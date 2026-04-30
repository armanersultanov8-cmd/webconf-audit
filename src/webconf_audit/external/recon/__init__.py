from __future__ import annotations

import http.client
import socket
import ssl
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Literal, NamedTuple
from urllib.parse import SplitResult, urljoin, urlsplit

from webconf_audit.external.rules import run_external_rules
from webconf_audit.models import AnalysisIssue, AnalysisResult, SourceLocation

if TYPE_CHECKING:
    from webconf_audit.external.recon.port_discovery import DiscoveredPort

ProbeScheme = Literal["http", "https"]
DEFAULT_TIMEOUT_SECONDS = 2.0


@dataclass(frozen=True, slots=True)
class ProbeTarget:
    scheme: ProbeScheme
    host: str
    port: int
    path: str

    @property
    def url(self) -> str:
        default_port = 443 if self.scheme == "https" else 80
        port_suffix = "" if self.port == default_port else f":{self.port}"
        host_part = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host_part}{port_suffix}{self.path}"


class ProbeResolution(NamedTuple):
    probe_targets: list[ProbeTarget]
    diagnostics: list[str]
    scan_metadata: list[dict[str, object]] | None
    use_discovery: bool
    invalid_discovery_target: bool


ProbeMethod = Literal["HEAD", "GET"]
_HEAD_FALLBACK_STATUS_CODES = frozenset({405, 501})


@dataclass(frozen=True, slots=True)
class TLSInfo:
    protocol_version: str | None = None
    cert_not_before: str | None = None
    cert_not_after: str | None = None
    cert_subject: str | None = None
    cert_issuer: str | None = None
    # Cipher details from the negotiated connection
    cipher_name: str | None = None
    cipher_bits: int | None = None
    cipher_protocol: str | None = None
    # Subject Alternative Names from the certificate
    cert_san: tuple[str, ...] = ()
    # Actively probed protocol support (filled by tls_probe, not the main connection)
    supported_protocols: tuple[str, ...] = ()
    # Certificate chain completeness (filled by verify_certificate_chain)
    cert_chain_complete: bool | None = None
    cert_chain_error: str | None = None
    # Number of certificates the server supplied in the handshake (filled by probe_chain_depth)
    cert_chain_depth: int | None = None


@dataclass(frozen=True, slots=True)
class OptionsObservation:
    status_code: int | None = None
    allow_header: str | None = None
    public_header: str | None = None
    error_message: str | None = None


_SENSITIVE_PATHS: tuple[str, ...] = (
    "/.git/HEAD",
    "/server-status",
    "/server-info",
    "/nginx_status",
    "/.env",
    "/.htaccess",
    "/.htpasswd",
    "/wp-admin/",
    "/phpinfo.php",
    "/elmah.axd",
    "/trace.axd",
    "/web.config",
    "/robots.txt",
    "/sitemap.xml",
    "/.svn/entries",
)
_CONDITIONAL_SENSITIVE_PATHS_BY_SERVER_TYPE: dict[str, tuple[str, ...]] = {
    "apache": ("/server-status?auto",),
}
_CONDITIONAL_SENSITIVE_PATH_CONFIDENCES = frozenset({"medium", "high"})
_REDIRECT_STATUS_CODES = frozenset({301, 302, 307, 308})
_REDIRECT_CHAIN_MAX_HOPS = 5
_BODY_SNIPPET_MAX_BYTES = 512
_ERROR_PAGE_PROBE_PATH = "/_wca_nonexistent_404_probe"
_ERROR_PAGE_BODY_MAX_BYTES = 2048


@dataclass(frozen=True, slots=True)
class SensitivePathProbe:
    url: str
    path: str
    status_code: int | None = None
    content_type: str | None = None
    body_snippet: str | None = None
    error_message: str | None = None


@dataclass(frozen=True, slots=True)
class ErrorPageProbe:
    url: str
    status_code: int | None = None
    server_header: str | None = None
    body_snippet: str | None = None
    error_message: str | None = None


@dataclass(frozen=True, slots=True)
class MalformedRequestProbe:
    url: str
    status_code: int | None = None
    reason_phrase: str | None = None
    server_header: str | None = None
    body_snippet: str | None = None
    error_message: str | None = None


@dataclass(frozen=True, slots=True)
class RedirectHop:
    url: str
    status_code: int | None = None
    location_header: str | None = None
    error_message: str | None = None


@dataclass(frozen=True, slots=True)
class RedirectChainAnalysis:
    source_url: str
    hops: tuple[RedirectHop, ...] = ()
    final_url: str | None = None
    loop_detected: bool = False
    mixed_scheme_redirect: bool = False
    cross_domain_redirect: bool = False
    truncated: bool = False
    error_message: str | None = None


# Default error page body signatures.
# Each entry: (substring_or_tuple_of_substrings, server_type)
_ERROR_PAGE_BODY_SIGNATURES: tuple[tuple[tuple[str, ...], str], ...] = (
    # Nginx default 404: "<center>nginx</center>" or "<hr><center>nginx/1.x.x</center>"
    (("<center>nginx</center>", "<center>nginx/"), "nginx"),
    # OpenResty (nginx fork): "<center>openresty</center>" or "<center>openresty/"
    (("<center>openresty</center>", "<center>openresty/"), "nginx"),
    # Apache default error pages contain "Apache" in footer or title
    (("Apache Server at", "Apache/"), "apache"),
    # Lighttpd default error pages
    (("lighttpd/", "powered by lighttpd"), "lighttpd"),
    # IIS default error pages
    (("Microsoft-IIS/", "IIS Detailed Error", "Server Error in"), "iis"),
)

# Malformed request response body signatures.
# Reuses the same structure as error page signatures.
_MALFORMED_RESPONSE_BODY_SIGNATURES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("<center>nginx</center>", "<center>nginx/"), "nginx"),
    (("<center>openresty</center>", "<center>openresty/"), "nginx"),
    (("Apache Server at", "Apache/", "Your browser sent a request that this server could not understand"), "apache"),
    (("lighttpd/", "powered by lighttpd"), "lighttpd"),
    (("Microsoft-IIS/", "Bad Request - Invalid URL", "IIS Detailed Error"), "iis"),
)

# Raw HTTP request line to trigger 400 Bad Request.
_MALFORMED_REQUEST_LINE = b"GET /%%MALFORMED%%PATH HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"


@dataclass(frozen=True, slots=True)
class ProbeAttempt:
    target: ProbeTarget
    tcp_open: bool
    effective_method: ProbeMethod | None = None
    status_code: int | None = None
    reason_phrase: str | None = None
    server_header: str | None = None
    strict_transport_security_header: str | None = None
    location_header: str | None = None
    content_type_header: str | None = None
    x_frame_options_header: str | None = None
    x_content_type_options_header: str | None = None
    content_security_policy_header: str | None = None
    referrer_policy_header: str | None = None
    permissions_policy_header: str | None = None
    cache_control_header: str | None = None
    x_dns_prefetch_control_header: str | None = None
    x_powered_by_header: str | None = None
    x_aspnet_version_header: str | None = None
    x_aspnetmvc_version_header: str | None = None
    via_header: str | None = None
    etag_header: str | None = None
    cross_origin_embedder_policy_header: str | None = None
    cross_origin_opener_policy_header: str | None = None
    cross_origin_resource_policy_header: str | None = None
    access_control_allow_origin_header: str | None = None
    access_control_allow_credentials_header: str | None = None
    allow_header: str | None = None
    set_cookie_headers: tuple[str, ...] = ()
    body_snippet: str | None = None
    tls_info: TLSInfo | None = None
    options_observation: OptionsObservation | None = None
    error_message: str | None = None

    @property
    def has_http_response(self) -> bool:
        return self.status_code is not None


def _is_bare_host(target: str) -> bool:
    """Return *True* when *target* is a plain hostname without scheme, port, path, or query."""
    normalized = target.strip()
    if not normalized or "://" in normalized:
        return False
    split = urlsplit(f"//{normalized}")
    if split.hostname is None or split.port is not None:
        return False
    # Reject targets that contain a path or query component.
    if split.path and split.path != "/":
        return False
    if split.query:
        return False
    return True


def analyze_external_target(
    target: str,
    *,
    scan_ports: bool = False,
    ports: tuple[int, ...] | None = None,
) -> AnalysisResult:
    """Run external analysis against *target*.

    Parameters
    ----------
    target:
        URL, ``host``, or ``host:port`` to probe.
    scan_ports:
        When *True* **and** *target* is a bare hostname (no scheme, no
        port), run port discovery across ``ports`` instead of probing
        only 80/443.  The CLI defaults to *True*; the API defaults to
        *False* for backward compatibility.
    ports:
        Explicit port set for discovery.  ``None`` uses
        ``DEFAULT_SCAN_PORTS``.  Ignored when *scan_ports* is *False*
        or *target* already specifies a scheme / port.
    """
    probe_resolution = _resolve_probe_targets(target, scan_ports=scan_ports, ports=ports)
    if probe_resolution.invalid_discovery_target:
        return _invalid_external_target_result(target)
    if not probe_resolution.probe_targets:
        return _no_probe_targets_result(
            target,
            use_discovery=probe_resolution.use_discovery,
            diagnostics=probe_resolution.diagnostics,
            scan_metadata=probe_resolution.scan_metadata,
        )

    attempts, successful_attempts, attempt_diagnostics = _probe_attempts(
        probe_resolution.probe_targets,
    )
    diagnostics = [*probe_resolution.diagnostics, *attempt_diagnostics]

    redirect_chain_analyses = _analyze_redirect_chains(successful_attempts)
    diagnostics.extend(_redirect_chain_diagnostics(redirect_chain_analyses))

    error_page_probes = _probe_error_pages(successful_attempts)
    malformed_request_probes = _probe_malformed_requests(successful_attempts)
    if not successful_attempts:
        return _no_http_service_result(
            target,
            probe_targets=probe_resolution.probe_targets,
            attempts=attempts,
            diagnostics=diagnostics,
            scan_metadata=probe_resolution.scan_metadata,
        )

    identification = _identify_server(
        successful_attempts,
        error_page_probes,
        malformed_request_probes,
    )
    sensitive_path_probes = _probe_sensitive_paths(
        successful_attempts,
        identification,
    )
    findings = run_external_rules(
        attempts,
        target,
        sensitive_path_probes,
        identification,
    )
    metadata = _analysis_metadata(
        attempts=attempts,
        redirect_chain_analyses=redirect_chain_analyses,
        sensitive_path_probes=sensitive_path_probes,
        error_page_probes=error_page_probes,
        malformed_request_probes=malformed_request_probes,
        identification=identification,
        scan_metadata=probe_resolution.scan_metadata,
    )
    issues = _identification_issues(
        identification,
        successful_attempts[0].target.url,
        diagnostics,
    )

    return AnalysisResult(
        mode="external",
        target=target,
        server_type=identification.server_type,
        findings=findings,
        issues=issues,
        diagnostics=diagnostics,
        metadata=metadata,
    )


def _resolve_probe_targets(
    target: str,
    *,
    scan_ports: bool,
    ports: tuple[int, ...] | None,
) -> ProbeResolution:
    diagnostics: list[str] = []
    scan_metadata: list[dict[str, object]] | None = None
    use_discovery = scan_ports and _is_bare_host(target)
    if not use_discovery:
        return ProbeResolution(
            probe_targets=_build_probe_targets(target),
            diagnostics=diagnostics,
            scan_metadata=scan_metadata,
            use_discovery=False,
            invalid_discovery_target=False,
        )

    # --- lazy import to avoid circular dependency at module level ---
    from webconf_audit.external.recon.port_discovery import (  # noqa: PLC0415
        DEFAULT_SCAN_PORTS,
        discover_probe_targets,
    )

    effective_ports = ports if ports is not None else DEFAULT_SCAN_PORTS
    hostname = urlsplit(f"//{target.strip()}").hostname
    if hostname is None:
        return ProbeResolution(
            probe_targets=[],
            diagnostics=diagnostics,
            scan_metadata=scan_metadata,
            use_discovery=use_discovery,
            invalid_discovery_target=True,
        )

    probe_targets, scan_results = discover_probe_targets(hostname, effective_ports)
    scan_metadata = [_scan_result_to_metadata(scan_result) for scan_result in scan_results]
    open_count = sum(1 for scan_result in scan_results if scan_result.tcp_open)
    diagnostics.append(
        f"port_scan: {len(effective_ports)} ports scanned, {open_count} open"
    )
    diagnostics.extend(_format_port_scan_diagnostics(scan_results))
    return ProbeResolution(
        probe_targets=probe_targets,
        diagnostics=diagnostics,
        scan_metadata=scan_metadata,
        use_discovery=use_discovery,
        invalid_discovery_target=False,
    )


def _scan_result_to_metadata(scan_result: DiscoveredPort) -> dict[str, object]:
    return {
        "host": scan_result.host,
        "port": scan_result.port,
        "tcp_open": scan_result.tcp_open,
        "error_message": scan_result.error_message,
    }


def _invalid_external_target_result(target: str) -> AnalysisResult:
    return AnalysisResult(
        mode="external",
        target=target,
        issues=[
            AnalysisIssue(
                code="external_invalid_target",
                level="error",
                message=f"Could not parse target hostname: {target}",
                location=SourceLocation(
                    mode="external",
                    kind="url",
                    target=target,
                ),
            )
        ],
    )


def _no_probe_targets_result(
    target: str,
    *,
    use_discovery: bool,
    diagnostics: list[str],
    scan_metadata: list[dict[str, object]] | None,
) -> AnalysisResult:
    return AnalysisResult(
        mode="external",
        target=target,
        issues=[
            AnalysisIssue(
                code=(
                    "external_no_open_ports"
                    if use_discovery
                    else "external_invalid_target"
                ),
                level="error",
                message=(
                    f"Port scan found no open ports on {target}"
                    if use_discovery
                    else f"Could not parse external target: {target}"
                ),
                location=SourceLocation(
                    mode="external",
                    kind="check",
                    target=target,
                ),
            )
        ],
        diagnostics=diagnostics,
        metadata={"port_scan": scan_metadata} if scan_metadata else {},
    )


def _probe_attempts(
    probe_targets: list[ProbeTarget],
) -> tuple[list[ProbeAttempt], list[ProbeAttempt], list[str]]:
    attempts = [_probe_target(probe_target) for probe_target in probe_targets]
    successful_attempts: list[ProbeAttempt] = []
    diagnostics: list[str] = []
    for attempt in attempts:
        diagnostics.extend(_format_attempt_diagnostics(attempt))
        if attempt.has_http_response:
            successful_attempts.append(attempt)
    return attempts, successful_attempts, diagnostics


def _redirect_chain_diagnostics(
    redirect_chain_analyses: list[RedirectChainAnalysis],
) -> list[str]:
    diagnostics: list[str] = []
    for chain in redirect_chain_analyses:
        diagnostics.extend(_format_redirect_chain_diagnostics(chain))
    return diagnostics


def _no_http_service_result(
    target: str,
    *,
    probe_targets: list[ProbeTarget],
    attempts: list[ProbeAttempt],
    diagnostics: list[str],
    scan_metadata: list[dict[str, object]] | None,
) -> AnalysisResult:
    return AnalysisResult(
        mode="external",
        target=target,
        findings=run_external_rules(
            attempts,
            target,
            [],
            None,
        ),
        issues=[
            AnalysisIssue(
                code="external_no_http_service",
                level="error",
                message=(
                    "No reachable HTTP or HTTPS service was identified during "
                    "the external probe."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="endpoint",
                    target=", ".join(probe_target.url for probe_target in probe_targets),
                ),
            )
        ],
        diagnostics=diagnostics,
        metadata=_no_http_service_metadata(attempts, scan_metadata),
    )


def _no_http_service_metadata(
    attempts: list[ProbeAttempt],
    scan_metadata: list[dict[str, object]] | None,
) -> dict[str, object]:
    metadata: dict[str, object] = {
        "probe_attempts": [_attempt_to_metadata(attempt) for attempt in attempts],
        "redirect_chains": [],
        "sensitive_path_probes": [],
        "error_page_probes": [],
        "malformed_request_probes": [],
    }
    if scan_metadata is not None:
        metadata["port_scan"] = scan_metadata
    return metadata


def _analysis_metadata(
    *,
    attempts: list[ProbeAttempt],
    redirect_chain_analyses: list[RedirectChainAnalysis],
    sensitive_path_probes: list[SensitivePathProbe],
    error_page_probes: list[ErrorPageProbe],
    malformed_request_probes: list[MalformedRequestProbe],
    identification: ServerIdentification,
    scan_metadata: list[dict[str, object]] | None,
) -> dict[str, object]:
    metadata: dict[str, object] = {
        "probe_attempts": [_attempt_to_metadata(attempt) for attempt in attempts],
        "redirect_chains": [
            _redirect_chain_analysis_to_metadata(chain)
            for chain in redirect_chain_analyses
        ],
        "sensitive_path_probes": [
            _sensitive_path_probe_to_metadata(probe)
            for probe in sensitive_path_probes
        ],
        "error_page_probes": [
            _error_page_probe_to_metadata(probe)
            for probe in error_page_probes
        ],
        "malformed_request_probes": [
            _malformed_request_probe_to_metadata(probe)
            for probe in malformed_request_probes
        ],
        "server_identification": _server_identification_to_metadata(identification),
    }
    if scan_metadata is not None:
        metadata["port_scan"] = scan_metadata
    return metadata


def _identification_issues(
    identification: ServerIdentification,
    source_url: str,
    diagnostics: list[str],
) -> list[AnalysisIssue]:
    if identification.server_type is not None:
        diagnostics.append(f"probable_server_type: {identification.server_type}")
        diagnostics.append(f"identification_confidence: {identification.confidence}")
        return []
    if identification.ambiguous:
        diagnostics.append(
            "identification_ambiguous: "
            + ", ".join(identification.candidate_server_types)
        )
        return [
            AnalysisIssue(
                code="external_server_type_ambiguous",
                level="warning",
                message=(
                    "Reached an HTTP/HTTPS service but observed conflicting "
                    "external indicators for the probable web server type."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=source_url,
                    details=", ".join(identification.candidate_server_types),
                ),
            )
        ]
    return [
        AnalysisIssue(
            code="external_server_type_unknown",
            level="warning",
            message=(
                "Reached an HTTP/HTTPS service but could not classify the probable "
                "web server type from external indicators."
            ),
            location=SourceLocation(
                mode="external",
                kind="header",
                target=source_url,
            ),
        )
    ]


def _build_probe_targets(target: str) -> list[ProbeTarget]:
    normalized_target = target.strip()
    if not normalized_target:
        return []

    if "://" in normalized_target:
        split_target = urlsplit(normalized_target)
        scheme = split_target.scheme.lower()
        if scheme not in {"http", "https"} or split_target.hostname is None:
            return []

        return [
            ProbeTarget(
                scheme=scheme,
                host=split_target.hostname,
                port=split_target.port or _default_port_for_scheme(scheme),
                path=_target_path(split_target),
            )
        ]

    split_target = urlsplit(f"//{normalized_target}")
    if split_target.hostname is None:
        return []

    path = _target_path(split_target)
    if split_target.port is not None:
        preferred_schemes: tuple[ProbeScheme, ProbeScheme]
        if split_target.port in {443, 8443}:
            preferred_schemes = ("https", "http")
        else:
            preferred_schemes = ("http", "https")

        return [
            ProbeTarget(
                scheme=scheme,
                host=split_target.hostname,
                port=split_target.port,
                path=path,
            )
            for scheme in preferred_schemes
        ]

    return [
        ProbeTarget(scheme="https", host=split_target.hostname, port=443, path=path),
        ProbeTarget(scheme="http", host=split_target.hostname, port=80, path=path),
    ]


def _default_port_for_scheme(scheme: ProbeScheme) -> int:
    if scheme == "https":
        return 443
    return 80


def _target_path(split_target: SplitResult) -> str:
    path = split_target.path or "/"
    if split_target.query:
        return f"{path}?{split_target.query}"
    return path


def _probe_target(probe_target: ProbeTarget) -> ProbeAttempt:
    if not _is_tcp_port_open(probe_target.host, probe_target.port):
        return ProbeAttempt(
            target=probe_target,
            tcp_open=False,
            error_message="TCP connection failed or timed out.",
        )

    head_attempt = _try_http_method(probe_target, "HEAD")

    if (
        head_attempt.has_http_response
        and head_attempt.status_code not in _HEAD_FALLBACK_STATUS_CODES
    ):
        result = head_attempt
    else:
        get_attempt = _try_http_method(probe_target, "GET")
        if get_attempt.has_http_response:
            result = _preserve_head_allow_header(get_attempt, head_attempt)
        else:
            result = head_attempt if head_attempt.has_http_response else get_attempt

    if result.has_http_response:
        options_obs = _try_options_request(probe_target)
        result = replace(result, options_observation=options_obs)

        # Active TLS version probing for HTTPS targets.
        if probe_target.scheme == "https" and result.tls_info is not None:
            result = _enrich_tls_with_version_probe(result, probe_target)

    return result


def _analyze_redirect_chains(
    successful_attempts: list[ProbeAttempt],
) -> list[RedirectChainAnalysis]:
    chains: list[RedirectChainAnalysis] = []

    for attempt in successful_attempts:
        if attempt.target.scheme != "http":
            continue
        if not _is_http_to_https_redirect(attempt):
            continue

        chains.append(_follow_redirect_chain(attempt))

    return chains


def _follow_redirect_chain(initial_attempt: ProbeAttempt) -> RedirectChainAnalysis:
    source_url = initial_attempt.target.url
    source_host = initial_attempt.target.host.lower()
    seen_urls = {source_url}
    hops: list[RedirectHop] = []
    current_attempt = initial_attempt
    mixed_scheme_redirect = False
    cross_domain_redirect = False

    for _hop_index in range(_REDIRECT_CHAIN_MAX_HOPS):
        hops.append(
            RedirectHop(
                url=current_attempt.target.url,
                status_code=current_attempt.status_code,
                location_header=current_attempt.location_header,
                error_message=current_attempt.error_message,
            )
        )

        if (
            current_attempt.status_code not in _REDIRECT_STATUS_CODES
            or current_attempt.location_header is None
        ):
            return RedirectChainAnalysis(
                source_url=source_url,
                hops=tuple(hops),
                final_url=current_attempt.target.url,
                mixed_scheme_redirect=mixed_scheme_redirect,
                cross_domain_redirect=cross_domain_redirect,
                error_message=current_attempt.error_message,
            )

        next_target = _redirect_target_from_location(
            current_attempt.target.url,
            current_attempt.location_header,
        )
        if next_target is None:
            return RedirectChainAnalysis(
                source_url=source_url,
                hops=tuple(hops),
                final_url=urljoin(current_attempt.target.url, current_attempt.location_header),
                mixed_scheme_redirect=mixed_scheme_redirect,
                cross_domain_redirect=cross_domain_redirect,
                error_message="Unsupported redirect target.",
            )

        if len(hops) >= 1 and next_target.scheme != "https":
            mixed_scheme_redirect = True
        if next_target.host.lower() != source_host:
            cross_domain_redirect = True

        if next_target.url in seen_urls:
            return RedirectChainAnalysis(
                source_url=source_url,
                hops=tuple(hops),
                final_url=next_target.url,
                loop_detected=True,
                mixed_scheme_redirect=mixed_scheme_redirect,
                cross_domain_redirect=cross_domain_redirect,
            )

        seen_urls.add(next_target.url)
        current_attempt = _probe_target(next_target)

    return RedirectChainAnalysis(
        source_url=source_url,
        hops=tuple(hops),
        final_url=current_attempt.target.url,
        mixed_scheme_redirect=mixed_scheme_redirect,
        cross_domain_redirect=cross_domain_redirect,
        truncated=True,
    )


def _is_http_to_https_redirect(attempt: ProbeAttempt) -> bool:
    return (
        attempt.status_code in _REDIRECT_STATUS_CODES
        and attempt.location_header is not None
        and attempt.location_header.startswith("https://")
    )


def _redirect_target_from_location(
    base_url: str,
    location_header: str,
) -> ProbeTarget | None:
    resolved_url = urljoin(base_url, location_header)
    split_target = urlsplit(resolved_url)
    scheme = split_target.scheme.lower()
    if scheme not in {"http", "https"} or split_target.hostname is None:
        return None
    return ProbeTarget(
        scheme=scheme,
        host=split_target.hostname,
        port=split_target.port or _default_port_for_scheme(scheme),
        path=_target_path(split_target),
    )


def _enrich_tls_with_version_probe(
    attempt: ProbeAttempt,
    probe_target: ProbeTarget,
) -> ProbeAttempt:
    """Run active TLS probing (version scan + chain verification) and merge results."""
    from webconf_audit.external.recon.tls_probe import (  # noqa: PLC0415
        probe_chain_depth,
        probe_tls_versions,
        supported_protocol_labels,
        verify_certificate_chain,
    )

    tls_results = probe_tls_versions(
        probe_target.host,
        probe_target.port,
    )
    protocols = supported_protocol_labels(tls_results)

    chain_result = verify_certificate_chain(
        probe_target.host,
        probe_target.port,
    )

    depth_result = probe_chain_depth(
        probe_target.host,
        probe_target.port,
    )

    if attempt.tls_info is None:
        return attempt
    enriched_tls = replace(
        attempt.tls_info,
        supported_protocols=protocols,
        cert_chain_complete=chain_result.verified,
        cert_chain_error=chain_result.error_message,
        cert_chain_depth=depth_result.depth,
    )
    return replace(attempt, tls_info=enriched_tls)


def _try_http_method(
    probe_target: ProbeTarget,
    method: ProbeMethod,
) -> ProbeAttempt:
    connection = _build_connection(probe_target)
    try:
        connection.request(method, probe_target.path)
        response = connection.getresponse()
        tls_info = _extract_tls_info(connection, response)
        body_snippet: str | None = None
        if method == "GET":
            raw_body = response.read(_BODY_SNIPPET_MAX_BYTES)
            try:
                body_snippet = raw_body.decode("utf-8", errors="replace").strip() or None
            except Exception:
                body_snippet = None
        else:
            response.read()
        return ProbeAttempt(
            target=probe_target,
            tcp_open=True,
            effective_method=method,
            status_code=response.status,
            reason_phrase=response.reason,
            server_header=response.getheader("Server"),
            strict_transport_security_header=response.getheader("Strict-Transport-Security"),
            location_header=response.getheader("Location"),
            content_type_header=response.getheader("Content-Type"),
            x_frame_options_header=response.getheader("X-Frame-Options"),
            x_content_type_options_header=response.getheader("X-Content-Type-Options"),
            content_security_policy_header=response.getheader("Content-Security-Policy"),
            referrer_policy_header=response.getheader("Referrer-Policy"),
            permissions_policy_header=response.getheader("Permissions-Policy"),
            cache_control_header=response.getheader("Cache-Control"),
            x_dns_prefetch_control_header=response.getheader("X-DNS-Prefetch-Control"),
            x_powered_by_header=response.getheader("X-Powered-By"),
            x_aspnet_version_header=response.getheader("X-AspNet-Version"),
            x_aspnetmvc_version_header=response.getheader("X-AspNetMvc-Version"),
            via_header=response.getheader("Via"),
            etag_header=response.getheader("ETag"),
            cross_origin_embedder_policy_header=response.getheader("Cross-Origin-Embedder-Policy"),
            cross_origin_opener_policy_header=response.getheader("Cross-Origin-Opener-Policy"),
            cross_origin_resource_policy_header=response.getheader("Cross-Origin-Resource-Policy"),
            access_control_allow_origin_header=response.getheader("Access-Control-Allow-Origin"),
            access_control_allow_credentials_header=response.getheader("Access-Control-Allow-Credentials"),
            allow_header=response.getheader("Allow"),
            set_cookie_headers=tuple(response.msg.get_all("Set-Cookie") or []),
            body_snippet=body_snippet,
            tls_info=tls_info,
        )
    except (OSError, http.client.HTTPException) as exc:
        return ProbeAttempt(
            target=probe_target,
            tcp_open=True,
            error_message=str(exc),
        )
    finally:
        connection.close()


def _extract_tls_info(
    connection: http.client.HTTPConnection,
    response: http.client.HTTPResponse,
) -> TLSInfo | None:
    sock = _tls_socket_from_connection(connection, response)
    if not isinstance(sock, ssl.SSLSocket):
        return None

    try:
        protocol_version = sock.version()
    except (AttributeError, ValueError):
        protocol_version = None

    # --- cipher info ---
    cipher_name: str | None = None
    cipher_bits: int | None = None
    cipher_protocol: str | None = None
    try:
        cipher_tuple = sock.cipher()
        if cipher_tuple is not None:
            cipher_name = cipher_tuple[0]
            cipher_protocol = cipher_tuple[1]
            cipher_bits = cipher_tuple[2]
    except (AttributeError, ValueError, IndexError):
        pass

    cert = _decoded_peer_certificate(sock)
    if cert is None:
        return TLSInfo(
            protocol_version=protocol_version,
            cipher_name=cipher_name,
            cipher_bits=cipher_bits,
            cipher_protocol=cipher_protocol,
        )

    # --- SAN ---
    cert_san = _extract_san(cert)

    return TLSInfo(
        protocol_version=protocol_version,
        cert_not_before=cert.get("notBefore"),
        cert_not_after=cert.get("notAfter"),
        cert_subject=_format_x509_name(cert.get("subject")),
        cert_issuer=_format_x509_name(cert.get("issuer")),
        cipher_name=cipher_name,
        cipher_bits=cipher_bits,
        cipher_protocol=cipher_protocol,
        cert_san=cert_san,
    )


def _tls_socket_from_connection(
    connection: http.client.HTTPConnection,
    response: http.client.HTTPResponse,
) -> ssl.SSLSocket | None:
    direct_sock = getattr(connection, "sock", None)
    if isinstance(direct_sock, ssl.SSLSocket):
        return direct_sock

    response_fp = getattr(response, "fp", None)
    raw = getattr(response_fp, "raw", None)
    raw_sock = getattr(raw, "_sock", None)
    if isinstance(raw_sock, ssl.SSLSocket):
        return raw_sock
    return None


def _decoded_peer_certificate(sock: ssl.SSLSocket) -> dict | None:
    try:
        parsed = sock.getpeercert()
        if parsed:
            return parsed
    except (AttributeError, ValueError, ssl.SSLError):
        pass

    try:
        der_bytes = sock.getpeercert(binary_form=True)
    except (AttributeError, ValueError, ssl.SSLError):
        return None
    if not der_bytes:
        return None

    return _decode_der_certificate(der_bytes)


def _decode_der_certificate(der_bytes: bytes) -> dict | None:
    try:
        from cryptography import x509  # noqa: PLC0415
        from cryptography.x509.oid import NameOID  # noqa: PLC0415
    except ImportError:
        return None

    try:
        cert = x509.load_der_x509_certificate(der_bytes)
    except (TypeError, ValueError):
        return None

    return {
        "notBefore": _format_cert_datetime(_cert_time(cert, "not_valid_before")),
        "notAfter": _format_cert_datetime(_cert_time(cert, "not_valid_after")),
        "subject": _x509_name_to_ssl_tuple(cert.subject, NameOID),
        "issuer": _x509_name_to_ssl_tuple(cert.issuer, NameOID),
        "subjectAltName": _x509_san_entries(cert, x509),
    }


def _cert_time(cert, attr_name: str) -> datetime | None:
    utc_attr = f"{attr_name}_utc"
    value = getattr(cert, utc_attr, None)
    if value is not None:
        return value
    value = getattr(cert, attr_name, None)
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc)


def _format_cert_datetime(parsed: datetime | None) -> str | None:
    if parsed is None:
        return None
    return (
        f"{parsed:%b} {parsed.day:2d} "
        f"{parsed:%H:%M:%S} {parsed:%Y} GMT"
    )


def _x509_name_to_ssl_tuple(name, name_oid) -> tuple[tuple[tuple[str, str], ...], ...]:
    name_map = {
        name_oid.COMMON_NAME: "commonName",
        name_oid.COUNTRY_NAME: "countryName",
        name_oid.STATE_OR_PROVINCE_NAME: "stateOrProvinceName",
        name_oid.LOCALITY_NAME: "localityName",
        name_oid.ORGANIZATION_NAME: "organizationName",
        name_oid.ORGANIZATIONAL_UNIT_NAME: "organizationalUnitName",
        name_oid.EMAIL_ADDRESS: "emailAddress",
    }
    result: list[tuple[tuple[str, str], ...]] = []
    for attribute in name:
        oid = attribute.oid
        # ``ObjectIdentifier._name`` is an internal cryptography detail
        # and can disappear across releases.  Fall back to the public
        # ``dotted_string`` when the OID is not in our curated map — the
        # rule downstream only needs a stable human-readable key, not
        # the pretty RFC-style short name.
        key = name_map.get(oid, getattr(oid, "dotted_string", None) or str(oid))
        result.append(((key, attribute.value),))
    return tuple(result)


def _x509_san_entries(cert, x509_module) -> tuple[tuple[str, str], ...]:
    try:
        san = cert.extensions.get_extension_for_class(
            x509_module.SubjectAlternativeName,
        ).value
    except x509_module.ExtensionNotFound:
        return ()

    entries: list[tuple[str, str]] = [
        ("DNS", value)
        for value in san.get_values_for_type(x509_module.DNSName)
    ]
    entries.extend(
        ("IP Address", str(value))
        for value in san.get_values_for_type(x509_module.IPAddress)
    )
    return tuple(entries)


def _extract_san(cert: dict) -> tuple[str, ...]:
    """Extract DNS Subject Alternative Names from a parsed certificate dict.

    Only ``DNS`` type entries are included.  Non-DNS entries (``IP``,
    ``email``, ``URI``, etc.) are intentionally excluded because they
    are not meaningful for hostname-based matching in
    :func:`_hostname_matches_san`.
    """
    san_entries = cert.get("subjectAltName")
    if not san_entries:
        return ()
    return tuple(value for san_type, value in san_entries if san_type == "DNS")


def _format_x509_name(name_tuples: tuple | None) -> str | None:
    if name_tuples is None:
        return None

    parts: list[str] = []
    for rdn in name_tuples:
        for attr_type, attr_value in rdn:
            parts.append(f"{attr_type}={attr_value}")
    return ", ".join(parts) if parts else None


def _try_options_request(probe_target: ProbeTarget) -> OptionsObservation:
    connection = _build_connection(probe_target)
    try:
        connection.request("OPTIONS", probe_target.path)
        response = connection.getresponse()
        response.read()
        return OptionsObservation(
            status_code=response.status,
            allow_header=response.getheader("Allow"),
            public_header=response.getheader("Public"),
        )
    except OSError as exc:
        return OptionsObservation(error_message=str(exc))
    finally:
        connection.close()


def _probe_sensitive_paths(
    successful_attempts: list[ProbeAttempt],
    identification: ServerIdentification | None = None,
) -> list[SensitivePathProbe]:
    seen: set[tuple[str, str, int]] = set()
    results: list[SensitivePathProbe] = []
    paths_to_probe = _sensitive_paths_for_identification(identification)

    for attempt in successful_attempts:
        target = attempt.target
        key = (target.scheme, target.host, target.port)
        if key in seen:
            continue
        seen.add(key)

        for path in paths_to_probe:
            base_target = ProbeTarget(
                scheme=target.scheme,
                host=target.host,
                port=target.port,
                path=path,
            )
            results.append(_try_sensitive_path(base_target))

    return results


def _sensitive_paths_for_identification(
    identification: ServerIdentification | None,
) -> tuple[str, ...]:
    if identification is None:
        return _SENSITIVE_PATHS
    if identification.server_type is None:
        return _SENSITIVE_PATHS
    if identification.confidence not in _CONDITIONAL_SENSITIVE_PATH_CONFIDENCES:
        return _SENSITIVE_PATHS

    conditional_paths = _CONDITIONAL_SENSITIVE_PATHS_BY_SERVER_TYPE.get(
        identification.server_type,
        (),
    )
    if not conditional_paths:
        return _SENSITIVE_PATHS

    return _SENSITIVE_PATHS + tuple(
        path for path in conditional_paths if path not in _SENSITIVE_PATHS
    )


def _try_sensitive_path(probe_target: ProbeTarget) -> SensitivePathProbe:
    connection = _build_connection(probe_target)
    try:
        connection.request("GET", probe_target.path)
        response = connection.getresponse()
        raw_body = response.read(_BODY_SNIPPET_MAX_BYTES)
        try:
            body_snippet = raw_body.decode("utf-8", errors="replace").strip() or None
        except Exception:
            body_snippet = None
        return SensitivePathProbe(
            url=probe_target.url,
            path=probe_target.path,
            status_code=response.status,
            content_type=response.getheader("Content-Type"),
            body_snippet=body_snippet,
        )
    except OSError as exc:
        return SensitivePathProbe(
            url=probe_target.url,
            path=probe_target.path,
            error_message=str(exc),
        )
    finally:
        connection.close()


def _probe_error_pages(
    successful_attempts: list[ProbeAttempt],
) -> list[ErrorPageProbe]:
    """Request a nonexistent path on each distinct scheme+host+port to capture default error pages."""
    seen: set[tuple[str, str, int]] = set()
    results: list[ErrorPageProbe] = []

    for attempt in successful_attempts:
        target = attempt.target
        key = (target.scheme, target.host, target.port)
        if key in seen:
            continue
        seen.add(key)

        probe_target = ProbeTarget(
            scheme=target.scheme,
            host=target.host,
            port=target.port,
            path=_ERROR_PAGE_PROBE_PATH,
        )
        results.append(_try_error_page_probe(probe_target))

    return results


def _try_error_page_probe(probe_target: ProbeTarget) -> ErrorPageProbe:
    connection = _build_connection(probe_target)
    try:
        connection.request("GET", probe_target.path)
        response = connection.getresponse()
        raw_body = response.read(_ERROR_PAGE_BODY_MAX_BYTES)
        try:
            body_snippet = raw_body.decode("utf-8", errors="replace").strip() or None
        except Exception:
            body_snippet = None
        return ErrorPageProbe(
            url=probe_target.url,
            status_code=response.status,
            server_header=response.getheader("Server"),
            body_snippet=body_snippet,
        )
    except OSError as exc:
        return ErrorPageProbe(
            url=probe_target.url,
            error_message=str(exc),
        )
    finally:
        connection.close()


def _match_error_page_body(body: str) -> str | None:
    """Return the server type if *body* matches a known default error page signature."""
    for signatures, server_type in _ERROR_PAGE_BODY_SIGNATURES:
        for sig in signatures:
            if sig in body:
                return server_type
    return None


def _probe_malformed_requests(
    successful_attempts: list[ProbeAttempt],
) -> list[MalformedRequestProbe]:
    """Send a deliberately malformed HTTP request to each distinct scheme+host+port."""
    seen: set[tuple[str, str, int]] = set()
    results: list[MalformedRequestProbe] = []

    for attempt in successful_attempts:
        target = attempt.target
        key = (target.scheme, target.host, target.port)
        if key in seen:
            continue
        seen.add(key)

        results.append(_try_malformed_request_probe(target))

    return results


def _try_malformed_request_probe(target: ProbeTarget) -> MalformedRequestProbe:
    """Send a raw malformed request and parse the 400-class response."""
    url = target.url
    try:
        if target.scheme == "https":
            raw_sock = socket.create_connection(
                (target.host, target.port), timeout=DEFAULT_TIMEOUT_SECONDS,
            )
            try:
                tls_sock = _probe_tls_context().wrap_socket(
                    raw_sock,
                    server_hostname=target.host,
                )
            except BaseException:
                raw_sock.close()
                raise
            sock = tls_sock
        else:
            sock = socket.create_connection(
                (target.host, target.port), timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        try:
            host_header = target.host.encode("idna")
            request_line = _MALFORMED_REQUEST_LINE.replace(
                b"{host}", host_header,
            )
            sock.sendall(request_line)

            response_data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
                if len(response_data) >= _ERROR_PAGE_BODY_MAX_BYTES:
                    break
        finally:
            sock.close()

        return _parse_malformed_response(url, response_data)

    except (OSError, UnicodeError) as exc:
        return MalformedRequestProbe(url=url, error_message=str(exc))


def _parse_malformed_response(
    url: str, raw: bytes,
) -> MalformedRequestProbe:
    """Parse a raw HTTP response into MalformedRequestProbe fields."""
    text = _decoded_malformed_response(raw)
    if text is None:
        return MalformedRequestProbe(url=url, error_message="Failed to decode response")

    header_block, body = _split_malformed_response(text)
    if header_block is None:
        return MalformedRequestProbe(url=url, body_snippet=text[:512].strip() or None)

    lines = header_block.split("\n")
    status_code, reason_phrase = _parse_malformed_status_line(lines)
    return MalformedRequestProbe(
        url=url,
        status_code=status_code,
        reason_phrase=reason_phrase,
        server_header=_malformed_server_header(lines),
        body_snippet=body[:512].strip() or None,
    )


def _decoded_malformed_response(raw: bytes) -> str | None:
    # ``errors="replace"`` makes ``bytes.decode`` total for *decoding*
    # problems, so the only exceptions we can reasonably expect here are
    # ``LookupError`` (unknown codec — impossible for a hard-coded
    # ``"utf-8"`` alias, but harmless to guard against a ``codecs``
    # registry surprise) and ``TypeError`` (non-``bytes`` input slipping
    # through).  Narrow the catch so an unrelated bug — e.g. a ``raw``
    # that is suddenly ``None`` — surfaces instead of being silently
    # turned into ``None`` here.
    try:
        return raw.decode("utf-8", errors="replace")
    except (LookupError, TypeError):
        return None


def _split_malformed_response(text: str) -> tuple[str | None, str]:
    header_end = text.find("\r\n\r\n")
    if header_end == -1:
        header_end = text.find("\n\n")
    if header_end == -1:
        return None, text
    return text[:header_end], text[header_end:].strip()


def _parse_malformed_status_line(
    lines: list[str],
) -> tuple[int | None, str | None]:
    status_line = lines[0].strip() if lines else ""
    if not status_line.startswith("HTTP/"):
        return None, None

    parts = status_line.split(None, 2)
    status_code = _malformed_status_code(parts)
    reason_phrase = parts[2].strip() if len(parts) >= 3 else None
    return status_code, reason_phrase


def _malformed_status_code(parts: list[str]) -> int | None:
    if len(parts) < 2:
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


def _malformed_server_header(lines: list[str]) -> str | None:
    for line in lines[1:]:
        if line.lower().startswith("server:"):
            return line.split(":", 1)[1].strip()
    return None


def _match_malformed_response_body(body: str) -> str | None:
    """Return the server type if *body* matches a known malformed-response signature."""
    for signatures, server_type in _MALFORMED_RESPONSE_BODY_SIGNATURES:
        for sig in signatures:
            if sig in body:
                return server_type
    return None


def _is_error_status(status_code: int | None) -> bool:
    """Return True for 4xx/5xx responses suitable for error fingerprinting."""
    return status_code is not None and 400 <= status_code < 600


def _preserve_head_allow_header(
    get_attempt: ProbeAttempt,
    head_attempt: ProbeAttempt,
) -> ProbeAttempt:
    if get_attempt.allow_header is not None:
        return get_attempt
    if head_attempt.allow_header is None:
        return get_attempt

    return replace(get_attempt, allow_header=head_attempt.allow_header)


def _is_tcp_port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT_SECONDS):
            return True
    except OSError:
        return False


def _probe_tls_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _build_connection(probe_target: ProbeTarget) -> http.client.HTTPConnection:
    if probe_target.scheme == "https":
        return http.client.HTTPSConnection(
            probe_target.host,
            probe_target.port,
            timeout=DEFAULT_TIMEOUT_SECONDS,
            context=_probe_tls_context(),
        )

    return http.client.HTTPConnection(
        probe_target.host,
        probe_target.port,
        timeout=DEFAULT_TIMEOUT_SECONDS,
    )


def _format_attempt_diagnostics(attempt: ProbeAttempt) -> list[str]:
    diagnostics = [f"probe_target: {attempt.target.url}"]

    if not attempt.tcp_open:
        diagnostics.append(
            f"tcp_port_closed_or_unreachable: {attempt.target.host}:{attempt.target.port}"
        )
        return diagnostics

    diagnostics.append(f"tcp_port_open: {attempt.target.host}:{attempt.target.port}")

    if not attempt.has_http_response:
        diagnostics.append(f"http_probe_failed: {attempt.error_message}")
        return diagnostics

    diagnostics.append(f"http_status: {attempt.status_code} {attempt.reason_phrase}")
    diagnostics.extend(_attempt_header_diagnostics(attempt))
    diagnostics.extend(_attempt_tls_diagnostics(attempt.tls_info))
    diagnostics.extend(_attempt_options_diagnostics(attempt.options_observation))
    return diagnostics


def _attempt_header_diagnostics(attempt: ProbeAttempt) -> list[str]:
    diagnostics = _optional_diagnostics(
        (
            ("server_header", attempt.server_header),
            ("location_header", attempt.location_header),
            ("content_type", attempt.content_type_header),
            ("x_frame_options", attempt.x_frame_options_header),
            ("x_content_type_options", attempt.x_content_type_options_header),
            ("content_security_policy", attempt.content_security_policy_header),
            ("referrer_policy", attempt.referrer_policy_header),
            ("permissions_policy", attempt.permissions_policy_header),
            ("cache_control", attempt.cache_control_header),
            ("x_dns_prefetch_control", attempt.x_dns_prefetch_control_header),
            ("x_powered_by", attempt.x_powered_by_header),
            ("x_aspnet_version", attempt.x_aspnet_version_header),
            ("x_aspnetmvc_version", attempt.x_aspnetmvc_version_header),
            ("via", attempt.via_header),
            ("etag", attempt.etag_header),
            (
                "cross_origin_embedder_policy",
                attempt.cross_origin_embedder_policy_header,
            ),
            (
                "cross_origin_opener_policy",
                attempt.cross_origin_opener_policy_header,
            ),
            (
                "cross_origin_resource_policy",
                attempt.cross_origin_resource_policy_header,
            ),
            (
                "access_control_allow_origin",
                attempt.access_control_allow_origin_header,
            ),
            (
                "access_control_allow_credentials",
                attempt.access_control_allow_credentials_header,
            ),
            ("allow", attempt.allow_header),
        )
    )
    if attempt.set_cookie_headers:
        diagnostics.append(f"set_cookie_count: {len(attempt.set_cookie_headers)}")
    return diagnostics


def _attempt_tls_diagnostics(tls_info: TLSInfo | None) -> list[str]:
    if tls_info is None:
        return []

    diagnostics: list[str] = []
    if tls_info.protocol_version is not None:
        diagnostics.append(f"tls_version: {tls_info.protocol_version}")
    if tls_info.cipher_name is not None:
        diagnostics.append(
            f"tls_cipher: {tls_info.cipher_name} ({tls_info.cipher_bits} bits)"
        )
    if tls_info.cert_not_after is not None:
        diagnostics.append(f"cert_not_after: {tls_info.cert_not_after}")
    if tls_info.cert_san:
        diagnostics.append(f"cert_san: {', '.join(tls_info.cert_san)}")
    if tls_info.supported_protocols:
        diagnostics.append(
            f"tls_supported: {', '.join(tls_info.supported_protocols)}"
        )
    if tls_info.cert_chain_complete is not None:
        diagnostics.append(f"cert_chain_complete: {tls_info.cert_chain_complete}")
        if tls_info.cert_chain_error is not None:
            diagnostics.append(f"cert_chain_error: {tls_info.cert_chain_error}")
    if tls_info.cert_chain_depth is not None:
        diagnostics.append(f"cert_chain_depth: {tls_info.cert_chain_depth}")
    return diagnostics


def _attempt_options_diagnostics(
    options_observation: OptionsObservation | None,
) -> list[str]:
    if options_observation is None:
        return []
    return _optional_diagnostics(
        (
            ("options_status", options_observation.status_code),
            ("options_allow", options_observation.allow_header),
            ("options_public", options_observation.public_header),
        )
    )


def _optional_diagnostics(
    entries: tuple[tuple[str, object | None], ...],
) -> list[str]:
    return [
        f"{label}: {value}"
        for label, value in entries
        if value is not None
    ]


def _attempt_to_metadata(attempt: ProbeAttempt) -> dict[str, object]:
    return {
        "scheme": attempt.target.scheme,
        "host": attempt.target.host,
        "port": attempt.target.port,
        "path": attempt.target.path,
        "url": attempt.target.url,
        "tcp_open": attempt.tcp_open,
        "effective_method": attempt.effective_method,
        "status_code": attempt.status_code,
        "reason_phrase": attempt.reason_phrase,
        "server_header": attempt.server_header,
        "strict_transport_security_header": attempt.strict_transport_security_header,
        "location_header": attempt.location_header,
        "content_type_header": attempt.content_type_header,
        "x_frame_options_header": attempt.x_frame_options_header,
        "x_content_type_options_header": attempt.x_content_type_options_header,
        "content_security_policy_header": attempt.content_security_policy_header,
        "referrer_policy_header": attempt.referrer_policy_header,
        "permissions_policy_header": attempt.permissions_policy_header,
        "cache_control_header": attempt.cache_control_header,
        "x_dns_prefetch_control_header": attempt.x_dns_prefetch_control_header,
        "x_powered_by_header": attempt.x_powered_by_header,
        "x_aspnet_version_header": attempt.x_aspnet_version_header,
        "x_aspnetmvc_version_header": attempt.x_aspnetmvc_version_header,
        "via_header": attempt.via_header,
        "etag_header": attempt.etag_header,
        "cross_origin_embedder_policy_header": attempt.cross_origin_embedder_policy_header,
        "cross_origin_opener_policy_header": attempt.cross_origin_opener_policy_header,
        "cross_origin_resource_policy_header": attempt.cross_origin_resource_policy_header,
        "access_control_allow_origin_header": attempt.access_control_allow_origin_header,
        "access_control_allow_credentials_header": attempt.access_control_allow_credentials_header,
        "allow_header": attempt.allow_header,
        "set_cookie_headers": list(attempt.set_cookie_headers),
        "tls_info": _tls_info_to_metadata(attempt.tls_info),
        "options_observation": _options_observation_to_metadata(attempt.options_observation),
        "error_message": attempt.error_message,
    }


def _redirect_chain_analysis_to_metadata(
    chain: RedirectChainAnalysis,
) -> dict[str, object]:
    return {
        "source_url": chain.source_url,
        "hops": [
            {
                "url": hop.url,
                "status_code": hop.status_code,
                "location_header": hop.location_header,
                "error_message": hop.error_message,
            }
            for hop in chain.hops
        ],
        "final_url": chain.final_url,
        "loop_detected": chain.loop_detected,
        "mixed_scheme_redirect": chain.mixed_scheme_redirect,
        "cross_domain_redirect": chain.cross_domain_redirect,
        "truncated": chain.truncated,
        "error_message": chain.error_message,
    }


def _format_redirect_chain_diagnostics(
    chain: RedirectChainAnalysis,
) -> list[str]:
    diagnostics: list[str] = []
    path = _redirect_chain_path(chain)
    diagnostics.append(f"redirect_chain: {path}")
    if chain.loop_detected:
        diagnostics.append(f"redirect_chain_loop: {chain.source_url}")
    if chain.mixed_scheme_redirect:
        diagnostics.append(f"redirect_chain_mixed_scheme: {path}")
    if chain.cross_domain_redirect:
        diagnostics.append(f"redirect_chain_cross_domain: {path}")
    if chain.truncated:
        diagnostics.append(f"redirect_chain_truncated: {chain.source_url}")
    if chain.error_message is not None:
        diagnostics.append(f"redirect_chain_error: {chain.error_message}")
    return diagnostics


def _format_port_scan_diagnostics(
    scan_results: list[DiscoveredPort],
) -> list[str]:
    diagnostics: list[str] = []
    for result in scan_results:
        host = result.host
        port = result.port
        endpoint = f"{host}:{port}"
        if result.tcp_open:
            diagnostics.append(f"port_scan_open: {endpoint}")
            continue
        diagnostics.append(f"port_scan_closed_or_unreachable: {endpoint}")
        if result.error_message:
            diagnostics.append(f"port_scan_error: {endpoint}: {result.error_message}")
    return diagnostics


def _redirect_chain_path(chain: RedirectChainAnalysis) -> str:
    urls = [hop.url for hop in chain.hops]
    if chain.final_url is not None and (not urls or chain.final_url != urls[-1]):
        urls.append(chain.final_url)
    return " -> ".join(urls)


def _tls_info_to_metadata(tls_info: TLSInfo | None) -> dict[str, object] | None:
    if tls_info is None:
        return None
    return {
        "protocol_version": tls_info.protocol_version,
        "cert_not_before": tls_info.cert_not_before,
        "cert_not_after": tls_info.cert_not_after,
        "cert_subject": tls_info.cert_subject,
        "cert_issuer": tls_info.cert_issuer,
        "cipher_name": tls_info.cipher_name,
        "cipher_bits": tls_info.cipher_bits,
        "cipher_protocol": tls_info.cipher_protocol,
        "cert_san": list(tls_info.cert_san),
        "supported_protocols": list(tls_info.supported_protocols),
        "cert_chain_complete": tls_info.cert_chain_complete,
        "cert_chain_error": tls_info.cert_chain_error,
        "cert_chain_depth": tls_info.cert_chain_depth,
    }


def _options_observation_to_metadata(
    obs: OptionsObservation | None,
) -> dict[str, object] | None:
    if obs is None:
        return None
    return {
        "status_code": obs.status_code,
        "allow_header": obs.allow_header,
        "public_header": obs.public_header,
        "error_message": obs.error_message,
    }


def _sensitive_path_probe_to_metadata(
    probe: SensitivePathProbe,
) -> dict[str, object]:
    return {
        "url": probe.url,
        "path": probe.path,
        "status_code": probe.status_code,
        "content_type": probe.content_type,
        "body_snippet": probe.body_snippet,
        "error_message": probe.error_message,
    }


IdentificationStrength = Literal["strong", "moderate", "weak"]
IdentificationConfidence = Literal["high", "medium", "low", "none"]


@dataclass(frozen=True, slots=True)
class ServerIdentificationEvidence:
    source_url: str
    signal: str
    value: str
    indicates: str | None
    strength: IdentificationStrength
    detail: str


@dataclass(frozen=True, slots=True)
class ServerIdentification:
    server_type: str | None
    confidence: IdentificationConfidence
    evidence: tuple[ServerIdentificationEvidence, ...]
    ambiguous: bool = False
    candidate_server_types: tuple[str, ...] = ()


_SERVER_HEADER_SIGNATURES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("openresty", "nginx"), "nginx"),
    (("apache",), "apache"),
    (("lighttpd",), "lighttpd"),
    (("microsoft-iis", " iis"), "iis"),
)


def _identify_server(
    attempts: list[ProbeAttempt],
    error_page_probes: list[ErrorPageProbe] | None = None,
    malformed_request_probes: list[MalformedRequestProbe] | None = None,
) -> ServerIdentification:
    evidence: list[ServerIdentificationEvidence] = []
    direct_server_votes: dict[str, int] = {}
    app_stack_votes: dict[str, int] = {}

    _collect_attempt_identification_evidence(
        attempts,
        evidence,
        direct_server_votes,
        app_stack_votes,
    )

    # Error page body fingerprinting — moderate-strength signal.
    error_page_votes = _error_page_votes(error_page_probes, evidence)

    # Malformed request fingerprinting — server header is strong (→ direct),
    # body signature is moderate (→ secondary bucket).
    malformed_server_votes, malformed_body_votes = _malformed_request_votes(
        malformed_request_probes,
        evidence,
    )
    # Merge malformed server-header votes into direct votes (strong evidence).
    _merge_vote_counts(direct_server_votes, malformed_server_votes)
    # Merge malformed body votes into error-page-level bucket.
    _merge_vote_counts(error_page_votes, malformed_body_votes)

    if not evidence:
        return ServerIdentification(
            server_type=None,
            confidence="none",
            evidence=(),
        )

    direct_identification = _identify_server_from_votes(
        direct_server_votes,
        evidence,
        strong_evidence=True,
    )
    if direct_identification is not None:
        return direct_identification

    error_page_identification = _identify_server_from_votes(
        error_page_votes,
        evidence,
        strong_evidence=False,
    )
    if error_page_identification is not None:
        return error_page_identification

    fallback_identification = _identify_server_from_votes(
        app_stack_votes,
        evidence,
        strong_evidence=False,
    )
    if fallback_identification is not None:
        return fallback_identification

    return ServerIdentification(
        server_type=None,
        confidence="none",
        evidence=tuple(evidence),
    )


def _collect_attempt_identification_evidence(
    attempts: list[ProbeAttempt],
    evidence: list[ServerIdentificationEvidence],
    direct_server_votes: dict[str, int],
    app_stack_votes: dict[str, int],
) -> None:
    for attempt in attempts:
        if not attempt.has_http_response:
            continue
        if attempt.server_header:
            _collect_server_header_evidence(attempt, evidence, direct_server_votes)
        if attempt.x_powered_by_header:
            _collect_x_powered_by_evidence(attempt, evidence, app_stack_votes)
        _collect_x_aspnet_version_evidence(attempt, evidence, app_stack_votes)
        _collect_extended_header_evidence(attempt, evidence, app_stack_votes)


def _collect_x_aspnet_version_evidence(
    attempt: ProbeAttempt,
    evidence: list[ServerIdentificationEvidence],
    app_stack_votes: dict[str, int],
) -> None:
    if not attempt.x_aspnet_version_header:
        return
    evidence.append(
        ServerIdentificationEvidence(
            source_url=attempt.target.url,
            signal="x_aspnet_version_header",
            value=attempt.x_aspnet_version_header,
            indicates="iis",
            strength="moderate",
            detail=(
                f"X-AspNet-Version header ({attempt.x_aspnet_version_header}) "
                "indicates an ASP.NET runtime, commonly hosted on IIS."
            ),
        )
    )
    app_stack_votes["iis"] = app_stack_votes.get("iis", 0) + 1


def _error_page_votes(
    probes: list[ErrorPageProbe] | None,
    evidence: list[ServerIdentificationEvidence],
) -> dict[str, int]:
    votes: dict[str, int] = {}
    for probe in probes or ():
        _collect_error_page_evidence(probe, evidence, votes)
    return votes


def _malformed_request_votes(
    probes: list[MalformedRequestProbe] | None,
    evidence: list[ServerIdentificationEvidence],
) -> tuple[dict[str, int], dict[str, int]]:
    malformed_server_votes: dict[str, int] = {}
    malformed_body_votes: dict[str, int] = {}
    for probe in probes or ():
        _collect_malformed_request_evidence(
            probe,
            evidence,
            malformed_server_votes,
            malformed_body_votes,
        )
    return malformed_server_votes, malformed_body_votes


def _merge_vote_counts(
    target_votes: dict[str, int],
    additional_votes: dict[str, int],
) -> None:
    for server_type, count in additional_votes.items():
        target_votes[server_type] = target_votes.get(server_type, 0) + count


def _identify_server_from_votes(
    votes: dict[str, int],
    evidence: list[ServerIdentificationEvidence],
    *,
    strong_evidence: bool,
) -> ServerIdentification | None:
    if not votes:
        return None

    candidate_server_types = tuple(sorted(votes))
    if len(candidate_server_types) > 1:
        return ServerIdentification(
            server_type=None,
            confidence="none",
            evidence=tuple(evidence),
            ambiguous=True,
            candidate_server_types=candidate_server_types,
        )

    best_type = candidate_server_types[0]
    confidence: IdentificationConfidence
    if strong_evidence:
        confidence = "high"
    elif votes[best_type] > 1:
        confidence = "medium"
    else:
        confidence = "low"

    return ServerIdentification(
        server_type=best_type,
        confidence=confidence,
        evidence=tuple(evidence),
        candidate_server_types=candidate_server_types,
    )


def _collect_server_header_evidence(
    attempt: ProbeAttempt,
    evidence: list[ServerIdentificationEvidence],
    votes: dict[str, int],
) -> None:
    server_header = attempt.server_header
    if server_header is None:
        return

    lower = server_header.lower()
    for signatures, server_type in _SERVER_HEADER_SIGNATURES:
        for sig in signatures:
            if sig in lower:
                evidence.append(
                    ServerIdentificationEvidence(
                        source_url=attempt.target.url,
                        signal="server_header",
                        value=server_header,
                        indicates=server_type,
                        strength="strong",
                        detail=(
                            f"Server header '{server_header}' contains "
                            f"'{sig}', a strong indicator of {server_type}."
                        ),
                    )
                )
                votes[server_type] = votes.get(server_type, 0) + 2
                return

    if lower == "iis":
        evidence.append(
            ServerIdentificationEvidence(
                source_url=attempt.target.url,
                signal="server_header",
                value=server_header,
                indicates="iis",
                strength="strong",
                detail=f"Server header '{server_header}' exactly matches IIS.",
            )
        )
        votes["iis"] = votes.get("iis", 0) + 2


def _collect_x_powered_by_evidence(
    attempt: ProbeAttempt,
    evidence: list[ServerIdentificationEvidence],
    votes: dict[str, int],
) -> None:
    x_powered_by = attempt.x_powered_by_header
    if x_powered_by is None:
        return

    lower = x_powered_by.lower()
    if "asp.net" in lower:
        evidence.append(
            ServerIdentificationEvidence(
                source_url=attempt.target.url,
                signal="x_powered_by_header",
                value=x_powered_by,
                indicates="iis",
                strength="moderate",
                detail=(
                    f"X-Powered-By header '{x_powered_by}' references ASP.NET, "
                    "commonly associated with IIS."
                ),
            )
        )
        votes["iis"] = votes.get("iis", 0) + 1
    elif "php" in lower:
        evidence.append(
            ServerIdentificationEvidence(
                source_url=attempt.target.url,
                signal="x_powered_by_header",
                value=x_powered_by,
                indicates=None,
                strength="weak",
                detail=(
                    f"X-Powered-By header '{x_powered_by}' references PHP, "
                    "which is retained as application-stack evidence but not used "
                    "to classify the web server."
                ),
            )
        )


def _collect_extended_header_evidence(
    attempt: ProbeAttempt,
    evidence: list[ServerIdentificationEvidence],
    app_stack_votes: dict[str, int],
) -> None:
    """Collect fingerprinting evidence from extended response headers."""
    url = attempt.target.url

    # X-AspNetMvc-Version → IIS (moderate, same tier as X-AspNet-Version).
    if attempt.x_aspnetmvc_version_header:
        evidence.append(
            ServerIdentificationEvidence(
                source_url=url,
                signal="x_aspnetmvc_version_header",
                value=attempt.x_aspnetmvc_version_header,
                indicates="iis",
                strength="moderate",
                detail=(
                    f"X-AspNetMvc-Version header ({attempt.x_aspnetmvc_version_header}) "
                    "indicates an ASP.NET MVC runtime, commonly hosted on IIS."
                ),
            )
        )
        app_stack_votes["iis"] = app_stack_votes.get("iis", 0) + 1

    # Set-Cookie session ID patterns.
    for cookie in attempt.set_cookie_headers:
        cookie_lower = cookie.lower()
        if "asp.net_sessionid=" in cookie_lower or "aspxauth=" in cookie_lower:
            evidence.append(
                ServerIdentificationEvidence(
                    source_url=url,
                    signal="set_cookie_session",
                    value=cookie.split("=", 1)[0].strip(),
                    indicates="iis",
                    strength="moderate",
                    detail=(
                        "Set-Cookie contains ASP.NET session identifier, "
                        "commonly associated with IIS."
                    ),
                )
            )
            app_stack_votes["iis"] = app_stack_votes.get("iis", 0) + 1
            break

    # Via header — can reveal proxied server software.
    if attempt.via_header:
        via_lower = attempt.via_header.lower()
        for signatures, server_type in _SERVER_HEADER_SIGNATURES:
            for sig in signatures:
                if sig in via_lower:
                    evidence.append(
                        ServerIdentificationEvidence(
                            source_url=url,
                            signal="via_header",
                            value=attempt.via_header,
                            indicates=server_type,
                            strength="weak",
                            detail=(
                                f"Via header '{attempt.via_header}' contains "
                                f"'{sig}', a weak indicator of {server_type}."
                            ),
                        )
                    )
                    # Weak signal — no vote, just evidence.
                    break
            else:
                continue
            break


def _collect_error_page_evidence(
    probe: ErrorPageProbe,
    evidence: list[ServerIdentificationEvidence],
    votes: dict[str, int],
) -> None:
    """Extract fingerprinting evidence from a default error page body."""
    if not _is_error_status(probe.status_code):
        return
    if probe.body_snippet is None:
        return

    matched = _match_error_page_body(probe.body_snippet)
    if matched is None:
        return

    # Truncate snippet for evidence display.
    snippet_display = probe.body_snippet[:120]
    if len(probe.body_snippet) > 120:
        snippet_display += "..."

    evidence.append(
        ServerIdentificationEvidence(
            source_url=probe.url,
            signal="error_page_body",
            value=snippet_display,
            indicates=matched,
            strength="moderate",
            detail=(
                f"Default error page body at {probe.url} matches "
                f"known {matched} error page signature."
            ),
        )
    )
    votes[matched] = votes.get(matched, 0) + 1


def _error_page_probe_to_metadata(probe: ErrorPageProbe) -> dict[str, object]:
    snippet = probe.body_snippet
    if snippet is not None and len(snippet) > 256:
        snippet = snippet[:256] + "..."
    return {
        "url": probe.url,
        "status_code": probe.status_code,
        "server_header": probe.server_header,
        "body_snippet": snippet,
        "error_message": probe.error_message,
    }


def _collect_malformed_request_evidence(
    probe: MalformedRequestProbe,
    evidence: list[ServerIdentificationEvidence],
    server_header_votes: dict[str, int],
    body_votes: dict[str, int],
) -> None:
    """Extract fingerprinting evidence from a malformed-request response."""
    if not _is_error_status(probe.status_code):
        return
    # 1. Server header from the malformed response (strong).
    if probe.server_header:
        lower = probe.server_header.lower()
        for signatures, server_type in _SERVER_HEADER_SIGNATURES:
            for sig in signatures:
                if sig in lower:
                    evidence.append(
                        ServerIdentificationEvidence(
                            source_url=probe.url,
                            signal="malformed_response_server_header",
                            value=probe.server_header,
                            indicates=server_type,
                            strength="strong",
                            detail=(
                                f"Server header '{probe.server_header}' in 400 response "
                                f"contains '{sig}', a strong indicator of {server_type}."
                            ),
                        )
                    )
                    server_header_votes[server_type] = server_header_votes.get(server_type, 0) + 2
                    break
            else:
                continue
            break

    # 2. Body signature from the malformed response (moderate).
    if probe.body_snippet:
        matched = _match_malformed_response_body(probe.body_snippet)
        if matched is not None:
            snippet_display = probe.body_snippet[:120]
            if len(probe.body_snippet) > 120:
                snippet_display += "..."
            evidence.append(
                ServerIdentificationEvidence(
                    source_url=probe.url,
                    signal="malformed_response_body",
                    value=snippet_display,
                    indicates=matched,
                    strength="moderate",
                    detail=(
                        f"Malformed-request response body at {probe.url} matches "
                        f"known {matched} error signature."
                    ),
                )
            )
            body_votes[matched] = body_votes.get(matched, 0) + 1


def _malformed_request_probe_to_metadata(probe: MalformedRequestProbe) -> dict[str, object]:
    snippet = probe.body_snippet
    if snippet is not None and len(snippet) > 256:
        snippet = snippet[:256] + "..."
    return {
        "url": probe.url,
        "status_code": probe.status_code,
        "reason_phrase": probe.reason_phrase,
        "server_header": probe.server_header,
        "body_snippet": snippet,
        "error_message": probe.error_message,
    }


def _server_identification_to_metadata(
    identification: ServerIdentification,
) -> dict[str, object]:
    return {
        "server_type": identification.server_type,
        "confidence": identification.confidence,
        "ambiguous": identification.ambiguous,
        "candidate_server_types": list(identification.candidate_server_types),
        "evidence": [
            {
                "source_url": e.source_url,
                "signal": e.signal,
                "value": e.value,
                "indicates": e.indicates,
                "strength": e.strength,
                "detail": e.detail,
            }
            for e in identification.evidence
        ],
    }


__all__ = [
    "ErrorPageProbe",
    "MalformedRequestProbe",
    "OptionsObservation",
    "ProbeAttempt",
    "SensitivePathProbe",
    "ProbeMethod",
    "ProbeTarget",
    "ServerIdentification",
    "ServerIdentificationEvidence",
    "TLSInfo",
    "analyze_external_target",
]
