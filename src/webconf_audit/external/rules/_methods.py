from __future__ import annotations

from typing import TYPE_CHECKING

from webconf_audit.external.rules._helpers import (
    _ALLOW_HEADER_DANGEROUS_METHODS,
    _DANGEROUS_METHODS,
    _WEBDAV_METHODS,
    _parse_options_methods,
)
from webconf_audit.models import Finding, SourceLocation

if TYPE_CHECKING:
    from webconf_audit.external.recon import ProbeAttempt


def _find_trace_method_allowed(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in probe_attempts:
        if not attempt.has_http_response:
            continue
        if attempt.allow_header is None:
            continue

        methods = {m.strip().upper() for m in attempt.allow_header.split(",")}
        if "TRACE" not in methods:
            continue

        findings.append(
            Finding(
                rule_id="external.trace_method_allowed",
                title="TRACE method allowed",
                severity="low",
                description=(
                    "The Allow header advertises TRACE as a permitted HTTP method. "
                    "TRACE can be exploited for cross-site tracing attacks."
                ),
                recommendation=(
                    "Disable the TRACE HTTP method on the web server unless "
                    "it is explicitly required for diagnostics."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="Allow",
                ),
            )
        )

    return findings


def _find_allow_header_dangerous_methods(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    """Dangerous methods (excluding TRACE) in primary probe Allow header."""
    findings: list[Finding] = []

    for attempt in probe_attempts:
        if not attempt.has_http_response:
            continue
        if attempt.allow_header is None:
            continue

        methods = {m.strip().upper() for m in attempt.allow_header.split(",")}
        dangerous_found = methods & _ALLOW_HEADER_DANGEROUS_METHODS
        if not dangerous_found:
            continue

        findings.append(
            Finding(
                rule_id="external.allow_header_dangerous_methods",
                title="Dangerous HTTP methods in Allow header",
                severity="medium",
                description=(
                    f"The Allow header from the primary probe advertises "
                    f"potentially dangerous HTTP methods: "
                    f"{', '.join(sorted(dangerous_found))}."
                ),
                recommendation=(
                    "Disable HTTP methods that are not required by the "
                    "application, especially PUT, DELETE, CONNECT, and TRACK."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details=f"Allow: {attempt.allow_header}",
                ),
            )
        )

    return findings


def _find_options_method_exposed(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in probe_attempts:
        if not attempt.has_http_response:
            continue
        obs = attempt.options_observation
        if obs is None or obs.status_code is None:
            continue

        methods = _parse_options_methods(obs)
        if not methods:
            continue

        findings.append(
            Finding(
                rule_id="external.options_method_exposed",
                title="OPTIONS method exposes allowed methods",
                severity="info",
                description=(
                    f"The OPTIONS response exposes the following HTTP methods: "
                    f"{', '.join(sorted(methods))}."
                ),
                recommendation=(
                    "If method disclosure is not intended, disable or restrict "
                    "the OPTIONS HTTP method on the web server."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="OPTIONS Allow/Public",
                ),
            )
        )

    return findings


def _find_dangerous_http_methods_enabled(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in probe_attempts:
        if not attempt.has_http_response:
            continue
        obs = attempt.options_observation
        if obs is None or obs.status_code is None:
            continue

        methods = _parse_options_methods(obs)
        dangerous_found = methods & _DANGEROUS_METHODS
        if not dangerous_found:
            continue

        findings.append(
            Finding(
                rule_id="external.dangerous_http_methods_enabled",
                title="Dangerous HTTP methods enabled",
                severity="medium",
                description=(
                    f"The OPTIONS response indicates that the following potentially "
                    f"dangerous HTTP methods are enabled: "
                    f"{', '.join(sorted(dangerous_found))}."
                ),
                recommendation=(
                    "Disable HTTP methods that are not required by the application, "
                    "especially TRACE, TRACK, PUT, DELETE, and CONNECT."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="OPTIONS",
                ),
            )
        )

    return findings


def _find_trace_method_exposed_via_options(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in probe_attempts:
        source_detail = _trace_method_options_source_detail(attempt)
        if source_detail is None:
            continue

        findings.append(
            Finding(
                rule_id="external.trace_method_exposed_via_options",
                title="TRACE method exposed via OPTIONS",
                severity="low",
                description=(
                    "The OPTIONS response reveals that the TRACE HTTP method is enabled, "
                    "even though it was not advertised in the primary probe's Allow header. "
                    "TRACE can be exploited for cross-site tracing attacks."
                ),
                recommendation=(
                    "Disable the TRACE HTTP method on the web server unless "
                    "it is explicitly required for diagnostics."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details=source_detail,
                ),
            )
        )

    return findings


def _trace_method_options_source_detail(attempt: "ProbeAttempt") -> str | None:
    if not attempt.has_http_response:
        return None

    obs = attempt.options_observation
    if obs is None or obs.status_code is None:
        return None
    if "TRACE" not in _parse_options_methods(obs):
        return None
    if "TRACE" in _header_methods(attempt.allow_header):
        return None
    if "TRACE" in _header_methods(obs.allow_header):
        return "OPTIONS Allow"
    return "OPTIONS Public"


def _find_webdav_methods_exposed(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    """WebDAV methods exposed via Allow header or OPTIONS observation."""
    findings: list[Finding] = []

    for attempt in probe_attempts:
        exposure = _webdav_exposure(attempt)
        if exposure is None:
            continue

        all_methods, source_label = exposure
        findings.append(
            Finding(
                rule_id="external.webdav_methods_exposed",
                title="WebDAV methods exposed",
                severity="medium",
                description=(
                    f"The server exposes WebDAV HTTP methods via {source_label}: "
                    f"{', '.join(sorted(all_methods))}. WebDAV methods can allow "
                    f"unauthorized file manipulation if not properly secured."
                ),
                recommendation=(
                    "Disable WebDAV methods unless they are explicitly required "
                    "by the application. If WebDAV is needed, restrict access "
                    "to authorized users only."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details=source_label,
                ),
            )
        )

    return findings


def _webdav_exposure(
    attempt: "ProbeAttempt",
) -> tuple[set[str], str] | None:
    if not attempt.has_http_response:
        return None

    all_methods: set[str] = set()
    sources: list[str] = []
    _merge_webdav_source(
        all_methods,
        sources,
        _header_methods(attempt.allow_header) & _WEBDAV_METHODS,
        "Allow",
    )

    obs = attempt.options_observation
    if obs is not None and obs.status_code is not None:
        _merge_webdav_source(
            all_methods,
            sources,
            _header_methods(obs.allow_header) & _WEBDAV_METHODS,
            "OPTIONS Allow",
        )
        _merge_webdav_source(
            all_methods,
            sources,
            _header_methods(obs.public_header) & _WEBDAV_METHODS,
            "OPTIONS Public",
        )

    if not all_methods:
        return None
    return all_methods, ", ".join(sources)


def _merge_webdav_source(
    all_methods: set[str],
    sources: list[str],
    source_methods: set[str],
    label: str,
) -> None:
    if not source_methods:
        return

    new_methods = source_methods - all_methods
    all_methods.update(source_methods)
    if new_methods:
        sources.append(label)


def _header_methods(value: str | None) -> set[str]:
    if value is None:
        return set()
    return {method.strip().upper() for method in value.split(",") if method.strip()}


def collect_method_findings(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_find_trace_method_allowed(probe_attempts))
    findings.extend(_find_allow_header_dangerous_methods(probe_attempts))
    findings.extend(_find_options_method_exposed(probe_attempts))
    findings.extend(_find_dangerous_http_methods_enabled(probe_attempts))
    findings.extend(_find_trace_method_exposed_via_options(probe_attempts))
    findings.extend(_find_webdav_methods_exposed(probe_attempts))
    return findings


__all__ = [
    "collect_method_findings",
]
