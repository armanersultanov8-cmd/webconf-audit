from __future__ import annotations

from typing import TYPE_CHECKING

from webconf_audit.external.rules._helpers import (
    _APACHE_INODE_ETAG_PATTERN,
    _is_accessible_status,
    _is_apache_conditional_applicable,
    _is_apache_server_header,
    _is_iis_conditional_applicable,
    _is_lighttpd_conditional_applicable,
    _is_lighttpd_server_header,
    _is_nginx_conditional_applicable,
    _is_nginx_family_server_header,
    _looks_like_iis_detailed_error,
    _looks_like_nginx_default_welcome_page,
)
from webconf_audit.models import Finding, SourceLocation

if TYPE_CHECKING:
    from webconf_audit.external.recon import (
        ProbeAttempt,
        SensitivePathProbe,
        ServerIdentification,
    )


def _find_nginx_version_disclosed_in_server_header(
    probe_attempts: list["ProbeAttempt"],
    server_identification: "ServerIdentification | None",
) -> list[Finding]:
    if not _is_nginx_conditional_applicable(server_identification):
        return []

    findings: list[Finding] = []
    for attempt in probe_attempts:
        if not attempt.has_http_response:
            continue
        if attempt.server_header is None:
            continue
        if not _is_nginx_family_server_header(attempt.server_header):
            continue

        findings.append(
            Finding(
                rule_id="external.nginx.version_disclosed_in_server_header",
                title="Nginx version disclosed in Server header",
                severity="low",
                description=(
                    "The Server header discloses an nginx-family version string: "
                    f"{attempt.server_header}"
                ),
                recommendation=(
                    "Configure nginx or the reverse proxy layer to suppress "
                    "version details in the Server header."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details=f"Server: {attempt.server_header}",
                ),
            )
        )

    return findings


def _find_nginx_default_welcome_page(
    probe_attempts: list["ProbeAttempt"],
    server_identification: "ServerIdentification | None",
) -> list[Finding]:
    if not _is_nginx_conditional_applicable(server_identification):
        return []

    findings: list[Finding] = []
    for attempt in probe_attempts:
        if not attempt.has_http_response:
            continue
        if attempt.status_code != 200:
            continue
        if attempt.target.path != "/":
            continue
        if attempt.body_snippet is None:
            continue
        if not _looks_like_nginx_default_welcome_page(attempt.body_snippet):
            continue

        findings.append(
            Finding(
                rule_id="external.nginx.default_welcome_page",
                title="Default nginx welcome page exposed",
                severity="medium",
                description=(
                    "The externally visible root page matches the default nginx "
                    "welcome page, indicating a default or placeholder "
                    "deployment is still exposed."
                ),
                recommendation=(
                    "Replace the default nginx welcome page with the intended "
                    "application content or a hardened maintenance page."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="url",
                    target=attempt.target.url,
                    details="default nginx welcome page",
                ),
            )
        )

    return findings


def _find_apache_version_disclosed_in_server_header(
    probe_attempts: list["ProbeAttempt"],
    server_identification: "ServerIdentification | None",
) -> list[Finding]:
    if not _is_apache_conditional_applicable(server_identification):
        return []

    findings: list[Finding] = []
    for attempt in probe_attempts:
        if not attempt.has_http_response:
            continue
        if attempt.server_header is None:
            continue
        if not _is_apache_server_header(attempt.server_header):
            continue

        findings.append(
            Finding(
                rule_id="external.apache.version_disclosed_in_server_header",
                title="Apache version disclosed in Server header",
                severity="low",
                description=(
                    f"The Server header discloses Apache version details: {attempt.server_header}"
                ),
                recommendation=(
                    "Configure Apache to suppress version and platform details "
                    "in the Server header."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details=f"Server: {attempt.server_header}",
                ),
            )
        )

    return findings


def _find_apache_mod_status_public(
    path_probes: list["SensitivePathProbe"],
    server_identification: "ServerIdentification | None",
) -> list[Finding]:
    if not _is_apache_conditional_applicable(server_identification):
        return []

    findings: list[Finding] = []
    for probe in path_probes:
        if probe.path not in {"/server-status", "/server-status?auto"}:
            continue
        if not _is_accessible_status(probe.status_code):
            continue

        findings.append(
            Finding(
                rule_id="external.apache.mod_status_public",
                title="Apache mod_status exposed publicly",
                severity="medium",
                description=(
                    "Apache mod_status appears to be externally accessible "
                    f"at {probe.path}. It can expose worker state, request "
                    "activity, and operational details."
                ),
                recommendation=(
                    "Restrict mod_status to trusted networks or disable it "
                    "in the Apache configuration."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="url",
                    target=probe.url,
                    details=probe.path,
                ),
            )
        )

    return findings


def _find_apache_etag_inode_disclosure(
    probe_attempts: list["ProbeAttempt"],
    server_identification: "ServerIdentification | None",
) -> list[Finding]:
    if not _is_apache_conditional_applicable(server_identification):
        return []

    findings: list[Finding] = []
    for attempt in probe_attempts:
        if not attempt.has_http_response:
            continue
        if attempt.etag_header is None:
            continue
        if not _APACHE_INODE_ETAG_PATTERN.search(attempt.etag_header):
            continue

        findings.append(
            Finding(
                rule_id="external.apache.etag_inode_disclosure",
                title="Apache ETag reveals inode metadata",
                severity="low",
                description=(
                    "The ETag header appears to expose Apache inode-based "
                    f"metadata: {attempt.etag_header}"
                ),
                recommendation=(
                    "Disable inode-based ETag components, for example by "
                    "setting FileETag to avoid inode disclosure."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details=f"ETag: {attempt.etag_header}",
                ),
            )
        )

    return findings


def _find_iis_aspnet_version_header_present(
    probe_attempts: list["ProbeAttempt"],
    server_identification: "ServerIdentification | None",
) -> list[Finding]:
    if not _is_iis_conditional_applicable(server_identification):
        return []

    findings: list[Finding] = []
    for attempt in probe_attempts:
        if not attempt.has_http_response:
            continue
        if not attempt.x_aspnet_version_header:
            continue

        findings.append(
            Finding(
                rule_id="external.iis.aspnet_version_header_present",
                title="IIS X-AspNet-Version header present",
                severity="low",
                description=(
                    "The response exposes an X-AspNet-Version header on an "
                    "endpoint identified as IIS, revealing ASP.NET runtime "
                    "details."
                ),
                recommendation=(
                    "Suppress the X-AspNet-Version header in IIS/ASP.NET unless "
                    "this disclosure is intentionally required."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="X-AspNet-Version",
                ),
            )
        )

    return findings


def _find_iis_detailed_error_page(
    server_identification: "ServerIdentification | None",
) -> list[Finding]:
    if not _is_iis_conditional_applicable(server_identification):
        return []
    if server_identification is None:
        return []

    findings: list[Finding] = []
    seen_targets: set[str] = set()
    for evidence in server_identification.evidence:
        if evidence.indicates != "iis":
            continue
        if evidence.signal not in {"error_page_body", "malformed_response_body"}:
            continue
        if not _looks_like_iis_detailed_error(evidence.value):
            continue
        if evidence.source_url in seen_targets:
            continue

        seen_targets.add(evidence.source_url)
        findings.append(
            Finding(
                rule_id="external.iis.detailed_error_page",
                title="Detailed IIS error page exposed",
                severity="medium",
                description=(
                    "Externally visible IIS error content appears to expose a "
                    "detailed error page, which can leak application or "
                    "environment details."
                ),
                recommendation=(
                    "Disable detailed IIS/ASP.NET error pages for external "
                    "clients and return generic error responses instead."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="url",
                    target=evidence.source_url,
                    details=evidence.signal,
                ),
            )
        )

    return findings


def _find_lighttpd_version_in_server_header(
    probe_attempts: list["ProbeAttempt"],
    server_identification: "ServerIdentification | None",
) -> list[Finding]:
    if not _is_lighttpd_conditional_applicable(server_identification):
        return []

    findings: list[Finding] = []
    for attempt in probe_attempts:
        if not attempt.has_http_response:
            continue
        if attempt.server_header is None:
            continue
        if not _is_lighttpd_server_header(attempt.server_header):
            continue

        findings.append(
            Finding(
                rule_id="external.lighttpd.version_in_server_header",
                title="lighttpd version disclosed in Server header",
                severity="low",
                description=(
                    f"The Server header discloses lighttpd version details: {attempt.server_header}"
                ),
                recommendation=(
                    "Configure lighttpd to suppress version details in the Server header."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details=f"Server: {attempt.server_header}",
                ),
            )
        )

    return findings


def _find_lighttpd_mod_status_public(
    path_probes: list["SensitivePathProbe"],
    server_identification: "ServerIdentification | None",
) -> list[Finding]:
    if not _is_lighttpd_conditional_applicable(server_identification):
        return []

    findings: list[Finding] = []
    for probe in path_probes:
        if probe.path != "/server-status":
            continue
        if not _is_accessible_status(probe.status_code):
            continue

        findings.append(
            Finding(
                rule_id="external.lighttpd.mod_status_public",
                title="lighttpd mod_status exposed publicly",
                severity="medium",
                description=(
                    "lighttpd mod_status appears to be externally accessible "
                    "at /server-status, which can expose operational details."
                ),
                recommendation=(
                    "Restrict lighttpd mod_status to trusted networks or "
                    "disable it for external clients."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="url",
                    target=probe.url,
                    details=probe.path,
                ),
            )
        )

    return findings


def collect_conditional_findings(
    probe_attempts: list["ProbeAttempt"],
    path_probes: list["SensitivePathProbe"],
    server_identification: "ServerIdentification | None" = None,
) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(
        _find_nginx_version_disclosed_in_server_header(
            probe_attempts,
            server_identification,
        )
    )
    findings.extend(
        _find_nginx_default_welcome_page(
            probe_attempts,
            server_identification,
        )
    )
    findings.extend(
        _find_apache_version_disclosed_in_server_header(
            probe_attempts,
            server_identification,
        )
    )
    findings.extend(
        _find_apache_mod_status_public(
            path_probes,
            server_identification,
        )
    )
    findings.extend(
        _find_apache_etag_inode_disclosure(
            probe_attempts,
            server_identification,
        )
    )
    findings.extend(
        _find_iis_aspnet_version_header_present(
            probe_attempts,
            server_identification,
        )
    )
    findings.extend(
        _find_iis_detailed_error_page(
            server_identification,
        )
    )
    findings.extend(
        _find_lighttpd_version_in_server_header(
            probe_attempts,
            server_identification,
        )
    )
    findings.extend(
        _find_lighttpd_mod_status_public(
            path_probes,
            server_identification,
        )
    )
    return findings


__all__ = [
    "collect_conditional_findings",
]
