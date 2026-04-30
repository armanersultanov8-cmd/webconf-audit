from __future__ import annotations

from typing import TYPE_CHECKING

from webconf_audit.external.rules._helpers import (
    _VERSION_PATTERN,
    _is_iis_conditional_applicable,
    _is_server_header_handled_by_conditional_rule,
)
from webconf_audit.models import Finding, SourceLocation

if TYPE_CHECKING:
    from webconf_audit.external.recon import ProbeAttempt, ServerIdentification


def collect_disclosure_findings(
    probe_attempts: list[ProbeAttempt],
    server_identification: ServerIdentification | None = None,
) -> list[Finding]:
    version_findings: list[Finding] = []
    powered_by_findings: list[Finding] = []
    aspnet_findings: list[Finding] = []
    skip_generic_aspnet = _is_iis_conditional_applicable(server_identification)

    for attempt in probe_attempts:
        if not attempt.has_http_response:
            continue
        version_findings.extend(
            _version_disclosure_findings_for_attempt(
                attempt, server_identification,
            )
        )
        powered_by_finding = _x_powered_by_finding_if_present(attempt)
        if powered_by_finding is not None:
            powered_by_findings.append(powered_by_finding)
        aspnet_finding = _x_aspnet_version_finding_if_applicable(
            attempt,
            skip_generic_aspnet=skip_generic_aspnet,
        )
        if aspnet_finding is not None:
            aspnet_findings.append(aspnet_finding)

    return [*version_findings, *powered_by_findings, *aspnet_findings]


def _version_disclosure_findings_for_attempt(
    attempt: ProbeAttempt,
    server_identification: ServerIdentification | None,
) -> list[Finding]:
    findings: list[Finding] = []
    for header_name, header_value in _version_sources(attempt):
        if _skip_generic_server_disclosure(
            header_name, header_value, server_identification,
        ):
            continue
        if not _VERSION_PATTERN.search(header_value):
            continue
        findings.append(
            _server_version_disclosed_finding(attempt, header_name, header_value)
        )
    return findings


def _version_sources(attempt: ProbeAttempt) -> list[tuple[str, str]]:
    sources: list[tuple[str, str]] = []
    if attempt.server_header is not None:
        sources.append(("Server", attempt.server_header))
    if attempt.x_powered_by_header is not None:
        sources.append(("X-Powered-By", attempt.x_powered_by_header))
    if attempt.x_aspnet_version_header is not None:
        sources.append(("X-AspNet-Version", attempt.x_aspnet_version_header))
    return sources


def _skip_generic_server_disclosure(
    header_name: str,
    header_value: str,
    server_identification: ServerIdentification | None,
) -> bool:
    return (
        header_name == "Server"
        and _is_server_header_handled_by_conditional_rule(
            header_value,
            server_identification,
        )
    )


def _x_powered_by_finding_if_present(attempt: ProbeAttempt) -> Finding | None:
    if not attempt.x_powered_by_header:
        return None
    return _x_powered_by_finding(attempt)


def _x_aspnet_version_finding_if_applicable(
    attempt: ProbeAttempt,
    *,
    skip_generic_aspnet: bool,
) -> Finding | None:
    if not attempt.x_aspnet_version_header or skip_generic_aspnet:
        return None
    return _x_aspnet_version_finding(attempt)


def _server_version_disclosed_finding(
    attempt: ProbeAttempt,
    header_name: str,
    header_value: str,
) -> Finding:
    return Finding(
        rule_id="external.server_version_disclosed",
        title="Server version disclosed",
        severity="low",
        description=f"{header_name} header discloses version information: {header_value}",
        recommendation=(
            f"Configure the web server to suppress version details "
            f"from the {header_name} header."
        ),
        location=SourceLocation(
            mode="external",
            kind="header",
            target=attempt.target.url,
            details=f"{header_name}: {header_value}",
        ),
    )


def _x_powered_by_finding(attempt: ProbeAttempt) -> Finding:
    return Finding(
        rule_id="external.x_powered_by_header_present",
        title="X-Powered-By header present",
        severity="low",
        description=(
            "The response exposes an X-Powered-By header, which may "
            "reveal framework or technology details."
        ),
        recommendation=(
            "Remove the X-Powered-By header unless this disclosure "
            "is intentionally required."
        ),
        location=SourceLocation(
            mode="external",
            kind="header",
            target=attempt.target.url,
            details=f"X-Powered-By: {attempt.x_powered_by_header}",
        ),
    )


def _x_aspnet_version_finding(attempt: ProbeAttempt) -> Finding:
    return Finding(
        rule_id="external.x_aspnet_version_header_present",
        title="X-AspNet-Version header present",
        severity="low",
        description=(
            "The response exposes an X-AspNet-Version header, which "
            "reveals ASP.NET version details."
        ),
        recommendation=(
            "Suppress the X-AspNet-Version header unless exposing "
            "the framework version is intentionally required."
        ),
        location=SourceLocation(
            mode="external",
            kind="header",
            target=attempt.target.url,
            details=f"X-AspNet-Version: {attempt.x_aspnet_version_header}",
        ),
    )


__all__ = [
    "collect_disclosure_findings",
]
