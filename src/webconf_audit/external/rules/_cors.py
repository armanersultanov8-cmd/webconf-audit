from __future__ import annotations

from typing import TYPE_CHECKING

from webconf_audit.models import Finding, SourceLocation

if TYPE_CHECKING:
    from webconf_audit.external.recon import ProbeAttempt


def _find_cors_wildcard_origin(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in probe_attempts:
        if not attempt.has_http_response:
            continue
        if attempt.access_control_allow_origin_header is None:
            continue
        if attempt.access_control_allow_origin_header.strip() != "*":
            continue
        if (
            attempt.access_control_allow_credentials_header is not None
            and attempt.access_control_allow_credentials_header.strip().lower() == "true"
        ):
            continue

        findings.append(
            Finding(
                rule_id="external.cors_wildcard_origin",
                title="CORS allows any origin",
                severity="low",
                description=(
                    "The response includes Access-Control-Allow-Origin: *, "
                    "which permits any origin to read the response."
                ),
                recommendation=(
                    "Restrict Access-Control-Allow-Origin to specific trusted "
                    "origins unless public access is intentionally required."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="Access-Control-Allow-Origin",
                ),
            )
        )

    return findings


def _find_cors_wildcard_with_credentials(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in probe_attempts:
        if not attempt.has_http_response:
            continue
        if attempt.access_control_allow_origin_header is None:
            continue
        if attempt.access_control_allow_origin_header.strip() != "*":
            continue
        if attempt.access_control_allow_credentials_header is None:
            continue
        if attempt.access_control_allow_credentials_header.strip().lower() != "true":
            continue

        findings.append(
            Finding(
                rule_id="external.cors_wildcard_with_credentials",
                title="CORS wildcard origin with credentials",
                severity="medium",
                description=(
                    "The response includes Access-Control-Allow-Origin: * together "
                    "with Access-Control-Allow-Credentials: true. This combination "
                    "is insecure and may expose credentialed responses to any origin."
                ),
                recommendation=(
                    "Do not combine wildcard Access-Control-Allow-Origin with "
                    "Access-Control-Allow-Credentials: true. Use a specific origin "
                    "when credentials are required."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="Access-Control-Allow-Origin, Access-Control-Allow-Credentials",
                ),
            )
        )

    return findings


def collect_cors_findings(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_find_cors_wildcard_origin(probe_attempts))
    findings.extend(_find_cors_wildcard_with_credentials(probe_attempts))
    return findings


__all__ = [
    "collect_cors_findings",
]
