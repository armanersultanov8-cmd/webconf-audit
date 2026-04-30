from __future__ import annotations

from typing import TYPE_CHECKING

from webconf_audit.external.rules._helpers import (
    _HSTS_MAX_AGE_PATTERN,
    _HSTS_MIN_MAX_AGE,
    _PERMANENT_REDIRECT_STATUS_CODES,
    _attempt_redirects_to_https,
    _hsts_has_include_subdomains,
    _hsts_has_valid_max_age,
    _successful_attempts_for_scheme,
)
from webconf_audit.models import Finding, SourceLocation

if TYPE_CHECKING:
    from webconf_audit.external.recon import ProbeAttempt


def _find_https_not_available(probe_attempts: list["ProbeAttempt"], target: str) -> list[Finding]:
    if not any(attempt.has_http_response for attempt in probe_attempts):
        return []

    successful_https_attempts = _successful_attempts_for_scheme(probe_attempts, "https")
    if successful_https_attempts:
        return []

    https_targets = [
        attempt.target.url for attempt in probe_attempts if attempt.target.scheme == "https"
    ]
    target_summary = ", ".join(https_targets) if https_targets else target

    return [
        Finding(
            rule_id="external.https_not_available",
            title="HTTPS not available",
            severity="medium",
            description="External probe did not observe a successful HTTPS HTTP response.",
            recommendation="Expose a working HTTPS endpoint and verify it responds to external clients.",
            location=SourceLocation(
                mode="external",
                kind="endpoint",
                target=target_summary,
            ),
        )
    ]


def _find_http_not_redirected_to_https(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "http"):
        if _attempt_redirects_to_https(attempt):
            continue

        findings.append(
            Finding(
                rule_id="external.http_not_redirected_to_https",
                title="HTTP not redirected to HTTPS",
                severity="low",
                description="HTTP endpoint responded without redirecting the client to HTTPS.",
                recommendation="Configure the HTTP endpoint to redirect clients to an HTTPS URL.",
                location=SourceLocation(
                    mode="external",
                    kind="url",
                    target=attempt.target.url,
                ),
            )
        )

    return findings


def _find_hsts_header_missing(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.strict_transport_security_header is not None:
            continue

        findings.append(
            Finding(
                rule_id="external.hsts_header_missing",
                title="HSTS header missing",
                severity="low",
                description="HTTPS endpoint responded without a Strict-Transport-Security header.",
                recommendation="Add a Strict-Transport-Security header to the HTTPS response.",
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="Strict-Transport-Security",
                ),
            )
        )

    return findings


def _find_hsts_header_invalid(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.strict_transport_security_header is None:
            continue

        if _hsts_has_valid_max_age(attempt.strict_transport_security_header):
            continue

        findings.append(
            Finding(
                rule_id="external.hsts_header_invalid",
                title="HSTS header value invalid",
                severity="medium",
                description=(
                    "HTTPS endpoint responded with a Strict-Transport-Security header, "
                    "but the value does not contain a valid positive max-age directive."
                ),
                recommendation=(
                    "Set Strict-Transport-Security with a valid positive max-age value, "
                    "for example max-age=31536000."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="Strict-Transport-Security",
                ),
            )
        )

    return findings


def _find_hsts_max_age_too_short(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.strict_transport_security_header is None:
            continue

        match = _HSTS_MAX_AGE_PATTERN.search(attempt.strict_transport_security_header)
        if match is None:
            continue

        max_age = int(match.group(1))
        if max_age <= 0 or max_age >= _HSTS_MIN_MAX_AGE:
            continue

        findings.append(
            Finding(
                rule_id="external.hsts_max_age_too_short",
                title="HSTS max-age too short",
                severity="low",
                description=(
                    f"HTTPS endpoint sets Strict-Transport-Security with "
                    f"max-age={max_age}, which is below the recommended "
                    f"minimum of {_HSTS_MIN_MAX_AGE} seconds (1 year)."
                ),
                recommendation=(
                    "Increase the HSTS max-age directive to at least "
                    "31536000 (1 year) for effective protection."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details=f"Strict-Transport-Security: {attempt.strict_transport_security_header}",
                ),
            )
        )

    return findings


def _find_hsts_missing_include_subdomains(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.strict_transport_security_header is None:
            continue

        if not _hsts_has_valid_max_age(attempt.strict_transport_security_header):
            continue

        if _hsts_has_include_subdomains(attempt.strict_transport_security_header):
            continue

        findings.append(
            Finding(
                rule_id="external.hsts_missing_include_subdomains",
                title="HSTS missing includeSubDomains directive",
                severity="info",
                description=(
                    "The Strict-Transport-Security header does not include the "
                    "includeSubDomains directive. Subdomains are not covered by "
                    "the HSTS policy and may be vulnerable to downgrade attacks."
                ),
                recommendation=(
                    "Add the includeSubDomains directive to the "
                    "Strict-Transport-Security header if all subdomains also "
                    "support HTTPS."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details=f"Strict-Transport-Security: {attempt.strict_transport_security_header}",
                ),
            )
        )

    return findings


def _find_http_redirect_not_permanent(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "http"):
        if not _attempt_redirects_to_https(attempt):
            continue

        if attempt.status_code in _PERMANENT_REDIRECT_STATUS_CODES:
            continue

        findings.append(
            Finding(
                rule_id="external.http_redirect_not_permanent",
                title="HTTP-to-HTTPS redirect is not permanent",
                severity="info",
                description=(
                    f"HTTP endpoint redirects to HTTPS using status {attempt.status_code}, "
                    "which is a temporary redirect. Browsers and search engines may not "
                    "cache this redirect reliably."
                ),
                recommendation=(
                    "Use a permanent redirect status (301 or 308) for the HTTP-to-HTTPS redirect."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="url",
                    target=attempt.target.url,
                    details=f"status: {attempt.status_code}, Location: {attempt.location_header}",
                ),
            )
        )

    return findings


def collect_https_findings(
    probe_attempts: list["ProbeAttempt"],
    target: str,
) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_find_https_not_available(probe_attempts, target))
    findings.extend(_find_http_not_redirected_to_https(probe_attempts))
    findings.extend(_find_http_redirect_not_permanent(probe_attempts))
    findings.extend(_find_hsts_header_missing(probe_attempts))
    findings.extend(_find_hsts_header_invalid(probe_attempts))
    findings.extend(_find_hsts_max_age_too_short(probe_attempts))
    findings.extend(_find_hsts_missing_include_subdomains(probe_attempts))
    return findings


__all__ = [
    "collect_https_findings",
]
