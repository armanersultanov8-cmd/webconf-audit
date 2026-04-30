from __future__ import annotations

from typing import TYPE_CHECKING

from webconf_audit.external.recon._cookie import (
    ParsedCookie,
    is_session_like_cookie,
    parse_cookie,
)
from webconf_audit.models import Finding, SourceLocation

if TYPE_CHECKING:
    from webconf_audit.external.recon import ProbeAttempt


def collect_cookie_findings(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in probe_attempts:
        if not attempt.has_http_response:
            continue
        for raw_cookie in attempt.set_cookie_headers:
            findings.extend(_findings_for_session_cookie(attempt, raw_cookie))

    return findings


def _findings_for_session_cookie(
    attempt: "ProbeAttempt",
    raw_cookie: str,
) -> list[Finding]:
    findings: list[Finding] = []
    cookie = parse_cookie(raw_cookie)
    if not is_session_like_cookie(cookie.name):
        return findings

    if attempt.target.scheme == "https" and not cookie.has_secure:
        findings.append(_missing_secure_finding(attempt, cookie))

    if not cookie.has_httponly:
        findings.append(_missing_httponly_finding(attempt, cookie))

    if cookie.samesite_value is None:
        findings.append(_missing_samesite_finding(attempt, cookie))
    elif cookie.samesite_value.lower() == "none" and not cookie.has_secure:
        findings.append(_samesite_none_without_secure_finding(attempt, cookie))

    return findings


def _cookie_finding(
    attempt: "ProbeAttempt",
    cookie: ParsedCookie,
    *,
    rule_id: str,
    title: str,
    description: str,
    recommendation: str,
) -> Finding:
    """Build a cookie-related finding with shared location logic."""
    return Finding(
        rule_id=rule_id,
        title=title,
        severity="low",
        description=description,
        recommendation=recommendation,
        location=SourceLocation(
            mode="external",
            kind="header",
            target=attempt.target.url,
            details=f"Set-Cookie: {cookie.name}",
        ),
    )


def _missing_secure_finding(
    attempt: "ProbeAttempt",
    cookie: ParsedCookie,
) -> Finding:
    return _cookie_finding(
        attempt,
        cookie,
        rule_id="external.cookie_missing_secure_on_https",
        title="Session cookie missing Secure flag",
        description=(
            f"HTTPS response sets a session-like cookie '{cookie.name}' "
            f"without the Secure attribute."
        ),
        recommendation=(
            f"Add the Secure attribute to the '{cookie.name}' cookie "
            f"so it is only sent over HTTPS."
        ),
    )


def _missing_httponly_finding(
    attempt: "ProbeAttempt",
    cookie: ParsedCookie,
) -> Finding:
    return _cookie_finding(
        attempt,
        cookie,
        rule_id="external.cookie_missing_httponly",
        title="Session cookie missing HttpOnly flag",
        description=(
            f"Response sets a session-like cookie '{cookie.name}' "
            f"without the HttpOnly attribute."
        ),
        recommendation=(
            f"Add the HttpOnly attribute to the '{cookie.name}' cookie "
            f"to prevent client-side script access."
        ),
    )


def _missing_samesite_finding(
    attempt: "ProbeAttempt",
    cookie: ParsedCookie,
) -> Finding:
    return _cookie_finding(
        attempt,
        cookie,
        rule_id="external.cookie_missing_samesite",
        title="Session cookie missing SameSite attribute",
        description=(
            f"Response sets a session-like cookie '{cookie.name}' "
            f"without the SameSite attribute."
        ),
        recommendation=(
            f"Add a SameSite attribute to the '{cookie.name}' cookie, "
            f"for example SameSite=Lax or SameSite=Strict."
        ),
    )


def _samesite_none_without_secure_finding(
    attempt: "ProbeAttempt",
    cookie: ParsedCookie,
) -> Finding:
    return _cookie_finding(
        attempt,
        cookie,
        rule_id="external.cookie_samesite_none_without_secure",
        title="Session cookie with SameSite=None missing Secure flag",
        description=(
            f"Response sets a session-like cookie '{cookie.name}' with "
            f"SameSite=None but without the Secure attribute. Modern "
            f"browsers reject SameSite=None cookies that lack the Secure flag."
        ),
        recommendation=(
            f"Add the Secure attribute to the '{cookie.name}' cookie "
            f"when using SameSite=None."
        ),
    )


__all__ = [
    "collect_cookie_findings",
]
