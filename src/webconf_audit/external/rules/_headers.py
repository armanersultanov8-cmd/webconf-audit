from __future__ import annotations

from typing import TYPE_CHECKING

from webconf_audit.external.rules._helpers import _successful_attempts_for_scheme
from webconf_audit.models import Finding, SourceLocation

if TYPE_CHECKING:
    from webconf_audit.external.recon import ProbeAttempt


def _find_x_frame_options_missing(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.x_frame_options_header is not None:
            continue

        findings.append(
            Finding(
                rule_id="external.x_frame_options_missing",
                title="X-Frame-Options header missing",
                severity="low",
                description="HTTPS endpoint responded without an X-Frame-Options header.",
                recommendation="Add an X-Frame-Options header (e.g. DENY or SAMEORIGIN) to prevent clickjacking.",
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="X-Frame-Options",
                ),
            )
        )

    return findings


def _find_x_frame_options_invalid(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.x_frame_options_header is None:
            continue

        normalized = attempt.x_frame_options_header.strip().upper()
        if normalized in {"DENY", "SAMEORIGIN"}:
            continue

        findings.append(
            Finding(
                rule_id="external.x_frame_options_invalid",
                title="X-Frame-Options header value invalid",
                severity="low",
                description=(
                    "HTTPS endpoint responded with an X-Frame-Options header, "
                    "but the value is not a recognized restrictive setting."
                ),
                recommendation="Use X-Frame-Options with DENY or SAMEORIGIN.",
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="X-Frame-Options",
                ),
            )
        )

    return findings


def _find_x_content_type_options_missing(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.x_content_type_options_header is not None:
            continue

        findings.append(
            Finding(
                rule_id="external.x_content_type_options_missing",
                title="X-Content-Type-Options header missing",
                severity="low",
                description="HTTPS endpoint responded without an X-Content-Type-Options header.",
                recommendation="Add an X-Content-Type-Options: nosniff header to prevent MIME-type sniffing.",
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="X-Content-Type-Options",
                ),
            )
        )

    return findings


def _find_x_content_type_options_invalid(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.x_content_type_options_header is None:
            continue

        normalized = attempt.x_content_type_options_header.strip().lower()
        if normalized == "nosniff":
            continue

        findings.append(
            Finding(
                rule_id="external.x_content_type_options_invalid",
                title="X-Content-Type-Options header value invalid",
                severity="low",
                description=(
                    "HTTPS endpoint responded with an X-Content-Type-Options header, "
                    "but the value is not nosniff."
                ),
                recommendation="Set X-Content-Type-Options to nosniff.",
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="X-Content-Type-Options",
                ),
            )
        )

    return findings


def _find_content_security_policy_missing(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.content_security_policy_header is not None:
            continue

        findings.append(
            Finding(
                rule_id="external.content_security_policy_missing",
                title="Content-Security-Policy header missing",
                severity="medium",
                description="HTTPS endpoint responded without a Content-Security-Policy header.",
                recommendation="Add a Content-Security-Policy header to mitigate cross-site scripting and injection attacks.",
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="Content-Security-Policy",
                ),
            )
        )

    return findings


def _find_content_security_policy_unsafe_inline(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.content_security_policy_header is None:
            continue

        if "'unsafe-inline'" not in attempt.content_security_policy_header.lower():
            continue

        findings.append(
            Finding(
                rule_id="external.content_security_policy_unsafe_inline",
                title="Content-Security-Policy allows unsafe-inline",
                severity="medium",
                description=(
                    "The Content-Security-Policy header contains 'unsafe-inline', "
                    "which permits inline scripts or styles and weakens XSS protection."
                ),
                recommendation=(
                    "Remove 'unsafe-inline' from the Content-Security-Policy and use "
                    "nonce-based or hash-based allowlisting for inline scripts."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details=f"Content-Security-Policy: {attempt.content_security_policy_header}",
                ),
            )
        )

    return findings


def _find_content_security_policy_unsafe_eval(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.content_security_policy_header is None:
            continue

        if "'unsafe-eval'" not in attempt.content_security_policy_header.lower():
            continue

        findings.append(
            Finding(
                rule_id="external.content_security_policy_unsafe_eval",
                title="Content-Security-Policy allows unsafe-eval",
                severity="medium",
                description=(
                    "The Content-Security-Policy header contains 'unsafe-eval', "
                    "which permits dynamic code execution via eval() and weakens "
                    "XSS protection."
                ),
                recommendation=(
                    "Remove 'unsafe-eval' from the Content-Security-Policy and "
                    "refactor application code to avoid eval()."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details=f"Content-Security-Policy: {attempt.content_security_policy_header}",
                ),
            )
        )

    return findings


def _find_referrer_policy_missing(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.referrer_policy_header is not None:
            continue

        findings.append(
            Finding(
                rule_id="external.referrer_policy_missing",
                title="Referrer-Policy header missing",
                severity="info",
                description="HTTPS endpoint responded without a Referrer-Policy header.",
                recommendation="Add a Referrer-Policy header to control referrer information leakage.",
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="Referrer-Policy",
                ),
            )
        )

    return findings


def _find_referrer_policy_unsafe(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.referrer_policy_header is None:
            continue

        normalized = attempt.referrer_policy_header.strip().lower()
        if normalized != "unsafe-url":
            continue

        findings.append(
            Finding(
                rule_id="external.referrer_policy_unsafe",
                title="Unsafe Referrer-Policy value",
                severity="low",
                description=(
                    "HTTPS endpoint responded with Referrer-Policy: unsafe-url, "
                    "which may leak full referrer URLs."
                ),
                recommendation=(
                    "Use a stricter Referrer-Policy value such as "
                    "strict-origin-when-cross-origin, same-origin, or no-referrer "
                    "as appropriate."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="Referrer-Policy",
                ),
            )
        )

    return findings


def _find_permissions_policy_missing(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.permissions_policy_header is not None:
            continue

        findings.append(
            Finding(
                rule_id="external.permissions_policy_missing",
                title="Permissions-Policy header missing",
                severity="info",
                description="HTTPS endpoint responded without a Permissions-Policy header.",
                recommendation="Add a Permissions-Policy header to restrict browser feature access.",
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="Permissions-Policy",
                ),
            )
        )

    return findings


def _find_coep_missing(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.cross_origin_embedder_policy_header is not None:
            continue

        findings.append(
            Finding(
                rule_id="external.coep_missing",
                title="Cross-Origin-Embedder-Policy header missing",
                severity="info",
                description=(
                    "HTTPS endpoint responded without a "
                    "Cross-Origin-Embedder-Policy header."
                ),
                recommendation=(
                    "Add a Cross-Origin-Embedder-Policy header if the "
                    "application should enforce stronger cross-origin "
                    "embedding isolation."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="Cross-Origin-Embedder-Policy",
                ),
            )
        )

    return findings


def _find_coop_missing(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.cross_origin_opener_policy_header is not None:
            continue

        findings.append(
            Finding(
                rule_id="external.coop_missing",
                title="Cross-Origin-Opener-Policy header missing",
                severity="info",
                description=(
                    "HTTPS endpoint responded without a "
                    "Cross-Origin-Opener-Policy header."
                ),
                recommendation=(
                    "Add a Cross-Origin-Opener-Policy header if the "
                    "application should isolate its browsing context from "
                    "cross-origin documents."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="Cross-Origin-Opener-Policy",
                ),
            )
        )

    return findings


def _find_corp_missing(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.cross_origin_resource_policy_header is not None:
            continue

        findings.append(
            Finding(
                rule_id="external.corp_missing",
                title="Cross-Origin-Resource-Policy header missing",
                severity="info",
                description=(
                    "HTTPS endpoint responded without a "
                    "Cross-Origin-Resource-Policy header."
                ),
                recommendation=(
                    "Add a Cross-Origin-Resource-Policy header if the "
                    "application should restrict how its resources are loaded "
                    "cross-origin."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="header",
                    target=attempt.target.url,
                    details="Cross-Origin-Resource-Policy",
                ),
            )
        )

    return findings


def collect_header_findings(probe_attempts: list["ProbeAttempt"]) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_find_x_frame_options_missing(probe_attempts))
    findings.extend(_find_x_frame_options_invalid(probe_attempts))
    findings.extend(_find_x_content_type_options_missing(probe_attempts))
    findings.extend(_find_x_content_type_options_invalid(probe_attempts))
    findings.extend(_find_content_security_policy_missing(probe_attempts))
    findings.extend(_find_content_security_policy_unsafe_inline(probe_attempts))
    findings.extend(_find_content_security_policy_unsafe_eval(probe_attempts))
    findings.extend(_find_referrer_policy_missing(probe_attempts))
    findings.extend(_find_referrer_policy_unsafe(probe_attempts))
    findings.extend(_find_permissions_policy_missing(probe_attempts))
    findings.extend(_find_coep_missing(probe_attempts))
    findings.extend(_find_coop_missing(probe_attempts))
    findings.extend(_find_corp_missing(probe_attempts))
    return findings


__all__ = [
    "collect_header_findings",
]
