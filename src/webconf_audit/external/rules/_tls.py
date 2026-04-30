from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from webconf_audit.external.rules._helpers import (
    _CERT_CHAIN_DEPTH_MAX,
    _CERT_EXPIRY_SOON_DAYS,
    _WEAK_CIPHER_KEYWORDS,
    _hostname_matches_san,
    _parse_cert_date,
    _successful_attempts_for_scheme,
)
from webconf_audit.models import Finding, SourceLocation

if TYPE_CHECKING:
    from webconf_audit.external.recon import ProbeAttempt


def _find_certificate_expired(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.tls_info is None:
            continue
        if attempt.tls_info.cert_not_after is None:
            continue

        not_after = _parse_cert_date(attempt.tls_info.cert_not_after)
        if not_after is None:
            continue

        now = datetime.now(timezone.utc)
        if not_after >= now:
            continue

        findings.append(
            Finding(
                rule_id="external.certificate_expired",
                title="TLS certificate expired",
                severity="high",
                description=(f"The TLS certificate expired on {attempt.tls_info.cert_not_after}."),
                recommendation="Renew the TLS certificate immediately.",
                location=SourceLocation(
                    mode="external",
                    kind="tls",
                    target=attempt.target.url,
                    details=f"notAfter: {attempt.tls_info.cert_not_after}",
                ),
            )
        )

    return findings


def _find_certificate_expires_soon(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.tls_info is None:
            continue
        if attempt.tls_info.cert_not_after is None:
            continue

        not_after = _parse_cert_date(attempt.tls_info.cert_not_after)
        if not_after is None:
            continue

        now = datetime.now(timezone.utc)
        if not_after < now:
            continue

        days_left = (not_after - now).days
        if days_left > _CERT_EXPIRY_SOON_DAYS:
            continue

        findings.append(
            Finding(
                rule_id="external.certificate_expires_soon",
                title="TLS certificate expires soon",
                severity="medium",
                description=(
                    f"The TLS certificate expires on {attempt.tls_info.cert_not_after} "
                    f"({days_left} days remaining)."
                ),
                recommendation=("Renew the TLS certificate before it expires."),
                location=SourceLocation(
                    mode="external",
                    kind="tls",
                    target=attempt.target.url,
                    details=f"notAfter: {attempt.tls_info.cert_not_after}",
                ),
            )
        )

    return findings


def _find_tls_certificate_self_signed(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.tls_info is None:
            continue
        if attempt.tls_info.cert_subject is None or attempt.tls_info.cert_issuer is None:
            continue
        if attempt.tls_info.cert_subject != attempt.tls_info.cert_issuer:
            continue

        findings.append(
            Finding(
                rule_id="external.tls_certificate_self_signed",
                title="TLS certificate appears self-signed",
                severity="medium",
                description=(
                    "The TLS certificate subject matches its issuer, which "
                    "indicates a self-signed certificate. Clients will not "
                    "trust this certificate by default."
                ),
                recommendation=(
                    "Replace the self-signed certificate with one issued by "
                    "a trusted certificate authority."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="tls",
                    target=attempt.target.url,
                    details=f"subject: {attempt.tls_info.cert_subject}, issuer: {attempt.tls_info.cert_issuer}",
                ),
            )
        )

    return findings


def _find_tls_1_0_supported(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    """Flag endpoints where active probing detected TLSv1.0 support."""
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.tls_info is None:
            continue
        if "TLSv1" not in attempt.tls_info.supported_protocols:
            continue

        findings.append(
            Finding(
                rule_id="external.tls_1_0_supported",
                title="TLS 1.0 supported",
                severity="high",
                description=(
                    "Active TLS probing confirmed that the server accepts TLS 1.0 "
                    "connections. TLS 1.0 has known vulnerabilities (BEAST, POODLE) "
                    "and is deprecated by RFC 8996."
                ),
                recommendation="Disable TLS 1.0 and require TLS 1.2 or later.",
                location=SourceLocation(
                    mode="external",
                    kind="tls",
                    target=attempt.target.url,
                    details="supported_protocol: TLSv1",
                ),
            )
        )

    return findings


def _find_tls_1_1_supported(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    """Flag endpoints where active probing detected TLSv1.1 support."""
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.tls_info is None:
            continue
        if "TLSv1.1" not in attempt.tls_info.supported_protocols:
            continue

        findings.append(
            Finding(
                rule_id="external.tls_1_1_supported",
                title="TLS 1.1 supported",
                severity="medium",
                description=(
                    "Active TLS probing confirmed that the server accepts TLS 1.1 "
                    "connections. TLS 1.1 is deprecated by RFC 8996 and no longer "
                    "considered secure."
                ),
                recommendation="Disable TLS 1.1 and require TLS 1.2 or later.",
                location=SourceLocation(
                    mode="external",
                    kind="tls",
                    target=attempt.target.url,
                    details="supported_protocol: TLSv1.1",
                ),
            )
        )

    return findings


def _find_tls_1_3_not_supported(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    """Flag HTTPS endpoints that do not support TLS 1.3.

    Only fires when ``supported_protocols`` has been populated (i.e.
    active probing ran) and TLSv1.3 is absent.
    """
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.tls_info is None:
            continue
        # Only evaluate when active probing actually ran.
        if not attempt.tls_info.supported_protocols:
            continue
        if "TLSv1.3" in attempt.tls_info.supported_protocols:
            continue

        findings.append(
            Finding(
                rule_id="external.tls_1_3_not_supported",
                title="TLS 1.3 not supported",
                severity="low",
                description=(
                    "Active TLS probing did not detect TLS 1.3 support. "
                    "TLS 1.3 provides improved security and performance over "
                    "earlier versions."
                ),
                recommendation="Enable TLS 1.3 on the server.",
                location=SourceLocation(
                    mode="external",
                    kind="tls",
                    target=attempt.target.url,
                    details=("supported: " + ", ".join(attempt.tls_info.supported_protocols)),
                ),
            )
        )

    return findings


def _find_weak_cipher_suite(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    """Flag negotiated cipher suites that contain known weak algorithms."""
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.tls_info is None:
            continue
        if attempt.tls_info.cipher_name is None:
            continue

        upper_cipher = attempt.tls_info.cipher_name.upper()
        matched = [kw for kw in _WEAK_CIPHER_KEYWORDS if kw.upper() in upper_cipher]
        if not matched:
            continue

        findings.append(
            Finding(
                rule_id="external.weak_cipher_suite",
                title="Weak TLS cipher suite negotiated",
                severity="high",
                description=(
                    f"The negotiated cipher suite '{attempt.tls_info.cipher_name}' "
                    f"contains weak algorithm(s): {', '.join(matched)}."
                ),
                recommendation=(
                    "Disable weak cipher suites and configure the server to use "
                    "only modern, strong ciphers (e.g. AES-GCM, ChaCha20-Poly1305)."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="tls",
                    target=attempt.target.url,
                    details=f"cipher: {attempt.tls_info.cipher_name}",
                ),
            )
        )

    return findings


def _find_cert_chain_incomplete(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    """Flag HTTPS endpoints where the certificate trust chain is broken.

    Only fires when ``cert_chain_complete`` is explicitly *False* (a
    definitive chain / CA-trust failure).  *None* (indeterminate, e.g.
    network error) and *True* are skipped.
    """
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.tls_info is None:
            continue
        # Only fire on a definitive chain failure (False), not
        # indeterminate (None) or success (True).
        if attempt.tls_info.cert_chain_complete is not False:
            continue

        error_detail = attempt.tls_info.cert_chain_error or "unknown"

        findings.append(
            Finding(
                rule_id="external.cert_chain_incomplete",
                title="Certificate chain verification failed",
                severity="medium",
                description=(
                    "Certificate chain verification against the system CA store "
                    f"failed: {error_detail}. This may indicate a missing "
                    "intermediate certificate, an untrusted root, or a "
                    "self-signed certificate."
                ),
                recommendation=(
                    "Ensure the server sends the complete certificate chain "
                    "including all intermediate certificates. Use a certificate "
                    "from a trusted CA."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="tls",
                    target=attempt.target.url,
                    details=f"verify_error: {error_detail}",
                ),
            )
        )

    return findings


def _find_cert_chain_length_unusual(
    probe_attempts: list["ProbeAttempt"],
) -> list[Finding]:
    """Flag HTTPS endpoints with a suspicious certificate chain depth.

    * ``depth == 1``: server sends only the leaf certificate with no
      intermediate certificates.  Clients that do not have the issuer
      cached will fail to build the trust path.  This is a common
      server misconfiguration.
    * ``depth > _CERT_CHAIN_DEPTH_MAX``: server sends an unusually long
      chain (e.g. redundant or duplicate intermediate certificates),
      which increases handshake overhead without security benefit.

    Skipped entirely when ``cert_chain_depth`` is ``None`` (probe could
    not measure the chain).
    """
    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.tls_info is None:
            continue
        depth = attempt.tls_info.cert_chain_depth
        if depth is None:
            continue

        if depth == 1:
            detail = "leaf-only (no intermediates sent)"
            description = (
                "The server sent only the leaf certificate without any intermediate "
                "certificates (chain depth: 1). Clients that do not have the issuing "
                "CA cached will fail to build the trust path, causing certificate "
                "validation errors."
            )
            recommendation = (
                "Configure the server to send the full certificate chain, "
                "including all intermediate CA certificates up to (but not "
                "including) the trusted root."
            )
        elif depth > _CERT_CHAIN_DEPTH_MAX:
            detail = f"chain depth {depth} exceeds expected maximum of {_CERT_CHAIN_DEPTH_MAX}"
            description = (
                f"The server sent an unusually long certificate chain "
                f"(depth: {depth}, expected <= {_CERT_CHAIN_DEPTH_MAX}). "
                "This may indicate duplicate or unnecessary intermediate certificates "
                "are included, which increases TLS handshake size without benefit."
            )
            recommendation = (
                "Review the certificate chain configuration and remove any redundant "
                "or duplicate intermediate certificates."
            )
        else:
            continue

        findings.append(
            Finding(
                rule_id="external.cert_chain_length_unusual",
                title="Unusual certificate chain length",
                severity="low",
                description=description,
                recommendation=recommendation,
                location=SourceLocation(
                    mode="external",
                    kind="tls",
                    target=attempt.target.url,
                    details=detail,
                ),
            )
        )

    return findings


def _find_cert_san_mismatch(
    probe_attempts: list["ProbeAttempt"],
    target: str,
) -> list[Finding]:
    """Flag HTTPS endpoints where the target hostname is not in the SAN list.

    Compares the original *target* hostname (stripped of scheme/port) against
    each ``DNS:`` entry in the certificate's Subject Alternative Names.
    Wildcard matching (``*.example.com``) is supported for one level.
    """
    from urllib.parse import urlsplit  # noqa: PLC0415

    # Extract the hostname the user intended to reach.
    normalized = target.strip()
    if "://" in normalized:
        hostname = urlsplit(normalized).hostname
    else:
        hostname = urlsplit(f"//{normalized}").hostname

    if hostname is None:
        return []

    hostname_lower = hostname.lower()
    if _is_ip_literal(hostname_lower):
        return []

    findings: list[Finding] = []

    for attempt in _successful_attempts_for_scheme(probe_attempts, "https"):
        if attempt.tls_info is None:
            continue
        if not attempt.tls_info.cert_san:
            continue

        if _hostname_matches_san(hostname_lower, attempt.tls_info.cert_san):
            continue

        findings.append(
            Finding(
                rule_id="external.cert_san_mismatch",
                title="Certificate SAN does not match target hostname",
                severity="medium",
                description=(
                    f"The target hostname '{hostname}' was not found in the "
                    f"certificate's Subject Alternative Names: "
                    f"{', '.join(attempt.tls_info.cert_san)}."
                ),
                recommendation=(
                    "Obtain a certificate that includes the target hostname "
                    "in its SAN list, or use a wildcard certificate that covers it."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="tls",
                    target=attempt.target.url,
                    details=f"hostname: {hostname}, san: {', '.join(attempt.tls_info.cert_san)}",
                ),
            )
        )

    return findings


def _is_ip_literal(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname.strip("[]"))
    except ValueError:
        return False
    return True


def collect_tls_findings(
    probe_attempts: list["ProbeAttempt"],
    target: str,
) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_find_certificate_expired(probe_attempts))
    findings.extend(_find_certificate_expires_soon(probe_attempts))
    findings.extend(_find_tls_certificate_self_signed(probe_attempts))
    findings.extend(_find_tls_1_0_supported(probe_attempts))
    findings.extend(_find_tls_1_1_supported(probe_attempts))
    findings.extend(_find_tls_1_3_not_supported(probe_attempts))
    findings.extend(_find_weak_cipher_suite(probe_attempts))
    findings.extend(_find_cert_chain_incomplete(probe_attempts))
    findings.extend(_find_cert_chain_length_unusual(probe_attempts))
    findings.extend(_find_cert_san_mismatch(probe_attempts, target))
    return findings


__all__ = [
    "collect_tls_findings",
]
