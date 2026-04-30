from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from webconf_audit.external.recon import (
        OptionsObservation,
        ProbeAttempt,
        SensitivePathProbe,
        ServerIdentification,
    )

HTTPS_REDIRECT_STATUS_CODES = frozenset({301, 302, 307, 308})
_PERMANENT_REDIRECT_STATUS_CODES = frozenset({301, 308})
_CONDITIONAL_RULE_MINIMUM_CONFIDENCE = frozenset({"medium", "high"})
# Cipher name substrings that indicate weak/broken algorithms.
_WEAK_CIPHER_KEYWORDS: tuple[str, ...] = (
    "RC4",
    "DES",
    "3DES",
    "NULL",
    "EXPORT",
    "EXP",
    "anon",
    "MD5",
)
_DANGEROUS_METHODS = frozenset({"TRACE", "TRACK", "PUT", "DELETE", "CONNECT"})
_ALLOW_HEADER_DANGEROUS_METHODS = frozenset({"TRACK", "PUT", "DELETE", "CONNECT"})
_WEBDAV_METHODS = frozenset(
    {
        "PROPFIND",
        "PROPPATCH",
        "MKCOL",
        "COPY",
        "MOVE",
        "LOCK",
        "UNLOCK",
    }
)
_CERT_EXPIRY_SOON_DAYS = 30
# Chain length boundaries for cert_chain_length_unusual rule.
# depth == 1 -> leaf-only, no intermediates sent (likely misconfiguration).
# depth > _CERT_CHAIN_DEPTH_MAX -> server sends too many certificates.
_CERT_CHAIN_DEPTH_MAX = 4
_HSTS_MIN_MAX_AGE = 31536000  # 1 year in seconds
_HSTS_MAX_AGE_PATTERN = re.compile(r"max-age\s*=\s*(\d+)(?:\s*;|\s*$|\s)", re.IGNORECASE)
_DOTENV_ASSIGNMENT_PATTERN = re.compile(r"(?m)^[A-Za-z_][A-Za-z0-9_]*\s*=")
_APACHE_VERSION_SERVER_HEADER_PATTERN = re.compile(r"(?i)\bapache/\d")
_NGINX_VERSION_SERVER_HEADER_PATTERN = re.compile(r"(?i)\b(?:nginx|openresty)/\d")
_LIGHTTPD_VERSION_SERVER_HEADER_PATTERN = re.compile(r"(?i)\blighttpd/\d")
_APACHE_INODE_ETAG_PATTERN = re.compile(r'^(?:W/)?"[0-9A-Fa-f]+-[0-9A-Fa-f]+-[0-9A-Fa-f]+"$')
_IIS_DETAILED_ERROR_MARKERS: tuple[str, ...] = (
    "iis detailed error",
    "server error in ",
)

_VERSION_PATTERN = re.compile(r"(?:^|[/\s])\d+\.\d+")


def _is_conditional_server_match(
    server_identification: "ServerIdentification | None",
    expected_server_type: str,
) -> bool:
    if server_identification is None:
        return False
    if server_identification.server_type != expected_server_type:
        return False
    return server_identification.confidence in _CONDITIONAL_RULE_MINIMUM_CONFIDENCE


def _is_nginx_conditional_applicable(
    server_identification: "ServerIdentification | None",
) -> bool:
    return _is_conditional_server_match(server_identification, "nginx")


def _is_apache_conditional_applicable(
    server_identification: "ServerIdentification | None",
) -> bool:
    return _is_conditional_server_match(server_identification, "apache")


def _is_iis_conditional_applicable(
    server_identification: "ServerIdentification | None",
) -> bool:
    return _is_conditional_server_match(server_identification, "iis")


def _is_lighttpd_conditional_applicable(
    server_identification: "ServerIdentification | None",
) -> bool:
    return _is_conditional_server_match(server_identification, "lighttpd")


def _is_nginx_family_server_header(server_header: str) -> bool:
    return _NGINX_VERSION_SERVER_HEADER_PATTERN.search(server_header) is not None


def _is_apache_server_header(server_header: str) -> bool:
    return _APACHE_VERSION_SERVER_HEADER_PATTERN.search(server_header) is not None


def _is_lighttpd_server_header(server_header: str) -> bool:
    return _LIGHTTPD_VERSION_SERVER_HEADER_PATTERN.search(server_header) is not None


def _is_server_header_handled_by_conditional_rule(
    server_header: str,
    server_identification: "ServerIdentification | None",
) -> bool:
    return (
        (
            _is_nginx_conditional_applicable(server_identification)
            and _is_nginx_family_server_header(server_header)
        )
        or (
            _is_apache_conditional_applicable(server_identification)
            and _is_apache_server_header(server_header)
        )
        or (
            _is_lighttpd_conditional_applicable(server_identification)
            and _is_lighttpd_server_header(server_header)
        )
    )


def _looks_like_nginx_default_welcome_page(body_snippet: str) -> bool:
    lower_body = body_snippet.lower()
    return (
        "welcome to nginx!" in lower_body
        and "nginx web server is successfully installed" in lower_body
    )


def _looks_like_iis_detailed_error(value: str) -> bool:
    lower_value = value.lower()
    return any(marker in lower_value for marker in _IIS_DETAILED_ERROR_MARKERS)


def _parse_options_methods(obs: "OptionsObservation") -> set[str]:
    methods: set[str] = set()
    for header_val in (obs.allow_header, obs.public_header):
        if header_val is not None:
            methods.update(m.strip().upper() for m in header_val.split(",") if m.strip())
    return methods


def _parse_cert_date(date_str: str) -> datetime | None:
    # CPython's ssl certificate dict uses GMT timestamps.  Parse that
    # explicit format and attach UTC rather than relying on platform-specific
    # %Z timezone handling.
    normalized = date_str.strip()
    for fmt in ("%b %d %H:%M:%S %Y GMT", "%b  %d %H:%M:%S %Y GMT"):
        try:
            dt = datetime.strptime(normalized, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _hostname_matches_san(hostname: str, san_entries: tuple[str, ...]) -> bool:
    """Check whether *hostname* matches any SAN entry (case-insensitive).

    Supports simple wildcard matching: ``*.example.com`` matches
    ``sub.example.com`` but not ``example.com`` or ``a.b.example.com``.
    """
    hostname_lower = hostname.lower()
    for entry in san_entries:
        entry_lower = entry.lower()
        if entry_lower == hostname_lower:
            return True
        if entry_lower.startswith("*."):
            # Wildcard: *.example.com matches sub.example.com
            wildcard_base = entry_lower[2:]
            # hostname must end with .example.com and have exactly one
            # additional label (no nested sub-subdomains matched).
            if hostname_lower.endswith(f".{wildcard_base}"):
                prefix = hostname_lower[: -(len(wildcard_base) + 1)]
                if "." not in prefix:
                    return True
    return False


def hostname_matches_san(hostname: str, san_entries: tuple[str, ...]) -> bool:
    """Public wrapper for SAN hostname matching."""
    return _hostname_matches_san(hostname, san_entries)


def _hsts_has_valid_max_age(header_value: str) -> bool:
    match = _HSTS_MAX_AGE_PATTERN.search(header_value)
    if match is None:
        return False
    return int(match.group(1)) > 0


def _hsts_has_include_subdomains(header_value: str) -> bool:
    """Token-aware check: includeSubDomains must appear as a standalone directive."""
    for part in header_value.split(";"):
        if part.strip().lower() == "includesubdomains":
            return True
    return False


def _successful_attempts_for_scheme(
    probe_attempts: list["ProbeAttempt"],
    scheme: str,
) -> list["ProbeAttempt"]:
    return [
        attempt
        for attempt in probe_attempts
        if attempt.target.scheme == scheme and attempt.has_http_response
    ]


def _attempt_redirects_to_https(attempt: "ProbeAttempt") -> bool:
    if attempt.status_code not in HTTPS_REDIRECT_STATUS_CODES:
        return False

    if attempt.location_header is None:
        return False

    return attempt.location_header.startswith("https://")


def _is_accessible_status(status_code: int | None) -> bool:
    return status_code is not None and 200 <= status_code < 300


def _probe_body_contains(probe: "SensitivePathProbe", needle: str) -> bool:
    if probe.body_snippet is None:
        return False
    return needle.lower() in probe.body_snippet.lower()


def _probe_body_looks_like_env_file(probe: "SensitivePathProbe") -> bool:
    if probe.body_snippet is None:
        return False
    return _DOTENV_ASSIGNMENT_PATTERN.search(probe.body_snippet) is not None
