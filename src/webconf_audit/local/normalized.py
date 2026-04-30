"""Normalized security-relevant entities extracted from server-specific ASTs.

This module defines a thin, server-agnostic data model used by universal rules.
Each server has its own normalizer that maps native AST/effective-config data
into these structures on a best-effort basis.  Fields that a server cannot
populate are left as ``None``; universal rules skip silently in that case.

Every normalized entity carries a :class:`SourceRef` that points back to the
original AST node so findings remain traceable.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SourceRef:
    """Back-reference to the original AST node that produced this entity."""

    server_type: str  # "nginx" | "apache" | "lighttpd" | "iis"
    file_path: str
    line: int | None = None
    xml_path: str | None = None  # IIS only
    details: str | None = None


# ---------------------------------------------------------------------------
# Listen points
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NormalizedListenPoint:
    """A single address:port the server is configured to listen on."""

    port: int
    protocol: str  # "http" | "https"
    tls: bool
    source: SourceRef
    address: str | None = None  # "0.0.0.0", "127.0.0.1", "*", etc.


# ---------------------------------------------------------------------------
# TLS configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NormalizedTLS:
    """TLS-related configuration for a scope.

    *protocols* and *ciphers* are ``None`` when the server does not expose
    the information (e.g. IIS stores TLS protocol config in the registry,
    not in web.config).  Universal rules treat ``None`` as "unknown — skip".
    """

    source: SourceRef
    protocols: list[str] | None = None  # ["TLSv1", "TLSv1.2", …] or None
    ciphers: str | None = None  # raw cipher string or None
    certificate: str | None = None
    certificate_key: str | None = None
    require_ssl: bool | None = None  # IIS sslFlags concept; None = unknown


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NormalizedSecurityHeader:
    """A single security-relevant response header."""

    name: str  # lowercase: "strict-transport-security", "x-frame-options", …
    value: str | None  # raw value if present
    source: SourceRef


# ---------------------------------------------------------------------------
# Access / disclosure policy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NormalizedAccessPolicy:
    """Coarse access-control and information-disclosure flags for a scope.

    *server_identification_disclosed* covers a heterogeneous set of settings:
    Nginx ``server_tokens``, Apache ``ServerTokens``/``ServerSignature``,
    Lighttpd ``server.tag``, IIS ``enableVersionHeader``.  The common
    denominator is "server name and/or version information is sent to
    clients".
    """

    source: SourceRef
    directory_listing: bool | None = None
    server_identification_disclosed: bool | None = None
    debug_mode: bool | None = None


# ---------------------------------------------------------------------------
# Scope & top-level container
# ---------------------------------------------------------------------------


@dataclass
class NormalizedScope:
    """One logical configuration scope.

    Maps to a Nginx ``server`` block, Apache ``<VirtualHost>``, Lighttpd
    global/conditional scope, or IIS location path.
    """

    scope_name: str | None = None
    listen_points: list[NormalizedListenPoint] = field(default_factory=list)
    tls: NormalizedTLS | None = None
    security_headers: list[NormalizedSecurityHeader] = field(default_factory=list)
    access_policy: NormalizedAccessPolicy | None = None


@dataclass
class NormalizedConfig:
    """Server-agnostic normalized configuration for universal rules."""

    server_type: str  # "nginx" | "apache" | "lighttpd" | "iis"
    scopes: list[NormalizedScope] = field(default_factory=list)


__all__ = [
    "NormalizedAccessPolicy",
    "NormalizedConfig",
    "NormalizedListenPoint",
    "NormalizedScope",
    "NormalizedSecurityHeader",
    "NormalizedTLS",
    "SourceRef",
]
