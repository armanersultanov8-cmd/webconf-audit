"""Tests for the normalized security-entity data model."""

from __future__ import annotations

import pytest

from webconf_audit.local.normalized import (
    NormalizedAccessPolicy,
    NormalizedConfig,
    NormalizedListenPoint,
    NormalizedScope,
    NormalizedSecurityHeader,
    NormalizedTLS,
    SourceRef,
)


# ── SourceRef ────────────────────────────────────────────────────────────

def test_source_ref_minimal():
    ref = SourceRef(server_type="nginx", file_path="/etc/nginx/nginx.conf")
    assert ref.server_type == "nginx"
    assert ref.file_path == "/etc/nginx/nginx.conf"
    assert ref.line is None
    assert ref.xml_path is None
    assert ref.details is None


def test_source_ref_full():
    ref = SourceRef(
        server_type="iis",
        file_path="C:/inetpub/web.config",
        line=42,
        xml_path="/configuration/system.webServer/security/access",
        details="sslFlags attribute",
    )
    assert ref.line == 42
    assert ref.xml_path == "/configuration/system.webServer/security/access"
    assert ref.details == "sslFlags attribute"


def test_source_ref_is_frozen():
    ref = SourceRef(server_type="nginx", file_path="/etc/nginx/nginx.conf")
    with pytest.raises(AttributeError):
        ref.server_type = "apache"  # type: ignore[misc]


# ── NormalizedListenPoint ────────────────────────────────────────────────

def _make_ref(server: str = "nginx") -> SourceRef:
    return SourceRef(server_type=server, file_path="/fake", line=1)


def test_listen_point_http():
    lp = NormalizedListenPoint(
        port=80, protocol="http", tls=False, source=_make_ref(),
    )
    assert lp.port == 80
    assert lp.tls is False
    assert lp.address is None


def test_listen_point_https_with_address():
    lp = NormalizedListenPoint(
        port=443, protocol="https", tls=True,
        source=_make_ref(), address="0.0.0.0",
    )
    assert lp.tls is True
    assert lp.address == "0.0.0.0"


def test_listen_point_is_frozen():
    lp = NormalizedListenPoint(
        port=80, protocol="http", tls=False, source=_make_ref(),
    )
    with pytest.raises(AttributeError):
        lp.port = 443  # type: ignore[misc]


# ── NormalizedTLS ────────────────────────────────────────────────────────

def test_tls_full():
    tls = NormalizedTLS(
        source=_make_ref(),
        protocols=["TLSv1.2", "TLSv1.3"],
        ciphers="HIGH:!aNULL",
        certificate="/etc/ssl/cert.pem",
        certificate_key="/etc/ssl/key.pem",
        require_ssl=True,
    )
    assert tls.protocols == ["TLSv1.2", "TLSv1.3"]
    assert tls.ciphers == "HIGH:!aNULL"
    assert tls.require_ssl is True


def test_tls_unknown_protocols():
    """protocols=None means 'unknown / not available', not 'empty list'."""
    tls = NormalizedTLS(source=_make_ref(), protocols=None)
    assert tls.protocols is None
    assert tls.ciphers is None
    assert tls.certificate is None
    assert tls.require_ssl is None


def test_tls_is_frozen():
    tls = NormalizedTLS(source=_make_ref())
    with pytest.raises(AttributeError):
        tls.protocols = ["TLSv1.3"]  # type: ignore[misc]


# ── NormalizedSecurityHeader ─────────────────────────────────────────────

def test_security_header():
    hdr = NormalizedSecurityHeader(
        name="strict-transport-security",
        value="max-age=31536000; includeSubDomains",
        source=_make_ref(),
    )
    assert hdr.name == "strict-transport-security"
    assert hdr.value is not None


def test_security_header_no_value():
    hdr = NormalizedSecurityHeader(
        name="x-frame-options", value=None, source=_make_ref(),
    )
    assert hdr.value is None


# ── NormalizedAccessPolicy ───────────────────────────────────────────────

def test_access_policy_full():
    ap = NormalizedAccessPolicy(
        source=_make_ref(),
        directory_listing=True,
        server_identification_disclosed=True,
        debug_mode=False,
    )
    assert ap.directory_listing is True
    assert ap.server_identification_disclosed is True
    assert ap.debug_mode is False


def test_access_policy_defaults_none():
    ap = NormalizedAccessPolicy(source=_make_ref())
    assert ap.directory_listing is None
    assert ap.server_identification_disclosed is None
    assert ap.debug_mode is None


# ── NormalizedScope ──────────────────────────────────────────────────────

def test_scope_defaults():
    scope = NormalizedScope()
    assert scope.scope_name is None
    assert scope.listen_points == []
    assert scope.tls is None
    assert scope.security_headers == []
    assert scope.access_policy is None


def test_scope_populated():
    ref = _make_ref()
    scope = NormalizedScope(
        scope_name="example.com:443",
        listen_points=[
            NormalizedListenPoint(port=443, protocol="https", tls=True, source=ref),
        ],
        tls=NormalizedTLS(source=ref, protocols=["TLSv1.3"]),
        security_headers=[
            NormalizedSecurityHeader(name="x-frame-options", value="DENY", source=ref),
        ],
        access_policy=NormalizedAccessPolicy(source=ref, directory_listing=False),
    )
    assert scope.scope_name == "example.com:443"
    assert len(scope.listen_points) == 1
    assert scope.tls is not None
    assert len(scope.security_headers) == 1
    assert scope.access_policy is not None


def test_scope_is_mutable():
    """Scopes are mutable so normalizers can build them incrementally."""
    scope = NormalizedScope()
    ref = _make_ref()
    scope.listen_points.append(
        NormalizedListenPoint(port=80, protocol="http", tls=False, source=ref),
    )
    assert len(scope.listen_points) == 1


# ── NormalizedConfig ─────────────────────────────────────────────────────

def test_config_empty():
    cfg = NormalizedConfig(server_type="iis")
    assert cfg.server_type == "iis"
    assert cfg.scopes == []


def test_config_with_scopes():
    cfg = NormalizedConfig(
        server_type="nginx",
        scopes=[NormalizedScope(scope_name="default"), NormalizedScope(scope_name="api")],
    )
    assert len(cfg.scopes) == 2
    assert cfg.scopes[0].scope_name == "default"


def test_config_is_mutable():
    cfg = NormalizedConfig(server_type="apache")
    cfg.scopes.append(NormalizedScope(scope_name="vh1"))
    assert len(cfg.scopes) == 1


# ── Cross-cutting: traceability ──────────────────────────────────────────

def test_all_entities_carry_source_ref():
    """Every frozen entity must carry a SourceRef for traceability."""
    ref = SourceRef(server_type="lighttpd", file_path="/etc/lighttpd.conf", line=5)
    entities = [
        NormalizedListenPoint(port=80, protocol="http", tls=False, source=ref),
        NormalizedTLS(source=ref),
        NormalizedSecurityHeader(name="hsts", value=None, source=ref),
        NormalizedAccessPolicy(source=ref),
    ]
    for entity in entities:
        assert entity.source is ref
        assert entity.source.server_type == "lighttpd"
        assert entity.source.line == 5
