"""Tests for Apache → NormalizedConfig mapper."""

from __future__ import annotations

from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
    ApacheSourceSpan,
)
from webconf_audit.local.normalizers.apache_normalizer import normalize_apache


def _span(line: int = 1) -> ApacheSourceSpan:
    return ApacheSourceSpan(file_path="/etc/apache2/httpd.conf", line=line)


def _dir(name: str, args: list[str], line: int = 1) -> ApacheDirectiveNode:
    return ApacheDirectiveNode(name=name, args=args, source=_span(line))


def _block(
    name: str,
    args: list[str],
    children: list,
    line: int = 1,
) -> ApacheBlockNode:
    return ApacheBlockNode(name=name, args=args, children=children, source=_span(line))


# ── Listen points ────────────────────────────────────────────────────────


def test_listen_http():
    ast = ApacheConfigAst(nodes=[_dir("Listen", ["80"])])
    cfg = normalize_apache(ast)

    assert len(cfg.scopes) == 1
    lps = cfg.scopes[0].listen_points
    assert len(lps) == 1
    assert lps[0].port == 80
    assert lps[0].tls is False


def test_listen_https_protocol_hint():
    ast = ApacheConfigAst(nodes=[_dir("Listen", ["443", "https"])])
    cfg = normalize_apache(ast)

    lp = cfg.scopes[0].listen_points[0]
    assert lp.port == 443
    assert lp.tls is True
    assert lp.protocol == "https"


def test_listen_addr_port():
    ast = ApacheConfigAst(nodes=[_dir("Listen", ["0.0.0.0:8080"])])
    cfg = normalize_apache(ast)

    lp = cfg.scopes[0].listen_points[0]
    assert lp.address == "0.0.0.0"
    assert lp.port == 8080


# ── VirtualHost scopes ───────────────────────────────────────────────────


def test_virtualhost_scope():
    vh = _block("VirtualHost", ["*:443"], [
        _dir("SSLEngine", ["on"], line=5),
        _dir("SSLProtocol", ["all", "-SSLv3", "-TLSv1"], line=6),
    ])
    ast = ApacheConfigAst(nodes=[vh])
    cfg = normalize_apache(ast)

    assert len(cfg.scopes) == 1
    assert cfg.scopes[0].scope_name == "*:443"
    tls = cfg.scopes[0].tls
    assert tls is not None
    assert tls.require_ssl is True
    assert tls.protocols == ["all", "-SSLv3", "-TLSv1"]


def test_global_and_virtualhost():
    """When VirtualHosts exist the normalizer emits only VH scopes.

    Global directives (ServerTokens) are inherited into the VH scope via
    ``build_server_effective_config``, so a separate global scope is not
    needed and would cause false-positive universal findings.
    """
    ast = ApacheConfigAst(nodes=[
        _dir("ServerTokens", ["Prod"]),
        _block("VirtualHost", ["*:80"], [
            _dir("Options", ["Indexes"]),
        ]),
    ])
    cfg = normalize_apache(ast)

    # Only the VH scope — no separate global scope.
    assert len(cfg.scopes) == 1
    vh_scope = cfg.scopes[0]
    assert vh_scope.scope_name == "*:80"
    # VH inherits ServerTokens Prod from global.
    assert vh_scope.access_policy is not None
    assert vh_scope.access_policy.server_identification_disclosed is False
    # VH has its own Options Indexes.
    assert vh_scope.access_policy.directory_listing is True


# ── TLS ──────────────────────────────────────────────────────────────────


def test_no_tls_directives():
    ast = ApacheConfigAst(nodes=[_dir("Listen", ["80"])])
    cfg = normalize_apache(ast)
    assert cfg.scopes[0].tls is None


def test_tls_full():
    ast = ApacheConfigAst(nodes=[
        _dir("SSLEngine", ["on"]),
        _dir("SSLProtocol", ["TLSv1.2", "TLSv1.3"]),
        _dir("SSLCipherSuite", ["HIGH:!aNULL"]),
        _dir("SSLCertificateFile", ["/cert.pem"]),
        _dir("SSLCertificateKeyFile", ["/key.pem"]),
    ])
    cfg = normalize_apache(ast)

    tls = cfg.scopes[0].tls
    assert tls is not None
    assert tls.protocols == ["TLSv1.2", "TLSv1.3"]
    assert tls.ciphers == "HIGH:!aNULL"
    assert tls.certificate == "/cert.pem"
    assert tls.certificate_key == "/key.pem"
    assert tls.require_ssl is True


def test_ssl_engine_off():
    ast = ApacheConfigAst(nodes=[_dir("SSLEngine", ["off"])])
    cfg = normalize_apache(ast)
    assert cfg.scopes[0].tls.require_ssl is False


# ── Security headers ─────────────────────────────────────────────────────


def test_header_set():
    ast = ApacheConfigAst(nodes=[
        _dir("Header", ["set", "Strict-Transport-Security", "max-age=31536000"]),
        _dir("Header", ["set", "X-Frame-Options", "DENY"]),
    ])
    cfg = normalize_apache(ast)
    hdrs = cfg.scopes[0].security_headers

    assert len(hdrs) == 2
    names = {h.name for h in hdrs}
    assert "strict-transport-security" in names
    assert "x-frame-options" in names


def test_header_non_security_ignored():
    ast = ApacheConfigAst(nodes=[
        _dir("Header", ["set", "X-Custom", "value"]),
    ])
    cfg = normalize_apache(ast)
    # No security-relevant content → global scope filtered out.
    assert cfg.scopes == []


def test_header_unset_ignored():
    ast = ApacheConfigAst(nodes=[
        _dir("Header", ["unset", "X-Frame-Options"]),
    ])
    cfg = normalize_apache(ast)
    # "unset" is not set/append/add → no content → filtered out.
    assert cfg.scopes == []


# ── Access policy ────────────────────────────────────────────────────────


def test_options_indexes():
    ast = ApacheConfigAst(nodes=[_dir("Options", ["Indexes"])])
    cfg = normalize_apache(ast)
    assert cfg.scopes[0].access_policy.directory_listing is True


def test_options_minus_indexes():
    ast = ApacheConfigAst(nodes=[_dir("Options", ["-Indexes"])])
    cfg = normalize_apache(ast)
    assert cfg.scopes[0].access_policy.directory_listing is False


def test_server_tokens_prod():
    ast = ApacheConfigAst(nodes=[_dir("ServerTokens", ["Prod"])])
    cfg = normalize_apache(ast)
    assert cfg.scopes[0].access_policy.server_identification_disclosed is False


def test_server_tokens_full():
    ast = ApacheConfigAst(nodes=[_dir("ServerTokens", ["Full"])])
    cfg = normalize_apache(ast)
    assert cfg.scopes[0].access_policy.server_identification_disclosed is True


def test_server_signature_off():
    ast = ApacheConfigAst(nodes=[_dir("ServerSignature", ["Off"])])
    cfg = normalize_apache(ast)
    assert cfg.scopes[0].access_policy.server_identification_disclosed is False


# ── Edge cases ───────────────────────────────────────────────────────────


def test_server_signature_on_overrides_server_tokens_prod():
    ast = ApacheConfigAst(nodes=[
        _dir("ServerTokens", ["Prod"]),
        _dir("ServerSignature", ["On"]),
    ])
    cfg = normalize_apache(ast)
    assert cfg.scopes[0].access_policy.server_identification_disclosed is True


def test_empty_ast():
    ast = ApacheConfigAst(nodes=[])
    cfg = normalize_apache(ast)
    assert cfg.scopes == []
    assert cfg.server_type == "apache"


def test_source_traceability():
    ast = ApacheConfigAst(nodes=[
        _dir("Listen", ["443", "https"], line=10),
    ])
    cfg = normalize_apache(ast)
    lp = cfg.scopes[0].listen_points[0]
    assert lp.source.server_type == "apache"
    assert lp.source.line == 10


def test_directory_and_location_scopes_are_normalized_from_effective_layers():
    ast = ApacheConfigAst(nodes=[
        _block("VirtualHost", ["*:443"], [
            _dir("DocumentRoot", ["/var/www"], line=4),
            _dir("SSLEngine", ["on"], line=5),
            _block("Directory", ["/var/www"], [
                _dir("Header", ["set", "X-Frame-Options", "DENY"], line=8),
            ], line=7),
            _block("Location", ["/admin"], [
                _dir("Header", ["append", "Content-Security-Policy", "default-src 'self'"], line=11),
            ], line=10),
        ], line=3),
    ])

    cfg = normalize_apache(ast)

    scope_names = {scope.scope_name for scope in cfg.scopes}
    assert "*:443" in scope_names
    assert "*:443 directory:/var/www" in scope_names
    assert "*:443 location:/admin" in scope_names

    location_scope = next(
        scope
        for scope in cfg.scopes
        if scope.scope_name == "*:443 location:/admin"
    )
    header_names = {header.name for header in location_scope.security_headers}
    assert "x-frame-options" in header_names
    assert "content-security-policy" in header_names


def test_location_scope_inherits_accumulated_headers():
    ast = ApacheConfigAst(nodes=[
        _dir("Header", ["set", "X-Frame-Options", "DENY"], line=1),
        _block("Location", ["/admin"], [
            _dir("Header", ["append", "Permissions-Policy", "geolocation=()"], line=4),
        ], line=3),
    ])

    cfg = normalize_apache(ast)

    location_scope = next(
        scope
        for scope in cfg.scopes
        if scope.scope_name == "location:/admin"
    )
    header_names = {header.name for header in location_scope.security_headers}
    assert "x-frame-options" in header_names
    assert "permissions-policy" in header_names


# ── Per-VirtualHost universal-level alignment ───────────────────────────


def test_universal_scope_differs_per_virtualhost_when_header_only_in_one():
    """Security header in one VH produces a scope; the other VH omits it."""
    ast = ApacheConfigAst(nodes=[
        _block("VirtualHost", ["*:80"], [
            _dir("ServerName", ["secure.test"], line=2),
            _dir("Header", ["set", "Strict-Transport-Security", "max-age=31536000"], line=3),
        ], line=1),
        _block("VirtualHost", ["*:80"], [
            _dir("ServerName", ["plain.test"], line=6),
        ], line=5),
    ])

    cfg = normalize_apache(ast)

    secure_scope = next(
        (s for s in cfg.scopes if s.scope_name == "secure.test"), None,
    )
    plain_scope = next(
        (s for s in cfg.scopes if s.scope_name == "plain.test"), None,
    )

    assert secure_scope is not None
    secure_header_names = {h.name for h in secure_scope.security_headers}
    assert "strict-transport-security" in secure_header_names

    # plain.test has no security headers → either scope is absent or has no headers
    if plain_scope is not None:
        plain_header_names = {h.name for h in plain_scope.security_headers}
        assert "strict-transport-security" not in plain_header_names
