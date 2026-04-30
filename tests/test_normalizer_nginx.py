"""Tests for Nginx → NormalizedConfig mapper."""

from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    DirectiveNode,
    SourceSpan,
)
from webconf_audit.local.normalizers.nginx_normalizer import normalize_nginx


def _span(line: int = 1) -> SourceSpan:
    return SourceSpan(file_path="/etc/nginx/nginx.conf", line=line, column=1)


def _directive(name: str, args: list[str], line: int = 1) -> DirectiveNode:
    return DirectiveNode(name=name, args=args, source=_span(line))


def _server(*children: DirectiveNode | BlockNode, line: int = 1) -> BlockNode:
    return BlockNode(name="server", children=list(children), source=_span(line))


def _http(*children: DirectiveNode | BlockNode) -> ConfigAst:
    http_block = BlockNode(name="http", children=list(children), source=_span(1))
    return ConfigAst(nodes=[http_block])


# ── Listen points ────────────────────────────────────────────────────────


def test_http_listen_point():
    ast = _http(_server(_directive("listen", ["80"])))
    cfg = normalize_nginx(ast)

    assert len(cfg.scopes) == 1
    lps = cfg.scopes[0].listen_points
    assert len(lps) == 1
    assert lps[0].port == 80
    assert lps[0].tls is False
    assert lps[0].protocol == "http"


def test_https_listen_point():
    ast = _http(
        _server(
            _directive("listen", ["443", "ssl"]),
            _directive("ssl_certificate", ["/cert.pem"], line=3),
        )
    )
    cfg = normalize_nginx(ast)

    lps = cfg.scopes[0].listen_points
    assert len(lps) == 1
    assert lps[0].port == 443
    assert lps[0].tls is True
    assert lps[0].protocol == "https"


def test_listen_address_port():
    ast = _http(_server(_directive("listen", ["0.0.0.0:8080"])))
    cfg = normalize_nginx(ast)

    lp = cfg.scopes[0].listen_points[0]
    assert lp.address == "0.0.0.0"
    assert lp.port == 8080


def test_listen_ipv6():
    ast = _http(_server(_directive("listen", ["[::]:443", "ssl"])))
    cfg = normalize_nginx(ast)

    lp = cfg.scopes[0].listen_points[0]
    assert lp.address == "[::]"
    assert lp.port == 443
    assert lp.tls is True


# ── TLS ──────────────────────────────────────────────────────────────────


def test_tls_full_config():
    ast = _http(
        _server(
            _directive("listen", ["443", "ssl"]),
            _directive("ssl_protocols", ["TLSv1.2", "TLSv1.3"], line=2),
            _directive("ssl_ciphers", ["HIGH:!aNULL"], line=3),
            _directive("ssl_certificate", ["/cert.pem"], line=4),
            _directive("ssl_certificate_key", ["/key.pem"], line=5),
        )
    )
    cfg = normalize_nginx(ast)
    tls = cfg.scopes[0].tls

    assert tls is not None
    assert tls.protocols == ["TLSv1.2", "TLSv1.3"]
    assert tls.ciphers == "HIGH:!aNULL"
    assert tls.certificate == "/cert.pem"
    assert tls.certificate_key == "/key.pem"


def test_tls_none_for_http_only():
    ast = _http(_server(_directive("listen", ["80"])))
    cfg = normalize_nginx(ast)

    assert cfg.scopes[0].tls is None


def test_tls_ssl_listen_without_directives():
    """SSL in listen but no ssl_* directives → TLS with all None fields."""
    ast = _http(_server(_directive("listen", ["443", "ssl"], line=5)))
    cfg = normalize_nginx(ast)

    tls = cfg.scopes[0].tls
    assert tls is not None
    assert tls.protocols is None
    assert tls.ciphers is None
    # Source should anchor to the listen directive, not the server block.
    assert tls.source.line == 5


# ── Security headers ─────────────────────────────────────────────────────


def test_security_headers_extracted():
    ast = _http(
        _server(
            _directive("listen", ["80"]),
            _directive("add_header", ["Strict-Transport-Security", "max-age=31536000"], line=2),
            _directive("add_header", ["X-Frame-Options", "DENY"], line=3),
        )
    )
    cfg = normalize_nginx(ast)
    hdrs = cfg.scopes[0].security_headers

    assert len(hdrs) == 2
    names = {h.name for h in hdrs}
    assert "strict-transport-security" in names
    assert "x-frame-options" in names


def test_non_security_headers_ignored():
    ast = _http(
        _server(
            _directive("listen", ["80"]),
            _directive("add_header", ["X-Custom-Header", "value"]),
        )
    )
    cfg = normalize_nginx(ast)
    assert cfg.scopes[0].security_headers == []


def test_empty_headers():
    ast = _http(_server(_directive("listen", ["80"])))
    cfg = normalize_nginx(ast)
    assert cfg.scopes[0].security_headers == []


# ── Access policy ────────────────────────────────────────────────────────


def test_autoindex_on():
    ast = _http(
        _server(
            _directive("listen", ["80"]),
            _directive("autoindex", ["on"], line=7),
        )
    )
    cfg = normalize_nginx(ast)
    ap = cfg.scopes[0].access_policy

    assert ap is not None
    assert ap.directory_listing is True
    # Source anchored to the autoindex directive, not the server block.
    assert ap.source.line == 7


def test_autoindex_off():
    ast = _http(
        _server(
            _directive("listen", ["80"]),
            _directive("autoindex", ["off"]),
        )
    )
    cfg = normalize_nginx(ast)
    assert cfg.scopes[0].access_policy.directory_listing is False


def test_server_tokens_off():
    ast = _http(
        _server(
            _directive("listen", ["80"]),
            _directive("server_tokens", ["off"]),
        )
    )
    cfg = normalize_nginx(ast)
    assert cfg.scopes[0].access_policy.server_identification_disclosed is False


def test_server_tokens_on():
    ast = _http(
        _server(
            _directive("listen", ["80"]),
            _directive("server_tokens", ["on"], line=9),
        )
    )
    cfg = normalize_nginx(ast)
    assert cfg.scopes[0].access_policy.server_identification_disclosed is True
    # Source anchored to server_tokens directive, not server block.
    assert cfg.scopes[0].access_policy.source.line == 9


def test_access_policy_none_when_nginx_has_no_access_directives():
    ast = _http(_server(_directive("listen", ["80"])))
    cfg = normalize_nginx(ast)

    assert cfg.scopes[0].access_policy is None


# ── Scope / traceability ─────────────────────────────────────────────────


def test_multiple_server_blocks():
    ast = _http(
        _server(
            _directive("listen", ["80"]),
            _directive("server_name", ["example.com"]),
            line=1,
        ),
        _server(
            _directive("listen", ["443", "ssl"]),
            _directive("server_name", ["secure.example.com"]),
            line=10,
        ),
    )
    cfg = normalize_nginx(ast)

    assert len(cfg.scopes) == 2
    assert cfg.scopes[0].scope_name == "example.com"
    assert cfg.scopes[1].scope_name == "secure.example.com"


def test_source_traceability():
    ast = _http(
        _server(
            _directive("listen", ["443", "ssl"], line=5),
            _directive("ssl_protocols", ["TLSv1.3"], line=6),
        )
    )
    cfg = normalize_nginx(ast)

    lp = cfg.scopes[0].listen_points[0]
    assert lp.source.server_type == "nginx"
    assert lp.source.file_path == "/etc/nginx/nginx.conf"
    assert lp.source.line == 5

    tls = cfg.scopes[0].tls
    assert tls.source.line == 6


def test_no_server_blocks():
    ast = _http()
    cfg = normalize_nginx(ast)
    assert cfg.scopes == []


def test_server_type():
    ast = _http(_server(_directive("listen", ["80"])))
    cfg = normalize_nginx(ast)
    assert cfg.server_type == "nginx"
