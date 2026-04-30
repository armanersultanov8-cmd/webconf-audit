"""Tests for Lighttpd → NormalizedConfig mapper."""

from __future__ import annotations

from webconf_audit.local.lighttpd.effective import (
    LighttpdConditionalScope,
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
)
from webconf_audit.local.lighttpd.parser import (
    LighttpdAssignmentNode,
    LighttpdCondition,
    LighttpdConfigAst,
    LighttpdSourceSpan,
)
from webconf_audit.local.normalizers.lighttpd_normalizer import normalize_lighttpd


def _span(line: int = 1) -> LighttpdSourceSpan:
    return LighttpdSourceSpan(file_path="/etc/lighttpd/lighttpd.conf", line=line)


def _eff_dir(
    name: str,
    value: str,
    *,
    scope: str = "global",
    line: int = 1,
    condition: LighttpdCondition | None = None,
) -> LighttpdEffectiveDirective:
    return LighttpdEffectiveDirective(
        name=name,
        value=value,
        operator="=",
        scope=scope,
        condition=condition,
        source=_span(line),
    )


def _assign(name: str, value: str, line: int = 1) -> LighttpdAssignmentNode:
    return LighttpdAssignmentNode(name=name, operator="=", value=value, source=_span(line))


# ── Listen points (global) ───────────────────────────────────────────────


def test_global_listen_default():
    eff = LighttpdEffectiveConfig(
        global_directives={
            "server.port": _eff_dir("server.port", '"80"'),
        },
    )
    ast = LighttpdConfigAst(nodes=[], main_file_path="/etc/lighttpd/lighttpd.conf")
    cfg = normalize_lighttpd(ast, effective_config=eff)

    assert len(cfg.scopes) >= 1
    lps = cfg.scopes[0].listen_points
    assert len(lps) == 1
    assert lps[0].port == 80
    assert lps[0].tls is False


def test_global_listen_with_ssl():
    eff = LighttpdEffectiveConfig(
        global_directives={
            "server.port": _eff_dir("server.port", '"443"'),
            "server.bind": _eff_dir("server.bind", '"0.0.0.0"'),
            "ssl.engine": _eff_dir("ssl.engine", '"enable"'),
        },
    )
    ast = LighttpdConfigAst(nodes=[], main_file_path="/etc/lighttpd/lighttpd.conf")
    cfg = normalize_lighttpd(ast, effective_config=eff)

    lp = cfg.scopes[0].listen_points[0]
    assert lp.port == 443
    assert lp.tls is True
    assert lp.address == "0.0.0.0"


# ── Conditional scope listen points ──────────────────────────────────────


def test_conditional_socket_scope():
    cond = LighttpdCondition(
        variable='$SERVER["socket"]',
        operator="==",
        value='":443"',
    )
    eff = LighttpdEffectiveConfig(
        global_directives={
            "server.port": _eff_dir("server.port", '"80"'),
        },
        conditional_scopes=[
            LighttpdConditionalScope(
                condition=cond,
                header='$SERVER["socket"] == ":443"',
                directives={
                    "ssl.engine": _eff_dir("ssl.engine", '"enable"', scope="conditional", condition=cond),
                    "ssl.pemfile": _eff_dir("ssl.pemfile", '"/cert.pem"', scope="conditional", condition=cond),
                },
            ),
        ],
    )
    ast = LighttpdConfigAst(nodes=[], main_file_path="/etc/lighttpd/lighttpd.conf")
    cfg = normalize_lighttpd(ast, effective_config=eff)

    # Should have global + conditional scopes
    assert len(cfg.scopes) == 2
    cond_scope = cfg.scopes[1]
    assert len(cond_scope.listen_points) == 1
    assert cond_scope.listen_points[0].port == 443
    assert cond_scope.listen_points[0].tls is True


# ── TLS ──────────────────────────────────────────────────────────────────


def test_tls_from_global():
    eff = LighttpdEffectiveConfig(
        global_directives={
            "server.port": _eff_dir("server.port", '"443"'),
            "ssl.engine": _eff_dir("ssl.engine", '"enable"', line=5),
            "ssl.pemfile": _eff_dir("ssl.pemfile", '"/cert.pem"', line=6),
            "ssl.cipher-list": _eff_dir("ssl.cipher-list", '"HIGH:!aNULL"', line=7),
        },
    )
    ast = LighttpdConfigAst(nodes=[], main_file_path="/etc/lighttpd/lighttpd.conf")
    cfg = normalize_lighttpd(ast, effective_config=eff)

    tls = cfg.scopes[0].tls
    assert tls is not None
    assert tls.protocols is None  # Best-effort: unknown for Lighttpd
    assert tls.ciphers == "HIGH:!aNULL"
    assert tls.certificate == "/cert.pem"
    assert tls.require_ssl is True


def test_no_tls():
    eff = LighttpdEffectiveConfig(
        global_directives={
            "server.port": _eff_dir("server.port", '"80"'),
        },
    )
    ast = LighttpdConfigAst(nodes=[], main_file_path="/etc/lighttpd/lighttpd.conf")
    cfg = normalize_lighttpd(ast, effective_config=eff)

    assert cfg.scopes[0].tls is None


# ── Security headers ─────────────────────────────────────────────────────


def test_security_headers_from_ast():
    ast = LighttpdConfigAst(
        nodes=[
            _assign(
                "setenv.add-response-header",
                '( "Strict-Transport-Security" => "max-age=31536000", "X-Frame-Options" => "DENY" )',
                line=10,
            ),
        ],
        main_file_path="/etc/lighttpd/lighttpd.conf",
    )
    eff = LighttpdEffectiveConfig(
        global_directives={
            "server.port": _eff_dir("server.port", '"80"'),
        },
    )
    cfg = normalize_lighttpd(ast, effective_config=eff)

    hdrs = cfg.scopes[0].security_headers
    assert len(hdrs) == 2
    names = {h.name for h in hdrs}
    assert "strict-transport-security" in names
    assert "x-frame-options" in names


def test_no_security_headers():
    ast = LighttpdConfigAst(nodes=[], main_file_path="/etc/lighttpd/lighttpd.conf")
    eff = LighttpdEffectiveConfig(
        global_directives={"server.port": _eff_dir("server.port", '"80"')},
    )
    cfg = normalize_lighttpd(ast, effective_config=eff)
    assert cfg.scopes[0].security_headers == []


# ── Access policy ────────────────────────────────────────────────────────


def test_dir_listing_enabled():
    eff = LighttpdEffectiveConfig(
        global_directives={
            "server.port": _eff_dir("server.port", '"80"'),
            "dir-listing.activate": _eff_dir("dir-listing.activate", '"enable"'),
        },
    )
    ast = LighttpdConfigAst(nodes=[], main_file_path="/etc/lighttpd/lighttpd.conf")
    cfg = normalize_lighttpd(ast, effective_config=eff)
    assert cfg.scopes[0].access_policy.directory_listing is True


def test_server_tag_blank():
    eff = LighttpdEffectiveConfig(
        global_directives={
            "server.port": _eff_dir("server.port", '"80"'),
            "server.tag": _eff_dir("server.tag", '""'),
        },
    )
    ast = LighttpdConfigAst(nodes=[], main_file_path="/etc/lighttpd/lighttpd.conf")
    cfg = normalize_lighttpd(ast, effective_config=eff)
    assert cfg.scopes[0].access_policy.server_identification_disclosed is False


def test_server_tag_present():
    eff = LighttpdEffectiveConfig(
        global_directives={
            "server.port": _eff_dir("server.port", '"80"'),
            "server.tag": _eff_dir("server.tag", '"lighttpd"'),
        },
    )
    ast = LighttpdConfigAst(nodes=[], main_file_path="/etc/lighttpd/lighttpd.conf")
    cfg = normalize_lighttpd(ast, effective_config=eff)
    assert cfg.scopes[0].access_policy.server_identification_disclosed is True


# ── Edge cases ───────────────────────────────────────────────────────────


def test_server_type():
    ast = LighttpdConfigAst(nodes=[], main_file_path="/etc/lighttpd/lighttpd.conf")
    cfg = normalize_lighttpd(ast)
    assert cfg.server_type == "lighttpd"


def test_source_traceability():
    eff = LighttpdEffectiveConfig(
        global_directives={
            "server.port": _eff_dir("server.port", '"443"', line=3),
            "ssl.engine": _eff_dir("ssl.engine", '"enable"', line=5),
        },
    )
    ast = LighttpdConfigAst(nodes=[], main_file_path="/etc/lighttpd/lighttpd.conf")
    cfg = normalize_lighttpd(ast, effective_config=eff)

    lp = cfg.scopes[0].listen_points[0]
    assert lp.source.server_type == "lighttpd"
    assert lp.source.line == 3

    tls = cfg.scopes[0].tls
    assert tls.source.line == 5
