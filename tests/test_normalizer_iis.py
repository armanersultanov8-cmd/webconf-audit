"""Tests for IIS → NormalizedConfig mapper."""

from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig, IISEffectiveSection
from webconf_audit.local.iis.parser import (
    IISChildElement,
    IISConfigDocument,
    IISSection,
    IISSourceRef,
)
from webconf_audit.local.normalizers.iis_normalizer import normalize_iis


def _src(line: int = 1, xml_path: str | None = None) -> IISSourceRef:
    return IISSourceRef(file_path="C:/inetpub/web.config", xml_path=xml_path, line=line)


def _child(tag: str, attrs: dict[str, str], line: int = 1) -> IISChildElement:
    return IISChildElement(tag=tag, attributes=attrs, source=_src(line))


def _section(
    tag: str,
    suffix: str,
    attrs: dict[str, str] | None = None,
    children: list[IISChildElement] | None = None,
    line: int = 1,
) -> IISEffectiveSection:
    return IISEffectiveSection(
        tag=tag,
        section_path_suffix=suffix,
        attributes=attrs or {},
        children=children or [],
        location_path=None,
        origin_chain=[_src(line, xml_path=f"/configuration{suffix}")],
    )


def _empty_doc() -> IISConfigDocument:
    return IISConfigDocument(
        root_tag="configuration",
        config_kind="web",
        sections=[],
        file_path="C:/inetpub/web.config",
    )


# ── TLS (sslFlags) ──────────────────────────────────────────────────────


def test_tls_ssl_required():
    eff = IISEffectiveConfig(
        global_sections={
            "/access": _section("access", "/access", {"sslFlags": "Ssl,Ssl128"}, line=5),
        },
    )
    cfg = normalize_iis(_empty_doc(), effective_config=eff)

    tls = cfg.scopes[0].tls
    assert tls is not None
    assert tls.require_ssl is True
    assert tls.protocols is None  # Unknown for IIS


def test_tls_no_ssl_flags():
    eff = IISEffectiveConfig(
        global_sections={
            "/access": _section("access", "/access", {"sslFlags": ""}),
        },
    )
    cfg = normalize_iis(_empty_doc(), effective_config=eff)
    assert cfg.scopes[0].tls is None


def test_no_access_section():
    eff = IISEffectiveConfig(global_sections={})
    cfg = normalize_iis(_empty_doc(), effective_config=eff)
    assert cfg.scopes[0].tls is None


# ── Security headers ─────────────────────────────────────────────────────


def test_security_headers():
    eff = IISEffectiveConfig(
        global_sections={
            "/customHeaders": _section(
                "customHeaders",
                "/customHeaders",
                children=[
                    _child("add", {"name": "Strict-Transport-Security", "value": "max-age=31536000"}, line=10),
                    _child("add", {"name": "X-Frame-Options", "value": "DENY"}, line=11),
                    _child("add", {"name": "X-Custom", "value": "foo"}, line=12),
                ],
            ),
        },
    )
    cfg = normalize_iis(_empty_doc(), effective_config=eff)
    hdrs = cfg.scopes[0].security_headers

    assert len(hdrs) == 2
    names = {h.name for h in hdrs}
    assert "strict-transport-security" in names
    assert "x-frame-options" in names


def test_no_custom_headers_section():
    eff = IISEffectiveConfig(global_sections={})
    cfg = normalize_iis(_empty_doc(), effective_config=eff)
    assert cfg.scopes[0].security_headers == []


def test_remove_children_ignored():
    eff = IISEffectiveConfig(
        global_sections={
            "/customHeaders": _section(
                "customHeaders",
                "/customHeaders",
                children=[
                    _child("remove", {"name": "X-Frame-Options"}, line=10),
                ],
            ),
        },
    )
    cfg = normalize_iis(_empty_doc(), effective_config=eff)
    assert cfg.scopes[0].security_headers == []


# ── Access policy ────────────────────────────────────────────────────────


def test_directory_browse_enabled():
    eff = IISEffectiveConfig(
        global_sections={
            "/directoryBrowse": _section(
                "directoryBrowse", "/directoryBrowse", {"enabled": "true"},
            ),
        },
    )
    cfg = normalize_iis(_empty_doc(), effective_config=eff)
    ap = cfg.scopes[0].access_policy

    assert ap is not None
    assert ap.directory_listing is True


def test_directory_browse_disabled():
    eff = IISEffectiveConfig(
        global_sections={
            "/directoryBrowse": _section(
                "directoryBrowse", "/directoryBrowse", {"enabled": "false"},
            ),
        },
    )
    cfg = normalize_iis(_empty_doc(), effective_config=eff)
    assert cfg.scopes[0].access_policy.directory_listing is False


def test_debug_mode():
    eff = IISEffectiveConfig(
        global_sections={
            "/compilation": _section(
                "compilation", "/compilation", {"debug": "true"},
            ),
        },
    )
    cfg = normalize_iis(_empty_doc(), effective_config=eff)
    assert cfg.scopes[0].access_policy.debug_mode is True


def test_version_header_disclosed():
    eff = IISEffectiveConfig(
        global_sections={
            "/httpRuntime": _section(
                "httpRuntime", "/httpRuntime", {"enableVersionHeader": "true"},
            ),
        },
    )
    cfg = normalize_iis(_empty_doc(), effective_config=eff)
    assert cfg.scopes[0].access_policy.server_identification_disclosed is True


def test_version_header_hidden():
    eff = IISEffectiveConfig(
        global_sections={
            "/httpRuntime": _section(
                "httpRuntime", "/httpRuntime", {"enableVersionHeader": "false"},
            ),
        },
    )
    cfg = normalize_iis(_empty_doc(), effective_config=eff)
    assert cfg.scopes[0].access_policy.server_identification_disclosed is False


# ── Location scopes ──────────────────────────────────────────────────────


def test_location_scope():
    eff = IISEffectiveConfig(
        global_sections={},
        location_sections={
            "api": {
                "/directoryBrowse": _section(
                    "directoryBrowse", "/directoryBrowse", {"enabled": "true"},
                ),
            },
        },
    )
    cfg = normalize_iis(_empty_doc(), effective_config=eff)

    assert len(cfg.scopes) == 2
    loc_scope = cfg.scopes[1]
    assert loc_scope.scope_name == "api"
    assert loc_scope.access_policy.directory_listing is True


# ── Listen points from bindings ──────────────────────────────────────────


def test_binding_extraction():
    doc = IISConfigDocument(
        root_tag="configuration",
        config_kind="applicationHost",
        sections=[
            IISSection(
                tag="site",
                xml_path="/configuration/system.applicationHost/sites/site",
                children=[
                    _child("binding", {"bindingInformation": "*:443:example.com", "protocol": "https"}),
                    _child("binding", {"bindingInformation": "*:80:", "protocol": "http"}),
                ],
                source=_src(),
            ),
        ],
        file_path="C:/Windows/System32/inetsrv/config/applicationHost.config",
    )
    eff = IISEffectiveConfig(global_sections={})
    cfg = normalize_iis(doc, effective_config=eff)

    lps = cfg.scopes[0].listen_points
    assert len(lps) == 2
    https_lp = next(lp for lp in lps if lp.tls)
    assert https_lp.port == 443
    assert https_lp.protocol == "https"

    http_lp = next(lp for lp in lps if not lp.tls)
    assert http_lp.port == 80


# ── Edge cases ───────────────────────────────────────────────────────────


def test_no_effective_config():
    cfg = normalize_iis(_empty_doc(), effective_config=None)
    assert cfg.server_type == "iis"
    assert cfg.scopes == []


def test_server_type():
    eff = IISEffectiveConfig(global_sections={})
    cfg = normalize_iis(_empty_doc(), effective_config=eff)
    assert cfg.server_type == "iis"


def test_source_traceability():
    eff = IISEffectiveConfig(
        global_sections={
            "/access": _section("access", "/access", {"sslFlags": "Ssl"}, line=15),
        },
    )
    cfg = normalize_iis(_empty_doc(), effective_config=eff)
    tls = cfg.scopes[0].tls
    assert tls.source.server_type == "iis"
    assert tls.source.line == 15
    assert tls.source.xml_path == "/configuration/access"
