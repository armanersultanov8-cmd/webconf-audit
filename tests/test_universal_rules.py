"""Tests for universal rules against the normalized config model."""

from __future__ import annotations

from webconf_audit.local.normalized import (
    NormalizedAccessPolicy,
    NormalizedConfig,
    NormalizedListenPoint,
    NormalizedScope,
    NormalizedSecurityHeader,
    NormalizedTLS,
    SourceRef,
)
from webconf_audit.local.universal_rules import run_universal_rules


def _ref(server: str = "nginx", line: int = 1) -> SourceRef:
    return SourceRef(server_type=server, file_path="/fake.conf", line=line)


def _http_scope(
    *,
    name: str = "test",
    port: int = 80,
    tls: bool = False,
    headers: list[str] | None = None,
    dir_listing: bool | None = None,
    server_id: bool | None = None,
    tls_protocols: list[str] | None = None,
    tls_ciphers: str | None = None,
    address: str | None = None,
    server: str = "nginx",
    line: int = 1,
) -> NormalizedScope:
    ref = _ref(server, line=line)
    lp = NormalizedListenPoint(
        port=port,
        protocol="https" if tls else "http",
        tls=tls,
        source=ref,
        address=address,
    )
    tls_obj = None
    if tls:
        tls_obj = NormalizedTLS(
            source=ref,
            protocols=tls_protocols,
            ciphers=tls_ciphers,
        )
    sec_headers = [
        NormalizedSecurityHeader(name=h, value="test", source=ref)
        for h in (headers or [])
    ]
    ap = NormalizedAccessPolicy(
        source=ref,
        directory_listing=dir_listing,
        server_identification_disclosed=server_id,
    )
    return NormalizedScope(
        scope_name=name,
        listen_points=[lp],
        tls=tls_obj,
        security_headers=sec_headers,
        access_policy=ap,
    )


def _config(*scopes: NormalizedScope, server: str = "nginx") -> NormalizedConfig:
    return NormalizedConfig(server_type=server, scopes=list(scopes))


def _rule_ids(config: NormalizedConfig) -> set[str]:
    return {f.rule_id for f in run_universal_rules(config)}


# ═══════════════════════════════════════════════════════════════════════════
# 1. universal.tls_intent_without_config
# ═══════════════════════════════════════════════════════════════════════════


def test_tls_intent_fires_on_443_without_tls():
    """Port 443 but no TLS config → fires."""
    scope = NormalizedScope(
        scope_name="broken-tls",
        listen_points=[
            NormalizedListenPoint(port=443, protocol="https", tls=True, source=_ref()),
        ],
        tls=None,
    )
    ids = _rule_ids(_config(scope))
    assert "universal.tls_intent_without_config" in ids


def test_tls_intent_silent_on_http_only():
    """Plain HTTP on port 80 → silent."""
    scope = _http_scope(port=80, tls=False)
    ids = _rule_ids(_config(scope))
    assert "universal.tls_intent_without_config" not in ids


def test_tls_intent_fires_on_empty_tls_object():
    """Port 443 with an empty NormalizedTLS (all fields None) → fires."""
    scope = NormalizedScope(
        scope_name="ssl-listen-only",
        listen_points=[
            NormalizedListenPoint(port=443, protocol="https", tls=True, source=_ref()),
        ],
        tls=NormalizedTLS(source=_ref()),  # empty: no cert, no ciphers, no protocols
    )
    ids = _rule_ids(_config(scope))
    assert "universal.tls_intent_without_config" in ids


def test_tls_intent_silent_when_tls_present():
    """Port 443 with proper TLS config (has certificate) → silent."""
    scope = _http_scope(port=443, tls=True, tls_protocols=["TLSv1.2", "TLSv1.3"])
    ids = _rule_ids(_config(scope))
    assert "universal.tls_intent_without_config" not in ids


def test_tls_intent_silent_when_require_ssl_set():
    """TLS object with require_ssl=True is usable config → silent."""
    scope = NormalizedScope(
        scope_name="iis-ssl",
        listen_points=[
            NormalizedListenPoint(port=443, protocol="https", tls=True, source=_ref()),
        ],
        tls=NormalizedTLS(source=_ref(), require_ssl=True),
    )
    ids = _rule_ids(_config(scope))
    assert "universal.tls_intent_without_config" not in ids


def test_tls_intent_fires_when_tls_fields_are_empty_strings_and_lists():
    """Empty normalized TLS fields are not usable TLS config."""
    scope = NormalizedScope(
        scope_name="empty-strings",
        listen_points=[
            NormalizedListenPoint(port=443, protocol="https", tls=True, source=_ref()),
        ],
        tls=NormalizedTLS(
            source=_ref(),
            protocols=[],
            ciphers="",
            certificate="",
        ),
    )
    ids = _rule_ids(_config(scope))
    assert "universal.tls_intent_without_config" in ids


# ═══════════════════════════════════════════════════════════════════════════
# 2. universal.weak_tls_protocol
# ═══════════════════════════════════════════════════════════════════════════


def test_weak_protocol_fires():
    scope = _http_scope(tls=True, port=443, tls_protocols=["TLSv1", "TLSv1.2"])
    ids = _rule_ids(_config(scope))
    assert "universal.weak_tls_protocol" in ids


def test_weak_protocol_silent_on_strong():
    scope = _http_scope(tls=True, port=443, tls_protocols=["TLSv1.2", "TLSv1.3"])
    ids = _rule_ids(_config(scope))
    assert "universal.weak_tls_protocol" not in ids


def test_weak_protocol_skips_unknown():
    """protocols=None → skip, not fire."""
    scope = _http_scope(tls=True, port=443, tls_protocols=None)
    ids = _rule_ids(_config(scope))
    assert "universal.weak_tls_protocol" not in ids


# ═══════════════════════════════════════════════════════════════════════════
# 3. universal.weak_tls_ciphers
# ═══════════════════════════════════════════════════════════════════════════


def test_weak_ciphers_fires():
    scope = _http_scope(tls=True, port=443, tls_ciphers="RC4-SHA:AES128")
    ids = _rule_ids(_config(scope))
    assert "universal.weak_tls_ciphers" in ids


def test_weak_ciphers_silent_on_strong():
    scope = _http_scope(tls=True, port=443, tls_ciphers="ECDHE-RSA-AES256-GCM-SHA384")
    ids = _rule_ids(_config(scope))
    assert "universal.weak_tls_ciphers" not in ids


def test_weak_ciphers_skips_unknown():
    scope = _http_scope(tls=True, port=443, tls_ciphers=None)
    ids = _rule_ids(_config(scope))
    assert "universal.weak_tls_ciphers" not in ids


def test_weak_ciphers_ignores_disabled_openssl_tokens():
    scope = _http_scope(tls=True, port=443, tls_ciphers="HIGH:!aNULL:!MD5:-DES")
    ids = _rule_ids(_config(scope))
    assert "universal.weak_tls_ciphers" not in ids


# ═══════════════════════════════════════════════════════════════════════════
# 4. universal.missing_hsts
# ═══════════════════════════════════════════════════════════════════════════


def test_missing_hsts_fires_on_tls_without_header():
    scope = _http_scope(tls=True, port=443, headers=[])
    ids = _rule_ids(_config(scope))
    assert "universal.missing_hsts" in ids


def test_missing_hsts_silent_with_header():
    scope = _http_scope(tls=True, port=443, headers=["strict-transport-security"])
    ids = _rule_ids(_config(scope))
    assert "universal.missing_hsts" not in ids


def test_missing_hsts_silent_on_metadata_only_tls():
    """IIS scope with require_ssl=False and no TLS listeners → silent."""
    scope = NormalizedScope(
        scope_name="iis-no-ssl",
        listen_points=[],
        tls=NormalizedTLS(source=_ref("iis"), require_ssl=False),
    )
    ids = _rule_ids(_config(scope, server="iis"))
    assert "universal.missing_hsts" not in ids


def test_missing_hsts_fires_on_require_ssl_true():
    """IIS scope with require_ssl=True but no HSTS header → fires."""
    scope = NormalizedScope(
        scope_name="iis-ssl",
        listen_points=[],
        tls=NormalizedTLS(source=_ref("iis"), require_ssl=True),
        security_headers=[],
    )
    ids = _rule_ids(_config(scope, server="iis"))
    assert "universal.missing_hsts" in ids


def test_missing_hsts_silent_on_http():
    scope = _http_scope(port=80, tls=False)
    ids = _rule_ids(_config(scope))
    assert "universal.missing_hsts" not in ids


# ═══════════════════════════════════════════════════════════════════════════
# 5-8. Missing security headers
# ═══════════════════════════════════════════════════════════════════════════


def test_missing_x_content_type_options():
    scope = _http_scope(headers=[])
    ids = _rule_ids(_config(scope))
    assert "universal.missing_x_content_type_options" in ids


def test_x_content_type_options_present_with_nosniff():
    """Correct value 'nosniff' → silent."""
    ref = _ref()
    scope = _http_scope(headers=[])
    scope.security_headers = [
        NormalizedSecurityHeader(name="x-content-type-options", value="nosniff", source=ref),
    ]
    ids = _rule_ids(_config(scope))
    assert "universal.missing_x_content_type_options" not in ids


def test_x_content_type_options_wrong_value():
    """Header present but wrong value → fires."""
    ref = _ref()
    scope = _http_scope(headers=[])
    scope.security_headers = [
        NormalizedSecurityHeader(name="x-content-type-options", value="wrong", source=ref),
    ]
    ids = _rule_ids(_config(scope))
    assert "universal.missing_x_content_type_options" in ids


def test_missing_x_frame_options():
    scope = _http_scope(headers=[])
    ids = _rule_ids(_config(scope))
    assert "universal.missing_x_frame_options" in ids


def test_x_frame_options_present():
    scope = _http_scope(headers=["x-frame-options"])
    ids = _rule_ids(_config(scope))
    assert "universal.missing_x_frame_options" not in ids


def test_missing_content_security_policy():
    scope = _http_scope(headers=[])
    ids = _rule_ids(_config(scope))
    assert "universal.missing_content_security_policy" in ids


def test_content_security_policy_present():
    scope = _http_scope(headers=["content-security-policy"])
    ids = _rule_ids(_config(scope))
    assert "universal.missing_content_security_policy" not in ids


def test_missing_referrer_policy():
    scope = _http_scope(headers=[])
    ids = _rule_ids(_config(scope))
    assert "universal.missing_referrer_policy" in ids


def test_referrer_policy_present():
    scope = _http_scope(headers=["referrer-policy"])
    ids = _rule_ids(_config(scope))
    assert "universal.missing_referrer_policy" not in ids


def test_missing_header_findings_use_header_source_when_scope_has_no_listener():
    ref = _ref(line=17)
    scope = NormalizedScope(
        scope_name="headers-only",
        security_headers=[
            NormalizedSecurityHeader(
                name="content-security-policy",
                value="default-src 'self'",
                source=ref,
            )
        ],
    )

    findings = run_universal_rules(_config(scope))
    missing = [
        finding
        for finding in findings
        if finding.rule_id in {
            "universal.missing_x_content_type_options",
            "universal.missing_x_frame_options",
            "universal.missing_referrer_policy",
        }
    ]

    assert missing
    for finding in missing:
        assert finding.location is not None
        assert finding.location.file_path == "/fake.conf"
        assert finding.location.line == 17


# ═══════════════════════════════════════════════════════════════════════════
# 9. universal.directory_listing_enabled
# ═══════════════════════════════════════════════════════════════════════════


def test_directory_listing_fires():
    scope = _http_scope(dir_listing=True)
    ids = _rule_ids(_config(scope))
    assert "universal.directory_listing_enabled" in ids


def test_directory_listing_silent_when_off():
    scope = _http_scope(dir_listing=False)
    ids = _rule_ids(_config(scope))
    assert "universal.directory_listing_enabled" not in ids


def test_directory_listing_silent_when_none():
    scope = _http_scope(dir_listing=None)
    ids = _rule_ids(_config(scope))
    assert "universal.directory_listing_enabled" not in ids


# ═══════════════════════════════════════════════════════════════════════════
# 10. universal.server_identification_disclosed
# ═══════════════════════════════════════════════════════════════════════════


def test_server_id_fires():
    scope = _http_scope(server_id=True)
    ids = _rule_ids(_config(scope))
    assert "universal.server_identification_disclosed" in ids


def test_server_id_silent_when_off():
    scope = _http_scope(server_id=False)
    ids = _rule_ids(_config(scope))
    assert "universal.server_identification_disclosed" not in ids


def test_server_id_silent_when_none():
    scope = _http_scope(server_id=None)
    ids = _rule_ids(_config(scope))
    assert "universal.server_identification_disclosed" not in ids


# ═══════════════════════════════════════════════════════════════════════════
# 11. universal.listen_on_all_interfaces
# ═══════════════════════════════════════════════════════════════════════════


def test_listen_all_fires_on_wildcard():
    scope = _http_scope(address="0.0.0.0")
    ids = _rule_ids(_config(scope))
    assert "universal.listen_on_all_interfaces" in ids


def test_listen_all_fires_on_no_address():
    scope = _http_scope(address=None)
    ids = _rule_ids(_config(scope))
    assert "universal.listen_on_all_interfaces" in ids


def test_listen_all_fires_on_unbracketed_ipv6_wildcard():
    scope = _http_scope(address="::")
    ids = _rule_ids(_config(scope))
    assert "universal.listen_on_all_interfaces" in ids


def test_listen_all_silent_on_specific():
    scope = _http_scope(address="127.0.0.1")
    ids = _rule_ids(_config(scope))
    assert "universal.listen_on_all_interfaces" not in ids


def test_listen_all_preserves_same_port_different_scopes():
    s1 = _http_scope(name="a", address="0.0.0.0", port=80, line=10)
    s2 = _http_scope(name="b", address="0.0.0.0", port=80, line=20)
    findings = run_universal_rules(_config(s1, s2))
    listen_findings = [f for f in findings if f.rule_id == "universal.listen_on_all_interfaces"]
    assert len(listen_findings) == 2
    assert {f.metadata.get("scope_name") for f in listen_findings} == {"a", "b"}


# ═══════════════════════════════════════════════════════════════════════════
# Cross-cutting
# ═══════════════════════════════════════════════════════════════════════════


def test_all_rules_run_on_empty_config():
    """No crash on empty config."""
    cfg = NormalizedConfig(server_type="nginx", scopes=[])
    findings = run_universal_rules(cfg)
    assert findings == []


def test_finding_has_server_type_in_details():
    scope = _http_scope(dir_listing=True, server="apache")
    findings = run_universal_rules(_config(scope, server="apache"))
    dir_f = [f for f in findings if f.rule_id == "universal.directory_listing_enabled"]
    assert len(dir_f) == 1
    assert "server_type=apache" in dir_f[0].location.details


def test_runner_returns_all_11_rule_ids_when_everything_bad():
    """A maximally-bad scope should trigger all 11 rules."""
    # Port 443 with TLS intent but broken TLS config
    scope_no_tls = NormalizedScope(
        scope_name="broken",
        listen_points=[
            NormalizedListenPoint(port=443, protocol="https", tls=True, source=_ref()),
        ],
        tls=None,
        access_policy=NormalizedAccessPolicy(
            source=_ref(),
            directory_listing=True,
            server_identification_disclosed=True,
        ),
    )
    # Separate scope with weak TLS + weak ciphers + no headers
    scope_weak_tls = _http_scope(
        name="weak",
        tls=True,
        port=8443,
        tls_protocols=["TLSv1", "TLSv1.2"],
        tls_ciphers="RC4-SHA:AES128",
        address="0.0.0.0",
    )
    cfg = _config(scope_no_tls, scope_weak_tls)
    ids = _rule_ids(cfg)

    expected = {
        "universal.tls_intent_without_config",
        "universal.weak_tls_protocol",
        "universal.weak_tls_ciphers",
        "universal.missing_hsts",
        "universal.missing_x_content_type_options",
        "universal.missing_x_frame_options",
        "universal.missing_content_security_policy",
        "universal.missing_referrer_policy",
        "universal.directory_listing_enabled",
        "universal.server_identification_disclosed",
        "universal.listen_on_all_interfaces",
    }
    assert expected.issubset(ids), f"Missing: {expected - ids}"


def test_multiple_server_types():
    """Universal rules work regardless of server_type."""
    for server in ("nginx", "apache", "lighttpd", "iis"):
        scope = _http_scope(dir_listing=True, server=server)
        cfg = _config(scope, server=server)
        ids = _rule_ids(cfg)
        assert "universal.directory_listing_enabled" in ids, f"Failed for {server}"
