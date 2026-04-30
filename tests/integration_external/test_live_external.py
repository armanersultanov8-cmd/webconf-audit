from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from webconf_audit.external import analyze_external_target


_ROOT = Path(__file__).resolve().parents[2]


def _rule_ids(result) -> set[str]:
    return {finding.rule_id for finding in result.findings}


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "webconf_audit.cli", "analyze-external", *args],
        cwd=_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_cli_bare_host_port_discovery_end_to_end() -> None:
    result = _run_cli("127.0.0.1", "--ports", "18080,18443")

    assert result.returncode == 0, result.stderr
    assert "Mode: external" in result.stdout
    assert "Server: iis" in result.stdout
    assert "External Summary:" in result.stdout
    assert "port discovery: 2 scanned; open ports: 18080, 18443" in result.stdout
    assert "external.iis.aspnet_version_header_present" in result.stdout
    assert "external.cert_chain_incomplete" in result.stdout


def test_live_bare_host_discovery_tls_and_iis_conditional() -> None:
    result = analyze_external_target("127.0.0.1", scan_ports=True, ports=(18080, 18443))

    assert result.server_type == "iis"
    assert result.metadata["server_identification"]["confidence"] in {"medium", "high"}
    assert {entry["port"] for entry in result.metadata["port_scan"] if entry["tcp_open"]} == {
        18080,
        18443,
    }
    assert "port_scan_open: 127.0.0.1:18080" in result.diagnostics
    assert "port_scan_open: 127.0.0.1:18443" in result.diagnostics

    rule_ids = _rule_ids(result)
    assert "external.iis.aspnet_version_header_present" in rule_ids
    assert "external.cors_wildcard_with_credentials" in rule_ids
    assert "external.cookie_missing_secure_on_https" in rule_ids
    assert "external.cookie_missing_httponly" in rule_ids
    assert "external.x_frame_options_invalid" in rule_ids
    assert "external.x_content_type_options_invalid" in rule_ids
    assert "external.content_security_policy_unsafe_inline" in rule_ids
    assert "external.content_security_policy_unsafe_eval" in rule_ids
    assert "external.referrer_policy_unsafe" in rule_ids
    assert "external.permissions_policy_missing" in rule_ids
    assert "external.coep_missing" in rule_ids
    assert "external.coop_missing" in rule_ids
    assert "external.corp_missing" in rule_ids
    assert "external.tls_1_3_not_supported" in rule_ids
    assert "external.tls_certificate_self_signed" in rule_ids
    assert "external.cert_chain_incomplete" in rule_ids
    assert "external.cert_san_mismatch" not in rule_ids

    https_attempt = next(
        attempt
        for attempt in result.metadata["probe_attempts"]
        if attempt["scheme"] == "https" and attempt["port"] == 18443 and attempt["status_code"] == 200
    )
    assert https_attempt["tls_info"]["supported_protocols"] == ["TLSv1.2"]
    assert https_attempt["tls_info"]["cert_chain_complete"] is False


def test_live_url_target_head_get_fallback_and_options_observation() -> None:
    result = analyze_external_target("http://127.0.0.1:18080/head-fallback")

    attempt = result.metadata["probe_attempts"][0]
    assert attempt["effective_method"] == "GET"

    rule_ids = _rule_ids(result)
    assert "external.https_not_available" in rule_ids
    assert "external.allow_header_dangerous_methods" in rule_ids
    assert "external.options_method_exposed" in rule_ids
    assert "external.dangerous_http_methods_enabled" in rule_ids
    assert "external.trace_method_exposed_via_options" in rule_ids
    assert "external.webdav_methods_exposed" in rule_ids


def test_live_url_target_primary_allow_trace_and_wildcard_cors() -> None:
    result = analyze_external_target("http://127.0.0.1:18080/allow-trace")

    rule_ids = _rule_ids(result)
    assert "external.trace_method_allowed" in rule_ids
    assert "external.allow_header_dangerous_methods" in rule_ids
    assert "external.cors_wildcard_origin" in rule_ids


def test_live_host_port_sensitive_paths_and_fingerprint_probes() -> None:
    result = analyze_external_target("127.0.0.1:18080")

    assert result.server_type == "iis"
    signals = {entry["signal"] for entry in result.metadata["server_identification"]["evidence"]}
    assert "server_header" in signals
    assert "error_page_body" in signals
    assert "malformed_response_body" in signals

    rule_ids = _rule_ids(result)
    assert "external.git_metadata_exposed" in rule_ids
    assert "external.env_file_exposed" in rule_ids
    assert "external.phpinfo_exposed" in rule_ids
    assert "external.web_config_exposed" in rule_ids
    assert "external.trace_axd_exposed" in rule_ids
    assert "external.elmah_axd_exposed" in rule_ids


def test_live_redirect_chain_analysis() -> None:
    result = analyze_external_target("http://127.0.0.1:18080/redirect-start")

    assert "external.http_redirect_not_permanent" in _rule_ids(result)
    chains = result.metadata["redirect_chains"]
    assert len(chains) == 1
    chain = chains[0]
    assert chain["final_url"] == "https://127.0.0.1:18443/final"
    assert [hop["url"] for hop in chain["hops"]] == [
        "http://127.0.0.1:18080/redirect-start",
        "https://127.0.0.1:18443/redirect-middle",
        "https://127.0.0.1:18443/final",
    ]
    assert chain["mixed_scheme_redirect"] is False
    assert chain["cross_domain_redirect"] is False
    assert chain["loop_detected"] is False


def test_live_nginx_conditional_rules() -> None:
    result = analyze_external_target("127.0.0.1:18082")

    assert result.server_type == "nginx"
    assert result.metadata["server_identification"]["confidence"] == "high"
    rule_ids = _rule_ids(result)
    assert "external.nginx.version_disclosed_in_server_header" in rule_ids
    assert "external.nginx.default_welcome_page" in rule_ids
    assert "external.nginx_status_exposed" in rule_ids


def test_live_apache_conditional_rules() -> None:
    result = analyze_external_target("127.0.0.1:18083")

    assert result.server_type == "apache"
    assert result.metadata["server_identification"]["confidence"] == "high"
    rule_ids = _rule_ids(result)
    assert "external.apache.version_disclosed_in_server_header" in rule_ids
    assert "external.apache.mod_status_public" in rule_ids
    assert "external.apache.etag_inode_disclosure" in rule_ids


def test_live_lighttpd_conditional_rules() -> None:
    result = analyze_external_target("127.0.0.1:18084")

    assert result.server_type == "lighttpd"
    assert result.metadata["server_identification"]["confidence"] == "high"
    rule_ids = _rule_ids(result)
    assert "external.lighttpd.version_in_server_header" in rule_ids
    assert "external.lighttpd.mod_status_public" in rule_ids
