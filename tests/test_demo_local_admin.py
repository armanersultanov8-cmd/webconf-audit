from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from webconf_audit.cli import app
from webconf_audit.local.apache import analyze_apache_config
from webconf_audit.local.iis import analyze_iis_config
from webconf_audit.local.lighttpd import analyze_lighttpd_config
from webconf_audit.local.nginx import analyze_nginx_config


_ROOT = Path(__file__).resolve().parents[1]
_DEMO_ROOT = _ROOT / "demo" / "local_admin"
_RUNNER = CliRunner()


def _rule_ids(result) -> set[str]:
    return {finding.rule_id for finding in result.findings}


@pytest.mark.parametrize(
    ("server_type", "analyze", "expected_rule_ids"),
    [
        (
            "nginx",
            lambda: analyze_nginx_config(str(_DEMO_ROOT / "nginx" / "nginx.conf")),
            {
                "nginx.autoindex_on",
                "nginx.if_in_location",
                "nginx.server_tokens_on",
            },
        ),
        (
            "apache",
            lambda: analyze_apache_config(str(_DEMO_ROOT / "apache" / "conf" / "httpd.conf")),
            {
                "apache.allowoverride_all_in_directory",
                "apache.index_options_fancyindexing_enabled",
                "apache.index_options_scanhtmltitles_enabled",
                "apache.options_includes_enabled",
                "apache.options_indexes",
                "apache.server_status_exposed",
                "apache.htaccess_disables_security_headers",
                "apache.htaccess_enables_cgi",
                "apache.htaccess_enables_directory_listing",
                "apache.htaccess_rewrite_without_limit",
            },
        ),
        (
            "lighttpd",
            lambda: analyze_lighttpd_config(str(_DEMO_ROOT / "lighttpd" / "lighttpd.conf")),
            {
                "lighttpd.access_log_missing",
                "lighttpd.dir_listing_enabled",
                "lighttpd.mod_cgi_enabled",
                "lighttpd.mod_status_public",
                "lighttpd.ssl_honor_cipher_order_missing",
                "lighttpd.weak_ssl_cipher_list",
            },
        ),
        (
            "iis",
            lambda: analyze_iis_config(
                str(_DEMO_ROOT / "iis" / "web.config"),
                machine_config_path=str(_DEMO_ROOT / "iis" / "machine.config"),
            ),
            {
                "iis.directory_browse_enabled",
                "iis.http_errors_detailed",
                "iis.ssl_not_required",
                "iis.ssl_weak_cipher_strength",
                "iis.logging_not_configured",
                "iis.webdav_module_enabled",
                "iis.cgi_handler_enabled",
                "iis.trace_enabled",
            },
        ),
    ],
)
def test_local_admin_demo_analyzers_cover_expected_findings(
    server_type: str,
    analyze,
    expected_rule_ids: set[str],
) -> None:
    result = analyze()

    assert result.mode == "local"
    assert result.server_type == server_type
    assert result.issues == []
    assert expected_rule_ids <= _rule_ids(result)


def test_local_admin_demo_apache_tracks_htaccess_in_metadata() -> None:
    result = analyze_apache_config(str(_DEMO_ROOT / "apache" / "conf" / "httpd.conf"))

    contexts = result.metadata.get("analysis_contexts")
    assert contexts is not None
    assert len(contexts) == 1
    assert contexts[0]["label"] == "secure.example.com"
    assert contexts[0]["htaccess_count"] == 1


def test_run_external_demo_script_checks_all_demo_ports() -> None:
    script_path = _ROOT / "scripts" / "run_external_demo.ps1"
    script_text = script_path.read_text(encoding="utf-8")

    assert "Test-TcpPortReachable" in script_text
    assert 'Port = 18080' in script_text
    assert 'Port = 18081' in script_text
    assert 'Port = 18082' in script_text


@pytest.mark.parametrize(
    ("args", "server_type", "expected_rule_ids"),
    [
        (
            [
                "analyze-nginx",
                str(_DEMO_ROOT / "nginx" / "nginx.conf"),
                "--format",
                "json",
            ],
            "nginx",
            {"nginx.autoindex_on", "nginx.server_tokens_on"},
        ),
        (
            [
                "analyze-apache",
                str(_DEMO_ROOT / "apache" / "conf" / "httpd.conf"),
                "--format",
                "json",
            ],
            "apache",
            {
                "apache.options_indexes",
                "apache.server_status_exposed",
                "apache.htaccess_enables_directory_listing",
            },
        ),
        (
            [
                "analyze-lighttpd",
                str(_DEMO_ROOT / "lighttpd" / "lighttpd.conf"),
                "--format",
                "json",
            ],
            "lighttpd",
            {"lighttpd.mod_status_public", "lighttpd.ssl_honor_cipher_order_missing"},
        ),
        (
            [
                "analyze-iis",
                str(_DEMO_ROOT / "iis" / "web.config"),
                "--machine-config",
                str(_DEMO_ROOT / "iis" / "machine.config"),
                "--format",
                "json",
            ],
            "iis",
            {"iis.directory_browse_enabled", "iis.ssl_weak_cipher_strength"},
        ),
    ],
)
def test_local_admin_demo_cli_json_smoke(
    args: list[str],
    server_type: str,
    expected_rule_ids: set[str],
) -> None:
    result = _RUNNER.invoke(app, args)

    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["results"][0]["server_type"] == server_type
    assert parsed["results"][0]["issues"] == []
    assert expected_rule_ids <= {finding["rule_id"] for finding in parsed["findings"]}
