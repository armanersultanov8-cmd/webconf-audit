from pathlib import Path

from typer.testing import CliRunner

from webconf_audit.cli import app
from webconf_audit.models import AnalysisIssue, AnalysisResult, Finding, SourceLocation

runner = CliRunner()


# ---------------------------------------------------------------------------
# list-rules command
# ---------------------------------------------------------------------------


class TestListRules:
    def test_list_rules_no_filters(self) -> None:
        result = runner.invoke(app, ["list-rules"])
        assert result.exit_code == 0
        assert "Total:" in result.stdout
        assert "nginx.server_tokens_on" in result.stdout
        assert "external.https_not_available" in result.stdout

    def test_list_rules_category_universal(self) -> None:
        result = runner.invoke(app, ["list-rules", "--category", "universal"])
        assert result.exit_code == 0
        assert "universal.tls_intent_without_config" in result.stdout
        assert "nginx." not in result.stdout

    def test_list_rules_category_external(self) -> None:
        result = runner.invoke(app, ["list-rules", "--category", "external"])
        assert result.exit_code == 0
        assert "external.https_not_available" in result.stdout
        assert "universal." not in result.stdout

    def test_list_rules_server_type_nginx(self) -> None:
        result = runner.invoke(app, ["list-rules", "--server-type", "nginx"])
        assert result.exit_code == 0
        assert "nginx.server_tokens_on" in result.stdout
        assert "apache." not in result.stdout

    def test_list_rules_severity_high(self) -> None:
        result = runner.invoke(app, ["list-rules", "--severity", "high"])
        assert result.exit_code == 0
        assert "HIGH" in result.stdout.upper()
        assert "external.git_metadata_exposed" in result.stdout

    def test_list_rules_tag_tls(self) -> None:
        result = runner.invoke(app, ["list-rules", "--tag", "tls"])
        assert result.exit_code == 0
        assert "universal.tls_intent_without_config" in result.stdout
        assert "universal.weak_tls_protocol" in result.stdout

    def test_list_rules_combined_filters(self) -> None:
        result = runner.invoke(app, ["list-rules", "--category", "local", "--server-type", "apache"])
        assert result.exit_code == 0
        assert "apache.server_tokens_not_prod" in result.stdout
        assert "nginx." not in result.stdout

    def test_list_rules_no_match(self) -> None:
        result = runner.invoke(
            app,
            ["list-rules", "--category", "universal", "--server-type", "nginx"],
        )
        assert result.exit_code == 0
        assert "No rules match" in result.stdout

    def test_list_rules_invalid_category_fails(self) -> None:
        result = runner.invoke(app, ["list-rules", "--category", "invalid"])
        assert result.exit_code != 0
        assert "invalid category" in result.output

    def test_list_rules_invalid_severity_fails(self) -> None:
        result = runner.invoke(app, ["list-rules", "--severity", "urgent"])
        assert result.exit_code != 0
        assert "invalid severity" in result.output

    def test_list_rules_invalid_server_type_fails(self) -> None:
        result = runner.invoke(app, ["list-rules", "--server-type", "nonexistent"])
        assert result.exit_code != 0
        assert "invalid server type" in result.output

    def test_list_rules_invalid_tag_fails(self) -> None:
        result = runner.invoke(app, ["list-rules", "--tag", "not-a-real-tag"])
        assert result.exit_code != 0
        assert "invalid tag" in result.output

    def test_list_rules_table_header(self) -> None:
        result = runner.invoke(app, ["list-rules", "--category", "universal"])
        assert result.exit_code == 0
        assert "RULE ID" in result.stdout
        assert "SEV" in result.stdout
        assert "CAT" in result.stdout
        assert "ORDER" in result.stdout


# ---------------------------------------------------------------------------
# analyze-* commands — text output (new report format)
# ---------------------------------------------------------------------------


def test_analyze_apache_cli_prints_findings_section(monkeypatch) -> None:
    def fake_analyze_apache_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="apache",
            findings=[
                Finding(
                    rule_id="apache.server_tokens_not_prod",
                    title="ServerTokens not set to Prod",
                    severity="low",
                    description="Apache config sets ServerTokens unsafely.",
                    recommendation="Set ServerTokens Prod.",
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path="/tmp/extra.conf",
                        line=3,
                    ),
                )
            ],
            issues=[],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_apache_config", fake_analyze_apache_config)

    result = runner.invoke(app, ["analyze-apache", str(Path("httpd.conf"))])

    assert result.exit_code == 0
    assert "Mode: local" in result.stdout
    assert "Server: apache" in result.stdout
    assert "Target: httpd.conf" in result.stdout
    assert "Findings: 1" in result.stdout
    assert "Analysis issues: 0" in result.stdout
    assert "=== LOW (1) ===" in result.stdout
    assert "[apache.server_tokens_not_prod] ServerTokens not set to Prod" in result.stdout
    assert "location: /tmp/extra.conf:3" in result.stdout
    assert "description: Apache config sets ServerTokens unsafely." in result.stdout
    assert "recommendation: Set ServerTokens Prod." in result.stdout


def test_analyze_nginx_cli_prints_issues_section(monkeypatch) -> None:
    def fake_analyze_nginx_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
            findings=[],
            issues=[
                AnalysisIssue(
                    code="nginx_parse_error",
                    level="error",
                    message="Expected ';' or '{'",
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path="/tmp/nginx.conf",
                        line=2,
                    ),
                )
            ],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_nginx_config", fake_analyze_nginx_config)

    result = runner.invoke(app, ["analyze-nginx", str(Path("nginx.conf"))])

    assert result.exit_code == 0
    assert "Mode: local" in result.stdout
    assert "Server: nginx" in result.stdout
    assert "Target: nginx.conf" in result.stdout
    assert "Findings: 0" in result.stdout
    assert "Analysis issues: 1" in result.stdout
    assert "Issues:" in result.stdout
    assert "[error] nginx_parse_error: Expected ';' or '{'" in result.stdout
    assert "location: /tmp/nginx.conf:2" in result.stdout


def test_cli_omits_issues_section_when_empty(monkeypatch) -> None:
    def fake_analyze_apache_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="apache",
            findings=[],
            issues=[],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_apache_config", fake_analyze_apache_config)

    result = runner.invoke(app, ["analyze-apache", str(Path("httpd.conf"))])

    assert result.exit_code == 0
    assert "Mode: local" in result.stdout
    assert "Server: apache" in result.stdout
    assert "Target: httpd.conf" in result.stdout
    assert "Findings: 0" in result.stdout
    assert "Analysis issues: 0" in result.stdout
    assert "Issues:" not in result.stdout


def test_cli_does_not_print_location_when_result_entry_has_no_location(monkeypatch) -> None:
    def fake_analyze_apache_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="apache",
            findings=[
                Finding(
                    rule_id="apache.server_tokens_not_prod",
                    title="ServerTokens not set to Prod",
                    severity="low",
                    description="Apache config sets ServerTokens unsafely.",
                    recommendation="Set ServerTokens Prod.",
                    location=None,
                )
            ],
            issues=[
                AnalysisIssue(
                    code="apache_parse_error",
                    level="error",
                    message="Unexpected end of input",
                    location=None,
                )
            ],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_apache_config", fake_analyze_apache_config)

    result = runner.invoke(app, ["analyze-apache", str(Path("httpd.conf"))])

    assert result.exit_code == 0
    assert "Mode: local" in result.stdout
    assert "Server: apache" in result.stdout
    assert "Target: httpd.conf" in result.stdout
    assert "[apache.server_tokens_not_prod]" in result.stdout
    assert "Issues:" in result.stdout
    assert "location:" not in result.stdout


def test_analyze_external_cli_prints_diagnostics_section(monkeypatch) -> None:
    def fake_analyze_external_target(target: str, **kwargs) -> AnalysisResult:
        return AnalysisResult(
            mode="external",
            target=target,
            server_type="nginx",
            diagnostics=[
                "tcp_port_open: example.com:443",
                "probable_server_type: nginx",
            ],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_external_target", fake_analyze_external_target)

    result = runner.invoke(app, ["analyze-external", "example.com"])

    assert result.exit_code == 0
    assert "Mode: external" in result.stdout
    assert "Server: nginx" in result.stdout
    assert "Target: example.com" in result.stdout
    assert "Findings: 0" in result.stdout
    assert "Diagnostics:" in result.stdout
    assert "- tcp_port_open: example.com:443" in result.stdout
    assert "- probable_server_type: nginx" in result.stdout


def test_analyze_external_cli_prints_external_summary(monkeypatch) -> None:
    def fake_analyze_external_target(target: str, **kwargs) -> AnalysisResult:
        return AnalysisResult(
            mode="external",
            target=target,
            server_type="nginx",
            diagnostics=["probable_server_type: nginx"],
            metadata={
                "port_scan": [
                    {"host": "example.com", "port": 80, "tcp_open": False, "error_message": "refused"},
                    {"host": "example.com", "port": 443, "tcp_open": True, "error_message": None},
                    {"host": "example.com", "port": 8443, "tcp_open": True, "error_message": None},
                ],
                "server_identification": {
                    "server_type": "nginx",
                    "confidence": "high",
                    "ambiguous": False,
                    "candidate_server_types": ["nginx"],
                    "evidence": [
                        {"signal": "server_header"},
                        {"signal": "error_page_body"},
                        {"signal": "malformed_response_body"},
                    ],
                },
                "probe_attempts": [
                    {
                        "scheme": "https",
                        "url": "https://example.com/",
                        "cache_control_header": "no-store",
                        "x_dns_prefetch_control_header": "off",
                        "cross_origin_embedder_policy_header": "require-corp",
                        "cross_origin_opener_policy_header": "same-origin",
                        "cross_origin_resource_policy_header": "same-origin",
                        "tls_info": {
                            "protocol_version": "TLSv1.3",
                            "cipher_name": "TLS_AES_256_GCM_SHA384",
                            "cipher_bits": 256,
                            "supported_protocols": ["TLSv1.2", "TLSv1.3"],
                            "cert_chain_complete": True,
                            "cert_chain_error": None,
                        },
                    }
                ],
                "redirect_chains": [
                    {
                        "hops": [
                            {"url": "http://example.com/"},
                            {"url": "https://example.com/login"},
                        ],
                        "final_url": "https://example.com/login",
                        "loop_detected": False,
                        "mixed_scheme_redirect": False,
                        "cross_domain_redirect": True,
                        "truncated": False,
                        "error_message": None,
                    }
                ],
            },
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_external_target", fake_analyze_external_target)

    result = runner.invoke(app, ["analyze-external", "example.com"])

    assert result.exit_code == 0
    assert "External Summary:" in result.stdout
    assert "- port discovery: 3 scanned; open ports: 443, 8443" in result.stdout
    assert "- port discovery errors: 80" in result.stdout
    assert (
        "- server identification: nginx (high confidence; signals: "
        "error_page_body, malformed_response_body, server_header)"
    ) in result.stdout
    assert (
        "- tls: https://example.com/: TLSv1.3; supports TLSv1.2, TLSv1.3; "
        "cipher TLS_AES_256_GCM_SHA384 (256 bits); chain complete"
    ) in result.stdout
    assert (
        "- extra headers: https://example.com/: Cache-Control=no-store; "
        "X-DNS-Prefetch-Control=off; COEP=require-corp; COOP=same-origin; "
        "CORP=same-origin"
    ) in result.stdout
    assert (
        "- redirect chain: http://example.com/ -> https://example.com/login "
        "(cross-domain)"
    ) in result.stdout


def test_analyze_external_cli_prints_findings_section(monkeypatch) -> None:
    def fake_analyze_external_target(target: str, **kwargs) -> AnalysisResult:
        return AnalysisResult(
            mode="external",
            target=target,
            server_type="apache",
            findings=[
                Finding(
                    rule_id="external.hsts_header_missing",
                    title="HSTS header missing",
                    severity="low",
                    description="HTTPS endpoint responded without a Strict-Transport-Security header.",
                    recommendation="Add a Strict-Transport-Security header to the HTTPS response.",
                    location=SourceLocation(
                        mode="external",
                        kind="header",
                        target="https://example.com/",
                        details="Strict-Transport-Security",
                    ),
                )
            ],
            diagnostics=["http_status: 200 OK"],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_external_target", fake_analyze_external_target)

    result = runner.invoke(app, ["analyze-external", "example.com"])

    assert result.exit_code == 0
    assert "Mode: external" in result.stdout
    assert "Server: apache" in result.stdout
    assert "Findings: 1" in result.stdout
    assert "Analysis issues: 0" in result.stdout
    assert "=== LOW (1) ===" in result.stdout
    assert "[external.hsts_header_missing] HSTS header missing" in result.stdout
    assert "location: https://example.com/" in result.stdout
    assert "Diagnostics:" in result.stdout


def test_analyze_iis_cli_prints_result(monkeypatch) -> None:
    def fake_analyze_iis_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="iis",
            findings=[],
            issues=[
                AnalysisIssue(
                    code="iis_parse_error",
                    level="error",
                    message="XML parse error: not well-formed",
                    location=SourceLocation(
                        mode="local",
                        kind="xml",
                        file_path="/tmp/web.config",
                        line=5,
                    ),
                )
            ],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_iis_config", fake_analyze_iis_config)

    result = runner.invoke(app, ["analyze-iis", str(Path("web.config"))])

    assert result.exit_code == 0
    assert "Mode: local" in result.stdout
    assert "Server: iis" in result.stdout
    assert "Target: web.config" in result.stdout
    assert "Findings: 0" in result.stdout
    assert "Analysis issues: 1" in result.stdout
    assert "Issues:" in result.stdout
    assert "[error] iis_parse_error: XML parse error: not well-formed" in result.stdout


def test_analyze_iis_cli_passes_machine_config_option(monkeypatch) -> None:
    captured: dict[str, str | None] = {}

    def fake_analyze_iis_config(
        config_path: str,
        machine_config_path: str | None = None,
    ) -> AnalysisResult:
        captured["config_path"] = config_path
        captured["machine_config_path"] = machine_config_path
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="iis",
            findings=[],
            issues=[],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_iis_config", fake_analyze_iis_config)

    result = runner.invoke(
        app,
        [
            "analyze-iis",
            "web.config",
            "--machine-config",
            "machine.config",
        ],
    )

    assert result.exit_code == 0
    assert captured == {
        "config_path": "web.config",
        "machine_config_path": "machine.config",
    }


def test_analyze_lighttpd_cli_prints_issue_section(monkeypatch) -> None:
    def fake_analyze_lighttpd_config(config_path: str, **kwargs) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="lighttpd",
            findings=[],
            issues=[
                AnalysisIssue(
                    code="lighttpd_include_not_found",
                    level="error",
                    message="Included config path not found: conf.d/missing.conf",
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path="/tmp/lighttpd.conf",
                        line=1,
                    ),
                )
            ],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_lighttpd_config", fake_analyze_lighttpd_config)

    result = runner.invoke(app, ["analyze-lighttpd", str(Path("lighttpd.conf"))])

    assert result.exit_code == 0
    assert "Mode: local" in result.stdout
    assert "Server: lighttpd" in result.stdout
    assert "Target: lighttpd.conf" in result.stdout
    assert "Findings: 0" in result.stdout
    assert "Analysis issues: 1" in result.stdout
    assert "Issues:" in result.stdout
    assert "[error] lighttpd_include_not_found: Included config path not found: conf.d/missing.conf" in result.stdout
    assert "location: /tmp/lighttpd.conf:1" in result.stdout


def test_analyze_lighttpd_cli_prints_findings_section(monkeypatch) -> None:
    def fake_analyze_lighttpd_config(config_path: str, **kwargs) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="lighttpd",
            findings=[
                Finding(
                    rule_id="lighttpd.dir_listing_enabled",
                    title="Directory listing enabled",
                    severity="medium",
                    description="Lighttpd configuration explicitly enables directory listing.",
                    recommendation="Disable directory listing unless it is intentionally required.",
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path="/tmp/extra.conf",
                        line=4,
                    ),
                )
            ],
            issues=[],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_lighttpd_config", fake_analyze_lighttpd_config)

    result = runner.invoke(app, ["analyze-lighttpd", str(Path("lighttpd.conf"))])

    assert result.exit_code == 0
    assert "Mode: local" in result.stdout
    assert "Server: lighttpd" in result.stdout
    assert "Target: lighttpd.conf" in result.stdout
    assert "Findings: 1" in result.stdout
    assert "Analysis issues: 0" in result.stdout
    assert "=== MEDIUM (1) ===" in result.stdout
    assert "[lighttpd.dir_listing_enabled] Directory listing enabled" in result.stdout
    assert "location: /tmp/extra.conf:4" in result.stdout
    assert "description: Lighttpd configuration explicitly enables directory listing." in result.stdout
    assert "recommendation: Disable directory listing unless it is intentionally required." in result.stdout


def test_analyze_lighttpd_cli_passes_execute_shell_option(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_analyze_lighttpd_config(
        config_path: str,
        execute_shell: bool = False,
        **kwargs,
    ) -> AnalysisResult:
        captured["config_path"] = config_path
        captured["execute_shell"] = execute_shell
        captured.update(kwargs)
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="lighttpd",
            findings=[],
            issues=[],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_lighttpd_config", fake_analyze_lighttpd_config)

    result = runner.invoke(app, ["analyze-lighttpd", "lighttpd.conf", "--execute-shell"])

    assert result.exit_code == 0
    assert captured["config_path"] == "lighttpd.conf"
    assert captured["execute_shell"] is True


# ---------------------------------------------------------------------------
# --format json
# ---------------------------------------------------------------------------


def test_analyze_apache_json_format(monkeypatch) -> None:
    import json

    def fake_analyze_apache_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="apache",
            findings=[
                Finding(
                    rule_id="apache.test_rule",
                    title="Test",
                    severity="medium",
                    description="desc",
                    recommendation="rec",
                )
            ],
            issues=[],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_apache_config", fake_analyze_apache_config)

    result = runner.invoke(app, ["analyze-apache", "httpd.conf", "--format", "json"])

    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["summary"]["total_findings"] == 1
    assert parsed["results"][0]["server_type"] == "apache"
    assert parsed["results"][0]["findings"][0]["rule_id"] == "apache.test_rule"
    # top-level aggregated arrays
    assert len(parsed["findings"]) == 1
    assert parsed["findings"][0]["rule_id"] == "apache.test_rule"
    assert parsed["issues"] == []


def test_analyze_external_json_format(monkeypatch) -> None:
    import json

    def fake_analyze_external_target(target: str, **kwargs) -> AnalysisResult:
        return AnalysisResult(
            mode="external",
            target=target,
            server_type="nginx",
            findings=[],
            metadata={"port_scan": [{"port": 443, "tcp_open": True}]},
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_external_target", fake_analyze_external_target)

    result = runner.invoke(app, ["analyze-external", "example.com", "--format", "json"])

    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["summary"]["total_findings"] == 0
    assert parsed["results"][0]["metadata"]["port_scan"][0]["port"] == 443
    assert "generated_at" in parsed
    assert parsed["findings"] == []
    assert parsed["issues"] == []


def test_analyze_nginx_json_has_summary_and_results(monkeypatch) -> None:
    import json

    def fake_analyze_nginx_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
            findings=[],
            issues=[],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_nginx_config", fake_analyze_nginx_config)

    result = runner.invoke(app, ["analyze-nginx", "nginx.conf", "--format", "json"])

    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert "summary" in parsed
    assert "results" in parsed
    assert set(parsed["summary"]["by_severity"].keys()) == {
        "critical", "high", "medium", "low", "info",
    }


def test_analyze_iis_json_format(monkeypatch) -> None:
    import json

    def fake_analyze_iis_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="iis",
            findings=[
                Finding(
                    rule_id="iis.directory_browse_enabled",
                    title="Directory browsing enabled",
                    severity="medium",
                    description="desc",
                    recommendation="rec",
                )
            ],
            issues=[],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_iis_config", fake_analyze_iis_config)

    result = runner.invoke(app, ["analyze-iis", "web.config", "--format", "json"])

    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["summary"]["total_findings"] == 1
    assert parsed["findings"][0]["rule_id"] == "iis.directory_browse_enabled"


def test_analyze_lighttpd_json_format(monkeypatch) -> None:
    import json

    def fake_analyze_lighttpd_config(config_path: str, **kwargs) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="lighttpd",
            findings=[
                Finding(
                    rule_id="lighttpd.dir_listing_enabled",
                    title="Directory listing enabled",
                    severity="medium",
                    description="desc",
                    recommendation="rec",
                )
            ],
            issues=[],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_lighttpd_config", fake_analyze_lighttpd_config)

    result = runner.invoke(app, ["analyze-lighttpd", "lighttpd.conf", "--format", "json"])

    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["summary"]["total_findings"] == 1
    assert parsed["findings"][0]["rule_id"] == "lighttpd.dir_listing_enabled"


def test_all_analyze_commands_default_to_text(monkeypatch) -> None:
    def fake_result(config_path: str, **kwargs) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
            findings=[],
            issues=[],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_nginx_config", fake_result)

    result = runner.invoke(app, ["analyze-nginx", "nginx.conf"])
    assert result.exit_code == 0
    assert "webconf-audit report" in result.stdout


def test_format_flag_short_form(monkeypatch) -> None:
    import json

    def fake_result(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
            findings=[],
            issues=[],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_nginx_config", fake_result)

    result = runner.invoke(app, ["analyze-nginx", "nginx.conf", "-f", "json"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert "summary" in parsed


def test_json_generated_at_is_utc(monkeypatch) -> None:
    import json

    def fake_result(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
            findings=[],
            issues=[],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_nginx_config", fake_result)

    result = runner.invoke(app, ["analyze-nginx", "nginx.conf", "--format", "json"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert "+00:00" in parsed["generated_at"] or "Z" in parsed["generated_at"]


def test_invalid_format_rejected() -> None:
    result = runner.invoke(app, ["analyze-nginx", "nginx.conf", "--format", "xml"])
    assert result.exit_code != 0


def test_cli_does_not_expose_placeholder_hello_command() -> None:
    result = runner.invoke(app, ["hello"])
    assert result.exit_code != 0
