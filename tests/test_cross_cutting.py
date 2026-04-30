"""Cross-cutting regression tests for shared plumbing.

Validates consistency between models, report module, rule registry,
normalizers, and CLI layer.
"""

from __future__ import annotations

import json
from pathlib import Path

from webconf_audit.local.apache import analyze_apache_config
from webconf_audit.local.iis import analyze_iis_config
from webconf_audit.local.lighttpd import analyze_lighttpd_config
from webconf_audit.local.nginx import analyze_nginx_config
from webconf_audit.models import (
    AnalysisIssue,
    AnalysisResult,
    Finding,
    SourceLocation,
)
from webconf_audit.report import (
    ReportData,
    TextFormatter,
    format_location,
)
from webconf_audit.rule_registry import registry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _loaded_registry():
    """Ensure global registry is fully loaded and return it."""
    registry.ensure_loaded("webconf_audit.local.rules.universal")
    registry.ensure_loaded("webconf_audit.local.nginx.rules")
    registry.ensure_loaded("webconf_audit.local.apache.rules")
    registry.ensure_loaded("webconf_audit.local.lighttpd.rules")
    registry.ensure_loaded("webconf_audit.local.iis.rules")
    import webconf_audit.external.rules._runner  # noqa: F401
    return registry


def _write(tmp_path: Path, name: str, content: str) -> str:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return str(p)


# ---------------------------------------------------------------------------
# Report <-> models consistency
# ---------------------------------------------------------------------------


class TestReportModelsConsistency:
    def test_finding_model_dump_has_expected_keys(self) -> None:
        f = Finding(
            rule_id="test.rule",
            title="T",
            severity="medium",
            description="D",
            recommendation="R",
        )
        d = f.model_dump()
        for key in ("rule_id", "title", "severity", "description", "recommendation", "kind"):
            assert key in d, f"missing key: {key}"

    def test_analysis_result_model_dump_roundtrip(self) -> None:
        r = AnalysisResult(
            mode="local",
            target="/a",
            server_type="nginx",
            findings=[
                Finding(
                    rule_id="x.rule",
                    title="T",
                    severity="high",
                    description="D",
                    recommendation="R",
                )
            ],
        )
        d = r.model_dump()
        r2 = AnalysisResult.model_validate(d)
        assert r2.model_dump() == d

    def test_analysis_result_boolean_helpers_reflect_findings_and_issues(self) -> None:
        empty = AnalysisResult(mode="local", target="/empty")
        assert empty.has_findings is False
        assert empty.has_issues is False

        populated = AnalysisResult(
            mode="local",
            target="/populated",
            findings=[
                Finding(
                    rule_id="x.rule",
                    title="T",
                    severity="high",
                    description="D",
                    recommendation="R",
                )
            ],
            issues=[
                AnalysisIssue(
                    code="x.issue",
                    message="Issue",
                )
            ],
        )
        assert populated.has_findings is True
        assert populated.has_issues is True

    def test_source_location_all_kinds_format(self) -> None:
        cases = [
            ({"mode": "local", "kind": "file", "file_path": "/a.conf", "line": 5}, "/a.conf:5"),
            ({"mode": "local", "kind": "file", "file_path": "/a.conf"}, "/a.conf"),
            ({"mode": "external", "kind": "header", "target": "https://x/"}, "https://x/"),
            ({"mode": "local", "kind": "xml", "xml_path": "/config/system"}, "/config/system"),
            ({"mode": "external", "kind": "tls", "details": "TLSv1.0"}, "TLSv1.0"),
            ({"mode": "external", "kind": "check"}, "check"),
        ]
        for kwargs, expected in cases:
            loc = SourceLocation(**kwargs)
            assert format_location(loc) == expected, f"failed for {kwargs}"

    def test_format_location_none(self) -> None:
        assert format_location(None) is None


# ---------------------------------------------------------------------------
# Rule registry <-> runner consistency
# ---------------------------------------------------------------------------


class TestRegistryRunnerConsistency:
    def test_all_findings_have_valid_rule_ids(self, tmp_path: Path) -> None:
        """Every finding.rule_id produced by a runner exists in the registry catalog."""
        reg = _loaded_registry()
        catalog_ids = {m.rule_id for m in reg.list_rules()}

        config = _write(tmp_path, "nginx.conf", (
            "worker_processes 1;\n"
            "events {}\n"
            "http {\n"
            "  server {\n"
            "    listen 80;\n"
            "    server_tokens on;\n"
            "  }\n"
            "}\n"
        ))
        result = analyze_nginx_config(config)
        for f in result.findings:
            assert f.rule_id in catalog_ids, f"rule_id {f.rule_id!r} not in catalog"

    def test_apache_findings_have_valid_rule_ids(self, tmp_path: Path) -> None:
        reg = _loaded_registry()
        catalog_ids = {m.rule_id for m in reg.list_rules()}

        config = _write(tmp_path, "httpd.conf", (
            'ServerSignature On\n'
            'ErrorLog "logs/error_log"\n'
            'CustomLog "logs/access_log" combined\n'
        ))
        result = analyze_apache_config(config)
        for f in result.findings:
            assert f.rule_id in catalog_ids, f"rule_id {f.rule_id!r} not in catalog"

    def test_runner_uses_only_registered_rule_ids(self, tmp_path: Path) -> None:
        """Lighttpd + IIS findings also belong to the registry."""
        reg = _loaded_registry()
        catalog_ids = {m.rule_id for m in reg.list_rules()}

        lighty = _write(tmp_path, "lighttpd.conf", (
            'server.document-root = "/var/www"\n'
            'dir-listing.activate = "enable"\n'
        ))
        iis = _write(tmp_path, "web.config", (
            '<?xml version="1.0"?>\n'
            '<configuration>\n'
            '  <system.webServer>\n'
            '    <directoryBrowse enabled="true" />\n'
            '  </system.webServer>\n'
            '</configuration>\n'
        ))

        for result in [analyze_lighttpd_config(lighty), analyze_iis_config(iis)]:
            for f in result.findings:
                assert f.rule_id in catalog_ids, f"rule_id {f.rule_id!r} not in catalog"


# ---------------------------------------------------------------------------
# Normalization <-> universal rules
# ---------------------------------------------------------------------------


class TestNormalizationUniversal:
    def test_universal_findings_have_correct_prefix(self, tmp_path: Path) -> None:
        """All universal rule findings start with 'universal.'."""
        config = _write(tmp_path, "nginx.conf", (
            "worker_processes 1;\n"
            "events {}\n"
            "http {\n"
            "  server {\n"
            "    listen 443 ssl;\n"
            "  }\n"
            "}\n"
        ))
        result = analyze_nginx_config(config)
        universal = [f for f in result.findings if f.rule_id.startswith("universal.")]
        assert universal, "expected at least one universal finding (TLS intent without config)"
        for f in universal:
            assert f.rule_id.startswith("universal.")


# ---------------------------------------------------------------------------
# CLI <-> report integration
# ---------------------------------------------------------------------------


class TestCliReportIntegration:
    def test_cli_text_output_matches_text_formatter(self, tmp_path: Path) -> None:
        """CLI text output should be produced by TextFormatter."""
        from typer.testing import CliRunner
        from webconf_audit.cli import app

        config = _write(tmp_path, "nginx.conf", "worker_processes 1;\n")
        result = analyze_nginx_config(config)
        report = ReportData(results=[result])
        expected = TextFormatter().format(report)

        cli_result = CliRunner().invoke(app, ["analyze-nginx", config])
        assert cli_result.exit_code == 0
        # CLI output includes trailing newline from typer.echo
        cli_text = cli_result.stdout.rstrip("\n")
        # generated_at timestamps will differ, so compare structure
        assert "webconf-audit report" in cli_text
        assert "Findings: 0" in cli_text
        assert "webconf-audit report" in expected

    def test_cli_json_output_is_valid_json(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner
        from webconf_audit.cli import app

        config = _write(tmp_path, "nginx.conf", "worker_processes 1;\n")
        cli_result = CliRunner().invoke(app, ["analyze-nginx", config, "--format", "json"])
        assert cli_result.exit_code == 0
        parsed = json.loads(cli_result.stdout)
        assert "summary" in parsed
        assert "findings" in parsed
        assert "issues" in parsed

    def test_list_rules_count_matches_registry_catalog(self) -> None:
        from typer.testing import CliRunner
        from webconf_audit.cli import app

        reg = _loaded_registry()
        catalog_count = len(reg.list_rules())

        cli_result = CliRunner().invoke(app, ["list-rules"])
        assert cli_result.exit_code == 0
        assert f"Total: {catalog_count} rules" in cli_result.stdout


# ---------------------------------------------------------------------------
# Apache end-to-end: effective-config wiring regressions
# ---------------------------------------------------------------------------


def _posix(p: Path) -> str:
    return str(p).replace("\\", "/")


def _safe_apache_base() -> str:
    return (
        "ServerSignature Off\n"
        "ServerTokens Prod\n"
        "TraceEnable Off\n"
        "LimitRequestBody 102400\n"
        "LimitRequestFields 100\n"
        "ErrorLog logs/error_log\n"
        "CustomLog logs/access_log combined\n"
        "ErrorDocument 404 /custom404.html\n"
        "ErrorDocument 500 /custom500.html\n"
        '<FilesMatch "\\.(bak|old|swp)$">\n'
        "    Require all denied\n"
        "</FilesMatch>\n"
    )


class TestApacheEffectiveConfigRegressions:
    """End-to-end tests that fail if the analyzer regresses to flat AST semantics."""

    def test_scenario_a_global_server_status_overridden_in_all_vhosts(
        self, tmp_path: Path,
    ) -> None:
        """Scenario A: global /server-status is permissive, but each VirtualHost
        overrides it safely. No false-positive should appear."""
        config = _write(tmp_path, "httpd.conf", _safe_apache_base() + (
            '<Location "/server-status">\n'
            "    SetHandler server-status\n"
            "</Location>\n"
            "<VirtualHost *:80>\n"
            "    ServerName site1.test\n"
            '    <Location "/server-status">\n'
            "        SetHandler server-status\n"
            "        Require ip 127.0.0.1\n"
            "    </Location>\n"
            "</VirtualHost>\n"
            "<VirtualHost *:80>\n"
            "    ServerName site2.test\n"
            '    <Location "/server-status">\n'
            "        SetHandler server-status\n"
            "        Require ip 10.0.0.0/8\n"
            "    </Location>\n"
            "</VirtualHost>\n"
        ))
        result = analyze_apache_config(config)
        exposed = [f for f in result.findings if f.rule_id == "apache.server_status_exposed"]
        assert exposed == [], (
            "Flat-AST regression: global /server-status triggers false positive "
            "even though every VirtualHost overrides it safely."
        )

    def test_scenario_b_two_vhosts_different_docroots_different_htaccess(
        self, tmp_path: Path,
    ) -> None:
        """Scenario B: two VirtualHosts with different DocumentRoots and
        different .htaccess — findings must differ by context."""
        alpha_dir = tmp_path / "alpha"
        alpha_dir.mkdir()
        (alpha_dir / ".htaccess").write_text("Options +Indexes\n", encoding="utf-8")

        beta_dir = tmp_path / "beta"
        beta_dir.mkdir()
        # no .htaccess in beta

        config = _write(tmp_path, "httpd.conf", _safe_apache_base() + (
            "<VirtualHost *:80>\n"
            "    ServerName alpha.test\n"
            f'    DocumentRoot "{_posix(alpha_dir)}"\n'
            f'    <Directory "{_posix(alpha_dir)}">\n'
            "        AllowOverride All\n"
            "    </Directory>\n"
            "</VirtualHost>\n"
            "<VirtualHost *:80>\n"
            "    ServerName beta.test\n"
            f'    DocumentRoot "{_posix(beta_dir)}"\n'
            "</VirtualHost>\n"
        ))
        result = analyze_apache_config(config)

        # Alpha has htaccess enabling directory listing — should produce a finding
        htaccess_findings = [
            f for f in result.findings
            if f.rule_id == "apache.htaccess_enables_directory_listing"
        ]
        assert len(htaccess_findings) >= 1, (
            "alpha.test has .htaccess with Options +Indexes but no finding was produced."
        )

        # Verify analysis_contexts metadata shows the htaccess difference
        contexts = result.metadata.get("analysis_contexts", [])
        alpha_ctx = next((c for c in contexts if c["label"] == "alpha.test"), None)
        beta_ctx = next((c for c in contexts if c["label"] == "beta.test"), None)
        assert alpha_ctx is not None
        assert beta_ctx is not None
        assert alpha_ctx["htaccess_count"] >= 1
        assert beta_ctx["htaccess_count"] == 0

    def test_scenario_c_security_header_only_in_one_virtualhost(
        self, tmp_path: Path,
    ) -> None:
        """Scenario C: a security header exists only inside one VirtualHost.
        Universal findings should differ accordingly per effective context."""
        config = _write(tmp_path, "httpd.conf", _safe_apache_base() + (
            "Listen 80\n"
            "<VirtualHost *:80>\n"
            "    ServerName secure.test\n"
            '    Header set Strict-Transport-Security "max-age=31536000"\n'
            '    Header set X-Content-Type-Options "nosniff"\n'
            "</VirtualHost>\n"
            "<VirtualHost *:80>\n"
            "    ServerName plain.test\n"
            "</VirtualHost>\n"
        ))
        result = analyze_apache_config(config)

        # Verify per-VH context metadata.
        contexts = result.metadata.get("analysis_contexts", [])
        assert len(contexts) == 2
        labels = {c["label"] for c in contexts}
        assert labels == {"secure.test", "plain.test"}

        # Key regression check: universal findings should differ per VH scope.
        # secure.test sets X-Content-Type-Options, so it should NOT get
        # universal.missing_x_content_type_options for that scope.
        # plain.test sets nothing, so it should.
        universal_xcto = [
            f for f in result.findings
            if f.rule_id == "universal.missing_x_content_type_options"
        ]
        # At least one finding for the VH that lacks the header.
        assert len(universal_xcto) >= 1, (
            "plain.test lacks X-Content-Type-Options but no universal finding fired."
        )
        # The finding should NOT reference the secure.test scope — that VH sets
        # the header.  Check that secure.test scope is NOT present among the
        # findings for this rule.
        xcto_scope_names = {f.metadata.get("scope_name") for f in universal_xcto}
        assert "plain.test" in xcto_scope_names, (
            "Regression: universal.missing_x_content_type_options did not target "
            "plain.test even though it lacks the header."
        )
        assert "secure.test" not in xcto_scope_names, (
            "Regression: universal.missing_x_content_type_options fires for "
            "secure.test even though it sets the header."
        )
