"""Integration tests: analyze_*_config() -> ReportData -> formatters.

These tests verify the full pipeline from config file through analysis
to formatted report output, without going through the CLI layer.
"""

from __future__ import annotations

import json
from pathlib import Path

from webconf_audit.external import analyze_external_target
from webconf_audit.external.recon import ProbeAttempt, ProbeTarget, SensitivePathProbe, TLSInfo
from webconf_audit.local.apache import analyze_apache_config
from webconf_audit.local.apache.effective import (
    build_effective_config,
    build_server_effective_config,
    extract_virtualhost_contexts,
    select_applicable_virtualhosts,
)
from webconf_audit.local.apache.parser import ApacheParser, ApacheTokenizer
from webconf_audit.local.iis import analyze_iis_config
from webconf_audit.local.lighttpd import analyze_lighttpd_config
from webconf_audit.local.nginx import analyze_nginx_config
from webconf_audit.models import AnalysisResult
from webconf_audit.report import JsonFormatter, ReportData, TextFormatter

# ---------------------------------------------------------------------------
# Realistic config snippets that trigger at least one finding per server
# ---------------------------------------------------------------------------

_NGINX_CONFIG = """\
worker_processes 1;
events {}
http {
    limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;
    limit_conn_zone $binary_remote_addr zone=addr:10m;
    server {
        listen 80;
        server_name test.local;
        server_tokens on;
        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;
        client_max_body_size 10m;
        client_body_timeout 10s;
        client_header_timeout 10s;
        send_timeout 10s;
        keepalive_timeout 10s;
        limit_req zone=perip burst=10;
        limit_conn addr 10;
    }
}
"""

_APACHE_CONFIG = """\
ServerRoot "/usr/local/apache2"
ServerSignature On
ServerTokens Full
TraceEnable On
ErrorLog "logs/error_log"
CustomLog "logs/access_log" combined
ErrorDocument 404 "Not Found"
ErrorDocument 500 "Server Error"
LimitRequestBody 1048576
LimitRequestFields 50
<Directory "/var/www">
    Options Indexes
    AllowOverride None
</Directory>
"""

_LIGHTTPD_CONFIG = """\
server.document-root = "/var/www"
server.port = 8080
dir-listing.activate = "enable"
server.tag = "lighttpd/1.4.0"
"""

_IIS_CONFIG = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <directoryBrowse enabled="true" />
    <httpErrors errorMode="Detailed" />
    <security>
      <access sslFlags="None" />
    </security>
  </system.webServer>
  <system.web>
    <customErrors mode="Off" />
    <compilation debug="true" />
  </system.web>
</configuration>
"""


def _write_config(tmp_path: Path, name: str, content: str) -> str:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return str(p)


def _make_report(result: AnalysisResult) -> ReportData:
    return ReportData(results=[result])


def _analyze_external_with_probe_attempts(
    monkeypatch,
    probe_attempts: list[ProbeAttempt],
    *,
    target: str = "example.com",
    sensitive_path_probes: list[SensitivePathProbe] | None = None,
) -> AnalysisResult:
    attempts_by_target = {attempt.target: attempt for attempt in probe_attempts}

    def _fake_build_probe_targets(_external_target: str) -> list[ProbeTarget]:
        return [attempt.target for attempt in probe_attempts]

    def _fake_probe_target(probe_target: ProbeTarget) -> ProbeAttempt:
        return attempts_by_target[probe_target]

    def _fake_sensitive_path_probes(
        _successful_attempts: list[ProbeAttempt],
        identification=None,
    ) -> list[SensitivePathProbe]:
        del identification
        return sensitive_path_probes or []

    monkeypatch.setattr(
        "webconf_audit.external.recon._build_probe_targets",
        _fake_build_probe_targets,
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_target",
        _fake_probe_target,
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_sensitive_paths",
        _fake_sensitive_path_probes,
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_error_pages",
        lambda successful_attempts: [],
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_malformed_requests",
        lambda successful_attempts: [],
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._analyze_redirect_chains",
        lambda successful_attempts: [],
    )

    return analyze_external_target(target)


# ---------------------------------------------------------------------------
# Nginx: analyze -> ReportData -> formatters
# ---------------------------------------------------------------------------


class TestNginxPipeline:
    def test_text_output_contains_summary_and_findings(self, tmp_path: Path) -> None:
        path = _write_config(tmp_path, "nginx.conf", _NGINX_CONFIG)
        result = analyze_nginx_config(path)
        report = _make_report(result)
        text = TextFormatter().format(report)

        assert "webconf-audit report" in text
        assert "Mode: local" in text
        assert "Server: nginx" in text
        assert "Findings:" in text
        assert result.findings, "expected at least one finding"
        assert f"Findings: {len(report.all_findings)}" in text

    def test_json_output_valid_and_complete(self, tmp_path: Path) -> None:
        path = _write_config(tmp_path, "nginx.conf", _NGINX_CONFIG)
        result = analyze_nginx_config(path)
        report = _make_report(result)
        raw = JsonFormatter().format(report)

        parsed = json.loads(raw)
        assert parsed["summary"]["total_findings"] == len(report.all_findings)
        assert parsed["summary"]["total_findings"] > 0
        assert len(parsed["findings"]) == len(report.all_findings)
        assert parsed["results"][0]["server_type"] == "nginx"


# ---------------------------------------------------------------------------
# Apache: analyze -> ReportData -> formatters
# ---------------------------------------------------------------------------


class TestApachePipeline:
    def test_text_output_contains_summary_and_findings(self, tmp_path: Path) -> None:
        path = _write_config(tmp_path, "httpd.conf", _APACHE_CONFIG)
        result = analyze_apache_config(path)
        report = _make_report(result)
        text = TextFormatter().format(report)

        assert "Server: apache" in text
        assert result.findings, "expected at least one finding"
        assert f"Findings: {len(report.all_findings)}" in text

    def test_json_output_valid_and_complete(self, tmp_path: Path) -> None:
        path = _write_config(tmp_path, "httpd.conf", _APACHE_CONFIG)
        result = analyze_apache_config(path)
        report = _make_report(result)
        raw = JsonFormatter().format(report)

        parsed = json.loads(raw)
        assert parsed["summary"]["total_findings"] > 0
        assert len(parsed["findings"]) == parsed["summary"]["total_findings"]


# ---------------------------------------------------------------------------
# Apache: VirtualHost / Location effective-config pipeline
# ---------------------------------------------------------------------------

_APACHE_VIRTUALHOST_CONFIG = """\
ServerRoot "/usr/local/apache2"
ServerSignature On
ServerTokens Full
TraceEnable On
ErrorLog "logs/error_log"
DocumentRoot "/var/www/default"

<VirtualHost *:80>
    ServerName secure.example.com
    ServerAlias www.secure.example.com
    DocumentRoot "/var/www/secure"
    ServerSignature Off
    <Location "/admin">
        Require all denied
    </Location>
</VirtualHost>

<VirtualHost *:80>
    ServerName insecure.example.com
    ServerSignature On
    ServerTokens Full
    <Directory "/var/www/insecure">
        Options Indexes
        AllowOverride None
    </Directory>
</VirtualHost>
"""

_APACHE_VIRTUALHOST_LOCATION_OVERRIDE_CONFIG = """\
ServerSignature Off
ServerTokens Prod
TraceEnable Off
ErrorLog "logs/error_log"
CustomLog "logs/access_log" combined
ErrorDocument 404 "Not Found"
ErrorDocument 500 "Server Error"
LimitRequestBody 1048576
LimitRequestFields 50
<FilesMatch "\\.(bak|old|swp)$">
    Require all denied
</FilesMatch>
<Location "/server-status">
    SetHandler server-status
</Location>
<VirtualHost *:80>
    ServerName secure.example.com
    DocumentRoot "/var/www/secure"
    <Location "/server-status">
        Require ip 127.0.0.1
    </Location>
</VirtualHost>
<VirtualHost *:80>
    ServerName insecure.example.com
    DocumentRoot "/var/www/insecure"
    <Location "/server-status">
        SetHandler server-status
    </Location>
</VirtualHost>
"""


class TestApacheVirtualHostPipeline:
    """Exercise the VirtualHost extraction → selection → effective-config path."""

    def _parse(self, config_text: str):
        tokens = ApacheTokenizer(config_text, file_path="test.conf").tokenize()
        return ApacheParser(tokens).parse()

    def test_extract_virtualhost_contexts(self) -> None:
        ast = self._parse(_APACHE_VIRTUALHOST_CONFIG)
        contexts = extract_virtualhost_contexts(ast)
        assert len(contexts) == 2
        names = {ctx.server_name for ctx in contexts}
        assert names == {"secure.example.com", "insecure.example.com"}
        # Check ServerAlias on the first VH
        secure = [c for c in contexts if c.server_name == "secure.example.com"][0]
        assert "www.secure.example.com" in secure.server_aliases

    def test_select_applicable_virtualhosts_by_host(self) -> None:
        ast = self._parse(_APACHE_VIRTUALHOST_CONFIG)
        contexts = extract_virtualhost_contexts(ast)
        selected = select_applicable_virtualhosts(contexts, target_host="secure.example.com")
        assert len(selected) == 1
        assert selected[0].server_name == "secure.example.com"

    def test_select_applicable_virtualhosts_by_alias(self) -> None:
        ast = self._parse(_APACHE_VIRTUALHOST_CONFIG)
        contexts = extract_virtualhost_contexts(ast)
        selected = select_applicable_virtualhosts(
            contexts, target_host="www.secure.example.com"
        )
        assert len(selected) == 1
        assert selected[0].server_name == "secure.example.com"

    def test_select_all_when_no_host(self) -> None:
        ast = self._parse(_APACHE_VIRTUALHOST_CONFIG)
        contexts = extract_virtualhost_contexts(ast)
        selected = select_applicable_virtualhosts(contexts, target_host=None)
        assert len(selected) == 2

    def test_server_effective_config_virtualhost_overrides_global(self) -> None:
        ast = self._parse(_APACHE_VIRTUALHOST_CONFIG)
        contexts = extract_virtualhost_contexts(ast)
        secure = [c for c in contexts if c.server_name == "secure.example.com"][0]
        effective = build_server_effective_config(ast, virtualhost_context=secure)
        # VH overrides global ServerSignature On → Off
        sig = effective.directives.get("serversignature")
        assert sig is not None
        assert sig.args == ["Off"]
        assert sig.origin.layer.startswith("virtualhost:")

    def test_build_effective_config_with_location(self) -> None:
        ast = self._parse(_APACHE_VIRTUALHOST_CONFIG)
        contexts = extract_virtualhost_contexts(ast)
        secure = [c for c in contexts if c.server_name == "secure.example.com"][0]
        effective = build_effective_config(
            ast,
            directory_path="/var/www/secure",
            virtualhost_context=secure,
            location_path="/admin",
        )
        # Location /admin should apply Require directive
        require = effective.directives.get("require")
        assert require is not None
        assert require.origin.layer == "location:/admin"

    def test_analyzer_with_virtualhost_location_override_reports_only_insecure_vhost(
        self,
        tmp_path: Path,
    ) -> None:
        """End-to-end: only the insecure VirtualHost should remain exposed."""
        path = _write_config(
            tmp_path,
            "httpd.conf",
            _APACHE_VIRTUALHOST_LOCATION_OVERRIDE_CONFIG,
        )
        result = analyze_apache_config(path)
        report = _make_report(result)
        findings = [
            finding
            for finding in result.findings
            if finding.rule_id == "apache.server_status_exposed"
        ]

        assert len(findings) == 1
        assert findings[0].location is not None
        assert findings[0].location.line == 26
        text = TextFormatter().format(report)
        assert "Server: apache" in text
        raw = JsonFormatter().format(report)
        parsed = json.loads(raw)
        assert parsed["summary"]["total_findings"] >= 1
        server_status_in_json = [
            f for f in parsed["findings"]
            if f["rule_id"] == "apache.server_status_exposed"
        ]
        assert len(server_status_in_json) == 1


# ---------------------------------------------------------------------------
# Lighttpd: analyze -> ReportData -> formatters
# ---------------------------------------------------------------------------


class TestLighttpdPipeline:
    def test_text_output_contains_summary_and_findings(self, tmp_path: Path) -> None:
        path = _write_config(tmp_path, "lighttpd.conf", _LIGHTTPD_CONFIG)
        result = analyze_lighttpd_config(path)
        report = _make_report(result)
        text = TextFormatter().format(report)

        assert "Server: lighttpd" in text
        assert result.findings, "expected at least one finding"
        assert f"Findings: {len(report.all_findings)}" in text

    def test_json_output_valid_and_complete(self, tmp_path: Path) -> None:
        path = _write_config(tmp_path, "lighttpd.conf", _LIGHTTPD_CONFIG)
        result = analyze_lighttpd_config(path)
        report = _make_report(result)
        raw = JsonFormatter().format(report)

        parsed = json.loads(raw)
        assert parsed["summary"]["total_findings"] > 0
        assert len(parsed["findings"]) == parsed["summary"]["total_findings"]


# ---------------------------------------------------------------------------
# IIS: analyze -> ReportData -> formatters
# ---------------------------------------------------------------------------


class TestIISPipeline:
    def test_text_output_contains_summary_and_findings(self, tmp_path: Path) -> None:
        path = _write_config(tmp_path, "web.config", _IIS_CONFIG)
        result = analyze_iis_config(path)
        report = _make_report(result)
        text = TextFormatter().format(report)

        assert "Server: iis" in text
        assert result.findings, "expected at least one finding"
        assert f"Findings: {len(report.all_findings)}" in text

    def test_json_output_valid_and_complete(self, tmp_path: Path) -> None:
        path = _write_config(tmp_path, "web.config", _IIS_CONFIG)
        result = analyze_iis_config(path)
        report = _make_report(result)
        raw = JsonFormatter().format(report)

        parsed = json.loads(raw)
        assert parsed["summary"]["total_findings"] > 0
        assert len(parsed["findings"]) == parsed["summary"]["total_findings"]


# ---------------------------------------------------------------------------
# External: analyze -> ReportData -> formatters
# ---------------------------------------------------------------------------


class TestExternalPipeline:
    def test_text_output_contains_external_summary_and_findings(self, monkeypatch) -> None:
        result = _analyze_external_with_probe_attempts(
            monkeypatch,
            [
                ProbeAttempt(
                    target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
                    tcp_open=True,
                    effective_method="GET",
                    status_code=200,
                    reason_phrase="OK",
                    server_header="nginx/1.24.0",
                    strict_transport_security_header="max-age=300",
                    x_frame_options_header="ALLOWALL",
                    x_content_type_options_header="invalid",
                    referrer_policy_header="unsafe-url",
                    set_cookie_headers=("session=abc123",),
                    tls_info=TLSInfo(
                        protocol_version="TLSv1.2",
                        supported_protocols=("TLSv1.2",),
                        cert_chain_complete=False,
                        cert_chain_error="self-signed certificate",
                        cert_chain_depth=1,
                        cert_san=("other.example",),
                    ),
                )
            ],
            sensitive_path_probes=[
                SensitivePathProbe(
                    url="https://example.com/.git/HEAD",
                    path="/.git/HEAD",
                    status_code=200,
                    content_type="text/plain",
                    body_snippet="ref: refs/heads/main",
                )
            ],
        )
        report = _make_report(result)
        text = TextFormatter().format(report)

        assert "Mode: external" in text
        assert "External Summary:" in text
        assert "server identification: nginx" in text
        assert "tls: https://example.com/" in text
        assert result.findings, "expected at least one finding"
        assert f"Findings: {len(report.all_findings)}" in text

    def test_json_output_valid_and_complete(self, monkeypatch) -> None:
        result = _analyze_external_with_probe_attempts(
            monkeypatch,
            [
                ProbeAttempt(
                    target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
                    tcp_open=True,
                    effective_method="GET",
                    status_code=200,
                    reason_phrase="OK",
                    server_header="nginx/1.24.0",
                    strict_transport_security_header="max-age=300",
                    x_frame_options_header="ALLOWALL",
                    x_content_type_options_header="invalid",
                    referrer_policy_header="unsafe-url",
                    set_cookie_headers=("session=abc123",),
                    tls_info=TLSInfo(
                        protocol_version="TLSv1.2",
                        supported_protocols=("TLSv1.2",),
                        cert_chain_complete=False,
                        cert_chain_error="self-signed certificate",
                        cert_chain_depth=1,
                        cert_san=("other.example",),
                    ),
                )
            ],
        )
        report = _make_report(result)
        raw = JsonFormatter().format(report)

        parsed = json.loads(raw)
        assert parsed["summary"]["total_findings"] > 0
        assert parsed["results"][0]["mode"] == "external"
        assert parsed["results"][0]["server_type"] == "nginx"
        assert parsed["results"][0]["metadata"]["probe_attempts"][0]["tls_info"]["cert_chain_depth"] == 1
        assert len(parsed["findings"]) == parsed["summary"]["total_findings"]


# ---------------------------------------------------------------------------
# Cross-format consistency
# ---------------------------------------------------------------------------


class TestCrossFormat:
    def test_text_and_json_finding_counts_match(self, tmp_path: Path) -> None:
        path = _write_config(tmp_path, "nginx.conf", _NGINX_CONFIG)
        result = analyze_nginx_config(path)
        report = _make_report(result)

        text = TextFormatter().format(report)
        raw_json = JsonFormatter().format(report)
        parsed = json.loads(raw_json)

        assert f"Findings: {len(report.all_findings)}" in text
        assert parsed["summary"]["total_findings"] == len(report.all_findings)

    def test_json_findings_severity_order(self, tmp_path: Path) -> None:
        """Findings in JSON top-level array are severity-sorted."""
        path = _write_config(tmp_path, "httpd.conf", _APACHE_CONFIG)
        result = analyze_apache_config(path)
        report = _make_report(result)
        raw = JsonFormatter().format(report)
        parsed = json.loads(raw)

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        severities = [severity_order[f["severity"]] for f in parsed["findings"]]
        assert severities == sorted(severities)

    def test_multi_result_aggregation(self, tmp_path: Path) -> None:
        nginx_path = _write_config(tmp_path, "nginx.conf", _NGINX_CONFIG)
        apache_path = _write_config(tmp_path, "httpd.conf", _APACHE_CONFIG)

        r1 = analyze_nginx_config(nginx_path)
        r2 = analyze_apache_config(apache_path)
        report = ReportData(results=[r1, r2])

        text = TextFormatter().format(report)
        raw_json = JsonFormatter().format(report)
        parsed = json.loads(raw_json)

        dedup_total = len(report.all_findings)
        assert f"Findings: {dedup_total}" in text
        assert parsed["summary"]["total_findings"] == dedup_total
        assert len(parsed["findings"]) == dedup_total
        assert len(parsed["results"]) == 2


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_result_produces_valid_output(self, tmp_path: Path) -> None:
        path = _write_config(tmp_path, "nginx.conf", "worker_processes 1;\n")
        result = analyze_nginx_config(path)
        report = _make_report(result)

        text = TextFormatter().format(report)
        assert "Findings: 0" in text

        raw = JsonFormatter().format(report)
        parsed = json.loads(raw)
        assert parsed["summary"]["total_findings"] == 0
        assert parsed["findings"] == []

    def test_result_with_only_issues(self, tmp_path: Path) -> None:
        path = _write_config(tmp_path, "nginx.conf", "broken config\n")
        result = analyze_nginx_config(path)
        report = _make_report(result)

        assert result.issues, "parse error expected"
        text = TextFormatter().format(report)
        assert "Issues:" in text
        assert "Analysis issues: " in text

        raw = JsonFormatter().format(report)
        parsed = json.loads(raw)
        assert parsed["summary"]["total_issues"] > 0
        assert len(parsed["issues"]) > 0

    def test_json_generated_at_is_utc(self, tmp_path: Path) -> None:
        path = _write_config(tmp_path, "nginx.conf", "worker_processes 1;\n")
        result = analyze_nginx_config(path)
        report = _make_report(result)
        raw = JsonFormatter().format(report)
        parsed = json.loads(raw)
        assert "+00:00" in parsed["generated_at"] or "Z" in parsed["generated_at"]


# ---------------------------------------------------------------------------
# Plan G: extended integration tests
# ---------------------------------------------------------------------------


class TestLighttpdConditionalIntegration:
    """Lighttpd with conditional blocks and include_shell skipped."""

    def test_lighttpd_with_conditional_and_include_shell(self, tmp_path: Path) -> None:
        config = (
            'server.document-root = "/var/www"\n'
            'server.port = 8080\n'
            'server.tag = "lighttpd/1.4"\n'
            '$HTTP["host"] == "secure.example" {\n'
            '    ssl.engine = "enable"\n'
            '}\n'
            'include_shell "generate-extra.sh"\n'
        )
        path = _write_config(tmp_path, "lighttpd.conf", config)
        result = analyze_lighttpd_config(path)
        report = _make_report(result)

        # Should have findings and an include_shell_skipped issue.
        assert result.findings
        shell_issues = [i for i in result.issues if "include_shell" in i.code]
        assert len(shell_issues) == 1
        assert shell_issues[0].level == "warning"

        text = TextFormatter().format(report)
        assert "lighttpd" in text.lower()
        assert f"Findings: {len(report.all_findings)}" in text

    def test_lighttpd_host_filter_integration(self, tmp_path: Path) -> None:
        config = (
            'server.tag = ""\n'
            'server.errorlog = "/var/log/err.log"\n'
            '$HTTP["host"] == "a.example" {\n'
            '    dir-listing.activate = "enable"\n'
            '}\n'
        )
        path = _write_config(tmp_path, "lighttpd.conf", config)
        result_a = analyze_lighttpd_config(path, host="a.example")
        result_b = analyze_lighttpd_config(path, host="b.example")

        dir_a = [f for f in result_a.findings if f.rule_id == "lighttpd.dir_listing_enabled"]
        dir_b = [f for f in result_b.findings if f.rule_id == "lighttpd.dir_listing_enabled"]
        assert len(dir_a) >= 1
        assert len(dir_b) == 0


class TestIISMachineConfigIntegration:
    """IIS with machine.config chain."""

    def test_iis_with_machine_config(self, tmp_path: Path) -> None:
        machine = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            "<configuration>\n"
            "  <system.web>\n"
            '    <compilation debug="true" />\n'
            "  </system.web>\n"
            "</configuration>\n"
        )
        web = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            "<configuration>\n"
            "  <system.webServer>\n"
            '    <directoryBrowse enabled="true" />\n'
            "  </system.webServer>\n"
            "</configuration>\n"
        )
        machine_path = _write_config(tmp_path, "machine.config", machine)
        web_path = _write_config(tmp_path, "web.config", web)

        result = analyze_iis_config(web_path, machine_config_path=machine_path)
        report = _make_report(result)

        assert result.findings
        assert result.metadata["machine_config_path"] is not None
        assert len(result.metadata["inheritance_chain"]) == 2

        text = TextFormatter().format(report)
        assert f"Findings: {len(report.all_findings)}" in text


class TestDeduplicationEndToEnd:
    """Deduplication between universal and server-specific findings."""

    def test_dedup_suppresses_universal_duplicates(self, tmp_path: Path) -> None:
        # Nginx config that triggers both server-specific and universal dir listing.
        config = (
            "worker_processes 1;\n"
            "events {}\n"
            "http {\n"
            "    server {\n"
            "        listen 80;\n"
            "        autoindex on;\n"
            "        server_tokens on;\n"
            "    }\n"
            "}\n"
        )
        path = _write_config(tmp_path, "nginx.conf", config)
        result = analyze_nginx_config(path)
        report = _make_report(result)

        # Raw findings include both nginx.autoindex_on and universal.directory_listing_enabled.
        raw_ids = {f.rule_id for f in result.findings}
        assert "nginx.autoindex_on" in raw_ids
        assert "universal.directory_listing_enabled" in raw_ids

        # Deduplicated findings should suppress the universal duplicate.
        dedup_ids = {f.rule_id for f in report.all_findings}
        assert "nginx.autoindex_on" in dedup_ids
        assert "universal.directory_listing_enabled" not in dedup_ids

        summary = report.summary()
        assert summary.suppressed_duplicates > 0
