"""Tests for the report module."""

from __future__ import annotations

import json

from webconf_audit.models import (
    AnalysisIssue,
    AnalysisResult,
    Finding,
    SourceLocation,
)
from webconf_audit.report import JsonFormatter, ReportData, TextFormatter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(
    rule_id: str = "test.rule",
    severity: str = "medium",
    title: str = "Test finding",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,  # type: ignore[arg-type]
        description="desc",
        recommendation="rec",
    )


def _issue(code: str = "W001", level: str = "warning", message: str = "warn") -> AnalysisIssue:
    return AnalysisIssue(code=code, level=level, message=message)  # type: ignore[arg-type]


def _result(
    mode: str = "local",
    target: str = "/etc/nginx/nginx.conf",
    server_type: str | None = "nginx",
    findings: list[Finding] | None = None,
    issues: list[AnalysisIssue] | None = None,
) -> AnalysisResult:
    return AnalysisResult(
        mode=mode,  # type: ignore[arg-type]
        target=target,
        server_type=server_type,
        findings=findings or [],
        issues=issues or [],
    )


# ---------------------------------------------------------------------------
# 7.1.1  ReportData + ReportSummary
# ---------------------------------------------------------------------------

class TestReportDataBasic:
    def test_single_result_counts(self) -> None:
        r = _result(findings=[_finding(), _finding(severity="high")])
        report = ReportData(results=[r])
        s = report.summary()
        assert s.total_findings == 2
        assert s.total_issues == 0

    def test_multiple_results_aggregation(self) -> None:
        r1 = _result(
            target="/a",
            server_type="nginx",
            findings=[_finding(severity="high")],
        )
        r2 = _result(
            target="/b",
            server_type="apache",
            findings=[_finding(severity="low"), _finding(severity="low")],
        )
        report = ReportData(results=[r1, r2])
        s = report.summary()
        assert s.total_findings == 3
        assert s.by_server_type == {"nginx": 1, "apache": 2}
        assert s.targets_analyzed == ["/a", "/b"]

    def test_all_findings_sorted_by_severity(self) -> None:
        r = _result(findings=[
            _finding(rule_id="z", severity="low"),
            _finding(rule_id="a", severity="critical"),
            _finding(rule_id="m", severity="high"),
        ])
        report = ReportData(results=[r])
        ids = [f.rule_id for f in report.all_findings]
        assert ids == ["a", "m", "z"]

    def test_all_findings_sorted_by_rule_id_within_severity(self) -> None:
        r = _result(findings=[
            _finding(rule_id="b.rule", severity="medium"),
            _finding(rule_id="a.rule", severity="medium"),
        ])
        report = ReportData(results=[r])
        ids = [f.rule_id for f in report.all_findings]
        assert ids == ["a.rule", "b.rule"]

    def test_summary_by_severity_full_keys(self) -> None:
        """by_severity always contains all 5 keys, even if zero."""
        r = _result(findings=[_finding(severity="high")])
        report = ReportData(results=[r])
        s = report.summary()
        assert set(s.by_severity.keys()) == {"critical", "high", "medium", "low", "info"}
        assert s.by_severity["high"] == 1
        assert s.by_severity["critical"] == 0

    def test_summary_by_mode(self) -> None:
        r1 = _result(mode="local", findings=[_finding()])
        r2 = _result(mode="external", target="example.com", findings=[_finding(), _finding()])
        report = ReportData(results=[r1, r2])
        s = report.summary()
        assert s.by_mode == {"local": 1, "external": 2}

    def test_empty_report(self) -> None:
        report = ReportData(results=[])
        s = report.summary()
        assert s.total_findings == 0
        assert s.total_issues == 0
        assert s.targets_analyzed == []

    def test_issues_sorted_error_before_warning(self) -> None:
        r = _result(issues=[
            _issue(code="W001", level="warning"),
            _issue(code="E001", level="error"),
        ])
        report = ReportData(results=[r])
        codes = [i.code for i in report.all_issues]
        assert codes == ["E001", "W001"]

    def test_generated_at_is_utc_iso(self) -> None:
        report = ReportData(results=[])
        # UTC ISO format ends with +00:00
        assert "+00:00" in report.generated_at or "Z" in report.generated_at

    def test_issues_counted_in_summary(self) -> None:
        r = _result(issues=[_issue(), _issue(code="E002", level="error")])
        report = ReportData(results=[r])
        s = report.summary()
        assert s.total_issues == 2


# ---------------------------------------------------------------------------
# 7.1.2  TextFormatter
# ---------------------------------------------------------------------------

class TestTextFormatter:
    def test_contains_summary_header(self) -> None:
        r = _result(findings=[_finding(severity="high")])
        out = TextFormatter().format(ReportData(results=[r]))
        assert "webconf-audit report" in out
        assert "Findings: 1" in out

    def test_severity_group_headers(self) -> None:
        r = _result(findings=[_finding(severity="high")])
        out = TextFormatter().format(ReportData(results=[r]))
        assert "=== HIGH (1) ===" in out
        assert "=== MEDIUM (0) ===" in out

    def test_findings_grouped_critical_before_low(self) -> None:
        r = _result(findings=[
            _finding(rule_id="low.rule", severity="low"),
            _finding(rule_id="crit.rule", severity="critical"),
        ])
        out = TextFormatter().format(ReportData(results=[r]))
        crit_pos = out.index("crit.rule")
        low_pos = out.index("low.rule")
        assert crit_pos < low_pos

    def test_location_in_output(self) -> None:
        f = _finding()
        f.location = SourceLocation(mode="local", kind="file", file_path="/a.conf", line=10)
        r = _result(findings=[f])
        out = TextFormatter().format(ReportData(results=[r]))
        assert "/a.conf:10" in out

    def test_issues_in_output(self) -> None:
        r = _result(issues=[_issue(code="E001", level="error", message="bad")])
        out = TextFormatter().format(ReportData(results=[r]))
        assert "[error] E001: bad" in out

    def test_footer_totals(self) -> None:
        r = _result(findings=[_finding()], issues=[_issue()])
        out = TextFormatter().format(ReportData(results=[r]))
        assert "Total: 1 findings, 1 issues" in out

    def test_multi_target_headers(self) -> None:
        r1 = _result(target="/a", server_type="nginx")
        r2 = _result(target="/b", server_type="apache")
        out = TextFormatter().format(ReportData(results=[r1, r2]))
        assert "-- /a (nginx) --" in out
        assert "-- /b (apache) --" in out

    def test_empty_report(self) -> None:
        out = TextFormatter().format(ReportData(results=[]))
        assert "Findings: 0" in out
        assert "Total: 0 findings, 0 issues" in out

    def test_external_summary_renders_port_tls_headers_and_redirects(self) -> None:
        result = AnalysisResult(
            mode="external",
            target="example.com",
            server_type="nginx",
            metadata={
                "port_scan": [
                    {"port": 443, "tcp_open": True},
                    {"port": 8443, "tcp_open": False, "error_message": "timeout"},
                ],
                "server_identification": {
                    "server_type": "nginx",
                    "confidence": "high",
                    "evidence": [
                        {"signal": "server_header"},
                        {"signal": "error_page_body"},
                    ],
                },
                "probe_attempts": [
                    {
                        "scheme": "https",
                        "url": "https://example.com/",
                        "tls_info": {
                            "protocol_version": "TLSv1.3",
                            "supported_protocols": ["TLSv1.2", "TLSv1.3"],
                            "cipher_name": "TLS_AES_256_GCM_SHA384",
                            "cipher_bits": 256,
                            "cert_chain_complete": False,
                            "cert_chain_error": "certificate verify failed",
                        },
                        "cache_control_header": "no-store",
                        "cross_origin_embedder_policy_header": "require-corp",
                    }
                ],
                "redirect_chains": [
                    {
                        "hops": [{"url": "http://example.com/"}],
                        "final_url": "https://example.com/login",
                        "mixed_scheme_redirect": True,
                        "truncated": True,
                    }
                ],
            },
        )

        out = TextFormatter().format(ReportData(results=[result]))

        assert "External Summary:" in out
        assert "port discovery: 2 scanned; open ports: 443" in out
        assert "port discovery errors: 8443" in out
        assert "server identification: nginx" in out
        assert "high confidence" in out
        assert "signals: error_page_body, server_header" in out
        assert "tls: https://example.com/:" in out
        assert "TLSv1.3" in out
        assert "supports TLSv1.2, TLSv1.3" in out
        assert "cipher TLS_AES_256_GCM_SHA384 (256 bits)" in out
        assert "chain incomplete" in out
        assert "chain error: certificate verify failed" in out
        assert "extra headers: https://example.com/:" in out
        assert "Cache-Control=no-store" in out
        assert "COEP=require-corp" in out
        assert "redirect chain: http://example.com/ -> https://example.com/login" in out
        assert "mixed-scheme" in out
        assert "truncated" in out

    def test_external_summary_renders_ambiguous_identification(self) -> None:
        result = AnalysisResult(
            mode="external",
            target="example.com",
            metadata={
                "server_identification": {
                    "ambiguous": True,
                    "confidence": "medium",
                    "candidate_server_types": ["apache", "nginx"],
                    "evidence": [
                        {"signal": "server_header"},
                        {"signal": "malformed_response_body"},
                    ],
                }
            },
        )

        out = TextFormatter().format(ReportData(results=[result]))

        assert "server identification: ambiguous" in out
        assert "medium confidence" in out
        assert "candidates: apache, nginx" in out
        assert "malformed_response_body" in out
        assert "server_header" in out


# ---------------------------------------------------------------------------
# 7.1.2  JsonFormatter
# ---------------------------------------------------------------------------

class TestJsonFormatter:
    def test_valid_json(self) -> None:
        r = _result(findings=[_finding()])
        out = JsonFormatter().format(ReportData(results=[r]))
        parsed = json.loads(out)
        assert isinstance(parsed, dict)

    def test_json_has_summary(self) -> None:
        r = _result(findings=[_finding(severity="high")])
        out = JsonFormatter().format(ReportData(results=[r]))
        parsed = json.loads(out)
        assert "summary" in parsed
        assert parsed["summary"]["total_findings"] == 1
        assert parsed["summary"]["by_severity"]["high"] == 1

    def test_json_has_results(self) -> None:
        r = _result(findings=[_finding()])
        out = JsonFormatter().format(ReportData(results=[r]))
        parsed = json.loads(out)
        assert len(parsed["results"]) == 1
        assert parsed["results"][0]["target"] == "/etc/nginx/nginx.conf"

    def test_json_has_generated_at(self) -> None:
        out = JsonFormatter().format(ReportData(results=[]))
        parsed = json.loads(out)
        assert "generated_at" in parsed

    def test_json_findings_present(self) -> None:
        r = _result(findings=[_finding(rule_id="x.rule")])
        out = JsonFormatter().format(ReportData(results=[r]))
        parsed = json.loads(out)
        findings = parsed["results"][0]["findings"]
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "x.rule"

    def test_json_empty_report(self) -> None:
        out = JsonFormatter().format(ReportData(results=[]))
        parsed = json.loads(out)
        assert parsed["summary"]["total_findings"] == 0
        assert parsed["results"] == []

    def test_json_severity_full_keys(self) -> None:
        out = JsonFormatter().format(ReportData(results=[]))
        parsed = json.loads(out)
        keys = set(parsed["summary"]["by_severity"].keys())
        assert keys == {"critical", "high", "medium", "low", "info"}

    def test_json_top_level_findings_sorted(self) -> None:
        """Top-level findings array is severity-sorted (critical before low)."""
        r = _result(findings=[
            _finding(rule_id="low.rule", severity="low"),
            _finding(rule_id="high.rule", severity="high"),
            _finding(rule_id="crit.rule", severity="critical"),
        ])
        out = JsonFormatter().format(ReportData(results=[r]))
        parsed = json.loads(out)
        top_ids = [f["rule_id"] for f in parsed["findings"]]
        assert top_ids == ["crit.rule", "high.rule", "low.rule"]

    def test_json_top_level_issues_sorted(self) -> None:
        """Top-level issues array is level-sorted (error before warning)."""
        r = _result(issues=[
            _issue(code="W001", level="warning"),
            _issue(code="E001", level="error"),
        ])
        out = JsonFormatter().format(ReportData(results=[r]))
        parsed = json.loads(out)
        top_codes = [i["code"] for i in parsed["issues"]]
        assert top_codes == ["E001", "W001"]

    def test_json_top_level_findings_aggregated_across_results(self) -> None:
        """Top-level findings aggregates from multiple results."""
        r1 = _result(target="/a", findings=[_finding(rule_id="a.rule", severity="high")])
        r2 = _result(target="/b", findings=[_finding(rule_id="b.rule", severity="medium")])
        out = JsonFormatter().format(ReportData(results=[r1, r2]))
        parsed = json.loads(out)
        assert len(parsed["findings"]) == 2
        assert parsed["findings"][0]["rule_id"] == "a.rule"
        assert parsed["findings"][1]["rule_id"] == "b.rule"

    def test_json_empty_report_has_empty_top_level_arrays(self) -> None:
        out = JsonFormatter().format(ReportData(results=[]))
        parsed = json.loads(out)
        assert parsed["findings"] == []
        assert parsed["issues"] == []
