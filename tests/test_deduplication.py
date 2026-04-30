"""Tests for finding deduplication between universal and server-specific rules."""

from __future__ import annotations

import json

from webconf_audit.models import AnalysisResult, Finding, SourceLocation
from webconf_audit.report import (
    UNIVERSAL_TO_SPECIFIC_MAP,
    JsonFormatter,
    ReportData,
    TextFormatter,
    deduplicate_findings,
)
from webconf_audit.rule_registry import registry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(rule_id: str, severity: str = "medium") -> Finding:
    return Finding(
        rule_id=rule_id,
        title=f"Title for {rule_id}",
        severity=severity,  # type: ignore[arg-type]
        description="desc",
        recommendation="rec",
    )


def _finding_at(rule_id: str, line: int) -> Finding:
    finding = _finding(rule_id)
    finding.location = SourceLocation(
        mode="local",
        kind="file",
        file_path="/etc/nginx/nginx.conf",
        line=line,
    )
    return finding


def _result(findings: list[Finding]) -> AnalysisResult:
    return AnalysisResult(
        mode="local",
        target="/test",
        server_type="nginx",
        findings=findings,
        issues=[],
    )


# ---------------------------------------------------------------------------
# deduplicate_findings() unit tests
# ---------------------------------------------------------------------------

class TestDeduplicateFindings:
    def test_empty_list(self) -> None:
        result, suppressed = deduplicate_findings([])
        assert result == []
        assert suppressed == 0

    def test_no_universal_findings_unchanged(self) -> None:
        findings = [_finding("nginx.server_tokens_on"), _finding("nginx.autoindex_on")]
        result, suppressed = deduplicate_findings(findings)
        assert len(result) == 2
        assert suppressed == 0

    def test_universal_only_preserved(self) -> None:
        """Universal finding without server-specific counterpart stays."""
        findings = [_finding("universal.directory_listing_enabled")]
        result, suppressed = deduplicate_findings(findings)
        assert len(result) == 1
        assert suppressed == 0

    def test_universal_suppressed_when_specific_exists(self) -> None:
        """nginx.autoindex_on covers universal.directory_listing_enabled."""
        findings = [
            _finding("nginx.autoindex_on"),
            _finding("universal.directory_listing_enabled"),
        ]
        result, suppressed = deduplicate_findings(findings)
        assert len(result) == 1
        assert result[0].rule_id == "nginx.autoindex_on"
        assert suppressed == 1

    def test_multiple_universal_suppressed(self) -> None:
        """Multiple universal findings suppressed at once."""
        findings = [
            _finding("nginx.autoindex_on"),
            _finding("nginx.server_tokens_on"),
            _finding("nginx.missing_hsts_header"),
            _finding("universal.directory_listing_enabled"),
            _finding("universal.server_identification_disclosed"),
            _finding("universal.missing_hsts"),
        ]
        result, suppressed = deduplicate_findings(findings)
        assert suppressed == 3
        rule_ids = {f.rule_id for f in result}
        assert "universal.directory_listing_enabled" not in rule_ids
        assert "universal.server_identification_disclosed" not in rule_ids
        assert "universal.missing_hsts" not in rule_ids
        assert "nginx.autoindex_on" in rule_ids
        assert "nginx.server_tokens_on" in rule_ids
        assert "nginx.missing_hsts_header" in rule_ids

    def test_universal_kept_when_different_server_specific(self) -> None:
        """Universal finding kept when only unrelated server-specific exists."""
        findings = [
            _finding("nginx.server_tokens_on"),  # maps to server_identification_disclosed
            _finding("universal.directory_listing_enabled"),  # no nginx dir listing → keep
        ]
        result, suppressed = deduplicate_findings(findings)
        assert len(result) == 2
        assert suppressed == 0

    def test_apache_specific_suppresses_universal(self) -> None:
        findings = [
            _finding("apache.options_indexes"),
            _finding("universal.directory_listing_enabled"),
        ]
        result, suppressed = deduplicate_findings(findings)
        assert len(result) == 1
        assert result[0].rule_id == "apache.options_indexes"
        assert suppressed == 1

    def test_universal_kept_when_specific_is_different_location(self) -> None:
        findings = [
            _finding_at("nginx.autoindex_on", 10),
            _finding_at("universal.directory_listing_enabled", 20),
        ]
        result, suppressed = deduplicate_findings(findings)
        assert len(result) == 2
        assert suppressed == 0

    def test_universal_suppressed_when_specific_is_same_location(self) -> None:
        findings = [
            _finding_at("nginx.autoindex_on", 10),
            _finding_at("universal.directory_listing_enabled", 10),
        ]
        result, suppressed = deduplicate_findings(findings)
        assert len(result) == 1
        assert result[0].rule_id == "nginx.autoindex_on"
        assert suppressed == 1

    def test_lighttpd_specific_suppresses_universal(self) -> None:
        findings = [
            _finding("lighttpd.dir_listing_enabled"),
            _finding("lighttpd.server_tag_not_blank"),
            _finding("universal.directory_listing_enabled"),
            _finding("universal.server_identification_disclosed"),
        ]
        result, suppressed = deduplicate_findings(findings)
        assert suppressed == 2
        assert len(result) == 2

    def test_iis_specific_suppresses_universal(self) -> None:
        findings = [
            _finding("iis.directory_browse_enabled"),
            _finding("iis.missing_hsts_header"),
            _finding("universal.directory_listing_enabled"),
            _finding("universal.missing_hsts"),
        ]
        result, suppressed = deduplicate_findings(findings)
        assert suppressed == 2
        assert len(result) == 2

    def test_original_list_not_modified(self) -> None:
        findings = [
            _finding("nginx.autoindex_on"),
            _finding("universal.directory_listing_enabled"),
        ]
        original_len = len(findings)
        deduplicate_findings(findings)
        assert len(findings) == original_len

    def test_header_rules_nginx(self) -> None:
        """All nginx header universal duplicates are suppressed."""
        findings = [
            _finding("nginx.missing_x_content_type_options"),
            _finding("nginx.missing_x_frame_options"),
            _finding("nginx.missing_content_security_policy"),
            _finding("nginx.missing_referrer_policy"),
            _finding("universal.missing_x_content_type_options"),
            _finding("universal.missing_x_frame_options"),
            _finding("universal.missing_content_security_policy"),
            _finding("universal.missing_referrer_policy"),
        ]
        result, suppressed = deduplicate_findings(findings)
        assert suppressed == 4
        assert len(result) == 4
        assert all(f.rule_id.startswith("nginx.") for f in result)


# ---------------------------------------------------------------------------
# Mapping integrity
# ---------------------------------------------------------------------------

class TestMappingIntegrity:
    def test_all_universal_ids_exist_in_registry(self) -> None:
        """Every universal rule_id in the mapping is a real rule."""
        registry.ensure_loaded("webconf_audit.local.rules.universal")
        for uid in UNIVERSAL_TO_SPECIFIC_MAP:
            assert registry.get_meta(uid) is not None, f"{uid} not in registry"

    def test_all_specific_ids_exist_in_registry(self) -> None:
        """Every server-specific rule_id in the mapping is a real rule."""
        registry.ensure_loaded("webconf_audit.local.nginx.rules")
        registry.ensure_loaded("webconf_audit.local.apache.rules")
        registry.ensure_loaded("webconf_audit.local.lighttpd.rules")
        registry.ensure_loaded("webconf_audit.local.iis.rules")
        for specific_ids in UNIVERSAL_TO_SPECIFIC_MAP.values():
            for sid in specific_ids:
                assert registry.get_meta(sid) is not None, f"{sid} not in registry"

    def test_no_duplicate_specific_ids(self) -> None:
        """No server-specific rule appears in two different universal mappings."""
        all_specific: list[str] = []
        for specific_ids in UNIVERSAL_TO_SPECIFIC_MAP.values():
            all_specific.extend(specific_ids)
        assert len(all_specific) == len(set(all_specific))


# ---------------------------------------------------------------------------
# ReportData integration
# ---------------------------------------------------------------------------

class TestReportDataDeduplication:
    def test_all_findings_returns_deduplicated(self) -> None:
        findings = [
            _finding("nginx.autoindex_on"),
            _finding("universal.directory_listing_enabled"),
        ]
        report = ReportData(results=[_result(findings)])
        assert len(report.all_findings) == 1
        assert report.all_findings[0].rule_id == "nginx.autoindex_on"

    def test_all_findings_raw_returns_everything(self) -> None:
        findings = [
            _finding("nginx.autoindex_on"),
            _finding("universal.directory_listing_enabled"),
        ]
        report = ReportData(results=[_result(findings)])
        assert len(report.all_findings_raw) == 2

    def test_summary_uses_dedup_counts(self) -> None:
        findings = [
            _finding("nginx.autoindex_on"),
            _finding("universal.directory_listing_enabled"),
            _finding("nginx.missing_hsts_header"),
            _finding("universal.missing_hsts"),
        ]
        report = ReportData(results=[_result(findings)])
        summary = report.summary()
        assert summary.total_findings == 2
        assert summary.suppressed_duplicates == 2

    def test_summary_no_suppression_when_no_overlap(self) -> None:
        findings = [
            _finding("nginx.missing_server_name"),
            _finding("universal.listen_on_all_interfaces", severity="info"),
        ]
        report = ReportData(results=[_result(findings)])
        summary = report.summary()
        assert summary.total_findings == 2
        assert summary.suppressed_duplicates == 0

    def test_results_not_modified(self) -> None:
        """Original AnalysisResult.findings are untouched."""
        findings = [
            _finding("nginx.autoindex_on"),
            _finding("universal.directory_listing_enabled"),
        ]
        report = ReportData(results=[_result(findings)])
        _ = report.all_findings
        assert len(report.results[0].findings) == 2

    def test_deduplication_is_scoped_per_result(self) -> None:
        report = ReportData(results=[
            AnalysisResult(
                mode="local",
                target="/nginx",
                server_type="nginx",
                findings=[_finding("nginx.autoindex_on")],
                issues=[],
            ),
            AnalysisResult(
                mode="local",
                target="/apache",
                server_type="apache",
                findings=[_finding("universal.directory_listing_enabled")],
                issues=[],
            ),
        ])

        rule_ids = [finding.rule_id for finding in report.all_findings]
        assert rule_ids == [
            "nginx.autoindex_on",
            "universal.directory_listing_enabled",
        ]

        summary = report.summary()
        assert summary.total_findings == 2
        assert summary.suppressed_duplicates == 0
        assert summary.by_server_type["nginx"] == 1
        assert summary.by_server_type["apache"] == 1


# ---------------------------------------------------------------------------
# Formatter integration
# ---------------------------------------------------------------------------

class TestFormatterDeduplication:
    def test_text_shows_suppressed_count(self) -> None:
        findings = [
            _finding("nginx.autoindex_on"),
            _finding("universal.directory_listing_enabled"),
        ]
        report = ReportData(results=[_result(findings)])
        text = TextFormatter().format(report)
        assert "1 universal finding(s) suppressed" in text
        assert "Findings: 1" in text

    def test_text_body_omits_suppressed_finding(self) -> None:
        findings = [
            _finding("nginx.autoindex_on"),
            _finding("universal.directory_listing_enabled"),
        ]
        report = ReportData(results=[_result(findings)])
        text = TextFormatter().format(report)
        assert "[nginx.autoindex_on]" in text
        assert "[universal.directory_listing_enabled]" not in text

    def test_text_no_suppressed_line_when_zero(self) -> None:
        findings = [_finding("nginx.missing_server_name")]
        report = ReportData(results=[_result(findings)])
        text = TextFormatter().format(report)
        assert "suppressed" not in text

    def test_json_includes_suppressed_count(self) -> None:
        findings = [
            _finding("nginx.autoindex_on"),
            _finding("universal.directory_listing_enabled"),
        ]
        report = ReportData(results=[_result(findings)])
        raw = JsonFormatter().format(report)
        parsed = json.loads(raw)
        assert parsed["summary"]["suppressed_duplicates"] == 1
        assert len(parsed["findings"]) == 1

    def test_json_zero_suppressed(self) -> None:
        findings = [_finding("nginx.missing_server_name")]
        report = ReportData(results=[_result(findings)])
        raw = JsonFormatter().format(report)
        parsed = json.loads(raw)
        assert parsed["summary"]["suppressed_duplicates"] == 0
