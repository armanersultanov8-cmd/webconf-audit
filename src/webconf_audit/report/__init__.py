"""Unified report module for webconf-audit.

Aggregates AnalysisResult(s) into a structured report with summary
statistics, severity-sorted findings, and multiple output formats.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from pydantic import BaseModel, Field

from webconf_audit.models import (
    AnalysisIssue,
    AnalysisResult,
    Finding,
    SourceLocation,
    Severity,
)

# Severity ordering: most critical first.
_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

_ISSUE_LEVEL_ORDER: dict[str, int] = {
    "error": 0,
    "warning": 1,
}

_ALL_SEVERITIES: list[Severity] = ["critical", "high", "medium", "low", "info"]

# ---------------------------------------------------------------------------
# Deduplication: universal vs server-specific rule mapping
# ---------------------------------------------------------------------------

# When a server-specific rule fires for the same issue that a universal rule
# also covers, the universal finding is suppressed in the report to avoid
# duplicates.  The server-specific finding is always more precise.

UNIVERSAL_TO_SPECIFIC_MAP: dict[str, list[str]] = {
    "universal.directory_listing_enabled": [
        "nginx.autoindex_on",
        "apache.options_indexes",
        "lighttpd.dir_listing_enabled",
        "iis.directory_browse_enabled",
    ],
    "universal.server_identification_disclosed": [
        "nginx.server_tokens_on",
        "apache.server_tokens_not_prod",
        "apache.server_signature_not_off",
        "lighttpd.server_tag_not_blank",
        "iis.http_runtime_version_header_enabled",
    ],
    "universal.missing_hsts": [
        "nginx.missing_hsts_header",
        "lighttpd.missing_strict_transport_security",
        "iis.missing_hsts_header",
    ],
    "universal.missing_x_content_type_options": [
        "nginx.missing_x_content_type_options",
        "lighttpd.missing_x_content_type_options",
    ],
    "universal.missing_x_frame_options": [
        "nginx.missing_x_frame_options",
    ],
    "universal.missing_content_security_policy": [
        "nginx.missing_content_security_policy",
    ],
    "universal.missing_referrer_policy": [
        "nginx.missing_referrer_policy",
    ],
}


def deduplicate_findings(findings: list[Finding]) -> tuple[list[Finding], int]:
    """Remove universal findings when a server-specific equivalent exists.

    Returns a tuple of (deduplicated findings, number of suppressed findings).
    The original list is not modified.
    """
    present_specific_locations = _collect_finding_locations(findings)
    suppress = _suppressed_universal_findings(
        findings, present_specific_locations,
    )

    if not suppress:
        return list(findings), 0

    deduplicated = [
        f
        for f in findings
        if (f.rule_id, _dedup_location_key(f)) not in suppress
    ]
    return deduplicated, len(findings) - len(deduplicated)


def _collect_finding_locations(
    findings: list[Finding],
) -> dict[str, set[tuple[object, ...]]]:
    present_locations: dict[str, set[tuple[object, ...]]] = {}
    for finding in findings:
        present_locations.setdefault(finding.rule_id, set()).add(
            _dedup_location_key(finding)
        )
    return present_locations


def _suppressed_universal_findings(
    findings: list[Finding],
    present_specific_locations: dict[str, set[tuple[object, ...]]],
) -> set[tuple[str, tuple[object, ...]]]:
    suppress: set[tuple[str, tuple[object, ...]]] = set()
    for universal_id, specific_ids in UNIVERSAL_TO_SPECIFIC_MAP.items():
        suppress.update(
            _suppressed_keys_for_universal_rule(
                findings,
                universal_id,
                specific_ids,
                present_specific_locations,
            )
        )
    return suppress


def _suppressed_keys_for_universal_rule(
    findings: list[Finding],
    universal_id: str,
    specific_ids: list[str],
    present_specific_locations: dict[str, set[tuple[object, ...]]],
) -> set[tuple[str, tuple[object, ...]]]:
    suppress: set[tuple[str, tuple[object, ...]]] = set()
    for finding in findings:
        if finding.rule_id != universal_id:
            continue
        universal_key = _dedup_location_key(finding)
        if _has_specific_location_match(
            universal_key, specific_ids, present_specific_locations,
        ):
            suppress.add((universal_id, universal_key))
    return suppress


def _has_specific_location_match(
    universal_key: tuple[object, ...],
    specific_ids: list[str],
    present_specific_locations: dict[str, set[tuple[object, ...]]],
) -> bool:
    return any(
        universal_key in present_specific_locations.get(specific_id, set())
        for specific_id in specific_ids
    )


def _dedup_location_key(finding: Finding) -> tuple[object, ...]:
    location = finding.location
    if location is None:
        return ("no-location",)
    return (
        location.mode,
        location.kind,
        location.file_path,
        location.line,
        location.xml_path,
        location.target,
        location.details
        if location.line is None and location.xml_path is None and location.target is None
        else None,
    )


def _deduplicated_findings_by_result(
    results: list[AnalysisResult],
) -> tuple[list[tuple[AnalysisResult, list[Finding]]], int]:
    """Deduplicate findings independently inside each analysis result."""
    deduplicated_results: list[tuple[AnalysisResult, list[Finding]]] = []
    suppressed_total = 0

    for result in results:
        deduplicated, suppressed = deduplicate_findings(result.findings)
        deduplicated.sort(key=_finding_sort_key)
        deduplicated_results.append((result, deduplicated))
        suppressed_total += suppressed

    return deduplicated_results, suppressed_total


def _finding_sort_key(f: Finding) -> tuple[int, str]:
    return (_SEVERITY_ORDER.get(f.severity, 99), f.rule_id)


def _issue_sort_key(i: AnalysisIssue) -> tuple[int, str]:
    return (_ISSUE_LEVEL_ORDER.get(i.level, 99), i.code)


class ReportSummary(BaseModel):
    """Aggregated statistics across all results."""

    total_findings: int = 0
    total_issues: int = 0
    suppressed_duplicates: int = 0
    by_severity: dict[str, int] = Field(default_factory=lambda: {s: 0 for s in _ALL_SEVERITIES})
    by_mode: dict[str, int] = Field(default_factory=dict)
    by_server_type: dict[str, int] = Field(default_factory=dict)
    targets_analyzed: list[str] = Field(default_factory=list)


class ReportData(BaseModel):
    """Unified report payload from one or more analysis runs."""

    results: list[AnalysisResult] = Field(default_factory=list)
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )

    @property
    def all_findings_raw(self) -> list[Finding]:
        """All findings across results (before deduplication), sorted."""
        findings: list[Finding] = []
        for r in self.results:
            findings.extend(r.findings)
        findings.sort(key=_finding_sort_key)
        return findings

    @property
    def all_findings(self) -> list[Finding]:
        """All findings across results, deduplicated and sorted."""
        deduplicated_results, _ = _deduplicated_findings_by_result(self.results)
        findings: list[Finding] = []
        for _result, deduplicated in deduplicated_results:
            findings.extend(deduplicated)
        findings.sort(key=_finding_sort_key)
        return findings

    @property
    def all_issues(self) -> list[AnalysisIssue]:
        """All issues across results, sorted by level then code."""
        issues: list[AnalysisIssue] = []
        for r in self.results:
            issues.extend(r.issues)
        issues.sort(key=_issue_sort_key)
        return issues

    def summary(self) -> ReportSummary:
        """Compute aggregated statistics (uses deduplicated findings)."""
        deduplicated_results, suppressed = _deduplicated_findings_by_result(self.results)

        by_severity: dict[str, int] = {s: 0 for s in _ALL_SEVERITIES}
        by_mode: dict[str, int] = {}
        by_server_type: dict[str, int] = {}
        targets: list[str] = []

        for result, deduplicated in deduplicated_results:
            targets.append(result.target)
            dedup_count = len(deduplicated)
            by_mode[result.mode] = by_mode.get(result.mode, 0) + dedup_count
            if result.server_type:
                by_server_type[result.server_type] = (
                    by_server_type.get(result.server_type, 0) + dedup_count
                )
            for finding in deduplicated:
                by_severity[finding.severity] = (
                    by_severity.get(finding.severity, 0) + 1
                )

        total_issues = sum(len(result.issues) for result in self.results)

        return ReportSummary(
            total_findings=sum(
                len(deduplicated)
                for _, deduplicated in deduplicated_results
            ),
            total_issues=total_issues,
            suppressed_duplicates=suppressed,
            by_severity=by_severity,
            by_mode=by_mode,
            by_server_type=by_server_type,
            targets_analyzed=targets,
        )


# ---------------------------------------------------------------------------
# Location formatting (shared by formatters)
# ---------------------------------------------------------------------------

def format_location(location: SourceLocation | None) -> str | None:
    """Format a SourceLocation into a human-readable string."""
    if location is None:
        return None
    if location.file_path:
        if location.line is not None:
            return f"{location.file_path}:{location.line}"
        return location.file_path
    if location.target:
        return location.target
    if location.xml_path:
        return location.xml_path
    if location.details:
        return location.details
    return location.kind


# ---------------------------------------------------------------------------
# TextFormatter
# ---------------------------------------------------------------------------

class TextFormatter:
    """Render ReportData as human-readable terminal output."""

    def format(self, report: ReportData) -> str:
        summary = report.summary()
        deduplicated_results, _ = _deduplicated_findings_by_result(report.results)
        lines = _report_header_lines(report, summary)
        multi = len(report.results) > 1

        for result, result_findings in deduplicated_results:
            lines.extend(_result_section_lines(result, result_findings, multi=multi))

        lines.append(
            f"Total: {summary.total_findings} findings,"
            f" {summary.total_issues} issues"
        )
        return "\n".join(lines)


def _report_header_lines(
    report: ReportData,
    summary: ReportSummary,
) -> list[str]:
    lines = ["=" * 50, "  webconf-audit report"]
    lines.extend(_report_target_lines(report.results))
    lines.extend(_report_summary_lines(report.generated_at, summary))
    return lines


def _report_target_lines(results: list[AnalysisResult]) -> list[str]:
    lines: list[str] = []
    for result in results:
        parts = [f"Target: {result.target}", f"Mode: {result.mode}"]
        if result.server_type:
            parts.append(f"Server: {result.server_type}")
        lines.append(f"  {' | '.join(parts)}")
    return lines


def _report_summary_lines(
    generated_at: str,
    summary: ReportSummary,
) -> list[str]:
    sev = summary.by_severity
    lines = [
        f"  Generated: {generated_at}",
        "-" * 50,
        f"  Findings: {summary.total_findings}",
        (
            f"    Critical: {sev['critical']}  High: {sev['high']}"
            f"  Medium: {sev['medium']}  Low: {sev['low']}"
            f"  Info: {sev['info']}"
        ),
        f"  Analysis issues: {summary.total_issues}",
    ]
    if summary.suppressed_duplicates > 0:
        lines.append(
            f"  ({summary.suppressed_duplicates} universal finding(s)"
            " suppressed as duplicates of server-specific rules)"
        )
    lines.extend(["=" * 50, ""])
    return lines


def _result_section_lines(
    result: AnalysisResult,
    result_findings: list[Finding],
    *,
    multi: bool,
) -> list[str]:
    lines: list[str] = []
    if multi:
        lines.extend(_multi_target_header_lines(result))
    lines.extend(_external_section_lines(result))
    lines.extend(_severity_section_lines(result_findings))
    lines.extend(_issue_section_lines(result.issues))
    lines.extend(_diagnostic_section_lines(result.diagnostics))
    return lines


def _multi_target_header_lines(result: AnalysisResult) -> list[str]:
    server_label = f" ({result.server_type})" if result.server_type else ""
    return [f"-- {result.target}{server_label} --", ""]


def _external_section_lines(result: AnalysisResult) -> list[str]:
    ext_lines = _external_summary_lines(result)
    if not ext_lines:
        return []
    return ["External Summary:", *[f"- {line}" for line in ext_lines], ""]


def _severity_section_lines(result_findings: list[Finding]) -> list[str]:
    lines: list[str] = []
    by_severity = _findings_by_severity(result_findings)
    for severity in _ALL_SEVERITIES:
        group = by_severity[severity]
        lines.append(f"=== {severity.upper()} ({len(group)}) ===")
        for finding in group:
            lines.extend(_finding_lines(finding))
        lines.append("")
    return lines


def _findings_by_severity(
    result_findings: list[Finding],
) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = {severity: [] for severity in _ALL_SEVERITIES}
    for finding in result_findings:
        grouped[finding.severity].append(finding)
    return grouped


def _finding_lines(finding: Finding) -> list[str]:
    lines = [f"  [{finding.rule_id}] {finding.title}"]
    location = format_location(finding.location)
    if location:
        lines.append(f"    location: {location}")
    lines.append(f"    description: {finding.description}")
    lines.append(f"    recommendation: {finding.recommendation}")
    return lines


def _issue_section_lines(issues: list[AnalysisIssue]) -> list[str]:
    if not issues:
        return []
    lines = ["Issues:"]
    for issue in sorted(issues, key=_issue_sort_key):
        lines.extend(_issue_lines(issue))
    lines.append("")
    return lines


def _issue_lines(issue: AnalysisIssue) -> list[str]:
    lines = [f"  [{issue.level}] {issue.code}: {issue.message}"]
    location = format_location(issue.location)
    if location:
        lines.append(f"    location: {location}")
    return lines


def _diagnostic_section_lines(diagnostics: list[str]) -> list[str]:
    if not diagnostics:
        return []
    return ["Diagnostics:", *[f"  - {diagnostic}" for diagnostic in diagnostics], ""]


# ---------------------------------------------------------------------------
# JsonFormatter
# ---------------------------------------------------------------------------

class JsonFormatter:
    """Render ReportData as structured JSON."""

    def format(self, report: ReportData) -> str:
        summary = report.summary()
        payload = {
            "generated_at": report.generated_at,
            "summary": summary.model_dump(),
            "results": [r.model_dump() for r in report.results],
            "findings": [f.model_dump() for f in report.all_findings],
            "issues": [i.model_dump() for i in report.all_issues],
        }
        return json.dumps(payload, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# External summary helpers (moved from cli.py)
# ---------------------------------------------------------------------------

def _external_summary_lines(result: AnalysisResult) -> list[str]:
    if result.mode != "external":
        return []
    lines: list[str] = []
    lines.extend(_port_scan_summary_lines(result.metadata))
    identification_line = _identification_summary_line(result.metadata)
    if identification_line is not None:
        lines.append(identification_line)
    lines.extend(_tls_summary_lines(result.metadata))
    lines.extend(_extra_header_summary_lines(result.metadata))
    lines.extend(_redirect_chain_summary_lines(result.metadata))
    return lines


def _port_scan_summary_lines(metadata: dict[str, object]) -> list[str]:
    raw_scan_results = metadata.get("port_scan")
    if not isinstance(raw_scan_results, list) or not raw_scan_results:
        return []
    open_ports: list[str] = []
    errored_ports: list[str] = []
    for entry in raw_scan_results:
        if not isinstance(entry, dict):
            continue
        port = entry.get("port")
        if not isinstance(port, int):
            continue
        if entry.get("tcp_open") is True:
            open_ports.append(str(port))
        elif entry.get("error_message"):
            errored_ports.append(str(port))
    lines = [
        "port discovery: "
        f"{len(raw_scan_results)} scanned; open ports: "
        f"{', '.join(open_ports) if open_ports else 'none'}"
    ]
    if errored_ports:
        lines.append(f"port discovery errors: {', '.join(errored_ports)}")
    return lines


def _identification_summary_line(metadata: dict[str, object]) -> str | None:
    raw_identification = metadata.get("server_identification")
    if not isinstance(raw_identification, dict):
        return None
    confidence = _summary_string(raw_identification.get("confidence"), default="unknown")
    signal_suffix = _identification_signal_suffix(raw_identification)
    if raw_identification.get("ambiguous") is True:
        return _ambiguous_identification_line(raw_identification, confidence, signal_suffix)
    server_type = _summary_string(raw_identification.get("server_type"))
    if server_type:
        return (
            "server identification: "
            f"{server_type} ({confidence} confidence{signal_suffix})"
        )
    return f"server identification: unknown ({confidence} confidence{signal_suffix})"


def _identification_signal_suffix(raw_identification: dict[str, object]) -> str:
    signals = _identification_signals(raw_identification.get("evidence"))
    if not signals:
        return ""
    return f"; signals: {', '.join(signals)}"


def _identification_signals(raw_evidence: object) -> list[str]:
    if not isinstance(raw_evidence, list):
        return []
    seen: set[str] = set()
    for entry in raw_evidence:
        if not isinstance(entry, dict):
            continue
        signal = _summary_string(entry.get("signal"))
        if signal:
            seen.add(signal)
    return sorted(seen)


def _ambiguous_identification_line(
    raw_identification: dict[str, object],
    confidence: str,
    signal_suffix: str,
) -> str:
    candidates = raw_identification.get("candidate_server_types")
    if isinstance(candidates, list) and candidates:
        return (
            "server identification: ambiguous "
            f"({confidence} confidence; candidates: {', '.join(candidates)}"
            f"{signal_suffix})"
        )
    return f"server identification: ambiguous ({confidence} confidence{signal_suffix})"


def _tls_summary_lines(metadata: dict[str, object]) -> list[str]:
    raw_attempts = metadata.get("probe_attempts")
    if not isinstance(raw_attempts, list):
        return []
    lines: list[str] = []
    for attempt in raw_attempts:
        line = _tls_summary_line(attempt)
        if line is not None:
            lines.append(line)
    return lines


def _tls_summary_line(attempt: object) -> str | None:
    if not isinstance(attempt, dict) or attempt.get("scheme") != "https":
        return None
    tls_info = attempt.get("tls_info")
    url = _summary_string(attempt.get("url"))
    if not isinstance(tls_info, dict) or not url:
        return None
    parts = _tls_summary_parts(tls_info)
    if not parts:
        return None
    return f"tls: {url}: {'; '.join(parts)}"


def _tls_summary_parts(tls_info: dict[str, object]) -> list[str]:
    parts = _tls_protocol_parts(tls_info)
    cipher_text = _tls_cipher_text(tls_info)
    if cipher_text:
        parts.append(cipher_text)
    parts.extend(_tls_chain_parts(tls_info))
    return parts


def _tls_protocol_parts(tls_info: dict[str, object]) -> list[str]:
    parts: list[str] = []
    protocol_version = _summary_string(tls_info.get("protocol_version"))
    if protocol_version:
        parts.append(protocol_version)
    supported = _summary_string_list(tls_info.get("supported_protocols"))
    if supported:
        parts.append(f"supports {', '.join(supported)}")
    return parts


def _tls_cipher_text(tls_info: dict[str, object]) -> str | None:
    cipher_name = _summary_string(tls_info.get("cipher_name"))
    if not cipher_name:
        return None
    cipher_text = f"cipher {cipher_name}"
    cipher_bits = tls_info.get("cipher_bits")
    if isinstance(cipher_bits, int):
        cipher_text += f" ({cipher_bits} bits)"
    return cipher_text


def _tls_chain_parts(tls_info: dict[str, object]) -> list[str]:
    parts: list[str] = []
    chain_complete = tls_info.get("cert_chain_complete")
    if chain_complete is True:
        parts.append("chain complete")
    elif chain_complete is False:
        parts.append("chain incomplete")
    chain_error = _summary_string(tls_info.get("cert_chain_error"))
    if chain_error:
        parts.append(f"chain error: {chain_error}")
    return parts


def _extra_header_summary_lines(metadata: dict[str, object]) -> list[str]:
    raw_attempts = metadata.get("probe_attempts")
    if not isinstance(raw_attempts, list):
        return []
    lines: list[str] = []
    for attempt in raw_attempts:
        if not isinstance(attempt, dict):
            continue
        url = attempt.get("url")
        if not isinstance(url, str):
            continue
        header_parts: list[str] = []
        for field, label in (
            ("cache_control_header", "Cache-Control"),
            ("x_dns_prefetch_control_header", "X-DNS-Prefetch-Control"),
            ("cross_origin_embedder_policy_header", "COEP"),
            ("cross_origin_opener_policy_header", "COOP"),
            ("cross_origin_resource_policy_header", "CORP"),
        ):
            value = attempt.get(field)
            if isinstance(value, str) and value:
                header_parts.append(f"{label}={value}")
        if header_parts:
            lines.append(f"extra headers: {url}: {'; '.join(header_parts)}")
    return lines


def _redirect_chain_summary_lines(metadata: dict[str, object]) -> list[str]:
    raw_chains = metadata.get("redirect_chains")
    if not isinstance(raw_chains, list):
        return []
    lines: list[str] = []
    for chain in raw_chains:
        line = _redirect_chain_line(chain)
        if line is not None:
            lines.append(line)
    return lines


def _redirect_chain_line(chain: object) -> str | None:
    if not isinstance(chain, dict):
        return None
    path_parts = _redirect_path_parts(chain)
    if not path_parts:
        return None
    flags = _redirect_flags(chain)
    suffix = f" ({', '.join(flags)})" if flags else ""
    return f"redirect chain: {' -> '.join(path_parts)}{suffix}"


def _redirect_path_parts(chain: dict[str, object]) -> list[str]:
    hops = chain.get("hops")
    if not isinstance(hops, list) or not hops:
        return []
    path_parts: list[str] = []
    for hop in hops:
        if not isinstance(hop, dict):
            continue
        url = _summary_string(hop.get("url"))
        if url:
            path_parts.append(url)
    final_url = _summary_string(chain.get("final_url"))
    if final_url and (not path_parts or final_url != path_parts[-1]):
        path_parts.append(final_url)
    return path_parts


def _redirect_flags(chain: dict[str, object]) -> list[str]:
    flags: list[str] = []
    for field, label in (
        ("loop_detected", "loop"),
        ("mixed_scheme_redirect", "mixed-scheme"),
        ("cross_domain_redirect", "cross-domain"),
        ("truncated", "truncated"),
    ):
        if chain.get(field) is True:
            flags.append(label)
    error_message = _summary_string(chain.get("error_message"))
    if error_message:
        flags.append(f"error: {error_message}")
    return flags


def _summary_string(value: object, *, default: str | None = None) -> str | None:
    if isinstance(value, str) and value:
        return value
    return default


def _summary_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


__all__ = [
    "JsonFormatter",
    "ReportData",
    "ReportSummary",
    "TextFormatter",
    "UNIVERSAL_TO_SPECIFIC_MAP",
    "deduplicate_findings",
    "format_location",
]
