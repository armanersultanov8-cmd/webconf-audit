"""Shared helpers for resilient local rule execution."""

from __future__ import annotations

from collections.abc import Callable

from webconf_audit.models import AnalysisIssue, Finding, SourceLocation
from webconf_audit.rule_registry import RuleEntry


def run_rule_entry(
    entry: RuleEntry,
    *,
    issues: list[AnalysisIssue] | None,
    invoke: Callable[[], list[Finding]],
) -> list[Finding]:
    """Execute a rule and optionally downgrade rule crashes to analysis issues."""
    try:
        return invoke()
    except Exception as exc:
        if issues is None:
            raise
        issues.append(_rule_execution_issue(entry, exc))
        return []


def _rule_execution_issue(entry: RuleEntry, exc: Exception) -> AnalysisIssue:
    return AnalysisIssue(
        code="rule_execution_error",
        level="warning",
        message=f"Rule {entry.meta.rule_id} failed during local analysis.",
        details=f"{type(exc).__name__}: {exc}",
        location=SourceLocation(
            mode="local",
            kind="check",
            target=entry.meta.rule_id,
        ),
        metadata={
            "rule_id": entry.meta.rule_id,
            "server_type": entry.meta.server_type,
            "category": entry.meta.category,
            "input_kind": entry.meta.input_kind,
            "exception_type": type(exc).__name__,
        },
    )


__all__ = ["run_rule_entry"]
