"""Helpers for constructing findings from canonical rule metadata."""

from __future__ import annotations

from typing import Any, Callable

from webconf_audit.models import Finding, Severity, SourceLocation
from webconf_audit.rule_registry import RuleMeta, registry


def finding_from_rule(
    rule: str | Callable[..., Any] | RuleMeta,
    *,
    location: SourceLocation | None = None,
    metadata: dict[str, Any] | None = None,
    title: str | None = None,
    severity: Severity | None = None,
    description: str | None = None,
    recommendation: str | None = None,
) -> Finding:
    """Build a finding using rule metadata as the default source of truth."""
    meta = _resolve_rule_meta(rule)
    return Finding(
        rule_id=meta.rule_id,
        title=title or meta.title,
        severity=severity or meta.severity,
        description=description or meta.description,
        recommendation=recommendation or meta.recommendation,
        location=location,
        metadata={} if metadata is None else metadata.copy(),
    )


def _resolve_rule_meta(rule: str | Callable[..., Any] | RuleMeta) -> RuleMeta:
    if isinstance(rule, RuleMeta):
        return rule

    if isinstance(rule, str):
        meta = registry.get_meta(rule)
        if meta is None:
            raise ValueError(f"Unknown rule metadata for {rule!r}")
        return meta

    meta = getattr(rule, "_rule_meta", None)
    if isinstance(meta, RuleMeta):
        return meta

    raise ValueError("Rule metadata is not attached to the provided callable")


__all__ = ["finding_from_rule"]
