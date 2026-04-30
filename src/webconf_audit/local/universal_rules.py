"""Entry point for universal rules that run against the normalized config model.

Universal rules complement -- not replace -- server-specific rule packs.
Each rule is a ``check(NormalizedConfig) -> list[Finding]`` function
decorated with ``@rule(category="universal", input_kind="normalized")``.

Rules are discovered automatically via the global :data:`rule_registry.registry`.
"""

from __future__ import annotations

from webconf_audit.local.normalized import NormalizedConfig
from webconf_audit.local.rule_runner_utils import run_rule_entry
from webconf_audit.models import AnalysisIssue, Finding
from webconf_audit.rule_registry import registry

_UNIVERSAL_PKG = "webconf_audit.local.rules.universal"


def run_universal_rules(
    normalized: NormalizedConfig,
    *,
    issues: list[AnalysisIssue] | None = None,
) -> list[Finding]:
    """Run all universal rules against a normalized config."""
    registry.ensure_loaded(_UNIVERSAL_PKG)
    findings: list[Finding] = []
    for entry in registry.rules_for("universal"):
        findings.extend(
            run_rule_entry(
                entry,
                issues=issues,
                invoke=lambda entry=entry: entry.fn(normalized),
            )
        )
    return findings


__all__ = ["run_universal_rules"]
