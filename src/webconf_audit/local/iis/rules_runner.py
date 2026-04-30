"""Entry point for local IIS rule modules.

Rules are discovered automatically via the global rule registry.
Each rule file in ``rules/iis/`` is decorated with ``@rule(...)``
which registers it at import time.
"""

from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig
from webconf_audit.local.iis.parser import IISConfigDocument
from webconf_audit.local.rule_runner_utils import run_rule_entry
from webconf_audit.models import AnalysisIssue, Finding
from webconf_audit.rule_registry import registry

_IIS_PKG = "webconf_audit.local.iis.rules"


def run_iis_rules(
    doc: IISConfigDocument,
    *,
    effective_config: IISEffectiveConfig | None = None,
    issues: list[AnalysisIssue] | None = None,
) -> list[Finding]:
    registry.ensure_loaded(_IIS_PKG)
    findings: list[Finding] = []

    for entry in registry.rules_for("local", server_type="iis"):
        findings.extend(
            run_rule_entry(
                entry,
                issues=issues,
                invoke=lambda entry=entry: entry.fn(doc, effective_config=effective_config),
            )
        )

    return findings


__all__ = ["run_iis_rules"]
