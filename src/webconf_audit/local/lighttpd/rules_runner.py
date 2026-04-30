"""Entry point for local Lighttpd rule modules.

Rules are discovered automatically via the global rule registry.
Each rule file in ``rules/lighttpd/`` is decorated with ``@rule(...)``
which registers it at import time.
"""

from __future__ import annotations

from webconf_audit.local.lighttpd.effective import (
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
)
from webconf_audit.local.lighttpd.parser import LighttpdConfigAst
from webconf_audit.local.rule_runner_utils import run_rule_entry
from webconf_audit.models import AnalysisIssue, Finding
from webconf_audit.rule_registry import registry

_LIGHTTPD_PKG = "webconf_audit.local.lighttpd.rules"


def run_lighttpd_rules(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    issues: list[AnalysisIssue] | None = None,
) -> list[Finding]:
    registry.ensure_loaded(_LIGHTTPD_PKG)
    findings: list[Finding] = []

    for entry in registry.rules_for("local", server_type="lighttpd"):
        if entry.meta.input_kind == "effective":
            findings.extend(
                run_rule_entry(
                    entry,
                    issues=issues,
                    invoke=lambda entry=entry: entry.fn(
                        config_ast,
                        effective_config=effective_config,
                        merged_directives=merged_directives,
                    ),
                )
            )
        else:
            findings.extend(
                run_rule_entry(
                    entry,
                    issues=issues,
                    invoke=lambda entry=entry: entry.fn(config_ast),
                )
            )

    return findings


__all__ = ["run_lighttpd_rules"]
