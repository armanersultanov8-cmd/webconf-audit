"""Entry point for local Apache rule modules.

Rules are discovered automatically via the global rule registry.
Each rule file in ``rules/apache/`` is decorated with ``@rule(...)``
which registers it at import time.
"""

from __future__ import annotations

from pathlib import Path

from webconf_audit.local.apache.htaccess import HtaccessFile
from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.rule_runner_utils import run_rule_entry
from webconf_audit.models import AnalysisIssue, Finding
from webconf_audit.rule_registry import registry

_APACHE_PKG = "webconf_audit.local.apache.rules"


def run_apache_ast_rules(
    config_ast: ApacheConfigAst,
    *,
    issues: list[AnalysisIssue] | None = None,
) -> list[Finding]:
    """Run Apache rules that only need the parsed AST.

    Many AST rules already handle VirtualHost contexts internally,
    so they are invoked once on the full AST.
    """
    registry.ensure_loaded(_APACHE_PKG)
    findings: list[Finding] = []
    for entry in registry.rules_for("local", server_type="apache"):
        if entry.meta.input_kind == "ast":
            findings.extend(
                run_rule_entry(
                    entry,
                    issues=issues,
                    invoke=lambda entry=entry: entry.fn(config_ast),
                )
            )
    return findings


def run_apache_htaccess_rules(
    config_ast: ApacheConfigAst,
    htaccess_files: list[HtaccessFile],
    config_dir: Path | None = None,
    *,
    issues: list[AnalysisIssue] | None = None,
) -> list[Finding]:
    """Run Apache rules that need htaccess files (htaccess and mixed kinds)."""
    registry.ensure_loaded(_APACHE_PKG)
    findings: list[Finding] = []
    if not htaccess_files:
        return findings
    for entry in registry.rules_for("local", server_type="apache"):
        ik = entry.meta.input_kind
        if ik == "htaccess":
            findings.extend(
                run_rule_entry(
                    entry,
                    issues=issues,
                    invoke=lambda entry=entry: entry.fn(htaccess_files),
                )
            )
        elif ik == "mixed":
            findings.extend(
                run_rule_entry(
                    entry,
                    issues=issues,
                    invoke=lambda entry=entry: entry.fn(
                        config_ast,
                        htaccess_files,
                        config_dir=config_dir,
                    ),
                )
            )
    return findings


def run_apache_rules(
    config_ast: ApacheConfigAst,
    htaccess_files: list[HtaccessFile] | None = None,
    config_dir: str | None = None,
    *,
    issues: list[AnalysisIssue] | None = None,
) -> list[Finding]:
    """Run all Apache rules (backward-compatible entry point)."""
    findings = run_apache_ast_rules(config_ast, issues=issues)
    if htaccess_files:
        findings.extend(
            run_apache_htaccess_rules(
                config_ast,
                htaccess_files,
                config_dir=Path(config_dir) if config_dir else None,
                issues=issues,
            )
        )
    return findings


__all__ = ["run_apache_ast_rules", "run_apache_htaccess_rules", "run_apache_rules"]
