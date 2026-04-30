from __future__ import annotations

from webconf_audit.local.lighttpd.effective import (
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
)
from webconf_audit.local.lighttpd.parser import LighttpdConfigAst
from webconf_audit.local.lighttpd.rules.rule_utils import iter_all_nodes, normalize_value
from webconf_audit.finding_factory import finding_from_rule
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "lighttpd.dir_listing_enabled"
_DIRECTIVE = "dir-listing.activate"


@rule(
    rule_id=RULE_ID,
    title="Directory listing enabled",
    severity="medium",
    description="Lighttpd configuration explicitly enables directory listing.",
    recommendation="Disable directory listing unless it is intentionally required.",
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    order=401,
)
def find_dir_listing_enabled(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
) -> list[Finding]:
    if merged_directives is not None:
        return _find_from_merged(merged_directives)

    if effective_config is not None:
        return _find_from_effective(effective_config)

    # Fallback: no effective config - use raw AST (backward-compatible).
    return _find_from_ast(config_ast)


def _find_from_merged(
    merged: dict[str, LighttpdEffectiveDirective],
) -> list[Finding]:
    """Check the merged (host-filtered) directive view."""
    d = merged.get(_DIRECTIVE)
    if d is not None and normalize_value(d.value) == "enable":
        return [_make_finding(d.source.file_path, d.source.line)]
    return []


def _find_from_effective(
    effective_config: LighttpdEffectiveConfig,
) -> list[Finding]:
    findings: list[Finding] = []

    gd = effective_config.get_global(_DIRECTIVE)
    if gd is not None and normalize_value(gd.value) == "enable":
        findings.append(_make_finding(gd.source.file_path, gd.source.line))

    for scope in effective_config.conditional_scopes:
        sd = scope.directives.get(_DIRECTIVE)
        if sd is not None and normalize_value(sd.value) == "enable":
            findings.append(_make_finding(sd.source.file_path, sd.source.line))

    return findings


def _make_finding(
    file_path: str | None,
    line: int | None,
) -> Finding:
    return finding_from_rule(
        find_dir_listing_enabled,
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=file_path,
            line=line,
        ),
    )


def _find_from_ast(config_ast: LighttpdConfigAst) -> list[Finding]:
    """Legacy raw-AST fallback when effective config is not available."""
    from webconf_audit.local.lighttpd.parser import LighttpdAssignmentNode

    findings: list[Finding] = []
    for node in iter_all_nodes(config_ast):
        if not isinstance(node, LighttpdAssignmentNode):
            continue
        if node.name != _DIRECTIVE:
            continue
        if normalize_value(node.value) != "enable":
            continue
        findings.append(_make_finding(node.source.file_path, node.source.line))
    return findings


__all__ = ["find_dir_listing_enabled"]
