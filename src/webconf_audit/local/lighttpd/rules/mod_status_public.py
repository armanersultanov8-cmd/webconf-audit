from __future__ import annotations

from webconf_audit.local.lighttpd.effective import (
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
    merge_conditional_scopes,
)
from webconf_audit.finding_factory import finding_from_rule
from webconf_audit.local.lighttpd.parser import (
    LighttpdAssignmentNode,
    LighttpdBlockNode,
    LighttpdCondition,
    LighttpdConfigAst,
)
from webconf_audit.local.lighttpd.rules.rule_utils import iter_all_nodes, scope_conditions
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "lighttpd.mod_status_public"


@rule(
    rule_id=RULE_ID,
    title="Server status endpoint publicly accessible",
    severity="medium",
    description="status.status-url is configured without IP-based access restriction.",
    recommendation="Wrap status.status-url inside a remote-IP conditional to restrict access.",
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    order=408,
)
def find_mod_status_public(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
) -> list[Finding]:
    if (
        effective_config is not None
        and merged_directives is not None
        and merged_directives != merge_conditional_scopes(effective_config)
    ):
        return _find_from_merged(merged_directives, effective_config)

    if effective_config is not None:
        return _find_from_effective(effective_config)

    if merged_directives is not None:
        return _find_from_merged(merged_directives, effective_config)

    return _find_from_ast(config_ast)


def _find_from_effective(
    effective_config: LighttpdEffectiveConfig,
) -> list[Finding]:
    findings: list[Finding] = []

    global_directive = effective_config.get_global("status.status-url")
    if global_directive is not None:
        findings.append(_make_finding(global_directive.source.file_path, global_directive.source.line))

    for scope in effective_config.conditional_scopes:
        directive = scope.directives.get("status.status-url")
        if directive is None or _scope_is_remoteip_restricted(scope):
            continue
        findings.append(_make_finding(directive.source.file_path, directive.source.line))

    return findings


def _find_from_merged(
    merged_directives: dict[str, LighttpdEffectiveDirective],
    effective_config: LighttpdEffectiveConfig | None,
) -> list[Finding]:
    directive = merged_directives.get("status.status-url")
    if directive is None:
        return []

    if _directive_is_remoteip_restricted(directive, effective_config):
        return []

    return [
        _make_finding(
            file_path=directive.source.file_path,
            line=directive.source.line,
        )
    ]


def _directive_is_remoteip_restricted(
    directive: LighttpdEffectiveDirective,
    effective_config: LighttpdEffectiveConfig | None,
) -> bool:
    if _is_remoteip_condition(directive.condition):
        return True

    if effective_config is None:
        return False

    for scope in effective_config.conditional_scopes:
        scoped_directive = scope.directives.get("status.status-url")
        if scoped_directive is None:
            continue
        if not _same_source(scoped_directive, directive):
            continue
        if _scope_is_remoteip_restricted(scope):
            return True

    return False


def _same_source(
    left: LighttpdEffectiveDirective,
    right: LighttpdEffectiveDirective,
) -> bool:
    return (
        left.source.file_path == right.source.file_path
        and left.source.line == right.source.line
    )


def _is_remoteip_condition(condition: LighttpdCondition | None) -> bool:
    return condition is not None and '"remoteip"' in condition.variable


def _scope_is_remoteip_restricted(scope) -> bool:
    return any(_is_remoteip_condition(condition) for condition in scope_conditions(scope))


def _find_from_ast(config_ast: LighttpdConfigAst) -> list[Finding]:
    """Detect status.status-url set without remoteip restriction."""
    findings: list[Finding] = []

    for node in iter_all_nodes(config_ast):
        if not isinstance(node, LighttpdAssignmentNode):
            continue
        if node.name != "status.status-url":
            continue

        if _is_inside_remoteip_block(node, config_ast):
            continue

        findings.append(_make_finding(node.source.file_path, node.source.line))

    return findings


def _make_finding(
    file_path: str | None,
    line: int | None,
) -> Finding:
    return finding_from_rule(
        find_mod_status_public,
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=file_path,
            line=line,
        ),
    )


def _is_inside_remoteip_block(
    target: LighttpdAssignmentNode,
    config_ast: LighttpdConfigAst,
) -> bool:
    """Check whether the target node is a child of a $HTTP["remoteip"] block."""
    return _search_in_nodes(target, config_ast.nodes)


def _search_in_nodes(target: LighttpdAssignmentNode, nodes: list) -> bool:
    return _search_in_nodes_with_ancestors(target, nodes, ())


def _search_in_nodes_with_ancestors(
    target: LighttpdAssignmentNode,
    nodes: list,
    ancestor_conditions: tuple[LighttpdCondition | None, ...],
) -> bool:
    for node in nodes:
        if not isinstance(node, LighttpdBlockNode):
            continue
        conditions = (*ancestor_conditions, node.condition)
        if target in node.children:
            if any(_is_remoteip_condition(condition) for condition in conditions):
                return True
        if _search_in_nodes_with_ancestors(target, node.children, conditions):
            return True
    return False


__all__ = ["find_mod_status_public"]
