from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import BlockNode, ConfigAst, find_child_directives, iter_nodes
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.allow_all_with_deny_all"


@rule(
    rule_id=RULE_ID,
    title="Conflicting allow/deny all directives",
    severity="low",
    description="Location block contains both 'allow all;' and 'deny all;'.",
    recommendation="Remove one of the conflicting access directives from this location block.",
    category="local",
    server_type="nginx",
    order=201,
)
def find_allow_all_with_deny_all(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if isinstance(node, BlockNode) and node.name == "location":
            findings.extend(_find_allow_all_with_deny_all_in_location(node))

    return findings


def _find_allow_all_with_deny_all_in_location(location_block: BlockNode) -> list[Finding]:
    allow_all = any(node.args == ["all"] for node in find_child_directives(location_block, "allow"))
    deny_all = any(node.args == ["all"] for node in find_child_directives(location_block, "deny"))

    if not allow_all or not deny_all:
        return []

    return [
        Finding(
            rule_id=RULE_ID,
            title="Conflicting allow/deny all directives",
            severity="low",
            description="Location block contains both 'allow all;' and 'deny all;'.",
            recommendation="Remove one of the conflicting access directives from this location block.",
            location=SourceLocation(
                mode="local",
                kind="file",
                file_path=location_block.source.file_path,
                line=location_block.source.line,
            ),
        )
    ]


__all__ = ["find_allow_all_with_deny_all"]
