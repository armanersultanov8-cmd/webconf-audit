from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import BlockNode, ConfigAst, find_child_directives, iter_nodes
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.alias_without_trailing_slash"


@rule(
    rule_id=RULE_ID,
    title="Alias path missing trailing slash",
    severity="low",
    description="Location path ends with '/' but alias path does not.",
    recommendation="Add a trailing '/' to the alias path or adjust the location path.",
    category="local",
    server_type="nginx",
    order=200,
)
def find_alias_without_trailing_slash(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if isinstance(node, BlockNode) and node.name == "location":
            findings.extend(_find_alias_without_trailing_slash_in_location(node))

    return findings


def _find_alias_without_trailing_slash_in_location(location_block: BlockNode) -> list[Finding]:
    if not location_block.args or not location_block.args[0].endswith("/"):
        return []

    findings: list[Finding] = []

    for alias_node in find_child_directives(location_block, "alias"):
        if not alias_node.args or alias_node.args[0].endswith("/"):
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="Alias path missing trailing slash",
                severity="low",
                description="Location path ends with '/' but alias path does not.",
                recommendation="Add a trailing '/' to the alias path or adjust the location path.",
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=alias_node.source.file_path,
                    line=alias_node.source.line,
                ),
            )
        )

    return findings


__all__ = ["find_alias_without_trailing_slash"]
