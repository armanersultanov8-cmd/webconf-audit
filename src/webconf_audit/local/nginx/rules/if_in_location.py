from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import BlockNode, ConfigAst, iter_nodes
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.if_in_location"


@rule(
    rule_id=RULE_ID,
    title="if inside location block",
    severity="low",
    description="Location block contains an 'if' block.",
    recommendation="Move the condition out of this location block.",
    category="local",
    server_type="nginx",
    order=205,
)
def find_if_in_location(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if isinstance(node, BlockNode) and node.name == "location":
            findings.extend(_find_if_nodes(node))

    return findings


def _find_if_nodes(location_block: BlockNode) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(location_block.children):
        if getattr(node, "name", None) != "if":
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="if inside location block",
                severity="low",
                description="Location block contains an 'if' block.",
                recommendation="Move the condition out of this location block.",
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=node.source.file_path,
                    line=node.source.line,
                ),
            )
        )

    return findings


__all__ = ["find_if_in_location"]
