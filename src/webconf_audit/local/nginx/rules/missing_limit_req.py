from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    find_child_directives,
    iter_nodes,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.missing_limit_req"


@rule(
    rule_id=RULE_ID,
    title="Missing limit_req directive",
    severity="low",
    description="Server block does not define 'limit_req' in server or location scope.",
    recommendation="Add a 'limit_req' directive to this server block or one of its location blocks.",
    category="local",
    server_type="nginx",
    order=223,
)
def find_missing_limit_req(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if isinstance(node, BlockNode) and node.name == "server":
            finding = _find_missing_limit_req_in_server(node)
            if finding is not None:
                findings.append(finding)

    return findings


def _find_missing_limit_req_in_server(server_block: BlockNode) -> Finding | None:
    if find_child_directives(server_block, "limit_req"):
        return None

    if _server_has_location_limit_req(server_block):
        return None

    return Finding(
        rule_id=RULE_ID,
        title="Missing limit_req directive",
        severity="low",
        description="Server block does not define 'limit_req' in server or location scope.",
        recommendation="Add a 'limit_req' directive to this server block or one of its location blocks.",
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=server_block.source.file_path,
            line=server_block.source.line,
        ),
    )


def _server_has_location_limit_req(server_block: BlockNode) -> bool:
    return any(
        isinstance(node, BlockNode)
        and node.name == "location"
        and bool(find_child_directives(node, "limit_req"))
        for node in iter_nodes(server_block.children)
    )


__all__ = ["find_missing_limit_req"]
