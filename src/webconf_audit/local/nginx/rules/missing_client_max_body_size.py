from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    find_child_directives,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.missing_client_max_body_size"


@rule(
    rule_id=RULE_ID,
    title="Missing client_max_body_size directive",
    severity="low",
    description="Server block does not define 'client_max_body_size'.",
    recommendation="Add a 'client_max_body_size' directive to this server block.",
    category="local",
    server_type="nginx",
    order=213,
)
def find_missing_client_max_body_size(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for server_block, inherited in _iter_server_blocks_with_http_default(config_ast):
        if not inherited:
            finding = _find_missing_client_max_body_size_in_server(server_block)
            if finding is not None:
                findings.append(finding)

    return findings


def _find_missing_client_max_body_size_in_server(server_block: BlockNode) -> Finding | None:
    client_max_body_size_directives = find_child_directives(
        server_block,
        "client_max_body_size",
    )

    if client_max_body_size_directives:
        return None

    return Finding(
        rule_id=RULE_ID,
        title="Missing client_max_body_size directive",
        severity="low",
        description="Server block does not define 'client_max_body_size'.",
        recommendation="Add a 'client_max_body_size' directive to this server block.",
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=server_block.source.file_path,
            line=server_block.source.line,
        ),
    )


def _iter_server_blocks_with_http_default(
    config_ast: ConfigAst,
) -> list[tuple[BlockNode, bool]]:
    servers: list[tuple[BlockNode, bool]] = []

    def walk(nodes, inherited_client_max_body_size: bool = False) -> None:
        for node in nodes:
            if not isinstance(node, BlockNode):
                continue
            current_inherited = inherited_client_max_body_size
            if node.name == "http":
                current_inherited = bool(
                    find_child_directives(node, "client_max_body_size")
                )
            if node.name == "server":
                servers.append((node, current_inherited))
                continue
            walk(node.children, current_inherited)

    walk(config_ast.nodes)
    return servers


__all__ = ["find_missing_client_max_body_size"]
