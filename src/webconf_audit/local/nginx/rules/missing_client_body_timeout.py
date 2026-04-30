from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import BlockNode, ConfigAst, DirectiveNode, iter_nodes
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.missing_client_body_timeout"


@rule(
    rule_id=RULE_ID,
    title="Missing client_body_timeout directive",
    severity="low",
    description="Configuration does not define 'client_body_timeout'.",
    recommendation="Add a 'client_body_timeout' directive to the configuration.",
    category="local",
    server_type="nginx",
    order=211,
)
def find_missing_client_body_timeout(config_ast: ConfigAst) -> list[Finding]:
    server_blocks = [
        node for node in iter_nodes(config_ast.nodes) if isinstance(node, BlockNode) and node.name == "server"
    ]

    if not server_blocks:
        return []

    has_client_body_timeout = any(
        isinstance(node, DirectiveNode) and node.name == "client_body_timeout"
        for node in iter_nodes(config_ast.nodes)
    )

    if has_client_body_timeout:
        return []

    first_server = server_blocks[0]

    return [
        Finding(
            rule_id=RULE_ID,
            title="Missing client_body_timeout directive",
            severity="low",
            description="Configuration does not define 'client_body_timeout'.",
            recommendation="Add a 'client_body_timeout' directive to the configuration.",
            location=SourceLocation(
                mode="local",
                kind="file",
                file_path=first_server.source.file_path,
                line=first_server.source.line,
            ),
        )
    ]


__all__ = ["find_missing_client_body_timeout"]
