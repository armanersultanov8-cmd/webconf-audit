from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst, DirectiveNode, iter_nodes
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.server_tokens_on"


@rule(
    rule_id=RULE_ID,
    title="Server tokens enabled",
    severity="low",
    description="Nginx explicitly enables server_tokens with 'server_tokens on;'.",
    recommendation="Set 'server_tokens off;' or remove the directive if exposure is unnecessary.",
    category="local",
    server_type="nginx",
    order=237,
)
def find_server_tokens_on(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if isinstance(node, DirectiveNode) and node.name == "server_tokens" and node.args == ["on"]:
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    title="Server tokens enabled",
                    severity="low",
                    description="Nginx explicitly enables server_tokens with 'server_tokens on;'.",
                    recommendation="Set 'server_tokens off;' or remove the directive if exposure is unnecessary.",
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path=node.source.file_path,
                        line=node.source.line,
                    ),
                )
            )

    return findings


__all__ = ["find_server_tokens_on"]
