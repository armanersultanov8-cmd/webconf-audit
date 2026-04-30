from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst, DirectiveNode, iter_nodes
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.autoindex_on"


@rule(
    rule_id=RULE_ID,
    title="Autoindex enabled",
    severity="medium",
    description="Nginx explicitly enables directory listing with 'autoindex on;'.",
    recommendation="Set 'autoindex off;' or remove the directive if directory listing is unnecessary.",
    category="local",
    server_type="nginx",
    order=202,
)
def find_autoindex_on(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if isinstance(node, DirectiveNode) and node.name == "autoindex" and node.args == ["on"]:
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    title="Autoindex enabled",
                    severity="medium",
                    description="Nginx explicitly enables directory listing with 'autoindex on;'.",
                    recommendation="Set 'autoindex off;' or remove the directive if directory listing is unnecessary.",
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path=node.source.file_path,
                        line=node.source.line,
                    ),
                )
            )

    return findings


__all__ = ["find_autoindex_on"]
