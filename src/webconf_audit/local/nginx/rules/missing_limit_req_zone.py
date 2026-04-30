from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst, DirectiveNode, iter_nodes
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.missing_limit_req_zone"


@rule(
    rule_id=RULE_ID,
    title="Missing limit_req_zone directive",
    severity="low",
    description="Configuration uses 'limit_req' but does not define 'limit_req_zone'.",
    recommendation="Add a 'limit_req_zone' directive when using request rate limiting.",
    category="local",
    server_type="nginx",
    order=224,
)
def find_missing_limit_req_zone(config_ast: ConfigAst) -> list[Finding]:
    limit_req_directives = [
        node
        for node in iter_nodes(config_ast.nodes)
        if isinstance(node, DirectiveNode) and node.name == "limit_req"
    ]

    if not limit_req_directives:
        return []

    has_limit_req_zone = any(
        isinstance(node, DirectiveNode) and node.name == "limit_req_zone"
        for node in iter_nodes(config_ast.nodes)
    )

    if has_limit_req_zone:
        return []

    first_limit_req = limit_req_directives[0]

    return [
        Finding(
            rule_id=RULE_ID,
            title="Missing limit_req_zone directive",
            severity="low",
            description="Configuration uses 'limit_req' but does not define 'limit_req_zone'.",
            recommendation="Add a 'limit_req_zone' directive when using request rate limiting.",
            location=SourceLocation(
                mode="local",
                kind="file",
                file_path=first_limit_req.source.file_path,
                line=first_limit_req.source.line,
            ),
        )
    ]


__all__ = ["find_missing_limit_req_zone"]
