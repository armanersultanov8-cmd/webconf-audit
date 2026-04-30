from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import BlockNode, ConfigAst, iter_nodes
from webconf_audit.local.nginx.rules.header_utils import (
    build_missing_header_finding,
    server_has_header,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.missing_permissions_policy"


@rule(
    rule_id=RULE_ID,
    title="Missing Permissions-Policy header",
    severity="low",
    description="Server block does not define a Permissions-Policy header.",
    recommendation="Add a Permissions-Policy header to this server block.",
    category="local",
    server_type="nginx",
    tags=("headers",),
    order=226,
)
def find_missing_permissions_policy(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if isinstance(node, BlockNode) and node.name == "server":
            finding = _find_missing_permissions_policy_in_server(node)
            if finding is not None:
                findings.append(finding)

    return findings


def _find_missing_permissions_policy_in_server(server_block: BlockNode) -> Finding | None:
    has_permissions_policy = server_has_header(server_block, "Permissions-Policy")

    if has_permissions_policy:
        return None

    return build_missing_header_finding(
        server_block,
        rule_id=RULE_ID,
        title="Missing Permissions-Policy header",
        description="Server block does not define a Permissions-Policy header.",
        recommendation="Add a Permissions-Policy header to this server block.",
    )


__all__ = ["find_missing_permissions_policy"]
