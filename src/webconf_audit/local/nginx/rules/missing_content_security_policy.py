from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import BlockNode, ConfigAst, iter_nodes
from webconf_audit.local.nginx.rules.header_utils import (
    build_missing_header_finding,
    server_has_header,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.missing_content_security_policy"


@rule(
    rule_id=RULE_ID,
    title="Missing Content-Security-Policy header",
    severity="low",
    description="Server block does not define a Content-Security-Policy header.",
    recommendation="Add a Content-Security-Policy header to this server block.",
    category="local",
    server_type="nginx",
    tags=("headers",),
    order=214,
)
def find_missing_content_security_policy(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if isinstance(node, BlockNode) and node.name == "server":
            finding = _find_missing_content_security_policy_in_server(node)
            if finding is not None:
                findings.append(finding)

    return findings


def _find_missing_content_security_policy_in_server(server_block: BlockNode) -> Finding | None:
    has_content_security_policy = server_has_header(server_block, "Content-Security-Policy")

    if has_content_security_policy:
        return None

    return build_missing_header_finding(
        server_block,
        rule_id=RULE_ID,
        title="Missing Content-Security-Policy header",
        description="Server block does not define a Content-Security-Policy header.",
        recommendation="Add a Content-Security-Policy header to this server block.",
    )


__all__ = ["find_missing_content_security_policy"]
