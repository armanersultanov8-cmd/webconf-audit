from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import BlockNode, ConfigAst, iter_nodes
from webconf_audit.local.nginx.rules.header_utils import (
    build_missing_header_finding,
    server_header_contains_value,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.missing_x_content_type_options"


@rule(
    rule_id=RULE_ID,
    title="Missing X-Content-Type-Options header",
    severity="low",
    description="Server block does not define 'add_header X-Content-Type-Options nosniff;'.",
    recommendation="Add 'add_header X-Content-Type-Options nosniff;' to this server block.",
    category="local",
    server_type="nginx",
    tags=("headers",),
    order=234,
)
def find_missing_x_content_type_options(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if isinstance(node, BlockNode) and node.name == "server":
            finding = _find_missing_x_content_type_options_in_server(node)
            if finding is not None:
                findings.append(finding)

    return findings


def _find_missing_x_content_type_options_in_server(server_block: BlockNode) -> Finding | None:
    has_nosniff_header = server_header_contains_value(
        server_block,
        "X-Content-Type-Options",
        "nosniff",
    )

    if has_nosniff_header:
        return None

    return build_missing_header_finding(
        server_block,
        rule_id=RULE_ID,
        title="Missing X-Content-Type-Options header",
        description="Server block does not define 'add_header X-Content-Type-Options nosniff;'.",
        recommendation="Add 'add_header X-Content-Type-Options nosniff;' to this server block.",
    )


__all__ = ["find_missing_x_content_type_options"]
