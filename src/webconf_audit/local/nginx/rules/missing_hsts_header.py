from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    iter_nodes,
)
from webconf_audit.local.nginx.rules.header_utils import (
    build_missing_header_finding,
    server_has_header,
)
from webconf_audit.local.nginx.rules.tls_listener_utils import server_uses_tls
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.missing_hsts_header"


@rule(
    rule_id=RULE_ID,
    title="Missing HSTS header",
    severity="low",
    description="TLS server block does not define a Strict-Transport-Security header.",
    recommendation="Add a Strict-Transport-Security header to this server block.",
    category="local",
    server_type="nginx",
    tags=("headers", "tls"),
    order=217,
)
def find_missing_hsts_header(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if isinstance(node, BlockNode) and node.name == "server":
            finding = _find_missing_hsts_header_in_server(node)
            if finding is not None:
                findings.append(finding)

    return findings


def _find_missing_hsts_header_in_server(server_block: BlockNode) -> Finding | None:
    uses_tls = server_uses_tls(server_block)
    has_hsts_header = server_has_header(server_block, "Strict-Transport-Security")

    if not uses_tls or has_hsts_header:
        return None

    return build_missing_header_finding(
        server_block,
        rule_id=RULE_ID,
        title="Missing HSTS header",
        description="TLS server block does not define a Strict-Transport-Security header.",
        recommendation="Add a Strict-Transport-Security header to this server block.",
    )


__all__ = ["find_missing_hsts_header"]
