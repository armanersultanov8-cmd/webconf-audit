from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    find_child_directives,
    iter_nodes,
)
from webconf_audit.local.nginx.rules.tls_listener_utils import server_uses_tls
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.ssl_stapling_missing_resolver"


@rule(
    rule_id=RULE_ID,
    title="SSL stapling enabled without resolver",
    severity="low",
    description="Server block enables 'ssl_stapling' but does not define 'resolver'.",
    recommendation="Add a 'resolver' directive to this server block.",
    category="local",
    server_type="nginx",
    order=238,
)
def find_ssl_stapling_missing_resolver(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if isinstance(node, BlockNode) and node.name == "server":
            finding = _find_ssl_stapling_missing_resolver_in_server(node)
            if finding is not None:
                findings.append(finding)

    return findings


def _find_ssl_stapling_missing_resolver_in_server(server_block: BlockNode) -> Finding | None:
    ssl_stapling_directives = find_child_directives(server_block, "ssl_stapling")
    resolver_directives = find_child_directives(server_block, "resolver")

    uses_tls = server_uses_tls(server_block)
    stapling_on = any(directive.args == ["on"] for directive in ssl_stapling_directives)

    if not uses_tls or not stapling_on or resolver_directives:
        return None

    return Finding(
        rule_id=RULE_ID,
        title="SSL stapling enabled without resolver",
        severity="low",
        description="Server block enables 'ssl_stapling' but does not define 'resolver'.",
        recommendation="Add a 'resolver' directive to this server block.",
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=server_block.source.file_path,
            line=server_block.source.line,
        ),
    )


__all__ = ["find_ssl_stapling_missing_resolver"]
