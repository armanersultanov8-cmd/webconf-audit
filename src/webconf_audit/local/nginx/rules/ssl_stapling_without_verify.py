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

RULE_ID = "nginx.ssl_stapling_without_verify"


@rule(
    rule_id=RULE_ID,
    title="SSL stapling enabled without verification",
    severity="low",
    description="Server block enables 'ssl_stapling' without 'ssl_stapling_verify on'.",
    recommendation="Set 'ssl_stapling_verify on;' in this server block.",
    category="local",
    server_type="nginx",
    order=239,
)
def find_ssl_stapling_without_verify(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if isinstance(node, BlockNode) and node.name == "server":
            finding = _find_ssl_stapling_without_verify_in_server(node)
            if finding is not None:
                findings.append(finding)

    return findings


def _find_ssl_stapling_without_verify_in_server(server_block: BlockNode) -> Finding | None:
    ssl_stapling_directives = find_child_directives(server_block, "ssl_stapling")
    ssl_stapling_verify_directives = find_child_directives(server_block, "ssl_stapling_verify")

    uses_tls = server_uses_tls(server_block)
    stapling_on = _last_directive_is_on(ssl_stapling_directives)
    stapling_verify_on = _last_directive_is_on(ssl_stapling_verify_directives)

    if not uses_tls or not stapling_on or stapling_verify_on:
        return None

    return Finding(
        rule_id=RULE_ID,
        title="SSL stapling enabled without verification",
        severity="low",
        description="Server block enables 'ssl_stapling' without 'ssl_stapling_verify on'.",
        recommendation="Set 'ssl_stapling_verify on;' in this server block.",
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=server_block.source.file_path,
            line=server_block.source.line,
        ),
    )


def _last_directive_is_on(directives: list) -> bool:
    if not directives:
        return False
    last = directives[-1]
    return len(last.args) == 1 and last.args[0].lower() == "on"


__all__ = ["find_ssl_stapling_without_verify"]
