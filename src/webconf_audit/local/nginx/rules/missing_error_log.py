from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    find_child_directives,
    iter_nodes,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.missing_error_log"


@rule(
    rule_id=RULE_ID,
    title="Missing error_log directive",
    severity="low",
    description="Server block does not define an 'error_log' directive.",
    recommendation="Add an 'error_log' directive to this server block.",
    category="local",
    server_type="nginx",
    order=215,
)
def find_missing_error_log(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if isinstance(node, BlockNode) and node.name == "server":
            finding = _find_missing_error_log_in_server(node)
            if finding is not None:
                findings.append(finding)

    return findings


def _find_missing_error_log_in_server(server_block: BlockNode) -> Finding | None:
    error_log_directives = find_child_directives(server_block, "error_log")

    if error_log_directives:
        return None

    return Finding(
        rule_id=RULE_ID,
        title="Missing error_log directive",
        severity="low",
        description="Server block does not define an 'error_log' directive.",
        recommendation="Add an 'error_log' directive to this server block.",
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=server_block.source.file_path,
            line=server_block.source.line,
        ),
    )


__all__ = ["find_missing_error_log"]
