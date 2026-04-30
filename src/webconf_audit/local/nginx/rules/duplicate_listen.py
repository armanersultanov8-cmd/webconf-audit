from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    DirectiveNode,
    find_child_directives,
    iter_nodes,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.duplicate_listen"


@rule(
    rule_id=RULE_ID,
    title="Duplicate listen directive",
    severity="low",
    description="Duplicate listen directive",
    recommendation="Remove the duplicate listen directive from this server block.",
    category="local",
    server_type="nginx",
    order=203,
)
def find_duplicate_listen(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    for node in iter_nodes(config_ast.nodes):
        if isinstance(node, BlockNode) and node.name == "server":
            findings.extend(_find_duplicate_listen_in_server(node))

    return findings


def _find_duplicate_listen_in_server(server_block: BlockNode) -> list[Finding]:
    findings: list[Finding] = []
    seen: dict[str, DirectiveNode] = {}
    reported: set[str] = set()

    for child in find_child_directives(server_block, "listen"):
        listen_value = " ".join(child.args)

        if listen_value not in seen:
            seen[listen_value] = child
            continue

        if listen_value in reported:
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="Duplicate listen directive",
                severity="low",
                description=(
                    f"Server block defines the same listen directive more than once: {listen_value!r}."
                ),
                recommendation="Remove the duplicate listen directive from this server block.",
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=child.source.file_path,
                    line=child.source.line,
                ),
            )
        )
        reported.add(listen_value)

    return findings


__all__ = ["find_duplicate_listen"]
