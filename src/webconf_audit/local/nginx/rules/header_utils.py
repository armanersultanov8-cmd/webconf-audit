from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    DirectiveNode,
    find_child_directives,
)
from webconf_audit.models import Finding, SourceLocation


def find_server_add_headers(server_block: BlockNode) -> list[DirectiveNode]:
    return find_child_directives(server_block, "add_header")


def server_has_header(server_block: BlockNode, header_name: str) -> bool:
    wanted = header_name.lower()
    return any(
        directive.args and directive.args[0].lower() == wanted
        for directive in find_server_add_headers(server_block)
    )


def server_header_contains_value(
    server_block: BlockNode,
    header_name: str,
    value: str,
) -> bool:
    normalized_value = value.strip('"')
    wanted = header_name.lower()

    return any(
        len(directive.args) >= 2
        and directive.args[0].lower() == wanted
        and any(arg.strip('"') == normalized_value for arg in directive.args[1:])
        for directive in find_server_add_headers(server_block)
    )


def build_missing_header_finding(
    server_block: BlockNode,
    *,
    rule_id: str,
    title: str,
    description: str,
    recommendation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity="low",
        description=description,
        recommendation=recommendation,
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=server_block.source.file_path,
            line=server_block.source.line,
        ),
    )


__all__ = [
    "build_missing_header_finding",
    "find_server_add_headers",
    "server_has_header",
    "server_header_contains_value",
]
