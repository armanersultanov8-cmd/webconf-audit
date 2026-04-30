from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    find_child_directives,
    iter_nodes,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.missing_hidden_files_deny"


@rule(
    rule_id=RULE_ID,
    title="Missing hidden files deny location",
    severity="low",
    description="Server block does not define a hidden-files location with 'deny all;'.",
    recommendation="Add a location that targets hidden files or dotfiles and contains 'deny all;'.",
    category="local",
    server_type="nginx",
    order=216,
)
def find_missing_hidden_files_deny(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if isinstance(node, BlockNode) and node.name == "server":
            finding = _find_missing_hidden_files_deny_in_server(node)
            if finding is not None:
                findings.append(finding)

    return findings


def _find_missing_hidden_files_deny_in_server(server_block: BlockNode) -> Finding | None:
    if _server_has_hidden_files_deny(server_block):
        return None

    return Finding(
        rule_id=RULE_ID,
        title="Missing hidden files deny location",
        severity="low",
        description="Server block does not define a hidden-files location with 'deny all;'.",
        recommendation="Add a location that targets hidden files or dotfiles and contains 'deny all;'.",
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=server_block.source.file_path,
            line=server_block.source.line,
        ),
    )


def _server_has_hidden_files_deny(server_block: BlockNode) -> bool:
    return any(
        isinstance(node, BlockNode)
        and node.name == "location"
        and _looks_like_hidden_files_location(node)
        and any(directive.args == ["all"] for directive in find_child_directives(node, "deny"))
        for node in iter_nodes(server_block.children)
    )


def _looks_like_hidden_files_location(location_block: BlockNode) -> bool:
    if not location_block.args or location_block.args[0] not in {"~", "~*"}:
        return False

    pattern = " ".join(location_block.args[1:])

    return any(marker in pattern for marker in ("/\\.", "^/\\.", "/.", "^/."))


__all__ = ["find_missing_hidden_files_deny"]
