from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    find_child_directives,
    iter_nodes,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.missing_auth_basic_user_file"
TARGET_BLOCK_NAMES = {"server", "location"}


@rule(
    rule_id=RULE_ID,
    title="Missing auth_basic_user_file directive",
    severity="low",
    description=(
        "Server or location block enables 'auth_basic' but does not define "
        "'auth_basic_user_file' in the same block."
    ),
    recommendation=(
        "Add an 'auth_basic_user_file' directive to the same block when "
        "enabling 'auth_basic'."
    ),
    category="local",
    server_type="nginx",
    order=209,
)
def find_missing_auth_basic_user_file(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if not isinstance(node, BlockNode) or node.name not in TARGET_BLOCK_NAMES:
            continue

        finding = _find_missing_auth_basic_user_file_in_block(node)
        if finding is not None:
            findings.append(finding)

    return findings


def _find_missing_auth_basic_user_file_in_block(block: BlockNode) -> Finding | None:
    if not _block_uses_auth_basic(block) or find_child_directives(block, "auth_basic_user_file"):
        return None

    return Finding(
        rule_id=RULE_ID,
        title="Missing auth_basic_user_file directive",
        severity="low",
        description=(
            f"{block.name.capitalize()} block uses 'auth_basic' but does not define "
            "'auth_basic_user_file'."
        ),
        recommendation=(
            "Add an 'auth_basic_user_file' directive to the same block when enabling "
            "'auth_basic'."
        ),
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=block.source.file_path,
            line=block.source.line,
        ),
    )


def _block_uses_auth_basic(block: BlockNode) -> bool:
    return any(
        directive.args and directive.args[0].lower() != "off"
        for directive in find_child_directives(block, "auth_basic")
    )


__all__ = ["find_missing_auth_basic_user_file"]
