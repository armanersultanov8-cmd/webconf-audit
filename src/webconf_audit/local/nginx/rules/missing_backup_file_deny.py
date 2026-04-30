from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    find_child_directives,
    iter_nodes,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.missing_backup_file_deny"
BACKUP_EXTENSION_MARKERS = ("bak", "old", "backup", "orig", "save")


@rule(
    rule_id=RULE_ID,
    title="Missing backup files deny location",
    severity="low",
    description=(
        "Server block does not define a backup-files location with 'deny all;' "
        "or 'return 403;'."
    ),
    recommendation=(
        "Add a regex location for common backup file patterns such as '.bak', "
        "'.old', '.backup', '.orig', '.save', or trailing '~' and block it "
        "with 'deny all;' or 'return 403;'."
    ),
    category="local",
    server_type="nginx",
    order=210,
)
def find_missing_backup_file_deny(config_ast: ConfigAst) -> list[Finding]:
    server_blocks = [
        node for node in iter_nodes(config_ast.nodes) if isinstance(node, BlockNode) and node.name == "server"
    ]

    if not server_blocks:
        return []

    findings: list[Finding] = []
    for server_block in server_blocks:
        if _server_has_backup_file_deny(server_block):
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="Missing backup files deny location",
                severity="low",
                description=(
                    "Server block does not define a backup-files location with "
                    "'deny all;' or 'return 403;'."
                ),
                recommendation=(
                    "Add a regex location for common backup file patterns such as '.bak', "
                    "'.old', '.backup', '.orig', '.save', or trailing '~' and block it "
                    "with 'deny all;' or 'return 403;'."
                ),
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=server_block.source.file_path,
                    line=server_block.source.line,
                ),
            )
        )
    return findings


def _server_has_backup_file_deny(server_block: BlockNode) -> bool:
    return any(
        isinstance(child, BlockNode)
        and child.name == "location"
        and _looks_like_backup_files_location(child)
        and _location_blocks_backup_files(child)
        for child in server_block.children
    )


def _looks_like_backup_files_location(location_block: BlockNode) -> bool:
    if not location_block.args or location_block.args[0] not in {"~", "~*"}:
        return False

    pattern = " ".join(location_block.args[1:]).lower()

    return _looks_like_backup_extension_pattern(pattern) or _looks_like_backup_suffix_pattern(pattern)


def _looks_like_backup_extension_pattern(pattern: str) -> bool:
    if any(f".{marker}" in pattern for marker in BACKUP_EXTENSION_MARKERS):
        return True

    if any(group_start in pattern for group_start in ("\\.(", "\\.(?:")):
        return any(marker in pattern for marker in BACKUP_EXTENSION_MARKERS)

    return False


def _looks_like_backup_suffix_pattern(pattern: str) -> bool:
    return "~$" in pattern


def _location_blocks_backup_files(location_block: BlockNode) -> bool:
    return any(
        directive.args == ["all"] for directive in find_child_directives(location_block, "deny")
    ) or any(
        directive.args and directive.args[0] == "403"
        for directive in find_child_directives(location_block, "return")
    )


__all__ = ["find_missing_backup_file_deny"]
