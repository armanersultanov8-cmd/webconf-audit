from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheBlockNode, ApacheConfigAst, ApacheDirectiveNode
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.backup_temp_files_not_restricted"
TARGET_EXTENSIONS = ("bak", "old", "swp")


@rule(
    rule_id=RULE_ID,
    title="Backup/temp files not restricted",
    severity="low",
    description=(
        "Apache config does not contain a narrow baseline '<FilesMatch ...>' "
        "restriction for common backup or temporary file extensions."
    ),
    recommendation=(
        "Add a '<FilesMatch ...>' block for common backup or temporary file "
        "extensions with a direct 'Require all denied' directive."
    ),
    category="local",
    server_type="apache",
    order=301,
)
def find_backup_files_restricted(config_ast: ApacheConfigAst) -> list[Finding]:
    candidate_blocks = [
        block
        for block in _iter_files_match_blocks(config_ast.nodes)
        if _files_match_targets_backup_temp_files(block)
    ]

    for candidate_block in candidate_blocks:
        if _files_match_denies_all(candidate_block):
            return []

    return [
        Finding(
            rule_id=RULE_ID,
            title="Backup/temp files not restricted",
            severity="low",
            description=(
                "Apache config does not contain a narrow baseline '<FilesMatch ...>' "
                "restriction for common backup or temporary file extensions that includes "
                "a direct 'Require all denied' directive."
            ),
            recommendation=(
                "Add a '<FilesMatch ...>' block for common backup or temporary file "
                "extensions such as '.bak', '.old', or '.swp' with a direct "
                "'Require all denied' directive."
            ),
            location=_finding_location(config_ast, candidate_blocks),
        )
    ]


def _iter_files_match_blocks(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
) -> list[ApacheBlockNode]:
    files_match_blocks: list[ApacheBlockNode] = []

    for node in nodes:
        if isinstance(node, ApacheBlockNode):
            if node.name.lower() == "filesmatch":
                files_match_blocks.append(node)
            files_match_blocks.extend(_iter_files_match_blocks(node.children))

    return files_match_blocks


def _files_match_targets_backup_temp_files(files_match_block: ApacheBlockNode) -> bool:
    raw_args = " ".join(files_match_block.args).lower()
    return any(_pattern_mentions_extension(raw_args, extension) for extension in TARGET_EXTENSIONS)


def _pattern_mentions_extension(raw_args: str, extension: str) -> bool:
    # Keep matching textual and explicit: accept common extension-oriented spellings
    # without treating any arbitrary "bak"/"old"/"swp" substring as a target.
    explicit_markers = (
        f"\\.{extension}",
        f".{extension}",
        f"({extension}",
        f"|{extension}",
        f"{extension}|",
        f"{extension})",
    )
    return any(marker in raw_args for marker in explicit_markers)


def _files_match_denies_all(files_match_block: ApacheBlockNode) -> bool:
    for child in files_match_block.children:
        if not isinstance(child, ApacheDirectiveNode):
            continue

        if child.name.lower() != "require":
            continue

        if len(child.args) == 2 and child.args[0].lower() == "all" and child.args[1].lower() == "denied":
            return True

    return False


def _finding_location(
    config_ast: ApacheConfigAst,
    candidate_blocks: list[ApacheBlockNode],
) -> SourceLocation | None:
    if candidate_blocks:
        source = candidate_blocks[0].source
        return SourceLocation(
            mode="local",
            kind="file",
            file_path=source.file_path,
            line=source.line,
        )

    if not config_ast.nodes:
        return None

    source = config_ast.nodes[0].source
    return SourceLocation(
        mode="local",
        kind="file",
        file_path=source.file_path,
        line=source.line,
    )


__all__ = ["find_backup_files_restricted"]
