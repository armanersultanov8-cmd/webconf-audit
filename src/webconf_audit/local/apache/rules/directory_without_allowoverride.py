from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheBlockNode, ApacheConfigAst, ApacheDirectiveNode
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.directory_without_allowoverride"


@rule(
    rule_id=RULE_ID,
    title="Directory block lacks explicit AllowOverride",
    severity="low",
    description=(
        "This Directory block does not set AllowOverride explicitly. That "
        "makes .htaccess behavior depend on inherited or default Apache "
        "settings, which is harder to audit."
    ),
    recommendation=(
        "Set AllowOverride explicitly for each Directory block, preferably "
        "'AllowOverride None' or a narrow category list."
    ),
    category="local",
    server_type="apache",
    order=303,
)
def find_directory_without_allowoverride(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for block in _iter_directory_blocks(config_ast.nodes):
        if not block.args:
            continue
        if _has_explicit_allowoverride(block):
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="Directory block lacks explicit AllowOverride",
                severity="low",
                description=(
                    "This Directory block does not set AllowOverride explicitly. "
                    "That makes .htaccess behavior depend on inherited or default "
                    "Apache settings, which is harder to audit."
                ),
                recommendation=(
                    "Set AllowOverride explicitly for each Directory block, "
                    "preferably 'AllowOverride None' or a narrow category list."
                ),
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=block.source.file_path,
                    line=block.source.line,
                ),
            )
        )

    return findings


def _has_explicit_allowoverride(block: ApacheBlockNode) -> bool:
    return any(
        isinstance(child, ApacheDirectiveNode) and child.name.lower() == "allowoverride"
        for child in block.children
    )


def _iter_directory_blocks(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
) -> list[ApacheBlockNode]:
    blocks: list[ApacheBlockNode] = []
    for node in nodes:
        if isinstance(node, ApacheBlockNode):
            if node.name.lower() == "directory":
                blocks.append(node)
            blocks.extend(_iter_directory_blocks(node.children))
    return blocks


__all__ = ["find_directory_without_allowoverride"]
