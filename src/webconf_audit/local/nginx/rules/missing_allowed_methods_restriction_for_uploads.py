from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import BlockNode, ConfigAst, iter_nodes
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.missing_allowed_methods_restriction_for_uploads"
UPLOAD_LOCATION_MARKERS = ("/upload", "/uploads", "/media", "/files")


@rule(
    rule_id=RULE_ID,
    title="Missing allowed methods restriction for upload-like location",
    severity="low",
    description=(
        "Upload-like location does not define an explicit allowed-methods "
        "restriction with 'limit_except'."
    ),
    recommendation=(
        "Add a 'limit_except' block to this upload-like location to restrict "
        "unnecessary HTTP methods."
    ),
    category="local",
    server_type="nginx",
    order=208,
)
def find_missing_allowed_methods_restriction_for_uploads(
    config_ast: ConfigAst,
) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if isinstance(node, BlockNode) and node.name == "location" and _is_upload_like_location(node):
            if _location_has_limit_except(node):
                continue

            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    title="Missing allowed methods restriction for upload-like location",
                    severity="low",
                    description=(
                        "Upload-like location does not define an explicit allowed-methods "
                        "restriction with 'limit_except'."
                    ),
                    recommendation=(
                        "Add a 'limit_except' block to this upload-like location to restrict "
                        "unnecessary HTTP methods."
                    ),
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path=node.source.file_path,
                        line=node.source.line,
                    ),
                )
            )

    return findings


def _is_upload_like_location(location_block: BlockNode) -> bool:
    if not location_block.args:
        return False

    location_value = " ".join(location_block.args).lower()
    return any(marker in location_value for marker in UPLOAD_LOCATION_MARKERS)


def _location_has_limit_except(location_block: BlockNode) -> bool:
    return any(
        isinstance(child, BlockNode) and child.name == "limit_except"
        for child in location_block.children
    )


__all__ = ["find_missing_allowed_methods_restriction_for_uploads"]
