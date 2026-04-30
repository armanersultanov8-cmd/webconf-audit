from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import BlockNode, ConfigAst, find_child_directives, iter_nodes
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.executable_scripts_allowed_in_uploads"
UPLOAD_MARKERS = ("/upload", "/uploads", "/media", "/files")
SCRIPT_EXTENSION_MARKERS = (".php", ".pl", ".py", ".sh", ".exe")


@rule(
    rule_id=RULE_ID,
    title="Executable scripts allowed in upload-like location",
    severity="medium",
    description=(
        "Upload-like location does not define a nested script restriction for "
        "common executable file extensions."
    ),
    recommendation=(
        "Add a nested regex location for script extensions in this upload-like "
        "location and block it with 'return 403;' or 'deny all;'."
    ),
    category="local",
    server_type="nginx",
    order=204,
)
def find_executable_scripts_allowed_in_uploads(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if not isinstance(node, BlockNode) or node.name != "server":
            continue
        findings.extend(_server_upload_script_findings(node))

    return findings


def _server_upload_script_findings(server: BlockNode) -> list[Finding]:
    findings: list[Finding] = []
    sibling_locations = _server_locations(server)
    for location in sibling_locations:
        if not _missing_script_restriction(location, sibling_locations):
            continue
        findings.append(_upload_script_finding(location))
    return findings


def _server_locations(server: BlockNode) -> list[BlockNode]:
    return [
        child
        for child in server.children
        if isinstance(child, BlockNode) and child.name == "location"
    ]


def _missing_script_restriction(
    location: BlockNode,
    sibling_locations: list[BlockNode],
) -> bool:
    if not _looks_like_upload_location(location):
        return False
    if _location_has_script_restriction(location):
        return False
    return not _siblings_block_upload_scripts(location, sibling_locations)


def _upload_script_finding(location: BlockNode) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title="Executable scripts allowed in upload-like location",
        severity="medium",
        description=(
            "Upload-like location does not define a nested script restriction for common "
            "executable file extensions."
        ),
        recommendation=(
            "Add a nested regex location for script extensions in this upload-like location "
            "and block it with 'return 403;' or 'deny all;'."
        ),
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=location.source.file_path,
            line=location.source.line,
        ),
    )


def _looks_like_upload_location(location_block: BlockNode) -> bool:
    if not location_block.args:
        return False
    if location_block.args[0] in {"~", "~*"}:
        return False

    location_value = " ".join(location_block.args).lower()
    return any(marker in location_value for marker in UPLOAD_MARKERS)


def _location_has_script_restriction(location_block: BlockNode) -> bool:
    return any(
        isinstance(child, BlockNode)
        and child.name == "location"
        and _looks_like_script_regex_location(child)
        and _location_returns_403_or_denies_all(child)
        for child in location_block.children
    )


def _siblings_block_upload_scripts(
    upload_location: BlockNode,
    sibling_locations: list[BlockNode],
) -> bool:
    upload_prefix = _upload_prefix(upload_location)
    if upload_prefix is None:
        return False
    return any(
        sibling is not upload_location
        and _looks_like_script_regex_location(sibling)
        and upload_prefix in " ".join(sibling.args[1:]).lower()
        and _location_returns_403_or_denies_all(sibling)
        for sibling in sibling_locations
    )


def _upload_prefix(location_block: BlockNode) -> str | None:
    for arg in location_block.args:
        lowered = arg.lower()
        for marker in UPLOAD_MARKERS:
            if marker in lowered:
                return marker
    return None


def _looks_like_script_regex_location(location_block: BlockNode) -> bool:
    if not location_block.args or location_block.args[0] not in {"~", "~*"}:
        return False

    pattern = " ".join(location_block.args[1:]).lower()
    return any(marker in pattern for marker in SCRIPT_EXTENSION_MARKERS)


def _location_returns_403_or_denies_all(location_block: BlockNode) -> bool:
    return any(directive.args and directive.args[0] == "403" for directive in find_child_directives(location_block, "return")) or any(
        directive.args == ["all"] for directive in find_child_directives(location_block, "deny")
    )


__all__ = ["find_executable_scripts_allowed_in_uploads"]
