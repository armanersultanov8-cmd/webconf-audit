from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst, ApacheDirectiveNode
from webconf_audit.models import SourceLocation


def find_top_level_error_document(
    config_ast: ApacheConfigAst,
    status_code: str,
) -> ApacheDirectiveNode | None:
    for node in config_ast.nodes:
        if not isinstance(node, ApacheDirectiveNode):
            continue

        if node.name.lower() != "errordocument":
            continue

        if node.args and node.args[0] == status_code:
            return node

    return None


def default_location(config_ast: ApacheConfigAst) -> SourceLocation | None:
    if not config_ast.nodes:
        return None

    source = config_ast.nodes[0].source
    return SourceLocation(
        mode="local",
        kind="file",
        file_path=source.file_path,
        line=source.line,
    )


__all__ = ["default_location", "find_top_level_error_document"]
