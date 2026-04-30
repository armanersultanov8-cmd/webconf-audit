from __future__ import annotations

from webconf_audit.local.apache.htaccess import (
    HtaccessFile,
    extract_allowoverride,
    filter_htaccess_by_allowoverride,
)
from webconf_audit.local.apache.parser import ApacheBlockNode, ApacheConfigAst, ApacheDirectiveNode


def get_effective_htaccess_ast(htaccess_file: HtaccessFile) -> ApacheConfigAst | None:
    """Return the .htaccess AST after AllowOverride filtering."""
    if htaccess_file.source_directory_block is None:
        return htaccess_file.ast

    allowed = extract_allowoverride(htaccess_file.source_directory_block)
    if allowed is not None and len(allowed) == 0:
        return None
    if allowed is None:
        return htaccess_file.ast
    return filter_htaccess_by_allowoverride(htaccess_file.ast, allowed)


def iter_directives(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
) -> list[ApacheDirectiveNode]:
    """Recursively yield directives from an Apache AST fragment."""
    directives: list[ApacheDirectiveNode] = []
    for node in nodes:
        if isinstance(node, ApacheDirectiveNode):
            directives.append(node)
        else:
            directives.extend(iter_directives(node.children))
    return directives


__all__ = ["get_effective_htaccess_ast", "iter_directives"]
