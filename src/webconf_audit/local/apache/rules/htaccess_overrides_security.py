from __future__ import annotations

from webconf_audit.local.apache.htaccess import (
    HtaccessFile,
    extract_allowoverride,
    filter_htaccess_by_allowoverride,
)
from webconf_audit.local.apache.parser import ApacheBlockNode, ApacheDirectiveNode
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.htaccess_contains_security_directive"

# Directives with security significance that are noteworthy when present
# in .htaccess files.  These are all mapped in OVERRIDE_CATEGORY_MAP,
# so the AllowOverride filter will correctly drop them when their
# category is not permitted.
_SECURITY_DIRECTIVES = frozenset({
    "options",
    "require",
    "authtype",
    "authname",
    "header",
})


@rule(
    rule_id=RULE_ID,
    title=".htaccess contains security directive",
    severity="medium",
    description="A .htaccess file contains a security-sensitive directive that can alter security behavior.",
    recommendation="Review whether security directives in .htaccess are intentional. Consider moving them to the main config.",
    category="local",
    server_type="apache",
    input_kind="htaccess",
    tags=("htaccess",),
    order=311,
)
def find_htaccess_security_directives(
    htaccess_files: list[HtaccessFile],
) -> list[Finding]:
    """Flag security-sensitive directives present in .htaccess files.

    This checks for *presence* of security-relevant directives in .htaccess,
    not for proven override of a main-config directive (that requires
    effective-config comparison, planned for step 2.4).
    """
    findings: list[Finding] = []

    for htf in htaccess_files:
        if htf.source_directory_block is None:
            allowed = None
        else:
            allowed = extract_allowoverride(htf.source_directory_block)

        # AllowOverride None → .htaccess is fully ignored by Apache
        if allowed is not None and len(allowed) == 0:
            continue

        # Filter the AST by AllowOverride categories
        if allowed is not None:
            effective_ast = filter_htaccess_by_allowoverride(htf.ast, allowed)
        else:
            effective_ast = htf.ast

        for node in _iter_security_directives(effective_ast.nodes):
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    title=f".htaccess contains security directive '{node.name}'",
                    severity="medium",
                    description=(
                        f"The .htaccess file at {htf.htaccess_path} contains "
                        f"'{node.name}' which can alter security-relevant behavior."
                    ),
                    recommendation=(
                        f"Review whether '{node.name}' in .htaccess is intentional. "
                        f"Consider moving security-sensitive directives to the main "
                        f"config and restricting AllowOverride."
                    ),
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path=node.source.file_path or htf.htaccess_path,
                        line=node.source.line,
                    ),
                )
            )

    return findings


def _iter_security_directives(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
) -> list[ApacheDirectiveNode]:
    """Recursively find security-sensitive directives in .htaccess AST."""
    found: list[ApacheDirectiveNode] = []
    for node in nodes:
        if isinstance(node, ApacheDirectiveNode):
            if node.name.lower() in _SECURITY_DIRECTIVES:
                found.append(node)
        else:
            found.extend(_iter_security_directives(node.children))
    return found


__all__ = ["find_htaccess_security_directives"]
