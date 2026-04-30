from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    DirectiveNode,
    find_child_directives,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.missing_access_restrictions_on_sensitive_locations"
SENSITIVE_LOCATION_PATHS = {"/admin", "/admin/", "/phpmyadmin", "/manage", "/internal"}
_TITLE = "Missing access restrictions on sensitive location"
_SEVERITY = "low"
_DESCRIPTION = (
    "Sensitive location does not define a basic access restriction with "
    "'allow', 'deny', or 'auth_basic'."
)
_RECOMMENDATION = (
    "Add an access restriction such as 'allow'/'deny' rules or "
    "'auth_basic' to this sensitive location."
)


@rule(
    rule_id=RULE_ID,
    title=_TITLE,
    severity=_SEVERITY,
    description=_DESCRIPTION,
    recommendation=_RECOMMENDATION,
    category="local",
    server_type="nginx",
    order=207,
)
def find_missing_access_restrictions_on_sensitive_locations(
    config_ast: ConfigAst,
) -> list[Finding]:
    findings: list[Finding] = []

    def visit(nodes: list[DirectiveNode | BlockNode], ancestors: tuple[BlockNode, ...]) -> None:
        for node in nodes:
            if not isinstance(node, BlockNode):
                continue
            block_chain = (*ancestors, node)
            if (
                node.name == "location"
                and _is_sensitive_location(node)
                and not _has_access_restriction(block_chain)
            ):
                findings.append(
                    Finding(
                        rule_id=RULE_ID,
                        title=_TITLE,
                        severity=_SEVERITY,
                        description=_DESCRIPTION,
                        recommendation=_RECOMMENDATION,
                        location=SourceLocation(
                            mode="local",
                            kind="file",
                            file_path=node.source.file_path,
                            line=node.source.line,
                        ),
                    )
                )
            visit(node.children, block_chain)

    visit(config_ast.nodes, ())

    return findings


def _is_sensitive_location(location_block: BlockNode) -> bool:
    return any(arg.lower() in SENSITIVE_LOCATION_PATHS for arg in location_block.args)


def _has_access_restriction(block_chain: tuple[BlockNode, ...]) -> bool:
    """Return whether any block in the chain defines a basic restriction.

    This intentionally uses a simplified inheritance model: it walks the
    full ``block_chain`` with ``find_child_directives()`` and treats any
    restrictive ``deny``, enabled ``auth_basic``, or restrictive ``allow``
    paired with a ``deny`` somewhere in the chain as sufficient.

    It does not implement nginx's closest-wins override semantics. For
    example, a child ``auth_basic off`` does not cancel a parent
    ``auth_basic "realm"`` here; callers should treat this as a
    conservative approximation that is documented and covered by tests.
    """
    deny_directives = [
        directive
        for block in block_chain
        for directive in find_child_directives(block, "deny")
    ]
    if any(_is_restrictive_deny(directive) for directive in deny_directives):
        return True

    if any(
        _is_auth_basic_enabled(directive)
        for block in block_chain
        for directive in find_child_directives(block, "auth_basic")
    ):
        return True

    return any(
        _is_restrictive_allow(directive)
        for block in block_chain
        for directive in find_child_directives(block, "allow")
    ) and bool(deny_directives)


def _is_restrictive_deny(directive: DirectiveNode) -> bool:
    return bool(directive.args)


def _is_restrictive_allow(directive: DirectiveNode) -> bool:
    if not directive.args:
        return False
    return _normalize_argument(directive.args[0]) != "all"


def _is_auth_basic_enabled(directive: DirectiveNode) -> bool:
    if not directive.args:
        return False
    return _normalize_argument(directive.args[0]) != "off"


def _normalize_argument(value: str) -> str:
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in {'"', "'"}:
        stripped = stripped[1:-1]
    return stripped.lower()


__all__ = ["find_missing_access_restrictions_on_sensitive_locations"]
