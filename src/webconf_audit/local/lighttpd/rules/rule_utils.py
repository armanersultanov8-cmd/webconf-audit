"""Shared helpers for Lighttpd rules."""

from __future__ import annotations

from webconf_audit.local.lighttpd.effective import (
    LighttpdConditionalScope,
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
)
from webconf_audit.local.lighttpd.parser import (
    LighttpdAssignmentNode,
    LighttpdBlockNode,
    LighttpdCondition,
    LighttpdConfigAst,
)
from webconf_audit.models import SourceLocation


def iter_all_nodes(config_ast: LighttpdConfigAst):
    """Yield every AST node, recursing into blocks."""
    yield from _iter_nodes(config_ast.nodes)


def _iter_nodes(nodes: list):
    for node in nodes:
        yield node
        if isinstance(node, LighttpdBlockNode):
            yield from _iter_nodes(node.children)


def normalize_value(value: str) -> str:
    """Strip whitespace and surrounding quotes, then lowercase."""
    normalized = value.strip()
    if len(normalized) >= 2 and normalized[0] == normalized[-1] and normalized[0] in {'"', "'"}:
        normalized = normalized[1:-1].strip()
    return normalized.lower()


def unquote(value: str) -> str:
    """Strip surrounding quotes without lowercasing."""
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in {'"', "'"}:
        return stripped[1:-1]
    return stripped


def find_assignment(config_ast: LighttpdConfigAst, name: str) -> LighttpdAssignmentNode | None:
    """Find the last assignment to the given name anywhere in the AST."""
    found: LighttpdAssignmentNode | None = None
    for node in iter_all_nodes(config_ast):
        if isinstance(node, LighttpdAssignmentNode) and node.name == name:
            found = node
    return found


def has_assignment(config_ast: LighttpdConfigAst, name: str) -> bool:
    """Check whether any assignment to the given name exists."""
    return find_assignment(config_ast, name) is not None


def default_location(config_ast: LighttpdConfigAst) -> SourceLocation | None:
    if config_ast.main_file_path:
        return SourceLocation(mode="local", kind="file", file_path=config_ast.main_file_path, line=1)
    if not config_ast.nodes:
        return None
    source = config_ast.nodes[0].source
    return SourceLocation(mode="local", kind="file", file_path=source.file_path, line=source.line)


def collect_modules(config_ast: LighttpdConfigAst) -> set[str]:
    """Collect all module names loaded via server.modules assignments."""
    modules: set[str] = set()
    for node in iter_all_nodes(config_ast):
        if not isinstance(node, LighttpdAssignmentNode):
            continue
        if node.name != "server.modules":
            continue
        modules.update(_parse_module_list(node.value))
    return modules


def _parse_module_list(value: str) -> list[str]:
    """Extract module names from a parenthesized list like ( "mod_a", "mod_b" )."""
    stripped = value.strip()
    if stripped.startswith("(") and stripped.endswith(")"):
        stripped = stripped[1:-1]
    result: list[str] = []
    for part in stripped.split(","):
        part = part.strip().strip('"').strip("'").strip()
        if part:
            result.append(part)
    return result


def scope_conditions(
    scope: LighttpdConditionalScope,
) -> tuple[LighttpdCondition | None, ...]:
    return scope.conditions if scope.conditions else (scope.condition,)


def effective_directive_for_scope(
    effective_config: LighttpdEffectiveConfig,
    scope: LighttpdConditionalScope,
    directive_name: str,
) -> LighttpdEffectiveDirective | None:
    directive = effective_config.get_global(directive_name)
    target_conditions = scope_conditions(scope)
    applicable_scopes: list[tuple[int, int, LighttpdEffectiveDirective]] = []

    for index, candidate in enumerate(effective_config.conditional_scopes):
        scoped_directive = candidate.directives.get(directive_name)
        if scoped_directive is None:
            continue
        candidate_conditions = scope_conditions(candidate)
        if len(candidate_conditions) > len(target_conditions):
            continue
        if target_conditions[: len(candidate_conditions)] != candidate_conditions:
            continue
        applicable_scopes.append((len(candidate_conditions), index, scoped_directive))

    applicable_scopes.sort(key=lambda item: (item[0], item[1]))
    if applicable_scopes:
        directive = applicable_scopes[-1][2]

    return directive


__all__ = [
    "collect_modules",
    "default_location",
    "effective_directive_for_scope",
    "find_assignment",
    "has_assignment",
    "iter_all_nodes",
    "normalize_value",
    "scope_conditions",
    "unquote",
]
