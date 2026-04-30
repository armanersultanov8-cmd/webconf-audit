from __future__ import annotations

import re

from webconf_audit.local.lighttpd.parser import (
    LighttpdAssignmentNode,
    LighttpdAstNode,
    LighttpdBlockNode,
    LighttpdConfigAst,
)
from webconf_audit.models import AnalysisIssue, SourceLocation

_VAR_PREFIX = "var."

# Matches a single token in a concatenation expression:
# either a quoted string ("..." or '...') or a bare identifier (var.name).
_CONCAT_TOKEN = re.compile(
    r"""
    \s*
    (?:
        "((?:[^"\\]|\\.)*)"    # double-quoted string
      | '((?:[^'\\]|\\.)*)'    # single-quoted string
      | ([a-zA-Z_][a-zA-Z0-9_.\-]*)  # bare identifier (var.name)
    )
    \s*
    """,
    re.VERBOSE,
)


def expand_variables(config_ast: LighttpdConfigAst) -> list[AnalysisIssue]:
    variables: dict[str, str] = {}
    issues: list[AnalysisIssue] = []
    _expand_nodes(config_ast.nodes, variables, issues)
    return issues


def _expand_nodes(
    nodes: list[LighttpdAstNode],
    variables: dict[str, str],
    issues: list[AnalysisIssue],
) -> None:
    for node in nodes:
        if isinstance(node, LighttpdBlockNode):
            _expand_nodes(node.children, variables, issues)
            continue

        if not isinstance(node, LighttpdAssignmentNode):
            continue

        if node.name.startswith(_VAR_PREFIX):
            _collect_variable(node, variables, issues)
        else:
            _expand_value(node, variables, issues)


def _collect_variable(
    node: LighttpdAssignmentNode,
    variables: dict[str, str],
    issues: list[AnalysisIssue],
) -> None:
    resolved = _resolve_expression(node.value, variables, node, issues)
    if resolved is None:
        return

    if node.operator == "+=" and node.name in variables:
        variables[node.name] = variables[node.name] + resolved
    else:
        # Both "=" and ":=" set the value directly.
        variables[node.name] = resolved

    node.value = _quote(variables[node.name])


def _expand_value(
    node: LighttpdAssignmentNode,
    variables: dict[str, str],
    issues: list[AnalysisIssue],
) -> None:
    if not _references_variable(node.value):
        return

    resolved = _resolve_expression(node.value, variables, node, issues)
    if resolved is not None:
        node.value = _quote(resolved)


def _references_variable(value: str) -> bool:
    return _VAR_PREFIX in value


def _unescape_quoted_string(value: str, *, quote: str) -> str:
    result: list[str] = []
    escaped = False

    for char in value:
        if escaped:
            if char == quote or char == "\\":
                result.append(char)
            else:
                result.append(f"\\{char}")
            escaped = False
            continue

        if char == "\\":
            escaped = True
            continue

        result.append(char)

    if escaped:
        result.append("\\")

    return "".join(result)


def _resolve_expression(
    expression: str,
    variables: dict[str, str],
    node: LighttpdAssignmentNode,
    issues: list[AnalysisIssue],
) -> str | None:
    """Resolve a value expression like: var.x + "/path" or "literal".

    Returns the unquoted resolved string, or None if resolution failed.
    """
    parts: list[str] = []
    pos = 0
    text = expression.strip()

    while pos < len(text):
        match = _CONCAT_TOKEN.match(text, pos)
        if match is None:
            # Unparseable remainder — leave value as-is.
            return None

        double_quoted, single_quoted, bare_ident = match.groups()

        if double_quoted is not None:
            parts.append(_unescape_quoted_string(double_quoted, quote='"'))
        elif single_quoted is not None:
            parts.append(_unescape_quoted_string(single_quoted, quote="'"))
        elif bare_ident is not None:
            if bare_ident in variables:
                parts.append(variables[bare_ident])
            elif bare_ident.startswith(_VAR_PREFIX):
                issues.append(
                    AnalysisIssue(
                        code="lighttpd_undefined_variable",
                        level="warning",
                        message=f"Undefined variable reference: {bare_ident}",
                        location=SourceLocation(
                            mode="local",
                            kind="file",
                            file_path=node.source.file_path,
                            line=node.source.line,
                        ),
                    )
                )
                return None
            else:
                # Bare identifier that is not a var.* reference — not expandable.
                return None

        pos = match.end()

        # Skip optional '+' concatenation operator.
        rest = text[pos:].lstrip()
        if rest.startswith("+"):
            pos = pos + (len(text) - pos - len(rest)) + 1
        elif rest:
            # Unexpected content after token without '+' — leave value as-is.
            return None

    return "".join(parts)


def _quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


__all__ = ["expand_variables"]
