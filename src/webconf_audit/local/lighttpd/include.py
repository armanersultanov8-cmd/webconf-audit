from __future__ import annotations

import glob
import re
from pathlib import Path

from webconf_audit.local.lighttpd.parser import (
    LighttpdBlockNode,
    LighttpdConfigAst,
    LighttpdDirectiveNode,
    LighttpdParseError,
    LighttpdParser,
)
from webconf_audit.local.lighttpd.shell import execute_include_shell
from webconf_audit.local.load_context import LoadContext
from webconf_audit.models import AnalysisIssue, SourceLocation

INCLUDE_DIRECTIVES = frozenset({"include", "include_shell"})
_SHELL_SKIPPED_TARGET = "shell:skipped"


def resolve_includes(
    config_ast: LighttpdConfigAst,
    config_path: str | Path,
    load_context: LoadContext | None = None,
    execute_shell: bool = False,
) -> list[AnalysisIssue]:
    base_path = Path(config_path)
    normalized_base_path = base_path.resolve(strict=False)
    issues: list[AnalysisIssue] = []

    config_ast.nodes = _resolve_include_nodes(
        config_ast.nodes,
        current_file=base_path,
        include_chain=(normalized_base_path,),
        issues=issues,
        load_context=load_context,
        execute_shell=execute_shell,
    )

    return issues


def _resolve_include_nodes(
    nodes: list[LighttpdDirectiveNode | LighttpdBlockNode | object],
    *,
    current_file: Path,
    include_chain: tuple[Path | str, ...],
    issues: list[AnalysisIssue],
    load_context: LoadContext | None = None,
    execute_shell: bool = False,
) -> list[object]:
    resolved_nodes: list[object] = []

    for node in nodes:
        if isinstance(node, LighttpdBlockNode):
            resolved_nodes.append(
                _resolved_block_node(
                    node,
                    current_file=current_file,
                    include_chain=include_chain,
                    issues=issues,
                    load_context=load_context,
                    execute_shell=execute_shell,
                )
            )
            continue

        if not _is_include_directive(node):
            resolved_nodes.append(node)
            continue

        if node.name.lower() == "include_shell":
            resolved_nodes.extend(
                _resolve_include_shell_nodes(
                    node,
                    current_file=current_file,
                    include_chain=include_chain,
                    issues=issues,
                    load_context=load_context,
                    execute_shell=execute_shell,
                )
            )
            continue

        resolved_nodes.extend(
            _resolve_include_file_nodes(
                node,
                current_file=current_file,
                include_chain=include_chain,
                issues=issues,
                load_context=load_context,
                execute_shell=execute_shell,
            )
        )

    return resolved_nodes


def _resolved_block_node(
    node: LighttpdBlockNode,
    *,
    current_file: Path,
    include_chain: tuple[Path | str, ...],
    issues: list[AnalysisIssue],
    load_context: LoadContext | None,
    execute_shell: bool,
) -> LighttpdBlockNode:
    node.children = _resolve_include_nodes(
        node.children,
        current_file=current_file,
        include_chain=include_chain,
        issues=issues,
        load_context=load_context,
        execute_shell=execute_shell,
    )
    return node


def _is_include_directive(node: object) -> bool:
    return (
        isinstance(node, LighttpdDirectiveNode)
        and node.name.lower() in INCLUDE_DIRECTIVES
        and len(node.args) == 1
    )


def _resolve_include_shell_nodes(
    directive: LighttpdDirectiveNode,
    *,
    current_file: Path,
    include_chain: tuple[Path | str, ...],
    issues: list[AnalysisIssue],
    load_context: LoadContext | None,
    execute_shell: bool,
) -> list[object]:
    shell_target = f"shell:{directive.args[0]}"
    source_file = _directive_source_file(directive, current_file)

    if shell_target in include_chain:
        issues.append(
            _build_include_issue(
                code="lighttpd_include_cycle",
                message=f"Include cycle detected: {shell_target}",
                directive=directive,
            )
        )
        return []

    if not execute_shell:
        if load_context is not None:
            load_context.add_edge(
                source_file,
                directive.source.line,
                _SHELL_SKIPPED_TARGET,
            )
        issues.append(
            _build_include_issue(
                code="lighttpd_include_shell_skipped",
                level="warning",
                message="include_shell directive skipped (use --execute-shell to enable)",
                directive=directive,
            )
        )
        return []

    if load_context is not None:
        load_context.add_edge(source_file, directive.source.line, shell_target)

    shell_output = execute_include_shell(directive.args[0], cwd=current_file.parent)
    if shell_output is None:
        issues.append(
            _build_include_issue(
                code="lighttpd_include_shell_execution_failed",
                level="warning",
                message=f"include_shell command failed: {directive.args[0]}",
                directive=directive,
            )
        )
        return []

    include_ast = _parse_include_text(
        shell_output,
        source_path=shell_target,
        directive=directive,
        issues=issues,
    )
    if include_ast is None:
        return []

    include_ast.nodes = _resolve_include_nodes(
        include_ast.nodes,
        current_file=current_file,
        include_chain=(*include_chain, shell_target),
        issues=issues,
        load_context=load_context,
        execute_shell=execute_shell,
    )
    return list(include_ast.nodes)


def _resolve_include_file_nodes(
    directive: LighttpdDirectiveNode,
    *,
    current_file: Path,
    include_chain: tuple[Path | str, ...],
    issues: list[AnalysisIssue],
    load_context: LoadContext | None,
    execute_shell: bool,
) -> list[object]:
    include_paths = _expand_include_paths(directive.args[0], current_file.parent)
    if not include_paths:
        issues.append(
            _build_include_issue(
                code="lighttpd_include_not_found",
                message=f"Included config path not found: {directive.args[0]}",
                directive=directive,
            )
        )
        return []

    resolved_nodes: list[object] = []
    for include_path in include_paths:
        resolved_nodes.extend(
            _resolved_include_path_nodes(
                include_path,
                directive=directive,
                current_file=current_file,
                include_chain=include_chain,
                issues=issues,
                load_context=load_context,
                execute_shell=execute_shell,
            )
        )
    return resolved_nodes


def _resolved_include_path_nodes(
    include_path: Path,
    *,
    directive: LighttpdDirectiveNode,
    current_file: Path,
    include_chain: tuple[Path | str, ...],
    issues: list[AnalysisIssue],
    load_context: LoadContext | None,
    execute_shell: bool,
) -> list[object]:
    normalized_include_path = include_path.resolve(strict=False)
    normalized_current_path = current_file.resolve(strict=False)
    if normalized_include_path == normalized_current_path:
        issues.append(
            _build_include_issue(
                code="lighttpd_include_self_include",
                message=f"Self-include detected: {normalized_include_path}",
                directive=directive,
            )
        )
        return []

    if normalized_include_path in include_chain:
        issues.append(
            _build_include_issue(
                code="lighttpd_include_cycle",
                message=f"Include cycle detected: {normalized_include_path}",
                directive=directive,
            )
        )
        return []

    if load_context is not None:
        load_context.add_edge(
            _directive_source_file(directive, current_file),
            directive.source.line,
            str(include_path),
        )

    include_ast = _parse_include_file(include_path, directive=directive, issues=issues)
    if include_ast is None:
        return []

    include_ast.nodes = _resolve_include_nodes(
        include_ast.nodes,
        current_file=include_path,
        include_chain=(*include_chain, normalized_include_path),
        issues=issues,
        load_context=load_context,
        execute_shell=execute_shell,
    )
    return list(include_ast.nodes)


def _expand_include_paths(include_arg: str, base_dir: Path) -> list[Path]:
    include_path = _resolve_include_path(include_arg, base_dir)

    if _contains_glob_pattern(include_arg):
        try:
            paths = sorted(Path(path) for path in glob.glob(str(include_path)))
        except (re.error, ValueError):
            return []
        return [path for path in paths if path.is_file()]

    return [include_path] if include_path.is_file() else []


def _resolve_include_path(include_arg: str, base_dir: Path) -> Path:
    include_path = Path(include_arg)

    if include_path.is_absolute():
        return include_path

    return base_dir / include_path


def _contains_glob_pattern(include_arg: str) -> bool:
    return any(char in include_arg for char in "*?[]")


def _parse_include_file(
    include_path: Path,
    *,
    directive: LighttpdDirectiveNode,
    issues: list[AnalysisIssue],
) -> LighttpdConfigAst | None:
    try:
        text = include_path.read_text(encoding="utf-8")
    except OSError:
        issues.append(
            _build_include_issue(
                code="lighttpd_include_not_found",
                message=f"Included config file not found: {include_path}",
                directive=directive,
            )
        )
        return None

    return _parse_include_text(
        text,
        source_path=str(include_path),
        directive=directive,
        issues=issues,
    )


def _parse_include_text(
    text: str,
    *,
    source_path: str,
    directive: LighttpdDirectiveNode,
    issues: list[AnalysisIssue],
) -> LighttpdConfigAst | None:
    try:
        return LighttpdParser(text, file_path=source_path).parse()
    except LighttpdParseError as exc:
        issues.append(
            AnalysisIssue(
                code="lighttpd_include_parse_error",
                level="error",
                message=str(exc),
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=exc.file_path or source_path,
                    line=exc.line,
                ),
            )
        )
        return None


def _build_include_issue(
    *,
    code: str,
    message: str,
    directive: LighttpdDirectiveNode,
    level: str = "error",
) -> AnalysisIssue:
    return AnalysisIssue(
        code=code,
        level=level,
        message=message,
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=directive.source.file_path,
            line=directive.source.line,
        ),
    )


def _directive_source_file(directive: LighttpdDirectiveNode, current_file: Path) -> str:
    return directive.source.file_path or str(current_file)


__all__ = ["resolve_includes"]
