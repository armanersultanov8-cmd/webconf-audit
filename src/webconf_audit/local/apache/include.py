from __future__ import annotations

import glob
from pathlib import Path

from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
    ApacheParseError,
    ApacheParser,
    ApacheTokenizer,
)
from webconf_audit.local.load_context import LoadContext
from webconf_audit.models import AnalysisIssue, SourceLocation

INCLUDE_DIRECTIVES = frozenset({"include", "includeoptional"})


def resolve_includes(
    config_ast: ApacheConfigAst,
    config_path: str | Path,
    load_context: LoadContext | None = None,
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
    )

    return issues


def _resolve_include_nodes(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    *,
    current_file: Path,
    include_chain: tuple[Path, ...],
    issues: list[AnalysisIssue],
    load_context: LoadContext | None = None,
) -> list[ApacheDirectiveNode | ApacheBlockNode]:
    resolved_nodes: list[ApacheDirectiveNode | ApacheBlockNode] = []

    for node in nodes:
        if isinstance(node, ApacheBlockNode):
            resolved_nodes.append(
                _resolved_block_node(
                    node,
                    current_file=current_file,
                    include_chain=include_chain,
                    issues=issues,
                    load_context=load_context,
                )
            )
            continue

        if not _is_include_directive(node):
            resolved_nodes.append(node)
            continue

        resolved_nodes.extend(
            _resolved_include_directive_nodes(
                node,
                current_file=current_file,
                include_chain=include_chain,
                issues=issues,
                load_context=load_context,
            )
        )

    return resolved_nodes


def _resolved_block_node(
    node: ApacheBlockNode,
    *,
    current_file: Path,
    include_chain: tuple[Path, ...],
    issues: list[AnalysisIssue],
    load_context: LoadContext | None,
) -> ApacheBlockNode:
    node.children = _resolve_include_nodes(
        node.children,
        current_file=current_file,
        include_chain=include_chain,
        issues=issues,
        load_context=load_context,
    )
    return node


def _is_include_directive(node: ApacheDirectiveNode) -> bool:
    return node.name.lower() in INCLUDE_DIRECTIVES and len(node.args) == 1


def _resolved_include_directive_nodes(
    node: ApacheDirectiveNode,
    *,
    current_file: Path,
    include_chain: tuple[Path, ...],
    issues: list[AnalysisIssue],
    load_context: LoadContext | None,
) -> list[ApacheDirectiveNode | ApacheBlockNode]:
    include_paths = _expand_include_paths(node.args[0], current_file.parent)
    if not include_paths:
        _append_missing_include_issue(node, issues)
        return []

    resolved_nodes: list[ApacheDirectiveNode | ApacheBlockNode] = []
    for include_path in include_paths:
        include_ast = _resolved_include_ast(
            node,
            include_path=include_path,
            current_file=current_file,
            include_chain=include_chain,
            issues=issues,
            load_context=load_context,
        )
        if include_ast is not None:
            resolved_nodes.extend(include_ast.nodes)
    return resolved_nodes


def _append_missing_include_issue(
    node: ApacheDirectiveNode,
    issues: list[AnalysisIssue],
) -> None:
    if node.name.lower() == "includeoptional":
        return
    issues.append(
        _build_include_issue(
            code="apache_include_not_found",
            message=f"Included config path not found: {node.args[0]}",
            directive=node,
        )
    )


def _resolved_include_ast(
    node: ApacheDirectiveNode,
    *,
    include_path: Path,
    current_file: Path,
    include_chain: tuple[Path, ...],
    issues: list[AnalysisIssue],
    load_context: LoadContext | None,
) -> ApacheConfigAst | None:
    normalized_include_path = include_path.resolve(strict=False)
    include_issue = _include_path_issue(
        node,
        normalized_include_path=normalized_include_path,
        current_file=current_file,
        include_chain=include_chain,
    )
    if include_issue is not None:
        issues.append(include_issue)
        return None

    if load_context is not None:
        load_context.add_edge(str(current_file), node.source.line, str(include_path))

    include_ast = _parse_include_file(include_path, directive=node, issues=issues)
    if include_ast is None:
        return None

    include_ast.nodes = _resolve_include_nodes(
        include_ast.nodes,
        current_file=include_path,
        include_chain=(*include_chain, normalized_include_path),
        issues=issues,
        load_context=load_context,
    )
    return include_ast


def _include_path_issue(
    node: ApacheDirectiveNode,
    *,
    normalized_include_path: Path,
    current_file: Path,
    include_chain: tuple[Path, ...],
) -> AnalysisIssue | None:
    normalized_current_path = current_file.resolve(strict=False)
    if normalized_include_path == normalized_current_path:
        return _build_include_issue(
            code="apache_include_self_include",
            message=f"Self-include detected: {normalized_include_path}",
            directive=node,
        )
    if normalized_include_path in include_chain:
        return _build_include_issue(
            code="apache_include_cycle",
            message=f"Include cycle detected: {normalized_include_path}",
            directive=node,
        )
    return None


def _expand_include_paths(include_arg: str, base_dir: Path) -> list[Path]:
    include_path = _resolve_include_path(include_arg, base_dir)

    if _contains_glob_pattern(include_arg):
        paths = sorted(Path(path) for path in glob.glob(str(include_path)))
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
    directive: ApacheDirectiveNode,
    issues: list[AnalysisIssue],
) -> ApacheConfigAst | None:
    try:
        text = include_path.read_text(encoding="utf-8")
    except OSError:
        issues.append(
            _build_include_issue(
                code="apache_include_not_found",
                message=f"Included config file not found: {include_path}",
                directive=directive,
            )
        )
        return None
    except UnicodeDecodeError as exc:
        issues.append(
            _build_include_issue(
                code="apache_include_read_error",
                message=f"Cannot decode included config file {include_path}: {exc}",
                directive=directive,
            )
        )
        return None

    try:
        tokens = ApacheTokenizer(text, file_path=str(include_path)).tokenize()
        return ApacheParser(tokens).parse()
    except ApacheParseError as exc:
        issues.append(
            AnalysisIssue(
                code="apache_include_parse_error",
                level="error",
                message=str(exc),
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=exc.file_path or str(include_path),
                    line=exc.line,
                ),
            )
        )
        return None


def _build_include_issue(
    *,
    code: str,
    message: str,
    directive: ApacheDirectiveNode,
) -> AnalysisIssue:
    return AnalysisIssue(
        code=code,
        level="error",
        message=message,
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=directive.source.file_path,
            line=directive.source.line,
        ),
    )


__all__ = ["resolve_includes"]
