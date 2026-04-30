from __future__ import annotations

import glob
from pathlib import Path

from webconf_audit.local.load_context import LoadContext
from webconf_audit.local.nginx.parser.ast import AstNode, ConfigAst
from webconf_audit.local.nginx.parser.parser import NginxParseError, NginxTokenizer, NginxParser
from webconf_audit.models import AnalysisIssue, SourceLocation


def resolve_includes(
    config_ast: ConfigAst,
    config_path: str | Path,
    load_context: LoadContext | None = None,
) -> list[AnalysisIssue]:
    """Resolve include directives in-place, collecting issues instead of raising."""
    base_path = Path(config_path)
    normalized_base_path = base_path.resolve(strict=False)
    issues: list[AnalysisIssue] = []

    config_ast.nodes = _resolve_include_nodes(
        config_ast.nodes,
        base_dir=base_path.parent,
        current_file=normalized_base_path,
        include_chain=(normalized_base_path,),
        issues=issues,
        load_context=load_context,
    )

    return issues


def _resolve_include_nodes(
    nodes: list[AstNode],
    *,
    base_dir: Path,
    current_file: Path,
    include_chain: tuple[Path, ...],
    issues: list[AnalysisIssue],
    load_context: LoadContext | None = None,
) -> list[AstNode]:
    resolved_nodes: list[AstNode] = []

    for node in nodes:
        if node.node_type == "block":
            resolved_nodes.append(
                _resolved_block_node(
                    node,
                    base_dir=base_dir,
                    current_file=current_file,
                    include_chain=include_chain,
                    issues=issues,
                    load_context=load_context,
                )
            )
            continue

        if node.name != "include" or len(node.args) != 1:
            resolved_nodes.append(node)
            continue

        include_paths = _include_paths(node.args[0], base_dir)
        if include_paths is None:
            resolved_nodes.append(node)
            continue

        for include_path in include_paths:
            resolved_nodes.extend(
                _resolved_include_path_nodes(
                    include_path,
                    node=node,
                    include_chain=include_chain,
                    issues=issues,
                    load_context=load_context,
                    current_file=current_file,
                )
            )

    return resolved_nodes


def _resolved_block_node(
    node: AstNode,
    *,
    base_dir: Path,
    current_file: Path,
    include_chain: tuple[Path, ...],
    issues: list[AnalysisIssue],
    load_context: LoadContext | None,
) -> AstNode:
    node.children = _resolve_include_nodes(
        node.children,
        base_dir=base_dir,
        current_file=current_file,
        include_chain=include_chain,
        issues=issues,
        load_context=load_context,
    )
    return node


def _include_paths(include_arg: str, base_dir: Path) -> list[Path] | None:
    include_path = Path(include_arg)
    if _contains_glob_pattern(include_arg):
        include_pattern = include_path if include_path.is_absolute() else base_dir / include_arg
        return sorted(Path(path) for path in glob.glob(str(include_pattern)))
    if include_path.is_absolute():
        return [include_path]
    if not _is_supported_relative_file(include_arg):
        return None
    return [base_dir / include_arg]


def _resolved_include_path_nodes(
    include_path: Path,
    *,
    node: AstNode,
    include_chain: tuple[Path, ...],
    issues: list[AnalysisIssue],
    load_context: LoadContext | None,
    current_file: Path,
) -> list[AstNode]:
    issue = _include_path_issue(include_path, node, include_chain, current_file)
    if issue is not None:
        issues.append(issue)
        return []

    normalized_include_path = include_path.resolve(strict=False)
    normalized_current_file = current_file.resolve(strict=False)
    if load_context is not None:
        load_context.add_edge(
            str(normalized_current_file),
            node.source.line,
            str(normalized_include_path),
        )

    include_ast = _parse_include_file(include_path, node, issues)
    if include_ast is None:
        return []

    include_ast.nodes = _resolve_include_nodes(
        include_ast.nodes,
        base_dir=normalized_include_path.parent,
        current_file=normalized_include_path,
        include_chain=(*include_chain, normalized_include_path),
        issues=issues,
        load_context=load_context,
    )
    return list(include_ast.nodes)


def _include_path_issue(
    include_path: Path,
    node: AstNode,
    include_chain: tuple[Path, ...],
    current_file: Path,
) -> AnalysisIssue | None:
    normalized_include_path = include_path.resolve(strict=False)
    if _is_self_include(include_path, current_file):
        return _build_include_issue(
            code="nginx_include_self_include",
            message=f"Self-include detected: {normalized_include_path}",
            node=node,
        )

    if _check_include_cycle(include_path, include_chain) is None:
        return _build_include_issue(
            code="nginx_include_cycle",
            message=f"Include cycle detected: {normalized_include_path}",
            node=node,
        )
    return None


def _is_self_include(include_path: Path, current_file: Path) -> bool:
    return include_path.resolve(strict=False) == current_file.resolve(strict=False)


def _check_include_cycle(include_path: Path, include_chain: tuple[Path, ...]) -> Path | None:
    """Return normalized path if no cycle, or None if cycle detected."""
    normalized = include_path.resolve(strict=False)
    if normalized in include_chain:
        return None
    return normalized


def _contains_glob_pattern(include_arg: str) -> bool:
    return any(char in include_arg for char in "*?[]")


def _is_supported_relative_file(include_arg: str) -> bool:
    if not include_arg:
        return False

    if include_arg.startswith(("/", "\\")):
        return False

    if _contains_glob_pattern(include_arg) or "$" in include_arg:
        return False

    return not Path(include_arg).is_absolute()


def _parse_include_file(
    include_path: Path,
    node: AstNode,
    issues: list[AnalysisIssue],
) -> ConfigAst | None:
    try:
        text = include_path.read_text(encoding="utf-8")
    except OSError:
        issues.append(_build_include_issue(
            code="nginx_include_not_found",
            message=f"Included config file not found: {include_path}",
            node=node,
        ))
        return None

    try:
        tokens = NginxTokenizer(text, file_path=str(include_path)).tokenize()
        return NginxParser(tokens).parse()
    except NginxParseError as exc:
        issues.append(
            AnalysisIssue(
                code="nginx_include_parse_error",
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
    node: AstNode,
) -> AnalysisIssue:
    return AnalysisIssue(
        code=code,
        level="error",
        message=message,
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=node.source.file_path,
            line=node.source.line,
        ),
    )
