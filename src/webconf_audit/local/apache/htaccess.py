from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
    ApacheParseError,
    ApacheParser,
    ApacheTokenizer,
)
from webconf_audit.models import AnalysisIssue, SourceLocation

DEFAULT_ACCESS_FILE_NAME = ".htaccess"

# Apache AllowOverride categories and which directives belong to each.
# This is a practical subset covering directives relevant to security rules,
# not the full Apache directive catalogue.
OVERRIDE_CATEGORY_MAP: dict[str, str] = {
    # AuthConfig
    "authtype": "AuthConfig",
    "authname": "AuthConfig",
    "authuserfile": "AuthConfig",
    "authgroupfile": "AuthConfig",
    "authbasicprovider": "AuthConfig",
    "authdigestprovider": "AuthConfig",
    "require": "AuthConfig",
    # FileInfo
    "errordocument": "FileInfo",
    "header": "FileInfo",
    "requestheader": "FileInfo",
    "rewriteengine": "FileInfo",
    "rewriterule": "FileInfo",
    "rewritecond": "FileInfo",
    "rewritebase": "FileInfo",
    "addtype": "FileInfo",
    "addcharset": "FileInfo",
    "addencoding": "FileInfo",
    "addhandler": "FileInfo",
    "removehandler": "FileInfo",
    "sethandler": "FileInfo",
    "forcetype": "FileInfo",
    "defaulttype": "FileInfo",
    "expiresactive": "FileInfo",
    "expiresbytype": "FileInfo",
    "expiresdefault": "FileInfo",
    # Indexes
    "directoryindex": "Indexes",
    "indexoptions": "Indexes",
    "addicon": "Indexes",
    "addiconbytype": "Indexes",
    "addiconbyencoding": "Indexes",
    "adddescription": "Indexes",
    "indexignore": "Indexes",
    "headerindex": "Indexes",
    "readmename": "Indexes",
    # Limit
    "limit": "Limit",
    "limitexcept": "Limit",
    # Options
    "options": "Options",
}

ALL_OVERRIDE_CATEGORIES = frozenset(
    {"AuthConfig", "FileInfo", "Indexes", "Limit", "Options"}
)
LOWERCASE_OVERRIDE_CATEGORY_MAP = {
    category.lower(): category for category in ALL_OVERRIDE_CATEGORIES
}


@dataclass(frozen=True, slots=True)
class HtaccessFile:
    directory_path: str
    htaccess_path: str
    ast: ApacheConfigAst
    source_directory_block: ApacheBlockNode | None
    source_virtualhost_block: ApacheBlockNode | None = None


@dataclass(slots=True)
class HtaccessDiscoveryResult:
    found: list[HtaccessFile] = field(default_factory=list)
    issues: list[AnalysisIssue] = field(default_factory=list)


def discover_htaccess_files(
    config_ast: ApacheConfigAst,
    config_path: str | Path,
) -> HtaccessDiscoveryResult:
    """Discover and parse .htaccess files for Directory blocks and DocumentRoot."""
    result = HtaccessDiscoveryResult()
    config_dir = Path(config_path).parent
    access_file_name = _extract_access_file_name(config_ast)

    all_directory_blocks = _iter_directory_blocks_with_virtualhost(config_ast.nodes)
    dir_block_index = _build_directory_block_index(all_directory_blocks, config_dir)
    seen_dirs: set[Path] = set()

    for block, source_virtualhost_block in all_directory_blocks:
        dir_path = _resolve_directory_block_path(block, config_dir)
        if dir_path is None:
            continue

        effective_block = _find_effective_allowoverride_source_block(
            dir_path,
            dir_block_index,
        )
        effective_virtualhost_block = (
            source_virtualhost_block
            if source_virtualhost_block is not None
            else _find_virtualhost_for_directory(dir_path, dir_block_index)
        )
        _try_discover(
            dir_path,
            access_file_name,
            effective_block,
            effective_virtualhost_block,
            seen_dirs,
            result,
        )

    for doc_root, source_virtualhost_block in _extract_document_roots(config_ast):
        doc_root = _resolve_relative(doc_root, config_dir)
        covering_block = _find_effective_allowoverride_source_block(
            doc_root,
            dir_block_index,
        )
        _try_discover(
            doc_root,
            access_file_name,
            covering_block,
            source_virtualhost_block,
            seen_dirs,
            result,
        )

    return result


def _try_discover(
    dir_path: Path,
    access_file_name: str,
    source_block: ApacheBlockNode | None,
    source_virtualhost_block: ApacheBlockNode | None,
    seen_dirs: set[Path],
    result: HtaccessDiscoveryResult,
) -> None:
    resolved = dir_path.resolve()
    if resolved in seen_dirs:
        return
    seen_dirs.add(resolved)

    htaccess_path = dir_path / access_file_name
    if not htaccess_path.is_file():
        return

    try:
        text = htaccess_path.read_text(encoding="utf-8")
    except OSError as exc:
        result.issues.append(
            AnalysisIssue(
                code="htaccess_read_error",
                level="warning",
                message=f"Cannot read {htaccess_path}: {exc}",
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=str(htaccess_path),
                ),
            )
        )
        return

    try:
        tokens = ApacheTokenizer(text, file_path=str(htaccess_path)).tokenize()
        ast = ApacheParser(tokens).parse()
    except ApacheParseError as exc:
        result.issues.append(
            AnalysisIssue(
                code="htaccess_parse_error",
                level="warning",
                message=f"Parse error in {htaccess_path}: {exc}",
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=exc.file_path or str(htaccess_path),
                    line=exc.line,
                ),
            )
        )
        return

    result.found.append(
        HtaccessFile(
            directory_path=str(dir_path),
            htaccess_path=str(htaccess_path),
            ast=ast,
            source_directory_block=source_block,
            source_virtualhost_block=source_virtualhost_block,
        )
    )


def _resolve_relative(path: Path, base_dir: Path) -> Path:
    """Resolve a potentially relative path against a base directory."""
    if path.is_absolute():
        return path
    return base_dir / path


def _build_directory_block_index(
    blocks: list[tuple[ApacheBlockNode, ApacheBlockNode | None]],
    fallback_base_dir: Path | None = None,
) -> list[tuple[Path, ApacheBlockNode, ApacheBlockNode | None, int]]:
    """Build a list of resolved Directory paths for inheritance lookup."""
    index: list[tuple[Path, ApacheBlockNode, ApacheBlockNode | None, int]] = []
    for source_order, (block, source_virtualhost_block) in enumerate(blocks):
        dir_path = _resolve_directory_block_path(block, fallback_base_dir)
        if dir_path is None:
            continue
        index.append((dir_path.resolve(), block, source_virtualhost_block, source_order))
    return index


def _find_effective_allowoverride_source_block(
    target_dir: Path,
    dir_block_index: list[tuple[Path, ApacheBlockNode, ApacheBlockNode | None, int]],
) -> ApacheBlockNode | None:
    """Find the most specific covering block that explicitly sets AllowOverride."""
    resolved_target = target_dir.resolve()
    best_match: tuple[int, int, ApacheBlockNode] | None = None

    for dir_path, block, _source_virtualhost_block, source_order in dir_block_index:
        if not _path_is_covered_by_directory(resolved_target, dir_path):
            continue

        if extract_allowoverride(block) is None:
            continue

        specificity = len(_normalize_path_for_match(dir_path))
        if (
            best_match is None
            or specificity > best_match[0]
            or (specificity == best_match[0] and source_order > best_match[1])
        ):
            best_match = (specificity, source_order, block)

    return best_match[2] if best_match is not None else None


def _find_virtualhost_for_directory(
    target_dir: Path,
    dir_block_index: list[tuple[Path, ApacheBlockNode, ApacheBlockNode | None, int]],
) -> ApacheBlockNode | None:
    resolved_target = target_dir.resolve()
    best_match: tuple[int, int, ApacheBlockNode] | None = None

    for dir_path, _block, source_virtualhost_block, source_order in dir_block_index:
        if source_virtualhost_block is None:
            continue
        if not _path_is_covered_by_directory(resolved_target, dir_path):
            continue

        specificity = len(_normalize_path_for_match(dir_path))
        if (
            best_match is None
            or specificity > best_match[0]
            or (specificity == best_match[0] and source_order > best_match[1])
        ):
            best_match = (specificity, source_order, source_virtualhost_block)

    return best_match[2] if best_match is not None else None


def _path_is_covered_by_directory(target_path: Path, directory_path: Path) -> bool:
    target_str = _normalize_path_for_match(target_path)
    dir_str = _normalize_path_for_match(directory_path)
    return target_str == dir_str or target_str.startswith(dir_str + "/")


def _normalize_path_for_match(path: Path) -> str:
    return str(path).replace("\\", "/").rstrip("/").lower()


def _extract_access_file_name(config_ast: ApacheConfigAst) -> str:
    """Extract server-scope AccessFileName from top-level context only."""
    found = _find_server_scope_access_file_name(config_ast.nodes)
    return found if found is not None else DEFAULT_ACCESS_FILE_NAME


def _find_server_scope_access_file_name(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
) -> str | None:
    server_scope_blocks = frozenset({"ifmodule", "ifversion", "if", "ifdefine"})
    found: str | None = None

    for node in nodes:
        if (
            isinstance(node, ApacheDirectiveNode)
            and node.name.lower() == "accessfilename"
            and node.args
        ):
            found = node.args[0]
            continue

        if (
            isinstance(node, ApacheBlockNode)
            and node.name.lower() in server_scope_blocks
        ):
            nested = _find_server_scope_access_file_name(node.children)
            if nested is not None:
                found = nested

    return found


def _resolve_directory_block_path(
    block: ApacheBlockNode,
    fallback_base_dir: Path | None = None,
) -> Path | None:
    dir_path = _extract_directory_path(block)
    if dir_path is None:
        return None

    if dir_path.is_absolute():
        return dir_path

    source_file_path = block.source.file_path
    if source_file_path is not None:
        return Path(source_file_path).parent / dir_path

    if fallback_base_dir is not None:
        return fallback_base_dir / dir_path

    return dir_path


def _extract_directory_path(block: ApacheBlockNode) -> Path | None:
    """Extract filesystem path from <Directory "path"> block."""
    if not block.args:
        return None
    raw = block.args[0]
    if raw.startswith("~"):
        return None
    return Path(raw)


def _extract_document_roots(
    config_ast: ApacheConfigAst,
) -> list[tuple[Path, ApacheBlockNode | None]]:
    """Extract all DocumentRoot values (top-level and from VirtualHost blocks)."""
    roots: list[tuple[Path, ApacheBlockNode | None]] = []
    for node in config_ast.nodes:
        if isinstance(node, ApacheDirectiveNode):
            if node.name.lower() == "documentroot" and node.args:
                roots.append((Path(node.args[0]), None))
        elif isinstance(node, ApacheBlockNode):
            roots.extend(_extract_document_roots_from_block(node))
    return roots


def _extract_document_roots_from_block(
    block: ApacheBlockNode,
    source_virtualhost_block: ApacheBlockNode | None = None,
) -> list[tuple[Path, ApacheBlockNode | None]]:
    roots: list[tuple[Path, ApacheBlockNode | None]] = []
    current_virtualhost = (
        block if block.name.lower() == "virtualhost" else source_virtualhost_block
    )
    for child in block.children:
        if (
            isinstance(child, ApacheDirectiveNode)
            and child.name.lower() == "documentroot"
            and child.args
        ):
            roots.append((Path(child.args[0]), current_virtualhost))
        elif isinstance(child, ApacheBlockNode):
            roots.extend(
                _extract_document_roots_from_block(
                    child,
                    source_virtualhost_block=current_virtualhost,
                )
            )
    return roots


def _iter_directory_blocks_with_virtualhost(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
) -> list[tuple[ApacheBlockNode, ApacheBlockNode | None]]:
    return _collect_directory_blocks(nodes, source_virtualhost_block=None)


def _collect_directory_blocks(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    source_virtualhost_block: ApacheBlockNode | None,
) -> list[tuple[ApacheBlockNode, ApacheBlockNode | None]]:
    blocks: list[tuple[ApacheBlockNode, ApacheBlockNode | None]] = []
    for node in nodes:
        if isinstance(node, ApacheBlockNode):
            current_virtualhost = (
                node if node.name.lower() == "virtualhost" else source_virtualhost_block
            )
            if node.name.lower() == "directory":
                blocks.append((node, source_virtualhost_block))
            blocks.extend(
                _collect_directory_blocks(
                    node.children,
                    source_virtualhost_block=current_virtualhost,
                )
            )
    return blocks


def extract_allowoverride(directory_block: ApacheBlockNode) -> frozenset[str] | None:
    """Extract AllowOverride categories from a <Directory> block."""
    directive = _find_allowoverride_directive(directory_block)
    if directive is None:
        return None

    special_case = _allowoverride_special_case(directive.args)
    if special_case is not None:
        return special_case

    return _allowoverride_categories(directive.args)


def _find_allowoverride_directive(
    directory_block: ApacheBlockNode,
) -> ApacheDirectiveNode | None:
    # Apache honors the last ``AllowOverride`` declaration within a
    # single ``<Directory>`` block — a later sibling overrides earlier
    # ones, matching httpd's own core-module merge semantics.
    last_match: ApacheDirectiveNode | None = None
    for child in directory_block.children:
        if (
            isinstance(child, ApacheDirectiveNode)
            and child.name.lower() == "allowoverride"
            and child.args
        ):
            last_match = child
    return last_match


def _allowoverride_special_case(args: list[str]) -> frozenset[str] | None:
    args_lower = {arg.lower() for arg in args}
    if "none" in args_lower:
        return frozenset()
    if "all" in args_lower:
        return ALL_OVERRIDE_CATEGORIES
    return None


def _allowoverride_categories(args: list[str]) -> frozenset[str]:
    return frozenset(
        LOWERCASE_OVERRIDE_CATEGORY_MAP[arg.lower()]
        for arg in args
        if arg.lower() in LOWERCASE_OVERRIDE_CATEGORY_MAP
    )


def filter_htaccess_by_allowoverride(
    htaccess_ast: ApacheConfigAst,
    allowed_categories: frozenset[str],
) -> ApacheConfigAst:
    """Return a new AST containing only directives permitted by AllowOverride."""
    filtered = _filter_nodes(htaccess_ast.nodes, allowed_categories)
    return ApacheConfigAst(nodes=filtered)


def _filter_nodes(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    allowed_categories: frozenset[str],
) -> list[ApacheDirectiveNode | ApacheBlockNode]:
    result: list[ApacheDirectiveNode | ApacheBlockNode] = []
    for node in nodes:
        if isinstance(node, ApacheDirectiveNode):
            category = OVERRIDE_CATEGORY_MAP.get(node.name.lower())
            if category is not None and category in allowed_categories:
                result.append(node)
            continue

        block_category = OVERRIDE_CATEGORY_MAP.get(node.name.lower())
        if block_category is not None and block_category not in allowed_categories:
            continue

        filtered_children = _filter_nodes(node.children, allowed_categories)
        result.append(
            ApacheBlockNode(
                name=node.name,
                args=node.args,
                children=filtered_children,
                source=node.source,
            )
        )
    return result


__all__ = [
    "ALL_OVERRIDE_CATEGORIES",
    "DEFAULT_ACCESS_FILE_NAME",
    "HtaccessDiscoveryResult",
    "HtaccessFile",
    "OVERRIDE_CATEGORY_MAP",
    "discover_htaccess_files",
    "extract_allowoverride",
    "filter_htaccess_by_allowoverride",
]
