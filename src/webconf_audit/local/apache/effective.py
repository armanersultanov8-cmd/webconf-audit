"""Effective-config helpers for Apache.

This module reconstructs a practical subset of Apache's merge behavior for
security analysis. It supports:

1. Global server-scope directives
2. Optional VirtualHost server-scope overrides
3. Covering Directory blocks (shortest path first)
4. Optional .htaccess filtered by AllowOverride
5. Optional Location / LocationMatch layering

The goal is not to perfectly emulate Apache, but to provide stable,
traceable effective values that are good enough for static security
analysis.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Literal

from webconf_audit.local.apache.htaccess import (
    HtaccessFile,
    extract_allowoverride,
    filter_htaccess_by_allowoverride,
)
from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
    ApacheSourceSpan,
)

TRANSPARENT_WRAPPER_BLOCKS = frozenset(
    {"if", "ifdefine", "ifmodule", "ifversion", "else", "elseif"}
)
LOCATION_BLOCK_NAMES = frozenset({"location", "locationmatch"})
ACCUMULATION_DIRECTIVES: dict[str, dict[str, Literal["replace", "accumulate", "remove"]]] = {
    "header": {
        "set": "replace",
        "append": "accumulate",
        "add": "accumulate",
        "unset": "remove",
        "merge": "accumulate",
    }
}


DirectiveArgs = list[str] | list[list[str]]


@dataclass(frozen=True, slots=True)
class ApacheVirtualHostContext:
    """Minimal metadata about a VirtualHost block."""

    server_name: str | None
    server_aliases: list[str]
    listen_address: str | None
    node: ApacheBlockNode


@dataclass(frozen=True, slots=True)
class DirectiveOrigin:
    """Where a directive value came from."""

    layer: str
    source: ApacheSourceSpan


@dataclass(frozen=True, slots=True)
class EffectiveDirective:
    """The effective value of a single directive after layering."""

    name: str
    args: DirectiveArgs
    origin: DirectiveOrigin
    override_chain: list[DirectiveOrigin] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class LocationScope:
    """A raw <Location> / <LocationMatch> scope."""

    path: str
    match_type: Literal["prefix", "regex"]
    directives: dict[str, EffectiveDirective]
    source: ApacheSourceSpan
    node: ApacheBlockNode


@dataclass(frozen=True, slots=True)
class EffectiveConfig:
    """Effective configuration for a specific Apache scope."""

    directory_path: str
    directives: dict[str, EffectiveDirective]
    virtualhost: ApacheVirtualHostContext | None = None
    location_path: str | None = None
    location_scopes: list[LocationScope] = field(default_factory=list)


def extract_virtualhost_contexts(
    config_ast: ApacheConfigAst,
) -> list[ApacheVirtualHostContext]:
    """Extract VirtualHost blocks with ServerName / ServerAlias metadata."""
    contexts: list[ApacheVirtualHostContext] = []

    for block in _iter_virtualhost_blocks(config_ast.nodes):
        server_name: str | None = None
        server_aliases: list[str] = []

        for directive in _iter_scoped_directives(block.children):
            name = directive.name.lower()
            if name == "servername" and directive.args:
                server_name = directive.args[0]
            elif name == "serveralias":
                server_aliases.extend(directive.args)

        contexts.append(
            ApacheVirtualHostContext(
                server_name=server_name,
                server_aliases=server_aliases,
                listen_address=block.args[0] if block.args else None,
                node=block,
            )
        )

    return contexts


def select_applicable_virtualhosts(
    contexts: list[ApacheVirtualHostContext],
    target_host: str | None = None,
) -> list[ApacheVirtualHostContext]:
    """Select VirtualHosts applicable to a target host.

    If *target_host* is omitted, static analysis keeps all VirtualHosts.
    """
    if target_host is None:
        return list(contexts)

    target = target_host.lower()
    selected: list[ApacheVirtualHostContext] = []
    default_contexts: list[ApacheVirtualHostContext] = []

    for context in contexts:
        if context.server_name is None and not context.server_aliases:
            default_contexts.append(context)
            continue

        names = []
        if context.server_name is not None:
            names.append(context.server_name)
        names.extend(context.server_aliases)

        if any(_host_matches(target, candidate) for candidate in names):
            selected.append(context)

    return selected or default_contexts


def build_server_effective_config(
    config_ast: ApacheConfigAst,
    virtualhost_context: ApacheVirtualHostContext | None = None,
) -> EffectiveConfig:
    """Build effective server-scope directives (global -> VirtualHost)."""
    directives: dict[str, EffectiveDirective] = {}
    _apply_directives(
        directives,
        _extract_top_level_directives(config_ast),
        layer="global",
    )

    if virtualhost_context is not None:
        _apply_directives(
            directives,
            virtualhost_context.node.children,
            layer=_virtualhost_layer(virtualhost_context),
        )

    return EffectiveConfig(
        directory_path="",
        directives=directives,
        virtualhost=virtualhost_context,
    )


def build_effective_config(
    config_ast: ApacheConfigAst,
    directory_path: str,
    htaccess_file: HtaccessFile | None = None,
    config_dir: Path | None = None,
    virtualhost_context: ApacheVirtualHostContext | None = None,
    location_path: str | None = None,
) -> EffectiveConfig:
    """Build effective config for a directory / location scope."""
    directives = _clone_directives(
        build_server_effective_config(
            config_ast,
            virtualhost_context=virtualhost_context,
        ).directives
    )

    target = Path(directory_path)
    if config_dir is not None and not target.is_absolute():
        target = config_dir / target

    sorted_dirs = _collect_covering_directory_blocks(
        config_ast,
        target,
        config_dir,
        virtualhost_context=virtualhost_context,
    )
    for dir_path, block in sorted_dirs:
        _apply_directives(
            directives,
            block.children,
            layer="directory",
        )

    if htaccess_file is not None:
        htaccess_ast = htaccess_file.ast
        if htaccess_file.source_directory_block is not None:
            allowed = extract_allowoverride(htaccess_file.source_directory_block)
            if allowed is not None:
                htaccess_ast = filter_htaccess_by_allowoverride(htaccess_ast, allowed)
                if len(allowed) == 0:
                    htaccess_ast = ApacheConfigAst(nodes=[])
        _apply_directives(
            directives,
            htaccess_ast.nodes,
            layer="htaccess",
        )

    applicable_locations = _extract_location_scopes_for_context(
        config_ast,
        virtualhost_context=virtualhost_context,
    )

    if location_path is not None:
        for scope in _matching_location_scopes(applicable_locations, location_path):
            _apply_directives(
                directives,
                scope.node.children,
                layer=f"location:{scope.path}",
            )

    return EffectiveConfig(
        directory_path=directory_path,
        directives=directives,
        virtualhost=virtualhost_context,
        location_path=location_path,
        location_scopes=applicable_locations,
    )


def extract_location_scopes(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
) -> list[LocationScope]:
    """Extract raw Location / LocationMatch scopes from a node list."""
    scopes: list[LocationScope] = []

    for block in _iter_location_blocks(nodes):
        match_type = "regex" if block.name.lower() == "locationmatch" else "prefix"
        scope_directives: dict[str, EffectiveDirective] = {}
        _apply_directives(
            scope_directives,
            block.children,
            layer=f"location:{block.args[0] if block.args else ''}",
        )
        scopes.append(
            LocationScope(
                path=block.args[0] if block.args else "",
                match_type=match_type,
                directives=scope_directives,
                source=block.source,
                node=block,
            )
        )

    scopes.sort(key=lambda scope: (len(scope.path), 0 if scope.match_type == "prefix" else 1))
    return scopes


def extract_document_root(
    config_ast: ApacheConfigAst,
    virtualhost_context: ApacheVirtualHostContext | None = None,
    config_dir: Path | None = None,
) -> Path | None:
    """Extract the applicable DocumentRoot for global scope or a VirtualHost."""
    search_nodes: list[ApacheDirectiveNode | ApacheBlockNode]
    if virtualhost_context is None:
        search_nodes = config_ast.nodes
    else:
        search_nodes = virtualhost_context.node.children

    found = _find_scoped_directive(search_nodes, "documentroot")
    if found is None and virtualhost_context is not None:
        found = _find_scoped_directive(config_ast.nodes, "documentroot")

    if found is None or not found.args:
        return None

    raw = Path(found.args[0])
    if raw.is_absolute():
        return raw

    if found.source.file_path:
        return Path(found.source.file_path).parent / raw

    if config_dir is not None:
        return config_dir / raw

    return raw


def _extract_top_level_directives(
    config_ast: ApacheConfigAst,
) -> list[ApacheDirectiveNode]:
    return _iter_top_level_directives(config_ast.nodes)


def _iter_top_level_directives(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
) -> list[ApacheDirectiveNode]:
    directives: list[ApacheDirectiveNode] = []
    for node in nodes:
        if isinstance(node, ApacheDirectiveNode):
            directives.append(node)
        elif _is_transparent_wrapper_block(node):
            directives.extend(_iter_top_level_directives(node.children))
    return directives


def _collect_covering_directory_blocks(
    config_ast: ApacheConfigAst,
    target_dir: Path,
    config_dir: Path | None,
    virtualhost_context: ApacheVirtualHostContext | None = None,
) -> list[tuple[str, ApacheBlockNode]]:
    """Find covering Directory blocks for the current global / VirtualHost scope."""
    target_str = _normalize(target_dir)
    matches: list[tuple[str, int, ApacheBlockNode]] = []

    for block, source_priority in _iter_directory_blocks_for_context(
        config_ast,
        virtualhost_context=virtualhost_context,
    ):
        dir_path = _extract_directory_path(block)
        if dir_path is None:
            continue
        if config_dir is not None and not dir_path.is_absolute():
            dir_path = _resolve_path_from_block(dir_path, block, config_dir)
        dir_str = _normalize(dir_path)

        if target_str == dir_str or target_str.startswith(dir_str + "/"):
            matches.append((dir_str, source_priority, block))

    matches.sort(key=lambda item: (len(item[0]), item[1]))
    return [(dir_path, block) for dir_path, _priority, block in matches]


def _extract_location_scopes_for_context(
    config_ast: ApacheConfigAst,
    virtualhost_context: ApacheVirtualHostContext | None = None,
) -> list[LocationScope]:
    scopes: list[tuple[int, LocationScope]] = []

    for block, source_priority in _iter_location_blocks_for_context(
        config_ast,
        virtualhost_context=virtualhost_context,
    ):
        match_type = "regex" if block.name.lower() == "locationmatch" else "prefix"
        scope_directives: dict[str, EffectiveDirective] = {}
        _apply_directives(
            scope_directives,
            block.children,
            layer=f"location:{block.args[0] if block.args else ''}",
        )
        scopes.append(
            (
                source_priority,
                LocationScope(
                    path=block.args[0] if block.args else "",
                    match_type=match_type,
                    directives=scope_directives,
                    source=block.source,
                    node=block,
                ),
            )
        )

    scopes.sort(
        key=lambda item: (
            len(item[1].path),
            0 if item[1].match_type == "prefix" else 1,
            item[0],
        )
    )
    return [scope for _priority, scope in scopes]


def _apply_directives(
    directives: dict[str, EffectiveDirective],
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    layer: str,
) -> None:
    """Apply directives from a layer using last-wins plus special merges."""
    for node in nodes:
        if isinstance(node, ApacheBlockNode):
            if _is_transparent_wrapper_block(node):
                _apply_directives(directives, node.children, layer)
            continue

        name_lower = node.name.lower()
        origin = DirectiveOrigin(layer=layer, source=node.source)

        if name_lower == "options" and _has_plus_minus_prefix(node.args):
            _merge_options(directives, node, origin)
            continue

        if name_lower in ACCUMULATION_DIRECTIVES:
            if _merge_accumulation_directive(directives, node, origin):
                continue

        prev = directives.get(name_lower)
        chain = list(prev.override_chain) + [prev.origin] if prev else []
        directives[name_lower] = EffectiveDirective(
            name=node.name,
            args=list(node.args),
            origin=origin,
            override_chain=chain,
        )


def _has_plus_minus_prefix(args: list[str]) -> bool:
    return any(arg.startswith(("+", "-")) for arg in args)


def _merge_options(
    directives: dict[str, EffectiveDirective],
    node: ApacheDirectiveNode,
    origin: DirectiveOrigin,
) -> None:
    prev = directives.get("options")
    if prev is not None:
        current_set = _extract_option_set(prev.args)
    else:
        current_set = set()

    for arg in node.args:
        lowered = arg.lower()
        if lowered == "none":
            current_set.clear()
        elif arg.startswith("+"):
            current_set.add(arg[1:].lower())
        elif arg.startswith("-"):
            current_set.discard(arg[1:].lower())

    chain = list(prev.override_chain) + [prev.origin] if prev else []
    directives["options"] = EffectiveDirective(
        name="Options",
        args=sorted(current_set),
        origin=origin,
        override_chain=chain,
    )


def _merge_accumulation_directive(
    directives: dict[str, EffectiveDirective],
    node: ApacheDirectiveNode,
    origin: DirectiveOrigin,
) -> bool:
    """Merge directives with accumulation semantics.

    Currently this is implemented for ``Header``.
    """
    if len(node.args) < 2:
        return False

    name_lower = node.name.lower()
    behavior = _accumulation_behavior(name_lower, node.args)
    if behavior is None:
        return False

    directive_key = name_lower
    prev = directives.get(directive_key)
    entries = _as_accumulated_args(prev.args) if prev is not None else []
    entries = _updated_accumulation_entries(entries, node.args, behavior)

    if not entries:
        directives.pop(directive_key, None)
        return True

    chain = list(prev.override_chain) + [prev.origin] if prev else []
    directives[directive_key] = EffectiveDirective(
        name=node.name,
        args=entries,
        origin=origin,
        override_chain=chain,
    )
    return True


def _accumulation_behavior(
    directive_name: str,
    args: list[str],
) -> str | None:
    action = args[0].lower()
    return ACCUMULATION_DIRECTIVES.get(directive_name, {}).get(action)


def _updated_accumulation_entries(
    entries: list[list[str]],
    args: list[str],
    behavior: str,
) -> list[list[str]]:
    target_name = args[1].lower()
    if behavior == "replace":
        return _replaced_accumulation_entries(entries, args, target_name)
    if behavior == "accumulate":
        return _accumulated_entries(entries, args)
    if behavior == "remove":
        return _remaining_accumulation_entries(entries, target_name)
    return entries


def _replaced_accumulation_entries(
    entries: list[list[str]],
    args: list[str],
    target_name: str,
) -> list[list[str]]:
    remaining = _remaining_accumulation_entries(entries, target_name)
    remaining.append(list(args))
    return remaining


def _accumulated_entries(
    entries: list[list[str]],
    args: list[str],
) -> list[list[str]]:
    if args[0].lower() == "merge" and any(entry == args for entry in entries):
        return entries
    return [*entries, list(args)]


def _remaining_accumulation_entries(
    entries: list[list[str]],
    target_name: str,
) -> list[list[str]]:
    return [
        entry for entry in entries if not _same_accumulation_target(entry, target_name)
    ]


def _same_accumulation_target(args: list[str], target_name: str) -> bool:
    return len(args) >= 2 and args[1].lower() == target_name


def _as_accumulated_args(args: DirectiveArgs) -> list[list[str]]:
    if not args:
        return []

    first = args[0]
    if isinstance(first, list):
        return [list(entry) for entry in args]

    return [list(args)]


def _extract_option_set(args: DirectiveArgs) -> set[str]:
    if not args:
        return set()

    if isinstance(args[0], list):
        flat_args = [token for group in args for token in group]
    else:
        flat_args = args

    absolute_args = [arg.lower() for arg in flat_args if not arg.startswith(("+", "-"))]
    if "none" in absolute_args:
        return set()
    return set(absolute_args)


def _clone_directives(
    directives: dict[str, EffectiveDirective],
) -> dict[str, EffectiveDirective]:
    cloned: dict[str, EffectiveDirective] = {}
    for key, directive in directives.items():
        args: DirectiveArgs
        if directive.args and isinstance(directive.args[0], list):
            args = [list(entry) for entry in directive.args]
        else:
            args = list(directive.args)
        cloned[key] = EffectiveDirective(
            name=directive.name,
            args=args,
            origin=directive.origin,
            override_chain=list(directive.override_chain),
        )
    return cloned


def _matching_location_scopes(
    scopes: list[LocationScope],
    target_path: str,
) -> list[LocationScope]:
    matched: list[LocationScope] = []
    for scope in scopes:
        if _location_scope_matches(scope, target_path):
            matched.append(scope)
    return matched


def _location_scope_matches(scope: LocationScope, target_path: str) -> bool:
    if scope.match_type == "regex":
        try:
            return re.search(scope.path, target_path) is not None
        except re.error:
            return False

    prefix = scope.path or "/"
    if prefix == "/":
        return True
    return target_path == prefix or target_path.startswith(prefix.rstrip("/") + "/")


def _host_matches(target_host: str, candidate: str) -> bool:
    candidate_lower = candidate.lower()
    if "*" in candidate_lower or "?" in candidate_lower:
        return fnmatch(target_host, candidate_lower)
    return target_host == candidate_lower


def _virtualhost_layer(context: ApacheVirtualHostContext) -> str:
    label = context.server_name or context.listen_address or "<default>"
    return f"virtualhost:{label}"


def _iter_virtualhost_blocks(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
) -> list[ApacheBlockNode]:
    blocks: list[ApacheBlockNode] = []
    for node in nodes:
        if isinstance(node, ApacheBlockNode):
            if node.name.lower() == "virtualhost":
                blocks.append(node)
            blocks.extend(_iter_virtualhost_blocks(node.children))
    return blocks


def _iter_scoped_directives(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
) -> list[ApacheDirectiveNode]:
    directives: list[ApacheDirectiveNode] = []
    for node in nodes:
        if isinstance(node, ApacheDirectiveNode):
            directives.append(node)
        elif _is_transparent_wrapper_block(node):
            directives.extend(_iter_scoped_directives(node.children))
    return directives


def _find_scoped_directive(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    directive_name: str,
) -> ApacheDirectiveNode | None:
    found: ApacheDirectiveNode | None = None
    for directive in _iter_scoped_directives(nodes):
        if directive.name.lower() == directive_name.lower():
            found = directive
    return found


def _iter_directory_blocks_for_context(
    config_ast: ApacheConfigAst,
    virtualhost_context: ApacheVirtualHostContext | None = None,
) -> list[tuple[ApacheBlockNode, int]]:
    return _iter_blocks_for_context(
        config_ast.nodes,
        target_block_names=frozenset({"directory"}),
        virtualhost_context=virtualhost_context,
    )


def _iter_location_blocks_for_context(
    config_ast: ApacheConfigAst,
    virtualhost_context: ApacheVirtualHostContext | None = None,
) -> list[tuple[ApacheBlockNode, int]]:
    return _iter_blocks_for_context(
        config_ast.nodes,
        target_block_names=LOCATION_BLOCK_NAMES,
        virtualhost_context=virtualhost_context,
    )


def _iter_blocks_for_context(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    *,
    target_block_names: frozenset[str],
    virtualhost_context: ApacheVirtualHostContext | None = None,
    source_priority: int = 0,
) -> list[tuple[ApacheBlockNode, int]]:
    blocks: list[tuple[ApacheBlockNode, int]] = []

    for node in nodes:
        if not isinstance(node, ApacheBlockNode):
            continue

        name = node.name.lower()
        if name == "virtualhost":
            if virtualhost_context is not None and node is virtualhost_context.node:
                blocks.extend(
                    _iter_blocks_for_context(
                        node.children,
                        target_block_names=target_block_names,
                        virtualhost_context=virtualhost_context,
                        source_priority=1,
                    )
                )
            continue

        if name in target_block_names:
            blocks.append((node, source_priority))

        blocks.extend(
            _iter_blocks_for_context(
                node.children,
                target_block_names=target_block_names,
                virtualhost_context=virtualhost_context,
                source_priority=source_priority,
            )
        )

    return blocks


def _iter_location_blocks(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
) -> list[ApacheBlockNode]:
    blocks: list[ApacheBlockNode] = []
    for node in nodes:
        if isinstance(node, ApacheBlockNode):
            if node.name.lower() in LOCATION_BLOCK_NAMES:
                blocks.append(node)
            blocks.extend(_iter_location_blocks(node.children))
    return blocks


def _is_transparent_wrapper_block(block: ApacheBlockNode) -> bool:
    return block.name.lower() in TRANSPARENT_WRAPPER_BLOCKS


def _extract_directory_path(block: ApacheBlockNode) -> Path | None:
    if not block.args:
        return None
    raw = block.args[0]
    if raw.startswith("~"):
        return None
    return Path(raw)


def _resolve_path_from_block(
    raw_path: Path,
    block: ApacheBlockNode,
    config_dir: Path | None,
) -> Path:
    if raw_path.is_absolute():
        return raw_path
    if block.source.file_path is not None:
        return Path(block.source.file_path).parent / raw_path
    if config_dir is not None:
        return config_dir / raw_path
    return raw_path


def _normalize(path: Path) -> str:
    return str(path.resolve()).replace("\\", "/").rstrip("/").lower()


__all__ = [
    "ApacheVirtualHostContext",
    "DirectiveOrigin",
    "EffectiveConfig",
    "EffectiveDirective",
    "LocationScope",
    "build_effective_config",
    "build_server_effective_config",
    "extract_document_root",
    "extract_location_scopes",
    "extract_virtualhost_contexts",
    "select_applicable_virtualhosts",
]
