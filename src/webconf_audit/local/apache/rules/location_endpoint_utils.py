from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from webconf_audit.local.apache.effective import (
    ApacheVirtualHostContext,
    EffectiveConfig,
    LocationScope,
    build_effective_config,
    extract_document_root,
    extract_virtualhost_contexts,
)
from webconf_audit.local.apache.parser import ApacheBlockNode, ApacheDirectiveNode

TRANSPARENT_WRAPPER_BLOCKS = frozenset(
    {"if", "ifdefine", "ifmodule", "ifversion", "else", "elseif"}
)


@dataclass(frozen=True, slots=True)
class EffectiveLocationEvaluation:
    effective_config: EffectiveConfig
    scope: LocationScope
    virtualhost_context: ApacheVirtualHostContext | None


def find_location_blocks(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    target_path: str,
) -> list[ApacheBlockNode]:
    location_blocks: list[ApacheBlockNode] = []

    for node in nodes:
        if isinstance(node, ApacheBlockNode):
            node_name = node.name.lower()
            if node_name == "location" and any(
                _prefix_location_matches(arg, target_path) for arg in node.args
            ):
                location_blocks.append(node)
            elif node_name == "locationmatch" and any(
                _regex_location_matches(arg, target_path) for arg in node.args
            ):
                location_blocks.append(node)

            location_blocks.extend(find_location_blocks(node.children, target_path))

    return location_blocks


def location_has_require_ip(location_block: ApacheBlockNode) -> bool:
    for child in location_block.children:
        if isinstance(child, ApacheDirectiveNode):
            if (
                child.name.lower() == "require"
                and len(child.args) >= 2
                and child.args[0].lower() == "ip"
            ):
                return True
            continue

        if child.name.lower() in TRANSPARENT_WRAPPER_BLOCKS and location_has_require_ip(child):
            return True

    return False


def find_effective_location_evaluations(
    config_ast,
    target_path: str,
) -> list[EffectiveLocationEvaluation]:
    virtualhosts = extract_virtualhost_contexts(config_ast)
    if virtualhosts:
        return [
            evaluation
            for context in virtualhosts
            if (
                evaluation := _evaluate_effective_location_for_context(
                    config_ast,
                    target_path,
                    context,
                )
            )
            is not None
        ]

    evaluation = _evaluate_effective_location_for_context(
        config_ast,
        target_path,
        None,
    )
    return [evaluation] if evaluation is not None else []


def effective_location_has_require_ip(effective_config: EffectiveConfig) -> bool:
    directive = effective_config.directives.get("require")
    if directive is None or not directive.args:
        return False

    first_arg = directive.args[0]
    if isinstance(first_arg, list):
        return False

    return len(directive.args) >= 2 and first_arg.lower() == "ip"


def virtualhost_label(context: ApacheVirtualHostContext | None) -> str:
    if context is None:
        return "<global>"
    return context.server_name or context.listen_address or "<unnamed>"


def _evaluate_effective_location_for_context(
    config_ast,
    target_path: str,
    context: ApacheVirtualHostContext | None,
) -> EffectiveLocationEvaluation | None:
    base_directory = extract_document_root(
        config_ast,
        virtualhost_context=context,
    ) or Path("/")
    effective = build_effective_config(
        config_ast,
        str(base_directory),
        virtualhost_context=context,
        location_path=target_path,
    )
    matching_scopes = [
        scope
        for scope in effective.location_scopes
        if _location_scope_matches(scope, target_path)
    ]
    if not matching_scopes:
        return None

    return EffectiveLocationEvaluation(
        effective_config=effective,
        scope=matching_scopes[-1],
        virtualhost_context=context,
    )


def _location_scope_matches(scope: LocationScope, target_path: str) -> bool:
    if scope.match_type == "regex":
        return _regex_location_matches(scope.path, target_path)
    return _prefix_location_matches(scope.path or "/", target_path)


def _prefix_location_matches(raw_path: str, target_path: str) -> bool:
    if raw_path == "/":
        return True
    return raw_path.lower() == target_path.lower() or target_path.lower().startswith(
        raw_path.rstrip("/").lower() + "/"
    )


def _regex_location_matches(pattern: str, target_path: str) -> bool:
    try:
        return re.search(pattern, target_path) is not None
    except re.error:
        return False


__all__ = [
    "EffectiveLocationEvaluation",
    "effective_location_has_require_ip",
    "find_effective_location_evaluations",
    "find_location_blocks",
    "location_has_require_ip",
    "virtualhost_label",
]
