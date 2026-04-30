from __future__ import annotations

from collections.abc import Callable

from webconf_audit.local.apache.parser import ApacheBlockNode, ApacheDirectiveNode

ApacheAstNode = ApacheDirectiveNode | ApacheBlockNode
DirectiveTokenPredicate = Callable[[list[str]], bool]
DirectiveContextMatch = tuple[ApacheDirectiveNode, str]


def find_context_sensitive_directives(
    nodes: list[ApacheAstNode],
    directive_name: str,
    target_contexts: frozenset[str],
    token_predicate: DirectiveTokenPredicate,
) -> list[DirectiveContextMatch]:
    normalized_target_contexts = frozenset(context.lower() for context in target_contexts)
    matches: list[DirectiveContextMatch] = []
    _collect_context_sensitive_directives(
        nodes,
        directive_name=directive_name.lower(),
        target_contexts=normalized_target_contexts,
        token_predicate=token_predicate,
        block_stack=[],
        matches=matches,
    )
    return matches


def _find_nearest_target_context_name(
    block_stack: list[ApacheBlockNode],
    target_contexts: frozenset[str],
) -> str | None:
    for block in reversed(block_stack):
        block_name = block.name.lower()
        if block_name in target_contexts:
            return block_name

    return None


def _collect_context_sensitive_directives(
    nodes: list[ApacheAstNode],
    directive_name: str,
    target_contexts: frozenset[str],
    token_predicate: DirectiveTokenPredicate,
    block_stack: list[ApacheBlockNode],
    matches: list[DirectiveContextMatch],
) -> None:
    for node in nodes:
        if isinstance(node, ApacheDirectiveNode):
            if node.name.lower() != directive_name:
                continue

            if not token_predicate(node.args):
                continue

            context_name = _find_nearest_target_context_name(block_stack, target_contexts)
            if context_name is None:
                continue

            matches.append((node, context_name))
            continue

        _collect_context_sensitive_directives(
            node.children,
            directive_name=directive_name,
            target_contexts=target_contexts,
            token_predicate=token_predicate,
            block_stack=[*block_stack, node],
            matches=matches,
        )


__all__ = [
    "find_context_sensitive_directives",
]
