from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from webconf_audit.local.lighttpd.conditions import is_potentially_matching
from webconf_audit.local.lighttpd.parser import (
    LighttpdAssignmentNode,
    LighttpdBlockNode,
    LighttpdCondition,
    LighttpdConfigAst,
    LighttpdSourceSpan,
)

if TYPE_CHECKING:
    from webconf_audit.local.lighttpd.conditions import LighttpdRequestContext


@dataclass(frozen=True, slots=True)
class LighttpdEffectiveDirective:
    name: str
    value: str
    operator: str
    scope: str  # "global" or "conditional"
    condition: LighttpdCondition | None
    source: LighttpdSourceSpan


@dataclass(frozen=True, slots=True)
class LighttpdConditionalScope:
    condition: LighttpdCondition | None
    header: str
    directives: dict[str, LighttpdEffectiveDirective]
    # Full chain of ancestor conditions (outermost first).
    # For a top-level block this equals ``(condition,)`` when condition is set.
    # For a nested block it contains the parent's conditions followed by this one.
    conditions: tuple[LighttpdCondition | None, ...] = ()
    # True when this scope is an ``else`` block.
    is_else: bool = False
    # Index of the sibling if-scope that this else belongs to (within
    # conditional_scopes list).  -1 when not an else block.
    sibling_if_index: int = -1


@dataclass(frozen=True, slots=True)
class LighttpdEffectiveConfig:
    global_directives: dict[str, LighttpdEffectiveDirective] = field(
        default_factory=dict,
    )
    conditional_scopes: list[LighttpdConditionalScope] = field(
        default_factory=list,
    )

    def get_global(self, name: str) -> LighttpdEffectiveDirective | None:
        return self.global_directives.get(name)


def build_effective_config(
    config_ast: LighttpdConfigAst,
) -> LighttpdEffectiveConfig:
    global_directives: dict[str, LighttpdEffectiveDirective] = {}
    conditional_scopes: list[LighttpdConditionalScope] = []

    _collect_nodes(config_ast.nodes, global_directives, conditional_scopes)

    return LighttpdEffectiveConfig(
        global_directives=global_directives,
        conditional_scopes=conditional_scopes,
    )


def _collect_nodes(
    nodes: list,
    global_directives: dict[str, LighttpdEffectiveDirective],
    conditional_scopes: list[LighttpdConditionalScope],
) -> None:
    last_if_index: int = -1
    for node in nodes:
        if isinstance(node, LighttpdAssignmentNode):
            _apply_assignment(node, global_directives, scope="global", condition=None)
        elif isinstance(node, LighttpdBlockNode):
            last_if_index = _collect_block(
                node,
                conditional_scopes,
                parent_conditions=(),
                last_sibling_if_index=last_if_index,
            )


def _collect_block(
    block: LighttpdBlockNode,
    conditional_scopes: list[LighttpdConditionalScope],
    *,
    parent_conditions: tuple[LighttpdCondition | None, ...],
    last_sibling_if_index: int,
) -> int:
    """Create a scope for this block's direct assignments, then recurse for nested blocks.

    Returns the index of the scope that was just appended (used as
    ``sibling_if_index`` for a following ``else`` block).
    """
    scope_directives: dict[str, LighttpdEffectiveDirective] = {}

    conditions = (*parent_conditions, block.condition)
    is_else = block.condition is None and block.header.strip().lower() == "else"

    # Collect nested blocks — they inherit this block's full condition chain.
    nested_last_if: int = -1
    for child in block.children:
        if isinstance(child, LighttpdAssignmentNode):
            _apply_assignment(
                child,
                scope_directives,
                scope="conditional",
                condition=block.condition,
            )
        elif isinstance(child, LighttpdBlockNode):
            nested_last_if = _collect_block(
                child,
                conditional_scopes,
                parent_conditions=conditions,
                last_sibling_if_index=nested_last_if,
            )

    my_index = len(conditional_scopes)
    conditional_scopes.append(
        LighttpdConditionalScope(
            condition=block.condition,
            header=block.header,
            directives=scope_directives,
            conditions=conditions,
            is_else=is_else,
            sibling_if_index=last_sibling_if_index if is_else else -1,
        )
    )
    return my_index


def _apply_assignment(
    node: LighttpdAssignmentNode,
    directives: dict[str, LighttpdEffectiveDirective],
    *,
    scope: str,
    condition: LighttpdCondition | None,
) -> None:
    effective = LighttpdEffectiveDirective(
        name=node.name,
        value=node.value,
        operator=node.operator,
        scope=scope,
        condition=condition,
        source=node.source,
    )

    if node.operator == "+=" and node.name in directives:
        prev = directives[node.name]
        merged_value = _merge_append(prev.value, node.value)
        effective = LighttpdEffectiveDirective(
            name=node.name,
            value=merged_value,
            operator="+=",
            scope=scope,
            condition=condition,
            source=node.source,
        )

    # "=" and ":=" both use last-wins.
    directives[node.name] = effective


def _merge_append(prev_value: str, new_value: str) -> str:
    """Merge two values for the += operator.

    For parenthesized lists like ( "mod_a" ), concatenate the inner items.
    For plain strings, concatenate them.
    """
    prev_inner = _unwrap_paren_list(prev_value)
    new_inner = _unwrap_paren_list(new_value)

    if prev_inner is not None and new_inner is not None:
        items = []
        if prev_inner.strip():
            items.append(prev_inner.strip())
        if new_inner.strip():
            items.append(new_inner.strip())
        return "( " + ", ".join(items) + " )"

    # Fallback: plain string concatenation for non-parenthesized values.
    # Lighttpd += on non-list values is rare in practice; string concat
    # is a safe approximation for the common case.
    #
    # Only insert a space when both sides are non-empty — otherwise an
    # empty previous value turned ``"" + "foo"`` into ``" foo"`` (and
    # ``"foo" += ""`` into ``"foo "``), which rule code that compares
    # strings against literal tokens then reads as a different value.
    prev_clean = prev_value.strip()
    new_clean = new_value.strip()
    if not prev_clean:
        return new_clean
    if not new_clean:
        return prev_clean
    return prev_clean + " " + new_clean


def _unwrap_paren_list(value: str) -> str | None:
    stripped = value.strip()
    if stripped.startswith("(") and stripped.endswith(")"):
        return stripped[1:-1]
    return None


def merge_conditional_scopes(
    effective_config: LighttpdEffectiveConfig,
    context: LighttpdRequestContext | None = None,
) -> dict[str, LighttpdEffectiveDirective]:
    """Merge global directives with all potentially-matching conditional scopes.

    Returns a flat directive dict that represents the "effective" view for
    a given *context*.  When *context* is ``None`` every conditional scope
    is treated as potentially matching (worst-case static analysis).

    Merge order follows definition order — later scopes override earlier
    ones (last-wins), and ``+=`` appends are accumulated.

    **Nested condition chains** — every condition in
    ``scope.conditions`` must be potentially matching for the scope to
    be included.

    **else blocks** — an ``else`` scope is included only when its
    sibling ``if``-scope was *not* deterministically matched.  When the
    context is ``None`` (worst-case), both ``if`` and ``else`` are
    included because either branch could fire.
    """
    merged: dict[str, LighttpdEffectiveDirective] = dict(
        effective_config.global_directives,
    )

    scopes = effective_config.conditional_scopes
    # Pre-compute deterministic match results for if/else sibling logic.
    scope_deterministic: list[bool] = [
        _is_deterministic_match(s, context) for s in scopes
    ]

    for scope in scopes:
        if not _scope_matches(scope, scope_deterministic, context):
            continue
        for name, directive in scope.directives.items():
            if directive.operator == "+=" and name in merged:
                prev = merged[name]
                merged_value = _merge_append(prev.value, directive.value)
                merged[name] = LighttpdEffectiveDirective(
                    name=name,
                    value=merged_value,
                    operator="+=",
                    scope="merged",
                    condition=directive.condition,
                    source=directive.source,
                )
            else:
                merged[name] = directive

    return merged


def _scope_matches(
    scope: LighttpdConditionalScope,
    scope_deterministic: list[bool],
    context: LighttpdRequestContext | None,
) -> bool:
    """Decide whether *scope* should participate in the merge."""
    # else-block: skip when the sibling if-scope was *deterministically*
    # matched (i.e. all its conditions evaluated to True, not just
    # "potentially matching").  In worst-case (no context) both if and
    # else branches must be included.
    if scope.is_else and scope.sibling_if_index >= 0:
        if scope_deterministic[scope.sibling_if_index]:
            return False

    # Check the full condition chain (all ancestors + own condition).
    # When ``conditions`` is empty (e.g. manually constructed scope),
    # fall back to the single ``scope.condition``.
    conds = scope.conditions if scope.conditions else (scope.condition,)
    for cond in conds:
        if not is_potentially_matching(cond, context):
            return False
    return True


def _is_deterministic_match(
    scope: LighttpdConditionalScope,
    context: LighttpdRequestContext | None,
) -> bool:
    """Return True only when every condition in the chain evaluates to True
    (not just "potentially matching").  Requires a concrete context."""
    if context is None:
        return False
    from webconf_audit.local.lighttpd.conditions import evaluate_condition

    conds = scope.conditions if scope.conditions else (scope.condition,)
    for cond in conds:
        if cond is None:
            # None condition (else block) is not deterministic by itself.
            return False
        result = evaluate_condition(cond, context)
        if result is not True:
            return False
    return True


__all__ = [
    "LighttpdConditionalScope",
    "LighttpdEffectiveConfig",
    "LighttpdEffectiveDirective",
    "build_effective_config",
    "merge_conditional_scopes",
]
