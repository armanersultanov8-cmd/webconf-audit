"""Lighttpd condition evaluation for targeted and worst-case static analysis.

Provides a request context model, variable mapping, and condition evaluator
that determines whether a conditional block potentially matches a given
request context.  When no context is provided, all conditions are treated
as potentially matching (worst-case / static analysis default).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from webconf_audit.local.lighttpd.parser import LighttpdCondition


@dataclass(frozen=True, slots=True)
class LighttpdRequestContext:
    """Describes a hypothetical request for targeted condition evaluation.

    Every field is optional.  ``None`` means "unknown" — the evaluator
    treats unknown fields as potentially matching any value.
    """

    host: str | None = None
    url_path: str | None = None
    remote_ip: str | None = None
    scheme: str | None = None
    server_socket: str | None = None


# ---------------------------------------------------------------------------
# Variable → context field mapping
# ---------------------------------------------------------------------------

# Keys are the *exact* variable strings produced by the Lighttpd parser
# (e.g.  ``$HTTP["host"]``).  Values are attribute names on
# ``LighttpdRequestContext``.
CONDITION_VARIABLE_MAP: dict[str, str] = {
    '$HTTP["host"]': "host",
    '$HTTP["url"]': "url_path",
    '$HTTP["remoteip"]': "remote_ip",
    '$HTTP["scheme"]': "scheme",
    '$SERVER["socket"]': "server_socket",
}


# ---------------------------------------------------------------------------
# Single-condition evaluator
# ---------------------------------------------------------------------------

def evaluate_condition(
    condition: LighttpdCondition,
    context: LighttpdRequestContext,
) -> bool | None:
    """Evaluate *condition* against *context*.

    Returns ``True``/``False`` when the outcome is deterministic, or
    ``None`` when the relevant context field is unknown.
    """
    attr = CONDITION_VARIABLE_MAP.get(condition.variable)
    if attr is None:
        # Unknown variable — cannot decide.
        return None

    ctx_value = getattr(context, attr, None)
    if ctx_value is None:
        return None

    op = condition.operator
    pattern = condition.value

    if op == "==":
        return ctx_value == pattern
    if op == "!=":
        return ctx_value != pattern
    if op == "=~":
        return _regex_match(pattern, ctx_value)
    if op == "!~":
        m = _regex_match(pattern, ctx_value)
        return None if m is None else not m

    # Unrecognised operator — unknown.
    return None


def _regex_match(pattern: str, value: str) -> bool | None:
    """Try a regex match; return ``None`` on invalid pattern."""
    try:
        return re.search(pattern, value) is not None
    except re.error:
        return None


# ---------------------------------------------------------------------------
# Worst-case helper for static analysis
# ---------------------------------------------------------------------------

def is_potentially_matching(
    condition: LighttpdCondition | None,
    context: LighttpdRequestContext | None = None,
) -> bool:
    """Return whether *condition* could match the given *context*.

    * If *context* is ``None``, every condition is potentially matching
      (worst-case static analysis).
    * If *condition* is ``None`` (e.g. an ``else`` block), it is always
      potentially matching because it activates when no prior sibling
      matched.
    * When evaluation is indeterminate (unknown variable / context field),
      the condition is treated as potentially matching.
    """
    if context is None:
        return True
    if condition is None:
        return True

    result = evaluate_condition(condition, context)
    if result is None:
        return True
    return result


__all__ = [
    "CONDITION_VARIABLE_MAP",
    "LighttpdRequestContext",
    "evaluate_condition",
    "is_potentially_matching",
]
