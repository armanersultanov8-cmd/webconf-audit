from __future__ import annotations

from webconf_audit.local.lighttpd.effective import (
    LighttpdConditionalScope,
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
)
from webconf_audit.finding_factory import finding_from_rule
from webconf_audit.local.lighttpd.parser import (
    LighttpdAssignmentNode,
    LighttpdConfigAst,
)
from webconf_audit.local.lighttpd.rules.rule_utils import (
    default_location,
    iter_all_nodes,
    unquote,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "lighttpd.missing_x_content_type_options"

_HEADER_NAME = "x-content-type-options"


@rule(
    rule_id=RULE_ID,
    title="X-Content-Type-Options header missing",
    severity="medium",
    description="No X-Content-Type-Options header is configured via setenv.add-response-header.",
    recommendation="Add X-Content-Type-Options: nosniff to setenv.add-response-header.",
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    tags=('headers',),
    order=406,
)
def find_missing_x_content_type_options(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
) -> list[Finding]:
    if merged_directives is not None:
        return [] if _has_header_in_directives(merged_directives) else [_make_finding(config_ast)]

    if effective_config is not None:
        return [] if _has_header_in_effective(effective_config) else [_make_finding(config_ast)]

    return _find_from_ast(config_ast)


def _has_header_in_effective(effective_config: LighttpdEffectiveConfig) -> bool:
    if _has_header_in_directives(effective_config.global_directives):
        return True

    for scope in effective_config.conditional_scopes:
        if _scope_has_header(scope):
            return True

    return False


def _scope_has_header(scope: LighttpdConditionalScope) -> bool:
    return _has_header_in_directives(scope.directives)


def _has_header_in_directives(
    directives: dict[str, LighttpdEffectiveDirective],
) -> bool:
    directive = directives.get("setenv.add-response-header")
    if directive is None:
        return False
    return _HEADER_NAME in unquote(directive.value).lower()


def _find_from_ast(config_ast: LighttpdConfigAst) -> list[Finding]:
    for node in iter_all_nodes(config_ast):
        if not isinstance(node, LighttpdAssignmentNode):
            continue
        if node.name != "setenv.add-response-header":
            continue
        if _HEADER_NAME in unquote(node.value).lower():
            return []

    return [_make_finding(config_ast)]


def _make_finding(config_ast: LighttpdConfigAst) -> Finding:
    return finding_from_rule(
        find_missing_x_content_type_options,
        location=default_location(config_ast),
    )


__all__ = ["find_missing_x_content_type_options"]
