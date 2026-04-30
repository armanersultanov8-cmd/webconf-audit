from __future__ import annotations

from webconf_audit.local.lighttpd.effective import (
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
)
from webconf_audit.local.lighttpd.parser import (
    LighttpdAssignmentNode,
    LighttpdBlockNode,
    LighttpdConfigAst,
)
from webconf_audit.finding_factory import finding_from_rule
from webconf_audit.local.lighttpd.rules.rule_utils import (
    effective_directive_for_scope,
    normalize_value,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "lighttpd.ssl_honor_cipher_order_missing"


@rule(
    rule_id=RULE_ID,
    title="SSL cipher order not enforced",
    severity="medium",
    description="SSL is enabled but ssl.honor-cipher-order is not set to enforce server cipher preference.",
    recommendation="Set ssl.honor-cipher-order = 'enable' to enforce server-preferred cipher order.",
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    tags=('tls',),
    order=411,
)
def find_ssl_honor_cipher_order_missing(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
) -> list[Finding]:
    if effective_config is not None:
        return _find_from_effective(effective_config)

    if merged_directives is not None:
        return _find_from_merged(merged_directives)

    return _find_from_ast(config_ast)


def _find_from_effective(
    effective_config: LighttpdEffectiveConfig,
) -> list[Finding]:
    findings: list[Finding] = []

    global_ssl_engine = effective_config.get_global("ssl.engine")
    if _is_enabled(global_ssl_engine):
        honor = effective_config.get_global("ssl.honor-cipher-order")
        if not _is_enabled(honor):
            findings.append(_make_finding(_source_location(global_ssl_engine)))

    for scope in effective_config.conditional_scopes:
        ssl_engine = scope.directives.get("ssl.engine")
        if not _is_enabled(ssl_engine):
            continue
        honor = effective_directive_for_scope(effective_config, scope, "ssl.honor-cipher-order")
        if _is_enabled(honor):
            continue
        findings.append(_make_finding(_source_location(ssl_engine)))

    return findings


def _find_from_merged(
    merged_directives: dict[str, LighttpdEffectiveDirective],
) -> list[Finding]:
    ssl_engine = merged_directives.get("ssl.engine")
    if not _is_enabled(ssl_engine):
        return []

    honor = merged_directives.get("ssl.honor-cipher-order")
    if _is_enabled(honor):
        return []

    return [_make_finding(_source_location(ssl_engine))]


def _find_from_ast(config_ast: LighttpdConfigAst) -> list[Finding]:
    honor_scopes: list[tuple[int, ...]] = []
    ssl_engine_locations: list[tuple[tuple[int, ...], SourceLocation]] = []

    def visit(nodes: list[object], scope_chain: tuple[int, ...]) -> None:
        for node in nodes:
            if isinstance(node, LighttpdBlockNode):
                visit(node.children, (*scope_chain, id(node)))
                continue
            if not isinstance(node, LighttpdAssignmentNode):
                continue
            if normalize_value(node.value) != "enable":
                continue
            if node.name == "ssl.honor-cipher-order":
                honor_scopes.append(scope_chain)
                continue
            if node.name == "ssl.engine":
                ssl_engine_locations.append((scope_chain, _assignment_source(node)))

    visit(config_ast.nodes, ())

    findings = [
        _make_finding(location)
        for scope_chain, location in ssl_engine_locations
        if not _directive_enabled_for_scope(scope_chain, honor_scopes)
    ]
    if findings:
        return findings
    return []
def _assignment_source(node: LighttpdAssignmentNode) -> SourceLocation:
    return SourceLocation(
        mode="local",
        kind="file",
        file_path=node.source.file_path,
        line=node.source.line,
    )


def _directive_enabled_for_scope(
    scope_chain: tuple[int, ...],
    enabled_scopes: list[tuple[int, ...]],
) -> bool:
    for enabled_scope in enabled_scopes:
        if len(enabled_scope) > len(scope_chain):
            continue
        if scope_chain[: len(enabled_scope)] == enabled_scope:
            return True
    return False


def _is_enabled(directive: LighttpdEffectiveDirective | None) -> bool:
    return directive is not None and normalize_value(directive.value) == "enable"


def _source_location(directive: LighttpdEffectiveDirective) -> SourceLocation:
    return SourceLocation(
        mode="local",
        kind="file",
        file_path=directive.source.file_path,
        line=directive.source.line,
    )


def _make_finding(location: SourceLocation | None) -> Finding:
    return finding_from_rule(
        find_ssl_honor_cipher_order_missing,
        location=location,
    )


__all__ = ["find_ssl_honor_cipher_order_missing"]
