from __future__ import annotations

from webconf_audit.local.lighttpd.effective import (
    LighttpdConditionalScope,
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
    scope_conditions,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "lighttpd.ssl_engine_not_enabled"


@rule(
    rule_id=RULE_ID,
    title="SSL engine not enabled for HTTPS port",
    severity="medium",
    description="Lighttpd is configured to listen on port 443 but ssl.engine is not enabled.",
    recommendation="Set ssl.engine = 'enable' to activate TLS for HTTPS listeners.",
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    tags=('tls',),
    order=410,
)
def find_ssl_engine_not_enabled(
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

    global_port = effective_config.get_global("server.port")
    if _is_port_443(global_port) and not _global_ssl_engine_enabled(effective_config):
        findings.append(_make_finding(_source_location(global_port)))

    for scope in effective_config.conditional_scopes:
        port = scope.directives.get("server.port")
        if not _is_port_443(port):
            continue
        ssl_engine = effective_directive_for_scope(effective_config, scope, "ssl.engine")
        if _is_enabled(ssl_engine):
            continue
        findings.append(_make_finding(_source_location(port)))

    return findings


def _find_from_merged(
    merged_directives: dict[str, LighttpdEffectiveDirective],
) -> list[Finding]:
    port = merged_directives.get("server.port")
    if not _is_port_443(port):
        return []

    ssl_engine = merged_directives.get("ssl.engine")
    if _is_enabled(ssl_engine):
        return []

    return [_make_finding(_source_location(port))]


def _find_from_ast(config_ast: LighttpdConfigAst) -> list[Finding]:
    # Walk the AST while tracking the chain of enclosing blocks so a
    # ``ssl.engine = "enable"`` buried in one conditional scope does not
    # silently suppress the finding for a ``server.port = 443`` declared
    # in a different scope.  Pair each port-443 assignment with an
    # ``ssl.engine`` declared either at the global scope (an empty chain)
    # or along that specific port's own scope chain — otherwise emit the
    # finding for that listener.
    ssl_engine_scopes: list[tuple[int, ...]] = []
    port_findings: list[tuple[tuple[int, ...], SourceLocation]] = []

    def visit(
        nodes: list[object],
        scope_chain: tuple[int, ...],
    ) -> None:
        for node in nodes:
            if isinstance(node, LighttpdBlockNode):
                visit(node.children, (*scope_chain, id(node)))
                continue
            if not isinstance(node, LighttpdAssignmentNode):
                continue
            if node.name == "ssl.engine" and normalize_value(node.value) == "enable":
                ssl_engine_scopes.append(scope_chain)
            elif node.name == "server.port" and normalize_value(node.value) == "443":
                port_findings.append((
                    scope_chain,
                    SourceLocation(
                        mode="local",
                        kind="file",
                        file_path=node.source.file_path,
                        line=node.source.line,
                    ),
                ))

    visit(config_ast.nodes, ())

    findings: list[Finding] = []
    for port_scope, location in port_findings:
        if _port_scope_is_tls_enabled(port_scope, ssl_engine_scopes):
            continue
        findings.append(_make_finding(location))
    return findings


def _port_scope_is_tls_enabled(
    port_scope: tuple[int, ...],
    ssl_engine_scopes: list[tuple[int, ...]],
) -> bool:
    # An ``ssl.engine = "enable"`` covers a port-443 declaration when it
    # sits at global scope (``()``) or on a prefix of that port's own
    # scope chain — i.e. the same conditional block or one of its
    # ancestors.  A sibling conditional does not count.
    for engine_scope in ssl_engine_scopes:
        if len(engine_scope) > len(port_scope):
            continue
        if port_scope[: len(engine_scope)] == engine_scope:
            return True
    return False


def _global_ssl_engine_enabled(effective_config: LighttpdEffectiveConfig) -> bool:
    global_ssl_engine = effective_config.get_global("ssl.engine")
    if _is_enabled(global_ssl_engine):
        return True

    for scope in effective_config.conditional_scopes:
        if not _scope_targets_https_socket(scope):
            continue
        ssl_engine = effective_directive_for_scope(effective_config, scope, "ssl.engine")
        if _is_enabled(ssl_engine):
            return True

    return False


def _scope_targets_https_socket(scope: LighttpdConditionalScope) -> bool:
    return any(
        condition is not None
        and condition.variable == '$SERVER["socket"]'
        and (condition.value == "443" or condition.value.endswith(":443"))
        for condition in scope_conditions(scope)
    )


def _is_port_443(directive: LighttpdEffectiveDirective | None) -> bool:
    return directive is not None and normalize_value(directive.value) == "443"


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
        find_ssl_engine_not_enabled,
        location=location,
    )


__all__ = ["find_ssl_engine_not_enabled"]
