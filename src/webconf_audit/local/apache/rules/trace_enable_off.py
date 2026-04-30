from __future__ import annotations

from webconf_audit.local.apache.effective import (
    ApacheVirtualHostContext,
    build_server_effective_config,
    extract_virtualhost_contexts,
)
from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.trace_enable_not_off"


@rule(
    rule_id=RULE_ID,
    title="TraceEnable not set to Off",
    severity="low",
    description="Apache config does not define an effective 'TraceEnable Off' directive.",
    recommendation="Add 'TraceEnable Off' in the effective Apache scope.",
    category="local",
    server_type="apache",
    order=326,
)
def find_trace_enable_off(config_ast: ApacheConfigAst) -> list[Finding]:
    virtualhosts = extract_virtualhost_contexts(config_ast)
    if virtualhosts:
        return [
            finding
            for context in virtualhosts
            for finding in _evaluate_virtualhost(config_ast, context)
        ]

    directive = build_server_effective_config(config_ast).directives.get("traceenable")
    if directive is None:
        return [
            Finding(
                rule_id=RULE_ID,
                title="TraceEnable not set to Off",
                severity="low",
                description=(
                    "Apache config does not define an effective 'TraceEnable Off' "
                    "directive."
                ),
                recommendation="Add 'TraceEnable Off' in the Apache config.",
                location=_default_location(config_ast),
            )
        ]

    if len(directive.args) == 1 and directive.args[0].lower() == "off":
        return []

    configured_value = " ".join(directive.args) if directive.args else "<missing value>"
    return [
        Finding(
            rule_id=RULE_ID,
            title="TraceEnable not set to Off",
            severity="low",
            description=(
                "Apache config sets effective 'TraceEnable' to "
                f"'{configured_value}' instead of 'Off'."
            ),
            recommendation="Set the effective directive to 'TraceEnable Off'.",
            location=SourceLocation(
                mode="local",
                kind="file",
                file_path=directive.origin.source.file_path,
                line=directive.origin.source.line,
            ),
        )
    ]


def _evaluate_virtualhost(
    config_ast: ApacheConfigAst,
    context: ApacheVirtualHostContext,
) -> list[Finding]:
    directive = build_server_effective_config(
        config_ast,
        virtualhost_context=context,
    ).directives.get("traceenable")

    if directive is not None and len(directive.args) == 1 and directive.args[0].lower() == "off":
        return []

    if directive is not None:
        configured_value = " ".join(directive.args) if directive.args else "<missing value>"
        description = (
            f"VirtualHost '{_virtualhost_label(context)}' sets effective "
            f"'TraceEnable' to '{configured_value}' instead of 'Off'."
        )
        location = SourceLocation(
            mode="local",
            kind="file",
            file_path=directive.origin.source.file_path,
            line=directive.origin.source.line,
        )
    else:
        description = (
            f"VirtualHost '{_virtualhost_label(context)}' does not have an effective "
            "'TraceEnable Off' directive."
        )
        location = SourceLocation(
            mode="local",
            kind="file",
            file_path=context.node.source.file_path,
            line=context.node.source.line,
        )

    return [
        Finding(
            rule_id=RULE_ID,
            title="TraceEnable not set to Off",
            severity="low",
            description=description,
            recommendation="Set the effective VirtualHost directive to 'TraceEnable Off'.",
            location=location,
        )
    ]


def _virtualhost_label(context: ApacheVirtualHostContext) -> str:
    return context.server_name or context.listen_address or "<unnamed>"


def _default_location(config_ast: ApacheConfigAst) -> SourceLocation | None:
    if not config_ast.nodes:
        return None

    source = config_ast.nodes[0].source
    return SourceLocation(
        mode="local",
        kind="file",
        file_path=source.file_path,
        line=source.line,
    )


__all__ = ["find_trace_enable_off"]
