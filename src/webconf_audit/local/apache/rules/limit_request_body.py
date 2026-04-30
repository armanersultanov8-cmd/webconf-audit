from __future__ import annotations

from webconf_audit.local.apache.effective import (
    ApacheVirtualHostContext,
    build_server_effective_config,
    extract_virtualhost_contexts,
)
from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.limit_request_body_missing_or_invalid"


@rule(
    rule_id=RULE_ID,
    title="LimitRequestBody not configured safely",
    severity="low",
    description="Apache config does not define an effective LimitRequestBody baseline.",
    recommendation="Add a positive integer LimitRequestBody directive in the effective scope.",
    category="local",
    server_type="apache",
    order=316,
)
def find_limit_request_body(config_ast: ApacheConfigAst) -> list[Finding]:
    virtualhosts = extract_virtualhost_contexts(config_ast)
    if virtualhosts:
        return [
            finding
            for context in virtualhosts
            for finding in _evaluate_virtualhost(config_ast, context)
        ]

    directive = build_server_effective_config(config_ast).directives.get("limitrequestbody")
    if directive is None:
        return [
            Finding(
                rule_id=RULE_ID,
                title="LimitRequestBody not configured safely",
                severity="low",
                description=(
                    "Apache config does not define an effective 'LimitRequestBody' baseline."
                ),
                recommendation="Add a positive integer 'LimitRequestBody' directive.",
                location=_default_location(config_ast),
            )
        ]

    if _is_valid_limit_value(directive.args):
        return []

    configured_value = " ".join(directive.args) if directive.args else "<missing value>"
    return [
        Finding(
            rule_id=RULE_ID,
            title="LimitRequestBody not configured safely",
            severity="low",
            description=(
                "Apache config sets effective 'LimitRequestBody' to "
                f"'{configured_value}', which is not a valid positive integer baseline."
            ),
            recommendation="Set effective 'LimitRequestBody' to a positive integer value.",
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
    ).directives.get("limitrequestbody")

    if directive is not None and _is_valid_limit_value(directive.args):
        return []

    if directive is not None:
        configured_value = " ".join(directive.args) if directive.args else "<missing value>"
        description = (
            f"VirtualHost '{_virtualhost_label(context)}' sets effective "
            f"'LimitRequestBody' to '{configured_value}', which is not a valid positive "
            "integer baseline."
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
            "'LimitRequestBody' baseline."
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
            title="LimitRequestBody not configured safely",
            severity="low",
            description=description,
            recommendation="Set the effective VirtualHost LimitRequestBody to a positive integer.",
            location=location,
        )
    ]


def _is_valid_limit_value(args: list[str]) -> bool:
    if len(args) != 1:
        return False

    try:
        return int(args[0]) > 0
    except ValueError:
        return False


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


__all__ = ["find_limit_request_body"]
