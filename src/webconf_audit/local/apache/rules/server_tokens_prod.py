from __future__ import annotations

from webconf_audit.local.apache.effective import (
    ApacheVirtualHostContext,
    build_server_effective_config,
    extract_virtualhost_contexts,
)
from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.server_tokens_not_prod"


@rule(
    rule_id=RULE_ID,
    title="ServerTokens not set to Prod",
    severity="low",
    description="Apache config does not define an effective 'ServerTokens Prod' directive.",
    recommendation="Add 'ServerTokens Prod' in the effective Apache scope.",
    category="local",
    server_type="apache",
    tags=("disclosure",),
    order=325,
)
def find_server_tokens_prod(config_ast: ApacheConfigAst) -> list[Finding]:
    virtualhosts = extract_virtualhost_contexts(config_ast)
    if virtualhosts:
        return [
            finding
            for context in virtualhosts
            for finding in _evaluate_virtualhost(config_ast, context)
        ]

    directive = build_server_effective_config(config_ast).directives.get("servertokens")
    if directive is None:
        return [
            Finding(
                rule_id=RULE_ID,
                title="ServerTokens not set to Prod",
                severity="low",
                description=(
                    "Apache config does not define an effective 'ServerTokens Prod' "
                    "directive."
                ),
                recommendation="Add 'ServerTokens Prod' in the Apache config.",
                location=_default_location(config_ast),
            )
        ]

    if len(directive.args) == 1 and directive.args[0].lower() == "prod":
        return []

    configured_value = " ".join(directive.args) if directive.args else "<missing value>"
    return [
        Finding(
            rule_id=RULE_ID,
            title="ServerTokens not set to Prod",
            severity="low",
            description=(
                "Apache config sets effective 'ServerTokens' to "
                f"'{configured_value}' instead of 'Prod'."
            ),
            recommendation="Set the effective directive to 'ServerTokens Prod'.",
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
    ).directives.get("servertokens")

    if directive is not None and len(directive.args) == 1 and directive.args[0].lower() == "prod":
        return []

    if directive is not None:
        configured_value = " ".join(directive.args) if directive.args else "<missing value>"
        description = _configured_virtualhost_description(
            context,
            origin_layer=directive.origin.layer,
            configured_value=configured_value,
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
            "'ServerTokens Prod' directive."
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
            title="ServerTokens not set to Prod",
            severity="low",
            description=description,
            recommendation=(
                "Set the effective directive to 'ServerTokens Prod' in the global "
                "or VirtualHost scope."
            ),
            location=location,
        )
    ]


def _configured_virtualhost_description(
    context: ApacheVirtualHostContext,
    *,
    origin_layer: str,
    configured_value: str,
) -> str:
    label = _virtualhost_label(context)
    if origin_layer.startswith("virtualhost:"):
        return (
            f"VirtualHost '{label}' sets effective 'ServerTokens' to "
            f"'{configured_value}' instead of 'Prod'."
        )
    return (
        f"VirtualHost '{label}' inherits effective 'ServerTokens' value "
        f"'{configured_value}' from {origin_layer} scope instead of 'Prod'."
    )


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


__all__ = ["find_server_tokens_prod"]
