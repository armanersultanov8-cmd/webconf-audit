from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst, DirectiveNode, iter_nodes
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.missing_log_format"


@rule(
    rule_id=RULE_ID,
    title="Missing log_format directive",
    severity="low",
    description="Configuration uses 'access_log' but does not define 'log_format'.",
    recommendation="Add a 'log_format' directive when using access logging.",
    category="local",
    server_type="nginx",
    order=225,
)
def find_missing_log_format(config_ast: ConfigAst) -> list[Finding]:
    access_log_directives = [
        node
        for node in iter_nodes(config_ast.nodes)
        if isinstance(node, DirectiveNode)
        and node.name == "access_log"
        and _directive_enables_access_log(node)
    ]

    if not access_log_directives:
        return []

    has_log_format = any(
        isinstance(node, DirectiveNode) and node.name == "log_format"
        for node in iter_nodes(config_ast.nodes)
    )

    if has_log_format:
        return []

    first_access_log = access_log_directives[0]

    return [
        Finding(
            rule_id=RULE_ID,
            title="Missing log_format directive",
            severity="low",
            description="Configuration uses 'access_log' but does not define 'log_format'.",
            recommendation="Add a 'log_format' directive when using access logging.",
            location=SourceLocation(
                mode="local",
                kind="file",
                file_path=first_access_log.source.file_path,
                line=first_access_log.source.line,
            ),
        )
    ]


def _directive_enables_access_log(directive: DirectiveNode) -> bool:
    return bool(directive.args) and directive.args[0] != "off"


__all__ = ["find_missing_log_format"]
