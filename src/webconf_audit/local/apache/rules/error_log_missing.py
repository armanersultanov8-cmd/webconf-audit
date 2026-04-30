from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst, ApacheDirectiveNode
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.error_log_missing"


@rule(
    rule_id=RULE_ID,
    title="Missing top-level ErrorLog directive",
    severity="low",
    description="Apache config does not define a top-level 'ErrorLog' directive.",
    recommendation="Add a top-level 'ErrorLog' directive to establish an error logging baseline.",
    category="local",
    server_type="apache",
    order=306,
)
def find_error_log_missing(config_ast: ApacheConfigAst) -> list[Finding]:
    directive = _find_top_level_error_log(config_ast)

    if directive is not None:
        return []

    return [
        Finding(
            rule_id=RULE_ID,
            title="Missing top-level ErrorLog directive",
            severity="low",
            description="Apache config does not define a top-level 'ErrorLog' directive.",
            recommendation="Add a top-level 'ErrorLog' directive to establish an error logging baseline.",
            location=_default_location(config_ast),
        )
    ]


def _find_top_level_error_log(config_ast: ApacheConfigAst) -> ApacheDirectiveNode | None:
    for node in config_ast.nodes:
        if isinstance(node, ApacheDirectiveNode) and node.name.lower() == "errorlog":
            return node

    return None


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


__all__ = ["find_error_log_missing"]
