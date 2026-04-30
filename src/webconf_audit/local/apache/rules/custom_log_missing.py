from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst, ApacheDirectiveNode
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.custom_log_missing"


@rule(
    rule_id=RULE_ID,
    title="Missing top-level CustomLog directive",
    severity="low",
    description="Apache config does not define a top-level 'CustomLog' directive.",
    recommendation="Add a top-level 'CustomLog' directive to establish an access logging baseline.",
    category="local",
    server_type="apache",
    order=302,
)
def find_custom_log_missing(config_ast: ApacheConfigAst) -> list[Finding]:
    directive = _find_top_level_custom_log(config_ast)

    if directive is not None:
        return []

    return [
        Finding(
            rule_id=RULE_ID,
            title="Missing top-level CustomLog directive",
            severity="low",
            description="Apache config does not define a top-level 'CustomLog' directive.",
            recommendation="Add a top-level 'CustomLog' directive to establish an access logging baseline.",
            location=_default_location(config_ast),
        )
    ]


def _find_top_level_custom_log(config_ast: ApacheConfigAst) -> ApacheDirectiveNode | None:
    for node in config_ast.nodes:
        if isinstance(node, ApacheDirectiveNode) and node.name.lower() == "customlog":
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


__all__ = ["find_custom_log_missing"]
