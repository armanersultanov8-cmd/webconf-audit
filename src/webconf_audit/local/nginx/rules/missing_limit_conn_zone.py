from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst, DirectiveNode, iter_nodes
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.missing_limit_conn_zone"


@rule(
    rule_id=RULE_ID,
    title="Missing or undefined limit_conn_zone",
    severity="low",
    description=(
        "Configuration uses 'limit_conn' without a matching 'limit_conn_zone', "
        "or references an undefined zone."
    ),
    recommendation=(
        "Add a matching 'limit_conn_zone' directive or correct the referenced "
        "zone name."
    ),
    category="local",
    server_type="nginx",
    order=222,
)
def find_missing_limit_conn_zone(config_ast: ConfigAst) -> list[Finding]:
    limit_conn_directives = [
        node
        for node in iter_nodes(config_ast.nodes)
        if isinstance(node, DirectiveNode) and node.name == "limit_conn"
    ]

    if not limit_conn_directives:
        return []

    defined_zones = _defined_limit_conn_zones(config_ast)
    missing_zone_directives = [
        directive
        for directive in limit_conn_directives
        if not directive.args or directive.args[0] not in defined_zones
    ]

    if not missing_zone_directives:
        return []

    first_limit_conn = missing_zone_directives[0]

    return [
        Finding(
            rule_id=RULE_ID,
            title="Missing or undefined limit_conn_zone",
            severity="low",
            description=(
                "Configuration uses 'limit_conn' without a matching "
                "'limit_conn_zone', or references an undefined zone."
            ),
            recommendation=(
                "Add a matching 'limit_conn_zone' directive or correct the "
                "referenced zone name."
            ),
            location=SourceLocation(
                mode="local",
                kind="file",
                file_path=first_limit_conn.source.file_path,
                line=first_limit_conn.source.line,
            ),
        )
    ]


def _defined_limit_conn_zones(config_ast: ConfigAst) -> set[str]:
    zones: set[str] = set()
    for node in iter_nodes(config_ast.nodes):
        if not isinstance(node, DirectiveNode) or node.name != "limit_conn_zone":
            continue
        for arg in node.args:
            if not arg.startswith("zone="):
                continue
            zone = arg.removeprefix("zone=").split(":", 1)[0]
            if zone:
                zones.add(zone)
    return zones


__all__ = ["find_missing_limit_conn_zone"]
