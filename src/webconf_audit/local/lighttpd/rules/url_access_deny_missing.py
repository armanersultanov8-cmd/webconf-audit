from __future__ import annotations

from webconf_audit.local.lighttpd.parser import (
    LighttpdAssignmentNode,
    LighttpdConfigAst,
)
from webconf_audit.local.lighttpd.rules.rule_utils import (
    default_location,
    iter_all_nodes,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "lighttpd.url_access_deny_missing"


@rule(
    rule_id=RULE_ID,
    title="No file extension access restrictions",
    severity="medium",
    description=(
        "url.access-deny is not configured to block dangerous file extensions "
        "such as .inc, .bak, .sql, .conf, and .log."
    ),
    recommendation=(
        'Set url.access-deny = ( ".inc", ".bak", ".sql", ".log", ".conf" ) '
        "to prevent access to sensitive file types."
    ),
    category="local",
    server_type="lighttpd",
    order=413,
)
def find_url_access_deny_missing(config_ast: LighttpdConfigAst) -> list[Finding]:
    for node in iter_all_nodes(config_ast):
        if not isinstance(node, LighttpdAssignmentNode):
            continue
        if node.name == "url.access-deny":
            return []

    return [
        Finding(
            rule_id=RULE_ID,
            title="No file extension access restrictions",
            severity="medium",
            description=(
                "url.access-deny is not configured to block dangerous file extensions "
                "such as .inc, .bak, .sql, .conf, and .log."
            ),
            recommendation=(
                'Set url.access-deny = ( ".inc", ".bak", ".sql", ".log", ".conf" ) '
                "to prevent access to sensitive file types."
            ),
            location=default_location(config_ast),
        )
    ]


__all__ = ["find_url_access_deny_missing"]
