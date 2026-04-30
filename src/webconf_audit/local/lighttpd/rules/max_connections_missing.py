from __future__ import annotations

from webconf_audit.local.lighttpd.parser import LighttpdConfigAst
from webconf_audit.local.lighttpd.rules.rule_utils import (
    default_location,
    has_assignment,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "lighttpd.max_connections_missing"


@rule(
    rule_id=RULE_ID,
    title="Maximum connections not configured",
    severity="low",
    description="server.max-connections is not set.",
    recommendation="Set server.max-connections to limit concurrent connections.",
    category="local",
    server_type="lighttpd",
    order=403,
)
def find_max_connections_missing(config_ast: LighttpdConfigAst) -> list[Finding]:
    if has_assignment(config_ast, "server.max-connections"):
        return []

    return [
        Finding(
            rule_id=RULE_ID,
            title="Maximum connections not configured",
            severity="low",
            description="server.max-connections is not set.",
            recommendation="Set server.max-connections to limit concurrent connections.",
            location=default_location(config_ast),
        )
    ]


__all__ = ["find_max_connections_missing"]
