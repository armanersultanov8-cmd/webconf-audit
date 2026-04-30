from __future__ import annotations

from webconf_audit.local.lighttpd.parser import LighttpdConfigAst
from webconf_audit.local.lighttpd.rules.rule_utils import (
    default_location,
    has_assignment,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "lighttpd.max_request_size_missing"


@rule(
    rule_id=RULE_ID,
    title="Maximum request size not configured",
    severity="low",
    description="server.max-request-size is not set.",
    recommendation="Set server.max-request-size to limit the maximum allowed request body size.",
    category="local",
    server_type="lighttpd",
    order=404,
)
def find_max_request_size_missing(config_ast: LighttpdConfigAst) -> list[Finding]:
    if has_assignment(config_ast, "server.max-request-size"):
        return []

    return [
        Finding(
            rule_id=RULE_ID,
            title="Maximum request size not configured",
            severity="low",
            description="server.max-request-size is not set.",
            recommendation="Set server.max-request-size to limit the maximum allowed request body size.",
            location=default_location(config_ast),
        )
    ]


__all__ = ["find_max_request_size_missing"]
