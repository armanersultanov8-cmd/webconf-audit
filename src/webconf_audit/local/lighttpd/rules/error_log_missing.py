from __future__ import annotations

from webconf_audit.local.lighttpd.parser import LighttpdConfigAst
from webconf_audit.local.lighttpd.rules.rule_utils import (
    default_location,
    has_assignment,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "lighttpd.error_log_missing"


@rule(
    rule_id=RULE_ID,
    title="Error log not configured",
    severity="medium",
    description="server.errorlog is not configured.",
    recommendation="Set server.errorlog to a file path to capture error output.",
    category="local",
    server_type="lighttpd",
    order=402,
)
def find_error_log_missing(config_ast: LighttpdConfigAst) -> list[Finding]:
    if has_assignment(config_ast, "server.errorlog"):
        return []

    return [
        Finding(
            rule_id=RULE_ID,
            title="Error log not configured",
            severity="medium",
            description="server.errorlog is not configured.",
            recommendation="Set server.errorlog to a file path to capture error output.",
            location=default_location(config_ast),
        )
    ]


__all__ = ["find_error_log_missing"]
