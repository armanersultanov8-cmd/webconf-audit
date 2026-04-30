from __future__ import annotations

from webconf_audit.local.lighttpd.parser import LighttpdConfigAst
from webconf_audit.local.lighttpd.rules.rule_utils import (
    collect_modules,
    default_location,
    has_assignment,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "lighttpd.access_log_missing"


@rule(
    rule_id=RULE_ID,
    title="Access log file not configured",
    severity="low",
    description="mod_accesslog is loaded but accesslog.filename is not set.",
    recommendation="Set accesslog.filename to a file path to capture access logs.",
    category="local",
    server_type="lighttpd",
    order=400,
)
def find_access_log_missing(config_ast: LighttpdConfigAst) -> list[Finding]:
    modules = collect_modules(config_ast)

    if "mod_accesslog" not in modules:
        return []

    if has_assignment(config_ast, "accesslog.filename"):
        return []

    return [
        Finding(
            rule_id=RULE_ID,
            title="Access log file not configured",
            severity="low",
            description=(
                "mod_accesslog is loaded but accesslog.filename is not set."
            ),
            recommendation="Set accesslog.filename to a file path to capture access logs.",
            location=default_location(config_ast),
        )
    ]


__all__ = ["find_access_log_missing"]
