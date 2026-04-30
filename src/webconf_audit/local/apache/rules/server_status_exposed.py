from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules.location_endpoint_utils import (
    effective_location_has_require_ip,
    find_effective_location_evaluations,
    virtualhost_label,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.server_status_exposed"
TARGET_PATH = "/server-status"


@rule(
    rule_id=RULE_ID,
    title="server-status endpoint exposed",
    severity="low",
    description=(
        "Effective Location block for '/server-status' does not define a "
        "direct or inherited 'Require ip ...' restriction."
    ),
    recommendation=(
        "Add an effective 'Require ip ...' restriction for the '/server-status' "
        "Location."
    ),
    category="local",
    server_type="apache",
    tags=("disclosure",),
    order=324,
)
def find_server_status_exposed(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for evaluation in find_effective_location_evaluations(config_ast, TARGET_PATH):
        if effective_location_has_require_ip(evaluation.effective_config):
            continue

        description = (
            "Effective Location block for '/server-status' does not define a direct or "
            "inherited 'Require ip ...' restriction."
        )
        if evaluation.virtualhost_context is not None:
            description = (
                f"VirtualHost '{virtualhost_label(evaluation.virtualhost_context)}' leaves "
                "the effective '/server-status' Location without a 'Require ip ...' "
                "restriction."
            )

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="server-status endpoint exposed",
                severity="low",
                description=description,
                recommendation=(
                    "Add an effective 'Require ip ...' restriction for the "
                    "'/server-status' Location."
                ),
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=evaluation.scope.source.file_path,
                    line=evaluation.scope.source.line,
                ),
            )
        )

    return findings


__all__ = ["find_server_status_exposed"]
