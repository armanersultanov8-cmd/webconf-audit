"""universal.server_identification_disclosed

Fires when server name and/or version information is sent to clients.

The mapping is heterogeneous by design:
- Nginx: ``server_tokens on``
- Apache: ``ServerTokens`` not Prod, or ``ServerSignature On``
- Lighttpd: non-empty ``server.tag``
- IIS: ``enableVersionHeader="true"``
"""

from __future__ import annotations

from webconf_audit.local.normalized import NormalizedConfig
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "universal.server_identification_disclosed"


@rule(
    rule_id=RULE_ID,
    title="Server identification disclosed",
    severity="low",
    description="Server name and/or version information is sent to clients.",
    recommendation="Suppress server identification to reduce information leakage. The exact directive varies by server type.",
    category="universal",
    input_kind="normalized",
    tags=("disclosure",),
    order=109,
)
def check(config: NormalizedConfig) -> list[Finding]:
    findings: list[Finding] = []
    for scope in config.scopes:
        if scope.access_policy is None:
            continue
        if scope.access_policy.server_identification_disclosed is not True:
            continue
        src = scope.access_policy.source
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="Server identification disclosed",
                severity="low",
                description=(
                    f"Scope '{scope.scope_name or '(unnamed)'}' discloses server "
                    "name and/or version information to clients."
                ),
                recommendation=(
                    "Suppress server identification to reduce information leakage. "
                    "The exact directive varies by server type."
                ),
                location=SourceLocation(
                    mode="local",
                    kind="xml" if src.xml_path else "file",
                    file_path=src.file_path,
                    line=src.line,
                    xml_path=src.xml_path,
                    details=f"server_type={config.server_type}",
                ),
            )
        )
    return findings
