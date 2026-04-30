"""universal.weak_tls_protocol

Fires when TLS protocols include TLSv1.0 or TLSv1.1.
Skips silently when protocols are unknown (None).
"""

from __future__ import annotations

from webconf_audit.local.normalized import NormalizedConfig
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "universal.weak_tls_protocol"

_WEAK_PROTOCOLS = frozenset({"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"})


@rule(
    rule_id=RULE_ID,
    title="Weak TLS/SSL protocols enabled",
    severity="medium",
    description="TLS configuration includes weak protocols (TLSv1.0, TLSv1.1, SSLv2, SSLv3).",
    recommendation="Disable TLSv1.0, TLSv1.1, SSLv2, and SSLv3. Use TLSv1.2+ only.",
    category="universal",
    input_kind="normalized",
    tags=("tls",),
    order=101,
)
def check(config: NormalizedConfig) -> list[Finding]:
    findings: list[Finding] = []
    for scope in config.scopes:
        if scope.tls is None or scope.tls.protocols is None:
            continue
        weak = [p for p in scope.tls.protocols if p in _WEAK_PROTOCOLS]
        if weak:
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    title="Weak TLS/SSL protocols enabled",
                    severity="medium",
                    description=(
                        f"Scope '{scope.scope_name or '(unnamed)'}' enables "
                        f"weak protocols: {', '.join(weak)}."
                    ),
                    recommendation="Disable TLSv1.0, TLSv1.1, SSLv2, and SSLv3. Use TLSv1.2+ only.",
                    location=_location(scope, config),
                )
            )
    return findings


def _location(scope, config):
    src = scope.tls.source
    return SourceLocation(
        mode="local",
        kind="xml" if src.xml_path else "file",
        file_path=src.file_path,
        line=src.line,
        xml_path=src.xml_path,
        details=f"server_type={config.server_type}",
    )
