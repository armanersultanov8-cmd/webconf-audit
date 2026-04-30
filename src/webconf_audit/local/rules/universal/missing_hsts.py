"""universal.missing_hsts

Fires when a TLS-enabled scope lacks a Strict-Transport-Security header.
"""

from __future__ import annotations

from webconf_audit.local.normalized import NormalizedConfig, NormalizedScope
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "universal.missing_hsts"


@rule(
    rule_id=RULE_ID,
    title="Strict-Transport-Security header missing on TLS scope",
    severity="medium",
    description="A TLS-enabled scope does not set the Strict-Transport-Security header.",
    recommendation="Add a Strict-Transport-Security header with an appropriate max-age.",
    category="universal",
    input_kind="normalized",
    tags=("headers", "tls"),
    order=103,
)
def check(config: NormalizedConfig) -> list[Finding]:
    findings: list[Finding] = []
    for scope in config.scopes:
        if not _scope_has_tls(scope):
            continue
        if _has_hsts(scope):
            continue
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="Strict-Transport-Security header missing on TLS scope",
                severity="medium",
                description=(
                    f"Scope '{scope.scope_name or '(unnamed)'}' serves HTTPS "
                    "but does not set the Strict-Transport-Security header."
                ),
                recommendation="Add a Strict-Transport-Security header with an appropriate max-age.",
                location=_scope_location(scope, config),
            )
        )
    return findings


def _scope_has_tls(scope: NormalizedScope) -> bool:
    """Return True only when there is positive evidence the scope serves HTTPS.

    A listen point with ``tls=True`` is strong evidence.
    A ``NormalizedTLS`` with ``require_ssl=True`` is also positive.
    A bare metadata-only TLS object (e.g. IIS with ``require_ssl=False``)
    is NOT sufficient — it would cause false positives.
    """
    if any(lp.tls for lp in scope.listen_points):
        return True
    if scope.tls is not None and scope.tls.require_ssl is True:
        return True
    return False


def _has_hsts(scope: NormalizedScope) -> bool:
    return any(
        h.name == "strict-transport-security" for h in scope.security_headers
    )


def _scope_location(scope, config):
    src = scope.tls.source if scope.tls else (
        scope.listen_points[0].source if scope.listen_points else None
    )
    if src is None:
        return None
    return SourceLocation(
        mode="local",
        kind="xml" if src.xml_path else "file",
        file_path=src.file_path,
        line=src.line,
        xml_path=src.xml_path,
        details=f"server_type={config.server_type}",
    )
