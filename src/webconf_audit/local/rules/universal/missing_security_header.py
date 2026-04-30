"""Universal rules for missing security headers.

Covers:
- universal.missing_x_content_type_options
- universal.missing_x_frame_options
- universal.missing_content_security_policy
- universal.missing_referrer_policy
"""

from __future__ import annotations

from webconf_audit.local.normalized import NormalizedConfig, NormalizedScope
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

HeaderRule = tuple[str, str, str, str | None]

_HEADER_RULES: dict[str, HeaderRule] = {
    "universal.missing_x_content_type_options": (
        "x-content-type-options",
        "X-Content-Type-Options header missing or incorrect",
        "Add 'X-Content-Type-Options: nosniff' to prevent MIME-type sniffing.",
        "nosniff",
    ),
    "universal.missing_x_frame_options": (
        "x-frame-options",
        "X-Frame-Options header missing",
        "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking.",
        None,
    ),
    "universal.missing_content_security_policy": (
        "content-security-policy",
        "Content-Security-Policy header missing",
        "Add a Content-Security-Policy header to mitigate XSS and injection attacks.",
        None,
    ),
    "universal.missing_referrer_policy": (
        "referrer-policy",
        "Referrer-Policy header missing",
        "Add a Referrer-Policy header (e.g. 'strict-origin-when-cross-origin').",
        None,
    ),
}


@rule(
    rule_id="universal.missing_x_content_type_options",
    title="X-Content-Type-Options header missing or incorrect",
    severity="low",
    description="Scope does not set the X-Content-Type-Options response header with value 'nosniff'.",
    recommendation="Add 'X-Content-Type-Options: nosniff' to prevent MIME-type sniffing.",
    category="universal",
    input_kind="normalized",
    tags=("headers",),
    order=104,
)
def check_x_content_type_options(config: NormalizedConfig) -> list[Finding]:
    rule_id = "universal.missing_x_content_type_options"
    return _check_header(config, rule_id, *_HEADER_RULES[rule_id])


@rule(
    rule_id="universal.missing_x_frame_options",
    title="X-Frame-Options header missing",
    severity="low",
    description="Scope does not set the X-Frame-Options response header.",
    recommendation="Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking.",
    category="universal",
    input_kind="normalized",
    tags=("headers",),
    order=105,
)
def check_x_frame_options(config: NormalizedConfig) -> list[Finding]:
    rule_id = "universal.missing_x_frame_options"
    return _check_header(config, rule_id, *_HEADER_RULES[rule_id])


@rule(
    rule_id="universal.missing_content_security_policy",
    title="Content-Security-Policy header missing",
    severity="low",
    description="Scope does not set the Content-Security-Policy response header.",
    recommendation="Add a Content-Security-Policy header to mitigate XSS and injection attacks.",
    category="universal",
    input_kind="normalized",
    tags=("headers",),
    order=106,
)
def check_content_security_policy(config: NormalizedConfig) -> list[Finding]:
    rule_id = "universal.missing_content_security_policy"
    return _check_header(config, rule_id, *_HEADER_RULES[rule_id])


@rule(
    rule_id="universal.missing_referrer_policy",
    title="Referrer-Policy header missing",
    severity="low",
    description="Scope does not set the Referrer-Policy response header.",
    recommendation="Add a Referrer-Policy header (e.g. 'strict-origin-when-cross-origin').",
    category="universal",
    input_kind="normalized",
    tags=("headers",),
    order=107,
)
def check_referrer_policy(config: NormalizedConfig) -> list[Finding]:
    rule_id = "universal.missing_referrer_policy"
    return _check_header(config, rule_id, *_HEADER_RULES[rule_id])


def _check_header(
    config: NormalizedConfig,
    rule_id: str,
    header_name: str,
    title: str,
    recommendation: str,
    required_value: str | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for scope in config.scopes:
        if not _scope_is_auditable(scope):
            continue
        if _has_header(scope, header_name, required_value):
            continue
        findings.append(
            Finding(
                rule_id=rule_id,
                title=title,
                severity="low",
                description=(
                    f"Scope '{scope.scope_name or '(unnamed)'}' does not set "
                    f"the {header_name} response header"
                    + (f" with value '{required_value}'" if required_value else "")
                    + "."
                ),
                recommendation=recommendation,
                location=_scope_location(scope, config),
                metadata={
                    "scope_name": scope.scope_name,
                    "server_type": config.server_type,
                },
            )
        )
    return findings


def _scope_is_auditable(scope: NormalizedScope) -> bool:
    """Decide whether a scope should be checked for missing headers.

    A scope is auditable when it has security headers (even if it's missing
    some) or listen points — these indicate an active web-serving context.
    """
    return bool(scope.security_headers or scope.listen_points)


def _has_header(
    scope: NormalizedScope,
    name: str,
    required_value: str | None = None,
) -> bool:
    for h in scope.security_headers:
        if h.name != name:
            continue
        if required_value is None:
            return True
        # Value check: case-insensitive, strip quotes.
        if h.value and h.value.strip().strip('"').strip("'").lower() == required_value.lower():
            return True
    return False


def _scope_location(
    scope: NormalizedScope,
    config: NormalizedConfig,
) -> SourceLocation:
    if scope.listen_points:
        src = scope.listen_points[0].source
    elif scope.tls:
        src = scope.tls.source
    elif scope.access_policy:
        src = scope.access_policy.source
    elif scope.security_headers:
        src = scope.security_headers[0].source
    else:
        return SourceLocation(
            mode="local",
            kind="check",
            target=scope.scope_name or config.server_type,
            details=f"server_type={config.server_type}",
        )
    return SourceLocation(
        mode="local",
        kind="xml" if src.xml_path else "file",
        file_path=src.file_path,
        line=src.line,
        xml_path=src.xml_path,
        details=f"server_type={config.server_type}",
    )
