from __future__ import annotations

from webconf_audit.local.apache.htaccess import HtaccessFile
from webconf_audit.local.apache.rules.htaccess_rule_utils import (
    get_effective_htaccess_ast,
    iter_directives,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.htaccess_auth_without_require"
_AUTH_DIRECTIVES = frozenset(
    {
        "authname",
        "authtype",
        "authuserfile",
        "authgroupfile",
        "authbasicprovider",
        "authdigestprovider",
    }
)


@rule(
    rule_id=RULE_ID,
    title=".htaccess configures auth without Require",
    severity="medium",
    description=(
        "The effective .htaccess config defines authentication-related "
        "directives but no Require directive. That can leave the access "
        "policy incomplete or misleading."
    ),
    recommendation=(
        "Add an explicit Require directive that matches the intended "
        "authentication policy, or move the auth configuration into the "
        "main Apache config."
    ),
    category="local",
    server_type="apache",
    input_kind="htaccess",
    tags=('htaccess',),
    order=307,
)
def find_htaccess_auth_without_require(
    htaccess_files: list[HtaccessFile],
) -> list[Finding]:
    findings: list[Finding] = []

    for htaccess_file in htaccess_files:
        effective_ast = get_effective_htaccess_ast(htaccess_file)
        if effective_ast is None:
            continue

        directives = list(iter_directives(effective_ast.nodes))
        auth_directives = [d for d in directives if d.name.lower() in _AUTH_DIRECTIVES]
        has_require = any(d.name.lower() == "require" for d in directives)
        if not auth_directives or has_require:
            continue

        first_auth = auth_directives[0]
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title=".htaccess configures auth without Require",
                severity="medium",
                description=(
                    f"The .htaccess file at {htaccess_file.htaccess_path} defines "
                    "authentication-related directives but no Require directive. "
                    "That can leave the access policy incomplete or misleading."
                ),
                recommendation=(
                    "Add an explicit Require directive that matches the intended "
                    "authentication policy, or move the auth configuration into the "
                    "main Apache config."
                ),
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=first_auth.source.file_path or htaccess_file.htaccess_path,
                    line=first_auth.source.line,
                ),
            )
        )

    return findings


__all__ = ["find_htaccess_auth_without_require"]
