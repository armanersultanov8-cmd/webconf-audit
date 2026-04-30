from __future__ import annotations

from webconf_audit.local.apache.htaccess import HtaccessFile
from webconf_audit.local.apache.rules.htaccess_rule_utils import (
    get_effective_htaccess_ast,
    iter_directives,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.htaccess_disables_security_headers"
_SECURITY_HEADERS = frozenset(
    {
        "content-security-policy",
        "permissions-policy",
        "referrer-policy",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
    }
)


@rule(
    rule_id=RULE_ID,
    title=".htaccess unsets security header",
    severity="medium",
    description="A .htaccess file removes a security-relevant response header.",
    recommendation="Keep security headers in the main Apache config and avoid unsetting them in .htaccess.",
    category="local",
    server_type="apache",
    input_kind="htaccess",
    tags=("htaccess", "headers"),
    order=308,
)
def find_htaccess_disables_security_headers(
    htaccess_files: list[HtaccessFile],
) -> list[Finding]:
    findings: list[Finding] = []

    for htaccess_file in htaccess_files:
        effective_ast = get_effective_htaccess_ast(htaccess_file)
        if effective_ast is None:
            continue

        for directive in iter_directives(effective_ast.nodes):
            if directive.name.lower() != "header":
                continue

            header_name = _extract_unset_security_header(directive.args)
            if header_name is None:
                continue

            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    title=f".htaccess unsets security header '{header_name}'",
                    severity="medium",
                    description=(
                        f"The .htaccess file at {htaccess_file.htaccess_path} removes "
                        f"the security-relevant response header '{header_name}'."
                    ),
                    recommendation=(
                        "Keep security headers in the main Apache config and avoid "
                        "unsetting them in .htaccess unless this is explicitly "
                        "required and reviewed."
                    ),
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path=directive.source.file_path or htaccess_file.htaccess_path,
                        line=directive.source.line,
                    ),
                )
            )

    return findings


def _extract_unset_security_header(args: list[str]) -> str | None:
    if len(args) < 2:
        return None

    action_index = 0
    header_index = 1
    if args[0].lower() in {"always", "onsuccess"}:
        if len(args) < 3:
            return None
        action_index = 1
        header_index = 2

    if args[action_index].lower() != "unset":
        return None

    header_name = args[header_index]
    if header_name.lower() not in _SECURITY_HEADERS:
        return None
    return header_name


__all__ = ["find_htaccess_disables_security_headers"]
