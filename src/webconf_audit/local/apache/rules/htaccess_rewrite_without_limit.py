from __future__ import annotations

from webconf_audit.local.apache.htaccess import HtaccessFile
from webconf_audit.local.apache.rules.htaccess_rule_utils import (
    get_effective_htaccess_ast,
    iter_directives,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.htaccess_rewrite_without_limit"


@rule(
    rule_id=RULE_ID,
    title=".htaccess uses RewriteRule without RewriteCond",
    severity="low",
    description=(
        "The effective .htaccess config contains RewriteRule directives but "
        "no RewriteCond constraints. This is a heuristic and should be "
        "reviewed for overly broad rewrite behavior."
    ),
    recommendation=(
        "Review the rewrite logic and add explicit RewriteCond constraints "
        "where the rule should only apply to a narrower set of requests."
    ),
    category="local",
    server_type="apache",
    input_kind="htaccess",
    tags=('htaccess',),
    order=312,
)
def find_htaccess_rewrite_without_limit(
    htaccess_files: list[HtaccessFile],
) -> list[Finding]:
    findings: list[Finding] = []

    for htaccess_file in htaccess_files:
        effective_ast = get_effective_htaccess_ast(htaccess_file)
        if effective_ast is None:
            continue

        directives = list(iter_directives(effective_ast.nodes))
        rewrite_rules = [d for d in directives if d.name.lower() == "rewriterule"]
        rewrite_conds = [d for d in directives if d.name.lower() == "rewritecond"]
        if not rewrite_rules or rewrite_conds:
            continue

        first_rule = rewrite_rules[0]
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title=".htaccess uses RewriteRule without RewriteCond",
                severity="low",
                description=(
                    f"The .htaccess file at {htaccess_file.htaccess_path} contains "
                    "RewriteRule directives but no RewriteCond constraints. This is "
                    "a heuristic and should be reviewed for overly broad rewrite "
                    "behavior."
                ),
                recommendation=(
                    "Review the rewrite logic and add explicit RewriteCond "
                    "constraints where the rule should only apply to a narrower "
                    "set of requests."
                ),
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=first_rule.source.file_path or htaccess_file.htaccess_path,
                    line=first_rule.source.line,
                ),
            )
        )

    return findings


__all__ = ["find_htaccess_rewrite_without_limit"]
