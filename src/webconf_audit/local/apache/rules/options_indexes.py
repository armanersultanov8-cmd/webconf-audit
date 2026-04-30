"""Rule: apache.options_indexes — directory indexing enabled.

Uses the effective-config layer so that VirtualHost overrides and
Directory inheritance are correctly resolved.
"""

from __future__ import annotations

from webconf_audit.local.apache.effective import EffectiveDirective
from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules.effective_directive_check import (
    check_effective_directive_token,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.local.apache.rules.scope_phrase import scope_phrase

RULE_ID = "apache.options_indexes"


@rule(
    rule_id=RULE_ID,
    title="Directory indexing enabled",
    severity="medium",
    description=(
        "Apache 'Options' directive enables 'Indexes', which allows "
        "directory listing for that effective scope."
    ),
    recommendation=(
        "Remove 'Indexes' from the Options directive or set 'Options -Indexes' "
        "if directory listing is unnecessary."
    ),
    category="local",
    server_type="apache",
    order=320,
)
def find_options_indexes(config_ast: ApacheConfigAst) -> list[Finding]:
    return check_effective_directive_token(
        config_ast,
        directive_name="options",
        positive_tokens=frozenset({"indexes", "+indexes"}),
        disabled_value="-indexes",
        build_finding=_build_finding,
    )


def _build_finding(directive: EffectiveDirective, context_name: str) -> Finding:
    scope_text = scope_phrase(context_name)
    return Finding(
        rule_id=RULE_ID,
        title="Directory indexing enabled",
        severity="medium",
        description=(
            f"Apache 'Options' directive enables 'Indexes' {scope_text}, "
            "which allows directory listing for that effective scope."
        ),
        recommendation=(
            "Remove 'Indexes' from the Options directive or set 'Options -Indexes' "
            "if directory listing is unnecessary."
        ),
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=directive.origin.source.file_path,
            line=directive.origin.source.line,
        ),
    )



__all__ = ["find_options_indexes"]
