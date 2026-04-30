"""Rule: apache.index_options_scanhtmltitles_enabled — ScanHTMLTitles via IndexOptions.

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

RULE_ID = "apache.index_options_scanhtmltitles_enabled"


@rule(
    rule_id=RULE_ID,
    title="ScanHTMLTitles enabled via IndexOptions",
    severity="low",
    description=(
        "Apache 'IndexOptions' directive enables 'ScanHTMLTitles', which "
        "allows directory listings to scan HTML files for title data."
    ),
    recommendation=(
        "Remove 'ScanHTMLTitles' from the 'IndexOptions' directive or set "
        "'IndexOptions -ScanHTMLTitles' if title scanning for directory "
        "listings is not required."
    ),
    category="local",
    server_type="apache",
    order=315,
)
def find_index_options_scanhtmltitles_enabled(config_ast: ApacheConfigAst) -> list[Finding]:
    return check_effective_directive_token(
        config_ast,
        directive_name="indexoptions",
        positive_tokens=frozenset({"scanhtmltitles", "+scanhtmltitles"}),
        disabled_value="-scanhtmltitles",
        build_finding=_build_finding,
    )


def _build_finding(directive: EffectiveDirective, context_name: str) -> Finding:
    scope_text = scope_phrase(context_name)
    return Finding(
        rule_id=RULE_ID,
        title="ScanHTMLTitles enabled via IndexOptions",
        severity="low",
        description=(
            f"Apache 'IndexOptions' directive enables 'ScanHTMLTitles' {scope_text}, "
            "which allows directory listings to scan HTML files for title data."
        ),
        recommendation=(
            "Remove 'ScanHTMLTitles' from the 'IndexOptions' directive or set "
            "'IndexOptions -ScanHTMLTitles' if title scanning for directory listings "
            "is not required."
        ),
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=directive.origin.source.file_path,
            line=directive.origin.source.line,
        ),
    )



__all__ = ["find_index_options_scanhtmltitles_enabled"]
