from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules.error_document_utils import (
    default_location,
    find_top_level_error_document,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.error_document_404_missing"


@rule(
    rule_id=RULE_ID,
    title="ErrorDocument 404 not configured safely",
    severity="low",
    description=(
        "Apache config does not define a top-level 'ErrorDocument 404' "
        "directive with a custom target."
    ),
    recommendation="Add a top-level 'ErrorDocument 404' directive with a target path or URL.",
    category="local",
    server_type="apache",
    order=304,
)
def find_error_document_404_missing(config_ast: ApacheConfigAst) -> list[Finding]:
    directive = find_top_level_error_document(config_ast, "404")

    if directive is None:
        return [
            Finding(
                rule_id=RULE_ID,
                title="ErrorDocument 404 not configured safely",
                severity="low",
                description=(
                    "Apache config does not define a top-level 'ErrorDocument 404' directive "
                    "with a custom target."
                ),
                recommendation=(
                    "Add a top-level 'ErrorDocument 404' directive with a target path or URL."
                ),
                location=default_location(config_ast),
            )
        ]

    if len(directive.args) >= 2:
        return []

    return [
        Finding(
            rule_id=RULE_ID,
            title="ErrorDocument 404 not configured safely",
            severity="low",
            description=(
                "Apache config defines top-level 'ErrorDocument 404' without a target after "
                "the status code."
            ),
            recommendation=(
                "Set top-level 'ErrorDocument 404' with a target path or URL after the "
                "status code."
            ),
            location=SourceLocation(
                mode="local",
                kind="file",
                file_path=directive.source.file_path,
                line=directive.source.line,
            ),
        )
    ]


__all__ = ["find_error_document_404_missing"]
