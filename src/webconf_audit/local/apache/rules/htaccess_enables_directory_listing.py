from __future__ import annotations

from webconf_audit.local.apache.htaccess import HtaccessFile
from webconf_audit.local.apache.parser import ApacheDirectiveNode
from webconf_audit.local.apache.rules.htaccess_rule_utils import (
    get_effective_htaccess_ast,
    iter_directives,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.htaccess_enables_directory_listing"


@rule(
    rule_id=RULE_ID,
    title=".htaccess enables directory listing",
    severity="medium",
    description=".htaccess enables directory listing",
    recommendation=(
        "Remove Indexes from .htaccess or explicitly disable directory "
        "listing with 'Options -Indexes'."
    ),
    category="local",
    server_type="apache",
    input_kind="htaccess",
    tags=('htaccess',),
    order=310,
)
def find_htaccess_enables_directory_listing(
    htaccess_files: list[HtaccessFile],
) -> list[Finding]:
    findings: list[Finding] = []

    for htaccess_file in htaccess_files:
        effective_ast = get_effective_htaccess_ast(htaccess_file)
        if effective_ast is None:
            continue

        for directive in iter_directives(effective_ast.nodes):
            if directive.name.lower() != "options":
                continue
            if not _options_enable_indexes(directive):
                continue

            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    title=".htaccess enables directory listing",
                    severity="medium",
                    description=(
                        f"The .htaccess file at {htaccess_file.htaccess_path} enables "
                        "directory listing with an Options directive that includes "
                        "Indexes."
                    ),
                    recommendation=(
                        "Remove Indexes from .htaccess or explicitly disable "
                        "directory listing with 'Options -Indexes'."
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


def _options_enable_indexes(directive: ApacheDirectiveNode) -> bool:
    # Apache processes ``Options`` tokens left-to-right — ``+opt`` / bare
    # ``opt`` enables, ``-opt`` disables, ``None`` clears every option and
    # ``All`` enables every option. Later tokens override earlier ones, so
    # ``Options +Indexes -Indexes`` leaves directory listing disabled;
    # collapsing the arguments into a set would lose that ordering and
    # flag the directive as enabling listings even when the final state
    # is off.
    enabled: bool | None = None
    for raw in directive.args:
        token = raw.lower()
        if token == "none":
            enabled = False
        elif token == "all":
            enabled = True
        elif token in {"indexes", "+indexes"}:
            enabled = True
        elif token == "-indexes":
            enabled = False
    return bool(enabled)


__all__ = ["find_htaccess_enables_directory_listing"]
