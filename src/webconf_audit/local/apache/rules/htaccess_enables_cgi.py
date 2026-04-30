from __future__ import annotations

from webconf_audit.local.apache.htaccess import HtaccessFile
from webconf_audit.local.apache.parser import ApacheDirectiveNode
from webconf_audit.local.apache.rules.htaccess_rule_utils import (
    get_effective_htaccess_ast,
    iter_directives,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.htaccess_enables_cgi"


@rule(
    rule_id=RULE_ID,
    title=".htaccess enables ExecCGI",
    severity="medium",
    description=".htaccess enables ExecCGI",
    recommendation=(
        "Remove ExecCGI from .htaccess or move the setting into the main "
        "config with tighter review and scope control."
    ),
    category="local",
    server_type="apache",
    input_kind="htaccess",
    tags=('htaccess',),
    order=309,
)
def find_htaccess_enables_cgi(htaccess_files: list[HtaccessFile]) -> list[Finding]:
    findings: list[Finding] = []

    for htaccess_file in htaccess_files:
        effective_ast = get_effective_htaccess_ast(htaccess_file)
        if effective_ast is None:
            continue

        for directive in iter_directives(effective_ast.nodes):
            if directive.name.lower() != "options":
                continue
            if not _options_enable_execcgi(directive):
                continue

            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    title=".htaccess enables ExecCGI",
                    severity="medium",
                    description=(
                        f"The .htaccess file at {htaccess_file.htaccess_path} enables "
                        "ExecCGI via an Options directive, allowing CGI script "
                        "execution in that directory scope."
                    ),
                    recommendation=(
                        "Remove ExecCGI from .htaccess or move the setting into the "
                        "main config with tighter review and scope control."
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


def _options_enable_execcgi(directive: ApacheDirectiveNode) -> bool:
    # Apache processes ``Options`` tokens left-to-right — ``+opt`` / bare
    # ``opt`` enables, ``-opt`` disables, ``None`` clears every option and
    # ``All`` enables every option. Later tokens override earlier ones, so
    # ``Options +ExecCGI -ExecCGI`` leaves ExecCGI disabled; collapsing
    # the arguments into a set would lose that ordering and flag the
    # directive as enabling CGI even when the final state is off.
    enabled: bool | None = None
    for raw in directive.args:
        token = raw.lower()
        if token == "none":
            enabled = False
        elif token == "all":
            enabled = True
        elif token in {"execcgi", "+execcgi"}:
            enabled = True
        elif token == "-execcgi":
            enabled = False
    return bool(enabled)


__all__ = ["find_htaccess_enables_cgi"]
