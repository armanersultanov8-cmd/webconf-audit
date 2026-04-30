from __future__ import annotations

from webconf_audit.local.lighttpd.parser import (
    LighttpdAssignmentNode,
    LighttpdConfigAst,
)
from webconf_audit.local.lighttpd.rules.rule_utils import (
    collect_modules,
    default_location,
    iter_all_nodes,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "lighttpd.mod_cgi_enabled"


@rule(
    rule_id=RULE_ID,
    title="CGI module loaded",
    severity="low",
    description="mod_cgi is loaded in server.modules.",
    recommendation="Disable mod_cgi unless CGI execution is intentionally required.",
    category="local",
    server_type="lighttpd",
    order=407,
)
def find_mod_cgi_enabled(config_ast: LighttpdConfigAst) -> list[Finding]:
    modules = collect_modules(config_ast)

    if "mod_cgi" not in modules:
        return []

    last_modules_assignment: LighttpdAssignmentNode | None = None

    # Point to the assignment that loads mod_cgi.
    for node in iter_all_nodes(config_ast):
        if isinstance(node, LighttpdAssignmentNode) and node.name == "server.modules":
            last_modules_assignment = node
            if "mod_cgi" in node.value:
                return [
                    Finding(
                        rule_id=RULE_ID,
                        title="CGI module loaded",
                        severity="low",
                        description="mod_cgi is loaded in server.modules.",
                        recommendation=(
                            "Disable mod_cgi unless CGI execution is intentionally required."
                        ),
                        location=SourceLocation(
                            mode="local", kind="file",
                            file_path=node.source.file_path, line=node.source.line,
                        ),
                    )
                ]

    location = (
        SourceLocation(
            mode="local",
            kind="file",
            file_path=last_modules_assignment.source.file_path,
            line=last_modules_assignment.source.line,
        )
        if last_modules_assignment is not None
        else default_location(config_ast)
    )

    return [
        Finding(
            rule_id=RULE_ID,
            title="CGI module loaded",
            severity="low",
            description="mod_cgi is loaded in server.modules.",
            recommendation="Disable mod_cgi unless CGI execution is intentionally required.",
            location=location,
        )
    ]


__all__ = ["find_mod_cgi_enabled"]
