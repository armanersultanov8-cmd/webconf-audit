from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import BlockNode, ConfigAst, iter_nodes
from webconf_audit.local.nginx.rules.header_utils import (
    build_missing_header_finding,
    server_header_contains_value,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.missing_x_frame_options"

# Rule metadata used both in the registry decorator (for ``list-rules``
# / registry introspection) and in the per-finding message emitted by
# ``build_missing_header_finding`` below.  Keeping them in module-level
# constants guarantees the two copies stay in sync — the previous code
# repeated each string literal in both places, which made a harmless
# wording tweak silently produce a finding whose user-visible text
# disagreed with the registry metadata.
_TITLE = "Missing X-Frame-Options header"
_DESCRIPTION = "Server block does not define a valid X-Frame-Options header."
_RECOMMENDATION = (
    "Add 'add_header X-Frame-Options DENY;' or "
    "'add_header X-Frame-Options SAMEORIGIN;' to this server block."
)


@rule(
    rule_id=RULE_ID,
    title=_TITLE,
    severity="low",
    description=_DESCRIPTION,
    recommendation=_RECOMMENDATION,
    category="local",
    server_type="nginx",
    tags=("headers",),
    order=235,
)
def find_missing_x_frame_options(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if isinstance(node, BlockNode) and node.name == "server":
            finding = _find_missing_x_frame_options_in_server(node)
            if finding is not None:
                findings.append(finding)

    return findings


def _find_missing_x_frame_options_in_server(server_block: BlockNode) -> Finding | None:
    has_valid_x_frame_options = (
        server_header_contains_value(server_block, "X-Frame-Options", "DENY")
        or server_header_contains_value(server_block, "X-Frame-Options", "SAMEORIGIN")
    )

    if has_valid_x_frame_options:
        return None

    return build_missing_header_finding(
        server_block,
        rule_id=RULE_ID,
        title=_TITLE,
        description=_DESCRIPTION,
        recommendation=_RECOMMENDATION,
    )


__all__ = ["find_missing_x_frame_options"]
