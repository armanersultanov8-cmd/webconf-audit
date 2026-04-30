from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    find_child_directives,
    iter_nodes,
)
from webconf_audit.local.nginx.rules.tls_listener_utils import server_uses_tls
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.missing_ssl_certificate_key"


@rule(
    rule_id=RULE_ID,
    title="Missing ssl_certificate_key directive",
    severity="low",
    description=(
        "Server block uses TLS and defines 'ssl_certificate' but not "
        "'ssl_certificate_key'."
    ),
    recommendation="Add an 'ssl_certificate_key' directive to this server block.",
    category="local",
    server_type="nginx",
    order=231,
)
def find_missing_ssl_certificate_key(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if isinstance(node, BlockNode) and node.name == "server":
            finding = _find_missing_ssl_certificate_key_in_server(node)
            if finding is not None:
                findings.append(finding)

    return findings


def _find_missing_ssl_certificate_key_in_server(server_block: BlockNode) -> Finding | None:
    ssl_certificate_directives = find_child_directives(server_block, "ssl_certificate")
    ssl_certificate_key_directives = find_child_directives(server_block, "ssl_certificate_key")

    uses_tls = server_uses_tls(server_block)

    if not uses_tls or not ssl_certificate_directives or ssl_certificate_key_directives:
        return None

    return Finding(
        rule_id=RULE_ID,
        title="Missing ssl_certificate_key directive",
        severity="low",
        description=(
            "Server block uses TLS and defines 'ssl_certificate' but not "
            "'ssl_certificate_key'."
        ),
        recommendation="Add an 'ssl_certificate_key' directive to this server block.",
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=server_block.source.file_path,
            line=server_block.source.line,
        ),
    )


__all__ = ["find_missing_ssl_certificate_key"]
