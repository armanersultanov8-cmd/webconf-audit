from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    find_child_directives,
    iter_nodes,
)
from webconf_audit.local.nginx.rules.tls_listener_utils import listen_uses_tls_on_port_443
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.missing_http2_on_tls_listener"


@rule(
    rule_id=RULE_ID,
    title="TLS listener missing http2 parameter",
    severity="low",
    description=(
        "TLS listen directive exposes port 443 with 'ssl' but does not enable "
        "HTTP/2."
    ),
    recommendation="Add 'http2' to this TLS listen directive when HTTP/2 is intended.",
    category="local",
    server_type="nginx",
    order=218,
)
def find_missing_http2_on_tls_listener(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if isinstance(node, BlockNode) and node.name == "server":
            findings.extend(_find_missing_http2_on_tls_listener_in_server(node))

    return findings


def _find_missing_http2_on_tls_listener_in_server(server_block: BlockNode) -> list[Finding]:
    findings: list[Finding] = []

    if _server_has_http2_enabled(server_block):
        return []

    for directive in find_child_directives(server_block, "listen"):
        if not listen_uses_tls_on_port_443(directive) or "http2" in directive.args:
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="TLS listener missing http2 parameter",
                severity="low",
                description=(
                    "TLS listen directive exposes port 443 with 'ssl' but does not enable "
                    f"'http2': {' '.join(directive.args)!r}."
                ),
                recommendation="Add 'http2' to this TLS listen directive when HTTP/2 is intended.",
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=directive.source.file_path,
                    line=directive.source.line,
                ),
            )
        )

    return findings


def _server_has_http2_enabled(server_block: BlockNode) -> bool:
    return any(
        directive.args and directive.args[0].lower() == "on"
        for directive in find_child_directives(server_block, "http2")
    )


__all__ = ["find_missing_http2_on_tls_listener"]
