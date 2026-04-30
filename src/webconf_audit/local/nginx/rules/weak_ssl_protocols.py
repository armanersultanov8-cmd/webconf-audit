from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst, DirectiveNode, iter_nodes
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.weak_ssl_protocols"
WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1"}


@rule(
    rule_id=RULE_ID,
    title="Weak SSL/TLS protocols enabled",
    severity="medium",
    description="Nginx explicitly enables weak SSL/TLS protocols via ssl_protocols.",
    recommendation="Remove TLSv1 and TLSv1.1 from the ssl_protocols directive.",
    category="local",
    server_type="nginx",
    order=240,
)
def find_weak_ssl_protocols(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if isinstance(node, DirectiveNode) and node.name == "ssl_protocols":
            weak_protocols = [protocol for protocol in node.args if protocol in WEAK_PROTOCOLS]

            if weak_protocols:
                findings.append(
                    Finding(
                        rule_id=RULE_ID,
                        title="Weak SSL/TLS protocols enabled",
                        severity="medium",
                        description=(
                            "Nginx explicitly enables weak SSL/TLS protocols via "
                            f"'ssl_protocols {' '.join(node.args)};'."
                        ),
                        recommendation="Remove TLSv1 and TLSv1.1 from the ssl_protocols directive.",
                        location=SourceLocation(
                            mode="local",
                            kind="file",
                            file_path=node.source.file_path,
                            line=node.source.line,
                        ),
                    )
                )

    return findings


__all__ = ["find_weak_ssl_protocols"]
