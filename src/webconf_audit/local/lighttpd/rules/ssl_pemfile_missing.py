from __future__ import annotations

from webconf_audit.local.lighttpd.parser import (
    LighttpdAssignmentNode,
    LighttpdConfigAst,
)
from webconf_audit.local.lighttpd.rules.rule_utils import (
    default_location,
    iter_all_nodes,
    normalize_value,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "lighttpd.ssl_pemfile_missing"


@rule(
    rule_id=RULE_ID,
    title="SSL certificate file not configured",
    severity="high",
    description="SSL is enabled but ssl.pemfile is not set.",
    recommendation="Set ssl.pemfile to the path of the PEM certificate file.",
    category="local",
    server_type="lighttpd",
    tags=('tls',),
    order=412,
)
def find_ssl_pemfile_missing(config_ast: LighttpdConfigAst) -> list[Finding]:
    has_ssl_engine = False
    ssl_engine_source: SourceLocation | None = None
    has_pemfile = False

    for node in iter_all_nodes(config_ast):
        if not isinstance(node, LighttpdAssignmentNode):
            continue
        if node.name == "ssl.engine" and normalize_value(node.value) == "enable":
            has_ssl_engine = True
            ssl_engine_source = SourceLocation(
                mode="local", kind="file",
                file_path=node.source.file_path, line=node.source.line,
            )
        if node.name == "ssl.pemfile" and normalize_value(node.value):
            has_pemfile = True

    if not has_ssl_engine or has_pemfile:
        return []

    return [
        Finding(
            rule_id=RULE_ID,
            title="SSL certificate file not configured",
            severity="high",
            description="SSL is enabled but ssl.pemfile is not set.",
            recommendation="Set ssl.pemfile to the path of the PEM certificate file.",
            location=ssl_engine_source or default_location(config_ast),
        )
    ]


__all__ = ["find_ssl_pemfile_missing"]
