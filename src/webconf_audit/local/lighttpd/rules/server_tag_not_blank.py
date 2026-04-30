from __future__ import annotations

from webconf_audit.local.lighttpd.effective import (
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
)
from webconf_audit.local.lighttpd.parser import LighttpdConfigAst
from webconf_audit.local.lighttpd.rules.rule_utils import default_location, iter_all_nodes
from webconf_audit.finding_factory import finding_from_rule
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "lighttpd.server_tag_not_blank"
_DIRECTIVE = "server.tag"


@rule(
    rule_id=RULE_ID,
    title="Server banner not suppressed",
    severity="low",
    description="Lighttpd configuration does not explicitly suppress the Server header banner.",
    recommendation="Set server.tag to an empty string unless exposing a server banner is intentionally required.",
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    tags=('disclosure',),
    order=409,
)
def find_server_tag_not_blank(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
) -> list[Finding]:
    if merged_directives is not None:
        return _find_from_merged(config_ast, merged_directives)
    if effective_config is not None:
        return _find_from_effective(config_ast, effective_config)
    return _find_from_ast(config_ast)


def _find_from_merged(
    config_ast: LighttpdConfigAst,
    merged: dict[str, LighttpdEffectiveDirective],
) -> list[Finding]:
    """Check the merged (host-filtered) directive view."""
    d = merged.get(_DIRECTIVE)
    if d is None:
        return [_make_finding(default_location(config_ast))]
    if not _is_blank(d.value):
        return [_make_finding(SourceLocation(
            mode="local", kind="file",
            file_path=d.source.file_path, line=d.source.line,
        ))]
    return []


def _find_from_effective(
    config_ast: LighttpdConfigAst,
    effective_config: LighttpdEffectiveConfig,
) -> list[Finding]:
    findings: list[Finding] = []

    # Check global effective value (last-wins).
    gd = effective_config.get_global(_DIRECTIVE)
    if gd is None:
        # server.tag not set at all - report as missing.
        findings.append(_make_finding(default_location(config_ast)))
    elif not _is_blank(gd.value):
        findings.append(
            _make_finding(SourceLocation(
                mode="local", kind="file",
                file_path=gd.source.file_path, line=gd.source.line,
            ))
        )

    # Check each conditional scope - a non-blank value there is a separate finding.
    for scope in effective_config.conditional_scopes:
        sd = scope.directives.get(_DIRECTIVE)
        if sd is not None and not _is_blank(sd.value):
            findings.append(
                _make_finding(SourceLocation(
                    mode="local", kind="file",
                    file_path=sd.source.file_path, line=sd.source.line,
                ))
            )

    return findings


def _make_finding(location: SourceLocation | None) -> Finding:
    return finding_from_rule(
        find_server_tag_not_blank,
        location=location,
    )


def _is_blank(value: str) -> bool:
    stripped = value.strip()
    return stripped == '""' or stripped == "''"


# ---------------------------------------------------------------------------
# Legacy fallback when effective config is unavailable
# ---------------------------------------------------------------------------


def _find_from_ast(config_ast: LighttpdConfigAst) -> list[Finding]:
    from webconf_audit.local.lighttpd.parser import LighttpdAssignmentNode

    findings: list[Finding] = []
    found = False

    for node in iter_all_nodes(config_ast):
        if not isinstance(node, LighttpdAssignmentNode):
            continue
        if node.name != _DIRECTIVE:
            continue
        found = True
        if _is_blank(node.value):
            continue
        findings.append(
            _make_finding(SourceLocation(
                mode="local", kind="file",
                file_path=node.source.file_path, line=node.source.line,
            ))
        )

    if found:
        return findings

    return [_make_finding(default_location(config_ast))]


__all__ = ["find_server_tag_not_blank"]
