from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig, IISEffectiveSection
from webconf_audit.local.iis.parser import IISChildElement, IISConfigDocument, IISSection
from webconf_audit.local.iis.rules.rule_utils import (
    _DANGEROUS_HANDLERS,
    effective_location,
    is_pure_inheritance,
    location_context,
    raw_location,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "iis.cgi_handler_enabled"


@rule(
    rule_id=RULE_ID,
    title="CGI handler mapping enabled",
    severity="medium",
    description="A CGI handler mapping is enabled.",
    recommendation="Remove CGI handler mappings unless required.",
    category="local",
    server_type="iis",
    input_kind="effective",
    order=517,
)
def find_cgi_handler_enabled(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    if effective_config is not None:
        return _effective_findings(effective_config)
    return _raw_findings(doc)


def _effective_findings(effective_config: IISEffectiveConfig) -> list[Finding]:
    findings: list[Finding] = []
    for section in effective_config.all_sections:
        if section.section_path_suffix != "/handlers" or is_pure_inheritance(section):
            continue
        handler_name = _dangerous_handler_name(section.children)
        if handler_name is None:
            continue
        findings.append(_effective_handler_finding(section, handler_name))
    return findings


def _raw_findings(doc: IISConfigDocument) -> list[Finding]:
    findings: list[Finding] = []
    for section in doc.sections:
        if section.tag != "handlers":
            continue
        handler_name = _dangerous_handler_name(section.children)
        if handler_name is None:
            continue
        findings.append(_raw_handler_finding(section, handler_name))
    return findings


def _dangerous_handler_name(children: list[IISChildElement]) -> str | None:
    # By design we emit a single finding per ``<handlers>`` section
    # identifying the *first* dangerous handler we see.  Multiple CGI
    # handlers in the same section are not individually enumerated;
    # surfacing one is enough to flag the section as risky, and a user
    # can see the rest in the source file the finding points at.  This
    # mirrors ``webdav_module_enabled`` (other rules like
    # ``custom_headers_expose_server`` collapse all matches into one
    # message, but that pattern only makes sense when the finding is
    # expected to grow linearly with config size).
    for child in children:
        if child.tag.lower() != "add":
            continue
        if _is_dangerous_handler_module(child.attributes.get("modules", "")):
            return child.attributes.get("name", "unknown")
    return None


def _effective_handler_finding(
    section: IISEffectiveSection,
    handler_name: str,
) -> Finding:
    ctx = location_context(section)
    return Finding(
        rule_id=RULE_ID,
        title="CGI handler mapping enabled",
        severity="medium",
        description=(
            f"A CGI handler mapping is registered{ctx} "
            f"(name: {handler_name}). "
            "CGI execution can introduce command injection risks "
            "and should only be enabled when necessary."
        ),
        recommendation="Remove CGI handler mappings if they are not required, or restrict them to specific paths and extensions.",
        location=effective_location(section),
    )


def _raw_handler_finding(
    section: IISSection,
    handler_name: str,
) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title="CGI handler mapping enabled",
        severity="medium",
        description=(
            f"A CGI handler mapping is registered "
            f"(name: {handler_name}). "
            "CGI execution can introduce command injection risks "
            "and should only be enabled when necessary."
        ),
        recommendation="Remove CGI handler mappings if they are not required, or restrict them to specific paths and extensions.",
        location=raw_location(section),
    )


def _is_dangerous_handler_module(value: str) -> bool:
    return any(
        module.strip().lower() in _DANGEROUS_HANDLERS
        for module in value.split(",")
    )
