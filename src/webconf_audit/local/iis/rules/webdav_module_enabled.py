from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig, IISEffectiveSection
from webconf_audit.local.iis.parser import (
    IISChildElement,
    IISConfigDocument,
    IISSection,
)
from webconf_audit.local.iis.rules.rule_utils import (
    _WEBDAV_MODULES,
    effective_location,
    is_pure_inheritance,
    location_context,
    raw_location,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "iis.webdav_module_enabled"


@rule(
    rule_id=RULE_ID,
    title="WebDAV module enabled",
    severity="medium",
    description="The WebDAV module handler is enabled.",
    recommendation="Remove WebDAV handler unless required.",
    category="local",
    server_type="iis",
    input_kind="effective",
    order=516,
)
def find_webdav_module_enabled(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    if effective_config is not None:
        return _effective_findings(effective_config)
    return _raw_findings(doc)


def _effective_findings(effective_config: IISEffectiveConfig) -> list[Finding]:
    findings: list[Finding] = []
    for section in effective_config.all_sections:
        if section.section_path_suffix != "/modules" or is_pure_inheritance(section):
            continue
        module_name = _webdav_module_name(section.children)
        if module_name is None:
            continue
        findings.append(_effective_module_finding(section, module_name))
    return findings


def _raw_findings(doc: IISConfigDocument) -> list[Finding]:
    findings: list[Finding] = []
    for section in doc.sections:
        if section.tag != "modules":
            continue
        module_name = _webdav_module_name(section.children)
        if module_name is None:
            continue
        findings.append(_raw_module_finding(section, module_name))
    return findings


def _webdav_module_name(children: list[IISChildElement]) -> str | None:
    for child in children:
        if child.tag.lower() != "add":
            continue
        module_name = child.attributes.get("name", "")
        if _is_webdav_module_name(module_name):
            return module_name
    return None


def _effective_module_finding(section: IISEffectiveSection, module_name: str) -> Finding:
    ctx = location_context(section)
    return Finding(
        rule_id=RULE_ID,
        title="WebDAV module enabled",
        severity="medium",
        description=(
            f"The WebDAV module ({module_name}) "
            f"is registered{ctx}. WebDAV exposes additional HTTP "
            "methods (PUT, DELETE, PROPFIND) that can be exploited "
            "if not properly secured."
        ),
        recommendation="Remove the WebDAV module if it is not required, or restrict WebDAV access to authorized users only.",
        location=effective_location(section),
    )


def _raw_module_finding(section: IISSection, module_name: str) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title="WebDAV module enabled",
        severity="medium",
        description=(
            f"The WebDAV module ({module_name}) "
            "is registered. WebDAV exposes additional HTTP "
            "methods (PUT, DELETE, PROPFIND) that can be exploited "
            "if not properly secured."
        ),
        recommendation="Remove the WebDAV module if it is not required, or restrict WebDAV access to authorized users only.",
        location=raw_location(section),
    )


def _is_webdav_module_name(value: str) -> bool:
    name = value.lower()
    return any(token in name for token in _WEBDAV_MODULES)
