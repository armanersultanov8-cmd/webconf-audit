from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig
from webconf_audit.local.iis.parser import IISConfigDocument
from webconf_audit.local.iis.rules.rule_utils import _EXPOSE_SERVER_HEADERS, effective_location, is_pure_inheritance, location_context, raw_location
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "iis.custom_headers_expose_server"


@rule(
    rule_id=RULE_ID,
    title="Server-revealing custom headers present",
    severity="low",
    description="Custom response headers reveal server technology.",
    recommendation="Remove or anonymize server-revealing headers.",
    category="local",
    server_type="iis",
    tags=("disclosure",),
    input_kind="effective",
    order=518,
)
def find_custom_headers_expose_server(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    if effective_config is not None:
        for section in effective_config.all_sections:
            if section.section_path_suffix != "/customHeaders":
                continue
            if is_pure_inheritance(section):
                continue
            _check_expose(section.children, location_context(section), effective_location(section), findings)
    else:
        for section in doc.sections:
            if section.tag != "customHeaders":
                continue
            _check_expose(section.children, "", raw_location(section), findings)

    return findings


def _check_expose(children, ctx, location, findings):
    added: set[str] = set()
    removed: set[str] = set()
    for child in children:
        name = child.attributes.get("name", "").lower()
        if name in _EXPOSE_SERVER_HEADERS:
            if child.tag.lower() == "add":
                added.add(name)
            elif child.tag.lower() == "remove":
                removed.add(name)
    exposed = added - removed
    if exposed:
        exposed_display = ", ".join(sorted(
            child.attributes.get("name", "")
            for child in children
            if child.tag.lower() == "add"
            and child.attributes.get("name", "").lower() in exposed
        ))
        findings.append(Finding(
            rule_id=RULE_ID,
            title="Server-revealing custom headers present",
            severity="low",
            description=(
                f"The following headers disclose server technology{ctx}: "
                f"{exposed_display}. These headers aid attacker fingerprinting."
            ),
            recommendation=(
                "Remove server-revealing headers by adding <remove> directives "
                'for each one (e.g. <remove name="X-Powered-By" />, '
                '<remove name="X-AspNetMvc-Version" />).'
            ),
            location=location,
        ))
