from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig
from webconf_audit.local.iis.parser import IISConfigDocument
from webconf_audit.local.iis.rules.rule_utils import (
    effective_location,
    is_pure_inheritance,
    location_context,
    raw_location,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "iis.custom_errors_off"


@rule(
    rule_id=RULE_ID,
    title="ASP.NET custom errors disabled",
    severity="medium",
    description="ASP.NET custom errors are set to Off.",
    recommendation="Set customErrors mode to RemoteOnly or On.",
    category="local",
    server_type="iis",
    input_kind="effective",
    order=502,
)
def find_custom_errors_off(
    doc: IISConfigDocument,
    *,
    effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    if effective_config is not None:
        for section in effective_config.all_sections:
            if section.section_path_suffix != "/customErrors":
                continue
            if is_pure_inheritance(section):
                continue
            if section.attributes.get("mode", "").lower() == "off":
                ctx = location_context(section)
                findings.append(Finding(
                    rule_id=RULE_ID,
                    title="ASP.NET custom errors disabled",
                    severity="medium",
                    description=(
                        f"ASP.NET custom errors are set to Off{ctx}, which causes detailed "
                        "exception information including stack traces and source code "
                        "snippets to be shown to all clients."
                    ),
                    recommendation=(
                        "Set customErrors mode to RemoteOnly or On to prevent "
                        "detailed error information from reaching remote clients."
                    ),
                    location=effective_location(section),
                ))
    else:
        for section in doc.sections:
            if section.tag == "customErrors" and section.attributes.get("mode", "").lower() == "off":
                findings.append(Finding(
                    rule_id=RULE_ID,
                    title="ASP.NET custom errors disabled",
                    severity="medium",
                    description=(
                        "ASP.NET custom errors are set to Off, which causes detailed "
                        "exception information including stack traces and source code "
                        "snippets to be shown to all clients."
                    ),
                    recommendation=(
                        "Set customErrors mode to RemoteOnly or On to prevent "
                        "detailed error information from reaching remote clients."
                    ),
                    location=raw_location(section),
                ))

    return findings
