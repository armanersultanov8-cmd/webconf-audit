from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig
from webconf_audit.local.iis.parser import IISConfigDocument
from webconf_audit.local.iis.rules.rule_utils import effective_location, is_pure_inheritance, location_context, raw_location
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "iis.asp_script_error_sent_to_browser"


@rule(
    rule_id=RULE_ID,
    title="Classic ASP script errors sent to browser",
    severity="medium",
    description="ASP script error messages are sent to the browser.",
    recommendation="Disable scriptErrorSentToBrowser.",
    category="local",
    server_type="iis",
    input_kind="effective",
    order=503,
)
def find_asp_script_error_sent_to_browser(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    if effective_config is not None:
        for section in effective_config.all_sections:
            if section.section_path_suffix != "/asp":
                continue
            if is_pure_inheritance(section):
                continue
            if section.attributes.get("scriptErrorSentToBrowser", "").lower() == "true":
                ctx = location_context(section)
                findings.append(Finding(
                    rule_id=RULE_ID, title="Classic ASP script errors sent to browser", severity="medium",
                    description=(
                        f"Classic ASP is configured to send script error details "
                        f"to the browser{ctx}. This can expose internal paths, line numbers, "
                        "and error descriptions to remote users."
                    ),
                    recommendation="Set asp scriptErrorSentToBrowser to false to prevent script error details from reaching clients.",
                    location=effective_location(section),
                ))
    else:
        for section in doc.sections:
            if section.tag == "asp" and section.attributes.get("scriptErrorSentToBrowser", "").lower() == "true":
                findings.append(Finding(
                    rule_id=RULE_ID, title="Classic ASP script errors sent to browser", severity="medium",
                    description="Classic ASP is configured to send script error details to the browser. This can expose internal paths, line numbers, and error descriptions to remote users.",
                    recommendation="Set asp scriptErrorSentToBrowser to false to prevent script error details from reaching clients.",
                    location=raw_location(section),
                ))

    return findings
