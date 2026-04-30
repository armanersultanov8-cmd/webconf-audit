from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig
from webconf_audit.local.iis.parser import IISConfigDocument
from webconf_audit.local.iis.rules.rule_utils import effective_location, is_pure_inheritance, location_context, raw_location
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "iis.request_filtering_allow_high_bit"


@rule(
    rule_id=RULE_ID,
    title="Request filtering allows high-bit characters",
    severity="low",
    description="Request filtering allows high-bit characters in URLs.",
    recommendation="Set allowHighBitCharacters to false unless required.",
    category="local",
    server_type="iis",
    input_kind="effective",
    order=508,
)
def find_request_filtering_allow_high_bit(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    if effective_config is not None:
        for section in effective_config.all_sections:
            if section.section_path_suffix != "/requestFiltering":
                continue
            if is_pure_inheritance(section):
                continue
            if section.attributes.get("allowHighBitCharacters", "").lower() == "true":
                ctx = location_context(section)
                findings.append(Finding(
                    rule_id=RULE_ID, title="Request filtering allows high-bit characters", severity="low",
                    description=(
                        f"IIS request filtering allows high-bit (non-ASCII) characters "
                        f"in URLs{ctx}. This can facilitate homograph attacks and "
                        "may bypass URL-based security filters."
                    ),
                    recommendation='Set requestFiltering allowHighBitCharacters="false" or remove the attribute to restore the default restriction.',
                    location=effective_location(section),
                ))
    else:
        for section in doc.sections:
            if section.tag == "requestFiltering" and section.attributes.get("allowHighBitCharacters", "").lower() == "true":
                findings.append(Finding(
                    rule_id=RULE_ID, title="Request filtering allows high-bit characters", severity="low",
                    description="IIS request filtering allows high-bit (non-ASCII) characters in URLs. This can facilitate homograph attacks and may bypass URL-based security filters.",
                    recommendation='Set requestFiltering allowHighBitCharacters="false" or remove the attribute to restore the default restriction.',
                    location=raw_location(section),
                ))

    return findings
