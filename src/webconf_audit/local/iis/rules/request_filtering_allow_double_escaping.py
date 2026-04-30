from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig
from webconf_audit.local.iis.parser import IISConfigDocument
from webconf_audit.local.iis.rules.rule_utils import effective_location, is_pure_inheritance, location_context, raw_location
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "iis.request_filtering_allow_double_escaping"


@rule(
    rule_id=RULE_ID,
    title="Request filtering allows double escaping",
    severity="medium",
    description="Request filtering allows double-encoded URLs.",
    recommendation="Set allowDoubleEscaping to false.",
    category="local",
    server_type="iis",
    input_kind="effective",
    order=507,
)
def find_request_filtering_allow_double_escaping(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    if effective_config is not None:
        for section in effective_config.all_sections:
            if section.section_path_suffix != "/requestFiltering":
                continue
            if is_pure_inheritance(section):
                continue
            if section.attributes.get("allowDoubleEscaping", "").lower() == "true":
                ctx = location_context(section)
                findings.append(Finding(
                    rule_id=RULE_ID, title="Request filtering allows double escaping", severity="medium",
                    description=(
                        f"IIS request filtering allows double-escaped characters{ctx}. "
                        "This can be exploited to bypass URL-based "
                        "security restrictions and access restricted resources."
                    ),
                    recommendation='Set requestFiltering allowDoubleEscaping="false" or remove the attribute to restore the default restriction.',
                    location=effective_location(section),
                ))
    else:
        for section in doc.sections:
            if section.tag == "requestFiltering" and section.attributes.get("allowDoubleEscaping", "").lower() == "true":
                findings.append(Finding(
                    rule_id=RULE_ID, title="Request filtering allows double escaping", severity="medium",
                    description="IIS request filtering is configured to allow double-escaped characters in URLs. This can be exploited to bypass URL-based security restrictions and access restricted resources.",
                    recommendation='Set requestFiltering allowDoubleEscaping="false" or remove the attribute to restore the default restriction.',
                    location=raw_location(section),
                ))

    return findings
