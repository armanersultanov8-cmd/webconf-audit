from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig
from webconf_audit.local.iis.parser import IISConfigDocument
from webconf_audit.local.iis.rules.rule_utils import effective_location, is_pure_inheritance, location_context, raw_location
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "iis.http_runtime_version_header_enabled"


@rule(
    rule_id=RULE_ID,
    title="ASP.NET version header enabled",
    severity="low",
    description="The ASP.NET version header is enabled.",
    recommendation="Set enableVersionHeader to false.",
    category="local",
    server_type="iis",
    tags=("disclosure",),
    input_kind="effective",
    order=506,
)
def find_http_runtime_version_header_enabled(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    if effective_config is not None:
        for section in effective_config.all_sections:
            if section.section_path_suffix != "/httpRuntime":
                continue
            if is_pure_inheritance(section):
                continue
            if section.attributes.get("enableVersionHeader", "").lower() == "true":
                ctx = location_context(section)
                findings.append(Finding(
                    rule_id=RULE_ID, title="ASP.NET version header enabled", severity="low",
                    description=(
                        f"The ASP.NET version header (X-AspNet-Version) is explicitly "
                        f"enabled{ctx}. This discloses the ASP.NET framework version to "
                        "external clients and aids fingerprinting."
                    ),
                    recommendation='Set httpRuntime enableVersionHeader="false" to suppress the X-AspNet-Version response header.',
                    location=effective_location(section),
                ))
    else:
        for section in doc.sections:
            if section.tag == "httpRuntime" and section.attributes.get("enableVersionHeader", "").lower() == "true":
                findings.append(Finding(
                    rule_id=RULE_ID, title="ASP.NET version header enabled", severity="low",
                    description="The ASP.NET version header (X-AspNet-Version) is explicitly enabled. This discloses the ASP.NET framework version to external clients and aids fingerprinting.",
                    recommendation='Set httpRuntime enableVersionHeader="false" to suppress the X-AspNet-Version response header.',
                    location=raw_location(section),
                ))

    return findings
