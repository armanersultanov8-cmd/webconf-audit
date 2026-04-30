from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig
from webconf_audit.local.iis.parser import IISConfigDocument
from webconf_audit.local.iis.rules.rule_utils import effective_location, is_pure_inheritance, location_context, raw_location
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "iis.compilation_debug_enabled"


@rule(
    rule_id=RULE_ID,
    title="ASP.NET compilation debug mode enabled",
    severity="medium",
    description="ASP.NET compilation debug mode is enabled.",
    recommendation="Set compilation debug to false.",
    category="local",
    server_type="iis",
    input_kind="effective",
    order=504,
)
def find_compilation_debug_enabled(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    if effective_config is not None:
        for section in effective_config.all_sections:
            if section.section_path_suffix != "/compilation":
                continue
            if is_pure_inheritance(section):
                continue
            if _is_true(section.attributes.get("debug")):
                ctx = location_context(section)
                findings.append(Finding(
                    rule_id=RULE_ID, title="ASP.NET compilation debug mode enabled", severity="medium",
                    description=(
                        f"ASP.NET compilation debug mode is directly enabled{ctx}. "
                        "Debug mode disables request timeouts, reduces performance "
                        "optimizations, and can expose additional diagnostic information."
                    ),
                    recommendation='Set compilation debug="false" in production configurations.',
                    location=effective_location(section),
                ))
    else:
        for section in doc.sections:
            if section.tag == "compilation" and _is_true(section.attributes.get("debug")):
                findings.append(Finding(
                    rule_id=RULE_ID, title="ASP.NET compilation debug mode enabled", severity="medium",
                    description="ASP.NET compilation debug mode is directly enabled. Debug mode disables request timeouts, reduces performance optimizations, and can expose additional diagnostic information.",
                    recommendation='Set compilation debug="false" in production configurations.',
                    location=raw_location(section),
                ))

    return findings


def _is_true(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() == "true"
