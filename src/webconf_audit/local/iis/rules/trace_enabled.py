from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig
from webconf_audit.local.iis.parser import IISConfigDocument
from webconf_audit.local.iis.rules.rule_utils import effective_location, is_pure_inheritance, location_context, raw_location
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "iis.trace_enabled"


@rule(
    rule_id=RULE_ID,
    title="ASP.NET trace enabled",
    severity="medium",
    description="ASP.NET trace is enabled.",
    recommendation="Disable trace in production.",
    category="local",
    server_type="iis",
    input_kind="effective",
    order=505,
)
def find_trace_enabled(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    if effective_config is not None:
        for section in effective_config.all_sections:
            if section.section_path_suffix != "/trace":
                continue
            if is_pure_inheritance(section):
                continue
            if section.attributes.get("enabled", "").lower() == "true":
                ctx = location_context(section)
                findings.append(Finding(
                    rule_id=RULE_ID, title="ASP.NET trace enabled", severity="medium",
                    description=(
                        f"ASP.NET tracing is directly enabled{ctx}. Trace output can expose "
                        "request details, server variables, session state, and other "
                        "sensitive runtime information."
                    ),
                    recommendation='Set trace enabled="false" or remove the trace element in production configurations.',
                    location=effective_location(section),
                ))
    else:
        for section in doc.sections:
            if section.tag == "trace" and section.attributes.get("enabled", "").lower() == "true":
                findings.append(Finding(
                    rule_id=RULE_ID, title="ASP.NET trace enabled", severity="medium",
                    description="ASP.NET tracing is directly enabled. Trace output can expose request details, server variables, session state, and other sensitive runtime information.",
                    recommendation='Set trace enabled="false" or remove the trace element in production configurations.',
                    location=raw_location(section),
                ))

    return findings
