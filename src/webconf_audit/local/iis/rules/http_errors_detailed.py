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

RULE_ID = "iis.http_errors_detailed"


@rule(
    rule_id=RULE_ID,
    title="Detailed HTTP errors enabled",
    severity="medium",
    description="IIS is configured to send detailed HTTP error information.",
    recommendation="Set errorMode to DetailedLocalOnly or Custom.",
    category="local",
    server_type="iis",
    input_kind="effective",
    order=501,
)
def find_http_errors_detailed(
    doc: IISConfigDocument,
    *,
    effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    if effective_config is not None:
        for section in effective_config.all_sections:
            if section.section_path_suffix != "/httpErrors":
                continue
            if is_pure_inheritance(section):
                continue
            if section.attributes.get("errorMode", "").lower() == "detailed":
                ctx = location_context(section)
                findings.append(Finding(
                    rule_id=RULE_ID,
                    title="Detailed HTTP errors enabled",
                    severity="medium",
                    description=(
                        f"IIS is configured to return detailed HTTP error messages{ctx}. "
                        "Detailed errors can expose internal paths, "
                        "stack traces, and other sensitive information."
                    ),
                    recommendation=(
                        "Set httpErrors errorMode to Custom or DetailedLocalOnly "
                        "to prevent detailed errors from reaching remote clients."
                    ),
                    location=effective_location(section),
                ))
    else:
        for section in doc.sections:
            if section.tag == "httpErrors" and section.attributes.get("errorMode", "").lower() == "detailed":
                findings.append(Finding(
                    rule_id=RULE_ID,
                    title="Detailed HTTP errors enabled",
                    severity="medium",
                    description=(
                        "IIS is configured to return detailed HTTP error messages "
                        "to all clients. Detailed errors can expose internal paths, "
                        "stack traces, and other sensitive information."
                    ),
                    recommendation=(
                        "Set httpErrors errorMode to Custom or DetailedLocalOnly "
                        "to prevent detailed errors from reaching remote clients."
                    ),
                    location=raw_location(section),
                ))

    return findings
