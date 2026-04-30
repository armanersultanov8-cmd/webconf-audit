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

RULE_ID = "iis.directory_browse_enabled"


@rule(
    rule_id=RULE_ID,
    title="Directory browsing enabled",
    severity="medium",
    description="IIS directory browsing is enabled.",
    recommendation="Disable directory browsing unless required.",
    category="local",
    server_type="iis",
    input_kind="effective",
    order=500,
)
def find_directory_browse_enabled(
    doc: IISConfigDocument,
    *,
    effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    if effective_config is not None:
        for section in effective_config.all_sections:
            if section.section_path_suffix != "/directoryBrowse":
                continue
            if is_pure_inheritance(section):
                continue
            if section.attributes.get("enabled", "").lower() == "true":
                ctx = location_context(section)
                findings.append(Finding(
                    rule_id=RULE_ID,
                    title="Directory browsing enabled",
                    severity="medium",
                    description=(
                        f"IIS directory browsing is directly enabled{ctx}. "
                        "This allows external users to list the contents of directories "
                        "that do not have a default document."
                    ),
                    recommendation=(
                        "Disable directory browsing by setting "
                        'directoryBrowse enabled="false" or removing the element.'
                    ),
                    location=effective_location(section),
                ))
    else:
        for section in doc.sections:
            if section.tag == "directoryBrowse" and section.attributes.get("enabled", "").lower() == "true":
                findings.append(Finding(
                    rule_id=RULE_ID,
                    title="Directory browsing enabled",
                    severity="medium",
                    description=(
                        "IIS directory browsing is directly enabled in the configuration. "
                        "This allows external users to list the contents of directories "
                        "that do not have a default document."
                    ),
                    recommendation=(
                        "Disable directory browsing by setting "
                        'directoryBrowse enabled="false" or removing the element.'
                    ),
                    location=raw_location(section),
                ))

    return findings
