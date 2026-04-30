from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig, IISEffectiveSection
from webconf_audit.local.iis.parser import IISConfigDocument, IISSection
from webconf_audit.local.iis.rules.rule_utils import (
    effective_location,
    file_location,
    has_https_binding,
    is_pure_inheritance,
    location_context,
    raw_location,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "iis.ssl_not_required"


@rule(
    rule_id=RULE_ID,
    title="SSL not required",
    severity="medium",
    description="The access section does not require SSL.",
    recommendation="Set sslFlags to require SSL.",
    category="local",
    server_type="iis",
    tags=("tls",),
    input_kind="effective",
    order=509,
)
def find_ssl_not_required(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    if effective_config is not None:
        return _effective_findings(doc, effective_config)
    return _raw_findings(doc)


def _effective_findings(
    doc: IISConfigDocument,
    effective_config: IISEffectiveConfig,
) -> list[Finding]:
    findings = [
        _effective_ssl_not_required_finding(section)
        for section in effective_config.all_sections
        if section.section_path_suffix == "/access" and not is_pure_inheritance(section)
    ]
    resolved_findings = [finding for finding in findings if finding is not None]
    if has_https_binding(doc) and "/access" not in effective_config.global_sections:
        resolved_findings.append(_missing_access_section_finding(doc))
    return resolved_findings


def _raw_findings(doc: IISConfigDocument) -> list[Finding]:
    findings = [
        _raw_ssl_not_required_finding(section)
        for section in doc.sections
        if section.tag == "access"
    ]
    resolved_findings = [finding for finding in findings if finding is not None]
    if has_https_binding(doc) and "access" not in {section.tag for section in doc.sections}:
        resolved_findings.append(_missing_access_section_finding(doc))
    return resolved_findings


def _effective_ssl_not_required_finding(
    section: IISEffectiveSection,
) -> Finding | None:
    ssl_flags = section.attributes.get("sslFlags", "").lower()
    if ssl_flags not in ("", "none", "0"):
        return None
    ctx = location_context(section)
    return Finding(
        rule_id=RULE_ID,
        title="SSL not required",
        severity="medium",
        description=(
            f"IIS is not configured to require SSL{ctx}. "
            "Clients can connect over unencrypted HTTP, exposing "
            "transmitted data to interception."
        ),
        recommendation='Set access sslFlags to include "Ssl" (e.g. sslFlags="Ssl,Ssl128") to require HTTPS connections.',
        location=effective_location(section),
    )


def _raw_ssl_not_required_finding(section: IISSection) -> Finding | None:
    ssl_flags = section.attributes.get("sslFlags", "").lower()
    if ssl_flags not in ("", "none", "0"):
        return None
    return Finding(
        rule_id=RULE_ID,
        title="SSL not required",
        severity="medium",
        description="IIS is not configured to require SSL. Clients can connect over unencrypted HTTP, exposing transmitted data to interception.",
        recommendation='Set access sslFlags to include "Ssl" (e.g. sslFlags="Ssl,Ssl128") to require HTTPS connections.',
        location=raw_location(section),
    )


def _missing_access_section_finding(doc: IISConfigDocument) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title="SSL not required",
        severity="medium",
        description=(
            "The configuration defines an HTTPS binding but does not "
            "include an access section with sslFlags. Without an explicit "
            "SSL requirement, clients may reach content over unencrypted HTTP."
        ),
        recommendation='Add <access sslFlags="Ssl,Ssl128" /> inside <system.webServer><security> to require HTTPS connections.',
        location=file_location(doc),
    )
