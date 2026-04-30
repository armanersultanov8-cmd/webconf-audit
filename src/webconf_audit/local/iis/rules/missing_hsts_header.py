from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig, IISEffectiveSection
from webconf_audit.local.iis.parser import IISConfigDocument, IISSection
from webconf_audit.local.iis.rules.rule_utils import (
    effective_location,
    file_location,
    is_pure_inheritance,
    location_context,
    raw_location,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "iis.missing_hsts_header"


@rule(
    rule_id=RULE_ID,
    title="HSTS header not configured",
    severity="medium",
    description="Strict-Transport-Security header is not configured.",
    recommendation="Add an HSTS custom header.",
    category="local",
    server_type="iis",
    tags=("headers", "tls"),
    input_kind="effective",
    order=513,
)
def find_missing_hsts_header(
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
        _effective_missing_hsts_finding(section)
        for section in effective_config.all_sections
        if section.section_path_suffix == "/customHeaders"
        and not is_pure_inheritance(section)
        and not _has_hsts(section.children)
    ]
    if "/customHeaders" not in effective_config.global_sections:
        findings.append(_missing_custom_headers_finding(doc))
    return findings


def _raw_findings(doc: IISConfigDocument) -> list[Finding]:
    findings = [
        _raw_missing_hsts_finding(section)
        for section in doc.sections
        if section.tag == "customHeaders" and not _has_hsts(section.children)
    ]
    if "customHeaders" not in {section.tag for section in doc.sections}:
        findings.append(_missing_custom_headers_finding(doc))
    return findings


def _effective_missing_hsts_finding(section: IISEffectiveSection) -> Finding:
    ctx = location_context(section)
    return Finding(
        rule_id=RULE_ID,
        title="HSTS header not configured",
        severity="medium",
        description=(
            f"The Strict-Transport-Security (HSTS) header is not configured "
            f"in IIS custom headers{ctx}. Without HSTS, browsers will not "
            "enforce HTTPS and users remain vulnerable to protocol downgrade "
            "and cookie hijacking attacks."
        ),
        recommendation=(
            'Add an HSTS header: <add name="Strict-Transport-Security" '
            'value="max-age=31536000; includeSubDomains" />.'
        ),
        location=effective_location(section),
    )


def _raw_missing_hsts_finding(section: IISSection) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title="HSTS header not configured",
        severity="medium",
        description=(
            "The Strict-Transport-Security (HSTS) header is not configured "
            "in IIS custom headers. Without HSTS, browsers will not "
            "enforce HTTPS and users remain vulnerable to protocol downgrade "
            "and cookie hijacking attacks."
        ),
        recommendation=(
            'Add an HSTS header: <add name="Strict-Transport-Security" '
            'value="max-age=31536000; includeSubDomains" />.'
        ),
        location=raw_location(section),
    )


def _missing_custom_headers_finding(doc: IISConfigDocument) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title="HSTS header not configured",
        severity="medium",
        description=(
            "No customHeaders section is present in the configuration. "
            "The Strict-Transport-Security (HSTS) header is not configured. "
            "Without HSTS, browsers will not enforce HTTPS and users remain "
            "vulnerable to protocol downgrade and cookie hijacking attacks."
        ),
        recommendation=(
            'Add a customHeaders section with an HSTS header: '
            '<add name="Strict-Transport-Security" '
            'value="max-age=31536000; includeSubDomains" />.'
        ),
        location=file_location(doc),
    )


def _has_hsts(children) -> bool:
    for child in children:
        if child.tag.lower() == "add" and child.attributes.get("name", "").lower() == "strict-transport-security":
            return True
    return False
