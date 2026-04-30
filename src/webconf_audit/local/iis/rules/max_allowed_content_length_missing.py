from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig, IISEffectiveSection
from webconf_audit.local.iis.parser import IISConfigDocument, IISSection
from webconf_audit.local.iis.rules.rule_utils import (
    _MAX_CONTENT_LENGTH_THRESHOLD,
    effective_location,
    file_location,
    is_pure_inheritance,
    location_context,
    raw_location,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "iis.max_allowed_content_length_missing"


@rule(
    rule_id=RULE_ID,
    title="Maximum request content length not set",
    severity="low",
    description="No maxAllowedContentLength is configured.",
    recommendation="Set maxAllowedContentLength to limit request sizes.",
    category="local",
    server_type="iis",
    input_kind="effective",
    order=512,
)
def find_max_allowed_content_length_missing(
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
        _effective_request_limit_finding(section)
        for section in effective_config.all_sections
        if section.section_path_suffix == "/requestLimits"
        and not is_pure_inheritance(section)
    ]
    resolved_findings = [finding for finding in findings if finding is not None]
    if "/requestLimits" not in effective_config.global_sections:
        resolved_findings.append(_missing_request_limits_finding(doc))
    return resolved_findings


def _raw_findings(doc: IISConfigDocument) -> list[Finding]:
    findings = [
        _raw_request_limit_finding(section)
        for section in doc.sections
        if section.tag == "requestLimits"
    ]
    resolved_findings = [finding for finding in findings if finding is not None]
    if "requestLimits" not in {section.tag for section in doc.sections}:
        resolved_findings.append(_missing_request_limits_finding(doc))
    return resolved_findings


def _effective_request_limit_finding(section: IISEffectiveSection) -> Finding | None:
    raw_val = section.attributes.get("maxAllowedContentLength", "")
    if not raw_val:
        ctx = location_context(section)
        return Finding(
            rule_id=RULE_ID,
            title="Maximum request content length not set",
            severity="low",
            description=(
                f"IIS request limits do not specify maxAllowedContentLength{ctx}. "
                "The default limit of ~28.6 MB may be excessive for the "
                "application and could facilitate denial-of-service attacks."
            ),
            recommendation="Set requestLimits maxAllowedContentLength to an appropriate value for the application (e.g. 4194304 for 4 MB).",
            location=effective_location(section),
        )
    return _oversized_request_limit_finding(
        raw_val,
        location=effective_location(section),
        context_suffix=location_context(section),
    )


def _raw_request_limit_finding(section: IISSection) -> Finding | None:
    raw_val = section.attributes.get("maxAllowedContentLength", "")
    if not raw_val:
        return Finding(
            rule_id=RULE_ID,
            title="Maximum request content length not set",
            severity="low",
            description="IIS request limits do not specify maxAllowedContentLength. The default limit of ~28.6 MB may be excessive for the application and could facilitate denial-of-service attacks.",
            recommendation="Set requestLimits maxAllowedContentLength to an appropriate value for the application (e.g. 4194304 for 4 MB).",
            location=raw_location(section),
        )
    return _oversized_request_limit_finding(
        raw_val,
        location=raw_location(section),
        context_suffix="",
    )


def _oversized_request_limit_finding(
    raw_val: str,
    *,
    location: SourceLocation,
    context_suffix: str,
) -> Finding | None:
    if not raw_val.isdigit() or int(raw_val) <= _MAX_CONTENT_LENGTH_THRESHOLD:
        return None
    size_mb = int(raw_val) // 1_048_576
    return Finding(
        rule_id=RULE_ID,
        title="Maximum request content length excessively large",
        severity="low",
        description=(
            f"IIS maxAllowedContentLength is set to {raw_val} bytes "
            f"({size_mb} MB){context_suffix}, which exceeds the "
            "IIS default of ~28.6 MB and may facilitate denial-of-service attacks."
        ),
        recommendation="Set requestLimits maxAllowedContentLength to an appropriate value for the application (e.g. 4194304 for 4 MB).",
        location=location,
    )


def _missing_request_limits_finding(doc: IISConfigDocument) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title="Request content length limits not configured",
        severity="low",
        description=(
            "No requestLimits section is present in the configuration. "
            "The default maxAllowedContentLength of ~28.6 MB applies, "
            "which may be excessive and could facilitate denial-of-service attacks."
        ),
        recommendation='Add <requestLimits maxAllowedContentLength="4194304" /> inside <requestFiltering> to set an appropriate limit.',
        location=file_location(doc),
    )
