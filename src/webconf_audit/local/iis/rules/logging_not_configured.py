from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig, IISEffectiveSection
from webconf_audit.local.iis.parser import IISConfigDocument, IISSection
from webconf_audit.local.iis.rules.rule_utils import effective_location, file_location, is_pure_inheritance, location_context, raw_location
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "iis.logging_not_configured"


@rule(
    rule_id=RULE_ID,
    title="HTTP logging disabled",
    severity="medium",
    description="HTTP logging is not configured.",
    recommendation="Enable HTTP logging.",
    category="local",
    server_type="iis",
    input_kind="effective",
    order=511,
)
def find_logging_not_configured(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    if effective_config is not None:
        return _effective_findings(doc, effective_config)
    return _raw_findings(doc)


def _effective_findings(
    doc: IISConfigDocument,
    effective_config: IISEffectiveConfig,
) -> list[Finding]:
    # ``_effective_disabled_logging_finding`` never returns ``None`` —
    # the downstream ``if finding is not None`` filter is defensive only
    # and mirrors the shape used by other rule modules so a future
    # refactor that widens the helper's return type does not silently
    # poison the findings list with ``None`` entries.
    resolved_findings: list[Finding] = [
        _effective_disabled_logging_finding(section)
        for section in effective_config.all_sections
        if section.section_path_suffix == "/httpLogging"
        and not is_pure_inheritance(section)
        and section.attributes.get("dontLog", "").lower() == "true"
    ]
    if "/httpLogging" not in effective_config.global_sections:
        resolved_findings.append(_missing_logging_configuration_finding(doc))
    return resolved_findings


def _raw_findings(doc: IISConfigDocument) -> list[Finding]:
    # Same defensive-filter rationale as ``_effective_findings``: the
    # helper always returns ``Finding``, but keeping the ``list[Finding]``
    # pipeline explicit protects against a future return-type widening.
    resolved_findings: list[Finding] = [
        _raw_disabled_logging_finding(section)
        for section in doc.sections
        if section.tag == "httpLogging"
        and section.attributes.get("dontLog", "").lower() == "true"
    ]
    if "httpLogging" not in {section.tag for section in doc.sections}:
        resolved_findings.append(_missing_logging_configuration_finding(doc))
    return resolved_findings


def _effective_disabled_logging_finding(section: IISEffectiveSection) -> Finding:
    ctx = location_context(section)
    return Finding(
        rule_id=RULE_ID,
        title="HTTP logging disabled",
        severity="medium",
        description=(
            f"IIS HTTP logging is explicitly disabled{ctx}. "
            "Without access logs, security incidents cannot be "
            "detected or investigated after the fact."
        ),
        recommendation='Set httpLogging dontLog="false" or remove the attribute to restore default logging behavior.',
        location=effective_location(section),
    )


def _raw_disabled_logging_finding(section: IISSection) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title="HTTP logging disabled",
        severity="medium",
        description=(
            "IIS HTTP logging is explicitly disabled. Without access logs, security incidents cannot be detected or investigated after the fact."
        ),
        recommendation='Set httpLogging dontLog="false" or remove the attribute to restore default logging behavior.',
        location=raw_location(section),
    )


def _missing_logging_configuration_finding(doc: IISConfigDocument) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title="HTTP logging not explicitly configured",
        severity="medium",
        description=(
            "No httpLogging section is present in the configuration. "
            "Logging relies on server-level defaults which may not be "
            "adequate. Without explicit logging configuration, audit "
            "trails may be incomplete or missing."
        ),
        recommendation="Add an httpLogging section to explicitly configure request logging for this application or site.",
        location=file_location(doc),
    )
