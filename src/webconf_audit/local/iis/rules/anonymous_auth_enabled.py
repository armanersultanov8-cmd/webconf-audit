from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig
from webconf_audit.local.iis.parser import IISConfigDocument, IISSection
from webconf_audit.local.iis.rules.rule_utils import (
    _OTHER_AUTH_SUFFIXES,
    effective_location,
    is_pure_inheritance,
    location_context,
    raw_location,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "iis.anonymous_auth_enabled"


@rule(
    rule_id=RULE_ID,
    title="Anonymous authentication enabled alongside other schemes",
    severity="medium",
    description="Anonymous authentication is enabled together with other authentication schemes.",
    recommendation="Disable anonymous authentication if named auth is required.",
    category="local",
    server_type="iis",
    input_kind="effective",
    order=519,
)
def find_anonymous_auth_enabled(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    if effective_config is not None:
        return _check_effective(effective_config)
    return _check_raw(doc.sections)


def _check_effective(effective_config: IISEffectiveConfig) -> list[Finding]:
    findings: list[Finding] = []

    for section in effective_config.all_sections:
        if section.section_path_suffix != "/anonymousAuthentication":
            continue
        if is_pure_inheritance(section):
            continue
        if section.attributes.get("enabled", "").lower() != "true":
            continue

        active_others: list[str] = []
        for suffix, label in _OTHER_AUTH_SUFFIXES:
            other = effective_config.get_effective_section(
                suffix, location_path=section.location_path,
            )
            if other is not None and other.attributes.get("enabled", "").lower() == "true":
                active_others.append(label)

        if active_others:
            ctx = location_context(section)
            others_str = ", ".join(active_others)
            findings.append(Finding(
                rule_id=RULE_ID,
                title="Anonymous authentication enabled alongside other schemes",
                severity="medium",
                description=(
                    f"IIS anonymous authentication is enabled together with "
                    f"{others_str} authentication{ctx}. This combination can "
                    "lead to authorization bypass when anonymous access "
                    "satisfies a request before stronger schemes are checked."
                ),
                recommendation=(
                    "Disable anonymous authentication where it is not required "
                    'by setting anonymousAuthentication enabled="false", or '
                    "ensure authorization rules explicitly deny anonymous users."
                ),
                location=effective_location(section),
            ))

    return findings


def _check_raw(sections: list[IISSection]) -> list[Finding]:
    findings: list[Finding] = []
    for group in _sections_by_location(sections).values():
        finding = _raw_group_finding(group)
        if finding is not None:
            findings.append(finding)
    return findings


def _sections_by_location(
    sections: list[IISSection],
) -> dict[str | None, list[IISSection]]:
    by_location: dict[str | None, list[IISSection]] = {}
    for section in sections:
        by_location.setdefault(section.location_path, []).append(section)
    return by_location


def _raw_group_finding(group: list[IISSection]) -> Finding | None:
    anon_section = _enabled_raw_section(group, "anonymousAuthentication")
    active_others = _active_raw_auth_schemes(group)
    if anon_section is None or not active_others:
        return None

    others_str = ", ".join(active_others)
    return Finding(
        rule_id=RULE_ID,
        title="Anonymous authentication enabled alongside other schemes",
        severity="medium",
        description=(
            f"IIS anonymous authentication is enabled together with "
            f"{others_str} authentication. This combination can "
            "lead to authorization bypass when anonymous access "
            "satisfies a request before stronger schemes are checked."
        ),
        recommendation=(
            "Disable anonymous authentication where it is not required "
            'by setting anonymousAuthentication enabled="false", or '
            "ensure authorization rules explicitly deny anonymous users."
        ),
        location=raw_location(anon_section),
    )


def _enabled_raw_section(
    sections: list[IISSection],
    tag_name: str,
) -> IISSection | None:
    for section in sections:
        if section.tag != tag_name:
            continue
        if section.attributes.get("enabled", "").lower() == "true":
            return section
    return None


def _active_raw_auth_schemes(sections: list[IISSection]) -> list[str]:
    active: list[str] = []
    for tag_name, label in (
        ("basicAuthentication", "basic"),
        ("windowsAuthentication", "Windows"),
        ("digestAuthentication", "digest"),
    ):
        if _enabled_raw_section(sections, tag_name) is not None:
            active.append(label)
    return active
