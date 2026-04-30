from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig
from webconf_audit.local.iis.parser import IISConfigDocument
from webconf_audit.local.iis.rules.rule_utils import effective_location, is_pure_inheritance, location_context, raw_location
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "iis.forms_auth_require_ssl_missing"


@rule(
    rule_id=RULE_ID,
    title="Forms authentication does not require SSL",
    severity="medium",
    description="Forms authentication is configured without requireSSL.",
    recommendation="Set requireSSL to true.",
    category="local",
    server_type="iis",
    tags=("tls",),
    input_kind="effective",
    order=514,
)
def find_forms_auth_require_ssl_missing(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    if effective_config is not None:
        for section in effective_config.all_sections:
            if section.section_path_suffix != "/forms":
                continue
            if is_pure_inheritance(section):
                continue
            if _requires_ssl_missing_or_false(section.attributes.get("requireSSL")):
                ctx = location_context(section)
                findings.append(Finding(
                    rule_id=RULE_ID, title="Forms authentication does not require SSL", severity="medium",
                    description=(
                        f"ASP.NET forms authentication is configured without "
                        f"requiring SSL{ctx}. Authentication cookies can be "
                        "transmitted in plaintext and intercepted by attackers."
                    ),
                    recommendation='Set forms requireSSL="true" to ensure authentication cookies are only sent over encrypted connections.',
                    location=effective_location(section),
                ))
    else:
        for section in doc.sections:
            if section.tag == "forms" and _requires_ssl_missing_or_false(
                section.attributes.get("requireSSL")
            ):
                findings.append(Finding(
                    rule_id=RULE_ID, title="Forms authentication does not require SSL", severity="medium",
                    description="ASP.NET forms authentication is configured without requiring SSL. Authentication cookies can be transmitted in plaintext and intercepted by attackers.",
                    recommendation='Set forms requireSSL="true" to ensure authentication cookies are only sent over encrypted connections.',
                    location=raw_location(section),
                ))

    return findings


def _requires_ssl_missing_or_false(value: object) -> bool:
    if isinstance(value, bool):
        return not value
    if value is None:
        return True
    return str(value).strip().lower() != "true"
