from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig
from webconf_audit.local.iis.parser import IISConfigDocument
from webconf_audit.local.iis.rules.rule_utils import effective_location, is_pure_inheritance, location_context, raw_location
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "iis.session_state_cookieless"


@rule(
    rule_id=RULE_ID,
    title="Cookieless session state enabled",
    severity="medium",
    description="Session state is configured with cookieless mode.",
    recommendation="Use cookie-based session state.",
    category="local",
    server_type="iis",
    input_kind="effective",
    order=515,
)
def find_session_state_cookieless(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    if effective_config is not None:
        for section in effective_config.all_sections:
            if section.section_path_suffix != "/sessionState":
                continue
            if is_pure_inheritance(section):
                continue
            cookieless = section.attributes.get("cookieless", "").lower()
            if cookieless in ("true", "useuri", "autodetect"):
                ctx = location_context(section)
                findings.append(Finding(
                    rule_id=RULE_ID, title="Cookieless session state enabled", severity="medium",
                    description=(
                        f"ASP.NET session state is configured to use cookieless "
                        f"mode ({cookieless}){ctx}. Session IDs embedded in URLs "
                        "are visible in logs, referrer headers, and browser history, "
                        "making session hijacking easier."
                    ),
                    recommendation='Set sessionState cookieless="UseCookies" or "false" to transmit session IDs via cookies only.',
                    location=effective_location(section),
                ))
    else:
        for section in doc.sections:
            if section.tag == "sessionState":
                cookieless = section.attributes.get("cookieless", "").lower()
                if cookieless in ("true", "useuri", "autodetect"):
                    findings.append(Finding(
                        rule_id=RULE_ID, title="Cookieless session state enabled", severity="medium",
                        description=(
                            f"ASP.NET session state is configured to use cookieless "
                            f"mode ({cookieless}). Session IDs embedded in URLs "
                            "are visible in logs, referrer headers, and browser history, "
                            "making session hijacking easier."
                        ),
                        recommendation='Set sessionState cookieless="UseCookies" or "false" to transmit session IDs via cookies only.',
                        location=raw_location(section),
                    ))

    return findings
