from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig
from webconf_audit.local.iis.parser import IISConfigDocument
from webconf_audit.local.iis.rules.rule_utils import effective_location, is_pure_inheritance, location_context, raw_location
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "iis.ssl_weak_cipher_strength"


@rule(
    rule_id=RULE_ID,
    title="128-bit SSL not required",
    severity="low",
    description="SSL cipher strength does not require 128-bit encryption.",
    recommendation="Set sslFlags to require Ssl128.",
    category="local",
    server_type="iis",
    tags=("tls",),
    input_kind="effective",
    order=510,
)
def find_ssl_weak_cipher_strength(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    if effective_config is not None:
        return _effective_findings(effective_config)
    return _raw_findings(doc)


def _effective_findings(effective_config: IISEffectiveConfig) -> list[Finding]:
    findings: list[Finding] = []
    for section in effective_config.all_sections:
        if section.section_path_suffix != "/access" or is_pure_inheritance(section):
            continue
        if not _requires_ssl_without_ssl128(section.attributes.get("sslFlags")):
            continue
        findings.append(_effective_cipher_strength_finding(section))
    return findings


def _raw_findings(doc: IISConfigDocument) -> list[Finding]:
    findings: list[Finding] = []
    for section in doc.sections:
        if section.tag != "access":
            continue
        if not _requires_ssl_without_ssl128(section.attributes.get("sslFlags")):
            continue
        findings.append(_raw_cipher_strength_finding(section))
    return findings


def _requires_ssl_without_ssl128(value: object) -> bool:
    ssl_tokens = _ssl_flag_tokens(value)
    return "ssl" in ssl_tokens and "ssl128" not in ssl_tokens


def _effective_cipher_strength_finding(section) -> Finding:
    ctx = location_context(section)
    return Finding(
        rule_id=RULE_ID,
        title="128-bit SSL not required",
        severity="low",
        description=(
            f"IIS requires SSL but does not enforce 128-bit "
            f"cipher strength{ctx}. Weaker ciphers may be "
            "negotiated, reducing transport security."
        ),
        recommendation='Add Ssl128 to the sslFlags value (e.g. sslFlags="Ssl,Ssl128") to require strong ciphers.',
        location=effective_location(section),
    )


def _raw_cipher_strength_finding(section) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title="128-bit SSL not required",
        severity="low",
        description="IIS requires SSL but does not enforce 128-bit cipher strength. Weaker ciphers may be negotiated, reducing transport security.",
        recommendation='Add Ssl128 to the sslFlags value (e.g. sslFlags="Ssl,Ssl128") to require strong ciphers.',
        location=raw_location(section),
    )


def _ssl_flag_tokens(value: object) -> set[str]:
    if value is None:
        return set()
    return {
        token.strip().lower()
        for token in str(value).replace(";", ",").split(",")
        if token.strip()
    }
