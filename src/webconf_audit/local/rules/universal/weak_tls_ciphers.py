"""universal.weak_tls_ciphers

Fires when the cipher string contains known-weak patterns.
Skips silently when ciphers are unknown (None).
"""

from __future__ import annotations

import re

from webconf_audit.local.normalized import NormalizedConfig
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "universal.weak_tls_ciphers"

_WEAK_PATTERNS = re.compile(
    r"(?i)\b(RC4|DES|3DES|NULL|EXPORT|eNULL|aNULL|MD5|DES-CBC3)\b"
)


@rule(
    rule_id=RULE_ID,
    title="Weak TLS ciphers detected",
    severity="medium",
    description="The cipher string contains known-weak patterns (RC4, DES, 3DES, NULL, EXPORT, eNULL, aNULL, MD5).",
    recommendation="Remove weak ciphers (RC4, DES, 3DES, NULL, EXPORT, MD5) from the cipher list.",
    category="universal",
    input_kind="normalized",
    tags=("tls",),
    order=102,
)
def check(config: NormalizedConfig) -> list[Finding]:
    findings: list[Finding] = []
    for scope in config.scopes:
        if scope.tls is None or scope.tls.ciphers is None:
            continue
        matches: list[str] = []
        for token in _cipher_tokens(scope.tls.ciphers):
            if token.startswith(("!", "-", "+!")):
                continue
            matches.extend(_WEAK_PATTERNS.findall(token))
        if matches:
            unique = sorted(set(m.upper() for m in matches))
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    title="Weak TLS ciphers detected",
                    severity="medium",
                    description=(
                        f"Scope '{scope.scope_name or '(unnamed)'}' cipher string "
                        f"contains weak ciphers: {', '.join(unique)}."
                    ),
                    recommendation="Remove weak ciphers (RC4, DES, 3DES, NULL, EXPORT, MD5) from the cipher list.",
                    location=_location(scope, config),
                )
            )
    return findings


def _cipher_tokens(cipher_string: str) -> list[str]:
    return [token.strip() for token in re.split(r"[:\s,]+", cipher_string) if token.strip()]


def _location(scope, config):
    src = scope.tls.source
    return SourceLocation(
        mode="local",
        kind="xml" if src.xml_path else "file",
        file_path=src.file_path,
        line=src.line,
        xml_path=src.xml_path,
        details=f"server_type={config.server_type}",
    )
