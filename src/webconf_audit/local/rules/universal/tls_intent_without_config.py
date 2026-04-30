"""universal.tls_intent_without_config

Fires when a scope has explicit TLS intent (port 443, ``ssl`` flag, HTTPS
binding) but no usable TLS configuration is present.

"No usable config" means either ``tls is None`` or a ``NormalizedTLS`` with
all substantive fields empty (no certificate, no ciphers, no protocols).

Does NOT fire for plain HTTP-only scopes — that would be too noisy.
"""

from __future__ import annotations

from webconf_audit.local.normalized import NormalizedConfig, NormalizedScope, NormalizedTLS
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "universal.tls_intent_without_config"

_TLS_INTENT_PORTS = frozenset({443, 8443, 9443})


@rule(
    rule_id=RULE_ID,
    title="TLS intent detected but no TLS configuration found",
    severity="high",
    description="A scope has a listen point on a TLS-associated port or with an HTTPS protocol hint, but no TLS configuration was found.",
    recommendation="Add TLS configuration (certificate, key, protocols, ciphers) for the HTTPS listener, or change the listener to a non-TLS port.",
    category="universal",
    input_kind="normalized",
    tags=("tls",),
    order=100,
)
def check(config: NormalizedConfig) -> list[Finding]:
    findings: list[Finding] = []
    for scope in config.scopes:
        if _has_tls_intent(scope) and _tls_config_missing(scope.tls):
            ref = _best_source(scope)
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    title="TLS intent detected but no TLS configuration found",
                    severity="high",
                    description=(
                        f"Scope '{scope.scope_name or '(unnamed)'}' has a listen point "
                        "on a TLS-associated port or with an HTTPS protocol hint, but "
                        "no TLS configuration (certificates, ciphers, protocols) was found."
                    ),
                    recommendation=(
                        "Add TLS configuration (certificate, key, protocols, ciphers) "
                        "for the HTTPS listener, or change the listener to a non-TLS port."
                    ),
                    location=SourceLocation(
                        mode="local",
                        kind=ref.kind,
                        file_path=ref.file_path,
                        line=ref.line,
                        xml_path=ref.xml_path,
                        details=f"server_type={config.server_type}",
                    ),
                )
            )
    return findings


def _tls_config_missing(tls: NormalizedTLS | None) -> bool:
    """Return True when there is no usable TLS configuration.

    Covers both ``tls is None`` and an empty TLS object where all
    substantive fields (certificate, ciphers, protocols, require_ssl)
    are unset.
    """
    if tls is None:
        return True
    protocols = [p for p in tls.protocols or [] if p]
    return (
        not (tls.certificate or "")
        and not (tls.ciphers or "")
        and not protocols
        and tls.require_ssl is None
    )


def _has_tls_intent(scope: NormalizedScope) -> bool:
    for lp in scope.listen_points:
        if lp.tls or lp.protocol == "https" or lp.port in _TLS_INTENT_PORTS:
            return True
    return False


def _best_source(scope: NormalizedScope):
    """Return a SourceRef-like object for location building."""
    for lp in scope.listen_points:
        if lp.tls or lp.protocol == "https" or lp.port in _TLS_INTENT_PORTS:
            return _as_loc(lp.source)
    if scope.listen_points:
        return _as_loc(scope.listen_points[0].source)
    return _Loc()


class _Loc:
    kind = "file"
    file_path: str | None = None
    line: int | None = None
    xml_path: str | None = None


def _as_loc(source):
    loc = _Loc()
    loc.file_path = source.file_path
    loc.line = source.line
    loc.xml_path = getattr(source, "xml_path", None)
    loc.kind = "xml" if loc.xml_path else "file"
    return loc
