"""universal.listen_on_all_interfaces

Informational finding when a listen point binds to all interfaces
(0.0.0.0 / * / :: / [::] / no explicit address).
"""

from __future__ import annotations

from webconf_audit.local.normalized import NormalizedConfig
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "universal.listen_on_all_interfaces"

_WILDCARD_ADDRESSES = frozenset({"0.0.0.0", "*", "::", "[::]", ""})  # noqa: S104


@rule(
    rule_id=RULE_ID,
    title="Listening on all network interfaces",
    severity="info",
    description="A listen point binds to all interfaces (0.0.0.0, *, ::, [::], or implicit wildcard).",
    recommendation="If this service is internal, bind to a specific interface (e.g. 127.0.0.1) instead of all interfaces.",
    category="universal",
    input_kind="normalized",
    tags=("network",),
    order=110,
)
def check(config: NormalizedConfig) -> list[Finding]:
    findings: list[Finding] = []
    seen_listens: set[tuple[int, str, str | None, str, int | None, str | None]] = set()

    for scope in config.scopes:
        for lp in scope.listen_points:
            # ``lp.address or ""`` already collapses ``None`` into the
            # empty string, so the redundant ``addr is not None`` guard
            # that previously rode along with the wildcard check could
            # never trigger - drop it for clarity.
            addr = lp.address or ""
            if addr not in _WILDCARD_ADDRESSES:
                continue
            src = lp.source
            listen_key = (
                lp.port,
                addr,
                scope.scope_name,
                src.file_path,
                src.line,
                src.xml_path,
            )
            if listen_key in seen_listens:
                continue
            seen_listens.add(listen_key)

            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    title="Listening on all network interfaces",
                    severity="info",
                    description=(
                        f"Port {lp.port} is bound to all interfaces "
                        f"({addr or 'implicit wildcard'}). This is expected for "
                        "public-facing servers but may be a concern for internal services."
                    ),
                    recommendation=(
                        "If this service is internal, bind to a specific interface "
                        "(e.g. 127.0.0.1) instead of all interfaces."
                    ),
                    location=SourceLocation(
                        mode="local",
                        kind="xml" if src.xml_path else "file",
                        file_path=src.file_path,
                        line=src.line,
                        xml_path=src.xml_path,
                        details=f"server_type={config.server_type}",
                    ),
                    metadata={
                        "scope_name": scope.scope_name,
                        "address": addr or None,
                        "port": lp.port,
                    },
                )
            )
    return findings
