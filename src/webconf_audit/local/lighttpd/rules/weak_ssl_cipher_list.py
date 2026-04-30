from __future__ import annotations

from webconf_audit.local.lighttpd.parser import (
    LighttpdAssignmentNode,
    LighttpdConfigAst,
)
from webconf_audit.local.lighttpd.rules.rule_utils import iter_all_nodes, unquote
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "lighttpd.weak_ssl_cipher_list"

_WEAK_TOKENS = frozenset({
    "rc4", "des", "3des", "null", "export", "md5", "anull", "enull",
})


@rule(
    rule_id=RULE_ID,
    title="Weak SSL ciphers configured",
    severity="high",
    description="Weak SSL ciphers configured",
    recommendation="Remove weak ciphers and use only strong cipher suites.",
    category="local",
    server_type="lighttpd",
    tags=('tls',),
    order=414,
)
def find_weak_ssl_cipher_list(config_ast: LighttpdConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_all_nodes(config_ast):
        if not isinstance(node, LighttpdAssignmentNode):
            continue
        if node.name != "ssl.cipher-list":
            continue

        raw = unquote(node.value).lower()
        # Match each cipher token against the longest weak marker that
        # occurs inside it, then deduplicate across tokens.  A substring
        # scan that kept every match would double-count overlapping
        # tokens — e.g. ``3des`` contains both ``des`` and ``3des``, but
        # only ``3des`` is actually present in the config.  Sorting by
        # descending length and picking the first hit preserves the
        # previous "longest-match per token" semantics with set-based
        # deduplication.
        weak_by_length = sorted(_WEAK_TOKENS, key=len, reverse=True)
        found_weak: set[str] = set()
        for token in _cipher_tokens(raw):
            if token.startswith(("!", "-", "+!")):
                continue
            for marker in weak_by_length:
                if marker in token:
                    found_weak.add(marker)
                    break
        if not found_weak:
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="Weak SSL ciphers configured",
                severity="high",
                description=(
                    f"ssl.cipher-list contains weak cipher components: {', '.join(sorted(found_weak))}."
                ),
                recommendation="Remove weak ciphers and use only strong cipher suites.",
                location=SourceLocation(
                    mode="local", kind="file",
                    file_path=node.source.file_path, line=node.source.line,
                ),
            )
        )

    return findings


def _cipher_tokens(raw: str) -> list[str]:
    return [
        token.strip()
        for token in raw.replace(",", ":").split(":")
        if token.strip()
    ]


__all__ = ["find_weak_ssl_cipher_list"]
