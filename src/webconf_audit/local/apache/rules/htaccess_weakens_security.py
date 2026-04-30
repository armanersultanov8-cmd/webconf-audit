"""Rule: detect when .htaccess effectively weakens a security directive.

Unlike the simpler htaccess_contains_security_directive (presence-based),
this rule uses effective-config comparison to prove that a .htaccess file
actually *overrides* a security-significant directive set in the main config.
"""

from __future__ import annotations

import os
from pathlib import Path

from webconf_audit.local.apache.effective import (
    ApacheVirtualHostContext,
    EffectiveConfig,
    build_effective_config,
    extract_document_root,
    extract_virtualhost_contexts,
)
from webconf_audit.local.apache.htaccess import HtaccessFile
from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.htaccess_weakens_security"


@rule(
    rule_id=RULE_ID,
    title=".htaccess re-enables ServerSignature",
    severity="high",
    description=".htaccess re-enables ServerSignature",
    recommendation=(
        "Remove dangerous security overrides from .htaccess or set "
        "AllowOverride to restrict what .htaccess can change."
    ),
    category="local",
    server_type="apache",
    input_kind="mixed",
    tags=('htaccess',),
    order=313,
)
def find_htaccess_weakens_security(
    config_ast: ApacheConfigAst,
    htaccess_files: list[HtaccessFile],
    config_dir: Path | None = None,
) -> list[Finding]:
    """Compare effective config with/without .htaccess to detect weakening."""
    findings: list[Finding] = []
    virtualhost_contexts = extract_virtualhost_contexts(config_ast)

    for htf in htaccess_files:
        virtualhost_context = _select_virtualhost_for_htaccess(
            config_ast,
            virtualhost_contexts,
            htf,
            config_dir=config_dir,
        )
        # Build baseline (without .htaccess)
        baseline = build_effective_config(
            config_ast,
            htf.directory_path,
            htaccess_file=None,
            config_dir=config_dir,
            virtualhost_context=virtualhost_context,
        )
        # Build effective (with .htaccess)
        effective = build_effective_config(
            config_ast,
            htf.directory_path,
            htaccess_file=htf,
            config_dir=config_dir,
            virtualhost_context=virtualhost_context,
        )

        findings.extend(_compare_options(baseline, effective, htf))
        findings.extend(_compare_serversignature(baseline, effective, htf))

    return findings


def _select_virtualhost_for_htaccess(
    config_ast: ApacheConfigAst,
    virtualhost_contexts: list[ApacheVirtualHostContext],
    htf: HtaccessFile,
    *,
    config_dir: Path | None,
) -> ApacheVirtualHostContext | None:
    direct_match = _context_for_source_virtualhost(virtualhost_contexts, htf)
    if direct_match is not None:
        return direct_match

    target_path = _normalized_resolved_path(Path(htf.directory_path))
    best_match: tuple[int, ApacheVirtualHostContext] | None = None
    for context in virtualhost_contexts:
        doc_root = extract_document_root(
            config_ast,
            virtualhost_context=context,
            config_dir=config_dir,
        )
        specificity = _doc_root_specificity(doc_root, target_path)
        if specificity is None:
            continue
        if best_match is None or specificity > best_match[0]:
            best_match = (specificity, context)

    return best_match[1] if best_match is not None else None


def _context_for_source_virtualhost(
    virtualhost_contexts: list[ApacheVirtualHostContext],
    htf: HtaccessFile,
) -> ApacheVirtualHostContext | None:
    if htf.source_virtualhost_block is None:
        return None
    for context in virtualhost_contexts:
        if context.node is htf.source_virtualhost_block:
            return context
    return None


def _doc_root_specificity(doc_root: Path | None, target_path: str) -> int | None:
    if doc_root is None:
        return None

    doc_root_str = _normalized_resolved_path(doc_root)
    if target_path != doc_root_str and not target_path.startswith(doc_root_str + "/"):
        return None
    return len(doc_root_str)


def _normalized_resolved_path(path: Path) -> str:
    # Apache deployments on POSIX hosts use case-sensitive filesystems, so
    # lowercasing every path there would turn ``/srv/Site`` and
    # ``/srv/site`` into the same DocumentRoot and pick the wrong
    # VirtualHost.  Guard the ``lower()`` call with ``os.name`` so Windows
    # keeps its case-insensitive match while POSIX stays accurate.
    #
    # The ``rstrip("/")`` also needs a floor: stripping the root slash
    # turned ``/`` into ``""`` and broke the ``startswith(root + "/")``
    # specificity check, so preserve ``/`` as-is.
    normalized = str(path.resolve()).replace("\\", "/")
    if len(normalized) > 1:
        normalized = normalized.rstrip("/") or normalized
    if os.name == "nt":
        normalized = normalized.lower()
    return normalized


def _compare_options(
    baseline: EffectiveConfig,
    effective: EffectiveConfig,
    htf: HtaccessFile,
) -> list[Finding]:
    """Detect when .htaccess adds dangerous Options (Indexes, ExecCGI, Includes)."""
    findings: list[Finding] = []
    dangerous = {"indexes", "execcgi", "includes", "followsymlinks", "multiviews"}

    baseline_options = baseline.directives.get("options")
    effective_options = effective.directives.get("options")
    baseline_opts = set(a.lower() for a in (baseline_options.args if baseline_options else []))
    effective_opts = set(a.lower() for a in (effective_options.args if effective_options else []))

    added = (effective_opts - baseline_opts) & dangerous
    if added and effective_options is not None:
        eff = effective_options
        if eff.origin.layer == "htaccess":
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    title=f".htaccess enables dangerous Options: {', '.join(sorted(added))}",
                    severity="high",
                    description=(
                        f"The .htaccess at {htf.htaccess_path} adds Options "
                        f"'{', '.join(sorted(added))}' that were not present in "
                        f"the main configuration. This weakens the server's "
                        f"security posture."
                    ),
                    recommendation=(
                        "Remove the dangerous Options from .htaccess or set "
                        "'AllowOverride' to restrict what .htaccess can change."
                    ),
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path=eff.origin.source.file_path or htf.htaccess_path,
                        line=eff.origin.source.line,
                    ),
                )
            )

    return findings


def _compare_serversignature(
    baseline: EffectiveConfig,
    effective: EffectiveConfig,
    htf: HtaccessFile,
) -> list[Finding]:
    """Detect when .htaccess re-enables ServerSignature."""
    findings: list[Finding] = []

    baseline_sig = baseline.directives.get("serversignature")
    effective_sig = effective.directives.get("serversignature")

    if (
        baseline_sig is not None
        and effective_sig is not None
        and effective_sig.origin.layer == "htaccess"
    ):
        base_val = baseline_sig.args[0].lower() if baseline_sig.args else ""
        eff_val = effective_sig.args[0].lower() if effective_sig.args else ""

        if base_val == "off" and eff_val in ("on", "email"):
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    title=".htaccess re-enables ServerSignature",
                    severity="medium",
                    description=(
                        f"The main config sets ServerSignature Off, but "
                        f".htaccess at {htf.htaccess_path} overrides it to "
                        f"'{effective_sig.args[0]}'. This exposes server version "
                        f"information."
                    ),
                    recommendation=(
                        "Remove 'ServerSignature' from .htaccess or set "
                        "'AllowOverride None' for this directory."
                    ),
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path=effective_sig.origin.source.file_path or htf.htaccess_path,
                        line=effective_sig.origin.source.line,
                    ),
                )
            )

    return findings


__all__ = ["find_htaccess_weakens_security"]
