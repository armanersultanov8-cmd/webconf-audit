from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from webconf_audit.local.apache.effective import (
    ApacheVirtualHostContext,
    EffectiveConfig,
    build_server_effective_config,
    extract_document_root,
    extract_virtualhost_contexts,
)
from webconf_audit.local.apache.htaccess import (
    HtaccessDiscoveryResult,
    HtaccessFile,
    discover_htaccess_files,
)
from webconf_audit.local.apache.include import resolve_includes
from webconf_audit.local.apache.parser import (
    ApacheConfigAst,
    ApacheParseError,
    ApacheParser,
    ApacheTokenizer,
)
from webconf_audit.local.apache.rules_runner import (
    run_apache_ast_rules,
    run_apache_htaccess_rules,
    run_apache_rules,
)
from webconf_audit.local.load_context import LoadContext
from webconf_audit.local.normalizers import normalize_config
from webconf_audit.local.universal_rules import run_universal_rules
from webconf_audit.models import AnalysisIssue, AnalysisResult, Finding, SourceLocation


@dataclass
class ApacheAnalysisContext:
    """One analyzable slice of an Apache configuration.

    For configs without VirtualHosts, there is a single global context.
    For configs with VirtualHosts, there is one context per VirtualHost.
    """

    label: str
    virtualhost: ApacheVirtualHostContext | None
    document_root: Path | None
    htaccess_files: list[HtaccessFile]
    effective_server_config: EffectiveConfig


def analyze_apache_config(config_path: str) -> AnalysisResult:
    path = Path(config_path)

    if not path.is_file():
        return _config_not_found_result(config_path)

    try:
        text = path.read_text(encoding="utf-8")
        ast, load_ctx, issues = _parse_apache_source(text, path)
        htaccess_result = discover_htaccess_files(ast, path)
        issues.extend(htaccess_result.issues)
        contexts = _build_analysis_contexts(ast, path.parent, htaccess_result.found)
        findings = _collect_apache_findings(ast, path.parent, contexts, issues)
    except UnicodeDecodeError as exc:
        return _apache_config_read_error_result(
            config_path,
            path,
            f"Cannot decode config file {config_path}: {exc}",
        )
    except OSError as exc:
        return _apache_config_read_error_result(
            config_path,
            path,
            f"Cannot read config file {config_path}: {exc}",
        )
    except ApacheParseError as exc:
        return _apache_parse_error_result(config_path, path, exc)

    return AnalysisResult(
        mode="local",
        target=config_path,
        server_type="apache",
        findings=findings,
        issues=issues,
        metadata=_analysis_metadata(load_ctx, htaccess_result, contexts),
    )


def _config_not_found_result(config_path: str) -> AnalysisResult:
    return AnalysisResult(
        mode="local",
        target=config_path,
        server_type="apache",
        issues=[
            AnalysisIssue(
                code="config_not_found",
                level="error",
                message=f"Config file not found: {config_path}",
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=config_path,
                ),
            )
        ],
    )


def _parse_apache_source(
    text: str,
    path: Path,
) -> tuple[ApacheConfigAst, LoadContext, list[AnalysisIssue]]:
    tokens = ApacheTokenizer(text, file_path=str(path)).tokenize()
    ast = ApacheParser(tokens).parse()
    load_ctx = LoadContext(root_file=str(path))
    issues = resolve_includes(ast, path, load_context=load_ctx)
    return ast, load_ctx, issues


def _collect_apache_findings(
    ast: ApacheConfigAst,
    config_dir: Path,
    contexts: list[ApacheAnalysisContext],
    issues: list[AnalysisIssue],
) -> list[Finding]:
    findings = run_apache_ast_rules(ast, issues=issues)
    findings.extend(_context_htaccess_findings(ast, contexts, config_dir, issues))
    findings.extend(_universal_apache_findings(ast, config_dir, issues))
    return findings


def _context_htaccess_findings(
    ast: ApacheConfigAst,
    contexts: list[ApacheAnalysisContext],
    config_dir: Path,
    issues: list[AnalysisIssue],
) -> list[Finding]:
    findings: list[Finding] = []
    seen_findings: set[tuple[str, str | None, int | None]] = set()

    for context in contexts:
        context_findings = run_apache_htaccess_rules(
            ast,
            htaccess_files=context.htaccess_files,
            config_dir=config_dir,
            issues=issues,
        )
        for finding in context_findings:
            key = _finding_key(finding)
            if key in seen_findings:
                continue
            seen_findings.add(key)
            findings.append(finding)

    return findings


def _finding_key(finding: Finding) -> tuple[str, str | None, int | None]:
    return (
        finding.rule_id,
        finding.location.file_path if finding.location else None,
        finding.location.line if finding.location else None,
    )


def _universal_apache_findings(
    ast: ApacheConfigAst,
    config_dir: Path,
    issues: list[AnalysisIssue],
) -> list[Finding]:
    normalized = normalize_config(
        "apache",
        ast=ast,
        effective_config={"config_dir": config_dir},
    )
    return run_universal_rules(normalized, issues=issues)


def _analysis_metadata(
    load_ctx: LoadContext,
    htaccess_result: HtaccessDiscoveryResult,
    contexts: list[ApacheAnalysisContext],
) -> dict[str, object]:
    metadata: dict[str, object] = {"load_context": load_ctx.to_dict()}
    if htaccess_result.found:
        metadata["htaccess_files"] = htaccess_result.found
    metadata["analysis_contexts"] = [_context_metadata(ctx) for ctx in contexts]
    return metadata


def _apache_config_read_error_result(
    config_path: str,
    path: Path,
    message: str,
) -> AnalysisResult:
    return AnalysisResult(
        mode="local",
        target=config_path,
        server_type="apache",
        issues=[
            AnalysisIssue(
                code="apache_config_read_error",
                level="error",
                message=message,
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=str(path),
                ),
            )
        ],
    )


def _apache_parse_error_result(
    config_path: str,
    path: Path,
    exc: ApacheParseError,
) -> AnalysisResult:
    return AnalysisResult(
        mode="local",
        target=config_path,
        server_type="apache",
        issues=[
            AnalysisIssue(
                code="apache_parse_error",
                level="error",
                message=str(exc),
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=exc.file_path or str(path),
                    line=exc.line,
                ),
            )
        ],
    )


def _build_analysis_contexts(
    config_ast: ApacheConfigAst,
    config_dir: Path,
    all_htaccess: list[HtaccessFile],
) -> list[ApacheAnalysisContext]:
    """Build per-VirtualHost (or global) analysis contexts."""
    vhosts = extract_virtualhost_contexts(config_ast)

    if not vhosts:
        doc_root = extract_document_root(config_ast, config_dir=config_dir)
        effective = build_server_effective_config(config_ast)
        return [
            ApacheAnalysisContext(
                label="global",
                virtualhost=None,
                document_root=doc_root,
                htaccess_files=all_htaccess,
                effective_server_config=effective,
            )
        ]

    contexts: list[ApacheAnalysisContext] = []
    for vhost in vhosts:
        doc_root = extract_document_root(
            config_ast, virtualhost_context=vhost, config_dir=config_dir,
        )
        effective = build_server_effective_config(
            config_ast, virtualhost_context=vhost,
        )
        ctx_htaccess = _filter_htaccess_for_context(all_htaccess, vhost, doc_root)
        label = vhost.server_name or vhost.listen_address or "<default>"
        contexts.append(
            ApacheAnalysisContext(
                label=label,
                virtualhost=vhost,
                document_root=doc_root,
                htaccess_files=ctx_htaccess,
                effective_server_config=effective,
            )
        )
    return contexts


def _filter_htaccess_for_context(
    all_htaccess: list[HtaccessFile],
    vhost: ApacheVirtualHostContext,
    document_root: Path | None,
) -> list[HtaccessFile]:
    """Filter htaccess files to those belonging to a VirtualHost context.

    Includes htaccess files that were discovered inside the VirtualHost block,
    plus global htaccess files whose directory falls under the VirtualHost's
    effective DocumentRoot.
    """
    result: list[HtaccessFile] = []
    for h in all_htaccess:
        if h.source_virtualhost_block is vhost.node:
            result.append(h)
            continue
        if h.source_virtualhost_block is None and document_root is not None:
            if _path_is_under(h.directory_path, document_root):
                result.append(h)
    return result


def _path_is_under(child_path_str: str, parent: Path) -> bool:
    """Check if a path is under a parent directory."""
    try:
        child_resolved = str(Path(child_path_str).resolve()).replace("\\", "/").rstrip("/").lower()
        parent_resolved = str(parent.resolve()).replace("\\", "/").rstrip("/").lower()
        return child_resolved == parent_resolved or child_resolved.startswith(parent_resolved + "/")
    except (OSError, ValueError):
        return False


def _context_metadata(ctx: ApacheAnalysisContext) -> dict[str, object]:
    """Serialize an analysis context for result metadata."""
    return {
        "label": ctx.label,
        "virtualhost": ctx.virtualhost is not None,
        "document_root": str(ctx.document_root) if ctx.document_root else None,
        "htaccess_count": len(ctx.htaccess_files),
        "effective_directive_count": len(ctx.effective_server_config.directives),
    }


__all__ = ["ApacheAnalysisContext", "analyze_apache_config", "run_apache_rules"]
