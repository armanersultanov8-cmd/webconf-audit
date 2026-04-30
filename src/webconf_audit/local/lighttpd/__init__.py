from __future__ import annotations

from os import PathLike
from pathlib import Path

from webconf_audit.local.lighttpd.conditions import LighttpdRequestContext
from webconf_audit.local.lighttpd.effective import build_effective_config, merge_conditional_scopes
from webconf_audit.local.lighttpd.include import resolve_includes
from webconf_audit.local.lighttpd.parser import LighttpdParseError, LighttpdParser
from webconf_audit.local.lighttpd.rules_runner import run_lighttpd_rules
from webconf_audit.local.lighttpd.variables import expand_variables
from webconf_audit.local.load_context import LoadContext
from webconf_audit.local.normalizers import normalize_config
from webconf_audit.local.universal_rules import run_universal_rules
from webconf_audit.models import AnalysisIssue, AnalysisResult, SourceLocation


def analyze_lighttpd_config(
    config_path: str | PathLike[str],
    execute_shell: bool = False,
    host: str | None = None,
) -> AnalysisResult:
    config_path_str = str(config_path)
    path = Path(config_path_str)

    if not path.is_file():
        return AnalysisResult(
            mode="local",
            target=config_path_str,
            server_type="lighttpd",
            issues=[
                AnalysisIssue(
                    code="config_not_found",
                    level="error",
                    message=f"Config file not found: {config_path_str}",
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path=config_path_str,
                    ),
                )
            ],
        )

    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return AnalysisResult(
            mode="local",
            target=config_path_str,
            server_type="lighttpd",
            issues=[
                AnalysisIssue(
                    code="lighttpd_config_read_error",
                    level="error",
                    message=f"Cannot read config file: {exc}",
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path=str(path),
                    ),
                )
            ],
        )

    try:
        ast = LighttpdParser(text, file_path=str(path)).parse()
        load_ctx = LoadContext(root_file=str(path))
        issues = resolve_includes(
            ast,
            path,
            load_context=load_ctx,
            execute_shell=execute_shell,
        )
        issues.extend(expand_variables(ast))
        effective = build_effective_config(ast)

        context = LighttpdRequestContext(host=host) if host is not None else None
        merged_directives = merge_conditional_scopes(effective, context=context)

        findings = run_lighttpd_rules(
            ast,
            effective_config=effective,
            merged_directives=merged_directives,
            issues=issues,
        )
        normalized = normalize_config(
            "lighttpd", ast=ast, effective_config=effective,
            merged_directives=merged_directives,
        )
        findings.extend(run_universal_rules(normalized, issues=issues))
    except LighttpdParseError as exc:
        return AnalysisResult(
            mode="local",
            target=config_path_str,
            server_type="lighttpd",
            issues=[
                AnalysisIssue(
                    code="lighttpd_parse_error",
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

    return AnalysisResult(
        mode="local",
        target=config_path_str,
        server_type="lighttpd",
        findings=findings,
        issues=issues,
        metadata={
            "load_context": load_ctx.to_dict(),
            "host_filter": host,
        },
    )


__all__ = ["analyze_lighttpd_config"]
