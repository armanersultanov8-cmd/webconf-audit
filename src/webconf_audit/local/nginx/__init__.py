from pathlib import Path

from webconf_audit.local.load_context import LoadContext
from webconf_audit.local.nginx.include import resolve_includes
from webconf_audit.local.nginx.parser.parser import NginxParseError, NginxParser, NginxTokenizer
from webconf_audit.local.nginx.rules_runner import run_nginx_rules
from webconf_audit.local.normalizers import normalize_config
from webconf_audit.local.universal_rules import run_universal_rules
from webconf_audit.models import AnalysisIssue, AnalysisResult, SourceLocation


def analyze_nginx_config(config_path: str) -> AnalysisResult:
    path = Path(config_path)

    if not path.is_file():
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
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

    try:
        text = read_text_file(config_path)
    except (OSError, UnicodeDecodeError) as exc:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
            issues=[
                AnalysisIssue(
                    code="nginx_config_read_error",
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
        tokens = NginxTokenizer(text, file_path=str(path)).tokenize()
        ast = NginxParser(tokens).parse()
    except NginxParseError as exc:
        error_path = getattr(exc, "file_path", str(path))
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
            issues=[
                AnalysisIssue(
                    code="nginx_parse_error",
                    level="error",
                    message=str(exc),
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path=error_path,
                        line=getattr(exc, "line", None),
                    ),
                )
            ],
        )

    load_ctx = LoadContext(root_file=str(path))
    issues = resolve_includes(ast, path, load_context=load_ctx)
    findings = run_nginx_rules(ast, issues=issues)
    normalized = normalize_config("nginx", ast=ast)
    findings.extend(run_universal_rules(normalized, issues=issues))

    return AnalysisResult(
        mode="local",
        target=config_path,
        server_type="nginx",
        findings=findings,
        issues=issues,
        metadata={"load_context": load_ctx.to_dict()},
    )


def read_text_file(path: str) -> str:
    file_path = Path(path)
    return file_path.read_text(encoding="utf-8")
