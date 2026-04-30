import threading
from pathlib import Path

from webconf_audit.local.load_context import LoadContext
from webconf_audit.local.nginx import analyze_nginx_config
from webconf_audit.local.nginx.include import resolve_includes
from webconf_audit.local.nginx.parser.parser import NginxParser, NginxTokenizer
from webconf_audit.models import AnalysisResult


# pipeline error handling
def test_analyze_nginx_config_returns_issue_when_config_not_found(tmp_path: Path) -> None:
    missing_config = tmp_path / "missing.conf"

    result = analyze_nginx_config(str(missing_config))

    assert isinstance(result, AnalysisResult)
    assert result.mode == "local"
    assert result.target == str(missing_config)
    assert result.server_type == "nginx"
    assert result.findings == []
    assert len(result.issues) == 1

    issue = result.issues[0]
    assert issue.code == "config_not_found"
    assert issue.message == f"Config file not found: {missing_config}"
    assert issue.location is not None
    assert issue.location.mode == "local"
    assert issue.location.kind == "file"
    assert issue.location.file_path == str(missing_config)


def test_analyze_nginx_config_returns_issue_when_parsing_fails(tmp_path: Path) -> None:
    config_path = tmp_path / "invalid.conf"
    config_path.write_text("worker_processes 1\n", encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.mode == "local"
    assert result.target == str(config_path)
    assert result.server_type == "nginx"
    assert result.findings == []
    assert len(result.issues) == 1

    issue = result.issues[0]
    assert issue.code == "nginx_parse_error"
    assert issue.message == "Expected ';' or '{'"
    assert issue.location is not None
    assert issue.location.mode == "local"
    assert issue.location.kind == "file"
    assert issue.location.file_path == str(config_path)
    assert issue.location.line == 1


# happy path / basic analysis
def test_analyze_nginx_config_returns_empty_result_for_existing_file(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text("worker_processes 1;\n", encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.mode == "local"
    assert result.target == str(config_path)
    assert result.server_type == "nginx"
    assert result.findings == []
    assert result.issues == []


# include resolution
def test_analyze_nginx_config_resolves_simple_relative_include(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    include_path = tmp_path / "extra.conf"

    config_path.write_text("include extra.conf;\nworker_processes 1;\n", encoding="utf-8")
    include_path.write_text("events {}\n", encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.mode == "local"
    assert result.target == str(config_path)
    assert result.server_type == "nginx"
    assert result.findings == []
    assert result.issues == []


def test_analyze_nginx_config_resolves_glob_include(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    conf_dir = tmp_path / "conf.d"
    conf_dir.mkdir()

    config_path.write_text("include conf.d/*.conf;\nworker_processes 1;\n", encoding="utf-8")
    (conf_dir / "a.conf").write_text("events {}\n", encoding="utf-8")
    (conf_dir / "b.conf").write_text("http {}\n", encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.mode == "local"
    assert result.target == str(config_path)
    assert result.server_type == "nginx"
    assert result.findings == []
    assert result.issues == []


def test_analyze_nginx_config_resolves_absolute_include(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    include_path = tmp_path / "extra.conf"

    config_path.write_text(
        f'include "{include_path.as_posix()}";\n',
        encoding="utf-8",
    )
    include_path.write_text("http {\n    server_tokens on;\n}\n", encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert any(finding.rule_id == "nginx.server_tokens_on" for finding in result.findings)


def test_resolve_includes_inlines_include_inside_http_block(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    include_path = tmp_path / "extra.conf"

    config_path.write_text("http {\n    include extra.conf;\n}\n", encoding="utf-8")
    include_path.write_text("gzip on;\n", encoding="utf-8")

    tokens = NginxTokenizer(
        config_path.read_text(encoding="utf-8"), file_path=str(config_path)
    ).tokenize()
    ast = NginxParser(tokens).parse()

    resolve_includes(ast, config_path)

    assert len(ast.nodes) == 1
    http_block = ast.nodes[0]
    assert http_block.node_type == "block"
    assert http_block.name == "http"
    assert len(http_block.children) == 1
    child = http_block.children[0]
    assert child.node_type == "directive"
    assert child.name == "gzip"
    assert child.args == ["on"]


def test_resolve_includes_normalizes_load_context_paths(tmp_path: Path) -> None:
    config_dir = tmp_path / "conf"
    config_dir.mkdir()
    include_dir = tmp_path / "shared"
    include_dir.mkdir()

    config_path = config_dir / "nginx.conf"
    include_path = include_dir / "common.conf"
    config_path.write_text(
        "include ../shared/../shared/common.conf;\nworker_processes 1;\n",
        encoding="utf-8",
    )
    include_path.write_text("events {}\n", encoding="utf-8")

    tokens = NginxTokenizer(
        config_path.read_text(encoding="utf-8"),
        file_path=str(config_path),
    ).tokenize()
    ast = NginxParser(tokens).parse()
    load_context = LoadContext(root_file=str(config_path.resolve(strict=False)))

    issues = resolve_includes(ast, config_path, load_context=load_context)

    assert issues == []
    assert len(load_context.edges) == 1
    edge = load_context.edges[0]
    assert edge.source_file == str(config_path.resolve(strict=False))
    assert edge.target_file == str(include_path.resolve(strict=False))


def test_analyze_nginx_config_reports_issue_for_self_include_cycle(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text("include nginx.conf;\n", encoding="utf-8")

    result_holder: dict[str, AnalysisResult] = {}
    error_holder: dict[str, BaseException] = {}

    def run_analysis() -> None:
        try:
            result_holder["result"] = analyze_nginx_config(str(config_path))
        except BaseException as exc:
            error_holder["error"] = exc

    thread = threading.Thread(target=run_analysis, daemon=True)
    thread.start()
    thread.join(timeout=1)

    assert not thread.is_alive(), "analyze_nginx_config hung on self-include"
    assert "error" not in error_holder

    result = result_holder["result"]
    assert isinstance(result, AnalysisResult)
    assert result.issues

    issue = result.issues[0]
    assert issue.code == "nginx_include_self_include"
    assert issue.location is not None
    assert issue.location.file_path == str(config_path)


def test_analyze_nginx_config_reports_issue_for_self_include_via_glob(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text("include *.conf;\n", encoding="utf-8")

    result_holder: dict[str, AnalysisResult] = {}
    error_holder: dict[str, BaseException] = {}

    def run_analysis() -> None:
        try:
            result_holder["result"] = analyze_nginx_config(str(config_path))
        except BaseException as exc:
            error_holder["error"] = exc

    thread = threading.Thread(target=run_analysis, daemon=True)
    thread.start()
    thread.join(timeout=1)

    assert not thread.is_alive(), "analyze_nginx_config hung on self-include via glob"
    assert "error" not in error_holder

    result = result_holder["result"]
    assert isinstance(result, AnalysisResult)
    assert result.issues

    issue = result.issues[0]
    assert issue.code == "nginx_include_self_include"
    assert issue.location is not None
    assert issue.location.file_path == str(config_path)


def test_analyze_nginx_config_reports_issue_for_self_include_via_relative_path(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text("include ./nginx.conf;\n", encoding="utf-8")

    result_holder: dict[str, AnalysisResult] = {}
    error_holder: dict[str, BaseException] = {}

    def run_analysis() -> None:
        try:
            result_holder["result"] = analyze_nginx_config(str(config_path))
        except BaseException as exc:
            error_holder["error"] = exc

    thread = threading.Thread(target=run_analysis, daemon=True)
    thread.start()
    thread.join(timeout=1)

    assert not thread.is_alive(), "analyze_nginx_config hung on self-include via relative path"
    assert "error" not in error_holder

    result = result_holder["result"]
    assert isinstance(result, AnalysisResult)
    assert result.issues

    issue = result.issues[0]
    assert issue.code == "nginx_include_self_include"
    assert issue.location is not None
    assert issue.location.file_path == str(config_path)


def test_analyze_nginx_config_reports_issue_for_self_include_via_normalized_path(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    (tmp_path / "subdir").mkdir()
    config_path.write_text("include subdir/../nginx.conf;\n", encoding="utf-8")

    result_holder: dict[str, AnalysisResult] = {}
    error_holder: dict[str, BaseException] = {}

    def run_analysis() -> None:
        try:
            result_holder["result"] = analyze_nginx_config(str(config_path))
        except BaseException as exc:
            error_holder["error"] = exc

    thread = threading.Thread(target=run_analysis, daemon=True)
    thread.start()
    thread.join(timeout=1)

    assert not thread.is_alive(), "analyze_nginx_config hung on self-include via normalized path"
    assert "error" not in error_holder

    result = result_holder["result"]
    assert isinstance(result, AnalysisResult)
    assert result.issues

    issue = result.issues[0]
    assert issue.code == "nginx_include_self_include"
    assert issue.location is not None
    assert issue.location.file_path == str(config_path)


def test_analyze_nginx_config_resolves_nested_include_from_included_file(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    conf_dir = tmp_path / "conf.d"
    conf_dir.mkdir()

    config_path.write_text("include conf.d/a.conf;\n", encoding="utf-8")
    (conf_dir / "a.conf").write_text("include b.conf;\n", encoding="utf-8")
    (conf_dir / "b.conf").write_text("server_tokens on;\n", encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "nginx.server_tokens_on"


def test_analyze_nginx_config_reports_missing_include_and_continues_analysis(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "include missing.conf;\n"
        "http {\n"
        "    server_tokens on;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert {issue.code for issue in result.issues} == {"nginx_include_not_found"}
    assert "nginx.server_tokens_on" in {finding.rule_id for finding in result.findings}


def test_analyze_nginx_config_reports_include_parse_error_and_continues_analysis(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    include_path = tmp_path / "broken.conf"
    config_path.write_text(
        "include broken.conf;\n"
        "http {\n"
        "    server_tokens on;\n"
        "}\n",
        encoding="utf-8",
    )
    include_path.write_text("events {\n", encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert {issue.code for issue in result.issues} == {"nginx_include_parse_error"}
    assert "nginx.server_tokens_on" in {finding.rule_id for finding in result.findings}


def test_analyze_nginx_config_reports_issue_for_mutual_include_cycle(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    conf_dir = tmp_path / "conf.d"
    conf_dir.mkdir()

    config_path.write_text("include conf.d/a.conf;\n", encoding="utf-8")
    (conf_dir / "a.conf").write_text("include b.conf;\n", encoding="utf-8")
    (conf_dir / "b.conf").write_text("include a.conf;\n", encoding="utf-8")

    result_holder: dict[str, AnalysisResult] = {}
    error_holder: dict[str, BaseException] = {}

    def run_analysis() -> None:
        try:
            result_holder["result"] = analyze_nginx_config(str(config_path))
        except BaseException as exc:
            error_holder["error"] = exc

    thread = threading.Thread(target=run_analysis, daemon=True)
    thread.start()
    thread.join(timeout=1)

    assert not thread.is_alive(), "analyze_nginx_config hung on mutual include cycle"
    assert "error" not in error_holder

    result = result_holder["result"]
    assert isinstance(result, AnalysisResult)
    assert result.issues

    issue = result.issues[0]
    assert issue.code == "nginx_include_cycle"


# nginx rules
def _safe_server_block(*directives: str) -> str:
    safe_directives = (
        "server_name example.com;",
        "add_header X-Content-Type-Options nosniff;",
        "add_header X-Frame-Options DENY;",
        "add_header Referrer-Policy no-referrer;",
        "add_header Content-Security-Policy \"default-src 'self'\";",
        "add_header Permissions-Policy geolocation=();",
        'add_header X-XSS-Protection "1; mode=block";',
        "client_max_body_size 10m;",
        "client_body_timeout 10s;",
        "client_header_timeout 10s;",
        "send_timeout 10s;",
        "keepalive_timeout 10s;",
        "limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;",
        "limit_req zone=perip burst=10;",
        "limit_conn_zone $binary_remote_addr zone=addr:10m;",
        "limit_conn addr 10;",
        'log_format main "$remote_addr";',
        "access_log /var/log/nginx/access.log;",
        "error_log /var/log/nginx/error.log warn;",
        "location ~ /\\. {",
        "    deny all;",
        "}",
        "location ~ \\.(bak|old|backup|orig|save)$ {",
        "    deny all;",
        "}",
        "location ~ ~$ {",
        "    deny all;",
        "}",
    )
    lines = directives + safe_directives

    return "server {\n" + "".join(f"    {line}\n" for line in lines) + "}\n"


def _http_block(*blocks: str) -> str:
    content = "".join("".join(f"    {line}\n" for line in block.splitlines()) for block in blocks)

    return f"http {{\n{content}}}\n"


def test_analyze_nginx_config_reports_duplicate_listen_in_same_server(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _http_block(
            _safe_server_block(
                "listen 80;",
                "listen 80;",
            )
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    server_findings = [f for f in result.findings if not f.rule_id.startswith("universal.")]
    assert len(server_findings) == 1

    finding = server_findings[0]
    assert finding.rule_id == "nginx.duplicate_listen"
    assert finding.title == "Duplicate listen directive"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 4


def test_analyze_nginx_config_does_not_report_when_listen_values_differ(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _http_block(
            _safe_server_block(
                "listen 80;",
                "listen 443;",
            )
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    server_findings = [f for f in result.findings if not f.rule_id.startswith("universal.")]
    assert server_findings == []


def test_analyze_nginx_config_reports_server_tokens_on(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text("http {\n    server_tokens on;\n}\n", encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert len(result.findings) == 1

    finding = result.findings[0]
    assert finding.rule_id == "nginx.server_tokens_on"
    assert finding.title == "Server tokens enabled"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 2


def test_analyze_nginx_config_does_not_report_server_tokens_off(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text("http {\n    server_tokens off;\n}\n", encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert result.findings == []


def test_analyze_nginx_config_reports_autoindex_on(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text("location /listing/ {\n    autoindex on;\n}\n", encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert len(result.findings) == 1

    finding = result.findings[0]
    assert finding.rule_id == "nginx.autoindex_on"
    assert finding.title == "Autoindex enabled"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 2


def test_analyze_nginx_config_does_not_report_autoindex_off(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text("location /listing/ {\n    autoindex off;\n}\n", encoding="utf-8")

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert result.findings == []


def test_analyze_nginx_config_reports_alias_without_trailing_slash(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "location /static/ {\n    alias /srv/static;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert len(result.findings) == 1

    finding = result.findings[0]
    assert finding.rule_id == "nginx.alias_without_trailing_slash"
    assert finding.title == "Alias path missing trailing slash"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 2


def test_analyze_nginx_config_does_not_report_alias_with_trailing_slash(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "location /static/ {\n    alias /srv/static/;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert result.findings == []


def test_analyze_nginx_config_reports_executable_scripts_allowed_in_uploads(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /uploads {",
            "    root /srv/www;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []

    finding = next(
        finding
        for finding in result.findings
        if finding.rule_id == "nginx.executable_scripts_allowed_in_uploads"
    )
    assert finding.rule_id == "nginx.executable_scripts_allowed_in_uploads"
    assert finding.title == "Executable scripts allowed in upload-like location"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 3


def test_analyze_nginx_config_does_not_report_executable_scripts_in_uploads_when_php_is_blocked(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /uploads {",
            "    root /srv/www;",
            "    location ~ \\.php$ {",
            "        return 403;",
            "    }",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.executable_scripts_allowed_in_uploads"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_executable_scripts_in_uploads_when_scripts_are_denied(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /files {",
            "    root /srv/www;",
            "    location ~ \\.sh$ {",
            "        deny all;",
            "    }",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.executable_scripts_allowed_in_uploads"
        for finding in result.findings
    )


def test_analyze_nginx_config_respects_sibling_upload_script_deny(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /uploads {",
            "    root /srv/www;",
            "}",
            "location ~ ^/uploads/.*\\.php$ {",
            "    deny all;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.executable_scripts_allowed_in_uploads"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_executable_scripts_for_root_location(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location / {",
            "    root /srv/www;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert result.findings == []


def test_analyze_nginx_config_reports_executable_scripts_allowed_in_media_location(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /media {",
            "    root /srv/www;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.executable_scripts_allowed_in_uploads"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_http_method_restrictions_for_admin(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /admin {",
            "    proxy_pass http://backend;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_http_method_restrictions"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_http_method_restrictions_when_limit_except_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /admin {",
            "    proxy_pass http://backend;",
            "    limit_except GET POST {",
            "        deny all;",
            "    }",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_http_method_restrictions"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_http_method_restrictions_for_root_location(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location / {",
            "    proxy_pass http://backend;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert result.findings == []


def test_analyze_nginx_config_reports_missing_http_method_restrictions_for_api(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /api {",
            "    proxy_pass http://backend;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_http_method_restrictions"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_access_restrictions_on_admin_location(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /admin {",
            "    proxy_pass http://backend;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_access_restrictions_on_sensitive_locations"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_access_restrictions_when_allow_and_deny_are_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /admin {",
            "    allow 10.0.0.0/8;",
            "    deny all;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_access_restrictions_on_sensitive_locations"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_access_restrictions_when_auth_basic_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /admin {",
            '    auth_basic "Restricted";',
            "    auth_basic_user_file /etc/nginx/.htpasswd;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_access_restrictions_on_sensitive_locations"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_access_restrictions_when_auth_basic_is_inherited(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            'auth_basic "Restricted";',
            "auth_basic_user_file /etc/nginx/.htpasswd;",
            "location /admin {",
            "    proxy_pass http://backend;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_access_restrictions_on_sensitive_locations"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_access_restrictions_when_allow_all_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /admin {",
            "    allow all;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_access_restrictions_on_sensitive_locations"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_access_restrictions_when_auth_basic_is_off(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /admin {",
            "    auth_basic off;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_access_restrictions_on_sensitive_locations"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_auth_basic_user_file_in_location(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /protected {",
            '    auth_basic "Restricted";',
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_auth_basic_user_file" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_auth_basic_user_file_in_location_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /protected {",
            '    auth_basic "Restricted";',
            "    auth_basic_user_file /etc/nginx/.htpasswd;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_auth_basic_user_file" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_auth_basic_user_file_in_server(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            'auth_basic "Restricted";',
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_auth_basic_user_file" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_auth_basic_user_file_when_auth_basic_is_absent(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /protected {",
            "    return 204;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_auth_basic_user_file" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_access_restrictions_for_root_location(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location / {",
            "    proxy_pass http://backend;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_access_restrictions_on_sensitive_locations"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_allowed_methods_restriction_for_uploads(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /uploads {",
            "    root /srv/www;",
            "    location ~ \\.php$ {",
            "        return 403;",
            "    }",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_allowed_methods_restriction_for_uploads"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_allowed_methods_restriction_for_uploads_when_limit_except_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /uploads {",
            "    root /srv/www;",
            "    location ~ \\.php$ {",
            "        return 403;",
            "    }",
            "    limit_except GET POST {",
            "        deny all;",
            "    }",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_allowed_methods_restriction_for_uploads"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_allowed_methods_restriction_for_root_location(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location / {",
            "    root /srv/www;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_allowed_methods_restriction_for_uploads"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_allowed_methods_restriction_for_files(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 80;",
            "location /files {",
            "    root /srv/www;",
            "    location ~ \\.sh$ {",
            "        deny all;",
            "    }",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_allowed_methods_restriction_for_uploads"
        for finding in result.findings
    )


def test_analyze_nginx_config_reports_allow_all_with_deny_all_in_same_location(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "location /protected/ {\n    allow all;\n    deny all;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert len(result.findings) == 1

    finding = result.findings[0]
    assert finding.rule_id == "nginx.allow_all_with_deny_all"
    assert finding.title == "Conflicting allow/deny all directives"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 1


def test_analyze_nginx_config_does_not_report_when_only_one_access_rule_targets_all(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "location /protected/ {\n    allow all;\n    deny 10.0.0.0/8;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert result.findings == []


def test_analyze_nginx_config_reports_if_inside_location(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "location /app {",
            "    if ($deny) {",
            "        return 403;",
            "    }",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []

    finding = next(
        finding for finding in result.findings if finding.rule_id == "nginx.if_in_location"
    )
    assert finding.rule_id == "nginx.if_in_location"
    assert finding.title == "if inside location block"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 3


def test_analyze_nginx_config_does_not_report_if_outside_location(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "if ($deny) {",
            "    return 403;",
            "}",
            "location /app {",
            "    proxy_pass http://backend;",
            "}",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert result.findings == []


def test_analyze_nginx_config_reports_missing_ssl_ciphers_when_listen_uses_ssl(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 443 ssl http2;",
            "ssl_certificate cert.pem;",
            "ssl_certificate_key cert.key;",
            'add_header Strict-Transport-Security "max-age=31536000";',
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert len(result.findings) == 1

    finding = result.findings[0]
    assert finding.rule_id == "nginx.missing_ssl_ciphers"
    assert finding.title == "Missing ssl_ciphers directive"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 1


def test_analyze_nginx_config_reports_missing_ssl_ciphers_when_ssl_protocols_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "ssl_protocols TLSv1.2 TLSv1.3;",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "nginx.missing_ssl_ciphers"


def test_analyze_nginx_config_does_not_report_missing_ssl_ciphers_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 443 ssl http2;",
            "ssl_certificate cert.pem;",
            "ssl_certificate_key cert.key;",
            "ssl_ciphers HIGH:!aNULL:!MD5;",
            "ssl_prefer_server_ciphers on;",
            'add_header Strict-Transport-Security "max-age=31536000";',
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert result.findings == []


def test_analyze_nginx_config_does_not_report_missing_ssl_certificate_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_ssl_certificate" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_ssl_certificate_for_non_tls_server(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_ssl_certificate" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_ssl_certificate_when_only_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    location / {\n"
        "        ssl_certificate cert.pem;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_ssl_certificate" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_ssl_certificate_key_when_ssl_certificate_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_ssl_certificate_key" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_ssl_certificate_key_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_ssl_certificate_key" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_ssl_certificate_key_for_non_tls_server(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    ssl_certificate cert.pem;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_ssl_certificate_key" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_ssl_certificate_key_when_only_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    location / {\n"
        "        ssl_certificate_key cert.key;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_ssl_certificate_key" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_ssl_prefer_server_ciphers_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_ssl_prefer_server_ciphers" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_ssl_prefer_server_ciphers_when_off(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    ssl_prefer_server_ciphers off;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_ssl_prefer_server_ciphers" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_ssl_prefer_server_ciphers_when_on(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    ssl_prefer_server_ciphers on;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_ssl_prefer_server_ciphers" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_ssl_prefer_server_ciphers_for_non_tls_server(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    ssl_ciphers HIGH:!aNULL:!MD5;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_ssl_prefer_server_ciphers" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_ssl_prefer_server_ciphers_when_only_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    location / {\n"
        "        ssl_prefer_server_ciphers on;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_ssl_prefer_server_ciphers" for finding in result.findings
    )


def test_analyze_nginx_config_reports_ssl_stapling_without_verify_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    ssl_prefer_server_ciphers on;\n"
        "    ssl_stapling on;\n"
        "    resolver 1.1.1.1;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.ssl_stapling_without_verify" for finding in result.findings
    )


def test_analyze_nginx_config_reports_ssl_stapling_without_verify_when_off(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    ssl_prefer_server_ciphers on;\n"
        "    ssl_stapling on;\n"
        "    ssl_stapling_verify off;\n"
        "    resolver 1.1.1.1;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.ssl_stapling_without_verify" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_ssl_stapling_without_verify_when_on(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    ssl_prefer_server_ciphers on;\n"
        "    ssl_stapling on;\n"
        "    ssl_stapling_verify on;\n"
        "    resolver 1.1.1.1;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.ssl_stapling_without_verify" for finding in result.findings
    )


def test_analyze_nginx_config_uses_last_ssl_stapling_verify_value(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    ssl_prefer_server_ciphers on;\n"
        "    ssl_stapling on;\n"
        "    ssl_stapling_verify off;\n"
        "    ssl_stapling_verify on;\n"
        "    resolver 1.1.1.1;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.ssl_stapling_without_verify" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_ssl_stapling_without_verify_for_non_tls_server(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    ssl_stapling on;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.ssl_stapling_without_verify" for finding in result.findings
    )


def test_analyze_nginx_config_reports_ssl_stapling_without_verify_when_only_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    ssl_prefer_server_ciphers on;\n"
        "    ssl_stapling on;\n"
        "    resolver 1.1.1.1;\n"
        "    location / {\n"
        "        ssl_stapling_verify on;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.ssl_stapling_without_verify" for finding in result.findings
    )


def test_analyze_nginx_config_reports_ssl_stapling_missing_resolver_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    ssl_prefer_server_ciphers on;\n"
        "    ssl_stapling on;\n"
        "    ssl_stapling_verify on;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.ssl_stapling_missing_resolver" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_ssl_stapling_missing_resolver_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    ssl_prefer_server_ciphers on;\n"
        "    ssl_stapling on;\n"
        "    ssl_stapling_verify on;\n"
        "    resolver 1.1.1.1;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.ssl_stapling_missing_resolver" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_ssl_stapling_missing_resolver_for_non_tls_server(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    ssl_stapling on;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.ssl_stapling_missing_resolver" for finding in result.findings
    )


def test_analyze_nginx_config_reports_ssl_stapling_missing_resolver_when_only_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    ssl_ciphers HIGH:!aNULL:!MD5;\n"
        "    ssl_prefer_server_ciphers on;\n"
        "    ssl_stapling on;\n"
        "    ssl_stapling_verify on;\n"
        "    location / {\n"
        "        resolver 1.1.1.1;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.ssl_stapling_missing_resolver" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_hsts_header_for_tls_server(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_hsts_header" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_hsts_header_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        '    add_header Strict-Transport-Security "max-age=31536000";\n'
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_hsts_header" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_hsts_header_for_non_tls_server(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_hsts_header" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_hsts_header_when_only_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key cert.key;\n"
        "    location / {\n"
        '        add_header Strict-Transport-Security "max-age=31536000";\n'
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_hsts_header" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_x_content_type_options_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_x_content_type_options" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_x_content_type_options_when_wrong_value(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    add_header X-Content-Type-Options off;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_x_content_type_options" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_x_content_type_options_when_nosniff(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    add_header X-Content-Type-Options nosniff;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_x_content_type_options" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_x_content_type_options_when_only_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    location / {\n"
        "        add_header X-Content-Type-Options nosniff;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_x_content_type_options" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_x_frame_options_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_x_frame_options" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_x_frame_options_when_wrong_value(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    add_header X-Frame-Options off;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_x_frame_options" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_x_frame_options_when_deny(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    add_header X-Frame-Options DENY;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_x_frame_options" for finding in result.findings
    )


def test_analyze_nginx_config_matches_security_headers_case_insensitively(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    add_header x-frame-options DENY;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_x_frame_options" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_x_frame_options_when_sameorigin(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    add_header X-Frame-Options SAMEORIGIN;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_x_frame_options" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_x_frame_options_when_only_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    location / {\n"
        "        add_header X-Frame-Options DENY;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_x_frame_options" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_x_xss_protection_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_x_xss_protection" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_x_xss_protection_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        'server {\n    listen 80;\n    add_header X-XSS-Protection "1; mode=block";\n}\n',
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_x_xss_protection" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_x_xss_protection_when_only_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    location / {\n"
        '        add_header X-XSS-Protection "1; mode=block";\n'
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_x_xss_protection" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_server_name_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_server_name" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_server_name_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    server_name example.com;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_server_name" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_server_name_with_multiple_values(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    server_name example.com www.example.com;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_server_name" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_referrer_policy_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_referrer_policy" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_referrer_policy_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    add_header Referrer-Policy no-referrer;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_referrer_policy" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_referrer_policy_when_only_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    location / {\n"
        "        add_header Referrer-Policy no-referrer;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_referrer_policy" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_permissions_policy_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_permissions_policy" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_permissions_policy_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    add_header Permissions-Policy geolocation=();\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_permissions_policy" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_permissions_policy_when_only_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    location / {\n"
        "        add_header Permissions-Policy geolocation=();\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_permissions_policy" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_client_max_body_size_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_client_max_body_size" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_client_max_body_size_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    client_max_body_size 10m;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_client_max_body_size" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_client_body_timeout_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_client_body_timeout" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_client_body_timeout_when_10s_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    client_body_timeout 10s;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_client_body_timeout" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_client_body_timeout_when_60s_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    client_body_timeout 60s;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_client_body_timeout" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_client_body_timeout_when_declared_in_http(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n    client_body_timeout 10s;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_client_body_timeout" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_client_header_timeout_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_client_header_timeout" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_client_header_timeout_when_10s_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    client_header_timeout 10s;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_client_header_timeout" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_client_header_timeout_when_60s_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    client_header_timeout 60s;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_client_header_timeout" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_client_header_timeout_when_declared_in_http(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n    client_header_timeout 10s;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_client_header_timeout" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_send_timeout_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_send_timeout" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_send_timeout_when_10s_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    send_timeout 10s;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_send_timeout" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_send_timeout_when_60s_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    send_timeout 60s;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_send_timeout" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_send_timeout_when_declared_in_http(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n    send_timeout 10s;\n    server {\n        listen 80;\n    }\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_send_timeout" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_keepalive_timeout_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_keepalive_timeout" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_keepalive_timeout_when_10s_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    keepalive_timeout 10s;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_keepalive_timeout" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_keepalive_timeout_when_60s_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    keepalive_timeout 60s;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_keepalive_timeout" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_keepalive_timeout_when_declared_in_http(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n    keepalive_timeout 10s;\n    server {\n        listen 80;\n    }\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_keepalive_timeout" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_client_max_body_size_when_only_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    location / {\n        client_max_body_size 10m;\n    }\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_client_max_body_size" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_client_max_body_size_when_http_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n    client_max_body_size 10m;\n    server {\n        listen 80;\n    }\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_client_max_body_size" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_limit_req_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_limit_req" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_limit_conn_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    limit_req zone=perip burst=10;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_limit_conn" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_limit_conn_when_present_in_server(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    limit_req zone=perip burst=10;\n    limit_conn addr 10;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_limit_conn" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_limit_conn_when_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    limit_req zone=perip burst=10;\n"
        "    location / {\n"
        "        limit_conn addr 10;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_limit_conn" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_limit_conn_when_only_limit_req_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    limit_req zone=perip burst=10;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_limit_conn" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_limit_req_zone_when_limit_req_is_used(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    limit_req zone=perip burst=10;\n    limit_conn addr 10;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_limit_req_zone" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_limit_req_zone_when_limit_req_zone_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;\n"
        "    server {\n"
        "        listen 80;\n"
        "        limit_req zone=perip burst=10;\n"
        "        limit_conn addr 10;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_limit_req_zone" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_limit_req_zone_when_limit_req_is_absent(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    limit_conn addr 10;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_limit_req_zone" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_limit_req_zone_when_only_limit_req_zone_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;\n"
        "    server {\n"
        "        listen 80;\n"
        "        limit_conn addr 10;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_limit_req_zone" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_limit_conn_zone_when_limit_conn_is_used(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;\n    limit_req zone=perip burst=10;\n    limit_conn addr 10;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_limit_conn_zone" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_limit_conn_zone_when_limit_conn_zone_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;\n"
        "    limit_conn_zone $binary_remote_addr zone=addr:10m;\n"
        "    server {\n"
        "        listen 80;\n"
        "        limit_req zone=perip burst=10;\n"
        "        limit_conn addr 10;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_limit_conn_zone" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_limit_conn_zone_for_mismatched_zone(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    limit_conn_zone $binary_remote_addr zone=perip:10m;\n"
        "    server {\n"
        "        listen 80;\n"
        "        limit_conn addr 10;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert any(f.rule_id == "nginx.missing_limit_conn_zone" for f in result.findings)


def test_analyze_nginx_config_does_not_report_missing_limit_conn_zone_when_limit_conn_is_absent(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;\n    limit_req zone=perip burst=10;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_limit_conn_zone" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_limit_conn_zone_when_only_limit_conn_zone_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    limit_conn_zone $binary_remote_addr zone=addr:10m;\n"
        "    server {\n"
        "        listen 80;\n"
        "        limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;\n"
        "        limit_req zone=perip burst=10;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_limit_conn_zone" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_limit_req_when_present_in_server(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    limit_req zone=perip burst=10;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_limit_req" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_limit_req_when_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    location /api {\n"
        "        limit_req zone=perip burst=10;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_limit_req" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_limit_req_when_only_http_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n    limit_req zone=perip burst=10;\n    server {\n        listen 80;\n    }\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_limit_req" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_access_log_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_access_log" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_access_log_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    access_log /var/log/nginx/access.log;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_access_log" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_access_log_when_off(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    access_log off;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_access_log" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_access_log_when_only_http_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    access_log /var/log/nginx/access.log;\n"
        "    server {\n"
        "        listen 80;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_access_log" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_log_format_when_access_log_is_used(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    access_log /var/log/nginx/access.log;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_log_format" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_log_format_when_log_format_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        '    log_format main "$remote_addr";\n'
        "    server {\n"
        "        listen 80;\n"
        "        access_log /var/log/nginx/access.log;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_log_format" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_log_format_when_access_log_is_absent(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_log_format" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_log_format_when_only_log_format_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        'http {\n    log_format main "$remote_addr";\n}\n',
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_log_format" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_error_log_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_error_log" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_error_log_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    error_log /var/log/nginx/error.log warn;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(finding.rule_id == "nginx.missing_error_log" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_error_log_when_only_http_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    error_log /var/log/nginx/error.log warn;\n"
        "    server {\n"
        "        listen 80;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_error_log" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_hidden_files_deny_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_hidden_files_deny" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_hidden_files_deny_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    location ~ /\\. {\n        deny all;\n    }\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_hidden_files_deny" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_hidden_files_deny_for_well_known_pattern(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    location ~ /\\.(?!well-known) {\n"
        "        deny all;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_hidden_files_deny" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_hidden_files_deny_when_location_has_no_deny(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    location ~ /\\. {\n        return 404;\n    }\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_hidden_files_deny" for finding in result.findings)


def test_analyze_nginx_config_reports_missing_backup_file_deny_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    location / {\n"
        "        try_files $uri $uri/ =404;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(finding.rule_id == "nginx.missing_backup_file_deny" for finding in result.findings)


def test_analyze_nginx_config_does_not_report_missing_backup_file_deny_when_backup_extensions_are_denied(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    location ~ \\.(bak|old|orig|save)$ {\n"
        "        deny all;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_backup_file_deny" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_backup_file_deny_when_trailing_tilde_is_denied(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    location ~ ~$ {\n"
        "        deny all;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_backup_file_deny" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_backup_file_deny_when_location_returns_403(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    location ~ \\.(bak|old|orig|save)$ {\n"
        "        return 403;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_backup_file_deny" for finding in result.findings
    )


def test_analyze_nginx_config_checks_backup_file_deny_per_server(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    location ~ \\.(bak|old)$ { deny all; }\n"
        "}\n"
        "server {\n"
        "    listen 8080;\n"
        "    location / { try_files $uri =404; }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    findings = [
        f for f in result.findings if f.rule_id == "nginx.missing_backup_file_deny"
    ]
    assert len(findings) == 1
    assert findings[0].location is not None
    assert findings[0].location.line == 5


def test_analyze_nginx_config_reports_missing_content_security_policy_when_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_content_security_policy" for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_content_security_policy_when_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    add_header Content-Security-Policy \"default-src 'self'\";\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_content_security_policy" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_content_security_policy_when_only_location_has_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    location / {\n"
        "        add_header Content-Security-Policy \"default-src 'self'\";\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert any(
        finding.rule_id == "nginx.missing_content_security_policy" for finding in result.findings
    )


def test_analyze_nginx_config_reports_missing_http2_on_tls_listener(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 443 ssl;",
            'add_header Strict-Transport-Security "max-age=31536000";',
            "ssl_certificate /etc/ssl/cert.pem;",
            "ssl_certificate_key /etc/ssl/key.pem;",
            "ssl_ciphers HIGH:!aNULL:!MD5;",
            "ssl_prefer_server_ciphers on;",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert len(result.findings) == 1

    finding = result.findings[0]
    assert finding.rule_id == "nginx.missing_http2_on_tls_listener"
    assert finding.title == "TLS listener missing http2 parameter"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 2


def test_analyze_nginx_config_does_not_report_missing_http2_when_http2_is_present(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 443 ssl http2;",
            'add_header Strict-Transport-Security "max-age=31536000";',
            "ssl_certificate /etc/ssl/cert.pem;",
            "ssl_certificate_key /etc/ssl/key.pem;",
            "ssl_ciphers HIGH:!aNULL:!MD5;",
            "ssl_prefer_server_ciphers on;",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_http2_on_tls_listener"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_http2_when_server_http2_on(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "listen 443 ssl;",
            "http2 on;",
            'add_header Strict-Transport-Security "max-age=31536000";',
            "ssl_certificate /etc/ssl/cert.pem;",
            "ssl_certificate_key /etc/ssl/key.pem;",
            "ssl_ciphers HIGH:!aNULL:!MD5;",
            "ssl_prefer_server_ciphers on;",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "nginx.missing_http2_on_tls_listener"
        for finding in result.findings
    )


def test_analyze_nginx_config_does_not_report_missing_http2_for_port_80_listener(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block("listen 80;"),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert result.findings == []


def test_analyze_nginx_config_does_not_report_missing_http2_for_443_without_ssl(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block("listen 443;"),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert result.findings == []


def test_analyze_nginx_config_reports_ssl_protocols_with_tlsv1(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "ssl_protocols TLSv1 TLSv1.2;",
            "ssl_ciphers HIGH:!aNULL:!MD5;",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert len(result.findings) == 1

    finding = result.findings[0]
    assert finding.rule_id == "nginx.weak_ssl_protocols"
    assert finding.title == "Weak SSL/TLS protocols enabled"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 2


def test_analyze_nginx_config_reports_ssl_protocols_with_tlsv1_1(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;",
            "ssl_ciphers HIGH:!aNULL:!MD5;",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert len(result.findings) == 1

    finding = result.findings[0]
    assert finding.rule_id == "nginx.weak_ssl_protocols"
    assert finding.title == "Weak SSL/TLS protocols enabled"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 2


def test_analyze_nginx_config_does_not_report_ssl_protocols_with_modern_versions_only(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        _safe_server_block(
            "ssl_protocols TLSv1.2 TLSv1.3;",
            "ssl_ciphers HIGH:!aNULL:!MD5;",
        ),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.issues == []
    assert result.findings == []


def test_nginx_rule_pack_wiring_regression(tmp_path: Path) -> None:
    config = tmp_path / "nginx.conf"
    config.write_text(
        """
        http {
            server {
                listen 443 ssl;
                server_tokens on;
                ssl_protocols TLSv1 TLSv1.2;
                location / {
                    root html;
                }
            }
        }
        """.strip(),
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config))
    assert isinstance(result, AnalysisResult)
    assert result.issues == []

    rule_ids = {finding.rule_id for finding in result.findings}

    assert {
        "nginx.server_tokens_on",
        "nginx.weak_ssl_protocols",
        "nginx.missing_hsts_header",
        "nginx.missing_access_log",
        "nginx.missing_server_name",
        "nginx.missing_ssl_certificate",
        "nginx.missing_ssl_ciphers",
    } <= rule_ids
