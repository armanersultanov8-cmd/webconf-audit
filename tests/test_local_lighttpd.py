import re
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from webconf_audit.local.lighttpd import analyze_lighttpd_config
from webconf_audit.local.lighttpd.include import resolve_includes
from webconf_audit.local.lighttpd.parser import (
    LighttpdAssignmentNode,
    LighttpdBlockNode,
    LighttpdCondition,
    LighttpdDirectiveNode,
    LighttpdParseError,
    parse_lighttpd_config,
)
from webconf_audit.local.lighttpd.effective import build_effective_config
from webconf_audit.local.lighttpd.rules.mod_cgi_enabled import find_mod_cgi_enabled
from webconf_audit.local.lighttpd.rules.server_tag_not_blank import find_server_tag_not_blank
from webconf_audit.local.lighttpd.rules.ssl_engine_not_enabled import (
    find_ssl_engine_not_enabled,
)
from webconf_audit.local.normalizers.lighttpd_normalizer import _parse_header_tuple
from webconf_audit.local.lighttpd.shell import execute_include_shell
from webconf_audit.local.lighttpd.variables import _quote, expand_variables
from webconf_audit.models import AnalysisResult


def _fake_shell_include_result(result: str | None) -> Callable[..., str | None]:
    def _runner(*_args: object, **_kwargs: object) -> str | None:
        return result

    return _runner


def _raise_regex_error(*_args: object, **_kwargs: object) -> list[str]:
    raise re.error("malformed character range")


def _collect_mod_cgi(*_args: object, **_kwargs: object) -> set[str]:
    return {"mod_cgi"}


def test_parse_lighttpd_simple_config_preserves_source_locations() -> None:
    ast = parse_lighttpd_config(
        'server.document-root = "/var/www/html"\ninclude "conf.d/app.conf"\n',
        file_path="lighttpd.conf",
    )

    assert len(ast.nodes) == 2

    assignment = ast.nodes[0]
    assert isinstance(assignment, LighttpdAssignmentNode)
    assert assignment.name == "server.document-root"
    assert assignment.operator == "="
    assert assignment.value == '"/var/www/html"'
    assert assignment.source.file_path == "lighttpd.conf"
    assert assignment.source.line == 1

    directive = ast.nodes[1]
    assert isinstance(directive, LighttpdDirectiveNode)
    assert directive.name == "include"
    assert directive.args == ["conf.d/app.conf"]
    assert directive.source.file_path == "lighttpd.conf"
    assert directive.source.line == 2


def test_parse_lighttpd_reports_unterminated_quoted_string_on_start_line() -> None:
    with pytest.raises(LighttpdParseError) as exc_info:
        parse_lighttpd_config(
            'server.tag = "unterminated\nserver.port = 8080\n',
            file_path="lighttpd.conf",
        )

    assert exc_info.value.line == 1
    assert exc_info.value.file_path == "lighttpd.conf"


def test_parse_lighttpd_config_accepts_utf8_bom() -> None:
    ast = parse_lighttpd_config('\ufeffserver.tag = ""\n', file_path="lighttpd.conf")

    assert len(ast.nodes) == 1
    assignment = ast.nodes[0]
    assert isinstance(assignment, LighttpdAssignmentNode)
    assert assignment.name == "server.tag"
    assert assignment.source.file_path == "lighttpd.conf"
    assert assignment.source.line == 1


def test_ssl_engine_not_enabled_finding_uses_rule_metadata_defaults() -> None:
    ast = parse_lighttpd_config("server.port = 443\n", file_path="lighttpd.conf")

    finding = find_ssl_engine_not_enabled(ast)[0]
    meta = find_ssl_engine_not_enabled._rule_meta

    assert finding.title == meta.title
    assert finding.description == meta.description
    assert finding.recommendation == meta.recommendation


def test_server_tag_not_blank_finding_uses_rule_metadata_defaults() -> None:
    ast = parse_lighttpd_config('server.tag = "demo"\n', file_path="lighttpd.conf")

    finding = find_server_tag_not_blank(ast)[0]
    meta = find_server_tag_not_blank._rule_meta

    assert finding.title == meta.title
    assert finding.description == meta.description
    assert finding.recommendation == meta.recommendation


def test_parse_lighttpd_include_shell_with_spaces_and_quotes() -> None:
    ast = parse_lighttpd_config(
        'include_shell "python -c \\"print(\'hello world\')\\""\n',
        file_path="lighttpd.conf",
    )

    assert len(ast.nodes) == 1

    directive = ast.nodes[0]
    assert isinstance(directive, LighttpdDirectiveNode)
    assert directive.name == "include_shell"
    assert directive.args == ['python -c "print(\'hello world\')"']
    assert directive.source.file_path == "lighttpd.conf"
    assert directive.source.line == 1


def test_parse_lighttpd_config_with_condition_block() -> None:
    ast = parse_lighttpd_config(
        '$HTTP["host"] == "example.test" {\n'
        '    server.tag = "demo"\n'
        '    include "extra.conf"\n'
        "}\n",
        file_path="lighttpd.conf",
    )

    assert len(ast.nodes) == 1

    block = ast.nodes[0]
    assert isinstance(block, LighttpdBlockNode)
    assert block.header == '$HTTP["host"] == "example.test"'
    assert block.source.file_path == "lighttpd.conf"
    assert block.source.line == 1
    assert len(block.children) == 2

    child_assignment = block.children[0]
    assert isinstance(child_assignment, LighttpdAssignmentNode)
    assert child_assignment.name == "server.tag"
    assert child_assignment.source.line == 2

    child_directive = block.children[1]
    assert isinstance(child_directive, LighttpdDirectiveNode)
    assert child_directive.name == "include"
    assert child_directive.args == ["extra.conf"]
    assert child_directive.source.line == 3


def test_parse_condition_http_host_equality() -> None:
    ast = parse_lighttpd_config(
        '$HTTP["host"] == "example.test" {\n'
        '    server.tag = "demo"\n'
        "}\n",
    )
    block = ast.nodes[0]
    assert isinstance(block, LighttpdBlockNode)
    assert block.condition == LighttpdCondition(
        variable='$HTTP["host"]',
        operator="==",
        value="example.test",
    )


def test_parse_condition_server_socket() -> None:
    ast = parse_lighttpd_config(
        '$SERVER["socket"] == ":443" {\n'
        '    ssl.engine = "enable"\n'
        "}\n",
    )
    block = ast.nodes[0]
    assert isinstance(block, LighttpdBlockNode)
    assert block.condition == LighttpdCondition(
        variable='$SERVER["socket"]',
        operator="==",
        value=":443",
    )


def test_parse_condition_url_regex_match() -> None:
    ast = parse_lighttpd_config(
        '$HTTP["url"] =~ "^/api/" {\n'
        "    server.port = 9000\n"
        "}\n",
    )
    block = ast.nodes[0]
    assert isinstance(block, LighttpdBlockNode)
    assert block.condition == LighttpdCondition(
        variable='$HTTP["url"]',
        operator="=~",
        value="^/api/",
    )


def test_parse_condition_negated_regex() -> None:
    ast = parse_lighttpd_config(
        '$HTTP["host"] !~ "^www\\." {\n'
        "    server.port = 8080\n"
        "}\n",
    )
    block = ast.nodes[0]
    assert isinstance(block, LighttpdBlockNode)
    assert block.condition == LighttpdCondition(
        variable='$HTTP["host"]',
        operator="!~",
        value="^www\\.",
    )


def test_parse_condition_inequality() -> None:
    ast = parse_lighttpd_config(
        '$HTTP["host"] != "blocked.test" {\n'
        "    server.port = 8080\n"
        "}\n",
    )
    block = ast.nodes[0]
    assert isinstance(block, LighttpdBlockNode)
    assert block.condition == LighttpdCondition(
        variable='$HTTP["host"]',
        operator="!=",
        value="blocked.test",
    )


def test_parse_condition_else_block_has_no_condition() -> None:
    ast = parse_lighttpd_config(
        '$HTTP["host"] == "example.test" {\n'
        "    server.port = 443\n"
        "}\n"
        "else {\n"
        "    server.port = 80\n"
        "}\n",
    )
    assert len(ast.nodes) == 2
    cond_block = ast.nodes[0]
    else_block = ast.nodes[1]
    assert isinstance(cond_block, LighttpdBlockNode)
    assert cond_block.condition is not None
    assert isinstance(else_block, LighttpdBlockNode)
    assert else_block.header == "else"
    assert else_block.condition is None


def test_parse_condition_unrecognized_header_has_no_condition() -> None:
    ast = parse_lighttpd_config(
        "some_custom_block {\n"
        "    server.port = 8080\n"
        "}\n",
    )
    block = ast.nodes[0]
    assert isinstance(block, LighttpdBlockNode)
    assert block.header == "some_custom_block"
    assert block.condition is None


def test_parse_condition_existing_block_test_still_works() -> None:
    """Existing test: condition parsing does not break header field."""
    ast = parse_lighttpd_config(
        '$HTTP["host"] == "example.test" {\n'
        '    server.tag = "demo"\n'
        "}\n",
        file_path="lighttpd.conf",
    )
    block = ast.nodes[0]
    assert isinstance(block, LighttpdBlockNode)
    assert block.header == '$HTTP["host"] == "example.test"'
    assert block.condition is not None
    assert block.condition.variable == '$HTTP["host"]'


# ---------------------------------------------------------------------------
# Variable expansion
# ---------------------------------------------------------------------------


def test_expand_variables_simple_reference() -> None:
    ast = parse_lighttpd_config(
        'var.basedir = "/var/www"\n'
        'server.document-root = var.basedir\n',
    )
    issues = expand_variables(ast)
    assert issues == []
    doc_root = ast.nodes[1]
    assert isinstance(doc_root, LighttpdAssignmentNode)
    assert doc_root.value == '"/var/www"'


def test_expand_variables_concatenation() -> None:
    ast = parse_lighttpd_config(
        'var.basedir = "/var/www"\n'
        'server.document-root = var.basedir + "/htdocs"\n',
    )
    issues = expand_variables(ast)
    assert issues == []
    doc_root = ast.nodes[1]
    assert isinstance(doc_root, LighttpdAssignmentNode)
    assert doc_root.value == '"/var/www/htdocs"'


def test_expand_variables_append_operator() -> None:
    ast = parse_lighttpd_config(
        'var.x = "hello"\n'
        'var.x += " world"\n',
    )
    issues = expand_variables(ast)
    assert issues == []
    second = ast.nodes[1]
    assert isinstance(second, LighttpdAssignmentNode)
    assert second.value == '"hello world"'


def test_expand_variables_force_assign_operator() -> None:
    ast = parse_lighttpd_config(
        'var.x = "original"\n'
        'var.x := "override"\n',
    )
    issues = expand_variables(ast)
    assert issues == []
    second = ast.nodes[1]
    assert isinstance(second, LighttpdAssignmentNode)
    assert second.value == '"override"'


def test_expand_variables_inside_block() -> None:
    ast = parse_lighttpd_config(
        'var.logdir = "/var/log"\n'
        '$HTTP["host"] == "example.test" {\n'
        '    server.errorlog = var.logdir + "/error.log"\n'
        "}\n",
    )
    issues = expand_variables(ast)
    assert issues == []
    block = ast.nodes[1]
    assert isinstance(block, LighttpdBlockNode)
    errlog = block.children[0]
    assert isinstance(errlog, LighttpdAssignmentNode)
    assert errlog.value == '"/var/log/error.log"'


def test_expand_variables_undefined_reference_reports_issue() -> None:
    ast = parse_lighttpd_config(
        'server.document-root = var.missing + "/htdocs"\n',
    )
    issues = expand_variables(ast)
    assert len(issues) == 1
    assert issues[0].code == "lighttpd_undefined_variable"
    assert "var.missing" in issues[0].message
    # Value unchanged when expansion fails.
    node = ast.nodes[0]
    assert isinstance(node, LighttpdAssignmentNode)
    assert node.value == 'var.missing + "/htdocs"'


def test_expand_variables_non_var_value_unchanged() -> None:
    ast = parse_lighttpd_config(
        'server.port = 8080\n',
    )
    issues = expand_variables(ast)
    assert issues == []
    node = ast.nodes[0]
    assert isinstance(node, LighttpdAssignmentNode)
    assert node.value == "8080"


def test_variable_quote_escapes_quotes_and_backslashes() -> None:
    assert _quote('a"b\\c') == '"a\\"b\\\\c"'


def test_expand_variables_unescapes_quoted_string_tokens() -> None:
    ast = parse_lighttpd_config(
        'var.root = "/srv/\\"quoted\\""\n'
        'server.document-root = var.root + "/a\\\\b"\n',
        file_path="lighttpd.conf",
    )

    issues = expand_variables(ast)

    assert issues == []
    assignment = ast.nodes[1]
    assert isinstance(assignment, LighttpdAssignmentNode)
    assert assignment.value == '"/srv/\\"quoted\\"/a\\\\b"'


def test_expand_variables_integration_rules_see_expanded_values(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'var.tag = ""\n'
        "server.tag = var.tag\n",
        encoding="utf-8",
    )
    result = analyze_lighttpd_config(str(config_path))
    assert isinstance(result, AnalysisResult)
    # server.tag expands to "" → should NOT trigger server_tag_not_blank.
    assert not any(
        f.rule_id == "lighttpd.server_tag_not_blank" for f in result.findings
    )


def test_expand_variables_integration_unexpanded_triggers_rule(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'var.tag = "lighttpd"\n'
        "server.tag = var.tag\n",
        encoding="utf-8",
    )
    result = analyze_lighttpd_config(str(config_path))
    assert isinstance(result, AnalysisResult)
    # server.tag expands to "lighttpd" → SHOULD trigger server_tag_not_blank.
    assert any(
        f.rule_id == "lighttpd.server_tag_not_blank" for f in result.findings
    )


def test_analyze_lighttpd_config_accepts_path_object(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text('server.tag = ""\n', encoding="utf-8")

    result = analyze_lighttpd_config(config_path)

    assert isinstance(result, AnalysisResult)
    assert result.target == str(config_path)


def test_analyze_lighttpd_config_accepts_path_object_for_missing_file(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "missing-lighttpd.conf"

    result = analyze_lighttpd_config(config_path)

    assert isinstance(result, AnalysisResult)
    assert result.target == str(config_path)
    assert len(result.issues) == 1
    assert result.issues[0].code == "config_not_found"
    assert result.issues[0].location is not None
    assert result.issues[0].location.file_path == str(config_path)


def test_analyze_lighttpd_config_reports_read_error_for_invalid_utf8(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_bytes(b"\xff\xfe")

    result = analyze_lighttpd_config(str(config_path))

    assert result.findings == []
    assert len(result.issues) == 1
    assert result.issues[0].code == "lighttpd_config_read_error"


def test_analyze_lighttpd_config_accepts_utf8_bom(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text('server.tag = ""\n', encoding="utf-8-sig")

    result = analyze_lighttpd_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "lighttpd.server_tag_not_blank" for finding in result.findings
    )


# ---------------------------------------------------------------------------
# Effective config / last-wins
# ---------------------------------------------------------------------------


def test_effective_config_last_wins_for_simple_assignment() -> None:
    ast = parse_lighttpd_config(
        'server.tag = "lighttpd"\n'
        'server.tag = ""\n',
    )
    eff = build_effective_config(ast)
    directive = eff.get_global("server.tag")
    assert directive is not None
    assert directive.value == '""'


def test_effective_config_force_assign_overrides() -> None:
    ast = parse_lighttpd_config(
        'server.tag = "original"\n'
        'server.tag := "forced"\n',
    )
    eff = build_effective_config(ast)
    directive = eff.get_global("server.tag")
    assert directive is not None
    assert directive.value == '"forced"'


def test_effective_config_append_accumulates() -> None:
    ast = parse_lighttpd_config(
        'server.modules = ( "mod_access" )\n'
        'server.modules += ( "mod_status" )\n',
    )
    eff = build_effective_config(ast)
    directive = eff.get_global("server.modules")
    assert directive is not None
    assert directive.operator == "+="
    assert '"mod_access"' in directive.value
    assert '"mod_status"' in directive.value


def test_effective_config_conditional_scope_separate_from_global() -> None:
    ast = parse_lighttpd_config(
        'server.port = 80\n'
        '$SERVER["socket"] == ":443" {\n'
        '    ssl.engine = "enable"\n'
        "}\n",
    )
    eff = build_effective_config(ast)
    assert eff.get_global("server.port") is not None
    assert eff.get_global("ssl.engine") is None
    assert len(eff.conditional_scopes) == 1
    scope = eff.conditional_scopes[0]
    assert scope.condition is not None
    assert scope.condition.variable == '$SERVER["socket"]'
    assert "ssl.engine" in scope.directives
    assert scope.directives["ssl.engine"].value == '"enable"'


def test_effective_config_last_wins_inside_conditional() -> None:
    ast = parse_lighttpd_config(
        '$HTTP["host"] == "example.test" {\n'
        '    server.tag = "first"\n'
        '    server.tag = "second"\n'
        "}\n",
    )
    eff = build_effective_config(ast)
    assert len(eff.conditional_scopes) == 1
    scope = eff.conditional_scopes[0]
    assert scope.directives["server.tag"].value == '"second"'


def test_effective_config_nested_block_becomes_separate_scope() -> None:
    ast = parse_lighttpd_config(
        '$HTTP["host"] == "example.test" {\n'
        '    server.port = 8080\n'
        '    $HTTP["url"] =~ "^/api/" {\n'
        '        server.tag = "api"\n'
        "    }\n"
        "}\n",
    )
    eff = build_effective_config(ast)
    # Two scopes: the nested url block + the outer host block.
    assert len(eff.conditional_scopes) == 2
    # Nested block has its own scope with its own directive.
    url_scope = eff.conditional_scopes[0]
    assert url_scope.condition is not None
    assert url_scope.condition.operator == "=~"
    assert "server.tag" in url_scope.directives
    # Parent block has only its direct assignment.
    host_scope = eff.conditional_scopes[1]
    assert host_scope.condition is not None
    assert host_scope.condition.variable == '$HTTP["host"]'
    assert "server.port" in host_scope.directives
    assert "server.tag" not in host_scope.directives


def test_effective_config_sibling_nested_conditions_stay_separate() -> None:
    """Regression: sibling nested conditions must not overwrite each other."""
    ast = parse_lighttpd_config(
        '$HTTP["host"] == "example.test" {\n'
        '    $HTTP["url"] =~ "^/api/" {\n'
        '        server.tag = "api"\n'
        "    }\n"
        '    $HTTP["url"] =~ "^/admin/" {\n'
        '        server.tag = "admin"\n'
        "    }\n"
        "}\n",
    )
    eff = build_effective_config(ast)
    # Three scopes: two nested url blocks + one parent host block.
    assert len(eff.conditional_scopes) == 3
    api_scope = eff.conditional_scopes[0]
    admin_scope = eff.conditional_scopes[1]
    assert api_scope.directives["server.tag"].value == '"api"'
    assert admin_scope.directives["server.tag"].value == '"admin"'


def test_effective_config_source_location_preserved() -> None:
    ast = parse_lighttpd_config(
        'server.port = 80\n'
        'server.port = 8080\n',
        file_path="lighttpd.conf",
    )
    eff = build_effective_config(ast)
    directive = eff.get_global("server.port")
    assert directive is not None
    assert directive.source.line == 2
    assert directive.source.file_path == "lighttpd.conf"


def test_effective_config_multiple_conditional_scopes() -> None:
    ast = parse_lighttpd_config(
        '$HTTP["host"] == "a.test" {\n'
        '    server.tag = "a"\n'
        "}\n"
        '$HTTP["host"] == "b.test" {\n'
        '    server.tag = "b"\n'
        "}\n",
    )
    eff = build_effective_config(ast)
    assert len(eff.conditional_scopes) == 2
    assert eff.conditional_scopes[0].directives["server.tag"].value == '"a"'
    assert eff.conditional_scopes[1].directives["server.tag"].value == '"b"'


def test_effective_config_else_block_has_no_condition() -> None:
    ast = parse_lighttpd_config(
        '$HTTP["host"] == "example.test" {\n'
        '    server.tag = "main"\n'
        "}\n"
        "else {\n"
        '    server.tag = "other"\n'
        "}\n",
    )
    eff = build_effective_config(ast)
    assert len(eff.conditional_scopes) == 2
    assert eff.conditional_scopes[0].condition is not None
    assert eff.conditional_scopes[1].condition is None
    assert eff.conditional_scopes[1].header == "else"


def test_execute_include_shell_captures_stdout(tmp_path: Path) -> None:
    script_path = tmp_path / "emit_config.py"
    script_path.write_text('print(\'server.tag = ""\')\n', encoding="utf-8")

    command = f'"{Path(sys.executable).as_posix()}" "{script_path.as_posix()}"'

    assert execute_include_shell(command, cwd=tmp_path) == 'server.tag = ""\n'


def test_execute_include_shell_returns_none_on_timeout(tmp_path: Path) -> None:
    script_path = tmp_path / "sleepy.py"
    script_path.write_text(
        "import time\n"
        "time.sleep(1)\n"
        "print('server.port = 8080')\n",
        encoding="utf-8",
    )

    command = f'"{Path(sys.executable).as_posix()}" "{script_path.as_posix()}"'

    assert execute_include_shell(command, timeout=0.01, cwd=tmp_path) is None


def test_execute_include_shell_returns_none_for_invalid_command() -> None:
    assert execute_include_shell("definitely-not-a-real-command --version") is None


def test_lighttpd_include_single_file_is_inlined(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    include_path = tmp_path / "extra.conf"

    config_path.write_text('include "extra.conf"\nserver.port = 8080\n', encoding="utf-8")
    include_path.write_text('server.tag = "included"\n', encoding="utf-8")

    ast = parse_lighttpd_config(config_path.read_text(encoding="utf-8"), file_path=str(config_path))
    issues = resolve_includes(ast, config_path)

    assert issues == []
    assert len(ast.nodes) == 2

    included_assignment = ast.nodes[0]
    assert isinstance(included_assignment, LighttpdAssignmentNode)
    assert included_assignment.name == "server.tag"
    assert included_assignment.source.file_path == str(include_path)
    assert included_assignment.source.line == 1


def test_lighttpd_include_shell_is_skipped_by_default(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'include_shell "generate-config"\nserver.port = 8080\n',
        encoding="utf-8",
    )

    ast = parse_lighttpd_config(config_path.read_text(encoding="utf-8"), file_path=str(config_path))
    issues = resolve_includes(ast, config_path)

    assert len(issues) == 1
    assert issues[0].code == "lighttpd_include_shell_skipped"
    assert len(ast.nodes) == 1
    assert isinstance(ast.nodes[0], LighttpdAssignmentNode)
    assert ast.nodes[0].name == "server.port"


def test_lighttpd_include_shell_is_inlined_when_enabled(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'include_shell "generate-config"\nserver.port = 8080\n',
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "webconf_audit.local.lighttpd.include.execute_include_shell",
        _fake_shell_include_result('server.tag = "generated"\n'),
    )

    ast = parse_lighttpd_config(config_path.read_text(encoding="utf-8"), file_path=str(config_path))
    issues = resolve_includes(ast, config_path, execute_shell=True)

    assert issues == []
    assert len(ast.nodes) == 2
    assert isinstance(ast.nodes[0], LighttpdAssignmentNode)
    assert ast.nodes[0].name == "server.tag"
    assert ast.nodes[0].source.file_path == "shell:generate-config"
    assert ast.nodes[0].source.line == 1


def test_lighttpd_include_absolute_file_path_is_resolved(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    include_path = tmp_path / "absolute.conf"

    config_path.write_text(f'include "{include_path}"\n', encoding="utf-8")
    include_path.write_text("server.port = 8080\n", encoding="utf-8")

    ast = parse_lighttpd_config(config_path.read_text(encoding="utf-8"), file_path=str(config_path))
    issues = resolve_includes(ast, config_path)

    assert issues == []
    assert len(ast.nodes) == 1
    assert isinstance(ast.nodes[0], LighttpdAssignmentNode)
    assert ast.nodes[0].name == "server.port"
    assert ast.nodes[0].source.file_path == str(include_path)


def test_lighttpd_include_glob_is_resolved_in_sorted_order(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    conf_dir = tmp_path / "conf.d"
    conf_dir.mkdir()

    config_path.write_text('include "conf.d/*.conf"\n', encoding="utf-8")
    (conf_dir / "b.conf").write_text("server.port = 8080\n", encoding="utf-8")
    (conf_dir / "a.conf").write_text('server.tag = "a"\n', encoding="utf-8")

    ast = parse_lighttpd_config(config_path.read_text(encoding="utf-8"), file_path=str(config_path))
    issues = resolve_includes(ast, config_path)

    assert issues == []
    assert [node.name for node in ast.nodes if isinstance(node, LighttpdAssignmentNode)] == [
        "server.tag",
        "server.port",
    ]
    assert ast.nodes[0].source.file_path == str(conf_dir / "a.conf")
    assert ast.nodes[1].source.file_path == str(conf_dir / "b.conf")


def test_analyze_lighttpd_config_reports_malformed_glob_include_without_crashing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text('include "conf.d/*.conf"\nserver.tag = ""\n', encoding="utf-8")

    monkeypatch.setattr("webconf_audit.local.lighttpd.include.glob.glob", _raise_regex_error)

    result = analyze_lighttpd_config(str(config_path))

    assert len(result.issues) == 1
    assert result.issues[0].code == "lighttpd_include_not_found"
    assert result.issues[0].location is not None
    assert result.issues[0].location.file_path == str(config_path)
    assert result.issues[0].location.line == 1


def test_analyze_lighttpd_config_reports_missing_include_without_crashing(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'include "missing.conf"\nserver.tag = ""\nserver.port = 8080\n',
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.mode == "local"
    assert result.server_type == "lighttpd"
    assert not any(f.rule_id in {"lighttpd.dir_listing_enabled", "lighttpd.server_tag_not_blank"} for f in result.findings)
    assert len(result.issues) == 1

    issue = result.issues[0]
    assert issue.code == "lighttpd_include_not_found"
    assert issue.location is not None
    assert issue.location.file_path == str(config_path)
    assert issue.location.line == 1


def test_analyze_lighttpd_config_skips_include_shell_by_default(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'include_shell "generate-config"\nserver.tag = ""\n',
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(str(config_path))

    assert len(result.issues) == 1
    assert result.issues[0].code == "lighttpd_include_shell_skipped"
    assert not any(f.rule_id == "lighttpd.dir_listing_enabled" for f in result.findings)


def test_analyze_lighttpd_config_reports_include_shell_execution_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'include_shell "generate-config"\nserver.tag = ""\n',
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "webconf_audit.local.lighttpd.include.execute_include_shell",
        _fake_shell_include_result(None),
    )

    result = analyze_lighttpd_config(str(config_path), execute_shell=True)

    assert len(result.issues) == 1
    assert result.issues[0].code == "lighttpd_include_shell_execution_failed"
    assert result.issues[0].level == "warning"
    assert not any(f.rule_id == "lighttpd.dir_listing_enabled" for f in result.findings)


def test_analyze_lighttpd_config_executes_include_shell_when_enabled(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'include_shell "generate-config"\nserver.tag = ""\n',
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "webconf_audit.local.lighttpd.include.execute_include_shell",
        _fake_shell_include_result('dir-listing.activate = "enable"\n'),
    )

    result = analyze_lighttpd_config(str(config_path), execute_shell=True)

    dir_findings = [f for f in result.findings if f.rule_id == "lighttpd.dir_listing_enabled"]
    assert len(dir_findings) == 1
    assert dir_findings[0].location is not None
    assert dir_findings[0].location.file_path == "shell:generate-config"
    assert result.issues == []


def test_analyze_lighttpd_config_detects_shell_include_cycle(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'include_shell "generate-config"\nserver.tag = ""\n',
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "webconf_audit.local.lighttpd.include.execute_include_shell",
        _fake_shell_include_result('include_shell "generate-config"\n'),
    )

    result = analyze_lighttpd_config(str(config_path), execute_shell=True)

    assert len(result.issues) == 1
    assert result.issues[0].code == "lighttpd_include_cycle"
    assert result.issues[0].location is not None
    assert result.issues[0].location.file_path == "shell:generate-config"
    assert result.issues[0].level == "error"


def test_analyze_lighttpd_config_reports_self_include_issue(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text('include "lighttpd.conf"\nserver.tag = ""\n', encoding="utf-8")

    result = analyze_lighttpd_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert not any(f.rule_id in {"lighttpd.dir_listing_enabled", "lighttpd.server_tag_not_blank"} for f in result.findings)
    assert len(result.issues) == 1
    assert result.issues[0].code == "lighttpd_include_self_include"


def test_analyze_lighttpd_config_reports_include_cycle_issue(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    conf_dir = tmp_path / "conf.d"
    conf_dir.mkdir()

    config_path.write_text('include "conf.d/a.conf"\nserver.tag = ""\n', encoding="utf-8")
    (conf_dir / "a.conf").write_text('include "b.conf"\n', encoding="utf-8")
    (conf_dir / "b.conf").write_text('include "a.conf"\n', encoding="utf-8")

    result = analyze_lighttpd_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert not any(f.rule_id in {"lighttpd.dir_listing_enabled", "lighttpd.server_tag_not_blank"} for f in result.findings)
    assert len(result.issues) == 1
    assert result.issues[0].code == "lighttpd_include_cycle"
    assert result.issues[0].location is not None
    assert result.issues[0].location.file_path == str(conf_dir / "b.conf")
    assert result.issues[0].location.line == 1


def test_analyze_lighttpd_config_passes_execute_shell_to_resolve_includes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text('server.tag = ""\n', encoding="utf-8")
    captured: dict[str, bool] = {}

    def fake_resolve_includes(ast, config_path, load_context=None, execute_shell=False):
        captured["execute_shell"] = execute_shell
        return []

    monkeypatch.setattr("webconf_audit.local.lighttpd.resolve_includes", fake_resolve_includes)

    result = analyze_lighttpd_config(str(config_path), execute_shell=True)

    assert isinstance(result, AnalysisResult)
    assert captured == {"execute_shell": True}


def test_analyze_lighttpd_config_returns_analysis_result_for_existing_config(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'server.document-root = "/var/www/html"\n'
        'server.tag = ""\n'
        '$HTTP["scheme"] == "https" {\n'
        "    server.port = 443\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.mode == "local"
    assert result.target == str(config_path)
    assert result.server_type == "lighttpd"
    assert not any(f.rule_id in {"lighttpd.dir_listing_enabled", "lighttpd.server_tag_not_blank"} for f in result.findings)
    assert result.issues == []


def test_analyze_lighttpd_config_reports_dir_listing_enabled_at_top_level(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text('server.tag = ""\ndir-listing.activate = "enable"\n', encoding="utf-8")

    result = analyze_lighttpd_config(str(config_path))

    assert result.issues == []
    dir_findings = [f for f in result.findings if f.rule_id == "lighttpd.dir_listing_enabled"]
    assert len(dir_findings) == 1
    finding = dir_findings[0]
    assert finding.title == "Directory listing enabled"
    assert finding.severity == "medium"


def test_analyze_lighttpd_config_does_not_report_dir_listing_when_disabled(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text('server.tag = ""\ndir-listing.activate = "disable"\n', encoding="utf-8")

    result = analyze_lighttpd_config(str(config_path))

    assert result.issues == []
    assert not any(f.rule_id == "lighttpd.dir_listing_enabled" for f in result.findings)


def test_analyze_lighttpd_config_reports_dir_listing_enabled_inside_block(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'server.tag = ""\n'
        '$HTTP["host"] == "example.test" {\n'
        '    dir-listing.activate = "enable"\n'
        "}\n",
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(str(config_path))

    assert result.issues == []
    dir_findings = [f for f in result.findings if f.rule_id == "lighttpd.dir_listing_enabled"]
    assert len(dir_findings) == 1


def test_analyze_lighttpd_config_reports_dir_listing_finding_source_location(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text('server.tag = ""\ndir-listing.activate = "enable"\n', encoding="utf-8")

    result = analyze_lighttpd_config(str(config_path))

    dir_findings = [f for f in result.findings if f.rule_id == "lighttpd.dir_listing_enabled"]
    assert len(dir_findings) == 1
    finding = dir_findings[0]
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 2


def test_analyze_lighttpd_config_reports_dir_listing_enabled_from_include_file(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    include_path = tmp_path / "extra.conf"

    config_path.write_text('server.tag = ""\ninclude "extra.conf"\n', encoding="utf-8")
    include_path.write_text('dir-listing.activate = "enable"\n', encoding="utf-8")

    result = analyze_lighttpd_config(str(config_path))

    assert result.issues == []
    dir_findings = [f for f in result.findings if f.rule_id == "lighttpd.dir_listing_enabled"]
    assert len(dir_findings) == 1
    finding = dir_findings[0]
    assert finding.location is not None
    assert finding.location.file_path == str(include_path)
    assert finding.location.line == 1


def test_analyze_lighttpd_config_reports_missing_server_tag(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text("server.port = 8080\n", encoding="utf-8")

    result = analyze_lighttpd_config(str(config_path))

    assert result.issues == []
    tag_findings = [f for f in result.findings if f.rule_id == "lighttpd.server_tag_not_blank"]
    assert len(tag_findings) == 1
    finding = tag_findings[0]
    assert finding.title == "Server banner not suppressed"
    assert finding.severity == "low"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 1


def test_analyze_lighttpd_config_does_not_report_server_tag_when_explicitly_blank(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text('server.tag = ""\n', encoding="utf-8")

    result = analyze_lighttpd_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "lighttpd.server_tag_not_blank" for finding in result.findings
    )


def test_analyze_lighttpd_config_reports_default_server_tag_banner(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text('server.tag = "lighttpd"\n', encoding="utf-8")

    result = analyze_lighttpd_config(str(config_path))

    assert result.issues == []
    tag_findings = [f for f in result.findings if f.rule_id == "lighttpd.server_tag_not_blank"]
    assert len(tag_findings) == 1
    finding = tag_findings[0]
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 1


def test_analyze_lighttpd_config_reports_custom_server_tag_banner(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text('server.tag = "custom-banner"\n', encoding="utf-8")

    result = analyze_lighttpd_config(str(config_path))

    assert result.issues == []
    tag_findings = [f for f in result.findings if f.rule_id == "lighttpd.server_tag_not_blank"]
    assert len(tag_findings) == 1


def test_analyze_lighttpd_config_reports_server_tag_location_for_explicit_assignment(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text('server.tag = "custom-banner"\n', encoding="utf-8")

    result = analyze_lighttpd_config(str(config_path))

    tag_findings = [f for f in result.findings if f.rule_id == "lighttpd.server_tag_not_blank"]
    assert len(tag_findings) == 1
    finding = tag_findings[0]
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 1


def test_analyze_lighttpd_config_safe_server_tag_from_include_file_does_not_report(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    include_path = tmp_path / "extra.conf"

    config_path.write_text('include "extra.conf"\n', encoding="utf-8")
    include_path.write_text('server.tag = ""\n', encoding="utf-8")

    result = analyze_lighttpd_config(str(config_path))

    assert result.issues == []
    assert not any(
        finding.rule_id == "lighttpd.server_tag_not_blank" for finding in result.findings
    )


def test_analyze_lighttpd_config_reports_non_blank_server_tag_from_include_file(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    include_path = tmp_path / "extra.conf"

    config_path.write_text('include "extra.conf"\n', encoding="utf-8")
    include_path.write_text('server.tag = "lighttpd"\n', encoding="utf-8")

    result = analyze_lighttpd_config(str(config_path))

    assert result.issues == []
    tag_findings = [f for f in result.findings if f.rule_id == "lighttpd.server_tag_not_blank"]
    assert len(tag_findings) == 1
    finding = tag_findings[0]
    assert finding.location is not None
    assert finding.location.file_path == str(include_path)
    assert finding.location.line == 1


# ---------------------------------------------------------------------------
# Helper for new rule tests
# ---------------------------------------------------------------------------

# Base config that silences pre-existing rules (server.tag blank, no dir-listing).
_BASE = 'server.tag = ""\nserver.errorlog = "/var/log/error.log"\n'


def _analyze(tmp_path: Path, config_text: str) -> AnalysisResult:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(config_text, encoding="utf-8")
    return analyze_lighttpd_config(str(config_path))


def _has_finding(result: AnalysisResult, rule_id: str) -> bool:
    return any(f.rule_id == rule_id for f in result.findings)


# ---------------------------------------------------------------------------
# SSL/TLS rules
# ---------------------------------------------------------------------------


def test_ssl_engine_not_enabled_fires_when_port_443_without_ssl(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + "server.port = 443\n")
    assert _has_finding(result, "lighttpd.ssl_engine_not_enabled")


def test_ssl_engine_not_enabled_silent_when_ssl_enabled(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + 'server.port = 443\nssl.engine = "enable"\nssl.pemfile = "/cert.pem"\n')
    assert not _has_finding(result, "lighttpd.ssl_engine_not_enabled")


def test_ssl_engine_not_enabled_silent_when_no_443(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + "server.port = 80\n")
    assert not _has_finding(result, "lighttpd.ssl_engine_not_enabled")


def test_ssl_engine_not_enabled_fires_when_ssl_is_only_enabled_in_unrelated_scope(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + 'server.port = 443\n'
        + '$HTTP["host"] == "example.test" {\n'
        + '    ssl.engine = "enable"\n'
        + "}\n",
    )
    assert _has_finding(result, "lighttpd.ssl_engine_not_enabled")


def test_ssl_engine_not_enabled_silent_when_socket_443_scope_enables_ssl(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + 'server.port = 443\n'
        + '$SERVER["socket"] == ":443" {\n'
        + '    ssl.engine = "enable"\n'
        + "}\n",
    )
    assert not _has_finding(result, "lighttpd.ssl_engine_not_enabled")


def test_ssl_pemfile_missing_fires_when_ssl_without_pemfile(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + 'ssl.engine = "enable"\n')
    assert _has_finding(result, "lighttpd.ssl_pemfile_missing")


def test_ssl_pemfile_missing_silent_when_pemfile_set(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + 'ssl.engine = "enable"\nssl.pemfile = "/cert.pem"\n')
    assert not _has_finding(result, "lighttpd.ssl_pemfile_missing")


def test_ssl_pemfile_missing_fires_when_pemfile_empty(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + 'ssl.engine = "enable"\nssl.pemfile = ""\n')
    assert _has_finding(result, "lighttpd.ssl_pemfile_missing")


def test_ssl_pemfile_missing_silent_when_no_ssl(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE)
    assert not _has_finding(result, "lighttpd.ssl_pemfile_missing")


def test_weak_ssl_cipher_list_fires_for_rc4(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + 'ssl.cipher-list = "RC4-SHA:AES128"\n')
    assert _has_finding(result, "lighttpd.weak_ssl_cipher_list")


def test_weak_ssl_cipher_list_silent_for_strong(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + 'ssl.cipher-list = "ECDHE-ECDSA-AES256-GCM-SHA384"\n')
    assert not _has_finding(result, "lighttpd.weak_ssl_cipher_list")


def test_weak_ssl_cipher_list_ignores_disabled_weak_tokens(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + 'ssl.cipher-list = "HIGH:!aNULL:!MD5:-DES"\n')
    assert not _has_finding(result, "lighttpd.weak_ssl_cipher_list")


def test_lighttpd_header_tuple_keeps_comma_inside_quoted_value() -> None:
    headers = _parse_header_tuple(
        '( "Content-Security-Policy" => "default-src self, report-uri /csp" )',
        LighttpdAssignmentNode(
            name="dummy",
            operator="=",
            value='""',
        ).source,
    )

    assert len(headers) == 1
    assert headers[0].name == "content-security-policy"
    assert headers[0].value == "default-src self, report-uri /csp"


def test_ssl_honor_cipher_order_fires_when_ssl_without_honor(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + 'ssl.engine = "enable"\nssl.pemfile = "/c.pem"\n')
    assert _has_finding(result, "lighttpd.ssl_honor_cipher_order_missing")


def test_ssl_honor_cipher_order_silent_when_set(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        _BASE + 'ssl.engine = "enable"\nssl.pemfile = "/c.pem"\nssl.honor-cipher-order = "enable"\n',
    )
    assert not _has_finding(result, "lighttpd.ssl_honor_cipher_order_missing")


def test_ssl_honor_cipher_order_fires_when_honor_is_only_enabled_in_unrelated_scope(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + 'ssl.engine = "enable"\n'
        + 'ssl.pemfile = "/c.pem"\n'
        + '$HTTP["host"] == "example.test" {\n'
        + '    ssl.honor-cipher-order = "enable"\n'
        + "}\n",
    )
    assert _has_finding(result, "lighttpd.ssl_honor_cipher_order_missing")


# ---------------------------------------------------------------------------
# Security headers rules
# ---------------------------------------------------------------------------


def test_missing_strict_transport_security_fires(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE)
    assert _has_finding(result, "lighttpd.missing_strict_transport_security")


def test_missing_strict_transport_security_silent_when_set(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        _BASE + 'setenv.add-response-header = ( "Strict-Transport-Security" => "max-age=31536000" )\n',
    )
    assert not _has_finding(result, "lighttpd.missing_strict_transport_security")


def test_missing_x_content_type_options_fires(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE)
    assert _has_finding(result, "lighttpd.missing_x_content_type_options")


def test_missing_x_content_type_options_silent_when_set(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        _BASE + 'setenv.add-response-header = ( "X-Content-Type-Options" => "nosniff" )\n',
    )
    assert not _has_finding(result, "lighttpd.missing_x_content_type_options")


# ---------------------------------------------------------------------------
# Access control rules
# ---------------------------------------------------------------------------


def test_url_access_deny_missing_fires(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE)
    assert _has_finding(result, "lighttpd.url_access_deny_missing")


def test_url_access_deny_missing_silent_when_set(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + 'url.access-deny = ( ".bak", ".inc" )\n')
    assert not _has_finding(result, "lighttpd.url_access_deny_missing")


def test_mod_status_public_fires_when_no_remoteip(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        _BASE + 'server.modules = ( "mod_status" )\nstatus.status-url = "/server-status"\n',
    )
    assert _has_finding(result, "lighttpd.mod_status_public")


def test_mod_status_public_silent_inside_remoteip_block(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + 'server.modules = ( "mod_status" )\n'
        + '$HTTP["remoteip"] == "127.0.0.1" {\n'
        + '    status.status-url = "/server-status"\n'
        + "}\n",
    )
    assert not _has_finding(result, "lighttpd.mod_status_public")


def test_mod_status_public_silent_when_nested_inside_remoteip_block(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + 'server.modules = ( "mod_status" )\n'
        + '$HTTP["remoteip"] == "127.0.0.1" {\n'
        + '    $HTTP["host"] == "admin.example.test" {\n'
        + '        status.status-url = "/server-status"\n'
        + "    }\n"
        + "}\n",
    )
    assert not _has_finding(result, "lighttpd.mod_status_public")


def test_mod_status_public_silent_when_no_status_url(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + 'server.modules = ( "mod_status" )\n')
    assert not _has_finding(result, "lighttpd.mod_status_public")


# ---------------------------------------------------------------------------
# Logging rules
# ---------------------------------------------------------------------------


def test_error_log_missing_fires(tmp_path: Path) -> None:
    result = _analyze(tmp_path, 'server.tag = ""\n')
    assert _has_finding(result, "lighttpd.error_log_missing")


def test_error_log_missing_silent_when_set(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE)  # _BASE includes server.errorlog
    assert not _has_finding(result, "lighttpd.error_log_missing")


def test_access_log_missing_fires_when_module_loaded(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + 'server.modules = ( "mod_accesslog" )\n')
    assert _has_finding(result, "lighttpd.access_log_missing")


def test_access_log_missing_silent_when_filename_set(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        _BASE + 'server.modules = ( "mod_accesslog" )\naccesslog.filename = "/var/log/access.log"\n',
    )
    assert not _has_finding(result, "lighttpd.access_log_missing")


def test_access_log_missing_silent_when_module_not_loaded(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE)
    assert not _has_finding(result, "lighttpd.access_log_missing")


# ---------------------------------------------------------------------------
# Request limits rules
# ---------------------------------------------------------------------------


def test_max_request_size_missing_fires(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE)
    assert _has_finding(result, "lighttpd.max_request_size_missing")


def test_max_request_size_missing_silent_when_set(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + "server.max-request-size = 1048576\n")
    assert not _has_finding(result, "lighttpd.max_request_size_missing")


def test_max_connections_missing_fires(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE)
    assert _has_finding(result, "lighttpd.max_connections_missing")


def test_max_connections_missing_silent_when_set(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + "server.max-connections = 1024\n")
    assert not _has_finding(result, "lighttpd.max_connections_missing")


# ---------------------------------------------------------------------------
# Module safety rules
# ---------------------------------------------------------------------------


def test_mod_cgi_enabled_fires(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + 'server.modules = ( "mod_cgi" )\n')
    assert _has_finding(result, "lighttpd.mod_cgi_enabled")


def test_mod_cgi_enabled_silent_when_not_loaded(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + 'server.modules = ( "mod_access" )\n')
    assert not _has_finding(result, "lighttpd.mod_cgi_enabled")


def test_mod_cgi_enabled_falls_back_to_default_location_when_module_source_is_unknown(
    monkeypatch,
) -> None:
    ast = parse_lighttpd_config(
        'server.tag = ""\n',
        file_path="lighttpd.conf",
    )
    monkeypatch.setattr(
        "webconf_audit.local.lighttpd.rules.mod_cgi_enabled.collect_modules",
        _collect_mod_cgi,
    )

    findings = find_mod_cgi_enabled(ast)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.location is not None
    assert finding.location.file_path == "lighttpd.conf"
    assert finding.location.line == 1


# ---------------------------------------------------------------------------
# Effective config integration: last-wins and conditional scope behavior
# ---------------------------------------------------------------------------


def test_dir_listing_last_wins_disable_after_enable(tmp_path: Path) -> None:
    """Enable then disable → no finding (last-wins)."""
    config = _BASE + 'dir-listing.activate = "enable"\ndir-listing.activate = "disable"\n'
    result = _analyze(tmp_path, config)
    assert not _has_finding(result, "lighttpd.dir_listing_enabled")


def test_dir_listing_last_wins_enable_after_disable(tmp_path: Path) -> None:
    """Disable then enable → finding (last-wins)."""
    config = _BASE + 'dir-listing.activate = "disable"\ndir-listing.activate = "enable"\n'
    result = _analyze(tmp_path, config)
    assert _has_finding(result, "lighttpd.dir_listing_enabled")


def test_dir_listing_in_conditional_still_fires(tmp_path: Path) -> None:
    """Enable inside a conditional block → finding (conditional scope)."""
    config = (
        _BASE
        + '$HTTP["host"] == "example.test" {\n'
        + '    dir-listing.activate = "enable"\n'
        + "}\n"
    )
    result = _analyze(tmp_path, config)
    assert _has_finding(result, "lighttpd.dir_listing_enabled")


def test_dir_listing_conditional_disable_after_enable(tmp_path: Path) -> None:
    """Enable then disable inside same conditional → no finding (last-wins in scope)."""
    config = (
        _BASE
        + '$HTTP["host"] == "example.test" {\n'
        + '    dir-listing.activate = "enable"\n'
        + '    dir-listing.activate = "disable"\n'
        + "}\n"
    )
    result = _analyze(tmp_path, config)
    assert not _has_finding(result, "lighttpd.dir_listing_enabled")


def test_server_tag_last_wins_blank_after_non_blank(tmp_path: Path) -> None:
    """Non-blank then blank → no finding (last-wins)."""
    config = (
        'server.errorlog = "/var/log/error.log"\n'
        + 'server.tag = "lighttpd"\n'
        + 'server.tag = ""\n'
    )
    result = _analyze(tmp_path, config)
    assert not _has_finding(result, "lighttpd.server_tag_not_blank")


def test_server_tag_last_wins_non_blank_after_blank(tmp_path: Path) -> None:
    """Blank then non-blank → finding (last-wins)."""
    config = (
        'server.errorlog = "/var/log/error.log"\n'
        + 'server.tag = ""\n'
        + 'server.tag = "lighttpd"\n'
    )
    result = _analyze(tmp_path, config)
    assert _has_finding(result, "lighttpd.server_tag_not_blank")


def test_server_tag_conditional_non_blank_fires(tmp_path: Path) -> None:
    """Non-blank in conditional scope → finding even if global is blank."""
    config = (
        _BASE
        + '$HTTP["host"] == "example.test" {\n'
        + '    server.tag = "custom"\n'
        + "}\n"
    )
    result = _analyze(tmp_path, config)
    assert _has_finding(result, "lighttpd.server_tag_not_blank")


def test_server_tag_conditional_blank_is_silent(tmp_path: Path) -> None:
    """Blank in conditional scope → no finding from that scope."""
    config = (
        _BASE
        + '$HTTP["host"] == "example.test" {\n'
        + '    server.tag = ""\n'
        + "}\n"
    )
    result = _analyze(tmp_path, config)
    assert not _has_finding(result, "lighttpd.server_tag_not_blank")
