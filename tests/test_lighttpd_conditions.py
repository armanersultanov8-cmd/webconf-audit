"""Tests for lighttpd deep condition evaluation (Plan E)."""

from __future__ import annotations

from webconf_audit.local.lighttpd.conditions import (
    CONDITION_VARIABLE_MAP,
    LighttpdRequestContext,
    evaluate_condition,
    is_potentially_matching,
)
from webconf_audit.local.lighttpd.effective import (
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
    LighttpdConditionalScope,
    build_effective_config,
    merge_conditional_scopes,
)
from webconf_audit.local.lighttpd.parser import (
    LighttpdCondition,
    LighttpdSourceSpan,
    parse_lighttpd_config,
)


# ---------------------------------------------------------------------------
# LighttpdRequestContext
# ---------------------------------------------------------------------------


class TestRequestContext:
    def test_all_none_by_default(self) -> None:
        ctx = LighttpdRequestContext()
        assert ctx.host is None
        assert ctx.url_path is None
        assert ctx.remote_ip is None
        assert ctx.scheme is None
        assert ctx.server_socket is None

    def test_partial_fields(self) -> None:
        ctx = LighttpdRequestContext(host="example.com", scheme="https")
        assert ctx.host == "example.com"
        assert ctx.scheme == "https"
        assert ctx.url_path is None

    def test_all_fields(self) -> None:
        ctx = LighttpdRequestContext(
            host="example.com",
            url_path="/api",
            remote_ip="10.0.0.1",
            scheme="https",
            server_socket=":443",
        )
        assert ctx.host == "example.com"
        assert ctx.url_path == "/api"
        assert ctx.remote_ip == "10.0.0.1"
        assert ctx.scheme == "https"
        assert ctx.server_socket == ":443"


# ---------------------------------------------------------------------------
# CONDITION_VARIABLE_MAP
# ---------------------------------------------------------------------------


class TestConditionVariableMap:
    def test_http_host_maps_to_host(self) -> None:
        assert CONDITION_VARIABLE_MAP['$HTTP["host"]'] == "host"

    def test_http_url_maps_to_url_path(self) -> None:
        assert CONDITION_VARIABLE_MAP['$HTTP["url"]'] == "url_path"

    def test_http_remoteip_maps_to_remote_ip(self) -> None:
        assert CONDITION_VARIABLE_MAP['$HTTP["remoteip"]'] == "remote_ip"

    def test_http_scheme_maps_to_scheme(self) -> None:
        assert CONDITION_VARIABLE_MAP['$HTTP["scheme"]'] == "scheme"

    def test_server_socket_maps_to_server_socket(self) -> None:
        assert CONDITION_VARIABLE_MAP['$SERVER["socket"]'] == "server_socket"

    def test_all_mapped_attrs_exist_on_context(self) -> None:
        ctx = LighttpdRequestContext()
        for attr in CONDITION_VARIABLE_MAP.values():
            assert hasattr(ctx, attr)


# ---------------------------------------------------------------------------
# evaluate_condition
# ---------------------------------------------------------------------------


def _cond(variable: str, operator: str, value: str) -> LighttpdCondition:
    return LighttpdCondition(variable=variable, operator=operator, value=value)


class TestEvaluateCondition:
    def test_eq_match(self) -> None:
        cond = _cond('$HTTP["host"]', "==", "example.com")
        ctx = LighttpdRequestContext(host="example.com")
        assert evaluate_condition(cond, ctx) is True

    def test_eq_no_match(self) -> None:
        cond = _cond('$HTTP["host"]', "==", "example.com")
        ctx = LighttpdRequestContext(host="other.com")
        assert evaluate_condition(cond, ctx) is False

    def test_ne_match(self) -> None:
        cond = _cond('$HTTP["host"]', "!=", "example.com")
        ctx = LighttpdRequestContext(host="other.com")
        assert evaluate_condition(cond, ctx) is True

    def test_ne_no_match(self) -> None:
        cond = _cond('$HTTP["host"]', "!=", "example.com")
        ctx = LighttpdRequestContext(host="example.com")
        assert evaluate_condition(cond, ctx) is False

    def test_regex_match(self) -> None:
        cond = _cond('$HTTP["url"]', "=~", r"^/api/")
        ctx = LighttpdRequestContext(url_path="/api/v1/users")
        assert evaluate_condition(cond, ctx) is True

    def test_regex_no_match(self) -> None:
        cond = _cond('$HTTP["url"]', "=~", r"^/api/")
        ctx = LighttpdRequestContext(url_path="/static/style.css")
        assert evaluate_condition(cond, ctx) is False

    def test_regex_negation_match(self) -> None:
        cond = _cond('$HTTP["url"]', "!~", r"^/api/")
        ctx = LighttpdRequestContext(url_path="/static/style.css")
        assert evaluate_condition(cond, ctx) is True

    def test_regex_negation_no_match(self) -> None:
        cond = _cond('$HTTP["url"]', "!~", r"^/api/")
        ctx = LighttpdRequestContext(url_path="/api/v1/users")
        assert evaluate_condition(cond, ctx) is False

    def test_unknown_context_field_returns_none(self) -> None:
        cond = _cond('$HTTP["host"]', "==", "example.com")
        ctx = LighttpdRequestContext()  # host is None
        assert evaluate_condition(cond, ctx) is None

    def test_unknown_variable_returns_none(self) -> None:
        cond = _cond('$HTTP["referer"]', "==", "something")
        ctx = LighttpdRequestContext(host="example.com")
        assert evaluate_condition(cond, ctx) is None

    def test_unknown_operator_returns_none(self) -> None:
        cond = _cond('$HTTP["host"]', ">>", "example.com")
        ctx = LighttpdRequestContext(host="example.com")
        assert evaluate_condition(cond, ctx) is None

    def test_invalid_regex_returns_none(self) -> None:
        cond = _cond('$HTTP["url"]', "=~", "[invalid")
        ctx = LighttpdRequestContext(url_path="/test")
        assert evaluate_condition(cond, ctx) is None

    def test_server_socket_eq(self) -> None:
        cond = _cond('$SERVER["socket"]', "==", ":443")
        ctx = LighttpdRequestContext(server_socket=":443")
        assert evaluate_condition(cond, ctx) is True

    def test_scheme_eq(self) -> None:
        cond = _cond('$HTTP["scheme"]', "==", "https")
        ctx = LighttpdRequestContext(scheme="https")
        assert evaluate_condition(cond, ctx) is True

    def test_remoteip_regex(self) -> None:
        cond = _cond('$HTTP["remoteip"]', "=~", r"^10\.")
        ctx = LighttpdRequestContext(remote_ip="10.0.0.5")
        assert evaluate_condition(cond, ctx) is True


# ---------------------------------------------------------------------------
# is_potentially_matching
# ---------------------------------------------------------------------------


class TestIsPotentiallyMatching:
    def test_no_context_always_true(self) -> None:
        cond = _cond('$HTTP["host"]', "==", "example.com")
        assert is_potentially_matching(cond) is True

    def test_no_context_explicit_none(self) -> None:
        cond = _cond('$HTTP["host"]', "==", "example.com")
        assert is_potentially_matching(cond, context=None) is True

    def test_none_condition_always_true(self) -> None:
        ctx = LighttpdRequestContext(host="example.com")
        assert is_potentially_matching(None, context=ctx) is True

    def test_both_none(self) -> None:
        assert is_potentially_matching(None, context=None) is True

    def test_matching_condition_returns_true(self) -> None:
        cond = _cond('$HTTP["host"]', "==", "example.com")
        ctx = LighttpdRequestContext(host="example.com")
        assert is_potentially_matching(cond, ctx) is True

    def test_non_matching_condition_returns_false(self) -> None:
        cond = _cond('$HTTP["host"]', "==", "example.com")
        ctx = LighttpdRequestContext(host="other.com")
        assert is_potentially_matching(cond, ctx) is False

    def test_unknown_field_treated_as_matching(self) -> None:
        cond = _cond('$HTTP["host"]', "==", "example.com")
        ctx = LighttpdRequestContext(scheme="https")  # host is None
        assert is_potentially_matching(cond, ctx) is True

    def test_unknown_variable_treated_as_matching(self) -> None:
        cond = _cond('$HTTP["referer"]', "==", "x")
        ctx = LighttpdRequestContext(host="example.com")
        assert is_potentially_matching(cond, ctx) is True


# ---------------------------------------------------------------------------
# merge_conditional_scopes
# ---------------------------------------------------------------------------


def _src(line: int = 1) -> LighttpdSourceSpan:
    return LighttpdSourceSpan(file_path="test.conf", line=line)


class TestMergeConditionalScopes:
    def test_global_only(self) -> None:
        eff = LighttpdEffectiveConfig(
            global_directives={
                "server.port": LighttpdEffectiveDirective(
                    name="server.port", value="80", operator="=",
                    scope="global", condition=None, source=_src(1),
                ),
            },
        )
        merged = merge_conditional_scopes(eff)
        assert "server.port" in merged
        assert merged["server.port"].value == "80"

    def test_no_context_merges_all_scopes(self) -> None:
        cond = _cond('$HTTP["host"]', "==", "example.com")
        eff = LighttpdEffectiveConfig(
            global_directives={
                "server.port": LighttpdEffectiveDirective(
                    name="server.port", value="80", operator="=",
                    scope="global", condition=None, source=_src(1),
                ),
            },
            conditional_scopes=[
                LighttpdConditionalScope(
                    condition=cond,
                    header='$HTTP["host"] == "example.com"',
                    directives={
                        "ssl.engine": LighttpdEffectiveDirective(
                            name="ssl.engine", value='"enable"', operator="=",
                            scope="conditional", condition=cond, source=_src(3),
                        ),
                    },
                ),
            ],
        )
        merged = merge_conditional_scopes(eff, context=None)
        assert "server.port" in merged
        assert "ssl.engine" in merged

    def test_matching_context_includes_scope(self) -> None:
        cond = _cond('$HTTP["host"]', "==", "example.com")
        eff = LighttpdEffectiveConfig(
            global_directives={},
            conditional_scopes=[
                LighttpdConditionalScope(
                    condition=cond,
                    header='$HTTP["host"] == "example.com"',
                    directives={
                        "ssl.engine": LighttpdEffectiveDirective(
                            name="ssl.engine", value='"enable"', operator="=",
                            scope="conditional", condition=cond, source=_src(3),
                        ),
                    },
                ),
            ],
        )
        ctx = LighttpdRequestContext(host="example.com")
        merged = merge_conditional_scopes(eff, context=ctx)
        assert "ssl.engine" in merged

    def test_non_matching_context_excludes_scope(self) -> None:
        cond = _cond('$HTTP["host"]', "==", "example.com")
        eff = LighttpdEffectiveConfig(
            global_directives={},
            conditional_scopes=[
                LighttpdConditionalScope(
                    condition=cond,
                    header='$HTTP["host"] == "example.com"',
                    directives={
                        "ssl.engine": LighttpdEffectiveDirective(
                            name="ssl.engine", value='"enable"', operator="=",
                            scope="conditional", condition=cond, source=_src(3),
                        ),
                    },
                ),
            ],
        )
        ctx = LighttpdRequestContext(host="other.com")
        merged = merge_conditional_scopes(eff, context=ctx)
        assert "ssl.engine" not in merged

    def test_conditional_overrides_global(self) -> None:
        cond = _cond('$HTTP["host"]', "==", "example.com")
        eff = LighttpdEffectiveConfig(
            global_directives={
                "server.tag": LighttpdEffectiveDirective(
                    name="server.tag", value='"lighttpd"', operator="=",
                    scope="global", condition=None, source=_src(1),
                ),
            },
            conditional_scopes=[
                LighttpdConditionalScope(
                    condition=cond,
                    header='$HTTP["host"] == "example.com"',
                    directives={
                        "server.tag": LighttpdEffectiveDirective(
                            name="server.tag", value='""', operator="=",
                            scope="conditional", condition=cond, source=_src(3),
                        ),
                    },
                ),
            ],
        )
        merged = merge_conditional_scopes(eff, context=None)
        assert merged["server.tag"].value == '""'

    def test_append_accumulates_across_scopes(self) -> None:
        cond = _cond('$HTTP["host"]', "==", "example.com")
        eff = LighttpdEffectiveConfig(
            global_directives={
                "server.modules": LighttpdEffectiveDirective(
                    name="server.modules", value='( "mod_access" )', operator="=",
                    scope="global", condition=None, source=_src(1),
                ),
            },
            conditional_scopes=[
                LighttpdConditionalScope(
                    condition=cond,
                    header='$HTTP["host"] == "example.com"',
                    directives={
                        "server.modules": LighttpdEffectiveDirective(
                            name="server.modules", value='( "mod_status" )', operator="+=",
                            scope="conditional", condition=cond, source=_src(3),
                        ),
                    },
                ),
            ],
        )
        merged = merge_conditional_scopes(eff, context=None)
        assert '"mod_access"' in merged["server.modules"].value
        assert '"mod_status"' in merged["server.modules"].value

    def test_multiple_scopes_last_wins(self) -> None:
        cond1 = _cond('$HTTP["host"]', "==", "a.com")
        cond2 = _cond('$HTTP["host"]', "==", "b.com")
        eff = LighttpdEffectiveConfig(
            global_directives={},
            conditional_scopes=[
                LighttpdConditionalScope(
                    condition=cond1,
                    header='$HTTP["host"] == "a.com"',
                    directives={
                        "server.tag": LighttpdEffectiveDirective(
                            name="server.tag", value='"A"', operator="=",
                            scope="conditional", condition=cond1, source=_src(2),
                        ),
                    },
                ),
                LighttpdConditionalScope(
                    condition=cond2,
                    header='$HTTP["host"] == "b.com"',
                    directives={
                        "server.tag": LighttpdEffectiveDirective(
                            name="server.tag", value='"B"', operator="=",
                            scope="conditional", condition=cond2, source=_src(5),
                        ),
                    },
                ),
            ],
        )
        # No context -> both match -> last wins
        merged = merge_conditional_scopes(eff, context=None)
        assert merged["server.tag"].value == '"B"'

    def test_else_block_always_matches(self) -> None:
        """Scope with condition=None (else block) is always potentially matching."""
        eff = LighttpdEffectiveConfig(
            global_directives={},
            conditional_scopes=[
                LighttpdConditionalScope(
                    condition=None,
                    header="else",
                    directives={
                        "ssl.engine": LighttpdEffectiveDirective(
                            name="ssl.engine", value='"disable"', operator="=",
                            scope="conditional", condition=None, source=_src(5),
                        ),
                    },
                ),
            ],
        )
        ctx = LighttpdRequestContext(host="any.com")
        merged = merge_conditional_scopes(eff, context=ctx)
        assert "ssl.engine" in merged

    def test_empty_config(self) -> None:
        eff = LighttpdEffectiveConfig()
        merged = merge_conditional_scopes(eff)
        assert merged == {}


# ---------------------------------------------------------------------------
# Integration: merge via parsed config
# ---------------------------------------------------------------------------


class TestMergeFromParsedConfig:
    def test_global_and_conditional_merge(self) -> None:
        ast = parse_lighttpd_config(
            'server.port = 80\n'
            '$HTTP["host"] == "secure.example.com" {\n'
            '    ssl.engine = "enable"\n'
            '}\n',
        )
        eff = build_effective_config(ast)
        merged = merge_conditional_scopes(eff, context=None)
        assert merged["server.port"].value == "80"
        assert merged["ssl.engine"].value == '"enable"'

    def test_targeted_host_excludes_non_matching(self) -> None:
        ast = parse_lighttpd_config(
            'server.port = 80\n'
            '$HTTP["host"] == "secure.example.com" {\n'
            '    ssl.engine = "enable"\n'
            '}\n'
            '$HTTP["host"] == "other.example.com" {\n'
            '    server.tag = "other"\n'
            '}\n',
        )
        eff = build_effective_config(ast)
        ctx = LighttpdRequestContext(host="secure.example.com")
        merged = merge_conditional_scopes(eff, context=ctx)
        assert "ssl.engine" in merged
        assert "server.tag" not in merged

    def test_worst_case_includes_all(self) -> None:
        ast = parse_lighttpd_config(
            '$HTTP["host"] == "a.com" {\n'
            '    ssl.engine = "enable"\n'
            '}\n'
            '$HTTP["host"] == "b.com" {\n'
            '    server.tag = "B"\n'
            '}\n',
        )
        eff = build_effective_config(ast)
        merged = merge_conditional_scopes(eff, context=None)
        assert "ssl.engine" in merged
        assert "server.tag" in merged

    def test_regex_condition_matching(self) -> None:
        ast = parse_lighttpd_config(
            '$HTTP["url"] =~ "^/api/" {\n'
            '    server.tag = "api"\n'
            '}\n',
        )
        eff = build_effective_config(ast)
        ctx = LighttpdRequestContext(url_path="/api/v1")
        merged = merge_conditional_scopes(eff, context=ctx)
        assert "server.tag" in merged

    def test_regex_condition_not_matching(self) -> None:
        ast = parse_lighttpd_config(
            '$HTTP["url"] =~ "^/api/" {\n'
            '    server.tag = "api"\n'
            '}\n',
        )
        eff = build_effective_config(ast)
        ctx = LighttpdRequestContext(url_path="/static/file.css")
        merged = merge_conditional_scopes(eff, context=ctx)
        assert "server.tag" not in merged


# ---------------------------------------------------------------------------
# Analyzer integration
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Regression: P1 — nested scopes must respect parent conditions
# ---------------------------------------------------------------------------


class TestNestedConditionChain:
    def test_nested_url_inside_host_excluded_by_host_filter(self) -> None:
        """A nested $HTTP["url"] block inside a non-matching $HTTP["host"]
        must NOT appear in the merge when a targeted host is specified."""
        ast = parse_lighttpd_config(
            '$HTTP["host"] == "a.example" {\n'
            '    $HTTP["url"] =~ "^/admin" {\n'
            '        dir-listing.activate = "enable"\n'
            '    }\n'
            '}\n',
        )
        eff = build_effective_config(ast)
        ctx = LighttpdRequestContext(host="b.example")
        merged = merge_conditional_scopes(eff, context=ctx)
        assert "dir-listing.activate" not in merged

    def test_nested_url_inside_matching_host_included(self) -> None:
        ast = parse_lighttpd_config(
            '$HTTP["host"] == "a.example" {\n'
            '    $HTTP["url"] =~ "^/admin" {\n'
            '        dir-listing.activate = "enable"\n'
            '    }\n'
            '}\n',
        )
        eff = build_effective_config(ast)
        ctx = LighttpdRequestContext(host="a.example")
        merged = merge_conditional_scopes(eff, context=ctx)
        # url condition is unknown -> potentially matching
        assert "dir-listing.activate" in merged

    def test_nested_url_worst_case_includes_all(self) -> None:
        ast = parse_lighttpd_config(
            '$HTTP["host"] == "a.example" {\n'
            '    $HTTP["url"] =~ "^/admin" {\n'
            '        dir-listing.activate = "enable"\n'
            '    }\n'
            '}\n',
        )
        eff = build_effective_config(ast)
        merged = merge_conditional_scopes(eff, context=None)
        assert "dir-listing.activate" in merged

    def test_conditions_tuple_populated_for_nested(self) -> None:
        ast = parse_lighttpd_config(
            '$HTTP["host"] == "a.example" {\n'
            '    $HTTP["url"] =~ "^/admin" {\n'
            '        dir-listing.activate = "enable"\n'
            '    }\n'
            '}\n',
        )
        eff = build_effective_config(ast)
        # There should be 2 scopes: the nested one and the parent.
        # The nested scope (first due to recursion order) has 2 conditions.
        nested = [s for s in eff.conditional_scopes if len(s.conditions) == 2]
        assert len(nested) == 1
        assert nested[0].conditions[0].variable == '$HTTP["host"]'
        assert nested[0].conditions[1].variable == '$HTTP["url"]'


# ---------------------------------------------------------------------------
# Regression: P1 — else blocks must not override matching if-branch
# ---------------------------------------------------------------------------


class TestElseBranchHandling:
    def test_else_skipped_when_if_matches(self) -> None:
        """When targeted host matches the if-branch, the else-branch
        should NOT contribute its directives."""
        ast = parse_lighttpd_config(
            '$HTTP["host"] == "a.example" {\n'
            '    server.tag = ""\n'
            '}\n'
            'else {\n'
            '    server.tag = "Lighttpd"\n'
            '}\n',
        )
        eff = build_effective_config(ast)
        ctx = LighttpdRequestContext(host="a.example")
        merged = merge_conditional_scopes(eff, context=ctx)
        assert merged["server.tag"].value == '""'

    def test_else_included_when_if_not_matching(self) -> None:
        ast = parse_lighttpd_config(
            '$HTTP["host"] == "a.example" {\n'
            '    server.tag = ""\n'
            '}\n'
            'else {\n'
            '    server.tag = "Lighttpd"\n'
            '}\n',
        )
        eff = build_effective_config(ast)
        ctx = LighttpdRequestContext(host="b.example")
        merged = merge_conditional_scopes(eff, context=ctx)
        assert merged["server.tag"].value == '"Lighttpd"'

    def test_else_included_in_worst_case(self) -> None:
        """Without context, both if and else branches are potentially active."""
        ast = parse_lighttpd_config(
            '$HTTP["host"] == "a.example" {\n'
            '    server.tag = ""\n'
            '}\n'
            'else {\n'
            '    server.tag = "Lighttpd"\n'
            '}\n',
        )
        eff = build_effective_config(ast)
        merged = merge_conditional_scopes(eff, context=None)
        # Both match -> last-wins -> else value
        assert merged["server.tag"].value == '"Lighttpd"'

    def test_else_is_else_flag_set(self) -> None:
        ast = parse_lighttpd_config(
            '$HTTP["host"] == "a.example" {\n'
            '    ssl.engine = "enable"\n'
            '}\n'
            'else {\n'
            '    ssl.engine = "disable"\n'
            '}\n',
        )
        eff = build_effective_config(ast)
        else_scopes = [s for s in eff.conditional_scopes if s.is_else]
        assert len(else_scopes) == 1
        if_scopes = [s for s in eff.conditional_scopes if not s.is_else]
        assert len(if_scopes) == 1
        assert else_scopes[0].sibling_if_index >= 0


# ---------------------------------------------------------------------------
# Regression: P2 — rules use merged_directives for host filtering
# ---------------------------------------------------------------------------


class TestRulesUseMergedDirectives:
    def test_server_tag_rule_uses_merged(self) -> None:
        """server_tag_not_blank should respect --host filter via merged_directives."""
        from webconf_audit.local.lighttpd import analyze_lighttpd_config

        import tempfile
        import os

        config_text = (
            '$HTTP["host"] == "a.example" {\n'
            '    server.tag = "A-Banner"\n'
            '}\n'
            '$HTTP["host"] == "b.example" {\n'
            '    server.tag = ""\n'
            '}\n'
        )
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False, encoding="utf-8",
        ) as f:
            f.write(config_text)
            f.flush()
            path = f.name

        try:
            result_a = analyze_lighttpd_config(path, host="a.example")
            result_b = analyze_lighttpd_config(path, host="b.example")
        finally:
            os.unlink(path)

        tag_findings_a = [
            f for f in result_a.findings
            if f.rule_id == "lighttpd.server_tag_not_blank"
        ]
        tag_findings_b = [
            f for f in result_b.findings
            if f.rule_id == "lighttpd.server_tag_not_blank"
        ]
        # a.example has a non-blank tag -> finding
        assert len(tag_findings_a) >= 1
        # b.example has blank tag -> no finding
        assert len(tag_findings_b) == 0

    def test_dir_listing_rule_uses_merged(self) -> None:
        """dir_listing_enabled should respect --host filter via merged_directives."""
        from webconf_audit.local.lighttpd import analyze_lighttpd_config

        import tempfile
        import os

        config_text = (
            '$HTTP["host"] == "a.example" {\n'
            '    dir-listing.activate = "enable"\n'
            '}\n'
            '$HTTP["host"] == "b.example" {\n'
            '    dir-listing.activate = "disable"\n'
            '}\n'
        )
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False, encoding="utf-8",
        ) as f:
            f.write(config_text)
            f.flush()
            path = f.name

        try:
            result_a = analyze_lighttpd_config(path, host="a.example")
            result_b = analyze_lighttpd_config(path, host="b.example")
        finally:
            os.unlink(path)

        dir_findings_a = [
            f for f in result_a.findings
            if f.rule_id == "lighttpd.dir_listing_enabled"
        ]
        dir_findings_b = [
            f for f in result_b.findings
            if f.rule_id == "lighttpd.dir_listing_enabled"
        ]
        # a.example enables dir listing -> finding
        assert len(dir_findings_a) >= 1
        # b.example disables it -> no finding
        assert len(dir_findings_b) == 0


# ---------------------------------------------------------------------------
# Regression: P2 — normalizer uses merged_directives for universal findings
# ---------------------------------------------------------------------------


class TestNormalizerUseMergedDirectives:
    def test_normalizer_with_merged_filters_scopes(self) -> None:
        from webconf_audit.local.normalizers import normalize_config

        ast = parse_lighttpd_config(
            '$HTTP["host"] == "a.example" {\n'
            '    ssl.engine = "enable"\n'
            '}\n'
            '$HTTP["host"] == "b.example" {\n'
            '    server.tag = "B"\n'
            '}\n',
        )
        eff = build_effective_config(ast)
        ctx = LighttpdRequestContext(host="a.example")
        merged = merge_conditional_scopes(eff, context=ctx)

        normalized = normalize_config(
            "lighttpd", ast=ast, effective_config=eff,
            merged_directives=merged,
        )
        # Should have a single "merged" scope, not all conditional scopes.
        assert len(normalized.scopes) == 1
        assert normalized.scopes[0].scope_name == "merged"


# ---------------------------------------------------------------------------
# Regression: P2 — AST-based Lighttpd rules respect host filtering
# ---------------------------------------------------------------------------


class TestAstRulesRespectHostFilter:
    def test_header_rules_use_merged_view(self) -> None:
        from webconf_audit.local.lighttpd import analyze_lighttpd_config

        import os
        import tempfile

        config_text = (
            'server.tag = ""\n'
            'server.errorlog = "/var/log/error.log"\n'
            '$HTTP["host"] == "a.example" {\n'
            '    setenv.add-response-header = ( '
            '"Strict-Transport-Security" => "max-age=31536000", '
            '"X-Content-Type-Options" => "nosniff" )\n'
            '}\n'
        )
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False, encoding="utf-8",
        ) as f:
            f.write(config_text)
            f.flush()
            path = f.name

        try:
            result_a = analyze_lighttpd_config(path, host="a.example")
            result_b = analyze_lighttpd_config(path, host="b.example")
        finally:
            os.unlink(path)

        rule_ids_a = {f.rule_id for f in result_a.findings}
        rule_ids_b = {f.rule_id for f in result_b.findings}

        assert "lighttpd.missing_strict_transport_security" not in rule_ids_a
        assert "lighttpd.missing_x_content_type_options" not in rule_ids_a
        assert "lighttpd.missing_strict_transport_security" in rule_ids_b
        assert "lighttpd.missing_x_content_type_options" in rule_ids_b

    def test_mod_status_public_uses_merged_view(self) -> None:
        from webconf_audit.local.lighttpd import analyze_lighttpd_config

        import os
        import tempfile

        config_text = (
            'server.tag = ""\n'
            'server.errorlog = "/var/log/error.log"\n'
            '$HTTP["host"] == "a.example" {\n'
            '    status.status-url = "/server-status"\n'
            '}\n'
        )
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False, encoding="utf-8",
        ) as f:
            f.write(config_text)
            f.flush()
            path = f.name

        try:
            result_a = analyze_lighttpd_config(path, host="a.example")
            result_b = analyze_lighttpd_config(path, host="b.example")
        finally:
            os.unlink(path)

        findings_a = [f for f in result_a.findings if f.rule_id == "lighttpd.mod_status_public"]
        findings_b = [f for f in result_b.findings if f.rule_id == "lighttpd.mod_status_public"]

        assert len(findings_a) == 1
        assert findings_a[0].location is not None
        assert findings_a[0].location.line == 4
        assert findings_b == []

    def test_mod_status_public_stays_silent_for_nested_remoteip_scope(self) -> None:
        from webconf_audit.local.lighttpd import analyze_lighttpd_config

        import os
        import tempfile

        config_text = (
            'server.tag = ""\n'
            'server.errorlog = "/var/log/error.log"\n'
            '$HTTP["host"] == "a.example" {\n'
            '    $HTTP["remoteip"] == "127.0.0.1" {\n'
            '        status.status-url = "/server-status"\n'
            "    }\n"
            '}\n'
        )
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False, encoding="utf-8",
        ) as f:
            f.write(config_text)
            f.flush()
            path = f.name

        try:
            result = analyze_lighttpd_config(path, host="a.example")
        finally:
            os.unlink(path)

        assert not any(f.rule_id == "lighttpd.mod_status_public" for f in result.findings)


# ---------------------------------------------------------------------------
# Analyzer integration
# ---------------------------------------------------------------------------


class TestAnalyzerHostFilter:
    def test_analyze_with_host_sets_metadata(self, tmp_path) -> None:
        config = tmp_path / "lighttpd.conf"
        config.write_text('server.port = 80\n', encoding="utf-8")
        from webconf_audit.local.lighttpd import analyze_lighttpd_config

        result = analyze_lighttpd_config(str(config), host="example.com")
        assert result.metadata["host_filter"] == "example.com"

    def test_analyze_without_host_sets_none(self, tmp_path) -> None:
        config = tmp_path / "lighttpd.conf"
        config.write_text('server.port = 80\n', encoding="utf-8")
        from webconf_audit.local.lighttpd import analyze_lighttpd_config

        result = analyze_lighttpd_config(str(config))
        assert result.metadata["host_filter"] is None


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


class TestCLIHostOption:
    def test_cli_help_includes_host(self) -> None:
        from typer.testing import CliRunner
        from webconf_audit.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["analyze-lighttpd", "--help"])
        assert "--host" in result.output

    def test_cli_with_host(self, tmp_path) -> None:
        from typer.testing import CliRunner
        from webconf_audit.cli import app

        config = tmp_path / "lighttpd.conf"
        config.write_text('server.port = 80\n', encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(app, [
            "analyze-lighttpd", str(config), "--host", "example.com",
        ])
        assert result.exit_code == 0
