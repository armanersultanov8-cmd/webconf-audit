from __future__ import annotations

from pathlib import Path
from typing import NoReturn

import pytest

from webconf_audit.local.normalized import NormalizedConfig
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import RuleEntry, RuleMeta


def _finding(rule_id: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=f"{rule_id} title",
        severity="low",
        description="test finding",
        recommendation="test recommendation",
        location=SourceLocation(
            mode="local",
            kind="check",
            target=rule_id,
        ),
    )


def _entry(
    rule_id: str,
    *,
    category: str,
    server_type: str | None = None,
    input_kind: str = "ast",
    fn,
) -> RuleEntry:
    return RuleEntry(
        meta=RuleMeta(
            rule_id=rule_id,
            title=f"{rule_id} title",
            severity="low",
            description="test description",
            recommendation="test recommendation",
            category=category,
            server_type=server_type,
            input_kind=input_kind,
        ),
        fn=fn,
    )


def test_run_universal_rules_collects_rule_execution_issue_and_continues(monkeypatch):
    from webconf_audit.local import universal_rules as module

    cfg = NormalizedConfig(server_type="nginx", scopes=[])
    issues = []

    def _raise(_normalized) -> NoReturn:
        raise RuntimeError("boom")

    good_entry = _entry(
        "universal.good",
        category="universal",
        input_kind="normalized",
        fn=lambda _normalized: [_finding("universal.good")],
    )
    bad_entry = _entry(
        "universal.bad",
        category="universal",
        input_kind="normalized",
        fn=_raise,
    )

    monkeypatch.setattr(module.registry, "ensure_loaded", lambda _package_name: None)
    monkeypatch.setattr(
        module.registry,
        "rules_for",
        lambda _category, server_type=None: [bad_entry, good_entry],
    )

    findings = module.run_universal_rules(cfg, issues=issues)

    assert [finding.rule_id for finding in findings] == ["universal.good"]
    assert len(issues) == 1
    assert issues[0].code == "rule_execution_error"
    assert issues[0].metadata["rule_id"] == "universal.bad"
    assert issues[0].metadata["input_kind"] == "normalized"
    assert issues[0].location is not None
    assert issues[0].location.target == "universal.bad"
    assert issues[0].details == "RuntimeError: boom"


def test_run_universal_rules_reraises_without_issue_collector(monkeypatch):
    from webconf_audit.local import universal_rules as module

    cfg = NormalizedConfig(server_type="nginx", scopes=[])

    def _raise(_normalized) -> NoReturn:
        raise RuntimeError("boom")

    bad_entry = _entry(
        "universal.bad",
        category="universal",
        input_kind="normalized",
        fn=_raise,
    )

    monkeypatch.setattr(module.registry, "ensure_loaded", lambda _package_name: None)
    monkeypatch.setattr(
        module.registry,
        "rules_for",
        lambda _category, server_type=None: [bad_entry],
    )

    with pytest.raises(RuntimeError, match="boom"):
        module.run_universal_rules(cfg)


def test_run_lighttpd_rules_collects_effective_rule_execution_issue(monkeypatch):
    from webconf_audit.local.lighttpd import rules_runner as module

    issues = []

    def _raise(*_args: object, **_kwargs: object) -> NoReturn:
        raise ValueError("bad effective rule")

    bad_entry = _entry(
        "lighttpd.bad-effective",
        category="local",
        server_type="lighttpd",
        input_kind="effective",
        fn=_raise,
    )
    good_entry = _entry(
        "lighttpd.good-ast",
        category="local",
        server_type="lighttpd",
        input_kind="ast",
        fn=lambda _config_ast: [_finding("lighttpd.good-ast")],
    )

    monkeypatch.setattr(module.registry, "ensure_loaded", lambda _package_name: None)
    monkeypatch.setattr(
        module.registry,
        "rules_for",
        lambda _category, server_type=None: [bad_entry, good_entry],
    )

    findings = module.run_lighttpd_rules(
        object(),
        effective_config=object(),
        merged_directives={},
        issues=issues,
    )

    assert [finding.rule_id for finding in findings] == ["lighttpd.good-ast"]
    assert len(issues) == 1
    assert issues[0].metadata["rule_id"] == "lighttpd.bad-effective"
    assert issues[0].metadata["input_kind"] == "effective"
    assert issues[0].details == "ValueError: bad effective rule"


def test_run_iis_rules_collects_rule_execution_issue_and_continues(monkeypatch):
    from webconf_audit.local.iis import rules_runner as module

    issues = []

    def _raise(*_args: object, **_kwargs: object) -> NoReturn:
        raise RuntimeError("bad iis rule")

    bad_entry = _entry(
        "iis.bad",
        category="local",
        server_type="iis",
        fn=_raise,
    )
    good_entry = _entry(
        "iis.good",
        category="local",
        server_type="iis",
        fn=lambda _doc, **_kwargs: [_finding("iis.good")],
    )

    monkeypatch.setattr(module.registry, "ensure_loaded", lambda _package_name: None)
    monkeypatch.setattr(
        module.registry,
        "rules_for",
        lambda _category, server_type=None: [bad_entry, good_entry],
    )

    findings = module.run_iis_rules(object(), effective_config=object(), issues=issues)

    assert [finding.rule_id for finding in findings] == ["iis.good"]
    assert len(issues) == 1
    assert issues[0].metadata["rule_id"] == "iis.bad"
    assert issues[0].details == "RuntimeError: bad iis rule"


def test_analyze_nginx_config_reports_rule_execution_issue(monkeypatch, tmp_path: Path):
    from webconf_audit.local.nginx import analyze_nginx_config
    from webconf_audit.local.nginx import rules_runner as module

    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        "    server {\n"
        "        listen 80;\n"
        "        server_name example.test;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    original_ensure_loaded = module.registry.ensure_loaded
    original_rules_for = module.registry.rules_for

    def _raise(_config_ast) -> NoReturn:
        raise RuntimeError("broken nginx rule")

    bad_entry = _entry(
        "nginx.bad",
        category="local",
        server_type="nginx",
        fn=_raise,
    )

    def _fake_ensure_loaded(package_name: str) -> None:
        if package_name == module._NGINX_PKG:
            return
        original_ensure_loaded(package_name)

    def _fake_rules_for(
        category: str,
        server_type: str | None = None,
    ) -> list[RuleEntry]:
        if category == "local" and server_type == "nginx":
            return [bad_entry]
        return original_rules_for(category, server_type)

    monkeypatch.setattr(module.registry, "ensure_loaded", _fake_ensure_loaded)
    monkeypatch.setattr(module.registry, "rules_for", _fake_rules_for)

    result = analyze_nginx_config(str(config_path))

    assert any(
        issue.code == "rule_execution_error"
        and issue.metadata["rule_id"] == "nginx.bad"
        and issue.details == "RuntimeError: broken nginx rule"
        for issue in result.issues
    )
