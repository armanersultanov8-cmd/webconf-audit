"""Tests for the rule registry core: RuleMeta, RuleRegistry, @rule decorator.

The ensure_loaded tests use a self-contained fake package under
``tests/_fake_rule_pkg/`` that contains decorated rule functions.  This
avoids coupling to the real rule modules (which don't have @rule yet)
and gives full control over expected counts and rule_ids.
"""

from __future__ import annotations

import sys

import pytest

from webconf_audit.rule_registry import (
    RuleEntry,
    RuleMeta,
    RuleRegistry,
    rule,
    registry as global_registry,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAKE_PKG = "tests._fake_rule_pkg"

# Rule IDs defined in the fake package (public modules only).
_FAKE_PUBLIC_IDS = {"fake.alpha_one", "fake.alpha_two", "fake.beta_one"}
_FAKE_PRIVATE_ID = "fake.private_should_not_load"


def _meta(
    rule_id: str = "test.sample",
    *,
    title: str = "Sample",
    severity: str = "low",
    description: str = "desc",
    recommendation: str = "rec",
    category: str = "local",
    server_type: str | None = None,
    input_kind: str = "ast",
    tags: tuple[str, ...] = (),
    condition: str | None = None,
    order: int = 1000,
) -> RuleMeta:
    return RuleMeta(
        rule_id=rule_id,
        title=title,
        severity=severity,
        description=description,
        recommendation=recommendation,
        category=category,
        server_type=server_type,
        input_kind=input_kind,
        tags=tags,
        condition=condition,
        order=order,
    )


def _noop(*_args, **_kwargs):
    return []


@pytest.fixture()
def reg() -> RuleRegistry:
    """Return a fresh, empty registry for each test."""
    return RuleRegistry()


def _purge_fake_from_global():
    """Remove fake rule IDs from the global singleton so tests are independent."""
    for rid in list(global_registry._catalog):
        if rid.startswith("fake."):
            global_registry._catalog.pop(rid, None)
            global_registry._executable.pop(rid, None)


def _purge_fake_modules():
    """Remove fake package modules from sys.modules to allow reimport."""
    to_remove = [k for k in sys.modules if k.startswith("tests._fake_rule_pkg")]
    for k in to_remove:
        del sys.modules[k]


# ---------------------------------------------------------------------------
# RuleMeta
# ---------------------------------------------------------------------------


class TestRuleMeta:
    def test_frozen(self):
        meta = _meta()
        with pytest.raises(AttributeError):
            meta.rule_id = "other"  # type: ignore[misc]

    def test_defaults(self):
        meta = _meta()
        assert meta.tags == ()
        assert meta.condition is None
        assert meta.order == 1000
        assert meta.input_kind == "ast"
        assert meta.server_type is None

    def test_equality(self):
        a = _meta(rule_id="x.a")
        b = _meta(rule_id="x.a")
        assert a == b

    def test_all_fields(self):
        meta = _meta(
            rule_id="nginx.foo",
            title="Foo",
            severity="high",
            description="D",
            recommendation="R",
            category="local",
            server_type="nginx",
            input_kind="effective",
            tags=("tls", "disclosure"),
            condition=None,
            order=50,
        )
        assert meta.rule_id == "nginx.foo"
        assert meta.severity == "high"
        assert meta.input_kind == "effective"
        assert meta.tags == ("tls", "disclosure")
        assert meta.order == 50


# ---------------------------------------------------------------------------
# RuleRegistry -- register / get / get_meta
# ---------------------------------------------------------------------------


class TestRegistryBasic:
    def test_register_and_get(self, reg: RuleRegistry):
        meta = _meta()
        reg.register(meta, _noop)
        entry = reg.get("test.sample")
        assert entry is not None
        assert entry.meta is meta
        assert entry.fn is _noop

    def test_register_adds_to_catalog(self, reg: RuleRegistry):
        meta = _meta()
        reg.register(meta, _noop)
        assert reg.get_meta("test.sample") is meta

    def test_register_meta_only(self, reg: RuleRegistry):
        meta = _meta(rule_id="iis.browse")
        reg.register_meta(meta)
        assert reg.get_meta("iis.browse") is meta
        assert reg.get("iis.browse") is None  # not executable

    def test_duplicate_register_raises(self, reg: RuleRegistry):
        meta = _meta()
        reg.register(meta, _noop)
        with pytest.raises(ValueError, match="Duplicate rule_id"):
            reg.register(meta, _noop)

    def test_duplicate_register_meta_raises(self, reg: RuleRegistry):
        meta = _meta()
        reg.register_meta(meta)
        with pytest.raises(ValueError, match="Duplicate rule_id"):
            reg.register_meta(meta)

    def test_duplicate_register_then_meta_raises(self, reg: RuleRegistry):
        meta = _meta()
        reg.register(meta, _noop)
        with pytest.raises(ValueError, match="Duplicate rule_id"):
            reg.register_meta(meta)

    def test_get_nonexistent(self, reg: RuleRegistry):
        assert reg.get("nonexistent") is None
        assert reg.get_meta("nonexistent") is None

    def test_catalog_and_executable_size(self, reg: RuleRegistry):
        reg.register(_meta(rule_id="a.1"), _noop)
        reg.register_meta(_meta(rule_id="b.2"))
        assert reg.catalog_size == 2
        assert reg.executable_size == 1

    def test_clear(self, reg: RuleRegistry):
        reg.register(_meta(rule_id="a.1"), _noop)
        reg.register_meta(_meta(rule_id="b.2"))
        reg.clear()
        assert reg.catalog_size == 0
        assert reg.executable_size == 0

    def test_repr(self, reg: RuleRegistry):
        assert "catalog=0" in repr(reg)


# ---------------------------------------------------------------------------
# list_rules (catalog queries)
# ---------------------------------------------------------------------------


class TestListRules:
    @pytest.fixture(autouse=True)
    def _populate(self, reg: RuleRegistry):
        reg.register(
            _meta(rule_id="nginx.a", category="local", server_type="nginx", severity="low", order=10),
            _noop,
        )
        reg.register(
            _meta(rule_id="nginx.b", category="local", server_type="nginx", severity="high", tags=("tls",), order=20),
            _noop,
        )
        reg.register(
            _meta(rule_id="apache.c", category="local", server_type="apache", severity="medium", order=10),
            _noop,
        )
        reg.register(
            _meta(rule_id="universal.d", category="universal", severity="medium", input_kind="normalized", order=5),
            _noop,
        )
        reg.register_meta(
            _meta(rule_id="external.e", category="external", severity="low", input_kind="probe", order=1),
        )
        reg.register_meta(
            _meta(rule_id="external.nginx.f", category="external", severity="low", condition="nginx", input_kind="probe"),
        )

    def test_list_all(self, reg: RuleRegistry):
        assert len(reg.list_rules()) == 6

    def test_filter_category_local(self, reg: RuleRegistry):
        rules = reg.list_rules(category="local")
        assert {m.rule_id for m in rules} == {"nginx.a", "nginx.b", "apache.c"}

    def test_filter_category_universal(self, reg: RuleRegistry):
        rules = reg.list_rules(category="universal")
        assert len(rules) == 1
        assert rules[0].rule_id == "universal.d"

    def test_filter_category_external(self, reg: RuleRegistry):
        rules = reg.list_rules(category="external")
        assert len(rules) == 2

    def test_filter_server_type(self, reg: RuleRegistry):
        rules = reg.list_rules(server_type="nginx")
        assert {m.rule_id for m in rules} == {"nginx.a", "nginx.b"}

    def test_filter_severity(self, reg: RuleRegistry):
        rules = reg.list_rules(severity="high")
        assert len(rules) == 1
        assert rules[0].rule_id == "nginx.b"

    def test_filter_tag(self, reg: RuleRegistry):
        rules = reg.list_rules(tag="tls")
        assert len(rules) == 1
        assert rules[0].rule_id == "nginx.b"

    def test_combined_filters(self, reg: RuleRegistry):
        rules = reg.list_rules(category="local", server_type="nginx", severity="low")
        assert len(rules) == 1
        assert rules[0].rule_id == "nginx.a"

    def test_no_match(self, reg: RuleRegistry):
        assert reg.list_rules(category="local", server_type="iis") == []

    def test_sorted_by_order_then_rule_id(self, reg: RuleRegistry):
        rules = reg.list_rules(category="local", server_type="nginx")
        assert [m.rule_id for m in rules] == ["nginx.a", "nginx.b"]

    def test_meta_only_included_in_list(self, reg: RuleRegistry):
        """register_meta entries appear in list_rules."""
        rules = reg.list_rules(category="external")
        ids = {m.rule_id for m in rules}
        assert "external.e" in ids

    def test_deterministic_order_across_categories(self, reg: RuleRegistry):
        all_rules = reg.list_rules()
        ids = [m.rule_id for m in all_rules]
        # external.e (order=1) < universal.d (order=5) < nginx.a/apache.c (order=10) < nginx.b (order=20) < external.nginx.f (order=1000)
        assert ids.index("external.e") < ids.index("universal.d")
        assert ids.index("universal.d") < ids.index("nginx.a")
        assert ids.index("nginx.b") > ids.index("nginx.a")


# ---------------------------------------------------------------------------
# rules_for (executable queries)
# ---------------------------------------------------------------------------


class TestRulesFor:
    @pytest.fixture(autouse=True)
    def _populate(self, reg: RuleRegistry):
        reg.register(
            _meta(rule_id="nginx.x", category="local", server_type="nginx", order=20),
            _noop,
        )
        reg.register(
            _meta(rule_id="nginx.y", category="local", server_type="nginx", order=10),
            _noop,
        )
        reg.register(
            _meta(rule_id="universal.z", category="universal", input_kind="normalized"),
            _noop,
        )
        # Meta-only: should NOT appear in rules_for
        reg.register_meta(
            _meta(rule_id="iis.q", category="local", server_type="iis"),
        )

    def test_rules_for_local_nginx(self, reg: RuleRegistry):
        entries = reg.rules_for("local", server_type="nginx")
        assert len(entries) == 2
        assert all(isinstance(e, RuleEntry) for e in entries)

    def test_rules_for_universal(self, reg: RuleRegistry):
        entries = reg.rules_for("universal")
        assert len(entries) == 1
        assert entries[0].meta.rule_id == "universal.z"

    def test_meta_only_excluded(self, reg: RuleRegistry):
        entries = reg.rules_for("local", server_type="iis")
        assert entries == []

    def test_sorted_by_order(self, reg: RuleRegistry):
        entries = reg.rules_for("local", server_type="nginx")
        assert [e.meta.rule_id for e in entries] == ["nginx.y", "nginx.x"]

    def test_empty_category(self, reg: RuleRegistry):
        assert reg.rules_for("external") == []


# ---------------------------------------------------------------------------
# @rule decorator
# ---------------------------------------------------------------------------


class TestRuleDecorator:
    def test_decorator_stores_rule_meta_on_function(self):
        """@rule stores _rule_meta attribute on the decorated function."""
        test_id = "__test_decorator_meta_attr__"
        _purge_fake_from_global()
        global_registry._catalog.pop(test_id, None)
        global_registry._executable.pop(test_id, None)

        try:

            @rule(
                rule_id=test_id,
                title="Probe",
                severity="info",
                description="d",
                recommendation="r",
                category="universal",
                input_kind="normalized",
            )
            def _probe(cfg):
                return []

            assert hasattr(_probe, "_rule_meta")
            assert isinstance(_probe._rule_meta, RuleMeta)
            assert _probe._rule_meta.rule_id == test_id
        finally:
            global_registry._catalog.pop(test_id, None)
            global_registry._executable.pop(test_id, None)

    def test_decorator_registers_in_global(self):
        """@rule registers the function in the global registry singleton."""
        test_id = "__test_decorator_global__"
        global_registry._catalog.pop(test_id, None)
        global_registry._executable.pop(test_id, None)

        try:

            @rule(
                rule_id=test_id,
                title="Probe",
                severity="info",
                description="d",
                recommendation="r",
                category="universal",
                input_kind="normalized",
            )
            def _probe(cfg):
                return []

            assert global_registry.get_meta(test_id) is not None
            entry = global_registry.get(test_id)
            assert entry is not None
            assert entry.fn is _probe
        finally:
            global_registry._catalog.pop(test_id, None)
            global_registry._executable.pop(test_id, None)

    def test_decorator_idempotent_on_global(self):
        """If rule_id is already in the global catalog, @rule does not raise."""
        test_id = "__test_decorator_idempotent__"
        global_registry._catalog.pop(test_id, None)
        global_registry._executable.pop(test_id, None)

        try:
            meta = _meta(rule_id=test_id, category="universal")
            global_registry.register(meta, _noop)

            # Applying @rule with the same id should NOT raise.
            @rule(
                rule_id=test_id,
                title="Dup",
                severity="low",
                description="d",
                recommendation="r",
                category="universal",
            )
            def _dup(cfg):
                return []

            # _rule_meta is still stored on the function
            assert _dup._rule_meta.rule_id == test_id
        finally:
            global_registry._catalog.pop(test_id, None)
            global_registry._executable.pop(test_id, None)

    def test_decorator_preserves_function(self):
        """Decorated function is still callable and returns normally."""
        test_id = "__test_decorator_return__"
        global_registry._catalog.pop(test_id, None)
        global_registry._executable.pop(test_id, None)

        try:

            @rule(
                rule_id=test_id,
                title="T",
                severity="low",
                description="d",
                recommendation="r",
                category="local",
                server_type="nginx",
            )
            def _sample(_config_ast) -> list[str]:
                return ["finding"]

            assert _sample(None) == ["finding"]
        finally:
            global_registry._catalog.pop(test_id, None)
            global_registry._executable.pop(test_id, None)


# ---------------------------------------------------------------------------
# ensure_loaded -- with fake rule package
# ---------------------------------------------------------------------------


class TestEnsureLoaded:
    """Test auto-discovery using ``tests/_fake_rule_pkg/``.

    The fake package has:
    - ``alpha.py``  — 2 rules (fake.alpha_one, fake.alpha_two)
    - ``beta.py``   — 1 rule  (fake.beta_one)
    - ``_private.py`` — 1 rule (should NOT be loaded)
    """

    @pytest.fixture(autouse=True)
    def _clean(self):
        """Purge fake rules from global and sys.modules before/after each test."""
        _purge_fake_from_global()
        _purge_fake_modules()
        yield
        _purge_fake_from_global()
        _purge_fake_modules()

    def test_fresh_registry_discovers_decorated_rules(self):
        """A brand-new RuleRegistry discovers all @rule functions via _rule_meta scan."""
        fresh = RuleRegistry()
        assert fresh.catalog_size == 0

        fresh.ensure_loaded(_FAKE_PKG)

        registered_ids = {m.rule_id for m in fresh.list_rules()}
        assert _FAKE_PUBLIC_IDS == registered_ids
        assert fresh.executable_size == 3

    def test_populates_self_not_only_global(self):
        """ensure_loaded registers on the instance it's called on."""
        fresh = RuleRegistry()
        fresh.ensure_loaded(_FAKE_PKG)

        for rid in _FAKE_PUBLIC_IDS:
            entry = fresh.get(rid)
            assert entry is not None, f"{rid} missing from fresh registry"
            assert callable(entry.fn)
            assert hasattr(entry.fn, "_rule_meta")

    def test_clear_then_reload(self):
        """After clear(), ensure_loaded re-registers from cached modules."""
        fresh = RuleRegistry()
        fresh.ensure_loaded(_FAKE_PKG)
        assert fresh.executable_size == 3

        fresh.clear()
        assert fresh.catalog_size == 0
        assert fresh.executable_size == 0

        # Modules are still cached in sys.modules — but scan finds _rule_meta.
        fresh.ensure_loaded(_FAKE_PKG)
        registered_ids = {m.rule_id for m in fresh.list_rules()}
        assert _FAKE_PUBLIC_IDS == registered_ids
        assert fresh.executable_size == 3

    def test_idempotent(self):
        """Calling ensure_loaded twice is a no-op."""
        fresh = RuleRegistry()
        fresh.ensure_loaded(_FAKE_PKG)
        size = fresh.catalog_size
        fresh.ensure_loaded(_FAKE_PKG)
        assert fresh.catalog_size == size

    def test_skips_private_modules(self):
        """Modules starting with _ are not imported by ensure_loaded."""
        fresh = RuleRegistry()
        fresh.ensure_loaded(_FAKE_PKG)
        assert fresh.get_meta(_FAKE_PRIVATE_ID) is None

    def test_discovered_rules_have_correct_metadata(self):
        """Metadata from @rule decorator is preserved through discovery."""
        fresh = RuleRegistry()
        fresh.ensure_loaded(_FAKE_PKG)

        alpha_one = fresh.get_meta("fake.alpha_one")
        assert alpha_one is not None
        assert alpha_one.severity == "low"
        assert alpha_one.server_type == "nginx"
        assert alpha_one.order == 10

        beta_one = fresh.get_meta("fake.beta_one")
        assert beta_one is not None
        assert beta_one.severity == "high"
        assert beta_one.category == "universal"
        assert beta_one.input_kind == "normalized"

    def test_discovered_rules_sorted_by_order(self):
        """rules_for returns entries in deterministic order."""
        fresh = RuleRegistry()
        fresh.ensure_loaded(_FAKE_PKG)

        nginx_entries = fresh.rules_for("local", server_type="nginx")
        assert [e.meta.rule_id for e in nginx_entries] == [
            "fake.alpha_one",  # order=10
            "fake.alpha_two",  # order=20
        ]

    def test_nonexistent_package_raises(self, reg: RuleRegistry):
        with pytest.raises(ModuleNotFoundError):
            reg.ensure_loaded("webconf_audit.nonexistent_package_xyz")

    def test_package_without_path(self, reg: RuleRegistry):
        """A plain module (no __path__) does not crash."""
        reg.ensure_loaded("webconf_audit.models")
        assert reg.catalog_size == 0


# ---------------------------------------------------------------------------
# ensure_loaded -- real universal rules package (integration)
# ---------------------------------------------------------------------------


class TestEnsureLoadedUniversal:
    """Integration tests: ensure_loaded discovers all 11 real universal rules."""

    _UNIVERSAL_PKG = "webconf_audit.local.rules.universal"
    _EXPECTED_IDS = {
        "universal.tls_intent_without_config",
        "universal.weak_tls_protocol",
        "universal.weak_tls_ciphers",
        "universal.missing_hsts",
        "universal.missing_x_content_type_options",
        "universal.missing_x_frame_options",
        "universal.missing_content_security_policy",
        "universal.missing_referrer_policy",
        "universal.directory_listing_enabled",
        "universal.server_identification_disclosed",
        "universal.listen_on_all_interfaces",
    }

    def test_fresh_registry_discovers_all_11(self):
        fresh = RuleRegistry()
        fresh.ensure_loaded(self._UNIVERSAL_PKG)
        registered_ids = {m.rule_id for m in fresh.list_rules()}
        assert self._EXPECTED_IDS == registered_ids
        assert fresh.executable_size == 11

    def test_all_are_category_universal(self):
        fresh = RuleRegistry()
        fresh.ensure_loaded(self._UNIVERSAL_PKG)
        for entry in fresh.rules_for("universal"):
            assert entry.meta.category == "universal"
            assert entry.meta.input_kind == "normalized"

    def test_deterministic_order(self):
        fresh = RuleRegistry()
        fresh.ensure_loaded(self._UNIVERSAL_PKG)
        entries = fresh.rules_for("universal")
        orders = [e.meta.order for e in entries]
        assert orders == sorted(orders), "Universal rules should be sorted by order"
        # All orders in [100..110]
        assert all(100 <= o <= 110 for o in orders)

    def test_clear_then_reload_universal(self):
        fresh = RuleRegistry()
        fresh.ensure_loaded(self._UNIVERSAL_PKG)
        assert fresh.executable_size == 11
        fresh.clear()
        fresh.ensure_loaded(self._UNIVERSAL_PKG)
        assert fresh.executable_size == 11

    def test_run_universal_rules_uses_registry(self):
        """run_universal_rules produces findings via registry-backed discovery."""
        from webconf_audit.local.normalized import (
            NormalizedConfig,
            NormalizedListenPoint,
            NormalizedScope,
            SourceRef,
        )

        ref = SourceRef(server_type="nginx", file_path="/f.conf", line=1)
        scope = NormalizedScope(
            scope_name="test",
            listen_points=[NormalizedListenPoint(port=80, protocol="http", tls=False, source=ref)],
        )
        cfg = NormalizedConfig(server_type="nginx", scopes=[scope])

        from webconf_audit.local.universal_rules import run_universal_rules

        findings = run_universal_rules(cfg)
        rule_ids = {f.rule_id for f in findings}
        # At minimum: missing headers + listen wildcard + dir listing absent won't fire,
        # but missing_x_content_type_options etc. should fire
        assert any(rid.startswith("universal.") for rid in rule_ids)


# ---------------------------------------------------------------------------
# RuleEntry
# ---------------------------------------------------------------------------


class TestRuleEntry:
    def test_frozen(self):
        entry = RuleEntry(meta=_meta(), fn=_noop)
        with pytest.raises(AttributeError):
            entry.fn = _noop  # type: ignore[misc]

    def test_callable(self):
        entry = RuleEntry(meta=_meta(), fn=_noop)
        assert callable(entry.fn)
        assert entry.fn() == []
