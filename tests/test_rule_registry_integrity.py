"""Integrity tests for the rule registry.

Verify that all rule packages load the expected number of rules into
the catalog and executable stores, with no duplicate IDs and correct
ordering.
"""

from __future__ import annotations

import pytest

from webconf_audit.rule_registry import RuleRegistry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fresh_registry() -> RuleRegistry:
    """Return a registry loaded with all known rule packages."""
    reg = RuleRegistry()
    # Executable rules (decorator-based)
    reg.ensure_loaded("webconf_audit.local.rules.universal")
    reg.ensure_loaded("webconf_audit.local.nginx.rules")
    reg.ensure_loaded("webconf_audit.local.apache.rules")
    reg.ensure_loaded("webconf_audit.local.lighttpd.rules")
    reg.ensure_loaded("webconf_audit.local.iis.rules")
    # Meta-only rules (external) register on module import.
    import webconf_audit.external.rules._runner  # noqa: F401

    for meta in webconf_audit.external.rules._runner._EXTERNAL_RULE_METAS:
        if meta.rule_id not in reg._catalog:
            reg.register_meta(meta)
    return reg


@pytest.fixture()
def full_reg() -> RuleRegistry:
    return _fresh_registry()


# ---------------------------------------------------------------------------
# Total counts
# ---------------------------------------------------------------------------

class TestTotalCounts:
    def test_catalog_total(self, full_reg: RuleRegistry) -> None:
        assert len(full_reg._catalog) == 183

    def test_executable_total(self, full_reg: RuleRegistry) -> None:
        assert len(full_reg._executable) == 114


# ---------------------------------------------------------------------------
# Per-category / per-server counts
# ---------------------------------------------------------------------------

class TestCategoryCounts:
    def test_universal(self, full_reg: RuleRegistry) -> None:
        rules = full_reg.list_rules(category="universal")
        assert len(rules) == 11

    def test_nginx(self, full_reg: RuleRegistry) -> None:
        rules = full_reg.list_rules(category="local", server_type="nginx")
        assert len(rules) == 41

    def test_apache(self, full_reg: RuleRegistry) -> None:
        rules = full_reg.list_rules(category="local", server_type="apache")
        assert len(rules) == 27

    def test_lighttpd(self, full_reg: RuleRegistry) -> None:
        rules = full_reg.list_rules(category="local", server_type="lighttpd")
        assert len(rules) == 15

    def test_iis(self, full_reg: RuleRegistry) -> None:
        rules = full_reg.list_rules(category="local", server_type="iis")
        assert len(rules) == 20

    def test_external(self, full_reg: RuleRegistry) -> None:
        rules = full_reg.list_rules(category="external")
        assert len(rules) == 69


# ---------------------------------------------------------------------------
# No duplicate rule IDs
# ---------------------------------------------------------------------------

class TestNoDuplicates:
    def test_no_duplicate_ids_in_catalog(self, full_reg: RuleRegistry) -> None:
        # _catalog is a dict so duplicates would silently overwrite.
        # Check that the count matches expectations (covered above),
        # and also verify all IDs are unique across the meta lists.
        import webconf_audit.external.rules._runner

        all_ids: list[str] = []
        for entry in full_reg._executable.values():
            all_ids.append(entry.meta.rule_id)
        for meta in webconf_audit.external.rules._runner._EXTERNAL_RULE_METAS:
            all_ids.append(meta.rule_id)

        assert len(all_ids) == len(set(all_ids)), (
            f"Duplicate rule IDs found: "
            f"{[x for x in all_ids if all_ids.count(x) > 1]}"
        )


# ---------------------------------------------------------------------------
# Ordering invariants
# ---------------------------------------------------------------------------

class TestOrdering:
    def test_universal_order_range(self, full_reg: RuleRegistry) -> None:
        for m in full_reg.list_rules(category="universal"):
            assert 100 <= m.order <= 199, f"{m.rule_id} order={m.order}"

    def test_nginx_order_range(self, full_reg: RuleRegistry) -> None:
        for m in full_reg.list_rules(category="local", server_type="nginx"):
            assert 200 <= m.order <= 299, f"{m.rule_id} order={m.order}"

    def test_apache_order_range(self, full_reg: RuleRegistry) -> None:
        for m in full_reg.list_rules(category="local", server_type="apache"):
            assert 300 <= m.order <= 399, f"{m.rule_id} order={m.order}"

    def test_lighttpd_order_range(self, full_reg: RuleRegistry) -> None:
        for m in full_reg.list_rules(category="local", server_type="lighttpd"):
            assert 400 <= m.order <= 499, f"{m.rule_id} order={m.order}"

    def test_iis_order_range(self, full_reg: RuleRegistry) -> None:
        for m in full_reg.list_rules(category="local", server_type="iis"):
            assert 500 <= m.order <= 599, f"{m.rule_id} order={m.order}"

    def test_external_order_range(self, full_reg: RuleRegistry) -> None:
        for m in full_reg.list_rules(category="external"):
            assert 600 <= m.order <= 799, f"{m.rule_id} order={m.order}"

    def test_list_rules_sorted(self, full_reg: RuleRegistry) -> None:
        all_rules = full_reg.list_rules()
        keys = [(m.order, m.rule_id) for m in all_rules]
        assert keys == sorted(keys)


# ---------------------------------------------------------------------------
# Executable store only has callable entries
# ---------------------------------------------------------------------------

class TestExecutableCallable:
    def test_all_executable_have_fn(self, full_reg: RuleRegistry) -> None:
        for entry in full_reg._executable.values():
            assert callable(entry.fn), f"{entry.meta.rule_id} has non-callable fn"


# ---------------------------------------------------------------------------
# Prefix conventions
# ---------------------------------------------------------------------------

class TestPrefixConventions:
    def test_nginx_prefix(self, full_reg: RuleRegistry) -> None:
        for m in full_reg.list_rules(category="local", server_type="nginx"):
            assert m.rule_id.startswith("nginx."), m.rule_id

    def test_apache_prefix(self, full_reg: RuleRegistry) -> None:
        for m in full_reg.list_rules(category="local", server_type="apache"):
            assert m.rule_id.startswith("apache."), m.rule_id

    def test_lighttpd_prefix(self, full_reg: RuleRegistry) -> None:
        for m in full_reg.list_rules(category="local", server_type="lighttpd"):
            assert m.rule_id.startswith("lighttpd."), m.rule_id

    def test_iis_prefix(self, full_reg: RuleRegistry) -> None:
        for m in full_reg.list_rules(category="local", server_type="iis"):
            assert m.rule_id.startswith("iis."), m.rule_id

    def test_external_prefix(self, full_reg: RuleRegistry) -> None:
        for m in full_reg.list_rules(category="external"):
            assert m.rule_id.startswith("external."), m.rule_id

    def test_universal_prefix(self, full_reg: RuleRegistry) -> None:
        for m in full_reg.list_rules(category="universal"):
            assert m.rule_id.startswith("universal."), m.rule_id
