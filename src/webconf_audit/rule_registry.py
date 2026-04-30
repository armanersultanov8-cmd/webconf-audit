"""Centralized rule registry for webconf-audit.

Two separate stores:

* **catalog** -- metadata for every known rule ID (used by ``list-rules``
  and introspection).  Populated by both ``register()`` and
  ``register_meta()``.
* **executable** -- rules that have a callable attached (used by runners).
  Populated only by ``register()``.

This separation lets external rules publish their metadata for
``list-rules`` without requiring full modularization of their
composite runner.
"""

from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass
from typing import Any, Callable, Literal

from webconf_audit.models import Severity

# ---------------------------------------------------------------------------
# Public type aliases
# ---------------------------------------------------------------------------

RuleCategory = Literal["local", "external", "universal"]

InputKind = Literal[
    "ast",         # server-specific AST (Nginx / Apache / Lighttpd)
    "effective",   # AST + effective config (Lighttpd effective-aware rules)
    "htaccess",    # Apache htaccess file list
    "mixed",       # Apache AST + htaccess + config_dir
    "normalized",  # NormalizedConfig (universal rules)
    "probe",       # ProbeAttempt list (external rules)
]

# ---------------------------------------------------------------------------
# RuleMeta -- immutable metadata for a single rule
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RuleMeta:
    """Metadata describing a single rule.

    Every rule in the catalog has exactly one ``RuleMeta``.  Fields that
    are only meaningful for certain categories (e.g. *condition* for
    external conditional rules) default to ``None``.
    """

    rule_id: str
    title: str
    severity: Severity
    description: str
    recommendation: str
    category: RuleCategory
    server_type: str | None = None
    input_kind: InputKind = "ast"
    tags: tuple[str, ...] = ()
    condition: str | None = None
    order: int = 1000


# ---------------------------------------------------------------------------
# RuleEntry -- catalog entry with an attached callable
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RuleEntry:
    """An executable rule: metadata + callable."""

    meta: RuleMeta
    fn: Callable[..., Any]


# ---------------------------------------------------------------------------
# RuleRegistry
# ---------------------------------------------------------------------------


class RuleRegistry:
    """Central rule registry with separate catalog and executable stores."""

    def __init__(self) -> None:
        self._catalog: dict[str, RuleMeta] = {}
        self._executable: dict[str, RuleEntry] = {}
        self._loaded_packages: set[str] = set()

    # -- mutation -----------------------------------------------------------

    def register(self, meta: RuleMeta, fn: Callable[..., Any]) -> None:
        """Register an executable rule (adds to both catalog and executable)."""
        if meta.rule_id in self._catalog:
            raise ValueError(f"Duplicate rule_id: {meta.rule_id!r}")
        self._catalog[meta.rule_id] = meta
        self._executable[meta.rule_id] = RuleEntry(meta=meta, fn=fn)

    def register_meta(self, meta: RuleMeta) -> None:
        """Register metadata only (no callable).

        Used for external grouped rules that have metadata but are
        executed through a composite runner.
        """
        if meta.rule_id in self._catalog:
            raise ValueError(f"Duplicate rule_id: {meta.rule_id!r}")
        self._catalog[meta.rule_id] = meta

    # -- queries (catalog) --------------------------------------------------

    def get_meta(self, rule_id: str) -> RuleMeta | None:
        """Look up metadata by rule_id (catalog)."""
        return self._catalog.get(rule_id)

    def list_rules(
        self,
        *,
        category: RuleCategory | None = None,
        server_type: str | None = None,
        severity: Severity | None = None,
        tag: str | None = None,
    ) -> list[RuleMeta]:
        """Return catalog entries matching the given filters, sorted by order then rule_id."""
        result: list[RuleMeta] = []
        for meta in self._catalog.values():
            if category is not None and meta.category != category:
                continue
            if server_type is not None and meta.server_type != server_type:
                continue
            if severity is not None and meta.severity != severity:
                continue
            if tag is not None and tag not in meta.tags:
                continue
            result.append(meta)
        result.sort(key=lambda m: (m.order, m.rule_id))
        return result

    # -- queries (executable) -----------------------------------------------

    def get(self, rule_id: str) -> RuleEntry | None:
        """Look up an executable rule by rule_id."""
        return self._executable.get(rule_id)

    def rules_for(
        self,
        category: RuleCategory,
        server_type: str | None = None,
    ) -> list[RuleEntry]:
        """Return executable rules for the given category/server, sorted by order then rule_id."""
        result: list[RuleEntry] = []
        for entry in self._executable.values():
            if entry.meta.category != category:
                continue
            if server_type is not None and entry.meta.server_type != server_type:
                continue
            result.append(entry)
        result.sort(key=lambda e: (e.meta.order, e.meta.rule_id))
        return result

    # -- auto-discovery -----------------------------------------------------

    def ensure_loaded(self, package_name: str) -> None:
        """Import all public submodules of *package_name* and register decorated rules on *self*.

        Unlike the ``@rule`` decorator (which always targets the global
        singleton), this method scans already-imported modules for
        functions carrying a ``_rule_meta`` attribute and registers them
        on *self*.  This means:

        * A fresh ``RuleRegistry()`` instance can use ``ensure_loaded``
          to populate itself — the decorated functions are discovered
          via their ``_rule_meta`` attribute, not via import-time side
          effects on the global singleton.
        * After ``clear()``, calling ``ensure_loaded`` again re-registers
          rules from cached modules without requiring Python to re-import
          (and therefore re-execute decorators).

        Skips modules whose name starts with ``_`` (private / utility).
        Repeated calls for the same package are no-ops.
        """
        if package_name in self._loaded_packages:
            return
        pkg = importlib.import_module(package_name)
        pkg_path = getattr(pkg, "__path__", None)
        if pkg_path is None:
            self._mark_loaded(package_name)
            return
        self._register_decorated_rules(
            self._import_public_modules(package_name, pkg_path)
        )
        self._mark_loaded(package_name)

    def _import_public_modules(self, package_name: str, pkg_path: object) -> list[object]:
        modules: list[object] = []
        for _importer, name, _ispkg in pkgutil.iter_modules(pkg_path):
            if name.startswith("_"):
                continue
            modules.append(importlib.import_module(f"{package_name}.{name}"))
        return modules

    def _register_decorated_rules(self, modules: list[object]) -> None:
        for module in modules:
            for obj in self._decorated_rule_functions(module):
                self.register(obj._rule_meta, obj)

    def _decorated_rule_functions(self, module: object) -> list[Callable[..., Any]]:
        functions: list[Callable[..., Any]] = []
        for attr_name in dir(module):
            obj = getattr(module, attr_name, None)
            if self._is_registerable_rule(obj):
                functions.append(obj)
        return functions

    def _is_registerable_rule(self, obj: object) -> bool:
        return (
            callable(obj)
            and hasattr(obj, "_rule_meta")
            and isinstance(obj._rule_meta, RuleMeta)
            and obj._rule_meta.rule_id not in self._catalog
        )

    def _mark_loaded(self, package_name: str) -> None:
        self._loaded_packages.add(package_name)

    # -- test support -------------------------------------------------------

    def clear(self) -> None:
        """Remove all registered rules.  Intended for test isolation only."""
        self._catalog.clear()
        self._executable.clear()
        self._loaded_packages.clear()

    # -- introspection ------------------------------------------------------

    @property
    def catalog_size(self) -> int:
        return len(self._catalog)

    @property
    def executable_size(self) -> int:
        return len(self._executable)

    def __repr__(self) -> str:
        return (
            f"RuleRegistry(catalog={self.catalog_size}, "
            f"executable={self.executable_size})"
        )


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

registry = RuleRegistry()

# ---------------------------------------------------------------------------
# @rule decorator
# ---------------------------------------------------------------------------


def rule(
    rule_id: str,
    *,
    title: str,
    severity: Severity,
    description: str,
    recommendation: str,
    category: RuleCategory,
    server_type: str | None = None,
    input_kind: InputKind = "ast",
    tags: tuple[str, ...] = (),
    condition: str | None = None,
    order: int = 1000,
) -> Callable:
    """Decorator that attaches :class:`RuleMeta` to a function and registers
    it in the global :data:`registry`.

    The metadata is stored as ``fn._rule_meta`` so that
    :meth:`RuleRegistry.ensure_loaded` can discover it on *any* registry
    instance (not only the global singleton) and re-register it after
    ``clear()``.

    Usage::

        @rule(
            rule_id="nginx.server_tokens_on",
            title="Server tokens enabled",
            severity="low",
            description="...",
            recommendation="...",
            category="local",
            server_type="nginx",
        )
        def find_server_tokens_on(config_ast):
            ...
    """

    def decorator(fn: Callable) -> Callable:
        meta = RuleMeta(
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
        fn._rule_meta = meta  # type: ignore[attr-defined]
        if registry.get_meta(meta.rule_id) is None:
            registry.register(meta, fn)
        return fn

    return decorator


__all__ = [
    "InputKind",
    "RuleCategory",
    "RuleEntry",
    "RuleMeta",
    "RuleRegistry",
    "registry",
    "rule",
]
