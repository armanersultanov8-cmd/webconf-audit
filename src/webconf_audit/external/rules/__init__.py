"""Structured external rules package."""

from webconf_audit.external.rules._helpers import hostname_matches_san
from webconf_audit.external.rules._runner import run_external_rules

__all__ = ["hostname_matches_san", "run_external_rules"]
