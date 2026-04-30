"""Fake rule module for testing ensure_loaded discovery."""

from webconf_audit.rule_registry import rule


@rule(
    rule_id="fake.alpha_one",
    title="Alpha one",
    severity="low",
    description="First fake rule",
    recommendation="No action",
    category="local",
    server_type="nginx",
    order=10,
)
def _find_alpha_one(_config_ast: object) -> list[object]:
    return []


@rule(
    rule_id="fake.alpha_two",
    title="Alpha two",
    severity="medium",
    description="Second fake rule",
    recommendation="No action",
    category="local",
    server_type="nginx",
    tags=("tls",),
    order=20,
)
def _find_alpha_two(_config_ast: object) -> list[object]:
    return []
