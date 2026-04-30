"""Fake rule module for testing ensure_loaded discovery."""

from webconf_audit.rule_registry import rule


@rule(
    rule_id="fake.beta_one",
    title="Beta one",
    severity="high",
    description="Third fake rule",
    recommendation="No action",
    category="universal",
    input_kind="normalized",
    order=5,
)
def _check_beta_one(_config: object) -> list[object]:
    return []
