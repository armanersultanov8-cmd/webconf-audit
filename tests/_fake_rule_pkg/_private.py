"""Private module — should be skipped by ensure_loaded."""

from webconf_audit.rule_registry import rule


@rule(
    rule_id="fake.private_should_not_load",
    title="Private",
    severity="info",
    description="Should never be discovered",
    recommendation="No action",
    category="local",
)
def _find_private(_config_ast) -> list[object]:
    return []
