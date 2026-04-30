from enum import Enum
from typing import cast

import typer

from webconf_audit.external import analyze_external_target
from webconf_audit.local.apache import analyze_apache_config
from webconf_audit.local.iis import analyze_iis_config
from webconf_audit.local.lighttpd import analyze_lighttpd_config
from webconf_audit.local.nginx import analyze_nginx_config
from webconf_audit.models import AnalysisResult, Severity
from webconf_audit.report import JsonFormatter, ReportData, TextFormatter
from webconf_audit.rule_registry import RuleCategory

app = typer.Typer(help="Web server configuration security audit tool")


class OutputFormat(str, Enum):
    text = "text"
    json = "json"


def _output_result(result: AnalysisResult, fmt: OutputFormat = OutputFormat.text) -> None:
    report = ReportData(results=[result])
    formatter = TextFormatter() if fmt == OutputFormat.text else JsonFormatter()
    typer.echo(formatter.format(report))


@app.command("analyze-nginx")
def analyze_nginx(
    config_path: str = typer.Argument(..., help="Path to nginx config file"),
    output_format: OutputFormat = typer.Option(
        OutputFormat.text, "--format", "-f", help="Output format: text, json.",
    ),
) -> None:
    result = analyze_nginx_config(config_path)
    _output_result(result, output_format)


@app.command("analyze-apache")
def analyze_apache(
    config_path: str = typer.Argument(..., help="Path to Apache config file"),
    output_format: OutputFormat = typer.Option(
        OutputFormat.text, "--format", "-f", help="Output format: text, json.",
    ),
) -> None:
    result = analyze_apache_config(config_path)
    _output_result(result, output_format)


@app.command("analyze-lighttpd")
def analyze_lighttpd(
    config_path: str = typer.Argument(..., help="Path to Lighttpd config file"),
    execute_shell: bool = typer.Option(
        False,
        "--execute-shell/--no-execute-shell",
        help="Execute include_shell directives during analysis.",
    ),
    host: str | None = typer.Option(
        None,
        "--host",
        help="Evaluate conditional blocks for a specific host (targeted analysis).",
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.text, "--format", "-f", help="Output format: text, json.",
    ),
) -> None:
    result = analyze_lighttpd_config(
        config_path, execute_shell=execute_shell, host=host,
    )
    _output_result(result, output_format)


@app.command("analyze-iis")
def analyze_iis(
    config_path: str = typer.Argument(
        ...,
        help="Path to IIS config file (web.config or applicationHost.config)",
    ),
    machine_config: str | None = typer.Option(
        None,
        "--machine-config",
        help="Optional path to machine.config for IIS inheritance analysis.",
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.text, "--format", "-f", help="Output format: text, json.",
    ),
) -> None:
    if machine_config is None:
        result = analyze_iis_config(config_path)
    else:
        result = analyze_iis_config(config_path, machine_config_path=machine_config)
    _output_result(result, output_format)


def _parse_ports(raw: str) -> tuple[int, ...]:
    """Parse a comma-separated port string with validation.

    Raises :class:`typer.BadParameter` on invalid tokens, out-of-range
    values (must be 1-65535), or an empty result.
    """
    seen: set[int] = set()
    result: list[int] = []
    for idx, token in enumerate(raw.split(",")):
        token = token.strip()
        if not token:
            raise typer.BadParameter(
                f"empty port value at position {idx + 1} in: {raw!r}"
            )
        try:
            port = int(token)
        except ValueError:
            raise typer.BadParameter(f"invalid port value: {token!r}") from None
        if port < 1 or port > 65535:
            raise typer.BadParameter(
                f"port out of range (1-65535): {port}"
            )
        if port not in seen:
            seen.add(port)
            result.append(port)
    if not result:
        raise typer.BadParameter("--ports requires at least one valid port")
    return tuple(result)


@app.command("analyze-external")
def analyze_external(
    target: str = typer.Argument(..., help="URL, host, or host:port to probe"),
    scan_ports: bool = typer.Option(
        True,
        "--scan-ports/--no-scan-ports",
        help="Enable or disable port discovery for bare-host targets.",
    ),
    ports: str | None = typer.Option(
        None,
        "--ports",
        help="Comma-separated list of ports to scan (e.g. '80,443,8080').",
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.text, "--format", "-f", help="Output format: text, json.",
    ),
) -> None:
    parsed_ports: tuple[int, ...] | None = None
    if ports is not None:
        parsed_ports = _parse_ports(ports)
    result = analyze_external_target(target, scan_ports=scan_ports, ports=parsed_ports)
    _output_result(result, output_format)


@app.command("list-rules")
def list_rules(
    category: str | None = typer.Option(
        None,
        "--category",
        "-c",
        help="Filter by category (local, external, universal).",
    ),
    server_type: str | None = typer.Option(
        None,
        "--server-type",
        "-s",
        help="Filter by server type (nginx, apache, lighttpd, iis).",
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        help="Filter by severity (critical, high, medium, low, info).",
    ),
    tag: str | None = typer.Option(None, "--tag", "-t", help="Filter by tag (e.g. tls, headers)."),
) -> None:
    """List all registered audit rules with optional filtering."""
    from webconf_audit.rule_registry import registry

    _ensure_all_rules_loaded()
    parsed_category = _parse_rule_category(category)
    parsed_server_type = _parse_rule_server_type(server_type)
    parsed_severity = _parse_rule_severity(severity)
    parsed_tag = _parse_rule_tag(tag)

    rules = registry.list_rules(
        category=parsed_category,
        server_type=parsed_server_type,
        severity=parsed_severity,
        tag=parsed_tag,
    )

    if not rules:
        typer.echo("No rules match the given filters.")
        raise typer.Exit()

    typer.echo(f"{'RULE ID':<55} {'SEV':<7} {'CAT':<10} {'SERVER':<10} ORDER")
    typer.echo("-" * 90)
    for m in rules:
        server = m.server_type or ""
        typer.echo(f"{m.rule_id:<55} {m.severity:<7} {m.category:<10} {server:<10} {m.order}")
    typer.echo(f"\nTotal: {len(rules)} rules")


def _parse_rule_category(value: str | None) -> RuleCategory | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    valid = {"local", "external", "universal"}
    if normalized not in valid:
        raise typer.BadParameter(
            f"invalid category {value!r}; expected one of: {', '.join(sorted(valid))}"
        )
    return cast(RuleCategory, normalized)


def _parse_rule_severity(value: str | None) -> Severity | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    valid = {"critical", "high", "medium", "low", "info"}
    if normalized not in valid:
        raise typer.BadParameter(
            f"invalid severity {value!r}; expected one of: {', '.join(sorted(valid))}"
        )
    return cast(Severity, normalized)


def _parse_rule_server_type(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    valid = _available_rule_server_types()
    if normalized not in valid:
        raise typer.BadParameter(
            f"invalid server type {value!r}; expected one of: {', '.join(sorted(valid))}"
        )
    return normalized


def _parse_rule_tag(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    valid = _available_rule_tags()
    if normalized not in valid:
        raise typer.BadParameter(
            f"invalid tag {value!r}; expected one of: {', '.join(sorted(valid))}"
        )
    return normalized


def _available_rule_server_types() -> set[str]:
    from webconf_audit.rule_registry import registry

    return {
        meta.server_type
        for meta in registry.list_rules()
        if meta.server_type is not None
    }


def _available_rule_tags() -> set[str]:
    from webconf_audit.rule_registry import registry

    return {
        tag
        for meta in registry.list_rules()
        for tag in meta.tags
    }


def _ensure_all_rules_loaded() -> None:
    """Load all rule packages + meta-only registrations into the registry."""
    from webconf_audit.rule_registry import registry

    registry.ensure_loaded("webconf_audit.local.rules.universal")
    registry.ensure_loaded("webconf_audit.local.nginx.rules")
    registry.ensure_loaded("webconf_audit.local.apache.rules")
    registry.ensure_loaded("webconf_audit.local.lighttpd.rules")
    registry.ensure_loaded("webconf_audit.local.iis.rules")
    # External meta-only rules register on import.
    import webconf_audit.external.rules._runner  # noqa: F401


if __name__ == "__main__":
    app()
