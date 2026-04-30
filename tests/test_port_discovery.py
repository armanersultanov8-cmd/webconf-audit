"""Tests for webconf_audit.external.recon.port_discovery and related integration."""

from __future__ import annotations

from typer.testing import CliRunner

from webconf_audit.cli import app
from webconf_audit.external.recon.port_discovery import (
    DEFAULT_SCAN_PORTS,
    DiscoveredPort,
    _check_tcp_port,
    discover_probe_targets,
    probe_targets_for_port,
    scan_ports,
)
from webconf_audit.external.recon import ProbeTarget, _is_bare_host, analyze_external_target

runner = CliRunner()


def _no_sensitive_path_probes(
    *_args: object,
    **_kwargs: object,
) -> list[object]:
    return []


# ---------------------------------------------------------------------------
# probe_targets_for_port
# ---------------------------------------------------------------------------


def test_probe_targets_for_http_preferred_port() -> None:
    targets = probe_targets_for_port("h", 8080)
    assert len(targets) == 2
    assert targets[0].scheme == "http"
    assert targets[1].scheme == "https"
    assert all(t.port == 8080 and t.host == "h" for t in targets)


def test_probe_targets_for_https_preferred_port() -> None:
    targets = probe_targets_for_port("h", 443)
    assert targets[0].scheme == "https"
    assert targets[1].scheme == "http"


def test_probe_targets_for_port_8443() -> None:
    targets = probe_targets_for_port("h", 8443)
    assert targets[0].scheme == "https"


def test_probe_targets_for_port_9443() -> None:
    targets = probe_targets_for_port("h", 9443)
    assert targets[0].scheme == "https"


def test_probe_targets_custom_path() -> None:
    targets = probe_targets_for_port("h", 80, path="/app")
    assert all(t.path == "/app" for t in targets)


# ---------------------------------------------------------------------------
# _check_tcp_port
# ---------------------------------------------------------------------------


def test_check_tcp_port_open(monkeypatch) -> None:
    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

    monkeypatch.setattr(
        "webconf_audit.external.recon.port_discovery.socket.create_connection",
        lambda addr, timeout: FakeConn(),
    )
    result = _check_tcp_port("host", 80)
    assert result == DiscoveredPort(host="host", port=80, tcp_open=True)


def test_check_tcp_port_closed(monkeypatch) -> None:
    monkeypatch.setattr(
        "webconf_audit.external.recon.port_discovery.socket.create_connection",
        lambda addr, timeout: (_ for _ in ()).throw(OSError("refused")),
    )
    result = _check_tcp_port("host", 80)
    assert result.tcp_open is False
    assert result.error_message is not None


def test_check_tcp_port_timeout(monkeypatch) -> None:
    monkeypatch.setattr(
        "webconf_audit.external.recon.port_discovery.socket.create_connection",
        lambda addr, timeout: (_ for _ in ()).throw(OSError("timed out")),
    )
    result = _check_tcp_port("host", 9999)
    assert result.tcp_open is False
    assert "timed out" in (result.error_message or "")


def test_check_tcp_port_rejects_invalid_range_without_socket(monkeypatch) -> None:
    called = False

    def fake_create_connection(addr, timeout):
        nonlocal called
        called = True
        raise AssertionError("socket.create_connection should not be called")

    monkeypatch.setattr(
        "webconf_audit.external.recon.port_discovery.socket.create_connection",
        fake_create_connection,
    )

    result = _check_tcp_port("host", 70000)

    assert called is False
    assert result.tcp_open is False
    assert "invalid port" in (result.error_message or "")


# ---------------------------------------------------------------------------
# scan_ports
# ---------------------------------------------------------------------------


def test_scan_ports_empty_tuple() -> None:
    assert scan_ports("host", ports=()) == []


def test_scan_ports_returns_results_in_port_order(monkeypatch) -> None:
    monkeypatch.setattr(
        "webconf_audit.external.recon.port_discovery._check_tcp_port",
        lambda host, port, timeout: DiscoveredPort(
            host=host, port=port, tcp_open=(port != 81),
        ),
    )
    results = scan_ports("h", ports=(80, 81, 8080))
    assert [r.port for r in results] == [80, 81, 8080]
    assert results[0].tcp_open is True
    assert results[1].tcp_open is False
    assert results[2].tcp_open is True


def test_scan_ports_all_closed(monkeypatch) -> None:
    monkeypatch.setattr(
        "webconf_audit.external.recon.port_discovery._check_tcp_port",
        lambda host, port, timeout: DiscoveredPort(
            host=host, port=port, tcp_open=False, error_message="refused",
        ),
    )
    results = scan_ports("h", ports=(80, 443))
    assert all(not r.tcp_open for r in results)
    assert len(results) == 2


def test_scan_ports_single_port(monkeypatch) -> None:
    monkeypatch.setattr(
        "webconf_audit.external.recon.port_discovery._check_tcp_port",
        lambda host, port, timeout: DiscoveredPort(
            host=host, port=port, tcp_open=True,
        ),
    )
    results = scan_ports("h", ports=(3000,))
    assert len(results) == 1
    assert results[0].port == 3000
    assert results[0].tcp_open is True


# ---------------------------------------------------------------------------
# discover_probe_targets (dual-scheme, no TLS guessing)
# ---------------------------------------------------------------------------


def test_discover_no_open_ports(monkeypatch) -> None:
    monkeypatch.setattr(
        "webconf_audit.external.recon.port_discovery._check_tcp_port",
        lambda host, port, timeout: DiscoveredPort(
            host=host, port=port, tcp_open=False, error_message="refused",
        ),
    )
    targets, scan_results = discover_probe_targets("h", ports=(80, 443))
    assert targets == []
    assert len(scan_results) == 2
    assert all(not sr.tcp_open for sr in scan_results)


def test_discover_open_port_generates_both_schemes(monkeypatch) -> None:
    """Each open port produces two ProbeTargets (both schemes)."""
    monkeypatch.setattr(
        "webconf_audit.external.recon.port_discovery._check_tcp_port",
        lambda host, port, timeout: DiscoveredPort(
            host=host, port=port, tcp_open=True,
        ),
    )
    targets, _ = discover_probe_targets("h", ports=(8080,))
    assert len(targets) == 2
    schemes = [t.scheme for t in targets]
    assert "http" in schemes
    assert "https" in schemes


def test_discover_https_preferred_port_order(monkeypatch) -> None:
    """Port 443 should list https first."""
    monkeypatch.setattr(
        "webconf_audit.external.recon.port_discovery._check_tcp_port",
        lambda host, port, timeout: DiscoveredPort(
            host=host, port=port, tcp_open=True,
        ),
    )
    targets, _ = discover_probe_targets("h", ports=(443,))
    assert targets[0].scheme == "https"
    assert targets[1].scheme == "http"


def test_discover_multiple_open_ports(monkeypatch) -> None:
    monkeypatch.setattr(
        "webconf_audit.external.recon.port_discovery._check_tcp_port",
        lambda host, port, timeout: DiscoveredPort(
            host=host, port=port, tcp_open=True,
        ),
    )
    targets, scan_results = discover_probe_targets("h", ports=(80, 443, 8080))
    # 3 ports × 2 schemes = 6 targets
    assert len(targets) == 6
    assert len(scan_results) == 3


def test_discover_mixed_open_closed(monkeypatch) -> None:
    monkeypatch.setattr(
        "webconf_audit.external.recon.port_discovery._check_tcp_port",
        lambda host, port, timeout: DiscoveredPort(
            host=host, port=port, tcp_open=(port != 81),
        ),
    )
    targets, scan_results = discover_probe_targets("h", ports=(80, 81, 8080))
    # 2 open ports × 2 schemes = 4 targets
    assert len(targets) == 4
    assert {t.port for t in targets} == {80, 8080}
    assert len(scan_results) == 3


def test_discover_uses_custom_path(monkeypatch) -> None:
    monkeypatch.setattr(
        "webconf_audit.external.recon.port_discovery._check_tcp_port",
        lambda host, port, timeout: DiscoveredPort(
            host=host, port=port, tcp_open=True,
        ),
    )
    targets, _ = discover_probe_targets("h", ports=(80,), path="/app")
    assert all(t.path == "/app" for t in targets)


# ---------------------------------------------------------------------------
# _is_bare_host (from recon.py)
# ---------------------------------------------------------------------------


def test_is_bare_host_plain_hostname() -> None:
    assert _is_bare_host("example.com") is True


def test_is_bare_host_with_spaces() -> None:
    assert _is_bare_host("  example.com  ") is True


def test_is_bare_host_with_scheme() -> None:
    assert _is_bare_host("https://example.com") is False


def test_is_bare_host_with_port() -> None:
    assert _is_bare_host("example.com:8080") is False


def test_is_bare_host_empty() -> None:
    assert _is_bare_host("") is False


def test_is_bare_host_ip() -> None:
    assert _is_bare_host("192.168.1.1") is True


def test_is_bare_host_ip_with_port() -> None:
    assert _is_bare_host("192.168.1.1:80") is False


def test_is_bare_host_with_path() -> None:
    assert _is_bare_host("example.com/path") is False


def test_is_bare_host_with_query() -> None:
    assert _is_bare_host("example.com?x=1") is False


def test_is_bare_host_with_path_and_query() -> None:
    assert _is_bare_host("example.com/path?x=1") is False


# ---------------------------------------------------------------------------
# Integration: analyze_external_target with scan_ports=True
# ---------------------------------------------------------------------------


def _make_fake_probe(monkeypatch):
    """Patch _probe_target and _probe_sensitive_paths with minimal fakes."""
    from webconf_audit.external.recon import ProbeAttempt

    def fake_probe(pt):
        return ProbeAttempt(
            target=pt, tcp_open=True, status_code=200, reason_phrase="OK",
            server_header="nginx/1.25.0",
        )

    monkeypatch.setattr("webconf_audit.external.recon._probe_target", fake_probe)
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_sensitive_paths",
        _no_sensitive_path_probes,
    )


def test_analyze_external_with_scan_ports_discovers_services(monkeypatch) -> None:
    """Port discovery finds port 8080 open, probing succeeds."""
    monkeypatch.setattr(
        "webconf_audit.external.recon.port_discovery._check_tcp_port",
        lambda host, port, timeout: DiscoveredPort(
            host=host, port=port, tcp_open=(port == 8080),
        ),
    )
    _make_fake_probe(monkeypatch)

    result = analyze_external_target(
        "example.com", scan_ports=True, ports=(80, 8080, 443),
    )

    assert result.mode == "external"
    assert result.server_type == "nginx"
    assert any("port_scan" in d for d in result.diagnostics)
    assert "port_scan_open: example.com:8080" in result.diagnostics
    assert "port_scan_closed_or_unreachable: example.com:80" in result.diagnostics
    assert "port_scan_closed_or_unreachable: example.com:443" in result.diagnostics
    assert "port_scan" in result.metadata
    scan_meta = result.metadata["port_scan"]
    assert len(scan_meta) == 3
    open_ports = [s for s in scan_meta if s["tcp_open"]]
    assert len(open_ports) == 1
    assert open_ports[0]["port"] == 8080


def test_analyze_external_with_scan_ports_no_open_ports(monkeypatch) -> None:
    """Port discovery finds nothing open -> AnalysisIssue."""
    monkeypatch.setattr(
        "webconf_audit.external.recon.port_discovery._check_tcp_port",
        lambda host, port, timeout: DiscoveredPort(
            host=host, port=port, tcp_open=False, error_message="refused",
        ),
    )

    result = analyze_external_target(
        "example.com", scan_ports=True, ports=(80, 443),
    )

    assert len(result.issues) == 1
    assert result.issues[0].code == "external_no_open_ports"
    assert "port_scan_closed_or_unreachable: example.com:80" in result.diagnostics
    assert "port_scan_closed_or_unreachable: example.com:443" in result.diagnostics
    assert "port_scan_error: example.com:80: refused" in result.diagnostics
    assert "port_scan_error: example.com:443: refused" in result.diagnostics
    assert "port_scan" in result.metadata


def test_analyze_external_scan_ports_ignored_for_url(monkeypatch) -> None:
    """scan_ports=True is ignored when target is a full URL."""
    _make_fake_probe(monkeypatch)

    result = analyze_external_target("https://example.com", scan_ports=True)

    assert result.mode == "external"
    assert "port_scan" not in result.metadata


def test_analyze_external_scan_ports_ignored_for_host_port(monkeypatch) -> None:
    """scan_ports=True is ignored when target has an explicit port."""
    from webconf_audit.external.recon import ProbeAttempt

    targets_seen: list[ProbeTarget] = []

    def fake_probe(pt):
        targets_seen.append(pt)
        return ProbeAttempt(
            target=pt, tcp_open=True, status_code=200, reason_phrase="OK",
        )

    monkeypatch.setattr("webconf_audit.external.recon._probe_target", fake_probe)
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_sensitive_paths",
        _no_sensitive_path_probes,
    )

    result = analyze_external_target("example.com:8080", scan_ports=True)

    assert "port_scan" not in result.metadata
    assert len(targets_seen) == 2
    assert all(t.port == 8080 for t in targets_seen)


def test_analyze_external_scan_ports_ignored_for_host_with_path(monkeypatch) -> None:
    """scan_ports=True is ignored when target has a path (falls back to _build_probe_targets)."""
    from webconf_audit.external.recon import ProbeAttempt

    targets_seen: list[ProbeTarget] = []

    def fake_probe(pt):
        targets_seen.append(pt)
        return ProbeAttempt(
            target=pt, tcp_open=True, status_code=200, reason_phrase="OK",
        )

    monkeypatch.setattr("webconf_audit.external.recon._probe_target", fake_probe)
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_sensitive_paths",
        _no_sensitive_path_probes,
    )

    result = analyze_external_target("example.com/path", scan_ports=True)

    assert "port_scan" not in result.metadata
    # Falls back to _build_probe_targets which probes 80+443
    assert any(t.path == "/path" for t in targets_seen)


def test_analyze_external_scan_ports_ignored_for_host_with_query(monkeypatch) -> None:
    """scan_ports=True is ignored when target has a query string."""
    from webconf_audit.external.recon import ProbeAttempt

    targets_seen: list[ProbeTarget] = []

    def fake_probe(pt):
        targets_seen.append(pt)
        return ProbeAttempt(
            target=pt, tcp_open=True, status_code=200, reason_phrase="OK",
        )

    monkeypatch.setattr("webconf_audit.external.recon._probe_target", fake_probe)
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_sensitive_paths",
        _no_sensitive_path_probes,
    )

    result = analyze_external_target("example.com?x=1", scan_ports=True)

    assert "port_scan" not in result.metadata


def test_no_scan_ports_preserves_old_bare_host_flow(monkeypatch) -> None:
    """scan_ports=False on bare host uses _build_probe_targets (80+443)."""
    from webconf_audit.external.recon import ProbeAttempt

    targets_seen: list[ProbeTarget] = []

    def fake_probe(pt):
        targets_seen.append(pt)
        return ProbeAttempt(
            target=pt, tcp_open=True, status_code=200, reason_phrase="OK",
        )

    monkeypatch.setattr("webconf_audit.external.recon._probe_target", fake_probe)
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_sensitive_paths",
        _no_sensitive_path_probes,
    )

    result = analyze_external_target("example.com", scan_ports=False)

    assert "port_scan" not in result.metadata
    assert len(targets_seen) == 2
    ports = {t.port for t in targets_seen}
    assert ports == {80, 443}


# ---------------------------------------------------------------------------
# CLI: --ports validation
# ---------------------------------------------------------------------------


def test_cli_ports_rejects_non_numeric(monkeypatch) -> None:
    monkeypatch.setattr(
        "webconf_audit.cli.analyze_external_target",
        lambda target, **kw: None,
    )
    result = runner.invoke(app, ["analyze-external", "h", "--ports", "abc"])
    assert result.exit_code != 0


def test_cli_ports_rejects_empty_string(monkeypatch) -> None:
    monkeypatch.setattr(
        "webconf_audit.cli.analyze_external_target",
        lambda target, **kw: None,
    )
    result = runner.invoke(app, ["analyze-external", "h", "--ports", ",,,"])
    assert result.exit_code != 0


def test_cli_ports_rejects_empty_interior_token(monkeypatch) -> None:
    monkeypatch.setattr(
        "webconf_audit.cli.analyze_external_target",
        lambda target, **kw: None,
    )
    result = runner.invoke(app, ["analyze-external", "h", "--ports", "80,,443"])
    assert result.exit_code != 0


def test_cli_ports_rejects_trailing_comma(monkeypatch) -> None:
    monkeypatch.setattr(
        "webconf_audit.cli.analyze_external_target",
        lambda target, **kw: None,
    )
    result = runner.invoke(app, ["analyze-external", "h", "--ports", "80,443,"])
    assert result.exit_code != 0


def test_cli_ports_rejects_leading_comma(monkeypatch) -> None:
    monkeypatch.setattr(
        "webconf_audit.cli.analyze_external_target",
        lambda target, **kw: None,
    )
    result = runner.invoke(app, ["analyze-external", "h", "--ports", ",80,443"])
    assert result.exit_code != 0


def test_cli_ports_rejects_space_only_token(monkeypatch) -> None:
    monkeypatch.setattr(
        "webconf_audit.cli.analyze_external_target",
        lambda target, **kw: None,
    )
    result = runner.invoke(app, ["analyze-external", "h", "--ports", "80, ,443"])
    assert result.exit_code != 0


def test_cli_ports_rejects_out_of_range(monkeypatch) -> None:
    monkeypatch.setattr(
        "webconf_audit.cli.analyze_external_target",
        lambda target, **kw: None,
    )
    result = runner.invoke(app, ["analyze-external", "h", "--ports", "70000"])
    assert result.exit_code != 0


def test_cli_ports_rejects_zero(monkeypatch) -> None:
    monkeypatch.setattr(
        "webconf_audit.cli.analyze_external_target",
        lambda target, **kw: None,
    )
    result = runner.invoke(app, ["analyze-external", "h", "--ports", "0"])
    assert result.exit_code != 0


def test_cli_ports_deduplicates(monkeypatch) -> None:
    captured_ports = []

    def fake_analyze(target, **kwargs):
        captured_ports.append(kwargs.get("ports"))
        from webconf_audit.models import AnalysisResult
        return AnalysisResult(mode="external", target=target)

    monkeypatch.setattr("webconf_audit.cli.analyze_external_target", fake_analyze)
    result = runner.invoke(app, ["analyze-external", "h", "--ports", "80,80,443"])
    assert result.exit_code == 0
    assert captured_ports[0] == (80, 443)


def test_cli_ports_valid_input(monkeypatch) -> None:
    captured_ports = []

    def fake_analyze(target, **kwargs):
        captured_ports.append(kwargs.get("ports"))
        from webconf_audit.models import AnalysisResult
        return AnalysisResult(mode="external", target=target)

    monkeypatch.setattr("webconf_audit.cli.analyze_external_target", fake_analyze)
    result = runner.invoke(app, ["analyze-external", "h", "--ports", "80, 443, 8080"])
    assert result.exit_code == 0
    assert captured_ports[0] == (80, 443, 8080)


# ---------------------------------------------------------------------------
# CLI: --scan-ports / --no-scan-ports
# ---------------------------------------------------------------------------


def test_cli_no_scan_ports_flag(monkeypatch) -> None:
    captured_kwargs: list[dict] = []

    def fake_analyze(target, **kwargs):
        captured_kwargs.append(kwargs)
        from webconf_audit.models import AnalysisResult
        return AnalysisResult(mode="external", target=target)

    monkeypatch.setattr("webconf_audit.cli.analyze_external_target", fake_analyze)
    result = runner.invoke(app, ["analyze-external", "h", "--no-scan-ports"])
    assert result.exit_code == 0
    assert captured_kwargs[0]["scan_ports"] is False


def test_cli_scan_ports_flag_default(monkeypatch) -> None:
    captured_kwargs: list[dict] = []

    def fake_analyze(target, **kwargs):
        captured_kwargs.append(kwargs)
        from webconf_audit.models import AnalysisResult
        return AnalysisResult(mode="external", target=target)

    monkeypatch.setattr("webconf_audit.cli.analyze_external_target", fake_analyze)
    result = runner.invoke(app, ["analyze-external", "h"])
    assert result.exit_code == 0
    assert captured_kwargs[0]["scan_ports"] is True


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


def test_default_scan_ports_constant() -> None:
    """Sanity: DEFAULT_SCAN_PORTS contains expected standard ports."""
    assert 80 in DEFAULT_SCAN_PORTS
    assert 443 in DEFAULT_SCAN_PORTS
    assert 8080 in DEFAULT_SCAN_PORTS
    assert 8443 in DEFAULT_SCAN_PORTS
    assert len(DEFAULT_SCAN_PORTS) >= 5
