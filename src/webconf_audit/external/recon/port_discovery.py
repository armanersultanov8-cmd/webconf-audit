"""Port discovery for external web-service detection.

Scans a predefined (or user-supplied) set of TCP ports on the target host
to find open ports where HTTP/HTTPS services may be running.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from webconf_audit.external.recon import DEFAULT_TIMEOUT_SECONDS, ProbeScheme, ProbeTarget

# --- Default port set ---------------------------------------------------
# Common ports where HTTP/HTTPS services are typically found.
# The tuple is kept ordered for deterministic output.
DEFAULT_SCAN_PORTS: tuple[int, ...] = (
    80,
    443,
    8080,
    8443,
    8000,
    8888,
    3000,
    5000,
    9443,
)

# Ports that are conventionally associated with HTTPS (TLS).
# When probing these, HTTPS is attempted first.
_HTTPS_PREFERRED_PORTS: frozenset[int] = frozenset({443, 8443, 9443})


# --- Data structures -----------------------------------------------------

@dataclass(frozen=True, slots=True)
class DiscoveredPort:
    """Result of a single TCP-connect probe against one port."""

    host: str
    port: int
    tcp_open: bool
    error_message: str | None = None


def probe_targets_for_port(host: str, port: int, path: str = "/") -> list[ProbeTarget]:
    """Return the ``ProbeTarget`` list for a given open port.

    The order reflects which scheme is tried first:
    * Ports in ``_HTTPS_PREFERRED_PORTS`` → HTTPS first, then HTTP.
    * All other ports → HTTP first, then HTTPS.
    """
    schemes: tuple[ProbeScheme, ProbeScheme]
    if port in _HTTPS_PREFERRED_PORTS:
        schemes = ("https", "http")
    else:
        schemes = ("http", "https")

    return [
        ProbeTarget(scheme=scheme, host=host, port=port, path=path)
        for scheme in schemes
    ]


# --- TCP scanning ---------------------------------------------------------

_MAX_SCAN_WORKERS = 12


def _check_tcp_port(
    host: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> DiscoveredPort:
    """Attempt a TCP connect to *host*:*port* and report the result."""
    if port < 0 or port > 65535:
        return DiscoveredPort(
            host=host,
            port=port,
            tcp_open=False,
            error_message="invalid port: must be between 0 and 65535",
        )

    try:
        with socket.create_connection((host, port), timeout=timeout):
            return DiscoveredPort(host=host, port=port, tcp_open=True)
    except OSError as exc:
        return DiscoveredPort(
            host=host, port=port, tcp_open=False, error_message=str(exc),
        )


def scan_ports(
    host: str,
    ports: tuple[int, ...] = DEFAULT_SCAN_PORTS,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> list[DiscoveredPort]:
    """Scan *ports* on *host* in parallel and return results.

    Results are returned in the same order as *ports*, regardless of the
    order in which the probes complete.  Only ``_MAX_SCAN_WORKERS`` threads
    run concurrently to avoid flooding the target.
    """
    if not ports:
        return []

    workers = min(_MAX_SCAN_WORKERS, len(ports))
    # Map future → original index so we can restore ordering.
    future_to_index: dict[object, int] = {}
    results: list[DiscoveredPort | None] = [None] * len(ports)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        for idx, port in enumerate(ports):
            future = executor.submit(_check_tcp_port, host, port, timeout)
            future_to_index[future] = idx

        for future in as_completed(future_to_index):
            idx = future_to_index[future]
            results[idx] = future.result()

    # All slots are filled; narrow the type for the caller.
    return [r for r in results if r is not None]


# --- High-level discovery -------------------------------------------------


def discover_probe_targets(
    host: str,
    ports: tuple[int, ...] = DEFAULT_SCAN_PORTS,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    path: str = "/",
) -> tuple[list[ProbeTarget], list[DiscoveredPort]]:
    """Scan *ports* and build ``ProbeTarget`` entries for every open port.

    For each open port, both HTTP and HTTPS ``ProbeTarget`` entries are
    generated (via :func:`probe_targets_for_port`), with the preferred
    scheme listed first.  The actual probing stage will try both and
    handle failures, so no premature scheme guessing is done here.

    Returns a ``(probe_targets, all_results)`` pair.  The first element
    contains the targets that should be passed to the probing stage; the
    second element contains the raw TCP-scan results for diagnostics.
    """
    scan_results = scan_ports(host, ports, timeout)

    probe_targets: list[ProbeTarget] = []
    for result in scan_results:
        if result.tcp_open:
            probe_targets.extend(probe_targets_for_port(host, result.port, path))

    return probe_targets, scan_results


__all__ = [
    "DEFAULT_SCAN_PORTS",
    "DiscoveredPort",
    "discover_probe_targets",
    "probe_targets_for_port",
    "scan_ports",
]
