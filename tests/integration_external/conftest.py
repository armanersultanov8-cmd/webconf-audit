from __future__ import annotations

from collections.abc import Generator
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest


_ROOT = Path(__file__).resolve().parents[2]
_COMPOSE_FILE = Path(__file__).resolve().parent / "docker-compose.yml"
_PROJECT_NAME = "webconf_audit_external_it"
_DOCKER_PROBE_TIMEOUT_SECONDS = 5
_READY_URLS: tuple[tuple[str, bool], ...] = (
    ("http://127.0.0.1:18080/", False),
    ("https://127.0.0.1:18443/", True),
    ("http://127.0.0.1:18082/", False),
    ("http://127.0.0.1:18083/", False),
    ("http://127.0.0.1:18084/", False),
)


def _docker_command() -> str | None:
    return shutil.which("docker")


def _compose_command() -> list[str] | None:
    docker_command = _docker_command()
    if docker_command is not None:
        try:
            compose_result = subprocess.run(
                [docker_command, "compose", "version"],
                cwd=_ROOT,
                text=True,
                capture_output=True,
                timeout=_DOCKER_PROBE_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            compose_result = None
        if compose_result is not None and compose_result.returncode == 0:
            return [docker_command, "compose"]

    docker_compose_command = shutil.which("docker-compose")
    if docker_compose_command is None:
        return None

    try:
        compose_result = subprocess.run(
            [docker_compose_command, "version"],
            cwd=_ROOT,
            text=True,
            capture_output=True,
            timeout=_DOCKER_PROBE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if compose_result.returncode != 0:
        return None
    return [docker_compose_command]


def _run_compose(*args: str) -> subprocess.CompletedProcess[str]:
    if _COMPOSE_COMMAND is None:
        raise RuntimeError(_DOCKER_SKIP_REASON)
    return subprocess.run(
        [*_COMPOSE_COMMAND, "-p", _PROJECT_NAME, "-f", str(_COMPOSE_FILE), *args],
        cwd=_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def _docker_available() -> bool:
    if _COMPOSE_COMMAND is None:
        return False
    try:
        result = subprocess.run(
            [*_COMPOSE_COMMAND, "-p", _PROJECT_NAME, "-f", str(_COMPOSE_FILE), "ps"],
            cwd=_ROOT,
            text=True,
            capture_output=True,
            timeout=_DOCKER_PROBE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


_COMPOSE_COMMAND = _compose_command()
_DOCKER_AVAILABLE = _docker_available()
_DOCKER_SKIP_REASON = (
    "Docker Engine with docker compose support is required for external integration tests"
)


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    if _DOCKER_AVAILABLE:
        return
    skip = pytest.mark.skip(reason=_DOCKER_SKIP_REASON)
    for item in items:
        item.add_marker(skip)


def _wait_for_url(url: str, *, insecure_https: bool, timeout_seconds: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    context = None
    if insecure_https:
        import ssl

        context = ssl._create_unverified_context()

    last_error: str | None = None
    while time.monotonic() < deadline:
        try:
            request = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(request, timeout=2.0, context=context) as response:
                if response.status < 500:
                    return
        except urllib.error.HTTPError as exc:
            if exc.code < 500:
                return
            last_error = str(exc)
        except OSError as exc:
            last_error = str(exc)
        time.sleep(0.5)

    raise RuntimeError(f"Timed out waiting for {url}: {last_error}")


@pytest.fixture(scope="session", autouse=True)
def external_integration_stack() -> Generator[None, None, None]:
    if not _DOCKER_AVAILABLE:
        yield
        return
    _run_compose("down", "-v", "--remove-orphans")
    up = _run_compose("up", "-d", "--build")
    if up.returncode != 0:
        raise RuntimeError(f"docker compose up failed:\nSTDOUT:\n{up.stdout}\nSTDERR:\n{up.stderr}")

    try:
        for url, insecure_https in _READY_URLS:
            _wait_for_url(url, insecure_https=insecure_https)
        yield
    finally:
        down = _run_compose("down", "-v", "--remove-orphans")
        if down.returncode != 0:
            raise RuntimeError(
                f"docker compose down failed:\nSTDOUT:\n{down.stdout}\nSTDERR:\n{down.stderr}"
            )
