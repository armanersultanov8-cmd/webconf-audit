from __future__ import annotations

import http.client
import subprocess
import textwrap
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from webconf_audit.local.apache import analyze_apache_config
from webconf_audit.local.lighttpd import analyze_lighttpd_config


_ROOT = Path(__file__).resolve().parents[2]
_COMPOSE_FILE = _ROOT / "demo" / "local_admin" / "docker-compose.yml"
_DEMO_ROOT = _ROOT / "demo" / "local_admin"
_PROJECT_NAME = "webconf_audit_local_demo_it"
_READINESS_URLS: tuple[str, ...] = (
    "http://127.0.0.1:19080/",
    "http://127.0.0.1:19081/server-status",
    "http://127.0.0.1:19082/server-status",
)


def _run_command(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def _docker_available() -> bool:
    result = _run_command("docker", "info")
    return result.returncode == 0


def _require_docker() -> None:
    if not _docker_available():
        pytest.skip("Docker Engine is required for local integration tests")


def _run_compose(*args: str, compose_file: Path | None = None) -> subprocess.CompletedProcess[str]:
    cmd = [
        "docker",
        "compose",
        "-p",
        _PROJECT_NAME,
        "-f",
        str(compose_file or _COMPOSE_FILE),
    ]
    cmd.extend(args)
    return _run_command(*cmd)


def _wait_for_url(url: str, timeout_seconds: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error: str | None = None

    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2.0) as response:
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


def _read_url_text(
    url: str,
    *,
    timeout_seconds: float = 5.0,
    attempts: int = 5,
) -> tuple[int, str]:
    last_error: str | None = None

    for _ in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=timeout_seconds) as response:
                return response.status, response.read().decode("utf-8", errors="replace")
        except (http.client.HTTPException, OSError, urllib.error.URLError) as exc:
            last_error = str(exc)
            time.sleep(0.5)

    raise RuntimeError(f"Failed to read {url}: {last_error}")


@pytest.fixture(scope="session")
def local_admin_demo_stack(tmp_path_factory: pytest.TempPathFactory) -> dict[str, str]:
    if not _docker_available():
        pytest.skip("Docker Engine is required for local integration tests")

    override_dir = tmp_path_factory.mktemp("integration_local_compose")
    compose_file = override_dir / "docker-compose.yml"
    compose_file.write_text(
        textwrap.dedent(
            f"""
            services:
              nginx:
                image: nginx:1.27-alpine
                container_name: webconf-audit-local-demo-it-nginx
                ports:
                  - "19080:80"
                volumes:
                  - "{(_DEMO_ROOT / 'nginx').as_posix()}:/etc/nginx:ro"

              apache:
                image: httpd:2.4
                container_name: webconf-audit-local-demo-it-apache
                ports:
                  - "19081:80"
                volumes:
                  - "{(_DEMO_ROOT / 'apache' / 'conf').as_posix()}:/usr/local/apache2/conf:ro"

              lighttpd:
                build:
                  context: "{(_DEMO_ROOT / 'lighttpd' / 'docker').as_posix()}"
                image: webconf-audit-lighttpd-demo-it
                container_name: webconf-audit-local-demo-it-lighttpd
                ports:
                  - "19082:8080"
                volumes:
                  - "{(_DEMO_ROOT / 'lighttpd').as_posix()}:/etc/lighttpd:ro"
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )

    _run_compose("down", "-v", "--remove-orphans", compose_file=compose_file)
    up = _run_compose("up", "-d", "--build", compose_file=compose_file)
    if up.returncode != 0:
        raise RuntimeError(f"docker compose up failed:\nSTDOUT:\n{up.stdout}\nSTDERR:\n{up.stderr}")

    try:
        for url in _READINESS_URLS:
            _wait_for_url(url)
        yield {
            "nginx": "http://127.0.0.1:19080/",
            "apache_server_status": "http://127.0.0.1:19081/server-status",
            "lighttpd_server_status": "http://127.0.0.1:19082/server-status",
        }
    finally:
        down = _run_compose("down", "-v", "--remove-orphans", compose_file=compose_file)
        if down.returncode != 0:
            raise RuntimeError(
                f"docker compose down failed:\nSTDOUT:\n{down.stdout}\nSTDERR:\n{down.stderr}"
            )


@pytest.mark.parametrize(
    ("service", "command", "expected_snippet"),
    [
        ("nginx", ("nginx", "-t", "-c", "/etc/nginx/nginx.conf"), "test is successful"),
        ("apache", ("httpd", "-t", "-f", "/usr/local/apache2/conf/httpd.conf"), "Syntax OK"),
        (
            "lighttpd",
            ("lighttpd", "-tt", "-f", "/etc/lighttpd/lighttpd.conf"),
            "ssl.cipher-list is deprecated",
        ),
    ],
)
def test_demo_configs_pass_native_server_validation(
    service: str,
    command: tuple[str, ...],
    expected_snippet: str,
) -> None:
    _require_docker()

    if service == "lighttpd":
        build = _run_compose("build", service)
        assert build.returncode == 0, build.stdout + build.stderr

    result = _run_compose("run", "--rm", service, *command)

    assert result.returncode == 0, result.stdout + result.stderr
    output = result.stdout + result.stderr
    assert expected_snippet in output


@pytest.mark.parametrize(
    ("service_name", "url_key", "expected_body_fragment"),
    [
        ("nginx", "nginx", "Thank you for using nginx."),
        ("apache", "apache_server_status", "Apache Server Status"),
        ("lighttpd", "lighttpd_server_status", "Server-Status"),
    ],
)
def test_demo_stack_services_respond_over_http(
    local_admin_demo_stack: dict[str, str],
    service_name: str,
    url_key: str,
    expected_body_fragment: str,
) -> None:
    url = local_admin_demo_stack[url_key]

    status, body = _read_url_text(url)

    assert status == 200, f"{service_name} did not return HTTP 200"
    assert expected_body_fragment in body


def test_live_exposed_status_endpoints_match_local_findings(
    local_admin_demo_stack: dict[str, str],
) -> None:
    apache_result = analyze_apache_config(
        str(_ROOT / "demo" / "local_admin" / "apache" / "conf" / "httpd.conf")
    )
    lighttpd_result = analyze_lighttpd_config(
        str(_ROOT / "demo" / "local_admin" / "lighttpd" / "lighttpd.conf")
    )

    apache_rule_ids = {finding.rule_id for finding in apache_result.findings}
    lighttpd_rule_ids = {finding.rule_id for finding in lighttpd_result.findings}

    assert "apache.server_status_exposed" in apache_rule_ids
    assert "lighttpd.mod_status_public" in lighttpd_rule_ids

    _, apache_body = _read_url_text(local_admin_demo_stack["apache_server_status"])
    _, lighttpd_body = _read_url_text(local_admin_demo_stack["lighttpd_server_status"])

    assert "Apache Server Status" in apache_body
    assert "Server-Status" in lighttpd_body
