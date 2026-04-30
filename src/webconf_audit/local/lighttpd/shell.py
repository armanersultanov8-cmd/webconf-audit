from __future__ import annotations

import shlex
import subprocess  # nosec B404
from pathlib import Path


def execute_include_shell(
    command: str,
    *,
    timeout: float = 5,
    cwd: str | Path | None = None,
) -> str | None:
    """Execute an include_shell command and return captured stdout."""
    try:
        argv = shlex.split(command, posix=True)
    except ValueError:
        return None

    if not argv:
        return None

    try:
        result = subprocess.run(  # nosec B603
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            cwd=None if cwd is None else str(Path(cwd)),
        )
    except (OSError, subprocess.SubprocessError):
        return None

    if result.returncode != 0:
        return None

    return result.stdout


__all__ = ["execute_include_shell"]
