"""Central helpers for interactive vs non-interactive execution.

This module is shared across:
- the open-source launcher (PyPI)
- the runtime CLI inside the Docker image

It must remain dependency-light and free of import side-effects so it can be
imported early (including during error handling paths).
"""

from __future__ import annotations

import os
import sys
from typing import Callable, Mapping


_CI_MARKER_KEYS: tuple[str, ...] = (
    "CI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "CIRCLECI",
    "TRAVIS",
    "JENKINS_HOME",
    "TEAMCITY_VERSION",
    "BUILDKITE",
    "DRONE",
    "CONTINUOUS_INTEGRATION",
)


def env_truthy(key: str, *, env: Mapping[str, str] | None = None) -> bool:
    """Return True if an environment variable is set to a truthy value."""
    source = os.environ if env is None else env
    return str(source.get(key, "")).strip().lower() in {"1", "true", "yes", "on"}


def is_ci_marker_present(
    *,
    os_getenv: Callable[[str, str | None], str | None] = os.getenv,
) -> bool:
    """Return True if we detect an external CI environment marker."""
    return any(os_getenv(key, None) for key in _CI_MARKER_KEYS)


def stdin_isatty() -> bool:
    """Return True if stdin is a TTY (best-effort)."""
    try:
        return bool(sys.stdin.isatty())
    except Exception:
        return False


def stdout_isatty() -> bool:
    """Return True if stdout is a TTY (best-effort)."""
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


def is_interactive() -> bool:
    """Return True when a user is likely in an interactive terminal."""
    return stdin_isatty() and stdout_isatty()


def is_non_interactive(
    shell: object | None = None,
    *,
    os_getenv: Callable[[str, str | None], str | None] = os.getenv,
    stdin_isatty_fn: Callable[[], bool] = sys.stdin.isatty,
    stdout_isatty_fn: Callable[[], bool] = sys.stdout.isatty,
) -> bool:
    """Return True if ADscan must not block waiting for user interaction.

    Non-interactive signals:
    - `ADSCAN_NONINTERACTIVE=1`: hard override (used by `adscan ci`)
    - `ADSCAN_SESSION_ENV=ci` or `shell.session_command_type == "ci"`
    - external CI markers (GitHub Actions, GitLab CI, etc.)
    - missing TTY (stdin or stdout)
    """
    if (os_getenv("ADSCAN_NONINTERACTIVE", None) or "").strip() == "1":
        return True

    session_env = (os_getenv("ADSCAN_SESSION_ENV", None) or "").strip().lower()
    if session_env == "ci":
        return True

    if getattr(shell, "session_command_type", None) == "ci":
        return True

    if is_ci_marker_present(os_getenv=os_getenv):
        return True

    return bool((not stdin_isatty_fn()) or (not stdout_isatty_fn()))
