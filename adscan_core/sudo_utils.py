"""Centralized sudo validation and prefix-building utilities.

Canonical implementation shared by both launcher and runtime.
"""

from __future__ import annotations

import os
import shutil
import subprocess

from adscan_core.interaction import is_non_interactive
from adscan_core.rich_output import print_info_debug, print_info_verbose

_sudo_validated: bool = False

DEFAULT_SUDO_PRESERVE_ENV_KEYS: tuple[str, ...] = (
    "HOME",
    "XDG_CONFIG_HOME",
    "ADSCAN_HOME",
)


def sudo_validate() -> bool:
    """Ensure sudo credentials are cached for the current session (best-effort)."""
    global _sudo_validated  # pylint: disable=global-statement

    if os.geteuid() == 0:
        _sudo_validated = True
        return True

    if _sudo_validated:
        return True

    if not shutil.which("sudo"):
        print_info_debug("sudo binary not found in PATH")
        return False

    try:
        probe = subprocess.run(  # noqa: S603
            ["sudo", "-n", "true"],
            check=False,
            capture_output=True,
            timeout=10,
        )
        if probe.returncode == 0:
            _sudo_validated = True
            return True
    except (subprocess.TimeoutExpired, OSError) as exc:
        print_info_debug(f"sudo -n true failed: {exc}")

    if is_non_interactive():
        print_info_verbose("Non-interactive environment; sudo requires NOPASSWD")
        return False

    try:
        result = subprocess.run(  # noqa: S603
            ["sudo", "true"],
            check=False,
            capture_output=False,
            timeout=120,
        )
        if result.returncode == 0:
            _sudo_validated = True
            return True
    except (subprocess.TimeoutExpired, OSError) as exc:
        print_info_debug(f"sudo true (interactive) failed: {exc}")

    return False


def reset_sudo_cache() -> None:
    global _sudo_validated  # pylint: disable=global-statement
    _sudo_validated = False


def is_sudo_cached() -> bool:
    return _sudo_validated or os.geteuid() == 0


def sudo_prefix_args(
    *,
    non_interactive: bool = False,
    preserve_env_keys: tuple[str, ...] = DEFAULT_SUDO_PRESERVE_ENV_KEYS,
) -> list[str]:
    args: list[str] = ["sudo"]
    if non_interactive:
        args.append("-n")
    if preserve_env_keys:
        args.append(f"--preserve-env={','.join(preserve_env_keys)}")
    return args


def run_with_sudo(
    argv: list[str],
    *,
    require_noninteractive: bool = False,
    preserve_env_keys: tuple[str, ...] = (),
    timeout: int = 20,
) -> subprocess.CompletedProcess[str]:
    cmd = list(argv)
    if os.geteuid() != 0:
        prefix: list[str] = ["sudo"]
        if require_noninteractive:
            prefix.append("-n")
        if preserve_env_keys:
            prefix.append(f"--preserve-env={','.join(preserve_env_keys)}")
        cmd = prefix + cmd
    return subprocess.run(  # noqa: S603
        cmd,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )
