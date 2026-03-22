"""Helpers for long-running background tool processes.

Shared by tools that need to:
  - Launch a command in the background (with optional sudo elevation)
  - Stop it cleanly, handling the root/non-root sudo-kill edge case

Typical usage::

    from adscan_internal.background_process import launch_background, stop_background

    process = launch_background(
        command,
        shell.spawn_command,
        env=env,
        needs_root=True,
        label="Responder",
    )
    # …later…
    stop_background(process, label="Responder")
"""

from __future__ import annotations

import os
import signal
import subprocess
from typing import Callable

from adscan_internal import telemetry
from adscan_internal.rich_output import print_error, print_info_debug
from adscan_internal.sudo_utils import sudo_prefix_args, sudo_validate

# Matches the signature of shell.spawn_command (accepts **kwargs forwarded to Popen).
SpawnFn = Callable[..., "subprocess.Popen[str] | None"]


def launch_background(
    command: list[str],
    spawn_fn: SpawnFn,
    *,
    env: dict[str, str] | None = None,
    needs_root: bool = False,
    label: str = "process",
) -> "subprocess.Popen[str] | None":
    """Launch a command in the background, optionally with sudo elevation.

    The spawned process is placed in its own process group via ``os.setsid``
    so it can be cleanly terminated later with :func:`stop_background`.

    Args:
        command: Command to execute as a list of strings.
        spawn_fn: Callable that launches the process — typically
            ``shell.spawn_command``.
        env: Environment for the child process.  Defaults to
            ``os.environ.copy()`` when *None*.
        needs_root: If ``True``, prepend a ``sudo`` prefix when the current
            process is not already running as root.
        label: Short human-readable name for debug/error messages
            (e.g. ``"Responder"``, ``"ntlmrelayx"``).

    Returns:
        The :class:`subprocess.Popen` instance on success, or ``None`` if
        sudo validation failed or the process could not be launched.
    """
    if env is None:
        env = os.environ.copy()

    if needs_root and os.geteuid() != 0:
        if not sudo_validate():
            print_error(
                f"{label} requires root privileges. "
                "Please configure sudo and try again."
            )
            return None
        # Use non-interactive sudo without --preserve-env: the entrypoint
        # Defaults already cover env_keep, matching the nmap/ntpdate pattern.
        command = sudo_prefix_args(non_interactive=True, preserve_env_keys=()) + command

    print_info_debug(f"[DEBUG] launch_background({label}): {' '.join(command)}")

    try:
        process = spawn_fn(
            command,
            env=env,
            shell=False,
            stdout=None,
            stderr=None,
            preexec_fn=os.setsid,
        )
        if process and hasattr(process, "pid"):
            print_info_debug(f"[DEBUG] launch_background({label}): PID {process.pid}")
        else:
            print_info_debug(
                f"[DEBUG] launch_background({label}): process is None or has no PID"
            )
        return process
    except Exception as e:
        telemetry.capture_exception(e)
        print_info_debug(f"[DEBUG] launch_background({label}): exception — {e}")
        print_error(f"Error launching {label}.")
        return None


def stop_background(
    process: "subprocess.Popen[str] | None",
    *,
    label: str = "process",
) -> bool:
    """Send SIGTERM to a background process group, using sudo when needed.

    When the process was launched as root via sudo, a non-root caller cannot
    send signals directly.  This function detects that case and uses
    ``sudo kill`` instead of :func:`os.killpg`.

    Args:
        process: The :class:`subprocess.Popen` instance returned by
            :func:`launch_background`.  A ``None`` value is a no-op that
            returns ``False``.
        label: Short human-readable name for error messages.

    Returns:
        ``True`` if the signal was sent, ``False`` otherwise.
    """
    if not process:
        return False
    try:
        pgid = os.getpgid(process.pid)
        if os.geteuid() != 0:
            # Process may be owned by root (launched via sudo); use sudo to kill.
            subprocess.run(  # noqa: S603
                ["sudo", "kill", "--", f"-{pgid}"],
                check=False,
            )
        else:
            os.killpg(pgid, signal.SIGTERM)
        return True
    except Exception as e:
        telemetry.capture_exception(e)
        print_error(f"Error stopping {label}.")
        return False
