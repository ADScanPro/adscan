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
import threading
import time
from typing import Callable

from adscan_internal import telemetry
from adscan_internal.rich_output import print_error, print_info_debug, print_warning
from adscan_internal.sudo_utils import sudo_prefix_args, sudo_validate

# Matches the signature of shell.spawn_command (accepts **kwargs forwarded to Popen).
SpawnFn = Callable[..., "subprocess.Popen[str] | None"]
ExitFn = Callable[[int | None, bool], None]


def _stream_background_output_to_debug(
    process: "subprocess.Popen[str] | None",
    *,
    label: str,
) -> None:
    """Mirror captured background-process output into debug-only logs."""
    if not process:
        return

    def _pump(stream_name: str) -> Callable[[], None]:
        def _reader() -> None:
            stream = getattr(process, stream_name, None)
            if stream is None:
                return
            try:
                for raw_line in iter(stream.readline, ""):
                    line = str(raw_line or "").rstrip()
                    if line:
                        print_info_debug(f"[background][{label}][{stream_name}] {line}")
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_info_debug(
                    f"[background] {label} {stream_name} stream exception — {exc}"
                )

        return _reader

    for stream_name in ("stdout", "stderr"):
        if getattr(process, stream_name, None) is None:
            continue
        thread = threading.Thread(
            target=_pump(stream_name),
            name=f"{label}-{stream_name}-stream",
            daemon=True,
        )
        thread.start()


def watch_background_process(
    process: "subprocess.Popen[str] | None",
    *,
    label: str = "process",
    poll_interval_seconds: float = 1.0,
    on_exit: ExitFn | None = None,
    warn_on_unexpected_exit: bool = True,
) -> threading.Thread | None:
    """Monitor a background process and log when it exits.

    Args:
        process: Process returned by ``launch_background``.
        label: Human-readable process label.
        poll_interval_seconds: Polling interval for ``process.poll()``.
        on_exit: Optional callback invoked with ``(returncode, expected_stop)``.
        warn_on_unexpected_exit: Whether to emit a warning if the process exits
            without having been marked for an intentional stop.

    Returns:
        The watcher thread on success, or ``None`` if the process is invalid or
        already has a watcher attached.
    """
    if not process or not hasattr(process, "poll"):
        return None
    if getattr(process, "_adscan_watch_started", False):
        return getattr(process, "_adscan_watch_thread", None)

    setattr(process, "_adscan_watch_started", True)
    if not hasattr(process, "_adscan_expected_stop"):
        setattr(process, "_adscan_expected_stop", False)

    def _watch() -> None:
        try:
            while True:
                returncode = process.poll()
                if returncode is not None:
                    expected_stop = bool(
                        getattr(process, "_adscan_expected_stop", False)
                    )
                    print_info_debug(
                        f"[background] {label} exited with return code {returncode} "
                        f"(expected_stop={expected_stop})"
                    )
                    if warn_on_unexpected_exit and not expected_stop:
                        print_warning(f"{label} stopped unexpectedly.")
                    if on_exit is not None:
                        try:
                            on_exit(returncode, expected_stop)
                        except Exception as callback_exc:  # noqa: BLE001
                            telemetry.capture_exception(callback_exc)
                            print_info_debug(
                                f"[background] {label} watcher callback exception — "
                                f"{callback_exc}"
                            )
                    break
                time.sleep(max(poll_interval_seconds, 0.1))
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(f"[background] watcher({label}) exception — {exc}")

    watcher = threading.Thread(
        target=_watch,
        name=f"{label}-watcher",
        daemon=True,
    )
    setattr(process, "_adscan_watch_thread", watcher)
    watcher.start()
    return watcher


def launch_background(
    command: list[str],
    spawn_fn: SpawnFn,
    *,
    env: dict[str, str] | None = None,
    needs_root: bool = False,
    label: str = "process",
    watch: bool = False,
    on_exit: ExitFn | None = None,
    warn_on_unexpected_exit: bool = True,
    stream_output_to_debug: bool = True,
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
        watch: Whether to attach a watcher thread that logs process exit.
        on_exit: Optional callback for the watcher.
        warn_on_unexpected_exit: Emit a warning when the process dies without
            an intentional stop.
        stream_output_to_debug: Capture stdout/stderr and mirror them to
            ``print_info_debug`` instead of letting the child write directly to
            the terminal. Defaults to ``True`` so background tools stay quiet in
            normal UX and only expose raw process output under debug logging.

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
            stdout=subprocess.PIPE if stream_output_to_debug else None,
            stderr=subprocess.PIPE if stream_output_to_debug else None,
            text=True,
            preexec_fn=os.setsid,
        )
        if process and hasattr(process, "pid"):
            print_info_debug(f"[DEBUG] launch_background({label}): PID {process.pid}")
        else:
            print_info_debug(
                f"[DEBUG] launch_background({label}): process is None or has no PID"
            )
        if watch:
            watch_background_process(
                process,
                label=label,
                on_exit=on_exit,
                warn_on_unexpected_exit=warn_on_unexpected_exit,
            )
        if stream_output_to_debug:
            _stream_background_output_to_debug(process, label=label)
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
        setattr(process, "_adscan_expected_stop", True)
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
