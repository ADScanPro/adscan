"""Open files on the user's desktop from any ADscan flow.

ADscan runs inside a Docker container that has no GUI session: a bare
``xdg-open`` call would either silently fail or never reach the user's
desktop. This module routes the open request through the host helper
socket (mounted at ``ADSCAN_HOST_HELPER_SOCK``), which validates the path
and dispatches the opener as the invoking host user.

Outside the container the module falls back to ``xdg-open`` / ``open`` /
``os.startfile`` so the same call works in dev (``uv run adscan``) and in
production.

Public API
----------
- :func:`open_workspace_file` — single entry point used by demo, deliver,
  generate_report, and anyone else who wants "open this artefact for the
  user when they ask for it."

The helper validates that the path lives under the invoker's workspaces
tree on the host side, so adding new call sites here cannot escalate into
arbitrary host-file exposure.
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Final

from adscan_core import telemetry
from adscan_core.rich_output import print_info_debug
from adscan_core.rich_output import print_exception

__all__ = ("open_workspace_file", "display_host_path", "prompt_and_open")


_CONTAINER_RUNTIME_ENV: Final[str] = "ADSCAN_CONTAINER_RUNTIME"
_HOST_HELPER_SOCK_ENV: Final[str] = "ADSCAN_HOST_HELPER_SOCK"
_CONTAINER_ADSCAN_ROOT: Final[str] = "/opt/adscan"
_HOST_ADSCAN_ROOT: Final[str] = "~/.adscan"


def _is_container_runtime() -> bool:
    """Return True when ADscan runs inside its official Docker runtime."""
    return os.environ.get(_CONTAINER_RUNTIME_ENV) == "1"


def _request_open_via_host_helper(file_path: Path) -> bool:
    """Ask the host helper to open ``file_path`` on the host desktop.

    Returns True only when the helper accepted the request and reports
    success. Any failure path (no socket, helper error, opener missing)
    yields False — callers can then choose to fall back or surface the
    file path to the user.
    """
    sock = os.environ.get(_HOST_HELPER_SOCK_ENV, "").strip()
    if not sock:
        print_info_debug(
            "[host_open] ADSCAN_HOST_HELPER_SOCK is unset; cannot use host helper"
        )
        return False
    if not os.path.exists(sock):
        print_info_debug(
            f"[host_open] Host helper socket missing at {sock}; "
            "container likely not launched via the official launcher"
        )
        return False

    try:
        from adscan_internal.host_privileged_helper import (
            host_helper_client_request,
        )
    except Exception as exc:  # noqa: BLE001 — import is optional from caller's POV
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[host_open] Cannot import host helper client: {exc}")
        return False

    try:
        resp = host_helper_client_request(
            sock,
            op="open_file",
            payload={"path": str(file_path)},
            timeout_seconds=10,
        )
    except Exception as exc:  # noqa: BLE001 — opener is non-critical
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[host_open] Host helper request raised: {exc}")
        return False

    ok = bool(getattr(resp, "ok", False))
    if not ok:
        msg = getattr(resp, "message", None) or getattr(resp, "stderr", None) or "?"
        print_info_debug(f"[host_open] Host helper refused open_file: {msg}")
    return ok


def _try_local_opener(file_path: Path) -> bool:
    """Best-effort local desktop opener (used outside the container).

    Returns True when a launcher command was successfully spawned. The
    actual GUI launch is asynchronous and cannot be confirmed from here.
    """
    try:
        system = platform.system()
        if system == "Linux":
            subprocess.Popen(  # noqa: S603,S607
                ["xdg-open", str(file_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        if system == "Darwin":
            subprocess.Popen(  # noqa: S603,S607
                ["open", str(file_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        if system == "Windows":  # pragma: no cover — runtime is Linux
            os.startfile(str(file_path))  # type: ignore[attr-defined]  # pylint: disable=no-member
            return True
    except Exception as exc:  # noqa: BLE001 — opener is non-critical
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[host_open] Local opener failed: {exc}")
    return False


def display_host_path(path: Path | str) -> str:
    """Render a container-runtime path as the equivalent host path.

    Inside the ADscan container the workspace tree lives at ``/opt/adscan/``,
    but the launcher bind-mounts the same files to ``~/.adscan/`` on the
    host. The user typing ``ls`` will reach for the host path; show that
    one. Outside the container the path is returned unchanged.

    This is presentation-only — it returns a string for display, not a
    resolved filesystem path. Use the container path for actual I/O.
    """
    raw = str(path)
    if not _is_container_runtime():
        return raw
    if raw == _CONTAINER_ADSCAN_ROOT:
        return _HOST_ADSCAN_ROOT
    prefix = _CONTAINER_ADSCAN_ROOT + "/"
    if raw.startswith(prefix):
        return _HOST_ADSCAN_ROOT + "/" + raw[len(prefix):]
    return raw


def open_workspace_file(file_path: Path | str) -> bool:
    """Open ``file_path`` on the user's desktop, best-effort.

    Resolution order:

    1. Inside the ADscan container runtime → ask the host helper.
    2. On the host (dev mode, no container) → use the platform launcher
       (``xdg-open`` / ``open`` / ``os.startfile``).
    3. As a last resort inside the container, attempt the local opener
       anyway — usually fails silently but covers non-launcher entrypoints.

    Args:
        file_path: Absolute path to the artefact. Inside the container the
            container path is expected (``/opt/adscan/...``); the host
            helper translates it to the host path automatically.

    Returns:
        True when an opener was successfully dispatched. False otherwise
        — the caller should surface the file path to the user so they
        can open it manually.
    """
    path_obj = Path(file_path)

    if _is_container_runtime():
        if _request_open_via_host_helper(path_obj):
            return True
        # Fall through — in-container xdg-open usually fails but is harmless.

    return _try_local_opener(path_obj)


def prompt_and_open(
    file_path: Path | str,
    *,
    prompt: str = "Open it now?",
    default: bool = True,
) -> bool:
    """Ask the operator whether to open ``file_path`` and dispatch on yes.

    Auto-skipped in non-interactive contexts (no TTY,
    ``ADSCAN_NONINTERACTIVE=1`` set) — those paths must never block on user
    input. The questionary prompt is used when available, falling back to a
    plain ``input()`` so the helper works inside minimal containers too.

    Args:
        file_path: Artefact to open if the user confirms.
        prompt: Question text shown to the operator. Phrase it as a yes/no.
        default: Default answer when the operator just presses Enter.

    Returns:
        True when the open request was dispatched (helper accepted or local
        launcher spawned). False when the user declined, the prompt was
        skipped (non-interactive), or the open attempt failed.
    """
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return False
    if os.environ.get("ADSCAN_NONINTERACTIVE", "").strip() == "1":
        return False

    try:
        from questionary import confirm  # type: ignore[import-untyped]

        answer = confirm(prompt, default=default).ask()
    except Exception:  # noqa: BLE001 — questionary may be missing
        try:
            suffix = "[Y/n]" if default else "[y/N]"
            raw = input(f"{prompt} {suffix} ").strip().lower()
            if not raw:
                answer = default
            else:
                answer = raw in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            answer = False

    if not answer:
        return False
    return open_workspace_file(file_path)
