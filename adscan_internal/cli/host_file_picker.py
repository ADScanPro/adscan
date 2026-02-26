"""Shared helpers for selecting and importing files from the host.

These helpers centralize the Docker-runtime host-helper flow used by multiple
CLI modules (e.g. cracking and Kerberos user enumeration):
- open a GUI file picker on the host desktop
- import the selected host file into the active workspace when needed
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Protocol

from adscan_internal import (
    print_info_debug,
    print_warning,
    telemetry,
)
from adscan_internal.rich_output import mark_sensitive, print_exception


class HostFilePickerShell(Protocol):
    """Minimal shell surface needed by host file picker helpers."""

    current_workspace_dir: str | None

    def _is_full_adscan_container_runtime(self) -> bool: ...


def is_full_container_runtime(shell: object) -> bool:
    """Return True if running inside the ADscan FULL container runtime."""
    try:
        method = getattr(shell, "_is_full_adscan_container_runtime", None)
        if callable(method):
            return bool(method())
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)

    try:
        from adscan_internal.cli.tools_env import _is_full_adscan_container_runtime

        return bool(_is_full_adscan_container_runtime())
    except Exception:
        return os.getenv("ADSCAN_CONTAINER_RUNTIME") == "1"


def _read_positive_int_env(name: str, *, default: int) -> int:
    """Parse a positive integer env var, returning default on errors."""
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def select_host_file_via_gui(
    shell: HostFilePickerShell,
    *,
    title: str,
    initial_dir: str | None = None,
    log_prefix: str = "file_picker",
) -> str | None:
    """Open a host GUI file picker (container runtime) and return selected path."""
    if not is_full_container_runtime(shell):
        print_info_debug(
            f"[{log_prefix}] Not running in container runtime; skipping host GUI picker"
        )
        return None

    helper_sock = os.getenv("ADSCAN_HOST_HELPER_SOCK", "").strip()
    if not helper_sock or not os.path.exists(helper_sock):
        marked_sock = mark_sensitive(helper_sock or "<unset>", "path")
        print_info_debug(
            f"[{log_prefix}] Host GUI picker unavailable: ADSCAN_HOST_HELPER_SOCK={marked_sock}"
        )
        return None

    try:
        from adscan_internal.host_privileged_helper import host_helper_client_request

        marked_sock = mark_sensitive(helper_sock, "path")
        print_info_debug(
            f"[{log_prefix}] Opening host GUI file picker via host-helper ({marked_sock})"
        )

        width = _read_positive_int_env("ADSCAN_FILE_PICKER_WIDTH", default=1400)
        height = _read_positive_int_env("ADSCAN_FILE_PICKER_HEIGHT", default=900)
        fullscreen = os.getenv("ADSCAN_FILE_PICKER_FULLSCREEN", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        timeout_seconds = (
            float(_read_positive_int_env("ADSCAN_FILE_PICKER_TIMEOUT", default=600))
            + 30.0
        )

        print_info_debug(
            f"[{log_prefix}] File picker settings: width={width}, height={height}, "
            f"fullscreen={fullscreen}, timeout={timeout_seconds:.0f}s"
        )

        resp = host_helper_client_request(
            helper_sock,
            op="select_file_gui",
            payload={
                "title": title,
                "initial_dir": initial_dir or "",
                "width": width,
                "height": height,
                "fullscreen": fullscreen,
            },
            timeout_seconds=timeout_seconds,
        )
        if not resp.ok:
            msg = (resp.message or "").strip() or "Unknown error"
            stderr = (resp.stderr or "").strip()
            details = f"message={msg}"
            if resp.returncode is not None:
                details += f", returncode={resp.returncode}"
            if stderr:
                details += f", stderr={stderr}"
            print_info_debug(
                f"[{log_prefix}] Host GUI picker failed; falling back to manual path ({details})"
            )
            return None

        selected = (resp.stdout or "").strip() or None
        if not selected:
            print_info_debug(
                f"[{log_prefix}] Host GUI picker returned no selection; falling back to manual path"
            )
            return None

        marked_selected = mark_sensitive(selected, "path")
        print_info_debug(f"[{log_prefix}] Host GUI picker selected: {marked_selected}")
        return selected
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[{log_prefix}] Exception while using host GUI picker; falling back to manual path"
        )
        print_exception(exception=exc)
        return None


def maybe_import_host_file_to_workspace(
    shell: HostFilePickerShell,
    *,
    domain: str,
    source_path: str,
    dest_dir: str = "wordlists_custom",
    log_prefix: str = "file_picker",
) -> str:
    """Best-effort import of a host file into the current workspace (Docker runtime)."""
    if not source_path:
        return source_path
    if os.path.exists(source_path):
        return source_path
    if not is_full_container_runtime(shell):
        return source_path

    helper_sock = os.getenv("ADSCAN_HOST_HELPER_SOCK", "").strip()
    if not helper_sock or not os.path.exists(helper_sock):
        marked_sock = mark_sensitive(helper_sock or "<unset>", "path")
        print_warning(
            f"Host helper socket not available ({marked_sock}). Cannot import host file."
        )
        return source_path

    workspace_dir = getattr(shell, "current_workspace_dir", None) or ""
    workspace_name = Path(workspace_dir).name if workspace_dir else ""
    if not workspace_name:
        print_warning("Could not determine workspace name. Cannot import host file.")
        return source_path

    dest_rel = Path(dest_dir) / domain / (Path(source_path).name or "custom_wordlist.txt")

    try:
        from adscan_internal.host_privileged_helper import host_helper_client_request

        marked_workspace_dir = mark_sensitive(workspace_dir or "<unset>", "path")
        marked_workspace = mark_sensitive(workspace_name, "workspace")
        marked_dest_rel = mark_sensitive(str(dest_rel), "path")
        print_info_debug(
            f"[{log_prefix}] Importing host file into workspace "
            f"(workspace_dir={marked_workspace_dir}, workspace={marked_workspace}, "
            f"dest_rel_path={marked_dest_rel})"
        )

        resp = host_helper_client_request(
            helper_sock,
            op="import_file_to_workspace",
            payload={
                "workspace": workspace_name,
                "src_path": source_path,
                "dest_rel_path": str(dest_rel),
            },
        )
        if not resp.ok or not resp.stdout:
            marked_path = mark_sensitive(source_path, "path")
            print_info_debug(
                f"[{log_prefix}] Host file import request failed "
                f"(workspace={marked_workspace}, message={resp.message or 'Unknown error'})"
            )
            print_warning(
                f"Failed to import host file {marked_path}. {resp.message or 'Unknown error'}"
            )
            return source_path

        data = json.loads(resp.stdout)
        container_dest = str(data.get("container_dest") or "").strip()
        if not container_dest:
            return source_path

        marked_src = mark_sensitive(source_path, "path")
        marked_dst = mark_sensitive(container_dest, "path")
        print_info_debug(
            f"[{log_prefix}] Imported host file {marked_src} -> {marked_dst}"
        )
        return container_dest
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning("Host file import failed; continuing anyway.")
        print_exception(exception=exc)
        return source_path


# Backward-compatible alias for earlier imports.
WordlistPickerShell = HostFilePickerShell
