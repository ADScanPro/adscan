"""Premium CLI rendering for encrypted Office artifact detection and cracking.

Three distinct UX moments, each with a precise visual weight:

  1. render_office_vault_detected()  — amber panel on discovery
  2. render_office_vault_unlocked()  — green success with cracked secret
  3. render_office_vault_failed()    — dim panel with offline cracking guidance
"""

from __future__ import annotations

import os
from pathlib import Path

from rich.table import Table, Column
from rich.text import Text

from adscan_internal import print_info, print_info_debug
from adscan_internal.rich_output import (
    BRAND_COLORS,
    mark_sensitive,
    print_panel_with_table,
)
from adscan_internal.services.office_artifact_service import OfficeArtifactCrackResult


# ---------------------------------------------------------------------------
# Palette — operator aesthetic: amber warn / cyan active / green unlock
# ---------------------------------------------------------------------------
_AMBER   = "dark_orange"
_CYAN    = BRAND_COLORS["info"]
_GREEN   = BRAND_COLORS["success"]
_DIM     = "dim"
_RED     = "red"
_BOLD    = "bold"


def _short_path(file_path: str, workspace_cwd: str) -> str:
    """Return a concise relative path for display."""
    try:
        return os.path.relpath(file_path, workspace_cwd)
    except ValueError:
        return file_path


def _encryption_label(source_path: str) -> str:
    """Infer a human-readable encryption scheme label from the file path."""
    ext = Path(source_path).suffix.lower()
    if ext in {".xlsx", ".xlsm", ".docx", ".pptx"}:
        return "Office 2013+ · AES-256 / SHA-512"
    if ext in {".xls", ".doc", ".ppt"}:
        return "Office 97–2003 · RC4 / MD5"
    return "Office (encrypted)"


# ---------------------------------------------------------------------------
# 1.  DISCOVERY
# ---------------------------------------------------------------------------

def render_office_vault_detected(
    *,
    file_path: str,
    workspace_cwd: str,
    office2john_available: bool = True,
) -> None:
    """Render an amber discovery panel when an encrypted Office vault is found.

    Designed to give the operator an immediate, unambiguous signal:
    high-value encrypted credential store detected, cracking queued.

    Args:
        file_path: Absolute path to the encrypted file.
        workspace_cwd: Workspace root for relative-path display.
        office2john_available: When False, notes that office2john is missing.
    """
    rel = _short_path(file_path, workspace_cwd)
    stem = Path(file_path).name
    folder = Path(rel).parent.name or Path(rel).parent.as_posix()

    table = Table(
        Column(style=f"bold {_AMBER}", no_wrap=True),
        Column(style="default"),
        show_header=False,
        show_edge=False,
        pad_edge=False,
        box=None,
    )
    table.add_row("▸ File",       mark_sensitive(stem, "path"))
    table.add_row("▸ Encryption", _encryption_label(file_path))
    table.add_row("▸ Location",   mark_sensitive(rel, "path"))
    table.add_row("▸ Folder",     mark_sensitive(folder, "path"))
    if not office2john_available:
        table.add_row(
            "▸ Warning",
            Text("office2john not found — cracking will be skipped", style=_RED),
        )
    else:
        table.add_row("▸ Action", "office2john → John the Ripper → crack attempt")

    print_panel_with_table(
        table,
        title=f"[bold {_AMBER}]◆  ENCRYPTED CREDENTIAL VAULT DETECTED[/]",
        border_style=_AMBER,
        spacing="auto",
    )
    print_info_debug(
        f"[office_artifact] Encrypted Office vault detected: {rel}"
    )


# ---------------------------------------------------------------------------
# 2.  UNLOCKED
# ---------------------------------------------------------------------------

def render_office_vault_unlocked(
    *,
    result: OfficeArtifactCrackResult,
    workspace_cwd: str,
) -> None:
    """Render a green success panel when the Office vault password is recovered.

    Surfaces the cracked secret cleartext to the operator while wrapping it with
    ``mark_sensitive`` so the export-time telemetry sanitizer scrubs it from the
    session recording.

    Args:
        result: The completed :class:`OfficeArtifactCrackResult`.
        workspace_cwd: Workspace root for relative-path display.
    """
    rel = _short_path(result.source_path, workspace_cwd)
    stem = Path(result.source_path).name
    hash_rel = (
        _short_path(result.hash_file, workspace_cwd)
        if result.hash_file
        else "—"
    )

    table = Table(
        Column(style=f"bold {_GREEN}", no_wrap=True),
        Column(style="default"),
        show_header=False,
        show_edge=False,
        pad_edge=False,
        box=None,
    )
    table.add_row("▸ File",     mark_sensitive(stem, "path"))
    table.add_row("▸ Password", mark_sensitive(result.cracked_password or "", "secret"))
    table.add_row("▸ Hash",     mark_sensitive(hash_rel, "path"))
    table.add_row("▸ Location", mark_sensitive(rel, "path"))
    table.add_section()
    table.add_row(
        "▸ Next step",
        Text(
            "Content extraction deferred — use the cracked password to open the file manually.",
            style=_DIM,
        ),
    )

    print_panel_with_table(
        table,
        title=f"[bold {_GREEN}]◆  VAULT UNLOCKED[/]",
        border_style=_GREEN,
        spacing="auto",
    )
    print_info(
        f"Encrypted Office vault cracked: {mark_sensitive(stem, 'path')}"
    )


# ---------------------------------------------------------------------------
# 3.  FAILED
# ---------------------------------------------------------------------------

def render_office_vault_failed(
    *,
    result: OfficeArtifactCrackResult,
    workspace_cwd: str,
) -> None:
    """Render a dim failure panel when no password is recovered.

    Keeps tone neutral — wordlist exhaustion is expected, not an error.
    Provides the operator with the hash path for offline cracking.

    Args:
        result: The completed :class:`OfficeArtifactCrackResult`.
        workspace_cwd: Workspace root for relative-path display.
    """
    stem = Path(result.source_path).name
    hash_rel = (
        _short_path(result.hash_file, workspace_cwd)
        if result.hash_file
        else "—"
    )

    ext = Path(result.source_path).suffix.lower()
    john_format = "office2013" if ext in {".xlsx", ".xlsm", ".docx", ".pptx"} else "office97"

    table = Table(
        Column(style=f"bold {_DIM}", no_wrap=True),
        Column(style=_DIM),
        show_header=False,
        show_edge=False,
        pad_edge=False,
        box=None,
    )
    table.add_row("▸ File",   mark_sensitive(stem, "path"))
    table.add_row("▸ Hash",   mark_sensitive(hash_rel, "path"))
    table.add_row("▸ Reason", result.error_message or "Wordlist exhausted")
    table.add_section()
    table.add_row(
        "▸ Offline",
        Text(
            f"john --wordlist=<list> --format={john_format} {hash_rel}",
            style="dim italic",
        ),
    )
    table.add_row(
        "▸ Hashcat",
        Text(
            f"hashcat -m 9600 {hash_rel} <list>",
            style="dim italic",
        ),
    )

    print_panel_with_table(
        table,
        title=f"[{_DIM}]◆  VAULT REMAINS ENCRYPTED[/]",
        border_style="dim",
        spacing="auto",
    )
    print_info_debug(
        f"[office_artifact] Cracking failed for {stem}: {result.error_message}"
    )


__all__ = [
    "render_office_vault_detected",
    "render_office_vault_failed",
    "render_office_vault_unlocked",
]
