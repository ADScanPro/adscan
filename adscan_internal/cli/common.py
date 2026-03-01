"""Common CLI helpers for telemetry context, workspace selection, first-run, and shared constants.

This module provides shared functionality used across CLI commands to avoid
circular dependencies and duplicate code.
"""

from __future__ import annotations

import hashlib
from typing import Any

from adscan_core.lab_context import (
    build_lab_telemetry_fields,
    build_workspace_telemetry_fields,
)
from adscan_internal.path_utils import get_adscan_state_dir
from adscan_internal.telemetry import TELEMETRY_ID
from adscan_internal.rich_output import print_panel
from rich.text import Text


# SECRET_MODE is a global flag that controls whether internal implementation
# details are shown. It is set in adscan.py during initialization.
# CLI modules should import this from here instead of adscan.py.
# This will be initialized by adscan.py on startup.
import os

SECRET_MODE: bool = os.getenv("ADSCAN_SECRET_MODE") == "1"  # pylint: disable=invalid-name


def build_telemetry_context(
    *,
    shell: Any,
    trigger: str,
) -> dict[str, Any]:
    """Build telemetry context dictionary from shell state.

    This helper extracts workspace and lab information from a shell instance
    and builds a standardized telemetry context dictionary.

    Args:
        shell: Shell instance with workspace attributes (current_workspace, type,
               lab_provider, lab_name, lab_name_whitelisted).
        trigger: Telemetry change trigger (e.g., "session_start", "ci_start").

    Returns:
        Dictionary with telemetry context including workspace_id_hash,
        workspace_type, lab_provider, lab_name, lab_name_whitelisted, and
        telemetry_change_trigger.
    """
    telemetry_context: dict[str, Any] = {}

    if getattr(shell, "current_workspace", None):
        workspace_unique_id = f"{TELEMETRY_ID}:{shell.current_workspace}"
        telemetry_context["workspace_id_hash"] = hashlib.sha256(
            workspace_unique_id.encode()
        ).hexdigest()[:12]

    telemetry_context.update(
        build_workspace_telemetry_fields(workspace_type=getattr(shell, "type", None))
    )

    telemetry_context.update(build_lab_event_fields(shell=shell, include_slug=False))

    telemetry_context["telemetry_change_trigger"] = trigger

    return telemetry_context


def build_lab_event_fields(*, shell: Any, include_slug: bool = True) -> dict[str, Any]:
    """Build normalized lab telemetry fields for event payloads.

    Args:
        shell: Shell instance that may expose ``lab_provider``, ``lab_name``,
            ``lab_name_whitelisted`` and optional ``_get_lab_slug``.
        include_slug: Whether to include ``lab_slug``.

    Returns:
        Dictionary with normalized lab context fields according to privacy rules.
    """
    lab_slug: str | None = None
    if include_slug:
        slug_getter = getattr(shell, "_get_lab_slug", None)
        if callable(slug_getter):
            try:
                lab_slug = slug_getter()
            except Exception:
                lab_slug = None

    return build_lab_telemetry_fields(
        lab_provider=getattr(shell, "lab_provider", None),
        lab_name=getattr(shell, "lab_name", None),
        lab_name_whitelisted=getattr(shell, "lab_name_whitelisted", None),
        include_slug=include_slug,
        lab_slug=lab_slug,
    )


def is_first_run() -> bool:
    """Check if this is the first time running ADscan.

    Returns:
        True if first run, False otherwise.
    """
    # Use persisted state (mounted from host in Docker-mode) so the panel is only shown once.
    flag_file = get_adscan_state_dir() / ".first_run_complete"
    return not flag_file.exists()


def mark_first_run_complete() -> None:
    """Mark first run as complete by creating flag file."""
    flag_file = get_adscan_state_dir() / ".first_run_complete"
    try:
        flag_file.parent.mkdir(parents=True, exist_ok=True)
        flag_file.touch()
    except Exception:
        # Silently fail if can't create flag (non-critical)
        pass


def show_first_run_helper(
    track_docs_link_shown: Any | None = None,
) -> None:
    """Show getting started helper on first run only.

    Args:
        track_docs_link_shown: Optional function to track when docs link is shown.
                              If provided, should accept (context: str, url: str).
    """
    helper_text = Text.from_markup(
        "💡 [bold]New to ADscan?[/bold]\n\n"
        "Quick Start:\n"
        "  1. Create workspace:  [cyan]workspace create my_pentest[/cyan]\n"
        "  2. Scan unauth:       [cyan]start_unauth[/cyan]\n"
        "  3. Scan auth:         [cyan]start_auth[/cyan]\n"
        "  4. Add a credential:  [cyan]creds save <domain> <username> <password>[/cyan]\n\n"
        "📚 Full documentation: [link=https://www.adscanpro.com/docs?utm_source=cli&utm_medium=first_run]"
        "www.adscanpro.com/docs[/link]\n"
        "   (Installation, guides, troubleshooting, and more)\n\n"
        "[dim]Type 'help' for available commands[/dim]"
    )

    print_panel(
        helper_text,
        title="[bold cyan]Getting Started[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    )

    # Track docs link shown if tracking function provided
    if track_docs_link_shown is not None:
        try:
            track_docs_link_shown(
                "first_run",
                "https://www.adscanpro.com/docs?utm_source=cli&utm_medium=first_run",
            )
        except Exception:
            # Silently fail if tracking fails (non-critical)
            pass
