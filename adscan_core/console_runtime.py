"""Helpers for building Rich consoles across local and CI environments."""

from __future__ import annotations

import os
import sys
from typing import Any

from rich.console import Console

from adscan_core.interaction import is_ci_marker_present


def is_ci_render_context() -> bool:
    """Return whether Rich should render like a CI/non-interactive console."""
    session_env = str(os.getenv("ADSCAN_SESSION_ENV") or "").strip().lower()
    return session_env == "ci" or is_ci_marker_present()


def detect_rich_console_width(default: int = 160) -> int:
    """Return the best available width for CI/non-interactive Rich rendering."""
    env_columns = str(os.getenv("COLUMNS") or "").strip()
    if env_columns.isdigit() and int(env_columns) > 0:
        return int(env_columns)

    for stream in (sys.__stdout__, sys.stdout, sys.__stderr__, sys.stderr):
        try:
            size = os.get_terminal_size(stream.fileno())
        except (AttributeError, OSError, ValueError):
            continue
        if size.columns > 0:
            return size.columns

    return default


def build_rich_console(
    *,
    theme: Any,
    record: bool = False,
    file: Any | None = None,
) -> Console:
    """Build one Rich console with stable defaults across CI environments."""
    console_kwargs: dict[str, Any] = {"theme": theme, "record": record}
    if file is not None:
        console_kwargs["file"] = file

    if is_ci_render_context():
        width = detect_rich_console_width()
        os.environ.setdefault("COLUMNS", str(width))
        console_kwargs.update(
            force_terminal=True,
            color_system="truecolor",
            width=width,
        )

    return Console(**console_kwargs)
