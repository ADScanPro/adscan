"""Helpers for building Rich consoles across local and CI environments."""

from __future__ import annotations

import os
import sys
from typing import Any

from rich.console import Console

from adscan_core.interaction import is_ci_marker_present
from adscan_core.sensitive import strip_sensitive_markers


class MarkerStrippingTextIO:
    """Proxy file object that strips invisible sensitivity markers on write.

    This is used only for user-facing sinks such as the primary terminal
    console. Telemetry/session-recording consoles must keep the original marked
    content so downstream sanitization can still identify sensitive spans.
    """

    def __init__(self, wrapped: Any) -> None:
        self._wrapped = wrapped

    def write(self, data: Any) -> Any:
        if isinstance(data, str):
            data = strip_sensitive_markers(data)
        return self._wrapped.write(data)

    def writelines(self, lines: Any) -> Any:
        cleaned = [
            strip_sensitive_markers(line) if isinstance(line, str) else line
            for line in lines
        ]
        return self._wrapped.writelines(cleaned)

    def flush(self) -> Any:
        return self._wrapped.flush()

    def isatty(self) -> bool:
        return bool(getattr(self._wrapped, "isatty", lambda: False)())

    def fileno(self) -> int:
        return self._wrapped.fileno()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._wrapped, name)


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
    strip_markers: bool = False,
) -> Console:
    """Build one Rich console with stable defaults across CI environments."""
    console_kwargs: dict[str, Any] = {"theme": theme, "record": record}
    if file is not None:
        console_kwargs["file"] = MarkerStrippingTextIO(file) if strip_markers else file
    elif strip_markers:
        console_kwargs["file"] = MarkerStrippingTextIO(sys.stdout)

    if is_ci_render_context():
        width = detect_rich_console_width()
        os.environ.setdefault("COLUMNS", str(width))
        console_kwargs.update(
            force_terminal=True,
            color_system="truecolor",
            width=width,
        )

    return Console(**console_kwargs)
