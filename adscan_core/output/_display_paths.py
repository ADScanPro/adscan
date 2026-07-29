"""Container ↔ host path translation for user-facing output.

ADscan ships every command inside a Docker container that bind-mounts the
user's ``~/.adscan/`` directory to ``/opt/adscan/`` inside the container.
Container code legitimately refers to paths under ``/opt/adscan/`` (that is
where the files physically live at runtime), but every string the user reads
in the TUI must show the HOST path — otherwise they try ``cat /opt/adscan/...``
from their own shell and get "No such file or directory".

This module is the single source of truth for that rewrite. It handles the
three shapes output helpers actually receive:

* ``str`` — plain or Rich-markup message
* ``rich.text.Text`` — a styled message; spans are re-mapped so styling still
  covers the same words after the substitution shortens the path
* ``rich.console.Group`` / ``list`` / ``tuple`` — recursed element by element

Anything else (Table, Panel, Progress, arbitrary renderables) passes through
untouched: walking every Rich renderable is fragile, and a caller that builds
one with a container path inside should translate the value itself with
``adscan_internal.services.host_open.display_host_path``.

The substitution runs only when ``ADSCAN_CONTAINER_RUNTIME=1`` is set. Outside
the container (dev mode, host process) the input passes through unchanged.
"""

from __future__ import annotations

import os
import re
from typing import Any

from rich.console import Group
from rich.text import Text

__all__ = (
    "translate_paths_for_display",
    "translate_items_for_display",
)


# The regex anchors on a boundary character after ``/opt/adscan`` so that
# sibling paths like ``/opt/adscan-src`` (the source mount) are NOT rewritten —
# they are container-internal and never user-facing.
_CONTAINER_DISPLAY_PATH_RE = re.compile(r"/opt/adscan(?=[/\s\"'`,;:)\]}]|$)")
_CONTAINER_ADSCAN_ROOT = "/opt/adscan"
_HOST_DISPLAY_PATH_REPLACEMENT = "~/.adscan"
_LENGTH_DELTA = len(_HOST_DISPLAY_PATH_REPLACEMENT) - len(_CONTAINER_ADSCAN_ROOT)


def _is_container_runtime() -> bool:
    return os.environ.get("ADSCAN_CONTAINER_RUNTIME") == "1"


def _translate_string(value: str) -> str:
    return _CONTAINER_DISPLAY_PATH_RE.sub(_HOST_DISPLAY_PATH_REPLACEMENT, value)


def _translate_rich_text(value: Text) -> Text:
    """Translate a ``Text`` object, keeping its styling on the same words.

    Each substitution shortens the string, so every span offset that sits
    after a match has to shift left by the same amount. Without the re-map the
    styling would drift right by three characters per path in the message.
    """
    plain = value.plain
    matches = list(_CONTAINER_DISPLAY_PATH_RE.finditer(plain))
    if not matches:
        return value

    new_plain = _translate_string(plain)

    def _remap(offset: int) -> int:
        shift = 0
        for match in matches:
            if match.end() <= offset:
                shift += _LENGTH_DELTA
            elif match.start() < offset:
                # The offset falls INSIDE a rewritten path: clamp it to the
                # start of the replacement rather than into the middle of it.
                return match.start() + shift
            else:
                break
        return offset + shift

    max_offset = len(new_plain)
    spans = []
    for span in value.spans:
        start = min(max(_remap(span.start), 0), max_offset)
        end = min(max(_remap(span.end), 0), max_offset)
        if end > start:
            spans.append(type(span)(start, end, span.style))

    return Text(
        new_plain,
        style=value.style,
        justify=value.justify,
        overflow=value.overflow,
        no_wrap=value.no_wrap,
        end=value.end,
        tab_size=value.tab_size,
        spans=spans,
    )


def translate_paths_for_display(value: Any) -> Any:
    """Rewrite container paths to host paths for display.

    Returns a translated copy; the caller's object is never mutated. Values of
    an unsupported type are returned as-is (identity preserved).
    """
    if not _is_container_runtime():
        return value

    if isinstance(value, str):
        return _translate_string(value)
    if isinstance(value, Text):
        return _translate_rich_text(value)
    if isinstance(value, Group):
        renderables = [translate_paths_for_display(r) for r in value.renderables]
        return Group(*renderables)
    if isinstance(value, list):
        return [translate_paths_for_display(item) for item in value]
    if isinstance(value, tuple):
        return tuple(translate_paths_for_display(item) for item in value)
    return value


def translate_items_for_display(items: Any) -> Any:
    """Translate every entry in an ``items`` list for display."""
    if items is None:
        return items
    return [translate_paths_for_display(item) for item in items]
