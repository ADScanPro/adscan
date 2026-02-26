"""Sensitive marker primitives shared across the codebase.

ADscan uses invisible Unicode marker pairs to tag sensitive values in terminal
output so that telemetry/session-recording sanitization can replace them with
placeholders/pseudonyms before uploading.

This module must stay dependency-light because it is intended to ship in the
open-source PyPI launcher as well as the full runtime image.
"""

from __future__ import annotations

from typing import Dict, Tuple

# Sensitive data markers (invisible to user, used for automatic sanitization).
# IMPORTANT: Keep these stable across versions to avoid breaking deterministic
# sanitization and marker-based parsing in telemetry.
SENSITIVE_MARKERS: Dict[str, Tuple[str, str]] = {
    "user": ("\u200b\u200c", "\u200c\u200b"),
    "domain": ("\u200b\u200d", "\u200d\u200b"),
    "ip": ("\u200b\u2060", "\u2060\u200b"),
    "password": ("\u200c\u200d", "\u200d\u200c"),
    "service": ("\u200c\u2060", "\u2060\u200c"),
    "path": ("\u200d\u2060", "\u2060\u200d"),
    "hostname": ("\u2060\u200d", "\u200d\u2060"),
    # Workspace markers use different zero-width characters (LTR/RTL marks)
    # to avoid overlapping with other marker sequences.
    "workspace": ("\u200e\u200f", "\u200f\u200e"),
}

# Passthrough markers (invisible) for non-sensitive values.
PASSTHROUGH_MARKERS: Dict[str, Tuple[str, str]] = {
    "passthrough": (
        "\u2062\u2063",
        "\u2063\u2062",
    ),  # INVISIBLE TIMES + INVISIBLE SEPARATOR
}

# All zero-width characters used by the marker system.
MARKER_CHARS = "\u200b\u200c\u200d\u2060\u200e\u200f"


def strip_sensitive_markers(text: str) -> str:
    """Remove invisible marker characters from a string.

    This is used when preparing Rich exports for post-processing or for
    defensive cleanup before passing strings to subprocesses.
    """
    if not isinstance(text, str):
        return text

    for start, end in SENSITIVE_MARKERS.values():
        text = text.replace(start, "").replace(end, "")
    for start, end in PASSTHROUGH_MARKERS.values():
        text = text.replace(start, "").replace(end, "")

    # Defensive cleanup in case only a partial marker sequence was copied.
    for marker in (
        "\u200b",
        "\u200c",
        "\u200d",
        "\u2060",
        "\u200e",
        "\u200f",
        "\u2062",
        "\u2063",
    ):
        text = text.replace(marker, "")

    return text


def mark_passthrough(value: str) -> str:
    """Wrap a non-sensitive value with invisible passthrough markers."""
    if not value or not isinstance(value, str):
        return value
    start, end = PASSTHROUGH_MARKERS["passthrough"]
    return f"{start}{value}{end}"


def mark_sensitive(value: str, data_type: str) -> str:
    """Wrap a sensitive value with invisible markers for later sanitization."""
    if not value or not isinstance(value, str):
        return value

    # Keep behaviour consistent with the full runtime:
    # treat "hostname" like "domain" to avoid overlapping marker sequences.
    if data_type == "hostname":
        data_type = "domain"

    start, end = SENSITIVE_MARKERS.get(data_type, ("", ""))
    if not start:
        return value
    return f"{start}{value}{end}"
