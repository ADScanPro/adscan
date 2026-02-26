"""Utility helpers for working with textual output."""

from __future__ import annotations

import re

_ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]")


def strip_ansi_codes(text: str) -> str:
    """Remove ANSI escape sequences from the provided text string."""
    if not text:
        return text
    return _ANSI_ESCAPE_RE.sub("", text)


def strip_control_characters(text: str) -> str:
    """Remove non-printable ASCII control characters from text.

    This preserves common whitespace such as newlines and tabs, but removes
    characters that can make "empty" output appear non-empty (e.g. null bytes).
    """
    if not text:
        return text
    return _CONTROL_CHARS_RE.sub("", text)


def normalize_cli_output(text: str) -> str:
    """Normalize CLI output for content checks and parsing."""
    return strip_control_characters(strip_ansi_codes(text or ""))
