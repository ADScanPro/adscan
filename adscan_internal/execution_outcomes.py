"""Shared execution outcome helpers for tool runners.

This module centralizes marker conventions and timeout/no-result handling so
all runners can expose consistent behavior and UX.
"""

from __future__ import annotations

import re
import subprocess


TIMEOUT_RETURN_CODE = 124
GENERIC_ERROR_RETURN_CODE = 1

_TIMEOUT_SUFFIX = "_COMMAND_TIMEOUT"
_NO_RESULT_SUFFIX = "_COMMAND_NO_RESULT"


def normalize_tool_name(tool_name: str) -> str:
    """Return uppercase marker-safe tool name."""
    normalized = re.sub(r"[^A-Za-z0-9_]+", "_", str(tool_name or "tool"))
    normalized = normalized.strip("_")
    return (normalized or "TOOL").upper()


def timeout_marker(tool_name: str) -> str:
    """Return standardized timeout marker for a tool."""
    return f"[ADSCAN] {normalize_tool_name(tool_name)}{_TIMEOUT_SUFFIX}"


def no_result_marker(tool_name: str) -> str:
    """Return standardized no-result marker for a tool."""
    return f"[ADSCAN] {normalize_tool_name(tool_name)}{_NO_RESULT_SUFFIX}"


def build_timeout_completed_process(
    command: str | list[str],
    *,
    tool_name: str,
) -> subprocess.CompletedProcess[str]:
    """Build a synthetic timeout CompletedProcess."""
    return subprocess.CompletedProcess(
        args=command,
        returncode=TIMEOUT_RETURN_CODE,
        stdout="",
        stderr=f"{timeout_marker(tool_name)}\n",
    )


def build_no_result_completed_process(
    command: str | list[str],
    *,
    tool_name: str,
) -> subprocess.CompletedProcess[str]:
    """Build a synthetic no-result CompletedProcess."""
    return subprocess.CompletedProcess(
        args=command,
        returncode=GENERIC_ERROR_RETURN_CODE,
        stdout="",
        stderr=f"{no_result_marker(tool_name)}\n",
    )


def output_has_timeout_marker(output: str, *, tool_name: str | None = None) -> bool:
    """Return True when output contains a timeout marker.

    Args:
        output: Combined stdout/stderr text.
        tool_name: Optional tool filter. When provided, only that marker matches.
    """
    if not output:
        return False
    if tool_name:
        return timeout_marker(tool_name) in output
    return _TIMEOUT_SUFFIX in output


def result_is_timeout(
    result: subprocess.CompletedProcess[str] | None, *, tool_name: str | None = None
) -> bool:
    """Return True when a completed process represents a timeout outcome."""
    if not isinstance(result, subprocess.CompletedProcess):
        return False
    if int(getattr(result, "returncode", 1)) == TIMEOUT_RETURN_CODE:
        return True
    combined = f"{result.stdout or ''}\n{result.stderr or ''}"
    return output_has_timeout_marker(combined, tool_name=tool_name)

