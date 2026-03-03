"""Centralized version helpers for ADscan.

Canonical version discovery lives in ``adscan_core.telemetry`` (installer/runtime
aware fallback chain + debug traces). This module provides a stable, low-noise
API for UX/reporting code that needs version strings/tags.
"""

from __future__ import annotations

from typing import Any

from adscan_core.rich_output import print_info_debug
from adscan_core.version_context import VERSION, get_telemetry_version_fields

__all__ = [
    "get_version",
    "get_version_source",
    "get_version_context",
    "get_version_tag",
]


def get_version_context() -> dict[str, Any]:
    """Return normalized version context for current process."""
    return dict(get_telemetry_version_fields() or {})


def get_version_source() -> str:
    """Return the source used to resolve ``get_version()``."""
    context = get_version_context()
    return str(context.get("adscan_version_source") or "fallback_constant")


def get_version() -> str:
    """Return the installed ADscan version."""
    context = get_version_context()
    version = str(context.get("adscan_version") or VERSION)
    if get_version_source() == "fallback_constant":
        print_info_debug("[version] Using fallback VERSION constant")
    return version


def get_version_tag(license_mode: str | None = None) -> str:
    """Return a version tag including license mode suffix.

    Args:
        license_mode: "LITE" or "PRO".

    Returns:
        Version tag like "4.1.2-lite" or "4.1.2-pro".
    """
    normalized = (license_mode or "LITE").strip().upper()
    if normalized not in {"LITE", "PRO"}:
        normalized = "LITE"
    return f"{get_version()}-{normalized.lower()}"
