"""Centralized version helpers for ADscan.

This module is shared by both:
- the open-source launcher (PyPI)
- the runtime CLI inside the Docker image

It intentionally delegates version resolution to `adscan_core.telemetry` because
that logic already handles:
- pipx metadata
- package metadata
- fallback version file under `~/.adscan/`
- fallback VERSION constant
"""

from __future__ import annotations

from adscan_core import telemetry
from adscan_core.rich_output import print_info_debug


def get_version() -> str:
    """Return the installed ADscan version."""
    version = telemetry.get_installed_version()
    if version == telemetry.VERSION:
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
