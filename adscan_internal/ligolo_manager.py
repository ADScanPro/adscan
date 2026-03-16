"""Helpers for locating and resolving pinned ligolo-ng binaries.

The first integration step keeps ligolo-ng as a managed external dependency.
This module resolves the correct release asset for the local proxy and the
remote agent without forking upstream or hardcoding URLs in multiple places.
"""

from __future__ import annotations

import os
from pathlib import Path
import platform
from typing import Final, Optional

from adscan_internal.path_utils import expand_effective_user_path, get_adscan_home

LIGOLO_NG_VERSION: Final[str] = "0.8.3"
LIGOLO_PROXY_ENV_VAR: Final[str] = "ADSCAN_LIGOLO_PROXY_PATH"
LIGOLO_AGENT_ENV_VAR: Final[str] = "ADSCAN_LIGOLO_AGENT_PATH"

_SUPPORTED_PROXY_TARGETS: Final[set[tuple[str, str]]] = {
    ("linux", "amd64"),
    ("linux", "arm64"),
    ("darwin", "amd64"),
    ("darwin", "arm64"),
    ("freebsd", "amd64"),
    ("freebsd", "arm64"),
    ("openbsd", "amd64"),
    ("openbsd", "arm64"),
    ("windows", "amd64"),
    ("windows", "arm64"),
}

_SUPPORTED_AGENT_TARGETS: Final[set[tuple[str, str]]] = {
    *{
        (os_name, arch)
        for os_name in ("linux", "darwin", "freebsd", "openbsd")
        for arch in ("amd64", "arm64", "armv6", "armv7")
    },
    ("windows", "amd64"),
    ("windows", "arm64"),
    ("windows", "armv6"),
    ("windows", "armv7"),
}


def normalize_ligolo_os(target_os: str) -> str:
    """Normalize one OS label to the naming used by ligolo-ng assets."""
    normalized = str(target_os or "").strip().lower()
    aliases = {
        "macos": "darwin",
        "osx": "darwin",
        "windows_nt": "windows",
    }
    return aliases.get(normalized, normalized)


def normalize_ligolo_arch(arch: str) -> str:
    """Normalize one architecture label to the naming used by ligolo-ng assets."""
    normalized = str(arch or "").strip().lower()
    aliases = {
        "x86_64": "amd64",
        "x64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
        "armv6l": "armv6",
        "armv7l": "armv7",
    }
    return aliases.get(normalized, normalized)


def _default_ligolo_binary_path(*, component: str, target_os: str, arch: str) -> Path:
    """Return the default on-disk location for one ligolo-ng binary."""
    base_dir = get_adscan_home() / "tools" / "ligolo-ng" / component.lower()
    subdir = f"{normalize_ligolo_os(target_os)}-{normalize_ligolo_arch(arch)}"
    binary_name = "proxy"
    if component.lower() == "agent":
        binary_name = "agent"
    if normalize_ligolo_os(target_os) == "windows":
        binary_name += ".exe"
    return base_dir / subdir / binary_name


def get_current_ligolo_proxy_target() -> tuple[str, str]:
    """Return the normalized OS/arch tuple for the local ligolo-ng proxy."""
    return (
        normalize_ligolo_os(platform.system()),
        normalize_ligolo_arch(platform.machine()),
    )


def get_ligolo_release_asset_name(*, component: str, target_os: str, arch: str) -> str:
    """Return the upstream ligolo-ng release asset name for one component/target."""
    normalized_component = str(component or "").strip().lower()
    normalized_os = normalize_ligolo_os(target_os)
    normalized_arch = normalize_ligolo_arch(arch)
    key = (normalized_os, normalized_arch)
    if normalized_component == "proxy":
        if key not in _SUPPORTED_PROXY_TARGETS:
            raise ValueError(f"Unsupported ligolo-ng proxy target: {normalized_os}/{normalized_arch}")
        extension = "zip" if normalized_os == "windows" else "tar.gz"
        return f"ligolo-ng_proxy_{LIGOLO_NG_VERSION}_{normalized_os}_{normalized_arch}.{extension}"
    if normalized_component == "agent":
        if key not in _SUPPORTED_AGENT_TARGETS:
            raise ValueError(f"Unsupported ligolo-ng agent target: {normalized_os}/{normalized_arch}")
        extension = "zip" if normalized_os == "windows" else "tar.gz"
        return f"ligolo-ng_agent_{LIGOLO_NG_VERSION}_{normalized_os}_{normalized_arch}.{extension}"
    raise ValueError(f"Unsupported ligolo-ng component: {component}")


def get_ligolo_release_download_url(*, component: str, target_os: str, arch: str) -> str:
    """Return the pinned GitHub release URL for one ligolo-ng asset."""
    asset_name = get_ligolo_release_asset_name(
        component=component,
        target_os=target_os,
        arch=arch,
    )
    return (
        "https://github.com/nicocha30/ligolo-ng/releases/download/"
        f"v{LIGOLO_NG_VERSION}/{asset_name}"
    )


def get_ligolo_checksums_url() -> str:
    """Return the pinned checksum manifest URL for the selected ligolo-ng release."""
    return (
        "https://github.com/nicocha30/ligolo-ng/releases/download/"
        f"v{LIGOLO_NG_VERSION}/ligolo-ng_{LIGOLO_NG_VERSION}_checksums.txt"
    )


def _resolve_env_override(env_var: str) -> Optional[Path]:
    """Return one existing override path from the environment, if any."""
    env_path = os.getenv(env_var)
    if not env_path:
        return None
    candidate = Path(expand_effective_user_path(env_path))
    if candidate.is_file():
        return candidate
    return None


def get_ligolo_proxy_local_path(
    *,
    target_os: str = "linux",
    arch: str = "amd64",
) -> Optional[Path]:
    """Return the local filesystem path to the pinned ligolo-ng proxy binary."""
    env_candidate = _resolve_env_override(LIGOLO_PROXY_ENV_VAR)
    if env_candidate is not None:
        return env_candidate
    candidate = _default_ligolo_binary_path(
        component="proxy",
        target_os=target_os,
        arch=arch,
    )
    if candidate.is_file():
        return candidate
    return None


def get_ligolo_agent_local_path(
    *,
    target_os: str = "windows",
    arch: str = "amd64",
) -> Optional[Path]:
    """Return the local filesystem path to the pinned ligolo-ng agent binary."""
    env_candidate = _resolve_env_override(LIGOLO_AGENT_ENV_VAR)
    if env_candidate is not None:
        return env_candidate
    candidate = _default_ligolo_binary_path(
        component="agent",
        target_os=target_os,
        arch=arch,
    )
    if candidate.is_file():
        return candidate
    return None


__all__ = [
    "LIGOLO_AGENT_ENV_VAR",
    "LIGOLO_NG_VERSION",
    "LIGOLO_PROXY_ENV_VAR",
    "get_ligolo_agent_local_path",
    "get_ligolo_checksums_url",
    "get_current_ligolo_proxy_target",
    "get_ligolo_proxy_local_path",
    "get_ligolo_release_asset_name",
    "get_ligolo_release_download_url",
    "normalize_ligolo_arch",
    "normalize_ligolo_os",
]
