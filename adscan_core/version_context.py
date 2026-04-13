"""Centralized version context resolution for ADscan.

This module is the single source of truth for version discovery across:
- host launcher processes
- in-container runtime processes
- telemetry payload builders
"""

from __future__ import annotations

import functools
import json
import os
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import re
from typing import Any

from adscan_core.path_utils import get_adscan_home, get_effective_user_home

VERSION = "7.0.0"
_LAUNCHER_VERSION_ENV = "ADSCAN_LAUNCHER_VERSION"
_RUNTIME_IMAGE_ENV = "ADSCAN_RUNTIME_IMAGE"
_SOURCE_TREE_VERSION_RE = re.compile(
    r'(?ms)^\[project\].*?^\s*version\s*=\s*"([^"]+)"\s*$'
)


def _print_info_debug(message: str) -> None:
    """Best-effort debug logging without introducing hard runtime coupling."""
    try:
        from adscan_core.rich_output import print_info_debug

        print_info_debug(message)
    except Exception:
        return


def detect_installer() -> str:
    """Detect installation method: ``pip`` or ``pipx``."""
    pipx_home = Path(
        os.environ.get("PIPX_HOME", str(get_effective_user_home() / ".local" / "pipx"))
    )
    pipx_venvs = pipx_home / "venvs"
    exe_path = Path(os.path.realpath(os.sys.executable))
    if pipx_venvs in exe_path.parents:
        return "pipx"
    if "pipx" in str(exe_path).lower():
        return "pipx"
    if _resolve_source_tree_version() is not None:
        if (
            os.environ.get("UV_ACTIVE")
            or os.environ.get("UV_PROJECT_ENVIRONMENT")
            or os.environ.get("UV_NO_SYNC")
        ):
            return "uv"
        if ".venv" in str(exe_path):
            return "uv"
        return "source_tree"
    return "pip"


@functools.lru_cache(maxsize=1)
def _resolve_source_tree_version() -> str | None:
    """Return the source-tree version from ``pyproject.toml`` when available."""
    candidate_roots = (
        Path.cwd(),
        Path(os.path.realpath(os.sys.executable)).parent,
        Path(__file__).resolve().parent,
    )
    for root in candidate_roots:
        try:
            search_roots = (root, *root.parents)
        except Exception:
            continue
        for candidate in search_roots:
            pyproject = candidate / "pyproject.toml"
            if not pyproject.is_file():
                continue
            if not (candidate / "adscan_core").exists():
                continue
            if not (candidate / "adscan_launcher").exists():
                continue
            try:
                contents = pyproject.read_text(encoding="utf-8")
            except OSError:
                continue
            match = _SOURCE_TREE_VERSION_RE.search(contents)
            if match:
                return str(match.group(1)).strip() or None
    return None


def get_source_tree_version() -> str | None:
    """Return the source-tree version from ``pyproject.toml`` when available."""
    return _resolve_source_tree_version()


@functools.lru_cache(maxsize=1)
def resolve_installed_version_info() -> dict[str, str]:
    """Resolve installed version and source with deterministic fallback order."""
    ver_file = get_adscan_home() / "version"
    installer = detect_installer()
    info: dict[str, str] = {
        "version": VERSION,
        "source": "fallback_constant",
        "detected_installer": installer,
    }

    if installer == "pipx":
        pipx_home = os.environ.get(
            "PIPX_HOME", str(get_effective_user_home() / ".local" / "pipx")
        )
        pipx_meta = Path(pipx_home) / "venvs" / "adscan" / "pipx_metadata.json"
        if pipx_meta.is_file():
            try:
                data = json.loads(pipx_meta.read_text(encoding="utf-8"))
                ver = data.get("main_package", {}).get("package_version")
                if ver:
                    ver_file.parent.mkdir(parents=True, exist_ok=True)
                    ver_file.write_text(str(ver), encoding="utf-8")
                    info["version"] = str(ver)
                    info["source"] = "pipx_metadata"
                    _print_info_debug(
                        "[version] resolved from pipx metadata "
                        f"({pipx_meta}): {info['version']}"
                    )
                    return info
            except (OSError, json.JSONDecodeError):
                pass

    try:
        pkg_ver = version("adscan")
        ver_file.parent.mkdir(parents=True, exist_ok=True)
        ver_file.write_text(str(pkg_ver), encoding="utf-8")
        info["version"] = str(pkg_ver)
        info["source"] = "package_metadata"
        _print_info_debug(f"[version] resolved from package metadata: {info['version']}")
        return info
    except PackageNotFoundError:
        pass

    source_tree_version = _resolve_source_tree_version()
    if source_tree_version:
        info["version"] = source_tree_version
        info["source"] = "source_tree_pyproject"
        _print_info_debug(
            "[version] resolved from source tree pyproject.toml: "
            f"{info['version']}"
        )
        return info

    if ver_file.is_file():
        persisted = ver_file.read_text(encoding="utf-8").strip()
        if persisted:
            info["version"] = persisted
            info["source"] = "version_file"
            _print_info_debug(
                f"[version] resolved from persisted version file: {info['version']}"
            )
            return info

    _print_info_debug(
        f"[version] falling back to embedded VERSION constant: {info['version']}"
    )
    return info


def get_installed_version() -> str:
    """Return installed ADscan version string."""
    return str(resolve_installed_version_info().get("version") or VERSION)


@functools.lru_cache(maxsize=1)
def get_telemetry_version_fields() -> dict[str, Any]:
    """Return normalized version fields for telemetry payloads and debug logs."""
    resolved = resolve_installed_version_info()
    installed_version = str(resolved.get("version") or VERSION)
    version_source = str(resolved.get("source") or "fallback_constant")
    detected_installer = str(resolved.get("detected_installer") or "unknown")

    in_container_runtime = os.getenv("ADSCAN_CONTAINER_RUNTIME") == "1"
    fields: dict[str, Any] = {
        "adscan_version": installed_version,
        "adscan_version_source": version_source,
        "adscan_detected_installer": detected_installer,
        "version_context_mode": (
            "container_runtime" if in_container_runtime else "host_process"
        ),
    }

    runtime_image = (os.getenv(_RUNTIME_IMAGE_ENV) or "").strip()
    if runtime_image:
        fields["runtime_image"] = runtime_image

    if in_container_runtime:
        fields["runtime_version"] = installed_version
        fields["runtime_version_source"] = version_source
        launcher_version = (os.getenv(_LAUNCHER_VERSION_ENV) or "").strip()
        if launcher_version:
            fields["launcher_version"] = launcher_version
            fields["launcher_version_source"] = f"env:{_LAUNCHER_VERSION_ENV}"
    else:
        fields["launcher_version"] = installed_version
        fields["launcher_version_source"] = version_source

    _print_info_debug(
        "[version] telemetry fields: "
        f"adscan_version={fields.get('adscan_version')!r}, "
        f"adscan_version_source={fields.get('adscan_version_source')!r}, "
        f"launcher_version={fields.get('launcher_version')!r}, "
        f"runtime_version={fields.get('runtime_version')!r}, "
        f"runtime_image={fields.get('runtime_image')!r}, "
        f"installer={fields.get('adscan_detected_installer')!r}, "
        f"mode={fields.get('version_context_mode')!r}"
    )
    return fields


def clear_version_context_caches() -> None:
    """Clear internal LRU caches (test helper)."""
    resolve_installed_version_info.cache_clear()
    get_telemetry_version_fields.cache_clear()
    _resolve_source_tree_version.cache_clear()


__all__ = [
    "VERSION",
    "detect_installer",
    "resolve_installed_version_info",
    "get_installed_version",
    "get_source_tree_version",
    "get_telemetry_version_fields",
    "clear_version_context_caches",
]
