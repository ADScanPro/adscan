"""High-level Docker-mode commands for ADscan.

This module implements a minimal Docker-based installation and execution path:
  - `adscan install`: pulls the ADscan image
  - `adscan check`: verifies docker + image
  - `adscan start`: runs ADscan inside the container

The legacy host-based installer remains in `adscan.py`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import socket
import re
import secrets
import time
from pathlib import Path
from typing import Any

from rich.prompt import Confirm

from adscan_launcher import telemetry
from adscan_launcher import runtime_session as _runtime_session
from adscan_launcher.docker_pull_diagnostics import (
    PullFailureDiagnosis,
    consume_last_failure,
    get_presentation,
    peek_last_failure,
    record_last_failure,
)
from adscan_launcher.docker_runtime import (
    DockerRunConfig,
    build_adscan_run_command,
    probe_and_warn_reduced_runtime,
    docker_access_denied,
    docker_available,
    docker_needs_sudo,
    ensure_image_pulled,
    image_exists,
    is_docker_env,
    run_docker,
    shell_quote_cmd,
)
from adscan_launcher.docker_status import (
    ensure_docker_daemon_running as _ensure_docker_daemon_running_internal,
    is_docker_daemon_running as _is_docker_daemon_running_internal,
)
from adscan_launcher.output import (
    confirm_ask,
    mark_sensitive,
    print_exception,
    print_error,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_instruction,
    print_panel,
    print_success,
    print_success_verbose,
    print_warning,
)
from adscan_launcher.paths import (
    get_adscan_home_dir,
    get_logs_dir,
    get_run_dir,
    get_state_dir,
    get_workspaces_dir,
)


DEFAULT_DOCKER_IMAGE = "adscan/adscan-lite:latest"
DEFAULT_DEV_DOCKER_IMAGE = "adscan/adscan-lite-dev:edge"
LEGACY_DEFAULT_DOCKER_IMAGE = "adscan/adscan:latest"
LEGACY_DEFAULT_DEV_DOCKER_IMAGE = "adscan/adscan-dev:edge"
ADSCAN_RUNTIME_LICENSE_MODE_ENV = "ADSCAN_RUNTIME_LICENSE_MODE"
DEFAULT_HOST_HELPER_SOCKET_NAME = "host-helper.sock"
_DOCKER_RUN_HELP_HAS_GPUS_RE = re.compile(r"\s--gpus\b", re.IGNORECASE)
_DOCKER_INSTALL_DOCS_URL = "https://www.adscanpro.com/docs/getting-started/installation"
_ALLOW_PODMAN_DOCKER_API_ENV = "ADSCAN_ALLOW_PODMAN_DOCKER_API"
_ALLOW_LEGACY_IMAGE_FALLBACK_ENV = "ADSCAN_ALLOW_LEGACY_IMAGE_FALLBACK"
_HOST_HELPER_TROUBLESHOOTING_DOCS_URL = (
    "https://www.adscanpro.com/docs/guides/troubleshooting#host-helper-docker-mode"
)
_DOCKER_SERVICE_UNIT_MISSING_RE = re.compile(
    r"(unit\s+docker\.service\s+could\s+not\s+be\s+found|could\s+not\s+find\s+the\s+requested\s+service\s+docker)",
    re.IGNORECASE,
)
# Re-exported from adscan_core so callers that already imported it from
# this module keep working; the canonical value lives in
# adscan_core/host_resource_thresholds.py so launcher and runtime
# (adscan_internal) cannot drift.
from adscan_core.host_resource_thresholds import (  # noqa: E402
    MIN_DOCKER_INSTALL_FREE_GB as _MIN_DOCKER_INSTALL_FREE_GB,
)
from adscan_core.interaction import is_non_interactive  # noqa: E402

_DEFAULT_DOCKER_PULL_TIMEOUT_SECONDS = 3600
_LOW_MEMORY_HARD_BLOCK_THRESHOLD_GB = 1.0
_LOW_MEMORY_WARNING_THRESHOLD_GB = 1.5
_EPHEMERAL_CONTAINER_SHARED_TOKEN: str | None = None
_LEGACY_IMAGE_WARNING_SHOWN = False
_DOCKER_RUNTIME_CONTEXT_EMITTED = False
_DOCKER_HOST_RESOURCES_CONTEXT_EMITTED = False
_DOCKER_HOST_ENGINE_OVERRIDE_APPLIED = False
_DOCKER_HOST_ENGINE_OVERRIDE_DECLINED = False
_DOCKER_CLI_RUNTIME_FLAVOR_CACHE: tuple[str, str] | None = None
_DOCKER_PULL_DNS_PREFLIGHT_HOST = "registry-1.docker.io"
_DOCKER_PULL_NETWORK_PREFLIGHT_TIMEOUT_SECONDS = 2.0


def _infer_runtime_license_mode_from_image(image: str) -> str | None:
    """Best-effort runtime license inference from the Docker image reference.

    This is only a compatibility fallback for older runtime images that were
    published before the explicit runtime license environment variable existed.

    Args:
        image: Docker image reference selected by the launcher.

    Returns:
        ``"PRO"`` or ``"LITE"`` when the image name is unambiguous, otherwise
        ``None`` so the runtime can fall back to its own default.
    """
    normalized_image = _strip_default_docker_io_prefix(str(image or "")).strip().lower()
    if not normalized_image:
        return None
    if "adscan-pro" in normalized_image:
        return "PRO"
    if "adscan-lite" in normalized_image:
        return "LITE"
    return None


def _build_runtime_license_env(image: str) -> tuple[tuple[str, str], ...]:
    """Return explicit runtime license env overrides for Docker execution.

    Preference order:
    1. Explicit host override via ``ADSCAN_RUNTIME_LICENSE_MODE``.
    2. Image-name inference for backward compatibility with older images.
    3. No override; let the runtime resolve its own default.

    Args:
        image: Docker image reference selected by the launcher.

    Returns:
        Zero or one ``(key, value)`` tuples suitable for ``DockerRunConfig``.
    """
    explicit_license_mode = (
        str(os.getenv(ADSCAN_RUNTIME_LICENSE_MODE_ENV, "")).strip().upper()
    )
    if explicit_license_mode in {"LITE", "PRO"}:
        return ((ADSCAN_RUNTIME_LICENSE_MODE_ENV, explicit_license_mode),)

    inferred_license_mode = _infer_runtime_license_mode_from_image(image)
    if inferred_license_mode is None:
        return ()
    return ((ADSCAN_RUNTIME_LICENSE_MODE_ENV, inferred_license_mode),)


def _extract_workspace_from_passthrough_args(adscan_args: list[str]) -> str | None:
    """Best-effort extraction of `--workspace/-w` from passthrough args."""
    args = list(adscan_args or [])
    for index, value in enumerate(args):
        if value in {"--workspace", "-w"} and index + 1 < len(args):
            workspace_name = str(args[index + 1] or "").strip()
            return workspace_name or None
        if value.startswith("--workspace="):
            workspace_name = value.split("=", 1)[1].strip()
            return workspace_name or None
    return None


def _print_workspace_lock_conflict(
    *,
    command_name: str,
    workspace_name: str,
    metadata: dict[str, Any],
) -> None:
    """Render a premium UX panel when a workspace lock is contended."""
    active_command = str(metadata.get("command_name", "") or "").strip() or "unknown"
    active_pid = str(metadata.get("pid", "") or "").strip() or "unknown"
    started_at = str(metadata.get("started_at_utc", "") or "").strip() or "unknown"
    active_home = str(metadata.get("adscan_home", "") or "").strip() or str(
        get_adscan_home_dir()
    )

    lines = [
        f"Workspace '{mark_sensitive(workspace_name, 'workspace')}' is in use by another ADscan session.",
        "",
        f"Active command: {mark_sensitive(active_command, 'detail')}",
        f"Active PID: {mark_sensitive(active_pid, 'detail')}",
        f"Started at (UTC): {mark_sensitive(started_at, 'detail')}",
        f"ADSCAN_HOME: {mark_sensitive(active_home, 'path')}",
        "",
        "Two ADscan sessions cannot share the same workspace because workspace files, reports,",
        "and credentials would race. A different workspace name runs concurrently with no conflict.",
    ]
    print_panel(
        "\n".join(lines),
        title="Workspace Already In Use",
        border_style="yellow",
    )
    print_instruction(
        f"Pick another workspace name (e.g. --workspace {workspace_name}-2)"
    )
    print_instruction("Or wait for the active session to exit and retry.")


def _print_install_lock_conflict(
    *,
    command_name: str,
    metadata: dict[str, Any],
) -> None:
    """Render a UX panel when ``adscan install``/``update`` is contended."""
    active_command = str(metadata.get("command_name", "") or "").strip() or "unknown"
    active_pid = str(metadata.get("pid", "") or "").strip() or "unknown"
    started_at = str(metadata.get("started_at_utc", "") or "").strip() or "unknown"
    lines = [
        "Another ADscan install/update is already running.",
        "",
        f"Active command: {mark_sensitive(active_command, 'detail')}",
        f"Active PID: {mark_sensitive(active_pid, 'detail')}",
        f"Started at (UTC): {mark_sensitive(started_at, 'detail')}",
        "",
        "Concurrent Docker pulls of the same image are serialised to avoid clobbering each other.",
    ]
    print_panel(
        "\n".join(lines),
        title="Install Already Running",
        border_style="yellow",
    )
    print_instruction("Wait for the active install/update to finish, then retry.")


_LOCK_CONTENDED: Any = object()
"""Sentinel returned by lock-acquire helpers when contended.

Distinct from ``None`` so callers disambiguate "another launcher holds
this lock — must abort" from "no lock was needed for this command".
"""


def _acquire_workspace_lock_or_warn(
    *,
    command_name: str,
    workspace_name: str,
) -> "_runtime_session.LockHandle | Any | None":
    """Acquire the per-workspace lock or render a conflict panel.

    Returns:
        * :class:`_runtime_session.LockHandle` on success.
        * :data:`_LOCK_CONTENDED` when another launcher holds the same
          workspace — caller must abort with a non-zero exit.
        * ``None`` when ``workspace_name`` is empty — no lock is needed
          and the caller may continue.
    """
    if not _runtime_session.normalize_workspace_name(workspace_name):
        return None
    handle = _runtime_session.acquire_workspace_lock(
        workspace_name, command_name=command_name
    )
    if handle is not None:
        return handle

    from adscan_launcher.runtime_session import (  # noqa: PLC0415
        _workspace_lock_path,
    )

    lock_path = _workspace_lock_path(workspace_name)
    metadata = _runtime_session.read_lock_metadata(lock_path)
    telemetry.capture(
        "docker_workspace_lock_blocked",
        {
            "command_name": str(command_name or "").strip() or "unknown",
            "owner_command_name": str(metadata.get("command_name", "") or "").strip()
            or "unknown",
            "owner_pid": str(metadata.get("pid", "") or "").strip() or "unknown",
        },
    )
    print_info_debug(
        "[runtime-lock] workspace conflict: "
        f"workspace={mark_sensitive(workspace_name, 'workspace')} "
        f"path={mark_sensitive(str(lock_path), 'path')} "
        f"owner_pid={mark_sensitive(str(metadata.get('pid', 'unknown')), 'detail')}"
    )
    _print_workspace_lock_conflict(
        command_name=command_name,
        workspace_name=workspace_name,
        metadata=metadata,
    )
    return _LOCK_CONTENDED


def _acquire_install_lock_or_warn(
    *,
    command_name: str,
) -> "_runtime_session.LockHandle | None":
    """Acquire the install lock or render a conflict panel.

    Returns the lock handle on success or ``None`` when contended (panel
    already rendered — caller must abort).
    """
    handle = _runtime_session.acquire_install_lock(command_name=command_name)
    if handle is not None:
        return handle

    lock_path = _runtime_session.get_locks_dir() / "install.lock"
    metadata = _runtime_session.read_lock_metadata(lock_path)
    telemetry.capture(
        "docker_install_lock_blocked",
        {
            "command_name": str(command_name or "").strip() or "unknown",
            "owner_command_name": str(metadata.get("command_name", "") or "").strip()
            or "unknown",
            "owner_pid": str(metadata.get("pid", "") or "").strip() or "unknown",
        },
    )
    _print_install_lock_conflict(command_name=command_name, metadata=metadata)
    return None


class _RuntimeAcquisition:
    """Bundle of resources held by an active launcher invocation.

    Each docker-mode entrypoint mints one of these, populates it as it
    acquires resources (workspace lock, install lock, session directory,
    resolver-IP lock, host-helper subprocess), and unconditionally calls
    :func:`_release_runtime_acquisition` from its ``finally`` block.

    Holders are released in reverse-of-acquire order so the host helper
    is stopped before its socket directory is removed.
    """

    __slots__ = (
        "session_dir",
        "workspace_lock",
        "install_lock",
        "resolver_ip_lock",
        "helper_proc",
    )

    def __init__(self) -> None:
        self.session_dir: Path | None = None
        self.workspace_lock: _runtime_session.LockHandle | None = None
        self.install_lock: _runtime_session.LockHandle | None = None
        self.resolver_ip_lock: _runtime_session.LockHandle | None = None
        self.helper_proc: subprocess.Popen[str] | None = None


def _release_runtime_acquisition(acq: _RuntimeAcquisition) -> None:
    """Release every resource owned by an acquisition (idempotent, safe in finally)."""
    if acq.helper_proc is not None:
        try:
            _stop_host_helper(acq.helper_proc)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
        acq.helper_proc = None

    for handle_attr in ("resolver_ip_lock", "install_lock", "workspace_lock"):
        handle = getattr(acq, handle_attr, None)
        if handle is not None:
            _runtime_session.release_lock(handle)
            setattr(acq, handle_attr, None)

    if acq.session_dir is not None:
        _runtime_session.cleanup_session_dir(acq.session_dir)
        acq.session_dir = None


def _prepare_runtime_session_dir(*, command_name: str) -> Path:
    """Create a fresh per-launcher session dir, sweeping stale neighbours first."""
    try:
        _runtime_session.cleanup_stale_session_dirs()
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[runtime-session] stale-cleanup failed: {mark_sensitive(str(exc), 'error')}"
        )
    return _runtime_session.create_session_dir(command_name=command_name)


def _maybe_warn_about_slow_network_before_pull(
    *, image: str, pull_timeout: int | None
) -> bool:
    """Warn the user that Docker pulls may be slow on VPNs/proxies.

    This is intentionally shown only in interactive contexts to avoid noisy CI logs.

    Returns:
        True when install should continue, False when the operator aborts.
    """
    if os.getenv("ADSCAN_NONINTERACTIVE", "").strip() == "1":
        return True
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return True

    timeout_label = "disabled" if pull_timeout is None else f"{pull_timeout}s"
    lines = [
        "This step downloads multiple GB of container images and may take a while.",
        "VPNs / proxies / flaky Wi-Fi can throttle or stall Docker pulls.",
        "If possible, run the installation on a faster connection (or temporarily outside the VPN).",
        f"Current pull timeout: {timeout_label}",
        "",
        "Adjust it if needed:",
        f"  adscan install --pull-timeout {max(_DEFAULT_DOCKER_PULL_TIMEOUT_SECONDS, 7200)}",
        "Disable it entirely:",
        "  adscan install --pull-timeout 0",
        "",
        f"Manual pull (to test connectivity): docker pull {image}",
    ]
    print_panel(
        "\n".join(lines),
        title="Large Docker Download",
        border_style="yellow",
    )
    return bool(
        Confirm.ask(
            "Continue with Docker image download now?",
            default=True,
        )
    )


def _normalize_pull_timeout_seconds(value: int | None) -> int | None:
    """Normalize a user-provided pull timeout.

    Args:
        value: Timeout in seconds. `0` disables the timeout. `None` uses the default.

    Returns:
        Timeout in seconds, or None when disabled.
    """
    if value is None:
        return _DEFAULT_DOCKER_PULL_TIMEOUT_SECONDS
    if value == 0:
        return None
    if value < 0:
        print_warning(
            f"Invalid --pull-timeout value ({value}). Using default "
            f"{_DEFAULT_DOCKER_PULL_TIMEOUT_SECONDS}s."
        )
        return _DEFAULT_DOCKER_PULL_TIMEOUT_SECONDS
    return value


def normalize_pull_timeout_seconds(value: int | None) -> int | None:
    """Public wrapper for normalizing Docker pull timeouts.

    This stays public because multiple host-side entrypoints (launcher CLI,
    update manager, Docker orchestration) need consistent semantics:
    - `None` uses the default.
    - `0` disables the timeout (no abort).
    - Negative values fall back to default.
    """

    return _normalize_pull_timeout_seconds(value)


def _get_free_disk_bytes(path: Path) -> int:
    """Return free disk space in bytes for the filesystem containing `path`."""
    usage = shutil.disk_usage(path)
    return int(usage.free)


def _parse_memavailable_bytes(meminfo_text: str) -> int | None:
    """Parse `MemAvailable` from `/proc/meminfo` content.

    Returns bytes when the key is present and valid, otherwise ``None``.
    """
    for raw_line in str(meminfo_text or "").splitlines():
        line = raw_line.strip()
        if not line.startswith("MemAvailable:"):
            continue
        parts = line.split()
        if len(parts) < 2:
            return None
        try:
            # `/proc/meminfo` reports kB.
            return int(parts[1]) * 1024
        except ValueError:
            return None
    return None


def _get_free_memory_bytes() -> int:
    """Return available system memory in bytes (best effort)."""
    meminfo_path = Path("/proc/meminfo")
    try:
        if meminfo_path.is_file():
            parsed = _parse_memavailable_bytes(
                meminfo_path.read_text(encoding="utf-8", errors="ignore")
            )
            if parsed is not None:
                return parsed
    except OSError:
        pass

    try:
        page_size = os.sysconf("SC_PAGE_SIZE")
        avail_pages = os.sysconf("SC_AVPHYS_PAGES")
        return int(page_size * avail_pages)
    except (OSError, ValueError, AttributeError):
        return 0


def _log_install_resource_status(path: Path) -> tuple[float, float]:
    """Return free disk and memory in GB for install preflight checks."""
    free_disk_bytes = _get_free_disk_bytes(path)
    free_mem_bytes = _get_free_memory_bytes()
    free_disk_gb = free_disk_bytes / (1024**3)
    free_mem_gb = free_mem_bytes / (1024**3)
    return free_disk_gb, free_mem_gb


def _get_docker_storage_path() -> Path:
    """Return best-effort path for Docker storage."""
    docker_path = Path("/var/lib/docker")
    if docker_path.exists():
        return docker_path
    return get_adscan_home_dir()


def _get_docker_image_candidates() -> list[str]:
    """Return Docker image candidates in priority order.

    Order:
    1. Explicit `ADSCAN_DOCKER_IMAGE` (single candidate, no fallback)
    2. New default naming by channel (`*-lite` / `*-lite-dev`)
    3. Legacy naming fallback (`adscan/adscan*`) only when explicitly enabled
       via `ADSCAN_ALLOW_LEGACY_IMAGE_FALLBACK=1`.
    """
    explicit = os.getenv("ADSCAN_DOCKER_IMAGE", "").strip()
    if explicit:
        return [explicit]

    allow_legacy_fallback = str(
        os.getenv(_ALLOW_LEGACY_IMAGE_FALLBACK_ENV, "")
    ).strip().lower() in ("1", "true", "yes", "on")
    channel = os.getenv("ADSCAN_DOCKER_CHANNEL", "").strip().lower()
    if channel == "dev":
        if allow_legacy_fallback:
            return [DEFAULT_DEV_DOCKER_IMAGE, LEGACY_DEFAULT_DEV_DOCKER_IMAGE]
        return [DEFAULT_DEV_DOCKER_IMAGE]

    if allow_legacy_fallback:
        return [DEFAULT_DOCKER_IMAGE, LEGACY_DEFAULT_DOCKER_IMAGE]
    return [DEFAULT_DOCKER_IMAGE]


def _image_reference_has_registry(image: str) -> bool:
    """Return True when image ref already includes an explicit registry host."""
    token = str(image or "").strip()
    if not token:
        return False
    head = token.split("/", 1)[0]
    return "." in head or ":" in head or head == "localhost"


def _registry_host_for_image(image: str) -> str:
    """Derive the network registry host for a Docker image reference.

    The launcher runs DNS / connectivity preflights and renders troubleshooting
    hints before pulling. Both must point at the host the daemon will actually
    contact, otherwise (for example) a ``ghcr.io/...`` image would be checked
    against Docker Hub's ``registry-1.docker.io`` — the wrong host.

    Mapping:
      * No explicit registry (Docker Hub short name, e.g. ``adscan/adscan-pro``)
        → ``registry-1.docker.io`` (the Docker Hub registry endpoint; the
        ``docker.io`` namespace alias resolves there).
      * Explicit ``docker.io/...`` → ``registry-1.docker.io`` (same endpoint).
      * Any other explicit registry host (``ghcr.io/...``, ``localhost:5000/...``,
        ``myregistry.example.com/...``) → that host verbatim (port stripped, the
        DNS/TCP preflight always targets :443).

    Args:
        image: Docker image reference selected by the launcher.

    Returns:
        The hostname the launcher should resolve / probe for this image.
    """
    token = _strip_default_docker_io_prefix(str(image or "")).strip()
    if not token:
        return _DOCKER_PULL_DNS_PREFLIGHT_HOST
    head = token.split("/", 1)[0]
    if not _image_reference_has_registry(token):
        # Docker Hub short name (``namespace/repo[:tag]``) — the daemon pulls
        # from the Docker Hub registry endpoint.
        return _DOCKER_PULL_DNS_PREFLIGHT_HOST
    if head.lower() in ("docker.io", "index.docker.io", "registry-1.docker.io"):
        return _DOCKER_PULL_DNS_PREFLIGHT_HOST
    # Explicit registry host (e.g. ``ghcr.io``, ``localhost:5000``). Strip any
    # ``:port`` so the host is suitable for a :443 DNS/TCP preflight.
    return head.split(":", 1)[0]


def _registry_label_for_host(host: str) -> str:
    """Return a human-friendly registry label for diagnostic messages.

    Keeps the long-standing ``Docker Hub`` wording for the Docker Hub endpoint
    so existing UX is unchanged, and shows the bare host for any other registry
    (e.g. ``ghcr.io``) so the operator sees the registry the pull actually used.
    """
    normalized = str(host or "").strip().lower()
    if normalized in ("", _DOCKER_PULL_DNS_PREFLIGHT_HOST, "docker.io", "index.docker.io"):
        return "Docker Hub"
    if normalized == "ghcr.io":
        return "GitHub Container Registry (ghcr.io)"
    return str(host).strip()


def _docker_login_command_for_image(image: str) -> str:
    """Return the copy-pasteable ``docker login`` command for an image's registry.

    * Docker Hub images keep the long-standing ``docker logout && docker login``
      (no host argument — that is the Docker Hub default endpoint).
    * Any other registry (e.g. a private ``ghcr.io/...`` PRO image) gets an
      explicit ``docker login <host>`` so the operator authenticates against the
      registry the pull actually contacts — this is what unblocks a private
      GHCR pull (the partner's GHCR read token via ``docker login ghcr.io``).
    """
    host = _registry_host_for_image(image)
    if str(host or "").strip().lower() == _DOCKER_PULL_DNS_PREFLIGHT_HOST:
        return "docker logout && docker login"
    return f"docker login {host}"


def _strip_default_docker_io_prefix(image: str) -> str:
    """Strip docker.io prefix to compare semantic image identity."""
    token = str(image or "").strip()
    if token.startswith("docker.io/"):
        return token[len("docker.io/") :]
    return token


def _qualify_image_reference_for_podman(image: str) -> str:
    """Return docker.io-qualified image ref for Podman short-name safety."""
    token = str(image or "").strip()
    if not token or _image_reference_has_registry(token):
        return token
    return f"docker.io/{token}"


def _normalize_image_reference_for_runtime(image: str) -> str:
    """Normalize image references for runtime-specific compatibility behavior."""
    token = str(image or "").strip()
    if not token:
        return token
    if not _allow_podman_docker_api_mode():
        return token
    runtime, _detail = _get_docker_cli_runtime_flavor()
    if runtime != "podman":
        return token
    normalized = _qualify_image_reference_for_podman(token)
    if normalized != token:
        print_info_debug(
            "[docker] normalized image reference for Podman compatibility: "
            f"source={mark_sensitive(token, 'detail')} "
            f"normalized={mark_sensitive(normalized, 'detail')}"
        )
    return normalized


def _get_docker_image() -> str:
    """Return the preferred Docker image for this environment."""
    return _get_docker_image_candidates()[0]


def _warn_using_legacy_image(*, selected_image: str, preferred_image: str) -> None:
    """Emit a one-time warning when legacy image naming is selected."""
    global _LEGACY_IMAGE_WARNING_SHOWN  # pylint: disable=global-statement
    if _LEGACY_IMAGE_WARNING_SHOWN:
        return
    if _strip_default_docker_io_prefix(
        selected_image
    ) == _strip_default_docker_io_prefix(preferred_image):
        return
    print_warning(
        "Using legacy Docker image naming for compatibility: "
        f"{selected_image} (preferred: {preferred_image})."
    )
    print_instruction(
        "Legacy fallback may be outdated. Remove "
        f"{_ALLOW_LEGACY_IMAGE_FALLBACK_ENV} when stable tags recover."
    )
    _LEGACY_IMAGE_WARNING_SHOWN = True


def _extract_first_nonempty_line(text: str) -> str:
    """Return the first non-empty line from command output."""
    for line in str(text or "").splitlines():
        cleaned = line.strip()
        if cleaned:
            return cleaned
    return ""


def _detect_linux_package_owner(binary_path: str) -> str:
    """Best-effort package owner hint for a binary path (Deb/RPM families)."""
    path = str(binary_path or "").strip()
    if not path:
        return ""

    try:
        if shutil.which("dpkg-query"):
            proc = subprocess.run(  # noqa: S603
                ["dpkg-query", "-S", path],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0:
                first = _extract_first_nonempty_line(proc.stdout or "")
                if ":" in first:
                    return first.split(":", 1)[0].strip()
                return first
    except (OSError, subprocess.TimeoutExpired):
        pass

    try:
        if shutil.which("rpm"):
            proc = subprocess.run(  # noqa: S603
                ["rpm", "-qf", path],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0:
                return _extract_first_nonempty_line(proc.stdout or "")
    except (OSError, subprocess.TimeoutExpired):
        pass

    return ""


def _parse_docker_client_version(raw: str) -> str:
    """Extract semantic-ish Docker client version from `docker --version`."""
    line = _extract_first_nonempty_line(raw)
    match = re.search(r"docker version\s+([^\s,]+)", line, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return line


def _parse_compose_version(raw: str) -> str:
    """Extract compose version token from `docker compose version` output."""
    line = _extract_first_nonempty_line(raw)
    match = re.search(r"v?(\d+\.\d+\.\d+[^\s,]*)", line, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return line


def _get_docker_cli_runtime_flavor() -> tuple[str, str]:
    """Detect whether `docker` CLI is Docker Engine or Podman compatibility mode."""
    global _DOCKER_CLI_RUNTIME_FLAVOR_CACHE  # pylint: disable=global-statement
    if _DOCKER_CLI_RUNTIME_FLAVOR_CACHE is not None:
        return _DOCKER_CLI_RUNTIME_FLAVOR_CACHE

    docker_bin = shutil.which("docker") or ""
    if not docker_bin:
        _DOCKER_CLI_RUNTIME_FLAVOR_CACHE = ("unknown", "docker_not_found")
        return _DOCKER_CLI_RUNTIME_FLAVOR_CACHE

    package_hint = _detect_linux_package_owner(docker_bin)
    command_output = ""
    try:
        proc = subprocess.run(  # noqa: S603
            [docker_bin, "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=8,
        )
        command_output = (
            f"{proc.stdout or ''}\n{proc.stderr or ''}"
            if proc.returncode == 0
            else proc.stderr or proc.stdout or ""
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        telemetry.capture_exception(exc)
        command_output = str(exc)

    lowered = f"{package_hint}\n{command_output}".lower()
    detail = (
        _extract_first_nonempty_line(command_output)
        or str(package_hint or "").strip()
        or "unknown"
    )
    if "podman" in lowered:
        _DOCKER_CLI_RUNTIME_FLAVOR_CACHE = ("podman", detail)
        return _DOCKER_CLI_RUNTIME_FLAVOR_CACHE
    if "docker" in lowered:
        _DOCKER_CLI_RUNTIME_FLAVOR_CACHE = ("docker", detail)
        return _DOCKER_CLI_RUNTIME_FLAVOR_CACHE
    _DOCKER_CLI_RUNTIME_FLAVOR_CACHE = ("unknown", detail)
    return _DOCKER_CLI_RUNTIME_FLAVOR_CACHE


def _categorize_daemon_diagnostic(diag: str) -> str:
    """Bucket Docker daemon diagnostics into stable telemetry categories."""
    lowered = str(diag or "").strip().lower()
    if not lowered:
        return "unknown"
    if "is running" in lowered:
        return "running"
    if "timed out" in lowered or "timeout" in lowered:
        return "timeout"
    if "cannot connect" in lowered or "not reachable" in lowered:
        return "unreachable"
    if "permission denied" in lowered or "got permission denied" in lowered:
        return "permission_denied"
    if "podman" in lowered:
        return "podman_socket"
    return "other"


def _ensure_supported_container_runtime(*, stage: str) -> bool:
    """Enforce Docker-by-default runtime policy for managed mode operations."""
    runtime, runtime_detail = _get_docker_cli_runtime_flavor()
    if runtime != "podman":
        return True

    if _allow_podman_docker_api_mode():
        print_info_debug(
            "[docker] Podman compatibility CLI detected and accepted via explicit opt-in: "
            f"stage={mark_sensitive(stage, 'status')} "
            f"runtime_detail={mark_sensitive(runtime_detail, 'detail')}"
        )
        telemetry.capture(
            "docker_runtime_preflight",
            {
                "stage": stage,
                "runtime": "podman",
                "opt_in": True,
            },
        )
        return True

    print_error(
        "Detected Podman compatibility Docker CLI (`docker` maps to Podman). "
        "ADscan requires Docker Engine by default."
    )
    print_instruction(
        "Use Docker Engine (docker-ce/docker-ce-cli/docker-compose-plugin), then retry."
    )
    print_instruction(
        "If you explicitly want Podman compatibility mode, set "
        f"{_ALLOW_PODMAN_DOCKER_API_ENV}=1 and retry."
    )
    print_info_debug(
        "[docker] runtime preflight blocked unsupported default runtime: "
        f"stage={mark_sensitive(stage, 'status')} "
        f"runtime_detail={mark_sensitive(runtime_detail, 'detail')}"
    )
    telemetry.capture(
        "docker_runtime_preflight",
        {
            "stage": stage,
            "runtime": "podman",
            "opt_in": False,
        },
    )
    # Record this as a distinct terminal outcome, not a bare `None`. A
    # policy refusal on a *reachable* runtime (the `docker` CLI answers
    # fine — it's just Podman) is otherwise indistinguishable from a
    # genuine unclassified pull failure once it reaches
    # `_print_docker_image_pull_failure_guidance`: that function sees
    # daemon_running=True and no recorded diagnosis, and synthesizes a
    # generic "unclassified error" panel that contradicts the specific
    # rejection just printed above and dangles an irrelevant legacy-image
    # fallback hint. See `docker_pull_diagnostics.PullFailureKind`.
    record_last_failure(
        PullFailureDiagnosis(
            kind="runtime_unsupported",
            evidence=[runtime_detail] if runtime_detail else [],
        )
    )
    return False


def _emit_docker_runtime_context(*, command_name: str) -> None:
    """Emit one-time Docker/Compose runtime fingerprint for troubleshooting."""
    global _DOCKER_RUNTIME_CONTEXT_EMITTED  # pylint: disable=global-statement
    if _DOCKER_RUNTIME_CONTEXT_EMITTED:
        return
    _DOCKER_RUNTIME_CONTEXT_EMITTED = True

    try:
        docker_bin = shutil.which("docker") or ""
        docker_client_version = ""
        compose_mode = "missing"
        compose_version = ""
        compose_v1_bin = shutil.which("docker-compose") or ""
        compose_v1_package = _detect_linux_package_owner(compose_v1_bin)

        if docker_bin:
            try:
                proc = subprocess.run(  # noqa: S603
                    [docker_bin, "--version"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=8,
                )
                if proc.returncode == 0:
                    docker_client_version = _parse_docker_client_version(
                        proc.stdout or proc.stderr or ""
                    )
            except (OSError, subprocess.TimeoutExpired) as exc:
                telemetry.capture_exception(exc)

        # Compose v2 plugin preferred.
        try:
            compose_v2_proc = run_docker(
                ["docker", "compose", "version"],
                check=False,
                capture_output=True,
                timeout=10,
            )
            compose_v2_text = (
                f"{compose_v2_proc.stdout or ''}\n{compose_v2_proc.stderr or ''}"
            )
            if compose_v2_proc.returncode == 0 and "compose" in compose_v2_text.lower():
                compose_mode = "v2"
                compose_version = _parse_compose_version(compose_v2_text)
        except Exception as exc:  # pragma: no cover - best effort only
            telemetry.capture_exception(exc)

        if compose_mode == "missing" and compose_v1_bin:
            try:
                compose_v1_proc = subprocess.run(  # noqa: S603
                    [compose_v1_bin, "version"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=8,
                )
                compose_v1_text = (
                    f"{compose_v1_proc.stdout or ''}\n{compose_v1_proc.stderr or ''}"
                )
                if (
                    compose_v1_proc.returncode == 0
                    and "compose" in compose_v1_text.lower()
                ):
                    compose_mode = "v1"
                    compose_version = _parse_compose_version(compose_v1_text)
            except (OSError, subprocess.TimeoutExpired) as exc:
                telemetry.capture_exception(exc)

        daemon_running, daemon_diagnostic = _is_docker_daemon_running_internal(
            run_docker_command_func=_run_docker_status_command
        )

        docker_server_version = ""
        if daemon_running:
            try:
                server_proc = run_docker(
                    ["docker", "version", "--format", "{{.Server.Version}}"],
                    check=False,
                    capture_output=True,
                    timeout=10,
                )
                if server_proc.returncode == 0:
                    docker_server_version = _extract_first_nonempty_line(
                        server_proc.stdout or ""
                    )
            except Exception as exc:  # pragma: no cover - best effort only
                telemetry.capture_exception(exc)

        payload: dict[str, Any] = {
            "command_name": command_name,
            "docker_cli_present": bool(docker_bin),
            "docker_client_version": docker_client_version,
            "docker_server_version": docker_server_version,
            "docker_package_hint": _detect_linux_package_owner(docker_bin),
            "compose_mode": compose_mode,
            "compose_version": compose_version,
            "compose_v1_package_hint": compose_v1_package,
            "docker_daemon_reachable": bool(daemon_running),
            "docker_daemon_diagnostic_kind": _categorize_daemon_diagnostic(
                daemon_diagnostic
            ),
        }
        print_info_debug(
            "[docker] runtime context: "
            f"command={mark_sensitive(command_name, 'status')} "
            f"docker_cli_present={mark_sensitive(str(payload['docker_cli_present']).lower(), 'status')} "
            f"docker_client={mark_sensitive(docker_client_version or 'unknown', 'status')} "
            f"docker_server={mark_sensitive(docker_server_version or 'unknown', 'status')} "
            f"docker_pkg={mark_sensitive(str(payload['docker_package_hint'] or 'unknown'), 'status')} "
            f"compose_mode={mark_sensitive(compose_mode, 'status')} "
            f"compose_version={mark_sensitive(compose_version or 'unknown', 'status')} "
            f"compose_v1_pkg={mark_sensitive(str(compose_v1_package or 'unknown'), 'status')} "
            f"daemon_reachable={mark_sensitive(str(bool(daemon_running)).lower(), 'status')} "
            f"daemon_diag={mark_sensitive(str(payload['docker_daemon_diagnostic_kind']), 'status')}"
        )
        telemetry.capture("docker_runtime_context", payload)
    except Exception as exc:  # pragma: no cover - best effort only
        telemetry.capture_exception(exc)


def _emit_docker_host_resources_context(*, command_name: str) -> None:
    """Emit one-time host resources snapshot for Docker troubleshooting."""
    global _DOCKER_HOST_RESOURCES_CONTEXT_EMITTED  # pylint: disable=global-statement
    if _DOCKER_HOST_RESOURCES_CONTEXT_EMITTED:
        return
    _DOCKER_HOST_RESOURCES_CONTEXT_EMITTED = True

    try:
        storage_path = _get_docker_storage_path()
        free_disk_bytes = _get_free_disk_bytes(storage_path)
        free_mem_bytes = _get_free_memory_bytes()
        free_disk_gb = round(free_disk_bytes / (1024**3), 2)
        free_mem_gb = round(free_mem_bytes / (1024**3), 2)

        payload: dict[str, Any] = {
            "command_name": command_name,
            "storage_path": str(storage_path),
            "free_disk_gb": free_disk_gb,
            "free_memory_gb": free_mem_gb,
            "low_disk": free_disk_gb < _MIN_DOCKER_INSTALL_FREE_GB,
            "low_memory": free_mem_gb < _LOW_MEMORY_WARNING_THRESHOLD_GB,
        }
        print_info_debug(
            "[docker] host resources context: "
            f"command={mark_sensitive(command_name, 'status')} "
            f"storage_path={mark_sensitive(str(storage_path), 'path')} "
            f"free_disk_gb={mark_sensitive(str(free_disk_gb), 'status')} "
            f"free_memory_gb={mark_sensitive(str(free_mem_gb), 'status')} "
            f"low_disk={mark_sensitive(str(payload['low_disk']).lower(), 'status')} "
            f"low_memory={mark_sensitive(str(payload['low_memory']).lower(), 'status')}"
        )
        telemetry.capture("docker_host_resources_context", payload)
    except Exception as exc:  # pragma: no cover - best effort only
        telemetry.capture_exception(exc)


def _select_existing_or_preferred_image() -> str:
    """Use an existing compatible image when available, else preferred image."""
    candidates = _get_docker_image_candidates()
    preferred = candidates[0]
    for candidate in candidates:
        if image_exists(candidate):
            _warn_using_legacy_image(
                selected_image=candidate,
                preferred_image=preferred,
            )
            return candidate
    return preferred


def _run_docker_pull_dns_preflight(
    *, host: str = _DOCKER_PULL_DNS_PREFLIGHT_HOST
) -> bool:
    """Best-effort DNS preflight for Docker Hub pulls.

    This check is intentionally non-blocking: it emits early diagnostics when
    DNS resolution appears broken, but the pull still proceeds in case of
    transient resolver issues.
    """
    try:
        addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        resolved_hosts = sorted({entry[4][0] for entry in addresses if entry[4]})
        print_info_debug(
            "[docker] pull DNS preflight passed: "
            f"host={mark_sensitive(host, 'detail')} "
            f"resolved={mark_sensitive(','.join(resolved_hosts[:3]) or 'yes', 'detail')}"
        )
        telemetry.capture(
            "docker_pull_dns_preflight",
            {
                "host": host,
                "resolved": True,
                "resolved_count": len(resolved_hosts),
            },
        )
        return True
    except socket.gaierror as exc:
        registry_label = _registry_label_for_host(host)
        print_warning(
            f"DNS preflight could not resolve {registry_label}. Image pull may fail."
        )
        print_instruction(f"Check resolver health: getent hosts {host}")
        print_instruction(
            "If DNS is unstable, switch to a reliable resolver and retry."
        )
        print_info_debug(
            "[docker] pull DNS preflight failed: "
            f"host={mark_sensitive(host, 'detail')} "
            f"error={mark_sensitive(str(exc), 'detail')}"
        )
        telemetry.capture(
            "docker_pull_dns_preflight",
            {
                "host": host,
                "resolved": False,
                "error_kind": "gaierror",
                "error": str(exc),
            },
        )
        return False
    except Exception as exc:  # pragma: no cover - best effort only
        telemetry.capture_exception(exc)
        print_info_debug(
            "[docker] pull DNS preflight skipped after unexpected error: "
            f"{mark_sensitive(str(exc), 'detail')}"
        )
        return True


def _run_docker_pull_network_preflight(
    *,
    host: str = _DOCKER_PULL_DNS_PREFLIGHT_HOST,
    port: int = 443,
    timeout_seconds: float = _DOCKER_PULL_NETWORK_PREFLIGHT_TIMEOUT_SECONDS,
) -> bool:
    """Best-effort network preflight for Docker Hub HTTPS connectivity.

    This check is non-blocking: failures emit guidance and telemetry but do not
    abort pull attempts because transient routing conditions can recover.
    """
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        print_info_debug(
            "[docker] pull network preflight skipped because DNS resolution failed: "
            f"host={mark_sensitive(host, 'detail')} "
            f"error={mark_sensitive(str(exc), 'detail')}"
        )
        telemetry.capture(
            "docker_pull_network_preflight",
            {
                "host": host,
                "port": int(port),
                "reachable": False,
                "skipped_reason": "dns_resolution_failed",
                "error": str(exc),
            },
        )
        return False

    attempted = 0
    failures: list[tuple[str, str]] = []
    max_attempts = min(len(addresses), 6)
    for entry in addresses[:max_attempts]:
        sockaddr = entry[4]
        if not sockaddr:
            continue
        ip = str(sockaddr[0])
        attempted += 1
        try:
            with socket.create_connection((ip, port), timeout=timeout_seconds):
                print_info_debug(
                    "[docker] pull network preflight passed: "
                    f"host={mark_sensitive(host, 'detail')} "
                    f"ip={mark_sensitive(ip, 'detail')} "
                    f"port={mark_sensitive(str(port), 'detail')}"
                )
                telemetry.capture(
                    "docker_pull_network_preflight",
                    {
                        "host": host,
                        "port": int(port),
                        "reachable": True,
                        "attempted": attempted,
                        "successful_ip": ip,
                    },
                )
                return True
        except OSError as exc:
            failures.append((ip, str(exc)))

    ipv6_unreachable = any(
        ":" in ip and "network is unreachable" in err.lower() for ip, err in failures
    )
    ipv4_timed_out = any(
        ":" not in ip and ("timed out" in err.lower() or "timeout" in err.lower())
        for ip, err in failures
    )
    registry_label = _registry_label_for_host(host)
    print_warning(
        f"Network preflight could not reach {registry_label} over HTTPS. Image pull may fail."
    )
    print_instruction(
        "Verify host internet connectivity, VPN/proxy, and firewall policy."
    )
    if ipv6_unreachable:
        print_instruction(
            "IPv6 route appears unreachable. Prefer IPv4 connectivity if IPv6 is unstable."
        )
    if ipv6_unreachable and ipv4_timed_out:
        print_instruction(
            f"IPv4 connections also timed out. Network path to {registry_label} is "
            "unstable; retry on a cleaner network."
        )
        print_instruction(f"Quick check: curl -4 -I https://{host}/v2/")
    print_info_debug(
        "[docker] pull network preflight failed: "
        f"host={mark_sensitive(host, 'detail')} "
        f"attempted={mark_sensitive(str(attempted), 'detail')} "
        f"ipv6_unreachable={mark_sensitive(str(ipv6_unreachable).lower(), 'status')} "
        f"ipv4_timed_out={mark_sensitive(str(ipv4_timed_out).lower(), 'status')} "
        f"failure_sample={mark_sensitive(str(failures[:2]), 'detail')}"
    )
    telemetry.capture(
        "docker_pull_network_preflight",
        {
            "host": host,
            "port": int(port),
            "reachable": False,
            "attempted": attempted,
            "ipv6_unreachable": ipv6_unreachable,
            "ipv4_timed_out": ipv4_timed_out,
            "failure_sample": [{"ip": ip, "error": err} for ip, err in failures[:3]],
        },
    )
    return False


def _emit_pull_retry_notice(
    *,
    reason: str,
    diagnosis: "PullFailureDiagnosis | None" = None,
) -> None:
    """Render a compact, premium-styled "retry pending" line.

    The retry path used to emit a yellow ``print_warning("Docker image
    pull failed. Retrying once...")`` BEFORE the retry was attempted.
    That message was alarming and turned out to be misleading: most
    transient retries succeed in seconds because Docker reuses the
    layers already cached from the failed attempt. The new message is
    informational, names the classified cause so the operator sees what
    went wrong, and signals that recovery is in progress — no scary
    glyph, no panel, no whiplash.
    """
    pieces = ["[dim]First attempt failed[/dim]"]
    if diagnosis is not None:
        presentation = get_presentation(diagnosis.kind)
        pieces.append(
            f"[dim]·[/dim] {presentation.glyph} [bold]{presentation.title}[/bold]"
        )
    pieces.append(f"[dim]·[/dim] {reason}")
    print_info(" ".join(pieces))


def _emit_pull_recovery_notice(
    *,
    first_failure: "PullFailureDiagnosis | None",
) -> None:
    """Render a sober recovery line after a successful retry.

    Pairs with ``_emit_pull_retry_notice``: the operator saw the
    transient failure, now they see the operation finished cleanly.
    Single line, dim secondary tone so it does not steal attention from
    the eventual ``pulled successfully`` line that follows.
    """
    if first_failure is None:
        print_info("[dim]Recovered automatically on retry.[/dim]")
        return
    presentation = get_presentation(first_failure.kind)
    print_info(
        f"[dim]Recovered on retry after[/dim] {presentation.glyph} "
        f"[dim]{presentation.title}.[/dim] "
        f"[dim]Docker reused cached layers from the previous attempt.[/dim]"
    )


def _ensure_image_pulled_with_legacy_fallback(
    *,
    pull_timeout: int | None,
    stream_output: bool,
) -> str | None:
    """Pull preferred image, then fallback to legacy naming if needed.

    Failure UX contract:

    * Intermediate attempts (first try, transient retry, post-daemon-
      recovery retry) are silent on success-or-defer paths. The
      ``ensure_image_pulled`` call sets ``surface_failure=False`` so the
      DNS guidance and timeout warning do not fire mid-loop — the
      diagnosis is still recorded for the eventual panel.
    * Between attempts, a compact info line names the cause and signals
      that a retry is in flight (see ``_emit_pull_retry_notice``).
    * When a retry succeeds, a single dim recovery line acknowledges
      the transient failure without alarm (see
      ``_emit_pull_recovery_notice``).
    * The final premium failure panel is rendered exactly once by the
      caller of this function via ``_print_docker_image_pull_failure_guidance``,
      using the diagnosis of the *last* attempt.
    """
    if not _ensure_docker_daemon_available_for_pull(stage="pre_pull"):
        return None
    # Derive the preflight host from the image that will actually be pulled so
    # the DNS/TCP checks and any troubleshooting hints target the right
    # registry (Docker Hub → registry-1.docker.io; ghcr.io/... → ghcr.io; any
    # explicit registry → that host). Falls back to Docker Hub for short names.
    preflight_image = _get_docker_image_candidates()[0]
    preflight_host = _registry_host_for_image(preflight_image)
    dns_preflight_ok = _run_docker_pull_dns_preflight(host=preflight_host)
    network_preflight_ok = _run_docker_pull_network_preflight(host=preflight_host)
    preflight_ok = bool(dns_preflight_ok and network_preflight_ok)

    def _on_pull_success(
        selected_image: str,
        *,
        preferred_image: str,
        first_failure: "PullFailureDiagnosis | None" = None,
    ) -> str:
        """Emit recovery/preflight notes, then return the resolved image."""
        if first_failure is not None:
            _emit_pull_recovery_notice(first_failure=first_failure)
        if not preflight_ok:
            print_info(
                "Continuing after non-blocking network preflight warning. "
                "Docker image pull succeeded."
            )
            print_info_debug(
                "[docker] pull succeeded despite preflight warning: "
                f"image={mark_sensitive(selected_image, 'detail')} "
                f"dns_preflight_ok={mark_sensitive(str(dns_preflight_ok).lower(), 'status')} "
                f"network_preflight_ok={mark_sensitive(str(network_preflight_ok).lower(), 'status')}"
            )
            telemetry.capture(
                "docker_pull_preflight_nonblocking_success",
                {
                    "image": selected_image,
                    "dns_preflight_ok": bool(dns_preflight_ok),
                    "network_preflight_ok": bool(network_preflight_ok),
                },
            )
        _warn_using_legacy_image(
            selected_image=selected_image,
            preferred_image=preferred_image,
        )
        return selected_image

    candidates = _get_docker_image_candidates()
    preferred = _normalize_image_reference_for_runtime(candidates[0])
    for idx, candidate in enumerate(candidates):
        candidate_to_pull = _normalize_image_reference_for_runtime(candidate)
        if idx > 0:
            print_info(
                "[dim]Primary image unavailable — trying legacy naming[/dim] "
                f"[dim]·[/dim] {candidate_to_pull}"
            )
        # First attempt: classify on failure but do NOT surface guidance
        # — the retry path below decides whether to recover quietly or
        # promote the failure to the caller.
        if ensure_image_pulled(
            candidate_to_pull,
            timeout=pull_timeout,
            stream_output=stream_output,
            surface_failure=False,
        ):
            return _on_pull_success(
                candidate_to_pull,
                preferred_image=preferred,
            )

        first_failure = peek_last_failure()
        daemon_running, daemon_diagnostic = _is_docker_daemon_running_internal(
            run_docker_command_func=_run_docker_status_command
        )
        if daemon_running:
            _emit_pull_retry_notice(
                reason="[dim]retrying with cached layers…[/dim]",
                diagnosis=first_failure,
            )
            print_info_debug(
                "[docker] transient pull retry: "
                f"image={mark_sensitive(candidate_to_pull, 'detail')} "
                f"first_kind={first_failure.kind if first_failure else 'unknown'} "
                f"diagnostic={mark_sensitive(daemon_diagnostic, 'detail')}"
            )
            telemetry.capture(
                "docker_pull_retry",
                {
                    "image": candidate_to_pull,
                    "reason": "transient_pull_failure",
                    "first_failure_kind": first_failure.kind if first_failure else "unknown",
                },
            )
            time.sleep(1.5)
            # Retry attempt: also silent on failure — if it fails, we
            # fall through to the daemon-recovery branch or to the loop
            # exit, at which point the caller renders the final panel
            # using whichever diagnosis is freshest.
            if ensure_image_pulled(
                candidate_to_pull,
                timeout=pull_timeout,
                stream_output=stream_output,
                surface_failure=False,
            ):
                return _on_pull_success(
                    candidate_to_pull,
                    preferred_image=preferred,
                    first_failure=first_failure,
                )
            daemon_running, daemon_diagnostic = _is_docker_daemon_running_internal(
                run_docker_command_func=_run_docker_status_command
            )
        if daemon_running:
            continue

        _emit_pull_retry_notice(
            reason="[dim]daemon became unavailable — recovering before retry…[/dim]",
            diagnosis=first_failure,
        )
        print_info_debug(
            "[docker] daemon diagnostic after pull failure: "
            f"{mark_sensitive(daemon_diagnostic, 'detail')}"
        )
        if not _ensure_docker_daemon_available_for_pull(stage="post_pull_failure"):
            return None

        # Daemon recovered: final attempt for THIS candidate. We surface
        # the failure here because if this one fails too there is nothing
        # left for this candidate — the caller's panel is the right
        # place to render it, so we still keep surface_failure=False and
        # let _print_docker_image_pull_failure_guidance own the panel.
        if ensure_image_pulled(
            candidate_to_pull,
            timeout=pull_timeout,
            stream_output=stream_output,
            surface_failure=False,
        ):
            return _on_pull_success(
                candidate_to_pull,
                preferred_image=preferred,
                first_failure=first_failure,
            )
    return None


def _ensure_runtime_image_available(
    *,
    image: str,
    pull_timeout_seconds: int | None,
    command_name: str,
) -> str | None:
    """Ensure ADscan runtime image is locally available before heavy preflights."""
    if image_exists(image):
        return image
    print_warning(f"ADscan docker image not present: {image}")
    print_info("Pulling the image now...")
    pull_timeout = _normalize_pull_timeout_seconds(pull_timeout_seconds)
    resolved_image = _ensure_image_pulled_with_legacy_fallback(
        pull_timeout=pull_timeout,
        stream_output=True,
    )
    if resolved_image:
        return resolved_image
    _print_docker_image_pull_failure_guidance(
        image=image,
        pull_timeout=pull_timeout,
        command_name=command_name,
    )
    return None


def pull_runtime_image_with_diagnostics(
    *,
    image: str,
    pull_timeout_seconds: int | None,
    command_name: str,
    stream_output: bool = True,
) -> str | None:
    """Pull the ADscan runtime image with the standard daemon/network diagnostics.

    Unlike `_ensure_runtime_image_available`, this always attempts a pull even if
    the image already exists locally, so update flows can reuse the same robust
    troubleshooting path as install/start/check.
    """
    pull_timeout = _normalize_pull_timeout_seconds(pull_timeout_seconds)
    resolved_image = _ensure_image_pulled_with_legacy_fallback(
        pull_timeout=pull_timeout,
        stream_output=stream_output,
    )
    if resolved_image:
        return resolved_image
    _print_docker_image_pull_failure_guidance(
        image=image,
        pull_timeout=pull_timeout,
        command_name=command_name,
    )
    return None


def _emit_docker_daemon_troubleshooting_snapshot(*, stage: str) -> None:
    """Emit focused diagnostics when Docker daemon is unreachable.

    The goal is to provide actionable debug context (service state, socket and
    DOCKER_HOST hints) without requiring users to rerun extra commands first.
    """
    docker_host = os.getenv("DOCKER_HOST", "").strip()
    if docker_host:
        print_info_debug(
            f"[docker] DOCKER_HOST is set: {mark_sensitive(docker_host, 'detail')}"
        )

    sock_path = Path("/var/run/docker.sock")
    sock_exists = sock_path.exists()
    sock_readable = os.access(sock_path, os.R_OK | os.W_OK) if sock_exists else False
    print_info_debug(
        "[docker] socket probe: "
        f"path={mark_sensitive(str(sock_path), 'path')} "
        f"exists={sock_exists} readable_writable={sock_readable}"
    )

    if not shutil.which("systemctl"):
        print_info_debug(
            "[docker] systemctl is unavailable; skipping docker service diagnostics."
        )
        return

    def _run_systemctl_capture(args: list[str]) -> tuple[str, str]:
        cmd: list[str] = ["systemctl"] + args
        if os.geteuid() != 0:
            if not _ensure_sudo_ticket_if_needed():
                print_info_debug(
                    "[docker] systemctl diagnostics skipped: sudo validation failed."
                )
                return "", ""
            cmd = [
                "sudo",
                "--preserve-env=HOME,XDG_CONFIG_HOME,ADSCAN_HOME,ADSCAN_SESSION_ENV,CI,GITHUB_ACTIONS",
            ] + cmd

        try:
            proc = subprocess.run(  # noqa: S603
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            telemetry.capture_exception(exc)
            print_info_debug(
                "[docker] systemctl diagnostic command failed: "
                f"stage={stage} cmd={shell_quote_cmd(cmd)} "
                f"error={mark_sensitive(str(exc), 'error')}"
            )
            return "", ""

        stdout = (proc.stdout or "").strip()
        stderr = (proc.stderr or "").strip()
        if stdout:
            print_info_debug(
                "[docker] systemctl diagnostic stdout: "
                f"stage={stage} cmd={shell_quote_cmd(cmd)}\n"
                f"{mark_sensitive(stdout, 'detail')}"
            )
        if stderr:
            print_info_debug(
                "[docker] systemctl diagnostic stderr: "
                f"stage={stage} cmd={shell_quote_cmd(cmd)}\n"
                f"{mark_sensitive(stderr, 'detail')}"
            )
        return stdout, stderr

    _run_systemctl_capture(["is-active", "docker"])
    status_stdout, status_stderr = _run_systemctl_capture(
        ["status", "docker", "--no-pager", "--full"]
    )
    status_text = f"{status_stdout}\n{status_stderr}".strip()
    if _DOCKER_SERVICE_UNIT_MISSING_RE.search(status_text):
        print_error(
            "Docker service unit (`docker.service`) was not found on this host."
        )
        print_instruction("Install Docker Engine, then retry.")
        print_instruction(f"Installation guide: {_DOCKER_INSTALL_DOCS_URL}")


def _render_premium_pull_failure_panel(
    *,
    diagnosis: PullFailureDiagnosis,
    image: str,
    command_name: str,
    pull_timeout: int | None,
) -> None:
    """Render the premium, classified failure panel.

    Self-contained: pulls the presentation metadata, substitutes the
    operator's actual retry command + image into the fix steps, and
    emits a single Rich panel with semantic chrome. No raw ANSI dump;
    no version-specific copy. The presentation tables in
    ``docker_pull_diagnostics`` are the single source of truth — if you
    want to change wording or chrome, edit that file, not this one.
    """
    presentation = get_presentation(diagnosis.kind)
    suggested_timeout = 7200 if pull_timeout is None else max(pull_timeout, 7200)
    retry_command = f"adscan {command_name}"
    login_command = _docker_login_command_for_image(image)

    body_lines: list[str] = []
    if presentation.what_lines:
        body_lines.append("[bold]What happened[/bold]")
        body_lines.extend(f"  {ln}" for ln in presentation.what_lines)
        body_lines.append("")
    if presentation.why_lines:
        body_lines.append("[bold]Why[/bold]")
        body_lines.extend(f"  {ln}" for ln in presentation.why_lines)
        body_lines.append("")
    if presentation.fix_steps:
        body_lines.append("[bold]Fix[/bold]")
        for step in presentation.fix_steps:
            rendered = step.format(
                retry_command=retry_command,
                image_name=image,
                login_command=login_command,
            )
            body_lines.append(f"  [cyan]$[/cyan] {rendered}")
        body_lines.append("")
    if diagnosis.evidence:
        body_lines.append("[bold]Registry said[/bold]")
        for line in diagnosis.evidence:
            # Truncate over-long lines so the panel stays scannable.
            shown = line if len(line) <= 200 else line[:197] + "..."
            body_lines.append(f"  [dim]{mark_sensitive(shown, 'detail')}[/dim]")
        body_lines.append("")
    if presentation.followup:
        body_lines.append(f"[dim]{presentation.followup}[/dim]")

    # For `unknown`, surface the timeout escape hatch since the panel
    # has no targeted remediation. Network_timeout already shows it
    # in its own Fix block, so don't double up.
    if diagnosis.kind == "unknown":
        body_lines.append("")
        body_lines.append("[dim]Need more time on a slow link:[/dim]")
        body_lines.append(
            f"  [cyan]$[/cyan] adscan {command_name} --pull-timeout {suggested_timeout}"
        )

    body = "\n".join(body_lines).rstrip()
    print_panel(
        body,
        title=f"{presentation.glyph}  {presentation.title}",
        border_style=presentation.border_style,
        title_align="left",
    )


def _print_docker_image_pull_failure_guidance(
    *,
    image: str,
    pull_timeout: int | None,
    command_name: str,
) -> None:
    """Print targeted guidance for Docker image pull failures.

    Two paths:

    * Daemon down → short-circuit with the daemon recovery checklist
      (the pull never reached the registry, so a registry classification
      would be misleading).
    * Daemon up → render the premium classified failure panel using the
      diagnosis recorded by ``ensure_image_pulled``. Falls back to the
      ``unknown`` presentation if no diagnosis was recorded (e.g. the
      pull short-circuited before any failure capture).
    """
    daemon_running, daemon_diagnostic = _is_docker_daemon_running_internal(
        run_docker_command_func=_run_docker_status_command
    )

    if not daemon_running:
        print_error("Failed to pull the ADscan Docker image.")
        print_warning(
            "Docker daemon is not reachable. ADscan cannot pull images until "
            "Docker API is available."
        )
        print_info_debug(
            "[docker] daemon diagnostic (image_pull_failure): "
            f"{mark_sensitive(daemon_diagnostic, 'detail')}"
        )
        _emit_docker_daemon_troubleshooting_snapshot(stage="image_pull_failure")
        print_instruction("Start Docker and retry:")
        print_instruction("  sudo systemctl start docker")
        print_instruction("Check service state:")
        print_instruction("  sudo systemctl status docker --no-pager")
        print_instruction("Check daemon logs:")
        print_instruction("  sudo journalctl -u docker -n 120 --no-pager")
        if os.getenv("DOCKER_HOST", "").strip():
            print_instruction("If DOCKER_HOST is misconfigured, unset it and retry:")
            print_instruction("  unset DOCKER_HOST")
        print_instruction(f"Retry command: adscan {command_name}")
        return

    diagnosis = consume_last_failure()
    if diagnosis is not None and diagnosis.kind == "runtime_unsupported":
        # A container-runtime policy refusal is a distinct terminal
        # outcome, not a genuine unclassified pull failure: the daemon
        # answered fine (daemon_running is True above), ADscan simply
        # refused to use it because it's a rejected Podman compatibility
        # shim. `_ensure_supported_container_runtime` already printed the
        # exact rejection + remediation for this case. Rendering the
        # generic "unclassified error" panel here would contradict that
        # message, and the legacy-image fallback hint below is irrelevant
        # to a runtime rejection — so stop here with nothing further to add.
        print_info_debug(
            "[docker] pull guidance short-circuited: runtime policy refusal "
            "already explained by the preflight check."
        )
        return

    if diagnosis is None:
        # Pull failed but no diagnosis was recorded (shouldn't happen in
        # practice — defensive fallback). Synthesize an "unknown" so the
        # operator still sees a structured panel rather than nothing.
        diagnosis = PullFailureDiagnosis(kind="unknown", evidence=[])

    _render_premium_pull_failure_panel(
        diagnosis=diagnosis,
        image=image,
        command_name=command_name,
        pull_timeout=pull_timeout,
    )

    telemetry.capture(
        "docker_pull_failure_classified",
        {
            "kind": diagnosis.kind,
            "rate_limit_likely": diagnosis.rate_limit_likely,
            "has_evidence": bool(diagnosis.evidence),
            "command_name": command_name,
        },
    )

    if diagnosis.kind in ("manifest_not_found", "unknown"):
        # Only surface the legacy-image escape hatch where it might
        # actually help. Manifest_not_found is the canonical case
        # (preferred tag rotated away); unknown is the catch-all.
        print_instruction(
            "Emergency compatibility fallback (may use older image naming): "
            f"{_ALLOW_LEGACY_IMAGE_FALLBACK_ENV}=1 adscan {command_name}"
        )


def get_docker_image_name() -> str:
    """Return the resolved ADscan Docker image name for this environment."""
    return _get_docker_image()


def _get_workspaces_dir() -> Path:
    return get_workspaces_dir()


def _get_logs_dir() -> Path:
    return get_logs_dir()


def _get_config_dir() -> Path:
    return get_adscan_home_dir() / ".config"


def _get_codex_container_dir() -> Path:
    """Return the host directory used for container-scoped Codex auth/session state."""
    return get_adscan_home_dir() / ".codex-container"


def _get_run_dir() -> Path:
    return get_run_dir()


def _get_state_dir() -> Path:
    return get_state_dir()


def _resolve_self_executable() -> str:
    """Return an absolute path to the running ADscan executable (best effort)."""
    try:
        candidate = Path(sys.argv[0]).expanduser()
        if candidate.is_file():
            return str(candidate.resolve())
    except Exception:
        pass
    which = shutil.which(sys.argv[0]) if sys.argv else None
    if which:
        return which
    # Fallback: rely on PATH.
    return sys.argv[0] if sys.argv else "adscan"


def _ensure_sudo_ticket_if_needed() -> bool:
    """Ensure sudo can be used when required (best effort).

    Delegates to the centralized ``sudo_utils.sudo_validate()`` which tries
    ``sudo -n true`` first (works with NOPASSWD, never blocks) and only falls
    back to an interactive prompt on a real TTY.
    """
    from adscan_launcher.sudo_utils import sudo_validate

    return sudo_validate()


def _run_docker_status_command(
    command: list[str],
    *,
    shell: bool = False,
    check: bool = False,
    capture_output: bool = True,
    text: bool = True,
    timeout: int = 10,
) -> subprocess.CompletedProcess:
    """Run a Docker status command via launcher runtime wrapper.

    This adapter keeps a `subprocess.run`-like signature so it can be passed to
    the shared `docker_status` helpers.
    """
    del text
    if shell:
        raise ValueError("shell=True is not supported for docker status commands")
    return run_docker(
        command,
        check=check,
        capture_output=capture_output,
        timeout=timeout,
    )


def _run_systemctl_command_for_docker_service(
    args: list[str],
    *,
    check: bool = False,
    timeout: int = 30,
) -> subprocess.CompletedProcess | None:
    """Run a `systemctl` command (best effort), elevating with sudo when needed."""
    if not shutil.which("systemctl"):
        return None

    cmd: list[str] = ["systemctl"] + args
    if os.geteuid() != 0:
        if not _ensure_sudo_ticket_if_needed():
            raise RuntimeError("sudo validation failed for systemctl")
        cmd = [
            "sudo",
            "--preserve-env=HOME,XDG_CONFIG_HOME,ADSCAN_HOME,ADSCAN_SESSION_ENV,CI,GITHUB_ACTIONS",
        ] + cmd

    return subprocess.run(  # noqa: S603
        cmd,
        check=check,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _is_interactive_launcher_session() -> bool:
    """Return True when launcher can safely ask interactive recovery prompts."""
    if os.getenv("ADSCAN_NONINTERACTIVE", "").strip() == "1":
        return False
    if _is_ci():
        return False
    return bool(sys.stdin.isatty() and sys.stdout.isatty())


def _diagnostic_points_to_podman_socket(diagnostic: str) -> bool:
    """Return True when docker CLI is configured to use Podman socket."""
    lowered = (diagnostic or "").lower()
    return "podman.sock" in lowered and (
        "cannot connect" in lowered
        or "connection refused" in lowered
        or "is the docker daemon running" in lowered
    )


def _diagnostic_looks_transient_daemon_timeout(diagnostic: str) -> bool:
    """Return True for daemon diagnostics that look like transient timeout errors."""
    lowered = (diagnostic or "").lower()
    return (
        "daemon check timed out" in lowered
        or "timeout" in lowered
        or "timed out" in lowered
        or "context deadline exceeded" in lowered
    )


def _allow_podman_docker_api_mode() -> bool:
    """Return True when explicit Podman Docker API mode is enabled."""
    raw = str(os.getenv(_ALLOW_PODMAN_DOCKER_API_ENV, "")).strip().lower()
    return raw in ("1", "true", "yes", "on")


def _probe_docker_engine_without_docker_host() -> tuple[bool, str]:
    """Check whether Docker Engine is reachable when DOCKER_HOST is ignored."""
    env = os.environ.copy()
    env.pop("DOCKER_HOST", None)
    env.pop("DOCKER_CONTEXT", None)
    cmd = ["docker", "info", "--format", "{{.ServerVersion}}"]

    try:
        proc = subprocess.run(  # noqa: S603
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        telemetry.capture_exception(exc)
        return False, f"probe_exception={exc}"

    if proc.returncode == 0:
        version = _extract_first_nonempty_line(proc.stdout or "") or "unknown"
        return True, version

    stderr = (proc.stderr or "").strip()
    stdout = (proc.stdout or "").strip()
    diagnostic = stderr or stdout or "docker info failed"
    return False, diagnostic


def _attempt_docker_host_engine_autoremediation(
    *,
    stage: str,
    diagnostic: str,
) -> bool:
    """Offer session-scoped DOCKER_HOST fix when Podman socket is misconfigured."""
    del diagnostic
    global _DOCKER_HOST_ENGINE_OVERRIDE_APPLIED  # pylint: disable=global-statement
    global _DOCKER_HOST_ENGINE_OVERRIDE_DECLINED  # pylint: disable=global-statement

    if _DOCKER_HOST_ENGINE_OVERRIDE_APPLIED:
        running, _diag = _is_docker_daemon_running_internal(
            run_docker_command_func=_run_docker_status_command
        )
        return bool(running)

    if _DOCKER_HOST_ENGINE_OVERRIDE_DECLINED:
        return False

    current_docker_host = str(os.getenv("DOCKER_HOST", "")).strip()
    if not current_docker_host:
        return False

    engine_reachable, probe_detail = _probe_docker_engine_without_docker_host()
    if not engine_reachable:
        print_info_debug(
            "[docker] DOCKER_HOST auto-remediation skipped: Docker Engine probe "
            "without DOCKER_HOST failed. "
            f"stage={stage} detail={mark_sensitive(probe_detail, 'detail')}"
        )
        return False

    if not _is_interactive_launcher_session():
        print_info_debug(
            "[docker] DOCKER_HOST auto-remediation available but skipped "
            f"(non-interactive). stage={stage}"
        )
        return False

    details = [
        "Detected a Podman Docker API endpoint in DOCKER_HOST, but Docker Engine appears available.",
        f"Current DOCKER_HOST: {mark_sensitive(current_docker_host, 'detail')}",
        f"Docker Engine version (default socket): {mark_sensitive(probe_detail, 'status')}",
        "",
        "ADscan can auto-fix this for the current launcher session by unsetting DOCKER_HOST.",
        "This does not modify your shell profile files.",
    ]
    print_panel(
        "\n".join(details),
        title="Docker Endpoint Auto-Remediation",
        border_style="yellow",
    )
    proceed = confirm_ask(
        "Apply session-only DOCKER_HOST fix now and continue?",
        default=True,
    )
    if not proceed:
        _DOCKER_HOST_ENGINE_OVERRIDE_DECLINED = True
        telemetry.capture(
            "docker_host_autoremediation_declined",
            {
                "stage": stage,
                "docker_host": current_docker_host,
            },
        )
        return False

    os.environ.pop("DOCKER_HOST", None)
    _DOCKER_HOST_ENGINE_OVERRIDE_APPLIED = True
    print_success(
        "Applied session-only Docker endpoint fix (DOCKER_HOST unset). Continuing."
    )
    telemetry.capture(
        "docker_host_autoremediation_applied",
        {
            "stage": stage,
            "docker_host_was": current_docker_host,
            "engine_version": probe_detail,
        },
    )

    running, post_diag = _is_docker_daemon_running_internal(
        run_docker_command_func=_run_docker_status_command
    )
    if running:
        return True

    print_info_debug(
        "[docker] DOCKER_HOST auto-remediation applied but daemon check still failed: "
        f"{mark_sensitive(post_diag, 'detail')}"
    )
    return False


def _attempt_start_user_podman_socket() -> bool:
    """Best-effort start of rootless Podman socket used as Docker API endpoint."""
    if not shutil.which("systemctl"):
        return False
    try:
        proc = subprocess.run(  # noqa: S603
            ["systemctl", "--user", "start", "podman.socket"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        telemetry.capture_exception(exc)
        print_info_debug(f"[docker] podman socket auto-start failed: {exc}")
        return False

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        if stderr:
            print_info_debug(
                "[docker] systemctl --user start podman.socket stderr: "
                f"{mark_sensitive(stderr, 'detail')}"
            )
        return False

    running, diagnostic = _is_docker_daemon_running_internal(
        run_docker_command_func=_run_docker_status_command
    )
    if running:
        print_success_verbose(
            "Podman user socket started successfully; Docker API endpoint is reachable."
        )
        return True

    print_info_debug(
        "[docker] podman socket started but docker endpoint still unavailable: "
        f"{mark_sensitive(diagnostic, 'detail')}"
    )
    return False


def _ensure_docker_daemon_available_for_pull(*, stage: str) -> bool:
    """Ensure Docker daemon is reachable before/after image pull attempts."""
    if not _ensure_supported_container_runtime(stage=stage):
        return False

    # An absent Docker CLI cannot have a daemon to start. Short-circuit before
    # the offer-to-start + systemctl recovery dance so we never attempt to
    # manage a daemon that cannot exist; surface a clear install message instead.
    if not docker_available():
        print_error("Docker is not installed or not in PATH.")
        print_instruction("Install Docker Engine, then retry.")
        print_instruction(f"Installation guide: {_DOCKER_INSTALL_DOCS_URL}")
        return False

    running, diagnostic = _is_docker_daemon_running_internal(
        run_docker_command_func=_run_docker_status_command
    )
    if running:
        return True

    # Transient host load can occasionally make `docker info` status checks time
    # out while the daemon remains healthy. Retry once before showing warnings.
    if _diagnostic_looks_transient_daemon_timeout(diagnostic):
        print_info_debug(
            "[docker] daemon probe timed out; retrying once before recovery flow "
            f"(stage={stage})."
        )
        time.sleep(0.8)
        retry_running, retry_diagnostic = _is_docker_daemon_running_internal(
            run_docker_command_func=_run_docker_status_command
        )
        if retry_running:
            print_info_verbose("Docker daemon probe recovered after transient timeout.")
            return True
        diagnostic = retry_diagnostic

    print_warning("Docker daemon is not reachable, so image pull cannot continue yet.")
    print_info_debug(
        f"[docker] daemon diagnostic ({stage}): {mark_sensitive(diagnostic, 'detail')}"
    )

    if _diagnostic_points_to_podman_socket(diagnostic):
        if not _allow_podman_docker_api_mode():
            if _attempt_docker_host_engine_autoremediation(
                stage=stage,
                diagnostic=diagnostic,
            ):
                return True
            print_error(
                "Detected Docker CLI endpoint configured for Podman socket. "
                "ADscan requires Docker Engine by default."
            )
            print_instruction(
                "Use Docker Engine (recommended): unset DOCKER_HOST, start Docker daemon, and retry."
            )
            print_instruction(
                "If you explicitly want Podman Docker API mode, set "
                f"{_ALLOW_PODMAN_DOCKER_API_ENV}=1 and ensure podman.socket is running."
            )
            return False

        print_warning(
            "Detected Docker CLI endpoint pointing to a Podman socket that is not reachable."
        )
        if _is_interactive_launcher_session():
            start_podman_socket = Confirm.ask(
                "Try to start Podman user socket automatically now?",
                default=True,
            )
            if start_podman_socket and _attempt_start_user_podman_socket():
                return True
        elif _attempt_start_user_podman_socket():
            return True

        print_instruction(
            "If you use Podman as Docker API, start it manually: systemctl --user start podman.socket"
        )
        print_instruction(
            "If you intended to use Docker Engine instead, unset DOCKER_HOST and retry."
        )

    if _is_interactive_launcher_session():
        proceed = Confirm.ask(
            "Try to start the Docker daemon automatically now?",
            default=True,
        )
        if not proceed:
            print_instruction(
                "Start Docker manually (for example: sudo systemctl start docker) and retry."
            )
            return False

    return _ensure_docker_daemon_running_internal(
        docker_access_denied_func=docker_access_denied,
        run_docker_command_func=_run_docker_status_command,
        sudo_validate_func=_ensure_sudo_ticket_if_needed,
        run_systemctl_command_func=_run_systemctl_command_for_docker_service,
        print_warning_func=print_warning,
        print_info_func=print_info,
        print_info_debug_func=print_info_debug,
        print_info_verbose_func=print_info_verbose,
        print_success_verbose_func=print_success_verbose,
        print_error_func=print_error,
        print_exception_func=print_exception,
        set_docker_use_sudo_func=None,
    )


def _is_ci() -> bool:
    return bool(
        os.getenv("CI")
        or os.getenv("GITHUB_ACTIONS")
        or os.getenv("GITLAB_CI")
        or os.getenv("BUILD_NUMBER")
    )


def _host_listeners_on_port_53() -> tuple[set[str], bool, set[str], set[int]]:
    """Return (bound_ips, wildcard_bound, proc_names, pids) for host port 53.

    We check both TCP and UDP listeners via `ss`. This runs on the host before
    starting the ADscan container (which uses `--network host`).
    """
    bound_ips: set[str] = set()
    wildcard_bound = False
    proc_names: set[str] = set()
    pids: set[int] = set()

    def _parse_local_addr_port(local: str) -> tuple[str, int] | None:
        local = local.strip()
        if not local:
            return None
        # Some ss builds include an interface suffix (e.g., 127.0.0.1%lo:53).
        if "%" in local:
            if local.startswith("[") and "]" in local:
                # [fe80::1%lo]:53 -> [fe80::1]:53
                local = re.sub(r"%[^\\]]+", "", local)
            else:
                # 127.0.0.1%lo:53 -> 127.0.0.1:53
                local = local.split("%", 1)[0] + ":" + local.rsplit(":", 1)[1]
        # IPv6 addresses are typically bracketed: [::1]:53
        m = re.match(r"^\\[(?P<addr>.+)\\]:(?P<port>\\d+)$", local)
        if m:
            return m.group("addr"), int(m.group("port"))
        # IPv4 / wildcard entries: 127.0.0.1:53, *:53, 0.0.0.0:53
        if local.count(":") == 1:
            addr, port_str = local.rsplit(":", 1)
            if port_str.isdigit():
                return addr, int(port_str)
        # Some ss builds render IPv6 wildcard as :::53
        m = re.match(r"^(?P<addr>:::|::):(?P<port>\d+)$", local)
        if m:
            return "::", int(m.group("port"))
        return None

    try:
        tcp = subprocess.run(  # noqa: S603
            ["ss", "-Hn", "-ltnup"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        tcp = None

    try:
        udp = subprocess.run(  # noqa: S603
            ["ss", "-Hn", "-lunp"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        udp = None

    combined = "\n".join(
        [
            (tcp.stdout or "") if tcp else "",
            (udp.stdout or "") if udp else "",
        ]
    )
    for line in combined.splitlines():
        # In numeric mode (`-n`), port 53 is always shown as ":53" (not ":domain").
        # Still, avoid false positives by parsing the local port explicitly.
        if ":53" not in line:
            continue

        parts = line.split()
        # ss output shape: <netid> <state> <recv-q> <send-q> <local> <peer> ...
        if len(parts) < 6:
            continue
        local = parts[4]
        parsed = _parse_local_addr_port(local)
        if not parsed:
            continue
        addr, port = parsed
        if port != 53:
            continue

        if addr in {"0.0.0.0", "*", "::"}:
            wildcard_bound = True
            continue

        # Record explicit IP binds (127.0.0.x, 127.0.0.53, etc).
        bound_ips.add(addr)
        # ss example: users:(("unbound",pid=97229,fd=4))
        # Prefer simple parsing over regex here: a malformed pattern would
        # crash the whole docker launcher path in CI.
        users_marker = 'users:(("'
        users_idx = line.find(users_marker)
        if users_idx != -1:
            name_start = users_idx + len(users_marker)
            name_end = line.find('"', name_start)
            if name_end != -1 and name_end > name_start:
                proc_names.add(line[name_start:name_end])

        pid_marker = "pid="
        pid_idx = line.find(pid_marker)
        if pid_idx != -1:
            pid_start = pid_idx + len(pid_marker)
            pid_end = pid_start
            while pid_end < len(line) and line[pid_end].isdigit():
                pid_end += 1
            if pid_end > pid_start:
                try:
                    pids.add(int(line[pid_start:pid_end]))
                except ValueError:
                    pass

    return bound_ips, wildcard_bound, proc_names, pids


def _host_stop_dns_services_best_effort(proc_names: set[str], pids: set[int]) -> bool:
    """Best-effort stop common DNS services on the host (requires sudo).

    Attempts `systemctl stop` for known service names, and falls back to killing
    the detected PIDs.
    """
    if os.geteuid() != 0 and not _ensure_sudo_ticket_if_needed():
        return False

    candidates: list[str] = []
    for name in sorted(proc_names):
        if name in {"dnsmasq", "unbound", "systemd-resolved"}:
            candidates.append(name)

    ok = True
    for svc in candidates:
        argv = ["systemctl", "stop", svc]
        if os.geteuid() != 0:
            argv = ["sudo", "--preserve-env=CONTAINER_SHARED_TOKEN", "-n"] + argv
        proc = subprocess.run(argv, check=False, capture_output=True, text=True)  # noqa: S603
        if proc.returncode != 0:
            ok = False

    if ok:
        return True

    # Fallback: kill the PIDs holding port 53 (best-effort).
    for pid in sorted(pids):
        argv = ["kill", "-TERM", str(pid)]
        if os.geteuid() != 0:
            argv = ["sudo", "--preserve-env=CONTAINER_SHARED_TOKEN", "-n"] + argv
        subprocess.run(argv, check=False, capture_output=True, text=True)  # noqa: S603
    # Give the system a moment to release sockets.
    time.sleep(1)
    return True


def _claim_container_local_resolver_ip(
    *,
    command_name: str,
) -> tuple[str, "_runtime_session.LockHandle | None"] | None:
    """Atomically claim a free loopback IP for the in-container resolver.

    With ``--network host`` the container shares the host network namespace,
    so each launcher must end up on a different ``127/8`` address. The IP
    is reserved with ``flock`` against the per-IP lock file so two
    launchers never race past the ``ss`` check and both pick the same
    address.

    Returns ``(ip, lock_handle)`` on success or ``None`` when no IP can be
    claimed. The lock_handle is ``None`` only when ``ADSCAN_LOCAL_RESOLVER_IP``
    overrides the selection (operator opt-in escape hatch — they take
    responsibility for ensuring nobody else uses that IP).
    """
    explicit = os.getenv("ADSCAN_LOCAL_RESOLVER_IP", "").strip()
    if explicit:
        if explicit.startswith("127.") and explicit.count(".") == 3:
            print_info_debug(
                f"[docker] Using explicit ADSCAN_LOCAL_RESOLVER_IP={explicit}"
            )
            return explicit, None
        print_warning(
            f"Ignoring invalid ADSCAN_LOCAL_RESOLVER_IP value: {explicit!r} "
            "(expected an IPv4 loopback like 127.0.0.2)."
        )

    bound_ips, wildcard_bound, proc_names, pids = _host_listeners_on_port_53()

    if wildcard_bound:
        print_warning(
            "Port 53 appears to be bound on all interfaces (0.0.0.0/[::]). "
            "This prevents ADscan's local DNS resolver from starting in the container."
        )

        default_yes = True
        proceed = True
        if not _is_ci() and sys.stdin.isatty():
            proceed = Confirm.ask(
                "Stop the host DNS service(s) using port 53 to allow ADscan to run?",
                default=default_yes,
            )
        if proceed:
            stopped = _host_stop_dns_services_best_effort(proc_names, pids)
            if not stopped:
                print_warning(
                    "Could not stop host DNS services automatically. "
                    "If you have a DNS daemon bound to 0.0.0.0:53, stop it and retry."
                )
                return None
            # Re-snapshot after stop attempt.
            bound_ips, wildcard_bound, _, _ = _host_listeners_on_port_53()
            if wildcard_bound:
                print_warning(
                    "Port 53 still appears bound on all interfaces after stop attempt."
                )
                return None
        else:
            print_warning(
                "Cannot proceed without a free loopback port for the local DNS resolver."
            )
            return None

    claim = _runtime_session.claim_resolver_ip(
        skip_ips=bound_ips, command_name=command_name
    )
    if claim is None:
        print_warning(
            "All loopback IPs for the local resolver appear in use — either bound on the host "
            "or reserved by other ADscan launchers."
        )
        print_instruction(
            "Stop one of the running ADscan sessions, or set ADSCAN_LOCAL_RESOLVER_IP=127.0.0.X "
            "to a verified-free address."
        )
        return None
    ip, handle = claim
    print_info_debug(f"[docker] claimed local resolver IP: {ip}")
    return ip, handle


def _ensure_container_shared_token() -> str:
    """Ensure CONTAINER_SHARED_TOKEN exists for this launcher process.

    Returns:
        A process-local ephemeral token (stable within the current process).
    """
    global _EPHEMERAL_CONTAINER_SHARED_TOKEN
    if _EPHEMERAL_CONTAINER_SHARED_TOKEN is None:
        _EPHEMERAL_CONTAINER_SHARED_TOKEN = secrets.token_urlsafe(48)
        print_info_debug(
            "[host-helper] Generated ephemeral CONTAINER_SHARED_TOKEN for this launcher process."
        )

    # Export only as an internal transport mechanism for child processes
    # (sudo --preserve-env + docker -e), not as user-provided configuration.
    os.environ["CONTAINER_SHARED_TOKEN"] = _EPHEMERAL_CONTAINER_SHARED_TOKEN
    return _EPHEMERAL_CONTAINER_SHARED_TOKEN


def _reset_host_helper_log() -> None:
    """Truncate the host-helper log so a launch shows only the current run.

    The log is written append-only across launches, so a failure panel would
    otherwise surface errors mixed across many past runs. Truncating in place
    at the start of each launch keeps the path stable while scoping the
    diagnostic tail to this run. Best-effort: never blocks startup.
    """
    log_path = _get_logs_dir() / "host-helper.log"
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "w", encoding="utf-8"):
            pass
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_info_debug(
            "[host-helper] failed to reset log for this run: "
            f"path={mark_sensitive(str(log_path), 'path')} "
            f"error={mark_sensitive(str(exc), 'error')}"
        )


def _print_host_helper_log_tail(*, max_lines: int = 40) -> None:
    """Emit the latest host-helper log lines for troubleshooting."""
    log_path = _get_logs_dir() / "host-helper.log"
    try:
        if not log_path.is_file():
            print_info_debug(
                "[host-helper] log tail unavailable: "
                f"path={mark_sensitive(str(log_path), 'path')} missing"
            )
            return
        raw = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_info_debug(
            "[host-helper] failed reading log tail: "
            f"path={mark_sensitive(str(log_path), 'path')} "
            f"error={mark_sensitive(str(exc), 'error')}"
        )
        return

    lines = raw.splitlines()
    if not lines:
        print_info_debug(
            "[host-helper] log tail is empty: "
            f"path={mark_sensitive(str(log_path), 'path')}"
        )
        return
    tail = "\n".join(lines[-max_lines:])
    print_info_debug("[host-helper] log tail:\n" + mark_sensitive(tail, "detail"))


def _wait_for_host_helper_ready(
    *,
    proc: subprocess.Popen[str],
    socket_path: Path,
    timeout_seconds: float = 8.0,
) -> bool:
    """Wait until the host helper socket responds to a ping request."""
    from adscan_launcher.host_privileged_helper import (  # noqa: PLC0415
        HostHelperError,
        host_helper_client_request,
    )

    deadline = time.monotonic() + max(float(timeout_seconds), 1.0)
    attempt = 0
    last_error: Exception | None = None

    while time.monotonic() < deadline:
        attempt += 1

        returncode = proc.poll()
        if returncode is not None:
            print_warning("Host helper exited before becoming ready.")
            print_info_debug(
                "[host-helper] readiness failed: "
                f"socket={mark_sensitive(str(socket_path), 'path')} "
                f"attempt={attempt} exit_code={returncode}"
            )
            _print_host_helper_log_tail()
            return False

        if not socket_path.exists():
            time.sleep(0.15)
            continue

        try:
            resp = host_helper_client_request(
                str(socket_path),
                op="ping",
                payload={},
                timeout_seconds=1.5,
            )
            if resp.ok:
                print_info_debug(
                    "[host-helper] ready: "
                    f"socket={mark_sensitive(str(socket_path), 'path')} "
                    f"attempt={attempt}"
                )
                return True
            last_error = HostHelperError(resp.message or "ping returned not-ok")
        except (HostHelperError, OSError) as exc:
            last_error = exc
            print_info_debug(
                "[host-helper] readiness probe failed: "
                f"attempt={attempt} "
                f"error={mark_sensitive(str(exc), 'error')}"
            )
        time.sleep(0.2)

    print_warning("Host helper did not become ready within the expected time window.")
    if last_error is not None:
        print_info_debug(
            "[host-helper] readiness final error: "
            f"{mark_sensitive(str(last_error), 'error')}"
        )
    print_info_debug(
        "[host-helper] readiness timeout: "
        f"socket={mark_sensitive(str(socket_path), 'path')}"
    )
    _print_host_helper_log_tail()
    return False


def _spawn_host_helper_process(
    *,
    socket_path: Path,
    force_self_executable: bool = False,
) -> subprocess.Popen[str]:
    """Spawn the privileged host helper process."""

    def _prepend_path_entry(existing: str, entry: str) -> str:
        parts = [p for p in str(existing or "").split(os.pathsep) if p]
        if entry not in parts:
            parts.insert(0, entry)
        return os.pathsep.join(parts)

    def _build_host_helper_launch() -> tuple[list[str], dict[str, str], str]:
        env = os.environ.copy()
        preserve_env_vars = ["CONTAINER_SHARED_TOKEN"]
        launch_mode = "self-executable"
        # Avoid root-owned __pycache__ files in repo/workspace when helper is
        # started via sudo Python in CI/self-hosted runners.
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        # For Python launcher installs (pip/pipx/uv), invoking the console
        # script under sudo can fail in two common ways:
        #   1) root cannot import adscan_launcher from user-site paths
        #   2) the resolved `adscan` entrypoint does not expose `host-helper`
        #      (mixed/older wrapper on PATH)
        # Use a direct inline import of host_privileged_helper and inject
        # PYTHONPATH explicitly to avoid relying on CLI subcommand parsing.
        if not bool(getattr(sys, "frozen", False)) and not force_self_executable:
            package_root = str(Path(__file__).resolve().parent.parent)
            if package_root:
                env["PYTHONPATH"] = _prepend_path_entry(
                    env.get("PYTHONPATH", ""),
                    package_root,
                )
                launch_mode = "python-inline-host-helper"
                python_exec = str(sys.executable or "").strip() or "python3"
                inline_host_helper_entry = (
                    "from adscan_launcher.host_privileged_helper import "
                    "run_host_helper_server as _run;"
                    "import sys;"
                    "raise SystemExit(_run(sys.argv[1]))"
                )
                argv = [
                    python_exec,
                    "-B",
                    "-c",
                    inline_host_helper_entry,
                    str(socket_path),
                ]
            else:
                argv = [
                    _resolve_self_executable(),
                    "host-helper",
                    "--socket",
                    str(socket_path),
                ]
        else:
            if force_self_executable and not bool(getattr(sys, "frozen", False)):
                launch_mode = "self-executable-forced"
            argv = [
                _resolve_self_executable(),
                "host-helper",
                "--socket",
                str(socket_path),
            ]

        if os.geteuid() != 0:
            preserve = ",".join(preserve_env_vars)
            # Only force non-interactive sudo (`-n`) when the session cannot
            # prompt (CI / NOPASSWD), where blocking on a password must never
            # happen. In an interactive terminal we DROP `-n` so the child
            # sudo can reuse the cached credential timestamp (or prompt on
            # /dev/tty when the timestamp is not honoured for this tty),
            # instead of failing with "a password is required".
            non_interactive = is_non_interactive()
            sudo_prefix = ["sudo", f"--preserve-env={preserve}"]
            if non_interactive:
                sudo_prefix.append("-n")
            print_info_debug(
                "[host-helper] sudo mode: "
                f"non_interactive={str(non_interactive).lower()} "
                f"flag_n={'yes' if non_interactive else 'no'}"
            )
            if launch_mode.startswith("python-") and env.get("PYTHONPATH", "").strip():
                # `sudo` can filter PYTHONPATH even when preserving env vars.
                # Pass it via `env` so module resolution remains stable.
                argv = (
                    sudo_prefix
                    + [
                        "env",
                        f"PYTHONPATH={env['PYTHONPATH']}",
                        "PYTHONDONTWRITEBYTECODE=1",
                    ]
                    + argv
                )
            else:
                argv = sudo_prefix + argv

        print_info_debug(
            "[host-helper] launch context: "
            f"mode={launch_mode} socket={mark_sensitive(str(socket_path), 'path')}"
        )
        return argv, env, launch_mode

    socket_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if socket_path.exists():
            socket_path.unlink()
    except OSError:
        pass

    argv, launch_env, _launch_mode = _build_host_helper_launch()

    logs_dir = _get_logs_dir()
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / "host-helper.log"
    log_fh = None
    try:
        log_fh = open(log_path, "a", encoding="utf-8")  # noqa: SIM115
        proc = subprocess.Popen(  # noqa: S603
            argv,
            stdin=subprocess.DEVNULL,
            stdout=log_fh,
            stderr=log_fh,
            text=True,
            env=launch_env,
        )
    except OSError:
        proc = subprocess.Popen(  # noqa: S603
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            env=launch_env,
        )
    finally:
        if log_fh is not None:
            try:
                log_fh.close()
            except OSError:
                pass

    return proc


def _start_host_helper(*, socket_path: Path) -> subprocess.Popen[str] | None:
    """Start the privileged host helper via sudo (best effort)."""
    _ensure_container_shared_token()

    if not _ensure_sudo_ticket_if_needed():
        print_warning(
            "Sudo authorization is required to start the host helper in Docker mode."
        )
        print_instruction("Run `sudo -v` and retry the command.")
        print_info_debug("[host-helper] startup aborted: sudo validation failed")
        return None

    # Scope the log to this launch so the diagnostic tail on failure reflects
    # only the current run, not errors accumulated across past launches.
    _reset_host_helper_log()

    # The forced self-executable fallback only makes sense for PyInstaller
    # (frozen) PRO binaries. For pip/pipx/uv installs it resolves the `adscan`
    # entrypoint on PATH, which may be a stale wrapper lacking the
    # `host-helper` subcommand and unable to import `adscan_launcher`. So for
    # non-frozen installs we never force it: attempt 2 retries the reliable
    # inline `sys.executable -m` path, recovering only from transient startup
    # races.
    is_frozen = bool(getattr(sys, "frozen", False))
    for launch_attempt, force_self_exec in ((1, False), (2, True)):
        proc = _spawn_host_helper_process(
            socket_path=socket_path,
            force_self_executable=force_self_exec and is_frozen,
        )
        if _wait_for_host_helper_ready(proc=proc, socket_path=socket_path):
            return proc
        _stop_host_helper(proc)
        if launch_attempt == 1:
            print_warning("Host helper readiness failed. Retrying once...")

    print_info_debug("[host-helper] startup failed after retry attempts.")
    return None


def _probe_sudo_noninteractive_status() -> tuple[str, str]:
    """Return best-effort sudo availability status for troubleshooting output."""
    if os.geteuid() == 0:
        return "root", ""
    if not shutil.which("sudo"):
        return "missing", ""
    try:
        proc = subprocess.run(  # noqa: S603
            ["sudo", "-n", "true"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        telemetry.capture_exception(exc)
        return "error", str(exc)

    if proc.returncode == 0:
        return "ok", ""
    stderr = str(proc.stderr or "").strip()
    if "a password is required" in stderr.lower():
        return "needs_password", stderr
    return "denied", stderr


def _collect_host_helper_runtime_diagnostics(*, socket_path: Path) -> dict[str, str]:
    """Collect concise host-helper diagnostics for operator-facing troubleshooting."""
    diagnostics: dict[str, str] = {}

    log_path = _get_logs_dir() / "host-helper.log"
    diagnostics["socket_path"] = str(socket_path)
    diagnostics["socket_exists"] = str(socket_path.exists()).lower()
    diagnostics["log_path"] = str(log_path)
    diagnostics["log_exists"] = str(log_path.exists()).lower()
    if log_path.exists():
        try:
            diagnostics["log_size_bytes"] = str(log_path.stat().st_size)
        except OSError as exc:
            telemetry.capture_exception(exc)
            diagnostics["log_size_bytes"] = f"error:{exc}"
    else:
        diagnostics["log_size_bytes"] = "0"

    daemon_ok, daemon_diag = _is_docker_daemon_running_internal(
        run_docker_command_func=_run_docker_status_command
    )
    diagnostics["docker_daemon_reachable"] = str(bool(daemon_ok)).lower()
    if daemon_diag:
        diagnostics["docker_daemon_diagnostic"] = str(daemon_diag).strip()

    sudo_status, sudo_detail = _probe_sudo_noninteractive_status()
    diagnostics["sudo_status"] = sudo_status
    if sudo_detail:
        diagnostics["sudo_detail"] = sudo_detail

    return diagnostics


def _print_host_helper_runtime_troubleshooting(
    *,
    command_name: str,
    socket_path: Path,
    failure_reason: str,
    diagnostics: dict[str, str] | None = None,
) -> None:
    """Render actionable troubleshooting guidance for host-helper startup failures."""
    diagnostics = diagnostics or _collect_host_helper_runtime_diagnostics(
        socket_path=socket_path
    )
    log_path = _get_logs_dir() / "host-helper.log"
    details = [
        "ADscan Docker mode requires the host helper for privileged host operations.",
        f"Command: {command_name}",
        f"Failure: {failure_reason}",
        f"Helper socket: {mark_sensitive(diagnostics.get('socket_path', 'UNKNOWN'), 'path')}",
        (
            "Socket present: "
            f"{mark_sensitive(diagnostics.get('socket_exists', 'unknown'), 'detail')}"
        ),
        f"Helper log: {mark_sensitive(diagnostics.get('log_path', str(log_path)), 'path')}",
        (
            "Log size (bytes): "
            f"{mark_sensitive(diagnostics.get('log_size_bytes', 'unknown'), 'detail')}"
        ),
        (
            "Docker daemon reachable: "
            f"{mark_sensitive(diagnostics.get('docker_daemon_reachable', 'unknown'), 'status')}"
        ),
        (
            "Sudo status: "
            f"{mark_sensitive(diagnostics.get('sudo_status', 'unknown'), 'status')}"
        ),
    ]

    daemon_diag = diagnostics.get("docker_daemon_diagnostic", "").strip()
    if daemon_diag:
        details.append(f"Daemon diagnostic: {mark_sensitive(daemon_diag, 'detail')}")

    sudo_detail = diagnostics.get("sudo_detail", "").strip()
    if sudo_detail:
        details.append(f"Sudo detail: {mark_sensitive(sudo_detail, 'detail')}")

    print_panel(
        "\n".join(details),
        title="Host Helper Required",
        border_style="yellow",
    )
    marked_log_path = mark_sensitive(str(log_path), "path")
    print_instruction(f"Check host-helper logs: tail -n 200 {marked_log_path}")
    print_instruction("Check daemon state: docker info || sudo docker info")
    print_instruction("If needed, start daemon: sudo systemctl start docker")
    print_instruction("If sudo is required, refresh credentials: sudo -v")
    print_instruction(f"Retry: adscan {command_name}")
    print_instruction(f"Troubleshooting guide: {_HOST_HELPER_TROUBLESHOOTING_DOCS_URL}")


def _ensure_host_helper_runtime_ready(
    *,
    command_name: str,
    run_dir: Path,
) -> tuple[subprocess.Popen[str] | None, Path]:
    """Start and validate host-helper readiness for Docker-mode runtime commands."""
    helper_socket = run_dir / DEFAULT_HOST_HELPER_SOCKET_NAME
    helper_proc = _start_host_helper(socket_path=helper_socket)
    if helper_proc is not None:
        return helper_proc, helper_socket

    diagnostics = _collect_host_helper_runtime_diagnostics(socket_path=helper_socket)
    telemetry.capture(
        "docker_host_helper_unavailable",
        {
            "command_name": command_name,
            "socket_exists": diagnostics.get("socket_exists", "unknown"),
            "docker_daemon_reachable": diagnostics.get(
                "docker_daemon_reachable",
                "unknown",
            ),
            "sudo_status": diagnostics.get("sudo_status", "unknown"),
        },
    )
    _print_host_helper_runtime_troubleshooting(
        command_name=command_name,
        socket_path=helper_socket,
        failure_reason="Host helper startup failed or did not become ready.",
        diagnostics=diagnostics,
    )
    return None, helper_socket


def _stop_host_helper(proc: subprocess.Popen[str] | None) -> None:
    if proc is None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=3)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _detect_gpu_docker_run_args() -> tuple[str, ...]:
    """Best-effort GPU passthrough flags for docker run.

    IMPORTANT:
        Intel/AMD `/dev/dri` passthrough remains **opt-in** because it can break
        OpenCL/Hashcat on some hosts (especially when running the container as a
        non-root UID/GID). NVIDIA is safer to enable automatically *only when*
        Docker already advertises the NVIDIA runtime on the host.

        Enable with:
            `export ADSCAN_DOCKER_GPU=auto`   (best-effort)
            `export ADSCAN_DOCKER_GPU=dri`    (force /dev/dri passthrough)
            `export ADSCAN_DOCKER_GPU=nvidia` (force --gpus all when supported)
            `export ADSCAN_DOCKER_GPU=all`    (dri + nvidia)
    """
    args: list[str] = []

    raw_mode = os.getenv("ADSCAN_DOCKER_GPU", "").strip().lower()
    if raw_mode in {"0", "false", "no", "off"}:
        return ()
    mode = raw_mode or "nvidia-auto"

    enable_dri = mode in {"1", "true", "yes", "on", "auto", "dri", "all"}
    enable_nvidia = mode in {
        "1",
        "true",
        "yes",
        "on",
        "auto",
        "nvidia",
        "all",
        "nvidia-auto",
    }

    # Intel/AMD iGPU/dri devices (best-effort, opt-in).
    if enable_dri and Path("/dev/dri").exists():
        args.extend(["--device", "/dev/dri"])

    # NVIDIA: requires nvidia-container-toolkit + docker `--gpus`.
    has_nvidia_dev = enable_nvidia and any(
        Path(p).exists() for p in ("/dev/nvidiactl", "/dev/nvidia0", "/dev/nvidia-uvm")
    )
    if has_nvidia_dev:
        try:
            help_proc = run_docker(
                ["docker", "run", "--help"],
                check=False,
                capture_output=True,
                timeout=10,
            )
            if help_proc.returncode == 0 and _DOCKER_RUN_HELP_HAS_GPUS_RE.search(
                help_proc.stdout or ""
            ):
                info_proc = run_docker(
                    ["docker", "info"],
                    check=False,
                    capture_output=True,
                    timeout=10,
                )
                # Only enable when docker advertises the nvidia runtime.
                if "nvidia" in (info_proc.stdout or "").lower():
                    args.extend(["--gpus", "all"])
        except Exception:
            # Never fail hard on GPU detection.
            pass

    if args:
        print_info_debug(f"[docker] GPU passthrough enabled: {args}")
    return tuple(args)


def _ensure_host_mount_dir_writable(path: Path, *, description: str) -> bool:
    """Ensure host mount directory exists and is writable by the current user.

    Docker-mode runs the container entrypoint as root, repairs ownership
    inside the container on the bind-mounted tree without traversing nested
    mount points, and then drops privileges to the host UID/GID. This avoids
    root-owned files on the host without trying to recurse into CIFS mounts or
    requiring the host to run privileged `chown` commands.

    Args:
        path: Host path that will be bind-mounted into the container.
        description: Human-readable label for messages.

    Returns:
        True if the directory exists (best-effort). Writability is repaired
        inside the container when possible.
    """
    try:
        path.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        print_warning(f"{description} directory is not accessible: {path}")
        print_instruction(f"Fix manually: sudo chown -R $USER:$USER {path}")
        return False

    if os.access(path, os.W_OK):
        return True

    try:
        st = path.stat()
        owner = f"{st.st_uid}:{st.st_gid}"
    except OSError:
        owner = "unknown"

    print_warning(
        f"{description} directory is not writable and may be owned by root: {path} (owner={owner})"
    )
    print_instruction(
        "ADscan will attempt to repair this automatically inside the container. "
        "If it still fails, run: sudo chown -R $USER:$USER "
        f"{path}"
    )
    return True


def _print_docker_install_summary() -> None:
    """Render a professional installation summary panel for Docker mode."""
    from rich.console import Group
    from rich.text import Text
    from rich.table import Table
    from rich.panel import Panel
    from rich.box import ROUNDED

    from adscan_core.rich_output import (
        _get_console,
        _get_telemetry_console,
        BRAND_COLORS,
    )

    console = _get_console()
    telemetry_console = _get_telemetry_console()
    renderables: list = []

    # Telemetry section
    tele_header = Text("Telemetry", style=f"bold {BRAND_COLORS['info']}")
    renderables.append(tele_header)

    from adscan_core.telemetry import _is_telemetry_enabled

    telemetry_enabled = _is_telemetry_enabled()
    if telemetry_enabled:
        tele_status = Text("  ON", style="bold green")
        tele_status.append(" -- anonymous, sanitized usage analytics", style="dim")
        renderables.append(tele_status)
        renderables.append(Text(""))

        tele_detail = Table.grid(padding=(0, 1))
        tele_detail.add_column(justify="right", style="dim", no_wrap=True, min_width=12)
        tele_detail.add_column(justify="left", style="dim")
        tele_detail.add_row("What", "Commands run, feature usage, errors")
        tele_detail.add_row("Not sent", "IPs, domains, credentials, paths")
        tele_detail.add_row("Session off", "export ADSCAN_TELEMETRY=0")
        tele_detail.add_row("Permanent", "telemetry off  (inside ADscan)")
        tele_detail.add_row("Details", "adscanpro.com/docs/telemetry")
        renderables.append(tele_detail)
    else:
        tele_status = Text("  OFF", style="bold yellow")
        tele_status.append(" -- no data is collected", style="dim")
        renderables.append(tele_status)

    panel = Panel(
        Group(*renderables),
        title="[bold]Installation Summary[/bold]",
        border_style="green",
        box=ROUNDED,
        padding=(1, 2),
        expand=True,
    )

    console.print()
    console.print(panel)
    console.print()
    if telemetry_console is not None:
        telemetry_console.print()
        telemetry_console.print(panel)
        telemetry_console.print()

    print_success("ADscan installation complete")

    from rich.syntax import Syntax

    next_steps = Syntax(
        "# Launch the interactive CLI\nadscan start",
        "bash",
        theme="monokai",
        background_color=None,
    )
    next_panel = Panel(
        next_steps,
        title="[bold]Next Steps[/bold]",
        border_style=BRAND_COLORS["info"],
        padding=(1, 2),
    )
    console.print(next_panel)
    if telemetry_console is not None:
        telemetry_console.print(next_panel)


def handle_install_docker(
    *,
    pull_timeout_seconds: int | None = None,
    allow_low_memory: bool = False,
) -> bool:
    """Install ADscan via Docker (pull image)."""
    del allow_low_memory
    _emit_docker_runtime_context(command_name="install")
    _emit_docker_host_resources_context(command_name="install")

    install_lock = _acquire_install_lock_or_warn(command_name="install")
    if install_lock is None:
        return False
    try:
        return _do_install_docker(pull_timeout_seconds=pull_timeout_seconds)
    finally:
        _runtime_session.release_lock(install_lock)


def _do_install_docker(*, pull_timeout_seconds: int | None) -> bool:
    """Install body that runs while the install lock is held."""
    telemetry.capture(
        "docker_install_started",
        {
            "in_container": is_docker_env(),
        },
    )
    start_time = time.monotonic()

    image = _get_docker_image()
    print_info("Installing ADscan (Docker mode)...")

    if not docker_available():
        telemetry.capture(
            "docker_install_check_docker_availability",
            {"docker_available": False, "docker_in_path": False},
        )
        telemetry.capture(
            "docker_install_failed",
            {
                "success": False,
                "total_duration_seconds": time.monotonic() - start_time,
                "failure_stage": "docker_check",
                "failure_reason": "docker_not_installed",
            },
        )
        print_error("Docker is not installed or not in PATH.")
        print_instruction(
            f"Install Docker Engine, then retry. Guide: {_DOCKER_INSTALL_DOCS_URL}"
        )
        return False

    telemetry.capture(
        "docker_install_check_docker_availability",
        {"docker_available": True, "needs_sudo": docker_needs_sudo()},
    )

    storage_path = _get_docker_storage_path()
    free_disk_gb, free_mem_gb = _log_install_resource_status(storage_path)
    if free_disk_gb < _MIN_DOCKER_INSTALL_FREE_GB:
        panel_lines = [
            f"Required: ≥ {_MIN_DOCKER_INSTALL_FREE_GB} GB free",
            f"Available: {free_disk_gb:.2f} GB",
            f"Docker storage path: {storage_path}",
            "Free up disk space and retry.",
        ]
        print_panel(
            "\n".join(panel_lines),
            title="Insufficient Disk Space",
            border_style="yellow",
        )
        print_info_debug(
            f"[install] Disk check failed at {storage_path} | free={free_disk_gb:.2f} GB"
        )
        print_info_debug(f"[install] Free RAM at install: {free_mem_gb:.2f} GB")
        return False

    print_info(f"Pulling image: {image}")
    image_pull_start = time.monotonic()
    telemetry.capture("docker_install_pull_adscan_image_started", {"image": image})

    pull_timeout = _normalize_pull_timeout_seconds(pull_timeout_seconds)
    timeout_label = "disabled" if pull_timeout is None else f"{pull_timeout}s"
    print_info_debug(f"[docker] pull timeout: {timeout_label}")
    if not _maybe_warn_about_slow_network_before_pull(
        image=image, pull_timeout=pull_timeout
    ):
        telemetry.capture(
            "docker_install_cancelled",
            {
                "failure_stage": "image_pull_prompt",
                "reason": "operator_cancelled_before_pull",
            },
        )
        print_warning("Installation cancelled before Docker image download.")
        return False
    resolved_image = _ensure_image_pulled_with_legacy_fallback(
        pull_timeout=pull_timeout,
        stream_output=True,
    )
    if not resolved_image:
        telemetry.capture(
            "docker_install_pull_adscan_image_failed",
            {"failure_reason": "network_or_timeout"},
        )
        telemetry.capture(
            "docker_install_failed",
            {
                "success": False,
                "total_duration_seconds": time.monotonic() - start_time,
                "failure_stage": "image_pull",
                "failure_reason": "image_pull_failed",
            },
        )
        _print_docker_image_pull_failure_guidance(
            image=image,
            pull_timeout=pull_timeout,
            command_name="install",
        )
        return False
    image = resolved_image

    telemetry.capture(
        "docker_install_pull_adscan_image_completed",
        {
            "success": True,
            "duration_seconds": time.monotonic() - image_pull_start,
        },
    )
    print_success("ADscan Docker image pulled successfully.")

    telemetry.capture(
        "docker_install_completed",
        {
            "success": True,
            "total_duration_seconds": time.monotonic() - start_time,
            "image": image,
        },
    )

    _print_docker_install_summary()

    return True


def handle_check_docker(
    *,
    allow_low_memory: bool = False,
) -> bool:
    """Check ADscan Docker-mode prerequisites."""
    del allow_low_memory
    _emit_docker_runtime_context(command_name="check")
    _emit_docker_host_resources_context(command_name="check")
    image = _select_existing_or_preferred_image()
    acq = _RuntimeAcquisition()
    all_ok = True
    try:
        print_info("Checking ADscan Docker mode...")
        if not docker_available():
            print_error("Docker is not installed or not in PATH.")
            print_instruction(
                f"Install Docker + Docker Compose, then retry. Guide: {_DOCKER_INSTALL_DOCS_URL}"
            )
            return False

        if not image_exists(image):
            print_warning(f"ADscan docker image not present: {image}")
            print_instruction("Run: adscan install (pulls the latest image).")
            all_ok = False

        if all_ok:
            workspaces_dir = _get_workspaces_dir()
            config_dir = _get_config_dir()
            codex_dir = _get_codex_container_dir()
            logs_dir = _get_logs_dir()
            run_dir = _get_run_dir()
            state_dir = _get_state_dir()
            if not _ensure_host_mount_dir_writable(
                workspaces_dir, description="Workspaces"
            ):
                return False
            if not _ensure_host_mount_dir_writable(config_dir, description="Config"):
                return False
            if not _ensure_host_mount_dir_writable(
                codex_dir, description="Codex Container Auth"
            ):
                return False
            if not _ensure_host_mount_dir_writable(logs_dir, description="Logs"):
                return False
            if not _ensure_host_mount_dir_writable(run_dir, description="Runtime"):
                return False
            if not _ensure_host_mount_dir_writable(state_dir, description="State"):
                return False

            acq.session_dir = _prepare_runtime_session_dir(command_name="check")
            helper_proc, _helper_socket = _ensure_host_helper_runtime_ready(
                command_name="check",
                run_dir=acq.session_dir,
            )
            if helper_proc is None:
                all_ok = False
            else:
                # Stop the helper immediately — the probe below does not need it.
                _stop_host_helper(helper_proc)

            if all_ok:
                cfg = DockerRunConfig(
                    image=image,
                    workspaces_host_dir=workspaces_dir,
                    interactive=False,
                    extra_env=_build_runtime_license_env(image),
                    run_host_dir=acq.session_dir,
                )
                cmd = build_adscan_run_command(cfg, adscan_args=["--version"])
                print_info_debug(f"[docker] probe: {shell_quote_cmd(cmd)}")
                try:
                    proc = run_docker(cmd, check=False, capture_output=True, timeout=60)
                    if proc.returncode == 0:
                        print_success("Docker-mode execution probe succeeded.")
                    else:
                        all_ok = False
                        print_warning("Docker-mode execution probe failed.")
                        if proc.stderr:
                            print_info_debug(f"[docker] probe stderr:\n{proc.stderr}")
                        if proc.stdout:
                            print_info_debug(f"[docker] probe stdout:\n{proc.stdout}")
                except Exception as exc:  # pragma: no cover
                    telemetry.capture_exception(exc)
                    print_warning(
                        "Docker-mode execution probe failed due to an exception."
                    )
                    print_info_debug(f"[docker] probe exception: {exc}")
                    all_ok = False

        return all_ok
    finally:
        _release_runtime_acquisition(acq)


def handle_start_docker(
    *,
    verbose: bool,
    debug: bool,
    pull_timeout_seconds: int | None = None,
    allow_low_memory: bool = False,
    tui: bool = False,
) -> int:
    """Start ADscan inside Docker and return the docker exit code."""
    del allow_low_memory
    _emit_docker_runtime_context(command_name="start")
    _emit_docker_host_resources_context(command_name="start")
    image = _select_existing_or_preferred_image()
    acq = _RuntimeAcquisition()
    try:
        if not docker_available():
            print_error("Docker is not installed or not in PATH.")
            return 1
        resolved_image = _ensure_runtime_image_available(
            image=image,
            pull_timeout_seconds=pull_timeout_seconds,
            command_name="start",
        )
        if not resolved_image:
            return 1
        image = resolved_image

        workspaces = _get_workspaces_dir()
        config_dir = _get_config_dir()
        codex_dir = _get_codex_container_dir()
        logs_dir = _get_logs_dir()
        run_dir = _get_run_dir()
        state_dir = _get_state_dir()
        if not _ensure_host_mount_dir_writable(workspaces, description="Workspaces"):
            return 1
        if not _ensure_host_mount_dir_writable(config_dir, description="Config"):
            return 1
        if not _ensure_host_mount_dir_writable(
            codex_dir, description="Codex Container Auth"
        ):
            return 1
        if not _ensure_host_mount_dir_writable(logs_dir, description="Logs"):
            return 1
        if not _ensure_host_mount_dir_writable(run_dir, description="Runtime"):
            return 1
        if not _ensure_host_mount_dir_writable(state_dir, description="State"):
            return 1

        acq.session_dir = _prepare_runtime_session_dir(command_name="start")
        helper_proc, _helper_socket = _ensure_host_helper_runtime_ready(
            command_name="start",
            run_dir=acq.session_dir,
        )
        if helper_proc is None:
            return 1
        acq.helper_proc = helper_proc

        gpu_args = _detect_gpu_docker_run_args()
        resolver_claim = _claim_container_local_resolver_ip(command_name="start")
        if resolver_claim is None:
            return 1
        local_resolver_ip, acq.resolver_ip_lock = resolver_claim

        extra_run_args: list[str] = list(gpu_args)

        cfg = DockerRunConfig(
            image=image,
            workspaces_host_dir=workspaces,
            interactive=True,
            extra_run_args=tuple(extra_run_args),
            extra_env=tuple(
                list(_build_runtime_license_env(image))
                + [
                    ("ADSCAN_LOCAL_RESOLVER_IP", local_resolver_ip),
                    ("ADSCAN_DIAG_LOGGING", os.getenv("ADSCAN_DIAG_LOGGING", "")),
                ]
            ),
            run_host_dir=acq.session_dir,
        )

        adscan_args: list[str] = []
        adscan_args.append("start")
        if verbose:
            adscan_args.append("--verbose")
        if debug:
            adscan_args.append("--debug")
        if tui:
            adscan_args.append("--tui")

        # Non-blocking: warn (premium panel) if the runtime is rootless/userns,
        # so the operator sees what's degraded instead of a cryptic kernel EPERM.
        probe_and_warn_reduced_runtime(cfg)
        cmd = build_adscan_run_command(cfg, adscan_args=adscan_args)
        print_info_debug(f"[docker] start: {shell_quote_cmd(cmd)}")
        try:
            proc = run_docker(cmd, check=False, capture_output=False, timeout=None)
            return int(proc.returncode)
        except subprocess.SubprocessError as exc:
            telemetry.capture_exception(exc)
            print_error("Failed to start ADscan in Docker.")
            print_info_debug(f"[docker] start exception: {exc}")
            return 1
    finally:
        _release_runtime_acquisition(acq)


def handle_ci_docker(
    *,
    mode: str,
    workspace_type: str,
    interface: str,
    hosts: str | None,
    domain: str | None,
    dc_ip: str | None,
    username: str | None,
    password: str | None,
    workspace: str | None,
    verbose: bool,
    debug: bool,
    keep_workspace: bool,
    generate_report: bool,
    report_format: str,
    report_engine: str = "",
    report_renderer: str = "",
    report_template: str = "",
    report_theme: str = "",
    report_only: str = "",
    pull_timeout_seconds: int | None = None,
    allow_low_memory: bool = False,
) -> int:
    """Run `adscan ci` inside Docker and return the docker exit code."""
    del allow_low_memory
    _emit_docker_runtime_context(command_name="ci")
    _emit_docker_host_resources_context(command_name="ci")
    image = _select_existing_or_preferred_image()
    acq = _RuntimeAcquisition()
    try:
        if workspace and _runtime_session.normalize_workspace_name(workspace):
            workspace_lock = _acquire_workspace_lock_or_warn(
                command_name="ci",
                workspace_name=workspace,
            )
            if workspace_lock is _LOCK_CONTENDED:
                return 1
            if isinstance(workspace_lock, _runtime_session.LockHandle):
                acq.workspace_lock = workspace_lock

        if not docker_available():
            print_error("Docker is not installed or not in PATH.")
            return 1
        resolved_image = _ensure_runtime_image_available(
            image=image,
            pull_timeout_seconds=pull_timeout_seconds,
            command_name="ci",
        )
        if not resolved_image:
            return 1
        image = resolved_image

        workspaces_dir = _get_workspaces_dir()
        config_dir = _get_config_dir()
        codex_dir = _get_codex_container_dir()
        logs_dir = _get_logs_dir()
        run_dir = _get_run_dir()
        state_dir = _get_state_dir()
        if not _ensure_host_mount_dir_writable(
            workspaces_dir, description="Workspaces"
        ):
            return 1
        if not _ensure_host_mount_dir_writable(config_dir, description="Config"):
            return 1
        if not _ensure_host_mount_dir_writable(
            codex_dir, description="Codex Container Auth"
        ):
            return 1
        if not _ensure_host_mount_dir_writable(logs_dir, description="Logs"):
            return 1
        if not _ensure_host_mount_dir_writable(run_dir, description="Runtime"):
            return 1
        if not _ensure_host_mount_dir_writable(state_dir, description="State"):
            return 1

        acq.session_dir = _prepare_runtime_session_dir(command_name="ci")
        helper_proc, _helper_socket = _ensure_host_helper_runtime_ready(
            command_name="ci",
            run_dir=acq.session_dir,
        )
        if helper_proc is None:
            return 1
        acq.helper_proc = helper_proc

        is_ci_session = os.getenv("ADSCAN_SESSION_ENV") == "ci"
        interactive = bool(
            sys.stdin.isatty() and sys.stdout.isatty() and not is_ci_session
        )
        resolver_claim = _claim_container_local_resolver_ip(command_name="ci")
        if resolver_claim is None:
            return 1
        local_resolver_ip, acq.resolver_ip_lock = resolver_claim
        cfg = DockerRunConfig(
            image=image,
            workspaces_host_dir=workspaces_dir,
            interactive=interactive,
            extra_env=tuple(
                list(_build_runtime_license_env(image))
                + [
                    ("ADSCAN_LOCAL_RESOLVER_IP", local_resolver_ip),
                    ("ADSCAN_DIAG_LOGGING", os.getenv("ADSCAN_DIAG_LOGGING", "")),
                ]
            ),
            run_host_dir=acq.session_dir,
        )

        adscan_args: list[str] = []
        adscan_args.append("ci")
        adscan_args.append(mode)
        if debug:
            adscan_args.append("--debug")
        if verbose:
            adscan_args.append("--verbose")
        adscan_args.extend(["--type", workspace_type, "--interface", interface])

        if hosts:
            adscan_args.extend(["--hosts", hosts])
        if domain:
            adscan_args.extend(["--domain", domain])
        if dc_ip:
            adscan_args.extend(["--dc-ip", dc_ip])
        if username:
            adscan_args.extend(["--username", username])
        if password:
            adscan_args.extend(["--password", password])
        if workspace:
            adscan_args.extend(["--workspace", workspace])
        if keep_workspace:
            adscan_args.append("--keep-workspace")
        if generate_report:
            adscan_args.append("--generate-report")
            adscan_args.extend(["--report-format", report_format])
            if report_engine:
                adscan_args.extend(["--report-engine", report_engine])
            if report_renderer:
                adscan_args.extend(["--report-renderer", report_renderer])
            if report_template:
                adscan_args.extend(["--report-template", report_template])
            if report_theme:
                adscan_args.extend(["--report-theme", report_theme])
            if report_only:
                adscan_args.extend(["--only", report_only])

        probe_and_warn_reduced_runtime(cfg)
        cmd = build_adscan_run_command(cfg, adscan_args=adscan_args)
        print_info_debug(f"[docker] ci: {shell_quote_cmd(cmd)}")
        try:
            proc = run_docker(cmd, check=False, capture_output=False, timeout=None)
            return int(proc.returncode)
        except subprocess.SubprocessError as exc:
            telemetry.capture_exception(exc)
            print_error("Failed to run ADscan CI in Docker.")
            print_info_debug(f"[docker] ci exception: {exc}")
            return 1
    finally:
        _release_runtime_acquisition(acq)


def update_docker_image(*, pull_timeout_seconds: int | None = None) -> int:
    """Pull the configured ADscan Docker image.

    Returns:
        Process exit code (0 success).
    """
    _emit_docker_runtime_context(command_name="update")
    _emit_docker_host_resources_context(command_name="update")
    install_lock = _acquire_install_lock_or_warn(command_name="update")
    if install_lock is None:
        return 1
    try:
        image = _get_docker_image()
        if not docker_available():
            print_error("Docker is not installed or not in PATH.")
            return 1
        pull_timeout = _normalize_pull_timeout_seconds(pull_timeout_seconds)
        print_info(f"Pulling image: {image}")
        resolved_image = _ensure_image_pulled_with_legacy_fallback(
            pull_timeout=pull_timeout,
            stream_output=True,
        )
        if not resolved_image:
            _print_docker_image_pull_failure_guidance(
                image=image,
                pull_timeout=pull_timeout,
                command_name="update",
            )
            return 1
        image = resolved_image
        print_success("Docker image pulled successfully.")
        return 0
    finally:
        _runtime_session.release_lock(install_lock)


def run_adscan_passthrough_docker(
    *,
    adscan_args: list[str],
    verbose: bool,
    debug: bool,
    pull_timeout_seconds: int | None = None,
    allow_low_memory: bool = False,
    extra_env: list[tuple[str, str]] | None = None,
    extra_mounts: list[tuple[str, str]] | None = None,
) -> int:
    """Run an arbitrary `adscan ...` command inside the container (host-side).

    This is used by the PyPI launcher to avoid duplicating the full internal
    CLI argument parsing while still keeping Docker-mode preflight consistent.

    Args:
        extra_mounts: Optional ``(host_path, container_path)`` read-only file
            bind-mounts (e.g. a ``--scan-config`` file passed by absolute path
            outside the standard mounted tree).
    """
    del allow_low_memory
    _emit_docker_runtime_context(command_name="passthrough")
    _emit_docker_host_resources_context(command_name="passthrough")
    image = _select_existing_or_preferred_image()
    acq = _RuntimeAcquisition()
    try:
        passthrough_workspace = _extract_workspace_from_passthrough_args(adscan_args)
        if passthrough_workspace and _runtime_session.normalize_workspace_name(
            passthrough_workspace
        ):
            workspace_lock = _acquire_workspace_lock_or_warn(
                command_name="passthrough",
                workspace_name=passthrough_workspace,
            )
            if workspace_lock is _LOCK_CONTENDED:
                return 1
            if isinstance(workspace_lock, _runtime_session.LockHandle):
                acq.workspace_lock = workspace_lock

        if not docker_available():
            print_error("Docker is not installed or not in PATH.")
            return 1
        resolved_image = _ensure_runtime_image_available(
            image=image,
            pull_timeout_seconds=pull_timeout_seconds,
            command_name="passthrough",
        )
        if not resolved_image:
            return 1
        image = resolved_image

        workspaces_dir = _get_workspaces_dir()
        config_dir = _get_config_dir()
        codex_dir = _get_codex_container_dir()
        logs_dir = _get_logs_dir()
        run_dir = _get_run_dir()
        state_dir = _get_state_dir()
        if not _ensure_host_mount_dir_writable(
            workspaces_dir, description="Workspaces"
        ):
            return 1
        if not _ensure_host_mount_dir_writable(config_dir, description="Config"):
            return 1
        if not _ensure_host_mount_dir_writable(
            codex_dir, description="Codex Container Auth"
        ):
            return 1
        if not _ensure_host_mount_dir_writable(logs_dir, description="Logs"):
            return 1
        if not _ensure_host_mount_dir_writable(run_dir, description="Runtime"):
            return 1
        if not _ensure_host_mount_dir_writable(state_dir, description="State"):
            return 1

        acq.session_dir = _prepare_runtime_session_dir(command_name="passthrough")
        helper_proc, _helper_socket = _ensure_host_helper_runtime_ready(
            command_name="passthrough",
            run_dir=acq.session_dir,
        )
        if helper_proc is None:
            return 1
        acq.helper_proc = helper_proc

        interactive = bool(sys.stdin.isatty() and sys.stdout.isatty())
        resolver_claim = _claim_container_local_resolver_ip(command_name="passthrough")
        if resolver_claim is None:
            return 1
        local_resolver_ip, acq.resolver_ip_lock = resolver_claim

        cfg = DockerRunConfig(
            image=image,
            workspaces_host_dir=workspaces_dir,
            interactive=interactive,
            extra_env=tuple(
                list(_build_runtime_license_env(image))
                + [
                    ("ADSCAN_LOCAL_RESOLVER_IP", local_resolver_ip),
                    ("ADSCAN_DIAG_LOGGING", os.getenv("ADSCAN_DIAG_LOGGING", "")),
                ]
                # Engagement-posture toggles translated from the `ci` flags
                # (--offline -> ADSCAN_OFFLINE=1, --no-telemetry ->
                # ADSCAN_TELEMETRY=0). Appended last so an explicit toggle wins
                # over any inherited value; empty by default (behaviour unchanged).
                + list(extra_env or [])
            ),
            extra_mounts=tuple(extra_mounts or []),
            run_host_dir=acq.session_dir,
        )

        container_args: list[str] = list(adscan_args)
        if verbose:
            container_args.append("--verbose")
        if debug:
            container_args.append("--debug")

        probe_and_warn_reduced_runtime(cfg)
        cmd = build_adscan_run_command(cfg, adscan_args=container_args)
        print_info_debug(f"[docker] passthrough: {shell_quote_cmd(cmd)}")
        try:
            proc = run_docker(cmd, check=False, capture_output=False, timeout=None)
            return int(proc.returncode)
        except subprocess.SubprocessError as exc:
            telemetry.capture_exception(exc)
            print_error("Failed to run ADscan in Docker.")
            print_info_debug(f"[docker] passthrough exception: {exc}")
            return 1
    finally:
        _release_runtime_acquisition(acq)
