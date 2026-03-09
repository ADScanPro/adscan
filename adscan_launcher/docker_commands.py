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
import getpass
import socket
import re
import secrets
import time
from pathlib import Path
from typing import Any

import requests
from rich.prompt import Confirm, Prompt
import configparser

from adscan_launcher import telemetry
from adscan_launcher.bloodhound_ce_compose import (
    BLOODHOUND_CE_DEFAULT_WEB_PORT,
    BLOODHOUND_CE_VERSION,
    compose_images_present,
    compose_list_images,
    compose_pull,
    compose_up,
    docker_compose_available,
    ensure_bloodhound_compose_file,
    get_bloodhound_compose_project_name,
)
from adscan_launcher.bloodhound_ce_password import (
    detect_existing_bloodhound_ce_state,
    ensure_bloodhound_admin_password,
    validate_bloodhound_admin_password_policy,
)
from adscan_launcher.docker_runtime import (
    DockerRunConfig,
    build_adscan_run_command,
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
from adscan_launcher.path_utils import get_effective_user_home
from adscan_launcher.paths import (
    get_adscan_home_dir,
    get_logs_dir,
    get_run_dir,
    get_state_dir,
    get_workspaces_dir,
)
from adscan_core.interrupts import emit_interrupt_debug


DEFAULT_DOCKER_IMAGE = "adscan/adscan-lite:latest"
DEFAULT_DEV_DOCKER_IMAGE = "adscan/adscan-lite-dev:edge"
LEGACY_DEFAULT_DOCKER_IMAGE = "adscan/adscan:latest"
LEGACY_DEFAULT_DEV_DOCKER_IMAGE = "adscan/adscan-dev:edge"
DEFAULT_BLOODHOUND_ADMIN_PASSWORD = "Adscan4thewin!"
DEFAULT_BLOODHOUND_STACK_MODE = "managed"
SUPPORTED_BLOODHOUND_STACK_MODES = ("managed",)
DEFAULT_HOST_HELPER_SOCKET_NAME = "host-helper.sock"
_DOCKER_RUN_HELP_HAS_GPUS_RE = re.compile(r"\\s--gpus\\b", re.IGNORECASE)
_DOCKER_INSTALL_DOCS_URL = "https://www.adscanpro.com/docs/getting-started/installation"
_BLOODHOUND_TROUBLESHOOTING_DOCS_URL = (
    "https://www.adscanpro.com/docs/guides/troubleshooting"
)
_ALLOW_PODMAN_DOCKER_API_ENV = "ADSCAN_ALLOW_PODMAN_DOCKER_API"
_ALLOW_LEGACY_IMAGE_FALLBACK_ENV = "ADSCAN_ALLOW_LEGACY_IMAGE_FALLBACK"
_HOST_HELPER_TROUBLESHOOTING_DOCS_URL = (
    "https://www.adscanpro.com/docs/guides/troubleshooting#host-helper-docker-mode"
)
_LOCAL_RESOLVER_LOOPBACK_CANDIDATES = (
    "127.0.0.2",
    "127.0.0.3",
    "127.0.0.4",
    "127.0.0.5",
    "127.0.0.1",
)
_DOCKER_SERVICE_UNIT_MISSING_RE = re.compile(
    r"(unit\s+docker\.service\s+could\s+not\s+be\s+found|could\s+not\s+find\s+the\s+requested\s+service\s+docker)",
    re.IGNORECASE,
)
_MIN_DOCKER_INSTALL_FREE_GB = 10
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

# Keep BloodHound CE config in the effective user's home (sudo-safe), matching
# the default behavior of bloodhound-cli tooling.
BH_CONFIG_FILE = get_effective_user_home() / ".bloodhound_config"


def _emit_bloodhound_ce_config_diagnostics(
    *, context: str, exception: Exception | None = None
) -> None:
    """Emit best-effort debug diagnostics for ~/.bloodhound_config parsing issues."""
    marked_path = mark_sensitive(str(BH_CONFIG_FILE), "path")
    diagnostics = [
        f"context={context}",
        f"path={marked_path}",
        f"exists={BH_CONFIG_FILE.exists()}",
    ]
    if BH_CONFIG_FILE.exists():
        try:
            file_stats = BH_CONFIG_FILE.stat()
            diagnostics.append(f"size_bytes={int(file_stats.st_size)}")
            diagnostics.append(f"mode={oct(file_stats.st_mode & 0o777)}")
        except OSError as stat_exc:
            diagnostics.append(f"stat_error={mark_sensitive(str(stat_exc), 'error')}")
    if exception is not None:
        diagnostics.append(f"exception={mark_sensitive(str(exception), 'error')}")
    print_info_debug("[bloodhound-ce] config diagnostics: " + " ".join(diagnostics))


def _load_bloodhound_ce_config(
    *,
    context: str,
    emit_diagnostics: bool = True,
) -> tuple[configparser.ConfigParser | None, bool]:
    """Load ~/.bloodhound_config with robust parsing and diagnostics.

    Returns:
        Tuple ``(config, read_failed)`` where ``config`` is None when the file
        is missing or unreadable, and ``read_failed`` indicates parser/IO errors.
    """
    if not BH_CONFIG_FILE.exists():
        return None, False

    config = configparser.ConfigParser()
    try:
        with open(BH_CONFIG_FILE, "r", encoding="utf-8") as fp:
            config.read_file(fp)
    except (
        configparser.Error,
        OSError,
        UnicodeDecodeError,
        ValueError,
    ) as exc:
        telemetry.capture_exception(exc)
        print_info_debug(
            "[bloodhound-ce] failed reading host config file: "
            f"context={context} error={mark_sensitive(str(exc), 'error')}"
        )
        if emit_diagnostics:
            _emit_bloodhound_ce_config_diagnostics(context=context, exception=exc)
        return None, True
    return config, False


def _build_bloodhound_ce_config_backup_path() -> Path:
    """Return a collision-safe backup path for ~/.bloodhound_config."""
    timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    candidate = BH_CONFIG_FILE.with_name(f"{BH_CONFIG_FILE.name}.bak.{timestamp}")
    suffix_index = 1
    while candidate.exists():
        candidate = BH_CONFIG_FILE.with_name(
            f"{BH_CONFIG_FILE.name}.bak.{timestamp}.{suffix_index}"
        )
        suffix_index += 1
    return candidate


def _backup_bloodhound_ce_config(
    *,
    reason: str,
    warn_user: bool = False,
) -> Path | None:
    """Create a timestamped backup of ~/.bloodhound_config when it is unreadable."""
    if not BH_CONFIG_FILE.exists():
        return None
    backup_path = _build_bloodhound_ce_config_backup_path()
    try:
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(BH_CONFIG_FILE, backup_path)
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_info_debug(
            "[bloodhound-ce] failed creating config backup: "
            f"reason={reason} error={mark_sensitive(str(exc), 'error')}"
        )
        return None

    if warn_user:
        print_warning(
            "Detected an invalid BloodHound CE config file. ADscan will recreate it."
        )
    print_info_verbose(
        "BloodHound CE config backup created: "
        f"{mark_sensitive(str(backup_path), 'path')}"
    )
    print_info_debug(
        "[bloodhound-ce] config backup created: "
        f"reason={reason} source={mark_sensitive(str(BH_CONFIG_FILE), 'path')} "
        f"backup={mark_sensitive(str(backup_path), 'path')}"
    )
    return backup_path


def _normalize_bloodhound_stack_mode(mode: str | None) -> str:
    """Return normalized BloodHound stack mode."""
    raw = str(mode or os.getenv("ADSCAN_BLOODHOUND_STACK_MODE", "")).strip().lower()
    if raw in SUPPORTED_BLOODHOUND_STACK_MODES:
        return raw
    return DEFAULT_BLOODHOUND_STACK_MODE


def _normalize_external_bloodhound_base_url(base_url: str | None) -> str | None:
    """Normalize optional external BloodHound CE base URL."""
    value = str(base_url or "").strip()
    if not value:
        return None
    return value.rstrip("/")


def _normalize_external_bloodhound_username(username: str | None) -> str:
    """Normalize optional external BloodHound CE username."""
    raw = str(username or "admin").strip()
    return raw or "admin"


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


def _maybe_warn_low_memory_for_bloodhound(*, free_mem_gb: float) -> None:
    """Emit a soft warning when available RAM is likely too low for CE bootstrap."""
    if free_mem_gb >= _LOW_MEMORY_WARNING_THRESHOLD_GB:
        return
    print_warning(
        "Low available RAM detected. BloodHound CE may crash during startup "
        f"(available: {free_mem_gb:.2f} GB)."
    )
    print_instruction(
        "Close memory-heavy applications or add swap, then retry if BloodHound CE exits unexpectedly."
    )
    telemetry.capture(
        "docker_install_low_memory_warning",
        {
            "free_memory_gb": round(float(free_mem_gb), 2),
            "threshold_gb": _LOW_MEMORY_WARNING_THRESHOLD_GB,
        },
    )


def _enforce_bloodhound_memory_preflight(
    *,
    free_mem_gb: float,
    command_name: str,
    allow_low_memory: bool = False,
) -> bool:
    """Validate host RAM headroom before starting BloodHound CE bootstrap.

    Policy:
    - >= warning threshold: continue silently
    - hard-block <= RAM < warning threshold: soft warning, continue
    - RAM < hard-block threshold:
      - continue only when ``allow_low_memory`` is True
      - in non-interactive sessions, fail fast
      - in interactive sessions, require explicit confirmation
    """
    if free_mem_gb >= _LOW_MEMORY_WARNING_THRESHOLD_GB:
        return True

    if free_mem_gb >= _LOW_MEMORY_HARD_BLOCK_THRESHOLD_GB:
        _maybe_warn_low_memory_for_bloodhound(free_mem_gb=free_mem_gb)
        return True

    if allow_low_memory:
        print_warning(
            "Very low available RAM detected. Continuing because --allow-low-memory was provided "
            f"(available: {free_mem_gb:.2f} GB)."
        )
        print_instruction(
            "BloodHound CE may still crash (OOM). Free RAM or add swap if startup fails."
        )
        telemetry.capture(
            "docker_install_low_memory_override",
            {
                "command_name": command_name,
                "free_memory_gb": round(float(free_mem_gb), 2),
                "hard_threshold_gb": _LOW_MEMORY_HARD_BLOCK_THRESHOLD_GB,
                "warning_threshold_gb": _LOW_MEMORY_WARNING_THRESHOLD_GB,
            },
        )
        return True

    if not _is_interactive_launcher_session():
        print_error(
            "Available RAM is critically low for BloodHound CE startup "
            f"(available: {free_mem_gb:.2f} GB)."
        )
        print_instruction(
            "Free RAM or add swap and retry. To continue intentionally, rerun with "
            "`adscan install --allow-low-memory`."
        )
        telemetry.capture(
            "docker_install_low_memory_blocked",
            {
                "command_name": command_name,
                "reason": "noninteractive_critical_low_memory",
                "free_memory_gb": round(float(free_mem_gb), 2),
                "hard_threshold_gb": _LOW_MEMORY_HARD_BLOCK_THRESHOLD_GB,
            },
        )
        return False

    panel_lines = [
        "Available RAM is critically low for BloodHound CE startup.",
        f"Available: {free_mem_gb:.2f} GB",
        f"Recommended minimum: {_LOW_MEMORY_WARNING_THRESHOLD_GB:.2f} GB",
        "At this level, BloodHound CE can crash with OOM (exit 137) during initialization.",
    ]
    print_panel(
        "\n".join(panel_lines),
        title="Critical Low Memory",
        border_style="yellow",
    )
    should_continue = confirm_ask(
        "Continue installation anyway with high OOM risk?",
        default=False,
    )
    telemetry.capture(
        "docker_install_low_memory_confirmation",
        {
            "command_name": command_name,
            "accepted": bool(should_continue),
            "free_memory_gb": round(float(free_mem_gb), 2),
            "hard_threshold_gb": _LOW_MEMORY_HARD_BLOCK_THRESHOLD_GB,
        },
    )
    if not should_continue:
        print_warning("Installation cancelled due to critical low memory.")
        return False

    print_warning(
        "Proceeding with critical low memory. BloodHound CE startup may fail with OOM."
    )
    print_instruction(
        "If startup fails, free RAM or add swap and retry `adscan install`."
    )
    return True


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

    allow_legacy_fallback = (
        str(os.getenv(_ALLOW_LEGACY_IMAGE_FALLBACK_ENV, "")).strip().lower()
        in ("1", "true", "yes", "on")
    )
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
    if _strip_default_docker_io_prefix(selected_image) == _strip_default_docker_io_prefix(
        preferred_image
    ):
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


def _emit_docker_compose_missing_diagnostics(*, command_name: str) -> None:
    """Emit debug/telemetry diagnostics when compose detection reports missing."""
    docker_bin = shutil.which("docker") or ""
    compose_v1_bin = shutil.which("docker-compose") or ""
    docker_pkg = _detect_linux_package_owner(docker_bin)
    compose_v1_pkg = _detect_linux_package_owner(compose_v1_bin)

    compose_v2_rc: int | None = None
    compose_v2_first_line = ""
    compose_v2_error_line = ""
    if docker_bin:
        try:
            proc = run_docker(
                ["docker", "compose", "version"],
                check=False,
                capture_output=True,
                timeout=10,
            )
            compose_v2_rc = int(proc.returncode)
            compose_v2_first_line = _extract_first_nonempty_line(proc.stdout or "")
            compose_v2_error_line = _extract_first_nonempty_line(proc.stderr or "")
        except Exception as exc:  # pragma: no cover - best effort only
            telemetry.capture_exception(exc)
            compose_v2_error_line = str(exc)

    compose_v1_rc: int | None = None
    compose_v1_first_line = ""
    compose_v1_error_line = ""
    if compose_v1_bin:
        try:
            proc = run_docker(
                ["docker-compose", "version"],
                check=False,
                capture_output=True,
                timeout=10,
            )
            compose_v1_rc = int(proc.returncode)
            compose_v1_first_line = _extract_first_nonempty_line(proc.stdout or "")
            compose_v1_error_line = _extract_first_nonempty_line(proc.stderr or "")
        except Exception as exc:  # pragma: no cover - best effort only
            telemetry.capture_exception(exc)
            compose_v1_error_line = str(exc)

    payload: dict[str, Any] = {
        "command_name": command_name,
        "docker_bin_present": bool(docker_bin),
        "docker_pkg_hint": docker_pkg,
        "compose_v1_bin_present": bool(compose_v1_bin),
        "compose_v1_pkg_hint": compose_v1_pkg,
        "compose_v2_returncode": compose_v2_rc,
        "compose_v2_stdout_head": compose_v2_first_line,
        "compose_v2_stderr_head": compose_v2_error_line,
        "compose_v1_returncode": compose_v1_rc,
        "compose_v1_stdout_head": compose_v1_first_line,
        "compose_v1_stderr_head": compose_v1_error_line,
    }
    print_info_debug(
        "[docker] compose missing diagnostics: "
        f"command={mark_sensitive(command_name, 'status')} "
        f"docker_bin={mark_sensitive(docker_bin or 'missing', 'detail')} "
        f"docker_pkg={mark_sensitive(docker_pkg or 'unknown', 'status')} "
        f"compose_v2_rc={mark_sensitive(str(compose_v2_rc), 'status')} "
        f"compose_v2_out={mark_sensitive(compose_v2_first_line or '(empty)', 'detail')} "
        f"compose_v2_err={mark_sensitive(compose_v2_error_line or '(empty)', 'detail')} "
        f"compose_v1_bin={mark_sensitive(compose_v1_bin or 'missing', 'detail')} "
        f"compose_v1_pkg={mark_sensitive(compose_v1_pkg or 'unknown', 'status')} "
        f"compose_v1_rc={mark_sensitive(str(compose_v1_rc), 'status')} "
        f"compose_v1_out={mark_sensitive(compose_v1_first_line or '(empty)', 'detail')} "
        f"compose_v1_err={mark_sensitive(compose_v1_error_line or '(empty)', 'detail')}"
    )
    telemetry.capture("docker_compose_missing_diagnostics", payload)


def _ensure_docker_compose_prerequisites(*, command_name: str) -> bool:
    """Validate Docker + Docker Compose prerequisites with combined UX.

    Returns ``True`` when both prerequisites are available. When they are not,
    emits a single actionable guidance block so users can fix everything in one
    pass instead of hitting sequential errors.
    """
    has_docker = docker_available()
    has_compose = docker_compose_available() if has_docker else False
    if has_docker and has_compose:
        return True

    print_error("Docker prerequisites are incomplete for this command.")
    lines = [
        f"Docker CLI/Engine: {'OK' if has_docker else 'MISSING'}",
        f"Docker Compose: {'OK' if has_compose else 'MISSING'}",
    ]
    if has_docker and not has_compose:
        _emit_docker_compose_missing_diagnostics(command_name=command_name)
        lines.append("Detected Docker but Compose plugin is unavailable.")
        lines.append(
            "Install Compose plugin (for example on Debian/Ubuntu): "
            "sudo apt install docker-compose-plugin"
        )
    elif not has_docker:
        lines.append(
            "Docker is not installed or not in PATH. Compose cannot work without Docker."
        )
    print_panel(
        "\n".join(lines),
        title="Docker Prerequisites Required",
        border_style="yellow",
    )
    retry_hint = (
        "adscan start (or rerun your original command)"
        if command_name == "passthrough"
        else f"adscan {command_name}"
    )
    print_instruction(
        f"Install Docker + Docker Compose, then retry: {retry_hint}. Guide: {_DOCKER_INSTALL_DOCS_URL}"
    )
    return False


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


def _run_docker_pull_dns_preflight(*, host: str = _DOCKER_PULL_DNS_PREFLIGHT_HOST) -> bool:
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
        print_warning(
            "DNS preflight could not resolve Docker Hub. Image pull may fail."
        )
        print_instruction(
            "Check resolver health: getent hosts registry-1.docker.io"
        )
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
    print_warning(
        "Network preflight could not reach Docker Hub over HTTPS. Image pull may fail."
    )
    print_instruction("Verify host internet connectivity, VPN/proxy, and firewall policy.")
    if ipv6_unreachable:
        print_instruction(
            "IPv6 route appears unreachable. Prefer IPv4 connectivity if IPv6 is unstable."
        )
    if ipv6_unreachable and ipv4_timed_out:
        print_instruction(
            "IPv4 connections also timed out. Network path to Docker Hub is unstable; retry on a cleaner network."
        )
        print_instruction("Quick check: curl -4 -I https://registry-1.docker.io/v2/")
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
            "failure_sample": [
                {"ip": ip, "error": err} for ip, err in failures[:3]
            ],
        },
    )
    return False


def _ensure_image_pulled_with_legacy_fallback(
    *,
    pull_timeout: int | None,
    stream_output: bool,
) -> str | None:
    """Pull preferred image, then fallback to legacy naming if needed."""
    if not _ensure_docker_daemon_available_for_pull(stage="pre_pull"):
        return None
    dns_preflight_ok = _run_docker_pull_dns_preflight()
    network_preflight_ok = _run_docker_pull_network_preflight()
    preflight_ok = bool(dns_preflight_ok and network_preflight_ok)

    def _on_pull_success(selected_image: str, *, preferred_image: str) -> str:
        """Emit non-blocking preflight note when pull succeeds after warning."""
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
            print_warning(
                "Primary Docker image pull failed; trying legacy image naming: "
                f"{candidate_to_pull}"
            )
        if ensure_image_pulled(
            candidate_to_pull, timeout=pull_timeout, stream_output=stream_output
        ):
            return _on_pull_success(
                candidate_to_pull,
                preferred_image=preferred,
            )

        daemon_running, daemon_diagnostic = _is_docker_daemon_running_internal(
            run_docker_command_func=_run_docker_status_command
        )
        if daemon_running:
            print_warning(
                "Docker image pull failed. Retrying once in case of transient network/registry issues..."
            )
            print_info_debug(
                "[docker] transient pull retry: "
                f"image={mark_sensitive(candidate_to_pull, 'detail')} "
                f"diagnostic={mark_sensitive(daemon_diagnostic, 'detail')}"
            )
            telemetry.capture(
                "docker_pull_retry",
                {
                    "image": candidate_to_pull,
                    "reason": "transient_pull_failure",
                },
            )
            time.sleep(1.5)
            if ensure_image_pulled(
                candidate_to_pull,
                timeout=pull_timeout,
                stream_output=stream_output,
            ):
                return _on_pull_success(
                    candidate_to_pull,
                    preferred_image=preferred,
                )
            daemon_running, daemon_diagnostic = _is_docker_daemon_running_internal(
                run_docker_command_func=_run_docker_status_command
            )
        if daemon_running:
            continue

        print_warning(
            "Docker daemon became unavailable during image pull; "
            "attempting recovery before retrying."
        )
        print_info_debug(
            "[docker] daemon diagnostic after pull failure: "
            f"{mark_sensitive(daemon_diagnostic, 'detail')}"
        )
        if not _ensure_docker_daemon_available_for_pull(stage="post_pull_failure"):
            return None

        print_info("Retrying image pull after Docker daemon recovery...")
        if ensure_image_pulled(
            candidate_to_pull,
            timeout=pull_timeout,
            stream_output=stream_output,
        ):
            return _on_pull_success(
                candidate_to_pull,
                preferred_image=preferred,
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
        print_error("Docker service unit (`docker.service`) was not found on this host.")
        print_instruction("Install Docker Engine + Docker Compose plugin, then retry.")
        print_instruction(f"Installation guide: {_DOCKER_INSTALL_DOCS_URL}")


def _print_docker_image_pull_failure_guidance(
    *,
    image: str,
    pull_timeout: int | None,
    command_name: str,
) -> None:
    """Print targeted guidance for Docker image pull failures.

    Distinguishes daemon/runtime failures from network/registry failures so users
    get relevant troubleshooting steps.
    """
    daemon_running, daemon_diagnostic = _is_docker_daemon_running_internal(
        run_docker_command_func=_run_docker_status_command
    )

    print_error("Failed to pull the ADscan Docker image.")
    if not daemon_running:
        print_warning(
            "Docker daemon is not reachable. ADscan cannot pull images until Docker API is available."
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

    print_instruction("Retry the command, or pull manually and retry:")
    pull_cmd_prefix = "sudo " if (docker_needs_sudo() and os.geteuid() != 0) else ""
    print_instruction(f"  {pull_cmd_prefix}docker pull {image}")
    suggested_timeout = 7200 if pull_timeout is None else max(pull_timeout, 7200)
    print_instruction(
        "If you are on a slow network, increase the pull timeout and retry:"
    )
    print_instruction(f"  adscan {command_name} --pull-timeout {suggested_timeout}")
    print_instruction("To disable the pull timeout entirely:")
    print_instruction(f"  adscan {command_name} --pull-timeout 0")
    print_instruction(
        "If the error mentions 'content descriptor ... not found', this is usually a "
        "registry/tag consistency issue. Retry shortly."
    )
    print_instruction(
        "Emergency compatibility fallback (may use older image naming): "
        f"{_ALLOW_LEGACY_IMAGE_FALLBACK_ENV}=1 adscan {command_name}"
    )


def _run_bloodhound_compose_pull_with_daemon_recovery(
    *,
    compose_path: Path,
    stream_output: bool,
    pull_timeout_seconds: int | None,
    command_name: str,
) -> bool:
    """Run `docker compose pull` with daemon availability recovery.

    This helper centralizes daemon checks/retries for BloodHound CE image pulls so
    install/start/check/ci paths share the same resilient behavior.
    """
    if not _ensure_docker_daemon_available_for_pull(
        stage="pre_bloodhound_compose_pull"
    ):
        return False
    _run_docker_pull_dns_preflight()
    _run_docker_pull_network_preflight()

    if compose_pull(
        compose_path,
        stream_output=stream_output,
        timeout_seconds=pull_timeout_seconds,
        command_name=command_name,
    ):
        return True

    daemon_running, daemon_diagnostic = _is_docker_daemon_running_internal(
        run_docker_command_func=_run_docker_status_command
    )
    if daemon_running:
        return False

    print_warning(
        "Docker daemon became unavailable while pulling BloodHound CE images; "
        "attempting recovery before retrying."
    )
    print_info_debug(
        "[docker] daemon diagnostic after BloodHound CE pull failure: "
        f"{mark_sensitive(daemon_diagnostic, 'detail')}"
    )

    if not _ensure_docker_daemon_available_for_pull(
        stage="post_bloodhound_compose_pull_failure"
    ):
        return False

    print_info("Retrying BloodHound CE image pull after Docker daemon recovery...")
    return compose_pull(
        compose_path,
        stream_output=stream_output,
        timeout_seconds=pull_timeout_seconds,
        command_name=command_name,
    )


def _run_bloodhound_compose_up_with_daemon_recovery(*, compose_path: Path) -> bool:
    """Run `docker compose up -d` with daemon availability recovery.

    This helper centralizes daemon checks/retries for BloodHound CE stack start so
    install/start/check/ci paths share the same resilient behavior.
    """
    if not _ensure_docker_daemon_available_for_pull(stage="pre_bloodhound_compose_up"):
        return False

    if compose_up(compose_path):
        return True

    daemon_running, daemon_diagnostic = _is_docker_daemon_running_internal(
        run_docker_command_func=_run_docker_status_command
    )
    if daemon_running:
        return False

    print_warning(
        "Docker daemon became unavailable while starting BloodHound CE containers; "
        "attempting recovery before retrying."
    )
    print_info_debug(
        "[docker] daemon diagnostic after BloodHound CE compose-up failure: "
        f"{mark_sensitive(daemon_diagnostic, 'detail')}"
    )

    if not _ensure_docker_daemon_available_for_pull(
        stage="post_bloodhound_compose_up_failure"
    ):
        return False

    print_info(
        "Retrying BloodHound CE container startup after Docker daemon recovery..."
    )
    return compose_up(compose_path)


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


def _get_bloodhound_admin_password() -> str:
    """Resolve the desired BloodHound CE admin password for host auth."""
    return (
        os.getenv("ADSCAN_BLOODHOUND_ADMIN_PASSWORD")
        or os.getenv("ADSCAN_BH_ADMIN_PASSWORD")
        or DEFAULT_BLOODHOUND_ADMIN_PASSWORD
    )


def _persist_bloodhound_ce_config(
    *, username: str, password: str, base_url: str | None = None
) -> bool:
    """Authenticate and persist BloodHound CE credentials to the host config file."""
    if is_docker_env():
        print_warning("Skipping BloodHound CE config persistence inside the container.")
        return False

    resolved_base_url = base_url or f"http://127.0.0.1:{BLOODHOUND_CE_DEFAULT_WEB_PORT}"
    if not _wait_for_bloodhound_ce_api_ready(base_url=resolved_base_url):
        return False

    # BloodHound CE supports secret-based login. We persist the resulting token
    # in ~/.bloodhound_config so host+container share the same auth context.
    payload = {
        "login_method": "secret",
        "username": username,
        "secret": password,
    }
    try:
        resp = requests.post(
            f"{resolved_base_url}/api/v2/login",
            json=payload,
            timeout=30,
        )
    except requests.exceptions.RequestException as exc:
        telemetry.capture_exception(exc)
        print_warning("Could not authenticate to BloodHound CE (network error).")
        return False
    if resp.status_code != 200:
        print_warning(
            f"BloodHound CE rejected credentials (status={resp.status_code})."
        )
        return False
    try:
        data = resp.json() or {}
    except ValueError:
        data = {}
    token = ((data.get("data") or {}) or {}).get("session_token")
    if not token:
        print_warning("BloodHound CE login succeeded but did not return a token.")
        return False

    config = configparser.ConfigParser()
    if BH_CONFIG_FILE.exists():
        existing_config, read_failed = _load_bloodhound_ce_config(
            context="persist_host_config",
            emit_diagnostics=True,
        )
        if existing_config is not None:
            config = existing_config
        elif read_failed:
            _backup_bloodhound_ce_config(
                reason="persist_recreate_on_parse_error",
                warn_user=False,
            )
            config = configparser.ConfigParser()
    config["CE"] = {
        "base_url": str(resolved_base_url),
        "api_token": str(token),
        "username": str(username),
        "password": str(password),
        "verify": "true",
    }
    if "GENERAL" not in config:
        config["GENERAL"] = {}
    config["GENERAL"]["edition"] = "ce"
    try:
        BH_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        BH_CONFIG_FILE.write_text("", encoding="utf-8")  # ensure file exists
        with open(BH_CONFIG_FILE, "w", encoding="utf-8") as fp:
            config.write(fp)
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_warning("Failed to persist BloodHound CE config on the host.")
        return False

    marked_path = mark_sensitive(str(BH_CONFIG_FILE), "path")
    print_info_verbose(f"BloodHound CE config written on host: {marked_path}")
    return True


def _validate_bloodhound_ce_config() -> bool:
    """Check if ~/.bloodhound_config has the expected CE structure."""
    config, read_failed = _load_bloodhound_ce_config(
        context="validate_host_config",
        emit_diagnostics=True,
    )
    if config is None:
        if read_failed:
            print_info_debug("[bloodhound-ce] config validation failed: parse error.")
        return False

    if "CE" not in config:
        print_info_debug("[bloodhound-ce] config missing [CE] section")
        return False

    required = {"base_url", "api_token", "username", "password", "verify"}
    ce_keys = set(k.lower() for k in config["CE"].keys())
    if not required.issubset(ce_keys):
        missing = sorted(required - ce_keys)
        print_info_debug(
            f"[bloodhound-ce] config missing CE keys: {', '.join(missing)}"
        )
        return False

    if "GENERAL" not in config:
        print_info_debug("[bloodhound-ce] config missing [GENERAL] section")
        return False
    if config["GENERAL"].get("edition") != "ce":
        print_info_debug("[bloodhound-ce] config GENERAL.edition is not 'ce'")
        return False

    return True


def _get_stored_bloodhound_ce_password() -> str | None:
    """Return the stored BloodHound CE password from host config when available."""
    config, read_failed = _load_bloodhound_ce_config(
        context="get_stored_password",
        emit_diagnostics=False,
    )
    if config is None:
        if read_failed:
            print_info_debug(
                "[bloodhound-ce] failed reading stored CE password from config."
            )
        return None
    if "CE" not in config:
        return None
    value = config["CE"].get("password")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _get_stored_bloodhound_ce_base_url() -> str | None:
    """Return stored BloodHound CE base_url from host config when available."""
    config, read_failed = _load_bloodhound_ce_config(
        context="get_stored_base_url",
        emit_diagnostics=False,
    )
    if config is None:
        if read_failed:
            print_info_debug(
                "[bloodhound-ce] failed reading stored CE base_url from config."
            )
        return None
    if "CE" not in config:
        return None
    value = config["CE"].get("base_url")
    if isinstance(value, str) and value.strip():
        return value.strip().rstrip("/")
    return None


def _reset_bloodhound_ce_stack_for_password_recovery(compose_path: Path) -> bool:
    """Reset BloodHound CE containers+volumes and start the pinned stack again."""
    print_warning(
        "Resetting BloodHound CE stack for password recovery. Existing BloodHound data will be deleted."
    )
    project_name = get_bloodhound_compose_project_name()
    down_cmd = [
        "docker",
        "compose",
        "-p",
        project_name,
        "-f",
        str(compose_path),
        "down",
        "-v",
        "--remove-orphans",
    ]
    print_info_debug(
        f"[bloodhound-ce] password recovery reset down: {shell_quote_cmd(down_cmd)}"
    )
    try:
        proc_down = run_docker(
            down_cmd,
            check=False,
            capture_output=True,
            timeout=180,
        )
        if proc_down.returncode != 0:
            print_warning("Failed to stop/reset BloodHound CE stack for recovery.")
            if proc_down.stderr:
                print_info_debug(
                    f"[bloodhound-ce] reset down stderr: {proc_down.stderr}"
                )
            return False
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning("Error while resetting BloodHound CE stack for recovery.")
        print_info_debug(
            f"[bloodhound-ce] reset down exception: {mark_sensitive(str(exc), 'error')}"
        )
        return False

    return compose_up(compose_path)


def _bootstrap_bloodhound_ce_auth(
    *,
    compose_path: Path,
    desired_password: str,
    suppress_browser: bool,
) -> tuple[bool, bool, bool]:
    """Resolve BloodHound CE auth after compose-up with first-run and reuse fallbacks.

    Returns:
        Tuple ``(auth_verified, desired_password_verified, password_automation_ok)``.
    """
    password_automation_ok = False
    desired_password_verified = False
    auth_verified = False

    config_exists = BH_CONFIG_FILE.exists()
    print_info_debug(
        f"[bloodhound-ce] install auth bootstrap context: config_exists={config_exists}"
    )
    managed_base_url = f"http://127.0.0.1:{BLOODHOUND_CE_DEFAULT_WEB_PORT}"

    if config_exists:
        # Reused installation: validate current config/token first.
        auth_verified = _ensure_bloodhound_ce_auth_for_docker(
            desired_password=desired_password,
            # Even with an existing host config, the managed stack may be freshly
            # created (or migrated) and require first-run recovery from logs.
            allow_managed_password_bootstrap=True,
        )
        stored_password = _get_stored_bloodhound_ce_password()
        desired_password_verified = bool(
            stored_password and stored_password == desired_password
        )
        if auth_verified:
            return auth_verified, desired_password_verified, password_automation_ok
    else:
        # Fresh installation path: try initial-password automation from logs.
        print_info_debug(
            "[bloodhound-ce] no existing config found; attempting first-run "
            "initial-password extraction from container logs."
        )
        existing_ce_state = detect_existing_bloodhound_ce_state()
        if existing_ce_state:
            print_info(
                "Detected an existing BloodHound CE data state without local ADscan "
                "credentials. Attempting password extraction from container logs anyway."
            )
            print_info_debug(
                "[bloodhound-ce] existing CE state detected; continuing with "
                "best-effort container-log password extraction."
            )
        runtime_stable = _wait_for_bloodhound_ce_api_ready(
            base_url=managed_base_url,
            timeout_seconds=120,
            interval_seconds=2,
            required_consecutive_successes=3,
            require_managed_container_health=True,
        )
        if not runtime_stable:
            print_warning(
                "BloodHound CE runtime is not stable yet; skipping automatic initial-password "
                "bootstrap for now."
            )
            password_automation_ok = False
        else:
            password_automation_ok = ensure_bloodhound_admin_password(
                desired_password=desired_password,
                suppress_browser=suppress_browser,
            )
        if not password_automation_ok:
            print_info_debug(
                "[bloodhound-ce] initial-password automation did not succeed; "
                "trying desired-password fallback auth bootstrap."
            )
        marked_desired_password = mark_sensitive(desired_password, "password")
        print_info_debug(
            "[bloodhound-ce] desired-password fallback attempt: "
            f"username=admin password={marked_desired_password}"
        )
        desired_password_verified = _persist_bloodhound_ce_config(
            username="admin",
            password=desired_password,
        )
        auth_verified = _ensure_bloodhound_ce_auth_for_docker(
            desired_password=desired_password,
            allow_managed_password_bootstrap=True,
        )
        if auth_verified:
            stored_password = _get_stored_bloodhound_ce_password()
            desired_password_verified = bool(
                stored_password and stored_password == desired_password
            )
            return auth_verified, desired_password_verified, password_automation_ok

    # Auth is still not verified. Offer destructive recovery only in interactive mode.
    if not sys.stdin.isatty():
        return auth_verified, desired_password_verified, password_automation_ok

    should_reset = Confirm.ask(
        "BloodHound CE password is unknown. Reset BloodHound CE data and regenerate initial password?",
        default=False,
    )
    if not should_reset:
        return auth_verified, desired_password_verified, password_automation_ok
    try:
        reset_confirmation = Prompt.ask(
            "Type RESET to confirm destructive BloodHound CE data reset",
            default="",
        )
    except (EOFError, KeyboardInterrupt) as exc:
        interrupt_kind = (
            "keyboard_interrupt" if isinstance(exc, KeyboardInterrupt) else "eof"
        )
        emit_interrupt_debug(
            kind=interrupt_kind,
            source="launcher.bloodhound_ce_destructive_reset_confirmation",
            print_debug=print_info_debug,
        )
        return auth_verified, desired_password_verified, password_automation_ok
    if str(reset_confirmation or "").strip().upper() != "RESET":
        print_warning(
            "BloodHound CE reset cancelled. Destructive reset was not confirmed."
        )
        return auth_verified, desired_password_verified, password_automation_ok

    if not _reset_bloodhound_ce_stack_for_password_recovery(compose_path):
        return auth_verified, desired_password_verified, password_automation_ok

    runtime_stable = _wait_for_bloodhound_ce_api_ready(
        base_url=managed_base_url,
        timeout_seconds=120,
        interval_seconds=2,
        required_consecutive_successes=3,
        require_managed_container_health=True,
    )
    if not runtime_stable:
        print_warning(
            "BloodHound CE runtime is not stable after reset; skipping automatic "
            "initial-password bootstrap."
        )
        password_automation_ok = False
    else:
        password_automation_ok = ensure_bloodhound_admin_password(
            desired_password=desired_password,
            suppress_browser=suppress_browser,
        )
    desired_password_verified = _persist_bloodhound_ce_config(
        username="admin",
        password=desired_password,
    )
    auth_verified = _ensure_bloodhound_ce_auth_for_docker(
        desired_password=desired_password,
        allow_managed_password_bootstrap=True,
    )
    stored_password = _get_stored_bloodhound_ce_password()
    desired_password_verified = bool(
        stored_password and stored_password == desired_password
    )
    return auth_verified, desired_password_verified, password_automation_ok


def _ensure_bloodhound_ce_auth_for_docker(
    *,
    desired_password: str | None = None,
    base_url_override: str | None = None,
    username_override: str | None = None,
    allow_managed_password_bootstrap: bool = False,
    allow_destructive_reset: bool = False,
    recovery_compose_path: Path | None = None,
) -> bool:
    """Ensure we can authenticate to BloodHound CE before starting Docker mode.

    This runs on the host, against the BloodHound CE stack managed by
    ``bloodhound_ce_compose``. It validates the current token and attempts
    non‑interactive renewal first; if that fails, it will interactively prompt
    the user for credentials and update ``~/.bloodhound_config`` via the
    shared BloodHound CE client.

    Returns:
        True if authentication is available and a valid token is present.
        False if we could not authenticate (in which case Docker start should
        be aborted and the user instructed to repair/reinstall BloodHound CE).
    """
    print_info("Verifying BloodHound CE authentication for Docker mode...")
    resolved_desired_password = desired_password or _get_bloodhound_admin_password()
    resolved_base_url_override = _normalize_external_bloodhound_base_url(
        base_url_override
    )
    resolved_username = _normalize_external_bloodhound_username(username_override)
    resolved_base_url = (
        resolved_base_url_override
        or f"http://127.0.0.1:{BLOODHOUND_CE_DEFAULT_WEB_PORT}"
    )
    if not _wait_for_bloodhound_ce_api_ready(
        base_url=resolved_base_url,
        timeout_seconds=120,
        interval_seconds=2,
        required_consecutive_successes=3,
        require_managed_container_health=True,
    ):
        print_warning(
            "BloodHound CE runtime is not stable enough yet to validate credentials."
        )
        return False

    if not BH_CONFIG_FILE.exists():
        print_info_verbose(
            "BloodHound CE config not found on host; attempting default auth."
        )
        marked_desired_password = mark_sensitive(resolved_desired_password, "password")
        print_info_debug(
            "[bloodhound-ce] config bootstrap attempt with desired password: "
            f"username={mark_sensitive(resolved_username, 'username')} "
            f"password={marked_desired_password}"
        )
        if _persist_bloodhound_ce_config(
            username=resolved_username,
            password=resolved_desired_password,
            base_url=resolved_base_url,
        ):
            print_success("BloodHound CE config created on host.")
        else:
            print_info_debug(
                "[bloodhound-ce] desired-password bootstrap auth failed while "
                "config file was missing."
            )
            if allow_managed_password_bootstrap:
                print_info_debug(
                    "[bloodhound-ce] missing host config and default bootstrap failed; "
                    "attempting managed password recovery before prompting."
                )
                recovered = ensure_bloodhound_admin_password(
                    desired_password=resolved_desired_password,
                    suppress_browser=True,
                    base_url=resolved_base_url,
                )
                if recovered and _wait_for_bloodhound_ce_api_ready(
                    base_url=resolved_base_url,
                    timeout_seconds=60,
                    interval_seconds=2,
                    required_consecutive_successes=2,
                    require_managed_container_health=True,
                ):
                    if _persist_bloodhound_ce_config(
                        username=resolved_username,
                        password=resolved_desired_password,
                        base_url=resolved_base_url,
                    ):
                        print_success(
                            "BloodHound CE authentication verified via managed password recovery."
                        )
                        return True

                # Even when recovery from logs fails, retry desired-password auth once
                # after a short readiness window to absorb transient API/network flaps.
                print_info_debug(
                    "[bloodhound-ce] retrying desired-password bootstrap after managed "
                    "runtime stabilization window."
                )
                if _wait_for_bloodhound_ce_api_ready(
                    base_url=resolved_base_url,
                    timeout_seconds=60,
                    interval_seconds=2,
                    required_consecutive_successes=2,
                    require_managed_container_health=True,
                ) and _persist_bloodhound_ce_config(
                    username=resolved_username,
                    password=resolved_desired_password,
                    base_url=resolved_base_url,
                ):
                    print_success(
                        "BloodHound CE authentication verified after runtime stabilization retry."
                    )
                    return True
            if not sys.stdin.isatty():
                print_warning(
                    "Default BloodHound CE password failed and no TTY available for prompt."
                )
                return False
            print_warning(
                "Default BloodHound CE password failed. Please enter the current "
                "admin password for your current BloodHound CE installation."
            )
            try:
                new_password = getpass.getpass(
                    f"BloodHound CE password (leave empty for {resolved_desired_password}): "
                )
            except (EOFError, KeyboardInterrupt) as exc:
                interrupt_kind = (
                    "keyboard_interrupt"
                    if isinstance(exc, KeyboardInterrupt)
                    else "eof"
                )
                emit_interrupt_debug(
                    kind=interrupt_kind,
                    source="launcher.bloodhound_ce_password_prompt_initial",
                    print_debug=print_info_debug,
                )
                print_warning("Aborting: no credentials provided.")
                return False
            if not new_password:
                new_password = resolved_desired_password
            if not _persist_bloodhound_ce_config(
                username=resolved_username,
                password=new_password,
                base_url=resolved_base_url,
            ):
                print_warning(
                    "Could not create BloodHound CE config with the provided password."
                )
                return False
    else:
        if not _validate_bloodhound_ce_config():
            marked_path = mark_sensitive(str(BH_CONFIG_FILE), "path")
            print_warning(
                "BloodHound CE config is missing required fields or is unreadable; refreshing it."
            )
            print_info_verbose(f"Config path: {marked_path}")
            config, read_failed = _load_bloodhound_ce_config(
                context="refresh_invalid_config",
                emit_diagnostics=True,
            )
            stored_user = resolved_username
            stored_password = None
            stored_base_url = resolved_base_url_override
            if config is not None and "CE" in config:
                stored_user = config["CE"].get("username", "admin")
                stored_password = config["CE"].get("password")
                stored_base_url = config["CE"].get("base_url")
            elif read_failed:
                _backup_bloodhound_ce_config(
                    reason="invalid_or_corrupt_config",
                    warn_user=True,
                )
                print_instruction(
                    "ADscan will recreate ~/.bloodhound_config once valid BloodHound "
                    "credentials are confirmed."
                )
            if stored_password:
                if not _persist_bloodhound_ce_config(
                    username=stored_user,
                    password=stored_password,
                    base_url=stored_base_url,
                ):
                    print_warning(
                        "Failed to refresh BloodHound CE config with stored credentials."
                    )
            else:
                print_warning(
                    "BloodHound CE config has no stored password; will prompt if needed."
                )

    # Best-effort: re-authenticate using stored credentials to refresh the token.
    base_url = (
        resolved_base_url_override
        or f"http://127.0.0.1:{BLOODHOUND_CE_DEFAULT_WEB_PORT}"
    )
    stored_user = resolved_username
    stored_password: str | None = None
    config, _read_failed = _load_bloodhound_ce_config(
        context="auth_verify_stored_credentials",
        emit_diagnostics=False,
    )
    if config is not None and "CE" in config:
        stored_user = config["CE"].get("username", stored_user)
        stored_password = config["CE"].get("password")
        if not resolved_base_url_override:
            configured_base_url = (config["CE"].get("base_url") or "").strip()
            if (
                allow_managed_password_bootstrap
                and configured_base_url
                and configured_base_url.rstrip("/") != base_url.rstrip("/")
            ):
                print_info_debug(
                    "[bloodhound-ce] ignoring stored base_url during managed auth bootstrap: "
                    f"stored={mark_sensitive(configured_base_url, 'url')} "
                    f"effective={mark_sensitive(base_url, 'url')}"
                )
            else:
                base_url = configured_base_url or base_url

    if stored_password and _persist_bloodhound_ce_config(
        username=stored_user, password=stored_password, base_url=base_url
    ):
        print_success("BloodHound CE authentication verified.")
        return True

    if allow_managed_password_bootstrap:
        print_info_debug(
            "[bloodhound-ce] attempting managed desired-password auth fallback "
            "before container-log recovery."
        )
        if _persist_bloodhound_ce_config(
            username=resolved_username,
            password=resolved_desired_password,
            base_url=base_url,
        ):
            print_success(
                "BloodHound CE authentication verified with the managed desired password."
            )
            return True
        print_info_debug(
            "[bloodhound-ce] managed auth verification failed with stored credentials; "
            "attempting first-run password recovery from container logs."
        )
        existing_ce_state = detect_existing_bloodhound_ce_state()
        if existing_ce_state:
            print_info_debug(
                "[bloodhound-ce] existing CE state detected during managed auth bootstrap; "
                "attempting container-log recovery as best effort."
            )
        recovered = ensure_bloodhound_admin_password(
            desired_password=resolved_desired_password,
            suppress_browser=True,
            base_url=base_url,
        )
        if recovered and _persist_bloodhound_ce_config(
            username=resolved_username,
            password=resolved_desired_password,
            base_url=base_url,
        ):
            print_success(
                "BloodHound CE authentication verified via managed password recovery."
            )
            return True
        if not recovered:
            print_info_debug(
                "[bloodhound-ce] managed auth recovery could not extract/update initial password."
            )

    if not sys.stdin.isatty():
        print_warning(
            "BloodHound CE authentication could not be verified and no TTY is available for a prompt."
        )
        return False

    print_warning("BloodHound CE credentials need to be refreshed.")
    try:
        new_password = getpass.getpass(
            f"BloodHound CE password (leave empty for {resolved_desired_password}): "
        )
    except (EOFError, KeyboardInterrupt) as exc:
        interrupt_kind = (
            "keyboard_interrupt" if isinstance(exc, KeyboardInterrupt) else "eof"
        )
        emit_interrupt_debug(
            kind=interrupt_kind,
            source="launcher.bloodhound_ce_password_prompt_refresh",
            print_debug=print_info_debug,
        )
        print_warning("Aborting: no credentials provided.")
        return False
    if not new_password:
        new_password = resolved_desired_password
    if not _persist_bloodhound_ce_config(
        username=stored_user,
        password=new_password,
        base_url=base_url,
    ):
        if (
            allow_destructive_reset
            and recovery_compose_path is not None
            and sys.stdin.isatty()
        ):
            print_warning(
                "Could not authenticate with the provided password. A full managed "
                "BloodHound CE reset can regenerate first-run credentials."
            )
            should_reset = Confirm.ask(
                "Reset managed BloodHound CE data and regenerate initial password?",
                default=False,
            )
            if should_reset:
                try:
                    reset_confirmation = Prompt.ask(
                        "Type RESET to confirm destructive BloodHound CE data reset",
                        default="",
                    )
                except (EOFError, KeyboardInterrupt) as exc:
                    interrupt_kind = (
                        "keyboard_interrupt"
                        if isinstance(exc, KeyboardInterrupt)
                        else "eof"
                    )
                    emit_interrupt_debug(
                        kind=interrupt_kind,
                        source="launcher.bloodhound_ce_destructive_reset_confirmation_auth",
                        print_debug=print_info_debug,
                    )
                    return False
                if str(reset_confirmation or "").strip().upper() != "RESET":
                    print_warning(
                        "BloodHound CE reset cancelled. Destructive reset was not confirmed."
                    )
                    return False

                if not _reset_bloodhound_ce_stack_for_password_recovery(
                    recovery_compose_path
                ):
                    return False

                if not _wait_for_bloodhound_ce_api_ready(
                    base_url=base_url,
                    timeout_seconds=120,
                    interval_seconds=2,
                    required_consecutive_successes=3,
                    require_managed_container_health=True,
                ):
                    print_warning(
                        "BloodHound CE runtime is not stable after reset; automatic recovery skipped."
                    )
                    return False

                recovered = ensure_bloodhound_admin_password(
                    desired_password=resolved_desired_password,
                    suppress_browser=True,
                    base_url=base_url,
                )
                if recovered and _persist_bloodhound_ce_config(
                    username=resolved_username,
                    password=resolved_desired_password,
                    base_url=base_url,
                ):
                    print_success(
                        "BloodHound CE authentication verified after destructive managed reset."
                    )
                    return True

        print_error(
            "Unable to authenticate to BloodHound CE with the provided password."
        )
        print_instruction(
            "If you changed or lost the BloodHound CE admin password, reset it in the UI "
            "or reinstall the stack (e.g. rerun `adscan install`)."
        )
        return False

    print_success("BloodHound CE authentication verified.")
    return True


def _ensure_bloodhound_config_mountable() -> bool:
    """Ensure the host BloodHound config file exists so Docker can bind-mount it."""
    if is_docker_env():
        return False

    try:
        BH_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        if not BH_CONFIG_FILE.exists():
            BH_CONFIG_FILE.touch()
            try:
                BH_CONFIG_FILE.chmod(0o600)
            except OSError:
                # Best-effort; permissions may be managed by the host environment.
                pass
            print_info_debug(
                "[bloodhound-ce] created empty host config file for bind-mount: "
                f"{mark_sensitive(str(BH_CONFIG_FILE), 'path')}"
            )
        return True
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_info_debug(
            "[bloodhound-ce] failed to prepare host config for bind-mount: "
            f"{mark_sensitive(str(exc), 'error')}"
        )
        return False


def _get_managed_bloodhound_container_statuses() -> dict[str, str] | None:
    """Return managed BloodHound CE container statuses from docker ps.

    Returns:
        Mapping ``container_name -> status`` for expected managed containers.
        Returns None when docker status cannot be collected.
    """
    project_name = get_bloodhound_compose_project_name()
    service_names = ("bloodhound", "app-db", "graph-db")
    expected_names = {
        f"{project_name}-{service_name}-1" for service_name in service_names
    }
    canonical_name_by_service = {
        service_name: f"{project_name}-{service_name}-1"
        for service_name in service_names
    }
    fallback_name_aliases = {
        canonical_name_by_service["bloodhound"]: {
            canonical_name_by_service["bloodhound"],
            f"{project_name}_bloodhound_1",
        },
        canonical_name_by_service["app-db"]: {
            canonical_name_by_service["app-db"],
            f"{project_name}_app-db_1",
            f"{project_name}_app_db_1",
        },
        canonical_name_by_service["graph-db"]: {
            canonical_name_by_service["graph-db"],
            f"{project_name}_graph-db_1",
            f"{project_name}_graph_db_1",
        },
    }
    try:
        # Use `ps -a` so we can detect "Exited"/"Dead" containers explicitly
        # instead of only seeing them as "missing" from the runtime gate.
        proc = run_docker(
            [
                "docker",
                "ps",
                "-a",
                "--filter",
                f"label=com.docker.compose.project={project_name}",
                "--format",
                "{{.Names}}\t{{.Label \"com.docker.compose.service\"}}\t{{.Status}}",
            ],
            check=False,
            capture_output=True,
            timeout=15,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            "[bloodhound-ce] managed status probe exception: "
            f"{mark_sensitive(str(exc), 'error')}"
        )
        return None

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        if stderr:
            print_info_debug(
                "[bloodhound-ce] managed status probe stderr: "
                f"{mark_sensitive(stderr, 'detail')}"
            )
        return None

    snapshot: dict[str, str] = {name: "" for name in expected_names}
    for raw_line in (proc.stdout or "").splitlines():
        line = str(raw_line or "").strip()
        if not line or "\t" not in line:
            continue
        parts = line.split("\t", 2)
        if len(parts) < 3:
            continue
        name, service_name, status = parts[0].strip(), parts[1].strip(), parts[2].strip()
        if service_name in canonical_name_by_service:
            snapshot[canonical_name_by_service[service_name]] = status
            continue
        for canonical_name, aliases in fallback_name_aliases.items():
            if name in aliases:
                snapshot[canonical_name] = status
                break
    return snapshot


def _evaluate_managed_bloodhound_container_readiness(
    snapshot: dict[str, str] | None,
) -> tuple[bool, str]:
    """Evaluate whether managed BloodHound CE containers are stable enough for auth."""
    if snapshot is None:
        return False, "docker_ps_unavailable"

    missing = sorted(name for name, status in snapshot.items() if not status)
    if missing:
        return False, f"missing={','.join(missing)}"

    lowered = {name: status.lower() for name, status in snapshot.items()}
    bloodhound_name = next(name for name in lowered if name.endswith("-bloodhound-1"))
    app_db_name = next(name for name in lowered if name.endswith("-app-db-1"))
    graph_db_name = next(name for name in lowered if name.endswith("-graph-db-1"))

    if "dead" in lowered[bloodhound_name] or "exited" in lowered[bloodhound_name]:
        return False, f"web_exited={snapshot[bloodhound_name]!r}"
    if "dead" in lowered[app_db_name] or "exited" in lowered[app_db_name]:
        return False, f"app_db_exited={snapshot[app_db_name]!r}"
    if "dead" in lowered[graph_db_name] or "exited" in lowered[graph_db_name]:
        return False, f"graph_db_exited={snapshot[graph_db_name]!r}"

    if "up" not in lowered[bloodhound_name]:
        return False, f"web_not_up={snapshot[bloodhound_name]!r}"
    if "up" not in lowered[app_db_name]:
        return False, f"app_db_not_up={snapshot[app_db_name]!r}"
    if "healthy" not in lowered[app_db_name]:
        return False, f"app_db_not_healthy={snapshot[app_db_name]!r}"
    if "up" not in lowered[graph_db_name]:
        return False, f"graph_db_not_up={snapshot[graph_db_name]!r}"
    if "healthy" not in lowered[graph_db_name]:
        return False, f"graph_db_not_healthy={snapshot[graph_db_name]!r}"

    return True, "ok"


def _is_fatal_managed_readiness_reason(reason: str) -> bool:
    """Return whether a managed readiness reason should fail immediately."""
    normalized = str(reason or "").strip().lower()
    return normalized.startswith(("web_exited=", "app_db_exited=", "graph_db_exited="))


def _inspect_container_runtime_state(container_name: str) -> dict[str, str] | None:
    """Return best-effort Docker inspect state for a container."""
    try:
        proc = run_docker(
            [
                "docker",
                "inspect",
                "--format",
                (
                    "{{.State.Status}}\t{{.State.ExitCode}}\t{{.State.OOMKilled}}\t"
                    "{{.State.Error}}\t{{.RestartCount}}\t{{.State.StartedAt}}\t{{.State.FinishedAt}}"
                ),
                container_name,
            ],
            check=False,
            capture_output=True,
            timeout=15,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            "[bloodhound-ce] inspect state probe exception: "
            f"container={mark_sensitive(container_name, 'detail')} "
            f"error={mark_sensitive(str(exc), 'error')}"
        )
        return None

    if proc.returncode != 0:
        stderr = str(proc.stderr or "").strip()
        if stderr:
            print_info_debug(
                "[bloodhound-ce] inspect state probe stderr: "
                f"container={mark_sensitive(container_name, 'detail')} "
                f"stderr={mark_sensitive(stderr, 'detail')}"
            )
        return None

    raw = str(proc.stdout or "").strip()
    if not raw:
        return None
    parts = raw.split("\t")
    while len(parts) < 7:
        parts.append("")
    return {
        "status": parts[0].strip(),
        "exit_code": parts[1].strip(),
        "oom_killed": parts[2].strip(),
        "error": parts[3].strip(),
        "restart_count": parts[4].strip(),
        "started_at": parts[5].strip(),
        "finished_at": parts[6].strip(),
    }


def _print_managed_runtime_failure_hint(*, reason: str) -> None:
    """Print targeted guidance for fatal managed runtime failures."""
    project_name = get_bloodhound_compose_project_name()
    web_container = f"{project_name}-bloodhound-1"
    state = _inspect_container_runtime_state(web_container) or {}
    exit_code = str(state.get("exit_code") or "").strip()
    oom_killed = str(state.get("oom_killed") or "").strip().lower() == "true"
    probable_oom = exit_code == "137" or oom_killed

    details = [
        "BloodHound CE web container exited during startup, so authentication checks cannot continue.",
        f"Reason: {mark_sensitive(reason, 'detail')}",
    ]
    if state:
        details.append(
            "Container state: "
            f"status={mark_sensitive(state.get('status', ''), 'detail')} "
            f"exit_code={mark_sensitive(exit_code or 'unknown', 'detail')} "
            f"oom_killed={mark_sensitive(str(state.get('oom_killed', '')).lower(), 'detail')}"
        )
    if probable_oom:
        details.append(
            "Probable cause: out-of-memory kill (exit 137 / OOMKilled) while BloodHound CE was initializing."
        )
        details.append(
            "Action: free RAM or add swap, then retry `adscan install` / `adscan start`."
        )

    print_panel(
        "\n".join(details),
        title="BloodHound CE Container Exited",
        border_style="yellow",
    )
    print_instruction(f"Inspect logs: docker logs {web_container} --tail 200")
    print_instruction(
        f"Inspect state: docker inspect {web_container} --format '{{{{json .State}}}}'"
    )
    print_instruction(f"Troubleshooting guide: {_BLOODHOUND_TROUBLESHOOTING_DOCS_URL}")


def _wait_for_bloodhound_ce_api_ready(
    *,
    base_url: str,
    timeout_seconds: int = 60,
    interval_seconds: int = 1,
    required_consecutive_successes: int = 1,
    require_managed_container_health: bool = False,
) -> bool:
    """Wait for the BloodHound CE API to become reachable.

    We probe the lightweight /api/version endpoint and treat HTTP 200/401/403 as
    "ready" (API up, auth may still be required). This avoids prompting for
    credentials while the service is still starting.
    """
    if not base_url:
        base_url = f"http://localhost:{BLOODHOUND_CE_DEFAULT_WEB_PORT}"

    if required_consecutive_successes < 1:
        required_consecutive_successes = 1

    if require_managed_container_health:
        print_info("Waiting for BloodHound CE runtime to stabilize...")
    else:
        print_info("Waiting for BloodHound CE API to be ready...")
    start = time.monotonic()
    last_status: int | None = None
    last_error: Exception | None = None
    last_container_reason = "not_checked"
    consecutive_ok = 0

    while time.monotonic() - start < timeout_seconds:
        containers_ready = True
        if require_managed_container_health:
            snapshot = _get_managed_bloodhound_container_statuses()
            containers_ready, last_container_reason = (
                _evaluate_managed_bloodhound_container_readiness(snapshot)
            )
            if not containers_ready:
                consecutive_ok = 0
                if _is_fatal_managed_readiness_reason(last_container_reason):
                    print_warning(
                        "BloodHound CE containers exited during startup; runtime checks cannot continue."
                    )
                    _print_managed_runtime_failure_hint(reason=last_container_reason)
                    _print_bloodhound_ce_readiness_diagnostics()
                    return False
                time.sleep(interval_seconds)
                continue

        try:
            resp = requests.get(f"{base_url}/api/version", timeout=2)
            last_status = resp.status_code
            last_error = None
            if resp.status_code in (200, 401, 403):
                consecutive_ok += 1
                if consecutive_ok >= required_consecutive_successes:
                    return True
            else:
                consecutive_ok = 0
        except requests.exceptions.RequestException as exc:
            telemetry.capture_exception(exc)
            last_error = exc
            consecutive_ok = 0
        time.sleep(interval_seconds)

    print_warning(
        "BloodHound CE runtime did not become stable within "
        f"{timeout_seconds} seconds. The containers may still be initializing."
    )
    print_instruction(
        "Wait a moment and retry. If it keeps failing, check the BloodHound CE "
        "container logs for errors."
    )
    if last_error is not None:
        print_info_debug(
            "[bloodhound-ce] readiness probe last error: "
            f"{mark_sensitive(str(last_error), 'error')}"
        )
    if last_status is not None:
        print_info_debug(
            "[bloodhound-ce] readiness probe last status: "
            f"{mark_sensitive(str(last_status), 'status')}"
        )
    if require_managed_container_health:
        print_info_debug(
            "[bloodhound-ce] readiness probe container gate reason: "
            f"{mark_sensitive(last_container_reason, 'detail')}"
        )
    _print_bloodhound_ce_readiness_diagnostics()
    return False


def _print_bloodhound_ce_readiness_diagnostics() -> None:
    """Print best-effort docker diagnostics when BloodHound CE readiness fails."""

    def _run_docker_debug(command: list[str]) -> str | None:
        try:
            proc = run_docker(
                command,
                check=False,
                capture_output=True,
                timeout=20,
            )
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_info_debug(
                "[bloodhound-ce] readiness diagnostics command failed: "
                f"{mark_sensitive(shell_quote_cmd(command), 'detail')} "
                f"error={mark_sensitive(str(exc), 'error')}"
            )
            return None

        stdout = str(proc.stdout or "").strip()
        stderr = str(proc.stderr or "").strip()
        if proc.returncode != 0 and stderr:
            print_info_debug(
                "[bloodhound-ce] readiness diagnostics stderr: "
                f"{mark_sensitive(stderr, 'detail')}"
            )
        if stdout:
            return stdout
        return None

    ps_output = _run_docker_debug(
        ["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Status}}\t{{.Ports}}"]
    )
    if not ps_output:
        print_info_debug("[bloodhound-ce] readiness diagnostics: no docker ps output.")
        return

    managed_project = get_bloodhound_compose_project_name().lower()
    lines = [
        line
        for line in ps_output.splitlines()
        if (
            "bloodhound" in line.lower()
            or line.lower().startswith(f"{managed_project}-")
        )
    ]
    if not lines:
        print_info_debug(
            "[bloodhound-ce] readiness diagnostics: no bloodhound containers found in docker ps."
        )
        return

    print_info_debug(
        "[bloodhound-ce] readiness diagnostics containers:\n"
        f"{mark_sensitive(chr(10).join(lines), 'detail')}"
    )

    for line in lines[:3]:
        name = line.split("\t", 1)[0].strip()
        if not name:
            continue
        state = _inspect_container_runtime_state(name)
        if state:
            print_info_debug(
                "[bloodhound-ce] readiness diagnostics inspect "
                f"({mark_sensitive(name, 'detail')}): "
                f"status={mark_sensitive(state.get('status', ''), 'detail')} "
                f"exit_code={mark_sensitive(state.get('exit_code', ''), 'detail')} "
                f"oom_killed={mark_sensitive(str(state.get('oom_killed', '')).lower(), 'detail')} "
                f"restart_count={mark_sensitive(state.get('restart_count', ''), 'detail')} "
                f"error={mark_sensitive(state.get('error', ''), 'detail')}"
            )
        logs = _run_docker_debug(["docker", "logs", "--tail", "80", name])
        if not logs:
            continue
        print_info_debug(
            "[bloodhound-ce] readiness diagnostics logs "
            f"({mark_sensitive(name, 'detail')}):\n"
            f"{mark_sensitive(logs, 'detail')}"
        )


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
            print_info_verbose(
                "Docker daemon probe recovered after transient timeout."
            )
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


def _select_container_local_resolver_ip() -> str | None:
    """Pick a loopback IP in 127/8 that is free on the host for port 53.

    With `--network host`, the container shares the host network namespace.
    If the host binds 0.0.0.0:53 or [::]:53, no 127/8 address will be usable.
    """
    explicit = os.getenv("ADSCAN_LOCAL_RESOLVER_IP", "").strip()
    if explicit:
        if explicit.startswith("127.") and explicit.count(".") == 3:
            print_info_debug(
                f"[docker] Using explicit ADSCAN_LOCAL_RESOLVER_IP={explicit}"
            )
            return explicit
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

    for candidate in _LOCAL_RESOLVER_LOOPBACK_CANDIDATES:
        if candidate not in bound_ips:
            return candidate

    # If all explicit loopbacks are occupied (rare), abort.
    print_warning(
        "All candidate loopback IPs for the local resolver appear occupied on port 53: "
        f"{', '.join(_LOCAL_RESOLVER_LOOPBACK_CANDIDATES)}"
    )
    return None


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
            sudo_prefix = ["sudo", f"--preserve-env={preserve}", "-n"]
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

    for launch_attempt, force_self_exec in ((1, False), (2, True)):
        proc = _spawn_host_helper_process(
            socket_path=socket_path,
            force_self_executable=force_self_exec,
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
        GPU passthrough is intentionally **opt-in** because `/dev/dri` mapping can
        break OpenCL/Hashcat on some hosts (especially when running the container
        as a non-root UID/GID). Default behaviour should be the most reliable:
        CPU-only execution.

        Enable with:
            `export ADSCAN_DOCKER_GPU=auto`   (best-effort)
            `export ADSCAN_DOCKER_GPU=dri`    (force /dev/dri passthrough)
            `export ADSCAN_DOCKER_GPU=nvidia` (force --gpus all when supported)
            `export ADSCAN_DOCKER_GPU=all`    (dri + nvidia)
    """
    args: list[str] = []

    mode = os.getenv("ADSCAN_DOCKER_GPU", "").strip().lower()
    if not mode or mode in {"0", "false", "no", "off"}:
        return ()

    enable_dri = mode in {"1", "true", "yes", "on", "auto", "dri", "all"}
    enable_nvidia = mode in {"1", "true", "yes", "on", "auto", "nvidia", "all"}

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

    Docker-mode runs the container entrypoint as root, fixes mount ownership
    inside the container (affecting the host bind mount), and then drops
    privileges to the host UID/GID. This avoids root-owned files on the host
    without requiring the host to run privileged `chown` commands.

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


def _print_docker_install_summary(
    *,
    bloodhound_admin_password: str,
    bloodhound_auth_verified: bool = True,
    bloodhound_desired_password_verified: bool = True,
    bloodhound_stack_mode: str = DEFAULT_BLOODHOUND_STACK_MODE,
    bloodhound_base_url: str | None = None,
) -> None:
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

    # ── BloodHound CE section ──
    effective_url = (
        str(bloodhound_base_url or "").strip()
        or f"http://localhost:{BLOODHOUND_CE_DEFAULT_WEB_PORT}"
    ).rstrip("/")
    login_url = f"{effective_url}/ui/login"

    bh_header = Text("BloodHound CE", style=f"bold {BRAND_COLORS['info']}")
    renderables.append(bh_header)
    if bloodhound_auth_verified:
        renderables.append(Text("  Ready ", style="bold white on green"))
    else:
        renderables.append(Text("  Needs attention ", style="bold black on yellow"))
    renderables.append(Text(""))

    bh_table = Table.grid(padding=(0, 1))
    bh_table.add_column(justify="right", style="dim", no_wrap=True, min_width=12)
    bh_table.add_column(justify="left")
    bh_table.add_row("URL", login_url)
    bh_table.add_row("Mode", bloodhound_stack_mode)
    bh_table.add_row("Username", "admin")
    if bloodhound_desired_password_verified:
        bh_table.add_row("Password", bloodhound_admin_password)
    elif bloodhound_auth_verified:
        bh_table.add_row(
            "Password", "Configured manually/current value (see ~/.bloodhound_config)"
        )
    else:
        bh_table.add_row("Password", "UNVERIFIED")
    if not bloodhound_auth_verified:
        bh_table.add_row(
            "Action",
            "Run `adscan start` and refresh BloodHound credentials when prompted.",
        )
    renderables.append(bh_table)

    # ── Telemetry section ──
    renderables.append(Text(""))
    tele_header = Text("Telemetry", style=f"bold {BRAND_COLORS['info']}")
    renderables.append(tele_header)

    from adscan_core.telemetry import _is_telemetry_enabled

    telemetry_enabled = _is_telemetry_enabled()
    if telemetry_enabled:
        tele_status = Text("  ON", style="bold green")
        tele_status.append(" — anonymous, sanitized usage analytics", style="dim")
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
        tele_status.append(" — no data is collected", style="dim")
        renderables.append(tele_status)

    # ── Render panel ──
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


def _print_managed_bloodhound_runtime_troubleshooting(
    *,
    command_name: str,
    compose_path: Path | None,
    failure_reason: str,
    auth_failed: bool = False,
) -> None:
    """Render actionable troubleshooting guidance for managed BloodHound CE failures."""
    project_name = get_bloodhound_compose_project_name()
    login_url = f"http://localhost:{BLOODHOUND_CE_DEFAULT_WEB_PORT}/ui/login"
    compose_path_display = (
        mark_sensitive(str(compose_path), "path") if compose_path else "UNAVAILABLE"
    )
    details = [
        "ADscan requires a healthy managed BloodHound CE stack to continue.",
        f"Command: {command_name}",
        f"Failure: {failure_reason}",
        f"Managed compose path: {compose_path_display}",
        (
            "Compose source: bundled with ADscan (works for PyPI installs), then "
            "written to the managed path above."
        ),
        f"Expected UI: {mark_sensitive(login_url, 'url')}",
    ]
    if auth_failed:
        details.append(
            "Authentication to BloodHound CE could not be verified with the current "
            "managed configuration."
        )
        details.append(
            "If ~/.bloodhound_config is stale or corrupt, ADscan can recreate it "
            "after valid credentials are provided."
        )
    print_panel(
        "\n".join(details),
        title="BloodHound CE Runtime Required",
        border_style="yellow",
    )

    if compose_path:
        marked_path = mark_sensitive(str(compose_path), "path")
        print_instruction(
            f"Try: docker compose -p {project_name} -f {marked_path} pull"
        )
        print_instruction(
            f"Try: docker compose -p {project_name} -f {marked_path} up -d"
        )
        print_instruction(f"Try: docker compose -p {project_name} -f {marked_path} ps")
    else:
        print_instruction("Run: adscan install")

    print_instruction(
        f"Inspect logs: docker logs {project_name}-bloodhound-1 --tail 200"
    )
    print_instruction(f"Troubleshooting guide: {_BLOODHOUND_TROUBLESHOOTING_DOCS_URL}")


def _ensure_managed_bloodhound_runtime_ready(
    *,
    command_name: str,
    desired_password: str | None = None,
    pull_missing_images: bool,
    pull_stream_output: bool,
    pull_timeout_seconds: int | None = None,
    start_stack: bool,
    verify_auth: bool,
    allow_auth_bootstrap: bool,
    allow_low_memory: bool = False,
) -> tuple[bool, Path | None]:
    """Ensure the managed BloodHound CE compose stack is usable for Docker mode."""
    compose_path = ensure_bloodhound_compose_file(version=BLOODHOUND_CE_VERSION)
    if not compose_path:
        _print_managed_bloodhound_runtime_troubleshooting(
            command_name=command_name,
            compose_path=None,
            failure_reason="Managed BloodHound CE compose file is unavailable.",
        )
        return False, None

    if start_stack:
        free_mem_gb = _get_free_memory_bytes() / (1024**3)
        if not _enforce_bloodhound_memory_preflight(
            free_mem_gb=free_mem_gb,
            command_name=command_name,
            allow_low_memory=allow_low_memory,
        ):
            return False, compose_path

    images = compose_list_images(compose_path)
    if images is None:
        _print_managed_bloodhound_runtime_troubleshooting(
            command_name=command_name,
            compose_path=compose_path,
            failure_reason="Could not resolve images from managed compose file.",
        )
        return False, compose_path

    present, missing = compose_images_present(images)
    if not present:
        print_warning("Some BloodHound CE images are missing locally.")
        print_info_debug(f"[bloodhound-ce] missing images: {missing}")
        if pull_missing_images:
            print_info("Pulling missing BloodHound CE images...")
            if not _run_bloodhound_compose_pull_with_daemon_recovery(
                compose_path=compose_path,
                stream_output=pull_stream_output,
                pull_timeout_seconds=pull_timeout_seconds,
                command_name=command_name,
            ):
                _print_managed_bloodhound_runtime_troubleshooting(
                    command_name=command_name,
                    compose_path=compose_path,
                    failure_reason="Failed to pull managed BloodHound CE images.",
                )
                return False, compose_path
        else:
            _print_managed_bloodhound_runtime_troubleshooting(
                command_name=command_name,
                compose_path=compose_path,
                failure_reason="Managed BloodHound CE images are missing.",
            )
            return False, compose_path

    if start_stack and not _run_bloodhound_compose_up_with_daemon_recovery(
        compose_path=compose_path
    ):
        _print_managed_bloodhound_runtime_troubleshooting(
            command_name=command_name,
            compose_path=compose_path,
            failure_reason="Managed BloodHound CE stack could not be started.",
        )
        return False, compose_path

    if verify_auth and not _ensure_bloodhound_ce_auth_for_docker(
        desired_password=desired_password or _get_bloodhound_admin_password(),
        allow_managed_password_bootstrap=allow_auth_bootstrap,
        allow_destructive_reset=allow_auth_bootstrap,
        recovery_compose_path=compose_path,
    ):
        _print_managed_bloodhound_runtime_troubleshooting(
            command_name=command_name,
            compose_path=compose_path,
            failure_reason="Managed BloodHound CE authentication validation failed.",
            auth_failed=True,
        )
        return False, compose_path

    return True, compose_path


def handle_install_docker(
    *,
    bloodhound_admin_password: str,
    suppress_bloodhound_browser: bool,
    pull_timeout_seconds: int | None = None,
    bloodhound_stack_mode: str | None = None,
    allow_low_memory: bool = False,
) -> bool:
    """Install ADscan via Docker (pull image + bootstrap BloodHound CE)."""
    _emit_docker_runtime_context(command_name="install")
    _emit_docker_host_resources_context(command_name="install")
    password_len = len(str(bloodhound_admin_password or ""))
    resolved_stack_mode = _normalize_bloodhound_stack_mode(bloodhound_stack_mode)
    print_info_debug(
        "[bloodhound-ce] install desired admin password metadata: "
        f"length={password_len}, custom={bloodhound_admin_password != DEFAULT_BLOODHOUND_ADMIN_PASSWORD}"
    )
    policy_ok, policy_error = validate_bloodhound_admin_password_policy(
        bloodhound_admin_password
    )
    if not policy_ok:
        print_error(policy_error or "Invalid BloodHound CE admin password.")
        print_instruction(
            "Use --bloodhound-admin-password with at least 12 characters, one lowercase, one uppercase, one number, and one of (!@#$%^&*)."
        )
        telemetry.capture(
            "docker_install_failed",
            {
                "success": False,
                "failure_stage": "bloodhound_password_validation",
                "failure_reason": "password_policy",
                "password_length": password_len,
            },
        )
        return False

    # Track installation start
    telemetry.capture(
        "docker_install_started",
        {
            "bloodhound_admin_password_custom": (
                bloodhound_admin_password != "Adscan4thewin!"
            ),
            "bloodhound_stack_mode": resolved_stack_mode,
            "suppress_browser": suppress_bloodhound_browser,
            "in_container": is_docker_env(),
        },
    )
    start_time = time.monotonic()

    image = _get_docker_image()
    print_info("Installing ADscan (Docker mode)...")

    # Check Docker availability
    if not docker_available():
        telemetry.capture(
            "docker_install_check_docker_availability",
            {
                "docker_available": False,
                "docker_in_path": False,
            },
        )
        telemetry.capture(
            "docker_failure_constraint",
            {
                "constraint_type": "docker_not_installed",
                "failure_stage": "docker_check",
                "user_guided_to_docs": True,
                "legacy_fallback_suggested": True,
            },
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
            f"Install Docker + Docker Compose, then retry. Guide: {_DOCKER_INSTALL_DOCS_URL}"
        )
        return False

    if not _ensure_docker_compose_prerequisites(command_name="install"):
        telemetry.capture(
            "docker_install_failed",
            {
                "success": False,
                "total_duration_seconds": time.monotonic() - start_time,
                "failure_stage": "docker_prerequisites",
                "failure_reason": "docker_or_compose_missing",
            },
        )
        return False

    # Docker is available
    telemetry.capture(
        "docker_install_check_docker_availability",
        {
            "docker_available": True,
            "needs_sudo": docker_needs_sudo(),
        },
    )

    # Resource preflight: ensure enough disk space for Docker image pulls.
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
    if not _enforce_bloodhound_memory_preflight(
        free_mem_gb=free_mem_gb,
        command_name="install",
        allow_low_memory=allow_low_memory,
    ):
        telemetry.capture(
            "docker_failure_constraint",
            {
                "constraint_type": "low_memory",
                "failure_stage": "resource_preflight",
                "user_guided_to_docs": True,
            },
        )
        telemetry.capture(
            "docker_install_failed",
            {
                "success": False,
                "total_duration_seconds": time.monotonic() - start_time,
                "failure_stage": "resource_preflight",
                "failure_reason": "low_memory",
                "free_memory_gb": round(float(free_mem_gb), 2),
                "hard_threshold_gb": _LOW_MEMORY_HARD_BLOCK_THRESHOLD_GB,
                "warning_threshold_gb": _LOW_MEMORY_WARNING_THRESHOLD_GB,
            },
        )
        return False

    # Pull ADscan image
    print_info(f"Pulling image: {image}")
    image_pull_start = time.monotonic()
    telemetry.capture(
        "docker_install_pull_adscan_image_started",
        {
            "image": image,
        },
    )

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
            {
                "failure_reason": "network_or_timeout",
            },
        )
        telemetry.capture(
            "docker_failure_constraint",
            {
                "constraint_type": "image_pull_failed",
                "failure_stage": "image_pull",
                "user_guided_to_docs": True,
            },
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

    auth_verified = False
    desired_password_verified = False
    password_automation_ok = False
    effective_bloodhound_url = f"http://localhost:{BLOODHOUND_CE_DEFAULT_WEB_PORT}"

    # BloodHound compose download
    print_info("Configuring BloodHound CE stack (docker compose)...")
    telemetry.capture(
        "docker_install_bloodhound_compose_download_started",
        {
            "source_url": "github.com/SpecterOps/bloodhound",
        },
    )

    compose_path = ensure_bloodhound_compose_file(version=BLOODHOUND_CE_VERSION)
    if not compose_path:
        telemetry.capture(
            "docker_failure_constraint",
            {
                "constraint_type": "compose_download_failed",
                "failure_stage": "compose_download",
                "user_guided_to_docs": True,
            },
        )
        telemetry.capture(
            "docker_install_failed",
            {
                "success": False,
                "total_duration_seconds": time.monotonic() - start_time,
                "failure_stage": "compose_download",
            },
        )
        _print_managed_bloodhound_runtime_troubleshooting(
            command_name="install",
            compose_path=None,
            failure_reason="Managed BloodHound CE compose file setup failed.",
        )
        return False

    telemetry.capture(
        "docker_install_bloodhound_compose_download_completed",
        {
            "success": True,
            "bloodhound_version": BLOODHOUND_CE_VERSION,
        },
    )

    # BloodHound image pull
    telemetry.capture(
        "docker_install_bloodhound_pull_started",
        {
            "compose_path": str(compose_path),
        },
    )

    if not _run_bloodhound_compose_pull_with_daemon_recovery(
        compose_path=compose_path,
        stream_output=True,
        pull_timeout_seconds=pull_timeout_seconds,
        command_name="install",
    ):
        telemetry.capture(
            "docker_failure_constraint",
            {
                "constraint_type": "bloodhound_pull_failed",
                "failure_stage": "bloodhound_pull",
            },
        )
        telemetry.capture(
            "docker_install_failed",
            {
                "success": False,
                "total_duration_seconds": time.monotonic() - start_time,
                "failure_stage": "bloodhound_pull",
            },
        )
        print_error("Failed to pull BloodHound CE images.")
        _print_managed_bloodhound_runtime_troubleshooting(
            command_name="install",
            compose_path=compose_path,
            failure_reason="Failed to pull managed BloodHound CE images.",
        )
        return False

    telemetry.capture(
        "docker_install_bloodhound_pull_completed",
        {
            "success": True,
        },
    )

    # BloodHound compose up
    if not _run_bloodhound_compose_up_with_daemon_recovery(compose_path=compose_path):
        telemetry.capture(
            "docker_install_failed",
            {
                "success": False,
                "total_duration_seconds": time.monotonic() - start_time,
                "failure_stage": "bloodhound_up",
            },
        )
        _print_managed_bloodhound_runtime_troubleshooting(
            command_name="install",
            compose_path=compose_path,
            failure_reason="Managed BloodHound CE stack did not start.",
        )
        return False

    telemetry.capture(
        "docker_install_bloodhound_compose_up_completed",
        {
            "success": True,
        },
    )

    # Resolve BloodHound CE auth with first-run + reuse + recovery fallbacks.
    (
        auth_verified,
        desired_password_verified,
        password_automation_ok,
    ) = _bootstrap_bloodhound_ce_auth(
        compose_path=compose_path,
        desired_password=bloodhound_admin_password,
        suppress_browser=suppress_bloodhound_browser,
    )

    telemetry.capture(
        "docker_install_bloodhound_auth_completed",
        {
            "password_automation_ok": bool(password_automation_ok),
            "desired_password_verified": bool(desired_password_verified),
            "auth_verified": bool(auth_verified),
            "stack_mode": resolved_stack_mode,
        },
    )
    if not auth_verified:
        print_warning(
            "BloodHound CE is running, but authentication could not be verified automatically."
        )
        _print_managed_bloodhound_runtime_troubleshooting(
            command_name="install",
            compose_path=compose_path,
            failure_reason="Managed BloodHound CE authentication could not be verified.",
            auth_failed=True,
        )

    # Installation completed successfully
    telemetry.capture(
        "docker_install_completed",
        {
            "success": True,
            "total_duration_seconds": time.monotonic() - start_time,
            "bloodhound_version": BLOODHOUND_CE_VERSION,
            "image": image,
        },
    )

    _print_docker_install_summary(
        bloodhound_admin_password=bloodhound_admin_password,
        bloodhound_auth_verified=bool(auth_verified),
        bloodhound_desired_password_verified=bool(desired_password_verified),
        bloodhound_stack_mode=resolved_stack_mode,
        bloodhound_base_url=effective_bloodhound_url,
    )

    return True


def handle_check_docker(
    *,
    bloodhound_stack_mode: str | None = None,
    allow_low_memory: bool = False,
) -> bool:
    """Check ADscan Docker-mode prerequisites."""
    _emit_docker_runtime_context(command_name="check")
    _emit_docker_host_resources_context(command_name="check")
    image = _select_existing_or_preferred_image()
    all_ok = True
    _normalize_bloodhound_stack_mode(bloodhound_stack_mode)

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

    managed_ready, _compose_path = _ensure_managed_bloodhound_runtime_ready(
        command_name="check",
        desired_password=_get_bloodhound_admin_password(),
        pull_missing_images=False,
        pull_stream_output=False,
        pull_timeout_seconds=None,
        start_stack=True,
        verify_auth=True,
        allow_auth_bootstrap=False,
        allow_low_memory=allow_low_memory,
    )
    if not managed_ready:
        all_ok = False

    # Best-effort: run `--version` inside the container to validate basic execution.
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

        helper_proc, _helper_socket = _ensure_host_helper_runtime_ready(
            command_name="check",
            run_dir=run_dir,
        )
        if helper_proc is None:
            all_ok = False
        else:
            _stop_host_helper(helper_proc)

        if all_ok:
            cfg = DockerRunConfig(
                image=image, workspaces_host_dir=workspaces_dir, interactive=False
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
                print_warning("Docker-mode execution probe failed due to an exception.")
                print_info_debug(f"[docker] probe exception: {exc}")
                all_ok = False

    return all_ok


def handle_start_docker(
    *,
    verbose: bool,
    debug: bool,
    pull_timeout_seconds: int | None = None,
    bloodhound_stack_mode: str | None = None,
    allow_low_memory: bool = False,
) -> int:
    """Start ADscan inside Docker and return the docker exit code."""
    _emit_docker_runtime_context(command_name="start")
    _emit_docker_host_resources_context(command_name="start")
    image = _select_existing_or_preferred_image()
    resolved_stack_mode = _normalize_bloodhound_stack_mode(bloodhound_stack_mode)
    compose_path: Path | None = None
    if not docker_available():
        print_error("Docker is not installed or not in PATH.")
        return 1
    if not _ensure_docker_compose_prerequisites(command_name="start"):
        return 1
    resolved_image = _ensure_runtime_image_available(
        image=image,
        pull_timeout_seconds=pull_timeout_seconds,
        command_name="start",
    )
    if not resolved_image:
        return 1
    image = resolved_image

    managed_ready, compose_path = _ensure_managed_bloodhound_runtime_ready(
        command_name="start",
        desired_password=_get_bloodhound_admin_password(),
        pull_missing_images=True,
        pull_stream_output=False,
        pull_timeout_seconds=pull_timeout_seconds,
        start_stack=True,
        verify_auth=True,
        allow_auth_bootstrap=True,
        allow_low_memory=allow_low_memory,
    )
    if not managed_ready or compose_path is None:
        return 1
    _ensure_bloodhound_config_mountable()
    print_info_debug(
        "[bloodhound-ce] host config availability before docker run: "
        f"path={mark_sensitive(str(BH_CONFIG_FILE), 'path')} "
        f"exists={BH_CONFIG_FILE.exists()}"
    )

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

    helper_proc, _helper_socket = _ensure_host_helper_runtime_ready(
        command_name="start",
        run_dir=run_dir,
    )
    if helper_proc is None:
        return 1
    try:
        gpu_args = _detect_gpu_docker_run_args()
        local_resolver_ip = _select_container_local_resolver_ip()
        if local_resolver_ip is None:
            return 1

        # Build extra docker run args, including GPU flags and a bind mount for the
        # shared BloodHound CE configuration so host and container always see the
        # same ~/.bloodhound_config.
        extra_run_args: list[str] = list(gpu_args)
        try:
            if BH_CONFIG_FILE.exists():
                print_info_debug(
                    "[bloodhound-ce] mounting host config into container: "
                    f"{mark_sensitive(str(BH_CONFIG_FILE), 'path')} -> "
                    "/opt/adscan/.bloodhound_config"
                )
                extra_run_args.extend(
                    [
                        "-v",
                        f"{BH_CONFIG_FILE}:/opt/adscan/.bloodhound_config",
                    ]
                )
            else:
                print_info_debug(
                    "[bloodhound-ce] host config missing; no mount for ~/.bloodhound_config"
                )
        except Exception:
            # Best-effort only; failure to mount the config should not break docker
            # start, but may cause host/container configs to diverge.
            pass

        cfg = DockerRunConfig(
            image=image,
            workspaces_host_dir=workspaces,
            interactive=True,
            extra_run_args=tuple(extra_run_args),
            extra_env=tuple(
                [("ADSCAN_BLOODHOUND_STACK_MODE", resolved_stack_mode)]
                + (
                    [("ADSCAN_HOST_BLOODHOUND_COMPOSE", str(compose_path))]
                    if compose_path is not None
                    else []
                )
                + [
                    ("ADSCAN_LOCAL_RESOLVER_IP", local_resolver_ip),
                    ("ADSCAN_DIAG_LOGGING", os.getenv("ADSCAN_DIAG_LOGGING", "")),
                ]
            ),
        )

        adscan_args: list[str] = []
        if verbose:
            # Subcommand-scoped flag.
            pass
        if debug:
            # Subcommand-scoped flag.
            pass
        adscan_args.append("start")
        if verbose:
            adscan_args.append("--verbose")
        if debug:
            adscan_args.append("--debug")

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
        _stop_host_helper(helper_proc)


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
    pull_timeout_seconds: int | None = None,
    bloodhound_stack_mode: str | None = None,
    allow_low_memory: bool = False,
) -> int:
    """Run `adscan ci` inside Docker and return the docker exit code."""
    _emit_docker_runtime_context(command_name="ci")
    _emit_docker_host_resources_context(command_name="ci")
    image = _select_existing_or_preferred_image()
    resolved_stack_mode = _normalize_bloodhound_stack_mode(bloodhound_stack_mode)
    compose_path: Path | None = None
    if not docker_available():
        print_error("Docker is not installed or not in PATH.")
        return 1
    if not _ensure_docker_compose_prerequisites(command_name="ci"):
        return 1
    resolved_image = _ensure_runtime_image_available(
        image=image,
        pull_timeout_seconds=pull_timeout_seconds,
        command_name="ci",
    )
    if not resolved_image:
        return 1
    image = resolved_image

    managed_ready, compose_path = _ensure_managed_bloodhound_runtime_ready(
        command_name="ci",
        desired_password=_get_bloodhound_admin_password(),
        pull_missing_images=True,
        pull_stream_output=False,
        pull_timeout_seconds=pull_timeout_seconds,
        start_stack=True,
        verify_auth=True,
        allow_auth_bootstrap=True,
        allow_low_memory=allow_low_memory,
    )
    if not managed_ready or compose_path is None:
        return 1

    workspaces_dir = _get_workspaces_dir()
    config_dir = _get_config_dir()
    codex_dir = _get_codex_container_dir()
    logs_dir = _get_logs_dir()
    run_dir = _get_run_dir()
    state_dir = _get_state_dir()
    if not _ensure_host_mount_dir_writable(workspaces_dir, description="Workspaces"):
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

    helper_proc, _helper_socket = _ensure_host_helper_runtime_ready(
        command_name="ci",
        run_dir=run_dir,
    )
    if helper_proc is None:
        return 1

    try:
        # Preserve Rich colors when running locally: allocate a TTY when the host has one.
        # In CI (no TTY), we avoid `-t` to prevent "the input device is not a TTY" errors.
        interactive = bool(sys.stdin.isatty() and sys.stdout.isatty())
        local_resolver_ip = _select_container_local_resolver_ip()
        if local_resolver_ip is None:
            return 1
        _ensure_bloodhound_config_mountable()
        extra_run_args: list[str] = []
        try:
            if BH_CONFIG_FILE.exists():
                print_info_debug(
                    "[bloodhound-ce] mounting host config into container: "
                    f"{mark_sensitive(str(BH_CONFIG_FILE), 'path')} -> "
                    "/opt/adscan/.bloodhound_config"
                )
                extra_run_args.extend(
                    [
                        "-v",
                        f"{BH_CONFIG_FILE}:/opt/adscan/.bloodhound_config",
                    ]
                )
            else:
                print_info_debug(
                    "[bloodhound-ce] host config missing; no mount for ~/.bloodhound_config"
                )
        except Exception:
            pass
        cfg = DockerRunConfig(
            image=image,
            workspaces_host_dir=workspaces_dir,
            interactive=interactive,
            extra_run_args=tuple(extra_run_args),
            extra_env=tuple(
                [("ADSCAN_BLOODHOUND_STACK_MODE", resolved_stack_mode)]
                + (
                    [("ADSCAN_HOST_BLOODHOUND_COMPOSE", str(compose_path))]
                    if compose_path is not None
                    else []
                )
                + [
                    ("ADSCAN_LOCAL_RESOLVER_IP", local_resolver_ip),
                    ("ADSCAN_DIAG_LOGGING", os.getenv("ADSCAN_DIAG_LOGGING", "")),
                ]
            ),
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
        _stop_host_helper(helper_proc)


def update_docker_image(*, pull_timeout_seconds: int | None = None) -> int:
    """Pull the configured ADscan Docker image.

    Returns:
        Process exit code (0 success).
    """
    _emit_docker_runtime_context(command_name="update")
    _emit_docker_host_resources_context(command_name="update")
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


def run_adscan_passthrough_docker(
    *,
    adscan_args: list[str],
    verbose: bool,
    debug: bool,
    pull_timeout_seconds: int | None = None,
    bloodhound_stack_mode: str | None = None,
    allow_low_memory: bool = False,
) -> int:
    """Run an arbitrary `adscan ...` command inside the container (host-side).

    This is used by the PyPI launcher to avoid duplicating the full internal
    CLI argument parsing while still keeping Docker-mode preflight consistent.
    """
    _emit_docker_runtime_context(command_name="passthrough")
    _emit_docker_host_resources_context(command_name="passthrough")
    image = _select_existing_or_preferred_image()
    resolved_stack_mode = _normalize_bloodhound_stack_mode(bloodhound_stack_mode)
    compose_path: Path | None = None
    if not docker_available():
        print_error("Docker is not installed or not in PATH.")
        return 1
    if not _ensure_docker_compose_prerequisites(command_name="passthrough"):
        return 1
    resolved_image = _ensure_runtime_image_available(
        image=image,
        pull_timeout_seconds=pull_timeout_seconds,
        command_name="passthrough",
    )
    if not resolved_image:
        return 1
    image = resolved_image

    managed_ready, compose_path = _ensure_managed_bloodhound_runtime_ready(
        command_name="passthrough",
        desired_password=_get_bloodhound_admin_password(),
        pull_missing_images=True,
        pull_stream_output=True,
        pull_timeout_seconds=pull_timeout_seconds,
        start_stack=True,
        verify_auth=True,
        allow_auth_bootstrap=True,
        allow_low_memory=allow_low_memory,
    )
    if not managed_ready or compose_path is None:
        return 1

    workspaces_dir = _get_workspaces_dir()
    config_dir = _get_config_dir()
    codex_dir = _get_codex_container_dir()
    logs_dir = _get_logs_dir()
    run_dir = _get_run_dir()
    state_dir = _get_state_dir()
    if not _ensure_host_mount_dir_writable(workspaces_dir, description="Workspaces"):
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

    helper_proc, _helper_socket = _ensure_host_helper_runtime_ready(
        command_name="passthrough",
        run_dir=run_dir,
    )
    if helper_proc is None:
        return 1
    try:
        # Preserve Rich colors when running locally: allocate a TTY when the host has one.
        interactive = bool(sys.stdin.isatty() and sys.stdout.isatty())
        local_resolver_ip = _select_container_local_resolver_ip()
        if local_resolver_ip is None:
            return 1
        _ensure_bloodhound_config_mountable()
        extra_run_args: list[str] = []
        try:
            if BH_CONFIG_FILE.exists():
                extra_run_args.extend(
                    [
                        "-v",
                        f"{BH_CONFIG_FILE}:/opt/adscan/.bloodhound_config",
                    ]
                )
        except Exception:
            pass

        cfg = DockerRunConfig(
            image=image,
            workspaces_host_dir=workspaces_dir,
            interactive=interactive,
            extra_run_args=tuple(extra_run_args),
            extra_env=tuple(
                [("ADSCAN_BLOODHOUND_STACK_MODE", resolved_stack_mode)]
                + (
                    [("ADSCAN_HOST_BLOODHOUND_COMPOSE", str(compose_path))]
                    if compose_path is not None
                    else []
                )
                + [
                    ("ADSCAN_LOCAL_RESOLVER_IP", local_resolver_ip),
                    ("ADSCAN_DIAG_LOGGING", os.getenv("ADSCAN_DIAG_LOGGING", "")),
                ]
            ),
        )

        container_args: list[str] = list(adscan_args)
        if verbose:
            container_args.append("--verbose")
        if debug:
            container_args.append("--debug")

        cmd = build_adscan_run_command(cfg, adscan_args=container_args)
        print_info_debug(f"[docker] passthrough: {shell_quote_cmd(cmd)}")
        proc = run_docker(cmd, check=False, capture_output=False, timeout=None)
        return int(proc.returncode)
    except subprocess.SubprocessError as exc:
        telemetry.capture_exception(exc)
        print_error("Failed to run ADscan in Docker.")
        print_info_debug(f"[docker] passthrough exception: {exc}")
        return 1
    finally:
        _stop_host_helper(helper_proc)
