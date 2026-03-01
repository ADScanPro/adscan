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
import re
import secrets
import time
from pathlib import Path

import requests
from rich.prompt import Confirm
import configparser

from adscan_launcher import telemetry
from adscan_launcher.bloodhound_ce_compose import (
    BLOODHOUND_CE_DEFAULT_WEB_PORT,
    BLOODHOUND_CE_VERSION,
    compose_images_present,
    compose_list_images,
    compose_pull,
    compose_up,
    ensure_bloodhound_compose_file,
    get_bloodhound_compose_path,
)
from adscan_launcher.bloodhound_ce_password import ensure_bloodhound_admin_password
from adscan_launcher.docker_runtime import (
    DockerRunConfig,
    build_adscan_run_command,
    docker_available,
    docker_needs_sudo,
    ensure_image_pulled,
    image_exists,
    is_docker_env,
    run_docker,
    shell_quote_cmd,
)
from adscan_launcher.output import (
    mark_sensitive,
    print_error,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_instruction,
    print_panel,
    print_success,
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
DEFAULT_HOST_HELPER_SOCKET_NAME = "host-helper.sock"
_DOCKER_RUN_HELP_HAS_GPUS_RE = re.compile(r"\\s--gpus\\b", re.IGNORECASE)
_DOCKER_INSTALL_DOCS_URL = "https://www.adscanpro.com/docs/getting-started/installation"
_LOCAL_RESOLVER_LOOPBACK_CANDIDATES = (
    "127.0.0.2",
    "127.0.0.3",
    "127.0.0.4",
    "127.0.0.5",
    "127.0.0.1",
)
_MIN_DOCKER_INSTALL_FREE_GB = 10
_DEFAULT_DOCKER_PULL_TIMEOUT_SECONDS = 3600
_EPHEMERAL_CONTAINER_SHARED_TOKEN: str | None = None
_LEGACY_IMAGE_WARNING_SHOWN = False

# Keep BloodHound CE config in the effective user's home (sudo-safe), matching
# the default behavior of bloodhound-cli tooling.
BH_CONFIG_FILE = get_effective_user_home() / ".bloodhound_config"


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


def _get_free_memory_bytes() -> int:
    """Return available system memory in bytes (best effort)."""
    try:
        page_size = os.sysconf("SC_PAGE_SIZE")
        avail_pages = os.sysconf("SC_AVPHYS_PAGES")
        return int(page_size * avail_pages)
    except (OSError, ValueError, AttributeError):
        return 0


def _log_install_resource_status(path: Path) -> tuple[float, float]:
    """Log free disk and memory, returning values in GB."""
    free_disk_bytes = _get_free_disk_bytes(path)
    free_mem_bytes = _get_free_memory_bytes()
    free_disk_gb = free_disk_bytes / (1024**3)
    free_mem_gb = free_mem_bytes / (1024**3)
    print_info_debug(
        f"[install] Free disk: {free_disk_gb:.2f} GB | Free RAM: {free_mem_gb:.2f} GB"
    )
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
    3. Legacy naming fallback (`adscan/adscan*`) for backward compatibility
    """
    explicit = os.getenv("ADSCAN_DOCKER_IMAGE", "").strip()
    if explicit:
        return [explicit]

    channel = os.getenv("ADSCAN_DOCKER_CHANNEL", "").strip().lower()
    if channel == "dev":
        return [DEFAULT_DEV_DOCKER_IMAGE, LEGACY_DEFAULT_DEV_DOCKER_IMAGE]

    return [DEFAULT_DOCKER_IMAGE, LEGACY_DEFAULT_DOCKER_IMAGE]


def _get_docker_image() -> str:
    """Return the preferred Docker image for this environment."""
    return _get_docker_image_candidates()[0]


def _warn_using_legacy_image(*, selected_image: str, preferred_image: str) -> None:
    """Emit a one-time warning when legacy image naming is selected."""
    global _LEGACY_IMAGE_WARNING_SHOWN  # pylint: disable=global-statement
    if _LEGACY_IMAGE_WARNING_SHOWN:
        return
    if selected_image == preferred_image:
        return
    print_warning(
        "Using legacy Docker image naming for compatibility: "
        f"{selected_image} (preferred: {preferred_image})."
    )
    _LEGACY_IMAGE_WARNING_SHOWN = True


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


def _ensure_image_pulled_with_legacy_fallback(
    *,
    pull_timeout: int | None,
    stream_output: bool,
) -> str | None:
    """Pull preferred image, then fallback to legacy naming if needed."""
    candidates = _get_docker_image_candidates()
    preferred = candidates[0]
    for idx, candidate in enumerate(candidates):
        if idx > 0:
            print_warning(
                "Primary Docker image pull failed; trying legacy image naming: "
                f"{candidate}"
            )
        if ensure_image_pulled(candidate, timeout=pull_timeout, stream_output=stream_output):
            _warn_using_legacy_image(
                selected_image=candidate,
                preferred_image=preferred,
            )
            return candidate
    return None


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
        config.read(str(BH_CONFIG_FILE))
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
    if not BH_CONFIG_FILE.exists():
        return False

    config = configparser.ConfigParser()
    config.read(str(BH_CONFIG_FILE))
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


def _ensure_bloodhound_ce_auth_for_docker() -> bool:
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
    desired_password = _get_bloodhound_admin_password()

    if not BH_CONFIG_FILE.exists():
        print_info_verbose(
            "BloodHound CE config not found on host; attempting default auth."
        )
        if _persist_bloodhound_ce_config(username="admin", password=desired_password):
            print_success("BloodHound CE config created on host.")
        else:
            if not sys.stdin.isatty():
                print_warning(
                    "Default BloodHound CE password failed and no TTY available for prompt."
                )
                return False
            print_warning(
                "Default BloodHound CE password failed. Please enter the current password."
            )
            try:
                new_password = getpass.getpass(
                    "BloodHound CE password (leave empty for Adscan4thewin!): "
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
                new_password = desired_password
            if not _persist_bloodhound_ce_config(
                username="admin",
                password=new_password,
            ):
                print_warning(
                    "Could not create BloodHound CE config with the provided password."
                )
                return False
    else:
        if not _validate_bloodhound_ce_config():
            marked_path = mark_sensitive(str(BH_CONFIG_FILE), "path")
            print_warning(
                "BloodHound CE config is missing required fields; refreshing it."
            )
            print_info_verbose(f"Config path: {marked_path}")
            config = configparser.ConfigParser()
            config.read(str(BH_CONFIG_FILE))
            stored_user = "admin"
            stored_password = None
            stored_base_url = None
            if "CE" in config:
                stored_user = config["CE"].get("username", "admin")
                stored_password = config["CE"].get("password")
                stored_base_url = config["CE"].get("base_url")
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
    base_url = f"http://127.0.0.1:{BLOODHOUND_CE_DEFAULT_WEB_PORT}"
    stored_user = "admin"
    stored_password: str | None = None
    if BH_CONFIG_FILE.exists():
        try:
            config = configparser.ConfigParser()
            config.read(str(BH_CONFIG_FILE))
            if "CE" in config:
                stored_user = config["CE"].get("username", "admin")
                stored_password = config["CE"].get("password")
                base_url = config["CE"].get("base_url") or base_url
        except Exception:
            stored_password = stored_password

    if stored_password and _persist_bloodhound_ce_config(
        username=stored_user, password=stored_password, base_url=base_url
    ):
        print_success("BloodHound CE authentication verified.")
        return True

    if not sys.stdin.isatty():
        print_warning(
            "BloodHound CE authentication could not be verified and no TTY is available for a prompt."
        )
        return False

    print_warning("BloodHound CE credentials need to be refreshed.")
    try:
        new_password = getpass.getpass(
            "BloodHound CE password (leave empty for Adscan4thewin!): "
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
        new_password = desired_password
    if not _persist_bloodhound_ce_config(
        username=stored_user,
        password=new_password,
        base_url=base_url,
    ):
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


def _wait_for_bloodhound_ce_api_ready(
    *, base_url: str, timeout_seconds: int = 60, interval_seconds: int = 1
) -> bool:
    """Wait for the BloodHound CE API to become reachable.

    We probe the lightweight /api/version endpoint and treat HTTP 200/401/403 as
    "ready" (API up, auth may still be required). This avoids prompting for
    credentials while the service is still starting.
    """
    if not base_url:
        base_url = f"http://localhost:{BLOODHOUND_CE_DEFAULT_WEB_PORT}"

    print_info("Waiting for BloodHound CE API to be ready...")
    start = time.monotonic()
    last_status: int | None = None
    last_error: Exception | None = None

    while time.monotonic() - start < timeout_seconds:
        try:
            resp = requests.get(f"{base_url}/api/version", timeout=2)
            last_status = resp.status_code
            last_error = None
            if resp.status_code in (200, 401, 403):
                return True
        except requests.exceptions.RequestException as exc:
            telemetry.capture_exception(exc)
            last_error = exc
        time.sleep(interval_seconds)

    print_warning(
        "BloodHound CE API did not become ready within "
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

    lines = [line for line in ps_output.splitlines() if "bloodhound" in line.lower()]
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


def _start_host_helper(*, socket_path: Path) -> subprocess.Popen[str] | None:
    """Start the privileged host helper via sudo (best effort)."""
    _ensure_container_shared_token()

    if not _ensure_sudo_ticket_if_needed():
        print_warning(
            "Unable to acquire sudo privileges; host clock sync will not be available "
            "from inside the container."
        )
        print_instruction(
            "If Kerberos fails due to clock skew, run on host: sudo ntpdate <PDC_IP>"
        )
        return None

    socket_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if socket_path.exists():
            socket_path.unlink()
    except OSError:
        pass

    exe = _resolve_self_executable()
    argv = [exe, "host-helper", "--socket", str(socket_path)]
    if os.geteuid() != 0:
        argv = ["sudo", "--preserve-env=CONTAINER_SHARED_TOKEN", "-n"] + argv

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
            env=os.environ.copy(),
        )
    except OSError:
        proc = subprocess.Popen(  # noqa: S603
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            env=os.environ.copy(),
        )
    finally:
        if log_fh is not None:
            try:
                log_fh.close()
            except OSError:
                pass

    return proc


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
    login_url = f"http://localhost:{BLOODHOUND_CE_DEFAULT_WEB_PORT}/ui/login"

    bh_header = Text("BloodHound CE", style=f"bold {BRAND_COLORS['info']}")
    renderables.append(bh_header)
    renderables.append(Text("  Ready ", style="bold white on green"))
    renderables.append(Text(""))

    bh_table = Table.grid(padding=(0, 1))
    bh_table.add_column(justify="right", style="dim", no_wrap=True, min_width=12)
    bh_table.add_column(justify="left")
    bh_table.add_row("URL", login_url)
    bh_table.add_row("Username", "admin")
    bh_table.add_row("Password", bloodhound_admin_password)
    renderables.append(bh_table)

    # ── Telemetry section ──
    renderables.append(Text(""))
    tele_header = Text("Telemetry", style=f"bold {BRAND_COLORS['info']}")
    renderables.append(tele_header)

    from adscan_core.telemetry import _is_telemetry_enabled

    telemetry_enabled = _is_telemetry_enabled()
    if telemetry_enabled:
        tele_status = Text("  ON", style="bold green")
        tele_status.append(
            " — anonymous, sanitized usage analytics", style="dim"
        )
        renderables.append(tele_status)
        renderables.append(Text(""))

        tele_detail = Table.grid(padding=(0, 1))
        tele_detail.add_column(
            justify="right", style="dim", no_wrap=True, min_width=12
        )
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


def handle_install_docker(
    *,
    bloodhound_admin_password: str,
    suppress_bloodhound_browser: bool,
    pull_timeout_seconds: int | None = None,
) -> bool:
    """Install ADscan via Docker (pull image + bootstrap BloodHound CE)."""
    # Track installation start
    telemetry.capture(
        "docker_install_started",
        {
            "bloodhound_admin_password_custom": (
                bloodhound_admin_password != "Adscan4thewin!"
            ),
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

        print_error("Failed to pull the ADscan Docker image.")
        print_instruction("Retry the install, or pull manually and retry:")
        pull_cmd_prefix = "sudo " if (docker_needs_sudo() and os.geteuid() != 0) else ""
        print_instruction(f"  {pull_cmd_prefix}docker pull {image}")
        suggested_timeout = 7200 if pull_timeout is None else max(pull_timeout, 7200)
        print_instruction(
            "If you are on a slow network, increase the pull timeout and retry:"
        )
        print_instruction(f"  adscan install --pull-timeout {suggested_timeout}")
        print_instruction("To disable the pull timeout entirely:")
        print_instruction("  adscan install --pull-timeout 0")
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

    if not compose_pull(compose_path, stream_output=True):
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
        return False

    telemetry.capture(
        "docker_install_bloodhound_pull_completed",
        {
            "success": True,
        },
    )

    # BloodHound compose up
    if not compose_up(compose_path):
        telemetry.capture(
            "docker_install_failed",
            {
                "success": False,
                "total_duration_seconds": time.monotonic() - start_time,
                "failure_stage": "bloodhound_up",
            },
        )
        return False

    telemetry.capture(
        "docker_install_bloodhound_compose_up_completed",
        {
            "success": True,
        },
    )

    # Set password
    ensure_bloodhound_admin_password(
        desired_password=bloodhound_admin_password,
        suppress_browser=suppress_bloodhound_browser,
    )
    _persist_bloodhound_ce_config(
        username="admin",
        password=bloodhound_admin_password,
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
    )

    return True


def handle_check_docker() -> bool:
    """Check ADscan Docker-mode prerequisites."""
    image = _select_existing_or_preferred_image()
    all_ok = True

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

    compose_path = get_bloodhound_compose_path()
    if not compose_path.exists():
        print_warning("BloodHound CE docker-compose.yml not found.")
        print_instruction("Run: adscan install (downloads compose + pulls images).")
        all_ok = False
    else:
        images = compose_list_images(compose_path)
        if images is None:
            print_warning("Could not determine BloodHound CE images from compose file.")
            print_instruction(
                "Ensure docker compose is available, then retry: adscan check"
            )
            all_ok = False
        else:
            present, missing = compose_images_present(images)
            if not present:
                all_ok = False
                print_warning("Some BloodHound CE images are missing locally.")
                print_info_debug(f"[bloodhound-ce] missing images: {missing}")
                print_instruction("Run: adscan install (pulls missing images).")

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
) -> int:
    """Start ADscan inside Docker and return the docker exit code."""
    image = _select_existing_or_preferred_image()
    if not docker_available():
        print_error("Docker is not installed or not in PATH.")
        return 1

    compose_path = ensure_bloodhound_compose_file(version=BLOODHOUND_CE_VERSION)
    if not compose_path:
        return 1
    images = compose_list_images(compose_path)
    if images is not None:
        present, missing = compose_images_present(images)
        if not present:
            print_warning("Some BloodHound CE images are missing; pulling now...")
            print_info_debug(f"[bloodhound-ce] missing images: {missing}")
            compose_pull(compose_path)
    if not compose_up(compose_path):
        print_error(
            "BloodHound CE stack could not be started automatically. "
            "ADscan Docker mode cannot proceed without a running BloodHound CE instance."
        )
        return 1

    # Require a valid BloodHound CE token before starting the Dockerized ADscan.
    if not _ensure_bloodhound_ce_auth_for_docker():
        return 1
    _ensure_bloodhound_config_mountable()
    print_info_debug(
        "[bloodhound-ce] host config availability before docker run: "
        f"path={mark_sensitive(str(BH_CONFIG_FILE), 'path')} "
        f"exists={BH_CONFIG_FILE.exists()}"
    )

    if not image_exists(image):
        print_warning(f"ADscan docker image not present: {image}")
        print_info("Pulling the image now...")
        pull_timeout = _normalize_pull_timeout_seconds(pull_timeout_seconds)
        resolved_image = _ensure_image_pulled_with_legacy_fallback(
            pull_timeout=pull_timeout,
            stream_output=True,
        )
        if not resolved_image:
            print_error("Failed to pull the ADscan Docker image.")
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

    helper_proc: subprocess.Popen[str] | None = None
    helper_socket = run_dir / DEFAULT_HOST_HELPER_SOCKET_NAME
    helper_proc = _start_host_helper(socket_path=helper_socket)
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
        extra_env=(
            ("ADSCAN_HOST_BLOODHOUND_COMPOSE", str(compose_path)),
            ("ADSCAN_LOCAL_RESOLVER_IP", local_resolver_ip),
            ("ADSCAN_DIAG_LOGGING", os.getenv("ADSCAN_DIAG_LOGGING", "")),
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
) -> int:
    """Run `adscan ci` inside Docker and return the docker exit code."""
    image = _select_existing_or_preferred_image()
    if not docker_available():
        print_error("Docker is not installed or not in PATH.")
        return 1

    compose_path = ensure_bloodhound_compose_file(version=BLOODHOUND_CE_VERSION)
    if not compose_path:
        return 1
    images = compose_list_images(compose_path)
    if images is not None:
        present, missing = compose_images_present(images)
        if not present:
            print_warning("Some BloodHound CE images are missing; pulling now...")
            print_info_debug(f"[bloodhound-ce] missing images: {missing}")
            compose_pull(compose_path)

    if not image_exists(image):
        print_warning(f"ADscan docker image not present: {image}")
        print_info("Pulling the image now...")
        pull_timeout = _normalize_pull_timeout_seconds(pull_timeout_seconds)
        resolved_image = _ensure_image_pulled_with_legacy_fallback(
            pull_timeout=pull_timeout,
            stream_output=True,
        )
        if not resolved_image:
            print_error("Failed to pull the ADscan Docker image.")
            return 1
        image = resolved_image

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

    helper_proc: subprocess.Popen[str] | None = None
    helper_socket = run_dir / DEFAULT_HOST_HELPER_SOCKET_NAME
    helper_proc = _start_host_helper(socket_path=helper_socket)

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
        extra_env=(
            ("ADSCAN_HOST_BLOODHOUND_COMPOSE", str(compose_path)),
            ("ADSCAN_LOCAL_RESOLVER_IP", local_resolver_ip),
            ("ADSCAN_DIAG_LOGGING", os.getenv("ADSCAN_DIAG_LOGGING", "")),
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
        print_error("Failed to pull the ADscan Docker image.")
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
) -> int:
    """Run an arbitrary `adscan ...` command inside the container (host-side).

    This is used by the PyPI launcher to avoid duplicating the full internal
    CLI argument parsing while still keeping Docker-mode preflight consistent.
    """
    image = _select_existing_or_preferred_image()
    if not docker_available():
        print_error("Docker is not installed or not in PATH.")
        return 1

    compose_path = ensure_bloodhound_compose_file(version=BLOODHOUND_CE_VERSION)
    if not compose_path:
        return 1
    images = compose_list_images(compose_path)
    if images is not None:
        present, missing = compose_images_present(images)
        if not present:
            print_warning("Some BloodHound CE images are missing; pulling now...")
            print_info_debug(f"[bloodhound-ce] missing images: {missing}")
            compose_pull(compose_path, stream_output=True)

    if not image_exists(image):
        print_warning(f"ADscan docker image not present: {image}")
        print_info("Pulling the image now...")
        pull_timeout = _normalize_pull_timeout_seconds(pull_timeout_seconds)
        resolved_image = _ensure_image_pulled_with_legacy_fallback(
            pull_timeout=pull_timeout,
            stream_output=True,
        )
        if not resolved_image:
            print_error("Failed to pull the ADscan Docker image.")
            return 1
        image = resolved_image

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

    helper_proc: subprocess.Popen[str] | None = None
    helper_socket = run_dir / DEFAULT_HOST_HELPER_SOCKET_NAME
    helper_proc = _start_host_helper(socket_path=helper_socket)
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
            extra_env=(
                ("ADSCAN_HOST_BLOODHOUND_COMPOSE", str(compose_path)),
                ("ADSCAN_LOCAL_RESOLVER_IP", local_resolver_ip),
                ("ADSCAN_DIAG_LOGGING", os.getenv("ADSCAN_DIAG_LOGGING", "")),
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
