"""BloodHound CE (docker compose) helpers for Docker-first ADscan mode.

This module manages the BloodHound CE stack using docker compose directly:
  - ensure the pinned docker-compose.yml exists under the user's config dir
  - `docker compose pull` to prefetch required images
  - `docker compose up -d` to start the stack

The goal is to avoid host-level installers and external helpers (e.g. downloading
`bloodhound-ce-cli`) while keeping the workflow robust and repeatable.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
import urllib.request
from importlib import resources
from pathlib import Path
from typing import Callable

from adscan_launcher import telemetry
from adscan_launcher.docker_runtime import (
    docker_available,
    run_docker,
    run_docker_stream,
    shell_quote_cmd,
)
from adscan_launcher.path_utils import expand_effective_user_path, get_adscan_home
from adscan_launcher.output import (
    confirm_operation,
    mark_sensitive,
    print_error,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_instruction,
    print_success,
    print_warning,
)


BLOODHOUND_CE_DEFAULT_WEB_PORT = 8442
BLOODHOUND_CE_GRAPH_HTTP_PORT = 17474
BLOODHOUND_CE_GRAPH_BOLT_PORT = 17687
BLOODHOUND_CE_VERSION = "7.4.1"
BLOODHOUND_COMPOSE_URL = "https://raw.githubusercontent.com/SpecterOps/bloodhound/main/examples/docker-compose/docker-compose.yml"
_VENDORED_BLOODHOUND_COMPOSE_RESOURCE = "assets/bloodhound/docker-compose.yml"
_ALLOW_REMOTE_COMPOSE_FALLBACK_ENV = "ADSCAN_BLOODHOUND_ALLOW_REMOTE_COMPOSE_FALLBACK"
_DOCKER_INSTALL_DOCS_URL = "https://www.adscanpro.com/docs/getting-started/installation"
_DEFAULT_BH_COMPOSE_PROJECT = "adscan-bhce"
_DEFAULT_BH_COMPOSE_DIRNAME = "bloodhound-ce"

_PORT_BIND_ERROR_RE = re.compile(
    r"bind port 127\.0\.0\.1:(\d+)/tcp:.*address already in use", re.IGNORECASE
)

_PINNED_BLOODHOUND_CE_SERVICES: dict[str, str] = {
    "bloodhound": f"specterops/bloodhound:{BLOODHOUND_CE_VERSION}",
    "app-db": "postgres:16",
    "graph-db": "neo4j:4.4.42",
}


def get_bloodhound_compose_project_name() -> str:
    """Return the Docker Compose project name used for ADscan-managed CE."""
    raw = os.getenv("ADSCAN_BLOODHOUND_COMPOSE_PROJECT", "").strip()
    return raw or _DEFAULT_BH_COMPOSE_PROJECT


def _compose_container_name(service_name: str) -> str:
    """Return deterministic container name for a service in the managed project."""
    return f"{get_bloodhound_compose_project_name()}-{service_name}-1"


def get_pinned_bloodhound_ce_containers() -> dict[str, str]:
    """Return expected container->image mapping for the managed CE project."""
    return {
        _compose_container_name(service): image
        for service, image in _PINNED_BLOODHOUND_CE_SERVICES.items()
    }


_PINNED_BLOODHOUND_CE_CONTAINERS: dict[str, str] = get_pinned_bloodhound_ce_containers()
_LEGACY_BLOODHOUND_CE_CONTAINER_NAMES: tuple[str, ...] = (
    "bloodhound-bloodhound-1",
    "bloodhound-app-db-1",
    "bloodhound-graph-db-1",
)
_LEGACY_BLOODHOUND_UI_PORT_RE = re.compile(r"(?:127\.0\.0\.1:)?(\d+)->8080/tcp")


def _get_bloodhound_config_dir() -> Path:
    """Return ADscan-managed BloodHound CE compose directory."""
    override = os.getenv("ADSCAN_BLOODHOUND_COMPOSE_DIR", "").strip()
    if override:
        return Path(expand_effective_user_path(override))

    return get_adscan_home() / "bloodhound" / _DEFAULT_BH_COMPOSE_DIRNAME


def _get_legacy_bloodhound_config_dir() -> Path:
    """Return previous shared BloodHound CE config directory (~/.config/bloodhound)."""
    xdg = os.getenv("XDG_CONFIG_HOME", "~/.config")
    return Path(expand_effective_user_path(xdg)) / "bloodhound"


def get_bloodhound_compose_path() -> Path:
    """Return the expected docker-compose.yml path for BloodHound CE."""
    return _get_bloodhound_config_dir() / "docker-compose.yml"


def _docker_compose_v2_available() -> bool:
    """Return True if Docker Compose v2 plugin (`docker compose`) is available.

    Note:
        Some environments (notably certain `docker.io` packages) may return the
        top-level Docker help (exit code 0) for unknown subcommands. We require
        the output to explicitly mention Docker Compose to avoid false positives.
    """
    if not docker_available():
        return False

    # Use `docker compose version` only. Some Docker builds treat `--version`
    # as a global docker flag (or error), which can lead to false positives.
    try:
        proc = run_docker(
            ["docker", "compose", "version"],
            check=False,
            capture_output=True,
            timeout=10,
        )
    except Exception:
        return False
    text = f"{proc.stdout or ''}\n{proc.stderr or ''}"
    if proc.returncode == 0 and "compose" in text.lower():
        # Typical output: "Docker Compose version v2.x.x"
        return True
    return False


def _docker_compose_v1_available() -> bool:
    """Return True if Docker Compose v1 (`docker-compose`) is available."""
    if not docker_available():
        return False
    if not shutil.which("docker-compose"):
        return False
    try:
        proc = run_docker(
            ["docker-compose", "version"], check=False, capture_output=True, timeout=10
        )
    except Exception:
        return False
    text = f"{proc.stdout or ''}\n{proc.stderr or ''}"
    return proc.returncode == 0 and "compose" in text.lower()


def _get_compose_invocation() -> list[str] | None:
    """Return the docker compose command prefix to use, or None if unavailable."""
    if _docker_compose_v2_available():
        return ["docker", "compose"]
    if _docker_compose_v1_available():
        return ["docker-compose"]
    return None


def docker_compose_available() -> bool:
    """Return True if Docker Compose is available (v2 plugin or v1 binary)."""
    return _get_compose_invocation() is not None


def _download_text(url: str, *, timeout: int = 60) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "adscan"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _load_vendored_compose_template() -> str | None:
    """Load the vendored BloodHound CE compose template from package data."""
    try:
        package_root = resources.files("adscan_launcher")
        template_path = (
            package_root.joinpath("assets")
            .joinpath("bloodhound")
            .joinpath("docker-compose.yml")
        )
        if not template_path.is_file():
            return None
        return template_path.read_text(encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            "[bloodhound-ce] failed to read vendored compose template "
            f"{_VENDORED_BLOODHOUND_COMPOSE_RESOURCE}: {exc}"
        )
        return None


def _remote_compose_fallback_enabled() -> bool:
    """Return True when runtime remote compose fallback is allowed."""
    raw = str(os.getenv(_ALLOW_REMOTE_COMPOSE_FALLBACK_ENV, "1")).strip().lower()
    return raw not in ("0", "false", "no", "off")


def _apply_compose_port_migrations(content: str) -> tuple[str, bool, bool]:
    """Apply ADscan port migrations to the upstream compose text.

    Returns:
        Tuple ``(updated_text, web_port_changed, graph_ports_changed)``.
    """
    updated = str(content or "")
    original = updated

    # Web UI host port migration.
    updated = updated.replace(
        "127.0.0.1:8080:8080",
        f"127.0.0.1:{BLOODHOUND_CE_DEFAULT_WEB_PORT}:8080",
    )
    updated = updated.replace("8080:8080", f"{BLOODHOUND_CE_DEFAULT_WEB_PORT}:8080")
    updated = updated.replace(
        "${BLOODHOUND_PORT:-8080}",
        f"${{BLOODHOUND_PORT:-{BLOODHOUND_CE_DEFAULT_WEB_PORT}}}",
    )

    # Graph DB host port migration to avoid collisions with existing Neo4j.
    updated = updated.replace(
        "127.0.0.1:7474:7474",
        f"127.0.0.1:{BLOODHOUND_CE_GRAPH_HTTP_PORT}:7474",
    )
    updated = updated.replace("7474:7474", f"{BLOODHOUND_CE_GRAPH_HTTP_PORT}:7474")
    updated = updated.replace(
        "127.0.0.1:7687:7687",
        f"127.0.0.1:{BLOODHOUND_CE_GRAPH_BOLT_PORT}:7687",
    )
    updated = updated.replace("7687:7687", f"{BLOODHOUND_CE_GRAPH_BOLT_PORT}:7687")
    updated = updated.replace(
        "${NEO4J_HTTP_PORT:-7474}",
        f"${{NEO4J_HTTP_PORT:-{BLOODHOUND_CE_GRAPH_HTTP_PORT}}}",
    )
    updated = updated.replace(
        "${NEO4J_BOLT_PORT:-7687}",
        f"${{NEO4J_BOLT_PORT:-{BLOODHOUND_CE_GRAPH_BOLT_PORT}}}",
    )
    updated = updated.replace(
        "${NEO4J_WEB_PORT:-7474}",
        f"${{NEO4J_WEB_PORT:-{BLOODHOUND_CE_GRAPH_HTTP_PORT}}}",
    )
    updated = updated.replace(
        "${NEO4J_DB_PORT:-7687}",
        f"${{NEO4J_DB_PORT:-{BLOODHOUND_CE_GRAPH_BOLT_PORT}}}",
    )

    web_changed = (
        f"{BLOODHOUND_CE_DEFAULT_WEB_PORT}:8080" in updated
        and f"{BLOODHOUND_CE_DEFAULT_WEB_PORT}:8080" not in original
    )
    graph_changed = (
        f"{BLOODHOUND_CE_GRAPH_HTTP_PORT}:7474" in updated
        or f"{BLOODHOUND_CE_GRAPH_BOLT_PORT}:7687" in updated
    ) and (
        f"{BLOODHOUND_CE_GRAPH_HTTP_PORT}:7474" not in original
        or f"{BLOODHOUND_CE_GRAPH_BOLT_PORT}:7687" not in original
    )

    return updated, web_changed, graph_changed


def _maybe_migrate_legacy_compose_path(target_path: Path) -> bool:
    """Copy legacy ~/.config/bloodhound compose file into ADscan-managed location."""
    legacy_path = _get_legacy_bloodhound_config_dir() / "docker-compose.yml"
    if target_path.exists() or not legacy_path.exists():
        return False

    try:
        legacy_content = legacy_path.read_text(encoding="utf-8", errors="replace")
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(legacy_content, encoding="utf-8")
        print_info(
            "Migrated existing BloodHound CE compose file to ADscan-managed path "
            "for isolated operation."
        )
        print_info_debug(
            "[bloodhound-ce] compose migration: "
            f"legacy={mark_sensitive(str(legacy_path), 'path')} "
            f"new={mark_sensitive(str(target_path), 'path')}"
        )
        return True
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(f"[bloodhound-ce] compose migration failed: {exc}")
        return False


def ensure_bloodhound_compose_file(
    *, version: str = BLOODHOUND_CE_VERSION
) -> Path | None:
    """Ensure the BloodHound CE docker-compose.yml exists locally.

    Args:
        version: BloodHound CE version to pin in the compose file.

    Returns:
        Path to the compose file on success, otherwise None.
    """
    compose_path = get_bloodhound_compose_path()
    compose_dir = compose_path.parent
    _maybe_migrate_legacy_compose_path(compose_path)

    if compose_path.exists():
        # Best-effort: ensure the file is pinned and uses our preferred host port
        # if it still contains upstream defaults from older installs.
        try:
            existing = compose_path.read_text(encoding="utf-8", errors="replace")
            updated = existing

            # Pin the image tag if the upstream placeholder is still present.
            if "${BLOODHOUND_TAG:-latest}" in updated and version not in updated:
                updated = updated.replace("${BLOODHOUND_TAG:-latest}", version)
                print_info_debug(
                    f"[bloodhound-ce] updated docker-compose.yml to pin version {version}"
                )

            updated, web_changed, graph_changed = _apply_compose_port_migrations(
                updated
            )
            if web_changed:
                print_info_debug(
                    "[bloodhound-ce] migrated docker-compose.yml host web port "
                    f"to {BLOODHOUND_CE_DEFAULT_WEB_PORT}"
                )
            if graph_changed:
                print_info_debug(
                    "[bloodhound-ce] migrated docker-compose.yml graph-db ports to "
                    f"{BLOODHOUND_CE_GRAPH_HTTP_PORT}/{BLOODHOUND_CE_GRAPH_BOLT_PORT}"
                )

            if updated != existing:
                compose_path.write_text(updated, encoding="utf-8")
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_info_debug(f"[bloodhound-ce] compose read/update failed: {exc}")
        return compose_path

    print_info("Configuring BloodHound CE docker-compose.yml...")
    try:
        compose_dir.mkdir(parents=True, exist_ok=True)
        content = _load_vendored_compose_template()
        compose_source = "vendored"
        if content is None:
            if _remote_compose_fallback_enabled():
                print_warning(
                    "Vendored BloodHound CE compose template is unavailable; "
                    "falling back to upstream download."
                )
                content = _download_text(BLOODHOUND_COMPOSE_URL, timeout=60)
                compose_source = "remote_fallback"
            else:
                print_error(
                    "Vendored BloodHound CE compose template is unavailable and "
                    "remote fallback is disabled."
                )
                print_instruction(
                    "Reinstall ADscan or set "
                    f"{_ALLOW_REMOTE_COMPOSE_FALLBACK_ENV}=1 and retry."
                )
                return None
        # Replace ${BLOODHOUND_TAG:-latest} with a pinned version for consistency.
        pinned = content.replace("${BLOODHOUND_TAG:-latest}", version)
        pinned, _, _ = _apply_compose_port_migrations(pinned)
        compose_path.write_text(pinned, encoding="utf-8")
        print_info_debug(f"[bloodhound-ce] compose source: {compose_source}")
        print_success(
            f"BloodHound CE docker-compose.yml configured for version {version}."
        )
        return compose_path
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Failed to configure BloodHound CE docker-compose.yml.")
        print_error(f"[bloodhound-ce] compose setup exception: {exc}")
        print_instruction(
            f"Check DNS/connectivity, ensure Docker is installed, then retry: adscan install. Guide: {_DOCKER_INSTALL_DOCS_URL}"
        )
        return None


def _compose_base_args(compose_path: Path) -> list[str]:
    invocation = _get_compose_invocation()
    project_name = get_bloodhound_compose_project_name()
    if invocation is None:
        # Callers guard with docker_compose_available(); keep a safe fallback.
        return [
            "docker",
            "compose",
            "-p",
            project_name,
            "-f",
            str(compose_path),
        ]
    return invocation + ["-p", project_name, "-f", str(compose_path)]


def compose_pull(compose_path: Path, *, stream_output: bool = False) -> bool:
    """Pull BloodHound CE compose images."""
    if not docker_compose_available():
        print_error("Docker Compose is not available.")
        print_instruction(
            f"Install Docker + Docker Compose, then retry: adscan install. Guide: {_DOCKER_INSTALL_DOCS_URL}"
        )
        return False

    cmd = _compose_base_args(compose_path) + ["pull"]
    print_info_debug(f"[bloodhound-ce] pull: {shell_quote_cmd(cmd)}")
    try:
        if stream_output:
            rc, stdout, stderr = run_docker_stream(cmd, timeout=1200)
            if rc == 0:
                print_success("BloodHound CE images pulled successfully.")
                return True
            print_error("Failed to pull BloodHound CE images.")
            if stderr:
                print_info_debug(f"[bloodhound-ce] pull stderr:\n{stderr}")
            if stdout:
                print_info_debug(f"[bloodhound-ce] pull stdout:\n{stdout}")
            return False

        proc = run_docker(cmd, check=False, capture_output=True, timeout=1200)
        if proc.returncode == 0:
            print_success("BloodHound CE images pulled successfully.")
            return True
        print_error("Failed to pull BloodHound CE images.")
        if proc.stderr:
            print_info_debug(f"[bloodhound-ce] pull stderr:\n{proc.stderr}")
        if proc.stdout:
            print_info_debug(f"[bloodhound-ce] pull stdout:\n{proc.stdout}")
        return False
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Failed to pull BloodHound CE images due to an exception.")
        print_info_debug(f"[bloodhound-ce] pull exception: {exc}")
        return False


def compose_up(compose_path: Path) -> bool:
    """Start BloodHound CE stack in detached mode."""
    if not docker_compose_available():
        print_error("Docker Compose is not available.")
        print_instruction(
            f"Install Docker + Docker Compose, then retry: adscan start. Guide: {_DOCKER_INSTALL_DOCS_URL}"
        )
        return False

    if not _preflight_bloodhound_ce_host_conflicts(compose_path):
        return False

    cmd = _compose_base_args(compose_path) + ["up", "-d"]
    print_info("Starting BloodHound CE containers...")
    print_info_debug(f"[bloodhound-ce] up: {shell_quote_cmd(cmd)}")
    try:
        proc = run_docker(cmd, check=False, capture_output=True, timeout=600)
        if proc.returncode == 0:
            print_success("BloodHound CE containers started.")
            return True

        # Common case: BloodHound CE web port already in use.
        combined = (proc.stderr or "") + "\n" + (proc.stdout or "")
        if "port is already allocated" in combined.lower() or (
            (match := _PORT_BIND_ERROR_RE.search(combined))
            and match.group(1) == str(BLOODHOUND_CE_DEFAULT_WEB_PORT)
        ):
            print_warning(
                f"Port {BLOODHOUND_CE_DEFAULT_WEB_PORT} is already in use on the host. "
                "BloodHound CE cannot bind to it."
            )
            if _maybe_free_host_port_for_bloodhound_ce(BLOODHOUND_CE_DEFAULT_WEB_PORT):
                proc_retry = run_docker(
                    cmd, check=False, capture_output=True, timeout=600
                )
                if proc_retry.returncode == 0:
                    print_success("BloodHound CE containers started.")
                    return True
                combined_retry = (
                    (proc_retry.stderr or "") + "\n" + (proc_retry.stdout or "")
                )
                print_error(
                    "Failed to start BloodHound CE containers after freeing "
                    f"port {BLOODHOUND_CE_DEFAULT_WEB_PORT}."
                )
                print_info_debug(f"[bloodhound-ce] up retry output:\n{combined_retry}")
                return False
            print_info_debug(f"[bloodhound-ce] up output:\n{combined}")
            return False

        # Common case: graph-db host port already in use.
        match = _PORT_BIND_ERROR_RE.search(combined)
        if match and match.group(1) == str(BLOODHOUND_CE_GRAPH_HTTP_PORT):
            print_warning(
                f"Graph DB host port {BLOODHOUND_CE_GRAPH_HTTP_PORT} is already in use on the host. "
                "BloodHound CE cannot bind to it."
            )
            if _maybe_free_host_port_for_bloodhound_ce(BLOODHOUND_CE_GRAPH_HTTP_PORT):
                # Retry once after freeing the conflicting port.
                proc_retry = run_docker(
                    cmd, check=False, capture_output=True, timeout=600
                )
                if proc_retry.returncode == 0:
                    print_success("BloodHound CE containers started.")
                    return True
                combined_retry = (
                    (proc_retry.stderr or "") + "\n" + (proc_retry.stdout or "")
                )
                print_error(
                    "Failed to start BloodHound CE containers after freeing "
                    f"port {BLOODHOUND_CE_GRAPH_HTTP_PORT}."
                )
                print_info_debug(f"[bloodhound-ce] up retry output:\n{combined_retry}")
                return False
            print_info_debug(f"[bloodhound-ce] up output:\n{combined}")
            return False

        print_error("Failed to start BloodHound CE containers.")
        if proc.stderr:
            print_info_debug(f"[bloodhound-ce] up stderr:\n{proc.stderr}")
        if proc.stdout:
            print_info_debug(f"[bloodhound-ce] up stdout:\n{proc.stdout}")
        return False
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Failed to start BloodHound CE containers due to an exception.")
        print_info_debug(f"[bloodhound-ce] up exception: {exc}")
        return False


def _preflight_bloodhound_ce_host_conflicts(compose_path: Path) -> bool:
    """Detect host conflicts that commonly prevent BloodHound CE from starting.

    If the pinned BloodHound CE stack is already running, treat it as healthy and
    do not attempt to free ports that are legitimately owned by the stack.
    """
    # If the pinned stack is already running, don't try to "free" its ports.
    pinned_ok, reason = _pinned_bloodhound_ce_running_status()
    if pinned_ok:
        print_info_verbose(
            "BloodHound CE pinned stack already running; skipping port-conflict preflight."
        )
        return True

    # If containers exist but mismatch versions, offer to replace (CI auto-yes).
    if reason == "mismatch":
        if not _maybe_replace_bloodhound_ce_stack(compose_path):
            return False
        # Re-check after replacement attempt. If it still mismatches, stop early to
        # avoid repeatedly killing host services for a stack that we can't control.
        pinned_ok_after, reason_after = _pinned_bloodhound_ce_running_status()
        if reason_after == "mismatch" and not pinned_ok_after:
            print_error(
                "BloodHound CE stack is still not matching pinned versions after replacement attempt."
            )
            return False

    # Web UI is bound to localhost in the compose file; a local service on that port will conflict.
    if _is_tcp_port_listening(BLOODHOUND_CE_DEFAULT_WEB_PORT):
        print_warning(
            f"Port {BLOODHOUND_CE_DEFAULT_WEB_PORT} is already in use on the host. "
            "BloodHound CE's web UI cannot bind to it."
        )
        if not _maybe_free_host_port_for_bloodhound_ce(BLOODHOUND_CE_DEFAULT_WEB_PORT):
            return False

    if _is_tcp_port_listening(BLOODHOUND_CE_GRAPH_HTTP_PORT):
        # If the port is already owned by the pinned BloodHound CE stack itself,
        # do not treat it as a host-level conflict.
        if _pinned_ce_graph_db_owns_port(BLOODHOUND_CE_GRAPH_HTTP_PORT):
            print_info_verbose(
                f"Port {BLOODHOUND_CE_GRAPH_HTTP_PORT} is already bound by the BloodHound CE graph-db container; "
                "skipping host Neo4j preflight."
            )
            return True

        print_warning(
            f"Port {BLOODHOUND_CE_GRAPH_HTTP_PORT} is already in use on the host. "
            "BloodHound CE's graph-db container cannot bind to it."
        )
        return _maybe_free_host_port_for_bloodhound_ce(BLOODHOUND_CE_GRAPH_HTTP_PORT)

    return True


def _pinned_ce_graph_db_owns_port(port: int) -> bool:
    """Return True if the pinned BloodHound CE graph-db container owns the given port."""
    expected_graph_container = _compose_container_name("graph-db")
    try:
        proc = run_docker(
            [
                "docker",
                "ps",
                "--format",
                "{{.Names}}\t{{.Ports}}",
            ],
            check=False,
            capture_output=True,
            timeout=10,
        )
        if proc.returncode != 0:
            return False

        for line in (proc.stdout or "").splitlines():
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            name, ports = parts[0], parts[1]
            if name == expected_graph_container and f":{port}->" in ports:
                return True
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_info_debug(f"[bloodhound-ce] pinned-ce-port-check exception: {exc}")
    return False


def _pinned_bloodhound_ce_running_status() -> tuple[bool, str]:
    """Check whether pinned BloodHound CE containers are running with expected images.

    Returns:
        (ok, reason) where reason is:
          - "ok": all pinned containers are Up with expected images
          - "absent": pinned container names not all present
          - "mismatch": containers present but status/image mismatch
          - "error": docker query failed
    """
    try:
        proc = run_docker(
            ["docker", "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}"],
            check=False,
            capture_output=True,
            timeout=10,
        )
        if proc.returncode != 0:
            return False, "error"
        seen: dict[str, tuple[str, str]] = {}
        for line in (proc.stdout or "").splitlines():
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            name, image, status = parts[0], parts[1], parts[2]
            if name in _PINNED_BLOODHOUND_CE_CONTAINERS:
                seen[name] = (image, status)

        if set(seen) != set(_PINNED_BLOODHOUND_CE_CONTAINERS):
            return False, "absent"

        for name, expected_image in _PINNED_BLOODHOUND_CE_CONTAINERS.items():
            image, status = seen.get(name, ("", ""))
            if image != expected_image:
                print_info_debug(
                    f"[bloodhound-ce] pinned container image mismatch: {name} expected={expected_image} got={image}"
                )
                return False, "mismatch"
            if "up" not in status.lower():
                print_info_debug(
                    f"[bloodhound-ce] pinned container not running: {name} status={status!r}"
                )
                return False, "mismatch"

        return True, "ok"
    except Exception as exc:
        telemetry.capture_exception(exc)
        return False, "error"


def check_bloodhound_ce_running(
    *,
    is_full_adscan_container_runtime_func: Callable[[], bool] | None = None,
    host_helper_client_request_func: Callable[..., object] | None = None,
    run_docker_command_func: Callable[..., subprocess.CompletedProcess] | None = None,
) -> bool:
    """Check if BloodHound CE containers are running using Docker.

    Args:
        is_full_adscan_container_runtime_func: Optional function to check if running in ADscan container.
        host_helper_client_request_func: Optional function to make host helper requests.
        run_docker_command_func: Optional function to run docker commands (defaults to run_docker)

    Returns:
        bool: True if all 3 required containers are running with expected images, False otherwise
    """
    try:
        in_container = (
            bool(is_full_adscan_container_runtime_func())
            if is_full_adscan_container_runtime_func
            else (os.getenv("ADSCAN_CONTAINER_RUNTIME") == "1")
        )

        if in_container:
            sock_path = os.getenv("ADSCAN_HOST_HELPER_SOCK", "").strip()
            if not sock_path:
                return False

            if not host_helper_client_request_func:
                try:
                    # Optional dependency: available in launcher/runtime package.
                    from adscan_launcher.host_privileged_helper import (  # noqa: PLC0415
                        host_helper_client_request,
                    )

                    host_helper_client_request_func = host_helper_client_request
                except ImportError:
                    return False

            try:
                resp = host_helper_client_request_func(
                    sock_path,
                    op="docker_ps_names_images_status",
                    payload={},
                )
                if not getattr(resp, "ok", False) or not getattr(resp, "stdout", ""):
                    return False
                docker_ps_output = str(getattr(resp, "stdout", "") or "")
            except Exception as exc:
                telemetry.capture_exception(exc)
                return False
        else:
            if not shutil.which("docker"):
                return False

            docker_cmd_func = run_docker_command_func or run_docker

            proc = docker_cmd_func(
                ["docker", "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}"],
                check=False,
                capture_output=True,
                text=True,
            )
            if proc.returncode != 0:
                return False
            docker_ps_output = proc.stdout or ""

        # Parse output and check for required containers
        expected_images_by_container = _PINNED_BLOODHOUND_CE_CONTAINERS

        running_containers: list[str] = []
        running_images_by_container: dict[str, str] = {}
        for line in docker_ps_output.strip().split("\n"):
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) >= 3:
                container_name = parts[0]
                image = (parts[1] or "").split("@", 1)[0]  # Remove digest if present
                status = parts[2]
                # Check if container is in required list and status contains "Up"
                if container_name in expected_images_by_container and "Up" in status:
                    running_containers.append(container_name)
                    running_images_by_container[container_name] = image

        # All containers must be running
        if len(running_containers) != len(expected_images_by_container):
            return False

        # And the running images must match our pinned stack
        for container_name, expected_image in expected_images_by_container.items():
            if running_images_by_container.get(container_name) != expected_image:
                return False

        return True
    except Exception as exc:
        telemetry.capture_exception(exc)
        return False


def detect_legacy_bloodhound_ce_running_stack() -> dict[str, object]:
    """Detect an already-running non-managed BloodHound CE stack on the host.

    Returns:
        Dict with keys:
            - detected (bool): Whether non-managed CE containers are running.
            - container_names (list[str]): Running non-managed container names.
            - ui_url (str|None): Best-effort CE UI URL from port mapping.
            - compose_project (str|None): Detected compose project prefix when obvious.
    """
    result: dict[str, object] = {
        "detected": False,
        "container_names": [],
        "ui_url": None,
        "compose_project": None,
    }
    try:
        if not docker_available():
            return result
        proc = run_docker(
            ["docker", "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Ports}}"],
            check=False,
            capture_output=True,
            timeout=10,
        )
        if proc.returncode != 0:
            return result

        seen_names: set[str] = set()
        ui_url: str | None = None
        compose_project: str | None = None
        managed_names = set(_PINNED_BLOODHOUND_CE_CONTAINERS.keys())
        expected_legacy_names = set(_LEGACY_BLOODHOUND_CE_CONTAINER_NAMES)
        running: dict[str, tuple[str, str]] = {}

        for line in (proc.stdout or "").splitlines():
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            name, image, ports = parts[0], parts[1], parts[2]
            normalized_image = (image or "").split("@", 1)[0]
            running[name] = (normalized_image, ports)

        # Legacy project names (backward compatibility).
        for name in expected_legacy_names:
            if name not in running:
                continue
            seen_names.add(name)
            if name == "bloodhound-bloodhound-1":
                if compose_project is None:
                    compose_project = "bloodhound"
                ports = running[name][1]
                match = _LEGACY_BLOODHOUND_UI_PORT_RE.search(ports or "")
                if match:
                    ui_url = f"http://127.0.0.1:{match.group(1)}"
                elif "->8080/tcp" in (ports or ""):
                    ui_url = f"http://127.0.0.1:{BLOODHOUND_CE_DEFAULT_WEB_PORT}"

        # Any non-managed BloodHound web container by image.
        for name, (image, ports) in running.items():
            if name in managed_names:
                continue
            if not image.startswith("specterops/bloodhound:"):
                continue
            seen_names.add(name)
            match = _LEGACY_BLOODHOUND_UI_PORT_RE.search(ports or "")
            if match and not ui_url:
                ui_url = f"http://127.0.0.1:{match.group(1)}"
            elif "->8080/tcp" in (ports or "") and not ui_url:
                ui_url = f"http://127.0.0.1:{BLOODHOUND_CE_DEFAULT_WEB_PORT}"

            if name.endswith("-bloodhound-1"):
                project_prefix = name[: -len("-bloodhound-1")]
                if project_prefix:
                    candidate_app_db = f"{project_prefix}-app-db-1"
                    candidate_graph_db = f"{project_prefix}-graph-db-1"
                    if candidate_app_db in running:
                        seen_names.add(candidate_app_db)
                    if candidate_graph_db in running:
                        seen_names.add(candidate_graph_db)
                    if compose_project is None:
                        compose_project = project_prefix

        if seen_names:
            result["detected"] = True
            result["container_names"] = sorted(seen_names)
            result["ui_url"] = ui_url
            result["compose_project"] = compose_project
        return result
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(f"[bloodhound-ce] legacy stack detection failed: {exc}")
        return result


def stop_legacy_bloodhound_ce_stack() -> bool:
    """Stop running non-managed BloodHound CE containers without deleting data."""
    detection = detect_legacy_bloodhound_ce_running_stack()
    if not bool(detection.get("detected", False)):
        return True
    container_names = [
        str(name).strip() for name in (detection.get("container_names") or []) if name
    ]
    if not container_names:
        return True

    print_info(
        "Stopping non-managed BloodHound CE containers to migrate to managed mode..."
    )
    for name in container_names:
        try:
            proc = run_docker(
                ["docker", "stop", name],
                check=False,
                capture_output=True,
                timeout=45,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                "[bloodhound-ce] legacy stop exception "
                f"(container={mark_sensitive(name, 'detail')}): {exc}"
            )
            return False
        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            stdout = (proc.stdout or "").strip()
            combined = (stderr + "\n" + stdout).lower()
            if "no such container" in combined:
                continue
            print_info_debug(
                "[bloodhound-ce] legacy stop failed "
                f"(container={mark_sensitive(name, 'detail')}, rc={proc.returncode}): "
                f"stderr={mark_sensitive(stderr, 'detail')} "
                f"stdout={mark_sensitive(stdout, 'detail')}"
            )
            return False

    print_success(
        "Non-managed BloodHound CE containers stopped. Data volumes were not deleted."
    )
    return True


def _maybe_replace_bloodhound_ce_stack(compose_path: Path) -> bool:
    """If a different BloodHound CE stack is running, offer to replace it."""
    is_ci = bool(os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"))
    if is_ci:
        print_info(
            "CI environment detected. Replacing existing BloodHound CE stack automatically to match pinned versions..."
        )
        return _replace_bloodhound_ce_stack(
            compose_path, require_noninteractive_sudo=True
        )

    expected = ", ".join(_PINNED_BLOODHOUND_CE_CONTAINERS.values())
    confirmed = confirm_operation(
        "Replace BloodHound CE stack",
        "A BloodHound CE stack is already running but does not match the pinned versions required by ADscan.",
        context={
            "Expected images": expected,
            "Impact": "Stops/restarts BloodHound CE containers",
        },
        default=True,
        icon="🩸",
        show_panel=True,
    )
    if not confirmed:
        print_warning(
            "Cannot continue while an incompatible BloodHound CE stack is running. Stop it manually or accept replacement."
        )
        return False
    return _replace_bloodhound_ce_stack(compose_path, require_noninteractive_sudo=False)


def _replace_bloodhound_ce_stack(
    compose_path: Path, *, require_noninteractive_sudo: bool
) -> bool:
    """Stop any existing BloodHound CE containers and bring up the pinned stack."""
    # Try compose down first (best-effort); this works when the stack was started with our compose file path.
    cmd_down = _compose_base_args(compose_path) + ["down", "--remove-orphans"]
    print_info_debug(f"[bloodhound-ce] down: {shell_quote_cmd(cmd_down)}")
    try:
        proc_down = run_docker(cmd_down, check=False, capture_output=True, timeout=120)
        if proc_down.returncode != 0:
            print_info_debug(
                f"[bloodhound-ce] down failed: rc={proc_down.returncode}, stderr={proc_down.stderr!r}, stdout={proc_down.stdout!r}"
            )
    except Exception as exc:
        telemetry.capture_exception(exc)

    # If containers still exist, stop them explicitly by name.
    try:
        for name in _PINNED_BLOODHOUND_CE_CONTAINERS:
            proc = run_docker(
                ["docker", "stop", name],
                check=False,
                capture_output=True,
                timeout=30,
            )
            if proc.returncode == 0:
                continue
    except Exception as exc:
        telemetry.capture_exception(exc)

    # Verify ports are free (or at least no longer bound by old containers).
    time.sleep(1)
    if _is_tcp_port_listening(BLOODHOUND_CE_GRAPH_HTTP_PORT) or _is_tcp_port_listening(
        BLOODHOUND_CE_DEFAULT_WEB_PORT
    ):
        # Ports might be used by other processes; let the normal preflight handle it.
        return True

    return True


def _is_tcp_port_listening(port: int) -> bool:
    """Return True if any process is listening on the given TCP port (localhost or any)."""
    # Prefer ss; fall back to lsof if available.
    try:
        proc = subprocess.run(
            ["ss", "-ltnp", f"sport = :{port}"],
            capture_output=True,
            text=True,
            check=False,
            timeout=2,
        )
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
        # If a LISTEN line exists, the port is in use.
        if "LISTEN" in out.upper():
            return True
        # Some builds omit LISTEN label in filtered output; consider any match with :port.
        return f":{port}" in out
    except Exception:
        pass

    if shutil.which("lsof"):
        try:
            proc = subprocess.run(
                ["lsof", "-iTCP:%d" % port, "-sTCP:LISTEN", "-Pn"],
                capture_output=True,
                text=True,
                check=False,
                timeout=2,
            )
            return bool((proc.stdout or "").strip())
        except Exception:
            return False
    return False


def _maybe_free_host_port_for_bloodhound_ce(port: int) -> bool:
    """Offer (or auto-accept in CI) to free a host port for BloodHound CE."""
    is_ci = bool(os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"))
    if is_ci:
        print_info(
            f"CI environment detected. Attempting to free port {port} automatically to unblock BloodHound CE..."
        )
        return _free_host_port_for_bloodhound_ce(port, require_noninteractive_sudo=True)

    confirmed = confirm_operation(
        f"Free port {port} for BloodHound CE",
        f"Port {port} is already in use on the host. BloodHound CE needs this port on localhost.",
        context={
            "Port": str(port),
            "Impact": "Stops containers / kills processes listening on the port",
        },
        default=True,
        icon="🩸",
        show_panel=True,
    )
    if not confirmed:
        print_warning(
            f"BloodHound CE cannot start while port {port} is in use. Stop the service using the port and retry."
        )
        print_instruction(f"Try: sudo lsof -iTCP:{port} -sTCP:LISTEN -Pn")
        return False

    return _free_host_port_for_bloodhound_ce(port, require_noninteractive_sudo=False)


def _docker_containers_publishing_port(port: int) -> list[dict[str, str]]:
    """Return running docker containers that publish the given host port."""
    try:
        proc = run_docker(
            ["docker", "ps", "--format", "{{.ID}}\t{{.Names}}\t{{.Ports}}"],
            check=False,
            capture_output=True,
            timeout=10,
        )
        if proc.returncode != 0:
            return []
        matches: list[dict[str, str]] = []
        needle = f":{port}->"
        for line in (proc.stdout or "").splitlines():
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            container_id, name, ports = parts[0], parts[1], parts[2]
            if needle in ports or f"::{port}->" in ports:
                matches.append({"id": container_id, "name": name, "ports": ports})
        return matches
    except Exception:
        return []


def _run_with_sudo(
    argv: list[str], *, require_noninteractive: bool
) -> subprocess.CompletedProcess[str]:
    """Run a command with sudo if needed.

    Delegates to ``sudo_utils.run_with_sudo()`` for consistent sudo handling.
    """
    from adscan_launcher.sudo_utils import run_with_sudo

    return run_with_sudo(
        argv,
        require_noninteractive=require_noninteractive,
    )


def _listening_pids_for_tcp_port(
    port: int, *, require_noninteractive_sudo: bool
) -> list[str]:
    """Return PIDs listening on TCP port, best-effort (uses lsof/ss)."""
    if shutil.which("lsof"):
        try:
            proc = _run_with_sudo(
                ["lsof", "-t", f"-iTCP:{port}", "-sTCP:LISTEN", "-Pn"],
                require_noninteractive=require_noninteractive_sudo,
            )
            if proc.returncode == 0 and proc.stdout:
                return sorted(
                    {line.strip() for line in proc.stdout.splitlines() if line.strip()}
                )
        except Exception:
            pass
    try:
        proc = _run_with_sudo(
            ["ss", "-ltnp", f"sport = :{port}"],
            require_noninteractive=require_noninteractive_sudo,
        )
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
        return sorted({m.group(1) for m in re.finditer(r"pid=(\d+)", out)})
    except Exception:
        return []


def _kill_pids(pids: list[str], *, require_noninteractive_sudo: bool) -> bool:
    """Terminate PIDs with TERM then KILL if needed."""
    if not pids:
        return True
    for pid in pids:
        proc = _run_with_sudo(
            ["kill", "-TERM", pid], require_noninteractive=require_noninteractive_sudo
        )
        if proc.returncode not in (0, 1):
            return False
    time.sleep(1)
    for pid in pids:
        proc = _run_with_sudo(
            ["kill", "-KILL", pid], require_noninteractive=require_noninteractive_sudo
        )
        if proc.returncode not in (0, 1):
            return False
    return True


def _free_host_port_for_bloodhound_ce(
    port: int, *, require_noninteractive_sudo: bool
) -> bool:
    """Try to free a host TCP port by stopping docker containers and killing listeners."""
    containers = _docker_containers_publishing_port(port)
    for c in containers:
        try:
            print_info_debug(
                f"[bloodhound-ce] stopping container {c.get('name')} publishing port {port}"
            )
            run_docker(
                ["docker", "stop", c["id"]],
                check=False,
                capture_output=True,
                timeout=30,
            )
        except Exception as exc:
            telemetry.capture_exception(exc)

    if not _is_tcp_port_listening(port):
        print_success(f"Port {port} is now free.")
        return True

    pids = _listening_pids_for_tcp_port(
        port, require_noninteractive_sudo=require_noninteractive_sudo
    )
    if not pids:
        print_error(
            f"Port {port} is still in use, but no listener PID could be determined."
        )
        print_instruction(f"Try: sudo lsof -iTCP:{port} -sTCP:LISTEN -Pn")
        return False

    print_info_debug(f"[bloodhound-ce] pids listening on {port}: {pids}")
    if not _kill_pids(pids, require_noninteractive_sudo=require_noninteractive_sudo):
        print_error(f"Failed to stop processes listening on port {port}.")
        print_instruction(f"Try: sudo lsof -iTCP:{port} -sTCP:LISTEN -Pn")
        return False

    time.sleep(1)
    if _is_tcp_port_listening(port):
        print_error(f"Port {port} is still in use after attempting to free it.")
        print_instruction(f"Stop the service manually and retry. (Port: {port})")
        return False

    print_success(f"Port {port} is now free.")
    return True


def _maybe_stop_host_neo4j_service_for_bloodhound() -> bool:
    """Offer to stop a local Neo4j service so BloodHound CE can start."""
    is_ci = bool(os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"))
    if is_ci:
        print_info(
            "CI environment detected. Attempting to stop the host Neo4j service automatically to unblock BloodHound CE..."
        )
        ok = _stop_host_neo4j_service(require_noninteractive_sudo=True)
        if not ok:
            print_error("Failed to stop local Neo4j service automatically in CI.")
            return False
        return not _is_tcp_port_listening(7474)

    confirmed = confirm_operation(
        "Stop local Neo4j service",
        "BloodHound CE needs ports 7474/7687 on localhost. A local Neo4j instance is already using 7474.",
        context={"Port": "7474", "Impact": "Stops host Neo4j service"},
        default=True,
        icon="🩸",
        show_panel=True,
    )
    if not confirmed:
        print_warning(
            "BloodHound CE cannot start while port 7474 is in use. Stop your local Neo4j service and retry."
        )
        print_instruction("Try: sudo systemctl stop neo4j (or: sudo neo4j stop)")
        return False

    ok = _stop_host_neo4j_service()
    if not ok:
        print_error("Failed to stop local Neo4j service automatically.")
        print_instruction("Stop it manually, then retry: sudo systemctl stop neo4j")
        return False

    # Verify the port is free before continuing.
    if _is_tcp_port_listening(7474):
        print_error("Port 7474 is still in use after attempting to stop Neo4j.")
        print_instruction("Stop the service manually, then retry the install/start.")
        return False

    print_success("Local Neo4j service stopped. Retrying BloodHound CE startup...")
    return True


def _stop_host_neo4j_service(*, require_noninteractive_sudo: bool = False) -> bool:
    """Best-effort attempt to stop a host Neo4j service.

    Args:
        require_noninteractive_sudo: If True and the current user isn't root,
            uses `sudo -n` to avoid hanging in CI waiting for a password prompt.
    """
    from adscan_launcher.sudo_utils import sudo_prefix_args

    if os.geteuid() != 0:
        sudo_prefix = sudo_prefix_args(
            non_interactive=require_noninteractive_sudo,
            preserve_env_keys=(),
        )
    else:
        sudo_prefix = []

    candidates: list[list[str]] = []
    if shutil.which("systemctl"):
        candidates.append(sudo_prefix + ["systemctl", "stop", "neo4j"])
    if shutil.which("service"):
        candidates.append(sudo_prefix + ["service", "neo4j", "stop"])
    if shutil.which("neo4j"):
        candidates.append(sudo_prefix + ["neo4j", "stop"])

    for cmd in candidates:
        try:
            print_info_debug(f"[bloodhound-ce] stopping neo4j: {shell_quote_cmd(cmd)}")
            proc = subprocess.run(  # noqa: S603
                cmd, capture_output=True, text=True, check=False, timeout=15
            )
            if proc.returncode == 0:
                return True
            combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
            if "not running" in combined.lower() or "inactive" in combined.lower():
                return True
            if require_noninteractive_sudo and "password" in combined.lower():
                return False
        except Exception as exc:
            telemetry.capture_exception(exc)
            continue
    return False


def compose_list_images(compose_path: Path) -> list[str] | None:
    """Return the list of images used by the compose file."""
    if not docker_compose_available():
        return None
    cmd = _compose_base_args(compose_path) + ["config", "--images"]
    print_info_debug(f"[bloodhound-ce] images: {shell_quote_cmd(cmd)}")
    try:
        proc = run_docker(cmd, check=False, capture_output=True, timeout=30)
        if proc.returncode != 0:
            print_info_debug(
                f"[bloodhound-ce] images failed: rc={proc.returncode}, stderr={proc.stderr!r}, stdout={proc.stdout!r}"
            )
            return None
        images = [
            line.strip() for line in (proc.stdout or "").splitlines() if line.strip()
        ]
        return images or []
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_info_debug(f"[bloodhound-ce] images exception: {exc}")
        return None


def compose_images_present(images: list[str]) -> tuple[bool, list[str]]:
    """Check whether docker images exist locally.

    Returns:
        (all_present, missing_images)
    """
    missing: list[str] = []
    for image in images:
        proc = run_docker(
            ["docker", "image", "inspect", image],
            check=False,
            capture_output=True,
            timeout=10,
        )
        if proc.returncode != 0:
            missing.append(image)
    return (len(missing) == 0, missing)


def start_bloodhound_ce(
    *,
    is_full_adscan_container_runtime_func: Callable[[], bool] | None = None,
    host_helper_client_request_func: Callable[..., object] | None = None,
    check_bloodhound_ce_running_func: Callable[..., bool] | None = None,
    docker_available_func: Callable[[], bool] | None = None,
    ensure_docker_daemon_running_func: Callable[[], bool] | None = None,
    ensure_bloodhound_compose_file_func: Callable[..., Path | None] | None = None,
    compose_up_func: Callable[[Path], bool] | None = None,
    print_info_func: Callable[[str], None] | None = None,
    print_info_verbose_func: Callable[[str], None] | None = None,
    print_info_debug_func: Callable[[str], None] | None = None,
    print_success_func: Callable[[str], None] | None = None,
    print_error_func: Callable[[str], None] | None = None,
    print_exception_func: Callable[..., None] | None = None,
    telemetry_capture_exception_func: Callable[[Exception], None] | None = None,
    bloodhound_ce_version: str = BLOODHOUND_CE_VERSION,
) -> bool:
    """Start BloodHound CE containers.

    Ensures the pinned BloodHound CE stack is started, using the shared compose
    helpers for host runtime and the host helper when running inside the FULL
    ADscan Docker image.

    Args:
        is_full_adscan_container_runtime_func: Function to check if running in ADscan container
        host_helper_client_request_func: Function to make host helper requests
        check_bloodhound_ce_running_func: Function to check if BloodHound CE is running
        docker_available_func: Function to check if Docker is available
        ensure_docker_daemon_running_func: Function to ensure Docker daemon is running
        ensure_bloodhound_compose_file_func: Function to ensure compose file exists
        compose_up_func: Function to start compose stack
        print_info_func: Function to print info messages
        print_info_verbose_func: Function to print verbose info messages
        print_info_debug_func: Function to print debug info messages
        print_success_func: Function to print success messages
        print_error_func: Function to print error messages
        print_exception_func: Function to print exceptions
        telemetry_capture_exception_func: Function to capture exceptions in telemetry
        bloodhound_ce_version: BloodHound CE version to use

    Returns:
        bool: True if containers started successfully, False otherwise
    """
    try:
        check_running = check_bloodhound_ce_running_func or check_bloodhound_ce_running
        docker_avail = docker_available_func or docker_available
        ensure_compose = (
            ensure_bloodhound_compose_file_func or ensure_bloodhound_compose_file
        )
        compose_start = compose_up_func or compose_up

        in_container = (
            bool(is_full_adscan_container_runtime_func())
            if is_full_adscan_container_runtime_func
            else (os.getenv("ADSCAN_CONTAINER_RUNTIME") == "1")
        )

        if in_container:
            sock_path = os.getenv("ADSCAN_HOST_HELPER_SOCK", "").strip()
            compose_path = os.getenv("ADSCAN_HOST_BLOODHOUND_COMPOSE", "").strip()
            if not sock_path or not compose_path:
                if print_error_func:
                    print_error_func(
                        "Cannot start BloodHound CE from container runtime: missing host helper context."
                    )
                return False

            if not host_helper_client_request_func:
                try:
                    # Optional dependency: available in launcher/runtime package.
                    from adscan_launcher.host_privileged_helper import (  # noqa: PLC0415
                        host_helper_client_request,
                    )

                    host_helper_client_request_func = host_helper_client_request
                except ImportError:
                    if print_error_func:
                        print_error_func("Host helper not available.")
                    return False

            try:
                resp = host_helper_client_request_func(
                    sock_path,
                    op="bloodhound_ce_compose_up",
                    payload={"compose_path": compose_path},
                )
                if not getattr(resp, "ok", False):
                    if print_error_func:
                        print_error_func(
                            "Failed to start BloodHound CE containers on the host."
                        )
                    if print_info_debug_func:
                        stderr = getattr(resp, "stderr", "") or ""
                        stdout = getattr(resp, "stdout", "") or ""
                        if stderr:
                            print_info_debug_func(
                                f"[DEBUG] host-helper stderr:\n{stderr}"
                            )
                        if stdout:
                            print_info_debug_func(
                                f"[DEBUG] host-helper stdout:\n{stdout}"
                            )
                    return False
                return bool(check_running())
            except Exception as exc:
                if telemetry_capture_exception_func:
                    telemetry_capture_exception_func(exc)
                if print_error_func:
                    print_error_func("Failed to start BloodHound CE via host helper.")
                if print_info_debug_func:
                    marked_sock = mark_sensitive(sock_path, "path")
                    marked_compose = mark_sensitive(compose_path, "path")
                    print_info_debug_func(
                        "[bloodhound-ce] host-helper startup failure context: "
                        f"socket={marked_sock} socket_exists={Path(sock_path).exists()} "
                        f"compose_path={marked_compose}"
                    )
                if print_info_func:
                    print_info_func(
                        "Check host-helper logs at ~/.adscan/logs/host-helper.log and retry."
                    )
                if print_exception_func:
                    print_exception_func(show_locals=False, exception=exc)
                return False

        if check_running():
            if print_info_verbose_func:
                print_info_verbose_func(
                    "BloodHound CE containers already appear to be running"
                )
            return True

        if not docker_avail():
            if print_error_func:
                print_error_func("Docker is not available.")
            return False

        if (
            ensure_docker_daemon_running_func
            and not ensure_docker_daemon_running_func()
        ):
            if print_error_func:
                print_error_func(
                    "Cannot start BloodHound CE containers because the Docker daemon is not running "
                    "or not accessible."
                )
            return False

        compose_path = ensure_compose(version=bloodhound_ce_version)
        if not compose_path:
            return False

        if print_info_func:
            print_info_func("Starting BloodHound CE containers...")
        if not compose_start(compose_path):
            return False

        if print_success_func:
            print_success_func("BloodHound CE containers started successfully.")
        return True
    except Exception as exc:
        if telemetry_capture_exception_func:
            telemetry_capture_exception_func(exc)
        if print_error_func:
            print_error_func("Error starting BloodHound CE.")
        if print_exception_func:
            print_exception_func(show_locals=False, exception=exc)
        return False
