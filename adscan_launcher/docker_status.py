"""Docker status helpers (host-side).

This module centralizes lightweight checks about the host Docker environment:
- Whether the official Docker Engine binary is available (not `docker.io`)
- Whether the Docker Compose v2 plugin (`docker compose`) is available
- Whether the Docker daemon is running and reachable
- Best-effort auto-start logic for the Docker daemon

Canonical implementation for host/launcher operations.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from typing import Callable, Tuple

from adscan_launcher import telemetry


_DOCKER_SERVICE_UNIT_MISSING_RE = re.compile(
    r"(unit\s+docker\.service\s+could\s+not\s+be\s+found|could\s+not\s+find\s+the\s+requested\s+service\s+docker)",
    re.IGNORECASE,
)


def is_official_docker_installed() -> Tuple[bool, str]:
    """Return whether official Docker Engine is installed (not `docker.io`)."""
    try:
        if not shutil.which("docker"):
            return False, "Docker not found in PATH"

        result = subprocess.run(
            ["docker", "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return False, "Docker command failed"

        version_output = (result.stdout or "").strip()
        if "Docker version" in version_output:
            # Filter out distro-packaged docker.io variants.
            if "+dfsg" in version_output or "+deb" in version_output:
                return False, f"Non-official Docker detected: {version_output}"
            return True, version_output

        return False, f"Unexpected Docker version format: {version_output}"
    except subprocess.TimeoutExpired:
        return False, "Docker version check timed out"
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return False, f"Error checking Docker: {exc}"


def is_docker_compose_plugin_available() -> Tuple[bool, str]:
    """Return whether Docker Compose v2 plugin (`docker compose`) is available."""
    try:
        if not shutil.which("docker"):
            return False, "Docker not found in PATH"

        result = subprocess.run(
            ["docker", "compose", "version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            version_output = (result.stdout or "").strip()
            return True, version_output

        stderr_output = (result.stderr or "").strip() or "No error output"
        return False, f"Docker Compose plugin not available: {stderr_output}"
    except subprocess.TimeoutExpired:
        return False, "Docker Compose version check timed out"
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return False, f"Error checking Docker Compose plugin: {exc}"


def is_docker_daemon_running(
    *,
    run_docker_command_func: Callable[..., subprocess.CompletedProcess] | None = None,
) -> Tuple[bool, str]:
    """Return whether the Docker daemon is running and reachable."""
    try:
        if not shutil.which("docker"):
            return False, "Docker CLI not found in PATH"

        docker_cmd = run_docker_command_func or subprocess.run
        result = docker_cmd(
            ["docker", "info"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return True, "Docker daemon is running"

        stderr_output = (result.stderr or "").strip()
        stdout_output = (result.stdout or "").strip()
        message = (
            stderr_output
            or stdout_output
            or "Docker daemon not running or not accessible"
        )
        return False, message
    except subprocess.TimeoutExpired:
        return False, "Docker daemon check timed out"
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return False, f"Error checking Docker daemon: {exc}"


def ensure_docker_daemon_running(
    *,
    docker_access_denied_func: Callable[[str], bool],
    run_docker_command_func: Callable[..., subprocess.CompletedProcess],
    sudo_validate_func: Callable[[], bool],
    run_systemctl_command_func: Callable[..., subprocess.CompletedProcess],
    print_warning_func: Callable[[str], None],
    print_info_func: Callable[[str], None],
    print_info_debug_func: Callable[[str], None],
    print_info_verbose_func: Callable[[str], None],
    print_success_verbose_func: Callable[[str], None],
    print_error_func: Callable[[str], None],
    print_exception_func: Callable[..., None],
    set_docker_use_sudo_func: Callable[[bool], None] | None = None,
) -> bool:
    """Ensure the Docker daemon is running; try to start it when possible."""
    is_running, diagnostic = is_docker_daemon_running(
        run_docker_command_func=run_docker_command_func
    )
    if is_running:
        return True

    print_warning_func(
        "Docker daemon appears to be stopped or not accessible. "
        "BloodHound CE containers cannot start without a running Docker daemon."
    )
    print_info_debug_func(f"[docker] Daemon diagnostic: {diagnostic}")

    if docker_access_denied_func(diagnostic):
        # If daemon is running but user lacks permissions, use sudo for docker commands.
        if set_docker_use_sudo_func:
            set_docker_use_sudo_func(True)
        if sudo_validate_func():
            sudo_probe = run_docker_command_func(
                ["docker", "info"],
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if sudo_probe and sudo_probe.returncode == 0:
                print_info_verbose_func(
                    "Docker daemon is running but requires sudo; continuing with sudo docker."
                )
                return True

    # Attempt to start Docker via systemd when available
    if shutil.which("systemctl"):
        try:
            print_info_func("Attempting to start Docker service via systemctl...")
            run_systemctl_command_func(["start", "docker"], check=False)
            is_running_after, diagnostic_after = is_docker_daemon_running(
                run_docker_command_func=run_docker_command_func
            )
            print_info_debug_func(f"[docker] Post-start diagnostic: {diagnostic_after}")
            if is_running_after:
                print_success_verbose_func("Docker service started successfully.")
                return True

            status_text = ""
            try:
                status_proc = run_systemctl_command_func(
                    ["status", "docker", "--no-pager", "--full"],
                    check=False,
                )
                if status_proc is not None:
                    status_text = (
                        f"{getattr(status_proc, 'stdout', '')}\n"
                        f"{getattr(status_proc, 'stderr', '')}"
                    ).strip()
                    if status_text:
                        print_info_debug_func(
                            f"[docker] systemctl status docker output: {status_text}"
                        )
            except Exception as exc:  # pragma: no cover - best effort diagnostics
                telemetry.capture_exception(exc)
                print_info_debug_func(
                    f"[docker] Unable to inspect docker.service status: {exc}"
                )

            if _DOCKER_SERVICE_UNIT_MISSING_RE.search(status_text):
                print_error_func(
                    "Docker service unit (`docker.service`) was not found on this host."
                )
                print_info_func(
                    "Install Docker Engine + Docker Compose plugin, then rerun install/check."
                )
                return False

            if docker_access_denied_func(diagnostic_after):
                if set_docker_use_sudo_func:
                    set_docker_use_sudo_func(True)
                if sudo_validate_func():
                    sudo_probe = run_docker_command_func(
                        ["docker", "info"],
                        shell=False,
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    if sudo_probe and sudo_probe.returncode == 0:
                        print_info_verbose_func(
                            "Docker daemon is running but requires sudo; continuing with sudo docker."
                        )
                        return True

            print_error_func(
                "Docker service start command completed, but the daemon is still not reachable."
            )
        except Exception as exc:  # pragma: no cover
            try:
                telemetry.capture_exception(exc)
            except Exception:
                pass
            print_error_func("Error while trying to start Docker service.")
            print_exception_func(show_locals=False, exception=exc)
    else:
        print_info_debug_func(
            "[docker] systemctl not available; cannot auto-start Docker daemon."
        )

    print_info_func(
        "Please ensure the Docker daemon is running (for example, with "
        "'sudo systemctl start docker') and rerun the check or install command."
    )
    return False


__all__ = [
    "ensure_docker_daemon_running",
    "is_docker_compose_plugin_available",
    "is_docker_daemon_running",
    "is_official_docker_installed",
]
