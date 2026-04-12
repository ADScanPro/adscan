"""Host-aware Docker operations for ADscan runtime.

This module centralizes Docker actions that may need to cross the container
boundary when ADscan runs inside its own runtime container. In host runtime we
can call Docker directly; in container runtime we must delegate privileged host
operations to the host helper.
"""

from __future__ import annotations

from dataclasses import dataclass
import os

from adscan_internal.docker_runtime import docker_available, run_docker
from adscan_internal.host_privileged_helper import (
    HostHelperError,
    host_helper_client_request,
)
from adscan_launcher.bloodhound_ce_compose import _compose_container_name


_HOST_HELPER_SOCKET_ENV = "ADSCAN_HOST_HELPER_SOCK"
_CONTAINER_RUNTIME_ENV = "ADSCAN_CONTAINER_RUNTIME"
_MANAGED_BLOODHOUND_SERVICES = frozenset({"bloodhound", "neo4j", "postgres"})


@dataclass(frozen=True)
class HostDockerActionResult:
    """Structured result for host-aware Docker operations."""

    ok: bool
    method: str
    message: str | None = None
    stdout: str | None = None
    stderr: str | None = None


def _is_container_runtime() -> bool:
    """Return True when ADscan is running inside its managed container runtime."""
    return str(os.getenv(_CONTAINER_RUNTIME_ENV, "")).strip() == "1"


def _host_helper_socket_path() -> str:
    """Return the configured host helper socket path, if any."""
    return str(os.getenv(_HOST_HELPER_SOCKET_ENV, "")).strip()


def _validate_service_name(service_name: str) -> str:
    """Validate a managed BloodHound CE service name."""
    normalized = str(service_name or "").strip().lower()
    if normalized not in _MANAGED_BLOODHOUND_SERVICES:
        allowed = ", ".join(sorted(_MANAGED_BLOODHOUND_SERVICES))
        raise ValueError(
            f"Unsupported managed BloodHound CE service: {service_name!r}. Allowed: {allowed}"
        )
    return normalized


def _run_host_helper_operation(
    *,
    op: str,
    payload: dict[str, object],
    timeout_seconds: float,
) -> HostDockerActionResult:
    """Run a host-helper-backed Docker operation from container runtime."""
    socket_path = _host_helper_socket_path()
    if not socket_path:
        return HostDockerActionResult(
            ok=False,
            method="host_helper",
            message="host_helper_unavailable",
        )

    try:
        resp = host_helper_client_request(
            socket_path,
            op=op,
            payload=payload,
            timeout_seconds=timeout_seconds,
        )
    except HostHelperError as exc:
        return HostDockerActionResult(
            ok=False,
            method="host_helper",
            message=str(exc),
        )

    return HostDockerActionResult(
        ok=bool(resp.ok),
        method="host_helper",
        message=resp.message,
        stdout=resp.stdout,
        stderr=resp.stderr,
    )


def _run_direct_docker_operation(
    *,
    argv: list[str],
    timeout_seconds: int,
) -> HostDockerActionResult:
    """Run a Docker CLI operation directly from host runtime."""
    if not docker_available():
        return HostDockerActionResult(
            ok=False,
            method="docker_cli",
            message="docker_unavailable",
        )

    try:
        proc = run_docker(
            argv,
            check=False,
            capture_output=True,
            timeout=timeout_seconds,
        )
    except Exception as exc:  # noqa: BLE001
        return HostDockerActionResult(
            ok=False,
            method="docker_cli",
            message=str(exc),
        )

    return HostDockerActionResult(
        ok=proc.returncode == 0,
        method="docker_cli",
        message=None if proc.returncode == 0 else "docker_command_failed",
        stdout=(getattr(proc, "stdout", "") or None),
        stderr=(getattr(proc, "stderr", "") or None),
    )


def get_managed_bloodhound_ce_service_time(
    service_name: str = "bloodhound",
) -> HostDockerActionResult:
    """Return UTC time details for a managed BloodHound CE service container."""
    service = _validate_service_name(service_name)
    if _is_container_runtime():
        return _run_host_helper_operation(
            op="bloodhound_ce_service_utc",
            payload={"service": service},
            timeout_seconds=20,
        )

    container_name = _compose_container_name(service)
    return _run_direct_docker_operation(
        argv=[
            "docker",
            "exec",
            container_name,
            "date",
            "-u",
            "+%Y-%m-%dT%H:%M:%SZ (%s)",
        ],
        timeout_seconds=20,
    )


def restart_managed_bloodhound_ce_service(
    service_name: str = "bloodhound",
) -> HostDockerActionResult:
    """Restart a managed BloodHound CE service container."""
    service = _validate_service_name(service_name)
    if _is_container_runtime():
        return _run_host_helper_operation(
            op="bloodhound_ce_restart_service",
            payload={"service": service},
            timeout_seconds=60,
        )

    container_name = _compose_container_name(service)
    return _run_direct_docker_operation(
        argv=["docker", "restart", container_name],
        timeout_seconds=60,
    )


def wait_for_bloodhound_ce_api_ready(
    *,
    base_url: str,
    timeout_seconds: int = 60,
    interval_seconds: int = 2,
) -> bool:
    """Wait until the BloodHound CE API is reachable again after recovery."""
    from adscan_launcher.docker_commands import (  # noqa: PLC0415
        _wait_for_bloodhound_ce_api_ready,
    )

    return bool(
        _wait_for_bloodhound_ce_api_ready(
            base_url=base_url,
            timeout_seconds=timeout_seconds,
            interval_seconds=interval_seconds,
        )
    )


def restart_bloodhound_ce_and_wait(
    *,
    base_url: str,
    service_name: str = "bloodhound",
    timeout_seconds: int = 60,
    interval_seconds: int = 2,
) -> HostDockerActionResult:
    """Restart the managed BloodHound CE web container and wait for API readiness."""
    restart_result = restart_managed_bloodhound_ce_service(service_name=service_name)
    if not restart_result.ok:
        return restart_result

    if not wait_for_bloodhound_ce_api_ready(
        base_url=base_url,
        timeout_seconds=timeout_seconds,
        interval_seconds=interval_seconds,
    ):
        return HostDockerActionResult(
            ok=False,
            method=restart_result.method,
            message="bloodhound_api_not_ready_after_restart",
            stdout=restart_result.stdout,
            stderr=restart_result.stderr,
        )

    return restart_result
