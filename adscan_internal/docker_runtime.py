"""Docker runtime helpers for ADscan container mode.

This module is part of the host-side launcher surface.

Source of truth:
    The canonical implementation lives in `adscan_launcher.docker_runtime` so the
    same Docker orchestration logic can be used by:
    - the PyPI/GitHub launcher (open source)
    - the full ADscan codebase

This file remains as a compatibility shim for existing imports.
"""

from __future__ import annotations

from adscan_launcher.docker_runtime import (  # noqa: F401
    DockerRunConfig,
    build_adscan_run_command,
    docker_access_denied,
    docker_available,
    docker_needs_sudo,
    emit_entrypoint_logs_from_state,
    ensure_image_pulled,
    image_exists,
    is_docker_env,
    run_docker,
    run_docker_command,
    run_docker_stream,
    shell_quote_cmd,
)

__all__ = [
    "DockerRunConfig",
    "build_adscan_run_command",
    "docker_access_denied",
    "docker_available",
    "docker_needs_sudo",
    "emit_entrypoint_logs_from_state",
    "ensure_image_pulled",
    "image_exists",
    "is_docker_env",
    "run_docker",
    "run_docker_command",
    "run_docker_stream",
    "shell_quote_cmd",
]
