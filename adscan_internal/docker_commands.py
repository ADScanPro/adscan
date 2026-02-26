"""High-level Docker-mode commands for ADscan.

Source of truth:
    The canonical implementation lives in `adscan_launcher.docker_commands`.

This file remains as a compatibility shim for existing imports.
"""

from __future__ import annotations

from adscan_launcher.docker_commands import (  # noqa: F401
    DEFAULT_BLOODHOUND_ADMIN_PASSWORD,
    DEFAULT_DEV_DOCKER_IMAGE,
    DEFAULT_DOCKER_IMAGE,
    DEFAULT_HOST_HELPER_SOCKET_NAME,
    get_docker_image_name,
    handle_check_docker,
    handle_ci_docker,
    handle_install_docker,
    handle_start_docker,
    run_adscan_passthrough_docker,
    update_docker_image,
)

__all__ = [
    "DEFAULT_BLOODHOUND_ADMIN_PASSWORD",
    "DEFAULT_DEV_DOCKER_IMAGE",
    "DEFAULT_DOCKER_IMAGE",
    "DEFAULT_HOST_HELPER_SOCKET_NAME",
    "get_docker_image_name",
    "handle_check_docker",
    "handle_ci_docker",
    "handle_install_docker",
    "handle_start_docker",
    "run_adscan_passthrough_docker",
    "update_docker_image",
]
