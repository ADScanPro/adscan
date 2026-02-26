from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable

from adscan_internal import (
    print_error,
    print_info_debug,
    print_info_verbose,
    print_warning,
)
from adscan_internal import telemetry


def get_nxc_workspaces_dir(nxc_base_dir: str) -> str:
    """Return the NetExec workspaces directory for a given base directory."""
    return os.path.join(nxc_base_dir, "workspaces")


def clean_netexec_workspaces(
    nxc_workspaces_dir: str,
    *,
    use_sudo_if_needed: bool = True,
    is_tool_installed: Callable[[str], bool],
    sudo_prefix_args: Callable[..., list[str]],
    build_effective_user_env_for_command: Callable[[list[str]], dict[str, str]],
) -> bool:
    """Clean the NetExec workspaces directory to avoid schema mismatch errors.

    NetExec can have schema mismatches when switching between different workspace
    contexts. Removing the NetExec workspaces directory forces a clean state on
    the next run.

    Args:
        nxc_workspaces_dir: Path to the NetExec workspaces directory.
        use_sudo_if_needed: When True, attempts a sudo-based cleanup if the
            directory cannot be removed due to permissions (common when older
            ADscan versions were run as root).
        is_tool_installed: Callback to check for sudo availability.
        sudo_prefix_args: Callback returning a sudo argv prefix.
        build_effective_user_env_for_command: Callback building a subprocess env
            suitable for sudo-based rm.

    Returns:
        True if the directory is now absent (cleaned or already missing), False otherwise.
    """
    try:
        if os.path.exists(nxc_workspaces_dir):
            shutil.rmtree(nxc_workspaces_dir)
            print_info_verbose("Cleaned NetExec workspaces directory")
        return not os.path.exists(nxc_workspaces_dir)
    except PermissionError as exc:
        telemetry.capture_exception(exc)
        print_info_debug(
            "NetExec workspaces cleanup failed due to permissions: "
            f"{nxc_workspaces_dir}"
        )
        if not use_sudo_if_needed:
            return False

        if not is_tool_installed("sudo"):
            print_warning(
                "sudo is not available; cannot automatically repair NetExec workspaces permissions."
            )
            return False

        try:
            cmd = ["rm", "-rf", nxc_workspaces_dir]
            rm_proc = subprocess.run(
                sudo_prefix_args(non_interactive=False) + cmd,
                capture_output=True,
                text=True,
                check=False,
                env=build_effective_user_env_for_command(cmd),
            )
            print_info_debug(
                "NetExec workspaces sudo cleanup "
                f"rc={rm_proc.returncode}, stdout={len(rm_proc.stdout or '')}, "
                f"stderr={len(rm_proc.stderr or '')}"
            )
            return not os.path.exists(nxc_workspaces_dir)
        except Exception as inner_exc:
            telemetry.capture_exception(inner_exc)
            print_warning("Failed to clean NetExec workspaces via sudo.")
            return False
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error(f"Failed to clean NetExec workspaces: {exc}")
        return False


__all__ = [
    "clean_netexec_workspaces",
    "get_nxc_workspaces_dir",
]
