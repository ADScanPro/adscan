"""RDP CLI orchestration helpers.

This module extracts RDP-related orchestration logic out of the monolithic
`adscan.py` so it can be reused by future UX layers while keeping runtime
behaviour stable for the current CLI.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from typing import Any

from rich.prompt import Confirm

from adscan_internal import (
    print_error,
    print_exception,
    print_info,
    print_info_verbose,
    telemetry,
)
from adscan_internal.rich_output import mark_sensitive, strip_sensitive_markers
from adscan_internal.text_utils import strip_ansi_codes


def ask_for_rdp_access(
    shell: Any, *, domain: str, host: str, username: str, password: str
) -> None:
    """Ask to access a host via RDP and execute the connection.

    Args:
        shell: Active `PentestShell` instance.
        domain: User's domain.
        host: Target host.
        username: RDP username.
        password: Password or NTLM hash.
    """
    marked_host = mark_sensitive(host, "hostname")
    marked_username = mark_sensitive(username, "user")
    answer = Confirm.ask(
        f"Do you want to access host {marked_host} via RDP as user {marked_username}?"
    )
    if answer:
        rdp_access(
            shell,
            domain=domain,
            host=host,
            username=username,
            password=password,
        )


def rdp_access(
    shell: Any, *, domain: str, host: str, username: str, password: str
) -> None:
    """Access a host via RDP using xfreerdp.

    This helper extracts the legacy ``PentestShell.rdp_access`` method from
    ``adscan.py`` so that RDP logic can be reused by other UX layers.

    Args:
        shell: Active `PentestShell` instance.
        domain: User's domain.
        host: Target host.
        username: RDP username.
        password: Password or NTLM hash.
    """
    from adscan_internal.docker_runtime import is_docker_env

    rdp_binary = shutil.which("xfreerdp3") or shutil.which("xfreerdp")
    if not rdp_binary:
        print_error(
            "RDP client not found. Please install xfreerdp3 or xfreerdp via 'adscan install'."
        )
        return

    # Import GUI session check functions from adscan.py
    # These are defined at module level in adscan.py
    # We'll need to pass them or import them if available
    try:
        # Try to import from adscan if available (circular import risk, but adscan imports this module)
        import sys
        adscan_module = sys.modules.get("adscan")
        if adscan_module:
            _has_gui_session = getattr(adscan_module, "_has_gui_session", None)
            _is_full_adscan_container_runtime = getattr(
                adscan_module, "_is_full_adscan_container_runtime", None
            )
            if _has_gui_session and _is_full_adscan_container_runtime:
                # Use imported functions
                pass
            else:
                raise AttributeError("Functions not found in adscan module")
        else:
            raise ImportError("adscan module not loaded")
    except (ImportError, AttributeError):
        # Fallback: define inline checks if not available
        def _has_gui_session() -> bool:
            """Check if GUI session is available."""
            display = os.getenv("DISPLAY") or os.getenv("WAYLAND_DISPLAY")
            if display:
                try:
                    # Most X11 clients require the Unix socket directory to be mounted.
                    if os.path.isdir("/tmp/.X11-unix"):
                        return True
                except OSError:
                    pass
            return bool(display)

        def _is_full_adscan_container_runtime() -> bool:
            """Check if running in full ADscan container runtime."""
            if os.getenv("ADSCAN_CONTAINER_RUNTIME") == "1":
                return True
            if not is_docker_env():
                return False
            if os.getenv("ADSCAN_HOME") != "/opt/adscan":
                return False
            return (
                os.path.isdir("/opt/adscan/tool_venvs")
                and os.path.isdir("/opt/adscan/tools")
                and os.path.isdir("/opt/adscan/wordlists")
            )

    if not _has_gui_session():
        in_container = _is_full_adscan_container_runtime() or is_docker_env()
        if in_container:
            # In Docker FULL mode, fall back to launching RDP on the host when
            # container GUI passthrough is not available.
            if _is_full_adscan_container_runtime() and try_launch_rdp_on_host(
                shell,
                domain=domain,
                host=host,
                username=username,
                password=password,
            ):
                return
            print_error(
                "Cannot launch RDP from the container: no GUI session detected "
                "(DISPLAY/WAYLAND_DISPLAY is not set)."
            )
            print_info(
                "Run this from your host desktop session, or restart ADscan with GUI passthrough enabled "
                "(export ADSCAN_DOCKER_GUI=1 on the host before `adscan start`)."
            )
        else:
            print_error(
                "Cannot launch RDP: no GUI session detected (DISPLAY/WAYLAND_DISPLAY is not set)."
            )
            print_info("Run ADscan from a graphical desktop session and try again.")
        return

    marked_domain = mark_sensitive(domain, "domain")
    marked_username = mark_sensitive(username, "user")
    marked_password = mark_sensitive(password, "password")
    marked_host = mark_sensitive(host, "hostname")

    command = (
        f"{rdp_binary} /d:'{marked_domain}' /u:'{marked_username}' "
        f"/p:'{marked_password}' /v:{marked_host} /cert:ignore"
    )

    print_info(f"Accessing host {marked_host} via RDP as user {marked_username}")
    execute_rdp_access(shell, command)


def try_launch_rdp_on_host(
    shell: Any, *, domain: str, host: str, username: str, password: str
) -> bool:
    """Best-effort: launch the RDP client on the host when running in Docker FULL mode.

    Args:
        shell: Active `PentestShell` instance.
        domain: User's domain.
        host: Target host.
        username: RDP username.
        password: Password or NTLM hash.

    Returns:
        True if RDP was successfully launched on the host, False otherwise.
    """
    sock_path = os.getenv("ADSCAN_HOST_HELPER_SOCK", "").strip()
    if not sock_path:
        return False
    try:
        from adscan_internal.host_privileged_helper import (
            HostHelperError,
            host_helper_client_request,
        )

        clean_domain = strip_sensitive_markers(domain)
        clean_host = strip_sensitive_markers(host)
        clean_user = strip_sensitive_markers(username)
        clean_pass = strip_sensitive_markers(password)

        resp = host_helper_client_request(
            sock_path,
            op="rdp_launch",
            payload={
                "domain": clean_domain,
                "host": clean_host,
                "username": clean_user,
                "password": clean_pass,
            },
        )
        if resp.ok:
            print_info(
                "RDP launched on the host desktop session (container GUI passthrough not available)."
            )
            marked_host = mark_sensitive(clean_host, "hostname")
            marked_user = mark_sensitive(clean_user, "user")
            print_info(f"Host RDP target: {marked_user}@{marked_host}")
            return True

        if resp.message:
            print_info_verbose(f"[rdp] host-helper: {resp.message}")
        if resp.stderr:
            print_info_verbose(
                f"[rdp] host-helper stderr: {strip_ansi_codes(resp.stderr)[:200]}"
            )
    except HostHelperError as exc:
        telemetry.capture_exception(exc)
        print_info_verbose(f"[rdp] host-helper error: {exc}")
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_info_verbose(f"[rdp] host-helper exception: {exc}")
    return False


def execute_rdp_access(shell: Any, command: str) -> bool:
    """Execute an RDP access command.

    This helper extracts the legacy ``PentestShell.execute_rdp_access`` method
    from ``adscan.py`` so that RDP execution logic can be reused by other UX layers.

    Args:
        shell: Active `PentestShell` instance with `spawn_command` method.
        command: RDP command string to execute.

    Returns:
        True if RDP session was launched successfully, False otherwise.
    """
    from adscan_internal.docker_runtime import is_docker_env

    try:
        # RDP is typically interactive; using a blocking command with a timeout can
        # incorrectly surface "errors" if the user keeps the session open.
        # Spawn the RDP client and return immediately.
        print_info(f"Executing RDP command: {command}")

        proc = shell.spawn_command(
            command,
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            ignore_errors=True,
        )
        if not proc:
            print_error("Failed to start RDP client.")
            return False

        # If it exits immediately, treat it as an error; otherwise consider it launched.
        time.sleep(1)
        returncode = proc.poll()
        if returncode is None:
            print_info(
                "RDP session launched. Close the RDP window to end the session."
            )
            return True

        if returncode == 0:
            print_info("RDP command completed successfully.")
            return True

        stderr_text = ""
        try:
            _, stderr_text = proc.communicate(timeout=1)
        except Exception:
            stderr_text = ""
        clean_stderr = strip_ansi_codes(stderr_text or "").strip()
        normalized = clean_stderr.lower()
        if "failed to open display" in normalized or "$display" in normalized:
            print_error(
                "RDP client could not open a display (GUI not available in this environment)."
            )
            try:
                import sys
                adscan_module = sys.modules.get("adscan")
                if adscan_module:
                    _is_full_adscan_container_runtime = getattr(
                        adscan_module, "_is_full_adscan_container_runtime", None
                    )
                    if not _is_full_adscan_container_runtime:
                        raise AttributeError("Function not found")
                else:
                    raise ImportError("adscan module not loaded")
            except (ImportError, AttributeError):
                def _is_full_adscan_container_runtime() -> bool:
                    """Check if running in full ADscan container runtime."""
                    if os.getenv("ADSCAN_CONTAINER_RUNTIME") == "1":
                        return True
                    if not is_docker_env():
                        return False
                    if os.getenv("ADSCAN_HOME") != "/opt/adscan":
                        return False
                    return (
                        os.path.isdir("/opt/adscan/tool_venvs")
                        and os.path.isdir("/opt/adscan/tools")
                        and os.path.isdir("/opt/adscan/wordlists")
                    )

            if _is_full_adscan_container_runtime() or is_docker_env():
                print_info(
                    "If you're running ADscan in Docker, run RDP from the host desktop session "
                    "or restart with GUI passthrough (export ADSCAN_DOCKER_GUI=1 on the host)."
                )
            else:
                print_info(
                    "Please ensure your $DISPLAY (or Wayland session) is set correctly and try again."
                )
        else:
            print_error("RDP process exited with an error.")
            if clean_stderr:
                print_info_verbose(f"RDP error output: {clean_stderr}")
        return False
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error during RDP command execution.")
        print_exception(show_locals=False, exception=e)
        return False

