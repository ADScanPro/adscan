"""BloodHound CE admin password helpers.

This module provides best-effort automation to set the BloodHound CE admin
password (Docker Compose based installation).

Why this exists:
- The BloodHound CE stack prints a one-time initial admin password in container
  logs.
- ADscan wants a predictable admin password to keep UX smooth (and to avoid a
  hard stop where the user cannot proceed).

The automation is designed to be safe:
- First try the desired password (maybe already set).
- If it fails, fetch the initial password from logs and change it via the
  BloodHound CE REST API.
- If the password cannot be changed automatically, provide clear manual steps.
"""

from __future__ import annotations

import os
import time

import requests

from adscan_launcher import telemetry
from adscan_launcher.docker_runtime import docker_available, run_docker
from adscan_launcher.bloodhound_ce_compose import BLOODHOUND_CE_DEFAULT_WEB_PORT
from adscan_launcher.output import (
    mark_sensitive,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_panel,
    print_success,
    print_warning,
)


_DEFAULT_BH_BASE_URL = f"http://127.0.0.1:{BLOODHOUND_CE_DEFAULT_WEB_PORT}"
_DEFAULT_BH_CONTAINER_NAME = "bloodhound-bloodhound-1"


def _parse_initial_password_from_logs(logs: str) -> str | None:
    """Parse the initial admin password from BloodHound CE logs."""
    if not logs:
        return None
    for line in logs.splitlines():
        if "Initial Password Set To:" not in line:
            continue
        password_part = line.split("Initial Password Set To:", 1)[1].strip()
        if not password_part:
            continue
        parts = password_part.split()
        return parts[0] if parts else password_part
    return None


def _try_bloodhound_login(
    *, base_url: str, password: str, max_attempts: int = 3, delay_seconds: int = 2
) -> tuple[bool, dict | None]:
    """Try to authenticate to BloodHound CE with a secret login."""
    payload = {"login_method": "secret", "username": "admin", "secret": password}
    for attempt in range(1, max_attempts + 1):
        try:
            resp = requests.post(f"{base_url}/api/v2/login", json=payload, timeout=30)
        except requests.exceptions.RequestException:
            resp = None
        if resp is not None and resp.status_code == 200:
            try:
                data = resp.json() or {}
            except ValueError:
                return True, None
            session = data.get("data") or {}
            return True, session or None
        if attempt < max_attempts:
            time.sleep(delay_seconds)
    return False, None


def _get_initial_password_from_container_logs(
    *,
    container_name: str = _DEFAULT_BH_CONTAINER_NAME,
    poll_attempts: int = 12,
    poll_interval_seconds: int = 5,
) -> str | None:
    """Fetch and parse the initial admin password from container logs."""
    if not docker_available():
        return None

    for attempt in range(1, poll_attempts + 1):
        try:
            proc = run_docker(
                ["docker", "logs", container_name],
                check=False,
                capture_output=True,
                timeout=30,
            )
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[bloodhound-ce] password log probe exception (attempt {attempt}/{poll_attempts}): {exc}"
            )
            proc = None

        logs = ""
        if proc is not None and proc.returncode == 0:
            logs = proc.stdout or ""

        pw = _parse_initial_password_from_logs(logs)
        if pw:
            return pw

        if attempt < poll_attempts:
            time.sleep(poll_interval_seconds)
    return None


def ensure_bloodhound_admin_password(
    *,
    desired_password: str,
    suppress_browser: bool = False,
    base_url: str = _DEFAULT_BH_BASE_URL,
    container_name: str = _DEFAULT_BH_CONTAINER_NAME,
) -> bool:
    """Ensure BloodHound CE admin password is set to a desired value.

    Returns:
        True if the desired password is confirmed (or successfully set).
    """
    if not desired_password:
        print_warning("No desired BloodHound CE admin password provided; skipping.")
        return True

    print_info("Ensuring BloodHound CE admin password is set...")

    # 1) If already set, do nothing.
    ok, _ = _try_bloodhound_login(base_url=base_url, password=desired_password)
    if ok:
        print_success("BloodHound CE admin password already matches the desired value.")
        return True

    # 2) Try to recover the initial password from logs.
    default_password = _get_initial_password_from_container_logs(
        container_name=container_name
    )
    if not default_password:
        print_warning(
            "Could not detect the initial BloodHound CE admin password from container logs."
        )
        _show_manual_password_steps(
            base_url=base_url,
            default_password=None,
            suppress_browser=suppress_browser,
        )
        return False

    print_info(
        f"Detected initial BloodHound CE password: {mark_sensitive(default_password, 'password')}"
    )

    # 3) Login with default password and update it.
    ok, session = _try_bloodhound_login(
        base_url=base_url, password=default_password, max_attempts=12, delay_seconds=5
    )
    if not ok:
        print_warning(
            "BloodHound CE rejected the detected initial password. Manual reset may be required."
        )
        _show_manual_password_steps(
            base_url=base_url,
            default_password=default_password,
            suppress_browser=suppress_browser,
        )
        return False

    session_token = (session or {}).get("session_token")
    user_id = (session or {}).get("user_id")
    if not session_token or not user_id:
        print_warning(
            "BloodHound CE login succeeded but did not return session metadata; cannot update password automatically."
        )
        _show_manual_password_steps(
            base_url=base_url,
            default_password=default_password,
            suppress_browser=suppress_browser,
        )
        return False

    headers = {"Authorization": f"Bearer {session_token}"}
    update_payload = {
        "secret": desired_password,
        "current_secret": default_password,
        "needs_password_reset": False,
    }

    update_response = None
    for attempt in range(1, 7):
        try:
            update_response = requests.put(
                f"{base_url}/api/v2/bloodhound-users/{user_id}/secret",
                json=update_payload,
                headers=headers,
                timeout=30,
            )
        except requests.exceptions.RequestException as exc:
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[bloodhound-ce] password update exception (attempt {attempt}/6): {exc}"
            )
            time.sleep(5)
            continue

        if update_response.status_code in (200, 204):
            break
        print_info_debug(
            f"[bloodhound-ce] password update failed (attempt {attempt}/6): "
            f"status={update_response.status_code}, body={(update_response.text or '')[:200]!r}"
        )
        time.sleep(5)

    if update_response is None or update_response.status_code not in (200, 204):
        print_warning("Failed to update BloodHound CE password automatically.")
        if update_response is not None:
            print_info_debug(
                f"[bloodhound-ce] password update last response: "
                f"status={update_response.status_code}, body={(update_response.text or '')[:500]!r}"
            )
        _show_manual_password_steps(
            base_url=base_url,
            default_password=default_password,
            suppress_browser=suppress_browser,
        )
        return False

    print_success("BloodHound CE admin password updated successfully to Adscan4thewin!")

    # 4) Validate desired password.
    ok, _ = _try_bloodhound_login(
        base_url=base_url, password=desired_password, max_attempts=12, delay_seconds=5
    )
    if ok:
        return True

    print_info_verbose(
        "Password update succeeded, but validation failed. Proceeding anyway."
    )
    return True


def _show_manual_password_steps(
    *, base_url: str, default_password: str | None, suppress_browser: bool
) -> None:
    """Show manual steps to set BloodHound CE password."""
    url = f"{base_url}/ui/login".replace("127.0.0.1", "localhost")
    default_pw_display = (
        mark_sensitive(default_password, "password") if default_password else "UNKNOWN"
    )
    print_panel(
        f"Open the BloodHound CE UI:\n[bold]{url}[/bold]\n\n"
        "Login:\n"
        "  user: admin\n"
        f"  password: {default_pw_display}\n\n"
        "On first login, change the admin password.\n",
        title="BloodHound CE",
        border_style="yellow",
        fit=True,
    )
    if suppress_browser:
        return
    # Best-effort open (host only). If it fails, it's not fatal.
    has_gui = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    if not has_gui:
        return
    try:
        import subprocess

        if (
            subprocess.call(
                ["which", "xdg-open"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            == 0
        ):  # nosec B607
            subprocess.Popen(
                ["xdg-open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )  # nosec B603
    except Exception:
        pass
