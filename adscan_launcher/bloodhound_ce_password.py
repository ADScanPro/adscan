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

import getpass
import os
import re
import sys
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
    print_instruction,
    print_panel,
    print_success,
    print_warning,
)


_DEFAULT_BH_BASE_URL = f"http://127.0.0.1:{BLOODHOUND_CE_DEFAULT_WEB_PORT}"
_DEFAULT_BH_CONTAINER_NAME = "bloodhound-bloodhound-1"
_DEFAULT_PASSWORD_PATTERNS = (
    re.compile(r"initial\s+password\s+set\s+to:\s*([^\s\"']+)", re.IGNORECASE),
    re.compile(r"initial\s+admin\s+password:\s*([^\s\"']+)", re.IGNORECASE),
    re.compile(r'"initialPassword"\s*:\s*"([^"]+)"'),
)
_PASSWORD_LOG_HEAD_LINES = 30
_PASSWORD_LOG_HEAD_MAX_CHARS = 6000
_AUTH_RATE_LIMIT_MARKERS = (
    "neo.clienterror.security.authenticationratelimit",
    "incorrect authentication details too many times in a row",
)
_MIN_BH_ADMIN_PASSWORD_LENGTH = 12
_RECOMMENDED_BH_ADMIN_PASSWORD = "Adscan4thewin!"
_PASSWORD_POLICY_MIN_LENGTH_RE = re.compile(
    r"at\s+least\s+(?P<min_len>\d+)\s+characters", re.IGNORECASE
)


def validate_bloodhound_admin_password_policy(
    password: str, *, min_length: int = _MIN_BH_ADMIN_PASSWORD_LENGTH
) -> tuple[bool, str | None]:
    """Validate BloodHound admin password policy requirements.

    Args:
        password: Candidate password to validate.
        min_length: Minimum allowed password length.

    Returns:
        Tuple ``(is_valid, error_message)``.
    """
    value = str(password or "")
    if len(value) < int(min_length):
        return (
            False,
            (
                "BloodHound CE admin password must have at least "
                f"{int(min_length)} characters."
            ),
        )
    return True, None


def _extract_password_policy_error_message(response_body: str) -> str | None:
    """Extract normalized password policy details from BloodHound API body."""
    body = str(response_body or "").strip()
    if not body:
        return None
    lowered = body.lower()
    if "secret:" not in lowered:
        return None
    if "must have at least" not in lowered:
        return None
    match = _PASSWORD_POLICY_MIN_LENGTH_RE.search(body)
    if match:
        min_len = match.group("min_len")
        return (
            "BloodHound CE rejected the requested admin password: "
            f"minimum length is {min_len} characters."
        )
    return "BloodHound CE rejected the requested admin password due password policy."


def _resolve_interactive_desired_password(
    *,
    current_password: str,
    policy_error_message: str,
) -> str | None:
    """Prompt for a replacement password when policy validation fails."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return None

    print_warning(policy_error_message)
    print_instruction(
        "Enter a new BloodHound CE admin password, or press Enter to use the recommended default."
    )
    try:
        entered = getpass.getpass(
            "BloodHound CE admin password "
            f"(leave empty for {_RECOMMENDED_BH_ADMIN_PASSWORD}): "
        )
    except (EOFError, KeyboardInterrupt):
        print_warning("Password update canceled by user.")
        return None

    candidate = str(entered or "").strip() or _RECOMMENDED_BH_ADMIN_PASSWORD
    is_valid, policy_msg = validate_bloodhound_admin_password_policy(candidate)
    if not is_valid:
        print_warning(policy_msg or "Provided password does not satisfy policy.")
        return None

    if candidate == current_password:
        print_info_debug(
            "[bloodhound-ce] interactive replacement password matches current candidate."
        )
    else:
        print_info_debug(
            "[bloodhound-ce] interactive replacement password accepted: "
            f"length={len(candidate)}"
        )
    return candidate


def _parse_initial_password_from_logs(logs: str) -> str | None:
    """Parse the initial admin password from BloodHound CE logs."""
    if not logs:
        return None
    latest_candidate: str | None = None
    latest_pos = -1
    for pattern in _DEFAULT_PASSWORD_PATTERNS:
        for match in pattern.finditer(logs):
            candidate = str(match.group(1) or "").strip()
            if candidate and match.start() >= latest_pos:
                latest_candidate = candidate
                latest_pos = match.start()
    return latest_candidate


def _get_container_started_at(container_name: str) -> str | None:
    """Return container start timestamp from docker inspect (best effort)."""
    try:
        proc = run_docker(
            ["docker", "inspect", "--format", "{{.State.StartedAt}}", container_name],
            check=False,
            capture_output=True,
            timeout=15,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_info_debug(
            "[bloodhound-ce] container started-at probe exception "
            f"(container={mark_sensitive(container_name, 'detail')}): {exc}"
        )
        return None

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        if stderr:
            print_info_debug(
                "[bloodhound-ce] container started-at probe stderr "
                f"(container={mark_sensitive(container_name, 'detail')}): "
                f"{mark_sensitive(stderr, 'detail')}"
            )
        return None

    started_at = str(proc.stdout or "").strip()
    if not started_at or started_at.startswith("0001-01-01"):
        return None
    return started_at


def _list_bloodhound_container_candidates(
    *, preferred_container_name: str
) -> list[str]:
    """Return likely BloodHound CE web container names.

    We prefer the canonical container name but include dynamic matches to handle
    custom compose project names.
    """
    candidates: list[str] = []
    preferred = str(preferred_container_name or "").strip()
    if preferred:
        candidates.append(preferred)
    if not docker_available():
        return candidates

    try:
        proc = run_docker(
            ["docker", "ps", "-a", "--format", "{{.Names}}"],
            check=False,
            capture_output=True,
            timeout=15,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_info_debug(f"[bloodhound-ce] container listing probe exception: {exc}")
        return candidates

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        if stderr:
            print_info_debug(
                f"[bloodhound-ce] container listing probe stderr: {stderr}"
            )
        return candidates

    dynamic: list[str] = []
    for raw_line in (proc.stdout or "").splitlines():
        name = str(raw_line or "").strip()
        if not name:
            continue
        lowered = name.lower()
        if "bloodhound" not in lowered:
            continue
        if re.search(r"(?:^|[-_])bloodhound(?:[-_])", lowered):
            dynamic.append(name)

    for name in dynamic:
        if name not in candidates:
            candidates.append(name)
    return candidates


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


def _probe_bloodhound_login_failure_reason(*, base_url: str, password: str) -> str:
    """Return one-shot diagnostic details for a failed BloodHound login."""
    payload = {"login_method": "secret", "username": "admin", "secret": password}
    try:
        resp = requests.post(f"{base_url}/api/v2/login", json=payload, timeout=15)
    except requests.exceptions.RequestException as exc:
        return f"request_exception={exc.__class__.__name__}: {exc}"

    body = (resp.text or "").strip().replace("\n", " ")
    if len(body) > 240:
        body = body[:240] + "...<truncated>"
    return f"status={resp.status_code}, body={body!r}"


def _get_container_runtime_state(container_name: str) -> dict[str, str] | None:
    """Return best-effort Docker runtime state for a container."""
    if not docker_available():
        return None
    try:
        proc = run_docker(
            [
                "docker",
                "inspect",
                "--format",
                "{{.State.Status}}\t{{.State.ExitCode}}\t{{.State.Error}}\t{{.State.StartedAt}}\t{{.State.FinishedAt}}",
                container_name,
            ],
            check=False,
            capture_output=True,
            timeout=15,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            "[bloodhound-ce] container state probe exception "
            f"(container={mark_sensitive(container_name, 'detail')}): {exc}"
        )
        return None

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        if stderr:
            print_info_debug(
                "[bloodhound-ce] container state probe stderr "
                f"(container={mark_sensitive(container_name, 'detail')}): "
                f"{mark_sensitive(stderr, 'detail')}"
            )
        return None

    raw = str(proc.stdout or "").strip()
    if not raw:
        return None
    parts = raw.split("\t")
    while len(parts) < 5:
        parts.append("")
    return {
        "status": parts[0].strip(),
        "exit_code": parts[1].strip(),
        "error": parts[2].strip(),
        "started_at": parts[3].strip(),
        "finished_at": parts[4].strip(),
    }


def _emit_container_log_tail(container_name: str, *, lines: int = 80) -> None:
    """Emit debug tail logs for a container (best effort)."""
    if not docker_available():
        return
    try:
        proc = run_docker(
            ["docker", "logs", "--tail", str(lines), container_name],
            check=False,
            capture_output=True,
            timeout=30,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            "[bloodhound-ce] container log-tail probe exception "
            f"(container={mark_sensitive(container_name, 'detail')}): {exc}"
        )
        return

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        if stderr:
            print_info_debug(
                "[bloodhound-ce] container log-tail probe stderr "
                f"(container={mark_sensitive(container_name, 'detail')}): "
                f"{mark_sensitive(stderr, 'detail')}"
            )
        return

    logs = (proc.stdout or "").strip()
    if not logs:
        return
    print_info_debug(
        "[bloodhound-ce] container log tail "
        f"(container={mark_sensitive(container_name, 'detail')}):\n"
        f"{mark_sensitive(logs, 'detail')}"
    )


def _container_logs_show_neo4j_auth_rate_limit(
    container_name: str, *, lines: int = 150
) -> bool:
    """Return True when container logs indicate Neo4j auth rate-limit failure."""
    if not docker_available():
        return False
    try:
        proc = run_docker(
            ["docker", "logs", "--tail", str(lines), container_name],
            check=False,
            capture_output=True,
            timeout=30,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            "[bloodhound-ce] auth-rate-limit log probe exception "
            f"(container={mark_sensitive(container_name, 'detail')}): {exc}"
        )
        return False

    if proc.returncode != 0:
        return False
    logs = str(proc.stdout or "").lower()
    return any(marker in logs for marker in _AUTH_RATE_LIMIT_MARKERS)


def _attempt_recover_from_auth_rate_limit(
    *,
    container_name: str,
    base_url: str,
    default_password: str,
) -> tuple[bool, dict | None]:
    """Attempt automatic recovery when BloodHound web container hit auth rate-limit."""
    if not _container_logs_show_neo4j_auth_rate_limit(container_name):
        return False, None

    print_warning(
        "Detected Neo4j authentication rate-limit in BloodHound CE logs. "
        "Attempting automatic container recovery."
    )
    try:
        restart_proc = run_docker(
            ["docker", "restart", container_name],
            check=False,
            capture_output=True,
            timeout=60,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            "[bloodhound-ce] automatic recovery restart exception "
            f"(container={mark_sensitive(container_name, 'detail')}): {exc}"
        )
        return False, None

    if restart_proc.returncode != 0:
        stderr = (restart_proc.stderr or "").strip()
        if stderr:
            print_info_debug(
                "[bloodhound-ce] automatic recovery restart stderr "
                f"(container={mark_sensitive(container_name, 'detail')}): "
                f"{mark_sensitive(stderr, 'detail')}"
            )
        return False, None

    print_info("Waiting for BloodHound CE web container after automatic restart...")
    for _ in range(15):
        state = _get_container_runtime_state(container_name)
        if state and state.get("status") == "running":
            break
        time.sleep(2)

    state = _get_container_runtime_state(container_name)
    if not state or state.get("status") != "running":
        print_info_debug(
            "[bloodhound-ce] automatic recovery restart did not reach running state."
        )
        return False, None

    print_info("Retrying BloodHound CE login with detected initial password...")
    ok, session = _try_bloodhound_login(
        base_url=base_url,
        password=default_password,
        max_attempts=12,
        delay_seconds=5,
    )
    if ok:
        print_success(
            "BloodHound CE recovered automatically after auth-rate-limit restart."
        )
        return True, session
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

    candidates = _list_bloodhound_container_candidates(
        preferred_container_name=container_name
    )
    print_info_debug(
        "[bloodhound-ce] password log probe container candidates: "
        f"{mark_sensitive(', '.join(candidates) if candidates else '<none>', 'detail')}"
    )

    for attempt in range(1, poll_attempts + 1):
        for candidate in candidates:
            started_at = _get_container_started_at(candidate)
            logs_command = ["docker", "logs"]
            if started_at:
                logs_command.extend(["--since", started_at])
            logs_command.append(candidate)
            try:
                proc = run_docker(
                    logs_command,
                    check=False,
                    capture_output=True,
                    timeout=30,
                )
            except Exception as exc:
                telemetry.capture_exception(exc)
                print_info_debug(
                    "[bloodhound-ce] password log probe exception "
                    f"(attempt {attempt}/{poll_attempts}, container={candidate}): {exc}"
                )
                proc = None

            # Some Docker engines may reject --since formats in corner cases.
            # Fallback to plain logs only when the scoped query itself fails.
            if proc is not None and proc.returncode != 0 and started_at:
                try:
                    fallback_proc = run_docker(
                        ["docker", "logs", candidate],
                        check=False,
                        capture_output=True,
                        timeout=30,
                    )
                except Exception as exc:
                    telemetry.capture_exception(exc)
                    print_info_debug(
                        "[bloodhound-ce] password log probe fallback exception "
                        f"(attempt {attempt}/{poll_attempts}, container={candidate}): {exc}"
                    )
                    fallback_proc = None
                if fallback_proc is not None:
                    print_info_debug(
                        "[bloodhound-ce] password log probe fallback to full logs "
                        f"(container={mark_sensitive(candidate, 'detail')}, "
                        f"started_at={mark_sensitive(started_at, 'detail')})"
                    )
                    proc = fallback_proc

            logs = ""
            if proc is not None and proc.returncode == 0:
                logs = proc.stdout or ""
            elif proc is not None and proc.stderr:
                print_info_debug(
                    "[bloodhound-ce] password log probe stderr "
                    f"(attempt {attempt}/{poll_attempts}, container={candidate}): "
                    f"{mark_sensitive((proc.stderr or '').strip(), 'detail')}"
                )

            pw = _parse_initial_password_from_logs(logs)
            if pw:
                print_info_debug(
                    "[bloodhound-ce] initial password detected from container "
                    f"{mark_sensitive(candidate, 'detail')} "
                    f"(scoped_since_start={started_at is not None})"
                )
                return pw

        if attempt < poll_attempts:
            time.sleep(poll_interval_seconds)
    _emit_password_probe_diagnostics(candidates=candidates, poll_attempts=poll_attempts)
    return None


def _log_head_excerpt(logs: str) -> str:
    """Return a bounded first-lines excerpt for diagnostics."""
    lines = (logs or "").splitlines()[:_PASSWORD_LOG_HEAD_LINES]
    excerpt = "\n".join(lines).strip()
    if len(excerpt) > _PASSWORD_LOG_HEAD_MAX_CHARS:
        excerpt = excerpt[:_PASSWORD_LOG_HEAD_MAX_CHARS] + "\n...<truncated>"
    return excerpt


def _emit_password_probe_diagnostics(
    *, candidates: list[str], poll_attempts: int
) -> None:
    """Emit debug diagnostics when initial password extraction fails."""
    print_info_debug(
        "[bloodhound-ce] initial password was not detected from container logs "
        f"after {poll_attempts} attempt(s). Collecting diagnostics."
    )

    try:
        status_proc = run_docker(
            ["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}"],
            check=False,
            capture_output=True,
            timeout=15,
        )
        if status_proc.returncode == 0:
            bh_lines = [
                line
                for line in (status_proc.stdout or "").splitlines()
                if "bloodhound" in str(line).lower()
            ]
            if bh_lines:
                print_info_debug(
                    "[bloodhound-ce] container status snapshot (docker ps -a):\n"
                    f"{mark_sensitive(chr(10).join(bh_lines), 'detail')}"
                )
            else:
                print_info_debug(
                    "[bloodhound-ce] container status snapshot: no bloodhound containers found in docker ps -a output."
                )
        else:
            print_info_debug(
                "[bloodhound-ce] docker ps -a diagnostics failed: "
                f"{mark_sensitive((status_proc.stderr or '').strip(), 'detail')}"
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(f"[bloodhound-ce] docker ps -a diagnostics exception: {exc}")

    for candidate in candidates:
        try:
            proc = run_docker(
                ["docker", "logs", candidate],
                check=False,
                capture_output=True,
                timeout=30,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                "[bloodhound-ce] password probe log-head exception "
                f"(container={mark_sensitive(candidate, 'detail')}): {exc}"
            )
            continue

        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            if stderr:
                print_info_debug(
                    "[bloodhound-ce] password probe log-head stderr "
                    f"(container={mark_sensitive(candidate, 'detail')}): "
                    f"{mark_sensitive(stderr, 'detail')}"
                )
            continue

        excerpt = _log_head_excerpt(proc.stdout or "")
        if not excerpt:
            print_info_debug(
                "[bloodhound-ce] password probe log-head is empty "
                f"(container={mark_sensitive(candidate, 'detail')})."
            )
            continue

        print_info_debug(
            "[bloodhound-ce] password probe log head "
            f"(container={mark_sensitive(candidate, 'detail')}):\n"
            f"{mark_sensitive(excerpt, 'detail')}"
        )


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

    is_valid, policy_error = validate_bloodhound_admin_password_policy(desired_password)
    print_info_debug(
        "[bloodhound-ce] desired admin password metadata: "
        f"length={len(str(desired_password or ''))}, min_required={_MIN_BH_ADMIN_PASSWORD_LENGTH}"
    )
    if not is_valid:
        print_warning(policy_error or "Invalid BloodHound CE admin password.")
        replacement = _resolve_interactive_desired_password(
            current_password=desired_password,
            policy_error_message=policy_error
            or "The desired BloodHound CE password does not satisfy policy.",
        )
        if not replacement:
            print_instruction(
                "Use --bloodhound-admin-password (launcher) or --bh-admin-password (CLI) "
                "with at least 12 characters."
            )
            return False
        desired_password = replacement

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
        login_failure = _probe_bloodhound_login_failure_reason(
            base_url=base_url,
            password=default_password,
        )
        state = _get_container_runtime_state(container_name)
        if state and state.get("status") and state.get("status") != "running":
            print_warning(
                "BloodHound CE web container is not running, so initial-password login cannot be validated."
            )
            print_instruction(
                "Inspect container logs (for example: docker logs bloodhound-bloodhound-1) and restart the stack."
            )
        else:
            print_warning(
                "BloodHound CE rejected the detected initial password. Manual reset may be required."
            )
        print_info_debug(
            "[bloodhound-ce] initial-password login diagnostic: "
            f"{mark_sensitive(login_failure, 'detail')}"
        )
        if state:
            print_info_debug(
                "[bloodhound-ce] web container state at login failure: "
                f"status={mark_sensitive(state.get('status', ''), 'detail')}, "
                f"exit_code={mark_sensitive(state.get('exit_code', ''), 'detail')}, "
                f"error={mark_sensitive(state.get('error', ''), 'detail')}, "
                f"started_at={mark_sensitive(state.get('started_at', ''), 'detail')}, "
                f"finished_at={mark_sensitive(state.get('finished_at', ''), 'detail')}"
            )
            if state.get("status") != "running":
                _emit_container_log_tail(container_name, lines=100)
                recovered_ok, recovered_session = _attempt_recover_from_auth_rate_limit(
                    container_name=container_name,
                    base_url=base_url,
                    default_password=default_password,
                )
                if recovered_ok:
                    ok = True
                    session = recovered_session
        print_info_debug(
            "[bloodhound-ce] detected initial password was rejected by API. "
            "Common causes: stale first-run password in logs, container crash before API readiness, "
            "or backend database authentication issues."
        )
        if not ok:
            started_at = _get_container_started_at(container_name)
            if started_at:
                print_info_debug(
                    "[bloodhound-ce] web container start time during rejection: "
                    f"{mark_sensitive(started_at, 'detail')}"
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
        policy_message = None
        if update_response.status_code == 400:
            policy_message = _extract_password_policy_error_message(
                update_response.text or ""
            )
        if policy_message:
            print_warning(policy_message)
            print_info_debug(
                "[bloodhound-ce] password update rejected by policy: "
                f"status={update_response.status_code}, body={(update_response.text or '')[:500]!r}"
            )
            replacement = _resolve_interactive_desired_password(
                current_password=desired_password,
                policy_error_message=policy_message,
            )
            if replacement and replacement != desired_password:
                desired_password = replacement
                update_payload["secret"] = desired_password
                continue
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

    print_success("BloodHound CE admin password updated successfully.")

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
