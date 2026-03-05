"""Host-side ADscan launcher CLI.

This CLI is intended for PyPI/GitHub distribution as open source.
It orchestrates Docker to run the real ADscan CLI inside the container image.

Supported commands (host-side):
- install: pull image + bootstrap BloodHound CE
- check: sanity checks for Docker mode
- start: run interactive container session
- ci: run CI mode inside container
- update/upgrade: update the launcher and pull the latest image
- version: show launcher version

Any other arguments are passed through to the container.
"""

from __future__ import annotations

import argparse
import re
from io import StringIO
import os
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Callable

from rich.console import Console

from adscan_core.interrupts import emit_interrupt_debug
from adscan_core.theme import ADSCAN_THEME
from adscan_launcher import __version__
from adscan_launcher.bloodhound_ce_password import (
    validate_bloodhound_admin_password_policy,
)
from adscan_launcher.bloodhound_ce_compose import (
    detect_legacy_bloodhound_ce_running_stack,
    stop_legacy_bloodhound_ce_stack,
)
from adscan_launcher.docker_commands import (
    DEFAULT_BLOODHOUND_ADMIN_PASSWORD,
    DEFAULT_BLOODHOUND_STACK_MODE,
    get_docker_image_name,
    handle_check_docker,
    handle_install_docker,
    handle_start_docker,
    run_adscan_passthrough_docker,
    normalize_pull_timeout_seconds,
)
from adscan_launcher.docker_runtime import (
    ensure_image_pulled,
    image_exists,
    is_docker_env,
    run_docker,
)
from adscan_launcher.output import (
    confirm_ask,
    print_error,
    print_info,
    print_info_debug,
    print_instruction,
    print_panel,
    print_success,
    print_warning,
    set_output_config,
)
from adscan_launcher.paths import get_state_dir
from adscan_launcher.telemetry import (
    HOST_SESSION_CAPTURE_COMMANDS,
    SESSION_CAPTURE_ALLOWED_COMMANDS,
    capture,
    capture_command_session,
    capture_exception,
    collect_system_context,
)
from adscan_launcher.update_manager import (
    UpdateContext,
    offer_updates_for_command,
    run_update_command,
)


ADSCAN_SUDO_ALIAS_MARKER = "# ADscan auto-sudo alias"
_SESSION_CAPTURE_FINALIZED = False


def _parse_bloodhound_admin_password(value: str) -> str:
    """argparse type validator for BloodHound CE admin password."""
    candidate = str(value or "")
    valid, error_message = validate_bloodhound_admin_password_policy(candidate)
    if not valid:
        raise argparse.ArgumentTypeError(
            error_message
            or (
                "Invalid BloodHound CE admin password "
                "(requires 12+ chars, lowercase, uppercase, number, and one of !@#$%^&*)."
            )
        )
    return candidate


def _remove_legacy_adscan_sudo_alias(rcfile: str) -> bool:
    """Remove the legacy ADscan auto-sudo alias from a shell rc file (best-effort)."""
    try:
        path = Path(rcfile)
        if not path.exists():
            return False
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        changed = False
        new_lines: list[str] = []

        idx = 0
        while idx < len(lines):
            line = lines[idx]
            if line.strip() == ADSCAN_SUDO_ALIAS_MARKER.strip():
                next_idx = idx + 1
                if next_idx < len(lines) and lines[next_idx].lstrip().startswith(
                    "alias adscan='sudo -E "
                ):
                    changed = True
                    idx += 2
                    continue
            new_lines.append(line)
            idx += 1

        if not changed:
            return False

        path.write_text("".join(new_lines), encoding="utf-8")
        return True
    except Exception:
        return False


def _cleanup_legacy_sudo_alias() -> None:
    """Best-effort removal of the legacy auto-sudo alias from user shell configs."""
    is_sudo = "SUDO_USER" in os.environ
    if os.geteuid() == 0 and is_sudo:
        target_user = os.environ.get("SUDO_USER")
    else:
        target_user = os.environ.get("USER")

    home = (
        os.path.expanduser(f"~{target_user}")
        if target_user
        else os.path.expanduser("~")
    )
    shell = os.environ.get("SHELL", "")
    if "zsh" in shell:
        rcfiles = [os.path.join(home, ".zshrc")]
    else:
        rcfiles = [os.path.join(home, ".bash_aliases"), os.path.join(home, ".bashrc")]

    for rcfile in rcfiles:
        _remove_legacy_adscan_sudo_alias(rcfile)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="adscan", add_help=True)
    parser.add_argument(
        "--version",
        action="store_true",
        help="Show launcher version and Docker image configuration.",
    )
    parser.add_argument(
        "--image",
        help="Override the ADscan Docker image (defaults to env ADSCAN_DOCKER_IMAGE or channel).",
        default=None,
    )
    parser.add_argument(
        "--channel",
        choices=["stable", "dev"],
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output (launcher + forwarded to container subcommands where applicable).",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output (launcher + forwarded to container subcommands where applicable).",
    )
    parser.add_argument(
        "--dev",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--bloodhound-stack-mode",
        choices=["managed"],
        default=None,
        help=(
            "BloodHound runtime mode. `managed` (default) starts ADscan's isolated compose stack."
        ),
    )

    sub = parser.add_subparsers(dest="command", required=False)

    install = sub.add_parser("install", help="Install ADscan (Docker mode)")
    install.add_argument(
        "--bloodhound-admin-password",
        default=DEFAULT_BLOODHOUND_ADMIN_PASSWORD,
        type=_parse_bloodhound_admin_password,
        help="Desired BloodHound CE admin password used during install.",
    )
    install.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not open the BloodHound browser automatically.",
    )
    install.add_argument(
        "--pull-timeout",
        type=int,
        default=3600,
        help="Docker pull timeout in seconds (0 disables). Default: 3600.",
    )
    install.add_argument(
        "--allow-low-memory",
        action="store_true",
        help=(
            "Allow install to continue when available RAM is critically low "
            "(below 1.0 GB). Use only for constrained environments."
        ),
    )

    check = sub.add_parser("check", help="Check Docker-mode prerequisites")
    check.add_argument(
        "--allow-low-memory",
        action="store_true",
        help=(
            "Allow checks to continue when available RAM is critically low "
            "(below 1.0 GB)."
        ),
    )

    start = sub.add_parser("start", help="Start ADscan interactive session")
    start.add_argument(
        "--pull-timeout",
        type=int,
        default=3600,
        help="Docker pull timeout in seconds when pulling the image (0 disables). Default: 3600.",
    )
    start.add_argument(
        "--allow-low-memory",
        action="store_true",
        help=(
            "Allow start to continue when available RAM is critically low "
            "(below 1.0 GB)."
        ),
    )

    ci = sub.add_parser("ci", help="Run `adscan ci` inside the container")
    ci.add_argument(
        "--pull-timeout",
        type=int,
        default=3600,
        help="Docker pull timeout in seconds when pulling the image (0 disables). Default: 3600.",
    )
    ci.add_argument(
        "--allow-low-memory",
        action="store_true",
        help=(
            "Allow CI preflight to continue when available RAM is critically low "
            "(below 1.0 GB). Place this before CI passthrough args."
        ),
    )
    ci.add_argument(
        "args",
        nargs=argparse.REMAINDER,
        help="Arguments passed to the container after `ci`",
    )

    upd = sub.add_parser(
        "update", help="Update the launcher (pip) and pull the latest ADscan image"
    )
    upd.add_argument(
        "--pull-timeout",
        type=int,
        default=3600,
        help="Docker pull timeout in seconds (0 disables). Default: 3600.",
    )

    upg = sub.add_parser("upgrade", help="Alias of update")
    upg.add_argument(
        "--pull-timeout",
        type=int,
        default=3600,
        help="Docker pull timeout in seconds (0 disables). Default: 3600.",
    )

    sub.add_parser("version", help="Show launcher version")

    # Internal-only command used by the host launcher to run the privileged
    # helper process required by container runtime features (e.g. BH compose up,
    # host clock sync). Hidden from end users.
    host_helper = sub.add_parser("host-helper", help=argparse.SUPPRESS)
    host_helper.add_argument(
        "--socket",
        required=True,
        help=argparse.SUPPRESS,
    )

    return parser


def _apply_image_overrides(args: argparse.Namespace) -> None:
    if getattr(args, "image", None):
        os.environ["ADSCAN_DOCKER_IMAGE"] = str(args.image)
    if getattr(args, "channel", None):
        os.environ["ADSCAN_DOCKER_CHANNEL"] = "dev" if args.channel == "dev" else ""
    if getattr(args, "dev", False):
        os.environ["ADSCAN_DOCKER_CHANNEL"] = "dev"


def _consume_trailing_global_flags(
    ns: argparse.Namespace, unknown: list[str]
) -> list[str]:
    """Consume global launcher flags that appear after a known subcommand.

    `argparse` only applies top-level options reliably when they are placed
    before the subcommand (e.g., `adscan --debug start`). Users often type
    `adscan start --debug`; for known launcher commands we normalize both forms.
    """
    cmd = str(getattr(ns, "command", "") or "")
    known_cmds = {"install", "check", "start", "ci", "update", "upgrade", "version"}
    low_memory_supported_cmds = {"install", "check", "start", "ci"}
    if cmd not in known_cmds:
        return unknown

    remaining: list[str] = []
    idx = 0
    while idx < len(unknown):
        token = unknown[idx]

        if token == "--verbose":
            setattr(ns, "verbose", True)
            idx += 1
            continue
        if token == "--debug":
            setattr(ns, "debug", True)
            idx += 1
            continue
        if token == "--dev":
            setattr(ns, "dev", True)
            idx += 1
            continue
        if token == "--allow-low-memory" and cmd in low_memory_supported_cmds:
            setattr(ns, "allow_low_memory", True)
            idx += 1
            continue
        if token.startswith("--image="):
            setattr(ns, "image", token.split("=", 1)[1])
            idx += 1
            continue
        if token == "--image" and idx + 1 < len(unknown):
            setattr(ns, "image", unknown[idx + 1])
            idx += 2
            continue
        if token.startswith("--channel="):
            setattr(ns, "channel", token.split("=", 1)[1])
            idx += 1
            continue
        if token == "--channel" and idx + 1 < len(unknown):
            setattr(ns, "channel", unknown[idx + 1])
            idx += 2
            continue
        if token.startswith("--bloodhound-stack-mode="):
            value = token.split("=", 1)[1]
            if str(value).strip().lower() != "managed":
                remaining.append(token)
                idx += 1
                continue
            setattr(ns, "bloodhound_stack_mode", value)
            idx += 1
            continue
        if token == "--bloodhound-stack-mode" and idx + 1 < len(unknown):
            value = unknown[idx + 1]
            if str(value).strip().lower() != "managed":
                remaining.extend([token, value])
                idx += 2
                continue
            setattr(ns, "bloodhound_stack_mode", value)
            idx += 2
            continue

        remaining.append(token)
        idx += 1

    return remaining


def _consume_ci_remainder_global_flags(ns: argparse.Namespace) -> None:
    """Consume launcher-global flags from `ci` remainder args.

    For `adscan ci`, argparse stores everything after `ci` in `ns.args`
    (`argparse.REMAINDER`), so trailing launcher flags (e.g. `--debug --dev`)
    never appear in `unknown`.

    If the remainder starts with `--`, treat it as an explicit passthrough
    separator and leave tokens untouched.
    """
    if str(getattr(ns, "command", "") or "") != "ci":
        return

    remainder = list(getattr(ns, "args", []) or [])
    if not remainder or remainder[0] == "--":
        return

    setattr(ns, "args", _consume_trailing_global_flags(ns, remainder))


def _should_print_debug_enabled_banner(command: str | None) -> bool:
    """Return whether launcher should emit the debug-enabled confirmation."""
    return command in (None, "start", "ci", "install", "check")


def _should_emit_system_context(command: str | None) -> bool:
    """Return whether launcher should emit system-context diagnostics."""
    return command in {"install", "start", "ci", "update", "upgrade"}


def _emit_launcher_privilege_context(command: str | None) -> None:
    """Emit launcher privilege/sudo context for troubleshooting."""
    try:
        is_root = os.geteuid() == 0
        has_sudo_user = bool(os.getenv("SUDO_USER"))
        has_sudo_uid = bool(os.getenv("SUDO_UID"))
        has_sudo_gid = bool(os.getenv("SUDO_GID"))
        has_adscan_home = bool(os.getenv("ADSCAN_HOME"))
        has_ci = bool(os.getenv("CI"))
        is_container_runtime = os.getenv("ADSCAN_CONTAINER_RUNTIME") == "1"
        is_sudo_invocation = has_sudo_user or has_sudo_uid or has_sudo_gid
        # Best-effort heuristic for root shells entered via `sudo su` / `su -`.
        # We avoid storing usernames/paths and only capture boolean context.
        likely_sudo_su_shell = (
            is_root
            and not is_sudo_invocation
            and not has_adscan_home
            and not has_ci
        )
        context = {
            "command_type": str(command or ""),
            "is_root": is_root,
            "is_low_priv_user": not is_root,
            "is_sudo_invocation": is_sudo_invocation,
            "likely_sudo_su_shell": likely_sudo_su_shell,
            "has_sudo_user": has_sudo_user,
            "has_sudo_uid": has_sudo_uid,
            "has_sudo_gid": has_sudo_gid,
            "has_adscan_home": has_adscan_home,
            "has_ci": has_ci,
            "is_container_runtime": is_container_runtime,
            "root_without_user_context": is_root
            and not is_sudo_invocation
            and not has_adscan_home,
        }
        print_info_debug(f"Launcher privilege context: {context}")
        capture("launcher_privilege_context", context)
    except Exception as exc:  # pragma: no cover - best effort only
        capture_exception(exc)


def _guard_root_shell_without_user_context(command: str | None) -> None:
    """Block accidental root-shell state split unless operator explicitly confirms.

    Running launcher commands from a root shell created via `sudo su` / `su -`
    commonly drops `SUDO_USER`, so launcher state can drift into `/root/.adscan`.
    """
    if command not in {"install", "start", "check"}:
        return
    if os.geteuid() != 0:
        return
    if os.getenv("CI"):
        return
    if os.getenv("SUDO_USER"):
        return
    if os.getenv("ADSCAN_HOME"):
        return

    message = (
        "ADscan launcher is running as root, but without SUDO_USER/ADSCAN_HOME context.\n\n"
        "This usually happens with `sudo su` or `su -` and can create state under `/root/.adscan`,\n"
        "causing later permission and consistency issues.\n\n"
        "Recommended:\n"
        "  1) Exit the root shell\n"
        "  2) Run ADscan as your normal user (without sudo)\n\n"
        "Advanced alternative:\n"
        "  Set ADSCAN_HOME explicitly before running as root."
    )
    print_panel(
        message,
        title="Root Shell Detected",
        border_style="yellow",
    )
    proceed = confirm_ask("Continue anyway (not recommended)?", default=False)
    if not proceed:
        print_warning("Aborted to avoid creating launcher state under /root.")
        raise SystemExit(1)


def _command_uses_bloodhound_stack(command: str | None) -> bool:
    """Return whether the launcher command depends on BloodHound stack state."""
    return command not in {"version", "update", "upgrade", "host-helper"}


def _is_noninteractive_session() -> bool:
    """Return True when launcher should avoid interactive prompts."""
    if os.getenv("ADSCAN_NONINTERACTIVE", "").strip() == "1":
        return True
    return not (sys.stdin.isatty() and sys.stdout.isatty())


def _resolve_bloodhound_stack_mode_with_legacy_detection(
    *,
    command: str | None,
    stack_mode: str,
    stack_mode_explicit: bool,
) -> str:
    """Resolve effective BloodHound stack mode with legacy-stack auto-detection."""
    if not _command_uses_bloodhound_stack(command):
        return stack_mode

    requested_mode = str(stack_mode or "").strip().lower()
    if requested_mode != "managed":
        print_warning(
            "BloodHound external mode is deprecated and ignored. "
            "ADscan always uses managed mode."
        )
        capture(
            "bloodhound_stack_mode_autoswitch",
            {
                "from_mode": requested_mode or "unknown",
                "to_mode": "managed",
                "reason": "external_mode_deprecated_forced_managed",
                "command": command or "",
            },
        )

    stack_mode = "managed"

    detection = detect_legacy_bloodhound_ce_running_stack()
    if not bool(detection.get("detected", False)):
        return stack_mode

    container_names = ", ".join(detection.get("container_names") or [])
    detected_ui_url = detection.get("ui_url")
    if isinstance(detected_ui_url, str):
        detected_ui_url = detected_ui_url.strip() or None
    else:
        detected_ui_url = None

    if stack_mode_explicit:
        print_info_debug(
            "[bloodhound-ce] managed mode explicitly requested; checking legacy "
            "containers for migration safety."
        )

    details = [
        "Detected an existing BloodHound CE installation already running on this host.",
        "ADscan always uses its managed isolated stack.",
        "To prevent port/resource conflicts, stop non-managed containers before continuing.",
        f"Running containers: {container_names or 'unknown'}",
    ]
    if detected_ui_url:
        details.append(f"Detected CE URL: {detected_ui_url}")
    print_panel(
        "\n".join(details),
        title="Existing BloodHound CE Detected",
        border_style="cyan",
    )

    if _is_noninteractive_session():
        print_info(
            "Non-interactive session detected. Continuing in managed mode and "
            "attempting to stop non-managed containers automatically."
        )
        stopped = stop_legacy_bloodhound_ce_stack()
        if not stopped:
            capture(
                "bloodhound_stack_mode_autoswitch",
                {
                    "from_mode": "managed",
                    "to_mode": "managed",
                    "reason": "legacy_stack_detected_noninteractive_stop_failed_blocked",
                    "command": command or "",
                },
            )
            print_error(
                "ADscan requires its managed BloodHound CE stack. "
                "Detected non-managed containers could not be stopped automatically."
            )
            detected_names = list(detection.get("container_names") or [])
            if detected_names:
                manual_stop = "docker stop " + " ".join(detected_names)
                print_instruction(
                    f"Stop them manually (`{manual_stop}`) and retry."
                )
            else:
                print_instruction(
                    "Stop non-managed BloodHound CE containers manually and retry."
                )
            raise SystemExit(1)
        capture(
            "bloodhound_stack_mode_autoswitch",
            {
                "from_mode": "managed",
                "to_mode": "managed",
                "reason": (
                    "legacy_stack_detected_noninteractive_stopped"
                    if stopped
                    else "legacy_stack_detected_noninteractive_stop_failed"
                ),
                "command": command or "",
            },
        )
        return "managed"

    stop_legacy_now = confirm_ask(
        "Stop detected non-managed BloodHound CE containers and continue in managed mode?",
        default=True,
    )
    if stop_legacy_now:
        if stop_legacy_bloodhound_ce_stack():
            print_success("Migration pre-step complete. Continuing with managed mode.")
            capture(
                "bloodhound_stack_mode_autoswitch",
                {
                    "from_mode": "managed",
                    "to_mode": "managed",
                    "reason": "legacy_stack_detected_migrated_to_managed",
                    "command": command or "",
                },
            )
            return "managed"
        print_error("Could not stop non-managed BloodHound CE containers automatically.")
        detected_names = list(detection.get("container_names") or [])
        if detected_names:
            manual_stop = "docker stop " + " ".join(detected_names)
            print_instruction(
                f"You can stop them manually (`{manual_stop}`) and retry managed mode."
            )
        else:
            print_instruction(
                "You can stop non-managed BloodHound CE containers manually and retry managed mode."
            )
        capture(
            "bloodhound_stack_mode_autoswitch",
            {
                "from_mode": "managed",
                "to_mode": "managed",
                "reason": "legacy_stack_detected_stop_failed_interactive_blocked",
                "command": command or "",
            },
        )
        raise SystemExit(1)

    print_error(
        "ADscan cannot continue while non-managed BloodHound CE containers are running."
    )
    detected_names = list(detection.get("container_names") or [])
    if detected_names:
        manual_stop = "docker stop " + " ".join(detected_names)
        print_instruction(
            f"Stop them manually (`{manual_stop}`) and retry."
        )
    else:
        print_instruction(
            "Stop non-managed BloodHound CE containers manually and retry."
        )
    capture(
        "bloodhound_stack_mode_autoswitch",
        {
            "from_mode": "managed",
            "to_mode": "managed",
            "reason": "legacy_stack_detected_user_declined_blocked",
            "command": command or "",
        },
    )
    raise SystemExit(1)


def _emit_launcher_system_context(command: str | None) -> None:
    """Emit non-sensitive host system context for telemetry diagnostics."""
    if not _should_emit_system_context(command):
        return
    try:
        system_context = collect_system_context()
        print_info_debug(f"System context: {system_context}")
        event_payload = dict(system_context)
        if command:
            event_payload["command_type"] = str(command)
        capture("telemetry_system_context", event_payload)
    except Exception as exc:  # pragma: no cover - best effort only
        capture_exception(exc)


def _seed_session_environment_from_host() -> None:
    """Seed ADSCAN_SESSION_ENV from host context when not explicitly overridden.

    This keeps container telemetry aligned with host classification (ci/dev/prod)
    and avoids relying on container-local environment heuristics.
    """
    if os.getenv("ADSCAN_ENV") or os.getenv("ADSCAN_SESSION_ENV"):
        return
    try:
        context = collect_system_context()
        environment = str(context.get("environment") or "").strip().lower()
        if environment:
            os.environ["ADSCAN_SESSION_ENV"] = environment
            print_info_debug(
                f"Seeded ADSCAN_SESSION_ENV from host context: {environment!r}"
            )
    except Exception as exc:  # pragma: no cover - best effort only
        capture_exception(exc)


def _seed_session_trace_id() -> None:
    """Seed ADSCAN_SESSION_TRACE_ID once per launcher invocation."""
    if os.getenv("ADSCAN_SESSION_TRACE_ID"):
        return
    try:
        trace_id = uuid.uuid4().hex
        os.environ["ADSCAN_SESSION_TRACE_ID"] = trace_id
        print_info_debug(f"Seeded ADSCAN_SESSION_TRACE_ID: {trace_id!r}")
    except Exception as exc:  # pragma: no cover - best effort only
        capture_exception(exc)


def _build_launcher_telemetry_console() -> Console:
    """Create a dedicated in-memory Rich console for session recording export."""
    return Console(record=True, theme=ADSCAN_THEME, file=StringIO())


def _capture_launcher_command_session(
    *,
    command_type: str,
    telemetry_console: Console,
    success: bool | None = None,
    extra: dict[str, Any] | None = None,
    allowed_commands: set[str] | None = None,
) -> None:
    """Capture host-side command session exactly once for launcher-owned commands."""
    global _SESSION_CAPTURE_FINALIZED
    if _SESSION_CAPTURE_FINALIZED:
        return

    capture_command_session(
        console=telemetry_console,
        command_type=command_type,
        success=success,
        extra=extra,
        allowed_commands=allowed_commands or set(HOST_SESSION_CAPTURE_COMMANDS),
    )
    _SESSION_CAPTURE_FINALIZED = True


def _run_host_command_with_session_capture(
    *,
    command_type: str,
    telemetry_console: Console,
    runner: Callable[[], bool | int],
    extra: dict[str, Any] | None = None,
    allowed_commands: set[str] | None = None,
) -> int:
    """Execute a launcher-owned command and always finalize session capture."""
    success = False
    try:
        result = runner()
        if isinstance(result, bool):
            success = bool(result)
            return 0 if success else 1
        exit_code = int(result)
        success = exit_code == 0
        return exit_code
    except KeyboardInterrupt:
        _log_launcher_interrupt(
            kind="keyboard_interrupt",
            source=f"launcher.host_command:{command_type}",
        )
        return 130
    except EOFError:
        _log_launcher_interrupt(
            kind="eof",
            source=f"launcher.host_command:{command_type}",
        )
        return 130
    finally:
        _capture_launcher_command_session(
            command_type=command_type,
            telemetry_console=telemetry_console,
            success=success,
            extra=extra,
            allowed_commands=allowed_commands,
        )


def _log_launcher_interrupt(*, kind: str, source: str) -> None:
    """Emit a standardized debug line for launcher interrupt events."""
    emit_interrupt_debug(kind=kind, source=source, print_debug=print_info_debug)


def _detect_installer_for_launcher() -> str:
    """Best-effort detection for whether `adscan` is installed via pipx or pip."""
    try:
        exe = os.path.realpath(sys.executable)
    except Exception:
        exe = str(sys.executable)
    lowered = exe.lower()
    if "/pipx/venvs/" in lowered or "pipx/venvs" in lowered:
        return "pipx"
    return "pip"


def _get_clean_env_for_launcher_update() -> dict[str, str]:
    """Return a conservative env dict for pip installs (best-effort)."""
    env = os.environ.copy()
    # Avoid surprising behavior when users have custom pythonpaths.
    env.pop("PYTHONPATH", None)
    return env


def _run_pip_install_with_break_system_packages_retry(
    *,
    python_executable: str,
    args: list[str],
    env: dict[str, str] | None,
    prefer_break_system_packages: bool,
) -> None:
    """Run pip install and retry with --break-system-packages when needed."""

    def _requires_break_system_packages(output: str) -> bool:
        """Return True when pip output indicates a PEP 668 managed env error."""
        normalized = (output or "").lower()
        # pip errors vary across distros/versions:
        # - "externally managed environment"
        # - "externally-managed-environment"
        return bool(
            re.search(r"externally[-\\s]+managed[-\\s]+environment", normalized)
        )

    base_cmd = [python_executable, "-m", "pip", "install"] + list(args)
    proc = subprocess.run(  # noqa: S603
        base_cmd, check=False, capture_output=True, text=True, env=env
    )
    if proc.returncode == 0:
        return

    combined = (proc.stderr or "") + "\n" + (proc.stdout or "")
    needs_break = _requires_break_system_packages(combined)
    if prefer_break_system_packages and needs_break:
        retry_cmd = base_cmd + ["--break-system-packages"]
        proc2 = subprocess.run(  # noqa: S603
            retry_cmd, check=False, capture_output=True, text=True, env=env
        )
        if proc2.returncode == 0:
            return
        combined = (proc2.stderr or "") + "\n" + (proc2.stdout or "")

    raise RuntimeError(f"pip install failed: {combined.strip()}")


def _build_update_context_for_launcher(
    *, docker_pull_timeout_seconds: int | None
) -> UpdateContext:
    """Build an UpdateContext suitable for the PyPI launcher distribution."""
    return UpdateContext(
        adscan_base_dir=str(get_state_dir()),
        docker_pull_timeout_seconds=docker_pull_timeout_seconds,
        get_installed_version=lambda: __version__,
        detect_installer=_detect_installer_for_launcher,
        get_clean_env_for_compilation=_get_clean_env_for_launcher_update,
        run_pip_install_with_optional_break_system_packages=_run_pip_install_with_break_system_packages_retry,
        mark_passthrough=lambda s: s,
        telemetry_capture_exception=lambda exc: capture_exception(exc),
        get_docker_image_name=get_docker_image_name,
        image_exists=image_exists,
        ensure_image_pulled=ensure_image_pulled,
        run_docker=run_docker,
        is_container_runtime=is_docker_env,
        sys_stdin_isatty=sys.stdin.isatty,
        os_getenv=os.getenv,
        print_info=print_info,
        print_info_debug=print_info_debug,
        print_warning=print_warning,
        print_instruction=print_instruction,
        print_error=print_error,
        print_success=print_success,
        print_panel=print_panel,
        confirm_ask=lambda prompt, default: confirm_ask(prompt, default),
    )


def main(argv: list[str] | None = None) -> None:
    global _SESSION_CAPTURE_FINALIZED
    _SESSION_CAPTURE_FINALIZED = False
    _cleanup_legacy_sudo_alias()

    raw_argv = list(sys.argv[1:] if argv is None else argv)
    parser = _build_parser()
    if not raw_argv:
        parser.print_help()
        raise SystemExit(0)

    ns, unknown = parser.parse_known_args(raw_argv)
    unknown = _consume_trailing_global_flags(ns, unknown)
    _consume_ci_remainder_global_flags(ns)
    known_cmds = {"install", "check", "start", "ci", "update", "upgrade", "version"}
    if getattr(ns, "command", None) in known_cmds and unknown:
        parser.error(f"unrecognized arguments: {' '.join(unknown)}")

    cmd = getattr(ns, "command", None)
    show_version = bool(getattr(ns, "version", False)) or cmd == "version"
    if cmd is None and not unknown and not show_version:
        parser.print_help()
        raise SystemExit(0)

    telemetry_console = _build_launcher_telemetry_console()
    set_output_config(
        verbose=bool(getattr(ns, "verbose", False)),
        debug=bool(getattr(ns, "debug", False)),
        telemetry_console=telemetry_console,
    )
    if bool(getattr(ns, "debug", False)) and _should_print_debug_enabled_banner(
        "version" if show_version else cmd
    ):
        print_success("Debug mode enabled")

    # Ensure runtime container telemetry can distinguish launcher vs runtime
    # version contexts.
    os.environ["ADSCAN_LAUNCHER_VERSION"] = str(__version__)

    _apply_image_overrides(ns)
    raw_stack_mode = getattr(ns, "bloodhound_stack_mode", None)
    stack_mode_explicit = (
        raw_stack_mode is not None and str(raw_stack_mode).strip() != ""
    )
    resolved_stack_mode = (
        str(raw_stack_mode).strip().lower()
        if raw_stack_mode is not None
        else DEFAULT_BLOODHOUND_STACK_MODE
    ) or DEFAULT_BLOODHOUND_STACK_MODE
    resolved_stack_mode = _resolve_bloodhound_stack_mode_with_legacy_detection(
        command=cmd,
        stack_mode=resolved_stack_mode,
        stack_mode_explicit=stack_mode_explicit,
    )

    if show_version:
        print_info(f"ADscan launcher: v{__version__}")
        img = get_docker_image_name()
        print_info(f"Docker image: {img}")
        raise SystemExit(0)

    if cmd == "host-helper":
        try:
            from adscan_launcher.host_privileged_helper import run_host_helper_server
        except Exception as exc:
            capture_exception(exc)
            print_error("Host helper is unavailable in this launcher build.")
            raise SystemExit(2) from exc
        raise SystemExit(run_host_helper_server(str(getattr(ns, "socket", ""))))

    _emit_launcher_privilege_context(cmd)
    _guard_root_shell_without_user_context(cmd)
    _seed_session_environment_from_host()
    _seed_session_trace_id()
    _emit_launcher_system_context(cmd)

    # Offer upgrades early for relevant subcommands (interactive only).
    cmd_for_update_offer = cmd or "start"
    pull_timeout_raw = getattr(ns, "pull_timeout", 3600)
    pull_timeout_norm = normalize_pull_timeout_seconds(int(pull_timeout_raw))
    try:
        offer_updates_for_command(
            _build_update_context_for_launcher(
                docker_pull_timeout_seconds=pull_timeout_norm
            ),
            cmd_for_update_offer,
        )
    except KeyboardInterrupt:
        _log_launcher_interrupt(
            kind="keyboard_interrupt",
            source="launcher.offer_updates",
        )
        raise SystemExit(130)
    except EOFError:
        _log_launcher_interrupt(
            kind="eof",
            source="launcher.offer_updates",
        )
        raise SystemExit(130)

    if cmd == "start":
        pull_timeout = getattr(ns, "pull_timeout", 3600)
        raise SystemExit(
            _run_host_command_with_session_capture(
                command_type="start",
                telemetry_console=telemetry_console,
                runner=lambda: handle_start_docker(
                    verbose=bool(getattr(ns, "verbose", False)),
                    debug=bool(getattr(ns, "debug", False)),
                    pull_timeout_seconds=int(pull_timeout),
                    bloodhound_stack_mode=resolved_stack_mode,
                    allow_low_memory=bool(getattr(ns, "allow_low_memory", False)),
                ),
                extra={"mode": "docker", "session_scope": "launcher_preflight"},
                allowed_commands=set(SESSION_CAPTURE_ALLOWED_COMMANDS),
            )
        )

    if cmd == "install":
        raise SystemExit(
            _run_host_command_with_session_capture(
                command_type="install",
                telemetry_console=telemetry_console,
                runner=lambda: handle_install_docker(
                    bloodhound_admin_password=str(ns.bloodhound_admin_password),
                    suppress_bloodhound_browser=bool(ns.no_browser),
                    pull_timeout_seconds=int(ns.pull_timeout),
                    bloodhound_stack_mode=resolved_stack_mode,
                    allow_low_memory=bool(getattr(ns, "allow_low_memory", False)),
                ),
                extra={"mode": "docker"},
            )
        )

    if cmd == "check":
        raise SystemExit(
            _run_host_command_with_session_capture(
                command_type="check",
                telemetry_console=telemetry_console,
                runner=lambda: handle_check_docker(
                    bloodhound_stack_mode=resolved_stack_mode,
                    allow_low_memory=bool(getattr(ns, "allow_low_memory", False)),
                ),
                extra={"mode": "docker"},
            )
        )

    if cmd in ("update", "upgrade"):
        pull_timeout_norm = normalize_pull_timeout_seconds(int(ns.pull_timeout))
        raise SystemExit(
            _run_host_command_with_session_capture(
                command_type=str(cmd),
                telemetry_console=telemetry_console,
                runner=lambda: run_update_command(
                    _build_update_context_for_launcher(
                        docker_pull_timeout_seconds=pull_timeout_norm
                    )
                ),
                extra={"mode": "docker"},
            )
        )

    if cmd == "ci":
        # Pass-through execution inside the container, but still do Docker-mode preflight.
        passthrough = list(getattr(ns, "args", []) or [])
        # argparse.REMAINDER keeps leading --, but may start with a "--" separator.
        if passthrough and passthrough[0] == "--":
            passthrough = passthrough[1:]
        raise SystemExit(
            _run_host_command_with_session_capture(
                command_type="ci",
                telemetry_console=telemetry_console,
                runner=lambda: run_adscan_passthrough_docker(
                    adscan_args=["ci"] + passthrough,
                    verbose=bool(getattr(ns, "verbose", False)),
                    debug=bool(getattr(ns, "debug", False)),
                    pull_timeout_seconds=int(ns.pull_timeout),
                    bloodhound_stack_mode=resolved_stack_mode,
                    allow_low_memory=bool(getattr(ns, "allow_low_memory", False)),
                ),
                extra={"mode": "docker", "session_scope": "launcher_preflight"},
                allowed_commands=set(SESSION_CAPTURE_ALLOWED_COMMANDS),
            )
        )

    # Anything else: pass through to the container.
    if cmd:
        adscan_args = [cmd] + unknown
    else:
        adscan_args = unknown

    if not adscan_args:
        print_error("No command provided.")
        print_instruction("Try: adscan --help")
        raise SystemExit(2)

    try:
        rc = run_adscan_passthrough_docker(
            adscan_args=adscan_args,
            verbose=bool(getattr(ns, "verbose", False)),
            debug=bool(getattr(ns, "debug", False)),
            pull_timeout_seconds=3600,
            bloodhound_stack_mode=resolved_stack_mode,
        )
    except KeyboardInterrupt:
        _log_launcher_interrupt(
            kind="keyboard_interrupt",
            source="launcher.generic_passthrough",
        )
        rc = 130
    except EOFError:
        _log_launcher_interrupt(
            kind="eof",
            source="launcher.generic_passthrough",
        )
        rc = 130
    raise SystemExit(rc)
