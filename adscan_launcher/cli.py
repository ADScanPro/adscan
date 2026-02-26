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
import os
import subprocess
import sys
from pathlib import Path

from adscan_launcher import __version__
from adscan_launcher.docker_commands import (
    DEFAULT_BLOODHOUND_ADMIN_PASSWORD,
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
from adscan_launcher.telemetry import capture_exception
from adscan_launcher.update_manager import (
    UpdateContext,
    offer_updates_for_command,
    run_update_command,
)


ADSCAN_SUDO_ALIAS_MARKER = "# ADscan auto-sudo alias"


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
        help="Shortcut to select the stable/dev image channel (overrides env ADSCAN_DOCKER_CHANNEL).",
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
        help="Use the development Docker image channel.",
    )

    sub = parser.add_subparsers(dest="command", required=False)

    install = sub.add_parser("install", help="Install ADscan (Docker mode)")
    install.add_argument(
        "--bloodhound-admin-password",
        default=DEFAULT_BLOODHOUND_ADMIN_PASSWORD,
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

    sub.add_parser("check", help="Check Docker-mode prerequisites")

    start = sub.add_parser("start", help="Start ADscan interactive session")
    start.add_argument(
        "--pull-timeout",
        type=int,
        default=3600,
        help="Docker pull timeout in seconds when pulling the image (0 disables). Default: 3600.",
    )

    ci = sub.add_parser("ci", help="Run `adscan ci` inside the container")
    ci.add_argument(
        "--pull-timeout",
        type=int,
        default=3600,
        help="Docker pull timeout in seconds when pulling the image (0 disables). Default: 3600.",
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

        remaining.append(token)
        idx += 1

    return remaining


def _should_print_debug_enabled_banner(command: str | None) -> bool:
    """Return whether launcher should emit the debug-enabled confirmation."""
    return command in (None, "start", "ci", "install", "check")


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
    base_cmd = [python_executable, "-m", "pip", "install"] + list(args)
    proc = subprocess.run(  # noqa: S603
        base_cmd, check=False, capture_output=True, text=True, env=env
    )
    if proc.returncode == 0:
        return

    combined = (proc.stderr or "") + "\n" + (proc.stdout or "")
    needs_break = "externally managed environment" in combined.lower()
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
    _cleanup_legacy_sudo_alias()

    raw_argv = list(sys.argv[1:] if argv is None else argv)
    parser = _build_parser()
    if not raw_argv:
        parser.print_help()
        raise SystemExit(0)

    ns, unknown = parser.parse_known_args(raw_argv)
    unknown = _consume_trailing_global_flags(ns, unknown)
    known_cmds = {"install", "check", "start", "ci", "update", "upgrade", "version"}
    if getattr(ns, "command", None) in known_cmds and unknown:
        parser.error(f"unrecognized arguments: {' '.join(unknown)}")

    cmd = getattr(ns, "command", None)
    show_version = bool(getattr(ns, "version", False)) or cmd == "version"
    if cmd is None and not unknown and not show_version:
        parser.print_help()
        raise SystemExit(0)

    set_output_config(
        verbose=bool(getattr(ns, "verbose", False)),
        debug=bool(getattr(ns, "debug", False)),
    )
    if bool(getattr(ns, "debug", False)) and _should_print_debug_enabled_banner(
        "version" if show_version else cmd
    ):
        print_success("Debug mode enabled")
    _apply_image_overrides(ns)

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

    # Offer upgrades early for relevant subcommands (interactive only).
    cmd_for_update_offer = cmd or "start"
    pull_timeout_raw = getattr(ns, "pull_timeout", 3600)
    pull_timeout_norm = normalize_pull_timeout_seconds(int(pull_timeout_raw))
    offer_updates_for_command(
        _build_update_context_for_launcher(
            docker_pull_timeout_seconds=pull_timeout_norm
        ),
        cmd_for_update_offer,
    )

    if cmd == "start":
        pull_timeout = getattr(ns, "pull_timeout", 3600)
        rc = handle_start_docker(
            verbose=bool(getattr(ns, "verbose", False)),
            debug=bool(getattr(ns, "debug", False)),
            pull_timeout_seconds=int(pull_timeout),
        )
        raise SystemExit(rc)

    if cmd == "install":
        ok = handle_install_docker(
            bloodhound_admin_password=str(ns.bloodhound_admin_password),
            suppress_bloodhound_browser=bool(ns.no_browser),
            pull_timeout_seconds=int(ns.pull_timeout),
        )
        raise SystemExit(0 if ok else 1)

    if cmd == "check":
        ok = handle_check_docker()
        raise SystemExit(0 if ok else 1)

    if cmd in ("update", "upgrade"):
        pull_timeout_norm = normalize_pull_timeout_seconds(int(ns.pull_timeout))
        ok = run_update_command(
            _build_update_context_for_launcher(
                docker_pull_timeout_seconds=pull_timeout_norm
            )
        )
        raise SystemExit(0 if ok else 1)

    if cmd == "ci":
        # Pass-through execution inside the container, but still do Docker-mode preflight.
        passthrough = list(getattr(ns, "args", []) or [])
        # argparse.REMAINDER keeps leading --, but may start with a "--" separator.
        if passthrough and passthrough[0] == "--":
            passthrough = passthrough[1:]
        rc = run_adscan_passthrough_docker(
            adscan_args=["ci"] + passthrough,
            verbose=bool(getattr(ns, "verbose", False)),
            debug=bool(getattr(ns, "debug", False)),
            pull_timeout_seconds=int(ns.pull_timeout),
        )
        raise SystemExit(rc)

    # Anything else: pass through to the container.
    if cmd:
        adscan_args = [cmd] + unknown
    else:
        adscan_args = unknown

    if not adscan_args:
        print_error("No command provided.")
        print_instruction("Try: adscan --help")
        raise SystemExit(2)

    rc = run_adscan_passthrough_docker(
        adscan_args=adscan_args,
        verbose=bool(getattr(ns, "verbose", False)),
        debug=bool(getattr(ns, "debug", False)),
        pull_timeout_seconds=3600,
    )
    raise SystemExit(rc)
