"""Legacy CI command handler.

This module contains the orchestration logic for `adscan ci` (legacy mode).
It is intentionally decoupled from `adscan.py` by injecting the shell factory.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import re
import shutil
import uuid
from typing import Callable, Optional

from adscan_internal import (
    print_error,
    print_exception,
    print_info,
    print_info_verbose,
    print_success,
    print_warning,
    telemetry,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.cli.ci_events import emit_phase
from adscan_internal.cli.session_preflight import (
    SessionPreflightConfig,
    SessionPreflightDeps,
    run_session_preflight,
)

try:
    from adscan_internal.services.report_service import (
        ReportService,
        ReportGenerationConfig,
    )
except ImportError:  # pragma: no cover - public LITE repo excludes report generation
    ReportService = None  # type: ignore[assignment]
    ReportGenerationConfig = None  # type: ignore[assignment]


@dataclass(frozen=True)
class CiConfig:
    """Configuration for running the legacy CI flow."""

    args: object
    requested_pro: bool


@dataclass(frozen=True)
class CiDeps:
    """Dependency bundle for running CI."""

    enable_auto_mode: Callable[[], None]
    build_preflight_args: Callable[[], object]
    handle_check: Callable[[object], bool]
    get_last_check_extra: Callable[[], dict[str, object]]
    track_docs_link_shown: Callable[[str, str], None]
    resolve_license_mode: Callable[[bool], object]
    create_shell: Callable[[object, object], object]
    console: object
    exit: Callable[[int], None]


def run_ci(*, config: CiConfig, deps: CiDeps) -> int:
    """Run a non-interactive scan suitable for CI pipelines.

    Behaviour matches the original `handle_ci` implementation in `adscan.py`.
    """
    args = config.args

    deps.enable_auto_mode()
    preflight_result = run_session_preflight(
        config=SessionPreflightConfig(
            command_name="ci",
            docs_utm_medium="ci_preflight_failed",
            allow_unsafe_override=False,
        ),
        deps=SessionPreflightDeps(
            build_preflight_args=deps.build_preflight_args,
            handle_check=deps.handle_check,
            get_last_check_extra=deps.get_last_check_extra,
            track_docs_link_shown=deps.track_docs_link_shown,
            confirm_ask=lambda _prompt, _default: False,
            exit=deps.exit,
        ),
    )

    license_mode = deps.resolve_license_mode(config.requested_pro)
    shell = deps.create_shell(deps.console, license_mode)
    shell.session_command_type = "ci"
    shell.preflight_check_passed = bool(preflight_result.passed)
    shell.preflight_check_fix_attempted = bool(preflight_result.fix_attempted)
    shell.preflight_check_overridden = bool(preflight_result.overridden)
    shell.ensure_workspaces_dir()

    created_workspace = False
    if getattr(args, "workspace", None):
        ws_dir = os.path.join(shell.workspaces_dir, args.workspace)
        if not os.path.isdir(ws_dir):
            marked_workspace = mark_sensitive(args.workspace, "workspace")
            print_error(f"Workspace '{marked_workspace}' not found")
            return False
        shell.current_workspace = args.workspace
        shell.current_workspace_dir = ws_dir
        shell.load_workspace_data(ws_dir)
    else:
        ws = f"ci-{uuid.uuid4().hex[:6]}"
        ws_dir = os.path.join(shell.workspaces_dir, ws)
        os.makedirs(ws_dir, exist_ok=True)
        shell.current_workspace = ws
        shell.current_workspace_dir = ws_dir
        shell.load_workspace_data(ws_dir)
        created_workspace = True

    from adscan_internal.cli.common import build_telemetry_context

    telemetry_context = build_telemetry_context(shell=shell, trigger="ci_start")

    telemetry.set_cli_telemetry(shell.telemetry, context=telemetry_context)
    session_properties = {
        "$set": {"installation_status": "installed"},
        "mode": "ci",
        "scan_type": getattr(args, "type", None),
        "scan_mode": getattr(args, "mode", None),
        "preflight_check_passed": bool(preflight_result.passed),
        "preflight_check_fix_attempted": bool(preflight_result.fix_attempted),
        "preflight_check_overridden": bool(preflight_result.overridden),
        **telemetry_context,
    }
    telemetry.capture("session_start", properties=session_properties)

    shell.type = args.type
    shell.interface = args.interface
    shell.auto = True

    def _run_auto_auth() -> bool:
        required = [args.domain, args.dc_ip, args.username, args.password]
        if not all(required):
            print_error(
                "Auth mode requires --domain, --dc-ip, --username, and --password"
            )
            return False
        if not shell.type:
            print_error(
                "Pentest type (ctf/audit) must be configured using 'set type <value>' before starting a scan."
            )
            return False
        if not shell.interface:
            print_error(
                "Interface not found. Please configure it using 'set iface <value>'."
            )
            return False
        if shell.auto is None:
            print_error(
                "Auto mode not found. Please configure it using 'set auto <value>'."
            )
            return False
        emit_phase("dns_validation")
        if not shell.do_check_dns(args.domain, args.dc_ip):
            return False
        emit_phase("dns_configuration")
        shell.do_clear_all(None)
        shell.scan_mode = None
        shell.do_start_auth(
            f"{args.domain} {args.dc_ip} {args.username} {args.password}"
        )
        if getattr(shell, "scan_mode", None) != "auth":
            return False
        domain_data = shell.domains_data.get(args.domain)
        if not domain_data:
            print_warning("Authentication scan did not populate domain data.")
            return False
        username_key = args.username.lower()
        if username_key not in domain_data.get("credentials", {}):
            print_warning("Authenticated credential not stored; treating as failure.")
            return False
        return True

    def _run_auto_unauth() -> bool:
        if not args.hosts and not getattr(args, "dc_ip", None):
            print_error("Unauth mode requires --hosts or --dc-ip")
            return False
        if not shell.type:
            print_error(
                "Pentest type (ctf/audit) must be configured using 'set type <value>' before starting a scan."
            )
            return False
        if not shell.interface:
            print_error(
                "Interface not found. Please configure it using 'set iface <value>'."
            )
            return False
        if shell.auto is None:
            print_error(
                "Auto mode not found. Please configure it using 'set auto <value>'."
            )
            return False

        shell.hosts = args.hosts
        shell.do_clear_all(None)
        shell.scan_mode = None
        if getattr(args, "dc_ip", None):
            shell.do_start_unauth(str(args.dc_ip))
        else:
            shell.do_start_unauth(None)
        if getattr(shell, "scan_mode", None) != "unauth":
            return False
        if not shell.domains_data:
            print_warning(
                "Unauthenticated scan completed but did not discover any domains."
            )
            return False
        return True

    success = _run_auto_auth() if args.mode == "auth" else _run_auto_unauth()

    should_validate_flags = (
        success and str(getattr(shell, "type", "") or "").strip().lower() == "ctf"
    )
    flags_valid = not should_validate_flags
    if should_validate_flags and shell.current_workspace_dir:
        flags_dir = os.path.join(shell.current_workspace_dir, "flags")
        user_flag_path = os.path.join(flags_dir, "user.txt")
        root_flag_path = os.path.join(flags_dir, "root.txt")

        user_flag_exists = os.path.exists(user_flag_path)
        root_flag_exists = os.path.exists(root_flag_path)

        if user_flag_exists and root_flag_exists:
            flag_pattern = re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE)
            try:
                with open(user_flag_path, "r", encoding="utf-8") as file:
                    user_flag = file.read().strip()
                with open(root_flag_path, "r", encoding="utf-8") as file:
                    root_flag = file.read().strip()

                if flag_pattern.match(user_flag) and flag_pattern.match(root_flag):
                    flags_valid = True
                    print_success("Flags validation passed:")
                    print_success(f"   User flag: {user_flag}")
                    print_success(f"   Root flag: {root_flag}")
                else:
                    print_warning("Flags found but format is invalid:")
                    if not flag_pattern.match(user_flag):
                        print_warning(f"   User flag format invalid: {user_flag}")
                    if not flag_pattern.match(root_flag):
                        print_warning(f"   Root flag format invalid: {root_flag}")
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_error("Error reading flag files.")
                print_exception(show_locals=False, exception=exc)
        else:
            missing = []
            if not user_flag_exists:
                missing.append("user.txt")
            if not root_flag_exists:
                missing.append("root.txt")
            print_warning(f"Flag files not found: {', '.join(missing)}")

    report_file_path = None
    if success and flags_valid and getattr(args, "generate_report", False):
        emit_phase("report_generation")
        print_info("Generating report as requested...")
        if shell.current_workspace_dir:
            report_json_path = os.path.join(shell.current_workspace_dir, "report.json")
            report_format = getattr(args, "report_format", "word")
            report_file_path = run_generate_report(
                shell, report_json_path, report_format
            )
            if not report_file_path:
                print_warning("Report generation failed")
        else:
            print_warning("Workspace directory not available, cannot generate report")

    if success and flags_valid and should_validate_flags:
        print_success("CI scan finished successfully with flags validated.")
        exit_code = 0
    elif success and not flags_valid and should_validate_flags:
        print_error("CI scan completed but flags validation failed.")
        exit_code = 2
    elif success:
        print_success("CI scan finished successfully.")
        exit_code = 0
    else:
        print_error("CI scan failed. Check the logs above for details.")
        exit_code = 1

    artifact_report_path = None
    if report_file_path and os.path.exists(report_file_path):
        print_success(f"Report generated successfully: {report_file_path}")
        if os.environ.get("GITHUB_ACTIONS") == "true":
            artifacts_dir = os.path.join(os.getcwd(), "artifacts")
            os.makedirs(artifacts_dir, exist_ok=True)
            artifact_report_path = os.path.join(
                artifacts_dir, os.path.basename(report_file_path)
            )
            try:
                shutil.copy2(report_file_path, artifact_report_path)
                print_info(
                    f"Report copied to artifacts directory: {artifact_report_path}"
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_warning(f"Failed to copy report to artifacts directory: {exc}")

    if created_workspace and not getattr(args, "keep_workspace", False):
        try:
            shutil.rmtree(shell.current_workspace_dir)
            marked_current_workspace_1 = mark_sensitive(
                shell.current_workspace, "workspace"
            )
            print_success(f"Workspace '{marked_current_workspace_1}' deleted")
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            marked_current_workspace_1 = mark_sensitive(
                shell.current_workspace, "workspace"
            )
            print_error("Failed to remove workspace '{marked_current_workspace_1}'.")
            print_exception(show_locals=False, exception=exc)
    elif created_workspace and getattr(args, "keep_workspace", False):
        marked_current_workspace_1 = mark_sensitive(
            shell.current_workspace, "workspace"
        )
        print_info(
            f"Workspace '{marked_current_workspace_1}' kept (--keep-workspace specified)"
        )

    shell.do_exit(exit=False)
    return exit_code


def run_generate_report(
    shell: object,
    report_file: str,
    report_format: str = "word",
    report_profile: str = "full",
    frameworks: Optional[list] = None,
) -> Optional[str]:
    """Generate a Word or PDF report from JSON report file.

    Args:
        shell: Shell instance with license_mode and event_bus
        report_file: Path to JSON report file
        report_format: Format to generate ("word" or "pdf")
        report_profile: Report profile ("full", "technical", "executive")
        frameworks: Compliance frameworks to include. Valid values: "ens",
            "iso27001", "dora". Defaults to ["ens"] (ENS Alto + NIS2).

    Returns:
        Path to generated report file, or None on failure
    """
    if ReportService is None or ReportGenerationConfig is None:
        print_error("Report generation module is not available.")
        return None

    if not os.path.exists(report_file):
        print_error(f"Report file not found: {report_file}")
        return None

    report_format_lower = report_format.lower()
    if report_format_lower not in {"word", "pdf"}:
        print_error(f"Invalid format '{report_format}'. Valid formats: word, pdf")
        return None
    report_profile_lower = report_profile.lower()
    if report_profile_lower not in {"full", "technical", "executive"}:
        print_error(
            f"Invalid profile '{report_profile}'. Valid profiles: full, technical, executive"
        )
        return None

    workspace_dir = Path(os.path.dirname(report_file)) if report_file else Path.cwd()

    # Prefer technical_report.json when available (attack paths + findings).
    technical_report = workspace_dir / "technical_report.json"
    report_path = Path(report_file)
    if technical_report.exists():
        report_path = technical_report
        print_info_verbose(
            f"Using technical report source: {mark_sensitive(str(report_path), 'path')}"
        )

    report_service = ReportService(
        event_bus=getattr(shell, "event_bus", None),
        license_mode=getattr(shell, "license_mode", None),
    )

    config = ReportGenerationConfig(
        report_file=report_path,
        format=report_format_lower,
        profile=report_profile_lower,
        workspace_dir=workspace_dir,
        frameworks=frameworks,
    )

    result_path = report_service.generate_report(config)
    return str(result_path) if result_path else None
