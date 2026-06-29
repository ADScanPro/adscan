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
from adscan_internal.cli.ci_events import emit_phase, emit_scan_plan
from adscan_internal.cli.session_preflight import (
    SessionPreflightConfig,
    SessionPreflightDeps,
    run_session_preflight,
)
from adscan_internal.workspaces import (
    create_workspace_dir,
    write_initial_workspace_variables,
)
from adscan_core.rich_output_collection import (
    PhaseChapter,
    SessionHeader,
    SessionLootCard,
    print_ci_autonomous_callout,
    print_phase_chapter,
    print_session_header,
    print_session_loot_card,
)

try:
    from adscan_internal.services.report_service import (
        ReportService,
        ReportGenerationConfig,
    )
except ImportError:  # pragma: no cover - public LITE repo excludes report generation
    ReportService = None  # type: ignore[assignment]
    ReportGenerationConfig = None  # type: ignore[assignment]


# Coarse CLI-only banner strip for `adscan ci`. ci.py orchestrates a few
# boundaries it can confidently identify in this file; the inner scan phases
# (enumeration, kerberos, ACL, collection, exploitation) live inside
# shell.do_start_auth / do_start_unauth.
#
# This list is purely cosmetic terminal text — it is NOT the machine-readable
# scan plan and feeds nothing the web consumes. The canonical plan (chapters →
# phases → subphases, with the stable ids the structured ``phase`` /
# ``scan_plan`` events and the web render) is the single source of truth in
# ``adscan_internal.services.scan_phases``; this banner is a deliberately
# coarser operator-facing wrapper around it.
_CI_PHASES: tuple[tuple[str, str], ...] = (
    ("Preflight", "DNS validation, connectivity, and credential sanity checks."),
    ("Reconnaissance", "Domain mapping, trust enumeration, and authentication."),
    ("Scan", "Users, groups, kerberoast, ACLs, BloodHound, and exploitation."),
    ("Reporting", "Compile findings, render report, and stage artefacts."),
    ("Loot", "Owned accounts, attack-path materialisation, and summary."),
)


def _chapter(number: int) -> PhaseChapter:
    """Build a PhaseChapter for the given 1-indexed phase number."""
    title, subtitle = _CI_PHASES[number - 1]
    return PhaseChapter(
        number=number,
        title=title,
        subtitle=subtitle,
        all_phases=tuple(name for name, _ in _CI_PHASES),
    )


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

    # Load the optional scan configuration (--scan-config). The launcher
    # bind-mounts the file read-only and points ADSCAN_SCAN_CONFIG at it; an
    # explicit ``args.scan_config`` (when the engine parser declares it) takes
    # precedence. Absent / empty = DEFAULT_SCAN_CONFIG = today's interactive
    # behavior, so the no-config path is byte-for-byte unchanged. The resolved
    # config is stored on the shell so the gated decision points (trust enum,
    # attack-path execution) consult one SSOT.
    from adscan_internal.services.scan_config import (
        DEFAULT_SCAN_CONFIG,
        ScanConfigError,
        load_scan_config,
    )

    scan_config_path = (
        getattr(args, "scan_config", None) or os.environ.get("ADSCAN_SCAN_CONFIG") or ""
    )
    try:
        shell.scan_config = load_scan_config(scan_config_path)
    except ScanConfigError as exc:
        telemetry.capture_exception(exc)
        print_error(f"Invalid scan configuration: {exc}")
        deps.exit(2)
        return 2
    if not shell.scan_config.is_default:
        print_info("Scan configuration applied from --scan-config.")
        print_info_verbose(
            "Scan config: "
            f"disabled_phases={list(shell.scan_config.phases.disabled)} "
            f"trust_policy={shell.scan_config.trust_enumeration.policy} "
            f"attack_path_policy={shell.scan_config.attack_paths.policy}"
        )
    else:
        # Keep the attribute present and well-typed even on the default path so
        # downstream getattr(shell, "scan_config", ...) always finds it.
        shell.scan_config = DEFAULT_SCAN_CONFIG

    # PRO partner-tag gate (non-interactive path): the env var ADSCAN_PARTNER_TAG
    # must satisfy it; otherwise refuse to start PRO rather than hang on stdin.
    # LITE is never gated. Placed after session_command_type="ci" so the
    # non-interactive predicate resolves correctly.
    from adscan_internal.cli.partner_tag_gate import ensure_partner_tag_for_pro

    if not ensure_partner_tag_for_pro(getattr(shell, "license_mode", None)):
        return 1

    shell.preflight_check_passed = bool(preflight_result.passed)
    shell.preflight_check_fix_attempted = bool(preflight_result.fix_attempted)
    shell.preflight_check_overridden = bool(preflight_result.overridden)
    shell.ensure_workspaces_dir()

    created_workspace = False
    if getattr(args, "workspace", None):
        ws_dir = os.path.join(shell.workspaces_dir, args.workspace)
        if not os.path.isdir(ws_dir):
            create_workspace_dir(shell.workspaces_dir, args.workspace)
            write_initial_workspace_variables(
                workspace_name=args.workspace,
                workspace_path=ws_dir,
                workspace_type=args.type,
            )
            created_workspace = True
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

    # --- Premium session header ---
    _ci_domain = str(getattr(args, "domain", "") or "")
    _ci_dc = str(getattr(args, "dc_ip", "") or "")
    _ci_user = str(getattr(args, "username", "") or "")
    _ci_cred = (
        f"{_ci_user} / {_ci_domain.upper()}" if _ci_user and _ci_domain else _ci_user
    )
    print_session_header(
        SessionHeader(
            workspace=str(shell.current_workspace or ""),
            target_domain=_ci_domain,
            dc_ip=_ci_dc,
            credential_label=_ci_cred,
            scan_mode="ci",
            experimental=True,
        )
    )
    # Premium one-shot callout that frames the autonomous flow + sets
    # operator expectations (BETA, defaults may shift, fallback paths).
    # Always shown — the cost of redundancy here is much lower than the
    # cost of an operator believing autonomous output equals supported
    # contract.
    print_ci_autonomous_callout()

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
    try:
        from adscan_internal.services.myip_staleness import check_and_refresh_myip

        check_and_refresh_myip(shell, context="ci_start")
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_verbose(
            "CI could not auto-configure myip from the selected interface: "
            f"{mark_sensitive(str(exc), 'detail')}"
        )
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
        # Declare the full ordered plan up-front so the web renders the
        # engine-declared chapters → phases → subphases dynamically.
        from adscan_internal.services.scan_phases import (
            COMMAND_AUDIT,
            COMMAND_CI_AUTH,
        )

        emit_scan_plan(
            COMMAND_AUDIT if shell.type == "audit" else COMMAND_CI_AUTH,
            getattr(shell, "scan_config", None),
        )
        # Chapter 1: Preflight (DNS validation, connectivity)
        print_phase_chapter(_chapter(1))
        emit_phase("dns_validation")
        if not shell.do_check_dns(args.domain, args.dc_ip):
            return False
        emit_phase("dns_configuration")
        shell.do_clear_all(None)
        shell.scan_mode = None
        # Chapter 2: Reconnaissance + Chapter 3: Scan are merged here because
        # the entire authenticated scan pipeline runs inside do_start_auth
        # without external phase boundaries we can hook from this file.
        print_phase_chapter(_chapter(2))
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
        # Declare the unauth plan up-front for the web renderer.
        from adscan_internal.services.scan_phases import COMMAND_CI_UNAUTH

        emit_scan_plan(COMMAND_CI_UNAUTH, getattr(shell, "scan_config", None))
        # Chapter 2: Reconnaissance — the unauth path is pure recon.
        print_phase_chapter(_chapter(2))
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
        # Chapter 4: Reporting
        print_phase_chapter(_chapter(4))
        emit_phase("report_generation")
        print_info("Generating report as requested...")
        if shell.current_workspace_dir:
            report_json_path = os.path.join(
                shell.current_workspace_dir, "technical_report.json"
            )
            report_format = "pdf"
            frameworks_raw = getattr(args, "frameworks", None)
            frameworks = (
                [f.strip() for f in frameworks_raw.split(",") if f.strip()]
                if frameworks_raw
                else None
            )
            report_file_path = _run_ci_report_generation(
                shell,
                args,
                report_json_path=report_json_path,
                report_format=report_format,
                frameworks=frameworks,
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

    # --- End-of-run loot card ---
    try:
        # Chapter 5: Loot — final act, the loot card is its centrepiece.
        print_phase_chapter(_chapter(5))
        _loot_domain = str(
            getattr(args, "domain", "") or getattr(shell, "current_domain", "") or ""
        )
        _domains_data = getattr(shell, "domains_data", {}) or {}
        _domain_info = _domains_data.get(_loot_domain, {}) or {}
        _owned = list(_domain_info.get("owned_accounts", []) or [])
        print_session_loot_card(
            SessionLootCard(
                domain=_loot_domain,
                owned_accounts=_owned,
            )
        )
    except Exception:  # noqa: BLE001
        pass  # loot card is cosmetic — never block exit

    shell.do_exit(exit=False)
    return exit_code


def run_generate_report(
    shell: object,
    report_file: str,
    report_format: str = "pdf",
    report_profile: str = "full",
    frameworks: Optional[list] = None,
    *,
    engine: str = "",
    renderer: str = "",
    template: str = "",
    theme: str = "",
    display_name: str = "",
) -> Optional[str]:
    """Generate a report from technical report JSON.

    Args:
        shell: Shell instance with license_mode and event_bus
        report_file: Path to technical_report.json
        report_format: Format to generate. Public CLI flows pass "pdf".
        report_profile: Report profile ("full", "technical", "executive")
        frameworks: Compliance frameworks. Valid values: "ens", "iso27001",
            "dora", "pci_dss". Defaults to ["ens"] (ENS Alto + NIS2).
        engine: PDF engine ("chromium" — the only supported engine). Empty = env/default.
        renderer: Attack-path renderer ("graphviz" | "cytoscape"). Empty = env/default.
        template: Report template ("legacy" | "premium"). Empty = env/default.
        theme: Report theme ("premium_dark" | "corporate_light" | ""). Empty = env/default.

    Returns:
        Path to generated report file, or None on failure
    """
    if ReportService is None or ReportGenerationConfig is None:
        # LITE — the PRO report service is stripped from the image. Render
        # the canonical PRO upsell panel instead of a flat error so the
        # operator sees the same CTA they would get from ``adscan deliver``
        # (host) or ``deliver`` (REPL). The panel surfaces ``adscan demo``
        # as the zero-risk preview path and ``adscanpro.com/pro`` as the
        # upgrade URL — single source of truth for the PRO ask.
        #
        # Note: ``do_generate_report`` in adscan.py gates earlier so the
        # operator never reaches this branch with prompts already
        # answered. This stays as the final safety net for non-REPL
        # callers (e.g. ``adscan ci`` invoking the report path directly).
        from adscan_core.pro_upsell import print_pro_upsell

        print_pro_upsell("generate_report", "direct_invocation")
        return None

    if not os.path.exists(report_file):
        print_error(f"Report file not found: {report_file}")
        return None

    report_format_lower = report_format.lower()
    if report_format_lower not in {"word", "pdf"}:
        print_error(f"Invalid format '{report_format}'. Valid formats: word, pdf")
        return None
    report_profile_lower = report_profile.lower()
    if report_profile_lower not in {"full", "technical", "executive", "sample"}:
        print_error(
            f"Invalid profile '{report_profile}'. "
            "Valid profiles: full, technical, executive, sample"
        )
        return None

    workspace_dir = Path(os.path.dirname(report_file)) if report_file else Path.cwd()

    report_path = Path(report_file)
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
        engine=engine,
        renderer=renderer,
        template=template,
        theme=theme,
        display_name=display_name,
    )

    result_path = report_service.generate_report(config)

    # Offer to open the freshly generated report. Auto-skipped in non-interactive
    # contexts (TTY check + ADSCAN_NONINTERACTIVE), so this is safe to call from
    # both the shell `generate_report` command and `adscan ci`.
    if result_path is not None:
        from adscan_internal.services.host_open import prompt_and_open

        result_path_obj = Path(result_path) if not isinstance(result_path, Path) else result_path
        if result_path_obj.is_file():
            prompt_and_open(result_path_obj, prompt="Open the report now?")

    return str(result_path) if result_path else None


def _run_ci_report_generation(
    shell: object,
    args: object,
    *,
    report_json_path: str,
    report_format: str,
    frameworks: Optional[list] = None,
) -> Optional[str]:
    """Route ``adscan ci --generate-report`` through the unified deliver engine.

    CI defaults to REPORT-ONLY (a single Security Assessment Report PDF) — the
    web runs ``adscan ci`` and then SEPARATELY dispatches the full kit via
    ``_maybe_dispatch_deliverable_kit``, so emitting a full kit inline here
    would double-generate. The deliverable selection grammar (``--only``) is the
    SAME one the deliver flow uses, so there is one selection vocabulary across
    the product:

    * Report-only (default, or ``--only report`` / ``--only executive``) → render
      the single PDF via :func:`run_generate_report`, preserving CI's single-PDF
      artifact contract (pipelines and the web expect the PDF at the existing
      report-service path).
    * A wider explicit ``--only`` (e.g. ``--only report,playbook``) → render that
      selection inline through the unified deliver engine, returning the headline
      Security Assessment Report PDF as the artifact path.

    Returns the path to the report PDF artifact, or ``None`` on failure.
    """
    from adscan_internal.cli.deliver import _parse_only

    raw_only = getattr(args, "only", None)
    try:
        selected = _parse_only(raw_only)
    except ValueError as exc:
        print_error(str(exc))
        return None
    selected_slugs = {item.slug for item in selected}

    # Report-only when the selection is exactly the assessment report (the
    # ``report``/``executive`` slug). This is the CI/web default and keeps the
    # single-PDF artifact contract untouched.
    if selected_slugs == {"executive"}:
        return run_generate_report(
            shell,
            report_json_path,
            report_format,
            frameworks=frameworks,
            engine=getattr(args, "report_engine", "") or "",
            renderer=getattr(args, "report_renderer", "") or "",
            template=getattr(args, "report_template", "") or "",
            theme=getattr(args, "report_theme", "") or "",
            display_name=getattr(args, "display_name", "") or "",
        )

    # Wider selection: render it inline via the unified deliver engine. The
    # headline Security Assessment Report PDF is returned as the artifact path so
    # the downstream single-PDF plumbing (artifact copy) still works.
    return _run_ci_deliver_selection(
        shell,
        args,
        report_json_path=report_json_path,
        frameworks=frameworks,
        only=raw_only,
    )


def _run_ci_deliver_selection(
    shell: object,
    args: object,
    *,
    report_json_path: str,
    frameworks: Optional[list],
    only: Optional[str],
) -> Optional[str]:
    """Render a multi-deliverable CI selection via the unified deliver engine.

    Builds the ``deliver`` argparse namespace from the CI flags and runs it
    synchronously, then returns the staged Security Assessment Report PDF (the
    headline artifact) so CI's single-PDF artifact plumbing still resolves.
    """
    import argparse as _argparse

    from adscan_internal.cli.deliver import run_deliver_sync as _run_deliver_sync

    workspace_dir = Path(report_json_path).parent
    fw_value = ",".join(frameworks) if frameworks else None
    ns = _argparse.Namespace(
        workspace=str(workspace_dir),
        client=getattr(args, "display_name", "") or None,
        engagement=None,
        output=None,
        only=only,
        no_navigator=False,
        frameworks=fw_value,
        theme="",
        report_theme=getattr(args, "report_theme", "") or "",
    )
    rc = _run_deliver_sync(ns)
    if rc != 0:
        return None
    headline = workspace_dir / "deliverables" / "staging" / "Security_Assessment_Report.pdf"
    return str(headline) if headline.is_file() else None
