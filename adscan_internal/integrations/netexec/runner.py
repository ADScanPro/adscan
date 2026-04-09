from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import shlex
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from adscan_internal import (
    print_error,
    print_error_verbose,
    print_info,
    print_info_debug,
    print_instruction,
    print_panel,
    print_warning,
    print_warning_debug,
    print_warning_verbose,
    telemetry,
)
from adscan_internal.command_runner import (
    CommandRunner,
    CommandSpec,
    build_execution_output_preview,
    summarize_execution_result,
)
from adscan_internal.execution_outcomes import build_timeout_completed_process
from adscan_internal.execution_outcomes import (
    build_ldap_exact_connection_timeout_completed_process,
    output_has_exact_ldap_connection_timeout,
    result_is_timeout,
)
from adscan_internal.integrations.auth_policy import (
    build_netexec_kerberos_command,
    build_netexec_ntlm_command,
    netexec_can_use_kerberos,
    output_indicates_kerberos_auth_failure,
    output_indicates_kerberos_invalid_credentials,
    output_indicates_ntlm_disabled,
    resolve_netexec_auth_policy_decision,
)
from adscan_internal.integrations.netexec.parsers import (
    parse_netexec_delegated_auth_failure,
)
from adscan_internal.integrations.netexec.timeouts import (
    resolve_extended_timeout_seconds,
)
from adscan_internal.rich_output import mark_sensitive, strip_sensitive_markers
from adscan_internal.reporting_compat import load_optional_report_service_attr
from adscan_internal.subprocess_env import (
    command_string_needs_clean_env,
    get_clean_env_for_compilation,
)
from adscan_internal.text_utils import normalize_cli_output
from adscan_internal.services.auth_posture_service import (
    record_ntlm_disabled_signal,
    record_ntlm_enabled_signal,
)

ExecutionResult = subprocess.CompletedProcess[str]

_NETEXEC_SERVICE_TOKENS = {
    "smb",
    "ldap",
    "mssql",
    "rdp",
    "winrm",
    "ssh",
    "vnc",
    "ftp",
    "http",
    "https",
}


def _is_netexec_autoquote_enabled() -> bool:
    """Return whether NetExec path-like argument auto-quoting is enabled."""
    value = os.getenv("ADSCAN_NETEXEC_AUTOQUOTE", "1").strip().lower()
    return value not in {"0", "false", "no", "off"}


def _notify_ntlm_disabled_prioritize_kerberos(
    *,
    domain: str | None,
    protocol: str | None,
    source: str,
) -> None:
    """Render one-time UX notice when NTLM appears disabled for one domain."""
    marked_domain = mark_sensitive(str(domain or "unknown"), "domain")
    protocol_label = str(protocol or "domain services").upper()
    print_panel(
        (
            f"ADscan detected that NTLM appears disabled or unsupported for {marked_domain}.\n\n"
            f"Evidence source: {source}\n"
            f"Protocol scope: {protocol_label}\n\n"
            "From this point on, ADscan will prioritize Kerberos for compatible authenticated "
            "operations in this domain and only fall back when necessary."
        ),
        title="Authentication Posture Updated",
        border_style="cyan",
        expand=False,
    )
    print_info(
        "Authentication posture updated: "
        f"{marked_domain} will now prefer Kerberos for compatible authenticated operations."
    )


def _log_netexec_attempt_result(proc: subprocess.CompletedProcess[str]) -> None:
    """Emit concise execution summary and output preview for one attempt.

    This must run before auth-mode fallback breaks so operators can inspect the
    failed Kerberos or NTLM attempt that triggered the retry.
    """
    try:
        exit_code, stdout_count, stderr_count, duration_text = summarize_execution_result(
            proc
        )
        print_info_debug(
            "[netexec] Result: "
            f"exit_code={exit_code}, "
            f"stdout_lines={stdout_count}, "
            f"stderr_lines={stderr_count}, "
            f"duration={duration_text}"
        )
        preview_text = build_execution_output_preview(
            proc,
            stdout_head=20,
            stdout_tail=20,
            stderr_head=20,
            stderr_tail=20,
        )
        if preview_text:
            print_info_debug("[netexec] Output preview:\n" + preview_text, panel=True)
    except Exception:
        # Never let logging failures affect command flow.
        pass


def _sync_ntlm_control_evidence(
    state_owner: Any,
    *,
    domain: str | None,
    protocol: str | None,
    status: str,
    source: str,
    message: str | None = None,
) -> None:
    """Persist positive/neutral NTLM posture evidence to technical_report.json."""
    domain_name = str(domain or "").strip()
    if not domain_name:
        return

    record_control_evidence = load_optional_report_service_attr(
        "record_control_evidence",
        action="Control evidence sync",
        debug_printer=print_info_debug,
        prefix="[auth-posture]",
    )
    if not callable(record_control_evidence):
        return

    try:
        record_control_evidence(
            state_owner,
            domain_name,
            key="ntlm_likely_disabled",
            title="NTLM Likely Disabled or Unsupported",
            category="Authentication Posture",
            status=status,
            details={
                "confidence": "heuristic",
                "source": source,
                "protocol": str(protocol or "").strip().lower() or None,
                "message": str(message or "").strip()[:500] or None,
            },
        )
    except Exception as exc:  # pragma: no cover - best effort sync
        telemetry.capture_exception(exc)
        print_info_debug(f"[auth-posture] Failed to sync NTLM control evidence: {exc}")


def _quote_path_like_netexec_args(command: str) -> str:
    """Quote known NetExec file path args when they arrive unquoted.

    Some callers still build command strings manually. If an absolute path with
    spaces is passed to flags like ``--asreproast`` or ``--log`` without quotes,
    shell splitting breaks the command. This helper normalizes those flag values
    before execution while preserving already-quoted values.
    """

    def _quote_flag_value(cmd: str, flag: str) -> str:
        pattern = re.compile(
            rf"({re.escape(flag)}\s+)"
            r"(?P<value>(?:\"[^\"]*\"|'[^']*'|[^|]+?))"
            r"(?=(?:\s--[A-Za-z0-9][A-Za-z0-9-]*|\s-[A-Za-z0-9](?=\s|$)|\s\|\||\s&&|\s[|;]|\s\d?>>?|\s>>?|\s\||$))"
        )

        def _replace(match: re.Match[str]) -> str:
            value = match.group("value").strip()
            if value.startswith(("'", '"')):
                return f"{match.group(1)}{value}"
            return f"{match.group(1)}{shlex.quote(value)}"

        return pattern.sub(_replace, cmd)

    normalized = command
    for flag in ("--asreproast", "--log"):
        normalized = _quote_flag_value(normalized, flag)
    return normalized


def _extract_service_from_command(command: str) -> str | None:
    """Return the NetExec service token from one command."""

    try:
        argv = shlex.split(str(command or ""))
    except ValueError:
        return None
    return next((token for token in argv if token in _NETEXEC_SERVICE_TOKENS), None)


def _infer_target_count_from_command(command: str) -> int:
    """Best-effort target count inference for one NetExec command."""

    try:
        argv = shlex.split(str(command or ""))
    except ValueError:
        return 1

    service_index = next(
        (idx for idx, token in enumerate(argv) if token in _NETEXEC_SERVICE_TOKENS),
        None,
    )
    if service_index is None or service_index + 1 >= len(argv):
        return 1

    target_value = str(argv[service_index + 1]).strip()
    if not target_value:
        return 1
    target_path = Path(os.path.expanduser(target_value))
    if not target_path.is_file():
        return 1

    try:
        with target_path.open("r", encoding="utf-8", errors="replace") as handle:
            count = sum(1 for line in handle if line.strip())
    except OSError:
        return 1
    return max(count, 1)


@dataclass(frozen=True)
class NetExecContext:
    """Dependencies required to run NetExec commands safely.

    The NetExec runner is designed to be usable from both the CLI orchestration
    (adscan.py) and future service layers without re-implementing fragile retry
    logic or coupling to the giant adscan module.

    All callables should be side-effect free except where explicitly intended
    (clock sync and workspace cleanup).
    """

    state_owner: Any
    default_domain: str | None
    extract_domain: Callable[[str], str | None]
    is_domain_configured: Callable[[str], bool]
    sync_clock_with_pdc: Callable[[str], bool]
    detect_output_redirection: Callable[[str], tuple[bool, str | Path | None]]
    redirected_file_has_content: Callable[[str | Path], bool]
    clean_workspaces: Callable[[bool], bool]
    get_workspaces_dir: Callable[[], str | Path]
    confirm_ask: Callable[[str, bool], bool]


class NetExecRunner:
    """Run NetExec (nxc) commands with bounded retries and common fixes."""

    def __init__(self, *, command_runner: CommandRunner) -> None:
        self._command_runner = command_runner

    @staticmethod
    def _print_delegated_smb_status_more_processing_required_guidance(
        *,
        command: str,
        failure_line: str,
    ) -> None:
        """Render operator guidance for delegated SMB STATUS_MORE_PROCESSING_REQUIRED."""
        print_warning(
            "NetExec delegated SMB authentication hit "
            "`STATUS_MORE_PROCESSING_REQUIRED`, which ADscan treats as a known "
            "NetExec/Impacket client-side failure mode for this path."
        )
        print_panel(
            (
                "The delegated SMB session did not complete cleanly, so ADscan "
                "cannot trust this command result.\n\n"
                f"NetExec output: {failure_line}\n\n"
                "Current guidance:\n"
                "- There is no reliable client-side fix in ADscan for this "
                "specific delegated SMB handshake failure.\n"
                "- In CTF/lab environments, rebooting or resetting the target "
                "machine is the only known practical workaround before retrying.\n"
                "- If reset is not possible, use another follow-up route instead "
                "of retrying the same delegated SMB path."
            ),
            title="Delegated SMB Command Blocked",
            border_style="yellow",
            expand=False,
        )
        print_info_debug(
            "[netexec] delegated SMB command degraded to failure due to "
            f"STATUS_MORE_PROCESSING_REQUIRED: {command}"
        )

    def run(
        self,
        command: str,
        *,
        ctx: NetExecContext,
        domain: str | None = None,
        timeout: int | None = None,
        pre_sync: bool = True,
        operation_kind: str | None = None,
        service: str | None = None,
        target_count: int | None = None,
        allow_timeout_recovery: bool = True,
        **kwargs: object,
    ) -> ExecutionResult | None:
        """Run a NetExec command, applying automatic recovery steps.

        Args:
            command: Full NetExec command string to execute.
            ctx: Execution context providing callbacks and state.
            domain: Optional domain name used for clock synchronization. If not
                provided, will attempt to extract from command or use the default.
            timeout: Optional timeout in seconds for the NetExec command.
            pre_sync: When True, attempts clock synchronization with the PDC before
                running the command (only when the domain is configured).
            **kwargs: Extra arguments forwarded to the underlying command runner.

        Returns:
            A completed process, or None if execution failed before producing a result.
        """
        # Never pass invisible sensitive markers to external binaries.
        command = strip_sensitive_markers(command)
        if _is_netexec_autoquote_enabled():
            command = _quote_path_like_netexec_args(command)
        else:
            print_info_debug(
                "[netexec] Auto-quoting disabled by ADSCAN_NETEXEC_AUTOQUOTE."
            )

        # Log the NetExec command about to be executed (sanitized).
        try:
            print_info_debug(f"[netexec] Running command: {command}")
        except Exception:
            # Logging should never break execution flow
            pass

        effective_domain = domain or ctx.extract_domain(command) or ctx.default_domain
        current_timeout = timeout
        effective_service = str(service or _extract_service_from_command(command) or "").strip().lower() or None
        effective_target_count = max(
            int(target_count or _infer_target_count_from_command(command) or 1),
            1,
        )
        timeout_recovery_attempts = 0
        max_timeout_recovery_attempts = 2

        print_info_debug(
            "[netexec] timeout context: "
            f"operation_kind={operation_kind or 'default'} "
            f"service={effective_service or 'unknown'} "
            f"target_count={effective_target_count} "
            f"global_timeout={current_timeout if current_timeout is not None else 'disabled'} "
            f"allow_timeout_recovery={allow_timeout_recovery!r}"
        )

        if pre_sync and effective_domain:
            should_sync = True
            try:
                ipaddress.ip_address(str(effective_domain))
                should_sync = False
            except Exception:
                pass

            if should_sync and not ctx.is_domain_configured(str(effective_domain)):
                should_sync = False

            if should_sync:
                ctx.sync_clock_with_pdc(str(effective_domain))
            else:
                try:
                    marked_value = mark_sensitive(str(effective_domain), "domain")
                    print_info_debug(
                        f"[netexec] Skipping pre-sync clock: domain {marked_value} "
                        "is not configured or is an IP."
                    )
                except Exception:
                    pass

        def _execute_command_internal(cmd: str) -> ExecutionResult | None:
            local_kwargs = dict(kwargs)

            ignore_errors_flag = bool(local_kwargs.pop("ignore_errors", False))

            use_clean_env = local_kwargs.pop("use_clean_env", None)
            if use_clean_env is None:
                use_clean_env = command_string_needs_clean_env(cmd)

            cmd_env = local_kwargs.pop("env", None)
            if use_clean_env and cmd_env is None:
                cmd_env = get_clean_env_for_compilation()

            try:
                spec = CommandSpec(
                    command=cmd,
                    timeout=current_timeout
                    if current_timeout is not None
                    else local_kwargs.pop("timeout", None),
                    shell=bool(local_kwargs.pop("shell", True)),
                    capture_output=bool(local_kwargs.pop("capture_output", True)),
                    text=bool(local_kwargs.pop("text", True)),
                    check=bool(local_kwargs.pop("check", False)),
                    env=cmd_env,
                    cwd=local_kwargs.pop("cwd", None),
                    extra=local_kwargs or None,
                )
                result = self._command_runner.run(spec)
                if result is None:
                    print_warning_verbose(
                        f"Command runner returned None for command: {cmd}"
                    )
                return result
            except subprocess.TimeoutExpired as exc:
                if not ignore_errors_flag:
                    telemetry.capture_exception(exc)
                    print_warning(
                        "NetExec command timed out before producing output. "
                        "This usually indicates connectivity instability."
                    )
                    print_instruction(
                        "Verify VPN/network connectivity to the target and retry."
                    )
                return build_timeout_completed_process(cmd, tool_name="netexec")
            except Exception as exc:
                if not ignore_errors_flag:
                    telemetry.capture_exception(exc)
                    print_error_verbose(f"Error executing command: {cmd} - {exc}")
                return None

        max_retries = 3
        current_command = command
        command_started_with_kerberos = " -k " in f" {command} "
        max_clock_skew_sync_attempts = 3
        clock_skew_sync_attempts = 0
        schema_mismatch_cleanup_attempts = 0
        max_schema_mismatch_cleanup_attempts = 2

        def _is_ldap_command(cmd: str) -> bool:
            try:
                argv = shlex.split(cmd)
            except ValueError:
                return " ldap " in f" {cmd} "
            return "ldap" in argv

        def _has_connection_reset_by_peer(output: str) -> bool:
            return "CONNECTION RESET BY PEER" in output.upper()

        def _resolve_domain_info(known_domain: str | None) -> dict[str, object]:
            domains_data = getattr(ctx.state_owner, "domains_data", {}) or {}
            if not isinstance(domains_data, dict) or not known_domain:
                return {}

            normalized = str(known_domain).strip().casefold()
            if not normalized:
                return {}

            for domain_key, domain_info in domains_data.items():
                if str(domain_key).strip().casefold() != normalized:
                    continue
                if isinstance(domain_info, dict):
                    return domain_info
                break
            return {}

        def _build_no_output_kerberos_fallback_command(cmd: str) -> str | None:
            try:
                argv = shlex.split(cmd)
            except ValueError:
                return None

            if "-k" not in argv:
                return None

            fallback_argv = [part for part in argv if part != "-k"]
            services = {
                "smb",
                "ldap",
                "mssql",
                "winrm",
                "ssh",
                "rdp",
                "vnc",
                "ftp",
                "http",
                "https",
            }

            service_idx = next(
                (idx for idx, token in enumerate(fallback_argv) if token in services),
                None,
            )
            if service_idx is None or service_idx + 1 >= len(fallback_argv):
                return shlex.join(fallback_argv)

            target_idx = service_idx + 1
            target = str(fallback_argv[target_idx]).strip()
            domain_info = _resolve_domain_info(effective_domain)
            pdc_ip = str(domain_info.get("pdc") or "").strip()
            pdc_hostname = str(domain_info.get("pdc_hostname") or "").strip().casefold()
            fqdn_candidates = {
                pdc_hostname,
                f"{pdc_hostname}.{str(effective_domain).strip().casefold()}"
                if pdc_hostname and effective_domain
                else "",
            }

            try:
                ipaddress.ip_address(target)
                target_is_ip = True
            except Exception:
                target_is_ip = False

            if (
                pdc_ip
                and not target_is_ip
                and target
                and "/" not in target
                and "\\" not in target
                and not target.endswith(".txt")
                and target.casefold() in fqdn_candidates
            ):
                fallback_argv[target_idx] = pdc_ip

            return shlex.join(fallback_argv)

        while True:
            needs_retry = False
            schema_mismatch_detected = False
            netexec_auth_decision = (
                resolve_netexec_auth_policy_decision(
                    command=current_command,
                    domains_data=getattr(ctx.state_owner, "domains_data", None),
                    domain=effective_domain,
                    protocol=effective_service,
                    domain_configured=ctx.is_domain_configured(str(effective_domain))
                    if effective_domain is not None
                    else False,
                    target_count=effective_target_count,
                )
                if effective_domain is not None
                else None
            )

            print_info_debug(
                "[netexec] Auth policy: "
                f"domain={mark_sensitive(str(effective_domain), 'domain') if effective_domain is not None else 'unknown'} "
                f"protocol={effective_service or 'unknown'} "
                f"ntlm_status={netexec_auth_decision.ntlm_status if netexec_auth_decision is not None else 'unknown'} "
                f"kerberos_first={netexec_auth_decision.prefer_kerberos if netexec_auth_decision is not None else False!r} "
                f"reason={netexec_auth_decision.reason if netexec_auth_decision is not None else 'missing_domain'}"
            )

            if (
                not command_started_with_kerberos
                and "-k" not in f" {current_command} "
                and effective_domain is not None
                and netexec_auth_decision is not None
                and netexec_auth_decision.prefer_kerberos
                and netexec_can_use_kerberos(current_command)
                and not getattr(ctx.state_owner, "_netexec_kerberos_first_attempted", False)
            ):
                kerberos_first_command = build_netexec_kerberos_command(current_command)
                if kerberos_first_command and kerberos_first_command != current_command:
                    setattr(ctx.state_owner, "_netexec_kerberos_first_attempted", True)
                    print_info_debug(
                        "[netexec] Kerberos-first initial command selected: "
                        f"reason={netexec_auth_decision.reason} command={kerberos_first_command}"
                    )
                    current_command = kerberos_first_command

            for retry_attempt in range(1, max_retries + 1):
                proc = _execute_command_internal(current_command)
                if not isinstance(proc, subprocess.CompletedProcess):
                    return proc
                attempt_result_logged = False

                def _log_attempt_once() -> None:
                    nonlocal attempt_result_logged
                    if attempt_result_logged:
                        return
                    _log_netexec_attempt_result(proc)
                    attempt_result_logged = True

                stdout_clean = normalize_cli_output(proc.stdout or "")
                stderr_clean = normalize_cli_output(proc.stderr or "")
                proc.stdout = stdout_clean
                proc.stderr = stderr_clean
                combined_output = stdout_clean + stderr_clean
                delegated_auth_failure = parse_netexec_delegated_auth_failure(
                    combined_output
                )
                if (
                    delegated_auth_failure is not None
                    and delegated_auth_failure.status
                    == "STATUS_MORE_PROCESSING_REQUIRED"
                ):
                    self._print_delegated_smb_status_more_processing_required_guidance(
                        command=current_command,
                        failure_line=delegated_auth_failure.line,
                    )
                    synthesized_stderr = (stderr_clean or "").strip()
                    if synthesized_stderr:
                        synthesized_stderr += "\n"
                    synthesized_stderr += (
                        "[ADSCAN] NETEXEC_DELEGATED_SMB_STATUS_MORE_PROCESSING_REQUIRED\n"
                        + delegated_auth_failure.line
                    )
                    proc = subprocess.CompletedProcess(
                        args=proc.args,
                        returncode=1,
                        stdout=stdout_clean,
                        stderr=synthesized_stderr,
                    )
                    stdout_clean = proc.stdout or ""
                    stderr_clean = proc.stderr or ""
                    combined_output = stdout_clean + stderr_clean
                has_exact_ldap_connection_timeout = _is_ldap_command(
                    current_command
                ) and output_has_exact_ldap_connection_timeout(combined_output)
                has_timeout_result = result_is_timeout(proc, tool_name="netexec")

                output_lines = (
                    combined_output.strip().splitlines() if combined_output else []
                )
                non_empty_lines = [
                    line.strip() for line in output_lines if line.strip()
                ]
                has_empty_output = len(non_empty_lines) == 0

                init_markers = (
                    "first time use detected",
                    "creating home directory structure",
                    "copying default configuration file",
                    "creating missing folder",
                )
                lower_output = combined_output.lower()
                init_detected = any(
                    marker.lower() in lower_output for marker in init_markers
                )
                has_service_line = any(
                    re.match(r"^(SMB|LDAP|MSSQL|RDP|WINRM|WMI|SSH|VNC)\\s", line)
                    for line in non_empty_lines
                )
                if (
                    init_detected
                    and not has_service_line
                    and retry_attempt < max_retries
                ):
                    _log_attempt_once()
                    print_warning_verbose(
                        "NetExec is initializing its workspace (first run detected). "
                        f"Retrying command ({retry_attempt}/{max_retries})..."
                    )
                    time.sleep(1.0)
                    continue

                if " -k " not in f" {current_command} ":
                    if output_indicates_ntlm_disabled(combined_output):
                        posture_update = record_ntlm_disabled_signal(
                            getattr(ctx.state_owner, "domains_data", None),
                            domain=effective_domain,
                            protocol=effective_service,
                            source="netexec",
                            signal="ntlm_disabled",
                            message=combined_output.strip()[:500],
                        )
                        print_info_debug(
                            "[netexec] Observed NTLM-disabled signal: "
                            f"domain={mark_sensitive(str(effective_domain), 'domain') if effective_domain is not None else 'unknown'} "
                            f"protocol={effective_service or 'unknown'} "
                            "new_ntlm_status=likely_disabled "
                            "action=recorded"
                        )
                        if posture_update is not None and posture_update.should_notify_user:
                            _notify_ntlm_disabled_prioritize_kerberos(
                                domain=effective_domain,
                                protocol=effective_service,
                                source="NetExec",
                            )
                        if posture_update is not None:
                            _sync_ntlm_control_evidence(
                                ctx.state_owner,
                                domain=effective_domain,
                                protocol=effective_service,
                                status="observed",
                                source="netexec",
                                message=combined_output.strip()[:500],
                            )

                    kerberos_retry_attempted = getattr(
                        ctx.state_owner,
                        "_netexec_ntlm_disabled_kerberos_retry_attempted",
                        False,
                    )
                    if not kerberos_retry_attempted and output_indicates_ntlm_disabled(
                        combined_output
                    ):
                        kerberos_retry_command = build_netexec_kerberos_command(
                            current_command
                        )
                        if kerberos_retry_command and kerberos_retry_command != current_command:
                            setattr(
                                ctx.state_owner,
                                "_netexec_ntlm_disabled_kerberos_retry_attempted",
                                True,
                            )
                            _log_attempt_once()
                            print_warning(
                                "NetExec reported NTLM is disabled or unsupported. Retrying with Kerberos (-k)."
                            )
                            print_info_debug(
                                "[netexec] NTLM-disabled Kerberos retry command: "
                                f"reason=ntlm_disabled_signal command={kerberos_retry_command}"
                            )
                            current_command = kerberos_retry_command
                            needs_retry = True
                            break
                    if proc.returncode == 0 and combined_output.strip():
                        record_ntlm_enabled_signal(
                            getattr(ctx.state_owner, "domains_data", None),
                            domain=effective_domain,
                            protocol=effective_service,
                            source="netexec",
                            message=combined_output.strip()[:500],
                        )
                        print_info_debug(
                            "[netexec] Observed NTLM success signal: "
                            f"domain={mark_sensitive(str(effective_domain), 'domain') if effective_domain is not None else 'unknown'} "
                            f"protocol={effective_service or 'unknown'} "
                            "new_ntlm_status=likely_enabled "
                            "action=recorded"
                        )
                        _sync_ntlm_control_evidence(
                            ctx.state_owner,
                            domain=effective_domain,
                            protocol=effective_service,
                            status="contradicted",
                            source="netexec",
                            message=combined_output.strip()[:500],
                        )
                else:
                    has_wrong_realm = "KDC_ERR_WRONG_REALM" in combined_output
                    has_connection_reset = _has_connection_reset_by_peer(combined_output)
                    kerberos_ntlm_fallback_attempted = getattr(
                        ctx.state_owner,
                        "_netexec_kerberos_first_ntlm_fallback_attempted",
                        False,
                    )
                    if (
                        not kerberos_ntlm_fallback_attempted
                        and not has_wrong_realm
                        and not has_connection_reset
                        and not output_indicates_kerberos_invalid_credentials(
                            combined_output
                        )
                        and output_indicates_kerberos_auth_failure(combined_output)
                    ):
                        ntlm_fallback_command = build_netexec_ntlm_command(current_command)
                        if ntlm_fallback_command and ntlm_fallback_command != current_command:
                            setattr(
                                ctx.state_owner,
                                "_netexec_kerberos_first_ntlm_fallback_attempted",
                                True,
                            )
                            _log_attempt_once()
                            print_warning(
                                "NetExec Kerberos authentication failed. Retrying with NTLM."
                            )
                            print_info_debug(
                                f"[netexec] Kerberos-first NTLM fallback command: {ntlm_fallback_command}"
                            )
                            current_command = ntlm_fallback_command
                            needs_retry = True
                            break

                has_redirection, redirected_file = ctx.detect_output_redirection(
                    current_command
                )
                if has_empty_output and has_redirection and redirected_file:
                    if ctx.redirected_file_has_content(redirected_file):
                        has_empty_output = False
                    else:
                        marked_redirected_file = (
                            mark_sensitive(str(redirected_file), "path")
                            if redirected_file is not None
                            else ""
                        )
                        if retry_attempt < max_retries:
                            _log_attempt_once()
                            print_warning(
                                "No output received and redirected file "
                                f"'{marked_redirected_file}' is empty or missing "
                                f"(attempt {retry_attempt}/{max_retries}). "
                                "Retrying command..."
                            )
                            continue
                        print_error(
                            "No output received and redirected file "
                            f"'{marked_redirected_file}' is empty or missing after "
                            f"{max_retries} attempts. Proceeding with empty result."
                        )

                if has_empty_output and retry_attempt < max_retries:
                    _log_attempt_once()
                    print_warning_verbose(
                        f"No output received from NetExec (attempt {retry_attempt}/{max_retries}). "
                        "Retrying command..."
                    )
                    continue
                if has_empty_output and retry_attempt >= max_retries:
                    no_output_kerberos_fallback_attempted = getattr(
                        ctx.state_owner,
                        "_netexec_no_output_kerberos_fallback_attempted",
                        False,
                    )
                    fallback_command = _build_no_output_kerberos_fallback_command(
                        current_command
                    )
                    if fallback_command and not no_output_kerberos_fallback_attempted:
                        setattr(
                            ctx.state_owner,
                            "_netexec_no_output_kerberos_fallback_attempted",
                            True,
                        )
                        _log_attempt_once()
                        print_warning(
                            "Kerberos NetExec command produced no output after repeated retries. "
                            "Retrying once with NTLM fallback."
                        )
                        if fallback_command != current_command:
                            print_info_debug(
                                f"[netexec] No-output NTLM fallback command: {fallback_command}"
                            )
                        current_command = fallback_command
                        needs_retry = True
                        break
                    print_error(
                        f"No output received after {max_retries} attempts. "
                        "Proceeding with empty result."
                    )

                if has_timeout_result:
                    timeout_label = (
                        f"{current_timeout}s"
                        if current_timeout is not None
                        else "disabled"
                    )
                    print_warning(
                        "NetExec command exceeded the current ADscan execution timeout "
                        f"({timeout_label})."
                    )
                    print_info(
                        f"Scope size estimate: {effective_target_count} target(s)."
                    )

                    if (
                        not allow_timeout_recovery
                        or bool(os.getenv("CI"))
                        or bool(getattr(ctx.state_owner, "non_interactive", False))
                    ):
                        if not allow_timeout_recovery:
                            print_warning(
                                "Timeout recovery is disabled for this NetExec command."
                            )
                        else:
                            print_warning(
                                "Non-interactive mode detected; timeout recovery will not prompt."
                            )
                        _log_attempt_once()
                        return proc

                    if timeout_recovery_attempts >= max_timeout_recovery_attempts:
                        print_warning(
                            "NetExec timeout recovery has already been attempted multiple times. "
                            "Stopping retries to avoid an infinite loop."
                        )
                        _log_attempt_once()
                        return proc

                    extended_timeout = resolve_extended_timeout_seconds(
                        service=effective_service,
                        current_timeout_seconds=current_timeout,
                        target_count=effective_target_count,
                    )
                    if current_timeout is not None and ctx.confirm_ask(
                        (
                            "Do you want to retry this NetExec command "
                            f"with a longer ADscan timeout ({extended_timeout}s)?"
                        ),
                        True,
                    ):
                        timeout_recovery_attempts += 1
                        current_timeout = extended_timeout
                        needs_retry = True
                        _log_attempt_once()
                        print_info_debug(
                            "[netexec] Retrying after timeout with extended "
                            f"global_timeout={current_timeout}s"
                        )
                        break

                    if current_timeout is not None and ctx.confirm_ask(
                        "Do you want to retry this NetExec command without a global ADscan timeout?",
                        False,
                    ):
                        timeout_recovery_attempts += 1
                        current_timeout = None
                        needs_retry = True
                        _log_attempt_once()
                        print_info_debug(
                            "[netexec] Retrying after timeout with global_timeout=disabled"
                        )
                        break

                    _log_attempt_once()
                    return proc

                if has_exact_ldap_connection_timeout:
                    print_warning(
                        "NetExec LDAP hit the exact connection-timeout signature "
                        "(TimeoutError: [Errno 110] Connection timed out). "
                        "LDAP appears unstable or unreachable; skipping further "
                        "NetExec retries/recovery for this command."
                    )
                    print_instruction(
                        "LDAP did not complete successfully. Continue with non-LDAP "
                        "logic or re-run later when LDAP connectivity is stable."
                    )
                    _log_attempt_once()
                    return build_ldap_exact_connection_timeout_completed_process(
                        current_command,
                        stdout=stdout_clean,
                        stderr=stderr_clean,
                    )

                # NetExec sometimes wraps error messages across many lines, so we
                # support both:
                # - the human-friendly sentence (whitespace-normalized)
                # - the structured token (NetBIOSTimeout) shown in some modules
                compact_output = re.sub(r"\\s+", " ", combined_output).strip()
                has_netbios_timeout = (
                    "NETBIOSTIMEOUT" in combined_output.upper()
                    or "The NETBIOS connection with the remote host timed out"
                    in compact_output
                )

                if has_netbios_timeout and retry_attempt < max_retries:
                    _log_attempt_once()
                    print_warning_debug(
                        f"NETBIOS connection timeout detected (attempt {retry_attempt}/{max_retries}). "
                        "Retrying command..."
                    )
                    continue

                if has_netbios_timeout and retry_attempt >= max_retries:

                    def _is_slow_netexec_settings(cmd_text: str) -> bool:
                        t_match = re.search(r"(?:^|\\s)-t\\s+(\\d+)\\b", cmd_text)
                        timeout_match = re.search(
                            r"(?:^|\\s)--timeout\\s+(\\d+)\\b", cmd_text
                        )
                        t_val = int(t_match.group(1)) if t_match else None
                        timeout_val = (
                            int(timeout_match.group(1)) if timeout_match else None
                        )
                        return t_val == 1 and timeout_val == 30

                    def _force_slow_netexec_settings(cmd_text: str) -> str:
                        updated = cmd_text
                        if re.search(r"(?:^|\\s)-t\\s+\\d+\\b", updated):
                            updated = re.sub(
                                r"(?:(^|\\s)-t\\s+)\\d+\\b",
                                r"\\g<1>1",
                                updated,
                            )
                        else:
                            updated = f"{updated} -t 1"

                        if re.search(r"(?:^|\\s)--timeout\\s+\\d+\\b", updated):
                            updated = re.sub(
                                r"(?:(^|\\s)--timeout\\s+)\\d+\\b",
                                r"\\g<1>30",
                                updated,
                            )
                        else:
                            updated = f"{updated} --timeout 30"
                        return updated

                    preview_lines = [
                        line for line in combined_output.splitlines() if line.strip()
                    ]
                    preview_tail = (
                        "\n".join(preview_lines[-30:]) if preview_lines else ""
                    )
                    if preview_tail:
                        _log_attempt_once()
                        print_info_debug(
                            "[netexec] NETBIOS timeout output preview (tail):\n"
                            + preview_tail,
                            panel=True,
                        )

                    already_slow = _is_slow_netexec_settings(current_command)
                    if not already_slow and not getattr(
                        ctx.state_owner, "_netexec_slow_retry_attempted", False
                    ):
                        print_warning(
                            f"SMB connection attempt timed out after {max_retries} retries."
                        )
                        retry_slow = ctx.confirm_ask(
                            "Retry the same check in a safer (slower) mode?",
                            True,
                        )
                        if retry_slow:
                            setattr(
                                ctx.state_owner, "_netexec_slow_retry_attempted", True
                            )
                            needs_retry = True
                            _log_attempt_once()
                            current_command = _force_slow_netexec_settings(
                                current_command
                            )
                            print_info_debug(f"Command (slower): {current_command}")
                            break

                        skip_check = ctx.confirm_ask(
                            "Skip this check and continue?",
                            False,
                        )
                        if skip_check:
                            _log_attempt_once()
                            return subprocess.CompletedProcess(
                                args=current_command,
                                returncode=0,
                                stdout="[ADSCAN] NETEXEC_SKIPPED_DUE_TO_TIMEOUT\n",
                                stderr="",
                            )

                    print_warning(
                        "SMB connection attempt timed out after "
                        f"{max_retries} retries (even in slow mode). Results may be incomplete."
                    )
                    print_instruction(
                        "Troubleshooting: verify VPN/connectivity and that TCP/445 is reachable on targets."
                    )
                    print_instruction(
                        "For more help, visit: https://adscanpro.com/docs/guides/troubleshooting"
                    )

                has_clock_skew = "KRB_AP_ERR_SKEW" in combined_output
                has_sched_error = (
                    "SCHED_S_TASK_HAS_NOT_RUN" in combined_output
                    or "SCHED_E_MALFORMEDXML" in combined_output
                )
                has_schema_mismatch = "Schema mismatch detected" in combined_output
                has_wrong_realm = "KDC_ERR_WRONG_REALM" in combined_output
                has_connection_reset = _has_connection_reset_by_peer(combined_output)

                if has_schema_mismatch:
                    if (
                        schema_mismatch_cleanup_attempts
                        >= max_schema_mismatch_cleanup_attempts
                    ):
                        print_warning(
                            "Schema mismatch detected in NetExec output, but auto-cleanup was already attempted "
                            f"{max_schema_mismatch_cleanup_attempts} times. Proceeding without further retries."
                        )
                        print_info(
                            "💡 Try: `adscan check --fix` (repairs NetExec state/permissions) or manually run "
                            f"`sudo rm -rf {ctx.get_workspaces_dir()}` and re-run the command."
                        )
                        _log_attempt_once()
                        return proc
                    print_warning(
                        "Schema mismatch detected in NetExec output. Cleaning NetExec workspaces and retrying."
                    )
                    schema_mismatch_cleanup_attempts += 1
                    if not ctx.clean_workspaces(True):
                        print_warning(
                            "Could not clean NetExec workspaces automatically (likely a permissions issue)."
                        )
                        print_info(
                            "💡 Try: `adscan check --fix` (repairs NetExec state/permissions) or manually run "
                            f"`sudo rm -rf {ctx.get_workspaces_dir()}` and re-run the command."
                        )
                        _log_attempt_once()
                        return proc
                    needs_retry = True
                    schema_mismatch_detected = True
                    _log_attempt_once()
                    break

                if (
                    has_connection_reset
                    and " -k" in f" {current_command} "
                ):
                    connection_reset_fallback_attempted = getattr(
                        ctx.state_owner,
                        "_netexec_connection_reset_ntlm_fallback_attempted",
                        False,
                    )
                    if not connection_reset_fallback_attempted:
                        fallback_command = _build_no_output_kerberos_fallback_command(
                            current_command
                        )
                        if fallback_command and fallback_command != current_command:
                            setattr(
                                ctx.state_owner,
                                "_netexec_connection_reset_ntlm_fallback_attempted",
                                True,
                            )
                            _log_attempt_once()
                            print_warning(
                                "Kerberos NetExec command hit 'Connection reset by peer'. "
                                "Retrying once with NTLM fallback."
                            )
                            print_info_debug(
                                "[netexec] Connection-reset NTLM fallback command: "
                                f"{fallback_command}"
                            )
                            current_command = fallback_command
                            needs_retry = True
                            break

                if (
                    not has_clock_skew
                    and not has_sched_error
                    and not has_wrong_realm
                    and not needs_retry
                ):
                    _log_attempt_once()

                    return proc

                retry_command = current_command
                if has_wrong_realm:
                    krb5_path = os.environ.get("KRB5_CONFIG")
                    if krb5_path:
                        marked_krb5 = mark_sensitive(krb5_path, "path")
                        print_info_debug(
                            "[netexec] KRB5_CONFIG="
                            f"{marked_krb5} (exists={os.path.exists(krb5_path)})"
                        )
                    else:
                        print_info_debug("[netexec] KRB5_CONFIG is not set.")

                    wrong_realm_attempted = getattr(
                        ctx.state_owner, "_netexec_wrong_realm_retry_attempted", False
                    )
                    if wrong_realm_attempted:
                        print_warning(
                            "KDC_ERR_WRONG_REALM persists after removing -k. "
                            "Not retrying further to avoid a loop."
                        )
                        _log_attempt_once()
                    else:
                        try:
                            argv = shlex.split(retry_command)
                        except ValueError:
                            argv = retry_command.split()

                        if "-k" in argv:
                            argv = [part for part in argv if part != "-k"]
                            retry_command = " ".join(argv)
                            setattr(
                                ctx.state_owner,
                                "_netexec_wrong_realm_retry_attempted",
                                True,
                            )
                            _log_attempt_once()
                            print_warning(
                                "KDC_ERR_WRONG_REALM detected. Retrying NetExec without "
                                "Kerberos (-k) using NTLM."
                            )
                            needs_retry = True
                        else:
                            print_warning(
                                "KDC_ERR_WRONG_REALM detected but command does not "
                                "include -k. Cannot retry with NTLM fallback."
                            )
                            _log_attempt_once()
                if has_sched_error:
                    if "--exec-method atexec" in retry_command:
                        retry_command = retry_command.replace(
                            "--exec-method atexec", "--exec-method wmiexec"
                        )
                        _log_attempt_once()
                        print_warning(
                            "atexec method failed. Changing to wmiexec and retrying."
                        )
                        needs_retry = True
                    else:
                        print_warning(
                            "SCHED_S_TASK_HAS_NOT_RUN detected but command does not use "
                            "--exec-method atexec. Cannot automatically fix."
                        )
                        _log_attempt_once()

                if has_clock_skew:
                    if not effective_domain:
                        _log_attempt_once()
                        print_warning(
                            "KRB_AP_ERR_SKEW detected in NetExec output but no domain is available "
                            "to synchronize the clock with the PDC."
                        )
                    else:
                        marked_domain = mark_sensitive(str(effective_domain), "domain")
                        if clock_skew_sync_attempts >= max_clock_skew_sync_attempts:
                            _log_attempt_once()
                            print_warning(
                                "KRB_AP_ERR_SKEW persists after multiple clock synchronization attempts. "
                                "Stopping retries to avoid an infinite loop."
                            )
                            print_info_debug(
                                "[DEBUG] Clock-skew retries exhausted for "
                                f"domain={marked_domain}: attempts={clock_skew_sync_attempts}/"
                                f"{max_clock_skew_sync_attempts}"
                            )
                        else:
                            clock_skew_sync_attempts += 1
                            _log_attempt_once()
                            print_warning(
                                "KRB_AP_ERR_SKEW detected when running NetExec. Attempting to synchronize "
                                "the local clock with the PDC of domain "
                                f"'{marked_domain}' and retrying "
                                f"({clock_skew_sync_attempts}/{max_clock_skew_sync_attempts})."
                            )
                            if ctx.sync_clock_with_pdc(str(effective_domain)):
                                needs_retry = True
                            else:
                                _log_attempt_once()
                                print_error(
                                    "Clock synchronization with the PDC of domain "
                                    f"'{marked_domain}' failed. NetExec command will not be retried for clock skew."
                                )

                if needs_retry:
                    if not schema_mismatch_detected:
                        print_info_debug(f"Command: {retry_command}")
                        current_command = retry_command
                    break

                _log_attempt_once()
                return proc

            if not needs_retry:
                break

        return proc
