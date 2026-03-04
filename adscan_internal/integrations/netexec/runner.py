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
from adscan_internal.rich_output import mark_sensitive, strip_sensitive_markers
from adscan_internal.subprocess_env import (
    command_string_needs_clean_env,
    get_clean_env_for_compilation,
)
from adscan_internal.text_utils import normalize_cli_output

ExecutionResult = subprocess.CompletedProcess[str]


def _is_netexec_autoquote_enabled() -> bool:
    """Return whether NetExec path-like argument auto-quoting is enabled."""
    value = os.getenv("ADSCAN_NETEXEC_AUTOQUOTE", "1").strip().lower()
    return value not in {"0", "false", "no", "off"}


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

    def run(
        self,
        command: str,
        *,
        ctx: NetExecContext,
        domain: str | None = None,
        timeout: int | None = None,
        pre_sync: bool = True,
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
                    timeout=timeout or local_kwargs.pop("timeout", None),
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
                    print_error_verbose(
                        f"Command timed out after {timeout if timeout is not None else 'unknown'}s: "
                        f"{cmd}"
                    )
                return None
            except Exception as exc:
                if not ignore_errors_flag:
                    telemetry.capture_exception(exc)
                    print_error_verbose(f"Error executing command: {cmd} - {exc}")
                return None

        max_retries = 3
        current_command = command
        kerberos_fallback_command: str | None = None
        kerberos_forced = False
        max_clock_skew_sync_attempts = 3
        clock_skew_sync_attempts = 0
        schema_mismatch_cleanup_attempts = 0
        max_schema_mismatch_cleanup_attempts = 2

        def _should_force_kerberos(cmd: str) -> bool:
            try:
                argv = shlex.split(cmd)
            except ValueError:
                return False
            if "-k" in argv:
                return False
            if "--local-auth" in argv or "-no-pass" in argv:
                return False
            has_domain = "-d" in argv or "--domain" in argv
            if not has_domain:
                return False
            if "-u" not in argv:
                return False
            try:
                u_idx = argv.index("-u")
                username = argv[u_idx + 1]
            except (ValueError, IndexError):
                return False
            if username.strip().strip("'\"") == "":
                return False
            if "-p" not in argv and "-H" not in argv:
                return False
            if "-p" in argv:
                try:
                    p_idx = argv.index("-p")
                    password = argv[p_idx + 1]
                except (ValueError, IndexError):
                    return False
                if password.strip().strip("'\"") == "":
                    return False
            if "-H" in argv:
                try:
                    h_idx = argv.index("-H")
                    nt_hash = argv[h_idx + 1]
                except (ValueError, IndexError):
                    return False
                if nt_hash.strip().strip("'\"") == "":
                    return False
            return True

        def _has_kerberos_auth_failure(output: str) -> bool:
            patterns = (
                "KDC_ERR_PREAUTH_FAILED",
                "KRB_AP_ERR",
                "KDC_ERR",
                "STATUS_LOGON_FAILURE",
                "STATUS_NOT_SUPPORTED",
                "STATUS_ACCOUNT_RESTRICTION",
                "STATUS_PASSWORD_EXPIRED",
            )
            upper = output.upper()
            return any(token in upper for token in patterns)

        if _should_force_kerberos(current_command):
            kerberos_forced = True
            kerberos_fallback_command = current_command
            print_info_debug(
                "[netexec] Kerberos-first enabled, but command lacks -k; "
                "leaving command unchanged to avoid breaking modules/protocols. "
                "If NTLM is disabled, this command may fail."
            )

        while True:
            needs_retry = False
            schema_mismatch_detected = False

            for retry_attempt in range(1, max_retries + 1):
                proc = _execute_command_internal(current_command)
                if not isinstance(proc, subprocess.CompletedProcess):
                    return proc

                stdout_clean = normalize_cli_output(proc.stdout or "")
                stderr_clean = normalize_cli_output(proc.stderr or "")
                proc.stdout = stdout_clean
                proc.stderr = stderr_clean
                combined_output = stdout_clean + stderr_clean

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
                    print_warning_verbose(
                        "NetExec is initializing its workspace (first run detected). "
                        f"Retrying command ({retry_attempt}/{max_retries})..."
                    )
                    time.sleep(1.0)
                    continue

                if kerberos_forced and kerberos_fallback_command:
                    if current_command.endswith(" -k") and _has_kerberos_auth_failure(
                        combined_output
                    ):
                        fallback_attempted = getattr(
                            ctx.state_owner,
                            "_netexec_kerberos_fallback_attempted",
                            False,
                        )
                        if not fallback_attempted:
                            setattr(
                                ctx.state_owner,
                                "_netexec_kerberos_fallback_attempted",
                                True,
                            )
                            print_warning(
                                "Kerberos authentication failed. Retrying with NTLM fallback."
                            )
                            current_command = kerberos_fallback_command
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
                    print_warning_verbose(
                        f"No output received from NetExec (attempt {retry_attempt}/{max_retries}). "
                        "Retrying command..."
                    )
                    continue
                if has_empty_output and retry_attempt >= max_retries:
                    print_error(
                        f"No output received after {max_retries} attempts. "
                        "Proceeding with empty result."
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
                    try:
                        stdout_lines = [
                            line for line in stdout_clean.splitlines() if line.strip()
                        ]
                        stderr_lines = [
                            line for line in stderr_clean.splitlines() if line.strip()
                        ]
                        print_info_debug(
                            "[netexec] NETBIOS timeout output preview:\n"
                            + "\n".join((stdout_lines + stderr_lines)[:30]),
                            panel=True,
                        )
                    except Exception:
                        pass
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
                        return proc
                    needs_retry = True
                    schema_mismatch_detected = True
                    break

                if not has_clock_skew and not has_sched_error and not has_wrong_realm:
                    # Log a concise summary and truncated preview of the NetExec output.
                    try:
                        exit_code, stdout_count, stderr_count, duration_text = (
                            summarize_execution_result(proc)
                        )
                        print_info_debug(
                            "[netexec] Result: "
                            f"exit_code={exit_code}, "
                            f"stdout_lines={stdout_count}, "
                            f"stderr_lines={stderr_count}, "
                            f"duration={duration_text}"
                        )

                        preview_text = build_execution_output_preview(proc)
                        if preview_text:
                            print_info_debug(
                                "[netexec] Output preview:\n" + preview_text,
                                panel=True,
                            )
                    except Exception:
                        # Never let logging failures affect command flow
                        pass

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
                if has_sched_error:
                    if "--exec-method atexec" in retry_command:
                        retry_command = retry_command.replace(
                            "--exec-method atexec", "--exec-method wmiexec"
                        )
                        print_warning(
                            "atexec method failed. Changing to wmiexec and retrying."
                        )
                        needs_retry = True
                    else:
                        print_warning(
                            "SCHED_S_TASK_HAS_NOT_RUN detected but command does not use "
                            "--exec-method atexec. Cannot automatically fix."
                        )

                if has_clock_skew:
                    if not effective_domain:
                        print_warning(
                            "KRB_AP_ERR_SKEW detected in NetExec output but no domain is available "
                            "to synchronize the clock with the PDC."
                        )
                    else:
                        marked_domain = mark_sensitive(str(effective_domain), "domain")
                        if clock_skew_sync_attempts >= max_clock_skew_sync_attempts:
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
                            print_warning(
                                "KRB_AP_ERR_SKEW detected when running NetExec. Attempting to synchronize "
                                "the local clock with the PDC of domain "
                                f"'{marked_domain}' and retrying "
                                f"({clock_skew_sync_attempts}/{max_clock_skew_sync_attempts})."
                            )
                            if ctx.sync_clock_with_pdc(str(effective_domain)):
                                needs_retry = True
                            else:
                                print_error(
                                    "Clock synchronization with the PDC of domain "
                                    f"'{marked_domain}' failed. NetExec command will not be retried for clock skew."
                                )

                if needs_retry:
                    if not schema_mismatch_detected:
                        print_info_debug(f"Command: {retry_command}")
                        current_command = retry_command
                    break

                return proc

            if not needs_retry:
                break

        return proc
