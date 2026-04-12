"""Impacket tools runner.

This module provides a unified runner for Impacket tools with:
- Automatic error handling and retries
- Output capture and parsing
- Credential validation
- Path management for workspace outputs
"""

from __future__ import annotations

import subprocess
import shlex
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Optional, Callable, Mapping, Any

from adscan_internal import (
    print_error,
    print_error_verbose,
    print_info,
    print_info_debug,
    print_instruction,
    print_panel,
    print_warning,
    telemetry,
)
from adscan_internal.command_runner import (
    CommandRunner,
    CommandSpec,
    build_execution_output_preview,
    summarize_execution_result,
)
from adscan_internal.execution_outcomes import (
    build_no_result_completed_process,
    build_timeout_completed_process,
)
from adscan_internal.integrations.auth_policy import (
    build_impacket_kerberos_command,
    build_impacket_ntlm_command,
    impacket_script_supports_kerberos_first,
    output_indicates_kerberos_auth_failure,
    output_indicates_kerberos_invalid_credentials,
    output_indicates_ntlm_disabled,
    resolve_auth_policy_decision,
)
from adscan_internal.integrations.impacket.helpers import (
    resolve_impacket_ldaps_fallback_command,
)
from adscan_internal.rich_output import mark_sensitive, strip_sensitive_markers
from adscan_internal.reporting_compat import load_optional_report_service_attr
from adscan_internal.services.auth_posture_service import (
    record_ntlm_disabled_signal,
    record_ntlm_enabled_signal,
)
from adscan_internal.subprocess_env import (
    command_string_needs_clean_env,
    get_clean_env_for_compilation,
)
from adscan_internal.text_utils import normalize_cli_output


ExecutionResult = subprocess.CompletedProcess[str]


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


def _sync_ntlm_control_evidence(
    ctx: "ImpacketContext",
    *,
    domain: str | None,
    protocol: str | None,
    status: str,
    source: str,
    message: str | None = None,
) -> None:
    """Persist positive/neutral NTLM posture evidence to technical_report.json."""
    domain_name = str(domain or "").strip()
    workspace_dir = str(ctx.workspace_dir or "").strip()
    if not domain_name or not workspace_dir:
        return

    record_control_evidence = load_optional_report_service_attr(
        "record_control_evidence",
        action="Control evidence sync",
        debug_printer=print_info_debug,
        prefix="[auth-posture]",
    )
    if not callable(record_control_evidence):
        return

    shell_adapter = SimpleNamespace(
        current_workspace_dir=workspace_dir,
        technical_report_file="technical_report.json",
        domains_data=ctx.domains_data if isinstance(ctx.domains_data, dict) else {},
        domains=[],
        report_file="",
        report={},
        technical_report={},
    )
    try:
        record_control_evidence(
            shell_adapter,
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


@dataclass(frozen=True)
class ImpacketContext:
    """Context for running Impacket tools.

    Provides callbacks and state needed to execute Impacket commands
    safely from both CLI and service layers.
    """

    impacket_scripts_dir: str | Path
    validate_script_exists: Callable[[str], bool]
    get_domain_pdc: Callable[[str], str | None]
    workspace_dir: str | Path | None = None
    domains_data: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class ImpacketKerberosRetryContext:
    """Credential context required to prepare a deterministic Kerberos run."""

    domain: str
    username: str
    credential: str
    dc_ip: str | None = None


class ImpacketRunner:
    """Runner for Impacket tools with automatic error handling."""

    def __init__(self, *, command_runner: CommandRunner) -> None:
        """Initialize Impacket runner.

        Args:
            command_runner: Command runner instance for executing commands
        """
        self._command_runner = command_runner

    @staticmethod
    def _log_result(script_name: str, result: ExecutionResult | None) -> None:
        """Emit a concise summary and output preview for one Impacket result."""
        if not isinstance(result, subprocess.CompletedProcess):
            return
        exit_code, stdout_count, stderr_count, duration_text = (
            summarize_execution_result(result)
        )

        print_info_debug(
            f"[impacket] Result for {script_name}: "
            f"exit_code={exit_code}, "
            f"stdout_lines={stdout_count}, "
            f"stderr_lines={stderr_count}, "
            f"duration={duration_text}"
        )

        preview_text = build_execution_output_preview(result)
        if preview_text:
            print_info_debug(
                f"[impacket] Output preview for {script_name}:\n{preview_text}",
                panel=True,
            )

    def run(
        self,
        script_name: str,
        args: list[str],
        *,
        ctx: ImpacketContext,
        timeout: int | None = None,
        output_file: str | Path | None = None,
        capture_output: bool = True,
        **kwargs: object,
    ) -> ExecutionResult | None:
        """Run an Impacket script with automatic error handling.

        Args:
            script_name: Name of Impacket script (e.g., 'GetUserSPNs.py')
            args: List of command-line arguments for the script
            ctx: Execution context with paths and callbacks
            timeout: Optional timeout in seconds
            output_file: Optional output file path (script will write to this)
            capture_output: Whether to capture stdout/stderr
            **kwargs: Additional arguments forwarded to command runner

        Returns:
            Completed process or None if execution failed
        """
        # Validate script exists
        script_path = Path(ctx.impacket_scripts_dir) / script_name
        if not ctx.validate_script_exists(str(script_path)):
            print_error(
                f"Impacket script '{script_name}' not found at {script_path}. "
                "Please check Impacket installation."
            )
            return None

        # Build command safely for shell=True by quoting each token.
        cleaned_args = [strip_sensitive_markers(str(arg)) for arg in args]
        command_parts = [str(script_path)] + cleaned_args
        command = shlex.join(command_parts)

        result = self._run_with_kerberos_retry(
            script_name=script_name,
            command=command,
            ctx=ctx,
            timeout=timeout,
            capture_output=capture_output,
            **kwargs,
        )

        self._log_result(script_name, result)

        return result

    def run_getuserspns(
        self,
        domain: str,
        *,
        ctx: ImpacketContext,
        username: Optional[str] = None,
        password: Optional[str] = None,
        hashes: Optional[str] = None,
        no_preauth: bool = False,
        request: bool = True,
        usersfile: Optional[str | Path] = None,
        outputfile: Optional[str | Path] = None,
        timeout: int = 300,
    ) -> ExecutionResult | None:
        """Run GetUserSPNs.py for Kerberoasting.

        Args:
            domain: Target domain
            ctx: Execution context
            username: Username for authentication (optional if usersfile provided)
            password: Password for authentication
            hashes: NTLM hashes for authentication (format: LM:NT)
            no_preauth: Use Kerberos pre-authentication
            request: Request TGS tickets
            usersfile: File containing list of users to check
            outputfile: Output file for hashes
            timeout: Command timeout in seconds

        Returns:
            Completed process or None if failed
        """
        pdc = ctx.get_domain_pdc(domain)
        if not pdc:
            print_error(
                f"Cannot determine PDC for domain {mark_sensitive(domain, 'domain')}"
            )
            return None

        args = []
        clean_domain = strip_sensitive_markers(str(domain))

        # Request TGS (comes first, like old_adscan.py: -request {auth})
        if request:
            args.append("-request")

        # Authentication
        if username and password:
            clean_username = strip_sensitive_markers(str(username))
            clean_password = strip_sensitive_markers(str(password))
            args.append(f"{clean_domain}/{clean_username}:{clean_password}")
        elif username and hashes:
            clean_username = strip_sensitive_markers(str(username))
            clean_hashes = strip_sensitive_markers(str(hashes))
            is_hash = len(clean_hashes) == 32 and all(
                c in "0123456789abcdef" for c in clean_hashes.lower()
            )
            if is_hash:
                args.append(f"{clean_domain}/{clean_username}")
                args.extend(["-hashes", f":{clean_hashes}"])
            else:
                args.append(f"{clean_domain}/{clean_username}:{clean_hashes}")
        elif no_preauth:
            if not usersfile:
                print_error("no-preauth mode requires usersfile")
                return None
            args.append("-no-preauth")
            if username:
                clean_username = strip_sensitive_markers(str(username))
                args.append(clean_username)

        # Target domain (like old_adscan.py used -target-domain)
        args.extend(["-target-domain", clean_domain])

        # Output file
        if outputfile:
            args.extend(["-outputfile", str(outputfile)])

        # Users file
        if usersfile:
            args.extend(["-usersfile", str(usersfile)])

        # DC IP - needed to avoid LDAP referral errors and to force correct KDC selection
        clean_pdc = strip_sensitive_markers(str(pdc))
        args.extend(["-dc-ip", clean_pdc])

        # Build the raw command and parse stdout in Python. This avoids relying
        # on shell pipelines for candidate extraction and keeps outputfile
        # validation separate from stdout inspection.
        script_path = Path(ctx.impacket_scripts_dir) / "GetUserSPNs.py"
        if not ctx.validate_script_exists(str(script_path)):
            print_error(
                f"GetUserSPNs.py not found at {script_path}. "
                "Please check Impacket installation."
            )
            return None

        cleaned_args = [strip_sensitive_markers(str(arg)) for arg in args]
        command_parts = [str(script_path)] + cleaned_args
        command = shlex.join(command_parts)

        kerberos_retry_context = self._build_retry_context(
            domain=domain,
            username=username,
            password=password,
            hashes=hashes,
            dc_ip=clean_pdc,
        )

        result = self._run_with_kerberos_retry(
            script_name="GetUserSPNs.py",
            command=command,
            ctx=ctx,
            kerberos_retry_context=kerberos_retry_context,
            timeout=timeout,
            capture_output=True,
        )

        return result

    def run_getnpusers(
        self,
        domain: str,
        *,
        ctx: ImpacketContext,
        username: Optional[str] = None,
        password: Optional[str] = None,
        usersfile: Optional[str | Path] = None,
        format: str = "hashcat",
        outputfile: Optional[str | Path] = None,
        dc_ip: Optional[str] = None,
        timeout: int = 300,
    ) -> ExecutionResult | None:
        """Run GetNPUsers.py for AS-REP Roasting.

        Args:
            domain: Target domain
            ctx: Execution context
            username: Username for authenticated enumeration (optional)
            password: Password for authenticated enumeration (optional)
            usersfile: File containing list of users to check (required for unauthenticated)
            format: Output format ('hashcat' or 'john')
            outputfile: Output file for hashes
            dc_ip: Domain controller IP (optional, will use PDC if not provided)
            timeout: Command timeout in seconds

        Returns:
            Completed process or None if failed
        """
        if not dc_ip:
            dc_ip = ctx.get_domain_pdc(domain)
            if not dc_ip:
                print_error(
                    f"Cannot determine PDC for domain {mark_sensitive(domain, 'domain')}"
                )
                return None

        args = []

        # Domain format: DOMAIN/
        # CRITICAL: Strip sensitive markers from domain BEFORE adding to args
        clean_domain = strip_sensitive_markers(str(domain))
        args.append(f"{clean_domain}/")

        # Authentication (optional for AS-REP roasting)
        # CRITICAL: Strip sensitive markers from credentials BEFORE adding to args
        if username and password:
            clean_username = strip_sensitive_markers(str(username))
            clean_password = strip_sensitive_markers(str(password))
            args.extend(["-u", clean_username, "-p", clean_password])

        # Users file (required if no auth)
        if usersfile:
            args.extend(["-usersfile", str(usersfile)])
        elif not username:
            print_error("Either username or usersfile must be provided")
            return None

        # Format
        args.extend(["-format", format])

        # Output file
        if outputfile:
            args.extend(["-outputfile", str(outputfile)])

        # DC IP
        if dc_ip:
            args.extend(["-dc-ip", dc_ip])

        kerberos_retry_context = self._build_retry_context(
            domain=domain,
            username=username,
            password=password,
            hashes=None,
            dc_ip=dc_ip,
        )

        return self.run(
            "GetNPUsers.py",
            args,
            ctx=ctx,
            timeout=timeout,
            kerberos_retry_context=kerberos_retry_context,
        )

    def run_secretsdump(
        self,
        target: str,
        *,
        ctx: ImpacketContext,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        sam: Optional[str | Path] = None,
        system: Optional[str | Path] = None,
        security: Optional[str | Path] = None,
        just_dc: bool = False,
        just_dc_ntlm: bool = False,
        outputfile: Optional[str | Path] = None,
        timeout: int = 600,
    ) -> ExecutionResult | None:
        """Run secretsdump.py for credential extraction.

        Supports two modes:
        1. Remote DCSync: username/password required, target is DC
        2. Local dump: sam/system required, target is 'LOCAL'

        Args:
            target: Target (DC IP/hostname for remote, 'LOCAL' for local dump)
            ctx: Execution context
            username: Username for remote dump
            password: Password for remote dump
            domain: Domain name for remote dump
            hashes: NTLM hashes for authentication (format: LM:NT)
            sam: Path to SAM registry hive (for local dump)
            system: Path to SYSTEM registry hive (for local dump)
            security: Path to SECURITY registry hive (optional, for local dump)
            just_dc: Only extract NTDS.DIT data (no SAM/LSA)
            just_dc_ntlm: Only extract NTLM hashes from NTDS.DIT
            outputfile: Output file for credentials
            timeout: Command timeout in seconds

        Returns:
            Completed process or None if failed
        """
        args = []

        # Local or remote mode
        if target.upper() == "LOCAL":
            # Local dump mode
            if not sam or not system:
                print_error("Local dump requires both -sam and -system arguments")
                return None
            args.extend(["-sam", str(sam)])
            args.extend(["-system", str(system)])
            if security:
                args.extend(["-security", str(security)])
            args.append("LOCAL")

        else:
            # Remote DCSync mode
            if not username:
                print_error("Remote dump requires username")
                return None

            # Authentication
            if password:
                auth = f"{username}:{password}"
            elif hashes:
                auth = f"{username}@"
                args.extend(["-hashes", hashes])
            else:
                print_error("Remote dump requires either password or hashes")
                return None

            # Domain prefix
            if domain:
                auth = f"{domain}/{auth}"

            # Just DC options
            if just_dc:
                args.append("-just-dc")
            if just_dc_ntlm:
                args.append("-just-dc-ntlm")

            # Target (append auth if using password)
            if password:
                args.append(f"{auth}@{target}")
            else:
                args.append(f"{username}@{target}")

        # Output file
        if outputfile:
            args.extend(["-outputfile", str(outputfile)])

        kerberos_retry_context = self._build_retry_context(
            domain=domain,
            username=username,
            password=password,
            hashes=hashes,
            dc_ip=target,
        )

        return self.run(
            "secretsdump.py",
            args,
            ctx=ctx,
            timeout=timeout,
            kerberos_retry_context=kerberos_retry_context,
        )

    def _execute_command(
        self,
        command: str,
        *,
        timeout: int | None = None,
        capture_output: bool = True,
        **kwargs: object,
    ) -> ExecutionResult | None:
        """Execute Impacket command with error handling.

        Args:
            command: Full command string
            timeout: Optional timeout in seconds
            capture_output: Whether to capture stdout/stderr
            **kwargs: Additional arguments for command runner

        Returns:
            Completed process or None if failed
        """
        local_kwargs = dict(kwargs)

        # Determine if clean environment needed
        use_clean_env = local_kwargs.pop("use_clean_env", None)
        if use_clean_env is None:
            use_clean_env = command_string_needs_clean_env(command)

        cmd_env = local_kwargs.pop("env", None)
        if use_clean_env and cmd_env is None:
            cmd_env = get_clean_env_for_compilation()

        try:
            spec = CommandSpec(
                command=command,
                timeout=timeout,
                shell=bool(local_kwargs.pop("shell", True)),
                capture_output=capture_output,
                text=bool(local_kwargs.pop("text", True)),
                check=bool(local_kwargs.pop("check", False)),
                env=cmd_env,
                cwd=local_kwargs.pop("cwd", None),
                extra=local_kwargs or None,
            )

            result = self._command_runner.run(spec)
            if result is None:
                print_warning(f"Command runner returned None for: {command}")
                return build_no_result_completed_process(
                    command,
                    tool_name="impacket",
                )

            # Normalize output
            if isinstance(result, subprocess.CompletedProcess):
                if result.stdout:
                    result.stdout = normalize_cli_output(result.stdout)
                if result.stderr:
                    result.stderr = normalize_cli_output(result.stderr)

                fallback_command = resolve_impacket_ldaps_fallback_command(
                    command,
                    stdout=result.stdout,
                    stderr=result.stderr,
                )
                if fallback_command is not None:
                    print_warning("LDAPS connection failed. Retrying with LDAP...")
                    return self._execute_command(
                        fallback_command,
                        timeout=timeout,
                        capture_output=capture_output,
                        **kwargs,
                    )

            return result

        except subprocess.TimeoutExpired as exc:
            telemetry.capture_exception(exc)
            print_warning(
                f"Impacket command timed out after {timeout if timeout is not None else 'unknown'}s: "
                f"{command}"
            )
            print_instruction(
                "Verify VPN/network connectivity to the target and retry."
            )
            return build_timeout_completed_process(command, tool_name="impacket")

        except Exception as exc:
            telemetry.capture_exception(exc)
            print_error_verbose(f"Error executing Impacket command: {command} - {exc}")
            return None

    def _run_with_kerberos_retry(
        self,
        *,
        script_name: str,
        command: str,
        ctx: ImpacketContext,
        kerberos_retry_context: ImpacketKerberosRetryContext | None = None,
        timeout: int | None = None,
        capture_output: bool = True,
        **kwargs: object,
    ) -> ExecutionResult | None:
        """Run an Impacket command and retry with Kerberos when NTLM is disabled.

        Args:
            script_name: Script being executed.
            command: Shell-escaped command string.
            timeout: Optional timeout in seconds.
            capture_output: Whether to capture stdout/stderr.
            **kwargs: Additional arguments for command runner.

        Returns:
            Completed process or None if execution failed.
        """
        current_command = command
        kerberos_first_attempted = False
        protocol = self._resolve_auth_posture_protocol(script_name)
        supports_kerberos_first = impacket_script_supports_kerberos_first(script_name)
        command_already_uses_kerberos = self._command_uses_kerberos(current_command)
        decision = (
            resolve_auth_policy_decision(
                domains_data=ctx.domains_data,
                domain=kerberos_retry_context.domain,
                protocol=protocol,
                default_preference=True,
            )
            if kerberos_retry_context is not None
            else None
        )
        auth_posture_status = (
            decision.ntlm_status if decision is not None else "unknown"
        )
        kerberos_first_selected = (
            kerberos_retry_context is not None
            and supports_kerberos_first
            and not command_already_uses_kerberos
            and decision is not None
            and decision.prefer_kerberos
        )

        if kerberos_retry_context is None:
            auth_policy_reason = "no_retry_context"
        elif not supports_kerberos_first:
            auth_policy_reason = "script_not_supported"
        elif command_already_uses_kerberos:
            auth_policy_reason = "command_already_uses_kerberos"
        else:
            auth_policy_reason = (
                decision.reason if decision is not None else "policy_declined"
            )

        print_info_debug(
            "[impacket] Auth policy: "
            f"script={script_name} "
            f"domain={mark_sensitive(kerberos_retry_context.domain, 'domain') if kerberos_retry_context is not None else 'unknown'} "
            f"protocol={protocol or 'unknown'} "
            f"ntlm_status={auth_posture_status} "
            f"kerberos_first={kerberos_first_selected!r} "
            f"reason={auth_policy_reason}"
        )

        if kerberos_first_selected:
            kerberos_first_command = build_impacket_kerberos_command(
                script_name,
                current_command,
            )
            if kerberos_first_command is not None:
                kerberos_first_attempted = True
                current_command = kerberos_first_command

        if (
            self._command_uses_kerberos(current_command)
            and kerberos_retry_context is not None
        ):
            self._prepare_kerberos_execution(
                ctx=ctx,
                retry_context=kerberos_retry_context,
                purpose=f"{script_name} (initial Kerberos execution)",
            )

        print_info_debug(f"[impacket] Running {script_name}: {current_command}")
        result = self._execute_command(
            current_command,
            timeout=timeout,
            capture_output=capture_output,
            **kwargs,
        )

        if (
            result is not None
            and kerberos_retry_context is not None
            and not self._command_uses_kerberos(current_command)
        ):
            combined_output = normalize_cli_output(
                "\n".join(
                    part for part in (result.stdout or "", result.stderr or "") if part
                )
            )
            if output_indicates_ntlm_disabled(combined_output):
                posture_update = record_ntlm_disabled_signal(
                    ctx.domains_data if isinstance(ctx.domains_data, dict) else None,
                    domain=kerberos_retry_context.domain,
                    protocol=protocol,
                    source="impacket",
                    signal="ntlm_disabled",
                    message=combined_output.strip()[:500],
                )
                print_info_debug(
                    "[impacket] Observed NTLM-disabled signal: "
                    f"script={script_name} "
                    f"domain={mark_sensitive(kerberos_retry_context.domain, 'domain')} "
                    f"protocol={protocol or 'unknown'} "
                    "new_ntlm_status=likely_disabled "
                    "action=recorded"
                )
                if posture_update is not None and posture_update.should_notify_user:
                    _notify_ntlm_disabled_prioritize_kerberos(
                        domain=kerberos_retry_context.domain,
                        protocol=protocol,
                        source="Impacket",
                    )
                if posture_update is not None:
                    _sync_ntlm_control_evidence(
                        ctx,
                        domain=kerberos_retry_context.domain,
                        protocol=protocol,
                        status="observed",
                        source="impacket",
                        message=combined_output.strip()[:500],
                    )
            elif result.returncode == 0 and combined_output.strip():
                record_ntlm_enabled_signal(
                    ctx.domains_data if isinstance(ctx.domains_data, dict) else None,
                    domain=kerberos_retry_context.domain,
                    protocol=protocol,
                    source="impacket",
                    message=combined_output.strip()[:500],
                )
                print_info_debug(
                    "[impacket] Observed NTLM success signal: "
                    f"script={script_name} "
                    f"domain={mark_sensitive(kerberos_retry_context.domain, 'domain')} "
                    f"protocol={protocol or 'unknown'} "
                    "new_ntlm_status=likely_enabled "
                    "action=recorded"
                )
                _sync_ntlm_control_evidence(
                    ctx,
                    domain=kerberos_retry_context.domain,
                    protocol=protocol,
                    status="contradicted",
                    source="impacket",
                    message=combined_output.strip()[:500],
                )

        if (
            kerberos_first_attempted
            and self._command_uses_kerberos(current_command)
            and result is not None
            and not output_indicates_kerberos_invalid_credentials(
                normalize_cli_output(
                    "\n".join(
                        part
                        for part in (result.stdout or "", result.stderr or "")
                        if part
                    )
                )
            )
            and output_indicates_kerberos_auth_failure(
                normalize_cli_output(
                    "\n".join(
                        part
                        for part in (result.stdout or "", result.stderr or "")
                        if part
                    )
                )
            )
        ):
            ntlm_command = build_impacket_ntlm_command(current_command)
            if ntlm_command is not None:
                self._log_result(script_name, result)
                print_warning(
                    "Impacket Kerberos authentication failed. Retrying with NTLM."
                )
                print_info_debug(
                    f"[impacket] Kerberos-first NTLM fallback command for {script_name}: {ntlm_command}"
                )
                retry_result = self._execute_command(
                    ntlm_command,
                    timeout=timeout,
                    capture_output=capture_output,
                    **kwargs,
                )
                self._log_result(script_name, retry_result)
                return retry_result

        if not self._should_retry_with_kerberos(script_name, current_command, result):
            self._log_result(script_name, result)
            return result

        retry_command = build_impacket_kerberos_command(script_name, current_command)
        if retry_command is None:
            self._log_result(script_name, result)
            return result

        if kerberos_retry_context is not None:
            self._prepare_kerberos_execution(
                ctx=ctx,
                retry_context=kerberos_retry_context,
                purpose=f"{script_name} (Kerberos retry after NTLM-disabled signal)",
            )

        print_warning(
            "Impacket reported NTLM is disabled or unsupported. Retrying with Kerberos (-k)."
        )
        print_info_debug(
            f"[impacket] NTLM-disabled Kerberos retry command for {script_name}: {retry_command}"
        )
        self._log_result(script_name, result)
        retry_result = self._execute_command(
            retry_command,
            timeout=timeout,
            capture_output=capture_output,
            **kwargs,
        )
        self._log_result(script_name, retry_result)
        return retry_result

    def _should_retry_with_kerberos(
        self,
        script_name: str,
        command: str,
        result: ExecutionResult | None,
    ) -> bool:
        """Return True when a failed Impacket run should retry with Kerberos."""
        if result is None:
            return False
        if not output_indicates_ntlm_disabled(
            normalize_cli_output(
                "\n".join(
                    part for part in (result.stdout or "", result.stderr or "") if part
                )
            )
        ):
            return False
        if build_impacket_kerberos_command(script_name, command) is None:
            return False
        return True

    @staticmethod
    def _build_retry_context(
        *,
        domain: str | None,
        username: str | None,
        password: str | None,
        hashes: str | None,
        dc_ip: str | None,
    ) -> ImpacketKerberosRetryContext | None:
        """Build Kerberos retry context from available Impacket credentials."""
        user = str(username or "").strip()
        realm = str(domain or "").strip()
        if not user or not realm:
            return None

        secret = str(password or hashes or "").strip()
        if not secret:
            return None

        return ImpacketKerberosRetryContext(
            domain=realm,
            username=user,
            credential=secret.lstrip(":") if hashes and not password else secret,
            dc_ip=str(dc_ip or "").strip() or None,
        )

    @staticmethod
    def _command_uses_kerberos(command: str) -> bool:
        """Return True when one command explicitly requests Kerberos."""
        try:
            return "-k" in shlex.split(command)
        except ValueError:
            return " -k " in f" {command} "

    def _prepare_kerberos_execution(
        self,
        *,
        ctx: ImpacketContext,
        retry_context: ImpacketKerberosRetryContext,
        purpose: str,
    ) -> str | None:
        """Refresh the intended Kerberos ticket and bind the process env to it."""
        from adscan_internal.services.kerberos_ticket_service import (
            KerberosTicketService,
        )

        workspace_dir = str(ctx.workspace_dir or "").strip()
        if not workspace_dir:
            print_info_debug(
                f"[impacket] Kerberos preparation skipped for {purpose}: no workspace_dir in context."
            )
            return None

        service = KerberosTicketService()
        result = service.auto_generate_tgt(
            username=retry_context.username,
            credential=retry_context.credential,
            domain=retry_context.domain,
            workspace_dir=workspace_dir,
            dc_ip=retry_context.dc_ip,
        )
        if not result.success:
            print_warning(
                "Failed to refresh Kerberos ticket before Impacket Kerberos execution."
            )
            print_info_debug(
                "[impacket] Kerberos ticket refresh failed: "
                f"user={mark_sensitive(retry_context.username, 'user')}@"
                f"{mark_sensitive(retry_context.domain, 'domain')} "
                f"error={result.error_message!r}"
            )

        _conf_set, _ticket_set, krb5_config_path, ticket_path = (
            service.setup_environment_for_domain(
                workspace_dir=workspace_dir,
                domain=retry_context.domain,
                user_domain=retry_context.domain,
                username=retry_context.username,
                domains_data=ctx.domains_data,
            )
        )
        print_info_debug(
            "[impacket] Prepared Kerberos environment: "
            f"purpose={purpose!r} user={mark_sensitive(retry_context.username, 'user')}@"
            f"{mark_sensitive(retry_context.domain, 'domain')} "
            f"krb5_config={mark_sensitive(str(krb5_config_path or 'unknown'), 'path')} "
            f"ccache={mark_sensitive(str(ticket_path or 'unknown'), 'path')}"
        )
        return ticket_path

    @staticmethod
    def _resolve_auth_posture_protocol(script_name: str) -> str | None:
        """Map Impacket scripts to auth-posture protocol buckets."""
        if script_name in {"GetUserSPNs.py", "GetNPUsers.py"}:
            return "ldap"
        if script_name == "secretsdump.py":
            return "smb"
        return None
