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
from typing import Optional, Callable

from adscan_internal import (
    print_error,
    print_error_verbose,
    print_info_debug,
    print_warning,
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


@dataclass(frozen=True)
class ImpacketContext:
    """Context for running Impacket tools.

    Provides callbacks and state needed to execute Impacket commands
    safely from both CLI and service layers.
    """

    impacket_scripts_dir: str | Path
    validate_script_exists: Callable[[str], bool]
    get_domain_pdc: Callable[[str], str | None]


class ImpacketRunner:
    """Runner for Impacket tools with automatic error handling."""

    def __init__(self, *, command_runner: CommandRunner) -> None:
        """Initialize Impacket runner.

        Args:
            command_runner: Command runner instance for executing commands
        """
        self._command_runner = command_runner

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

        # Show full command in debug output (no truncation)
        print_info_debug(f"[impacket] Running {script_name}: {command}")

        result = self._execute_command(
            command,
            timeout=timeout,
            capture_output=capture_output,
            **kwargs,
        )

        # Always log a concise summary of the result for debugging.
        if isinstance(result, subprocess.CompletedProcess):
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
            print_error(f"Cannot determine PDC for domain {mark_sensitive(domain, 'domain')}")
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

        # NOTE: In old_adscan.py do_kerberoast (line 26732), the command includes a pipeline
        # for filtering output. The full command is:
        # GetUserSPNs.py -request {auth} -target-domain {domain} -outputfile ... | awk '{print $2}' | grep -vE 'Name|v0.|---|CCache|Principal:' | awk '!seen[$0]++' | awk 'NF'
        # We need to add this pipeline to the command string when request=True
        
        # Build the command with pipeline like old_adscan.py
        script_path = Path(ctx.impacket_scripts_dir) / "GetUserSPNs.py"
        if not ctx.validate_script_exists(str(script_path)):
            print_error(
                f"GetUserSPNs.py not found at {script_path}. "
                "Please check Impacket installation."
            )
            return None
        
        # Build command string
        cleaned_args = [strip_sensitive_markers(str(arg)) for arg in args]
        command_parts = [str(script_path)] + cleaned_args
        command = shlex.join(command_parts)
        
        # Add pipeline when request=True (like old_adscan.py line 26732)
        if request:
            pipeline = " | awk '{print $2}' | grep -vE 'Name|v0.|---|CCache|Principal:' | awk '!seen[$0]++' | awk 'NF'"
            command += pipeline
        
        # Show full command in debug output (no truncation)
        print_info_debug(f"[impacket] Running GetUserSPNs.py: {command}")
        
        # Execute command directly with pipeline
        result = self._execute_command(
            command,
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
                print_error(f"Cannot determine PDC for domain {mark_sensitive(domain, 'domain')}")
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

        return self.run(
            "GetNPUsers.py",
            args,
            ctx=ctx,
            timeout=timeout,
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

        return self.run(
            "secretsdump.py",
            args,
            ctx=ctx,
            timeout=timeout,
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
                return None

            # Normalize output
            if isinstance(result, subprocess.CompletedProcess):
                if result.stdout:
                    result.stdout = normalize_cli_output(result.stdout)
                if result.stderr:
                    result.stderr = normalize_cli_output(result.stderr)

            return result

        except subprocess.TimeoutExpired as exc:
            telemetry.capture_exception(exc)
            print_error_verbose(
                f"Impacket command timed out after {timeout if timeout is not None else 'unknown'}s: "
                f"{command}"
            )
            return None

        except Exception as exc:
            telemetry.capture_exception(exc)
            print_error_verbose(f"Error executing Impacket command: {command} - {exc}")
            return None
