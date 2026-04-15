"""MSSQL runner for NetExec command execution.

This module provides a unified interface for executing MSSQL commands
via NetExec with automatic error handling and output parsing.
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from typing import Optional, Callable, Any
from pathlib import Path

from adscan_internal.command_runner import build_execution_output_preview, build_text_preview
from adscan_internal.execution_outcomes import (
    build_timeout_completed_process,
    result_is_timeout,
)
from adscan_internal.rich_output import mark_sensitive, print_info_debug


@dataclass(frozen=True)
class ExecutionResult:
    """Result from MSSQL command execution.

    Attributes:
        stdout: Standard output from command
        stderr: Standard error from command
        returncode: Command exit code
        success: Whether command succeeded
    """

    stdout: str
    stderr: str
    returncode: int
    success: bool


@dataclass(frozen=True)
class MSSQLContext:
    """Dependencies required to run NetExec MSSQL commands.

    Attributes:
        netexec_path: Path to netexec executable
        command_runner: Function to execute shell commands
                       Signature: (command: str, timeout: int) -> subprocess.CompletedProcess
        workspace_dir: Optional workspace directory for output files
    """

    netexec_path: str
    command_runner: Callable[[str, int], Any]
    workspace_dir: Optional[Path] = None


class MSSQLRunner:
    """Runner for NetExec MSSQL commands with automatic error handling.

    This runner provides high-level methods for common MSSQL operations
    including command execution and privilege verification.
    """

    def execute_command(
        self,
        host: str,
        *,
        ctx: MSSQLContext,
        username: str,
        password: str,
        command: str,
        domain: Optional[str] = None,
        timeout: int = 120,
    ) -> ExecutionResult | None:
        """Execute remote command via NetExec MSSQL.

        Uses xp_cmdshell to execute commands on the target MSSQL server.

        Args:
            host: Target host (IP or hostname)
            ctx: MSSQLContext with paths and command runner
            username: Username for authentication
            password: Password or NTLM hash
            command: Command to execute
            domain: Optional domain name
            timeout: Command timeout in seconds

        Returns:
            ExecutionResult with command output, or None on failure
        """
        from .helpers import build_mssql_execute_command

        cmd_string = build_mssql_execute_command(
            netexec_path=ctx.netexec_path,
            host=host,
            username=username,
            password=password,
            command=command,
            domain=domain,
        )
        cmd_preview = build_text_preview(command, head=10, tail=5)
        print_info_debug(
            f"[mssql_runner] execute_command host={mark_sensitive(host, 'hostname')} "
            f"user={mark_sensitive(username, 'user')} "
            f"cmd={mark_sensitive(cmd_preview or command, 'text')}"
        )
        started_at = time.perf_counter()
        try:
            result = ctx.command_runner(cmd_string, timeout)
            elapsed = time.perf_counter() - started_at
            timed_out = result_is_timeout(result, tool_name="netexec_mssql")
            success = result.returncode == 0
            stdout_lines = [ln for ln in (result.stdout or "").splitlines() if ln.strip()]
            stderr_lines = [ln for ln in (result.stderr or "").splitlines() if ln.strip()]
            print_info_debug(
                f"[mssql_runner] result host={mark_sensitive(host, 'hostname')} "
                f"success={success} timed_out={timed_out} "
                f"stdout_lines={len(stdout_lines)} stderr_lines={len(stderr_lines)} "
                f"returncode={result.returncode} duration={elapsed:.3f}s"
            )
            output_preview = build_execution_output_preview(
                result, stdout_head=12, stdout_tail=12, stderr_head=12, stderr_tail=12
            )
            if output_preview:
                print_info_debug(
                    "[mssql_runner] output preview:\n"
                    + mark_sensitive(output_preview, "text"),
                    panel=True,
                )
            return ExecutionResult(
                stdout=result.stdout or "",
                stderr=result.stderr or "",
                returncode=result.returncode,
                success=success,
            )
        except subprocess.TimeoutExpired:
            elapsed = time.perf_counter() - started_at
            print_info_debug(
                f"[mssql_runner] TimeoutExpired host={mark_sensitive(host, 'hostname')} "
                f"duration={elapsed:.3f}s timeout={timeout}s"
            )
            timeout_result = build_timeout_completed_process(
                cmd_string, tool_name="netexec_mssql"
            )
            return ExecutionResult(
                stdout=timeout_result.stdout or "",
                stderr=timeout_result.stderr or "",
                returncode=timeout_result.returncode,
                success=False,
            )
        except Exception as exc:
            elapsed = time.perf_counter() - started_at
            print_info_debug(
                f"[mssql_runner] exception host={mark_sensitive(host, 'hostname')} "
                f"error={mark_sensitive(str(exc), 'detail')} duration={elapsed:.3f}s"
            )
            return None

    def execute_module(
        self,
        host: str,
        *,
        ctx: MSSQLContext,
        username: str,
        password: str,
        module: str,
        options: dict[str, str] | None = None,
        domain: Optional[str] = None,
        timeout: int = 120,
    ) -> ExecutionResult | None:
        """Execute a NetExec MSSQL module."""
        from .helpers import build_mssql_module_command

        cmd_string = build_mssql_module_command(
            netexec_path=ctx.netexec_path,
            host=host,
            username=username,
            password=password,
            module=module,
            options=options,
            domain=domain,
        )
        try:
            result = ctx.command_runner(cmd_string, timeout)
            if result_is_timeout(result, tool_name="netexec_mssql"):
                print_info_debug(
                    f"[mssql_runner] module timed out host={mark_sensitive(host, 'hostname')} "
                    f"module={mark_sensitive(module, 'text')} timeout={timeout}s"
                )
            success = result.returncode == 0
            return ExecutionResult(
                stdout=result.stdout or "",
                stderr=result.stderr or "",
                returncode=result.returncode,
                success=success,
            )
        except subprocess.TimeoutExpired:
            timeout_result = build_timeout_completed_process(
                cmd_string, tool_name="netexec_mssql"
            )
            return ExecutionResult(
                stdout=timeout_result.stdout or "",
                stderr=timeout_result.stderr or "",
                returncode=timeout_result.returncode,
                success=False,
            )
        except Exception as exc:
            print_info_debug(
                f"[mssql_runner] module exception host={mark_sensitive(host, 'hostname')} "
                f"module={mark_sensitive(module, 'text')} "
                f"error={mark_sensitive(str(exc), 'detail')}"
            )
            return None

    def verify_authentication(
        self,
        host: str,
        *,
        ctx: MSSQLContext,
        username: str,
        password: str,
        domain: Optional[str] = None,
        timeout: int = 60,
    ) -> tuple[bool, Optional[str]]:
        """Check whether NetExec MSSQL confirms valid authenticated access."""
        from .helpers import build_mssql_auth_string
        from .parsers import has_authenticated_mssql_access

        auth = build_mssql_auth_string(username, password, domain)
        command = f"{ctx.netexec_path} mssql '{host}' {auth}"
        try:
            result = ctx.command_runner(command, timeout)
        except subprocess.TimeoutExpired:
            timeout_result = build_timeout_completed_process(
                command, tool_name="netexec_mssql"
            )
            return False, timeout_result.stderr
        except Exception as exc:
            print_info_debug(
                f"[mssql_runner] auth verification exception host={mark_sensitive(host, 'hostname')} "
                f"error={mark_sensitive(str(exc), 'detail')}"
            )
            return False, None

        output = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
        return has_authenticated_mssql_access(output), output

    def check_seimpersonate_privilege(
        self,
        host: str,
        *,
        ctx: MSSQLContext,
        username: str,
        password: str,
        domain: Optional[str] = None,
        timeout: int = 60,
    ) -> tuple[bool, Optional[str]]:
        """Check if SeImpersonatePrivilege is available.

        Executes 'whoami /priv' and checks for SeImpersonatePrivilege.

        Args:
            host: Target host
            ctx: MSSQLContext
            username: Username for authentication
            password: Password or NTLM hash
            domain: Optional domain
            timeout: Timeout in seconds

        Returns:
            Tuple of (has_privilege: bool, output: Optional[str])
        """
        from .parsers import check_seimpersonate_privilege

        print_info_debug(
            f"[mssql_runner] check_seimpersonate host={mark_sensitive(host, 'hostname')} "
            f"user={mark_sensitive(username, 'user')}"
        )
        result = self.execute_command(
            host=host,
            ctx=ctx,
            username=username,
            password=password,
            command="whoami /priv",
            domain=domain,
            timeout=timeout,
        )
        if not result:
            print_info_debug(f"[mssql_runner] check_seimpersonate: execute_command returned None host={mark_sensitive(host, 'hostname')}")
            return False, None
        has_priv = check_seimpersonate_privilege(result.stdout)
        print_info_debug(
            f"[mssql_runner] check_seimpersonate result host={mark_sensitive(host, 'hostname')} "
            f"has_privilege={has_priv}"
        )
        return has_priv, result.stdout

    def execute_powershell_encoded(
        self,
        host: str,
        *,
        ctx: MSSQLContext,
        username: str,
        password: str,
        encoded_command: str,
        domain: Optional[str] = None,
        timeout: int = 300,
    ) -> ExecutionResult | None:
        """Execute encoded PowerShell command.

        Args:
            host: Target host
            ctx: MSSQLContext
            username: Username for authentication
            password: Password or NTLM hash
            encoded_command: Base64 encoded PowerShell command
            domain: Optional domain
            timeout: Timeout in seconds

        Returns:
            ExecutionResult or None on failure
        """
        print_info_debug(
            f"[mssql_runner] execute_powershell_encoded host={mark_sensitive(host, 'hostname')} "
            f"user={mark_sensitive(username, 'user')}"
        )
        ps_command = f"powershell.exe -EncodedCommand {encoded_command}"

        return self.execute_command(
            host=host,
            ctx=ctx,
            username=username,
            password=password,
            command=ps_command,
            domain=domain,
            timeout=timeout,
        )

    def test_xp_cmdshell(
        self,
        host: str,
        *,
        ctx: MSSQLContext,
        username: str,
        password: str,
        domain: Optional[str] = None,
        timeout: int = 30,
    ) -> bool:
        """Test if xp_cmdshell is enabled and accessible.

        Args:
            host: Target host
            ctx: MSSQLContext
            username: Username
            password: Password or hash
            domain: Optional domain
            timeout: Timeout in seconds

        Returns:
            True if xp_cmdshell is enabled and working
        """
        from .parsers import check_xp_cmdshell_enabled

        print_info_debug(f"[mssql_runner] test_xp_cmdshell host={mark_sensitive(host, 'hostname')}")
        result = self.execute_command(
            host=host,
            ctx=ctx,
            username=username,
            password=password,
            command="whoami",
            domain=domain,
            timeout=timeout,
        )
        if not result:
            return False
        enabled = check_xp_cmdshell_enabled(result.stdout)
        print_info_debug(
            f"[mssql_runner] test_xp_cmdshell result host={mark_sensitive(host, 'hostname')} enabled={enabled}"
        )
        return enabled

    def enable_xp_cmdshell(
        self,
        host: str,
        *,
        ctx: MSSQLContext,
        username: str,
        password: str,
        domain: Optional[str] = None,
        timeout: int = 120,
    ) -> tuple[bool, Optional[ExecutionResult]]:
        """Attempt to enable local xp_cmdshell via NetExec MSSQL module."""
        from .parsers import parse_xp_cmdshell_enable_success

        result = self.execute_module(
            host=host,
            ctx=ctx,
            username=username,
            password=password,
            module="enable_cmdshell",
            options={"ACTION": "enable"},
            domain=domain,
            timeout=timeout,
        )
        if not result:
            return False, None
        return parse_xp_cmdshell_enable_success(result.stdout), result

    def enum_linked_servers(
        self,
        host: str,
        *,
        ctx: MSSQLContext,
        username: str,
        password: str,
        domain: Optional[str] = None,
        timeout: int = 120,
    ) -> tuple[list[str], Optional[ExecutionResult]]:
        """Enumerate linked SQL servers via NetExec MSSQL module."""
        from .parsers import parse_linked_servers

        result = self.execute_module(
            host=host,
            ctx=ctx,
            username=username,
            password=password,
            module="enum_links",
            domain=domain,
            timeout=timeout,
        )
        if not result:
            return [], None
        return parse_linked_servers(result.stdout), result

    def enable_linked_xp_cmdshell(
        self,
        host: str,
        *,
        ctx: MSSQLContext,
        username: str,
        password: str,
        linked_server: str,
        domain: Optional[str] = None,
        timeout: int = 120,
    ) -> tuple[bool, Optional[ExecutionResult]]:
        """Attempt to enable xp_cmdshell on one linked SQL server."""
        from .parsers import parse_xp_cmdshell_enable_success

        result = self.execute_module(
            host=host,
            ctx=ctx,
            username=username,
            password=password,
            module="link_enable_cmdshell",
            options={"LINKED_SERVER": linked_server},
            domain=domain,
            timeout=timeout,
        )
        if not result:
            return False, None
        return parse_xp_cmdshell_enable_success(result.stdout), result

    def execute_linked_command(
        self,
        host: str,
        *,
        ctx: MSSQLContext,
        username: str,
        password: str,
        linked_server: str,
        command: str,
        domain: Optional[str] = None,
        timeout: int = 300,
    ) -> ExecutionResult | None:
        """Execute one command via xp_cmdshell on a linked SQL server."""
        return self.execute_module(
            host=host,
            ctx=ctx,
            username=username,
            password=password,
            module="link_xpcmd",
            options={"LINKED_SERVER": linked_server, "CMD": command},
            domain=domain,
            timeout=timeout,
        )
