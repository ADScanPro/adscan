"""MSSQL runner for NetExec command execution.

This module provides a unified interface for executing MSSQL commands
via NetExec with automatic error handling and output parsing.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional, Callable, Any
from pathlib import Path


logger = logging.getLogger(__name__)


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

        logger.info(
            "Executing MSSQL command",
            extra={
                "host": host,
                "username": username,
                "command": command,  # Log full command
            },
        )

        # Build command
        cmd_string = build_mssql_execute_command(
            netexec_path=ctx.netexec_path,
            host=host,
            username=username,
            password=password,
            command=command,
            domain=domain,
        )

        try:
            # Execute command
            result = ctx.command_runner(cmd_string, timeout)

            success = result.returncode == 0

            if not success:
                logger.warning(
                    "MSSQL command execution failed",
                    extra={
                        "host": host,
                        "returncode": result.returncode,
                        "stderr": result.stderr[:200] if result.stderr else None,
                    },
                )

            return ExecutionResult(
                stdout=result.stdout or "",
                stderr=result.stderr or "",
                returncode=result.returncode,
                success=success,
            )

        except Exception as e:
            logger.exception(
                "Exception during MSSQL command execution",
                extra={"host": host, "error": str(e)},
            )
            return None

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

        logger.info(
            "Checking SeImpersonatePrivilege",
            extra={"host": host, "username": username},
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
            logger.warning("Failed to execute whoami /priv")
            return False, None

        has_priv = check_seimpersonate_privilege(result.stdout)

        logger.info(
            f"SeImpersonatePrivilege check: {has_priv}",
            extra={"host": host, "has_privilege": has_priv},
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
        logger.info(
            "Executing encoded PowerShell",
            extra={"host": host, "username": username},
        )

        # PowerShell command to execute encoded payload
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

        logger.info("Testing xp_cmdshell availability", extra={"host": host})

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

        logger.info(
            f"xp_cmdshell test: {enabled}",
            extra={"host": host, "enabled": enabled},
        )

        return enabled
