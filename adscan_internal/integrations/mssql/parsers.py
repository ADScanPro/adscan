"""MSSQL output parsers.

This module provides parsers for NetExec MSSQL command outputs including:
- whoami /priv (privilege enumeration)
- Command execution results
- Privilege verification

These parsers are resilient to output format variations and focus on
extracting structured data from MSSQL command execution.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class WindowsPrivilege:
    """Parsed Windows privilege entry."""

    name: str
    description: str
    state: str  # "Enabled", "Disabled", "Enabled by Default"


@dataclass(frozen=True)
class CommandResult:
    """Parsed command execution result."""

    success: bool
    output: str
    error: Optional[str] = None


def parse_whoami_priv_output(output: str) -> List[WindowsPrivilege]:
    """Parse whoami /priv output for Windows privileges.

    Extracts privilege information from the output of `whoami /priv` command
    executed via NetExec MSSQL.

    Args:
        output: Command stdout/stderr text

    Returns:
        List of parsed WindowsPrivilege entries
    """
    if not output:
        return []

    privileges: List[WindowsPrivilege] = []
    lines = output.splitlines()

    # Pattern for privilege lines:
    # SeImpersonatePrivilege        Impersonate a client after authentication  Enabled
    privilege_pattern = re.compile(
        r"^(Se\w+Privilege)\s+(.*?)\s+(Enabled|Disabled|Enabled by Default)\s*$",
        re.IGNORECASE,
    )

    for line in lines:
        line = line.strip()
        if not line:
            continue

        match = privilege_pattern.match(line)
        if match:
            name = match.group(1)
            description = match.group(2).strip()
            state = match.group(3)

            privileges.append(
                WindowsPrivilege(name=name, description=description, state=state)
            )

    return privileges


def check_seimpersonate_privilege(output: str) -> bool:
    """Check if SeImpersonatePrivilege is present and enabled in output.

    Args:
        output: Output from whoami /priv command

    Returns:
        True if SeImpersonatePrivilege is enabled
    """
    if not output:
        return False

    # Parse privileges
    privileges = parse_whoami_priv_output(output)

    # Check for SeImpersonatePrivilege
    for priv in privileges:
        if priv.name == "SeImpersonatePrivilege":
            return "Enabled" in priv.state

    # Fallback: simple string search
    return "SeImpersonatePrivilege" in output and (
        "Enabled" in output or "Habilitado" in output  # Spanish Windows
    )


def parse_command_output(output: str, command: str) -> CommandResult:
    """Parse generic command execution output from NetExec MSSQL.

    Args:
        output: Command stdout/stderr
        command: Original command executed

    Returns:
        CommandResult with parsed information
    """
    if not output:
        return CommandResult(success=False, output="", error="No output received")

    # Check for common error indicators
    error_indicators = [
        "error",
        "failed",
        "denied",
        "unable to",
        "cannot",
        "not found",
        "access denied",
    ]

    output_lower = output.lower()
    has_error = any(indicator in output_lower for indicator in error_indicators)

    if has_error:
        return CommandResult(
            success=False, output=output, error="Command execution error detected"
        )

    return CommandResult(success=True, output=output, error=None)


def extract_netexec_mssql_output(output: str) -> str:
    """Extract clean command output from NetExec MSSQL wrapper output.

    NetExec adds MSSQL protocol markers and formatting. This function
    strips those to return only the actual command output.

    Args:
        output: Full NetExec output

    Returns:
        Cleaned command output
    """
    if not output:
        return ""

    lines = output.splitlines()
    clean_lines = []

    # Skip NetExec header lines and extract actual command output
    skip_patterns = ["MSSQL", "[*]", "[+]", "[-]"]

    for line in lines:
        line_stripped = line.strip()
        if not line_stripped:
            continue

        # Skip NetExec protocol markers
        if any(pattern in line for pattern in skip_patterns):
            # But keep lines that look like actual output
            if ":" in line and len(line.split(":")[-1].strip()) > 10:
                clean_lines.append(line.split(":")[-1].strip())
            continue

        clean_lines.append(line_stripped)

    return "\n".join(clean_lines)


def check_xp_cmdshell_enabled(output: str) -> bool:
    """Check if xp_cmdshell is enabled based on command output.

    Args:
        output: Command execution output

    Returns:
        True if xp_cmdshell appears to be enabled and working
    """
    if not output:
        return False

    # Successful command execution indicates xp_cmdshell is enabled
    error_indicators = [
        "xp_cmdshell is disabled",
        "blocked by",
        "not enabled",
        "configuration option 'xp_cmdshell' changed",
    ]

    output_lower = output.lower()
    return not any(indicator in output_lower for indicator in error_indicators)


def check_xp_cmdshell_disabled(output: str) -> bool:
    """Check if xp_cmdshell appears to be disabled based on output.

    This is a compatibility helper used by some unit tests.

    Args:
        output: Command execution output

    Returns:
        True if xp_cmdshell appears to be disabled.
    """
    return not check_xp_cmdshell_enabled(output)
