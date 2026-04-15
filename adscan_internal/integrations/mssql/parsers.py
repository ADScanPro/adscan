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


def has_authenticated_mssql_access(output: str) -> bool:
    """Return whether NetExec MSSQL output confirms valid authenticated access.

    For MSSQL post-auth workflows we treat the standard NetExec auth success
    marker ``[+] domain\\user:secret`` as sufficient to continue with low-priv
    follow-ups even when ``(Pwn3d!)`` is absent.
    """
    if not output:
        return False

    success_line = re.compile(r"^\s*MSSQL\b.*\[\+\]\s+\S+[:].*$", re.IGNORECASE)
    return any(success_line.search(line) for line in output.splitlines())


def parse_linked_servers(output: str) -> list[str]:
    """Parse NetExec ``enum_links`` output into a unique server list."""
    if not output:
        return []

    linked_servers: list[str] = []
    server_pattern = re.compile(r"^\s*ENUM_LINKS\b.*\[\*\]\s+-\s+(.+?)\s*$", re.IGNORECASE)
    for line in output.splitlines():
        match = server_pattern.search(line)
        if not match:
            continue
        server = str(match.group(1) or "").strip()
        if server and server not in linked_servers:
            linked_servers.append(server)
    return linked_servers


def parse_xp_cmdshell_enable_success(output: str) -> bool:
    """Return whether xp_cmdshell enablement succeeded."""
    if not output:
        return False

    normalized = output.lower()
    success_indicators = (
        "xp_cmdshell enabled",
        "configuration option 'xp_cmdshell' changed from 0 to 1",
    )
    failure_indicators = (
        "failed to enable xp_cmdshell",
        "do not have permission",
        "permission to run the reconfigure statement",
    )
    return any(marker in normalized for marker in success_indicators) and not any(
        marker in normalized for marker in failure_indicators
    )


def parse_xp_cmdshell_enable_failure_reason(output: str) -> str | None:
    """Return a user-facing reason when xp_cmdshell enablement fails.

    This parser focuses on premium UX rather than full T-SQL fidelity:
    it extracts the most actionable cause from common NetExec MSSQL module output.
    """
    if not output:
        return None

    normalized = output.lower()
    if (
        "do not have permission" in normalized
        or "permission to run the reconfigure statement" in normalized
        or "failed to enable xp_cmdshell" in normalized and "reconfigure" in normalized
    ):
        return "insufficient SQL privileges to run RECONFIGURE and enable xp_cmdshell"

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if "Failed to enable xp_cmdshell:" in line:
            return line.split("Failed to enable xp_cmdshell:", 1)[1].strip() or None

    if "xp_cmdshell is disabled" in normalized:
        return "xp_cmdshell is currently disabled and could not be enabled"

    return None


def parse_link_xpcmd_execution_success(output: str) -> bool:
    """Return whether NetExec reports command execution via linked server."""
    if not output:
        return False
    return "Executed command via linked server" in output


def parse_link_xpcmd_identity(output: str) -> str | None:
    """Extract the command identity returned by a successful linked ``whoami``.

    The output must already contain NetExec's linked execution success marker.
    Wrapper lines and obvious error lines are ignored.
    """
    if not parse_link_xpcmd_execution_success(output):
        return None

    ignored_tokens = (
        "MSSQL",
        "LINK_XPCMD",
        "[*]",
        "[+]",
        "[-]",
        "Please provide both LINKED_SERVER and CMD options.",
    )
    for raw_line in reversed(output.splitlines()):
        line = raw_line.strip()
        if not line:
            continue
        if any(token in line for token in ignored_tokens):
            continue
        return line
    return None


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
