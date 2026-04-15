"""MSSQL integration helpers.

Utility functions for working with NetExec MSSQL including:
- Authentication string building
- Command construction
- Credential formatting
"""

from __future__ import annotations

import shlex


def is_hash_authentication(password: str) -> bool:
    """Check if password is NTLM hash format.

    Args:
        password: Password or hash string

    Returns:
        True if appears to be NTLM hash (32 hex characters)
    """
    return len(password) == 32 and all(
        c in "0123456789abcdefABCDEF" for c in password
    )


def build_mssql_auth_string(
    username: str,
    password: str,
    domain: str | None = None,
) -> str:
    """Build authentication string for NetExec MSSQL.

    Args:
        username: Username
        password: Password or NTLM hash
        domain: Optional domain name

    Returns:
        Auth string formatted for NetExec (e.g., "-u 'user' -p 'pass' -d 'domain'")
    """
    # Check if hash authentication
    if is_hash_authentication(password):
        auth = f"-u '{username}' -H '{password}'"
    else:
        auth = f"-u '{username}' -p '{password}'"

    # Add domain if provided
    if domain:
        auth += f" -d '{domain}'"

    return auth


def build_mssql_execute_command(
    netexec_path: str,
    host: str,
    username: str,
    password: str,
    command: str,
    domain: str | None = None,
) -> str:
    """Build complete NetExec MSSQL command execution string.

    Args:
        netexec_path: Path to netexec executable
        host: Target host (IP or hostname)
        username: Username for authentication
        password: Password or NTLM hash
        command: Command to execute via xp_cmdshell
        domain: Optional domain name

    Returns:
        Complete command string ready for execution
    """
    auth_string = build_mssql_auth_string(username, password, domain)
    return f"{netexec_path} mssql '{host}' {auth_string} -x \"{command}\""


def build_mssql_module_command(
    netexec_path: str,
    host: str,
    username: str,
    password: str,
    module: str,
    options: dict[str, str] | None = None,
    domain: str | None = None,
) -> str:
    """Build a NetExec MSSQL module invocation.

    Args:
        netexec_path: Path to netexec executable.
        host: Target host.
        username: Username for authentication.
        password: Password or NTLM hash.
        module: NetExec MSSQL module name.
        options: Optional module arguments passed after one ``-o`` flag.
        domain: Optional domain.

    Returns:
        Complete command string ready for execution.
    """
    auth_string = build_mssql_auth_string(username, password, domain)
    command = f"{netexec_path} mssql '{host}' {auth_string} -M {shlex.quote(module)}"
    if options:
        joined_options = " ".join(
            f"{key}={shlex.quote(value)}" for key, value in options.items()
        )
        command += f" -o {joined_options}"
    return command


def escape_powershell_command(command: str) -> str:
    """Escape PowerShell command for safe execution.

    Args:
        command: PowerShell command to escape

    Returns:
        Escaped command string
    """
    # Escape double quotes and backticks
    escaped = command.replace('"', '\\"').replace("`", "``")
    return escaped


def check_priv_in_output(output: str, privilege_name: str) -> bool:
    """Check if a specific privilege appears in whoami /priv output.

    Args:
        output: Output from whoami /priv command
        privilege_name: Privilege to check for (e.g., "SeImpersonatePrivilege")

    Returns:
        True if privilege is present
    """
    return privilege_name in output
