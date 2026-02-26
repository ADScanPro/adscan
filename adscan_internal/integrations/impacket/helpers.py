"""Impacket integration helpers.

Utility functions for working with Impacket tools including:
- Path resolution
- Output file management
- Credential formatting
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


def get_impacket_script_path(scripts_dir: str | Path, script_name: str) -> Path:
    """Get full path to an Impacket script.

    Args:
        scripts_dir: Directory containing Impacket scripts
        script_name: Name of script (e.g., 'GetUserSPNs.py')

    Returns:
        Full path to the script
    """
    return Path(scripts_dir) / script_name


def validate_impacket_script(scripts_dir: str | Path, script_name: str) -> bool:
    """Check if an Impacket script exists and is executable.

    Args:
        scripts_dir: Directory containing Impacket scripts
        script_name: Name of script to validate

    Returns:
        True if script exists and is executable
    """
    script_path = get_impacket_script_path(scripts_dir, script_name)
    return script_path.is_file() and os.access(script_path, os.X_OK)


def format_hashes_for_impacket(lm_hash: Optional[str], ntlm_hash: str) -> str:
    """Format NTLM hashes for Impacket tools.

    Args:
        lm_hash: LM hash (optional, use empty string if not available)
        ntlm_hash: NTLM hash

    Returns:
        Formatted hash string (format: LM:NT)
    """
    lm = lm_hash if lm_hash else ""
    return f"{lm}:{ntlm_hash}"


def get_output_file_path(
    workspace: str | Path,
    domain: str,
    filename: str,
) -> Path:
    """Get path for Impacket output file.

    Constructs output path following workspace structure:
    workspace/domains/{domain}/{filename}

    Args:
        workspace: Workspace root directory
        domain: Domain name
        filename: Output filename

    Returns:
        Full path to output file
    """
    output_dir = Path(workspace) / "domains" / domain
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir / filename


def parse_domain_user(username: str) -> tuple[Optional[str], str]:
    """Parse domain\\user or user@domain format.

    Args:
        username: Username in various formats

    Returns:
        Tuple of (domain, username) where domain may be None
    """
    # Check for DOMAIN\\user format
    if "\\" in username:
        parts = username.split("\\", 1)
        return parts[0], parts[1]

    # Check for user@DOMAIN format
    if "@" in username:
        parts = username.split("@", 1)
        return parts[1], parts[0]

    # Just username, no domain
    return None, username


def build_auth_string(
    username: str,
    password: Optional[str] = None,
    domain: Optional[str] = None,
) -> str:
    """Build authentication string for Impacket tools.

    Args:
        username: Username
        password: Password (optional)
        domain: Domain name (optional)

    Returns:
        Formatted auth string (e.g., 'DOMAIN/user:pass' or 'user')
    """
    if domain:
        prefix = f"{domain}/{username}"
    else:
        prefix = username

    if password:
        return f"{prefix}:{password}"

    return prefix


def build_auth_impacket(
    username: str,
    password: str,
    domain: str,
    pdc_hostname: str | None = None,
    pdc_ip: str | None = None,
    kerberos: bool = False,
) -> str:
    """Build authentication string for Impacket tools with full domain context.

    This function handles various authentication methods:
    - Password authentication
    - NTLM hash authentication
    - Kerberos ticket (.ccache file)
    - Kerberos flag

    Args:
        username: Username for authentication.
        password: Password, NT hash (32 hex chars), or .ccache file path.
        domain: Domain name.
        pdc_hostname: Optional PDC hostname (used for .ccache authentication).
        pdc_ip: Optional PDC IP address (used for password/hash authentication).
        kerberos: Whether to append the ``-k`` flag for Kerberos authentication.

    Returns:
        Authentication string formatted for Impacket tools.
    """
    # Check if it is a .ccache file
    if password.lower().endswith(".ccache"):
        # Specific authentication for .ccache files with Kerberos
        if pdc_hostname:
            auth = f"-k -no-pass {domain}/'{username}'@{pdc_hostname}"
        else:
            auth = f"-k -no-pass {domain}/'{username}'"
    else:
        # Check if it is an NT hash (32 hexadecimal characters)
        is_hash = len(password) == 32 and all(
            c in "0123456789abcdef" for c in password.lower()
        )

        # Build the authentication part
        auth = f"{domain}/'{username}'"
        if pdc_ip:
            auth += (
                f"@{pdc_ip} -hashes :{password}"
                if is_hash
                else f":'{password}'@{pdc_ip}"
            )
        else:
            auth += f" -hashes :{password}" if is_hash else f":'{password}'"

    if kerberos:
        auth += " -k"
    return auth


def build_auth_impacket_no_host(
    username: str,
    password: str,
    domain: str,
    kerberos: bool = False,
) -> str:
    """Build authentication string for Impacket tools without host specification.

    This is a simplified version that doesn't include PDC hostname/IP in the
    authentication string. Useful for tools that determine the target host
    independently.

    Args:
        username: Username for authentication.
        password: Password or NT hash (32 hexadecimal characters).
        domain: Domain name.
        kerberos: Whether to append the ``-k`` flag for Kerberos authentication.

    Returns:
        Authentication string formatted for Impacket tools.
    """
    # Check if it is an NT hash (32 hexadecimal characters)
    is_hash = len(password) == 32 and all(
        c in "0123456789abcdef" for c in password.lower()
    )

    # Build the authentication part
    auth = f"{domain}/'{username}'"
    auth += f" -hashes :{password}" if is_hash else f":'{password}'"

    if kerberos:
        auth += " -k"
    return auth
