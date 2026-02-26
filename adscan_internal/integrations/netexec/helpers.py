from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Callable


def is_valid_domain_name(candidate: str) -> bool:
    """Return True if candidate looks like a real AD domain name.

    This rejects IPs or IP fragments that NetExec commands may include after
    the service token (e.g. `smb 10.129.11.65` could be misparsed as
    hostname=10, domain=129.11.65).

    Args:
        candidate: Potential domain string.

    Returns:
        True if candidate looks like a domain name.
    """
    if not candidate:
        return False

    value = candidate.strip().strip("'\"")
    if not value:
        return False

    try:
        ipaddress.ip_address(value)
        return False
    except Exception:
        pass

    if re.fullmatch(r"[0-9.]+", value):
        return False

    if not re.search(r"[A-Za-z]", value):
        return False

    return True


def extract_domain_from_netexec_command(
    command: str,
    *,
    validate_domain: Callable[[str], bool] = is_valid_domain_name,
) -> tuple[str | None, list[str]]:
    """Extract a domain from a NetExec command string.

    Extraction priority:
    1) `-d` / `--domain` parameter when present
    2) FQDN after service token (e.g. `smb forest.htb.local` -> `htb.local`)

    Args:
        command: Command string to analyze.
        validate_domain: Callable used to validate the extracted domain.

    Returns:
        Tuple of (domain_or_none, debug_messages).
    """
    debug: list[str] = []
    if not command:
        return None, debug

    match = re.search(
        r'(?:-d|--domain)\s+(?:["\']([^"\']+)["\']|([a-zA-Z0-9.-]+))',
        command,
    )
    if match:
        candidate = (match.group(1) or match.group(2) or "").strip()
        if candidate and validate_domain(candidate):
            debug.append(
                "Found domain from -d/--domain parameter: " + candidate,
            )
            return candidate, debug
        if candidate:
            debug.append(
                "Ignoring invalid domain from -d/--domain parameter: " + candidate,
            )

    services = [
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
    ]

    for service in services:
        pattern = rf"\b{re.escape(service)}\s+([a-zA-Z0-9-]+)\.([a-zA-Z0-9.-]+)"
        match = re.search(pattern, command)
        if not match:
            continue

        hostname = match.group(1)
        domain = match.group(2)

        if domain and validate_domain(domain):
            debug.append(
                f"Found FQDN after {service}: {hostname}.{domain} -> extracted domain: {domain}"
            )
            return domain, debug

        if domain:
            debug.append(
                f"Ignoring invalid domain from FQDN after {service}: {hostname}.{domain}"
            )
        else:
            debug.append(f"Found FQDN after {service} but domain part is empty")

    debug.append(
        "Could not extract domain from command (no FQDN pattern found, only IP/hostname)."
    )
    return None, debug


def detect_output_redirection(command: str) -> tuple[bool, str | None]:
    """Detect if a command has output redirection to a file.

    Detects redirections like:
    - `> file.txt`
    - `>> file.txt`
    - `> file.txt 2>&1`
    - `>> file.txt 2>&1`

    Args:
        command: Command string to analyze.

    Returns:
        Tuple of (has_redirection, file_path_or_none).
    """
    if not command:
        return False, None

    redirection_patterns = [
        r">>\s+([^\s|&;<>]+)(?:\s+2>&1)?",
        r">\s+([^\s|&;<>]+)(?:\s+2>&1)?",
    ]

    last_match = None
    last_match_pos = -1

    for pattern in redirection_patterns:
        for match in re.finditer(pattern, command):
            if match.start() > last_match_pos:
                last_match = match
                last_match_pos = match.start()

    if not last_match:
        return False, None

    file_path = last_match.group(1).strip().strip("\"'")
    if file_path.isdigit():
        return False, None
    if file_path and not file_path.startswith("-"):
        return True, file_path

    return False, None


def redirected_file_has_content(
    file_path: str,
    *,
    expand_user: Callable[[str], str],
) -> bool:
    """Return True if a redirected output file exists and has meaningful content."""
    if not file_path:
        return False

    try:
        expanded_path = expand_user(file_path)
        if not os.path.isabs(expanded_path):
            expanded_path = os.path.abspath(expanded_path)

        if not os.path.exists(expanded_path):
            return False
        if os.path.getsize(expanded_path) == 0:
            return False

        try:
            with open(expanded_path, "r", encoding="utf-8", errors="ignore") as handle:
                first_chunk = handle.read(1024)
                return bool(first_chunk.strip())
        except Exception:
            return os.path.getsize(expanded_path) > 0
    except Exception:
        return False


def build_auth_nxc(
    username: str,
    password: str,
    domain: str | None = None,
    kerberos: bool = False,
) -> str:
    """Build the authentication string for NetExec (nxc) commands.

    NetExec accepts either clear-text passwords or NT hashes. When an NT hash
    is used, it is passed with the ``-H`` flag instead of ``-p``.

    Args:
        username: The username.
        password: The password or NT hash (32 hexadecimal characters).
        domain: Optional domain name. When provided, NetExec will use domain
            authentication; otherwise ``--local-auth`` should be used by the caller.
        kerberos: Whether to append the ``-k`` flag for Kerberos authentication.

    Returns:
        Authentication string suitable for appending to NetExec commands.
    """
    # Check if it is an NT hash (32 hexadecimal characters)
    is_hash = len(password) == 32 and all(
        c in "0123456789abcdef" for c in password.lower()
    )

    # Build the authentication part
    auth = f"-u '{username}' "
    auth += f"-H {password}" if is_hash else f"-p '{password}'"

    # Add the domain if provided
    if domain:
        auth += f" -d {domain}"

        if kerberos:
            auth += " -k"
    else:
        auth += " --local-auth"

    return auth


__all__ = [
    "build_auth_nxc",
    "detect_output_redirection",
    "extract_domain_from_netexec_command",
    "is_valid_domain_name",
    "redirected_file_has_content",
]
