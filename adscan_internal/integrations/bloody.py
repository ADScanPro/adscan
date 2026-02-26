"""BloodyAD integration helpers.

This module provides small, reusable utilities for building BloodyAD command
lines and (in future steps) running them in a way that is reusable from both
the legacy CLI in ``adscan.py`` and the service layer.

For now it exposes :func:`build_auth_bloody`, which encapsulates the logic for
constructing the authentication string used by BloodyAD.
"""

from __future__ import annotations

import ipaddress


def build_auth_bloody(
    username: str,
    password: str,
    domain: str | None = None,
    kerberos: bool = False,
) -> str:
    """Build the authentication string for BloodyAD commands.

    BloodyAD accepts either clear-text passwords or NT hashes. When an NT hash
    is used it must be prefixed with a colon in the ``-p`` argument.

    Args:
        username: The username.
        password: The password or NT hash (32 hexadecimal characters).
        domain: Optional domain name. When provided, BloodyAD will use domain
            authentication; otherwise ``--local-auth`` semantics should be used
            by the caller if desired.
        kerberos: Whether to append the ``-k`` flag for Kerberos auth.

    Returns:
        Authentication string suitable for appending to BloodyAD commands.
    """
    # Detect if the password looks like an NT hash (32 hex chars).
    is_hash = len(password) == 32 and all(c in "0123456789abcdef" for c in password.lower())

    parts: list[str] = []

    if domain:
        parts.append(f"-d {domain}")

    parts.append(f"-u '{username}'")

    if is_hash:
        if kerberos:
            parts.append(f"-p '{password}'")
            parts.append("-f rc4")
        else:
            parts.append(f"-p ':{password}'")
    else:
        parts.append(f"-p '{password}'")

    if kerberos:
        parts.append("-k")

    # Join with spaces and ensure a leading space so callers can embed it
    # naturally into larger command strings if they wish.
    return " ".join(parts)


def resolve_bloody_host(
    *,
    pdc_ip: str | None,
    pdc_hostname: str | None,
    domain: str | None,
    kerberos: bool,
) -> str | None:
    """Resolve the host value for BloodyAD, preferring FQDN for Kerberos.

    Args:
        pdc_ip: PDC IP address.
        pdc_hostname: PDC hostname (short or FQDN).
        domain: Domain name.
        kerberos: Whether Kerberos auth is requested.

    Returns:
        Host string suitable for ``--host`` or None if nothing available.
    """
    hostname = (pdc_hostname or "").strip()
    if kerberos and hostname:
        if "." in hostname:
            return hostname
        if domain:
            return f"{hostname}.{domain}"
        return hostname

    if hostname:
        return hostname

    if pdc_ip:
        try:
            ipaddress.ip_address(pdc_ip)
            return pdc_ip
        except ValueError:
            return pdc_ip
    return None


__all__ = [
    "build_auth_bloody",
    "resolve_bloody_host",
]
