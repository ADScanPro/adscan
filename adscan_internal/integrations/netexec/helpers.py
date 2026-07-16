from __future__ import annotations

import shlex


def build_nxc_plaintext_password_arg(password: str) -> str:
    """Build a CLI-safe NetExec password argument fragment.

    Args:
        password: Plaintext password value.

    Returns:
        Argument fragment suitable for insertion after the username.

    Notes:
        NetExec/argparse is sensitive to two edge-cases:
        - empty passwords must remain a separate ``-p ''`` pair
        - passwords starting with ``-`` must be bound as ``-p=<value>`` so the
          value is not parsed as another CLI flag
    """

    quoted_password = shlex.quote(password)
    if password == "":
        return f"-p {quoted_password}"
    if password.startswith("-"):
        return f"-p={quoted_password}"
    return f"-p {quoted_password}"


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
    if is_hash:
        auth += f"-H {password}"
    else:
        auth += build_nxc_plaintext_password_arg(password)

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
]
