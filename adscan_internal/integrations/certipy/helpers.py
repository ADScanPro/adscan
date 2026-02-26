"""Certipy integration helpers.

Utility functions for working with Certipy tools including:
- Authentication string building
"""

from __future__ import annotations


def build_auth_certipy(
    domain: str,
    username: str,
    password: str,
) -> str:
    """Build the authentication string for Certipy commands.

    Certipy accepts either clear-text passwords or NT hashes. When an NT hash
    is used, it is passed with the ``-hashes`` flag.

    Args:
        domain: Domain name.
        username: The username.
        password: The password or NT hash (32 hexadecimal characters).

    Returns:
        Authentication string suitable for appending to Certipy commands.
    """
    # Check if it is an NT hash (32 hexadecimal characters)
    is_hash = len(password) == 32 and all(
        c in "0123456789abcdef" for c in password.lower()
    )

    # Build the authentication part
    auth = f"-u '{username}'@{domain}"
    auth += f" -hashes :{password}" if is_hash else f" -p '{password}'"

    return auth


__all__ = [
    "build_auth_certipy",
]

