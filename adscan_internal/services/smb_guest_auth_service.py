"""Shared SMB guest-session authentication helpers.

This module centralizes the transport username used for guest-session SMB
operations across NetExec, Impacket, and any future SMB backends.
"""

from __future__ import annotations

from typing import Any
import os


DEFAULT_SMB_GUEST_USERNAME = "ADscan"
_GUEST_ALIAS_VALUES = {"guest", "anonymous"}


def is_guest_alias(username: str | None) -> bool:
    """Return True when username represents a guest/anonymous logical identity."""
    lowered = str(username or "").strip().lower()
    return lowered in _GUEST_ALIAS_VALUES


def resolve_smb_guest_username(
    *,
    shell: Any | None = None,
    domain: str | None = None,
) -> str:
    """Resolve the concrete SMB username to use for guest-session transport.

    Resolution order:
    1. Per-domain override: ``domains_data[domain]["guest_username"]``.
    2. Shell-level override: ``shell.smb_guest_username``.
    3. Environment override: ``ADSCAN_SMB_GUEST_USERNAME``.
    4. Built-in default: ``ADscan``.
    """
    if shell is not None and domain:
        domains_data = (
            shell.domains_data
            if hasattr(shell, "domains_data") and isinstance(shell.domains_data, dict)
            else {}
        )
        domain_data = domains_data.get(domain, {})
        if isinstance(domain_data, dict):
            domain_override = str(domain_data.get("guest_username", "")).strip()
            if domain_override:
                return domain_override

    if shell is not None:
        shell_override = str(getattr(shell, "smb_guest_username", "") or "").strip()
        if shell_override:
            return shell_override

    env_override = os.getenv("ADSCAN_SMB_GUEST_USERNAME", "").strip()
    if env_override:
        return env_override

    return DEFAULT_SMB_GUEST_USERNAME

