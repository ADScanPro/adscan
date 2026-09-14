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


def is_credential_less_reader_identity(
    username: str | None,
    *,
    shell: Any | None = None,
    domain: str | None = None,
) -> bool:
    """Return True when ``username`` names a credential-less (guest/null) reader.

    The reading identity of a scan is what actually authenticated the SMB bind
    that read a file — it is NOT the same thing as "an ambient credential-less
    scope happens to be open somewhere above on the call stack" (a scope that
    can legitimately outlive the guest read it was opened for, when the
    downstream credential-hunt chain re-authenticates as a newly-recovered
    domain user and reads further shares synchronously inside it).

    A reader identity is credential-less when it is one of:

    * Empty/blank/``None`` — a null/anonymous SMB session carries no username.
    * A literal guest alias (:func:`is_guest_alias`: ``"guest"``/``"anonymous"``).
    * The resolved guest transport username for this domain
      (:func:`resolve_smb_guest_username` — the made-up identity ADscan itself
      uses for its guest-session bind, e.g. the built-in ``"ADscan"`` default
      or a per-domain/shell/env override).

    Any other value is a real, authenticated domain (or local) principal, so
    it returns ``False``.
    """
    text = str(username or "").strip()
    if not text:
        return True
    if is_guest_alias(text):
        return True
    guest_username = resolve_smb_guest_username(shell=shell, domain=domain)
    return text.lower() == guest_username.strip().lower()


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

