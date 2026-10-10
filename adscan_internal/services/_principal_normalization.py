"""Low-level, pure delimiter-splitting primitives for an AD principal string.

An AD principal (a username) can arrive qualified in one of two forms besides
a bare ``sAMAccountName``:

- NetBIOS-qualified: ``DOMAIN\\user`` (e.g. what Windows' own Credential
  Manager stores verbatim for a domain credential).
- UPN-qualified: ``user@domain`` (e.g. hashcat's cracked kerberoast/AS-REP
  output, keyed by ``--username``).

This module ONLY splits on the delimiter — it does not lowercase, strip
whitespace, or apply any domain-mismatch policy. That policy is deliberately
left to each caller, because the codebase has (at least) two genuinely
different use cases that must NOT be forced to agree:

- Sanitize-before-store (``adscan_internal/cli/creds.py::add_credential``):
  preserves case, warns on a domain mismatch, never strips an SPN-style
  ``/realm`` suffix (a ``service/host`` SPN is not a username to sanitize).
- Compare-already-stored (the ``_normalize_principal*`` helpers in
  ``_kerberos_ccache_guard.py``, ``_kerberos_recovery.py``, and
  ``credential_provenance_databinding.py``): lowercases for
  case-insensitive comparison, and one of them additionally strips an
  SPN-style ``/realm`` suffix.

Keeping the delimiter-splitting here as a single source of truth means a
future caller gets the exact same splitting semantics as every existing one,
while each caller keeps the policy (case, warnings, SPN handling) that is
correct for its own purpose.
"""

from __future__ import annotations

__all__ = ["split_netbios_qualifier", "split_upn_qualifier"]


def split_netbios_qualifier(value: str) -> tuple[str, str]:
    """Split a possibly NetBIOS-qualified principal on the FIRST backslash.

    Mirrors ``value.split("\\\\", 1)`` exactly: when ``value`` contains no
    backslash, the whole string is returned as the bare part with an empty
    prefix. When it does, the prefix is everything before the first
    backslash and the bare part is everything after it — no stripping, no
    case-folding.

    Args:
        value: The raw principal string, e.g. ``"DOMAIN\\\\user"`` or
            ``"user"``.

    Returns:
        A ``(prefix, bare)`` tuple. ``prefix`` is ``""`` when ``value``
        carries no NetBIOS qualifier.
    """
    if "\\" not in value:
        return "", value
    prefix, bare = value.split("\\", 1)
    return prefix, bare


def split_upn_qualifier(value: str) -> tuple[str, str]:
    """Split a possibly UPN-qualified principal on the FIRST ``@``.

    Mirrors ``value.split("@", 1)`` exactly: when ``value`` contains no
    ``@``, the whole string is returned as the local part with an empty
    domain. When it does, the local part is everything before the first
    ``@`` and the domain is everything after it — no stripping, no
    case-folding.

    Args:
        value: The raw principal string, e.g. ``"user@domain"`` or
            ``"user"``.

    Returns:
        A ``(local, domain)`` tuple. ``domain`` is ``""`` when ``value``
        carries no UPN qualifier.
    """
    if "@" not in value:
        return value, ""
    local, domain = value.split("@", 1)
    return local, domain
