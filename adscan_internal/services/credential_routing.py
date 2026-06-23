"""Single source of truth for credential format classification.

ADscan resolves a credential out of the workspace as a plain string. The same
string can later end up in any of three credential fields on a transport
config: ``password``, ``nt_hash``, ``aes_key`` (and ``ccache_path`` for
ticket-based auth). When a string that is actually an NTLM hash lands in
``password``, the Kerberos client treats it as plaintext and derives the
wrong AES key from it — AS-REQ preauth fails with ``KDC_ERR_PREAUTH_FAILED``
even though the credential is materially correct.

This module exposes one helper, :func:`promote_credential_fields`, used by
every transport config's ``__post_init__`` to normalise the credential
fields. The helper is deliberately conservative: it only re-routes a value
when the format is unambiguous.

Format heuristics (only the first match wins):
- 32 hex characters → NT hash (NTLM format).
- ``LM:NT`` 65-character pair with a colon between two 32-hex halves → NT
  hash (legacy combined form; the NT half is what authenticates).
- AES keys live in ``aes_key`` only when the caller supplies them
  explicitly. AES-128 collides with NT hash on length, so we never demote a
  hash to AES.

The promotion is one-directional: ``password`` may be moved to ``nt_hash``,
never the other way around. A value already in ``nt_hash`` is trusted as-is.
"""

from __future__ import annotations

from typing import Optional

_HEX_CHARS = frozenset("0123456789abcdef")


def looks_like_ntlm_hash(value: object) -> bool:
    """Return True when ``value`` is a 32-character lowercase-hex NTLM hash.

    Accepts both bare ``<NT>`` and combined ``<LM>:<NT>`` forms — the latter
    is normalised to the NT half by callers that handle it.
    """
    if not isinstance(value, str):
        return False
    raw = value.strip()
    if not raw:
        return False
    if ":" in raw:
        parts = raw.split(":", 1)
        if len(parts) == 2 and all(len(p) == 32 for p in parts):
            return all(c in _HEX_CHARS for p in parts for c in p.lower())
        return False
    return len(raw) == 32 and all(c in _HEX_CHARS for c in raw.lower())


def normalize_ntlm_hash(value: str) -> str:
    """Return the bare 32-hex NT hash from a ``<LM>:<NT>`` pair or itself."""
    raw = value.strip()
    if ":" in raw:
        parts = raw.split(":", 1)
        if len(parts) == 2 and all(len(p) == 32 for p in parts):
            return parts[1].lower()
    return raw.lower()


def promote_credential_fields(
    *,
    password: Optional[str],
    nt_hash: Optional[str] = None,
    aes_key: Optional[str] = None,
    ccache_path: Optional[str] = None,
) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """Return ``(password, nt_hash, aes_key, ccache_path)`` after auto-routing.

    The single transformation applied: if ``password`` contains an NTLM hash
    and ``nt_hash`` is empty, move the hash to ``nt_hash`` and clear
    ``password``. Every other field is returned unchanged. The function is
    pure and safe to call repeatedly (idempotent).
    """
    # Preserve an EMPTY password ('') as distinct from None: '' is a genuine
    # blank-password credential (a PASSWD_NOTREQD account, found by the native
    # blank spray) that must still verify/authenticate, whereas None means "no
    # password credential". The old ``(password or '').strip() or None`` collapsed
    # '' -> None, which made every blank-password transport config fail with
    # "no usable credential". Whitespace-only also normalises to '' (blank).
    pwd = password.strip() if isinstance(password, str) else None
    if pwd and not (nt_hash or "").strip() and looks_like_ntlm_hash(pwd):
        return None, normalize_ntlm_hash(pwd), aes_key, ccache_path
    return pwd, nt_hash, aes_key, ccache_path


__all__ = [
    "looks_like_ntlm_hash",
    "normalize_ntlm_hash",
    "promote_credential_fields",
]
