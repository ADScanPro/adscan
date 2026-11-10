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

from collections.abc import Callable
from typing import Any, Optional

_HEX_CHARS = frozenset("0123456789abcdef")


class CredentialMaterialMissingError(ValueError):
    """A transport config names a principal but carries no secret for it.

    Raised by :func:`require_credential_material` from a config's
    ``__post_init__``, i.e. before any packet is built. Reaching this means a
    caller resolved WHO to authenticate as and then lost the secret on the way
    (the classic ``password=None if is_hash else secret`` into a config that has
    no ``nt_hash`` field). Sending that config would put an empty secret on the
    wire as a real account: one failed logon per attempt, toward a lockout.
    """


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


def require_credential_material(
    *,
    transport: str,
    username: Optional[str],
    password: Optional[str],
    nt_hash: Optional[str] = None,
    aes_key: Optional[str] = None,
    ccache_path: Optional[str] = None,
    extra_material: tuple[Any, ...] = (),
    ambient_kerberos: Optional[Callable[[], bool]] = None,
) -> None:
    """Refuse a config that names a principal and holds no secret for it.

    The single invariant every authenticating transport config enforces from
    its ``__post_init__``: when ``username`` is set, at least one piece of
    credential material travels with it. Material is a password (an EMPTY
    string counts: it is the explicit blank-password credential the blank spray
    and AS-REP paths send on purpose, distinct from ``None``), an NT hash, an
    AES key, a ccache path, or any transport-specific material passed in
    ``extra_material`` (a ``CredentialContext``, PFX path, in-memory ccache).

    The ambient ``KRB5CCNAME`` is NOT material by itself: it holds whichever
    principal last minted, which is how a bind "as alice" turns into a bind as
    the Domain Admin, or into an empty-password AS-REQ. A Kerberos transport may
    pass ``ambient_kerberos``, a check that the ambient cache holds a ticket for
    THIS principal; only then does the ambient cache count.

    A config without a username (anonymous bind, null session, a posture-only
    carrier) is not checked: it authenticates as nobody.

    Raises:
        CredentialMaterialMissingError: ``username`` is set and no material is.
    """
    principal = str(username or "").strip()
    if not principal:
        return
    if password is not None:
        return
    if any(str(value or "").strip() for value in (nt_hash, aes_key, ccache_path)):
        return
    if any(bool(value) for value in extra_material):
        return
    if ambient_kerberos is not None:
        try:
            if ambient_kerberos():
                return
        except Exception:  # noqa: BLE001 - an unreadable cache is not material
            pass
    raise CredentialMaterialMissingError(
        f"{transport}: refusing to authenticate as a named principal with no "
        "password, NT hash, AES key or ticket; the secret was lost before the "
        "connection was built"
    )


def nt_hash_of_password(password: Optional[str]) -> str:
    """Return the NT hash of a cleartext password, or ``""`` when undecidable.

    NT hash = MD4(UTF-16LE(password)). Used to tell whether a stored cleartext
    and an incoming NT hash are the SAME secret (two formats of one password)
    or two DIFFERENT secrets for the same principal (one of them stale).
    Best-effort: returns ``""`` when MD4 is unavailable, never raises.
    """
    if not isinstance(password, str):
        return ""
    try:
        from Cryptodome.Hash import MD4  # noqa: PLC0415

        digest = MD4.new()
        digest.update(password.encode("utf-16-le"))
        return digest.hexdigest().lower()
    except Exception:  # noqa: BLE001 - undecidable, the caller keeps its default
        return ""


def same_secret(password: Optional[str], nt_hash: Optional[str]) -> Optional[bool]:
    """Whether ``password`` and ``nt_hash`` are one secret in two formats.

    Returns ``True`` / ``False`` when it can be decided, ``None`` when it cannot
    (no hash, an unhashable password, MD4 unavailable).
    """
    if not looks_like_ntlm_hash(nt_hash or ""):
        return None
    computed = nt_hash_of_password(password)
    if not computed:
        return None
    return computed == normalize_ntlm_hash(str(nt_hash))


__all__ = [
    "CredentialMaterialMissingError",
    "looks_like_ntlm_hash",
    "normalize_ntlm_hash",
    "nt_hash_of_password",
    "promote_credential_fields",
    "require_credential_material",
    "same_secret",
]
