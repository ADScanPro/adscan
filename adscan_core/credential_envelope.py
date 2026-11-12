"""Authenticated encryption for stored credentials: the one codec.

A credential the platform keeps (the assessment password and the cleanup
account's password on a scan, a schedule template, the workspace's saved
cleanup account) is stored as an *envelope*::

    enc:v1:<kid>:<base64url(nonce || ciphertext || tag)>

* **Primitive.** AES-256-GCM (``cryptography``'s ``AESGCM``) with a fresh 96-bit
  random nonce per seal. GCM authenticates the ciphertext, so a modified value
  is refused, never decrypted to garbage.
* **Associated data.** ``enc:v1:<kid>:<context>``. ``context`` names the field
  family (``password``, ``cleanup_password``), so a ciphertext moved into another
  field fails authentication. The row is deliberately NOT bound: a resume and a
  scheduled run copy the ciphertext to a new row, which is what lets them run
  without ever decrypting.
* **Key id.** ``kid`` is the first 12 hex characters of
  HMAC-SHA256(key, "adscan-envelope-kid/v1"): it says which key sealed a value
  (rotation) without revealing anything usable about the key.
* **Keyring.** One primary key seals; every key in the ring opens. A value whose
  kid no key in the ring carries raises :class:`EnvelopeKeyUnavailable`, which
  callers turn into "re-enter the credential". Nothing falls back to clear text.

The web platform's key comes from its environment file, never the database
(:func:`keyring_from_settings`): ``CREDENTIAL_ENCRYPTION_KEY`` (generated per
appliance at first boot), else a key derived with HKDF from ``SECRET_KEY`` (an
appliance updated from a release without the dedicated key), plus
``CREDENTIAL_ENCRYPTION_KEYS_RETIRED`` for rotation. The ``enc:v1:`` prefix is the
one the engine vault design reserves, so that vault reuses this module.

``cryptography`` is imported lazily, as ``enterprise_license`` does, so importing
``adscan_core`` costs nothing where no credential is handled.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional

__all__ = [
    "ENVELOPE_PREFIX",
    "SECRET_CONFIG_FIELDS",
    "SECRET_MASK",
    "CREDENTIAL_KEY_ENV",
    "RETIRED_KEYS_ENV",
    "SECRET_KEY_ENV",
    "CredentialKeyUnavailable",
    "EnvelopeError",
    "EnvelopeInvalid",
    "EnvelopeKeyUnavailable",
    "Keyring",
    "envelope_kid",
    "is_envelope",
    "key_id",
    "keyring_from_environment",
    "keyring_from_settings",
    "open_config_secrets",
    "open_envelope",
    "redact_config_secrets",
    "drop_config_secrets",
    "merge_config_secrets",
    "CREDENTIAL_REMOVED_KEY",
    "reseal",
    "seal",
    "seal_config_secrets",
]

ENVELOPE_VERSION = "v1"
ENVELOPE_PREFIX = f"enc:{ENVELOPE_VERSION}:"

#: Configuration keys that hold a secret, on scans and schedule templates alike.
#: The field name is also the envelope's context.
SECRET_CONFIG_FIELDS: tuple[str, ...] = ("password", "cleanup_password")

#: Marks a configuration whose stored credentials were removed on purpose (a
#: completed scan, or a secret purge), so a later reader can say why.
CREDENTIAL_REMOVED_KEY = "credential_removed"

#: What an API returns in place of a stored secret.
SECRET_MASK = "***"

CREDENTIAL_KEY_ENV = "CREDENTIAL_ENCRYPTION_KEY"
RETIRED_KEYS_ENV = "CREDENTIAL_ENCRYPTION_KEYS_RETIRED"
SECRET_KEY_ENV = "SECRET_KEY"

_NONCE_BYTES = 12
_KEY_BYTES = 32
_KID_HEX = 12
_KID_LABEL = b"adscan-envelope-kid/v1"
_HKDF_SALT = b"adscan-web"
_HKDF_INFO = b"adscan-web/credential-encryption/v1"
_MIN_SECRET_KEY_LENGTH = 32

#: Values shipped as placeholders or defaults. A key derived from one of these
#: would be public, which is the same as storing the secret in clear.
_PLACEHOLDER_SECRET_KEYS = frozenset(
    {
        "__set_at_first_boot__",
        "change-this-in-production-use-random-32-char-string",
        "change-this-to-a-random-64-character-hex-string",
    }
)


class EnvelopeError(Exception):
    """Base class: a stored credential could not be opened."""


class EnvelopeInvalid(EnvelopeError):
    """The value is malformed or failed authentication (modified, wrong field)."""


class EnvelopeKeyUnavailable(EnvelopeError):
    """No key in the ring carries the kid that sealed this value (key lost or rotated away)."""


class CredentialKeyUnavailable(Exception):
    """No usable encryption key is configured, so nothing can be sealed."""


def key_id(key: bytes) -> str:
    """The non-reversible identifier of ``key``."""
    return hmac.new(key, _KID_LABEL, hashlib.sha256).hexdigest()[:_KID_HEX]


@dataclass(frozen=True)
class Keyring:
    """A primary key (seals) and every key that may open a stored value."""

    primary_kid: str
    _keys: Mapping[str, bytes] = field(repr=False)

    def __str__(self) -> str:  # never key material
        return f"Keyring(primary_kid={self.primary_kid!r}, kids={sorted(self._keys)!r})"

    @property
    def kids(self) -> frozenset[str]:
        return frozenset(self._keys)

    def key_for(self, kid: str) -> Optional[bytes]:
        return self._keys.get(kid)

    @property
    def primary_key(self) -> bytes:
        return self._keys[self.primary_kid]


def _parse_hex_key(raw: str, name: str) -> bytes:
    text = raw.strip()
    try:
        key = bytes.fromhex(text)
    except ValueError as exc:
        raise CredentialKeyUnavailable(f"{name} is not hexadecimal.") from exc
    if len(key) != _KEY_BYTES:
        raise CredentialKeyUnavailable(f"{name} must be {_KEY_BYTES * 2} hex characters.")
    return key


def _derive_from_secret_key(secret_key: str) -> Optional[bytes]:
    text = (secret_key or "").strip()
    if len(text) < _MIN_SECRET_KEY_LENGTH or text.lower() in _PLACEHOLDER_SECRET_KEYS:
        return None
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(
        algorithm=hashes.SHA256(), length=_KEY_BYTES, salt=_HKDF_SALT, info=_HKDF_INFO
    ).derive(text.encode("utf-8"))


def keyring_from_settings(
    *, dedicated_key: Optional[str], retired_keys: Optional[str], secret_key: Optional[str]
) -> Keyring:
    """Build the platform's keyring from its configuration values.

    Primary: the dedicated key when set, else the key derived from
    ``secret_key``. The derived key and every retired key stay in the ring to
    open what they sealed.

    Raises:
        CredentialKeyUnavailable: a malformed dedicated or retired key, or no
            usable key at all.
    """
    keys: dict[str, bytes] = {}
    primary: Optional[str] = None
    if dedicated_key and dedicated_key.strip():
        dedicated = _parse_hex_key(dedicated_key, CREDENTIAL_KEY_ENV)
        primary = key_id(dedicated)
        keys[primary] = dedicated
    derived = _derive_from_secret_key(secret_key or "")
    if derived is not None:
        kid = key_id(derived)
        keys.setdefault(kid, derived)
        primary = primary or kid
    for raw in (retired_keys or "").split(","):
        if raw.strip():
            retired = _parse_hex_key(raw, RETIRED_KEYS_ENV)
            keys.setdefault(key_id(retired), retired)
    if primary is None:
        raise CredentialKeyUnavailable(
            "No credential encryption key is configured (set CREDENTIAL_ENCRYPTION_KEY, "
            "or a generated SECRET_KEY, in the platform environment)."
        )
    return Keyring(primary_kid=primary, _keys=keys)


def keyring_from_environment(environ: Optional[Mapping[str, str]] = None) -> Keyring:
    """:func:`keyring_from_settings` from process environment variables."""
    env = os.environ if environ is None else environ
    return keyring_from_settings(
        dedicated_key=env.get(CREDENTIAL_KEY_ENV),
        retired_keys=env.get(RETIRED_KEYS_ENV),
        secret_key=env.get(SECRET_KEY_ENV),
    )


def is_envelope(value: Any) -> bool:
    """Whether ``value`` is a sealed credential."""
    return isinstance(value, str) and value.startswith(ENVELOPE_PREFIX)


def envelope_kid(value: Any) -> Optional[str]:
    """The kid that sealed ``value``, or None when it is not an envelope."""
    if not is_envelope(value):
        return None
    kid, sep, _ = value[len(ENVELOPE_PREFIX):].partition(":")
    return kid if sep and kid else None


def _aad(kid: str, context: str) -> bytes:
    return f"{ENVELOPE_PREFIX}{kid}:{context}".encode("utf-8")


def seal(value: str, keyring: Keyring, *, context: str) -> str:
    """Encrypt ``value`` under the primary key for the field ``context``."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(_NONCE_BYTES)
    kid = keyring.primary_kid
    body = AESGCM(keyring.primary_key).encrypt(
        nonce, str(value).encode("utf-8"), _aad(kid, context)
    )
    token = base64.urlsafe_b64encode(nonce + body).rstrip(b"=").decode("ascii")
    return f"{ENVELOPE_PREFIX}{kid}:{token}"


def open_envelope(value: str, keyring: Keyring, *, context: str) -> str:
    """Decrypt an envelope sealed for ``context``.

    Raises:
        EnvelopeKeyUnavailable: no key in ``keyring`` carries its kid.
        EnvelopeInvalid: malformed, modified, or sealed for another field.
    """
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    kid = envelope_kid(value)
    if kid is None:
        raise EnvelopeInvalid("Not a credential envelope.")
    token = value[len(ENVELOPE_PREFIX) + len(kid) + 1:]
    key = keyring.key_for(kid)
    if key is None:
        raise EnvelopeKeyUnavailable(
            "The key that encrypted this credential is not configured on this appliance."
        )
    try:
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    except (ValueError, TypeError) as exc:
        raise EnvelopeInvalid("Malformed credential envelope.") from exc
    if len(raw) <= _NONCE_BYTES:
        raise EnvelopeInvalid("Malformed credential envelope.")
    try:
        plain = AESGCM(key).decrypt(raw[:_NONCE_BYTES], raw[_NONCE_BYTES:], _aad(kid, context))
    except InvalidTag as exc:
        raise EnvelopeInvalid("The stored credential failed its integrity check.") from exc
    return plain.decode("utf-8")


def reseal(value: str, keyring: Keyring, *, context: str) -> str:
    """Re-encrypt an envelope under the primary key (rotation). Unchanged when already primary."""
    if envelope_kid(value) == keyring.primary_kid:
        return value
    return seal(open_envelope(value, keyring, context=context), keyring, context=context)


def seal_config_secrets(
    config: Mapping[str, Any], keyring_provider: Callable[[], Keyring]
) -> dict[str, Any]:
    """Return a copy of ``config`` whose secret fields are sealed.

    Idempotent: envelopes and empty values are left as they are, and the keyring
    is only asked for when a clear value is present, so a configuration that
    holds nothing to seal never needs a key.
    """
    out = dict(config)
    for name in SECRET_CONFIG_FIELDS:
        value = out.get(name)
        if isinstance(value, str) and value and not is_envelope(value):
            out[name] = seal(value, keyring_provider(), context=name)
    return out


def open_config_secrets(config: Mapping[str, Any], keyring: Keyring) -> dict[str, Any]:
    """Return a copy of ``config`` with its secret fields decrypted, for one run.

    A value without the envelope prefix is a row written before encryption
    existed and is passed through unchanged.

    Raises:
        EnvelopeKeyUnavailable, EnvelopeInvalid: see :func:`open_envelope`.
    """
    out = dict(config)
    for name in SECRET_CONFIG_FIELDS:
        value = out.get(name)
        if is_envelope(value):
            out[name] = open_envelope(value, keyring, context=name)
    return out


def drop_config_secrets(config: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of ``config`` without its stored secrets.

    The copy is marked with :data:`CREDENTIAL_REMOVED_KEY` when a secret was
    actually present, so a resume can refuse with the reason instead of running
    without a credential. Unchanged when there was nothing to remove.
    """
    out = dict(config)
    removed = False
    for name in SECRET_CONFIG_FIELDS:
        if out.pop(name, None):
            removed = True
    if removed:
        out[CREDENTIAL_REMOVED_KEY] = True
    return out


def merge_config_secrets(
    incoming: Mapping[str, Any], stored: Mapping[str, Any]
) -> dict[str, Any]:
    """Apply write-only semantics to a configuration that replaces a stored one.

    A browser only ever sees :data:`SECRET_MASK`, so a secret field that comes
    back as the mask, or not at all, keeps the stored value (it is never
    overwritten with ``***``). An explicit empty value removes it; anything else
    is a new value the caller then seals.
    """
    out = dict(incoming)
    for name in SECRET_CONFIG_FIELDS:
        value = out.get(name, None)
        if name not in out or value == SECRET_MASK:
            previous = stored.get(name)
            if previous:
                out[name] = previous
            else:
                out.pop(name, None)
        elif not value:
            out.pop(name, None)
    return out


def redact_config_secrets(config: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of ``config`` safe to send to a browser: secrets masked."""
    out = dict(config)
    for name in SECRET_CONFIG_FIELDS:
        if out.get(name):
            out[name] = SECRET_MASK
    return out
