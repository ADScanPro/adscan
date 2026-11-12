"""The per-partner domain code: an HMAC of the forest's identity.

The engine registers a forest with the licence server, and shows it to the
operator on every scan, by this code alone: no domain name, no client detail.
Under one partner the same forest always has the same code; under two partners
the codes are unrelated, because each partner's licence carries its own key.

The basis is the best identity the scan established, in this order: the forest
root domain GUID (``root_guid``), the GUID of the domain that answered when the
root did not (``domain_guid``, provisional) and, with neither, the forest DNS
name (``name``, guessable, flagged as such to the server).
"""

from __future__ import annotations

import base64
import hashlib
import hmac

from adscan_core.environment_ledger import ForestIdentity, normalize_guid

BASIS_ROOT_GUID = "root_guid"
BASIS_DOMAIN_GUID = "domain_guid"
BASIS_NAME = "name"
BASES = (BASIS_ROOT_GUID, BASIS_DOMAIN_GUID, BASIS_NAME)
CODE_PREFIX = "dc1-"
_DOMAIN_SEPARATOR = "adscan-domain-code/1"
_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyz234567")


def _normalize(basis: str, value: str) -> str:
    if basis in (BASIS_ROOT_GUID, BASIS_DOMAIN_GUID):
        guid = normalize_guid(value)
        if guid is None:
            raise ValueError("A GUID basis needs a valid GUID.")
        return guid
    if basis == BASIS_NAME:
        name = str(value or "").strip().rstrip(".").lower()
        if not name:
            raise ValueError("A name basis needs a domain name.")
        return name
    raise ValueError(f"Unknown domain code basis '{basis}'.")


def compute_domain_code(key: bytes, basis: str, value: str) -> str:
    """Return ``dc1-xxxxxx-xxxxxx-xxxxxx-xxxxxx`` for ``value`` under ``key``."""
    message = f"{_DOMAIN_SEPARATOR}|{basis}|{_normalize(basis, value)}".encode("utf-8")
    digest = hmac.new(key, message, hashlib.sha256).digest()
    body = base64.b32encode(digest).decode("ascii").lower()[:24]
    return CODE_PREFIX + "-".join(body[i : i + 6] for i in range(0, 24, 6))


def code_for_identity(key: bytes, identity: ForestIdentity) -> tuple[str, str]:
    """Return ``(code, basis)`` for the best identity a scan established."""
    if identity.root_domain_guid:
        return compute_domain_code(key, BASIS_ROOT_GUID, identity.root_domain_guid), BASIS_ROOT_GUID
    if identity.domain_guid:
        return compute_domain_code(key, BASIS_DOMAIN_GUID, identity.domain_guid), BASIS_DOMAIN_GUID
    return compute_domain_code(key, BASIS_NAME, identity.label), BASIS_NAME


def is_domain_code(value: object) -> bool:
    """True when ``value`` has the shape of a domain code."""
    if not isinstance(value, str) or not value.startswith(CODE_PREFIX):
        return False
    parts = value[len(CODE_PREFIX) :].split("-")
    return len(parts) == 4 and all(len(p) == 6 and set(p) <= _ALPHABET for p in parts)


__all__ = [
    "BASES",
    "BASIS_DOMAIN_GUID",
    "BASIS_NAME",
    "BASIS_ROOT_GUID",
    "CODE_PREFIX",
    "code_for_identity",
    "compute_domain_code",
    "is_domain_code",
]
