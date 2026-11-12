"""Requests the installation signs and answers the licence server signs.

One wire format for every exchange (spec § 5): the format 2 envelope. A
request is signed by the INSTALLATION key (``kid`` = installation id); an
answer is signed by the SERVER key. HTTP and the relay file carry the same
documents unchanged, so a partner platform in between is a dumb transport.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Mapping, Set
from datetime import datetime, timezone
from typing import Any

from adscan_core.enterprise_license import (
    FORMAT_VERSION,
    PAYLOAD_FORMAT_KEY,
    LicenseError,
    canonical_payload_bytes,
)
from adscan_core.pro_license.model import verify_pro_envelope

PROTOCOL_VERSION = 1

# Request kinds (installation-signed).
KIND_ACTIVATION = "activation_request"
KIND_RENEWAL = "renewal_request"
KIND_REGISTRATION = "registration_request"
KIND_BAND_REPORT = "band_report"
#: A full scan of an already-registered domain code that opens a NEW billable
#: engagement (outside the retest window, see
#: :mod:`adscan_core.pro_license.billable_engagements`). Rechecks and retests
#: inside the window are never sent.
KIND_ENGAGEMENT_REPORT = "engagement_report"
KIND_DEACTIVATION = "deactivation_request"
REQUEST_KINDS = frozenset(
    {
        KIND_ACTIVATION,
        KIND_RENEWAL,
        KIND_REGISTRATION,
        KIND_BAND_REPORT,
        KIND_ENGAGEMENT_REPORT,
        KIND_DEACTIVATION,
    }
)

# Answer kinds (server-signed).
KIND_LICENCE = "licence"
KIND_REGISTRATION_RECEIPT = "registration_receipt"
KIND_BAND_RECEIPT = "band_receipt"
KIND_ENGAGEMENT_RECEIPT = "engagement_receipt"
KIND_NOTICE = "notice"
ANSWER_KINDS = frozenset(
    {KIND_LICENCE, KIND_REGISTRATION_RECEIPT, KIND_BAND_RECEIPT, KIND_ENGAGEMENT_RECEIPT, KIND_NOTICE}
)

#: Which answer kinds settle which request kind.
EXPECTED_ANSWERS: dict[str, frozenset[str]] = {
    KIND_ACTIVATION: frozenset({KIND_LICENCE, KIND_NOTICE}),
    KIND_RENEWAL: frozenset({KIND_LICENCE, KIND_NOTICE}),
    KIND_REGISTRATION: frozenset({KIND_REGISTRATION_RECEIPT, KIND_NOTICE}),
    KIND_BAND_REPORT: frozenset({KIND_BAND_RECEIPT, KIND_NOTICE}),
    KIND_ENGAGEMENT_REPORT: frozenset({KIND_ENGAGEMENT_RECEIPT, KIND_NOTICE}),
    KIND_DEACTIVATION: frozenset({KIND_NOTICE}),
}

# Notice codes (spec § 5.2).
NOTICE_REVOKED = "revoked"
NOTICE_INVALID_KEY = "invalid_key"
NOTICE_SEATS_EXHAUSTED = "seats_exhausted"
NOTICE_GRANT_EXPIRED = "grant_expired"
NOTICE_NO_CREDITS = "no_credits"
NOTICE_REPLAYED = "replayed"
NOTICE_STALE = "stale_request"
NOTICE_BAD_SIGNATURE = "bad_signature"
NOTICE_UNKNOWN_INSTALLATION = "unknown_installation"
NOTICE_DEACTIVATED = "deactivated"
NOTICE_MALFORMED = "malformed"
#: Notices that end the installation's right to start assessments.
TERMINAL_NOTICES = frozenset({NOTICE_REVOKED, NOTICE_DEACTIVATED})

MAX_REQUEST_BYTES = 64 * 1024


def utc_now() -> datetime:
    """Current UTC instant (one place, so tests can reason about it)."""
    return datetime.now(timezone.utc)


def format_instant(value: datetime) -> str:
    """``YYYY-MM-DDTHH:MM:SSZ`` in UTC."""
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_instant(text: str) -> datetime:
    """Parse an instant written by :func:`format_instant` (or any ISO form)."""
    value = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def request_digest(document: Mapping[str, Any]) -> str:
    """SHA-256 (hex) of the canonical bytes of a document's payload."""
    return hashlib.sha256(canonical_payload_bytes(document["payload"])).hexdigest()


def build_request(installation: Any, kind: str, *, engine_version: str, **fields: Any) -> dict[str, Any]:
    """Build and sign a request from ``installation`` (an :class:`Installation`)."""
    if kind not in REQUEST_KINDS:
        raise ValueError(f"Unknown request kind '{kind}'.")
    payload: dict[str, Any] = {
        PAYLOAD_FORMAT_KEY: FORMAT_VERSION,
        "kind": kind,
        "protocol": PROTOCOL_VERSION,
        "request_id": uuid.uuid4().hex,
        "created_at": format_instant(utc_now()),
        "installation_id": installation.installation_id,
        "installation_key": installation.public_key_b64,
        "sequence": installation.next_sequence(),
        "engine_version": str(engine_version or "unknown"),
    }
    for key, value in fields.items():
        if value is not None:
            payload[key] = value
    return installation.sign(payload)


def parse_installation_request(raw: bytes | str | Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    """Verify an installation-signed request; return ``(payload, digest)``.

    The installation key travels in the payload; the id must derive from it and
    match the signature's kid, so a request cannot be signed by one key and
    claimed for another installation. (The server additionally checks the key
    against the one it stored at activation.)

    Raises:
        LicenseError: malformed, a key/id mismatch, or a bad signature.
    """
    from adscan_core.pro_license.installation import installation_id_for

    if isinstance(raw, Mapping):
        raw = json.dumps(raw)
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if len(raw) > MAX_REQUEST_BYTES:
        raise LicenseError("too_large", "The request is too large.")
    try:
        document = json.loads(raw.decode("utf-8"))
        unverified = document["payload"]
        installation_id = str(unverified["installation_id"])
        installation_key = str(unverified["installation_key"])
        derived = installation_id_for(installation_key)
    except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
        raise LicenseError("malformed", "The request is not a signed installation request.") from exc
    if derived != installation_id:
        raise LicenseError("malformed", "The request installation id does not match its key.")
    payload, kid = verify_pro_envelope(raw, trusted_keys={installation_id: installation_key})
    if kid != installation_id or payload.get("kind") not in REQUEST_KINDS:
        raise LicenseError("malformed", "The request is not a signed installation request.")
    if payload.get("protocol") != PROTOCOL_VERSION:
        raise LicenseError("malformed", "The request protocol version is not supported.")
    return payload, request_digest(document)


def verify_server_document(
    document: Mapping[str, Any] | bytes | str,
    *,
    trusted_keys: Mapping[str, str] | None = None,
    kinds: Set[str] = ANSWER_KINDS,
) -> dict[str, Any]:
    """Verify a server-signed document and return its payload.

    Args:
        document: The answer (parsed or raw).
        trusted_keys: Defaults to the licence-server production keys.
        kinds: Accepted ``kind`` values.

    Raises:
        LicenseError: bad signature, unknown key, or an unexpected kind.
    """
    from adscan_core.pro_license.model import PRO_LICENSE_SERVER_PUBLIC_KEYS

    keys = PRO_LICENSE_SERVER_PUBLIC_KEYS if trusted_keys is None else trusted_keys
    raw = json.dumps(document) if isinstance(document, Mapping) else document
    payload, _kid = verify_pro_envelope(raw, trusted_keys=keys)
    if payload.get("kind") not in kinds:
        raise LicenseError("unexpected_kind", "The licence server answered with an unexpected document.")
    return payload


__all__ = [
    "ANSWER_KINDS",
    "EXPECTED_ANSWERS",
    "KIND_ACTIVATION",
    "KIND_BAND_RECEIPT",
    "KIND_BAND_REPORT",
    "KIND_DEACTIVATION",
    "KIND_ENGAGEMENT_RECEIPT",
    "KIND_ENGAGEMENT_REPORT",
    "KIND_LICENCE",
    "KIND_NOTICE",
    "KIND_REGISTRATION",
    "KIND_REGISTRATION_RECEIPT",
    "KIND_RENEWAL",
    "PROTOCOL_VERSION",
    "REQUEST_KINDS",
    "TERMINAL_NOTICES",
    "build_request",
    "format_instant",
    "parse_installation_request",
    "parse_instant",
    "request_digest",
    "utc_now",
    "verify_server_document",
]
