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
#: Answer to a launch check-in when the installation already holds the
#: current document: nothing to install, the check-in itself is the news
#: (the grant is neither revoked nor changed).
NOTICE_LICENCE_CURRENT = "licence_current"
#: Notices that end the installation's right to start assessments.
TERMINAL_NOTICES = frozenset({NOTICE_REVOKED, NOTICE_DEACTIVATED})

MAX_REQUEST_BYTES = 64 * 1024

# ── Sequence accounting (spec § 5.6) ─────────────────────────────────────────
#
# Every request consumes one number of the installation's sequence. Some are
# legitimately never delivered: a renewal replaced by the next launch's, an
# activation retried, a band report replaced by a newer band. So a gap in the
# numbers the server receives proves nothing on its own. Each request therefore
# states, at the moment it is signed, which earlier numbers this installation
# still HOLDS queued and which it WITHDREW without sending. A number that is
# neither delivered, held nor withdrawn was created and then lost: that is the
# gap the server reports. Both fields are lists of inclusive ``[first, last]``
# ranges. A request without them (an engine from before 15.0.0) is never used
# to open or confirm a gap.

#: Numbers this installation signed earlier and still holds, unsent or unanswered.
PENDING_SEQUENCES_FIELD = "pending_sequences"
#: Numbers this installation signed earlier and dropped without sending (replaced).
WITHDRAWN_SEQUENCES_FIELD = "withdrawn_sequences"
#: Most ranges either field may carry; a longer list is truncated to its newest ranges.
MAX_SEQUENCE_RANGES = 256

#: Request kinds that record usage (a domain brought in, a new engagement). The
#: engine never withdraws one: it stays queued until the server answers it.
USAGE_KINDS = frozenset({KIND_REGISTRATION, KIND_ENGAGEMENT_REPORT})
#: Which of the held numbers are usage requests, each with the first
#: :data:`USAGE_DIGEST_LENGTH` hex of its request digest: ``[[sequence, digest], ...]``.
#: Once a delivered request declared a number here, the server closes it only
#: when that same request arrives: a later withdrawal claim, or another request
#: taking the number, is reported instead (``license_server.sequence_gaps``).
#: A server from before this field ignores it; a request without it is handled
#: as before.
PENDING_USAGE_FIELD = "pending_usage"
USAGE_DIGEST_LENGTH = 16


def pending_usage(items: Any) -> list[list[Any]]:
    """The :data:`PENDING_USAGE_FIELD` value for queued ``items`` (the store's pending entries)."""
    declared: dict[int, str] = {}
    for item in items:
        if not isinstance(item, Mapping) or item.get("kind") not in USAGE_KINDS:
            continue
        payload = item.get("document", {}).get("payload", {}) if isinstance(item.get("document"), Mapping) else {}
        sequence, digest = payload.get("sequence"), item.get("digest")
        if isinstance(sequence, int) and not isinstance(sequence, bool) and sequence > 0 and isinstance(digest, str):
            declared[sequence] = digest[:USAGE_DIGEST_LENGTH]
    return [[n, declared[n]] for n in sorted(declared)][-MAX_SEQUENCE_RANGES:]


def parse_pending_usage(value: Any) -> list[tuple[int, str]] | None:
    """Validated ``(sequence, digest prefix)`` pairs from a request; None when absent or malformed."""
    if not isinstance(value, list) or len(value) > MAX_SEQUENCE_RANGES:
        return None
    parsed: list[tuple[int, str]] = []
    for item in value:
        if not isinstance(item, list) or len(item) != 2:
            return None
        sequence, digest = item
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence <= 0:
            return None
        if (
            not isinstance(digest, str)
            or len(digest) != USAGE_DIGEST_LENGTH
            or any(c not in "0123456789abcdef" for c in digest)
        ):
            return None
        parsed.append((sequence, digest))
    return parsed


def sequence_ranges(numbers: Any) -> list[list[int]]:
    """Inclusive ``[first, last]`` ranges covering ``numbers`` (positive ints only), newest last.

    Capped to :data:`MAX_SEQUENCE_RANGES`, keeping the newest ranges.
    """
    values = sorted({n for n in numbers if isinstance(n, int) and not isinstance(n, bool) and n > 0})
    ranges: list[list[int]] = []
    for value in values:
        if ranges and value == ranges[-1][1] + 1:
            ranges[-1][1] = value
        else:
            ranges.append([value, value])
    return ranges[-MAX_SEQUENCE_RANGES:]


def parse_sequence_ranges(value: Any) -> list[tuple[int, int]] | None:
    """Validated ranges from a request field; None when the field is absent or malformed."""
    if not isinstance(value, list) or len(value) > MAX_SEQUENCE_RANGES:
        return None
    parsed: list[tuple[int, int]] = []
    for item in value:
        if (
            not isinstance(item, list)
            or len(item) != 2
            or not all(isinstance(n, int) and not isinstance(n, bool) and n > 0 for n in item)
            or item[0] > item[1]
        ):
            return None
        parsed.append((item[0], item[1]))
    return parsed


def in_sequence_ranges(number: int, ranges: list[tuple[int, int]] | None) -> bool:
    """True when ``number`` falls inside one of ``ranges``."""
    return any(first <= number <= last for first, last in ranges or ())


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
    "NOTICE_LICENCE_CURRENT",
    "TERMINAL_NOTICES",
    "build_request",
    "format_instant",
    "parse_installation_request",
    "parse_instant",
    "request_digest",
    "utc_now",
    "verify_server_document",
]
