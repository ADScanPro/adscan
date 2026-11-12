"""The PRO licence document (format 2 envelope, signed by the licence server).

Payload (spec § 3.2)::

    {"license_format": 2, "kind": "licence", "license_id": "pl-…",
     "customer": "<holder display name>",
     "edition": "pro_trial | pro_partner | pro | pro_engagement",
     "issued_at": "…Z", "valid_from": "YYYY-MM-DD", "valid_until": "YYYY-MM-DD",
     "grace_days": 0, "holder_id": "h-…", "grant_id": "g-…", "partner_tag": "",
     "installation_id": "in-…", "installation_key": "<b64>",
     "request_id": "…", "request_digest": "…",
     "registration": {"policy": "deferred|blocking|credits|offline", "grace_days": 14},
     "domain_code_key": "<b64 32 bytes>", "band_edges": [500, 2000],
     "retest_window_days": 90,
     "renew_after": "YYYY-MM-DD", "entitlements": {}}

``retest_window_days`` is optional (default 90, read through
:func:`adscan_core.pro_license.billable_engagements.resolve_retest_window_days`):
how long a full scan of an already-assessed domain counts as a retest of the
same billable engagement rather than a new one.

The Enterprise verifier refuses every edition here, and this verifier refuses
the Enterprise ones, so neither product can be unlocked with the other's file.
``kind`` separates a licence from every other document the same key signs.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta, timezone
from typing import Any

from adscan_core.enterprise_license import (
    FORMAT_VERSION,
    PAYLOAD_FORMAT_KEY,
    LicenseError,
    LicensePayload,
    verify_signed_envelope,
)
from adscan_core.pro_license.billable_engagements import (
    DEFAULT_RETEST_WINDOW_DAYS,
    resolve_retest_window_days,
)

KIND_LICENCE = "licence"

EDITION_TRIAL = "pro_trial"
EDITION_PARTNER = "pro_partner"
EDITION_PAID = "pro"
EDITION_ENGAGEMENT = "pro_engagement"
PRO_EDITIONS = frozenset({EDITION_TRIAL, EDITION_PARTNER, EDITION_PAID, EDITION_ENGAGEMENT})

#: Label for every surface (never show the raw edition id).
EDITION_LABELS = {
    EDITION_TRIAL: "PRO trial",
    EDITION_PARTNER: "PRO partner",
    EDITION_PAID: "PRO",
    EDITION_ENGAGEMENT: "PRO engagement (offline)",
}

POLICY_DEFERRED = "deferred"
POLICY_BLOCKING = "blocking"
POLICY_CREDITS = "credits"
POLICY_OFFLINE = "offline"

#: Which registration policies each edition may carry. A trial never blocks
#: (founder decision 2026-11-10), so a server bug cannot issue a blocking trial.
ALLOWED_POLICIES: dict[str, frozenset[str]] = {
    EDITION_TRIAL: frozenset({POLICY_DEFERRED}),
    EDITION_PARTNER: frozenset({POLICY_BLOCKING}),
    EDITION_PAID: frozenset({POLICY_CREDITS, POLICY_BLOCKING}),
    EDITION_ENGAGEMENT: frozenset({POLICY_OFFLINE}),
}

MAX_REGISTRATION_GRACE_DAYS = 90
MAX_LICENCE_GRACE_DAYS = 90
DOMAIN_CODE_KEY_BYTES = 32

#: Licence-server verification keys: key id -> base64 raw Ed25519 public key.
#: ONLY public keys live here; the private half never leaves the licence
#: server. Separate from the Enterprise ``PRODUCTION_PUBLIC_KEYS`` so a
#: compromise of one issuer never reaches the other. Holds the production
#: server key (the kid its server publishes at ``/v1/keys``, checked at every
#: release cut by ``scripts/check_pro_license_anchors.py``). There is
#: deliberately no environment variable that adds a key and no development key
#: here; tests pass ``trusted_keys``. Rotation: spec § 3.3.
PRO_LICENSE_SERVER_PUBLIC_KEYS: dict[str, str] = {
    "adscan-ls-2026-11": "niKnSFzJ1371Ns1z+5U37OwebtDWaH0jvbfct9m8YtA=",
}


@dataclass(frozen=True)
class ProLicense:
    """The verified content of a PRO licence."""

    license_id: str
    customer: str
    edition: str
    issued_at: datetime
    valid_from: date
    valid_until: date
    holder_id: str
    grant_id: str
    registration_policy: str
    domain_code_key: bytes
    grace_days: int = 0
    registration_grace_days: int = 0
    partner_tag: str = ""
    installation_id: str = ""
    installation_key: str = ""
    request_id: str = ""
    request_digest: str = ""
    band_edges: tuple[int, ...] = ()
    retest_window_days: int = DEFAULT_RETEST_WINDOW_DAYS
    renew_after: date | None = None
    entitlements: Mapping[str, Any] = field(default_factory=dict)
    key_id: str = ""

    @property
    def label(self) -> str:
        """Human label of the edition."""
        return EDITION_LABELS.get(self.edition, "PRO")

    @property
    def starts_at(self) -> datetime:
        """First instant (UTC) the licence is valid."""
        return datetime.combine(self.valid_from, time.min, tzinfo=timezone.utc)

    @property
    def ends_at(self) -> datetime:
        """First instant (UTC) after the last valid day."""
        return datetime.combine(self.valid_until + timedelta(days=1), time.min, tzinfo=timezone.utc)

    @property
    def grace_ends_at(self) -> datetime:
        """First instant (UTC) after the licence grace period."""
        return self.ends_at + timedelta(days=self.grace_days)

    @property
    def bound(self) -> bool:
        """True when the licence names the installation it belongs to."""
        return bool(self.installation_id)

    @property
    def needs_server(self) -> bool:
        """True when domains are registered with the licence server."""
        return self.registration_policy != POLICY_OFFLINE

    def bound_to(self, installation_id: str, installation_key: str) -> bool:
        """True when this licence may be used by that installation."""
        if not self.bound:
            return True
        return self.installation_id == installation_id and self.installation_key == installation_key

    def as_ledger_payload(self) -> LicensePayload:
        """The view :mod:`adscan_core.environment_ledger` counts against."""
        return LicensePayload(
            license_id=self.license_id,
            customer=self.customer,
            edition=self.edition,
            issued_at=self.issued_at,
            valid_from=self.valid_from,
            valid_until=self.valid_until,
            grace_days=self.grace_days,
            entitlements=dict(self.entitlements),
            key_id=self.key_id,
            format_version=FORMAT_VERSION,
        )

    def band_for(self, identities: int) -> str:
        """Size band label for ``identities`` enabled identities.

        ``band_edges`` [500, 2000] gives ``b0`` (< 500), ``b1`` (< 2000) and
        ``b2`` (the rest). Without edges every count is ``b0``.
        """
        for index, edge in enumerate(self.band_edges):
            if identities < edge:
                return f"b{index}"
        return f"b{len(self.band_edges)}"


def _str(payload: Mapping[str, Any], key: str, *, required: bool = True) -> str:
    value = payload.get(key, "")
    if not isinstance(value, str):
        raise LicenseError("malformed", f"The licence field '{key}' is not text.")
    value = value.strip()
    if required and not value:
        raise LicenseError("malformed", f"The licence is missing '{key}'.")
    return value


def _int(payload: Mapping[str, Any], key: str, default: int, maximum: int) -> int:
    value = payload.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise LicenseError("malformed", f"The licence field '{key}' is out of range.")
    return value


def _date(payload: Mapping[str, Any], key: str, *, required: bool = True) -> date | None:
    text = _str(payload, key, required=required)
    if not text:
        return None
    try:
        return date.fromisoformat(text)
    except ValueError as exc:
        raise LicenseError("malformed", f"The licence field '{key}' is not a date.") from exc


def _instant(text: str) -> datetime:
    try:
        value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LicenseError("malformed", "The licence field 'issued_at' is not a timestamp.") from exc
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def validate_pro_license_payload(payload: Mapping[str, Any], *, key_id: str = "") -> ProLicense:
    """Apply the rules shared by the licence server (issuing) and the engine.

    Raises:
        LicenseError: the payload is not a valid PRO licence.
    """
    from adscan_core.environment_ledger import EntitlementError, parse_entitlement_policy
    from adscan_core.pro_license.installation import installation_id_for
    from adscan_core.partner_tag_format import validate_partner_tag

    if not isinstance(payload, Mapping):
        raise LicenseError("malformed", "The licence payload is not an object.")
    if payload.get("kind") != KIND_LICENCE:
        raise LicenseError("malformed", "The document is not a licence.")
    if payload.get(PAYLOAD_FORMAT_KEY) != FORMAT_VERSION:
        raise LicenseError("malformed", "The licence format is not one this version reads.")
    edition = _str(payload, "edition").lower()
    if edition not in PRO_EDITIONS:
        raise LicenseError("malformed", f"'{edition}' is not a PRO licence edition.")

    valid_from = _date(payload, "valid_from")
    valid_until = _date(payload, "valid_until")
    assert valid_from is not None and valid_until is not None
    if valid_until < valid_from:
        raise LicenseError("malformed", "The licence ends before it starts.")

    registration = payload.get("registration")
    if not isinstance(registration, Mapping):
        raise LicenseError("malformed", "The licence is missing 'registration'.")
    policy = registration.get("policy")
    if policy not in ALLOWED_POLICIES[edition]:
        raise LicenseError("malformed", f"Registration policy '{policy}' is not valid for this licence.")
    registration_grace = _int(registration, "grace_days", 0, MAX_REGISTRATION_GRACE_DAYS)

    partner_tag = _str(payload, "partner_tag", required=False).lower()
    if (edition == EDITION_PARTNER or partner_tag) and not validate_partner_tag(partner_tag):
        raise LicenseError("malformed", "The licence carries an invalid partner tag.")

    installation_id = _str(payload, "installation_id", required=edition != EDITION_ENGAGEMENT)
    installation_key = _str(payload, "installation_key", required=bool(installation_id))
    if installation_id:
        try:
            derived = installation_id_for(installation_key)
        except (ValueError, binascii.Error) as exc:
            raise LicenseError("malformed", "The licence installation key is unreadable.") from exc
        if derived != installation_id:
            raise LicenseError("malformed", "The licence installation id does not match its key.")

    try:
        code_key = base64.b64decode(_str(payload, "domain_code_key"), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise LicenseError("malformed", "The licence domain-code key is unreadable.") from exc
    if len(code_key) != DOMAIN_CODE_KEY_BYTES:
        raise LicenseError("malformed", "The licence domain-code key has the wrong length.")

    edges = payload.get("band_edges", [])
    if (
        not isinstance(edges, list)
        or any(isinstance(e, bool) or not isinstance(e, int) or e <= 0 for e in edges)
        or edges != sorted(set(edges))
    ):
        raise LicenseError("malformed", "The licence band edges are not increasing whole numbers.")

    try:
        retest_window_days = resolve_retest_window_days(payload)
    except ValueError as exc:
        raise LicenseError("malformed", "The licence retest window is out of range.") from exc

    entitlements = payload.get("entitlements", {})
    if not isinstance(entitlements, Mapping):
        raise LicenseError("malformed", "The licence field 'entitlements' is not an object.")
    try:
        parse_entitlement_policy(entitlements, format_version=FORMAT_VERSION)
    except EntitlementError as exc:
        raise LicenseError("malformed", str(exc)) from exc

    return ProLicense(
        license_id=_str(payload, "license_id"),
        customer=_str(payload, "customer"),
        edition=edition,
        issued_at=_instant(_str(payload, "issued_at")),
        valid_from=valid_from,
        valid_until=valid_until,
        holder_id=_str(payload, "holder_id"),
        grant_id=_str(payload, "grant_id"),
        registration_policy=str(policy),
        domain_code_key=code_key,
        grace_days=_int(payload, "grace_days", 0, MAX_LICENCE_GRACE_DAYS),
        registration_grace_days=registration_grace,
        partner_tag=partner_tag,
        installation_id=installation_id,
        installation_key=installation_key,
        request_id=_str(payload, "request_id", required=False),
        request_digest=_str(payload, "request_digest", required=False),
        band_edges=tuple(edges),
        retest_window_days=retest_window_days,
        renew_after=_date(payload, "renew_after", required=False),
        entitlements=dict(entitlements),
        key_id=key_id,
    )


#: PRO wording for the envelope errors (the shared helper words them for the
#: Enterprise appliance). Codes are kept; only the sentence changes.
_PRO_ENVELOPE_MESSAGES = {
    "unknown_key": "The document was not signed by an ADscan licence server key this version trusts.",
    "bad_signature": "The document's signature does not match its content. It was altered or damaged.",
    "too_large": "The document is too large to be an ADscan licence document.",
}


def verify_pro_envelope(raw: bytes | str, *, trusted_keys: Mapping[str, str]) -> tuple[dict[str, Any], str]:
    """:func:`verify_signed_envelope` with PRO wording on its errors."""
    try:
        return verify_signed_envelope(raw, trusted_keys=trusted_keys)
    except LicenseError as exc:
        message = _PRO_ENVELOPE_MESSAGES.get(exc.code)
        if message is None:
            raise
        raise LicenseError(exc.code, message) from exc


def parse_pro_license(
    raw: bytes | str, *, trusted_keys: Mapping[str, str] | None = None
) -> ProLicense:
    """Verify a PRO licence document and return its content.

    Args:
        raw: The document.
        trusted_keys: Key id -> base64 public key. Defaults to
            :data:`PRO_LICENSE_SERVER_PUBLIC_KEYS`.

    Raises:
        LicenseError: malformed, unknown key, bad signature, or not a PRO licence.
    """
    keys = PRO_LICENSE_SERVER_PUBLIC_KEYS if trusted_keys is None else trusted_keys
    payload, key_id = verify_pro_envelope(raw, trusted_keys=keys)
    return validate_pro_license_payload(payload, key_id=key_id)


__all__ = [
    "ALLOWED_POLICIES",
    "EDITION_ENGAGEMENT",
    "EDITION_LABELS",
    "EDITION_PAID",
    "EDITION_PARTNER",
    "EDITION_TRIAL",
    "KIND_LICENCE",
    "POLICY_BLOCKING",
    "POLICY_CREDITS",
    "POLICY_DEFERRED",
    "POLICY_OFFLINE",
    "PRO_EDITIONS",
    "PRO_LICENSE_SERVER_PUBLIC_KEYS",
    "ProLicense",
    "parse_pro_license",
    "validate_pro_license_payload",
    "verify_pro_envelope",
]
