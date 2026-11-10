"""Offline signed license for the Enterprise edition (appliance and PoV).

The Enterprise appliance works offline, so its license cannot be checked
against a server. Instead ADscan issues a small JSON file signed with an
Ed25519 private key that never leaves ADscan; the product carries only the
public half (:data:`PRODUCTION_PUBLIC_KEYS`). The appliance verifies the file
locally every time a NEW assessment is about to start: the engine's ``ci`` /
``execute`` / ``start`` entry points, and the web platform's scan-launch seams.

What a license controls, and what it deliberately does not:

- A missing, invalid, expired or not-yet-valid license, or a clock that moved
  back notably, stops NEW assessments from starting, with a clear message.
- The panel, the reports, the history and the exports are never gated. They
  are the client's own evidence; nothing in this module is consulted on a read.
- From ``warn_days`` before the end date (:data:`WARN_DAYS`, or
  :data:`POV_WARN_DAYS` for a PoV) the license is still valid but every
  surface warns. After the end date a grace period (``grace_days`` in
  the signed file, :data:`DEFAULT_GRACE_DAYS` by default) still allows
  assessments, with a warning, so a renewal held up by procurement does not
  cut an evaluation short.
- Renewing is replacing the file (web upload by an administrator, or placing
  it at :func:`license_path`). Nothing is rebuilt.

Only the Enterprise edition is affected. :func:`adscan_core.tier.is_enterprise_edition`
decides that from an explicit marker; LITE and PRO without the marker never
read a license and behave exactly as before (:func:`scan_launch_status`
returns ``not_required``).

Clock rollback. The highest wall-clock instant seen at a scan launch is kept in
``clock-state.json`` beside the license (one global high-water mark, not keyed
by license, so swapping in an older license does not reset it). If the clock is
now more than ``clock_tolerance_hours`` behind that mark, or behind the signed
``issued_at``, new assessments stop until the clock is corrected. It is a
deterrent, not a guarantee: whoever holds root on the box can delete the state
file, and the contract is what governs the term. The tolerance is generous on
purpose because ADscan steps the host clock to the domain controller's time
during a scan. While the clock is stepped (:func:`clock_currently_stepped`) the
mark is never advanced, so a DC days ahead of real time cannot raise it, and at
the end of the scan the host clock is restored to the pre-scan time plus the
elapsed monotonic time (never the DC's clock).

Entitlements. A format 2 licence (``license_format: 2`` inside the signed
payload) declares one enforced mode in ``entitlements``: ``scoped`` (an agreed
set of forests and domains, priced by enabled identities; out-of-scope domains
are refused, identities over the priced figure are warned and recorded, never
blocked) or ``organizations`` (N client organizations first assessed per term,
one per workspace, trusted forests included). The rules, the usage ledger and
its tamper seal live in :mod:`adscan_core.environment_ledger`;
:class:`LicenseStatus` carries the usage so every surface shows it. A format 1
licence keeps the behaviour it was issued under: its entitlements are recorded
and shown, never enforced. The format sits inside the signed payload, so a
file cannot be downgraded to escape its mode.

PyArmor. The obfuscated engine keeps its own build-date expiry as code
protection and a safety net. An Enterprise image is built with a long horizon
(``build_docker_pro_image.sh --enterprise``) and bakes that date into
``ADSCAN_BINARY_EXPIRES``; the engine records it beside the license
(:func:`record_engine_info`) so every surface can warn when the image would stop
before the license does.

Format (``adscan_license: 2``; a format 1 file has no ``license_format``)::

    {
      "adscan_license": 2,
      "payload": {
        "license_format": 2,                # must equal adscan_license
        "license_id": "lic-2026-0001",
        "customer": "Example Entity",
        "edition": "enterprise",            # or "pov"
        "issued_at": "2026-11-02T10:00:00Z",
        "valid_from": "2026-11-15",         # UTC, inclusive
        "valid_until": "2027-11-14",        # UTC, inclusive (whole day)
        "grace_days": 14,                   # optional
        "warn_days": 30,                    # optional (default 30; 7 for a PoV)
        "clock_tolerance_hours": 72,        # optional
        "deployment": "c01",                # optional, opaque deployment id
        "entitlements": {                   # optional; see environment_ledger
          "mode": "organizations", "organizations_per_year": 20,
          "max_declared_forests": 3        # or "unlimited"
        }
      },
      "signature": {"alg": "Ed25519", "kid": "adscan-2026-11", "value": "<base64>"}
    }

The signature covers :func:`canonical_payload_bytes` of ``payload`` (sorted
keys, no whitespace, ASCII). The payload stays readable on purpose: a client
can see everything the file says about them.
"""

from __future__ import annotations

import base64
import json
import math
import os
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any

from adscan_core.license_storage import (
    LICENSE_STORAGE_UNAVAILABLE_MESSAGE,
    LicenseStorageError,
    adopt_directory_owner,
)

# ── Constants ────────────────────────────────────────────────────────────────

#: Current licence format. Format 1 files (no ``license_format`` in the
#: payload) stay valid and keep their informational entitlements.
FORMAT_VERSION = 2
SUPPORTED_FORMAT_VERSIONS = frozenset({1, 2})
PAYLOAD_FORMAT_KEY = "license_format"
SIGNATURE_ALGORITHM = "Ed25519"
LICENSE_FILENAME = "adscan-license.json"
CLOCK_STATE_FILENAME = "clock-state.json"
#: Present while ADscan holds the host clock stepped to a domain controller.
#: Written by whoever stepped it (the host helper, or the engine itself on a
#: native runtime) and removed when the wall clock is restored.
CLOCK_STEPPED_FILENAME = "clock-stepped.json"
_BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
ENGINE_INFO_FILENAME = "engine.json"
LICENSE_DIR_ENV = "ADSCAN_LICENSE_DIR"
BINARY_EXPIRES_ENV = "ADSCAN_BINARY_EXPIRES"

#: Exit code the engine returns when a license blocks a new assessment. The
#: appliance worker maps it to a client-facing reason (mirrored, and locked by
#: a contract test, in ``appliance/celery/adscan_celery/tasks.py``). 78 is
#: EX_CONFIG: the scan was refused for a configuration reason, not a crash.
LICENSE_BLOCKED_EXIT_CODE = 78

#: ``LicenseStatus.error_code`` when the license file exists but this process
#: cannot read it: a storage fault on the appliance, reported as one (see
#: :mod:`adscan_core.license_storage`), never as a verdict on the license.
ERROR_LICENSE_UNREADABLE = "unreadable"

DEFAULT_GRACE_DAYS = 14
MAX_GRACE_DAYS = 90
WARN_DAYS = 30
#: A PoV runs about a month, so a 30-day warning would show from its first day.
POV_WARN_DAYS = 7
DEFAULT_CLOCK_TOLERANCE_HOURS = 72
MAX_LICENSE_BYTES = 64 * 1024
#: ``"pov"`` is the free trial, which customers and every visible label call a
#: PoC ("Proof of concept"). The identifier stays ``"pov"`` because it is inside
#: every license file already issued; map it to a label, never rename it.
LICENSE_EDITIONS = frozenset({"enterprise", "pov"})

#: Production verification keys: key id -> raw 32-byte Ed25519 public key,
#: base64. ONLY public keys live here. The private half is kept outside every
#: repository (see ``scripts/issue_enterprise_license.py``). An empty mapping
#: means this build accepts no license at all, which is the safe default until
#: the production key pair is generated; ``build_docker_pro_image.sh
#: --enterprise`` refuses to build in that state. Rotation = add the new key
#: here, issue new files with its kid, drop the old key a release later.
PRODUCTION_PUBLIC_KEYS: dict[str, str] = {
    "adscan-2026-11": "0uryycniORYki+WljBOxlIrx5ttrQ0EFBfsUbM2xqRg=",
}

# License states. ``scans_allowed`` is derived from the state in one place
# (:data:`_ALLOWED_STATES`) so no caller re-decides it.
STATE_NOT_REQUIRED = "not_required"
STATE_VALID = "valid"
STATE_EXPIRING = "expiring"
STATE_GRACE = "grace"
STATE_EXPIRED = "expired"
STATE_NOT_YET_VALID = "not_yet_valid"
STATE_MISSING = "missing"
STATE_INVALID = "invalid"
STATE_CLOCK_ROLLBACK = "clock_rollback"

_ALLOWED_STATES = frozenset(
    {STATE_NOT_REQUIRED, STATE_VALID, STATE_EXPIRING, STATE_GRACE}
)
_WARNING_STATES = frozenset({STATE_EXPIRING, STATE_GRACE})

_KEEPS_DATA = "Existing reports, history and exports remain available."
_HOW_TO_INSTALL = "An administrator can upload a license file under Settings > License."


# ── Errors and value objects ─────────────────────────────────────────────────


class LicenseError(Exception):
    """A license file that cannot be accepted.

    ``code`` is a stable machine-readable reason; ``str(exc)`` is the human
    reason, safe to show to the appliance administrator.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class LicensePayload:
    """The verified content of a license file."""

    license_id: str
    customer: str
    edition: str
    issued_at: datetime
    valid_from: date
    valid_until: date
    grace_days: int = DEFAULT_GRACE_DAYS
    warn_days: int = WARN_DAYS
    clock_tolerance_hours: int = DEFAULT_CLOCK_TOLERANCE_HOURS
    deployment: str = ""
    entitlements: Mapping[str, Any] = field(default_factory=dict)
    key_id: str = ""
    format_version: int = 1

    @property
    def starts_at(self) -> datetime:
        """First instant (UTC) the license is valid."""
        return datetime.combine(self.valid_from, time.min, tzinfo=timezone.utc)

    @property
    def ends_at(self) -> datetime:
        """First instant (UTC) after the last valid day."""
        return datetime.combine(
            self.valid_until + timedelta(days=1), time.min, tzinfo=timezone.utc
        )

    @property
    def grace_ends_at(self) -> datetime:
        """First instant (UTC) after the grace period."""
        return self.ends_at + timedelta(days=self.grace_days)


@dataclass(frozen=True)
class LicenseStatus:
    """The answer to "may a new assessment start now, and what do we say?"."""

    state: str
    message: str
    license: LicensePayload | None = None
    error_code: str = ""
    days_remaining: int | None = None
    binary_expires: date | None = None
    binary_warning: str = ""
    #: ``adscan_core.environment_ledger.EnvironmentUsage`` when the licence
    #: limits environments, else None.
    environments: Any = None

    @property
    def environment_warning(self) -> str:
        """Notice near or at the environment limit (empty otherwise)."""
        if self.environments is None or not self.scans_allowed:
            return ""
        return str(self.environments.warning_message or "")

    @property
    def scans_allowed(self) -> bool:
        """True when a new assessment may start (possibly with a warning)."""
        return self.state in _ALLOWED_STATES

    @property
    def required(self) -> bool:
        """True when this deployment enforces a license at all."""
        return self.state != STATE_NOT_REQUIRED

    @property
    def warning(self) -> bool:
        """True when an allowed state still deserves a visible warning."""
        return (
            self.state in _WARNING_STATES
            or bool(self.binary_warning)
            or bool(self.environment_warning)
        )

    @property
    def display_message(self) -> str:
        """The message plus the image-expiry and environment notices."""
        parts = [self.message, self.binary_warning, self.environment_warning]
        return " ".join(part for part in parts if part).strip()

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe projection for the web API and ``--json`` outputs."""
        lic = self.license
        return {
            "state": self.state,
            "required": self.required,
            "scans_allowed": self.scans_allowed,
            "warning": self.warning,
            "message": self.display_message,
            "error_code": self.error_code or None,
            "days_remaining": self.days_remaining,
            "binary_expires": self.binary_expires.isoformat()
            if self.binary_expires
            else None,
            "environments": self.environments.to_dict()
            if self.environments is not None
            else None,
            "license": None
            if lic is None
            else {
                "license_id": lic.license_id,
                "customer": lic.customer,
                "edition": lic.edition,
                "issued_at": _format_instant(lic.issued_at),
                "valid_from": lic.valid_from.isoformat(),
                "valid_until": lic.valid_until.isoformat(),
                "grace_days": lic.grace_days,
                "warn_days": lic.warn_days,
                "grace_until": (lic.grace_ends_at - timedelta(days=1))
                .date()
                .isoformat(),
                "deployment": lic.deployment or None,
                "entitlements": dict(lic.entitlements),
                "license_format": lic.format_version,
                "key_id": lic.key_id,
            },
        }


# ── Canonical form and signatures ────────────────────────────────────────────


def canonical_payload_bytes(payload: Mapping[str, Any]) -> bytes:
    """Return the exact bytes the signature covers.

    Sorted keys, no insignificant whitespace, ASCII-only. Floats are refused
    at validation time, so the serialisation is deterministic.
    """
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _load_ed25519():
    """Import the Ed25519 primitives lazily (never on a LITE/PRO hot path)."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:  # pragma: no cover - depends on the bundle
        raise LicenseError(
            "verifier_unavailable",
            "This build cannot verify licenses: its cryptographic library is missing.",
        ) from exc
    return Ed25519PrivateKey, Ed25519PublicKey, InvalidSignature


def public_key_b64_from_private_bytes(private_raw: bytes) -> str:
    """Return the base64 raw public key for a raw 32-byte private key."""
    private_cls, _public_cls, _invalid = _load_ed25519()
    from cryptography.hazmat.primitives import serialization

    key = private_cls.from_private_bytes(private_raw)
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def build_license_document(
    payload: Mapping[str, Any], *, private_key_raw: bytes, key_id: str
) -> dict[str, Any]:
    """Sign ``payload`` and return the license document.

    Used by the internal issuing tool and by tests. The payload is validated
    with the same rules the verifier applies, so the tool cannot emit a file
    the product would reject.
    """
    validated = _validate_payload(payload, key_id=key_id)
    private_cls, _public_cls, _invalid = _load_ed25519()
    key = private_cls.from_private_bytes(private_key_raw)
    signature = key.sign(canonical_payload_bytes(payload))
    return {
        "adscan_license": validated.format_version,
        "payload": dict(payload),
        "signature": {
            "alg": SIGNATURE_ALGORITHM,
            "kid": key_id,
            "value": base64.b64encode(signature).decode("ascii"),
        },
    }


def parse_license_document(
    raw: bytes | str,
    *,
    trusted_keys: Mapping[str, str] | None = None,
) -> LicensePayload:
    """Verify a license document and return its payload.

    Args:
        raw: The file content.
        trusted_keys: Key id -> base64 raw public key. Defaults to
            :data:`PRODUCTION_PUBLIC_KEYS`. Tests pass their own development
            key here; there is deliberately no environment variable that adds
            a key, so a production appliance accepts production keys only.

    Raises:
        LicenseError: malformed, unsigned, signed by an unknown key, or a
            signature that does not match.
    """
    keys = PRODUCTION_PUBLIC_KEYS if trusted_keys is None else trusted_keys
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if len(raw) > MAX_LICENSE_BYTES:
        raise LicenseError("too_large", "The license file is too large.")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LicenseError("malformed", "The license file is not valid JSON.") from exc
    if (
        not isinstance(document, dict)
        or isinstance(document.get("adscan_license"), bool)
        or document.get("adscan_license") not in SUPPORTED_FORMAT_VERSIONS
    ):
        raise LicenseError(
            "malformed", "The file is not an ADscan license (unknown format)."
        )
    payload = document.get("payload")
    signature = document.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, dict):
        raise LicenseError("malformed", "The license file is incomplete.")
    if payload.get(PAYLOAD_FORMAT_KEY, 1) != document.get("adscan_license"):
        raise LicenseError(
            "malformed", "The license format does not match its signed content."
        )
    if signature.get("alg") != SIGNATURE_ALGORITHM:
        raise LicenseError(
            "malformed", "The license uses an unsupported signature algorithm."
        )
    key_id = str(signature.get("kid") or "")
    public_b64 = keys.get(key_id)
    if not public_b64:
        raise LicenseError(
            "unknown_key",
            "The license was not signed by a key this appliance recognizes.",
        )
    try:
        sig_bytes = base64.b64decode(str(signature.get("value") or ""), validate=True)
        public_raw = base64.b64decode(public_b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise LicenseError("malformed", "The license signature is unreadable.") from exc

    _private_cls, public_cls, invalid_signature = _load_ed25519()
    try:
        public_cls.from_public_bytes(public_raw).verify(
            sig_bytes, canonical_payload_bytes(payload)
        )
    except invalid_signature as exc:
        raise LicenseError(
            "bad_signature",
            "The license signature does not match its content. The file was altered or damaged.",
        ) from exc
    except ValueError as exc:
        raise LicenseError("malformed", "The license signature is unreadable.") from exc
    return _validate_payload(payload, key_id=key_id)


def _require_str(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise LicenseError("malformed", f"The license is missing '{key}'.")
    return value.strip()


def _optional_int(
    payload: Mapping[str, Any], key: str, default: int, maximum: int
) -> int:
    value = payload.get(key, default)
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= maximum
    ):
        raise LicenseError("malformed", f"The license field '{key}' is out of range.")
    return value


def _parse_date(payload: Mapping[str, Any], key: str) -> date:
    text = _require_str(payload, key)
    try:
        return date.fromisoformat(text)
    except ValueError as exc:
        raise LicenseError(
            "malformed", f"The license field '{key}' is not a date."
        ) from exc


def _parse_instant(text: str) -> datetime:
    value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _format_instant(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _reject_floats(value: Any) -> None:
    if isinstance(value, float):
        raise LicenseError("malformed", "The license may not contain decimal numbers.")
    if isinstance(value, dict):
        for item in value.values():
            _reject_floats(item)
    elif isinstance(value, list):
        for item in value:
            _reject_floats(item)


def _validate_payload(payload: Mapping[str, Any], *, key_id: str) -> LicensePayload:
    """Apply the schema rules shared by the issuer and the verifier."""
    if not isinstance(payload, Mapping):
        raise LicenseError("malformed", "The license payload is not an object.")
    _reject_floats(dict(payload))
    edition = _require_str(payload, "edition").lower()
    if edition not in LICENSE_EDITIONS:
        raise LicenseError("malformed", f"Unknown license edition '{edition}'.")
    try:
        issued_at = _parse_instant(_require_str(payload, "issued_at"))
    except ValueError as exc:
        raise LicenseError(
            "malformed", "The license field 'issued_at' is not a timestamp."
        ) from exc
    valid_from = _parse_date(payload, "valid_from")
    valid_until = _parse_date(payload, "valid_until")
    if valid_until < valid_from:
        raise LicenseError("malformed", "The license ends before it starts.")
    entitlements = payload.get("entitlements", {})
    if not isinstance(entitlements, dict):
        raise LicenseError(
            "malformed", "The license field 'entitlements' is not an object."
        )
    deployment = payload.get("deployment", "")
    if not isinstance(deployment, str):
        raise LicenseError("malformed", "The license field 'deployment' is not text.")
    format_version = payload.get(PAYLOAD_FORMAT_KEY, 1)
    if isinstance(format_version, bool) or format_version not in SUPPORTED_FORMAT_VERSIONS:
        raise LicenseError("malformed", "The license format is not one this appliance reads.")
    if format_version >= 2:
        from adscan_core.environment_ledger import EntitlementError, parse_entitlement_policy

        try:
            parse_entitlement_policy(entitlements, format_version=format_version)
        except EntitlementError as exc:
            raise LicenseError("malformed", str(exc)) from exc
    return LicensePayload(
        license_id=_require_str(payload, "license_id"),
        customer=_require_str(payload, "customer"),
        edition=edition,
        issued_at=issued_at,
        valid_from=valid_from,
        valid_until=valid_until,
        grace_days=_optional_int(
            payload, "grace_days", DEFAULT_GRACE_DAYS, MAX_GRACE_DAYS
        ),
        warn_days=_optional_int(
            payload,
            "warn_days",
            POV_WARN_DAYS if edition == "pov" else WARN_DAYS,
            365,
        ),
        clock_tolerance_hours=_optional_int(
            payload, "clock_tolerance_hours", DEFAULT_CLOCK_TOLERANCE_HOURS, 24 * 30
        ),
        deployment=deployment.strip(),
        entitlements=dict(entitlements),
        key_id=key_id,
        format_version=format_version,
    )


# ── Evaluation (pure) ────────────────────────────────────────────────────────


def _days_until(target: datetime, now: datetime) -> int:
    return max(0, math.ceil((target - now).total_seconds() / 86400))


def _human_date(value: date) -> str:
    return f"{value.day} {value.strftime('%B %Y')}"


def _binary_warning(
    binary_expires: date | None, license_payload: LicensePayload | None, now: datetime
) -> str:
    """Warn when the engine image would stop before the license does."""
    if binary_expires is None:
        return ""
    stops_at = datetime.combine(
        binary_expires + timedelta(days=1), time.min, tzinfo=timezone.utc
    )
    if stops_at <= now:
        return (
            f"The assessment engine in this appliance image expired on "
            f"{_human_date(binary_expires)}. Ask ADscan for an updated image."
        )
    if license_payload is not None and stops_at < license_payload.grace_ends_at:
        return (
            f"The assessment engine in this appliance image stops running on "
            f"{_human_date(binary_expires)}, before the license ends. Ask ADscan "
            "for an updated image before then."
        )
    if stops_at - now <= timedelta(days=WARN_DAYS):
        return (
            f"The assessment engine in this appliance image stops running on "
            f"{_human_date(binary_expires)}. Ask ADscan for an updated image."
        )
    return ""


def evaluate_license(
    payload: LicensePayload | None,
    *,
    now: datetime,
    error: LicenseError | None = None,
    last_seen: datetime | None = None,
    binary_expires: date | None = None,
) -> LicenseStatus:
    """Decide the license state at ``now``. Pure: no I/O, no clock reads."""
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    if payload is None:
        if error is None:
            return LicenseStatus(
                state=STATE_MISSING,
                message=(
                    "No ADscan license is installed on this appliance, so new "
                    f"assessments cannot start. {_KEEPS_DATA} {_HOW_TO_INSTALL}"
                ),
                error_code="missing",
                binary_expires=binary_expires,
                binary_warning=_binary_warning(binary_expires, None, now),
            )
        if error.code == ERROR_LICENSE_UNREADABLE:
            # A storage fault on this appliance, not a verdict on the file:
            # asking the client for a new license would send them the wrong way.
            return LicenseStatus(
                state=STATE_INVALID,
                message=LICENSE_STORAGE_UNAVAILABLE_MESSAGE,
                error_code=error.code,
                binary_expires=binary_expires,
                binary_warning=_binary_warning(binary_expires, None, now),
            )
        return LicenseStatus(
            state=STATE_INVALID,
            message=(
                f"The installed license cannot be accepted: {error} New "
                f"assessments cannot start. {_KEEPS_DATA} Ask ADscan for a "
                "valid license file."
            ),
            error_code=error.code,
            binary_expires=binary_expires,
            binary_warning=_binary_warning(binary_expires, None, now),
        )

    common: dict[str, Any] = {
        "license": payload,
        "binary_expires": binary_expires,
        "binary_warning": _binary_warning(binary_expires, payload, now),
    }
    tolerance = timedelta(hours=payload.clock_tolerance_hours)
    reference = max(
        [payload.issued_at] + ([last_seen] if last_seen is not None else [])
    )
    if now < reference - tolerance:
        return LicenseStatus(
            state=STATE_CLOCK_ROLLBACK,
            message=(
                "The system clock is earlier than the last time this appliance "
                f"was used ({_format_instant(reference)}), so new assessments "
                "cannot start until it is corrected. Set the hypervisor time "
                f"for this virtual machine to the current date. {_KEEPS_DATA}"
            ),
            error_code="clock_rollback",
            **common,
        )
    if now < payload.starts_at:
        return LicenseStatus(
            state=STATE_NOT_YET_VALID,
            message=(
                f"The license for {payload.customer} starts on "
                f"{_human_date(payload.valid_from)}. New assessments can start "
                f"from that date. {_KEEPS_DATA}"
            ),
            error_code="not_yet_valid",
            days_remaining=_days_until(payload.ends_at, now),
            **common,
        )
    if now < payload.ends_at:
        days = _days_until(payload.ends_at, now)
        if payload.ends_at - now <= timedelta(days=payload.warn_days):
            return LicenseStatus(
                state=STATE_EXPIRING,
                message=(
                    f"The license for {payload.customer} ends on "
                    f"{_human_date(payload.valid_until)} ({days} day"
                    f"{'s' if days != 1 else ''} left). Contact ADscan to renew; "
                    "renewing is replacing the license file."
                ),
                days_remaining=days,
                **common,
            )
        return LicenseStatus(
            state=STATE_VALID,
            message=(
                f"Licensed to {payload.customer} until "
                f"{_human_date(payload.valid_until)}."
            ),
            days_remaining=days,
            **common,
        )
    if now < payload.grace_ends_at:
        grace_last = (payload.grace_ends_at - timedelta(days=1)).date()
        days = _days_until(payload.grace_ends_at, now)
        return LicenseStatus(
            state=STATE_GRACE,
            message=(
                f"The license for {payload.customer} ended on "
                f"{_human_date(payload.valid_until)}. New assessments remain "
                f"possible until {_human_date(grace_last)} ({days} day"
                f"{'s' if days != 1 else ''} of grace left). Contact ADscan to renew."
            ),
            days_remaining=days,
            **common,
        )
    return LicenseStatus(
        state=STATE_EXPIRED,
        message=(
            f"The license for {payload.customer} ended on "
            f"{_human_date(payload.valid_until)}, so new assessments cannot "
            f"start. {_KEEPS_DATA} Install a renewed license file to resume."
        ),
        error_code="expired",
        days_remaining=0,
        **common,
    )


# ── Files ────────────────────────────────────────────────────────────────────


def license_dir() -> Path:
    """Directory holding the license, the clock state and the engine info.

    ``ADSCAN_LICENSE_DIR`` wins (the web backend container sets it to its
    mount); otherwise ``<state dir>/license``. On the appliance both resolve to
    ``/home/adscan/.adscan/state/license``: the scan container reaches it
    through the state-dir bind mount the launcher already provides.
    """
    explicit = os.getenv(LICENSE_DIR_ENV, "").strip()
    if explicit:
        return Path(explicit)
    from adscan_core.paths import get_state_dir

    return get_state_dir() / "license"


def license_path(directory: Path | None = None) -> Path:
    """Path of the installed license file."""
    return (directory or license_dir()) / LICENSE_FILENAME


def _atomic_write(path: Path, data: bytes) -> None:
    """Replace ``path`` atomically; the file takes the directory's owner.

    Raises:
        LicenseStorageError: the directory or the file could not be written.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    except OSError as exc:
        raise LicenseStorageError.from_os_error(exc, path) from exc
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(tmp, 0o644)
        adopt_directory_owner(Path(tmp), directory=path.parent)
        os.replace(tmp, path)
    except BaseException as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        if isinstance(exc, OSError) and not isinstance(exc, LicenseStorageError):
            raise LicenseStorageError.from_os_error(exc, path) from exc
        raise


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _current_boot_id() -> str:
    """Kernel boot id (shared by the host and its containers), or ``""``."""
    try:
        return _BOOT_ID_PATH.read_text(encoding="ascii").strip()
    except OSError:
        return ""


def mark_clock_stepped(directory: Path | None = None, *, by: str = "engine") -> None:
    """Record that the host clock is now stepped to a domain controller.

    Best-effort. The marker carries the boot id, so one left behind by a crash
    stops counting after a reboot (which resets the clock from the RTC).
    """
    target = directory or license_dir()
    try:
        _atomic_write(
            target / CLOCK_STEPPED_FILENAME,
            json.dumps({"boot_id": _current_boot_id(), "by": by}).encode("ascii"),
        )
    except OSError:
        return


def clear_clock_stepped(directory: Path | None = None) -> None:
    """Remove the stepped-clock marker (best-effort)."""
    target = directory or license_dir()
    try:
        (target / CLOCK_STEPPED_FILENAME).unlink()
    except OSError:
        return


def clock_currently_stepped(directory: Path | None = None) -> bool:
    """True while ADscan holds the host clock stepped to a domain controller."""
    data = _read_json((directory or license_dir()) / CLOCK_STEPPED_FILENAME)
    if data is None:
        return False
    recorded = str(data.get("boot_id") or "")
    current = _current_boot_id()
    if recorded and current and recorded != current:
        return False
    return True


def read_last_seen(directory: Path | None = None) -> datetime | None:
    """Return the persisted clock high-water mark, if any."""
    data = _read_json((directory or license_dir()) / CLOCK_STATE_FILENAME)
    if not data or not isinstance(data.get("last_seen"), str):
        return None
    try:
        return _parse_instant(data["last_seen"])
    except ValueError:
        return None


def record_last_seen(now: datetime, directory: Path | None = None) -> None:
    """Advance the clock high-water mark to ``now`` (never moves it back).

    Never while the host clock is stepped to a domain controller: that instant
    is the DC's time, not real time, and one DC days ahead would otherwise
    block every later assessment as a clock rollback. The mark then advances
    at the next launch after the clock is restored.

    Best-effort: a read-only or missing directory must never block a scan
    that the license already allows. Other keys of the state file (the
    environment seal) are preserved. A failure is still recorded (telemetry
    and the debug log), because a mark that never advances quietly weakens the
    clock-rollback protection.
    """
    target = directory or license_dir()
    if clock_currently_stepped(target):
        return
    previous = read_last_seen(target)
    if previous is not None and previous >= now:
        return
    from adscan_core.environment_ledger import state_file_lock

    try:
        with state_file_lock(target):
            state = _read_json(target / CLOCK_STATE_FILENAME) or {}
            state["last_seen"] = _format_instant(now)
            _atomic_write(
                target / CLOCK_STATE_FILENAME,
                json.dumps(state, sort_keys=True).encode("ascii"),
            )
    except OSError as exc:
        _record_storage_failure(exc)
        return


def _record_storage_failure(exc: OSError) -> None:
    """Report a swallowed license-storage failure (best-effort, never raises)."""
    try:
        from adscan_core import telemetry  # noqa: PLC0415
        from adscan_core.rich_output import print_exception  # noqa: PLC0415

        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    except Exception:  # noqa: BLE001 - reporting must never break the caller
        return


def _parse_binary_expires(value: str | None) -> date | None:
    text = (value or "").strip()
    if not text or text.lower() == "none":
        return None
    try:
        return date.fromisoformat(text)
    except ValueError:
        return None


def record_engine_info(directory: Path | None = None) -> None:
    """Record the engine image's own expiry beside the license.

    Called by the engine (which knows ``ADSCAN_BINARY_EXPIRES``, baked at image
    build) so the web platform, a different container, can warn when the
    image would stop before the license. Best-effort.
    """
    target = directory or license_dir()
    expires = _parse_binary_expires(os.getenv(BINARY_EXPIRES_ENV))
    data = {
        "binary_expires": expires.isoformat() if expires else None,
        "runtime_version": os.getenv("ADSCAN_RUNTIME_VERSION") or None,
        "recorded_at": _format_instant(datetime.now(timezone.utc)),
    }
    try:
        _atomic_write(target / ENGINE_INFO_FILENAME, json.dumps(data).encode("ascii"))
    except OSError:
        return


def read_binary_expires(directory: Path | None = None) -> date | None:
    """Expiry of the engine image: own env first, then the recorded engine info."""
    own = _parse_binary_expires(os.getenv(BINARY_EXPIRES_ENV))
    if own is not None:
        return own
    data = _read_json((directory or license_dir()) / ENGINE_INFO_FILENAME)
    if not data:
        return None
    value = data.get("binary_expires")
    return _parse_binary_expires(value if isinstance(value, str) else None)


# ── Entry points ─────────────────────────────────────────────────────────────


def check_license(
    *,
    now: datetime | None = None,
    record: bool = False,
    directory: Path | None = None,
    trusted_keys: Mapping[str, str] | None = None,
) -> LicenseStatus:
    """Read, verify and evaluate the installed license.

    Args:
        now: Override the clock (tests). Defaults to the current UTC time.
        record: Advance the clock high-water mark when the license allows the
            launch. Only scan-launch seams pass True; status reads do not, so a
            panel open while a scan has the clock aligned to a domain
            controller never moves the mark.
        directory: Override :func:`license_dir` (tests).
        trusted_keys: Override :data:`PRODUCTION_PUBLIC_KEYS` (tests).
    """
    current = now or datetime.now(timezone.utc)
    target = directory or license_dir()
    payload: LicensePayload | None = None
    error: LicenseError | None = None
    path = license_path(target)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raw = None
    except OSError:
        raw = None
        error = LicenseError(ERROR_LICENSE_UNREADABLE, "The license file cannot be read.")
    if raw is not None:
        try:
            payload = parse_license_document(raw, trusted_keys=trusted_keys)
        except LicenseError as exc:
            error = exc
    status = evaluate_license(
        payload,
        now=current,
        error=error,
        last_seen=read_last_seen(target),
        binary_expires=read_binary_expires(target),
    )
    if payload is not None:
        status = _with_environment_usage(status, payload, target)
    if record and status.scans_allowed:
        record_last_seen(current, target)
    return status


def _with_environment_usage(
    status: LicenseStatus, payload: LicensePayload, directory: Path
) -> LicenseStatus:
    """Attach the environment usage (best-effort: a read error shows nothing)."""
    from dataclasses import replace

    try:
        from adscan_core.environment_ledger import environment_usage

        usage = environment_usage(payload, directory=directory)
    except Exception:  # noqa: BLE001 - display data must never break a status read
        return status
    if usage is None:
        return status
    return replace(status, environments=usage)


def not_required_status() -> LicenseStatus:
    """Status for an edition that does not use a license (LITE / PRO)."""
    return LicenseStatus(
        state=STATE_NOT_REQUIRED,
        message="This edition does not use a license file.",
    )


def scan_launch_status(
    *,
    record: bool = True,
    now: datetime | None = None,
    directory: Path | None = None,
    trusted_keys: Mapping[str, str] | None = None,
    enterprise: bool | None = None,
) -> LicenseStatus:
    """SSOT for every seam that starts a NEW assessment.

    Non-Enterprise editions get ``not_required`` without touching the disk,
    so LITE and PRO behave exactly as before.
    """
    if enterprise is None:
        from adscan_core.tier import is_enterprise_edition

        enterprise = is_enterprise_edition()
    if not enterprise:
        return not_required_status()
    return check_license(
        now=now, record=record, directory=directory, trusted_keys=trusted_keys
    )


def install_license(
    raw: bytes | str,
    *,
    now: datetime | None = None,
    directory: Path | None = None,
    trusted_keys: Mapping[str, str] | None = None,
) -> LicenseStatus:
    """Verify a license file and, only if it verifies, make it the active one.

    An expired or not-yet-valid file still installs (it is genuine; the status
    says what it allows). A file that fails verification never replaces the
    current one.

    Raises:
        LicenseError: the file does not verify.
    """
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    parse_license_document(raw, trusted_keys=trusted_keys)
    target = directory or license_dir()
    _atomic_write(license_path(target), raw)
    return check_license(now=now, directory=target, trusted_keys=trusted_keys)


__all__ = [
    "BINARY_EXPIRES_ENV",
    "CLOCK_STATE_FILENAME",
    "CLOCK_STEPPED_FILENAME",
    "DEFAULT_CLOCK_TOLERANCE_HOURS",
    "DEFAULT_GRACE_DAYS",
    "ENGINE_INFO_FILENAME",
    "ERROR_LICENSE_UNREADABLE",
    "LICENSE_BLOCKED_EXIT_CODE",
    "LICENSE_DIR_ENV",
    "LICENSE_FILENAME",
    "LicenseError",
    "LicensePayload",
    "LicenseStatus",
    "PAYLOAD_FORMAT_KEY",
    "PRODUCTION_PUBLIC_KEYS",
    "SUPPORTED_FORMAT_VERSIONS",
    "POV_WARN_DAYS",
    "WARN_DAYS",
    "build_license_document",
    "canonical_payload_bytes",
    "check_license",
    "clear_clock_stepped",
    "clock_currently_stepped",
    "evaluate_license",
    "install_license",
    "license_dir",
    "license_path",
    "mark_clock_stepped",
    "not_required_status",
    "parse_license_document",
    "public_key_b64_from_private_bytes",
    "read_binary_expires",
    "read_last_seen",
    "record_engine_info",
    "record_last_seen",
    "scan_launch_status",
]
