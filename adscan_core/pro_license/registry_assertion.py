"""Installation-signed credential for the licence-authorised image registry.

The launcher pulls the PRO image from ``registry.adscanpro.com`` with no stored
password (spec ``2026-11-12-licence-authorised-pro-registry.md`` § 3). Docker
sends Basic credentials to the token endpoint; this module builds them:

* username: the installation id;
* password: base64url of an envelope the installation key signs, payload
  ``{kind: "registry_auth", installation_id, request_id, created_at,
  expires_at, aud}``.

The same envelope and signature rules as every licence request
(:func:`adscan_core.enterprise_license.sign_payload`), but it is NOT a licence
request: the server never stores it in its request table and it does not bump
the installation's request ``sequence``, so pulling an image can never trip
clone detection. Its lifetime is bounded (12 hours by default) because the
Docker daemon receives the credentials once at the start of a pull and reuses
them for every token during a long download.

Both sides use this module: the launcher calls :func:`build_registry_credentials`
and the licence server calls :func:`verify_registry_assertion` with the public
key it stored at activation (never the one a request carries).
"""

from __future__ import annotations

import base64
import binascii
import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from adscan_core.enterprise_license import FORMAT_VERSION, PAYLOAD_FORMAT_KEY, LicenseError
from adscan_core.outbound_links import ADSCAN_REGISTRY_HOST
from adscan_core.pro_license import documents as docs

#: ``kind`` of the signed payload. Not a member of ``documents.REQUEST_KINDS``
#: on purpose: the licence routes must never accept it.
ASSERTION_KIND = "registry_auth"
#: The registry service the assertion is meant for (the token ``aud``).
DEFAULT_REGISTRY_SERVICE = ADSCAN_REGISTRY_HOST
#: Default and maximum lifetime of one assertion.
DEFAULT_TTL = timedelta(hours=12)
MAX_TTL = timedelta(hours=12)
#: Clock skew tolerated between the installation and the server.
MAX_SKEW = timedelta(minutes=10)
#: An assertion is a few hundred bytes; anything far larger is not one.
MAX_ASSERTION_BYTES = 8 * 1024


@dataclass(frozen=True)
class RegistryCredentials:
    """Docker Basic credentials for the registry token endpoint."""

    username: str
    password: str = ""

    def __repr__(self) -> str:  # never print the secret half
        return f"RegistryCredentials(username={self.username!r}, password=<redacted>)"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(text: str) -> bytes:
    padded = text + "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def build_registry_credentials(
    installation: Any,
    *,
    service: str = DEFAULT_REGISTRY_SERVICE,
    ttl: timedelta = DEFAULT_TTL,
    now: datetime | None = None,
) -> RegistryCredentials:
    """Sign a fresh registry assertion with ``installation`` (an ``Installation``).

    Args:
        installation: The machine's installation (its key signs the assertion).
        service: The registry host the assertion is for.
        ttl: Lifetime, capped at :data:`MAX_TTL`.
        now: Creation instant (tests); defaults to the current UTC time.
    """
    current = now or docs.utc_now()
    lifetime = min(ttl, MAX_TTL)
    payload = {
        PAYLOAD_FORMAT_KEY: FORMAT_VERSION,
        "kind": ASSERTION_KIND,
        "installation_id": installation.installation_id,
        "request_id": uuid.uuid4().hex,
        "created_at": docs.format_instant(current),
        "expires_at": docs.format_instant(current + lifetime),
        "aud": service,
    }
    envelope = installation.sign(payload)
    raw = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return RegistryCredentials(username=installation.installation_id, password=_b64url(raw))


def looks_like_assertion(password: str) -> bool:
    """Cheap shape test: a base64url JSON envelope (an activation key is ``ak1-…``)."""
    text = str(password or "")
    return bool(text) and not text.lower().startswith("ak1-") and len(text) <= MAX_ASSERTION_BYTES * 2


def verify_registry_assertion(
    password: str,
    *,
    username: str,
    stored_public_key: str,
    service: str = DEFAULT_REGISTRY_SERVICE,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify an assertion against the installation key the server stored.

    Args:
        password: The Basic password Docker sent.
        username: The Basic username (must equal the installation id).
        stored_public_key: The base64 Ed25519 key recorded at activation.
        service: The registry service this server issues tokens for.
        now: Current instant (tests).

    Returns:
        The verified payload.

    Raises:
        LicenseError: malformed, signed by another key, for another service,
            not yet valid, expired, or longer-lived than :data:`MAX_TTL`.
    """
    from adscan_core.pro_license.model import verify_pro_envelope

    current = now or docs.utc_now()
    try:
        raw = _b64url_decode(str(password))
    except (ValueError, binascii.Error) as exc:
        raise LicenseError("malformed", "The registry credential is not readable.") from exc
    if len(raw) > MAX_ASSERTION_BYTES:
        raise LicenseError("too_large", "The registry credential is too large.")
    installation_id = str(username or "")
    payload, kid = verify_pro_envelope(raw, trusted_keys={installation_id: stored_public_key})
    if kid != installation_id or payload.get("installation_id") != installation_id:
        raise LicenseError("malformed", "The registry credential names another installation.")
    if payload.get("kind") != ASSERTION_KIND:
        raise LicenseError("malformed", "The credential is not a registry credential.")
    if payload.get("aud") != service:
        raise LicenseError("wrong_audience", "The registry credential is for another registry.")
    try:
        created = docs.parse_instant(str(payload.get("created_at")))
        expires = docs.parse_instant(str(payload.get("expires_at")))
    except ValueError as exc:
        raise LicenseError("malformed", "The registry credential has no valid lifetime.") from exc
    if expires - created > MAX_TTL or expires <= created:
        raise LicenseError("malformed", "The registry credential lifetime is not allowed.")
    if created > current + MAX_SKEW:
        raise LicenseError("not_yet_valid", "The registry credential is dated in the future.")
    if current > expires + MAX_SKEW:
        raise LicenseError("expired", "The registry credential expired. Run the command again.")
    return dict(payload)


def docker_config_auth(credentials: RegistryCredentials, host: str) -> Mapping[str, Any]:
    """A Docker ``config.json`` body that carries ``credentials`` for ``host`` only."""
    token = base64.b64encode(f"{credentials.username}:{credentials.password}".encode("utf-8")).decode("ascii")
    return {"auths": {host: {"auth": token}}}


# ── Enterprise appliance: the licence is the credential ──────────────────────
#
# The appliance's online update channel pulls from the same registry, under the
# ``appliance/`` namespace. An appliance has no grant on the licence server: its
# Enterprise licence is an offline file signed by ADscan. So the Basic password
# carries that licence plus an assertion signed by an appliance key the
# appliance generated for itself (an ``Installation`` in its own state
# directory). The token service verifies the licence against the Enterprise
# licence keys, evaluates its term, refuses a licence ADscan revoked, and pins
# the first appliance key it sees per licence, so a copied licence file does not
# pull from a second machine. Everything is outbound: the appliance asks,
# nothing calls in.

APPLIANCE_ASSERTION_KIND = "appliance_registry_auth"
#: Prefix of the Basic username of an appliance credential (no colon: Basic auth splits on it).
APPLIANCE_USERNAME_PREFIX = "appliance."
#: A licence plus an assertion; generous, still far below header limits.
MAX_APPLIANCE_CREDENTIAL_BYTES = 24 * 1024


def build_appliance_credentials(
    licence_document: bytes | str,
    appliance_key: Any,
    *,
    service: str = DEFAULT_REGISTRY_SERVICE,
    ttl: timedelta = DEFAULT_TTL,
    now: datetime | None = None,
) -> RegistryCredentials:
    """Credentials for the appliance namespace: the licence file plus a signed assertion.

    Args:
        licence_document: The installed Enterprise licence file, as read.
        appliance_key: An ``Installation`` holding this appliance's own key pair.
        service: The registry host.
        ttl: Assertion lifetime (capped at :data:`MAX_TTL`).
        now: Creation instant (tests).
    """
    raw_licence = licence_document.encode("utf-8") if isinstance(licence_document, str) else licence_document
    licence = json.loads(raw_licence.decode("utf-8"))
    licence_id = str((licence.get("payload") or {}).get("license_id") or "")
    current = now or docs.utc_now()
    payload = {
        PAYLOAD_FORMAT_KEY: FORMAT_VERSION,
        "kind": APPLIANCE_ASSERTION_KIND,
        "license_id": licence_id,
        "appliance_key_id": appliance_key.installation_id,
        "appliance_key": appliance_key.public_key_b64,
        "request_id": uuid.uuid4().hex,
        "created_at": docs.format_instant(current),
        "expires_at": docs.format_instant(current + min(ttl, MAX_TTL)),
        "aud": service,
    }
    bundle = {"licence": licence, "assertion": appliance_key.sign(payload)}
    raw = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return RegistryCredentials(username=APPLIANCE_USERNAME_PREFIX + licence_id, password=_b64url(raw))


@dataclass(frozen=True)
class ApplianceProof:
    """What an appliance credential proved."""

    licence: Any  # adscan_core.enterprise_license.LicensePayload
    appliance_key_id: str
    appliance_key: str


def verify_appliance_credentials(
    password: str,
    *,
    username: str,
    enterprise_trusted_keys: Mapping[str, str] | None = None,
    service: str = DEFAULT_REGISTRY_SERVICE,
    now: datetime | None = None,
) -> ApplianceProof:
    """Verify an appliance credential (licence signature, assertion signature, lifetime).

    The licence TERM and revocation are the caller's to judge (the token service
    evaluates them with :func:`adscan_core.enterprise_license.evaluate_license`
    and its own revocation table).

    Raises:
        LicenseError: anything that does not verify.
    """
    from adscan_core.enterprise_license import parse_license_document
    from adscan_core.pro_license.installation import installation_id_for
    from adscan_core.pro_license.model import verify_pro_envelope

    current = now or docs.utc_now()
    try:
        raw = _b64url_decode(str(password))
    except (ValueError, binascii.Error) as exc:
        raise LicenseError("malformed", "The appliance credential is not readable.") from exc
    if len(raw) > MAX_APPLIANCE_CREDENTIAL_BYTES:
        raise LicenseError("too_large", "The appliance credential is too large.")
    try:
        bundle = json.loads(raw.decode("utf-8"))
        licence_doc = bundle["licence"]
        assertion = bundle["assertion"]
        key_b64 = str(assertion["payload"]["appliance_key"])
        key_id = installation_id_for(key_b64)
    except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
        raise LicenseError("malformed", "The appliance credential is not readable.") from exc
    licence = parse_license_document(json.dumps(licence_doc), trusted_keys=enterprise_trusted_keys)
    payload, kid = verify_pro_envelope(json.dumps(assertion), trusted_keys={key_id: key_b64})
    if kid != key_id or payload.get("appliance_key_id") != key_id:
        raise LicenseError("malformed", "The appliance credential names another key.")
    if payload.get("kind") != APPLIANCE_ASSERTION_KIND:
        raise LicenseError("malformed", "The credential is not an appliance registry credential.")
    if payload.get("license_id") != licence.license_id or username != APPLIANCE_USERNAME_PREFIX + licence.license_id:
        raise LicenseError("malformed", "The appliance credential names another licence.")
    if payload.get("aud") != service:
        raise LicenseError("wrong_audience", "The appliance credential is for another registry.")
    try:
        created = docs.parse_instant(str(payload.get("created_at")))
        expires = docs.parse_instant(str(payload.get("expires_at")))
    except ValueError as exc:
        raise LicenseError("malformed", "The appliance credential has no valid lifetime.") from exc
    if expires - created > MAX_TTL or expires <= created:
        raise LicenseError("malformed", "The appliance credential lifetime is not allowed.")
    if created > current + MAX_SKEW:
        raise LicenseError("not_yet_valid", "The appliance credential is dated in the future.")
    if current > expires + MAX_SKEW:
        raise LicenseError("expired", "The appliance credential expired. Try the update again.")
    return ApplianceProof(licence=licence, appliance_key_id=key_id, appliance_key=key_b64)


__all__ = [
    "APPLIANCE_ASSERTION_KIND",
    "APPLIANCE_USERNAME_PREFIX",
    "ASSERTION_KIND",
    "DEFAULT_REGISTRY_SERVICE",
    "DEFAULT_TTL",
    "MAX_TTL",
    "ApplianceProof",
    "RegistryCredentials",
    "build_appliance_credentials",
    "build_registry_credentials",
    "docker_config_auth",
    "looks_like_assertion",
    "verify_appliance_credentials",
    "verify_registry_assertion",
]
