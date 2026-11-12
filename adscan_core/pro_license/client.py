"""Talking to the licence server: direct HTTPS, or a relay file through a partner platform.

The engine never connects on a plain run (spec § 5.4): it sends only queued
work (an activation, a registration, a band report, an engagement report, a
due renewal, a deactivation). Direct mode posts each queued request; relay mode writes them
all to one batch file that a partner platform forwards to ``POST /v1/relay``
and whose answers come back through :func:`import_relay`. Both paths apply
answers through :meth:`ProLicenseStore.apply_answer`, which accepts only
documents signed by our server for a request this installation still holds.

Relay batch format (documented for integrators)::

    {"adscan_relay": 1, "direction": "requests", "items": [<signed request>, ...]}
    {"adscan_relay": 1, "direction": "answers",  "items": [<signed answer>, ...]}

A requests batch may hold an activation request, which carries the activation
key: it is written with mode 0600 and must be handled as a secret.
"""

from __future__ import annotations

import ipaddress
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, time, timezone
from pathlib import Path
from typing import Any

from adscan_core.enterprise_license import LicenseError
from adscan_core.outbound_links import ADSCAN_SITE_HOST
from adscan_core.pro_license import documents as docs
from adscan_core.pro_license._io import atomic_write
from adscan_core.pro_license.model import ProLicense
from adscan_core.pro_license.state import STATUS_REGISTERED, ProLicenseStore

SERVER_URL_ENV = "ADSCAN_LICENSE_SERVER_URL"
#: Placeholder until the production hostname is decided (spec open question Q7).
#: An API endpoint, not a marketing link, so it is composed from the site host
#: rather than a CTA placement (no UTM parameters on an API call).
DEFAULT_SERVER_URL = f"https://license.{ADSCAN_SITE_HOST}"
DEFAULT_TIMEOUT_SECONDS = 5.0
RELAY_FORMAT = 1

ROUTE_FOR_KIND = {
    docs.KIND_ACTIVATION: "/v1/activate",
    docs.KIND_RENEWAL: "/v1/renew",
    docs.KIND_REGISTRATION: "/v1/register",
    docs.KIND_BAND_REPORT: "/v1/band",
    docs.KIND_ENGAGEMENT_REPORT: "/v1/engagement",
    docs.KIND_DEACTIVATION: "/v1/deactivate",
}


def server_url() -> str:
    """The licence server base URL (``ADSCAN_LICENSE_SERVER_URL`` overrides).

    Overriding it is harmless: answers verify against our public key only.
    """
    return (os.getenv(SERVER_URL_ENV, "").strip() or DEFAULT_SERVER_URL).rstrip("/")


def engine_version() -> str:
    """Best-effort engine version for requests (no host detail)."""
    version = os.getenv("ADSCAN_RUNTIME_VERSION", "").strip()
    if version:
        return version
    try:
        from importlib.metadata import version as package_version

        return package_version("adscan")
    except Exception:  # noqa: BLE001 - informational only
        return "unknown"


def _is_loopback(host: str) -> bool:
    if host in ("localhost",):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class HttpTransport:
    """POST signed documents to the licence server. Never raises on network errors."""

    def __init__(self, base_url: str | None = None, *, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> None:
        self.base_url = (base_url or server_url()).rstrip("/")
        parsed = urllib.parse.urlparse(self.base_url)
        if parsed.scheme != "https" and not (parsed.scheme == "http" and _is_loopback(parsed.hostname or "")):
            raise ValueError("The licence server must be reached over HTTPS (plain HTTP only on loopback).")
        self.timeout = timeout
        self.last_error = ""

    def _post(self, path: str, body: Mapping[str, Any]) -> Any:
        data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path, data=data, method="POST", headers={"Content-Type": "application/json"}
        )
        try:
            context = None
            if self.base_url.startswith("https"):
                import ssl

                try:
                    import certifi

                    context = ssl.create_default_context(cafile=certifi.where())
                except ImportError:
                    context = ssl.create_default_context()
            with urllib.request.urlopen(request, timeout=self.timeout, context=context) as response:
                self.last_error = ""
                return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            try:
                detail = json.loads(exc.read())
                self.last_error = str(detail.get("message") or detail.get("error") or exc.code)
            except Exception:  # noqa: BLE001
                self.last_error = f"HTTP {exc.code}"
            return None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            self.last_error = str(getattr(exc, "reason", exc)) or exc.__class__.__name__
            return None

    def send(self, document: Mapping[str, Any]) -> dict[str, Any] | None:
        """Send one request; return the server's signed answer, or None."""
        route = ROUTE_FOR_KIND.get(str(document.get("payload", {}).get("kind")))
        if route is None:
            return None
        answer = self._post(route, document)
        return answer if isinstance(answer, dict) and "payload" in answer else None


# ── Results ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ActivationResult:
    ok: bool
    message: str
    queued: bool = False
    notice_code: str = ""
    licence: ProLicense | None = None


@dataclass
class SyncSummary:
    sent: int = 0
    applied: int = 0
    unreachable: bool = False
    rejected: list[tuple[str, str]] = field(default_factory=list)
    notices: list[tuple[str, str]] = field(default_factory=list)
    error: str = ""


@dataclass
class ImportSummary:
    applied: int = 0
    rejected: list[tuple[str, str]] = field(default_factory=list)
    notices: list[tuple[str, str]] = field(default_factory=list)


# ── Activation ───────────────────────────────────────────────────────────────


def normalize_activation_key(key: str) -> str:
    return str(key or "").strip().lower()


def queue_activation(store: ProLicenseStore, activation_key: str, *, seat_label: str | None = None) -> dict[str, Any]:
    """Build and queue a signed activation request (replacing an older one)."""
    for item in store.pending():
        if item.get("kind") == docs.KIND_ACTIVATION:
            store.drop_pending(str(item["request_id"]))
    document = docs.build_request(
        store.installation(),
        docs.KIND_ACTIVATION,
        engine_version=engine_version(),
        activation_key=normalize_activation_key(activation_key),
        seat_label=(seat_label or None),
    )
    return store.add_pending(document)


def activate(
    store: ProLicenseStore,
    activation_key: str,
    *,
    transport: HttpTransport | None,
    seat_label: str | None = None,
    trusted_keys: Mapping[str, str] | None = None,
) -> ActivationResult:
    """Activate this installation. ``transport=None`` only queues it (relay mode)."""
    if not normalize_activation_key(activation_key).startswith("ak1-"):
        return ActivationResult(False, "That does not look like an ADscan activation key (it starts with ak1-).")
    pending = queue_activation(store, activation_key, seat_label=seat_label)
    if transport is None:
        return ActivationResult(
            False,
            "The activation request is ready. Send it with `adscan license relay export` through your "
            "platform, then load the answer with `adscan license relay import`.",
            queued=True,
        )
    answer = transport.send(pending["document"])
    if answer is None:
        return ActivationResult(
            False,
            "ADscan could not reach the licence server"
            + (f" ({transport.last_error})" if transport.last_error else "")
            + ". The request is kept. Run the command again when this machine is online, or send it "
            "through your platform with `adscan license relay export`.",
            queued=True,
        )
    result = store.apply_answer(answer, trusted_keys=trusted_keys)
    if result.applied and result.kind == docs.KIND_LICENCE:
        _save_sidecar_credential(store, answer)
        licence, _error = store.load_licence(trusted_keys=trusted_keys)
        return ActivationResult(True, result.message, licence=licence)
    if result.applied and result.notice_code:
        return ActivationResult(False, result.message or result.notice_code, notice_code=result.notice_code)
    return ActivationResult(False, f"The licence server's answer could not be accepted: {result.message}")


def _save_sidecar_credential(store: ProLicenseStore, answer: Mapping[str, Any]) -> None:
    credential = answer.get("registry_credential")
    if isinstance(credential, Mapping):
        store.save_registry_credential(credential)


def install_offline_licence(
    store: ProLicenseStore, raw: bytes | str, *, trusted_keys: Mapping[str, str] | None = None
) -> ProLicense:
    """Install an offline engagement licence file (``adscan license install``).

    Raises:
        LicenseError: it does not verify, is not an offline licence, or names another installation.
    """
    from adscan_core.pro_license.model import POLICY_OFFLINE, parse_pro_license

    licence = parse_pro_license(raw, trusted_keys=trusted_keys)
    if licence.registration_policy != POLICY_OFFLINE:
        raise LicenseError(
            "not_offline", "This file is not an offline engagement licence; activate online licences instead."
        )
    return store.install_licence_document(raw, trusted_keys=trusted_keys)


# ── Queued work ──────────────────────────────────────────────────────────────


def queue_renewal_if_due(store: ProLicenseStore, licence: ProLicense | None, *, now: datetime | None = None) -> bool:
    """Queue a renewal when the licence reached ``renew_after`` (once)."""
    if licence is None or licence.renew_after is None:
        return False
    current = now or docs.utc_now()
    if current < datetime.combine(licence.renew_after, time.min, tzinfo=timezone.utc):
        return False
    if store.pending_of_kind(docs.KIND_RENEWAL, license_id=licence.license_id) is not None:
        return False
    store.add_pending(
        docs.build_request(
            store.installation(), docs.KIND_RENEWAL, engine_version=engine_version(), license_id=licence.license_id
        )
    )
    return True


def queue_band_report(store: ProLicenseStore, licence: ProLicense, domain_code: str, identities: int) -> bool:
    """Queue a band report when the band of a registered or pending code changed."""
    band = licence.band_for(int(identities))
    entry = store.register_entries().get(domain_code)
    if entry is None or entry.get("band") == band:
        return False
    store.upsert_entry(domain_code, band=band)
    for item in store.pending():
        payload = item.get("document", {}).get("payload", {})
        if item.get("kind") == docs.KIND_BAND_REPORT and payload.get("domain_code") == domain_code:
            store.drop_pending(str(item["request_id"]))
    store.add_pending(
        docs.build_request(
            store.installation(),
            docs.KIND_BAND_REPORT,
            engine_version=engine_version(),
            license_id=licence.license_id,
            domain_code=domain_code,
            band=band,
        )
    )
    return True


def _ordered_pending(store: ProLicenseStore) -> list[dict[str, Any]]:
    """Registrations before band and engagement reports, so a report always follows its code."""
    order = {
        docs.KIND_ACTIVATION: 0,
        docs.KIND_RENEWAL: 1,
        docs.KIND_REGISTRATION: 2,
        docs.KIND_BAND_REPORT: 3,
        docs.KIND_ENGAGEMENT_REPORT: 4,
        docs.KIND_DEACTIVATION: 5,
    }
    return sorted(store.pending(), key=lambda item: order.get(str(item.get("kind")), 9))


def sync(
    store: ProLicenseStore,
    transport: HttpTransport,
    *,
    trusted_keys: Mapping[str, str] | None = None,
    now: datetime | None = None,
) -> SyncSummary:
    """Send every queued request directly; stop at the first unreachable attempt."""
    summary = SyncSummary()
    licence, _error = store.load_licence(trusted_keys=trusted_keys)
    queue_renewal_if_due(store, licence, now=now)
    for item in _ordered_pending(store):
        answer = transport.send(item["document"])
        summary.sent += 1
        if answer is None:
            summary.unreachable = True
            summary.error = transport.last_error
            break
        result = store.apply_answer(answer, trusted_keys=trusted_keys)
        if result.applied:
            summary.applied += 1
            if result.notice_code:
                summary.notices.append((result.notice_code, result.message))
        else:
            summary.rejected.append((str(item["request_id"]), result.reason))
    return summary


def has_pending_work(store: ProLicenseStore, *, now: datetime | None = None, trusted_keys=None) -> bool:
    """True when a connection would achieve something (queued request or due renewal)."""
    if store.pending():
        return True
    licence, _error = store.load_licence(trusted_keys=trusted_keys)
    if licence is None or licence.renew_after is None:
        return False
    return (now or docs.utc_now()) >= datetime.combine(licence.renew_after, time.min, tzinfo=timezone.utc)


# ── Relay ────────────────────────────────────────────────────────────────────


def export_relay(store: ProLicenseStore, *, now: datetime | None = None, trusted_keys=None) -> dict[str, Any]:
    """Every queued request in one batch (idempotent: same request ids each time)."""
    licence, _error = store.load_licence(trusted_keys=trusted_keys)
    queue_renewal_if_due(store, licence, now=now)
    return {
        "adscan_relay": RELAY_FORMAT,
        "direction": "requests",
        "items": [item["document"] for item in _ordered_pending(store)],
    }


def import_relay(
    store: ProLicenseStore, batch: Mapping[str, Any], *, trusted_keys: Mapping[str, str] | None = None
) -> ImportSummary:
    """Verify and apply every answer of a relay batch."""
    summary = ImportSummary()
    if (
        not isinstance(batch, Mapping)
        or batch.get("adscan_relay") != RELAY_FORMAT
        or batch.get("direction") != "answers"
        or not isinstance(batch.get("items"), list)
    ):
        summary.rejected.append(("", "not_an_answers_batch"))
        return summary
    for item in batch["items"]:
        if not isinstance(item, Mapping) or "payload" not in item:
            reason = str(item.get("error")) if isinstance(item, Mapping) and item.get("error") else "malformed"
            summary.rejected.append(("", reason))
            continue
        request_id = str(item.get("payload", {}).get("request_id") or "")
        result = store.apply_answer(item, trusted_keys=trusted_keys)
        if result.applied:
            summary.applied += 1
            if result.kind == docs.KIND_LICENCE:
                _save_sidecar_credential(store, item)
            if result.notice_code:
                summary.notices.append((result.notice_code, result.message))
        else:
            summary.rejected.append((request_id, result.reason))
    return summary


def write_relay_batch(batch: Mapping[str, Any], target: Path | str) -> None:
    """Write a batch to ``target`` ("-" = stdout). Files are 0600 (may hold the activation key)."""
    data = json.dumps(batch, indent=2, sort_keys=True).encode("utf-8")
    if str(target) == "-":
        sys.stdout.write(data.decode("utf-8") + "\n")
        sys.stdout.flush()
        return
    atomic_write(Path(target), data, mode=0o600)


def read_relay_batch(source: Path | str) -> Any:
    """Read a batch from ``source`` ("-" = stdin)."""
    text = sys.stdin.read() if str(source) == "-" else Path(source).read_text(encoding="utf-8")
    return json.loads(text)


# ── Deactivation ─────────────────────────────────────────────────────────────


def deactivate(
    store: ProLicenseStore,
    *,
    transport: HttpTransport | None,
    trusted_keys: Mapping[str, str] | None = None,
) -> ActivationResult:
    """Release this installation's seat, then remove the local licence."""
    licence, _error = store.load_licence(trusted_keys=trusted_keys)
    if licence is None:
        return ActivationResult(False, "No PRO licence is active on this machine.")
    pending = store.pending_of_kind(docs.KIND_DEACTIVATION, license_id=licence.license_id) or store.add_pending(
        docs.build_request(
            store.installation(), docs.KIND_DEACTIVATION, engine_version=engine_version(), license_id=licence.license_id
        )
    )
    if transport is None:
        return ActivationResult(
            False,
            "The release request is ready. Send it with `adscan license relay export` through your platform.",
            queued=True,
        )
    answer = transport.send(pending["document"])
    if answer is None:
        return ActivationResult(
            False,
            "ADscan could not reach the licence server, so the seat is still in use. Run the command again "
            "when this machine is online.",
            queued=True,
        )
    result = store.apply_answer(answer, trusted_keys=trusted_keys)
    if result.notice_code == docs.NOTICE_DEACTIVATED:
        store.remove_licence()
        return ActivationResult(True, "This machine's seat was released.", notice_code=result.notice_code)
    return ActivationResult(False, result.message or "The seat could not be released.", notice_code=result.notice_code)


# ── Register export ──────────────────────────────────────────────────────────


def _assessment_line(record: Any) -> dict[str, Any]:
    line = record.to_dict()
    line.setdefault("retest_window_days", None)
    return line


def register_export(store: ProLicenseStore, *, trusted_keys: Mapping[str, str] | None = None) -> dict[str, Any]:
    """The local register for reconciliation (spec § 10). Never carries a domain name.

    Registered entries carry our signed receipt and ``receipt_verified``: that
    part is proof. Pending entries are a declaration. ``assessments`` is one
    usage line per assessment of a code (run kind, run, parent run of a
    recheck, band, date) and ``engagements`` what those lines count as under
    the licence's retest window (``retest_window_days``), by the same rule the
    licence server reconciles with. Versioned output: ``schema_version`` from
    the ``license_register`` output format.
    """
    from adscan_core.engagement.output_formats import SCHEMA_VERSION_KEY, output_marker
    from adscan_core.pro_license.billable_engagements import (
        engagement_summary,
        resolve_retest_window_days,
    )

    licence, _error = store.load_licence(trusted_keys=trusted_keys)
    installation = store.existing_installation()
    entries = []
    for code, entry in sorted(store.register_entries().items()):
        receipt = entry.get("receipt")
        verified = False
        if entry.get("status") == STATUS_REGISTERED and isinstance(receipt, Mapping):
            try:
                payload = docs.verify_server_document(
                    receipt, trusted_keys=trusted_keys, kinds={docs.KIND_REGISTRATION_RECEIPT}
                )
                verified = payload.get("domain_code") == code
            except LicenseError:
                verified = False
        entries.append(
            {
                "domain_code": code,
                "code_basis": entry.get("code_basis"),
                "band": entry.get("band"),
                "first_seen": store.first_seen(code),
                "status": entry.get("status"),
                "registered_at": entry.get("registered_at"),
                "receipt_id": entry.get("receipt_id"),
                "receipt": receipt if verified else None,
                "receipt_verified": verified,
            }
        )
    window = resolve_retest_window_days(licence)
    records = store.assessment_records()
    summary = engagement_summary(records, default_window_days=window)
    export: dict[str, Any] = {
        SCHEMA_VERSION_KEY: output_marker("license_register"),
        "adscan_register": 1,
        "exported_at": docs.format_instant(docs.utc_now()),
        "installation_id": installation.installation_id if installation else None,
        "license_id": licence.license_id if licence else None,
        "edition": licence.edition if licence else None,
        "partner_tag": (licence.partner_tag or None) if licence else None,
        "retest_window_days": window,
        "entries": entries,
        "assessments": [_assessment_line(record) for record in records],
        "engagements": summary["engagements"],
        "unattached_rechecks": summary["unattached_rechecks"],
    }
    if licence is not None and licence.entitlements:
        from adscan_core.environment_ledger import environment_usage

        usage = environment_usage(licence.as_ledger_payload(), directory=store.directory)
        if usage is not None:
            export["usage"] = {
                "mode": usage.mode,
                "quota": usage.quota,
                "used": usage.used,
                "term_start": usage.term_start.isoformat(),
                "term_end": usage.term_end.isoformat(),
            }
    return export


__all__ = [
    "ActivationResult",
    "DEFAULT_SERVER_URL",
    "HttpTransport",
    "ImportSummary",
    "SERVER_URL_ENV",
    "SyncSummary",
    "activate",
    "deactivate",
    "engine_version",
    "export_relay",
    "has_pending_work",
    "import_relay",
    "install_offline_licence",
    "normalize_activation_key",
    "queue_activation",
    "queue_band_report",
    "queue_renewal_if_due",
    "read_relay_batch",
    "register_export",
    "server_url",
    "sync",
    "write_relay_batch",
]
