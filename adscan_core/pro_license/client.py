"""Talking to the licence server: direct HTTPS, or a relay file through a partner platform.

Besides queued work (an activation, a registration, a band report, an
engagement report, a deactivation), every online launch makes one CHECK-IN
(:func:`check_in`): a signed renewal request that carries only what a renewal
always carried (installation id and public key, the licence id, which names
the grant, a request id, a sequence number, the creation time and the engine
version) and never any scan data. The answer is a fresh licence document when
the grant changed or the document reached its renewal date, a revocation
notice when ADscan revoked the grant, or "current" otherwise. A check-in that
reaches the server also sends every queued registration and report
(:func:`flush_pending`), inside the same budget. Whether the channel may
connect at all is :func:`adscan_core.pro_license.channel.licence_channel_allowed`:
every online licence connects even under offline mode
(``ADSCAN_OFFLINE`` / ``ADSCAN_NO_EXTERNAL``); an offline engagement licence never does. Direct mode posts each queued request; relay mode writes them
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
import time as _time
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
from adscan_core.pro_license.state import CHECK_IN_UNREACHABLE_RESULT, ProLicenseStore

SERVER_URL_ENV = "ADSCAN_LICENSE_SERVER_URL"
#: A proxy for the licence channel only (``http://[user:pass@]host:port``). The
#: scan container does not inherit the host's ``HTTPS_PROXY`` (that would route
#: other HTTP clients, WinRM included, through it); this ``ADSCAN_*`` variable is
#: forwarded into it, and ``adscan license check`` suggests it when the host
#: reaches ADscan only through a proxy.
LICENCE_PROXY_ENV = "ADSCAN_LICENSE_PROXY"


def licence_proxy() -> str:
    """The licence-channel proxy URL, or ``""``."""
    return os.getenv(LICENCE_PROXY_ENV, "").strip()


def tls_context():
    """The TLS context every licence-server connection uses (certifi's roots when available)."""
    import ssl

    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def open_url(request: urllib.request.Request, *, timeout: float):
    """Open a licence-server URL: the licence proxy when set, else urllib's environment proxies."""
    context = tls_context() if request.full_url.startswith("https") else None
    handlers: list[Any] = [urllib.request.HTTPSHandler(context=context)] if context is not None else []
    proxy = licence_proxy()
    if proxy:
        handlers.insert(0, urllib.request.ProxyHandler({"https": proxy, "http": proxy}))
    return urllib.request.build_opener(*handlers).open(request, timeout=timeout)
#: Placeholder until the production hostname is decided (spec open question Q7).
#: An API endpoint, not a marketing link, so it is composed from the site host
#: rather than a CTA placement (no UTM parameters on an API call).
DEFAULT_SERVER_URL = f"https://license.{ADSCAN_SITE_HOST}"
DEFAULT_TIMEOUT_SECONDS = 5.0
#: Network budget of the launch check-in: an unreachable server costs a launch
#: at most this long (the caller also bounds the wait on its side).
CHECK_IN_TIMEOUT_SECONDS = 2.0
RELAY_FORMAT = 1

#: Outcome of a check-in, persisted for ``adscan license status``.
CHECK_IN_CURRENT = "current"
CHECK_IN_REFRESHED = "refreshed"
CHECK_IN_REVOKED = "revoked"
CHECK_IN_NOTICE = "notice"
CHECK_IN_UNREACHABLE = CHECK_IN_UNREACHABLE_RESULT
CHECK_IN_REJECTED = "rejected"
CHECK_IN_SKIPPED = "skipped"

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
            with open_url(request, timeout=self.timeout) as response:
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
            store.withdraw_pending(str(item["request_id"]))
    document = store.build_request(
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
        store.build_request(
            docs.KIND_RENEWAL, engine_version=engine_version(), license_id=licence.license_id
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
    _withdraw_band_reports(store, domain_code, run_id=None)
    store.add_pending(
        store.build_request(
            docs.KIND_BAND_REPORT,
            engine_version=engine_version(),
            license_id=licence.license_id,
            domain_code=domain_code,
            band=band,
        )
    )
    return True


def _withdraw_band_reports(store: ProLicenseStore, domain_code: str, *, run_id: str | None) -> None:
    """Withdraw the queued band reports a new one replaces.

    A plain band report (no run) replaces only the plain ones: a run's size
    report is that run's record and stays queued until it is delivered. A
    run's size report replaces the plain ones and its own run's earlier one.
    """
    for item in store.pending():
        payload = item.get("document", {}).get("payload", {})
        if item.get("kind") != docs.KIND_BAND_REPORT or payload.get("domain_code") != domain_code:
            continue
        queued_run = payload.get("run_id")
        if queued_run is None or (run_id is not None and queued_run == run_id):
            store.withdraw_pending(str(item["request_id"]))


def queue_run_size_report(
    store: ProLicenseStore,
    licence: ProLicense,
    *,
    domain_code: str,
    run_id: str,
    band: str | None,
    run_status: str | None,
    domain_sizes: Any,
) -> bool:
    """Queue the size report of one run of one code (partner licences only).

    It travels as a band report (``/v1/band``) carrying the band, the run id,
    the run status and the counts of each domain of the code the run assessed
    (:mod:`adscan_core.pro_license.run_size`): counts only, never a name. A
    licence server that predates the counts records the band and ignores the
    rest. Any other edition keeps its counts in the local register and this
    queues nothing. Needs a counted band (never ``pending``), because the
    server updates the code's band from the same report. Returns True when
    queued.
    """
    from adscan_core.pro_license.run_size import normalize_domain_sizes, normalize_run_status

    if not licence.reports_run_sizes or not run_id:
        return False
    if not band or band == "pending":
        return False
    sizes = normalize_domain_sizes(domain_sizes)
    if not sizes:
        return False
    if store.register_entries().get(domain_code) is None:
        return False
    store.upsert_entry(domain_code, band=band)
    _withdraw_band_reports(store, domain_code, run_id=run_id)
    store.add_pending(
        store.build_request(
            docs.KIND_BAND_REPORT,
            engine_version=engine_version(),
            license_id=licence.license_id,
            domain_code=domain_code,
            band=band,
            run_id=run_id,
            run_status=normalize_run_status(run_status),
            domain_sizes=sizes,
        )
    )
    return True


def requeue_clock_refused_registrations(store: ProLicenseStore, licence: ProLicense | None) -> int:
    """Queue a fresh registration for every code the server refused only for its date.

    A registration signed while ADscan held the host clock at a domain
    controller's time more than a day ahead is refused as ``stale_request``.
    That says nothing about the domain, so once the clock is right again the
    code goes back to waiting with a new request. Returns how many were queued.
    """
    from adscan_core.pro_license.state import STATUS_PENDING, STATUS_REFUSED

    if licence is None or not licence.needs_server:
        return 0
    queued = 0
    for code, entry in store.register_entries().items():
        if entry.get("status") != STATUS_REFUSED or entry.get("refusal") != docs.NOTICE_STALE:
            continue
        store.upsert_entry(code, status=STATUS_PENDING, refusal=None)
        if store.pending_of_kind(docs.KIND_REGISTRATION, domain_code=code) is None:
            store.add_pending(
                store.build_request(
                    docs.KIND_REGISTRATION,
                    engine_version=engine_version(),
                    license_id=licence.license_id,
                    domain_code=code,
                    code_basis=entry.get("code_basis") or "name",
                    band=entry.get("band") or "pending",
                )
            )
        queued += 1
    return queued


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


#: Queued kinds a successful contact sends on its own. Activation and
#: deactivation stay explicit operator actions (``adscan license``).
FLUSH_KINDS: frozenset[str] = frozenset(
    {docs.KIND_REGISTRATION, docs.KIND_BAND_REPORT, docs.KIND_ENGAGEMENT_REPORT}
)
#: Kinds the server accepts only for a code it already registered. Sent before
#: the registration lands, the server answers "not registered" and the report
#: would be dropped, so it stays queued until its code is registered.
_NEEDS_REGISTERED_CODE: frozenset[str] = frozenset({docs.KIND_BAND_REPORT, docs.KIND_ENGAGEMENT_REPORT})
#: A send is not started with less budget than this left (seconds).
_MIN_SEND_SECONDS = 0.2


def flush_pending(
    store: ProLicenseStore,
    transport: HttpTransport,
    *,
    deadline: float | None = None,
    trusted_keys: Mapping[str, str] | None = None,
) -> SyncSummary:
    """Send queued registrations and reports after a contact reached the server.

    Order is :func:`_ordered_pending` (registrations first, so a report follows
    its code). A band or engagement report waits until its code is registered.
    ``deadline`` is a :func:`time.monotonic` instant: no send starts after it,
    and each send's socket timeout is capped to the time left, so the whole
    flush stays inside the caller's budget. Stops at the first unreachable
    attempt; whatever is not sent stays queued. Never raises.
    """
    summary = SyncSummary()
    original_timeout = getattr(transport, "timeout", None)
    try:
        for item in _ordered_pending(store):
            kind = str(item.get("kind"))
            if kind not in FLUSH_KINDS:
                continue
            if kind in _NEEDS_REGISTERED_CODE:
                code = item.get("document", {}).get("payload", {}).get("domain_code")
                if not store.is_registered(str(code or ""), trusted_keys=trusted_keys):
                    continue
            if deadline is not None:
                remaining = deadline - _time.monotonic()
                if remaining < _MIN_SEND_SECONDS:
                    break
                if isinstance(original_timeout, (int, float)):
                    transport.timeout = min(float(original_timeout), remaining)
            answer = transport.send(item["document"])
            summary.sent += 1
            if answer is None:
                summary.unreachable = True
                summary.error = getattr(transport, "last_error", "")
                break
            result = store.apply_answer(answer, trusted_keys=trusted_keys)
            if result.applied:
                summary.applied += 1
                if result.notice_code:
                    summary.notices.append((result.notice_code, result.message))
                    if result.notice_code in docs.TERMINAL_NOTICES:
                        break
            else:
                summary.rejected.append((str(item["request_id"]), result.reason))
    except Exception as exc:  # noqa: BLE001 - a flush never breaks its caller; the work stays queued
        summary.error = str(exc) or exc.__class__.__name__
    finally:
        if original_timeout is not None:
            try:
                transport.timeout = original_timeout
            except Exception:  # noqa: BLE001
                pass
    return summary


def channel_transport(
    licence: ProLicense | None, *, timeout: float = DEFAULT_TIMEOUT_SECONDS
) -> HttpTransport | None:
    """A direct transport when the licence channel may connect (:mod:`.channel`), else None."""
    from adscan_core.pro_license.channel import licence_channel_allowed

    if not licence_channel_allowed(licence):
        return None
    try:
        return HttpTransport(timeout=timeout)
    except ValueError:
        return None


def has_pending_work(store: ProLicenseStore, *, now: datetime | None = None, trusted_keys=None) -> bool:
    """True when a connection would achieve something (queued request or due renewal)."""
    if store.pending():
        return True
    licence, _error = store.load_licence(trusted_keys=trusted_keys)
    if licence is None or licence.renew_after is None:
        return False
    return (now or docs.utc_now()) >= datetime.combine(licence.renew_after, time.min, tzinfo=timezone.utc)


# ── Launch check-in ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class CheckInResult:
    """What one check-in achieved."""

    outcome: str
    message: str = ""
    notice_code: str = ""
    #: An unexpected failure, for the caller to report on its own thread
    #: (a check-in may run on a worker thread, which must not print).
    error: BaseException | None = None
    #: Queued registrations and reports this check-in also delivered.
    flushed: int = 0


def check_in(
    store: ProLicenseStore,
    transport: HttpTransport,
    *,
    force: bool = False,
    trusted_keys: Mapping[str, str] | None = None,
    deadline: float | None = None,
) -> CheckInResult:
    """Tell the licence server this installation is starting, and apply its answer.

    A fresh request every time (an older unanswered renewal is dropped), so a
    revocation that happened after the last answer is never hidden behind a
    replayed one. ``force`` asks for a new document even when nothing changed
    (``adscan license renew``). When the server answered (and did not revoke),
    every queued registration and report is sent too (:func:`flush_pending`),
    no send starting after ``deadline`` (a :func:`time.monotonic` instant).
    Never raises. The outcome is recorded in the licence directory for
    ``adscan license status``.
    """
    try:
        licence, _error = store.load_licence(trusted_keys=trusted_keys)
        if licence is None or not licence.needs_server:
            return CheckInResult(CHECK_IN_SKIPPED)
        for item in store.pending():
            if item.get("kind") == docs.KIND_RENEWAL:
                store.withdraw_pending(str(item["request_id"]))
        pending = store.add_pending(
            store.build_request(
                docs.KIND_RENEWAL,
                engine_version=engine_version(),
                license_id=licence.license_id,
                refresh="force" if force else None,
            )
        )
        answer = transport.send(pending["document"])
        if answer is None:
            result = CheckInResult(CHECK_IN_UNREACHABLE, transport.last_error)
        else:
            applied = store.apply_answer(answer, trusted_keys=trusted_keys)
            if not applied.applied:
                result = CheckInResult(CHECK_IN_REJECTED, applied.message or applied.reason)
            elif applied.kind == docs.KIND_LICENCE:
                _save_sidecar_credential(store, answer)
                result = CheckInResult(CHECK_IN_REFRESHED, applied.message)
            elif applied.notice_code == docs.NOTICE_LICENCE_CURRENT:
                result = CheckInResult(CHECK_IN_CURRENT)
            elif applied.notice_code in docs.TERMINAL_NOTICES:
                result = CheckInResult(CHECK_IN_REVOKED, applied.message, applied.notice_code)
            else:
                result = CheckInResult(CHECK_IN_NOTICE, applied.message, applied.notice_code)
        store.record_check_in(result.outcome, error=result.message if result.outcome == CHECK_IN_UNREACHABLE else "")
        if result.outcome in (CHECK_IN_CURRENT, CHECK_IN_REFRESHED, CHECK_IN_NOTICE):
            flushed = flush_pending(store, transport, deadline=deadline, trusted_keys=trusted_keys)
            if flushed.applied:
                from dataclasses import replace

                result = replace(result, flushed=flushed.applied)
        return result
    except Exception as exc:  # noqa: BLE001 - a check-in never breaks a launch; the caller reports it
        return CheckInResult(CHECK_IN_REJECTED, str(exc), error=exc)


def launch_check_in(
    store: ProLicenseStore,
    *,
    timeout: float = CHECK_IN_TIMEOUT_SECONDS,
    transport: HttpTransport | None = None,
    trusted_keys: Mapping[str, str] | None = None,
) -> CheckInResult | None:
    """The check-in a launch makes, bounded so a scan never waits on the network.

    Returns None (nothing sent) when the licence channel may not connect
    (:func:`adscan_core.pro_license.channel.licence_channel_allowed`: no online
    licence, an offline engagement licence, an Enterprise process). An online
    licence checks in even under offline mode; the first such contact of
    the run prints one line saying so. Runs :func:`check_in` on a daemon thread
    and waits at most ``timeout`` seconds: an answer inside the budget is
    applied before the launch decides (a revocation refuses THIS launch); a
    slower one is applied whenever it lands, and the launch proceeds on the
    document it holds. Queued registrations ride the same budget. DNS
    resolution is covered by the wait, not only the socket timeout.
    """
    import threading

    from adscan_core.pro_license.channel import licence_channel_allowed, note_offline_contact

    licence, _error = store.load_licence(trusted_keys=trusted_keys)
    if not licence_channel_allowed(licence):
        return None
    try:
        sender = transport or HttpTransport(timeout=timeout)
    except ValueError as exc:
        return CheckInResult(CHECK_IN_REJECTED, str(exc))
    note_offline_contact(licence)
    deadline = _time.monotonic() + timeout
    box: list[CheckInResult] = []

    def _run() -> None:
        box.append(check_in(store, sender, trusted_keys=trusted_keys, deadline=deadline))

    worker = threading.Thread(target=_run, name="adscan-licence-check-in", daemon=True)
    worker.start()
    worker.join(timeout + 0.5)
    if box:
        return box[0]
    result = CheckInResult(CHECK_IN_UNREACHABLE, "no answer within the launch budget")
    try:
        # The worker may still land an answer later, which records itself.
        store.record_check_in(result.outcome, error=result.message)
    except Exception:  # noqa: BLE001 - bookkeeping never breaks a launch
        pass
    return result


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


def owed_work(
    store: ProLicenseStore, *, trusted_keys: Mapping[str, str] | None = None
) -> dict[str, int]:
    """What this machine has queued that ADscan must still receive: ``{"registrations", "reports"}``.

    Every queued registration, and every band or engagement report whose code
    is registered (one that still waits for its registration is counted with
    that registration).
    """
    registrations = reports = 0
    for item in store.pending():
        kind = str(item.get("kind"))
        if kind == docs.KIND_REGISTRATION:
            registrations += 1
        elif kind in _NEEDS_REGISTERED_CODE:
            code = str(item.get("document", {}).get("payload", {}).get("domain_code") or "")
            if store.is_registered(code, trusted_keys=trusted_keys):
                reports += 1
    return {"registrations": registrations, "reports": reports}


def _owed_phrase(owed: Mapping[str, int]) -> str:
    """``"2 domain registrations and 1 usage report"``, or ``""`` when nothing is owed."""
    parts = []
    for count, noun in ((owed.get("registrations", 0), "domain registration"), (owed.get("reports", 0), "usage report")):
        if count:
            parts.append(f"{count} {noun}{'s' if count != 1 else ''}")
    return " and ".join(parts)


def deactivate(
    store: ProLicenseStore,
    *,
    transport: HttpTransport | None,
    trusted_keys: Mapping[str, str] | None = None,
) -> ActivationResult:
    """Send what this machine still owes, release its seat, then remove the local licence.

    The server answers a released installation with "seat released", so a
    registration or report still queued at that point could never be
    delivered. The queue therefore goes first (:func:`flush_pending`), and the
    seat is released only when nothing is owed any more (:func:`owed_work`).
    Otherwise the command refuses, keeps every queued request and says what is
    owed. In relay mode (``transport=None``) the batch carries the queue ahead
    of the release request (:func:`_ordered_pending`).
    """
    licence, _error = store.load_licence(trusted_keys=trusted_keys)
    if licence is None:
        return ActivationResult(False, "No PRO licence is active on this machine.")

    def _release_request() -> dict[str, Any]:
        return store.pending_of_kind(docs.KIND_DEACTIVATION, license_id=licence.license_id) or store.add_pending(
            store.build_request(
                docs.KIND_DEACTIVATION, engine_version=engine_version(), license_id=licence.license_id
            )
        )

    if transport is None:
        owed = _owed_phrase(owed_work(store, trusted_keys=trusted_keys))
        _release_request()
        return ActivationResult(
            False,
            "The release request is ready"
            + (f", together with {owed} this machine still owes, which go first" if owed else "")
            + ". Send it with `adscan license relay export` through your platform.",
            queued=True,
        )
    flushed = flush_pending(store, transport, trusted_keys=trusted_keys)
    terminal = next((message for code, message in flushed.notices if code in docs.TERMINAL_NOTICES), None)
    if terminal is not None:
        return ActivationResult(False, terminal or "The seat could not be released.")
    owed = _owed_phrase(owed_work(store, trusted_keys=trusted_keys))
    if owed:
        why = (
            "ADscan could not reach the licence server"
            + (f" ({flushed.error})" if flushed.error else "")
            if flushed.unreachable
            else "The licence server did not accept everything this machine sent"
        )
        return ActivationResult(
            False,
            f"{why}, so the seat is still in use: {owed} queued on this machine must reach ADscan before "
            "the seat is released. Nothing was dropped. Run the command again when this machine is online, "
            "or send everything through your platform with `adscan license deactivate --relay-out FILE`.",
            queued=True,
        )
    pending = _release_request()
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
        # The same check admission makes: signed by us, for this code and this installation.
        verified = store.is_registered(code, trusted_keys=trusted_keys)
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
    "CHECK_IN_CURRENT",
    "CHECK_IN_NOTICE",
    "CHECK_IN_REFRESHED",
    "CHECK_IN_REJECTED",
    "CHECK_IN_REVOKED",
    "CHECK_IN_SKIPPED",
    "CHECK_IN_TIMEOUT_SECONDS",
    "CHECK_IN_UNREACHABLE",
    "ActivationResult",
    "CheckInResult",
    "channel_transport",
    "check_in",
    "flush_pending",
    "launch_check_in",
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
    "queue_run_size_report",
    "queue_renewal_if_due",
    "read_relay_batch",
    "requeue_clock_refused_registrations",
    "register_export",
    "server_url",
    "sync",
    "write_relay_batch",
]
