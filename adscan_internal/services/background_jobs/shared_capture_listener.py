"""Shared :445 NTLM-capture listener broker.

One process-wide owner of the :445 ``NativeListenerCapture`` socket(s), so every
coercion vector (broadcast poisoning, the write-share bait job, the NTLM
auth-type sweep, a single coercion probe) CONSUMES a shared listener instead of
each trying to ``bind()`` :445 independently, which collides with
``[Errno 98] address already in use`` (the prod bug where poisoning held :445 and
the NTLM auth-type sweep was silently dropped from an audit).

**Bind is the broker's decision, advertise is the consumer's.** A consumer hands
the broker the LOCAL address its callback will land on (``bind_ip``, or a
wildcard when it has no single one). That is a statement about where the target
connects, not an instruction for the socket. The broker binds the WILDCARD of
that address family first, which serves every local address at once. On a
multi-NIC appliance (one NIC per client segment) that is what lets a coercion
toward segment A and one toward segment B share one listener: the old broker
bound the first consumer's concrete address and refused every other address, so
a coercion toward the second segment had no listener and the refusal was a debug
line. The relay listeners already bind the wildcard for the same reason
(``esc_relay``, ``relay_rbcd``).

**Contention fallback.** When the wildcard bind is refused with ``EADDRINUSE``
(a local SMB service already holds :445 on one address), the broker binds the
consumer's own concrete address instead, one listener per address, so each
segment still gets served on the address its targets call. A consumer that asked
for the wildcard cannot be served by one address and is refused. Every refusal
is recorded with a classified reason (:meth:`last_refusal`) so the caller can
tell the operator why, instead of the capture vanishing.

**Refcounted.** A listener starts on the first ``acquire`` that needs it and
stops only when the last consumer it serves releases, so stopping one consumer
(``stop_poisoning``) never tears :445 down while another (the write-share bait)
still needs it, in any launch/stop ordering.

**Fan-out.** One poll thread per listener drains its capture queue
(``wait_for_capture`` with no username filter) and dispatches each capture to
EVERY registered sink. Each sink applies its own relevance filter and
de-duplication; the broker itself is capture-agnostic.

The broker NEVER prints user-facing output and NEVER raises into its callers: a
sink that throws is captured to telemetry and the other sinks still run. It lives
on the shell (one broker per session) via :func:`get_or_create_capture_broker`,
mirroring ``get_or_create_registry``. Cross-platform: binding ``0.0.0.0`` is the
same stdlib call on Windows, and the classified errno codes come from
``NativeListenerCapture.describe_start_error``, which reads portable ``errno``
names.
"""
from __future__ import annotations

import ipaddress
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from adscan_core import telemetry
from adscan_core.rich_output import print_exception, print_info_debug

#: A capture sink: called with one ``NtlmCaptureObservation`` per capture. Must
#: not raise (a raising sink is isolated + telemetered); must not block long.
CaptureSink = Callable[[Any], None]

#: Poll granularity for the internal fan-out loop. Short so a stop is prompt and
#: captures are dispatched with low latency; the listener queue does the real
#: blocking wait inside ``wait_for_capture``.
_POLL_TIMEOUT_SECONDS = 2

_IPV4_WILDCARD = "0.0.0.0"  # noqa: S104 - a capture listener serves every segment
_IPV6_WILDCARD = "::"

#: ``describe_start_error`` code for "another socket already holds the port".
_CONTENDED_CODE = "eaddrinuse"


def _normalize(address: object) -> str:
    """Return ``address`` as a canonical IP literal, or ``""`` when not an IP."""
    text = str(address or "").strip()
    if not text:
        return ""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def _wildcard_for(address: str) -> str:
    """Return the wildcard of ``address``'s family."""
    return _IPV6_WILDCARD if ":" in address else _IPV4_WILDCARD


def _is_wildcard(address: str) -> bool:
    return address in (_IPV4_WILDCARD, _IPV6_WILDCARD)


@dataclass
class _Served:
    """One bound listener and the consumers it serves."""

    listener: Any
    poll_thread: Optional[threading.Thread] = None
    stop_event: threading.Event = field(default_factory=threading.Event)
    consumers: set[str] = field(default_factory=set)


class SharedCaptureListenerBroker:
    """Refcounted owner of the :445 capture listener(s) with sink fan-out."""

    def __init__(self, *, port: int = 445) -> None:
        self._lock = threading.RLock()
        self._port = int(port)
        self._served: dict[str, _Served] = {}  # bound address -> listener
        self._consumer_bind: dict[str, str] = {}  # consumer -> bound address
        self._sinks: dict[str, CaptureSink] = {}
        self._refusals: dict[str, tuple[str, str]] = {}

    # ── public API ──────────────────────────────────────────────────────────

    def acquire(self, consumer_id: str, *, bind_ip: str, on_capture: CaptureSink) -> bool:
        """Register ``consumer_id`` against a live listener that serves ``bind_ip``.

        Args:
            consumer_id: Stable id of the consumer (``poisoning@eth1``, ...).
            bind_ip: The LOCAL address this consumer's callback lands on, or a
                wildcard when it has no single one. It is where the target
                connects, never the socket's bind address: the broker binds the
                wildcard whenever it can (see the module docstring).
            on_capture: The consumer's capture sink.

        Returns:
            ``True`` when the consumer is registered against a live listener.
            ``False`` when no listener can serve it; :meth:`last_refusal` then
            holds the classified reason. Idempotent per ``consumer_id``:
            re-acquiring updates the sink in place.
        """
        cid = str(consumer_id or "").strip()
        requested = _normalize(bind_ip)
        if not cid:
            return False
        if not requested:
            with self._lock:
                self._refusals[cid] = (
                    "no_address",
                    f"no valid local callback address was given ({bind_ip!r})",
                )
            return False
        to_stop: Optional[tuple[_Served, str]] = None
        with self._lock:
            address = self._serving_address_locked(requested)
            if address is None:
                address, refusal = self._bind_for_locked(requested)
                if address is None:
                    self._refusals[cid] = refusal
                    print_info_debug(
                        f"capture-broker: consumer {cid} refused for {requested}: "
                        f"{refusal[0]}"
                    )
                    return False

            previous = self._consumer_bind.get(cid)
            if previous is not None and previous != address:
                to_stop = self._detach_locked(cid)
            self._served[address].consumers.add(cid)
            self._consumer_bind[cid] = address
            self._sinks[cid] = on_capture
            self._refusals.pop(cid, None)
            print_info_debug(
                f"capture-broker: consumer {cid} acquired on {address} "
                f"(callback address {requested}, refcount={len(self._sinks)})"
            )
        if to_stop is not None:
            self._shutdown(*to_stop)
        return True

    def release(self, consumer_id: str) -> None:
        """Unregister ``consumer_id``; stop a listener once it serves nobody."""
        cid = str(consumer_id or "").strip()
        with self._lock:
            if cid not in self._sinks:
                return
            self._sinks.pop(cid, None)
            to_stop = self._detach_locked(cid)
            print_info_debug(
                f"capture-broker: consumer {cid} released (refcount={len(self._sinks)})"
            )
        if to_stop is not None:
            self._shutdown(*to_stop)

    def is_active(self) -> bool:
        """True when a listener is bound and at least one consumer holds it."""
        with self._lock:
            return bool(self._served) and bool(self._sinks)

    def consumers(self) -> list[str]:
        with self._lock:
            return sorted(self._sinks.keys())

    def bound_addresses(self) -> list[str]:
        """Every local address a listener is bound to right now, sorted."""
        with self._lock:
            return sorted(self._served.keys())

    def bind_ip(self) -> Optional[str]:
        """The primary bound address (the wildcard when bound), ``None`` when down."""
        with self._lock:
            for wildcard in (_IPV4_WILDCARD, _IPV6_WILDCARD):
                if wildcard in self._served:
                    return wildcard
            return min(self._served) if self._served else None

    def last_refusal(self, consumer_id: str) -> Optional[tuple[str, str]]:
        """``(code, operator_message)`` for the consumer's last refused acquire.

        ``code`` is host-free (``eaddrinuse`` / ``eacces`` / ``eaddrnotavail`` /
        ``other`` / ``no_address``) and safe for telemetry; the message is an
        operator string. ``None`` when the last acquire succeeded or never ran.
        """
        with self._lock:
            return self._refusals.get(str(consumer_id or "").strip())

    def listener_for(self, consumer_id: str) -> Any:
        """The live listener serving ``consumer_id`` (or ``None``), READ-ONLY.

        For consumers that read the listener's append-only ``_observed`` buffer
        (``make_capture_signal`` / ``drain_observations`` / ``connection_stats``),
        which the broker's queue-draining poll loop does NOT consume. **NEVER call
        ``wait_for_capture`` on it**: that drains the shared queue and races the
        fan-out. The caller must hold the listener via ``acquire`` for as long as
        it uses it.
        """
        with self._lock:
            address = self._consumer_bind.get(str(consumer_id or "").strip())
            served = self._served.get(address) if address else None
            return served.listener if served is not None else None

    def active_listener(self) -> Any:
        """The primary live listener (or ``None``); same rules as :meth:`listener_for`.

        Kept for callers that predate per-consumer listeners. Prefer
        :meth:`listener_for`, which is right when the wildcard was contended and
        each segment has its own listener.
        """
        with self._lock:
            address = self.bind_ip()
            return self._served[address].listener if address else None

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "active": bool(self._served),
                "bind_ip": self.bind_ip(),
                "bound_addresses": sorted(self._served.keys()),
                "consumers": sorted(self._sinks.keys()),
            }

    # ── internals ───────────────────────────────────────────────────────────

    def _serving_address_locked(self, requested: str) -> Optional[str]:
        """Return the bound address that already serves ``requested``, if any."""
        wildcard = _wildcard_for(requested)
        if wildcard in self._served:
            return wildcard
        if requested in self._served:
            return requested
        return None

    def _bind_for_locked(self, requested: str) -> tuple[Optional[str], tuple[str, str]]:
        """Bind a listener that serves ``requested``: wildcard first, then itself."""
        wildcard = _wildcard_for(requested)
        ok, refusal = self._start_locked(wildcard)
        if ok:
            return wildcard, ("none", "")
        if refusal[0] != _CONTENDED_CODE or _is_wildcard(requested):
            return None, refusal
        print_info_debug(
            f"capture-broker: {wildcard}:{self._port} is held by another local "
            f"service; binding the callback address {requested} only"
        )
        ok, concrete_refusal = self._start_locked(requested)
        if ok:
            return requested, ("none", "")
        return None, concrete_refusal

    def _start_locked(self, address: str) -> tuple[bool, tuple[str, str]]:
        listener = self._make_listener(address)
        if listener is None:
            return False, ("other", "the capture listener could not be constructed")
        if not self._start_listener(listener):
            return False, self._describe_failure(listener, address)
        served = _Served(listener=listener)
        self._served[address] = served
        served.poll_thread = threading.Thread(
            target=self._poll,
            args=(served,),
            name=f"shared-capture-broker-{address}",
            daemon=True,
        )
        served.poll_thread.start()
        print_info_debug(f"capture-broker: shared :{self._port} listener started on {address}")
        return True, ("none", "")

    def _describe_failure(self, listener: Any, address: str) -> tuple[str, str]:
        describe = getattr(listener, "describe_start_error", None)
        if callable(describe):
            try:
                code, message = describe()
                if code and code != "none":
                    return str(code), str(message)
            except Exception as exc:  # noqa: BLE001 - observability only
                telemetry.capture_exception(exc)
        return "other", f"the capture listener did not start on {address}:{self._port}"

    def _detach_locked(self, cid: str) -> Optional[tuple[_Served, str]]:
        """Detach ``cid``; return the listener to stop when it served nobody else.

        The caller stops it AFTER releasing the lock, so the join on the poll
        thread (which takes the lock to snapshot sinks) cannot stall.
        """
        address = self._consumer_bind.pop(cid, None)
        served = self._served.get(address) if address else None
        if served is None or address is None:
            return None
        served.consumers.discard(cid)
        if served.consumers:
            return None
        self._served.pop(address, None)
        return served, address

    def _make_listener(self, bind_ip: str) -> Any:
        try:
            from adscan_internal.services.ntlm_capture_workflow import (  # noqa: PLC0415
                NativeListenerCapture,
            )

            return NativeListenerCapture(listen_host=bind_ip, listen_port=self._port)
        except Exception as exc:  # noqa: BLE001 — bind/import failure must not raise out
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(f"capture-broker: could not construct listener: {exc}")
            return None

    @staticmethod
    def _start_listener(listener: Any) -> bool:
        try:
            return bool(listener.start())
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(f"capture-broker: listener.start() failed: {exc}")
            return False

    def _poll(self, served: _Served) -> None:
        """Drain one listener's queue and fan every capture out to all sinks."""
        listener = served.listener
        while not served.stop_event.is_set():
            try:
                obs = listener.wait_for_capture(
                    timeout_seconds=_POLL_TIMEOUT_SECONDS, expected_usernames=None
                )
            except Exception as exc:  # noqa: BLE001 — never let a poll error kill fan-out
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                served.stop_event.wait(0.5)
                continue
            if obs is None:
                continue
            # Snapshot sinks under the lock so acquire/release during dispatch is safe.
            with self._lock:
                sinks = list(self._sinks.values())
            for sink in sinks:
                try:
                    sink(obs)
                except Exception as exc:  # noqa: BLE001 — isolate one bad sink
                    telemetry.capture_exception(exc)
                    print_exception(exception=exc)

    def _shutdown(self, served: _Served, address: Optional[str]) -> None:
        """Stop one listener and its poll thread."""
        served.stop_event.set()
        # The poll thread only takes the lock briefly to snapshot sinks, and the
        # stop event ends it, so stopping the listener first cannot deadlock.
        try:
            served.listener.stop()
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
        thread = served.poll_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=8.0)
        print_info_debug(f"capture-broker: shared :{self._port} listener on {address} stopped")


def get_or_create_capture_broker(shell: Any) -> SharedCaptureListenerBroker:
    """Return the session's shared capture-listener broker (one per shell).

    Mirrors ``get_or_create_registry`` — stored on ``shell._capture_broker`` so
    every coercion vector in the session shares one :445 owner. Falls back to a
    module-level broker when the shell cannot hold the attribute (never raises).
    """
    try:
        broker = getattr(shell, "_capture_broker", None)
        if isinstance(broker, SharedCaptureListenerBroker):
            return broker
        broker = SharedCaptureListenerBroker()
        setattr(shell, "_capture_broker", broker)
        return broker
    except Exception:  # noqa: BLE001 — a shell that rejects the attr still gets a broker
        return _module_fallback_broker()


_FALLBACK_BROKER: Optional[SharedCaptureListenerBroker] = None
_FALLBACK_LOCK = threading.Lock()


def _module_fallback_broker() -> SharedCaptureListenerBroker:
    global _FALLBACK_BROKER  # noqa: PLW0603
    with _FALLBACK_LOCK:
        if _FALLBACK_BROKER is None:
            _FALLBACK_BROKER = SharedCaptureListenerBroker()
        return _FALLBACK_BROKER
