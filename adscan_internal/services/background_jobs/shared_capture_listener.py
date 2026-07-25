"""Shared :445 NTLM-capture listener broker.

One process-wide owner of a SINGLE ``NativeListenerCapture`` per bind IP, so
every coercion vector — broadcast poisoning, the write-share bait job, and the
NTLM auth-type sweep — CONSUMES one listener instead of each trying to ``bind()``
:445 independently (which collides: ``[Errno 98] address already in use`` — the
exact prod bug where poisoning held :445 and the NTLM auth-type sweep was
silently dropped from an audit).

**Refcounted.** The listener starts on the FIRST ``acquire`` and stops only on
the LAST ``release`` — so stopping one consumer (e.g. ``stop_poisoning``) never
tears :445 down while another consumer (e.g. the write-share bait) still needs
it, in ANY launch/stop ordering.

**Fan-out.** A single internal poll thread drains the listener's capture queue
(``wait_for_capture`` with NO username filter — every raw observation) and
dispatches each capture to EVERY registered sink. Each consumer's sink applies
its own relevance filter and de-duplication; the broker itself is
capture-agnostic (it does not know or care which coercion produced the auth —
the victim just connected to :445).

The broker NEVER prints and NEVER raises into its callers — a sink that throws is
captured to telemetry and the other sinks still run. It lives on the shell
(one broker per session) via :func:`get_or_create_capture_broker`, mirroring
``get_or_create_registry``.
"""
from __future__ import annotations

import threading
from typing import Any, Callable, Optional

from adscan_core import telemetry
from adscan_core.rich_output import print_info_debug
from adscan_core.rich_output import print_exception

#: A capture sink: called with one ``NtlmCaptureObservation`` per capture. Must
#: not raise (a raising sink is isolated + telemetered); must not block long.
CaptureSink = Callable[[Any], None]

#: Poll granularity for the internal fan-out loop. Short so a stop is prompt and
#: captures are dispatched with low latency; the listener queue does the real
#: blocking wait inside ``wait_for_capture``.
_POLL_TIMEOUT_SECONDS = 2


class SharedCaptureListenerBroker:
    """Refcounted owner of one :445 ``NativeListenerCapture`` with sink fan-out."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._listener: Any = None
        self._bind_ip: Optional[str] = None
        self._sinks: dict[str, CaptureSink] = {}
        self._poll_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    # ── public API ──────────────────────────────────────────────────────────

    def acquire(self, consumer_id: str, *, bind_ip: str, on_capture: CaptureSink) -> bool:
        """Register ``consumer_id``; start the shared listener if it is the first.

        Returns ``True`` when the consumer is registered against a live listener.
        Returns ``False`` (registering nothing) when the listener cannot bind, or
        when a DIFFERENT ``bind_ip`` is requested than the one already serving
        (only one :445 per host — the caller should reuse the active bind IP).
        Idempotent per ``consumer_id``: re-acquiring updates the sink in place.
        """
        cid = str(consumer_id or "").strip()
        ip = str(bind_ip or "").strip()
        if not cid or not ip:
            return False
        with self._lock:
            if self._listener is not None and self._bind_ip and ip != self._bind_ip:
                print_info_debug(
                    f"capture-broker: consumer {cid} asked for bind {ip} but the "
                    f"shared listener is already on {self._bind_ip}; refusing (one "
                    ":445 per host)."
                )
                return False

            if self._listener is None:
                listener = self._make_listener(ip)
                if listener is None or not self._start_listener(listener):
                    return False
                self._listener = listener
                self._bind_ip = ip
                self._stop_event.clear()
                self._start_poll_thread()
                print_info_debug(f"capture-broker: shared :445 listener started on {ip}")

            self._sinks[cid] = on_capture
            print_info_debug(
                f"capture-broker: consumer {cid} acquired (refcount={len(self._sinks)})"
            )
            return True

    def release(self, consumer_id: str) -> None:
        """Unregister ``consumer_id``; stop the listener when it was the last one."""
        cid = str(consumer_id or "").strip()
        with self._lock:
            if cid not in self._sinks:
                return
            self._sinks.pop(cid, None)
            print_info_debug(
                f"capture-broker: consumer {cid} released (refcount={len(self._sinks)})"
            )
            if self._sinks:
                return  # others still need :445 — keep it up (the ordering guarantee)
            self._shutdown_listener_locked()

    def is_active(self) -> bool:
        """True when the shared listener is bound and at least one consumer holds it."""
        with self._lock:
            return self._listener is not None and bool(self._sinks)

    def consumers(self) -> list[str]:
        with self._lock:
            return sorted(self._sinks.keys())

    def bind_ip(self) -> Optional[str]:
        """The IP the shared listener is currently bound to (None when down)."""
        with self._lock:
            return self._bind_ip

    def active_listener(self) -> Any:
        """The live ``NativeListenerCapture`` (or None) for READ-ONLY use.

        For consumers that read the listener's append-only ``_observed`` buffer —
        ``make_capture_signal`` / ``observed`` / ``connection_stats`` — which are
        NOT consumed by the broker's queue-draining poll loop, so they are safe to
        call alongside it. **NEVER call ``wait_for_capture`` on the returned
        listener** — that drains the shared queue and races the broker's fan-out.
        The caller MUST still hold the listener via ``acquire`` (refcount) for its
        lifetime; this only exposes the object for the read-side operations the
        broker's sink API cannot express.
        """
        with self._lock:
            return self._listener

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "active": self._listener is not None,
                "bind_ip": self._bind_ip,
                "consumers": sorted(self._sinks.keys()),
            }

    # ── internals ───────────────────────────────────────────────────────────

    def _make_listener(self, bind_ip: str) -> Any:
        try:
            from adscan_internal.services.ntlm_capture_workflow import (  # noqa: PLC0415
                NativeListenerCapture,
            )

            return NativeListenerCapture(listen_host=bind_ip)
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

    def _start_poll_thread(self) -> None:
        self._poll_thread = threading.Thread(
            target=self._poll, name="shared-capture-broker", daemon=True
        )
        self._poll_thread.start()

    def _poll(self) -> None:
        """Drain the listener queue and fan every capture out to all sinks."""
        listener = self._listener
        if listener is None:
            return
        while not self._stop_event.is_set():
            try:
                obs = listener.wait_for_capture(
                    timeout_seconds=_POLL_TIMEOUT_SECONDS, expected_usernames=None
                )
            except Exception as exc:  # noqa: BLE001 — never let a poll error kill fan-out
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                self._stop_event.wait(0.5)
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

    def _shutdown_listener_locked(self) -> None:
        """Stop the poll thread + listener. Caller holds ``self._lock``."""
        self._stop_event.set()
        listener = self._listener
        self._listener = None
        self._bind_ip = None
        thread = self._poll_thread
        self._poll_thread = None
        # Stop the listener OUTSIDE the join so a slow listener.stop() does not
        # deadlock with the poll thread trying to take the lock. The poll thread
        # only reads the lock briefly to snapshot sinks; stop_event ends it.
        if listener is not None:
            try:
                listener.stop()
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=8.0)
        print_info_debug("capture-broker: shared :445 listener stopped (refcount=0)")


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
