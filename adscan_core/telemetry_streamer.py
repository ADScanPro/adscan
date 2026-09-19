"""Tier 2 — live chunked streaming of the Rich console recording.

ADscan's CLI captures every Rich-rendered byte into the dedicated
``TELEMETRY_CONSOLE`` (in-memory). Tier 1 ships that recording as a
single HTML blob at the end of the session. Tier 2 streams it in
chunks while the session is still running, so the operator sees the
scan unfold in real time on ``sessions.adscanpro.com`` and the
notification matrix can trigger on **lifecycle events** (scan started,
scan finished, session ended) instead of waiting for the CLI to close.

Design constraints kept in mind:

* **Best-effort, never blocking** — the streamer runs on a daemon
  thread. If a chunk upload fails, the chunk lands in the disk queue
  (Tier 1 reuses ``telemetry_queue``) and a future drain retries.
  Telemetry must never delay the foreground CLI.
* **Diff-based** — each chunk is the *new* HTML since the previous
  chunk, not the full export. The server reassembles by concatenation
  ordered by ``seq``. Cheap on bandwidth, cheap on server CPU
  (no rewriting the whole row per chunk).
* **Cadence triggers** — three independent triggers fire a chunk
  flush:
    1. Timer (``CHUNK_INTERVAL_SECONDS``, default 30 s).
    2. Size (``CHUNK_SIZE_BYTES``, default 32 KiB of new content).
    3. Lifecycle event — flushed immediately so the server can act on
       ``scan_started`` / ``scan_finished`` without latency.
* **Scope-gated** — only enabled for command_type ∈ {start, ci, tui}
  via :func:`should_stream_for_command`. Other commands continue
  using the Tier 1 single-shot path.
* **Auto-fallback when nothing was sent** — if the session ends
  before the first chunk leaves the loom (very short sessions), the
  Tier 1 single-shot path runs as before and the streamer is a no-op.

Threading model:

* One ``threading.Thread(daemon=True)`` per streamer instance.
* The Rich console export is **not** thread-safe; the streamer grabs
  a short lock while calling ``console.export_html()``.
* The CLI main thread emits lifecycle events via
  :meth:`SessionStreamer.emit_lifecycle` — that method just sets a
  pending lifecycle marker and signals the loop, which then performs
  the actual upload from the streamer thread. No blocking on the
  network from the CLI thread.

All telemetry knobs are honoured: ``ADSCAN_TELEMETRY=0`` and
``ADSCAN_SESSION_CAPTURE=0`` disable the streamer entirely.
"""

from __future__ import annotations

import base64
import gzip
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional

# Triggers — chosen to keep wire chatter low for slow sessions
# (~10-12h pentests) while still feeling "live" for the operator.
# 30s timer + 32 KiB size = roughly 30-50 chunks for a typical run.
CHUNK_INTERVAL_SECONDS: float = 30.0
CHUNK_SIZE_BYTES: int = 32 * 1024
# Hard ceiling on a single chunk's decompressed bytes. The server's
# ``MAX_DECOMPRESSED_BYTES`` is 10 MiB; we cap each chunk at 1 MiB so
# even a sudden burst (huge attack-path panel) fits comfortably.
MAX_CHUNK_DECOMPRESSED_BYTES: int = 1 * 1024 * 1024

# Commands whose Rich recordings benefit from live streaming. Other
# commands (install / check / update / upgrade) finish in seconds to
# minutes and ship the recording in one shot via the legacy path.
_STREAM_COMMANDS: frozenset[str] = frozenset({"start", "ci", "tui"})


def should_stream_for_command(command_type: Optional[str]) -> bool:
    """Return True iff Tier 2 streaming should run for ``command_type``."""
    if not command_type:
        return False
    return command_type.strip().lower() in _STREAM_COMMANDS


@dataclass
class LifecycleEvent:
    """One lifecycle marker pending emission as the next chunk.

    ``event`` is one of the strings accepted by the server's
    ``isLifecycleEvent`` validator. ``metadata`` is a free-form JSON
    dict; per-event conventions documented in ingest_pipeline on the
    server side.
    """

    event: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class StreamerConfig:
    """All state the streamer needs at construction time."""

    trace_id: str
    user_id_hash: str
    command_type: str
    session_scope: str
    # Privacy: the raw workspace name is customer-sensitive and never
    # leaves the host. The only identity that travels is
    # ``workspace_id_hash`` (set on each chunk via
    # ``version_payload_fn``). No field for the raw name on purpose —
    # if it existed, future call-sites would inevitably populate it.
    environment: str
    started_at: datetime
    upload_fn: Callable[[dict[str, Any]], bool]
    """Network callback. Returns True on 2xx, False otherwise."""
    enqueue_fn: Callable[[dict[str, Any]], None]
    """Disk-queue callback for failed chunk uploads (reuses Tier 1 queue)."""
    sanitize_fn: Callable[[str], str]
    """Pass-through for ``_sanitize_rich_output`` — chunks must arrive
    sanitised at the server (same rules as the single-shot path)."""
    export_html_fn: Callable[[], str]
    """Callback that returns the current Rich console HTML recording.
    The streamer takes a short export-lock around the call."""
    version_payload_fn: Callable[[], dict[str, Any]]
    """Returns the version + lab metadata block to include on every
    chunk (so the server can bootstrap the sessions row from the first
    chunk that arrives)."""


class SessionStreamer:
    """Drives chunked uploads on a daemon thread."""

    def __init__(self, config: StreamerConfig) -> None:
        self._config = config
        self._seq: int = 0
        self._sent_chars: int = 0  # length of the sanitized text already shipped
        # Length of the raw exported HTML at the last flush that actually
        # sanitized. The record buffer is append-only (export_html(clear=False)),
        # so an unchanged length means no new content since the last flush -- we
        # then skip the (whole-buffer, O(n)) sanitize entirely. -1 = never flushed.
        self._last_flush_raw_len: int = -1
        self._lock = threading.Lock()
        self._event_wake = threading.Event()
        self._stop_event = threading.Event()
        self._pending_lifecycle: list[LifecycleEvent] = []
        self._final_pending: bool = False
        self._final_metadata: dict[str, Any] = {}
        self._thread: Optional[threading.Thread] = None
        self._scan_count: int = 0
        self._had_scan: bool = False

    # ────────────────────────────────────────────────────────────────
    # Lifecycle API (called from the CLI main thread)
    # ────────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Spawn the streamer thread. Safe to call multiple times — the
        second invocation is a no-op so feature toggles can call it
        from anywhere without bookkeeping.
        """
        if self._thread is not None and self._thread.is_alive():
            return
        thread = threading.Thread(
            target=self._run_loop,
            name="adscan-session-streamer",
            daemon=True,
        )
        self._thread = thread
        thread.start()

    def emit_lifecycle(
        self,
        event: str,
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        """Queue a lifecycle marker for the next chunk.

        Returns immediately. The marker is appended to the pending
        list and the streamer thread is woken so it flushes promptly
        (without waiting for the 30-s timer). If two lifecycle events
        fire back-to-back from the CLI thread, both ride the next
        chunk's metadata array — the server unpacks them in order.
        """
        if not event:
            return
        with self._lock:
            self._pending_lifecycle.append(
                LifecycleEvent(event=event, metadata=dict(metadata or {}))
            )
            if event == "scan_started":
                self._had_scan = True
                self._scan_count += 1
        self._event_wake.set()

    def finalise(
        self,
        *,
        finished_at: datetime,
        compromise_status: Optional[str] = None,
        compromised_users_count: Optional[int] = None,
    ) -> None:
        """Mark the session as finished — the next chunk is the final.

        The streamer wakes, ships any pending diff plus the
        ``is_final=true`` marker, and exits its loop. Synchronous wait
        on the thread is bounded by the upload timeout (10 s) so a
        slow server cannot block CLI exit beyond that.
        """
        with self._lock:
            self._final_pending = True
            self._final_metadata = {
                "finished_at": finished_at.isoformat(),
                "duration_seconds": max(
                    0.0,
                    (finished_at - self._config.started_at).total_seconds(),
                ),
                "compromise_status": compromise_status,
                "compromised_users_count": compromised_users_count,
                "had_scan": self._had_scan,
                "scan_count": self._scan_count,
            }
        self._event_wake.set()
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=12.0)  # 10s upload + 2s margin

    # ────────────────────────────────────────────────────────────────
    # Worker loop
    # ────────────────────────────────────────────────────────────────

    def _run_loop(self) -> None:
        """Daemon-thread loop: timer + size + lifecycle triggers."""
        while True:
            triggered = self._event_wake.wait(timeout=CHUNK_INTERVAL_SECONDS)
            self._event_wake.clear()

            should_finalise = self._stop_event.is_set()
            try:
                self._flush_once(force_final=should_finalise)
            except Exception:  # noqa: BLE001
                # Best-effort: a failed flush must not crash the loop
                # — wait for the next trigger and try again. Errors
                # surface in the debug log via the upload callback.
                pass

            if should_finalise:
                return
            if not triggered:
                # Timer fired with no lifecycle and no stop signal —
                # still loop back; the size trigger is checked inside
                # _flush_once.
                continue

    def _flush_once(self, *, force_final: bool) -> None:
        """Compute the diff, attach pending lifecycle, ship or enqueue."""
        with self._lock:
            lifecycle_batch = list(self._pending_lifecycle)
            self._pending_lifecycle.clear()
            final_metadata = dict(self._final_metadata) if force_final else {}
            final_flag = force_final

        # Pull current sanitized HTML and compute the diff vs what we've
        # already shipped. Sanitization runs INSIDE the lock-free
        # section because the sanitizer is pure.
        raw_html = self._safe_export_html()

        # Skip the whole-buffer sanitize when there is NOTHING new to ship. The
        # record buffer is append-only, so an unchanged raw length means no new
        # content since the last flush; sanitizing it again would just recompute
        # the same output and the existing "nothing changed" guard below would
        # discard it anyway. A timer flush during a quiet scan phase (waiting on a
        # tool / the network) hits this and avoids a wasted O(buffer) sanitize.
        # A pending lifecycle event or the final flush must always proceed.
        raw_len = len(raw_html)
        if (
            not force_final
            and not lifecycle_batch
            and raw_len == self._last_flush_raw_len
        ):
            return

        sanitized = self._config.sanitize_fn(raw_html) if raw_html else ""
        self._last_flush_raw_len = raw_len

        # Defensive cursor recovery: if the sanitized buffer is SHORTER
        # than our cursor, the upstream Rich console was reset / cleared
        # behind our back (someone called ``export_html()`` with the
        # default ``clear=True``, or a Live context drained the
        # record buffer). Treat the current sanitized content as new
        # material from scratch — better to re-ship some bytes than
        # to silently stop shipping forever, which is what happens
        # when ``sanitized[sent_chars:]`` returns an empty string.
        if len(sanitized) < self._sent_chars:
            self._sent_chars = 0

        new_chars = sanitized[self._sent_chars:]
        new_bytes = new_chars.encode("utf-8")

        size_trigger = len(new_bytes) >= CHUNK_SIZE_BYTES
        lifecycle_trigger = bool(lifecycle_batch)
        if not (force_final or size_trigger or lifecycle_trigger):
            # Timer fired but nothing changed and no lifecycle pending —
            # skip the upload entirely. Saves bandwidth on idle sessions
            # (user opened CLI and went to lunch).
            return

        # Truncate oversized chunks (defensive — shouldn't happen but
        # the server enforces 1 MiB per chunk decompressed).
        if len(new_bytes) > MAX_CHUNK_DECOMPRESSED_BYTES:
            new_chars = new_bytes[:MAX_CHUNK_DECOMPRESSED_BYTES].decode(
                "utf-8", errors="ignore"
            )
            new_bytes = new_chars.encode("utf-8")

        seq = self._seq

        # Build the payload. We send the content as base64-encoded gzip
        # so the JSON envelope stays printable and the size on the wire
        # is already minimal even before HTTP-level gzip. Each chunk
        # also carries enough identity for the server to bootstrap the
        # sessions row from the very first chunk that arrives.
        version_payload = self._config.version_payload_fn() or {}
        chunk_content_gz = gzip.compress(new_bytes) if new_bytes else b""
        content_b64 = base64.b64encode(chunk_content_gz).decode("ascii")

        # Lifecycle metadata: when multiple events queued between
        # flushes, only one chunk carries them — use the LAST event as
        # the chunk-level marker (most recent state), but attach the
        # full ordered list to scan_metadata so the server timeline is
        # complete.
        lifecycle_event: Optional[str] = None
        scan_metadata: dict[str, Any] = {}
        if lifecycle_batch:
            lifecycle_event = lifecycle_batch[-1].event
            scan_metadata = dict(lifecycle_batch[-1].metadata)
            if len(lifecycle_batch) > 1:
                scan_metadata["_batched_events"] = [
                    {"event": e.event, "metadata": e.metadata}
                    for e in lifecycle_batch
                ]
        if force_final and final_metadata:
            # On the final chunk, ALWAYS carry session_finished as the
            # lifecycle marker if no other event is queued — the
            # server uses it to drive the "session_finished without
            # scan" telegram branch.
            if lifecycle_event is None:
                lifecycle_event = "session_finished"
            scan_metadata.update(final_metadata)

        payload: dict[str, Any] = {
            "seq": seq,
            "content_b64": content_b64,
            "lifecycle_event": lifecycle_event,
            "scan_metadata": scan_metadata or None,
            "is_final": final_flag,
            "user_id_hash": self._config.user_id_hash,
            "command_type": self._config.command_type,
            "session_scope": self._config.session_scope,
            "environment": self._config.environment,
            "started_at": self._config.started_at.isoformat(),
        }
        payload.update(version_payload)

        # Network attempt; on failure, enqueue for retry.
        ok = False
        try:
            ok = bool(self._config.upload_fn(payload))
        except Exception:  # noqa: BLE001
            ok = False
        if not ok:
            try:
                self._config.enqueue_fn(payload)
            except Exception:  # noqa: BLE001
                # Disk queue also failed — accept the chunk loss.
                pass

        # Advance the cursor regardless: a failed upload that was
        # enqueued will be retried with the exact same content; if the
        # disk queue also failed, retrying the same seq would only
        # duplicate effort. The server's primary key (trace_id, seq)
        # makes either path safely idempotent.
        self._seq = seq + 1
        self._sent_chars += len(new_chars)

    def _safe_export_html(self) -> str:
        try:
            return self._config.export_html_fn() or ""
        except Exception:  # noqa: BLE001
            return ""


__all__ = (
    "CHUNK_INTERVAL_SECONDS",
    "CHUNK_SIZE_BYTES",
    "LifecycleEvent",
    "MAX_CHUNK_DECOMPRESSED_BYTES",
    "SessionStreamer",
    "StreamerConfig",
    "should_stream_for_command",
)
