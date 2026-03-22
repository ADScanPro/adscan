"""BloodHound CE OpenGraph edge upload queue.

This module provides a background queue that uploads ADscan-discovered custom
attack steps to BloodHound CE via the same ``BloodHoundService.start_upload_job``
pipeline used for collector ZIP files (RustHound-CE, bloodhound-ce-python).

Design
------
Custom edges (non-native BH relations such as Kerberoasting, PasswordSpray, etc.)
are enqueued immediately when they are created — regardless of whether the BH
service is available yet.  The queue acts as a pre-activation buffer: items
accumulate until ``setup()`` is called and the background worker is started.
This means any scan that creates custom edges (spraying, LDAP enum, etc.) is
fully covered without requiring BH to be initialised beforehand.

The queue has a bounded capacity (``_MAX_QUEUE_SIZE``) so it never grows
unboundedly in sessions where BH is never set up.

Usage::

    # Once a BH service is available, register a factory and start the worker:
    bh_opengraph_sync.setup(lambda: shell._get_bloodhound_service())

    # Edges are enqueued automatically from upsert_edge — no manual calls needed.

    # Before computing attack paths (ensures BH graph is up-to-date):
    bh_opengraph_sync.wait_until_flushed(timeout=30.0)
"""

from __future__ import annotations

import json
import os
import queue
import tempfile
import threading
import time
from typing import Any, Callable

from adscan_core.rich_output import (
    print_info_debug,
    print_info_verbose,
    print_warning,
    print_error,
)

# ── Module-level state ────────────────────────────────────────────────────────
_MAX_QUEUE_SIZE = 50_000  # cap to prevent unbounded growth when BH is never set up
_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=_MAX_QUEUE_SIZE)
_worker_thread: threading.Thread | None = None
_worker_stop: threading.Event = threading.Event()
_get_service: Callable[[], Any] | None = None
_lock: threading.Lock = threading.Lock()
_total_uploaded: int = 0
_total_failed: int = 0

# When True, enqueue_custom_edge uploads synchronously on the calling thread
# instead of deferring to the background worker. This ensures upload logs
# appear inline with the operation that triggered them.
# Set ADSCAN_BH_OPENGRAPH_ASYNC=true to switch to background mode.
_sync_mode: bool = True


def set_sync_mode(enabled: bool) -> None:
    """Enable or disable synchronous upload mode.

    When enabled, ``enqueue_custom_edge`` uploads immediately on the calling
    thread instead of queuing for the background worker.  Use this during
    debugging to keep upload logs visible in the main console output.
    """
    global _sync_mode
    _sync_mode = enabled


def setup(get_service: Callable[[], Any]) -> None:
    """Register a ``BloodHoundService`` factory and start the background worker.

    Reuses the same service layer used by ``upload_bloodhound_ce_zip_files``
    (i.e. ``BloodHoundService.start_upload_job``).

    Idempotent: safe to call multiple times. The worker is only started once;
    subsequent calls update the factory (e.g. after reconnect).

    Args:
        get_service: Zero-argument callable returning a ``BloodHoundService`` instance.
    """
    global _get_service, _worker_thread
    _get_service = get_service
    with _lock:
        if _worker_thread is None or not _worker_thread.is_alive():
            _worker_stop.clear()
            _worker_thread = threading.Thread(
                target=_worker_loop,
                daemon=True,
                name="bh-opengraph-sync",
            )
            _worker_thread.start()
            print_info_debug("[bh_opengraph_sync] worker thread started")


def shutdown() -> None:
    """Signal the worker to stop after draining the current queue."""
    _worker_stop.set()


def is_active() -> bool:
    """Return True if the module has been initialised with a service factory."""
    return _get_service is not None


def pending_count() -> int:
    """Return the number of edges currently waiting to be uploaded."""
    return _queue.qsize()


def enqueue_custom_edge(edge: dict[str, Any]) -> None:
    """Add a custom OpenGraph edge to the upload queue.

    Always enqueues — even before ``setup()`` is called.  The queue acts as a
    pre-activation buffer: edges accumulate and are drained once the background
    worker is started via ``setup()``.

    Silently drops the edge when the queue is at capacity (``_MAX_QUEUE_SIZE``).

    Args:
        edge: OpenGraph edge dict with ``kind``, ``start``, ``end``, ``properties``.
    """
    if _sync_mode and is_active():
        print_info_debug(
            f"[bh_opengraph_sync] uploading synchronously (kind={edge.get('kind')})"
        )
        _upload_batch([edge])
        return

    try:
        _queue.put_nowait(edge)
    except queue.Full:
        print_info_debug(
            f"[bh_opengraph_sync] queue full, edge dropped (kind={edge.get('kind')})"
        )
        return
    print_info_debug(
        f"[bh_opengraph_sync] edge enqueued (kind={edge.get('kind')}, pending={_queue.qsize()})"
    )


def wait_until_flushed(timeout: float = 30.0) -> bool:
    """Block until all queued edges have been uploaded or timeout expires.

    Args:
        timeout: Maximum seconds to wait.

    Returns:
        True if queue was fully drained, False on timeout.
    """
    if _queue.empty():
        return True
    deadline = time.monotonic() + timeout
    while not _queue.empty():
        if time.monotonic() >= deadline:
            print_warning(
                f"[bh_opengraph_sync] wait_until_flushed timed out (pending={_queue.qsize()})"
            )
            return False
        time.sleep(0.05)
    return True


def stats() -> dict[str, int]:
    """Return cumulative upload statistics for diagnostics."""
    return {
        "total_uploaded": _total_uploaded,
        "total_failed": _total_failed,
        "pending": _queue.qsize(),
    }


# ── Background worker ─────────────────────────────────────────────────────────

def _worker_loop() -> None:
    """Drain the queue in batches and upload to BH CE."""
    while not _worker_stop.is_set():
        try:
            first = _queue.get(timeout=0.5)
        except queue.Empty:
            continue

        batch = [first]
        # Drain any items that arrived concurrently.
        while True:
            try:
                batch.append(_queue.get_nowait())
            except queue.Empty:
                break

        try:
            _upload_batch(batch)
        except Exception as exc:  # noqa: BLE001
            print_error(
                f"[bh_opengraph_sync] upload batch failed: {exc} (edge_count={len(batch)})"
            )
        finally:
            for _ in batch:
                _queue.task_done()


def _upload_batch(edges: list[dict[str, Any]]) -> None:
    """Upsert a batch of custom edges into BH CE.

    Primary path: Cypher MERGE via ``/api/v2/graphs/cypher`` (~10-50ms per edge).
    Fallback path: file upload job pipeline for any edges the cypher path rejects.
    """
    global _total_uploaded, _total_failed

    service_getter = _get_service
    if not service_getter:
        _total_failed += len(edges)
        return

    try:
        service = service_getter()
    except Exception as exc:  # noqa: BLE001
        print_info_verbose(
            f"[bh_opengraph_sync] could not obtain BloodHoundService: {exc}"
        )
        _total_failed += len(edges)
        return

    if service is None:
        _total_failed += len(edges)
        return

    # ── Primary: Cypher MERGE ──────────────────────────────────────────────────
    cypher_fn = getattr(service, "upsert_custom_edge", None)
    fallback_edges: list[dict[str, Any]] = []

    if callable(cypher_fn):
        t0 = time.perf_counter()
        for edge in edges:
            try:
                ok = cypher_fn(edge)
            except Exception:  # noqa: BLE001
                ok = False
            if ok:
                _total_uploaded += 1
            else:
                fallback_edges.append(edge)
        cypher_ms = round((time.perf_counter() - t0) * 1000)
        cypher_ok = len(edges) - len(fallback_edges)
        print_info_verbose(
            f"[bh_opengraph_sync] cypher upsert"
            f" (ok={cypher_ok}, fallback={len(fallback_edges)}, ms={cypher_ms})"
        )
    else:
        # Service doesn't expose cypher upsert — route everything to file upload.
        fallback_edges = list(edges)

    if not fallback_edges:
        return

    # ── Fallback: file upload job pipeline ────────────────────────────────────
    if not hasattr(service, "start_upload_job"):
        _total_failed += len(fallback_edges)
        print_info_verbose(
            f"[bh_opengraph_sync] no upload fallback available"
            f" (failed_edges={len(fallback_edges)})"
        )
        return

    payload = {"graph": {"nodes": [], "edges": fallback_edges}}
    t0 = time.perf_counter()
    tmp_path: str | None = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            prefix="adscan_opengraph_",
            delete=False,
            encoding="utf-8",
        ) as tmp:
            json.dump(payload, tmp)
            tmp_path = tmp.name

        job_id = service.start_upload_job(tmp_path)
        transfer_ms = round((time.perf_counter() - t0) * 1000)

        if job_id is None:
            _total_failed += len(fallback_edges)
            print_info_verbose(
                f"[bh_opengraph_sync] fallback upload returned no job_id"
                f" (edge_count={len(fallback_edges)}, transfer_ms={transfer_ms})"
            )
            return

        wait_ingestion = os.getenv("ADSCAN_BH_OPENGRAPH_WAIT_INGESTION", "true").lower() != "false"
        ingestion_ms: int | None = None
        ingestion_ok: bool | None = None

        if wait_ingestion and hasattr(service, "wait_for_upload_job"):
            t_ingest = time.perf_counter()
            try:
                ingestion_ok = service.wait_for_upload_job(
                    job_id, poll_interval=2, timeout=120
                )
            except Exception as exc:  # noqa: BLE001
                print_info_verbose(
                    f"[bh_opengraph_sync] ingestion wait failed (job_id={job_id}): {exc}"
                )
            ingestion_ms = round((time.perf_counter() - t_ingest) * 1000)

        _total_uploaded += len(fallback_edges)
        print_info_verbose(
            f"[bh_opengraph_sync] fallback upload complete"
            f" (edges={len(fallback_edges)}, job_id={job_id},"
            f" transfer_ms={transfer_ms}, ingestion_ms={ingestion_ms},"
            f" ingestion_ok={ingestion_ok}, total={_total_uploaded})"
        )
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
