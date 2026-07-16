"""Poisoning as a background job.

Reuses the daemon-thread + private-event-loop + ``queue.Queue`` substrate of
``adscan_internal.cli.poisoning`` (``_run_suite``). The behavioral difference
from the manual ``start_poisoning`` path: captures are routed through a
:data:`JobResultSink` (persist + deferred notification) instead of being printed
inline and prompting for cracking. The background thread therefore NEVER prints
and NEVER prompts — the design's two hard invariants.
"""
from __future__ import annotations

import asyncio
import contextlib
import os
import queue as _queue
import threading
from typing import Any, Optional

from adscan_core import telemetry
from adscan_core.rich_output import background_console_context, print_info_debug
from adscan_internal.cli.creds import save_ntlm_hash
from adscan_internal.cli.poisoning import (
    _record_poison_captured_ntlmv2_user,
    _resolve_full_domain,
    _run_suite,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.background_jobs.cracking_enqueue import enqueue_cracking_job
from adscan_internal.services.background_jobs.results_bus import (
    JobResult,
    JobResultSink,
)


class PoisoningJobRuntime:
    """Live poisoning worker; implements the ``JobRuntime`` protocol."""

    def __init__(
        self,
        shell: Any,
        *,
        interface: str,
        advertised_ip: Optional[str],
        sink: JobResultSink,
        job_id: str,
    ) -> None:
        self.shell = shell
        self.interface = interface
        self.advertised_ip = advertised_ip
        self.sink = sink
        self.job_id = job_id
        self.processed_users: set[str] = set()
        self.captured = 0
        self._stop_event = threading.Event()
        self._capture_queue: _queue.Queue = _queue.Queue()
        self._async_thread: Optional[threading.Thread] = None
        self._consumer_thread: Optional[threading.Thread] = None

    # ── JobRuntime protocol ─────────────────────────────────────────────────

    def start(self) -> bool:
        """Spawn the suite thread + capture consumer. Returns True on ready."""
        ready_event = threading.Event()
        error_holder: list[Exception] = []
        loop_holder: list[asyncio.AbstractEventLoop] = []
        interface = self.interface
        advertised_ip = self.advertised_ip

        def _async_thread() -> None:
            # The suite's LLMNR/NBT-NS/mDNS listener DEBUG runs on THIS worker
            # thread; route it off the live console (telemetry + deferred flush)
            # so it never collides with the foreground flow or a prompt.
            with background_console_context(f"poisoning-{interface}"):
                loop = asyncio.new_event_loop()
                loop_holder.append(loop)
                asyncio.set_event_loop(loop)
                try:
                    loop.run_until_complete(
                        _run_suite(
                            interface_name=interface,
                            advertised_ipv4=advertised_ip,
                            capture_queue=self._capture_queue,
                            stop_event=self._stop_event,
                            ready_event=ready_event,
                            error_holder=error_holder,
                        )
                    )
                finally:
                    with contextlib.suppress(Exception):
                        loop.run_until_complete(loop.shutdown_asyncgens())
                    loop.close()

        self._async_thread = threading.Thread(
            target=_async_thread, name=f"job-poisoning-{self.interface}", daemon=True
        )
        self._async_thread.start()
        ready_event.wait(timeout=15.0)

        if error_holder:
            telemetry.capture_exception(error_holder[0])
            print_info_debug(
                f"poisoning-job: suite failed to start on {self.interface}: "
                f"{error_holder[0]}"
            )
            self._stop_event.set()
            self._async_thread.join(timeout=5.0)
            return False
        if not self._async_thread.is_alive():
            print_info_debug("poisoning-job: suite exited before becoming ready")
            return False

        self._consumer_thread = threading.Thread(
            target=self._consume,
            name=f"job-poisoning-consumer-{self.interface}",
            daemon=True,
        )
        self._consumer_thread.start()
        return True

    def stop(self) -> None:
        self._stop_event.set()
        self._capture_queue.put(None)  # wake the consumer
        if self._async_thread is not None:
            self._async_thread.join(timeout=10.0)
        if self._consumer_thread is not None:
            self._consumer_thread.join(timeout=5.0)

    def snapshot(self) -> dict[str, Any]:
        return {"captured": self.captured, "interface": self.interface}

    def is_alive(self) -> bool:
        return bool(self._async_thread is not None and self._async_thread.is_alive())

    # ── capture consumer ────────────────────────────────────────────────────

    def _consume(self) -> None:
        # Runs on a background worker thread — keep any incidental console
        # output off the live terminal (deferred + telemetered).
        with background_console_context(f"poisoning-{self.interface}"):
            while not self._stop_event.is_set():
                try:
                    item = self._capture_queue.get(timeout=0.5)
                except _queue.Empty:
                    continue
                if item is None:
                    return
                try:
                    _handle_capture_to_sink(self, item)
                except Exception as exc:  # noqa: BLE001 — never let a bad capture kill the job
                    telemetry.capture_exception(exc)


def _handle_capture_to_sink(runtime: "PoisoningJobRuntime", item: dict) -> None:
    """Persist one capture + emit a JobResult. No print, no prompt.

    Dedups per user, resolves the storage domain (workspace FQDN or the captured
    NetBIOS fallback), persists via ``save_ntlm_hash``, records NetNTLMv2
    provenance for the Part-3 attack-step, and emits a deferred notification.
    Cracking is intentionally NOT triggered here (it is interactive) — the
    foreground offers it at the notification / reconciliation point.
    """
    user = str(item.get("username") or "")
    if not user:
        return
    if user in runtime.processed_users:
        return
    runtime.processed_users.add(user)

    shell = runtime.shell
    netbios = item.get("domain_netbios") or None
    fullhash = item.get("fullhash") or ""
    version = item.get("version") or "v2"

    domain = _resolve_full_domain(shell, netbios)
    if not domain:
        domain = (netbios or "captured").strip().lower() or "captured"

    if not save_ntlm_hash(shell, domain, version, user, fullhash):
        return  # already recorded for this user

    if version == "v2":
        _record_poison_captured_ntlmv2_user(shell, domain, user)

    runtime.captured += 1

    marked_user = mark_sensitive(user, "user")
    marked_domain = mark_sensitive(domain, "domain")
    summary = f"Poisoning captured a NetNTLM{version} response for {marked_user}@{marked_domain}"
    runtime.sink(
        JobResult(
            job_id=runtime.job_id,
            kind="poisoning",
            scope=getattr(runtime, "interface", ""),
            summary=summary,
            detail={
                "captured": runtime.captured,
                "version": version,
                "user": user,
                "domain": domain,
            },
        )
    )

    # Policy-gated auto-crack: user hashes get a background wordlist job,
    # machine NTLMv1 gets a rainbow-pending notification, machine NTLMv2 is
    # skipped (not recoverable). Best-effort — never break capture on failure.
    try:
        from adscan_internal.services.cracking_wordlist_policy import (  # noqa: PLC0415
            resolve_effort_or_default,
        )

        hash_file = os.path.join(
            shell.domains_dir, domain, shell.cracking_dir, f"{user}_hashes.NTLM{version}"
        )
        enqueue_cracking_job(
            shell, domain=domain, user=user, ntlm_version=version, hash_file=hash_file,
            effort=resolve_effort_or_default(shell),
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
