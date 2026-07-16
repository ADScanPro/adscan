"""Ordered results-bus for background jobs.

A job **emits** a :class:`JobResult` to a sink. The registry-backed sink
**persists** the result into the job's ``result_summary`` and **enqueues** the
result for later, foreground-thread notification. The sink NEVER prints — that
is what keeps a background thread from colliding with the live sequential output
(the design's core invariant). Rendering is a separate consumer that drains the
registry's notification queue at a safe point in the REPL loop.

Mirrors the emit→persist→render decoupling of
``adscan_internal.services.posture_sink``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from adscan_core import telemetry
from adscan_core.rich_output import print_info_debug
from adscan_internal.services.background_jobs.registry import BackgroundJobRegistry


@dataclass
class JobResult:
    """One deferred, JSON-safe result emitted by a background job.

    ``terminal`` marks a job's LAST result — the job has run to completion and
    will emit nothing further. A finite job (a cracking ladder that cracked or
    exhausted its wordlists) sets it ``True`` on its final emit; an indefinite
    listener (broadcast poisoning, which keeps capturing until stopped) leaves it
    ``False`` on every emit. The sink uses it to transition the job to a terminal
    registry state (``done``) for a finite job's last result while keeping an
    indefinite listener ``running`` — see :func:`make_registry_result_sink`.
    """

    job_id: str
    kind: str
    scope: str
    summary: str
    detail: dict[str, Any] = field(default_factory=dict)
    terminal: bool = False


JobResultSink = Callable[[JobResult], None]


def make_registry_result_sink(
    registry: BackgroundJobRegistry,
    *,
    on_persist: Optional[Callable[[JobResult], None]] = None,
) -> JobResultSink:
    """Build a sink that persists a result + enqueues its notification.

    Args:
        registry: The session registry to persist into + enqueue onto.
        on_persist: Optional best-effort callback fired after persistence (used
            in tests / future consumers). Never affects the enqueue.

    Returns:
        A :data:`JobResultSink`. Never prints; never raises.
    """

    def _sink(result: JobResult) -> None:
        try:
            # A terminal result (a finite job's LAST emit) transitions the job to
            # a terminal registry state so it LEAVES ``registry.active()``; a
            # non-terminal result keeps the job ``running`` (an indefinite
            # listener emits many of these and must stay active until stopped).
            # This is the one place the ``running`` mark lives, so the terminal
            # transition is generic here — no per-kind hardcoding. ``done`` is the
            # right terminal state for a job that completed on its own (cracked or
            # exhausted); an operator stop / failed start / session finalize stamp
            # ``stopped`` / ``failed`` elsewhere. The final ``result_summary`` is
            # preserved on the record so ``jobs`` shows the correct final state.
            registry.mark(
                result.job_id,
                state="done" if result.terminal else "running",
                result_summary=dict(result.detail),
            )
        except Exception as exc:  # noqa: BLE001 — persistence is best-effort
            telemetry.capture_exception(exc)
        try:
            # crack-sink: greppable, --debug-only. Confirms the result reached the
            # bus and was enqueued for the foreground drain — the checkpoint
            # between "the runtime emitted" and "the foreground drained".
            detail = result.detail if isinstance(result.detail, dict) else {}
            print_info_debug(
                "crack-sink: enqueue "
                f"kind={result.kind} job_id={result.job_id} terminal={result.terminal} "
                f"status={detail.get('status')}"
            )
        except Exception as exc:  # noqa: BLE001 — a debug log must never break the enqueue
            telemetry.capture_exception(exc)
        try:
            registry.enqueue_notification(result)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
        if on_persist is not None:
            try:
                on_persist(result)
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)

    return _sink
