"""Durable, thread-safe registry for background jobs.

Durability model mirrors ``environment_change_ledger``: a JSON file under the
workspace directory is (re)written after every state change, so job metadata
survives session death. ``finalize()`` force-resolves any still-running job to
``stopped`` — the session-died guarantee.

The registry holds two layers:
  * JSON-safe metadata (``BackgroundJob`` records) — persisted.
  * Live runtime handles (thread + stop machinery) — in memory only, keyed by
    job id, never serialized.

Idempotency is by ``(kind, scope)``: while a job with that pair is running,
``find_active`` returns it, so a second launch is a no-op.
"""
from __future__ import annotations

import os
import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Callable, Literal, Optional, Protocol, runtime_checkable

from adscan_core import telemetry
from adscan_internal.workspaces.io import read_json_file, write_json_file

_JOBS_FILENAME = "background_jobs.json"
_SCHEMA_VERSION = "1.0"

JobState = Literal["pending", "running", "done", "failed", "stopped"]
_TERMINAL_STATES: frozenset[str] = frozenset({"done", "failed", "stopped"})


def _utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


@runtime_checkable
class JobRuntime(Protocol):
    """A live background worker the registry can control + inspect."""

    def stop(self) -> None: ...
    def snapshot(self) -> dict[str, Any]: ...
    def is_alive(self) -> bool: ...


@dataclass
class BackgroundJob:
    """JSON-safe metadata for one background job."""

    id: str
    kind: str
    scope: str
    state: JobState
    started_at: Optional[str]
    finished_at: Optional[str]
    result_summary: dict[str, Any] = field(default_factory=dict)

    def key(self) -> tuple[str, str]:
        return (self.kind, self.scope)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "scope": self.scope,
            "state": self.state,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "result_summary": dict(self.result_summary),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BackgroundJob":
        return cls(
            id=str(data.get("id") or ""),
            kind=str(data.get("kind") or ""),
            scope=str(data.get("scope") or ""),
            state=str(data.get("state") or "pending"),  # type: ignore[arg-type]
            started_at=data.get("started_at"),
            finished_at=data.get("finished_at"),
            result_summary=dict(data.get("result_summary") or {}),
        )


class BackgroundJobRegistry:
    """Thread-safe registry of background jobs with durable JSON persistence."""

    def __init__(self, workspace_dir: str) -> None:
        self._path = os.path.join(workspace_dir, _JOBS_FILENAME)
        self._lock = threading.RLock()
        self._runtimes: dict[str, JobRuntime] = {}
        self._notifications: list[Any] = []
        # Optional dependency-inverted hook fired (best-effort, off-lock) right
        # after a notification is enqueued, so the foreground REPL can surface a
        # result LIVE while the operator is parked at the idle prompt instead of
        # waiting for the next command's pre-prompt drain. The registry never
        # imports the REPL / prompt_toolkit — the shell injects the hook.
        self._notification_hook: Optional[Callable[[], None]] = None
        self._state: dict[str, Any] = self._load()

    # ── persistence ─────────────────────────────────────────────────────────

    def _load(self) -> dict[str, Any]:
        try:
            if os.path.exists(self._path):
                raw = read_json_file(self._path)
                if isinstance(raw, dict) and isinstance(raw.get("jobs"), list):
                    return {"schema": _SCHEMA_VERSION, "jobs": list(raw["jobs"])}
        except Exception as exc:  # noqa: BLE001 — a corrupt file must not break load
            telemetry.capture_exception(exc)
        return {"schema": _SCHEMA_VERSION, "jobs": []}

    def flush(self) -> None:
        with self._lock:
            try:
                write_json_file(self._path, dict(self._state))
            except Exception as exc:  # noqa: BLE001 — persistence is best-effort
                telemetry.capture_exception(exc)

    # ── job records ─────────────────────────────────────────────────────────

    def _records(self) -> list[dict[str, Any]]:
        return self._state.setdefault("jobs", [])

    def _find_record(self, job_id: str) -> Optional[dict[str, Any]]:
        for rec in self._records():
            if rec.get("id") == job_id:
                return rec
        return None

    def create(self, *, kind: str, scope: str) -> BackgroundJob:
        """Create a running job, or return the existing active one (idempotent)."""
        with self._lock:
            existing = self.find_active(kind, scope)
            if existing is not None:
                return existing
            job = BackgroundJob(
                id=str(uuid.uuid4()),
                kind=str(kind),
                scope=str(scope),
                state="running",
                started_at=_utc_now_iso(),
                finished_at=None,
                result_summary={},
            )
            self._records().append(job.to_dict())
            self.flush()
            return job

    def find_active(self, kind: str, scope: str) -> Optional[BackgroundJob]:
        with self._lock:
            for rec in self._records():
                if (
                    rec.get("kind") == kind
                    and rec.get("scope") == scope
                    and str(rec.get("state")) not in _TERMINAL_STATES
                ):
                    return BackgroundJob.from_dict(rec)
            return None

    def mark(
        self,
        job_id: str,
        *,
        state: JobState,
        result_summary: Optional[dict[str, Any]] = None,
    ) -> None:
        with self._lock:
            rec = self._find_record(job_id)
            if rec is None:
                return
            rec["state"] = state
            if result_summary is not None:
                rec["result_summary"] = dict(result_summary)
            if state in _TERMINAL_STATES and not rec.get("finished_at"):
                rec["finished_at"] = _utc_now_iso()
            self.flush()

    def list_jobs(self) -> list[BackgroundJob]:
        with self._lock:
            return [BackgroundJob.from_dict(rec) for rec in self._records()]

    def active(self) -> list[BackgroundJob]:
        with self._lock:
            return [
                BackgroundJob.from_dict(rec)
                for rec in self._records()
                if str(rec.get("state")) not in _TERMINAL_STATES
            ]

    # ── live runtimes ───────────────────────────────────────────────────────

    def attach_runtime(self, job_id: str, runtime: JobRuntime) -> None:
        with self._lock:
            self._runtimes[job_id] = runtime

    def get_runtime(self, job_id: str) -> Optional[JobRuntime]:
        with self._lock:
            return self._runtimes.get(job_id)

    def stop(self, job_id: str) -> None:
        """Stop a running job via its runtime, then mark it stopped."""
        runtime = self.get_runtime(job_id)
        if runtime is not None:
            try:
                summary = runtime.snapshot()
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                summary = None
            try:
                runtime.stop()
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
            self.mark(job_id, state="stopped", result_summary=summary)
        else:
            self.mark(job_id, state="stopped")

    # ── deferred notifications ──────────────────────────────────────────────

    def set_notification_hook(self, hook: Optional[Callable[[], None]]) -> None:
        """Inject (or clear) the post-enqueue notification hook.

        Dependency-inverted: the shell passes a callable that wakes the idle
        prompt. The registry calls it (best-effort, never under the lock) after
        each ``enqueue_notification`` so a completed job can surface live. Never
        imports the REPL / prompt_toolkit itself.
        """
        with self._lock:
            self._notification_hook = hook

    def enqueue_notification(self, result: Any) -> None:
        with self._lock:
            self._notifications.append(result)
            hook = self._notification_hook
        # Fire OUTSIDE the lock: the hook may schedule work on another thread's
        # event loop and must not block (or re-enter) the registry lock. Fully
        # best-effort — a hook failure never affects the enqueue.
        if hook is not None:
            try:
                hook()
            except Exception as exc:  # noqa: BLE001 — the wake hook must never break enqueue
                telemetry.capture_exception(exc)

    def drain_notifications(self) -> list[Any]:
        with self._lock:
            drained = list(self._notifications)
            self._notifications.clear()
            return drained

    # ── session-death guarantee ─────────────────────────────────────────────

    def finalize(self) -> None:
        """Force every still-running job to ``stopped`` and flush.

        Called on graceful OR abrupt exit so the persisted state never shows a
        job wedged in ``running`` after the process is gone.

        The blocking ``runtime.stop()`` join runs OUTSIDE the lock (mirroring
        :meth:`stop`). Holding the lock across the join would deadlock a
        consumer thread that is mid-capture waiting on the same lock, and would
        let that consumer's in-flight ``mark(state="running")`` land AFTER
        finalize — flipping the job back to ``running`` and leaving a ghost
        record that the ``find_active`` guard would then treat as active,
        suppressing a future launch. Stopping the runtime first (the join
        completes → the consumer has terminated, so no late ``mark`` can fire)
        and stamping ``stopped`` only afterwards closes that window.
        """
        # Phase 1 — under the lock, snapshot the non-terminal jobs + runtimes.
        with self._lock:
            pending = [
                (str(rec.get("id")), self._runtimes.get(str(rec.get("id"))))
                for rec in self._records()
                if str(rec.get("state")) not in _TERMINAL_STATES
            ]
        if not pending:
            return
        # Phase 2 — stop each runtime OUTSIDE the lock (the join can block).
        summaries: dict[str, dict[str, Any]] = {}
        for job_id, runtime in pending:
            if runtime is None:
                continue
            try:
                runtime.stop()
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
            try:
                summaries[job_id] = dict(runtime.snapshot())
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
        # Phase 3 — re-acquire and stamp ``stopped``; the consumers have now
        # terminated, so no late mark can flip these back to ``running``.
        with self._lock:
            for job_id, _runtime in pending:
                rec = self._find_record(job_id)
                if rec is None:
                    continue
                if job_id in summaries:
                    rec["result_summary"] = summaries[job_id]
                rec["state"] = "stopped"
                if not rec.get("finished_at"):
                    rec["finished_at"] = _utc_now_iso()
            self.flush()


def get_or_create_registry(shell: Any) -> BackgroundJobRegistry:
    """Return the shell's registry, creating + attaching it on first use.

    Keyed off ``shell.current_workspace_dir`` (falls back to cwd). The registry
    is stored on ``shell._background_jobs`` so all callers in a session share it.
    """
    existing = getattr(shell, "_background_jobs", None)
    if isinstance(existing, BackgroundJobRegistry):
        return existing
    workspace_dir = getattr(shell, "current_workspace_dir", None) or os.getcwd()
    registry = BackgroundJobRegistry(str(workspace_dir))
    try:
        shell._background_jobs = registry  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
    return registry
