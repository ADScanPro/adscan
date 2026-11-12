"""The scan control plane: one process-wide controller every entry point shares.

A scan is a sequence of phases, each a sequence of steps. This module lets the
operator (Ctrl+C menu), ``adscan ci`` (SIGINT) and the web platform (a control
file in the execution workspace) change its course with ONE vocabulary
(:mod:`adscan_core.scan_control.vocabulary`):

* ``skip_step`` stops the current long step; it keeps what it found so far;
* ``skip_phase`` stops the current step and skips the rest of the phase;
* ``abort_scan`` stops the scan cleanly and returns to the prompt.

Scopes, outermost first: :meth:`ScanControl.scan` (one scan),
:meth:`ScanControl.enter_phase` (a boundary marker, the pipeline is sequential),
:meth:`ScanControl.step` / :meth:`ScanControl.run_step` (one step).

Rules that keep this safe (design: docs/superpowers/specs/
2026-11-12-scan-control-plane-design.md):

* **Only boundaries raise.** :meth:`StepScope.should_stop` is a cheap boolean an
  in-loop check reads; the loop breaks and returns its partial result. Step
  entry/exit, phase entry and :meth:`ScanControl.checkpoint` raise
  :class:`ScanAbortRequested` when an abort is pending.
* :class:`ScanAbortRequested` is a ``BaseException``: the pipeline's broad
  ``except Exception`` blocks cannot swallow it, and every ``finally`` (rollback,
  ledger, background-job finalize) still runs while it unwinds to the scan scope.
* Threading primitives only. Nothing here is bound to an event loop (CLAUDE.md
  "Nothing loop-bound outlives one event loop"); the controller is read from
  worker threads and from the SIGINT handler on the main thread.
* A stop is a declared coverage gap. The engine installs a recorder
  (:meth:`ScanControl.set_gap_recorder`) that persists every stop through the
  coverage SSOTs; this module never decides how a gap is worded in a report.
"""

from __future__ import annotations

import contextlib
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator

from adscan_core.scan_control.vocabulary import (
    SOURCE_OPERATOR_MENU,
    SOURCE_PLATFORM,
    ControlAction,
    ControlRequest,
    consume_control_request,
)

#: Minimum seconds between two reads of the control file. The in-loop check is
#: called per unit of work (per share, per host), so the file is polled at most
#: once a second however tight the loop is.
CONTROL_FILE_POLL_INTERVAL = 1.0


class ScanAbortRequested(BaseException):
    """Raised at a scan boundary when the scan was asked to stop.

    A ``BaseException`` on purpose: the pipeline has many ``except Exception``
    blocks that log and continue, and none of them may swallow an abort. It is
    caught by :meth:`ScanControl.scan` (and by the scan entry points), never by
    step code.
    """

    def __init__(self, request: ControlRequest | None = None) -> None:
        super().__init__("scan stopped by the operator")
        self.request = request


@dataclass(frozen=True)
class OperatorStop:
    """One stop the gap recorder must persist.

    Attributes:
        action: ``skip_step``, ``skip_phase`` or ``abort_scan``.
        source: Where the request came from (see the vocabulary sources).
        domain: Domain the scan was working on, ``""`` when unknown.
        phase_id: Canonical ``scan_phases`` id of the phase, ``""`` when none.
        step_id: Stable id of the stopped step, ``""`` for a stop at a boundary.
        label: Client-safe display name of the step (English).
        examined: Units completed before the stop, ``None`` when not counted.
        total: Units the step had to do, ``None`` when unknown.
        unit: Plural noun for the units (``"shares"``, ``"hosts"``).
    """

    action: str
    source: str
    domain: str = ""
    phase_id: str = ""
    step_id: str = ""
    label: str = ""
    examined: int | None = None
    total: int | None = None
    unit: str = ""


@dataclass
class StepScope:
    """One running step. Handed to the body of :meth:`ScanControl.step`.

    Attributes:
        step_id: Stable machine id (``share_credential_hunt``).
        label: Client-safe display name (``SMB share credential hunt``).
        long: Whether the body polls :meth:`should_stop` inside its loop. Only a
            long step is offered "stop this step": a step that never checks would
            make that offer a lie.
        unit: Plural noun for :meth:`progress` counts.
        phase_id: Phase the step runs in (``""`` outside a phase).
        domain: Domain the step works on (``""`` when unknown).
    """

    step_id: str
    label: str
    long: bool
    unit: str
    phase_id: str
    domain: str
    _control: "ScanControl" = field(repr=False)
    done: int | None = None
    total: int | None = None
    _stop_action: ControlAction | None = field(default=None, repr=False)
    _stop_source: str = field(default="", repr=False)
    _stop_observed: bool = field(default=False, repr=False)
    record_gap: bool = True

    def should_stop(self) -> bool:
        """Cheap in-loop check: True when this step must stop launching new work.

        True for a ``skip_step`` aimed at this step, a ``skip_phase`` aimed at
        its phase, and an ``abort_scan``. Polls the control file at most once a
        second. Never raises: a loop breaks on True and returns what it has.
        """
        verdict = self._control._stop_verdict_for(self)
        if verdict is not None:
            action, source = verdict
            if not self._stop_observed:
                self._stop_observed = True
                self._stop_action = action
                self._stop_source = source
            return True
        return False

    def progress(self, done: int | None = None, total: int | None = None) -> None:
        """Record how far the step got, for the "N of M" gap statement."""
        if done is not None:
            self.done = max(0, int(done))
        if total is not None:
            self.total = max(0, int(total))
        self._control._emit_state()

    @property
    def stopped(self) -> bool:
        """Whether the body observed a stop (its loop ended early)."""
        return self._stop_observed

    @property
    def stop_action(self) -> ControlAction | None:
        """The action that stopped the step, ``None`` when it ran to the end."""
        return self._stop_action if self._stop_observed else None

    @property
    def stop_source(self) -> str:
        """Where the stop came from, ``""`` when it ran to the end."""
        return self._stop_source if self._stop_observed else ""


class ScanControl:
    """The process-wide control plane. Use :func:`scan_control` to get it."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._scan_depth = 0
        self._scan_kind = ""
        self._workspace_dir: str | None = None
        self._interactive: bool | None = None
        self._phase_id = ""
        self._domain = ""
        self._steps: list[StepScope] = []
        self._pending: ControlRequest | None = None
        self._abort: ControlRequest | None = None
        self._abort_recorded = False
        self._phase_skip = ""
        self._next_poll = 0.0
        self._gap_recorder: Callable[[OperatorStop], None] | None = None
        self._event_emitter: Callable[[dict[str, Any]], None] | None = None
        self._last_scan_aborted = False
        self._signal_count = 0
        # (domain, phase_id) the operator cut short in this scan. Keyed by
        # domain too: the pipeline re-enters the same phase for every domain of
        # a multi-domain scan, and a stop in one is not a stop in the next.
        self._stopped_phases: set[tuple[str, str]] = set()

    # ------------------------------------------------------------------
    # Wiring (installed once by the engine; tests use their own instance)
    # ------------------------------------------------------------------
    def set_gap_recorder(self, recorder: Callable[[OperatorStop], None] | None) -> None:
        """Install the callable that persists a stop as a coverage gap."""
        self._gap_recorder = recorder

    def set_event_emitter(
        self, emitter: Callable[[dict[str, Any]], None] | None
    ) -> None:
        """Install the callable that publishes the ``scan_control`` state event."""
        self._event_emitter = emitter

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------
    def active(self) -> bool:
        """Whether a scan or a step scope is open (Ctrl+C belongs to us)."""
        with self._lock:
            return self._scan_depth > 0 or bool(self._steps)

    def in_scan(self) -> bool:
        """Whether a scan scope is open."""
        with self._lock:
            return self._scan_depth > 0

    def interactive(self) -> bool:
        """Whether the running scan has an operator at a terminal."""
        with self._lock:
            known = self._interactive
        if known is not None:
            return known
        try:
            from adscan_core.interaction import is_non_interactive  # noqa: PLC0415

            return not is_non_interactive()
        except Exception:  # noqa: BLE001 - unknown reads as unattended (safer)
            return False

    def current_step(self) -> StepScope | None:
        """The innermost running step, ``None`` between steps."""
        with self._lock:
            return self._steps[-1] if self._steps else None

    @property
    def phase_id(self) -> str:
        """Canonical id of the phase the scan is in (``""`` outside one)."""
        return self._phase_id

    @property
    def domain(self) -> str:
        """Domain the scan is working on (``""`` when unknown)."""
        return self._domain

    def abort_requested(self) -> bool:
        """Whether an ``abort_scan`` is pending."""
        return self._abort is not None

    def stop_pending(self) -> bool:
        """Whether any stop (step, phase or scan) is waiting to be honoured."""
        with self._lock:
            return self._abort is not None or self._pending is not None or bool(
                self._phase_skip
            )

    @property
    def last_scan_aborted(self) -> bool:
        """Whether the most recent scan scope ended on an abort."""
        return self._last_scan_aborted

    def phase_was_stopped(self, phase_id: str, *, domain: str | None = None) -> bool:
        """Whether the operator cut ``phase_id`` short for ``domain`` in this scan.

        ``domain`` defaults to the domain the scan is working on. A phase cut
        short must not be checkpointed as complete (a resume offers it again)
        and is recorded as incomplete by the gap recorder.
        """
        key = (_domain_key(self._domain if domain is None else domain), str(phase_id))
        with self._lock:
            return key in self._stopped_phases or self.phase_skip_active(phase_id)

    def phase_skip_active(self, phase_id: str | None = None) -> bool:
        """Whether the rest of ``phase_id`` (default: the current phase) is skipped."""
        target = self._phase_id if phase_id is None else str(phase_id)
        return bool(self._phase_skip) and self._phase_skip == target

    # ------------------------------------------------------------------
    # Requests
    # ------------------------------------------------------------------
    def request(self, request: ControlRequest) -> bool:
        """Register a request. Returns whether it was accepted.

        ``continue`` is accepted and changes nothing. A ``skip_step`` with no
        long step running, or aimed at a step that already finished, is dropped
        (stale or not applicable). A ``skip_phase`` outside a phase is dropped.
        An abort always wins and is never dropped.
        """
        action = request.action
        if action == ControlAction.CONTINUE:
            return True
        with self._lock:
            if action == ControlAction.ABORT_SCAN:
                if self._abort is None:
                    self._abort = request
                return True
            step = self._steps[-1] if self._steps else None
            if action == ControlAction.SKIP_STEP:
                if step is None or not step.long:
                    return False
                if request.target_step and request.target_step != step.step_id:
                    return False
                self._pending = ControlRequest(
                    action=action,
                    source=request.source,
                    target_step=step.step_id,
                    target_phase=step.phase_id,
                    request_id=request.request_id,
                    created_at=request.created_at,
                )
                return True
            if action == ControlAction.SKIP_PHASE:
                phase = self._phase_id
                if not phase:
                    return False
                if request.target_phase and request.target_phase != phase:
                    return False
                self._phase_skip = phase
                self._pending = ControlRequest(
                    action=action,
                    source=request.source,
                    target_step=step.step_id if step is not None else "",
                    target_phase=phase,
                    request_id=request.request_id,
                    created_at=request.created_at,
                )
                return True
        return False

    def poll(self, *, force: bool = False) -> None:
        """Read the platform control file (throttled to once a second)."""
        workspace_dir = self._workspace_dir
        if not workspace_dir:
            return
        now = time.monotonic()
        if not force and now < self._next_poll:
            return
        self._next_poll = now + CONTROL_FILE_POLL_INTERVAL
        incoming = consume_control_request(workspace_dir)
        if incoming is None:
            return
        accepted = self.request(
            ControlRequest(
                action=incoming.action,
                source=incoming.source or SOURCE_PLATFORM,
                target_step=incoming.target_step,
                target_phase=incoming.target_phase,
                request_id=incoming.request_id,
                created_at=incoming.created_at,
            )
        )
        _debug(
            f"scan-control: platform request {incoming.action.value} "
            f"step={incoming.target_step or '-'} phase={incoming.target_phase or '-'} "
            f"accepted={accepted}"
        )

    def _stop_verdict_for(self, step: StepScope) -> tuple[ControlAction, str] | None:
        self.poll()
        with self._lock:
            if self._abort is not None:
                return ControlAction.ABORT_SCAN, self._abort.source
            pending = self._pending
            if pending is None:
                return None
            if pending.action == ControlAction.SKIP_PHASE:
                if step.phase_id and step.phase_id == pending.target_phase:
                    return ControlAction.SKIP_PHASE, pending.source
                return None
            if pending.action == ControlAction.SKIP_STEP:
                if pending.target_step == step.step_id and step.long:
                    return ControlAction.SKIP_STEP, pending.source
            return None

    def should_stop(self) -> bool:
        """Module-level check for code that does not hold its step scope."""
        step = self.current_step()
        if step is None:
            self.poll()
            return self._abort is not None
        return step.should_stop()

    def checkpoint(self) -> None:
        """A safe point between units of work: raise when an abort is pending."""
        self.poll()
        if self._abort is not None:
            raise ScanAbortRequested(self._abort)

    # ------------------------------------------------------------------
    # Scopes
    # ------------------------------------------------------------------
    @contextlib.contextmanager
    def scan(
        self,
        *,
        kind: str,
        workspace_dir: str | None = None,
        interactive: bool | None = None,
        domain: str = "",
    ) -> Iterator["ScanControl"]:
        """Open a scan scope. Swallows :class:`ScanAbortRequested` at the end.

        Nested scans (``start_auth`` handing over to ``start_unauth``) share the
        outermost scope: only the outermost resets state and catches the abort.
        Read :attr:`last_scan_aborted` afterwards to finish the run honestly.
        """
        with self._lock:
            outermost = self._scan_depth == 0
            self._scan_depth += 1
            if outermost:
                self._reset_requests()
                self._scan_kind = str(kind or "")
                self._workspace_dir = str(workspace_dir) if workspace_dir else None
                self._interactive = interactive
                self._phase_id = ""
                self._domain = str(domain or "")
                self._last_scan_aborted = False
                self._next_poll = 0.0
                # A request left over from an earlier run in this workspace is
                # not this scan's: drop it before the first poll.
                if self._workspace_dir:
                    consume_control_request(self._workspace_dir)
        aborted = False
        try:
            yield self
        except ScanAbortRequested as exc:
            if not outermost:
                raise
            aborted = True
            self._record_scan_abort(exc.request)
        finally:
            with self._lock:
                self._scan_depth = max(0, self._scan_depth - 1)
                if outermost:
                    if self._abort is not None:
                        aborted = True
                    self._last_scan_aborted = aborted
                    self._reset_requests()
                    self._workspace_dir = None
                    self._interactive = None
                    self._phase_id = ""
                    self._steps.clear()
            if outermost:
                self._emit({"state": "idle"})

    def enter_phase(self, phase_id: str, *, domain: str | None = None) -> None:
        """Mark the start of a phase. Raises when an abort is pending.

        A pending ``skip_phase`` ends here: it named the phase in progress when
        it was requested, and a new phase entry (the next phase, or the same
        phase for the next domain of a multi-domain scan) is not that phase.
        """
        self.checkpoint()
        with self._lock:
            self._phase_id = str(phase_id or "")
            if domain is not None:
                self._domain = str(domain or "")
            self._phase_skip = ""
            if (
                self._pending is not None
                and self._pending.action == ControlAction.SKIP_PHASE
            ):
                self._pending = None
        self._emit_state()

    @contextlib.contextmanager
    def step(
        self,
        step_id: str,
        *,
        label: str,
        long: bool = False,
        unit: str = "",
        total: int | None = None,
        domain: str | None = None,
        record_gap: bool = True,
    ) -> Iterator[StepScope]:
        """Run one step. Records its stop as a gap and honours an abort at exit."""
        self.checkpoint()
        with self._lock:
            scope = StepScope(
                step_id=str(step_id),
                label=str(label or step_id),
                long=bool(long),
                unit=str(unit or ""),
                phase_id=self._phase_id,
                domain=self._domain if domain is None else str(domain or ""),
                _control=self,
                total=None if total is None else max(0, int(total)),
                record_gap=bool(record_gap),
            )
            self._steps.append(scope)
        self._emit_state()
        body_raised = True
        try:
            yield scope
            body_raised = False
        finally:
            with self._lock:
                if scope in self._steps:
                    self._steps.remove(scope)
                if (
                    self._pending is not None
                    and self._pending.action == ControlAction.SKIP_STEP
                    and self._pending.target_step == scope.step_id
                ):
                    # Honoured (or the step ended first): either way it is spent.
                    self._pending = None
            if scope.stopped and scope.record_gap:
                self._record_step_stop(scope)
            with self._lock:
                # A step outside any scan (a REPL command) is its own outermost
                # scope: once it closes, nothing it was asked must outlive it.
                standalone_done = self._scan_depth == 0 and not self._steps
                pending_abort = self._abort
                if standalone_done:
                    self._reset_requests()
            self._emit_state()
        if not body_raised:
            if not standalone_done:
                self.checkpoint()
            elif pending_abort is not None:
                raise ScanAbortRequested(pending_abort)

    def run_step(
        self,
        step_id: str,
        fn: Callable[[], Any],
        *,
        label: str,
        long: bool = False,
    ) -> bool:
        """Run ``fn`` as one step, or skip it when its phase is being skipped.

        Returns whether ``fn`` ran. Raises :class:`ScanAbortRequested` before or
        after it when an abort is pending.
        """
        self.checkpoint()
        if self.phase_skip_active():
            _debug(f"scan-control: step {step_id} skipped (phase {self._phase_id} skipped)")
            return False
        with self.step(step_id, label=label, long=long):
            fn()
        return True

    # ------------------------------------------------------------------
    # Menu support (rendering lives in interrupts.py)
    # ------------------------------------------------------------------
    def menu_choices(self) -> list[tuple[ControlAction, str]]:
        """The operator menu for the current position, in display order."""
        step = self.current_step()
        choices: list[tuple[ControlAction, str]] = []
        if step is not None and step.long and not step.stopped:
            choices.append((ControlAction.SKIP_STEP, "Stop this step and keep what it found"))
        if self._phase_id and self.in_scan() and not self.phase_skip_active():
            title = _phase_title(self._phase_id)
            suffix = f" ({title})" if title else ""
            choices.append(
                (ControlAction.SKIP_PHASE, f"Skip the rest of this phase{suffix}")
            )
        if self.in_scan():
            choices.append((ControlAction.ABORT_SCAN, "Stop the scan and return to the prompt"))
        else:
            choices.append(
                (ControlAction.ABORT_SCAN, "Stop this command and return to the prompt")
            )
        choices.append((ControlAction.CONTINUE, "Keep going"))
        return choices

    def position_line(self) -> str:
        """One line naming where the scan is, for the menu header."""
        step = self.current_step()
        parts: list[str] = []
        if step is not None:
            label = step.label
            if step.total and step.done is not None:
                unit = f" {step.unit}" if step.unit else ""
                label = f"{label} ({step.done} of {step.total}{unit})"
            parts.append(label)
        elif self._phase_id:
            parts.append(_phase_title(self._phase_id) or self._phase_id)
        if self.stop_pending():
            parts.append("a stop is already pending")
        return " · ".join(parts)

    def note_signal(self) -> int:
        """Count one SIGINT seen in this scan and return the running count."""
        with self._lock:
            self._signal_count += 1
            return self._signal_count

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _reset_requests(self) -> None:
        self._pending = None
        self._abort = None
        self._abort_recorded = False
        self._phase_skip = ""
        self._signal_count = 0
        self._stopped_phases = set()

    def _record_step_stop(self, scope: StepScope) -> None:
        action = scope.stop_action
        if action is None:
            return
        if action == ControlAction.ABORT_SCAN:
            self._abort_recorded = True
        self._record(
            OperatorStop(
                action=action.value,
                source=scope.stop_source,
                domain=scope.domain,
                phase_id=scope.phase_id,
                step_id=scope.step_id,
                label=scope.label,
                examined=scope.done,
                total=scope.total,
                unit=scope.unit,
            )
        )

    def _record_scan_abort(self, request: ControlRequest | None) -> None:
        if self._abort_recorded:
            return
        self._abort_recorded = True
        self._record(
            OperatorStop(
                action=ControlAction.ABORT_SCAN.value,
                source=(request.source if request is not None else SOURCE_OPERATOR_MENU),
                domain=self._domain,
                phase_id=self._phase_id,
            )
        )

    def _record(self, stop: OperatorStop) -> None:
        if stop.phase_id:
            with self._lock:
                self._stopped_phases.add((_domain_key(stop.domain), stop.phase_id))
        recorder = self._gap_recorder
        if recorder is None:
            return
        try:
            recorder(stop)
        except Exception as exc:  # noqa: BLE001 - recording never breaks the scan
            _debug(f"scan-control: gap recorder failed ({type(exc).__name__}: {exc})")

    def state_document(self) -> dict[str, Any]:
        """The ``scan_control`` state the platform renders its controls from."""
        step = self.current_step()
        return {
            "state": "running" if self.active() else "idle",
            "phase": self._phase_id or None,
            "step": step.step_id if step is not None else None,
            "step_label": step.label if step is not None else None,
            "step_skippable": bool(step is not None and step.long and not step.stopped),
            "phase_skippable": bool(
                self._phase_id and self.in_scan() and not self.phase_skip_active()
            ),
            "stop_pending": self.stop_pending(),
            "current": step.done if step is not None else None,
            "total": step.total if step is not None else None,
        }

    def _emit_state(self) -> None:
        self._emit(self.state_document())

    def _emit(self, fields: dict[str, Any]) -> None:
        emitter = self._event_emitter
        if emitter is None:
            return
        try:
            emitter(dict(fields))
        except Exception as exc:  # noqa: BLE001 - observability never breaks the scan
            _debug(f"scan-control: event emit failed ({type(exc).__name__}: {exc})")


def _domain_key(domain: str | None) -> str:
    return str(domain or "").strip().lower()


def _phase_title(phase_id: str) -> str:
    """Operator-facing title of a phase, via the injected resolver (best-effort)."""
    resolver = _PHASE_TITLE_RESOLVER
    if resolver is None or not phase_id:
        return ""
    try:
        return str(resolver(phase_id) or "")
    except Exception:  # noqa: BLE001 - a title is decoration, never a failure
        return ""


_PHASE_TITLE_RESOLVER: Callable[[str], str] | None = None


def set_phase_title_resolver(resolver: Callable[[str], str] | None) -> None:
    """Install the phase-id to title lookup (the engine owns the phase registry)."""
    global _PHASE_TITLE_RESOLVER
    _PHASE_TITLE_RESOLVER = resolver


def _debug(message: str) -> None:
    try:
        from adscan_core.rich_output import print_info_debug  # noqa: PLC0415

        print_info_debug(message)
    except Exception:  # noqa: BLE001
        pass


_CONTROL = ScanControl()


def scan_control() -> ScanControl:
    """Return the process-wide control plane."""
    return _CONTROL


__all__ = [
    "CONTROL_FILE_POLL_INTERVAL",
    "OperatorStop",
    "ScanAbortRequested",
    "ScanControl",
    "StepScope",
    "scan_control",
    "set_phase_title_resolver",
]
