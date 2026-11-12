"""One recorded run of an attack path: plan, step lifecycle, honest result.

``execute_selected_attack_path`` opens one :class:`AttackPathExecutionRun` per
call and installs it on the shell. The run observes three seams that every step
branch already passes through, so a branch never has to remember to report:

* :meth:`AttackPathExecutionRun.begin_step`, called once per executable step
  right before the step's runtime context is set (the loop's per-step seam);
* :func:`notify_edge_status`, called by ``update_edge_status_by_labels`` (every
  branch persists its outcome there, directly or through the active-step and
  blocked-step helpers);
* :func:`notify_legacy_event`, called by the legacy execution-event recorder,
  which carries the free-text reason a branch attached.

:meth:`AttackPathExecutionRun.finish` runs in the caller's ``finally`` and emits
exactly one ``run_finished`` per run, on every exit path.

Each stage is persisted as a v2 technical event (vocabulary in
:mod:`adscan_core.reporting.attack_path_execution_events`) that the web relays,
and is mirrored on the terminal through the shared output helpers. The terminal
output is plain Rich, not a ``LiveSession``: technique output and step-gate
prompts interleave with the run, and an alt-screen would hide both.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from rich.markup import escape as rich_markup_escape
from rich.padding import Padding
from rich.table import Table
from rich.text import Text

from adscan_core.reporting.attack_path_execution_events import (
    DECISION_EXECUTION_MODE,
    DECISION_CHANGE_GATE,
    DECISION_STEP_GATE,
    EXECUTION_EVENT_SCHEMA,
    KIND_CONTEXTUAL,
    KIND_EXECUTABLE,
    KIND_POLICY_BLOCKED,
    MODE_CONTINUOUS,
    MODE_STEP,
    OUTCOME_ATTEMPTED,
    OUTCOME_CLOSED_BY_CONFIGURATION,
    OUTCOME_NOT_NEEDED,
    OUTCOME_NOT_REACHED,
    OUTCOME_NOT_VULNERABLE,
    OUTCOME_SAFETY_BLOCKED,
    OUTCOME_SKIPPED,
    OUTCOME_SUCCESS,
    RESULT_COMPLETED,
    RESULT_NOT_STARTED,
    RESULT_PARTIAL,
    STAGE_RUN_FINISHED,
    STAGE_RUN_STARTED,
    STAGE_STEP_FINISHED,
    STAGE_STEP_STARTED,
    declined_explanation,
    declined_reason,
    not_needed_explanation,
    not_needed_reason,
    outcome_from_status,
    summarize_run_result,
)
from adscan_core.reporting.attack_step_reason_codes import (
    ReasonCode,
    normalize_reason_code,
)
from adscan_core.reporting.execution_failure_explanations import (
    failure_view,
    is_attempted_step_status,
    resolve_step_failure_reason,
)
from adscan_core.path_offer import display_label
from adscan_core.sensitive import strip_sensitive_markers
from adscan_core.theme import (
    ADSCAN_PRIMARY,
    COLOR_AMBER,
    COLOR_MUTED,
    COLOR_SAGE,
)
from adscan_internal import print_exception, print_info_debug, telemetry
from adscan_internal.rich_output import mark_sensitive, print_panel

_ACTIVE_RUN_ATTR = "_attack_path_execution_run"

#: Operator-facing label per outcome. Shared by the CLI; the web mirrors the
#: tokens, and its labels live with its renderer.
OUTCOME_LABELS: dict[str, str] = {
    OUTCOME_SUCCESS: "Succeeded",
    OUTCOME_ATTEMPTED: "Did not complete",
    OUTCOME_SAFETY_BLOCKED: "Not executed for safety",
    OUTCOME_CLOSED_BY_CONFIGURATION: "Closed by configuration",
    OUTCOME_NOT_VULNERABLE: "Not exploitable here",
    OUTCOME_SKIPPED: "Not run",
    OUTCOME_NOT_NEEDED: "Not needed",
    OUTCOME_NOT_REACHED: "Not reached",
}

_OUTCOME_STYLE: dict[str, str] = {
    OUTCOME_SUCCESS: f"bold {COLOR_SAGE}",
    OUTCOME_ATTEMPTED: f"bold {COLOR_AMBER}",
    OUTCOME_SAFETY_BLOCKED: f"bold {COLOR_AMBER}",
    OUTCOME_CLOSED_BY_CONFIGURATION: f"bold {COLOR_SAGE}",
    OUTCOME_NOT_VULNERABLE: f"bold {COLOR_SAGE}",
    OUTCOME_SKIPPED: COLOR_MUTED,
    OUTCOME_NOT_NEEDED: COLOR_MUTED,
    OUTCOME_NOT_REACHED: COLOR_MUTED,
}

_OUTCOME_GLYPH: dict[str, str] = {
    OUTCOME_SUCCESS: "✓",
    OUTCOME_ATTEMPTED: "✗",
    OUTCOME_SAFETY_BLOCKED: "■",
    OUTCOME_CLOSED_BY_CONFIGURATION: "◆",
    OUTCOME_NOT_VULNERABLE: "◆",
    OUTCOME_SKIPPED: "–",
    OUTCOME_NOT_NEEDED: "○",
    OUTCOME_NOT_REACHED: "·",
}

_UNRECORDED_ENDING = {
    "code": "",
    "reason_code": "",
    "headline": "The step stopped without a recorded result.",
    "detail": "The technical log for this run holds the detail of what happened.",
    "next_step": "",
}


# ── Plan ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PlanStep:
    """One step of a path as the operator will see it."""

    index: int
    relation: str
    from_label: str
    to_label: str
    kind: str
    technique: str
    relation_label: str
    mitre_id: str
    mitre_name: str
    summary: str
    from_display: str = ""
    to_display: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON shape carried in ``run_started``."""
        return {
            "index": self.index,
            "relation": self.relation,
            "from": self.from_label,
            "to": self.to_label,
            "from_display": self.from_display or self.from_label,
            "to_display": self.to_display or self.to_label,
            "kind": self.kind,
            "technique": self.technique,
            "relation_label": self.relation_label,
            "mitre_id": self.mitre_id,
            "mitre_name": self.mitre_name,
            "summary": self.summary,
        }


def _step_kind(relation: str) -> str:
    from adscan_internal.services.attack_step_support_registry import (  # noqa: PLC0415
        CONTEXT_ONLY_RELATIONS,
        POLICY_BLOCKED_RELATIONS,
    )

    key = relation.strip().lower()
    if key in CONTEXT_ONLY_RELATIONS:
        return KIND_CONTEXTUAL
    if key in POLICY_BLOCKED_RELATIONS:
        return KIND_POLICY_BLOCKED
    return KIND_EXECUTABLE


def build_execution_plan(summary: dict[str, Any], domain: str | None = None) -> list[PlanStep]:
    """Build the operator-facing plan of a path from its summary.

    Every string comes from the catalog SSOTs (business relation phrase, MITRE
    fields, the short narrative rendered with the step's real labels), so a
    technique added to the catalog shows up here with no extra code.
    """

    from adscan_core.reporting.principal_display import (  # noqa: PLC0415
        format_graph_node_label,
    )
    from adscan_internal.services.attack_relation_labels import (  # noqa: PLC0415
        business_relation_phrase,
        format_relation_label,
    )
    from adscan_internal.services.attack_step_catalog import (  # noqa: PLC0415
        get_step_mitre,
        render_step_narrative,
    )

    steps = summary.get("steps") if isinstance(summary, dict) else None
    if not isinstance(steps, list):
        return []
    plan: list[PlanStep] = []
    for index, step in enumerate(steps, start=1):
        if not isinstance(step, dict):
            continue
        relation = str(step.get("action") or step.get("relation") or "").strip()
        if not relation:
            continue
        details = step.get("details") if isinstance(step.get("details"), dict) else {}
        try:
            mitre_id, mitre_name = get_step_mitre(relation)
        except Exception:  # noqa: BLE001 - catalog lookup is best-effort
            mitre_id, mitre_name = None, None
        try:
            narrative = render_step_narrative(step, short=True) or ""
        except Exception:  # noqa: BLE001
            narrative = ""
        from_label = str(details.get("from") or "").strip()
        to_label = str(details.get("to") or "").strip()
        display_to = str(details.get("display_to") or to_label).strip()
        try:
            from_display = format_graph_node_label(from_label, domain) if from_label else ""
            to_display = format_graph_node_label(display_to, domain) if display_to else ""
        except Exception:  # noqa: BLE001 - display only
            from_display, to_display = from_label, display_to
        plan.append(
            PlanStep(
                index=index,
                relation=relation,
                from_label=from_label,
                to_label=to_label,
                from_display=from_display,
                to_display=to_display,
                kind=_step_kind(relation),
                technique=business_relation_phrase(relation),
                relation_label=format_relation_label(relation),
                mitre_id=str(mitre_id or ""),
                mitre_name=str(mitre_name or ""),
                summary=narrative.strip(),
            )
        )
    return plan


@dataclass(frozen=True)
class StepOutcome:
    """One executable step's final outcome in a finished run."""

    index: int
    relation: str
    from_label: str
    to_label: str
    outcome: str
    explanation: dict[str, Any]
    executed: bool


def new_run_id() -> str:
    """Return a fresh opaque run identifier."""
    return f"run-{secrets.token_hex(8)}"


# ── Run state ────────────────────────────────────────────────────────────────


@dataclass
class _StepState:
    started_at: float | None = None
    finished: bool = False
    status: str = ""
    status_notes: dict[str, Any] = field(default_factory=dict)
    legacy_outcome: str = ""
    reasons: list[str] = field(default_factory=list)
    actor: str = ""
    target_host: str = ""
    operator_stopped: bool = False
    #: The ``OperatorDecision`` recorded when the operator stopped here (who, when).
    decision: Any = None
    passed_over: bool = False
    error: BaseException | None = None


def _operator_stop_headline(decision: Any) -> str:
    """The step's "not executed" line, in the report's vocabulary.

    Same words and same who/when as the report and the platform
    (``operator_declined_label``); a decision nobody answered reads as the
    awaiting-approval line, never as a decline.
    """
    from adscan_core.scan_policy.execution import (  # noqa: PLC0415
        REASON_AWAITING_APPROVAL,
        awaiting_approval_label,
        operator_declined_label,
    )

    reason = str(getattr(decision, "reason", "") or "")
    if reason == REASON_AWAITING_APPROVAL:
        return awaiting_approval_label(int(getattr(decision, "timeout_seconds", 0) or 0) or None)
    return operator_declined_label(
        str(getattr(decision, "declined_by", "") or ""),
        str(getattr(decision, "declined_at", "") or ""),
    )


def _dependent_on_operator_decision(notes: dict[str, Any], status: str) -> str:
    """The label of a step left unrun behind an operator decision, or ``""``.

    True only for a step that did not run and carries the decision note
    (``record_operator_decision_on_edges`` writes it on every not-yet-run step
    of the route). The gated step itself is labelled by ``operator_stopped``.
    """
    from adscan_core.scan_policy.annotate import NOTE_REASON_KEY, status_is_not_run  # noqa: PLC0415
    from adscan_core.scan_policy.execution import dependent_step_label  # noqa: PLC0415

    if not isinstance(notes, dict) or not status_is_not_run(status):
        return ""
    return dependent_step_label(str(notes.get(NOTE_REASON_KEY) or ""))


def _operator_stop_line(decision: Any) -> str:
    """The path-level line printed when the step gate stopped the route.

    From the one recorded decision: silence never reads as an operator's stop.
    """
    from adscan_core.scan_policy.execution import (  # noqa: PLC0415
        REASON_AWAITING_APPROVAL,
        REASON_OPERATOR_DECLINED,
    )

    reason = str(getattr(decision, "reason", "") or "")
    if reason == REASON_AWAITING_APPROVAL:
        return (
            "Path not continued: this step is awaiting approval, so the steps after "
            "it were not run."
        )
    if reason == REASON_OPERATOR_DECLINED:
        return "Path stopped: the operator chose not to run this step."
    return "Path not continued past this step."


def _norm_label(value: Any) -> str:
    text = str(value or "").strip().lower()
    if "@" in text:
        text = text.split("@", 1)[0]
    if "\\" in text:
        text = text.rsplit("\\", 1)[-1]
    return text.rstrip("$").strip()


class AttackPathExecutionRun:
    """Recorder for one execution of one attack path."""

    def __init__(
        self,
        shell: Any,
        *,
        domain: str,
        summary: dict[str, Any],
        run_id: str | None = None,
        mode: str = MODE_CONTINUOUS,
        emitter: Callable[[str, str, dict[str, Any]], None] | None = None,
        render: bool = True,
    ) -> None:
        self.shell = shell
        self.domain = domain
        self.summary = summary
        self.run_id = run_id or new_run_id()
        self.mode = mode if mode in {MODE_CONTINUOUS, MODE_STEP} else MODE_CONTINUOUS
        self.plan = build_execution_plan(summary, domain)
        self._by_index = {step.index: step for step in self.plan}
        self._states: dict[int, _StepState] = {}
        self._current: int | None = None
        self._emitter = emitter
        self._render = render
        self._thread = threading.get_ident()
        self._started_mono = time.monotonic()
        self._refusal: str = ""
        self._refusal_view: dict[str, str] = {}
        #: The decision recorded when the step gate stopped the route (one per run).
        self._stop_decision: Any = None
        self._finished = False
        self._outcomes: dict[int, str] = {}
        self._explanations: dict[int, dict[str, str]] = {}
        # Attempted steps no reason category explains, with the sanitized shape
        # of their cause: the measurement that drives the next mappings.
        self._unexplained: list[dict[str, Any]] = []
        # Per-run order of emission. The host wall clock can be stepped to the
        # domain controller mid-run, so timestamps are not a reliable order.
        self._seq = 0
        self._ledger_ids_at_start = self._ledger_change_ids()

    # ── identity helpers ───────────────────────────────────────────────────
    @property
    def executable_steps(self) -> list[PlanStep]:
        return [step for step in self.plan if step.kind != KIND_CONTEXTUAL]

    def _state(self, index: int) -> _StepState:
        return self._states.setdefault(index, _StepState())

    def _match_step(self, relation: str, from_label: str, to_label: str) -> int | None:
        rel = relation.strip().lower()
        src, dst = _norm_label(from_label), _norm_label(to_label)
        candidates = [step for step in self.plan if step.relation.lower() == rel]
        for step in candidates:
            if _norm_label(step.from_label) == src and _norm_label(step.to_label) == dst:
                return step.index
        if self._current is not None:
            current = self._by_index.get(self._current)
            if current is not None and current.relation.lower() == rel:
                return current.index
        if len(candidates) == 1:
            return candidates[0].index
        return None

    # ── emission ───────────────────────────────────────────────────────────
    def _emit(self, stage: str, message: str, execution: dict[str, Any]) -> None:
        self._seq += 1
        execution = {**execution, "seq": self._seq}
        details = {
            "source": "attack_path_execution",
            "event_stage": stage,
            "schema": EXECUTION_EVENT_SCHEMA,
            "run_id": self.run_id,
            "path_id": _path_event_id(self.summary),
            "path_source": str(self.summary.get("source") or "").strip(),
            "path_target": str(self.summary.get("target") or "").strip(),
            "execution": execution,
        }
        if self._emitter is not None:
            self._emitter(stage, message, details)
            return
        try:
            from adscan_internal.reporting_compat import (  # noqa: PLC0415
                load_optional_report_service_attr,
            )

            record_technical_event = load_optional_report_service_attr(
                "record_technical_event",
                action="Technical event sync",
                debug_printer=print_info_debug,
                prefix="[attack_paths]",
                module_name="adscan_internal.pro.services.report_service",
            )
            if callable(record_technical_event):
                record_technical_event(
                    self.shell,
                    self.domain,
                    event_type="attack_path_execution",
                    message=message,
                    details=details,
                )
        except Exception as exc:  # noqa: BLE001 - never alter the execution flow
            telemetry.capture_exception(exc)
            print_info_debug(f"attack_paths run event persistence failed: {exc}")

    # ── lifecycle ──────────────────────────────────────────────────────────
    def start(self) -> None:
        """Emit ``run_started`` with the plan and print it."""
        executable_total = len(self.executable_steps)
        self._emit(
            STAGE_RUN_STARTED,
            "Attack path run started.",
            {
                "mode": self.mode,
                "domain": self.domain,
                "source": str(self.summary.get("source") or ""),
                "target": str(self.summary.get("target") or ""),
                "source_display": display_label(
                    str(self.summary.get("source") or ""), self.domain
                ),
                "target_display": display_label(
                    str(self.summary.get("target") or ""), self.domain
                ),
                "executable_total": executable_total,
                "steps": [step.to_dict() for step in self.plan],
            },
        )
        if self._render:
            _render_plan(self)

    def stop_line(self) -> str:
        """The path-level line for a route the step gate stopped, from its decision."""
        return _operator_stop_line(self._stop_decision)

    def refuse(self, reason: str, *, explanation: dict[str, str] | None = None) -> None:
        """Record why the run is not going to execute any step.

        ``explanation`` (the run's explanation shape) replaces the one derived
        from ``reason`` when the caller already has the operator wording, as a
        scan-policy refusal does.
        """
        self._refusal = strip_sensitive_markers(str(reason or "")).strip()
        if explanation:
            self._refusal_view = {
                key: strip_sensitive_markers(str(value or "")) for key, value in explanation.items()
            }

    def begin_step(self, index: int) -> bool:
        """Mark ``index`` as starting. Returns False when the operator stops.

        Finalizes every earlier step first, so in step mode the operator sees
        the previous outcome before deciding on the next step.
        """
        if self._finished or threading.get_ident() != self._thread:
            return True
        self._finalize_before(index)
        step = self._by_index.get(index)
        if step is None:
            return True
        if self.mode == MODE_STEP and not self._confirm_step(step):
            decision = self._record_step_gate_refusal(step)
            state = self._state(index)
            state.operator_stopped = True
            state.decision = decision
            self._stop_decision = decision
            state.started_at = time.monotonic()
            self._finalize(index)
            return False
        state = self._state(index)
        state.started_at = time.monotonic()
        self._current = index
        position = self._position(index)
        self._emit(
            STAGE_STEP_STARTED,
            f"{step.technique} started (step {position}).",
            {
                "step_index": index,
                "position": position,
                "executable_total": len(self.executable_steps),
            },
        )
        if self._render:
            _render_step_header(self, step, position)
        return True

    def observe_status(
        self,
        *,
        relation: str,
        from_label: str,
        to_label: str,
        status: str,
        notes: dict[str, Any] | None,
    ) -> None:
        """Record a persisted step status (latest write wins)."""
        if self._finished or threading.get_ident() != self._thread:
            return
        index = self._match_step(relation, from_label, to_label)
        if index is None:
            return
        state = self._state(index)
        if state.finished:
            return
        state.status = str(status or "").strip().lower()
        state.status_notes = {
            key: strip_sensitive_markers(value) if isinstance(value, str) else value
            for key, value in (notes or {}).items()
        }

    def observe_legacy_event(
        self,
        *,
        stage: str,
        step_index: int | None,
        action: str | None,
        from_label: str | None,
        to_label: str | None,
        reason: str | None,
        actor: str | None,
        target_host: str | None,
    ) -> None:
        """Record the reason / actor a branch attached to a legacy event."""
        if self._finished or threading.get_ident() != self._thread:
            return
        index: int | None = None
        if action:
            index = self._match_step(action, from_label or "", to_label or "")
        if index is None and isinstance(step_index, int) and step_index in self._by_index:
            index = step_index
        if index is None:
            index = self._current
        if index is None:
            if stage in {"path_blocked", "path_unavailable"} and reason:
                self._refusal = self._refusal or strip_sensitive_markers(str(reason))
            return
        state = self._state(index)
        if state.finished:
            return
        if reason:
            state.reasons.append(strip_sensitive_markers(str(reason)))
        if actor:
            state.actor = strip_sensitive_markers(str(actor))
        if target_host:
            state.target_host = strip_sensitive_markers(str(target_host))
        legacy = {
            "step_succeeded": OUTCOME_SUCCESS,
            "step_failed": OUTCOME_ATTEMPTED,
            "path_aborted": OUTCOME_ATTEMPTED,
            "step_blocked": OUTCOME_SKIPPED,
        }.get(stage)
        if legacy:
            state.legacy_outcome = legacy

    def record_error(self, exc: BaseException) -> None:
        """Attach an unhandled exception to the step that was running."""
        if self._current is not None:
            self._state(self._current).error = exc

    def finish(self) -> None:
        """Finalize every step and emit ``run_finished`` (idempotent)."""
        if self._finished:
            return
        self._finalize_before(None)
        executable = self.executable_steps
        for step in executable:
            state = self._states.get(step.index)
            if state is not None and state.finished:
                continue
            if outcome_from_status(_summary_step_status(self.summary, step.index)) == OUTCOME_SUCCESS:
                outcome, explanation = OUTCOME_SUCCESS, {
                    "code": "",
                    "reason_code": "",
                    "headline": "Already proven earlier; not repeated in this run.",
                    "detail": "",
                    "next_step": "",
                }
            else:
                outcome, explanation = OUTCOME_NOT_REACHED, {}
            self._explanations[step.index] = explanation
            self._emit_step_finished(
                step, outcome, explanation, duration_ms=None, actor="", target_host=""
            )
            self._state(step.index).finished = True
        self._finished = True
        outcomes = [self._outcomes.get(step.index, OUTCOME_NOT_REACHED) for step in executable]
        result = summarize_run_result(outcomes, executable_total=len(executable))
        succeeded = sum(1 for outcome in outcomes if outcome == OUTCOME_SUCCESS)
        not_needed = sum(1 for outcome in outcomes if outcome == OUTCOME_NOT_NEEDED)
        first_break = next(
            (
                step
                for step in executable
                if self._outcomes.get(step.index)
                not in {OUTCOME_SUCCESS, OUTCOME_NOT_NEEDED, OUTCOME_NOT_REACHED}
            ),
            None,
        )
        breaking: dict[str, Any] | None = None
        if first_break is not None:
            breaking = {
                "step_index": first_break.index,
                "technique": first_break.technique,
                "outcome": self._outcomes.get(first_break.index, ""),
                "explanation": self._explanations.get(first_break.index, {}),
            }
        elif result == RESULT_NOT_STARTED and self._refusal:
            breaking = {
                "step_index": None,
                "technique": "",
                "outcome": OUTCOME_SKIPPED,
                "explanation": self._refusal_view or _refusal_explanation(self._refusal),
            }
        changes = self._run_changes()
        duration_ms = int((time.monotonic() - self._started_mono) * 1000)
        domain_compromised = self._domain_compromised()
        summary = {
            "result": result,
            "executable_total": len(executable),
            "succeeded": succeeded,
            "first_break": breaking,
            "changes": changes,
            "duration_ms": duration_ms,
            "domain_compromised": domain_compromised,
            "not_needed": not_needed,
            "headline": _result_headline(
                result,
                succeeded,
                len(executable),
                domain_compromised,
                breaking,
                not_needed=not_needed,
            ),
            # Internal measurement (sanitized, never rendered to a client): the
            # attempted steps whose cause no reason category explains yet.
            "unexplained_attempted": [dict(item) for item in self._unexplained],
        }
        self._emit(STAGE_RUN_FINISHED, summary["headline"], summary)
        if self._render:
            _render_summary(self, summary)
        _notify_run_finished(self, summary)

    def step_outcomes(self) -> list[StepOutcome]:
        """Each executable step's final outcome (valid once :meth:`finish` ran).

        ``executed`` is True only for a step this run started; a step reported
        as succeeded from an earlier proof was not re-executed here.
        """
        out: list[StepOutcome] = []
        for step in self.executable_steps:
            state = self._states.get(step.index)
            out.append(
                StepOutcome(
                    index=step.index,
                    relation=step.relation,
                    from_label=step.from_label,
                    to_label=step.to_label,
                    outcome=self._outcomes.get(step.index, OUTCOME_NOT_REACHED),
                    explanation=dict(self._explanations.get(step.index, {})),
                    executed=bool(state is not None and state.started_at is not None),
                )
            )
        return out

    # ── internals ──────────────────────────────────────────────────────────
    def _position(self, index: int) -> int:
        for position, step in enumerate(self.executable_steps, start=1):
            if step.index == index:
                return position
        return 0

    def _finalize_before(self, index: int | None) -> None:
        if index is not None:
            # Executable steps the loop passed over without starting (a resumed
            # run, a previously processed step) are settled here, in order, so
            # they never read as "not reached" behind a later step.
            for step in self.executable_steps:
                if step.index < index and step.index not in self._states:
                    self._state(step.index).passed_over = True
        pending = sorted(
            idx
            for idx, state in self._states.items()
            if not state.finished
            and (
                state.started_at is not None
                or state.status
                or state.legacy_outcome
                or state.passed_over
            )
            and (index is None or idx < index)
        )
        for idx in pending:
            self._finalize(idx)
        if index is None or (self._current is not None and self._current < index):
            self._current = None

    def _finalize(self, index: int) -> None:
        step = self._by_index.get(index)
        state = self._state(index)
        if step is None or state.finished:
            return
        state.finished = True
        notes = state.status_notes
        explanation: dict[str, str] = {}
        if state.operator_stopped:
            outcome = OUTCOME_SKIPPED
            explanation = {
                "code": "",
                "reason_code": "",
                "headline": _operator_stop_headline(state.decision),
                "detail": "",
                "next_step": "",
            }
        elif _dependent_on_operator_decision(notes, state.status):
            # A later step of the route the step gate stopped: the decision
            # note was written on it from the SAME recorded decision. It waited
            # on that step and never ran, so it reads "depends on a step awaiting
            # approval" (or declined), never "did not complete".
            outcome = OUTCOME_SKIPPED
            explanation = {
                "code": "",
                "reason_code": "",
                "headline": _dependent_on_operator_decision(notes, state.status),
                "detail": "",
                "next_step": "",
            }
        elif _excluded_by_scan_policy(notes, state.reasons):
            # The scan policy kept the step off: a choice, not a failure.
            outcome = OUTCOME_SKIPPED
            explanation = _scan_policy_explanation(self.shell, step, notes)
        elif _declined_before_acting(state):
            # Declined before any write because the change could not be shown
            # to be undoable (``reversal_not_proven`` / ``revert_not_permitted``):
            # nothing was attempted, so it is never an unexplained attempt.
            outcome = OUTCOME_SKIPPED
            explanation = declined_explanation(declined_reason(notes, state.reasons))
        elif state.error is not None:
            outcome = OUTCOME_ATTEMPTED
            explanation = failure_view(state.error, *state.reasons)
            if not explanation.get("headline"):
                explanation = dict(_UNRECORDED_ENDING)
        elif not_needed_reason(notes) and outcome_from_status(state.status, notes) == OUTCOME_NOT_NEEDED:
            # Deliberately not run because its result was already in hand: a
            # choice with its own reason, never "the step stopped".
            outcome = OUTCOME_NOT_NEEDED
            explanation = not_needed_explanation(not_needed_reason(notes))
        else:
            outcome = outcome_from_status(state.status, notes) or state.legacy_outcome
            if not outcome:
                prior = _summary_step_status(self.summary, index)
                if outcome_from_status(prior) == OUTCOME_SUCCESS:
                    outcome = OUTCOME_SUCCESS
                    explanation = {
                        "code": "",
                        "reason_code": "",
                        "headline": "Already proven earlier; reused in this run.",
                        "detail": "",
                        "next_step": "",
                    }
                elif state.passed_over:
                    outcome = OUTCOME_SKIPPED
                    explanation = {
                        "code": "",
                        "reason_code": "",
                        "headline": "Not run in this execution.",
                        "detail": "The run started at a later step.",
                        "next_step": "",
                    }
                else:
                    outcome = OUTCOME_ATTEMPTED
            if outcome != OUTCOME_SUCCESS and not explanation:
                explanation = failure_view(
                    notes,
                    *state.reasons,
                    reason_code=notes.get("reason_code"),
                )
                if not explanation.get("headline"):
                    readable = _readable_reason(notes, state.reasons)
                    explanation = (
                        {
                            "code": "",
                            "reason_code": "",
                            "headline": readable,
                            "detail": "",
                            "next_step": "",
                        }
                        if readable
                        else dict(_UNRECORDED_ENDING)
                    )
        actor = state.actor or acting_principal_from_notes(notes)
        target_host = state.target_host or str(notes.get("target_host") or "")
        cause_signature = ""
        if outcome == OUTCOME_ATTEMPTED:
            explanation, cause_signature = self._classify_attempted(
                step, state, explanation, actor=actor, target_host=target_host
            )
        self._outcomes[index] = outcome
        self._explanations[index] = explanation
        duration_ms = (
            int((time.monotonic() - state.started_at) * 1000)
            if state.started_at is not None
            else None
        )
        self._emit_step_finished(
            step,
            outcome,
            explanation,
            duration_ms=duration_ms,
            actor=actor,
            target_host=target_host,
            cause_signature=cause_signature,
        )
        if self._render and outcome != OUTCOME_NOT_REACHED:
            _render_step_outcome(step, outcome, explanation, duration_ms)
        if self._current == index:
            self._current = None

    def _emit_step_finished(
        self,
        step: PlanStep,
        outcome: str,
        explanation: dict[str, str],
        *,
        duration_ms: int | None,
        actor: str,
        target_host: str,
        cause_signature: str = "",
    ) -> None:
        self._outcomes[step.index] = outcome
        payload: dict[str, Any] = {
            "step_index": step.index,
            "position": self._position(step.index),
            "outcome": outcome,
            "explanation": explanation or None,
            "duration_ms": duration_ms,
            "actor": actor or None,
            "target_host": target_host or None,
        }
        if cause_signature:
            # Internal measurement only (sanitized): the raw shape of a cause
            # no reason category explains yet. Never rendered to a client.
            payload["unexplained_cause"] = cause_signature
        self._emit(
            STAGE_STEP_FINISHED,
            f"{step.technique} ({OUTCOME_LABELS.get(outcome, outcome).lower()}).",
            payload,
        )

    def _classify_attempted(
        self,
        step: PlanStep,
        state: "_StepState",
        explanation: dict[str, str],
        *,
        actor: str,
        target_host: str,
    ) -> tuple[dict[str, str], str]:
        """Give an attempted step its reason category, and measure the unexplained.

        Every attempted step leaves here with a valid ``reason_code`` on its
        explanation (the run view, the reports and the web read the same
        category). A cause the resolver explains only through what this run
        observed (an exception, a reason a branch attached to an event) is
        written back to the edge, so the deliverable states it too. A cause no
        category explains is counted: in the run record, in telemetry and in
        the debug log, as a sanitized signature.
        """
        notes = state.status_notes
        status = state.status if is_attempted_step_status(state.status) else "attempted"
        reason = resolve_step_failure_reason(
            status,
            notes,
            relation=step.relation,
            sources=[value for value in (state.error, *state.reasons) if value],
            known_identifiers=(
                step.from_label,
                step.to_label,
                actor,
                target_host,
                notes.get("username"),
                notes.get("target"),
                notes.get("user"),
            ),
        )
        if reason is None:  # pragma: no cover - status is attempted by construction
            return explanation, ""
        view = dict(explanation or {})
        explained_by_view = normalize_reason_code(view.get("reason_code"))
        if explained_by_view == ReasonCode.CAUSE_NOT_RECORDED.value:
            explained_by_view = ""
        if not explained_by_view:
            view["reason_code"] = reason.reason_code
            if reason.mapped and view.get("headline") == _UNRECORDED_ENDING["headline"]:
                view.update(
                    {"code": reason.code, "headline": reason.client_note, "detail": ""}
                )
        for key in ("code", "reason_code", "headline", "detail", "next_step"):
            view.setdefault(key, "")
        edge_code = reason.reason_code if reason.mapped else explained_by_view
        if edge_code:
            self._persist_reason_code(step, state, edge_code)
            return view, ""
        signature = reason.cause_signature or "no_cause_recorded"
        self._unexplained.append(
            {
                "step_index": step.index,
                "relation": step.relation,
                "status": status,
                "cause_signature": signature,
            }
        )
        print_info_debug(
            "attack_paths unexplained step failure: "
            f"relation={step.relation} status={status} "
            f"cause={mark_sensitive(signature, 'detail')}"
        )
        try:
            telemetry.capture(
                "attack_step_unexplained_failure",
                {
                    "relation": step.relation,
                    "step_status": status,
                    "cause_signature": signature,
                },
            )
        except Exception as exc:  # noqa: BLE001 - measurement never breaks a run
            telemetry.capture_exception(exc)
        return view, signature

    def _persist_reason_code(self, step: PlanStep, state: "_StepState", code: str) -> None:
        """Write a cause the run observed onto the step's edge, best-effort."""
        if not is_attempted_step_status(state.status):
            return
        if normalize_reason_code(state.status_notes.get("reason_code")) == code:
            return
        try:
            from adscan_internal.services.attack_graph_service import (  # noqa: PLC0415
                update_edge_status_by_labels,
            )

            update_edge_status_by_labels(
                self.shell,
                self.domain,
                from_label=step.from_label,
                relation=step.relation,
                to_label=step.to_label,
                status=state.status,
                notes={"reason_code": code},
            )
        except Exception as exc:  # noqa: BLE001 - never alter the execution flow
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    def _record_step_gate_refusal(self, step: PlanStep) -> Any:
        """Record why this step and the rest of the route did not run.

        A "no" at the step gate stops the route here, so this step and every
        later one stay unexecuted. Each gets the decision note (declined by
        whom and when, or no answer from the console), never left blank.
        Returns the recorded decision (``None`` when it could not be recorded) so
        the console states the same who and when the report does.
        """
        try:
            from adscan_internal.services.operator_decisions import (  # noqa: PLC0415
                record_operator_decision_on_edges,
                resolve_negative_decision,
            )

            remaining = [s for s in self.plan if s.index >= step.index]
            decision = resolve_negative_decision(self.shell)
            # The gated step first, then the steps that waited on it.
            record_operator_decision_on_edges(
                self.shell,
                domain=self.domain,
                edges=[(s.from_label, s.relation, s.to_label, "theoretical") for s in remaining],
                decision=decision,
                dependent_after_first=True,
            )
            return decision
        except Exception as exc:  # noqa: BLE001 - the record never breaks the run
            telemetry.capture_exception(exc)
            return None

    def _confirm_step(self, step: PlanStep) -> bool:
        position = self._position(step.index)
        total = len(self.executable_steps)
        prompt = f"Run step {position} of {total} now ({step.technique})?"
        context = {
            "remote_interaction": True,
            "category": "attack_path_execution",
            "decision": DECISION_STEP_GATE,
            "domain": self.domain,
            "run_id": self.run_id,
            "step_index": step.index,
            "position": position,
            "executable_total": total,
        }
        from adscan_core.scan_policy.execution import (  # noqa: PLC0415
            suppress_remote_decision,
        )

        if suppress_remote_decision(self.shell, "attack_path_execution"):
            # An unattended policy already answered every attack-step decision.
            return True
        # Silence never approves (release gate 14.0.0): the gate's default is
        # "skip" on every channel, a relayed request that times out resolves to
        # "skip" (``timeout_result=False``), and a run with nobody to ask does
        # not run the step. The caller records the step as awaiting approval
        # (``resolve_negative_decision``), never as declined.
        confirm = getattr(self.shell, "_questionary_confirm", None)
        if callable(confirm):
            try:
                resolved = confirm(prompt, default=False, timeout_result=False, context=context)
                if isinstance(resolved, bool):
                    return resolved
            except TypeError:
                pass
        from adscan_internal.interaction import is_non_interactive  # noqa: PLC0415

        if is_non_interactive(self.shell):
            return False
        from rich.prompt import Confirm  # noqa: PLC0415

        return bool(Confirm.ask(prompt, default=False))

    def confirm_environment_change(self, prompt: str, *, change_kind: str) -> bool | None:
        """Ask the operator to approve one change made INSIDE the current step.

        Step mode promises that nothing runs without an approval at the console.
        Approving a step is approving the technique, and some techniques only
        work after a configuration change the operator did not see named on the
        step (the SQL Server setting that enables command execution is the
        case that prompted this). In step mode such a change gets its own
        approve-or-skip decision, through the same channel as the step gate, so
        an unattended console never approves it: no answer means skip.

        Returns:
            The operator's answer in step mode, or ``None`` outside it (the
            caller then applies its usual policy).
        """
        if self.mode != MODE_STEP or self._finished:
            return None
        if threading.get_ident() != self._thread:
            return None
        context = {
            "remote_interaction": True,
            "category": "attack_path_execution",
            "decision": DECISION_CHANGE_GATE,
            "domain": self.domain,
            "run_id": self.run_id,
            "change_kind": change_kind,
        }
        if self._current is not None:
            context["step_index"] = self._current
            context["position"] = self._position(self._current)
        confirm = getattr(self.shell, "_questionary_confirm", None)
        if callable(confirm):
            try:
                resolved = confirm(prompt, default=False, timeout_result=False, context=context)
                if isinstance(resolved, bool):
                    return resolved
            except TypeError:
                pass
        from adscan_internal.interaction import is_non_interactive  # noqa: PLC0415

        if is_non_interactive(self.shell):
            # Step mode with nobody to ask: never approve a change by default.
            return False
        from rich.prompt import Confirm  # noqa: PLC0415

        return bool(Confirm.ask(prompt, default=False))

    def _domain_compromised(self) -> bool:
        domains_data = getattr(self.shell, "domains_data", None)
        if not isinstance(domains_data, dict):
            return False
        data = domains_data.get(self.domain)
        return isinstance(data, dict) and data.get("auth") == "pwned"

    def _ledger(self) -> Any:
        try:
            from adscan_internal.services.environment_change_ledger import (  # noqa: PLC0415
                active_session_ledger,
            )

            return active_session_ledger(getattr(self.shell, "current_workspace_dir", None))
        except Exception:  # noqa: BLE001
            return None

    def _ledger_change_ids(self) -> set[str]:
        ledger = self._ledger()
        if ledger is None:
            return set()
        try:
            return {str(entry.get("change_id")) for entry in ledger.get_changes()}
        except Exception:  # noqa: BLE001
            return set()

    def _run_changes(self) -> list[dict[str, Any]]:
        ledger = self._ledger()
        if ledger is None:
            return []
        try:
            from adscan_internal.services import cleanup_taxonomy as tax  # noqa: PLC0415

            changes = []
            for entry in ledger.get_changes():
                change_id = str(entry.get("change_id") or "")
                if not change_id or change_id in self._ledger_ids_at_start:
                    continue
                status = str(entry.get("revert_status") or "")
                changes.append(
                    {
                        "kind": tax.kind_display(entry.get("kind")),
                        "target": str(entry.get("target") or ""),
                        "cleanup_status": status,
                        "cleanup_label": tax.status_label(status),
                        "cleanup_bucket": tax.cleanup_bucket(status),
                    }
                )
            return changes
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            return []


def acting_principal_from_notes(notes: dict[str, Any]) -> str:
    """The principal that performed a step, from its status notes; "" when unknown.

    The run-result caption reads "As <name>", so the name must be who acted.
    The chain-resolved acting principal keys come first, then the legacy
    ``actor`` / ``exec_username``. Nothing here ever reads a ``target_*`` or
    ``user`` note: those name the object acted on, and falling back to one made a
    Kerberoast step read "As <the roasted account>".
    """
    from adscan_internal.services.step_actor_resolution import (  # noqa: PLC0415
        ACTING_PRINCIPAL_KEY,
        ACTING_PRINCIPAL_SAM_KEY,
    )

    for key in (ACTING_PRINCIPAL_SAM_KEY, ACTING_PRINCIPAL_KEY, "actor", "exec_username"):
        value = str(notes.get(key) or "").strip()
        if value:
            return value
    return ""


def _declined_before_acting(state: "_StepState") -> bool:
    """A step declined before acting, whose latest write did not prove or attempt it."""
    if not declined_reason(state.status_notes, state.reasons):
        return False
    return outcome_from_status(state.status, state.status_notes) not in (
        OUTCOME_SUCCESS,
        OUTCOME_ATTEMPTED,
    )


def _excluded_by_scan_policy(notes: dict[str, Any], reasons: list[str]) -> bool:
    from adscan_core.scan_policy.skip_notice import EXPLANATION_REASON_CODE  # noqa: PLC0415

    if str(notes.get("not_executed_reason") or "") == EXPLANATION_REASON_CODE:
        return True
    return any(str(r).strip() == EXPLANATION_REASON_CODE for r in reasons)


def _scan_policy_explanation(
    shell: Any, step: "PlanStep", notes: dict[str, Any]
) -> dict[str, str]:
    """The skip-notice SSOT wording for a step the scan policy kept off."""
    from adscan_internal.services.scan_policy_enforcement import (  # noqa: PLC0415
        check_id_for,
    )
    from adscan_internal.services.scan_policy_notice import (  # noqa: PLC0415
        policy_skip_explanation,
    )

    check_id = str(notes.get("scan_policy_check_id") or "") or check_id_for(
        shell, relation=step.relation
    )
    view = policy_skip_explanation(shell, check_id)
    if view.get("headline"):
        return view
    return {
        "code": "",
        "reason_code": "excluded_by_scan_policy",
        "headline": "The scan policy turns this step off.",
        "detail": "",
        "next_step": "",
    }


def _refusal_explanation(reason: str) -> dict[str, str]:
    view = failure_view(reason)
    if view.get("headline"):
        return view
    return {
        "code": "",
        "reason_code": "",
        "headline": "The path was not run.",
        "detail": reason,
        "next_step": "",
    }


def _path_event_id(summary: dict[str, Any]) -> str:
    source = str(summary.get("source") or "unknown-source").strip()
    target = str(summary.get("target") or "unknown-target").strip()
    length = int(summary.get("length") or 0)
    return f"{source}->{target}:{length}"


def _summary_step_status(summary: dict[str, Any], index: int) -> str:
    steps = summary.get("steps")
    if not isinstance(steps, list) or not 1 <= index <= len(steps):
        return ""
    step = steps[index - 1]
    return str(step.get("status") or "") if isinstance(step, dict) else ""


def _readable_reason(notes: dict[str, Any], reasons: list[str]) -> str:
    """Return a human sentence already attached by the branch, if any.

    Branches pass either a token (``source_principal_not_controlled``, handled
    by the explanation SSOT) or a sentence. Only a sentence is shown verbatim.
    """

    for candidate in [str(notes.get("reason") or ""), *reversed(reasons)]:
        text = candidate.strip()
        if text and " " in text and "_" not in text.split(" ", 1)[0]:
            return text[0].upper() + text[1:] if text else text
    return ""


def _breaks_on_scan_policy(breaking: dict[str, Any] | None) -> bool:
    if not isinstance(breaking, dict):
        return False
    explanation = breaking.get("explanation")
    return isinstance(explanation, dict) and explanation.get("reason_code") == "excluded_by_scan_policy"


def _result_headline(
    result: str,
    succeeded: int,
    total: int,
    compromised: bool,
    breaking: dict[str, Any] | None = None,
    *,
    not_needed: int = 0,
) -> str:
    headline = _base_result_headline(result, succeeded, total, compromised, breaking)
    if not_needed and headline.endswith(" steps succeeded."):
        noun = "step was" if not_needed == 1 else "steps were"
        headline = f"{headline[:-1]}. {not_needed} {noun} not needed."
    return headline


def _base_result_headline(
    result: str,
    succeeded: int,
    total: int,
    compromised: bool,
    breaking: dict[str, Any] | None = None,
) -> str:
    if compromised and result in {RESULT_COMPLETED, RESULT_PARTIAL}:
        return "Domain compromise proven."
    if (
        succeeded == 0
        and isinstance(breaking, dict)
        and breaking.get("outcome") == OUTCOME_SAFETY_BLOCKED
    ):
        return "Not executed for safety. This path includes a step ADscan never runs automatically."
    if _breaks_on_scan_policy(breaking):
        if result == RESULT_NOT_STARTED:
            return "The path was not run. The scan policy turns its first step off."
        return (
            f"Path stopped at a step the scan policy turns off, {succeeded} of {total} "
            "steps succeeded."
        )
    if result == RESULT_COMPLETED:
        return f"Path executed end to end, {succeeded} of {total} steps succeeded."
    if result == RESULT_PARTIAL:
        return f"Path partly executed, {succeeded} of {total} steps succeeded."
    if result == RESULT_NOT_STARTED:
        return "The path was not run."
    return f"Path stopped, {succeeded} of {total} steps succeeded."


# ── shell wiring ─────────────────────────────────────────────────────────────


_FINISH_LISTENERS_ATTR = "_attack_path_execution_finish_listeners"


def add_run_finished_listener(
    shell: Any, listener: Callable[[AttackPathExecutionRun, dict[str, Any]], None]
) -> None:
    """Call ``listener(run, summary)`` after every run on ``shell`` finishes.

    Used by ``recheck`` to record a walk's per-step outcomes without a second
    executor. A listener's failure never affects the run.
    """
    listeners = getattr(shell, _FINISH_LISTENERS_ATTR, None)
    if not isinstance(listeners, list):
        listeners = []
        try:
            setattr(shell, _FINISH_LISTENERS_ATTR, listeners)
        except Exception:  # noqa: BLE001
            return
    listeners.append(listener)


def remove_run_finished_listener(
    shell: Any, listener: Callable[[AttackPathExecutionRun, dict[str, Any]], None]
) -> None:
    """Remove a listener added by :func:`add_run_finished_listener`."""
    listeners = getattr(shell, _FINISH_LISTENERS_ATTR, None)
    if isinstance(listeners, list) and listener in listeners:
        listeners.remove(listener)


def _notify_run_finished(run: AttackPathExecutionRun, summary: dict[str, Any]) -> None:
    for listener in list(getattr(run.shell, _FINISH_LISTENERS_ATTR, None) or ()):
        try:
            listener(run, summary)
        except Exception as exc:  # noqa: BLE001 - a listener never breaks a run
            telemetry.capture_exception(exc)


def install_execution_run(shell: Any, run: AttackPathExecutionRun | None) -> None:
    """Install (or clear, with ``None``) the active run on the shell."""
    try:
        setattr(shell, _ACTIVE_RUN_ATTR, run)
    except Exception:  # noqa: BLE001
        pass


def get_active_execution_run(shell: Any) -> AttackPathExecutionRun | None:
    """Return the run active on ``shell``, or ``None``."""
    run = getattr(shell, _ACTIVE_RUN_ATTR, None)
    return run if isinstance(run, AttackPathExecutionRun) else None


def notify_edge_status(
    shell: Any,
    *,
    relation: str,
    from_label: str,
    to_label: str,
    status: str,
    notes: dict[str, Any] | None,
) -> None:
    """Edge-status seam: forward a persisted status to the active run."""
    run = get_active_execution_run(shell)
    if run is None:
        return
    try:
        run.observe_status(
            relation=relation,
            from_label=from_label,
            to_label=to_label,
            status=status,
            notes=notes,
        )
    except Exception as exc:  # noqa: BLE001 - observation must never break a write
        telemetry.capture_exception(exc)


def notify_legacy_event(shell: Any, **kwargs: Any) -> None:
    """Legacy-event seam: forward a branch's reason to the active run."""
    run = get_active_execution_run(shell)
    if run is None:
        return
    try:
        run.observe_legacy_event(**kwargs)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)


# ── execution mode decision ──────────────────────────────────────────────────

_MODE_OPTIONS: tuple[tuple[str, str | None], ...] = (
    ("Run continuously", MODE_CONTINUOUS),
    ("Step through, confirming each step", MODE_STEP),
    ("Do not execute now", None),
)


def prompt_execution_mode(
    shell: Any,
    *,
    domain: str,
    summary: dict[str, Any],
    run_id: str,
    default_mode: str = MODE_CONTINUOUS,
) -> str | None:
    """Ask how to run the selected path. Returns a mode, or ``None`` for "not now".

    One decision for the web, the CLI and unattended runs: it goes through the
    shell's remote-capable select, so the web renders it with the plan carried
    in its context. Silence never runs anything (release gate 14.0.0): a relayed
    request that times out resolves to "not now", and so does a run with no
    operator and no remote bridge unless an unattended policy (or no policy at
    all, the legacy ``ci`` behaviour) answered the decision already.
    """

    from adscan_core.scan_policy.execution import silence_must_not_run  # noqa: PLC0415
    from adscan_internal import interactive_requests  # noqa: PLC0415
    from adscan_internal.interaction import is_non_interactive  # noqa: PLC0415

    labels = [label for label, _mode in _MODE_OPTIONS]
    default_idx = 1 if default_mode == MODE_STEP else 0
    if (
        is_non_interactive(shell)
        and not interactive_requests.is_remote_interaction_enabled()
        and silence_must_not_run(shell)
    ):
        # Nobody can answer and no policy answered for them: do not execute.
        return None
    plan = build_execution_plan(summary, domain)
    context = {
        "remote_interaction": True,
        "category": "attack_path_execution",
        "decision": DECISION_EXECUTION_MODE,
        "domain": domain,
        "run_id": run_id,
        "path_source": str(summary.get("source") or ""),
        "path_target": str(summary.get("target") or ""),
        # The raw labels stay the matching key; the console prints these.
        "path_source_display": display_label(str(summary.get("source") or ""), domain),
        "path_target_display": display_label(str(summary.get("target") or ""), domain),
        "steps": [step.to_dict() for step in plan],
    }
    select = getattr(shell, "_questionary_select", None)
    selected: int | None
    if callable(select):
        try:
            selected = select(
                "How should ADscan run this attack path?",
                labels,
                default_idx=default_idx,
                context=context,
            )
        except TypeError:
            selected = select(
                "How should ADscan run this attack path?", labels, default_idx=default_idx
            )
    elif is_non_interactive(shell):
        selected = default_idx
    else:
        from adscan_core.rich_output import questionary_select_index  # noqa: PLC0415

        selected = questionary_select_index(
            title="How should ADscan run this attack path?",
            options=labels,
            default_idx=default_idx,
            shell=shell,
        )
    if selected is None or not 0 <= int(selected) < len(_MODE_OPTIONS):
        return None
    return _MODE_OPTIONS[int(selected)][1]


def resolve_default_execution_mode(shell: Any = None) -> str:
    """Return the run-mode prompt's default.

    ``ADSCAN_ATTACK_PATH_EXECUTION_MODE=step`` selects step-through. So does a
    policy that leaves each attack step to an operator ("Decide during scan"):
    its default must be the conservative choice, where every step still asks,
    never "Run continuously" (release gate 14.0.0). Otherwise continuous.
    """
    import os  # noqa: PLC0415

    value = str(os.environ.get("ADSCAN_ATTACK_PATH_EXECUTION_MODE") or "").strip().lower()
    if value == MODE_STEP:
        return MODE_STEP
    if shell is not None:
        from adscan_core.scan_policy.execution import policy_asks_operator  # noqa: PLC0415

        if policy_asks_operator(shell):
            return MODE_STEP
    return MODE_CONTINUOUS


# ── terminal rendering ───────────────────────────────────────────────────────


def _render_plan(run: AttackPathExecutionRun) -> None:
    if not run.plan:
        return
    table = Table(show_header=False, box=None, pad_edge=False, padding=(0, 1))
    table.add_column(justify="right", style=COLOR_MUTED, no_wrap=True)
    table.add_column()
    table.add_column(style=COLOR_MUTED)
    position = 0
    for step in run.plan:
        label = Text()
        if step.kind == KIND_CONTEXTUAL:
            label.append(step.technique, style=COLOR_MUTED)
            label.append("  contextual, not executed", style=f"italic {COLOR_MUTED}")
            marker = "·"
        else:
            position += 1
            marker = str(position)
            label.append(step.technique, style="bold")
            if step.kind == KIND_POLICY_BLOCKED:
                label.append("  not run automatically", style=f"italic {COLOR_AMBER}")
        edge = Text()
        edge.append(mark_sensitive(step.from_display or step.from_label or "?", "node"))
        edge.append(" → ")
        edge.append(mark_sensitive(step.to_display or step.to_label or "?", "node"))
        table.add_row(marker, label, edge)
    mode_line = Text(
        "Step through. Each step asks before it runs."
        if run.mode == MODE_STEP
        else "Runs continuously, one step after another.",
        style=COLOR_MUTED,
    )
    print_panel(
        [table, Text(""), mode_line],
        title=Text("Attack path run", style=f"bold {ADSCAN_PRIMARY}"),
        border_style=ADSCAN_PRIMARY,
        expand=False,
    )


def _render_step_header(run: AttackPathExecutionRun, step: PlanStep, position: int) -> None:
    from adscan_internal import get_console  # noqa: PLC0415

    header = Text()
    header.append(f"Step {position} of {len(run.executable_steps)}  ", style=f"bold {ADSCAN_PRIMARY}")
    header.append(step.technique, style="bold")
    if step.mitre_id:
        header.append(f"  {step.mitre_id}", style=COLOR_MUTED)
    get_console().print(header)
    if step.summary:
        get_console().print(Padding(Text(step.summary, style=COLOR_MUTED), (0, 0, 0, 2)))


def _render_step_outcome(
    step: PlanStep,
    outcome: str,
    explanation: dict[str, str],
    duration_ms: int | None,
) -> None:
    from adscan_internal import get_console  # noqa: PLC0415

    line = Text("  ")
    line.append(f"{_OUTCOME_GLYPH.get(outcome, '?')} {OUTCOME_LABELS.get(outcome, outcome)}", style=_OUTCOME_STYLE.get(outcome, ""))
    line.append(f"  {step.technique}", style="bold")
    if duration_ms is not None:
        line.append(f"  {duration_ms / 1000:.1f}s", style=COLOR_MUTED)
    get_console().print(line)
    # Two layers: the plain cause first, then the technical code it came from.
    lines: list[Text] = []
    headline = str(explanation.get("headline") or "").strip()
    if headline:
        lines.append(Text(headline))
    detail = str(explanation.get("detail") or "").strip()
    if detail:
        lines.append(Text(detail, style=COLOR_MUTED))
    next_step = str(explanation.get("next_step") or "").strip()
    if next_step:
        lines.append(Text(next_step, style=COLOR_MUTED))
    code = str(explanation.get("code") or "").strip()
    if code:
        lines.append(Text(f"Code {code}", style=COLOR_MUTED))
    for text in lines:
        get_console().print(Padding(text, (0, 0, 0, 4)))


def _render_summary(run: AttackPathExecutionRun, summary: dict[str, Any]) -> None:
    body: list[Any] = []
    headline = Text(str(summary.get("headline") or ""), style="bold")
    body.append(headline)
    body.append(
        Text(
            f"Run time {int(summary.get('duration_ms') or 0) / 1000:.1f}s.",
            style=COLOR_MUTED,
        )
    )
    breaking = summary.get("first_break")
    if isinstance(breaking, dict):
        explanation = breaking.get("explanation") if isinstance(breaking.get("explanation"), dict) else {}
        line = Text("\nStopped at ", style="bold")
        line.append(rich_markup_escape(str(breaking.get("technique") or "before the first step")))
        body.append(line)
        if explanation.get("headline"):
            body.append(Text(str(explanation["headline"])))
        if _breaks_on_scan_policy(breaking) and explanation.get("next_step"):
            # A policy stop is reversible: say how, where the operator reads it.
            body.append(Text(str(explanation["next_step"]), style=COLOR_MUTED))
        if explanation.get("code"):
            body.append(Text(f"Code {explanation['code']}", style=COLOR_MUTED))
    changes = summary.get("changes") if isinstance(summary.get("changes"), list) else []
    if changes:
        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
        table.add_column("Change")
        table.add_column("Object")
        table.add_column("Cleanup")
        for change in changes:
            table.add_row(
                str(change.get("kind") or ""),
                mark_sensitive(str(change.get("target") or ""), "text"),
                str(change.get("cleanup_label") or ""),
            )
        body.append(Text("\nChanges made in the environment", style="bold"))
        body.append(table)
    else:
        body.append(Text("\nNo changes were recorded in the environment.", style=COLOR_MUTED))
    result = str(summary.get("result") or "")
    border = COLOR_SAGE if result == RESULT_COMPLETED else COLOR_AMBER if result == RESULT_PARTIAL else COLOR_MUTED
    print_panel(
        body,
        title=Text("Run result", style=f"bold {border}"),
        border_style=border,
        expand=False,
    )


__all__ = [
    "AttackPathExecutionRun",
    "OUTCOME_LABELS",
    "PlanStep",
    "StepOutcome",
    "add_run_finished_listener",
    "build_execution_plan",
    "get_active_execution_run",
    "install_execution_run",
    "new_run_id",
    "notify_edge_status",
    "notify_legacy_event",
    "prompt_execution_mode",
    "remove_run_finished_listener",
    "resolve_default_execution_mode",
]
