"""Vocabulary of the attack-path execution events (schema v2).

One run of an attack path emits, through the same technical-event transport the
web already relays (``source = attack_path_execution``), four stages:

* ``run_started``  carries the plan: every step, its kind and its catalog text;
* ``step_started`` when an executable step begins;
* ``step_finished`` with the honest outcome and, when it did not succeed, the
  two-layer explanation;
* ``run_finished`` exactly once per run, with the result summary.

Each v2 event's ``details`` carries ``schema = 2``, ``run_id`` and an
``execution`` dict. The legacy stages (``step_attempting`` ...) are unchanged.

This module is the single definition of the stage names, step kinds and step
outcomes, plus the status-to-outcome mapping. It is pure (stdlib + sibling
``adscan_core.reporting`` modules) so the engine and the web backend import it;
the Celery relay, which never imports ``adscan_core``, mirrors
:data:`EXECUTION_RELAY_KEYS` under a contract test.

Outcome rules (Exposure-Validation doctrine): a step either proved something
(``success``), ran without completing (``attempted``), was not run for safety
(``safety_blocked``, only from the destructive-action classifier marker), was
found closed by an observed configuration (``closed_by_configuration``) or not
vulnerable (``not_vulnerable``), was not run because a precondition was missing
or the operator stopped (``skipped``), was not run because its result was
already in hand (``not_needed``), or was never reached (``not_reached``).
No outcome says a security product stopped a step.
"""

from __future__ import annotations

from typing import Any, Final, Mapping

#: Version stamped on every v2 event (``details["schema"]``).
EXECUTION_EVENT_SCHEMA: Final[int] = 2

# ── Stages ───────────────────────────────────────────────────────────────────
STAGE_RUN_STARTED: Final[str] = "run_started"
STAGE_STEP_STARTED: Final[str] = "step_started"
STAGE_STEP_FINISHED: Final[str] = "step_finished"
STAGE_RUN_FINISHED: Final[str] = "run_finished"
EXECUTION_STAGES: Final[frozenset[str]] = frozenset(
    {STAGE_RUN_STARTED, STAGE_STEP_STARTED, STAGE_STEP_FINISHED, STAGE_RUN_FINISHED}
)

# ── Step kinds ───────────────────────────────────────────────────────────────
KIND_EXECUTABLE: Final[str] = "executable"
KIND_CONTEXTUAL: Final[str] = "contextual"
KIND_POLICY_BLOCKED: Final[str] = "policy_blocked"
STEP_KINDS: Final[frozenset[str]] = frozenset(
    {KIND_EXECUTABLE, KIND_CONTEXTUAL, KIND_POLICY_BLOCKED}
)

# ── Step outcomes ────────────────────────────────────────────────────────────
OUTCOME_SUCCESS: Final[str] = "success"
OUTCOME_ATTEMPTED: Final[str] = "attempted"
OUTCOME_SAFETY_BLOCKED: Final[str] = "safety_blocked"
OUTCOME_CLOSED_BY_CONFIGURATION: Final[str] = "closed_by_configuration"
OUTCOME_NOT_VULNERABLE: Final[str] = "not_vulnerable"
OUTCOME_SKIPPED: Final[str] = "skipped"
OUTCOME_NOT_REACHED: Final[str] = "not_reached"
#: Deliberately not run: what the step would obtain was already held (the
#: password reset of an account whose credential the session holds). Neither a
#: success (nothing was done) nor a failure (the path continues with it).
OUTCOME_NOT_NEEDED: Final[str] = "not_needed"
STEP_OUTCOMES: Final[frozenset[str]] = frozenset(
    {
        OUTCOME_SUCCESS,
        OUTCOME_ATTEMPTED,
        OUTCOME_SAFETY_BLOCKED,
        OUTCOME_CLOSED_BY_CONFIGURATION,
        OUTCOME_NOT_VULNERABLE,
        OUTCOME_SKIPPED,
        OUTCOME_NOT_NEEDED,
        OUTCOME_NOT_REACHED,
    }
)

# ── Steps not run because they were not needed ───────────────────────────────
#: Edge-note key the engine writes on a step it deliberately did not run.
NOT_EXECUTED_REASON_KEY: Final[str] = "not_executed_reason"
#: The credential of the target account was already held.
NOT_NEEDED_CREDENTIAL_ALREADY_HELD: Final[str] = "credential_already_held"

#: Every "not needed" reason, with the client wording each surface prints: the
#: step chip in the reports and the web (``label``) and the run summary
#: (``headline`` / ``detail``). One table, so no surface words it its own way.
NOT_NEEDED_REASONS: Final[Mapping[str, Mapping[str, str]]] = {
    NOT_NEEDED_CREDENTIAL_ALREADY_HELD: {
        "label": "Not needed, the account's credential was already held",
        "headline": (
            "Not needed. The credential of the target account was already held, "
            "so its password was not changed."
        ),
        "detail": "The path continued as that account with the credential already in hand.",
    },
}


def not_needed_reason(notes: Mapping[str, Any] | None) -> str:
    """The "not needed" reason recorded on a step, or ``""`` when there is none."""
    if not isinstance(notes, Mapping):
        return ""
    reason = str(notes.get(NOT_EXECUTED_REASON_KEY) or "").strip().lower()
    return reason if reason in NOT_NEEDED_REASONS else ""


def not_needed_explanation(reason: str) -> dict[str, str]:
    """The run-summary explanation shape for a step that was not needed."""
    entry = NOT_NEEDED_REASONS.get(str(reason or "").strip().lower()) or {}
    return {
        "code": "",
        "reason_code": str(reason or ""),
        "headline": str(entry.get("headline") or "Not needed in this run."),
        "detail": str(entry.get("detail") or ""),
        "next_step": "",
    }

# ── Run results ──────────────────────────────────────────────────────────────
#: Every executable step succeeded.
RESULT_COMPLETED: Final[str] = "completed"
#: At least one step succeeded, the path did not complete.
RESULT_PARTIAL: Final[str] = "partial"
#: No step succeeded.
RESULT_STOPPED: Final[str] = "stopped"
#: The run never started a step (refused by a readiness gate or by the operator).
RESULT_NOT_STARTED: Final[str] = "not_started"
RUN_RESULTS: Final[frozenset[str]] = frozenset(
    {RESULT_COMPLETED, RESULT_PARTIAL, RESULT_STOPPED, RESULT_NOT_STARTED}
)

# ── Execution modes ──────────────────────────────────────────────────────────
MODE_CONTINUOUS: Final[str] = "continuous"
MODE_STEP: Final[str] = "step"
EXECUTION_MODES: Final[frozenset[str]] = frozenset({MODE_CONTINUOUS, MODE_STEP})

#: ``context["decision"]`` of the interactive request that picks the mode.
DECISION_EXECUTION_MODE: Final[str] = "attack_path_execution_mode"
#: ``context["decision"]`` of the per-step confirmation in step mode.
DECISION_STEP_GATE: Final[str] = "attack_path_step_gate"
#: ``context["decision"]`` of the approval a step-mode run asks for a change made
#: INSIDE an approved step (e.g. the SQL Server command-execution setting). It is
#: deliberately NOT run-owned: the console shows it as its own approve-or-skip
#: decision beside the run panel.
DECISION_CHANGE_GATE: Final[str] = "attack_path_change_gate"

#: Keys of a v2 event's ``details`` that every relay hop must forward verbatim.
#: Mirrored by ``appliance/celery/adscan_celery/tasks.py`` (contract-tested).
EXECUTION_RELAY_KEYS: Final[tuple[str, ...]] = ("schema", "run_id", "execution")

_PROVEN_STATUSES: Final[frozenset[str]] = frozenset(
    {"success", "succeeded", "exploited", "domain_compromised", "completed"}
)
_ATTEMPTED_STATUSES: Final[frozenset[str]] = frozenset(
    {"attempted", "failed", "error", "partial", "aborted"}
)


def outcome_from_status(status: Any, notes: Mapping[str, Any] | None = None) -> str:
    """Map a persisted step status (and its notes) to a step outcome.

    ``blocked`` only becomes ``safety_blocked`` when the destructive-action
    classifier stamped ``blocked_kind = dangerous_destructive``; any other
    ``blocked`` is a step that was not run for a missing precondition
    (``skipped``). This mirrors the report's bucket rule, so the live view and
    the deliverable never disagree on what a stop means.
    """

    token = str(status or "").strip().lower()
    notes = notes or {}
    blocked_kind = str(notes.get("blocked_kind") or "").strip().lower()
    if token in _PROVEN_STATUSES:
        return OUTCOME_SUCCESS
    if token not in _ATTEMPTED_STATUSES and not_needed_reason(notes):
        # Put back to "discovered" with the reason: deliberately not run.
        return OUTCOME_NOT_NEEDED
    if token == "closed_by_configuration":
        return OUTCOME_CLOSED_BY_CONFIGURATION
    if token == "not_vulnerable":
        return OUTCOME_NOT_VULNERABLE
    if token == "blocked":
        if blocked_kind == "dangerous_destructive":
            return OUTCOME_SAFETY_BLOCKED
        return OUTCOME_SKIPPED
    if token in {"unavailable", "unsupported", "cancelled", "skipped"}:
        return OUTCOME_SKIPPED
    if token in _ATTEMPTED_STATUSES:
        return OUTCOME_ATTEMPTED
    return ""


def is_terminal_outcome(outcome: Any) -> bool:
    """Return whether ``outcome`` is a known step outcome."""

    return str(outcome or "") in STEP_OUTCOMES


def summarize_run_result(outcomes: list[str], *, executable_total: int) -> str:
    """Return the run result for the ordered outcomes of its executable steps."""

    if not any(outcome in {OUTCOME_SUCCESS, OUTCOME_ATTEMPTED} for outcome in outcomes) and not any(
        outcome in {OUTCOME_SAFETY_BLOCKED, OUTCOME_CLOSED_BY_CONFIGURATION, OUTCOME_NOT_VULNERABLE}
        for outcome in outcomes
    ):
        return RESULT_NOT_STARTED
    succeeded = sum(1 for outcome in outcomes if outcome == OUTCOME_SUCCESS)
    # A step not needed (its result was already held) does not stop the path:
    # it counts toward completion, but only once something was actually run.
    not_needed = sum(1 for outcome in outcomes if outcome == OUTCOME_NOT_NEEDED)
    if executable_total > 0 and succeeded > 0 and succeeded + not_needed >= executable_total:
        return RESULT_COMPLETED
    if succeeded > 0:
        return RESULT_PARTIAL
    return RESULT_STOPPED


def sanitize_execution_block(value: Any, *, depth: int = 0) -> Any:
    """Return a JSON-safe copy of an ``execution`` block for relay hops.

    Keeps dicts, lists, strings, numbers, booleans and ``None``; drops anything
    else. Depth-capped so a malformed artifact cannot blow up a relay.
    """

    if depth > 6:
        return None
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Mapping):
        return {
            str(key): sanitize_execution_block(item, depth=depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [sanitize_execution_block(item, depth=depth + 1) for item in value]
    return None


def relay_fields(details: Mapping[str, Any] | None) -> dict[str, Any]:
    """Extract the v2 fields every relay hop forwards, sanitized.

    Returns an empty dict for a legacy (v1) event so a hop can splat it
    unconditionally.
    """

    if not isinstance(details, Mapping):
        return {}
    schema = details.get("schema")
    if not isinstance(schema, int) or schema < EXECUTION_EVENT_SCHEMA:
        return {}
    execution = details.get("execution")
    return {
        "schema": schema,
        "run_id": str(details.get("run_id") or "").strip() or None,
        "execution": sanitize_execution_block(execution) if isinstance(execution, Mapping) else None,
    }


__all__ = [
    "DECISION_EXECUTION_MODE",
    "DECISION_STEP_GATE",
    "EXECUTION_EVENT_SCHEMA",
    "EXECUTION_MODES",
    "EXECUTION_RELAY_KEYS",
    "EXECUTION_STAGES",
    "KIND_CONTEXTUAL",
    "KIND_EXECUTABLE",
    "KIND_POLICY_BLOCKED",
    "MODE_CONTINUOUS",
    "MODE_STEP",
    "OUTCOME_ATTEMPTED",
    "OUTCOME_CLOSED_BY_CONFIGURATION",
    "OUTCOME_NOT_NEEDED",
    "OUTCOME_NOT_REACHED",
    "NOT_EXECUTED_REASON_KEY",
    "NOT_NEEDED_CREDENTIAL_ALREADY_HELD",
    "NOT_NEEDED_REASONS",
    "not_needed_reason",
    "not_needed_explanation",
    "OUTCOME_NOT_VULNERABLE",
    "OUTCOME_SAFETY_BLOCKED",
    "OUTCOME_SKIPPED",
    "OUTCOME_SUCCESS",
    "RESULT_COMPLETED",
    "RESULT_NOT_STARTED",
    "RESULT_PARTIAL",
    "RESULT_STOPPED",
    "RUN_RESULTS",
    "STAGE_RUN_FINISHED",
    "STAGE_RUN_STARTED",
    "STAGE_STEP_FINISHED",
    "STAGE_STEP_STARTED",
    "STEP_KINDS",
    "STEP_OUTCOMES",
    "is_terminal_outcome",
    "outcome_from_status",
    "relay_fields",
    "sanitize_execution_block",
    "summarize_run_result",
]
