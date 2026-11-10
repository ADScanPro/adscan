"""Record an operator decision that kept attack steps from running.

An attended run asks before it acts. When the answer is "no", or when the
question gets no answer, the steps it covered stay mapped and unexecuted, and
the deliverable must say which of the two happened:

* **Declined** (reason 3): an operator answered "no". Recorded with WHO
  (the signed-in console user on the web, the stated command-line operator
  otherwise; :mod:`operator_identity`) and WHEN (UTC).
* **Awaiting approval** (reason 2): the relayed decision timed out, or the
  answer was unreadable. Nobody decided, so it is never worded as a decision;
  the wait is recorded so the label can say "no answer within N minutes".

The record is an edge note on each not-yet-run step of the route, written
through ``update_edge_status_by_labels`` (status unchanged). Edge notes travel
into ``step["details"]``, where :mod:`adscan_core.scan_policy.annotate` labels
the step and the verdict SSOT counts the route. Nothing else needs to carry it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from adscan_core import telemetry
from adscan_core.rich_output import print_exception, print_info_debug
from adscan_core.scan_policy.annotate import (
    NOTE_AWAITING_TIMEOUT_KEY,
    NOTE_DECISION_DEPENDENT_KEY,
    NOTE_DECLINED_AT_KEY,
    NOTE_DECLINED_BY_KEY,
    NOTE_REASON_KEY,
    status_is_not_run,
)
from adscan_core.scan_policy.execution import (
    REASON_AWAITING_APPROVAL,
    REASON_OPERATOR_DECLINED,
)

#: How a relayed request resolved (``interactive_requests.last_resolution``).
_RESOLUTION_ANSWERED = "answered"
#: Prompt shown when the command-line operator must be asked for a name.
_NAME_PROMPT = "Your name, recorded in the report beside the attack path you declined"


@dataclass(frozen=True)
class OperatorDecision:
    """What a "no" or a missing answer means for the steps it covered."""

    reason: str
    declined_by: str = ""
    declined_at: str = ""
    timeout_seconds: int = 0

    def notes(self, *, dependent: bool = False) -> dict[str, Any]:
        """The edge / step note for one covered step.

        ``dependent`` marks a later step of the route: it waited on the step the
        operator was asked about and was never put to the operator itself, so
        it reads "depends on a step awaiting approval" (or declined) on every
        surface. The marker is written either way, so a later decision on the
        same edge overwrites an earlier one cleanly.
        """
        notes: dict[str, Any] = {
            NOTE_REASON_KEY: self.reason,
            NOTE_DECISION_DEPENDENT_KEY: bool(dependent),
        }
        if self.reason == REASON_OPERATOR_DECLINED:
            if self.declined_by:
                notes[NOTE_DECLINED_BY_KEY] = self.declined_by
            notes[NOTE_DECLINED_AT_KEY] = self.declined_at
        elif self.timeout_seconds:
            notes[NOTE_AWAITING_TIMEOUT_KEY] = int(self.timeout_seconds)
        return notes


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def resolve_negative_decision(shell: Any) -> OperatorDecision:
    """Classify the decision that just came back negative (or empty).

    A relayed request that was answered is a decline by the console user who
    answered it. One that timed out, or whose answer could not be read, is
    "awaiting approval" (nobody decided). A local prompt is always answered by
    the person at the terminal.
    """
    from adscan_internal import interactive_requests  # noqa: PLC0415

    if interactive_requests.is_remote_interaction_enabled():
        resolution = interactive_requests.last_resolution()
        if resolution != _RESOLUTION_ANSWERED:
            return OperatorDecision(
                reason=REASON_AWAITING_APPROVAL,
                timeout_seconds=interactive_requests.request_timeout_seconds()
                if resolution == "timeout"
                else 0,
            )
        who = str(interactive_requests.last_responder() or "").strip()
        return OperatorDecision(
            reason=REASON_OPERATOR_DECLINED, declined_by=who, declined_at=_now_utc_iso()
        )
    from adscan_internal.interaction import is_non_interactive  # noqa: PLC0415

    if is_non_interactive(shell):
        # No relay and nobody at a terminal: the "no" is the prompt helper's
        # unattended default, not a person's answer. Nobody decided.
        return OperatorDecision(reason=REASON_AWAITING_APPROVAL)
    from adscan_internal.services.operator_identity import (  # noqa: PLC0415
        command_line_operator_name,
    )

    who = ""
    try:
        who = command_line_operator_name(shell, prompt_text=_NAME_PROMPT)
    except Exception as exc:  # noqa: BLE001 - a name is best-effort; the decline is not
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    return OperatorDecision(
        reason=REASON_OPERATOR_DECLINED, declined_by=who, declined_at=_now_utc_iso()
    )


def _step_edges(summary: Mapping[str, Any]) -> list[tuple[int, str, str, str, str]]:
    """``(index, from, relation, to, status)`` for each step of a display record."""
    nodes = summary.get("nodes") if isinstance(summary.get("nodes"), list) else []
    steps = summary.get("steps") if isinstance(summary.get("steps"), list) else []
    edges: list[tuple[int, str, str, str, str]] = []
    for position, step in enumerate(steps, start=1):
        if not isinstance(step, Mapping):
            continue
        index = int(step.get("step") or position)
        if index < 1 or index >= len(nodes):
            continue
        edges.append(
            (
                index,
                str(nodes[index - 1] or ""),
                str(step.get("action") or step.get("relation") or ""),
                str(nodes[index] or ""),
                str(step.get("status") or ""),
            )
        )
    return edges


def record_operator_decision(
    shell: Any,
    *,
    domain: str,
    summary: Mapping[str, Any],
    decision: OperatorDecision,
    step_indexes: Sequence[int] | None = None,
) -> int:
    """Write ``decision`` onto the route's not-yet-run steps. Returns how many.

    Args:
        shell: The session shell.
        domain: The attack graph's domain.
        summary: The display record of the route (``nodes`` + ``steps``).
        decision: From :func:`resolve_negative_decision`.
        step_indexes: Only these 1-based steps (a step-gate "no" covers one
            step); ``None`` covers every step not run yet (a path-level "no").
    """
    wanted = set(step_indexes) if step_indexes is not None else None
    edges = [
        (from_label, relation, to_label, status)
        for index, from_label, relation, to_label, status in _step_edges(summary)
        if (wanted is None or index in wanted) and status_is_not_run(status)
    ]
    # A path-level "no" covers the whole route: its first not-run step is the
    # one decided, every later one waited on it.
    return record_operator_decision_on_edges(
        shell,
        domain=domain,
        edges=edges,
        decision=decision,
        dependent_after_first=wanted is None,
    )


def record_operator_decision_on_edges(
    shell: Any,
    *,
    domain: str,
    edges: Sequence[tuple[str, str, str, str]],
    decision: OperatorDecision,
    dependent_after_first: bool = False,
) -> int:
    """Write ``decision`` onto ``(from, relation, to, status)`` edges. Returns how many.

    The status is written back unchanged (the graph never lowers a status), so a
    step that already ran keeps its proof; annotation drops the note there.
    With ``dependent_after_first`` the first edge is the step the operator was
    asked about and every later edge is marked as waiting on it.
    """
    from adscan_internal.services.attack_graph_service import (  # noqa: PLC0415
        update_edge_status_by_labels,
    )

    written = 0
    for position, (from_label, relation, to_label, status) in enumerate(edges):
        if not (from_label and relation and to_label):
            continue
        try:
            update_edge_status_by_labels(
                shell,
                domain,
                from_label=from_label,
                relation=relation,
                to_label=to_label,
                status=str(status or "theoretical").strip().lower() or "theoretical",
                notes=decision.notes(dependent=dependent_after_first and position > 0),
            )
            written += 1
        except Exception as exc:  # noqa: BLE001 - the record never breaks the scan
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
    print_info_debug(
        f"operator decision recorded: reason={decision.reason} steps={written}"
    )
    return written


__all__ = [
    "OperatorDecision",
    "record_operator_decision",
    "record_operator_decision_on_edges",
    "resolve_negative_decision",
]
