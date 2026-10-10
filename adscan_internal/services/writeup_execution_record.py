"""Replay a run's EXECUTION RECORD into one ordered narrative per attack path.

The writeup used to synthesize its single causal chain from the path GRAPH and
then stamp each step with an outcome looked up by edge identity
(``(relation, from, to)``). That join deliberately folded "the same edge
attempted inside three different chains" into one record, which is wrong the
moment a run walks more than one path: two separate executions of DCSync, in
two different chains, forty-eight minutes apart, became one step with one
timestamp inside one invented chain. The document then printed a step
succeeding FIFTY-ONE MINUTES BEFORE the step that supposedly enabled it, and
asserted a causal link (roasting an SPN does not confer domain-controller group
membership) the record never supported. Worse, fusing the two discarded the
strongest fact of the engagement: the second path went from an ordinary domain
user to full domain compromise in under three minutes, and the writeup never
said so.

The event log always had what was needed. Every execution event carries a
``path_id``, so the paths are separable by construction. This module groups on
it and returns, per path, exactly what the record states and nothing more:

* the steps in the order they ran, each with its OWN timestamp, its OWN source
  label, and the ``actor`` that actually authenticated (which is frequently not
  the step's source principal: a DCSync step whose source is the
  domain-controllers group runs as an owned DC machine account, and the repro
  command rightly names the machine account);
* the wall-clock start, completion and therefore DURATION;
* whether the path completed, and whether a domain compromise was recorded
  inside its window.

Nothing here reads the graph, and nothing here infers. A path the record did
not close has no end time rather than a guessed one, and an event with no
``path_id`` is never invented into a path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

#: Event stages that open a path.
_PATH_STARTED = "path_started"
#: Event stages that close a path, and whether the close is a success.
_PATH_COMPLETED = "path_completed"
_PATH_ABORTED = "path_aborted"

_STEP_ATTEMPTING = "step_attempting"
_STEP_SUCCEEDED = "step_succeeded"
_STEP_FAILED = "step_failed"
_STEP_BLOCKED = "step_blocked"

#: Statuses that mean the step did its job, whatever stage carried them.
_SUCCESS_STATUSES = frozenset({"success", "succeeded", "completed"})

_EXECUTION_EVENT_TYPE = "attack_path_execution"
_COMPROMISE_EVENT_TYPE = "domain_compromise"

#: Proof source for a step whose outcome is the attack graph's own status for
#: the edge rather than a ``step_*`` event. Some techniques never emit a step
#: event (a derived privileged-group escalation follow-up stamps the edge and
#: names its actor in the edge's own record), so the path they belong to
#: replays as a start, a stop and nothing in between unless that proof is
#: attached — with this marker, so the document says where it came from.
PROOF_SOURCE_GRAPH_EDGE = "graph_edge"


def parse_timestamp(value: Any) -> Optional[datetime]:
    """Return ``value`` as a datetime, or ``None`` when it is unusable.

    A malformed stamp is a data gap, never a reason to drop the event that
    carried it: the step still ran.
    """
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def format_duration(seconds: Optional[float]) -> Optional[str]:
    """Return a human duration for ``seconds``, or ``None``.

    Reads as the operator would say it out loud. Sub-second is rendered as
    "under a second" rather than ``0s``, which would look like a missing
    measurement.
    """
    if seconds is None:
        return None
    try:
        total = float(seconds)
    except (TypeError, ValueError):
        return None
    if total < 0:
        return None
    if total < 1:
        return "under a second"
    if total < 60:
        return f"{int(total)}s"
    if total < 3600:
        return f"{int(total) // 60}m{int(total) % 60:02d}s"
    return f"{int(total) // 3600}h{(int(total) % 3600) // 60:02d}m"


@dataclass(frozen=True, slots=True)
class ExecutedStep:
    """One step exactly as the execution record describes it.

    Attributes:
        action: The technique as the executor named it (``"DCSync"``).
        source: The step's source label, verbatim. A localized group name is
            the client's own and is never translated.
        target: The step's target label, verbatim.
        actor: The principal that actually authenticated, when the record names
            one. Often NOT ``source``: a DCSync step sourced from the
            domain-controllers group runs as an owned DC machine account.
        outcome: ``"success"`` when the record says so, else the recorded
            failure status (``"failed"`` / ``"blocked"``).
        at: Timestamp of the outcome, per THIS path. Never borrowed from the
            same technique's execution inside another path.
        attempts: How many times this step was attempted in this path.
        proof_source: Where the outcome was read. Empty for the ordinary case,
            the step event log. :data:`PROOF_SOURCE_GRAPH_EDGE` when the step
            emitted no event of its own and the proof is the attack graph's
            status for the edge, which the renderer has to state rather than
            print a step that looks event-recorded and carries no clock.
        reason: Why the step did not complete, exactly as the executor recorded
            it on the ``step_failed`` / ``step_blocked`` event. The record has
            carried this all along while the writeup asserted the opposite
            ("where a step stopped is recorded, the cause is not"), which threw
            away the run's best operator lesson: a DCSync that could not be
            exercised because the DRSUAPI dynamic RPC range did not answer from
            this network position is a constraint the reader needs. Empty when
            the record genuinely carries no cause.
    """

    action: str
    source: str = ""
    target: str = ""
    actor: Optional[str] = None
    outcome: str = ""
    at: Optional[str] = None
    attempts: int = 0
    proof_source: str = ""
    reason: str = ""

    @property
    def succeeded(self) -> bool:
        """Whether the record states this step did its job."""
        return self.outcome == "success"


@dataclass(frozen=True, slots=True)
class ExecutedPath:
    """One attack path the run actually walked, replayed from the record.

    Attributes:
        path_id: The executor's own key for this path. The grouping identity.
        source: The path's start principal (``path_source``).
        target: The path's terminal (``path_target``).
        started_at: Wall clock of ``path_started``.
        completed_at: Wall clock of the close, or ``None`` when never closed.
        steps: Steps in execution order.
        completed: Whether the record closed this path successfully.
        domain_compromise_evidence: The evidence value of a domain-compromise
            event recorded INSIDE this path's window, else ``None``.
    """

    path_id: str
    source: str = ""
    target: str = ""
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    steps: tuple[ExecutedStep, ...] = ()
    completed: bool = False
    domain_compromise_evidence: Optional[str] = None

    @property
    def duration_seconds(self) -> Optional[float]:
        """Elapsed wall clock, or ``None`` when either end is missing.

        Wall clock is correct here: these are persisted calendar timestamps
        read back from a finished run, not a duration this process is timing.
        """
        start = parse_timestamp(self.started_at)
        end = parse_timestamp(self.completed_at)
        if start is None or end is None:
            return None
        return (end - start).total_seconds()

    @property
    def duration_display(self) -> Optional[str]:
        """The duration as a human would say it, or ``None``."""
        return format_duration(self.duration_seconds)

    @property
    def proven(self) -> bool:
        """Whether this path ran end to end with every step succeeding."""
        return bool(self.completed and self.steps) and all(
            step.succeeded for step in self.steps
        )

    @property
    def has_attempted_step(self) -> bool:
        """Whether any step ran and did not complete."""
        return any(not step.succeeded for step in self.steps)

    @property
    def succeeded_steps(self) -> tuple[ExecutedStep, ...]:
        """Only the steps the record states succeeded."""
        return tuple(step for step in self.steps if step.succeeded)


@dataclass
class _PathBuilder:
    """Mutable accumulator for one ``path_id`` while walking the event log."""

    path_id: str
    source: str = ""
    target: str = ""
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    completed: bool = False
    order: int = 0
    steps: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)
    step_order: list[tuple[str, str, str]] = field(default_factory=list)

    def step(self, key: tuple[str, str, str]) -> dict[str, Any]:
        """Return (creating on first sight) the record for one step key."""
        if key not in self.steps:
            self.steps[key] = {
                "action": key[0],
                "source": key[1],
                "target": key[2],
                "actor": None,
                "outcome": "",
                "at": None,
                "attempts": 0,
                "reason": "",
            }
            self.step_order.append(key)
        return self.steps[key]

    def build(self, *, evidence: Optional[str]) -> ExecutedPath:
        return ExecutedPath(
            path_id=self.path_id,
            source=self.source,
            target=self.target,
            started_at=self.started_at,
            completed_at=self.completed_at,
            steps=tuple(
                ExecutedStep(
                    action=self.steps[key]["action"],
                    source=self.steps[key]["source"],
                    target=self.steps[key]["target"],
                    actor=self.steps[key]["actor"],
                    outcome=self.steps[key]["outcome"],
                    at=self.steps[key]["at"],
                    attempts=self.steps[key]["attempts"],
                    reason=self.steps[key]["reason"],
                )
                for key in self.step_order
            ),
            completed=self.completed,
            domain_compromise_evidence=evidence,
        )


def _domain_events(technical_report: Any, domain: str) -> list[dict[str, Any]]:
    """Return the event list for ``domain``, or an empty list."""
    if not isinstance(technical_report, dict):
        return []
    domains = technical_report.get("domains")
    if not isinstance(domains, dict):
        return []
    payload = domains.get(domain)
    if not isinstance(payload, dict):
        return []
    events = payload.get("events")
    if not isinstance(events, list):
        return []
    return [event for event in events if isinstance(event, dict)]


def _sorted_by_clock(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Order events by their own timestamp, keeping unstamped ones in place.

    The log is normally already ordered, but a writeup that renders steps in
    file order would print an out-of-order chain the moment it is not, which is
    the class of defect this module exists to remove.
    """
    indexed = list(enumerate(events))

    def key(item: tuple[int, dict[str, Any]]) -> tuple[int, float, int]:
        index, event = item
        stamp = parse_timestamp(event.get("timestamp"))
        if stamp is None:
            # No clock to sort by: hold its original position rather than
            # sinking every unstamped event to one end.
            return (1, 0.0, index)
        return (0, stamp.timestamp(), index)

    return [event for _, event in sorted(indexed, key=key)]


def parse_executed_paths(
    technical_report: Any, domain: str
) -> tuple[ExecutedPath, ...]:
    """Return one :class:`ExecutedPath` per executed path, in wall-clock order.

    Args:
        technical_report: The workspace's ``technical_report.json`` payload.
        domain: The domain whose events to replay.

    Returns:
        The executed paths, earliest start first. Empty when the workspace
        holds no execution record (a scan that never ran a path, or a report
        that predates the event log).
    """
    events = _sorted_by_clock(_domain_events(technical_report, domain))
    builders: dict[str, _PathBuilder] = {}
    compromises: list[tuple[Optional[datetime], str]] = []

    for position, event in enumerate(events):
        details = event.get("details")
        if not isinstance(details, dict):
            continue
        timestamp = event.get("timestamp")

        if event.get("type") == _COMPROMISE_EVENT_TYPE:
            evidence = str(details.get("evidence") or "").strip()
            if evidence:
                compromises.append((parse_timestamp(timestamp), evidence))
            continue

        path_id = str(details.get("path_id") or "").strip()
        if not path_id:
            # Without the path identity there is nothing to attribute this to,
            # and attributing it anyway is how the fused chain happened.
            continue

        builder = builders.get(path_id)
        if builder is None:
            builder = _PathBuilder(path_id=path_id, order=position)
            builders[path_id] = builder

        source = str(details.get("path_source") or "").strip()
        if source and not builder.source:
            builder.source = source
        target = str(details.get("path_target") or "").strip()
        if target and not builder.target:
            builder.target = target

        stage = str(details.get("event_stage") or "").strip()
        if stage == _PATH_STARTED:
            if builder.started_at is None:
                builder.started_at = timestamp
            continue
        if stage in {_PATH_COMPLETED, _PATH_ABORTED}:
            builder.completed_at = timestamp
            builder.completed = stage == _PATH_COMPLETED
            continue

        action = str(details.get("action") or "").strip()
        if not action:
            continue
        key = (
            action,
            str(details.get("from") or "").strip(),
            str(details.get("to") or "").strip(),
        )
        step = builder.step(key)
        actor = str(details.get("actor") or "").strip()
        if actor:
            step["actor"] = actor

        if stage == _STEP_ATTEMPTING:
            step["attempts"] += 1
            continue

        status = str(details.get("step_status") or "").strip().lower()
        succeeded = stage == _STEP_SUCCEEDED or status in _SUCCESS_STATUSES
        if succeeded:
            # First success wins: it is the moment the author is placing.
            if step["outcome"] != "success":
                step["outcome"] = "success"
                step["at"] = timestamp
                step["reason"] = ""
        elif step["outcome"] != "success":
            step["outcome"] = status or (
                "blocked" if stage == _STEP_BLOCKED else "failed"
            )
            step["at"] = timestamp
            # The cause the executor recorded, verbatim. A later success clears
            # it above, so a step that eventually worked never carries the
            # reason an earlier attempt stopped.
            step["reason"] = str(details.get("reason") or "").strip()

    ordered = sorted(
        builders.values(),
        key=lambda b: (
            (0, parse_timestamp(b.started_at).timestamp())
            if parse_timestamp(b.started_at) is not None
            else (1, float(b.order))
        ),
    )
    return tuple(
        builder.build(evidence=_evidence_within(builder, compromises))
        for builder in ordered
    )


def _evidence_within(
    builder: _PathBuilder,
    compromises: list[tuple[Optional[datetime], str]],
) -> Optional[str]:
    """Return the domain-compromise evidence recorded inside this path's window.

    A ``domain_compromise`` event carries no ``path_id``, only a timestamp, so
    the clock is the only honest way to attribute it. A path with no window
    (never started, or an unparseable stamp) gets nothing rather than a guess.
    """
    start = parse_timestamp(builder.started_at)
    end = parse_timestamp(builder.completed_at)
    if start is None or end is None:
        return None
    for stamp, evidence in compromises:
        if stamp is not None and start <= stamp <= end:
            return evidence
    return None


__all__ = (
    "PROOF_SOURCE_GRAPH_EDGE",
    "ExecutedPath",
    "ExecutedStep",
    "format_duration",
    "parse_executed_paths",
    "parse_timestamp",
)
