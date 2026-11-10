"""The per-run observation record (``observations.json``, ``adscan.observations/1``).

One entry per run, per domain, per check, written by the code that performed the
check at the moment it ran. Everything else that answers "was this checked" is a
VIEW of this record, so the answers cannot drift apart:

* :func:`coverage_from_observations` is the :class:`RunCoverage` reconciliation
  reads (``coverage.json`` is its persisted projection);
* :func:`positive_observations` is the set of compliance positives the run may
  green (the three-state doctrine: only an observed-good, complete reading);
* the recheck plan (Phase 6) reads :func:`observation_for` to tell which
  detector re-observes an item and what it found last time.

Outcomes. ``clear`` (the check ran and found nothing), ``finding`` (the check ran
and found something), ``observed`` (the check ran; its per-item results live in
the findings and the graph, as for a whole collection phase), ``not_assessed``
(the check did not run, with its reason) and ``failed`` (it was attempted and
errored). Completeness is a separate axis: a check that ran on part of its scope
is ``complete=False`` and names what it examined, so it can only vouch for those
objects.

Raw instances. An observation may carry ``instances``: the unsuppressed,
per-object rows the detector saw (for example one row per principal and
certificate template for an AD CS escalation). That is the raw "who can do what"
view execution needs, beside the judged graph clients see.

Stdlib only: the web backend and LITE on Windows import this package.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

from adscan_core.engagement.model import (
    RUN_UNKNOWN,
    CheckCoverage,
    CheckStatus,
    RunCoverage,
    Vantage,
)

OBSERVATIONS_SCHEMA = "adscan.observations/1"
OBSERVATIONS_FILENAME = "observations.json"


class Outcome(str, Enum):
    """What one check concluded in one run, for one domain."""

    CLEAR = "clear"
    FINDING = "finding"
    OBSERVED = "observed"
    NOT_ASSESSED = "not_assessed"
    FAILED = "failed"


#: Outcomes meaning the check actually ran.
RAN_OUTCOMES = frozenset({Outcome.CLEAR, Outcome.FINDING, Outcome.OBSERVED})

# Result precedence when two observations of the same check are merged: a single
# positive detection anywhere makes the domain's outcome a finding.
_RESULT_RANK = {Outcome.OBSERVED: 0, Outcome.CLEAR: 1, Outcome.FINDING: 2}


@dataclass(frozen=True)
class CheckObservation:
    """What one check did and found, for one domain, in one run.

    Attributes:
        check_id: Stable detector-family id (``cve.zerologon``, ``adcs.esc4``,
            ``posture.ldap_signing``) or a coarse phase check id.
        domain_id: The domain the observation covers (coverage domain key).
        outcome: See :class:`Outcome`.
        scope_kind: ``domain``, ``object``, ``host`` (what ``examined`` counts).
        complete: Whether the check covered its whole scope.
        examined: How many objects were examined (``None`` when not counted).
        total: How many were in scope (``None`` when unknown).
        examined_ids: Object ids examined, when the check covered only part of
            its scope and can name what it did cover.
        vantage: Vantage the check observed from (``None``: the run's).
        reason: Stable reason code for a non-run, an incomplete run or a failure.
        positive_key: Compliance positive this observation greens when it is a
            complete ``clear``; empty when the check carries none.
        instances: Raw per-object rows the detector saw (may be empty).
        source: Who wrote it: ``detector``, ``phase`` or ``explicit``.
    """

    check_id: str
    domain_id: str
    outcome: Outcome
    scope_kind: str = "domain"
    complete: bool = True
    examined: Optional[int] = None
    total: Optional[int] = None
    examined_ids: Optional[frozenset[str]] = None
    vantage: Optional[Vantage] = None
    reason: str = ""
    positive_key: str = ""
    instances: tuple[Mapping[str, Any], ...] = ()
    source: str = "detector"

    @property
    def ran(self) -> bool:
        """Whether the check actually ran."""
        return self.outcome in RAN_OUTCOMES


@dataclass(frozen=True)
class ObservationRecord:
    """All observations of one run, keyed by ``(check_id, domain_id)``."""

    run_id: str
    run_status: str
    vantage: Vantage
    observations: Mapping[tuple[str, str], CheckObservation] = field(default_factory=dict)


def _join_reasons(*reasons: str) -> str:
    parts: list[str] = []
    for reason in reasons:
        for part in str(reason or "").split(","):
            part = part.strip()
            if part and part not in parts:
                parts.append(part)
    return ",".join(parts)


def _sum(a: Optional[int], b: Optional[int]) -> Optional[int]:
    if a is None and b is None:
        return None
    return (a or 0) + (b or 0)


def _union(
    a: Optional[frozenset[str]], b: Optional[frozenset[str]]
) -> Optional[frozenset[str]]:
    if a is None and b is None:
        return None
    return frozenset(a or ()) | frozenset(b or ())


def merge_observations(a: CheckObservation, b: CheckObservation) -> CheckObservation:
    """Combine two observations of the same check and domain from one run.

    A detector that reports per host or per object (a CVE probe per host, an AD
    CS detection per authority) records several observations of one check; the
    run keeps one entry. The merge is conservative on completeness (never more
    complete than its least complete part, and a part that did not run makes the
    whole incomplete) and decisive on the result (one finding makes it a
    finding). Order does not matter.
    """
    if a.ran and b.ran:
        outcome = a.outcome if _RESULT_RANK[a.outcome] >= _RESULT_RANK[b.outcome] else b.outcome
        complete = a.complete and b.complete
    elif a.ran or b.ran:
        outcome = a.outcome if a.ran else b.outcome
        complete = False
    else:
        outcome = Outcome.FAILED if Outcome.FAILED in (a.outcome, b.outcome) else Outcome.NOT_ASSESSED
        complete = False
    vantages = [v for v in (a.vantage, b.vantage) if v is not None]
    return CheckObservation(
        check_id=a.check_id,
        domain_id=a.domain_id,
        outcome=outcome,
        scope_kind=a.scope_kind if a.scope_kind == b.scope_kind else "object",
        complete=complete,
        examined=_sum(a.examined, b.examined),
        total=_sum(a.total, b.total) if a.total is not None and b.total is not None else (
            a.total if a.total is not None else b.total
        ),
        examined_ids=_union(a.examined_ids, b.examined_ids),
        vantage=min(vantages) if vantages else None,
        reason=_join_reasons(a.reason, b.reason),
        positive_key=a.positive_key or b.positive_key,
        instances=tuple(a.instances) + tuple(b.instances),
        source=a.source if a.source == b.source else "detector",
    )


def _to_coverage(observation: CheckObservation) -> CheckCoverage:
    if observation.outcome is Outcome.NOT_ASSESSED:
        status = CheckStatus.SKIPPED
    elif observation.outcome is Outcome.FAILED:
        status = CheckStatus.FAILED
    elif observation.complete:
        status = CheckStatus.RAN
    else:
        status = CheckStatus.PARTIAL
    return CheckCoverage(
        check_id=observation.check_id,
        status=status,
        domain_id=observation.domain_id,
        scope_kind=observation.scope_kind,
        examined=observation.examined,
        total=observation.total,
        examined_ids=observation.examined_ids,
        reason=observation.reason,
    )


def coverage_from_observations(record: ObservationRecord) -> RunCoverage:
    """Project the record into the :class:`RunCoverage` reconciliation reads."""
    return RunCoverage(
        run_status=record.run_status,
        vantage=record.vantage,
        checks={key: _to_coverage(obs) for key, obs in record.observations.items()},
        run_id=record.run_id,
    )


def positive_observations(record: ObservationRecord) -> list[CheckObservation]:
    """Observations that may green a compliance control, ordered by key.

    Only a complete ``clear`` reading carrying a ``positive_key``: a partial
    reading, a finding, a check that did not run and an inferred absence all stay
    out (they are grey, never green).
    """
    return [
        obs
        for _key, obs in sorted(record.observations.items())
        if obs.outcome is Outcome.CLEAR and obs.complete and obs.positive_key
    ]


def observation_for(
    record: ObservationRecord, check_id: str, domain_id: str
) -> Optional[CheckObservation]:
    """The run's observation of one check on one domain, or ``None``."""
    return record.observations.get((check_id, str(domain_id or "").lower()))


# ---------------------------------------------------------------------------
# Document IO (fail-closed reader, deterministic writer).
# ---------------------------------------------------------------------------

_VANTAGE_NAMES = {
    "unauth": Vantage.UNAUTH,
    "auth": Vantage.AUTH,
    "privileged_read": Vantage.PRIVILEGED_READ,
}
_VANTAGE_TOKENS = {v: k for k, v in _VANTAGE_NAMES.items()}


def unknown_record() -> ObservationRecord:
    """The record of a run nothing is known about: closes nothing, greens nothing."""
    return ObservationRecord(run_id="", run_status=RUN_UNKNOWN, vantage=Vantage.UNAUTH)


def _observation_to_entry(obs: CheckObservation) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "check_id": obs.check_id,
        "domain_id": obs.domain_id,
        "outcome": obs.outcome.value,
        "scope_kind": obs.scope_kind,
        "complete": obs.complete,
        "examined": obs.examined,
        "total": obs.total,
        "reason": obs.reason,
        "source": obs.source,
    }
    if obs.examined_ids is not None:
        entry["examined_ids"] = sorted(obs.examined_ids)
    if obs.vantage is not None:
        entry["vantage"] = _VANTAGE_TOKENS[obs.vantage]
    if obs.positive_key:
        entry["positive_key"] = obs.positive_key
    if obs.instances:
        entry["instances"] = [dict(i) for i in obs.instances]
    return entry


def observation_record_to_document(
    record: ObservationRecord, *, extra: Optional[Mapping[str, Any]] = None
) -> dict[str, Any]:
    """Serialise a record into the ``adscan.observations/1`` document."""
    doc: dict[str, Any] = {
        "schema": OBSERVATIONS_SCHEMA,
        "run_id": record.run_id,
        "run_status": record.run_status,
        "vantage": _VANTAGE_TOKENS[record.vantage],
        "observations": [
            _observation_to_entry(obs) for _key, obs in sorted(record.observations.items())
        ],
    }
    if extra:
        doc.update(extra)
    return doc


def _int(value: Any) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _parse_entry(raw: Any) -> Optional[CheckObservation]:
    if not isinstance(raw, Mapping):
        return None
    check_id = str(raw.get("check_id") or "").strip()
    domain_id = str(raw.get("domain_id") or "").strip().lower()
    if not check_id or not domain_id:
        return None
    try:
        outcome = Outcome(str(raw.get("outcome") or ""))
    except ValueError:
        outcome = Outcome.FAILED
    ids = raw.get("examined_ids")
    raw_instances = raw.get("instances")
    instances = tuple(
        dict(i) for i in (raw_instances if isinstance(raw_instances, list) else [])
        if isinstance(i, Mapping)
    )
    vantage_token = raw.get("vantage")
    return CheckObservation(
        check_id=check_id,
        domain_id=domain_id,
        outcome=outcome,
        scope_kind=str(raw.get("scope_kind") or "domain"),
        # A record that does not say it was complete is read as incomplete.
        complete=raw.get("complete") is True,
        examined=_int(raw.get("examined")),
        total=_int(raw.get("total")),
        examined_ids=frozenset(str(i) for i in ids) if isinstance(ids, list) else None,
        vantage=_VANTAGE_NAMES.get(str(vantage_token)) if vantage_token else None,
        reason=str(raw.get("reason") or ""),
        positive_key=str(raw.get("positive_key") or ""),
        instances=instances,
        source=str(raw.get("source") or "detector"),
    )


def observation_record_from_document(doc: Any) -> ObservationRecord:
    """Parse a document; anything foreign or malformed reads as :func:`unknown_record`."""
    if not isinstance(doc, Mapping) or doc.get("schema") != OBSERVATIONS_SCHEMA:
        return unknown_record()
    observations: dict[tuple[str, str], CheckObservation] = {}
    raw_list = doc.get("observations")
    for raw in raw_list if isinstance(raw_list, list) else []:
        parsed = _parse_entry(raw)
        if parsed is None:
            continue
        key = (parsed.check_id, parsed.domain_id)
        observations[key] = (
            merge_observations(observations[key], parsed) if key in observations else parsed
        )
    return ObservationRecord(
        run_id=str(doc.get("run_id") or ""),
        run_status=str(doc.get("run_status") or RUN_UNKNOWN),
        vantage=_VANTAGE_NAMES.get(str(doc.get("vantage") or ""), Vantage.UNAUTH),
        observations=observations,
    )


def load_observation_record(directory: str) -> ObservationRecord:
    """Load ``<directory>/observations.json``; unknown when absent or invalid."""
    path = Path(directory) / OBSERVATIONS_FILENAME
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return unknown_record()
    return observation_record_from_document(doc)


def with_observations(
    record: ObservationRecord, observations: Iterable[CheckObservation]
) -> ObservationRecord:
    """Return ``record`` with ``observations`` merged in (pure helper)."""
    merged = dict(record.observations)
    for obs in observations:
        key = (obs.check_id, obs.domain_id)
        merged[key] = merge_observations(merged[key], obs) if key in merged else obs
    return replace(record, observations=merged)


__all__ = (
    "OBSERVATIONS_FILENAME",
    "OBSERVATIONS_SCHEMA",
    "RAN_OUTCOMES",
    "CheckObservation",
    "ObservationRecord",
    "Outcome",
    "coverage_from_observations",
    "load_observation_record",
    "merge_observations",
    "observation_for",
    "observation_record_from_document",
    "observation_record_to_document",
    "positive_observations",
    "unknown_record",
    "with_observations",
)
