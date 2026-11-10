"""Data model of the coverage-aware reconciliation SSOT.

Stdlib only. See ``docs/superpowers/specs/2026-11-03-engagement-state-and-reverification-design.md``
section 5 for the rules these types carry.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Mapping, Optional


class CheckStatus(str, Enum):
    """Outcome of one check in one run."""

    RAN = "ran"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"


class Transition(str, Enum):
    """Lifecycle decision for one item in one run."""

    NEW = "new"
    STILL_PRESENT = "still_present"
    REMEDIATED = "remediated"
    REOPENED = "reopened"
    NOT_REEVALUATED = "not_reevaluated"
    TERMINAL_UNCHANGED = "terminal_unchanged"


class Vantage(IntEnum):
    """How much of the directory the run's start credential could observe."""

    UNAUTH = 0
    AUTH = 1
    PRIVILEGED_READ = 2


#: Run statuses. Only ``complete`` may close anything.
RUN_COMPLETE = "complete"
RUN_PARTIAL = "partial"
RUN_INTERRUPTED = "interrupted"
RUN_UNKNOWN = "unknown"

#: Item statuses ``PriorItem.status`` understands.
STATUS_OPEN = "open"
STATUS_REOPENED = "reopened"
STATUS_REMEDIATED = "remediated"
STATUS_ACCEPTED = "accepted"
STATUS_FALSE_POSITIVE = "false_positive"
TERMINAL_STATUSES = frozenset({STATUS_ACCEPTED, STATUS_FALSE_POSITIVE})
STATUS_ACTIVE = "active"  # attack paths (findings use STATUS_OPEN)
ACTIVE_STATUSES = frozenset({STATUS_OPEN, STATUS_ACTIVE, STATUS_REOPENED})


@dataclass(frozen=True)
class CheckCoverage:
    """What one check did, on which scope, in one run."""

    check_id: str
    status: CheckStatus
    domain_id: str
    scope_kind: str = "domain"
    examined: Optional[int] = None
    total: Optional[int] = None
    examined_ids: Optional[frozenset[str]] = None
    reason: str = ""


@dataclass(frozen=True)
class RunCoverage:
    """Coverage of one run, keyed by ``(check_id, domain_id)``."""

    run_status: str
    vantage: Vantage
    checks: Mapping[tuple[str, str], CheckCoverage] = field(default_factory=dict)
    #: Id of the run that produced this coverage. The artifacts that run wrote
    #: carry the same id, so a consumer can tell whether the coverage still
    #: describes the files on disk (``coverage_io.bind_coverage_to_artifact``).
    run_id: str = ""


@dataclass(frozen=True)
class PriorItem:
    """An item as the ledger knew it before this run."""

    item_id: str
    kind: str
    key: str
    domain_id: str
    object_id: Optional[str]
    status: str
    last_vantage: Vantage = Vantage.UNAUTH


@dataclass(frozen=True)
class Observed:
    """An item this run observed to be present."""

    item_id: str
    kind: str
    key: str
    domain_id: str
    object_id: Optional[str] = None


@dataclass(frozen=True)
class ItemResult:
    """The reconciliation decision for one item."""

    item_id: str
    transition: Transition
    reason: str = ""
