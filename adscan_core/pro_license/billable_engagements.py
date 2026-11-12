"""Billable engagements: which assessments of a domain a partner pays for.

The billing unit of a revenue-share partner is the DOMAIN, identified by its
per-partner domain code (:mod:`adscan_core.pro_license.domain_code`). Each
assessment of a code leaves one record (:class:`AssessmentRecord`): the code,
the run kind, the date, the run id and, for a recheck, its parent run. The
rule that turns records into engagements is the one agreed with partners:

1. A recheck (``adscan recheck``) NEVER opens an engagement. It re-reads what a
   previous scan found; the engagement store already records it as its own run
   with ``kind=recheck`` and a ``parent_run_id``.
2. A full scan of a code with no engagement open opens one. A full scan that
   falls inside the RETEST WINDOW of the engagement already open for that code
   is part of that engagement; at or after the window's end it opens a new one.
   The window runs from the scan that opened the engagement, never from the
   latest retest, so retests cannot chain one engagement forever.
3. The window is a licence value (``retest_window_days``), default
   :data:`DEFAULT_RETEST_WINDOW_DAYS`, read ONLY through
   :func:`resolve_retest_window_days`. Each opening scan records the window in
   force when it ran, and that window governs its engagement: a licence renewed
   with a different window does not change an engagement already sold.

Pure: no I/O and no clock. The engine (local register) and the licence server
(reconciliation) both count through :func:`count_engagements`, so the two can
never disagree on what a partner owes. Stdlib only.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

RUN_KIND_FULL_SCAN = "full_scan"
RUN_KIND_RECHECK = "recheck"
RUN_KINDS = frozenset({RUN_KIND_FULL_SCAN, RUN_KIND_RECHECK})

#: Retest window when the licence does not set one. A contractual default, not
#: a guess: the licence (and the licence server's grant) overrides it.
DEFAULT_RETEST_WINDOW_DAYS = 90
#: Upper bound on a licence's window, so a malformed value cannot make every
#: later scan of a domain free.
MAX_RETEST_WINDOW_DAYS = 730
#: The licence payload key.
RETEST_WINDOW_KEY = "retest_window_days"


def validate_retest_window_days(value: Any) -> int:
    """Return ``value`` when it is a valid window in days.

    Raises:
        ValueError: not a whole number between 0 and :data:`MAX_RETEST_WINDOW_DAYS`.
    """
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_RETEST_WINDOW_DAYS:
        raise ValueError(
            f"The retest window must be a whole number of days between 0 and {MAX_RETEST_WINDOW_DAYS}."
        )
    return value


def resolve_retest_window_days(source: Any) -> int:
    """The retest window of a licence: THE accessor for the value.

    Args:
        source: A licence payload (mapping), an object with a
            ``retest_window_days`` attribute (:class:`ProLicense`), or None.

    Returns:
        The licence's window, or :data:`DEFAULT_RETEST_WINDOW_DAYS` when it
        sets none.

    Raises:
        ValueError: the licence sets an invalid window.
    """
    if source is None:
        return DEFAULT_RETEST_WINDOW_DAYS
    if isinstance(source, Mapping):
        value = source.get(RETEST_WINDOW_KEY)
    else:
        value = getattr(source, RETEST_WINDOW_KEY, None)
    if value is None:
        return DEFAULT_RETEST_WINDOW_DAYS
    return validate_retest_window_days(value)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _parse_instant(text: Any) -> datetime | None:
    if not isinstance(text, str) or not text:
        return None
    try:
        return _utc(datetime.fromisoformat(text.replace("Z", "+00:00")))
    except ValueError:
        return None


def format_instant(value: datetime) -> str:
    """``YYYY-MM-DDTHH:MM:SSZ`` in UTC."""
    return _utc(value).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class AssessmentRecord:
    """One assessment of one domain code (a usage line).

    Attributes:
        domain_code: The per-partner code of the domain.
        run_kind: :data:`RUN_KIND_FULL_SCAN` or :data:`RUN_KIND_RECHECK`.
        assessed_at: When the assessment of that domain began (UTC).
        run_id: The engine run (the engagement store's run id).
        parent_run_id: For a recheck, the scan it re-checked.
        band: Identity band of the domain at that assessment (``pending`` until counted).
        window_days: Retest window of the licence in force (full scans only).
    """

    domain_code: str
    run_kind: str
    assessed_at: datetime
    run_id: str = ""
    parent_run_id: str = ""
    band: str = ""
    window_days: int | None = None

    def __post_init__(self) -> None:
        if self.run_kind not in RUN_KINDS:
            raise ValueError(f"'{self.run_kind}' is not a run kind ({', '.join(sorted(RUN_KINDS))}).")
        if not self.domain_code:
            raise ValueError("An assessment record needs a domain code.")
        object.__setattr__(self, "assessed_at", _utc(self.assessed_at))
        if self.window_days is not None:
            validate_retest_window_days(self.window_days)

    @property
    def is_recheck(self) -> bool:
        return self.run_kind == RUN_KIND_RECHECK

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "domain_code": self.domain_code,
            "run_kind": self.run_kind,
            "assessed_at": format_instant(self.assessed_at),
            "run_id": self.run_id,
            "parent_run_id": self.parent_run_id or None,
            "band": self.band or None,
        }
        if self.window_days is not None:
            data["retest_window_days"] = self.window_days
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AssessmentRecord | None:
        """Read a stored line; None when it cannot be one.

        A line written before ``run_kind`` existed is a full scan (rechecks
        never wrote lines then).
        """
        if not isinstance(data, Mapping):
            return None
        at = _parse_instant(data.get("assessed_at"))
        code = data.get("domain_code")
        if at is None or not isinstance(code, str) or not code:
            return None
        kind = data.get("run_kind") or RUN_KIND_FULL_SCAN
        window = data.get(RETEST_WINDOW_KEY)
        try:
            return cls(
                domain_code=code,
                run_kind=str(kind),
                assessed_at=at,
                run_id=str(data.get("run_id") or ""),
                parent_run_id=str(data.get("parent_run_id") or ""),
                band=str(data.get("band") or ""),
                window_days=window if window is not None else None,
            )
        except ValueError:
            return None


@dataclass(frozen=True)
class BillableEngagement:
    """One engagement of one domain code: what a partner owes a line for."""

    domain_code: str
    opened_at: datetime
    opened_by: str
    window_days: int
    band: str = ""
    retest_run_ids: tuple[str, ...] = ()
    recheck_run_ids: tuple[str, ...] = ()

    @property
    def retest_until(self) -> datetime:
        """First instant at which a full scan of the code opens a NEW engagement."""
        return self.opened_at + timedelta(days=self.window_days)

    def covers(self, at: datetime) -> bool:
        return self.opened_at <= _utc(at) < self.retest_until

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain_code": self.domain_code,
            "opened_at": format_instant(self.opened_at),
            "opened_by_run_id": self.opened_by,
            "retest_window_days": self.window_days,
            "retest_until": format_instant(self.retest_until),
            "band": self.band or None,
            "retest_run_ids": list(self.retest_run_ids),
            "recheck_run_ids": list(self.recheck_run_ids),
        }


def _sort_key(record: AssessmentRecord) -> tuple[datetime, str]:
    return record.assessed_at, record.run_id


def count_engagements(
    records: Iterable[AssessmentRecord], *, default_window_days: int = DEFAULT_RETEST_WINDOW_DAYS
) -> list[BillableEngagement]:
    """Group assessment records into billable engagements (rules 1-3).

    Args:
        records: Every known record, any order, any codes.
        default_window_days: Window for an opening scan that recorded none.

    Returns:
        Engagements ordered by opening time, then code.
    """
    validate_retest_window_days(default_window_days)
    ordered = sorted(records, key=_sort_key)
    opened: dict[str, list[dict[str, Any]]] = {}
    by_run: dict[tuple[str, str], dict[str, Any]] = {}
    for record in ordered:
        if record.is_recheck:
            continue
        chain = opened.setdefault(record.domain_code, [])
        current = chain[-1] if chain else None
        if current is not None and current["engagement"].covers(record.assessed_at):
            current["retests"].append(record.run_id)
        else:
            window = record.window_days if record.window_days is not None else default_window_days
            current = {
                "engagement": BillableEngagement(
                    record.domain_code, record.assessed_at, record.run_id, window, band=record.band
                ),
                "retests": [],
                "rechecks": [],
            }
            chain.append(current)
        if record.run_id:
            by_run[(record.domain_code, record.run_id)] = current
        if not current["engagement"].band and record.band and record.band != "pending":
            engagement = current["engagement"]
            current["engagement"] = BillableEngagement(
                engagement.domain_code, engagement.opened_at, engagement.opened_by, engagement.window_days, band=record.band
            )

    for record in ordered:
        if not record.is_recheck:
            continue
        target = by_run.get((record.domain_code, record.parent_run_id)) if record.parent_run_id else None
        if target is None:
            earlier = [e for e in opened.get(record.domain_code, []) if e["engagement"].opened_at <= record.assessed_at]
            target = earlier[-1] if earlier else None
        if target is not None:
            target["rechecks"].append(record.run_id)

    result = [
        BillableEngagement(
            item["engagement"].domain_code,
            item["engagement"].opened_at,
            item["engagement"].opened_by,
            item["engagement"].window_days,
            band=item["engagement"].band,
            retest_run_ids=tuple(item["retests"]),
            recheck_run_ids=tuple(item["rechecks"]),
        )
        for chain in opened.values()
        for item in chain
    ]
    return sorted(result, key=lambda e: (e.opened_at, e.domain_code))


def opens_new_engagement(
    record: AssessmentRecord,
    prior: Sequence[AssessmentRecord],
    *,
    window_days: int = DEFAULT_RETEST_WINDOW_DAYS,
) -> bool:
    """Does ``record`` open a new billable engagement, given the ``prior`` records?

    A recheck never does. A full scan does unless an engagement of its code,
    opened by an EARLIER prior record, still covers its date. ``window_days``
    is the window this record would open with (the licence in force); the
    windows of earlier engagements are the ones their opening scans recorded.
    """
    if record.is_recheck:
        return False
    earlier = [p for p in prior if p.domain_code == record.domain_code and _sort_key(p) < _sort_key(record)]
    engagements = count_engagements(earlier, default_window_days=window_days)
    return not any(e.covers(record.assessed_at) for e in engagements)


def engagement_summary(
    records: Iterable[AssessmentRecord], *, default_window_days: int = DEFAULT_RETEST_WINDOW_DAYS
) -> dict[str, Any]:
    """The engagements of ``records`` as a serialisable block (register export, reconciliation)."""
    records = list(records)
    engagements = count_engagements(records, default_window_days=default_window_days)
    attached = {run for e in engagements for run in e.recheck_run_ids}
    return {
        "engagements": [e.to_dict() for e in engagements],
        "unattached_rechecks": sorted(r.run_id for r in records if r.is_recheck and r.run_id not in attached),
    }


__all__ = [
    "AssessmentRecord",
    "BillableEngagement",
    "DEFAULT_RETEST_WINDOW_DAYS",
    "MAX_RETEST_WINDOW_DAYS",
    "RETEST_WINDOW_KEY",
    "RUN_KINDS",
    "RUN_KIND_FULL_SCAN",
    "RUN_KIND_RECHECK",
    "count_engagements",
    "engagement_summary",
    "format_instant",
    "opens_new_engagement",
    "resolve_retest_window_days",
    "validate_retest_window_days",
]
