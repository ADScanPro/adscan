"""Which clock a persisted timestamp came from, and whether a report may print it.

ADscan physically steps the host wall clock to the domain controller's time
mid-scan so Kerberos and PKINIT work (``CLAUDE.md`` § "Clock and time
constraints"), and it holds host NTP off for the rest of the run. Every absolute
timestamp the scan persists after that moment therefore reads the DC's clock
while still carrying a ``+00:00`` suffix, and on exit the host clock goes back to
real time. One workspace ends up holding instants from two different clocks with
nothing on them saying which.

That is a cosmetic inconsistency almost everywhere and a real defect in exactly
one place: the containment section, which tells the client to search their own
security log at a named instant. A client who searches the wrong frame finds
nothing, and a report that pre-writes a conclusion from an empty result has
manufactured a finding about the client's own auditing out of our clock handling.
So the frame has to be recorded when the step happens and stated when the instant
is printed.

Two facts, and the module keeps them apart because they answer different
questions:

* **Which clock produced a stamp.** Resolved from the per-domain record the sync
  guard persists (:data:`CLOCK_SYNC_KEY` under ``domains_data[<domain>]``). A
  stamp taken once the host agreed with the DC is in the frame the DC's own
  Security log is written in, which is the frame a log search has to be in. A
  stamp with no record behind it is :data:`FRAME_UNVERIFIED`, never assumed.
* **Whether the stamp may be compared with the document's generation time.**
  Only when both are in the same clock. A DC-frame instant that post-dates a
  host-frame generation stamp is not a timestamp from the future, it is two
  clocks, so comparing them would suppress a correct value. An UNVERIFIED stamp
  has no such excuse: if it post-dates generation, the report cannot stand behind
  it and must not name it.

Pure logic, stdlib only. No console, no network, no ``adscan_internal`` import,
so both tiers and the web backend can read it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

__all__ = [
    "CLOCK_SYNC_KEY",
    "CLOCK_SYNC_SCHEMA_VERSION",
    "FRAME_TARGET_AGREED",
    "FRAME_UNVERIFIED",
    "StampFrame",
    "build_clock_sync_record",
    "clock_offset_phrase",
    "format_instant_for_client",
    "merge_clock_sync_record",
    "parse_iso8601",
    "resolve_stamp_frame",
    "stamp_post_dates",
]

#: Key the sync guard writes its per-domain record under, inside
#: ``domains_data[<domain>]``. Lives here rather than in the writer so the
#: reader and the writer cannot drift apart.
CLOCK_SYNC_KEY = "clock_sync"

CLOCK_SYNC_SCHEMA_VERSION = 1

#: The stamp was taken while the host clock agreed with the target domain's
#: controller, so it is in the frame that controller's own logs are written in.
FRAME_TARGET_AGREED = "target_agreed"

#: No record places this stamp in any clock. Nothing is claimed about it.
FRAME_UNVERIFIED = "unverified"


def parse_iso8601(value: Any) -> datetime | None:
    """Return an aware UTC datetime for an ISO 8601 string, or ``None``.

    Accepts a ``datetime`` unchanged, so a caller holding the real object does
    not have to round-trip it through a string. Never raises: a stamp this
    cannot parse is one no claim gets made about.
    """
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class StampFrame:
    """Which clock a persisted stamp came from.

    Attributes:
        frame: :data:`FRAME_TARGET_AGREED` or :data:`FRAME_UNVERIFIED`.
        stepped: True when the host clock was physically moved to reach that
            agreement. False means it already agreed, which is the ordinary
            case in a healthy domain.
        offset_seconds: The measured DC-minus-host offset at the moment of the
            step, when recorded. Positive when the DC was ahead.
    """

    frame: str = FRAME_UNVERIFIED
    stepped: bool = False
    offset_seconds: float | None = None

    @property
    def agrees_with_target(self) -> bool:
        """True when the stamp is in the target controller's own clock."""
        return self.frame == FRAME_TARGET_AGREED

    @property
    def comparable_to_generation(self) -> bool:
        """True when this stamp and a host-clock stamp are in the same clock.

        A DC-frame stamp is not, so the generation guard must not reject it for
        sitting after a host-frame instant.
        """
        return not self.agrees_with_target


def build_clock_sync_record(
    *,
    stepped: bool,
    offset_seconds: float | None,
    channel: str = "",
    at_iso: str = "",
) -> dict[str, Any]:
    """Return the record to persist when the clock agreed with a DC.

    ``at_iso`` is the instant on the clock as it stands AFTER any step, which is
    the boundary a later stamp is compared against.
    """
    return {
        "schema_version": CLOCK_SYNC_SCHEMA_VERSION,
        "agreed_since": str(at_iso or ""),
        "last_agreed_at": str(at_iso or ""),
        "stepped": bool(stepped),
        "offset_seconds": (
            round(float(offset_seconds), 3) if isinstance(offset_seconds, (int, float)) else None
        ),
        "channel": str(channel or ""),
    }


def merge_clock_sync_record(
    existing: Any, fresh: Mapping[str, Any]
) -> dict[str, Any]:
    """Fold a fresh agreement into one already on record for that domain.

    ``agreed_since`` is kept from the FIRST agreement and never moved forward.
    Host NTP stays off for the rest of the run, so once the clock agrees with a
    controller it keeps agreeing, and the earliest agreement is the boundary
    every later stamp sits after. Overwriting it with the latest sync would
    demote stamps taken in between to unverified and silence them.
    """
    merged = dict(fresh)
    if not isinstance(existing, Mapping):
        return merged
    first = str(existing.get("agreed_since") or "").strip()
    if first:
        merged["agreed_since"] = first
        # The offset and the step belong to the agreement that is still being
        # described, which is the first one.
        if "stepped" in existing:
            merged["stepped"] = bool(existing.get("stepped"))
        if existing.get("offset_seconds") is not None:
            merged["offset_seconds"] = existing.get("offset_seconds")
    return merged


def resolve_stamp_frame(domain_store: Any, observed_at: Any) -> StampFrame:
    """Return which clock ``observed_at`` came from, for one domain's store.

    Args:
        domain_store: ``domains_data[<domain>]`` from the workspace.
        observed_at: The persisted stamp to place.

    Returns:
        :data:`FRAME_TARGET_AGREED` only when the record proves the host clock
        already agreed with that domain's controller when the stamp was taken.
        Anything else, including a missing record and an unparseable stamp, is
        :data:`FRAME_UNVERIFIED`.
    """
    stamp = parse_iso8601(observed_at)
    if stamp is None or not isinstance(domain_store, Mapping):
        return StampFrame()
    record = domain_store.get(CLOCK_SYNC_KEY)
    if not isinstance(record, Mapping):
        return StampFrame()
    agreed_since = parse_iso8601(record.get("agreed_since"))
    if agreed_since is None or stamp < agreed_since:
        return StampFrame()
    offset = record.get("offset_seconds")
    return StampFrame(
        frame=FRAME_TARGET_AGREED,
        stepped=bool(record.get("stepped")),
        offset_seconds=float(offset) if isinstance(offset, (int, float)) else None,
    )


def format_instant_for_client(value: Any) -> str:
    """Return a stamp trimmed to the second, for an instant a client searches.

    The persisted stamp carries microseconds, which are noise in a log query
    and read as a precision the clock behind them does not have. The UTC offset
    is kept because it is part of what the client pastes. An unparseable value
    is returned unchanged rather than reshaped into something that looks
    authoritative.
    """
    parsed = parse_iso8601(value)
    if parsed is None:
        return str(value or "").strip()
    return parsed.replace(microsecond=0).isoformat()


def stamp_post_dates(observed_at: Any, generated_at: Any, *, tolerance_seconds: int = 60) -> bool:
    """True when ``observed_at`` sits after ``generated_at`` by more than the tolerance.

    The tolerance absorbs the ordinary case where a stamp and the render that
    prints it are seconds apart. Returns False when either side is unparseable:
    a comparison that cannot be made is not evidence of a problem.
    """
    stamp = parse_iso8601(observed_at)
    reference = parse_iso8601(generated_at)
    if stamp is None or reference is None:
        return False
    return (stamp - reference).total_seconds() > tolerance_seconds


def clock_offset_phrase(offset_seconds: float | None) -> str:
    """Return a client-readable span for a clock offset, or ``""`` when unknown.

    Rounded to the unit a reader uses when comparing two log windows. An offset
    small enough to be irrelevant to a day-wide search returns ``""`` so no
    sentence gets built around it.
    """
    if not isinstance(offset_seconds, (int, float)):
        return ""
    total = int(abs(float(offset_seconds)))
    if total < 120:
        return ""
    hours, remainder = divmod(total, 3600)
    minutes = remainder // 60
    if hours and minutes:
        return (
            f"{hours} {'hour' if hours == 1 else 'hours'} "
            f"{minutes} {'minute' if minutes == 1 else 'minutes'}"
        )
    if hours:
        return f"{hours} {'hour' if hours == 1 else 'hours'}"
    return f"{minutes} {'minute' if minutes == 1 else 'minutes'}"
