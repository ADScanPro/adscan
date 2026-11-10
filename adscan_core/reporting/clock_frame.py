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
  Agreement is a BOUNDARY only on a run that physically stepped the clock: when
  nothing moved it, one clock produced every instant in the run and the recorded
  agreement is just the moment it was measured. See
  :func:`resolve_frame_from_record`.
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
    "FRAME_LABELS",
    "FRAME_SUMMARY_LABELS",
    "FRAME_TARGET_AGREED",
    "FRAME_MIXED",
    "FRAME_UNVERIFIED",
    "StampFrame",
    "build_clock_sync_record",
    "clock_offset_phrase",
    "combine_window_frame",
    "format_instant_for_client",
    "frame_label",
    "merge_clock_sync_record",
    "parse_iso8601",
    "resolve_frame_from_record",
    "resolve_stamp_frame",
    "stamp_post_dates",
    "summarize_stamp_frame",
    "summary_frame_label",
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

#: A run-level stamp that agrees with some assessed domains' controllers and not
#: others (see :func:`summarize_stamp_frame`), or a WINDOW whose two boundaries
#: disagree (see :func:`combine_window_frame`). Never a single instant: a stamp
#: came from exactly one clock.
FRAME_MIXED = "mixed"

#: Client-facing name for each clock a SINGLE instant can have come from. The
#: unverified label names the clock AND says the agreement is unconfirmed, so a
#: reader never has to guess which log to search by.
#:
#: Lives here rather than beside any one renderer because every surface that
#: prints an instant needs it: the engagement timeline, the containment
#: instruction, the per-host endpoint-defense export. A second copy is how two
#: renders of one instant end up naming different clocks.
FRAME_LABELS: dict[str, str] = {
    FRAME_TARGET_AGREED: "target domain controller clock",
    FRAME_UNVERIFIED: "assessment host clock, agreement with the target unconfirmed",
}

#: Client-facing name for the frame of a SPAN: a window, or one run across
#: several domains. Adds :data:`FRAME_MIXED`, which a single instant can never
#: be, so a renderer cannot label one stamp with a frame no stamp can have.
FRAME_SUMMARY_LABELS: dict[str, str] = {
    **FRAME_LABELS,
    FRAME_MIXED: "two clocks, so treat the day rather than the second as the boundary",
}


def frame_label(frame: Any) -> str:
    """Client-facing name for the clock one instant came from, or ``""``.

    ``""`` for anything that is not a frame a single instant can have, including
    :data:`FRAME_MIXED`: an unnamed clock prints nothing rather than a guess.
    """
    return FRAME_LABELS.get(str(frame or ""), "")


def summary_frame_label(frame: Any) -> str:
    """Client-facing name for the frame of a window or a whole run, or ``""``."""
    return FRAME_SUMMARY_LABELS.get(str(frame or ""), "")


def combine_window_frame(first: Any, second: Any) -> str:
    """Return the frame of a span whose two boundaries carry their own frames.

    A span is in one clock only when both of its boundaries are, so two frames
    that disagree make it :data:`FRAME_MIXED` rather than silently inheriting
    either one. A boundary with no frame contributes nothing: one placed
    boundary describes the span, and neither placed leaves it
    :data:`FRAME_UNVERIFIED`.

    This is what a tabular surface needs. A column and a ``min()`` have nowhere
    to put a caveat, so the frame has to be a value they can carry.
    """
    frames = [
        str(value or "")
        for value in (first, second)
        if str(value or "") in FRAME_LABELS
    ]
    if not frames:
        return FRAME_UNVERIFIED
    return frames[0] if len(set(frames)) == 1 else FRAME_MIXED


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
    # ``stepped`` answers "did the wall clock move during this run", which is a
    # fact about the RUN and not about any one agreement, so it is sticky in
    # either direction. Keeping only the first agreement's value loses a later
    # step, and both the frame boundary below and the run-level guard in
    # :func:`summarize_stamp_frame` rest on this field: a lost step would place
    # a stamp in a clock it never came from.
    if existing.get("stepped") or fresh.get("stepped"):
        merged["stepped"] = True
    first = str(existing.get("agreed_since") or "").strip()
    if first:
        merged["agreed_since"] = first
        # The offset belongs to the agreement that is still being described,
        # which is the first one.
        if existing.get("offset_seconds") is not None:
            merged["offset_seconds"] = existing.get("offset_seconds")
    return merged


def resolve_stamp_frame(domain_store: Any, observed_at: Any) -> StampFrame:
    """Return which clock ``observed_at`` came from, for one domain's store.

    Args:
        domain_store: ``domains_data[<domain>]`` from the workspace.
        observed_at: The persisted stamp to place.

    Returns:
        See :func:`resolve_frame_from_record`. A store carrying no record places
        nothing: :data:`FRAME_UNVERIFIED`, never assumed.
    """
    if not isinstance(domain_store, Mapping):
        return StampFrame()
    return resolve_frame_from_record(domain_store.get(CLOCK_SYNC_KEY), observed_at)


def resolve_frame_from_record(record: Any, observed_at: Any) -> StampFrame:
    """Return which clock ``observed_at`` came from, for one sync record.

    The store-free half of :func:`resolve_stamp_frame`, so a caller holding the
    record alone (a report block baked in an earlier process, which has no
    ``domains_data`` in reach) resolves the frame through the same rule instead
    of its own.

    ``agreed_since`` records when agreement was CONFIRMED, and whether it is
    also a FRAME BOUNDARY depends entirely on ``stepped``:

    * ``stepped`` is True: the wall clock was physically moved to reach that
      agreement, so an instant taken before it genuinely came from a different
      clock and no record places it.
    * ``stepped`` is False: nothing moved the clock and host NTP is held off for
      the rest of the run, so ONE clock produced every instant in it. A pre-sync
      stamp sits in the same frame as a post-sync one, and ``agreed_since`` is
      only the moment the agreement was measured.

    Reading the boundary without consulting ``stepped`` marked a stamp
    unverified on every run against a healthy domain, because the change
    ledger's ``scan_started_at`` is written before the first DC contact and is
    therefore structurally earlier than the first sync.

    Returns:
        :data:`FRAME_TARGET_AGREED` when the record places the stamp in that
        domain's controller's clock. Anything else, including a missing record,
        a record with no agreement instant and an unparseable stamp, is
        :data:`FRAME_UNVERIFIED`. ``stepped`` and ``offset_seconds`` describe
        the RUN and are carried either way, because an unplaced stamp on a run
        that moved the clock is a different thing from one on a run that did
        not, and a caller deciding what to print needs to tell them apart.
    """
    if not isinstance(record, Mapping):
        return StampFrame()
    offset = record.get("offset_seconds")
    run = StampFrame(
        frame=FRAME_UNVERIFIED,
        stepped=bool(record.get("stepped")),
        offset_seconds=float(offset) if isinstance(offset, (int, float)) else None,
    )
    stamp = parse_iso8601(observed_at)
    agreed_since = parse_iso8601(record.get("agreed_since"))
    if stamp is None or agreed_since is None:
        return run
    if run.stepped and stamp < agreed_since:
        return run
    return StampFrame(
        frame=FRAME_TARGET_AGREED,
        stepped=run.stepped,
        offset_seconds=run.offset_seconds,
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


def summarize_stamp_frame(
    domain_stores: Any, observed_at: Any, *, clock_released: bool
) -> dict[str, Any]:
    """Place one RUN-level stamp (a run summary, a manifest) across every domain.

    A run-level document names no domain, so it states one frame for all of
    them: :data:`FRAME_TARGET_AGREED` when the stamp agrees with every assessed
    domain's controller, :data:`FRAME_MIXED` when with some, otherwise
    :data:`FRAME_UNVERIFIED`.

    ``clock_released`` says the run has already handed the host clock back (NTP
    restored at exit). A stamp taken then, on a run that STEPPED the clock, may
    read either clock, so it is :data:`FRAME_UNVERIFIED` whatever the records say;
    a run that agreed without stepping kept one clock throughout.

    Returns:
        ``{"frame": <frame>, "stepped": <any domain's agreement needed a step>}``.
    """
    stores = [store for store in (domain_stores or ()) if isinstance(store, Mapping)]
    frames = [resolve_stamp_frame(store, observed_at) for store in stores]
    stepped = any(frame.stepped for frame in frames)
    agreed = [frame.agrees_with_target for frame in frames]
    if not frames or (clock_released and stepped) or not any(agreed):
        frame_name = FRAME_UNVERIFIED
    elif all(agreed):
        frame_name = FRAME_TARGET_AGREED
    else:
        frame_name = FRAME_MIXED
    return {"frame": frame_name, "stepped": stepped}
