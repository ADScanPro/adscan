"""The engagement timeline: what ADscan did, when, from where, and as whom.

A regulated client has two needs no scanner can serve, and both are answered by
the same record. They have to reconcile their own SOC alerts against the
assessment, so an alert that fired inside the window is accounted for rather
than investigated twice. And they have to show a supervisor that the privileged
logon spike in their security log was the authorised test, which means naming
the window, the host the traffic came from, and the accounts it used. ADscan is
the only party that holds those facts, so it is the only party that can write
them down.

The report already sends the client here. The credential-custody section tells
them to search "the assessment window recorded in this report's timeline" and
hands them a log query whose start boundary was an unfilled token, because no
timeline existed to fill it from. This module is the record that reference was
written against, and :func:`assessment_window` is what fills the boundary.

Three rules decide what may be written, and each of them is a line the
deliverable has already crossed once somewhere else:

* **Every instant declares which clock produced it.** The scan steps the host
  wall clock to the domain controller's for Kerberos and holds host NTP off for
  the rest of the run, so one workspace holds instants from two clocks with
  nothing on them saying which. A timeline that silently mixes them is worse
  than no timeline: a client who searches their Security log in the wrong frame
  finds nothing, and an empty result reads as a verdict about their own
  auditing. So a stamp with no declared frame cannot be constructed here
  (:class:`TimelineStamp` refuses it), and the frame travels with the instant to
  every surface. The frame itself is resolved by the shared
  :mod:`~adscan_core.reporting.clock_frame` SSOT off the per-domain record the
  sync guard persists, because this builder runs in a later process than the
  scan and the in-memory sync state is long gone.

* **It states what ADscan did, never what the client's controls did.** An action
  that failed is an action that failed. It is not evidence that an endpoint
  product caught it, and the Exposure-Validation doctrine forbids inferring one
  from the other. No entry in this record carries a claim about the client's
  defences, in either direction.

* **An unconfirmed action is recorded as attempted.** The same honesty the
  attack-step statuses already apply: :data:`OUTCOME_COMPLETED` requires a
  signal that the thing finished, :data:`OUTCOME_ATTEMPTED` is everything ADscan
  started and could not confirm, and :data:`OUTCOME_NOT_PERFORMED` is what it
  declined to run or could not run at all. An action ADscan merely began has
  never been promoted to done.

What is NOT recorded is declared rather than papered over, in
:data:`UNRECORDED_DETAIL` terms carried on the block. Per-host enumeration
contact is the significant one: collection is timestamped per phase, not per
host, so the record states the phase window and the hosts reached inside it
without implying a second-level contact log it does not have.

Pure logic plus a few small JSON reads: no console, no network, no
``adscan_internal`` import. Safe to import from ``adscan_core``, the LITE
runtime, the PRO report renderer and the web backend alike.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Sequence

from adscan_core.credential_origins import (
    NON_COMPROMISE_ORIGINS,
    ORIGIN_ADSCAN_PROVISIONED,
    adscan_created_accounts,
    mark_adscan_provisioned_origins,
)
from adscan_core.reporting.clock_frame import (
    FRAME_LABELS,
    FRAME_TARGET_AGREED,
    FRAME_UNVERIFIED,
    format_instant_for_client,
    parse_iso8601,
    resolve_stamp_frame,
)

__all__ = [
    "ENGAGEMENT_TIMELINE_KEY",
    "ENGAGEMENT_TIMELINE_SCHEMA_VERSION",
    "ENTRY_KIND_CREDENTIAL",
    "ENTRY_KIND_ENVIRONMENT_CHANGE",
    "ENTRY_KIND_PHASE",
    "ENTRY_KIND_STEP",
    "FRAME_LABELS",
    "OUTCOME_ATTEMPTED",
    "OUTCOME_COMPLETED",
    "OUTCOME_NOT_PERFORMED",
    "UNRECORDED_DETAIL",
    "UNRESOLVED_WINDOW_START",
    "AssessmentWindow",
    "TimelineEntry",
    "TimelineStamp",
    "assessment_window",
    "build_engagement_timeline",
    "engagement_timeline_view",
    "load_engagement_timeline",
    "merge_session_window_stamps",
    "read_engagement_timeline",
    "read_phase_trail",
    "vantage_sentence",
    "window_sentence",
]

#: Top-level key the block is persisted under, in ``technical_report.json`` and
#: in the renderer's ``report_data``. Workspace-scoped rather than per-domain:
#: one engagement ran once, from one host, inside one window, even when it
#: crossed three domains. Mirrors ``attack_fanout_rollup``.
ENGAGEMENT_TIMELINE_KEY = "engagement_timeline"

ENGAGEMENT_TIMELINE_SCHEMA_VERSION = 1

#: The action finished and ADscan observed it finish.
OUTCOME_COMPLETED = "completed"

#: ADscan started the action and could not confirm it finished. The default for
#: anything ambiguous, because the alternative overstates the engagement.
OUTCOME_ATTEMPTED = "attempted"

#: ADscan did not run the action: it declined for safety, the avenue was closed,
#: or the technique was unavailable on this target. Says nothing about why
#: beyond what ADscan itself decided.
OUTCOME_NOT_PERFORMED = "not_performed"

_OUTCOMES: frozenset[str] = frozenset(
    {OUTCOME_COMPLETED, OUTCOME_ATTEMPTED, OUTCOME_NOT_PERFORMED}
)

#: Re-exported from the ``clock_frame`` SSOT, which owns the frame vocabulary
#: because every surface printing an instant needs it and a second copy is how
#: two renders of one instant end up naming different clocks. Kept in this
#: module's namespace for the callers that already read it from here.
#:
#: Deliberately the SINGLE-instant map: a window or a run can be ``mixed``, one
#: stamp never can, so :class:`TimelineStamp` validating against this map cannot
#: accept a frame no instant can have.
#: Entry kinds. A phase is a window of work; a step is one action against one
#: target; a credential is the moment a principal's secret came into ADscan's
#: hands; an environment change is a modification the ledger tracks for undoing.
ENTRY_KIND_PHASE = "phase"
ENTRY_KIND_STEP = "step"
ENTRY_KIND_CREDENTIAL = "credential"
ENTRY_KIND_ENVIRONMENT_CHANGE = "environment_change"

_ENTRY_KINDS: frozenset[str] = frozenset(
    {
        ENTRY_KIND_PHASE,
        ENTRY_KIND_STEP,
        ENTRY_KIND_CREDENTIAL,
        ENTRY_KIND_ENVIRONMENT_CHANGE,
    }
)

#: What the record does not hold, keyed so a renderer prints one sentence per
#: gap rather than inventing a hedge. Declared on the block whenever the gap
#: applies, per the data-gap rule: a bounded record must never read as a
#: complete one.
UNRECORDED_DETAIL: dict[str, str] = {
    "per_host_contact": (
        "Enumeration is timestamped per phase, not per host, so this record "
        "states when each phase ran and which hosts it reached, and not the "
        "second at which any single host was first contacted."
    ),
    "source_hostname": (
        "The assessment host is identified by the address it reached your "
        "network from. Its own name is not part of this record."
    ),
    "clock_agreement": (
        "Some instants below come from the assessment host's clock with no "
        "record confirming it agreed with the target controller's. Each one "
        "says so, and for those, treat the day rather than the second as the "
        "boundary when searching your own logs."
    ),
}

#: What a log query prints when no window resolved. Lower-snake and angle
#: bracketed, the form the catalog already uses for a value the reader supplies
#: (``<privileged_account>``), so a client meets a question instead of a token
#: or a dangling reference to a section that may not be there.
UNRESOLVED_WINDOW_START = "<assessment_start_date>"

#: Execution stages that mean the action finished. Everything ADscan merely
#: began is deliberately absent: promoting ``step_attempting`` would be the
#: overclaim this module exists to prevent.
_COMPLETED_STAGES: frozenset[str] = frozenset({"step_succeeded", "path_completed"})

#: Stages that mean ADscan did not run the action at all.
_NOT_PERFORMED_STAGES: frozenset[str] = frozenset(
    {"step_blocked", "path_blocked", "path_unavailable", "path_cancelled"}
)

#: Phase statuses that mean the phase ran to its end.
_COMPLETED_PHASE_STATUSES: frozenset[str] = frozenset({"ok", "complete", "completed"})

#: Credential-acquisition markers that mean the secret was actually recovered.
#: ``executed`` is the engine's own word for a technique that ran and produced
#: the material.
_COMPLETED_ACQUISITIONS: frozenset[str] = frozenset({"executed", "recovered", "proven"})


def _text(value: Any) -> str:
    """Return a trimmed string for any value, empty for ``None``."""
    return str(value or "").strip()


@dataclass(frozen=True)
class TimelineStamp:
    """One instant, with the clock that produced it stated.

    The frame is not optional and not defaulted. A stamp whose clock nobody can
    name is the defect this whole record exists to avoid, so constructing one
    raises rather than quietly shipping an instant a client may search by.

    Attributes:
        iso: The instant, ISO 8601, trimmed to the second for a client.
        frame: :data:`~adscan_core.reporting.clock_frame.FRAME_TARGET_AGREED` or
            :data:`~adscan_core.reporting.clock_frame.FRAME_UNVERIFIED`.
    """

    iso: str
    frame: str

    def __post_init__(self) -> None:
        if not _text(self.iso):
            raise ValueError("TimelineStamp requires an instant")
        if self.frame not in FRAME_LABELS:
            raise ValueError(
                "TimelineStamp requires a declared clock frame, one of "
                f"{sorted(FRAME_LABELS)}; got {self.frame!r}. An instant whose "
                "clock cannot be named must not reach a client."
            )

    @property
    def frame_label(self) -> str:
        """Client-facing name for the clock this instant came from."""
        return FRAME_LABELS[self.frame]

    @property
    def agrees_with_target(self) -> bool:
        """True when this instant is in the target controller's own clock."""
        return self.frame == FRAME_TARGET_AGREED

    @property
    def day(self) -> str:
        """The calendar day, for a log query that opens at a safe boundary."""
        return self.iso[:10]

    def to_dict(self) -> dict[str, Any]:
        """Project into the persisted shape. The frame always travels along."""
        return {"at": self.iso, "frame": self.frame, "frame_label": self.frame_label}


@dataclass(frozen=True)
class TimelineEntry:
    """One thing ADscan did, placed in time.

    Attributes:
        stamp: When it happened, and on whose clock.
        kind: One of the :data:`ENTRY_KIND_PHASE` family.
        action: What ADscan did, in the client's terms.
        outcome: :data:`OUTCOME_COMPLETED`, :data:`OUTCOME_ATTEMPTED` or
            :data:`OUTCOME_NOT_PERFORMED`. Never inferred upward.
        domain: The domain the action touched, as the workspace recorded it.
        target: The object or host acted against, when one was recorded.
        actor: The account the action authenticated as, when one was recorded.
        ended_at: For a phase, the instant it finished, same clock as ``stamp``.
        detail: One short client-safe clause, or empty.
    """

    stamp: TimelineStamp
    kind: str
    action: str
    outcome: str
    domain: str = ""
    target: str = ""
    actor: str = ""
    ended_at: str = ""
    detail: str = ""

    def __post_init__(self) -> None:
        if self.kind not in _ENTRY_KINDS:
            raise ValueError(f"unknown timeline entry kind {self.kind!r}")
        if self.outcome not in _OUTCOMES:
            raise ValueError(
                f"unknown timeline outcome {self.outcome!r}; an action whose "
                "completion was not observed is recorded as "
                f"{OUTCOME_ATTEMPTED!r}."
            )
        if not _text(self.action):
            raise ValueError("TimelineEntry requires an action")

    def to_dict(self) -> dict[str, Any]:
        """Project into the persisted shape."""
        payload: dict[str, Any] = {
            "kind": self.kind,
            "action": self.action,
            "outcome": self.outcome,
        }
        payload.update(self.stamp.to_dict())
        for key, value in (
            ("domain", self.domain),
            ("target", self.target),
            ("actor", self.actor),
            ("ended_at", self.ended_at),
            ("detail", self.detail),
        ):
            if _text(value):
                payload[key] = _text(value)
        return payload


@dataclass(frozen=True)
class AssessmentWindow:
    """When the assessment ran, and whether the boundary can be named.

    Attributes:
        start: The opening instant, or ``""`` when none resolved.
        end: The closing instant, or ``""``.
        frame: The clock both boundaries are stated in. Empty when unresolved.
        basis: Which record the window came from, for a reader who asks.
    """

    start: str = ""
    end: str = ""
    frame: str = ""
    basis: str = ""

    @property
    def resolved(self) -> bool:
        """True when a boundary exists that a log query can open at."""
        return bool(_text(self.start))

    @property
    def frame_label(self) -> str:
        """Client-facing name for the clock, or ``""``."""
        return FRAME_LABELS.get(self.frame, "")

    @property
    def query_start(self) -> str:
        """The ``StartTime`` boundary a rendered log query prints.

        The calendar day the assessment opened, because a client needs a
        boundary certain to sit before the first action, and never an instant
        the record cannot stand behind. Degrades to an obvious fill-in.
        """
        day = _text(self.start)[:10]
        if len(day) == 10 and day[4] == "-" and day[7] == "-" and day.replace("-", "").isdigit():
            return day
        return UNRESOLVED_WINDOW_START

    def to_dict(self) -> dict[str, Any]:
        """Project into the persisted shape."""
        return {
            "start": self.start,
            "end": self.end,
            "frame": self.frame,
            "frame_label": self.frame_label,
            "basis": self.basis,
        }


@dataclass(frozen=True)
class _Vantage:
    """Where the assessment ran from, as the network saw it."""

    address: str = ""
    interface: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"address": self.address, "interface": self.interface}


@dataclass(frozen=True)
class _Account:
    """One account whose credential material the assessment came to hold.

    ``authenticated`` keeps the distinction a client cares about and ADscan can
    actually prove: holding a password hash is not the same as having logged in
    with it, and their security log only shows the second. So it is set from an
    OBSERVED sign-in (a minted ticket, the account the scan ran as, or an action
    recorded as having executed under it), never from merely holding the secret.

    Attributes:
        principal: The account, as the workspace recorded it.
        domain: The domain it lives in.
        stamp: When the material arrived, and on whose clock.
        origin: What produced the material, in the engine's own term.
        confirmed: Whether the recovery itself was observed to succeed.
        authenticated: Whether ADscan was observed to sign in as this account.
    """

    principal: str
    domain: str = ""
    stamp: TimelineStamp | None = None
    origin: str = ""
    confirmed: bool = False
    authenticated: bool = False

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "principal": self.principal,
            "domain": self.domain,
            "origin": self.origin,
            "authenticated": self.authenticated,
            "outcome": OUTCOME_COMPLETED if self.confirmed else OUTCOME_ATTEMPTED,
        }
        if self.stamp is not None:
            payload.update(self.stamp.to_dict())
        return payload


@dataclass(frozen=True)
class _Host:
    """One host ADscan acted against, and what it was to the engagement."""

    host: str
    domain: str = ""
    role: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"host": self.host, "domain": self.domain, "role": self.role}


# --- Frame resolution -------------------------------------------------------


@dataclass
class _FrameResolver:
    """Place an instant in a clock, for one workspace's per-domain records.

    Holds the ``domains_data`` mapping so every call site resolves the frame the
    same way, through the shared ``clock_frame`` SSOT, instead of each builder
    deciding for itself. A domain with no sync record yields
    :data:`~adscan_core.reporting.clock_frame.FRAME_UNVERIFIED`, which is the
    honest answer and never an assumption.
    """

    domains_data: Mapping[str, Any] = field(default_factory=dict)

    def _store_for(self, domain: str) -> Any:
        wanted = _text(domain).lower()
        if not wanted:
            return None
        for name, payload in self.domains_data.items():
            if _text(name).lower() == wanted and isinstance(payload, Mapping):
                return payload
        return None

    def stamp(self, value: Any, *, domain: str = "") -> TimelineStamp | None:
        """Return a framed stamp for ``value``, or ``None`` when unparseable."""
        instant = format_instant_for_client(value)
        if parse_iso8601(instant) is None:
            return None
        frame = resolve_stamp_frame(self._store_for(domain), value)
        return TimelineStamp(
            iso=instant,
            frame=FRAME_TARGET_AGREED if frame.agrees_with_target else FRAME_UNVERIFIED,
        )


def _humanize_kind(kind: Any) -> str:
    """Return a readable label for a ledger change kind with no provider."""
    text = _text(kind).replace("_", " ").strip()
    return text[:1].upper() + text[1:] if text else "Environment change"


# --- The builder ------------------------------------------------------------


def _phase_entries(
    phase_rows: Iterable[Mapping[str, Any]], resolver: _FrameResolver
) -> list[TimelineEntry]:
    """Turn the per-phase trail into entries. Abandoned rows are dropped.

    A row marked ``abandoned`` is a phase whose measurement was superseded
    within the same run, so it is bookkeeping rather than a second pass over the
    client's estate, and printing it would double-count the work.
    """
    out: list[TimelineEntry] = []
    for row in phase_rows:
        if not isinstance(row, Mapping) or row.get("abandoned"):
            continue
        domain = _text(row.get("domain"))
        stamp = resolver.stamp(row.get("started_at"), domain=domain)
        if stamp is None:
            continue
        title = _text(row.get("phase_title")) or _humanize_kind(row.get("phase_id"))
        if not title:
            continue
        ended = resolver.stamp(row.get("ended_at"), domain=domain)
        status = _text(row.get("status")).lower()
        out.append(
            TimelineEntry(
                stamp=stamp,
                kind=ENTRY_KIND_PHASE,
                action=title,
                outcome=(
                    OUTCOME_COMPLETED
                    if (ended is not None and status in _COMPLETED_PHASE_STATUSES)
                    else OUTCOME_ATTEMPTED
                ),
                domain=domain,
                ended_at=ended.iso if ended is not None else "",
            )
        )
    return out


def _step_outcome(stage: str, step_status: str) -> str:
    """Classify one execution event, never upward.

    The stage is the engine's own account of what happened, so it decides. A
    stage the engine added after this code was written falls through to
    :data:`OUTCOME_ATTEMPTED`, which is the direction that cannot overstate the
    engagement.
    """
    if stage in _COMPLETED_STAGES:
        return OUTCOME_COMPLETED
    if stage in _NOT_PERFORMED_STAGES:
        return OUTCOME_NOT_PERFORMED
    if stage == "path_started" and step_status == "success":
        return OUTCOME_COMPLETED
    return OUTCOME_ATTEMPTED


def _merge_outcome(first: str, second: str) -> str:
    """Return the RESOLVED outcome for two observations of one action.

    A resolution outranks the attempt that preceded it, in either direction: an
    action that completed is completed, and one ADscan declined to run is not
    performed even though it emitted a start marker first. Two observations that
    both say only "started" stay attempted.
    """
    for resolved in (OUTCOME_COMPLETED, OUTCOME_NOT_PERFORMED):
        if resolved in (first, second):
            return resolved
    return OUTCOME_ATTEMPTED


def _step_entries(
    domain: str, events: Iterable[Mapping[str, Any]], resolver: _FrameResolver
) -> list[TimelineEntry]:
    """Turn one domain's recorded execution events into entries.

    Only events that name an ACTION become entries. A path-level start or finish
    marker carries no action of its own and would add rows a client cannot act
    on.

    The engine emits one event when it BEGINS an action and another when that
    action resolves, so the same action reaches this function twice and the two
    events disagree about the outcome by design. Printing both would show the
    client one action as two, one of them permanently reading ``attempted``
    after it had in fact completed. So the pair is folded into the single action
    it describes: the instant kept is the one the action STARTED at, because
    that is the instant the client's own log recorded, and the outcome kept is
    the resolved one. Folding is keyed on the step's own identity within its
    path, so an action genuinely run twice stays two rows.
    """
    folded: dict[tuple[str, ...], TimelineEntry] = {}
    order: list[tuple[str, ...]] = []
    for event in events:
        if not isinstance(event, Mapping):
            continue
        details = event.get("details")
        details = details if isinstance(details, Mapping) else {}
        stage = _text(details.get("event_stage"))
        action = _text(details.get("action"))
        if not action:
            continue
        stamp = resolver.stamp(event.get("timestamp"), domain=domain)
        if stamp is None:
            continue
        target = _text(details.get("target_host")) or _text(details.get("to"))
        entry = TimelineEntry(
            stamp=stamp,
            kind=ENTRY_KIND_STEP,
            action=action,
            outcome=_step_outcome(stage, _text(details.get("step_status")).lower()),
            domain=domain,
            target=target,
            actor=_text(details.get("actor")),
        )
        key = (
            domain.lower(),
            _text(details.get("path_id")).lower(),
            _text(details.get("step_index")),
            action.lower(),
            target.lower(),
        )
        previous = folded.get(key)
        if previous is None:
            folded[key] = entry
            order.append(key)
            continue
        folded[key] = TimelineEntry(
            stamp=previous.stamp if previous.stamp.iso <= entry.stamp.iso else entry.stamp,
            kind=ENTRY_KIND_STEP,
            action=action,
            outcome=_merge_outcome(previous.outcome, entry.outcome),
            domain=domain,
            target=target,
            actor=previous.actor or entry.actor,
        )
    return [folded[key] for key in order]


def _change_entries(
    changes: Iterable[Mapping[str, Any]],
    resolver: _FrameResolver,
    change_kind_label: Callable[[Any], str] | None,
) -> list[TimelineEntry]:
    """Turn the change ledger into entries for what ADscan modified.

    The label for a change kind comes from the caller when it has the cleanup
    taxonomy in reach, so the timeline and the environment-modifications section
    name the same change the same way. Without a provider it degrades to the
    humanized kind rather than growing a second label vocabulary here.
    """
    out: list[TimelineEntry] = []
    for entry in changes:
        if not isinstance(entry, Mapping):
            continue
        domain = _text(entry.get("domain"))
        stamp = resolver.stamp(entry.get("registered_at"), domain=domain)
        if stamp is None:
            continue
        label = ""
        if change_kind_label is not None:
            try:
                label = _text(change_kind_label(entry.get("kind")))
            except Exception:  # noqa: BLE001 - a label never breaks the record
                label = ""
        raw_detail = entry.get("detail")
        detail = (
            _text(raw_detail.get("ca_host")) if isinstance(raw_detail, Mapping) else ""
        )
        out.append(
            TimelineEntry(
                stamp=stamp,
                kind=ENTRY_KIND_ENVIRONMENT_CHANGE,
                action=label or _humanize_kind(entry.get("kind")),
                # A modification ADscan registered is one it made. Whether it was
                # undone afterwards is the cleanup ledger's question, reported in
                # its own section, and folding it in here would answer a
                # different question in the wrong place.
                outcome=OUTCOME_COMPLETED,
                domain=domain,
                target=_text(entry.get("target")) or detail,
                actor=_text(entry.get("min_credential_principal")),
            )
        )
    return out


def _credentials(
    domains_data: Mapping[str, Any],
    resolver: _FrameResolver,
    *,
    signed_in: Mapping[str, set[str]],
) -> tuple[list[_Account], list[TimelineEntry]]:
    """Return the accounts ADscan held, and the moment each secret arrived.

    Read from the per-domain credential metadata, whose ``origins`` carry both
    the instant and the technique that produced the secret. An account with no
    recorded origin still appears, because ADscan did hold it, and it carries no
    instant rather than a guessed one.

    Args:
        domains_data: The per-domain workspace stores.
        resolver: Places each instant in a clock.
        signed_in: ``{domain_lower: {principal_lower}}`` for the accounts ADscan
            was OBSERVED to sign in as. Resolved by the caller, because the
            evidence for a sign-in sits partly in the execution events and
            partly in the workspace, and neither half is sufficient alone.
    """
    accounts: list[_Account] = []
    entries: list[TimelineEntry] = []
    for domain, payload in sorted(domains_data.items(), key=lambda kv: _text(kv[0]).lower()):
        if not isinstance(payload, Mapping):
            continue
        meta = payload.get("credentials_meta")
        meta = meta if isinstance(meta, Mapping) else {}
        stored = payload.get("credentials")
        stored = stored if isinstance(stored, Mapping) else {}
        for principal in sorted(set(stored) | set(meta), key=lambda n: _text(n).lower()):
            name = _text(principal)
            if not name:
                continue
            record = meta.get(principal)
            record = record if isinstance(record, Mapping) else {}
            origins = record.get("origins")
            origins = [o for o in (origins or []) if isinstance(o, Mapping)]
            first = origins[0] if origins else {}
            stamp = resolver.stamp(first.get("at"), domain=_text(domain))
            origin = _text(first.get("origin")) or _text(record.get("credential_origin"))
            if _text(record.get("credential_origin")).lower() == ORIGIN_ADSCAN_PROVISIONED:
                origin = ORIGIN_ADSCAN_PROVISIONED
            confirmed = _text(first.get("acquisition")).lower() in _COMPLETED_ACQUISITIONS
            accounts.append(
                _Account(
                    principal=name,
                    domain=_text(domain),
                    stamp=stamp,
                    origin=origin,
                    confirmed=confirmed,
                    authenticated=name.lower()
                    in signed_in.get(_text(domain).lower(), set()),
                )
            )
            if stamp is not None:
                entries.append(
                    TimelineEntry(
                        stamp=stamp,
                        kind=ENTRY_KIND_CREDENTIAL,
                        action=_credential_action(name, record),
                        outcome=OUTCOME_COMPLETED if confirmed else OUTCOME_ATTEMPTED,
                        domain=_text(domain),
                        actor=name,
                        detail=origin,
                    )
                )
    return accounts, entries


def _credential_action(name: str, record: Mapping[str, Any]) -> str:
    """What the moment a secret arrived means, worded by where the secret came from.

    Only a secret the assessment obtained is "recovered". The scan's own starting
    credential was supplied, and an account ADscan created carries a password
    ADscan chose; reading either as recovered client material is false.
    """
    primary = _text(record.get("credential_origin")).lower()
    if primary == ORIGIN_ADSCAN_PROVISIONED:
        return f"Set the password of {name}, an account ADscan created"
    if primary in NON_COMPROMISE_ORIGINS:
        return f"Used the supplied credential for {name}"
    return f"Recovered credential material for {name}"


def _signed_in_accounts(
    domains_data: Mapping[str, Any], step_entries: Sequence[TimelineEntry]
) -> dict[str, set[str]]:
    """Return ``{domain_lower: {principal_lower}}`` for OBSERVED sign-ins.

    Three pieces of evidence, each of them a record that an authentication
    happened rather than that a secret was held: the account the scan itself ran
    as for that domain, an account a Kerberos ticket was minted for, and the
    actor of an action recorded as having executed. An action that only reached
    ``attempted`` is deliberately excluded: it may have failed at the sign-in,
    which is the one case where claiming a logon would be wrong.
    """
    out: dict[str, set[str]] = {}

    def _add(domain: Any, principal: Any) -> None:
        name = _text(principal).lower()
        key = _text(domain).lower()
        if not name or not key:
            return
        out.setdefault(key, set()).add(name.split("@", 1)[0])

    for domain, payload in domains_data.items():
        if not isinstance(payload, Mapping):
            continue
        _add(domain, payload.get("username"))
        tickets = payload.get("kerberos_tickets")
        if isinstance(tickets, Mapping):
            for principal in tickets:
                _add(domain, principal)
    for entry in step_entries:
        if entry.outcome == OUTCOME_COMPLETED:
            _add(entry.domain, entry.actor)
    return out


def _hosts(domains_data: Mapping[str, Any], changes: Sequence[Mapping[str, Any]]) -> list[_Host]:
    """Return the hosts ADscan authenticated against or modified.

    Two sources, both of them records of a real interaction: the controller each
    domain was assessed through, and any host the change ledger names. A host
    that merely answered a port probe is NOT here, because answering a probe is
    not an action taken against it, and listing it would overstate the
    engagement's footprint.
    """
    seen: dict[str, _Host] = {}

    def _add(host: Any, domain: Any, role: str) -> None:
        name = _text(host)
        if not name:
            return
        key = name.lower()
        if key not in seen:
            seen[key] = _Host(host=name, domain=_text(domain), role=role)

    for domain, payload in sorted(domains_data.items(), key=lambda kv: _text(kv[0]).lower()):
        if not isinstance(payload, Mapping):
            continue
        _add(
            payload.get("pdc_hostname_fqdn") or payload.get("dc_fqdn") or payload.get("dc_ip"),
            domain,
            "domain controller",
        )
    for entry in changes:
        if not isinstance(entry, Mapping):
            continue
        detail = entry.get("detail")
        detail = detail if isinstance(detail, Mapping) else {}
        _add(detail.get("ca_host"), entry.get("domain"), "certification authority")
    return list(seen.values())


def _resolve_window(
    ledger: Mapping[str, Any],
    entries: Sequence[TimelineEntry],
    resolver: _FrameResolver,
    *,
    domain_hint: str,
) -> AssessmentWindow:
    """Decide the window, preferring the record written for exactly that purpose.

    The change ledger stamps the session's own opening and closing instants, so
    it is the first source. Failing that the window is inferred from the entries
    themselves, which is weaker (it opens at the first action rather than at the
    scan) and says so in its basis. A window built from entries in two different
    clocks is not a window: the frame is only stated when every boundary agrees.
    """
    start = resolver.stamp(ledger.get("scan_started_at"), domain=domain_hint)
    end = resolver.stamp(ledger.get("scan_completed_at"), domain=domain_hint)
    if start is not None:
        return AssessmentWindow(
            start=start.iso,
            end=end.iso if end is not None and end.frame == start.frame else "",
            frame=start.frame,
            basis="session record",
        )
    framed = sorted(entries, key=lambda e: e.stamp.iso)
    if not framed:
        return AssessmentWindow()
    first, last = framed[0], framed[-1]
    return AssessmentWindow(
        start=first.stamp.iso,
        end=last.stamp.iso if last.stamp.frame == first.stamp.frame else "",
        frame=first.stamp.frame,
        basis="first and last recorded action",
    )


def build_engagement_timeline(
    *,
    domains_data: Mapping[str, Any] | None = None,
    events_by_domain: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
    phase_rows: Sequence[Mapping[str, Any]] | None = None,
    environment_changes: Mapping[str, Any] | None = None,
    vantage_address: str = "",
    vantage_interface: str = "",
    change_kind_label: Callable[[Any], str] | None = None,
) -> dict[str, Any]:
    """Assemble the engagement timeline block. Pure: nothing is read from disk.

    Args:
        domains_data: ``{domain: domains_data[<domain>]}`` from the workspace
            ``variables.json``. Supplies the credentials ADscan held, the
            controller each domain was assessed through, and the per-domain
            clock-sync record every instant's frame is resolved against.
        events_by_domain: ``{domain: events}`` from ``technical_report.json``.
        phase_rows: Rows from the per-domain phase trail (``timeline.jsonl``).
        environment_changes: The resolved ledger block, whose session stamps are
            the preferred source for the window.
        vantage_address: The address the assessment reached the network from.
        vantage_interface: The interface it left by.
        change_kind_label: Optional provider turning a ledger change kind into
            its client-facing label, injected by a caller that can reach the
            cleanup taxonomy. Absent, kinds are humanized here.

    Returns:
        The block to persist. Entries are ordered by instant. Never raises: an
        input it cannot read contributes nothing rather than failing the record.
    """
    ledger = environment_changes if isinstance(environment_changes, Mapping) else {}
    raw_changes = ledger.get("changes")
    changes: list[Mapping[str, Any]] = [
        c for c in (raw_changes or []) if isinstance(c, Mapping)
    ]
    # An account the ledger records ADscan creating keeps its place among the
    # accounts ADscan signed in as (the client's logs show it), but its origin
    # says it was ADscan's own, never recovered client material.
    store = {
        _text(name): payload
        for name, payload in mark_adscan_provisioned_origins(
            domains_data or {}, adscan_created_accounts(changes)
        ).items()
        if isinstance(payload, Mapping) and _text(name)
    }
    resolver = _FrameResolver(domains_data=store)

    steps: list[TimelineEntry] = []
    for domain, events in (events_by_domain or {}).items():
        steps.extend(_step_entries(_text(domain), events or [], resolver))

    entries: list[TimelineEntry] = []
    entries.extend(_phase_entries(phase_rows or [], resolver))
    entries.extend(steps)
    entries.extend(_change_entries(changes, resolver, change_kind_label))
    accounts, credential_entries = _credentials(
        store, resolver, signed_in=_signed_in_accounts(store, steps)
    )
    entries.extend(credential_entries)
    entries.sort(key=lambda e: (e.stamp.iso, e.kind, e.action))

    hosts = _hosts(store, changes)
    domain_hint = next(iter(store), "")
    window = _resolve_window(ledger, entries, resolver, domain_hint=domain_hint)

    gaps = ["per_host_contact"]
    if vantage_address:
        gaps.append("source_hostname")
    if any(not e.stamp.agrees_with_target for e in entries) or (
        window.resolved and window.frame != FRAME_TARGET_AGREED
    ):
        gaps.append("clock_agreement")

    return {
        "schema_version": ENGAGEMENT_TIMELINE_SCHEMA_VERSION,
        "window": window.to_dict(),
        "vantage": _Vantage(
            address=_text(vantage_address), interface=_text(vantage_interface)
        ).to_dict(),
        "accounts": [a.to_dict() for a in accounts],
        "hosts": [h.to_dict() for h in hosts],
        "entries": [e.to_dict() for e in entries],
        "not_recorded": [UNRECORDED_DETAIL[key] for key in gaps if key in UNRECORDED_DETAIL],
    }


# --- Reading it back --------------------------------------------------------


def read_engagement_timeline(technical_report: Any) -> dict[str, Any] | None:
    """Return the persisted block from a loaded ``technical_report``, or ``None``."""
    if not isinstance(technical_report, Mapping):
        return None
    block = technical_report.get(ENGAGEMENT_TIMELINE_KEY)
    return dict(block) if isinstance(block, Mapping) else None


def assessment_window(block: Any) -> AssessmentWindow:
    """Return the window a persisted block records.

    The one call a containment instruction makes to fill a log-query boundary.
    An absent or malformed block yields an unresolved window, whose
    :attr:`AssessmentWindow.query_start` is the obvious fill-in rather than a
    date nothing supports.
    """
    if not isinstance(block, Mapping):
        return AssessmentWindow()
    window = block.get("window")
    if not isinstance(window, Mapping):
        return AssessmentWindow()
    frame = _text(window.get("frame"))
    return AssessmentWindow(
        start=_text(window.get("start")),
        end=_text(window.get("end")),
        frame=frame if frame in FRAME_LABELS else "",
        basis=_text(window.get("basis")),
    )


def engagement_timeline_view(block: Any) -> dict[str, Any]:
    """Turn the persisted block into the shape a renderer consumes.

    One derivation for every surface, so the PDF report and the paid web
    platform cannot word the same record differently. ``present`` is False when
    there is nothing to show, and a section must then be OMITTED rather than
    rendered empty: an empty timeline reads as an assessment that did nothing.
    """
    if not isinstance(block, Mapping):
        return {"present": False}
    entries = [e for e in (block.get("entries") or []) if isinstance(e, Mapping)]
    window = assessment_window(block)
    if not entries and not window.resolved:
        return {"present": False}
    vantage = block.get("vantage")
    vantage = vantage if isinstance(vantage, Mapping) else {}
    counts = {
        outcome: sum(1 for e in entries if _text(e.get("outcome")) == outcome)
        for outcome in sorted(_OUTCOMES)
    }
    return {
        "present": True,
        "window": window.to_dict(),
        "window_sentence": window_sentence(window),
        "vantage": dict(vantage),
        "vantage_sentence": vantage_sentence(
            _text(vantage.get("address")), _text(vantage.get("interface"))
        ),
        "accounts": [dict(a) for a in (block.get("accounts") or []) if isinstance(a, Mapping)],
        "hosts": [dict(h) for h in (block.get("hosts") or []) if isinstance(h, Mapping)],
        "entries": [dict(e) for e in entries],
        "counts": counts,
        "not_recorded": [
            _text(n) for n in (block.get("not_recorded") or []) if _text(n)
        ],
    }


def window_sentence(window: AssessmentWindow) -> str:
    """Return the window as one sentence, with the clock named.

    Empty when no window resolved, so a caller prints nothing instead of a
    sentence about an interval it cannot place.
    """
    if not window.resolved:
        return ""
    label = window.frame_label
    if window.end:
        body = f"The assessment ran from {window.start} to {window.end}"
    else:
        body = f"The assessment opened at {window.start}"
    return f"{body}, on the {label}." if label else f"{body}."


def vantage_sentence(address: str, interface: str) -> str:
    """Return where the assessment ran from, as one sentence.

    The address is what the client's own logs recorded as the source, which is
    the fact they need to match an alert against. Empty when no address was
    recorded.
    """
    host = _text(address)
    if not host:
        return ""
    sentence = f"Every action below originated from {host}"
    nic = _text(interface)
    if nic:
        sentence += f", over the {nic} interface"
    return sentence + "."


# --- Loading a workspace ----------------------------------------------------


def _read_json(path: str) -> Any:
    """Return parsed JSON for a path, or ``None``. Never raises."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def read_phase_trail(workspace_dir: str) -> list[Mapping[str, Any]]:
    """Return every per-domain phase row under the workspace. Never raises.

    Public because the writer at scan end builds from the LIVE shell rather
    than from ``variables.json`` on disk, and still needs this half of the
    record, which only exists on disk.
    """
    from adscan_core.workspace_domain_buckets import (  # noqa: PLC0415
        is_reserved_domain_bucket,
    )

    rows: list[Mapping[str, Any]] = []
    domains_root = os.path.join(workspace_dir, "domains")
    try:
        names = sorted(os.listdir(domains_root))
    except OSError:
        return rows
    # The engagement timeline is a CLIENT-FACING deliverable section, and it
    # attributes each row to a domain. A reserved bucket is not one, so it is
    # filtered here rather than left to depend on the bucket having no timeline.
    names = [name for name in names if not is_reserved_domain_bucket(name)]
    for name in names:
        path = os.path.join(domains_root, name, "timeline.jsonl")
        try:
            with open(path, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(row, Mapping):
                        rows.append(row)
        except OSError:
            continue
    return rows


def merge_session_window_stamps(
    environment_changes: Any, workspace_dir: Any
) -> dict[str, Any]:
    """Return a ledger block carrying the SESSION's own opening and closing stamps.

    The on-disk ledger (``environment_changes.json``) is the one record that
    stamps when the session opened and closed, which is the strongest source for
    the window. A caller-supplied block is fresher about the CHANGES but is often
    the projection stored on the report, which carries no session stamps. So the
    two are merged rather than one replacing the other: taking the caller's block
    whole silently demotes the window to "first and last recorded action", a
    boundary that opens AFTER the scan did and therefore excludes the start of
    the very activity a client is trying to account for.

    Args:
        environment_changes: The caller's block, or ``None``.
        workspace_dir: Workspace root holding the on-disk ledger.

    Returns:
        The merged block. Never raises.
    """
    on_disk = _read_json(os.path.join(str(workspace_dir or ""), "environment_changes.json"))
    on_disk = on_disk if isinstance(on_disk, Mapping) else {}
    if not isinstance(environment_changes, Mapping):
        return dict(on_disk)
    merged = dict(environment_changes)
    for key in ("scan_started_at", "scan_completed_at"):
        if not _text(merged.get(key)) and _text(on_disk.get(key)):
            merged[key] = on_disk[key]
    return merged


def load_engagement_timeline(
    workspace_dir: Any,
    *,
    environment_changes: Mapping[str, Any] | None = None,
    change_kind_label: Callable[[Any], str] | None = None,
) -> dict[str, Any]:
    """Read a workspace and build its timeline. Never raises.

    The one entry point a caller without the live session needs, so the writer
    at scan end and a later render both derive the record the same way.

    Args:
        workspace_dir: Workspace root holding ``variables.json``,
            ``technical_report.json``, ``environment_changes.json`` and the
            per-domain phase trail.
        environment_changes: A caller holding a fresher ledger block passes it
            and it wins; ``None`` reads ``environment_changes.json``.
        change_kind_label: See :func:`build_engagement_timeline`.

    Returns:
        The block, or an empty mapping on any read failure.
    """
    try:
        root = str(workspace_dir or "").strip()
        if not root:
            return {}
        variables = _read_json(os.path.join(root, "variables.json"))
        variables = variables if isinstance(variables, Mapping) else {}
        report = _read_json(os.path.join(root, "technical_report.json"))
        report = report if isinstance(report, Mapping) else {}
        ledger = merge_session_window_stamps(environment_changes, root)
        domains = report.get("domains")
        events = {
            _text(name): (payload.get("events") or [])
            for name, payload in (domains or {}).items()
            if isinstance(payload, Mapping)
        }
        domains_data = variables.get("domains_data")
        return build_engagement_timeline(
            domains_data=domains_data if isinstance(domains_data, Mapping) else {},
            events_by_domain=events,
            phase_rows=read_phase_trail(root),
            environment_changes=ledger,
            vantage_address=_text(variables.get("myip")),
            vantage_interface=_text(variables.get("interface")),
            change_kind_label=change_kind_label,
        )
    except Exception:  # noqa: BLE001 - a report must ship
        return {}
