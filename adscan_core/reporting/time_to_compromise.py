"""Time to compromise: the single most valuable fact an engagement produces.

An engagement that starts from nothing but an IP address and ends holding the
domain has one figure a board member repeats verbatim, and it is not a finding
count: it is how long it took. The scan already measures it and already persists
it (``<workspace>/scan_summary.json`` carries ``time_to_compromise_minutes``,
written by the scan-outcome seam off a monotonic clock), and until this module
existed no deliverable stated it. The free report and the paid kit both now read
the figure from here, so the two tiers cannot quote a different number or word it
differently, per ``CLAUDE.md`` § "Dual-tier reporting" (the derivation of a shared
headline figure belongs in the shared layer, never formatted twice).

The copy is the deliverable, not the decimal. ``1.55`` is a developer artifact;
"ADscan held full control of cicada.htb in 1 minute 33 seconds" is a sentence a
CISO forwards unedited. So this module owns the prose as well as the arithmetic.

Three honesty rules decide whether the figure renders at all, and they are the
reason this is a resolver rather than a formatter:

* **Only a run that reached compromise states a time to compromise.** A scan
  that did not is not a fast scan and not a slow one: there is no such duration.
  The resolver returns ``None`` and every surface OMITS the card. It never
  renders a zero, a dash or an empty slot, which would read as "compromised in
  no time at all" to the one reader who matters.
* **The clock measures what it measures.** It is the elapsed time from the start
  of this scan to proven domain compromise, from the network position the
  engagement ran from. It is not a claim about how fast any attacker would be,
  and the qualifier says exactly that in one sentence rather than a paragraph of
  hedging.
* **The zero-credential framing is asserted only when it was proven.** "Starting
  with no credentials" is what makes the number land, and it is also a factual
  claim about the entry point. It is taken from the engine's own
  unauthenticated-domain-breaker signal (the shared
  :mod:`~adscan_core.reporting.unauthenticated_reach` SSOT), never assumed from
  the scan mode. Without that proof the sentence states the time and nothing
  about the starting position.

The SECOND figure this module owns answers a different question and therefore
gets a different slot. ``duration_minutes`` is how long the whole assessment
ran, and what a CISO needs it for is capacity planning: whether recurring
validation fits inside a change window. So it lives in the scope-and-method part
of each deliverable, not on the cover, it renders even when nothing was
compromised (a clean run still costs the same window), and its label says
"assessment duration" where the other says "time to domain compromise" so no
reader can take one for the other. The two are never placed in the same slot
competing: a cover that offered both would make the reader choose which number
the document is about.

``time_to_first_cred_minutes`` is persisted beside both and is deliberately NOT
rendered. It is a weaker version of the compromise story, and two durations
competing for one slot is worse than one that lands.

Pure logic plus one small JSON read: no console, no network, no
``adscan_internal`` import. Safe to import from ``adscan_core``, the LITE
runtime, the PRO report renderer and the web backend alike.
"""

from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass
from typing import Any, Mapping, Optional

#: The persisted record the figure is read from, written at every scan-completion
#: seam by ``adscan_internal.services.scan_outcome_telemetry.write_scan_summary``.
SCAN_SUMMARY_FILENAME = "scan_summary.json"

#: The compromise-status token that means full domain control. Mirrors
#: ``SESSION_COMPROMISE_STATUS_DOMAIN`` as a stable protocol string so this module
#: stays free of any engine import.
COMPROMISE_STATUS_DOMAIN = "domain"

#: The card's key line. Identical on both tiers, so a reader who meets the free
#: report first and the paid kit later sees one label for one number.
CARD_LABEL = "Time to domain compromise"

#: The one qualifier. States the measurement's boundary without hedging the
#: result, and without implying a prediction about other attackers.
QUALIFIER = (
    "Measured from the start of this scan to proven domain compromise, on the "
    "network position this engagement ran from."
)

#: Sub-line under the figure when the entry point was proven credential-free.
CARD_SUB_UNAUTHENTICATED = "From scan start, holding no credentials"
#: Sub-line otherwise.
CARD_SUB_DEFAULT = "From the start of this scan"

#: The whole assessment's elapsed-time label. Deliberately unlike
#: :data:`CARD_LABEL`: the two figures sit in different parts of the deliverable
#: and the LABELS, not the position, are what keep a reader from reading one as
#: the other.
ASSESSMENT_DURATION_LABEL = "Assessment duration"

#: Sub-line under the assessment duration. Says which interval was measured,
#: without implying anything about what the assessment reached.
ASSESSMENT_DURATION_SUB = "Elapsed time, start to finish"


def _plural(count: int, noun: str) -> str:
    """Return ``"1 minute"`` / ``"2 minutes"``."""

    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def format_duration_prose(seconds: int) -> str:
    """Render a duration the way a person says it out loud.

    Minutes and seconds, spelled out, because this string lands inside a sentence
    a board member reads: "1 minute 33 seconds", "45 seconds", "2 minutes". A
    zero component is dropped rather than printed, and anything past an hour
    drops the seconds, which stop carrying meaning at that scale.

    Args:
        seconds: Whole seconds, at least 1.

    Returns:
        The spoken form. Empty string for a non-positive input, which the
        resolver never produces (it refuses the figure instead).
    """

    total = int(seconds)
    if total <= 0:
        return ""
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        parts = [_plural(hours, "hour")]
        if minutes:
            parts.append(_plural(minutes, "minute"))
        return " ".join(parts)
    parts = []
    if minutes:
        parts.append(_plural(minutes, "minute"))
    if secs or not parts:
        parts.append(_plural(secs, "second"))
    return " ".join(parts)


def format_duration_compact(seconds: int) -> str:
    """Render the same duration for a KPI numeral: ``1m 33s``, ``45s``, ``1h 02m``."""

    total = int(seconds)
    if total <= 0:
        return ""
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}h {minutes:02d}m"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


@dataclass(frozen=True)
class TimeToCompromise:
    """The resolved figure and every string a surface needs to render it.

    Every consumer reads the prose from here rather than composing its own, so
    the free report, the paid report and the web cannot word the same measurement
    three ways. A surface that only has room for a numeral uses
    :attr:`card_value` with :attr:`card_label`; one with room for a sentence uses
    :attr:`headline`, and the sentence is self-contained.
    """

    #: Whole seconds from scan start to proven domain compromise.
    seconds: int
    #: The persisted figure in minutes, carried through unrounded for telemetry
    #: and tests. Never rendered: a decimal of minutes is not how anyone speaks.
    minutes: float
    #: The domain the engagement took control of, as the scan recorded it. Empty
    #: when the record carries no domain, and the prose then says "the domain".
    domain_label: str
    #: True when the engine PROVED a route to full domain compromise whose entry
    #: needed no credential. Gates the zero-credential clause in the prose.
    unauthenticated_start: bool
    #: "1 minute 33 seconds".
    duration_text: str
    #: "1m 33s" — for a KPI numeral.
    card_value: str
    #: The card's key line.
    card_label: str = CARD_LABEL
    #: The card's sub-line, which carries the starting position.
    card_sub: str = CARD_SUB_DEFAULT
    #: The full sentence, self-contained and forwardable.
    headline: str = ""
    #: :attr:`headline` split around :attr:`duration_text`, so a surface can set
    #: the duration in its own emphasis without authoring the sentence or running
    #: a string replace over rendered markup. Concatenating the three parts with
    #: the duration between them reproduces :attr:`headline` exactly.
    headline_before: str = ""
    headline_after: str = ""
    #: The measurement's boundary, in one sentence.
    qualifier: str = QUALIFIER


def _positive_minutes(value: Any) -> Optional[float]:
    """Return the value as positive finite minutes, or ``None`` if it is not one.

    ``bool`` is rejected explicitly: it is an ``int`` subclass, and ``True``
    arriving here would render as a one-minute compromise.
    """

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    minutes = float(value)
    if not math.isfinite(minutes) or minutes <= 0:
        return None
    return minutes


def _domain_compromise_proven(summary: Mapping[str, Any]) -> bool:
    """True when the record attests full domain control, by either of its markers."""

    if bool(summary.get("domain_compromised")):
        return True
    status = str(summary.get("compromise_status") or "").strip().lower()
    return status == COMPROMISE_STATUS_DOMAIN


def _compose_headline(
    *, duration_text: str, domain_label: str, unauthenticated_start: bool
) -> str:
    """Compose the forwardable sentence.

    The zero-credential opening is what makes the duration land, so it leads when
    it is true. When it is not proven the sentence states the time and claims
    nothing about the starting position.
    """

    target = domain_label.strip() or "the domain"
    if unauthenticated_start:
        return (
            "Starting with no credentials and only the IP of your domain "
            f"controller, ADscan held full control of {target} in {duration_text}."
        )
    return f"ADscan held full control of {target} in {duration_text}."


def time_to_compromise_from_summary(
    summary: Any,
    *,
    unauthenticated_start: bool = False,
    domain_label: str = "",
) -> Optional[TimeToCompromise]:
    """Resolve the figure from a loaded scan-summary record. Pure, never raises.

    Args:
        summary: The parsed ``scan_summary.json`` mapping. Anything else returns
            ``None``.
        unauthenticated_start: Whether the engine PROVED a route to full domain
            compromise that began with no credential. Resolved by the caller
            through :func:`adscan_core.reporting.unauthenticated_reach.unauthenticated_domain_breaker_present`,
            because that signal lives per-domain in the technical report and this
            record does not carry it.
        domain_label: Overrides the record's own ``domain``. For a caller that
            already resolved the client-facing domain label.

    Returns:
        The resolved figure, or ``None`` when this engagement has no time to
        compromise to state (compromise unproven, or the duration absent or not a
        positive number). ``None`` means OMIT the card. Never substitute a zero.
    """

    if not isinstance(summary, Mapping):
        return None
    if not _domain_compromise_proven(summary):
        return None
    minutes = _positive_minutes(summary.get("time_to_compromise_minutes"))
    if minutes is None:
        return None
    seconds = int(round(minutes * 60))
    if seconds < 1:
        # A sub-second compromise is a measurement artifact, not a result worth
        # printing: "0 seconds" reads as a broken number rather than a fast one.
        return None

    duration_text = format_duration_prose(seconds)
    label = str(domain_label or summary.get("domain") or "").strip()
    unauth = bool(unauthenticated_start)
    headline = _compose_headline(
        duration_text=duration_text,
        domain_label=label,
        unauthenticated_start=unauth,
    )
    # Split on the LAST occurrence: the duration is the sentence's closing clause,
    # and a domain whose name happened to contain the duration text would
    # otherwise move the emphasis onto the wrong token.
    before, _, after = headline.rpartition(duration_text)
    return TimeToCompromise(
        seconds=seconds,
        minutes=minutes,
        domain_label=label,
        unauthenticated_start=unauth,
        duration_text=duration_text,
        card_value=format_duration_compact(seconds),
        card_sub=CARD_SUB_UNAUTHENTICATED if unauth else CARD_SUB_DEFAULT,
        headline=headline,
        headline_before=before,
        headline_after=after,
    )


def load_scan_summary(workspace_dir: Any) -> Optional[dict[str, Any]]:
    """Read ``<workspace_dir>/scan_summary.json``. Best-effort; ``None`` when absent.

    The one I/O half of this module, kept separate so the resolver above stays
    pure and both tiers' pure model builders can take the loaded record as an
    argument.
    """

    root = str(workspace_dir or "").strip()
    if not root:
        return None
    path = os.path.join(root, SCAN_SUMMARY_FILENAME)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            loaded = json.load(fh)
    except (OSError, ValueError):
        return None
    return loaded if isinstance(loaded, dict) else None


def load_time_to_compromise(
    workspace_dir: Any,
    *,
    unauthenticated_start: bool = False,
    domain_label: str = "",
) -> Optional[TimeToCompromise]:
    """Convenience: load the record and resolve the figure in one call."""

    return time_to_compromise_from_summary(
        load_scan_summary(workspace_dir),
        unauthenticated_start=unauthenticated_start,
        domain_label=domain_label,
    )


@dataclass(frozen=True)
class AssessmentDuration:
    """How long the whole assessment ran, and the strings a surface renders it with.

    A separate type from :class:`TimeToCompromise` on purpose. They answer
    different questions ("what does it cost to assess me" against "how fast do we
    fall"), they render in different parts of the document, and one of them gates
    on proven compromise while the other does not. Collapsing them into one
    optional-field object would make every consumer re-decide which half it is
    holding, and the first consumer to get that wrong would print a scan's
    runtime as its time to domain control.
    """

    #: Whole seconds the assessment ran, start to finish.
    seconds: int
    #: The persisted figure in minutes, carried through unrounded. Never
    #: rendered: a decimal of minutes is not how anyone speaks.
    minutes: float
    #: "2 minutes 16 seconds".
    duration_text: str
    #: "2m 16s" — for a KPI numeral.
    card_value: str
    #: The card's key line.
    card_label: str = ASSESSMENT_DURATION_LABEL
    #: The card's sub-line, naming the interval measured.
    card_sub: str = ASSESSMENT_DURATION_SUB
    #: The scope-and-method sentence, self-contained and forwardable.
    statement: str = ""


def _compose_duration_statement(duration_text: str) -> str:
    """Compose the scope-and-method sentence for the whole assessment's runtime.

    The second clause is the figure's reason for being in the document: a reader
    deciding whether to run this quarterly needs to know what window it occupies.
    It claims nothing about what the assessment found, so the sentence is equally
    true on a run that compromised the domain and on one that did not.
    """

    return (
        f"This assessment ran for {duration_text}, start to finish. That is the "
        "elapsed time to budget for repeating it on the same estate."
    )


def assessment_duration_from_summary(summary: Any) -> Optional[AssessmentDuration]:
    """Resolve the whole assessment's runtime from a loaded scan-summary record.

    Pure, never raises. Deliberately does NOT gate on proven compromise: a scan
    that found nothing still occupied the window it occupied, and that figure is
    the only time measurement such a run can honestly state.

    Args:
        summary: The parsed ``scan_summary.json`` mapping. Anything else returns
            ``None``.

    Returns:
        The resolved figure, or ``None`` when the record carries no usable
        duration (absent, non-numeric, non-positive, or under a second). ``None``
        means OMIT, exactly as it does for the compromise figure: a dash or a
        zero in the slot would read as a scan that never ran.
    """

    if not isinstance(summary, Mapping):
        return None
    minutes = _positive_minutes(summary.get("duration_minutes"))
    if minutes is None:
        return None
    seconds = int(round(minutes * 60))
    if seconds < 1:
        return None
    duration_text = format_duration_prose(seconds)
    return AssessmentDuration(
        seconds=seconds,
        minutes=minutes,
        duration_text=duration_text,
        card_value=format_duration_compact(seconds),
        statement=_compose_duration_statement(duration_text),
    )


def load_assessment_duration(workspace_dir: Any) -> Optional[AssessmentDuration]:
    """Convenience: load the record and resolve the assessment's runtime."""

    return assessment_duration_from_summary(load_scan_summary(workspace_dir))


def scan_timing_payload(
    summary: Any,
    *,
    unauthenticated_start: bool = False,
    domain_label: str = "",
) -> Optional[dict[str, Any]]:
    """Resolve BOTH figures into one JSON-safe blob, for a consumer that persists.

    This exists for the web platform, which cannot hold a frozen dataclass in
    Postgres and must not re-author the prose on its way to a browser. Both
    surfaces then render strings this module composed, so the paid platform and
    the paid PDF cannot word one measurement two ways, and a TypeScript copy of
    either sentence never has to exist.

    Args:
        summary: The parsed ``scan_summary.json`` mapping.
        unauthenticated_start: Whether the engine PROVED a no-credential route to
            full domain compromise. Resolved by the caller through the same
            :mod:`~adscan_core.reporting.unauthenticated_reach` signal the
            deliverables use, never from the scan mode.
        domain_label: Overrides the record's own ``domain``.

    Returns:
        ``{"time_to_compromise": {...}?, "assessment_duration": {...}?}`` with
        each half present only when it resolved, or ``None`` when NEITHER did.
        ``None`` means persist nothing, so a row carrying no timing is
        distinguishable from one whose scan produced no compromise.
    """

    ttc = time_to_compromise_from_summary(
        summary,
        unauthenticated_start=unauthenticated_start,
        domain_label=domain_label,
    )
    duration = assessment_duration_from_summary(summary)
    if ttc is None and duration is None:
        return None
    payload: dict[str, Any] = {}
    if ttc is not None:
        payload["time_to_compromise"] = {
            "seconds": ttc.seconds,
            "minutes": ttc.minutes,
            "domain_label": ttc.domain_label,
            "unauthenticated_start": ttc.unauthenticated_start,
            "duration_text": ttc.duration_text,
            "card_value": ttc.card_value,
            "card_label": ttc.card_label,
            "card_sub": ttc.card_sub,
            "headline": ttc.headline,
            "qualifier": ttc.qualifier,
        }
    if duration is not None:
        payload["assessment_duration"] = {
            "seconds": duration.seconds,
            "minutes": duration.minutes,
            "duration_text": duration.duration_text,
            "card_value": duration.card_value,
            "card_label": duration.card_label,
            "card_sub": duration.card_sub,
            "statement": duration.statement,
        }
    return payload


def load_scan_timing_payload(
    workspace_dir: Any,
    *,
    unauthenticated_start: bool = False,
    domain_label: str = "",
) -> Optional[dict[str, Any]]:
    """Convenience: load the record and resolve the persistable timing blob."""

    return scan_timing_payload(
        load_scan_summary(workspace_dir),
        unauthenticated_start=unauthenticated_start,
        domain_label=domain_label,
    )
