"""Endpoint defense: what was observed on the client's hosts, and what it did.

Two different questions, deliberately kept apart, because conflating them is
how this section would mislead:

* **Coverage** — on the hosts ADscan interacted with, was an antivirus or
  endpoint-detection product observed active? This is NOT an estate-coverage
  survey, and must never be rendered as one (see below).
* **Efficacy** — of the credential-extraction techniques ADscan ran on a host
  where a product was CONFIRMED active, how many completed anyway?

Why there is no "EDR coverage %" here, and why adding one would be the worst
number in the deliverable
--------------------------------------------------------------------------
ADscan fingerprints the hosts it has reason to touch, not the estate. Measured
on a real engagement: 173 computers in the directory, 8 fingerprinted, all 8
with a product active. Both obvious percentages are false. "100% of hosts have
endpoint protection active" is true of the 8 and a fiction about the 173.
"4.6% coverage" is worse, because it reports 165 hosts as unprotected when the
truth is that they were never measured. So this module reports COUNTS and an
explicit not-assessed population, never a coverage rate, and the statement
names the unmeasured hosts in the first breath rather than in a footnote.

Why efficacy is the honest headline
-----------------------------------
Its denominator is sound by construction: it counts only attempts ADscan
actually ran on hosts where a product's presence was independently confirmed.
"On 12 hosts with the product confirmed active, 9 credential extractions
completed" is a fact, it needs no inference, and it is the finding a CISO acts
on. The inverse framing a client might expect ("N% were correctly blocked") is
deliberately absent: see ``build_endpoint_defense``.

Five posture states, never two
------------------------------
A product list is not a verdict. ``classify_host_posture`` is the SSOT that
keeps apart the five readings an empty or partial product list can have, so no
consumer has to re-derive them and get it wrong:

================== =========================================================
``active``         A product was observed running with real-time protection.
``installed_      A product is installed but NOT active (service disabled,
inactive``         or real-time protection off). Worse than absent: it is
                   protection the client believes they have. A finding.
``none_detected``  The host was probed and no product was found. This is NOT
                   a claim that the host has none.
``undetermined``   The probe did not complete. UNKNOWN, never clean.
``not_assessed``   The host was never fingerprinted at all.
================== =========================================================

Pure logic: no IO, no console, no network. Safe to import from ``adscan_core``,
the LITE runtime, the PRO report renderer and the web backend alike. Mirrors
:mod:`adscan_core.reporting.host_enrichment_coverage` and
:mod:`adscan_core.reporting.cracking_coverage` (build / view / merge trio).
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from adscan_core.reporting.privilege_tier_labels import (
    TIER0_TOKENS,
    TIER_RANK,
    UNGRADED_TIER_LABEL,
    privilege_tier_label_for_token,
    privilege_tier_token_rank,
    set_privilege_tier_label_provider,
    token_is_tier0,
)

#: Per-domain key this block is stamped under, in ``technical_report.json`` and
#: in the renderer's ``report_data``. One name, so the writer, the PDF, the LITE
#: report and the web platform cannot drift apart on where the record lives.
ENDPOINT_DEFENSE_KEY = "endpoint_defense"

# ── Posture states (see the module docstring table) ────────────────────────
POSTURE_ACTIVE = "active"
POSTURE_INSTALLED_INACTIVE = "installed_inactive"
POSTURE_NONE_DETECTED = "none_detected"
POSTURE_UNDETERMINED = "undetermined"
POSTURE_NOT_ASSESSED = "not_assessed"

#: Ordered worst-reading-first, for a stable render and a deterministic merge.
POSTURE_STATES = (
    POSTURE_ACTIVE,
    POSTURE_INSTALLED_INACTIVE,
    POSTURE_NONE_DETECTED,
    POSTURE_UNDETERMINED,
    POSTURE_NOT_ASSESSED,
)

#: The states that need somebody to do something, worst-reading first. This is
#: what a size-bounded surface should list, instead of a slice of every
#: examined host: the ``active`` rows are the good news and carry no action,
#: and on a large estate they are also the bulk of the rows. The counts above
#: already cover every host, so dropping the good news from a table loses
#: nothing and keeps a 10,000-host engagement from producing a 200-page
#: section.
#:
#: ``installed_inactive`` leads because it reads worst: it is protection the
#: host appears to have and does not, which is more dangerous than none at all
#: because nobody is looking for it.
POSTURE_EXCEPTION_STATES = (
    POSTURE_INSTALLED_INACTIVE,
    POSTURE_NONE_DETECTED,
    POSTURE_UNDETERMINED,
)

# ── Technique outcomes ─────────────────────────────────────────────────────
#: The technique produced its result.
OUTCOME_COMPLETED = "completed"
#: The technique was interrupted on every retry, on the credential-bearing
#: stage. The one outcome that supports an interference assessment, and only
#: when the host's posture is ``active`` (a confirmed product).
OUTCOME_INTERRUPTED = "interrupted"
#: Did not complete, for a reason not determined. Never counted as a defensive
#: success: the Exposure-Validation doctrine forbids crediting a control that
#: was not observed.
OUTCOME_INCOMPLETE = "incomplete"

OUTCOME_TOKENS = (OUTCOME_COMPLETED, OUTCOME_INTERRUPTED, OUTCOME_INCOMPLETE)

#: Not an attempt outcome: the LABEL for a technique-host row whose folded
#: attempts disagree (it completed at least once AND was interrupted at
#: least once). It is never written to an attempt record, only derived, so
#: it stays out of OUTCOME_TOKENS.
OUTCOME_MIXED = "mixed"

#: Client-facing wording for a technique-host row's outcome. `Mixed` has to
#: say what it mixes, or the reader is left to guess whether it is good news.
#: Ordering ranks for the stamped ``privilege_tier`` tokens, highest
#: criticality first. Mirrors ``compromise_class.PrivilegeTier.rank`` (which it
#: cannot import: this module is dependency-light on purpose, because the web
#: backend imports it), and a test asserts the two never diverge.
#:
#: Only the ORDER lives here. The client-facing LABEL does NOT: it is owned by
#: ``compromise_class.privilege_tier_label`` and reaches this module through the
#: shared provider seam, so the tier badge on an endpoint-defense row and the
#: one on a finding's affected assets cannot word the same tier differently. A
#: second local label map was written first and had already drifted ("Tier 2"
#: against the SSOT's "Tier 2: Standard") before it was deleted.
#:
#: The tokens, the order and the provider now live ONCE in
#: ``privilege_tier_labels``, because the password-hygiene block needs exactly
#: the same seam: a second copy of the tokens is how a second copy of the labels
#: starts. These names stay as this module's own API (the report render and the
#: web both import them from here) and are re-exported, never redefined.
_TIER_RANK = TIER_RANK
_TIER0_TOKENS = TIER0_TOKENS


def _tier_rank(tier: Any) -> int:
    """Sort rank for a stamped tier; an unknown tier sorts last, never first."""
    return privilege_tier_token_rank(tier)


def _is_tier0(tier: Any) -> bool:
    return token_is_tier0(tier)


def _tier_badge_label(tier: Any) -> str:
    """The client-facing wording for one host's tier badge.

    An ABSENT tier words itself "Not graded", taken from the one owner of that
    string, because a host the assessment could not place must never read as
    harmless. A tier that IS stamped but cannot be worded (the label provider
    was not installed) stays EMPTY on purpose: wording it "Not graded" would
    tell the client the assessment never placed a host it did place, and on a
    Tier-0 host that is the same falsehood class as guessing the tier.

    Renderers print this verbatim and carry no fallback of their own. They used
    to, and a hardcoded "Not graded" in the report template, in the exception
    worklist and in the web panel was both a third copy of a label the tier
    SSOT owns and the mechanism that turned an unworded Tier-0 host into an
    ungraded one.
    """
    token = str(tier or "").strip()
    if not token:
        return UNGRADED_TIER_LABEL
    return privilege_tier_label_for_token(token)


#: How a credential read reached the data. Recorded per attempt at the dump
#: seam, and client-facing because the two are materially different facts: a
#: read that writes nothing leaves the SOC no file artifact to look for, so an
#: absent alert proves far less than it would against a hive written to the
#: host and removed again. It also grades the exposure, because a read needing
#: no disk write is the harder one to catch.
METHOD_IN_PLACE = "inline"
METHOD_EXPORTED = "savekey"

METHOD_LABELS: dict[str, str] = {
    METHOD_IN_PLACE: "Read in place, no file written",
    METHOD_EXPORTED: "Hive exported to the host, then removed",
}


def read_method_label(method: Any) -> str:
    """The client-facing label for a read method, or "" when unrecorded.

    Empty for an unrecorded method, and that is the point: "no file written"
    is a claim about the engagement's footprint that a reader may act on, so
    it is never inferred from a missing field.
    """
    return METHOD_LABELS.get(str(method or "").strip().lower(), "")


OUTCOME_LABELS: dict[str, str] = {
    OUTCOME_COMPLETED: "Completed",
    OUTCOME_INTERRUPTED: "Interrupted every attempt",
    OUTCOME_INCOMPLETE: "Undetermined",
    OUTCOME_MIXED: "Completed and interrupted",
}


#: One client-facing label per state. Lives here, not in a renderer, because
#: three surfaces name these states (the report, the appendix CSV and the
#: platform) and a state named differently in two of them is the same drift
#: this module exists to prevent. Deliberately not the raw token: a person
#: reads these, and "installed_inactive" is not a sentence.
POSTURE_STATE_LABELS: dict[str, str] = {
    POSTURE_ACTIVE: "Product observed active",
    POSTURE_INSTALLED_INACTIVE: "Installed, not active",
    POSTURE_NONE_DETECTED: "No product detected",
    POSTURE_UNDETERMINED: "Could not be determined",
    POSTURE_NOT_ASSESSED: "Not examined",
}


def posture_state_label(posture: Any) -> str:
    """The client-facing label for a state token."""
    token = str(posture or "")
    return POSTURE_STATE_LABELS.get(token, token or "Unknown")


#: Strength order for folding several invocations of one technique on one host
#: into a single outcome. Higher wins.
_OUTCOME_RANK = {
    OUTCOME_INCOMPLETE: 0,
    OUTCOME_INTERRUPTED: 1,
    OUTCOME_COMPLETED: 2,
}


def _outcome_rank(outcome: str) -> int:
    return _OUTCOME_RANK.get(outcome, 0)


def classify_host_posture(products: Any, posture_assessed: Any) -> str:
    """Classify one host's endpoint posture into one of :data:`POSTURE_STATES`.

    The SSOT for the distinction every consumer would otherwise re-derive.
    ``posture_assessed`` is authoritative for "could we tell at all": a host
    whose probe failed carries an empty product list exactly like a host where
    nothing was found, and reading the first as unprotected is a finding the
    evidence does not support.

    A host absent from the posture records entirely is :data:`POSTURE_NOT_ASSESSED`
    and is classified by the caller, not here, since this function only sees
    hosts that have a record.

    Args:
        products: The host's product entries. Each may carry ``active``, or the
            lower-level ``installed`` / ``running`` / ``realtime_protection``
            from which activity is derived by the runtime; ``active`` is
            preferred when present.
        posture_assessed: Whether the posture was determined. ``None`` (a record
            predating the flag) is treated as NOT assessed, the conservative
            direction.

    Returns:
        One of :data:`POSTURE_STATES`, never :data:`POSTURE_NOT_ASSESSED`.
    """
    rows = [p for p in (products or ()) if isinstance(p, Mapping)]
    any_active = any(_product_is_active(p) for p in rows)
    if any_active:
        # An observed active product is a fact regardless of a partial probe
        # error, so it outranks the assessed flag.
        return POSTURE_ACTIVE
    if posture_assessed is not True:
        return POSTURE_UNDETERMINED
    if rows:
        return POSTURE_INSTALLED_INACTIVE
    return POSTURE_NONE_DETECTED


def _product_is_active(product: Mapping[str, Any]) -> bool:
    """Whether one product entry reads as actively protecting the host.

    Prefers the runtime's own derived ``active``. Falls back to the same rule
    the runtime applies (``DetectedProduct.active``): process-running AND
    real-time protection on, where running is either observed directly or
    implied by an auto-start service.
    """
    if "active" in product:
        return bool(product.get("active"))
    running = bool(product.get("running"))
    installed = bool(product.get("installed"))
    try:
        svc_start = int(product.get("svc_start"))
    except (TypeError, ValueError):
        svc_start = -1
    process_running = running or (installed and svc_start in (0, 1, 2))
    return process_running and bool(product.get("realtime_protection", True))


def _product_names(products: Any) -> list[str]:
    """The distinct product names on a host, order preserved."""
    names: list[str] = []
    for product in products or ():
        if not isinstance(product, Mapping):
            continue
        name = str(product.get("name") or "").strip()
        if name and name not in names:
            names.append(name)
    return names


def _coverage_statement(
    *,
    assessed: int,
    estate: int,
    counts: Mapping[str, int],
    estate_known: bool = True,
) -> str:
    """The client-facing sentence for what was and was not observed.

    Leads with the boundary, not the result. A reader who takes only the first
    clause away must still have the correct picture, which is why the
    unmeasured population comes first whenever there is one.

    ``estate_known`` is the honesty gate on the DENOMINATOR. When the
    directory's computer total could not be read, the sentence must not fall
    back to the examined count and assert "all N computers in the directory":
    that reads as complete coverage of the estate, which is the dangerous
    direction, and a sysadmin disproves it with one cmdlet. An unknown
    denominator is stated as unknown, exactly as an unexamined host is stated
    as unexamined rather than as unprotected.
    """
    not_assessed = max(0, int(counts.get(POSTURE_NOT_ASSESSED, 0)))
    if assessed <= 0:
        return (
            "No host's antivirus or endpoint-detection posture was determined "
            "during this assessment, so this report makes no statement about "
            "endpoint protection on any host."
        )

    if not estate_known:
        lead = (
            f"Endpoint protection was examined on {assessed:,} "
            f"{'computer' if assessed == 1 else 'computers'}. The directory's "
            "total computer count was not available to this assessment, so "
            "this is not a share of your estate."
        )
    elif not_assessed > 0:
        lead = (
            f"Endpoint protection was examined on {assessed:,} of the "
            f"{estate:,} computers in the directory. The remaining "
            f"{not_assessed:,} were not examined, which is not a statement "
            "that they are unprotected."
        )
    else:
        lead = (
            f"Endpoint protection was examined on all {assessed:,} computers "
            "in the directory."
        )

    observed: list[str] = []
    if counts.get(POSTURE_ACTIVE):
        observed.append(f"{counts[POSTURE_ACTIVE]:,} had a product observed active")
    if counts.get(POSTURE_INSTALLED_INACTIVE):
        observed.append(
            f"{counts[POSTURE_INSTALLED_INACTIVE]:,} had a product installed "
            "but not active"
        )
    if counts.get(POSTURE_NONE_DETECTED):
        observed.append(f"on {counts[POSTURE_NONE_DETECTED]:,} no product was detected")
    if counts.get(POSTURE_UNDETERMINED):
        observed.append(
            f"on {counts[POSTURE_UNDETERMINED]:,} the check could not be completed"
        )
    if not observed:
        return lead
    return f"{lead} Of those examined, {_join_clauses(observed)}."


def _join_clauses(parts: list[str]) -> str:
    """Join clauses as readable prose rather than a comma list."""
    if len(parts) == 1:
        return parts[0]
    return ", ".join(parts[:-1]) + " and " + parts[-1]


def _efficacy_statement(
    *,
    techniques: int,
    hosts: int,
    attempts: int,
    pairs: int,
    tier0_completed: int = 0,
    tier0_mixed: int = 0,
    remaining: int | None = None,
    completed_only: int = 0,
    mixed: int,
    interrupted_only: int,
    incomplete: int,
) -> str:
    """The client-facing sentence for what the observed products did.

    Counts in the unit each figure actually measures: techniques are
    techniques, hosts are DISTINCT hosts, attempts are attempts, and the
    outcomes are per technique-and-host combination, which is one row of the
    table beneath it. Reporting one technique run against two hosts as "two
    techniques" was wrong in the noun, and a reader who then counted the rows
    found a different number.

    A host where the same read COMPLETED on some attempts and was INTERRUPTED
    on others is reported as exactly that. Collapsing it to its strongest
    outcome hid the more useful operational fact: against that host the
    interference was not consistent. That is a finding for the client's own
    SOC, not a detail to average away.

    It states only what was observed. It never reports a block rate, and never
    says a product blocked, prevented or stopped anything: in the completed
    cases it demonstrably did not, and in the interrupted cases we cannot know
    whether another method would have succeeded. Crediting a control with
    succeeding is the false positive-control the Exposure-Validation doctrine
    forbids.
    """
    if pairs <= 0:
        return ""

    # Named first and separately, because WHICH host it was changes what the
    # fact means. Credential material recovered from a Tier 0 host, with its
    # product confirmed active, is the sentence a CISO acts on; folded into a
    # combined count it reads the same as a workstation and it is not the same.
    # Still no claim that anything was blocked: it demonstrably was not.
    tier0_clause = ""
    if tier0_completed:
        one = tier0_completed == 1
        tier0_clause = (
            f" On {tier0_completed:,} Tier 0 {'host' if one else 'hosts'}, the "
            f"{'one that controls' if one else 'ones that control'} the "
            "domain's identity, the extraction completed and recovered "
            "credential material with the endpoint product confirmed active."
        )
        if tier0_mixed:
            tier0_clause += (
                " On that host the read was also cut off on other attempts, "
                "so the interference was not consistent."
                if tier0_mixed == 1 and one
                else (
                    f" On {tier0_mixed:,} of them the read was also cut off on "
                    "other attempts, so the interference was not consistent."
                )
            )

    head = (
        f"ADscan ran {techniques:,} credential-extraction "
        f"{'technique' if techniques == 1 else 'techniques'} against "
        f"{hosts:,} {'host' if hosts == 1 else 'hosts'} where an endpoint "
        f"product was confirmed active, over {attempts:,} "
        f"{'attempt' if attempts == 1 else 'attempts'}."
    )

    # One combination needs no preamble counting them, and reads far better
    # without it. Several do, and the count has to be the row count of the
    # table below or the reader finds two different numbers for one thing.
    head = f"{head}{tier0_clause}"

    if pairs == 1 and not tier0_completed:
        if completed_only:
            return (
                f"{head} The extraction completed and recovered credential "
                "material despite endpoint protection being active."
            )
        if mixed:
            return (
                f"{head} It completed on some attempts and was interrupted on "
                "others, so the interference was not consistent."
            )
        if interrupted_only:
            return (
                f"{head} Every attempt was interrupted, assessed with high "
                "confidence as the endpoint protection on that host "
                "interrupting the read."
            )
        return f"{head} It did not complete for a reason that was not determined."

    parts: list[str] = []
    if completed_only:
        parts.append(
            f"in {completed_only:,} the extraction completed and recovered "
            "credential material despite endpoint protection being active"
        )
    if mixed:
        parts.append(
            f"in {mixed:,} it completed on some attempts and was interrupted "
            "on others, so the interference was not consistent"
        )
    if interrupted_only:
        parts.append(
            f"in {interrupted_only:,} every attempt was interrupted, assessed "
            "with high confidence as the endpoint protection on "
            f"{'that host' if interrupted_only == 1 else 'those hosts'} "
            "interrupting the read"
        )
    if incomplete:
        parts.append(
            f"in {incomplete:,} it did not complete for a reason that was not "
            "determined"
        )
    if not parts:
        return head
    # Counted over what is LEFT once the Tier 0 sentence has had its say, so a
    # reader adding the clauses up against the table is never handed a host
    # twice.
    left = pairs if remaining is None else remaining
    if left <= 0:
        return head
    if left == 1 and len(parts) == 1:
        # "Of the other 1, in 1 every attempt was interrupted" is the count
        # said twice about one thing. One combination is named, not counted.
        clause = parts[0]
        if clause.startswith("in 1 "):
            clause = clause[len("in 1 ") :]
        return f"{head} On the remaining combination, {clause}."
    lead = (
        f"Of the {left:,} technique and host combinations"
        if tier0_completed == 0
        else f"Of the other {left:,}"
    )
    return f"{head} {lead}, {_join_clauses(parts)}."


def _order_observations(observations: list[dict[str, Any]]) -> None:
    """Order one row's attempts in place, chronologically and robustly.

    Sorting by the wall-clock stamp alone is wrong here: ADscan steps the host
    clock mid-scan to sync with the DC, so two attempts either side of that
    step can sort backwards and the report would print a window running in
    reverse. Within one process a monotonic reading cannot move backwards, so
    it decides the order there; across processes only the wall clock has any
    shared meaning, so sessions are ordered by their own earliest stamp. The
    value DISPLAYED is always the wall clock, which is the only thing the
    client can search for.
    """
    if len(observations) < 2:
        return
    earliest: dict[str, str] = {}
    for obs in observations:
        session = str(obs.get("session_id") or "")
        stamp = str(obs.get("observed_at") or "")
        if stamp and (session not in earliest or stamp < earliest[session]):
            earliest[session] = stamp
    session_rank = {
        session: rank
        for rank, session in enumerate(
            sorted(earliest, key=lambda s: (earliest.get(s, ""), s))
        )
    }

    def _key(obs: Mapping[str, Any]) -> tuple[int, float, str]:
        session = str(obs.get("session_id") or "")
        monotonic = obs.get("observed_monotonic")
        return (
            session_rank.get(session, len(session_rank)),
            float(monotonic) if isinstance(monotonic, (int, float)) else 0.0,
            str(obs.get("observed_at") or ""),
        )

    observations.sort(key=_key)


def build_endpoint_defense(
    *,
    posture_hosts: Iterable[Any] = (),
    attempts: Iterable[Any] = (),
    computers_in_estate: int = 0,
    attempts_recorded: bool = True,
    host_tiers: Mapping[str, str] | None = None,
    host_names: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build the ``endpoint_defense`` block for one domain.

    Args:
        posture_hosts: The per-host posture records, as persisted in
            ``inventory/defensive_posture.json`` (``products``,
            ``posture_assessed``, ``dns_name``, ``host_object_id``).
        attempts: The per-technique attempt records (``technique``, ``host``,
            ``outcome``, ``host_posture``, ``products``). One row per
            credential-extraction technique ADscan ran.
        computers_in_estate: Total computers in the directory, the only honest
            context for the examined count. Never used as a coverage
            denominator; see the module docstring.
        host_names: Optional recorded host to the searchable NAME the
            workspace resolved for it, injected for the same reason as
            ``host_tiers``. A dump records whatever the operator targeted,
            usually an address, and the section asks the client to find the
            event in their own console: a console is indexed by hostname, so an
            address is the one identifier that does not help. The address is
            still shown, because it is what correlates with a network log.
        host_tiers: Optional host name to stamped ``privilege_tier`` token,
            injected by the caller because this module cannot import the tier
            classifier. Keys are matched case-insensitively against every
            alias the caller supplies. Recovering credential material from a
            Tier 0 host with its product confirmed active is a materially
            worse finding than the same read on a workstation, so the tier
            leads the ordering and the prose. An absent entry makes no claim.
        attempts_recorded: Whether attempt recording was active for this scan
            at all. ``False`` means a workspace predating the record, where
            "no attempts" is unknown rather than observed, so no efficacy
            claim is made.

    Returns:
        The block to persist. Always carries ``statement`` so the recorder
        accepts it, and ``present`` so every surface shares one gate.
    """
    tiers = {
        str(key).strip().lower(): str(value).strip().lower()
        for key, value in (host_tiers or {}).items()
        if str(key).strip() and str(value).strip()
    }

    def _tier_for(host: str) -> str:
        return tiers.get(str(host).strip().lower(), "")

    names = {
        str(key).strip().lower(): str(value).strip()
        for key, value in (host_names or {}).items()
        if str(key).strip() and str(value).strip()
    }

    def _name_for(host: str) -> str:
        """The searchable name for a recorded host, or "" when it IS one."""
        resolved = names.get(str(host).strip().lower(), "")
        return "" if resolved.strip().lower() == str(host).strip().lower() else resolved

    counts: dict[str, int] = {state: 0 for state in POSTURE_STATES}
    hosts: list[dict[str, Any]] = []

    for record in posture_hosts or ():
        if not isinstance(record, Mapping):
            continue
        products = record.get("products")
        state = classify_host_posture(products, record.get("posture_assessed"))
        counts[state] = counts.get(state, 0) + 1
        host_name = str(
            record.get("dns_name") or record.get("host_object_id") or ""
        ).strip()
        host_tier = _tier_for(host_name)
        hosts.append(
            {
                "host": host_name,
                "posture": state,
                "products": _product_names(products),
                "privilege_tier": host_tier,
                "privilege_tier_label": _tier_badge_label(host_tier),
            }
        )

    hosts.sort(key=lambda h: (POSTURE_STATES.index(h["posture"]), h["host"].lower()))
    assessed = len(hosts)
    # Decided on the RAW input, because the clamp below hides the difference:
    # a count of 0 (the inventory was missing or unreadable) and a count
    # SMALLER than what was examined (a stale or partial inventory) are both
    # "unknown", and neither may become "all N computers in the directory".
    raw_estate = int(computers_in_estate or 0)
    estate_known = raw_estate >= assessed > 0
    estate = max(assessed, raw_estate)
    counts[POSTURE_NOT_ASSESSED] = max(0, estate - assessed)

    # Efficacy counts ONLY attempts on a host with a confirmed-active product.
    # An attempt on an unprotected or undetermined host says nothing about any
    # product, so mixing it in would corrupt the one figure here whose
    # denominator is sound.
    #
    # One ROW per technique per host, so re-running a dump while working a
    # host does not inflate the count (8 recorded invocations over 2
    # technique-host pairs, measured on a real engagement). But the row keeps
    # every attempt it folded, with its timestamp and its own outcome, for two
    # reasons. A host whose read COMPLETED on some attempts and was
    # INTERRUPTED on others is a real and more useful finding than either
    # outcome alone, and collapsing it to the strongest hid it. And the report
    # asks the client to correlate these events in their own console, which
    # needs the host and the time, not a count.
    by_pair: dict[tuple[str, str], dict[str, Any]] = {}

    for record in attempts or ():
        if not isinstance(record, Mapping):
            continue
        technique = str(record.get("technique") or "").strip() or "unknown"
        host = str(record.get("host") or "").strip()
        posture = str(record.get("host_posture") or "")
        outcome = str(record.get("outcome") or "").strip().lower()
        if outcome not in OUTCOME_TOKENS:
            outcome = OUTCOME_INCOMPLETE
        observed_at = str(record.get("observed_at") or "").strip()

        key = (technique, host)
        pair = by_pair.get(key)
        if pair is None:
            pair = by_pair[key] = {
                "technique": technique,
                "host": host,
                "posture": posture,
                "outcome": outcome,
                "products": _product_names(record.get("products")),
                "attempts": 0,
                OUTCOME_COMPLETED: 0,
                OUTCOME_INTERRUPTED: 0,
                OUTCOME_INCOMPLETE: 0,
                "observations": [],
                "methods": set(),
            }
        pair["attempts"] = int(pair["attempts"]) + 1
        pair[outcome] = int(pair[outcome]) + 1
        monotonic = record.get("observed_monotonic")
        method = str(record.get("source_method") or "").strip().lower()
        pair["methods"].add(method)
        pair["observations"].append(
            {
                "observed_at": observed_at,
                "outcome": outcome,
                "session_id": str(record.get("session_id") or ""),
                "observed_monotonic": (
                    float(monotonic) if isinstance(monotonic, (int, float)) else None
                ),
                # Three states, not two. ABSENT means the record predates the
                # stamp, so whether the clock had been stepped is UNKNOWN and
                # no claim is made about it; only an explicit False is an
                # attempt we know was recorded before the sync. Treating
                # absent as False would have the report assert, about every
                # older workspace, something it never observed.
                "clock_synced_to_dc": (
                    bool(record.get("clock_synced_to_dc"))
                    if "clock_synced_to_dc" in record
                    else None
                ),
            }
        )
        # The row's single `outcome` keeps the STRONGEST observed, because a
        # single success proves the exposure and reporting it as a failure
        # would understate what the client is exposed to. `mixed` below is
        # what stops that from erasing the inconsistency.
        if _outcome_rank(outcome) > _outcome_rank(str(pair["outcome"])):
            pair["outcome"] = outcome
        if posture:
            pair["posture"] = posture
        for name in _product_names(record.get("products")):
            if name not in pair["products"]:
                pair["products"].append(name)

    for pair in by_pair.values():
        _order_observations(pair["observations"])
        stamps = [
            str(o.get("observed_at") or "")
            for o in pair["observations"]
            if str(o.get("observed_at") or "")
        ]
        pair["first_observed_at"] = stamps[0] if stamps else ""
        pair["last_observed_at"] = stamps[-1] if stamps else ""
        # An attempt stamped before the host clock was stepped to the DC
        # carries whatever offset the host had, so its wall-clock time is the
        # one the client may not find. Counting them lets the report qualify
        # the window instead of asserting a precision it does not have.
        pair["attempts_before_clock_sync"] = sum(
            1 for o in pair["observations"] if o.get("clock_synced_to_dc") is False
        )
        pair["mixed"] = bool(
            int(pair[OUTCOME_COMPLETED]) and int(pair[OUTCOME_INTERRUPTED])
        )
        pair["outcome_label"] = OUTCOME_MIXED if pair["mixed"] else str(pair["outcome"])
        # "No file written" may only be claimed when EVERY folded attempt says
        # so. One exported hive among them means a file WAS written on that
        # host, and an unrecorded method means we do not know, so neither case
        # may inherit the quieter claim.
        # Every attempt must have recorded a method before the quieter claim
        # can stand. One export means a file WAS written on this host. One
        # UNRECORDED attempt means it could have been an export, so the claim
        # is unsupportable and nothing is said: the same rule the rest of this
        # section follows, where an unexamined host is never reported as
        # unprotected.
        methods = set(pair.pop("methods", set()))
        if METHOD_EXPORTED in methods:
            pair["read_method"] = METHOD_EXPORTED
        elif methods == {METHOD_IN_PLACE}:
            pair["read_method"] = METHOD_IN_PLACE
        else:
            pair["read_method"] = ""
        pair["read_method_label"] = read_method_label(pair["read_method"])
        pair["host_name"] = _name_for(str(pair["host"]))
        pair_tier = _tier_for(str(pair["host"]))
        pair["privilege_tier"] = pair_tier
        pair["privilege_tier_label"] = _tier_badge_label(pair_tier)

    by_technique: dict[str, dict[str, Any]] = {}
    attempts_total = 0
    on_protected = 0
    attempts_on_protected = 0
    completed = 0
    interrupted = 0
    incomplete = 0
    mixed_hosts = 0
    tier0_completed = 0
    tier0_mixed = 0

    for pair in by_pair.values():
        attempts_total += int(pair["attempts"])
        if str(pair["posture"]) != POSTURE_ACTIVE:
            continue
        outcome = str(pair["outcome"])
        on_protected += 1
        attempts_on_protected += int(pair["attempts"])
        if bool(pair["mixed"]):
            mixed_hosts += 1
        if outcome == OUTCOME_COMPLETED:
            completed += 1
            # The headline of this whole section, and its own bucket. Credential
            # material came out of a host that controls the identity plane while
            # its product was confirmed active: a materially worse fact than the
            # same read on a workstation, which is why it is stated first and
            # NOT counted again in the generic clause (saying it twice in weaker
            # words only dilutes the stronger sentence).
            if _is_tier0(pair.get("privilege_tier")):
                tier0_completed += 1
                if bool(pair["mixed"]):
                    tier0_mixed += 1
        elif outcome == OUTCOME_INTERRUPTED:
            interrupted += 1
        else:
            incomplete += 1

        technique = str(pair["technique"])
        row = by_technique.setdefault(
            technique,
            {
                "technique": technique,
                "hosts_attempted": 0,
                "attempts": 0,
                OUTCOME_COMPLETED: 0,
                OUTCOME_INTERRUPTED: 0,
                OUTCOME_INCOMPLETE: 0,
                OUTCOME_MIXED: 0,
                "hosts": [],
                "products": [],
            },
        )
        row["hosts_attempted"] += 1
        row["attempts"] += int(pair["attempts"])
        row[outcome] += 1
        if bool(pair["mixed"]):
            row[OUTCOME_MIXED] += 1
        host = str(pair["host"])
        if host and host not in row["hosts"]:
            row["hosts"].append(host)
        for name in pair["products"]:
            if name not in row["products"]:
                row["products"].append(name)

    techniques = sorted(
        by_technique.values(),
        key=lambda r: (
            -int(r[OUTCOME_COMPLETED]),
            -int(r["hosts_attempted"]),
            r["technique"],
        ),
    )

    protected_hosts = {
        str(pair["host"]).strip().lower()
        for pair in by_pair.values()
        if str(pair["posture"]) == POSTURE_ACTIVE and str(pair["host"]).strip()
    }
    protected_pairs = [
        pair for pair in by_pair.values() if str(pair["posture"]) == POSTURE_ACTIVE
    ]
    # Tier leads, because WHICH host it was decides how much the row matters:
    # a completed extraction on a domain controller outranks anything on a
    # workstation. Within a tier the strongest outcome leads, since that is
    # what the client is exposed to.
    protected_pairs.sort(
        key=lambda pair: (
            _tier_rank(pair.get("privilege_tier")),
            _outcome_rank(str(pair["outcome"])),
            str(pair["technique"]),
            str(pair["host"]).lower(),
        )
    )

    coverage_statement = _coverage_statement(
        assessed=assessed, estate=estate, counts=counts, estate_known=estate_known
    )
    efficacy_statement = (
        _efficacy_statement(
            techniques=len(by_technique),
            hosts=len(protected_hosts) or on_protected,
            attempts=attempts_on_protected,
            pairs=on_protected,
            remaining=max(0, on_protected - tier0_completed),
            tier0_completed=tier0_completed,
            tier0_mixed=tier0_mixed,
            # Tier 0 is excluded from both generic buckets: it has its own
            # sentence, and counting it twice would overstate the totals a
            # reader adds up against the table.
            completed_only=max(
                0, completed - mixed_hosts - tier0_completed + tier0_mixed
            ),
            mixed=max(0, mixed_hosts - tier0_mixed),
            interrupted_only=interrupted,
            incomplete=incomplete,
        )
        if attempts_recorded
        else ""
    )

    return {
        "present": bool(assessed or on_protected),
        "attempts_recorded": bool(attempts_recorded),
        "computers_in_estate": estate,
        "hosts_examined": assessed,
        "hosts_not_examined": counts[POSTURE_NOT_ASSESSED],
        "posture_counts": {state: counts.get(state, 0) for state in POSTURE_STATES},
        "hosts": hosts,
        "attempts_total": attempts_total,
        "attempts_on_protected_hosts": attempts_on_protected,
        "hosts_attempted_on_protected": len(protected_hosts) or on_protected,
        "pairs_on_protected_hosts": on_protected,
        OUTCOME_COMPLETED: completed,
        OUTCOME_INTERRUPTED: interrupted,
        OUTCOME_INCOMPLETE: incomplete,
        OUTCOME_MIXED: mixed_hosts,
        "techniques": techniques,
        "tier0_completed": tier0_completed,
        "observations": protected_pairs,
        "coverage_statement": coverage_statement,
        "efficacy_statement": efficacy_statement,
        "statement": " ".join(s for s in (coverage_statement, efficacy_statement) if s),
    }


def endpoint_defense_view(block: Any) -> dict[str, Any]:
    """Return the render-ready view of a persisted ``endpoint_defense`` block.

    The one shape the PDF report, the LITE report and the web platform read, so
    the same observation is worded identically wherever a client meets it. The
    recorded prose is preferred over any fresh derivation, so a later change to
    this module cannot silently rewrite a statement an already-delivered report
    made.

    An absent or unreadable block yields ``present=False`` and empty prose: a
    scan predating this record must render exactly as it did before, rather
    than grow a section nobody observed.
    """
    if not isinstance(block, Mapping):
        return {
            "present": False,
            "attempts_recorded": False,
            "computers_in_estate": 0,
            "hosts_examined": 0,
            "hosts_not_examined": 0,
            "posture_counts": {state: 0 for state in POSTURE_STATES},
            "hosts": [],
            "attempts_total": 0,
            "attempts_on_protected_hosts": 0,
            "hosts_attempted_on_protected": 0,
            "pairs_on_protected_hosts": 0,
            OUTCOME_COMPLETED: 0,
            OUTCOME_INTERRUPTED: 0,
            OUTCOME_INCOMPLETE: 0,
            OUTCOME_MIXED: 0,
            "tier0_completed": 0,
            "tier0_mixed": 0,
            "techniques": [],
            "observations": [],
            "coverage_statement": "",
            "efficacy_statement": "",
            "has_efficacy": False,
            "single_posture_state": False,
            "verdict_lines": [],
        }

    def _int(key: str) -> int:
        try:
            return max(0, int(block.get(key) or 0))
        except (TypeError, ValueError):
            return 0

    raw_counts = block.get("posture_counts")
    counts = {state: 0 for state in POSTURE_STATES}
    if isinstance(raw_counts, Mapping):
        for state in POSTURE_STATES:
            try:
                counts[state] = max(0, int(raw_counts.get(state) or 0))
            except (TypeError, ValueError):
                counts[state] = 0

    hosts = [h for h in (block.get("hosts") or ()) if isinstance(h, Mapping)]
    techniques = [t for t in (block.get("techniques") or ()) if isinstance(t, Mapping)]
    observations = [
        o for o in (block.get("observations") or ()) if isinstance(o, Mapping)
    ]
    on_protected = _int("attempts_on_protected_hosts")
    # A block written before the per-host rows existed carries attempts but no
    # observations and no host count. Falling back to the attempt count keeps
    # its prose and its gate intact rather than reading as zero hosts.
    hosts_attempted = (
        _int("hosts_attempted_on_protected") or len(observations) or on_protected
    )

    out = {
        "present": bool(block.get("present")),
        "attempts_recorded": bool(block.get("attempts_recorded")),
        "computers_in_estate": _int("computers_in_estate"),
        "hosts_examined": _int("hosts_examined"),
        "hosts_not_examined": _int("hosts_not_examined"),
        "posture_counts": counts,
        "hosts": [dict(h) for h in hosts],
        "attempts_total": _int("attempts_total") or on_protected,
        "attempts_on_protected_hosts": on_protected,
        "hosts_attempted_on_protected": hosts_attempted,
        "pairs_on_protected_hosts": _int("pairs_on_protected_hosts")
        or len(observations)
        or hosts_attempted,
        OUTCOME_COMPLETED: _int(OUTCOME_COMPLETED),
        OUTCOME_INTERRUPTED: _int(OUTCOME_INTERRUPTED),
        OUTCOME_INCOMPLETE: _int(OUTCOME_INCOMPLETE),
        OUTCOME_MIXED: _int(OUTCOME_MIXED),
        "tier0_completed": _int("tier0_completed"),
        "tier0_mixed": _int("tier0_mixed"),
        "techniques": [dict(t) for t in techniques],
        "observations": [dict(o) for o in observations],
        "coverage_statement": str(block.get("coverage_statement") or "").strip(),
        "efficacy_statement": str(block.get("efficacy_statement") or "").strip(),
        "has_efficacy": bool(on_protected > 0),
        # A state table showing one row of three declared states looks like an
        # omission. It is a positive finding, and saying so costs one line.
        "single_posture_state": sum(1 for v in counts.values() if v) == 1,
    }
    # Carried ON the view so the report, the free report and the platform all
    # read the SAME authored sentences. A surface deriving them itself is how
    # two renders of one observation end up worded differently.
    out["verdict_lines"] = endpoint_defense_verdict_lines(out)
    return out


def endpoint_defense_verdict_lines(view: Any) -> list[str]:
    """The section's finding, as sentences, before any methodology.

    Every honesty qualifier this section carries is kept, in order, and none is
    softened: what was costing the reader was that the qualifiers SPOKE FIRST,
    so a CISO with thirty seconds reached the end of the boundary statement and
    the state table and left without the result. These lines go above all of
    it and say the same thing the section already says further down, in the
    section's own words.

    The Tier 0 line is emitted even when the count is ZERO, and that is the
    point of it: a zero that is never printed cannot be told apart from a
    lookup that never ran. It is also the half of the finding that stops a
    reader over-reacting to "credentials came off a protected host".

    Empty when no technique ran on a host with a confirmed-active product,
    because then the section has a coverage observation and no finding.
    """
    if not isinstance(view, Mapping) or not view.get("has_efficacy"):
        return []

    def _int(key: str) -> int:
        try:
            return max(0, int(view.get(key) or 0))
        except (TypeError, ValueError):
            return 0

    completed = _int(OUTCOME_COMPLETED)
    interrupted = _int(OUTCOME_INTERRUPTED)
    tier0 = _int("tier0_completed")

    lines: list[str] = []
    if completed:
        lines.append(
            "Credential material was read from "
            f"{'a host' if completed == 1 else f'{completed:,} hosts'} with "
            "endpoint protection active, so that protection did not prevent it."
        )
    if interrupted:
        lines.append(
            f"On {interrupted:,} {'host' if interrupted == 1 else 'hosts'} the "
            "same read was cut off on every attempt."
        )
    if not lines:
        return []

    # The reassurance half, printed whichever way it falls.
    if tier0:
        lines.append(
            f"{tier0:,} of those reads came from a host that controls the "
            "domain, so the material reaches the whole domain."
            if tier0 == 1
            else f"{tier0:,} of those reads came from hosts that control the "
            "domain, so the material reaches the whole domain."
        )
    elif completed:
        lines.append("No completed read came from a host that controls the domain.")
    return lines


def endpoint_defense_exception_rows(view: Any, *, limit: int = 40) -> dict[str, Any]:
    """The hosts that need somebody to do something, bounded.

    What a size-constrained surface should list instead of a slice of every
    examined host. ADscan fingerprints endpoint protection inside the per-host
    SMB enrichment stage, gated on administrative access, so the examined
    population scales with how far the engagement's credentials reach: eight
    hosts on one engagement, and potentially thousands on a 10,000-host estate
    assessed with Domain Admin. A table of every examined host would then run
    to hundreds of pages, and most of those rows would be the good news.

    Only :data:`POSTURE_EXCEPTION_STATES` rows are returned, worst-reading
    first, so the rows that survive the bound are the ones carrying an action.
    The per-state counts in the block already cover every host, so nothing is
    lost by leaving the rest to the full per-host export.

    Args:
        view: The output of :func:`endpoint_defense_view`.
        limit: Maximum rows to return. ``0`` or negative returns none, which a
            surface can use to show only the counts.

    Returns:
        A mapping with ``rows`` (bounded, render-ready), ``shown``, ``total``
        (every exception, not just the shown ones) and ``truncated``. A surface
        rendering ``rows`` must state ``total`` whenever ``truncated``, or a
        bounded list reads as the whole of it.
    """
    if not isinstance(view, Mapping):
        return {"rows": [], "shown": 0, "total": 0, "truncated": False}

    hosts = [h for h in (view.get("hosts") or ()) if isinstance(h, Mapping)]
    exceptions = [
        dict(h)
        for h in hosts
        if str(h.get("posture") or "") in POSTURE_EXCEPTION_STATES
    ]
    # Tier leads the worklist, then the worst-reading state. An administrator
    # working top-down has to meet the Tier 0 hosts first whatever state they
    # are in: one of those with its posture undetermined is a more urgent check
    # than a workstation with a product installed but idle, because what it
    # protects is the domain's identity.
    exceptions.sort(
        key=lambda h: (
            _tier_rank(h.get("privilege_tier")),
            POSTURE_EXCEPTION_STATES.index(str(h.get("posture") or "")),
            str(h.get("host") or "").lower(),
        )
    )
    cap = max(0, int(limit))
    rows = exceptions[:cap]
    return {
        "rows": rows,
        "shown": len(rows),
        "total": len(exceptions),
        "truncated": len(exceptions) > len(rows),
    }


#: Host rows a summary surface should carry. The examined population scales
#: with how far the engagement's credentials reach (endpoint protection is
#: fingerprinted per host, gated on administrative access), so a large estate
#: assessed with Domain Admin can examine thousands, and an HTTP summary that
#: streamed every row would load megabytes into one panel. The full per-host
#: record belongs in the appendix export and on each host's own surface.
#: The per-technique-host observation table is driven by what the operator
#: actually ran, which is a handful of deliberate dumps on most engagements.
#: It is still bounded, because a swept non-interactive run on a large estate
#: could record far more, and a report must never silently truncate: the
#: appendix CSV carries every row and the table says so when it is cut.
DEFAULT_OBSERVATION_ROWS = 40

#: The order the observation table is read in. `mixed` leads because it is the
#: one row whose meaning is not self-evident and the one the client's SOC can
#: act on; `completed` follows because it is the exposure; the rest trail.
_OBSERVATION_ORDER = (
    OUTCOME_MIXED,
    OUTCOME_COMPLETED,
    OUTCOME_INTERRUPTED,
    OUTCOME_INCOMPLETE,
)


def _format_observed_window(first: str, last: str) -> str:
    """Render the attempt window as unambiguous UTC for correlation.

    The client is asked to find these events in their own console, so the
    timestamp has to carry its zone. The records are stamped in UTC; saying so
    is the difference between a correlation the client can run and one they
    have to guess the offset for.
    """

    def _clean(value: str) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        text = text.replace("+00:00", "").replace("Z", "")
        return text.replace("T", " ")[:16]

    start, end = _clean(first), _clean(last)
    if not start and not end:
        return ""
    # The attempts are ordered by a monotonic reading, which the clock step
    # cannot invert, but the VALUES shown come from the wall clock and that
    # step can move it. So the displayed range is normalised to run forward:
    # a window printed backwards is a time the client cannot look for, and it
    # reads as a defect rather than as the clock sync it actually is.
    if start and end and end < start:
        start, end = end, start
    if not start:
        start, end = end, ""
    if not end or end == start:
        return f"{start} UTC"
    if start[:10] == end[:10]:
        return f"{start} - {end[11:]} UTC"
    return f"{start} - {end} UTC"


def endpoint_defense_observation_rows(
    view: Any, *, limit: int = DEFAULT_OBSERVATION_ROWS
) -> dict[str, Any]:
    """Return the per technique-host rows for the efficacy table.

    One row per technique per host, carrying the attempts it folded, the
    window they fell in and whether they agreed. This is what makes the
    report's own "confirm it in your console" instruction followable: an
    instruction that names neither the host nor the time asks the client to
    reproduce work they cannot locate.
    """
    rows: list[dict[str, Any]] = []
    source = view.get("observations") if isinstance(view, Mapping) else None
    for record in source or ():
        if not isinstance(record, Mapping):
            continue
        label = str(record.get("outcome_label") or record.get("outcome") or "")
        rows.append(
            {
                "technique": str(record.get("technique") or ""),
                "host": str(record.get("host") or ""),
                "attempts": max(1, int(record.get("attempts") or 1)),
                "outcome": label,
                "outcome_label": OUTCOME_LABELS.get(
                    label, label.title() or "Undetermined"
                ),
                OUTCOME_COMPLETED: int(record.get(OUTCOME_COMPLETED) or 0),
                OUTCOME_INTERRUPTED: int(record.get(OUTCOME_INTERRUPTED) or 0),
                OUTCOME_INCOMPLETE: int(record.get(OUTCOME_INCOMPLETE) or 0),
                "observed_window": _format_observed_window(
                    str(record.get("first_observed_at") or ""),
                    str(record.get("last_observed_at") or ""),
                ),
                "attempts_before_clock_sync": int(
                    record.get("attempts_before_clock_sync") or 0
                ),
                # Carried explicitly: this re-projection rebuilds the row from
                # a whitelist, so a field stamped upstream is dropped here
                # unless it is named. That is the recurring defect class, and
                # it silently dropped the tier once already.
                "host_name": str(record.get("host_name") or ""),
                "read_method": str(record.get("read_method") or ""),
                "read_method_label": str(record.get("read_method_label") or ""),
                "privilege_tier": str(record.get("privilege_tier") or ""),
                "privilege_tier_label": str(record.get("privilege_tier_label") or ""),
                "products": [str(n) for n in (record.get("products") or ())],
            }
        )

    def _order(row: Mapping[str, Any]) -> tuple[int, str, str]:
        label = str(row.get("outcome") or "")
        rank = (
            _OBSERVATION_ORDER.index(label)
            if label in _OBSERVATION_ORDER
            else len(_OBSERVATION_ORDER)
        )
        return (
            rank,
            str(row.get("technique") or ""),
            str(row.get("host") or "").lower(),
        )

    rows.sort(key=_order)
    total = len(rows)
    cap = max(1, int(limit or DEFAULT_OBSERVATION_ROWS))
    shown = rows[:cap]
    return {
        "rows": shown,
        "shown": len(shown),
        "total": total,
        "truncated": total > len(shown),
        # True when any shown attempt was stamped before ADscan stepped the
        # host clock to the DC. The report then says so, because that stamp
        # carries the host's own offset while every later one agrees with the
        # DC, and therefore with the client's own DC-synced hosts.
        "any_before_clock_sync": any(
            int(row.get("attempts_before_clock_sync") or 0) for row in shown
        ),
        # The "Not graded" legend is legend text: rendering it when every row
        # IS graded is pure noise on the page.
        "any_ungraded": any(not str(row.get("privilege_tier") or "") for row in shown),
    }


DEFAULT_HOST_ROWS_SERVED = 200


def bound_endpoint_defense_hosts(
    view: Any, *, limit: int = DEFAULT_HOST_ROWS_SERVED
) -> dict[str, Any]:
    """Bound a view's host rows, keeping the true total and saying it was bound.

    Every COUNT is untouched: they already describe the whole examined
    population, so a bounded row list can never change a figure. That property
    is what makes the bound safe, and it is asserted by test.

    Adds ``hosts_returned`` and ``hosts_truncated`` so a consumer can say the
    list is partial rather than present it as the whole of it.
    """
    if not isinstance(view, Mapping):
        return {}
    hosts = [h for h in (view.get("hosts") or ()) if isinstance(h, Mapping)]
    cap = max(0, int(limit))
    kept = [dict(h) for h in hosts[:cap]]
    bounded = dict(view)
    bounded["hosts"] = kept
    bounded["hosts_returned"] = len(kept)
    bounded["hosts_truncated"] = len(hosts) > len(kept)

    # The per-technique-host rows are bounded on the same terms: the counts
    # above already describe every one of them, so cutting the list changes no
    # figure, and the flags let the panel say the list is partial. A
    # non-interactive run that swept a large estate is the case this exists
    # for; a report must never truncate in silence.
    observations = [
        o for o in (view.get("observations") or ()) if isinstance(o, Mapping)
    ]
    observations = sorted(
        observations,
        key=lambda o: (
            _OBSERVATION_ORDER.index(str(o.get("outcome_label") or ""))
            if str(o.get("outcome_label") or "") in _OBSERVATION_ORDER
            else len(_OBSERVATION_ORDER),
            str(o.get("technique") or ""),
            str(o.get("host") or "").lower(),
        ),
    )
    kept_observations = [dict(o) for o in observations[:DEFAULT_OBSERVATION_ROWS]]
    bounded["observations"] = kept_observations
    bounded["observations_returned"] = len(kept_observations)
    bounded["observations_truncated"] = len(observations) > len(kept_observations)
    return bounded


def merge_endpoint_defense(domain_entries: Any) -> dict[str, Any]:
    """Fold every domain's recorded block into one report-wide view.

    Counts sum across domains; the per-host and per-technique rows concatenate.
    A recorded statement is honoured verbatim when only one domain recorded
    one, and re-derived from the summed figures when several disagree, so the
    report-wide sentence stays arithmetically true to its own totals.

    ``domain_entries`` is any iterable of per-domain mappings (the renderer
    passes ``report_data.values()``); non-mapping entries and the reserved
    non-domain blocks that ride alongside are skipped. No recorded block
    anywhere yields ``present=False``: the pre-existing render, unchanged.
    """
    views: list[dict[str, Any]] = []
    for entry in domain_entries or ():
        if not isinstance(entry, Mapping):
            continue
        view = endpoint_defense_view(entry.get(ENDPOINT_DEFENSE_KEY))
        if view["present"]:
            views.append(view)

    if not views:
        return endpoint_defense_view(None)

    counts = {state: 0 for state in POSTURE_STATES}
    hosts: list[dict[str, Any]] = []
    by_technique: dict[str, dict[str, Any]] = {}
    estate = examined = not_examined = 0
    on_protected = completed = interrupted = incomplete = 0
    pairs = attempts_total = mixed_hosts = 0
    tier0_completed = tier0_mixed = 0
    observations: list[dict[str, Any]] = []
    coverage_statements: list[str] = []
    efficacy_statements: list[str] = []
    attempts_recorded = False

    for view in views:
        estate += int(view["computers_in_estate"])
        examined += int(view["hosts_examined"])
        not_examined += int(view["hosts_not_examined"])
        on_protected += int(view["hosts_attempted_on_protected"])
        pairs += int(view.get("pairs_on_protected_hosts") or 0) or len(
            view.get("observations") or ()
        )
        attempts_total += int(view["attempts_on_protected_hosts"])
        mixed_hosts += int(view.get(OUTCOME_MIXED) or 0)
        tier0_completed += int(view.get("tier0_completed") or 0)
        tier0_mixed += int(view.get("tier0_mixed") or 0)
        observations.extend(view.get("observations") or ())
        completed += int(view[OUTCOME_COMPLETED])
        interrupted += int(view[OUTCOME_INTERRUPTED])
        incomplete += int(view[OUTCOME_INCOMPLETE])
        attempts_recorded = attempts_recorded or bool(view["attempts_recorded"])
        for state in POSTURE_STATES:
            counts[state] += int(view["posture_counts"].get(state, 0))
        hosts.extend(view["hosts"])
        for row in view["techniques"]:
            key = str(row.get("technique") or "unknown")
            merged_row = by_technique.setdefault(
                key,
                {
                    "technique": key,
                    "attempts": 0,
                    "hosts_attempted": 0,
                    OUTCOME_COMPLETED: 0,
                    OUTCOME_INTERRUPTED: 0,
                    OUTCOME_INCOMPLETE: 0,
                    OUTCOME_MIXED: 0,
                    "hosts": [],
                    "products": [],
                },
            )
            for field in (
                "attempts",
                "hosts_attempted",
                OUTCOME_MIXED,
                *OUTCOME_TOKENS,
            ):
                try:
                    merged_row[field] += int(row.get(field) or 0)
                except (TypeError, ValueError):
                    pass
            for field in ("hosts", "products"):
                for value in row.get(field) or ():
                    text = str(value).strip()
                    if text and text not in merged_row[field]:
                        merged_row[field].append(text)
        if view["coverage_statement"] not in coverage_statements:
            coverage_statements.append(view["coverage_statement"])
        if view["efficacy_statement"] and (
            view["efficacy_statement"] not in efficacy_statements
        ):
            efficacy_statements.append(view["efficacy_statement"])

    hosts.sort(
        key=lambda h: (
            POSTURE_STATES.index(str(h.get("posture") or POSTURE_NOT_ASSESSED))
            if str(h.get("posture") or "") in POSTURE_STATES
            else len(POSTURE_STATES),
            str(h.get("host") or "").lower(),
        )
    )

    coverage_statement = (
        coverage_statements[0]
        if len(coverage_statements) == 1
        else _coverage_statement(assessed=examined, estate=estate, counts=counts)
    )
    efficacy_statement = (
        efficacy_statements[0]
        if len(efficacy_statements) == 1
        else _efficacy_statement(
            techniques=len(by_technique),
            hosts=on_protected,
            attempts=attempts_total,
            pairs=pairs or on_protected,
            remaining=max(0, (pairs or on_protected) - tier0_completed),
            tier0_completed=tier0_completed,
            tier0_mixed=tier0_mixed,
            completed_only=max(
                0, completed - mixed_hosts - tier0_completed + tier0_mixed
            ),
            mixed=max(0, mixed_hosts - tier0_mixed),
            interrupted_only=interrupted,
            incomplete=incomplete,
        )
    )

    merged = {
        "present": True,
        "attempts_recorded": attempts_recorded,
        "computers_in_estate": estate,
        "hosts_examined": examined,
        "hosts_not_examined": not_examined,
        "posture_counts": counts,
        "hosts": hosts,
        "attempts_total": attempts_total,
        "attempts_on_protected_hosts": attempts_total,
        "hosts_attempted_on_protected": on_protected,
        "pairs_on_protected_hosts": pairs or on_protected,
        OUTCOME_COMPLETED: completed,
        OUTCOME_INTERRUPTED: interrupted,
        OUTCOME_INCOMPLETE: incomplete,
        OUTCOME_MIXED: mixed_hosts,
        "tier0_completed": tier0_completed,
        "tier0_mixed": tier0_mixed,
        "observations": observations,
        "techniques": sorted(
            by_technique.values(),
            key=lambda r: (
                -int(r[OUTCOME_COMPLETED]),
                -int(r["hosts_attempted"]),
                r["technique"],
            ),
        ),
        "coverage_statement": coverage_statement,
        "efficacy_statement": efficacy_statement,
    }
    return endpoint_defense_view(merged)


__all__ = [
    "DEFAULT_HOST_ROWS_SERVED",
    "DEFAULT_OBSERVATION_ROWS",
    "ENDPOINT_DEFENSE_KEY",
    "POSTURE_EXCEPTION_STATES",
    "POSTURE_STATE_LABELS",
    "OUTCOME_COMPLETED",
    "OUTCOME_INCOMPLETE",
    "OUTCOME_INTERRUPTED",
    "OUTCOME_LABELS",
    "OUTCOME_MIXED",
    "OUTCOME_TOKENS",
    "POSTURE_ACTIVE",
    "POSTURE_INSTALLED_INACTIVE",
    "POSTURE_NONE_DETECTED",
    "POSTURE_NOT_ASSESSED",
    "POSTURE_STATES",
    "POSTURE_UNDETERMINED",
    "bound_endpoint_defense_hosts",
    "build_endpoint_defense",
    "classify_host_posture",
    "endpoint_defense_exception_rows",
    "endpoint_defense_verdict_lines",
    "endpoint_defense_observation_rows",
    "endpoint_defense_view",
    "merge_endpoint_defense",
    "METHOD_EXPORTED",
    "METHOD_IN_PLACE",
    "METHOD_LABELS",
    "posture_state_label",
    "read_method_label",
    "privilege_tier_label_for_token",
    "set_privilege_tier_label_provider",
]
