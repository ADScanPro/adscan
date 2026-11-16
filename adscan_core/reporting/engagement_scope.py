"""The engagement scope: which domains a scan was authorised to act against.

A scan pointed at one domain routinely learns of others: the parent of a child
domain, a trusting forest, a domain named on a group member. Learning that a
domain exists is not authorisation to act on it. The trust-scope decision
(the request's trusted-domain setting, the scan policy, or the operator before
collection) settles which domains are in scope, and every attack step consults
that decision before it runs (``adscan_internal.services.engagement_scope``).

A step whose acting object or target belongs to a domain outside that scope is
not executed. Its route stays MAPPED: never attempted, never counted as
executed, and never read as a sign that the domain held. That is the fourth
reason a mapped step did not run, beside the three of
:mod:`adscan_core.reporting.compromise_verdict` (excluded by the scan policy,
awaiting approval, declined by the operator).

This module holds the vocabulary every surface shares (the CLI, both report
tiers and the web backend) and the client sentence that discloses the scope
decision. Stdlib only.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

#: Step-note reason token of a step outside the engagement scope. Written by the
#: engine on the attack-graph edge (``not_executed_reason``) and read by
#: ``adscan_core.scan_policy.annotate`` and ``compromise_verdict``.
NOT_EXECUTED_OUTSIDE_SCOPE = "outside_engagement_scope"

#: The label every surface prints beside such a step.
OUTSIDE_SCOPE_STEP_LABEL = "Not executed: outside the engagement scope."

#: Variant of the same reason for a step that is itself inside the scope but
#: comes AFTER a step outside it on the same route (a route that leaves the
#: scope and comes back): it could not run because what it depends on was never
#: executed. An in-scope step is never labelled "outside the scope".
NOT_EXECUTED_DEPENDS_ON_OUTSIDE_SCOPE = "depends_on_outside_engagement_scope"
DEPENDS_ON_OUTSIDE_SCOPE_STEP_LABEL = (
    "Not executed: depends on a step outside the engagement scope."
)
#: Both tokens of the fourth reason.
OUTSIDE_SCOPE_REASONS = frozenset(
    {NOT_EXECUTED_OUTSIDE_SCOPE, NOT_EXECUTED_DEPENDS_ON_OUTSIDE_SCOPE}
)
#: Step / edge note key naming the out-of-scope domain that stopped the step.
NOTE_SCOPE_DOMAIN_KEY = "engagement_scope_domain"
#: Step / edge note key saying WHICH scope kept the step out. Absent (the
#: original notes) means the domain scope; :data:`SCOPE_KIND_ASSET` means the
#: asset scope (an excluded host or account inside an in-scope domain).
NOTE_SCOPE_KIND_KEY = "engagement_scope_kind"
#: Step / edge note key naming the excluded object of an asset refusal.
NOTE_SCOPE_OBJECT_KEY = "engagement_scope_object"
SCOPE_KIND_ASSET = "asset"
#: Graph glue that never runs (membership expansion).
_STRUCTURAL_RELATIONS = frozenset({"memberof", "contains"})

#: ``execution_support_status`` the engine's readiness overlay writes on a route
#: whose first pending step is outside the engagement scope, so no surface
#: offers to run it.
EXECUTION_STATUS_OUTSIDE_SCOPE = NOT_EXECUTED_OUTSIDE_SCOPE

#: Who settled the scope (``scope.json`` ``decided_by``).
DECIDED_BY_CONFIGURATION = "scan_configuration"
DECIDED_BY_POLICY = "scan_policy"
DECIDED_BY_OPERATOR = "operator"
DECIDED_BY_DEFAULT = "default"

_DECIDED_BY_PHRASE: dict[str, str] = {
    DECIDED_BY_CONFIGURATION: "as set in the scan request",
    DECIDED_BY_POLICY: "as set by the scan policy",
    DECIDED_BY_OPERATOR: "as confirmed by the operator before collection",
    DECIDED_BY_DEFAULT: "by default",
}

#: Client names of the cross-domain techniques a withheld route would have used.
_TECHNIQUE_PHRASE: dict[str, str] = {
    "raisechild": "a child-to-parent escalation over the forest trust",
    "raise_child": "a child-to-parent escalation over the forest trust",
    "crossorgtgtdelegation": "a cross-forest ticket delegation over the trust",
    "cross_org_tgt_delegation": "a cross-forest ticket delegation over the trust",
}


def _clean(value: Any) -> str:
    return str(value or "").strip().rstrip(".").lower()


def _join(names: list[str]) -> str:
    if len(names) <= 1:
        return "".join(names)
    return f"{', '.join(names[:-1])} and {names[-1]}"


def excluded_domains(payload: Mapping[str, Any] | None) -> list[str]:
    """The domains a ``scope.json`` payload records as outside the scope."""
    if not isinstance(payload, Mapping):
        return []
    origins = {_clean(d) for d in payload.get("origin_domains") or () if _clean(d)}
    names: list[str] = []
    for entry in payload.get("entries") or ():
        if not isinstance(entry, Mapping) or entry.get("in_scope") is not False:
            continue
        name = _clean(entry.get("domain"))
        if name and name not in origins and name not in names:
            names.append(name)
    return names


def withheld_steps(payload: Mapping[str, Any] | None) -> list[dict[str, str]]:
    """The cross-domain steps the scope kept from running, one per target."""
    if not isinstance(payload, Mapping):
        return []
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, str]] = []
    for item in payload.get("withheld") or ():
        if not isinstance(item, Mapping):
            continue
        target = _clean(item.get("target_domain"))
        technique = _clean(item.get("technique")).replace(" ", "")
        if not target or (target, technique) in seen:
            continue
        seen.add((target, technique))
        out.append(
            {
                "source_domain": _clean(item.get("source_domain")),
                "target_domain": target,
                "technique": technique,
            }
        )
    return out


def format_engagement_scope_note(payload: Mapping[str, Any] | None) -> str:
    """Client sentences stating the scope decision and what it kept from running.

    Empty when the payload records no excluded domain and no withheld step. The
    wording states the fact (out of scope, not acted on) and never implies the
    excluded domain resisted anything.
    """
    excluded = excluded_domains(payload)
    withheld = withheld_steps(payload)
    if not excluded and not withheld:
        return ""
    decided_by = _clean((payload or {}).get("decided_by")) if payload else ""
    how = _DECIDED_BY_PHRASE.get(decided_by, "")
    sentences: list[str] = []
    if excluded:
        noun = "a trusted domain" if len(excluded) == 1 else "trusted domains"
        tail = f", {how}" if how else ""
        sentences.append(
            f"The engagement scope was limited to the assessed domains{tail}. "
            f"ADscan took no action against {_join(excluded)}, {noun} outside "
            "that scope."
        )
    for item in withheld:
        technique = _TECHNIQUE_PHRASE.get(item["technique"], "a route over the trust")
        source = item["source_domain"]
        origin = f" from {source}" if source else ""
        sentences.append(
            f"A route{origin} into {item['target_domain']} through {technique} was "
            "mapped and not executed, because that domain is outside the "
            "engagement scope."
        )
    return " ".join(sentences)


def is_outside_scope_note(notes: Any) -> bool:
    """True when step / edge notes carry the outside-the-scope reason (the boundary)."""
    return (
        isinstance(notes, Mapping)
        and str(notes.get("not_executed_reason") or "").strip().lower()
        == NOT_EXECUTED_OUTSIDE_SCOPE
    )


def scope_note(domain: str = "") -> dict[str, str]:
    """The edge / step note recording a step kept out by the engagement scope."""
    note = {
        "not_executed_reason": NOT_EXECUTED_OUTSIDE_SCOPE,
        "not_executed_label": OUTSIDE_SCOPE_STEP_LABEL,
    }
    if _clean(domain):
        note[NOTE_SCOPE_DOMAIN_KEY] = _clean(domain)
    return note


#: Step / edge note key saying which of the two asset-scope outcomes kept the
#: step from running. Absent means :data:`SCOPE_OUTCOME_EXCLUDED`, so a note
#: written before the key existed reads as it always did.
NOTE_SCOPE_OUTCOME_KEY = "engagement_scope_outcome"
#: The client excluded the object (or, with an allow list, did not list it):
#: the engine's REFUSED outcome. The client's own decision, honoured.
SCOPE_OUTCOME_EXCLUDED = "excluded"
#: The engine could not establish whether the object is in the scope, so it was
#: left alone as a precaution: the UNDETERMINED outcome. Actionable: the client
#: can close it by listing the host or account the way it is known.
SCOPE_OUTCOME_UNCONFIRMED = "unconfirmed"
#: Step / edge note key carrying why an unconfirmed object could not be placed.
NOTE_SCOPE_CAUSE_KEY = "engagement_scope_cause"
#: Step / edge note key carrying how the deciding scope entry was written, when
#: it differs from how the target was known (an address entry, a host by name).
NOTE_SCOPE_ENTRY_KEY = "engagement_scope_entry"

#: The label of a step left alone because its target could not be confirmed as
#: within the scope. Same fourth reason token as an excluded step (it is mapped,
#: never attempted), worded for what actually happened.
UNCONFIRMED_SCOPE_STEP_LABEL = (
    "Not executed: the target could not be confirmed as within the engagement scope."
)

#: Why an object could not be confirmed as in scope (the ``cause`` of an
#: unconfirmed item). The engine records it when it knows; otherwise the
#: reporting layer infers it from how the target was known.
CAUSE_NAME_NOT_RESOLVED = "name_not_resolved"
CAUSE_ADDRESS_NOT_ATTRIBUTED = "address_not_attributed"
CAUSE_ENTRY_NOT_MATCHED = "entry_not_matched"
CAUSE_AFFECTED_HOSTS_UNKNOWN = "affected_hosts_unknown"
CAUSE_RECORD_UNREADABLE = "scope_record_unreadable"
CAUSE_UNKNOWN = "unknown"
_CAUSE_LABEL: dict[str, str] = {
    CAUSE_NAME_NOT_RESOLVED: "known only by name, and the name did not resolve to an address",
    CAUSE_ADDRESS_NOT_ATTRIBUTED: "known only by address, and the address is not attributed to a known host",
    CAUSE_ENTRY_NOT_MATCHED: "a scope entry that could apply had not been matched to a directory object",
    CAUSE_AFFECTED_HOSTS_UNKNOWN: "the change would reach hosts that could not be enumerated",
    CAUSE_RECORD_UNREADABLE: "the recorded scope could not be read",
    CAUSE_UNKNOWN: "its place in the scope could not be established",
}
_CAUSE_REMEDY: dict[str, str] = {
    CAUSE_NAME_NOT_RESOLVED: "Listing the host by name in the scope would settle it.",
    CAUSE_ADDRESS_NOT_ATTRIBUTED: "Listing the address itself in the scope would settle it.",
    CAUSE_ENTRY_NOT_MATCHED: (
        "Correcting that entry, or listing the host by address, would settle it."
    ),
    CAUSE_AFFECTED_HOSTS_UNKNOWN: (
        "Listing the hosts the change reaches, or confirming they are in scope, "
        "would settle it."
    ),
    CAUSE_RECORD_UNREADABLE: "Recording the scope again before the next run would settle it.",
    CAUSE_UNKNOWN: "Listing the object in the scope explicitly would settle it.",
}


def scope_cause_label(cause: Any) -> str:
    """Client wording of why an object could not be confirmed as in scope."""
    return _CAUSE_LABEL.get(str(cause or ""), _CAUSE_LABEL[CAUSE_UNKNOWN])


def scope_cause_remedy(cause: Any) -> str:
    """The sentence saying what would confirm an unconfirmed object."""
    return _CAUSE_REMEDY.get(str(cause or ""), _CAUSE_REMEDY[CAUSE_UNKNOWN])


def asset_scope_note(
    object_label: str = "",
    *,
    outcome: str = SCOPE_OUTCOME_EXCLUDED,
    cause: str = "",
    entry_written_as: str = "",
) -> dict[str, str]:
    """The edge / step note of a step the ASSET scope kept from running.

    It carries the object and never a domain: the object sits inside an
    in-scope domain, so naming a domain here would make the route split read the
    client's own domain as "outside the scope" (:func:`split_route_at_scope`).

    ``outcome`` is :data:`SCOPE_OUTCOME_EXCLUDED` (the client excluded it; the
    engine's REFUSED) or :data:`SCOPE_OUTCOME_UNCONFIRMED` (the engine could not
    establish it was in scope; UNDETERMINED), with ``cause`` naming why. An
    excluded note is byte-identical to the note written before the two outcomes
    were told apart.
    """
    unconfirmed = str(outcome or "").strip().lower() == SCOPE_OUTCOME_UNCONFIRMED
    note = {
        "not_executed_reason": NOT_EXECUTED_OUTSIDE_SCOPE,
        "not_executed_label": UNCONFIRMED_SCOPE_STEP_LABEL if unconfirmed else OUTSIDE_SCOPE_STEP_LABEL,
        NOTE_SCOPE_KIND_KEY: SCOPE_KIND_ASSET,
    }
    label = str(object_label or "").strip()
    if label:
        note[NOTE_SCOPE_OBJECT_KEY] = label
    if unconfirmed:
        note[NOTE_SCOPE_OUTCOME_KEY] = SCOPE_OUTCOME_UNCONFIRMED
        if str(cause or "").strip():
            note[NOTE_SCOPE_CAUSE_KEY] = str(cause).strip()
    if str(entry_written_as or "").strip():
        note[NOTE_SCOPE_ENTRY_KEY] = str(entry_written_as).strip()
    return note


def is_unconfirmed_scope_note(notes: Any) -> bool:
    """True when the note records an object that could not be confirmed as in scope."""
    return (
        is_asset_scope_note(notes)
        and str(notes.get(NOTE_SCOPE_OUTCOME_KEY) or "").strip().lower()
        == SCOPE_OUTCOME_UNCONFIRMED
    )


def outside_scope_step_label(notes: Any) -> str:
    """The step label for a note carrying the fourth reason (either outcome)."""
    return UNCONFIRMED_SCOPE_STEP_LABEL if is_unconfirmed_scope_note(notes) else OUTSIDE_SCOPE_STEP_LABEL


def is_asset_scope_note(notes: Any) -> bool:
    """True when step / edge notes record an ASSET-scope refusal."""
    return (
        is_outside_scope_note(notes)
        and str(notes.get(NOTE_SCOPE_KIND_KEY) or "").strip().lower() == SCOPE_KIND_ASSET
    )


def step_target_domain(step: Mapping[str, Any]) -> str:
    """The domain a route step's target belongs to, from its own details."""
    details = step.get("details") if isinstance(step, Mapping) else None
    return continuation_domain(details, (details or {}).get("to") if details else "")


class RouteScopeSplit:
    """Where a route crosses the engagement-scope boundary, and whether it returns.

    ``boundary`` is the index (in the route's own step list) of the first not-run step the engine noted as
    outside the scope (``None`` when the route never crosses). ``out_domains``
    are the out-of-scope domains the route touches. ``returns`` is True when the
    route ends back inside the scope (its terminal target is not one of the
    out-of-scope domains), or when that cannot be established, which is the
    conservative reading: such a route is judged as a whole, never on its
    prefix alone.

    ``out_objects`` are the objects the ASSET scope excluded on the route (an
    excluded host or account). They never add a domain to ``out_domains``: an
    asset boundary sits inside an in-scope domain, so a route that crosses only
    asset boundaries comes back and is judged whole. ``domain_boundary`` is the
    index of the first DOMAIN-scope boundary (``None`` when there is none): the
    point a route that ends outside the scope is cut at.

    ``unconfirmed_objects`` are the objects the engine could not confirm as
    within the scope and left alone as a precaution. They are kept apart from
    ``out_objects`` (the client's own exclusions) because the two are stated
    differently, and like them they never add a domain.
    """

    __slots__ = (
        "boundary",
        "out_domains",
        "returns",
        "out_objects",
        "domain_boundary",
        "unconfirmed_objects",
    )

    def __init__(
        self,
        boundary: int | None,
        out_domains: tuple[str, ...],
        returns: bool,
        out_objects: tuple[str, ...] = (),
        domain_boundary: int | None = None,
        unconfirmed_objects: tuple[str, ...] = (),
    ):
        self.boundary = boundary
        self.out_domains = out_domains
        self.returns = returns
        self.out_objects = out_objects
        self.unconfirmed_objects = unconfirmed_objects
        self.domain_boundary = boundary if domain_boundary is None and out_domains else domain_boundary

    @property
    def crossed(self) -> bool:
        """True when the route crosses the boundary."""
        return self.boundary is not None

    @property
    def prefix_only(self) -> bool:
        """True when the route is judged on its in-scope prefix alone.

        It leaves the scope and never comes back, so everything past the
        boundary is a mapped continuation into the out-of-scope domain. The
        canonical domain listing splits such a route in two
        (``attack_paths_core.split_routes_at_engagement_scope``): the in-scope
        segment is a route of its own, counted where it ends, and the
        continuation is reported beside it as reach beyond the scope
        (:func:`aggregate_beyond_scope_reach`). An unsplit route of this shape
        reads ``partial`` at most, because its last step did not run.

        The cut is at the DOMAIN boundary (``domain_boundary``), whichever kind
        of boundary comes first. When an asset boundary precedes it (an excluded
        host or account inside the scope, then the hop into an out-of-scope
        domain), the in-scope segment keeps that not-executed step, so it reads
        ``partial`` at most, and the continuation still leaves the in-scope
        listing: a route into a domain outside the scope is never counted among
        the in-scope domain's routes because of where an excluded object sits.
        """
        return self.domain_boundary is not None and not self.returns


def split_route_at_scope(steps: Iterable[Any]) -> RouteScopeSplit:
    """The ONE reading of a route against the engagement scope (display only).

    Shared by the path-status derivation (``attack_paths_core``) and the step
    labelling (``scan_policy.annotate``), so the status and the labels can never
    disagree. Reads only what the engine wrote on the steps.
    """
    ordered = list(steps or ())
    rows = [step for step in ordered if isinstance(step, Mapping)]
    boundary: int | None = None
    domain_boundary: int | None = None
    out: list[str] = []
    objects: list[str] = []
    unconfirmed: list[str] = []
    seen_objects: set[str] = set()
    for index, step in enumerate(ordered):
        if not isinstance(step, Mapping):
            continue
        status = str(step.get("status") or "").strip().lower()
        details = step.get("details")
        if status == "success" or not is_outside_scope_note(details):
            continue
        if boundary is None:
            boundary = index
        if is_asset_scope_note(details):
            # An excluded host or account inside an in-scope domain: never a
            # domain the route left (the route-split trap).
            # The label is kept as the engine wrote it (the display humanizes
            # it); de-duplication is case-insensitive.
            label = str((details or {}).get(NOTE_SCOPE_OBJECT_KEY) or "").strip() or str(
                (details or {}).get("to") or ""
            ).strip()
            if label and _clean(label) not in seen_objects:
                seen_objects.add(_clean(label))
                (unconfirmed if is_unconfirmed_scope_note(details) else objects).append(label)
            continue
        if domain_boundary is None:
            domain_boundary = index
        domain = _clean((details or {}).get(NOTE_SCOPE_DOMAIN_KEY)) or step_target_domain(step)
        if domain and domain not in out:
            out.append(domain)
    if boundary is None:
        return RouteScopeSplit(None, (), False)
    terminal = None
    for step in reversed(rows):
        relation = str(step.get("action") or "").strip().lower()
        if relation not in _STRUCTURAL_RELATIONS:
            terminal = step
            break
    returns = True
    if terminal is not None:
        terminal_details = terminal.get("details")
        terminal_noted = is_outside_scope_note(terminal_details) and not is_asset_scope_note(
            terminal_details
        )
        terminal_domain = step_target_domain(terminal)
        if terminal_noted or (terminal_domain and terminal_domain in out):
            returns = False
    return RouteScopeSplit(
        boundary,
        tuple(out),
        returns,
        tuple(objects),
        domain_boundary=domain_boundary,
        unconfirmed_objects=tuple(unconfirmed),
    )


def crossing_sentence(
    domains: Iterable[str], objects: Iterable[str] = (), unconfirmed: Iterable[str] = ()
) -> str:
    """The route note of a route that leaves the scope and comes back.

    ``objects`` are the hosts or accounts the asset scope excluded on the route;
    ``unconfirmed`` those the engine could not confirm as within the scope. When
    the route crosses no out-of-scope domain, the sentence names them instead
    (never the in-scope domain they sit in), each population in its own words.
    """
    names = [d for d in (_clean(x) for x in domains or ()) if d]
    excluded = asset_objects_display(objects)
    unsure = asset_objects_display(unconfirmed)
    if not names and (excluded or unsure):
        parts: list[str] = []
        if excluded:
            verb = "is" if len(excluded) == 1 else "are"
            parts.append(f"{_join(excluded)}, which {verb} excluded from the engagement scope")
        if unsure:
            verb = "was" if len(unsure) == 1 else "were"
            parts.append(
                f"{_join(unsure)}, which {verb} not confirmed as within the engagement scope"
            )
        return (
            f"This route passes through {', and '.join(parts)}, so it was not executed "
            "from that point on."
        )
    where = _join(names) if names else "a domain outside the engagement scope"
    verb = "is" if len(names) <= 1 else "are"
    return (
        f"This route passes through {where}, which {verb} outside the engagement "
        "scope, so it was not executed from that point on."
    )


def continuation_domain(details: Mapping[str, Any] | None, to_label: Any = "") -> str:
    """The out-of-scope domain a continuation step reaches, for its sentence.

    Read from the step's target distinguished name, then the label's realm, then
    a dotted label (a domain object). ``""`` when none names a domain.
    """
    details = details if isinstance(details, Mapping) else {}
    parts = [
        part.split("=", 1)[1].strip()
        for part in str(details.get("target_dn") or "").split(",")
        if part.strip().upper().startswith("DC=") and "=" in part
    ]
    if parts:
        return ".".join(parts).lower()
    label = str(to_label or details.get("to") or "").strip()
    if "@" in label:
        return _clean(label.split("@", 1)[1])
    return _clean(label) if "." in label and " " not in label else ""


def continuation_sentence(domain: str) -> str:
    """The sentence every surface prints beside a route's out-of-scope continuation."""
    name = _clean(domain)
    if not name:
        return (
            "From here, the route continues into another domain. It was not "
            "tested because it is outside the engagement scope."
        )
    return (
        f"From here, {name} is reachable. It was not tested because it is "
        "outside the engagement scope."
    )


# ── Reach beyond the scope ──────────────────────────────────────────────────
#
# A route that compromises an in-scope domain and then continues into a domain
# outside the scope (a child domain, then the forest root over the trust) is two
# facts, counted in two places. The in-scope segment is a route to the in-scope
# domain's compromise and counts in THAT domain's figures, proven when every
# step of the segment ran. The continuation is reach beyond the scope: mapped,
# never executed, never counted in the in-scope domain's figures or
# denominators, and never hidden. It is stated in its own block, with the
# outside-the-scope reason and the gravity it carries (founder decision
# 2026-11-10, release gate 14.0.0).

#: Record ``meta`` key carrying the continuations split off a route.
META_BEYOND_SCOPE_KEY = "beyond_scope_reach"
#: ``exposure_kpis`` key: the aggregated reach beyond the scope for one domain.
BEYOND_SCOPE_KPI_KEY = "beyond_scope_reach"
#: The block title every surface prints.
BEYOND_SCOPE_TITLE = "Reach beyond your scope"


def beyond_scope_continuation(
    *, from_domain: Any, to_domain: Any, technique: Any = "", from_compromised: bool = False
) -> dict[str, Any]:
    """One continuation split off one route (the record ``meta`` entry)."""
    return {
        "from_domain": _clean(from_domain),
        "to_domain": _clean(to_domain),
        "technique": _clean(technique).replace(" ", ""),
        "from_compromised": bool(from_compromised),
        "routes": 1,
    }


def _entry_key(entry: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        _clean(entry.get("from_domain")),
        _clean(entry.get("to_domain")),
        _clean(entry.get("technique")).replace(" ", ""),
    )


def merge_beyond_scope_entries(*groups: Iterable[Any]) -> list[dict[str, Any]]:
    """Merge continuation entries by (from, to, technique): routes add up."""
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for group in groups:
        for entry in group or ():
            if not isinstance(entry, Mapping):
                continue
            key = _entry_key(entry)
            if not key[1]:
                continue
            try:
                routes = max(0, int(entry.get("routes") or 0))
            except (TypeError, ValueError):
                routes = 0
            current = merged.get(key)
            if current is None:
                merged[key] = {
                    "from_domain": key[0],
                    "to_domain": key[1],
                    "technique": key[2],
                    "from_compromised": bool(entry.get("from_compromised")),
                    "routes": routes,
                }
            else:
                current["routes"] += routes
                current["from_compromised"] = current["from_compromised"] or bool(
                    entry.get("from_compromised")
                )
    return [merged[k] for k in sorted(merged)]


def beyond_scope_sentence(from_domain: Any, to_domain: Any, *, from_compromised: bool) -> str:
    """"From <in-scope domain> (compromised), <domain> is reachable. ..." """
    source = _clean(from_domain)
    target = _clean(to_domain)
    if not target:
        return ""
    if not source:
        return (
            f"{target} is reachable from inside the agreed scope. It was not tested "
            "because it is outside the agreed scope."
        )
    if from_compromised:
        return (
            f"From {source} (compromised), {target} is reachable. It was not tested "
            "because it is outside the agreed scope."
        )
    return (
        f"From {source}, {target} is reachable once {source} is compromised. It was "
        "not tested because it is outside the agreed scope."
    )


def beyond_scope_gravity(from_domain: Any, to_domain: Any) -> str:
    """Why the reach matters, stated plainly (empty when the domains are unknown)."""
    source = _clean(from_domain)
    target = _clean(to_domain)
    if not source or not target:
        return ""
    if source.endswith("." + target):
        return (
            f"A forest is one security boundary. Whoever controls {source} can take "
            f"over {target}, the forest root, and with it every domain in the forest, "
            f"so this reach is as serious as the compromise of {source} itself."
        )
    if target.endswith("." + source):
        return (
            f"{target} sits in the same forest as {source}, so whoever controls "
            f"{source} controls {target} as well."
        )
    return (
        f"The trust between the two domains carries this reach, so control of "
        f"{source} also exposes {target}."
    )


def aggregate_beyond_scope_reach(records: Iterable[Any]) -> list[dict[str, Any]]:
    """The reach beyond the scope a domain listing carries, one entry per pair.

    Read from the continuations the split stamped on each record's ``meta``
    (:data:`META_BEYOND_SCOPE_KEY`). Each entry carries the route count, whether
    the in-scope domain's compromise is proven, the client sentence and the
    gravity line. Empty when no route continues past the scope.
    """
    groups = []
    for record in records or ():
        meta = record.get("meta") if isinstance(record, Mapping) else None
        if isinstance(meta, Mapping):
            groups.append(meta.get(META_BEYOND_SCOPE_KEY) or ())
    merged = merge_beyond_scope_entries(*groups)
    # One entry per (from, to): several techniques over one trust are one reach.
    by_pair: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in merged:
        pair = (entry["from_domain"], entry["to_domain"])
        current = by_pair.get(pair)
        if current is None:
            current = {
                "from_domain": pair[0],
                "to_domain": pair[1],
                "techniques": [],
                "from_compromised": False,
                "routes": 0,
            }
            by_pair[pair] = current
        if entry["technique"] and entry["technique"] not in current["techniques"]:
            current["techniques"].append(entry["technique"])
        current["routes"] += entry["routes"]
        current["from_compromised"] = current["from_compromised"] or entry["from_compromised"]
    out: list[dict[str, Any]] = []
    for pair in sorted(by_pair):
        entry = by_pair[pair]
        entry["technique_phrases"] = [
            _TECHNIQUE_PHRASE.get(t, "a route over the trust") for t in entry["techniques"]
        ]
        entry["sentence"] = beyond_scope_sentence(
            entry["from_domain"], entry["to_domain"], from_compromised=entry["from_compromised"]
        )
        entry["gravity"] = beyond_scope_gravity(entry["from_domain"], entry["to_domain"])
        out.append(entry)
    return out


def combine_beyond_scope_blocks(*blocks: Any) -> list[dict[str, Any]]:
    """Combine persisted per-domain blocks into one, one entry per (from, to).

    Route counts add up, the compromise flag holds if any block proves it and the
    techniques are unioned. Feed the result to :func:`beyond_scope_reach_view`.
    """
    combined: dict[tuple[str, str], dict[str, Any]] = {}
    for block in blocks:
        if not isinstance(block, (list, tuple)):
            continue
        for item in block:
            if not isinstance(item, Mapping):
                continue
            pair = (_clean(item.get("from_domain")), _clean(item.get("to_domain")))
            if not pair[1]:
                continue
            try:
                routes = max(0, int(item.get("routes") or 0))
            except (TypeError, ValueError):
                routes = 0
            current = combined.setdefault(
                pair,
                {
                    "from_domain": pair[0],
                    "to_domain": pair[1],
                    "techniques": [],
                    "from_compromised": False,
                    "routes": 0,
                },
            )
            current["routes"] += routes
            current["from_compromised"] = current["from_compromised"] or bool(
                item.get("from_compromised")
            )
            for technique in item.get("techniques") or ():
                token = _clean(technique).replace(" ", "")
                if token and token not in current["techniques"]:
                    current["techniques"].append(token)
    return [combined[k] for k in sorted(combined)]


def beyond_scope_reach_view(block: Any) -> dict[str, Any] | None:
    """The render shape every surface reads (``None`` when there is nothing to say).

    ``block`` is the persisted :data:`BEYOND_SCOPE_KPI_KEY` list (or the output of
    :func:`aggregate_beyond_scope_reach`). The sentences are re-derived from the
    stored facts so an older block reads with the current wording.
    """
    if not isinstance(block, (list, tuple)):
        return None
    entries: list[dict[str, Any]] = []
    for item in block:
        if not isinstance(item, Mapping) or not _clean(item.get("to_domain")):
            continue
        try:
            routes = max(0, int(item.get("routes") or 0))
        except (TypeError, ValueError):
            routes = 0
        source = _clean(item.get("from_domain"))
        target = _clean(item.get("to_domain"))
        compromised = bool(item.get("from_compromised"))
        entries.append(
            {
                "from_domain": source,
                "to_domain": target,
                "from_compromised": compromised,
                "routes": routes,
                "techniques": [str(t) for t in item.get("techniques") or ()],
                "sentence": beyond_scope_sentence(source, target, from_compromised=compromised),
                "gravity": beyond_scope_gravity(source, target),
                "routes_label": (
                    f"{routes} mapped {'route' if routes == 1 else 'routes'}, not executed"
                ),
            }
        )
    if not entries:
        return None
    return {
        "title": BEYOND_SCOPE_TITLE,
        "entries": entries,
        "routes": sum(e["routes"] for e in entries),
        "domains": sorted({e["to_domain"] for e in entries}),
    }


# ── The asset scope: hosts and accounts the client excluded ─────────────────
#
# A client can name the hosts and directory objects an assessment must leave
# alone (a deny list), or the only ones it may assess (an allow list). The engine
# keeps every excluded object out of contact and out of every attack step
# (``adscan_internal.services.engagement_scope``). This section is the reporting
# half: ONE persisted block per domain (:func:`build_asset_scope_coverage`,
# stamped by the scan itself into ``technical_report.json``) and ONE render
# shape (:func:`asset_scope_coverage_view` / :func:`merge_asset_scope_coverage`)
# that the Security Assessment Report, the free report, the terminal recap and
# the web platform all read, so no surface words the exclusion differently.
#
# An excluded object is a declared coverage gap the client asked for: stated as
# a scope fact, never as a finding, never as a defence the client has, and never
# inside a "no weakness found" or "hosts assessed" figure.

#: Per-domain ``technical_report.json`` key of the persisted block.
ASSET_SCOPE_COVERAGE_KEY = "asset_scope_coverage"
#: Top-level ``technical_report.json`` key of the run-level summary.
ASSET_SCOPE_SUMMARY_KEY = "asset_scope"
#: Version of the block's own shape (independent of the file's marker).
ASSET_SCOPE_COVERAGE_FORMAT = 1
#: Label every surface prints beside an excluded object.
NOT_ASSESSED_EXCLUDED_LABEL = "Not assessed: excluded by the engagement scope"
#: Label every surface prints beside an object left alone because it could not
#: be confirmed as within the scope.
NOT_ASSESSED_UNCONFIRMED_LABEL = "Not assessed: not confirmed as within the engagement scope"
#: Title of the block on every surface.
ASSET_SCOPE_TITLE = "Engagement scope"

#: Asset verdict reasons (``adscan_internal.services.engagement_scope``).
#: ``dc_directory_only`` is in neither population: such a domain controller was
#: used for directory reads and is stated on its own.
REASON_DENIED_ENTRY = "denied_entry"
REASON_NOT_IN_ALLOW = "not_in_allow_list"
REASON_UNDETERMINED = "identity_undetermined"
REASON_RECORD_UNREADABLE = "scope_record_unreadable"
REASON_DC_DIRECTORY_ONLY = "dc_directory_only"
#: The engine's REFUSED outcome on the client's own lists: excluded by the scope.
EXCLUDED_REASONS = frozenset({REASON_DENIED_ENTRY, REASON_NOT_IN_ALLOW})
#: The engine could not establish the object is in scope (UNDETERMINED, or a
#: scope record it could not read): left alone as a precaution.
UNCONFIRMED_REASONS = frozenset({REASON_UNDETERMINED, REASON_RECORD_UNREADABLE})
#: Every reason that kept an object out of the assessment (either population).
EXCLUSION_REASONS = EXCLUDED_REASONS | UNCONFIRMED_REASONS
#: Reason tokens of an asset-scope gap. A phase whose only gaps carry one of
#: these is complete over its in-scope set and never makes a run "incomplete"
#: (``scan_progress.authenticated_assessment_gap`` filters them): an exclusion
#: is the client's decision, and an unconfirmed object is a scope gap the
#: report declares with what would settle it, not a scan that stopped early.
#: ONE exception: a scope record that cannot be used
#: (:data:`REASON_RECORD_UNREADABLE`) is not a gap anybody asked for. An
#: unattended run ends on it before any contact (exit 2), and when the record
#: becomes unusable mid-run the phases it kept from running are incomplete.
ASSET_SCOPE_GAP_REASONS = frozenset(
    {
        *(EXCLUSION_REASONS - {REASON_RECORD_UNREADABLE}),
        REASON_DC_DIRECTORY_ONLY,
        "outside_asset_scope",
        "excluded_by_engagement_scope",
    }
)

#: How many excluded objects the block names per domain (counts are exact).
MAX_EXCLUDED_NAMED = 200
#: How many rows a rendered document lists before it counts the rest.
MAX_EXCLUDED_ROWS = 25
#: How many unresolved entries the block keeps.
MAX_UNRESOLVED_NAMED = 50

_KIND_COMPUTER = "computer"
_ACCOUNT_KINDS = frozenset({"user", "group"})
_ADDRESS_ENTRY_TYPES = frozenset({"ip", "cidr", "range"})
_SUBTREE_ENTRY_TYPES = frozenset({"dn", "dns_suffix"})

_DECIDED_PHRASE_ASSET: dict[str, str] = {
    DECIDED_BY_CONFIGURATION: "set in the scan request",
    DECIDED_BY_POLICY: "set by the scan policy",
    DECIDED_BY_OPERATOR: "confirmed by the operator",
    "web_user": "set on the platform",
}


def _int0(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _count(n: int, singular: str, plural: str) -> str:
    return f"{n:,} {singular if n == 1 else plural}"


def _looks_like_ip(value: str) -> bool:
    import ipaddress  # noqa: PLC0415

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def asset_object_display(label: Any, *, kind: str = "", domain: str = "") -> str:
    """The client-facing name of one excluded host or account.

    A host keeps its full DNS name (lower case), because that is the name a
    client checks against their own inventory; an address stays as written; an
    account goes through the principal humanization SSOT
    (:func:`adscan_core.reporting.principal_display.humanize_principal_for_prose`),
    so a shouting ``SVC_BACKUP@CORP.EXAMPLE`` reads ``svc_backup`` and a raw SID
    never reaches a client.
    """
    text = str(label or "").strip().rstrip(".")
    if not text:
        return ""
    if _looks_like_ip(text):
        return text
    from adscan_core.reporting.principal_display import (  # noqa: PLC0415
        humanize_principal_for_prose,
    )

    if "\\" in text:
        text = text.rpartition("\\")[2]
    if "@" in text or text.upper().startswith("S-1-"):
        return humanize_principal_for_prose(label=text, kind=kind, report_domain=domain)
    if "." in text or text.endswith("$") or str(kind).lower() == _KIND_COMPUTER:
        return text.lower()
    return humanize_principal_for_prose(label=text, kind=kind, report_domain=domain)


def asset_objects_display(labels: Iterable[Any], *, domain: str = "") -> list[str]:
    """Display names for several excluded objects, de-duplicated in order."""
    out: list[str] = []
    for label in labels or ():
        shown = asset_object_display(label, domain=domain)
        if shown and shown.lower() not in {o.lower() for o in out}:
            out.append(shown)
    return out


def _identity_label(identity: Mapping[str, Any]) -> str:
    for key in ("fqdn", "label", "upn", "samaccountname"):
        value = str(identity.get(key) or "").strip()
        if value:
            return value
    dn = str(identity.get("dn") or "").strip()
    if dn.upper().startswith("CN="):
        return dn.split(",", 1)[0][3:]
    addresses = identity.get("addresses") or ()
    if isinstance(addresses, (list, tuple)) and addresses:
        return str(addresses[0])
    return str(identity.get("object_id") or "").strip()


def _identity_aliases(identity: Mapping[str, Any]) -> set[str]:
    """Every lower-cased name one excluded object is known by."""
    aliases: set[str] = set()
    for key in ("fqdn", "label", "upn", "samaccountname", "object_id", "dn"):
        value = _clean(identity.get(key))
        if value:
            aliases.add(value)
            if key == "fqdn":
                aliases.add(value.split(".", 1)[0])
            if key == "samaccountname":
                aliases.add(value.rstrip("$"))
    for address in identity.get("addresses") or ():
        if _clean(address):
            aliases.add(_clean(address))
    return aliases


def _entries_by_id(asset_block: Mapping[str, Any]) -> dict[str, tuple[str, Mapping[str, Any]]]:
    out: dict[str, tuple[str, Mapping[str, Any]]] = {}
    for list_name in ("allow", "deny"):
        for row in asset_block.get(list_name) or ():
            if isinstance(row, Mapping) and row.get("id"):
                out[str(row["id"])] = (list_name, row)
    return out


def _how_identified(reason: str, entry: tuple[str, Mapping[str, Any]] | None) -> str:
    """Short phrase saying how the scope caught one object."""
    if reason == REASON_NOT_IN_ALLOW:
        return "not on the allow list"
    if reason == REASON_UNDETERMINED:
        return "could not be confirmed inside the scope"
    if reason == REASON_RECORD_UNREADABLE:
        return "the scope record could not be read"
    if entry is None:
        return "on the deny list"
    list_name, row = entry
    etype = str(row.get("type") or "")
    value = str(row.get("value") or "").strip()
    where = f"the {list_name} list"
    if etype == "ip" and value:
        return f"address {value} on {where}"
    if etype in ("cidr", "range") and value:
        return f"inside {value} on {where}"
    if etype in _SUBTREE_ENTRY_TYPES and value:
        return f"under {value} on {where}"
    return f"named on {where}"


def _object_kind(kind: Any) -> str:
    text = str(kind or "").strip().lower()
    if text in ("address", "host"):
        return _KIND_COMPUTER
    return text or _KIND_COMPUTER


def _kind_label(kind: str) -> str:
    return {
        _KIND_COMPUTER: "Computer",
        "user": "User account",
        "group": "Group",
    }.get(kind, "Directory object")


def identity_observed(identity: Any) -> bool:
    """Whether a resolved identity of a scope entry is an OBSERVED object.

    An entry's row may carry a reading of the entry's own text (the name as
    the client wrote it, kept so the entry can be looked up again). That is a
    guess, not something the directory or the name service reported, so it is
    never counted, listed or stated as a computer. A host is observed when the
    directory holds it (a SID or a distinguished name) or when its name
    resolved (an address). Only a host name is ever read that way: an identity
    of any other kind (an account, a group, a unit) exists in a row only
    because the directory returned it.

    THE one test for "did this entry match something": the excluded counts of
    the coverage block, the statement built from them and the operator's
    summary line all read it, so none can count what the per-entry table calls
    "matched nothing".
    """
    if isinstance(identity, Mapping):
        kind = _clean(identity.get("kind"))
        evidence = identity.get("object_id") or identity.get("dn") or identity.get("addresses")
    else:
        kind = _clean(getattr(identity, "kind", ""))
        evidence = (
            getattr(identity, "object_id", "")
            or getattr(identity, "dn", "")
            or getattr(identity, "addresses", ())
        )
    return bool(evidence) or kind not in ("", _KIND_COMPUTER)


def _belongs_to(identity: Mapping[str, Any], domain: str) -> bool:
    if not domain:
        # A run-wide reading (the record alone, before any per-domain block).
        return True
    owner = _clean(identity.get("domain"))
    if owner:
        return owner == domain
    name = _clean(identity.get("fqdn") or identity.get("label"))
    if name and "." in name and not _looks_like_ip(name):
        return name == domain or name.endswith("." + domain)
    dn_domain = continuation_domain({"target_dn": identity.get("dn")})
    return dn_domain == domain if dn_domain else False


def _infer_cause(
    *,
    reason: str,
    known_as: str,
    entry_status: str,
    has_address_entries: bool,
    has_name_entries: bool,
    kind: str = _KIND_COMPUTER,
) -> str:
    """Why an object could not be confirmed as in scope, when the engine did not say.

    Read from how the target was known and how the scope was written. The
    engine's own cause, when it records one, always wins over this. Only a
    host has an address: an account or any other directory object is never
    said to have a name that "did not resolve".
    """
    if reason == REASON_RECORD_UNREADABLE:
        return CAUSE_RECORD_UNREADABLE
    if entry_status == "pending":
        return CAUSE_ENTRY_NOT_MATCHED
    if kind != _KIND_COMPUTER:
        return CAUSE_UNKNOWN
    target = str(known_as or "").strip()
    if target and _looks_like_ip(target):
        return CAUSE_ADDRESS_NOT_ATTRIBUTED if has_name_entries else CAUSE_UNKNOWN
    if target and has_address_entries:
        return CAUSE_NAME_NOT_RESOLVED
    return CAUSE_UNKNOWN


def _correlation(item: Mapping[str, Any]) -> str:
    """"Deny list entry 192.0.2.14 matched it." when the entry and target differ.

    The client will ask why a host they listed by address appears by name (or
    the reverse), so the row states both forms whenever they differ.
    """
    written = str(item.get("entry_written_as") or "").strip()
    known = str(item.get("known_as") or item.get("label") or "").strip()
    if not written or not known:
        return ""
    written_is_address = _looks_like_ip(written.split("/", 1)[0].split("-", 1)[0])
    if written_is_address == _looks_like_ip(known):
        # Same form on both sides (or a subtree or suffix entry, which ``how``
        # already states): nothing to reconcile for the reader.
        return ""
    entry_id = str(item.get("entry") or "")
    which = "deny" if entry_id.startswith("d") else "allow" if entry_id.startswith("a") else ""
    listed = f"the {which} list entry" if which else "the scope entry"
    return f"Matched by {listed} {written}."


def build_asset_scope_coverage(
    asset_block: Mapping[str, Any] | None,
    *,
    domain: str,
    excluded: Iterable[Mapping[str, Any]] = (),
    directory_only_dcs: Iterable[Any] = (),
    routes_not_executed: int | None = None,
    steps_not_executed: int | None = None,
    routes_unconfirmed: int | None = None,
    steps_unconfirmed: int | None = None,
    entry_outcomes: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    """The persisted per-domain block (``domains[<d>]["asset_scope_coverage"]``).

    Two populations, never merged:

    * ``excluded``: objects the client excluded, or did not list on an allow
      list (the engine's REFUSED outcome, reasons :data:`EXCLUDED_REASONS`).
    * ``unconfirmed``: objects the engine could not confirm as within the scope
      and left alone as a precaution (UNDETERMINED, reasons
      :data:`UNCONFIRMED_REASONS`), each with its ``cause``.

    Every item keeps how the deciding entry was written (``entry_written_as``)
    and how the target was known (``known_as``), so a correlation such as an
    address entry that excluded a host reached by name is stated in both forms.

    Args:
        asset_block: The ``asset_scope`` block of ``scope.json``. ``None`` or an
            empty scope yields ``None`` (nothing to state; the documents stay
            exactly as they were).
        domain: The domain this block describes.
        excluded: The objects of ``domain`` the engine's verdicts kept out, each
            ``{kind, label|fqdn|samaccountname, object_id, addresses, reason,
            entry, cause}`` (``reason`` decides the population; ``cause`` is
            optional and inferred when absent). The deny entries' resolved
            identities of ``domain`` are folded in too, so a denied object is
            listed even when no stage met it.
        directory_only_dcs: Domain controllers of ``domain`` used for directory
            reads only (an allow list that does not name them).
        routes_not_executed / steps_not_executed: Routes of ``domain`` that pass
            through an excluded object, and distinct steps it stopped (``None``
            when not counted yet).
        routes_unconfirmed / steps_unconfirmed: The same for unconfirmed objects.
        entry_outcomes: What became of each entry the client wrote, for this
            domain (:func:`build_entry_outcomes`): the entries themselves, what
            each matched and one outcome each. Absent keeps the block as it was.
    """
    if not isinstance(asset_block, Mapping):
        return None
    allow_rows = [r for r in asset_block.get("allow") or () if isinstance(r, Mapping)]
    deny_rows = [r for r in asset_block.get("deny") or () if isinstance(r, Mapping)]
    if not allow_rows and not deny_rows:
        return None
    domain = _clean(domain)
    entries = _entries_by_id(asset_block)
    resolution = asset_block.get("resolution") if isinstance(asset_block.get("resolution"), Mapping) else {}
    status_by_entry = {
        str(r.get("id") or ""): str(r.get("status") or "")
        for r in resolution.get("entries") or ()
        if isinstance(r, Mapping)
    }
    has_address_entries = any(str(r.get("type") or "") in _ADDRESS_ENTRY_TYPES for r in (*allow_rows, *deny_rows))
    has_name_entries = any(str(r.get("type") or "") not in _ADDRESS_ENTRY_TYPES for r in (*allow_rows, *deny_rows))

    excluded_items: list[dict[str, Any]] = []
    unconfirmed_items: list[dict[str, Any]] = []
    seen: list[set[str]] = []

    def _add(identity: Mapping[str, Any], reason: str, entry_id: str, cause: str = "") -> None:
        aliases = _identity_aliases(identity)
        if not aliases:
            return
        for known in seen:
            if known & aliases:
                known.update(aliases)
                return
        seen.append(set(aliases))
        kind = _object_kind(identity.get("kind"))
        entry = entries.get(entry_id) if entry_id else None
        label = _identity_label(identity)
        item: dict[str, Any] = {
            "kind": kind,
            "label": label,
            "object_id": str(identity.get("object_id") or ""),
            "reason": reason,
            "entry": entry_id,
            "how": _how_identified(reason, entry),
            "entry_written_as": str(entry[1].get("value") or "") if entry else "",
            "known_as": str(identity.get("known_as") or label),
        }
        if reason in UNCONFIRMED_REASONS:
            item["cause"] = cause or _infer_cause(
                reason=reason,
                known_as=item["known_as"],
                entry_status=status_by_entry.get(entry_id, ""),
                has_address_entries=has_address_entries,
                has_name_entries=has_name_entries,
                kind=kind,
            )
            unconfirmed_items.append(item)
        else:
            excluded_items.append(item)

    for item in excluded or ():
        if not isinstance(item, Mapping):
            continue
        reason = str(item.get("reason") or REASON_DENIED_ENTRY)
        if reason not in EXCLUSION_REASONS:
            continue
        _add(item, reason, str(item.get("entry") or ""), str(item.get("cause") or ""))
    for row in resolution.get("entries") or ():
        if not isinstance(row, Mapping):
            continue
        entry_id = str(row.get("id") or "")
        if entries.get(entry_id, ("", {}))[0] != "deny":
            continue
        for identity in row.get("identities") or ():
            # Only what the entry was OBSERVED to match: a reading of the
            # entry's own text (a name that matched nothing) excludes nothing.
            if (
                isinstance(identity, Mapping)
                and identity_observed(identity)
                and _belongs_to(identity, domain)
            ):
                _add(identity, REASON_DENIED_ENTRY, entry_id)

    def _counts(items: list[dict[str, Any]]) -> tuple[int, int, int]:
        computers = sum(1 for o in items if o["kind"] == _KIND_COMPUTER)
        accounts = sum(1 for o in items if o["kind"] in _ACCOUNT_KINDS)
        return computers, accounts, len(items) - computers - accounts

    def _order(o: Mapping[str, Any]) -> tuple[bool, str]:
        return (o["kind"] != _KIND_COMPUTER, str(o["label"]).lower())

    computers, accounts, others = _counts(excluded_items)
    u_computers, u_accounts, u_others = _counts(unconfirmed_items)
    excluded_items.sort(key=_order)
    unconfirmed_items.sort(key=_order)
    collected = excluded_items

    unresolved: list[dict[str, str]] = []
    for row in resolution.get("entries") or ():
        if not isinstance(row, Mapping):
            continue
        status = str(row.get("status") or "")
        if status not in ("pending", "unresolvable", "ambiguous"):
            continue
        entry = entries.get(str(row.get("id") or ""))
        if entry is None:
            continue
        unresolved.append(
            {
                "id": str(row.get("id") or ""),
                "list": entry[0],
                "type": str(entry[1].get("type") or ""),
                "value": str(entry[1].get("value") or ""),
                "status": status,
            }
        )

    dcs = asset_objects_display(directory_only_dcs)
    by_type: dict[str, int] = {}
    for row in (*allow_rows, *deny_rows):
        etype = str(row.get("type") or "")
        if etype:
            by_type[etype] = by_type.get(etype, 0) + 1
    block: dict[str, Any] = {
        "format": ASSET_SCOPE_COVERAGE_FORMAT,
        "domain": domain,
        "revision": _int0(asset_block.get("revision")),
        "digest": str(asset_block.get("digest") or ""),
        "decided_by": str(asset_block.get("decided_by") or ""),
        "decided_by_label": str(asset_block.get("decided_by_label") or ""),
        "decided_at": str(asset_block.get("decided_at") or ""),
        "clock_frame": str(asset_block.get("clock_frame") or ""),
        "mode": _scope_mode(len(allow_rows), len(deny_rows)),
        "dc_access": str(asset_block.get("dc_access") or ""),
        "entries": {"allow": len(allow_rows), "deny": len(deny_rows), "by_type": by_type},
        "excluded_computers": computers,
        "excluded_accounts": accounts,
        "excluded_other": others,
        "excluded": collected[:MAX_EXCLUDED_NAMED],
        "excluded_omitted": max(0, len(collected) - MAX_EXCLUDED_NAMED),
        "unconfirmed_computers": u_computers,
        "unconfirmed_accounts": u_accounts,
        "unconfirmed_other": u_others,
        "unconfirmed": unconfirmed_items[:MAX_EXCLUDED_NAMED],
        "unconfirmed_omitted": max(0, len(unconfirmed_items) - MAX_EXCLUDED_NAMED),
        "directory_only_dcs": dcs,
        "unresolved_entries": unresolved[:MAX_UNRESOLVED_NAMED],
        "unresolved_omitted": max(0, len(unresolved) - MAX_UNRESOLVED_NAMED),
        "routes_not_executed": routes_not_executed,
        "steps_not_executed": steps_not_executed,
        "routes_unconfirmed": routes_unconfirmed,
        "steps_unconfirmed": steps_unconfirmed,
    }
    if isinstance(entry_outcomes, Mapping) and entry_outcomes.get("entries"):
        block["entry_outcomes"] = dict(entry_outcomes)
    view = _view_from_blocks([(domain, block)])
    block["statement"] = view["statement"] if view else ""
    return block


def _scope_mode(allow: int, deny: int) -> str:
    if allow and deny:
        return "allow_and_deny"
    return "allow" if allow else "deny"


def _decided_clause(block: Mapping[str, Any]) -> str:
    decided_by = _clean(block.get("decided_by"))
    phrase = _DECIDED_PHRASE_ASSET.get(decided_by, "")
    label = str(block.get("decided_by_label") or "").strip()
    if phrase and label and decided_by == "web_user":
        phrase = f"{phrase} by {label}"
    revision = _int0(block.get("revision"))
    parts = [f"scope revision {revision}"] if revision else []
    if phrase:
        parts.append(phrase)
    return f" ({', '.join(parts)})" if parts else ""


def _objects_phrase(computers: int, accounts: int, others: int) -> str:
    parts = []
    if computers:
        parts.append(_count(computers, "computer", "computers"))
    if accounts:
        parts.append(_count(accounts, "account", "accounts"))
    if others:
        parts.append(_count(others, "other directory object", "other directory objects"))
    return _join(parts)


def _sentence_start(text: str) -> str:
    """Spell a leading ``1`` out so a sentence never opens on a lone digit."""
    return f"One {text[2:]}" if text.startswith("1 ") else text


def _disclosure(block: Mapping[str, Any], *, where: str, counted: bool = True) -> str:
    """The scope statement: what was excluded, who decided, what it means.

    ``counted`` is False when the caller holds only the record (no per-domain
    verdicts yet), so an absence of excluded objects is not stated as a fact.
    """
    entries = block.get("entries") if isinstance(block.get("entries"), Mapping) else {}
    allow = _int0(entries.get("allow"))
    deny = _int0(entries.get("deny"))
    computers = _int0(block.get("excluded_computers"))
    accounts = _int0(block.get("excluded_accounts"))
    others = _int0(block.get("excluded_other"))
    total = computers + accounts + others
    decided = _decided_clause(block)
    sentences: list[str] = []
    if allow:
        lead = (
            "At your request, the assessment was limited to the computers and accounts "
            f"on an allow list of {_count(allow, 'entry', 'entries')}"
        )
        if deny:
            lead += f", minus a deny list of {_count(deny, 'entry', 'entries')}"
        sentences.append(f"{lead}{decided}.")
        if total:
            verb = "was" if total == 1 else "were"
            sentences.append(
                _sentence_start(
                    f"{_objects_phrase(computers, accounts, others)} {verb} outside that scope."
                )
            )
    elif total:
        sentences.append(
            "At your request, the engagement scope excluded "
            f"{_objects_phrase(computers, accounts, others)}{decided}."
        )
    else:
        sentences.append(
            f"At your request, the assessment ran under an engagement scope with a deny "
            f"list of {_count(deny, 'entry', 'entries')}{decided}."
        )
    if not total:
        if counted:
            sentences.append(f"No computer or account in {where} was excluded by it.")
        return " ".join(sentences)
    actions = []
    if computers:
        actions.append(
            "sent no network traffic to the excluded "
            + ("computer" if computers == 1 else "computers")
        )
    if accounts or others:
        if accounts and others:
            noun = "accounts and objects"
        elif accounts:
            noun = "account" if accounts == 1 else "accounts"
        else:
            noun = "object" if others == 1 else "objects"
        actions.append(f"took no action on the excluded {noun}")
    sentences.append(f"ADscan {_join(actions)}.")
    if total == 1:
        sentences.append(
            "It appears in this report from directory data only and was not assessed."
        )
    else:
        sentences.append(
            "They appear in this report from directory data only and were not assessed."
        )
    return " ".join(sentences)


def _dc_sentence(by_domain: list[tuple[str, list[str]]]) -> str:
    sentences = []
    for domain, dcs in by_domain:
        if not dcs:
            continue
        where = f" of {domain}" if domain else ""
        if len(dcs) == 1:
            sentences.append(
                f"The domain controller{where} ({dcs[0]}) was used for directory reads only "
                "(LDAP, Kerberos, DNS and time). It was not assessed as a host."
            )
        else:
            sentences.append(
                f"The domain controllers{where} ({_join(dcs)}) were used for directory reads "
                "only (LDAP, Kerberos, DNS and time). They were not assessed as hosts."
            )
    return " ".join(sentences)


def _unresolved_sentence(rows: list[Mapping[str, Any]], omitted: int) -> str:
    groups: dict[tuple[str, str], list[str]] = {}
    for row in rows:
        key = (str(row.get("status") or ""), str(row.get("list") or ""))
        groups.setdefault(key, []).append(str(row.get("value") or ""))
    sentences = []
    for (status, list_name), values in sorted(groups.items()):
        n = len(values)
        named = _join([v for v in values[:5] if v]) + (
            f" and {n - 5:,} more" if n > 5 else ""
        )
        noun = _count(n, f"entry on the {list_name} list", f"entries on the {list_name} list")
        if status == "unresolvable":
            effect = (
                "so nothing was excluded because of " + ("it" if n == 1 else "them")
                if list_name == "deny"
                else "so " + ("it" if n == 1 else "they") + " added nothing to the assessment"
            )
            sentences.append(
                f"{_sentence_start(noun)} ({named}) matched no computer or account in "
                f"the directory, {effect}."
            )
        elif status == "ambiguous":
            effect = (
                "every match was excluded"
                if list_name == "deny"
                else "none of the matches was added to the assessment"
            )
            sentences.append(
                f"{_sentence_start(noun)} ({named}) matched more than one computer, so "
                f"{effect}."
            )
        else:
            verb = "was" if n == 1 else "were"
            sentences.append(
                f"{_sentence_start(noun)} ({named}) {verb} not yet matched to a "
                "directory object when the assessment ended."
            )
    if omitted:
        sentences.append(
            f"{omitted:,} further {'entry' if omitted == 1 else 'entries'} did not match "
            "and are not listed here."
        )
    return " ".join(sentences)


def _routes_sentence(routes: int, *, unconfirmed: bool = False) -> str:
    if routes <= 0:
        return ""
    what = (
        "a computer or account that could not be confirmed as within the engagement scope"
        if unconfirmed
        else "an excluded computer or account"
    )
    if routes == 1:
        return (
            f"One attack route passes through {what}. It was mapped and not executed "
            "from that point on."
        )
    return (
        f"{routes:,} attack routes pass through {what}. They were mapped and not "
        "executed from that point on."
    )


def _unconfirmed_sentence(computers: int, accounts: int, others: int) -> str:
    """The statement of the second population: left alone as a precaution."""
    total = computers + accounts + others
    if total <= 0:
        return ""
    subject = _sentence_start(_objects_phrase(computers, accounts, others))
    verb = "was" if total == 1 else "were"
    pronoun = "It is" if total == 1 else "Each is"
    return (
        f"{subject} {verb} not assessed because ADscan could not confirm "
        f"{'it was' if total == 1 else 'they were'} within the engagement scope, so "
        f"{'it was' if total == 1 else 'they were'} left alone as a precaution. "
        f"{pronoun} listed with what was missing and what would settle it."
    )


def _rows_for(
    blocks: list[tuple[str, Mapping[str, Any]]], key: str, *, unconfirmed: bool
) -> tuple[list[dict[str, str]], int]:
    rows: list[dict[str, str]] = []
    omitted = 0
    for domain, block in blocks:
        omitted += _int0(block.get(f"{key}_omitted"))
        for item in block.get(key) or ():
            if not isinstance(item, Mapping):
                continue
            kind = _object_kind(item.get("kind"))
            row = {
                "object": asset_object_display(item.get("label"), kind=kind, domain=domain),
                "kind": kind,
                "kind_label": _kind_label(kind),
                "domain": domain,
                "how": str(item.get("how") or ""),
                "correlation": _correlation(item),
                "entry_written_as": str(item.get("entry_written_as") or ""),
                "known_as": str(item.get("known_as") or ""),
                "status_label": (
                    NOT_ASSESSED_UNCONFIRMED_LABEL if unconfirmed else NOT_ASSESSED_EXCLUDED_LABEL
                ),
            }
            if unconfirmed:
                cause = str(item.get("cause") or CAUSE_UNKNOWN)
                row["cause"] = cause
                row["cause_label"] = scope_cause_label(cause)
                row["remedy"] = scope_cause_remedy(cause)
                row["how"] = row["cause_label"]
            rows.append(row)
    rows = [r for r in rows if r["object"]]
    omitted += max(0, len(rows) - MAX_EXCLUDED_ROWS)
    return rows[:MAX_EXCLUDED_ROWS], omitted


def _recap_lines(
    excluded: tuple[int, int, int], unconfirmed: tuple[int, int, int]
) -> list[str]:
    """The operator's end-of-scan lines, one per population (empty ones omitted)."""
    lines = []
    if sum(excluded):
        lines.append(
            f"{_sentence_start(_objects_phrase(*excluded))} excluded by the engagement "
            "scope, not assessed"
        )
    if sum(unconfirmed):
        lines.append(
            f"{_sentence_start(_objects_phrase(*unconfirmed))} not confirmed as within "
            "the engagement scope, left alone"
        )
    return lines


def _view_from_blocks(pairs: list[tuple[str, Mapping[str, Any]]]) -> dict[str, Any] | None:
    blocks = [(d, b) for d, b in pairs if isinstance(b, Mapping) and b.get("entries")]
    if not blocks:
        return None
    # The scope is one decision for the run: the latest revision speaks for it.
    lead = max((b for _d, b in blocks), key=lambda b: _int0(b.get("revision")))

    def _sum(key: str) -> int:
        return sum(_int0(b.get(key)) for _d, b in blocks)

    computers = _sum("excluded_computers")
    accounts = _sum("excluded_accounts")
    others = _sum("excluded_other")
    u_computers = _sum("unconfirmed_computers")
    u_accounts = _sum("unconfirmed_accounts")
    u_others = _sum("unconfirmed_other")
    merged = dict(lead)
    merged.update(
        excluded_computers=computers, excluded_accounts=accounts, excluded_other=others
    )
    domains = [d for d, _b in blocks if d]
    where = _join(domains) if domains else "the assessed domains"
    rows, omitted = _rows_for(blocks, "excluded", unconfirmed=False)
    unconfirmed_rows, unconfirmed_omitted = _rows_for(blocks, "unconfirmed", unconfirmed=True)
    entry_rows: list[Mapping[str, Any]] = []
    entry_seen: set[str] = set()
    entry_omitted = 0
    for _domain, block in blocks:
        outcomes = block.get("entry_outcomes")
        if not isinstance(outcomes, Mapping):
            continue
        entry_omitted = max(entry_omitted, _int0(outcomes.get("omitted")))
        for row in outcomes.get("entries") or ():
            if isinstance(row, Mapping) and str(row.get("id")) not in entry_seen:
                entry_seen.add(str(row.get("id")))
                entry_rows.append(row)
    unresolved: list[Mapping[str, Any]] = []
    unresolved_seen: set[str] = set()
    unresolved_omitted = 0
    for _d, block in blocks:
        unresolved_omitted = max(unresolved_omitted, _int0(block.get("unresolved_omitted")))
        for row in block.get("unresolved_entries") or ():
            if isinstance(row, Mapping) and str(row.get("id")) not in unresolved_seen:
                unresolved_seen.add(str(row.get("id")))
                unresolved.append(row)
    routes = _sum("routes_not_executed")
    routes_unconfirmed = _sum("routes_unconfirmed")
    entries = lead.get("entries") if isinstance(lead.get("entries"), Mapping) else {}
    return {
        "present": True,
        "title": ASSET_SCOPE_TITLE,
        # Population 1: excluded by the client's scope (the engine's REFUSED).
        "statement": _disclosure(merged, where=where),
        "routes_statement": _routes_sentence(routes),
        "rows": rows,
        "rows_omitted": omitted,
        "status_label": NOT_ASSESSED_EXCLUDED_LABEL,
        "excluded_computers": computers,
        "excluded_accounts": accounts,
        "excluded_other": others,
        "excluded_total": computers + accounts + others,
        "routes_not_executed": routes,
        # Population 2: not confirmed as within the scope (UNDETERMINED).
        "unconfirmed_statement": _unconfirmed_sentence(u_computers, u_accounts, u_others),
        "unconfirmed_routes_statement": _routes_sentence(routes_unconfirmed, unconfirmed=True),
        "unconfirmed_rows": unconfirmed_rows,
        "unconfirmed_rows_omitted": unconfirmed_omitted,
        "unconfirmed_status_label": NOT_ASSESSED_UNCONFIRMED_LABEL,
        "unconfirmed_computers": u_computers,
        "unconfirmed_accounts": u_accounts,
        "unconfirmed_other": u_others,
        "unconfirmed_total": u_computers + u_accounts + u_others,
        "routes_unconfirmed": routes_unconfirmed,
        # Run-level context.
        "dc_statement": _dc_sentence(
            [(d, list(b.get("directory_only_dcs") or ())) for d, b in blocks]
        ),
        # An exclusion that matched nothing leads: a typo there leaves the
        # host the client wanted excluded inside the scope under its real name.
        "unresolved_statement": " ".join(
            part
            for part in (
                _deny_nothing_sentence(entry_rows),
                _unresolved_sentence(unresolved, unresolved_omitted),
            )
            if part
        ),
        # What became of each entry the client wrote (the ones needing
        # attention first), for the scope card and the report table.
        "entry_rows": entry_rows[:MAX_ENTRY_ROWS],
        # The same rows as every surface draws them (``entry_row_display``).
        "entry_table": entry_rows_display(entry_rows[:MAX_ENTRY_ROWS]),
        "entry_rows_omitted": max(0, len(entry_rows) - MAX_ENTRY_ROWS) + entry_omitted,
        "deny_matched_nothing": sum(
            1 for r in entry_rows if r.get("side") == "deny" and r.get("outcome") == "matched_nothing"
        ),
        "recap_lines": _recap_lines((computers, accounts, others), (u_computers, u_accounts, u_others)),
        "revision": _int0(lead.get("revision")),
        "digest": str(lead.get("digest") or ""),
        "mode": str(lead.get("mode") or ""),
        "dc_access": str(lead.get("dc_access") or ""),
        "entries_allow": _int0(entries.get("allow")),
        "entries_deny": _int0(entries.get("deny")),
        "domains": domains,
    }


def _deny_nothing_sentence(entry_rows: Iterable[Mapping[str, Any]]) -> str:
    values = [
        str(r.get("value") or "")
        for r in entry_rows
        if r.get("side") == "deny" and r.get("outcome") == "matched_nothing"
    ]
    if not values:
        return ""
    shown = ", ".join(values[:5]) + (f" and {len(values) - 5} more" if len(values) > 5 else "")
    if len(values) == 1:
        return f"The exclusion {shown} matched nothing; check the name."
    return f"{len(values)} exclusions matched nothing; check the names: {shown}."


def asset_scope_coverage_view(block: Any, *, domain: str = "") -> dict[str, Any] | None:
    """The render shape of one persisted block (``None`` when there is nothing to say).

    Keys: ``title``, ``statement`` (the disclosure), ``dc_statement``,
    ``unresolved_statement``, ``routes_statement``, ``rows`` (``object``,
    ``kind_label``, ``how``, ``status_label``) with ``rows_omitted``, and the
    figures (``excluded_computers``, ``excluded_accounts``, ``excluded_total``,
    ``routes_not_executed``, ``revision``, ``mode``, ``dc_access``). Sentences are
    re-derived from the stored facts, so an older block reads with the current
    wording.
    """
    if not isinstance(block, Mapping):
        return None
    return _view_from_blocks([(_clean(domain), block)])


def merge_asset_scope_coverage(domain_entries: Any) -> dict[str, Any] | None:
    """One view over every domain's block (the report-wide scope statement).

    ``domain_entries`` is the ``technical_report.json`` ``domains`` mapping or an
    iterable of its values (each carrying :data:`ASSET_SCOPE_COVERAGE_KEY`).
    """
    pairs: list[tuple[str, Mapping[str, Any]]] = []
    if isinstance(domain_entries, Mapping):
        items = list(domain_entries.items())
    else:
        items = [("", e) for e in domain_entries or ()]
    for name, entry in items:
        if not isinstance(entry, Mapping):
            continue
        block = entry.get(ASSET_SCOPE_COVERAGE_KEY)
        if isinstance(block, Mapping):
            pairs.append((_clean(name) or _clean(block.get("domain")), block))
    return _view_from_blocks(pairs)


def format_asset_scope_note(payload: Mapping[str, Any] | None) -> str:
    """The disclosure sentence for a ``scope.json`` payload, before any block exists.

    Reads only the record (entry counts and who decided), for a surface that runs
    before the scan stamped its per-domain blocks. Empty without an asset scope.
    """
    block = (payload or {}).get("asset_scope") if isinstance(payload, Mapping) else None
    coverage = build_asset_scope_coverage(block, domain="")
    if not coverage:
        return ""
    entries = coverage.get("entries") or {}
    return _disclosure(
        coverage, where="the assessed domains", counted=not _int0(entries.get("allow"))
    )


def build_asset_scope_summary(
    asset_block: Mapping[str, Any] | None, blocks: Iterable[Mapping[str, Any]] = ()
) -> dict[str, Any] | None:
    """The run-level summary (``technical_report.json`` ``asset_scope``)."""
    if not isinstance(asset_block, Mapping):
        return None
    allow = len([r for r in asset_block.get("allow") or () if isinstance(r, Mapping)])
    deny = len([r for r in asset_block.get("deny") or () if isinstance(r, Mapping)])
    if not allow and not deny:
        return None
    blocks = [b for b in blocks or () if isinstance(b, Mapping)]
    unresolved = 0
    for row in ((asset_block.get("resolution") or {}).get("entries") or ()):
        if isinstance(row, Mapping) and row.get("status") in ("pending", "unresolvable", "ambiguous"):
            unresolved += 1
    return {
        "revision": _int0(asset_block.get("revision")),
        "digest": str(asset_block.get("digest") or ""),
        "decided_by": str(asset_block.get("decided_by") or ""),
        "decided_at": str(asset_block.get("decided_at") or ""),
        "clock_frame": str(asset_block.get("clock_frame") or ""),
        "mode": _scope_mode(allow, deny),
        "dc_access": str(asset_block.get("dc_access") or ""),
        "entries_allow": allow,
        "entries_deny": deny,
        "entries_unresolved": unresolved,
        "excluded_computers": sum(_int0(b.get("excluded_computers")) for b in blocks),
        "excluded_accounts": sum(_int0(b.get("excluded_accounts")) for b in blocks),
        "excluded_other": sum(_int0(b.get("excluded_other")) for b in blocks),
        "unconfirmed_computers": sum(_int0(b.get("unconfirmed_computers")) for b in blocks),
        "unconfirmed_accounts": sum(_int0(b.get("unconfirmed_accounts")) for b in blocks),
        "unconfirmed_other": sum(_int0(b.get("unconfirmed_other")) for b in blocks),
        "refused_contacts": sum(
            _int0(r.get("count")) for r in asset_block.get("refusals") or () if isinstance(r, Mapping)
        ),
        "backstop_hits": _int0(asset_block.get("backstop_hits")),
    }


def excluded_host_aliases(
    domain_entry: Mapping[str, Any] | None, *, population: str = "all"
) -> frozenset[str]:
    """Lower-cased names of the computers a domain's block kept out of the assessment.

    ``population`` is ``"excluded"`` (the client's exclusions), ``"unconfirmed"``
    (not confirmed as within the scope) or ``"all"`` (both: neither was
    contacted). For a reader that must keep them out of an "assessed" figure or
    a positive control claim (``control_evidence_verdict``).
    """
    block = (domain_entry or {}).get(ASSET_SCOPE_COVERAGE_KEY) if isinstance(domain_entry, Mapping) else None
    if not isinstance(block, Mapping):
        return frozenset()
    keys = {"excluded": ("excluded",), "unconfirmed": ("unconfirmed",)}.get(
        population, ("excluded", "unconfirmed")
    )
    aliases: set[str] = set()
    for key in keys:
        for item in block.get(key) or ():
            if isinstance(item, Mapping) and _object_kind(item.get("kind")) == _KIND_COMPUTER:
                aliases |= _identity_aliases(item)
    return frozenset(aliases)


def excluded_computer_count(domain_entry: Mapping[str, Any] | None) -> int:
    """How many computers a domain's block records as excluded (0 without one)."""
    block = (domain_entry or {}).get(ASSET_SCOPE_COVERAGE_KEY) if isinstance(domain_entry, Mapping) else None
    return _int0(block.get("excluded_computers")) if isinstance(block, Mapping) else 0


def asset_route_counts(records: Iterable[Any]) -> dict[str, int]:
    """Routes and distinct steps the asset scope kept from running, per population.

    Read from the engine's own step notes through :func:`split_route_at_scope`.
    Returns ``routes_not_executed`` / ``steps_not_executed`` (an excluded object
    on the route) and ``routes_unconfirmed`` / ``steps_unconfirmed`` (an object
    not confirmed as within the scope). A route crossing both counts in both.
    """
    routes = {"excluded": 0, "unconfirmed": 0}
    steps: dict[str, set[tuple[str, str, str]]] = {"excluded": set(), "unconfirmed": set()}
    for record in records or ():
        if not isinstance(record, Mapping):
            continue
        rows = record.get("steps")
        if not isinstance(rows, list):
            continue
        split = split_route_at_scope(rows)
        if split.out_objects:
            routes["excluded"] += 1
        if split.unconfirmed_objects:
            routes["unconfirmed"] += 1
        for step in rows:
            details = step.get("details") if isinstance(step, Mapping) else None
            if not is_asset_scope_note(details):
                continue
            population = "unconfirmed" if is_unconfirmed_scope_note(details) else "excluded"
            steps[population].add(
                (
                    _clean(details.get("from") or step.get("from")),
                    _clean(step.get("action")),
                    _clean(details.get("to") or step.get("to")),
                )
            )
    return {
        "routes_not_executed": routes["excluded"],
        "steps_not_executed": len(steps["excluded"]),
        "routes_unconfirmed": routes["unconfirmed"],
        "steps_unconfirmed": len(steps["unconfirmed"]),
    }


#: The workspace file the engine writes the scope record to.
SCOPE_FILENAME = "scope.json"


#: Called before ``scope.json`` is read by a renderer of the SAME process, so
#: what the engine counted in memory since its last write (refusals, backstop
#: hits) is on disk. Injected by the engine (``adscan_core`` never imports it);
#: ``None`` in a process with no engine session (the web backend, a report
#: rendered later), where the file is already complete.
_RECORD_FLUSHER: Any = None


def set_scope_record_flusher(flusher: Any) -> None:
    """Install the engine's "write what is pending" callable (``None`` removes it)."""
    global _RECORD_FLUSHER  # noqa: PLW0603 - one engine session per process
    _RECORD_FLUSHER = flusher


#: The advisory lock file every writer of ``scope.json`` holds while it reads,
#: merges and replaces the record (beside it, inside the workspace).
SCOPE_LOCK_FILENAME = "scope.json.lock"


class _ScopeRecordLock:
    """Context manager of :func:`scope_record_lock` (``held`` says if it was taken)."""

    def __init__(self, workspace_dir: Any, timeout: float) -> None:
        self._workspace = workspace_dir
        self._timeout = timeout
        self._handle: Any = None
        self.held = False

    def __enter__(self) -> "_ScopeRecordLock":
        import os  # noqa: PLC0415

        from adscan_core.pal import filelock  # noqa: PLC0415

        if not self._workspace or not filelock.file_lock_supported():
            return self
        path = os.path.join(os.fspath(self._workspace), SCOPE_LOCK_FILENAME)
        try:
            self._handle = filelock.acquire_file_lock(path, blocking=True, timeout=self._timeout)
        except OSError:
            # No lock file can be made (a read-only workspace): the write
            # itself will say so.
            self._handle = None
            return self
        if self._handle is None:
            raise TimeoutError(
                f"the engagement scope record is locked by another writer ({SCOPE_LOCK_FILENAME})"
            )
        self.held = True
        return self

    def __exit__(self, *exc_info: Any) -> None:
        from adscan_core.pal import filelock  # noqa: PLC0415

        filelock.release_file_lock(self._handle)
        self._handle = None
        self.held = False


def scope_record_lock(workspace_dir: Any, *, timeout: float = 10.0) -> _ScopeRecordLock:
    """THE lock of a workspace's ``scope.json``, for every program that writes it.

    The record has several writers (a running scan, a second session, the web
    platform, the promotion of an execution workspace). Each one follows the
    same protocol, or the last writer silently undoes the others::

        with scope_record_lock(workspace_dir):
            current = <read scope.json again, now>
            <never write allow/deny lists older than current's:
             asset_scope.revision decides, the digest breaks a tie>
            <a new scope is revision current.revision + 1>
            <counters (refusals, backstop_hits) are ADDED to current's>
            <replace the file atomically (temporary file, rename)>

    An advisory lock on ``scope.json.lock`` (released by the kernel if the
    holder dies). Where the platform cannot lock, or no lock file can be made,
    the block runs unlocked (``held`` is False).

    Raises:
        TimeoutError: Another writer held the lock for ``timeout`` seconds.
    """
    return _ScopeRecordLock(workspace_dir, timeout)


def load_engagement_scope(workspace_dir: Any) -> dict[str, Any] | None:
    """Read the scope record of a workspace (``scope.json``), or ``None``.

    Inside a scan's own process the engine writes the record in batches; its
    pending changes are flushed first, so a reader never sees a stale count.
    """
    if not workspace_dir:
        return None
    import json  # noqa: PLC0415
    import os  # noqa: PLC0415

    flusher = _RECORD_FLUSHER
    if flusher is not None:
        try:
            flusher(os.fspath(workspace_dir))
        except Exception:  # noqa: BLE001 - a failed flush never hides the record
            pass
    path = os.path.join(os.fspath(workspace_dir), SCOPE_FILENAME)
    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def domains_named(values: Iterable[Any]) -> list[str]:
    """Normalised, de-duplicated domain names (helper for the engine record)."""
    out: list[str] = []
    for value in values or ():
        name = _clean(value)
        if name and name not in out:
            out.append(name)
    return out


__all__ = (
    "ASSET_SCOPE_COVERAGE_FORMAT",
    "ASSET_SCOPE_COVERAGE_KEY",
    "ASSET_SCOPE_GAP_REASONS",
    "ASSET_SCOPE_SUMMARY_KEY",
    "ASSET_SCOPE_TITLE",
    "CAUSE_ADDRESS_NOT_ATTRIBUTED",
    "CAUSE_AFFECTED_HOSTS_UNKNOWN",
    "CAUSE_ENTRY_NOT_MATCHED",
    "CAUSE_NAME_NOT_RESOLVED",
    "CAUSE_RECORD_UNREADABLE",
    "CAUSE_UNKNOWN",
    "EXCLUDED_REASONS",
    "EXCLUSION_REASONS",
    "NOT_ASSESSED_EXCLUDED_LABEL",
    "NOT_ASSESSED_UNCONFIRMED_LABEL",
    "NOTE_SCOPE_CAUSE_KEY",
    "NOTE_SCOPE_ENTRY_KEY",
    "NOTE_SCOPE_OUTCOME_KEY",
    "SCOPE_OUTCOME_EXCLUDED",
    "SCOPE_OUTCOME_UNCONFIRMED",
    "UNCONFIRMED_REASONS",
    "UNCONFIRMED_SCOPE_STEP_LABEL",
    "asset_object_display",
    "asset_objects_display",
    "asset_route_counts",
    "is_unconfirmed_scope_note",
    "outside_scope_step_label",
    "scope_cause_label",
    "scope_cause_remedy",
    "asset_scope_coverage_view",
    "build_asset_scope_coverage",
    "build_asset_scope_summary",
    "excluded_computer_count",
    "excluded_host_aliases",
    "identity_observed",
    "format_asset_scope_note",
    "merge_asset_scope_coverage",
    "BEYOND_SCOPE_KPI_KEY",
    "BEYOND_SCOPE_TITLE",
    "META_BEYOND_SCOPE_KEY",
    "aggregate_beyond_scope_reach",
    "beyond_scope_continuation",
    "beyond_scope_gravity",
    "beyond_scope_reach_view",
    "beyond_scope_sentence",
    "combine_beyond_scope_blocks",
    "merge_beyond_scope_entries",
    "DEPENDS_ON_OUTSIDE_SCOPE_STEP_LABEL",
    "NOTE_SCOPE_DOMAIN_KEY",
    "NOTE_SCOPE_KIND_KEY",
    "NOTE_SCOPE_OBJECT_KEY",
    "SCOPE_KIND_ASSET",
    "asset_scope_note",
    "is_asset_scope_note",
    "NOT_EXECUTED_DEPENDS_ON_OUTSIDE_SCOPE",
    "OUTSIDE_SCOPE_REASONS",
    "RouteScopeSplit",
    "continuation_domain",
    "continuation_sentence",
    "crossing_sentence",
    "load_engagement_scope",
    "split_route_at_scope",
    "step_target_domain",
    "DECIDED_BY_CONFIGURATION",
    "DECIDED_BY_DEFAULT",
    "DECIDED_BY_OPERATOR",
    "DECIDED_BY_POLICY",
    "EXECUTION_STATUS_OUTSIDE_SCOPE",
    "NOT_EXECUTED_OUTSIDE_SCOPE",
    "OUTSIDE_SCOPE_STEP_LABEL",
    "domains_named",
    "excluded_domains",
    "format_engagement_scope_note",
    "is_outside_scope_note",
    "scope_note",
    "withheld_steps",
)


# ── What became of each entry the client wrote (scope verification) ─────────
#
# One vocabulary for the terminal (``scope verify``, the line an unattended run
# prints at its start), the report block and the structured result the web
# reads. The engine produces the rows
# (``adscan_internal.services.engagement_scope_verify.verify_asset_scope``);
# this module words them, and nothing else does.

#: Closed vocabulary of ``entry["outcome"]``.
ENTRY_MATCHED = "matched"
ENTRY_MATCHED_ASSESSED = "matched_assessed"
ENTRY_MATCHED_EXCLUDED = "matched_excluded"
ENTRY_MATCHED_NOT_REACHED = "matched_not_reached"
ENTRY_MATCHED_NOT_CONFIRMED = "matched_not_confirmed"
ENTRY_MATCHED_NOTHING = "matched_nothing"
ENTRY_OUTCOMES = (
    ENTRY_MATCHED,
    ENTRY_MATCHED_ASSESSED,
    ENTRY_MATCHED_EXCLUDED,
    ENTRY_MATCHED_NOT_REACHED,
    ENTRY_MATCHED_NOT_CONFIRMED,
    ENTRY_MATCHED_NOTHING,
)

#: Causes an ENTRY (not a target) can carry on top of the target causes above.
CAUSE_DIRECTORY_NOT_READ = "directory_not_read"
CAUSE_AMBIGUOUS_ENTRY = "ambiguous_entry"
_ENTRY_CAUSE_LABEL: dict[str, str] = {
    CAUSE_DIRECTORY_NOT_READ: "the directory has not been read yet",
    CAUSE_AMBIGUOUS_ENTRY: "it matches several objects",
    CAUSE_NAME_NOT_RESOLVED: "the name did not resolve to an address",
    CAUSE_ADDRESS_NOT_ATTRIBUTED: "its address is not attributed to a known host",
    CAUSE_ENTRY_NOT_MATCHED: "it has not been matched to a directory object yet",
}

#: Verification levels: what the answer was built from.
VERIFY_LEVEL_NAME_RESOLUTION = "name_resolution"
VERIFY_LEVEL_DIRECTORY = "directory"
VERIFY_LEVEL_MIXED = "mixed"

#: Kinds of ``issues`` rows, in the order they are stated.
ISSUE_DENY_MATCHED_NOTHING = "deny_matched_nothing"
ISSUE_ALLOW_MATCHED_NOTHING = "allow_matched_nothing"
ISSUE_ALLOW_AND_DENY = "allow_and_deny"
ISSUE_PARTIAL_HOST = "host_covered_in_part"
ISSUE_SHARED_ADDRESS = "address_shared"
ISSUE_SHADOWED = "entry_shadowed"
ISSUE_DIRECTORY_SERVER_EXCLUDED = "directory_server_excluded"
ISSUE_ORDER = (
    ISSUE_DENY_MATCHED_NOTHING,
    ISSUE_DIRECTORY_SERVER_EXCLUDED,
    ISSUE_ALLOW_AND_DENY,
    ISSUE_PARTIAL_HOST,
    ISSUE_ALLOW_MATCHED_NOTHING,
    ISSUE_SHARED_ADDRESS,
    ISSUE_SHADOWED,
)

#: Labels named per entry in a persisted block (counts stay exact).
MAX_ENTRY_LABELS = 5
#: Entry rows named in one persisted block.
MAX_ENTRY_ROWS = 200

_NO_OBJECT_SENTENCE = (
    "No computer in this directory corresponds to this entry. ADscan assesses the "
    "systems joined to the directory, so nothing was contacted there."
)
_DENY_NOTHING_SENTENCE = "This exclusion matched nothing; check the name."


def entry_cause_label(cause: Any) -> str:
    """Client wording of why an ENTRY could not be confirmed."""
    return _ENTRY_CAUSE_LABEL.get(str(cause or ""), scope_cause_label(cause))


def _matched_phrase(matched: Mapping[str, Any]) -> str:
    return _objects_phrase(
        _int0(matched.get("computers")), _int0(matched.get("accounts")), _int0(matched.get("other"))
    )


def entry_outcome_note(row: Mapping[str, Any]) -> str:
    """One client-safe sentence for what became of one scope entry.

    Honest about what ADscan knows: an entry that matched no computer of the
    directory is never "excluded", and nothing is said about what the machine
    behind an address might be (ADscan did not contact it).
    """
    outcome = str(row.get("outcome") or "")
    side = str(row.get("side") or "")
    matched = row.get("matched") if isinstance(row.get("matched"), Mapping) else {}
    what = _matched_phrase(matched) or "nothing"
    if outcome == ENTRY_MATCHED_NOTHING:
        if side == "deny":
            return _DENY_NOTHING_SENTENCE
        if row.get("addresses"):
            return "It resolves to an address. " + _NO_OBJECT_SENTENCE
        return _NO_OBJECT_SENTENCE
    if outcome == ENTRY_MATCHED_NOT_CONFIRMED:
        cause = entry_cause_label(row.get("cause"))
        if _int0(matched.get("computers")) or _int0(matched.get("accounts")) or _int0(matched.get("other")):
            return f"Matched {what}, not confirmed as within the scope: {cause}."
        return f"Not confirmed: {cause}."
    if outcome == ENTRY_MATCHED_EXCLUDED:
        if what == "nothing":
            return (
                "Resolves to an address that no computer of this directory holds: the "
                "address is excluded, and nothing was sent there."
            )
        return f"Matched {what}: excluded, nothing was sent there."
    if outcome == ENTRY_MATCHED_NOT_REACHED:
        states = row.get("states") if isinstance(row.get("states"), Mapping) else {}
        silent = _int0(states.get("not_reached"))
        return (
            f"Matched {what}; {_count(silent, 'computer', 'computers')} resolved and "
            "answered on no service, so it was not assessed."
            if silent == 1
            else f"Matched {what}; {_count(silent, 'computer', 'computers')} resolved and "
            "answered on no service, so they were not assessed."
        )
    if outcome == ENTRY_MATCHED_ASSESSED:
        return f"Matched {what}: assessed."
    if outcome == ENTRY_MATCHED:
        return f"Matches {what}." if side == "allow" else f"Matches {what}: excluded."
    return ""


#: Short outcome labels of an entry row (the table's last column).
_ENTRY_OUTCOME_LABEL: dict[str, str] = {
    ENTRY_MATCHED: "Matched",
    ENTRY_MATCHED_ASSESSED: "Assessed",
    ENTRY_MATCHED_EXCLUDED: "Excluded",
    ENTRY_MATCHED_NOT_REACHED: "Not reached",
    ENTRY_MATCHED_NOT_CONFIRMED: "Not confirmed",
    ENTRY_MATCHED_NOTHING: "Matched nothing",
}
_ENTRY_SIDE_LABEL: dict[str, str] = {"allow": "Allow list", "deny": "Deny list"}


def entry_row_display(row: Mapping[str, Any]) -> dict[str, Any]:
    """One entry row as every surface draws it (the report, the web Scope card).

    The entry as the client wrote it, the list it is on, what it matched, the
    outcome and the sentence. ``is_error`` marks the one outcome that leaves
    the client's intent unmet: an EXCLUSION that matched nothing, so the host
    they wanted left alone is still inside the scope under its real name.
    """
    matched = row.get("matched") if isinstance(row.get("matched"), Mapping) else {}
    labels = [str(x) for x in (row.get("labels") or ()) if str(x)]
    more = _int0(row.get("labels_omitted"))
    named = _join(labels) + (f" and {more:,} more" if labels and more else "")
    phrase = _matched_phrase(matched)
    side = str(row.get("side") or "")
    outcome = str(row.get("outcome") or "")
    return {
        "id": str(row.get("id") or ""),
        "value": str(row.get("value") or ""),
        "side": side,
        "list_label": _ENTRY_SIDE_LABEL.get(side, ""),
        "matched_text": (f"{phrase}: {named}" if phrase and named else phrase) or "Nothing",
        "outcome": outcome,
        "outcome_label": _ENTRY_OUTCOME_LABEL.get(outcome, ""),
        "statement": str(row.get("statement") or "") or entry_outcome_note(row),
        "is_error": side == "deny" and outcome == ENTRY_MATCHED_NOTHING,
    }


def entry_rows_display(rows: Iterable[Any]) -> list[dict[str, Any]]:
    """Entry rows for display, the unmatched exclusions first (they are the error)."""
    shown = [entry_row_display(row) for row in rows or () if isinstance(row, Mapping)]
    return sorted(shown, key=lambda r: not r["is_error"])


def scope_verification_level_statement(level: Any) -> str:
    """What a verification at this level can and cannot say."""
    if str(level or "") == VERIFY_LEVEL_DIRECTORY:
        return (
            "Checked against the directory ADscan has read: every entry is matched to "
            "the computers and accounts it names."
        )
    if str(level or "") == VERIFY_LEVEL_MIXED:
        return (
            "Checked against the directory for the domains ADscan has read, and by name "
            "resolution only for the others: entries of a domain not read yet stay "
            "not confirmed."
        )
    return (
        "No directory has been read yet, so this check uses name resolution only: it "
        "shows where each name points, not which computers an address, an account or "
        "a unit covers. Run it again after the collection for the complete answer."
    )


def scope_verification_summary(result: Mapping[str, Any] | None) -> str:
    """The one line an unattended run prints at its start (and ``scope verify`` leads with)."""
    if not isinstance(result, Mapping):
        return ""
    counts = result.get("counts") if isinstance(result.get("counts"), Mapping) else {}
    entries = result.get("entry_counts") if isinstance(result.get("entry_counts"), Mapping) else {}
    known = _int0(counts.get("known_computers"))
    parts = [
        f"{_count(_int0(entries.get('allow')), 'allow entry', 'allow entries')} and "
        f"{_count(_int0(entries.get('deny')), 'deny entry', 'deny entries')}"
    ]
    if known:
        figures = (
            f"of {_count(known, 'known computer', 'known computers')}, "
            f"{_int0(counts.get('inside'))} inside, {_int0(counts.get('excluded'))} excluded, "
            f"{_int0(counts.get('not_confirmed'))} not confirmed"
        )
        if _int0(counts.get("directory_only")):
            figures += (
                f", {_count(_int0(counts.get('directory_only')), 'domain controller', 'domain controllers')} "
                "used for directory reads only"
            )
        parts.append(figures)
    else:
        parts.append("no directory read yet (name resolution only)")
    nothing = _int0(entries.get("matched_nothing"))
    deny_nothing = _int0(entries.get("deny_matched_nothing"))
    if deny_nothing:
        parts.append(
            f"{_count(deny_nothing, 'exclusion', 'exclusions')} matched nothing (check the name)"
        )
    if nothing - deny_nothing > 0:
        parts.append(f"{_count(nothing - deny_nothing, 'allow entry', 'allow entries')} matched nothing")
    waiting = _int0(entries.get("not_confirmed"))
    if waiting:
        parts.append(f"{_count(waiting, 'entry', 'entries')} not confirmed")
    return "Scope check: " + "; ".join(parts) + "."


def build_entry_outcomes(
    entries: Iterable[Mapping[str, Any]] | None,
    *,
    domain: str = "",
    host_reach: Mapping[str, str] | None = None,
    host_states: Mapping[str, str] | None = None,
) -> dict[str, Any] | None:
    """The per-entry rows of a run, for the persisted coverage block.

    Args:
        entries: The ``entries`` rows of a verification result. Each carries the
            entry as the client wrote it and ``computer_names`` (every computer
            it matched, by DNS name), which this function consumes and drops.
        domain: Keep the rows that concern this domain: an entry that matched
            an object of it, and every entry tied to no domain (an address
            nobody holds, a name that matched nothing).
        host_reach: ``computer name -> "reached" | "not_reached"`` from the
            run's network-reach figures (``host_reach_coverage.host_reach_states``).
            A computer absent from it was not measured.
        host_states: ``computer name -> "inside" | "excluded" | "not_confirmed"``,
            the engine's verdict for each known computer.

    Returns:
        ``{"entries": [...], "omitted": n, "counts": {outcome: n},
        "deny_matched_nothing": n}`` with at most :data:`MAX_ENTRY_ROWS` rows
        (the ones needing attention first; the counts are exact), or ``None``
        when there is no row.
    """
    wanted = _clean(domain)
    reach = host_reach or {}
    states = host_states or {}
    rows: list[dict[str, Any]] = []
    for raw in entries or ():
        if not isinstance(raw, Mapping):
            continue
        domains = [_clean(d) for d in raw.get("domains") or () if _clean(d)]
        if wanted and domains and wanted not in domains:
            continue
        side = str(raw.get("side") or "")
        outcome = str(raw.get("outcome") or "")
        names = [str(n) for n in raw.get("computer_names") or ()]
        tally = {"assessed": 0, "not_reached": 0, "not_measured": 0, "excluded": 0, "not_confirmed": 0}
        for name in names:
            state = states.get(name, "")
            if side == "deny" or state == "excluded":
                tally["excluded"] += 1
            elif state == "not_confirmed":
                tally["not_confirmed"] += 1
            elif reach.get(name) == "reached":
                tally["assessed"] += 1
            elif reach.get(name) == "not_reached":
                tally["not_reached"] += 1
            else:
                tally["not_measured"] += 1
        cause = str(raw.get("cause") or "")
        if outcome in (ENTRY_MATCHED, ENTRY_MATCHED_EXCLUDED) and names:
            if side == "deny":
                outcome = ENTRY_MATCHED_EXCLUDED
            elif tally["not_confirmed"]:
                outcome, cause = ENTRY_MATCHED_NOT_CONFIRMED, cause or CAUSE_ENTRY_NOT_MATCHED
            elif tally["not_reached"]:
                outcome = ENTRY_MATCHED_NOT_REACHED
            elif tally["assessed"] and not tally["not_measured"]:
                outcome = ENTRY_MATCHED_ASSESSED
        row: dict[str, Any] = {
            "id": str(raw.get("id") or ""),
            "side": side,
            "type": str(raw.get("type") or ""),
            "value": str(raw.get("value") or ""),
            "outcome": outcome,
            "matched": {
                key: _int0((raw.get("matched") or {}).get(key))
                for key in ("computers", "accounts", "other")
            },
            "labels": [str(x) for x in (raw.get("labels") or ())][:MAX_ENTRY_LABELS],
        }
        row["labels_omitted"] = max(
            0,
            sum(row["matched"].values()) - len(row["labels"]),
        )
        if cause and outcome == ENTRY_MATCHED_NOT_CONFIRMED:
            row["cause"] = cause
        if names:
            row["states"] = {k: v for k, v in tally.items() if v}
        row["statement"] = entry_outcome_note(row)
        rows.append(row)
    if not rows:
        return None
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["outcome"]] = counts.get(row["outcome"], 0) + 1
    deny_nothing = sum(
        1 for row in rows if row["side"] == "deny" and row["outcome"] == ENTRY_MATCHED_NOTHING
    )
    attention = {
        ENTRY_MATCHED_NOTHING: 0,
        ENTRY_MATCHED_NOT_CONFIRMED: 1,
        ENTRY_MATCHED_NOT_REACHED: 2,
        ENTRY_MATCHED_EXCLUDED: 3,
        ENTRY_MATCHED: 4,
        ENTRY_MATCHED_ASSESSED: 5,
    }
    rows.sort(
        key=lambda r: (
            attention.get(r["outcome"], 9),
            r["side"] != "deny",
            r["id"][:1],
            int(r["id"][1:]) if r["id"][1:].isdigit() else 0,
        )
    )
    return {
        "entries": rows[:MAX_ENTRY_ROWS],
        "omitted": max(0, len(rows) - MAX_ENTRY_ROWS),
        "counts": counts,
        "deny_matched_nothing": deny_nothing,
    }


__all__ += (
    "CAUSE_AMBIGUOUS_ENTRY",
    "CAUSE_DIRECTORY_NOT_READ",
    "ENTRY_MATCHED",
    "ENTRY_MATCHED_ASSESSED",
    "ENTRY_MATCHED_EXCLUDED",
    "ENTRY_MATCHED_NOTHING",
    "ENTRY_MATCHED_NOT_CONFIRMED",
    "ENTRY_MATCHED_NOT_REACHED",
    "ENTRY_OUTCOMES",
    "ISSUE_ORDER",
    "MAX_ENTRY_LABELS",
    "entry_row_display",
    "entry_rows_display",
    "MAX_ENTRY_ROWS",
    "VERIFY_LEVEL_DIRECTORY",
    "VERIFY_LEVEL_MIXED",
    "VERIFY_LEVEL_NAME_RESOLUTION",
    "build_entry_outcomes",
    "entry_cause_label",
    "entry_outcome_note",
    "scope_verification_level_statement",
    "scope_verification_summary",
)
