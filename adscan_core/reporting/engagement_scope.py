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
    """

    __slots__ = ("boundary", "out_domains", "returns")

    def __init__(self, boundary: int | None, out_domains: tuple[str, ...], returns: bool):
        self.boundary = boundary
        self.out_domains = out_domains
        self.returns = returns

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
        """
        return self.boundary is not None and not self.returns


def split_route_at_scope(steps: Iterable[Any]) -> RouteScopeSplit:
    """The ONE reading of a route against the engagement scope (display only).

    Shared by the path-status derivation (``attack_paths_core``) and the step
    labelling (``scan_policy.annotate``), so the status and the labels can never
    disagree. Reads only what the engine wrote on the steps.
    """
    ordered = list(steps or ())
    rows = [step for step in ordered if isinstance(step, Mapping)]
    boundary: int | None = None
    out: list[str] = []
    for index, step in enumerate(ordered):
        if not isinstance(step, Mapping):
            continue
        status = str(step.get("status") or "").strip().lower()
        details = step.get("details")
        if status == "success" or not is_outside_scope_note(details):
            continue
        if boundary is None:
            boundary = index
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
        terminal_noted = is_outside_scope_note(terminal.get("details"))
        terminal_domain = step_target_domain(terminal)
        if terminal_noted or (terminal_domain and terminal_domain in out):
            returns = False
    return RouteScopeSplit(boundary, tuple(out), returns)


def crossing_sentence(domains: Iterable[str]) -> str:
    """The route note of a route that leaves the scope and comes back."""
    names = [d for d in (_clean(x) for x in domains or ()) if d]
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


#: The workspace file the engine writes the scope record to.
SCOPE_FILENAME = "scope.json"


def load_engagement_scope(workspace_dir: Any) -> dict[str, Any] | None:
    """Read the scope record of a workspace (``scope.json``), or ``None``."""
    if not workspace_dir:
        return None
    import json  # noqa: PLC0415
    import os  # noqa: PLC0415

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
