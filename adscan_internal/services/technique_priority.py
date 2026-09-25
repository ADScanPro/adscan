"""Which fixes eliminate the most attack paths — one derivation, both tiers.

Every ADscan document that answers *"if I fix one thing, how many compromise
routes close?"* reads its numbers from here: the free exposure report's choke-point
table, the paid deliverable's "Attack Technique Priorities" ranking, the remediation
roadmap document, and the web CTEM's remediation page.

WHY THIS MODULE EXISTS
----------------------
That question used to be derived twice — once in
:mod:`adscan_internal.services.attack_surface_analysis` for LITE and once in
:mod:`adscan_internal.pro.reporting.remediation_engine` for PRO — and the two copies
drifted. The paid report ranked the built-in nesting ``DOMAIN ADMINS ∈
ADMINISTRATORS`` as a client's second remediation priority, twenty paths and 65% of
the total, advising them to remove a membership Windows will not let them remove.
The free report was correct, because only its copy filtered group memberships. A
shared predicate closed that one hole; this module closes the class it belonged
to. Which edges a client can actually change is now decided per EDGE INSTANCE by
:mod:`~adscan_internal.services.remediability` — a relation-name filter
suppressed every ``MemberOf``, including the 48% that are an ordinary
``Remove-ADGroupMember`` away, and admitted every ``DCSync``, including the ones
held by a domain controller that cannot give them up.

WHAT IS SHARED AND WHAT IS NOT
------------------------------
Shared (here): normalising a path's status, deciding whether a path describes
client exposure at all, reading a path's distinct techniques from whichever shape
the caller holds, excluding steps the client cannot change, counting paths and
principals and proven executions per technique, and joining the attack-step
catalog's remediation and MITRE metadata.

Not shared (per document): how the ranking is *scored and presented*. PRO weights
path coverage against blast radius, severity and exploitation evidence into an
impact score and ranks on it; LITE shows the coverage arithmetic and leaves the
"how" to the paid deliverable. Those live with their documents, over one derivation.

INPUT SHAPES
------------
Two path shapes reach this module and both are accepted, because the callers
genuinely hold different records:

* the persisted snapshot / attack-graph record — carries ``relations`` *and*
  ``steps``, plus ``nodes``, ``source`` and ``status``;
* the report/web render record — carries only ``steps`` (each a mapping with an
  ``action``), plus ``status`` and ``top_choke_point``.

``steps`` is preferred when present and ``relations`` is the fallback, so a caller
holding either one gets the same answer. On a real workspace the two agree edge for
edge; ``relations`` exists for records that never carried step detail.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from adscan_internal.services.attack_relation_labels import (
    format_business_relation_label,
)
from adscan_internal.services.path_state import carries_client_exposure
from adscan_internal.services.remediability import (
    classify_edge_remediability,
    remediability_for_step,
)


__all__ = [
    "TechniquePriority",
    "compute_technique_priorities",
    "complexity_rank",
    "carries_client_exposure",
    "domain_affected_user_total",
    "iter_domain_tagged_paths",
    "normalize_path_status",
    "path_technique_keys",
    "status_for_severity",
    "status_severity",
    "technique_label",
]


# ── Status vocabulary ─────────────────────────────────────────────────────────
#
# Attack PATH display statuses, collapsed onto the buckets the remediation
# ranking distinguishes. Lower severity number = worse.
#
# `partial` is its OWN bucket, never folded into `attempted` or `theoretical`: a
# chain with at least one proven step is demonstrated evidence, and flattening it
# hides exactly the validation the product sells (CLAUDE.md § Nomenclature
# Standard, "Status vocabularies").
#
# `unsupported` / `unavailable` / `closed_by_configuration` sit BELOW
# `theoretical` rather than above `attempted`. They are not degrees of exposure:
# the first two are an ADscan data gap and the third is observed hardening, so
# labelling a technique "unsupported" when it also carries theoretical routes
# reads as a worse finding than it is. Nothing they touch reaches a remediation
# row (see `carries_client_exposure`); the ordering only governs how a mixed
# census is displayed.

_STATUS_SEVERITY: dict[str, int] = {
    "exploited": 0,
    "success": 0,
    "succeeded": 0,
    "domain_compromised": 0,
    "partial": 1,
    "blocked": 2,
    "attempted": 3,
    "failed": 3,
    "error": 3,
    "theoretical": 4,
    "unsupported": 5,
    "unavailable": 5,
    "closed_by_configuration": 6,
}

#: Inverse of the normalised buckets, for rendering ``worst_status``.
_SEVERITY_TO_STATUS: dict[int, str] = {
    0: "exploited",
    1: "partial",
    2: "blocked",
    3: "attempted",
    4: "theoretical",
    5: "unsupported",
    6: "closed_by_configuration",
}

#: How much exploitation EVIDENCE a path status carries, for the paid ranking's
#: impact score. Distinct from ``_STATUS_SEVERITY``, which orders how bad a
#: status is to display: a safety abstention is a serious finding but proves no
#: execution, so it weighs the same as a theoretical hop here.
#:
#: ``partial`` sits at the top with ``exploited`` because both rest on execution
#: ADscan actually performed — a partially-validated chain has a demonstrated
#: segment, which is a different kind of fact from "we tried and nothing landed".
#: How far the execution got is carried by ``exploited_paths``, not by this
#: weight.
_STATUS_EVIDENCE_WEIGHT: dict[str, int] = {
    "exploited": 3,
    "partial": 3,
    "attempted": 2,
    "theoretical": 1,
    "blocked": 1,
}

_COMPLEXITY_ORDER: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "very_high": 3,
}

_SEVERITY_WEIGHT: dict[str, int] = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def normalize_path_status(raw: Any) -> str:
    """Collapse any attack-path status token onto one of five display buckets.

    Args:
        raw: A raw status from a snapshot record, a render record, or a
            :class:`~adscan_internal.services.path_state.PathState` value.

    Returns:
        One of ``exploited`` / ``blocked`` / ``unsupported`` / ``attempted`` /
        ``theoretical``. Unknown tokens read as ``theoretical`` — the ranking must
        never claim evidence it does not have.
    """
    token = str(raw or "theoretical").strip().lower()
    return _SEVERITY_TO_STATUS.get(_STATUS_SEVERITY.get(token, 4), "theoretical")


def status_severity(status: str) -> int:
    """Return the display severity of a status; lower is worse."""
    return _STATUS_SEVERITY.get(str(status or "").strip().lower(), 4)


def status_for_severity(severity: int) -> str:
    """Return the display bucket a severity number stands for.

    The inverse of :func:`status_severity`, for callers that accumulate the
    worst severity across a set of paths and then need to name it.
    """
    return _SEVERITY_TO_STATUS.get(int(severity), "theoretical")


def complexity_rank(complexity: str) -> int:
    """Return the sort rank of a remediation complexity; lower is cheaper."""
    return _COMPLEXITY_ORDER.get(str(complexity or "").strip().lower(), 1)


def technique_label(technique: str) -> str:
    """Return the client-facing name of one technique.

    Delegates to the business-headline SSOT
    (:func:`~adscan_internal.services.attack_relation_labels.format_business_relation_label`),
    which renders ``"Replicate Directory Secrets (DCSync)"`` — the phrase an
    executive reads, the token an engineer verifies. Before this, each tier kept
    its own map: the paid ranking said ``"DCSync (Domain Replication)"`` while the
    same document's path steps said ``"Replicate Directory Secrets (DCSync)"``, and
    the web panel fell through to the bare token ``"dumplsa"``.
    """
    raw = str(technique or "").strip()
    if not raw:
        return ""
    try:
        label = format_business_relation_label(raw)
    except Exception:  # pragma: no cover - defensive; a label is never fatal
        label = ""
    return label or raw.replace("_", " ").title()


def finding_technique_labels(key: str) -> set[str]:
    """Return the client-facing technique labels a finding key can appear as.

    Resolves the finding's graph-relation aliases via the affected-assets SSOT
    (:func:`~adscan_internal.services.affected_assets._relation_aliases_for_vulnerability`),
    then names each alias through :func:`technique_label` — the SAME business-
    headline vocabulary the ``remediation_start_here`` rows carry. A posture
    finding with no graph edge (LDAP signing, RC4, NTLM) resolves to no path-
    technique label and so never matches a priority row. Best-effort: any failure
    yields an empty set.

    This is the ONE mapper both paid deliverables share to align a finding with
    the paths-broken ranking, so the Security Assessment Report and the Hardening
    Playbook can never disagree about which finding a priority row names.
    """
    try:
        from adscan_internal.services.affected_assets import (  # noqa: PLC0415
            _relation_aliases_for_vulnerability,
        )
    except Exception:  # noqa: BLE001 — a missing SSOT degrades to "not on path"
        return set()

    labels: set[str] = set()
    for alias in _relation_aliases_for_vulnerability(str(key or "")):
        label = technique_label(alias)
        if label:
            labels.add(label)
    return labels


def order_findings_by_priority(
    findings: Sequence[Mapping[str, Any]],
    priority_labels: Sequence[str],
) -> list[Any]:
    """Order findings to match the paths-broken priority ranking. Stable.

    ``priority_labels`` is the ordered technique-label list the paths-broken
    ranking produces (``remediation_start_here`` rows, or the ``action_label`` of
    :func:`compute_technique_priorities`). Every finding whose technique matches a
    priority row leads, in priority order — a finding's rank is the MINIMUM
    priority index across its matching labels (via :func:`finding_technique_labels`).
    Findings that match no priority row follow, keeping their incoming order (the
    caller's severity/CVSS order), so nothing is dropped and off-path ordering is
    unchanged.

    Returns a new list of the SAME finding objects; the input is never mutated.
    When ``priority_labels`` is empty the input order is preserved verbatim, so a
    workspace with no persisted ranking degrades to the legacy severity order.
    """
    label_rank: dict[str, int] = {}
    for idx, label in enumerate(priority_labels):
        lbl = str(label or "").strip()
        if lbl and lbl not in label_rank:
            label_rank[lbl] = idx
    findings_list = list(findings)
    if not label_rank:
        return findings_list
    unmatched_rank = len(label_rank)

    def _rank(finding: Any) -> int:
        key = ""
        if isinstance(finding, Mapping):
            key = str(finding.get("key") or "")
        matched = [label_rank[lbl] for lbl in finding_technique_labels(key) if lbl in label_rank]
        return min(matched) if matched else unmatched_rank

    return [
        finding
        for _, finding in sorted(
            enumerate(findings_list), key=lambda pair: (_rank(pair[1]), pair[0])
        )
    ]


def finding_priority_rank(finding: Mapping[str, Any], priority_labels: Sequence[str]) -> int | None:
    """Return a finding's 1-based ADscan-Priority position, or ``None`` if off-path.

    The position is derived from the SAME ``priority_labels`` order
    :func:`order_findings_by_priority` sorts by: the finding's rank is the minimum
    matching priority index, expressed 1-based. A finding whose technique is not on
    any validated-path priority row returns ``None`` (it has no paths-broken rank).
    """
    label_rank: dict[str, int] = {}
    for idx, label in enumerate(priority_labels):
        lbl = str(label or "").strip()
        if lbl and lbl not in label_rank:
            label_rank[lbl] = idx
    if not label_rank:
        return None
    key = str(finding.get("key") or "") if isinstance(finding, Mapping) else ""
    matched = [label_rank[lbl] for lbl in finding_technique_labels(key) if lbl in label_rank]
    return min(matched) + 1 if matched else None


# ── Reading one path ──────────────────────────────────────────────────────────


def _step_action(step: Any) -> str:
    """Return the relation a step exercises, from either step shape."""
    if isinstance(step, Mapping):
        for key in ("action", "relation", "type"):
            value = step.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return ""
    if isinstance(step, str):
        return step.strip()
    return ""


def path_technique_keys(path: Mapping[str, Any]) -> list[str]:
    """Return the distinct remediable technique keys one path exercises.

    Deduplicated, status-filtered and structural-filtered, in path order. All
    three matter:

    * A chain that uses ``GenericWrite`` twice is still one path. Counting the
      repeat pushed ``paths_eliminated`` above the number of paths that exist,
      which reads as nonsense beside a percentage.
    * A path that describes no client exposure — their configuration already
      closed the avenue, or ADscan had no surface to walk it — exercises nothing
      anyone should be asked to fix, so it yields no keys at all. Predicate:
      :func:`carries_client_exposure`.
    * A step the client cannot change is not a fix. That verdict belongs to the
      EDGE INSTANCE, not the relation: most group memberships are removable and
      most directory-replication rights are not, and the relation name cannot
      tell the two apart. SSOT:
      :mod:`~adscan_internal.services.remediability`, whose verdict the engine
      stamps onto every display-path step at derivation time (where the graph
      nodes are in hand). A step with no stamp — a snapshot record, or the web's
      thinner path shape — falls back to what the relation alone supports, which
      keeps a group membership suppressed rather than guessing.

    A technique survives when ANY instance of it on this path is remediable, so
    a domain where ``MemberOf`` is sometimes ``DOMAIN ADMINS ∈ ADMINISTRATORS``
    and sometimes ``BB.MORGAN ∈ IT`` reports the second without resurrecting the
    first.

    This function is where "what could a client fix on this path" is decided,
    and BOTH consumers read it: the ranking here, and the web's marginal-cover
    index (``adscan_web/backend/app/services/remediation_cover.py``, which takes
    it as an injected callable). Filtering here rather than inside the ranking
    loop is what keeps the two from disagreeing — a path the ranking has written
    off must not still count toward the union the client is promised.

    Keys stay as the lower-cased edge token the record carries; catalog lookups
    normalise separately, so two spellings of one technique are two rows here
    exactly as they are two rows in the attack path.
    """
    if not carries_client_exposure(path.get("status")):
        return []

    ordered: list[str] = []
    seen: set[str] = set()

    def _add(raw: Any, step: Any = None) -> None:
        key = str(raw or "").strip().lower()
        if not key or key in seen:
            return
        verdict = remediability_for_step(step) or classify_edge_remediability(key)
        if not verdict.is_remediable:
            return
        seen.add(key)
        ordered.append(key)

    steps = path.get("steps")
    if isinstance(steps, Sequence) and not isinstance(steps, (str, bytes)) and steps:
        saw_action = False
        for step in steps:
            action = _step_action(step)
            if action:
                saw_action = True
            _add(action, step)
        if saw_action:
            # Every action on this path was read, and any that survived are in
            # `ordered`. Falling through to `relations` here would re-read the
            # SAME edges without their endpoint facts and resurrect the ones the
            # instance rules just excluded.
            return ordered
        # A step shape we do not recognise yielded no actions at all — fall
        # through to `relations` rather than reporting the path as technique-free.

    relations = path.get("relations")
    if isinstance(relations, Sequence) and not isinstance(relations, (str, bytes)):
        for relation in relations:
            _add(relation)
    return ordered


def _build_domain_tier2_set(paths: Iterable[Mapping[str, Any]]) -> set[str] | None:
    """The DOMAIN-level ordinary Tier-2 user set, from every path's tier map.

    Aggregates ``meta.affected_users_tier_map`` across ALL paths and returns the
    accounts graded ``tier2`` (lower-cased). This must be domain-level, not
    per-path: only the broad-group paths (a handful) resolve full membership and
    carry a tier map, while the many single-user paths carry none — so a per-path
    filter would leak every single-user path's account. Aggregating gives the one
    ordinary-Tier-2 population the exposure-KPI headline counts (its "N of M
    standard users" figure). Returns ``None`` when NO path carries any tier data
    (an old snapshot) so callers degrade to an unfiltered union rather than a zero
    reach; returns a (possibly empty) set otherwise.
    """
    result: set[str] = set()
    saw_tier_data = False
    for path in paths or ():
        if not isinstance(path, Mapping):
            continue
        meta = path.get("meta")
        if not isinstance(meta, Mapping):
            continue
        tier_map = meta.get("affected_users_tier_map")
        if not isinstance(tier_map, Mapping) or not tier_map:
            continue
        saw_tier_data = True
        for user, tier in tier_map.items():
            if (
                isinstance(user, str)
                and user.strip()
                and str(tier).strip().lower() == "tier2"
            ):
                result.add(user.strip().lower())
    return result if saw_tier_data else None


def _path_affected_users(
    path: Mapping[str, Any], tier2_set: set[str] | None = None
) -> set[str]:
    """Return the distinct ordinary **Tier-2** users one path exposes, lower-cased.

    The set is read from the path record's ``meta.affected_users`` and FILTERED to
    ``tier2_set`` — the DOMAIN-level ordinary Tier-2 population the caller built once
    via :func:`_build_domain_tier2_set` (the SAME "ordinary (non-administrative)
    user" population the exposure-KPI headline counts, its "N of M standard users
    hold a reachable path" figure). A Tier-0 account (already privileged — its "path
    to Tier 0" is meaningless and the KPI explicitly excludes it) and any account
    not in the ordinary-Tier-2 set are dropped, so the reach numerator/denominator
    agree with the KPI's ordinary figure instead of the raw affected set (which
    mixes Tier-0 + untiered accounts). Lower-cased so ``SVC_TGS`` and ``svc_tgs``
    fold to one person, which keeps the per-technique union and the domain union
    self-consistent (one account once).

    ``tier2_set`` is ``None`` ONLY when the whole domain carried no tier data (an
    old snapshot that predates the stamp); the list is then kept UNFILTERED — a
    best-effort degrade so an old workspace still ranks rather than collapsing to
    zero reach. Returns an empty set when there is no ``meta.affected_users`` at
    all; never raises.
    """
    meta = path.get("meta")
    if not isinstance(meta, Mapping):
        return set()
    users = meta.get("affected_users")
    if not isinstance(users, (list, tuple, set)):
        return set()
    names = {u.strip().lower() for u in users if isinstance(u, str) and u.strip()}
    if tier2_set is not None:
        return names & tier2_set
    return names


def domain_affected_user_total(paths: Iterable[Mapping[str, Any]]) -> int:
    """Return the size of the UNION of ``meta.affected_users`` over all paths.

    The domain denominator for the affected-user REACH metric. Numerator (a
    technique's per-technique union) and denominator (this) come from the SAME
    ``_path_affected_users`` source, so reach_pct is self-consistent by
    construction — never crossed with the ``tier2_exposure_total`` /
    ``affected_principal_count`` populations (the documented two-denominator trap
    in :mod:`adscan_internal.services.exposure_score_service`). Overlap-honest: a
    user counted in ten paths is one person here.
    """
    materialized = [p for p in (paths or ()) if isinstance(p, Mapping)]
    tier2_set = _build_domain_tier2_set(materialized)
    union: set[str] = set()
    for path in materialized:
        union |= _path_affected_users(path, tier2_set)
    return len(union)


def _path_principal(path: Mapping[str, Any]) -> str:
    """Return the normalised principal a path starts from, or ``""``."""
    source = path.get("source")
    if not isinstance(source, str) or not source.strip():
        nodes = path.get("nodes")
        if isinstance(nodes, Sequence) and not isinstance(nodes, (str, bytes)):
            for node in nodes:
                if isinstance(node, str) and node.strip():
                    source = node
                    break
    return str(source or "").strip().upper()


def _path_domain(path: Mapping[str, Any], fallback: str) -> str:
    """Return the domain a path belongs to."""
    for key in ("_domain", "domain"):
        value = path.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return fallback


def iter_domain_tagged_paths(
    domains_data: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Flatten ``[{name, attack_paths}, …]`` into paths tagged with their domain.

    The adapter for callers that hold the per-domain report structure. Tagging
    rather than passing the domain alongside keeps one code path for both inputs,
    and keeps the domain attached to the path when a caller concatenates several
    domains' lists — the shape in which a multi-domain forest reaches the report.
    """
    tagged: list[dict[str, Any]] = []
    for domain_data in domains_data or ():
        if not isinstance(domain_data, Mapping):
            continue
        domain_name = str(domain_data.get("name") or "")
        for path in domain_data.get("attack_paths") or ():
            if not isinstance(path, Mapping):
                continue
            record = dict(path)
            record.setdefault("_domain", domain_name)
            tagged.append(record)
    return tagged


# ── The result ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TechniquePriority:
    """One attack technique, and what fixing it would close.

    Every figure any tier shows about a technique is here. A document picks the
    columns it renders and adds its own ordering; none of them recompute a figure.
    """

    #: The edge token as the attack graph emits it, lower-cased (``"dcsync"``).
    technique: str
    #: Client-facing name from the business-headline SSOT.
    label: str
    #: Attack paths this technique appears in.
    paths_affected: int
    #: Paths in the whole analysed set, the denominator of :attr:`share`.
    total_paths: int
    #: Distinct principals whose paths use this technique. "12 paths" is abstract;
    #: "12 paths, 9 accounts" is the number a client acts on.
    affected_principals: int
    #: Paths using this technique that ADscan executed end to end.
    exploited_paths: int
    #: Domains the technique was seen in, sorted.
    domains: tuple[str, ...]
    #: Worst path status among those paths, as a display bucket.
    worst_status: str
    #: Numeric form of :attr:`worst_status`; lower is worse.
    worst_status_severity: int
    #: Largest blast radius among the affected paths' top choke points.
    max_blast_radius: int
    #: Highest choke-point severity among the affected paths.
    max_choke_point_severity: str
    #: Strongest exploitation evidence among the affected paths (3 proven … 1 none).
    max_status_weight: int
    #: Identifier of the node this technique's top choke point maps to, best-effort
    #: — the object a client would fix. Taken from the max-blast affected path's
    #: ``top_choke_point`` (its ``node_id`` when present, else ``source_label``).
    #: Empty when no affected path carried a choke record. Used only to attach the
    #: structural-choke durability badge; it never sets order.
    top_choke_point_id: str
    remediation_complexity: str
    remediation_complexity_rank: int
    remediation_effort: str
    #: Remediation rendered against a representative step, so ``{source}`` and
    #: ``{target}`` reach the client as real principal names.
    remediation_steps: tuple[str, ...]
    can_fully_mitigate: bool
    mitre_technique_id: str | None
    mitre_technique_name: str | None
    #: Distinct affected USERS this technique exposes — the size of the UNION of
    #: each affected path's ``meta.affected_users``. This is the LEAD remediation
    #: metric (a fix whose technique is exposed to 1,172 people outranks one that
    #: breaks more graph paths but touches fewer people). Overlap-honest: it is a
    #: set union, so it is never summed across techniques (Kerberoast and ESC8 can
    #: both cover the same population). ``0`` when the paths carry no
    #: ``meta.affected_users`` (an older snapshot), which degrades reach to the
    #: legacy path-count lead rather than fabricating a number.
    reach_users: int = 0

    @property
    def share(self) -> float:
        """Fraction of all analysed paths this technique appears in."""
        return self.paths_affected / self.total_paths if self.total_paths else 0.0

    @property
    def share_pct(self) -> int:
        """:attr:`share` as a whole percentage, the form both documents print."""
        return round(self.share * 100)


# ── The derivation ────────────────────────────────────────────────────────────


def _catalog_metadata(technique: str, sample_step: Any) -> dict[str, Any]:
    """Return remediation + MITRE metadata for one technique.

    Imported lazily: the attack-step catalog is a large module and the appliance
    backend imports this one for figures alone on paths where no catalog is
    present. A missing catalog degrades to neutral defaults rather than failing
    the ranking.
    """
    defaults: dict[str, Any] = {
        "remediation_complexity": "medium",
        "remediation_effort": "",
        "remediation_steps": (),
        "can_fully_mitigate": True,
        "mitre_technique_id": None,
        "mitre_technique_name": None,
    }
    try:
        from adscan_internal.services.attack_step_catalog import (  # noqa: PLC0415
            get_attack_step_entry,
            render_step_remediation,
        )
    except Exception:
        return defaults

    try:
        entry = get_attack_step_entry(technique)
    except Exception:
        entry = None
    if entry is None:
        return defaults

    steps: tuple[str, ...] = tuple(entry.remediation_steps or ())
    if isinstance(sample_step, Mapping):
        try:
            rendered = render_step_remediation(dict(sample_step))
        except Exception:
            rendered = []
        if rendered:
            steps = tuple(rendered)

    return {
        "remediation_complexity": entry.remediation_complexity or "medium",
        "remediation_effort": entry.remediation_effort or "",
        "remediation_steps": steps,
        "can_fully_mitigate": bool(entry.can_fully_mitigate),
        "mitre_technique_id": entry.mitre_technique_id,
        "mitre_technique_name": entry.mitre_technique_name,
    }


def compute_technique_priorities(
    paths: Iterable[Mapping[str, Any]],
    *,
    domain: str = "",
    total_paths: int | None = None,
) -> list[TechniquePriority]:
    """Rank the techniques that carry the most attack paths.

    Args:
        paths: Attack-path records in either accepted shape (see the module
            docstring). Records may carry ``_domain``; otherwise ``domain``
            applies. Non-mapping entries are skipped.
        domain: Domain to attribute paths that do not name one themselves.
        total_paths: Denominator for :attr:`TechniquePriority.share`. Defaults to
            the number of usable records. Pass it explicitly when the caller
            counted the paths itself, so the report's percentages match the path
            count printed beside them.

    Returns:
        One entry per remediable technique, ordered by paths covered, then by
        cheapest remediation, then by worst status. Ties keep the order the paths
        were traversed in, so two documents built from the same records agree row
        for row.

        Only paths that describe client exposure contribute
        (:func:`carries_client_exposure`), so a technique whose every path was
        closed by the client's own configuration — or that ADscan had no surface
        to walk — produces no entry at all. ``total_paths`` is unaffected: the
        denominator stays the path total the document prints beside the table.
    """
    accumulators: dict[str, dict[str, Any]] = {}
    counted = 0

    # The DOMAIN-level ordinary Tier-2 population, resolved ONCE so every path's
    # affected users filter to the SAME set the exposure-KPI headline counts. Only
    # the broad-group paths carry a tier map, so it must be aggregated across all
    # paths (a per-path filter leaks the single-user paths). Materialize the
    # iterable because we pass over it twice (build the set, then accumulate).
    materialized_paths = list(paths or ())
    tier2_set = _build_domain_tier2_set(materialized_paths)

    for path in materialized_paths:
        if not isinstance(path, Mapping):
            continue
        # Every usable record counts toward the denominator — the document still
        # lists the path — while a path carrying no client exposure yields no
        # techniques (``path_technique_keys``) and so touches no accumulator.
        counted += 1

        status = normalize_path_status(path.get("status"))
        severity = status_severity(status)
        evidence = _STATUS_EVIDENCE_WEIGHT.get(status, 1)
        path_domain = _path_domain(path, domain)
        principal = _path_principal(path)
        path_users = _path_affected_users(path, tier2_set)

        choke_point = path.get("top_choke_point")
        choke_id = ""
        if isinstance(choke_point, Mapping):
            try:
                blast = int(choke_point.get("blast_radius") or 1)
            except (TypeError, ValueError):
                blast = 1
            choke_severity = (
                str(choke_point.get("severity") or "medium").strip().lower()
            )
            # The object a client would fix: an explicit node id when the graph
            # stamped one, else the choke's source label. Carried through so the
            # report can attach the structural-choke durability badge — it never
            # affects ordering.
            for _id_key in ("node_id", "source_label"):
                _id_val = choke_point.get(_id_key)
                if isinstance(_id_val, str) and _id_val.strip():
                    choke_id = _id_val.strip()
                    break
        else:
            blast = 1
            choke_severity = "medium"

        steps = path.get("steps")
        step_list = (
            list(steps)
            if isinstance(steps, Sequence) and not isinstance(steps, (str, bytes))
            else []
        )

        for technique in path_technique_keys(path):
            state = accumulators.get(technique)
            if state is None:
                state = {
                    "paths_affected": 0,
                    "principals": set(),
                    "affected_users": set(),
                    "domains": set(),
                    "exploited_paths": 0,
                    "worst_severity": severity,
                    "max_blast": 0,
                    "max_choke_severity": "low",
                    "max_evidence": 0,
                    "sample_step": None,
                    "top_choke_point_id": "",
                }
                accumulators[technique] = state

            state["paths_affected"] += 1
            if principal:
                state["principals"].add(principal)
            # Accumulate the per-technique affected-USER union (the reach lead).
            # A set union, so a user on several of this technique's paths counts
            # once — the overlap-honesty rule.
            state["affected_users"] |= path_users
            if path_domain:
                state["domains"].add(path_domain)
            if status == "exploited":
                state["exploited_paths"] += 1
            state["worst_severity"] = min(state["worst_severity"], severity)
            # The choke id follows the max-blast path: the widest-blast choke is
            # the one whose durability badge is worth surfacing.
            if blast > state["max_blast"] and choke_id:
                state["top_choke_point_id"] = choke_id
            elif not state["top_choke_point_id"] and choke_id:
                state["top_choke_point_id"] = choke_id
            state["max_blast"] = max(state["max_blast"], blast)
            if _SEVERITY_WEIGHT.get(choke_severity, 0) > _SEVERITY_WEIGHT.get(
                state["max_choke_severity"], 0
            ):
                state["max_choke_severity"] = choke_severity
            state["max_evidence"] = max(state["max_evidence"], evidence)

            # A representative step, used only to resolve the templated
            # remediation's {source}/{target} into real principals. Prefer one
            # carrying a details dict, where those names actually live; a step
            # without one still beats nothing, because the catalog degrades to a
            # generic client-safe phrase rather than printing a placeholder.
            #
            # It must also be an instance the client can actually change. A path
            # can carry both kinds of one technique — ``BB.MORGAN ∈ IT`` and
            # ``DOMAIN ADMINS ∈ ADMINISTRATORS`` — and naming the second one in
            # the remediation would print the exact advice this filtering exists
            # to remove: take Domain Admins out of Administrators.
            sample = state["sample_step"]
            if sample is None or not isinstance(sample.get("details"), Mapping):
                for step in step_list:
                    if (
                        not isinstance(step, Mapping)
                        or _step_action(step).lower() != technique
                    ):
                        continue
                    verdict = remediability_for_step(step)
                    if verdict is not None and not verdict.is_remediable:
                        continue
                    has_details = isinstance(step.get("details"), Mapping)
                    if sample is None or has_details:
                        sample = dict(step)
                        state["sample_step"] = sample
                    if has_details:
                        break

    denominator = counted if total_paths is None else max(int(total_paths), 0)

    results: list[TechniquePriority] = []
    for technique, state in accumulators.items():
        metadata = _catalog_metadata(technique, state["sample_step"])
        worst_severity = int(state["worst_severity"])
        results.append(
            TechniquePriority(
                technique=technique,
                label=technique_label(technique),
                paths_affected=int(state["paths_affected"]),
                total_paths=denominator,
                affected_principals=len(state["principals"]),
                exploited_paths=int(state["exploited_paths"]),
                domains=tuple(sorted(state["domains"])),
                worst_status=_SEVERITY_TO_STATUS.get(worst_severity, "theoretical"),
                worst_status_severity=worst_severity,
                max_blast_radius=int(state["max_blast"]),
                max_choke_point_severity=str(state["max_choke_severity"]),
                max_status_weight=int(state["max_evidence"]),
                top_choke_point_id=str(state["top_choke_point_id"]),
                remediation_complexity=str(metadata["remediation_complexity"]),
                remediation_complexity_rank=complexity_rank(
                    str(metadata["remediation_complexity"])
                ),
                remediation_effort=str(metadata["remediation_effort"]),
                remediation_steps=tuple(metadata["remediation_steps"]),
                can_fully_mitigate=bool(metadata["can_fully_mitigate"]),
                mitre_technique_id=metadata["mitre_technique_id"],
                mitre_technique_name=metadata["mitre_technique_name"],
                reach_users=len(state["affected_users"]),
            )
        )

    results.sort(
        key=lambda entry: (
            -entry.paths_affected,
            entry.remediation_complexity_rank,
            entry.worst_status_severity,
        )
    )
    return results
