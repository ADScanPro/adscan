"""Outbound fan-out → capability-node rollup (single source of truth).

A **presentation** view computed over the already-materialized attack graph.
In large environments one source principal + one edge kind (Account Operators
``GenericAll`` over the mailbox population, Exchange groups ``WriteDacl`` over
most computers) fans out to hundreds or thousands of near-identical control
transitions. The engine correctly materializes every one of them as a distinct
attack step; the *presentation* is then a wall of N rows that reads as noise
rather than the single highest-value finding it actually is:

    Account Operators controls 4,996 user objects via one delegated right.

This module collapses that fan-out **for display only**. It never drops a path
or edge from the engine — the DFS / containment output stays byte-identical
(the byte-identity gate in ``scripts/debug_attack_path_filters.py`` is the red
line). It is a pure, side-effect-free function of its inputs, testable in
isolation, and consumed by every surface (CLI recap, PDF report, web dashboard)
exactly like :mod:`compromise_class` and :mod:`severity` are single-source.

Design invariants:

* **Rollup key = ``(source_principal_id, edge_kind, target_tier_class)``.**
  Tier-class is REQUIRED in the key — a source with ``GenericWrite`` over
  {1 DC, 3 member servers, 4,996 workstations} collapses to THREE steps
  (→ 1 Tier-0-direct, → 3 Tier-1, → 4,996 Tier-2), each keeping its bucket's
  severity and compromise class, so the severity delta stays visible. A
  Tier-0-direct bucket never collapses silently — every target label is named.
* **Threshold, not a cap.** A bucket collapses for display only when its count
  reaches :func:`resolve_collapse_floor` (env ``ADSCAN_FANOUT_COLLAPSE_FLOOR``,
  default 10). Below the floor the caller renders per-target exactly as today.
* **Never-drop.** ``sum(step.count) + len(passthrough) == len(inputs)`` always
  holds for de-duplicated targets: every input is either inside a collapsed
  bucket or in the passthrough.

The existing SSOTs are reused, no new vocabulary is invented: tier from
:mod:`compromise_class` (:class:`PrivilegeTier`, ``privilege_tier_*``), edge
kind from :mod:`edge_kind` (:func:`classify_edge_kind`), severity from
:mod:`severity` (:func:`compute_edge_severity`).
"""

from __future__ import annotations

import os
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from adscan_internal.services.compromise_class import (
    CompromiseClass,
    PrivilegeTier,
    derive_compromise_class_from_path,
    privilege_tier_for_node,
    privilege_tier_label,
)
from adscan_internal.services.edge_kind import (
    EdgeKind,
    classify_edge_kind,
    edge_control_strength,
)
from adscan_internal.services.severity import (
    EdgeSeverityInput,
    Severity,
    compute_edge_severity,
    edge_proven_unauthenticated_reachable,
    severity_rank,
)

# Default fan-out collapse floor. A bucket collapses for DISPLAY only once it
# holds this many distinct targets; below it, the caller renders per-target as
# today. Env-overridable (``ADSCAN_FANOUT_COLLAPSE_FLOOR``) like the local-reuse
# topology precedent — read at call time so tests / operators can override it.
_FANOUT_COLLAPSE_FLOOR: int = 10

# Bounded evidence sample size for a collapsed bucket (non-Tier-0-direct). A
# Tier-0-direct bucket bypasses this and names every target (they are the
# headline finding, never elided).
_FANOUT_SAMPLE_MAX: int = 5

# Well-known source-principal classification for the blast-radius view — the SSOT
# both the PRODUCER (the non-executable-edge gate below) and the PDF display
# (:mod:`adscan_internal.pro.reporting.html_pdf_generator`) reference, so a source
# is classified in exactly ONE place.
#
# An UNAUTHENTICATED identity (Anonymous Logon, well-known SID ``S-1-5-7``) holds
# NO credentials at all — it can only READ (the anonymous LDAP bind) and CANNOT
# exercise a write ACE, so its control/escalation/derived edges are
# non-executable (see :func:`_source_is_unauthenticated`). An IMPLICIT identity
# (Everyone, Authenticated Users) IS an authenticated population that CAN write,
# so its control edges are legitimate reach. Both read differently in the display
# from a named privileged group whose membership a client can audit and remove.
# SIDs are Microsoft constants; the name set is the fallback for a record that
# carries only a display label (the collector labels Anonymous Logon by name).
_UNAUTHENTICATED_SOURCE_SIDS: frozenset[str] = frozenset({"S-1-5-7"})
_UNAUTHENTICATED_SOURCE_NAMES: frozenset[str] = frozenset({"anonymous logon", "anonymous"})
_IMPLICIT_SOURCE_SIDS: frozenset[str] = frozenset({"S-1-1-0", "S-1-5-11"})
_IMPLICIT_SOURCE_NAMES: frozenset[str] = frozenset({"everyone", "authenticated users"})

# The write/exercise edge kinds an unauthenticated (no-credential) actor CANNOT
# perform. A control ACE, an escalation primitive, or a proven-control derived
# edge all require an authenticated session to exercise; from Anonymous Logon
# they are non-executable and must not be counted as blast-radius reach. AUTH
# edges (the anonymous LDAP bind / read exposure) are the only real
# unauthenticated reach and are NEVER gated.
_WRITE_EXERCISE_EDGE_KINDS: frozenset[EdgeKind] = frozenset(
    {EdgeKind.CONTROL, EdgeKind.ESCALATION, EdgeKind.DERIVED}
)


def fanout_source_access_class(source_principal_id: Any, source_label: Any = "") -> str:
    """Classify a blast-radius source as unauthenticated / implicit / named.

    The single classifier for the source of a fan-out spoke, shared by the
    producer gate and the PDF display so both agree by construction.

    Returns ``"unauthenticated"`` for the Anonymous Logon identity (reach that
    needs no credential at all), ``"implicit"`` for a population every account
    already belongs to (Everyone, Authenticated Users), and ``""`` for a named
    principal whose membership a client can audit and remove. Detected by
    well-known SID first (precise), then by canonical display name (the
    collector labels Anonymous Logon by name, not a SID). Accepts a raw
    ``name:<label>`` node id and strips the prefix.

    Args:
        source_principal_id: The source node id / SID (may carry a ``name:``
            prefix or a ``user@domain`` suffix).
        source_label: The source display label, used as the name fallback.

    Returns:
        ``"unauthenticated"``, ``"implicit"``, or ``""``.
    """
    raw = str(source_principal_id or "").strip()
    bare = raw.split("name:", 1)[-1].strip() if raw.lower().startswith("name:") else raw
    sid = bare.upper()
    name = str(source_label or bare or "").strip().lower().split("@", 1)[0].strip()
    if sid in _UNAUTHENTICATED_SOURCE_SIDS or name in _UNAUTHENTICATED_SOURCE_NAMES:
        return "unauthenticated"
    if sid in _IMPLICIT_SOURCE_SIDS or name in _IMPLICIT_SOURCE_NAMES:
        return "implicit"
    return ""


def _source_is_unauthenticated(source_principal_id: Any, source_label: Any = "") -> bool:
    """Return True when the source is the unauthenticated (Anonymous Logon) identity."""
    return fanout_source_access_class(source_principal_id, source_label) == "unauthenticated"


@dataclass(frozen=True)
class GroupActorIndex:
    """Which groups have >=1 authenticated real actor (a transitive member).

    Built by the caller from the membership SSOT
    (:func:`attack_paths_core.build_group_member_index`, which already merges the
    implicit primary-group / Domain Users membership and expands nested groups)
    and threaded into :func:`fanout_input_from_edge` so the blast-radius gate can
    drop an EMPTY group — one with 0 transitive real ``User`` / ``Computer``
    members — whose control reach no actor could ever exercise. This keeps this
    module pure and schema-agnostic: no membership import lives here.

    Authoritative ONLY for its own domain. A source label from a DIFFERENT domain
    (cross-forest / well-known) returns ``None`` (unknown), so the gate stays
    conservative and never drops reach it cannot judge.

    Attributes:
        domain_suffix: The ``@DOMAIN`` suffix (upper-case) the index covers,
            e.g. ``"@HTB.LOCAL"``.
        populated_labels: Canonical (upper-case ``NAME@DOMAIN``) labels of every
            group with >=1 transitive real actor member. A group absent from this
            set — but within ``domain_suffix`` — is authoritatively empty.
    """

    domain_suffix: str
    populated_labels: frozenset[str]

    def status_for(self, source_label: Any) -> bool | None:
        """Return ``True`` (has an actor) / ``False`` (empty) / ``None`` (unknown).

        ``True`` when the group is in :attr:`populated_labels`; ``False`` when it
        is within this index's domain but absent (authoritatively empty); ``None``
        when the label belongs to a different domain (out of authority → keep).
        """
        raw = str(source_label or "").strip()
        if raw.lower().startswith("name:"):
            raw = raw.split("name:", 1)[-1].strip()
        canonical = raw.upper()
        if not canonical.endswith(self.domain_suffix):
            return None
        return canonical in self.populated_labels


def blast_radius_source_is_exercisable(
    relation: str,
    source_principal_id: Any,
    source_label: Any = "",
    *,
    group_actor_status: bool | None = None,
) -> bool:
    """Return True when a write/exercise edge's SOURCE could be exercised by an actor.

    The principled blast-radius gate (honesty / Exposure-Validation): a
    ``control`` / ``escalation`` / ``derived`` edge is EXERCISABLE reach only when
    its source principal has >=1 AUTHENTICATED real actor that could exercise it.
    It SUBSUMES the unauthenticated-source gate and adds the empty-group case:

    * an ``auth`` / read edge (the anonymous bind, ``CanRDP`` …) is always real
      reach — never gated here (returns ``True``);
    * an UNAUTHENTICATED identity (Anonymous Logon) holds no credential and cannot
      exercise a write ACE → ``False``;
    * a broad IMPLICIT identity (Everyone / Authenticated Users) is populated by
      every authenticated principal → ``True``;
    * a group the caller resolved as EMPTY (``group_actor_status is False`` — 0
      transitive real actors) has no actor to exercise its reach → ``False``;
    * a real actor (User / Computer), a populated group, or an unknown/unjudgeable
      source → ``True`` (conservative; never drop unproven reach).

    Args:
        relation: Raw terminal-edge relation (e.g. ``"GenericAll"``).
        source_principal_id: The source node id / SID.
        source_label: The source display label (name fallback for classification).
        group_actor_status: For a GROUP source, ``True`` if it has >=1 transitive
            real actor member, ``False`` if authoritatively empty, ``None`` if
            unknown / not a group / no membership data. Resolved by the caller via
            :meth:`GroupActorIndex.status_for` — pass ``None`` for non-group sources.

    Returns:
        ``True`` to keep the edge as blast-radius reach, ``False`` to drop it.
    """
    if classify_edge_kind(relation) not in _WRITE_EXERCISE_EDGE_KINDS:
        return True
    access = fanout_source_access_class(source_principal_id, source_label)
    if access == "unauthenticated":
        return False
    if access == "implicit":
        return True
    if group_actor_status is False:
        return False
    return True


def resolve_collapse_floor(floor: int | None = None) -> int:
    """Return the effective fan-out collapse floor.

    An explicit ``floor`` argument wins (used by callers and tests). Otherwise
    the env override ``ADSCAN_FANOUT_COLLAPSE_FLOOR`` is consulted, falling back
    to :data:`_FANOUT_COLLAPSE_FLOOR`. The floor is clamped to at least 2 — a
    floor of 0 or 1 would "collapse" a single path, which is never a fan-out.

    Args:
        floor: Explicit floor, or ``None`` to consult the environment.

    Returns:
        The effective floor, always ``>= 2``.
    """
    if floor is not None:
        return max(2, int(floor))
    raw = str(os.getenv("ADSCAN_FANOUT_COLLAPSE_FLOOR", "")).strip()
    if raw:
        try:
            return max(2, int(raw))
        except ValueError:
            pass
    return max(2, _FANOUT_COLLAPSE_FLOOR)


@dataclass(frozen=True)
class FanoutInput:
    """One materialized control transition, normalized for the rollup.

    A caller adapts its own path/edge shape into these (see
    :func:`fanout_input_from_path`) before calling :func:`rollup_fanout`. This
    keeps the rollup pure and schema-agnostic, and makes it unit-testable with
    synthetic inputs — no shell, no graph, no DC.

    Attributes:
        source_principal_id: Stable identity of the principal that exercises the
            terminal edge (the node immediately before the last edge). The
            rollup groups on this — NOT on the path's origin node.
        source_label: Display label for that principal.
        edge_relation: Raw relation of the terminal edge, e.g. ``"GenericAll"``.
            Its :class:`EdgeKind` (via :func:`classify_edge_kind`) is part of the
            rollup key; the raw string is kept for the technical drill-down line.
        target_label: Display label of the immediate target object controlled by
            the terminal edge.
        target_tier: The target's OWN granted :class:`PrivilegeTier` (axis 1),
            resolved by the caller from the target node. Part of the rollup key.
        source_compromise_class: The source principal's compromise class, fed to
            the severity SSOT. ``None`` = low-priv / unclassified.
        target_compromise_class: The target's compromise class, fed to severity.
        path_compromise_class: The full path's compromise class as already
            computed by the engine (the summary record's ``compromise_class``).
            Reused verbatim for the collapsed step's client label — not
            recomputed.
        target_is_domain: True when the target node is the Domain object itself.
        proven_unauthenticated_reachable: True when the terminal edge's reach
            was PROVEN over the unauthenticated (null-session) phase (read from
            the edge's ``notes.unauthenticated_reachable``). Fed to the severity
            SSOT so a proven no-credential path into Tier 0 uplifts to CRITICAL.
    """

    source_principal_id: str
    source_label: str
    edge_relation: str
    target_label: str
    target_tier: PrivilegeTier
    source_compromise_class: CompromiseClass | None = None
    target_compromise_class: CompromiseClass | None = None
    path_compromise_class: CompromiseClass | None = None
    target_is_domain: bool = False
    proven_unauthenticated_reachable: bool = False


@dataclass(frozen=True)
class FanoutStep:
    """A collapsed fan-out bucket — one capability node standing for N targets.

    Carries everything the three surfaces (CLI recap, PDF report, web dashboard)
    need to render the capability node without recomputing. The rollup key is
    ``(source_principal_id, edge_kind, target_tier_class)``.

    Attributes:
        source_principal_id: Identity of the fanning-out principal.
        source_label: Display label for that principal.
        edge_kind: Canonical :class:`EdgeKind` of the fanned-out edge.
        edge_relation: A representative raw relation (e.g. ``"GenericAll"``) for
            the technical drill-down sub-line. Client headlines must NOT surface
            this raw token (nomenclature standard).
        target_tier_class: The shared target :class:`PrivilegeTier` of the bucket.
        tier_label: The buyer-facing label for ``target_tier_class``.
        count: Number of distinct targets collapsed into this step.
        severity: The most severe :class:`Severity` across the bucket (never
            understated), via the severity SSOT.
        compromise_class: The representative path :class:`CompromiseClass`.
        sample_target_labels: Bounded evidence sample of target labels. For a
            Tier-0-direct bucket this is EVERY target (never elided); otherwise
            it is capped at :data:`_FANOUT_SAMPLE_MAX`.
    """

    source_principal_id: str
    source_label: str
    edge_kind: EdgeKind
    edge_relation: str
    target_tier_class: PrivilegeTier
    tier_label: str
    count: int
    severity: Severity
    compromise_class: CompromiseClass
    sample_target_labels: tuple[str, ...]


@dataclass(frozen=True)
class FanoutRollup:
    """Result of :func:`rollup_fanout` — the collapse view over the inputs.

    Attributes:
        collapsed: The collapsed capability nodes (buckets at/above the floor),
            ordered most-severe first, then highest-count.
        passthrough: The below-floor inputs, in their original input order. The
            caller renders these per-target exactly as today.
    """

    collapsed: tuple[FanoutStep, ...] = ()
    passthrough: tuple[FanoutInput, ...] = ()

    @property
    def collapsed_target_count(self) -> int:
        """Return the total number of targets folded into collapsed steps."""
        return sum(step.count for step in self.collapsed)


# ---------------------------------------------------------------------------
# Adapter — normalize a summary record / edge dict into a FanoutInput.
# ---------------------------------------------------------------------------


def resolve_fanout_target_tier(
    node: Mapping[str, Any] | None,
    *,
    is_tier0_asset: bool = False,
) -> PrivilegeTier:
    """Return the granted :class:`PrivilegeTier` of a fan-out target node.

    Thin alias over the axis-1 SSOT :func:`compromise_class.privilege_tier_for_node`,
    which dispatches by node kind: a Computer grades through the DC /
    Tier-0-asset / server / workstation path, a user, group or container through
    the direct-breaker / escalation-group path, and the Domain object is Tier 0
    direct. Kept as a named entry point because the fan-out axis reads better at
    its call sites; it adds no logic of its own.

    Because the tier is part of the rollup KEY and is rendered as the bucket's
    client label, a mis-graded target both mislabels the row and files it in the
    wrong bucket. Grading a principal from the node's ``isTierZero`` tag alone
    did exactly that — DnsAdmins (untagged) landed in a "Tier 2: Standard"
    bucket and Domain Admins (tagged) in an "escalation-capable" one, each
    contradicting the report's own client glossary.

    Args:
        node: A BloodHound/ADscan-shaped node dict, or ``None``.
        is_tier0_asset: True when the caller has already flagged this node a
            Tier 0 asset outside group identity (``isTierZero`` / ``highvalue``
            / ADCS CA / Exchange). A degraded fallback only — a node whose group
            identity resolves is graded from that.

    Returns:
        The :class:`PrivilegeTier`; :attr:`PrivilegeTier.TIER2` for ``None``.
    """
    return privilege_tier_for_node(node, is_tier0_asset=is_tier0_asset)


#: Severity floor per TARGET tier for the blast-radius display. Reaching a Tier-0
#: object is a containment-boundary event, so a grant that reaches Tier-0 targets
#: must never rank below one that reaches only Tier-2 targets (CLAUDE § "graded
#: target criticality"). The floor RAISES a computed severity up to the tier's
#: minimum; it never lowers one (never understate a blast radius) and never
#: touches INFO / STRUCTURAL — those are the Domain-Breaker-source tautologies the
#: HTB Forest guard suppresses, and flooring them would resurface the 444 false
#: criticals. Applied once in :func:`_build_step`.
_TARGET_TIER_SEVERITY_FLOOR: dict[PrivilegeTier, Severity] = {
    PrivilegeTier.TIER0_DIRECT: Severity.CRITICAL,
    PrivilegeTier.TIER0_ESCALATION_CAPABLE: Severity.HIGH,
    PrivilegeTier.TIER1: Severity.MEDIUM,
}


def _apply_target_tier_floor(severity: Severity, tier: PrivilegeTier) -> Severity:
    """Raise ``severity`` to the target tier's floor; never lower it, never touch INFO.

    A reach onto a Tier-0 object is graded at least as severe as the tier warrants
    so the blast-radius table cannot invert the tier boundary (a Tier-2-reaching
    grant out-ranking a Tier-0-reaching one). INFO / STRUCTURAL pass through
    untouched so the Domain-Breaker-source HTB-Forest suppression is preserved.
    """
    if severity in (Severity.INFO, Severity.STRUCTURAL):
        return severity
    floor = _TARGET_TIER_SEVERITY_FLOOR.get(tier)
    if floor is not None and severity_rank(floor) < severity_rank(severity):
        return floor
    return severity


def _reconcile_target_compromise_class(
    tier: PrivilegeTier, cc: CompromiseClass | None
) -> CompromiseClass | None:
    """Drop a compromise class that CONTRADICTS the authoritative target tier.

    The target tier is resolved by :func:`privilege_tier_for_node` from the
    RID-based group classifier (``classify_principal_by_groups`` — the locale-
    independent SSOT). A name-based compromise class can disagree with it: the
    Tactical-Findings node classifier substring-matches "Cloneable Domain
    Controllers" to ``DOMAIN_BREAKER`` while its RID (522) grades Tier 2. Left
    alone, that false breaker drives the Tier-2 fan-out bucket to a CRITICAL that
    out-ranks a genuine Tier-0 bucket — the exact tier-boundary inversion the
    blast-radius table must not show. So when the authoritative tier is NOT Tier 0,
    a ``DOMAIN_BREAKER`` / ``PRIVILEGED_ESCALATOR`` class is a contradiction and is
    dropped (the tier wins); a non-privileged class is kept. Tier-0 targets keep
    their class (the tier floor handles their severity).
    """
    if tier.is_tier0:
        return cc
    if cc in (CompromiseClass.DOMAIN_BREAKER, CompromiseClass.PRIVILEGED_ESCALATOR):
        return None
    return cc


def _coerce_compromise_class(value: Any) -> CompromiseClass | None:
    """Return a :class:`CompromiseClass` for a raw string / enum, else ``None``."""
    if isinstance(value, CompromiseClass):
        return value
    token = str(value or "").strip().lower()
    if not token:
        return None
    for member in CompromiseClass:
        if member.value == token:
            return member
    return None


def _node_is_tier0_asset(node: Mapping[str, Any] | None) -> bool:
    """Return True when a node carries a Tier 0 asset flag (best-effort)."""
    if not isinstance(node, Mapping):
        return False
    props = node.get("properties")
    props = props if isinstance(props, Mapping) else {}
    for source in (node, props):
        for key in ("isTierZero", "istierzero", "highvalue", "highValue"):
            if bool(source.get(key)):
                return True
    return False


def fanout_input_from_path(
    path: Mapping[str, Any],
    node_index: Mapping[str, Mapping[str, Any]] | None = None,
) -> FanoutInput | None:
    """Adapt one attack-path summary record into a :class:`FanoutInput`.

    The terminal edge is the fan-out edge: its acting principal is the node just
    before the last relation (``nodes[-2]``) and its target is the last node
    (``nodes[-1]``). A pure-membership or empty path yields ``None``.

    The target's tier is resolved from ``node_index`` when supplied (label →
    node dict); with no node data the target defaults to Tier 2 (users) — the
    caller SHOULD supply a node index so computer targets grade correctly.

    Args:
        path: An attack-path summary dict (``nodes``, ``relations``, ``source``,
            ``target``, ``compromise_class``).
        node_index: Optional label → node-dict map for tier resolution.

    Returns:
        A :class:`FanoutInput`, or ``None`` when the record has no terminal edge.
    """
    raw_nodes = path.get("nodes")
    raw_edges = path.get("relations") or path.get("rels")
    if not isinstance(raw_nodes, list) or len(raw_nodes) < 2:
        return None
    if not isinstance(raw_edges, list) or not raw_edges:
        return None

    nodes = [str(n) for n in raw_nodes]
    edges = [str(e) for e in raw_edges]
    edge_relation = edges[-1]
    if classify_edge_kind(edge_relation) is EdgeKind.MEMBERSHIP:
        # A pure-membership terminus is structural, never a fan-out finding.
        return None

    target_label = str(path.get("target") or nodes[-1])
    # The acting principal is the node the terminal edge departs from. For a
    # single-edge path this is the path source.
    source_principal_id = nodes[-2] if len(nodes) >= 2 else str(path.get("source") or nodes[0])

    # An unauthenticated actor (Anonymous Logon) cannot exercise a write ACE, so
    # a control/escalation/derived terminus from it is non-executable and never a
    # blast-radius finding (its read exposure stays via its auth edges). The path
    # adapter has no membership index at this seam, so the empty-group case is not
    # judged here (the edge adapter — the primary production path — handles it).
    if not blast_radius_source_is_exercisable(edge_relation, source_principal_id, source_principal_id):
        return None

    node_index = node_index or {}
    target_node = node_index.get(target_label)
    target_is_domain = str((target_node or {}).get("kind") or "").strip().lower() == "domain"
    target_tier = resolve_fanout_target_tier(
        target_node, is_tier0_asset=_node_is_tier0_asset(target_node)
    )

    return FanoutInput(
        source_principal_id=source_principal_id,
        source_label=source_principal_id,
        edge_relation=edge_relation,
        target_label=target_label,
        target_tier=target_tier,
        source_compromise_class=_coerce_compromise_class(
            (node_index.get(source_principal_id) or {}).get("compromise_class")
        ),
        target_compromise_class=_reconcile_target_compromise_class(
            target_tier,
            _coerce_compromise_class((target_node or {}).get("compromise_class")),
        ),
        path_compromise_class=_coerce_compromise_class(
            path.get("compromise_class") or path.get("outcome_class")
        ),
        target_is_domain=target_is_domain,
    )


def fanout_input_from_edge(
    edge: Mapping[str, Any],
    node_index: Mapping[str, Mapping[str, Any]] | None = None,
    *,
    group_actor_index: GroupActorIndex | None = None,
) -> FanoutInput | None:
    """Adapt one raw attack-graph edge into a :class:`FanoutInput`.

    Cheaper and count-accurate alternative to :func:`fanout_input_from_path`
    when the caller has the raw graph (``{nodes, edges}``): each control/auth
    edge IS a fan-out spoke from its ``from`` principal, with no path traversal.
    ``node_index`` is keyed by node **id** (matching ``edge["from"]`` /
    ``edge["to"]``); the display labels are read off the resolved nodes.

    A membership / structural edge, or an edge whose endpoints are missing from
    ``node_index``, yields ``None``.

    The spoke's REACH (``path_compromise_class``) is derived from the SSOT
    :func:`derive_compromise_class_from_path` over this single edge — a fan-out
    spoke IS a one-edge path, so its reach class is the same question the path
    classifier answers. Leaving it unset made every edge-derived bucket fall
    back to a hardcoded ``compromise_enabler``, so a row whose targets are
    Domain Admins still reported the weakest class on the ladder.

    Args:
        edge: A raw graph edge dict (``from``, ``to``, ``relation``).
        node_index: node-id → node-dict map. Nodes may carry a stamped
            ``compromise_class`` (the caller resolves it from the SSOT
            classifier) for severity grading.

    Returns:
        A :class:`FanoutInput`, or ``None`` for a non-fan-out edge.
    """
    relation = str(edge.get("relation") or edge.get("kind_label") or "")
    if not relation or classify_edge_kind(relation) is EdgeKind.MEMBERSHIP:
        return None

    node_index = node_index or {}
    from_id = str(edge.get("from") or edge.get("source") or "")
    to_id = str(edge.get("to") or edge.get("target") or "")
    from_node = node_index.get(from_id)
    to_node = node_index.get(to_id)
    if not isinstance(from_node, Mapping) or not isinstance(to_node, Mapping):
        return None

    source_label = str(from_node.get("label") or from_node.get("name") or from_id)

    # The membership-based blast-radius gate — keep this write/exercise edge only
    # when its SOURCE has >=1 authenticated real actor that could exercise it. An
    # unauthenticated actor (Anonymous Logon) cannot write; a GROUP with 0
    # transitive real members has no actor to exercise its reach either — both are
    # NON-EXECUTABLE and must not be counted as blast-radius reach (honesty /
    # Exposure-Validation). A real User/Computer, a populated group, or a broad
    # well-known identity (Everyone / Authenticated Users) stays; an auth/read edge
    # (the anonymous LDAP bind) is real reach and is never gated. The empty-group
    # verdict is resolved ONLY for GROUP sources against the per-domain membership
    # index, so a real actor is never mistaken for an empty group.
    group_actor_status: bool | None = None
    if group_actor_index is not None and str(from_node.get("kind") or "").strip().lower() == "group":
        group_actor_status = group_actor_index.status_for(source_label)
    if not blast_radius_source_is_exercisable(
        relation, from_id, source_label, group_actor_status=group_actor_status
    ):
        return None

    target_label = str(to_node.get("label") or to_node.get("name") or to_id)
    target_is_domain = str(to_node.get("kind") or "").strip().lower() == "domain"
    target_tier = resolve_fanout_target_tier(
        to_node, is_tier0_asset=_node_is_tier0_asset(to_node)
    )

    return FanoutInput(
        source_principal_id=from_id,
        source_label=source_label,
        edge_relation=relation,
        target_label=target_label,
        target_tier=target_tier,
        source_compromise_class=_coerce_compromise_class(from_node.get("compromise_class")),
        target_compromise_class=_reconcile_target_compromise_class(
            target_tier, _coerce_compromise_class(to_node.get("compromise_class"))
        ),
        path_compromise_class=derive_compromise_class_from_path([dict(edge)], to_node),
        target_is_domain=target_is_domain,
        proven_unauthenticated_reachable=edge_proven_unauthenticated_reachable(edge),
    )


# ---------------------------------------------------------------------------
# The rollup — pure grouping + collapse.
# ---------------------------------------------------------------------------


@dataclass
class _Bucket:
    """Mutable accumulator for one ``(source, edge_kind, tier)`` group."""

    key: tuple[str, EdgeKind, PrivilegeTier]
    inputs: list[FanoutInput] = field(default_factory=list)
    seen_targets: set[str] = field(default_factory=set)


def _severity_for_input(inp: FanoutInput, kind: EdgeKind) -> Severity:
    """Compute one input's severity via the severity SSOT (no recomputation)."""
    return compute_edge_severity(
        EdgeSeverityInput(
            source_compromise_class=inp.source_compromise_class,
            target_compromise_class=inp.target_compromise_class,
            edge_kind=kind,
            target_privilege_tier=inp.target_tier,
            edge_control_strength=edge_control_strength(inp.edge_relation),
            target_is_tier0_asset=inp.target_tier.is_tier0,
            target_is_domain=inp.target_is_domain,
            proven_unauthenticated_reachable=inp.proven_unauthenticated_reachable,
        )
    )


def _build_step(bucket: _Bucket) -> FanoutStep:
    """Materialize a collapsed :class:`FanoutStep` from an at-floor bucket."""
    _source, kind, tier = bucket.key
    inputs = bucket.inputs
    representative = inputs[0]

    # Most-severe over the bucket — never understate a blast radius.
    best_input = inputs[0]
    best_sev = _severity_for_input(inputs[0], kind)
    for inp in inputs[1:]:
        sev = _severity_for_input(inp, kind)
        if severity_rank(sev) < severity_rank(best_sev):
            best_sev, best_input = sev, inp

    # Grade the bucket's severity by the TARGET tier so a Tier-0-reaching blast
    # radius is never ranked below a Tier-2 one (the tier-boundary inversion the
    # blast-radius table must not show). Raises up to the tier floor only; never
    # lowers, and never touches the INFO/STRUCTURAL Domain-Breaker-source
    # tautologies the genuine-fan-out filter drops.
    best_sev = _apply_target_tier_floor(best_sev, tier)

    # Distinct target labels, first-seen order. A Tier-0-direct bucket names
    # every target (headline); other tiers cap the evidence sample.
    ordered_targets: list[str] = []
    seen: set[str] = set()
    for inp in inputs:
        if inp.target_label not in seen:
            seen.add(inp.target_label)
            ordered_targets.append(inp.target_label)
    if tier is PrivilegeTier.TIER0_DIRECT:
        sample = tuple(ordered_targets)
    else:
        sample = tuple(ordered_targets[:_FANOUT_SAMPLE_MAX])

    compromise_class = (
        best_input.path_compromise_class
        or representative.path_compromise_class
        or CompromiseClass.COMPROMISE_ENABLER
    )

    return FanoutStep(
        source_principal_id=representative.source_principal_id,
        source_label=representative.source_label,
        edge_kind=kind,
        edge_relation=best_input.edge_relation,
        target_tier_class=tier,
        tier_label=privilege_tier_label(tier),
        count=len(bucket.seen_targets),
        severity=best_sev,
        compromise_class=compromise_class,
        sample_target_labels=sample,
    )


def rollup_fanout(
    inputs: Sequence[FanoutInput],
    *,
    floor: int | None = None,
) -> FanoutRollup:
    """Collapse fan-out control transitions into capability nodes for display.

    Groups the inputs by ``(source_principal_id, edge_kind, target_tier_class)``
    and collapses any group whose DISTINCT-target count reaches the floor into a
    single :class:`FanoutStep`. A ``TIER0_DIRECT`` group is ALWAYS surfaced as a
    step regardless of count (reaching the domain control plane is the headline
    finding, never elided; its sample names every target). Non-Tier-0-direct
    groups below the floor pass through unchanged, in the original input order,
    for per-target rendering.

    This is a pure function — no I/O, no graph access, no engine mutation. It is
    a VIEW over the already-materialized graph and never drops a path: the
    never-drop invariant ``sum(step.count) + len(passthrough) == len(inputs)``
    holds for de-duplicated targets (a repeated ``(source, edge, tier, target)``
    input is counted once; when a bucket is below the floor every raw input
    passes through).

    Args:
        inputs: Normalized control transitions (see :func:`fanout_input_from_path`).
        floor: Explicit collapse floor; ``None`` consults
            :func:`resolve_collapse_floor`.

    Returns:
        A :class:`FanoutRollup` with collapsed capability nodes (most-severe
        first) and below-floor passthrough inputs.
    """
    effective_floor = resolve_collapse_floor(floor)

    buckets: "OrderedDict[tuple[str, EdgeKind, PrivilegeTier], _Bucket]" = OrderedDict()
    for inp in inputs:
        kind = classify_edge_kind(inp.edge_relation)
        key = (inp.source_principal_id, kind, inp.target_tier)
        bucket = buckets.get(key)
        if bucket is None:
            bucket = _Bucket(key=key)
            buckets[key] = bucket
        bucket.inputs.append(inp)
        bucket.seen_targets.add(inp.target_label)

    collapsed: list[FanoutStep] = []
    passthrough: list[FanoutInput] = []
    for bucket in buckets.values():
        # A Tier-0-direct bucket is ALWAYS surfaced as a capability node (the
        # headline finding — reaching the domain control plane), even below the
        # floor, and it names every target (never elided). Other tiers collapse
        # only once they reach the floor; below it they pass through per-target.
        _tier = bucket.key[2]
        if _tier is PrivilegeTier.TIER0_DIRECT or len(bucket.seen_targets) >= effective_floor:
            collapsed.append(_build_step(bucket))
        else:
            passthrough.extend(bucket.inputs)

    # Worst-first: most-severe, then target tier (Tier 0 ahead of Tier 2 on a
    # severity tie), then highest count — NOT by object count. The target-tier
    # severity floor above guarantees a Tier-0-reaching bucket is graded at least
    # as severe as any Tier-2 one, so worst-first ordering can never invert the
    # tier boundary (a Tier-2 CRITICAL above a Tier-0 HIGH). Mirrored in
    # adscan_web/frontend/lib/attack-fanout.ts.
    collapsed.sort(
        key=lambda s: (severity_rank(s.severity), -s.target_tier_class.rank, -s.count)
    )

    return FanoutRollup(collapsed=tuple(collapsed), passthrough=tuple(passthrough))


# ---------------------------------------------------------------------------
# The genuine-fan-out filter + serialization — one SSOT for every surface.
# ---------------------------------------------------------------------------


def genuine_fanout_steps(
    inputs: Sequence[FanoutInput],
    *,
    floor: int | None = None,
    max_steps: int | None = None,
) -> tuple[FanoutStep, ...]:
    """Roll up inputs and keep only genuine "privilege blast radius" fan-outs.

    The single filter every consuming surface applies (CLI recap, PDF report,
    web) so the "blast radius" finding reads identically everywhere. It runs the
    :func:`rollup_fanout` SSOT, then keeps a collapsed step ONLY when both hold:

    * its distinct-target ``count`` reaches the collapse floor (a blast radius
      means MANY targets — this drops the single-edge ``TIER0_DIRECT`` capability
      nodes the rollup always emits, which surface as ordinary critical findings
      rather than blast radii), and
    * its ``severity`` is a real finding — NOT :attr:`Severity.INFO` /
      :attr:`Severity.STRUCTURAL` (drops the Domain-Breaker structural
      tautologies, where the AD hierarchy grants full control by definition).

    Args:
        inputs: Normalized control transitions (see :func:`fanout_input_from_path`
            / :func:`fanout_input_from_edge`).
        floor: Explicit collapse floor; ``None`` consults
            :func:`resolve_collapse_floor`.
        max_steps: Optional cap on the number of returned steps (most-severe
            first). ``None`` returns every genuine fan-out.

    Returns:
        The genuine blast-radius :class:`FanoutStep`s, most-severe first.
    """
    rollup = rollup_fanout(inputs, floor=floor)
    effective_floor = resolve_collapse_floor(floor)
    actionable = [
        step
        for step in rollup.collapsed
        if step.count >= effective_floor
        and step.severity not in (Severity.INFO, Severity.STRUCTURAL)
    ]
    if max_steps is not None:
        actionable = actionable[: max(0, max_steps)]
    return tuple(actionable)


def fanout_step_to_dict(step: FanoutStep) -> dict[str, Any]:
    """Serialize one :class:`FanoutStep` to the CLI↔web JSON contract.

    The exact shape persisted under the top-level ``attack_fanout_rollup`` key of
    ``technical_report.json`` and consumed by the web (Slice 3). Enum fields are
    emitted as their ``.value`` strings; the sample list is a plain ``list``.
    This is the SINGLE source of the schema — the persistence writer, the PDF
    renderer's fallback, and the contract test all reference it, so the shape can
    never drift between producer and consumer.

    Args:
        step: The collapsed capability node to serialize.

    Returns:
        A JSON-serializable dict with the frozen schema.
    """
    return {
        "source_principal_id": step.source_principal_id,
        "source_label": step.source_label,
        "edge_kind": step.edge_kind.value,
        "edge_relation": step.edge_relation,
        "target_tier_class": step.target_tier_class.value,
        "tier_label": step.tier_label,
        "count": int(step.count),
        "severity": step.severity.value,
        "compromise_class": step.compromise_class.value,
        "sample_target_labels": list(step.sample_target_labels),
    }


__all__ = [
    "FanoutInput",
    "FanoutStep",
    "FanoutRollup",
    "GroupActorIndex",
    "resolve_collapse_floor",
    "resolve_fanout_target_tier",
    "fanout_source_access_class",
    "blast_radius_source_is_exercisable",
    "fanout_input_from_path",
    "fanout_input_from_edge",
    "rollup_fanout",
    "genuine_fanout_steps",
    "fanout_step_to_dict",
]
