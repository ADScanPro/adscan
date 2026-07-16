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
    privilege_tier_for_computer_node,
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

    Pure node-dict → tier resolution for the fan-out bucketing axis. Reuses the
    computer SSOT :func:`privilege_tier_for_computer_node` (DC / Tier-0-asset /
    server / workstation grading). Domain objects are Tier-0-direct. Non-computer
    principals (users, groups) are Tier 2 unless flagged as a Tier 0 asset, in
    which case they grade escalation-capable (the conservative non-direct
    verdict) — matching the degraded fallback in
    :func:`privilege_tier_for_computer`.

    Args:
        node: A BloodHound/ADscan-shaped node dict, or ``None``.
        is_tier0_asset: True when the caller has already flagged this node a
            Tier 0 asset outside group membership (``isTierZero`` / ``highvalue``
            / ADCS CA / Exchange).

    Returns:
        The :class:`PrivilegeTier`; :attr:`PrivilegeTier.TIER2` for ``None``.
    """
    if not isinstance(node, Mapping):
        return PrivilegeTier.TIER2

    kind = str(node.get("kind") or "").strip().lower()
    if kind == "domain":
        return PrivilegeTier.TIER0_DIRECT
    if kind == "computer":
        return privilege_tier_for_computer_node(node, is_tier0_asset=is_tier0_asset)

    # User / group / container target — no per-object computer role. Defer to
    # the Tier 0 asset flag; else standard Tier 2.
    if is_tier0_asset:
        return PrivilegeTier.TIER0_ESCALATION_CAPABLE
    return PrivilegeTier.TIER2


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
        target_compromise_class=_coerce_compromise_class(
            (target_node or {}).get("compromise_class")
        ),
        path_compromise_class=_coerce_compromise_class(
            path.get("compromise_class") or path.get("outcome_class")
        ),
        target_is_domain=target_is_domain,
    )


def fanout_input_from_edge(
    edge: Mapping[str, Any],
    node_index: Mapping[str, Mapping[str, Any]] | None = None,
) -> FanoutInput | None:
    """Adapt one raw attack-graph edge into a :class:`FanoutInput`.

    Cheaper and count-accurate alternative to :func:`fanout_input_from_path`
    when the caller has the raw graph (``{nodes, edges}``): each control/auth
    edge IS a fan-out spoke from its ``from`` principal, with no path traversal.
    ``node_index`` is keyed by node **id** (matching ``edge["from"]`` /
    ``edge["to"]``); the display labels are read off the resolved nodes.

    A membership / structural edge, or an edge whose endpoints are missing from
    ``node_index``, yields ``None``.

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
    target_label = str(to_node.get("label") or to_node.get("name") or to_id)
    target_is_domain = str(to_node.get("kind") or "").strip().lower() == "domain"

    return FanoutInput(
        source_principal_id=from_id,
        source_label=source_label,
        edge_relation=relation,
        target_label=target_label,
        target_tier=resolve_fanout_target_tier(
            to_node, is_tier0_asset=_node_is_tier0_asset(to_node)
        ),
        source_compromise_class=_coerce_compromise_class(from_node.get("compromise_class")),
        target_compromise_class=_coerce_compromise_class(to_node.get("compromise_class")),
        path_compromise_class=None,
        target_is_domain=target_is_domain,
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

    # Most-severe first, then highest count — the headline order.
    collapsed.sort(key=lambda s: (severity_rank(s.severity), -s.count))

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
    "resolve_collapse_floor",
    "resolve_fanout_target_tier",
    "fanout_input_from_path",
    "fanout_input_from_edge",
    "rollup_fanout",
    "genuine_fanout_steps",
    "fanout_step_to_dict",
]
