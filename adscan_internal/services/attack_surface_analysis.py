"""Attack Surface Analysis — shared, Word/PDF-free service.

Computes node centrality, technique (relation) centrality, and remediation
priority from a set of attack paths for a single domain.

The technique axis — *which fix closes the most paths* — is derived by the shared
single source of truth :mod:`adscan_internal.services.technique_priority`, the
same derivation the paid deliverable's remediation ranking reads. Only the NODE
axis (which single object the most paths run through) lives here, because it
answers a different question. Nothing about a technique is recomputed in this
module.

Designed to be importable by:
- CLI report renderer  (adscan_internal.pro.reporting.*)
- adscan_web CTEM backend (per-finding remediation intelligence)
- the LITE exposure report's choke-point table

No Word, PDF, or graphviz dependencies.  Pure Python + stdlib.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from adscan_internal.services.technique_priority import (
    carries_client_exposure,
    compute_technique_priorities,
    normalize_path_status,
    status_for_severity,
    status_severity,
)


def _path_nodes(path: dict[str, Any]) -> list[str]:
    """Return all node IDs for a path."""
    nodes = path.get("nodes")
    if not isinstance(nodes, list):
        return []
    return [str(n) for n in nodes if n]


# ── Public data structures ─────────────────────────────────────────────────────


@dataclass
class NodeCentralityEntry:
    """A node that appears in one or more attack paths."""

    node_id: str
    path_count: int  # number of paths passing through this node
    worst_status: str  # most severe status among paths using this node
    worst_status_severity: int  # numeric severity (0 = most severe)
    is_entry_point: bool = False  # True if node appears as path source
    is_tier0_target: bool = False  # True if node appears as path target (last node)
    is_intermediate: bool = False  # True if node is neither source nor target
    #: Of :attr:`path_count`, how many describe client exposure — a path whose
    #: avenue the client's configuration already closed, or that ADscan had no
    #: surface to walk, still runs through this node topologically but is not
    #: something to fix. Remediation reads this count; graph rendering reads
    #: :attr:`path_count`.
    exposed_path_count: int = 0
    #: :attr:`worst_status` restricted to those exposure-bearing paths.
    exposed_worst_status: str = "theoretical"


@dataclass
class RelationCentralityEntry:
    """A relation/step type that appears in one or more attack paths."""

    relation: str
    path_count: int
    worst_status: str
    worst_status_severity: int
    # Remediation metadata (populated if step_metadata is available)
    remediation_complexity: str = "medium"
    remediation_effort: str = ""
    can_fully_mitigate: bool = True
    #: Distinct principals whose paths use this relation. "12 paths" is abstract;
    #: "12 paths, 9 accounts" is the number a client acts on.
    affected_principals: int = 0


@dataclass
class RemediationTarget:
    """A prioritised remediation action: fix this → eliminate N paths.

    Targets are ranked by:
    1. paths_eliminated (descending) — maximum path elimination
    2. remediation_complexity (ascending) — lowest effort first when equal
    3. worst_status_severity (ascending) — confirmed exploited paths first
    """

    target_id: str  # node_id or relation name
    target_label: str  # human-readable
    target_type: str  # "node" | "relation"
    paths_eliminated: int  # paths that become invalid if this is fixed
    total_paths: int
    elimination_rate: float  # paths_eliminated / total_paths
    worst_status: str
    remediation_complexity: str  # low | medium | high | very_high
    remediation_complexity_rank: int  # 0–3 for sorting
    remediation_effort: str
    can_fully_mitigate: bool = True
    #: Distinct principals whose paths this target eliminates.
    affected_principals: int = 0


@dataclass
class AttackSurfaceAnalysis:
    """Complete attack surface analysis for one domain."""

    domain: str
    total_paths: int
    paths_by_status: dict[str, int]  # status -> count
    node_centrality: list[NodeCentralityEntry]  # sorted by path_count desc
    relation_centrality: list[RelationCentralityEntry]  # sorted by path_count desc
    remediation_priority: list[RemediationTarget]  # sorted by priority
    # Raw data (for graph rendering)
    unique_nodes: set[str] = field(default_factory=set)
    unique_relations: set[str] = field(default_factory=set)
    entry_nodes: set[str] = field(default_factory=set)
    tier0_nodes: set[str] = field(default_factory=set)


# ── Core analysis ──────────────────────────────────────────────────────────────


def compute_attack_surface_analysis(
    paths: list[dict[str, Any]],
    domain: str = "",
) -> AttackSurfaceAnalysis:
    """Compute full attack surface analysis for a list of attack paths.

    Args:
        paths:  List of attack path dicts (nodes, relations, status, etc.)
        domain: Domain name for labelling.

    Returns:
        AttackSurfaceAnalysis with centrality, remediation priority, etc.
    """
    if not isinstance(paths, list) or not paths:
        return AttackSurfaceAnalysis(
            domain=domain,
            total_paths=0,
            paths_by_status={},
            node_centrality=[],
            relation_centrality=[],
            remediation_priority=[],
        )

    # ── Pass 1: the TECHNIQUE axis, from the shared SSOT ─────────────────────
    # "Which technique carries the most paths" is one question with one
    # derivation, shared with the paid deliverable's remediation ranking.
    techniques = compute_technique_priorities(paths, domain=domain)

    # ── Pass 2: the NODE axis, local ─────────────────────────────────────────
    # A different question: which single OBJECT do the most paths run through.
    status_counts: dict[str, int] = {}
    # node_id -> {path_count, worst_severity, is_entry, is_target, is_intermediate}
    node_data: dict[str, dict] = {}
    all_nodes: set[str] = set()
    entry_nodes: set[str] = set()
    tier0_nodes: set[str] = set()

    for path in paths:
        if not isinstance(path, dict):
            continue

        status = normalize_path_status(path.get("status"))
        severity = status_severity(status)
        status_counts[status] = status_counts.get(status, 0) + 1
        exposed = carries_client_exposure(path.get("status"))

        nodes = _path_nodes(path)

        for i, node_id in enumerate(nodes):
            all_nodes.add(node_id)
            is_entry = i == 0
            is_target = i == len(nodes) - 1
            is_intermediate = not is_entry and not is_target

            if is_entry:
                entry_nodes.add(node_id)
            if is_target:
                tier0_nodes.add(node_id)

            if node_id not in node_data:
                node_data[node_id] = {
                    "path_count": 0,
                    "worst_severity": severity,
                    "exposed_path_count": 0,
                    "exposed_worst_severity": None,
                    "is_entry": is_entry,
                    "is_target": is_target,
                    "is_intermediate": is_intermediate,
                }
            d = node_data[node_id]
            d["path_count"] += 1
            if severity < d["worst_severity"]:
                d["worst_severity"] = severity
            if exposed:
                d["exposed_path_count"] += 1
                current = d["exposed_worst_severity"]
                if current is None or severity < current:
                    d["exposed_worst_severity"] = severity
            if is_entry:
                d["is_entry"] = True
            if is_target:
                d["is_target"] = True
            if is_intermediate:
                d["is_intermediate"] = True

    total = len([p for p in paths if isinstance(p, dict)])

    node_centrality: list[NodeCentralityEntry] = []
    for node_id, d in node_data.items():
        worst_sev = d["worst_severity"]
        worst_status = status_for_severity(worst_sev)
        exposed_sev = d["exposed_worst_severity"]
        node_centrality.append(
            NodeCentralityEntry(
                node_id=node_id,
                path_count=d["path_count"],
                worst_status=worst_status,
                worst_status_severity=worst_sev,
                is_entry_point=d["is_entry"],
                is_tier0_target=d["is_target"],
                is_intermediate=d["is_intermediate"],
                exposed_path_count=d["exposed_path_count"],
                exposed_worst_status=(
                    status_for_severity(exposed_sev)
                    if exposed_sev is not None
                    else "theoretical"
                ),
            )
        )
    node_centrality.sort(key=lambda e: (-e.path_count, e.worst_status_severity))

    # ── Pass 3: project the shared technique ranking ─────────────────────────
    # Structural edges never reach this list — the SSOT already excludes them,
    # so a built-in group nesting can never be offered to a client as a fix.
    relation_centrality: list[RelationCentralityEntry] = [
        RelationCentralityEntry(
            relation=entry.technique,
            path_count=entry.paths_affected,
            worst_status=entry.worst_status,
            worst_status_severity=entry.worst_status_severity,
            remediation_complexity=entry.remediation_complexity,
            remediation_effort=entry.remediation_effort,
            can_fully_mitigate=entry.can_fully_mitigate,
            affected_principals=entry.affected_principals,
        )
        for entry in techniques
    ]
    relation_centrality.sort(key=lambda e: (-e.path_count, e.worst_status_severity))
    all_relations: set[str] = {entry.relation for entry in relation_centrality}

    # ── Pass 4: Remediation priority list ───────────────────────────────────
    # Two kinds of target, deduplicated into one ranking:
    #   * a TECHNIQUE — fix the class (patch Zerologon, revoke the ACL pattern)
    #     and every path that uses it closes;
    #   * an intermediate NODE — one over-connected object many paths run
    #     through, which is usually a symptom of one of the techniques above.
    # Sorted by paths eliminated, then cheapest remediation, then worst status.

    remediation_targets: list[RemediationTarget] = [
        RemediationTarget(
            target_id=entry.technique,
            target_label=entry.label,
            target_type="relation",
            paths_eliminated=entry.paths_affected,
            total_paths=total,
            elimination_rate=entry.paths_affected / total if total else 0.0,
            worst_status=entry.worst_status,
            remediation_complexity=entry.remediation_complexity,
            remediation_complexity_rank=entry.remediation_complexity_rank,
            remediation_effort=entry.remediation_effort,
            can_fully_mitigate=entry.can_fully_mitigate,
            affected_principals=entry.affected_principals,
        )
        for entry in techniques
    ]

    # Node-based targets (intermediate nodes with high centrality). Counted on
    # exposure-bearing paths only, for the same reason the technique axis is: a
    # node whose routes the client's configuration already closed is not work to
    # do, and a node ADscan could not reach is our data gap, not their exposure.
    for entry in node_centrality:
        if entry.is_entry_point or entry.is_tier0_target:
            continue  # entry points and targets are structural, not remediable
        if entry.exposed_path_count < 2:
            continue  # single-path nodes: not worth listing separately
        elimination_rate = entry.exposed_path_count / total if total else 0.0
        remediation_targets.append(
            RemediationTarget(
                target_id=entry.node_id,
                target_label=entry.node_id,
                target_type="node",
                paths_eliminated=entry.exposed_path_count,
                total_paths=total,
                elimination_rate=elimination_rate,
                worst_status=entry.exposed_worst_status,
                remediation_complexity="medium",  # node-level: ACL/config fix
                remediation_complexity_rank=1,
                remediation_effort=(
                    f"Remediate the vulnerabilities or ACL misconfigurations that "
                    f"allow {entry.exposed_path_count} attack path(s) to pass through this object."
                ),
                can_fully_mitigate=True,
            )
        )

    remediation_targets.sort(
        key=lambda t: (
            -t.paths_eliminated,
            t.remediation_complexity_rank,
            status_severity(t.worst_status),
        )
    )

    return AttackSurfaceAnalysis(
        domain=domain,
        total_paths=total,
        paths_by_status=status_counts,
        node_centrality=node_centrality,
        relation_centrality=relation_centrality,
        remediation_priority=remediation_targets,
        unique_nodes=all_nodes,
        unique_relations=all_relations,
        entry_nodes=entry_nodes,
        tier0_nodes=tier0_nodes,
    )


#: Minimum number of exposure-bearing paths that must run through an
#: intermediate node before it counts as a convergence point. Two is the same
#: threshold the node-based remediation targets already use above (a node one
#: path crosses is not a junction), so the count reported here and the node
#: entries a client sees in the remediation ranking always agree.
CONVERGENCE_FLOOR = 2


def convergence_metrics(
    analysis: AttackSurfaceAnalysis,
    *,
    floor: int = CONVERGENCE_FLOOR,
) -> dict[str, int]:
    """Return the convergence (choke-point) shape of an analysis, as counts.

    Pure projection of an :class:`AttackSurfaceAnalysis` that
    :func:`compute_attack_surface_analysis` already built — nothing is
    recomputed and no path is re-walked. Every value is a plain ``int``, which
    is what makes the result safe to send as telemetry: no node id, principal,
    host or domain name can travel with it.

    The axis measured here is TOPOLOGICAL convergence — how many attack paths
    funnel through one object. It is deliberately NOT
    :mod:`~adscan_internal.services.choke_point_classifier`, which flags a
    privilege TRANSITION on a single edge; the two answer different questions
    and must never be mixed in one published figure.

    Convergence is counted on ``exposed_path_count``, not ``path_count``, for
    the same reason the node-based remediation targets are: a path whose avenue
    the client's own configuration already closed still crosses the node
    topologically but is not exposure, and a path ADscan had no surface to walk
    is our data gap rather than their risk.

    Args:
        analysis: Output of :func:`compute_attack_surface_analysis`.
        floor: Minimum exposure-bearing paths through an intermediate node for
            it to count as a convergence point. Values below 1 are clamped.

    Returns:
        A mapping with five integer keys:

        * ``paths_total_analyzed`` — paths the analysis was built from.
        * ``nodes_on_paths_total`` — distinct objects appearing on any path.
          The denominator for "what share of the attack surface converges".
        * ``choke_point_nodes`` — intermediate objects (never a path's entry
          point and never its target) that at least ``floor`` exposure-bearing
          paths run through.
        * ``max_paths_through_node`` — the largest exposure-bearing path count
          of any single intermediate object; ``0`` when there is none. Entry
          points and targets are excluded because every path trivially touches
          its own endpoints, which would make the figure meaningless.
        * ``paths_closed_by_top_3_fixes`` — an UPPER BOUND on how many paths the
          three highest-ranked remediation targets close between them. Targets
          can cover the same path, and a :class:`RemediationTarget` carries a
          count rather than a path set, so the true union lies between the
          largest single target and this sum. Clamped to
          ``paths_total_analyzed``. Read it as "no more than N", never as an
          exact union.
    """
    empty = {
        "choke_point_nodes": 0,
        "max_paths_through_node": 0,
        "nodes_on_paths_total": 0,
        "paths_total_analyzed": 0,
        "paths_closed_by_top_3_fixes": 0,
    }
    if not isinstance(analysis, AttackSurfaceAnalysis):
        return empty

    threshold = max(1, int(floor))
    total_paths = max(0, int(analysis.total_paths or 0))
    centrality = analysis.node_centrality or []

    # Strictly intermediate: a node that is never an entry point and never a
    # target. This is the exact predicate the node-based remediation targets
    # use, so the two views of "choke point" cannot drift apart.
    intermediate_counts = [
        max(0, int(entry.exposed_path_count or 0))
        for entry in centrality
        if not entry.is_entry_point and not entry.is_tier0_target
    ]

    top_three = top_remediation_targets(analysis, top_n=3)
    closed_upper_bound = sum(max(0, int(t.paths_eliminated or 0)) for t in top_three)

    return {
        "choke_point_nodes": sum(1 for c in intermediate_counts if c >= threshold),
        "max_paths_through_node": max(intermediate_counts, default=0),
        "nodes_on_paths_total": len(centrality),
        "paths_total_analyzed": total_paths,
        "paths_closed_by_top_3_fixes": min(closed_upper_bound, total_paths),
    }


def top_remediation_targets(
    analysis: AttackSurfaceAnalysis,
    *,
    top_n: int = 10,
    include_partial_mitigation: bool = True,
) -> list[RemediationTarget]:
    """Return the top N remediation targets from the analysis.

    Args:
        analysis: Output of compute_attack_surface_analysis().
        top_n:    Maximum number of targets to return.
        include_partial_mitigation: Include targets where can_fully_mitigate=False.
    """
    targets = analysis.remediation_priority
    if not include_partial_mitigation:
        targets = [t for t in targets if t.can_fully_mitigate]
    return targets[:top_n]
