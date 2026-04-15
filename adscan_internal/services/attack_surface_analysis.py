"""Attack Surface Analysis — shared, Word/PDF-free service.

Computes node centrality, relation centrality, and remediation priority
from a set of attack paths for a single domain.

Designed to be importable by:
- CLI report renderer  (adscan_internal.pro.reporting.*)
- adscan_web CTEM backend (future — exposes this data via REST API)
- CLI shell commands (attack_surface, remediation_priority, etc.)

No Word, PDF, or graphviz dependencies.  Pure Python + stdlib.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ── Status priority (lower = more severe) ─────────────────────────────────────
_STATUS_SEVERITY: dict[str, int] = {
    "exploited": 0,
    "success": 0,
    "succeeded": 0,
    "blocked": 1,
    "unsupported": 2,
    "attempted": 3,
    "failed": 3,
    "error": 3,
    "partial": 3,
    "theoretical": 4,
}

_COMPLEXITY_ORDER: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "very_high": 3,
}


def _normalize_status(raw: str) -> str:
    s = str(raw or "theoretical").strip().lower()
    if s in {"exploited", "success", "succeeded"}:
        return "exploited"
    if s == "blocked":
        return "blocked"
    if s == "unsupported":
        return "unsupported"
    if s in {"attempted", "failed", "error", "partial"}:
        return "attempted"
    return "theoretical"


def _status_severity(status: str) -> int:
    return _STATUS_SEVERITY.get(status, 4)


def _path_relations(path: dict[str, Any]) -> list[str]:
    """Return the non-MemberOf relation names for a path."""
    relations = path.get("relations")
    if not isinstance(relations, list):
        return []
    return [
        str(r).strip().lower()
        for r in relations
        if str(r).strip().lower() != "memberof"
    ]


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
    # Lazy import to avoid circular deps at module level.
    # attack_step_catalog is in services/ — no pro/reporting dep needed.
    try:
        from adscan_internal.services.attack_step_catalog import (
            get_step_metadata,
        )

        _has_step_meta = True
    except ImportError:
        _has_step_meta = False

    if not isinstance(paths, list) or not paths:
        return AttackSurfaceAnalysis(
            domain=domain,
            total_paths=0,
            paths_by_status={},
            node_centrality=[],
            relation_centrality=[],
            remediation_priority=[],
        )

    # ── Pass 1: per-path data ────────────────────────────────────────────────
    status_counts: dict[str, int] = {}
    # node_id -> {path_count, worst_severity, is_entry, is_target, is_intermediate}
    node_data: dict[str, dict] = {}
    # relation_key -> {path_count, worst_severity, meta}
    rel_data: dict[str, dict] = {}
    # All unique node ids and relation keys across all paths
    all_nodes: set[str] = set()
    all_relations: set[str] = set()
    entry_nodes: set[str] = set()
    tier0_nodes: set[str] = set()

    for path in paths:
        if not isinstance(path, dict):
            continue

        raw_status = path.get("status") or "theoretical"
        status = _normalize_status(str(raw_status))
        severity = _status_severity(status)
        status_counts[status] = status_counts.get(status, 0) + 1

        nodes = _path_nodes(path)
        rels = _path_relations(path)

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
                    "is_entry": is_entry,
                    "is_target": is_target,
                    "is_intermediate": is_intermediate,
                }
            d = node_data[node_id]
            d["path_count"] += 1
            if severity < d["worst_severity"]:
                d["worst_severity"] = severity
            if is_entry:
                d["is_entry"] = True
            if is_target:
                d["is_target"] = True
            if is_intermediate:
                d["is_intermediate"] = True

        for rel_key in rels:
            all_relations.add(rel_key)

            if _has_step_meta:
                meta = get_step_metadata(rel_key)
                complexity = meta.get("remediation_complexity", "medium")
                effort = meta.get("remediation_effort", "")
                can_mitigate = bool(meta.get("can_fully_mitigate", True))
                complexity_rank = _COMPLEXITY_ORDER.get(complexity, 1)
            else:
                complexity = "medium"
                effort = ""
                can_mitigate = True
                complexity_rank = 1

            if rel_key not in rel_data:
                rel_data[rel_key] = {
                    "path_count": 0,
                    "worst_severity": severity,
                    "remediation_complexity": complexity,
                    "remediation_effort": effort,
                    "can_fully_mitigate": can_mitigate,
                    "complexity_rank": complexity_rank,
                }
            d = rel_data[rel_key]
            d["path_count"] += 1
            if severity < d["worst_severity"]:
                d["worst_severity"] = severity

    total = len([p for p in paths if isinstance(p, dict)])

    # ── Pass 2: build NodeCentralityEntry list ───────────────────────────────
    _sev_to_status = {
        v: k
        for k, v in _STATUS_SEVERITY.items()
        if k in {"exploited", "blocked", "unsupported", "attempted", "theoretical"}
    }

    node_centrality: list[NodeCentralityEntry] = []
    for node_id, d in node_data.items():
        worst_sev = d["worst_severity"]
        worst_status = _sev_to_status.get(worst_sev, "theoretical")
        node_centrality.append(
            NodeCentralityEntry(
                node_id=node_id,
                path_count=d["path_count"],
                worst_status=worst_status,
                worst_status_severity=worst_sev,
                is_entry_point=d["is_entry"],
                is_tier0_target=d["is_target"],
                is_intermediate=d["is_intermediate"],
            )
        )
    node_centrality.sort(key=lambda e: (-e.path_count, e.worst_status_severity))

    # ── Pass 3: build RelationCentralityEntry list ───────────────────────────
    relation_centrality: list[RelationCentralityEntry] = []
    for rel_key, d in rel_data.items():
        worst_sev = d["worst_severity"]
        worst_status = _sev_to_status.get(worst_sev, "theoretical")
        relation_centrality.append(
            RelationCentralityEntry(
                relation=rel_key,
                path_count=d["path_count"],
                worst_status=worst_status,
                worst_status_severity=worst_sev,
                remediation_complexity=d["remediation_complexity"],
                remediation_effort=d["remediation_effort"],
                can_fully_mitigate=d["can_fully_mitigate"],
            )
        )
    relation_centrality.sort(key=lambda e: (-e.path_count, e.worst_status_severity))

    # ── Pass 4: Remediation priority list ───────────────────────────────────
    # Intermediate nodes: fixing the node (e.g., removing a GenericAll ACL on it)
    # eliminates all paths passing through it.
    # Relations: fixing the relation type (e.g., patching Zerologon) eliminates
    # all paths using that edge.
    # We include both, deduplicated, sorted by:
    #   1. paths_eliminated desc
    #   2. remediation_complexity_rank asc (easier first)
    #   3. worst_status_severity asc (confirmed first)

    remediation_targets: list[RemediationTarget] = []

    # Relation-based targets (more actionable — you fix a vuln, not a specific node)
    for entry in relation_centrality:
        if entry.relation in {"memberof"}:
            continue
        complexity_rank = _COMPLEXITY_ORDER.get(entry.remediation_complexity, 1)
        elimination_rate = entry.path_count / total if total else 0.0
        remediation_targets.append(
            RemediationTarget(
                target_id=entry.relation,
                target_label=entry.relation.upper()
                if not entry.remediation_effort
                else _friendly_rel_label(entry.relation),
                target_type="relation",
                paths_eliminated=entry.path_count,
                total_paths=total,
                elimination_rate=elimination_rate,
                worst_status=entry.worst_status,
                remediation_complexity=entry.remediation_complexity,
                remediation_complexity_rank=complexity_rank,
                remediation_effort=entry.remediation_effort,
                can_fully_mitigate=entry.can_fully_mitigate,
            )
        )

    # Node-based targets (intermediate nodes with high centrality)
    for entry in node_centrality:
        if entry.is_entry_point or entry.is_tier0_target:
            continue  # entry points and targets are structural, not remediable
        if entry.path_count < 2:
            continue  # single-path nodes: not worth listing separately
        elimination_rate = entry.path_count / total if total else 0.0
        remediation_targets.append(
            RemediationTarget(
                target_id=entry.node_id,
                target_label=entry.node_id,
                target_type="node",
                paths_eliminated=entry.path_count,
                total_paths=total,
                elimination_rate=elimination_rate,
                worst_status=entry.worst_status,
                remediation_complexity="medium",  # node-level: ACL/config fix
                remediation_complexity_rank=1,
                remediation_effort=(
                    f"Remediate the vulnerabilities or ACL misconfigurations that "
                    f"allow {entry.path_count} attack path(s) to pass through this object."
                ),
                can_fully_mitigate=True,
            )
        )

    remediation_targets.sort(
        key=lambda t: (
            -t.paths_eliminated,
            t.remediation_complexity_rank,
            t.worst_status,
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


def _friendly_rel_label(rel: str) -> str:
    """Return a human-readable label for a relation key."""
    label_map = {
        "adcsesc1": "ADCS ESC1",
        "adcsesc2": "ADCS ESC2",
        "adcsesc3": "ADCS ESC3",
        "adcsesc4": "ADCS ESC4",
        "adcsesc6": "ADCS ESC6",
        "adcsesc8": "ADCS ESC8",
        "adcsesc9": "ADCS ESC9",
        "adcsesc10": "ADCS ESC10",
        "adcsesc13": "ADCS ESC13",
        "adcsesc15": "ADCS ESC15",
        "genericall": "GenericAll",
        "genericwrite": "GenericWrite",
        "writedacl": "WriteDACL",
        "writeowner": "WriteOwner",
        "forcechangepassword": "ForceChangePassword",
        "addmember": "AddMember",
        "writelogonscript": "WriteLogonScript",
        "managerodcprp": "ManageRODCPrp",
        "writesmbpath": "WriteSmbPath",
        "readlapspassword": "ReadLAPSPassword",
        "readgmsapassword": "ReadGMSAPassword",
        "dcsync": "DCSync",
        "goldencert": "GoldenCert",
        "adminto": "AdminTo",
        "kerberoasting": "Kerberoasting",
        "asreproasting": "ASREPRoasting",
        "zerologon": "Zerologon",
        "nopac": "NoPac",
        "printnightmare": "PrintNightmare",
        "dfscoerce": "DFSCoerce",
        "petitpotam": "PetitPotam",
        "printerbug": "PrinterBug",
        "mseven": "MS17-010",
        "ms17-010": "MS17-010",
        "sqlaccess": "SQLAccess",
        "sqladmin": "SQLAdmin",
        "allowedtodelegate": "ConstrainedDelegation",
        "coercetotgt": "UnconstrainedDelegation",
        "allowedtoactonbehalfofotheridentity": "RBCD",
    }
    return label_map.get(str(rel).lower(), str(rel))


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
