"""Privileged-group escalation edges, derived from collected directory state.

Membership in a handful of built-in groups (Backup Operators, DnsAdmins, Print
Operators) is, on its own, a path to full domain compromise: the group holds a
privilege that can be turned into domain secrets without any further ACL grant.
ADscan models that as one **real derived edge** from the GROUP to the domain
object, exactly like the ``DCSync`` edge derived from the
(GetChanges + GetChangesAll) ACE pair and the ``UnconstrainedDelegation`` edge
derived from the userAccountControl flag.

Why a real edge and not a render-time synthetic
-----------------------------------------------
The escalation used to be born inside the display record, in
``attack_graph_core.path_to_display_record``. That made the GRAPH say the group
was a dead end, so every graph-reading consumer was blind to it: the DFS would
not route through it, the terminal-``MemberOf`` trim ate the chain that ended at
the group, the choke-point cardinality and the reverse-reachability floods did
not see it, the web CTEM live recompute did not see it, and the executor had no
edge to key on. A direct Backup Operators member therefore rendered zero attack
paths while being one step from the domain. This module is the single source of
truth that replaces it.

Why it is a structural derivation and not a post-exploitation technique
-----------------------------------------------------------------------
The distinguishing test is whether the fact is determinable from collected
directory state without touching a host. Group identity is: the group's SID (or
its name, for a localized directory) is already in the graph. So the edge is a
collection-time derivation, consistent with the "post-exploitation techniques
are not graph edges" doctrine, which governs outcomes that only exist once a
host has been compromised.

The edge is emitted FROM THE GROUP, never once per member: the group holds the
privilege, and members reach it through their existing ``MemberOf`` edge. One
edge per group per domain keeps the derivation deterministic (about three edges
in a typical domain) and means a member's ``MemberOf`` hop is no longer terminal.

Status fidelity is delegated, not restated. ``attack_graph_service.upsert_edge``
reads the execution-support registry in ``attack_step_catalog`` and lands the
honest status by itself: ``BackupOperatorEscalation`` is supported, so it stays
``discovered`` and the path derives as theoretical; ``DnsAdminAbuse`` is
``policy_blocked``, so it becomes ``blocked`` (a safety abstention);
``PrintOperatorAbuse`` is ``unsupported``, so it becomes ``unsupported`` (a data
gap). Per the Exposure-Validation doctrine neither of the latter two may ever be
rendered as an executable theoretical path.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adscan_internal.services.privileged_group_classifier import (
    classify_privileged_membership,
    normalize_group_name,
)

# The normalized name of the Print Operators group. Backup Operators and
# DnsAdmins are recognised through the SID/RID-based classifier
# (``classify_privileged_membership``); Print Operators has no classifier flag,
# so it is matched on the normalized name, mirroring the check the render-time
# synthetic used.
_PRINT_OPERATORS_NORMALIZED_NAME = "print operators"


@dataclass(frozen=True)
class PrivilegedGroupEscalation:
    """One privileged group's escalation relation, status input and reason.

    ``requested_status`` is the status handed to ``upsert_edge``, not always the
    status the edge ends up with. ``upsert_edge`` only consults the
    execution-support registry when the requested status is ``discovered``, so a
    relation whose honest status must come from that registry (``DnsAdminAbuse``
    is ``policy_blocked`` -> ``blocked``; ``PrintOperatorAbuse`` is
    ``unsupported``) asks for ``discovered`` and lets the registry decide, while
    a supported relation (``BackupOperatorEscalation``) states its
    ``theoretical`` status directly. Passing ``theoretical`` for all three would
    bypass the registry and render a safety abstention and a data gap as
    executable theoretical paths, which the Exposure-Validation doctrine forbids.
    """

    relation: str
    requested_status: str
    reason: str


BACKUP_OPERATORS_ESCALATION = PrivilegedGroupEscalation(
    relation="BackupOperatorEscalation",
    requested_status="theoretical",
    reason="Backup Operators can enable a follow-up path to domain compromise",
)
DNS_ADMINS_ESCALATION = PrivilegedGroupEscalation(
    relation="DnsAdminAbuse",
    requested_status="discovered",
    reason="Production-impacting DNS modification is blocked by design",
)
PRINT_OPERATORS_ESCALATION = PrivilegedGroupEscalation(
    relation="PrintOperatorAbuse",
    requested_status="discovered",
    reason=(
        "Print Operators exposure is modeled, but ADscan has no automated follow-up yet"
    ),
)

#: Every relation this module emits. Consumers that need to recognise a
#: privileged-group escalation edge read this set rather than re-listing names.
PRIVILEGED_GROUP_ESCALATION_RELATIONS: frozenset[str] = frozenset(
    {
        BACKUP_OPERATORS_ESCALATION.relation,
        DNS_ADMINS_ESCALATION.relation,
        PRINT_OPERATORS_ESCALATION.relation,
    }
)

#: The notes marker every emitted edge carries, so a consumer can tell a derived
#: privileged-group escalation apart from a collected ACL edge.
ESCALATION_EDGE_SOURCE = "derived_privileged_group_escalation"


def _node_kind(node: Any) -> str:
    """Return a node's kind as a plain string (``kind`` may be a list)."""
    if not isinstance(node, dict):
        return ""
    kind = node.get("kind") or node.get("labels") or node.get("type")
    if isinstance(kind, list):
        kind = kind[0] if kind else ""
    return str(kind or "")


def _node_properties(node: Any) -> dict[str, Any]:
    if not isinstance(node, dict):
        return {}
    props = node.get("properties")
    return props if isinstance(props, dict) else {}


def _node_sid(node: Any) -> str:
    """Return the node's normalized (upper-case) object SID, or ``""``."""
    props = _node_properties(node)
    candidates = (
        props.get("objectid"),
        props.get("objectId"),
        node.get("objectid") if isinstance(node, dict) else None,
        node.get("objectId") if isinstance(node, dict) else None,
    )
    for value in candidates:
        if isinstance(value, str) and value.strip():
            sid = value.strip().upper()
            index = sid.find("S-1-")
            return sid[index:] if index != -1 else sid
    return ""


def _node_domain_sid(node: Any) -> str:
    """Return the SID of the domain a node belongs to, or ``""``.

    A domain object's own SID IS its domain SID. For any account/group carrying
    a trailing RID the RID component is stripped. Built-in groups
    (``S-1-5-32-*``) have no domain SID, so they resolve to ``""`` and fall
    through to the label-based match in :func:`resolve_escalation_domain_node_id`.
    """
    sid = _node_sid(node)
    if not sid.startswith("S-1-5-21-"):
        return ""
    if _node_kind(node).strip().lower() == "domain":
        return sid
    head, _, tail = sid.rpartition("-")
    if not head or not tail.isdigit():
        return ""
    return head


def resolve_privileged_group_escalation(
    node: Any,
) -> PrivilegedGroupEscalation | None:
    """Return the escalation a Group node carries, or ``None``.

    Recognition order mirrors the render-time synthetic this replaces
    (DnsAdmins, then Backup Operators, then Print Operators) so a group that
    somehow matched more than one family keeps the same verdict.

    Args:
        node: An attack-graph node dict.

    Returns:
        The matching :class:`PrivilegedGroupEscalation`, or ``None`` when the
        node is not a privileged group this module models.
    """
    if _node_kind(node) != "Group":
        return None
    props = _node_properties(node)
    group_name = str(props.get("name") or node.get("label") or "").strip()
    sid = _node_sid(node)
    membership = classify_privileged_membership(
        group_sids=[sid] if sid else [],
        group_names=[group_name] if group_name else [],
    )
    if membership.dns_admins:
        return DNS_ADMINS_ESCALATION
    if membership.backup_operators:
        return BACKUP_OPERATORS_ESCALATION
    if normalize_group_name(group_name) == _PRINT_OPERATORS_NORMALIZED_NAME:
        return PRINT_OPERATORS_ESCALATION
    return None


def resolve_escalation_domain_node_id(graph: dict[str, Any], group_node: Any) -> str:
    """Return the node id of the domain object a privileged group escalates into.

    Multi-domain / forest-merged safe, and deliberately conservative: with a
    single domain node that node wins; with several, the group's own domain SID
    decides, then its ``properties.domain`` label. When neither disambiguates,
    ``""`` is returned and the caller skips emission rather than pointing a
    domain-compromise edge at the wrong forest.

    Args:
        graph: The attack-graph dict.
        group_node: The privileged group node the edge is sourced from.

    Returns:
        The domain node id, or ``""`` when it cannot be resolved with certainty.
    """
    nodes = graph.get("nodes")
    if not isinstance(nodes, dict):
        return ""
    domain_nodes = sorted(
        (
            (str(node_id), node)
            for node_id, node in nodes.items()
            if _node_kind(node).strip().lower() == "domain"
        ),
        key=lambda item: item[0],
    )
    if not domain_nodes:
        return ""
    if len(domain_nodes) == 1:
        return domain_nodes[0][0]

    group_domain_sid = _node_domain_sid(group_node)
    if group_domain_sid:
        for node_id, node in domain_nodes:
            if _node_domain_sid(node) == group_domain_sid:
                return node_id

    group_domain = str(_node_properties(group_node).get("domain") or "").strip().lower()
    if group_domain:
        for node_id, node in domain_nodes:
            label = str(node.get("label") or node.get("name") or "").strip().lower()
            if label == group_domain or label.endswith("@" + group_domain):
                return node_id
    return ""


def derive_privileged_group_escalation_edges(graph: dict[str, Any]) -> int:
    """Derive one ``Group -> Domain`` escalation edge per privileged group node.

    The single emitter, called from both the collector persist path
    (``collector/persistence``) and the load-time backfill
    (``attack_graph_core.load_attack_graph``) so a freshly-collected and a
    reopened workspace carry an identical edge set. Pure graph-dict input, so it
    re-derives over an existing ``attack_graph.json`` with no collector re-run.

    Additive and idempotent: ``upsert_edge`` keys on
    ``(from, relation, to)``, so re-running this never duplicates an edge and
    never removes one.

    Args:
        graph: The attack-graph dict, mutated in place.

    Returns:
        The number of edges created (0 when every edge already existed).
    """
    nodes = graph.get("nodes")
    if not isinstance(nodes, dict):
        return 0

    # Deferred import: ``attack_graph_service`` imports ``attack_graph_core``,
    # which imports this module from its load-time backfill, so a top-level
    # import would close a cycle.
    from adscan_internal.services import attack_graph_service  # noqa: PLC0415

    created = 0
    for node_id, node in sorted(nodes.items(), key=lambda item: str(item[0])):
        escalation = resolve_privileged_group_escalation(node)
        if escalation is None:
            continue
        domain_node_id = resolve_escalation_domain_node_id(graph, node)
        if not domain_node_id or domain_node_id == str(node_id):
            continue
        # Count by edge-list delta rather than by the upsert's return value:
        # ``upsert_edge`` returns the edge for an UPDATE as well as an insert, so
        # only the delta tells a re-run (0) from a first run.
        before = len(graph.get("edges") or [])
        attack_graph_service.upsert_edge(
            graph,
            from_id=str(node_id),
            to_id=domain_node_id,
            relation=escalation.relation,
            edge_type="native_derived",
            # See ``PrivilegedGroupEscalation.requested_status``: ``discovered``
            # delegates the verdict to the execution-support registry, which
            # lands ``blocked`` for DnsAdmins and ``unsupported`` for Print
            # Operators.
            status=escalation.requested_status,
            notes={
                "collector_method": ESCALATION_EDGE_SOURCE,
                "source": ESCALATION_EDGE_SOURCE,
                "followup_source_group": str(
                    node.get("label") or node.get("name") or ""
                ),
                "reason": escalation.reason,
            },
            log_creation=False,
        )
        if len(graph.get("edges") or []) > before:
            created += 1
    return created
