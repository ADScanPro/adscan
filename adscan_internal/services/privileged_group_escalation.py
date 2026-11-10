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

#: Edge-target kinds a privileged-group escalation may point at.
TARGET_DOMAIN = "domain"
TARGET_DOMAIN_CONTROLLER = "domain_controller"


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

    ``target`` names the OBJECT CLASS the edge lands on — :data:`TARGET_DOMAIN`
    for a group whose privilege acts on the directory itself, or
    :data:`TARGET_DOMAIN_CONTROLLER` for one whose privilege is exercised ON a
    controller and yields credential material rather than the domain. The edge
    must assert only what it proves, so the class is declared per group here and
    resolved by :func:`resolve_escalation_target_node_id`.
    """

    relation: str
    requested_status: str
    reason: str
    target: str = TARGET_DOMAIN


BACKUP_OPERATORS_ESCALATION = PrivilegedGroupEscalation(
    relation="BackupOperatorEscalation",
    requested_status="theoretical",
    reason="Backup Operators can enable a follow-up path to domain compromise",
    # The source SID is ``S-1-5-32-551`` — BUILTIN, which is LOCAL TO A MACHINE by
    # definition, so the privilege is exercised ON A DOMAIN CONTROLLER and what it
    # yields is CREDENTIAL MATERIAL read from that controller's registry and
    # directory database. Reaching the DOMAIN takes a further technique, so an
    # edge straight onto the domain object compressed two techniques into one hop
    # and skipped the very host the privilege applies to; the chain that should
    # have been its tail then read as an unrelated path from a privileged start.
    target=TARGET_DOMAIN_CONTROLLER,
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


def _node_host_aliases(node: Any) -> list[str]:
    """Return every identifier that denotes a Computer node's host.

    Ordered most-specific first (FQDN, then the label's host part, then the short
    name, then the recorded address) so an alias-aware comparison sees the FQDN
    before anything a short name could collide with. The trailing ``$`` of a
    machine account is kept: the DC-set matcher is ``HOST$``-aware.
    """
    props = _node_properties(node)
    raw = (
        props.get("dnshostname"),
        props.get("samaccountname"),
        props.get("name"),
        node.get("label") if isinstance(node, dict) else None,
        props.get("ip_address"),
    )
    aliases: list[str] = []
    seen: set[str] = set()
    for value in raw:
        token = str(value or "").strip()
        if not token:
            continue
        # A graph label is ``HOST$@DOMAIN``; the host part is what denotes the
        # machine, the realm qualifier is not an alias of it.
        if "@" in token:
            token = token.split("@", 1)[0].strip()
        key = token.lower()
        if not token or key in seen:
            continue
        seen.add(key)
        aliases.append(token)
    return aliases


def _writable_dc_node_ids_for_domain(
    graph: dict[str, Any], domain_node_id: str
) -> list[str]:
    """Return the WRITABLE domain-controller Computer nodes of one domain.

    Writable only: an RODC holds partial secrets and no full replication, so it
    is not the controller this escalation is exercised against. Membership of the
    domain is decided by the node's own domain SID, falling back to its
    ``properties.domain`` label — never by "it is the only DC in the file", which
    would cross a forest boundary in a merged multi-domain graph.

    Returned in sorted node-id order so the candidate set is deterministic.
    """
    nodes = graph.get("nodes")
    if not isinstance(nodes, dict):
        return []
    domain_node = nodes.get(domain_node_id)
    domain_sid = _node_domain_sid(domain_node)
    domain_label = (
        str(domain_node.get("label") or domain_node.get("name") or "").strip().lower()
        if isinstance(domain_node, dict)
        else ""
    )

    # Local import: the role classifier is pure graph-node logic but lives in its
    # own module, and a top-level import here is not needed by the rest of this one.
    from adscan_internal.services.computer_node_role import (  # noqa: PLC0415
        classify_computer_node_role,
    )

    candidates: list[str] = []
    for node_id, node in sorted(nodes.items(), key=lambda item: str(item[0])):
        if not isinstance(node, dict) or _node_kind(node) != "Computer":
            continue
        try:
            if classify_computer_node_role(node) != "writable_dc":
                continue
        except Exception:  # noqa: BLE001 — a malformed node is simply not a DC
            continue
        node_domain_sid = _node_domain_sid(node)
        if domain_sid and node_domain_sid:
            if node_domain_sid != domain_sid:
                continue
        elif domain_label:
            node_domain = str(_node_properties(node).get("domain") or "").strip().lower()
            if node_domain and node_domain != domain_label:
                continue
        candidates.append(str(node_id))
    return candidates


def resolve_escalation_target_node_id(
    graph: dict[str, Any],
    group_node: Any,
    *,
    escalation: PrivilegedGroupEscalation,
    domain_data: Any = None,
) -> tuple[str, str]:
    """Return the node id this escalation's edge lands on, plus the basis.

    For a :data:`TARGET_DOMAIN` escalation this is the domain object, unchanged.
    For :data:`TARGET_DOMAIN_CONTROLLER` it is a writable DC of the group's own
    domain, PINNED to the domain's RECORDED PRIMARY controller so the edge has a
    concrete, DETERMINISTIC target at the moment the graph is built — which is
    before anything has executed, so there is no "controller we read" to point
    at yet. The pin is resolved through the DC-set SSOT
    (``resolve_domain_controllers``, the record form of ``resolve_dc_ip``'s
    ``pdc -> dc_ip -> dcs[0]`` ladder) and matched alias-aware against each
    candidate's own identifiers, so the node is identified by its stable object
    identity and not by whichever address answered. **The graph never probes**:
    reachability is transient, two runs minutes apart must not build different
    graphs, and a probe verdict baked into a persisted artifact would be caching
    an absence. The executor does the probing, obeys this pin, and writes back
    the controller it actually exercised.

    Degrades rather than guesses. With no recorded primary and more than one
    writable DC the target falls back to the domain object (the pre-pin
    behaviour): every candidate would be equally true, and inventing a primary
    would assert a selection the directory never made. Reaching the
    ``Domain Controllers`` group instead is NOT an option — Backup Operators
    membership does not confer it, and drawing that edge would assert a
    membership that does not exist.

    Args:
        graph: The attack-graph dict.
        group_node: The privileged group node the edge is sourced from.
        escalation: The escalation whose ``target`` class decides the shape.
        domain_data: The ``domains_data[<domain>]`` entry, when the caller has
            one. Absent (the load-time backfill), the single-writable-DC case
            still resolves exactly; a multi-DC domain degrades to the domain.

    Returns:
        ``(node_id, basis)``. ``node_id`` is ``""`` when nothing resolves with
        certainty and the caller must skip emission. ``basis`` names how the
        target was chosen, for the edge's notes.
    """
    domain_node_id = resolve_escalation_domain_node_id(graph, group_node)
    if escalation.target != TARGET_DOMAIN_CONTROLLER:
        return domain_node_id, TARGET_DOMAIN
    if not domain_node_id:
        return "", ""

    candidates = _writable_dc_node_ids_for_domain(graph, domain_node_id)
    if not candidates:
        # The collection never saw a writable DC computer object. The domain
        # object keeps the finding visible; losing the path would lose coverage.
        return domain_node_id, "domain_fallback_no_dc_node"

    if domain_data:
        try:
            from adscan_internal.models.domain import (  # noqa: PLC0415
                resolve_domain_controllers,
            )

            dc_set = resolve_domain_controllers(domain_data)
        except Exception:  # noqa: BLE001 — never fail a derivation over an enrichment
            dc_set = None
        if dc_set is not None and dc_set.dcs:
            nodes = graph.get("nodes") or {}
            for node_id in candidates:
                for alias in _node_host_aliases(nodes.get(node_id)):
                    if dc_set.host_is_primary_dc(alias) is True:
                        return node_id, "recorded_primary_dc"

    if len(candidates) == 1:
        return candidates[0], "sole_writable_dc"
    return domain_node_id, "domain_fallback_ambiguous_dc"


def _group_escalation_edge_exists(
    graph: dict[str, Any], *, group_node_id: str, relation: str
) -> bool:
    """Return whether this group already carries an escalation edge, ANY target.

    The derivation's invariant is ONE edge per group per domain, so the guard is
    ``(group, relation)`` and not the ``(from, relation, to)`` triple ``upsert_edge``
    keys on. Two consequences, both wanted:

    * A graph whose escalation edge was authored by an EARLIER version of this
      module (pointing at the domain object) is left exactly as collected. The
      target is a COLLECTION-time fact and the status recorded on it was reached
      against that target; re-pointing it afterwards would rewrite the record of
      what the run actually did, and on a workspace whose chain was proven it
      would downgrade a proven finding at render time. Those workspaces take the
      new shape on their next collection, which is the re-scan this change needs
      anyway.
    * The collector (which holds ``domains_data``) and the load-time backfill
      (which does not) can never both author an edge for the same group, so they
      cannot disagree about its target on a multi-DC domain.
    """
    relation_key = str(relation or "").strip().lower()
    for edge in graph.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        if str(edge.get("from") or "").strip() != group_node_id:
            continue
        if str(edge.get("relation") or "").strip().lower() != relation_key:
            continue
        notes = edge.get("notes")
        source = str(notes.get("source") or "") if isinstance(notes, dict) else ""
        if source == ESCALATION_EDGE_SOURCE or not source:
            return True
    return False


def derive_privileged_group_escalation_edges(
    graph: dict[str, Any], *, domain_data: Any = None
) -> int:
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
        domain_data: The ``domains_data[<domain>]`` entry when the caller has one
            (the collector does; the load-time backfill does not). Used ONLY to
            resolve the recorded primary controller for a DC-targeted escalation
            — see :func:`resolve_escalation_target_node_id`, which degrades
            without it rather than guessing.

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
        if _group_escalation_edge_exists(
            graph, group_node_id=str(node_id), relation=escalation.relation
        ):
            continue
        target_node_id, target_basis = resolve_escalation_target_node_id(
            graph, node, escalation=escalation, domain_data=domain_data
        )
        if not target_node_id or target_node_id == str(node_id):
            continue
        # Count by edge-list delta rather than by the upsert's return value:
        # ``upsert_edge`` returns the edge for an UPDATE as well as an insert, so
        # only the delta tells a re-run (0) from a first run.
        before = len(graph.get("edges") or [])
        attack_graph_service.upsert_edge(
            graph,
            from_id=str(node_id),
            to_id=target_node_id,
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
                # How the target was chosen, so a later reader can tell a pinned
                # primary controller from a degrade without re-deriving it.
                "escalation_target_class": escalation.target,
                "escalation_target_basis": target_basis,
            },
            log_creation=False,
        )
        if len(graph.get("edges") or []) > before:
            created += 1
    return created
