"""Delegation derivation: constrained and unconstrained delegation steps, and SPN-jacking.

Moved from ``collector/persistence.py`` (bodies unchanged).
"""

from __future__ import annotations

from typing import Any

from adscan_internal.services import attack_graph_service
from adscan_internal.services.collector.models import CollectionResult
from adscan_internal.services.graph_build.passes._common import (
    _node_bool_property,
    _node_list_property,
    _upsert_derived_edge,
)


def _persist_delegation_steps(
    graph: dict[str, Any],
    *,
    domain: str,
    result: CollectionResult,
    sid_to_graph_id: dict[str, str],
    source_node: Any,
    source_graph_id: str,
    edge_index: "attack_graph_service.EdgeUpsertIndex | None" = None,
) -> int:
    """Persist constrained and unconstrained delegation attack steps."""
    if edge_index is None:
        edge_index = attack_graph_service.EdgeUpsertIndex()
    created = 0
    # TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION (protocol transition / "Use any
    # authentication protocol"): a constrained delegation with this flag can
    # impersonate a victim WITHOUT that victim ever authenticating to the
    # delegating service (S4U2Self + S4U2Proxy), so it is materially more
    # dangerous than a Kerberos-only (S4U2Proxy-only) delegation. Collected
    # reliably from userAccountControl, so the finding grades severity on it.
    protocol_transition = _node_bool_property(source_node, "hastrustedtoauth")
    for spn in _node_list_property(source_node, "allowedtodelegate"):
        target_id = _resolve_delegation_target_graph_id(
            graph,
            domain=domain,
            result=result,
            sid_to_graph_id=sid_to_graph_id,
            spn=spn,
        )
        if not target_id:
            continue
        created += _upsert_derived_edge(
            graph,
            edge_index=edge_index,
            from_id=source_graph_id,
            to_id=target_id,
            relation="AllowedToDelegate",
            notes={
                "collector_method": "derived_constrained_delegation",
                "source_property": "msDS-AllowedToDelegateTo",
                "delegated_spn": spn,
                "protocol_transition": protocol_transition,
            },
        )
    if _node_bool_property(source_node, "hasunconstrainedauth") or _node_bool_property(
        source_node, "unconstraineddelegation"
    ):
        # Domain Controllers (primarygroupid=516) always have TrustedForDelegation=True
        # by design — it is required for the DC to function as a KDC.  Emitting an
        # UnconstrainedDelegation edge for a DC is a false positive and clutters
        # attack paths.  Only non-DC machines with this flag set are a finding.
        _pgid = source_node.properties.get("primarygroupid")
        _is_dc = int(_pgid) == 516 if _pgid is not None else False
        if not _is_dc:
            created += _upsert_derived_edge(
                graph,
                edge_index=edge_index,
                from_id=source_graph_id,
                to_id=source_graph_id,
                relation="UnconstrainedDelegation",
                notes={
                    "collector_method": "derived_unconstrained_delegation",
                    "source_property": "userAccountControl",
                },
            )
    return created


# servicePrincipalName-write capability: any ACE that lets the holder set an
# SPN on the target object. WriteSPN is the precise right; the three generic
# property-set writes and ownership transitively grant it too.
_SPN_WRITE_RELATIONS: frozenset[str] = frozenset(
    {"writespn", "genericall", "genericwrite", "writedacl", "owns"}
)


def _bfs_memberof_node_ids(
    memberof_adjacency: dict[str, set[str]], start_id: str
) -> set[str]:
    """Return all node ids reachable from ``start_id`` via MemberOf edges (cycle-safe).

    Operates on graph *node ids* (``name:<sam|sid>``), not raw SIDs, so it works
    against the canonical graph dict at both collector persist-time and standalone
    re-derivation over an existing ``attack_graph.json``. ``start_id`` is NOT
    included in the result.
    """
    visited: set[str] = set()
    queue: list[str] = list(memberof_adjacency.get(start_id, set()))
    while queue:
        current = queue.pop()
        if current in visited:
            continue
        visited.add(current)
        for nxt in memberof_adjacency.get(current, ()):
            if nxt not in visited:
                queue.append(nxt)
    return visited


def derive_spnjack_edges(
    graph: dict[str, Any], *, edge_index: "attack_graph_service.EdgeUpsertIndex | None" = None
) -> int:
    """Derive ``SPNJack`` escalation edges from collected delegation + ACL state.

    SPN-jacking + KCD with protocol transition. A principal P escalates to a
    target computer T when **all three** conditions hold:

    1. **KCD + protocol transition (T2A4D):** ``P.hastrustedtoauth`` is True and
       ``P.allowedtodelegate`` (msDS-AllowedToDelegateTo) is non-empty. T2A4D is
       required so P can S4U2Self an *arbitrary* user (e.g. Administrator), not
       only users who authenticate to P.
    2. **servicePrincipalName-write over a Computer T:** P holds — directly or via
       transitive group membership — an edge of relation in
       :data:`_SPN_WRITE_RELATIONS` to a Computer object T. The WriteSPN edges in
       the wild frequently originate from a *group* P belongs to, so the
       capability is resolved over P's effective token (self + MemberOf closure).
    3. **Vehicle SPN is plantable:** at least one SPN S in ``P.allowedtodelegate``
       is either currently unowned (free) or owned by a computer P can write SPNs
       on (so P can ``delspn`` S from it before ``addspn`` onto T).

    For each qualifying target T the edge ``P -> SPNJack -> T`` is emitted
    (``EdgeKind.ESCALATION``, ``direct_target_compromise``, deterministic — no
    offline crack). Targets that are the current owner of P's vehicle SPN are
    skipped: P can already delegate to them directly (modelled by the existing
    ``AllowedToDelegate`` edge), so SPNJack would duplicate it.

    Operates purely on the canonical graph dict (``nodes`` + ``edges``) and is
    idempotent (``upsert_edge`` keys on ``(from, relation, to)``), so it is safe
    to run at collector persist-time and to re-derive over an existing graph.

    Returns:
        Count of SPNJack edges created.
    """
    if edge_index is None:
        edge_index = attack_graph_service.EdgeUpsertIndex()
    from collections import defaultdict

    nodes = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes, dict) or not isinstance(edges, list):
        return 0

    # Index 1 — SPN string (lower) -> owning computer node id. First writer wins;
    # an SPN is unique in AD so there is at most one owner.
    spn_owner: dict[str, str] = {}
    for node_id, node in nodes.items():
        if not isinstance(node, dict) or str(node.get("kind") or "") != "Computer":
            continue
        props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
        for spn in props.get("serviceprincipalnames") or []:
            key = str(spn).strip().lower()
            if key:
                spn_owner.setdefault(key, str(node_id))

    # Index 2 — MemberOf adjacency (node id -> set(group node id)).
    # Index 3 — SPN-write source node id -> set(Computer target node id).
    # Snapshot existing SPNJack pairs so the created-count stays accurate on a
    # re-derive (upsert is idempotent but returns the existing edge truthily).
    memberof_adjacency: dict[str, set[str]] = defaultdict(set)
    spnwrite_targets_by_source: dict[str, set[str]] = defaultdict(set)
    existing_spnjack: set[tuple[str, str]] = set()
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        relation = str(edge.get("relation") or "").strip().lower()
        from_id = str(edge.get("from") or "").strip()
        to_id = str(edge.get("to") or "").strip()
        if not from_id or not to_id:
            continue
        if relation == "memberof":
            memberof_adjacency[from_id].add(to_id)
        elif relation == "spnjack":
            existing_spnjack.add((from_id, to_id))
        elif relation in _SPN_WRITE_RELATIONS:
            target_node = nodes.get(to_id)
            if (
                isinstance(target_node, dict)
                and str(target_node.get("kind") or "") == "Computer"
            ):
                spnwrite_targets_by_source[from_id].add(to_id)

    created = 0
    for principal_id, principal in nodes.items():
        if not isinstance(principal, dict):
            continue
        if str(principal.get("kind") or "") not in {"User", "Computer"}:
            continue
        props = (
            principal.get("properties")
            if isinstance(principal.get("properties"), dict)
            else {}
        )
        # Condition 1 — KCD + T2A4D.
        if not bool(props.get("hastrustedtoauth")):
            continue
        kcd_spns = [
            str(spn).strip()
            for spn in (props.get("allowedtodelegate") or [])
            if str(spn).strip()
        ]
        if not kcd_spns:
            continue

        # Condition 2 — effective SPN-write computer targets (self + groups).
        effective_token = {str(principal_id)} | _bfs_memberof_node_ids(
            memberof_adjacency, str(principal_id)
        )
        targets: set[str] = set()
        for sid in effective_token:
            targets |= spnwrite_targets_by_source.get(sid, set())
        if not targets:
            continue

        # Condition 3 — a plantable vehicle SPN (free, or owner P can write).
        vehicle_spn: str | None = None
        vehicle_owner: str | None = None
        kcd_owner_ids: set[str] = set()
        for spn in kcd_spns:
            owner = spn_owner.get(spn.lower())
            if owner is not None:
                kcd_owner_ids.add(owner)
            if vehicle_spn is None and (owner is None or owner in targets):
                vehicle_spn = spn
                vehicle_owner = owner
        if vehicle_spn is None:
            continue

        # Emit SPNJack to each writable computer target, skipping targets P can
        # already delegate to directly (current owners of P's KCD SPNs) — those
        # are covered by the AllowedToDelegate edge and would be duplicates.
        def _label(node_id: str | None) -> str:
            node = nodes.get(node_id) if node_id else None
            return str(node.get("label") or node_id or "") if isinstance(node, dict) else (node_id or "")

        owner_label = _label(vehicle_owner) if vehicle_owner is not None else ""
        vehicle_mode = "free_spn" if vehicle_owner is None else "delspn_from_owner"
        for target_id in sorted(targets):
            if target_id == str(principal_id) or target_id in kcd_owner_ids:
                continue
            is_new = (str(principal_id), target_id) not in existing_spnjack
            # Which principal(s) in P's token actually grant the SPN-write on this
            # target — the precondition the report/UX must surface faithfully so a
            # group-mediated right is never shown as a direct one. Self when P
            # holds it directly; otherwise the group(s) in P's membership token.
            grantors = sorted(
                _label(sid)
                for sid in effective_token
                if target_id in spnwrite_targets_by_source.get(sid, set())
            )
            spn_write_via = (
                "direct"
                if _label(str(principal_id)) in grantors and len(grantors) == 1
                else ", ".join(g for g in grantors if g)
            )
            edge = attack_graph_service.upsert_edge(
                graph,
                index=edge_index,
                from_id=str(principal_id),
                to_id=target_id,
                relation="SPNJack",
                edge_type="native_derived",
                status="discovered",
                notes={
                    "collector_method": "derived_spnjack",
                    # Precondition chain — kept structured so report/UX can expand
                    # the single SPNJack edge into the multi-step requirement it
                    # represents (no over-simplification of a multi-step technique).
                    "delegated_spn": vehicle_spn,
                    "vehicle_spn_owner": owner_label,
                    "vehicle_mode": vehicle_mode,
                    "spn_write_via": spn_write_via,
                    "protocol_transition": True,
                    "source_property": (
                        "msDS-AllowedToDelegateTo + TrustedToAuthForDelegation"
                    ),
                },
            )
            if edge and is_new:
                existing_spnjack.add((str(principal_id), target_id))
                created += 1
    return created


def _resolve_delegation_target_graph_id(
    graph: dict[str, Any],
    *,
    domain: str,
    result: CollectionResult,
    sid_to_graph_id: dict[str, str],
    spn: str,
) -> str:
    host = _host_from_spn(spn)
    if not host:
        return ""
    host_key = host.casefold().rstrip(".")
    short_key = host_key.split(".", 1)[0].rstrip("$")
    for object_id, node in result.nodes.items():
        if node.kind != "Computer":
            continue
        candidates = {
            str(node.name or "").casefold().rstrip("."),
            str(node.samaccountname or "").casefold().rstrip("$"),
        }
        dns_name = str(node.properties.get("dnshostname") or "").casefold().rstrip(".")
        if dns_name:
            candidates.add(dns_name)
            candidates.add(dns_name.split(".", 1)[0].rstrip("$"))
        if host_key in candidates or short_key in candidates:
            return sid_to_graph_id.get(object_id.upper(), "")

    hostname = host.rstrip(".")
    node_payload = {
        "kind": "Computer",
        "label": hostname.upper(),
        "name": hostname.upper(),
        "objectId": f"{domain.upper()}-DELEGATION-SPN-{hostname.upper()}",
        "properties": {
            "domain": domain.upper(),
            "dnshostname": hostname.lower(),
            "name": hostname.upper(),
            "synthetic": True,
            "source": "msDS-AllowedToDelegateTo",
        },
    }
    attack_graph_service.upsert_nodes(graph, [node_payload])
    return attack_graph_service._node_id(node_payload)  # noqa: SLF001


def _host_from_spn(spn: str) -> str:
    raw = str(spn or "").strip()
    if "/" not in raw:
        return ""
    host = raw.split("/", 1)[1].split(":", 1)[0].split("/", 1)[0].strip()
    return host.rstrip(".")


def derive_delegation_edges(
    graph: dict[str, Any],
    *,
    domain: str,
    result: CollectionResult,
    sid_to_graph_id: dict[str, str],
    edge_index: "attack_graph_service.EdgeUpsertIndex | None" = None,
) -> int:
    """Derive the delegation steps of every collected User and Computer."""
    if edge_index is None:
        edge_index = attack_graph_service.EdgeUpsertIndex()
    created = 0
    for node in result.nodes.values():
        graph_id = sid_to_graph_id.get(node.object_id.upper())
        if not graph_id or node.kind not in {"User", "Computer"}:
            continue
        created += _persist_delegation_steps(
            graph,
            domain=domain,
            result=result,
            sid_to_graph_id=sid_to_graph_id,
            source_node=node,
            source_graph_id=graph_id,
            edge_index=edge_index,
        )
    return created
