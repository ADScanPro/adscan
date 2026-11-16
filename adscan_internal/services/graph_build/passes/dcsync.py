"""DCSync derivation: one ``DCSync`` edge per principal whose intrinsic token holds both replication rights.

Moved from ``collector/persistence.py`` (body unchanged).
"""

from __future__ import annotations

from typing import Any, Callable

from adscan_internal.services import attack_graph_service
from adscan_internal.services.collector.models import CollectionResult
from adscan_internal.services.graph_build.passes._common import _upsert_derived_edge


def _spec_leaf_rights(spec: Any) -> set[str]:
    """Every right name a compound right spec reads (its leaves)."""
    if isinstance(spec, str):
        return {spec}
    children = getattr(spec, "rights", None) or getattr(spec, "alternatives", None) or ()
    leaves: set[str] = set()
    for child in children:
        leaves |= _spec_leaf_rights(child)
    return leaves


def _persist_dcsync_steps(
    graph: dict[str, Any],
    *,
    result: CollectionResult,
    sid_to_graph_id: dict[str, str],
    surface_tally: Any | None = None,
    is_tier0: Callable[[str], bool] | None = None,
    edge_index: "attack_graph_service.EdgeUpsertIndex | None" = None,
) -> int:
    """Derive DCSync edges using intrinsic-token rights evaluation.

    For every User / Computer / Group / ManagedServiceAccount in the
    collection, evaluate the principal's *intrinsic* token — self plus
    kind-implicit well-known SIDs (e.g. S-1-5-9 for DC groups) but
    without transitive MemberOf expansion. A ``DCSync`` edge is emitted
    when the rights union of the intrinsic token satisfies the canonical
    DCSync spec.

    Why intrinsic-only (no MemberOf BFS):
      Deriving DCSync on a principal that has no direct ACE rights, only
      transitively reachable via MemberOf, violates the "one edge = one
      permission" invariant and produces denormalized paths.  The MemberOf
      edges are already in the graph; the path-finding engine traverses
      them naturally, producing the canonical kill chain:

          Domain Admins → MemberOf → Administrators → DCSync → Domain

      rather than the misleading short-cut:

          Domain Admins → DCSync → Domain  ← no literal ACE

    Split-rights (GOAD-essos) exception:
      S-1-5-9 (Enterprise DCs) carries GetChanges; -516 (Domain
      Controllers) carries GetChangesAll. Neither comes from MemberOf —
      the S-1-5-9 SID is *implicit* (added by the KDC to all DC machine
      accounts and to groups whose RID is 516/498). Domain Controllers
      IS the union point, so deriving DCSync on -516 is correct.

    ``GenericAll`` on the Domain is intentionally NOT mapped here — the
    semantic mapping to DCSync belongs to the attack-path step layer.
    """
    if edge_index is None:
        edge_index = attack_graph_service.EdgeUpsertIndex()
    from collections import defaultdict

    from adscan_internal.services.effective_principal_rights import (
        DCSYNC,
        compute_intrinsic_token_sids,
        evaluate_compound_right,
    )

    domain_target_sids: set[str] = {
        oid.upper() for oid, n in result.nodes.items() if n.kind == "Domain"
    }
    if not domain_target_sids:
        # The replication right has nothing to be held over, so the surface is
        # NOT APPLICABLE here. Recorded as such rather than left empty, because
        # an absent precondition must never read as a healthy one.
        if surface_tally is not None:
            surface_tally.note_precondition_absent(
                "No domain object was collected, so directory replication "
                "rights could not be evaluated."
            )
        return 0

    # Census of the replication-rights surface: the catalogued replication
    # rights, lowercased, read off the SAME definition the client-facing
    # sentence is built from. Broader than the DCSync compound on purpose, since
    # holding GetChanges alone is itself a catalogued technique on this surface.
    replication_rights: set[str] = set()
    if surface_tally is not None:
        from adscan_core.reporting.enumerated_surface_evidence import (  # noqa: PLC0415
            ENUMERATED_SURFACE_DEFINITIONS,
        )

        replication_rights = set(
            ENUMERATED_SURFACE_DEFINITIONS["credential_access"].covered_techniques
        )

    # Build (target, source) → frozenset(rights) index from collected ACEs.
    # Only what is looked up below: rights over a domain object, and only the
    # relations the DCSync spec and the census read. Every other key of the
    # wave-1 index (one per fact) was never read.
    from adscan_internal.services.graph_build.edge_view import edges_of  # noqa: PLC0415

    indexed_relations = _spec_leaf_rights(DCSYNC) | replication_rights
    raw_index: dict[tuple[str, str], set[str]] = defaultdict(set)
    for edge in edges_of(result.edges, indexed_relations):
        relation = str(edge.relation or "")
        if not relation:
            continue
        target_sid = edge.target_object_id.upper()
        if target_sid not in domain_target_sids:
            continue
        raw_index[(target_sid, edge.source_object_id.upper())].add(relation)
    rights_index: dict[tuple[str, str], frozenset[str]] = {
        key: frozenset(value) for key, value in raw_index.items()
    }

    eligible_kinds: set[str] = {
        "User",
        "Computer",
        "Group",
        "ManagedServiceAccount",
    }
    token_cache: dict[str, frozenset[str]] = {}

    created = 0
    for principal_oid, principal_node in result.nodes.items():
        if str(principal_node.kind) not in eligible_kinds:
            continue
        principal_upper = principal_oid.upper()

        if principal_upper not in token_cache:
            token_cache[principal_upper] = compute_intrinsic_token_sids(
                principal_oid,
                nodes=result.nodes,
            )

        if surface_tally is not None:
            # Counted on the SAME intrinsic token the derivation evaluates, so
            # the census covers the rights a principal carries through its own
            # well-known group membership exactly as the client sentence says.
            held: set[str] = set()
            for token_sid in token_cache[principal_upper]:
                for target_sid in domain_target_sids:
                    held |= {
                        str(right).strip().lower()
                        for right in rights_index.get(
                            (target_sid, str(token_sid).upper()), frozenset()
                        )
                    }
            holds_replication = bool(held & replication_rights)
            outside_tier0 = is_tier0 is None or not is_tier0(principal_upper)
            surface_tally.record(qualifying=holds_replication and outside_tier0)

        for target_sid in domain_target_sids:
            if not evaluate_compound_right(
                principal_oid,
                target_sid,
                DCSYNC,
                rights_index=rights_index,
                effective_token=token_cache,
            ):
                continue
            from_id = sid_to_graph_id.get(principal_upper)
            to_id = sid_to_graph_id.get(target_sid)
            if not from_id or not to_id:
                continue
            created += _upsert_derived_edge(
                graph,
                edge_index=edge_index,
                from_id=from_id,
                to_id=to_id,
                relation="DCSync",
                notes={"collector_method": "derived_dcsync_intrinsic_token"},
            )

    return created
