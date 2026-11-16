"""Share-file credential edges re-sourced to the measured read-set (a post-overlay rule).

The unauthenticated phase records a credential found in a share file (a GPP
``cpassword``, a script, a config) as a runtime edge BEFORE the authenticated
share collection has measured who can read that share, so its source falls to
an honest provisional fallback (Anonymous Logon, Authenticated Users, Domain
Users, ...). 14.0.x re-pointed those edges at the measured readers when the
collector persisted (``reconcile_share_credential_edge_sources``).

With the store the edges are overlay operations and the readers are the share
stage's facts, so the rule runs ONCE in ``build_graph``, right after the
overlay, over:

* the read-set of every share, from the store's read-capable share facts
  (``ReadShare`` / ``WriteShare`` / ``FullControlShare`` with their measured
  ``verification`` tier), never from ``inventory/relationships.json``, merged
  with the readers the light credential-less share probe proved (its
  ``unauthenticated`` evidence facts) under the 14.0.x rule: only a reader the
  authenticated set does not already carry is added;
* the graph itself to resolve a reader to its node (the fused well-known node
  first, then the collected object by SID). A reader that resolves to no node
  is never invented: the honest fallback stays.

It does not run on the live post-overlay path (the runtime facade); the next
build applies it. :func:`reconcile_share_credential_edges` is the rule itself,
shared with the shell-bound 14.0.x entry point in
``share_credential_provenance_service``. No ``shell``.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

#: Reader principals of one share: ``(artifact UNC, share name) -> [{"sid", "label",
#: "verification", "method"}]`` (the PRIMARY tier).
ReadSet = Callable[[str | None, str | None], list[dict[str, str]]]
#: The graph node of a reader: ``(label, notes, sid) -> node id or None``.
ResolveEntry = Callable[[str, dict[str, Any], str], "str | None"]


def reconcile_share_credential_edges(
    graph: dict[str, Any], *, read_set: ReadSet, resolve_entry: ResolveEntry
) -> int:
    """Re-point share-file credential edges still on a provisional fallback.

    Contract (Exposure-Validation discipline), unchanged from 14.0.x:
    only share-file credential relations with a share-file origin whose source
    is a provisional fallback are candidates; an edge already sourced from a
    measured reader is never rewritten; a share with no read-set keeps its
    honest fallback; a proven credential-less read keeps that fact and is
    attributed only to principals the credential-less token can present;
    idempotent. Returns how many edges were re-sourced.
    """
    edges = graph.get("edges")
    if not isinstance(edges, list) or not edges:
        return 0

    from adscan_internal.services.attack_graph_service import (  # noqa: PLC0415
        EdgeUpsertIndex,
        upsert_edge,
    )
    from adscan_internal.services.share_credential_provenance_service import (  # noqa: PLC0415
        _SHARE_FILE_EDGE_ORIGINS,
        _SHARE_FILE_EDGE_RELATIONS,
        _filtered_credential_less_readset,
        _is_provisional_fallback_source,
        _normalize_reached_via,
        _origin_is_unauthenticated_reachable,
    )

    edge_index = EdgeUpsertIndex()
    reconciled = 0

    # Snapshot the candidate edges first: upsert_edge appends/rewrites the edges
    # list, so iterate over a stable copy.
    candidates = [edge for edge in edges if isinstance(edge, dict)]
    for edge in candidates:
        relation = str(edge.get("relation") or "").strip().lower()
        if relation not in _SHARE_FILE_EDGE_RELATIONS:
            continue
        notes = edge.get("notes") if isinstance(edge.get("notes"), dict) else {}
        origin = str(notes.get("origin") or "").strip().lower()
        if origin not in _SHARE_FILE_EDGE_ORIGINS:
            continue
        from_id = str(edge.get("from") or "").strip()
        if not _is_provisional_fallback_source(from_id):
            continue  # already on a measured read-set principal — never rewrite

        artifact = str(notes.get("artifact") or "").strip()
        share = str(notes.get("share") or notes.get("shares") or "").strip()
        sources = list(read_set(artifact or None, share or None))

        # Preserve the proven-no-credential FACT across the source upgrade. The
        # source node is correctly rewritten to the measured read-set ("who can
        # read"), but an ``unauth_enrichment`` edge was read over a pre-credential
        # bind — that separate fact must not be erased, so it rides onto the
        # rewritten edge as an attribute. The bind kind is carried from the
        # build-time notes (``null_session`` or ``guest_session``) so a guest read
        # stays a guest read through reconciliation; a legacy/missing value
        # normalizes to ``null_session``. Idempotent: re-stamping is a no-op.
        preserve_unauth_reachable = _origin_is_unauthenticated_reachable(origin)
        preserved_reached_via = _normalize_reached_via(notes.get("reached_via"))
        authorized_by_acl: list[str] | None = None
        if preserve_unauth_reachable:
            # A credential-less (guest/null) proven read can only be attributed
            # to a principal the proven token can actually present — never to a
            # domain-authenticated grantee the measured ACL also happens to
            # list. Filter down to what the token can use before it becomes the
            # edge source; the surviving labels ride along as the ACL evidence.
            # See :func:`_filtered_credential_less_readset` (the shared
            # filter+attribution helper ``build_credential_source_steps`` and
            # ``build_password_artifact_source_steps`` also call), including
            # its self_mxac exemption and Authenticated-Users carve-out.
            sources, authorized_by_acl_list = _filtered_credential_less_readset(
                sources, preserved_reached_via
            )
            authorized_by_acl = authorized_by_acl_list or None

        if not sources:
            continue  # no read-set → leave the honest fallback, never fabricate

        to_id = str(edge.get("to") or "").strip()
        edge_type = str(edge.get("edge_type") or "").strip()
        status = str(edge.get("status") or "discovered").strip()
        if not to_id or not edge_type:
            continue

        # Resolve the read-set source node(s) through the SAME fusion the
        # credential-recording path uses. When several principals read the share,
        # each becomes its own source edge to the credential owner.
        resolved_any = False
        # A measured winner CAN fuse onto the SAME node id the provisional
        # fallback already points from — the honest case where the read is a
        # null-session read AND the measured NTFS ACEs name Anonymous Logon
        # itself (the fallback label and the measured source coincide). When
        # that happens ``upsert_edge`` below matches the EXISTING edge by
        # (from, to, relation) identity and mutates it IN PLACE, so the
        # measured evidence (``authorized_by_acl``/``source_sid``/
        # ``verification``) lands directly on it — there is no stale
        # duplicate to remove afterward. Skipping the upsert in this case (as
        # earlier code did) silently left the edge on its incomplete
        # provisional notes forever, never attaching the measured evidence.
        edge_updated_in_place = False
        for src in sources:
            src_notes = {k: v for k, v in notes.items()}
            if preserve_unauth_reachable:
                src_notes["unauthenticated_reachable"] = True
                src_notes["reached_via"] = preserved_reached_via
                if authorized_by_acl:
                    src_notes["authorized_by_acl"] = authorized_by_acl
            src_notes["source_sid"] = src.get("sid", "")
            if src.get("verification"):
                src_notes["verification"] = src["verification"]
            if src.get("method"):
                src_notes["method"] = src["method"]
            entry_label = str(src.get("label") or src.get("sid") or "").strip()
            entry_id = resolve_entry(entry_label, src_notes, str(src.get("sid") or ""))
            if not entry_id:
                continue
            new_edge = upsert_edge(
                graph,
                index=edge_index,
                from_id=entry_id,
                to_id=to_id,
                relation=edge.get("relation") or relation,
                edge_type=edge_type,
                status=status,
                notes=src_notes,
            )
            if not new_edge:
                continue
            resolved_any = True
            if entry_id == from_id:
                edge_updated_in_place = True

        if not resolved_any:
            continue

        if not edge_updated_in_place:
            # Remove the stale provisional-fallback edge now that the measured
            # source edge(s) are in place under a different node id. Identity
            # by the original dict object.
            graph["edges"] = [e for e in graph.get("edges", []) if e is not edge]
        reconciled += 1

    return reconciled


def _share_read_records(store: Any) -> list[dict[str, Any]]:
    """The store's AUTHENTICATED read-capable share facts as relationship records
    (the share stage's; the light probe's evidence is read apart)."""
    from adscan_internal.services.graph_build.ingest import is_evidence_only_fact  # noqa: PLC0415
    from adscan_internal.services.share_credential_provenance_service import (  # noqa: PLC0415
        _READ_CAPABLE_RELATIONS,
    )

    relations = sorted(
        {name for name in ("ReadShare", "WriteShare", "FullControlShare") if name.lower() in _READ_CAPABLE_RELATIONS}
    )
    labels: dict[str, str] = {}
    records: list[dict[str, Any]] = []
    for fact in store.iter_facts(relations=relations):
        if is_evidence_only_fact(fact):
            continue
        sid = str(fact.subject_id or "")
        if sid not in labels:
            record = store.get_object(sid)
            labels[sid] = str(record.name) if record is not None else ""
        records.append(
            {
                "relation": fact.relation,
                "source_object_id": sid,
                "source_name": labels[sid],
                "method": fact.method,
                "notes": dict(fact.notes or {}),
            }
        )
    return records


def _probe_read_sets(store: Any) -> dict[str, list[dict[str, str]]]:
    """Share name (lower) -> the light probe's proven readers, in the tier shape.

    The credential-less probe's read-set, committed as ``unauthenticated``
    evidence facts (``collector.store_writer.commit_share_probe_read_sets``).
    Only entries whose effective mask grants READ count, through the same
    translation 14.0.x applied to ``smb/shares.json``.
    """
    from adscan_core.graph_store.records import STAGE_UNAUTH  # noqa: PLC0415
    from adscan_internal.services.graph_build.ingest import is_evidence_only_fact  # noqa: PLC0415
    from adscan_internal.services.share_credential_provenance_service import (  # noqa: PLC0415
        ShareCredentialProvenanceService,
    )

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for fact in store.iter_facts(stages=[STAGE_UNAUTH], relations=["ReadShare"]):
        if not is_evidence_only_fact(fact):
            continue
        notes = fact.notes or {}
        share = str(notes.get("share_name") or "").strip().lower()
        if not share:
            continue
        verification = str(notes.get("verification") or "").strip().lower()
        grouped.setdefault((share, verification), []).append(
            {"sid": fact.subject_id, "label": notes.get("label") or "", "mask": notes.get("mask") or 0}
        )
    out: dict[str, list[dict[str, str]]] = {}
    seen: dict[str, set[str]] = {}
    for (share, verification), read_set in sorted(grouped.items()):
        entries = ShareCredentialProvenanceService._filter_smb_shares_read_set_entries(  # noqa: SLF001
            read_set, verification=verification
        )
        bucket = out.setdefault(share, [])
        known = seen.setdefault(share, set())
        for entry in entries:
            if entry["sid"] not in known:
                known.add(entry["sid"])
                bucket.append(entry)
    return out


def _has_candidates(graph: dict[str, Any]) -> bool:
    from adscan_internal.services.share_credential_provenance_service import (  # noqa: PLC0415
        _SHARE_FILE_EDGE_ORIGINS,
        _SHARE_FILE_EDGE_RELATIONS,
        _is_provisional_fallback_source,
    )

    for edge in graph.get("edges") or ():
        if not isinstance(edge, dict):
            continue
        if str(edge.get("relation") or "").strip().lower() not in _SHARE_FILE_EDGE_RELATIONS:
            continue
        notes = edge.get("notes") if isinstance(edge.get("notes"), dict) else {}
        if str(notes.get("origin") or "").strip().lower() not in _SHARE_FILE_EDGE_ORIGINS:
            continue
        if _is_provisional_fallback_source(str(edge.get("from") or "")):
            return True
    return False


def reconcile_share_credential_sources(graph: dict[str, Any], store: Any) -> int:
    """The build's step: re-source share-file credential edges from the store's readers.

    Called once by ``build_graph`` after the overlay. Reads the store only when
    the graph holds a candidate edge. Returns how many edges were re-sourced.
    """
    if not _has_candidates(graph):
        return 0
    from adscan_internal.services.attack_graph_service import (  # noqa: PLC0415
        _extract_node_object_id,
        _resolve_wellknown_source_entry,
    )
    from adscan_internal.services.share_credential_provenance_service import (  # noqa: PLC0415
        ShareCredentialProvenanceService,
        read_set_tiers_from_records,
    )

    records = _share_read_records(store)
    probe = _probe_read_sets(store)
    if not records and not probe:
        return 0
    node_by_sid: dict[str, str] = {}
    for node_id, node in (graph.get("nodes") or {}).items():
        if isinstance(node, dict):
            sid = str(_extract_node_object_id(node) or "").strip().upper()
            if sid:
                node_by_sid.setdefault(sid, str(node_id))
    share_from_artifact = ShareCredentialProvenanceService._share_from_artifact  # noqa: SLF001

    def _read_set(artifact: str | None, share: str | None) -> list[dict[str, str]]:
        name = str(share or "").strip() or share_from_artifact(artifact)
        if not name:
            return []
        # The probe's readers merge under 14.0.x's rule: a SID the
        # authenticated set already carries keeps its authenticated tier.
        primary, _others = read_set_tiers_from_records(records, probe.get(name.lower(), ()), name)
        return primary

    def _resolve_entry(label: str, notes: dict[str, Any], sid: str) -> str | None:
        entry_id = _resolve_wellknown_source_entry(graph, label, notes)
        if entry_id is None:
            entry_id = node_by_sid.get(str(sid or "").strip().upper())
        return entry_id or None

    return reconcile_share_credential_edges(graph, read_set=_read_set, resolve_entry=_resolve_entry)


__all__ = (
    "ReadSet",
    "ResolveEntry",
    "reconcile_share_credential_edges",
    "reconcile_share_credential_sources",
)
