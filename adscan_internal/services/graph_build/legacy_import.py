"""Import a graph written by 14.0.x into a domain's store, once.

A workspace written by 14.0.x has an ``attack_graph.json`` and no store. Reading
it needs nothing (the file is loaded as it is). The FIRST write creates the
store, and this module puts that file into it so nothing it held is lost
(spec section 8):

* every node becomes an object and every edge a fact of stage
  :data:`~adscan_core.graph_store.records.STAGE_LEGACY_IMPORT`, through B's
  ``ingest.legacy_object_record`` / ``legacy_fact_record``. The build takes them
  as the base, as they are, until a real collection stage commits;
* every edge ADscan wrote at runtime (``edge_type`` ``runtime``) and every edge
  whose status is not ``discovered`` ALSO becomes an overlay operation, so what
  was executed is in the overlay from that moment and survives the
  re-collection that drops the legacy base.

The import is one stage run: ``begin_stage`` (fresh), the overlay ops, the one
unit, ``end_stage(complete)``. :func:`legacy_import_complete` is what
``graph_runtime`` checks before importing, so an import interrupted half-way is
retried rather than mistaken for a finished one (a retry re-appends the
status ops, which apply idempotently: same status, same notes).

No ``shell`` here: the caller redacts the graph's secrets first (it holds the
workspace key and the secret sidecar).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from adscan_core.graph_store import EdgeRef, GraphStore, OverlayOp
from adscan_core.graph_store.records import STAGE_LEGACY_IMPORT, WHOLE_STAGE_UNIT
from adscan_internal.services.graph_build import ingest

#: ``OverlayOp.origin`` of the operations an import writes.
LEGACY_IMPORT_ORIGIN = "legacy_graph_import"

#: Statuses that carry nothing ADscan did: no overlay op for them.
_UNEXECUTED_STATUSES = frozenset({"", "discovered"})


def legacy_import_complete(store: GraphStore) -> bool:
    """Whether a legacy import already completed in ``store``."""
    for run in store.stage_runs():
        if run.stage == STAGE_LEGACY_IMPORT:
            return run.status == "complete"
    return False


def identity_notes_for(relation: str, notes: Mapping[str, Any] | None) -> dict[str, Any]:
    """The identity-bearing notes of an edge: the share of a share-access edge.

    Taken verbatim (the first of ``share_name``, ``share``, ``collector_method``
    that names a share), so carrying them on an ``EdgeRef`` adds no new key to
    the edge's notes when an op merges them back.
    """
    from adscan_core.attack_graph_edge_identity import (  # noqa: PLC0415
        is_share_access_relation,
    )

    if not isinstance(notes, Mapping) or not is_share_access_relation(relation):
        return {}
    for key in ("share_name", "share"):
        value = notes.get(key)
        if isinstance(value, str) and value.strip():
            return {key: value}
    method = notes.get("collector_method")
    if isinstance(method, str) and method.strip().lower().startswith("share_acl:"):
        return {"collector_method": method}
    return {}


def edge_ref_for(edge: Mapping[str, Any]) -> EdgeRef | None:
    """The :class:`EdgeRef` of a stored edge (``from``/``to``, falling back to
    the ``source``/``target`` a host-check edge names), or ``None``."""
    source = str(edge.get("from") or edge.get("source") or "").strip()
    target = str(edge.get("to") or edge.get("target") or "").strip()
    relation = str(edge.get("relation") or "").strip()
    if not source or not target or not relation:
        return None
    notes = edge.get("notes") if isinstance(edge.get("notes"), Mapping) else {}
    return EdgeRef(
        from_id=source,
        to_id=target,
        relation=relation,
        identity_notes=identity_notes_for(relation, notes),
    )


def legacy_overlay_ops(graph: Mapping[str, Any]) -> list[OverlayOp]:
    """The overlay ops that keep a 14.0.x graph's runtime edges and statuses.

    One op per edge with ``edge_type`` ``runtime`` (an ``upsert_edge``) or a
    status other than ``discovered`` (a ``set_edge_status``), stamped with the
    edge's own ``last_seen``, so a rebuild reproduces it.
    """
    ops: list[OverlayOp] = []
    for edge in graph.get("edges") or ():
        if not isinstance(edge, Mapping):
            continue
        status = str(edge.get("status") or "").strip()
        edge_type = str(edge.get("edge_type") or "").strip()
        runtime = edge_type == "runtime"
        if not runtime and status.lower() in _UNEXECUTED_STATUSES:
            continue
        ref = edge_ref_for(edge)
        if ref is None:
            continue
        notes = edge.get("notes") if isinstance(edge.get("notes"), Mapping) else {}
        ops.append(
            OverlayOp(
                kind="upsert_edge" if runtime else "set_edge_status",
                edge=ref,
                status=status,
                edge_type=edge_type or "runtime",
                payload=dict(notes),
                origin=LEGACY_IMPORT_ORIGIN,
                recorded_at=str(edge.get("last_seen") or edge.get("first_seen") or ""),
            )
        )
    return ops


def import_legacy_graph(store: GraphStore, graph: Mapping[str, Any]) -> int:
    """Import a 14.0.x graph into ``store`` as the legacy base plus overlay ops.

    Args:
        store: The domain's (writable) store.
        graph: The graph as the file held it, its secrets already redacted.

    Returns:
        How many overlay operations were written.
    """
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), Mapping) else {}
    edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
    store.begin_stage(STAGE_LEGACY_IMPORT, units_total=1, fresh=True)
    try:
        ops = legacy_overlay_ops(graph)
        if ops:
            store.append_overlay(ops)
        with store.unit(STAGE_LEGACY_IMPORT, WHOLE_STAGE_UNIT) as writer:
            writer.add_objects(
                ingest.legacy_object_record(str(node_id), node)
                for node_id, node in nodes.items()
                if isinstance(node, Mapping)
            )
            writer.add_facts(
                ingest.legacy_fact_record(dict(edge))
                for edge in edges
                if isinstance(edge, Mapping)
            )
    except BaseException:
        store.end_stage(STAGE_LEGACY_IMPORT, "failed", reason="import_interrupted")
        raise
    store.end_stage(STAGE_LEGACY_IMPORT, "complete")
    return len(ops)


__all__ = (
    "LEGACY_IMPORT_ORIGIN",
    "edge_ref_for",
    "identity_notes_for",
    "import_legacy_graph",
    "legacy_import_complete",
    "legacy_overlay_ops",
)
