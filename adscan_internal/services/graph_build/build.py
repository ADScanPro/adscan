"""The graph build: inventory -> nodes -> base edges -> derived edges -> overlay -> graph.

Implements ``api.build_graph``. Reads the store only through the
:class:`~adscan_core.graph_store.GraphStore` interface, never writes to it, never
touches disk, and takes no ``shell``.

Bounded memory (spec section 14): the relationships are never held as a list.
``result.edges`` is an ``edge_view.EdgeView`` that streams the store on each
iteration, and each rule streams only the relations it reads. After the build,
memory holds the graph, the object index and the indexes a pass needs; nothing
holds one entry per fact.

Steps:

1. **Nodes** from the collected objects (classification, privileged-membership
   annotations, tier stamp): ``nodes.upsert_result_nodes``.
2. **Base edges** from the collected relationships: ``base_edges.emit_base_edges``
   (skip rules, endpoint resolution, foreign endpoints through the sibling
   stores). One stream of the store, which also stamps each edge with the
   dates of its facts and accumulates the inventory span.
3. **Derivation passes**, in registry order (``passes.registry``).
4. **Timestamps** from the store (``base_edges.apply_store_stamps``): a base
   edge carries the first and last time its relationship was committed; a
   derived edge the span of the whole inventory (its earliest and latest
   commit), so its ``first_seen`` does not move when a unit it was derived from
   is re-collected. Never the clock at build time.
5. **Overlay**: every stored runtime operation, in ``seq`` order, through
   ``overlay.apply_op`` (the same function the live facade applies).
6. **Post-overlay passes** (``passes.post_overlay.run_post_overlay``) over
   every domain's recorded facts, then the root ``technique_knowledge`` block
   (:func:`finish_post_overlay`).
7. **Root**: schema marker, domain, ``generated_at`` (``context.now``), the
   collection stages (``collection.stages``), the command coordinates and the
   recorded run.
8. **Interning** of the strings repeated on every edge.

A workspace whose store holds only a 14.0.x graph imported as the base
(``STAGE_LEGACY_IMPORT``) is built from that base, taken as it is; once any real
stage committed, the legacy base is dropped for the domain and the inventory
replaces it (the overlay, imported statuses included, applies either way).
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from adscan_core.graph_compact import compact_graph
from adscan_core.graph_store import GraphStore, StageRun
from adscan_core.graph_store.records import STAGE_LEGACY_IMPORT
from adscan_internal.services import attack_graph_core, attack_graph_service
from adscan_internal.services.graph_build import ingest
from adscan_internal.services.graph_build.api import (
    BuildReport,
    Graph,
    GraphBuildContext,
)
from adscan_internal.services.graph_build.base_edges import (
    apply_store_stamps,
    emit_base_edges,
)
from adscan_internal.services.graph_build.edge_view import (
    InventorySpan,
    streamed_build_inputs,
)
from adscan_internal.services.graph_build.inputs import activate_build_inputs
from adscan_core.memory_guard import MemoryCeilingReached, MemoryGuard
from adscan_internal.services.graph_build.memory_guard import new_build_guard
from adscan_internal.services.graph_build.nodes import upsert_result_nodes
from adscan_internal.services.graph_build.overlay import OverlayOutcome, apply_op
from adscan_internal.services.graph_build.passes import registry
from adscan_internal.services.graph_build.passes.post_overlay import (
    run_post_overlay,
    sort_edges,
    stamp_graph_coordinates,
)

LEGACY_NODE_PROPERTY = ingest.LEGACY_NODE_PROPERTY

#: Edge fields whose values repeat on most edges; interned so the in-memory
#: graph holds one copy of each (spec 5.4, item 1).
_INTERNED_EDGE_FIELDS = (
    "from",
    "to",
    "relation",
    "kind",
    "edge_type",
    "status",
    "category",
    "first_seen",
    "last_seen",
    "discovered_at",
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _empty_graph(context: GraphBuildContext) -> Graph:
    now = context.now() if context.now is not None else _utc_now_iso()
    return {
        "schema_version": attack_graph_service.ATTACK_GRAPH_SCHEMA_VERSION,
        "domain": context.domain,
        "generated_at": now,
        "maintenance": {
            "normalization": attack_graph_service._maintenance_key(  # noqa: SLF001
                attack_graph_service._ATTACK_GRAPH_MAINTENANCE_VERSION  # noqa: SLF001
            ),
            "bh_ce_synced": True,
            "native_collector_synced": True,
        },
        "nodes": {},
        "edges": [],
    }


def _legacy_base_only(store: GraphStore, result: Any) -> bool:
    """True when the store holds a 14.0.x graph import and nothing collected.

    ``result`` is the collected view (legacy records excluded): one collected
    object or relationship and the legacy base is dropped for the domain.
    """
    if result.nodes or result.edges:
        return False
    return bool(store.done_units(STAGE_LEGACY_IMPORT))


def _emit_legacy_base(graph: Graph, store: GraphStore, guard: MemoryGuard | None = None) -> int:
    """Take an imported 14.0.x graph as the base, AS IT IS.

    Nodes and edges are inserted exactly as the file stored them (an edge's
    status, verdicts, timestamps and endpoint naming included; its technique
    text left out, format 2). Nothing is re-derived or re-classified here: the
    post-overlay passes then do what a 14.0.x save of the same file did
    (follow-ups, classification of what carries no verdict yet, the
    Tier-0-source prune). A duplicate ``from``/``to`` identity keeps the first,
    as a 14.0.x upsert did.
    """
    nodes = graph["nodes"]
    for record in store.iter_objects():
        payload = record.properties.get(LEGACY_NODE_PROPERTY)
        if isinstance(payload, dict):
            nodes[record.object_id] = dict(payload)
    index = attack_graph_service.EdgeUpsertIndex()
    facts = store.iter_facts(stages=[STAGE_LEGACY_IMPORT])
    try:
        persisted = _emit_legacy_facts(graph, facts, index, guard)
    finally:
        _close_stream(facts)
    return persisted


def _emit_legacy_facts(
    graph: Graph,
    facts: Any,
    index: "attack_graph_service.EdgeUpsertIndex",
    guard: MemoryGuard | None,
) -> int:
    edges = graph["edges"]
    persisted = 0
    for fact in facts:
        if guard is not None:
            guard.tick()
        stored = (fact.notes or {}).get(ingest.LEGACY_EDGE_NOTE)
        if not isinstance(stored, dict):
            continue
        entry = {k: v for k, v in stored.items() if k != "knowledge"}
        if entry.get("from") and entry.get("to"):
            existing, _key = index.find(
                edges,
                from_id=str(entry["from"]),
                to_id=str(entry["to"]),
                relation=str(entry.get("relation") or ""),
                incoming_notes=entry.get("notes") if isinstance(entry.get("notes"), dict) else {},
            )
            if existing is not None:
                continue
        edges.append(entry)
        index.appended(edges, entry)
        persisted += 1
    return persisted


def _close_stream(stream: Any) -> None:
    """Close a store stream (an unexhausted read pins the SQLite WAL)."""
    close = getattr(stream, "close", None)
    if callable(close):
        close()


def _legacy_span(store: GraphStore, guard: MemoryGuard | None = None) -> tuple[str, str]:
    """``(earliest first_seen, latest last_seen)`` over the facts that carry a first date.

    The stamp of an imported 14.0.x edge that stored none. A running minimum
    and maximum over one stream: nothing per fact is kept.
    """
    span = InventorySpan()
    stream = store.iter_facts()
    try:
        for fact in stream:
            if guard is not None:
                guard.tick()
            if fact.first_seen and not ingest.is_evidence_only_fact(fact):
                span.add(fact)
    finally:
        _close_stream(stream)
    return span.as_tuple()


def _collection_block(runs: list[StageRun]) -> dict[str, Any]:
    return {
        "stages": [
            {
                "stage": run.stage,
                "status": run.status,
                "reason": run.reason,
                "units_done": int(run.units_done),
                "units_total": int(run.units_total),
            }
            for run in runs
        ]
    }


def _intern_graph(graph: Graph) -> None:
    """Compact residency for the built graph (spec 15.3): every edge and node a
    key-sharing dict, endpoints, timestamps and vocabulary one string each,
    identical scalar notes shared when ``ADSCAN_GRAPH_SHARED_NOTES`` is on
    (``adscan_core.graph_compact``). Equal to the uncompacted graph, key order
    included; one element at a time, so the peak is the graph plus one."""
    compact_graph(graph)


def finish_post_overlay(graph: Graph, context: GraphBuildContext) -> dict[str, int]:
    """The post-overlay passes, then the root ``technique_knowledge`` block.

    The one step both the build and the runtime facade end with
    (``api.run_post_overlay_passes``). The passes get the real multi-domain
    ``context.domains_data``. The block is computed from the final edge set, as
    ``save_attack_graph`` computed it before writing, so a graph exported
    straight from the build keeps the generic technique text of every relation
    it uses (format 2) and no edge carries its own.
    """
    from adscan_internal.services.edge_knowledge import (  # noqa: PLC0415
        build_technique_knowledge,
    )

    counts = run_post_overlay(graph, domains_data=context.domains_data_for_passes())
    graph["technique_knowledge"] = build_technique_knowledge(graph)
    return counts


def build_graph(store: GraphStore, context: GraphBuildContext) -> tuple[Graph, BuildReport]:
    """See ``api.build_graph``.

    Raises:
        MemoryCeilingReached: The build reached the memory ceiling
            (``adscan_core.memory_guard``, stage ``graph_build``) and stopped.
            Nothing was built: the partial graph is released before the
            exception leaves and the store is untouched. Only the stage
            boundary catches it (``memory_bounded`` with
            ``memory_guard.record_graph_build_stop``), never an export.
    """
    guard = new_build_guard()
    held: dict[str, Any] = {}
    try:
        return _build_graph(store, context, guard, held)
    except MemoryCeilingReached:
        # The exception's traceback pins this frame and the build's frames: drop
        # what they reference so the stop actually frees the memory it guards.
        graph = held.get("graph")
        if isinstance(graph, dict):
            graph.clear()
        inputs = held.get("inputs")
        if inputs is not None:
            inputs.result.nodes.clear()
            inputs.nodes = None
        held.clear()
        raise


def _build_graph(
    store: GraphStore,
    context: GraphBuildContext,
    guard: MemoryGuard,
    held: dict[str, Any],
) -> tuple[Graph, BuildReport]:
    started = time.monotonic()
    seconds: dict[str, float] = {}
    generation = store.generation()
    graph = held["graph"] = _empty_graph(context)
    guard.check()
    inputs = held["inputs"] = streamed_build_inputs(store, context, on_fact=guard.tick)
    dropped: dict[str, int] = {}
    inventory_span = ("", "")
    legacy_only = _legacy_base_only(store, inputs.result)

    mark = time.monotonic()
    guard.check()
    if legacy_only:
        base_edges = _emit_legacy_base(graph, store, guard)
        # The legacy nodes are verbatim; the derivation passes below re-derive
        # over the graph dict only (the result view holds no object).
        inputs.nodes = upsert_result_nodes(graph, inputs.result)
        seconds["nodes"] = time.monotonic() - mark
    else:
        inputs.nodes = upsert_result_nodes(graph, inputs.result)
        seconds["nodes"] = time.monotonic() - mark
        mark = time.monotonic()
        guard.check()
        outcome = emit_base_edges(
            graph,
            result=inputs.result,
            sid_to_graph_id=inputs.sid_to_graph_id,
            foreign_sid_to_label=inputs.foreign_refs,
        )
        base_edges = outcome.persisted
        dropped.update(outcome.dropped)
        inventory_span = outcome.span.as_tuple()
        seconds["base_edges"] = time.monotonic() - mark

    derived = 0
    with activate_build_inputs(store, inputs):
        for derivation in registry():
            mark = time.monotonic()
            guard.check()
            derived += int(derivation.run(graph, store, context) or 0)
            seconds[derivation.name] = time.monotonic() - mark

    mark = time.monotonic()
    guard.check()
    if not legacy_only:
        apply_store_stamps(graph, inventory_span)
    else:
        earliest, latest = _legacy_span(store, guard)
        for edge in graph["edges"]:
            if isinstance(edge, dict) and not edge.get("first_seen"):
                edge["first_seen"] = edge["discovered_at"] = earliest
                edge["last_seen"] = latest
    # Engine follow-ups exist before the overlay, as they do in a live graph, so
    # a status recorded on one lands on the same edge in both. Sorted first, as
    # the live graph is, so both derive them from the same edge order.
    sort_edges(graph)
    attack_graph_core.materialize_engine_followup_edges(graph)
    sort_edges(graph)
    seconds["timestamps_and_followups"] = time.monotonic() - mark
    edges_before_overlay = len(graph["edges"])

    mark = time.monotonic()
    guard.check()
    applied = 0
    orphaned = 0
    overlay_index = attack_graph_service.EdgeUpsertIndex()
    overlay_ops = store.iter_overlay()
    try:
        for op in overlay_ops:
            guard.tick()
            result = apply_op(graph, op, index=overlay_index)
            if result is OverlayOutcome.APPLIED:
                applied += 1
            elif result in (OverlayOutcome.ORPHANED, OverlayOutcome.INVALID):
                orphaned += 1
    finally:
        _close_stream(overlay_ops)
    seconds["overlay"] = time.monotonic() - mark
    overlay_edges = max(0, len(graph["edges"]) - edges_before_overlay)

    # Share-file credential edges are runtime (overlay) edges recorded before
    # the share stage measured who reads the share: re-source them from the
    # store's readers, once per build (never on the live post-overlay path).
    mark = time.monotonic()
    from adscan_internal.services.graph_build.passes.shares import (  # noqa: PLC0415
        reconcile_share_credential_sources,
    )

    reconcile_share_credential_sources(graph, store)
    seconds["share_credential_sources"] = time.monotonic() - mark

    mark = time.monotonic()
    guard.check()
    finish_post_overlay(graph, context)
    seconds["post_overlay"] = time.monotonic() - mark
    guard.check()

    runs = store.stage_runs()
    graph["collection"] = _collection_block(runs)
    stamp_graph_coordinates(graph, domain=context.domain, domain_data=context.domain_data)
    from adscan_core.engagement.coverage_io import stamp_artifact_run_id  # noqa: PLC0415

    stamp_artifact_run_id(graph, context.coverage_run_id or None)
    _intern_graph(graph)

    report = BuildReport(
        generation=generation,
        nodes=len(graph["nodes"]),
        base_edges=base_edges,
        derived_edges=derived,
        overlay_edges=overlay_edges,
        overlay_ops_applied=applied,
        overlay_ops_orphaned=orphaned,
        dropped_facts=dict(sorted(dropped.items())),
        stages=tuple(runs),
        seconds_by_pass=seconds,
        seconds_total=time.monotonic() - started,
    )
    held.clear()
    return graph, report


__all__ = ("LEGACY_NODE_PROPERTY", "build_graph", "finish_post_overlay")
