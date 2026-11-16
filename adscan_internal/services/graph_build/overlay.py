"""Overlay semantics: how ONE runtime operation changes a built graph.

The single implementation of the runtime overlay. The build applies every stored
operation through :func:`apply_op` in ``seq`` order, and the runtime facade
applies each new operation to the live in-memory graph through the same
function (``api.apply_overlay_op``), so a live graph and a rebuilt one cannot
differ.

Every edge write goes through ``attack_graph_service.upsert_edge``, the
edge-writing SSOT, so a status recorded through the overlay follows exactly the
rules a status recorded by ``update_edge_status_by_labels`` follows today: the
Tier-0-source refusal, the execution-support classification, the status-rank
rule (a lower-ranked status never overwrites a higher one), the "not needed"
reset and the notes merge.

Per operation kind (``records.OverlayOpKind``):

* ``upsert_edge`` / ``set_edge_status``: upsert the edge with ``status`` and the
  payload as notes. An edge the graph does not hold is created (``edge_type``
  ``runtime`` unless the op names one), exactly as a status on a missing edge
  creates one today. When an ENDPOINT is missing (the object left the directory
  after the step ran) the edge is still recorded, on a placeholder node, and the
  op is reported :attr:`OverlayOutcome.ORPHANED`: nothing ADscan did disappears
  from the graph. An endpoint that is not a node id at all (a host-check edge's
  IP or host label, the scanner ``ADscan``) gets no placeholder: the edge is
  recorded with it as is, as the 14.0.x writers stored it.
* ``patch_edge``: payload ``{"notes": {...}, "stamps": {...}}``. Notes merge into
  the edge's notes; stamps set top-level fields (never the identity, the status
  or the notes). Status untouched. No edge, nothing written: ORPHANED.
  Two optional keys make the patch EXACT instead of a merge, for the legacy
  save bridge (``graph_runtime``), which records "this edge became exactly
  this": ``"status"`` sets the status as given (no rank rule), and
  ``"replace_notes": true`` replaces the notes instead of merging them, and
  ``"edge_type"`` sets the edge's ``edge_type`` as given (``null``: none).
* ``retire_edge``: payload ``{"reason": ...}``. The edge leaves the built graph:
  a retired edge no longer holds (a dismissed candidate, a reverted change), so
  no reader (the path engine, the findings, the report, the web) may see it,
  and dropping it here keeps every one of them correct by construction. The
  history stays in the op log (who retired it, when, why), never in the graph.
  A later write of the same edge creates it again. No edge: ORPHANED.
* ``upsert_node``: payload is a node payload, upserted through
  ``attack_graph_service.upsert_nodes`` (the node id is computed from the
  payload). When the op names a ``node_id``, the payload is merged into the node
  with exactly that id instead (properties merged, the id kept): what the legacy
  save bridge records, since a caller-written node keeps the id it was given.
* ``patch_node``: payload merges into the node's ``properties``. No node: ORPHANED.
* ``reset_statuses``: payload is the selector (:func:`reset_statuses_selector`);
  every matching edge goes back to its support-derived default status.

Timestamps come from the op (``recorded_at``), never from the clock at apply
time, so a rebuild reproduces them.
"""

from __future__ import annotations

import enum
from collections.abc import Iterable, Mapping
from typing import Any

from adscan_core.graph_store import EdgeRef, OverlayOp
from adscan_internal.services import attack_graph_service

#: Placeholder-node marker for an overlay edge whose endpoint is gone.
ORPHAN_ENDPOINT_SOURCE = "overlay_orphan_endpoint"

#: Endpoint ids that name an actor, not a directory object: the scanner itself
#: (the source of a host-check edge such as ``Ntlmv1Enabled`` or a CVE edge). An
#: edge to or from one is recorded as it is, without a placeholder node, exactly
#: as the 14.0.x writers stored it.
NON_NODE_ENDPOINTS = frozenset({"ADscan"})

#: Prefix of every graph node id (``attack_graph_service._node_id``). Only an
#: endpoint shaped like one names a directory object that can leave the
#: directory; any other endpoint (an IP or a host label a host-check edge
#: names, the scanner) is recorded as it is, never as a placeholder node a
#: reader would show.
_NODE_ID_PREFIX = "name:"

#: Fields of an edge a ``patch_edge`` stamp may never overwrite.
_PROTECTED_EDGE_FIELDS = frozenset(
    {"id", "from", "to", "relation", "status", "notes", "kind", "edge_type"}
)

#: Execution outcomes a version-reconcile reset (``keep_outcomes``) leaves alone,
#: mirroring ``attack_graph_service.refresh_attack_graph_execution_support``.
_KEPT_OUTCOMES = frozenset(
    {"success", "attempted", "failed", "error", "unavailable", "closed_by_configuration"}
)


class OverlayOutcome(enum.Enum):
    """What one operation did to the graph."""

    #: The op found its target and changed (or confirmed) it.
    APPLIED = "applied"
    #: The op's target is gone. An edge write is still recorded (on a
    #: placeholder endpoint); a patch or retire writes nothing.
    ORPHANED = "orphaned"
    #: The graph refused the op (a Tier-0-source edge). Nothing written.
    REFUSED = "refused"
    #: The op cannot be applied by this engine (no target named, or an op kind
    #: a newer engine wrote). Kept in the log, nothing written.
    INVALID = "invalid"


def edge_payload_for_patch(
    *,
    notes: Mapping[str, Any] | None = None,
    stamps: Mapping[str, Any] | None = None,
    status: str | None = None,
    replace_notes: bool = False,
    exact_edge_type: bool = False,
    edge_type: str | None = None,
) -> dict[str, Any]:
    """The ``payload`` of a ``patch_edge`` op.

    ``status`` and ``replace_notes`` make the patch exact (see the module
    docstring); a runtime writer leaves them unset and gets the merge.
    """
    payload: dict[str, Any] = {"notes": dict(notes or {}), "stamps": dict(stamps or {})}
    if status is not None:
        payload["status"] = str(status)
    if replace_notes:
        payload["replace_notes"] = True
    if exact_edge_type:
        # ``None`` included: an edge stored without an ``edge_type`` keeps none.
        payload["edge_type"] = edge_type
    return payload


def reset_statuses_selector(
    *,
    relations: Iterable[str] | None = None,
    edge_types: Iterable[str] | None = None,
    keep_outcomes: bool = False,
) -> dict[str, Any]:
    """The ``payload`` of a ``reset_statuses`` op.

    Args:
        relations: Only edges of these relations (case-insensitive); all when None.
        edge_types: Only edges of these ``edge_type`` values; all when None.
        keep_outcomes: Leave execution outcomes, configuration closes and safety
            abstentions alone (the version reconcile of a reopened workspace).
            ``False`` resets everything (``attack_path_reset``).
    """
    selector: dict[str, Any] = {"keep_outcomes": bool(keep_outcomes)}
    if relations is not None:
        selector["relations"] = sorted({str(r) for r in relations})
    if edge_types is not None:
        selector["edge_types"] = sorted({str(t) for t in edge_types})
    return selector


def _nodes(graph: dict[str, Any]) -> dict[str, Any]:
    nodes = graph.get("nodes")
    if not isinstance(nodes, dict):
        nodes = {}
        graph["nodes"] = nodes
    return nodes


def _edges(graph: dict[str, Any]) -> list[Any]:
    edges = graph.get("edges")
    if not isinstance(edges, list):
        edges = []
        graph["edges"] = edges
    return edges


def _ensure_endpoint(graph: dict[str, Any], node_id: str) -> bool:
    """Make sure ``node_id`` is a node; returns False when a placeholder was needed."""
    nodes = _nodes(graph)
    if node_id in nodes or node_id in NON_NODE_ENDPOINTS:
        return True
    if not node_id.startswith(_NODE_ID_PREFIX):
        return True
    label = node_id.split(":", 1)[1] if node_id.startswith("name:") else node_id
    nodes[node_id] = {
        "id": node_id,
        "label": label,
        "kind": "Unknown",
        "objectId": None,
        "properties": {
            "name": label,
            "synthetic": True,
            "source": ORPHAN_ENDPOINT_SOURCE,
        },
    }
    return False


def find_edge(
    graph: dict[str, Any],
    ref: EdgeRef,
    *,
    index: "attack_graph_service.EdgeUpsertIndex | None" = None,
) -> dict[str, Any] | None:
    """The graph's edge with ``ref``'s identity (the ``upsert_edge`` identity), or None."""
    relation = attack_graph_service._normalize_relation(ref.relation)  # noqa: SLF001
    if index is None:
        index = attack_graph_service.EdgeUpsertIndex()
    found, _key = index.find(
        _edges(graph),
        from_id=ref.from_id,
        to_id=ref.to_id,
        relation=relation,
        incoming_notes=dict(ref.identity_notes or {}),
    )
    return found


def _stamp_seen(
    edge: dict[str, Any], recorded_at: str, *, created: bool, previous_last_seen: str | None = None
) -> None:
    """Stamp the op's time on ``edge``; never the clock at apply time.

    ``previous_last_seen`` is the edge's ``last_seen`` before the op touched it
    (``upsert_edge`` refreshes it to the wall clock, which must not survive:
    a rebuild would read a different value).
    """
    previous = str(edge.get("last_seen") or "") if previous_last_seen is None else previous_last_seen
    if not recorded_at:
        if previous and not created:
            edge["last_seen"] = previous
        return
    if created or not edge.get("first_seen"):
        # Created now, or an edge that carried no stamp (an engine follow-up):
        # its first observation is this op, never the apply-time clock.
        edge["first_seen"] = recorded_at
        edge["discovered_at"] = recorded_at
    edge["last_seen"] = max(previous, recorded_at) if previous and not created else recorded_at


def _apply_edge_write(
    graph: dict[str, Any],
    op: OverlayOp,
    *,
    default_status: str,
    index: "attack_graph_service.EdgeUpsertIndex | None",
) -> OverlayOutcome:
    ref = op.edge
    if ref is None or not ref.from_id or not ref.to_id or not ref.relation:
        return OverlayOutcome.INVALID
    existing = find_edge(graph, ref, index=index)
    previous_last_seen = str(existing.get("last_seen") or "") if existing is not None else ""
    # The identity-bearing notes (a share-access edge's share) always travel
    # with the write, so the upsert lands on the same edge after any rebuild.
    notes = {**dict(ref.identity_notes or {}), **dict(op.payload or {})}
    edge = attack_graph_service.upsert_edge(
        graph,
        from_id=ref.from_id,
        to_id=ref.to_id,
        relation=ref.relation,
        edge_type=op.edge_type or "runtime",
        status=op.status or default_status,
        notes=notes,
        log_creation=False,
        index=index,
    )
    if not edge:
        return OverlayOutcome.REFUSED
    _stamp_seen(
        edge, op.recorded_at, created=existing is None, previous_last_seen=previous_last_seen
    )
    source_present = _ensure_endpoint(graph, ref.from_id)
    target_present = _ensure_endpoint(graph, ref.to_id)
    return (
        OverlayOutcome.APPLIED
        if source_present and target_present
        else OverlayOutcome.ORPHANED
    )


def _apply_patch_edge(
    graph: dict[str, Any],
    op: OverlayOp,
    *,
    index: "attack_graph_service.EdgeUpsertIndex | None",
) -> OverlayOutcome:
    if op.edge is None:
        return OverlayOutcome.INVALID
    edge = find_edge(graph, op.edge, index=index)
    if edge is None:
        return OverlayOutcome.ORPHANED
    payload = dict(op.payload or {})
    notes_in = payload.get("notes")
    if payload.get("replace_notes"):
        edge["notes"] = dict(notes_in) if isinstance(notes_in, Mapping) else {}
    elif isinstance(notes_in, Mapping) and notes_in:
        existing = edge.get("notes") if isinstance(edge.get("notes"), dict) else {}
        edge["notes"] = attack_graph_service._merge_attack_step_notes(  # noqa: SLF001
            existing=existing, incoming=dict(notes_in)
        )
    status = payload.get("status")
    if isinstance(status, str) and status.strip():
        edge["status"] = status.strip()
    if "edge_type" in payload:
        if payload["edge_type"] is None:
            edge.pop("edge_type", None)
        else:
            edge["edge_type"] = str(payload["edge_type"])
    stamps = payload.get("stamps")
    if isinstance(stamps, Mapping):
        for key, value in stamps.items():
            if str(key) not in _PROTECTED_EDGE_FIELDS:
                edge[str(key)] = value
    _stamp_seen(edge, op.recorded_at, created=False)
    return OverlayOutcome.APPLIED


def _apply_retire_edge(
    graph: dict[str, Any],
    op: OverlayOp,
    *,
    index: "attack_graph_service.EdgeUpsertIndex | None",
) -> OverlayOutcome:
    if op.edge is None:
        return OverlayOutcome.INVALID
    edge = find_edge(graph, op.edge, index=index)
    if edge is None:
        return OverlayOutcome.ORPHANED
    edges = _edges(graph)
    graph["edges"] = [item for item in edges if item is not edge]
    if index is not None:
        index.invalidate()
    return OverlayOutcome.APPLIED


def _apply_upsert_node(graph: dict[str, Any], op: OverlayOp) -> OverlayOutcome:
    payload = dict(op.payload or {})
    if not payload:
        return OverlayOutcome.INVALID
    if op.node_id:
        nodes = _nodes(graph)
        existing = nodes.get(op.node_id)
        merged = dict(existing) if isinstance(existing, dict) else {}
        properties = dict(merged.get("properties") or {}) if isinstance(
            merged.get("properties"), dict
        ) else {}
        incoming_properties = payload.get("properties")
        merged.update(payload)
        if isinstance(incoming_properties, Mapping):
            properties.update(incoming_properties)
            merged["properties"] = properties
        elif properties:
            merged["properties"] = properties
        nodes[op.node_id] = merged
        return OverlayOutcome.APPLIED
    attack_graph_service.upsert_nodes(graph, [payload])
    return OverlayOutcome.APPLIED


def _apply_patch_node(graph: dict[str, Any], op: OverlayOp) -> OverlayOutcome:
    node = _nodes(graph).get(op.node_id)
    if not isinstance(node, dict):
        return OverlayOutcome.ORPHANED
    properties = node.get("properties")
    if not isinstance(properties, dict):
        properties = {}
    properties = {**properties, **dict(op.payload or {})}
    node["properties"] = properties
    return OverlayOutcome.APPLIED


def _reset_one_edge(graph: dict[str, Any], edge: dict[str, Any], *, keep_outcomes: bool) -> None:
    from adscan_internal.services.destructive_action_policy import (  # noqa: PLC0415
        DANGEROUS_DESTRUCTIVE_MARKER,
    )

    relation = str(edge.get("relation") or "").strip()
    current = str(edge.get("status") or "discovered").strip().lower()
    notes = edge.get("notes") if isinstance(edge.get("notes"), dict) else {}
    if keep_outcomes:
        if current in _KEPT_OUTCOMES:
            return
        if (
            current == "blocked"
            and str(notes.get("blocked_kind") or "").strip() == DANGEROUS_DESTRUCTIVE_MARKER
        ):
            return
    desired_status, desired_notes = attack_graph_service._desired_exec_support_state(  # noqa: SLF001
        graph, relation=relation, to_id=str(edge.get("to") or "")
    )
    edge["status"] = desired_status
    notes = dict(notes)
    if not keep_outcomes:
        notes.pop("attempts", None)
    notes.update(desired_notes)
    edge["notes"] = notes


def _apply_reset_statuses(graph: dict[str, Any], op: OverlayOp) -> OverlayOutcome:
    selector = dict(op.payload or {})
    relations = selector.get("relations")
    relation_set = (
        {str(r).strip().lower() for r in relations} if isinstance(relations, list) else None
    )
    edge_types = selector.get("edge_types")
    type_set = {str(t) for t in edge_types} if isinstance(edge_types, list) else None
    keep_outcomes = bool(selector.get("keep_outcomes"))
    for edge in _edges(graph):
        if not isinstance(edge, dict) or not str(edge.get("relation") or "").strip():
            continue
        if relation_set is not None and str(edge.get("relation")).strip().lower() not in relation_set:
            continue
        if type_set is not None and str(edge.get("edge_type") or "") not in type_set:
            continue
        _reset_one_edge(graph, edge, keep_outcomes=keep_outcomes)
    return OverlayOutcome.APPLIED


def apply_op(
    graph: dict[str, Any],
    op: OverlayOp,
    *,
    index: "attack_graph_service.EdgeUpsertIndex | None" = None,
) -> OverlayOutcome:
    """Apply ONE runtime operation to ``graph`` in place.

    ``index`` makes the edge lookups O(1) when a caller applies many operations
    to one graph (the build); a single live apply passes none.
    """
    kind = op.kind
    if kind == "set_edge_status":
        return _apply_edge_write(graph, op, default_status="discovered", index=index)
    if kind == "upsert_edge":
        return _apply_edge_write(graph, op, default_status="discovered", index=index)
    if kind == "patch_edge":
        return _apply_patch_edge(graph, op, index=index)
    if kind == "retire_edge":
        return _apply_retire_edge(graph, op, index=index)
    if kind == "upsert_node":
        return _apply_upsert_node(graph, op)
    if kind == "patch_node":
        return _apply_patch_node(graph, op)
    if kind == "reset_statuses":
        return _apply_reset_statuses(graph, op)
    # An op kind this engine does not know (written by a newer one) is kept in
    # the log and reported, never guessed at.
    return OverlayOutcome.INVALID


__all__ = (
    "NON_NODE_ENDPOINTS",
    "ORPHAN_ENDPOINT_SOURCE",
    "OverlayOutcome",
    "apply_op",
    "edge_payload_for_patch",
    "find_edge",
    "reset_statuses_selector",
)
