"""Turn a pure graph edit into runtime-facade calls.

Several runtime callers decide a graph change with a pure function that edits a
loaded graph dict in place (the ESC9, ESC14 and ESC15 confirmation verdicts, the
BloodHound-path edge writers) and then used to serialise the whole graph with
``save_attack_graph``. Every change the graph receives after collection now goes
through :mod:`adscan_internal.services.graph_runtime`, one overlay operation per
change. This module is the bridge for those callers: it keeps their decision
logic exactly as it was, runs it on an isolated copy of the edges it touches, and
records the resulting difference through the facade.

* :func:`apply_graph_edit` runs ``edit(view)`` on a private view of the graph and
  records what it removed (retired), changed (status, notes, stamps) or added.
* :func:`record_path_edges` is the shell-aware twin of
  ``attack_graph_service.add_bloodhound_path_edges``: the same node enrichment and
  the same edge identity, written as overlay operations instead of into a dict.
* :func:`edge_ref_for_edge` is the identity of a stored edge as the overlay keys it.

Nothing here is bound to an event loop and nothing here opens a store: every write
is a facade call, so the facade owns the store, the throttle and the export.
"""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, TypeVar

from adscan_core.attack_graph_edge_identity import (
    is_share_access_relation,
    share_access_name_from_notes,
)
from adscan_core.graph_store import EdgeRef
from adscan_core.rich_output import print_info_debug

_T = TypeVar("_T")

#: Fields of a stored edge that are never a "stamp" (identity, state, notes).
_NON_STAMP_FIELDS = frozenset(
    {"id", "from", "to", "relation", "status", "notes", "kind", "edge_type"}
)


def edge_ref_for_edge(edge: Mapping[str, Any]) -> EdgeRef:
    """The overlay identity of a stored edge (``from``/``to`` ids, relation, share)."""
    relation = str(edge.get("relation") or "").strip()
    notes = edge.get("notes") if isinstance(edge.get("notes"), dict) else {}
    identity_notes: dict[str, Any] = {}
    if is_share_access_relation(relation):
        share = share_access_name_from_notes(notes)
        if share:
            identity_notes["share_name"] = share
    return EdgeRef(
        from_id=str(edge.get("from") or "").strip(),
        to_id=str(edge.get("to") or "").strip(),
        relation=relation,
        identity_notes=identity_notes,
    )


def _edge_key(edge: Mapping[str, Any]) -> tuple[str, str, str, str]:
    ref = edge_ref_for_edge(edge)
    share = str(ref.identity_notes.get("share_name") or "").casefold()
    return (ref.from_id, ref.relation.casefold(), ref.to_id, share)


def _notes_delta(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
    """The notes ``after`` adds or changes against ``before`` (merge semantics)."""
    return {key: value for key, value in after.items() if before.get(key, _MISSING) != value}


_MISSING = object()


@dataclass
class GraphEditOutcome:
    """What recording one edit through the facade did, for the caller's logging."""

    retired: int = 0
    status_changes: int = 0
    patched: int = 0
    added: int = 0
    refused: int = 0
    refs: list[EdgeRef] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.retired + self.status_changes + self.patched + self.added


def apply_graph_edit(
    shell: object,
    domain: str,
    graph: Mapping[str, Any],
    edit: Callable[[dict[str, Any]], _T],
    *,
    edge_filter: Callable[[Mapping[str, Any]], bool] | None = None,
    origin: str = "",
) -> tuple[_T, GraphEditOutcome]:
    """Run ``edit`` on a private view of ``graph`` and record its difference.

    ``edit`` is the caller's existing pure function, called with a graph dict that
    carries a private deep copy of the edges ``edge_filter`` selects (all edges
    when it is ``None``) and the live ``nodes`` map shared READ-ONLY. It may edit
    those edges in place or drop them from ``view["edges"]``. The loaded ``graph``
    is never touched, so the memoised graph only ever changes through the facade.

    Recorded through :mod:`graph_runtime`, per edge:

    * dropped from the view: ``retire_runtime_edge`` (the edge stays as history);
    * status changed: ``record_edge_status`` (carrying the notes delta);
    * notes or top-level stamps changed: ``patch_runtime_edge``;
    * added: ``record_runtime_edge``.

    Args:
        shell: The session.
        domain: The domain the graph belongs to.
        graph: The loaded graph (read only).
        edit: The pure edit; its return value is returned unchanged.
        edge_filter: Which edges the edit may see and change.
        origin: The writer name recorded on every operation.

    Returns:
        ``(edit's return value, GraphEditOutcome)``.
    """
    from adscan_internal.services import graph_runtime  # noqa: PLC0415

    edges = graph.get("edges")
    selected = [
        edge
        for edge in (edges if isinstance(edges, list) else [])
        if isinstance(edge, dict) and (edge_filter is None or edge_filter(edge))
    ]
    view: dict[str, Any] = {key: value for key, value in graph.items() if key != "edges"}
    view["edges"] = [copy.deepcopy(edge) for edge in selected]
    before = {_edge_key(edge): edge for edge in selected}

    result = edit(view)

    outcome = GraphEditOutcome()
    after_edges = view.get("edges")
    after = {
        _edge_key(edge): edge
        for edge in (after_edges if isinstance(after_edges, list) else [])
        if isinstance(edge, dict)
    }
    for key, original in before.items():
        ref = edge_ref_for_edge(original)
        edited = after.get(key)
        if edited is None:
            if graph_runtime.retire_runtime_edge(
                shell, domain, ref, reason=origin or "graph_edit", origin=origin
            ):
                outcome.retired += 1
                outcome.refs.append(ref)
            continue
        original_notes = original.get("notes") if isinstance(original.get("notes"), dict) else {}
        edited_notes = edited.get("notes") if isinstance(edited.get("notes"), dict) else {}
        delta = _notes_delta(original_notes, edited_notes)
        status_before = str(original.get("status") or "")
        status_after = str(edited.get("status") or "")
        if status_after and status_after != status_before:
            if graph_runtime.record_edge_status(
                shell, domain, ref, status_after, notes=delta or None, origin=origin
            ):
                outcome.status_changes += 1
                outcome.refs.append(ref)
            else:
                outcome.refused += 1
            continue
        stamps = {
            key_: value
            for key_, value in edited.items()
            if key_ not in _NON_STAMP_FIELDS and original.get(key_, _MISSING) != value
        }
        if delta or stamps:
            if graph_runtime.patch_runtime_edge(
                shell,
                domain,
                ref,
                notes=delta or None,
                stamps=stamps or None,
                origin=origin,
            ):
                outcome.patched += 1
                outcome.refs.append(ref)
    for key, edited in after.items():
        if key in before:
            continue
        ref = edge_ref_for_edge(edited)
        notes = edited.get("notes") if isinstance(edited.get("notes"), dict) else {}
        if graph_runtime.record_runtime_edge(
            shell,
            domain,
            ref,
            edge_type=str(edited.get("edge_type") or "runtime"),
            status=str(edited.get("status") or "discovered"),
            notes=dict(notes) or None,
            origin=origin,
        ):
            outcome.added += 1
            outcome.refs.append(ref)
        else:
            outcome.refused += 1
    print_info_debug(
        "graph edit recorded through the runtime facade: "
        f"origin={origin or 'unspecified'} retired={outcome.retired} "
        f"status={outcome.status_changes} patched={outcome.patched} added={outcome.added} "
        f"refused={outcome.refused}"
    )
    return result, outcome


def record_path_edges(
    shell: object,
    domain: str,
    *,
    nodes: list[dict[str, Any]],
    relations: list[str],
    status: str = "discovered",
    edge_type: str = "graph_collection",
    notes_by_relation_index: Mapping[int, dict[str, Any]] | None = None,
    origin: str = "",
) -> int:
    """Record a BloodHound-derived path (ordered nodes plus the relations between them).

    The overlay twin of ``attack_graph_service.add_bloodhound_path_edges``: the nodes
    are enriched with the persisted enabled state exactly as that function does,
    each node is recorded through ``record_runtime_node`` and each consecutive pair
    through ``record_runtime_edge``. Node ids and edge identity come from the same
    helpers the dict writer uses, so the edge lands on the same identity.

    Returns:
        How many edges the graph accepted (one a Tier-0-source refusal does not count).
    """
    from adscan_internal.services import attack_graph_service as ags  # noqa: PLC0415
    from adscan_internal.services import graph_runtime  # noqa: PLC0415

    if not nodes or not relations:
        return 0
    scratch: dict[str, Any] = {"domain": str(domain or ""), "nodes": {}, "edges": []}
    enriched = [ags._enrich_node_enabled_metadata(shell, scratch, node) for node in nodes]  # noqa: SLF001
    node_ids: list[str] = []
    for node in enriched:
        node_ids.append(graph_runtime.record_runtime_node(shell, domain, node, origin=origin))
    created = 0
    for idx, relation in enumerate(relations):
        if idx + 1 >= len(enriched):
            break
        notes = notes_by_relation_index.get(idx) if notes_by_relation_index else None
        ref = EdgeRef(from_id=node_ids[idx], to_id=node_ids[idx + 1], relation=str(relation))
        if graph_runtime.record_runtime_edge(
            shell,
            domain,
            ref,
            edge_type=edge_type,
            status=status,
            notes=dict(notes) if notes else None,
            origin=origin,
        ):
            created += 1
    return created


__all__ = (
    "GraphEditOutcome",
    "apply_graph_edit",
    "edge_ref_for_edge",
    "record_path_edges",
)
