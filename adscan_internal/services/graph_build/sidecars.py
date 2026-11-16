"""The files exported beside ``attack_graph.json``: ``memberships.json`` and ``inventory/*.json``.

In 14.0.x the collector rewrote these on every checkpoint. With the store they
are exported from it, by one function, right after a successful graph export
(``graph_runtime.export_graph_if_due`` passes it to ``export_if_due`` as the
``after_export`` hook), so the three files of a domain describe the same
inventory and the same overlay.

What each holds:

* ``memberships.json``: the membership snapshot every membership reader
  consumes (``services/membership_snapshot.py``), built from the inventory's
  ``MemberOf`` facts exactly as the 14.0.x collector wrote it, plus the
  runtime ``MemberOf`` edges the built graph carries from the overlay
  (spec 4.5), so a membership ADscan proved at runtime is seen by every reader.
* ``inventory/*.json``: the per-kind inventory files (users, computers, ...),
  written by the collector's single inventory writer
  (``collector.inventory_persistence.write_inventory_files``) from the store's
  objects, facts and directory data.

When: at the end of a stage and at session end, NOT during a stage. An export
made while any stage is still ``running`` (the host sweep's throttled live
export) refreshes the graph only; the sidecars follow when the stage ends, so
the sweep's cost never includes rewriting every inventory file.

Both are in-scope output files: their schema version marker, schema and
contract test are unchanged; only WHEN and FROM WHAT they are written moved.
Both are streamed, so the export never holds a whole sidecar document:
``memberships.json`` in the export's one-element-per-line layout
(:func:`write_memberships_snapshot`, spec 15.9), each membership encoded as it
is read from the store; the inventory files record by record in their own
layout (``collector.inventory_streaming``), every relationship read once. The
bytes are what the whole-document writers produced (locked by
``tests/unit/services/graph_build/test_sidecar_streaming.py``). Same rules as
the graph export: atomic replace, nothing written on a frozen workspace, no
secret (the store never holds one).
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Iterator, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from adscan_core.graph_store import GraphStore

#: ``memberships.json`` file name inside ``domains/<domain>/``.
MEMBERSHIPS_FILENAME = "memberships.json"
#: Inventory directory inside ``domains/<domain>/``.
INVENTORY_DIRNAME = "inventory"


def _stage_running(store: GraphStore) -> bool:
    return any(run.status == "running" for run in store.stage_runs())


def _graph_ids_by_object_id(graph: Mapping[str, Any]) -> dict[str, str]:
    """Object SID -> graph node id, from the built graph (foreign endpoints included)."""
    out: dict[str, str] = {}
    for node_id, node in (graph.get("nodes") or {}).items():
        if not isinstance(node, Mapping):
            continue
        props = node.get("properties") if isinstance(node.get("properties"), Mapping) else {}
        sid = str(node.get("objectId") or props.get("objectid") or "").strip().upper()
        if sid and sid not in out:
            out[sid] = str(node_id)
    return out


def _memberships_pieces(
    nodes: Mapping[str, Any],
    member_edges: Iterable[Any],
    graph: Mapping[str, Any],
    *,
    domain: str,
    generated_at: str,
) -> Iterator[str]:
    """``memberships.json`` for ``domain``, piece by piece, in the export layout.

    The 14.0.x content exactly (the collector's former ``_write_memberships``,
    frozen in ``tests/unit/services/graph_build/golden/legacy_persist/``):
    every collected object's graph payload keyed by its graph id, one
    ``native_ldap`` ``MemberOf`` edge per distinct (member, group), a foreign
    group as its light cross-domain endpoint node; then every runtime
    ``MemberOf`` edge of the built graph (the overlay's, ``edge_type``
    ``runtime_membership``), so the snapshot holds what ADscan proved after
    collection too.

    Streamed: the root keys go out in sorted order (``edges`` before
    ``nodes``), so each edge is encoded as it is read and each node payload is
    built only when its line is written; what is held is the graph-id index and
    the (member, group) pairs already written. ``member_edges`` are the
    collected ``MemberOf`` relationships (any iterable of ``CollectorEdge``;
    other relations are skipped).
    """
    from adscan_core.engagement.output_formats import output_marker  # noqa: PLC0415
    from adscan_internal.services import attack_graph_service  # noqa: PLC0415
    from adscan_internal.services.graph_build.export import _ENCODER  # noqa: PLC0415

    encode = _ENCODER.encode
    graph_nodes = graph.get("nodes") if isinstance(graph.get("nodes"), Mapping) else {}
    by_sid = _graph_ids_by_object_id(graph)

    # Collected objects: graph id -> SID (a later object with the same graph id
    # replaces the earlier one, as the dict assignment of 14.0.x did).
    sid_to_graph_id: dict[str, str] = {}
    collected: dict[str, str] = {}
    for sid, node in nodes.items():
        graph_id = attack_graph_service._node_id(node.to_graph_payload())  # noqa: SLF001
        if not graph_id:
            continue
        sid_to_graph_id[str(sid).upper()] = graph_id
        collected[graph_id] = sid
    # Endpoint nodes the edges add (a foreign group, a runtime member).
    extra: dict[str, dict[str, Any]] = {}

    def _edges() -> Iterator[dict[str, Any]]:
        seen: set[tuple[str, str]] = set()
        for edge in member_edges:
            if edge.relation != "MemberOf":
                continue
            from_id = sid_to_graph_id.get(edge.source_object_id.upper())
            if not from_id:
                continue
            target_sid = edge.target_object_id.upper()
            to_id = sid_to_graph_id.get(target_sid)
            if not to_id:
                # A group of another collected domain: its light endpoint node,
                # as the built graph holds it (the build resolved it through
                # the sibling stores).
                foreign_id = by_sid.get(target_sid)
                foreign = graph_nodes.get(foreign_id) if foreign_id else None
                if not isinstance(foreign, Mapping):
                    continue
                to_id = str(foreign_id)
                if to_id not in collected and to_id not in extra:
                    extra[to_id] = _light_endpoint(foreign, target_sid)
            if (from_id, to_id) in seen:
                continue
            seen.add((from_id, to_id))
            yield {
                "from": from_id,
                "to": to_id,
                "relation": edge.relation,
                "edge_type": "native_ldap",
                "status": "discovered",
                "notes": {"collector_method": edge.method},
            }
        for edge in graph.get("edges") or ():
            if not isinstance(edge, Mapping) or str(edge.get("relation") or "") != "MemberOf":
                continue
            if str(edge.get("edge_type") or "").startswith("native_"):
                continue
            from_id = str(edge.get("from") or "")
            to_id = str(edge.get("to") or "")
            if not from_id or not to_id or (from_id, to_id) in seen:
                continue
            seen.add((from_id, to_id))
            for node_id in (from_id, to_id):
                node = graph_nodes.get(node_id)
                if node_id not in collected and node_id not in extra and isinstance(node, Mapping):
                    extra[node_id] = dict(node)
            yield {
                "from": from_id,
                "to": to_id,
                "relation": "MemberOf",
                "edge_type": str(edge.get("edge_type") or "runtime"),
                "status": str(edge.get("status") or "discovered"),
                "notes": dict(edge.get("notes") or {}),
            }

    # Root keys in sorted order: domain, edges, generated_at, nodes,
    # schema_version, version (the layout of ``_document_pieces``).
    yield "{\n" + encode("domain") + ":" + encode(domain)
    yield ",\n" + encode("edges") + ":"
    wrote_edge = False
    for edge_doc in _edges():
        yield ("[\n" if not wrote_edge else ",\n") + encode(edge_doc)
        wrote_edge = True
    yield "\n]" if wrote_edge else "[]"
    yield ",\n" + encode("generated_at") + ":" + encode(generated_at)
    yield ",\n" + encode("nodes") + ":"
    node_ids = sorted(set(collected) | set(extra))
    if not node_ids:
        yield "{}"
    else:
        yield "{\n"
        for position, node_id in enumerate(node_ids):
            sid = collected.get(node_id)
            payload = nodes[sid].to_graph_payload() if sid is not None else extra[node_id]
            yield (",\n" if position else "") + encode(node_id) + ":" + encode(payload)
        yield "\n}"
    yield ",\n" + encode("schema_version") + ":" + encode(output_marker("memberships"))
    yield ",\n" + encode("version") + ":" + encode(2)
    yield "\n}\n"


def write_memberships_snapshot(
    path: str | Path,
    *,
    nodes: Mapping[str, Any],
    member_edges: Iterable[Any],
    graph: Mapping[str, Any],
    domain: str,
) -> int:
    """Write ``memberships.json`` streamed and atomically (see :func:`_memberships_pieces`).

    Returns the bytes written; 0 on a frozen workspace.
    """
    pieces = _memberships_pieces(
        nodes,
        member_edges,
        graph,
        domain=domain,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
    return _write_pieces(pieces, path)


def _light_endpoint(node: Mapping[str, Any], sid: str) -> dict[str, Any]:
    """The light cross-domain endpoint payload (``base_edges._ensure_foreign_endpoint_node``)."""
    label = str(node.get("label") or node.get("name") or sid)
    is_tier0 = bool(node.get("highvalue") or node.get("isTierZero"))
    return {
        "kind": str(node.get("kind") or "Base"),
        "label": label,
        "name": label,
        "objectId": sid,
        "highvalue": is_tier0,
        "isTierZero": is_tier0,
        "properties": {"name": label, "objectid": sid, "cross_domain_endpoint": True},
    }


def _document_pieces(document: Mapping[str, Any]) -> Any:
    """``document`` as text pieces in the export's layout: root keys sorted,
    then one node and one edge per line (the layout of ``attack_graph.json``,
    ``graph_build.export``), with the SAME encoder, so a reader parses both the
    same way and never needs the whole document as one string."""
    from adscan_internal.services.graph_build.export import _ENCODER  # noqa: PLC0415

    encode = _ENCODER.encode
    yield "{\n"
    for index, key in enumerate(sorted(document)):
        if index:
            yield ",\n"
        yield encode(key) + ":"
        value = document[key]
        if key == "edges" and isinstance(value, list) and value:
            yield "[\n"
            for position, edge in enumerate(value):
                yield (",\n" if position else "") + encode(edge)
            yield "\n]"
        elif key == "nodes" and isinstance(value, Mapping) and value:
            yield "{\n"
            for position, node_id in enumerate(sorted(value)):
                yield (",\n" if position else "") + encode(node_id) + ":" + encode(value[node_id])
            yield "\n}"
        else:
            yield encode(value)
    yield "\n}\n"


def write_streamed_document(document: Mapping[str, Any], path: str | Path) -> int:
    """Write ``document`` to ``path`` in the export layout, streamed and
    atomically (temp file, fsync, replace). Returns the bytes written; 0 on a
    frozen workspace."""
    return _write_pieces(_document_pieces(document), path)


def _write_pieces(pieces: Iterable[str], path: str | Path) -> int:
    """Write text ``pieces`` to ``path`` atomically, about 1 MiB at a time.

    The memberships snapshot's writer (spec 15.9). Its layout and encoder are
    the graph export's; the export itself stamps the attack-graph marker, which
    this document must not carry, so it has its own small driver here.
    """
    import tempfile  # noqa: PLC0415

    from adscan_core.workspace_freeze import write_blocked  # noqa: PLC0415

    destination = os.path.abspath(os.fspath(path))
    if write_blocked(destination):
        return 0
    directory = os.path.dirname(destination)
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".memberships-", suffix=".tmp")
    written = 0
    try:
        with os.fdopen(fd, "wb") as handle:
            buffer: list[str] = []
            size = 0
            for piece in pieces:
                buffer.append(piece)
                size += len(piece)
                if size >= 1 << 20:
                    data = "".join(buffer).encode("utf-8")
                    handle.write(data)
                    written += len(data)
                    buffer.clear()
                    size = 0
            data = "".join(buffer).encode("utf-8")
            handle.write(data)
            written += len(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, destination)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return written


def export_sidecars(store: GraphStore, graph: Mapping[str, Any], domain_dir: str | Path) -> None:
    """Write ``memberships.json`` and ``inventory/*.json`` of one domain from its store.

    Args:
        store: The domain's store (read only through the ``GraphStore`` interface).
        graph: The graph just exported from ``store`` (its overlay ``MemberOf``
            edges are part of ``memberships.json``; its run id stamps the
            inventory files).
        domain_dir: ``<workspace>/domains/<domain>``, the directory the graph
            was exported into (the execution workspace's during a live scan).

    A no-op while any stage of the store is running (see the module docstring),
    and on a frozen workspace. Raises on an I/O problem; the caller
    (``export_if_due``) logs it and keeps the graph export.
    """
    from adscan_core.engagement.coverage_io import ARTIFACT_RUN_ID_KEY  # noqa: PLC0415
    from adscan_core.workspace_freeze import write_blocked  # noqa: PLC0415
    from adscan_internal.services.collector.inventory_persistence import (  # noqa: PLC0415
        write_inventory_files,
    )
    from adscan_internal.services.graph_build.ingest import (  # noqa: PLC0415
        CollectedEdges,
        inventory_result_from_store,
    )

    if _stage_running(store):
        return
    domain_dir = os.fspath(domain_dir)
    memberships_path = os.path.join(domain_dir, MEMBERSHIPS_FILENAME)
    if write_blocked(memberships_path):
        return
    result = inventory_result_from_store(store)
    if not result.nodes:
        # Nothing collected yet (a store holding only a legacy import or the
        # overlay): the files a 14.0.x collector wrote stay as they are.
        return
    domain = str(store.domain)
    os.makedirs(domain_dir, exist_ok=True)
    # The snapshot first: the inventory's classification annotates the objects
    # it reads (``control_plane_sync_state``), which the snapshot never carried.
    write_memberships_snapshot(
        memberships_path,
        nodes=result.nodes,
        member_edges=CollectedEdges(store, relations=("MemberOf",)),
        graph=graph,
        domain=domain,
    )
    write_inventory_files(
        os.path.join(domain_dir, INVENTORY_DIRNAME),
        domain=domain,
        result=result,
        run_id=str(graph.get(ARTIFACT_RUN_ID_KEY) or ""),
    )


__all__ = (
    "INVENTORY_DIRNAME",
    "MEMBERSHIPS_FILENAME",
    "export_sidecars",
    "write_memberships_snapshot",
    "write_streamed_document",
)
