"""Helpers shared by the derivation passes (bodies moved from ``collector/persistence.py``)."""

from __future__ import annotations

from typing import Any

from adscan_internal.services import attack_graph_service


def _upsert_derived_edge(
    graph: dict[str, Any],
    *,
    from_id: str,
    to_id: str,
    relation: str,
    notes: dict[str, Any],
    edge_index: "attack_graph_service.EdgeUpsertIndex",
) -> int:
    edge = attack_graph_service.upsert_edge(
        graph,
        index=edge_index,
        from_id=from_id,
        to_id=to_id,
        relation=relation,
        edge_type="native_derived",
        status="discovered",
        notes=notes,
        log_creation=False,
    )
    return 1 if edge else 0


def _node_bool_property(node: Any, key: str) -> bool:
    return bool(node.properties.get(key))


def _node_list_property(node: Any, key: str) -> list[str]:
    value = node.properties.get(key)
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []
