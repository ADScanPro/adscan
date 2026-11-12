"""What a run's artifacts say is present: the items the engagement ledger tracks.

Pure transforms from the engine's artifacts to ledger items, shared by the CLI
ledger writer and (Phase 2.6) the web ingestion, so the two decompose a run into
the same items:

* a **finding** is one catalog finding key per domain (the web's row grain);
  non-catalog keys the report also carries (posture and coverage metrics) are
  not findings, exactly as ``ingestion_service`` gates them;
* a **step** is one attack-graph edge, keyed by its stable identity (relation
  and the stable ids of both endpoints, plus what tells twins apart), with the
  web's edge fingerprint kept as ``legacy_alias`` so the two histories join.
  An exploitation edge is a ``step``; any other edge is a ``structural_step``
  (the collector owns it, ``specs.STRUCTURAL_EDGE_SPEC``).

Import-light (``adscan_core`` only): the web backend imports it.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from adscan_core.attack_graph_edge_identity import (
    attack_graph_edge_fingerprint,
    edge_identity_discriminator,
)
from adscan_core.engagement.identity import finding_id, object_id_from_node, step_id
from adscan_core.engagement.model import Observed
from adscan_core.engagement.specs import KIND_STRUCTURAL_STEP
from adscan_core.engagement.store import LedgerItem
from adscan_core.reporting.finding_vuln_map import is_catalog_finding_key


def domain_key(domain: str) -> str:
    """The coverage / ledger domain key (lowercased DNS name)."""
    return str(domain or "").strip().rstrip(".").lower()


def finding_items(report_domain: Mapping[str, Any], domain: str) -> list[LedgerItem]:
    """Catalog findings a report's domain entry carries, one item per key."""
    domain_id = domain_key(domain)
    raw = report_domain.get("findings") if isinstance(report_domain, Mapping) else None
    items: dict[str, LedgerItem] = {}
    for finding in raw if isinstance(raw, list) else []:
        if not isinstance(finding, Mapping):
            continue
        key = str(finding.get("key") or "").strip()
        if not key or not is_catalog_finding_key(key):
            continue
        item_id = finding_id(key, domain_id)
        items.setdefault(
            item_id,
            LedgerItem(
                item_id=item_id,
                kind="finding",
                key=key,
                domain_id=domain_id,
                label=str(finding.get("title") or key),
                legacy_alias=key,
            ),
        )
    return [items[k] for k in sorted(items)]


def _endpoint(raw: Mapping[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = raw.get(key)
        if value:
            return str(value).strip()
    return ""


def _host_object_id(*nodes: Optional[Mapping[str, Any]]) -> Optional[str]:
    """The computer a host-scoped edge sits on (target first), as coverage names it."""
    for node in nodes:
        if not isinstance(node, Mapping) or str(node.get("kind") or "").lower() != "computer":
            continue
        oid = object_id_from_node(node)
        if not oid.startswith(("unresolved:", "synthetic:", "guid:", "wk:")):
            return oid
    return None


def step_object_id(
    source_node: Optional[Mapping[str, Any]],
    target_node: Optional[Mapping[str, Any]],
    *,
    target_ref: str = "",
) -> str:
    """The ledger ``object_id`` of one edge's step item (the ONE rule).

    The computer the edge sits on (target first, then source), else the
    target's stable object id. The ledger writer and the recheck observers
    both use it, so a re-read names a step exactly as the scan recorded it.
    """
    return _host_object_id(target_node, source_node) or object_id_from_node(
        target_node or {"id": target_ref}
    )


def step_item_id(
    relation: str,
    source_node: Optional[Mapping[str, Any]],
    target_node: Optional[Mapping[str, Any]],
    notes: Any,
    domain: str,
    *,
    source_ref: str = "",
    target_ref: str = "",
) -> str:
    """Stable step id of one edge: what the CLI ledger and the web both store.

    ``source_ref`` / ``target_ref`` are the graph node ids, used for the
    explicit ``unresolved:`` bucket when the node itself is missing.
    """
    source_oid = object_id_from_node(source_node or {"id": source_ref})
    target_oid = object_id_from_node(target_node or {"id": target_ref})
    discriminator = edge_identity_discriminator(relation, notes if isinstance(notes, Mapping) else {})
    return step_id(relation, source_oid, target_oid, discriminator, domain=domain_key(domain))


def step_items(graph: Mapping[str, Any], domain: str) -> list[LedgerItem]:
    """Every edge of one domain's ``attack_graph.json``, one item per stable step."""
    domain_id = domain_key(domain)
    nodes = graph.get("nodes") if isinstance(graph, Mapping) else None
    edges = graph.get("edges") if isinstance(graph, Mapping) else None
    if not isinstance(nodes, Mapping) or not isinstance(edges, list):
        return []
    items: dict[str, LedgerItem] = {}
    for raw in edges:
        if not isinstance(raw, Mapping):
            continue
        source = _endpoint(raw, ("from", "source_node", "source"))
        target = _endpoint(raw, ("to", "target_node", "target"))
        relation = _endpoint(raw, ("relation", "edge_type", "type", "label"))
        if not source or not target or not relation:
            continue
        notes = raw.get("notes") if isinstance(raw.get("notes"), Mapping) else {}
        source_node = nodes.get(source) if isinstance(nodes.get(source), Mapping) else None
        target_node = nodes.get(target) if isinstance(nodes.get(target), Mapping) else None
        item_id = step_item_id(
            relation, source_node, target_node, notes, domain_id,
            source_ref=source, target_ref=target,
        )
        kind = "step" if raw.get("category") == "exploitation" else KIND_STRUCTURAL_STEP
        label_source = (source_node or {}).get("label") or source
        label_target = (target_node or {}).get("label") or target
        items.setdefault(
            item_id,
            LedgerItem(
                item_id=item_id,
                kind=kind,
                key=relation,
                domain_id=domain_id,
                object_id=step_object_id(source_node, target_node, target_ref=target),
                label=f"{label_source} -> {relation} -> {label_target}",
                legacy_alias=attack_graph_edge_fingerprint(source, relation, target, dict(notes)),
            ),
        )
    return [items[k] for k in sorted(items)]


def observed(items: list[LedgerItem]) -> list[Observed]:
    """The reconciliation view of present items."""
    return [Observed(i.item_id, i.kind, i.key, i.domain_id, i.object_id) for i in items]


__all__ = (
    "domain_key",
    "finding_items",
    "observed",
    "step_item_id",
    "step_items",
    "step_object_id",
)
