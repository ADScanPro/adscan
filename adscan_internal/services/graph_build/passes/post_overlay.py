"""The passes that run AFTER the runtime overlay, and the graph's root stamps.

These depend on edge statuses or on the whole edge set, so they run once the
overlay is applied, in the build and again whenever the runtime facade patches
the live graph (``api.run_post_overlay_passes``). They are what
``attack_graph_service.save_attack_graph`` ran on every write in 14.0.x, plus the
privilege-tier backfill ``attack_graph_core.load_attack_graph`` ran on every
read, called through their single implementations:

1. the engine follow-up edges (``attack_graph_core.materialize_engine_followup_edges``);
2. the foreign-DC role markers from the recorded DC inventory
   (``attack_graph_core.enrich_foreign_dc_nodes_from_inventory``), then the
   membership-aware privilege-tier stamp of any node that lacks one
   (synthetic, foreign-endpoint and overlay nodes; collected nodes are stamped
   when they are built);
3. edge classification (``attack_graph_service.classify_graph_edges``);
4. the Tier-0-source prune;
5. the AD CS display contract (``attack_graph_findings.stamp_adcs_edge_display_contract``);
6. no technique text on an edge (``attack_graph.json`` format 2: it is rendered
   when read, by ``edge_knowledge``);
7. stable edge order ``(from, relation, to)`` and node-id order.

Every step is idempotent, so running them twice equals running them once.
Secret redaction is not a step: the store never holds a secret (the write seam
redacts before a record exists), so the graph built from it holds none either.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from adscan_internal.services import attack_graph_core, attack_graph_service


def _sort_key(edge: Any) -> tuple[str, str, str]:
    if not isinstance(edge, dict):
        return ("", "", "")
    return (str(edge.get("from", "")), str(edge.get("relation", "")), str(edge.get("to", "")))


def run_post_overlay(
    graph: dict[str, Any], *, domains_data: Mapping[str, Mapping[str, Any]]
) -> dict[str, int]:
    """Run the post-overlay passes on ``graph`` in place; returns per-step counts.

    ``domains_data`` is every domain's recorded facts (the build context's
    ``domains_data_for_passes()``), not this domain's entry alone: the AD CS
    display contract reads the trusts recorded on both ends of an edge.
    """
    from adscan_internal.services.attack_graph_findings import (  # noqa: PLC0415
        stamp_adcs_edge_display_contract,
    )

    counts: dict[str, int] = {}
    # Stable order first: the follow-up derivation picks a step's parent by edge
    # order, so a live graph (ops appended to a sorted graph) and a rebuilt one
    # must present the same order to it.
    sort_edges(graph)
    added, removed = attack_graph_core.materialize_engine_followup_edges(graph)
    counts["engine_followups_added"] = added
    counts["engine_followups_removed"] = removed
    # The foreign-DC role marker (and the trusted domain's Domain node) from the
    # recorded DC inventory of every domain: part of the build, so the export is
    # a function of the store and the context alone. Before the tier stamp, as
    # the store-less read path orders it.
    counts["foreign_dcs_marked"] = int(
        bool(attack_graph_core.enrich_foreign_dc_nodes_from_inventory(graph, domains_data))
    )
    attack_graph_core._backfill_privilege_tier(graph)  # noqa: SLF001
    counts["classified"] = attack_graph_service.classify_graph_edges(graph)
    counts["tier0_source_pruned"] = attack_graph_service._prune_tier0_source_attack_edges(  # noqa: SLF001
        graph
    )
    attack_graph_service._flush_tier0_source_attack_edge_skip_summary(graph)  # noqa: SLF001
    counts["adcs_display_stamped"] = stamp_adcs_edge_display_contract(
        graph, {str(name): dict(entry) for name, entry in (domains_data or {}).items()}
    )
    counts["knowledge_dropped"] = attack_graph_core.drop_format1_edge_knowledge(graph)
    sort_edges(graph)
    sort_nodes(graph)
    return counts


def sort_nodes(graph: dict[str, Any]) -> None:
    """Node map in node-id order: the order the exported file holds (its keys
    are sorted), so the in-memory graph and a reload of the export present the
    same order to the path engine, whose representative choice among equal
    routes follows node order."""
    nodes = graph.get("nodes")
    if isinstance(nodes, dict):
        graph["nodes"] = dict(sorted(nodes.items()))


def sort_edges(graph: dict[str, Any]) -> None:
    """Stable ``(from, relation, to)`` edge order (ties keep their order)."""
    edges = graph.get("edges")
    if isinstance(edges, list):
        graph["edges"] = sorted(edges, key=_sort_key)


def stamp_graph_coordinates(
    graph: dict[str, Any], *, domain: str, domain_data: Mapping[str, Any] | None
) -> None:
    """Stamp the graph-level coordinates a command is filled with.

    ``dc_ip`` (``resolve_dc_ip``), ``netbios``, ``dc_fqdn`` (``resolve_dc_fqdn``),
    the account the scan authenticated as, and the certificate authority's name
    and host. None of them is a secret. The same values and rules as
    ``save_attack_graph``'s stamp; best-effort, a missing value leaves the field
    unset and the renderers degrade to a fill-in token.
    """
    entry = domain_data if isinstance(domain_data, Mapping) else None
    if not entry:
        return
    try:
        from adscan_internal.models.domain import (  # noqa: PLC0415
            resolve_dc_fqdn,
            resolve_dc_ip,
        )

        entry_dict = dict(entry)
        resolved_dc_ip = resolve_dc_ip(entry_dict)
        if resolved_dc_ip:
            graph["dc_ip"] = resolved_dc_ip
        netbios = str(entry_dict.get("netbios") or "").strip()
        if netbios:
            graph["netbios"] = netbios
        dc_fqdn = resolve_dc_fqdn(entry_dict, target_domain=domain)
        if dc_fqdn:
            graph["dc_fqdn"] = dc_fqdn
        scan_principal = str(entry_dict.get("username") or "").strip()
        if scan_principal:
            graph["scan_principal"] = scan_principal
        ca_name = str(entry_dict.get("ca") or "").strip()
        ca_host = str(entry_dict.get("adcs_fqdn") or entry_dict.get("adcs") or "").strip()
        if ca_name and isinstance(entry_dict.get("ca"), str):
            graph["ca_name"] = ca_name
        if ca_host and "." in ca_host:
            graph["ca_host"] = ca_host.lower()
    except Exception:  # noqa: BLE001 - never break the build over an enrichment
        return


__all__ = (
    "run_post_overlay",
    "sort_edges",
    "sort_nodes",
    "stamp_graph_coordinates",
)
