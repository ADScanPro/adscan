"""Writable-GPO filter — graph-driven replacement for the legacy LDAP discovery.

This module replaces ``gpo_writable_discovery_service`` (deleted). Discovery of
``groupPolicyContainer`` objects, their ACL trustees, and the ``GPLink`` edges
that ground them in OUs/sites/the domain root is performed by the **native
LDAP collector** (`adscan_internal.services.collector.ldap_collector`) and
persisted as part of ``attack_graph.json``. This module is the thin filter
that surfaces the GPOs a given attacker principal can mutate sufficiently
to plant an Immediate Scheduled Task.

It is intentionally I/O-light:

* Reads `attack_graph.json` (or accepts an in-memory graph dict) once.
* Walks ``MemberOf`` edges to compute the principal's effective SID set
  (transitive group membership), so we do not re-issue ``tokenGroups``.
* Filters ACL edges with ``target_kind == "GPO"`` and
  ``relation ∈ {GenericAll, GenericWrite, WriteDACL, WriteOwner}`` whose
  ``source_object_id`` is one of the effective SIDs.
* Joins the resulting GPOs with their ``GPLink`` edges to enumerate
  linked SOMs, descendant Computer/User nodes, and Tier-0 reach.

Vendor / collector verification (read before writing):

* ``adscan_internal/services/collector/ldap_collector.py:32`` —
  ``LDAPCollectionScope.gpos = True`` is on by default and triggers GPC
  discovery.
* ``adscan_internal/services/collector/ldap_collector.py:666`` — every
  ``groupPolicyContainer`` is emitted as ``CollectorNode(kind="GPO",
  object_id=<GUID>)``.
* ``adscan_internal/services/collector/ldap_collector.py:1158`` — the
  collector reads ``nTSecurityDescriptor`` with
  ``SD_FLAGS_DACL_CONTROL`` and feeds it to :class:`ACLParser`.
* ``adscan_internal/services/collector/acl_parser.py:31`` — ACL parser
  emits ``relation ∈ {GenericAll, GenericWrite, WriteDACL,
  WriteOwner}`` (plus refined object-ACE relations) for every applicable
  ACE.
* ``adscan_internal/services/collector/ldap_collector.py:1287`` —
  ``_collect_gpo_links()`` emits ``GPLink`` edges shaped
  ``GPO -> SOM`` (source = GPO GUID, target = container_id).
* ``adscan_internal/services/collector/ldap_collector.py:1276`` —
  ``MemberOf`` edges shaped ``member -> group``.
* ``adscan_internal/services/attack_graph_service.py:6907`` —
  persisted edges carry ``from`` / ``to`` (graph node ids) and
  ``relation``. Node ids are derived from ``objectId``; the GPO node id
  is the uppercased GUID.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from adscan_core.rich_output import print_info_debug, print_info_verbose
from adscan_internal import telemetry
from adscan_core.rich_output import print_exception


# ACL relations the GPO Immediate Scheduled Task technique can leverage.
# Per acl_parser.py, these are the only generic-mask relations the collector
# emits for whole-object ACEs targeting a ``groupPolicyContainer``. ACEs
# scoped to a specific property GUID (e.g. ``WriteProperty:gPCFileSysPath``)
# are intentionally out of scope here — the catalog covers them separately
# via the per-property relation entries and they require a dedicated
# exploit chain, not the generic plant.
_GPO_ABUSE_RELATIONS: frozenset[str] = frozenset(
    {"genericall", "genericwrite", "writedacl", "writeowner"}
)


# ---------------------------------------------------------------------------
# Public dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WritableGPOCandidate:
    """A GPO the principal can mutate enough to plant an Immediate Task.

    Field shape is the canonical one consumed by the wizard
    (`adscan_internal.cli.gpo_abuse_handler`) and the GOAD harness
    (`tests.lab.cases.gpo.goad_native`). All collections are tuples to keep
    the dataclass hashable and safe to pass through async boundaries.
    """

    gpo_object_id: str  # upper-case GUID (collector node objectId)
    gpo_dn: str
    display_name: str
    gpc_path: str
    granted_rights: tuple[str, ...]  # subset of {GenericAll, ...}
    via_principals: tuple[str, ...]  # SIDs whose ACE granted the right
    linked_soms: tuple[str, ...]  # OU/Site/Domain DNs from GPLink edges
    affected_computers: tuple[str, ...] = field(default_factory=tuple)
    affected_users: tuple[str, ...] = field(default_factory=tuple)
    touches_tier0: bool = False


# ---------------------------------------------------------------------------
# Graph helpers — no network, no LDAP
# ---------------------------------------------------------------------------


def _index_nodes(graph: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return ``{node_id: node_dict}`` for any graph schema variant.

    The collector persists nodes via ``attack_graph_service.upsert_nodes``
    using a dict keyed by the canonical id. Older variants store nodes as
    a list. Handle both.
    """
    nodes_field = graph.get("nodes")
    if isinstance(nodes_field, dict):
        return {str(nid): n for nid, n in nodes_field.items() if isinstance(n, dict)}
    if isinstance(nodes_field, list):
        out: dict[str, dict[str, Any]] = {}
        for item in nodes_field:
            if not isinstance(item, dict):
                continue
            nid = str(
                item.get("id")
                or item.get("node_id")
                or item.get("objectId")
                or item.get("objectid")
                or ""
            )
            if nid:
                out[nid] = item
        return out
    return {}


def _node_object_id(node: dict[str, Any]) -> str:
    raw = (
        node.get("objectId")
        or node.get("objectid")
        or (node.get("properties") or {}).get("objectid")
        or ""
    )
    return str(raw).strip().upper()


def _node_kind(node: dict[str, Any]) -> str:
    return str(node.get("kind") or node.get("type") or "").strip()


def _node_dn(node: dict[str, Any]) -> str:
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    return str(
        node.get("distinguishedname")
        or node.get("distinguished_name")
        or props.get("distinguishedname")
        or props.get("distinguished_name")
        or ""
    )


def _node_label(node: dict[str, Any]) -> str:
    return str(
        node.get("label")
        or node.get("name")
        or (node.get("properties") or {}).get("name")
        or ""
    )


def _is_tier0_node(node: dict[str, Any]) -> bool:
    """Return True when the node is marked Tier-0 / high-value."""
    if bool(node.get("isTierZero") or node.get("highvalue")):
        return True
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    if bool(props.get("isTierZero") or props.get("highvalue")):
        return True
    tags = props.get("system_tags")
    if isinstance(tags, str) and "admin_tier_0" in tags.lower():
        return True
    if isinstance(tags, list) and any(
        "admin_tier_0" in str(tag).lower() for tag in tags
    ):
        return True
    return False


def _is_dc_ou(dn: str) -> bool:
    return "ou=domain controllers" in str(dn or "").casefold()


def _edge_endpoint(edge: dict[str, Any], side: str) -> str:
    """Return the canonical endpoint id for ``side`` ('from'|'to')."""
    if side == "from":
        return str(edge.get("from") or edge.get("source") or "").strip()
    return str(edge.get("to") or edge.get("target") or "").strip()


def _normalize_relation(rel: str) -> str:
    return str(rel or "").strip().lower()


# ---------------------------------------------------------------------------
# Effective-SID resolution (no tokenGroups round-trip)
# ---------------------------------------------------------------------------


def _resolve_principal_node(
    nodes: dict[str, dict[str, Any]], principal: str
) -> dict[str, Any] | None:
    """Find a User node that matches the principal SID / sAMAccountName / UPN."""
    target = str(principal or "").strip()
    if not target:
        return None
    target_upper = target.upper()
    target_sam = target.split("@", 1)[0].lower() if "@" in target else target.lower()
    for node in nodes.values():
        kind = _node_kind(node)
        if kind not in ("User", "Computer"):
            continue
        oid = _node_object_id(node)
        if oid and oid == target_upper:
            return node
        props = (
            node.get("properties") if isinstance(node.get("properties"), dict) else {}
        )
        sam = str(
            node.get("samaccountname") or props.get("samaccountname") or ""
        ).lower()
        if sam and sam == target_sam:
            return node
        label = _node_label(node).lower()
        if label and (label == target.lower() or label.split("@", 1)[0] == target_sam):
            return node
    return None


def _walk_member_of(
    *,
    start_node_ids: set[str],
    edges_by_source: dict[str, list[dict[str, Any]]],
) -> set[str]:
    """Return the closure of ``start_node_ids`` under ``MemberOf`` edges."""
    visited: set[str] = set(start_node_ids)
    stack: list[str] = list(start_node_ids)
    while stack:
        current = stack.pop()
        for edge in edges_by_source.get(current, ()):
            if _normalize_relation(edge.get("relation")) != "memberof":
                continue
            nxt = _edge_endpoint(edge, "to")
            if nxt and nxt not in visited:
                visited.add(nxt)
                stack.append(nxt)
    return visited


def _node_ids_to_object_ids(
    node_ids: Iterable[str], nodes: dict[str, dict[str, Any]]
) -> set[str]:
    out: set[str] = set()
    for nid in node_ids:
        node = nodes.get(nid)
        if not node:
            continue
        oid = _node_object_id(node)
        if oid:
            out.add(oid)
    return out


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _attack_graph_path(workspace_dir: Path, domain: str) -> Path:
    """Return the canonical path for one domain's ``attack_graph.json``.

    Mirrors :func:`adscan_internal.services.attack_graph_derived._attack_graph_path`
    without taking a dependency on the shell object — the filter accepts a
    plain workspace dir to keep it usable from non-shell contexts (lab harness,
    web backend).
    """
    return Path(workspace_dir) / "domains" / domain / "attack_graph.json"


def _load_graph(workspace_dir: Path, domain: str) -> dict[str, Any]:
    path = _attack_graph_path(workspace_dir, domain)
    if not path.exists():
        return {"nodes": {}, "edges": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[gpo-filter] failed to load {path}: {exc}")
        return {"nodes": {}, "edges": []}
    if not isinstance(data, dict):
        return {"nodes": {}, "edges": []}
    return data


async def discover_writable_gpos(
    *,
    workspace_dir: Path | str | None = None,
    domain: str | None = None,
    graph: dict[str, Any] | None = None,
    principal_sid: str | None = None,
    principal: str | None = None,
    include_unlinked: bool = False,
) -> list[WritableGPOCandidate]:
    """Return GPOs that ``principal`` can mutate enough to plant an Immediate Task.

    Args:
        workspace_dir: Workspace path containing ``domains/<domain>/attack_graph.json``.
            Mutually exclusive with ``graph``.
        domain: Domain name (used to locate ``attack_graph.json``). Required
            when ``workspace_dir`` is provided.
        graph: In-memory attack graph dict (produced by the collector). When
            provided, ``workspace_dir`` / ``domain`` are ignored. This is the
            path the lab harness uses after running the collector inline.
        principal_sid: Pre-resolved attacker SID. When omitted, ``principal``
            is resolved against the graph node set.
        principal: Attacker identifier (sAMAccountName / UPN / SID). Used to
            seed the effective-SID walk if ``principal_sid`` is not given.
        include_unlinked: Include GPOs not linked to any SOM (default False).

    Returns:
        List of :class:`WritableGPOCandidate` (possibly empty). Tier-0 reach
        is computed from linked SOMs (``OU=Domain Controllers``, the domain
        root) and from descendant Computer/User nodes flagged ``isTierZero``.
    """
    # ── 1. Load the graph (already-collected, no LDAP I/O here) ────────────
    if graph is None:
        if workspace_dir is None or not domain:
            raise ValueError(
                "discover_writable_gpos: pass either graph= or both "
                "workspace_dir= and domain="
            )
        graph = _load_graph(Path(workspace_dir), domain)

    nodes = _index_nodes(graph)
    edges_raw = graph.get("edges") or []
    if not isinstance(edges_raw, list):
        edges_raw = []
    edges: list[dict[str, Any]] = [e for e in edges_raw if isinstance(e, dict)]

    if not nodes or not edges:
        print_info_verbose(
            "[gpo-filter] graph empty or no edges — run the LDAP collector first"
        )
        return []

    # Index edges by source node id for fast MemberOf walks.
    edges_by_source: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        src = _edge_endpoint(edge, "from")
        if src:
            edges_by_source.setdefault(src, []).append(edge)

    # ── 2. Resolve the attacking principal and its effective SIDs ──────────
    principal_sid_norm = (principal_sid or "").strip().upper()
    principal_node: dict[str, Any] | None = None
    if principal_sid_norm:
        for node in nodes.values():
            if _node_object_id(node) == principal_sid_norm:
                principal_node = node
                break
    if principal_node is None and principal:
        principal_node = _resolve_principal_node(nodes, principal)
        if principal_node is not None:
            principal_sid_norm = _node_object_id(principal_node)

    if not principal_sid_norm:
        print_info_debug(
            "[gpo-filter] could not resolve principal to a SID in the graph"
        )
        return []

    # MemberOf walk on graph node ids, then translate to objectIds.
    start_node_ids: set[str] = set()
    if principal_node is not None:
        for nid, node in nodes.items():
            if node is principal_node:
                start_node_ids.add(nid)
                break
    if not start_node_ids:
        # Fall back to "any node whose objectId == principal SID".
        for nid, node in nodes.items():
            if _node_object_id(node) == principal_sid_norm:
                start_node_ids.add(nid)

    member_of_node_ids = _walk_member_of(
        start_node_ids=start_node_ids,
        edges_by_source=edges_by_source,
    )
    effective_sids: set[str] = _node_ids_to_object_ids(member_of_node_ids, nodes)
    effective_sids.add(principal_sid_norm)

    # Build a graph-id → objectId map so we can match ACL edges (whose
    # endpoints are graph ids) against effective SIDs (objectIds).
    nid_to_oid: dict[str, str] = {
        nid: _node_object_id(node) for nid, node in nodes.items()
    }
    oid_to_nid: dict[str, str] = {oid: nid for nid, oid in nid_to_oid.items() if oid}

    # ── 3. Filter ACL edges targeting GPOs the principal controls ──────────
    candidates_by_oid: dict[str, dict[str, Any]] = {}
    for edge in edges:
        rel = _normalize_relation(edge.get("relation"))
        if rel not in _GPO_ABUSE_RELATIONS:
            continue
        target_nid = _edge_endpoint(edge, "to")
        target_node = nodes.get(target_nid)
        if not target_node or _node_kind(target_node) != "GPO":
            continue
        source_oid = nid_to_oid.get(_edge_endpoint(edge, "from"), "").upper()
        if source_oid not in effective_sids:
            continue
        target_oid = _node_object_id(target_node)
        if not target_oid:
            continue
        bucket = candidates_by_oid.setdefault(
            target_oid,
            {
                "node": target_node,
                "rights": set(),
                "via": set(),
            },
        )
        # Preserve the canonical (capitalized) relation name from the catalog.
        bucket["rights"].add(_canonical_relation(rel))
        if source_oid:
            bucket["via"].add(source_oid)

    if not candidates_by_oid:
        return []

    # ── 4. Resolve linked SOMs and descendant principals via GPLink ────────
    # Build OU descendant index (DN-prefix → list of (kind, dn)).
    ou_descendants: dict[str, list[tuple[str, str, dict[str, Any]]]] = {}
    for node in nodes.values():
        kind = _node_kind(node)
        if kind not in ("User", "Computer"):
            continue
        dn = _node_dn(node)
        if not dn:
            continue
        # Group by every parent OU/container DN suffix.
        parts = dn.split(",", 1)
        if len(parts) == 2:
            parent = parts[1].strip()
            ou_descendants.setdefault(parent.casefold(), []).append((kind, dn, node))

    domain_root_dn_cf = ""
    for node in nodes.values():
        if _node_kind(node) == "Domain":
            dn = _node_dn(node)
            if dn:
                domain_root_dn_cf = dn.casefold()
                break

    results: list[WritableGPOCandidate] = []
    for gpo_oid, bucket in candidates_by_oid.items():
        target_node = bucket["node"]
        gpo_nid = oid_to_nid.get(gpo_oid, "")
        # Linked SOMs come from GPLink edges with source=GPO.
        linked_soms: list[str] = []
        linked_som_nids: list[str] = []
        for edge in edges_by_source.get(gpo_nid, ()):
            if _normalize_relation(edge.get("relation")) != "gplink":
                continue
            som_nid = _edge_endpoint(edge, "to")
            som_node = nodes.get(som_nid)
            if som_node is None:
                continue
            som_dn = _node_dn(som_node)
            if som_dn:
                linked_soms.append(som_dn)
                linked_som_nids.append(som_nid)

        if not include_unlinked and not linked_soms:
            continue

        # Descendant principals across all linked SOMs.
        affected_computers: set[str] = set()
        affected_users: set[str] = set()
        touches_tier0 = False
        for som_dn in linked_soms:
            cf = som_dn.casefold()
            # Direct descendants of this SOM.
            for kind, dn, node in ou_descendants.get(cf, ()):
                label = _node_label(node) or dn
                if kind == "Computer":
                    affected_computers.add(label)
                elif kind == "User":
                    affected_users.add(label)
                if _is_tier0_node(node):
                    touches_tier0 = True
            if _is_dc_ou(som_dn) or (domain_root_dn_cf and cf == domain_root_dn_cf):
                touches_tier0 = True

        # GPO itself flagged Tier-0 (rare but possible if the collector tags it).
        if _is_tier0_node(target_node):
            touches_tier0 = True

        gpc_path = ""
        props = (
            target_node.get("properties")
            if isinstance(target_node.get("properties"), dict)
            else {}
        )
        for key in ("gpcfilesyspath", "gPCFileSysPath", "gpc_path"):
            value = props.get(key)
            if value:
                gpc_path = str(value)
                break
        if not gpc_path:
            # Fallback: reconstruct the canonical SYSVOL UNC. The collector
            # does not currently emit gPCFileSysPath into the graph, but the
            # path is deterministic given (domain, GPO name/CN with braces).
            domain_fqdn = str(props.get("domain") or "").strip().lower()
            cn_name = str(props.get("name") or "").strip()
            if not cn_name:
                # Derive {GUID} from the DN if name is missing.
                dn = _node_dn(target_node)
                if dn.startswith("CN={"):
                    end = dn.find("}")
                    if end > 0:
                        cn_name = dn[3:end + 1]
            if domain_fqdn and cn_name:
                gpc_path = (
                    f"\\\\{domain_fqdn}\\SysVol\\{domain_fqdn}\\Policies\\{cn_name}"
                )

        results.append(
            WritableGPOCandidate(
                gpo_object_id=gpo_oid,
                gpo_dn=_node_dn(target_node),
                display_name=_node_label(target_node),
                gpc_path=gpc_path,
                granted_rights=tuple(sorted(bucket["rights"])),
                via_principals=tuple(sorted(bucket["via"])),
                linked_soms=tuple(linked_soms),
                affected_computers=tuple(sorted(affected_computers)),
                affected_users=tuple(sorted(affected_users)),
                touches_tier0=touches_tier0,
            )
        )

    results.sort(key=lambda c: (not c.touches_tier0, c.display_name.lower()))
    return results


def _canonical_relation(relation_lower: str) -> str:
    """Return the canonical (capitalized) relation name for the given lowercase form."""
    return {
        "genericall": "GenericAll",
        "genericwrite": "GenericWrite",
        "writedacl": "WriteDACL",
        "writeowner": "WriteOwner",
    }.get(relation_lower, relation_lower)


__all__ = [
    "WritableGPOCandidate",
    "discover_writable_gpos",
]
