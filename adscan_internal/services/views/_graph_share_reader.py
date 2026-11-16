"""Read per-share ACL data from a domain's ``attack_graph.json``.

The native share collector (``services/collector/share_collector.py``)
writes:

* ``Computer`` node ``properties.smb_shares`` — list of share names.
* Edges with ``relation in {"ReadShare","WriteShare","FullControlShare"}``,
  source object id = principal SID, target = computer object id, and
  ``notes={"share_name": ..., "sd_source": ..., "verification": ...}``.

This module is a pure reader — it loads the JSON, finds the Computer node
matching a host (by DNS hostname, IP, or NetBIOS name), and returns a
per-share principal-by-principal ACL view. No network, no side effects.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from adscan_internal.services.collector.share_ntfs_verification import (
    VERIFICATION_NTFS_COMPUTED,
    VERIFICATION_SELF_MXAC,
    VERIFICATION_SHARE_ACL_ONLY,
    effective_mask_relations,
)


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


@dataclass
class GraphSharePrincipal:
    """One principal entry on a share's ACL as recorded in the graph."""

    sid: str
    name: str          # e.g. "Domain Users@LAB.LOCAL", "alice", "DC01$"
    kind: str          # "User" | "Group" | "Computer" | ""
    permissions: List[str] = field(default_factory=list)  # READ/WRITE/FULL_CONTROL

    def to_dict(self) -> dict:
        return {
            "sid": self.sid,
            "name": self.name,
            "kind": self.kind,
            "permissions": list(self.permissions),
        }


@dataclass
class GraphShareACL:
    """ACL view of one share as last collected by the share collector."""

    share_name: str
    principals: List[GraphSharePrincipal] = field(default_factory=list)
    # srvsvc502 (share permissions) / smb2_path_root (root folder NTFS DACL,
    # read when level 502 is refused) / registry / unavailable
    sd_source: str = "unknown"
    # NTFS-aware effective-access verification tier (the strongest tier seen
    # across the share's edges). ``ntfs_computed`` means the graph access was
    # confirmed against the NTFS folder ACL (share ∩ NTFS); ``share_acl_only``
    # means it is share-ACL-only and NTFS-unverified. Default is the
    # conservative ``share_acl_only`` for back-compat with graphs collected
    # before this tag existed.
    verification: str = VERIFICATION_SHARE_ACL_ONLY

    @property
    def is_ntfs_verified(self) -> bool:
        """True when the share's access was confirmed against the NTFS ACL."""
        return self.verification in (
            VERIFICATION_NTFS_COMPUTED,
            VERIFICATION_SELF_MXAC,
        )

    def to_dict(self) -> dict:
        return {
            "share_name": self.share_name,
            "sd_source": self.sd_source,
            "verification": self.verification,
            "is_ntfs_verified": self.is_ntfs_verified,
            "principals": [p.to_dict() for p in self.principals],
        }


@dataclass
class GraphShareSnapshot:
    """All shares collected for one host."""

    host: str
    computer_object_id: str
    shares: Dict[str, GraphShareACL] = field(default_factory=dict)
    collected_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "computer_object_id": self.computer_object_id,
            "collected_at": self.collected_at.isoformat() if self.collected_at else None,
            "shares": {k: v.to_dict() for k, v in self.shares.items()},
        }


# ---------------------------------------------------------------------------
# Edge relation → permission label map
# ---------------------------------------------------------------------------


_RELATION_TO_PERMISSION = {
    "ReadShare": "READ",
    "WriteShare": "WRITE",
    "FullControlShare": "FULL_CONTROL",
}

# Verification tier strength ranking (higher = stronger evidence). Used to keep
# the strongest tier seen across a share's edges.
_VERIFICATION_RANK = {
    VERIFICATION_SHARE_ACL_ONLY: 0,
    VERIFICATION_NTFS_COMPUTED: 1,
    VERIFICATION_SELF_MXAC: 2,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_graph_share_snapshot(
    *, graph_path: str, host: str
) -> Optional[GraphShareSnapshot]:
    """Load ``attack_graph.json`` and extract share ACLs for ``host``.

    Args:
        graph_path: Absolute path to a domain's ``attack_graph.json``.
        host: Hostname or IP to look up. Matched against the Computer
            node's ``dnshostname``, ``ip_address``, or NetBIOS ``name``
            (case-insensitive, with/without ``$`` suffix).

    Returns:
        :class:`GraphShareSnapshot` if a matching computer + at least one
        share record is found. ``None`` if the graph file does not exist,
        is unreadable, or contains no matching host.
    """
    graph = _load_graph(graph_path)
    if graph is None:
        return None

    nodes = _index_nodes(graph)
    computer = _find_computer(nodes.values(), host)
    if computer is None:
        return None

    snapshot = GraphShareSnapshot(
        host=host,
        computer_object_id=str(computer.get("object_id") or "").upper(),
        collected_at=_resolve_collected_at(graph, computer),
    )

    share_names = list(computer.get("properties", {}).get("smb_shares") or [])
    shares: Dict[str, GraphShareACL] = {
        name: GraphShareACL(share_name=name)
        for name in share_names
        if name
    }

    target_oid = snapshot.computer_object_id
    for edge in graph.get("edges", []) or []:
        if str(edge.get("target_object_id", "")).upper() != target_oid:
            continue
        relation = edge.get("relation")
        permission = _RELATION_TO_PERMISSION.get(relation)
        if permission is None:
            continue
        notes = edge.get("notes") or {}
        share_name = (notes.get("share_name") or "").strip()
        if not share_name:
            continue

        acl = shares.setdefault(share_name, GraphShareACL(share_name=share_name))
        # First non-default ``sd_source`` wins. The collector emits one edge
        # per (principal, relation) for the same share, all with the same
        # ``sd_source`` from the same SD lookup, so first-wins is stable
        # across edge ordering.
        if acl.sd_source in {"unknown", "unavailable"} and notes.get("sd_source"):
            acl.sd_source = notes["sd_source"]

        # Verification tier: keep the STRONGEST tier seen across the share's
        # edges (a single ntfs_computed edge means the NTFS ACL was read).
        edge_verification = str(notes.get("verification") or "").strip()
        if edge_verification in _VERIFICATION_RANK:
            if _VERIFICATION_RANK[edge_verification] > _VERIFICATION_RANK.get(
                acl.verification, -1
            ):
                acl.verification = edge_verification

        sid = str(edge.get("source_object_id", "")).strip().upper()
        principal_node = nodes.get(sid)
        principal = _find_or_create_principal(acl.principals, sid, principal_node)
        # When the edge is VERIFIED (ntfs_computed or self_mxac) and carries an
        # effective mask, the principal's real permissions are that mask — NOT the
        # raw share-grant relation. A share grant (e.g. Authenticated Users: Full
        # Control on NETLOGON) over-reports access the NTFS ACL restricts to Read;
        # using the effective mask is what stops the false "writable/full-control"
        # on NETLOGON/SYSVOL for a non-admin. Unverified (share_acl_only) edges
        # keep the raw relation as the (flagged) lead.
        eff_mask = notes.get("effective_mask")
        if (
            edge_verification in (VERIFICATION_NTFS_COMPUTED, VERIFICATION_SELF_MXAC)
            and eff_mask is not None
        ):
            contributed = [
                _RELATION_TO_PERMISSION[r]
                for r in effective_mask_relations(int(eff_mask))
                if r in _RELATION_TO_PERMISSION
            ]
        else:
            contributed = [permission]
        for perm in contributed:
            if perm not in principal.permissions:
                principal.permissions.append(perm)

    if not shares:
        return None

    snapshot.shares = shares
    return snapshot


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_graph(graph_path: str) -> Optional[Dict[str, Any]]:
    if not graph_path or not os.path.isfile(graph_path):
        return None
    try:
        with open(graph_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and "nodes" in data and "edges" in data:
            return data
        return None
    except (OSError, json.JSONDecodeError):
        return None


def _index_nodes(graph: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    nodes_field = graph.get("nodes")
    out: Dict[str, Dict[str, Any]] = {}
    if isinstance(nodes_field, dict):
        for key, node in nodes_field.items():
            oid = _first_str(node.get("object_id"), key)
            if oid:
                out[oid.upper()] = node
    elif isinstance(nodes_field, list):
        for node in nodes_field:
            oid = _first_str(node.get("object_id"))
            if oid:
                out[oid.upper()] = node
    return out


def _first_str(*values: Any) -> str:
    for v in values:
        if v is None:
            continue
        s = str(v).strip()
        if s:
            return s
    return ""


def _find_computer(
    nodes: Iterable[Dict[str, Any]], host: str
) -> Optional[Dict[str, Any]]:
    target = (host or "").strip().lower().rstrip(".")
    if not target:
        return None
    netbios = target.split(".")[0]

    for node in nodes:
        if str(node.get("kind") or "").lower() != "computer":
            continue
        props = node.get("properties") or {}
        dns = str(props.get("dnshostname") or "").lower().rstrip(".")
        ip = str(props.get("ip_address") or "").lower()
        name = str(node.get("name") or "").lower().rstrip("$").rstrip(".")
        if target in {dns, ip, name} or (netbios and netbios == name):
            return node
    return None


def _find_or_create_principal(
    principals: List[GraphSharePrincipal],
    sid: str,
    node: Optional[Dict[str, Any]],
) -> GraphSharePrincipal:
    for existing in principals:
        if existing.sid == sid:
            return existing
    name = ""
    kind = ""
    if node is not None:
        name = str(node.get("name") or node.get("display_name") or "")
        kind = str(node.get("kind") or "")
    principals.append(
        GraphSharePrincipal(sid=sid, name=name, kind=kind, permissions=[])
    )
    return principals[-1]


def _resolve_collected_at(
    graph: Dict[str, Any], computer: Dict[str, Any]
) -> Optional[datetime]:
    """Best-effort timestamp of when the share collector wrote this data.

    Falls back through: per-node ``properties.shares_collected_at`` →
    graph-level ``metadata.share_collector_at`` → ``metadata.collected_at``.
    Returns ``None`` if nothing parseable is present.
    """
    candidates = [
        (computer.get("properties") or {}).get("shares_collected_at"),
        (graph.get("metadata") or {}).get("share_collector_at"),
        (graph.get("metadata") or {}).get("collected_at"),
    ]
    for value in candidates:
        if not value:
            continue
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            continue
    return None


__all__ = [
    "GraphSharePrincipal",
    "GraphShareACL",
    "GraphShareSnapshot",
    "load_graph_share_snapshot",
]
