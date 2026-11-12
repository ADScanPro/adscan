"""What the scan recorded, read back for a recheck observer.

A read-only observer re-reads the CURRENT directory state, but it decides the
items the scan RECORDED: the ledger names each attack step by the stable id of
one graph edge, and the edge itself (source, target, the resources in its notes)
lives in the domain's ``attack_graph.json``. These helpers are shared by every
observer that decides steps edge by edge (AD CS, ACL rights, replication, gMSA):

* :func:`load_recorded_graph` - the domain's graph as the scan wrote it;
* :func:`recorded_steps` - its exploitation edges of some relations, each with
  the ledger item id and object id computed by the ledger's own rules
  (``engagement_items.step_item_id`` / ``step_object_id``);
* :func:`principal_classifier` - what a source the scan never recorded is
  (Tier 0, a deleted account's SID left in an ACL, an ordinary principal, or
  unknown), from the stamped tier SSOT first and the directory second;
* :func:`reportable_finding_keys` - which finding keys a set of edges raises,
  through the scan's own finding gate (``_group_reportable_edges_by_key``);
* :func:`report_finding_keys` - the finding keys the scan's report holds.

Nothing here writes. Every read failure degrades to "unknown", never to absent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Optional

STATE_PRESENT = "present"
STATE_ABSENT = "absent"
STATE_UNKNOWN = "unknown"

REASON_SCAN_GRAPH_UNAVAILABLE = "scan_graph_unavailable"


@dataclass(frozen=True)
class RecordedStep:
    """One exploitation edge of the recorded graph, named as the ledger names it."""

    item_id: str
    relation: str
    source_sid: str
    target_sid: str
    target_kind: str
    object_id: str
    edge: Mapping[str, Any] = field(default_factory=dict, compare=False, hash=False)
    source_node: Optional[Mapping[str, Any]] = field(default=None, compare=False, hash=False)


def shell_domain(shell: Any, domain_id: str) -> str:
    """The workspace's spelling of ``domain_id`` (``domains_data`` key)."""
    for name in (getattr(shell, "domains_data", None) or {}):
        if str(name).strip().rstrip(".").lower() == domain_id:
            return str(name)
    return domain_id


def node_sid(node: Optional[Mapping[str, Any]]) -> str:
    """A graph node's object id (SID, or GUID for non-principals), upper-cased."""
    if not isinstance(node, Mapping):
        return ""
    props = node.get("properties") if isinstance(node.get("properties"), Mapping) else {}
    return str(node.get("objectId") or props.get("objectid") or "").strip().upper()


def load_recorded_graph(ctx: Any) -> Optional[Mapping[str, Any]]:
    """The domain's ``attack_graph.json`` as the scan wrote it, or ``None``."""
    if "recorded_graph" in ctx.cache:
        return ctx.cache["recorded_graph"]
    graph = None
    shell = getattr(ctx, "shell", None)
    if shell is not None:
        from pathlib import Path  # noqa: PLC0415

        from adscan_internal.services.attack_graph_core import load_attack_graph  # noqa: PLC0415
        from adscan_internal.workspaces import domain_subpath, resolve_workspace_cwd  # noqa: PLC0415

        path = domain_subpath(
            resolve_workspace_cwd(shell),
            getattr(shell, "domains_dir", "domains"),
            shell_domain(shell, ctx.domain_id),
            "attack_graph.json",
        )
        graph = load_attack_graph(Path(path))
    ctx.cache["recorded_graph"] = graph
    return graph


def recorded_steps(graph: Mapping[str, Any], relations: Iterable[str], domain_id: str) -> list[RecordedStep]:
    """The recorded exploitation edges of ``relations`` (case-insensitive)."""
    from adscan_core.reporting.engagement_items import (  # noqa: PLC0415
        step_item_id,
        step_object_id,
    )

    wanted = {str(r).lower() for r in relations}
    nodes = graph.get("nodes") if isinstance(graph, Mapping) else None
    edges = graph.get("edges") if isinstance(graph, Mapping) else None
    if not isinstance(nodes, Mapping) or not isinstance(edges, list):
        return []
    out: list[RecordedStep] = []
    for raw in edges:
        if not isinstance(raw, Mapping):
            continue
        relation = str(raw.get("relation") or "")
        if relation.lower() not in wanted or raw.get("category") not in (None, "exploitation"):
            continue
        source_ref = str(raw.get("from") or "")
        target_ref = str(raw.get("to") or "")
        source_node = nodes.get(source_ref) if isinstance(nodes.get(source_ref), Mapping) else None
        target_node = nodes.get(target_ref) if isinstance(nodes.get(target_ref), Mapping) else None
        notes = raw.get("notes") if isinstance(raw.get("notes"), Mapping) else {}
        out.append(
            RecordedStep(
                item_id=step_item_id(
                    relation, source_node, target_node, notes, domain_id,
                    source_ref=source_ref, target_ref=target_ref,
                ),
                relation=relation,
                source_sid=node_sid(source_node) or source_ref.upper(),
                target_sid=node_sid(target_node) or target_ref.upper(),
                target_kind=str((target_node or {}).get("kind") or ""),
                object_id=step_object_id(source_node, target_node, target_ref=target_ref),
                edge=raw,
                source_node=source_node,
            )
        )
    return out


def graph_nodes_by_sid(graph: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    """Graph nodes keyed by upper-cased object id."""
    nodes = graph.get("nodes") if isinstance(graph, Mapping) else None
    out: dict[str, Mapping[str, Any]] = {}
    for node in (nodes.values() if isinstance(nodes, Mapping) else ()):
        sid = node_sid(node)
        if sid:
            out[sid] = node
    return out


def domain_sid(ctx: Any) -> str:
    """This domain's SID, read from the domain root (cached per run)."""
    if "domain_sid" in ctx.cache:
        return ctx.cache["domain_sid"]
    from adscan_internal.services.collector.ldap_collector import (  # noqa: PLC0415
        decode_object_sid,
        ldap_entry_attributes,
    )

    value = ""
    ctx.conn.search(
        search_base=ctx.domain_dn,
        search_filter="(objectClass=domain)",
        attributes=["objectSid"],
        search_scope="BASE",
    )
    for entry in list(ctx.conn.entries):
        for key, values in ldap_entry_attributes(entry).items():
            if key.casefold() == "objectsid" and values:
                value = decode_object_sid(values[0]).upper()
    ctx.cache["domain_sid"] = value
    return value


def principal_classifier(ctx: Any, graph: Mapping[str, Any]) -> Callable[[str], str]:
    """Classify a source SID the scan did not record.

    Returns ``"tier0"`` (a Tier 0 principal administering its own estate is no
    finding), ``"orphaned"`` (this domain's SID with no object left: a deleted
    account still named in an ACL), ``"qualifying"`` or ``"unknown"``. The
    stamped privilege tier of the scan's graph node comes first (the tier SSOT);
    a principal the graph does not hold falls back to the well-known group rule
    and a directory lookup by ``objectSid``. A SID of another domain cannot be
    classified from here and stays unknown.
    """
    cache = ctx.cache.setdefault("principal_status", {})
    by_sid = graph_nodes_by_sid(graph)

    def classify(sid: str) -> str:
        sid = str(sid or "").upper()
        if sid in cache:
            return cache[sid]
        from adscan_internal.services.compromise_class import (  # noqa: PLC0415
            node_is_tier0_by_stamped_label,
            node_stamped_privilege_tier,
        )
        from adscan_internal.services.privileged_group_classifier import (  # noqa: PLC0415
            is_tier_zero_group_sid,
        )

        node = by_sid.get(sid)
        if node is not None and node_stamped_privilege_tier(node) is not None:
            status = "tier0" if node_is_tier0_by_stamped_label(node) else "qualifying"
        elif is_tier_zero_group_sid(sid):
            status = "tier0"
        elif node is not None or not sid.startswith("S-1-5-21-"):
            status = "qualifying"
        else:
            status = _lookup_principal(ctx, sid)
        cache[sid] = status
        return status

    return classify


def _lookup_principal(ctx: Any, sid: str) -> str:
    from adscan_internal.services.recheck.observers import _sid_filter  # noqa: PLC0415

    query = _sid_filter([sid])
    if not query:
        return "unknown"
    try:
        ctx.conn.search(ctx.domain_dn, query, attributes=["objectSid"])
        if list(ctx.conn.entries):
            return "qualifying"
        own_sid = domain_sid(ctx)
    except Exception as exc:  # noqa: BLE001 - an unclassified source never closes anything
        from adscan_core import telemetry  # noqa: PLC0415
        from adscan_core.rich_output import print_exception  # noqa: PLC0415

        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return "unknown"
    if own_sid and sid.rsplit("-", 1)[0] == own_sid:
        return "orphaned"
    return "unknown"


def reportable_finding_keys(
    edges: Iterable[Mapping[str, Any]], graph: Mapping[str, Any], domains_data: Any = None
) -> set[str]:
    """Finding keys these graph edges raise, through the scan's own finding gate."""
    from adscan_internal.services.attack_graph_findings import (  # noqa: PLC0415
        _group_reportable_edges_by_key,
    )

    nodes = graph.get("nodes") if isinstance(graph, Mapping) else None
    reportable, _gated = _group_reportable_edges_by_key(
        [dict(e) for e in edges], dict(nodes) if isinstance(nodes, Mapping) else {}, domains_data
    )
    return set(reportable)


def report_finding_keys(shell: Any, domain_id: str) -> Optional[set[str]]:
    """Finding keys the scan's ``technical_report.json`` holds for the domain.

    ``None`` when the report cannot be read: the caller then treats every key
    it cannot decide as possibly open.
    """
    if shell is None:
        return None
    import json  # noqa: PLC0415
    import os  # noqa: PLC0415

    from adscan_internal.workspaces import resolve_workspace_cwd  # noqa: PLC0415

    path = os.path.join(resolve_workspace_cwd(shell), "technical_report.json")
    try:
        with open(path, encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, ValueError):
        return None
    domains = report.get("domains") if isinstance(report, dict) else None
    if not isinstance(domains, dict):
        return None
    keys: set[str] = set()
    for name, block in domains.items():
        if str(name).strip().rstrip(".").lower() != domain_id or not isinstance(block, dict):
            continue
        for finding in block.get("findings") or []:
            if isinstance(finding, dict) and finding.get("key"):
                keys.add(str(finding["key"]))
    return keys


__all__ = (
    "REASON_SCAN_GRAPH_UNAVAILABLE",
    "RecordedStep",
    "STATE_ABSENT",
    "STATE_PRESENT",
    "STATE_UNKNOWN",
    "domain_sid",
    "graph_nodes_by_sid",
    "load_recorded_graph",
    "node_sid",
    "principal_classifier",
    "recorded_steps",
    "report_finding_keys",
    "reportable_finding_keys",
    "shell_domain",
)
