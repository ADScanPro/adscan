"""MSSQL access and linked-server edges, derived from the MSSQL stage's data.

The MSSQL collector (``collector/mssql_collector.py``) no longer writes graph
edges. Per enumerated instance it commits one ``mssql`` store unit holding one
datum (:data:`DATUM_MSSQL_AUTHORIZATION`): what the instance said (its
principals with their effective sysadmin and bulk-admin verdicts, the CONNECT
SQL permissions, the linked servers and their login mappings) and the host
node the instance resolved to at collection time (the shell's resolver,
hostname first, DNS-reverse fallback). This pass turns that into the edges the
14.0.x collector upserted, with the same rules, the same notes and the same
``edge_type`` (``mssql_collector``):

* ``SQLAccess`` / ``SQLAdmin`` from every AD-backed login (Windows user or
  group, matched to its graph node by SID) that can connect: a disabled login
  or an explicit ``CONNECT SQL`` DENY emits nothing. A group login attaches the
  edge to the GROUP, so membership delivers the blast radius;
* ``MssqlLinkedServerLateral`` from the source instance's host to every linked
  server's ``data_source`` host (a minimal foreign Computer node when the target
  is in no collected domain), marked theoretical.

Registered after ``privileged_groups`` (the MSSQL stage runs after the
directory, and in 14.0.x its edges landed on the graph the collector had
already persisted). Idempotent: a rebuild re-derives the same edges, and a
re-enumerated instance replaces its unit.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterable, Mapping
from typing import Any

from adscan_core import telemetry
from adscan_core.rich_output import print_exception, print_info_debug

#: Datum family of one enumerated MSSQL instance (key: :func:`instance_unit`).
DATUM_MSSQL_AUTHORIZATION = "mssql_authorization"

#: Relations this pass writes.
MSSQL_RELATIONS = ("MssqlLinkedServerLateral", "SQLAccess", "SQLAdmin")


def instance_unit(instance: Any) -> str:
    """The store unit (and datum key) of one instance: its SPN, FQDN or address."""
    for value in (getattr(instance, "spn", None), getattr(instance, "fqdn", None), getattr(instance, "host", None)):
        text = str(value or "").strip().lower()
        if text:
            return text
    return "unknown"


def host_record_for(host_node: Mapping[str, Any], fqdn: str) -> dict[str, Any]:
    """The Computer record the instance's edges attach to (the 14.0.x shape)."""
    return {
        "name": str(host_node.get("name") or fqdn),
        "kind": ["Computer"],
        "objectId": host_node.get("objectid") or host_node.get("objectId"),
        "properties": dict(host_node),
    }


# --------------------------------------------------------------------------- #
# Datum <-> authorization
# --------------------------------------------------------------------------- #


def authorization_body(authorization: Any, *, host_record: Mapping[str, Any], fqdn: str) -> dict[str, Any]:
    """The JSON body of one instance's datum."""
    instance = authorization.instance
    return {
        "instance": {
            "host": instance.host,
            "fqdn": instance.fqdn,
            "spn": instance.spn,
        },
        "host_record": dict(host_record),
        "fqdn": fqdn,
        "connected": bool(authorization.connected),
        "connecting_login": authorization.connecting_login,
        "connecting_is_sysadmin": bool(authorization.connecting_is_sysadmin),
        "view_any_definition": bool(authorization.view_any_definition),
        "principals": [dataclasses.asdict(fact) for fact in authorization.principals],
        "permissions": [dict(row) for row in authorization.permissions or ()],
        "linked_servers": [
            dataclasses.asdict(ls) if dataclasses.is_dataclass(ls) else dict(vars(ls))
            for ls in authorization.linked_servers or ()
        ],
    }


def authorization_from_body(body: Mapping[str, Any]) -> Any:
    """The ``MSSQLInstanceAuthorization`` a datum body describes."""
    from adscan_internal.integrations.mssql.parsers import (  # noqa: PLC0415
        LinkedServer,
        LinkedServerLoginMapping,
    )
    from adscan_internal.services.collector.mssql_collector import (  # noqa: PLC0415
        MSSQLInstance,
        MSSQLInstanceAuthorization,
        MSSQLPrincipalFact,
    )

    def _known(cls: Any, data: Mapping[str, Any]) -> dict[str, Any]:
        names = {f.name for f in dataclasses.fields(cls)}
        return {k: v for k, v in data.items() if k in names}

    instance = MSSQLInstance(**_known(MSSQLInstance, body.get("instance") or {}))
    principals = [MSSQLPrincipalFact(**_known(MSSQLPrincipalFact, p)) for p in body.get("principals") or ()]
    linked: list[Any] = []
    for raw in body.get("linked_servers") or ():
        data = dict(raw)
        data["login_mappings"] = tuple(
            LinkedServerLoginMapping(**_known(LinkedServerLoginMapping, m)) for m in data.get("login_mappings") or ()
        )
        linked.append(LinkedServer(**_known(LinkedServer, data)))
    return MSSQLInstanceAuthorization(
        instance=instance,
        connected=bool(body.get("connected", True)),
        connecting_login=str(body.get("connecting_login") or ""),
        connecting_is_sysadmin=bool(body.get("connecting_is_sysadmin")),
        view_any_definition=bool(body.get("view_any_definition")),
        principals=principals,
        permissions=[dict(row) for row in body.get("permissions") or ()],
        linked_servers=linked,
    )


# --------------------------------------------------------------------------- #
# The rules (moved from mssql_collector's 14.0.x upserts, bodies unchanged)
# --------------------------------------------------------------------------- #


def _build_sid_index(graph: dict[str, Any]) -> dict[str, dict[str, Any]]:
    from adscan_internal.services.attack_graph_service import _extract_node_object_id  # noqa: PLC0415

    index: dict[str, dict[str, Any]] = {}
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    for node in nodes.values():
        if not isinstance(node, dict):
            continue
        oid = _extract_node_object_id(node)
        if oid:
            index[oid.strip().upper()] = node
    return index


def connect_denied_principal_ids(permissions: Iterable[Mapping[str, Any]]) -> set[int]:
    """Principal ids holding an explicit ``CONNECT SQL`` DENY (DENY always wins)."""
    from adscan_internal.services.collector.mssql_collector import _to_int  # noqa: PLC0415

    denied: set[int] = set()
    for row in permissions or ():
        if str(row.get("permission_name") or "").strip().upper() != "CONNECT SQL":
            continue
        if str(row.get("state_desc") or "").strip().upper() != "DENY":
            continue
        pid = _to_int(row.get("grantee_principal_id"))
        if pid is not None:
            denied.add(pid)
    return denied


def connectable_ad_principals(authorization: Any) -> list[Any]:
    """The principal facts that get an edge if their SID resolves: AD-backed
    logins (Windows user / group) that can connect. A disabled login and an
    explicit ``CONNECT SQL`` DENY are the two authoritative "cannot connect"
    signals; an explicit GRANT is NOT required (CONNECT may come from a role, and
    requiring it would drop real access)."""
    from adscan_internal.services.collector.mssql_collector import (  # noqa: PLC0415
        _AD_BACKED_PRINCIPAL_TYPES,
    )

    denied = connect_denied_principal_ids(authorization.permissions or [])
    return [
        fact
        for fact in authorization.principals
        if fact.type_code in _AD_BACKED_PRINCIPAL_TYPES
        and fact.sid
        and not fact.is_disabled
        and fact.principal_id not in denied
    ]


def emit_mssql_access_edges(
    graph: dict[str, Any],
    authorization: Any,
    *,
    host_record: Mapping[str, Any],
    fqdn: str,
    edge_index: Any = None,
) -> tuple[int, int]:
    """Upsert the instance's ``SQLAccess`` / ``SQLAdmin`` edges into ``graph``.

    Returns ``(sqlaccess, sqladmin)``. Effective sysadmin / CONTROL SERVER is
    ``SQLAdmin``, otherwise ``SQLAccess``; the raw principal fact rides as the
    edge's ``evidence``. A login whose SID is not in the graph gets no edge and
    no invented node.
    """
    from adscan_internal.services.attack_graph_service import (  # noqa: PLC0415
        EdgeUpsertIndex,
        _node_id,
        upsert_edge,
        upsert_nodes,
    )
    from adscan_internal.services.collector.mssql_collector import _principal_evidence  # noqa: PLC0415

    if not authorization.connected or not fqdn:
        return 0, 0
    edge_index = edge_index or EdgeUpsertIndex()
    comp_record = {**dict(host_record), "properties": dict(host_record.get("properties") or {})}
    upsert_nodes(graph, [comp_record])
    to_id = _node_id(comp_record)
    if not to_id:
        return 0, 0
    sid_index = _build_sid_index(graph)
    spn_label = authorization.instance.spn or f"MSSQLSvc/{fqdn}"
    sqlaccess = 0
    sqladmin = 0
    for fact in connectable_ad_principals(authorization):
        principal_node = sid_index.get(fact.sid.strip().upper())
        if not isinstance(principal_node, dict):
            continue
        from_id = _node_id(principal_node)
        if not from_id or from_id == to_id:
            continue
        fact.matched_object_id = fact.sid
        fact.matched_label = str(principal_node.get("label") or principal_node.get("name") or "")
        relation = "SQLAdmin" if fact.effective_sysadmin else "SQLAccess"
        notes: dict[str, Any] = {
            "source": "mssql_collector",
            "ip": authorization.instance.host,
            "fqdn": fqdn,
            "spn": spn_label,
            "via_group": fact.is_group,
            "connecting_login": authorization.connecting_login,
            "view_any_definition": authorization.view_any_definition,
            "evidence": _principal_evidence(fact),
            # Per-principal ADMINISTER BULK OPERATIONS capability: the signal the
            # MssqlOpenRowsetBulkRead overlay reads for a below-sysadmin login.
            "bulk_ops_capable": fact.effective_bulk_admin,
        }
        upsert_edge(
            graph,
            index=edge_index,
            from_id=from_id,
            to_id=to_id,
            relation=relation,
            edge_type="mssql_collector",
            status="discovered",
            notes=notes,
        )
        if relation == "SQLAdmin":
            sqladmin += 1
        else:
            sqlaccess += 1

    # Coverage fact on the host node: this instance was enumerated under this
    # login, at this visibility.
    try:
        node = graph.get("nodes", {}).get(to_id)
        props = node.get("properties") if isinstance(node, dict) else None
        if isinstance(props, dict):
            coverage = props.setdefault("mssql_authorization_coverage", {})
            if isinstance(coverage, dict):
                coverage[authorization.connecting_login or "?"] = {
                    "view_any_definition": authorization.view_any_definition,
                    "sysadmin": authorization.connecting_is_sysadmin,
                    "sqlaccess_edges": sqlaccess,
                    "sqladmin_edges": sqladmin,
                }
    except Exception as exc:  # noqa: BLE001 — coverage note is best-effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    return sqlaccess, sqladmin


def _resolve_linked_server_target_node(
    graph: dict[str, Any],
    data_source_host: str,
) -> tuple[str, bool]:
    """Resolve a linked-server target host to a graph node id, creating one if needed.

    The linked-server ``data_source`` is frequently a host in a DIFFERENT domain
    (e.g. ``DC02.darkzero.ext`` reached from ``darkzero.htb``), which will NOT
    exist in the current domain's graph. Resolution:

    1. Reuse an EXISTING node whose FQDN (``name`` / ``label`` / ``dnshostname``)
       matches ``data_source_host`` exactly (case-insensitive) — this attaches to
       the real host node when the linked server points back into the same graph.
    2. Otherwise create a MINIMAL foreign Computer node keyed by the FQDN, tagged
       as a linked-server target with the derived (foreign) domain. We deliberately
       match ONLY on the exact FQDN — never on a fuzzy short-name — so a
       cross-domain ``DC02.darkzero.ext`` is never mis-merged onto a same-domain
       ``DC02`` node.

    Returns ``(target_node_id, created_foreign_node)``.
    """
    from adscan_internal.services.attack_graph_service import _node_id, upsert_nodes  # noqa: PLC0415

    host = data_source_host.strip().lower()
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    for node in nodes.values():
        if not isinstance(node, dict):
            continue
        props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
        candidates = {
            str(node.get("name") or "").strip().lower(),
            str(node.get("label") or "").strip().lower(),
            str(props.get("name") or "").strip().lower(),
            str(props.get("dnshostname") or "").strip().lower(),
        }
        candidates.discard("")
        if host in candidates:
            return _node_id(node), False

    # Cross-domain / unknown host: create a minimal foreign Computer placeholder.
    # NOTE: keyed by the FQDN (never a short name) so it cannot collide with a
    # same-domain node; the derived domain is best-effort from the FQDN suffix.
    foreign_domain = host.split(".", 1)[1] if "." in host else ""
    record = {
        "name": host,
        "label": host,
        "kind": ["Computer"],
        "properties": {
            "name": host,
            "dnshostname": host,
            "type": "Computer",
            "mssql_linked_server_target": True,
        },
    }
    if foreign_domain:
        record["properties"]["domain"] = foreign_domain.upper()
    upsert_nodes(graph, [record])
    return _node_id(record), True


def emit_mssql_linked_server_edges(
    graph: dict[str, Any],
    authorization: Any,
    *,
    host_record: Mapping[str, Any],
    fqdn: str,
    edge_index: Any = None,
) -> int:
    """Upsert theoretical ``MssqlLinkedServerLateral`` edges for one instance.

    ``<source instance host> -MssqlLinkedServerLateral-> <linked data_source
    host>`` per configured linked server, ``status="discovered"`` with
    ``notes.theoretical=True``. Read-only: nothing is enabled or executed.
    Returns how many were upserted. A source host that is a Tier-0 asset makes
    the graph's Tier-0-source suppression drop the edge (``upsert_edge``).
    """
    from adscan_internal.services.attack_graph_service import (  # noqa: PLC0415
        EdgeUpsertIndex,
        _node_id,
        upsert_edge,
        upsert_nodes,
    )
    from adscan_internal.services.collector.mssql_collector import (  # noqa: PLC0415
        _linked_server_edge_notes,
        _normalize_linked_data_source,
    )

    if not authorization.connected or not fqdn:
        return 0
    linked_servers = [
        ls
        for ls in (authorization.linked_servers or [])
        if _normalize_linked_data_source(getattr(ls, "data_source", ""))
    ]
    if not linked_servers:
        return 0
    edge_index = edge_index or EdgeUpsertIndex()
    comp_record = {**dict(host_record), "properties": dict(host_record.get("properties") or {})}
    upsert_nodes(graph, [comp_record])
    from_id = _node_id(comp_record)
    if not from_id:
        return 0
    emitted = 0
    for linked_server in linked_servers:
        target_host = _normalize_linked_data_source(linked_server.data_source)
        if not target_host:
            continue
        to_id, created_foreign = _resolve_linked_server_target_node(graph, target_host)
        if not to_id or to_id == from_id:
            continue
        notes = _linked_server_edge_notes(authorization, fqdn, linked_server)
        notes["cross_domain_target_created"] = created_foreign
        if upsert_edge(
            graph,
            index=edge_index,
            from_id=from_id,
            to_id=to_id,
            relation="MssqlLinkedServerLateral",
            edge_type="mssql_collector",
            status="discovered",
            notes=notes,
        ):
            emitted += 1
    return emitted


def derive_mssql_edges(graph: dict[str, Any], store: Any) -> int:
    """Every MSSQL instance datum of ``store`` as edges in ``graph``. Returns the count."""
    from adscan_internal.services.attack_graph_service import EdgeUpsertIndex  # noqa: PLC0415

    index = EdgeUpsertIndex()
    total = 0
    for datum in store.iter_data(DATUM_MSSQL_AUTHORIZATION):
        body = datum.body or {}
        try:
            authorization = authorization_from_body(body)
            host_record = body.get("host_record") or {}
            fqdn = str(body.get("fqdn") or "")
            access, admin = emit_mssql_access_edges(
                graph, authorization, host_record=host_record, fqdn=fqdn, edge_index=index
            )
            linked = emit_mssql_linked_server_edges(
                graph, authorization, host_record=host_record, fqdn=fqdn, edge_index=index
            )
            total += access + admin + linked
        except Exception as exc:  # noqa: BLE001 — one instance never stops the build
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(f"mssql pass: instance datum {datum.key!r} skipped")
    return total


__all__ = (
    "DATUM_MSSQL_AUTHORIZATION",
    "MSSQL_RELATIONS",
    "authorization_body",
    "authorization_from_body",
    "connectable_ad_principals",
    "connect_denied_principal_ids",
    "derive_mssql_edges",
    "emit_mssql_access_edges",
    "emit_mssql_linked_server_edges",
    "host_record_for",
    "instance_unit",
)
