"""The bridge between a collector's ``CollectionResult`` and the graph store.

Two directions, one record mapping:

* :func:`write_collection_result` fills a store from a ``CollectionResult``:
  objects, facts, and the typed data the build reads. It is what the equivalence
  oracle uses to put a fixture through the build, and the first step package G
  takes to move a collector stage onto the store.
* :func:`collection_result_from_store` is the inverse view the build derives
  from: the collected objects and relationships of every committed unit, in the
  store's stable order, as the ``CollectionResult`` shape the derivation rules
  were written against. So the rules are reused unchanged (one implementation
  for the 14.0.x persist and the build), and the build depends on the store
  only through the :class:`GraphStore` interface.

A record carries exactly what its collector type carries. Nothing is derived
here, nothing secret is stored (the collector types hold no secret).

Design: ``docs/superpowers/specs/2026-11-12-inventory-first-graph-persistence.md``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from dataclasses import asdict, dataclass, field, fields
from typing import Any

from adscan_core.graph_store import (
    DatumRecord,
    FactRecord,
    GraphStore,
    ObjectRecord,
)
from adscan_core.graph_store.records import (
    STAGE_ADCS,
    StageStatus,
    STAGE_LDAP_ACLS,
    STAGE_LDAP_OBJECTS,
    STAGE_LDAP_RELATIONSHIPS,
    STAGE_LEGACY_IMPORT,
    STAGE_SMB_HOSTS,
    STAGE_SMB_SHARES,
    STAGE_TRUSTS,
    STAGE_WELL_KNOWN,
    WHOLE_STAGE_UNIT,
)
from adscan_internal.services.collector.models import (
    CollectionResult,
    CollectorEdge,
    CollectorNode,
    DomainPolicy,
)


#: Datum family holding the domain's password and account policy (one record,
#: key :data:`DOMAIN_POLICY_KEY`). The AD CS derivation reads its
#: ``machine_account_quota``.
DATUM_DOMAIN_POLICY = "domain_policy"
DOMAIN_POLICY_KEY = "domain"

#: Datum family of the foreign-security-principal placeholders (key: the SID,
#: body ``{"domain": <foreign domain>}``).
DATUM_FSP_PLACEHOLDER = "fsp_placeholder"

#: Datum family of the ACL enumeration census (one record, key
#: :data:`ACL_CENSUS_KEY`): the counters ``CollectionResult`` carries for the
#: delegated-rights positive control.
DATUM_ACL_CENSUS = "acl_census"
ACL_CENSUS_KEY = "acl_parser"

#: Datum families of the directory results the inventory export and the
#: report read (one record each, key :data:`DOMAIN_POLICY_KEY` unless noted).
DATUM_PSOS = "password_settings_objects"  # key: the PSO's DN
DATUM_PASSWORD_COMPLIANCE = "password_compliance"
DATUM_AUDIT_FINDINGS = "audit_findings"
DATUM_SHADOW_CREDENTIAL_FINDINGS = "shadow_credential_findings"
DATUM_TRUST_POSTURE_FINDINGS = "trust_posture_findings"
DATUM_MACHINE_PASSWORD_POLICY = "machine_password_policy"

_ADCS_OBJECT_KINDS = frozenset({"CertTemplate", "EnterpriseCA", "RootCA", "AIACA", "NTAuthStore"})
_SHARE_ACCESS_RELATIONS = frozenset({"readshare", "writeshare", "fullcontrolshare"})


# --------------------------------------------------------------------------- #
# Record mapping
# --------------------------------------------------------------------------- #


def object_record_from_node(node: CollectorNode) -> ObjectRecord:
    """The store record of one collected object, field for field."""
    return ObjectRecord(
        object_id=str(node.object_id),
        kind=str(node.kind),
        name=str(node.name),
        domain=str(node.domain),
        samaccountname=str(node.samaccountname or ""),
        distinguished_name=str(node.distinguished_name or ""),
        enabled=node.enabled,
        highvalue=bool(node.highvalue),
        properties=dict(node.properties or {}),
    )


def collector_node_from_record(record: ObjectRecord) -> CollectorNode:
    """The inverse of :func:`object_record_from_node`."""
    return CollectorNode(
        object_id=record.object_id,
        kind=record.kind,  # type: ignore[arg-type]
        name=record.name,
        domain=record.domain,
        samaccountname=record.samaccountname,
        distinguished_name=record.distinguished_name,
        enabled=record.enabled,
        highvalue=record.highvalue,
        properties=dict(record.properties or {}),
    )


def fact_record_from_edge(edge: CollectorEdge) -> FactRecord:
    """The store record of one collected relationship, field for field."""
    return FactRecord(
        subject_id=str(edge.source_object_id),
        object_id=str(edge.target_object_id),
        relation=str(edge.relation),
        source=str(edge.source),
        method=str(edge.method or ""),
        notes=dict(edge.notes or {}),
    )


def collector_edge_from_record(fact: FactRecord) -> CollectorEdge:
    """The inverse of :func:`fact_record_from_edge` (store timestamps are not carried)."""
    return CollectorEdge(
        source_object_id=fact.subject_id,
        target_object_id=fact.object_id,
        relation=fact.relation,
        source=fact.source,
        method=fact.method,
        notes=dict(fact.notes or {}),
    )


# --------------------------------------------------------------------------- #
# Which stage and unit a 14.0.x collector output belongs to
# --------------------------------------------------------------------------- #


def default_stage_of_edge(edge: CollectorEdge) -> str:
    """The collection stage that produces ``edge`` (the spec's stage table).

    Keyed on the collector that emitted the relationship (``source``) and how
    (``method``), never on the relation name alone: ``MemberOf`` comes from the
    LDAP group walk and from the well-known-principal injection, ``GenericAll``
    from the ACL parser.
    """
    source = str(edge.source or "").strip().lower()
    method = str(edge.method or "").strip().lower()
    relation = str(edge.relation or "").strip().lower()
    if source == "smb":
        if relation in _SHARE_ACCESS_RELATIONS or method.startswith("share_acl:"):
            return STAGE_SMB_SHARES
        return STAGE_SMB_HOSTS
    if source in {"adcs_detector", "ca_security"}:
        return STAGE_ADCS
    if source == "acl_parser" or method == "acl":
        return STAGE_LDAP_ACLS
    if relation == "trustedby":
        return STAGE_TRUSTS
    if relation == "memberof" and method == "group_inferred":
        return STAGE_WELL_KNOWN
    return STAGE_LDAP_RELATIONSHIPS


def default_unit_of_edge(edge: CollectorEdge) -> str:
    """The unit ``edge`` commits in: the host for the SMB stages, else the whole stage.

    A session (``HasSession``) is read from the host it runs on, which is the
    edge's source; local-group membership and share grants are read from the
    host they are over, the edge's target. The LDAP stages are committed as one
    unit here; package G splits them by object class.
    """
    stage = default_stage_of_edge(edge)
    if stage in {STAGE_SMB_HOSTS, STAGE_SMB_SHARES}:
        if str(edge.relation or "").strip().lower() == "hassession":
            return str(edge.source_object_id).upper()
        return str(edge.target_object_id).upper()
    return WHOLE_STAGE_UNIT


def default_stage_of_node(node: CollectorNode) -> str:
    """The collection stage that produces ``node``."""
    if str(node.kind) in _ADCS_OBJECT_KINDS:
        return STAGE_ADCS
    return STAGE_LDAP_OBJECTS


# --------------------------------------------------------------------------- #
# CollectionResult -> store
# --------------------------------------------------------------------------- #


def _result_data(result: CollectionResult) -> list[DatumRecord]:
    data: list[DatumRecord] = []
    if isinstance(result.domain_policy, DomainPolicy):
        data.append(
            DatumRecord(
                kind=DATUM_DOMAIN_POLICY,
                key=DOMAIN_POLICY_KEY,
                body=_json_safe(asdict(result.domain_policy)),
            )
        )
    for sid, foreign_domain in sorted(result.fsp_placeholders.items()):
        data.append(
            DatumRecord(kind=DATUM_FSP_PLACEHOLDER, key=str(sid), body={"domain": str(foreign_domain)})
        )
    if (
        result.security_descriptors_parsed
        or result.access_control_entries_examined
        or result.security_descriptors_without_dacl
    ):
        data.append(
            DatumRecord(
                kind=DATUM_ACL_CENSUS,
                key=ACL_CENSUS_KEY,
                body={
                    "security_descriptors_parsed": int(result.security_descriptors_parsed),
                    "access_control_entries_examined": int(result.access_control_entries_examined),
                    "security_descriptors_without_dacl": int(result.security_descriptors_without_dacl),
                },
            )
        )
    return data


def _dataclass_body(value: Any) -> dict[str, Any] | None:
    try:
        return _json_safe(asdict(value))
    except TypeError:
        return None


def _items_datum(kind: str, values: Iterable[Any]) -> DatumRecord | None:
    items = [body for body in (_dataclass_body(v) for v in values) if body is not None]
    if not items:
        return None
    return DatumRecord(kind=kind, key=DOMAIN_POLICY_KEY, body={"items": items})


def _directory_result_data(result: CollectionResult) -> list[DatumRecord]:
    """The directory results beyond what the build reads: PSOs, password
    compliance, audit and posture findings, the machine-password policy.

    Kept in the store so the inventory files are exported from it (package G)
    and a later reader has the whole collection in one place.
    """
    data: list[DatumRecord] = []
    for pso in getattr(result, "psos", None) or ():
        body = _dataclass_body(pso)
        if body is not None:
            data.append(DatumRecord(kind=DATUM_PSOS, key=str(pso.distinguished_name or pso.name), body=body))
    compliance = getattr(result, "password_compliance", None)
    if compliance is not None:
        body = _dataclass_body(compliance)
        if body is not None:
            data.append(DatumRecord(kind=DATUM_PASSWORD_COMPLIANCE, key=DOMAIN_POLICY_KEY, body=body))
    for kind, values in (
        (DATUM_AUDIT_FINDINGS, getattr(result, "audit_findings", None) or ()),
        (DATUM_SHADOW_CREDENTIAL_FINDINGS, getattr(result, "shadow_credential_findings", None) or ()),
        (DATUM_TRUST_POSTURE_FINDINGS, getattr(result, "trust_posture_findings", None) or ()),
    ):
        datum = _items_datum(kind, values)
        if datum is not None:
            data.append(datum)
    machine_policy = getattr(result, "machine_password_policy", None)
    if machine_policy is not None:
        body = _dataclass_body(machine_policy)
        if body is not None:
            data.append(DatumRecord(kind=DATUM_MACHINE_PASSWORD_POLICY, key=DOMAIN_POLICY_KEY, body=body))
    return data


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    return value


@dataclass
class UnitContent:
    """What one collection unit commits."""

    objects: list[ObjectRecord] = field(default_factory=list)
    facts: list[FactRecord] = field(default_factory=list)
    data: list[DatumRecord] = field(default_factory=list)


def collection_result_units(
    result: CollectionResult,
    *,
    stage_of: Callable[[CollectorEdge], str] | None = None,
    unit_of: Callable[[CollectorEdge], str] | None = None,
) -> dict[tuple[str, str], UnitContent]:
    """Split a ``CollectionResult`` into the units its stages would commit.

    Objects go to the stage :func:`default_stage_of_node` names (one whole-stage
    unit each), relationships to ``stage_of(edge)`` / ``unit_of(edge)`` (the
    defaults follow the spec's stage table), and the typed data the build reads
    with the LDAP objects. The relative order of the relationships inside one
    unit is the collector's order, which is the order the derivation rules see.
    """
    stage_fn = stage_of or default_stage_of_edge
    unit_fn = unit_of or (default_unit_of_edge if stage_of is None else (lambda _e: WHOLE_STAGE_UNIT))
    units: dict[tuple[str, str], UnitContent] = {}
    for node in result.nodes.values():
        key = (default_stage_of_node(node), WHOLE_STAGE_UNIT)
        units.setdefault(key, UnitContent()).objects.append(object_record_from_node(node))
    for edge in result.edges:
        key = (str(stage_fn(edge)), str(unit_fn(edge)))
        units.setdefault(key, UnitContent()).facts.append(fact_record_from_edge(edge))
    data = _result_data(result) + _directory_result_data(result)
    if data:
        units.setdefault((STAGE_LDAP_OBJECTS, WHOLE_STAGE_UNIT), UnitContent()).data.extend(data)
    return units


def write_units(
    store: GraphStore,
    units: dict[tuple[str, str], UnitContent],
    *,
    observed_at: str = "",
    end_status: StageStatus | None = "complete",
) -> None:
    """Commit ``units`` into ``store``, one atomic unit each, stage by stage.

    Every stage that receives a unit is begun first and, unless ``end_status``
    is ``None``, ended with it, so the store's stage runs describe what was
    written. Stages and units are committed in sorted order.
    """
    stages = sorted({stage for stage, _unit in units})
    for stage in stages:
        store.begin_stage(stage)
    for stage, unit in sorted(units):
        content = units[(stage, unit)]
        with store.unit(stage, unit, observed_at=observed_at) as writer:
            writer.add_objects(content.objects)
            writer.add_facts(content.facts)
            writer.add_data(content.data)
    if end_status is not None:
        for stage in stages:
            store.end_stage(stage, end_status)


def write_collection_result(
    store: GraphStore,
    result: CollectionResult,
    *,
    stage_of: Callable[[CollectorEdge], str] | None = None,
    unit_of: Callable[[CollectorEdge], str] | None = None,
    observed_at: str = "",
) -> None:
    """Commit a ``CollectionResult`` into ``store``, one unit per (stage, unit).

    See :func:`collection_result_units` for the split and :func:`write_units`
    for the commit. Every stage written is ended ``complete``.
    """
    write_units(
        store,
        collection_result_units(result, stage_of=stage_of, unit_of=unit_of),
        observed_at=observed_at,
    )


# --------------------------------------------------------------------------- #
# store -> CollectionResult (the view the derivation rules read)
# --------------------------------------------------------------------------- #


def _domain_policy_from_store(store: GraphStore) -> DomainPolicy | None:
    for datum in store.iter_data(DATUM_DOMAIN_POLICY):
        body = dict(datum.body or {})
        attrs = body.get("pwd_attrs_when_changed") or ()
        body["pwd_attrs_when_changed"] = tuple(tuple(item) for item in attrs)
        try:
            return DomainPolicy(**body)
        except TypeError:
            # A policy written by a newer engine with an extra field: keep the
            # fields this engine knows rather than lose the policy.
            names = {f.name for f in fields(DomainPolicy)}
            known = {k: v for k, v in body.items() if k in names}
            try:
                return DomainPolicy(**known)
            except TypeError:
                return None
    return None


class CollectedEdges:
    """The collected relationships of a store, re-read on every iteration.

    What :func:`collection_result_from_store` puts in ``result.edges``, without
    holding them: each ``iter()`` streams the store's facts again (legacy-import
    and evidence-only facts left out, the store's stable order), so a consumer
    that walks the relationships twice holds one relationship at a time, never
    the list. The sidecar export uses it: on a dense directory the materialised
    list of every relationship was the largest allocation of the export.

    ``relations`` narrows the facts the store returns (its filter is
    case-insensitive; :attr:`relations` are kept as given so a caller that
    needs the exact relation name still checks it).
    """

    def __init__(self, store: GraphStore, *, relations: Iterable[str] | None = None) -> None:
        self._store = store
        self.relations: tuple[str, ...] | None = None if relations is None else tuple(relations)

    def __iter__(self) -> Iterator[CollectorEdge]:
        for fact in self._store.iter_facts(relations=self.relations):
            if _is_legacy_fact(fact) or is_evidence_only_fact(fact):
                continue
            if not fact.subject_id or not fact.object_id:
                continue  # ``CollectionResult.add_edge`` keeps only both-ended edges
            yield collector_edge_from_record(fact)


def collection_result_from_store(
    store: GraphStore, *, stages: Iterable[str] | None = None, lazy_edges: bool = False
) -> CollectionResult:
    """The ``CollectionResult`` view of what the store holds, for the derivation rules.

    Objects ordered by object id, relationships in the store's stable order
    (stage, unit, then the order inside the unit), so two builds of one
    generation see the same input whatever order the stages arrived in.
    ``stages`` restricts the relationships to those stages (objects are always
    all of them: an object is keyed by id, not by stage). The legacy-import
    stage is never part of this view; the build takes it as it is.

    ``lazy_edges`` makes ``result.edges`` a :class:`CollectedEdges` view
    (every stage) instead of a list: iterable as often as needed, never held.
    """
    result = CollectionResult(domain=store.domain)
    for record in store.iter_objects():
        if record.properties.get(LEGACY_NODE_PROPERTY) is not None:
            continue
        result.add_node(collector_node_from_record(record))
    wanted = None if stages is None else set(stages)
    if lazy_edges:
        if wanted is not None:
            raise ValueError("lazy_edges reads every stage; it takes no stages filter")
        result.edges = CollectedEdges(store)  # type: ignore[assignment]
    for fact in () if lazy_edges else store.iter_facts(stages=wanted):
        if wanted is None and _is_legacy_fact(fact):
            continue
        if is_evidence_only_fact(fact):
            continue
        result.add_edge(collector_edge_from_record(fact))
    result.domain_policy = _domain_policy_from_store(store)
    for datum in store.iter_data(DATUM_FSP_PLACEHOLDER):
        result.add_fsp_placeholder(datum.key, str((datum.body or {}).get("domain") or ""))
    for datum in store.iter_data(DATUM_ACL_CENSUS):
        body = datum.body or {}
        result.security_descriptors_parsed = int(body.get("security_descriptors_parsed") or 0)
        result.access_control_entries_examined = int(body.get("access_control_entries_examined") or 0)
        result.security_descriptors_without_dacl = int(body.get("security_descriptors_without_dacl") or 0)
    return result


def _tuple_rows(rows: Any) -> tuple[tuple[Any, ...], ...]:
    return tuple(tuple(row) for row in rows or ())


def _known_fields(cls: Any, body: dict[str, Any]) -> dict[str, Any]:
    names = {f.name for f in fields(cls)}
    return {k: v for k, v in body.items() if k in names}


def inventory_result_from_store(store: GraphStore) -> CollectionResult:
    """:func:`collection_result_from_store` plus the directory results the
    inventory files carry (PSOs, password compliance), for the sidecar export.

    Its ``edges`` is a :class:`CollectedEdges` view: the objects are held, the
    relationships are streamed from the store each time they are walked."""
    from adscan_internal.services.collector.models import (  # noqa: PLC0415
        PasswordComplianceReport,
        PasswordSettingsObject,
        UserPasswordCompliance,
    )

    result = collection_result_from_store(store, lazy_edges=True)
    for datum in store.iter_data(DATUM_PSOS):
        body = dict(datum.body or {})
        body["applies_to"] = tuple(body.get("applies_to") or ())
        body["pwd_attrs_when_changed"] = _tuple_rows(body.get("pwd_attrs_when_changed"))
        try:
            result.psos.append(PasswordSettingsObject(**_known_fields(PasswordSettingsObject, body)))
        except TypeError:
            continue
    for datum in store.iter_data(DATUM_PASSWORD_COMPLIANCE):
        body = dict(datum.body or {})
        entries = []
        for entry in body.get("entries") or ():
            row = dict(entry)
            row["notes"] = tuple(row.get("notes") or ())
            try:
                entries.append(UserPasswordCompliance(**_known_fields(UserPasswordCompliance, row)))
            except TypeError:
                continue
        body["entries"] = tuple(entries)
        body["policy_pwd_attrs"] = _tuple_rows(body.get("policy_pwd_attrs"))
        try:
            result.password_compliance = PasswordComplianceReport(
                **_known_fields(PasswordComplianceReport, body)
            )
        except TypeError:
            result.password_compliance = None
    return result


#: ``FactRecord.source`` of a share reader proven by the light, credential-less
#: share probe (``cli/smb_shares_view``; stage ``unauthenticated``). Evidence
#: for the share-credential reconciliation only (``passes/shares.py``): never a
#: base edge and never an inventory relationship, exactly as 14.0.x kept it in
#: ``smb/shares.json`` and out of the graph.
SHARE_PROBE_FACT_SOURCE = "share_probe"


def is_evidence_only_fact(fact: FactRecord) -> bool:
    """Whether ``fact`` feeds a rule but is not part of the collected view."""
    return str(fact.source or "") == SHARE_PROBE_FACT_SOURCE


def _is_legacy_fact(fact: FactRecord) -> bool:
    return str(fact.source or "") == LEGACY_FACT_SOURCE


#: ``ObjectRecord.properties`` key of a node imported from a 14.0.x
#: ``attack_graph.json``: the node payload exactly as that graph held it (the
#: record's ``object_id`` is the graph node id).
LEGACY_NODE_PROPERTY = "_legacy_graph_node"

#: ``FactRecord.notes`` key carrying an imported edge exactly as it was stored.
LEGACY_EDGE_NOTE = "_legacy_edge"

#: ``FactRecord.source`` of an edge imported from a 14.0.x ``attack_graph.json``
#: (stage :data:`~adscan_core.graph_store.records.STAGE_LEGACY_IMPORT`).
LEGACY_FACT_SOURCE = "legacy_graph"


def legacy_object_record(node_id: str, node: dict[str, Any]) -> ObjectRecord:
    """The store record of one node of an imported 14.0.x graph (taken as it is)."""
    payload = dict(node)
    properties = payload.get("properties") if isinstance(payload.get("properties"), dict) else {}
    return ObjectRecord(
        object_id=str(node_id),
        kind=str(payload.get("kind") or "Unknown"),
        name=str(payload.get("label") or payload.get("name") or node_id),
        domain=str(properties.get("domain") or ""),
        properties={LEGACY_NODE_PROPERTY: payload},
    )


def legacy_fact_record(edge: dict[str, Any]) -> FactRecord:
    """The store record of one edge of an imported 14.0.x graph.

    The whole stored edge rides in the notes under :data:`LEGACY_EDGE_NOTE`
    (its technique text dropped), so the legacy base reproduces the file as it
    was: its status and verdicts, its timestamps, and edges that name their
    endpoints ``source``/``target`` instead of ``from``/``to`` (the CVE
    checks' derived host edges). The record's own fields index it (subject,
    object, relation, ``method`` = ``edge_type``). An EXECUTED status is in
    addition an overlay operation of the import, which is what keeps it once a
    re-collection drops the legacy base.
    """
    payload = {k: v for k, v in edge.items() if k != "knowledge"}
    return FactRecord(
        subject_id=str(edge.get("from") or edge.get("source") or ""),
        object_id=str(edge.get("to") or edge.get("target") or ""),
        relation=str(edge.get("relation") or ""),
        source=LEGACY_FACT_SOURCE,
        method=str(edge.get("edge_type") or "runtime"),
        notes={LEGACY_EDGE_NOTE: payload},
    )


__all__ = (
    "ACL_CENSUS_KEY",
    "DATUM_ACL_CENSUS",
    "DATUM_DOMAIN_POLICY",
    "DATUM_FSP_PLACEHOLDER",
    "DOMAIN_POLICY_KEY",
    "LEGACY_FACT_SOURCE",
    "LEGACY_NODE_PROPERTY",
    "LEGACY_EDGE_NOTE",
    "SHARE_PROBE_FACT_SOURCE",
    "STAGE_LEGACY_IMPORT",
    "UnitContent",
    "DATUM_AUDIT_FINDINGS",
    "DATUM_MACHINE_PASSWORD_POLICY",
    "DATUM_PASSWORD_COMPLIANCE",
    "DATUM_PSOS",
    "DATUM_SHADOW_CREDENTIAL_FINDINGS",
    "DATUM_TRUST_POSTURE_FINDINGS",
    "CollectedEdges",
    "collection_result_from_store",
    "inventory_result_from_store",
    "collection_result_units",
    "collector_edge_from_record",
    "collector_node_from_record",
    "default_stage_of_edge",
    "default_stage_of_node",
    "default_unit_of_edge",
    "fact_record_from_edge",
    "is_evidence_only_fact",
    "legacy_fact_record",
    "legacy_object_record",
    "object_record_from_node",
    "write_collection_result",
    "write_units",
)
