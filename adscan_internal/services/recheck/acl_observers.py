"""Read-only re-observation of directory rights (recheck depth ``observe``).

One observer per ACL detector family (``adscan_core.engagement.detectors``):

* ``ldap.object_acl`` - the ACE-abuse steps (GenericAll, GenericWrite,
  WriteDacl, WriteOwner, AllExtendedRights, ForceChangePassword, AddMember,
  AddSelf, AddKeyCredentialLink, WriteAccountRestrictions, WriteSPN,
  WriteLogonScript): the DACL of each recorded target, re-read;
* ``ldap.laps`` - ReadLAPSPassword: the DACL of each recorded computer;
* ``ldap.replication_rights`` - DCSync and the replication rights: the DACL of
  the domain object, which is where they live, so the read is domain-wide;
* ``ldap.gmsa`` - ReadGMSAPassword: ``msDS-GroupMSAMembership`` of every gMSA
  in the domain, also domain-wide.

Each re-read goes through the collector's own parsing (``ACLParser.parse_sd``
for DACLs with the same SD-flags control, ``parse_gmsa_membership_sd`` for the
gMSA retrieval list), and each recorded step is decided by the effective-rights
SSOT (``effective_principal_rights.evaluate_compound_right``): the step's
principal still holds the right if it, or any group it belongs to in the
scan's membership snapshot, holds it or a right that includes it (GenericAll
includes WriteDacl). DCSync uses the canonical ``DCSYNC`` spec.

**Three states, never a guess.** A target whose descriptor was not returned
(no read right, another domain, a read error) is "not re-checked"; a target the
directory no longer holds is fixed (the object is gone); otherwise the parsed
rights decide. Which findings the surviving steps still raise is decided by the
scan's own finding gate (``attack_graph_findings._group_reportable_edges_by_key``),
so a domain controller's inherent replication right stays a step and never a
finding, exactly as in the scan.

A finding that rests on every object in the domain (the umbrella
``excessive_cross_tier_rights`` and the LAPS findings) can be re-observed
present by a per-object read but never closed by one: a grant on an object the
recheck did not read would be missed. Those families read PARTIAL, their steps
close one by one, and the finding waits for a scan. The replication and gMSA
reads cover the whole domain, so they can close their findings, except the
external-tenant replication finding, whose verdict needs the sync-account
inventory a recheck does not re-read: while the scan's report holds it, the
replication read stays PARTIAL.

Not observed: ``Owns`` and ``SyncLAPSPassword`` (the native collector does not
produce them, so there is no scan predicate to reuse).

Nothing here writes. The reads go through the open recheck LDAP connection,
which the auth-attempt guard and the posture-aware transport already govern.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional, Sequence

from adscan_core.engagement.model import CheckStatus
from adscan_core.engagement.recheck import ReadOutcome
from adscan_internal.services.recheck.not_recheckable import undecided_keys
from adscan_internal.services.recheck.recorded import (
    REASON_SCAN_GRAPH_UNAVAILABLE,
    STATE_ABSENT,
    STATE_PRESENT,
    STATE_UNKNOWN,
    RecordedStep,
    domain_sid,
    graph_nodes_by_sid,
    load_recorded_graph,
    principal_classifier,
    recorded_steps,
    report_finding_keys,
    reportable_finding_keys,
    shell_domain,
)

SCOPE_PER_OBJECT = "per_object"
SCOPE_DOMAIN_OBJECT = "domain_object"
SCOPE_GMSA = "gmsa"

#: Read outcomes of one target object.
READ_OK = "read"
READ_GONE = "gone"
READ_UNREADABLE = "unreadable"
READ_FOREIGN = "foreign"

REASON_RIGHTS_NOT_READ = "rights_not_read"
REASON_DOMAIN_WIDE_FINDING = "finding_needs_a_domain_wide_read"
REASON_EXTERNAL_TENANT = "external_tenant_verdict_not_reread"

#: Rights that include another (the parser emits ONE relation per ACE, the
#: strongest its mask maps to, so a right can be held through a broader ACE).
_INCLUDED_BY: Mapping[str, tuple[str, ...]] = {
    "GenericWrite": ("GenericAll",),
    "WriteDACL": ("GenericAll",),
    "WriteOwner": ("GenericAll",),
    "AllExtendedRights": ("GenericAll",),
    "ForceChangePassword": ("GenericAll", "AllExtendedRights"),
    "AddMember": ("GenericAll", "GenericWrite"),
    "AddSelf": ("GenericAll", "GenericWrite", "AddMember"),
    "WriteSPN": ("GenericAll", "GenericWrite"),
    "AddKeyCredentialLink": ("GenericAll", "GenericWrite"),
    "WriteAccountRestrictions": ("GenericAll", "GenericWrite"),
    "WriteLogonScript": ("GenericAll", "GenericWrite"),
    "ReadLAPSPassword": ("GenericAll", "AllExtendedRights"),
    "GetChanges": ("GenericAll", "AllExtendedRights"),
    "GetChangesAll": ("GenericAll", "AllExtendedRights"),
    "GetChangesInFilteredSet": ("GenericAll", "AllExtendedRights"),
}


@dataclass(frozen=True)
class AclFamily:
    """One ACL detector family a recheck can observe read-only."""

    check_id: str
    scope: str
    relations: frozenset[str]
    finding_keys: tuple[str, ...]


def _families() -> dict[str, AclFamily]:
    from adscan_core.engagement.detectors import DETECTORS  # noqa: PLC0415

    scopes = {
        "ldap.object_acl": SCOPE_PER_OBJECT,
        "ldap.laps": SCOPE_PER_OBJECT,
        "ldap.replication_rights": SCOPE_DOMAIN_OBJECT,
        "ldap.gmsa": SCOPE_GMSA,
    }
    return {
        d.check_id: AclFamily(d.check_id, scopes[d.check_id], frozenset(d.step_relations), d.finding_keys)
        for d in DETECTORS
        if d.check_id in scopes
    }


ACL_FAMILIES: Mapping[str, AclFamily] = _families()

# The gaps below are read from the recheck's coverage declaration
# (``not_recheckable.NOT_RECHECKABLE_KEYS``), so what the operator is told and
# what this module does cannot drift apart.

#: Relations no observer decides (the native collector never produces them, so
#: there is no scan predicate to reuse): ``Owns`` and ``SyncLAPSPassword``.
UNOBSERVED_RELATIONS: frozenset[str] = frozenset(
    rel for fam in ACL_FAMILIES.values() for rel in fam.relations & undecided_keys(fam.check_id)
)

#: Finding keys a family's read cannot close even when it covers the domain
#: (the external-tenant replication verdict needs the sync-account inventory).
#: A per-object family never covers the domain, so its declared findings change
#: nothing there: its outcome is already partial.
_UNDECIDABLE_FINDINGS: Mapping[str, frozenset[str]] = {
    fam.check_id: frozenset(fam.finding_keys) & undecided_keys(fam.check_id)
    for fam in ACL_FAMILIES.values()
    if frozenset(fam.finding_keys) & undecided_keys(fam.check_id)
}


# ---------------------------------------------------------------------------
# Rights: the parser's relation names and what includes what.
# ---------------------------------------------------------------------------


def _parser_relation_names() -> dict[str, str]:
    from adscan_internal.services.collector import acl_parser  # noqa: PLC0415

    names: set[str] = set(acl_parser.GENERIC_ACL_RIGHTS.values())
    for table in (
        acl_parser.WRITE_PROPERTY_GUID_TO_RELATION,
        acl_parser.READ_PROPERTY_GUID_TO_RELATION,
        acl_parser.PROPERTY_SET_GUID_TO_RELATION,
        acl_parser.EXTENDED_RIGHT_GUID_TO_RELATION,
        acl_parser.SELF_WRITE_GUID_TO_RELATION,
    ):
        names.update(table.values())
    names.add("ReadGMSAPassword")
    return {n.lower(): n for n in names}


def right_spec(relation: str) -> Any:
    """The rights spec a recorded step needs to be still present, or ``None``."""
    from adscan_internal.services.effective_principal_rights import DCSYNC, AnyOf  # noqa: PLC0415

    rel = str(relation or "").lower()
    if rel == "dcsync":
        return AnyOf((DCSYNC, "GenericAll"))
    if rel in UNOBSERVED_RELATIONS:
        return None
    name = _parser_relation_names().get(rel)
    if name is None:
        return None
    return AnyOf((name, *_INCLUDED_BY.get(name, ())))


@dataclass
class TargetRead:
    """What the re-read returned for one target object."""

    status: str
    rights: dict[str, set[str]] = field(default_factory=dict)


@dataclass
class _NodeShim:
    """The fields ``effective_principal_rights`` reads from a principal node."""

    object_id: str
    kind: str
    properties: dict[str, Any]


def _shim(sid: str, node: Optional[Mapping[str, Any]]) -> _NodeShim:
    props = node.get("properties") if isinstance(node, Mapping) and isinstance(node.get("properties"), Mapping) else {}
    kind = str((node or {}).get("kind") or "") if isinstance(node, Mapping) else ""
    return _NodeShim(object_id=sid, kind=kind, properties={str(k).lower(): v for k, v in props.items()})


def token_resolver(
    graph: Mapping[str, Any], closure: Mapping[str, frozenset[str]], *, intrinsic: bool = False
) -> Callable[[str], frozenset[str]]:
    """``sid -> token SIDs``: self, its groups (membership snapshot) and implicit SIDs.

    ``intrinsic=True`` leaves the groups out, as the scan does when it derives
    DCSync for a principal it did not record before.
    """
    from adscan_internal.services.attack_paths_core import (  # noqa: PLC0415
        _primary_group_sid_for_node,
    )
    from adscan_internal.services.effective_principal_rights import (  # noqa: PLC0415
        compute_effective_token_sids,
        compute_intrinsic_token_sids,
    )

    by_sid = graph_nodes_by_sid(graph)
    cache: dict[str, frozenset[str]] = {}

    def groups_of(sid: str) -> set[str]:
        groups = set(closure.get(sid, ()))
        node = by_sid.get(sid)
        # The primary group (Domain Users) is not in memberOf; the attack-path
        # SSOT derives it from primaryGroupID, so this token does too.
        primary = _primary_group_sid_for_node(dict(node)).upper() if isinstance(node, Mapping) else ""
        if primary:
            groups.add(primary)
            groups.update(closure.get(primary, ()))
        return groups

    def resolve(sid: str) -> frozenset[str]:
        sid = str(sid or "").upper()
        if sid not in cache:
            nodes = {sid: _shim(sid, by_sid.get(sid))}
            if intrinsic:
                cache[sid] = compute_intrinsic_token_sids(sid, nodes=nodes)
            else:
                cache[sid] = compute_effective_token_sids(
                    sid, nodes=nodes, edges=(), memberships_index={sid: groups_of(sid)}
                )
        return cache[sid]

    return resolve


def holds(source_sid: str, relation: str, target: TargetRead, target_id: str,
          token: Callable[[str], frozenset[str]]) -> Optional[bool]:
    """Whether the source still holds the step's right on the target (``None``: cannot say)."""
    from adscan_internal.services.effective_principal_rights import evaluate_compound_right  # noqa: PLC0415

    spec = right_spec(relation)
    if spec is None:
        return None
    index = {(target_id, trustee): frozenset(rights) for trustee, rights in target.rights.items()}
    source = str(source_sid).upper()
    return evaluate_compound_right(source, target_id, spec, rights_index=index,
                                   effective_token={source: token(source)})


# ---------------------------------------------------------------------------
# Grading (pure).
# ---------------------------------------------------------------------------


@dataclass
class AclGrade:
    """A graded family: the outcome and the per-step decisions behind it."""

    outcome: ReadOutcome
    states: dict[str, str] = field(default_factory=dict)


def decide_step(step: RecordedStep, reads: Mapping[str, TargetRead],
                token: Callable[[str], frozenset[str]]) -> str:
    """Decide one recorded step from the fresh reads of its target."""
    target_id = step.target_sid.upper()
    read = reads.get(target_id)
    if read is None or read.status in {READ_UNREADABLE, READ_FOREIGN}:
        return STATE_UNKNOWN
    if read.status == READ_GONE:
        return STATE_ABSENT
    held = holds(step.source_sid, step.relation, read, target_id, token)
    if held is None:
        return STATE_UNKNOWN
    return STATE_PRESENT if held else STATE_ABSENT


def grade_acl_family(
    family: AclFamily,
    *,
    domain_id: str,
    steps: Sequence[RecordedStep],
    reads: Mapping[str, TargetRead],
    token: Callable[[str], frozenset[str]],
    graph: Mapping[str, Any],
    domain_wide_read: bool,
    new_edges: Sequence[Mapping[str, Any]] = (),
    new_unknown: bool = False,
    report_keys: Optional[set[str]] = None,
    domains_data: Any = None,
) -> AclGrade:
    """Grade one family from fresh reads. Pure but for the finding gate it calls.

    Args:
        family: The family.
        domain_id: Ledger domain id.
        steps: The recorded steps to decide.
        reads: Fresh reads by upper-cased target id.
        token: ``sid -> token SIDs`` (self, groups, implicit SIDs).
        graph: The recorded graph (the finding gate reads its nodes).
        domain_wide_read: The read covered every object the family can hold a
            right over (domain object, every gMSA), so the findings can close.
        new_edges: Graph-shaped edges for qualifying holders the scan did not
            record (domain-wide families only).
        new_unknown: A holder the scan did not record could not be classified.
        report_keys: Finding keys the scan's report holds (``None``: unreadable).
        domains_data: Trust SSOT for the finding gate's same-forest proof.
    """
    states: dict[str, str] = {}
    by_item: dict[str, RecordedStep] = {}
    for step in steps:
        states[step.item_id] = decide_step(step, reads, token)
        by_item[step.item_id] = step

    present_steps = [s for s in steps if states[s.item_id] == STATE_PRESENT]
    unknown_steps = [s for s in steps if states[s.item_id] == STATE_UNKNOWN]

    present: dict[str, frozenset[str]] = {}
    for step in present_steps:
        key = step.relation.lower()
        present[key] = frozenset(present.get(key, frozenset()) | {step.item_id})
    raised = reportable_finding_keys([s.edge for s in present_steps] + list(new_edges), graph, domains_data)
    for key in family.finding_keys:
        if key in raised:
            present[key] = frozenset({domain_id})

    unknown_objects = {s.object_id for s in unknown_steps}
    decided = frozenset(s.object_id for s in steps) - unknown_objects
    undecided_findings = reportable_finding_keys([s.edge for s in unknown_steps], graph, domains_data)
    blocked = set(_UNDECIDABLE_FINDINGS.get(family.check_id, frozenset()))
    blocked_in_report = blocked if report_keys is None else blocked & report_keys

    ran = (
        domain_wide_read
        and not unknown_objects
        and not new_unknown
        and not (undecided_findings & set(family.finding_keys))
        and not blocked_in_report
    )
    if ran:
        outcome = ReadOutcome(family.check_id, domain_id, CheckStatus.RAN, None, present)
    else:
        if not domain_wide_read:
            reason = REASON_DOMAIN_WIDE_FINDING
        elif blocked_in_report and not unknown_objects:
            reason = REASON_EXTERNAL_TENANT
        else:
            reason = REASON_RIGHTS_NOT_READ
        outcome = ReadOutcome(family.check_id, domain_id, CheckStatus.PARTIAL, decided, present, reason)
    return AclGrade(outcome=outcome, states=states)


# ---------------------------------------------------------------------------
# Reads.
# ---------------------------------------------------------------------------

#: Objects per ``(|(...)...)`` filter.
_BATCH = 50


def _guid_filter_value(guid: str) -> str:
    raw = uuid.UUID(guid).bytes_le
    return "".join(f"\\{b:02x}" for b in raw)


def _looks_like_guid(value: str) -> bool:
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False


def _target_kind_for_parser(kind: str) -> str:
    kind = str(kind or "")
    return kind[:1].upper() + kind[1:] if kind else kind


def read_targets(ctx: Any, targets: Mapping[str, str], *, domain_sid_value: str) -> dict[str, TargetRead]:
    """Re-read the DACL of every target (``target id -> graph kind``), batched.

    A target of another domain is not read (``foreign``); one the search does not
    return is ``gone``; one returned without its descriptor is ``unreadable``.
    """
    from adscan_internal.services.collector.acl_parser import ACLParser  # noqa: PLC0415
    from adscan_internal.services.collector.ldap_collector import (  # noqa: PLC0415
        decode_object_sid,
        ldap_entry_attributes,
        raw_attribute_bytes,
    )
    from adscan_internal.services.ldap_transport_service import SD_FLAGS_DACL_CONTROL  # noqa: PLC0415
    from adscan_internal.services.recheck.observers import _sid_filter  # noqa: PLC0415

    reads: dict[str, TargetRead] = {}
    parser = ACLParser(domain=ctx.domain_id, connection=ctx.conn)
    sids: list[str] = []
    guids: list[str] = []
    for target in targets:
        if target.startswith("S-1-5-21-"):
            if domain_sid_value and target.rsplit("-", 1)[0] != domain_sid_value and target != domain_sid_value:
                reads[target] = TargetRead(READ_FOREIGN)
            else:
                sids.append(target)
        elif target.startswith("S-1-5-32-"):
            sids.append(target)
        elif _looks_like_guid(target):
            guids.append(target)
        else:
            reads[target] = TargetRead(READ_FOREIGN)

    def run(batch: list[str], query: str, key_of: Callable[[dict[str, list[Any]], Any], str]) -> None:
        try:
            ctx.conn.search(
                search_base=ctx.domain_dn,
                search_filter=query,
                attributes=["objectSid", "objectGUID", "nTSecurityDescriptor"],
                search_scope="SUBTREE",
                controls=SD_FLAGS_DACL_CONTROL,
            )
            entries = list(ctx.conn.entries)
        except Exception as exc:  # noqa: BLE001 - an unread batch is never "gone"
            from adscan_core import telemetry  # noqa: PLC0415
            from adscan_core.rich_output import print_exception  # noqa: PLC0415

            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            for target in batch:
                reads[target] = TargetRead(READ_UNREADABLE)
            return
        found: set[str] = set()
        for entry in entries:
            target = key_of(ldap_entry_attributes(entry), entry)
            if target not in batch:
                continue
            found.add(target)
            sd = raw_attribute_bytes(entry, "nTSecurityDescriptor")
            if not sd:
                reads[target] = TargetRead(READ_UNREADABLE)
                continue
            rights: dict[str, set[str]] = {}
            kind = _target_kind_for_parser(targets[target])
            for edge in parser.parse_sd(sd, target, kind):
                rights.setdefault(str(edge.source_object_id).upper(), set()).add(edge.relation)
            reads[target] = TargetRead(READ_OK, rights)
        for target in batch:
            if target not in found:
                reads[target] = TargetRead(READ_GONE)

    def sid_of(attrs: dict[str, list[Any]], _entry: Any) -> str:
        for key, values in attrs.items():
            if key.casefold() == "objectsid" and values:
                return decode_object_sid(values[0]).upper()
        return ""

    def guid_of(_attrs: dict[str, list[Any]], entry: Any) -> str:
        raw = raw_attribute_bytes(entry, "objectGUID")
        if isinstance(raw, (bytes, bytearray)) and len(raw) == 16:
            return str(uuid.UUID(bytes_le=bytes(raw))).upper()
        return ""

    for start in range(0, len(sids), _BATCH):
        batch = sids[start:start + _BATCH]
        query = _sid_filter(batch)
        if query:
            run(batch, query, sid_of)
        else:
            for target in batch:
                reads[target] = TargetRead(READ_UNREADABLE)
    for start in range(0, len(guids), _BATCH):
        batch = guids[start:start + _BATCH]
        query = "(|" + "".join(f"(objectGUID={_guid_filter_value(g)})" for g in batch) + ")"
        run([g.upper() for g in batch], query, guid_of)
    return reads


def read_gmsa_rights(ctx: Any) -> tuple[dict[str, TargetRead], bool]:
    """Every gMSA's retrieval list, parsed by the collector's own parser.

    Returns the reads by gMSA SID and whether the domain-wide search completed.
    """
    from adscan_internal.services.collector.ldap_collector import (  # noqa: PLC0415
        decode_object_sid,
        ldap_entry_attributes,
        parse_gmsa_membership_sd,
        raw_attribute_bytes,
    )
    from adscan_internal.services.ldap_transport_service import SD_FLAGS_DACL_CONTROL  # noqa: PLC0415

    reads: dict[str, TargetRead] = {}
    try:
        ctx.conn.search(
            search_base=ctx.domain_dn,
            search_filter="(objectClass=msDS-GroupManagedServiceAccount)",
            attributes=["objectSid", "msDS-GroupMSAMembership"],
            search_scope="SUBTREE",
            controls=SD_FLAGS_DACL_CONTROL,
        )
        entries = list(ctx.conn.entries)
    except Exception as exc:  # noqa: BLE001 - an unread domain closes nothing
        from adscan_core import telemetry  # noqa: PLC0415
        from adscan_core.rich_output import print_exception  # noqa: PLC0415

        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return {}, False
    for entry in entries:
        sid = ""
        for key, values in ldap_entry_attributes(entry).items():
            if key.casefold() == "objectsid" and values:
                sid = decode_object_sid(values[0]).upper()
        if not sid:
            continue
        sd = raw_attribute_bytes(entry, "msDS-GroupMSAMembership")
        if not sd:
            reads[sid] = TargetRead(READ_UNREADABLE)
            continue
        rights: dict[str, set[str]] = {}
        for edge in parse_gmsa_membership_sd(sd, target_object_id=sid):
            rights.setdefault(str(edge.source_object_id).upper(), set()).add(edge.relation)
        reads[sid] = TargetRead(READ_OK, rights)
    return reads, True


def membership_closure(ctx: Any) -> dict[str, frozenset[str]]:
    """Per-SID transitive groups from the scan's membership snapshot (the SSOT)."""
    if "membership_closure" in ctx.cache:
        return ctx.cache["membership_closure"]
    closure: dict[str, frozenset[str]] = {}
    shell = getattr(ctx, "shell", None)
    if shell is not None:
        from adscan_internal.services.collector.share_ntfs_verification import (  # noqa: PLC0415
            build_sid_group_closure,
        )
        from adscan_internal.services.membership_snapshot import load_membership_snapshot  # noqa: PLC0415

        snapshot = load_membership_snapshot(shell, shell_domain(shell, ctx.domain_id)) or {}
        nodes = snapshot.get("nodes") if isinstance(snapshot.get("nodes"), Mapping) else {}
        sid_of = {
            str(gid): str((node or {}).get("objectId") or "").upper()
            for gid, node in nodes.items()
            if isinstance(node, Mapping)
        }
        pairs = []
        for edge in snapshot.get("edges") or []:
            if not isinstance(edge, Mapping) or str(edge.get("relation") or "") != "MemberOf":
                continue
            member, group = sid_of.get(str(edge.get("from"))), sid_of.get(str(edge.get("to")))
            if member and group:
                pairs.append((member, group))
        closure = build_sid_group_closure(pairs)
    ctx.cache["membership_closure"] = closure
    return closure


def _graph_node_id(graph: Mapping[str, Any], sid: str) -> str:
    nodes = graph.get("nodes") if isinstance(graph, Mapping) else None
    for gid, node in (nodes.items() if isinstance(nodes, Mapping) else ()):
        if isinstance(node, Mapping) and str(node.get("objectId") or "").upper() == sid:
            return str(gid)
    return f"name:{sid}"


def new_holder_edges(
    family: AclFamily,
    *,
    steps: Sequence[RecordedStep],
    reads: Mapping[str, TargetRead],
    graph: Mapping[str, Any],
    classify: Callable[[str], str],
    intrinsic_token: Callable[[str], frozenset[str]],
) -> tuple[list[dict[str, Any]], bool]:
    """Graph-shaped edges for holders the scan did not record (domain-wide families).

    Returns the edges of qualifying holders and whether any holder could not be
    classified. Tier 0 holders and orphaned SIDs raise nothing, as in the scan.
    """
    from adscan_internal.services.effective_principal_rights import (  # noqa: PLC0415
        DCSYNC,
        evaluate_compound_right,
    )

    relation = "DCSync" if family.scope == SCOPE_DOMAIN_OBJECT else "ReadGMSAPassword"
    recorded = {(s.source_sid.upper(), s.target_sid.upper()) for s in steps if s.relation.lower() == relation.lower()}
    edges: list[dict[str, Any]] = []
    unknown = False
    for target_id, read in reads.items():
        if read.status != READ_OK:
            continue
        index = {(target_id, t): frozenset(r) for t, r in read.rights.items()}
        for trustee in read.rights:
            if family.scope == SCOPE_DOMAIN_OBJECT:
                if not evaluate_compound_right(trustee, target_id, DCSYNC, rights_index=index,
                                               effective_token={trustee: intrinsic_token(trustee)}):
                    continue
            if (trustee, target_id) in recorded:
                continue
            status = classify(trustee)
            if status in {"tier0", "orphaned"}:
                continue
            if status == "unknown":
                unknown = True
                continue
            edges.append({
                "from": _graph_node_id(graph, trustee),
                "to": _graph_node_id(graph, target_id),
                "relation": relation,
                "category": "exploitation",
                "notes": {},
            })
    return edges, unknown


def observe_acl_family(family: AclFamily, ctx: Any, objects: Optional[frozenset[str]]) -> ReadOutcome:
    """Re-read and grade one ACL family for ``ctx``'s domain (read-only)."""
    graph = load_recorded_graph(ctx)
    if graph is None:
        return ReadOutcome(family.check_id, ctx.domain_id, CheckStatus.FAILED, None, {},
                           REASON_SCAN_GRAPH_UNAVAILABLE)
    steps = recorded_steps(graph, family.relations, ctx.domain_id)
    if family.scope == SCOPE_PER_OBJECT and objects is not None:
        steps = [s for s in steps if s.object_id in objects]
    own_sid = domain_sid(ctx)
    closure = membership_closure(ctx)
    token = token_resolver(graph, closure)
    new_edges: list[dict[str, Any]] = []
    new_unknown = False
    if family.scope == SCOPE_GMSA:
        reads, complete = read_gmsa_rights(ctx)
        for step in steps:
            reads.setdefault(step.target_sid.upper(), TargetRead(READ_GONE if complete else READ_UNREADABLE))
        domain_wide = complete and all(r.status == READ_OK for r in reads.values() if r.status != READ_GONE)
    else:
        targets = {s.target_sid.upper(): s.target_kind for s in steps}
        if family.scope == SCOPE_DOMAIN_OBJECT and own_sid:
            targets.setdefault(own_sid, "Domain")
        reads = read_targets(ctx, targets, domain_sid_value=own_sid)
        domain_wide = (
            family.scope == SCOPE_DOMAIN_OBJECT
            and bool(own_sid)
            and reads.get(own_sid, TargetRead(READ_UNREADABLE)).status == READ_OK
        )
    if family.scope in {SCOPE_DOMAIN_OBJECT, SCOPE_GMSA}:
        new_edges, new_unknown = new_holder_edges(
            family, steps=steps,
            reads={k: v for k, v in reads.items() if family.scope == SCOPE_GMSA or k == own_sid},
            graph=graph, classify=principal_classifier(ctx, graph),
            intrinsic_token=token_resolver(graph, closure, intrinsic=True),
        )
    shell = getattr(ctx, "shell", None)
    grade = grade_acl_family(
        family,
        domain_id=ctx.domain_id,
        steps=steps,
        reads=reads,
        token=token,
        graph=graph,
        domain_wide_read=domain_wide,
        new_edges=new_edges,
        new_unknown=new_unknown,
        report_keys=report_finding_keys(shell, ctx.domain_id),
        domains_data=getattr(shell, "domains_data", None),
    )
    return grade.outcome


def _observer_for(family: AclFamily) -> Callable[[Any, Optional[frozenset[str]]], ReadOutcome]:
    def observe(ctx: Any, objects: Optional[frozenset[str]]) -> ReadOutcome:
        return observe_acl_family(family, ctx, objects)

    observe.__name__ = f"observe_{family.check_id.replace('.', '_')}"
    observe.__doc__ = f"``{family.check_id}``: the recorded rights, re-read from the directory."
    return observe


ACL_OBSERVERS: Mapping[str, Callable[[Any, Optional[frozenset[str]]], ReadOutcome]] = {
    check_id: _observer_for(family) for check_id, family in ACL_FAMILIES.items()
}

_RIGHTS_SSOT = "adscan_internal.services.effective_principal_rights:evaluate_compound_right"
_GRADERS_BY_SCOPE: Mapping[str, tuple[str, ...]] = {
    SCOPE_PER_OBJECT: ("adscan_internal.services.collector.acl_parser:ACLParser", _RIGHTS_SSOT),
    SCOPE_DOMAIN_OBJECT: ("adscan_internal.services.collector.acl_parser:ACLParser", _RIGHTS_SSOT),
    SCOPE_GMSA: ("adscan_internal.services.collector.ldap_collector:parse_gmsa_membership_sd", _RIGHTS_SSOT),
}

#: The scan's own parsing and rights evaluation each ACL observer reuses
#: (``module:attribute``), checked by ``test_recheck_coverage_declared.py``.
ACL_SCAN_GRADERS: Mapping[str, tuple[str, ...]] = {
    check_id: _GRADERS_BY_SCOPE[family.scope] for check_id, family in ACL_FAMILIES.items()
}


__all__ = (
    "ACL_FAMILIES",
    "ACL_OBSERVERS",
    "ACL_SCAN_GRADERS",
    "AclFamily",
    "AclGrade",
    "TargetRead",
    "decide_step",
    "grade_acl_family",
    "holds",
    "membership_closure",
    "new_holder_edges",
    "observe_acl_family",
    "read_gmsa_rights",
    "read_targets",
    "right_spec",
    "token_resolver",
)
