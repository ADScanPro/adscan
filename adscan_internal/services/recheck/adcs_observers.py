"""Read-only re-observation of AD CS escalations (recheck depth ``observe``).

One observer per AD CS detector family (``adcs.escN``). Each re-reads the
CURRENT certificate-services state with the scan's own reads and grades it with
the scan's own detectors, so a re-check and a scan cannot disagree:

* the PKI objects, their access control lists and the ESC13 issuance-policy
  links come from :meth:`ADCSCollector.collect_directory` (LDAP only);
* the CA-host values (``EditFlags`` / ``InterfaceFlags`` over the remote
  registry, the CA security descriptor over DCOM, the web enrollment endpoint
  over HTTP) come from :meth:`ADCSCollector.read_ca_host_state`, only for the
  families that need them, and only on CA hosts this domain owns
  (``engagement_scope.collection_host_verdict``);
* the verdict is :func:`adcs_collector.detect_collected_escalations`, the
  single detection seam the scan itself uses.

Nothing here requests, enrolls, approves or revokes a certificate, and nothing
writes to the directory or the CA. A structural test locks it.

**What a re-check decides, and how honestly.** The scan recorded each AD CS
step as a derived graph edge (``source -> ADCSESCn -> Domain Admins``) whose
``notes.vulnerable_resources`` name the template or CA behind it. A re-check
reads those resources again and decides each recorded edge:

* *still present*: the detector still emits the same principal on one of its
  resources (for ESC9, whose recorded source is the account writer, the
  template is still exploitable by any enroller);
* *fixed*: every resource was read and none carries the condition any more,
  including a template that was deleted or is no longer published by any CA
  (the operator is told which);
* *not re-checked*: a resource could not be read (its access control list was
  not returned, the CA security descriptor or registry needs rights this
  account lacks, the web endpoint timed out). That is never "fixed".

Most AD CS steps name the same ledger object (the impersonated Domain Admins
group), so a present step is reported by its ledger item id, not its object:
one group losing enroll closes its own step while another group's stays open.
An object is examined only when every recorded step on it was decided.

Families with no observer: ESC10 (the domain-controller certificate binding
read is not wired in the scan either, so the scan never raises it), ESC12 (a
CA-host secret read that needs a proven CA-host administrator, recorded by its
own instrumented check), ESC14 (a write right on a user object, not a template
or CA setting) and ESC16/ESC17 (no detector).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence

from adscan_core.engagement.model import CheckStatus
from adscan_core.engagement.recheck import ReadOutcome
from adscan_internal.services.recheck.recorded import (
    REASON_SCAN_GRAPH_UNAVAILABLE,
    STATE_ABSENT,
    STATE_PRESENT,
    STATE_UNKNOWN,
    load_recorded_graph,
    principal_classifier,
    shell_domain,
)

#: Grounds of one family: what object carries the condition and what reads it.
BASIS_TEMPLATE = "template"
BASIS_TEMPLATE_WRITER = "template_writer"
BASIS_PKI_OBJECT = "pki_object"
BASIS_CA_SAN_FLAG = "ca_san_flag"
BASIS_CA_SECURITY = "ca_security"
BASIS_CA_WEB = "ca_web_enrollment"
BASIS_CA_INTERFACE_FLAG = "ca_interface_flag"

#: Families decided (wholly or partly) from a read on the CA host.
CA_HOST_BASES = frozenset(
    {BASIS_CA_SAN_FLAG, BASIS_CA_SECURITY, BASIS_CA_WEB, BASIS_CA_INTERFACE_FLAG}
)

_TEMPLATE_KINDS = frozenset({"certtemplate"})
_CA_KINDS = frozenset({"enterpriseca"})
_PKI_KINDS = frozenset({"ntauthstore", "rootca", "aiaca", "enterpriseca"})

#: ``not re-checked`` reasons (``ReadOutcome.reason``).
REASON_PKI_UNREADABLE = "pki_directory_unreadable"
REASON_PKI_INCOMPLETE = "pki_directory_read_incomplete"


@dataclass(frozen=True)
class AdcsCheck:
    """One AD CS detector family a re-check can observe read-only."""

    check_id: str
    relation: str
    finding_key: str
    basis: str
    label: str

    @property
    def resource_kinds(self) -> frozenset[str]:
        if self.basis in {BASIS_CA_SECURITY, BASIS_CA_WEB, BASIS_CA_INTERFACE_FLAG}:
            return _CA_KINDS
        if self.basis == BASIS_PKI_OBJECT:
            return _PKI_KINDS
        return _TEMPLATE_KINDS


def _check(number: int, basis: str) -> AdcsCheck:
    return AdcsCheck(
        check_id=f"adcs.esc{number}",
        relation=f"ADCSESC{number}",
        finding_key=f"adcs_esc{number}",
        basis=basis,
        label=f"ESC{number}",
    )


ADCS_CHECKS: Mapping[str, AdcsCheck] = {
    c.check_id: c
    for c in (
        _check(1, BASIS_TEMPLATE),
        _check(2, BASIS_TEMPLATE),
        _check(3, BASIS_TEMPLATE),
        _check(4, BASIS_TEMPLATE),
        _check(5, BASIS_PKI_OBJECT),
        _check(6, BASIS_CA_SAN_FLAG),
        _check(7, BASIS_CA_SECURITY),
        _check(8, BASIS_CA_WEB),
        _check(9, BASIS_TEMPLATE_WRITER),
        _check(11, BASIS_CA_INTERFACE_FLAG),
        _check(13, BASIS_TEMPLATE),
        _check(15, BASIS_TEMPLATE),
    )
}


# ---------------------------------------------------------------------------
# Inputs: what the scan recorded, and what was read now.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RecordedEscEdge:
    """One AD CS step as the scan recorded it in ``attack_graph.json``."""

    relation: str
    source_sid: str
    object_id: str
    resources: Mapping[str, str]
    client_finding: bool = True
    #: The ledger item id: present steps are named by it, so steps sharing one
    #: object (most AD CS steps name Domain Admins) are decided one by one.
    item_id: str = ""


@dataclass
class PkiState:
    """The certificate-services directory state read now (LDAP only).

    Attributes:
        nodes: PKI objects by upper-cased collector object id.
        result: The collection result (nodes + ACL edges), for the detectors.
        unread_acl: Upper-cased ids of objects whose ACL was not returned.
        oid_links_resolved: Whether the ESC13 issuance-policy links were read.
        published_labels: Casefolded ``cn`` of every published template.
        edges: Detector output with no CA-host input (template, PKI, LDAP ESC7).
    """

    nodes: dict[str, Any]
    result: Any
    unread_acl: frozenset[str]
    oid_links_resolved: bool
    published_labels: set[str]
    edges: list[Any]


@dataclass
class CaHostState:
    """The CA-host reads (registry, CA security, web enrollment), by CA id."""

    probes: Mapping[str, Any]
    edges: list[Any]


@dataclass
class AdcsGrade:
    """A graded family: the read outcome plus what the operator is told."""

    outcome: ReadOutcome
    resolved: list[tuple[str, str]] = field(default_factory=list)


def recorded_esc_edges(graph: Mapping[str, Any], relation: str, domain_id: str = "") -> list[RecordedEscEdge]:
    """Every recorded AD CS step of ``relation`` in one domain's attack graph.

    The ledger item id and object id come from the ledger's own rules (through
    :func:`recorded.recorded_steps`), so a decision lands on the exact item the
    scan recorded, even when several steps share one object.
    """
    from adscan_internal.services.recheck.recorded import recorded_steps  # noqa: PLC0415

    out: list[RecordedEscEdge] = []
    for step in recorded_steps(graph, (relation,), domain_id):
        notes = step.edge.get("notes") if isinstance(step.edge.get("notes"), Mapping) else {}
        resources: dict[str, str] = {}
        for entry in notes.get("vulnerable_resources") or []:
            if not isinstance(entry, Mapping):
                continue
            oid = str(entry.get("object_id") or "").strip().upper()
            if oid:
                resources[oid] = f"{str(entry.get('kind') or '').lower()}|{entry.get('name') or oid}"
        out.append(
            RecordedEscEdge(
                relation=relation.upper(),
                source_sid=step.source_sid,
                object_id=step.object_id,
                resources=resources,
                client_finding=notes.get("client_finding") is not False,
                item_id=step.item_id,
            )
        )
    return out


def build_pki_state(result: Any, *, oid_links: Any, unread_acl: Iterable[str], domain: str) -> PkiState:
    """Grade a fresh directory read with the scan's detectors (no CA-host input)."""
    from adscan_internal.services.collector.adcs_collector import (  # noqa: PLC0415
        detect_collected_escalations,
        published_template_labels,
    )

    detected = detect_collected_escalations(
        result, domain=domain, oid_links=oid_links, ca_probes={}, domain_binding=None
    )
    cas = [n for n in result.nodes.values() if n.kind == "EnterpriseCA"]
    return PkiState(
        nodes={str(oid).upper(): node for oid, node in result.nodes.items()},
        result=result,
        unread_acl=frozenset(str(o).upper() for o in unread_acl),
        oid_links_resolved=bool(getattr(oid_links, "resolved", False)),
        published_labels=published_template_labels(cas),
        edges=detected.all_edges(),
    )


def build_ca_host_state(pki: PkiState, probes: Mapping[str, Any], *, domain: str, oid_links: Any) -> CaHostState:
    """Grade the directory read again WITH the CA-host reads (same detector seam)."""
    from adscan_internal.services.collector.adcs_collector import (  # noqa: PLC0415
        detect_collected_escalations,
    )

    detected = detect_collected_escalations(
        pki.result, domain=domain, oid_links=oid_links, ca_probes=probes, domain_binding=None
    )
    return CaHostState(probes=dict(probes), edges=detected.all_edges())


# ---------------------------------------------------------------------------
# Grading (pure).
# ---------------------------------------------------------------------------


def _probe_for(ca_hosts: Optional[CaHostState], ca_oid: str) -> Any:
    if ca_hosts is None:
        return None
    for key, bundle in ca_hosts.probes.items():
        if str(key).upper() == ca_oid:
            return bundle
    return None


def _cas_publishing(pki: PkiState, template: Any) -> list[Any]:
    from adscan_internal.services.collector.adcs_collector import (  # noqa: PLC0415
        _published_template_ids,
    )

    return [
        ca
        for ca in pki.nodes.values()
        if ca.kind == "EnterpriseCA" and template.object_id in _published_template_ids(ca, [template])
    ]


def _template_still_qualifies_for_esc6(pki: PkiState, template: Any, source_sid: str) -> bool:
    """ESC6's template half, by the ESC6 detector itself (CA flag assumed on)."""
    from adscan_internal.services.collector.adcs_detectors.esc6 import detect_esc6  # noqa: PLC0415

    acl = [e for e in pki.result.edges if str(e.target_object_id).upper() == str(template.object_id).upper()]
    edges = detect_esc6(template_node=template, template_acl_edges=acl, domain="", ca_editf_san2_enabled=True)
    sources = {str(e.source_object_id).upper() for e in edges}
    return source_sid in sources if source_sid else bool(sources)


def _security_descriptor_read(ca: Any) -> bool:
    from adscan_core.reporting.ca_role_separation import (  # noqa: PLC0415
        READING_PROPERTY,
        READING_SECURITY_READ,
    )

    reading = (getattr(ca, "properties", None) or {}).get(READING_PROPERTY)
    return isinstance(reading, Mapping) and reading.get(READING_SECURITY_READ) is True


def resource_disposition(check: AdcsCheck, pki: PkiState, resource_oid: str) -> str:
    """Why a resource no longer carries the condition, for the operator line."""
    from adscan_internal.services.collector.adcs_collector import template_is_published  # noqa: PLC0415

    node = pki.nodes.get(resource_oid)
    if node is None:
        return "deleted"
    if (
        node.kind == "CertTemplate"
        and check.relation != "ADCSESC4"
        and not template_is_published(node, pki.published_labels)
    ):
        return "unpublished"
    return "reconfigured"


def _resource_unknown(
    check: AdcsCheck,
    pki: PkiState,
    ca_hosts: Optional[CaHostState],
    resource_oid: str,
    source_sid: str,
) -> bool:
    """Whether a resource whose condition did NOT re-appear could not be ruled out."""
    from adscan_internal.services.collector.adcs_collector import template_is_published  # noqa: PLC0415

    node = pki.nodes.get(resource_oid)
    if node is None:
        return False  # deleted: the condition is gone with the object
    gated = node.kind == "CertTemplate" and check.relation != "ADCSESC4"
    if gated and not template_is_published(node, pki.published_labels):
        return False  # published by no CA: nobody can request it
    if check.basis in {BASIS_TEMPLATE, BASIS_TEMPLATE_WRITER, BASIS_PKI_OBJECT}:
        if check.relation == "ADCSESC13" and not pki.oid_links_resolved:
            return True
        return resource_oid in pki.unread_acl
    if check.basis == BASIS_CA_SAN_FLAG:
        if resource_oid in pki.unread_acl:
            return True
        if not _template_still_qualifies_for_esc6(pki, node, source_sid):
            return False
        for ca in _cas_publishing(pki, node):
            probe = _probe_for(ca_hosts, str(ca.object_id).upper())
            registry = getattr(probe, "registry", None)
            if registry is None or not getattr(registry, "edit_flags_readable", False):
                return True
        return False
    probe = _probe_for(ca_hosts, resource_oid)
    if check.basis == BASIS_CA_SECURITY:
        return resource_oid in pki.unread_acl or not _security_descriptor_read(node)
    if check.basis == BASIS_CA_WEB:
        web = getattr(probe, "web", None)
        return web is None or not web.esc8_absence_certain
    if check.basis == BASIS_CA_INTERFACE_FLAG:
        registry = getattr(probe, "registry", None)
        return registry is None or not getattr(registry, "interface_flags_readable", False)
    return True


def _fresh_index(edges: Iterable[Any], relation: str) -> dict[str, set[str]]:
    index: dict[str, set[str]] = {}
    for edge in edges:
        if str(getattr(edge, "relation", "")).upper() != relation:
            continue
        index.setdefault(str(edge.target_object_id).upper(), set()).add(str(edge.source_object_id).upper())
    return index


def decide_recorded_edge(
    check: AdcsCheck,
    recorded: RecordedEscEdge,
    *,
    pki: PkiState,
    ca_hosts: Optional[CaHostState],
    fresh: Mapping[str, set[str]],
) -> tuple[str, list[str]]:
    """Decide one recorded step: ``(state, resource ids found clear)``."""
    writer = check.basis == BASIS_TEMPLATE_WRITER
    resources = [
        oid for oid, tag in recorded.resources.items() if tag.split("|", 1)[0] in check.resource_kinds
    ]
    if not resources:
        # An older graph with no resource list: decide on the relation alone.
        # Absent only when the condition is gone everywhere AND nothing that
        # could carry it went unread.
        holders = set().union(*fresh.values()) if fresh else set()
        if (writer and holders) or recorded.source_sid in holders:
            return STATE_PRESENT, []
        undecidable = bool(fresh) or check.basis in CA_HOST_BASES or bool(pki.unread_acl)
        return (STATE_UNKNOWN if undecidable else STATE_ABSENT), []
    unknown = False
    clear: list[str] = []
    for oid in resources:
        holders = fresh.get(oid, set())
        if holders and (writer or recorded.source_sid in holders):
            return STATE_PRESENT, []
        if _resource_unknown(check, pki, ca_hosts, oid, recorded.source_sid):
            unknown = True
        else:
            clear.append(oid)
    return (STATE_UNKNOWN if unknown else STATE_ABSENT), clear


def grade_adcs_check(
    check: AdcsCheck,
    *,
    domain_id: str,
    recorded: Sequence[RecordedEscEdge],
    pki: PkiState,
    ca_hosts: Optional[CaHostState],
    principal_status: Callable[[str], str],
) -> AdcsGrade:
    """Grade one family for one domain from a fresh read. Pure.

    ``principal_status(sid)`` classifies a source the scan never recorded:
    ``"tier0"`` (a Tier 0 principal administering its own PKI is no finding),
    ``"orphaned"`` (a deleted account's SID left in an ACL), ``"qualifying"`` or
    ``"unknown"``.
    """
    relation = check.relation
    use_host = check.basis in CA_HOST_BASES and ca_hosts is not None
    fresh = _fresh_index(ca_hosts.edges if use_host else pki.edges, relation)

    decisions: list[tuple[RecordedEscEdge, str]] = []
    finding_present = False
    finding_unknown = False
    resolved: dict[str, str] = {}
    for rec in recorded:
        state, clear = decide_recorded_edge(check, rec, pki=pki, ca_hosts=ca_hosts, fresh=fresh)
        decisions.append((rec, state))
        if rec.client_finding and state == STATE_PRESENT:
            finding_present = True
        if rec.client_finding and state == STATE_UNKNOWN:
            finding_unknown = True
        if state == STATE_ABSENT:
            for oid in clear:
                name = rec.resources.get(oid, "|").split("|", 1)[1]
                resolved.setdefault(name, resource_disposition(check, pki, oid))

    # A condition the scan did not record (a new grant, a newly vulnerable
    # template) keeps the finding open; ESC9's recorded source is the account
    # writer, which a directory ACL read of templates cannot re-derive, so
    # only its recorded templates count.
    if check.basis != BASIS_TEMPLATE_WRITER:
        known = {
            (oid, rec.source_sid) for rec in recorded for oid in rec.resources
        }
        for target, sources in fresh.items():
            for source in sources:
                if (target, source) in known:
                    continue
                status = principal_status(source)
                if status == "qualifying":
                    finding_present = True
                elif status == "unknown":
                    finding_unknown = True

    # Present steps are named by item id, so two principals on one object are
    # decided apart. An object is examined only when every recorded step on it
    # was decided: an undecided step must never close with its neighbours.
    present_items = frozenset(rec.item_id or rec.object_id for rec, s in decisions if s == STATE_PRESENT)
    unknown_objects = {rec.object_id for rec, s in decisions if s == STATE_UNKNOWN}
    decided = frozenset(rec.object_id for rec, _s in decisions) - unknown_objects

    present: dict[str, frozenset[str]] = {relation.lower(): present_items}
    if finding_present:
        present[check.finding_key] = frozenset({domain_id})
    if not unknown_objects and not finding_unknown:
        outcome = ReadOutcome(check.check_id, domain_id, CheckStatus.RAN, None, present)
    else:
        outcome = ReadOutcome(
            check.check_id, domain_id, CheckStatus.PARTIAL, decided, present, _unknown_reason(check)
        )
    return AdcsGrade(outcome=outcome, resolved=sorted(resolved.items()))


def _unknown_reason(check: AdcsCheck) -> str:
    return {
        BASIS_CA_SAN_FLAG: "ca_registry_not_read",
        BASIS_CA_INTERFACE_FLAG: "ca_registry_not_read",
        BASIS_CA_SECURITY: "ca_security_not_read",
        BASIS_CA_WEB: "web_enrollment_not_verified",
    }.get(check.basis, "access_control_list_not_read")


# ---------------------------------------------------------------------------
# Reads (one per domain per run, shared by every family through ctx.cache).
# ---------------------------------------------------------------------------


def _pki_read(ctx: Any) -> tuple[Optional[PkiState], str]:
    if "adcs_pki" in ctx.cache:
        return ctx.cache["adcs_pki"]
    from adscan_internal.services.collector.adcs_collector import ADCSCollector  # noqa: PLC0415

    shell = getattr(ctx, "shell", None)
    domain = shell_domain(shell, ctx.domain_id)
    smb_builder = None
    if shell is not None:
        from adscan_internal.services.adcs.ca_host_access import (  # noqa: PLC0415
            build_ca_host_smb_config_builder,
        )

        dc_ip = getattr(getattr(ctx.conn, "config", None), "dc_ip", None)
        smb_builder = build_ca_host_smb_config_builder(
            shell, domain=domain, dc_ip=str(dc_ip) if dc_ip else None
        )
    collector = ADCSCollector(
        connection=ctx.conn, domain=domain, smb_config_builder=smb_builder, shell=shell
    )
    result, oid_links = collector.collect_directory()
    if oid_links is None:
        value: tuple[Optional[PkiState], str] = (None, REASON_PKI_UNREADABLE)
    elif result.stage_failures:
        value = (None, REASON_PKI_INCOMPLETE)
    else:
        pki = build_pki_state(
            result, oid_links=oid_links, unread_acl=collector.unread_security_descriptors, domain=domain
        )
        ctx.cache["adcs_collector"] = (collector, oid_links, domain)
        value = (pki, "")
    ctx.cache["adcs_pki"] = value
    return value


def _ca_host_read(ctx: Any, pki: PkiState) -> Optional[CaHostState]:
    if "adcs_ca_hosts" in ctx.cache:
        return ctx.cache["adcs_ca_hosts"]
    state: Optional[CaHostState] = None
    collector, oid_links, domain = ctx.cache.get("adcs_collector", (None, None, ""))
    cas = [n for n in pki.nodes.values() if n.kind == "EnterpriseCA"]
    if collector is not None and cas and getattr(ctx, "shell", None) is not None:
        # The read-only recheck never runs ESC12 (it has its own check) and
        # never writes the scan's observation record.
        probes, _binding = collector.read_ca_host_state(cas, check_esc12=False)
        state = build_ca_host_state(pki, probes, domain=domain, oid_links=oid_links)
    ctx.cache["adcs_ca_hosts"] = state
    return state


def observe_adcs_check(check: AdcsCheck, ctx: Any) -> ReadOutcome:
    """Re-read and grade one AD CS family for ``ctx``'s domain (read-only)."""
    pki, reason = _pki_read(ctx)
    if pki is None:
        return ReadOutcome(check.check_id, ctx.domain_id, CheckStatus.FAILED, None, {}, reason)
    graph = load_recorded_graph(ctx)
    if graph is None:
        return ReadOutcome(
            check.check_id, ctx.domain_id, CheckStatus.FAILED, None, {}, REASON_SCAN_GRAPH_UNAVAILABLE
        )
    ca_hosts = _ca_host_read(ctx, pki) if check.basis in CA_HOST_BASES else None
    grade = grade_adcs_check(
        check,
        domain_id=ctx.domain_id,
        recorded=recorded_esc_edges(graph, check.relation, ctx.domain_id),
        pki=pki,
        ca_hosts=ca_hosts,
        principal_status=principal_classifier(ctx, graph),
    )
    _report_resolved(check, grade.resolved)
    return grade.outcome


_DISPOSITION_TEXT = {
    "deleted": "no longer exists in the directory",
    "unpublished": "is no longer published by any certification authority",
    "reconfigured": "no longer meets the condition",
}


def _report_resolved(check: AdcsCheck, resolved: Sequence[tuple[str, str]]) -> None:
    if not resolved:
        return
    from adscan_core.rich_output import mark_sensitive, print_info  # noqa: PLC0415

    for name, disposition in resolved:
        print_info(
            f"{check.label}: {mark_sensitive(name, 'service')} "
            f"{_DISPOSITION_TEXT.get(disposition, _DISPOSITION_TEXT['reconfigured'])}."
        )


def _observer_for(check: AdcsCheck) -> Callable[[Any, Optional[frozenset[str]]], ReadOutcome]:
    def observe(ctx: Any, _objects: Optional[frozenset[str]]) -> ReadOutcome:
        return observe_adcs_check(check, ctx)

    observe.__name__ = f"observe_{check.check_id.replace('.', '_')}"
    observe.__doc__ = f"``{check.finding_key}`` and its steps: the {check.label} condition, re-read."
    return observe


ADCS_OBSERVERS: Mapping[str, Callable[[Any, Optional[frozenset[str]]], ReadOutcome]] = {
    check_id: _observer_for(check) for check_id, check in ADCS_CHECKS.items()
}

#: The scan's own read and grading seam each AD CS observer reuses
#: (``module:attribute``), checked by ``test_recheck_coverage_declared.py``.
ADCS_SCAN_GRADERS: Mapping[str, tuple[str, ...]] = {
    check_id: (
        "adscan_internal.services.collector.adcs_collector:ADCSCollector",
        "adscan_internal.services.collector.adcs_collector:detect_collected_escalations",
    )
    for check_id in ADCS_CHECKS
}


__all__ = (
    "ADCS_CHECKS",
    "ADCS_OBSERVERS",
    "ADCS_SCAN_GRADERS",
    "AdcsCheck",
    "AdcsGrade",
    "CaHostState",
    "PkiState",
    "RecordedEscEdge",
    "build_ca_host_state",
    "build_pki_state",
    "decide_recorded_edge",
    "grade_adcs_check",
    "observe_adcs_check",
    "principal_classifier",
    "recorded_esc_edges",
)
