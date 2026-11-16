"""Offline-cracking derivation: Kerberoasting and AS-REP roasting edges, the
HTTP-SPN relay-surface classification read off the same SPN list, and the
enumerated-surface census the derivation feeds.

Moved from ``collector/persistence.py`` (bodies unchanged).
"""

from __future__ import annotations

from typing import Any, Callable

from adscan_core.kerberos_roasting import AccountSignals
from adscan_core.kerberos_roasting import (
    is_managed_service_account as _node_is_managed_service_account,
)
from adscan_core.kerberos_roasting import (
    password_is_ad_managed as _password_is_ad_managed,
)
from adscan_internal.services import attack_graph_service
from adscan_internal.services.collector.models import CollectionResult, HttpSpnFinding
from adscan_internal.services.credential_store_service import hosts_match
from adscan_internal.services.graph_build.passes._common import (
    _node_bool_property,
    _node_list_property,
    _upsert_derived_edge,
)
from adscan_internal.services.graph_queries.filters import is_active


# Well-known Authenticated Users SID — the broadest actor for Kerberoasting /
# AS-REP Roasting (only *being authenticated* is required, which is cross-forest
# capable). Sourcing those derived edges here (not from the domain-local Domain
# Users group) is what surfaces the cross-forest roasting paths.
_AUTHENTICATED_USERS_SID = "S-1-5-11"


def _find_authenticated_users_graph_id(
    sid_to_graph_id: dict[str, str],
) -> str:
    """Return the graph id of the Authenticated Users well-known node (S-1-5-11).

    Resolved by its fixed well-known SID rather than by group name — the node is
    synthetic (``Authenticated Users@WELLKNOWN``), guaranteed injected by
    ``well_known_sids.inject_all_well_known_sid_nodes`` before persistence, and
    keyed under its SID in ``sid_to_graph_id`` like every other collected node.
    Returns ``""`` when the node is absent so the caller can skip emission rather
    than sourcing an edge from an unresolvable placeholder.
    """
    return sid_to_graph_id.get(_AUTHENTICATED_USERS_SID, "")


def _node_is_enabled(node: Any) -> bool:
    """Return whether a collected principal should produce executable paths.

    ACTIVE, not merely enabled: a tombstone preserves its
    ``userAccountControl``, so a deleted-but-was-enabled account would otherwise
    derive a Kerberoasting / ASREPRoasting edge for an SPN that no longer
    resolves and an account that cannot authenticate. The deleted object keeps
    its real ACL edges (that is how the restorable-tombstone technique works);
    only these DERIVED executable edges are withheld.
    """
    return is_active(node)


def _http_service_spns(spns: list[str]) -> list[str]:
    """Return the subset of ``spns`` whose service class is HTTP.

    An SPN is ``serviceclass/instance[:port][/name]``; the service class is the
    token before the first ``/`` (MS-ADTS 2.2.21), matched case-insensitively.
    Unlike the auto-registered ``HOST/`` / ``RestrictedKrbHost/`` SPNs, an
    ``HTTP/`` SPN is registered deliberately when a Kerberos web service is
    published under the account, so every occurrence is the signal. Reuses the
    already-collected SPN list — the same one the kerberoastable derivation
    walks — so there is no second SPN pass.
    """
    out: list[str] = []
    for spn in spns or []:
        text = str(spn).strip()
        if text and text.split("/", 1)[0].strip().lower() == "http":
            out.append(text)
    return out


def _adcs_ca_web_enrollment_hosts(result: CollectionResult) -> set[str]:
    """Return the FQDN host identifiers of every ADCS Enterprise CA collected.

    An Enterprise CA's web-enrollment endpoint publishes an ``HTTP/<ca>`` SPN, so
    the generic HTTP-SPN relay-surface finding would fire on the very host that
    ADCS/ESC8 detection (and the active EPA probe in ``adcs_web_enrollment_probe``)
    already covers with a specific, higher-value finding. The authoritative marker
    is the ``EnterpriseCA`` node's ``dns_hostname`` (the CA's FQDN, populated by
    the ADCS collector). These hosts are used to suppress the duplicate.
    """
    hosts: set[str] = set()
    for node in result.nodes.values():
        if str(node.kind) != "EnterpriseCA":
            continue
        dns_hostname = str(node.properties.get("dns_hostname") or "").strip()
        if dns_hostname:
            hosts.add(dns_hostname)
    return hosts


def _spn_instance_host(spn: str) -> str:
    """Return the instance host of an SPN (``serviceclass/instance[:port][/name]``).

    The instance is the token after the first ``/``; an optional ``:port`` and an
    optional ``/servicename`` suffix are dropped. Returns ``""`` for a malformed
    SPN with no instance.
    """
    text = str(spn or "").strip()
    if "/" not in text:
        return ""
    instance = text.split("/", 1)[1].strip()
    instance = instance.split("/", 1)[0]
    instance = instance.split(":", 1)[0]
    return instance.strip()


def _exclude_adcs_ca_http_spns(
    http_spns: list[str], adcs_ca_hosts: set[str]
) -> list[str]:
    """Drop HTTP SPNs whose instance host is an ADCS CA web-enrollment endpoint.

    ADCS/ESC8 detection owns those hosts' Kerberos-relay story, so the generic
    HTTP-SPN surface finding would be a duplicate on the same asset. Host matching
    is alias-aware (IP <-> short <-> FQDN <-> ``HOST$``) via the canonical
    resolver. Non-ADCS HTTP SPNs are kept unchanged, so a principal carrying both
    a CA and a non-CA HTTP SPN still surfaces only for the non-CA endpoint.
    """
    if not adcs_ca_hosts:
        return http_spns
    kept: list[str] = []
    for spn in http_spns:
        instance = _spn_instance_host(spn)
        if instance and any(
            hosts_match(instance, ca_host) for ca_host in adcs_ca_hosts
        ):
            continue
        kept.append(spn)
    return kept


def _node_is_roastable_candidate(node: Any) -> bool:
    """Return whether this node belongs to the offline-Kerberos-cracking surface.

    ONE rule with two readers: :func:`derive_roasting_edges` gates its
    Kerberoasting / ASREPRoasting derivation on it, and
    :func:`_finalize_enumerated_surface_census` completes the census it feeds,
    counting the same population as the
    denominator of the ``kerberos`` positive control. Keeping them as one
    predicate is what makes the recorded count the count of what the derivation
    actually walked, rather than a second similar-looking walk that can drift
    away from it.

    A managed service account is excluded through the cross-tier predicate
    ``adscan_core.kerberos_roasting`` (never the fragile trailing-``$``
    heuristic): its password is directory-generated and 240 characters of
    random, so it is not crackable offline and belongs to neither the numerator
    nor the denominator. That predicate is the SAME one the inventory queries
    and the web product's identity views apply, so the edge this derivation
    writes and the lists those surfaces render cannot disagree about who is
    exposed.

    Both attributes must be PRESENT on the node, not merely falsy. An account
    whose userAccountControl or SPN list was never read cannot be declared clear
    of a surface derived from them, and reading a missing key as ``False`` is how
    a partial collection would manufacture a green. The one site that builds a
    user payload writes both, so this costs nothing on the real path and closes
    the hole on any future one.
    """
    return (
        node.kind == "User"
        and not _password_is_ad_managed(_node_account_signals(node))
        and _node_is_enabled(node)
        and "hasspn" in node.properties
        and "dontreqpreauth" in node.properties
    )


def _node_is_roastable(node: Any) -> bool:
    """Return whether a candidate account is exposed to offline ticket cracking.

    The abusable condition behind both techniques the ``kerberos`` surface
    covers: a published service principal name (a service ticket anyone
    authenticated can request) or Kerberos pre-authentication disabled (an
    AS-REP anyone can request).
    """
    return _node_bool_property(node, "hasspn") or _node_bool_property(
        node, "dontreqpreauth"
    )


def _new_surface_tallies() -> dict[str, Any]:
    """Return one empty :class:`SurfaceTally` per declared enumerated surface.

    Created BEFORE the derivation passes run, so each pass counts the population
    it is already walking instead of a later pass walking a similar-looking one.
    An empty tally resolves to ``not_assessed``, which is the correct state for a
    pass that never ran.
    """
    from adscan_core.reporting.enumerated_surface_evidence import (  # noqa: PLC0415
        ENUMERATED_SURFACE_DEFINITIONS,
        SurfaceTally,
    )

    return {
        surface: SurfaceTally(surface=surface)
        for surface in ENUMERATED_SURFACE_DEFINITIONS
    }


def _tier0_predicate(
    payload_by_sid: dict[str, dict[str, Any]],
) -> Callable[[str], bool]:
    """Return a SID -> "is this principal Tier 0" predicate over stamped payloads.

    Reads the membership-aware ``privilege_tier`` stamp
    (:func:`_stamp_privilege_tier_on_payloads`), never the legacy ``isTierZero``
    boolean. An unstamped or unknown principal answers ``False``: a delegated
    right whose holder cannot be graded must withhold the positive control
    rather than be waved through as administrative.
    """
    from adscan_internal.services.compromise_class import (  # noqa: PLC0415
        node_is_tier0_by_stamped_label,
    )

    def _is_tier0(sid: str) -> bool:
        payload = payload_by_sid.get(str(sid or "").upper())
        return bool(payload) and node_is_tier0_by_stamped_label(payload)

    return _is_tier0


def _finalize_enumerated_surface_census(
    result: CollectionResult,
    tallies: dict[str, Any],
    is_tier0: Callable[[str], bool],
) -> dict[str, dict[str, Any]]:
    """Complete the census the derivation passes filled, and serialize it.

    The ``kerberos`` and ``credential_access`` tallies arrive already counted by
    the passes that enumerated them. The ``acl_ace`` surface is completed here
    because its two halves are produced in different layers: the LDAP collector
    counts the security descriptors it READ (the denominator, and the only layer
    that knows it), while whether a derived right is abusable depends on its
    holder's stamped privilege tier, which first exists at this pass.

    See ``adscan_core.reporting.enumerated_surface_evidence`` for the three-state
    resolution this feeds, and for why a zero denominator can never resolve to a
    pass.
    """
    from adscan_core.reporting.enumerated_surface_evidence import (  # noqa: PLC0415
        ENUMERATED_SURFACE_DEFINITIONS,
    )

    acl = tallies.get("acl_ace")
    if acl is not None:
        acl.note_enumerated(
            examined=result.security_descriptors_parsed,
            secondary=result.access_control_entries_examined,
        )
        # Matched against the surface definition's own technique list, so there
        # is no second taxonomy of "which relations count" to keep in step with
        # the catalogue. The catalogue keys ARE the lowercased relation names,
        # and a drift test fails if that stops being true.
        acl_relations = set(
            ENUMERATED_SURFACE_DEFINITIONS["acl_ace"].covered_techniques
        )
        from adscan_internal.services.graph_build.edge_view import (  # noqa: PLC0415
            edges_of,
        )

        for edge in edges_of(result.edges, acl_relations):
            if str(edge.source or "") != "acl_parser":
                continue
            if str(edge.relation or "").strip().lower() not in acl_relations:
                continue
            if not is_tier0(edge.source_object_id):
                acl.record_qualifying()
        # A descriptor that parsed with no DACL is an unresolved object, not a
        # clean one (under MS-DTYP a NULL DACL grants everyone full control), so
        # it withholds the green.
        acl.record_qualifying(result.security_descriptors_without_dacl)

    return {
        surface: tally.as_census()
        for surface, tally in tallies.items()
        if tally is not None
    }


def _node_account_signals(node: Any) -> AccountSignals:
    """Build the cross-tier account-class signals for a collector node.

    A :class:`CollectorNode` keeps ``kind`` and ``distinguished_name`` beside
    its property bag rather than inside it, so the generic
    :meth:`AccountSignals.from_properties` adapter would miss both. Filling them
    in here is what lets the collector, the inventory queries and the web
    product reach the same verdict from three different record shapes.
    """
    props = node.properties if isinstance(node.properties, dict) else {}
    signals = AccountSignals.from_properties(props)
    return AccountSignals(
        account_type=signals.account_type,
        is_gmsa=signals.is_gmsa,
        object_classes=signals.object_classes,
        distinguished_name=signals.distinguished_name
        or str(getattr(node, "distinguished_name", "") or ""),
        kind=signals.kind or str(getattr(node, "kind", "") or ""),
    )


def _node_account_type(node: Any) -> str:
    """Human account-type label for the HTTP-SPN finding evidence."""
    explicit = str(node.properties.get("account_type") or "").strip().lower()
    if explicit:
        return explicit
    if _node_is_managed_service_account(_node_account_signals(node)):
        return "gmsa"
    return "computer" if node.kind == "Computer" else "user"


def collect_http_spn_findings(
    result: CollectionResult, *, sid_to_graph_id: dict[str, str]
) -> None:
    """Classify the ``HTTP/*`` SPNs of uncrackable accounts into ``result.http_spn_findings``.

    Not a graph edge: an observed configuration exposure surfaced as a report
    finding (emitted in ``cli/intelligence.py`` alongside the trust-posture
    findings, reaching both the PDF and the web CTEM). Reads the SAME collected
    SPN list the kerberoastable derivation reads, with the SAME account-type
    classification, so the two agree on what a gMSA is.
    """
    # ADCS Enterprise CA web-enrollment hosts carry an ``HTTP/<ca>`` SPN, but the
    # ADCS collector already owns that host's Kerberos-relay story (ESC8 detection
    # plus the active EPA probe in ``adcs_web_enrollment_probe``). Collect those
    # host identifiers up front so the generic HTTP-SPN surface finding below is
    # suppressed there — otherwise the same asset is reported twice.
    adcs_ca_hosts = _adcs_ca_web_enrollment_hosts(result)
    for node in result.nodes.values():
        if not sid_to_graph_id.get(node.object_id.upper()):
            continue
        if node.kind not in {"User", "Computer"}:
            continue
        # Fire only for structurally UNCRACKABLE accounts — machine accounts
        # and gMSAs (random 120/240-char passwords kerberoast cannot crack),
        # where the relay-surface / EPA-hardening signal is the UNIQUE finding.
        # A normal USER account carrying an HTTP/* SPN is already owned by the
        # Kerberoasting finding (offline password cracking is the direct,
        # higher-value attack); emitting a relay-surface finding on the same
        # account is the same one-asset/two-findings duplication we remove for
        # the ADCS CA vs ESC8 case.
        account_type = _node_account_type(node)
        if account_type not in {"computer", "gmsa"}:
            continue
        http_spns = _exclude_adcs_ca_http_spns(
            _http_service_spns(_node_list_property(node, "serviceprincipalnames")),
            adcs_ca_hosts,
        )
        if http_spns:
            result.http_spn_findings.append(
                HttpSpnFinding(
                    object_id=node.object_id,
                    samaccountname=node.samaccountname,
                    kind=node.kind,
                    account_type=account_type,
                    distinguished_name=node.distinguished_name,
                    http_spns=tuple(http_spns),
                    enabled=node.enabled,
                )
            )


def derive_roasting_edges(
    graph: dict[str, Any],
    *,
    result: CollectionResult,
    sid_to_graph_id: dict[str, str],
    kerberos_tally: Any | None = None,
    edge_index: "attack_graph_service.EdgeUpsertIndex | None" = None,
) -> int:
    """Derive ``Kerberoasting`` / ``ASREPRoasting`` edges from collected account properties.

    ``kerberos_tally`` counts the offline-cracking surface the walk examines into
    the enumerated-surface census (optional; the graph build passes none).
    """
    # Kerberoasting and AS-REP Roasting only require the requester to be
    # *authenticated* against the target realm — NOT to be a member of the
    # target domain's local Domain Users group. The correct broadest actor is
    # therefore Authenticated Users (well-known SID S-1-5-11), which a
    # foreign-forest authenticated principal is also a member of (a trusted-forest
    # user CAN kerberoast/AS-REP-roast the target domain). Sourcing these edges
    # from Domain Users (513) — which contains only the domain's own users —
    # silently drops every cross-forest roasting path. The Authenticated Users
    # node is guaranteed present: the orchestrator injects it and wires every
    # enabled principal's MemberOf into it before persistence runs.
    authenticated_users_id = _find_authenticated_users_graph_id(sid_to_graph_id)
    if edge_index is None:
        edge_index = attack_graph_service.EdgeUpsertIndex()
    created = 0
    for node in result.nodes.values():
        graph_id = sid_to_graph_id.get(node.object_id.upper())
        if not graph_id:
            continue
        # A gMSA (``account_type == "gmsa"``) has a KDC-managed 240-char random
        # password, so it is NEVER a valid kerberoast / AS-REP target even though
        # it is a ``User`` node that commonly carries SPNs. Exclude it explicitly
        # by account type (not the fragile trailing-``$`` heuristic) so no
        # false-positive Kerberoasting / ASREPRoasting edge is derived on an
        # account nobody can crack offline.
        roastable_candidate = _node_is_roastable_candidate(node)
        # Census of the offline-cracking surface, counted on the SAME walk and
        # behind the SAME predicate as the derivation below, and deliberately
        # independent of whether the Authenticated Users node resolved: the two
        # attributes were read off this account either way.
        if kerberos_tally is not None and roastable_candidate:
            kerberos_tally.record(qualifying=_node_is_roastable(node))
        if roastable_candidate and authenticated_users_id:
            if _node_bool_property(node, "hasspn"):
                created += _upsert_derived_edge(
                    graph,
                    edge_index=edge_index,
                    from_id=authenticated_users_id,
                    to_id=graph_id,
                    relation="Kerberoasting",
                    notes={
                        "collector_method": "derived_kerberoastable_user",
                        "source_property": "servicePrincipalName",
                        "serviceprincipalnames": _node_list_property(
                            node, "serviceprincipalnames"
                        ),
                    },
                )
            if _node_bool_property(node, "dontreqpreauth"):
                created += _upsert_derived_edge(
                    graph,
                    edge_index=edge_index,
                    from_id=authenticated_users_id,
                    to_id=graph_id,
                    relation="ASREPRoasting",
                    notes={
                        "collector_method": "derived_asreproastable_user",
                        "source_property": "userAccountControl",
                    },
                )
    return created
