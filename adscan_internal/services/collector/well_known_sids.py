"""Well-known Windows SID synthetic node injection for the native collector.

These SIDs are OS-level security principals that never appear as LDAP objects
in Active Directory. When ACEs reference them (e.g. Authenticated Users → ADCSESC1)
the LDAP collector has no node for the source SID, so persistence silently drops
the edge. This module injects synthetic CollectorNode entries for every well-known
SID that appears as a dangling edge endpoint in a CollectionResult.

The SID DATA and the client-facing label helpers (display name, dynamic-identity
predicate, humanizer) live in the LEAF module
:mod:`adscan_internal.services.well_known_principals` — importable without the
native collector stack (this package's ``__init__`` drags in aiosmb/badldap) so
the report / writeup / web render surfaces can humanize a principal label. They
are re-exported here for the collector's own use, so there is ONE data source.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

# Re-exported from the import-safe leaf SSOT (do not duplicate the tables here).
from adscan_internal.services.well_known_principals import (  # noqa: F401
    DYNAMIC_IDENTITY_SIDS,
    NON_GRANTEE_SIDS,
    _TIER_ZERO_WELL_KNOWN,
    _WELL_KNOWN,
    humanize_principal_label,
    is_dynamic_identity,
    principal_is_dynamic_identity,
    resolve_sid_display_name,
    well_known_sid_display_name,
)

if TYPE_CHECKING:
    from adscan_internal.services.collector.models import CollectionResult, CollectorNode


def _make_well_known_node(sid_upper: str) -> "CollectorNode | None":
    from adscan_internal.services.collector.models import CollectorNode

    entry = _WELL_KNOWN.get(sid_upper)
    if entry is None:
        return None
    name, kind = entry
    return CollectorNode(
        object_id=sid_upper,
        kind=kind,  # type: ignore[arg-type]
        name=f"{name}@WELLKNOWN",
        domain="WELLKNOWN",
        highvalue=sid_upper in _TIER_ZERO_WELL_KNOWN,
        properties={
            "synthetic": True,
            "well_known_sid": True,
            "display_name": name,
        },
    )


def inject_all_well_known_sid_nodes(result: "CollectionResult") -> int:
    """Proactively inject synthetic nodes for every well-known SID.

    Called before SMB/share collection so that ACE-principal lookups in the
    share collector find S-1-5-11 (Authenticated Users), S-1-1-0 (Everyone),
    etc., and create the corresponding ReadShare/WriteShare edges instead of
    silently dropping them.  Returns the number of nodes injected.
    """
    injected = 0
    for sid_upper in _WELL_KNOWN:
        if sid_upper in result.nodes:
            continue
        node = _make_well_known_node(sid_upper)
        if node is None:
            continue
        result.add_node(node)
        injected += 1
    return injected


# ---------------------------------------------------------------------------
# Implicit AD memberships not stored as LDAP ``member``/``memberOf``
# ---------------------------------------------------------------------------
#
# Active Directory has several classes of group membership that are computed
# at runtime (by the SAM/LSA on logon, by the KDC during ticket issuance, or
# by the LSASS authentication subsystem) instead of being persisted as
# ``member``/``memberOf`` LDAP attributes.  Without explicit MemberOf edges
# in the attack graph, the DFS path builder cannot reach any ACE granted to
# these groups and the corresponding attack steps (SYSVOL/NETLOGON read,
# ADCS template enrollment, ESC13 group membership, DA-relay paths via
# Enterprise Domain Controllers, etc.) never surface as paths even though
# the raw ACE edges exist in the graph.
#
# Inferring these virtual MemberOf edges in the collector propagates them to
# BOTH attack_graph.json and memberships.json via the existing persistence
# pipeline (``persistence._write_memberships`` filters on relation==MemberOf),
# matching the architectural pattern used by ``analyze_group_inferences``
# for CanRDP/CanPSRemote.

# OS-computed authentication groups — every authenticated principal is a
# member regardless of identity (User or Computer, regular or DC).
_AUTHENTICATION_SIDS: tuple[str, ...] = (
    "S-1-5-11",  # Authenticated Users
    "S-1-1-0",  # Everyone
)

# Forest-level implicit DC membership.  Every domain controller (regular and
# read-only) is implicitly a member of "Enterprise Domain Controllers" in
# the context of the forest it belongs to.
_ENTERPRISE_DC_SID = "S-1-5-9"

# Primary-group RIDs for Computer accounts — used to detect DCs.
# - 516: Domain Controllers (read-write)
# - 521: Read-only Domain Controllers
_DC_PRIMARY_GROUP_RIDS: frozenset[int] = frozenset({516, 521})


def _node_primary_group_id(node: "CollectorNode") -> int | None:
    """Return the integer primaryGroupID stored on a User/Computer node."""
    for key in ("primarygroupid", "primaryGroupID", "primary_group_id"):
        value = node.properties.get(key)
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return None


def _domain_sid_prefix(sid: str) -> str:
    """Return the ``S-1-5-21-X-Y-Z`` domain prefix from a principal SID."""
    sid_clean = str(sid or "").strip().upper()
    if not sid_clean.startswith("S-1-5-21-"):
        return ""
    parts = sid_clean.split("-")
    if len(parts) < 5:
        return ""
    return "-".join(parts[:7])  # S-1-5-21-X-Y-Z (drop trailing RID)


def analyze_implicit_well_known_memberships(result: "CollectionResult") -> int:
    """Infer all ``MemberOf`` edges that AD computes implicitly.

    Three classes of implicit membership are emitted as ``MemberOf`` edges
    so the attack-graph DFS path builder can reach ACL targets granted to
    these groups:

    1. **OS-computed authentication groups** — every enabled User and
       Computer is a member of ``S-1-5-11`` (Authenticated Users) and
       ``S-1-1-0`` (Everyone).  These are computed by the SAM/LSA on
       logon and never stored in LDAP.  Without these, ACEs to those
       SIDs (e.g. SYSVOL/NETLOGON ReadShare, ADCS Enroll for
       Authenticated Users, Everyone-readable shares) are unreachable.

    2. **Primary-group memberships** — AD does *not* include a
       principal's primary group in its ``memberOf`` attribute, only in
       ``primaryGroupID``.  Every enabled User is implicitly a member of
       its primary group (typically Domain Users / RID 513), every
       Computer is a member of Domain Computers (RID 515), every DC is a
       member of Domain Controllers (RID 516), every RODC is a member
       of Read-only Domain Controllers (RID 521).  Without the explicit
       MemberOf edge, AdminTo / GenericAll / share-access edges to those
       groups would be unreachable from concrete principals.

    3. **Enterprise Domain Controllers (S-1-5-9)** — every DC is
       implicitly a member of this forest-level group.  Cross-domain
       trust ACLs frequently grant rights to ``Enterprise Domain
       Controllers`` (e.g. DCSync rights), so DCs need an explicit
       MemberOf edge for paths that traverse those rights to surface.

    Mirrors the convention of ``analyze_group_inferences``: edges carry
    ``source="ldap"`` and ``method="group_inferred"``.  The notes field
    carries ``inference_kind`` so each class is identifiable for
    telemetry, debugging, and selective suppression.  Idempotent and
    cheap; safe to call multiple times.

    Returns the number of edges added.
    """
    from adscan_internal.services.collector.models import CollectorEdge

    # Pre-index existing MemberOf edges to avoid duplicates and respect any
    # explicit LDAP-derived membership the collector already persisted.
    existing: set[tuple[str, str, str]] = {
        (
            edge.source_object_id.upper(),
            edge.relation,
            edge.target_object_id.upper(),
        )
        for edge in result.edges
    }

    auth_targets = [sid for sid in _AUTHENTICATION_SIDS if sid in result.nodes]
    enterprise_dc_present = _ENTERPRISE_DC_SID in result.nodes

    def _add_edge(
        source_sid: str, target_sid: str, *, inference_kind: str
    ) -> bool:
        key = (source_sid.upper(), "MemberOf", target_sid.upper())
        if key in existing:
            return False
        existing.add(key)
        result.add_edge(
            CollectorEdge(
                source_object_id=source_sid.upper(),
                target_object_id=target_sid.upper(),
                relation="MemberOf",
                source="ldap",
                method="group_inferred",
                notes={
                    "inference_kind": inference_kind,
                    "rationale": _RATIONALE_BY_KIND[inference_kind],
                },
            )
        )
        return True

    added = 0
    for node in list(result.nodes.values()):
        if node.kind not in ("User", "Computer"):
            continue
        # Disabled accounts cannot authenticate, so they are NOT members of
        # any of the implicit authentication groups in practice.
        if node.enabled is False:
            continue
        # Synthetic well-known SID nodes don't represent real principals.
        if node.properties.get("well_known_sid"):
            continue
        source_sid = str(node.object_id or "").strip().upper()
        if not source_sid:
            continue

        primary_group_id = _node_primary_group_id(node)
        is_dc = node.kind == "Computer" and primary_group_id in _DC_PRIMARY_GROUP_RIDS

        # ── (1) Authenticated Users / Everyone — universal ──────────────
        # Skip highvalue (Tier-0) nodes — DCs are attack-graph terminals.
        # Outgoing auth-group edges from terminals cause the DFS to extend
        # past the target and the path-filter eliminates shorter paths
        # (e.g. AuthUsers→ReadShare→DC01$) as sub-sequences of longer
        # paths (AuthUsers→ReadShare→DC01$→MemberOf→Everyone), making
        # share-access paths from well-known SIDs invisible in the panel.
        if not node.highvalue:
            for target_sid in auth_targets:
                if _add_edge(
                    source_sid, target_sid, inference_kind="implicit_logon_membership"
                ):
                    added += 1

        # ── (2) Primary-group membership via primaryGroupID ─────────────
        # Normally skipped for highvalue (Tier-0) nodes — an outgoing
        # primary-group edge extends paths past the terminal and causes
        # sub-sequence filtering (same reason as the auth groups above).
        #
        # EXCEPTION — a DC machine account's primary group IS a
        # domain-takeover group (Domain Controllers 516 / RODC 521).  That
        # membership is the canonical kill-chain link
        # ``DC$ -> Domain Controllers -> DCSync -> Domain``: it is how
        # "compromise the DC = own the domain" is expressed.  Without it the
        # most fundamental AD attack path is unrepresentable — the DC$ node
        # has no path to the domain at all (primaryGroup membership is implicit
        # in AD, never present in the group's ``member`` attribute, so the
        # explicit memberOf collection cannot supply it).  So we emit it even
        # for the highvalue DC when the primary group is a DC group.
        emit_primary_group = primary_group_id is not None and (
            not node.highvalue or primary_group_id in _DC_PRIMARY_GROUP_RIDS
        )
        if emit_primary_group:
            domain_prefix = _domain_sid_prefix(source_sid)
            if domain_prefix:
                primary_group_sid = f"{domain_prefix}-{primary_group_id}"
                # Only emit if the primary-group node exists in the graph;
                # otherwise the edge would dangle.
                if primary_group_sid in result.nodes:
                    if _add_edge(
                        source_sid,
                        primary_group_sid,
                        inference_kind="primary_group_membership",
                    ):
                        added += 1

        # ── (3) Enterprise Domain Controllers (DCs only) ────────────────
        # Skip highvalue DCs for the same reason.
        if is_dc and enterprise_dc_present and not node.highvalue:
            if _add_edge(
                source_sid,
                _ENTERPRISE_DC_SID,
                inference_kind="enterprise_dc_membership",
            ):
                added += 1

    return added


_RATIONALE_BY_KIND: dict[str, str] = {
    "implicit_logon_membership": "OS-computed authentication group (SAM/LSA)",
    "primary_group_membership": "primaryGroupID attribute (not in LDAP memberOf)",
    "enterprise_dc_membership": "implicit forest-level membership for DCs",
}


def inject_well_known_sid_nodes(result: "CollectionResult") -> int:
    """Add synthetic nodes for well-known SIDs that appear in edges but have no node.

    Called after LDAP + ADCS collection, before persistence. Returns the number
    of synthetic nodes injected.
    """
    # Collect every SID referenced as source or target across all edges
    referenced: set[str] = set()
    for edge in result.edges:
        referenced.add(edge.source_object_id.upper())
        referenced.add(edge.target_object_id.upper())

    injected = 0
    for sid_upper in referenced:
        if sid_upper in result.nodes:
            continue
        node = _make_well_known_node(sid_upper)
        if node is None:
            continue
        result.add_node(node)
        injected += 1

    return injected
