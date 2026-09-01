"""Attack graph core utilities (pure functions).

This module contains the core logic for computing attack paths from an
`attack_graph.json` structure. It is intentionally written without any
dependency on the interactive CLI "shell" object, so it can be reused by both
the CLI and the web backend.

Notes:
    - The core functions operate on the in-memory attack graph dict structure
      (schema_version 1.1). Callers are responsible for loading/saving files.
    - Callers may optionally "enrich" the graph (e.g., inject runtime MemberOf
      edges) before calling these functions. The core treats the graph as the
      source of truth and performs no network calls.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Callable, Mapping
from typing import Any

from adscan_core.reporting.attack_path_memory_gate import (
    DfsMemoryBudget,
    _AttackPathMemoryBudgetExceeded,
)
from adscan_internal.services import attack_path_progress
from adscan_internal.services.domain_controller_classifier import (
    RID_DOMAIN_CONTROLLERS,
    RODC_TARGET_PRIORITY_RANK,
    _node_properties,
    classify_computer_node_role,
    node_is_rodc_computer,
)
from adscan_internal.models.domain import resolve_domain_controllers
from adscan_internal.services.adcs_target_filter import is_adcs_tier_zero_group
from adscan_internal.services.privileged_group_classifier import (
    classify_privileged_membership,
    is_dependency_only_tier_zero_group,
    is_future_followup_tier_zero_group,
    is_followup_terminal_group,
    is_graph_extension_group,
    normalize_group_name,
)

from adscan_internal.services.attack_step_support_registry import (
    CONTEXT_ONLY_RELATIONS,
)
from adscan_internal.services.attack_step_catalog import (
    context_requirement_satisfied,
    derive_step_display_status,
    provides_context_for_relation,
    required_context_for_relation,
)
from adscan_internal.services.smb_exclusion_policy import is_globally_excluded_smb_share
from adscan_internal.services.destructive_action_policy import (
    safety_abstention_notes as _safety_abstention_notes,
)
from adscan_internal.workspaces import read_json_file, write_json_file
from adscan_internal.workspaces.state import migrate_legacy_attack_graph
from adscan_internal.services.tier_lattice import (
    AttackCore,
    attack_core_is_prefix,
    attack_core_is_subsequence,
    attack_core_signature,
    domain_compromise_tier_from_record,
    edge_grants_local_admin_session as _edge_grants_local_admin_session,
    stamp_records_domain_compromise_tier,
    stamp_records_target_tier,
)

_LOCAL_REUSE_RELATION_KEY = "localadminpassreuse"
_SHARE_ACCESS_RELATION_KEYS = {"readshare", "writeshare", "fullcontrolshare"}

# ── Target-mode normalization ─────────────────────────────────────────────────
# Canonical target modes for path computation.  Any value outside this set
# is normalised to the ``"domain"`` fallback so callers never see an unknown
# mode reach the DFS.  Adding a new mode is a one-line change here; every
# consumer that calls ``normalize_target_mode`` picks it up automatically.
_VALID_TARGET_MODES: frozenset[str] = frozenset({"tier0", "impact", "object", "domain"})


def normalize_target_mode(value: str | None) -> str:
    """Return a canonical, lower-cased target_mode string.

    Recognises four modes:

    ``"tier0"``
        DFS terminates at any Tier-0 / ``direct_compromise`` node (Domain
        Admins, Domain Controllers, BUILTIN\\\\Administrators, …).

    ``"impact"``
        DFS terminates at high-impact nodes (superset of tier0).

    ``"object"``
        DFS terminates **only** at Domain-kind nodes (e.g. ``ESSOS.LOCAL``).
        This allows paths to extend past Tier-0 groups through kill-chain edges
        like DCSync, producing complete kill chains to the domain object.
        Use this for explicit object-targeted queries and for the default
        authenticated-scan display (``target_mode="object"`` in the CLI).

    ``"domain"``
        Legacy alias. DFS behaves identically to ``"tier0"`` but post-
        processing uses ``keep_longest`` path collapse (holistic domain view).

    Any other value normalises to ``"domain"``.
    """
    mode = str(value or "domain").strip().lower()
    return mode if mode in _VALID_TARGET_MODES else "domain"


# ── Credential-context DFS guard ──────────────────────────────────────────────
# Credential-context resolution is delegated to the catalog SSOT
# (provides_context_for_relation / required_context_for_relation). Both are
# punctuation-insensitive, so the underscored MSSQL catalog keys resolve from the
# PascalCase relation the graph emits (XpCmdshell, MssqlTokenTheftEscalation);
# both fall back to the safe defaults ("none" provides / "user_credentials"
# requires) for a relation missing from the catalog.
_MEMBEROF_KEY = "memberof"
_LOCAL_REUSE_KEY = "localadminpassreuse"
# Access-capability edges that do NOT change which OS credentials the attacker
# holds and do NOT grant OS local admin on their own:
#   * CanRDP / CanPSRemote — user-level RDP/WinRM session: execution on a new
#     host as the SAME user, no admin guarantee.
#   * SQLAdmin / SQLAccess — MSSQL sysadmin/access: a *service* capability.
# The catalog annotates all of them ``access_capability_only`` (→ provides
# ``local_admin_session``) so they sort alongside AdminTo for ranking, but for
# the credential-context DFS guard they must be transparent — exactly like
# MemberOf / LocalAdminPassReuse: a pivot that does not change held credentials.
# Without this, a dump-type edge (DumpLSA / DumpLSASS / DumpSAM, which requires
# ``local_admin_session``) chains directly after them — e.g. the false paths
# ``User -> CanRDP -> Computer -> DumpLSA`` or ``User -> SQLAdmin -> Computer ->
# DumpLSA`` — even though RDP/WinRM/SQL access does NOT grant the registry /
# LSA-secrets read DumpLSA needs. Transparency forces the guard to evaluate the
# dump against the context held BEFORE the capability, so a dump only chains
# when a genuine local-admin edge (AdminTo / ReadLAPSPassword) preceded it.
#
# NOTE (SQLAdmin, deferred): SQLAdmin CAN legitimately reach a dump via the
# separate ``mssql_seimpersonate_escalation`` edge (SQL sysadmin -> SeImpersonate
# -> SYSTEM -> dump). Modelling that bridge correctly (so the escalation grants
# ``local_admin_session``) is more complex and intentionally left for later; for
# now SQLAdmin is treated like the other capability pivots and the direct
# ``SQLAdmin -> DumpLSA`` is suppressed. The SeImpersonate/token-theft escalation
# edges themselves still chain — they require only ``user_credentials``, which
# the look-back satisfies — so the proper fix is additive.
_CANRDP_KEY = "canrdp"
_CANPSREMOTE_KEY = "canpsremote"
_SQLADMIN_KEY = "sqladmin"
_SQLACCESS_KEY = "sqlaccess"
# MssqlLinkedServerLateral (TrustedLink): a SQL-session pivot to a second
# instance. Transparent to the OS credential-context guard — it does not change
# which OS credentials the attacker holds (the identity switch is at the SQL
# layer). Being transparent lets the xp_cmdshell derived self-loop after it
# evaluate against the start-of-path user_credentials and chain. Its restriction
# to MSSQL arrivals is enforced separately by the positive MSSQL-lane gate below,
# not by credential-context.
_MSSQL_LINKED_KEY = "mssqllinkedserverlateral"
# Relations that are transparent to credential context — they change the
# principal identity (or lateral-pivot the attacker to a new host) but do NOT
# change which credentials the attacker holds.  Any edge that follows one of
# these is evaluated against the context of the *previous* non-transparent edge
# (or the implicit start-of-path user_credentials when the path is empty).
_CONTEXT_TRANSPARENT_KEYS: frozenset[str] = frozenset(
    {
        _MEMBEROF_KEY,
        _LOCAL_REUSE_KEY,
        _CANRDP_KEY,
        _CANPSREMOTE_KEY,
        _SQLADMIN_KEY,
        _SQLACCESS_KEY,
        _MSSQL_LINKED_KEY,
    }
)


# ── MSSQL-session edge gate — MSSQL lateral/execution chains only off an MSSQL
# access arrival.  ``MssqlLinkedServerLateral`` (and, when later un-gated, the
# in-SQL escalations) extend the SQL SESSION — they are a property of the SQL
# session, not of OS local admin.  So they must chain only after an MSSQL access
# lane (SQLAccess / SQLAdmin / a prior linked-server hop), NEVER after an OS
# access edge (AdminTo / CanRDP / CanPSRemote).  This is the positive mirror of
# ``_host_control_withheld_after_access``: instead of withholding host-control
# edges after a *user-level* arrival, it withholds MSSQL-session edges after a
# *non-MSSQL* arrival.
_MSSQL_SESSION_EDGE_KEYS: frozenset[str] = frozenset({_MSSQL_LINKED_KEY})


def _mssql_session_edge_withheld_off_non_mssql_arrival(
    path_relations: list[str],
    candidate_relation: str,
) -> bool:
    """Return True when an MSSQL-session edge is reached off a non-MSSQL arrival.

    Walks back to the most recent access lane in ``path_relations``.  If that
    lane is an MSSQL lane (SQLAccess / SQLAdmin / a prior linked-server hop) the
    candidate is allowed; if it is an OS lane (AdminTo / CanRDP / …) the
    MSSQL-session candidate is withheld.  A candidate with no access lane at all
    in the path (e.g. a linked-server edge sourced directly, not off a SQL
    foothold) is withheld — a linked server is reachable only through a SQL
    session on the source instance.
    """
    if str(candidate_relation or "").strip().lower() not in _MSSQL_SESSION_EDGE_KEYS:
        return False

    from adscan_internal.services.post_exploitation.access_followups import (  # noqa: PLC0415
        get_access_lane,
    )

    for rel in reversed(path_relations):
        lane = get_access_lane(rel)
        if lane is None:
            continue
        return not lane.is_mssql_lane
    return True


# ── Access-edge gating — arrival != ownership ──────────────────────────────
# Spec: docs/superpowers/specs/2026-06-01-access-edge-gating-followups-design.md
#
# An access edge (EdgeKind.AUTH: CanPSRemote, CanRDP, ExecuteDCOM, AdminTo,
# SQLAdmin, SQLAccess) terminates in a *session on a host*.  It does NOT confer
# the host principal's outbound graph privileges.  After an access-edge arrival
# the host's raw outbound *control / escalation / membership* edges are withheld;
# the path may continue only via a follow-up the access type unlocks.
#
# The ONLY follow-up that re-enables the host's own outbound control edges is the
# self-credential DumpLSA bridge (reads the host machine account secret →
# "becomes" the host Computer principal).  It is unlocked ONLY by LOCAL-ADMIN
# access (AdminTo / ReadLAPSPassword), never by a user-level WinRM / RDP session.
#
# Implementation note on the AdminTo case: a *direct* host control edge after a
# bare AdminTo (no DumpLSA) is already blocked by the credential-context guard
# (AdminTo provides local_admin_session; a control edge requires user_credentials,
# which local_admin_session does not satisfy), and the implicit DumpLSA overlay
# re-enables it.  The gate below closes the remaining gap: the *user-level* access
# edges (CanPSRemote / CanRDP / ExecuteDCOM / SQLAccess) were context-transparent,
# so a credential recovered BEFORE the access edge leaked the host's control edges
# straight through the pivot.  This is the HTB Pirate false-positive factory:
#   ReadGMSAPassword → CanPSRemote → DC01$ → ADCSESC7 → DOMAIN ADMINS.
#
# EdgeKinds that represent traversing the HOST's own outbound privileges (and so
# must be withheld after a non-self-credential access arrival).  AUTH and TRUST
# edges are not host-control traversals; DERIVED edges are follow-ups (handled by
# the self-credential bridge logic), so they are not gated here.
_HOST_CONTROL_GATED_EDGE_KINDS: frozenset[str] = frozenset(
    {"control", "escalation", "membership"}
)


def _candidate_is_host_control_edge(candidate_relation: str) -> bool:
    """Return True when the candidate edge traverses a host's outbound privilege.

    These are the edges that must be withheld after a non-self-credential access
    arrival (control / escalation / membership EdgeKinds).  Imported lazily to
    respect the documented ``edge_kind`` import-cycle avoidance in this module.
    """
    from adscan_internal.services.edge_kind import classify_edge_kind  # noqa: PLC0415

    return classify_edge_kind(candidate_relation).value in _HOST_CONTROL_GATED_EDGE_KINDS


def _host_control_withheld_after_access(
    path_relations: list[str],
    candidate_relation: str,
) -> bool:
    """Return True when ``candidate_relation`` must be withheld as a host-control
    edge traversed off a host reached via an access edge that has not "become"
    the host.

    Walks back from the end of ``path_relations``.  If a self-credential DumpLSA
    follow-up is seen before any access edge, the path has already "become" the
    host machine account, so the candidate is allowed.  If a LOCAL-ADMIN access
    edge that unlocks the self-credential bridge is seen, the candidate is allowed
    (the credential-context guard + DumpLSA overlay handle that lane).  If a
    user-level access edge (which does NOT unlock the bridge) is the most recent
    access-relevant relation, the host-control candidate is withheld.
    """
    from adscan_internal.services.post_exploitation.access_followups import (  # noqa: PLC0415
        access_unlocks_self_credential,
        get_access_lane,
        grants_host_system_session,
        is_self_credential_followup,
    )

    if not _candidate_is_host_control_edge(candidate_relation):
        return False

    for rel in reversed(path_relations):
        # A self-credential follow-up "becomes" the host machine account →
        # the host's own outbound control edges are legitimately available. The
        # MSSQL SYSTEM-escalation self-loops (SeImpersonate / Token-Theft) reach
        # NT AUTHORITY\SYSTEM, which IS the host machine account — the same
        # ownership, so they likewise stop the walk-back and re-enable the host's
        # outbound control edges (incl. the synthetic direct-DCSync bridge on a
        # writable DC). They must be seen BEFORE the SQL access lane that unlocked
        # them (SQLAccess / SQLAdmin / MssqlLinkedServerLateral), which does not
        # itself confer self-credential and would otherwise withhold the bridge.
        if is_self_credential_followup(rel) or grants_host_system_session(rel):
            return False
        lane = get_access_lane(rel)
        if lane is None:
            continue
        # First (most recent) access edge encountered with no intervening
        # self-credential follow-up.  LOCAL-ADMIN access that unlocks the
        # self-credential bridge is allowed through here (the credential-context
        # guard + DumpLSA overlay enforce the correct DumpLSA step); a user-level
        # access edge withholds the host-control candidate.
        return not access_unlocks_self_credential(rel)

    # No access edge in the path → the principal still owns its own privileges.
    return False


def _candidate_is_dc_dcsync_bridge(candidate_edge: dict[str, Any] | None) -> bool:
    """Return True for the synthetic direct-DCSync overlay edge (F6).

    Identifies the ``Computer -> DCSync -> Domain`` edge minted by
    :func:`_build_implicit_dc_dcsync_overlay`.  This edge models the DIRECT
    replication capability an admin/SYSTEM context already has on a writable DC,
    so it must bypass the arrival-!=-ownership gates that (correctly) withhold a
    REAL DCSync edge until the DumpLSA self-loop has "become" the machine
    account.  Only the synthetic edge — recognised by its ``synthesized_from``
    marker — is exempted; real DCSync edges remain fully gated.
    """
    if not isinstance(candidate_edge, dict):
        return False
    notes = candidate_edge.get("notes")
    return (
        isinstance(notes, dict)
        and notes.get("synthesized_from") == "implicit_dc_dcsync_bridge"
    )


def _edges_chain_ok(
    path_relations: list[str],
    candidate_relation: str,
    *,
    candidate_edge: dict[str, Any] | None = None,
) -> bool:
    """Return True when ``candidate_relation`` may extend the current path.

    Two independent gates:

    1. **Access-edge host-control gate** (arrival != ownership) — a host-control
       edge (control / escalation / membership EdgeKind) traversed off a host
       reached via a user-level access edge is withheld unless a self-credential
       DumpLSA follow-up has "become" the host.  Evaluated FIRST and for ALL
       candidate kinds, including the otherwise context-transparent ``MemberOf``.

    2. **Credential-context gate** — walks back through ``path_relations``
       skipping transparent-context edges (MemberOf, LocalAdminPassReuse,
       CanPSRemote, CanRDP, SQLAdmin, SQLAccess) which change principal identity
       (or lateral-pivot the host) but not what credentials the attacker holds.
       Returns True for an empty path (start of traversal) because the initial
       principal always has their own ``user_credentials``.

    The synthetic direct-DCSync overlay edge (F6, see
    :func:`_candidate_is_dc_dcsync_bridge`) bypasses Gate 2 (credential-context)
    only; Gate 1 (host-control withholding) stays active — so the synthetic edge
    is reachable only off a LOCAL-ADMIN arrival on the DC and is withheld after a
    user-level session.  It models the direct replication capability an admin
    session already holds on a writable DC.  Real DCSync edges
    (``candidate_edge=None`` or no synthesized marker) stay fully gated.
    """
    cand_rel = str(candidate_relation or "").strip().lower()

    # Gate 1 — access-edge host-control withholding (runs before the transparent
    # early-return so a host's own MemberOf is also gated after a user-level
    # access arrival).  This gate is intentionally LEFT ACTIVE for the synthetic
    # DCSync bridge too: it is exactly what restricts the direct DCSync to a
    # LOCAL-ADMIN arrival on the DC (AdminTo / AllowedToDelegate+T2A4D / SPNJack /
    # NTLMv1RelayRBCD) and withholds it after a user-level CanRDP / CanPSRemote
    # session — which has no replication capability.
    if _host_control_withheld_after_access(path_relations, cand_rel):
        return False

    # Gate 1.5 — MSSQL-session edges (linked-server lateral) chain ONLY off an
    # MSSQL access arrival, never off an OS access edge (AdminTo/CanRDP/…) nor
    # sourced with no SQL foothold in the path.  The linked-server login mapping
    # is a property of the SQL session, so the lateral hop belongs to the MSSQL
    # lane, not the OS lane.
    if _mssql_session_edge_withheld_off_non_mssql_arrival(path_relations, cand_rel):
        return False

    # F6 — the synthetic direct-DCSync bridge IS the modeled direct replication
    # capability an admin session already holds on a writable DC.  It passes Gate
    # 1 above (so it is reachable only off a local-admin arrival), but Gate 2
    # below would block it because a bare local_admin_session does not satisfy
    # DCSync's user_credentials requirement.  The whole point of this edge is
    # that on a DC you DO NOT need to first dump the machine credential — running
    # as SYSTEM / impersonating a DA replicates immediately — so bypass Gate 2
    # for this synthetic edge ONLY.  Real DCSync edges remain fully gated.
    #
    # But ONLY take the shortcut when no DumpLSA self-credential follow-up has
    # already run on this path: the direct edge models the "skip DumpLSA" route.
    # Once DumpLSA has "become" the machine account, the canonical continuation
    # is the host's own MemberOf -> Domain Controllers -> DCSync (the existing
    # DumpLSA path).  Suppressing the synthetic edge in that case avoids a
    # redundant ``...,DumpLSA,DCSync`` variant alongside the real DumpLSA path.
    if _candidate_is_dc_dcsync_bridge(candidate_edge):
        from adscan_internal.services.post_exploitation.access_followups import (  # noqa: PLC0415
            is_self_credential_followup,
        )

        if any(is_self_credential_followup(rel) for rel in path_relations):
            return False
        return True

    if cand_rel in _CONTEXT_TRANSPARENT_KEYS:
        return True  # transparent edges are never blocked

    requires = required_context_for_relation(cand_rel)

    # Find most recent non-transparent edge in path and read the context it
    # PRODUCES (override-aware — so XpCmdshell contributes mssql_rce_session, which
    # gates the MSSQL SYSTEM-escalation follow-ups behind it). An unknown relation
    # defaults to "none" (matching the old "other" semantics → provides "none").
    prev_provides: str | None = None
    for rel in reversed(path_relations):
        if rel not in _CONTEXT_TRANSPARENT_KEYS:
            prev_provides = provides_context_for_relation(rel) or "none"
            break
    # prev_provides=None means empty path → implicit user_credentials at start.

    return context_requirement_satisfied(prev_provides, requires)


@dataclass(frozen=True)
class AttackPathStep:
    from_id: str
    relation: str
    to_id: str
    status: str
    notes: dict[str, Any]


def _self_loop_relation_already_used(
    acc_steps: list[AttackPathStep],
    current: str,
    candidate_relation: str,
) -> bool:
    """Return True when this self-loop technique already ran on ``current``.

    Self-loop derived edges (XpCmdshell, DumpLSA, the MSSQL SYSTEM-escalations …)
    do not advance the DFS to a new node, so the node-visited guard cannot stop a
    same-node cycle.  Two self-loops that chain into each other and back — e.g.
    ``XpCmdshell → MssqlTokenTheftEscalation → XpCmdshell → …`` on one SQL host —
    otherwise oscillate until the depth cap, emitting a path with a doubled tail.
    A self-loop technique is a one-time capability gain on that host; repeating the
    SAME relation on the SAME node adds nothing, so it is pruned here.
    """
    for step in acc_steps:
        if (
            step.from_id == current
            and step.to_id == current
            and str(step.relation or "").strip().lower() == candidate_relation
        ):
            return True
    return False


@dataclass(frozen=True)
class AttackPath:
    steps: list[AttackPathStep]
    source_id: str
    target_id: str

    @property
    def length(self) -> int:
        return len(self.steps)


def display_record_signature(
    record: dict[str, Any],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return a case-insensitive deduplication signature for one display record.

    Attack-path records can occasionally differ only by label casing when
    multiple data sources persist semantically identical nodes (for example a
    BloodHound-backed `ESSOS.LOCAL` domain node and a synthetic `essos.local`
    node). The UI should treat those paths as the same path.

    Args:
        record: Display record produced by ``path_to_display_record``.

    Returns:
        Tuple ``(nodes, relations)`` normalized for case-insensitive matching.
    """
    nodes = tuple(
        str(node or "").strip().lower() for node in (record.get("nodes") or [])
    )
    relations = tuple(_display_relation_identity_values(record, normalize=True))
    return nodes, relations


def _extract_share_access_name_from_notes(notes: dict[str, Any] | None) -> str:
    """Return the SMB share name persisted on a share-access edge."""
    if not isinstance(notes, dict):
        return ""
    share_name = str(notes.get("share_name") or notes.get("share") or "").strip()
    if share_name:
        return share_name
    collector_method = str(notes.get("collector_method") or "").strip()
    if collector_method.lower().startswith("share_acl:"):
        return collector_method.split(":", 1)[1].strip()
    return ""


def share_access_step_signature_component(
    relation: str,
    notes: dict[str, Any] | None,
) -> str:
    """Return the share-specific identity component for path deduplication."""
    relation_key = str(relation or "").strip().lower()
    if relation_key not in _SHARE_ACCESS_RELATION_KEYS:
        return ""
    return _extract_share_access_name_from_notes(notes).casefold()


def attack_path_step_signature(step: AttackPathStep) -> tuple[str, str, str, str]:
    """Return a path-step identity that keeps distinct SMB shares separate."""
    return (
        step.from_id,
        step.relation,
        step.to_id,
        share_access_step_signature_component(step.relation, step.notes),
    )


def _display_relation_identity_values(
    record: dict[str, Any],
    *,
    normalize: bool,
) -> tuple[str, ...]:
    relations = record.get("relations") or []
    details = record.get("steps") or []
    values: list[str] = []
    for index, relation in enumerate(relations):
        rel_text = str(relation or "").strip()
        rel_key = rel_text.lower()
        identity = rel_key if normalize else rel_text
        if rel_key in _SHARE_ACCESS_RELATION_KEYS:
            step_details = details[index] if index < len(details) else {}
            step_notes = (
                step_details.get("details")
                if isinstance(step_details, dict)
                and isinstance(step_details.get("details"), dict)
                else {}
            )
            share_name = _extract_share_access_name_from_notes(step_notes)
            if share_name:
                share_identity = share_name.casefold() if normalize else share_name
                identity = f"{identity}:{share_identity}"
        values.append(identity)
    return tuple(values)


def _is_excluded_share_access_edge(edge: dict[str, Any]) -> bool:
    """Return True for share-access edges that should not enter the DFS adjacency.

    All ReadShare / WriteShare / FullControlShare edges are excluded from
    attack-path computation. Share access is an exposure finding (resource
    inventory) — not a host-compromise edge — and is enumerated separately
    via :func:`collect_share_exposures_from_graph`.

    Excluding these edges at adjacency-building time avoids wasting DFS
    cycles on paths that would be filtered out at render time anyway, and
    keeps the attack-paths cost bounded by the count of true compromise
    edges (control / auth / derived / escalation) rather than by the
    cardinality of share principals × shares.
    """
    relation_key = str(edge.get("relation") or "").strip().lower()
    return relation_key in _SHARE_ACCESS_RELATION_KEYS


def _is_nontraversable_attack_edge(
    edge: dict[str, Any],
    nodes_map: dict[str, Any] | None,
) -> bool:
    """Return True for edges that exist in the graph but must not enter DFS adjacency.

    Single source of truth for "edge is persisted in ``attack_graph.json`` but is
    not a traversable compromise transition". Two classes:

    * **Share-access edges** (ReadShare / WriteShare / FullControlShare) — see
      :func:`_is_excluded_share_access_edge`; an exposure finding, not a
      host-compromise edge.
    * **``WriteSPN`` on a Computer target** — write access to a machine account's
      ``servicePrincipalName`` grants only a kerberoastable ticket, and a machine
      account password (120 random bytes) is uncrackable, so the kerberoast has no
      compromise value. The *real* escalation a computer-targeted SPN write enables
      is SPN-jacking + KCD, modelled as the derived ``SPNJack`` edge
      (:func:`adscan_internal.services.collector.persistence.derive_spnjack_edges`).
      The raw ``WriteSPN → Computer$`` edge is kept in the graph (reporting +
      SPNJack derivation read it) but is non-traversable here. ``WriteSPN → User``
      stays traversable as targeted Kerberoast; only the Computer class is gated.

    Args:
        edge: One graph edge dict.
        nodes_map: The graph ``nodes`` dict (id → node). When ``None`` the
            class-aware ``WriteSPN`` check is skipped (share-access still applies),
            so callers without node context degrade safely.
    """
    if _is_excluded_share_access_edge(edge):
        return True
    if str(edge.get("relation") or "").strip().lower() == "writespn":
        if isinstance(nodes_map, dict):
            target_node = nodes_map.get(str(edge.get("to") or "").strip())
            if (
                isinstance(target_node, dict)
                and str(target_node.get("kind") or "").strip().lower() == "computer"
            ):
                return True
    return False


# ── Well-known SIDs that expand to the low-priv authenticated population ─────

_WELL_KNOWN_LABELS: dict[str, str] = {
    "S-1-1-0": "Everyone",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-32-545": "Users",
    "S-1-5-32-544": "Administrators",
}
_SHARE_ACCESS_RANK: dict[str, int] = {
    "readshare": 1,
    "writeshare": 2,
    "fullcontrolshare": 3,
}
_SHARE_ACCESS_LABEL: dict[str, str] = {
    "readshare": "Read",
    "writeshare": "Write",
    "fullcontrolshare": "Full Control",
}
# Map the effective-mask relation kinds (from
# ``share_ntfs_verification.effective_mask_relations``) to the same access
# labels used above. Used to downgrade a raw share grant to the access the
# scanning identity *effectively* has when an NTFS/MxAc measurement exists.
_EFFECTIVE_RELATION_TO_LABEL: dict[str, str] = {
    "ReadShare": "Read",
    "WriteShare": "Write",
    "FullControlShare": "Full Control",
}


def _share_node_is_tier0(node: dict[str, Any]) -> bool:
    """Lightweight Tier-0 check suitable for graph-level share enumeration."""
    if bool(node.get("isTierZero")):
        return True
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    if bool(props.get("isTierZero")):
        return True
    tags = node.get("system_tags") or props.get("system_tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    return any(str(t).lower() == "admin_tier_0" for t in tags)


def collect_share_exposures_from_graph(
    graph: dict[str, Any],
    *,
    domain_sid: str | None = None,
    limit: int | None = 20,
) -> list[dict[str, Any]]:
    """Build a share exposure inventory directly from the attack graph.

    Unlike ``_collect_share_exposure_rows`` (which derives data from path search
    results and inherits attack-path DFS rules like max_depth, target_mode, and
    max_paths cap), this function reads share-access edges directly from the raw
    graph. It applies no depth limit, no target filter, and no path cap — the
    result is an exhaustive inventory of every ReadShare / WriteShare /
    FullControlShare edge that exists in the graph at the time of the call.

    Args:
        graph: Raw attack graph dict (``nodes`` + ``edges``).
        domain_sid: Optional domain SID (``S-1-5-21-...``). When supplied,
            ``<domain_sid>-513`` is recognised as ``Domain Users``.
        limit: Maximum number of rows to return (ranked by risk). ``None`` means unbounded (return every share-access row).

    Returns:
        List of share exposure dicts compatible with
        ``_render_share_resources_panel``.  Each dict contains: ``host``,
        ``share``, ``access`` (set), ``principals`` (set), ``share_access``
        (dict), ``choke`` (bool), ``impact_rank`` (int 0-3),
        ``admin_share`` (bool).

        ``share_access`` is the per-principal read/write map (source A —
        DACL-derived, no new network I/O). It is keyed by ACE-holder principal
        node id (the SID for native-collector nodes) and each value is a plain
        dict of JSON-serialisable primitives::

            {"<PRINCIPAL_SID>": {
                "read": bool, "write": bool,
                "source": "acl" | "mxac",   # how the verdict was confirmed
                "ntfs_verified": bool,       # share ∩ NTFS both present
                "via_group_sid": str | None, # None for source A (direct ACE)
                "principal_label": str,
            }}

        The row-level ``access``/``principals`` collapse stays for backward
        compatibility (it is scanning-identity-centric); ``share_access`` keeps
        the split the collapse discards so the report, the web share-exposure
        view, and the write-share bait can render/consume "share X:
        WRITE={principals}, READ={principals}, confirmed via {method}". A
        non-admin scan often cannot read the NTFS folder DACL, so most source-A
        verdicts are ``ntfs_verified=False`` share-level leads — kept (recall
        over precision) and flagged. A later live-token (MxAc, source B) pass
        may add/overwrite a single principal's entry with ``source="mxac"``.
    """
    # Deferred import: ``collector`` package ``__init__`` pulls in
    # ``persistence`` → ``attack_graph_service`` → this module, so a top-level
    # import would create a cycle. ``share_ntfs_verification`` itself is a leaf.
    from adscan_internal.services.collector.share_ntfs_verification import (
        VERIFICATION_NTFS_COMPUTED,
        VERIFICATION_SELF_MXAC,
        VERIFICATION_SHARE_ACL_ONLY,
        effective_mask_relations,
    )

    nodes_map: dict[str, Any] = graph.get("nodes") or {}
    edges: list[Any] = graph.get("edges") or []

    # Domain Users SID: S-1-5-21-<domain>-513
    domain_users_sid = (
        f"{domain_sid.rstrip('-')}-513".upper() if domain_sid else None
    )
    well_known = dict(_WELL_KNOWN_LABELS)
    if domain_users_sid:
        well_known[domain_users_sid] = "Domain Users"

    def _principal_label(node_id: str) -> str:
        sid_upper = str(node_id or "").strip().upper()
        if sid_upper in well_known:
            return well_known[sid_upper]
        node = nodes_map.get(node_id) or {}
        label = str(node.get("label") or node.get("name") or node_id).strip()
        return label

    exposures: dict[tuple[str, str], dict[str, Any]] = {}

    for edge in edges:
        if not isinstance(edge, dict):
            continue
        rel_key = str(edge.get("relation") or "").strip().lower()
        if rel_key not in _SHARE_ACCESS_RELATION_KEYS:
            continue

        notes = edge.get("notes") if isinstance(edge.get("notes"), dict) else {}
        share_name = _extract_share_access_name_from_notes(notes)
        if not share_name:
            continue
        if is_globally_excluded_smb_share(share_name):
            continue

        from_id = str(edge.get("from") or "").strip()
        to_id = str(edge.get("to") or "").strip()
        if not from_id or not to_id:
            continue

        target_node = nodes_map.get(to_id) or {}
        host_label = str(
            target_node.get("label") or target_node.get("name") or to_id
        ).strip()
        # A CONNECTABLE host for the SMB drop/enum, distinct from the display
        # ``host`` label (a computer node's label is the account principal
        # ``HOST$@REALM``, which does NOT SMB-connect). Prefer the node's IP, then
        # its DNS hostname. Empty when the node carries neither — callers fall back
        # to ``host``, which is correct for LIVE-enumerated rows whose ``host`` is
        # already an IP. (Fixes bait/enum drops failing LOGON_FAILURE against the
        # principal string on the graph-derived audit path.)
        _tn_props = target_node.get("properties") or {}
        host_ip = str(
            _tn_props.get("ip_address")
            or target_node.get("ip_address")
            or _tn_props.get("dnshostname")
            or target_node.get("dnshostname")
            or ""
        ).strip()

        key = (host_label.lower(), share_name.lower())
        row = exposures.setdefault(
            key,
            {
                "host": host_label,
                "host_ip": host_ip,
                "share": share_name,
                "access": set(),
                "principals": set(),
                # Per-principal read/write split (source A — DACL-derived).
                # Keyed by ACE-holder principal node id (SID). Plain dict of
                # primitives only, so the row serialises clean into
                # attack_graph.json / technical_report.json / domains_data.
                "share_access": {},
                "choke": False,
                "impact_rank": 0,
                "admin_share": False,
                # Internal accumulators (resolved into ``access`` after the
                # edge loop). ``_verified_access`` holds the scanning
                # identity's effective access proven by an NTFS/MxAc
                # measurement; ``_raw_access`` holds the unverified
                # share-grant lead. When any verified edge exists, the
                # effective access is authoritative — a raw "Full Control"
                # share grant that NTFS restricts to Read must NOT mark the
                # share writable (the NETLOGON/SYSVOL false positive).
                "_verified_access": set(),
                "_raw_access": set(),
                "_has_verified": False,
            },
        )

        verification = str(notes.get("verification") or "").strip()
        eff_mask = notes.get("effective_mask")
        if (
            verification in (VERIFICATION_NTFS_COMPUTED, VERIFICATION_SELF_MXAC)
            and eff_mask is not None
        ):
            row["_has_verified"] = True  # type: ignore[index]
            for rel in effective_mask_relations(int(eff_mask)):
                label = _EFFECTIVE_RELATION_TO_LABEL.get(rel)
                if label:
                    row["_verified_access"].add(label)  # type: ignore[union-attr]
        else:
            row["_raw_access"].add(_SHARE_ACCESS_LABEL[rel_key])  # type: ignore[union-attr]
        row["principals"].add(_principal_label(from_id))  # type: ignore[union-attr]

        # Per-principal read/write split (source A). Mirrors the row-level
        # verified-vs-raw resolution exactly: a NTFS/MxAc-verified edge derives
        # read/write from the effective (share ∩ NTFS) mask — authoritative and
        # independent of how many relation edges the collector emitted for that
        # mask; an unverified edge falls back to the raw share-grant relation as
        # a preserved lead (recall over precision). ``source`` + ``ntfs_verified``
        # carry the confirmation method and confidence per principal.
        # Cross-domain / unknown-group ACEs arrive as ``share_acl_only`` →
        # ntfs_verified stays False (we never assert no-access, matching the
        # collector's is_closure_confident=False path).
        share_access: dict[str, Any] = row["share_access"]  # type: ignore[assignment]
        entry = share_access.get(from_id)
        if entry is None:
            entry = {
                "read": False,
                "write": False,
                "source": "acl",
                "ntfs_verified": False,
                "via_group_sid": None,
                "principal_label": _principal_label(from_id),
            }
            share_access[from_id] = entry
        if (
            verification in (VERIFICATION_NTFS_COMPUTED, VERIFICATION_SELF_MXAC)
            and eff_mask is not None
        ):
            for rel in effective_mask_relations(int(eff_mask)):
                if rel == "ReadShare":
                    entry["read"] = True
                elif rel == "WriteShare":
                    entry["write"] = True
                elif rel == "FullControlShare":
                    entry["read"] = True
                    entry["write"] = True
            if verification == VERIFICATION_NTFS_COMPUTED:
                # Effective access proven by intersecting share ∩ NTFS DACL.
                entry["ntfs_verified"] = True
            else:
                # Confirmed against the scanning identity's own live token
                # (MxAc), not the NTFS DACL read — a distinct, non-admin-required
                # method. NTFS DACL was NOT read, so ntfs_verified stays False.
                entry["source"] = "mxac"
        else:
            # Unverified raw share-grant lead (NTFS SD unreadable / not
            # evaluable for this principal). Kept, flagged ntfs_verified=False.
            if rel_key == "readshare":
                entry["read"] = True
            elif rel_key == "writeshare":
                entry["write"] = True
            elif rel_key == "fullcontrolshare":
                entry["read"] = True
                entry["write"] = True

        if bool(notes.get("is_choke_point")):
            row["choke"] = True

        is_t0 = _share_node_is_tier0(target_node)
        if is_t0:
            row["impact_rank"] = max(int(row.get("impact_rank") or 0), 3)
        elif bool(row.get("choke")):
            row["impact_rank"] = max(int(row.get("impact_rank") or 0), 2)
        else:
            row["impact_rank"] = max(int(row.get("impact_rank") or 0), 1)

    # Resolve each row's authoritative access. When the share carries any
    # NTFS/MxAc-verified effective measurement for the scanning identity, that
    # effective access wins outright — raw share-grant leads from other
    # principals (e.g. a "Creator Owner: Full Control" ACE) describe a
    # different identity and must not re-inflate the row to "writable". Only
    # when NO verified measurement exists do we fall back to the raw grant as
    # an explicitly unverified lead. A verified-but-no-effective-access row is
    # not an exposure for the scanning identity — drop it.
    resolved: list[dict[str, Any]] = []
    for row in exposures.values():
        has_verified = bool(row.get("_has_verified"))
        if has_verified:
            row["access"] = set(row.get("_verified_access") or set())
        else:
            row["access"] = set(row.get("_raw_access") or set())
        # Verification rollup for the access breakdown. When ANY edge on this
        # (host, share) carried an NTFS/MxAc measurement the access shown is the
        # effective (share ∩ NTFS) value — real. When none did, the access is
        # the raw share-level grant only: NTFS was not verifiable, so the level
        # may overstate (the NETLOGON/SYSVOL Full-Control-but-Read case). The
        # view labels these "share-level only — NTFS not verified".
        row["ntfs_verified"] = has_verified
        row["verification"] = (
            VERIFICATION_NTFS_COMPUTED if has_verified else VERIFICATION_SHARE_ACL_ONLY
        )
        for internal in ("_verified_access", "_raw_access", "_has_verified"):
            row.pop(internal, None)
        if not row["access"]:
            continue
        resolved.append(row)

    ranked = sorted(
        resolved,
        key=lambda r: (
            int(r.get("impact_rank") or 0),
            _SHARE_ACCESS_RANK.get(
                max(
                    (a.lower().replace(" ", "") for a in (r.get("access") or set())),
                    key=lambda k: _SHARE_ACCESS_RANK.get(k, 0),
                    default="readshare",
                ),
                0,
            ),
            str(r.get("host") or "").lower(),
            str(r.get("share") or "").lower(),
        ),
        reverse=True,
    )
    if limit is None:
        return ranked
    return ranked[: max(0, limit)]


def _display_record_exact_signature(
    record: dict[str, Any],
) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    """Return an exact dedupe signature for a display record.

    Display records in this pipeline already carry string labels/relations, so
    ``tuple(...)`` is enough and avoids repeated coercion on very large lists.
    """
    cached = record.get("_exact_signature")
    if (
        isinstance(cached, tuple)
        and len(cached) == 2
        and isinstance(cached[0], tuple)
        and isinstance(cached[1], tuple)
    ):
        return cached  # type: ignore[return-value]
    nodes = record.get("nodes")
    rels = record.get("relations")
    if not isinstance(nodes, list) or not isinstance(rels, list):
        return None
    nodes_sig = tuple(nodes)
    rels_sig = _display_relation_identity_values(record, normalize=False)
    return nodes_sig, rels_sig


def load_attack_graph(path: Path) -> dict[str, Any] | None:
    """Load an attack graph from an `attack_graph.json` file path.

    Phase 2 (schema 1.2): every edge carries a top-level ``kind`` field
    set from :class:`adscan_internal.services.edge_kind.EdgeKind`. Older
    workspaces (schema 1.1) load transparently — this function backfills
    ``kind`` in memory from the edge ``relation`` so downstream
    classifiers always see a populated value. The JSON on disk is NOT
    rewritten by this function alone; the next ``save_attack_graph``
    call will persist the upgraded schema.

    Args:
        path: Path to `attack_graph.json`.

    Returns:
        The parsed graph dict when readable/valid, otherwise None.
    """
    try:
        if not path.exists():
            return None
    except OSError:
        return None

    data = read_json_file(str(path))
    if not isinstance(data, dict):
        return None
    nodes_map = data.get("nodes")
    edges = data.get("edges")
    if not isinstance(nodes_map, dict) or not isinstance(edges, list):
        return None
    data, migrated = migrate_legacy_attack_graph(data)
    if migrated:
        try:
            write_json_file(str(path), data)
        except OSError:
            # Best-effort normalisation; in-memory data is already correct.
            pass
    _backfill_edge_kinds(data)
    return data


def _backfill_edge_kinds(graph: dict[str, Any]) -> None:
    """In-memory backfill of EdgeKind for legacy schema 1.1 graphs.

    No-op for edges that already carry a ``kind`` field. Imported lazily
    to avoid a hard import cycle with services that ultimately import
    this module.
    """
    edges = graph.get("edges")
    if not isinstance(edges, list):
        return
    from adscan_internal.services.edge_kind import classify_edge_kind

    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if edge.get("kind"):
            continue
        relation = str(edge.get("relation") or "")
        edge["kind"] = classify_edge_kind(relation).value


def get_owned_node_ids(
    variables: dict[str, Any],
    graph: dict[str, Any],
    *,
    domain: str,
) -> list[str]:
    """Resolve "owned" usernames from variables.json into attack-graph node ids.

    The core algorithm only understands node ids. The web backend typically
    reads owned credentials from variables.json and then needs to map them into
    the graph nodes.

    Args:
        variables: Parsed `variables.json`.
        graph: Parsed attack graph.
        domain: Domain key (e.g. "htb.local").

    Returns:
        A list of node ids that exist in the graph and represent owned users.
    """
    domains_data = (
        variables.get("domains_data") if isinstance(variables, dict) else None
    )
    domain_data = (
        domains_data.get(domain)
        if isinstance(domains_data, dict) and isinstance(domain, str)
        else None
    )
    if not isinstance(domain_data, dict):
        return []

    credentials = domain_data.get("credentials")
    owned_usernames: set[str] = set()
    if isinstance(credentials, dict):
        owned_usernames.update(
            str(u).strip() for u in credentials.keys() if str(u).strip()
        )

    if not owned_usernames:
        return []

    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    if not isinstance(nodes_map, dict):
        return []

    domain_upper = str(domain).strip().upper()
    resolved: list[str] = []
    for username in sorted(owned_usernames):
        canonical_label = f"{username.upper()}@{domain_upper}"
        node_id = _find_user_node_id(
            nodes_map, username=username, canonical_label=canonical_label
        )
        if node_id:
            resolved.append(node_id)
    return resolved


def _build_light_display_records(
    graph: dict[str, Any],
    computed: list[AttackPath],
    *,
    target: str,
    mode: str,
    key_fn: Callable[[dict[str, Any]], Any],
) -> list[dict[str, Any]]:
    """Shape raw DFS paths into light display records (shared by both entry points).

    The DFS emits thousands of candidates (42k+ on Forest owned/all); this loop
    turns each into a light record and stamps its target-criticality classes.
    ``_node_target_priority_class`` / ``_node_target_priority_rank`` /
    ``_node_target_terminal_class`` are PURE functions of the target node and
    internally re-call the costly ``_node_is_tier0`` 8+ times each, yet those
    thousands of paths resolve to only a few hundred distinct target nodes — so
    the triple is memoised per ``target_id`` (byte-identical, computed once per
    node instead of once per path). ``key_fn`` is the caller's own dedup key.
    """
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    from adscan_internal.services.compromise_class import (  # noqa: PLC0415
        apply_path_based_classification as _apply_pbc,
    )

    target_class_cache: dict[str, tuple[str, int, str]] = {}

    def _classify_target(target_id: str) -> tuple[str, int, str]:
        cached = target_class_cache.get(target_id)
        if cached is not None:
            return cached
        node = nodes_map.get(target_id) if isinstance(nodes_map, dict) else None
        if isinstance(node, dict):
            verdict = (
                _node_target_priority_class(node),
                _node_target_priority_rank(node),
                _node_target_terminal_class(node),
            )
        else:
            verdict = ("pivot", 100, "pivot")
        target_class_cache[target_id] = verdict
        return verdict

    results: list[dict[str, Any]] = []
    seen: set[Any] = set()

    for path in computed:
        candidate = path
        if target == "highvalue":
            target_is_hv = _path_target_is_high_value(graph, path.target_id, mode=mode)
            if not target_is_hv:
                promoted = _try_promote_target_via_membership_edges(
                    graph, path, required_rank=1 if mode == "impact" else 3, mode=mode
                )
                if promoted:
                    candidate = promoted
                    target_is_hv = True
            if not target_is_hv:
                continue
        elif target == "lowpriv":
            if _path_target_is_high_value(graph, path.target_id, mode=mode):
                continue

        # Build the LIGHT record here — the DFS emits thousands of candidates and
        # minimisation keeps ~2%; the expensive per-step decoration is deferred to
        # the survivors via ``decorate_display_records`` at the end of the
        # post-processing pipeline. See ``path_to_display_record``.
        record = path_to_display_record(graph, candidate, decorate=False)
        target_id = str(candidate.target_id or "")
        target_node = nodes_map.get(target_id) if isinstance(nodes_map, dict) else None
        priority_class, priority_rank, terminal_class = _classify_target(target_id)
        record["target_priority_class"] = priority_class
        record["target_priority_rank"] = priority_rank
        record["target_terminal_class"] = terminal_class
        record["is_tier_zero"] = priority_class == "tierzero"
        record["target_is_high_value"] = priority_class in {"tierzero", "highvalue"}
        # Phase 3 — path-based compromise-class classifier (overrides terminal_class).
        _apply_pbc(record, target_node if isinstance(target_node, dict) else None)
        nodes = record.get("nodes")
        rels = record.get("relations")
        if not isinstance(nodes, list) or not isinstance(rels, list):
            continue
        key = key_fn(record)
        if key in seen:
            continue
        seen.add(key)
        results.append(record)

    return results


def compute_display_paths_for_domain_unfiltered(
    graph: dict[str, Any],
    *,
    max_depth: int,
    max_paths: int | None = None,
    target: str = "highvalue",
    target_mode: str = "object",
    start_node_ids: set[str] | None = None,
    chokepoint_group_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Compute maximal attack paths for a domain (graph-only, unfiltered).

    This is the graph-only equivalent of the CLI `attack_paths <domain>` logic.
    Callers can optionally post-process with `filter_contained_paths_for_domain_listing`.
    """
    mode = normalize_target_mode(target_mode)

    high_value_reachable_node_ids: set[str] | None = None
    effective_start_node_ids = (
        {str(node_id) for node_id in start_node_ids if str(node_id).strip()}
        if start_node_ids
        else None
    )
    if target == "highvalue":
        high_value_reachable_node_ids = _build_high_value_reachable_node_ids(
            graph,
            mode=mode,
        )
        if not high_value_reachable_node_ids:
            return []
        if effective_start_node_ids is None:
            effective_start_node_ids = set(high_value_reachable_node_ids)
        else:
            effective_start_node_ids &= high_value_reachable_node_ids
            if not effective_start_node_ids:
                return []

    computed = compute_maximal_attack_paths(
        graph,
        max_depth=max_depth,
        max_paths=max_paths,
        # Always compute all paths and apply filtering/promotion after.
        target="all",
        terminal_mode=mode,
        start_node_ids=effective_start_node_ids,
        reachable_node_ids=high_value_reachable_node_ids,
        chokepoint_group_ids=chokepoint_group_ids,
    )

    return _build_light_display_records(
        graph,
        computed,
        target=target,
        mode=mode,
        key_fn=display_record_signature,
    )


def _record_affected_principal_count(record: dict[str, Any]) -> int:
    """Read a display record's affected-principal count (blast radius).

    Stamped by ``apply_affected_user_metadata`` under ``meta`` before the
    containment filter runs. Returns 0 when absent so the affected-widening
    carve-out never triggers on an un-annotated record.
    """
    meta = record.get("meta")
    if isinstance(meta, dict):
        val = meta.get("affected_principal_count")
        if isinstance(val, int):
            return val
    val = record.get("affected_principal_count")
    return val if isinstance(val, int) else 0


def filter_contained_paths_for_domain_listing(
    records: list[dict[str, Any]],
    *,
    keep_shortest: bool = False,
    is_hv_terminal: Callable[[dict[str, Any]], bool] | None = None,
    preserve_prefix_paths: bool = False,
    affected_widening_carveout: bool = False,
) -> tuple[list[dict[str, Any]], int]:
    """Remove paths that are fully contained within another path.

    Args:
        records: Display path records to filter.
        keep_shortest: When False (default / domain scope), keep the longest
            path and remove shorter ones that are strict contiguous sub-paths of
            it — giving the most holistic attack chain view.  When True
            (owned / principals multi-user scope), keep the shortest path and
            remove longer paths that contain it — giving the most direct route
            to exploitation from already-compromised principals.
        is_hv_terminal: Optional callable returning True when a record's
            terminal node is high-value / tier-0.  Only used with
            ``keep_shortest=True``.  In that mode (F5) matching is
            CONTEXT-INSENSITIVE (records are compared on their non-contextual
            attack core — MemberOf/structural relations stripped, ``X→DumpLSA→X``
            self-loops collapsed) and dominance follows the 4-tier
            domain-compromise total order (T4 Domain object > T3 direct-breaker
            group > T2 enabler > T1 host) via ``domain_compromise_tier_from_record``.
            The sort processes the highest domain-compromise tier first, then
            ``is_hv_terminal``, then shorter length, so a truncated lower-tier
            subpath never shadows the longer higher-tier kill chain, and a
            Domain-object (T4) prefix is never trimmed against a lower-tier
            super-path.  An HV terminal is never dropped in Pass 2.
        preserve_prefix_paths: When True (non-domain scopes) in the ``keep_longest``
            branch, a longer path is only considered redundant if the matching
            sub-sequence ends at the **same terminal node** as the longer path.
            This prevents dropping ``A→B`` just because ``A→B→C`` exists — B and C
            are different exploitable targets.  When False (domain scope), all
            sub-sequences are marked as covered/shadowed regardless of their
            terminal, giving the most compact holistic view.  In the
            ``keep_shortest`` branch this flag no longer gates matching — the
            attack-core comparison already ignores context hops.
    """
    if len(records) <= 1:
        return records, 0

    normalized: list[tuple[tuple[str, ...], tuple[str, ...], dict[str, Any]]] = []
    for record in records:
        sig = _display_record_exact_signature(record)
        if sig is None:
            continue
        nodes_t, rels_t = sig
        normalized.append((nodes_t, rels_t, record))

    if not keep_shortest:
        # Domain mode: process longest-first; mark strict sub-paths as covered.
        #
        # preserve_prefix_paths=True  (non-domain callers): only sub-sequences
        #   ending at the same terminal as the kept path are shadowed.  These are
        #   exactly the strict suffixes of the kept path — O(L) per path.
        #
        # preserve_prefix_paths=False (domain scope): all strict contiguous
        #   sub-sequences are shadowed — O(L²) per path but unavoidable for the
        #   holistic domain view.
        normalized.sort(key=lambda item: len(item[1]), reverse=True)
        # ``affected_widening_carveout``: track the MAX affected-principal count
        # among the KEPT super-paths that cover each signature. A shorter sub-path
        # that reaches strictly MORE principals than every super-path covering it
        # is a broader finding — it must be rescued, not collapsed into the longer,
        # narrower chain. This is the SAME "more affected wins" doctrine the
        # keep_shortest branch already applies; extending it here removes the
        # historical asymmetry where keep_longest silently buried a broad, often
        # PROVEN path (e.g. `DOMAIN USERS → ESC1 → DA`, 13 affected) inside a long
        # single-principal chain that merely PASSES THROUGH Domain Users (1
        # affected). Without the carve-out ``covered`` is a plain containment set
        # (legacy holistic behaviour, byte-identical).
        covered: dict[tuple[tuple[str, ...], tuple[str, ...]], int] = {}
        kept: list[dict[str, Any]] = []
        removed = 0
        for nodes_t, rels_t, record in normalized:
            sig = (nodes_t, rels_t)
            if sig in covered:
                if not (
                    affected_widening_carveout
                    and _record_affected_principal_count(record) > covered[sig]
                ):
                    removed += 1
                    continue
                # Broader-origin sub-path (strictly more affected than every kept
                # super-path covering it) — fall through and keep it.
            kept.append(record)
            rel_len = len(rels_t)
            if rel_len <= 0:
                continue
            aff = _record_affected_principal_count(record)
            if preserve_prefix_paths:
                # O(L): only strict suffixes share the same terminal by definition.
                # s=0 would be the full path itself — start from 1.
                for s in range(1, rel_len):
                    sub = (nodes_t[s:], rels_t[s:])
                    covered[sub] = max(covered.get(sub, -1), aff)
            else:
                # O(L²): mark every strict contiguous sub-sequence as covered.
                for start in range(0, rel_len):
                    for end in range(start + 1, rel_len + 1):
                        if end - start >= rel_len:
                            continue
                        sub = (nodes_t[start : end + 1], rels_t[start:end])
                        covered[sub] = max(covered.get(sub, -1), aff)
        return kept, removed
    else:
        # Owned/principals multi-user mode: keep the most direct path within each
        # contained group, while never collapsing a higher domain-compromise tier
        # into a lower one.  Matching is CONTEXT-INSENSITIVE (F5 Fix #1): two paths
        # are compared on their non-contextual attack core (``attack_core_signature``
        # — MemberOf/structural relations stripped, ``X→DumpLSA→X`` self-loops
        # collapsed), NOT the literal node/rel arrays.  Dominance uses the 4-tier
        # domain-compromise total order (F5 Fix #2): T4 Domain object > T3
        # direct-breaker group > T2 enabler > T1 host.
        #
        # Sort key (process the record that should be KEPT first):
        #   (-domain_compromise_tier, not is_hv, length)
        # Highest domain-compromise tier first (a T4 Domain-object path is kept
        # before any truncated T3/T1 subpath can shadow it), then the legacy
        # ``is_hv_terminal`` flag, then shorter length wins the tie.
        def _entry_core(record: dict[str, Any]) -> AttackCore | None:
            nodes = record.get("nodes")
            rels = record.get("relations")
            if not isinstance(nodes, list) or not isinstance(rels, list):
                return None
            return attack_core_signature(nodes, rels)

        cores_by_id: dict[int, AttackCore | None] = {}
        tiers_by_id: dict[int, int] = {}
        for _nt, _rt, record in normalized:
            cores_by_id[id(record)] = _entry_core(record)
            tiers_by_id[id(record)] = domain_compromise_tier_from_record(record)

        def _sort_key(
            item: tuple[tuple[str, ...], tuple[str, ...], dict[str, Any]],
        ) -> tuple[int, bool, int]:
            record = item[2]
            dct = tiers_by_id[id(record)]
            not_hv = (not is_hv_terminal(record)) if is_hv_terminal is not None else True
            return (-dct, not_hv, len(item[1]))

        normalized.sort(key=_sort_key)
        # Pass 1 — drop a candidate B when an already-kept A's attack core is a
        # contiguous sub-sequence (or prefix) of B's, UNLESS B reaches a strictly
        # higher domain-compromise tier than the kept A (then B carries genuinely
        # more domain impact and is preserved — the kept A becomes a redundant
        # prefix removed in Pass 2 instead).  ``preserve_prefix_paths`` only
        # influences the legacy literal mode; on the attack core a prefix and a
        # same-terminal suffix coincide because context hops are already stripped.
        kept_entries: list[tuple[AttackCore | None, dict[str, Any]]] = []
        kept_terminal_by_id: dict[int, str | None] = {}
        # Sub-quadratic scheduling index (byte-identical to the naive all-pairs
        # scan).  A kept sub-path is CONTAINED (prefix OR contiguous sub-sequence)
        # in the candidate only when its step tuple is a contiguous block of the
        # candidate's — which forces BOTH its first AND its last actionable step to
        # appear (at the block's two ends) among the candidate's steps.  Indexing
        # kept cores by the ``(first_step, last_step)`` ENDPOINT pair (not the
        # first step alone) is what tames the sibling-pivot explosion: thousands of
        # near-duplicate paths that share the same first step (e.g. one source
        # roasting every service account — ``… → Kerberoast → SVC_i``) land in the
        # SAME first-step bucket, so a first-step index still tests every sibling
        # against every other (O(N²)); their DISTINCT terminals give distinct
        # endpoint pairs, so the endpoint index buckets them apart and each
        # candidate only tests the few kept cores that could actually contain-match.
        # A contained kept core with endpoints ``(k0, km)`` sits at some contiguous
        # offset in the candidate, so ``(k0, km)`` is one of the candidate's own
        # ``(steps[i], steps[j]), i <= j`` endpoint pairs — the candidate probes
        # exactly those, so no true containment is skipped.  The predicate and the
        # tier/terminal guards below are unchanged; only the set of pairs they run
        # on is pruned, and ``is_super_path`` is an existence (OR) over the
        # qualifying kept paths, so the pruned iteration order does not change it.
        kept_by_endpoints: dict[
            tuple[tuple[str, str], tuple[str, str]],
            list[tuple[AttackCore, dict[str, Any]]],
        ] = {}
        removed_multi = 0
        for nodes_t, rels_t, record in normalized:
            cand_core = cores_by_id[id(record)]
            cand_tier = tiers_by_id[id(record)]
            cand_terminal = nodes_t[-1] if nodes_t else None
            is_super_path = False
            if cand_core is not None and cand_core[1]:
                cand_steps = cand_core[1]
                n_cand_steps = len(cand_steps)
                probed_endpoints: set[tuple[tuple[str, str], tuple[str, str]]] = set()
                for i in range(n_cand_steps):
                    if is_super_path:
                        break
                    for j in range(i, n_cand_steps):
                        endpoints = (cand_steps[i], cand_steps[j])
                        if endpoints in probed_endpoints:
                            continue
                        probed_endpoints.add(endpoints)
                        bucket = kept_by_endpoints.get(endpoints)
                        if not bucket:
                            continue
                        for kept_core, kept_rec in bucket:
                            contained = attack_core_is_prefix(
                                kept_core, cand_core
                            ) or attack_core_is_subsequence(kept_core, cand_core)
                            if not contained:
                                continue
                            kept_tier = tiers_by_id[id(kept_rec)]
                            # Keep the longer candidate when it reaches a strictly higher
                            # domain-compromise tier than the kept sub-path.
                            if cand_tier > kept_tier:
                                continue
                            # Keep the longer candidate when it reaches a DISTINCT terminal
                            # of EQUAL domain-compromise tier: it is a separately
                            # compromisable target, not merely a longer route to the same
                            # place.  (Vintage: ``FS01$→…→GMSA01$`` is a prefix of three
                            # distinct equal-tier service-account terminals SVC_ARK /
                            # SVC_LDAP / SVC_SQL — all three must survive, not collapse into
                            # the bare GMSA01$ prefix.)  The redundant bare prefix is
                            # dropped in Pass 2 instead.  Same-terminal longer routes still
                            # collapse here, and a lower-tier wander past the kept terminal
                            # (cand_tier < kept_tier) still collapses as noise.
                            if (
                                cand_tier == kept_tier
                                and cand_terminal is not None
                                and cand_terminal != kept_terminal_by_id.get(id(kept_rec))
                            ):
                                continue
                            # Keep the longer candidate when it reaches the SAME terminal
                            # at EQUAL tier but from a strictly BROADER origin — a larger
                            # affected-principal population.  The extra leading prefix
                            # (e.g. DOMAIN USERS -> Kerberoast -> ... -> domain, 14
                            # affected) widens "who can walk this" vs the single-principal
                            # suffix (1 affected); that is headline blast-radius value, not
                            # redundant length.  Domain-listing scope only
                            # (``affected_widening_carveout``); the redundant narrow twin is
                            # dropped in Pass 2.  Owned/principals keep the direct route.
                            if (
                                affected_widening_carveout
                                and cand_tier == kept_tier
                                and _record_affected_principal_count(record)
                                > _record_affected_principal_count(kept_rec)
                            ):
                                continue
                            is_super_path = True
                            break
                        if is_super_path:
                            break
            if is_super_path:
                removed_multi += 1
            else:
                kept_entries.append((cand_core, record))
                kept_terminal_by_id[id(record)] = cand_terminal
                # Index this kept path by its ``(first_step, last_step)`` endpoint
                # pair so later candidates can find it as a possible contained
                # sub-path via one bucket lookup.  Empty-step cores never
                # contain-match (the predicates guard ``n == 0``), so skip them.
                if cand_core is not None and cand_core[1]:
                    endpoint_key = (cand_core[1][0], cand_core[1][-1])
                    kept_by_endpoints.setdefault(endpoint_key, []).append(
                        (cand_core, record)
                    )

        # Pass 2 — remove a kept path A when a kept super-path B strictly contains
        # A's attack core as a prefix/sub-sequence AND B's domain-compromise tier is
        # >= A's (the 4-tier total order, F5 Fix #2 — replaces the lane-based
        # ``tier_dominates`` guard).  Carve-out: an HV terminal is never dropped
        # (legacy ``is_hv_terminal``).  Effects:
        #   • a T3 ``…→Domain Controllers`` prefix is dropped by the T4
        #     ``…→DCSync→Domain`` super-path it prefixes (4 >= 3);
        #   • a T4 Domain-object prefix is NEVER dropped by a longer T1-host
        #     super-path (1 >= 4 is False) — preserves the F2 anti-regression.
        # Sub-quadratic scheduling index (byte-identical to the naive all-pairs
        # scan).  Path A is dominated only by a super-path B that CONTAINS A's core
        # (prefix OR contiguous sub-sequence) — which forces A's FIRST and LAST
        # steps to sit at the two ends of a contiguous block of B's steps, i.e.
        # ``(a_first, a_last)`` is one of B's own ``(steps[i], steps[j]), i <= j``
        # endpoint pairs.  Indexing every kept super-path B under ALL its endpoint
        # pairs lets a given A find its dominators with ONE bucket lookup instead of
        # scanning every B that merely shares A's first step — the same
        # sibling-pivot fan-out (all siblings share a first step) that the by-step
        # index degraded to O(N²).  ``dominated`` is an existence (OR) over
        # qualifying B's, so the pruned iteration order does not change it.
        super_by_endpoints: dict[
            tuple[tuple[str, str], tuple[str, str]],
            list[tuple[AttackCore, dict[str, Any]]],
        ] = {}
        for b_core, other in kept_entries:
            if b_core is None or not b_core[1]:
                continue
            b_steps = b_core[1]
            n_b_steps = len(b_steps)
            seen_b_endpoints: set[tuple[tuple[str, str], tuple[str, str]]] = set()
            for i in range(n_b_steps):
                for j in range(i, n_b_steps):
                    endpoints = (b_steps[i], b_steps[j])
                    if endpoints in seen_b_endpoints:
                        continue
                    seen_b_endpoints.add(endpoints)
                    super_by_endpoints.setdefault(endpoints, []).append(
                        (b_core, other)
                    )
        pass2_kept: list[dict[str, Any]] = []
        pass2_removed = 0
        for a_core, record in kept_entries:
            a_tier = tiers_by_id[id(record)]
            a_terminal = kept_terminal_by_id.get(id(record))
            rec_is_hv = is_hv_terminal(record) if is_hv_terminal is not None else False
            dominated = False
            if a_core is not None and a_core[1]:
                a_aff = _record_affected_principal_count(record)
                a_endpoints = (a_core[1][0], a_core[1][-1])
                for b_core, other in super_by_endpoints.get(a_endpoints, ()):
                    if other is record:
                        continue
                    if not (
                        attack_core_is_prefix(a_core, b_core)
                        or attack_core_is_subsequence(a_core, b_core)
                    ):
                        continue
                    b_tier = tiers_by_id[id(other)]
                    if rec_is_hv:
                        # HV terminal stays protected (legacy) EXCEPT from a
                        # broader-origin twin of the SAME compromise: same terminal,
                        # same tier, strictly more affected principals.  Then the
                        # narrow twin is redundant and the broad path carries the
                        # blast-radius headline.  Domain-listing scope only — with the
                        # carve-out off this branch never fires, so an HV terminal is
                        # never dominated (byte-identical to the legacy guard).
                        if (
                            affected_widening_carveout
                            and b_tier == a_tier
                            and kept_terminal_by_id.get(id(other)) == a_terminal
                            and _record_affected_principal_count(other) > a_aff
                        ):
                            dominated = True
                            break
                        continue
                    if b_tier >= a_tier:
                        dominated = True
                        break
            if dominated:
                pass2_removed += 1
            else:
                pass2_kept.append(record)

        return pass2_kept, removed_multi + pass2_removed


# ── Domain-scope listing shortest/longest mode ─────────────────────────────────
# Product decision (2026-06): the ``domain`` scope listing returns the MOST DIRECT
# HV-aware route to domain compromise (``keep_shortest``) by default, instead of the
# legacy holistic longest kill chain. The old keep_longest behaviour buried the
# signal under many long ``theoretical`` paths. The behaviour is selected by the
# threaded ``keep_longest`` parameter (default shortest); callers opt into the
# holistic view via the ``--keep-longest`` flag wired through
# ``get_attack_path_summaries``.


def filter_domain_listing_paths(
    records: list[dict[str, Any]],
    *,
    label_to_node: Mapping[str, Mapping[str, Any]],
    keep_longest: bool = False,
) -> tuple[list[dict[str, Any]], int]:
    """Apply the domain-scope listing filter, shortest HV-aware by default.

    Single source of truth shared by BOTH domain-scope pipelines (the active
    compute pipeline in ``attack_paths_core`` and the display/report pipeline in
    ``attack_graph_service``). Stamps the per-record target tier and the 4-tier
    domain-compromise rank on ``records`` in place (the ``keep_shortest`` branch
    of :func:`filter_contained_paths_for_domain_listing` reads both stamps), then
    runs the containment filter:

    * Default (``keep_longest=False``): ``keep_shortest=True`` with an
      ``is_hv_terminal`` predicate and ``preserve_prefix_paths=True`` — the most
      direct route to each distinct domain-compromise terminal. The terminal
      protection (an HV terminal is never dropped, a higher domain-compromise tier
      is never collapsed into a lower one) keeps the short ``…→DCSync→DOMAIN`` /
      ``…→Domain Admins`` kill chains alive while pruning the long theoretical
      wanders that previously dominated the listing.
    * ``keep_longest=True``: ``keep_shortest=False`` — the holistic longest kill
      chain, reproducing the pre-2026-06 behaviour for rollback / a whole-domain
      exposure view.

    Args:
        records: Display path records for the domain scope (modified in place by
            the tier stamping).
        label_to_node: Label-to-node index used to resolve each terminal's tier and
            high-value classification. Required so the Domain object is recognised
            as the top domain-compromise tier and HV terminals are protected.
        keep_longest: When True, select the legacy holistic longest kill chain
            instead of the default shortest HV-aware route.

    Returns:
        ``(kept_records, removed_count)`` from the containment filter.
    """
    if keep_longest:
        # Holistic view: collapse sub-paths into the longest kill chain, BUT rescue
        # a broader-origin sub-path (strictly more affected principals than the
        # super-path covering it) — the "more affected wins" doctrine now applies
        # in BOTH domain-listing modes, not just keep_shortest.
        return filter_contained_paths_for_domain_listing(
            records, keep_shortest=False, affected_widening_carveout=True
        )
    # Shortest HV-aware: stamp the tiers the keep_shortest branch consumes, then
    # keep the most direct route while protecting HV / domain-object terminals.
    stamp_records_target_tier(records, label_to_node=label_to_node)
    stamp_records_domain_compromise_tier(records, label_to_node=label_to_node)
    resolve = label_to_node or {}

    def _is_hv_terminal(record: dict[str, Any]) -> bool:
        """Return True when the record's terminal node is high-value / tier-0."""
        target_node = resolve.get(str(record.get("target") or "")) or {}
        return _node_target_priority_class(target_node) != "pivot"

    return filter_contained_paths_for_domain_listing(
        records,
        keep_shortest=True,
        is_hv_terminal=_is_hv_terminal,
        preserve_prefix_paths=True,
        # Domain-listing SSOT: prefer the broader-origin twin (more affected
        # principals) over its single-principal suffix at equal tier/terminal, so
        # the "any Domain User can reach this" blast-radius headline survives.
        # Domain scope only — owned/principals never reach this wrapper.
        affected_widening_carveout=True,
    )


# Outcome-class priority ranking — higher value = more severe / more complete.
# Paths with lower-rank classes are dropped when a higher-rank super-path covers them.
_OUTCOME_CLASS_RANK: dict[str, int] = {
    "direct_compromise": 100,
    "domain_breaker": 100,      # alias used in some callers
    "tier0_foothold": 80,
    "privileged_escalator": 60,
    "compromise_enabler": 50,
    "graph_extension": 50,      # runtime alias for compromise_enabler
    "pivot": 20,
    "followup_terminal": 20,
}


def _outcome_class_rank(record: dict[str, Any]) -> int:
    cls = str(
        record.get("outcome_class") or record.get("compromise_class") or ""
    ).strip().lower()
    return _OUTCOME_CLASS_RANK.get(cls, 10)


def filter_prefix_paths_dominated_by_super_path(
    records: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    """Remove paths that are prefixes of a domain-tier-dominating super-path.

    Matching (F5 Fix #1 — context-insensitive): "A is a prefix of B" is decided on
    the **non-contextual attack core** (``attack_core_signature``) — MemberOf and
    the other structural relations are stripped and ``X→DumpLSA→X`` self-loops are
    collapsed — NOT on the literal node/rel arrays. This is what lets a path
    truncated at the Domain Controllers group be recognized as a prefix of the full
    ``…→DCSync→Domain`` kill chain even though the full path's rendered arrays carry
    an extra DumpLSA self-loop node and a different terminal. The DISPLAYED records
    are untouched; only the matching key is context-insensitive.

    Dominance (F5 Fix #2 — 4-tier total order): a prefix A is dropped by a
    containing super-path B iff A's core is a strict prefix of B's core AND
    ``domain_compromise_tier(B) >= domain_compromise_tier(A)`` on the operator-defined
    total order ``T4 Domain object > T3 direct-breaker group > T2 enabler > T1 host``.
    This:

    * collapses redundant domain-tier prefixes (a T3 ``…→Domain Controllers`` path is
      dropped in favour of the T4 ``…→DCSync→Domain`` super-path it prefixes);
    * preserves the F1 anti-regression — a T4 Domain-object prefix is NEVER dropped by
      a longer lower-tier super-path (``1 >= 4`` is False), so the headline
      domain-compromise path always survives a host-terminal extension.

    The legacy ``_outcome_class_rank`` guard is intentionally NOT re-applied here: the
    4-tier domain-compromise order is the finer, authoritative dominance for domain
    outcomes (e.g. it distinguishes the Domain object from a direct-breaker group,
    which both map to outcome rank 100 and would otherwise tie). This runs *after* the
    within-target contained-path filter, so it only deals with cross-target prefix
    relationships (different terminal nodes).
    """
    if len(records) <= 1:
        return records, 0

    # Pre-compute the context-insensitive attack core + 4-tier rank for each record.
    cores: list[tuple[AttackCore | None, int, dict[str, Any]]] = []
    for record in records:
        nodes = record.get("nodes")
        rels = record.get("relations")
        core = (
            attack_core_signature(nodes, rels)
            if isinstance(nodes, list) and isinstance(rels, list)
            else None
        )
        cores.append((core, domain_compromise_tier_from_record(record), record))

    # Sub-quadratic scheduling index (byte-identical to the naive all-pairs scan).
    # A is dropped only by a super-path B whose core strictly CONTAINS A's core as a
    # LEADING prefix (``attack_core_is_prefix`` — same start node, A's step tuple is
    # B's first ``len(A)`` steps, A strictly shorter) AND ``tier(B) >= tier(A)``.
    # So index, for every B, each of its PROPER-prefix keys ``(start, steps[:k])``
    # (k = 1..len(B)-1) → the MAX B-tier registered at that key.  A is then dominated
    # iff its own ``(start, steps)`` key is registered with a tier >= A's — an O(1)
    # lookup that replaces the inner all-pairs loop.  A never registers its own full
    # key (only strictly shorter prefixes), so it can never dominate itself and two
    # equal-core paths never dominate each other (matching the strict-prefix guard).
    prefix_dominator_tier: dict[tuple[str, tuple[tuple[str, str], ...]], int] = {}
    for b_core, b_tier, _b_record in cores:
        if b_core is None:
            continue
        b_start, b_steps = b_core[0], b_core[1]
        for k in range(1, len(b_steps)):
            key = (b_start, b_steps[:k])
            cur = prefix_dominator_tier.get(key)
            if cur is None or b_tier > cur:
                prefix_dominator_tier[key] = b_tier

    kept: list[dict[str, Any]] = []
    removed = 0
    for a_core, a_tier, record in cores:
        if a_core is None:
            kept.append(record)
            continue
        dominated = False
        if a_core[1]:
            best = prefix_dominator_tier.get((a_core[0], a_core[1]))
            dominated = best is not None and best >= a_tier
        if dominated:
            removed += 1
        else:
            kept.append(record)

    return kept, removed


def _attack_core_signature(
    nodes_t: tuple[str, ...],
    rels_t: tuple[str, ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return (nodes, rels) with trailing contextual edges stripped.

    Contextual relations (MemberOf, Contains, etc.) at the end of a path are
    structural annotations — they do not represent an attack action.  Two paths
    whose only difference is which contextual group they terminate in represent
    the same attack and should be deduplicated.

    Example:
      Kerberoasting → ADMINISTRATOR → MemberOf → Domain Admins
      Kerberoasting → ADMINISTRATOR → MemberOf → GPCO
    Both reduce to core: Kerberoasting → ADMINISTRATOR
    """
    if not rels_t:
        return nodes_t, rels_t
    # Strip trailing contextual relations from the right.
    end = len(rels_t)
    while end > 0 and rels_t[end - 1].lower() in _STRUCTURAL_RELATIONS_LOWER:
        end -= 1
    return nodes_t[: end + 1], rels_t[:end]


def deduplicate_trailing_contextual_suffix_paths(
    records: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    """Deduplicate paths that share the same attack core but differ only in trailing contextual edges.

    Paths like:
        A → GenericAll → B → MemberOf → Group1   [graph_extension]
        A → GenericAll → B → MemberOf → Group2   [graph_extension]
    share attack core ``A → GenericAll → B``.  Within each core group, keep
    only the **best representative**:

    Priority (descending):
        1. Highest outcome-class rank  (direct_compromise > graph_extension…)
        2. Highest target_priority_rank  (already set by Stage 7; tierzero wins)
        3. Longest path  (more context is better when all else is equal)

    This runs BEFORE Stage 7 so target_priority_rank may not yet be set; fall
    back to 0 when the field is missing.  Stage 7 will re-tag the survivors.
    """
    if len(records) <= 1:
        return records, 0

    # Group records by their attack core.
    # Key: (core_nodes, core_rels)
    groups: dict[
        tuple[tuple[str, ...], tuple[str, ...]],
        list[dict[str, Any]],
    ] = {}
    ungroupable: list[dict[str, Any]] = []

    for record in records:
        sig = _display_record_exact_signature(record)
        if sig is None:
            ungroupable.append(record)
            continue
        nodes_t, rels_t = sig
        core = _attack_core_signature(nodes_t, rels_t)
        groups.setdefault(core, []).append(record)

    kept: list[dict[str, Any]] = []
    removed = 0

    for core, group in groups.items():
        if len(group) == 1:
            kept.append(group[0])
            continue

        # Check whether any member of the group actually has trailing contextual
        # edges.  If all members share the same full signature (no difference),
        # they're exact duplicates — keep one (first, already handled by
        # dedupe_exact_display_paths).  If they have different full signatures
        # but the same core, the difference IS the trailing contextual suffix.
        full_sigs = {_display_record_exact_signature(r) for r in group}
        if len(full_sigs) == 1:
            # All identical — just keep one; exact-dupe filter handles this.
            kept.extend(group)
            continue

        # Multiple paths with the same attack core but different trailing context:
        # pick the single best representative.
        def _sort_key(rec: dict[str, Any]) -> tuple[int, int, int]:
            sig = _display_record_exact_signature(rec)
            length = len(sig[1]) if sig else 0
            return (
                -_outcome_class_rank(rec),                          # higher class first
                -(rec.get("target_priority_rank") or 0),            # higher priority first
                -length,                                            # longer path first
            )

        group_sorted = sorted(group, key=_sort_key)
        kept.append(group_sorted[0])
        removed += len(group) - 1

    kept.extend(ungroupable)
    return kept, removed


def compute_display_paths_for_start_node(
    graph: dict[str, Any],
    *,
    start_node_id: str,
    max_depth: int,
    max_paths: int | None = None,
    target: str = "highvalue",
    target_mode: str = "object",
) -> list[dict[str, Any]]:
    """Compute maximal attack paths starting from a specific node id."""
    mode = normalize_target_mode(target_mode)

    high_value_reachable_node_ids: set[str] | None = None
    if target == "highvalue":
        high_value_reachable_node_ids = _build_high_value_reachable_node_ids(
            graph,
            mode=mode,
        )
        if start_node_id not in high_value_reachable_node_ids:
            return []

    computed = compute_maximal_attack_paths_from_start(
        graph,
        start_node_id=start_node_id,
        max_depth=max_depth,
        max_paths=max_paths,
        target="all",
        terminal_mode=mode,
        reachable_node_ids=high_value_reachable_node_ids,
    )

    def _start_node_dedup_key(
        record: dict[str, Any],
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        nodes = record.get("nodes") or []
        rels = record.get("relations") or []
        return (tuple(str(n) for n in nodes), tuple(str(r) for r in rels))

    return _build_light_display_records(
        graph,
        computed,
        target=target,
        mode=mode,
        key_fn=_start_node_dedup_key,
    )


def _build_local_reuse_virtual_state(
    nodes_map: dict[str, Any],
    edges: list[dict[str, Any]],
) -> tuple[dict[str, list[dict[str, Any]]], set[tuple[str, str]]]:
    """Build virtual-expansion state for compressed LocalAdminPassReuse groups.

    When LocalAdminPassReuse is persisted in compressed topology (star), this
    helper reconstructs group membership metadata so traversal can expand
    missing host-to-host relations virtually (without materializing N^2 edges).
    """
    existing_pairs: set[tuple[str, str]] = set()
    clusters: dict[tuple[str, str], dict[str, Any]] = {}

    for edge in edges:
        if not isinstance(edge, dict):
            continue
        relation_key = str(edge.get("relation") or "").strip().lower()
        if relation_key != _LOCAL_REUSE_RELATION_KEY:
            continue

        from_id = str(edge.get("from") or "").strip()
        to_id = str(edge.get("to") or "").strip()
        if from_id and to_id:
            existing_pairs.add((from_id, to_id))

        notes = edge.get("notes")
        if not isinstance(notes, dict):
            continue
        topology = str(notes.get("topology") or "").strip().lower()
        if topology != "star":
            # Mesh already has all relations materialized.
            continue

        local_user = str(notes.get("local_admin_username") or "").strip().lower()
        cluster_id = str(notes.get("reuse_cluster_id") or "").strip()
        if not cluster_id:
            # Backward-compatible fallback for legacy edges without cluster id.
            cluster_id = f"legacy:{local_user or 'unknown'}"

        cluster_key = (cluster_id, local_user)
        if cluster_key not in clusters:
            clusters[cluster_key] = {
                "cluster_id": cluster_id,
                "local_admin_username": notes.get("local_admin_username"),
                "node_ids": set(),
            }
        cluster = clusters[cluster_key]
        node_ids_set = cluster.get("node_ids")
        if isinstance(node_ids_set, set):
            if from_id in nodes_map:
                node_ids_set.add(from_id)
            if to_id in nodes_map:
                node_ids_set.add(to_id)
            raw_node_ids = notes.get("confirmed_node_ids")
            if isinstance(raw_node_ids, list):
                node_ids_set.update(
                    {
                        str(node_id).strip()
                        for node_id in raw_node_ids
                        if isinstance(node_id, str)
                        and str(node_id).strip()
                        and str(node_id).strip() in nodes_map
                    }
                )

    by_node: dict[str, list[dict[str, Any]]] = {}
    for cluster in clusters.values():
        node_ids_set = cluster.get("node_ids")
        if not isinstance(node_ids_set, set):
            continue
        node_ids = tuple(
            sorted({str(node_id) for node_id in node_ids_set}, key=str.lower)
        )
        if len(node_ids) < 2:
            continue
        cluster["node_ids"] = node_ids
        for node_id in node_ids:
            by_node.setdefault(node_id, []).append(cluster)

    return by_node, existing_pairs


def _build_local_reuse_useful_node_ids(
    nodes_map: dict[str, Any],
    edges: list[dict[str, Any]],
) -> set[str]:
    """Return nodes worth targeting via LocalAdminPassReuse hops.

    We keep local-reuse transitions only when the destination node can produce
    non-context progress (e.g. AdminTo/HasSession/ExecuteDCOM) or is already a
    high-value node.
    """
    useful: set[str] = set()
    context_relations = {
        str(rel).strip().lower() for rel in CONTEXT_ONLY_RELATIONS.keys()
    }

    for edge in edges:
        if not isinstance(edge, dict):
            continue
        relation_key = str(edge.get("relation") or "").strip().lower()
        if (
            not relation_key
            or relation_key == _LOCAL_REUSE_RELATION_KEY
            or relation_key in context_relations
        ):
            continue
        from_id = str(edge.get("from") or "").strip()
        if from_id:
            useful.add(from_id)

    for node_id, node in nodes_map.items():
        if not isinstance(node, dict):
            continue
        if _node_is_effectively_high_value(node):
            useful.add(str(node_id))

    return useful


def _build_implicit_dumplsa_overlay(
    graph: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    """Build virtual DumpLSA self-loop edges for local-admin Computer targets.

    For every Computer node reachable via a deterministic local-admin access
    edge (see :func:`_edge_grants_local_admin_session` — AdminTo,
    ReadLAPSPassword, Ntlmv1RelayRBCD, SPNJack, and AllowedToDelegate with
    protocol transition), injects a synthetic self-loop ``DumpLSA`` edge that
    bridges local_admin_session to credential_recovered (machine account hash
    via T1003.004 — LSA secrets).

    DumpLSA is deterministic: HKLM\\SECURITY\\Policy\\Secrets\\$MACHINE.ACC
    always contains the machine account hash when the caller has local admin.

    Edges excluded from the bridge:
    - CanPSRemote — WinRM session as the source *user*, not as local admin.
    - CanRDP      — RDP session as the source *user*, not as local admin.
    Either can escalate inside the session, but that escalation is not
    guaranteed and is out of scope for a speculative bridge injection.

    The overlay is computed once per DFS call and never persisted to disk.
    """
    nodes_map: dict[str, Any] = graph.get("nodes") or {}
    overlay: dict[str, list[dict[str, Any]]] = {}
    seen_computer_targets: set[str] = set()

    for edge in graph.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        if not _edge_grants_local_admin_session(edge, nodes_map):
            continue
        to_id = str(edge.get("to") or "").strip()
        if not to_id or to_id in seen_computer_targets:
            continue
        target_node = nodes_map.get(to_id)
        if not isinstance(target_node, dict):
            continue
        if str(target_node.get("kind") or "").strip().lower() != "computer":
            continue
        seen_computer_targets.add(to_id)
        overlay.setdefault(to_id, []).append(
            {
                "from": to_id,
                "to": to_id,
                "relation": "DumpLSA",
                "kind": "derived",
                "notes": {
                    "virtual": True,
                    "theoretical": True,
                    "synthesized_from": "implicit_dumplsa_bridge",
                },
            }
        )

    return overlay


def _node_host_identifiers(node: dict[str, Any]) -> list[str]:
    """Return every host identifier a Computer node carries (for DC matching).

    Collects the node label, ``name``, ``samaccountname``, ``dnshostname`` and
    (best-effort) any IP field the collector may have populated. Used to test a
    Computer node against a known DC inventory record with the alias-aware
    :func:`resolve_domain_controllers` matcher.
    """
    props = _node_properties(node)
    candidates = [
        node.get("label"),
        node.get("name"),
        props.get("name"),
        props.get("samaccountname"),
        props.get("dnshostname"),
        props.get("ip"),
        props.get("ipaddress"),
    ]
    seen: set[str] = set()
    idents: list[str] = []
    for raw in candidates:
        token = str(raw or "").strip()
        if token and token.lower() not in seen:
            seen.add(token.lower())
            idents.append(token)
    return idents


def _synthetic_trusted_domain_node_id(domain_name: str) -> str:
    """Return the node id for a synthesized trusted-domain Domain object.

    Keyed on the uppercase domain FQDN (no real SID is available for a
    trust-partner domain discovered only through a pivot), matching the graph's
    ``name:<KEY>`` node-id convention.
    """
    return f"name:{str(domain_name or '').strip().upper()}"


def enrich_foreign_dc_nodes_from_inventory(
    graph: dict[str, Any],
    domains_data: Mapping[str, Any] | None,
) -> bool:
    """Back-fill the writable-DC role marker on foreign DC nodes from inventory.

    A Computer node discovered only through a pivot (e.g. a cross-forest MSSQL
    linked-server target such as ``dc02.darkzero.ext``) never went through the
    trusted domain's own LDAP enumeration, so it carries no ``primaryGroupID`` /
    ``userAccountControl`` — :func:`classify_computer_node_role` returns ``None``
    and every DC-role consumer (notably the F6 direct-DCSync overlay) skips it.

    Trust enumeration DID persist that DC into ``domains_data[<trusted>]`` (its
    ``dc_ip`` / ``pdc`` / ``pdc_hostname_fqdn`` / ``dcs``). This function reads
    that inventory across ALL ``domains_data`` entries — including trusts — via
    the alias-aware SSOT :func:`resolve_domain_controllers`, and when a Computer
    node matches a known DC (by IP / short / FQDN), stamps ``primaryGroupID=516``
    (``RID_DOMAIN_CONTROLLERS``) on the node's properties. That makes the node
    classify as ``writable_dc`` naturally, so every consumer inherits the verdict
    — node PROPERTIES stay the source of truth; the marker is only the value the
    collector could not read.

    For a matched foreign DC whose trusted domain has no Domain-object node in
    this (source-domain) graph, a synthetic Domain node is added from the
    trust-enum name so the DCSync overlay has a real terminal to point at. The
    synthetic node carries the domain SID when one is known, else name-only (no
    SID is available for a pivot-only trust partner). A DC whose domain cannot be
    resolved to a real or synthesizable Domain node is left untouched — the F6
    overlay then SKIPS it rather than mis-pointing the edge at the source domain
    (a false cross-domain DCSync edge is worse than a missing one).

    In-memory only — never persisted to disk. Idempotent (re-stamping an already
    marked node is a no-op). Returns True when it changed the graph.
    """
    if not isinstance(domains_data, Mapping) or not domains_data:
        return False
    nodes_map = graph.get("nodes")
    if not isinstance(nodes_map, dict) or not nodes_map:
        return False

    # Build the DC inventory once per domain: domain-key -> (DomainControllers,
    # domain_sid). ``resolve_domain_controllers`` is the alias-aware SSOT that
    # folds ``dc_ip`` / ``pdc`` / ``pdc_hostname_fqdn`` / ``dcs`` into deduped
    # records — never re-derive a DC walk here.
    inventory: list[tuple[str, Any, str | None]] = []
    for domain_key, domain_entry in domains_data.items():
        if not isinstance(domain_entry, Mapping):
            continue
        controllers = resolve_domain_controllers(domain_entry)
        if controllers.count == 0:
            continue
        domain_sid = str(domain_entry.get("domain_sid") or "").strip() or None
        inventory.append((str(domain_key or "").strip(), controllers, domain_sid))
    if not inventory:
        return False

    changed = False
    # Collect the domains whose Domain node must be ensured AFTER the node walk —
    # synthesizing inside the loop would mutate ``nodes_map`` mid-iteration.
    domains_to_ensure: list[tuple[str, str | None]] = []
    for node in list(nodes_map.values()):
        if not isinstance(node, dict):
            continue
        if str(node.get("kind") or "").strip().lower() != "computer":
            continue
        # Skip nodes the collector already classified from real props — node
        # properties remain the source of truth; we only back-fill absences.
        if classify_computer_node_role(node) is not None:
            continue
        identifiers = _node_host_identifiers(node)
        if not identifiers:
            continue

        matched_domain_key: str | None = None
        matched_domain_sid: str | None = None
        for domain_key, controllers, domain_sid in inventory:
            if any(
                controllers._record_for_host(ident) is not None  # noqa: SLF001
                for ident in identifiers
            ):
                matched_domain_key = domain_key
                matched_domain_sid = domain_sid
                break
        if matched_domain_key is None:
            continue

        # Back-fill the writable-DC marker so classify_computer_node_role -> "writable_dc".
        props = _node_properties(node)
        if node.get("properties") is not props:
            node["properties"] = props
        props["primaryGroupID"] = RID_DOMAIN_CONTROLLERS
        changed = True

        # Queue the matched DC's own domain so its Domain-object node is ensured
        # after the walk. Prefer the domain carried on the node itself
        # (``properties.domain``), falling back to the domains_data key. Never
        # point at the source domain when it does not match.
        node_domain = str(props.get("domain") or matched_domain_key or "").strip()
        if node_domain:
            domains_to_ensure.append((node_domain, matched_domain_sid))

    for node_domain, domain_sid in domains_to_ensure:
        if _ensure_trusted_domain_node(nodes_map, node_domain, domain_sid):
            changed = True

    return changed


#: Relation name of the derived cross-forest TGT-delegation escalation edge.
#: Classified as ``EdgeKind.ESCALATION`` in ``edge_kind.py`` and catalogued in
#: ``attack_step_catalog.py`` (``crossorgtgtdelegation``).
_CROSS_ORG_TGT_DELEGATION_RELATION = "CrossOrgTgtDelegation"

#: Relation for the child->parent forest-root escalation (RaiseChild): from a
#: compromised child Domain object to its parent/forest-root Domain object, via the
#: trust key + krbtgt SID-history forgery. Classified ``EdgeKind.ESCALATION``.
_RAISE_CHILD_RELATION = "RaiseChild"

#: Relations that escalate FROM one compromised Domain object INTO another domain
#: (the cross-domain / cross-forest escalation category). A Domain node is normally
#: a hard DFS terminal (``is_terminal`` in object mode), but when it carries one of
#: these OUTBOUND edges the kill chain genuinely continues across the trust boundary
#: — e.g. ``… → DCSync → DARKZERO.EXT → CrossOrgTgtDelegation → DARKZERO.HTB`` or a
#: child domain -> RaiseChild -> forest root. Only these modeled escalation relations
#: lift the terminal stop; every other outbound edge from a Domain node (structural
#: TrustedBy, etc.) leaves it terminal, so the existing single-domain paths are
#: unaffected. Extend this set as new cross-domain escalation steps land (SID-history
#: abuse, unconstrained-delegation-across-trust, foreign-group-membership).
_CROSS_DOMAIN_ESCALATION_RELATIONS: frozenset[str] = frozenset(
    {
        _CROSS_ORG_TGT_DELEGATION_RELATION.lower(),
        _RAISE_CHILD_RELATION.lower(),
    }
)


def _domain_has_cross_domain_escalation_out(
    node_id: str,
    adjacency: Mapping[str, list[dict[str, Any]]],
    visited: set[str],
) -> bool:
    """True when a Domain node can still escalate INTO another domain.

    A compromised Domain object is normally the end of a kill chain (a hard DFS
    terminal in object mode), but a forest trust that forwards Kerberos TGTs
    (``CrossOrgTgtDelegation`` and its cross-domain-escalation siblings) lets the
    chain continue into the trusting forest. So a Domain node stays terminal
    EXCEPT when it carries such an outbound escalation edge to an as-yet-unvisited
    node — then the DFS must keep going so
    ``… → DCSync → EXT → CrossOrgTgtDelegation → HTB`` materializes as one path.

    Reuses the caller's pre-built ``adjacency`` (already excludes non-traversable
    edges) — no rescan. The ``visited`` guard prevents a trust cycle (A→B→A) from
    looping the DFS.
    """
    for edge in adjacency.get(node_id, ()):
        if (
            str(edge.get("relation") or "").strip().lower()
            not in _CROSS_DOMAIN_ESCALATION_RELATIONS
        ):
            continue
        to_id = str(edge.get("to") or "")
        if to_id and to_id != node_id and to_id not in visited:
            return True
    return False


def _find_domain_node_id(
    nodes_map: Mapping[str, Any],
    *,
    label: str | None = None,
    domain_sid: str | None = None,
) -> str | None:
    """Return the id of the Domain-kind node matching ``label`` or ``domain_sid``.

    SID match is authoritative; the label match (uppercase FQDN) is the only way
    to resolve a trust-partner domain whose node was synthesized name-only (no
    SID available for a pivot-discovered domain). Returns ``None`` when no Domain
    node matches — the coupling then conservatively skips (a missing edge is
    safer than a mis-pointed one).
    """
    want_sid = str(domain_sid or "").strip().upper() or None
    want_label = str(label or "").strip().upper() or None
    for node_id, node in nodes_map.items():
        if not isinstance(node, dict) or not _node_is_domain(node):
            continue
        if want_sid is not None and _node_domain_sid(node) == want_sid:
            return str(node_id)
        node_label = str(node.get("label") or node.get("name") or "").strip().upper()
        if want_label is not None and node_label == want_label:
            return str(node_id)
    return None


def _iter_cross_org_tgt_delegation_trusts(
    graph: dict[str, Any] | None,
    domains_data: Mapping[str, Any] | None,
) -> list[dict[str, Any]]:
    """Collect trusts carrying CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION.

    Reads from BOTH robust sources and de-duplicates:

    * ``domains_data[<domain>]["trusts"]`` — the durable enum SSOT persisted by
      the trust enumerator (``_persist_trust_records_to_domains_data``), each
      record carrying ``source_domain`` / ``target_domain`` / ``trust_attributes``
      / ``attribute_flags`` / ``partner_sid``.
    * The graph's own ``TrustedBy`` edges — when the collector persisted one, its
      ``notes`` carry the same ``trustAttributes`` / ``attributeFlags``.

    Only a **forest-transitive** trust with the delegation attribute qualifies
    (mirrors the report finding's condition 1), so an external / intra-forest
    trust never couples. Each returned record is normalized to
    ``{"source_domain", "target_domain", "partner_sid"}`` where ``source_domain``
    is the TRUSTING domain (whose TDO carries the attribute) and
    ``target_domain`` is the TRUSTED (partner) domain that can escalate into it.
    """
    from adscan_internal.services.enumeration.trust_query import (  # noqa: PLC0415
        cross_org_tgt_delegation_enabled,
    )

    def _flags(record: Mapping[str, Any], *keys: str) -> set[str]:
        for key in keys:
            value = record.get(key)
            if isinstance(value, (list, tuple, set)):
                return {str(flag).strip().upper() for flag in value}
        return set()

    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def _consider(
        *,
        source_domain: str,
        target_domain: str,
        trust_attributes: int | None,
        flags: set[str],
        partner_sid: str | None,
    ) -> None:
        src = str(source_domain or "").strip().upper()
        tgt = str(target_domain or "").strip().upper()
        if not src or not tgt:
            return
        has_delegation = "CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION" in flags or (
            cross_org_tgt_delegation_enabled(trust_attributes)
        )
        is_forest_transitive = "FOREST_TRANSITIVE" in flags
        if not (has_delegation and is_forest_transitive):
            return
        key = (src, tgt)
        if key in seen:
            return
        seen.add(key)
        results.append(
            {
                "source_domain": src,
                "target_domain": tgt,
                "partner_sid": str(partner_sid or "").strip().upper() or None,
            }
        )

    # Source 1 — durable enum SSOT in domains_data.
    if isinstance(domains_data, Mapping):
        for domain_entry in domains_data.values():
            if not isinstance(domain_entry, Mapping):
                continue
            trusts = domain_entry.get("trusts")
            if not isinstance(trusts, (list, tuple)):
                continue
            for record in trusts:
                if not isinstance(record, Mapping):
                    continue
                raw_attrs = record.get("trust_attributes")
                try:
                    attrs_int = int(raw_attrs) if raw_attrs is not None else None
                except (TypeError, ValueError):
                    attrs_int = None
                _consider(
                    source_domain=str(record.get("source_domain") or ""),
                    target_domain=str(record.get("target_domain") or ""),
                    trust_attributes=attrs_int,
                    flags=_flags(record, "attribute_flags", "attributeFlags"),
                    partner_sid=str(record.get("partner_sid") or ""),
                )

    # Source 2 — TrustedBy edges persisted in the graph itself.
    # ``graph`` is optional: a caller resolving trusts purely from
    # ``domains_data`` (e.g. the cross-domain-escalation drain in
    # ``cross_domain_escalation._cross_org_applies``) passes ``None``. Treat a
    # missing/non-dict graph as "no graph-persisted trust edges" so Source 1
    # (domains_data) still works and this function never raises on ``None``.
    graph_map = graph if isinstance(graph, dict) else {}
    nodes_map = graph_map.get("nodes")
    nodes_map = nodes_map if isinstance(nodes_map, dict) else {}

    def _node_label(node_id: str) -> str:
        node = nodes_map.get(str(node_id or "").strip())
        if isinstance(node, dict):
            return str(node.get("label") or node.get("name") or "").strip()
        return ""

    for edge in graph_map.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        if str(edge.get("relation") or "").strip().lower() != "trustedby":
            continue
        notes = edge.get("notes") if isinstance(edge.get("notes"), dict) else {}
        raw_attrs = notes.get("trustAttributes")
        try:
            attrs_int = int(raw_attrs) if raw_attrs is not None else None
        except (TypeError, ValueError):
            attrs_int = None
        # A TrustedBy edge is source=trusting-domain -> target=partner (see
        # ldap_collector._collect_trusts), matching the domains_data convention.
        source_label = (
            str(edge.get("source_name") or "").strip()
            or _node_label(str(edge.get("from") or edge.get("source") or ""))
        )
        target_label = (
            str(edge.get("target_name") or "").strip()
            or _node_label(str(edge.get("to") or edge.get("target") or ""))
        )
        _consider(
            source_domain=source_label,
            target_domain=target_label,
            trust_attributes=attrs_int,
            flags=_flags(notes, "attributeFlags", "attribute_flags"),
            partner_sid=str(notes.get("partnerSid") or ""),
        )

    return results


def couple_cross_org_tgt_delegation_edges(
    graph: dict[str, Any],
    domains_data: Mapping[str, Any] | None,
) -> bool:
    """Couple a cross-forest TGT-delegation escalation edge onto the graph.

    For every forest trust that carries
    ``CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION``, add a derived escalation edge
    ``compromised (trusted) Domain -> trusting Domain`` when BOTH domain objects
    exist as nodes in the graph. This is the trust-attribute analogue of the F6
    direct-DCSync overlay: the trusted-forest DCSync anchor already terminates a
    kill chain at the compromised (trusted) domain node; this edge continues that
    chain across the trust boundary into the trusting forest, because the trust
    forwards Kerberos TGTs across the boundary.

    Conservative by construction:

    * Only fires when the attribute is ACTUALLY present on a forest-transitive
      trust — never speculatively.
    * Requires BOTH domain nodes to exist; a missing trusting-domain node means
      the graph has no terminal to point at, so no edge is minted.
    * The edge is marked ``theoretical`` — ADscan models the exposure from the
      trust attribute but does not (yet) execute the cross-forest ticket capture.

    Idempotent (re-adding an existing edge is a no-op). Returns True when it
    changed the graph. This mints the edge into the passed graph dict; when the
    dict is the ORIGIN domain's persisted graph (see
    :func:`attack_graph_service.persist_cross_domain_trust_edges`) the edge
    survives reloads so an executed escalation keeps its ``success`` status. The
    query-time merge re-runs this as a no-op once the edge is already present.
    """
    nodes_map = graph.get("nodes")
    if not isinstance(nodes_map, dict) or not nodes_map:
        return False
    trusts = _iter_cross_org_tgt_delegation_trusts(graph, domains_data)
    if not trusts:
        return False

    edges = graph.get("edges")
    if not isinstance(edges, list):
        edges = []
        graph["edges"] = edges

    # Index existing CrossOrgTgtDelegation edges to keep the coupling idempotent.
    existing_pairs: set[tuple[str, str]] = set()
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if str(edge.get("relation") or "") != _CROSS_ORG_TGT_DELEGATION_RELATION:
            continue
        frm = str(edge.get("from") or edge.get("source") or "").strip()
        to = str(edge.get("to") or edge.get("target") or "").strip()
        if frm and to:
            existing_pairs.add((frm, to))

    changed = False
    for trust in trusts:
        # trusting domain (whose TDO carries the attribute) = source_domain.
        trusting_node_id = _find_domain_node_id(
            nodes_map, label=trust["source_domain"]
        )
        # compromised / trusted (partner) domain = target_domain.
        compromised_node_id = _find_domain_node_id(
            nodes_map,
            label=trust["target_domain"],
            domain_sid=trust.get("partner_sid"),
        )
        if not trusting_node_id or not compromised_node_id:
            continue
        if compromised_node_id == trusting_node_id:
            continue
        pair = (compromised_node_id, trusting_node_id)
        if pair in existing_pairs:
            continue
        existing_pairs.add(pair)
        edges.append(
            {
                "from": compromised_node_id,
                "to": trusting_node_id,
                "relation": _CROSS_ORG_TGT_DELEGATION_RELATION,
                "kind": "escalation",
                "status": "discovered",
                "notes": {
                    "theoretical": True,
                    "synthesized_from": "cross_org_tgt_delegation_trust",
                    "trusting_domain": trust["source_domain"],
                    "compromised_domain": trust["target_domain"],
                },
            }
        )
        changed = True

    return changed


def _iter_within_forest_child_parent(
    domains_data: Mapping[str, Any] | None,
) -> list[dict[str, str]]:
    """Collect (child, parent) pairs for same-forest child->parent escalation.

    A domain ``a.b.c`` is a CHILD of ``b.c`` when a ``WITHIN_FOREST`` trust to the
    parent exists AND the parent (``b.c``) is a known domain in ``domains_data``
    (so RaiseChild has a real forest root to escalate into). The parent is the DNS
    suffix — matching ``run_raise_child``'s own child/parent identification
    (``privileges.py`` ``domain.split(".", 1)[1]``). Only the FIRST DNS label is
    stripped, so ``child.parent.forest`` -> ``parent.forest`` (one hop up); deeper
    chains escalate one level per compromise, which is correct.

    Returns records ``{"child": <lower>, "parent": <lower>}``; de-duplicated.
    """
    if not isinstance(domains_data, Mapping):
        return []
    known = {str(name).strip().lower() for name in domains_data.keys()}
    results: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for name, entry in domains_data.items():
        child = str(name or "").strip().lower()
        parts = child.split(".", 1)
        if len(parts) < 2:
            continue
        parent = parts[1]
        if parent not in known or parent == child:
            continue
        if not isinstance(entry, Mapping):
            continue
        # Require a WITHIN_FOREST trust from the child to the parent to avoid
        # coupling a RaiseChild edge on a mere DNS-suffix coincidence between two
        # unrelated domains that happen to share a suffix.
        has_within_forest = False
        for trust in entry.get("trusts") or ():
            if not isinstance(trust, Mapping):
                continue
            tgt = str(trust.get("target_domain") or "").strip().lower()
            flags = {
                str(f).strip().upper()
                for f in (trust.get("attribute_flags") or ())
            }
            if tgt == parent and "WITHIN_FOREST" in flags:
                has_within_forest = True
                break
        if not has_within_forest:
            continue
        key = (child, parent)
        if key in seen:
            continue
        seen.add(key)
        results.append({"child": child, "parent": parent})
    return results


def couple_raise_child_edges(
    graph: dict[str, Any],
    domains_data: Mapping[str, Any] | None,
) -> bool:
    """Couple a child->parent RaiseChild escalation edge onto the graph.

    For every same-forest child domain whose parent/forest root is a known domain
    (see :func:`_iter_within_forest_child_parent`), add a derived escalation edge
    ``child Domain -> parent Domain`` when BOTH domain objects exist as nodes. This
    is the intra-forest analogue of :func:`couple_cross_org_tgt_delegation_edges`:
    a compromise of the child forest-lets the kill chain continue up to the forest
    root via the trust key + krbtgt SID-history forgery (``raise_child_native``).

    Conservative + idempotent, mirrors the cross-org coupling. Persisted into the
    origin (child) domain's graph via
    :func:`attack_graph_service.persist_cross_domain_trust_edges` so its status
    survives reloads. Returns True when it changed the graph.
    """
    nodes_map = graph.get("nodes")
    if not isinstance(nodes_map, dict) or not nodes_map:
        return False
    pairs = _iter_within_forest_child_parent(domains_data)
    if not pairs:
        return False

    edges = graph.get("edges")
    if not isinstance(edges, list):
        edges = []
        graph["edges"] = edges

    existing_pairs: set[tuple[str, str]] = set()
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if str(edge.get("relation") or "") != _RAISE_CHILD_RELATION:
            continue
        frm = str(edge.get("from") or edge.get("source") or "").strip()
        to = str(edge.get("to") or edge.get("target") or "").strip()
        if frm and to:
            existing_pairs.add((frm, to))

    changed = False
    for pair_rec in pairs:
        child_node_id = _find_domain_node_id(nodes_map, label=pair_rec["child"])
        parent_node_id = _find_domain_node_id(nodes_map, label=pair_rec["parent"])
        if not child_node_id or not parent_node_id:
            continue
        if child_node_id == parent_node_id:
            continue
        pair = (child_node_id, parent_node_id)
        if pair in existing_pairs:
            continue
        existing_pairs.add(pair)
        edges.append(
            {
                "from": child_node_id,
                "to": parent_node_id,
                "relation": _RAISE_CHILD_RELATION,
                "kind": "escalation",
                "status": "discovered",
                "notes": {
                    "theoretical": True,
                    "synthesized_from": "within_forest_child_parent_trust",
                    "child_domain": pair_rec["child"],
                    "parent_domain": pair_rec["parent"],
                },
            }
        )
        changed = True

    return changed


def _ensure_trusted_domain_node(
    nodes_map: dict[str, Any],
    domain_name: str,
    domain_sid: str | None,
) -> bool:
    """Add a synthetic Domain-object node for ``domain_name`` when absent.

    Returns True when a node was added. No-op when a Domain node whose label /
    SID already denotes this domain is present. When a real SID is available the
    synthetic node uses the SID-keyed id (matching the collector convention);
    otherwise it is name-keyed (a pivot-only trust partner has no SID).
    """
    domain_upper = str(domain_name or "").strip().upper()
    if not domain_upper:
        return False
    normalized_sid = str(domain_sid or "").strip().upper() or None

    # Already present? Match by SID (authoritative) or by label/name.
    for node in nodes_map.values():
        if not isinstance(node, dict) or not _node_is_domain(node):
            continue
        if normalized_sid is not None and _node_domain_sid(node) == normalized_sid:
            return False
        label = str(node.get("label") or node.get("name") or "").strip().upper()
        if label == domain_upper:
            return False

    node_id = (
        f"name:{normalized_sid}"
        if normalized_sid is not None
        else _synthetic_trusted_domain_node_id(domain_upper)
    )
    if node_id in nodes_map:
        return False

    synthetic: dict[str, Any] = {
        "id": node_id,
        "kind": "Domain",
        "label": domain_upper,
        "name": domain_upper,
        "objectId": normalized_sid,
        "isTierZero": True,
        "properties": {
            "name": domain_upper,
            "domain": domain_upper,
            "objectid": normalized_sid,
            "isTierZero": True,
            "synthesized_from": "trusted_domain_inventory",
        },
    }
    nodes_map[node_id] = synthetic
    return True


def _build_implicit_dc_dcsync_overlay(
    graph: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    """Build virtual direct ``DCSync`` edges for admin-ticket arrivals on a DC.

    For every **writable Domain Controller** Computer node reached via a
    deterministic local-admin access edge (see
    :func:`_edge_grants_local_admin_session` — AdminTo, ReadLAPSPassword,
    Ntlmv1RelayRBCD, SPNJack, AllowedToDelegate with protocol transition, and the
    MSSQL SYSTEM-escalation self-loops MssqlSeImpersonateEscalation /
    MssqlTokenTheftEscalation, which reach NT AUTHORITY\\SYSTEM = the DC machine
    account), injects a synthetic ``Computer -> DCSync -> <Domain object>`` edge.

    AD rationale: an admin/SYSTEM context on a writable DC can DCSync directly.
    Running as SYSTEM IS the DC machine account, which is a member of Domain
    Controllers and holds DS-Replication-Get-Changes / -All on the domain head;
    impersonating Administrator (RID 500) likewise yields a Domain Admin with
    replication rights. So the admin ticket replicates the domain credentials
    *immediately*, without first dumping the machine account from LSA secrets.

    This is injected IN ADDITION to (never replacing) the DumpLSA self-loop from
    :func:`_build_implicit_dumplsa_overlay`. The two are distinct techniques:
    the direct edge is the fastest domain compromise; the DumpLSA path also
    extracts the durable machine-account credential (persistence / offline /
    cross-host reuse). Their attack cores diverge (``...,DCSync`` vs
    ``...,DumpLSA,...,DCSync``) so both survive the display filters.

    Scoped to **writable** DCs only — an RODC machine account holds only partial
    secrets and no full GetChangesAll, so it keeps DumpLSA-only.

    The overlay is computed once per DFS call and never persisted to disk.
    """
    nodes_map: dict[str, Any] = graph.get("nodes") or {}

    # Map every Domain-object node by its domain SID (a domain object's objectid
    # IS the domain SID ``S-1-5-21-X-Y-Z``).  A writable DC only holds GetChanges
    # / GetChangesAll on ITS OWN domain head, so each DC's synthetic DCSync edge
    # must point at the matching domain node — NEVER a foreign domain.  In a
    # multi-domain / forest graph, pointing every DC at a single first-found
    # domain node would mint a false ``DC-A -> DCSync -> DOMAIN-B`` edge.
    domain_node_by_sid: dict[str, str] = {}
    domain_node_by_label: dict[str, str] = {}
    domain_node_ids: list[str] = []
    for node_id, node in nodes_map.items():
        if not isinstance(node, dict) or not _node_is_domain(node):
            continue
        nid = str(node_id)
        domain_node_ids.append(nid)
        dom_sid = _node_domain_sid(node)
        if dom_sid and dom_sid not in domain_node_by_sid:
            domain_node_by_sid[dom_sid] = nid
        # Label index (uppercase FQDN) — the ONLY way to resolve a trust-partner
        # domain whose Domain node was synthesized name-only (no SID available
        # for a pivot-discovered DC; see enrich_foreign_dc_nodes_from_inventory).
        dom_label = str(node.get("label") or node.get("name") or "").strip().upper()
        if dom_label and dom_label not in domain_node_by_label:
            domain_node_by_label[dom_label] = nid
    if not domain_node_ids:
        return {}

    # Single-domain fallback target: when exactly one domain node exists, an
    # unresolved DC domain SID still maps unambiguously to it (the common,
    # currently-validated case — preserves today's single-domain behaviour).
    single_domain_node_id: str | None = (
        domain_node_ids[0] if len(domain_node_ids) == 1 else None
    )

    overlay: dict[str, list[dict[str, Any]]] = {}
    seen_dc_targets: set[str] = set()

    for edge in graph.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        if not _edge_grants_local_admin_session(edge, nodes_map):
            continue
        to_id = str(edge.get("to") or "").strip()
        if not to_id or to_id in seen_dc_targets:
            continue
        target_node = nodes_map.get(to_id)
        if not isinstance(target_node, dict):
            continue
        if str(target_node.get("kind") or "").strip().lower() != "computer":
            continue
        # Writable DC only — RODCs hold partial secrets / no full replication.
        if classify_computer_node_role(target_node) != "writable_dc":
            continue
        seen_dc_targets.add(to_id)

        # Per-DC domain resolution (the canonical AD mapping):
        #   (a) the DC's own domain SID resolves to a domain node -> use it;
        #   (b) else the DC node's own domain LABEL (``properties.domain``)
        #       resolves to a domain node -> use it. This is the cross-forest
        #       trusted-domain case: a pivot-discovered DC carries no SID, so
        #       its inventory-back-filled writable_dc marker + a name-only
        #       (synthesized) Domain node are linked only by label — NEVER by
        #       the source domain's SID;
        #   (c) else exactly one domain node in the graph -> use it (single-
        #       domain workspace, preserves today's behaviour);
        #   (d) else (multiple domains, no SID/label match) -> SKIP this DC. A
        #       false cross-domain DCSync edge is worse than a missing one.
        dc_domain_sid = _node_domain_sid(target_node)
        domain_node_id: str | None = None
        if dc_domain_sid is not None:
            domain_node_id = domain_node_by_sid.get(dc_domain_sid)
        if domain_node_id is None:
            dc_domain_label = (
                str(_node_properties(target_node).get("domain") or "").strip().upper()
            )
            if dc_domain_label:
                domain_node_id = domain_node_by_label.get(dc_domain_label)
        if domain_node_id is None:
            domain_node_id = single_domain_node_id
        if domain_node_id is None:
            continue

        overlay.setdefault(to_id, []).append(
            {
                "from": to_id,
                "to": domain_node_id,
                "relation": "DCSync",
                "kind": "derived",
                "notes": {
                    "virtual": True,
                    "theoretical": True,
                    "synthesized_from": "implicit_dc_dcsync_bridge",
                },
            }
        )

    return overlay


def _build_implicit_session_followup_overlay(
    graph: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    """Build virtual session-impersonation follow-up self-loops for HasSession.

    ``HasSession`` is an ACCESS edge (``EdgeKind.AUTH``): ``Computer ->
    HasSession -> User`` means a logon session of ``User`` exists on the host.
    Arriving at the user is NOT ownership — you must LEVERAGE the session to
    "become" the user. Two techniques do so, both modelled here as a derived
    self-loop on the session-user node (``User -> <technique> -> User``):

      * ``ScheduledTask`` — register a Task Scheduler task whose principal IS the
        session user (``InteractiveToken``), running code under their existing
        logon session (the implemented native path, ``hassession_native``).
      * ``DumpLSASS`` — dump the session user's credentials from the host LSASS.

    Both carry ``compromise_semantics=direct_target_compromise`` (provides
    ``credential_recovered``), so after the follow-up the path may traverse the
    session user's OWN outbound edges (``MemberOf -> Administrators -> DCSync ->
    Domain``, etc.).

    Self-gating — the credential-context guard only lets these chain when the
    immediately-preceding non-transparent edge produced ``local_admin_session``.
    Among edges that target a USER node that is uniquely ``HasSession``
    (``access_capability_only``); control edges that land on a user (GenericAll,
    ForceChangePassword, ...) produce ``credential_recovered``, which does NOT
    satisfy ``local_admin_session``, so the guard withholds the follow-ups there.
    The follow-ups also cannot self-chain (after one runs the context is
    ``credential_recovered``, not ``local_admin_session``), so exactly the two
    divergent variants are generated, never an explosion.

    CRITICAL — this is intentionally the ONLY follow-up set ``HasSession``
    unlocks. It does NOT receive the host self-credential follow-ups (``DumpLSA``
    / ``DumpDPAPI`` / ``DumpSAM``) that a local-admin Computer arrival gets:
    those are minted by :func:`_build_implicit_dumplsa_overlay` on COMPUTER nodes
    only, never on the user nodes this overlay targets.

    The overlay is computed once per DFS call and never persisted to disk.
    """
    nodes_map: dict[str, Any] = graph.get("nodes") or {}
    overlay: dict[str, list[dict[str, Any]]] = {}
    seen_session_users: set[str] = set()

    for edge in graph.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        if str(edge.get("relation") or "").strip().lower() != "hassession":
            continue
        to_id = str(edge.get("to") or "").strip()
        if not to_id or to_id in seen_session_users:
            continue
        target_node = nodes_map.get(to_id)
        if not isinstance(target_node, dict):
            continue
        # HasSession targets a session principal (User). Skip anything else.
        if str(target_node.get("kind") or "").strip().lower() != "user":
            continue
        seen_session_users.add(to_id)
        for technique in ("ScheduledTask", "DumpLSASS"):
            overlay.setdefault(to_id, []).append(
                {
                    "from": to_id,
                    "to": to_id,
                    "relation": technique,
                    "kind": "derived",
                    "notes": {
                        "virtual": True,
                        "theoretical": True,
                        "synthesized_from": "implicit_session_followup_bridge",
                    },
                }
            )

    return overlay


def _build_implicit_xpcmdshell_overlay(
    graph: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    """Build virtual ``XpCmdshell`` self-loops for MSSQL sysadmin-reachable hosts.

    ``xp_cmdshell`` requires **sysadmin** on the SQL instance.  This overlay
    injects a synthetic self-loop ``Computer -> XpCmdshell -> Computer`` (the
    terminal MSSQL-hosted OS-command-execution technique) on every Computer node
    reached via an MSSQL access edge that grants sysadmin on that instance:

      * ``SQLAdmin`` — sysadmin on the LOCAL instance (static, via the access
        lane's ``unlocks_mssql_rce`` flag);
      * ``MssqlLinkedServerLateral`` — sysadmin on the REMOTE instance ONLY when
        the mapped login is sysadmin there.  That is a PER-EDGE fact
        (``notes.remote_is_sysadmin``, set by the collector's read-only remote
        role check); the execution identity is the mapped remote login
        (``notes.remote_login``), carried onto the self-loop for rendering.

    ``SQLAccess`` (below sysadmin) is deliberately excluded — no local RCE.  This
    is why the DarkZero chain terminates at DC02 (linked, sysadmin) and not at
    DC01 (john.w is SQLAccess, not sysadmin there).

    Mirrors :func:`_build_implicit_dumplsa_overlay`: the technique is a host
    self-loop, ``kind="derived"`` (terminal → a kill chain can END at RCE),
    theoretical.  Computed once per DFS call, never persisted.
    """
    from adscan_internal.services.post_exploitation.access_followups import (  # noqa: PLC0415
        access_unlocks_mssql_rce,
    )

    nodes_map: dict[str, Any] = graph.get("nodes") or {}
    overlay: dict[str, list[dict[str, Any]]] = {}
    seen_computer_targets: set[str] = set()

    for edge in graph.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        rel = str(edge.get("relation") or "").strip().lower()
        exec_identity = ""
        # Tri-state: None = unknown (key absent), True = already enabled,
        # False = disabled-but-sysadmin-can-enable. Only the linked-server edge
        # carries this fact; the SQLAdmin-local branch leaves it unknown.
        xp_cmdshell_state: bool | None = None
        if rel == _MSSQL_LINKED_KEY:
            notes = edge.get("notes") if isinstance(edge.get("notes"), dict) else {}
            unlocks = bool(notes.get("remote_is_sysadmin"))
            exec_identity = str(notes.get("remote_login") or "").strip()
            if "xp_cmdshell_enabled" in notes:
                xp_cmdshell_state = bool(notes.get("xp_cmdshell_enabled"))
        else:
            unlocks = access_unlocks_mssql_rce(rel)
        if not unlocks:
            continue
        to_id = str(edge.get("to") or "").strip()
        if not to_id or to_id in seen_computer_targets:
            continue
        target_node = nodes_map.get(to_id)
        if not isinstance(target_node, dict):
            continue
        if str(target_node.get("kind") or "").strip().lower() != "computer":
            continue
        seen_computer_targets.add(to_id)
        loop_notes: dict[str, Any] = {
            "virtual": True,
            "theoretical": True,
            "synthesized_from": "implicit_xpcmdshell_bridge",
        }
        if exec_identity:
            loop_notes["execution_identity"] = exec_identity
        # Propagate the xp_cmdshell config state from the linked edge, when known.
        # True  → already enabled (commands run directly, no config change);
        # False → disabled but the sysadmin can enable it (must be reverted).
        # Unknown (key absent) → set neither; execution decides at runtime.
        if xp_cmdshell_state is True:
            loop_notes["xp_cmdshell_already_enabled"] = True
        elif xp_cmdshell_state is False:
            loop_notes["requires_enable"] = True
        overlay.setdefault(to_id, []).append(
            {
                "from": to_id,
                "to": to_id,
                "relation": "XpCmdshell",
                "kind": "derived",
                "notes": loop_notes,
            }
        )

    return overlay


def _build_implicit_openrowset_bulk_overlay(
    graph: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    """Build virtual ``MssqlOpenRowsetBulkRead`` self-loops for BULK-ops-capable hosts.

    ``OPENROWSET(BULK ... , SINGLE_BLOB)`` lets a session that holds ADMINISTER
    BULK OPERATIONS read arbitrary files the SQL service account can reach — an
    arbitrary-file-read technique, chained off the SAME three MSSQL access
    relations as the XpCmdshell overlay (mirrors
    :func:`_build_implicit_xpcmdshell_overlay`), but with a DIFFERENT gate:
    unlike xp_cmdshell (sysadmin-only), this capability is reachable WITHOUT
    sysadmin —

      * ``SQLAdmin`` — sysadmin on the LOCAL instance always has it (sysadmin
        bypasses every permission check) — unconditional, like XpCmdshell;
      * ``SQLAccess`` — below-sysadmin local access. Conditional on the
        collector's PER-PRINCIPAL fact ``notes.bulk_ops_capable`` (effective
        ``bulkadmin`` role membership or an explicit ``ADMINISTER BULK
        OPERATIONS`` grant) — the case XpCmdshell explicitly excludes, but this
        technique does not, since the permission does not require sysadmin;
      * ``MssqlLinkedServerLateral`` — conditional on the PER-EDGE fact
        ``notes.remote_bulk_admin`` (set by the collector's read-only remote
        probe), mirroring ``notes.remote_is_sysadmin`` for XpCmdshell.

    Computed once per DFS call, never persisted.
    """
    nodes_map: dict[str, Any] = graph.get("nodes") or {}
    overlay: dict[str, list[dict[str, Any]]] = {}
    seen_computer_targets: set[str] = set()

    for edge in graph.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        rel = str(edge.get("relation") or "").strip().lower()
        if rel not in {"sqladmin", "sqlaccess", _MSSQL_LINKED_KEY}:
            continue
        notes = edge.get("notes") if isinstance(edge.get("notes"), dict) else {}
        exec_identity = ""
        if rel == _MSSQL_LINKED_KEY:
            bulk_capable = bool(notes.get("remote_bulk_admin"))
            exec_identity = str(notes.get("remote_login") or "").strip()
        elif rel == "sqladmin":
            # Sysadmin on the local instance always has ADMINISTER BULK
            # OPERATIONS — the permission check does not apply to sysadmin.
            bulk_capable = True
        else:  # sqlaccess
            bulk_capable = bool(notes.get("bulk_ops_capable"))
        if not bulk_capable:
            continue
        to_id = str(edge.get("to") or "").strip()
        if not to_id or to_id in seen_computer_targets:
            continue
        target_node = nodes_map.get(to_id)
        if not isinstance(target_node, dict):
            continue
        if str(target_node.get("kind") or "").strip().lower() != "computer":
            continue
        seen_computer_targets.add(to_id)
        loop_notes: dict[str, Any] = {
            "virtual": True,
            "theoretical": True,
            "synthesized_from": "implicit_openrowset_bulk_bridge",
        }
        if exec_identity:
            loop_notes["execution_identity"] = exec_identity
        overlay.setdefault(to_id, []).append(
            {
                "from": to_id,
                "to": to_id,
                "relation": "MssqlOpenRowsetBulkRead",
                "kind": "derived",
                "notes": loop_notes,
            }
        )

    return overlay


def _build_implicit_path_overlays(
    graph: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    """Merge every synthetic per-node overlay the DFS traverses into one map.

    Single entry point for the DFS so new overlays can be added without
    threading another argument through three DFS sites and the worker globals.
    Currently merges:

    * the DumpLSA self-loop bridge (:func:`_build_implicit_dumplsa_overlay`) —
      ``Computer -> DumpLSA -> Computer`` for any deterministic local-admin
      arrival on a Computer;
    * the direct DCSync bridge (:func:`_build_implicit_dc_dcsync_overlay`) —
      ``Computer -> DCSync -> Domain`` for an admin-ticket arrival on a writable
      DC, in addition to (not replacing) the DumpLSA self-loop;
    * the session-impersonation follow-up
      (:func:`_build_implicit_session_followup_overlay`) —
      ``User -> ScheduledTask -> User`` and ``User -> DumpLSASS -> User`` for the
      session user a ``HasSession`` edge lands on, so the path can "become" the
      session user and traverse their outbound edges;
    * the OPENROWSET(BULK ...) arbitrary-file-read bridge
      (:func:`_build_implicit_openrowset_bulk_overlay`) —
      ``Computer -> MssqlOpenRowsetBulkRead -> Computer`` for any MSSQL access
      edge (SQLAdmin unconditionally, SQLAccess / MssqlLinkedServerLateral
      conditional on the collector's per-principal / per-edge BULK-ops fact).
    """
    merged: dict[str, list[dict[str, Any]]] = {}
    for builder in (
        _build_implicit_dumplsa_overlay,
        _build_implicit_dc_dcsync_overlay,
        _build_implicit_session_followup_overlay,
        _build_implicit_xpcmdshell_overlay,
        _build_implicit_openrowset_bulk_overlay,
    ):
        for node_id, edges in builder(graph).items():
            merged.setdefault(node_id, []).extend(edges)
    return merged



def _iter_outgoing_edges_with_virtual_local_reuse(
    current: str,
    *,
    adjacency: dict[str, list[dict[str, Any]]],
    acc_steps: list[AttackPathStep],
    local_reuse_by_node: dict[str, list[dict[str, Any]]],
    local_reuse_existing_pairs: set[tuple[str, str]],
    local_reuse_useful_nodes: set[str],
    implicit_edge_overlay: dict[str, list[dict[str, Any]]] | None = None,
) -> list[dict[str, Any]]:
    """Return real + virtual outgoing edges for traversal.

    Virtual edges are only emitted for compressed (`topology=star`) local reuse
    clusters, and only for missing direct pairs not already materialized.
    """
    next_edges: list[dict[str, Any]] = []
    for edge in list(adjacency.get(current) or []):
        if not isinstance(edge, dict):
            continue
        relation_key = str(edge.get("relation") or "").strip().lower()
        if relation_key == _LOCAL_REUSE_RELATION_KEY:
            dst = str(edge.get("to") or "").strip()
            if not dst or dst not in local_reuse_useful_nodes:
                continue
        next_edges.append(edge)
    clusters = local_reuse_by_node.get(current) or []
    if not clusters:
        # Virtual implicit DumpLSA self-loops — append even when there are no
        # local-reuse clusters so the early-return path does not skip them.
        for edge in (implicit_edge_overlay or {}).get(current, []):
            next_edges.append(edge)
        return next_edges

    last_step = acc_steps[-1] if acc_steps else None
    last_relation = str(last_step.relation or "").strip().lower() if last_step else ""
    last_cluster_id = (
        str((last_step.notes or {}).get("reuse_cluster_id") or "").strip()
        if last_step
        else ""
    )

    emitted_virtual_pairs: set[tuple[str, str]] = set()
    for cluster in clusters:
        cluster_id = str(cluster.get("cluster_id") or "").strip()
        # Avoid chaining the same local-reuse cluster repeatedly, which only
        # adds redundant permutations and increases path-search pressure.
        if (
            last_relation == _LOCAL_REUSE_RELATION_KEY
            and cluster_id
            and cluster_id == last_cluster_id
        ):
            continue
        for dst_id in cluster.get("node_ids") or []:
            dst = str(dst_id).strip()
            if not dst or dst == current:
                continue
            if dst not in local_reuse_useful_nodes:
                continue
            pair = (current, dst)
            if pair in local_reuse_existing_pairs or pair in emitted_virtual_pairs:
                continue
            emitted_virtual_pairs.add(pair)
            next_edges.append(
                {
                    "from": current,
                    "to": dst,
                    "relation": "LocalAdminPassReuse",
                    "status": "discovered",
                    "notes": {
                        "source": "local_reuse_virtual_expansion",
                        "virtual_expansion": True,
                        "reuse_cluster_id": cluster_id,
                        "local_admin_username": cluster.get("local_admin_username"),
                    },
                }
            )

    # Virtual implicit DumpLSA self-loops — append last so they have lowest
    # traversal priority. The DFS context guard will only allow them to chain
    # when the previous edge produced local_admin_session.
    for edge in (implicit_edge_overlay or {}).get(current, []):
        next_edges.append(edge)

    return next_edges


def _build_high_value_terminal_candidate_ids(
    nodes_map: dict[str, Any],
    edges: list[dict[str, Any]],
    *,
    mode: str,
) -> set[str]:
    """Return nodes whose paths can survive high-value filtering/promotion.

    This includes:
    - direct high-value / tier-0 targets, and
    - User/Computer nodes that can be promoted by one MemberOf hop to a
      privileged group, matching ``_try_promote_target_via_membership_edges``.
    """
    required_rank = 1 if mode == "impact" else 3
    direct_high_value_ids: set[str] = set()
    promotable_terminal_ids: set[str] = set()

    for node_id, node in nodes_map.items():
        if not isinstance(node, dict):
            continue
        is_high_value = (
            _node_is_impact_high_value(node)
            if mode == "impact"
            else _node_is_tier0(node)
        )
        if is_high_value:
            direct_high_value_ids.add(str(node_id))

    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if str(edge.get("relation") or "").strip().lower() != "memberof":
            continue
        from_id = str(edge.get("from") or "").strip()
        to_id = str(edge.get("to") or "").strip()
        if not from_id or not to_id:
            continue
        principal_node = nodes_map.get(from_id)
        group_node = nodes_map.get(to_id)
        if not isinstance(principal_node, dict) or not isinstance(group_node, dict):
            continue
        if str(principal_node.get("kind") or "") not in {"User", "Computer"}:
            continue
        if str(group_node.get("kind") or "") != "Group":
            continue
        if _node_high_value_rank(group_node) < required_rank:
            continue
        promotable_terminal_ids.add(from_id)

    return direct_high_value_ids | promotable_terminal_ids


def _build_reverse_reachable_node_ids(
    nodes_map: dict[str, Any],
    adjacency: dict[str, list[dict[str, Any]]],
    *,
    target_node_ids: set[str],
    local_reuse_by_node: dict[str, list[dict[str, Any]]],
    local_reuse_existing_pairs: set[tuple[str, str]],
    local_reuse_useful_nodes: set[str],
) -> set[str]:
    """Return nodes that can reach any target node via DFS-visible edges.

    Uses the same outgoing-edge expansion logic as DFS, including virtual local
    reuse edges. The expansion is computed with an empty path prefix, which
    slightly over-approximates actual DFS reachability but never undercuts it,
    making it safe for pruning.
    """
    if not target_node_ids:
        return set()

    reverse_adjacency: dict[str, set[str]] = {}
    for node_id, node in nodes_map.items():
        if not isinstance(node, dict):
            continue
        for edge in _iter_outgoing_edges_with_virtual_local_reuse(
            str(node_id),
            adjacency=adjacency,
            acc_steps=[],
            local_reuse_by_node=local_reuse_by_node,
            local_reuse_existing_pairs=local_reuse_existing_pairs,
            local_reuse_useful_nodes=local_reuse_useful_nodes,
        ):
            if not isinstance(edge, dict):
                continue
            to_id = str(edge.get("to") or "").strip()
            if not to_id:
                continue
            reverse_adjacency.setdefault(to_id, set()).add(str(node_id))

    reachable: set[str] = set(target_node_ids)
    pending = list(target_node_ids)
    while pending:
        current = pending.pop()
        for predecessor in reverse_adjacency.get(current, ()):
            if predecessor in reachable:
                continue
            reachable.add(predecessor)
            pending.append(predecessor)
    return reachable


def _build_high_value_reachable_node_ids(
    graph: dict[str, Any],
    *,
    mode: str,
) -> set[str]:
    """Return nodes that can reach a high-value or promotable terminal."""
    nodes_map = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes_map, dict) or not isinstance(edges, list):
        return set()

    adjacency: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        from_id = str(edge.get("from") or "").strip()
        to_id = str(edge.get("to") or "").strip()
        relation = str(edge.get("relation") or "").strip()
        if not from_id or not to_id or not relation:
            continue
        adjacency.setdefault(from_id, []).append(edge)

    local_reuse_by_node, local_reuse_existing_pairs = _build_local_reuse_virtual_state(
        nodes_map, edges
    )
    local_reuse_useful_nodes = _build_local_reuse_useful_node_ids(nodes_map, edges)
    target_node_ids = _build_high_value_terminal_candidate_ids(
        nodes_map,
        edges,
        mode=mode,
    )
    return _build_reverse_reachable_node_ids(
        nodes_map,
        adjacency,
        target_node_ids=target_node_ids,
        local_reuse_by_node=local_reuse_by_node,
        local_reuse_existing_pairs=local_reuse_existing_pairs,
        local_reuse_useful_nodes=local_reuse_useful_nodes,
    )


def _is_same_local_reuse_cluster_chain(
    previous_step: AttackPathStep | None,
    next_edge: dict[str, Any],
) -> bool:
    """Return True when two consecutive LocalAdminPassReuse hops use same cluster."""
    if previous_step is None:
        return False
    prev_relation = str(previous_step.relation or "").strip().lower()
    if prev_relation != _LOCAL_REUSE_RELATION_KEY:
        return False
    next_relation = str(next_edge.get("relation") or "").strip().lower()
    if next_relation != _LOCAL_REUSE_RELATION_KEY:
        return False
    prev_notes = previous_step.notes if isinstance(previous_step.notes, dict) else {}
    next_notes = next_edge.get("notes")
    next_notes = next_notes if isinstance(next_notes, dict) else {}
    prev_cluster = str(prev_notes.get("reuse_cluster_id") or "").strip()
    next_cluster = str(next_notes.get("reuse_cluster_id") or "").strip()
    if not prev_cluster or not next_cluster:
        return False
    return prev_cluster == next_cluster


# ---------------------------------------------------------------------------
# Parallel DFS infrastructure
#
# Activated by the ADSCAN_ATTACK_PATH_WORKERS env var:
#   0   → sequential (default, safe)
#   -1  → auto (cpu_count workers)
#   N>0 → use N worker processes (capped at cpu_count and source count)
#
# Uses spawn context for PyInstaller compatibility.  The graph data structures
# are sent to each worker process ONCE via the pool initializer (not per task),
# so only the per-batch source list is pickled on every task dispatch.
# ---------------------------------------------------------------------------


def _read_attack_path_workers() -> int:
    try:
        return int(os.getenv("ADSCAN_ATTACK_PATH_WORKERS", "0").strip())
    except (TypeError, ValueError):
        return 0


_ATTACK_PATH_WORKERS: int = _read_attack_path_workers()

# Per-worker state — populated once per worker process by _dfs_worker_init.
_W_ADJACENCY: dict[str, list[dict[str, Any]]] = {}
_W_LOCAL_REUSE_BY_NODE: dict[str, list[dict[str, Any]]] = {}
_W_LOCAL_REUSE_EXISTING_PAIRS: set[tuple[str, str]] = set()
_W_LOCAL_REUSE_USEFUL_NODES: set[str] = set()
_W_TERMINAL_SET: set[str] = set()
_W_IMPLICIT_EDGE_OVERLAY: dict[str, list[dict[str, Any]]] = {}
# Reverse-reachable set (nodes that can reach a high-value/Tier-0 sink). Empty
# when the caller did not request reachability pruning (i.e. every target except
# `highvalue`), in which case the expansion guard is a no-op and no node is
# skipped — see _dfs_sources_batch_worker.
_W_REACHABLE_NODE_IDS: set[str] = set()


def _dfs_worker_init(
    adjacency: dict[str, list[dict[str, Any]]],
    local_reuse_by_node: dict[str, list[dict[str, Any]]],
    local_reuse_existing_pairs: set[tuple[str, str]],
    local_reuse_useful_nodes: set[str],
    terminal_set: set[str],
    implicit_edge_overlay: dict[str, list[dict[str, Any]]],
    reachable_node_ids: set[str],
) -> None:
    """Populate per-worker globals. Called once per worker process by the pool initializer."""
    global _W_ADJACENCY, _W_LOCAL_REUSE_BY_NODE  # noqa: PLW0603
    global _W_LOCAL_REUSE_EXISTING_PAIRS, _W_LOCAL_REUSE_USEFUL_NODES, _W_TERMINAL_SET  # noqa: PLW0603
    global _W_IMPLICIT_EDGE_OVERLAY, _W_REACHABLE_NODE_IDS  # noqa: PLW0603
    _W_ADJACENCY = adjacency
    _W_LOCAL_REUSE_BY_NODE = local_reuse_by_node
    _W_LOCAL_REUSE_EXISTING_PAIRS = local_reuse_existing_pairs
    _W_LOCAL_REUSE_USEFUL_NODES = local_reuse_useful_nodes
    _W_TERMINAL_SET = terminal_set
    _W_IMPLICIT_EDGE_OVERLAY = implicit_edge_overlay
    _W_REACHABLE_NODE_IDS = reachable_node_ids


def _dfs_sources_batch_worker(
    sources_batch: list[str],
    target: str,
    max_depth: int,
    max_paths_cap: int | None,
) -> list[AttackPath]:
    """Run the DFS for a batch of source nodes using per-worker state.

    This is a module-level function so it is picklable for multiprocessing.
    The heavy data structures (adjacency, local-reuse indexes, terminal set)
    are already loaded into the worker process via the pool initializer;
    only the cheap per-task arguments are serialized on each dispatch.
    """
    terminal_set = _W_TERMINAL_SET
    reachable_node_ids = _W_REACHABLE_NODE_IDS
    # Rebuild the shared expansion view (concern 1) from the per-worker globals
    # the pool initializer populated. The worker path carries no gentime-collapse
    # state (it is not passed to workers), so those fields are empty — byte-
    # identical to the previous inline behaviour. Degree maps are unused here.
    view = AttackPathExpansionView(
        adjacency=_W_ADJACENCY,
        incoming={},
        outgoing={},
        local_reuse_by_node=_W_LOCAL_REUSE_BY_NODE,
        local_reuse_existing_pairs=_W_LOCAL_REUSE_EXISTING_PAIRS,
        local_reuse_useful_nodes=_W_LOCAL_REUSE_USEFUL_NODES,
        implicit_edge_overlay=_W_IMPLICIT_EDGE_OVERLAY,
        gentime_suppressed=set(),
        gentime_representatives={},
    )

    paths: list[AttackPath] = []
    seen_signatures: set[tuple[tuple[str, str, str, str], ...]] = set()
    # In-DFS runaway bound (shared with the sequential DFS entrypoints): converts a
    # mid-recursion OOM into the SAME declared coverage-bounded stop the outer gate
    # raises, instead of a kernel SIGKILL. Never fires on a graph that fits in RAM.
    _budget = DfsMemoryBudget()

    def emit(acc_steps: list[AttackPathStep]) -> None:
        if not acc_steps:
            return
        if max_paths_cap is not None and len(paths) >= max_paths_cap:
            return
        if target == "highvalue" and acc_steps[-1].to_id not in terminal_set:
            return
        if target == "lowpriv" and acc_steps[-1].to_id in terminal_set:
            return
        signature = tuple(attack_path_step_signature(s) for s in acc_steps)
        if signature in seen_signatures:
            return
        seen_signatures.add(signature)
        paths.append(
            AttackPath(
                steps=list(acc_steps),
                source_id=acc_steps[0].from_id,
                target_id=acc_steps[-1].to_id,
            )
        )

    def dfs(current: str, visited: set[str], acc_steps: list[AttackPathStep]) -> None:
        _budget.tick()
        if max_paths_cap is not None and len(paths) >= max_paths_cap:
            return
        actionable_depth = _count_actionable_edges(acc_steps)
        structural_depth = len(acc_steps) - actionable_depth
        if (
            actionable_depth >= max_depth
            or structural_depth >= _MAX_STRUCTURAL_HOPS
            or (acc_steps and current in terminal_set)
        ):
            emit(acc_steps)
            return
        next_edges = iter_view_frontier(view, current, acc_steps)
        if not next_edges:
            emit(acc_steps)
            return
        extended = False
        _path_rels = [str(s.relation or "").strip().lower() for s in acc_steps]
        for edge in next_edges:
            verdict, is_self_loop, step_notes = admit_frontier_edge(
                edge,
                current=current,
                acc_steps=acc_steps,
                path_rels=_path_rels,
                visited=visited,
                view=view,
                reachable_node_ids=reachable_node_ids,
                terminal_set=terminal_set,
                chokepoint_root_set=set(),
            )
            if verdict != "admit":
                continue
            to_id = str(edge.get("to") or "")
            step = AttackPathStep(
                from_id=current,
                relation=str(edge.get("relation") or ""),
                to_id=to_id,
                status=str(edge.get("status") or "discovered"),
                notes=step_notes,
            )
            if not is_self_loop:
                visited.add(to_id)
            acc_steps.append(step)
            dfs(to_id, visited, acc_steps)
            acc_steps.pop()
            if not is_self_loop:
                visited.remove(to_id)
            extended = True
        if not extended:
            emit(acc_steps)

    for source in sources_batch:
        if max_paths_cap is not None and len(paths) >= max_paths_cap:
            break
        dfs(source, visited={source}, acc_steps=[])

    return paths


def _effective_domain_dfs_workers(n_sources: int) -> int:
    """Return the effective worker count for a domain DFS of *n_sources* sources.

    Returns 0 when parallelism is disabled or the source set is too small to
    amortise the spawn overhead (fewer than 2 sources per worker).
    """
    if _ATTACK_PATH_WORKERS == 0 or n_sources < 2:
        return 0
    cpu = os.cpu_count() or 1
    if _ATTACK_PATH_WORKERS < 0:
        candidates = min(cpu, n_sources)
    else:
        candidates = min(_ATTACK_PATH_WORKERS, cpu, n_sources)
    # Require at least 2 sources per worker to make parallelism worthwhile.
    while candidates > 1 and n_sources // candidates < 2:
        candidates -= 1
    return candidates if candidates >= 2 else 0


def _run_parallel_domain_dfs(
    sources: list[str],
    adjacency: dict[str, list[dict[str, Any]]],
    local_reuse_by_node: dict[str, list[dict[str, Any]]],
    local_reuse_existing_pairs: set[tuple[str, str]],
    local_reuse_useful_nodes: set[str],
    terminal_set: set[str],
    target: str,
    max_depth: int,
    max_paths_cap: int | None,
    n_workers: int,
    implicit_edge_overlay: dict[str, list[dict[str, Any]]] | None = None,
    reachable_node_ids: set[str] | None = None,
) -> list[AttackPath]:
    """Distribute the DFS over *n_workers* spawn-context processes.

    Graph data is sent to each worker once via the pool initializer.
    Each task only carries a small source-batch list.
    Results are merged and globally deduplicated in the main process.
    Falls back to sequential on any error.

    *reachable_node_ids* is the reverse-reachable set (nodes that can reach a
    high-value/Tier-0 sink). When non-empty, each worker honours it as an
    expansion guard, mirroring the sequential DFS. Empty/None disables the
    guard (target=all/lowpriv), so no node is pruned.
    """
    import concurrent.futures
    import multiprocessing

    # Distribute sources across workers (round-robin keeps ordering predictable).
    batches: list[list[str]] = [[] for _ in range(n_workers)]
    for i, src in enumerate(sources):
        batches[i % n_workers].append(src)
    batches = [b for b in batches if b]

    ctx = multiprocessing.get_context("spawn")
    all_paths: list[AttackPath] = []
    seen_sigs: set[tuple[tuple[str, str, str], ...]] = set()

    try:
        with concurrent.futures.ProcessPoolExecutor(
            max_workers=n_workers,
            mp_context=ctx,
            initializer=_dfs_worker_init,
            initargs=(
                adjacency,
                local_reuse_by_node,
                local_reuse_existing_pairs,
                local_reuse_useful_nodes,
                terminal_set,
                implicit_edge_overlay or {},
                reachable_node_ids or set(),
            ),
        ) as pool:
            futures = [
                pool.submit(
                    _dfs_sources_batch_worker, batch, target, max_depth, max_paths_cap
                )
                for batch in batches
            ]
            for future in concurrent.futures.as_completed(futures):
                for path in future.result():
                    sig = tuple((s.from_id, s.relation, s.to_id) for s in path.steps)
                    if sig not in seen_sigs:
                        seen_sigs.add(sig)
                        all_paths.append(path)
                        if (
                            max_paths_cap is not None
                            and len(all_paths) >= max_paths_cap
                        ):
                            # Cancel remaining futures (best-effort).
                            for f in futures:
                                f.cancel()
                            return all_paths
    except _AttackPathMemoryBudgetExceeded:
        # A worker hit the in-DFS runaway bound. This is a DELIBERATE clean stop,
        # not a worker crash — re-raise so it reaches the declared coverage-bounded
        # handler at the public entry point instead of being swallowed into a
        # silent full sequential re-run (which would only OOM the same way).
        raise
    except Exception:  # noqa: BLE001
        # Any failure (spawn unavailable, worker crash, etc.) → fall back to
        # sequential; the caller will redo the DFS serially.
        return []

    return all_paths


# ---------------------------------------------------------------------------
# Path-depth budget — count only actionable edges
# ---------------------------------------------------------------------------
# Operators specify ``--max-depth N`` expecting "N attack steps". The DFS used
# to count every edge including structural ones (MemberOf, Contains, GpLink,
# TrustedBy, HasSIDHistory), forcing operators to mentally pad the value by
# the depth of the AD group hierarchy. That made depth=4 work for one lab and
# fail for another despite both having 2 actionable steps.
#
# Structural relations only express AD topology — they grant no privilege,
# they're not executable attack steps. The displayed ``Len`` column already
# excludes them. The DFS budget should align with operator intuition: depth=4
# means up to 4 actionable transitions, structural edges flow freely.
#
# The set below MUST align with ``EdgeKind.MEMBERSHIP`` ∪ ``EdgeKind.TRUST``
# in :mod:`adscan_internal.services.edge_kind`. Sync when adding new edges.
_STRUCTURAL_RELATIONS_LOWER: frozenset[str] = frozenset(
    {
        "memberof",
        "contains",
        "gplink",
        "trustedby",
        "hassidhistory",
    }
)

# Defensive cap on structural-edge depth. AD group hierarchies are 3–7 levels
# deep in normal environments, ≤15 in the most pathological. Anything beyond
# that is either a cycle (already pruned by the visited set) or a graph
# anomaly. Cap protects against runaway expansion without affecting any real
# kill chain.
_MAX_STRUCTURAL_HOPS: int = 12


def _count_actionable_edges(acc_steps: list[AttackPathStep]) -> int:
    """Return the number of attack-step edges in the accumulated path.

    Excludes structural relations (``MemberOf``, ``Contains``, ``GpLink``,
    ``TrustedBy``, ``HasSIDHistory``) — those don't grant privilege and
    should not consume the depth budget specified by the operator.
    """
    return sum(
        1
        for step in acc_steps
        if str(step.relation or "").strip().lower() not in _STRUCTURAL_RELATIONS_LOWER
    )


# ---------------------------------------------------------------------------
# Direct-compromise group priority — collapse redundant membership expansion
# ---------------------------------------------------------------------------
# When a principal is member of >1 ``direct_compromise`` groups (the
# domain-takeover sinks: Domain Admins, Enterprise Admins, BUILTIN
# Administrators, etc.), the DFS expands ``MemberOf`` through every one,
# producing one near-identical path per group. The kill chain is the same
# story: ``... → Administrator → MemberOf → <DA|EA|Administrators> → ...``.
# Only the group label changes.
#
# Rule: when a principal has multiple ``MemberOf`` outgoing edges to
# direct-compromise groups, follow ONLY the highest-priority group. The
# membership info for other groups stays in the persisted graph (and in
# memberships.json) for choke-point analysis, reporting, and BloodHound
# parity — the suppression is purely path-traversal-time.
#
# Priority order (lower rank = higher priority, picked first):
#   1. Domain Admins (RID 512) — canonical "I'm DA" phrasing in every report
#   2. Enterprise Admins (RID 519) — forest-wide takeover
#   3. BUILTIN Administrators (RID 544 / S-1-5-32-544) — equivalent at scale
#   4. Schema Admins (RID 518)
#   5. Domain Controllers (RID 516)
#   6. Enterprise Read-Only Domain Controllers (RID 498)
#   7. Read-Only Domain Controllers (RID 521)
_DIRECT_COMPROMISE_GROUP_PRIORITY: dict[int, int] = {
    512: 0,
    519: 1,
    544: 2,
    518: 3,
    516: 4,
    498: 5,
    521: 6,
}


def _direct_compromise_group_priority_rank(node: dict[str, Any]) -> int | None:
    """Return priority rank for direct-compromise group nodes, else None."""
    if str(node.get("kind") or "") != "Group":
        return None
    _, rid = _extract_node_sid_and_rid(node)
    if rid is None:
        return None
    return _DIRECT_COMPROMISE_GROUP_PRIORITY.get(rid)


def _build_priority_memberof_suppression(
    edges: list[dict[str, Any]],
    nodes_map: dict[str, Any],
) -> set[tuple[str, str]]:
    """Return ``{(from_id, to_id)}`` MemberOf edges to suppress in the DFS.

    For each principal with MemberOf edges into >1 direct-compromise groups,
    keeps only the edge to the highest-priority one. All other actionable
    edges are untouched — only redundant ``MemberOf`` expansion is collapsed.
    """
    if not isinstance(edges, list) or not isinstance(nodes_map, dict):
        return set()

    source_to_candidates: dict[str, list[tuple[int, str]]] = {}
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if str(edge.get("relation") or "").strip().lower() != "memberof":
            continue
        from_id = str(edge.get("from") or "")
        to_id = str(edge.get("to") or "")
        if not from_id or not to_id:
            continue
        target_node = nodes_map.get(to_id)
        if not isinstance(target_node, dict):
            continue
        rank = _direct_compromise_group_priority_rank(target_node)
        if rank is None:
            continue
        source_to_candidates.setdefault(from_id, []).append((rank, to_id))

    suppressed: set[tuple[str, str]] = set()
    for from_id, candidates in source_to_candidates.items():
        if len(candidates) <= 1:
            continue
        candidates.sort(key=lambda pair: (pair[0], pair[1]))
        for _, to_id in candidates[1:]:
            suppressed.add((from_id, to_id))
    return suppressed


# ---------------------------------------------------------------------------
# Generation-time interchangeable-pivot collapse (PROTOTYPE)
# ---------------------------------------------------------------------------
# ADscan's DFS enumerates then RETAINS every maximal simple path; on a mass-ACL
# / mass-membership fan-out over INTERCHANGEABLE pivots (e.g. Account Operators
# --GenericAll--> {4000 accounts} --AdminTo--> {sinks}) the raw path count and
# peak RAM explode combinatorially. The existing post-materialization merge
# ``collapse_sibling_pivot_paths`` (attack_paths_core) already flattens exactly
# these sibling paths — but only AFTER the DFS built every branch and memory
# peaked, and AFTER the O(N^2) minimisation walked them all.
#
# This moves that PROVEN-SAFE merge earlier: a pre-DFS pass detects each set of
# interchangeable pivots reachable from one source, and the DFS walks ONLY the
# representative pivot's subtree. Because the siblings are structurally
# identical (same incoming relation, same node kind, byte-identical outgoing
# signature, none Tier-0/high-value), the representative's subtree is exactly
# what every sibling would have produced — so no downstream path shape is lost.
#
# The collapse is coverage-preserving by CONSTRUCTION, not by re-implementing
# the display merge: the suppressed siblings are re-expanded (shallow, one row
# per representative record, not per subtree) right before the untouched
# ``collapse_sibling_pivot_paths`` runs, so that proven function produces the
# byte-identical ``via_accounts``/``via_accounts_count`` metadata it always has.
# The DFS + minimisation — where the K x subtree blow-up and the O(N^2) cost
# live — operate on the collapsed set. The suppression MIRRORS the established
# ``_build_priority_memberof_suppression`` pattern: pre-compute a set, honour it
# at the traversal seam.
#
# Toggle: ADSCAN_ATTACK_PATH_GENTIME_COLLAPSE=1 enables it (default OFF while it
# is a prototype under review). The debug script's --gentime-collapse flag sets
# this env var.

#: Note key stamped on a representative pivot's INCOMING step so the shallow
#: re-expansion can recover the suppressed sibling node ids.
_GENTIME_COLLAPSE_MEMBERS_KEY = "gentime_collapsed_pivot_members"


def _read_gentime_collapse_enabled() -> bool:
    return str(os.getenv("ADSCAN_ATTACK_PATH_GENTIME_COLLAPSE", "0")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _node_outgoing_signature(
    node_id: str,
    adjacency: dict[str, list[dict[str, Any]]],
) -> tuple[tuple[str, str], ...]:
    """Return a node's canonical outgoing signature: sorted ``(relation, to_id)``.

    Two pivots with the SAME signature have byte-identical downstream reach — the
    DFS subtree they generate is identical (same edges to the same nodes) — so
    keeping one representative loses no path. A self-loop (``to_id == node_id``)
    is normalised out: it is a per-node capability, identical for every sibling.
    """
    sig: list[tuple[str, str]] = []
    for edge in adjacency.get(node_id) or []:
        if not isinstance(edge, dict):
            continue
        rel = str(edge.get("relation") or "").strip().lower()
        to_id = str(edge.get("to") or "").strip()
        if not rel or not to_id:
            continue
        if to_id == node_id:
            # Self-loop capability — identical across siblings, drop from the key.
            continue
        sig.append((rel, to_id))
    sig.sort()
    return tuple(sig)


def _read_gentime_collapse_interior() -> bool:
    """Whether to ALSO collapse interior (non-dead-end) interchangeable pivots.

    Default ON. The SINGLE-PARENT guard (a pivot collapsed only when it is reached
    from exactly the grouping source) is what makes the collapse byte-safe: it
    removes the DFS ``visited``-set interaction that would otherwise let two
    same-outgoing pivots reach different terminals under different prefixes. Under
    that guard, an interior single-parent pivot's subtree is identical across
    siblings and self-contained, so collapsing it is byte-identical (validated on
    Forest / Blackfield / the synthetic AO fan-out). Set the env var to ``0`` to
    restrict to dead-end leaves only (measurement / extra caution).
    """
    return str(
        os.getenv("ADSCAN_ATTACK_PATH_GENTIME_COLLAPSE_INTERIOR", "1")
    ).strip().lower() in {"1", "true", "yes", "on"}


def _build_interchangeable_pivot_suppression(
    adjacency: dict[str, list[dict[str, Any]]],
    nodes_map: dict[str, Any],
    *,
    floor: int = 2,
    interior: bool | None = None,
) -> tuple[set[tuple[str, str]], dict[tuple[str, str], list[str]]]:
    """Return the interchangeable-pivot suppression set + representative map.

    For every source ``S`` and incoming relation ``rel``, group ``S``'s outgoing
    targets that are structurally interchangeable pivots and pick ONE
    representative per group. The other edges are suppressed at the DFS seam.

    Interchangeability test (all must hold; a leaf failing ANY is excluded):

    * **Same source and same incoming relation** — grouped by ``(S, rel)``.
    * **Same node kind** — a User pivot and a Computer pivot are not
      interchangeable even with the same downstream.
    * **Byte-identical outgoing signature** — the sorted ``(relation, to_id)``
      multiset (:func:`_node_outgoing_signature`) is identical.
    * **Dead-end by default** — only pivots with an EMPTY outgoing signature are
      collapsed unless ``interior`` is set. A dead-end leaf has no subtree, so
      the collapse is context-free and provably byte-identical. An interior
      pivot's subtree depends on the DFS ``visited`` set (a cyclic group mesh can
      route two same-outgoing pivots to different terminals), so collapsing it is
      NOT guaranteed lossless — gated behind ``interior`` for measurement only.
    * **Not Tier-0 / high-value** — a pivot that is itself a domain-takeover
      target is an independent finding and is NEVER collapsed.
    * **Group size >= floor** (default 2).

    Returns:
        ``(suppressed, representatives)`` where ``suppressed`` is a set of
        ``(from_id, to_id)`` edges to skip in the DFS, and ``representatives``
        maps ``(from_id, rep_to_id) -> [all_member_ids...]`` (representative
        first) so the shallow re-expansion can rebuild the sibling rows.
    """
    if not isinstance(nodes_map, dict) or not adjacency:
        return set(), {}
    allow_interior = _read_gentime_collapse_interior() if interior is None else interior

    # In-degree over the TRAVERSABLE adjacency. A pivot reached from more than one
    # parent can be visited via a DIFFERENT in-path, and the DFS ``visited`` set
    # then makes its presence context-dependent — collapsing it is NOT byte-safe
    # (a shared WELLKNOWN sink such as ``Authenticated Users`` reached from dozens
    # of sources). Only SINGLE-PARENT pivots (reached exclusively from the grouping
    # source) are collapsed, so the representative is reached exactly as often as
    # the full sibling set would be.
    in_parents: dict[str, set[str]] = {}
    for src, edges in adjacency.items():
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            to_id = str(edge.get("to") or "").strip()
            if to_id and to_id != src:
                in_parents.setdefault(to_id, set()).add(src)

    suppressed: set[tuple[str, str]] = set()
    representatives: dict[tuple[str, str], list[str]] = {}

    for src, edges in adjacency.items():
        if not isinstance(edges, list) or len(edges) < floor:
            continue
        # (relation, kind, outgoing_signature) -> [to_id...] preserving edge order.
        groups: dict[tuple[str, str, tuple[tuple[str, str], ...]], list[str]] = {}
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            to_id = str(edge.get("to") or "").strip()
            if not to_id or to_id == src:
                continue
            rel = str(edge.get("relation") or "").strip().lower()
            if not rel:
                continue
            node = nodes_map.get(to_id)
            if not isinstance(node, dict):
                continue
            # Never collapse a pivot that is itself a takeover target — it is an
            # independent, high-value finding.
            if _node_is_effectively_high_value(node):
                continue
            # SINGLE-PARENT ONLY: a pivot reachable from >1 parent is unsafe (the
            # visited-set makes it context-dependent). Its own parent set is
            # exactly {src} here.
            parents = in_parents.get(to_id)
            if parents is not None and len(parents) > 1:
                continue
            out_sig = _node_outgoing_signature(to_id, adjacency)
            # DEAD-END-ONLY by default: an interior pivot (non-empty out_sig) is
            # only collapsed when interior mode is explicitly enabled.
            if out_sig and not allow_interior:
                continue
            kind = str(node.get("kind") or "").strip().lower()
            key = (rel, kind, out_sig)
            groups.setdefault(key, []).append(to_id)

        for members in groups.values():
            # Dedupe while preserving order (an edge could be listed twice).
            seen: set[str] = set()
            ordered: list[str] = []
            for mid in members:
                if mid in seen:
                    continue
                seen.add(mid)
                ordered.append(mid)
            if len(ordered) < floor:
                continue
            # Deterministic representative: lowest node id (stable across runs).
            ordered.sort()
            rep = ordered[0]
            representatives[(src, rep)] = ordered
            for mid in ordered[1:]:
                suppressed.add((src, mid))

    return suppressed, representatives


# ===========================================================================
# Attack-path engine — the shared rule layer (architecture C, Phase 1)
# ===========================================================================
# The DFS in this module entangled three concerns that a pluggable enumeration
# engine (Python DFS today, rustworkx later) must be able to share WITHOUT
# re-implementing. The July rustworkx engine drifted precisely because it
# hand-copied these rules and missed several of them (see the audit at
# ``docs/superpowers/specs/2026-08-23-attack-path-engine-rustworkx-gentime-collapse/03-rustworkx-engine-audit.md``).
# Phase 1 formalises the separation seam so ANY enumerator consumes ONE rule
# layer. The three concerns:
#
#   1. GRAPH-SHAPE guards (this section, ``AttackPathExpansionView`` /
#      ``build_expansion_view``) — they INVENT edges/roots that do not exist in
#      ``graph["edges"]`` (virtual local-reuse edges, the five implicit overlays,
#      the memberof-priority suppression, the gen-time interchangeable-pivot
#      collapse). Any enumerator that only reads base out-edges is structurally
#      blind to them, so they are PRE-MATERIALISED into an expansion view before
#      enumeration — never applied as a post-filter over "raw paths" (that is the
#      exact bug the audit found; a post-filter silently drops the injected-edge
#      families).
#   2. PREFIX-PREDICATE guards (``admit_frontier_edge``) — pure functions of the
#      accumulated path prefix (credential-context ``_edges_chain_ok``, the
#      same-cluster local-reuse chain, self-loop one-time gating, the
#      gen-time-suppressed sibling skip, the visited/self-loop rule, the
#      reverse-reachability gate). The enumeration loop CALLS them per frontier;
#      a different engine calls the IDENTICAL callback.
#   3. ENUMERATION — the thin "all maximal simple paths under the callbacks over
#      the expansion view" loop. The Python DFS below is the FIRST consumer.
#
# This is a pure refactor: the behaviour (and therefore the finding set) is
# byte-identical, frozen by
# ``tests/unit/services/test_attack_path_engine_snapshot.py``.


@dataclass
class AttackPathExpansionView:
    """Pre-materialised graph-shape layer that any enumerator walks (concern 1).

    Built once by :func:`build_expansion_view` from a base attack graph, this
    value object carries the traversable adjacency plus every SYNTHETIC piece
    the DFS injects that is not a plain out-edge of ``graph["edges"]``:

    * ``adjacency`` — real edges with non-traversable edges removed and the
      memberof-priority suppression applied.
    * ``incoming`` / ``outgoing`` — per-node edge degrees (source selection, the
      choke-point rooting gates) — populated only for the domain builder.
    * ``local_reuse_by_node`` / ``local_reuse_existing_pairs`` /
      ``local_reuse_useful_nodes`` — the star-topology local-reuse virtual-edge
      state consumed by :func:`_iter_outgoing_edges_with_virtual_local_reuse`.
    * ``implicit_edge_overlay`` — the five implicit overlay families (DumpLSA +
      DC-DCSync/session-followup/xpcmdshell/openrowset self-loops).
    * ``gentime_suppressed`` / ``gentime_representatives`` — the generation-time
      interchangeable-pivot collapse suppression set + representative map.

    The synthetic local-reuse + overlay edges are surfaced per-visit through
    :func:`iter_view_frontier` (a thin wrapper over the existing
    ``_iter_outgoing_edges_with_virtual_local_reuse``), so an enumerator never
    reaches into these fields directly — it asks the view for the frontier.
    """

    adjacency: dict[str, list[dict[str, Any]]]
    incoming: dict[str, int]
    outgoing: dict[str, int]
    local_reuse_by_node: dict[str, list[dict[str, Any]]]
    local_reuse_existing_pairs: set[tuple[str, str]]
    local_reuse_useful_nodes: set[str]
    implicit_edge_overlay: dict[str, list[dict[str, Any]]]
    gentime_suppressed: set[tuple[str, str]]
    gentime_representatives: dict[tuple[str, str], list[str]]


def build_expansion_view(
    graph: dict[str, Any],
    *,
    nodes_map: dict[str, Any],
    edges: list[dict[str, Any]],
    track_degrees: bool,
    gentime_collapse_on: bool,
) -> AttackPathExpansionView:
    """Pre-materialise the graph-shape layer both engines consume (concern 1).

    Constructs the traversable adjacency (non-traversable edges removed,
    memberof-priority suppression applied) plus every synthetic-edge index the
    DFS injects. This is the SSOT for concern (1) of the separation seam — the
    exact construction the three DFS entry points previously inlined
    identically, so extracting it here is byte-identical by construction.

    Args:
        graph: The base attack graph (used for the implicit-overlay builder,
            which reads nodes + edges from it).
        nodes_map: ``graph["nodes"]`` (already validated as a dict by the caller).
        edges: ``graph["edges"]`` (already validated as a list by the caller).
        track_degrees: When ``True`` also compute the per-node ``incoming`` /
            ``outgoing`` degree maps (the domain builder needs them for source
            selection + choke-point rooting; the per-start builder does not).
        gentime_collapse_on: When ``True`` compute the interchangeable-pivot
            collapse suppression set + representative map (OFF by default).

    Returns:
        A populated :class:`AttackPathExpansionView`.
    """
    suppressed_memberof = _build_priority_memberof_suppression(edges, nodes_map)

    adjacency: dict[str, list[dict[str, Any]]] = {}
    incoming: dict[str, int] = {}
    outgoing: dict[str, int] = {}
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if _is_nontraversable_attack_edge(edge, nodes_map):
            continue
        from_id = str(edge.get("from") or "")
        to_id = str(edge.get("to") or "")
        rel = str(edge.get("relation") or "")
        if not from_id or not to_id or not rel:
            continue
        if rel.lower() == "memberof" and (from_id, to_id) in suppressed_memberof:
            continue
        adjacency.setdefault(from_id, []).append(edge)
        if track_degrees:
            outgoing[from_id] = outgoing.get(from_id, 0) + 1
            # MemberOf edges (persisted or runtime) should not change which nodes
            # are considered "sources" in domain-wide path listing.
            if rel != "MemberOf":
                incoming[to_id] = incoming.get(to_id, 0) + 1
            incoming.setdefault(from_id, incoming.get(from_id, 0))
            outgoing.setdefault(to_id, outgoing.get(to_id, 0))

    local_reuse_by_node, local_reuse_existing_pairs = _build_local_reuse_virtual_state(
        nodes_map, edges
    )
    local_reuse_useful_nodes = _build_local_reuse_useful_node_ids(nodes_map, edges)
    implicit_edge_overlay = _build_implicit_path_overlays(graph)

    gentime_suppressed: set[tuple[str, str]] = set()
    gentime_representatives: dict[tuple[str, str], list[str]] = {}
    if gentime_collapse_on:
        gentime_suppressed, gentime_representatives = (
            _build_interchangeable_pivot_suppression(adjacency, nodes_map)
        )

    return AttackPathExpansionView(
        adjacency=adjacency,
        incoming=incoming,
        outgoing=outgoing,
        local_reuse_by_node=local_reuse_by_node,
        local_reuse_existing_pairs=local_reuse_existing_pairs,
        local_reuse_useful_nodes=local_reuse_useful_nodes,
        implicit_edge_overlay=implicit_edge_overlay,
        gentime_suppressed=gentime_suppressed,
        gentime_representatives=gentime_representatives,
    )


def iter_view_frontier(
    view: AttackPathExpansionView,
    current: str,
    acc_steps: list[AttackPathStep],
) -> list[dict[str, Any]]:
    """Return the outgoing frontier (real + synthetic edges) for ``current``.

    Thin wrapper over :func:`_iter_outgoing_edges_with_virtual_local_reuse` so
    an enumerator asks the expansion view for the frontier instead of reaching
    into its synthetic-edge fields. Byte-identical to the previous inline call.
    """
    return _iter_outgoing_edges_with_virtual_local_reuse(
        current,
        adjacency=view.adjacency,
        acc_steps=acc_steps,
        local_reuse_by_node=view.local_reuse_by_node,
        local_reuse_existing_pairs=view.local_reuse_existing_pairs,
        local_reuse_useful_nodes=view.local_reuse_useful_nodes,
        implicit_edge_overlay=view.implicit_edge_overlay,
    )


def admit_frontier_edge(
    edge: dict[str, Any],
    *,
    current: str,
    acc_steps: list[AttackPathStep],
    path_rels: list[str],
    visited: set[str],
    view: AttackPathExpansionView,
    reachable_node_ids: set[str],
    terminal_set: set[str] | None,
    chokepoint_root_set: set[str],
) -> tuple[str, bool, dict[str, Any]]:
    """Apply the shared per-frontier prefix predicates to one candidate edge (concern 2).

    Pure function of the accumulated prefix + the expansion view. Both the
    Python DFS and any future engine call this IDENTICAL callback per frontier,
    so the prune rules cannot diverge between engines (the root cause of the
    rotted July rustworkx impl). It runs the exact in-loop admission sequence
    the three DFS bodies shared, in order:

    1. same-cluster local-reuse chain suppression (``_is_same_local_reuse_cluster_chain``);
    2. credential-context edge-chain guard (``_edges_chain_ok`` WITH the
       candidate edge — the arity the July engine got wrong);
    3. empty ``to_id`` skip;
    4. leading (depth-0) MemberOf-into-choke-point suppression (Layer 3);
    5. gen-time interchangeable-pivot sibling suppression;
    6. self-loop vs visited rule + self-loop one-time gating;
    7. reverse-reachability expansion gate.

    Args:
        reachable_node_ids: The reverse-reachable set; empty disables the gate.
        terminal_set: When provided (the worker path, which pre-computes the
            terminal set), the reachability gate also admits a node that IS a
            terminal sink — mirrors the worker's ``... or to_id in terminal_set``.
            When ``None`` (the sequential paths), the gate is the plain
            ``to_id in reachable_node_ids`` form.
        chokepoint_root_set: The rooted choke-point group ids; empty disables the
            leading-hop suppression (only the domain sequential path uses it).

    Returns:
        ``(verdict, is_self_loop, step_notes)`` where ``verdict`` is one of
        ``"skip"`` (reject this edge) or ``"admit"`` (append + recurse). The
        caller owns the recursion, visited mutation, and emit — only the
        admission predicates live here.
    """
    empty_notes: dict[str, Any] = {}

    last_step = acc_steps[-1] if acc_steps else None
    if _is_same_local_reuse_cluster_chain(last_step, edge):
        return "skip", False, empty_notes

    cand_rel = str(edge.get("relation") or "").strip().lower()
    if not _edges_chain_ok(path_rels, cand_rel, candidate_edge=edge):
        return "skip", False, empty_notes

    to_id = str(edge.get("to") or "")
    if not to_id:
        return "skip", False, empty_notes

    # Layer 3: suppress the redundant LEADING (depth-0) MemberOf hop from a real
    # source into a rooted choke point (walked once from the choke-point root).
    if (
        not acc_steps
        and chokepoint_root_set
        and cand_rel == "memberof"
        and to_id in chokepoint_root_set
        and current not in chokepoint_root_set
    ):
        return "skip", False, empty_notes

    # Gen-time collapse: skip a suppressed interchangeable-pivot sibling edge —
    # only the representative pivot's subtree is walked.
    if view.gentime_suppressed and (current, to_id) in view.gentime_suppressed:
        return "skip", False, empty_notes

    # Self-loop edges (to_id == current) are context-upgrading derived steps
    # (e.g. DumpLSASS on the same node). They don't advance the DFS to a new
    # node, so the visited-set check does not apply.
    is_self_loop = to_id == current
    if not is_self_loop and to_id in visited:
        return "skip", False, empty_notes
    # A self-loop technique is a one-time capability gain on this host; do not
    # re-traverse the same self-loop relation.
    if is_self_loop and _self_loop_relation_already_used(acc_steps, current, cand_rel):
        return "skip", is_self_loop, empty_notes

    # Reverse-reachability expansion gate. Empty reachable set is a no-op
    # (target=all/lowpriv), so no coverage loss. The worker path (terminal_set
    # provided) also admits a node that is itself a terminal sink.
    if reachable_node_ids and to_id not in reachable_node_ids:
        if terminal_set is None or to_id not in terminal_set:
            return "skip", is_self_loop, empty_notes

    step_notes = edge.get("notes") if isinstance(edge.get("notes"), dict) else {}
    # Stamp the representative pivot's INCOMING step with its suppressed sibling
    # ids so the shallow re-expansion can rebuild the K sibling rows.
    if view.gentime_representatives:
        members = view.gentime_representatives.get((current, to_id))
        if members and len(members) > 1:
            step_notes = dict(step_notes)
            step_notes[_GENTIME_COLLAPSE_MEMBERS_KEY] = list(members)

    return "admit", is_self_loop, step_notes


def compute_maximal_attack_paths(
    graph: dict[str, Any],
    *,
    max_depth: int,
    max_paths: int | None = None,
    target: str = "highvalue",
    terminal_mode: str = "domain",
    start_node_ids: set[str] | None = None,
    reachable_node_ids: set[str] | None = None,
    chokepoint_group_ids: set[str] | None = None,
) -> list[AttackPath]:
    """Compute maximal paths up to depth for a full-domain graph.

    Layer 3 — choke-point-rooted DFS (``chokepoint_group_ids``): the node-ids of
    ``>1``-member ``MemberOf`` target groups (the collapse choke points, computed
    by the caller from the membership snapshot).  When supplied, each such group
    that has a source direct-member is added as an extra DFS root and walked
    ONCE, while the redundant leading ``member -> MemberOf -> G`` hop is
    suppressed per source.  This turns the ``O(members x subtree)`` Cartesian
    re-walk into ``O(members + subtree)`` without changing the final emitted +
    collapsed path set (``collapse_memberof_prefixes`` still runs and would have
    stripped exactly these prefixes).  Two guards keep byte-identity when a
    subtree loops back to a choke-point member: an emit-span guard drops an
    over-long path whose span already holds EVERY member (no member outside it
    could have generated it), and a truncation emit re-adds the shorter
    member-blocked maximal path a per-source walk would have produced.
    """
    if max_depth <= 0:
        return []
    max_paths_cap = (
        None
        if max_paths is None
        else max(1, int(max_paths))
        if int(max_paths) > 0
        else None
    )

    nodes_map = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes_map, dict) or not isinstance(edges, list):
        return []

    # Concern 1 — pre-materialise the graph-shape layer (adjacency + degrees +
    # local-reuse + implicit overlays + the gen-time collapse). OFF-by-default
    # gentime collapse walks only ONE representative pivot per interchangeable
    # set and stamps its incoming step so the post-materialization
    # ``collapse_sibling_pivot_paths`` merge rebuilds the byte-identical rows.
    gentime_collapse_on = _read_gentime_collapse_enabled()
    view = build_expansion_view(
        graph,
        nodes_map=nodes_map,
        edges=edges,
        track_degrees=True,
        gentime_collapse_on=gentime_collapse_on,
    )
    adjacency = view.adjacency
    outgoing = view.outgoing

    mode = normalize_target_mode(terminal_mode)

    def is_terminal(node_id: str) -> bool:
        node = nodes_map.get(node_id)
        if not isinstance(node, dict):
            return False
        if mode in {"object"}:
            return _node_is_domain(node)
        if mode == "impact":
            return _node_is_terminal_target(node, mode=mode)
        return _node_is_terminal_target(node, mode=mode)

    allowed_start_ids: set[str] = (
        {str(node_id) for node_id in start_node_ids if str(node_id).strip()}
        if start_node_ids
        else set()
    )
    allowed_reachable_ids: set[str] = (
        {str(node_id) for node_id in reachable_node_ids if str(node_id).strip()}
        if reachable_node_ids
        else set()
    )
    sources: list[str] = []
    for node_id, node in nodes_map.items():
        if not isinstance(node, dict):
            continue
        if allowed_start_ids and node_id not in allowed_start_ids:
            continue
        if allowed_reachable_ids and node_id not in allowed_reachable_ids:
            continue
        if outgoing.get(node_id, 0) <= 0:
            continue
        if not _node_is_enabled_user(node):
            continue
        if _node_is_effectively_high_value(node):
            continue
        sources.append(node_id)

    # --- Layer 3: choke-point-rooted DFS setup -------------------------------
    # Identify the collapse choke points (>1-member groups) that at least one
    # source is a direct member of.  Those groups become extra DFS roots walked
    # ONCE; the redundant leading ``source -> MemberOf -> G`` hop is suppressed
    # (``collapse_memberof_prefixes`` would strip it anyway).  Membership is read
    # from the SAME post-suppression adjacency the DFS walks, so the suppression
    # set and the guard member-set stay exactly consistent with what collapses.
    chokepoint_ids = chokepoint_group_ids or set()
    chokepoint_root_members: dict[str, set[str]] = {}
    if chokepoint_ids:
        for src in sources:
            for edge in adjacency.get(src, ()):
                if str(edge.get("relation") or "") != "MemberOf":
                    continue
                gid = str(edge.get("to") or "")
                if gid and gid in chokepoint_ids:
                    chokepoint_root_members.setdefault(gid, set()).add(src)
    # Only groups that pass the same start/reachable/outgoing gates as sources
    # are actually rooted; suppression is tied strictly to this rooted set so a
    # suppressed leading hop always has a root that regenerates its subtree.
    chokepoint_roots: list[str] = []
    for gid in sorted(chokepoint_root_members):
        if allowed_start_ids and gid not in allowed_start_ids:
            continue
        if allowed_reachable_ids and gid not in allowed_reachable_ids:
            continue
        if outgoing.get(gid, 0) <= 0:
            continue
        chokepoint_roots.append(gid)
    chokepoint_root_set: set[str] = set(chokepoint_roots)

    # --- Parallel DFS (domain scope) -----------------------------------------
    # When ADSCAN_ATTACK_PATH_WORKERS != 0 and the source set is large enough,
    # distribute the per-source DFS across spawn-context worker processes.
    # Worker processes receive the pre-built adjacency and local-reuse indexes
    # via the pool initializer (pickled once per worker, not per task).
    # On any failure the result list is empty and we fall through to sequential.
    #
    # NOTE (Layer 3): the parallel worker path does NOT yet apply the
    # choke-point-rooted DFS (``chokepoint_group_ids``).  It runs the plain
    # per-source DFS, so its output is byte-IDENTICAL to the sequential engine
    # only AFTER ``collapse_memberof_prefixes`` (which still strips the
    # duplicated MemberOf prefixes downstream) — correctness is preserved, but
    # the parallel path pays the full O(members x subtree) cost.  Porting the
    # root-set + suppression + guards into ``_dfs_sources_batch_worker`` (via the
    # pool initializer) is the follow-up to give workers the same speedup; the
    # DEFAULT engine is sequential (``ADSCAN_ATTACK_PATH_WORKERS=0``), which is
    # fully optimized.
    n_workers = _effective_domain_dfs_workers(len(sources))
    if n_workers >= 2:
        from adscan_internal.rich_output import print_info_debug  # noqa: PLC0415

        print_info_debug(
            f"[domain-dfs] parallel: {n_workers} workers / {len(sources)} sources"
        )
        terminal_set = {
            node_id
            for node_id, node in nodes_map.items()
            if isinstance(node, dict) and is_terminal(node_id)
        }
        parallel_paths = _run_parallel_domain_dfs(
            sources,
            view.adjacency,
            view.local_reuse_by_node,
            view.local_reuse_existing_pairs,
            view.local_reuse_useful_nodes,
            terminal_set,
            target,
            max_depth,
            max_paths_cap,
            n_workers,
            view.implicit_edge_overlay,
            allowed_reachable_ids,
        )
        if parallel_paths or not sources:
            return parallel_paths
        # Fall through to sequential if parallel returned nothing unexpectedly.
        from adscan_internal.rich_output import print_info_debug  # noqa: PLC0415

        print_info_debug(
            "[domain-dfs] parallel returned empty, falling back to sequential"
        )
    # --- Sequential DFS (default / fallback) ---------------------------------

    paths: list[AttackPath] = []
    seen_signatures: set[tuple[tuple[str, str, str, str], ...]] = set()
    # Layer 3: the source-member set of the choke point currently being rooted
    # (None while walking a real source).  Two byte-identity guards use it:
    #   * emit guard — drop a choke-point-rooted path whose span already contains
    #     EVERY source-member of the root: no member is left outside it to have
    #     generated it under per-source blocking, so the post-hoc collapse would
    #     not have produced it either (it would be an over-long extra).
    #   * truncation emit (in the DFS) — when the ONLY onward continuation from a
    #     node is a single source-member ``m``, that member's own DFS would block
    #     there and emit the shorter path; the shared root walk continues past
    #     ``m``, so it must ALSO emit the truncated path to stay byte-identical.
    active_guard_members: set[str] | None = None
    # In-DFS runaway bound: converts a mid-recursion OOM into the SAME declared
    # coverage-bounded stop the outer gate raises, instead of a kernel SIGKILL.
    # Never fires on a graph that fits in RAM (byte-identical coverage there).
    _budget = DfsMemoryBudget()

    def emit(acc_steps: list[AttackPathStep]) -> None:
        if not acc_steps:
            return
        if max_paths_cap is not None and len(paths) >= max_paths_cap:
            return
        if (target == "highvalue" and not is_terminal(acc_steps[-1].to_id)) or (
            target == "lowpriv" and is_terminal(acc_steps[-1].to_id)
        ):
            return
        if active_guard_members is not None and len(active_guard_members) <= len(
            acc_steps
        ) + 1:
            # A span of N nodes can contain EVERY member only when members <= N,
            # so this O(members) subset test is skipped entirely at scale (a
            # universal group's member count vastly exceeds any path length) —
            # keeping the choke-point rooting O(members + subtree), never O(M*S).
            span = {acc_steps[0].from_id}
            span.update(s.to_id for s in acc_steps)
            if active_guard_members.issubset(span):
                return
        signature = tuple(attack_path_step_signature(s) for s in acc_steps)
        if signature in seen_signatures:
            return
        seen_signatures.add(signature)
        paths.append(
            AttackPath(
                steps=list(acc_steps),
                source_id=acc_steps[0].from_id,
                target_id=acc_steps[-1].to_id,
            )
        )

    def dfs(current: str, visited: set[str], acc_steps: list[AttackPathStep]) -> None:
        _budget.tick()
        if max_paths_cap is not None and len(paths) >= max_paths_cap:
            return
        actionable_depth = _count_actionable_edges(acc_steps)
        structural_depth = len(acc_steps) - actionable_depth
        # A Domain terminal normally stops the DFS, but a compromised domain that
        # can escalate cross-forest (CrossOrgTgtDelegation etc.) into an unvisited
        # domain is NOT the end — keep traversing so the cross-domain step chains
        # onto the kill chain (… → DCSync → EXT → CrossOrgTgtDelegation → HTB).
        terminal_here = bool(acc_steps) and is_terminal(current)
        if terminal_here and _domain_has_cross_domain_escalation_out(
            current, adjacency, visited
        ):
            terminal_here = False
        if (
            actionable_depth >= max_depth
            or structural_depth >= _MAX_STRUCTURAL_HOPS
            or terminal_here
        ):
            emit(acc_steps)
            return

        next_edges = iter_view_frontier(view, current, acc_steps)
        if not next_edges:
            emit(acc_steps)
            return

        extended = False
        new_targets: set[str] = set()
        self_loop_extended = False
        _path_rels = [str(s.relation or "").strip().lower() for s in acc_steps]
        for edge in next_edges:
            # Shared per-frontier prefix predicates (concern 2). The domain DFS
            # uses the plain reachability form (terminal_set=None) and passes the
            # rooted choke-point set for the Layer-3 leading-hop suppression.
            verdict, is_self_loop, step_notes = admit_frontier_edge(
                edge,
                current=current,
                acc_steps=acc_steps,
                path_rels=_path_rels,
                visited=visited,
                view=view,
                reachable_node_ids=allowed_reachable_ids,
                terminal_set=None,
                chokepoint_root_set=chokepoint_root_set,
            )
            if verdict != "admit":
                continue
            to_id = str(edge.get("to") or "")
            step = AttackPathStep(
                from_id=current,
                relation=str(edge.get("relation") or ""),
                to_id=to_id,
                status=str(edge.get("status") or "discovered"),
                notes=step_notes,
            )
            if not is_self_loop:
                visited.add(to_id)
            acc_steps.append(step)
            dfs(to_id, visited, acc_steps)
            acc_steps.pop()
            if not is_self_loop:
                visited.remove(to_id)
            extended = True
            if is_self_loop:
                self_loop_extended = True
            else:
                new_targets.add(to_id)

        # Layer 3 — member-loop-back truncation: when the ONLY onward move from
        # here is a single source-member ``m`` of the choke point being rooted
        # (and there is no self-loop ``m`` could otherwise take), ``m``'s own DFS
        # would block on itself and emit the path truncated HERE.  The shared
        # root walk continues past ``m``, so it must emit that truncated path too
        # — otherwise a real, shorter maximal path (the one the post-hoc collapse
        # kept) would go missing.
        if (
            active_guard_members is not None
            and acc_steps
            and not self_loop_extended
            and len(new_targets) == 1
            and next(iter(new_targets)) in active_guard_members
        ):
            emit(acc_steps)

        if not extended:
            emit(acc_steps)

    # Per-principal progress for the live compute panel. The sequential DFS is
    # the dominant, otherwise-unobserved phase (each source's walk is the
    # ~seconds-per-principal cost the ETA extrapolates from), so report the
    # position from inside the loop. ``notify_principal`` is a no-op single
    # global read when no UI is registered — the DFS is byte-identical for
    # web / report / debug-script callers. Sources + rooted choke points share
    # one denominator so the bar reaches 100% exactly when the DFS finishes.
    _dfs_total = len(sources) + len(chokepoint_roots)
    _dfs_done = 0

    # Sources first: they drop their redundant leading MemberOf hop into every
    # rooted choke point (see the DFS suppression), so each shared subtree is
    # walked once below instead of once per member.
    for source in sources:
        if max_paths_cap is not None and len(paths) >= max_paths_cap:
            break
        attack_path_progress.notify_principal(_dfs_done, _dfs_total)
        dfs(source, visited={source}, acc_steps=[])
        _dfs_done += 1

    # Then walk each choke-point subtree ONCE, rooted at the group, with the two
    # byte-identity guards active (emit-span guard for over-long extras, and the
    # member-loop-back truncation emit).  ``active_guard_members`` is the root's
    # own source-member set.
    for chokepoint in chokepoint_roots:
        if max_paths_cap is not None and len(paths) >= max_paths_cap:
            break
        attack_path_progress.notify_principal(_dfs_done, _dfs_total)
        active_guard_members = chokepoint_root_members.get(chokepoint)
        dfs(chokepoint, visited={chokepoint}, acc_steps=[])
        _dfs_done += 1
    active_guard_members = None
    attack_path_progress.notify_principal(_dfs_done, _dfs_total)

    return paths


def compute_maximal_attack_paths_from_start(
    graph: dict[str, Any],
    *,
    start_node_id: str,
    max_depth: int,
    max_paths: int | None = None,
    target: str = "highvalue",
    terminal_mode: str = "domain",
    reachable_node_ids: set[str] | None = None,
) -> list[AttackPath]:
    """Compute maximal paths starting from a specific node."""
    if max_depth <= 0 or not start_node_id:
        return []
    max_paths_cap = (
        None
        if max_paths is None
        else max(1, int(max_paths))
        if int(max_paths) > 0
        else None
    )

    nodes_map = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes_map, dict) or not isinstance(edges, list):
        return []

    allowed_reachable_ids: set[str] = (
        {str(node_id) for node_id in reachable_node_ids if str(node_id).strip()}
        if reachable_node_ids
        else set()
    )
    if allowed_reachable_ids and start_node_id not in allowed_reachable_ids:
        return []

    # Concern 1 — pre-materialise the graph-shape layer (adjacency + local-reuse
    # + implicit overlays + gen-time collapse). This is the owned/user/principals
    # per-start DFS, where the interchangeable-pivot fan-out (Account Operators
    # --GenericAll--> thousands of accounts) explodes per principal; the OFF-by-
    # default gen-time collapse walks one representative and rebuilds the sibling
    # rows before the proven post-materialization merge. No degree maps needed.
    gentime_collapse_on = _read_gentime_collapse_enabled()
    view = build_expansion_view(
        graph,
        nodes_map=nodes_map,
        edges=edges,
        track_degrees=False,
        gentime_collapse_on=gentime_collapse_on,
    )
    adjacency = view.adjacency

    mode = normalize_target_mode(terminal_mode)

    def is_terminal(node_id: str) -> bool:
        node = nodes_map.get(node_id)
        if not isinstance(node, dict):
            return False
        if mode in {"object"}:
            return _node_is_domain(node)
        if mode == "impact":
            return _node_is_terminal_target(node, mode=mode)
        return _node_is_terminal_target(node, mode=mode)

    paths: list[AttackPath] = []
    seen_signatures: set[tuple[tuple[str, str, str, str], ...]] = set()
    # In-DFS runaway bound: converts a mid-recursion OOM into the SAME declared
    # coverage-bounded stop the outer gate raises, instead of a kernel SIGKILL.
    # Never fires on a graph that fits in RAM (byte-identical coverage there).
    _budget = DfsMemoryBudget()

    def emit(acc_steps: list[AttackPathStep]) -> None:
        if not acc_steps:
            return
        if max_paths_cap is not None and len(paths) >= max_paths_cap:
            return
        if (target == "highvalue" and not is_terminal(acc_steps[-1].to_id)) or (
            target == "lowpriv" and is_terminal(acc_steps[-1].to_id)
        ):
            return
        signature = tuple(attack_path_step_signature(s) for s in acc_steps)
        if signature in seen_signatures:
            return
        seen_signatures.add(signature)
        paths.append(
            AttackPath(
                steps=list(acc_steps),
                source_id=acc_steps[0].from_id,
                target_id=acc_steps[-1].to_id,
            )
        )

    def dfs(current: str, visited: set[str], acc_steps: list[AttackPathStep]) -> None:
        _budget.tick()
        if max_paths_cap is not None and len(paths) >= max_paths_cap:
            return
        actionable_depth = _count_actionable_edges(acc_steps)
        structural_depth = len(acc_steps) - actionable_depth
        # A Domain terminal normally stops the DFS, but a compromised domain that
        # can escalate cross-forest (CrossOrgTgtDelegation etc.) into an unvisited
        # domain is NOT the end — keep traversing so the cross-domain step chains
        # onto the kill chain (… → DCSync → EXT → CrossOrgTgtDelegation → HTB).
        terminal_here = bool(acc_steps) and is_terminal(current)
        if terminal_here and _domain_has_cross_domain_escalation_out(
            current, adjacency, visited
        ):
            terminal_here = False
        if (
            actionable_depth >= max_depth
            or structural_depth >= _MAX_STRUCTURAL_HOPS
            or terminal_here
        ):
            emit(acc_steps)
            return

        next_edges = iter_view_frontier(view, current, acc_steps)
        if not next_edges:
            emit(acc_steps)
            return

        extended = False
        _path_rels = [str(s.relation or "").strip().lower() for s in acc_steps]
        for edge in next_edges:
            # Shared per-frontier prefix predicates (concern 2). The per-start DFS
            # uses the plain reachability form (terminal_set=None) and has no
            # choke-point rooting (empty root set).
            verdict, is_self_loop, step_notes = admit_frontier_edge(
                edge,
                current=current,
                acc_steps=acc_steps,
                path_rels=_path_rels,
                visited=visited,
                view=view,
                reachable_node_ids=allowed_reachable_ids,
                terminal_set=None,
                chokepoint_root_set=set(),
            )
            if verdict != "admit":
                continue
            to_id = str(edge.get("to") or "")
            step = AttackPathStep(
                from_id=current,
                relation=str(edge.get("relation") or ""),
                to_id=to_id,
                status=str(edge.get("status") or "discovered"),
                notes=step_notes,
            )
            if not is_self_loop:
                visited.add(to_id)
            acc_steps.append(step)
            dfs(to_id, visited, acc_steps)
            acc_steps.pop()
            if not is_self_loop:
                visited.remove(to_id)
            extended = True

        if not extended:
            emit(acc_steps)

    dfs(start_node_id, visited={start_node_id}, acc_steps=[])
    return paths


def collect_source_step_signatures_on_high_value_paths(
    graph: dict[str, Any],
    *,
    start_node_id: str,
    max_depth: int,
    target_mode: str = "object",
) -> set[tuple[str, str, str]]:
    """Return source-edge signatures that participate in HV/tier-zero paths.

    This helper is intentionally lower-level than the CLI display pipeline. It
    reuses the core DFS and high-value promotion semantics, but skips all
    display-only minimization, deduplication, and UX shaping.

    Args:
        graph: In-memory attack graph.
        start_node_id: Source node id to expand from.
        max_depth: Maximum path depth.
        target_mode: ``"tier0"`` or ``"impact"``. ``"tier0"`` is the default
            so intermediate high-value pivots do not stop expansion early.

    Returns:
        Set of ``(from_id, relation, to_id)`` signatures for steps that start
        at ``start_node_id`` and are part of at least one path that reaches a
        high-value / tier-zero target under the same promotion semantics used by
        display-path generation.
    """
    mode = normalize_target_mode(target_mode)

    required_rank = 1 if mode == "impact" else 3
    results: set[tuple[str, str, str]] = set()

    for path in compute_maximal_attack_paths_from_start(
        graph,
        start_node_id=start_node_id,
        max_depth=max_depth,
        max_paths=None,
        target="all",
        terminal_mode=mode,
    ):
        candidate = path
        if not _path_target_is_high_value(graph, path.target_id, mode=mode):
            promoted = _try_promote_target_via_membership_edges(
                graph,
                path,
                required_rank=required_rank,
                mode=mode,
            )
            if not promoted:
                continue
            candidate = promoted

        for step in candidate.steps:
            if step.from_id != start_node_id:
                continue
            results.add((step.from_id, step.relation, step.to_id))

    return results


def path_to_display_record(
    graph: dict[str, Any], path: AttackPath, *, decorate: bool = True
) -> dict[str, Any]:
    """Convert an AttackPath to the CLI/UI-friendly dict shape.

    ``decorate`` controls whether the expensive per-step decoration
    (``remediability`` verdict + ``source_privilege_tier``) is computed now.
    The DFS emits thousands of raw candidate records of which minimisation keeps
    ~2%, so decorating every raw record — a remediability classification plus a
    Privilege-Tier resolution PER STEP — is wasted work on the ~98% that are
    collapsed/deduped away (measured: ~40s and ~570 MB on a 3k-node domain, 98%
    discarded). With ``decorate=False`` this builds a *light* record: every field
    the minimisation stages read (``nodes``/``relations``/``steps`` with its
    ``action``+``status``+``details`` share identity, ``_exact_signature``,
    ``length``, ``source``, ``target``, ``status``) is present and byte-identical,
    but each step OMITS the two expensive fields and instead stamps the private
    ``_decorate_from_id``/``_decorate_to_id`` node ids so
    :func:`decorate_display_record` can fill them in on the surviving records
    ONLY. The minimisation stages slice ``steps`` by contiguous index range and
    re-derive status from ``action``/``status`` — they never read
    ``remediability`` or ``source_privilege_tier`` — so the deferred fields cannot
    change what survives. Decorating the light survivors reproduces the exact
    record ``decorate=True`` would have produced. The single decorate seam is at
    the end of ``attack_graph_service._apply_local_postprocessing_pipeline``,
    after every minimisation/filter/dedup stage across both pipelines.
    """
    from adscan_internal.services.attack_step_support_registry import (
        classify_relation_support,
    )
    from adscan_internal.services.compromise_class import privilege_tier_for_node
    from adscan_internal.services.remediability import (
        classify_edge_remediability,
        principal_facts_from_node,
    )

    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    context_relations = {
        str(rel).strip().lower() for rel in CONTEXT_ONLY_RELATIONS.keys()
    }

    def label(node_id: str) -> str:
        node = nodes_map.get(node_id)
        if isinstance(node, dict):
            return str(node.get("label") or node_id)
        return node_id

    # Whether a step is something the client can CHANGE is decided here, once,
    # because this is the only layer that holds both the edge and the graph nodes
    # its endpoints resolve to. Deciding it downstream would mean deciding it from
    # the relation name alone, which is wrong per instance: most group
    # memberships are removable and most replication rights are not (see
    # adscan_internal.services.remediability). Every consumer — the paid
    # deliverable's technique ranking, the free report's choke-point table and the
    # web CTEM's remediation page — reads the stamp instead of re-resolving.
    _facts_cache: dict[str, Any] = {}

    def _facts(node_id: str) -> Any:
        if node_id not in _facts_cache:
            _facts_cache[node_id] = principal_facts_from_node(nodes_map.get(node_id))
        return _facts_cache[node_id]

    def remediability_of(relation: str, from_id: str, to_id: str) -> dict[str, str]:
        try:
            return classify_edge_remediability(
                relation, source=_facts(from_id), target=_facts(to_id)
            ).as_dict()
        except Exception:  # pragma: no cover - a verdict is never fatal
            return {}

    def _resolve_membership_followup_step(
        target_node: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        if not isinstance(target_node, dict):
            return None
        target_kind = (
            target_node.get("kind")
            or target_node.get("labels")
            or target_node.get("type")
        )
        if isinstance(target_kind, list):
            target_kind = str(target_kind[0] if target_kind else "")
        if str(target_kind or "") != "Group":
            return None
        props = (
            target_node.get("properties")
            if isinstance(target_node.get("properties"), dict)
            else {}
        )
        sid_upper, _ = _extract_node_sid_and_rid(target_node)
        group_name = str(props.get("name") or target_node.get("label") or "").strip()
        membership = classify_privileged_membership(
            group_sids=[sid_upper],
            group_names=[group_name],
        )
        normalized_group_name = normalize_group_name(group_name)
        # Terminate the synthetic escalation follow-up at the REAL domain object
        # node (not a "Domain Control" placeholder) so the annotation phase — which
        # resolves the terminal node by label — classifies it against the domain
        # object and the canonical target_mode="object" ordering surfaces it in the
        # Domain Compromised tier.
        domain_label = _resolve_membership_followup_domain_label(graph, target_node)
        if membership.dns_admins:
            return {
                "relation": "DnsAdminAbuse",
                "status": "blocked",
                "to": domain_label,
                "reason": "Production-impacting DNS modification is blocked by design",
            }
        if membership.backup_operators:
            return {
                "relation": "BackupOperatorEscalation",
                "status": "theoretical",
                "to": domain_label,
                "reason": "Backup Operators can enable a follow-up path to domain compromise",
            }
        if normalized_group_name == "print operators":
            return {
                "relation": "PrintOperatorAbuse",
                "status": "unsupported",
                "to": domain_label,
                "reason": "Print Operators exposure is modeled, but ADscan has no automated follow-up yet",
            }
        return None

    nodes = [label(path.source_id)]
    relations: list[str] = []
    for step in path.steps:
        relations.append(step.relation)
        nodes.append(label(step.to_id))

    derived_status = "theoretical"
    executable_steps = [
        s
        for s in path.steps
        if isinstance(getattr(s, "relation", None), str)
        and str(s.relation).strip().lower() not in context_relations
    ]
    target_node = nodes_map.get(path.target_id) if isinstance(nodes_map, dict) else None
    synthetic_followup = None
    if (
        not executable_steps
        and path.steps
        and str(path.steps[-1].relation or "").strip().lower() == "memberof"
    ):
        synthetic_followup = _resolve_membership_followup_step(target_node)
        if synthetic_followup is not None:
            relations.append(str(synthetic_followup["relation"]))
            nodes.append(str(synthetic_followup["to"]))
    statuses = [
        s.status.lower()
        for s in executable_steps
        if isinstance(s.status, str) and s.status
    ]
    if synthetic_followup is not None:
        statuses.append(str(synthetic_followup.get("status") or "").strip().lower())
    if statuses and all(s == "success" for s in statuses):
        derived_status = "exploited"
    elif any(s in {"attempted", "failed", "error"} for s in statuses):
        derived_status = "attempted"
    elif any(s == "unavailable" for s in statuses):
        derived_status = "unavailable"
    elif any(s == "blocked" for s in statuses) or any(
        classify_relation_support(str(s.relation or "").strip().lower()).kind
        == "policy_blocked"
        for s in executable_steps
    ):
        derived_status = "blocked"
    elif any(s == "closed_by_configuration" for s in statuses):
        # A relay avenue ADscan observed to be CLOSED with certainty by the
        # environment's configuration/topology (signing/CBT/no-ADCS/MAQ/single-DC
        # reflection). A POSITIVE exposure fact — never a risk/held status.
        derived_status = "closed_by_configuration"
    elif any(s == "unsupported" for s in statuses):
        derived_status = "unsupported"

    steps_for_ui: list[dict[str, Any]] = []
    for idx, step in enumerate(path.steps, start=1):
        # ``details`` always carries ``from``/``to`` labels + the edge ``notes``
        # (the notes hold the SMB share name that ``_display_relation_identity_values``
        # folds into ``_exact_signature`` for share-access edges — so dedup /
        # containment stay byte-identical even in the light build). Only the
        # expensive ``source_privilege_tier`` and the ``remediability`` verdict are
        # deferred; ``decorate_display_record`` adds them for surviving records.
        step_details: dict[str, Any] = {
            "from": label(step.from_id),
            "to": label(step.to_id),
        }
        step_record: dict[str, Any] = {
            "step": idx,
            "action": step.relation,
            # A non-executed ``context_only`` hop (MemberOf, credential-reuse
            # pivot) is a structural FACT — surface it as ``structural`` at the
            # data SSOT so every consumer (snapshot/PDF/web) agrees, never a
            # per-render relabel. Proven / blocked / config-close statuses are
            # preserved unchanged (see ``derive_step_display_status``).
            "status": derive_step_display_status(step.relation, step.status),
            "details": step_details,
        }
        if decorate:
            step_record["remediability"] = remediability_of(
                step.relation, step.from_id, step.to_id
            )
            # The SOURCE's granted Privilege Tier (axis 1), resolved HERE for the
            # same reason ``remediability`` is: this is a layer that holds both
            # the edge and the graph NODES its endpoints resolve to. A downstream
            # renderer sees only labels, and no label can tell you that MEEREEN$
            # is a domain controller. Consumed by
            # ``attack_step_catalog.render_step_remediation`` to suppress
            # "remove it" advice on a step out of a Tier-0-direct principal
            # (built-in AD hierarchy, not a misconfiguration). Mirrored in the
            # sibling ``attack_graph_service.path_to_display_record``.
            step_details["source_privilege_tier"] = privilege_tier_for_node(
                nodes_map.get(step.from_id)
            ).value
            step_details.update(step.notes or {})
        else:
            # Light build: fold the notes now (needed for the share-name signature
            # and carried by the index-slicing minimisation) but defer the two
            # expensive fields. Stamp the endpoint node ids privately so the
            # decorate seam can compute them on the survivors without a graph
            # re-walk. These private keys are ignored by every signature/slicing
            # stage and are removed by ``decorate_display_record``.
            step_details.update(step.notes or {})
            step_record["_decorate_from_id"] = step.from_id
            step_record["_decorate_to_id"] = step.to_id
        steps_for_ui.append(step_record)
    if synthetic_followup is not None:
        synthetic_status = str(synthetic_followup.get("status") or "theoretical")
        # A synthetic follow-up has no target NODE (its target is a rendered
        # label), so only the source resolves — ``source_privilege_tier`` and the
        # ``remediability`` verdict both read the SOURCE node. Build the cheap
        # details first, in the exact key order the decorated form produces, then
        # add the two expensive fields (decorate) or defer them (light).
        followup_details: dict[str, Any] = {
            "from": label(path.target_id),
            "to": str(synthetic_followup["to"]),
        }
        if decorate:
            # Same axis-1 stamp as the real steps above, so every step a renderer
            # receives carries the source tier.
            followup_details["source_privilege_tier"] = privilege_tier_for_node(
                nodes_map.get(path.target_id)
            ).value
        followup_details["reason"] = str(synthetic_followup.get("reason") or "")
        followup_details["synthetic_followup"] = True
        followup_details["followup_source_group"] = label(path.target_id)
        # A blocked synthetic follow-up (e.g. DNSAdmins abuse) is a safety
        # abstention — route it through the single classifier so it is stamped
        # ``dangerous_destructive`` and renders under "Not executed for safety",
        # never a bare ``dangerous``.
        if synthetic_status.strip().lower() == "blocked":
            followup_details.update(
                _safety_abstention_notes(str(synthetic_followup["relation"]))
                or {
                    "blocked_kind": "dangerous",
                    "reason": str(synthetic_followup.get("reason") or ""),
                }
            )
        followup_record: dict[str, Any] = {
            "step": len(steps_for_ui) + 1,
            "action": str(synthetic_followup["relation"]),
            "status": synthetic_status,
            "details": followup_details,
        }
        if decorate:
            followup_record["remediability"] = remediability_of(
                str(synthetic_followup["relation"]), path.target_id, ""
            )
        else:
            # Defer both expensive fields; stamp the source id (target id is the
            # empty-string sentinel the decorator passes to ``remediability_of``).
            followup_record["_decorate_from_id"] = path.target_id
            followup_record["_decorate_to_id"] = ""
            followup_record["_decorate_synthetic"] = True
        steps_for_ui.append(followup_record)

    return {
        "nodes": nodes,
        "relations": relations,
        "_exact_signature": (
            tuple(nodes),
            _display_relation_identity_values(
                {
                    "relations": relations,
                    "steps": steps_for_ui,
                },
                normalize=False,
            ),
        ),
        "length": sum(
            1
            for rel in relations
            if str(rel or "").strip().lower() not in context_relations
        ),
        "source": nodes[0] if nodes else "",
        "target": nodes[-1] if nodes else "",
        # When a synthetic escalation follow-up extends the path past the group
        # to the domain object, the terminal IS that domain object — the
        # annotation phase must resolve the domain node, not the group, so the
        # path is classified/ordered as a domain-compromise terminal.
        "terminal_target_label": (
            str(synthetic_followup["to"])
            if synthetic_followup is not None
            else label(path.target_id)
        ),
        "status": derived_status,
        "steps": steps_for_ui,
    }


def decorate_display_record(
    graph: dict[str, Any],
    record: dict[str, Any],
    *,
    _caches: "_DecorationCaches | None" = None,
) -> dict[str, Any]:
    """Fill in the deferred per-step decoration on a light display record.

    Counterpart to ``path_to_display_record(..., decorate=False)``. For every
    step still carrying the private ``_decorate_from_id`` marker it computes the
    two expensive fields — the ``remediability`` verdict and the source
    ``source_privilege_tier`` — from the stamped endpoint node ids, and rebuilds
    the step dict so its final shape (top-level key order ``step, action, status,
    remediability, details``; inner ``details`` order ``from, to,
    source_privilege_tier, <notes…>``) is byte-identical to what
    ``decorate=True`` would have produced. Mutates and returns ``record`` in
    place. Idempotent: a step without the marker (already decorated, or an
    externally-built step) is left untouched. Only the ~2% of raw records that
    survive minimisation reach here, which is the whole point — the ~98%
    collapsed away never pay the decoration cost.

    ``_caches`` (internal) shares the per-node fact/tier resolution across every
    record of one batch — see :func:`decorate_display_records`. On a large domain
    thousands of surviving paths terminate at the same handful of Tier-0 nodes, so
    resolving the same node id once per batch instead of once per record collapses
    the repeated ``principal_facts_from_node``/``privilege_tier_for_node`` work.
    Byte-identical: both resolvers are pure functions of the node dict, which is
    stable across the batch (same ``graph``). Omitting ``_caches`` builds a
    per-call cache, preserving the standalone-call behaviour.
    """
    caches = _caches if _caches is not None else _DecorationCaches(graph)

    # The sibling-pivot collapse (``collapse_sibling_pivot_paths``) stashes each
    # sampled sibling's full path SHAPE — including its own ``steps`` — under
    # ``meta.via_account_paths[<label>]`` so a later re-target executes the ACTUAL
    # sibling. Those nested steps are light too, so decorate them here (they never
    # reach the top-level ``steps`` seam otherwise). Same graph, same idempotency,
    # same shared caches.
    meta = record.get("meta")
    if isinstance(meta, dict):
        via_paths = meta.get("via_account_paths")
        if isinstance(via_paths, dict):
            for shape in via_paths.values():
                if isinstance(shape, dict) and isinstance(shape.get("steps"), list):
                    decorate_display_record(graph, shape, _caches=caches)

    steps = record.get("steps")
    if not isinstance(steps, list):
        return record

    decorated_steps: list[Any] = []
    for step in steps:
        if not isinstance(step, dict) or "_decorate_from_id" not in step:
            decorated_steps.append(step)
            continue

        from_id = str(step.get("_decorate_from_id") or "")
        to_id = str(step.get("_decorate_to_id") or "")

        old_details = step.get("details")
        old_details = old_details if isinstance(old_details, dict) else {}
        # Rebuild ``details`` so ``source_privilege_tier`` lands between ``to`` and
        # the notes — the exact order the eager build produced (``from``, ``to``,
        # ``source_privilege_tier``, then the folded edge notes). Re-appending the
        # remaining keys preserves the notes and their order.
        new_details: dict[str, Any] = {
            "from": old_details.get("from", ""),
            "to": old_details.get("to", ""),
        }
        new_details["source_privilege_tier"] = caches.tier(from_id)
        for key, value in old_details.items():
            if key in ("from", "to"):
                continue
            new_details[key] = value

        # Rebuild the step in canonical top-level key order
        # (``step, action, status, remediability, details``), dropping the private
        # ``_decorate_*`` markers.
        new_step: dict[str, Any] = {
            "step": step.get("step"),
            "action": step.get("action"),
            "status": step.get("status"),
            "remediability": caches.remediability(
                str(step.get("action") or ""), from_id, to_id
            ),
            "details": new_details,
        }
        decorated_steps.append(new_step)

    record["steps"] = decorated_steps
    return record


class _DecorationCaches:
    """Per-batch shared resolution cache for :func:`decorate_display_record`.

    Memoizes the two pure per-node resolvers (``principal_facts_from_node`` and
    ``privilege_tier_for_node``) by node id across every record decorated in one
    batch, so a Tier-0 terminal shared by thousands of paths resolves once.
    """

    def __init__(self, graph: dict[str, Any]) -> None:
        from adscan_internal.services.compromise_class import privilege_tier_for_node
        from adscan_internal.services.remediability import (
            classify_edge_remediability,
            principal_facts_from_node,
        )

        nodes = graph.get("nodes")
        self._nodes_map = nodes if isinstance(nodes, dict) else {}
        self._privilege_tier_for_node = privilege_tier_for_node
        self._classify_edge_remediability = classify_edge_remediability
        self._principal_facts_from_node = principal_facts_from_node
        self._facts_cache: dict[str, Any] = {}
        self._tier_cache: dict[str, Any] = {}

    def _facts(self, node_id: str) -> Any:
        cached = self._facts_cache.get(node_id, _MISSING)
        if cached is _MISSING:
            cached = self._principal_facts_from_node(self._nodes_map.get(node_id))
            self._facts_cache[node_id] = cached
        return cached

    def tier(self, node_id: str) -> Any:
        cached = self._tier_cache.get(node_id, _MISSING)
        if cached is _MISSING:
            cached = self._privilege_tier_for_node(self._nodes_map.get(node_id)).value
            self._tier_cache[node_id] = cached
        return cached

    def remediability(
        self, relation: str, from_id: str, to_id: str
    ) -> dict[str, str]:
        try:
            return self._classify_edge_remediability(
                relation, source=self._facts(from_id), target=self._facts(to_id)
            ).as_dict()
        except Exception:  # pragma: no cover - a verdict is never fatal
            return {}


#: Sentinel distinguishing "not yet cached" from a legitimately cached ``None``.
_MISSING: Any = object()


def decorate_display_records(
    graph: dict[str, Any], records: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Decorate a batch of light display records in place (see
    :func:`decorate_display_record`).

    Builds ONE shared per-node resolution cache for the whole batch so a node id
    that appears across many records (a shared Tier-0 terminal) is resolved once,
    not once per record — byte-identical output, far fewer resolver calls.
    """
    if not isinstance(records, list):
        return records
    caches = _DecorationCaches(graph)
    for record in records:
        if isinstance(record, dict):
            decorate_display_record(graph, record, _caches=caches)
    return records


def _find_user_node_id(
    nodes_map: dict[str, Any],
    *,
    username: str,
    canonical_label: str,
) -> str | None:
    username_clean = str(username or "").strip().lower()
    if not username_clean:
        return None
    canonical_label_clean = str(canonical_label or "").strip().lower()
    for node_id, node in nodes_map.items():
        if not isinstance(node, dict):
            continue
        if str(node.get("kind") or "") != "User":
            continue
        if str(node.get("label") or "").strip().lower() == canonical_label_clean:
            return str(node_id)
        props = (
            node.get("properties") if isinstance(node.get("properties"), dict) else {}
        )
        sam = str(props.get("samaccountname") or "").strip().lower()
        if sam and sam == username_clean:
            return str(node_id)
    return None


def _path_target_is_high_value(
    graph: dict[str, Any], target_id: str, *, mode: str
) -> bool:
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    node = nodes_map.get(str(target_id or "")) if isinstance(nodes_map, dict) else None
    if not isinstance(node, dict):
        return False
    if mode == "domain":
        return _node_is_domain(node)
    if mode == "impact":
        return _node_is_impact_high_value(node)
    return _node_is_tier0(node)


def _node_is_domain(node: dict[str, Any]) -> bool:
    """Return True when the node represents the AD Domain object."""
    return str(node.get("kind") or "").strip().lower() == "domain"


def resolve_domain_node_labels(graph: dict[str, Any]) -> tuple[str, ...]:
    """Return the labels of all Domain-kind nodes in the attack graph.

    A small but load-bearing helper for the unified ``target_mode="object"``
    pipeline: callers that previously relied on ``target_mode="domain"`` to
    "find paths terminating at any domain object" can now resolve the
    concrete domain-node label(s) here and pass them as ``target_labels`` —
    making the target object explicit rather than implied.

    In single-domain workspaces this returns one label; in cross-domain /
    forest-merged graphs it can return several (one per domain node present).
    Returns an empty tuple when no domain node is materialised in the graph.
    """
    nodes = graph.get("nodes")
    if not isinstance(nodes, dict):
        return ()
    labels: list[str] = []
    seen: set[str] = set()
    for node in nodes.values():
        if not isinstance(node, dict) or not _node_is_domain(node):
            continue
        label = str(node.get("label") or node.get("name") or "").strip()
        if not label or label in seen:
            continue
        seen.add(label)
        labels.append(label)
    return tuple(labels)


def _resolve_membership_followup_domain_label(
    graph: dict[str, Any],
    group_node: dict[str, Any] | None,
) -> str:
    """Return the label of the domain object a privileged-group escalation reaches.

    A synthetic escalation follow-up (``BackupOperatorEscalation``,
    ``DnsAdminAbuse``, ``PrintOperatorAbuse``) must terminate at the **real**
    domain object node (e.g. ``BABY.VL``), not at a synthetic ``"Domain Control"``
    placeholder string. Only a real domain-object terminal is resolvable by the
    annotation phase (which looks the terminal node up by label), so the path is
    classified against the domain object — surfacing it in the *Domain Compromised*
    tier via the canonical ``target_mode="object"`` domain-object-first ordering
    instead of as an unresolved follow-up placeholder.

    Multi-domain safe: with a single domain node, return its label; with several,
    prefer the one matching the group's ``properties.domain``; fall back to the
    legacy ``"Domain Control"`` placeholder only when no domain node resolves.
    """
    labels = resolve_domain_node_labels(graph)
    if len(labels) == 1:
        return labels[0]
    if not labels:
        return "Domain Control"
    group_domain = ""
    if isinstance(group_node, dict):
        props = (
            group_node.get("properties")
            if isinstance(group_node.get("properties"), dict)
            else {}
        )
        group_domain = str((props or {}).get("domain") or "").strip().lower()
    if group_domain:
        for lbl in labels:
            normalized = lbl.strip().lower()
            if normalized == group_domain or normalized.endswith("@" + group_domain):
                return lbl
    return "Domain Control"


def _extract_node_sid_and_rid(node: dict[str, Any]) -> tuple[str | None, int | None]:
    """Return normalized SID and RID for one graph node when available."""
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    candidates = [
        props.get("objectid"),
        props.get("objectId"),
        node.get("objectid"),
        node.get("objectId"),
    ]
    sid: str | None = None
    for value in candidates:
        if isinstance(value, str) and value.strip():
            sid = value.strip()
            break
    if not sid:
        return None, None

    sid_upper = sid.strip().upper()
    sid_idx = sid_upper.find("S-1-")
    if sid_idx != -1:
        sid_upper = sid_upper[sid_idx:]
    try:
        rid = int(sid_upper.rsplit("-", 1)[-1])
    except Exception:
        rid = None
    return sid_upper, rid


def _node_domain_sid(node: dict[str, Any]) -> str | None:
    """Return the AD *domain SID* a node belongs to, or ``None``.

    A domain object's normalized SID (``S-1-5-21-X-Y-Z``) IS its domain SID, so
    it is returned unchanged. For any account/computer node whose SID carries a
    trailing RID (``S-1-5-21-X-Y-Z-<RID>``), the trailing ``-<RID>`` component is
    stripped to recover the SID of the domain that account belongs to. This is
    the canonical AD mapping used to point a DC's synthetic DCSync edge at its
    OWN domain head (never a foreign domain in a multi-domain / forest graph).

    Reuses :func:`_extract_node_sid_and_rid` for the normalized objectid lookup
    so the parser stays single-sourced. Guards against malformed / missing SIDs
    (returns ``None`` rather than raising).
    """
    sid_upper, _rid = _extract_node_sid_and_rid(node)
    if not sid_upper or not sid_upper.startswith("S-1-5-21-"):
        return None
    if _node_is_domain(node):
        # A Domain object's SID is already the domain SID.
        return sid_upper
    # Strip the trailing RID component to recover the parent domain's SID.
    head, _, tail = sid_upper.rpartition("-")
    if not head or not tail.isdigit():
        return None
    return head


def _node_is_tier0(node: dict[str, Any]) -> bool:
    if bool(node.get("isTierZero")):
        return True
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    if bool(props.get("isTierZero")):
        return True
    if node_is_rodc_computer(node):
        return True
    tags = node.get("system_tags") or props.get("system_tags") or []
    if isinstance(tags, str):
        tags = [tag.strip() for tag in re.split(r"[, ]+", tags) if tag.strip()]
    if any(str(tag).lower() == "admin_tier_0" for tag in tags):
        return True
    if is_adcs_tier_zero_group(node):
        return True
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    if is_dependency_only_tier_zero_group(
        sid=str(props.get("objectid") or node.get("objectid") or ""),
        name=str(props.get("name") or node.get("label") or ""),
    ):
        return True
    return is_future_followup_tier_zero_group(
        sid=str(props.get("objectid") or node.get("objectid") or ""),
        name=str(props.get("name") or node.get("label") or ""),
    )


def _node_is_privileged_group(node: dict[str, Any]) -> bool:
    if str(node.get("kind") or "") != "Group":
        return False
    sid_upper, rid = _extract_node_sid_and_rid(node)
    if not sid_upper:
        return False

    builtin_privileged_rids = {544, 548, 549, 550, 551}
    if rid in builtin_privileged_rids and sid_upper.startswith("S-1-5-32-"):
        return True

    domain_privileged_rids = {512, 518, 519}
    if rid in domain_privileged_rids:
        return True

    if rid == 1101:
        return True

    return False


def _node_is_effectively_high_value(node: dict[str, Any]) -> bool:
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    if _node_is_tier0(node):
        return True
    return bool(node.get("highvalue")) or bool(props.get("highvalue"))


def _node_is_enabled_user(node: dict[str, Any]) -> bool:
    """Return True when the node represents an enabled user principal."""
    if str(node.get("kind") or "") != "User":
        return False
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    enabled = props.get("enabled")
    if isinstance(enabled, bool):
        return enabled
    enabled = node.get("enabled")
    return enabled is True


def _node_is_impact_high_value(node: dict[str, Any]) -> bool:
    return _node_is_effectively_high_value(node)


def _node_high_value_rank(node: dict[str, Any]) -> int:
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    if _node_is_tier0(node):
        return 3
    if bool(node.get("highvalue")) or bool(props.get("highvalue")):
        return 2
    return 0


def _node_target_priority_class(node: dict[str, Any]) -> str:
    """Return BH-backed target criticality for one node."""
    if _node_is_tier0(node):
        return "tierzero"
    if _node_is_effectively_high_value(node):
        return "highvalue"
    return "pivot"


def _node_target_priority_rank(node: dict[str, Any]) -> int:
    """Return a stable priority rank within BH target criticality classes."""
    priority_class = _node_target_priority_class(node)
    sid_upper, rid = _extract_node_sid_and_rid(node)
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    group_name = str(props.get("name") or node.get("label") or "")
    distinguished_name = str(props.get("distinguishedname") or "")
    terminal_class = _node_target_terminal_class(node)

    if terminal_class == "graph_extension":
        if is_graph_extension_group(
            sid=sid_upper,
            name=group_name,
            distinguished_name=distinguished_name,
        ):
            if (
                rid == 548
                and isinstance(sid_upper, str)
                and sid_upper.startswith("S-1-5-32-")
            ):
                return 10
            return 15
        return 19

    if terminal_class == "followup_terminal":
        if node_is_rodc_computer(node):
            return RODC_TARGET_PRIORITY_RANK
        if is_followup_terminal_group(sid=sid_upper, name=group_name):
            if (
                rid == 551
                and isinstance(sid_upper, str)
                and sid_upper.startswith("S-1-5-32-")
            ):
                return 20
            if rid == 1101:
                return 30
        return 35

    if terminal_class == "dependency_only":
        return 32
    if terminal_class == "future_followup":
        return 31

    if priority_class == "tierzero":
        return 0
    if priority_class == "highvalue":
        if bool(node.get("highvalue")) or bool(props.get("highvalue")):
            return 40
        return 60
    return 100


def _node_target_terminal_class(node: dict[str, Any]) -> str:
    """Return ADscan's terminal-behaviour class for one node.

    This is intentionally distinct from ``_node_target_priority_class``:
    - priority class answers "how important is this target for UX ordering?"
    - terminal class answers "should path discovery stop when reaching it?"

    Classes:
        ``direct_compromise``:
            Reaching this node is a direct domain-compromise style outcome.
        ``followup_terminal``:
            Reaching this node is valuable and can terminate a path because a
            dedicated follow-up/exploitation chain starts there.
        ``graph_extension``:
            Reaching this node should *not* terminate path discovery because it
            primarily unlocks additional ACL/graph enrichment and the user
            benefits more from seeing the downstream direct-compromise options.
        ``dependency_only``:
            BloodHound classifies this group as Tier Zero due to local security
            dependency on DCs, but ADscan currently has no abuse/follow-up path
            to run from it, so it should not terminate discovery.
        ``future_followup``:
            BloodHound classifies this group as Tier Zero and ADscan expects to
            support a dedicated follow-up later, but that follow-up is not
            implemented yet, so it remains non-terminal for now.
        ``pivot``:
            Not a terminal-worthy target.
    """
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    group_name = str(props.get("name") or node.get("label") or "")
    distinguished_name = str(props.get("distinguishedname") or "")
    sid_upper, rid = _extract_node_sid_and_rid(node)
    priority_class = _node_target_priority_class(node)
    inherited_terminal_class = str(
        props.get("target_terminal_class") or node.get("target_terminal_class") or ""
    ).strip()
    if bool(
        props.get("tier0_inherited") or node.get("tier0_inherited")
    ) and inherited_terminal_class in {
        "direct_compromise",
        "followup_terminal",
        "graph_extension",
        "future_followup",
        "dependency_only",
    }:
        return inherited_terminal_class

    if node_is_rodc_computer(node):
        return "followup_terminal"
    if is_graph_extension_group(
        sid=sid_upper,
        name=group_name,
        distinguished_name=distinguished_name,
    ):
        return "graph_extension"
    if is_followup_terminal_group(sid=sid_upper, name=group_name):
        return "followup_terminal"
    if is_future_followup_tier_zero_group(sid=sid_upper, name=group_name):
        return "future_followup"
    if is_dependency_only_tier_zero_group(sid=sid_upper, name=group_name):
        return "dependency_only"
    if priority_class == "tierzero":
        return "direct_compromise"
    if priority_class != "highvalue":
        return "pivot"

    return "followup_terminal"


def _node_is_terminal_target(node: dict[str, Any], *, mode: str = "tier0") -> bool:
    """Return True when one node should terminate ADscan path discovery."""
    terminal_class = _node_target_terminal_class(node)
    if terminal_class == "direct_compromise":
        return True
    if terminal_class == "followup_terminal":
        return True
    return False


def _try_promote_target_via_membership_edges(
    graph: dict[str, Any],
    path: AttackPath,
    *,
    required_rank: int,
    mode: str,
) -> AttackPath | None:
    """Promote a non-high-value User/Computer target via MemberOf edges in the graph."""
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
    if not isinstance(nodes_map, dict) or not isinstance(edges, list):
        return None

    target_id = str(path.target_id or "")
    target_node = nodes_map.get(target_id)
    if not isinstance(target_node, dict):
        return None
    if str(target_node.get("kind") or "") not in {"User", "Computer"}:
        return None

    best_rank = 0
    best_group_id: str | None = None
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if str(edge.get("from") or "") != target_id:
            continue
        if str(edge.get("relation") or "").strip().lower() != "memberof":
            continue
        to_id = str(edge.get("to") or "")
        if not to_id:
            continue
        group_node = nodes_map.get(to_id)
        if not isinstance(group_node, dict):
            continue
        if str(group_node.get("kind") or "") != "Group":
            continue
        rank = _node_high_value_rank(group_node)
        if rank < required_rank:
            continue
        if rank > best_rank:
            best_rank = rank
            best_group_id = to_id
            if best_rank >= 3:
                break

    if not best_group_id:
        return None

    extended_steps = list(path.steps)
    extended_steps.append(
        AttackPathStep(
            from_id=target_id,
            relation="MemberOf",
            to_id=best_group_id,
            status="discovered",
            notes={
                "edge": "runtime",
                "context": "high_value_via_group"
                if mode == "impact"
                else "tier0_via_group",
            },
        )
    )
    return AttackPath(
        steps=extended_steps,
        source_id=path.source_id,
        target_id=best_group_id,
    )
