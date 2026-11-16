"""Membership snapshot loading and caching helpers."""

from __future__ import annotations

import os
from typing import Any, Callable

from adscan_core.engagement.output_formats import SCHEMA_VERSION_KEY, output_marker
from adscan_internal import telemetry
from adscan_internal.rich_output import (
    mark_sensitive,
    print_exception,
    print_info_debug,
)
from adscan_internal.workspaces import (
    domain_subpath,
    read_json_file,
    resolve_workspace_cwd,
    write_json_file,
)
from adscan_internal.services import attack_paths_core
from adscan_internal.services import membership_snapshot_shape as shape
from adscan_internal.services.cache_metrics import (
    copy_stats,
    increment_stats,
    reset_stats,
)

_MEMBERSHIP_SNAPSHOT_CACHE: dict[str, dict[str, Any] | None] = {}
_MEMBERSHIP_SNAPSHOT_CACHE_LOGGED: set[str] = set()
_MEMBERSHIP_SNAPSHOT_MTIME: dict[str, float | None] = {}
_MEMBERSHIP_SNAPSHOT_STATS: dict[str, int] = {
    "hits": 0,
    "misses": 0,
    "reloads": 0,
    "loaded": 0,
}


def get_membership_snapshot_cache_stats(*, reset: bool = False) -> dict[str, int]:
    """Return memberships.json cache counters."""
    stats = copy_stats(_MEMBERSHIP_SNAPSHOT_STATS)
    if reset:
        reset_stats(_MEMBERSHIP_SNAPSHOT_STATS)
    return stats


def snapshot_has_sid_metadata(snapshot: dict[str, Any] | None) -> bool:
    """Return True when snapshot has SID metadata needed for RID lookups."""
    if not isinstance(snapshot, dict):
        return False
    label_to_sid = snapshot.get("label_to_sid")
    domain_sid = snapshot.get("domain_sid")
    has_label_map = isinstance(label_to_sid, dict) and bool(label_to_sid)
    has_domain_sid = isinstance(domain_sid, str) and bool(domain_sid)
    return has_label_map or has_domain_sid


def membership_snapshot_path(shell: object, domain: str) -> str:
    """Resolve memberships.json path for a domain."""
    workspace_cwd = resolve_workspace_cwd(shell)
    domains_dir = getattr(shell, "domains_dir", "domains")
    path = domain_subpath(workspace_cwd, domains_dir, domain, "memberships.json")
    return path


def _write_membership_snapshot(path: str, data: dict[str, Any], *, domain: str) -> None:
    """Persist a runtime update of ``memberships.json`` in the current format.

    The one write path for every runtime membership change. It stamps the
    output-contract marker (schema ``memberships.v1.json``) and names the
    domain, so a snapshot a run creates before any collection is still a valid,
    versioned document.
    """
    data[SCHEMA_VERSION_KEY] = output_marker("memberships")
    if not str(data.get("domain") or "").strip():
        data["domain"] = str(domain or "")
    write_json_file(path, data)


def _canonical_membership_label(domain: str, value: str) -> str:
    """Return the canonical ``NAME@DOMAIN`` membership label."""
    raw = str(value or "").strip()
    domain_clean = str(domain or "").strip()
    if not raw:
        return ""
    if "\\" in raw:
        raw_domain, _, raw_name = raw.partition("\\")
        raw = raw_name or raw
        if raw_domain and "." in raw_domain:
            domain_clean = raw_domain
    if "@" in raw:
        left, _, right = raw.partition("@")
        if left and right:
            return f"{left.strip().upper()}@{right.strip().upper()}"
    if not domain_clean:
        return raw.strip().upper()
    return f"{raw.strip().upper()}@{domain_clean.upper()}"


def _invalidate_membership_snapshot_cache(domain: str) -> None:
    """Invalidate in-memory cache for one domain after a snapshot mutation."""
    domain_key = str(domain or "").strip().lower()
    if not domain_key:
        return
    _MEMBERSHIP_SNAPSHOT_CACHE.pop(domain_key, None)
    _MEMBERSHIP_SNAPSHOT_MTIME.pop(domain_key, None)
    _MEMBERSHIP_SNAPSHOT_CACHE_LOGGED.discard(domain_key)


def _invalidate_pac_for_membership_change(
    *,
    domain: str,
    user_label: str,
    group_label: str,
    action: str,
) -> None:
    """Notify the credential registry that a runtime group membership changed.

    AD builds the access token from the PAC inside the requesting user's TGT.
    A TGT minted before this membership change will not contain the new group
    SID, so subsequent operations using the cached ccache will be evaluated
    against an outdated token (classic ``insufficientAccessRights`` after a
    successful AddMember).  Bumping the realm-wide epoch forces every
    :class:`CredentialContext` bound to this realm to re-AS-REQ on its next
    bind.  Per-realm (rather than per-principal) invalidation is intentional:
    the principal whose PAC needs refreshing is most often **not** the user
    being added (it is the executor, who may be a transitive member of the
    target group).  Realm-wide is the conservative correct answer.
    """
    try:
        from adscan_internal.services.auth import get_credential_registry

        registry = get_credential_registry()
        registry.invalidate_domain(
            domain,
            reason=f"membership_{action}:{user_label}->{group_label}",
        )
        # Cross-domain: also bump the per-principal slot keyed by the user
        # label so a TGT whose realm differs from the membership realm (e.g.
        # user@domA added to group in domB) sees the timestamp bump too.
        registry.invalidate(
            user_label,
            domain,
            reason=f"membership_{action}_principal:{group_label}",
        )
    except Exception:  # noqa: BLE001 — never let registry failures break writes
        from adscan_internal.rich_output import print_info_debug

        print_info_debug(
            "[membership] credential registry unavailable; skipping PAC invalidation"
        )



def _normalize_runtime_membership_metadata(
    *,
    source: str,
    evidence: dict[str, Any] | None = None,
    origin_kind: str | None = None,
    origin_technique: str | None = None,
    origin_relation: str | None = None,
    cleanup_behavior: str | None = None,
    managed_by_adscan: bool = True,
) -> dict[str, Any]:
    """Return a stable provenance schema for runtime memberships."""
    evidence_dict = evidence if isinstance(evidence, dict) else {}
    source_value = str(source or "runtime").strip() or "runtime"
    normalized_origin_kind = str(
        origin_kind
        or evidence_dict.get("origin_kind")
        or ("runtime_effective" if source_value == "adcs_esc13" else "directory_write")
    ).strip()
    normalized_origin_technique = str(
        origin_technique
        or evidence_dict.get("origin_technique")
        or (
            "esc13"
            if source_value == "adcs_esc13"
            else str(evidence_dict.get("action") or "group_membership_change")
        )
    ).strip()
    normalized_origin_relation = str(
        origin_relation
        or evidence_dict.get("origin_relation")
        or ("ADCSESC13" if source_value == "adcs_esc13" else "AddMember")
    ).strip()
    normalized_cleanup_behavior = str(
        cleanup_behavior
        or evidence_dict.get("cleanup_behavior")
        or (
            "remove_runtime_only"
            if source_value == "adcs_esc13"
            else "remove_directory_and_runtime"
        )
    ).strip()
    return {
        "source": source_value,
        "managed_by_adscan": bool(managed_by_adscan),
        "origin_kind": normalized_origin_kind,
        "origin_technique": normalized_origin_technique,
        "origin_relation": normalized_origin_relation,
        "cleanup_behavior": normalized_cleanup_behavior,
        "evidence": evidence_dict,
    }



#: ``edge_type`` of the ``MemberOf`` overlay edge a runtime membership records.
RUNTIME_MEMBERSHIP_EDGE_TYPE = "runtime_membership"


def _principal_node_payload(label: str, kind: str) -> dict[str, Any]:
    """A node payload for a principal the graph does not hold yet.

    For an account ADscan created at runtime (a machine account for RBCD) whose
    node the collector never saw. Keyed the way ``upsert_nodes`` keys it, from
    the canonical ``NAME@REALM`` label.
    """
    name, _sep, realm = label.partition("@")
    properties: dict[str, Any] = {"name": label, "domain": realm}
    if kind == "Computer":
        properties["samaccountname"] = name
    elif kind == "User":
        properties["samaccountname"] = name.lower()
    return {"name": label, "label": label, "kind": [kind], "properties": properties}


def _record_runtime_memberof_edge(
    shell: object,
    domain: str,
    *,
    member_label: str,
    group_label: str,
    metadata: dict[str, Any] | None,
    member_kind: str = "User",
    group_object_id: str = "",
    remove: bool = False,
) -> bool:
    """Record a runtime membership change as a ``MemberOf`` overlay edge, then
    export so the sidecar is current for the next reader.

    ``memberships.json`` is a sidecar derived from the store (inventory
    ``MemberOf`` facts plus the overlay's ``MemberOf`` edges), so a runtime
    membership is ONLY an overlay edge (``edge_type`` ``runtime_membership``,
    the metadata under ``notes.runtime_membership``); its removal retires the
    edge this writer created. No writer reads or rewrites the file. The export
    is forced synchronously, so a follow-up step that resolves the membership
    right after an AddMember sees it (the snapshot cache invalidates on the
    file's mtime). A collected membership is never touched. Returns whether the
    change was recorded.
    """
    from adscan_core.graph_store import EdgeRef  # noqa: PLC0415
    from adscan_internal.services import graph_runtime  # noqa: PLC0415
    from adscan_internal.services.attack_graph_node_identity import (  # noqa: PLC0415
        resolve_node_candidates,
    )
    from adscan_internal.services.graph_build.overlay import find_edge  # noqa: PLC0415

    recorded = False
    try:
        with graph_runtime.write_scope(shell, origin="runtime_membership"):
            graph = graph_runtime.scoped_graph(shell, domain)
            if graph is None:
                graph = graph_runtime.live_graph(shell, domain, create=True, finalize=False)
            if not isinstance(graph, dict):
                return False
            nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
            members = resolve_node_candidates(nodes, member_label)
            groups = resolve_node_candidates(nodes, group_label)
            if groups:
                group_id = groups[0]
            elif remove:
                return False
            else:
                # The group was never collected (an ADscan-created account's
                # well-known primary group): synthesize its node so the edge
                # has an endpoint, as the old file write recorded the label.
                payload = _principal_node_payload(group_label, "Group")
                if group_object_id:
                    payload["objectId"] = group_object_id
                    payload["properties"]["objectid"] = group_object_id
                group_id = graph_runtime.record_runtime_node(
                    shell, domain, payload, origin="runtime_membership"
                )
                if not group_id:
                    print_info_debug(
                        "[membership] runtime membership not recorded: "
                        f"group={mark_sensitive(group_label, 'group')} reason=group_unresolved"
                    )
                    return False
            if members:
                member_id = members[0]
            elif remove:
                return False
            else:
                # An account ADscan created (an RBCD machine account): give it a
                # node so the edge has an endpoint, as the old file write did.
                member_id = graph_runtime.record_runtime_node(
                    shell, domain, _principal_node_payload(member_label, member_kind),
                    origin="runtime_membership",
                )
                if not member_id:
                    return False
            ref = EdgeRef(from_id=member_id, to_id=group_id, relation="MemberOf")
            existing = find_edge(graph, ref)
            if remove:
                if existing is not None and existing.get("edge_type") == RUNTIME_MEMBERSHIP_EDGE_TYPE:
                    recorded = graph_runtime.retire_runtime_edge(
                        shell, domain, ref, reason="runtime_membership_removed",
                        origin="remove_runtime_user_group_membership",
                    )
            elif existing is not None:
                recorded = False
            else:
                recorded = graph_runtime.record_runtime_edge(
                    shell, domain, ref,
                    edge_type=RUNTIME_MEMBERSHIP_EDGE_TYPE,
                    notes={"runtime_membership": dict(metadata or {})},
                    origin="add_runtime_membership",
                )
    except Exception as exc:  # noqa: BLE001 - a membership write never ends a scan
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False
    if recorded:
        # Force the export so the sidecar (and the snapshot cache's next read)
        # reflects the change for the follow-up step.
        try:
            graph_runtime.export_graph_if_due(shell, domain, force=True)
            _invalidate_membership_snapshot_cache(domain)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
    return recorded


def add_runtime_user_group_membership(
    shell: object,
    domain: str,
    *,
    username: str,
    group_name: str,
    source: str,
    evidence: dict[str, Any] | None = None,
    origin_kind: str | None = None,
    origin_technique: str | None = None,
    origin_relation: str | None = None,
    cleanup_behavior: str | None = None,
) -> bool:
    """Persist an effective runtime user-to-group membership in ``memberships.json``.

    This helper is intended for attack outcomes that create effective access for
    ADscan's graph engine without necessarily changing the LDAP ``memberOf``
    attribute, for example ESC13 PAC group authorization from a certificate.

    Args:
        shell: Shell object used to resolve the workspace path.
        domain: AD domain.
        username: User receiving effective membership.
        group_name: Group that should be considered effective for path search.
        source: Short source identifier for auditability.
        evidence: Optional structured evidence to persist.

    Returns:
        True when the snapshot was created or updated, otherwise False.
    """
    user_label = _canonical_membership_label(domain, username)
    group_label = _canonical_membership_label(domain, group_name)
    if not user_label or not group_label:
        return False

    metadata = _normalize_runtime_membership_metadata(
        source=source,
        evidence=evidence,
        origin_kind=origin_kind,
        origin_technique=origin_technique,
        origin_relation=origin_relation,
        cleanup_behavior=cleanup_behavior,
    )
    # The membership is ONLY a ``MemberOf`` overlay edge now; ``memberships.json``
    # is derived from the store and never read or rewritten here.
    recorded = _record_runtime_memberof_edge(
        shell, domain, member_label=user_label, group_label=group_label,
        metadata=metadata, member_kind="User",
    )
    if not recorded:
        return False
    _invalidate_pac_for_membership_change(
        domain=domain,
        user_label=user_label,
        group_label=group_label,
        action="add",
    )
    print_info_debug(
        "[membership] runtime membership recorded: "
        f"user={mark_sensitive(user_label, 'user')} "
        f"group={mark_sensitive(group_label, 'group')} "
        f"source={mark_sensitive(str(source), 'detail')}"
    )
    return True



def add_runtime_computer_group_membership(
    shell: object,
    domain: str,
    *,
    computer_name: str,
    group_rid: int = 515,
    group_name: str | None = None,
    source: str,
    evidence: dict[str, Any] | None = None,
    origin_kind: str | None = None,
    origin_technique: str | None = None,
    origin_relation: str | None = None,
    cleanup_behavior: str | None = None,
) -> bool:
    """Persist an effective runtime computer-to-group membership in ``memberships.json``.

    Companion to :func:`add_runtime_user_group_membership` for Computer
    principals.  Intended for ADscan-created machine accounts (e.g. RBCD
    attacker machines) that did not exist when the collector built the
    snapshot — without this injection, every subsequent attack-path render
    falls back to LDAP queries that return 0 results because computer
    primary-group memberships live in ``primaryGroupID`` (not in the
    ``member`` attribute).

    The default ``group_rid=515`` (Domain Computers) matches the SAMR
    convention for new machine accounts created via
    ``hSamrCreateUser2InDomain`` with ``USER_WORKSTATION_TRUST_ACCOUNT`` —
    Windows assigns ``primaryGroupID=515`` automatically.  When the
    snapshot already knows this group's label via ``sid_to_label`` we use
    that exact label; otherwise we fall back to the canonical synthetic
    label or the explicitly-supplied ``group_name``.

    Args:
        shell: Shell object used to resolve the workspace path.
        domain: AD domain.
        computer_name: ``sAMAccountName`` of the new machine account
            (with or without the trailing ``$`` — both are accepted).
        group_rid: Group RID to claim membership in.  Defaults to 515
            (Domain Computers).
        group_name: Optional explicit group name override.  When omitted,
            resolves from ``sid_to_label`` via ``<domain_sid>-<group_rid>``,
            falling back to ``"DOMAIN COMPUTERS"`` for RID 515.
        source: Short source identifier for auditability.
        evidence: Optional structured evidence to persist.

    Returns:
        True when the snapshot was created or updated, otherwise False.
    """
    # A machine account's membership label carries the trailing ``$`` (the
    # sAMAccountName form), whether or not the caller passed it.
    raw_name = str(computer_name or "").strip()
    if raw_name and not raw_name.endswith("$") and "@" not in raw_name and "\\" not in raw_name:
        raw_name += "$"
    computer_label = _canonical_membership_label(domain, raw_name)
    if not computer_label:
        return False

    # The group label comes from the prepared snapshot (``load_membership_snapshot``,
    # the streamed reader), never from a direct file read. Preference order:
    # 1. Explicit ``group_name`` argument.
    # 2. ``sid_to_label`` lookup for ``<domain_sid>-<group_rid>``.
    # 3. Synthetic fallback (``DOMAIN COMPUTERS`` for RID 515).
    snapshot = load_membership_snapshot(shell, domain) or {}
    resolved_group_label: str = ""
    if group_name and str(group_name).strip():
        resolved_group_label = _canonical_membership_label(domain, str(group_name))
    if not resolved_group_label:
        domain_sid = str(snapshot.get("domain_sid") or "").strip()
        if domain_sid:
            target_sid = f"{domain_sid}-{group_rid}"
            sid_to_label = snapshot.get("sid_to_label")
            if isinstance(sid_to_label, dict):
                candidate = sid_to_label.get(target_sid)
                if isinstance(candidate, str) and candidate.strip():
                    resolved_group_label = _canonical_membership_label(
                        domain, candidate
                    )
    if not resolved_group_label:
        # Per-RID synthetic fallback — only RID 515 is well-known enough to
        # synthesize blindly.  Other RIDs require the snapshot to have a real
        # label so we don't fabricate group names that may not exist.
        if group_rid == 515:
            resolved_group_label = _canonical_membership_label(
                domain, "DOMAIN COMPUTERS"
            )
        else:
            print_info_debug(
                "[membership] runtime computer membership skipped: cannot "
                f"resolve group label for RID {group_rid} in domain "
                f"{mark_sensitive(domain, 'domain')}"
            )
            return False

    metadata = _normalize_runtime_membership_metadata(
        source=source,
        evidence=evidence,
        origin_kind=origin_kind,
        origin_technique=origin_technique,
        origin_relation=origin_relation,
        cleanup_behavior=cleanup_behavior,
    )
    # A ``MemberOf`` overlay edge only; the Computer node is created when the
    # graph does not hold the account yet (an ADscan-created machine account).
    group_object_id = ""
    domain_sid = str((snapshot or {}).get("domain_sid") or "").strip()
    if domain_sid:
        group_object_id = f"{domain_sid}-{group_rid}"
    recorded = _record_runtime_memberof_edge(
        shell,
        domain,
        member_label=computer_label,
        group_label=resolved_group_label,
        metadata=metadata,
        member_kind="Computer",
        group_object_id=group_object_id,
    )
    if not recorded:
        return False
    print_info_debug(
        "[membership] runtime computer membership recorded: "
        f"computer={mark_sensitive(computer_label, 'user')} "
        f"group={mark_sensitive(resolved_group_label, 'group')} "
        f"source={mark_sensitive(str(source), 'detail')}"
    )
    return True


# ---------------------------------------------------------------------------
# Runtime AdminTo edge writer (Phase 3 of credential-metadata cleanup).
#
# When SMB Pwn3d! verifies a domain user as local admin on a host, we want
# the attack graph to reflect that effective access so the privilege-role
# picker (read side) returns the user via LOCAL_ADMIN_VERIFIED for that
# host. Domain Admins / Enterprise Admins / Built-in Administrators (and
# RID 500 / 519 principals) are explicitly skipped: they reach every
# domain-joined host implicitly via Domain Admins -> AdminTo -> All
# Computers and explicit per-host edges add graph noise without changing
# the picker outcome (those users already resolve to a higher-priority
# role via tier).
# ---------------------------------------------------------------------------


_ADMIN_RISK_REASON_SKIPS = {
    "domain_admins",
    "enterprise_admins",
    "builtin_administrators",
}
_ADMIN_RID_SKIPS = {500, 519}


def _admin_to_skip_user_via_risk(
    shell: object,
    *,
    domain: str,
    username: str,
) -> bool:
    """Return True when identity-risk reasons mark username as DA/EA/BA."""
    try:
        from adscan_internal.services.identity_risk_service import (
            get_identity_risk_record,
        )
    except Exception:  # noqa: BLE001
        return False
    try:
        record = get_identity_risk_record(
            shell, domain=domain, samaccountname=username
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False
    if not record:
        return False
    raw_reasons = (
        record.get("reasons")
        if isinstance(record, dict)
        else getattr(record, "reasons", None)
    ) or ()
    reasons = {str(r).strip().lower() for r in raw_reasons}
    return bool(reasons & _ADMIN_RISK_REASON_SKIPS)


def _admin_to_skip_user_via_rid(
    shell: object,
    *,
    domain: str,
    username: str,
) -> bool:
    """Return True when username has RID 500 or 519 in the attack graph."""
    try:
        from adscan_internal.services.high_value import (
            _find_user_node_in_attack_graph,
        )
    except Exception:  # noqa: BLE001
        return False
    try:
        node = _find_user_node_in_attack_graph(
            shell, domain=domain, samaccountname=username
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False
    if not isinstance(node, dict):
        return False
    sid = (
        node.get("objectId")
        or node.get("objectid")
        or node.get("id")
        or ""
    )
    if not sid:
        props = node.get("properties")
        if isinstance(props, dict):
            sid = (
                props.get("objectid")
                or props.get("objectId")
                or props.get("sid")
                or ""
            )
    sid = str(sid or "").strip()
    if not sid or "-" not in sid:
        return False
    try:
        rid = int(sid.rsplit("-", 1)[-1])
    except (TypeError, ValueError):
        return False
    return rid in _ADMIN_RID_SKIPS


def add_runtime_admin_to_edge(
    shell: object,
    domain: str,
    *,
    username: str,
    host_identifier: str,
    target_hostname: str | None = None,
    source: str = "smb_pwn3d_verified",
    evidence: dict[str, Any] | None = None,
) -> bool:
    """Persist an effective AdminTo edge from username to a host.

    Skipped silently when the user already has domain_admins /
    enterprise_admins / builtin_administrators via the
    identity-risk service or RID 500 / 519 in their SID — those users
    reach every domain-joined host implicitly via the
    Domain Admins -> AdminTo -> All Computers graph hierarchy and
    explicit edges add noise without changing picker decisions.

    Args:
        shell: Shell instance used to access the workspace, identity-risk
            store, and BloodHound graph service.
        domain: AD domain that owns username.
        username: User receiving effective AdminTo on the host.
        host_identifier: IP or FQDN of the target host. Resolved to a
            BloodHound Computer node by the underlying graph service.
        target_hostname: Optional hostname hint when host_identifier
            is an IP address (NetBIOS / FQDN).
        source: Short source identifier persisted on the edge notes
            ("smb_pwn3d_verified", "schtask_admin_validated", ...).
        evidence: Optional structured evidence (timestamp, NT_STATUS,
            share that was written, etc.) merged into the edge notes.

    Returns:
        True when the edge was upserted into the attack graph, False
        when the user was skipped (DA/EA/BA/RID 500/519), the host
        could not be resolved, or any internal error occurred. Never
        raises to the caller.
    """
    domain_clean = str(domain or "").strip()
    user_clean = str(username or "").strip()
    host_clean = str(host_identifier or "").strip()
    if not domain_clean or not user_clean or not host_clean:
        return False

    try:
        if _admin_to_skip_user_via_risk(
            shell, domain=domain_clean, username=user_clean
        ):
            print_info_debug(
                "[admin_to] skip: user is DA/EA/BA via identity-risk "
                f"user={mark_sensitive(user_clean, 'user')} "
                f"host={mark_sensitive(host_clean, 'hostname')}"
            )
            return False
        if _admin_to_skip_user_via_rid(
            shell, domain=domain_clean, username=user_clean
        ):
            print_info_debug(
                "[admin_to] skip: user RID is 500/519 "
                f"user={mark_sensitive(user_clean, 'user')} "
                f"host={mark_sensitive(host_clean, 'hostname')}"
            )
            return False
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        # Defensive: if the skip check fails, do not write the edge —
        # we cannot prove the user is non-DA, and a false-positive
        # explicit edge for a DA pollutes the graph.
        return False

    try:
        from adscan_internal.services.attack_graph_service import (
            upsert_netexec_privilege_edge,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False

    try:
        recorded = upsert_netexec_privilege_edge(
            shell,
            domain_clean,
            username=user_clean,
            relation="AdminTo",
            target_ip=host_clean,
            target_hostname=target_hostname,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False

    if recorded:
        evidence_marker = ""
        if isinstance(evidence, dict) and evidence:
            try:
                evidence_marker = " evidence=" + ",".join(
                    f"{k}={v}" for k, v in sorted(evidence.items())
                )
            except Exception:  # noqa: BLE001
                evidence_marker = ""
        print_info_debug(
            "[admin_to] runtime AdminTo edge persisted: "
            f"user={mark_sensitive(user_clean, 'user')} "
            f"host={mark_sensitive(host_clean, 'hostname')} "
            f"source={mark_sensitive(source, 'detail')}"
            f"{evidence_marker}"
        )
    return bool(recorded)




def remove_runtime_user_group_membership(
    shell: object,
    domain: str,
    *,
    username: str,
    group_name: str,
    source: str | None = None,
    origin_relation: str | None = None,
) -> bool:
    """Remove one runtime user-to-group membership from ``memberships.json``.

    Args:
        shell: Shell object used to resolve the workspace path.
        domain: AD domain.
        username: User losing the effective membership.
        group_name: Group that should no longer be considered effective.
        source: Optional source identifier. When set, only matching runtime
            evidence entries are removed. Group membership in ``user_to_groups``
            is removed regardless because runtime access should reflect the
            current effective state.

    Returns:
        True when the snapshot was updated, otherwise False.
    """
    user_label = _canonical_membership_label(domain, username)
    group_label = _canonical_membership_label(domain, group_name)
    if not user_label or not group_label:
        return False

    # The membership lives as a ``MemberOf`` overlay edge; retiring it (and
    # re-exporting) is the whole removal. ``memberships.json`` is derived from
    # the store and never read or rewritten here.
    recorded = _record_runtime_memberof_edge(
        shell, domain, member_label=user_label, group_label=group_label,
        metadata=None, remove=True,
    )
    if not recorded:
        return False
    _invalidate_pac_for_membership_change(
        domain=domain,
        user_label=user_label,
        group_label=group_label,
        action="remove",
    )
    print_info_debug(
        "[membership] runtime membership removed: "
        f"user={mark_sensitive(user_label, 'user')} "
        f"group={mark_sensitive(group_label, 'group')} "
        f"source={mark_sensitive(str(source or ''), 'detail')}"
    )
    return True


def _file_mentions_key(path: str, key: bytes) -> bool:
    """True when the quoted ``key`` appears anywhere in the file's bytes."""
    needle = b'"' + key + b'"'
    overlap = len(needle) - 1
    tail = b""
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1 << 20)
            if not chunk:
                return False
            if needle in tail + chunk[: len(needle)] or needle in chunk:
                return True
            tail = chunk[-overlap:]


def _read_prepared_snapshot(
    path: str, domain: str
) -> tuple[dict[str, Any] | None, list[str], Any] | None:
    """Read ``memberships.json`` into its prepared snapshot.

    Returns ``(snapshot, root_keys, generated_at)``; the snapshot is ``None``
    when the document is not a membership export. Returns ``None`` when the
    file is not a JSON object at all.

    A raw export (the collector's and the store export's) is read element by
    element (``graph_compact.iter_graph_file``) and the prepared maps are built
    directly, so neither the raw ``nodes`` nor ``edges`` are ever resident.
    Anything else keeps the whole-document path, so its snapshot is unchanged:
    a file a runtime write re-embedded the prepared maps into, an indent-4
    file from before the streamed layout the reader cannot stream, a file that
    is not parseable (``read_json_file`` quarantines it as before).
    """
    from adscan_core.graph_compact import iter_graph_file  # noqa: PLC0415

    streamed = None
    try:
        streamed = shape.prepare_membership_snapshot_from_events(
            iter_graph_file(path), domain
        )
    except ValueError:
        streamed = None
    if streamed is not None and not streamed.prepared:
        saw_nodes = streamed.saw_nodes or _file_mentions_key(path, b"nodes")
        saw_edges = streamed.saw_edges or _file_mentions_key(path, b"edges")
        snapshot = streamed.snapshot if (saw_nodes and saw_edges) else None
        return snapshot, streamed.root_keys, streamed.generated_at
    data = read_json_file(path)
    if not isinstance(data, dict):
        return None
    snapshot = attack_paths_core.prepare_membership_snapshot(data, domain)
    return snapshot, list(data.keys()), data.get("generated_at")


def load_membership_snapshot(
    shell: object,
    domain: str,
    *,
    augment_fn: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    """Load memberships.json with caching and optional augmentation."""
    domain_key = str(domain or "").strip().lower()
    if not domain_key:
        return None
    # Synthetic placeholder pseudo-domains ("wellknown") never have a
    # domains/<d>/memberships.json on disk — they are graph-structural, not
    # collected domains. Short-circuit before the file-stat + the noisy
    # "snapshot cache miss: domain=wellknown" line on every per-domain
    # resolution inside a compute. Returns None, identical to the miss path.
    from adscan_internal.services.attack_step_domain_resolution import (
        is_placeholder_domain,
    )

    if is_placeholder_domain(domain_key):
        return None
    if domain_key in _MEMBERSHIP_SNAPSHOT_CACHE:
        increment_stats(_MEMBERSHIP_SNAPSHOT_STATS, "hits")
        cached = _MEMBERSHIP_SNAPSHOT_CACHE[domain_key]
        cached_mtime = _MEMBERSHIP_SNAPSHOT_MTIME.get(domain_key)
        path = membership_snapshot_path(shell, domain)
        file_exists = os.path.exists(path)
        file_mtime = os.path.getmtime(path) if file_exists else None
        if cached is not None and not file_exists:
            print_info_debug(
                f"[membership] snapshot cache hit: domain={domain_key} value=loaded "
                f"but file missing at path={path}; invalidating cache."
            )
            _MEMBERSHIP_SNAPSHOT_CACHE.pop(domain_key, None)
            _MEMBERSHIP_SNAPSHOT_MTIME.pop(domain_key, None)
            _MEMBERSHIP_SNAPSHOT_CACHE_LOGGED.discard(domain_key)
            increment_stats(_MEMBERSHIP_SNAPSHOT_STATS, "reloads")
            return load_membership_snapshot(shell, domain, augment_fn=augment_fn)
        if cached is None and file_exists:
            print_info_debug(
                f"[membership] snapshot cache hit: domain={domain_key} value=none "
                f"but file now exists; invalidating cache (path={path})."
            )
            _MEMBERSHIP_SNAPSHOT_CACHE.pop(domain_key, None)
            _MEMBERSHIP_SNAPSHOT_MTIME.pop(domain_key, None)
            _MEMBERSHIP_SNAPSHOT_CACHE_LOGGED.discard(domain_key)
            increment_stats(_MEMBERSHIP_SNAPSHOT_STATS, "reloads")
            return load_membership_snapshot(shell, domain, augment_fn=augment_fn)
        if (
            cached is not None
            and file_mtime
            and cached_mtime
            and file_mtime != cached_mtime
        ):
            print_info_debug(
                f"[membership] snapshot cache stale for {domain_key}; file changed "
                f"(old_mtime={cached_mtime}, new_mtime={file_mtime}). Reloading."
            )
            _MEMBERSHIP_SNAPSHOT_CACHE.pop(domain_key, None)
            _MEMBERSHIP_SNAPSHOT_MTIME.pop(domain_key, None)
            _MEMBERSHIP_SNAPSHOT_CACHE_LOGGED.discard(domain_key)
            increment_stats(_MEMBERSHIP_SNAPSHOT_STATS, "reloads")
            return load_membership_snapshot(shell, domain, augment_fn=augment_fn)
        if domain_key not in _MEMBERSHIP_SNAPSHOT_CACHE_LOGGED:
            print_info_debug(
                f"[membership] snapshot cache hit: domain={domain_key} "
                f"value={'loaded' if cached else 'none'}"
            )
            _MEMBERSHIP_SNAPSHOT_CACHE_LOGGED.add(domain_key)
        if cached and not snapshot_has_sid_metadata(cached) and augment_fn:
            print_info_debug(
                f"[membership] snapshot cache missing SID metadata for {domain_key}; "
                "augmenting from attack_graph.json."
            )
            cached = augment_fn(cached)
            _MEMBERSHIP_SNAPSHOT_CACHE[domain_key] = cached
        return cached

    path = membership_snapshot_path(shell, domain)
    if not os.path.exists(path):
        increment_stats(_MEMBERSHIP_SNAPSHOT_STATS, "misses")
        print_info_debug(
            f"[membership] snapshot cache miss: domain={domain_key} "
            f"file_missing=True path={path}"
        )
        _MEMBERSHIP_SNAPSHOT_CACHE[domain_key] = None
        _MEMBERSHIP_SNAPSHOT_MTIME[domain_key] = None
        return None
    loaded = _read_prepared_snapshot(path, domain)
    if loaded is None:
        increment_stats(_MEMBERSHIP_SNAPSHOT_STATS, "misses")
        _MEMBERSHIP_SNAPSHOT_CACHE[domain_key] = None
        _MEMBERSHIP_SNAPSHOT_MTIME[domain_key] = None
        return None
    snapshot, root_keys, generated_at = loaded
    if not root_keys:
        print_info_debug(
            f"[membership] snapshot JSON is empty for {domain_key}: path={path}"
        )
    if snapshot is None:
        print_info_debug(
            f"[membership] snapshot normalization failed for {domain_key}; "
            f"raw_keys={sorted(root_keys)} path={path}"
        )
    if snapshot and not snapshot_has_sid_metadata(snapshot) and augment_fn:
        print_info_debug(
            f"[membership] snapshot missing SID metadata for {domain_key}; "
            "augmenting from attack_graph.json."
        )
        snapshot = augment_fn(snapshot)
    if snapshot:
        increment_stats(_MEMBERSHIP_SNAPSHOT_STATS, "loaded")
        domain_sid = snapshot.get("domain_sid")
        print_info_debug(
            f"[membership] snapshot loaded: domain={domain_key} path={path} "
            f"keys={sorted(snapshot.keys())} "
            f"domain_sid={mark_sensitive(domain_sid, 'sid') if domain_sid else 'unset'}"
        )
        if generated_at:
            print_info_debug(
                f"[membership] snapshot generated_at for {domain_key}: {generated_at}"
            )
        if (
            isinstance(domain_sid, str)
            and domain_sid
            and hasattr(shell, "domains_data")
            and isinstance(shell.domains_data, dict)
        ):
            domain_entry = shell.domains_data.get(domain)
            if isinstance(domain_entry, dict):
                stored_sid = domain_entry.get("domain_sid")
                if stored_sid != domain_sid:
                    domain_entry["domain_sid"] = domain_sid
                    shell.domains_data[domain] = domain_entry
                    marked_domain = mark_sensitive(domain, "domain")
                    marked_sid = mark_sensitive(domain_sid, "user")
                    print_info_debug(
                        f"[membership] persisted domain SID for {marked_domain}: {marked_sid}"
                    )
                    if hasattr(shell, "save_workspace_data"):
                        try:
                            shell.save_workspace_data()  # type: ignore[attr-defined]
                        except Exception as exc:  # noqa: BLE001
                            telemetry.capture_exception(exc)
                            print_exception(show_locals=False, exception=exc)
    _MEMBERSHIP_SNAPSHOT_CACHE[domain_key] = snapshot
    _MEMBERSHIP_SNAPSHOT_MTIME[domain_key] = os.path.getmtime(path)
    return snapshot


__all__ = [
    "add_runtime_computer_group_membership",
    "add_runtime_user_group_membership",
    "get_membership_snapshot_cache_stats",
    "load_membership_snapshot",
    "membership_snapshot_path",
    "remove_runtime_user_group_membership",
    "snapshot_has_sid_metadata",
]
