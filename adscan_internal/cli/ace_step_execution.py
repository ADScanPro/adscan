"""ACL/ACE step execution helpers.

This module centralizes the mapping between BloodHound ACL/ACE relationships
stored in ``attack_graph.json`` and the corresponding ADscan exploitation
wrappers on the shell.

It is intentionally shared by multiple interactive flows:
- executing an attack path (Phase 2, ask_for_user_privs, etc.)
- (future) direct execution from `enumerate_user_aces` without duplicating logic
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rich.prompt import Confirm, Prompt
from rich.text import Text

from adscan_internal import print_info, print_warning, telemetry
from adscan_internal.rich_output import (
    BRAND_COLORS,
    mark_sensitive,
    print_info_debug,
    print_panel,
    print_info_verbose,
    print_system_change_warning,
    strip_sensitive_markers,
)
from adscan_internal.services.attack_graph_service import (
    get_node_by_label,
    infer_directory_object_enabled_state,
    resolve_netexec_target_for_node_label,
)


def set_last_execution_outcome(shell: Any, outcome: dict[str, Any] | None) -> None:
    """Persist the last execution outcome on the shell for follow-up UX."""
    setattr(shell, "_last_ace_execution_outcome", outcome)


def _set_last_ace_execution_outcome(shell: Any, outcome: dict[str, Any] | None) -> None:
    """Backwards-compatible wrapper for ACE-specific callers."""
    set_last_execution_outcome(shell, outcome)


def get_last_execution_outcome(shell: Any) -> dict[str, Any] | None:
    """Return and clear the last execution outcome stored on the shell."""
    outcome = getattr(shell, "_last_ace_execution_outcome", None)
    if isinstance(outcome, dict):
        setattr(shell, "_last_ace_execution_outcome", None)
        return dict(outcome)
    setattr(shell, "_last_ace_execution_outcome", None)
    return None


def get_last_ace_execution_outcome(shell: Any) -> dict[str, Any] | None:
    """Backwards-compatible wrapper for ACE-specific callers."""
    return get_last_execution_outcome(shell)


def _consume_group_membership_operation_outcome(shell: Any) -> dict[str, Any]:
    """Return one temporary add-member outcome emitted by the exploit wrapper."""
    outcome = get_last_execution_outcome(shell) or {}
    if str(outcome.get("key") or "").strip().lower() != "group_membership_operation":
        return {}
    return outcome


def _normalize_account(value: str) -> str:
    name = strip_sensitive_markers(str(value or "")).strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name.strip().lower()


def _is_audit_mode(shell: Any) -> bool:
    """Return whether the current shell is running in audit mode."""
    return str(getattr(shell, "type", "") or "").strip().lower() == "audit"


def _sanitize_prompt_account(value: str) -> str:
    """Normalize an account value captured from interactive prompts."""
    return strip_sensitive_markers(str(value or "")).strip()


def _node_kind(node: dict[str, Any] | None) -> str:
    if not isinstance(node, dict):
        return "Unknown"
    kind = node.get("kind") or node.get("labels") or node.get("type")
    if isinstance(kind, list) and kind:
        return str(kind[0])
    if isinstance(kind, str) and kind:
        return kind
    return "Unknown"


def _node_props(node: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(node, dict):
        return {}
    props = node.get("properties")
    return props if isinstance(props, dict) else {}


def _infer_target_enabled(
    shell: Any,
    *,
    domain: str,
    target_kind: str,
    to_node: dict[str, Any] | None,
    to_label: str,
) -> tuple[bool | None, str]:
    """Infer whether a target is enabled using node metadata plus workspace fallbacks."""
    try:
        return infer_directory_object_enabled_state(
            shell,
            domain=domain,
            principal_name=_node_sam_or_label(to_node, to_label),
            principal_kind=target_kind,
            node=to_node,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        marked_target = mark_sensitive(
            _normalize_account(_node_sam_or_label(to_node, to_label)) or to_label,
            "user",
        )
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            "[ace-context] enabled-state fallback failed: "
            f"domain={marked_domain} target={marked_target} "
            f"reason={mark_sensitive(str(exc), 'detail')}"
        )
        return None, "fallback_error"


def _node_domain(node: dict[str, Any] | None) -> str | None:
    props = _node_props(node)
    value = props.get("domain")
    if isinstance(value, str) and value.strip():
        return value.strip().lower()
    return None


def _node_sam_or_label(node: dict[str, Any] | None, fallback: str) -> str:
    props = _node_props(node)
    sam = props.get("samaccountname")
    if isinstance(sam, str) and sam.strip():
        return sam.strip()
    label = fallback.strip()
    return label


def _node_object_sid(node: dict[str, Any] | None) -> str | None:
    """Return the node's objectSid (normalized to the ``S-1-...`` prefix) or None.

    The SID is the unambiguous identity for resolving a tombstone DN — it is
    preserved across AD Recycle Bin deletion. Mirrors the collector's node keying
    (``object_id`` == SID) and the graph-layer ``objectid``/``objectId`` keys.
    """
    if not isinstance(node, dict):
        return None
    props = _node_props(node)
    for value in (
        props.get("objectid"),
        props.get("objectId"),
        node.get("objectid"),
        node.get("objectId"),
        node.get("object_id"),
    ):
        if isinstance(value, str) and value.strip():
            sid = value.strip()
            idx = sid.upper().find("S-1-")
            if idx != -1:
                sid = sid[idx:]
            if sid.upper().startswith("S-1-"):
                return sid.upper()
    return None


def _resolve_domain_password(shell: object, domain: str, username: str) -> str | None:
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return None
    domain_data = domains_data.get(domain)
    if not isinstance(domain_data, dict):
        return None
    creds = domain_data.get("credentials")
    if not isinstance(creds, dict):
        return None
    normalized_target = _normalize_account(username)
    if not normalized_target:
        return None
    for stored_user, stored_credential in creds.items():
        if _normalize_account(str(stored_user or "")) != normalized_target:
            continue
        if not isinstance(stored_credential, str):
            return None
        candidate = stored_credential.strip()
        return candidate or None
    return None


def _pick_execution_user(
    *,
    summary: dict[str, Any],
    context_username: str | None,
    from_label: str,
    from_node: dict[str, Any] | None,
) -> str | None:
    if context_username:
        normalized = _normalize_account(context_username)
        if normalized:
            return normalized
    applies_to = summary.get("applies_to_users")
    if isinstance(applies_to, list):
        for user in applies_to:
            if isinstance(user, str) and user.strip():
                normalized = _normalize_account(user)
                if normalized:
                    return normalized
    if _node_kind(from_node).lower() == "user":
        normalized = _normalize_account(from_label)
        if normalized:
            return normalized
    return None


def _resolve_execution_user_with_source(
    shell: Any,
    *,
    domain: str,
    context_username: str | None,
    summary: dict[str, Any],
    from_label: str | None,
    from_node_kind: str | None = None,
    host: str | None = None,
    max_options: int = 20,
) -> tuple[str | None, str]:
    """Resolve an execution user and indicate which source was used.

    When ``host`` is provided (a NETWORK-authenticating step — SMB/WinRM/RDP/
    MSSQL), candidate principals the host has already denied a network logon
    (ground truth in the logon-denied cache) are sunk to the end of the list, so
    the sole-candidate auto-select and the default prompt index prefer a
    logon-capable principal while never emptying the candidate set. ``host=None``
    (TGT/AS-REQ/scoped-ticket callers, or callers without a host in scope) leaves
    ordering unchanged — the denial is network-logon-specific and must not gate
    those flows.
    """

    def _preview_users(users: list[str], *, max_items: int = 5) -> str:
        """Return a compact debug preview of candidate usernames."""
        cleaned = [str(user).strip() for user in users if str(user).strip()]
        if not cleaned:
            return "[]"
        preview = cleaned[:max_items]
        rendered = ", ".join(mark_sensitive(user, "user") for user in preview)
        if len(cleaned) > max_items:
            rendered = f"{rendered}, +{len(cleaned) - max_items} more"
        return f"[{rendered}]"

    exec_username = _normalize_account(context_username or "")
    if exec_username:
        print_info_debug(
            f"[exec-user] Using context username: {mark_sensitive(exec_username, 'user')}"
        )
        return exec_username, "context_username"

    creds = getattr(shell, "domains_data", {}).get(domain, {}).get("credentials", {})
    cred_keys = (
        {
            _normalize_account(str(stored_user or "")): str(stored_user)
            for stored_user in creds.keys()
        }
        if isinstance(creds, dict)
        else {}
    )
    from_user = _normalize_account(from_label or "")
    if from_user and from_user in cred_keys:
        print_info_debug(
            f"[exec-user] Using from_label credential: {mark_sensitive(from_user, 'user')}"
        )
        return from_user, "from_label_credential"
    if from_user and str(from_node_kind or "").strip().lower() == "user":
        print_info_debug(
            "[exec-user] Using from_label as execution user candidate without "
            "stored credential match."
        )
        return from_user, "from_label_user_node"

    meta = summary.get("meta") if isinstance(summary.get("meta"), dict) else {}
    affected_users = meta.get("affected_users") if isinstance(meta, dict) else None
    if isinstance(meta, dict):
        affected_count = meta.get("affected_user_count")
        affected_users_len = (
            len(affected_users) if isinstance(affected_users, list) else None
        )
        affected_preview = (
            _preview_users(
                [str(user) for user in affected_users if isinstance(user, str)]
            )
            if isinstance(affected_users, list)
            else "[]"
        )
        print_info_debug(
            "[exec-user] meta.affected_users summary: "
            f"count={affected_count!r}, list_len={affected_users_len!r}, "
            f"users={affected_preview}"
        )
    else:
        print_info_debug("[exec-user] No meta object available on path summary.")
    if not (isinstance(affected_users, list) and affected_users) and isinstance(
        meta, dict
    ):
        print_info_debug("[exec-user] meta.affected_users missing/empty.")

    node_kind_lower = str(from_node_kind or "").strip().lower()
    candidate_users: list[str] = []

    # For Group from_label, membership is the SOURCE OF TRUTH for who can
    # execute the step.  The graph collector writes the edge from the
    # group that ACTUALLY holds the right (e.g. DCSync edges originate
    # from ``DOMAIN ADMINS`` / ``DOMAIN CONTROLLERS`` / ``ADMINISTRATORS``
    # — the groups granted ``DS-Replication-Get-Changes-All``).  Therefore:
    #
    #   - We MUST prefer real group members over ``affected_users``: the
    #     path source (``affected_users``) may reach ``from_label`` via a
    #     MemberOf chain without being a direct member that holds the
    #     right.  Picking the source as the execution principal then
    #     fails with ``ERROR_DS_DRA_BAD_DN`` (or equivalent) because the
    #     principal lacks the underlying ACE.
    #
    #   - Membership lookup intersected with stored credentials is the
    #     implicit *privilege guard* for high-rights relations.  No
    #     separate per-relation table is needed: the collector already
    #     encoded the privilege requirement in the group choice.
    #
    #   - This is also what makes the multi-step carry-forward work
    #     naturally: when step N produces a credential that is a real
    #     member of step N+1's ``from_label`` group (e.g. ADCSESC8
    #     producing a DC machine account that belongs to
    #     ``DOMAIN CONTROLLERS``), step N+1 picks it without needing
    #     ``affected_users`` to be re-materialised mid-execution.
    group_members_resolved = False
    if node_kind_lower == "group" and isinstance(creds, dict) and creds:
        try:
            from adscan_internal.services.attack_paths_core import (
                build_group_member_index,
            )
            from adscan_internal.services.membership_snapshot import (
                load_membership_snapshot,
            )

            snapshot = load_membership_snapshot(shell, domain)
            user_members, computer_members, _has_principals = (
                build_group_member_index(
                    snapshot,
                    domain,
                    exclude_tier0=False,
                    include_computers=True,
                )
            )
            from_label_norm = (str(from_label or "").strip()).upper()
            member_labels: set[str] = set()
            member_labels.update(user_members.get(from_label_norm, set()) or set())
            member_labels.update(
                computer_members.get(from_label_norm, set()) or set()
            )

            def _member_label_to_sam(label: str) -> str:
                """Strip the ``@DOMAIN`` suffix and lowercase the SAM."""
                raw = str(label or "").strip()
                if not raw:
                    return ""
                left = raw.split("@", 1)[0]
                return left.strip().lower()

            matched_via_membership: list[str] = []
            for label in member_labels:
                sam = _member_label_to_sam(label)
                if not sam:
                    continue
                stored_key = cred_keys.get(sam)
                if stored_key:
                    matched_via_membership.append(stored_key)

            if matched_via_membership:
                candidate_users = matched_via_membership
                group_members_resolved = True
                print_info_debug(
                    "[exec-user] Group-membership resolution: selected "
                    f"{len(candidate_users)} candidate(s) for "
                    f"from_label={mark_sensitive(str(from_label or ''), 'node')}: "
                    f"{_preview_users(candidate_users)}"
                )
            else:
                print_info_debug(
                    "[exec-user] Group-membership resolution: no stored "
                    "credential matches any actual member of "
                    f"group={mark_sensitive(str(from_label or ''), 'node')} "
                    f"(members={len(member_labels)}); "
                    "falling back to affected_users intersection."
                )
        except Exception as _exc:  # noqa: BLE001
            telemetry.capture_exception(_exc)
            print_info_debug(
                f"[exec-user] Group-membership resolution failed: {type(_exc).__name__}; "
                "falling back to affected_users intersection."
            )

    # ``affected_users`` intersection: used for non-Group from_label, or
    # as best-effort fallback when Group membership resolution turned up
    # no match (snapshot missing, exotic group, etc.).
    if not candidate_users and isinstance(affected_users, list) and cred_keys:
        for raw_user in affected_users:
            if not isinstance(raw_user, str):
                continue
            normalized = _normalize_account(raw_user)
            if not normalized:
                continue
            stored_key = cred_keys.get(normalized)
            if stored_key:
                candidate_users.append(stored_key)

    if (
        not candidate_users
        and isinstance(creds, dict)
        and creds
        and node_kind_lower != "group"
    ):
        print_info_debug(
            "[exec-user] No meta.affected_users match; falling back to all stored credentials "
            f"(from_node_kind={mark_sensitive(node_kind_lower or 'unknown', 'detail')})."
        )
        candidate_users = [str(stored_user) for stored_user in creds.keys()]
    elif (
        not candidate_users
        and node_kind_lower == "group"
        and not group_members_resolved
    ):
        # Group from_label AND membership lookup failed AND
        # affected_users intersection also empty.  Without authoritative
        # membership data we can't safely fall back to "any stored cred"
        # (would invent privilege the principal doesn't hold).
        print_info_debug(
            "[exec-user] Group from_label with no candidate match: "
            "membership snapshot unavailable and affected_users intersection empty. "
            "Skipping fallback to avoid selecting a non-member principal."
        )

    if candidate_users:
        candidate_users = list(dict.fromkeys(candidate_users))
        if host:
            # Network-auth step: prefer a logon-capable principal (denied ones
            # sink to the tail, retained as last resort). Single source.
            from adscan_internal.services.credential_store_service import (  # noqa: PLC0415
                order_logon_capable_first,
            )

            candidate_users = order_logon_capable_first(
                getattr(shell, "domains_data", {}) or {},
                domain,
                host=host,
                candidates=candidate_users,
            )
        stored_credential_preview = (
            _preview_users([str(stored_user) for stored_user in creds.keys()])
            if isinstance(creds, dict)
            else "[]"
        )
        print_info_debug(
            "[exec-user] Found "
            f"{len(candidate_users)} candidate user(s) with stored credentials. "
            f"candidates={_preview_users(candidate_users)} "
            f"stored_credentials={stored_credential_preview}"
        )

        # Auto-select without a prompt when there is only one candidate;
        # showing a panel + questionary for a decision that doesn't exist is
        # noise that repeats for every step in a multi-step path.
        if len(candidate_users) == 1:
            print_info_debug(
                f"[exec-user] Auto-selected sole candidate: {mark_sensitive(candidate_users[0], 'user')}"
            )
            return _normalize_account(candidate_users[0]), "affected_users"

        marked_domain = mark_sensitive(domain, "domain")
        print_panel(
            "\n".join(
                [
                    f"Domain: {marked_domain}",
                    f"Users with stored credentials: {len(candidate_users)}",
                ]
            ),
            title=Text("Select Execution User", style=f"bold {BRAND_COLORS['info']}"),
            border_style=BRAND_COLORS["info"],
            expand=False,
        )

        if hasattr(shell, "_questionary_select"):
            options = [
                mark_sensitive(user, "user") for user in candidate_users[:max_options]
            ]
            if len(candidate_users) > max_options:
                options.append(
                    f"Enter username (showing {max_options} of {len(candidate_users)})"
                )
            options.append("Cancel")
            idx = shell._questionary_select(
                "Select a user to execute this step:",
                options,
                default_idx=0,
            )
            if idx is None or idx >= len(options) - 1:
                print_info_debug("[exec-user] User selection cancelled.")
                return None, "cancelled"
            if len(candidate_users) > max_options and idx == len(options) - 2:
                manual_user = Prompt.ask("Enter username")
                if not manual_user:
                    print_info_debug("[exec-user] Manual username entry empty.")
                    return None, "manual_empty"
                normalized = _normalize_account(manual_user)
                if not normalized:
                    print_info_debug("[exec-user] Manual username entry invalid.")
                    print_warning("Invalid username entered.")
                    return None, "manual_invalid"
                stored = cred_keys.get(normalized)
                if not stored:
                    marked_user = mark_sensitive(normalized, "user")
                    print_warning(
                        f"No stored credential found for {marked_user}. "
                        "Please select a user with saved credentials."
                    )
                    print_info_debug(
                        f"[exec-user] Manual username not in credentials: {marked_user}"
                    )
                    return None, "manual_missing_credential"
                print_info_debug(
                    f"[exec-user] Manual username matched credentials: {mark_sensitive(stored, 'user')}"
                )
                return _normalize_account(stored), "manual_selection"
            print_info_debug(
                f"[exec-user] Selected candidate: {mark_sensitive(candidate_users[idx], 'user')}"
            )
            return _normalize_account(
                str(candidate_users[idx])
            ), "interactive_selection"

        return _normalize_account(candidate_users[0]), "fallback_stored_credential"

    print_info_debug(
        "[exec-user] No execution user resolved: "
        f"from_label={from_label!r}, "
        f"meta.affected_users_len={len(affected_users) if isinstance(affected_users, list) else None!r}"
    )
    return None, "unresolved"


def resolve_execution_user(
    shell: Any,
    *,
    domain: str,
    context_username: str | None,
    summary: dict[str, Any],
    from_label: str | None,
    from_node_kind: str | None = None,
    host: str | None = None,
    max_options: int = 20,
) -> str | None:
    """Resolve an execution user for attack steps that require credentials.

    Pass ``host`` for a NETWORK-authenticating step so principals already denied
    a network logon on that host are deprioritized (see
    :func:`_resolve_execution_user_with_source`). Omit it for TGT/AS-REQ/
    scoped-ticket flows.
    """
    exec_username, _ = _resolve_execution_user_with_source(
        shell,
        domain=domain,
        context_username=context_username,
        summary=summary,
        from_label=from_label,
        from_node_kind=from_node_kind,
        host=host,
        max_options=max_options,
    )
    return exec_username


def resolve_exec_password(
    shell: Any,
    *,
    domain: str,
    username: str,
    context_username: str | None,
    context_password: str | None,
) -> str | None:
    """Resolve a password/hash for ``username`` without mismatching context creds."""
    normalized_user = _normalize_account(username)
    if not normalized_user:
        return None
    normalized_context_user = _normalize_account(context_username or "")
    if (
        context_password
        and normalized_context_user
        and normalized_user == normalized_context_user
    ):
        return context_password
    return _resolve_domain_password(shell, domain, normalized_user)


@dataclass(frozen=True, slots=True)
class AceStepContext:
    domain: str
    relation: str
    from_label: str
    to_label: str
    exec_username: str
    exec_password: str
    target_domain: str
    target_kind: str
    target_enabled: bool | None
    target_sam_or_label: str
    # RBCD chain coordination: when an AddMember/write-to-group step feeds a
    # downstream AllowedToAct whose trustee is this group, the member to add must
    # be an owned SPN-bearing account (the one the AllowedToAct will mint as) —
    # resolved once via the shared helper so both steps agree. None = default
    # behaviour (no downstream RBCD coordination).
    member_to_add: str | None = None
    # Tombstoned (AD Recycle Bin) target: the object is deleted and must be
    # reanimated before the ACE technique runs — mirrors target_enabled→enable-first.
    # target_enabled is derived from the tombstone's PRESERVED userAccountControl, so
    # the existing enable-first check then handles a restored-but-disabled account.
    target_tombstoned: bool = False
    target_deleted_dn: str | None = None
    # objectSid of the target — preserved across AD Recycle Bin deletion, so it is
    # the unambiguous key for resolving the real tombstone DN when target_deleted_dn
    # is absent (cached/merged graph node). msDS-LastKnownRDN is the clean RDN.
    target_sid: str | None = None
    target_last_known_rdn: str | None = None


ACL_ACE_RELATIONS: set[str] = {
    "genericall",
    "genericwrite",
    "writeaccountrestrictions",
    "forcechangepassword",
    "addself",
    "addmember",
    "readgmsapassword",
    "readlapspassword",
    "writedacl",
    "writeowner",
    "owns",
    "writespn",
    "dcsync",
}


def describe_ace_relation_support(
    relation: str,
    target_kind: str,
) -> tuple[bool, str | None]:
    """Return whether an ACE relation is supported for a target object type.

    This is used to prevent "false supported" cases where the relationship
    exists in BloodHound (and the action name is mapped), but ADscan does not
    implement an exploitation path for the specific target object type.

    Args:
        relation: ACE/ACL relation to evaluate.
        target_kind: Target object type.

    Returns:
        Tuple of (supported, reason). If supported is True, reason is None.
    """
    relation = relation.strip().lower()
    target_kind = target_kind.strip()
    target_kind_norm = target_kind.lower()

    if relation == "genericall":
        # GenericAll implies WriteDACL + WriteOwner, so on a Domain head it can
        # be exploited through the DCSync-via-DACL pipeline (add DS-Replication
        # ACEs, then DCSync). On other supported objects it routes to the
        # standard control-object handlers.
        if target_kind_norm in {"user", "computer", "ou", "group", "domain"}:
            return True, None
        return (
            False,
            f"GenericAll exploitation is not implemented for target type {target_kind}.",
        )

    if relation == "genericwrite":
        # GenericWrite allows property writes but NOT DACL modification, so it
        # cannot be turned into DCSync on a Domain head. Keep it scoped to
        # objects where a property-write primitive yields takeover.
        if target_kind_norm in {"user", "computer", "ou", "group"}:
            return True, None
        if target_kind_norm == "domain":
            return (
                False,
                (
                    "GenericWrite on a Domain object does not grant DACL modification, "
                    "so DCSync is not reachable through this edge."
                ),
            )
        return (
            False,
            f"GenericWrite exploitation is not implemented for target type {target_kind}.",
        )

    if relation == "owns":
        if target_kind_norm in {"user", "computer", "ou", "group", "domain"}:
            return True, None
        return (
            False,
            f"Owns exploitation is not implemented for target type {target_kind}.",
        )

    if relation == "writeaccountrestrictions":
        if target_kind_norm == "computer":
            return True, None
        return (
            False,
            f"WriteAccountRestrictions exploitation is only implemented for Computer targets (got {target_kind}).",
        )

    if relation == "writeowner":
        if target_kind_norm in {"user", "group"}:
            return True, None
        return (
            False,
            f"WriteOwner exploitation is only implemented for User/Group targets (got {target_kind}).",
        )

    if relation == "writespn":
        if target_kind_norm in {"user", "computer"}:
            return True, None
        return (
            False,
            f"WriteSPN exploitation is only implemented for User/Computer targets (got {target_kind}).",
        )

    # Default: assume supported (the executor may still fail at runtime).
    return True, None


def describe_ace_step_support(context: AceStepContext) -> tuple[bool, str | None]:
    """Return whether an ACE step is supported for the given context."""
    return describe_ace_relation_support(
        context.relation,
        context.target_kind,
    )


def build_ace_step_context(
    shell: Any,
    domain: str,
    *,
    relation: str,
    summary: dict[str, Any],
    from_label: str,
    to_label: str,
    context_username: str | None,
    context_password: str | None,
    member_to_add: str | None = None,
) -> AceStepContext | None:
    """Build an ACE execution context for a given step (best-effort).

    ``member_to_add`` (RBCD coordination) overrides the group-membership default
    when a downstream AllowedToAct needs a specific owned SPN-bearing member.
    """
    from_node = get_node_by_label(shell, domain, label=from_label)
    to_node = get_node_by_label(shell, domain, label=to_label)
    exec_username, exec_user_source = _resolve_execution_user_with_source(
        shell,
        domain=domain,
        context_username=context_username,
        summary=summary,
        from_label=from_label,
        from_node_kind=_node_kind(from_node),
    )
    if not exec_username:
        marked_domain = mark_sensitive(domain, "domain")
        marked_from = mark_sensitive(from_label, "node")
        marked_to = mark_sensitive(to_label, "node")
        print_info_debug(
            "[ace-context] Missing exec username: "
            f"relation={mark_sensitive(relation, 'detail')} domain={marked_domain} "
            f"from={marked_from} to={marked_to} "
            f"context_username={'set' if context_username else 'unset'} "
            f"applies_to_users={summary.get('applies_to_users')!r} "
            f"from_node_kind={mark_sensitive(_node_kind(from_node), 'detail')} "
            f"resolution_source={mark_sensitive(exec_user_source, 'detail')}"
        )
        return None

    stored_password = _resolve_domain_password(shell, domain, exec_username)
    password = resolve_exec_password(
        shell,
        domain=domain,
        username=exec_username,
        context_username=context_username,
        context_password=context_password,
    )
    if not password:
        marked_domain = mark_sensitive(domain, "domain")
        marked_from = mark_sensitive(from_label, "node")
        marked_to = mark_sensitive(to_label, "node")
        marked_user = mark_sensitive(exec_username, "user")
        print_info_debug(
            "[ace-context] Missing exec credential: "
            f"relation={mark_sensitive(relation, 'detail')} domain={marked_domain} "
            f"from={marked_from} to={marked_to} exec_user={marked_user} "
            f"context_password={'set' if context_password else 'unset'} "
            f"stored_domain_credential={'present' if stored_password else 'absent'} "
            f"resolution_source={mark_sensitive(exec_user_source, 'detail')}"
        )
        return None

    target_domain = _node_domain(to_node) or domain
    target_kind = _node_kind(to_node)
    target_enabled, target_enabled_source = _infer_target_enabled(
        shell,
        domain=target_domain,
        target_kind=target_kind,
        to_node=to_node,
        to_label=to_label,
    )
    target_sam_or_label = _node_sam_or_label(to_node, to_label)
    _target_props = _node_props(to_node)
    target_tombstoned = bool(_target_props.get("tombstoned"))
    target_deleted_dn = (
        str(_target_props.get("deleted_dn") or "").strip() or None
        if target_tombstoned
        else None
    )
    target_sid = _node_object_sid(to_node)
    target_last_known_rdn = (
        str(_target_props.get("last_known_rdn") or "").strip() or None
    )
    marked_domain = mark_sensitive(domain, "domain")
    marked_from = mark_sensitive(from_label, "node")
    marked_to = mark_sensitive(to_label, "node")
    marked_user = mark_sensitive(exec_username, "user")
    credential_source = (
        "context_password" if context_password else "stored_domain_credential"
    )
    print_info_debug(
        "[ace-context] Built execution context: "
        f"relation={mark_sensitive(relation, 'detail')} domain={marked_domain} "
        f"from={marked_from} to={marked_to} exec_user={marked_user} "
        f"credential_source={mark_sensitive(credential_source, 'detail')} "
        f"user_source={mark_sensitive(exec_user_source, 'detail')} "
        f"target_kind={mark_sensitive(target_kind, 'detail')} "
        f"target_domain={mark_sensitive(target_domain, 'domain')} "
        f"target_enabled={mark_sensitive(str(target_enabled), 'detail')} "
        f"target_enabled_source={mark_sensitive(target_enabled_source, 'detail')}"
    )

    return AceStepContext(
        domain=domain,
        relation=relation,
        from_label=from_label,
        to_label=to_label,
        exec_username=exec_username,
        exec_password=password,
        target_domain=target_domain,
        target_kind=target_kind,
        target_enabled=target_enabled,
        target_sam_or_label=target_sam_or_label,
        member_to_add=member_to_add,
        target_tombstoned=target_tombstoned,
        target_deleted_dn=target_deleted_dn,
        target_sid=target_sid,
        target_last_known_rdn=target_last_known_rdn,
    )


def _acl_cleanup_register(
    shell: Any,
    context: AceStepContext,
    *,
    kind: str,
    detail: dict[str, Any] | None = None,
) -> None:
    """Register an ACL/attribute change with the ledger and acl_cleanup_actions.

    No-op when neither environment_change_ledger nor acl_cleanup_actions is
    present on the shell; backward compatible with test stubs and lite builds.
    """
    ledger = getattr(shell, "environment_change_ledger", None)
    actions = getattr(shell, "acl_cleanup_actions", None)
    if ledger is None and actions is None:
        return

    change_id: str | None = None
    if ledger is not None:
        try:
            ledger_detail = {
                "target_domain": context.target_domain,
                "target_object": context.target_sam_or_label,
                "exec_username": context.exec_username,
                "executor_username": context.exec_username,
                "executor_auth_domain": context.domain,
                "credential_lookup_domain": context.domain,
            }
            if detail:
                ledger_detail.update(detail)
            change_id = ledger.register_change(
                kind=kind,
                domain=context.domain,
                target=context.target_sam_or_label,
                detail=ledger_detail,
                method=(
                    f"BloodHound ACE - {context.relation}"
                    f" ({context.from_label} → {context.to_label})"
                ),
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)

    if actions is not None:
        action: dict[str, Any] = {
            "kind": kind,
            "domain": context.domain,
            "target_domain": context.target_domain,
            "target": context.target_sam_or_label,
            "exec_username": context.exec_username,
            "exec_password": context.exec_password,
            "_ledger_change_id": change_id,
        }
        if detail:
            action.update(detail)
        try:
            actions.append(action)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)


def _capture_original_owner(shell: Any, context: AceStepContext) -> str | None:
    """Query BloodyAD for the current owner SID of the target object before WriteOwner.

    Returns the SID string (e.g. 'S-1-5-21-...') if parseable, else None.
    None causes cleanup to fall back to operator_required with PS instructions.
    """
    import re

    from adscan_internal.services.exploitation import ExploitationService

    try:
        domains_data = getattr(shell, "domains_data", {}) or {}
        target_domain_data = (
            domains_data.get(context.target_domain) or {}
            if isinstance(domains_data, dict)
            else {}
        )
        pdc_ip = str(target_domain_data.get("pdc") or "").strip() or None
        pdc_hostname = str(target_domain_data.get("pdc_hostname") or "").strip() or None
        pdc_host = pdc_hostname or pdc_ip
        if not pdc_host:
            return None

        service = ExploitationService()
        attr_result = service.acl.get_object_attributes(
            pdc_host=pdc_host,
            domain=context.domain,
            username=context.exec_username,
            password=context.exec_password,
            target_object=context.target_sam_or_label,
            attribute_names=("nTSecurityDescriptor",),
            kerberos=True,
            timeout=30,
        )
        if not attr_result.success:
            return None

        raw = str(attr_result.raw_output or "")
        sid_match = re.search(r"(S-1-\d+-\d+(?:-\d+)+)", raw)
        if sid_match:
            return sid_match.group(1)
        return None
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return None


def _execute_genericall_domain_dcsync(
    shell: Any,
    context: AceStepContext,
) -> bool:
    """Exploit GenericAll on a Domain head as WriteDACL → DCSync.

    GenericAll implies WriteDACL, so the canonical exploitation against a
    Domain object is to grant DS-Replication-Get-Changes / -All ACEs to the
    executing principal (DACL mutation) and then trigger DCSync. Both stages
    are run from this single handler so the attack-path step that ends at the
    Domain head reaches Domain Compromise without requiring the operator to
    chain a separate WriteDACL edge.

    The handler reuses the existing primitives (`exploit_write_dacl` for the
    DACL grant, `dcsync` for replication) - no new exploitation logic lives
    here, only orchestration and UX.
    """
    marked_target = mark_sensitive(context.target_sam_or_label, "domain")
    marked_user = mark_sensitive(context.exec_username, "user")
    print_system_change_warning(
        title="[bold yellow]Tier-0 Operation: GenericAll on Domain (WriteDACL + DCSync)[/bold yellow]",
        summary=(
            f"Technique: GenericAll on Domain head ({marked_target})\n"
            f"Execution user: {marked_user}"
        ),
        planned_changes=[
            "Grant DS-Replication-Get-Changes and DS-Replication-Get-Changes-All ACEs"
            " on the domain head via native LDAP DACL mutation.",
            "Trigger DCSync to extract domain credential material (krbtgt, DA accounts).",
        ],
        impact_notes=[
            "DACL mutation is logged by domain controllers and by EDR products monitoring"
            " replication ACE grants.",
            "DCSync traffic is visible to SIEM rules monitoring DRSUAPI GetNCChanges calls.",
            "Added replication ACEs will be removed on session teardown via the environment"
            " change ledger.",
        ],
        cleanup_notes=[
            "Added DS-Replication ACEs are tracked and removed automatically.",
            "Verify cleanup completed in the environment change ledger before ending the engagement.",
        ],
        authorization_note=(
            "This reaches Domain Compromise. Only continue if you are authorized"
            " to fully compromise this domain."
        ),
    )
    if not Confirm.ask(
        "Proceed with WriteDACL + DCSync execution?",
        default=False,
    ):
        print_warning("GenericAll on Domain execution cancelled by operator.")
        return False

    grant_ok = shell.exploit_write_dacl(
        context.domain,
        context.exec_username,
        context.exec_password,
        context.target_sam_or_label,
        context.target_domain,
        "domain",
        followup_after=False,
    )
    if not grant_ok:
        print_warning(
            "Failed to grant DCSync rights via DACL mutation; aborting DCSync stage."
        )
        return False

    exec_sid = getattr(shell, "_last_exec_sid", context.exec_username)
    _acl_cleanup_register(
        shell,
        context,
        kind="dacl_ace_added",
        detail={
            "trustee": exec_sid or context.exec_username,
            "rights_type": "dcsync",
        },
    )

    print_info(
        f"[{BRAND_COLORS['success']}]DCSync rights granted.[/{BRAND_COLORS['success']}]"
        " Triggering domain replication..."
    )
    return bool(
        shell.dcsync(
            context.domain,
            context.exec_username,
            context.exec_password,
            context.target_domain,
        )
    )


def execute_ace_step(shell: Any, *, context: AceStepContext) -> bool | None:
    """Execute an ACL/ACE relationship step using the best available primitive.

    Note:
        Most underlying exploit routines are interactive and do not return a
        simple True/False. The higher-level caller should set the active-step
        context and update the edge status to "attempted" before invoking this.
        Any downstream credential additions will typically mark the step as
        success via the active-step mechanism.
    """
    relation = context.relation.strip().lower()
    set_last_execution_outcome(shell, None)
    if relation not in ACL_ACE_RELATIONS:
        return None

    marked_to = mark_sensitive(context.to_label, "node")

    target_kind = context.target_kind.strip().lower()

    if relation == "dcsync":
        # GAP 3 — scoped-ticket-first: if a prior step (SPNJack, relay-RBCD)
        # minted an LDAP-service ticket scoped to the DC host (impersonating a
        # privileged user), DRSUAPI replication should run via that ccache rather
        # than the generic, under-privileged execution credential. Mirrors the
        # DumpLSA cifs-scoped-ticket path. Alias-aware host match guarantees a
        # ticket for a different host is never used here.
        dcsync_username = context.exec_username
        dcsync_password = context.exec_password
        try:
            from adscan_internal.models.domain import resolve_dc_fqdn  # noqa: PLC0415
            from adscan_internal.services.credential_store_service import (  # noqa: PLC0415
                resolve_execution_credential,
            )

            _domain_data = getattr(shell, "domains_data", {}).get(context.domain, {})
            # Resolve the DC via the FQDN SSOT (CLAUDE.md "Kerberos SPNs — always
            # FQDN"). The old ``dc_fqdn -> pdc_hostname_fqdn -> resolve_dc_ip``
            # chain skipped the short ``pdc_hostname`` rung and returned a raw IP
            # in best-effort mode, which cannot serve a ``cifs`` service ticket
            # (SEC_E_LOGON_DENIED). ``resolve_dc_fqdn`` promotes a short hostname
            # to ``<host>.<domain>`` and adds the workspace inventory fallback, so
            # the scoped-ticket lookup below keys on a real FQDN, never an IP.
            _dc_host = resolve_dc_fqdn(_domain_data, target_domain=context.domain) or ""
            if _dc_host:
                # relation="dcsync" -> cifs (DRSUAPI replicates over an aiosmb SMB
                # connection, NOT ldap). The central map owns the service class so
                # the right ticket is selected by construction; preferent matching
                # falls back to any ticket for the DC (a TGT-bearing ccache serves
                # cifs regardless of its own SPN class).
                _scoped = resolve_execution_credential(
                    shell, domain=context.domain, host=_dc_host, relation="dcsync"
                )
                if _scoped is not None:
                    dcsync_username, dcsync_password = _scoped
                    print_info_debug(
                        "ace dcsync: reusing host-scoped service ticket for "
                        f"{mark_sensitive(str(_dc_host), 'hostname')} as "
                        f"{mark_sensitive(dcsync_username, 'user')}"
                    )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)

        result = shell.dcsync(context.domain, dcsync_username, dcsync_password)
        # Edge semantics: DCSync → Domain means "compromise the domain by
        # replicating its secrets". Success requires either the krbtgt
        # secret (full domain compromise via Golden Ticket material) or at
        # least one Tier-0 account (Administrator RID 500, Domain/Schema/
        # Enterprise Admins). Extracting only standard accounts means the
        # replication ran but did not deliver what this edge promises, so
        # the edge is marked failed. ``None`` signals an aborted run
        # (missing context, transport failure) - also failed.
        if not isinstance(result, dict):
            return False
        if result.get("krbtgt") or int(result.get("tier0_count", 0)) >= 1:
            return True
        return False

    if relation == "readgmsapassword":
        from_domain = (
            context.from_label.rsplit("@", 1)[-1].strip().lower()
            if "@" in context.from_label
            else context.domain
        )

        # Pre-execution structural warning: if the source group is in a different
        # domain than the target gMSA, this edge may be blocked at runtime.
        # Domain Local groups (GROUP_TYPE_RESOURCE_GROUP | SECURITY_ENABLED = -2147483644)
        # are resource-domain scoped; membership via ForeignSecurityPrincipal in DomainB
        # does NOT grant effective read rights on a gMSA object stored in DomainA.
        # The graph edge is present because the group SID appears in msDS-GroupMSAMembership
        # on the gMSA, but that SID resolves to a Domain Local group in a different domain.
        if (
            from_domain
            and context.target_domain
            and from_domain != context.target_domain.lower()
        ):
            print_warning(
                f"[dim]Pre-execution check:[/dim] the ReadGMSAPassword source "
                f"({mark_sensitive(context.from_label, 'node')}) is in [bold]{from_domain}[/bold] "
                f"but the gMSA is in [bold]{context.target_domain}[/bold]. "
                "If the source group is Domain Local, this edge is structurally not effective - "
                "the SID appears in msDS-GroupMSAMembership but Domain Local scope does not "
                "grant cross-domain gMSA read rights. The attempt will proceed, "
                "but expect <no read permissions>."
            )

        return shell.exploit_gmsa_account(
            context.domain,
            context.exec_username,
            context.exec_password,
            context.target_sam_or_label,
            context.target_domain,
            prompt_for_user_privs_after=False,
            group_domain=from_domain,
        )

    if relation == "readlapspassword":
        # LAPS helper expects a host identifier (prefer FQDN).
        target_host = resolve_netexec_target_for_node_label(
            shell, context.domain, node_label=context.to_label
        )
        if not target_host:
            base = context.target_sam_or_label.rstrip("$")
            target_host = f"{base}.{context.target_domain}".lower()
            marked_target = mark_sensitive(target_host, "hostname")
            print_info_verbose(
                f"Resolved LAPS target via fallback (samAccountName -> FQDN): {marked_target}"
            )
        return shell.exploit_laps_password(
            context.domain,
            context.exec_username,
            context.exec_password,
            target_host,
            context.target_domain,
            prompt_for_user_privs_after=False,
        )

    if relation == "forcechangepassword":
        marked_from = mark_sensitive(context.exec_username, "user")
        audit_context = (
            " This is particularly disruptive in audit mode." if _is_audit_mode(shell) else ""
        )
        print_system_change_warning(
            title="[bold yellow]Disruptive Operation: ForceChangePassword[/bold yellow]",
            summary=(
                f"Execution user: {marked_from}\nTarget user: {marked_to}"
                f"{audit_context}"
            ),
            planned_changes=[
                "Reset the target user's domain password immediately.",
                "Store the new credential in ADscan for follow-up path execution.",
            ],
            impact_notes=[
                "This invalidates the target user's current password immediately.",
                "Active sessions and services using this account will lose access.",
                "Password reset is irreversible: the original password cannot be recovered.",
            ],
            cleanup_notes=[
                "Coordinate with the client to reset the password to a known value after the engagement.",
            ],
            authorization_note=(
                "Only continue if you are explicitly authorized to reset this credential during the engagement."
            ),
        )
        # CTF workspaces: password changes are acceptable — the DC is owned by
        # the operator. Skip the confirmation gate to keep the CTF flow fast.
        # Audit workspaces always require explicit consent because the original
        # password is lost permanently and needs client coordination.
        _is_ctf = str(getattr(shell, "type", "") or "").lower() == "ctf"
        if not _is_ctf and not Confirm.ask(
            "Proceed with ForceChangePassword execution?",
            default=False,
        ):
            print_warning("ForceChangePassword execution cancelled by operator.")
            return False
        # Ledger-ordering fix: do NOT register a cleanup obligation before the
        # reset runs. A pre-registered "password_changed" entry left a FALSE
        # operator-required obligation when the reset later failed (the operator
        # was told to reset a password that was never changed). Register only
        # AFTER the reset CONFIRMS success: a successful FCP leaves exactly one
        # operator-required entry; a failed FCP leaves the ledger clean.
        fcp_success = shell.exploit_force_change_password(
            context.domain,
            context.exec_username,
            context.exec_password,
            context.target_sam_or_label,
            context.target_domain,
            prompt_for_user_privs_after=False,
        )
        if not fcp_success:
            print_warning(
                "ForceChangePassword did not complete; the target password was not "
                "changed. No cleanup obligation was recorded."
            )
            return False

        _acl_cleanup_register(
            shell,
            context,
            kind="password_changed",
            detail={"target_user": context.target_sam_or_label},
        )
        ledger = getattr(shell, "environment_change_ledger", None)
        if ledger is not None:
            _cid = None
            actions = getattr(shell, "acl_cleanup_actions", None)
            if actions:
                _cid = actions[-1].get("_ledger_change_id")
            if _cid:
                try:
                    ledger.mark_operator_required(
                        _cid,
                        manual_cleanup_instructions=(
                            f"Coordinate with the client to reset the password for "
                            f"'{context.target_sam_or_label}' to a known value.\n"
                            f"  Set-ADAccountPassword -Identity '{context.target_sam_or_label}'"
                            f" -NewPassword (ConvertTo-SecureString 'NewPass' -AsPlainText -Force)"
                        ),
                    )
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
        return True

    if relation in {"genericall", "genericwrite", "writeaccountrestrictions"}:
        if target_kind in {"user", "computer"}:
            if context.target_tombstoned and target_kind == "user":
                print_warning(f"Target {marked_to} is a deleted (tombstoned) object.")
                if Confirm.ask(
                    "Restore it from the AD Recycle Bin first?", default=True
                ):
                    # Pass the tombstone DN when known; otherwise the SID +
                    # sAMAccountName so the service resolves the real Deleted-Objects
                    # DN. NEVER fall back to the bare label as a search base — that is
                    # an invalid base the DC always rejects with noSuchObject.
                    if not shell.restore_deleted_object(
                        context.domain,
                        context.exec_username,
                        context.exec_password,
                        context.target_deleted_dn,
                        object_sid=context.target_sid,
                        sam_account_name=context.target_sam_or_label,
                        last_known_rdn=context.target_last_known_rdn,
                    ):
                        print_warning(
                            f"Could not restore {marked_to}. Skipping exploitation."
                        )
                        return False
                    # Reanimated. target_enabled was read from the tombstone's
                    # PRESERVED userAccountControl, so the enable-first check below
                    # still fires for a restored-but-disabled account.
                else:
                    print_warning(
                        f"Skipping exploitation for tombstoned target {marked_to}."
                    )
                    return False
            if context.target_enabled is False and target_kind == "user":
                print_warning(f"Target {marked_to} is disabled.")
                if Confirm.ask("Do you want to try to enable it first?", default=True):
                    if not shell.enable_user(
                        context.domain,
                        context.exec_username,
                        context.exec_password,
                        context.target_sam_or_label,
                    ):
                        print_warning(
                            f"Could not enable {marked_to}. Skipping exploitation."
                        )
                        return False
                else:
                    print_warning(
                        f"Skipping exploitation for disabled target {marked_to}."
                    )
                    return False
            if context.target_enabled is False and target_kind == "computer":
                print_warning(f"Target {marked_to} is disabled.")
                if Confirm.ask("Do you want to try to enable it first?", default=True):
                    if not shell.enable_computer(
                        context.domain,
                        context.exec_username,
                        context.exec_password,
                        context.target_sam_or_label,
                    ):
                        print_warning(
                            f"Could not enable {marked_to}. Skipping exploitation."
                        )
                        return False
                else:
                    print_warning(
                        f"Skipping exploitation for disabled target {marked_to}."
                    )
                    return False
            if target_kind == "computer":
                computer_helper = getattr(
                    shell, "exploit_control_computer_object", None
                )
                if callable(computer_helper):
                    return computer_helper(
                        context.domain,
                        context.exec_username,
                        context.exec_password,
                        context.target_sam_or_label,
                        context.target_domain,
                        prompt_for_user_privs_after=False,
                        prompt_for_method_choice=True,
                    )
                if relation in {"genericall", "genericwrite"}:
                    # Backwards compatibility for older shell stubs while the
                    # dedicated computer-object helper rolls out.
                    return shell.exploit_generic_all_user(
                        context.domain,
                        context.exec_username,
                        context.exec_password,
                        context.target_sam_or_label,
                        context.target_domain,
                        prompt_for_password_fallback=False,
                        prompt_for_user_privs_after=False,
                        prompt_for_method_choice=True,
                        # ForceChangePassword needs GenericAll/Reset-Password — not GenericWrite.
                        allow_force_change_password=(relation == "genericall"),
                    )
                print_warning(
                    "Computer-object control exploitation helper is unavailable in this shell context."
                )
                return False

            ok = shell.exploit_generic_all_user(
                context.domain,
                context.exec_username,
                context.exec_password,
                context.target_sam_or_label,
                context.target_domain,
                prompt_for_password_fallback=False,
                prompt_for_user_privs_after=False,
                prompt_for_method_choice=True,
                # ForceChangePassword needs GenericAll/Reset-Password — not GenericWrite.
                allow_force_change_password=(relation == "genericall"),
            )
            if ok:
                _acl_cleanup_register(
                    shell,
                    context,
                    kind="shadow_credentials_added",
                    detail={"target_user": context.target_sam_or_label},
                )
            return ok

        if target_kind == "ou":
            return shell.exploit_generic_all_ou(
                context.domain,
                context.exec_username,
                context.exec_password,
                context.target_sam_or_label,
                context.target_domain,
                followup_after=False,
            )

        if target_kind == "domain":
            if relation != "genericall":
                # GenericWrite cannot modify the DACL - gated upstream in
                # describe_ace_relation_support, but kept defensive here.
                print_warning(
                    "GenericWrite on a Domain object does not grant DACL "
                    "modification; DCSync is not reachable through this edge."
                )
                return False
            return _execute_genericall_domain_dcsync(shell, context)

        if target_kind == "group":
            # RBCD coordination: a downstream AllowedToAct on this group needs an
            # owned SPN-bearing member (S4U requires an SPN). When the look-ahead
            # resolved one, default to it instead of the path-source executor — a
            # member without an SPN would fail the RBCD with KDC_ERR_BADOPTION.
            add_default = context.member_to_add or context.exec_username
            if context.member_to_add:
                print_info(
                    f"[dim]Add member:[/dim] the next step is resource-based "
                    f"constrained delegation (AllowedToAct) on {marked_to}, which "
                    f"needs an SPN-bearing member. ADscan selected the owned account "
                    f"{mark_sensitive(context.member_to_add, 'user')} — adding it so "
                    "the delegation ticket can be minted."
                )
            else:
                print_info(
                    f"[dim]Add member:[/dim] select a user to add to group {marked_to}."
                    " This modifies group membership in Active Directory."
                )
            changed_username = Prompt.ask(
                "Enter the user to add",
                default=add_default,
            )
            changed_username = _sanitize_prompt_account(changed_username)
            result = shell.exploit_add_member(
                context.domain,
                context.exec_username,
                context.exec_password,
                context.target_sam_or_label,
                changed_username,
                context.target_domain,
                enumerate_aces_after=False,
            )
            membership_outcome = _consume_group_membership_operation_outcome(shell)
            if result is True:
                _set_last_ace_execution_outcome(
                    shell,
                    {
                        "key": "group_membership_changed",
                        "domain": context.domain,
                        "target_domain": context.target_domain,
                        "target_group": context.target_sam_or_label,
                        "added_user": changed_username,
                        "exec_username": context.exec_username,
                        "exec_password": context.exec_password,
                        "cleanup_required": not bool(
                            membership_outcome.get("already_member")
                        ),
                        "membership_already_present": bool(
                            membership_outcome.get("already_member")
                        ),
                    },
                )
            return result

        print_warning(
            f"GenericAll/GenericWrite exploitation not supported for target type {context.target_kind}."
        )
        return False

    if relation == "addself":
        print_info(
            f"[dim]Add self:[/dim] adding {mark_sensitive(context.exec_username, 'user')}"
            f" to group {marked_to}."
            " This modifies group membership in Active Directory."
        )
        result = shell.exploit_add_member(
            context.domain,
            context.exec_username,
            context.exec_password,
            context.target_sam_or_label,
            context.exec_username,
            context.target_domain,
            enumerate_aces_after=False,
        )
        membership_outcome = _consume_group_membership_operation_outcome(shell)
        if result is True:
            _set_last_ace_execution_outcome(
                shell,
                {
                    "key": "group_membership_changed",
                    "domain": context.domain,
                    "target_domain": context.target_domain,
                    "target_group": context.target_sam_or_label,
                    "added_user": context.exec_username,
                    "exec_username": context.exec_username,
                    "exec_password": context.exec_password,
                    "cleanup_required": not bool(
                        membership_outcome.get("already_member")
                    ),
                    "membership_already_present": bool(
                        membership_outcome.get("already_member")
                    ),
                },
            )
        return result

    if relation == "addmember":
        # RBCD coordination (see the genericall/genericwrite group branch): a
        # downstream AllowedToAct on this group needs an SPN-bearing member.
        add_default = context.member_to_add or context.exec_username
        if context.member_to_add:
            print_info(
                f"[dim]Add member:[/dim] the next step is resource-based "
                f"constrained delegation (AllowedToAct) on {marked_to}, which needs "
                f"an SPN-bearing member. ADscan selected the owned account "
                f"{mark_sensitive(context.member_to_add, 'user')} — adding it so the "
                "delegation ticket can be minted."
            )
        else:
            print_info(
                f"[dim]Add member:[/dim] select a user to add to group {marked_to}."
                " This modifies group membership in Active Directory."
            )
        changed_username = Prompt.ask(
            "Enter the user to add",
            default=add_default,
        )
        changed_username = _sanitize_prompt_account(changed_username)
        result = shell.exploit_add_member(
            context.domain,
            context.exec_username,
            context.exec_password,
            context.target_sam_or_label,
            changed_username,
            context.target_domain,
            enumerate_aces_after=False,
        )
        membership_outcome = _consume_group_membership_operation_outcome(shell)
        if result is True:
            _set_last_ace_execution_outcome(
                shell,
                {
                    "key": "group_membership_changed",
                    "domain": context.domain,
                    "target_domain": context.target_domain,
                    "target_group": context.target_sam_or_label,
                    "added_user": changed_username,
                    "exec_username": context.exec_username,
                    "exec_password": context.exec_password,
                    "cleanup_required": not bool(
                        membership_outcome.get("already_member")
                    ),
                    "membership_already_present": bool(
                        membership_outcome.get("already_member")
                    ),
                },
            )
        return result

    if relation == "owns":
        # Phase 1: leverage ownership to write FullControl DACL entry (no owneredit needed).
        owns_ok = shell.exploit_owns(
            context.domain,
            context.exec_username,
            context.exec_password,
            context.target_sam_or_label,
            context.target_domain,
            target_kind,
        )
        if not owns_ok:
            return False

        # Phase 2: FullControl is now granted; chain to the same target-specific
        # actions as GenericAll.  Print a separator so the operator sees the two
        # phases clearly in the terminal output.
        print_info(
            "[green]Phase 2/2[/green] FullControl granted. "
            "Chaining to target-specific exploitation…"
        )

        if target_kind in {"user", "computer"}:
            if context.target_enabled is False and target_kind == "user":
                print_warning(f"Target {marked_to} is disabled.")
                if Confirm.ask("Do you want to try to enable it first?", default=True):
                    if not shell.enable_user(
                        context.domain,
                        context.exec_username,
                        context.exec_password,
                        context.target_sam_or_label,
                    ):
                        print_warning(f"Could not enable {marked_to}. Skipping.")
                        return False
                else:
                    return False
            if target_kind == "computer":
                computer_helper = getattr(
                    shell, "exploit_control_computer_object", None
                )
                if callable(computer_helper):
                    return computer_helper(
                        context.domain,
                        context.exec_username,
                        context.exec_password,
                        context.target_sam_or_label,
                        context.target_domain,
                        prompt_for_user_privs_after=False,
                        prompt_for_method_choice=True,
                    )
                return shell.exploit_generic_all_user(
                    context.domain,
                    context.exec_username,
                    context.exec_password,
                    context.target_sam_or_label,
                    context.target_domain,
                    prompt_for_password_fallback=False,
                    prompt_for_user_privs_after=False,
                    prompt_for_method_choice=True,
                )
            return shell.exploit_generic_all_user(
                context.domain,
                context.exec_username,
                context.exec_password,
                context.target_sam_or_label,
                context.target_domain,
                prompt_for_password_fallback=False,
                prompt_for_user_privs_after=False,
                prompt_for_method_choice=True,
            )

        if target_kind == "ou":
            return shell.exploit_generic_all_ou(
                context.domain,
                context.exec_username,
                context.exec_password,
                context.target_sam_or_label,
                context.target_domain,
                followup_after=False,
            )

        if target_kind == "group":
            # RBCD coordination: a downstream AllowedToAct on this group needs an
            # owned SPN-bearing member (S4U requires an SPN). When the look-ahead
            # resolved one, default to it instead of the path-source executor — a
            # member without an SPN would fail the RBCD with KDC_ERR_BADOPTION.
            add_default = context.member_to_add or context.exec_username
            if context.member_to_add:
                print_info(
                    f"[dim]Add member:[/dim] the next step is resource-based "
                    f"constrained delegation (AllowedToAct) on {marked_to}, which "
                    f"needs an SPN-bearing member. ADscan selected the owned account "
                    f"{mark_sensitive(context.member_to_add, 'user')} — adding it so "
                    "the delegation ticket can be minted."
                )
            else:
                print_info(
                    f"[dim]Add member:[/dim] select a user to add to group {marked_to}."
                    " This modifies group membership in Active Directory."
                )
            changed_username = Prompt.ask(
                "Enter the user to add",
                default=add_default,
            )
            changed_username = _sanitize_prompt_account(changed_username)
            result = shell.exploit_add_member(
                context.domain,
                context.exec_username,
                context.exec_password,
                context.target_sam_or_label,
                changed_username,
                context.target_domain,
                enumerate_aces_after=False,
            )
            membership_outcome = _consume_group_membership_operation_outcome(shell)
            if result is True:
                _set_last_ace_execution_outcome(
                    shell,
                    {
                        "key": "group_membership_changed",
                        "domain": context.domain,
                        "target_domain": context.target_domain,
                        "target_group": context.target_sam_or_label,
                        "added_user": changed_username,
                        "exec_username": context.exec_username,
                        "exec_password": context.exec_password,
                        "cleanup_required": not bool(
                            membership_outcome.get("already_member")
                        ),
                        "membership_already_present": bool(
                            membership_outcome.get("already_member")
                        ),
                    },
                )
            return result

        if target_kind == "domain":
            # After granting DCSync rights via dacledit, trigger DCSync.
            return shell.dcsync(
                context.domain,
                context.exec_username,
                context.exec_password,
                context.target_domain,
            )

        print_warning(
            f"Owns exploitation not supported for target type {context.target_kind}."
        )
        return False

    if relation == "writedacl":
        target_type = (
            target_kind if target_kind in {"user", "group", "domain"} else target_kind
        )
        ok = shell.exploit_write_dacl(
            context.domain,
            context.exec_username,
            context.exec_password,
            context.target_sam_or_label,
            context.target_domain,
            target_type,
            followup_after=False,
        )
        if ok:
            is_domain = target_type == "domain"
            exec_sid = getattr(shell, "_last_exec_sid", context.exec_username)
            _acl_cleanup_register(
                shell,
                context,
                kind="dacl_ace_added",
                detail={
                    "trustee": exec_sid or context.exec_username,
                    "rights_type": "dcsync" if is_domain else "genericAll",
                },
            )
        return ok

    if relation == "writeowner":
        if target_kind not in {"user", "group"}:
            print_warning(
                f"WriteOwner exploitation is only implemented for User/Group targets (got {context.target_kind})."
            )
            return False
        original_owner_sid = _capture_original_owner(shell, context)
        ok = shell.exploit_write_owner(
            context.domain,
            context.exec_username,
            context.exec_password,
            context.target_sam_or_label,
            context.target_domain,
            target_kind,
            followup_after=False,
        )
        if ok:
            _acl_cleanup_register(
                shell,
                context,
                kind="owner_changed",
                detail={"original_owner_sid": original_owner_sid},
            )
        return ok

    if relation == "writespn":
        if target_kind not in {"user", "computer"}:
            print_warning(
                f"WriteSPN exploitation is only implemented for User/Computer targets (got {context.target_kind})."
            )
            return False
        ok = shell.exploit_write_spn(
            context.domain,
            context.exec_username,
            context.exec_password,
            context.target_sam_or_label,
            context.target_domain,
        )
        if ok:
            from adscan_internal.cli.exploits import _build_targeted_kerberoast_spn  # noqa: PLC0415

            spn = _build_targeted_kerberoast_spn(context.target_sam_or_label)
            _acl_cleanup_register(
                shell,
                context,
                kind="spn_added",
                detail={"spn": spn},
            )
        return ok

    # Defensive: should not happen due to ACL_ACE_RELATIONS guard.
    try:
        telemetry.capture_exception(
            RuntimeError(f"Unhandled ACE relation: {context.relation}")
        )
    except Exception:
        pass
    return None
