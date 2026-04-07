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

from adscan_internal import print_warning, telemetry
from adscan_internal.rich_output import (
    BRAND_COLORS,
    mark_sensitive,
    print_info_debug,
    print_panel,
    print_info_verbose,
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


def _set_last_ace_execution_outcome(
    shell: Any, outcome: dict[str, Any] | None
) -> None:
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
    max_options: int = 20,
) -> tuple[str | None, str]:
    """Resolve an execution user and indicate which source was used."""
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
        print_info_debug(
            "[exec-user] meta.affected_users summary: "
            f"count={affected_count!r}, list_len={affected_users_len!r}"
        )
    else:
        print_info_debug("[exec-user] No meta object available on path summary.")
    if not (isinstance(affected_users, list) and affected_users) and isinstance(
        meta, dict
    ):
        print_info_debug("[exec-user] meta.affected_users missing/empty.")

    candidate_users: list[str] = []
    if isinstance(affected_users, list) and cred_keys:
        for raw_user in affected_users:
            if not isinstance(raw_user, str):
                continue
            normalized = _normalize_account(raw_user)
            if not normalized:
                continue
            stored_key = cred_keys.get(normalized)
            if stored_key:
                candidate_users.append(stored_key)

    if not candidate_users and isinstance(creds, dict) and creds:
        print_info_debug(
            "[exec-user] No meta.affected_users match; falling back to all stored credentials."
        )
        candidate_users = [str(stored_user) for stored_user in creds.keys()]

    if candidate_users:
        candidate_users = list(dict.fromkeys(candidate_users))
        print_info_debug(
            f"[exec-user] Found {len(candidate_users)} candidate user(s) with stored credentials."
        )
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

        if len(candidate_users) == 1:
            print_info_debug(
                f"[exec-user] Auto-selected sole candidate: {mark_sensitive(candidate_users[0], 'user')}"
            )
            return _normalize_account(candidate_users[0]), "affected_users"

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
            return _normalize_account(str(candidate_users[idx])), "interactive_selection"

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
    max_options: int = 20,
) -> str | None:
    """Resolve an execution user for attack steps that require credentials."""
    exec_username, _ = _resolve_execution_user_with_source(
        shell,
        domain=domain,
        context_username=context_username,
        summary=summary,
        from_label=from_label,
        from_node_kind=from_node_kind,
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


ACL_ACE_RELATIONS: set[str] = {
    "genericall",
    "genericwrite",
    "forcechangepassword",
    "addself",
    "addmember",
    "readgmsapassword",
    "readlapspassword",
    "writedacl",
    "writeowner",
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

    if relation in {"genericall", "genericwrite"}:
        if target_kind_norm in {"user", "computer", "ou", "group"}:
            return True, None
        return (
            False,
            f"GenericAll/GenericWrite exploitation is not implemented for target type {target_kind}.",
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
) -> AceStepContext | None:
    """Build an ACE execution context for a given step (best-effort)."""
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
        shell.dcsync(context.domain, context.exec_username, context.exec_password)
        return None

    if relation == "readgmsapassword":
        return shell.exploit_gmsa_account(
            context.domain,
            context.exec_username,
            context.exec_password,
            context.target_sam_or_label,
            context.target_domain,
            prompt_for_user_privs_after=False,
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
        if _is_audit_mode(shell):
            marked_from = mark_sensitive(context.exec_username, "user")
            message = Text()
            message.append(
                "ForceChangePassword is disruptive in audit mode.\n",
                style="bold yellow",
            )
            message.append(
                f"Execution user: {marked_from}\n"
                f"Target user: {marked_to}\n\n",
                style="bold",
            )
            message.append(
                "What ADscan will do:\n",
                style="bold",
            )
            message.append(
                " - Reset the target user's domain password immediately\n"
                " - Store the new credential in ADscan for follow-up path execution\n\n",
                style="dim",
            )
            message.append(
                "Risk notes:\n",
                style="bold",
            )
            message.append(
                " - This invalidates the target user's current password immediately.\n"
                " - If you do not coordinate with the client, this may interrupt active sessions or service access.\n",
                style="dim",
            )
            print_panel(
                message,
                title=Text("Disruptive Operation: ForceChangePassword", style="bold yellow"),
                border_style="yellow",
                expand=False,
            )
            if not Confirm.ask(
                "Proceed with ForceChangePassword execution?",
                default=False,
            ):
                print_warning("ForceChangePassword execution cancelled by operator.")
                return False
        return shell.exploit_force_change_password(
            context.domain,
            context.exec_username,
            context.exec_password,
            context.target_sam_or_label,
            context.target_domain,
            prompt_for_user_privs_after=False,
        )

    if relation in {"genericall", "genericwrite"}:
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
            changed_username = Prompt.ask(
                "Enter the user you want to add",
                default=context.exec_username,
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
                    },
                )
            return result

        print_warning(
            f"GenericAll/GenericWrite exploitation not supported for target type {context.target_kind}."
        )
        return False

    if relation == "addself":
        result = shell.exploit_add_member(
            context.domain,
            context.exec_username,
            context.exec_password,
            context.target_sam_or_label,
            context.exec_username,
            context.target_domain,
            enumerate_aces_after=False,
        )
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
                },
            )
        return result

    if relation == "addmember":
        changed_username = Prompt.ask(
            "Enter the user you want to add",
            default=context.exec_username,
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
                },
            )
        return result

    if relation == "writedacl":
        target_type = (
            target_kind if target_kind in {"user", "group", "domain"} else target_kind
        )
        return shell.exploit_write_dacl(
            context.domain,
            context.exec_username,
            context.exec_password,
            context.target_sam_or_label,
            context.target_domain,
            target_type,
            followup_after=False,
        )

    if relation == "writeowner":
        if target_kind not in {"user", "group"}:
            print_warning(
                f"WriteOwner exploitation is only implemented for User/Group targets (got {context.target_kind})."
            )
            return False
        return shell.exploit_write_owner(
            context.domain,
            context.exec_username,
            context.exec_password,
            context.target_sam_or_label,
            context.target_domain,
            target_kind,
            followup_after=False,
        )

    if relation == "writespn":
        if target_kind not in {"user", "computer"}:
            print_warning(
                f"WriteSPN exploitation is only implemented for User/Computer targets (got {context.target_kind})."
            )
            return False
        return shell.exploit_write_spn(
            context.domain,
            context.exec_username,
            context.exec_password,
            context.target_sam_or_label,
            context.target_domain,
        )

    # Defensive: should not happen due to ACL_ACE_RELATIONS guard.
    try:
        telemetry.capture_exception(
            RuntimeError(f"Unhandled ACE relation: {context.relation}")
        )
    except Exception:
        pass
    return None
