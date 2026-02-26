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

from adscan_internal import print_warning, telemetry
from adscan_internal.rich_output import mark_sensitive, print_info_verbose
from adscan_internal.services.attack_graph_service import (
    get_node_by_label,
    resolve_netexec_target_for_node_label,
)


def _normalize_account(value: str) -> str:
    name = (value or "").strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name.strip().lower()


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


def _node_enabled(node: dict[str, Any] | None) -> bool | None:
    props = _node_props(node)
    enabled = props.get("enabled")
    if isinstance(enabled, bool):
        return enabled
    return None


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
    value = creds.get(username)
    if not isinstance(value, str) or not value:
        return None
    return value


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


def describe_ace_step_support(context: AceStepContext) -> tuple[bool, str | None]:
    """Return whether an ACE step is supported for the given context.

    This is used to prevent "false supported" cases where the relationship
    exists in BloodHound (and the action name is mapped), but ADscan does not
    implement an exploitation path for the specific target object type.

    Args:
        context: Prepared ACE step execution context.

    Returns:
        Tuple of (supported, reason). If supported is True, reason is None.
    """
    relation = context.relation.strip().lower()
    target_kind = context.target_kind.strip()
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

    exec_username = _pick_execution_user(
        summary=summary,
        context_username=context_username,
        from_label=from_label,
        from_node=from_node,
    )
    if not exec_username:
        return None

    password = context_password or _resolve_domain_password(
        shell, domain, exec_username
    )
    if not password:
        return None

    target_domain = _node_domain(to_node) or domain
    target_kind = _node_kind(to_node)
    target_enabled = _node_enabled(to_node)
    target_sam_or_label = _node_sam_or_label(to_node, to_label)

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
    if relation not in ACL_ACE_RELATIONS:
        return None

    marked_user = mark_sensitive(context.exec_username, "user")
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
            if context.target_enabled is False:
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
                default=str(marked_user),
            )
            return shell.exploit_add_member(
                context.domain,
                context.exec_username,
                context.exec_password,
                context.target_sam_or_label,
                changed_username,
                context.target_domain,
                enumerate_aces_after=False,
            )

        print_warning(
            f"GenericAll/GenericWrite exploitation not supported for target type {context.target_kind}."
        )
        return False

    if relation == "addself":
        return shell.exploit_add_member(
            context.domain,
            context.exec_username,
            context.exec_password,
            context.target_sam_or_label,
            context.exec_username,
            context.target_domain,
            enumerate_aces_after=False,
        )

    if relation == "addmember":
        changed_username = Prompt.ask(
            "Enter the user you want to add",
            default=str(marked_user),
        )
        return shell.exploit_add_member(
            context.domain,
            context.exec_username,
            context.exec_password,
            context.target_sam_or_label,
            changed_username,
            context.target_domain,
            enumerate_aces_after=False,
        )

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
