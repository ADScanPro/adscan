"""Attack step follow-up planning (runtime substeps).

Some BloodHound relationships represent a *capability edge* but the actual
operator playbook requires additional steps to realize the impact. For example:

- WriteDacl -> Domain: grants replication rights, but the operator still needs
  to run DCSync to retrieve credentials.

During attack path execution, ADscan can offer these follow-ups as *runtime*
substeps without mutating the discovered attack path graph.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from adscan_internal import print_info, print_info_debug, print_info_verbose, print_warning
from adscan_internal.cli.privileges import run_service_access_sweep
from adscan_internal.cli.smb import run_auth_shares
from adscan_internal.rich_output import (
    BRAND_COLORS,
    mark_sensitive,
    print_panel,
    strip_sensitive_markers,
)
from adscan_internal.services.attack_graph_runtime_service import active_step_followup


@dataclass(frozen=True, slots=True)
class FollowupAction:
    """A suggested follow-up action for an executed step."""

    key: str
    title: str
    description: str
    handler: Callable[[], None]


def execute_guided_followup_actions(
    shell: Any,
    *,
    step_action: str,
    target_label: str,
    followups: list[FollowupAction],
) -> None:
    """Render follow-ups and execute them via guided confirm prompts."""
    if not followups:
        return

    render_followup_actions_panel(
        step_action=step_action,
        target_label=target_label,
        followups=followups,
    )
    confirmer = getattr(shell, "_questionary_confirm", None)
    selector = getattr(shell, "_questionary_select", None)
    for item in followups:
        prompt = f"Do you want to run follow-up '{item.title}' now?"
        if callable(confirmer):
            should_run = bool(confirmer(prompt, default=True))
        elif callable(selector):
            should_run = selector(prompt, ["Yes", "No"], default_idx=0) == 0
        else:
            should_run = Confirm.ask(prompt, default=True)
        if should_run:
            item.handler()
        else:
            print_info_verbose(
                f"Skipping post-exploitation follow-up action '{item.title}'."
            )


def _normalize_account(value: str) -> str:
    """Normalize a domain account label to a SAM-like lowercase identifier."""
    name = strip_sensitive_markers(str(value or "")).strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name.strip().lower()


def _resolve_domain_credential(
    shell: Any,
    *,
    domain: str,
    username: str,
) -> str | None:
    """Return a stored credential for a domain user using case-insensitive lookup."""
    normalized = _normalize_account(username)
    if not normalized:
        return None
    domain_data = getattr(shell, "domains_data", {}).get(domain, {})
    credentials = domain_data.get("credentials")
    if not isinstance(credentials, dict):
        return None
    for stored_user, stored_credential in credentials.items():
        if _normalize_account(str(stored_user)) != normalized:
            continue
        if not isinstance(stored_credential, str):
            return None
        candidate = stored_credential.strip()
        return candidate or None
    return None


def _refresh_group_membership_ticket(
    shell: Any,
    *,
    domain: str,
    added_user: str,
    credential: str,
) -> None:
    """Best-effort Kerberos ticket refresh after a group membership change."""
    marked_user = mark_sensitive(added_user, "user")
    marked_domain = mark_sensitive(domain, "domain")
    if not hasattr(shell, "_auto_generate_kerberos_ticket"):
        print_warning(
            f"Kerberos ticket refresh helper is unavailable for {marked_user}@{marked_domain}."
        )
        return
    dc_ip = getattr(shell, "domains_data", {}).get(domain, {}).get("dc_ip")
    print_info(
        f"Refreshing Kerberos ticket for {marked_user}@{marked_domain} "
        "after the group membership change."
    )
    ticket_path = shell._auto_generate_kerberos_ticket(added_user, credential, domain, dc_ip)  # type: ignore[attr-defined]
    if ticket_path:
        try:
            from adscan_internal.services.credential_store_service import (
                CredentialStoreService,
            )

            CredentialStoreService().store_kerberos_ticket(
                domains_data=shell.domains_data,
                domain=domain,
                username=added_user,
                ticket_path=ticket_path,
            )
        except Exception as exc:  # noqa: BLE001
            print_info_debug(
                "[followup] failed to persist refreshed kerberos ticket: "
                f"user={marked_user} domain={marked_domain} error={mark_sensitive(str(exc), 'detail')}"
            )
        print_info_debug(
            "[followup] refreshed kerberos ticket: "
            f"user={marked_user} domain={marked_domain} "
            f"ticket={mark_sensitive(ticket_path, 'path')}"
        )
        return
    print_warning(
        f"Could not refresh Kerberos ticket for {marked_user}@{marked_domain}. "
        "Continuing with credential-based follow-ups."
    )


def _run_user_host_access_followup(
    shell: Any,
    *,
    domain: str,
    username: str,
    credential: str,
) -> None:
    """Probe service access for a newly empowered or compromised user."""
    marked_user = mark_sensitive(username, "user")
    marked_domain = mark_sensitive(domain, "domain")
    print_info(
        f"Checking new host/service access for {marked_user} in domain {marked_domain}."
    )
    with active_step_followup(
        shell,
        source="attack_path_runtime_followup",
        title="Check New Host Access",
    ):
        run_service_access_sweep(
            shell,
            domain=domain,
            username=username,
            password=credential,
            services=["smb", "winrm", "rdp", "mssql"],
            hosts=None,
            prompt=True,
        )


def _run_user_share_followup(
    shell: Any,
    *,
    domain: str,
    username: str,
    credential: str,
) -> None:
    """Enumerate SMB shares reachable by a newly empowered or compromised user."""
    marked_user = mark_sensitive(username, "user")
    marked_domain = mark_sensitive(domain, "domain")
    print_info(
        f"Enumerating newly accessible SMB shares for {marked_user} in domain {marked_domain}."
    )
    with active_step_followup(
        shell,
        source="attack_path_runtime_followup",
        title="Enumerate SMB Shares",
    ):
        run_auth_shares(
            shell,
            domain=domain,
            username=username,
            password=credential,
        )


def _build_user_credential_followups(
    shell: Any,
    *,
    domain: str,
    username: str,
    credential: str,
) -> list[FollowupAction]:
    """Return reusable follow-ups after obtaining a user credential."""
    marked_user = mark_sensitive(username, "user")
    marked_domain = mark_sensitive(domain, "domain")

    return [
        FollowupAction(
            key="check_new_host_access",
            title="Check New Host Access",
            description=(
                f"Probe SMB/WinRM/RDP/MSSQL access for {marked_user} "
                f"after compromising {marked_user}@{marked_domain}."
            ),
            handler=lambda: _run_user_host_access_followup(
                shell,
                domain=domain,
                username=username,
                credential=credential,
            ),
        ),
        FollowupAction(
            key="enumerate_smb_shares",
            title="Enumerate SMB Shares",
            description=(
                f"Enumerate authenticated SMB shares now reachable by {marked_user}."
            ),
            handler=lambda: _run_user_share_followup(
                shell,
                domain=domain,
                username=username,
                credential=credential,
            ),
        ),
    ]


def build_followups_for_step(
    shell: Any,
    *,
    domain: str,
    step_action: str,
    exec_username: str,
    exec_password: str,
    target_kind: str,
    target_label: str,
    target_domain: str,
    target_sam_or_label: str,
) -> list[FollowupAction]:
    """Return follow-up actions for a given executed step (best-effort)."""
    action = (step_action or "").strip().lower()
    kind = (target_kind or "").strip().lower()

    followups: list[FollowupAction] = []

    if action == "writedacl":
        if kind == "domain":
            marked_domain = mark_sensitive(target_label or target_domain, "domain")

            def _handle_dcsync() -> None:
                ask_for_dcsync = getattr(shell, "ask_for_dcsync", None)
                if callable(ask_for_dcsync):
                    ask_for_dcsync(domain, exec_username, exec_password)
                    return
                dcsync = getattr(shell, "dcsync", None)
                if callable(dcsync):
                    dcsync(domain, exec_username, exec_password)
                    return

            followups.append(
                FollowupAction(
                    key="dcsync",
                    title="DCSync",
                    description=f"Attempt DCSync after granting replication rights on {marked_domain}.",
                    handler=_handle_dcsync,
                )
            )
            return followups

        if kind in {"user", "computer"}:
            marked_target = mark_sensitive(target_label, "user")

            def _handle_shadow_credentials() -> None:
                exploit = getattr(shell, "exploit_generic_all_user", None)
                if callable(exploit):
                    exploit(
                        domain,
                        exec_username,
                        exec_password,
                        target_sam_or_label,
                        target_domain,
                        prompt_for_password_fallback=True,
                        prompt_for_user_privs_after=True,
                    )

            followups.append(
                FollowupAction(
                    key="shadow_credentials",
                    title="Shadow Credentials",
                    description=f"Try Shadow Credentials against {marked_target} after DACL changes.",
                    handler=_handle_shadow_credentials,
                )
            )
            return followups

        if kind == "group":
            marked_target = mark_sensitive(target_sam_or_label or target_label, "user")

            def _handle_addmember() -> None:
                exploit = getattr(shell, "exploit_add_member", None)
                if not callable(exploit):
                    return
                changed_username = Prompt.ask(
                    f"Enter the user you want to add to group {target_sam_or_label}",
                    default=exec_username,
                )
                changed_username = strip_sensitive_markers(changed_username).strip()
                exploit(
                    domain,
                    exec_username,
                    exec_password,
                    target_sam_or_label,
                    changed_username,
                    target_domain,
                    enumerate_aces_after=True,
                )

            followups.append(
                FollowupAction(
                    key="addmember",
                    title="Add member",
                    description=f"Add a user to group {marked_target} after applying DACL changes.",
                    handler=_handle_addmember,
                )
            )
            return followups

    if action == "writeowner" and kind in {"user", "group"}:
        marked_target = mark_sensitive(target_label, "user")

        def _handle_writedacl() -> None:
            exploit = getattr(shell, "exploit_write_dacl", None)
            if callable(exploit):
                exploit(
                    domain,
                    exec_username,
                    exec_password,
                    target_sam_or_label,
                    target_domain,
                    kind,
                    followup_after=True,
                )

        followups.append(
            FollowupAction(
                key="writedacl",
                title="WriteDacl",
                description=f"Attempt WriteDacl against {marked_target} after becoming owner.",
                handler=_handle_writedacl,
            )
        )

    return followups


def build_followups_for_execution_outcome(
    shell: Any,
    *,
    outcome: dict[str, Any],
) -> list[FollowupAction]:
    """Return follow-up actions derived from the runtime outcome of a step."""
    outcome_key = str(outcome.get("key") or "").strip().lower()
    if outcome_key == "user_credential_obtained":
        target_domain = str(
            outcome.get("target_domain") or outcome.get("domain") or ""
        ).strip()
        compromised_user = strip_sensitive_markers(
            str(outcome.get("compromised_user") or "")
        ).strip()
        credential = str(outcome.get("credential") or "").strip()
        if not target_domain or not compromised_user or not credential:
            return []
        return _build_user_credential_followups(
            shell,
            domain=target_domain,
            username=compromised_user,
            credential=credential,
        )

    if outcome_key != "group_membership_changed":
        return []

    target_domain = str(
        outcome.get("target_domain") or outcome.get("domain") or ""
    ).strip()
    added_user = strip_sensitive_markers(str(outcome.get("added_user") or "")).strip()
    target_group = str(outcome.get("target_group") or "").strip()
    if not target_domain or not added_user or not target_group:
        return []

    credential = _resolve_domain_credential(
        shell,
        domain=target_domain,
        username=added_user,
    )
    exec_username = str(outcome.get("exec_username") or "").strip()
    exec_password = str(outcome.get("exec_password") or "").strip()
    if (
        not credential
        and exec_password
        and _normalize_account(exec_username) == _normalize_account(added_user)
    ):
        credential = exec_password
    marked_user = mark_sensitive(added_user, "user")
    marked_group = mark_sensitive(target_group, "group")
    marked_domain = mark_sensitive(target_domain, "domain")

    if not credential:
        print_info_debug(
            "[followup] group-membership outcome has no stored credential: "
            f"user={marked_user} group={marked_group} domain={marked_domain}"
        )
        return []

    return [
        FollowupAction(
            key="refresh_ticket",
            title="Refresh Kerberos Ticket",
            description=(
                f"Refresh the Kerberos ticket for {marked_user} so subsequent checks "
                f"use the new membership in {marked_group}."
            ),
            handler=lambda: _refresh_group_membership_ticket(
                shell,
                domain=target_domain,
                added_user=added_user,
                credential=credential,
            ),
        ),
        FollowupAction(
            key="enumerate_host_access",
            title="Check New Host Access",
            description=(
                f"Probe SMB/WinRM/RDP/MSSQL access for {marked_user} after joining "
                f"{marked_group}."
            ),
            handler=lambda: _run_user_host_access_followup(
                shell,
                domain=target_domain,
                username=added_user,
                credential=credential,
            ),
        ),
        FollowupAction(
            key="enumerate_shares",
            title="Enumerate SMB Shares",
            description=(
                f"Enumerate authenticated SMB shares now reachable by {marked_user} "
                f"via {marked_group}."
            ),
            handler=lambda: _run_user_share_followup(
                shell,
                domain=target_domain,
                username=added_user,
                credential=credential,
            ),
        ),
    ]


def render_followup_actions_panel(
    *,
    step_action: str,
    target_label: str,
    followups: list[FollowupAction],
) -> None:
    """Render a follow-up action list as a panel."""
    table = Table(
        title=Text("Recommended follow-ups", style=f"bold {BRAND_COLORS['info']}"),
        show_header=True,
        header_style=f"bold {BRAND_COLORS['info']}",
        show_lines=True,
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Action", style="bold")
    table.add_column("Description", style="dim", overflow="fold")

    for idx, item in enumerate(followups, start=1):
        table.add_row(str(idx), item.title, item.description)

    title = Text("Follow-up Actions", style=f"bold {BRAND_COLORS['info']}")
    marked_step = mark_sensitive(step_action, "node")
    marked_target = mark_sensitive(target_label, "node")
    subtitle = Text.assemble(
        ("Step: ", "dim"),
        (str(marked_step), "bold"),
        ("  Target: ", "dim"),
        (str(marked_target), "bold"),
    )
    print_panel(
        [subtitle, table], title=title, border_style=BRAND_COLORS["info"], expand=False
    )
