"""Credentials CLI orchestration helpers.

This module extracts credential management logic out of the monolithic
`adscan.py` so it can be reused by future UX layers while keeping runtime
behaviour stable for the current CLI.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from typing import Any

from rich.panel import Panel
from rich.prompt import Confirm
from rich.prompt import IntPrompt, Prompt
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

import rich

from adscan_internal import (
    print_error,
    print_info,
    print_info_debug,
    print_instruction,
    print_info_verbose,
    print_success_verbose,
    print_table,
    print_warning,
    telemetry,
)
from adscan_internal.rich_output import BRAND_COLORS, mark_sensitive, print_panel
from adscan_internal.cli.common import build_lab_event_fields
from adscan_internal.cli.cracking import (
    handle_hash_cracking,
    handle_hash_cracking_batch,
)

NON_SPRAYABLE_CREDSWEEPER_RULES = {"uuid"}
UUID_VALUE_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


@dataclass(frozen=True)
class CredentialPresentationOptions:
    """Shared credential-review presentation options for SMB/WinRM findings."""

    confidence_label: str | None = "ML Confidence"
    source_column_label: str = "Path(s)"


def normalize_creds_subcommand(subcommand: str) -> tuple[str, bool]:
    """Normalize `creds` subcommand aliases to their canonical form.

    Args:
        subcommand: Raw subcommand provided by the user (for example `save`).

    Returns:
        Tuple ``(normalized, alias_used)``.
    """
    normalized = str(subcommand or "").strip().lower()
    aliases = {
        "add": "save",
    }
    target = aliases.get(normalized, normalized)
    return target, target != normalized


def ensure_domain_ready_for_manual_credential_save(
    shell: Any,
    *,
    domain: str,
    username: str,
    is_local_target: bool = False,
) -> bool:
    """Validate that a domain is initialized before manual ``creds save`` usage.

    The expected workflow is:
    1) Initialize/validate target context with ``start_auth``.
    2) Use ``creds save`` later to add additional credentials discovered outside
       of ADscan while continuing the same workspace/domain campaign.

    Args:
        shell: Active shell instance.
        domain: Domain received by ``creds save``.
        username: Username received by ``creds save``.
        is_local_target: Whether save operation targets local creds (host/service).

    Returns:
        ``True`` when domain context exists and save may continue, ``False`` when
        the user should initialize the domain first.
    """
    domains_data = getattr(shell, "domains_data", {})
    if isinstance(domains_data, dict) and domain in domains_data:
        return True

    marked_domain = mark_sensitive(domain, "domain")
    marked_user = mark_sensitive(username, "user")
    operation_scope = "local credential" if is_local_target else "domain credential"

    print_panel(
        "\n".join(
            [
                "⚠️ Domain not initialized in this workspace.",
                f"Domain: {marked_domain}",
                f"Credential user: {marked_user}",
                f"Requested operation: {operation_scope}",
                "",
                "Recommended workflow:",
                "1) Run `start_auth` first to initialize domain context, validate DNS/DC, and verify credentials.",
                "2) After `start_auth`, use `creds save` only to add additional credentials discovered later.",
            ]
        ),
        title="[bold yellow]Initialize Domain First[/bold yellow]",
        border_style="yellow",
        expand=False,
    )
    print_instruction("Run `start_auth` now to initialize this domain properly.")
    print_instruction(
        "After initialization, you can add extra creds with: "
        "`creds save <domain> <username> <password_or_hash>`"
    )

    try:
        properties: dict[str, Any] = {
            "domain": domain,
            "username": username,
            "is_local_target": bool(is_local_target),
            "workspace_type": getattr(shell, "type", None),
            "auto_mode": getattr(shell, "auto", False),
            "scan_mode": getattr(shell, "scan_mode", None),
        }
        properties.update(build_lab_event_fields(shell=shell, include_slug=True))
        telemetry.capture("creds_save_requires_start_auth", properties)
    except Exception as exc:  # pragma: no cover - telemetry best effort
        telemetry.capture_exception(exc)

    return False


def show_creds(shell: Any) -> None:
    """Display all stored credentials using Rich Tables, Panels, and Trees.

    Args:
        shell: The PentestShell instance with domains_data and license_mode.
    """
    if not shell.domains_data:
        shell.console.print(
            Text("No credentials stored in the current workspace.", style="yellow")
        )
        return

    overall_creds_found = False
    for domain, data in shell.domains_data.items():
        domain_renderables = []
        creds_found_for_this_domain = False

        # Domain credentials
        if "credentials" in data and data["credentials"]:
            creds_found_for_this_domain = True
            overall_creds_found = True

            domain_creds_table = Table(
                title=Text("Domain Credentials", style=f"bold {BRAND_COLORS['info']}"),
                show_header=True,
                header_style=f"bold {BRAND_COLORS['info']}",
                box=rich.box.ROUNDED,
            )
            domain_creds_table.add_column(
                "User", style="green", width=30, overflow="fold"
            )
            domain_creds_table.add_column(
                "Credential", style="white", width=40, overflow="fold"
            )
            for user, cred_value in data["credentials"].items():
                cred_display = str(cred_value)
                marked_user = mark_sensitive(user, "user")
                marked_cred_display = mark_sensitive(cred_display, "password")
                domain_creds_table.add_row(marked_user, marked_cred_display)
            domain_renderables.append(domain_creds_table)

        # Local credentials
        if "local_credentials" in data and data["local_credentials"]:
            creds_found_for_this_domain = True
            overall_creds_found = True
            domain_renderables.append(
                Text("\nLocal Credentials", style=f"bold {BRAND_COLORS['info']}")
            )
            local_creds_tree_root = Tree("[bold]Hosts[/bold]")

            for host, services in data["local_credentials"].items():
                host_branch = local_creds_tree_root.add(
                    Text(host, style=BRAND_COLORS["info"])
                )
                for service, users in services.items():
                    service_branch = host_branch.add(Text(service, style="purple"))
                    for user, cred_value in users.items():
                        cred_display = str(cred_value)
                        service_branch.add(
                            Text(
                                f"User: {user}, Credential: {cred_display}",
                                style="white",
                            )
                        )
            domain_renderables.append(local_creds_tree_root)

        if creds_found_for_this_domain:
            from adscan_internal import print_panel

            marked_domain = mark_sensitive(domain, "domain")
            print_panel(
                domain_renderables,
                title=f"[bold {BRAND_COLORS['info']}]Domain: {marked_domain}[/bold {BRAND_COLORS['info']}]",
                border_style=BRAND_COLORS["info"],
            )

    if not overall_creds_found:
        print_warning("No credentials found in any domain.")


def clear_creds(shell: Any, domain: str) -> None:
    """Clear all credentials for a given domain.

    Args:
        shell: The PentestShell instance with domains_data.
        domain: The domain name to clear credentials for.
    """
    from adscan_internal.services.credential_store_service import (
        CredentialStoreService,
    )

    if domain not in shell.domains_data:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"Domain {marked_domain} does not exist.")
        return

    store_service = CredentialStoreService()

    # Get all usernames with domain credentials to delete them
    domain_data = shell.domains_data.get(domain, {})
    if "credentials" in domain_data:
        usernames = list(domain_data["credentials"].keys())
        for username in usernames:
            store_service.delete_domain_credential(
                domains_data=shell.domains_data, domain=domain, username=username
            )

    # Clear local credentials (direct manipulation still needed as there's no bulk delete method)
    # TODO: Add bulk delete method to CredentialStoreService if needed
    if "local_credentials" in shell.domains_data[domain]:
        shell.domains_data[domain]["local_credentials"] = {}

    marked_domain = mark_sensitive(domain, "domain")
    print_info(f"All credentials for domain {marked_domain} have been cleared.")


def select_cred(shell: Any, domain: str) -> None:
    """Select a credential for a domain and proceed with enumeration.

    Args:
        shell: The PentestShell instance with domains_data and related methods.
        domain: The domain name to select credentials for.
    """
    if (
        domain not in shell.domains_data
        or "credentials" not in shell.domains_data[domain]
        or not shell.domains_data[domain]["credentials"]
    ):
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"No credentials stored for domain [bold]{marked_domain}[/bold].")
        return

    credentials = shell.domains_data[domain]["credentials"]
    user_list = list(credentials.keys())

    if not user_list:
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            f"No users with credentials found for domain [bold]{marked_domain}[/bold], though credentials entry exists."
        )
        return

    print_panel(
        Text.from_markup(
            f"[bold {BRAND_COLORS['info']}]{domain}[/bold {BRAND_COLORS['info']}]",
            justify="center",
        ),
        title=f"[bold {BRAND_COLORS['info']}]Domain[/bold {BRAND_COLORS['info']}]",
        border_style=BRAND_COLORS["info"],
        expand=False,
        padding=(0, 1),
    )
    table = Table(
        title=f"[bold {BRAND_COLORS['info']}]Available Users[/bold {BRAND_COLORS['info']}]",
        box=rich.box.ROUNDED,
        show_lines=True,
        title_style=f"bold {BRAND_COLORS['info']}",
    )
    table.add_column("ID", style="dim white", width=6, justify="center")
    table.add_column("Username", style="bold magenta")

    for idx, user_name in enumerate(user_list):
        marked_user_name = mark_sensitive(user_name, "user")
        table.add_row(str(idx + 1), marked_user_name)

    print_table(table)

    try:
        num_users = len(user_list)
        if num_users == 0:
            return  # Should have been caught by earlier checks

        selected_user_num = IntPrompt.ask(
            f"Select a user by ID (1-{num_users})",
            choices=[str(i + 1) for i in range(num_users)],
            show_default=False,
            show_choices=False,
        )
        selected_user_idx = selected_user_num - 1

    except KeyboardInterrupt as e:
        telemetry.capture_exception(e)
        print_warning("Credential selection cancelled.")
        return

    # IntPrompt handles non-integer input and choice validation.
    # This check is mostly for safety, IntPrompt with choices should ensure validity.
    if not (0 <= selected_user_idx < len(user_list)):
        print_error("Invalid selection. Index out of range.")
        return

    selected_user = user_list[selected_user_idx]
    print_info_verbose(f"Selected user: [bold green]{selected_user}[/bold green]")

    cred_value = credentials[selected_user]

    # Verify domain credentials using the correctly scoped 'selected_user'
    if not shell.verify_domain_credentials(domain, selected_user, cred_value):
        from adscan_internal.services.credential_store_service import (
            CredentialStoreService,
        )

        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"Incorrect credentials for user '[bold]{selected_user}[/bold]' in domain [bold]{marked_domain}[/bold]."
        )
        # Remove the invalid credential using the service
        store_service = CredentialStoreService()
        deleted = store_service.delete_domain_credential(
            domains_data=shell.domains_data, domain=domain, username=selected_user
        )
        if deleted:
            marked_domain = mark_sensitive(domain, "domain")
            print_warning(
                f"Existing invalid credential for '[bold]{selected_user}[/bold]' in domain [bold]{marked_domain}[/bold] has been deleted."
            )
            # Persist changes after deleting invalid credential
            if shell.current_workspace_dir:
                if shell.save_workspace_data():
                    print_info(
                        "Workspace data saved after removing invalid credential."
                    )
                else:
                    print_error(
                        "Failed to save workspace data after removing invalid credential."
                    )
        return

    marked_domain = mark_sensitive(domain, "domain")
    print_success_verbose(
        f"Credentials for '[bold]{selected_user}[/bold]' verified successfully for domain [bold]{marked_domain}[/bold]."
    )

    handle_auth_and_optional_privs(
        shell,
        domain,
        [(selected_user, cred_value)],
        prompt_for_user_privs_after=True,
    )


def handle_auth_and_optional_privs(
    shell: Any,
    domain: str,
    users_with_creds: list[tuple[str, str]],
    *,
    prompt_for_user_privs_after: bool = True,
    force_authenticated_enumeration: bool = False,
    prompt_when_already_authenticated: bool = False,
    allow_empty_credentials: bool = False,
) -> None:
    """Ensure authenticated enumeration and optionally ask for user privileges.

    Args:
        shell: Shell instance with enumeration helpers.
        domain: Domain to operate on.
        users_with_creds: List of (username, credential) tuples.
        prompt_for_user_privs_after: When True, prompt for user privilege checks.
        force_authenticated_enumeration: When True, rerun authenticated
            enumeration even if the domain is already in ``auth`` state.
        prompt_when_already_authenticated: When True, and the domain is already
            ``auth``, ask whether to rerun the full authenticated scan or only
            continue with privilege enumeration for the current user.
        allow_empty_credentials: When True, treat an empty string as an explicit
            credential value (for example: valid blank-password logons) instead
            of discarding it as missing input.
    """
    marked_domain = mark_sensitive(domain, "domain")
    current_auth_status = shell.domains_data.get(domain, {}).get("auth", "")
    print_info_debug(
        f"[creds] handle_auth_and_optional_privs start: domain={marked_domain} "
        f"auth={current_auth_status!r} users={len(users_with_creds)} "
        f"prompt_privs={prompt_for_user_privs_after} "
        f"force_enum={force_authenticated_enumeration!r} "
        f"prompt_existing_auth={prompt_when_already_authenticated!r}"
    )
    has_non_empty_credential = any(
        user and (cred is not None) and cred != "" for user, cred in users_with_creds
    )

    def _choose_authenticated_enumeration_action() -> str:
        """Return how to proceed when start_auth targets an already-auth domain."""
        if current_auth_status != "auth":
            return "full_scan"
        if not prompt_when_already_authenticated:
            return "full_scan" if force_authenticated_enumeration else "skip"
        if getattr(shell, "auto", False) or not sys.stdin.isatty():
            print_info_debug(
                "[creds] start_auth re-run on already-auth domain in non-interactive mode; "
                "defaulting to full authenticated scan."
            )
            return "full_scan"

        workspace_type = str(getattr(shell, "type", "") or "").strip().lower()
        if workspace_type == "audit":
            scan_focus = (
                "Recommended for audits: refresh trust enumeration, BloodHound data, "
                "and the full authenticated pipeline."
            )
            focused_option = "Only inspect this user's privileges and attack paths"
        elif workspace_type == "ctf":
            scan_focus = (
                "Recommended for CTFs when you want a fresh authenticated pass before "
                "continuing foothold validation or post-auth escalation."
            )
            focused_option = (
                "Only inspect this user's privileges for quick foothold validation"
            )
        else:
            scan_focus = (
                "Recommended when you want a fresh authenticated pass across the full "
                "domain pipeline."
            )
            focused_option = "Only inspect this user's privileges"
        options = [
            "Rerun full authenticated scan (Recommended)",
            focused_option,
        ]
        print_panel(
            "\n".join(
                [
                    "This domain is already marked as authenticated in the current workspace.",
                    f"Workspace type: {str(workspace_type or 'unknown').upper()}",
                    f"Domain: {marked_domain}",
                    "",
                    scan_focus,
                    "",
                    "Choose how to proceed:",
                    "1) Rerun the full authenticated scan pipeline now",
                    "2) Skip the full scan and stay on the current user context",
                ]
            ),
            title="[bold cyan]Authenticated Domain Already Initialized[/bold cyan]",
            border_style="cyan",
            expand=False,
        )

        selected_idx: int | None = None
        selector = getattr(shell, "_questionary_select", None)
        if callable(selector):
            try:
                selected_idx = selector(
                    "Select how to proceed:", options, default_idx=0
                )
            except TypeError:
                selected_idx = selector("Select how to proceed:", options)
        if selected_idx is None:
            selected_choice = Prompt.ask(
                Text("Select an option", style="cyan"),
                choices=["1", "2"],
                default="1",
            )
            try:
                selected_idx = int(selected_choice) - 1
            except ValueError:
                selected_idx = 0

        if selected_idx == 1:
            print_info_debug(
                "[creds] start_auth re-run on already-auth domain: user selected privileges-only flow."
            )
            return "privs_only"

        print_info_debug(
            "[creds] start_auth re-run on already-auth domain: user selected full authenticated scan."
        )
        return "full_scan"

    enumeration_action = "skip"
    full_scan_started = False
    if current_auth_status != "pwned":
        if force_authenticated_enumeration:
            enumeration_action = _choose_authenticated_enumeration_action()
        elif current_auth_status not in {"auth", "pwned"}:
            enumeration_action = "full_scan"

    if enumeration_action == "full_scan" and not has_non_empty_credential:
        print_info_debug(
            "[creds] skipping do_enum_authenticated because only blank credentials "
            "were provided; continuing with privilege checks only."
        )
        enumeration_action = "skip"

    if enumeration_action == "full_scan":
        try:
            if force_authenticated_enumeration:
                print_info(
                    "Running full authenticated scan for "
                    f"{marked_domain} using the verified credential."
                )
            print_info_debug(
                f"[creds] auth={current_auth_status!r}; running do_enum_authenticated "
                f"(force={force_authenticated_enumeration!r})"
            )
            shell.do_enum_authenticated(domain)
            full_scan_started = True
        except Exception as e:  # noqa: BLE001
            telemetry.capture_exception(e)
            print_warning(f"Failed to start authenticated enumeration: {e}")
            print_info(
                "You can manually start enumeration with: enum_authenticated <domain>"
            )
    else:
        if force_authenticated_enumeration and enumeration_action == "privs_only":
            primary_user = next(
                (mark_sensitive(user, "user") for user, _cred in users_with_creds if user),
                mark_sensitive("current user", "user"),
            )
            print_info(
                "Skipping full authenticated scan. Continuing with privilege "
                f"enumeration for {primary_user} only."
            )
        print_info_debug(
            f"[creds] skipping do_enum_authenticated (auth={current_auth_status!r}, "
            f"action={enumeration_action!r})"
        )

    updated_auth_status = shell.domains_data.get(domain, {}).get("auth", "")
    print_info_debug(
        f"[creds] handle_auth_and_optional_privs post-enum: auth={updated_auth_status!r}"
    )
    try:
        from adscan_internal.services.attack_graph_runtime_service import (
            ActiveAttackGraphStep,
            get_attack_path_followup_context,
            get_attack_path_step_context,
            is_attack_path_execution_active,
        )
    except Exception:  # noqa: BLE001
        ActiveAttackGraphStep = object  # type: ignore[misc,assignment]

        def get_attack_path_step_context(_shell: Any) -> dict[str, object]:
            return {}

        def get_attack_path_followup_context(_shell: Any) -> dict[str, object]:
            return {}

        def is_attack_path_execution_active(_shell: Any) -> bool:
            return False

    from adscan_internal.services.high_value import (
        is_user_tier0_or_high_value,
        normalize_samaccountname,
    )
    from adscan_internal.services.attack_step_support_registry import (
        classify_relation_support,
    )

    def _resolve_active_step_compromise_metadata() -> tuple[str, str]:
        """Return normalized compromise semantics and effort for the active step."""
        context = get_attack_path_step_context(shell)
        semantics = str(context.get("compromise_semantics") or "").strip().lower()
        effort = str(context.get("compromise_effort") or "").strip().lower()
        if semantics or effort:
            return semantics or "other", effort or "other"
        active = getattr(shell, "_active_attack_graph_step", None)
        relation = str(getattr(active, "relation", "") or "").strip().lower()
        if relation:
            support = classify_relation_support(relation)
            return support.compromise_semantics, support.compromise_effort
        return "other", "other"

    def _is_terminal_direct_compromise_attack_step() -> bool:
        """Return True for a terminal direct-compromise step in a supported search."""
        context = get_attack_path_step_context(shell)
        search_mode = str(context.get("search_mode_label") or "").strip().lower()
        compromise_semantics, compromise_effort = (
            _resolve_active_step_compromise_metadata()
        )
        try:
            step_index = int(context.get("step_index") or 0)
            last_executable_idx = int(context.get("last_executable_idx") or 0)
        except (TypeError, ValueError):
            print_info_debug(
                "[creds] terminal pivot check: invalid attack-path step context "
                f"context={mark_sensitive(str(context), 'detail')}"
            )
            return False
        is_terminal_direct_compromise = (
            search_mode in {"pivot search", "high-value search"}
            and step_index > 0
            and step_index == last_executable_idx
            and compromise_semantics == "direct_target_compromise"
        )
        print_info_debug(
            "[creds] terminal direct-compromise check: "
            f"search_mode={mark_sensitive(search_mode or 'none', 'detail')} "
            f"compromise_semantics={mark_sensitive(compromise_semantics, 'detail')} "
            f"compromise_effort={mark_sensitive(compromise_effort, 'detail')} "
            f"step_index={step_index} last_executable_idx={last_executable_idx} "
            f"result={is_terminal_direct_compromise!r}"
        )
        return is_terminal_direct_compromise

    def _is_terminal_pivot_attack_step() -> bool:
        """Return True when the active step is the final actionable pivot step."""
        context = get_attack_path_step_context(shell)
        search_mode = str(context.get("search_mode_label") or "").strip().lower()
        is_terminal_pivot = (
            search_mode == "pivot search"
            and _is_terminal_direct_compromise_attack_step()
        )
        print_info_debug(
            "[creds] terminal pivot check: "
            f"search_mode={mark_sensitive(search_mode or 'none', 'detail')} "
            f"result={is_terminal_pivot!r}"
        )
        return is_terminal_pivot

    def _resolve_active_step_execution_user() -> str | None:
        """Best-effort extraction of the 'execution user' for the active step."""
        active = getattr(shell, "_active_attack_graph_step", None)
        if not isinstance(active, ActiveAttackGraphStep):
            return None

        candidates: list[str] = []
        notes = active.notes if isinstance(active.notes, dict) else {}
        for key in ("username", "exec_username", "user", "target_user"):
            value = notes.get(key)
            if isinstance(value, str) and value.strip():
                candidates.append(value.strip())

        # Fallbacks when steps did not include notes.
        for label in (active.to_label, active.from_label):
            if isinstance(label, str) and label.strip():
                candidates.append(label.strip())

        for raw in candidates:
            normalized = normalize_samaccountname(raw)
            if normalized:
                return normalized
        return None

    def _run_terminal_pivot_user_followups(user: str, credential: str) -> bool:
        """Offer lightweight follow-ups for user creds gained at the end of a pivot path."""
        attack_path_active = is_attack_path_execution_active(shell)
        if not attack_path_active:
            print_info_debug(
                "[creds] terminal pivot follow-up gate: disabled "
                "(attack path execution inactive)"
            )
            return False
        followup_context = get_attack_path_followup_context(shell)
        if followup_context:
            print_info_debug(
                "[creds] terminal pivot follow-up gate: disabled "
                "(nested attack-path follow-up active; defering to potential "
                "new-principal privilege assessment flow) "
                f"context={mark_sensitive(str(followup_context), 'detail')}"
            )
            return False
        if not _is_terminal_pivot_attack_step():
            print_info_debug(
                "[creds] terminal pivot follow-up gate: disabled "
                "(active step is not the terminal pivot step)"
            )
            return False

        normalized_user = normalize_samaccountname(user)
        active_step_user = _resolve_active_step_execution_user()
        step_context = get_attack_path_step_context(shell)
        print_info_debug(
            "[creds] terminal pivot follow-up evaluation: "
            f"user={mark_sensitive(normalized_user or user, 'user')} "
            f"active_step_user={mark_sensitive(active_step_user or 'N/A', 'user')} "
            f"step_context={mark_sensitive(str(step_context), 'detail')}"
        )
        if not normalized_user:
            print_info_debug(
                "[creds] terminal pivot follow-up gate: disabled "
                "(credential user could not be normalized)"
            )
            return False
        if active_step_user and normalized_user == active_step_user:
            print_info_debug(
                "[creds] skipping terminal pivot user follow-ups "
                "(credential belongs to active step execution user)"
            )
            return False

        try:
            from adscan_internal.cli.attack_step_followups import (
                build_followups_for_execution_outcome,
                execute_guided_followup_actions,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_verbose(
                f"Failed to load pivot follow-up helpers for {mark_sensitive(user, 'user')}: {exc}"
            )
            return False

        followups = build_followups_for_execution_outcome(
            shell,
            outcome={
                "key": "user_credential_obtained",
                "domain": domain,
                "target_domain": domain,
                "compromised_user": user,
                "credential": credential,
                "credential_type": (
                    "hash"
                    if callable(getattr(shell, "is_hash", None))
                    and bool(shell.is_hash(credential))
                    else "password"
                ),
            },
        )
        if not followups:
            print_info_debug(
                "[creds] terminal pivot follow-up gate: disabled "
                "(no follow-ups resolved for runtime outcome)"
            )
            return False

        print_info_debug(
            "[creds] terminal pivot follow-up gate: enabled "
            f"(resolved_followups={len(followups)})"
        )
        execute_guided_followup_actions(
            shell,
            step_action="Credential Added",
            target_label=f"{normalized_user}@{domain}",
            followups=followups,
        )
        return True

    def _should_force_full_user_privs_from_attack_context(user: str) -> bool:
        """Return True when attack-path context should promote a full user pivot.

        Credentials discovered from an active attack-path follow-up (for example,
        passwords recovered while enumerating SMB shares or services) represent a
        *new* pivot source that was not part of the original terminal step. In
        that scenario we intentionally prefer the broader ``ask_for_user_privs``
        flow over the lightweight terminal-pivot UX.
        """
        if not is_attack_path_execution_active(shell):
            print_info_debug(
                "[creds] attack-context credential flow: disabled "
                "(attack path execution inactive)"
            )
            return False
        followup_context = get_attack_path_followup_context(shell)
        compromise_semantics, compromise_effort = (
            _resolve_active_step_compromise_metadata()
        )
        if not followup_context and compromise_semantics != "access_capability_only":
            print_info_debug(
                "[creds] attack-context credential flow: disabled "
                "(no nested follow-up context and active step semantics are not access_capability_only)"
            )
            return False

        normalized_user = normalize_samaccountname(user)
        if not normalized_user:
            print_info_debug(
                "[creds] attack-context credential flow: disabled "
                "(credential user could not be normalized)"
            )
            return False

        active_step_user = _resolve_active_step_execution_user()
        if active_step_user and normalized_user == active_step_user:
            print_info_debug(
                "[creds] attack-context credential flow: disabled "
                "(credential belongs to active step execution user)"
            )
            return False

        print_info_debug(
            "[creds] attack-context credential flow: enabling full "
            "ask_for_user_privs for newly discovered principal "
            f"user={mark_sensitive(normalized_user, 'user')} "
            f"active_step_user={mark_sensitive(active_step_user or 'N/A', 'user')} "
            f"compromise_semantics={mark_sensitive(compromise_semantics, 'detail')} "
            f"compromise_effort={mark_sensitive(compromise_effort, 'detail')} "
            f"context={mark_sensitive(str(followup_context), 'detail')}"
        )
        return True

    standard_user_privs_covered_by_full_scan = full_scan_started and (
        enumeration_action == "full_scan"
    )
    should_offer_standard_user_privs = (
        prompt_for_user_privs_after
        and updated_auth_status != "pwned"
        and not standard_user_privs_covered_by_full_scan
    )
    if not should_offer_standard_user_privs:
        if not prompt_for_user_privs_after:
            print_info_debug(
                "[creds] standard ask_for_user_privs disabled by caller "
                f"(auth={updated_auth_status!r}, prompt={prompt_for_user_privs_after})"
            )
        elif updated_auth_status == "pwned":
            print_info_debug(
                "[creds] standard ask_for_user_privs disabled because domain is pwned"
            )
        elif standard_user_privs_covered_by_full_scan:
            print_info_debug(
                "[creds] standard ask_for_user_privs disabled because the "
                "full authenticated scan already includes User Privilege Assessment"
            )

    for user, cred in users_with_creds:
        if not user or (cred is None) or (cred == "" and not allow_empty_credentials):
            continue
        try:
            if _run_terminal_pivot_user_followups(user, cred):
                continue
            force_full_user_privs_from_attack_context = (
                _should_force_full_user_privs_from_attack_context(user)
            )
            normalized_user = normalize_samaccountname(user)
            should_force_high_value_terminal_user_privs = False
            if (
                is_attack_path_execution_active(shell)
                and not force_full_user_privs_from_attack_context
                and _is_terminal_direct_compromise_attack_step()
                and normalized_user
            ):
                should_force_high_value_terminal_user_privs = (
                    is_user_tier0_or_high_value(
                        shell, domain=domain, samaccountname=normalized_user
                    )
                )
                print_info_debug(
                    "[creds] terminal direct-compromise high-value check: "
                    f"user={mark_sensitive(normalized_user, 'user')} "
                    f"result={should_force_high_value_terminal_user_privs!r}"
                )
                if should_force_high_value_terminal_user_privs:
                    print_info_debug(
                        "[creds] enabling ask_for_user_privs for terminal "
                        "high-value direct compromise "
                        f"user={mark_sensitive(normalized_user, 'user')}"
                    )
            if (
                is_attack_path_execution_active(shell)
                and not force_full_user_privs_from_attack_context
                and not should_force_high_value_terminal_user_privs
            ):
                print_info_debug(
                    "[creds] standard ask_for_user_privs disabled during active "
                    "attack path (no attack-context new-principal override)"
                )
                continue
            should_offer_user_privs = (
                should_offer_standard_user_privs
                or force_full_user_privs_from_attack_context
                or should_force_high_value_terminal_user_privs
            )
            if not should_offer_user_privs:
                print_info_debug(
                    "[creds] ask_for_user_privs skipped "
                    f"(standard={should_offer_standard_user_privs!r}, "
                    f"attack_context_override={force_full_user_privs_from_attack_context!r})"
                )
                continue

            attack_path_active = is_attack_path_execution_active(shell)
            active_step_user = _resolve_active_step_execution_user()

            if attack_path_active:
                active = getattr(shell, "_active_attack_graph_step", None)
                if isinstance(active, ActiveAttackGraphStep):
                    marked_rel = str(active.relation or "")
                    marked_from = mark_sensitive(active.from_label, "node")
                    marked_to = mark_sensitive(active.to_label, "node")
                else:
                    marked_rel = "N/A"
                    marked_from = "N/A"
                    marked_to = "N/A"

                print_info_debug(
                    "[creds] ask_for_user_privs attack-path check: "
                    f"active={attack_path_active!r} "
                    f"active_step_user={mark_sensitive(active_step_user or 'N/A', 'user')} "
                    f"user={mark_sensitive(normalized_user or user, 'user')} "
                    f"relation={marked_rel} from={marked_from} to={marked_to}"
                )

            # While executing an attack path, avoid prompting for privileges for
            # the *step user* (it is noisy and can re-enter attack path search).
            # Still allow prompts for unrelated newly obtained creds (e.g. DA via DCSync),
            # and allow prompts for Tier-0/high-value users (e.g. kerberoast -> Administrator).
            if (
                attack_path_active
                and active_step_user
                and normalized_user == active_step_user
            ):
                is_hv = is_user_tier0_or_high_value(
                    shell, domain=domain, samaccountname=normalized_user
                )
                print_info_debug(
                    "[creds] ask_for_user_privs active-step match: "
                    f"user={mark_sensitive(normalized_user or user, 'user')} "
                    f"is_high_value={is_hv!r}"
                )
                if not is_hv:
                    print_info_debug(
                        "[creds] skipping ask_for_user_privs (matches active step execution user)"
                    )
                    continue
                print_info_debug(
                    "[creds] allowing ask_for_user_privs (Tier-0/high-value user)"
                )

            print_info_debug(
                "[creds] ask_for_user_privs pre-check: "
                f"attack_path_active={is_attack_path_execution_active(shell)!r}"
            )
            print_info_debug(
                f"[creds] ask_for_user_privs: user={mark_sensitive(user, 'user')}"
            )
            shell.ask_for_user_privs(domain, user, cred)
        except Exception as e:  # noqa: BLE001
            telemetry.capture_exception(e)
            print_info_verbose(f"Failed to prompt for user privileges: {e}")


def _mark_user_owned_in_bloodhound(shell: Any, domain: str, user: str) -> None:
    """Mark a verified domain credential holder as owned in BloodHound (best-effort).

    Args:
        shell: PentestShell instance with ``_get_bloodhound_service`` access.
        domain: Domain name (e.g. ``"corp.local"``).
        user: Username (samAccountName or UPN).
    """
    service_getter = getattr(shell, "_get_bloodhound_service", None)
    if not service_getter:
        return
    try:
        bh_service = service_getter()
    except Exception:
        return
    client = getattr(bh_service, "client", None)
    if client is None or not hasattr(client, "mark_principal_owned"):
        return

    username_upn = user if "@" in user else f"{user}@{domain}"
    marked_user = mark_sensitive(user, "user")
    marked_domain = mark_sensitive(domain, "domain")
    try:
        success = client.mark_principal_owned(username_upn, owned=True)
        if success:
            print_info_debug(
                f"[bloodhound] Marked {marked_user}@{marked_domain} as owned in BloodHound."
            )
        else:
            print_info_debug(
                f"[bloodhound] Could not mark {marked_user}@{marked_domain} as owned "
                "in BloodHound (principal may not be in the graph yet)."
            )
    except Exception as exc:
        print_info_debug(
            f"[bloodhound] mark_principal_owned raised for {marked_user}@{marked_domain}: {exc}"
        )


def add_credential(
    shell: Any,
    domain: str,
    user: str,
    cred: str,
    host: str | None = None,
    service: str | None = None,
    skip_hash_cracking: bool = False,
    pdc_ip: str | None = None,
    source_steps: list[object] | None = None,
    prompt_for_user_privs_after: bool = True,
    verify_credential: bool = True,
    verify_local_credential: bool = True,
    prompt_local_reuse_after: bool = True,
    ui_silent: bool = False,
    ensure_fresh_kerberos_ticket: bool = True,
    force_authenticated_enumeration: bool = False,
    prompt_when_already_authenticated: bool = False,
    allow_empty_credential: bool = False,
) -> None:
    """Add a credential to the workspace.

    This function handles both domain and local credentials, verifies them,
    handles hash cracking, and generates Kerberos tickets when appropriate.
    When a domain credential is verified, it can also record one or more
    provenance edges in `attack_graph.json` to track how the credential was
    obtained (e.g., UserDescription, GPP, roasting, etc.).

    Args:
        shell: The PentestShell instance with domains_data and related methods.
        domain: The domain name.
        user: The username.
        cred: The credential (password or hash).
        host: Optional host for local credentials.
        service: Optional service for local credentials.
        skip_hash_cracking: Whether to skip hash cracking attempts.
        pdc_ip: Optional PDC IP address for domain discovery when creating subworkspace.
        source_steps: Optional list of provenance step descriptors to record in the
            attack graph if the credential is verified. Each item should be a
            `CredentialSourceStep` from `adscan_internal.services.attack_graph_service`.
        prompt_for_user_privs_after: When True, prompt to enumerate privileges and
            search attack paths for the user after verifying the credential. This
            should be disabled when credentials are obtained as part of an active
            attack path execution to avoid double-executing downstream steps.
        verify_credential: When True (default), verify domain credentials before
            storing them. Set to False for trusted bulk-import flows (for example
            DCSync dumps) where per-credential verification would be too costly.
        verify_local_credential: When True (default), verify local credentials on
            the target host before storing them.
        prompt_local_reuse_after: When True (default), offer local credential
            reuse checks after successfully adding local SMB credentials.
        ui_silent: When True, suppress user-facing Rich panels/messages from this
            flow while preserving internal logging and credential processing.
        ensure_fresh_kerberos_ticket: When True (default), refresh Kerberos tickets
            for verified domain credentials. This prevents stale/expired ccache
            files from breaking Kerberos-dependent workflows.
        force_authenticated_enumeration: When True, rerun the full authenticated
            scan pipeline after a verified domain credential is processed.
        prompt_when_already_authenticated: When True, and the domain is already
            authenticated, prompt before rerunning the full authenticated scan.
        allow_empty_credential: When True, treat ``""`` as an explicit password
            value instead of rejecting it as empty input. This is reserved for
            flows such as blank-password spraying where an empty secret is the
            candidate being verified.
    """
    from adscan_internal import print_operation_header
    from adscan_internal.services.credential_store_service import (
        CredentialStoreService,
    )

    store_service = CredentialStoreService()
    normalized_domain = str(domain or "").strip().rstrip(".").lower()
    if not normalized_domain:
        print_error("Domain credential cannot be stored without a valid domain name.")
        return
    domain = normalized_domain

    if not skip_hash_cracking and not ui_silent:
        # Professional credential addition header
        cred_type = "Hash" if shell.is_hash(cred) else "Password"
        scope = "Local" if (host and service) else "Domain"
        details = {
            "Scope": scope,
            "Domain": domain,
            "Username": user,
            cred_type: cred,
        }
        if host:
            details["Target Host"] = host
        if service:
            details["Service"] = service.upper()

        print_operation_header(f"Adding {scope} Credential", details=details, icon="➕")

    # Initial validations
    user = user.lower()
    credential_verified = False
    credential_source_verified = False
    credential_persisted = False
    store_update_skipped = False

    import os
    import time

    if not os.path.exists(os.path.join("domains", domain)):
        marked_domain = mark_sensitive(domain, "domain")
        marked_pdc_ip = mark_sensitive(pdc_ip, "ip") if pdc_ip else None
        print_info_verbose(
            f"Creating subworkspace for domain {marked_domain}"
            + (f" with PDC IP {marked_pdc_ip}" if pdc_ip else " (no PDC IP provided)")
        )
        shell.domains.append(domain)
        # Convert to set and back to list to remove duplicates
        shell.domains = list(set(shell.domains))
        print_info_debug(
            f"[add_credential] Calling create_sub_workspace_for_domain with domain={marked_domain}, "
            f"pdc_ip={marked_pdc_ip if pdc_ip else 'None'}"
        )
        shell.create_sub_workspace_for_domain(domain, pdc_ip=pdc_ip)
        time.sleep(1)
        if verify_credential:
            if _verify_domain_credentials(
                shell,
                domain,
                user,
                cred,
                ui_silent=ui_silent,
                source_steps=source_steps,
            ):
                cred = _resolve_verified_domain_credential(
                    shell,
                    domain=domain,
                    user=user,
                    fallback_credential=cred,
                )
                credential_verified = True
            else:
                if _should_delete_failed_domain_credential(shell):
                    deleted = store_service.delete_domain_credential(
                        domains_data=shell.domains_data, domain=domain, username=user
                    )
                    if deleted:
                        marked_user = mark_sensitive(user, "user")
                        marked_domain = mark_sensitive(domain, "domain")
                        if not ui_silent:
                            print_error(
                                f"Existing credential for '{marked_user}' in domain {marked_domain} has been deleted."
                            )
                        else:
                            print_info_verbose(
                                f"[ui_silent] Existing credential for '{marked_user}' in domain {marked_domain} has been deleted."
                            )
                return
        shell.domains_data[domain]["username"] = user
        shell.domains_data[domain]["password"] = cred
        # Create necessary directories
        from adscan_internal.workspaces import domain_subpath

        workspace_cwd = shell.current_workspace_dir or os.getcwd()
        cracking_path = domain_subpath(
            workspace_cwd, shell.domains_dir, domain, shell.cracking_dir
        )
        ldap_path = domain_subpath(
            workspace_cwd, shell.domains_dir, domain, shell.ldap_dir
        )

        for directory in [cracking_path, ldap_path]:
            if not os.path.exists(directory):
                os.makedirs(directory)

    if domain not in shell.domains_data:
        shell.domains_data[domain] = {}

    if host and service:
        # Verify local credentials before adding them unless caller requested
        # candidate-only persistence (for example: SAM single-host workflows).
        local_verified = True
        if verify_local_credential:
            local_verified = bool(
                shell.check_local_creds(domain, user, cred, host, service)
            )
        if local_verified:
            credential_source_verified = bool(verify_local_credential)
            is_hash = shell.is_hash(cred)
            if is_hash and not user.endswith("$") and not skip_hash_cracking:
                cred, is_hash = handle_hash_cracking(shell, domain, user, cred)

            # Update local credential using the service
            store_service.update_local_credential(
                domains_data=shell.domains_data,
                domain=domain,
                host=host,
                service=service,
                username=user,
                credential=cred,
                is_hash=is_hash,
            )
            credential_persisted = True
            marked_user = mark_sensitive(user, "user")
            marked_host = mark_sensitive(host, "hostname")

            marked_domain = mark_sensitive(domain, "domain")
            marked_cred = mark_sensitive(cred, "password")
            print_info_verbose(
                f"Local credential added for user '{marked_user}' on host {marked_host} ({service}) of domain {marked_domain}: {marked_cred}"
            )

            if service == "mssql":
                shell.ask_for_mssql_steal(domain, host, user, cred, "false")
            elif service == "smb" and prompt_local_reuse_after:
                shell.ask_for_local_cred_reuse(domain, user, cred)

            if source_steps and credential_source_verified:
                try:
                    from adscan_internal.services.attack_graph_service import (
                        CredentialSourceStep,
                        record_credential_source_steps,
                    )

                    typed_steps = [
                        step
                        for step in source_steps
                        if isinstance(step, CredentialSourceStep)
                    ]
                    if typed_steps:
                        record_credential_source_steps(
                            shell,
                            domain,
                            username=user,
                            steps=typed_steps,
                            status="success",
                        )
                    else:
                        print_info_debug(
                            "[add_credential] source_steps provided but none match "
                            "CredentialSourceStep; skipping attack graph recording."
                        )
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
                    print_info_debug(
                        "[add_credential] Failed to record credential provenance steps "
                        "in attack graph (continuing)."
                    )
        else:
            if not ui_silent:
                print_error("Local credential not added - verification failed")
            else:
                print_info_verbose(
                    "[ui_silent] Local credential not added - verification failed"
                )
            return

    else:
        # Handle domain credentials
        is_hash = shell.is_hash(cred)
        is_explicit_blank_password = allow_empty_credential and cred == ""
        domain_data = shell.domains_data.get(domain, {})
        credentials_dict = domain_data.get("credentials", {})
        current_cred = (
            credentials_dict.get(user) if isinstance(credentials_dict, dict) else None
        )

        skip_store_update = False
        if current_cred is not None:
            current_is_hash = shell.is_hash(current_cred)
            if not current_is_hash and is_hash:
                print_info_verbose(
                    "Current credential is not a hash and new credential is a hash. Keeping existing."
                )
                cred = current_cred
                is_hash = False
                skip_store_update = True
            elif current_cred == cred:
                print_info_verbose(
                    "Current credential is the same as the new credential. Reusing existing."
                )
                skip_store_update = True
        store_update_skipped = skip_store_update
        if is_hash and not user.endswith("$") and not skip_hash_cracking:
            cred, is_hash = handle_hash_cracking(shell, domain, user, cred)

        # Verify domain credentials before adding them (skip when domain is already pwned)
        if verify_credential and not credential_verified:
            if _verify_domain_credentials(
                shell,
                domain,
                user,
                cred,
                ui_silent=ui_silent,
                source_steps=source_steps,
            ):
                cred = _resolve_verified_domain_credential(
                    shell,
                    domain=domain,
                    user=user,
                    fallback_credential=cred,
                )
                credential_verified = True
            else:
                if _should_delete_failed_domain_credential(shell):
                    deleted = store_service.delete_domain_credential(
                        domains_data=shell.domains_data, domain=domain, username=user
                    )
                    if deleted:
                        marked_user = mark_sensitive(user, "user")
                        marked_domain = mark_sensitive(domain, "domain")
                        if not ui_silent:
                            print_error(
                                f"Existing credential for '{marked_user}' in domain {marked_domain} has been deleted."
                            )
                        else:
                            print_info_verbose(
                                f"[ui_silent] Existing credential for '{marked_user}' in domain {marked_domain} has been deleted."
                            )
                return

        if (cred is not None) and (allow_empty_credential or cred != "") and not skip_store_update:
            # Update domain credential using the service
            update_result = store_service.update_domain_credential(
                domains_data=shell.domains_data,
                domain=domain,
                username=user,
                credential=cred,
                is_hash=is_hash,
            )
            credential_persisted = True
            # Respect store precedence rules (e.g. keep existing plaintext over new hash).
            is_hash = update_result.is_hash
            if is_hash:
                marked_user = mark_sensitive(user, "user")
                marked_domain = mark_sensitive(domain, "domain")
                print_info_verbose(
                    f"Hash added for user '{marked_user}' in domain {marked_domain}"
                )
            else:
                marked_user = mark_sensitive(user, "user")
                marked_domain = mark_sensitive(domain, "domain")
                marked_cred = mark_sensitive(cred, "password")
                print_info_verbose(
                    f"Password added for user '{marked_user}' in domain {marked_domain}: {marked_cred}"
                )

            # Telemetry: capture first validated domain credential depending on scan mode
            try:
                if hasattr(shell, "scan_mode") and shell.scan_mode in (
                    "auth",
                    "unauth",
                ):
                    # Ensure domain_validated_cred_counts is initialized
                    if not hasattr(shell, "domain_validated_cred_counts"):
                        shell.domain_validated_cred_counts = {}
                    count = shell.domain_validated_cred_counts.get(domain, 0)
                    target_index = 1 if shell.scan_mode == "unauth" else 2
                    new_count = count + 1
                    shell.domain_validated_cred_counts[domain] = new_count
                    if new_count == target_index:
                        duration = None
                        try:
                            if (
                                hasattr(shell, "scan_start_time")
                                and shell.scan_start_time
                            ):
                                duration = max(
                                    0.0, time.monotonic() - shell.scan_start_time
                                )
                        except Exception:
                            duration = None

                        # Try to determine source context (limited by add_credential not having full context)
                        # We'll track if it's a hash vs password and if host/service were provided
                        cred_source_hint = "domain"
                        if host and service:
                            cred_source_hint = f"local_{service}"

                        properties = {
                            "scan_mode": shell.scan_mode,
                            "duration_minutes": round((duration / 60.0), 2)
                            if isinstance(duration, (int, float))
                            else None,
                            "type": getattr(shell, "type", None),
                            "auto": getattr(shell, "auto", False),
                            "is_hash": is_hash,
                            "source_hint": cred_source_hint,
                            "auth_type": shell.domains_data.get(domain, {}).get(
                                "auth", "unknown"
                            ),
                        }
                        properties.update(
                            build_lab_event_fields(shell=shell, include_slug=True)
                        )
                        telemetry.capture("first_cred_found", properties)
                        # Track victory for session summary (Hormozi: Give:Ask ratio)
                        if hasattr(shell, "_session_victories"):
                            shell._session_victories.append("first_cred_found")

                        # Track scan-level TTFC for scan_complete event
                        if (
                            hasattr(shell, "_scan_first_credential_time")
                            and shell._scan_first_credential_time is None
                        ):
                            import time as time_module

                            shell._scan_first_credential_time = time_module.monotonic()

                        # Mark share prompt as eligible after a meaningful win.
                        # This is a best-effort UX nudge and must never affect scan flow.
                        if hasattr(shell, "_mark_share_prompt_eligible"):
                            shell._mark_share_prompt_eligible(reason="first_cred_found")

                        # Victory hint: domain compromised (Tier 2 - subtle)
                        try:
                            # Victory hints are defined as module-level functions in adscan.py
                            # Try to access them through the shell or module if available
                            should_show = getattr(
                                shell, "should_show_victory_hint", None
                            ) or getattr(
                                shell.__class__, "should_show_victory_hint", None
                            )
                            show_hint = getattr(
                                shell, "show_victory_hint_subtle", None
                            ) or getattr(
                                shell.__class__, "show_victory_hint_subtle", None
                            )

                            if should_show and show_hint:
                                if should_show("domain_compromised", "subtle"):
                                    show_hint(
                                        victory_type="domain_compromised",
                                        message="Valid credentials found!",
                                        docs_link="https://www.adscanpro.com/share?utm_source=cli&utm_medium=victory_domain_compromised",
                                    )
                            else:
                                # Try importing from adscan module if available
                                import sys

                                if "adscan" in sys.modules:
                                    adscan_module = sys.modules["adscan"]
                                    if hasattr(
                                        adscan_module, "should_show_victory_hint"
                                    ) and hasattr(
                                        adscan_module, "show_victory_hint_subtle"
                                    ):
                                        if adscan_module.should_show_victory_hint(
                                            "domain_compromised", "subtle"
                                        ):
                                            adscan_module.show_victory_hint_subtle(
                                                victory_type="domain_compromised",
                                                message="Valid credentials found!",
                                                docs_link="https://www.adscanpro.com/share?utm_source=cli&utm_medium=victory_domain_compromised",
                                            )
                        except Exception:
                            # Victory hints are optional, don't break flow if they fail
                            pass
            except Exception as e:
                telemetry.capture_exception(e)
                # Telemetry failures shouldn't break the credential addition flow

        if source_steps and (credential_verified or credential_source_verified):
            try:
                from adscan_internal.services.attack_graph_service import (
                    CredentialSourceStep,
                    record_credential_source_steps,
                )

                typed_steps = [
                    step
                    for step in source_steps
                    if isinstance(step, CredentialSourceStep)
                ]
                if typed_steps:
                    record_credential_source_steps(
                        shell,
                        domain,
                        username=user,
                        steps=typed_steps,
                        status="success",
                    )
                else:
                    print_info_debug(
                        "[add_credential] source_steps provided but none match "
                        "CredentialSourceStep; skipping attack graph recording."
                    )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_info_debug(
                    "[add_credential] Failed to record credential provenance steps "
                    "in attack graph (continuing)."
                )

        if credential_verified:
            # Track credential count for case study metrics
            if hasattr(shell, "_session_credentials_count"):
                shell._session_credentials_count += 1

            # Mark the verified user as owned in BloodHound (best-effort, non-blocking).
            try:
                _mark_user_owned_in_bloodhound(shell, domain, user)
            except Exception as _bh_exc:
                telemetry.capture_exception(_bh_exc)
                print_info_debug(
                    f"[add_credential] BH mark-owned failed for "
                    f"{mark_sensitive(user, 'user')}@{mark_sensitive(domain, 'domain')}: {_bh_exc}"
                )

            try:
                existing_ticket = store_service.get_kerberos_ticket(
                    domains_data=shell.domains_data,
                    domain=domain,
                    username=user,
                )
                if is_explicit_blank_password:
                    marked_user = mark_sensitive(user, "user")
                    marked_domain = mark_sensitive(domain, "domain")
                    print_info_debug(
                        "[add_credential] Skipping Kerberos ticket generation for "
                        f"{marked_user}@{marked_domain} because the credential is a blank password."
                    )
                elif existing_ticket and not ensure_fresh_kerberos_ticket:
                    marked_user = mark_sensitive(user, "user")
                    marked_domain = mark_sensitive(domain, "domain")
                    marked_ticket = mark_sensitive(existing_ticket, "path")
                    print_info_verbose(
                        f"Kerberos ticket already registered for {marked_user}@{marked_domain}; "
                        f"skipping auto-generation (ticket={marked_ticket})."
                    )
                else:
                    if existing_ticket and ensure_fresh_kerberos_ticket:
                        marked_user = mark_sensitive(user, "user")
                        marked_domain = mark_sensitive(domain, "domain")
                        marked_ticket = mark_sensitive(existing_ticket, "path")
                        print_info_verbose(
                            f"Refreshing Kerberos ticket for {marked_user}@{marked_domain} "
                            f"(existing_ticket={marked_ticket})."
                        )

                    # Try to get DC IP from domain data if available
                    dc_ip = None
                    if "dc_ip" in shell.domains_data.get(domain, {}):
                        dc_ip = shell.domains_data[domain]["dc_ip"]

                    ccache_file = shell._auto_generate_kerberos_ticket(
                        user, cred, domain, dc_ip
                    )
                    if ccache_file:
                        # Store ccache file path using the service
                        store_service.store_kerberos_ticket(
                            domains_data=shell.domains_data,
                            domain=domain,
                            username=user,
                            ticket_path=ccache_file,
                        )

                        marked_user = mark_sensitive(user, "user")
                        marked_domain = mark_sensitive(domain, "domain")
                        if not ui_silent:
                            print_info(
                                f"Kerberos ticket generated for {marked_user}@{marked_domain}"
                            )
                        else:
                            print_info_verbose(
                                f"[ui_silent] Kerberos ticket generated for {marked_user}@{marked_domain}"
                            )
                    else:
                        marked_user = mark_sensitive(user, "user")
                        marked_domain = mark_sensitive(domain, "domain")
                        if not ui_silent:
                            print_warning(
                                f"Could not generate Kerberos ticket for {marked_user}@{marked_domain}"
                            )
                        else:
                            print_info_verbose(
                                f"[ui_silent] Could not generate Kerberos ticket for {marked_user}@{marked_domain}"
                            )
            except Exception as e:
                telemetry.capture_exception(e)
                marked_user = mark_sensitive(user, "user")
                marked_domain = mark_sensitive(domain, "domain")
                if not ui_silent:
                    print_error(
                        f"Kerberos ticket generation skipped for {marked_user}@{marked_domain}: {e}"
                    )
                else:
                    print_info_verbose(
                        f"[ui_silent] Kerberos ticket generation skipped for {marked_user}@{marked_domain}: {e}"
                    )

            # Set shell.domain and proceed with enumeration if applicable.
            if hasattr(shell, "domain"):
                shell.domain = domain

            if (
                not is_explicit_blank_password
                and shell.domains_data[domain].get("username") is None
            ):
                shell.domains_data[domain]["username"] = user
                shell.domains_data[domain]["password"] = cred

            handle_auth_and_optional_privs(
                shell,
                domain,
                [(user, cred)],
                prompt_for_user_privs_after=prompt_for_user_privs_after,
                force_authenticated_enumeration=force_authenticated_enumeration,
                prompt_when_already_authenticated=prompt_when_already_authenticated,
                allow_empty_credentials=allow_empty_credential,
            )

        elif not credential_persisted and not store_update_skipped and not ui_silent:
            # Handle empty or invalid credential (matches old behavior)
            marked_user = mark_sensitive(user, "user")
            marked_domain = mark_sensitive(domain, "domain")
            print_error(
                f"Empty or invalid credential for '{marked_user}' in domain {marked_domain}"
            )
        elif not credential_persisted and not store_update_skipped:
            marked_user = mark_sensitive(user, "user")
            marked_domain = mark_sensitive(domain, "domain")
            print_info_verbose(
                f"[ui_silent] Empty or invalid credential for '{marked_user}' in domain {marked_domain}"
            )


def add_credentials_batch(
    shell: Any,
    *,
    domain: str,
    credentials: list[tuple[str, str]],
    skip_hash_cracking: bool = False,
    pdc_ip: str | None = None,
    source_steps: list[object] | None = None,
    prompt_for_user_privs_after: bool = True,
    verify_credential: bool = True,
    ui_silent: bool = False,
    ensure_fresh_kerberos_ticket: bool = True,
) -> list[tuple[str, str]]:
    """Persist multiple domain credentials with optional batch hash cracking.

    Args:
        shell: The PentestShell instance with domains_data and related helpers.
        domain: Target domain where credentials will be stored.
        credentials: ``[(username, credential), ...]`` raw candidates.
        skip_hash_cracking: When True, do not attempt weakpass cracking.
        pdc_ip: Optional PDC IP used when creating domain sub-workspace.
        source_steps: Optional provenance steps to attach to each credential.
        prompt_for_user_privs_after: Forwarded to add_credential.
        verify_credential: Forwarded to add_credential.
        ui_silent: Forwarded to add_credential.
        ensure_fresh_kerberos_ticket: Forwarded to add_credential.

    Returns:
        List of persisted candidates ``[(username, resolved_credential), ...]``.
        The credential is a cracked plaintext when batch cracking succeeds.
    """
    resolved_credentials = resolve_credential_pairs_for_batch(
        shell,
        credentials=credentials,
        skip_hash_cracking=skip_hash_cracking,
        skip_machine_accounts_cracking=True,
    )
    if not resolved_credentials:
        return []

    for username, resolved_credential in resolved_credentials:
        add_credential(
            shell=shell,
            domain=domain,
            user=username,
            cred=resolved_credential,
            skip_hash_cracking=True,
            pdc_ip=pdc_ip,
            source_steps=source_steps,
            prompt_for_user_privs_after=prompt_for_user_privs_after,
            verify_credential=verify_credential,
            ui_silent=ui_silent,
            ensure_fresh_kerberos_ticket=ensure_fresh_kerberos_ticket,
        )

    return resolved_credentials


def resolve_credential_pairs_for_batch(
    shell: Any,
    *,
    credentials: list[tuple[str, str]],
    skip_hash_cracking: bool = False,
    skip_machine_accounts_cracking: bool = True,
) -> list[tuple[str, str]]:
    """Normalize and optionally crack credential pairs for batch workflows.

    Args:
        shell: The active shell instance exposing ``is_hash`` and cracking helpers.
        credentials: Candidate ``[(username, credential), ...]`` pairs.
        skip_hash_cracking: When True, do not attempt weakpass batch cracking.
        skip_machine_accounts_cracking: When True, skip cracking for usernames
            ending with ``$``.

    Returns:
        Resolved ``[(username, credential), ...]`` pairs. Hash entries are replaced
        by plaintext when cracking succeeds.
    """

    def _is_hash_value(value: str) -> bool:
        is_hash_fn = getattr(shell, "is_hash", None)
        if callable(is_hash_fn):
            try:
                return bool(is_hash_fn(value))
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
        return bool(re.fullmatch(r"[0-9a-fA-F]{32}", str(value or "").strip()))

    prepared: list[tuple[str, str]] = []
    for username, credential in credentials:
        normalized_user = str(username or "").strip()
        normalized_credential = str(credential or "").strip()
        if not normalized_user or not normalized_credential:
            continue
        prepared.append((normalized_user, normalized_credential))

    if not prepared:
        return []

    cracked_by_hash: dict[str, str] = {}
    if not skip_hash_cracking:
        hash_candidates = [
            cred
            for user, cred in prepared
            if _is_hash_value(cred)
            and not (skip_machine_accounts_cracking and str(user).endswith("$"))
        ]
        cracked_by_hash = handle_hash_cracking_batch(shell, hash_candidates)

    resolved_credentials: list[tuple[str, str]] = []
    for username, credential in prepared:
        resolved_credential = credential
        if not skip_hash_cracking and _is_hash_value(credential):
            if not (skip_machine_accounts_cracking and str(username).endswith("$")):
                cracked_password = cracked_by_hash.get(credential.lower())
                if cracked_password:
                    resolved_credential = cracked_password
        resolved_credentials.append((username, resolved_credential))
    return resolved_credentials


def add_local_credentials_batch(
    shell: Any,
    *,
    domain: str,
    credentials: list[tuple[str, str, str, str]],
    skip_hash_cracking: bool = False,
    source_steps: list[object] | None = None,
    verify_local_credential: bool = True,
    prompt_local_reuse_after: bool = False,
    ui_silent: bool = False,
) -> list[tuple[str, str, str, str]]:
    """Persist multiple local (host/service) credentials with shared batch logic.

    Args:
        shell: The active shell instance.
        domain: Target domain context.
        credentials: ``[(host, service, username, credential), ...]`` candidates.
        skip_hash_cracking: When True, do not attempt weakpass batch cracking.
        source_steps: Optional provenance steps attached to each persisted cred.
        verify_local_credential: Forwarded to ``add_credential``.
        prompt_local_reuse_after: Forwarded to ``add_credential``.
        ui_silent: Forwarded to ``add_credential``.

    Returns:
        Persisted local credentials as ``[(host, service, username, resolved_cred)]``.
    """

    prepared_locals: list[tuple[str, str, str, str]] = []
    for host, service, username, credential in credentials:
        normalized_host = str(host or "").strip()
        normalized_service = str(service or "").strip()
        normalized_user = str(username or "").strip()
        normalized_credential = str(credential or "").strip()
        if not (
            normalized_host
            and normalized_service
            and normalized_user
            and normalized_credential
        ):
            continue
        prepared_locals.append(
            (
                normalized_host,
                normalized_service,
                normalized_user,
                normalized_credential,
            )
        )

    if not prepared_locals:
        return []

    resolved_pairs = resolve_credential_pairs_for_batch(
        shell,
        credentials=[(user, credential) for _, _, user, credential in prepared_locals],
        skip_hash_cracking=skip_hash_cracking,
        skip_machine_accounts_cracking=True,
    )

    persisted: list[tuple[str, str, str, str]] = []
    for local_entry, resolved_pair in zip(prepared_locals, resolved_pairs):
        host, service, username, _raw_credential = local_entry
        resolved_username, resolved_credential = resolved_pair
        add_credential(
            shell=shell,
            domain=domain,
            user=resolved_username,
            cred=resolved_credential,
            host=host,
            service=service,
            skip_hash_cracking=True,
            source_steps=source_steps,
            prompt_for_user_privs_after=False,
            verify_local_credential=verify_local_credential,
            prompt_local_reuse_after=prompt_local_reuse_after,
            ui_silent=ui_silent,
            ensure_fresh_kerberos_ticket=False,
        )
        persisted.append((host, service, resolved_username, resolved_credential))

    return persisted


def _verify_domain_credentials(
    shell: Any,
    domain: str,
    user: str,
    cred: str,
    *,
    ui_silent: bool,
    source_steps: list[object] | None = None,
) -> bool:
    """Verify credentials with backward-compatible support for `ui_silent`.

    Some test doubles and older wrappers still expose
    `verify_domain_credentials(domain, user, cred)` only.
    """
    try:
        return bool(
            shell.verify_domain_credentials(
                domain,
                user,
                cred,
                ui_silent=ui_silent,
                source_steps=source_steps,
            )
        )
    except TypeError:
        try:
            return bool(shell.verify_domain_credentials(domain, user, cred, ui_silent=ui_silent))
        except TypeError:
            return bool(shell.verify_domain_credentials(domain, user, cred))


def _should_delete_failed_domain_credential(shell: Any) -> bool:
    """Return True only for genuinely invalid credentials that should be purged."""
    from adscan_internal.services.credential_service import CredentialStatus

    last_result = getattr(shell, "_last_domain_credential_verification_result", None)
    status = getattr(last_result, "status", None)
    return status in {
        CredentialStatus.INVALID,
        CredentialStatus.USER_NOT_FOUND,
    }


def _resolve_verified_domain_credential(
    shell: Any,
    *,
    domain: str,
    user: str,
    fallback_credential: str,
) -> str:
    """Return the credential actually validated by the verification flow."""
    verified_domain = getattr(shell, "_last_verified_domain_name", None)
    verified_user = getattr(shell, "_last_verified_domain_username", None)
    verified_credential = getattr(shell, "_last_verified_domain_credential", None)

    if (
        isinstance(verified_credential, str)
        and verified_credential
        and str(verified_domain or "").strip().lower() == domain.strip().lower()
        and str(verified_user or "").strip().lower() == user.strip().lower()
    ):
        return verified_credential
    return fallback_credential


def check_local_creds(
    shell: Any,
    domain_name: str,
    username: str,
    cred_value: str,
    host: str,
    service: str,
) -> bool:
    """Verify host-specific credentials for a service using NetExec via CredentialService."""
    import os

    from rich.panel import Panel

    from adscan_internal import (
        print_error,
        print_exception,
        print_info,
        print_info_debug,
        print_info_verbose,
        print_operation_header,
        print_success,
        print_warning,
    )
    from adscan_internal.rich_output import mark_sensitive
    from adscan_internal.services.credential_service import CredentialStatus

    cred_type = "Hash" if shell.is_hash(cred_value) else "Password"
    print_operation_header(
        "Local Credential Verification",
        details={
            "Domain Context": domain_name,
            "Target Host": host,
            "Service": service.upper(),
            "Username": username,
            cred_type: cred_value,
        },
        icon="🔑",
    )

    auth_string = shell.build_auth_nxc(username, cred_value)
    log_file_path = ""

    if shell.current_workspace_dir:
        log_dir = os.path.join(
            shell.current_workspace_dir, "domains", domain_name, service
        )
        try:
            os.makedirs(log_dir, exist_ok=True)
            log_file_path = os.path.join(
                log_dir, f"check_local_{host}_{service}_{username}.log"
            )
        except OSError as exc:
            telemetry.capture_exception(exc)
            print_error(
                f"Failed to create log directory '{log_dir}': {exc}. "
                "Verification cannot proceed with logging."
            )
            print_warning("Logging to a relative path due to directory creation error.")
            log_file_path = f"check_local_{domain_name}_{host}_{service}_{username}.log"
    else:
        print_warning(
            "Current workspace directory not set. Log file path for NetExec will be relative."
        )
        log_file_path = f"check_local_{domain_name}_{host}_{service}_{username}.log"

    marked_host = mark_sensitive(host, "hostname")
    marked_log_file_path = mark_sensitive(log_file_path, "path")
    print_info_verbose("Executing host credential verification")
    local_timeout_arg = (
        " --smb-timeout 10" if str(service or "").strip().lower() == "smb" else ""
    )
    print_info_debug(
        f"Command: {shell.netexec_path} {service} {marked_host} "
        f'{auth_string}{local_timeout_arg} --log "{marked_log_file_path}"'
    )

    service_obj = shell._get_credential_service()

    try:
        result = service_obj.verify_local_credentials(
            domain=domain_name,
            username=username,
            credential=cred_value,
            host=host,
            service=service,
            netexec_path=shell.netexec_path,
            auth_string=auth_string,
            log_file_path=log_file_path,
            executor=lambda cmd, timeout: shell._run_netexec(
                cmd, domain=domain_name, timeout=timeout
            ),
        )
    except Exception as exc:  # pylint: disable=broad-except
        telemetry.capture_exception(exc)
        print_error(
            f"An unexpected error occurred during host credential verification: {exc}"
        )
        print_exception(show_locals=False, exception=exc)
        return False

    status = result.status
    marked_username = mark_sensitive(username, "user")
    marked_host = mark_sensitive(host, "hostname")

    if status == CredentialStatus.VALID:
        if result.is_admin:
            print_success(
                f"User '[bold]{marked_username}[/bold]' has "
                f"[bold red]ADMIN[/bold red] access to [bold]{marked_host}[/bold] "
                f"via [bold]{service}[/bold]!"
            )
        else:
            print_info_verbose(
                f"Successfully verified credentials for user "
                f"'[bold]{marked_username}[/bold]' on host "
                f"'[bold]{marked_host}[/bold]' via [bold]{service}[/bold] "
                "(non-admin access)."
            )
        return True

    if status == CredentialStatus.INVALID:
        print_error(
            f"Logon failure for local user '[bold]{marked_username}[/bold]' on "
            f"host '[bold]{marked_host}[/bold]' via [bold]{service}[/bold]. "
            "Incorrect credentials."
        )
        print_info("Trying with domain credentials instead...")
        shell.add_credential(domain_name, username, cred_value)
        return False

    if status == CredentialStatus.ACCOUNT_LOCKED:
        print_error(
            f"Account locked out for user '[bold]{marked_username}[/bold]' on "
            f"host '[bold]{marked_host}[/bold]'."
        )
        return False

    if status == CredentialStatus.ACCOUNT_DISABLED:
        print_error(
            f"Account disabled for user '[bold]{marked_username}[/bold]' on "
            f"host '[bold]{marked_host}[/bold]'."
        )
        return False

    if status == CredentialStatus.PASSWORD_EXPIRED:
        print_warning(
            f"Password expired for user '[bold]{marked_username}[/bold]' on "
            f"host '[bold]{marked_host}[/bold]'. Verification failed as the password needs to be changed."
        )
        return False

    if status == CredentialStatus.ACCOUNT_RESTRICTION:
        print_error(
            f"Account restricted for user '[bold]{marked_username}[/bold]' on "
            f"host '[bold]{marked_host}[/bold]'."
        )
        return False

    if status == CredentialStatus.TIMEOUT:
        print_error(
            f"Host credential verification command timed out for user "
            f"'[bold]{marked_username}[/bold]' on '[bold]{marked_host}[/bold]' "
            f"via [bold]{service}[/bold]."
        )
        return False

    if status == CredentialStatus.USER_NOT_FOUND:
        print_error(
            f"User '[bold]{marked_username}[/bold]' not found on host "
            f"'[bold]{marked_host}[/bold]'."
        )
        return False

    print_error(
        f"Host credential verification failed for user '[bold]{marked_username}[/bold]' "
        f"on '[bold]{marked_host}[/bold]' via [bold]{service}[/bold]. NetExec output did not indicate clear success or a known failure."
    )

    secret_mode = getattr(shell, "SECRET_MODE", False)
    if result.raw_output and secret_mode:
        shell.console.print(
            Panel(
                result.raw_output.strip(),
                title=f"NXC Output for {username}@{host} ({service})",
                border_style="dim red",
                expand=False,
            )
        )

    return False


def is_hash(cred: str) -> bool:
    """Check if a credential is an NTLM hash.

    Args:
        cred: Credential string to check

    Returns:
        True if the credential is a 32-character hexadecimal NTLM hash, False otherwise
    """
    return len(cred) == 32 and all(c in "0123456789abcdef" for c in cred.lower())


def save_ntlm_hash(
    shell: Any, domain: str, hash_version: str, user: str, hash_value: str
) -> bool:
    """Save an NTLM hash to the cracking directory, avoiding duplicates per user.

    Args:
        shell: The PentestShell instance with workspace directories
        domain: Domain name
        hash_version: Hash version (e.g., 'v1', 'v2')
        user: Username
        hash_value: Hash value to save

    Returns:
        True if the user is new (hash was added), False if the user already exists
    """
    from adscan_internal import print_error, print_exception
    from adscan_internal.workspaces import domain_subpath

    try:
        # Create directory if it does not exist
        workspace_cwd = shell.current_workspace_dir or os.getcwd()
        cracking_dir = domain_subpath(
            workspace_cwd, shell.domains_dir, domain, shell.cracking_dir
        )
        if not os.path.exists(cracking_dir):
            os.makedirs(cracking_dir)

        # Path of the hash file
        hash_file = os.path.join(cracking_dir, f"{user}_hashes.NTLM{hash_version}")

        # Check if a hash for this user already exists
        if os.path.exists(hash_file):
            with open(hash_file, "r", encoding="utf-8") as f:
                existing_content = f.read()
                if user in existing_content:
                    return False  # User already has a saved hash

        # If we reach here, the user is new or the file did not exist
        with open(hash_file, "a", encoding="utf-8") as f:
            f.write(f"{user}:{hash_value}\n")
        return True  # New hash added

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error saving hash.")
        print_exception(show_locals=False, exception=e)
        return False


def return_credentials(shell: Any, domain: str) -> tuple[str | None, str | None]:
    """Allow selecting a user and return their credentials.

    Args:
        shell: The PentestShell instance with domains_data
        domain: The domain from which to select credentials

    Returns:
        tuple: (username, password) if a valid user is selected, (None, None) otherwise
    """
    if (
        domain not in shell.domains_data
        or "credentials" not in shell.domains_data[domain]
    ):
        print_error("No credentials available for selection")
        return None, None

    user_list = list(shell.domains_data[domain]["credentials"].keys())
    shell.console.print("\nAvailable users:")
    for idx, user in enumerate(user_list):
        shell.console.print(f"{idx + 1}. {user}")

    try:
        selected_idx = int(Prompt.ask("\nSelect a user by number: ")) - 1
        if 0 <= selected_idx < len(user_list):
            selected_user = user_list[selected_idx]
            selected_cred = shell.domains_data[domain]["credentials"][selected_user]
            return selected_user, selected_cred
        print_error("Invalid selection")
        return None, None

    except ValueError as e:
        telemetry.capture_exception(e)
        print_error("Please enter a valid number")
        return None, None


def extract_creds_from_hash(file_path: str) -> dict[str, str] | None:
    """Extract credentials from a hash file.

    Args:
        file_path: Path to the hash file

    Returns:
        Dictionary mapping usernames to passwords/hashes, or None on error
    """
    creds = {}  # Dictionary to store credentials
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()  # Remove whitespace and newline characters
                if line:  # Check that the line is not empty
                    parts = line.split(":")  # Split the line using ":" delimiter
                    if (
                        len(parts) >= 2
                    ):  # Check that there is at least a username and a password
                        username = parts[0]
                        password = parts[1]
                        creds[username] = (
                            password  # Add the username:password pair to the dictionary
                        )
        return creds
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error extracting credentials from the file.")
        from adscan_internal import print_exception

        print_exception(show_locals=False, exception=e)
        return None


def extract_credentials(shell: Any, output_str: str, domain: str) -> None:
    """Extract credentials from output string using regex pattern.

    Args:
        shell: The PentestShell instance with add_credential method
        output_str: Output string to search for credentials
        domain: Domain name for the credentials
    """
    from adscan_internal.rich_output import mark_sensitive
    from adscan_internal import print_success

    match = re.search(
        r"([^/\\]+):\d+:(aad3b435b51404ee[a-zA-Z0-9]{32}|[^\:]+):([a-f0-9]*):",
        output_str,
    )
    if match:
        user = match.group(1)
        credential = match.group(2)
        shell.add_credential(domain, user, credential)
        marked_user = mark_sensitive(user, "user")
        marked_credential = mark_sensitive(credential, "password")
        print_success(
            f"Credential found: User: {marked_user}, Credential: {marked_credential}"
        )


def select_password_for_spraying(
    shell: Any, passwords: list[tuple], auto_mode: bool = False
) -> str | None:
    """Allow user to select a password for password spraying using shell helper.

    Passwords are sorted by ML confidence (highest first).
    In auto mode, automatically selects the password with highest ML confidence.

    Args:
        passwords: List of tuples (password, ml_probability, context_line, line_num, file_path)
        auto_mode: If True, automatically select highest confidence password

    Returns:
        Selected password string, or None if cancelled
    """
    if not passwords:
        return None

    # Sort by ML confidence (highest first)
    # Handle None values by treating them as 0.0 for sorting
    passwords_sorted = sorted(
        passwords,
        key=lambda x: float(x[1]) if x[1] is not None else 0.0,
        reverse=True,
    )

    # In auto mode, return the password with highest ML confidence
    if auto_mode:
        return passwords_sorted[0][0]

    # Create choices for questionary
    choices = []
    for idx, (password, ml_prob, context_line, line_num, file_path) in enumerate(
        passwords_sorted
    ):
        # Truncate password for display
        if password is None:
            display_password = ""
        elif isinstance(password, str):
            display_password = password[:40] + "..." if len(password) > 43 else password
        else:
            display_password = (
                str(password)[:40] + "..." if len(str(password)) > 43 else str(password)
            )

        # Handle ml_prob safely (can be None or non-numeric)
        if ml_prob is None:
            ml_display = "N/A"
        else:
            try:
                ml_display = f"{float(ml_prob):.2%}"
            except (ValueError, TypeError):
                ml_display = "N/A"

        # Create choice string
        choice_text = f"{display_password:<45} [ML: {ml_display:>8}]"
        choices.append(choice_text)
    choices.append("Skip automated spraying")

    try:
        selected_idx = shell._questionary_select(
            "Select a password for password spraying (sorted by ML confidence):",
            choices,
            default_idx=0,
        )

        if selected_idx is None:
            return None
        if selected_idx >= len(passwords_sorted):
            return None

        return passwords_sorted[selected_idx][0]

    except KeyboardInterrupt:
        return None
    except Exception as e:
        telemetry.capture_exception(e)
        print_warning(f"Error in password selection: {e}")
        # Fallback to highest confidence password
        return passwords_sorted[0][0]


def looks_like_cpassword_value(value: str | None) -> bool:
    """Heuristic check to determine if a string resembles a cpassword.

    Args:
        value: String to check

    Returns:
        True if the string looks like a cpassword value, False otherwise
    """
    if not value:
        return False
    candidate = value.strip()
    if len(candidate) < 20 or len(candidate) % 4 != 0:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/=]+", candidate))


def read_line_from_file(file_path: str | None, line_num: int | None) -> str | None:
    """Return a specific line from file, stripping newline.

    Args:
        file_path: Path to the file
        line_num: Line number to read (1-based)

    Returns:
        The line content without newline, or None on error
    """
    if not file_path or not line_num:
        return None
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
            for current_line, line in enumerate(handle, start=1):
                if current_line == line_num:
                    return line.strip()
    except OSError:
        return None
    return None


def decrypt_cpassword(cpassword: str) -> str | None:
    """Decrypt a GPP cpassword value using gpp-decrypt library (bundled).

    Args:
        cpassword: The cpassword string extracted from GPP XML.

    Returns:
        The decrypted password, or None on failure.
    """
    from adscan_internal import print_info, print_error, print_exception

    print_info("Decrypting the password with gpp-decrypt")
    try:
        from gpp_decrypt import decrypt_password

        normalized_cpassword = "".join(str(cpassword).split())
        decrypted = decrypt_password(  # type: ignore[no-untyped-call]
            normalized_cpassword
        )
        decrypted_str = str(decrypted or "")

        # gpp-decrypt currently returns UTF-16LE text with PKCS#7 padding
        # artifacts (e.g. repeated U+0C0C) for some passwords.
        decrypted_str = decrypted_str.rstrip("\x00")
        while decrypted_str:
            last_ord = ord(decrypted_str[-1])
            low = last_ord & 0xFF
            high = (last_ord >> 8) & 0xFF
            if low == high and 1 <= low <= 16:
                decrypted_str = decrypted_str[:-1]
            else:
                break

        if decrypted_str:
            return decrypted_str.strip() or None
        return None
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Error decrypting cpassword with gpp-decrypt.")
        print_exception(show_locals=False, exception=exc)
        return None


def process_cpassword_text(
    shell: Any,
    text: str,
    domain: str,
    source: str | None = None,
    source_hosts: list[str] | None = None,
    source_shares: list[str] | None = None,
    auth_username: str | None = None,
) -> bool:
    """Extract and decrypt cpassword entries from arbitrary text content.

    Args:
        shell: The PentestShell instance with add_credential method
        text: Text content to search for cpassword entries
        domain: Domain name for credential storage
        source: Optional source description for logging
    Returns:
        True if any cpassword entries were found and processed, False otherwise
    """
    from adscan_internal import print_success, print_warning

    if not text:
        return False

    source_label = f" ({source})" if source else ""
    entries: list[tuple[str | None, str]] = []

    entry_pattern = re.compile(
        r'(?is)(?:userName="(?P<user>[^"]+)".*?cpassword="(?P<pass>[^"]+)"|cpassword="(?P<pass_alt>[^"]+)".*?userName="(?P<user_alt>[^"]+)")'
    )

    for match in entry_pattern.finditer(text):
        username = match.group("user") or match.group("user_alt")
        cpassword_value = match.group("pass") or match.group("pass_alt")
        if cpassword_value:
            entries.append((username, cpassword_value))

    if not entries:
        standalone_pattern = re.compile(r'cpassword="([^"]+)"', re.IGNORECASE)
        entries = [(None, value) for value in standalone_pattern.findall(text)]

    if not entries:
        return False

    seen_values = set()
    report_updated = False
    report_recorded = False
    for username, cpassword_value in entries:
        cpassword_value = cpassword_value.strip()
        if not cpassword_value or cpassword_value in seen_values:
            continue
        seen_values.add(cpassword_value)
        if not report_updated:
            shell.update_report_field(domain, "gpp_passwords", True)
            report_updated = True
        if not report_recorded:
            try:
                from adscan_internal.services.report_service import (
                    record_technical_finding,
                )

                record_technical_finding(
                    shell,
                    domain,
                    key="gpp_passwords",
                    value=True,
                    details={
                        "source": source,
                        "cpassword_count": len(entries),
                    },
                    evidence=[
                        {
                            "type": "artifact",
                            "summary": "GPP cpassword source",
                            "artifact_path": source,
                        }
                    ]
                    if source
                    else None,
                )
                report_recorded = True
            except Exception as exc:  # pragma: no cover
                telemetry.capture_exception(exc)

        print_success(f"cpassword found{source_label}: {cpassword_value}")
        plaintext_password = decrypt_cpassword(cpassword_value)
        if not plaintext_password:
            print_warning(f"Failed to decrypt cpassword{source_label}.")
            continue

        if username:
            normalized_user = username.split("\\")[-1]
            shell.username = normalized_user
            print_success(f"Username: {normalized_user}")
            shell.password = plaintext_password
            print_success(f"Password: {plaintext_password}")
            try:
                from adscan_internal.services.share_credential_provenance_service import (
                    ShareCredentialProvenanceService,
                )

                provenance_service = ShareCredentialProvenanceService()
                source_steps = provenance_service.build_credential_source_steps(
                    relation="GPPPassword",
                    edge_type="gpp_password",
                    source="gpp_cpassword",
                    secret=plaintext_password,
                    hosts=source_hosts,
                    shares=source_shares,
                    artifact=source or None,
                    auth_username=auth_username,
                    origin="share_spidering",
                )
                if source_hosts or source_shares:
                    marked_hosts = (
                        [mark_sensitive(h, "hostname") for h in source_hosts]
                        if source_hosts
                        else []
                    )
                    marked_shares = (
                        [mark_sensitive(s, "path") for s in source_shares]
                        if source_shares
                        else []
                    )
                    print_info_debug(
                        "GPP credential context: "
                        f"hosts={marked_hosts or 'N/A'} shares={marked_shares or 'N/A'}"
                    )
                add_credential(
                    shell,
                    domain,
                    normalized_user,
                    plaintext_password,
                    source_steps=source_steps,
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                add_credential(shell, domain, normalized_user, plaintext_password)
        else:
            print_success(f"Decrypted password{source_label}: {plaintext_password}")

    return True


def filter_cpassword_credentials(
    shell: Any,
    credentials_list: list[tuple],
    domain: str,
    *,
    source_hosts: list[str] | None = None,
    source_shares: list[str] | None = None,
    auth_username: str | None = None,
) -> list[tuple]:
    """Remove cpassword entries from credential candidates and process them separately.

    Args:
        shell: The PentestShell instance with helper methods
        credentials_list: List of credential tuples (value, ml_prob, context_line, line_num, file_path)
        domain: Domain name

    Returns:
        Filtered list of credentials with cpassword entries removed
    """
    from adscan_internal import print_info, print_warning

    filtered_credentials: list[tuple] = []

    for cred_tuple in credentials_list:
        if len(cred_tuple) < 5:
            filtered_credentials.append(cred_tuple)
            continue

        value, ml_prob, context_line, line_num, file_path = cred_tuple
        context_text = context_line or read_line_from_file(file_path, line_num)
        snippet = context_text or ""

        is_cpassword_candidate = False
        if snippet and "cpassword" in snippet.lower():
            is_cpassword_candidate = True
        elif looks_like_cpassword_value(value):
            is_cpassword_candidate = True

        if is_cpassword_candidate:
            source_desc = None
            if file_path:
                source_desc = file_path
                if line_num:
                    source_desc = f"{file_path}:{line_num}"

            snippet_for_processing = snippet if "cpassword" in snippet.lower() else None
            if not snippet_for_processing:
                snippet_for_processing = f'cpassword="{value}"'

            print_info(
                "Detected potential Group Policy cpassword in share results. "
                "Decrypting and storing it instead of using it for password spraying."
            )
            processed = process_cpassword_text(
                shell,
                snippet_for_processing,
                domain,
                source_desc,
                source_hosts=source_hosts,
                source_shares=source_shares,
                auth_username=auth_username,
            )
            if not processed:
                print_warning(
                    "Unable to extract cpassword details automatically. "
                    "Review the spidering logs manually."
                )
            continue

        filtered_credentials.append(cred_tuple)

    return filtered_credentials


def normalize_credsweeper_ml_probability(value: Any) -> float | None:
    """Normalize CredSweeper ML probability values into a bounded float."""
    if value is None:
        return None
    try:
        normalized = float(value)
    except (TypeError, ValueError):
        return None
    if normalized < 0.0:
        return 0.0
    if normalized > 1.0:
        return 1.0
    return normalized


def is_sprayable_credsweeper_candidate(rule_name: str, cred_tuple: tuple) -> bool:
    """Return whether one CredSweeper finding is eligible for automated spraying."""
    if len(cred_tuple) < 2:
        return False
    value = str(cred_tuple[0] or "").strip()
    if not value:
        return False
    normalized_rule = str(rule_name or "").strip().casefold()
    if normalized_rule in NON_SPRAYABLE_CREDSWEEPER_RULES:
        return False
    if UUID_VALUE_RE.fullmatch(value):
        return False
    if normalize_credsweeper_ml_probability(cred_tuple[1]) is None:
        return False
    return True


def deduplicate_credential_entries_for_spraying(
    credential_entries: list[tuple[str, tuple]],
) -> list[tuple[str, tuple]]:
    """Deduplicate findings by value, preferring sprayable/high-confidence entries."""
    deduplicated: dict[str, tuple[str, tuple]] = {}
    for rule_name, cred_tuple in credential_entries:
        value = str(cred_tuple[0] or "").strip()
        if not value:
            continue
        existing = deduplicated.get(value)
        current_rank = (
            1 if is_sprayable_credsweeper_candidate(rule_name, cred_tuple) else 0,
            normalize_credsweeper_ml_probability(cred_tuple[1]) or 0.0,
        )
        if existing is None:
            deduplicated[value] = (rule_name, cred_tuple)
            continue
        existing_rule, existing_tuple = existing
        existing_rank = (
            1 if is_sprayable_credsweeper_candidate(existing_rule, existing_tuple) else 0,
            normalize_credsweeper_ml_probability(existing_tuple[1]) or 0.0,
        )
        if current_rank > existing_rank:
            deduplicated[value] = (rule_name, cred_tuple)
    return list(deduplicated.values())


def filter_sprayable_credential_entries(
    credential_entries: list[tuple[str, tuple]],
) -> tuple[list[tuple], int]:
    """Filter one deduplicated finding set down to spraying-eligible credentials."""
    sprayable: list[tuple] = []
    skipped = 0
    for rule_name, cred_tuple in credential_entries:
        if is_sprayable_credsweeper_candidate(rule_name, cred_tuple):
            sprayable.append(cred_tuple)
        else:
            skipped += 1
    return sprayable, skipped


def display_credentials_with_rich(
    shell: Any,
    credentials: dict,
    *,
    presentation: CredentialPresentationOptions | None = None,
) -> None:
    """Display all found credentials in a structured, aesthetic format using Rich.

    Organized by credential type with ML confidence scores.

    Args:
        shell: The PentestShell instance with console
        credentials: Dictionary of credentials organized by type
    """
    if not credentials:
        return

    presentation = presentation or CredentialPresentationOptions()

    # Create panels for each credential type
    panels = []

    # Sort credential types alphabetically
    sorted_types = sorted(credentials.keys())

    for cred_type in sorted_types:
        creds_list = credentials[cred_type]
        if not creds_list:
            continue

        creds_list_sorted = aggregate_credentials_for_display(creds_list)

        # Create table for this credential type
        unique_count = len(creds_list_sorted)
        total_count = len(creds_list)
        title = f"{cred_type} ({unique_count} unique)"
        if total_count != unique_count:
            title = f"{cred_type} ({total_count} found, {unique_count} unique)"
        table = Table(
            title=title,
            show_header=True,
            header_style="bold magenta",
            expand=True,
        )
        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("Value", style="cyan", no_wrap=False, max_width=72, overflow="ellipsis")
        if presentation.confidence_label:
            table.add_column(
                presentation.confidence_label,
                style="green",
                justify="right",
                width=12,
            )
        table.add_column("Seen", style="magenta", justify="right", width=6)
        table.add_column(
            presentation.source_column_label,
            style="dim",
            no_wrap=False,
            max_width=110,
            overflow="fold",
        )

        for idx, (
            value,
            ml_prob,
            context_line,
            line_num,
            file_path,
            occurrence_count,
            sources,
        ) in enumerate(
            creds_list_sorted, 1
        ):
            if value is None:
                display_value = ""
            elif isinstance(value, str):
                display_value = value
            else:
                display_value = str(value)

            # Handle ml_prob safely (can be None or non-numeric)
            if ml_prob is None:
                ml_display = "N/A"
            else:
                try:
                    ml_display = f"{float(ml_prob):.2%}"
                except (ValueError, TypeError):
                    ml_display = "N/A"

            row = [
                str(idx),
                display_value,
            ]
            if presentation.confidence_label:
                row.append(ml_display)
            row.extend(
                [
                    str(occurrence_count),
                    summarize_credential_sources(shell, sources) or "N/A",
                ]
            )
            table.add_row(*row)

        panels.append(Panel(table, border_style="blue"))

    # Display all panels
    shell.console.print()
    for panel in panels:
        shell.console.print(panel)
        shell.console.print()


def display_credential_path_lookup_with_rich(
    shell: Any,
    aggregated_credentials: dict[
        str,
        list[tuple[Any, Any, Any, Any, Any, int, list[tuple[str, int | None]]]],
    ],
) -> None:
    """Display one row-aligned remote/local source lookup table for each credential type."""
    if not aggregated_credentials:
        return

    panels: list[Panel] = []
    for cred_type in sorted(aggregated_credentials.keys()):
        rows = aggregated_credentials.get(cred_type) or []
        if not rows:
            continue
        table = Table(
            title=f"{cred_type} Source Paths",
            show_header=True,
            header_style="bold cyan",
            expand=True,
        )
        table.add_column("Row", style="dim", width=4, justify="right")
        table.add_column(
            "Remote",
            style="white",
            no_wrap=False,
            overflow="fold",
        )
        table.add_column(
            "Local copy",
            style="cyan",
            no_wrap=False,
            overflow="fold",
        )
        for idx, row in enumerate(rows, 1):
            sources = row[6]
            remote_sources = [
                _format_credential_source(shell, file_path=path, line_num=line_num)
                for path, line_num in sources
                if str(path or "").strip()
            ]
            local_sources = [
                _format_local_credential_source(shell, file_path=path, line_num=line_num)
                for path, line_num in sources
                if str(path or "").strip()
            ]
            table.add_row(
                str(idx),
                mark_sensitive(remote_sources[0], "path") if remote_sources else "N/A",
                mark_sensitive(local_sources[0], "path") if local_sources else "N/A",
            )
        panels.append(Panel(table, border_style="cyan"))

    if not panels:
        return
    print_info("Full remote/local source paths for the credential rows above:")
    shell.console.print()
    for panel in panels:
        shell.console.print(panel)
        shell.console.print()


def aggregate_credentials_for_display(
    creds_list: list[tuple[Any, Any, Any, Any, Any]],
) -> list[tuple[Any, Any, Any, Any, Any, int, list[tuple[str, int | None]]]]:
    """Aggregate duplicate credential values for table display.

    Duplicates are grouped by credential value. The representative entry keeps
    the highest ML-confidence occurrence while tracking how many times the same
    value appeared across files/lines.
    """
    aggregated: dict[str, dict[str, Any]] = {}
    for value, ml_prob, context_line, line_num, file_path in creds_list:
        normalized_value = str(value or "").strip()
        if not normalized_value:
            continue
        source_desc = build_credential_source_display(file_path, line_num)
        existing = aggregated.get(normalized_value)
        if existing is None:
            aggregated[normalized_value] = {
                "value": value,
                "ml_prob": ml_prob,
                "context_line": context_line,
                "line_num": line_num,
                "file_path": file_path,
                "occurrence_count": 1,
                "sources": [source_desc] if source_desc else [],
            }
            continue

        current_ml = normalize_credsweeper_ml_probability(ml_prob) or 0.0
        existing_ml = normalize_credsweeper_ml_probability(existing["ml_prob"]) or 0.0
        existing["occurrence_count"] = int(existing["occurrence_count"]) + 1
        if source_desc and source_desc not in existing["sources"]:
            existing["sources"].append(source_desc)
        if current_ml > existing_ml:
            existing["value"] = value
            existing["ml_prob"] = ml_prob
            existing["context_line"] = context_line
            existing["line_num"] = line_num
            existing["file_path"] = file_path

    return sorted(
        [
            (
                item["value"],
                item["ml_prob"],
                item["context_line"],
                item["line_num"],
                item["file_path"],
                int(item["occurrence_count"]),
                list(item["sources"]),
            )
            for item in aggregated.values()
        ],
        key=lambda item: (
            normalize_credsweeper_ml_probability(item[1]) or 0.0,
            item[5],
            str(item[0] or ""),
        ),
        reverse=True,
    )


def aggregate_credentials_by_type(
    credentials: dict[str, list[tuple[Any, Any, Any, Any, Any]]],
) -> dict[str, list[tuple[Any, Any, Any, Any, Any, int, list[tuple[str, int | None]]]]]:
    """Aggregate CredSweeper findings by credential type for downstream UX/reporting."""
    aggregated: dict[
        str,
        list[tuple[Any, Any, Any, Any, Any, int, list[tuple[str, int | None]]]],
    ] = {}
    for cred_type, creds_list in credentials.items():
        if not creds_list:
            continue
        aggregated[cred_type] = aggregate_credentials_for_display(creds_list)
    return aggregated


def build_credential_source_display(
    file_path: Any,
    line_num: Any,
) -> tuple[str, int | None] | None:
    """Build one normalized source tuple for one credential occurrence."""
    normalized_path = str(file_path or "").strip()
    if not normalized_path:
        return None
    if line_num is None:
        return (normalized_path, None)
    try:
        return (normalized_path, int(line_num))
    except (TypeError, ValueError):
        return (normalized_path, None)


def _get_workspace_root(shell: Any) -> str:
    """Return the current workspace root when available."""
    workspace_root = str(getattr(shell, "current_workspace_dir", "") or "").strip()
    if workspace_root:
        return os.path.abspath(workspace_root)
    workspace_cwd_getter = getattr(shell, "_get_workspace_cwd", None)
    if callable(workspace_cwd_getter):
        workspace_root = str(workspace_cwd_getter() or "").strip()
    return os.path.abspath(workspace_root) if workspace_root else ""


def _relativize_credential_loot_path(shell: Any, file_path: str) -> str:
    """Return a workspace-relative loot path when possible."""
    normalized_path = os.path.abspath(str(file_path or "").strip())
    workspace_root = _get_workspace_root(shell)
    if workspace_root:
        try:
            common = os.path.commonpath([workspace_root, normalized_path])
        except ValueError:
            common = ""
        if common == workspace_root:
            return os.path.relpath(normalized_path, workspace_root)
    return normalized_path


def _derive_credential_origin_path(file_path: str) -> str:
    """Derive a logical remote/source path from a local loot path when possible."""
    raw_path = str(file_path or "").strip()
    normalized = raw_path.replace("\\", "/")
    if not normalized:
        return ""

    if "!/" in normalized:
        outer_path, internal_path = normalized.split("!/", 1)
        outer_origin = _derive_credential_origin_path(outer_path)
        if outer_origin:
            return f"{outer_origin}!/{internal_path}"
        return f"{outer_path}!/{internal_path}"

    if "/winrm/sensitive/" in normalized and "/loot/" in normalized:
        relative = normalized.split("/loot/", 1)[1].strip("/")
        parts = [part for part in relative.split("/") if part]
        if parts:
            drive = ""
            remainder = parts
            if parts[0].endswith("_drive"):
                drive = parts[0].split("_drive", 1)[0].upper() + ":"
                remainder = parts[1:]
            remote_tail = "\\".join(remainder)
            if drive and remote_tail:
                return f"WinRM {drive}\\{remote_tail}"
            if drive:
                return f"WinRM {drive}\\"

    if "/smb/rclone/" in normalized and "/loot/" in normalized:
        relative = normalized.split("/loot/", 1)[1].strip("/")
        parts = [part for part in relative.split("/") if part]
        if len(parts) >= 2:
            host, share = parts[0], parts[1]
            remote_tail = "/".join(parts[2:])
            if remote_tail:
                return f"SMB {host}/{share}/{remote_tail}"
            return f"SMB {host}/{share}"

    if "/smb/cifs/mounts/" in normalized:
        relative = normalized.split("/smb/cifs/mounts/", 1)[1].strip("/")
        parts = [part for part in relative.split("/") if part]
        if len(parts) >= 2:
            host, share = parts[0], parts[1]
            remote_tail = "/".join(parts[2:])
            if remote_tail:
                return f"SMB {host}/{share}/{remote_tail}"
            return f"SMB {host}/{share}"

    return ""


def _format_local_credential_source(
    shell: Any,
    *,
    file_path: str,
    line_num: int | None,
) -> str:
    """Format one local loot source path for fast manual review."""
    line_suffix = f":{line_num}" if isinstance(line_num, int) and line_num > 0 else ""
    relative_path = _relativize_credential_loot_path(shell, file_path)
    return f"{relative_path}{line_suffix}"


def _format_credential_source(
    shell: Any,
    *,
    file_path: str,
    line_num: int | None,
) -> str:
    """Format one credential source for display."""
    line_suffix = f":{line_num}" if isinstance(line_num, int) and line_num > 0 else ""
    origin = _derive_credential_origin_path(file_path)
    if origin:
        return f"{origin}{line_suffix}"
    relative_path = _relativize_credential_loot_path(shell, file_path)
    return f"{relative_path}{line_suffix}"


def summarize_credential_sources(
    shell: Any,
    sources: list[tuple[str, int | None]],
    *,
    max_items: int = 3,
) -> str:
    """Return a compact preview of canonical review paths for one credential value."""
    normalized_sources = [
        _format_local_credential_source(shell, file_path=path, line_num=line_num)
        for path, line_num in sources
        if str(path or "").strip()
    ]
    if not normalized_sources:
        return ""
    preview_items = normalized_sources[:max_items]
    preview = ", ".join(mark_sensitive(item, "path") for item in preview_items)
    remaining = len(normalized_sources) - len(preview_items)
    if remaining > 0:
        preview = f"{preview}, +{remaining} more"
    return preview


def summarize_local_credential_sources(
    shell: Any,
    sources: list[tuple[str, int | None]],
    *,
    max_items: int = 2,
) -> str:
    """Return a compact preview of local loot paths for manual review."""
    normalized_sources = [
        _format_local_credential_source(shell, file_path=path, line_num=line_num)
        for path, line_num in sources
        if str(path or "").strip()
    ]
    deduplicated_sources = list(dict.fromkeys(normalized_sources))
    if not deduplicated_sources:
        return ""
    preview_items = deduplicated_sources[:max_items]
    preview = ", ".join(mark_sensitive(item, "path") for item in preview_items)
    remaining = len(deduplicated_sources) - len(preview_items)
    if remaining > 0:
        preview = f"{preview}, +{remaining} more"
    return preview


def save_aggregated_credential_review_reports(
    shell: Any,
    aggregated_credentials: dict[
        str,
        list[tuple[Any, Any, Any, Any, Any, int, list[tuple[str, int | None]]]],
    ],
    *,
    base_dir: str = "smb/spidering",
) -> dict[str, str]:
    """Persist enriched per-type review reports with remote and local source paths."""
    saved_files: dict[str, str] = {}
    if not aggregated_credentials:
        return saved_files

    os.makedirs(base_dir, exist_ok=True)
    for cred_type, rows in aggregated_credentials.items():
        if not rows:
            continue
        safe_type_name = cred_type.lower().replace(" ", "_").replace("/", "_")
        file_path = os.path.join(base_dir, f"{safe_type_name}.review.json")
        entries: list[dict[str, Any]] = []
        for idx, (
            value,
            ml_prob,
            context_line,
            line_num,
            file_path_orig,
            occurrence_count,
            sources,
        ) in enumerate(rows, 1):
            entries.append(
                {
                    "index": idx,
                    "value": value,
                    "ml_confidence": ml_prob,
                    "context_line": context_line,
                    "line_number": line_num,
                    "representative_source_file": file_path_orig,
                    "seen": occurrence_count,
                    "remote_sources": [
                        _format_credential_source(shell, file_path=path, line_num=source_line_num)
                        for path, source_line_num in sources
                        if str(path or "").strip()
                    ],
                    "local_sources": [
                        _format_local_credential_source(shell, file_path=path, line_num=source_line_num)
                        for path, source_line_num in sources
                        if str(path or "").strip()
                    ],
                }
            )
        try:
            with open(file_path, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "credential_type": cred_type,
                        "count": len(entries),
                        "entries": entries,
                    },
                    handle,
                    indent=2,
                    ensure_ascii=False,
                )
            saved_files[cred_type] = file_path
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_warning(
                f"Error saving local review report for {cred_type} credentials: {exc}"
            )
    return saved_files


def save_aggregated_credential_review_indexes(
    shell: Any,
    aggregated_credentials: dict[
        str,
        list[tuple[Any, Any, Any, Any, Any, int, list[tuple[str, int | None]]]],
    ],
    *,
    base_dir: str = "smb/spidering",
) -> dict[str, str]:
    """Persist one TSV index per credential type for quick terminal-based review."""
    saved_files: dict[str, str] = {}
    if not aggregated_credentials:
        return saved_files

    os.makedirs(base_dir, exist_ok=True)
    for cred_type, rows in aggregated_credentials.items():
        if not rows:
            continue
        safe_type_name = cred_type.lower().replace(" ", "_").replace("/", "_")
        file_path = os.path.join(base_dir, f"{safe_type_name}.review.tsv")
        try:
            with open(file_path, "w", encoding="utf-8") as handle:
                handle.write(
                    "\t".join(
                        [
                            "index",
                            "value",
                            "ml_confidence",
                            "seen",
                            "primary_remote_source",
                            "primary_local_source",
                        ]
                    )
                    + "\n"
                )
                for idx, row in enumerate(rows, 1):
                    remote_sources = [
                        _format_credential_source(shell, file_path=path, line_num=line_num)
                        for path, line_num in row[6]
                        if str(path or "").strip()
                    ]
                    local_sources = [
                        _format_local_credential_source(shell, file_path=path, line_num=line_num)
                        for path, line_num in row[6]
                        if str(path or "").strip()
                    ]
                    handle.write(
                        "\t".join(
                            [
                                str(idx),
                                str(row[0] or ""),
                                str(row[1] if row[1] is not None else ""),
                                str(int(row[5] or 0)),
                                remote_sources[0] if remote_sources else "",
                                local_sources[0] if local_sources else "",
                            ]
                        )
                        + "\n"
                    )
            saved_files[cred_type] = file_path
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_warning(
                f"Error saving local review index for {cred_type} credentials: {exc}"
            )
    return saved_files


def display_local_credential_review_paths(
    shell: Any,
    aggregated_credentials: dict[
        str,
        list[tuple[Any, Any, Any, Any, Any, int, list[tuple[str, int | None]]]],
    ],
    *,
    preview_limit: int = 12,
) -> None:
    """Render compact local review tables keyed to the main credential row numbers."""
    panels: list[Panel] = []
    for cred_type in sorted(aggregated_credentials.keys()):
        rows = aggregated_credentials.get(cred_type) or []
        if not rows or len(rows) > preview_limit:
            continue
        table = Table(
            title=f"{cred_type} Review Paths",
            show_header=True,
            header_style="bold cyan",
            expand=True,
        )
        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("Primary Path", style="white", no_wrap=False, max_width=110, overflow="fold")
        table.add_column("Copies", style="magenta", justify="right", width=6)
        for idx, row in enumerate(rows, 1):
            local_preview = summarize_local_credential_sources(shell, row[6], max_items=1) or "N/A"
            table.add_row(str(idx), local_preview, str(int(row[5] or 0)))
        panels.append(Panel(table, border_style="cyan"))

    if not panels:
        return
    print_info("Review paths for the credential rows above:")
    shell.console.print()
    for panel in panels:
        shell.console.print(panel)
        shell.console.print()


def save_credentials_to_files(
    credentials: dict, base_dir: str = "smb/spidering"
) -> dict[str, str]:
    """Save credentials to JSON files organized by category.

    Each credential type gets its own file.

    Args:
        credentials: Dictionary of credentials organized by type
        base_dir: Base directory to save credential files

    Returns:
        Dictionary mapping credential types to file paths where they were saved
    """
    saved_files = {}

    if not credentials:
        return saved_files

    # Ensure directory exists
    os.makedirs(base_dir, exist_ok=True)

    for cred_type, creds_list in credentials.items():
        if not creds_list:
            continue

        # Sanitize credential type name for filename
        safe_type_name = cred_type.lower().replace(" ", "_").replace("/", "_")
        filename = f"{safe_type_name}.json"
        file_path = os.path.join(base_dir, filename)

        # Prepare data for JSON
        cred_data = []
        for value, ml_prob, context_line, line_num, file_path_orig in creds_list:
            cred_data.append(
                {
                    "value": value,
                    "ml_confidence": ml_prob,
                    "context_line": context_line,
                    "line_number": line_num,
                    "source_file": file_path_orig,
                }
            )

        # Sort by ML confidence (highest first)
        cred_data.sort(key=lambda x: x["ml_confidence"] or 0.0, reverse=True)

        # Save to JSON file
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "credential_type": cred_type,
                        "count": len(cred_data),
                        "credentials": cred_data,
                    },
                    f,
                    indent=2,
                    ensure_ascii=False,
                )

            saved_files[cred_type] = file_path
        except Exception as e:
            telemetry.capture_exception(e)
            print_warning(f"Error saving {cred_type} credentials to file: {e}")

    return saved_files


def _select_action_index(
    *,
    shell: Any,
    title: str,
    options: list[str],
    default_idx: int = 0,
) -> int | None:
    """Return one selected option index using the shell questionary helper when available."""
    selector = getattr(shell, "_questionary_select", None)
    if callable(selector):
        return selector(title, options, default_idx=default_idx)
    return None


def _safe_secret_preview(secret: str, *, max_chars: int = 48) -> str:
    """Return one masked secret preview for interactive prompts."""
    value = str(secret or "").strip()
    if len(value) <= max_chars:
        return value
    return f"{value[:max_chars - 3]}..."


def _infer_ai_host_hint(finding: Any) -> str:
    """Return one best-effort host hint from an AI finding."""
    host_hint = str(getattr(finding, "host_hint", "") or "").strip()
    if host_hint:
        return host_hint
    local_source = str(getattr(finding, "local_source", "") or "").strip().replace("\\", "/")
    if not local_source:
        return ""
    parts = [part for part in local_source.split("/") if part]
    return parts[0] if parts else ""


def _run_ai_follow_up_actions(
    shell: Any,
    *,
    domain: str,
    ai_findings: list[Any],
) -> None:
    """Offer premium follow-up actions for AI findings based on actionable context."""
    domain_candidates: list[tuple[str, str]] = []
    local_smb_candidates: list[tuple[str, str, str]] = []
    local_mssql_candidates: list[tuple[str, str, str]] = []
    spray_candidates: list[str] = []
    manual_only_notes: list[str] = []

    seen_domain: set[tuple[str, str]] = set()
    seen_local_smb: set[tuple[str, str, str]] = set()
    seen_local_mssql: set[tuple[str, str, str]] = set()
    seen_spray: set[str] = set()
    seen_manual: set[str] = set()

    for finding in ai_findings:
        username = str(getattr(finding, "username", "") or "").strip()
        secret = str(getattr(finding, "secret", "") or "").strip()
        if not secret:
            continue
        recommended_action = str(
            getattr(finding, "recommended_action", "") or "manual_only"
        ).strip() or "manual_only"
        service_hint = str(getattr(finding, "service_hint", "") or "unknown").strip().lower() or "unknown"
        host_hint = _infer_ai_host_hint(finding)
        credential_type = str(getattr(finding, "credential_type", "") or "secret").strip() or "secret"

        if recommended_action == "add_domain_credential" and username:
            key = (username, secret)
            if key not in seen_domain:
                domain_candidates.append(key)
                seen_domain.add(key)
            continue
        if recommended_action == "add_local_smb_credential" and username and host_hint:
            key = (host_hint, username, secret)
            if key not in seen_local_smb:
                local_smb_candidates.append(key)
                seen_local_smb.add(key)
            continue
        if recommended_action == "add_local_mssql_credential" and username and host_hint:
            key = (host_hint, username, secret)
            if key not in seen_local_mssql:
                local_mssql_candidates.append(key)
                seen_local_mssql.add(key)
            continue
        if recommended_action == "spray" and not shell.is_hash(secret):
            if secret not in seen_spray:
                spray_candidates.append(secret)
                seen_spray.add(secret)
            continue

        note = (
            f"{credential_type}: user={username or '-'} service={service_hint or '-'} "
            f"host={host_hint or '-'}"
        )
        if note not in seen_manual:
            manual_only_notes.append(note)
            seen_manual.add(note)

    if domain_candidates:
        if Confirm.ask(
            f"Validate and store {len(domain_candidates)} AI-discovered domain credential(s)?",
            default=True,
        ):
            for username, secret in domain_candidates:
                shell.add_credential(
                    domain,
                    username,
                    secret,
                    prompt_for_user_privs_after=False,
                )

    if local_smb_candidates:
        if Confirm.ask(
            f"Validate and store {len(local_smb_candidates)} AI-discovered local SMB credential(s)?",
            default=True,
        ):
            for host, username, secret in local_smb_candidates:
                shell.add_credential(
                    domain,
                    username,
                    secret,
                    host=host,
                    service="smb",
                    prompt_for_user_privs_after=False,
                )

    if local_mssql_candidates:
        if Confirm.ask(
            f"Validate and store {len(local_mssql_candidates)} AI-discovered local MSSQL credential(s)?",
            default=True,
        ):
            for host, username, secret in local_mssql_candidates:
                shell.add_credential(
                    domain,
                    username,
                    secret,
                    host=host,
                    service="mssql",
                    prompt_for_user_privs_after=False,
                )

    if spray_candidates and domain in getattr(shell, "domains", []):
        selected_secrets = spray_candidates
        if len(spray_candidates) > 1:
            choice = _select_action_index(
                shell=shell,
                title="Select one AI-discovered secret to use for password spraying:",
                options=[_safe_secret_preview(value) for value in spray_candidates] + ["Skip automated spraying"],
                default_idx=0,
            )
            if choice is None or choice >= len(spray_candidates):
                selected_secrets = []
            else:
                selected_secrets = [spray_candidates[choice]]
        if selected_secrets and Confirm.ask(
            "Run password spraying using the selected AI-discovered secret?",
            default=False,
        ):
            shell.spraying_with_passwords(domain, selected_secrets, source_label="AI share findings")

    if manual_only_notes:
        preview = ", ".join(mark_sensitive(item, "text") for item in manual_only_notes[:5])
        if len(manual_only_notes) > 5:
            preview = f"{preview}, +{len(manual_only_notes) - 5} more"
        print_info(
            "AI discovered additional secrets that were kept for manual review only: "
            f"{preview}"
        )


def handle_found_credentials(
    shell: Any,
    credentials: dict,
    domain: str,
    *,
    source_hosts: list[str] | None = None,
    source_shares: list[str] | None = None,
    auth_username: str | None = None,
    source_artifact: str | None = None,
    analysis_origin: str = "credsweeper",
    ai_findings: list[Any] | None = None,
) -> None:
    """Handle all credentials found by CredSweeper, display them with Rich,
    save them to files, and offer password spraying for all credential types.

    Args:
        shell: The PentestShell instance with required methods
        credentials: Dictionary of credentials organized by type
        domain: Domain name where credentials were found
    """
    from adscan_internal import (
        print_info,
        print_info_debug,
        print_success,
        print_warning,
    )
    from adscan_internal.rich_output import mark_sensitive

    if not credentials:
        return

    share_values = [
        str(value or "").strip().lower() for value in (source_shares or []) if str(value or "").strip()
    ]
    access_vector = ""
    provenance_origin = "share_spidering"
    if any(value in {"winrm", "rdp", "psremote", "mssql"} for value in share_values):
        provenance_origin = "artifact_filesystem"
        access_vector = share_values[0]
    elif share_values:
        access_vector = "smb"
    spray_source_label = (
        "CredSweeper artifact findings"
        if provenance_origin == "artifact_filesystem"
        else "CredSweeper share findings"
    )

    # Display all credentials with Rich
    origin = str(analysis_origin or "credsweeper").strip().lower()
    presentation = CredentialPresentationOptions(
        confidence_label="ML Confidence" if origin == "credsweeper" else None,
        source_column_label="Path(s)",
    )

    print_success("Credentials discovered:")
    display_credentials_with_rich(shell, credentials, presentation=presentation)
    aggregated_credentials = aggregate_credentials_by_type(credentials)

    # Save credentials to files
    saved_files = save_credentials_to_files(credentials, base_dir="smb/spidering")
    review_files = save_aggregated_credential_review_reports(
        shell,
        aggregated_credentials,
        base_dir="smb/spidering",
    )
    review_index_files = save_aggregated_credential_review_indexes(
        shell,
        aggregated_credentials,
        base_dir="smb/spidering",
    )
    display_local_credential_review_paths(shell, aggregated_credentials)

    try:
        from adscan_internal.services.report_service import record_technical_finding

        total_found = sum(len(creds_list) for creds_list in credentials.values())
        evidence_entries = [
            {
                "type": "artifact",
                "summary": f"Credential findings ({cred_type})",
                "artifact_path": file_path,
            }
            for cred_type, file_path in saved_files.items()
        ]
        record_technical_finding(
            shell,
            domain,
            key="smb_share_secrets",
            value=True,
            details={
                "total_credentials": total_found,
                "credential_types": sorted(credentials.keys()),
            },
            evidence=evidence_entries or None,
        )
    except Exception as exc:  # pragma: no cover
        telemetry.capture_exception(exc)

    if saved_files:
        print_success("Credentials saved to smb/spidering/ directory:")
        for cred_type, file_path in saved_files.items():
            marked_file_path = mark_sensitive(file_path, "path")
            print_info(f"  - {cred_type}: {marked_file_path}")
    if review_files:
        print_info("Local review reports saved to smb/spidering/:")
        for cred_type, file_path in review_files.items():
            marked_file_path = mark_sensitive(file_path, "path")
            print_info(f"  - {cred_type}: {marked_file_path}")
    if review_index_files:
        print_info("Quick local review indexes saved to smb/spidering/:")
        for cred_type, file_path in review_index_files.items():
            marked_file_path = mark_sensitive(file_path, "path")
            print_info(f"  - {cred_type}: {marked_file_path}")

    if origin in {"ai", "mixed"} and ai_findings:
        _run_ai_follow_up_actions(shell, domain=domain, ai_findings=list(ai_findings))
        return

    # Collect all credentials from all types for password spraying
    credential_entries: list[tuple[str, tuple]] = []
    for cred_type, creds_list in credentials.items():
        if creds_list:
            credential_entries.extend((cred_type, cred_tuple) for cred_tuple in creds_list)

    deduplicated_entries = deduplicate_credential_entries_for_spraying(credential_entries)
    deduplicated_credentials = [cred_tuple for _, cred_tuple in deduplicated_entries]

    # Inform user if duplicates were removed
    if len(credential_entries) > len(deduplicated_credentials):
        duplicates_removed = len(credential_entries) - len(deduplicated_credentials)
        print_info_debug(
            f"Removed {duplicates_removed} duplicate credential(s). "
            f"Keeping {len(deduplicated_credentials)} unique credential(s) with highest ML confidence."
        )

    # Filter out cpassword entries and process them separately
    deduplicated_credentials = filter_cpassword_credentials(
        shell,
        deduplicated_credentials,
        domain,
        source_hosts=source_hosts,
        source_shares=source_shares,
        auth_username=auth_username,
    )

    retained_values = {str(item[0] or "").strip() for item in deduplicated_credentials}
    deduplicated_entries = [
        (rule_name, cred_tuple)
        for rule_name, cred_tuple in deduplicated_entries
        if str(cred_tuple[0] or "").strip() in retained_values
    ]
    sprayable_credentials, skipped_non_sprayable = filter_sprayable_credential_entries(
        deduplicated_entries
    )
    if skipped_non_sprayable:
        print_info_debug(
            "Excluded non-sprayable credential candidates from automated spraying: "
            f"count={skipped_non_sprayable}"
        )

    # Handle all credentials for password spraying
    if sprayable_credentials:
        if domain not in shell.domains:
            marked_domain = mark_sensitive(domain, "domain")
            print_warning(
                f"Domain '{marked_domain}' is not configured. Cannot perform password spraying."
            )
            return

        from adscan_internal.services.share_credential_provenance_service import (
            ShareCredentialProvenanceService,
        )

        provenance_service = ShareCredentialProvenanceService()
        source_context = provenance_service.build_source_context(
            hosts=source_hosts,
            shares=source_shares,
            artifact=source_artifact,
            auth_username=auth_username,
            origin=provenance_origin,
            access_vector=access_vector or None,
            include_origin_without_fields=False,
        )
        shell.spraying_with_passwords(
            domain,
            [str(credential or "").strip() for credential, *_ in sprayable_credentials],
            source_context=source_context,
            source_label=spray_source_label,
        )
    else:
        print_info(
            "No sprayable credentials found for automated spraying. "
            "All findings have been saved to files for manual review."
        )
