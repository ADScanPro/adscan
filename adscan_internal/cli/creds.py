"""Credentials CLI orchestration helpers.

This module extracts credential management logic out of the monolithic
`adscan.py` so it can be reused by future UX layers while keeping runtime
behaviour stable for the current CLI.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from adscan_internal.services.credentials import CredentialMetadata

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
from adscan_internal.rich_output import mark_sensitive, print_panel
from adscan_core.rich_output import confirm_ask
from adscan_internal.reporting_compat import handle_optional_report_service_exception
from adscan_internal.cli.ci_events import emit_event, emit_phase
from adscan_internal.cli.common import build_lab_event_fields
from adscan_internal.cli.cracking import (
    handle_hash_cracking,
    handle_hash_cracking_batch,
)
from adscan_internal.services.session_compromise_state_service import (
    NON_COMPROMISE_ORIGINS,
    mark_session_user_compromised,
)
from adscan_internal.services.credentials.credential_origin import (
    origin_display_label,
)
from adscan_internal.models.domain import resolve_dc_ip
from adscan_core.theme import (
    ADSCAN_PRIMARY,
    COLOR_AMBER,
    COLOR_CRIMSON,
    COLOR_MUTED,
    COLOR_SAGE,
    COLOR_STEEL,
)

# UX glyphs paired with semantic colors so the credential surfaces remain
# readable in NO_COLOR / monochrome terminals. Every state badge in this
# module leads with a glyph so meaning never depends on color alone.
GLYPH_VERIFIED = "✓"   # ✓ stored / verified
GLYPH_FAILED = "✗"     # ✗ rejected / failed
GLYPH_WARNING = "⚠"    # ⚠ caution
GLYPH_JACKPOT = "★"    # ★ Tier-0 / DA jackpot
GLYPH_PENDING = "○"    # ○ awaiting
GLYPH_ACTIVE = "●"     # ● active
GLYPH_NEXT = "▸"       # ▸ suggested next action
GLYPH_BULLET = "•"     # • neutral list bullet

NON_SPRAYABLE_CREDSWEEPER_RULES = {"uuid"}
UUID_VALUE_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
LAPS_CREDENTIAL_SOURCE_RELATIONS = {"readlapspassword", "synclapspassword"}
DEFAULT_LOCAL_ADMIN_RID = "500"


@dataclass(frozen=True)
class CredentialPresentationOptions:
    """Shared credential-review presentation options for SMB/WinRM findings."""

    confidence_label: str | None = "ML Confidence"
    source_column_label: str = "Path(s)"


def _normalize_optional_text(value: object) -> str:
    """Return a stripped lowercase text value for optional provenance fields."""
    return str(value or "").strip().lower()


def _source_steps_contain_laps_relation(source_steps: list[object] | None) -> bool:
    """Return whether provenance steps identify a LAPS password-read path."""
    for step in source_steps or []:
        relation = _normalize_optional_text(getattr(step, "relation", ""))
        if relation in LAPS_CREDENTIAL_SOURCE_RELATIONS:
            return True
    return False


def _source_steps_contain_default_local_admin_rid(
    source_steps: list[object] | None,
) -> bool:
    """Return whether provenance notes carry the default local Administrator RID."""
    for step in source_steps or []:
        notes = getattr(step, "notes", None)
        if not isinstance(notes, dict):
            continue
        for key in ("local_account_rid", "account_rid", "rid"):
            if str(notes.get(key) or "").strip() == DEFAULT_LOCAL_ADMIN_RID:
                return True
    return False


def _should_prompt_local_reuse_after(
    *,
    prompt_local_reuse_after: bool,
    service: str | None,
    credential_origin: str | None,
    local_account_rid: str | None,
    source_steps: list[object] | None,
) -> bool:
    """Decide whether a newly stored local credential should trigger reuse checks.

    LAPS-managed passwords for the built-in local Administrator account are
    expected to be unique per host, so probing other hosts from that acquisition
    path creates noisy work and misleading attack-graph edges.
    """
    if not prompt_local_reuse_after or _normalize_optional_text(service) != "smb":
        return False

    origin_is_laps = _normalize_optional_text(
        credential_origin
    ) in LAPS_CREDENTIAL_SOURCE_RELATIONS or _source_steps_contain_laps_relation(
        source_steps
    )
    rid_is_default_admin = (
        str(local_account_rid or "").strip() == DEFAULT_LOCAL_ADMIN_RID
        or _source_steps_contain_default_local_admin_rid(source_steps)
    )
    return not (origin_is_laps and rid_is_default_admin)


def normalize_creds_subcommand(subcommand: str) -> tuple[str, bool]:
    """Normalize `creds` subcommand aliases to their canonical form.

    Args:
        subcommand: Raw subcommand provided by the user (for example `save` or
            `show_users`).

    Returns:
        Tuple ``(normalized, alias_used)``.
    """
    normalized = str(subcommand or "").strip().lower()
    aliases = {
        "add": "save",
        "remove": "delete",
        "del": "delete",
        "show_users": "show",
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
                f"{GLYPH_WARNING} Domain not initialized in this workspace.",
                f"Domain:           {marked_domain}",
                f"Credential user:  {marked_user}",
                f"Requested:        {operation_scope}",
                "",
                "Recommended workflow:",
                f"  {GLYPH_BULLET} Run `start_auth` first to initialize domain context, validate DNS/DC, and verify credentials.",
                f"  {GLYPH_BULLET} After `start_auth`, use `creds save` only to add additional credentials discovered later.",
            ]
        ),
        title=f"[bold {COLOR_AMBER}]{GLYPH_WARNING} Initialize Domain First[/bold {COLOR_AMBER}]",
        border_style=COLOR_AMBER,
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


def _resolve_credential_provenance_label(
    shell: Any, *, domain: str, user: str
) -> str | None:
    """Return a compact provenance attribution for a stored credential.

    Reads the recorded ``credential_origin`` (when present) and derives a short,
    client-safe label via the SSOT (spray, kerberoast, DCSync, GPP, LAPS,
    backup_operators, ADCS, manual save, ...). When nothing is recorded, returns
    ``None`` so the caller can render a NEUTRAL marker instead of the literal
    "unknown" — the provenance column must never read "via unknown".
    """
    try:
        domain_data = (shell.domains_data or {}).get(domain, {}) or {}
    except Exception:  # noqa: BLE001
        return None

    meta_root = domain_data.get("credentials_meta") or {}
    user_meta = meta_root.get(user) if isinstance(meta_root, dict) else None
    if isinstance(user_meta, dict):
        origin = str(user_meta.get("credential_origin") or "").strip()
        if origin:
            # EXACT-match resolution via the SSOT origin label map. Substring
            # matching was a bug: ``adcs_esc1`` matched ``adcs_esc10``.. and
            # mislabeled them. The resolver also degrades unmapped slugs to a
            # title-cased rendering rather than the raw slug.
            label = origin_display_label(origin)
            if label:
                return label

    # Fall back to scanning the attack graph provenance edges when available.
    # The relation slug is routed through the SAME SSOT label map so the graph
    # fallback renders a curated label (e.g. "AS-REP roast"), never a raw
    # BloodHound relation like ``ASREPRoasting``.
    try:
        graph_provenance = domain_data.get("credential_provenance") or {}
        user_steps = (
            graph_provenance.get(user) if isinstance(graph_provenance, dict) else None
        )
        if isinstance(user_steps, list) and user_steps:
            first = user_steps[0]
            if isinstance(first, dict):
                relation = str(first.get("relation") or first.get("kind") or "").strip()
                if relation:
                    return origin_display_label(relation) or None
    except Exception:  # noqa: BLE001
        pass

    return None


def show_creds(shell: Any) -> None:
    """Display all stored credentials using Rich Tables, Panels, and Trees.

    Args:
        shell: The PentestShell instance with domains_data and license_mode.
    """
    if not shell.domains_data:
        empty_body = Text.from_markup(
            f"[{COLOR_MUTED}]{GLYPH_PENDING} No credentials stored in the current workspace.[/{COLOR_MUTED}]\n"
            f"[{COLOR_MUTED}]Next:[/{COLOR_MUTED}] [bold]{GLYPH_NEXT}[/bold] run `start_auth` to capture and validate your first credential."
        )
        print_panel(
            empty_body,
            title=f"[bold {COLOR_MUTED}]Credential Store[/bold {COLOR_MUTED}]",
            border_style=COLOR_MUTED,
            expand=False,
        )
        return

    overall_creds_found = False
    for domain, data in shell.domains_data.items():
        domain_renderables = []
        creds_found_for_this_domain = False

        # Domain credentials.
        if "credentials" in data and data["credentials"]:
            creds_found_for_this_domain = True
            overall_creds_found = True

            domain_creds_table = Table(
                title=Text(
                    "Domain Credentials",
                    style=f"bold {ADSCAN_PRIMARY}",
                ),
                show_header=True,
                header_style=f"bold {ADSCAN_PRIMARY}",
                box=rich.box.ROUNDED,
                pad_edge=False,
            )
            domain_creds_table.add_column("", width=2, no_wrap=True)
            domain_creds_table.add_column(
                "User", style=COLOR_SAGE, width=28, overflow="fold"
            )
            domain_creds_table.add_column(
                "Kind", style=COLOR_STEEL, width=10, no_wrap=True
            )
            domain_creds_table.add_column(
                "Credential", style="white", width=38, overflow="fold"
            )
            domain_creds_table.add_column(
                "Provenance", style=COLOR_MUTED, width=22, overflow="fold"
            )
            for user, cred_value in data["credentials"].items():
                cred_display = str(cred_value)
                marked_user = mark_sensitive(user, "user")
                marked_cred_display = mark_sensitive(cred_display, "password")
                try:
                    is_hash_cred = is_hash(cred_display)
                except Exception:  # noqa: BLE001
                    is_hash_cred = False
                kind_cell = (
                    Text(f"{GLYPH_BULLET} hash", style=COLOR_AMBER)
                    if is_hash_cred
                    else Text(f"{GLYPH_BULLET} pass", style=COLOR_STEEL)
                )
                glyph_cell = Text(GLYPH_VERIFIED, style=COLOR_SAGE)
                provenance = _resolve_credential_provenance_label(
                    shell, domain=domain, user=user
                )
                provenance_cell = (
                    Text(f"via {provenance}", style=COLOR_STEEL)
                    if provenance
                    else Text(GLYPH_BULLET, style=COLOR_MUTED)
                )
                domain_creds_table.add_row(
                    glyph_cell,
                    marked_user,
                    kind_cell,
                    marked_cred_display,
                    provenance_cell,
                )
            domain_renderables.append(domain_creds_table)

        # Local credentials.
        if "local_credentials" in data and data["local_credentials"]:
            creds_found_for_this_domain = True
            overall_creds_found = True
            domain_renderables.append(
                Text(
                    f"\n{GLYPH_BULLET} Local Credentials",
                    style=f"bold {ADSCAN_PRIMARY}",
                )
            )
            local_creds_tree_root = Tree(
                Text("Hosts", style=f"bold {COLOR_STEEL}")
            )

            for host, services in data["local_credentials"].items():
                host_branch = local_creds_tree_root.add(
                    Text(f"{GLYPH_ACTIVE} {host}", style=COLOR_STEEL)
                )
                for service, users in services.items():
                    service_branch = host_branch.add(
                        Text(service, style=ADSCAN_PRIMARY)
                    )
                    for user, cred_value in users.items():
                        cred_display = str(cred_value)
                        marked_user_local = mark_sensitive(user, "user")
                        marked_cred_local = mark_sensitive(cred_display, "password")
                        service_branch.add(
                            Text.from_markup(
                                f"[{COLOR_SAGE}]{GLYPH_VERIFIED}[/{COLOR_SAGE}] "
                                f"[bold]{marked_user_local}[/bold] "
                                f"[{COLOR_MUTED}]=>[/{COLOR_MUTED}] {marked_cred_local}"
                            )
                        )
            domain_renderables.append(local_creds_tree_root)

        if creds_found_for_this_domain:
            marked_domain = mark_sensitive(domain, "domain")
            # Verdict-first title: state the domain and the high-level posture
            # before the table renders, so operators scanning many domains in
            # a long session can triage at-a-glance.
            domain_data = shell.domains_data.get(domain, {}) or {}
            auth_status = str(domain_data.get("auth", "unauth") or "unauth").lower()
            if auth_status == "pwned":
                verdict_glyph, verdict_color, verdict_text = (
                    GLYPH_JACKPOT,
                    COLOR_CRIMSON,
                    "DOMAIN COMPROMISED",
                )
            elif auth_status == "auth":
                verdict_glyph, verdict_color, verdict_text = (
                    GLYPH_VERIFIED,
                    COLOR_SAGE,
                    "AUTHENTICATED",
                )
            else:
                verdict_glyph, verdict_color, verdict_text = (
                    GLYPH_PENDING,
                    COLOR_MUTED,
                    "UNAUTHENTICATED",
                )
            print_panel(
                domain_renderables,
                title=(
                    f"[bold {verdict_color}]{verdict_glyph} {verdict_text}"
                    f"[/bold {verdict_color}] "
                    f"[{COLOR_MUTED}]:[/{COLOR_MUTED}] "
                    f"[bold {ADSCAN_PRIMARY}]{marked_domain}[/bold {ADSCAN_PRIMARY}]"
                ),
                border_style=verdict_color,
            )

    if not overall_creds_found:
        print_warning(
            f"{GLYPH_PENDING} No credentials found in any domain."
        )


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


def _get_selectable_domain_users(
    shell: Any,
    *,
    domain: str,
) -> list[str] | None:
    """Return stored domain users that can be selected for a domain action.

    Args:
        shell: The PentestShell instance with domains_data.
        domain: Domain whose stored credentials should be inspected.

    Returns:
        The selectable username list when present, otherwise ``None`` after
        showing the corresponding user-facing error.
    """
    if (
        domain not in shell.domains_data
        or "credentials" not in shell.domains_data[domain]
        or not shell.domains_data[domain]["credentials"]
    ):
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"No credentials stored for domain [bold]{marked_domain}[/bold].")
        return None

    credentials = shell.domains_data[domain]["credentials"]
    user_list = list(credentials.keys())
    if not user_list:
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            f"No users with credentials found for domain [bold]{marked_domain}[/bold], though credentials entry exists."
        )
        return None

    return user_list


def _prompt_for_domain_user_selection(
    shell: Any,
    *,
    domain: str,
    user_list: list[str],
    prompt_label: str = "Select a user",
) -> str | None:
    """Display stored users for ``domain`` and return the selected username.

    Args:
        domain: The domain name whose users are being presented.
        user_list: Stored usernames for the domain.
        prompt_label: Interactive prompt shown to the operator.

    Returns:
        The selected username, or ``None`` when selection is cancelled/invalid.
    """
    print_panel(
        Text.from_markup(
            f"[bold {ADSCAN_PRIMARY}]{GLYPH_ACTIVE} {domain}[/bold {ADSCAN_PRIMARY}]",
            justify="center",
        ),
        title=f"[bold {ADSCAN_PRIMARY}]Domain[/bold {ADSCAN_PRIMARY}]",
        border_style=ADSCAN_PRIMARY,
        expand=False,
        padding=(0, 1),
    )
    table = Table(
        title=f"[bold {ADSCAN_PRIMARY}]Available Users[/bold {ADSCAN_PRIMARY}]",
        box=rich.box.ROUNDED,
        show_lines=True,
        title_style=f"bold {ADSCAN_PRIMARY}",
    )
    table.add_column("ID", style=COLOR_MUTED, width=6, justify="center")
    table.add_column("", width=2, no_wrap=True)
    table.add_column("Username", style=f"bold {COLOR_SAGE}")
    table.add_column("Provenance", style=COLOR_MUTED, overflow="fold")

    for idx, user_name in enumerate(user_list):
        marked_user_name = mark_sensitive(user_name, "user")
        provenance = _resolve_credential_provenance_label(
            shell, domain=domain, user=user_name
        )
        provenance_cell = (
            Text(f"via {provenance}", style=COLOR_STEEL)
            if provenance
            else Text(GLYPH_BULLET, style=COLOR_MUTED)
        )
        table.add_row(
            str(idx + 1),
            Text(GLYPH_VERIFIED, style=COLOR_SAGE),
            marked_user_name,
            provenance_cell,
        )

    print_table(table)

    selector = getattr(shell, "_questionary_select", None)
    if callable(selector):
        try:
            selected_user_idx = selector(
                f"{prompt_label}:",
                user_list,
                default_idx=0,
            )
        except KeyboardInterrupt as e:
            telemetry.capture_exception(e)
            print_warning("Credential selection cancelled.")
            return None
        except Exception as e:  # noqa: BLE001
            telemetry.capture_exception(e)
            print_warning(f"Questionary credential selection failed: {e}")
        else:
            if selected_user_idx is None:
                print_warning("Credential selection cancelled.")
                return None
            if 0 <= selected_user_idx < len(user_list):
                return user_list[selected_user_idx]
            print_error("Invalid selection. Index out of range.")
            return None

    try:
        num_users = len(user_list)
        if num_users == 0:
            return None

        selected_user_num = IntPrompt.ask(
            f"{prompt_label} (1-{num_users})",
            choices=[str(i + 1) for i in range(num_users)],
            # A non-interactive run (adscan ci) must not block: the IntPrompt
            # wrapper auto-resolves to default=, so pick the first user.
            default=1,
            show_default=False,
            show_choices=False,
        )
        selected_user_idx = selected_user_num - 1

    except KeyboardInterrupt as e:
        telemetry.capture_exception(e)
        print_warning("Credential selection cancelled.")
        return None

    # IntPrompt handles non-integer input and choice validation.
    # This check is mostly for safety, IntPrompt with choices should ensure validity.
    if not (0 <= selected_user_idx < len(user_list)):
        print_error("Invalid selection. Index out of range.")
        return None

    return user_list[selected_user_idx]


def select_cred(shell: Any, domain: str) -> None:
    """Select a credential for a domain and proceed with enumeration.

    Args:
        shell: The PentestShell instance with domains_data and related methods.
        domain: The domain name to select credentials for.
    """
    user_list = _get_selectable_domain_users(shell, domain=domain)
    if not user_list:
        return

    credentials = shell.domains_data[domain]["credentials"]
    selected_user = _prompt_for_domain_user_selection(
        shell,
        domain=domain,
        user_list=user_list,
        prompt_label="Select a user",
    )
    if not selected_user:
        return

    print_info_verbose(f"Selected user: [bold green]{selected_user}[/bold green]")

    cred_value = credentials[selected_user]

    # Verify domain credentials using the correctly scoped 'selected_user'.
    # On failure the disposition (keep valid-but-unusable / confirm-then-delete a
    # genuinely invalid one) is centralised in _purge_failed_domain_credential.
    if not shell.verify_domain_credentials(domain, selected_user, cred_value):
        _purge_failed_domain_credential(shell, domain=domain, user=selected_user)
        return

    marked_domain = mark_sensitive(domain, "domain")
    print_success_verbose(
        f"Credentials for '[bold]{selected_user}[/bold]' verified successfully for domain [bold]{marked_domain}[/bold]."
    )
    _ensure_verified_domain_credential_ticket(
        shell,
        domain=domain,
        user=selected_user,
        credential=cred_value,
        ui_silent=False,
        ensure_fresh_kerberos_ticket=True,
    )

    handle_auth_and_optional_privs(
        shell,
        domain,
        [(selected_user, cred_value)],
        prompt_for_user_privs_after=True,
    )


def delete_cred(shell: Any, domain: str) -> None:
    """Interactively delete one stored domain credential from a workspace.

    Args:
        shell: The PentestShell instance with domains_data.
        domain: The domain name to delete a credential from.
    """
    from adscan_internal.services.credential_store_service import (
        CredentialStoreService,
    )

    user_list = _get_selectable_domain_users(shell, domain=domain)
    if not user_list:
        return

    checkbox = getattr(shell, "_questionary_checkbox", None)
    if callable(checkbox):
        try:
            selected_users = checkbox(
                "Select credential(s) to delete:",
                user_list,
                default_values=None,
            )
        except KeyboardInterrupt as e:
            telemetry.capture_exception(e)
            print_warning("Credential deletion cancelled.")
            return
        except Exception as e:  # noqa: BLE001
            telemetry.capture_exception(e)
            print_warning(f"Questionary credential deletion selection failed: {e}")
            selected_users = None
    else:
        selected_user = _prompt_for_domain_user_selection(
            shell,
            domain=domain,
            user_list=user_list,
            prompt_label="Select a credential to delete",
        )
        selected_users = [selected_user] if selected_user else None

    if not selected_users:
        print_warning("Credential deletion cancelled.")
        return

    store_service = CredentialStoreService()
    marked_domain = mark_sensitive(domain, "domain")
    deleted_users: list[str] = []
    deleted_ticket_users: list[str] = []
    missing_users: list[str] = []

    for selected_user in selected_users:
        credential_deleted = store_service.delete_domain_credential(
            domains_data=shell.domains_data,
            domain=domain,
            username=selected_user,
        )
        ticket_deleted = store_service.delete_kerberos_ticket(
            domains_data=shell.domains_data,
            domain=domain,
            username=selected_user,
        )
        if credential_deleted:
            deleted_users.append(selected_user)
            if ticket_deleted:
                deleted_ticket_users.append(selected_user)
        else:
            missing_users.append(selected_user)

    if missing_users:
        marked_missing_users = ", ".join(
            mark_sensitive(user, "user") for user in missing_users
        )
        print_error(
            f"Credential(s) for {marked_missing_users} were not found in domain [bold]{marked_domain}[/bold]."
        )

    if not deleted_users:
        return

    marked_deleted_users = ", ".join(
        f"[bold]{mark_sensitive(user, 'user')}[/bold]" for user in deleted_users
    )
    print_info(
        f"Deleted credential(s) for {marked_deleted_users} in domain [bold]{marked_domain}[/bold]."
    )
    if deleted_ticket_users:
        marked_ticket_users = ", ".join(
            f"[bold]{mark_sensitive(user, 'user')}[/bold]"
            for user in deleted_ticket_users
        )
        print_info_verbose(
            f"Removed stored Kerberos ticket(s) for {marked_ticket_users} in domain [bold]{marked_domain}[/bold]."
        )

    if shell.current_workspace_dir:
        if shell.save_workspace_data():
            print_info("Workspace data saved after removing credential.")
        else:
            print_error("Failed to save workspace data after removing credential.")


def _ensure_verified_domain_credential_ticket(
    shell: Any,
    *,
    domain: str,
    user: str,
    credential: str,
    ui_silent: bool,
    ensure_fresh_kerberos_ticket: bool,
) -> None:
    """Refresh or create the Kerberos ticket for one verified domain credential."""
    from adscan_internal.services.credential_store_service import (
        CredentialStoreService,
    )

    store_service = CredentialStoreService()
    is_explicit_blank_password = credential == ""
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
                "[kerberos] Skipping Kerberos ticket generation for "
                f"{marked_user}@{marked_domain} because the credential is a blank password."
            )
            return
        if existing_ticket and not ensure_fresh_kerberos_ticket:
            marked_user = mark_sensitive(user, "user")
            marked_domain = mark_sensitive(domain, "domain")
            marked_ticket = mark_sensitive(existing_ticket, "path")
            print_info_verbose(
                f"Kerberos ticket already registered for {marked_user}@{marked_domain}; "
                f"skipping auto-generation (ticket={marked_ticket})."
            )
            return
        if existing_ticket and ensure_fresh_kerberos_ticket:
            marked_user = mark_sensitive(user, "user")
            marked_domain = mark_sensitive(domain, "domain")
            marked_ticket = mark_sensitive(existing_ticket, "path")
            print_info_verbose(
                f"Refreshing Kerberos ticket for {marked_user}@{marked_domain} "
                f"(existing_ticket={marked_ticket})."
            )

        dc_ip = None
        if "dc_ip" in shell.domains_data.get(domain, {}):
            dc_ip = shell.domains_data[domain]["dc_ip"]

        tgt_result = shell._auto_generate_kerberos_ticket_result(user, credential, domain, dc_ip)

        marked_user = mark_sensitive(user, "user")
        marked_domain = mark_sensitive(domain, "domain")

        if tgt_result is not None and tgt_result.success and tgt_result.ticket_path:
            store_service.store_kerberos_ticket(
                domains_data=shell.domains_data,
                domain=domain,
                username=user,
                ticket_path=tgt_result.ticket_path,
            )
            if not ui_silent:
                print_info(
                    f"Kerberos ticket generated for {marked_user}@{marked_domain}"
                )
            else:
                print_info_verbose(
                    f"[ui_silent] Kerberos ticket generated for {marked_user}@{marked_domain}"
                )
        else:
            error_kind = getattr(tgt_result, "error_kind", None) if tgt_result is not None else None
            if error_kind == "rc4_disabled":
                from adscan_internal.services.auth_posture_service import record_rc4_disabled_signal
                record_rc4_disabled_signal(
                    shell.domains_data,
                    domain=domain,
                    source="kerberos_ticket_service",
                    signal="KDC_ERR_ETYPE_NOSUPP",
                    message=getattr(tgt_result, "error_message", None),
                )
                if shell.current_workspace_dir:
                    shell.save_workspace_data()
                if not ui_silent:
                    print_warning(
                        f"Domain {marked_domain} requires AES for Kerberos (RC4 disabled). "
                        f"No Kerberos ticket generated for {marked_user}. "
                        "NTLM will be used if available, or supply a password for AES Kerberos."
                    )
            else:
                if not ui_silent:
                    print_warning(
                        f"Could not generate Kerberos ticket for {marked_user}@{marked_domain}"
                    )
                else:
                    print_info_verbose(
                        f"[ui_silent] Could not generate Kerberos ticket for {marked_user}@{marked_domain}"
                    )
    except Exception as e:  # noqa: BLE001
        telemetry.capture_exception(e)
        marked_user = mark_sensitive(user, "user")
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            f"[kerberos] Error while handling Kerberos ticket for "
            f"{marked_user}@{marked_domain}: {e}"
        )


def _privs_assessed_users_set(shell: Any, domain: str) -> set:
    """Return the per-domain session set of users whose privileges were assessed.

    SSOT for "was this user actually ENUMERATED this session" (ask_for_user_privs
    ran: privileges, attack paths, service privileges, shares). Lives as a shell
    attribute, NOT in domains_data, so it is never serialized to workspace JSON
    (resets on restart only) — see the dedup guard in handle_auth_and_optional_privs.
    """
    by_domain = getattr(shell, "_privs_assessed_users_by_domain", None)
    if not isinstance(by_domain, dict):
        by_domain = {}
        setattr(shell, "_privs_assessed_users_by_domain", by_domain)
    return by_domain.setdefault(domain, set())


def _assessed_user_key(user: str) -> str:
    """Canonical key for the assessed-set (matches the legacy dedup guard)."""
    from adscan_internal.services.high_value import normalize_samaccountname

    return normalize_samaccountname(user).lower()


def mark_user_privs_assessed(shell: Any, domain: str, user: str) -> None:
    """Record that ``user``'s privileges were assessed this session.

    Call this wherever enumeration actually runs (centralized in
    ``ask_for_user_privs``) so EVERY entry point marks the user — not only the
    attack-path credential loop. Best-effort; never raises.
    """
    try:
        _privs_assessed_users_set(shell, domain).add(_assessed_user_key(user))
    except Exception:  # noqa: BLE001 — the marker is a best-effort dedup hint
        pass


def user_privs_assessed_this_session(shell: Any, domain: str, user: str) -> bool:
    """True iff ``user``'s privileges were already assessed this session.

    The robust replacement for the old credential-PRESENCE heuristic: a stored
    credential does NOT imply the user was enumerated (e.g. spraying persists the
    credential via ``update_domain_credential`` without ever running
    ask_for_user_privs). Gating the re-enumerate offer on this marker means a
    stored-but-unenumerated user is enumerated normally instead of being prompted
    (and skipped in CI).
    """
    try:
        return _assessed_user_key(user) in _privs_assessed_users_set(shell, domain)
    except Exception:  # noqa: BLE001
        return False


def handle_auth_and_optional_privs(
    shell: Any,
    domain: str,
    users_with_creds: list[tuple[str, str]],
    *,
    prompt_for_user_privs_after: bool = True,
    skip_user_privs_enumeration: bool = False,
    force_authenticated_enumeration: bool = False,
    prompt_when_already_authenticated: bool = False,
    allow_empty_credentials: bool = False,
    force_recheck_user_privs: bool = False,
) -> None:
    """Ensure authenticated enumeration and optionally ask for user privileges.

    Args:
        shell: Shell instance with enumeration helpers.
        domain: Domain to operate on.
        users_with_creds: List of (username, credential) tuples.
        prompt_for_user_privs_after: When True, prompt for user privilege checks.
        skip_user_privs_enumeration: When True, skip every privilege-enumeration
            prompt and follow-up regardless of attack-path overrides.
        force_authenticated_enumeration: When True, rerun authenticated
            enumeration even if the domain is already in ``auth`` state.
        prompt_when_already_authenticated: When True, and the domain is already
            ``auth``, ask whether to rerun the full authenticated scan or only
            continue with privilege enumeration for the current user.
        allow_empty_credentials: When True, treat an empty string as an explicit
            credential value (for example: valid blank-password logons) instead
            of discarding it as missing input.
        force_recheck_user_privs: When True, bypass the per-session "privileges
            already assessed" dedup guard so a user whose privileges just changed
            (for example: an existing account that was just promoted to Domain
            Admins) is re-enumerated even if it was assessed earlier this session.

    The re-enumerate offer is gated on whether the user was already ASSESSED this
    session (``user_privs_assessed_this_session``), NOT on credential presence — a
    stored-but-unenumerated user (e.g. a sprayed credential) is enumerated normally.
    """
    marked_domain = mark_sensitive(domain, "domain")
    current_auth_status = shell.domains_data.get(domain, {}).get("auth", "")
    print_info_debug(
        f"[creds] handle_auth_and_optional_privs start: domain={marked_domain} "
        f"auth={current_auth_status!r} users={len(users_with_creds)} "
        f"prompt_privs={prompt_for_user_privs_after} "
        f"skip_user_privs={skip_user_privs_enumeration} "
        f"force_enum={force_authenticated_enumeration!r} "
        f"prompt_existing_auth={prompt_when_already_authenticated!r}"
    )
    has_non_empty_credential = any(
        user and (cred is not None) and cred != "" for user, cred in users_with_creds
    )

    # When this user's privileges were ALREADY ASSESSED this session
    # (ask_for_user_privs actually ran: privileges, attack paths from this user,
    # service privileges, shares), OFFER to re-enumerate the PER-USER assessment —
    # NOT a full domain re-scan; it reuses the already-collected domain data.
    #
    # We key on the ENUMERATION marker, NOT on credential presence: a stored
    # credential does NOT imply the user was enumerated. Spraying (and other paths)
    # persist a credential via update_domain_credential WITHOUT running
    # ask_for_user_privs, so the old credential-pre-existence heuristic
    # false-positived — it prompted "re-enumerate?" (default No → skipped in CI) for
    # a user that was never assessed, silently dropping its enumeration. Keying on
    # the assessed-marker means a stored-but-unenumerated user (and a brand-new
    # credential) is enumerated normally with no prompt; only a genuinely
    # already-assessed user gets the re-enumerate offer.
    #
    # Default No keeps the skip, so CI / non-interactive runs auto-resolve to No
    # (confirm_ask's auto-mode fallback). A Yes answer drives ONLY
    # force_recheck_user_privs (the per-session assessed-set discard so the
    # privilege check re-runs); it deliberately does NOT set
    # force_authenticated_enumeration — forcing a full scan would re-enumerate the
    # whole domain AND disable the standard ask_for_user_privs path (a full scan is
    # treated as already covering user privs at :1620), the opposite of the intent.
    # Scoped to the interactive credential-selection intent: not during attack-path
    # execution (steps run unattended), not when the caller already forces a scan,
    # and not when the richer prompt_when_already_authenticated flow owns the case.
    try:
        from adscan_internal.services.attack_graph_runtime_service import (
            is_attack_path_execution_active as _is_attack_path_execution_active,
        )
    except Exception:  # noqa: BLE001
        def _is_attack_path_execution_active(_shell: Any) -> bool:
            return False
    _reassess_user = next(
        (user for user, _cred in users_with_creds if user), None
    )
    if (
        _reassess_user is not None
        and user_privs_assessed_this_session(shell, domain, _reassess_user)
        and prompt_for_user_privs_after
        and not force_authenticated_enumeration
        and not prompt_when_already_authenticated
        and has_non_empty_credential
        and not _is_attack_path_execution_active(shell)
    ):
        if confirm_ask(
            f"{mark_sensitive(_reassess_user, 'user')}'s privileges were already "
            "assessed this session; re-enumerate it (privileges and attack paths)?",
            default=False,
        ):
            force_recheck_user_privs = True

    def _choose_authenticated_enumeration_action() -> str:
        """Return how to proceed when start_auth targets an already-auth domain.

        Consolidation: the old Panel 1 ("Authenticated Domain Already Initialized"
        — rerun-full vs privs-only) is removed. The workspace-resume panel
        (``_run_enum_domain_auth`` → ``resolve_workspace_action``) is now the single
        decision surface for an already-initialized domain, so this resolves to a
        full authenticated pass here and lets that panel offer Resume / Refresh /
        Replay / Inspect downstream. The privs-only intent survives as RESUME there.

        ``start_auth`` no longer sets ``prompt_when_already_authenticated`` (the
        only caller that did), so that branch is dead for the scan path; it is kept
        resolving to ``full_scan`` without rendering a panel for any other caller.
        """
        if current_auth_status != "auth":
            return "full_scan"
        if not prompt_when_already_authenticated:
            return "full_scan" if force_authenticated_enumeration else "skip"
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
        normalize_search_mode_label,
    )
    from adscan_internal.services.privileged_group_classifier import (
        resolve_privileged_followup_decision,
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

    def _get_terminal_attack_path_search_mode() -> str | None:
        """Return the canonical terminal search mode when the active step is last.

        ``search_mode_label`` is set by the attack-path execution engine when it
        opens an active step.  Most call sites pass canonical labels
        (``direct_compromise``, ``pivot``, ``followup_terminal``, ``low_priv``)
        or their visible aliases.  Bespoke follow-ups (e.g. RODC PRP control
        path) sometimes pass descriptive strings that don't normalize to any
        canonical mode — in that case the field arrives as a free-form string
        the alias table cannot map.

        To stay robust as new follow-ups are added, when the label cannot be
        normalized we **derive** the search mode from ``compromise_semantics``
        instead.  ``compromise_semantics`` is the catalog-level source of truth
        for what kind of compromise a relation produces, so the derivation is
        always correct as long as the relation is in the step catalog.
        """
        context = get_attack_path_step_context(shell)
        raw_search_mode = str(context.get("search_mode_label") or "").strip()
        search_mode = normalize_search_mode_label(raw_search_mode)
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
            return None

        canonical_modes = {"pivot", "direct_compromise", "followup_terminal", "low_priv"}
        is_terminal_step = step_index > 0 and step_index == last_executable_idx

        derivation_source = "search_mode_label"
        terminal_mode: str | None
        if search_mode in canonical_modes and is_terminal_step:
            terminal_mode = search_mode
        elif is_terminal_step:
            # Fallback: derive from compromise_semantics (catalog-level truth).
            # Maps every catalog semantic that has a sensible terminal-mode
            # interpretation; everything else stays ``None`` (no terminal
            # classification).
            semantics_to_mode = {
                "direct_target_compromise": "direct_compromise",
                "access_capability_only": "followup_terminal",
                "credential_access_only": "followup_terminal",
            }
            derived = semantics_to_mode.get(compromise_semantics)
            if derived:
                terminal_mode = derived
                derivation_source = "compromise_semantics"
            else:
                terminal_mode = None
        else:
            terminal_mode = None

        print_info_debug(
            "[creds] terminal attack-path check: "
            f"raw_search_mode_label={mark_sensitive(raw_search_mode or 'none', 'detail')} "
            f"normalized_search_mode={mark_sensitive(search_mode or 'none', 'detail')} "
            f"compromise_semantics={mark_sensitive(compromise_semantics, 'detail')} "
            f"compromise_effort={mark_sensitive(compromise_effort, 'detail')} "
            f"step_index={step_index} last_executable_idx={last_executable_idx} "
            f"result={mark_sensitive(terminal_mode or 'none', 'detail')} "
            f"derived_via={derivation_source}"
        )
        if (
            is_terminal_step
            and search_mode not in canonical_modes
            and raw_search_mode
        ):
            # Surface the bespoke label so the team knows which producer is
            # using a non-canonical string.  The fallback derivation kept the
            # behaviour correct, so this is a hint, not a failure.
            print_info_debug(
                "[creds] terminal attack-path: search_mode_label is non-canonical "
                f"(raw={mark_sensitive(raw_search_mode, 'detail')!r}); "
                "falling back to compromise_semantics. Consider passing one of "
                f"{sorted(canonical_modes)} from the producing call site."
            )
        return terminal_mode

    def _is_active_attack_path_step_terminal() -> bool:
        """Return True when the active attack-path step is the last executable step."""
        context = get_attack_path_step_context(shell)
        try:
            step_index = int(context.get("step_index") or 0)
            last_executable_idx = int(context.get("last_executable_idx") or 0)
        except (TypeError, ValueError):
            print_info_debug(
                "[creds] terminal step check: invalid attack-path step context "
                f"context={mark_sensitive(str(context), 'detail')}"
            )
            return False
        return step_index > 0 and step_index == last_executable_idx

    def _is_terminal_pivot_attack_step() -> bool:
        """Return True when the active step is the final pivot-search step."""
        terminal_mode = _get_terminal_attack_path_search_mode()
        is_terminal_pivot = terminal_mode == "pivot"
        print_info_debug(
            "[creds] terminal pivot check: "
            f"search_mode={mark_sensitive(terminal_mode or 'none', 'detail')} "
            f"result={is_terminal_pivot!r}"
        )
        return is_terminal_pivot

    def _resolve_active_step_target_principal() -> str | None:
        """Return the normalized principal represented by the step target.

        For some attack steps, especially ADCS paths like ``ADCSESC1``, the
        graph target is the Domain node while the execution target is a user
        chosen at runtime (for example ``administrator``). Prefer the explicit
        execution target from the active-step notes when it exists.
        """
        active = getattr(shell, "_active_attack_graph_step", None)
        if not isinstance(active, ActiveAttackGraphStep):
            return None
        notes = active.notes if isinstance(active.notes, dict) else {}
        for key in ("target_user", "expected_user", "compromised_user", "principal"):
            value = notes.get(key)
            if isinstance(value, str) and value.strip():
                normalized = normalize_samaccountname(value)
                if normalized:
                    return normalized
        target_label = str(getattr(active, "to_label", "") or "").strip()
        if not target_label:
            return None
        return normalize_samaccountname(target_label)

    def _resolve_terminal_effective_target_basis_primary() -> dict[str, object]:
        """Return the normalized primary effective-target-basis record."""
        context = get_attack_path_step_context(shell)
        payload = context.get("effective_target_basis_primary")
        if isinstance(payload, dict):
            return dict(payload)
        return {}

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
        if not _is_terminal_pivot_attack_step():
            print_info_debug(
                "[creds] terminal pivot follow-up gate: disabled "
                "(active step is not the terminal pivot step)"
            )
            return False

        normalized_user = normalize_samaccountname(user)
        target_principal = _resolve_active_step_target_principal()
        step_context = get_attack_path_step_context(shell)
        print_info_debug(
            "[creds] terminal pivot follow-up evaluation: "
            f"user={mark_sensitive(normalized_user or user, 'user')} "
            f"target_principal={mark_sensitive(target_principal or 'N/A', 'user')} "
            f"step_context={mark_sensitive(str(step_context), 'detail')}"
        )
        if not normalized_user:
            print_info_debug(
                "[creds] terminal pivot follow-up gate: disabled "
                "(credential user could not be normalized)"
            )
            return False
        if target_principal and normalized_user != target_principal:
            print_info_debug(
                "[creds] skipping terminal pivot user follow-ups "
                "(credential does not match the target node principal)"
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

    def _run_terminal_effective_privileged_followups(user: str, credential: str) -> bool:
        """Run direct privileged follow-ups when terminal target basis already explains them."""
        if not is_attack_path_execution_active(shell):
            return False

        terminal_search_mode = _get_terminal_attack_path_search_mode()
        if terminal_search_mode not in {"direct_compromise", "followup_terminal"}:
            return False

        normalized_user = normalize_samaccountname(user)
        target_principal = _resolve_active_step_target_principal()
        if not normalized_user or not target_principal or normalized_user != target_principal:
            return False

        basis_primary = _resolve_terminal_effective_target_basis_primary()
        basis_kind = str(
            basis_primary.get("basis_kind")
            or get_attack_path_step_context(shell).get("effective_target_basis_kind")
            or ""
        ).strip().lower()
        if basis_kind != "member_of":
            return False

        marked_user = mark_sensitive(normalized_user, "user")
        marked_basis = mark_sensitive(
            str(basis_primary.get("target_label") or "unknown"),
            "detail",
        )
        membership = shell.check_privileged_groups(
            domain,
            user,
            credential,
            execute_actions=False,
        )
        decision = resolve_privileged_followup_decision(membership or {})
        if not (
            decision.skip_attack_path_search or decision.should_run_enrichment_followup
        ):
            print_info_debug(
                "[creds] terminal privileged follow-up bypass disabled "
                f"(user={marked_user}, basis={marked_basis}, actionable=False)"
            )
            return False

        print_info_debug(
            "[creds] terminal privileged follow-up bypass enabled "
            f"(search_mode={mark_sensitive(terminal_search_mode, 'detail')}, "
            f"user={marked_user}, basis={marked_basis}, primary={decision.primary_key})"
        )
        shell._handle_privileged_group_membership(  # type: ignore[attr-defined]
            domain,
            user,
            credential,
            membership,
            "attack-path-effective-target-basis",
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

    def _should_force_direct_target_compromise_user_privs(
        user: str,
        *,
        target_principal: str | None,
    ) -> bool:
        """Promote direct-compromise steps to full user follow-up when justified.

        This covers steps whose graph target is broader than the principal
        actually compromised at runtime, such as ``ADCSESC1`` paths modeled
        against the Domain node while the operator chose a concrete Domain Admin
        target for certificate impersonation.
        """
        if not is_attack_path_execution_active(shell):
            return False

        compromise_semantics, compromise_effort = (
            _resolve_active_step_compromise_metadata()
        )
        if compromise_semantics != "direct_target_compromise":
            return False
        if not _is_active_attack_path_step_terminal():
            print_info_debug(
                "[creds] attack-context direct-compromise flow: disabled "
                "(active step is not terminal)"
            )
            return False

        normalized_user = normalize_samaccountname(user)
        if not normalized_user or not target_principal:
            return False
        if normalized_user != target_principal:
            return False

        active_step_user = _resolve_active_step_execution_user()
        if active_step_user and normalized_user == active_step_user:
            return False

        print_info_debug(
            "[creds] attack-context direct-compromise flow: enabling full "
            "ask_for_user_privs for effective target principal "
            f"user={mark_sensitive(normalized_user, 'user')} "
            f"target_principal={mark_sensitive(target_principal, 'user')} "
            f"active_step_user={mark_sensitive(active_step_user or 'N/A', 'user')} "
            f"compromise_semantics={mark_sensitive(compromise_semantics, 'detail')} "
            f"compromise_effort={mark_sensitive(compromise_effort, 'detail')}"
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
    if skip_user_privs_enumeration:
        print_info_debug(
            "[creds] skipping all ask_for_user_privs flows due to hard disable "
            f"(auth={updated_auth_status!r})"
        )

    # Defensive cleanup: an earlier (buggy) version stored the dedup set inside
    # domains_data[domain]["_privs_assessed_users"] which broke JSON
    # serialization.  Scrub it once on entry so workspaces resumed from that
    # buggy state can still serialize cleanly.
    try:
        _stale_entry = shell.domains_data.get(domain) if isinstance(shell.domains_data, dict) else None
        if isinstance(_stale_entry, dict) and "_privs_assessed_users" in _stale_entry:
            _stale_entry.pop("_privs_assessed_users", None)
    except Exception:  # noqa: BLE001
        pass

    for user, cred in users_with_creds:
        if not user or (cred is None) or (cred == "" and not allow_empty_credentials):
            continue
        try:
            if skip_user_privs_enumeration:
                continue

            # Dedup guard: skip privilege enumeration for users that were already
            # assessed this session.  This prevents the DCSync → fallback LSA dump
            # → re-add machine account → re-ask DCSync loop.
            # The set lives as a shell attribute (not domains_data) so it never
            # gets serialized to workspace JSON — resets on adscan restart only.
            #
            # Exception: when re-adding a Domain Admin credential while the domain
            # is NOT yet pwned, fall through and re-run the privilege check.  The
            # operator likely wants progress (a manual `dump lsa`, a different
            # attack path, changed network conditions, etc.).  Safe because the
            # "DA-already-captured" short-circuit in
            # _offer_machine_account_dump_fallback prevents the DCSync→fallback
            # automated loop independently.
            _by_domain: dict[str, set[str]] = getattr(shell, "_privs_assessed_users_by_domain", None) or {}
            if not isinstance(_by_domain, dict):
                _by_domain = {}
            _assessed: set[str] = _by_domain.setdefault(domain, set())
            setattr(shell, "_privs_assessed_users_by_domain", _by_domain)
            _user_key = normalize_samaccountname(user).lower()
            if _user_key in _assessed and force_recheck_user_privs:
                # Caller explicitly requested a re-check (e.g. the user was just
                # promoted to Domain Admins and its privileges changed). Drop the
                # dedup marker so the standard flow below re-enumerates.
                _assessed.discard(_user_key)
                print_info_debug(
                    f"[creds] force_recheck_user_privs: re-running privilege "
                    f"enumeration for {_user_key!r} despite prior assessment"
                )
            elif _user_key in _assessed:
                # Use the canonical DA-or-high-value resolver: layered fallback
                # of (1) is_user_tier0_or_high_value (graph + snapshot + cached
                # lists) and (2) is_well_known_da_name (localized Administrator
                # variants + krbtgt + persisted builtin_administrator_name).
                # Covers custom DA names (svc_eng_admin), localized DAs
                # (Administrador, Administrateur), and the early-pentest window
                # before any LDAP collection has run.
                from adscan_internal.services.high_value import (
                    is_user_da_or_high_value,
                )
                _is_high_value_user = False
                try:
                    _is_high_value_user = is_user_da_or_high_value(
                        shell, domain=domain, samaccountname=user
                    )
                except Exception:  # noqa: BLE001
                    _is_high_value_user = False
                _domain_pwned = updated_auth_status == "pwned"
                if _is_high_value_user and not _domain_pwned:
                    print_info_debug(
                        f"[creds] re-running ask_for_user_privs for high-value "
                        f"user {_user_key!r}: domain not yet pwned"
                    )
                    # Fall through to standard flow — do not skip.
                else:
                    # Compact muted notice — no prompt, no sound, no friction.
                    # Following tui-design §3: "Reversible → Just do it, show brief
                    # confirmation in status bar."  The operator can re-trigger with
                    # `privs <user>@<domain>` if needed.
                    from rich.text import Text as _Text
                    from adscan_core.rich_output import _get_console  # noqa: PLC0415
                    _line = _Text()
                    _line.append("  ↩ ", style="dim #6E7681")
                    _line.append(mark_sensitive(user, "user"), style="#6E7681")
                    _line.append("  ·  ", style="dim #6E7681")
                    _line.append("privileges already assessed this session", style="dim #6E7681")
                    try:
                        _get_console().print(_line)
                    except Exception:  # noqa: BLE001
                        pass
                    print_info_debug(
                        f"[creds] skipping ask_for_user_privs for {_user_key!r}: "
                        "already assessed this session"
                    )
                    continue

            if updated_auth_status == "pwned":
                print_info_debug(
                    "[creds] skipping attack-path privilege UX because domain is pwned"
                )
                continue
            terminal_search_mode = _get_terminal_attack_path_search_mode()
            normalized_user = normalize_samaccountname(user)
            target_principal = _resolve_active_step_target_principal()

            if terminal_search_mode == "pivot":
                if _run_terminal_pivot_user_followups(user, cred):
                    continue
                if target_principal and normalized_user == target_principal:
                    print_info_debug(
                        "[creds] terminal pivot path resolved expected target principal; "
                        "keeping lightweight follow-up flow only"
                    )
                    continue

            if _run_terminal_effective_privileged_followups(user, cred):
                continue

            if terminal_search_mode in {"direct_compromise", "followup_terminal"} and normalized_user:
                mode_label = (
                    "domain-compromise-enabler"
                    if terminal_search_mode == "followup_terminal"
                    else "direct-domain-control"
                )
                print_info_debug(
                    f"[creds] enabling ask_for_user_privs for terminal {mode_label} path "
                    f"user={mark_sensitive(normalized_user, 'user')}"
                )
                _assessed.add(_user_key)
                shell.ask_for_user_privs(domain, user, cred)
                continue

            if (
                terminal_search_mode == "pivot"
                and normalized_user
                and normalized_user != target_principal
            ):
                print_info_debug(
                    "[creds] enabling ask_for_user_privs for terminal pivot path "
                    "because credential differs from target node principal "
                    f"user={mark_sensitive(normalized_user, 'user')} "
                    f"target_principal={mark_sensitive(target_principal or 'N/A', 'user')}"
                )
                _assessed.add(_user_key)
                shell.ask_for_user_privs(domain, user, cred)
                continue

            if _run_terminal_pivot_user_followups(user, cred):
                continue
            force_full_user_privs_from_attack_context = (
                _should_force_full_user_privs_from_attack_context(user)
            )
            if not force_full_user_privs_from_attack_context:
                force_full_user_privs_from_attack_context = (
                    _should_force_direct_target_compromise_user_privs(
                        user, target_principal=target_principal
                    )
                )
            should_force_high_value_terminal_user_privs = False
            if (
                is_attack_path_execution_active(shell)
                and not force_full_user_privs_from_attack_context
                and terminal_search_mode in {"direct_compromise", "followup_terminal"}
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
                        "high-value path "
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
            # Mark as assessed BEFORE the call so that any re-entry triggered
            # inside ask_for_user_privs (e.g. DCSync → fallback → LSA re-dump →
            # add_credential again) sees the flag and skips immediately.
            try:
                _assessed.add(_user_key)
            except Exception:  # noqa: BLE001
                pass
            shell.ask_for_user_privs(domain, user, cred)
        except Exception as e:  # noqa: BLE001
            telemetry.capture_exception(e)
            print_info_verbose(f"Failed to prompt for user privileges: {e}")


def _mark_user_owned_in_bloodhound(shell: Any, domain: str, user: str) -> None:
    """Mark a verified domain credential holder as owned in BloodHound (best-effort).

    Args:
        shell: PentestShell instance with ``_get_graph_service`` access.
        domain: Domain name (e.g. ``"corp.local"``).
        user: Username (samAccountName or UPN).
    """
    service_getter = getattr(shell, "_get_graph_service", None)
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


def _classify_credential_jackpot(
    shell: Any,
    *,
    domain: str,
    user: str,
) -> tuple[str, str, str, str]:
    """Classify the just-stored credential into a verdict tier.

    Returns ``(verdict_text, verdict_glyph, verdict_color, next_action)``.
    Tier-0 / Domain-Admin accounts get a crimson + jackpot framing. Regular
    accounts get a sage "stored" framing. The verdict drives both the panel
    border and the suggested next action, so the prompt visually "jumps" the
    moment a Tier-0 account lands and stays subdued otherwise.
    """
    raw_user = (user or "").strip().lower()

    da_markers = {
        "administrator",
        "krbtgt",
        "domain admins",
    }
    is_da_account = any(marker in raw_user for marker in da_markers)

    is_tier0 = False
    try:
        domain_data = (shell.domains_data or {}).get(domain, {}) or {}
        tier0_users = domain_data.get("tier0_users") or domain_data.get("high_value_users") or []
        if isinstance(tier0_users, (list, set, tuple)):
            tier0_lower = {str(value or "").strip().lower() for value in tier0_users}
            if raw_user in tier0_lower:
                is_tier0 = True
    except Exception:  # noqa: BLE001
        is_tier0 = False

    if is_da_account or is_tier0:
        return (
            "DOMAIN ADMIN CAPTURED" if is_da_account else "TIER-0 PRINCIPAL CAPTURED",
            GLYPH_JACKPOT,
            COLOR_CRIMSON,
            "run `dump dcsync` to extract the full NTDS.dit",
        )

    return (
        "CREDENTIAL STORED",
        GLYPH_VERIFIED,
        COLOR_SAGE,
        f"run `attack_paths {domain} owned` to spray and pivot from this principal",
    )


def _render_credential_stored_panel(
    shell: Any,
    *,
    domain: str,
    user: str,
    credential: str,
    is_hash: bool,
    source_steps: list[object] | None,
    credential_origin: str | None,
) -> None:
    """Verdict-first panel rendered right after a domain credential verifies.

    UX intent: the operator stores credentials dozens of times in a single
    engagement. The single piece of information they want is a one-line
    answer to "what did I just unlock and what should I do next?". This
    panel leads with the verdict, places provenance + kind on a single
    info line, and surfaces a single highest-value next action.
    """
    marked_user = mark_sensitive(user, "user")
    marked_domain = mark_sensitive(domain, "domain")

    verdict_text, verdict_glyph, verdict_color, next_action = (
        _classify_credential_jackpot(shell, domain=domain, user=user)
    )

    # Provenance attribution. Prefer the explicit origin tag when the caller
    # supplied one, otherwise derive from recorded steps, otherwise fall back
    # to the credentials_meta-derived label.
    provenance_label = ""
    if credential_origin:
        provenance_label = str(credential_origin).strip()
    elif source_steps:
        try:
            first_step = source_steps[0]
            provenance_label = (
                getattr(first_step, "relation", None)
                or getattr(first_step, "kind", None)
                or ""
            )
            provenance_label = str(provenance_label or "").strip()
        except Exception:  # noqa: BLE001
            provenance_label = ""
    if not provenance_label:
        provenance_label = _resolve_credential_provenance_label(
            shell, domain=domain, user=user
        )

    kind_label = "NTLM hash" if is_hash else "password"

    provenance_part = (
        f"    [{COLOR_MUTED}]Provenance:[/{COLOR_MUTED}] via {provenance_label}"
        if provenance_label and provenance_label.lower() != "unknown"
        else ""
    )
    info_lines = [
        f"[bold]{marked_user}[/bold] [{COLOR_MUTED}]@[/{COLOR_MUTED}] [bold]{marked_domain}[/bold]",
        f"[{COLOR_MUTED}]Kind:[/{COLOR_MUTED}] {kind_label}{provenance_part}",
        "",
        (
            f"[bold {verdict_color}]{GLYPH_NEXT} Next:[/bold {verdict_color}] "
            f"{next_action}"
        ),
    ]

    body = Text.from_markup("\n".join(info_lines))

    print_panel(
        body,
        title=(
            f"[bold {verdict_color}]{verdict_glyph} {verdict_text}"
            f"[/bold {verdict_color}]"
        ),
        border_style=verdict_color,
        expand=False,
        padding=(0, 1),
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
    skip_user_privs_enumeration: bool = False,
    verify_credential: bool = True,
    verify_local_credential: bool = True,
    prompt_local_reuse_after: bool = True,
    ui_silent: bool = False,
    ensure_fresh_kerberos_ticket: bool = True,
    force_authenticated_enumeration: bool = False,
    prompt_when_already_authenticated: bool = False,
    allow_empty_credential: bool = False,
    trusted_manual_validation: bool = False,
    mark_user_compromised: bool = True,
    credential_origin: str | None = None,
    local_account_rid: str | None = None,
    metadata: "CredentialMetadata | None" = None,
    force_recheck_user_privs: bool = False,
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
        skip_user_privs_enumeration: When True, never invoke privilege-enumeration
            prompts or attack-path privilege follow-ups for this credential.
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
        trusted_manual_validation: When True, skip the live verification step and
            treat the credential as already validated by the operator. This is
            reserved for controlled flows such as manual confirmation of one
            staged WriteLogonScript password where another automatic LDAP check
            would risk locking the account.
        mark_user_compromised: When True (default), record that this credential
            should count as a compromised-user milestone for the current
            session. Manual/import flows such as ``creds save`` must override
            this to False.
        credential_origin: Optional machine-readable provenance label for this
            credential (for example ``kerberoast``, ``dcsync``, ``spray``,
            ``ReadLAPSPassword``). Persisted into
            ``credentials_meta[user]["credential_origin"]`` so the ``creds show``
            Provenance column can attribute the source. Two origins identify a
            SELF-INTRODUCED credential and are excluded from the
            compromised-credential side-effects (the ``first_cred_found``
            capture, the ``credential`` identity-compromise event, and the
            session-compromised milestone): ``authenticated_scan`` (the scan's
            own STARTING credential supplied to ``adscan ci auth`` /
            ``start_auth``) and ``user_provided`` (a manual ``creds save`` /
            ``creds add``). Such a credential remains a fully owned principal
            for attack-path discovery. See
            ``session_compromise_state_service.NON_COMPROMISE_ORIGINS``.
        local_account_rid: Optional RID for local-account credentials. RID 500
            combined with LAPS provenance suppresses local reuse prompts because
            LAPS-managed built-in Administrator passwords are per-host secrets.
        force_recheck_user_privs: When True, bypass the per-session "privileges
            already assessed" dedup guard so a user whose privileges just changed
            (for example: an existing account just promoted to Domain Admins) is
            re-enumerated even if it was assessed earlier this session.
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
            # Keep the secret CLEARTEXT on the operator terminal (the pentester
            # needs it) while marking it so the telemetry export sanitizer
            # scrubs it. Never redact to "***".
            cred_type: mark_sensitive(cred, "password"),
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

    # A SELF-INTRODUCED credential (the scan's own starting credential or a
    # manually entered one) is the INPUT to the scan, not something compromised
    # during it. Its provenance origin is in ``NON_COMPROMISE_ORIGINS`` — it is
    # excluded from the compromise side-effects below (first_cred_found capture,
    # the identity-compromise event, the session-compromised milestone) while
    # remaining a fully owned principal for attack-path discovery.
    is_self_introduced_credential = (
        str(credential_origin or "").strip().lower() in NON_COMPROMISE_ORIGINS
    )

    # SSOT hardening (empty-fed re-verification guard): an EMPTY secret fed for a
    # DOMAIN user that already has a real (non-empty) stored credential must NEVER
    # be verified or purged as the empty string — that would delete the captured
    # credential. This happens when a redundant re-verification / harvest
    # re-activation of an already-validated hit (e.g. a password-spray hit that
    # already stored the real password and minted a TGT) calls
    # add_credential(user, "", allow_empty_credential=True). Reuse the stored
    # secret instead of verifying the empty string. A GENUINE blank-password
    # candidate has NO non-empty stored secret for the user, so it stays on the
    # explicit-blank path untouched. Local credentials (host+service) own a
    # separate store and verification path, so they are excluded here. Computed
    # once, before both domain verification sites (subworkspace-creation and the
    # main domain branch), so neither can purge the real credential.
    empty_fed_over_stored_secret = False
    if not (host and service) and allow_empty_credential and cred == "":
        _domain_data = shell.domains_data.get(domain, {})
        _credentials_dict = (
            _domain_data.get("credentials", {}) if isinstance(_domain_data, dict) else {}
        )
        _current_domain_cred = (
            _credentials_dict.get(user) if isinstance(_credentials_dict, dict) else None
        )
        if isinstance(_current_domain_cred, str) and _current_domain_cred != "":
            empty_fed_over_stored_secret = True
            cred = _current_domain_cred
            print_info_verbose(
                "Empty credential supplied for a user with an existing stored "
                "secret; reusing the stored credential instead of verifying the "
                "empty string."
            )

    import os
    import time

    if not os.path.exists(os.path.join("domains", domain)):
        emit_phase("domain_setup")
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
        if verify_credential and not trusted_manual_validation:
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
                if empty_fed_over_stored_secret:
                    # Defense in depth: never delete the real stored credential
                    # because a redundant empty-fed re-verification failed. The
                    # captured secret (already validated by the flow that stored
                    # it, e.g. a spray hit that minted a TGT) stays authoritative.
                    print_info_verbose(
                        "Keeping the existing stored credential: empty-fed "
                        "re-verification for a user with a non-empty stored "
                        "secret must not purge it."
                    )
                    return
                _purge_failed_domain_credential(
                    shell, domain=domain, user=user, ui_silent=ui_silent
                )
                return
        if trusted_manual_validation:
            credential_verified = True
            print_info_verbose(
                "[creds] Skipping live domain verification because the credential "
                "was manually validated by the operator."
            )
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
            _apply_credential_metadata(
                shell, domain=domain, user=user, metadata=metadata
            )

            # Phase 3: AdminTo edge emission lives inside
            # ``_check_local_creds_native_smb`` (the native SMB Pwn3d!
            # verifier). Non-SMB services never emit an AdminTo edge here.

            marked_user = mark_sensitive(user, "user")
            marked_host = mark_sensitive(host, "hostname")

            marked_domain = mark_sensitive(domain, "domain")
            marked_cred = mark_sensitive(cred, "password")
            print_info_verbose(
                f"Local credential added for user '{marked_user}' on host {marked_host} ({service}) of domain {marked_domain}: {marked_cred}"
            )

            if service == "mssql":
                shell.ask_for_mssql_steal(domain, host, user, cred, "false")
            elif _should_prompt_local_reuse_after(
                prompt_local_reuse_after=prompt_local_reuse_after,
                service=service,
                credential_origin=credential_origin,
                local_account_rid=local_account_rid,
                source_steps=source_steps,
            ):
                shell.ask_for_local_cred_reuse(domain, user, cred)

            try:
                emit_event(
                    "credential",
                    phase="credential_analysis",
                    phase_label="Credential Analysis",
                    category="identity_compromise",
                    username=user,
                    domain=domain,
                    host=host,
                    service=service,
                    credential_type="hash" if is_hash else "password",
                    scope="local",
                    verification_status=(
                        "verified" if verify_local_credential else "trusted_import"
                    ),
                    message=f"Local access established for {user} on {host}.",
                )
            except Exception as exc:  # pragma: no cover - best effort eventing
                telemetry.capture_exception(exc)

            if mark_user_compromised:
                mark_session_user_compromised(shell, user)

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
        if trusted_manual_validation:
            credential_verified = True
            print_info_verbose(
                "[creds] Treating domain credential as manually validated; "
                "live verification skipped."
            )
        elif verify_credential and not credential_verified:
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
                if empty_fed_over_stored_secret:
                    # Defense in depth: never delete the real stored credential
                    # because a redundant empty-fed re-verification failed. The
                    # captured secret (already validated by the flow that stored
                    # it, e.g. a spray hit that minted a TGT) stays authoritative.
                    print_info_verbose(
                        "Keeping the existing stored credential: empty-fed "
                        "re-verification for a user with a non-empty stored "
                        "secret must not purge it."
                    )
                    return
                _purge_failed_domain_credential(
                    shell, domain=domain, user=user, ui_silent=ui_silent
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
            _apply_credential_metadata(
                shell, domain=domain, user=user, metadata=metadata
            )
            if credential_origin:
                # Persist provenance into ``credentials_meta`` so the
                # ``creds show`` Provenance column can attribute the source and
                # the compromise SSOT can exclude self-introduced credentials
                # (``authenticated_scan`` / ``user_provided``) from counters,
                # panel, telemetry, and PostHog.
                from adscan_internal.services.credentials import (  # noqa: PLC0415
                    set_credential_origin,
                )

                set_credential_origin(
                    shell, domain=domain, username=user, origin=credential_origin
                )
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
                    # A self-introduced credential (scan starting credential
                    # or a manual ``creds save``) is the INPUT, not a compromise
                    # win — never fire the first_cred_found PostHog capture /
                    # victory hint for it.
                    if new_count == target_index and not is_self_introduced_credential:
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

            if not is_self_introduced_credential:
                try:
                    emit_event(
                        "credential",
                        phase="credential_analysis",
                        phase_label="Credential Analysis",
                        category="identity_compromise",
                        username=user,
                        domain=domain,
                        credential_type="hash" if is_hash else "password",
                        scope="domain",
                        verification_status=(
                            "manually_validated"
                            if trusted_manual_validation
                            else "verified"
                            if verify_credential or credential_verified
                            else "trusted_import"
                        ),
                        message=f"Access established for {user}@{domain}.",
                    )
                except Exception as exc:  # pragma: no cover - best effort eventing
                    telemetry.capture_exception(exc)

                if mark_user_compromised:
                    mark_session_user_compromised(shell, user)

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

            if not ui_silent:
                try:
                    _render_credential_stored_panel(
                        shell,
                        domain=domain,
                        user=user,
                        credential=cred,
                        is_hash=is_hash,
                        source_steps=source_steps,
                        credential_origin=credential_origin,
                    )
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)

            _ensure_verified_domain_credential_ticket(
                shell,
                domain=domain,
                user=user,
                credential=cred,
                ui_silent=ui_silent,
                ensure_fresh_kerberos_ticket=ensure_fresh_kerberos_ticket,
            )

            # Set shell.domain and proceed with enumeration if applicable.
            # Single source of truth: ``set_active_domain`` (shared with the
            # start_unauth/start_auth DNS finalizer) keeps both paths in lockstep.
            from adscan_internal.cli.common import set_active_domain  # noqa: PLC0415

            set_active_domain(shell, domain)

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
                skip_user_privs_enumeration=skip_user_privs_enumeration,
                force_authenticated_enumeration=force_authenticated_enumeration,
                prompt_when_already_authenticated=prompt_when_already_authenticated,
                allow_empty_credentials=allow_empty_credential,
                force_recheck_user_privs=force_recheck_user_privs,
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


def store_kerberos_principal_material(
    shell: Any,
    *,
    domain: str,
    username: str,
    nt_hash: str | None = None,
    aes256: str | None = None,
    aes128: str | None = None,
    source: str = "",
    target_host: str = "",
    rid: str = "",
) -> Any:
    """Persist typed Kerberos key material without invoking ``add_credential``.

    This path is for principals whose recovered secret is primarily useful as
    Kerberos key material, not as a normal interactive AD credential. It stores
    RC4/NT, AES128 and AES256 under ``domains_data[domain]["kerberos_keys"]``
    and intentionally skips the generic credential pipeline:

    - no cracking attempts
    - no live credential verification
    - no auto-generated Kerberos TGT
    - no BloodHound "owned" tag
    - no follow-up privilege enumeration prompts

    Args:
        shell: Active shell instance with ``domains_data``.
        domain: Owning AD domain.
        username: Principal name whose material was recovered.
        nt_hash: Optional RC4/NT material.
        aes256: Optional AES256 material.
        aes128: Optional AES128 material.
        source: Short provenance label for the recovered material.
        target_host: Host/source context this material belongs to.
        rid: Optional RID suffix for per-RODC ``krbtgt_<RID>`` accounts.

    Returns:
        The normalized :class:`KerberosKeyMaterial` written to the workspace.
    """
    from adscan_internal.services.credential_store_service import CredentialStoreService

    normalized_domain = str(domain or "").strip().rstrip(".").lower()
    if not normalized_domain:
        raise ValueError("Kerberos principal material requires a valid domain.")

    material = CredentialStoreService().store_kerberos_key_material(
        domains_data=shell.domains_data,
        domain=normalized_domain,
        username=username,
        nt_hash=nt_hash,
        aes256=aes256,
        aes128=aes128,
        source=source,
        target_host=target_host,
        rid=rid,
    )

    print_info_debug(
        "[creds] stored Kerberos principal material: "
        f"user={mark_sensitive(material.username, 'user')} "
        f"domain={mark_sensitive(normalized_domain, 'domain')} "
        f"nt_hash={bool(material.nt_hash)} aes256={bool(material.aes256)} "
        f"aes128={bool(material.aes128)} "
        f"target_host={mark_sensitive(material.target_host, 'hostname')}"
    )
    return material


def add_credentials_batch(
    shell: Any,
    *,
    domain: str,
    credentials: list[tuple[str, str]],
    skip_hash_cracking: bool = False,
    pdc_ip: str | None = None,
    source_steps: list[object] | None = None,
    prompt_for_user_privs_after: bool = True,
    skip_user_privs_enumeration: bool = False,
    verify_credential: bool = True,
    ui_silent: bool = False,
    ensure_fresh_kerberos_ticket: bool = True,
    metadata_by_user: "dict[str, CredentialMetadata] | None" = None,
    credential_origin: str | None = None,
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
        skip_user_privs_enumeration: Forwarded to add_credential.
        verify_credential: Forwarded to add_credential.
        ui_silent: Forwarded to add_credential.
        ensure_fresh_kerberos_ticket: Forwarded to add_credential.
        credential_origin: Machine-readable provenance label (e.g. ``"spray"``)
            forwarded to each ``add_credential`` so the Provenance column never
            degrades to "via unknown" on the batch path.

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
        per_user_metadata = None
        if metadata_by_user:
            per_user_metadata = metadata_by_user.get(username) or metadata_by_user.get(
                username.lower()
            )
        add_credential(
            shell=shell,
            domain=domain,
            user=username,
            cred=resolved_credential,
            skip_hash_cracking=True,
            pdc_ip=pdc_ip,
            source_steps=source_steps,
            prompt_for_user_privs_after=prompt_for_user_privs_after,
            skip_user_privs_enumeration=skip_user_privs_enumeration,
            verify_credential=verify_credential,
            ui_silent=ui_silent,
            ensure_fresh_kerberos_ticket=ensure_fresh_kerberos_ticket,
            metadata=per_user_metadata,
            credential_origin=credential_origin,
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
    credential_origin: str | None = None,
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
        credential_origin: Machine-readable provenance label forwarded to each
            ``add_credential`` so the Provenance column never degrades to "via
            unknown" on the local batch path.

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
            credential_origin=credential_origin,
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


def _purge_failed_domain_credential(
    shell: Any, *, domain: str, user: str, ui_silent: bool = False
) -> bool:
    """Dispose of a credential that FAILED verification — SSOT for the policy.

    Shared by ``select_cred`` and the authenticated-enumeration flow so the
    keep/delete decision lives in exactly one place:

    * A credential that is valid-but-unusable (PASSWORD_MUST_CHANGE /
      PASSWORD_EXPIRED) or whose failure was transient/unclassified is NEVER
      purged — only genuinely INVALID / USER_NOT_FOUND credentials are deletion
      candidates (gated by :func:`_should_delete_failed_domain_credential`).
    * Even then the operator confirms before the irreversible delete
      (default yes). ``ui_silent`` (internal recovery sub-calls) and
      non-interactive runs auto-resolve to the default, preserving the prior
      auto-purge behaviour for batch/CI.

    Returns ``True`` iff the credential was deleted.
    """
    from adscan_internal.services.credential_store_service import (
        CredentialStoreService,
    )

    marked_user = mark_sensitive(user, "user")
    marked_domain = mark_sensitive(domain, "domain")

    if not _should_delete_failed_domain_credential(shell):
        # Valid but not usable as-is (e.g. password change required), expired, or
        # a transient/unclassified failure — keep a non-invalid credential.
        if not ui_silent:
            print_warning(
                f"Credential for '[bold]{marked_user}[/bold]' in domain "
                f"[bold]{marked_domain}[/bold] is KEPT — valid but not usable as-is "
                "(e.g. a password change is required before logon)."
            )
        return False

    if not ui_silent:
        print_error(
            f"Incorrect credentials for user '[bold]{marked_user}[/bold]' in "
            f"domain [bold]{marked_domain}[/bold]."
        )
        if not confirm_ask(
            f"Delete the invalid stored credential for '{user}'?", default=True
        ):
            print_info(
                f"Kept the credential for '{user}' in domain {domain} (not deleted)."
            )
            return False

    deleted = CredentialStoreService().delete_domain_credential(
        domains_data=shell.domains_data, domain=domain, username=user
    )
    if deleted:
        if not ui_silent:
            print_warning(
                f"Existing invalid credential for '[bold]{marked_user}[/bold]' in "
                f"domain [bold]{marked_domain}[/bold] has been deleted."
            )
        else:
            print_info_verbose(
                f"[ui_silent] Existing credential for '{marked_user}' in domain "
                f"{marked_domain} has been deleted."
            )
        if getattr(shell, "current_workspace_dir", None) and hasattr(
            shell, "save_workspace_data"
        ):
            try:
                shell.save_workspace_data()
            except Exception:  # noqa: BLE001
                pass
    return deleted


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


def _check_local_creds_native_smb(
    shell: Any,
    *,
    domain_name: str,
    username: str,
    cred_value: str,
    host: str,
) -> bool:
    """Verify a *local* credential has SMB admin on *host* via native aiosmb.

    Replaces the NetExec ``(Pwn3d!)`` subprocess for the SMB branch of
    :func:`check_local_creds`. The credential being verified is a
    **local account on the target host** — this is the
    ``add_credential(host=X, service="smb")`` path which stores under
    ``domains_data[domain]["local_credentials"]``, not the domain user
    branch. ``domain_name`` is workspace context, not an AD identity
    for the user.

    Graph mutation is intentionally NOT performed here. AdminTo edges
    are owned by:
      * the LDAP / native graph collector for domain users
      * ``LocalAdminPassReuse`` star-topology edges for local credential
        reuse (see ``dumps.py:_run_native_local_admin_reuse_check``)
    Emitting an ``AdminTo`` edge from a local-credential verification
    would risk a sAMAccountName collision falsely linking the AD
    built-in Administrator to the host.

    Returns:
        True when local admin is confirmed (Pwn3d!), False otherwise.
        Never raises to the caller.
    """
    from adscan_internal import (
        print_error,
        print_info_debug,
        print_info_verbose,
        print_operation_header,
        print_success,
        print_warning,
    )
    from adscan_internal.rich_output import mark_sensitive
    from adscan_internal.services.async_bridge import run_async_sync
    from adscan_internal.services.smb_privilege import (
        SMBPrivilegeStatus,
        verify_domain_user_local_admin,
    )

    is_hash = bool(shell.is_hash(cred_value))
    cred_type = "Hash" if is_hash else "Password"
    print_operation_header(
        "Local Credential Verification",
        details={
            "Domain Context": domain_name,
            "Target Host": host,
            "Service": "SMB",
            "Username": username,
            cred_type: cred_value,
        },
        icon="🔑",
    )

    marked_username = mark_sensitive(username, "user")
    marked_host = mark_sensitive(host, "hostname")

    print_info_verbose("Executing host credential verification (native aiosmb)")
    print_info_debug(
        f"[creds] native SMB Pwn3d! probe host={marked_host} "
        f"user={marked_username} cred_kind={'nt_hash' if is_hash else 'password'}"
    )

    # Pull a KDC hint from domains_data when available — keeps Kerberos
    # fallback working in NTLM-disabled environments.
    kdc_ip: str | None = None
    try:
        kdc_ip = resolve_dc_ip((shell.domains_data.get(domain_name, {}) or {}))
    except Exception:  # noqa: BLE001
        kdc_ip = None

    try:
        result = run_async_sync(
            verify_domain_user_local_admin(
                domain=domain_name,
                username=username,
                credential=cred_value,
                host=host,
                kdc_ip=kdc_ip,
            )
        )
    except Exception as exc:  # pylint: disable=broad-except
        telemetry.capture_exception(exc)
        print_error(
            f"An unexpected error occurred during host credential verification: {exc}"
        )
        return False

    status = result.status

    if status == SMBPrivilegeStatus.ADMIN:
        print_success(
            f"User '[bold]{marked_username}[/bold]' has "
            f"[bold red]ADMIN[/bold red] access to [bold]{marked_host}[/bold] "
            f"via [bold]smb[/bold]!"
        )
        # NOTE: This path is `add_credential(host=X, service="smb")` — a
        # LOCAL credential. The verified user is a local account on the
        # target host (no AD identity), so emitting an `AdminTo` edge
        # would be wrong: aside from the user node not existing in the
        # AD attack_graph.json, a sAMAccountName collision (e.g. local
        # "Administrator" matching the domain built-in Administrator)
        # would write a falsified AdminTo edge from the domain user to
        # the host. Local-credential reuse is captured separately by
        # `LocalAdminPassReuse` star-topology edges from
        # `dumps.py:_run_native_local_admin_reuse_check_async`. Domain
        # user → host AdminTo materialization is owned by the LDAP /
        # native graph collector, which is the canonical source of
        # truth for AD relationships. The `add_runtime_admin_to_edge`
        # helper from Phase 3 stays available for a future native
        # "domain-user pwn3d sweep" flow if one is added.
        return True

    if status == SMBPrivilegeStatus.NOT_ADMIN:
        print_info_verbose(
            f"Successfully verified credentials for user "
            f"'[bold]{marked_username}[/bold]' on host "
            f"'[bold]{marked_host}[/bold]' via [bold]smb[/bold] "
            "(non-admin access)."
        )
        return True

    if status == SMBPrivilegeStatus.AUTH_FAILED:
        print_error(
            f"Logon failure for local user '[bold]{marked_username}[/bold]' on "
            f"host '[bold]{marked_host}[/bold]' via [bold]smb[/bold]. "
            "Incorrect credentials."
        )
        return False

    if status == SMBPrivilegeStatus.UNREACHABLE:
        print_warning(
            f"Host '[bold]{marked_host}[/bold]' unreachable for SMB privilege "
            f"check ({result.error or 'network error'})."
        )
        return False

    print_error(
        f"Host credential verification failed for user '[bold]{marked_username}[/bold]' "
        f"on '[bold]{marked_host}[/bold]' via [bold]smb[/bold] "
        f"({result.error or 'unknown error'})."
    )
    return False


def _check_local_creds_native_nonsmb(
    shell: Any,
    *,
    domain_name: str,
    username: str,
    cred_value: str,
    host: str,
    service: str,
) -> bool:
    """Verify a *local* credential for a NON-SMB service via native access probes.

    Routes MSSQL and WinRM local-credential verification through the native
    service-access probes (the impacket MSSQL backend / the PSRP WinRM backend)
    instead of the NetExec subprocess. Local accounts authenticate over NTLM, so
    Kerberos is disabled for the probe. Returns True when access is confirmed;
    admin is sysadmin for MSSQL and a confirmed PSRP shell for WinRM. Never
    raises to the caller.
    """
    from adscan_internal import (
        print_error,
        print_info_verbose,
        print_operation_header,
        print_success,
        print_warning,
    )
    from adscan_internal.rich_output import mark_sensitive
    from adscan_internal.services.async_bridge import run_async_sync
    from adscan_internal.services.service_access_results import ServiceAccessFinding

    svc = str(service or "").strip().lower()
    is_hash = bool(shell.is_hash(cred_value))
    cred_type = "Hash" if is_hash else "Password"
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
    marked_username = mark_sensitive(username, "user")
    marked_host = mark_sensitive(host, "hostname")
    print_info_verbose(
        f"Executing host credential verification (native {svc} access probe)"
    )

    kdc_ip: str | None = None
    try:
        kdc_ip = resolve_dc_ip((shell.domains_data.get(domain_name, {}) or {}))
    except Exception:  # noqa: BLE001
        kdc_ip = None

    finding: ServiceAccessFinding | None = None
    is_admin = False
    try:
        if svc == "mssql":
            from adscan_internal.services.mssql_access_probe_service import (
                finding_is_sysadmin,
                run_mssql_access_probe_sweep,
            )

            findings = run_async_sync(
                run_mssql_access_probe_sweep(
                    domain=domain_name,
                    username=username,
                    secret=cred_value,
                    targets=[host],
                    use_kerberos=False,
                    kdc_host=kdc_ip,
                )
            )
            finding = findings[0] if findings else None
            is_admin = bool(finding and finding_is_sysadmin(finding))
        elif svc == "winrm":
            from adscan_internal.services.winrm_access_probe_service import (
                run_winrm_access_probe_sweep,
            )

            findings = run_winrm_access_probe_sweep(
                domain=domain_name,
                username=username,
                password=cred_value,
                targets=[host],
                workspace_dir=str(getattr(shell, "current_workspace_dir", "") or ""),
                domains_dir=str(getattr(shell, "domains_dir", "domains")),
                domain_data=(shell.domains_data.get(domain_name, {}) or {}),
                auth_mode="ntlm",
            )
            finding = findings[0] if findings else None
            # A confirmed WinRM/PSRP shell requires Remote Management access,
            # which on a member host is effectively local-admin equivalent.
            is_admin = bool(finding and finding.is_confirmed)
        else:
            print_warning(
                "Native local-credential verification supports SMB, MSSQL, and "
                f"WinRM; '{service}' is not supported."
            )
            return False
    except Exception as exc:  # pylint: disable=broad-except
        telemetry.capture_exception(exc)
        print_error(
            f"An unexpected error occurred during host credential verification: {exc}"
        )
        return False

    if finding is not None and finding.is_confirmed:
        if is_admin:
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

    reason = finding.reason if finding is not None else "no_result"
    print_error(
        f"Verification failed for local user '[bold]{marked_username}[/bold]' on "
        f"host '[bold]{marked_host}[/bold]' via [bold]{service}[/bold] ({reason})."
    )
    return False


def check_local_creds(
    shell: Any,
    domain_name: str,
    username: str,
    cred_value: str,
    host: str,
    service: str,
) -> bool:
    """Verify host-specific credentials for a service.

    Every service is verified natively (no subprocess): SMB via aiosmb
    (:func:`_check_local_creds_native_smb`); MSSQL and WinRM via their native
    access probes (:func:`_check_local_creds_native_nonsmb`).
    """
    if str(service or "").strip().lower() == "smb":
        return _check_local_creds_native_smb(
            shell,
            domain_name=domain_name,
            username=username,
            cred_value=cred_value,
            host=host,
        )

    return _check_local_creds_native_nonsmb(
        shell,
        domain_name=domain_name,
        username=username,
        cred_value=cred_value,
        host=host,
        service=service,
    )


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
        # default="1" so a non-interactive run (adscan ci) resolves to the
        # first user instead of returning "" → int("") ValueError crash.
        selected_idx = int(Prompt.ask("\nSelect a user by number: ", default="1")) - 1
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
        # ``user:rid:lm:nt:`` is the secretsdump (DRSUAPI/NTDS) dump format.
        shell.add_credential(domain, user, credential, credential_origin="secretsdump")
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
                from adscan_core.reporting.technical_report import (
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
                if not handle_optional_report_service_exception(
                    exc,
                    action="Technical finding sync",
                    debug_printer=print_info_debug,
                    prefix="[gpp]",
                ):
                    telemetry.capture_exception(exc)

        print_success(
            f"cpassword found{source_label}: {mark_sensitive(cpassword_value, 'password')}"
        )
        plaintext_password = decrypt_cpassword(cpassword_value)
        if not plaintext_password:
            print_warning(f"Failed to decrypt cpassword{source_label}.")
            continue

        if username:
            normalized_user = username.split("\\")[-1]
            shell.username = normalized_user
            print_success(f"Username: {normalized_user}")
            shell.password = plaintext_password
            print_success(f"Password: {mark_sensitive(plaintext_password, 'password')}")
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
                    credential_origin="gpp_cpassword",
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                add_credential(
                    shell,
                    domain,
                    normalized_user,
                    plaintext_password,
                    credential_origin="gpp_cpassword",
                )
        else:
            print_success(
                f"Decrypted password{source_label}: {mark_sensitive(plaintext_password, 'password')}"
            )

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
    *,
    include_implausible: bool = False,
) -> tuple[list[tuple], int]:
    """Filter one deduplicated finding set down to spraying-eligible credentials.

    Two gates apply in sequence, both load-bearing:

    1. **Sprayability gate** (legacy): the rule itself must produce
       password-shaped output. Rules that emit hashes, tokens, or
       structured secrets are excluded here so we never spray a
       SHA-256 against the DC by accident.
    2. **Plausibility gate** (new, 2026-05-21): even password-shaped
       output must pass :func:`is_plausible_password` to reach the
       spraying pool. This kills JSON-fragment FPs, GUIDs, hashes,
       and Base64 blobs that the regex layer accidentally captured.
       Operator can override via ``include_implausible=True`` when
       they have manual reason to spray a flagged candidate.

    Both gates merge into a single ``skipped`` counter for the caller's
    summary line; downstream debug logs surface the per-candidate
    reason so operators can audit exactly what the gate rejected.

    Args:
        credential_entries: ``(rule_name, cred_tuple)`` pairs produced
            by the dedup step. ``cred_tuple[0]`` is the password value.
        include_implausible: When ``True``, skip the plausibility gate
            and let implausible candidates through. The legacy
            sprayability gate still applies. Used by the
            ``spray --include-implausible`` override flag.

    Returns:
        ``(sprayable_tuples, skipped_count)``. ``sprayable_tuples`` is
        the curated list ready to be handed to kerbrute; ``skipped_count``
        is the COMBINED count of rule-incompatible AND implausible
        candidates dropped.
    """
    from adscan_internal.services.password_plausibility import (
        is_plausible_password,
    )

    sprayable: list[tuple] = []
    skipped = 0
    for rule_name, cred_tuple in credential_entries:
        if not is_sprayable_credsweeper_candidate(rule_name, cred_tuple):
            skipped += 1
            continue

        if not include_implausible:
            value = str(cred_tuple[0] or "")
            verdict = is_plausible_password(value)
            if not verdict.plausible:
                skipped += 1
                # Mark sensitive at debug time so the per-candidate audit
                # trail surfaces the reason without leaking the raw value
                # into shared telemetry.
                print_info_debug(
                    "[spray-gate] dropped implausible candidate: "
                    f"rule={rule_name!r} category={verdict.category!r} "
                    f"reason={verdict.reason!r}"
                )
                continue

        sprayable.append(cred_tuple)

    return sprayable, skipped


def display_credentials_with_rich(
    shell: Any,
    credentials: dict,
    *,
    presentation: CredentialPresentationOptions | None = None,
) -> None:
    """Display all found credentials in a structured, aesthetic format using Rich.

    Organized by credential type with ML confidence scores and a plausibility
    badge that surfaces structural anti-patterns (JSON fragments, GUIDs,
    hashes, Base64 blobs) without filtering them from the operator's view.
    See :mod:`adscan_internal.services.password_plausibility` for the
    verdict layers.

    Args:
        shell: The PentestShell instance with console
        credentials: Dictionary of credentials organized by type
    """
    if not credentials:
        return

    from adscan_internal.services.password_plausibility import (
        CATEGORY_DISPLAY,
        is_plausible_password,
    )

    presentation = presentation or CredentialPresentationOptions()

    # Create panels for each credential type
    panels = []

    # Sort credential types alphabetically
    sorted_types = sorted(credentials.keys())

    # Aggregate plausibility counters across all credential types so we can
    # render the post-table summary panel ("triage") in a single pass.
    plausible_total = 0
    implausible_total = 0
    implausible_by_category: dict[str, int] = {}

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
        table.add_column("Value", style="cyan", no_wrap=False, max_width=64, overflow="ellipsis")
        if presentation.confidence_label:
            table.add_column(
                presentation.confidence_label,
                style="green",
                justify="right",
                width=12,
            )
        # The "Plausibility" column carries operator-facing context for why a
        # candidate will or will not enter the spraying pool. Width capped so
        # long reasons (e.g. "structural delimiter X (JSON fragment...)") wrap
        # cleanly without pushing the rest of the table off-screen.
        table.add_column(
            "Plausibility",
            style="white",
            no_wrap=False,
            max_width=28,
            overflow="fold",
        )
        table.add_column("Seen", style="magenta", justify="right", width=6)
        table.add_column(
            presentation.source_column_label,
            style="dim",
            no_wrap=False,
            max_width=92,
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

            # Plausibility verdict — pure deterministic check, microseconds.
            # Even when the value is empty/None we still produce a verdict so
            # the column never carries blank cells (helps operators scanning
            # the table for issues).
            verdict = is_plausible_password(display_value or None)
            if verdict.plausible:
                plausible_total += 1
                plausibility_cell = "[bold green]✓ plausible[/bold green]"
                row_style = ""
            else:
                implausible_total += 1
                category = verdict.category or "other"
                implausible_by_category[category] = (
                    implausible_by_category.get(category, 0) + 1
                )
                # Two-line cell: short category tag (operator scans this
                # first) followed by the precise reason in dim text. Keeps
                # the table scannable without losing the diagnostic detail.
                cat_label = CATEGORY_DISPLAY.get(category, category) or category
                plausibility_cell = (
                    f"[bold yellow]⚠ {cat_label}[/bold yellow]\n"
                    f"[dim]{verdict.reason}[/dim]"
                )
                # Dim the entire row so the eye lands on plausible rows first.
                # The value remains visible (transparency) but its visual
                # weight signals "do not spray me by default".
                row_style = "dim"

            row = [
                str(idx),
                display_value,
            ]
            if presentation.confidence_label:
                row.append(ml_display)
            row.append(plausibility_cell)
            row.extend(
                [
                    str(occurrence_count),
                    summarize_credential_sources(shell, sources) or "N/A",
                ]
            )
            table.add_row(*row, style=row_style if row_style else None)

        panels.append(Panel(table, border_style="blue"))

    # Display all panels
    shell.console.print()
    for panel in panels:
        shell.console.print(panel)
        shell.console.print()

    # ── Triage summary ────────────────────────────────────────────────
    # Single line/panel that tells the operator EXACTLY what will happen
    # downstream: how many candidates pass the plausibility gate (these
    # go to spraying), how many were filtered, and the structural reason
    # breakdown so they can decide whether to override the gate.
    _render_credential_triage_summary(
        shell,
        plausible=plausible_total,
        implausible=implausible_total,
        by_category=implausible_by_category,
    )


def _render_credential_triage_summary(
    shell: Any,
    *,
    plausible: int,
    implausible: int,
    by_category: dict[str, int],
) -> None:
    """Render the post-table summary that explains what spray will and won't try.

    The summary is rendered as a single low-noise line when no candidates
    were filtered (the common case), and as a richer panel when there ARE
    implausible candidates the operator should know about. Both modes
    name the exact downstream consequence ("→ spray will skip N") so the
    operator never has to reverse-engineer why one of their findings
    isn't being tried against the DC.
    """
    from adscan_internal.services.password_plausibility import CATEGORY_DISPLAY

    total = plausible + implausible
    if total == 0:
        return

    if implausible == 0:
        # Quiet path: a single one-line success message keeps the CLI tidy
        # and avoids drawing attention away from the actual findings.
        shell.console.print(
            f"[bold green]✓[/bold green] "
            f"[bold]{plausible}/{total}[/bold] candidates plausible "
            f"→ all eligible for spraying."
        )
        shell.console.print()
        return

    # Loud path: explain what was filtered so the operator knows what the
    # gate decided. Categories are surfaced in deterministic order
    # (alphabetical by display label) so consecutive runs look stable.
    from rich.table import Table as _RichTable

    breakdown = _RichTable.grid(padding=(0, 2))
    breakdown.add_column(justify="left", no_wrap=True)
    breakdown.add_column(justify="right", style="dim")
    for category in sorted(by_category.keys(), key=lambda k: CATEGORY_DISPLAY.get(k, k)):
        label = CATEGORY_DISPLAY.get(category) or category or "other"
        breakdown.add_row(f"  [yellow]⚠[/yellow] {label}", f"× {by_category[category]}")

    headline = (
        f"[bold green]✓ {plausible}[/bold green] plausible "
        f"[dim]·[/dim] "
        f"[bold yellow]⚠ {implausible}[/bold yellow] filtered from spraying"
    )
    note = (
        "[dim]Filtered candidates remain visible above for review.\n"
        "Operator can override per-candidate via `spray --include-implausible`.[/dim]"
    )

    from rich.console import Group as _RichGroup

    shell.console.print(
        Panel(
            _RichGroup(headline, "", breakdown, "", note),
            title="Spray candidate triage",
            title_align="left",
            border_style="yellow",
            padding=(1, 2),
        )
    )
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
                    credential_origin="passwordinshares",
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
                    credential_origin="passwordinshares",
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
                    credential_origin="mssql_creds",
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
        from adscan_core.reporting.technical_report import record_technical_finding

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
        if not handle_optional_report_service_exception(
            exc,
            action="Technical finding sync",
            debug_printer=print_info_debug,
            prefix="[smb-share-secrets]",
        ):
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


# ---------------------------------------------------------------------------
# Centralized credential-metadata application
# ---------------------------------------------------------------------------


def _apply_credential_metadata(
    shell: Any,
    *,
    domain: str,
    user: str,
    metadata: "CredentialMetadata | None",
) -> None:
    """Apply :class:`CredentialMetadata` via the privilege_role helpers.

    Phase-2 scope: privilege role / enabled / local-admin-host hints are
    no longer persisted to ``credentials_meta`` — they are resolved at
    read time from the canonical attack graph + identity-risk store by
    :func:`pick_credential_for_local_admin`. Only the two non-derivable
    fields are written here:

    * ``secret_kind`` — how to interpret the secret string.
    * ``aes256_key`` / ``aes128_key`` / ``kerberos_keys`` — additional
      Kerberos key material captured during DCSync.

    Exception-safe by design — every helper call is wrapped in its own
    try/except so a failing tag does not lose the underlying credential
    persist.
    """
    from adscan_internal.services.credentials import (
        CredentialMetadata as _CredentialMetadata,
        set_credential_kerberos_material,
        set_credential_secret_kind,
    )

    if metadata is None:
        return
    if not isinstance(metadata, _CredentialMetadata):
        # Defensive: reject malformed payloads silently (do not crash the
        # add_credential flow on a bad caller).
        return

    # --- secret_kind --------------------------------------------------------
    try:
        if metadata.secret_kind is not None:
            set_credential_secret_kind(
                shell,
                domain=domain,
                username=user,
                secret_kind=metadata.secret_kind,
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)

    # --- kerberos material --------------------------------------------------
    try:
        if (
            metadata.aes256_key
            or metadata.aes128_key
            or metadata.kerberos_keys
        ):
            set_credential_kerberos_material(
                shell,
                domain=domain,
                username=user,
                aes256_key=metadata.aes256_key,
                aes128_key=metadata.aes128_key,
                kerberos_keys=tuple(metadata.kerberos_keys or ()),
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
