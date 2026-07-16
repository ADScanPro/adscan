"""Scan CLI orchestration helpers.

This module extracts scan-related orchestration logic out of the monolithic
`adscan.py` so it can be reused by future UX layers while keeping runtime
behaviour stable for the current CLI.
"""

from __future__ import annotations

import os
import re
from typing import Any, Protocol

from rich.prompt import Confirm

from adscan_internal import (
    print_error,
    print_exception,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_operation_header,
    print_warning,
    telemetry,
)
from adscan_internal.rich_output import (
    mark_sensitive,
)
from adscan_internal.cli.dns import (
    finalize_domain_context,
)


def _get_domain_auth_state(self: Any, domain: str) -> str:
    """Return domain auth state with a safe default.

    The start flow can create a domain context with only `pdc` populated before
    the auth state is established. In that case we default to `unauth` so scan
    orchestration does not raise `KeyError('auth')`.
    """
    domain_data = self.domains_data.setdefault(domain, {})
    auth_state = str(domain_data.get("auth", "")).strip().lower()
    if not auth_state:
        auth_state = "unauth"
        domain_data["auth"] = auth_state
        marked_domain = mark_sensitive(domain, "domain")
        print_info_verbose(
            f"Initializing missing auth state for {marked_domain} to '{auth_state}'."
        )
    return auth_state


def ask_for_unauth_scan(self, domain: str) -> None:
    """Prompt user to perform unauthenticated scan for the domain."""
    pdc_ip = self.domains_data.get(domain, {}).get("pdc")
    if pdc_ip:
        # Automated per-domain scan flow: populate this domain's context but
        # never flip the operator's active REPL domain (make_active stays
        # False, the default) — a scan must not silently switch shell.domain.
        finalize_domain_context(
            self,
            domain=domain,
            pdc_ip=pdc_ip,
            interactive=False,
            make_active=False,
        )
    # Unauthenticated scanning has two valid uses:
    # 1) Start unauth (black-box / no creds): get a first credential quickly, then stop.
    # 2) Start auth (gray-box / creds): optionally run unauth checks too (audit), because
    #    they can reveal additional attack surface even when we are already authenticated.
    #
    # In CTF mode, once we are authenticated/compromised we do not want additional
    # unauth noise, so we skip it entirely.
    current_auth = _get_domain_auth_state(self, domain)
    if self.type == "ctf" and current_auth in ["auth", "pwned"]:
        return

    if self.auto and current_auth not in ["auth", "pwned"]:
        self.do_unauth_scan(domain)
        return

    if not self.auto and current_auth not in ["auth", "pwned"]:
        marked_domain = mark_sensitive(domain, "domain")
        if Confirm.ask(
            f"Do you want to perform an unauthenticated scan for the domain {marked_domain}?",
            default=True,
        ):
            self.do_unauth_scan(domain)
        return

    if self.type == "ctf" and current_auth in ["auth", "pwned"]:
        marked_domain = mark_sensitive(domain, "domain")
        print_info_verbose(
            f"Skipping unauthenticated scan for domain {marked_domain} as it is authenticated."
        )
        return

    if self.type == "audit" and current_auth in ["auth", "pwned"]:
        marked_domain = mark_sensitive(domain, "domain")
        if Confirm.ask(
            f"Do you want to perform an unauthenticated scan for the domain {marked_domain}?",
            default=True,
        ):
            self.do_unauth_scan(domain)


def do_unauth_scan(self, domain: str) -> None:
    """Performs an unauthenticated scan for the specified domain.

    Phases 1 and 2 (SMB null/guest, LDAP anonymous bind) run concurrently on
    the native async stack — aiosmb + badldap, no NetExec subprocess. Phase 3
    (Kerberos user enumeration via kerbrute) stays sequential because the
    user-enumeration UX expects a focused, dedicated panel.
    """
    from adscan_internal.services.scan_phases import phase_is_enabled  # noqa: PLC0415

    if not phase_is_enabled(self, "unauthenticated_attack_surface"):
        print_info(
            "Unauthenticated Attack Surface skipped (disabled in scan configuration)."
        )
        return

    initial_auth = self.domains_data.get(domain, {}).get("auth")
    pdc_ip = self.domains_data.get(domain, {}).get("pdc")
    if pdc_ip:
        # Automated per-domain scan flow: populate this domain's context but
        # never flip the operator's active REPL domain (make_active stays
        # False, the default) — a scan must not silently switch shell.domain.
        finalize_domain_context(
            self,
            domain=domain,
            pdc_ip=pdc_ip,
            interactive=False,
            make_active=False,
        )

    # In CTF, once we are authenticated/compromised, avoid additional unauth noise.
    if self.type == "ctf" and initial_auth in ["auth", "pwned"]:
        return

    pdc = self.domains_data.get(domain, {}).get("pdc", "N/A")

    # ── Phases 1+2 — concurrent native probes ────────────────────────────
    probe_results = _run_unauth_native_probes(self, domain=domain, pdc=pdc)

    if initial_auth not in ["auth", "pwned"] and self.domains_data.get(domain, {}).get(
        "auth"
    ) in ["auth", "pwned"]:
        return

    # ── Phase 2.5 — native enrichment over the open unauth surface ───────
    enrichment_results = _run_unauth_enrichment(self, domain=domain, pdc=pdc)

    # ── Phase 3 — conditional: follow up on open surface or enumerate users ──
    # If at least one probe opened an attack surface, chain into share/LDAP
    # enumeration followups. Kerberos user enumeration (kerbrute) is only
    # useful when every probe was denied and we have no foothold at all.
    _run_unauth_followups_or_kerbrute(
        self,
        domain=domain,
        pdc=pdc,
        probe_results=probe_results,
        enrichment_results=enrichment_results,
    )


def _null_share_preview(probe_results: Any, *, max_names: int = 3) -> str:
    """Return a compact share-name preview from null-session probe results.

    Filters out noise shares (IPC$, ADMIN$, C$, PRINT$) and shows up to
    ``max_names`` interesting names followed by a "+N more" suffix when needed.
    Falls back to "shares" when no probe data is available.
    """
    if probe_results is None:
        return "shares"
    _NOISE = {"IPC$", "ADMIN$", "C$", "PRINT$"}
    interesting: list[str] = []
    for r in probe_results.smb_null:
        if r.status == "open":
            interesting.extend(s.name for s in r.shares if s.name.upper() not in _NOISE)
    if not interesting:
        # Fall back to all share names if everything was "noise"
        for r in probe_results.smb_null:
            if r.status == "open":
                interesting.extend(s.name for s in r.shares if s.name)
    if not interesting:
        return "shares"
    shown = interesting[:max_names]
    rest = len(interesting) - len(shown)
    preview = ", ".join(shown)
    return f"{preview} +{rest} more" if rest > 0 else preview


def _render_attack_surface_panel(
    probe_results: Any,
    *,
    domain: str,
    domain_data: dict,
) -> None:
    """Render a Rich summary panel of unauth probe outcomes, grouped by objective.

    Pentesters reason about objectives ("did I enumerate users? did I get
    shares? did I get a credential?"), not techniques in isolation.  The
    panel surfaces three objective sections — User enumeration, Share
    enumeration, Credential harvesting — and lists every technique tried
    under each, marking the winning technique with an arrow so attribution
    is unambiguous.

    The winning technique is the one whose result actually populated the
    inventory.  When techniques disagree (e.g. SAMR denied but LSARPC RID
    Cycling found 8 users via the guest session), the panel makes that
    crystal-clear instead of asking the operator to reconcile contradictory
    "DENIED" rows against later "8 unified accounts" output.

    ``domain_data`` carries Phase 2.5 enrichment status flags stored by
    :func:`_apply_unauth_enrichment_results`.
    """
    from rich.console import Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    from adscan_core.output._state import get_console
    from adscan_core.theme import (
        ADSCAN_PRIMARY,
        COLOR_SAGE,
        COLOR_AMBER,
        COLOR_MUTED,
        ICON_SUCCESS,
        ICON_ERROR,
    )

    console = get_console()

    # ── Gather all probe + enrichment outcomes ────────────────────────────
    # SMB null
    null_result = (
        next((r for r in probe_results.smb_null if r.status == "open"), None)
        if probe_results is not None and probe_results.smb_null
        else None
    )
    null_connected = null_result is not None
    null_share_count = len(null_result.shares) if null_result is not None else 0
    null_has_walkable_shares = null_share_count > 0
    null_ipc_only = null_connected and null_share_count == 0

    # SMB guest
    guest_open_targets = (
        [r for r in probe_results.smb_guest if r.status == "open"]
        if probe_results is not None and probe_results.smb_guest
        else []
    )
    guest_share_total = sum(len(r.shares) for r in guest_open_targets)
    guest_open = bool(guest_open_targets)
    guest_error = (
        probe_results.smb_guest[0].error
        if (probe_results is not None and probe_results.smb_guest and not guest_open)
        else ""
    )

    # LDAP anonymous
    ldap_probe = (
        probe_results.ldap_anonymous if probe_results is not None else None
    )
    ldap_bind_open = ldap_probe is not None and ldap_probe.status == "open"
    # Detect "bind worked but search denied" — probe.status is "denied" in this
    # case too, but the error string carries the distinction.  Surface it as
    # LIMITED (amber) rather than DENIED (muted) because the DC is reachable
    # and future auth paths (LDAPS, channel binding, credentials) may open it.
    ldap_bind_only = (
        ldap_probe is not None
        and ldap_probe.status == "denied"
        and "bind allowed" in (ldap_probe.error or "").lower()
    )
    ldap_bind_error = (
        (ldap_probe.error or "denied") if ldap_probe and not ldap_bind_open else ""
    )

    # Enrichment outcomes (Phase 2.5 — fresh because RID cycling now runs
    # *inside* the enrichment, not in a post-summary phase).
    samr_status = domain_data.get("smb_null_samr_status", "skipped")
    samr_count = domain_data.get("smb_null_samr_users_count", 0)
    gpp_status = domain_data.get("smb_null_gpp_status", "skipped")
    gpp_count = domain_data.get("smb_null_gpp_leaks_count", 0)
    gpp_autologon = domain_data.get("smb_null_gpp_autologon_count", 0)
    ldap_users_status = domain_data.get("ldap_anon_users_status", "skipped")
    ldap_users_count = domain_data.get("ldap_anon_users_count", 0)
    rid_status = domain_data.get("smb_null_rid_cycling_status", "skipped")
    rid_count = domain_data.get("smb_null_rid_cycling_users_count", 0)
    rid_new = domain_data.get("smb_null_rid_cycling_new_count", 0)
    rid_reason = domain_data.get("smb_null_rid_cycling_reason", "")
    unified_users_count = domain_data.get("unauth_users_count", 0)

    # ── Status glyphs ─────────────────────────────────────────────────────
    GLYPH_HIT = ICON_SUCCESS          # ✓ — populated the inventory / found data
    GLYPH_PARTIAL = "⚠"               # bind ok, enumeration limited
    GLYPH_MISS = ICON_ERROR           # ✗ — outright denied / error
    GLYPH_SKIP = "·"                  # technique not attempted (intentional)

    # ── Layout: one master grid; each objective contributes a header row
    #          plus N indented sub-rows; an empty row separates objectives.
    grid = Table.grid(padding=(0, 0))
    grid.add_column()

    def _objective_header(
        icon: str,
        label: str,
        total_text: str,
        total_style: str,
        winner: str | None,
    ) -> Table:
        """Top row of an objective section: icon + label + total + winner pointer."""
        row = Table.grid(padding=(0, 2))
        row.add_column(width=2)
        row.add_column(min_width=22)
        row.add_column(min_width=14, justify="right")
        row.add_column()
        winner_text = (
            Text.from_markup(f"[dim]← {winner}[/dim]") if winner else Text("")
        )
        row.add_row(
            Text(icon, style=f"bold {total_style}"),
            Text(label, style="bold white"),
            Text(total_text, style=f"bold {total_style}"),
            winner_text,
        )
        return row

    def _technique_row(
        status_glyph: str,
        status_style: str,
        label: str,
        badge: str,
        badge_style: str,
        detail: str,
        detail_style: str,
    ) -> Table:
        """Indented sub-row under an objective header: technique outcome."""
        row = Table.grid(padding=(0, 2))
        row.add_column(width=2)  # indent
        row.add_column(width=2)  # status glyph
        row.add_column(min_width=28)  # technique label
        row.add_column(min_width=12)  # badge
        row.add_column()  # detail
        row.add_row(
            Text("", style=COLOR_MUTED),
            Text(status_glyph, style=status_style),
            Text(label, style=COLOR_MUTED),
            Text(badge, style=f"bold {badge_style}"),
            Text(detail, style=detail_style),
        )
        return row

    # Track per-objective success for the footer summary.
    objectives_total = 0
    objectives_won = 0
    objectives_limited = 0

    # ─────────────────────────────────────────────────────────────────────
    # OBJECTIVE 1 — User enumeration (SAMR + LDAP + LSARPC RID Cycling)
    # ─────────────────────────────────────────────────────────────────────
    objectives_total += 1
    # Resolve the winning technique — whichever surfaced the most users.
    techniques: list[tuple[str, int, str]] = [
        ("SAMR EnumDomainUsers", samr_count if samr_status == "done" else 0, samr_status),
        ("LDAP anon search", ldap_users_count if ldap_users_status == "done" else 0, ldap_users_status),
        ("LSARPC RID Cycling", rid_count if rid_status == "done" else 0, rid_status),
    ]
    winners = [t for t in techniques if t[1] > 0]
    user_winner = max(winners, key=lambda t: t[1])[0] if winners else None

    if unified_users_count > 0:
        objectives_won += 1
        header_style = COLOR_SAGE
        total_text = (
            f"{unified_users_count} user{'s' if unified_users_count != 1 else ''}"
        )
    else:
        header_style = COLOR_MUTED
        total_text = "no users"

    grid.add_row(
        _objective_header("👥", "User enumeration", total_text, header_style, user_winner)
    )

    # Sub-row: SAMR
    if samr_status == "done" and samr_count > 0:
        grid.add_row(_technique_row(
            GLYPH_HIT, COLOR_SAGE, "SAMR EnumDomainUsers",
            f"{samr_count} users", COLOR_SAGE,
            "via SMB null session", COLOR_MUTED,
        ))
    elif samr_status in ("denied", "error"):
        badge = "DENIED" if samr_status == "denied" else "ERROR"
        grid.add_row(_technique_row(
            GLYPH_MISS, COLOR_MUTED, "SAMR EnumDomainUsers",
            badge, COLOR_MUTED,
            "0xc0000022 ACCESS_DENIED" if samr_status == "denied" else "RPC error",
            COLOR_MUTED,
        ))
    elif null_connected:
        grid.add_row(_technique_row(
            GLYPH_SKIP, COLOR_MUTED, "SAMR EnumDomainUsers",
            "SKIPPED", COLOR_MUTED,
            "not attempted", COLOR_MUTED,
        ))

    # Sub-row: LDAP anon search
    if ldap_users_status == "done" and ldap_users_count > 0:
        grid.add_row(_technique_row(
            GLYPH_HIT, COLOR_SAGE, "LDAP anon search",
            f"{ldap_users_count} users", COLOR_SAGE,
            "via anonymous bind", COLOR_MUTED,
        ))
    elif ldap_bind_open and ldap_users_status != "done":
        grid.add_row(_technique_row(
            GLYPH_PARTIAL, COLOR_AMBER, "LDAP anon search",
            "LIMITED", COLOR_AMBER,
            "bind allowed · search denied (RootDSE only)", COLOR_AMBER,
        ))
    elif ldap_bind_only:
        # Bind worked (TCP + anonymous bind succeeded) but enumeration was
        # denied — surface as LIMITED so the operator knows LDAP is reachable.
        grid.add_row(_technique_row(
            GLYPH_PARTIAL, COLOR_AMBER, "LDAP anon search",
            "LIMITED", COLOR_AMBER,
            "bind accepted · user search denied (RootDSE only)", COLOR_AMBER,
        ))
    elif ldap_probe is not None:
        grid.add_row(_technique_row(
            GLYPH_MISS, COLOR_MUTED, "LDAP anon search",
            "DENIED", COLOR_MUTED,
            ldap_bind_error or "denied", COLOR_MUTED,
        ))

    # Sub-row: LSARPC RID Cycling
    if rid_status == "done" and rid_count > 0:
        # Show new vs total so the operator can tell whether RID cycling
        # uniquely contributed accounts or only confirmed existing ones.
        detail = (
            f"{rid_new} new account{'s' if rid_new != 1 else ''}"
            if rid_new
            else "all overlap with SAMR/LDAP"
        )
        grid.add_row(_technique_row(
            GLYPH_HIT, COLOR_SAGE, "LSARPC RID Cycling",
            f"{rid_count} users", COLOR_SAGE,
            f"via guest session — {detail}", COLOR_MUTED,
        ))
    elif rid_status == "skipped" and rid_reason:
        # Skipped intentionally — show why so the operator learns when
        # ADscan's fallback ladder activates.
        grid.add_row(_technique_row(
            GLYPH_SKIP, COLOR_MUTED, "LSARPC RID Cycling",
            "SKIPPED", COLOR_MUTED,
            rid_reason, COLOR_MUTED,
        ))
    elif rid_status == "denied":
        grid.add_row(_technique_row(
            GLYPH_MISS, COLOR_MUTED, "LSARPC RID Cycling",
            "DENIED", COLOR_MUTED,
            rid_reason or "guest session restricted", COLOR_MUTED,
        ))
    elif rid_status == "error":
        grid.add_row(_technique_row(
            GLYPH_MISS, COLOR_MUTED, "LSARPC RID Cycling",
            "ERROR", COLOR_MUTED,
            rid_reason or "rpc error", COLOR_MUTED,
        ))
    # else: rid_status == "skipped" with no reason — no guest session, no row.

    # ─────────────────────────────────────────────────────────────────────
    # OBJECTIVE 2 — Share enumeration (SMB Null + SMB Guest)
    # ─────────────────────────────────────────────────────────────────────
    grid.add_row(Text(""))  # blank line between objectives
    objectives_total += 1
    share_total = (null_share_count if null_has_walkable_shares else 0) + guest_share_total
    share_winner = None
    if guest_share_total >= null_share_count and guest_open:
        share_winner = "SMB Guest"
    elif null_has_walkable_shares:
        share_winner = "SMB Null"

    if share_total > 0:
        objectives_won += 1
        header_style = COLOR_SAGE
        total_text = f"{share_total} share{'s' if share_total != 1 else ''}"
    elif null_ipc_only:
        objectives_limited += 1
        header_style = COLOR_AMBER
        total_text = "IPC$ only"
    else:
        header_style = COLOR_MUTED
        total_text = "no shares"

    grid.add_row(
        _objective_header("📂", "Share enumeration", total_text, header_style, share_winner)
    )

    # Sub-row: SMB Null
    if null_has_walkable_shares:
        preview = _null_share_preview(probe_results)
        grid.add_row(_technique_row(
            GLYPH_HIT, COLOR_SAGE, "SMB Null session",
            f"{null_share_count} shares", COLOR_SAGE,
            preview, COLOR_MUTED,
        ))
    elif null_ipc_only:
        grid.add_row(_technique_row(
            GLYPH_PARTIAL, COLOR_AMBER, "SMB Null session",
            "IPC$ ONLY", COLOR_AMBER,
            "bind allowed · RestrictAnonymous=1", COLOR_AMBER,
        ))
    elif probe_results is not None and probe_results.smb_null:
        grid.add_row(_technique_row(
            GLYPH_MISS, COLOR_MUTED, "SMB Null session",
            "DENIED", COLOR_MUTED,
            probe_results.smb_null[0].error or "denied", COLOR_MUTED,
        ))

    # Sub-row: SMB Guest
    if guest_open:
        grid.add_row(_technique_row(
            GLYPH_HIT, COLOR_SAGE, "SMB Guest session",
            f"{guest_share_total} shares",
            COLOR_SAGE,
            f"across {len(guest_open_targets)} host{'s' if len(guest_open_targets) != 1 else ''}",
            COLOR_MUTED,
        ))
    elif probe_results is not None and probe_results.smb_guest:
        grid.add_row(_technique_row(
            GLYPH_MISS, COLOR_MUTED, "SMB Guest session",
            "DENIED", COLOR_MUTED,
            guest_error or "denied", COLOR_MUTED,
        ))

    # ─────────────────────────────────────────────────────────────────────
    # OBJECTIVE 3 — Credential harvesting (GPP cpassword + autologon)
    # ─────────────────────────────────────────────────────────────────────
    grid.add_row(Text(""))
    objectives_total += 1
    cred_total = gpp_count + gpp_autologon

    if cred_total > 0:
        objectives_won += 1
        header_style = COLOR_SAGE
        # Heuristic: if both cpassword and autologon are present, prefer
        # the one with more findings as the winner pointer.
        if gpp_count and not gpp_autologon:
            cred_winner = "GPP cpassword"
            total_text = f"{gpp_count} cred{'s' if gpp_count != 1 else ''}"
        elif gpp_autologon and not gpp_count:
            cred_winner = "GPP autologon"
            total_text = f"{gpp_autologon} cred{'s' if gpp_autologon != 1 else ''}"
        else:
            cred_winner = "GPP cpassword + autologon"
            total_text = f"{cred_total} creds"
    else:
        cred_winner = None
        header_style = COLOR_MUTED
        total_text = "no creds"

    grid.add_row(
        _objective_header("🔑", "Credential harvesting", total_text, header_style, cred_winner)
    )

    # Sub-row: GPP cpassword
    if gpp_status == "done" and gpp_count > 0:
        grid.add_row(_technique_row(
            GLYPH_HIT, COLOR_SAGE, "GPP cpassword",
            f"{gpp_count} decrypted", COLOR_SAGE,
            "SYSVOL groups.xml / static AES key", COLOR_MUTED,
        ))
    elif gpp_status == "done" and gpp_count == 0:
        grid.add_row(_technique_row(
            GLYPH_SKIP, COLOR_MUTED, "GPP cpassword",
            "EMPTY", COLOR_MUTED,
            "SYSVOL readable — no cpassword found", COLOR_MUTED,
        ))
    elif gpp_status in ("denied", "error") and null_connected:
        grid.add_row(_technique_row(
            GLYPH_MISS, COLOR_MUTED, "GPP cpassword",
            "DENIED", COLOR_MUTED,
            "SYSVOL not readable", COLOR_MUTED,
        ))
    # Sub-row: GPP autologon (only show when explicitly found — the same
    # filesystem walk covers it, so a separate "denied" row would be noise).
    if gpp_autologon > 0:
        grid.add_row(_technique_row(
            GLYPH_HIT, COLOR_SAGE, "GPP autologon",
            f"{gpp_autologon} cred{'s' if gpp_autologon != 1 else ''}", COLOR_SAGE,
            "Registry.xml DefaultPassword", COLOR_MUTED,
        ))

    # ── Footer ────────────────────────────────────────────────────────────
    duration_str = ""
    if probe_results is not None and probe_results.duration_seconds:
        duration_str = f"  ·  probed in {probe_results.duration_seconds:.2f}s"

    accent = ADSCAN_PRIMARY if objectives_won > 0 else COLOR_MUTED
    footer = Text()
    footer.append(
        f"  {objectives_total} objective{'s' if objectives_total != 1 else ''} probed",
        style=COLOR_MUTED,
    )
    footer.append(
        f"  ·  {objectives_won} successful",
        style=f"bold {accent}",
    )
    if duration_str:
        footer.append(duration_str, style=COLOR_MUTED)
    if objectives_limited > 0:
        footer.append(
            f"\n  {objectives_limited} partial — bind allowed but enumeration limited",
            style=COLOR_AMBER,
        )

    title = Text()
    title.append("⚡ Attack Surface", style=f"bold {ADSCAN_PRIMARY}")
    title.append(f"  ·  {domain}", style=f"dim {ADSCAN_PRIMARY}")

    console.print()
    border = (
        ADSCAN_PRIMARY
        if objectives_won > 0
        else (COLOR_AMBER if objectives_limited > 0 else COLOR_MUTED)
    )
    console.print(
        Panel(
            Group(grid, Text(""), footer),
            title=title,
            title_align="left",
            border_style=border,
            padding=(1, 2),
        )
    )


def _render_harvested_panel(
    *,
    domain: str,
    samr_done: bool,
    samr_count: int,
    ldap_done: bool,
    ldap_count: int,
    unified_count: int,
    gpp_done: bool,
    gpp_count: int,
    desc_creds_count: int = 0,
    desc_creds_preview: str = "",
    sources_breakdown: dict | None = None,
) -> None:
    """Render the "already harvested" briefing panel above the followup prompt.

    The Attack Surface panel above this one describes *what's exposed*; this
    panel describes *what we already pulled out of it during Phase 2.5*. Keeps
    the followup checkbox honest — only actionable items live in the prompt.

    Skipped silently when nothing was harvested (zero noise on hardened DCs).
    """
    if not (samr_done or ldap_done or gpp_done or unified_count or desc_creds_count):
        return

    from rich.console import Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    from adscan_core.output._state import get_console
    from adscan_core.theme import (
        ADSCAN_PRIMARY,
        COLOR_SAGE,
        COLOR_AMBER,
        COLOR_MUTED,
        ICON_SUCCESS,
    )

    tbl = Table.grid(padding=(0, 2))
    tbl.add_column(width=2)  # icon
    tbl.add_column(min_width=22)  # label
    tbl.add_column()  # detail

    def _row(label: str, detail: str, *, dim: bool = False) -> None:
        style = COLOR_MUTED if dim else COLOR_SAGE
        tbl.add_row(
            Text(ICON_SUCCESS, style=f"bold {style}"),
            Text(label, style="bold white" if not dim else COLOR_MUTED),
            Text(detail, style=style),
        )

    if unified_count:
        # Pentester-grade attribution: show the per-technique breakdown so
        # it's obvious *which* technique populated the inventory.  The
        # breakdown is the raw (pre-dedup) discovery count per technique —
        # values may sum to more than ``unified_count`` because the same
        # account can be discovered by multiple techniques (e.g. SAMR + LDAP).
        # That overlap is operationally meaningful: it confirms data.
        from adscan_core.theme import COLOR_MUTED as _MUTED
        from adscan_core.theme import COLOR_SAGE as _SAGE

        breakdown = sources_breakdown or {}
        if not breakdown:
            # Best-effort fallback for callers that didn't populate the new
            # field — preserve the legacy single-line summary so older
            # workspaces still render coherently.
            sources_note = ""
            if samr_done and ldap_done:
                extra = unified_count - max(samr_count, ldap_count)
                delta = f" ({samr_count} SAMR · {ldap_count} LDAP"
                delta += f" · +{extra} unique to one source)" if extra > 0 else ")"
                sources_note = delta
            _row(
                "User inventory",
                f"{unified_count} unified accounts → users.json{sources_note}",
            )
        else:
            # Premium attribution: header row with the totals, indented
            # sub-line listing every technique that contributed.
            tbl.add_row(
                Text(ICON_SUCCESS, style=f"bold {_SAGE}"),
                Text("User inventory", style="bold white"),
                Text(
                    f"{unified_count} unified accounts → users.json",
                    style=_SAGE,
                ),
            )
            # Build the source attribution line — only mention techniques
            # that actually contributed (count > 0) so we don't dilute the
            # signal with zero-result rows.
            parts: list[str] = []
            ldap_n = int(breakdown.get("ldap", 0) or 0)
            samr_n = int(breakdown.get("samr", 0) or 0)
            rid_n = int(breakdown.get("rid_cycling", 0) or 0)
            cn_n = int(breakdown.get("cn_inference", 0) or 0)
            if ldap_n:
                parts.append(f"{ldap_n} LDAP")
            if samr_n:
                parts.append(f"{samr_n} SAMR")
            if rid_n:
                parts.append(f"{rid_n} LSARPC RID Cycling")
            if cn_n:
                parts.append(f"{cn_n} CN inference")
            if parts:
                tbl.add_row(
                    Text(""),  # no icon for continuation row
                    Text("", style=_MUTED),
                    Text(
                        "↳  " + "  ·  ".join(parts),
                        style=_MUTED,
                    ),
                )

    if samr_done and not unified_count:
        _row("SAMR users", f"{samr_count} enumerated via IPC$")

    if ldap_done and not unified_count:
        _row("LDAP users", f"{ldap_count} active accounts via anon bind")

    if gpp_done:
        if gpp_count > 0:
            _row(
                "GPP cpassword",
                f"{gpp_count} credential{'s' if gpp_count != 1 else ''} decrypted",
            )
        else:
            _row("GPP cpassword", "SYSVOL readable — no cpassword found", dim=True)

    # Description credentials are a high-signal find — surface them in amber
    # (the same accent the attack-surface panel uses for IPC$-only) so the
    # operator can't miss them. The first finding's preview goes inline.
    if desc_creds_count:
        plural = "s" if desc_creds_count != 1 else ""
        detail = f"{desc_creds_count} credential pattern{plural} found"
        if desc_creds_preview:
            detail += f"  ·  {desc_creds_preview}"
        tbl.add_row(
            Text("⚠", style=f"bold {COLOR_AMBER}"),
            Text("Description leaks", style=f"bold {COLOR_AMBER}"),
            Text(detail, style=COLOR_AMBER),
        )

    title = Text.from_markup(
        f"[bold {ADSCAN_PRIMARY}]🎯 Already Harvested[/]  "
        f"[{COLOR_MUTED}]·[/]  [bold]{domain}[/]"
    )
    get_console().print(
        Panel(
            Group(tbl),
            title=title,
            title_align="left",
            border_style=COLOR_SAGE,
            padding=(1, 2),
        )
    )


def _run_unauth_followups_or_kerbrute(
    self: Any,
    *,
    domain: str,
    pdc: str,
    probe_results: Any = None,
    enrichment_results: Any = None,
) -> None:
    """Show attack-surface briefing and offer a granular checkbox of followups.

    Sub-capabilities of an SMB null session are independent — share listing,
    SAMR/RPC user enumeration, and GPP harvesting can each succeed or fail on
    their own. The menu reflects what actually happened in Phases 1+2 and 2.5:

    - Actionable items (share walking, guest shares) are pre-checked.
    - Items completed in Phase 2.5 (SAMR users, GPP) are shown as already done
      with their result count — they appear in the panel but not the checkbox.
    - Kerbrute runs only when every probe and every enrichment task was denied,
      i.e. the DC offers zero anonymous foothold.
    """
    # If credentials were found during enrichment (e.g. GPP) and triggered an
    # authenticated scan, the domain is now auth/pwned by the time we reach
    # here.  Unauthenticated follow-ups (share walks, kerbrute) are irrelevant
    # at that point — skip them all.
    _current_auth = (
        str(self.domains_data.get(domain, {}).get("auth") or "").strip().lower()
    )
    if _current_auth in {"auth", "pwned"}:
        return

    from adscan_core.rich_output import questionary_checkbox_values

    domain_data = self.domains_data.get(domain, {}) or {}
    smb_guest_open = bool(domain_data.get("smb_guest_shares"))
    ldap_anon_open = bool(domain_data.get("ldap_anonymous"))

    samr_status = domain_data.get("smb_null_samr_status", "skipped")
    gpp_status = domain_data.get("smb_null_gpp_status", "skipped")
    samr_count = domain_data.get("smb_null_samr_users_count", 0)
    gpp_count = domain_data.get("smb_null_gpp_leaks_count", 0)
    ldap_users_status = domain_data.get("ldap_anon_users_status", "skipped")
    ldap_users_count = domain_data.get("ldap_anon_users_count", 0)
    unauth_users_count = domain_data.get("unauth_users_count", 0)
    desc_creds_count = domain_data.get("unauth_description_creds_count", 0)
    desc_creds_preview = domain_data.get("unauth_description_creds_preview", "")

    # Did any null session expose a *walkable* share (not just IPC$)?
    null_has_shares = probe_results is not None and any(
        r.status == "open" and r.shares for r in probe_results.smb_null
    )

    # Actionable foothold = something we can pivot on. A null-bind that only
    # exposed IPC$, or an anon LDAP bind that only returned RootDSE, are NOT
    # actionable on their own — even though the probe technically succeeded.
    has_actionable_foothold = (
        null_has_shares or smb_guest_open or unauth_users_count > 0 or gpp_count > 0
    )

    if not has_actionable_foothold:
        # Hardened DC: probes may have accepted the null bind / anon LDAP bind,
        # but every enumeration vector beyond that was denied (no walkable
        # shares, no SAMR users, no LDAP search, no GPP). Operator's next move
        # is Kerberos username enumeration — wire it directly.
        print_info(
            f"Anonymous surface restricted on {domain} — no walkable shares, "
            "no userlist, no GPP. Falling back to Kerberos username enumeration."
        )
        print_operation_header(
            "Kerberos User Enumeration",
            details={"Domain": domain, "PDC": pdc, "Tool": "kerbrute"},
            icon="🔑",
        )
        try:
            self.ask_for_kerberos_user_enum(domain)
        except Exception as e:  # noqa: BLE001
            telemetry.capture_exception(e)
            print_error(f"Kerberos user enumeration failed: {e}")
        return

    # Foothold exists, but if the user list came ONLY from a RESTRICTED anonymous
    # bind (RestrictAnonymous=1: bind allowed, full user search denied), it is
    # known-incomplete — the few CN-inferred users are not the whole picture.
    # Expand it via Kerberos username enumeration BEFORE the follow-ups, so the
    # AS-REP/spray steps operate on the full user set. This reuses the SAME
    # escalation the zero-foothold path uses (ask_for_kerberos_user_enum), so the
    # interactive/non-interactive behavior is identical to that path — no new
    # auto-spray decision is introduced.
    if ldap_anon_open and ldap_users_status in ("denied", "skipped") and unauth_users_count > 0:
        print_info(
            f"User list for {mark_sensitive(domain, 'domain')} came from a restricted "
            f"anonymous bind (RestrictAnonymous) — only {unauth_users_count} disclosed; "
            "more users likely exist. Expanding via Kerberos username enumeration."
        )
        print_operation_header(
            "Kerberos User Enumeration",
            details={
                "Domain": domain,
                "PDC": pdc,
                "Tool": "kerbrute",
                "Reason": "anon bind restricted",
            },
            icon="🔑",
        )
        try:
            self.ask_for_kerberos_user_enum(domain)
        except Exception as e:  # noqa: BLE001
            telemetry.capture_exception(e)
            print_error(f"Kerberos user enumeration failed: {e}")
        # Refresh the count so the follow-up menu reflects the expanded user set.
        unauth_users_count = domain_data.get("unauth_users_count", unauth_users_count)

    # ── Surface briefing panel ────────────────────────────────────────────
    _render_attack_surface_panel(probe_results, domain=domain, domain_data=domain_data)

    # ── Already Harvested · informational panel ──────────────────────────
    # Phase 2.5 ran SAMR, descriptions, GPP and LDAP inventory eagerly. Showing
    # those in the followup checkbox is UX rot — checkboxes mean "select to run"
    # and these are already done. Render them as a static "harvested" panel
    # so the operator sees the loot before choosing the next action.
    _render_harvested_panel(
        domain=domain,
        samr_done=samr_status == "done",
        samr_count=samr_count,
        ldap_done=ldap_anon_open and ldap_users_status == "done",
        ldap_count=ldap_users_count,
        unified_count=unauth_users_count,
        gpp_done=gpp_status == "done",
        gpp_count=gpp_count,
        desc_creds_count=desc_creds_count,
        desc_creds_preview=desc_creds_preview,
        sources_breakdown=domain_data.get("unauth_users_sources_breakdown"),
    )

    # ── Build actionable followup menu ───────────────────────────────────
    # Only items with a real callable. Walk-shares depends on actual shares
    # being listable (not just IPC$). AS-REP works against any user list — the
    # KDC tells us which accounts have DONT_REQUIRE_PREAUTH set.
    followups: list[tuple[str, Any]] = []

    # Quick wins first: credential attacks on known user list before slower
    # share enumeration.  AS-REP roasting is stealthy and fast; spraying is
    # noisy but high-value; share enumeration comes last.
    if unauth_users_count > 0:
        from adscan_internal.cli.kerberos import run_asreproast
        from adscan_internal.cli.spraying import ask_for_spraying

        followups.append(
            (
                f"Kerberos  ─  AS-REP Roasting  ({unauth_users_count} unified users)",
                lambda: run_asreproast(self, target_domain=domain, auto_crack=True),
            )
        )
        followups.append(
            (
                f"Credentials  ─  Password Spraying  ({unauth_users_count} users · noisy)",
                lambda: ask_for_spraying(self, domain),
            )
        )

    if null_has_shares:
        from adscan_internal.cli.smb import run_null_shares

        preview = _null_share_preview(probe_results)
        followups.append(
            (
                f"SMB Null  ─  Enumerate access + search for credentials  ({preview})",
                lambda: run_null_shares(self, domain=domain),
            )
        )

    if smb_guest_open:
        from adscan_internal.cli.smb import run_guest_shares

        followups.append(
            (
                "SMB Guest  ─  Enumerate access (READ/WRITE) + search for credentials",
                lambda: run_guest_shares(self, domain=domain),
            )
        )

    if not followups:
        # has_actionable_foothold was true but every actionable item is a
        # noop (e.g. GPP-only foothold with no users, no shares to walk).
        # Nothing more to offer — exit quietly.
        print_info_verbose("No further followups available — harvested loot only.")
        return

    labels = [label for label, _ in followups]
    default_labels = labels  # all actionable items pre-checked

    selected = questionary_checkbox_values(
        title="Select followups to run",
        options=labels,
        default_values=default_labels,
        shell=self,
    )

    if not selected:
        print_info("No followups selected — skipping.")
        return

    action_map = {label: fn for label, fn in followups}
    for label in selected:
        fn = action_map.get(label)
        if fn is None:
            continue
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            telemetry.capture_exception(e)
            print_error(f"Followup failed: {e}")


def _run_unauth_native_probes(self: Any, *, domain: str, pdc: str) -> Any:
    """Run SMB null/guest + LDAP anonymous probes concurrently and apply results.

    Returns the ``UnauthProbeResults`` object so callers can inspect raw probe
    data (share names, LDAP base DN, duration) for rich UX rendering. Returns
    ``None`` when the sweep could not run (no PDC, or a fatal exception).

    Replaces the legacy sequential ``ask_for_smb_scan`` + ``ask_for_ldap_scan``
    pair with a single concurrent native sweep. The result-handling logic
    (report fields, attack-graph edges, follow-up share/LDAP enumeration)
    delegates to the existing handlers, which keeps behavioural parity with
    every other scan flow that calls those handlers (e.g. ``ci.py``).
    """
    from adscan_internal.services.unauth_probe_service import (
        UnauthProbeConfig,
        render_smb_share_table,
        render_unauth_summary,
        run_unauth_probes,
    )

    # Without a PDC we cannot probe — skip entirely.
    if not pdc or pdc == "N/A":
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            f"No PDC recorded for {marked_domain} — skipping unauthenticated sweep."
        )
        return None

    domain_data = self.domains_data.get(domain, {}) or {}
    raw_guest = domain_data.get("guest_smb_targets")
    if isinstance(raw_guest, list):
        guest_targets = [str(t).strip() for t in raw_guest if str(t).strip()]
    elif isinstance(raw_guest, str):
        guest_targets = [t.strip() for t in re.split(r"[,\s]+", raw_guest) if t.strip()]
    else:
        guest_targets = []
    if not guest_targets:
        guest_targets = [pdc]

    config = UnauthProbeConfig(
        domain=domain,
        dc_ip=pdc,
        smb_null_targets=[pdc],
        smb_guest_targets=guest_targets,
        timeout=20,
    )

    try:
        results = run_unauth_probes(config)
    except Exception as e:  # noqa: BLE001
        telemetry.capture_exception(e)
        print_error(f"Concurrent unauth probes failed: {e}")
        return None

    # Render the share tables and the summary panel.
    render_smb_share_table(results.smb_null, domain=domain, auth_label="null")
    render_smb_share_table(results.smb_guest, domain=domain, auth_label="guest")
    render_unauth_summary(results, domain=domain)

    # Apply results into ADscan state via the existing handlers. This keeps
    # the CLI/report/graph integration coherent with every other scan flow.
    _apply_unauth_probe_results(self, domain=domain, results=results)
    return results


def _set_probe_flag(
    shell: Any, domain_data: dict, domain: str, key: str, value: Any
) -> None:
    """Write a probe flag to both the runtime state and the report store.

    Probe results like ``smb_null_session`` or ``ldap_anonymous`` are dual-use:
    - ``domain_data`` (``domains_data[domain]``) drives control flow — enrichment,
      followup decisions, auth-state elevation.
    - ``update_report_field`` feeds the PDF/web report engine.

    Writing to only one store causes silent divergence (the bug that caused kerbrute
    to fire even when null session was open). This helper ensures both stay in sync
    atomically so neither store can drift from the other.
    """
    domain_data[key] = value
    try:
        shell.update_report_field(domain, key, value)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)


def _apply_unauth_probe_results(self: Any, *, domain: str, results: Any) -> None:
    """Translate native probe outcomes into ADscan state updates.

    State updates are written directly from the structured native results —
    we do **not** re-enter the legacy ``ask_for_smb_scan`` / ``ask_for_ldap_scan``
    handlers, since those would re-issue NetExec subprocess probes and defeat
    the migration. Heavy follow-up flows that are already native (LDAP user
    inventory, attack-graph edges, technical findings) are dispatched here.
    """
    domain_data = self.domains_data.setdefault(domain, {})

    # ── SMB null session ──────────────────────────────────────────────────
    if results.smb_null:
        null_open = [r for r in results.smb_null if r.status == "open"]
        if null_open:
            _set_probe_flag(self, domain_data, domain, "smb_null_session", True)
            if domain_data.get("auth") not in ("auth", "pwned"):
                domain_data.setdefault("auth", "unauth")
        else:
            _set_probe_flag(self, domain_data, domain, "smb_null_session", False)

    # ── SMB guest ─────────────────────────────────────────────────────────
    if results.smb_guest:
        guest_open = [r for r in results.smb_guest if r.status == "open"]
        if guest_open:
            host_labels = [
                f"{mark_sensitive(r.target, 'ip')} "
                f"({len(r.shares)} share{'s' if len(r.shares) != 1 else ''})"
                for r in guest_open
            ]
            _set_probe_flag(self, domain_data, domain, "smb_guest_shares", host_labels)

    # ── LDAP anonymous ────────────────────────────────────────────────────
    ldap = results.ldap_anonymous
    if ldap is not None:
        ldap_open = ldap.status == "open"
        _set_probe_flag(self, domain_data, domain, "ldap_anonymous", ldap_open)

        if ldap_open:
            try:
                from adscan_internal.services.attack_graph_service import (
                    upsert_ldap_anonymous_bind_entry_edge,
                )

                upsert_ldap_anonymous_bind_entry_edge(
                    self,
                    domain,
                    status="success",
                    notes={
                        "source": "unauth_probe_service",
                        "protocol": "ldap",
                        "authentication": "anonymous_bind",
                        "pdc": domain_data.get("pdc"),
                        "transport": "LDAPS" if ldap.used_ldaps else "LDAP",
                        "base_dn": ldap.base_dn,
                    },
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)

            # LDAP anonymous enrichment (active users, descriptions, GPP) is
            # delegated to the Phase 2.5 native path (_run_unauth_enrichment →
            # unauth_enrichment_service). The legacy NetExec-backed followup
            # has been retired here to keep the unauth flow single-track.
            print_info_debug(
                "[unauth] LDAP anonymous enrichment delegated to Phase 2.5 "
                "(unauth_enrichment_service)"
            )


def _run_unauth_enrichment(self: Any, *, domain: str, pdc: str) -> Any:
    """Phase 2.5 — native enrichment over the unauth surface, if any.

    Reads the probe-derived flags from ``domains_data[domain]`` (set by
    :func:`_apply_unauth_probe_results`) and, when at least one of SMB null
    session or LDAP anonymous bind is open, runs the enrichment service and
    applies its outputs to the ADscan state via
    :func:`_apply_unauth_enrichment_results`.

    Returns the ``UnauthEnrichmentResults`` so callers can inspect per-task
    statuses (SAMR, descriptions, GPP, LDAP users) for rich UX rendering.
    Returns ``None`` when enrichment was skipped or failed before producing
    any structured result.
    """
    domain_data = self.domains_data.get(domain, {}) or {}
    smb_null_open = bool(domain_data.get("smb_null_session"))
    ldap_anon_open = bool(domain_data.get("ldap_anonymous"))
    if not (smb_null_open or ldap_anon_open):
        return None
    if not pdc or pdc == "N/A":
        return None

    try:
        from adscan_internal.services.unauth_enrichment_service import (
            UnauthEnrichmentConfig,
            run_unauth_enrichment,
        )

        workspace_dir = self.current_workspace_dir or os.getcwd()

        # Build the guest SMBConfig for LSARPC RID Cycling.  RID cycling is
        # the only enrichment task that uses a guest session (everything
        # else runs over a null session), so we only pay this cost when the
        # probe phase confirmed a guest session is open.  Failure to build
        # the config is non-fatal — the enrichment service treats a None
        # smb_guest_config as "guest session unavailable".
        smb_guest_config = None
        if bool(domain_data.get("smb_guest_shares")):
            try:
                from adscan_internal.cli.smb import _smb_config_for_guest
                smb_guest_config = _smb_config_for_guest(self, domain)
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_info_debug(
                    f"[unauth-enrich] could not build guest SMBConfig: {exc}"
                )

        enrichment_config = UnauthEnrichmentConfig(
            domain=domain,
            dc_ip=pdc,
            smb_null_open=smb_null_open,
            ldap_anon_open=ldap_anon_open,
            smb_readable_targets=[pdc] if smb_null_open else [],
            workspace_dir=workspace_dir,
            timeout=60,
            smb_guest_config=smb_guest_config,
        )
        enrichment_results = run_unauth_enrichment(enrichment_config)
        _apply_unauth_enrichment_results(
            self, domain=domain, results=enrichment_results
        )
        return enrichment_results
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error(f"Unauthenticated enrichment failed: {exc}")
        return None


def _review_description_credential_candidates(
    self: Any,
    domain: str,
    desc_creds: list,
) -> list:
    """Validate CredSweeper description findings interactively before saving.

    Shows one Rich summary panel (all candidates at a glance) then prompts
    once per item. High-confidence findings (ML ≥ 0.70) default to "Save and
    verify now"; low-confidence findings default to "Ignore (false positive)".

    Returns the accepted items only. Always returns a list (empty if all
    ignored, none found, or the operator stops early).
    """
    if not desc_creds:
        return []

    from rich.box import ROUNDED, SIMPLE_HEAVY
    from rich.console import Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    from adscan_core.rich_output import _get_console
    from adscan_core.theme import ADSCAN_PRIMARY

    HIGH_CONF = 0.70

    def _rule_label(rule: str, prob: float | None) -> Text:
        # DOC/narrative rules have near-zero ML probability by design — the ML
        # model was trained on code/config, not natural language. Show the rule
        # name instead of a misleading confidence bar for these deterministic hits.
        if prob is not None and prob >= HIGH_CONF:
            filled = round(prob * 4)
            bar = "█" * filled + "░" * (4 - filled)
            return Text(f"{bar} {prob:.2f}", style="bold green")
        rule_short = rule.replace("DOC ", "").replace("_", " ").title()
        return Text(rule_short, style="bold yellow" if prob is None or prob > 0 else "dim")

    tbl = Table(box=SIMPLE_HEAVY, header_style=f"bold {ADSCAN_PRIMARY}", show_lines=True)
    tbl.add_column("User", style="bold cyan", no_wrap=True)
    tbl.add_column("Field", style="dim")
    tbl.add_column("Extracted value", style="bold yellow")
    tbl.add_column("Rule", justify="right")
    tbl.add_column("Context", style="dim", max_width=50)

    for c in desc_creds:
        ctx = f'"{c.context_line[:60]}"' if c.context_line else "—"
        tbl.add_row(
            mark_sensitive(c.samaccountname, "user"),
            c.field.replace("_", " "),
            mark_sensitive(c.raw_value, "password"),
            _rule_label(c.rule_name, c.ml_probability),
            ctx,
        )

    count_line = (
        f"[dim]{len(desc_creds)} candidate{'s' if len(desc_creds) != 1 else ''}[/dim]"
    )

    panel = Panel(
        Group(
            Text.from_markup(
                "[dim]Detected by CredSweeper — review before saving to credential store[/dim]\n"
            ),
            tbl,
            Text(""),
            Text.from_markup(count_line),
        ),
        title=(
            f"[bold {ADSCAN_PRIMARY}]🔑 Credentials in User Descriptions"
            f"  ·  {mark_sensitive(domain, 'domain')}[/]"
        ),
        title_align="left",
        border_style=ADSCAN_PRIMARY,
        box=ROUNDED,
        padding=(1, 2),
    )
    _get_console().print(panel)

    accepted: list = []
    for cred in desc_creds:
        prob = cred.ml_probability
        conf_hint = f"{prob:.2f}" if prob is not None else "no ML score"
        field_label = cred.field.replace("_", " ")
        prompt = (
            f"{mark_sensitive(cred.samaccountname, 'user')} — "
            f'"{mark_sensitive(cred.raw_value, "password")}" '
            f"({field_label}, rule: {cred.rule_name}, {conf_hint})"
            f"\n  How do you want to handle this?"
        )
        options = ["Save and verify now", "Ignore (false positive)", "Stop reviewing"]
        default_idx = 0

        selection = self._questionary_select(prompt, options, default_idx=default_idx)
        if selection is None:
            break
        selected = options[selection]
        if selected == "Stop reviewing":
            break
        if selected == "Save and verify now":
            accepted.append(cred)

    return accepted


def _render_cn_inference_panel(self: Any, domain: str, result: Any) -> None:
    """Render a Rich diagnostic panel summarising anonymous LDAP CN username inference.

    Displays what was found (CN-only records), what pattern was detected from
    the known-user sample, what candidate was tried for each CN, and which
    passed Kerberos validation.  Always rendered when ``cn_only_count > 0`` so
    the operator can see what was attempted even when kerbrute found nothing.
    """
    from rich.box import ROUNDED, SIMPLE_HEAVY
    from rich.console import Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    from adscan_core.rich_output import _get_console
    from adscan_core.theme import ADSCAN_PRIMARY
    from adscan_core.username_patterns import USERNAME_PATTERN_LABELS
    from adscan_internal.rich_output import mark_sensitive

    validated_count = len(result.validated)
    cn_count = result.cn_only_count
    pattern_key = result.inferred_pattern
    pattern_label = USERNAME_PATTERN_LABELS.get(pattern_key, pattern_key) if pattern_key else None

    marked_domain = mark_sensitive(domain, "domain")

    if pattern_label:
        policy_line = Text.from_markup(
            f"  Policy inferred from [bold]{result.known_users_analyzed}[/bold] known users: "
            f"[bold {ADSCAN_PRIMARY}]{pattern_label}[/]"
            f"  [dim]({result.pattern_score}/{result.known_users_analyzed} confirmed)[/dim]"
        )
    else:
        policy_line = Text.from_markup(
            "  [yellow]No dominant policy detected — tried all formats[/yellow]"
        )

    intro = Text.from_markup(
        f"  LDAP anonymous withheld [bold]sAMAccountName[/bold] for "
        f"[bold {ADSCAN_PRIMARY}]{cn_count}[/] user object(s) — CN only disclosed"
    )

    tbl = Table(
        box=SIMPLE_HEAVY,
        header_style=f"bold {ADSCAN_PRIMARY}",
        show_lines=False,
        padding=(0, 1),
    )
    tbl.add_column("CN (disclosed by DC)", style="bold", no_wrap=True)
    tbl.add_column("", style="dim", no_wrap=True)
    tbl.add_column("Candidate tried", no_wrap=True)
    tbl.add_column("Kerberos", justify="right", no_wrap=True)

    for cn_name, candidate, is_valid in result.rows:
        kerberos_cell = (
            Text("valid", style="bold green")
            if is_valid
            else Text("not found", style="dim")
        )
        tbl.add_row(
            mark_sensitive(cn_name, "user"),
            "->",
            mark_sensitive(candidate, "user"),
            kerberos_cell,
        )

    if validated_count > 0:
        footer_text = Text.from_markup(
            f"  [bold green]{validated_count}/{cn_count}[/bold green] confirmed via Kerberos"
            "  [dim]·[/dim]  added to users.txt"
        )
    elif result.rows:
        footer_text = Text.from_markup(
            f"  [yellow]0/{cn_count} confirmed via Kerberos — no usernames added[/yellow]"
        )
    else:
        footer_text = Text.from_markup(
            "  [dim]No candidates generated — kerbrute validation skipped[/dim]"
        )

    content_group: list = [Text(""), intro, policy_line, Text("")]
    if result.rows:
        content_group.extend([tbl, Text("")])
    content_group.extend([footer_text, Text("")])

    panel = Panel(
        Group(*content_group),
        title=(
            f"[bold {ADSCAN_PRIMARY}]Username Policy Inference"
            f"  ·  {marked_domain}[/]"
        ),
        title_align="left",
        border_style=ADSCAN_PRIMARY,
        box=ROUNDED,
        padding=(0, 2),
    )
    _get_console().print(panel)


def _apply_unauth_enrichment_results(self: Any, *, domain: str, results: Any) -> None:
    """Persist enrichment artefacts and surface findings into ADscan state."""
    import json as _json

    workspace_dir = self.current_workspace_dir or os.getcwd()
    domain_root = os.path.join(workspace_dir, "domains", domain)
    smb_dir = os.path.join(domain_root, "smb")
    krb_dir = os.path.join(domain_root, "kerberos")
    for d in (domain_root, smb_dir, krb_dir):
        try:
            os.makedirs(d, exist_ok=True)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)

    domain_data = self.domains_data.setdefault(domain, {})

    # ── Canonical unified user inventory (LDAP + SAMR merged) ───────────
    # Single source of truth — see :mod:`adscan_inventory.unauth_inventory`.
    # Replaces the legacy per-probe artefacts (ldap_anonymous_active_users.json,
    # samr_users.json, samr_descriptions.json) with one ``users.json`` plus a
    # tool-consumption ``users.txt``. Provenance is preserved via the per-record
    # ``sources`` field.
    from adscan_internal.services.unauth_inventory import (
        merge_unauth_users,
        persist_unauth_users,
        scan_description_credentials,
    )

    unified_users = merge_unauth_users(results.ldap_active_users, results.samr_users)

    # ── LSARPC RID Cycling — merge results from Phase 2.5 ────────────────
    # RID cycling now runs INSIDE the enrichment service as a live task in
    # the intel dashboard (see ``_drive_rid_cycling`` in
    # ``unauth_enrichment_service``).  Here we just merge its findings so
    # the unified inventory + sources audit trail captures every probe.
    # The technique decision (skip when SAMR succeeded vs run when guest
    # session is open and SAMR failed) lives inside the driver — keeping it
    # there means the live dashboard accurately reflects what's happening.
    rid_new_count = 0
    if results.rid_cycling_users:
        from adscan_internal.services.unauth_inventory import (
            merge_rid_cycling_users,
        )
        _prev_count = len(unified_users)
        unified_users = merge_rid_cycling_users(
            unified_users, results.rid_cycling_users
        )
        rid_new_count = len(unified_users) - _prev_count

    # ── CN-only LDAP → kerbrute validation ───────────────────────────────
    # Runs before persist so all users land in users.json in one write.
    # Inferred usernames are added to unified_users as minimal UnauthUser
    # records with sources=["ldap_cn_inference"] so provenance is tracked.
    from adscan_internal.services.unauth_inventory import UnauthUser

    cn_only = list(getattr(results, "ldap_cn_only_records", None) or [])
    cn_inferred_count = 0
    if cn_only:
        try:
            from adscan_internal.cli.ldap import (
                _validate_ldap_anonymous_username_candidates,
            )

            cn_result = _validate_ldap_anonymous_username_candidates(
                self, domain, cn_only,
                known_users=list(results.ldap_active_users or []),
            )
            if cn_result.validated:
                existing_sams = {u.samaccountname.lower() for u in unified_users}
                for sam in cn_result.validated:
                    if sam.lower() not in existing_sams:
                        unified_users.append(
                            UnauthUser(
                                samaccountname=sam,
                                sources=["ldap_cn_inference"],
                            )
                        )
                        existing_sams.add(sam.lower())
                cn_inferred_count = len(cn_result.validated)
                domain_data["ldap_cn_inferred_users_count"] = cn_inferred_count
            _render_cn_inference_panel(self, domain, cn_result)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(f"[unauth] CN inference failed: {exc}")

    # ── Persist canonical unified inventory (LDAP + SAMR + CN inference) ─
    users_json_path: str | None = None
    users_txt_path: str | None = None
    try:
        users_json_path, users_txt_path = persist_unauth_users(
            unified_users, domain_root=domain_root
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error(f"Failed to persist unified user inventory: {exc}")

    # ── CredSweeper scan over description / fullName / comment ──────────
    # In-memory pass — descriptions are already from the merged unified_users
    # (LDAP anon + SAMR, best-of-both via _prefer_longer). No extra IO needed.
    # Findings are persisted as an audit trail then reviewed interactively
    # before injection into the credential store.
    desc_creds = scan_description_credentials(unified_users)
    if desc_creds:
        # Persist ALL raw findings as audit trail — independent of what the
        # operator accepts, so nothing is silently lost.
        try:
            desc_path = os.path.join(domain_root, "description_credentials.json")
            with open(desc_path, "w", encoding="utf-8") as fh:
                _json.dump(
                    [
                        {
                            "samaccountname": d.samaccountname,
                            "field": d.field,
                            "raw_value": d.raw_value,
                            "context_line": d.context_line,
                            "rule_name": d.rule_name,
                            "ml_probability": d.ml_probability,
                        }
                        for d in desc_creds
                    ],
                    fh,
                    indent=2,
                )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error(f"Failed to persist description credentials: {exc}")

    # ── Interactive review — operator validates before credential store ──
    # desc_creds_verified contains only the operator-accepted items.
    # desc_creds (full list) is still used for audit-trail counts below.
    desc_creds_verified = _review_description_credential_candidates(
        self, domain, desc_creds
    )

    # ── GPP cpassword leaks ──────────────────────────────────────────────
    try:
        gpp_path = os.path.join(smb_dir, "gpp_leaks.json")
        with open(gpp_path, "w", encoding="utf-8") as fh:
            _json.dump(
                [
                    {
                        "unc_path": g.unc_path,
                        "username": g.username,
                        "cpassword_ciphertext": g.cpassword_ciphertext,
                        "cleartext": g.cleartext,
                        "xml_type": g.xml_type,
                        "source_share": getattr(g, "source_share", ""),
                        "source_target": getattr(g, "source_target", ""),
                    }
                    for g in results.gpp_leaks
                ],
                fh,
                indent=2,
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error(f"Failed to persist GPP leaks: {exc}")

    # ── GPP autologon credentials (Registry.xml DefaultPassword) ────────
    autologin_leaks = list(getattr(results, "gpp_autologin_leaks", []) or [])
    try:
        autologin_path = os.path.join(smb_dir, "gpp_autologon.json")
        with open(autologin_path, "w", encoding="utf-8") as fh:
            _json.dump(
                [
                    {
                        "unc_path": a.unc_path,
                        "username": a.username,
                        "password": a.password,
                        "domain": a.domain,
                        "source_share": a.source_share,
                        "source_target": a.source_target,
                    }
                    for a in autologin_leaks
                ],
                fh,
                indent=2,
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error(f"Failed to persist GPP autologon credentials: {exc}")

    # ── AS-REP roastable target list ─────────────────────────────────────
    asrep_targets = results.asreproast_eligible_users
    if asrep_targets:
        try:
            asrep_path = os.path.join(krb_dir, "asreproast_targets.txt")
            with open(asrep_path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(asrep_targets) + "\n")
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error(f"Failed to persist AS-REP targets: {exc}")

    # ── Register decrypted GPP credentials in domain credential store ────
    # Route every decrypted cpassword through the canonical ``add_credential``
    # pipeline so it gets verified, hash-cracked, ticket-refreshed, and
    # recorded in the attack graph with proper provenance — exactly like
    # ``process_cpassword_text`` does for share-spidered cpasswords. Manual
    # ``domains_data["credentials"][user] = pwd`` insertion silently bypassed
    # all of that and left the credential invisible to the auth flow.
    from adscan_internal.cli.creds import add_credential as _add_credential
    from adscan_internal.services.high_value import normalize_samaccountname
    from adscan_internal.services.share_credential_provenance_service import (
        ShareCredentialProvenanceService,
    )

    def _split_principal(raw: str, fallback_domain: str) -> tuple[str, str]:
        """Split a GPP-emitted principal into ``(samaccount, domain)``.

        GPP XMLs commonly store the user as ``DOMAIN\\sam`` (HTB Active
        style: ``active.htb\\SVC_TGS``) or ``sam@domain`` (UPN form).
        Passing the raw qualified value to ``add_credential`` breaks the
        credential store — it must receive a clean samAccountName plus
        the domain in its dedicated argument.
        """
        text = (raw or "").strip()
        embedded_domain = ""
        if "\\" in text:
            embedded_domain, text = text.split("\\", 1)
        elif "@" in text:
            text, embedded_domain = text.split("@", 1)
        sam = normalize_samaccountname(text)
        dom = (embedded_domain or fallback_domain or "").strip().lower()
        return sam, (dom or fallback_domain)

    domain_data.setdefault("credentials", {})
    decrypted_leaks = [g for g in results.gpp_leaks if g.cleartext and g.username]
    provenance = ShareCredentialProvenanceService()
    for leak in decrypted_leaks:
        leak_user, leak_domain = _split_principal(leak.username, domain)
        if not leak_user:
            print_info_debug(
                f"[unauth-enrich] skipping GPP leak with empty username: {leak.unc_path}"
            )
            continue
        try:
            source_steps = provenance.build_credential_source_steps(
                relation="GPPPassword",
                edge_type="gpp_password",
                source="gpp_cpassword",
                secret=leak.cleartext,
                artifact=leak.unc_path,
                origin="unauth_enrichment",
            )
            _add_credential(
                self,
                leak_domain,
                leak_user,
                leak.cleartext,
                source_steps=source_steps,
                credential_origin="gpp_cpassword",
                prompt_for_user_privs_after=False,
                force_authenticated_enumeration=False,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[unauth-enrich] add_credential skipped for GPP leak: {exc}"
            )

        try:
            from adscan_core.reporting.technical_report import (
                record_technical_finding,
            )

            record_technical_finding(
                self,
                domain,
                key="gpp_cpassword_leak",
                value=True,
                details={
                    "source": "unauth_enrichment_service",
                    "username": leak.username,
                    "unc_path": leak.unc_path,
                    "xml_type": leak.xml_type,
                },
                evidence=[
                    {
                        "type": "file",
                        "summary": "GPP cpassword (Microsoft static AES key)",
                        "artifact_path": leak.unc_path,
                    }
                ],
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(f"[unauth-enrich] record_technical_finding skipped: {exc}")

    # ── Register GPP autologon credentials (Registry.xml plaintext) ──────
    # Same canonical path as cpassword: route through ``add_credential`` so
    # the cred gets verified, hash-cracked, ticket-refreshed, and recorded
    # in the attack graph. Autologon credentials are particularly valuable
    # because the user is, by definition, the local interactive account on
    # the box where the policy applied (often a workstation admin).
    for autologin in autologin_leaks:
        # Prefer the GPP-declared domain when present (some autologons set
        # ``DefaultDomainName`` to a different realm than the SYSVOL host),
        # but fall back to the enumeration domain so we never drop the cred.
        # The username itself may *also* be domain-qualified (``CORP\sam``);
        # split it so add_credential receives a clean samAccountName.
        autologin_user, autologin_domain = _split_principal(
            autologin.username, autologin.domain or domain
        )
        if not autologin_user:
            print_info_debug(
                f"[unauth-enrich] skipping GPP autologon with empty username: {autologin.unc_path}"
            )
            continue
        try:
            source_steps = provenance.build_credential_source_steps(
                relation="GPPAutologon",
                edge_type="gpp_autologon",
                source="gpp_autologon",
                secret=autologin.password,
                artifact=autologin.unc_path,
                origin="unauth_enrichment",
            )
            _add_credential(
                self,
                autologin_domain,
                autologin_user,
                autologin.password,
                source_steps=source_steps,
                credential_origin="gpp_autologon",
                prompt_for_user_privs_after=False,
                force_authenticated_enumeration=False,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[unauth-enrich] add_credential skipped for GPP autologon: {exc}"
            )

        try:
            from adscan_core.reporting.technical_report import (
                record_technical_finding,
            )

            record_technical_finding(
                self,
                domain,
                key="gpp_autologon_credential",
                value=True,
                details={
                    "source": "unauth_enrichment_service",
                    "username": autologin.username,
                    "domain": autologin.domain,
                    "unc_path": autologin.unc_path,
                },
                evidence=[
                    {
                        "type": "file",
                        "summary": "GPP autologon (Registry.xml DefaultPassword)",
                        "artifact_path": autologin.unc_path,
                    }
                ],
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(f"[unauth-enrich] record_technical_finding skipped: {exc}")

    # ── Inject operator-accepted credentials into the credential store ──
    # Only desc_creds_verified (operator-reviewed) are saved. The full
    # desc_creds list is preserved in the JSON artefact for the audit trail.
    for cred in desc_creds_verified:
        if not cred.raw_value:
            continue
        try:
            _add_credential(
                self,
                domain,
                cred.samaccountname,
                cred.raw_value,
                credential_origin="userdescription",
                prompt_for_user_privs_after=False,
                force_authenticated_enumeration=False,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[unauth-enrich] add_credential skipped for description leak: {exc}"
            )

        try:
            from adscan_core.reporting.technical_report import (
                record_technical_finding,
            )

            record_technical_finding(
                self,
                domain,
                key="user_description_credential_leak",
                value=True,
                details={
                    "source": "unauth_enrichment_service.credsweeper",
                    "username": cred.samaccountname,
                    "field": cred.field,
                    "rule": cred.rule_name,
                    "ml_probability": cred.ml_probability,
                },
                evidence=[
                    {
                        "type": "string",
                        "summary": f"Credential pattern in {cred.field} (rule: {cred.rule_name})",
                        "artifact_path": "users.json",
                    }
                ],
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(f"[unauth-enrich] description-cred record skipped: {exc}")

    # ── Update report fields ─────────────────────────────────────────────
    sensitive_descs = results.sensitive_descriptions
    report_updates = {
        "unauth_users_count": len(unified_users),
        "ldap_anonymous_active_users_count": len(results.ldap_active_users),
        "smb_samr_users_count": len(results.samr_users),
        "smb_samr_descriptions_sensitive_count": len(sensitive_descs),
        "smb_samr_descriptions_credentials_count": len(desc_creds),        # total found by CredSweeper
        "smb_samr_descriptions_credentials_saved_count": len(desc_creds_verified),  # operator-accepted
        "gpp_cpassword_leaks_count": len(decrypted_leaks),
        "gpp_autologon_credentials_count": len(autologin_leaks),
    }
    for field_name, value in report_updates.items():
        try:
            self.update_report_field(domain, field_name, value)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)

    # Store per-task capability flags in domain_data so the Phase 3 followup
    # menu can show independent status for shares vs SAMR vs GPP vs LDAP users
    # without re-running enrichment.
    domain_data["smb_null_samr_status"] = (
        results.samr_users_status
    )  # TaskStatus: "done"/"denied"/"error"/"skipped"
    domain_data["smb_null_samr_users_count"] = len(results.samr_users)
    domain_data["smb_null_gpp_status"] = results.gpp_status
    domain_data["smb_null_gpp_leaks_count"] = len(results.gpp_leaks)
    domain_data["smb_null_gpp_autologon_count"] = len(autologin_leaks)
    domain_data["ldap_anon_users_status"] = results.ldap_active_users_status
    domain_data["ldap_anon_users_count"] = len(results.ldap_active_users)

    # LSARPC RID Cycling — explicit first-class technique status so the
    # Attack Surface panel and report can attribute the user inventory
    # to the technique that actually paid off (often distinct from SAMR).
    domain_data["smb_null_rid_cycling_status"] = results.rid_cycling_status
    domain_data["smb_null_rid_cycling_reason"] = results.rid_cycling_reason
    # Total user-type SIDs the technique resolved (before de-dup against
    # SAMR/LDAP) and how many were genuinely new to the inventory.
    SID_TYPE_USER = 1
    rid_user_total = sum(
        1
        for e in results.rid_cycling_users
        if getattr(e, "sid_type", None) == SID_TYPE_USER
        and str(getattr(e, "name", "") or "").strip()
        and not str(getattr(e, "name", "") or "").strip().endswith("$")
    )
    domain_data["smb_null_rid_cycling_users_count"] = rid_user_total
    domain_data["smb_null_rid_cycling_new_count"] = rid_new_count

    # Source breakdown for the harvested panel: how many users came from
    # each discovery technique (raw, before de-dup).  The values may sum
    # to more than the unified count because a single account can be
    # discovered by multiple techniques — that's the whole point of
    # tracking provenance.
    domain_data["unauth_users_sources_breakdown"] = {
        "ldap": len(results.ldap_active_users),
        "samr": len(results.samr_users),
        "rid_cycling": rid_user_total,
        "cn_inference": cn_inferred_count,
    }

    if unified_users:
        # unified_users already includes CN-inferred users added before persist.
        domain_data["unauth_users_count"] = len(unified_users)
        if users_txt_path:
            domain_data["unauth_users_path"] = users_txt_path
        if users_json_path:
            domain_data["unauth_users_inventory_path"] = users_json_path

    domain_data["unauth_description_creds_count"] = len(desc_creds)
    if desc_creds:
        # First finding becomes a one-line summary the harvested panel can show.
        first = desc_creds[0]
        domain_data["unauth_description_creds_preview"] = (
            f"{first.samaccountname} → {first.raw_value} ({first.rule_name})"
        )


def ask_for_ldap_scan(self, domain: str) -> None:
    """Prompt user to perform unauthenticated LDAP service scan."""
    if _get_domain_auth_state(self, domain) == "pwned" and self.type == "ctf":
        return
    if self.auto:
        self.do_ldap_anonymous(domain)
    else:
        from adscan_internal.rich_output import confirm_operation

        pdc = self.domains_data.get(domain, {}).get("pdc", "N/A")

        if confirm_operation(
            operation_name="Unauthenticated LDAP Scan",
            description="Queries LDAP directory with anonymous bind to enumerate domain information",
            context={"Domain": domain, "PDC": pdc, "Protocol": "LDAP/389"},
            default=True,
            icon="📂",
        ):
            self.do_ldap_anonymous(domain)


class ScanShell(Protocol):
    """Protocol for shell attributes needed by the IP/computer consolidation helpers."""

    current_workspace_dir: str | None
    domains_dir: str
    domains: list[str]


def consolidate_service_ips(shell: ScanShell, service: str) -> None:
    """Consolidate IPs from all domains for a specific service.

    Args:
        shell: The active shell instance with workspace and domain data.
        service: Service name to consolidate IPs for.
    """
    try:
        # Create the service directory in the workspace if it does not exist
        workspace_service_dir = os.path.join(shell.current_workspace_dir, service)
        if not os.path.exists(workspace_service_dir):
            os.makedirs(workspace_service_dir)

        # Consolidated IPs file
        consolidated_ips_file = os.path.join(workspace_service_dir, "ips.txt")
        all_ips = set()  # Use a set to avoid duplicates

        # Iterate through all domains
        for domain in shell.domains:
            domain_service_ips = os.path.join(
                shell.domains_dir, domain, service, "ips.txt"
            )
            if os.path.exists(domain_service_ips):
                with open(domain_service_ips, "r", encoding="utf-8") as f:
                    domain_ips = set(line.strip() for line in f if line.strip())
                    all_ips.update(domain_ips)

        # Write all unique IPs to the consolidated file
        if all_ips:
            with open(consolidated_ips_file, "w", encoding="utf-8") as f:
                for ip in sorted(all_ips):  # Sort the IPs for better readability
                    f.write(f"{ip}\n")

    except Exception as e:
        telemetry.capture_exception(e)

        print_error(f"Error consolidating IPs for service {service}.")
        print_exception(show_locals=False, exception=e)


def consolidate_domain_computers(shell: ScanShell, args: Any) -> None:
    """Consolidate the list of computers from all domains.

    Args:
        shell: The active shell instance with workspace and domain data.
        args: Unused argument (kept for compatibility with original signature).
    """
    try:
        # Consolidated computers file
        consolidated_computers_file = os.path.join(
            shell.current_workspace_dir, "enabled_computers_ips.txt"
        )
        all_computers = set()  # Use a set to avoid duplicates

        # Iterate through all domains
        for domain in shell.domains:
            domain_computers_file = os.path.join(
                shell.domains_dir, domain, "enabled_computers_ips.txt"
            )
            if os.path.exists(domain_computers_file):
                with open(domain_computers_file, "r", encoding="utf-8") as f:
                    domain_computers = set(line.strip() for line in f if line.strip())
                    all_computers.update(domain_computers)

        # Write all unique computers to the consolidated file
        if all_computers:
            with open(consolidated_computers_file, "w", encoding="utf-8") as f:
                for computer in sorted(all_computers):
                    f.write(f"{computer}\n")

        # Also consolidate enabled_computers.txt across domains
        consolidated_names_file = os.path.join(
            shell.current_workspace_dir, "enabled_computers.txt"
        )
        all_names = set()
        for domain in shell.domains:
            domain_names_file = os.path.join(
                shell.domains_dir, domain, "enabled_computers.txt"
            )
            if os.path.exists(domain_names_file):
                with open(domain_names_file, "r", encoding="utf-8") as fn:
                    domain_names = set(line.strip() for line in fn if line.strip())
                    all_names.update(domain_names)
        if all_names:
            with open(consolidated_names_file, "w", encoding="utf-8") as f2:
                for name in sorted(all_names):
                    f2.write(f"{name}\n")

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error consolidating computers.")
        print_exception(show_locals=False, exception=e)
