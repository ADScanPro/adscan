"""Secretsdump CLI orchestration helpers.

This module contains all Impacket secretsdump execution and output processing
operations, regardless of the context (DCSync, registry dumps, etc.).

Scope:
- Execute secretsdump commands
- Parse secretsdump output to extract credentials
- Handle secretsdump errors and retries
- Filter and store extracted credentials

These helpers keep command execution and output processing out of the monolithic
`adscan.py` while delegating credential storage and shell-specific operations
to the existing methods on the interactive shell.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Dict, List, Tuple
import os
import re

from adscan_internal import (
    print_error,
    print_exception,
    print_info,
    print_info_debug,
    print_info_table,
    print_success,
    print_warning,
    print_warning_debug,
    telemetry,
)
from adscan_internal.rich_output import mark_sensitive, print_panel
from rich.console import Group as _RichGroup
from rich.prompt import Confirm
from rich.text import Text as _RichText

# DCSync All UX thresholds (compact output in large environments).
_DCSYNC_ALL_LARGE_THRESHOLD = 250
_DCSYNC_ALL_HUGE_THRESHOLD = 1000
_DCSYNC_ALL_CRACKED_PREVIEW_DEFAULT = 15
_DCSYNC_ALL_CRACKED_PREVIEW_LARGE = 8
_DCSYNC_ALL_UNCRACKED_TABLE_MAX = 10


def _capture_dcsync_batch_cracking_summary_telemetry(
    shell: Any,
    *,
    domain: str,
    total: int,
    cracked_total: int,
    uncracked_total: int,
    tier0_extracted: int,
    tier0_cracked: int,
    high_value_extracted: int,
    high_value_cracked: int,
    standard_extracted: int,
    standard_cracked: int,
    cracked_reuse_groups: dict[str, list[dict[str, str]]],
    uncracked_reuse_groups: dict[str, list[dict[str, str]]],
) -> None:
    """Emit telemetry for DCSync-All cracking summary analytics.

    Only aggregate counters/ratios are emitted (no credential or user values).
    """
    try:
        from adscan_internal.cli.common import build_lab_event_fields

        cracked_reused_accounts = sum(
            len(rows) for rows in cracked_reuse_groups.values()
        )
        uncracked_reused_accounts = sum(
            len(rows) for rows in uncracked_reuse_groups.values()
        )
        cracked_reuse_largest_group = max(
            (len(rows) for rows in cracked_reuse_groups.values()),
            default=0,
        )
        uncracked_reuse_largest_group = max(
            (len(rows) for rows in uncracked_reuse_groups.values()),
            default=0,
        )
        largest_cracked_group_rows = (
            max(cracked_reuse_groups.values(), key=len) if cracked_reuse_groups else []
        )
        largest_cracked_group_segment_counts = Counter(
            str(row.get("risk_segment") or "Standard")
            for row in largest_cracked_group_rows
        )

        properties: dict[str, Any] = {
            "domain": domain,
            "workspace_type": getattr(shell, "type", None),
            "auto_mode": getattr(shell, "auto", False),
            "scan_mode": getattr(shell, "scan_mode", None),
            "credentials_extracted": total,
            "hashes_cracked": cracked_total,
            "hashes_uncracked": uncracked_total,
            "hash_crack_rate_pct": round(((cracked_total / total) * 100), 2)
            if total > 0
            else 0.0,
            "tier0_extracted_count": tier0_extracted,
            "tier0_cracked_count": tier0_cracked,
            "tier0_crack_coverage_pct": round(
                ((tier0_cracked / tier0_extracted) * 100), 2
            )
            if tier0_extracted > 0
            else 0.0,
            "tier0_cracked_pct": round(((tier0_cracked / cracked_total) * 100), 2)
            if cracked_total > 0
            else 0.0,
            "high_value_extracted_count": high_value_extracted,
            "high_value_cracked_count": high_value_cracked,
            "high_value_crack_coverage_pct": round(
                ((high_value_cracked / high_value_extracted) * 100), 2
            )
            if high_value_extracted > 0
            else 0.0,
            "high_value_cracked_pct": round(
                ((high_value_cracked / cracked_total) * 100), 2
            )
            if cracked_total > 0
            else 0.0,
            "standard_extracted_count": standard_extracted,
            "standard_cracked_count": standard_cracked,
            "standard_crack_coverage_pct": round(
                ((standard_cracked / standard_extracted) * 100), 2
            )
            if standard_extracted > 0
            else 0.0,
            "standard_cracked_pct": round(((standard_cracked / cracked_total) * 100), 2)
            if cracked_total > 0
            else 0.0,
            "reused_cracked_secret_count": len(cracked_reuse_groups),
            "reused_cracked_accounts_count": cracked_reused_accounts,
            "reused_cracked_accounts_pct": round(
                ((cracked_reused_accounts / cracked_total) * 100), 2
            )
            if cracked_total > 0
            else 0.0,
            "reused_uncracked_hash_count": len(uncracked_reuse_groups),
            "reused_uncracked_accounts_count": uncracked_reused_accounts,
            "reused_cracked_largest_group_size": cracked_reuse_largest_group,
            "reused_uncracked_largest_group_size": uncracked_reuse_largest_group,
            "largest_cracked_reuse_cluster_tier0_count": largest_cracked_group_segment_counts.get(
                "Tier-0", 0
            ),
            "largest_cracked_reuse_cluster_high_value_count": largest_cracked_group_segment_counts.get(
                "High-Value", 0
            ),
            "largest_cracked_reuse_cluster_standard_count": largest_cracked_group_segment_counts.get(
                "Standard", 0
            ),
        }
        properties.update(build_lab_event_fields(shell=shell, include_slug=True))
        telemetry.capture("dcsync_cracking_summary", properties)
    except Exception as exc:  # pragma: no cover - telemetry best effort
        telemetry.capture_exception(exc)
        print_warning_debug(
            f"[dcsync] Failed to emit cracking summary telemetry: {type(exc).__name__}"
        )


def _get_positive_int_env(name: str, default: int) -> int:
    """Return a positive integer env value or the provided default."""
    raw_value = os.getenv(name, "").strip()
    if not raw_value:
        return default
    try:
        parsed = int(raw_value)
    except ValueError:
        return default
    return parsed if parsed > 0 else default


def _resolve_dcsync_all_ui_thresholds() -> dict[str, int]:
    """Resolve DCSync-All UX thresholds from environment variables."""
    large_threshold = _get_positive_int_env(
        "ADSCAN_DCSYNC_ALL_LARGE_THRESHOLD",
        _DCSYNC_ALL_LARGE_THRESHOLD,
    )
    huge_threshold = _get_positive_int_env(
        "ADSCAN_DCSYNC_ALL_HUGE_THRESHOLD",
        _DCSYNC_ALL_HUGE_THRESHOLD,
    )
    if huge_threshold < large_threshold:
        huge_threshold = large_threshold

    cracked_preview_default = _get_positive_int_env(
        "ADSCAN_DCSYNC_ALL_CRACKED_PREVIEW_DEFAULT",
        _DCSYNC_ALL_CRACKED_PREVIEW_DEFAULT,
    )
    cracked_preview_large = _get_positive_int_env(
        "ADSCAN_DCSYNC_ALL_CRACKED_PREVIEW_LARGE",
        _DCSYNC_ALL_CRACKED_PREVIEW_LARGE,
    )
    uncracked_table_max = _get_positive_int_env(
        "ADSCAN_DCSYNC_ALL_UNCRACKED_TABLE_MAX",
        _DCSYNC_ALL_UNCRACKED_TABLE_MAX,
    )

    return {
        "large_threshold": large_threshold,
        "huge_threshold": huge_threshold,
        "cracked_preview_default": cracked_preview_default,
        "cracked_preview_large": cracked_preview_large,
        "uncracked_table_max": uncracked_table_max,
    }



def _offer_machine_account_dump_fallback(
    shell: Any, domain: str, failure_reason: str | None = None
) -> None:
    """Offer SAM/LSA/DPAPI fallback when DCSync returns no credentials.

    Renders a structured panel that explains why DCSync yielded nothing,
    presents the alternative path as a forward option (not an error), and
    gives the operator an estimate of what secrets the fallback can recover.

    Args:
        shell: Active PentestShell instance.
        domain: Target domain that was replicated (or attempted).
        failure_reason: Optional human-readable explanation of why DCSync
            returned no credentials (e.g. "DRSUAPI access denied"). When
            supplied it is shown in the panel to help the operator understand
            what to expect from the alternative path.
    """
    from adscan_internal.services.exploitation.dump_display import (
        ACID_GREEN,
        AMBER,
        GHOST,
        ICE_BLUE,
        LAVA,
        MUTED,
    )

    context = getattr(shell, "_current_dcsync_context", None)
    if not isinstance(context, dict):
        return
    username = str(context.get("username") or "")
    password = str(context.get("password") or "")
    from adscan_internal.principal_utils import is_machine_account

    if not is_machine_account(username):
        return
    auth_state = shell.domains_data.get(domain, {}).get("auth")
    if auth_state == "pwned":
        return

    # Short-circuit: if a DA / high-value credential (e.g. Administrator
    # cleartext extracted from the same backup-operators run that produced this
    # machine account hash) is already stored, the SAM/LSA re-dump would only
    # re-yield secrets we already have.  Re-dumping is wasteful and noisy —
    # surface a compact notice and stop here.
    # Uses is_user_da_or_high_value: layered fallback of graph + snapshot +
    # cached lists + localized Administrator variants + krbtgt + persisted
    # builtin_administrator_name.  Catches built-in DAs, custom-named DAs,
    # localized DAs, and the early-pentest window before any LDAP collection.
    _stored_creds = shell.domains_data.get(domain, {}).get("credentials") or {}
    _existing_da: str | None = None
    if isinstance(_stored_creds, dict):
        from adscan_internal.services.high_value import is_user_da_or_high_value
        for stored_user, stored_cred in _stored_creds.items():
            if not stored_cred or str(stored_user).endswith("$"):
                continue
            try:
                if is_user_da_or_high_value(
                    shell, domain=domain, samaccountname=str(stored_user)
                ):
                    _existing_da = str(stored_user)
                    break
            except Exception:  # noqa: BLE001
                continue
    if _existing_da:
        from rich.text import Text as _Text
        from adscan_core.rich_output import _get_console as _gc
        _line = _Text()
        _line.append("  ↩ ", style="dim #6E7681")
        _line.append("SAM/LSA fallback skipped", style="#6E7681")
        _line.append("  ·  ", style="dim #6E7681")
        _line.append(
            f"high-value credential already captured: {mark_sensitive(_existing_da, 'user')}",
            style="dim #6E7681",
        )
        try:
            _gc().print(_line)
        except Exception:  # noqa: BLE001
            pass
        print_info_debug(
            f"[dcsync-fallback] Skipping SAM/LSA re-dump for {domain!r} — "
            f"high-value credential {_existing_da!r} already in credential store."
        )
        return

    pdc_host = shell.domains_data.get(domain, {}).get(
        "pdc_hostname"
    ) or shell.domains_data.get(domain, {}).get("pdc")
    if not pdc_host:
        return

    marked_domain = mark_sensitive(domain, "domain")
    marked_user = mark_sensitive(username, "user")

    # Build a structured panel explaining the situation and the alternative.
    why_line = _RichText()
    if failure_reason:
        why_line.append("Reason  ", style=MUTED)
        why_line.append(str(failure_reason), style=f"bold {LAVA}")
    else:
        why_line.append("Reason  ", style=MUTED)
        why_line.append("DCSync returned no credentials", style=f"bold {AMBER}")

    fallback_lines = _RichText()
    fallback_lines.append("Alternative path  ", style=MUTED)
    fallback_lines.append(
        "SMB SAM / LSA / DPAPI with machine-account delegation",
        style=f"bold {ACID_GREEN}",
    )
    fallback_lines.append("\n")
    fallback_lines.append("What to expect    ", style=MUTED)
    fallback_lines.append(
        "Local accounts (SAM)  ·  LSA secrets  ·  DPAPI master keys",
        style=ICE_BLUE,
    )
    fallback_lines.append("\n")
    fallback_lines.append("Coverage          ", style=MUTED)
    fallback_lines.append(
        "Covers machine-local Administrator hash + cached domain credentials",
        style=MUTED,
    )

    domain_line = _RichText()
    domain_line.append("Domain          ", style=MUTED)
    domain_line.append(marked_domain, style=f"bold {ICE_BLUE}")
    domain_line.append("   Machine      ", style=MUTED)
    domain_line.append(marked_user, style=f"bold {ICE_BLUE}")

    panel_body = _RichGroup(
        _RichText(""),
        why_line,
        _RichText(""),
        domain_line,
        _RichText(""),
        _RichText("─" * 48, style=GHOST),
        _RichText(""),
        fallback_lines,
        _RichText(""),
    )
    print_panel(
        panel_body,
        title=f"[bold {AMBER}]DCSync · Alternative Path Available[/bold {AMBER}]",
        border_style=AMBER,
        expand=False,
    )

    # Disclose blast radius before asking for consent. Three consecutive
    # SMB dumps fire authentication events (4624/4672) and registry/secret
    # reads visible to MDI / Defender for Identity. Default flips to False
    # so a stray Enter never auto-consents to additional noise. Auto mode
    # bypasses the prompt to honour the engagement contract.
    blast_line = _RichText()
    blast_line.append("  Will fire    ", style=MUTED)
    blast_line.append(
        "3 SMB dumps (SAM, LSA, DPAPI) against the PDC",
        style=f"bold {AMBER}",
    )
    telemetry_line = _RichText()
    telemetry_line.append("  Telemetry    ", style=MUTED)
    telemetry_line.append(
        "Windows 4624/4672 on the DC. SAM/LSA registry reads logged.",
        style=MUTED,
    )
    print_panel(
        _RichGroup(
            _RichText(""),
            blast_line,
            telemetry_line,
            _RichText(""),
        ),
        title=f"[bold {AMBER}]Confirm Fallback[/bold {AMBER}]",
        border_style=AMBER,
        expand=False,
    )
    prompt = "Proceed with SMB SAM/LSA/DPAPI dumps via machine delegation?"
    if getattr(shell, "auto", False):
        print_info_debug("[dcsync] Auto mode: proceeding with SMB fallback.")
    elif not Confirm.ask(prompt, default=False):
        return

    print_info_debug("[dcsync] Falling back to SMB dumps with machine delegation.")
    from adscan_internal.cli.dumps import run_dump_dpapi, run_dump_lsa, run_dump_sam

    print_info("Starting SAM dump via machine delegation...")
    run_dump_sam(
        shell,
        domain=domain,
        username=username,
        password=password,
        host=str(pdc_host),
        islocal="false",
    )
    if shell.domains_data.get(domain, {}).get("auth") == "pwned":
        return
    print_info("Starting LSA dump via machine delegation...")
    run_dump_lsa(
        shell,
        domain=domain,
        username=username,
        password=password,
        host=str(pdc_host),
        islocal="false",
    )
    if shell.domains_data.get(domain, {}).get("auth") == "pwned":
        return
    print_info("Starting DPAPI dump via machine delegation...")
    run_dump_dpapi(
        shell,
        domain=domain,
        username=username,
        password=password,
        host=str(pdc_host),
        islocal="false",
    )


def _render_dcsync_batch_cracking_summary(
    *,
    shell: Any,
    domain: str,
    credentials: list[tuple[str, str]],
) -> None:
    """Render compact cracking summary for DCSync All batch processing.

    Presents three distinct sections — CRACKED / UNCRACKED / REUSED — with
    visual hierarchy that elevates krbtgt and Tier-0 accounts. A progress bar
    shows the crack rate at a glance. When krbtgt was cracked a special banner
    emphasises the golden-ticket capability.
    """
    from adscan_internal.services.exploitation.dump_display import (
        ACID_GREEN,
        AMBER,
        GHOST,
        ICE_BLUE,
        LAVA,
        MUTED,
    )

    if not credentials:
        return

    cracked_rows: list[dict[str, str]] = []
    uncracked_rows: list[dict[str, str]] = []
    user_values: list[str] = []
    for username, credential in credentials:
        normalized_user = str(username or "").strip()
        normalized_credential = str(credential or "").strip()
        if not normalized_user or not normalized_credential:
            continue
        user_values.append(normalized_user)
        row_base = {
            "raw_user": normalized_user,
            "raw_credential": normalized_credential,
        }
        if re.fullmatch(r"[0-9a-fA-F]{32}", normalized_credential):
            uncracked_rows.append(row_base)
        else:
            cracked_rows.append(row_base)

    risk_map: dict[str, tuple[bool, bool]] = {}

    def normalize_user_for_lookup(value: str) -> str:
        return str(value or "").casefold()

    if user_values:
        try:
            from adscan_internal.services.high_value import (
                classify_users_tier0_high_value,
                normalize_samaccountname,
            )

            normalize_user_for_lookup = normalize_samaccountname
            resolved_risks = classify_users_tier0_high_value(
                shell, domain=domain, usernames=user_values
            )
            risk_map = {
                normalize_user_for_lookup(username): (
                    bool(flags.is_tier0),
                    bool(flags.is_high_value),
                )
                for username, flags in resolved_risks.items()
            }
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning_debug(
                f"[dcsync] Unable to classify cracked users by risk tier: {type(exc).__name__}"
            )

    def _classify_user(user_raw: str) -> tuple[bool, bool]:
        normalized = normalize_user_for_lookup(user_raw)
        return risk_map.get(normalized, (False, False))

    def _risk_segment_for_user(user_raw: str) -> str:
        is_tier0_user, is_high_value_user = _classify_user(user_raw)
        if is_tier0_user:
            return "Tier-0"
        if is_high_value_user:
            return "High-Value"
        return "Standard"

    # Detect krbtgt in cracked list (golden ticket signal)
    krbtgt_cracked = any(
        str(row.get("raw_user") or "").strip().lower() == "krbtgt"
        for row in cracked_rows
    )

    for row in cracked_rows:
        row["risk_segment"] = _risk_segment_for_user(row["raw_user"])
        row["User"] = mark_sensitive(str(row["raw_user"]), "user")
        row["Password"] = mark_sensitive(str(row["raw_credential"]), "password")
    for row in uncracked_rows:
        row["risk_segment"] = _risk_segment_for_user(row["raw_user"])
        row["User"] = mark_sensitive(str(row["raw_user"]), "user")
        row["Hash"] = mark_sensitive(str(row["raw_credential"]), "password")

    cracked_total = len(cracked_rows)
    uncracked_total = len(uncracked_rows)
    extracted_by_segment = Counter(
        row["risk_segment"] for row in [*cracked_rows, *uncracked_rows]
    )
    cracked_by_segment = Counter(row["risk_segment"] for row in cracked_rows)
    tier0_extracted = int(extracted_by_segment.get("Tier-0", 0))
    high_value_extracted = int(extracted_by_segment.get("High-Value", 0))
    standard_extracted = int(extracted_by_segment.get("Standard", 0))
    tier0_cracked = int(cracked_by_segment.get("Tier-0", 0))
    high_value_cracked = int(cracked_by_segment.get("High-Value", 0))
    standard_cracked = int(cracked_by_segment.get("Standard", 0))

    def _format_count_and_percent(count: int, denominator: int) -> str:
        if denominator <= 0:
            return str(count)
        return f"{count} ({(count / denominator) * 100:.1f}%)"

    def _format_percent(count: int, denominator: int) -> str:
        if denominator <= 0:
            return "0.0%"
        return f"{(count / denominator) * 100:.1f}%"

    def _format_ratio_with_percent(count: int, denominator: int) -> str:
        return f"{count}/{denominator} ({_format_percent(count, denominator)})"

    def _build_reuse_groups(
        rows: list[dict[str, str]],
    ) -> dict[str, list[dict[str, str]]]:
        grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
        for row in rows:
            grouped[str(row["raw_credential"])].append(row)
        return {value: users for value, users in grouped.items() if len(users) > 1}

    cracked_reuse_groups = _build_reuse_groups(cracked_rows)
    uncracked_reuse_groups = _build_reuse_groups(uncracked_rows)
    cracked_reused_accounts = sum(len(rows) for rows in cracked_reuse_groups.values())
    uncracked_reused_accounts = sum(
        len(rows) for rows in uncracked_reuse_groups.values()
    )

    total = len(cracked_rows) + len(uncracked_rows)

    _capture_dcsync_batch_cracking_summary_telemetry(
        shell,
        domain=domain,
        total=total,
        cracked_total=cracked_total,
        uncracked_total=uncracked_total,
        tier0_extracted=tier0_extracted,
        tier0_cracked=tier0_cracked,
        high_value_extracted=high_value_extracted,
        high_value_cracked=high_value_cracked,
        standard_extracted=standard_extracted,
        standard_cracked=standard_cracked,
        cracked_reuse_groups=cracked_reuse_groups,
        uncracked_reuse_groups=uncracked_reuse_groups,
    )

    marked_domain = mark_sensitive(domain, "domain")

    # ------------------------------------------------------------------
    # Visual crack-rate progress bar (ASCII, always visible)
    # ------------------------------------------------------------------
    BAR_WIDTH = 40
    filled = round((cracked_total / total) * BAR_WIDTH) if total > 0 else 0
    unfilled = BAR_WIDTH - filled
    crack_pct = (cracked_total / total * 100) if total > 0 else 0.0
    bar_text = _RichText()
    bar_text.append("  [", style=MUTED)
    bar_text.append("█" * filled, style=f"bold {ACID_GREEN}")
    bar_text.append("░" * unfilled, style=GHOST)
    bar_text.append("]", style=MUTED)
    bar_text.append(f"  {cracked_total}/{total} cracked", style=f"bold {ACID_GREEN}")
    bar_text.append(f"  ({crack_pct:.1f}%)", style=MUTED)

    # ------------------------------------------------------------------
    # Tier breakdown rows
    # ------------------------------------------------------------------
    def _tier_summary_line(
        label: str,
        label_style: str,
        cracked: int,
        extracted: int,
    ) -> _RichText:
        line = _RichText()
        seg_filled = round((cracked / extracted) * 20) if extracted > 0 else 0
        seg_bar = "█" * seg_filled + "░" * (20 - seg_filled)
        crack_rate = f"{(cracked / extracted * 100):.0f}%" if extracted > 0 else "—"
        line.append(f"  {label:<14}", style=label_style)
        line.append(f"  {cracked}/{extracted}", style=f"bold {label_style}")
        line.append(f"  [{seg_bar}]", style=MUTED)
        line.append(f"  {crack_rate}", style=label_style)
        return line

    tier0_line = _tier_summary_line("Tier-0", LAVA, tier0_cracked, tier0_extracted)
    hv_line = _tier_summary_line("High-Value", AMBER, high_value_cracked, high_value_extracted)
    std_line = _tier_summary_line("Standard", MUTED, standard_cracked, standard_extracted)

    # ------------------------------------------------------------------
    # CRACKED / UNCRACKED / REUSED section headers
    # ------------------------------------------------------------------
    cracked_header = _RichText()
    cracked_header.append(" ● CRACKED ", style=f"bold white on {ACID_GREEN}")
    cracked_header.append(f"  {cracked_total} credentials", style=f"bold {ACID_GREEN}")

    uncracked_header = _RichText()
    uncracked_header.append(" ○ UNCRACKED ", style=f"bold white on {LAVA}")
    uncracked_header.append(f"  {uncracked_total} hashes retained", style=MUTED)

    reuse_groups_total = len(cracked_reuse_groups) + len(uncracked_reuse_groups)
    reuse_accounts_total = cracked_reused_accounts + uncracked_reused_accounts
    reused_header = _RichText()
    reused_header.append(" ↺ REUSED ", style=f"bold white on {AMBER}")
    if reuse_groups_total:
        reused_header.append(
            f"  {reuse_accounts_total} accounts across {reuse_groups_total} shared secret(s)",
            style=f"bold {AMBER}",
        )
    else:
        reused_header.append("  no reuse detected", style=MUTED)

    # ------------------------------------------------------------------
    # Top-value account line
    # ------------------------------------------------------------------
    top_value_line = _RichText()
    top_value_user: str | None = None
    top_value_style = MUTED
    if krbtgt_cracked:
        top_value_user = "krbtgt"
        top_value_style = LAVA
    elif tier0_cracked > 0:
        for row in cracked_rows:
            if row.get("risk_segment") == "Tier-0":
                top_value_user = str(row.get("raw_user") or "")
                top_value_style = AMBER
                break
    elif high_value_cracked > 0:
        for row in cracked_rows:
            if row.get("risk_segment") == "High-Value":
                top_value_user = str(row.get("raw_user") or "")
                top_value_style = ICE_BLUE
                break

    if top_value_user:
        top_value_line.append("  Top value  ", style=MUTED)
        top_value_line.append(
            mark_sensitive(top_value_user, "user"), style=f"bold {top_value_style}"
        )

    summary_body = _RichGroup(
        _RichText(""),
        bar_text,
        _RichText(""),
        _RichText("─" * 48, style=GHOST),
        _RichText(""),
        tier0_line,
        hv_line,
        std_line,
        _RichText(""),
        _RichText("─" * 48, style=GHOST),
        _RichText(""),
        cracked_header,
        _RichText(""),
        uncracked_header,
        _RichText(""),
        reused_header,
        *((_RichText(""), top_value_line) if top_value_user else ()),
        _RichText(""),
    )
    print_panel(
        summary_body,
        title=f"[bold {ICE_BLUE}]DCSync Cracking Summary  {marked_domain}[/bold {ICE_BLUE}]",
        border_style=ICE_BLUE,
        expand=False,
    )

    # ------------------------------------------------------------------
    # Golden ticket banner — only when krbtgt was cracked
    # ------------------------------------------------------------------
    if krbtgt_cracked:
        gt_line1 = _RichText()
        gt_line1.append("  krbtgt CRACKED", style=f"bold {LAVA}")
        gt_line1.append(
            ": Golden Ticket forging is now possible", style="bold white"
        )
        gt_line2 = _RichText()
        gt_line2.append(
            "  Forge a TGT for any account, any group, any lifetime.",
            style=MUTED,
        )
        gt_line3 = _RichText()
        gt_line3.append(
            "  Rotate the krbtgt password twice on the DC to invalidate all forged tickets.",
            style=MUTED,
        )
        gt_body = _RichGroup(
            _RichText(""),
            gt_line1,
            gt_line2,
            _RichText(""),
            gt_line3,
            _RichText(""),
        )
        print_panel(
            gt_body,
            title=f"[bold white on {LAVA}] GOLDEN TICKET CAPABILITY [/bold white on {LAVA}]",
            border_style=LAVA,
            expand=False,
        )

    thresholds = _resolve_dcsync_all_ui_thresholds()
    large_threshold = thresholds["large_threshold"]
    huge_threshold = thresholds["huge_threshold"]
    cracked_preview_default = thresholds["cracked_preview_default"]
    cracked_preview_large = thresholds["cracked_preview_large"]
    uncracked_table_max = thresholds["uncracked_table_max"]

    if total >= huge_threshold:
        print_info(
            "Large environment detected. Showing aggregate results only to keep output concise."
        )
        return

    if total >= large_threshold:
        cracked_preview_limit = cracked_preview_large
    else:
        cracked_preview_limit = cracked_preview_default

    if cracked_rows:
        segment_breakdown_rows = []
        for segment in ("Tier-0", "High-Value", "Standard"):
            extracted_count = int(extracted_by_segment.get(segment, 0))
            cracked_count = int(cracked_by_segment.get(segment, 0))
            uncracked_count = max(extracted_count - cracked_count, 0)
            segment_breakdown_rows.append(
                {
                    "Segment": segment,
                    "Extracted": str(extracted_count),
                    "Cracked": str(cracked_count),
                    "Uncracked": str(uncracked_count),
                    "Crack Rate": _format_percent(cracked_count, extracted_count),
                    "Share of Cracked": _format_percent(cracked_count, cracked_total),
                }
            )
        print_info_table(
            segment_breakdown_rows,
            [
                "Segment",
                "Extracted",
                "Cracked",
                "Uncracked",
                "Crack Rate",
                "Share of Cracked",
            ],
            title="Cracked Privilege Breakdown",
        )
        print_info_table(
            cracked_rows[:cracked_preview_limit],
            ["User", "Password"],
            title="Cracked Credentials",
        )
        if len(cracked_rows) > cracked_preview_limit:
            print_info(
                "Showing first "
                f"{cracked_preview_limit} cracked credentials out of {len(cracked_rows)}."
            )

    if (
        uncracked_rows
        and total < large_threshold
        and len(uncracked_rows) <= uncracked_table_max
    ):
        print_info_table(
            uncracked_rows,
            ["User", "Hash"],
            title="Uncracked Hashes",
        )
    elif uncracked_rows:
        print_info(f"Uncracked hashes retained for {len(uncracked_rows)} account(s).")

    reuse_rows: list[dict[str, str]] = []

    def _append_reuse_rows(
        *,
        secret_label: str,
        groups: dict[str, list[dict[str, str]]],
    ) -> None:
        ordered = sorted(
            groups.items(),
            key=lambda item: (-len(item[1]), str(item[0]).casefold()),
        )
        for secret_value, rows in ordered[:5]:
            segment_counts = Counter(
                str(row.get("risk_segment") or "Standard") for row in rows
            )
            reuse_rows.append(
                {
                    "Secret Type": secret_label,
                    "Secret": mark_sensitive(str(secret_value), "password"),
                    "Accounts": str(len(rows)),
                    "Tier-0": str(segment_counts.get("Tier-0", 0)),
                    "High-Value": str(segment_counts.get("High-Value", 0)),
                    "Standard": str(segment_counts.get("Standard", 0)),
                }
            )

    _append_reuse_rows(secret_label="Password", groups=cracked_reuse_groups)
    _append_reuse_rows(secret_label="Hash", groups=uncracked_reuse_groups)

    if reuse_rows:
        print_info_table(
            reuse_rows,
            ["Secret Type", "Secret", "Accounts", "Tier-0", "High-Value", "Standard"],
            title="Top Reused Secrets",
        )


def _select_dcsync_ccache(
    explicit_ccache: str | None, workspace_ccache: str | None
) -> str | None:
    """Return the ccache DCSync should authenticate with, honouring the
    documented priority: an EXPLICIT caller-passed ccache (priority 1, e.g. a
    minted S4U service ticket handed to this call) beats a by-username workspace
    ccache found in ``kerberos_tickets`` (priority 2). An explicitly-passed
    ticket must never be silently overridden by a TGT matched only by username.
    """
    return explicit_ccache or workspace_ccache


def execute_dcsync_native(
    shell: Any,
    domain: str,
    auth_domain: str | None = None,
    target_users: list[str] | None = None,
) -> dict | None:
    """Execute DCSync via native DRSUAPI — streaming live display.

    Returns:
        ``None`` when the run aborted before secrets could be evaluated
        (missing context, missing PDC, transport failure). Otherwise a dict
        ``{"krbtgt": bool, "tier0_count": int, "total": int}`` summarising
        what was extracted, so callers (notably the attack-graph step
        executor) can decide whether the DCSync edge should be marked as
        ``success`` or ``failed``.


    Streams DRSUAPI secrets via the native dump service and runs the standard
    credential persistence + post-processing pipeline.

    Args:
        shell: The active ``PentestShell`` instance.
        domain: Target domain being replicated (enumeration target).
        auth_domain: Domain the credential belongs to. Defaults to ``domain``
            when the authenticating user lives in the same domain.
        target_users: List of sAMAccountNames to replicate. ``None`` / empty
            means "all users" (full DRSUAPI walk).
    """
    from adscan_internal.services.async_bridge import run_async_sync
    import time

    from adscan_internal.services.exploitation.native_dump_service import (
        NativeDumpService,
    )
    from adscan_internal.services.exploitation.dump_display import (
        DumpDisplay,
    )
    from adscan_internal.services.smb_transport import SMBConfig
    from adscan_internal.principal_utils import is_machine_account

    # ------------------------------------------------------------------ #
    # 1. Build SMBConfig from _current_dcsync_context + domains_data
    # ------------------------------------------------------------------ #
    context = getattr(shell, "_current_dcsync_context", None)
    if not isinstance(context, dict):
        print_error("execute_dcsync_native: missing DCSync context. Cannot proceed.")
        return None

    username: str = str(context.get("username") or "")
    password: str = str(context.get("password") or "")
    target_user: str = str(context.get("target_user") or "")

    domain_data = (getattr(shell, "domains_data", {}) or {}).get(domain, {})
    pdc_ip: str = str(domain_data.get("pdc") or "")
    pdc_hostname: str | None = domain_data.get("pdc_hostname") or None

    if not pdc_ip:
        print_error(
            f"execute_dcsync_native: no PDC IP for domain {mark_sensitive(domain, 'domain')}."
        )
        return None

    effective_auth_domain: str = auth_domain or domain

    # ------------------------------------------------------------------
    # Context panel — who, what, where (shown before the stream starts)
    # ------------------------------------------------------------------
    from adscan_internal.services.exploitation.dump_display import (
        ACID_GREEN,
        AMBER,
        GHOST,
        ICE_BLUE,
        MUTED,
    )

    _scope_label = "All accounts (DRSUAPI full walk)" if not target_users else (
        f"{len(target_users)} targeted account(s)"
    )
    _auth_label = f"{mark_sensitive(username, 'user')}@{mark_sensitive(effective_auth_domain, 'domain')}"
    _target_label = mark_sensitive(pdc_hostname or pdc_ip, "domain")

    _ctx_line1 = _RichText()
    _ctx_line1.append("  Operation    ", style=MUTED)
    _ctx_line1.append("DCSync via native DRSUAPI", style=f"bold {ICE_BLUE}")

    _ctx_line2 = _RichText()
    _ctx_line2.append("  Credential   ", style=MUTED)
    _ctx_line2.append(_auth_label, style=f"bold {ACID_GREEN}")

    _ctx_line3 = _RichText()
    _ctx_line3.append("  Target DC    ", style=MUTED)
    _ctx_line3.append(_target_label, style=f"bold {ICE_BLUE}")
    if pdc_ip and pdc_hostname and pdc_ip != pdc_hostname:
        _ctx_line3.append(f"  ({pdc_ip})", style=MUTED)

    _ctx_line4 = _RichText()
    _ctx_line4.append("  Scope        ", style=MUTED)
    _ctx_line4.append(_scope_label, style=MUTED)

    _ctx_opsec = _RichText()
    _ctx_opsec.append("  Detection    ", style=MUTED)
    _ctx_opsec.append(
        "MDI Event 4662, high severity. Source IP visible in DC security log.",
        style=f"bold {AMBER}",
    )

    _ctx_body = _RichGroup(
        _RichText(""),
        _ctx_line1,
        _ctx_line2,
        _ctx_line3,
        _ctx_line4,
        _RichText(""),
        _RichText("─" * 48, style=GHOST),
        _RichText(""),
        _ctx_opsec,
        _RichText(""),
    )
    print_panel(
        _ctx_body,
        title=f"[bold {ICE_BLUE}]Initiating DCSync[/bold {ICE_BLUE}]",
        border_style=ICE_BLUE,
        expand=False,
    )

    is_hash = len(password) == 32 and all(
        c in "0123456789abcdef" for c in password.lower()
    )
    is_ccache = password.lower().endswith(".ccache")

    # Always use an explicit ccache for DCSync — never rely on KRB5CCNAME or
    # plaintext NTLM.  bind_workspace_ticket_for_user() (called by the LDAP
    # adminCount check just before) mutates KRB5CCNAME to the adscan service
    # account.  If the DCERPC auth layer (from_smb_gssapi) later picks up the
    # contaminated global cache it authenticates as the wrong user, causing
    # ERROR_DS_DRA_BAD_DN on DRSGetNCChanges.  Passing ccache_path explicitly
    # forces smb+kerberos-ccache, which reads the path directly and is immune
    # to KRB5CCNAME global state.
    #
    # Priority:
    #   1. Explicit ccache in password field
    #   2. Workspace ccache already on disk for this user (NT hash or password)
    #   3. Freshly obtained TGT (plaintext password → kerbad get_tgt)
    #   4. NT hash with NTLM (last resort, only if kerbad fails)
    _workspace_ccache: str | None = None
    _tickets: dict = (domain_data.get("kerberos_tickets") or {})
    for _ukey, _upath in _tickets.items():
        if isinstance(_ukey, str) and _ukey.casefold() == username.casefold():
            _candidate = str(_upath or "").strip()
            if _candidate and os.path.exists(_candidate):
                _workspace_ccache = _candidate
                print_info_debug(
                    f"dcsync-native: found workspace ccache for "
                    f"{mark_sensitive(username, 'user')}: "
                    f"{mark_sensitive(_candidate, 'path')}"
                )
            break

    # For plaintext passwords: obtain a TGT now and use it as the explicit
    # ccache so the DCERPC auth layer never touches KRB5CCNAME.
    if not is_hash and not is_ccache and not _workspace_ccache:
        import tempfile
        try:
            from adscan_internal.services.kerberos_transport import (
                KerberosConfig, get_tgt,
            )
            _tgt_ccache = tempfile.mktemp(suffix=".ccache", prefix="adscan_dcsync_")
            _kr_cfg = KerberosConfig(
                domain=effective_auth_domain,
                kdc_ip=pdc_ip,
                username=username,
                password=password,
                ccache_path=_tgt_ccache,
            )
            import asyncio as _asyncio
            _asyncio.get_event_loop().run_until_complete(get_tgt(_kr_cfg))
            if os.path.exists(_tgt_ccache):
                _workspace_ccache = _tgt_ccache
                print_info_debug(
                    f"dcsync-native: obtained fresh TGT for "
                    f"{mark_sensitive(username, 'user')} → using explicit ccache"
                )
        except Exception as _tgt_exc:  # noqa: BLE001
            print_info_debug(
                f"dcsync-native: TGT acquisition failed for "
                f"{mark_sensitive(username, 'user')} ({type(_tgt_exc).__name__}: {_tgt_exc}); "
                "falling back to NTLM plaintext — KRB5CCNAME contamination risk"
            )

    _krb5ccname_at_dcsync = os.environ.get("KRB5CCNAME", "<unset>")
    print_info_debug(
        f"dcsync-native: KRB5CCNAME at DCSync entry: "
        f"{mark_sensitive(_krb5ccname_at_dcsync, 'path')} | "
        f"workspace_ccache={'yes' if _workspace_ccache else 'no'} | "
        f"is_hash={is_hash} is_ccache={is_ccache}"
    )

    _explicit_ccache = password if is_ccache else None
    _use_ccache = _select_dcsync_ccache(_explicit_ccache, _workspace_ccache)
    smb_config = SMBConfig(
        target_ip=pdc_ip,
        target_hostname=pdc_hostname,
        domain=domain,
        auth_domain=effective_auth_domain,
        username=username,
        # Pass plaintext only when no ccache available (NTLM last resort).
        password=None if (is_hash or is_ccache or _workspace_ccache) else password,
        nt_hash=password if (is_hash and not _workspace_ccache) else None,
        ccache_path=_use_ccache,
        use_kerberos=bool(_use_ccache),
        kdc_ip=pdc_ip,
    )
    print_info_debug(
        f"dcsync-native: SMBConfig: use_kerberos={smb_config.use_kerberos} "
        f"has_hash={bool(smb_config.nt_hash)} has_ccache={bool(smb_config.ccache_path)} "
        f"target={smb_config.target_ip} hostname={smb_config.target_hostname}"
    )

    # ------------------------------------------------------------------ #
    # 2. Stream DRSUAPI secrets via NativeDumpService.dcsync()
    # ------------------------------------------------------------------ #
    display = DumpDisplay()
    marked_domain = mark_sensitive(domain, "domain")
    display.operation_header("DCSync (native DRSUAPI)", pdc_hostname or pdc_ip, 1)
    display.phase_start(1, 1, f"Replicating secrets from {marked_domain}")
    display.start_credential_stream(f"NTDS · {marked_domain}")

    raw_credentials: List[Tuple[str, str]] = []
    raw_secrets_for_meta: list = []  # full DcsyncSecret objects — needed later for AES persistence
    aes_credentials: dict[str, str] = {}  # acct → aes256_key
    rid_by_account: dict[str, int] = {}  # acct (lowercased) → RID parsed from SID
    sid_by_account: dict[str, str] = {}  # acct (lowercased) → SID (DCSync inventory)
    enabled_by_account: dict[
        str, bool
    ] = {}  # acct (lowercased) → is_enabled (UAC bit 0x0002 inverted)
    privileged_accounts: set[str] = set()
    krbtgt_found: bool = False
    builtin_admin_account: str | None = None  # populated when RID==500 row arrives
    errors_seen: int = 0
    _stream_error_types: list[str] = []  # track error class names to distinguish timeout vs access denied
    start_time = time.monotonic()

    def _extract_rid(sid: str | None) -> int | None:
        """Return the trailing RID component of ``sid`` or ``None``.

        Universal across locales (es-ES "Administrador", de-DE "Administrator",
        renamed builtin admins) — RID 500 / 502 are stable.
        """
        if not sid:
            return None
        try:
            return int(str(sid).rsplit("-", 1)[1])
        except (ValueError, IndexError):
            return None

    _PRIVILEGED_PREFIXES = ("administrator", "admin", "krbtgt")
    _PRIVILEGED_SUFFIXES = ("-admin", "_admin", "adm")

    def _is_privileged(acct: str) -> bool:
        low = acct.lower()
        return any(low.startswith(p) for p in _PRIVILEGED_PREFIXES) or any(
            low.endswith(s) for s in _PRIVILEGED_SUFFIXES
        )

    async def _collect() -> None:
        nonlocal errors_seen, krbtgt_found, builtin_admin_account
        svc = NativeDumpService()
        print_info_debug(
            f"dcsync-native: config: target={smb_config.target_ip} "
            f"domain={smb_config.domain} auth_domain={smb_config.auth_domain} "
            f"user={smb_config.username} "
            f"has_hash={bool(smb_config.nt_hash)} has_pass={bool(smb_config.password)} "
            f"use_kerberos={smb_config.use_kerberos} kdc={smb_config.kdc_ip}"
        )
        async for secret, err in svc.dcsync(
            smb_config,
            target_domain=domain,
            target_users=target_users or [],
        ):
            if err is not None:
                errors_seen += 1
                _stream_error_types.append(type(err).__name__)
                print_info_debug(
                    f"dcsync-native: stream error: {type(err).__name__}: {err}"
                )
                continue
            if secret is None:
                continue

            acct = str(secret.username or "")
            nt = str(secret.nt_hash or "")

            # Filter: skip machine accounts and common noise accounts
            if is_machine_account(acct):
                continue
            if (
                acct.startswith("MSOL_")
                or acct.startswith("SM_")
                or acct.startswith("HealthMailbox")
            ):
                continue
            if acct.lower() in ("guest", "invitado", "defaultaccount"):
                continue

            if not nt:
                continue

            # Track AES256 keys — high value for pass-the-key when RC4 disabled
            aes256 = str(secret.aes256_key or "")
            if aes256:
                aes_credentials[acct] = aes256

            sid_value = getattr(secret, "sid", None)
            rid = _extract_rid(sid_value)
            if rid is not None:
                rid_by_account[acct.lower()] = rid
            if sid_value:
                sid_by_account[acct.lower()] = str(sid_value)
            try:
                enabled_by_account[acct.lower()] = bool(
                    getattr(secret, "is_enabled", True)
                )
            except Exception:
                enabled_by_account[acct.lower()] = True

            # RID-based detection — locale-agnostic.
            is_krbtgt = rid == 502 or acct.lower() == "krbtgt"
            if is_krbtgt:
                krbtgt_found = True
            if rid == 500 and builtin_admin_account is None:
                builtin_admin_account = acct
            is_priv = is_krbtgt or rid in (500, 512, 518, 519) or _is_privileged(acct)
            if is_priv:
                privileged_accounts.add(acct)

            raw_credentials.append((acct, nt))
            raw_secrets_for_meta.append(secret)
            display.stream_dcsync_credential(
                account=acct,
                nt_hash=nt,
                aes256=aes256 or None,
                is_krbtgt=is_krbtgt,
                is_privileged=is_priv,
                count=len(raw_credentials),
            )

    try:
        run_async_sync(_collect())
    except Exception as exc:
        telemetry.capture_exception(exc)
        display.stop_credential_stream()

        # Map known DCERPC / SMB error strings to a human-readable cause so
        # the operator understands what to fix without reading raw exception text.
        _exc_str = str(exc).lower()
        if "access_denied" in _exc_str or "access denied" in _exc_str:
            _cause = (
                f"DRSUAPI access denied. Verify DCSync rights for "
                f"{mark_sensitive(username, 'user')} on {mark_sensitive(domain, 'domain')}."
            )
        elif "logon_failure" in _exc_str or "invalid credentials" in _exc_str:
            _cause = (
                f"Authentication failed. Check credential for "
                f"{mark_sensitive(username, 'user')} (hash expired or password changed?)."
            )
        elif "bad_network_name" in _exc_str or "connection refused" in _exc_str:
            _cause = (
                f"Cannot reach PDC {mark_sensitive(pdc_hostname or pdc_ip, 'domain')}. "
                "Verify network connectivity and DC availability."
            )
        elif "kerberos" in _exc_str or "krb" in _exc_str:
            _cause = (
                "Kerberos authentication error. Check clock skew, realm, and SPN. "
                "Run with --debug for the full KRB error code."
            )
        else:
            _cause = f"Transport error ({type(exc).__name__})"

        print_error(f"DCSync failed: {_cause}")
        print_exception(show_locals=False, exception=exc)
        return None

    elapsed = time.monotonic() - start_time
    display.stop_credential_stream()
    display.dcsync_summary(
        total=len(raw_credentials),
        privileged_count=len(privileged_accounts),
        aes_count=len(aes_credentials),
        has_krbtgt=krbtgt_found,
        host=pdc_hostname or pdc_ip,
        elapsed=elapsed,
    )

    if errors_seen > 0:
        _stream_errors_lower = " ".join(_stream_error_types).lower()
        _is_network_block = "timeout" in _stream_errors_lower
        if _is_network_block:
            # tui-design: semantic color + glyph — amber ⚠ (network constraint)
            # not crimson ✗ (permission error). Contextual intelligence: distinguish
            # "not an ADscan bug" from "operator needs to fix rights".
            # impeccable: verdict-first, no hedging, actionable.
            from rich.console import Group as _Group
            from rich.panel import Panel as _Panel
            from rich.text import Text as _Text
            from adscan_core.theme import COLOR_AMBER, COLOR_MUTED
            _diag = _Group(
                _Text.from_markup(
                    f"[bold {COLOR_AMBER}]⚠  DRSUAPI dynamic ports unreachable[/bold {COLOR_AMBER}]"
                ),
                _Text(""),
                _Text.from_markup(
                    f"[{COLOR_MUTED}]DRSUAPI (MS-DRSR) is TCP-only — it uses dynamic RPC ports\n"
                    f"(49152-65535) discovered via the endpoint mapper on port 135.\n"
                    f"Those ports are not reachable from this host to the DC.[/{COLOR_MUTED}]"
                ),
                _Text(""),
                _Text.from_markup(
                    f"[bold]DC[/bold]      {mark_sensitive(pdc_hostname or pdc_ip, 'hostname')}\n"
                    f"[bold]Port 135[/bold]  reachable (EPM responded)\n"
                    f"[bold]Ports 49152+[/bold]  [bold {COLOR_AMBER}]filtered[/bold {COLOR_AMBER}] (timeout after "
                    f"{errors_seen} attempt(s))"
                ),
                _Text(""),
                _Text.from_markup(
                    f"[{COLOR_MUTED}]This is a network constraint, not an ADscan bug or a\n"
                    f"permissions error. DCSync works correctly in production\n"
                    f"domain networks where those ports are accessible.\n\n"
                    f"[bold]Fix:[/bold] verify that ports 49152-65535 are open from\n"
                    f"this host to {mark_sensitive(pdc_hostname or pdc_ip, 'hostname')} (check host/network firewall).\n"
                    f"In restricted VPNs (HTB, some audits) only well-known\n"
                    f"ports are routed — DCSync is not possible from there.[/{COLOR_MUTED}]"
                ),
            )
            from adscan_core.output._state import get_console as _gc
            _gc().print(_Panel(
                _diag,
                title=f"[bold {COLOR_AMBER}]DCSync blocked by network[/bold {COLOR_AMBER}]",
                title_align="left",
                border_style=COLOR_AMBER,
                padding=(1, 2),
            ))
        else:
            print_warning(f"DCSync native: {errors_seen} stream error(s) encountered.")

    if not raw_credentials:
        if errors_seen > 0 and "timeout" in " ".join(_stream_error_types).lower():
            _no_cred_reason = (
                "Dynamic RPC ports (49152-65535) unreachable. "
                "DCSync requires open access to the DC's dynamic port range."
            )
        else:
            _no_cred_reason = (
                f"{errors_seen} stream error(s). Check DCSync rights on "
                f"{mark_sensitive(username, 'user')}."
                if errors_seen > 0
                else None
            )
        if not ("timeout" in " ".join(_stream_error_types).lower() and errors_seen > 0):
            print_warning(
                f"No credentials returned by native DCSync for domain {marked_domain}."
            )
        _offer_machine_account_dump_fallback(
            shell, domain, failure_reason=_no_cred_reason
        )
        return {"krbtgt": False, "tier0_count": 0, "total": 0}

    # ------------------------------------------------------------------ #
    # 3. Post-processing pipeline (credential persistence + cracking + display)
    # ------------------------------------------------------------------ #
    verify_credential = target_user.casefold() != "all"
    creds_to_persist: List[Tuple[str, str]] = []
    display_rows: List[Dict[str, str]] = []

    if verify_credential:
        for acct, nt in raw_credentials:
            md = mark_sensitive(domain, "domain")
            mu = mark_sensitive(acct, "user")
            mh = mark_sensitive(nt, "password")
            print_success(f"Found credential: {md}/{mu} with hash {mh}")

        for acct, nt in raw_credentials:
            cred_to_store = nt
            try:
                cred_to_store, _ = shell._handle_hash_cracking(domain, acct, nt)
            except Exception:
                cred_to_store = nt
            creds_to_persist.append((acct, cred_to_store))
    else:
        from adscan_internal.cli.creds import add_credentials_batch
        from adscan_internal.services.credentials import CredentialMetadata

        # Build per-user metadata up-front so add_credentials_batch can
        # persist privilege-role + Kerberos-key material centrally,
        # rather than every credential source re-implementing tagging.
        metadata_by_user: dict[str, CredentialMetadata] = {}
        for sec in raw_secrets_for_meta:
            try:
                user = (getattr(sec, "username", "") or "").strip()
                if not user:
                    continue
                kkeys = tuple(getattr(sec, "kerberos_keys", ()) or ())
                metadata_by_user[user.lower()] = CredentialMetadata(
                    aes256_key=(getattr(sec, "aes256_key", None) or None),
                    aes128_key=(getattr(sec, "aes128_key", None) or None),
                    kerberos_keys=kkeys,
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)

        creds_to_persist = add_credentials_batch(
            shell=shell,
            domain=domain,
            credentials=raw_credentials,
            skip_hash_cracking=False,
            verify_credential=False,
            prompt_for_user_privs_after=False,
            ensure_fresh_kerberos_ticket=False,
            ui_silent=False,
            metadata_by_user=metadata_by_user,
            # Full DRSUAPI replication (DCSync-All): krbtgt + every user's hash.
            # Tag the provenance so the Compromised Credentials views (web card,
            # report, `creds show`) attribute each account to DCSync instead of
            # rendering an empty/"via unknown" method.
            credential_origin="dcsync",
        )
        _render_dcsync_batch_cracking_summary(
            shell=shell,
            domain=domain,
            credentials=creds_to_persist,
        )
        try:
            created_domain_reuse_edges = _record_dcsync_domain_password_reuse(
                shell,
                domain=domain,
                credentials=raw_credentials,
            )
            if created_domain_reuse_edges > 0:
                md = mark_sensitive(domain, "domain")
                print_info(
                    f"Recorded {created_domain_reuse_edges} DomainPassReuse context step(s) "
                    f"from DCSync-All credentials in {md}."
                )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            md = mark_sensitive(domain, "domain")
            print_warning(
                f"Failed to persist DomainPassReuse context steps from DCSync-All credentials in {md}; continuing."
            )

    # Surface disabled accounts in the summary panel so the operator sees them
    # even though the picker will filter them out at consumption time.
    # krbtgt is excluded from this count — its ACCOUNTDISABLE bit is set by
    # Microsoft design and the account is operationally active.
    disabled_count = sum(
        1
        for acct_key, v in enabled_by_account.items()
        if not v and acct_key != "krbtgt" and rid_by_account.get(acct_key) != 502
    )
    if disabled_count > 0:
        print_info(
            f"   {disabled_count} of {len(enabled_by_account)} extracted accounts "
            "are disabled (filtered from credential picker)"
        )

    for acct, cred_value in creds_to_persist:
        display_rows.append(
            {
                "User": mark_sensitive(acct, "user"),
                "Credential": mark_sensitive(cred_value, "password"),
            }
        )

    # Show the credential table immediately after the success banner so it
    # appears as part of the DCSync narrative — before promote_to_pwned fires
    # the post-compromise flow (which may trigger flag collection and push this
    # output after the flags panel).
    count = len(display_rows)
    if count == 0:
        print_info("No credentials were stored for this DCSync run.")
    else:
        from adscan_internal.services.exploitation.dump_display import (
            ACID_GREEN as _ACID_GREEN_S,
            AMBER as _AMBER_S,
            LAVA as _LAVA_S,
            MUTED as _MUTED_S,
        )
        _priv_count = len(privileged_accounts)
        _aes_count = len(aes_credentials)

        _s_line1 = _RichText()
        _s_line1.append("  Accounts replicated  ", style=_MUTED_S)
        _s_line1.append(str(count), style=f"bold {_ACID_GREEN_S}")

        _s_line2 = _RichText()
        _s_line2.append("  Privileged accounts  ", style=_MUTED_S)
        _s_line2.append(str(_priv_count), style=f"bold {_AMBER_S}")

        _s_line3 = _RichText()
        _s_line3.append("  AES256 keys captured ", style=_MUTED_S)
        _s_line3.append(str(_aes_count), style=_MUTED_S)

        _s_krbtgt = _RichText()
        if krbtgt_found:
            _s_krbtgt.append("  krbtgt hash obtained ", style=_MUTED_S)
            _s_krbtgt.append("YES", style=f"bold {_LAVA_S}")
            _s_krbtgt.append("  (golden ticket forging possible)", style=_MUTED_S)

        _success_body = _RichGroup(
            _RichText(""),
            _s_line1,
            _s_line2,
            _s_line3,
            *((_RichText(""), _s_krbtgt) if krbtgt_found else ()),
            _RichText(""),
        )
        print_panel(
            _success_body,
            title=f"[bold white on {_ACID_GREEN_S}] DCSync Complete [/bold white on {_ACID_GREEN_S}]",
            border_style=_ACID_GREEN_S,
            expand=False,
        )

        if verify_credential and count <= 10:
            print_info_table(
                display_rows,
                ["User", "Credential"],
                title=f"Extracted credentials for domain {mark_sensitive(domain, 'domain')}",
            )

    # Persist credentials into the workspace store BEFORE calling
    # promote_to_pwned.  promote_to_pwned fires _flush_ctf_post_compromise_queue
    # which calls pick_credential_for_local_admin to choose the best credential
    # for flag collection.  If add_credential runs after promote_to_pwned (the
    # old order), the just-extracted Administrator/krbtgt hash is not yet in the
    # map and the picker falls back to a lower-privilege account (wrong creds →
    # ACCESS_DENIED on C$).  Calling add_credential first ensures the picker
    # finds the DA credential and uses it for flags.
    if verify_credential:
        for acct, cred_value in creds_to_persist:
            try:
                shell.add_credential(
                    domain,
                    acct,
                    cred_value,
                    skip_hash_cracking=True,
                    verify_credential=True,
                    # DCSync already announced the credential — suppress the
                    # duplicate verification panel and TGT-generation messages.
                    ui_silent=True,
                    credential_origin="dcsync",
                )
            except Exception as _ac_exc:  # noqa: BLE001
                telemetry.capture_exception(_ac_exc)

    # A full ("all") DRSUAPI walk just replicated the entire NTDS — record it
    # (SSOT marker consumed by the CTF + audit post-compromise pipelines) so the
    # full "all" dump runs EXACTLY ONCE. Set BEFORE the promote_to_pwned calls
    # below fire the post-compromise hook, so that hook sees the flag and skips
    # a redundant re-dump. A targeted dump (``target_users`` set, e.g. the
    # ESC8→DC path extracting just the DA) never sets it, so post-compromise
    # still replicates everything once a DA credential is in hand.
    if not target_users and raw_credentials:
        from adscan_internal.services.domain_compromise_promotion import (
            mark_full_ntds_replicated,
        )

        mark_full_ntds_replicated(shell, domain)

    # Screenshot moment: krbtgt hash extracted = full domain compromise.
    # Augments (does not replace) the print_success above so logs stay
    # backwards-compatible.
    if krbtgt_found:
        try:
            from adscan_core.rich_output_collection import print_da_owned_card

            krbtgt_nt = ""
            for _acct, _nt in raw_credentials:
                if _acct.lower() == "krbtgt":
                    krbtgt_nt = _nt
                    break
            evidence_lines: list[str] = ["Hash extracted via native DCSync (DRSUAPI)"]
            if krbtgt_nt:
                preview = (
                    f"{krbtgt_nt[:8]}…{krbtgt_nt[-4:]}"
                    if len(krbtgt_nt) > 12
                    else krbtgt_nt
                )
                evidence_lines.append(f"NT: {mark_sensitive(preview, 'password')}")
            if "krbtgt" in aes_credentials:
                evidence_lines.append("RC4 + AES256 keys captured")
            evidence_lines.append(
                f"{len(raw_credentials)} accounts replicated "
                f"({len(privileged_accounts)} privileged)"
            )
            print_da_owned_card(
                account="krbtgt",
                domain=domain,
                evidence=evidence_lines,
                method="DCSync (DRSUAPI)",
            )
        except Exception as exc:  # pragma: no cover - presentation must never fail dump
            telemetry.capture_exception(exc)

        # Centralised domain compromise promotion. Idempotent: a no-op
        # when the domain was already promoted via a different vector
        # (Domain Admin membership, NTDS dump, etc.).
        try:
            from adscan_internal.services.domain_compromise_promotion import (
                CompromiseEvidence,
                promote_to_pwned,
            )

            krbtgt_nt_value = ""
            for _a, _n in raw_credentials:
                if _a.lower() == "krbtgt":
                    krbtgt_nt_value = _n
                    break
            promote_to_pwned(
                shell,
                domain=domain,
                evidence=CompromiseEvidence.KRBTGT_HASH_EXTRACTED,
                username="krbtgt",
                credential=krbtgt_nt_value or None,
                evidence_ref="native_dcsync",
            )
        except Exception as _exc:  # noqa: BLE001
            telemetry.capture_exception(_exc)

    # Built-in Administrator hash extracted: Tier 0 evidence even if
    # krbtgt was filtered out. Detection is RID-based (RID 500) so it
    # works in renamed-admin and non-English directories ("Administrador",
    # "Administrateur"). Falls back to a name match only when no SID was
    # available on any row (older parser paths).
    admin_acct_value: str | None = builtin_admin_account
    if admin_acct_value is None and not rid_by_account:
        for _a, _ in raw_credentials:
            if _a.lower() == "administrator":
                admin_acct_value = _a
                break

    admin_nt_value = ""
    if admin_acct_value:
        for _a, _n in raw_credentials:
            if _a == admin_acct_value:
                admin_nt_value = _n
                break

    if admin_acct_value and admin_nt_value:
        try:
            from adscan_internal.services.domain_compromise_promotion import (
                CompromiseEvidence,
                promote_to_pwned,
            )

            promote_to_pwned(
                shell,
                domain=domain,
                evidence=CompromiseEvidence.TIER0_HASH_EXTRACTED,
                username=admin_acct_value,
                credential=admin_nt_value,
                evidence_ref="native_dcsync",
            )
        except Exception as _exc:  # noqa: BLE001
            telemetry.capture_exception(_exc)

    # ── Persist DCSync dump as workspace inventory artefact ─────────────
    # Drives the web app's DCSync Intelligence KPIs (recovery rate,
    # Tier 0 exposure, password reuse clusters, armed attack paths).
    # Plaintext is never persisted — only the boolean recovery flag.
    try:
        from adscan_internal.services.dcsync_inventory_persistence import (
            write_dcsync_dump_file,
        )

        nt_by_acct = {a.lower(): n for a, n in raw_credentials}
        plaintext_users: list[str] = []
        for acct, cred_value in creds_to_persist:
            stored = str(cred_value or "").strip().lower()
            original_nt = nt_by_acct.get(acct.lower(), "").strip().lower()
            # creds_to_persist may have replaced the NT hash with the
            # cracked plaintext — when the stored value differs from
            # the dumped NT hash, we treat plaintext as recovered.
            if stored and original_nt and stored != original_nt:
                plaintext_users.append(acct)
        write_dcsync_dump_file(
            shell,
            domain=domain,
            raw_credentials=raw_credentials,
            plaintext_recovered_users=plaintext_users,
            sid_by_account=sid_by_account,
        )
    except Exception as _exc:  # noqa: BLE001
        telemetry.capture_exception(_exc)
        print_info_debug(f"dcsync-native: inventory dump failed: {_exc}")

    tier0_rids = {500, 512, 518, 519}
    tier0_count = sum(
        1
        for acct, _ in raw_credentials
        if rid_by_account.get(acct.lower()) in tier0_rids
    )
    return {
        "krbtgt": bool(krbtgt_found),
        "tier0_count": int(tier0_count),
        "total": len(raw_credentials),
    }


def _record_dcsync_domain_password_reuse(
    shell: Any,
    *,
    domain: str,
    credentials: list[tuple[str, str]],
) -> int:
    """Record DomainPassReuse context edges from DCSync-All credential material."""
    from adscan_internal.services.attack_graph_service import (
        upsert_domain_password_reuse_edges,
    )

    grouped: dict[str, dict[str, object]] = {}
    for username, credential in credentials:
        user_clean = str(username or "").strip()
        credential_clean = str(credential or "").strip()
        if not user_clean or not credential_clean:
            continue
        key = credential_clean.lower()
        bucket = grouped.setdefault(
            key,
            {"credential": credential_clean, "users": set()},
        )
        users = bucket.get("users")
        if isinstance(users, set):
            users.add(user_clean)

    created_total = 0
    for value in grouped.values():
        users_raw = value.get("users")
        if not isinstance(users_raw, set):
            continue
        usernames = sorted(
            {
                str(user).strip()
                for user in users_raw
                if isinstance(user, str) and str(user).strip()
            },
            key=str.lower,
        )
        if len(usernames) < 2:
            continue
        credential_value = str(value.get("credential") or "").strip()
        if not credential_value:
            continue
        created_total += int(
            upsert_domain_password_reuse_edges(
                shell,
                domain,
                source_usernames=usernames,
                target_usernames=usernames,
                credential=credential_value,
                status="discovered",
                evidence_source="dcsync_all",
            )
            or 0
        )
    return created_total
