"""Generic post-pivot follow-up orchestration for any pivoting technique.

This service handles the operator-facing consequences of a successful pivot:

- refresh current-vantage reachability/service inventories
- compute and render reachability deltas introduced by the pivot
- optionally offer owned-user follow-up actions that now make sense

The service is intentionally decoupled from any specific entry vector such as
WinRM, SMB, RDP, SSH, or from any specific pivot tool such as Ligolo.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from typing import Any

from rich.table import Table

from adscan_internal import print_info, print_info_debug, print_success, telemetry
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.workspaces import domain_subpath
from adscan_internal.workspaces.layout import DEFAULT_DOMAIN_LAYOUT


@dataclass(slots=True, frozen=True)
class PivotExecutionContext:
    """Context describing one successful pivot that changed the current vantage."""

    domain: str
    pivot_host: str
    pivot_method: str
    pivot_tool: str
    source_service: str


@dataclass(slots=True)
class PostPivotRefreshResult:
    """Structured result for one post-pivot network inventory refresh."""

    refreshed: bool
    refreshed_at: str | None = None
    report_path: str | None = None
    newly_reachable_ips: list[dict[str, Any]] | None = None
    newly_reachable_hosts: list[dict[str, Any]] | None = None


def _load_workspace_network_reachability_report(
    shell: Any, *, domain: str
) -> dict[str, Any] | None:
    """Load the persisted current-vantage reachability report for one domain."""
    report_path = os.path.join(
        shell.current_workspace_dir or "",
        shell.domains_dir,
        domain,
        "network_reachability_report.json",
    )
    if not report_path or not os.path.exists(report_path):
        return None
    try:
        with open(report_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _reachable_status_from_report_entry(entry: dict[str, Any]) -> bool:
    """Return whether one reachability-report IP entry is reachable now."""
    status = str(entry.get("status") or "").strip()
    return status in {
        "open_service_observed",
        "host_responded_no_important_ports_open",
        "responded_to_discovery",
    }


def _display_name_for_reachability_entry(entry: dict[str, Any]) -> str:
    """Return one stable, user-facing identifier for one reachability entry."""
    hostname_candidates = entry.get("hostname_candidates", [])
    if isinstance(hostname_candidates, list):
        for candidate in hostname_candidates:
            hostname = str(candidate or "").strip()
            if hostname:
                return hostname
    return str(entry.get("ip") or "").strip()


def _compute_post_pivot_reachability_delta(
    *,
    before_payload: dict[str, Any] | None,
    after_payload: dict[str, Any] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return IP- and host-level reachability deltas introduced by the pivot."""
    before_ips = (
        before_payload.get("ips", []) if isinstance(before_payload, dict) else []
    )
    after_ips = after_payload.get("ips", []) if isinstance(after_payload, dict) else []
    before_map = {
        str(entry.get("ip") or "").strip(): entry
        for entry in before_ips
        if isinstance(entry, dict) and str(entry.get("ip") or "").strip()
    }
    after_map = {
        str(entry.get("ip") or "").strip(): entry
        for entry in after_ips
        if isinstance(entry, dict) and str(entry.get("ip") or "").strip()
    }

    newly_reachable_ips: list[dict[str, Any]] = []
    for ip_value, after_entry in after_map.items():
        if not _reachable_status_from_report_entry(after_entry):
            continue
        before_entry = before_map.get(ip_value)
        if before_entry and _reachable_status_from_report_entry(before_entry):
            continue
        record = dict(after_entry)
        if before_entry:
            record["previous_status"] = str(before_entry.get("status") or "").strip()
            record["previous_classification"] = str(
                before_entry.get("classification") or ""
            ).strip()
        newly_reachable_ips.append(record)

    host_accumulator: dict[str, dict[str, Any]] = {}
    for entry in newly_reachable_ips:
        display_name = _display_name_for_reachability_entry(entry)
        host_record = host_accumulator.setdefault(
            display_name.lower(),
            {
                "display_name": display_name,
                "ips": [],
                "hostname_candidates": entry.get("hostname_candidates", []),
            },
        )
        host_record["ips"].append(
            {
                "ip": str(entry.get("ip") or "").strip(),
                "status": str(entry.get("status") or "").strip(),
                "classification": str(entry.get("classification") or "").strip(),
                "open_ports": list(entry.get("open_ports") or []),
            }
        )

    newly_reachable_hosts = sorted(
        host_accumulator.values(),
        key=lambda item: str(item.get("display_name") or "").lower(),
    )
    newly_reachable_ips.sort(key=lambda item: str(item.get("ip") or "").strip())
    return newly_reachable_ips, newly_reachable_hosts


def render_post_pivot_reachability_delta(
    shell: Any,
    *,
    context: PivotExecutionContext,
    refresh_result: PostPivotRefreshResult,
) -> None:
    """Render a concise UX summary for hosts unlocked by one successful pivot."""
    new_hosts = refresh_result.newly_reachable_hosts or []
    new_ips = refresh_result.newly_reachable_ips or []
    if not new_hosts:
        print_info(
            "Post-pivot inventory refresh completed, but no additional reachable hosts were discovered."
        )
        return

    print_success(
        f"The {mark_sensitive(context.pivot_tool, 'text')} pivot through "
        f"{mark_sensitive(context.pivot_host, 'hostname')} unlocked "
        f"{len(new_hosts)} newly reachable host(s) / {len(new_ips)} IP(s) in "
        f"{mark_sensitive(context.domain, 'domain')}."
    )
    if getattr(shell, "console", None):
        table = Table(title="Newly Reachable Hosts After Pivot", box=None)
        table.add_column("Host")
        table.add_column("New IPs")
        table.add_column("Open Ports")
        table.add_column("Status")
        for host_entry in new_hosts[:10]:
            ips = host_entry.get("ips", [])
            ip_values = ", ".join(
                mark_sensitive(str(item.get("ip") or ""), "ip")
                for item in ips
                if str(item.get("ip") or "").strip()
            ) or "-"
            open_ports = sorted(
                {
                    str(port)
                    for item in ips
                    for port in (item.get("open_ports") or [])
                    if str(port).strip()
                }
            )
            statuses = sorted(
                {
                    str(item.get("classification") or item.get("status") or "").strip()
                    for item in ips
                    if str(item.get("classification") or item.get("status") or "").strip()
                }
            )
            table.add_row(
                mark_sensitive(str(host_entry.get("display_name") or ""), "hostname"),
                ip_values,
                ", ".join(open_ports) or "-",
                ", ".join(mark_sensitive(status, "text") for status in statuses) or "-",
            )
        shell.console.print(table)
    if len(new_hosts) > 10:
        print_info(
            f"Showing the first 10 unlocked hosts. Total newly reachable hosts: {len(new_hosts)}."
        )
    print_info_debug(
        "[post-pivot] reachability delta: "
        f"domain={mark_sensitive(context.domain, 'domain')} "
        f"pivot_host={mark_sensitive(context.pivot_host, 'hostname')} "
        f"pivot_method={mark_sensitive(context.pivot_method, 'text')} "
        f"new_hosts={len(new_hosts)} new_ips={len(new_ips)}"
    )


def _run_owned_user_followup_after_pivot(shell: Any, *, domain: str) -> None:
    """Re-run owned-user attack-path and post-auth service/share follow-up flows."""
    from adscan_internal.cli.attack_path_execution import (
        offer_attack_paths_with_non_high_value_fallback,
    )
    from adscan_internal.cli.privileges import run_service_access_sweep
    from adscan_internal.services.attack_graph_service import (
        ATTACK_PATHS_MAX_DEPTH_USER,
        get_owned_domain_usernames_for_attack_paths,
    )

    credentials = shell.domains_data.get(domain, {}).get("credentials", {})
    owned_users = get_owned_domain_usernames_for_attack_paths(shell, domain)
    if not owned_users:
        print_info(
            "No owned domain users are stored yet, so no post-pivot owned-user follow-up was run."
        )
        return

    print_info(
        "Re-checking attack paths from owned users now that the pivot expanded current-vantage reachability."
    )
    offer_attack_paths_with_non_high_value_fallback(
        shell,
        domain,
        start="owned",
        max_depth=ATTACK_PATHS_MAX_DEPTH_USER,
        max_display=20,
        target="all",
        target_mode="tier0",
    )

    eligible_users: list[tuple[str, str]] = []
    skipped_hash_only: list[str] = []
    if isinstance(credentials, dict):
        for username in owned_users:
            secret = str(credentials.get(username) or "").strip()
            if not secret:
                continue
            if shell.is_hash(secret):
                skipped_hash_only.append(username)
                continue
            eligible_users.append((username, secret))

    if skipped_hash_only:
        print_info_debug(
            "[post-pivot] owned-user service/share follow-up skipped hash-only users: "
            f"domain={mark_sensitive(domain, 'domain')} "
            f"users={', '.join(mark_sensitive(user, 'user') for user in skipped_hash_only)}"
        )

    if not eligible_users:
        print_info(
            "No owned users with cleartext domain credentials are available for post-auth service/share follow-up."
        )
        return

    selected_users = eligible_users
    checkbox = getattr(shell, "_questionary_checkbox", None)
    if callable(checkbox):
        options: list[str] = []
        option_to_user: dict[str, tuple[str, str]] = {}
        for index, (username, secret) in enumerate(eligible_users, start=1):
            label = f"{index}. {mark_sensitive(username, 'user')}"
            options.append(label)
            option_to_user[label] = (username, secret)
        selected_labels = checkbox(
            "Select owned users for post-pivot service/share follow-up:",
            options,
            default_values=list(options),
        )
        if selected_labels is None:
            print_info("Skipping post-pivot service/share follow-up by user choice.")
            return
        selected_users = [
            option_to_user[label]
            for label in selected_labels
            if label in option_to_user
        ]

    if not selected_users:
        print_info("No owned users selected for post-pivot service/share follow-up.")
        return

    print_info(
        f"Running post-pivot service/share follow-up for {len(selected_users)} owned user(s)."
    )
    for username, secret in selected_users:
        run_service_access_sweep(
            shell,
            domain=domain,
            username=username,
            password=secret,
            services=["smb", "winrm", "rdp", "mssql"],
            hosts=None,
            prompt=False,
            scope_preference="optimized",
        )


def maybe_offer_post_pivot_owned_followup(
    shell: Any,
    *,
    context: PivotExecutionContext,
    refresh_result: PostPivotRefreshResult,
) -> None:
    """Offer a high-value owned-user follow-up when the pivot unlocked multiple hosts."""
    from rich.prompt import Confirm

    new_hosts = refresh_result.newly_reachable_hosts or []
    if len(new_hosts) <= 1:
        return

    prompt = (
        f"The pivot through {mark_sensitive(context.pivot_host, 'hostname')} unlocked "
        f"{len(new_hosts)} new reachable hosts. Re-check attack paths from owned users "
        "and run post-auth service/share follow-up now?"
    )
    confirmer = getattr(shell, "_questionary_confirm", None)
    if callable(confirmer):
        should_run = bool(confirmer(prompt, default=True))
    else:
        should_run = bool(Confirm.ask(prompt, default=True))

    if not should_run:
        print_info("Skipping post-pivot owned-user follow-up by user choice.")
        return
    _run_owned_user_followup_after_pivot(shell, domain=context.domain)


def refresh_network_inventory_after_pivot(
    shell: Any,
    *,
    context: PivotExecutionContext,
) -> PostPivotRefreshResult:
    """Refresh current-vantage reachability/service inventories after a pivot."""
    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "").strip()
    if not workspace_dir:
        print_info_debug(
            "Skipping post-pivot network inventory refresh: no active workspace is loaded."
        )
        return PostPivotRefreshResult(refreshed=False)

    refresh_callable = getattr(shell, "convert_hostnames_to_ips_and_scan", None)
    if not callable(refresh_callable):
        print_info_debug(
            "Skipping post-pivot network inventory refresh: shell does not expose convert_hostnames_to_ips_and_scan()."
        )
        return PostPivotRefreshResult(refreshed=False)

    computers_file = domain_subpath(
        workspace_dir,
        shell.domains_dir,
        context.domain,
        "enabled_computers.txt",
    )
    if not os.path.exists(computers_file):
        print_info_debug(
            "Skipping post-pivot network inventory refresh: "
            f"{mark_sensitive(computers_file, 'path')} is missing."
        )
        return PostPivotRefreshResult(refreshed=False)

    nmap_dir = domain_subpath(
        workspace_dir,
        shell.domains_dir,
        context.domain,
        DEFAULT_DOMAIN_LAYOUT.nmap,
    )
    before_payload = _load_workspace_network_reachability_report(
        shell, domain=context.domain
    )
    print_info(
        "Refreshing current-vantage reachability and service inventories after the pivot came up."
    )
    print_info_debug(
        "[post-pivot] inventory refresh: "
        f"domain={mark_sensitive(context.domain, 'domain')} "
        f"pivot_host={mark_sensitive(context.pivot_host, 'hostname')} "
        f"pivot_method={mark_sensitive(context.pivot_method, 'text')} "
        f"pivot_tool={mark_sensitive(context.pivot_tool, 'text')} "
        f"source_service={mark_sensitive(context.source_service, 'text')} "
        f"computers_file={mark_sensitive(computers_file, 'path')} "
        f"nmap_dir={mark_sensitive(nmap_dir, 'path')}"
    )
    try:
        refresh_callable(context.domain, computers_file, nmap_dir)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info(
            "The pivot was established, but the automatic current-vantage inventory refresh failed."
        )
        print_info_debug(
            "[post-pivot] inventory refresh failed: "
            f"{mark_sensitive(str(exc), 'detail')}"
        )
        return PostPivotRefreshResult(refreshed=False)

    refreshed_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    domain_state = shell.domains_data.setdefault(context.domain, {})
    if not isinstance(domain_state, dict):
        domain_state = {}
        shell.domains_data[context.domain] = domain_state
    after_payload = _load_workspace_network_reachability_report(
        shell, domain=context.domain
    )
    newly_reachable_ips, newly_reachable_hosts = _compute_post_pivot_reachability_delta(
        before_payload=before_payload,
        after_payload=after_payload,
    )
    domain_state["network_vantage"] = {
        "mode": "pivot_assisted",
        "pivot_host": context.pivot_host,
        "refresh_source": context.pivot_method,
        "pivot_tool": context.pivot_tool,
        "source_service": context.source_service,
        "refreshed_at": refreshed_at,
        "newly_reachable_host_count": len(newly_reachable_hosts),
        "newly_reachable_ip_count": len(newly_reachable_ips),
    }

    report_path = domain_subpath(
        workspace_dir,
        shell.domains_dir,
        context.domain,
        "network_reachability_report.json",
    )
    try:
        if os.path.exists(report_path):
            with open(report_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            if isinstance(payload, dict):
                payload["vantage"] = {
                    "mode": "pivot_assisted",
                    "pivot_host": context.pivot_host,
                    "refresh_source": context.pivot_method,
                    "pivot_tool": context.pivot_tool,
                    "source_service": context.source_service,
                    "refreshed_at": refreshed_at,
                    "newly_reachable_host_count": len(newly_reachable_hosts),
                    "newly_reachable_ip_count": len(newly_reachable_ips),
                }
                with open(report_path, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, indent=2, sort_keys=False)
                    handle.write("\n")
    except (OSError, json.JSONDecodeError) as exc:
        telemetry.capture_exception(exc)
        print_info_debug(
            "[post-pivot] failed to annotate network reachability report with pivot vantage metadata: "
            f"{mark_sensitive(str(exc), 'detail')}"
        )

    save_workspace_data = getattr(shell, "save_workspace_data", None)
    if callable(save_workspace_data):
        try:
            save_workspace_data()
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                "[post-pivot] failed to persist workspace data after pivot refresh: "
                f"{mark_sensitive(str(exc), 'detail')}"
            )
    return PostPivotRefreshResult(
        refreshed=True,
        refreshed_at=refreshed_at,
        report_path=report_path if os.path.exists(report_path) else None,
        newly_reachable_ips=newly_reachable_ips,
        newly_reachable_hosts=newly_reachable_hosts,
    )
