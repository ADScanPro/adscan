"""Refresh and assess current-vantage inventory freshness.

This service keeps "current-vantage" reachability artifacts honest even when no
pivot was involved. In real audits, reachable hosts and exposed ports drift
over time and change after operators receive access to additional VLANs.

Design contract (post-2026-05 redesign):

- The 24h staleness threshold and 12h prompt cooldown are no longer used to
  gate user-facing behavior. The workspace-load flow ALWAYS renders the
  inventory status banner and ALWAYS prompts (default ``No``) when in audit
  mode. The two constants remain exported for backward compat.
- Diff history (added/removed hosts, opened/closed ports) is owned by
  :mod:`adscan_internal.services.inventory_timeline_service`. After every
  successful refresh we record a snapshot there. Workspace-load always shows
  the cumulative diff against the operator's ``inventory_last_seen`` marker
  before asking whether to refresh.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from typing import Any

from rich.prompt import Confirm

from adscan_internal import telemetry
from adscan_internal.interaction import is_non_interactive
from adscan_internal.rich_output import (
    mark_sensitive,
    print_info,
    print_info_debug,
    print_instruction,
    print_success,
    print_warning,
)
from adscan_internal.services.domain_connectivity_service import (
    reconcile_domain_connectivity_from_current_vantage_report,
)
from adscan_internal.services.inventory_timeline_service import (
    TRIGGER_MANUAL_REFRESH_INVENTORY,
    TRIGGER_WORKSPACE_LOAD_REFRESH,
    diff_against_last_seen,
    is_timeline_enabled,
    mark_diff_seen,
    record_inventory_snapshot,
    render_inventory_diff,
    render_inventory_status_banner,
)
from adscan_internal.services.post_pivot_followup_service import (
    maybe_offer_trust_followup_for_newly_reachable_domains,
)
from adscan_core.rich_output import print_exception

CURRENT_VANTAGE_INVENTORY_STALE_AFTER_SECONDS = 24 * 60 * 60
CURRENT_VANTAGE_INVENTORY_PROMPT_COOLDOWN_SECONDS = 12 * 60 * 60


@dataclass(frozen=True, slots=True)
class CurrentVantageInventoryStatus:
    """Freshness assessment for one domain's current-vantage inventory."""

    domain: str
    enabled_computers_file: str
    reachability_report_file: str
    report_exists: bool
    generated_at: str | None
    age_seconds: float | None
    stale: bool
    reason: str
    reachable_ip_count: int | None
    no_response_ip_count: int | None
    total_ip_count: int | None
    important_port_scan_performed: bool | None


def _workspace_dir(shell: Any) -> str:
    return str(getattr(shell, "current_workspace_dir", "") or "").strip()


def _domains_dir(shell: Any) -> str:
    return (
        str(getattr(shell, "domains_dir", "domains") or "domains").strip() or "domains"
    )


def _report_path(shell: Any, *, domain: str) -> str:
    return os.path.join(
        _workspace_dir(shell),
        _domains_dir(shell),
        domain,
        "network_reachability_report.json",
    )


def _enabled_computers_path(shell: Any) -> str:
    return os.path.join(_workspace_dir(shell), "enabled_computers.txt")


def _nmap_dir(shell: Any, *, domain: str) -> str:
    return os.path.join(_workspace_dir(shell), _domains_dir(shell), domain, "nmap")


def _parse_iso8601_timestamp(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _resolve_report_generated_at(report_path: str) -> tuple[str | None, float | None]:
    """Return ``generated_at`` and age in seconds for one persisted report."""

    if not report_path or not os.path.exists(report_path):
        return None, None

    generated_at: str | None = None
    try:
        with open(report_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if isinstance(payload, dict):
            value = str(payload.get("generated_at") or "").strip()
            generated_at = value or None
    except (OSError, json.JSONDecodeError):
        generated_at = None

    if generated_at:
        parsed = _parse_iso8601_timestamp(generated_at)
        if parsed is not None:
            age = max((datetime.now(timezone.utc) - parsed).total_seconds(), 0.0)
            return generated_at, age

    try:
        mtime = os.path.getmtime(report_path)
    except OSError:
        return generated_at, None
    parsed_mtime = datetime.fromtimestamp(mtime, tz=timezone.utc)
    return parsed_mtime.replace(microsecond=0).isoformat(), max(
        (datetime.now(timezone.utc) - parsed_mtime).total_seconds(),
        0.0,
    )


def _load_report_summary(report_path: str) -> dict[str, object]:
    if not report_path or not os.path.exists(report_path):
        return {}
    try:
        with open(report_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    summary = payload.get("summary", {})
    return summary if isinstance(summary, dict) else {}


def _domain_inventory_freshness_state(shell: Any, *, domain: str) -> dict[str, Any]:
    """Return mutable per-domain bookkeeping dict (kept for backwards compat)."""

    domains_data = getattr(shell, "domains_data", {})
    if not isinstance(domains_data, dict):
        return {}
    domain_state = domains_data.setdefault(domain, {})
    if not isinstance(domain_state, dict):
        return {}
    freshness_state = domain_state.setdefault("inventory_freshness", {})
    return freshness_state if isinstance(freshness_state, dict) else {}


def _record_refresh_metadata(shell: Any, *, domain: str, reason: str) -> None:
    """Persist the most recent refresh event for one domain (informational)."""

    freshness_state = _domain_inventory_freshness_state(shell, domain=domain)
    freshness_state["last_refreshed_at"] = (
        datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    )
    freshness_state["last_refresh_reason"] = reason
    saver = getattr(shell, "save_workspace_data", None)
    if callable(saver):
        try:
            saver()
        except Exception as exc:  # noqa: BLE001
            print_info_debug(
                "[current-vantage-refresh] failed to persist refresh metadata for "
                f"{mark_sensitive(domain, 'domain')}: {exc}"
            )


def list_current_vantage_inventory_statuses(
    shell: Any,
) -> list[CurrentVantageInventoryStatus]:
    """Return freshness status for every domain that can be refreshed."""

    workspace_dir = _workspace_dir(shell)
    if not workspace_dir:
        return []
    enabled_path = _enabled_computers_path(shell)
    if not os.path.exists(enabled_path):
        return []

    domains: list[str] = []
    domains_data = getattr(shell, "domains_data", {})
    if isinstance(domains_data, dict):
        domains.extend(
            str(domain).strip() for domain in domains_data.keys() if str(domain).strip()
        )
    current_domain = str(getattr(shell, "current_domain", "") or "").strip()
    if current_domain and current_domain not in domains:
        domains.append(current_domain)

    statuses: list[CurrentVantageInventoryStatus] = []
    for domain in sorted(set(domains), key=str.lower):
        report_path = _report_path(shell, domain=domain)
        report_exists = os.path.exists(report_path)
        if not report_exists:
            statuses.append(
                CurrentVantageInventoryStatus(
                    domain=domain,
                    enabled_computers_file=enabled_path,
                    reachability_report_file=report_path,
                    report_exists=False,
                    generated_at=None,
                    age_seconds=None,
                    stale=True,
                    reason="missing_reachability_report",
                    reachable_ip_count=None,
                    no_response_ip_count=None,
                    total_ip_count=None,
                    important_port_scan_performed=None,
                )
            )
            continue
        generated_at, age_seconds = _resolve_report_generated_at(report_path)
        summary = _load_report_summary(report_path)
        is_stale = (
            age_seconds is None
            or age_seconds >= CURRENT_VANTAGE_INVENTORY_STALE_AFTER_SECONDS
        )
        statuses.append(
            CurrentVantageInventoryStatus(
                domain=domain,
                enabled_computers_file=enabled_path,
                reachability_report_file=report_path,
                report_exists=True,
                generated_at=generated_at,
                age_seconds=age_seconds,
                stale=is_stale,
                reason="stale_reachability_report"
                if is_stale
                else "fresh_reachability_report",
                reachable_ip_count=(
                    int(summary["responsive_ips"])
                    if isinstance(summary.get("responsive_ips"), int)
                    else None
                ),
                no_response_ip_count=(
                    int(summary["no_response_ips"])
                    if isinstance(summary.get("no_response_ips"), int)
                    else None
                ),
                total_ip_count=(
                    int(summary["total_ips"])
                    if isinstance(summary.get("total_ips"), int)
                    else None
                ),
                important_port_scan_performed=(
                    bool(summary.get("important_port_scan_performed"))
                    if "important_port_scan_performed" in summary
                    else None
                ),
            )
        )
    return statuses


def _trigger_for_reason(reason: str) -> str:
    """Map a refresh reason to a timeline trigger constant."""

    text = str(reason or "").strip().lower()
    if "manual" in text or "command" in text:
        return TRIGGER_MANUAL_REFRESH_INVENTORY
    return TRIGGER_WORKSPACE_LOAD_REFRESH


def refresh_current_vantage_inventory(
    shell: Any,
    *,
    domain: str,
    reason: str,
) -> bool:
    """Refresh one domain's current-vantage reachability/service inventory."""

    refresh_callable = getattr(shell, "convert_hostnames_to_ips_and_scan", None)
    if not callable(refresh_callable):
        print_warning(
            "Skipping current-vantage inventory refresh because the shell does not expose "
            "convert_hostnames_to_ips_and_scan()."
        )
        return False

    domain = str(domain or "").strip()
    if not domain:
        print_warning(
            "Skipping current-vantage inventory refresh because no domain was provided."
        )
        return False

    computers_file = _enabled_computers_path(shell)
    if not os.path.exists(computers_file):
        print_warning(
            "Skipping current-vantage inventory refresh because enabled_computers.txt is missing."
        )
        return False

    try:
        domains_data = getattr(shell, "domains_data", {})
        domain_data = (
            domains_data.get(domain, {}) if isinstance(domains_data, dict) else {}
        )
        pdc_ip = (
            str(domain_data.get("pdc") or "").strip()
            if isinstance(domain_data, dict)
            else ""
        )
        dns_checker = getattr(shell, "do_check_dns", None)
        dns_updater = getattr(shell, "do_update_resolv_conf", None)
        if pdc_ip and callable(dns_checker) and not bool(dns_checker(domain, pdc_ip)):
            if callable(dns_updater):
                print_info(
                    f"DNS validation for {mark_sensitive(domain, 'domain')} no longer matches the saved PDC. Repairing resolver context before refresh."
                )
                dns_updater(f"{domain} {pdc_ip}")
    except Exception as exc:  # noqa: BLE001
        print_info_debug(
            f"[current-vantage-refresh] DNS preflight failed for {mark_sensitive(domain, 'domain')}: {exc}"
        )

    marked_domain = mark_sensitive(domain, "domain")
    print_info(
        f"Refreshing current-vantage reachability and service inventories for {marked_domain}."
    )
    print_info_debug(
        "[current-vantage-refresh] "
        f"reason={mark_sensitive(reason, 'detail')} "
        f"computers_file={mark_sensitive(computers_file, 'path')} "
        f"nmap_dir={mark_sensitive(_nmap_dir(shell, domain=domain), 'path')}"
    )
    try:
        refresh_callable(domain, computers_file, _nmap_dir(shell, domain=domain))
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_warning(
            f"The current-vantage inventory refresh for {marked_domain} failed."
        )
        print_info_debug(
            f"[current-vantage-refresh] exception for {marked_domain}: {exc}"
        )
        return False

    refreshed_report = _report_path(shell, domain=domain)
    if os.path.exists(refreshed_report):
        try:
            record_inventory_snapshot(
                shell,
                domain=domain,
                trigger=_trigger_for_reason(reason),
                trigger_detail=reason,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(
                f"[current-vantage-refresh] failed to record inventory snapshot for {marked_domain}: {exc}"
            )

        _record_refresh_metadata(shell, domain=domain, reason=reason)

        newly_reachable_domains = (
            reconcile_domain_connectivity_from_current_vantage_report(
                shell,
                source_domain=domain,
            )
        )
        if newly_reachable_domains:
            print_info_debug(
                "[current-vantage-refresh] reconciled inter-domain connectivity from refreshed report: "
                f"domain={mark_sensitive(domain, 'domain')} "
                f"updated={len(newly_reachable_domains)}"
            )
            if not is_non_interactive(shell=shell) and not bool(
                getattr(shell, "auto", False)
            ):
                maybe_offer_trust_followup_for_newly_reachable_domains(
                    shell,
                    source_domain=domain,
                    newly_reachable_domains=newly_reachable_domains,
                    title="Trusted Domains Now Reachable",
                    lead_lines=[
                        "The refreshed current-vantage inventory unlocked additional trusted-domain reachability.",
                    ],
                    prompt=(
                        "Do you want ADscan to continue trust-driven authenticated enumeration "
                        f"from {mark_sensitive(domain, 'domain')} now?"
                    ),
                )
        print_success(
            f"Current-vantage inventory refresh completed for {marked_domain}."
        )
        return True

    print_warning(
        f"Current-vantage refresh for {marked_domain} completed without writing a reachability report."
    )
    return False


def maybe_offer_workspace_current_vantage_refresh(
    shell: Any,
    *,
    trigger: str,
) -> list[str]:
    """Render banner + cumulative diffs and prompt the operator to refresh now.

    The audit-mode contract is now: always render banner, always render any
    pending diffs against the last viewed snapshot, then ask once with default
    ``No``. There is no skip cooldown — the operator gets fresh context every
    workspace load.
    """

    statuses = list_current_vantage_inventory_statuses(shell)
    if not statuses:
        return []

    pending_diffs: dict[str, Any] = {}
    if is_timeline_enabled(shell):
        for status in statuses:
            try:
                diff = diff_against_last_seen(shell, domain=status.domain)
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                print_info_debug(
                    "[current-vantage-refresh] failed to compute pending diff for "
                    f"{mark_sensitive(status.domain, 'domain')}: {exc}"
                )
                diff = None
            if diff is not None:
                pending_diffs[status.domain] = diff

    render_inventory_status_banner(
        shell,
        statuses=statuses,
        pending_diffs=pending_diffs,
    )

    # Render the per-domain diffs before prompting so the operator has full
    # context when deciding whether to refresh now.
    for status in statuses:
        diff = pending_diffs.get(status.domain)
        if diff is None or diff.is_empty:
            continue
        try:
            render_inventory_diff(
                shell,
                diff=diff,
                title=f"What changed in {status.domain} since you last opened this workspace",
            )
            mark_diff_seen(shell, domain=status.domain, snapshot_id=diff.after_id)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(
                "[current-vantage-refresh] failed to render diff for "
                f"{mark_sensitive(status.domain, 'domain')}: {exc}"
            )

    workspace_type = str(getattr(shell, "type", "") or "").strip().lower()
    if workspace_type and workspace_type != "audit":
        print_info_debug(
            "[current-vantage-refresh] skipping workspace-load prompt because "
            f"workspace type is {mark_sensitive(workspace_type, 'detail')}."
        )
        return []

    if is_non_interactive(shell=shell) or bool(getattr(shell, "auto", False)):
        print_info_debug(
            "[current-vantage-refresh] skipping workspace-load prompt because the session is non-interactive/auto."
        )
        return []

    confirmer = getattr(shell, "_questionary_confirm", None)
    prompt = "Refresh current-vantage inventory now?"
    should_refresh = (
        bool(confirmer(prompt, default=False))
        if callable(confirmer)
        else bool(Confirm.ask(prompt, default=False))
    )
    if not should_refresh:
        print_info("Skipping current-vantage inventory refresh by user choice.")
        print_instruction(
            "Run `refresh_inventory <domain>` later if you want to revalidate current-vantage reachability."
        )
        return []

    selected_statuses = statuses
    selected_domains = [status.domain for status in selected_statuses]
    checkbox = getattr(shell, "_questionary_checkbox", None)
    if len(selected_statuses) > 1 and callable(checkbox):
        options = [
            f"{status.domain} | "
            f"{'missing report' if not status.report_exists else 'has report'}"
            for status in selected_statuses
        ]
        selected_labels = checkbox(
            "Select domains whose current-vantage inventory should be refreshed now:",
            options,
            default_values=list(options),
        )
        if not selected_labels:
            print_info("Skipping current-vantage inventory refresh by user choice.")
            return []
        selected_domains = [
            status.domain
            for status, label in zip(selected_statuses, options, strict=False)
            if label in selected_labels
        ]

    refreshed_domains: list[str] = []
    for domain in selected_domains:
        if refresh_current_vantage_inventory(
            shell,
            domain=domain,
            reason=f"{trigger}:inventory_prompt",
        ):
            refreshed_domains.append(domain)
    return refreshed_domains


def refresh_current_vantage_inventory_for_all_domains(
    shell: Any,
    *,
    reason: str,
) -> list[str]:
    """Refresh every known domain in the active workspace, returning successes."""

    domains_data = getattr(shell, "domains_data", {})
    domains: list[str] = []
    if isinstance(domains_data, dict):
        domains.extend(
            str(domain).strip() for domain in domains_data.keys() if str(domain).strip()
        )
    current_domain = str(getattr(shell, "current_domain", "") or "").strip()
    if current_domain and current_domain not in domains:
        domains.append(current_domain)

    refreshed: list[str] = []
    for domain in sorted(set(domains), key=str.lower):
        if refresh_current_vantage_inventory(shell, domain=domain, reason=reason):
            refreshed.append(domain)
    return refreshed


__all__ = [
    "CURRENT_VANTAGE_INVENTORY_STALE_AFTER_SECONDS",
    "CURRENT_VANTAGE_INVENTORY_PROMPT_COOLDOWN_SECONDS",
    "CurrentVantageInventoryStatus",
    "list_current_vantage_inventory_statuses",
    "maybe_offer_workspace_current_vantage_refresh",
    "refresh_current_vantage_inventory",
    "refresh_current_vantage_inventory_for_all_domains",
]
