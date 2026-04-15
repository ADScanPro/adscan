"""Refresh and assess current-vantage inventory freshness.

This service keeps "current-vantage" reachability artifacts honest even when no
pivot was involved. In real audits, reachable hosts and exposed ports can drift
over time or change after operators receive access to additional VLANs/subnets.

The service provides:

- stale/missing report assessment per domain
- a manual refresh primitive that reuses ``convert_hostnames_to_ips_and_scan``
- an optional workspace-load UX that offers refreshing only the current-vantage
  inventory without rerunning full Phase 1
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
    print_panel,
    print_success,
    print_warning,
)
from adscan_internal.services.domain_connectivity_service import (
    reconcile_domain_connectivity_from_current_vantage_report,
)
from adscan_internal.services.post_pivot_followup_service import (
    maybe_offer_trust_followup_for_newly_reachable_domains,
)

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
    """Return the current workspace root for the active shell."""

    return str(getattr(shell, "current_workspace_dir", "") or "").strip()


def _domains_dir(shell: Any) -> str:
    """Return the domains directory name used inside the workspace."""

    return str(getattr(shell, "domains_dir", "domains") or "domains").strip() or "domains"


def _report_path(shell: Any, *, domain: str) -> str:
    """Return the persisted current-vantage reachability report path."""

    return os.path.join(
        _workspace_dir(shell),
        _domains_dir(shell),
        domain,
        "network_reachability_report.json",
    )


def _enabled_computers_path(shell: Any) -> str:
    """Return the enabled computers inventory path for the workspace."""

    return os.path.join(_workspace_dir(shell), "enabled_computers.txt")


def _nmap_dir(shell: Any, *, domain: str) -> str:
    """Return the per-domain Nmap artifact directory."""

    return os.path.join(_workspace_dir(shell), _domains_dir(shell), domain, "nmap")


def _parse_iso8601_timestamp(value: str) -> datetime | None:
    """Parse one ISO-8601 timestamp into an aware ``datetime`` when possible."""

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
    """Return report ``generated_at`` and age in seconds.

    Newer workspaces persist ``generated_at`` in the JSON payload. Older ones do
    not, so we fall back to the report file's mtime to avoid a migration step.
    """

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
    """Return the persisted reachability report summary when available."""

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


def _format_age(age_seconds: float | None) -> str:
    """Return a concise age string for operator-facing summaries."""

    if age_seconds is None:
        return "unknown"
    total_seconds = int(max(age_seconds, 0.0))
    if total_seconds < 60:
        return f"{total_seconds}s"
    total_minutes, seconds = divmod(total_seconds, 60)
    if total_minutes < 60:
        return f"{total_minutes}m {seconds}s"
    total_hours, minutes = divmod(total_minutes, 60)
    if total_hours < 24:
        return f"{total_hours}h {minutes}m"
    total_days, hours = divmod(total_hours, 24)
    return f"{total_days}d {hours}h"


def _domain_inventory_freshness_state(shell: Any, *, domain: str) -> dict[str, Any]:
    """Return mutable per-domain prompt state for current-vantage freshness UX."""

    domains_data = getattr(shell, "domains_data", {})
    if not isinstance(domains_data, dict):
        return {}
    domain_state = domains_data.setdefault(domain, {})
    if not isinstance(domain_state, dict):
        return {}
    freshness_state = domain_state.setdefault("inventory_freshness", {})
    return freshness_state if isinstance(freshness_state, dict) else {}


def _age_seconds_from_iso8601(value: str | None) -> float | None:
    """Return elapsed seconds from one persisted ISO-8601 timestamp."""

    parsed = _parse_iso8601_timestamp(str(value or "").strip())
    if parsed is None:
        return None
    return max((datetime.now(timezone.utc) - parsed).total_seconds(), 0.0)


def _record_prompt_decision(shell: Any, *, domain: str, decision: str) -> None:
    """Persist the latest workspace-load prompt decision for one domain."""

    freshness_state = _domain_inventory_freshness_state(shell, domain=domain)
    freshness_state["last_prompted_at"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    freshness_state["last_prompt_decision"] = decision
    saver = getattr(shell, "save_workspace_data", None)
    if callable(saver):
        try:
            saver()
        except Exception as exc:  # noqa: BLE001
            print_info_debug(
                "[current-vantage-refresh] failed to persist prompt decision for "
                f"{mark_sensitive(domain, 'domain')}: {exc}"
            )


def _should_prompt_for_domain(shell: Any, *, status: CurrentVantageInventoryStatus) -> bool:
    """Return whether audit-mode workspace load should prompt for this domain now."""

    freshness_state = _domain_inventory_freshness_state(shell, domain=status.domain)
    last_prompted_at = str(freshness_state.get("last_prompted_at") or "").strip()
    last_prompt_decision = str(freshness_state.get("last_prompt_decision") or "").strip().lower()
    prompt_age = _age_seconds_from_iso8601(last_prompted_at)
    if prompt_age is None:
        return True
    if last_prompt_decision != "skip":
        return True
    return prompt_age >= CURRENT_VANTAGE_INVENTORY_PROMPT_COOLDOWN_SECONDS


def _render_stale_inventory_banner(statuses: list[CurrentVantageInventoryStatus]) -> None:
    """Render a compact stale inventory banner for workspace load UX."""

    if not statuses:
        return
    lines: list[str] = []
    for status in statuses:
        if status.reason == "missing_reachability_report":
            detail = "missing report"
        else:
            parts = [f"last refresh {mark_sensitive(_format_age(status.age_seconds), 'detail')} ago"]
            if status.reachable_ip_count is not None:
                parts.append(f"reachable={mark_sensitive(str(status.reachable_ip_count), 'detail')}")
            if status.no_response_ip_count is not None:
                parts.append(f"no-response={mark_sensitive(str(status.no_response_ip_count), 'detail')}")
            if status.total_ip_count is not None:
                parts.append(f"total={mark_sensitive(str(status.total_ip_count), 'detail')}")
            detail = " | ".join(parts)
        lines.append(f"{mark_sensitive(status.domain, 'domain')}: {detail}")

    print_panel(
        "\n".join(
            [
                "Current-vantage inventory may be stale for the domains below:",
                "",
                *lines,
                "",
                "Use `refresh_inventory <domain>` or `refresh_inventory all` to revalidate reachability and service target files.",
            ]
        ),
        title="Current-Vantage Inventory Status",
        border_style="yellow",
        expand=False,
    )


def list_current_vantage_inventory_statuses(shell: Any) -> list[CurrentVantageInventoryStatus]:
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
        domains.extend(str(domain).strip() for domain in domains_data.keys() if str(domain).strip())
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
            age_seconds is None or age_seconds >= CURRENT_VANTAGE_INVENTORY_STALE_AFTER_SECONDS
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
                reason="stale_reachability_report" if is_stale else "fresh_reachability_report",
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
        print_warning("Skipping current-vantage inventory refresh because no domain was provided.")
        return False

    computers_file = _enabled_computers_path(shell)
    if not os.path.exists(computers_file):
        print_warning(
            "Skipping current-vantage inventory refresh because enabled_computers.txt is missing."
        )
        return False

    try:
        domains_data = getattr(shell, "domains_data", {})
        domain_data = domains_data.get(domain, {}) if isinstance(domains_data, dict) else {}
        pdc_ip = str(domain_data.get("pdc") or "").strip() if isinstance(domain_data, dict) else ""
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
        print_warning(
            f"The current-vantage inventory refresh for {marked_domain} failed."
        )
        print_info_debug(f"[current-vantage-refresh] exception for {marked_domain}: {exc}")
        return False

    refreshed_report = _report_path(shell, domain=domain)
    if os.path.exists(refreshed_report):
        newly_reachable_domains = reconcile_domain_connectivity_from_current_vantage_report(
            shell,
            source_domain=domain,
        )
        if newly_reachable_domains:
            print_info_debug(
                "[current-vantage-refresh] reconciled inter-domain connectivity from refreshed report: "
                f"domain={mark_sensitive(domain, 'domain')} "
                f"updated={len(newly_reachable_domains)}"
            )
            if not is_non_interactive(shell=shell) and not bool(getattr(shell, "auto", False)):
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
    """Offer a premium prompt to refresh stale current-vantage inventories."""

    statuses = [status for status in list_current_vantage_inventory_statuses(shell) if status.stale]
    if not statuses:
        return []
    _render_stale_inventory_banner(statuses)

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

    promptable_statuses = [status for status in statuses if _should_prompt_for_domain(shell, status=status)]
    if not promptable_statuses:
        print_info_debug(
            "[current-vantage-refresh] skipping workspace-load prompt because all stale domains are within the prompt cooldown window."
        )
        return []

    threshold_hours = CURRENT_VANTAGE_INVENTORY_STALE_AFTER_SECONDS // 3600
    lines: list[str] = []
    for status in promptable_statuses:
        if status.reason == "missing_reachability_report":
            detail = "missing report"
        else:
            parts = [f"last refresh {mark_sensitive(_format_age(status.age_seconds), 'detail')} ago"]
            if status.reachable_ip_count is not None:
                parts.append(f"reachable={mark_sensitive(str(status.reachable_ip_count), 'detail')}")
            if status.no_response_ip_count is not None:
                parts.append(f"no-response={mark_sensitive(str(status.no_response_ip_count), 'detail')}")
            if status.total_ip_count is not None:
                parts.append(f"total={mark_sensitive(str(status.total_ip_count), 'detail')}")
            if status.important_port_scan_performed is not None:
                parts.append(
                    "service-scan="
                    + mark_sensitive(
                        "yes" if status.important_port_scan_performed else "discovery-only",
                        "detail",
                    )
                )
            detail = " | ".join(parts)
        lines.append(f"{mark_sensitive(status.domain, 'domain')}: {detail}")
    print_panel(
        "\n".join(
            [
                f"ADscan detected stale or missing current-vantage inventory data for {len(promptable_statuses)} domain(s).",
                f"Staleness threshold: {threshold_hours}h",
                "",
                *lines,
                "",
                "Refreshing now revalidates reachable hosts, segmentation, and service target files without rerunning full Phase 1.",
            ]
        ),
        title="Current-Vantage Inventory Refresh",
        border_style="yellow",
        expand=False,
    )

    confirmer = getattr(shell, "_questionary_confirm", None)
    prompt = "Refresh stale current-vantage inventory now?"
    should_refresh = (
        bool(confirmer(prompt, default=False))
        if callable(confirmer)
        else bool(Confirm.ask(prompt, default=False))
    )
    if not should_refresh:
        for status in promptable_statuses:
            _record_prompt_decision(shell, domain=status.domain, decision="skip")
        print_info("Skipping stale current-vantage inventory refresh by user choice.")
        print_instruction(
            "Run `refresh_inventory <domain>` later if you want to revalidate current-vantage reachability."
        )
        return []

    selected_domains = [status.domain for status in promptable_statuses]
    checkbox = getattr(shell, "_questionary_checkbox", None)
    if len(promptable_statuses) > 1 and callable(checkbox):
        options = [
            f"{status.domain} | "
            f"{'missing report' if status.reason == 'missing_reachability_report' else f'last refresh { _format_age(status.age_seconds)} ago'}"
            for status in promptable_statuses
        ]
        selected_labels = checkbox(
            "Select domains whose current-vantage inventory should be refreshed now:",
            options,
            default_values=list(options),
        )
        if not selected_labels:
            for status in promptable_statuses:
                _record_prompt_decision(shell, domain=status.domain, decision="skip")
            print_info("Skipping stale current-vantage inventory refresh by user choice.")
            return []
        selected_domains = [
            status.domain
            for status, label in zip(promptable_statuses, options, strict=False)
            if label in selected_labels
        ]

    refreshed_domains: list[str] = []
    selected_domain_set = set(selected_domains)
    for status in promptable_statuses:
        if status.domain not in selected_domain_set:
            _record_prompt_decision(shell, domain=status.domain, decision="skip")
    for domain in selected_domains:
        if refresh_current_vantage_inventory(
            shell,
            domain=domain,
            reason=f"{trigger}:stale_inventory_prompt",
        ):
            _record_prompt_decision(shell, domain=domain, decision="refresh")
            refreshed_domains.append(domain)
        else:
            _record_prompt_decision(shell, domain=domain, decision="refresh_attempt_failed")
    return refreshed_domains


__all__ = [
    "CURRENT_VANTAGE_INVENTORY_STALE_AFTER_SECONDS",
    "CURRENT_VANTAGE_INVENTORY_PROMPT_COOLDOWN_SECONDS",
    "CurrentVantageInventoryStatus",
    "list_current_vantage_inventory_statuses",
    "maybe_offer_workspace_current_vantage_refresh",
    "refresh_current_vantage_inventory",
]
