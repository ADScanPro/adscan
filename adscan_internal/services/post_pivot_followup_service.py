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

from adscan_internal import (
    print_info,
    print_info_debug,
    print_panel,
    print_success,
    telemetry,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.domain_connectivity_service import (
    normalize_domain_connectivity_entry,
    reconcile_domain_connectivity_from_current_vantage_report,
    reconcile_domain_connectivity_from_pivot_targets,
)
from adscan_internal.services.pivot_runtime_state_service import (
    snapshot_direct_vantage_artifacts,
)
from adscan_internal.services.inventory_timeline_service import (
    TRIGGER_POST_PIVOT,
    compute_inventory_diff,
    is_timeline_enabled,
    list_snapshots,
    load_snapshot_payload,
    mark_diff_seen,
    record_inventory_snapshot,
    render_inventory_diff,
)
from adscan_internal.workspaces import domain_subpath
from adscan_internal.workspaces.layout import DEFAULT_DOMAIN_LAYOUT
from adscan_core.rich_output import print_exception


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
    """Render the structured reachability diff unlocked by one successful pivot."""
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

    if not is_timeline_enabled(shell):
        print_info_debug(
            "[post-pivot] inventory timeline disabled; skipping detailed diff rendering."
        )
        return

    entries = list_snapshots(shell, domain=context.domain)
    if not entries:
        print_info_debug(
            "[post-pivot] no inventory snapshots recorded yet; skipping detailed diff rendering."
        )
        return

    after_entry = entries[-1]
    before_entry = entries[-2] if len(entries) >= 2 else None
    after_payload = load_snapshot_payload(
        shell, domain=context.domain, snapshot_id=after_entry.id
    )
    if not isinstance(after_payload, dict):
        return
    before_payload = (
        load_snapshot_payload(shell, domain=context.domain, snapshot_id=before_entry.id)
        if before_entry is not None
        else None
    )
    diff = compute_inventory_diff(
        domain=context.domain,
        before_payload=before_payload,
        before_id=before_entry.id if before_entry else None,
        before_at=before_entry.at if before_entry else None,
        after_payload=after_payload,
        after_id=after_entry.id,
        after_at=after_entry.at,
    )
    context_lines = [
        f"Pivot via {mark_sensitive(context.pivot_tool, 'text')} "
        f"({mark_sensitive(context.pivot_method, 'text')}) through "
        f"{mark_sensitive(context.pivot_host, 'hostname')}",
        f"Source service: {mark_sensitive(context.source_service, 'text')}",
    ]
    render_inventory_diff(
        shell,
        diff=diff,
        title="Newly Reachable Through Pivot",
        context_lines=context_lines,
    )
    mark_diff_seen(shell, domain=context.domain, snapshot_id=after_entry.id)
    print_info_debug(
        "[post-pivot] reachability delta: "
        f"domain={mark_sensitive(context.domain, 'domain')} "
        f"pivot_host={mark_sensitive(context.pivot_host, 'hostname')} "
        f"pivot_method={mark_sensitive(context.pivot_method, 'text')} "
        f"new_hosts={len(new_hosts)} new_ips={len(new_ips)}"
    )


# Stable option order for the post-pivot newly-reachable sweep scope select.
# Indices MUST NOT change — the non-interactive default-by-type mapping keys off
# them.
_POST_PIVOT_SWEEP_OPTION_ALL_NEW = 0
_POST_PIVOT_SWEEP_OPTION_DCS_ONLY = 1
_POST_PIVOT_SWEEP_OPTION_SKIP = 2


def _newly_reachable_ip_values(
    refresh_result: PostPivotRefreshResult,
) -> list[str]:
    """Return the ordered, de-duplicated newly-reachable IPs from one refresh."""
    seen: set[str] = set()
    ordered: list[str] = []
    for entry in refresh_result.newly_reachable_ips or []:
        if not isinstance(entry, dict):
            continue
        ip = str(entry.get("ip") or "").strip()
        if ip and ip not in seen:
            seen.add(ip)
            ordered.append(ip)
    return ordered


def _dc_ips_for_domain(shell: Any, domain: str) -> set[str]:
    """Return the known DC IPs for *domain* (pdc + dcs), de-duplicated."""
    from adscan_internal.models.domain import resolve_dc_ip  # noqa: PLC0415

    domain_data = (getattr(shell, "domains_data", {}) or {}).get(domain) or {}
    dc_ips: set[str] = set()
    primary = resolve_dc_ip(domain_data)
    if primary:
        dc_ips.add(str(primary).strip())
    for value in domain_data.get("dcs") or []:
        candidate = str(value or "").strip()
        if candidate:
            dc_ips.add(candidate)
    return {ip for ip in dc_ips if ip}


def _already_classified_ips(shell: Any, domain: str) -> set[str]:
    """Return IPs already holding a positive NTLMv1/NTLMv2 verdict for *domain*.

    Reads the per-host verdict map the sweep persists
    (``ntlm_auth_type_by_host``). Hosts with a positive verdict are excluded
    from a re-sweep — the delta scope already excludes pre-pivot-swept hosts in
    the common case, and this guards the rare overlap where a newly-reachable IP
    was classified through an earlier path.
    """
    domain_data = (getattr(shell, "domains_data", {}) or {}).get(domain) or {}
    host_map = domain_data.get("ntlm_auth_type_by_host") or {}
    if not isinstance(host_map, dict):
        return set()
    classified: set[str] = set()
    for ip, record in host_map.items():
        if not isinstance(record, dict):
            continue
        if str(record.get("ntlm_auth_type") or "").strip() in {"NTLMv1", "NTLMv2"}:
            classified.add(str(ip).strip())
    return classified


def _run_ntlm_sweep_for_newly_reachable_after_pivot(
    shell: Any,
    *,
    context: PivotExecutionContext,
    refresh_result: PostPivotRefreshResult,
) -> None:
    """Sweep NTLMv1 auth-type over hosts the pivot just unblocked, before recalc.

    The post-pivot follow-up re-scans ports and recalculates attack paths against
    newly-reachable hosts, but the NTLMv1 auth-type sweep is keyed to the
    pre-pivot reachable set. A host unblocked by the pivot that speaks NTLMv1 is
    therefore never classified -> never materialized into the attack graph ->
    cannot appear in the recalculated paths. This helper closes that gap by
    sweeping the newly-reachable delta (only) and materializing its NTLMv1-relay
    edges BEFORE the recalc runs.

    Scope is restricted to the newly-reachable IPs, so pre-pivot-swept hosts are
    not re-coerced; hosts already holding a positive verdict are also skipped.
    The OPSEC heads-up and the >=2-reachable relay gate inside the sweep stay
    intact. Best-effort: a sweep failure never aborts the follow-up recalc.
    """
    from adscan_core.output import questionary_select_index  # noqa: PLC0415
    from adscan_internal.cli.ntlm_capture import (  # noqa: PLC0415
        run_ntlm_auth_type_sweep_for_hosts,
    )
    from adscan_internal.interaction import is_non_interactive  # noqa: PLC0415

    domain = context.domain
    marked_domain = mark_sensitive(domain, "domain")

    candidate_ips = _newly_reachable_ip_values(refresh_result)
    if not candidate_ips:
        print_info_debug(
            "[post-pivot] NTLMv1 sweep: no newly-reachable IPs in the delta for "
            f"{marked_domain}; nothing to classify."
        )
        return

    # Idempotency: never re-coerce a host that already has a positive verdict.
    already = _already_classified_ips(shell, domain)
    candidate_ips = [ip for ip in candidate_ips if ip not in already]
    if not candidate_ips:
        print_info_debug(
            "[post-pivot] NTLMv1 sweep: every newly-reachable host already has a "
            f"positive NTLM verdict in {marked_domain}; skipping."
        )
        return

    dc_ips = _dc_ips_for_domain(shell, domain)
    dc_candidates = [ip for ip in candidate_ips if ip in dc_ips]

    options = [
        f"Sweep newly-reachable hosts ({len(candidate_ips)})",
        (
            f"Only DCs among the new hosts ({len(dc_candidates)})"
            if dc_candidates
            else "Only DCs among the new hosts (none)"
        ),
        "Skip the NTLM auth-type sweep for new hosts",
    ]

    # Engagement-type default: ctf -> sweep all newly-reachable; audit (and any
    # non-ctf) -> skip UNLESS a DC is newly reachable, in which case classify the
    # DC (a quiet, reportable win). Non-interactive/CI auto-resolves to this
    # default via the centralized helper and NEVER blocks.
    workspace_type = str(getattr(shell, "type", "") or "").strip().lower()
    if workspace_type == "ctf":
        default_idx = _POST_PIVOT_SWEEP_OPTION_ALL_NEW
    elif dc_candidates:
        default_idx = _POST_PIVOT_SWEEP_OPTION_DCS_ONLY
    else:
        default_idx = _POST_PIVOT_SWEEP_OPTION_SKIP

    print_info(
        f"The pivot unblocked {len(candidate_ips)} newly-reachable host(s) in "
        f"{marked_domain}. ADscan can classify their NTLM auth-type (NTLMv1 vs "
        "NTLMv2) and materialize any coerce-and-relay paths before re-checking "
        "attack paths."
    )

    selected_idx = questionary_select_index(
        title=f"NTLM auth-type sweep scope for newly-reachable hosts in {domain}",
        options=options,
        default_idx=default_idx,
        shell=shell,
    )
    if selected_idx is None:
        selected_idx = default_idx

    if is_non_interactive(shell):
        print_info_debug(
            "[post-pivot] NTLMv1 sweep scope auto-resolved (non-interactive): "
            f"idx={selected_idx} domain={marked_domain} type={workspace_type or 'unknown'}"
        )

    if selected_idx == _POST_PIVOT_SWEEP_OPTION_SKIP:
        print_info(
            "Skipping the NTLM auth-type sweep for newly-reachable hosts by "
            "selection."
        )
        return

    if selected_idx == _POST_PIVOT_SWEEP_OPTION_DCS_ONLY:
        scoped_ips = dc_candidates
        scope_mode = "dcs"
    else:
        scoped_ips = candidate_ips
        scope_mode = "all"

    if not scoped_ips:
        print_info_debug(
            "[post-pivot] NTLMv1 sweep: no in-scope hosts after scope selection "
            f"for {marked_domain}; skipping."
        )
        return

    try:
        run_ntlm_auth_type_sweep_for_hosts(
            shell,
            domain,
            candidate_ips=scoped_ips,
            scope_mode=scope_mode,
        )
    except Exception as exc:  # noqa: BLE001 - sweep failure must not abort recalc
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            "[post-pivot] NTLMv1 sweep over newly-reachable hosts raised: "
            f"{mark_sensitive(str(exc), 'detail')}"
        )


def _run_owned_user_followup_after_pivot(
    shell: Any,
    *,
    context: PivotExecutionContext,
    refresh_result: PostPivotRefreshResult,
) -> None:
    """Re-run owned-user attack-path and post-auth service/share follow-up flows.

    Order matters: the NTLMv1 auth-type sweep over the newly-reachable delta runs
    FIRST, so any NTLMv1-relay edges it materializes (and the attack-path artifact
    invalidation it triggers) are visible to the attack-path recalc that follows.
    A host unblocked by the pivot that speaks NTLMv1 would otherwise never be
    classified, never materialized, and never appear in the recalculated paths.
    """
    from adscan_internal.cli.attack_path_execution import (
        offer_attack_paths_with_non_high_value_fallback,
    )
    from adscan_internal.cli.privileges import run_postauth_service_and_share_followup
    from adscan_internal.services.attack_graph_service import (
        ATTACK_PATHS_MAX_DEPTH_USER,
        get_owned_domain_usernames_for_attack_paths,
    )

    domain = context.domain

    # Classify NTLMv1 vs NTLMv2 on the hosts the pivot just unblocked BEFORE the
    # attack-path recalc, so newly-materialized NTLMv1-relay edges are in the
    # graph when the paths are recomputed.
    _run_ntlm_sweep_for_newly_reachable_after_pivot(
        shell, context=context, refresh_result=refresh_result
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
        target_mode="object",
        display_friendly=True,
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
        run_postauth_service_and_share_followup(
            shell,
            domain=domain,
            username=username,
            password=secret,
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
    """Offer a high-value owned-user follow-up when the pivot unlocked new hosts."""
    from adscan_core.output import confirm_ask  # noqa: PLC0415

    new_hosts = refresh_result.newly_reachable_hosts or []
    if not new_hosts:
        return
    host_phrase = (
        "1 new reachable host"
        if len(new_hosts) == 1
        else f"{len(new_hosts)} new reachable hosts"
    )

    prompt = (
        f"The pivot through {mark_sensitive(context.pivot_host, 'hostname')} unlocked "
        f"{host_phrase}. Re-check attack paths from owned users "
        "and run post-auth service/share follow-up now?"
    )
    confirmer = getattr(shell, "_questionary_confirm", None)
    if callable(confirmer):
        should_run = bool(confirmer(prompt, default=True))
    else:
        should_run = bool(confirm_ask(prompt, default=True))

    if not should_run:
        print_info("Skipping post-pivot owned-user follow-up by user choice.")
        return
    _run_owned_user_followup_after_pivot(
        shell, context=context, refresh_result=refresh_result
    )


def maybe_offer_trust_followup_for_newly_reachable_domains(
    shell: Any,
    *,
    source_domain: str,
    newly_reachable_domains: list[str],
    title: str,
    lead_lines: list[str],
    prompt: str,
    prompt_default: bool = True,
) -> None:
    """Offer trust follow-up when current-vantage changes unlock trusted domains."""
    if not newly_reachable_domains:
        return

    domains_data = getattr(shell, "domains_data", {})
    pending_domains = [
        domain
        for domain in newly_reachable_domains
        if not bool(
            (
                domains_data.get(domain, {}) if isinstance(domains_data, dict) else {}
            ).get("phase1_complete")
        )
    ]
    if not pending_domains:
        print_info_debug(
            "[trust-followup] all newly reachable domains already completed Phase 1: "
            f"source={mark_sensitive(source_domain, 'domain')}"
        )
        return

    marked_source = mark_sensitive(source_domain, "domain")
    domain_lines = [
        f"• {mark_sensitive(domain, 'domain')}" for domain in pending_domains[:8]
    ]
    if len(pending_domains) > 8:
        domain_lines.append(f"• ... +{len(pending_domains) - 8} more")

    print_panel(
        "\n".join(
            [
                *lead_lines,
                "",
                f"Source domain: {marked_source}",
                "",
                "Newly reachable domains pending authenticated enumeration:",
                *domain_lines,
                "",
                "ADscan can now re-run trust analysis from the source domain and continue authenticated enumeration only for domains that have not already completed Phase 1.",
            ]
        ),
        title=title,
        border_style="green",
        expand=False,
    )

    trust_runner = getattr(shell, "do_enum_trusts", None)
    if not callable(trust_runner):
        print_info_debug("[trust-followup] shell does not expose do_enum_trusts().")
        return

    from adscan_core.output import confirm_ask  # noqa: PLC0415

    confirmer = getattr(shell, "_questionary_confirm", None)
    if callable(confirmer):
        proceed = bool(confirmer(prompt, default=prompt_default))
    else:
        proceed = bool(confirm_ask(prompt, default=prompt_default))
    if proceed:
        trust_runner(source_domain)


def maybe_offer_post_pivot_trust_followup_from_targets(
    shell: Any,
    *,
    context: PivotExecutionContext,
    confirmed_targets: list[dict[str, Any]],
) -> list[str]:
    """Reconcile and offer trusted-domain follow-up from direct pivot probe evidence.

    Args:
        shell: Active ADscan shell.
        context: Successful pivot execution context.
        confirmed_targets: Reachable targets confirmed from the pivot host before tunnel creation.

    Returns:
        Trusted domains that became reachable through this pivot.
    """
    newly_reachable_domains = reconcile_domain_connectivity_from_pivot_targets(
        shell,
        source_domain=context.domain,
        targets=confirmed_targets,
        pivot_host=context.pivot_host,
        pivot_method=context.pivot_method,
        pivot_tool=context.pivot_tool,
        source_service=context.source_service,
    )
    if not newly_reachable_domains:
        return []

    print_info_debug(
        "[post-pivot] reconciled trusted-domain connectivity from pivot targets: "
        f"domain={mark_sensitive(context.domain, 'domain')} "
        f"pivot_host={mark_sensitive(context.pivot_host, 'hostname')} "
        f"updated={len(newly_reachable_domains)}"
    )
    _maybe_offer_post_pivot_trust_followup(
        shell,
        context=context,
        newly_reachable_domains=newly_reachable_domains,
    )
    return newly_reachable_domains


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
        snapshot_direct_vantage_artifacts(
            workspace_dir=workspace_dir,
            domains_dir=shell.domains_dir,
            domain=context.domain,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            "[post-pivot] failed to snapshot direct/current-vantage artifacts before pivot refresh: "
            f"{mark_sensitive(str(exc), 'detail')}"
        )
    try:
        refresh_callable(context.domain, computers_file, nmap_dir)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
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
    try:
        record_inventory_snapshot(
            shell,
            domain=context.domain,
            trigger=TRIGGER_POST_PIVOT,
            trigger_detail=(
                f"{context.pivot_tool}:{context.source_service}:{context.pivot_host}"
            ),
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            "[post-pivot] failed to record inventory timeline snapshot: "
            f"{mark_sensitive(str(exc), 'detail')}"
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
                newly_reachable_domains = (
                    reconcile_domain_connectivity_from_current_vantage_report(
                        shell,
                        source_domain=context.domain,
                        payload=payload,
                    )
                )
                if newly_reachable_domains:
                    print_info_debug(
                        "[post-pivot] reconciled inter-domain connectivity from current-vantage report: "
                        f"domain={mark_sensitive(context.domain, 'domain')} "
                        f"updated={len(newly_reachable_domains)}"
                    )
                    _maybe_offer_post_pivot_trust_followup(
                        shell,
                        context=context,
                        newly_reachable_domains=newly_reachable_domains,
                    )
    except (OSError, json.JSONDecodeError) as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
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
            print_exception(exception=exc)
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


def _maybe_offer_post_pivot_trust_followup(
    shell: Any,
    *,
    context: PivotExecutionContext,
    newly_reachable_domains: list[str],
) -> None:
    """Offer trust follow-up when pivoting unlocks new trusted domains."""
    domain_details: list[str] = []
    raw_connectivity = getattr(shell, "domain_connectivity", {})
    for domain in newly_reachable_domains[:8]:
        entry = (
            raw_connectivity.get(domain, {})
            if isinstance(raw_connectivity, dict)
            else {}
        )
        normalized = normalize_domain_connectivity_entry(entry)
        summary = normalized.get("summary", {})
        if not isinstance(summary, dict):
            domain_details.append(f"• {mark_sensitive(domain, 'domain')}")
            continue
        pdc_ip = str(summary.get("pdc_ip") or summary.get("host") or "").strip()
        open_ports = ", ".join(
            str(port) for port in summary.get("open_ports", []) if str(port).strip()
        )
        previous = "previously unreachable from the direct vantage"
        direct_vantage = normalized.get("vantages", {}).get("direct:local", {})
        if isinstance(direct_vantage, dict):
            direct_status = str(direct_vantage.get("status") or "").strip()
            if direct_status:
                previous = f"previous direct status: {direct_status}"
        detail_parts = [mark_sensitive(domain, "domain")]
        if pdc_ip:
            detail_parts.append(f"PDC {mark_sensitive(pdc_ip, 'ip')}")
        if open_ports:
            detail_parts.append(f"AD ports {mark_sensitive(open_ports, 'text')}")
        detail_parts.append(mark_sensitive(previous, "text"))
        domain_details.append("• " + " | ".join(detail_parts))

    maybe_offer_trust_followup_for_newly_reachable_domains(
        shell,
        source_domain=context.domain,
        newly_reachable_domains=newly_reachable_domains,
        title="New Trusted Domains Reachable",
        lead_lines=[
            "High-value pivot discovery: the tunnel made previously unreachable trusted-domain infrastructure reachable.",
            f"Pivot host: {mark_sensitive(context.pivot_host, 'hostname')}",
            "",
            "Why this matters: ADscan may now be able to authenticate, enumerate BloodHound data, inspect trusts from the newly reachable domain, and discover cross-domain attack paths that were invisible before the pivot.",
            "",
            "Unlocked trusted-domain evidence:",
            *domain_details,
        ],
        prompt=(
            "Do you want ADscan to prioritize trust-driven authenticated enumeration "
            f"from {mark_sensitive(context.domain, 'domain')} now?"
        ),
    )
