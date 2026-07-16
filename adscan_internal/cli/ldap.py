"""CLI orchestration for LDAP enumeration.

This module keeps interactive CLI concerns (printing, reporting, file persistence)
separate from the LDAP service layer.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional, Protocol

from rich.prompt import Prompt, Confirm
from rich.table import Table

from adscan_core.username_patterns import (
    USERNAME_PATTERN_LABELS,
    build_username_pattern_candidates,
    format_username_pattern_option,
    normalize_username_candidate,
)
from adscan_internal import (
    print_error,
    print_exception,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_operation_header,
    print_success,
    print_success_verbose,
    print_warning,
    telemetry,
)
from adscan_internal.reporting_compat import handle_optional_report_service_exception
from adscan_internal.core import AuthMode
from adscan_internal.cli.common import SECRET_MODE, build_lab_event_fields
from adscan_internal.cli.ntlm_hash_finding_flow import (
    render_ntlm_hash_findings_flow,
)
from adscan_internal.cli.tools_env import TOOLS_INSTALL_DIR
from adscan_internal.cli.host_file_picker import (
    is_full_container_runtime,
    maybe_import_host_file_to_workspace,
    select_host_file_via_gui,
)
from adscan_internal.execution_outcomes import output_has_exact_ldap_connection_timeout
from adscan_internal.path_utils import get_effective_user_home
from adscan_internal.rich_output import (
    BRAND_COLORS,
    mark_sensitive,
    print_panel,
    print_panel_with_table,
)
from adscan_internal.services import EnumerationService
from adscan_internal.services.kerberos_username_wordlist_service import (
    LINKEDIN_SUPPORTED_PATTERN_KEYS,
    SUPPORTED_KERBEROS_PATTERN_KEYS,
    KerberosUsernameWordlistService,
    KerberosWordlistSourceMetadata,
    format_supported_pattern_label,
)
from adscan_internal.services.linkedin_username_discovery_service import (
    CachedLinkedInSessionProvider,
    LinkedInUsernameDiscoveryService,
)
from adscan_internal.services.enumeration.ldap import LDAPAnonymousUserRecord
from adscan_internal.services.credsweeper_service import (
    CREDSWEEPER_RULES_PROFILE_LDAP_DESCRIPTION,
)
from adscan_internal.services.credsweeper_library_service import (
    CredSweeperLibraryService,
    InMemoryCredSweeperTarget,
)
from adscan_internal.services.attack_graph_service import (
    CredentialSourceStep,
    resolve_group_members_by_rid,
)
from adscan_internal.services.attack_path_target_viability_service import (
    assess_computer_target_viability,
)
from adscan_internal.integrations.impacket.parsers import parse_secretsdump_output
from adscan_internal.workspaces import domain_relpath, domain_subpath, read_json_file


class LdapShell(Protocol):
    """Minimal shell surface used by the LDAP CLI controller."""

    domains: list[str]
    domains_dir: str
    ldap_dir: str
    domain: str | None
    type: str | None
    auto: bool
    scan_mode: str | None
    current_workspace_dir: str | None
    domains_data: dict
    netexec_path: str | None
    credsweeper_path: str | None
    auto: bool
    kerberos_dir: str
    console: object

    def _get_workspace_cwd(self) -> str: ...

    def _get_service_executor(
        self,
    ) -> Callable[[str, int], subprocess.CompletedProcess[str]]: ...

    def _get_lab_slug(self) -> str | None: ...

    def update_report_field(self, domain: str, field: str, value: object) -> None: ...

    def ask_for_enumerate_user_aces(
        self, domain: str, username: str, password: str
    ) -> None: ...

    def _display_items(self, items: list[str], label: str) -> None: ...

    def _write_domain_list_file(
        self, domain: str, filename: str, values: list[str]
    ) -> str: ...

    def _write_user_list_file(
        self, domain: str, filename: str, users: list[str]
    ) -> str: ...

    def _postprocess_user_list_file(
        self,
        domain: str,
        filename: str,
        *,
        trigger_followups: bool = True,
        source: str | None = None,
    ) -> None: ...

    def build_auth_nxc(
        self, username: str, password: str, domain: str, kerberos: bool = False
    ) -> str: ...

    def run_command(
        self, command: str, timeout: int | None = None, cwd: str | None = None
    ) -> subprocess.CompletedProcess[str]: ...

    def _questionary_select(
        self, message: str, options: list[str], default_idx: int = 0
    ) -> int | None: ...

    def _questionary_checkbox(
        self,
        title: str,
        options: list[str],
        default_values: list[str] | None = None,
    ) -> list[str] | None: ...

    def _generate_user_permutations_interactive(self, domain: str) -> str | None: ...

    def _open_fullscreen_editor(self, title: str, initial_text: str) -> str | None: ...

    def ask_for_kerberos_user_enum(
        self, domain: str, relaunch: bool = False
    ) -> None: ...

    def do_enum_with_users(self, domain: str) -> None: ...

    def ask_for_asreproast(self, domain: str) -> None: ...

    def ask_for_spraying(self, domain: str) -> None: ...

    def _is_full_adscan_container_runtime(self) -> bool: ...

    def _run_netexec(
        self, command: str, domain: str | None = None, timeout: int | None = None
    ) -> subprocess.CompletedProcess[str]: ...

    def add_credential(
        self, domain: str, username: str, credential: str, **kwargs: object
    ) -> None: ...

    def do_sync_clock_with_pdc(self, domain: str) -> None: ...

    def ask_for_graph_collection(
        self, target_domain: str, callback=None
    ) -> list[str] | None: ...

    def run_enumeration(
        self, domain: str, *, stop_after_phase: int | None = None
    ) -> None: ...

    def do_check_dns(self, domain: str) -> bool: ...

    def do_update_resolv_conf(self, resolv_conf_line: str) -> None: ...

    def convert_hostnames_to_ips_and_scan(
        self, domain: str, computers_file: str, nmap_dir: str
    ) -> None: ...

    def ask_for_smb_descriptions(self, domain: str) -> None: ...

    credsweeper_path: str | None

    base_dn: str | None


def _normalize_obsolete_host_key(value: object) -> str:
    """Return a stable case-insensitive key for obsolete-host deduplication."""
    return str(value or "").strip().rstrip(".").lower()


def _obsolete_host_label_for_node(
    node: dict[str, object],
    props: dict[str, object],
) -> str:
    """Pick the best operator-facing host label for one Computer node.

    Prefers the DNS host name (an FQDN the current-vantage resolver can match),
    then the sAMAccountName stem, then the node label. Trailing ``$`` and any
    ``@DOMAIN`` suffix are stripped so the value flows cleanly into viability
    resolution and the summary table.
    """
    dnshostname = str(props.get("dnshostname") or "").strip()
    if dnshostname:
        return dnshostname
    samaccountname = str(props.get("samaccountname") or "").strip().rstrip("$")
    if samaccountname:
        return samaccountname
    name = str(props.get("name") or node.get("label") or "").strip()
    return name.split("@", 1)[0].strip().rstrip("$")


def collect_obsolete_computers_from_graph(
    shell: LdapShell,
    *,
    domain: str,
) -> dict[str, object] | None:
    """Build obsolete-host evidence from the native collector's computer inventory.

    Reads the collected attack graph for ``domain`` and flags every Computer node
    whose ``operatingSystem`` (persisted as the ``os`` node property) matches the
    native obsolete-OS classifier (``audit_analyzer._is_obsolete_os`` — the single
    source of truth also used by the audit findings pipeline). The returned payload
    mirrors the structure the former NetExec parser produced, so the existing
    renderers and technical-report persistence stay untouched.

    Returns ``None`` when no computer inventory has been collected yet (attack graph
    missing or containing no Computer nodes), so the caller can prompt the operator
    to run graph collection instead of showing a misleading "no obsolete hosts"
    result.
    """
    from adscan_internal.services.attack_graph_service import load_attack_graph
    from adscan_internal.services.collector.audit_analyzer import _is_obsolete_os

    graph = load_attack_graph(shell, domain)
    nodes = graph.get("nodes") if isinstance(graph, dict) else None
    if not isinstance(nodes, dict):
        return None

    computer_nodes = [
        node
        for node in nodes.values()
        if isinstance(node, dict)
        and str(node.get("kind") or "").strip().lower() == "computer"
    ]
    if not computer_nodes:
        return None

    entries: list[dict[str, object]] = []
    seen_hosts: set[str] = set()
    hosts: list[str] = []
    operating_system_counts: dict[str, int] = {}

    for node in computer_nodes:
        props = node.get("properties")
        props = props if isinstance(props, dict) else {}
        operating_system = str(props.get("os") or "").strip()
        if not operating_system or not _is_obsolete_os(operating_system):
            continue

        host = _obsolete_host_label_for_node(node, props)
        if not host:
            continue
        host_key = _normalize_obsolete_host_key(host)
        if host_key in seen_hosts:
            continue
        seen_hosts.add(host_key)
        hosts.append(host)
        operating_system_counts[operating_system] = (
            int(operating_system_counts.get(operating_system) or 0) + 1
        )

        entry: dict[str, object] = {
            "host": host,
            "operating_system": operating_system,
            "raw_line": f"{host} : {operating_system}",
        }
        ip_address = str(props.get("ip_address") or "").strip()
        if ip_address:
            entry["ip"] = ip_address
        entries.append(entry)

    return {
        "source": "native_collector",
        "count": len(hosts),
        "hosts": hosts,
        "entries": entries,
        "operating_system_counts": operating_system_counts,
    }


def _enrich_obsolete_entries_with_current_vantage(
    shell: LdapShell,
    *,
    domain: str,
    parsed: dict[str, object],
) -> dict[str, object]:
    """Attach current-vantage viability context to parsed obsolete-host evidence."""
    entries = parsed.get("entries")
    if not isinstance(entries, list) or not entries:
        return parsed

    enriched_entries: list[dict[str, object]] = []
    status_counts = {
        "reachable_from_current_vantage": 0,
        "resolved_but_unreachable": 0,
        "enabled_but_unresolved": 0,
        "enabled_inventory_only": 0,
        "not_in_enabled_inventory": 0,
        "unknown": 0,
    }

    for raw_entry in entries:
        if not isinstance(raw_entry, dict):
            continue
        entry = dict(raw_entry)
        host = str(entry.get("host") or "").strip()
        if not host:
            continue

        viability = assess_computer_target_viability(
            shell,
            domain=domain,
            principal_name=host,
            node={"properties": {"name": host}},
        )
        entry["current_vantage_status"] = viability.status
        entry["current_vantage_summary"] = viability.operator_summary
        entry["matched_ips"] = list(viability.matched_ips)
        entry["matched_hostnames"] = list(viability.matched_hostnames)
        entry["reachable_from_current_vantage"] = (
            viability.reachable_from_current_vantage
        )
        entry["resolved_in_current_vantage_inventory"] = (
            viability.resolved_in_current_vantage_inventory
        )

        if viability.status in status_counts:
            status_counts[viability.status] += 1
        else:
            status_counts["unknown"] += 1
        enriched_entries.append(entry)

    parsed["entries"] = enriched_entries
    parsed["current_vantage_summary"] = {
        "report_available": any(
            entry.get("resolved_in_current_vantage_inventory") is not None
            for entry in enriched_entries
        ),
        "reachable_count": status_counts["reachable_from_current_vantage"],
        "resolved_but_unreachable_count": status_counts["resolved_but_unreachable"],
        "enabled_but_unresolved_count": status_counts["enabled_but_unresolved"],
        "enabled_inventory_only_count": status_counts["enabled_inventory_only"],
        "not_in_enabled_inventory_count": status_counts["not_in_enabled_inventory"],
        "unknown_count": status_counts["unknown"],
    }
    return parsed


def _status_label_for_obsolete_entry(status: str) -> str:
    """Return a concise operator-facing label for one obsolete-host viability status."""
    normalized = str(status or "").strip()
    status_map = {
        "reachable_from_current_vantage": "Reachable now",
        "resolved_but_unreachable": "Resolved, not reachable",
        "enabled_but_unresolved": "Enabled, no IP now",
        "enabled_inventory_only": "Enabled, no vantage report",
        "not_in_enabled_inventory": "Inventory drift",
        "unknown": "Unknown",
    }
    return status_map.get(normalized, "Unknown")


def _build_obsolete_inventory_drift_candidates(
    entries: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Return obsolete hosts that likely represent stale AD/DNS inventory drift."""
    drift_statuses = {"enabled_but_unresolved", "not_in_enabled_inventory"}
    return [
        entry
        for entry in entries
        if str(entry.get("current_vantage_status") or "").strip() in drift_statuses
    ]


_OBSOLETE_OS_AGE_BANDS = (
    # (substring matchers, glyph, color slot, age label); older first wins.
    (("windows 2000", "windows nt", "windows xp", "windows 2003", "windows server 2003"), "X", "crimson", "EOL > 15 yrs"),
    (("windows 2008", "windows server 2008", "windows vista", "windows 7"), "X", "crimson", "EOL > 5 yrs"),
    (("windows 2012", "windows server 2012", "windows 8"), "!", "amber", "EOL 2023"),
    (("windows 2016", "windows server 2016", "windows server 2019"), ".", "muted", "Aging"),
)


def _classify_obsolete_os(operating_system: str) -> tuple[str, str, str]:
    """Return (glyph, color_slot, age_label) for an obsolete OS string."""
    lower = (operating_system or "").lower()
    for needles, glyph, slot, label in _OBSOLETE_OS_AGE_BANDS:
        if any(needle in lower for needle in needles):
            return glyph, slot, label
    return ".", "muted", "Aging"


def _color_for_slot(slot: str) -> str:
    """Map a semantic slot name to the bundled theme color."""
    from adscan_core.theme import (
        COLOR_AMBER,
        COLOR_CRIMSON,
        COLOR_MUTED,
        COLOR_SAGE,
        COLOR_STEEL,
        ADSCAN_PRIMARY,
    )

    mapping = {
        "crimson": COLOR_CRIMSON,
        "amber": COLOR_AMBER,
        "sage": COLOR_SAGE,
        "steel": COLOR_STEEL,
        "muted": COLOR_MUTED,
        "primary": ADSCAN_PRIMARY,
    }
    return mapping.get(slot, COLOR_MUTED)


def _render_obsolete_computers_summary(
    shell: LdapShell,
    *,
    domain: str,
    parsed: dict[str, object],
) -> None:
    """Render a premium obsolete-host summary instead of raw NetExec output."""
    entries = parsed.get("entries")
    if not isinstance(entries, list) or not entries:
        marked_domain = mark_sensitive(domain, "domain")
        print_info(f"No obsolete operating systems were identified in {marked_domain}.")
        return

    from adscan_core.theme import (
        COLOR_AMBER,
        COLOR_CRIMSON,
        COLOR_MUTED,
        COLOR_SAGE,
        COLOR_STEEL,
    )

    current_vantage_summary = (
        parsed.get("current_vantage_summary")
        if isinstance(parsed.get("current_vantage_summary"), dict)
        else {}
    )
    operating_system_counts = (
        parsed.get("operating_system_counts")
        if isinstance(parsed.get("operating_system_counts"), dict)
        else {}
    )
    total_hosts = int(parsed.get("count") or len(entries))
    marked_domain = mark_sensitive(domain, "domain")
    report_available = bool(current_vantage_summary.get("report_available"))

    # Verdict-first headline: count + worst-band.
    worst_slot = "muted"
    worst_label = "Aging"
    for item in entries:
        if not isinstance(item, dict):
            continue
        _g, slot, label = _classify_obsolete_os(str(item.get("operating_system") or ""))
        if slot == "crimson":
            worst_slot, worst_label = "crimson", label
            break
        if slot == "amber" and worst_slot != "crimson":
            worst_slot, worst_label = "amber", label
    verdict_glyph = "X" if worst_slot == "crimson" else ("!" if worst_slot == "amber" else ".")
    verdict_color = _color_for_slot(worst_slot)

    summary_parts = [
        f"[{verdict_color}]{verdict_glyph} {total_hosts} obsolete host(s)[/{verdict_color}] "
        f"in {marked_domain} ({worst_label} worst-case)."
    ]
    if operating_system_counts:
        top_os = sorted(
            (
                (str(name), int(count))
                for name, count in operating_system_counts.items()
                if str(name).strip()
            ),
            key=lambda item: (-item[1], item[0].lower()),
        )
        summary_parts.append(
            "OS mix: "
            + ", ".join(f"{count}x {name}" for name, count in top_os[:3])
            + "."
        )
    if report_available:
        summary_parts.append(
            "Current-vantage triage: "
            f"[{COLOR_SAGE}]{int(current_vantage_summary.get('reachable_count') or 0)} reachable now[/{COLOR_SAGE}], "
            f"[{COLOR_AMBER}]{int(current_vantage_summary.get('resolved_but_unreachable_count') or 0)} resolved but not reachable[/{COLOR_AMBER}], "
            f"[{COLOR_MUTED}]{int(current_vantage_summary.get('enabled_but_unresolved_count') or 0)} enabled without IP resolution[/{COLOR_MUTED}]."
        )
    else:
        summary_parts.append(
            "No current-vantage reachability report is available yet, so ADscan cannot distinguish live exposure from stale directory entries."
        )
    print_info(" ".join(summary_parts))

    table = Table(
        title="Obsolete Operating Systems",
        show_header=True,
        header_style=f"bold {COLOR_AMBER}",
    )
    table.add_column("", width=2, justify="center")
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Host", style=COLOR_STEEL, no_wrap=False, max_width=32)
    table.add_column("Operating System", no_wrap=False, max_width=30)
    table.add_column("Age Band", no_wrap=False, max_width=14)
    table.add_column("Current Vantage", no_wrap=False, max_width=24)
    table.add_column("IP Context", style=COLOR_MUTED, no_wrap=False, max_width=26)

    shown_entries = entries[:12]
    for idx, item in enumerate(shown_entries, 1):
        if not isinstance(item, dict):
            continue
        host = mark_sensitive(str(item.get("host") or "unknown"), "hostname")
        operating_system = str(item.get("operating_system") or "Unknown").strip()
        glyph, slot, age_label = _classify_obsolete_os(operating_system)
        os_color = _color_for_slot(slot)
        status_label = _status_label_for_obsolete_entry(
            str(item.get("current_vantage_status") or "")
        )
        status_color = COLOR_MUTED
        if "Reachable now" in status_label:
            status_color = COLOR_CRIMSON  # legacy + reachable = critical
        elif "Resolved" in status_label:
            status_color = COLOR_AMBER
        matched_ips = [
            mark_sensitive(str(ip), "ip")
            for ip in item.get("matched_ips", [])
            if str(ip).strip()
        ]
        raw_ip = str(item.get("ip") or "").strip()
        ip_context = ", ".join(matched_ips[:2])
        if not ip_context and raw_ip and raw_ip.upper() != "N/A":
            ip_context = mark_sensitive(raw_ip, "ip")
        if not ip_context:
            ip_context = "N/A"
        table.add_row(
            f"[{os_color}]{glyph}[/{os_color}]",
            str(idx),
            host,
            f"[{os_color}]{operating_system}[/{os_color}]",
            f"[{os_color}]{age_label}[/{os_color}]",
            f"[{status_color}]{status_label}[/{status_color}]",
            ip_context,
        )

    remaining = max(0, total_hosts - len(shown_entries))
    if remaining:
        table.caption = (
            f"Showing first {len(shown_entries)} obsolete hosts. "
            f"{remaining} additional host(s) remain in the artifact and technical report."
        )

    subtitle = None
    if not report_available:
        subtitle = "Run `refresh_inventory <domain>` to separate reachable legacy systems from likely stale AD/DNS entries."

    print_panel_with_table(
        table,
        title="[bold]Obsolete Operating Systems[/bold]",
        border_style=verdict_color,
    )
    if subtitle:
        print_info(subtitle)

    # Action-oriented Next-step hint.
    next_hint: str | None = None
    if worst_slot == "crimson":
        next_hint = (
            f"[{COLOR_CRIMSON}]Next:[/{COLOR_CRIMSON}] prioritize patching or isolating EOL hosts; "
            "they are likely exploitable with public PoCs."
        )
    elif worst_slot == "amber":
        next_hint = (
            f"[{COLOR_AMBER}]Next:[/{COLOR_AMBER}] schedule extended-support review or migration; "
            "EOL window has passed or is imminent."
        )
    if next_hint:
        print_info(next_hint)

    drift_candidates = _build_obsolete_inventory_drift_candidates(
        [item for item in entries if isinstance(item, dict)]
    )
    if drift_candidates:
        shown_drift = drift_candidates[:8]
        drift_lines = [
            "These obsolete computer objects are enabled or still present in directory-linked evidence, "
            "but ADscan could not resolve them into usable current-vantage network targets."
        ]
        drift_lines.append(
            "This usually means stale AD/DNS inventory, decommissioned endpoints that were never cleaned up, "
            "or naming records that no longer map to live systems."
        )
        drift_lines.append("")
        drift_lines.append("Likely stale entries:")
        for item in shown_drift:
            host = mark_sensitive(str(item.get("host") or "unknown"), "hostname")
            operating_system = str(item.get("operating_system") or "Unknown").strip()
            status_label = _status_label_for_obsolete_entry(
                str(item.get("current_vantage_status") or "")
            )
            drift_lines.append(f"- {host} ({operating_system}) [{status_label}]")
        if len(drift_candidates) > len(shown_drift):
            drift_lines.append(
                f"- ... and {len(drift_candidates) - len(shown_drift)} additional stale-looking entry(s)"
            )
        drift_lines.append("")
        drift_lines.append(
            "Recommended action: validate decommission status, remove stale DNS records, "
            "disable orphaned computer objects, and refresh the current-vantage inventory after cleanup."
        )
        print_panel(
            "\n".join(drift_lines),
            title="[bold]Likely Stale AD/DNS Entries[/bold]",
            border_style=BRAND_COLORS["warning"],
        )


def _build_ldap_security_targets(
    shell: LdapShell, *, domain: str
) -> list[dict[str, str]]:
    """Build a stable per-DC target list for LDAP posture checks."""
    domain_info = shell.domains_data.get(domain, {})
    targets: list[dict[str, str]] = []
    seen: set[str] = set()

    def _append_target(connect_target: str, display_name: str) -> None:
        normalized_target = str(connect_target or "").strip().lower()
        normalized_display = str(display_name or "").strip().lower()
        if not normalized_target:
            return
        key = normalized_display or normalized_target
        if key in seen:
            return
        seen.add(key)
        targets.append(
            {
                "connect_target": connect_target,
                "display_name": display_name or connect_target,
            }
        )

    hostname_candidates: list[str] = []
    pdc_hostname = str(domain_info.get("pdc_hostname") or "").strip()
    if pdc_hostname:
        hostname_candidates.append(pdc_hostname)
    for hostname in domain_info.get("dcs_hostnames") or []:
        cleaned = str(hostname or "").strip()
        if cleaned:
            hostname_candidates.append(cleaned)

    if hostname_candidates:
        for hostname in hostname_candidates:
            fqdn = hostname if "." in hostname else f"{hostname}.{domain}"
            display_name = hostname.split(".", 1)[0]
            _append_target(fqdn, display_name)
        return targets

    ip_candidates: list[str] = []
    pdc_ip = str(domain_info.get("pdc") or "").strip()
    if pdc_ip:
        ip_candidates.append(pdc_ip)
    for dc_ip in domain_info.get("dcs") or []:
        cleaned = str(dc_ip or "").strip()
        if cleaned:
            ip_candidates.append(cleaned)

    for address in ip_candidates:
        _append_target(address, address)
    return targets


def _summarize_ldap_security_entries(
    dc_results: list[dict[str, object]],
) -> dict[str, object]:
    """Aggregate per-DC LDAP posture observations into one finding payload."""
    entries: list[dict[str, object]] = []
    insecure_signing_targets: list[str] = []
    insecure_channel_binding_targets: list[str] = []
    risky_targets: list[str] = []

    for result in dc_results:
        target_label = str(result.get("target_label") or "").strip()
        parsed = result.get("parsed") if isinstance(result.get("parsed"), dict) else {}
        per_target_entries = parsed.get("entries") if isinstance(parsed, dict) else None
        if not isinstance(per_target_entries, list) or not per_target_entries:
            entries.append(
                {
                    "target": target_label,
                    "reachable": False,
                    "signing": None,
                    "channel_binding": None,
                }
            )
            risky_targets.append(target_label or "unknown")
            continue

        entry = dict(per_target_entries[0])
        entry["target"] = (
            target_label or entry.get("server_name") or entry.get("target_name")
        )
        entries.append(entry)

        effective_target = str(entry.get("target") or target_label or "unknown")
        if not bool(entry.get("signing_hardened")):
            insecure_signing_targets.append(effective_target)
        if not bool(entry.get("channel_binding_hardened")):
            insecure_channel_binding_targets.append(effective_target)
        if not bool(entry.get("signing_hardened")) or not bool(
            entry.get("channel_binding_hardened")
        ):
            risky_targets.append(effective_target)

    return {
        "dc_count": len(entries),
        "entries": entries,
        "insecure_signing_targets": insecure_signing_targets,
        "insecure_channel_binding_targets": insecure_channel_binding_targets,
        "risky_targets": risky_targets,
    }


def _render_ldap_security_summary(
    shell: LdapShell,
    *,
    domain: str,
    summary: dict[str, object],
) -> None:
    """Render a premium LDAP signing/channel binding summary."""
    from adscan_core.theme import (
        COLOR_AMBER,
        COLOR_CRIMSON,
        COLOR_MUTED,
        COLOR_SAGE,
        COLOR_STEEL,
    )

    entries = summary.get("entries") if isinstance(summary.get("entries"), list) else []
    dc_count = int(summary.get("dc_count") or 0)
    insecure_signing = summary.get("insecure_signing_targets") or []
    insecure_channel_binding = summary.get("insecure_channel_binding_targets") or []
    risky_targets = summary.get("risky_targets") or []

    # Verdict-first headline with glyph + color.
    if risky_targets:
        verdict_glyph = "X"
        verdict_color = COLOR_CRIMSON
        verdict_label = "Risky posture detected"
        implication = (
            "  -> Unsigned LDAP and missing channel binding leave the domain open to NTLM relay "
            "and credential interception against the DC."
        )
    else:
        verdict_glyph = "+"
        verdict_color = COLOR_SAGE
        verdict_label = "Hardened"
        implication = "  -> Signed LDAP path is enforced; NTLM relay to LDAP is blocked here."

    marked_domain = mark_sensitive(domain, "domain")
    panel_body = "\n".join(
        [
            f"[{verdict_color}]{verdict_glyph} {verdict_label}[/{verdict_color}] for {marked_domain}",
            implication,
            "",
            f"  [{COLOR_STEEL}].[/{COLOR_STEEL}] DCs checked.................. {dc_count}",
            f"  [{COLOR_AMBER if insecure_signing else COLOR_SAGE}]"
            f"{'!' if insecure_signing else '+'}[/"
            f"{COLOR_AMBER if insecure_signing else COLOR_SAGE}]"
            f" DCs without LDAP signing..... {len(insecure_signing)}",
            f"  [{COLOR_AMBER if insecure_channel_binding else COLOR_SAGE}]"
            f"{'!' if insecure_channel_binding else '+'}[/"
            f"{COLOR_AMBER if insecure_channel_binding else COLOR_SAGE}]"
            f" DCs without channel binding.. {len(insecure_channel_binding)}",
            f"  [{COLOR_CRIMSON if risky_targets else COLOR_SAGE}]"
            f"{'X' if risky_targets else '+'}[/"
            f"{COLOR_CRIMSON if risky_targets else COLOR_SAGE}]"
            f" DCs needing remediation...... {len(risky_targets)}",
        ]
    )

    print_panel(
        panel_body,
        title="LDAP Security Posture",
        border_style=verdict_color,
    )

    if not entries:
        return

    table = Table(
        show_header=True,
        header_style=f"bold {COLOR_STEEL}",
    )
    table.add_column("", width=2, justify="center")
    table.add_column("Domain Controller", style=COLOR_STEEL)
    table.add_column("LDAP Signing")
    table.add_column("Channel Binding")
    table.add_column("Verdict")

    for entry in entries:
        target = mark_sensitive(str(entry.get("target") or "unknown"), "host")
        signing = str(entry.get("signing") or "Unknown")
        channel_binding = str(entry.get("channel_binding") or "Unknown")
        if not bool(entry.get("reachable", True)):
            glyph, glyph_color = "...", COLOR_MUTED
            verdict = f"[{COLOR_MUTED}]Unreachable[/{COLOR_MUTED}]"
            signing_styled = f"[{COLOR_MUTED}]{signing}[/{COLOR_MUTED}]"
            channel_styled = f"[{COLOR_MUTED}]{channel_binding}[/{COLOR_MUTED}]"
        elif bool(entry.get("signing_hardened")) and bool(
            entry.get("channel_binding_hardened")
        ):
            glyph, glyph_color = "+", COLOR_SAGE
            verdict = f"[{COLOR_SAGE}]Hardened[/{COLOR_SAGE}]"
            signing_styled = f"[{COLOR_SAGE}]{signing}[/{COLOR_SAGE}]"
            channel_styled = f"[{COLOR_SAGE}]{channel_binding}[/{COLOR_SAGE}]"
        else:
            glyph, glyph_color = "X", COLOR_CRIMSON
            verdict = f"[{COLOR_CRIMSON}]Remediate[/{COLOR_CRIMSON}]"
            sign_color = COLOR_SAGE if entry.get("signing_hardened") else COLOR_CRIMSON
            cb_color = COLOR_SAGE if entry.get("channel_binding_hardened") else COLOR_CRIMSON
            signing_styled = f"[{sign_color}]{signing}[/{sign_color}]"
            channel_styled = f"[{cb_color}]{channel_binding}[/{cb_color}]"

        table.add_row(
            f"[{glyph_color}]{glyph}[/{glyph_color}]",
            target,
            signing_styled,
            channel_styled,
            verdict,
        )

    print_panel_with_table(
        table,
        title="LDAP Signing and Channel Binding by Domain Controller",
        border_style=COLOR_STEEL,
    )

    # Action-oriented "Next:" hint.
    if risky_targets:
        print_info(
            f"[{COLOR_CRIMSON}]Next:[/{COLOR_CRIMSON}] enable LDAP signing and channel binding on the "
            "flagged DC(s) via Group Policy (Domain controller: LDAP server signing requirements = Require signing) "
            "and audit NTLM relay exposure with ntlmrelayx."
        )


def _record_ldap_security_posture_finding(
    shell: LdapShell,
    *,
    domain: str,
    summary: dict[str, object],
) -> None:
    """Persist LDAP signing/channel binding posture into the technical report."""
    if not summary:
        return

    try:
        from adscan_core.reporting.technical_report import record_technical_finding

        workspace_cwd = shell._get_workspace_cwd()
        artifact_path = domain_subpath(
            workspace_cwd,
            shell.domains_dir,
            domain,
            "ldap",
            "ldap_security_posture.log",
        )
        record_technical_finding(
            shell,
            domain,
            key="ldap_security_posture",
            value=bool(summary.get("risky_targets")),
            details=summary,
            evidence=[
                {
                    "type": "artifact",
                    "summary": "NetExec LDAP banner output with signing/channel binding posture",
                    "artifact_path": artifact_path,
                }
            ],
        )
    except Exception as exc:  # pragma: no cover
        if not handle_optional_report_service_exception(
            exc,
            action="Technical finding sync",
            debug_printer=print_info_debug,
            prefix="[ldap-security]",
        ):
            telemetry.capture_exception(exc)
            print_info_debug(
                "[ldap-security] Failed to persist technical finding: "
                f"{type(exc).__name__}: {exc}"
            )


def _record_obsolete_computers_finding(
    shell: LdapShell,
    *,
    domain: str,
    parsed: dict[str, object] | None = None,
) -> None:
    """Persist obsolete-computer evidence into the technical report."""
    if not parsed or not isinstance(parsed, dict):
        return

    try:
        from adscan_core.reporting.technical_report import record_technical_finding

        workspace_cwd = shell._get_workspace_cwd()
        artifact_path = domain_subpath(
            workspace_cwd, shell.domains_dir, domain, "attack_graph.json"
        )

        record_technical_finding(
            shell,
            domain,
            key="obsolete_computers",
            value=bool(parsed.get("hosts")),
            details=parsed,
            evidence=[
                {
                    "type": "artifact",
                    "summary": (
                        "Obsolete operating systems derived from the collected "
                        "computer inventory"
                    ),
                    "artifact_path": artifact_path,
                }
            ],
        )
    except Exception as exc:  # pragma: no cover
        if not handle_optional_report_service_exception(
            exc,
            action="Technical finding sync",
            debug_printer=print_info_debug,
            prefix="[obsolete]",
        ):
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[obsolete] Failed to persist technical finding: {type(exc).__name__}: {exc}"
            )


def execute_netexec_obsolete(shell: LdapShell, *, domain: str) -> None:
    """Audit obsolete operating systems from the native collector inventory.

    Derives the obsolete-host list from the collected attack-graph Computer nodes
    (``os`` node property + the native ``_is_obsolete_os`` classifier) instead of
    shelling out to a subprocess auditor. When no computer inventory has been
    collected yet, the operator is prompted to run graph collection first rather
    than being shown a misleading empty result.
    """
    try:
        parsed = collect_obsolete_computers_from_graph(shell, domain=domain)
        if parsed is None:
            marked_domain = mark_sensitive(domain, "domain")
            print_warning(
                f"No collected computer inventory is available for {marked_domain}, "
                "so obsolete operating systems cannot be audited yet."
            )
            print_info(
                "Run graph collection first (for example `adscan enum "
                f"{marked_domain}`), then re-run this audit."
            )
            return

        parsed = _enrich_obsolete_entries_with_current_vantage(
            shell,
            domain=domain,
            parsed=parsed,
        )
        hosts = parsed.get("hosts", []) if isinstance(parsed, dict) else []
        shell.update_report_field(
            domain,
            "obsolete_computers",
            hosts if isinstance(hosts, list) and hosts else False,
        )
        _render_obsolete_computers_summary(
            shell,
            domain=domain,
            parsed=parsed,
        )
        _record_obsolete_computers_finding(
            shell,
            domain=domain,
            parsed=parsed if isinstance(parsed, dict) else None,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("Error auditing obsolete operating systems.")
        print_exception(show_locals=False, exception=exc)


def execute_netexec_ldap_security(
    shell: LdapShell,
    *,
    domain: str,
    targets: list[dict[str, str]],
) -> None:
    """Execute per-DC LDAP signing/channel binding checks and persist posture."""
    if not targets:
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            f"No Domain Controllers were available to audit LDAP posture in {marked_domain}."
        )
        return

    results: list[dict[str, object]] = []
    combined_output_blocks: list[str] = []

    # Native LDAP posture: reuse the single-source-of-truth detection probes
    # (posture_probe) per DC instead of parsing a subprocess auditor's banner.
    # The shared workspace sink lets the domain posture cache learn each
    # observed signing/CBT verdict as a side effect.
    from adscan_internal.services.async_bridge import run_async_sync
    from adscan_internal.services.posture_probe import probe_ldap_security_for_dc
    from adscan_internal.services.posture_sink import make_workspace_posture_sink

    posture_sink = make_workspace_posture_sink(shell.domains_data)

    for target in targets:
        connect_target = str(target.get("connect_target") or "").strip()
        target_label = str(target.get("display_name") or connect_target).strip()
        if not connect_target:
            continue

        try:
            parsed = run_async_sync(
                probe_ldap_security_for_dc(
                    domain=domain,
                    dc_ip=connect_target,
                    sink=posture_sink,
                    timeout=5.0,
                )
            )
            if not isinstance(parsed, dict):
                parsed = {}
            entries = parsed.get("entries")
            if isinstance(entries, list) and entries:
                entry = entries[0]
                block = (
                    f"# Target: {target_label}\n"
                    f"signing: {entry.get('signing')} "
                    f"(hardened={entry.get('signing_hardened')}); "
                    f"channel binding: {entry.get('channel_binding')} "
                    f"(hardened={entry.get('channel_binding_hardened')})"
                )
            else:
                block = (
                    f"# Target: {target_label}\n"
                    "[unreachable] the DC did not return a conclusive LDAP posture."
                )
            combined_output_blocks.append(block)
            results.append(
                {
                    "target_label": target_label,
                    "command": "native:ldap-posture-probe",
                    "returncode": 0,
                    "parsed": parsed,
                }
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            combined_output_blocks.append(
                f"# Target: {target_label}\n[exception]\n{type(exc).__name__}: {exc}"
            )
            results.append(
                {
                    "target_label": target_label,
                    "command": "native:ldap-posture-probe",
                    "returncode": 1,
                    "parsed": {},
                }
            )

    summary = _summarize_ldap_security_entries(results)

    workspace_cwd = shell._get_workspace_cwd()
    artifact_path = domain_subpath(
        workspace_cwd,
        shell.domains_dir,
        domain,
        "ldap",
        "ldap_security_posture.log",
    )
    os.makedirs(os.path.dirname(artifact_path), exist_ok=True)
    with open(artifact_path, "w", encoding="utf-8") as handle:
        if combined_output_blocks:
            handle.write("\n\n".join(combined_output_blocks) + "\n")

    risky_targets = summary.get("risky_targets", [])
    shell.update_report_field(
        domain,
        "ldap_security_posture",
        risky_targets if isinstance(risky_targets, list) and risky_targets else False,
    )
    _record_ldap_security_posture_finding(
        shell,
        domain=domain,
        summary=summary,
    )
    _render_ldap_security_summary(shell, domain=domain, summary=summary)


def run_netexec_obsolete(shell: LdapShell, *, domain: str) -> None:
    """Audit obsolete operating systems from the native collector's inventory.

    The obsolete-OS list is derived from the already-collected attack-graph
    Computer nodes (the ``operatingSystem`` LDAP attribute the native collector
    stores as the ``os`` node property), so this is a read-only display over
    existing data — no additional network traffic or subprocess auditor.
    """
    marked_domain = mark_sensitive(domain, "domain")
    print_info_verbose(
        f"Auditing obsolete operating systems for domain {marked_domain}"
    )
    execute_netexec_obsolete(shell, domain=domain)


def run_netexec_ldap_security(shell: LdapShell, *, domain: str) -> None:
    """Audit LDAP signing / channel-binding posture against known DCs natively."""
    targets = _build_ldap_security_targets(shell, domain=domain)
    marked_domain = mark_sensitive(domain, "domain")
    print_info_verbose(
        f"Auditing LDAP signing and channel binding posture for domain {marked_domain}"
    )
    execute_netexec_ldap_security(shell, domain=domain, targets=targets)


def derive_base_dn(domain: str) -> str:
    """Derive Base Distinguished Name (DN) from a domain name.

    Takes a domain name, splits it into its components, and constructs
    the Base DN by joining each component as a Domain Component (DC).

    Args:
        domain: The domain name from which to extract the Base DN.

    Returns:
        The Base DN string (e.g., "DC=example,DC=local" for "example.local").

    Example:
        >>> derive_base_dn("example.local")
        'DC=example,DC=local'
    """
    domain_parts = domain.split(".")
    return ",".join([f"DC={part}" for part in domain_parts])


def extract_base_dn(shell: LdapShell, domain: str) -> str:
    """Extract Base Distinguished Name (DN) from a domain and update shell.

    This function derives the Base DN from the domain name and updates
    the shell's base_dn attribute.

    Args:
        shell: The shell instance to update.
        domain: The domain name from which to extract the Base DN.

    Returns:
        The Base DN string.
    """
    base_dn = derive_base_dn(domain)
    shell.base_dn = base_dn
    return base_dn




def ask_for_ldap_computers(shell: LdapShell, target_domain: str) -> None:
    """Prompt to enumerate LDAP computers for a domain and run the action if confirmed."""
    marked_target_domain = mark_sensitive(target_domain, "domain")
    answer = Confirm.ask(
        f"Do you want to enumerate LDAP computers for the domain {marked_target_domain}?"
    )
    if answer:
        run_ldap_computers(shell, target_domain)


_LDAP_ANONYMOUS_DISCOVERY_FILTER = "(objectClass=*)"

_LDAP_NON_USER_DISCOVERY_CNS = {
    "account operators",
    "administrators",
    "backup operators",
    "cert publishers",
    "cloneable domain controllers",
    "cryptographic operators",
    "denied rodc password replication group",
    "distributed com users",
    "dnsadmins",
    "dnsupdateproxy",
    "domain admins",
    "domain computers",
    "domain controllers",
    "domain guests",
    "domain users",
    "enterprise admins",
    "enterprise key admins",
    "event log readers",
    "group policy creator owners",
    "guests",
    "hyper-v administrators",
    "iis_iusrs",
    "incoming forest trust builders",
    "key admins",
    "network configuration operators",
    "performance log users",
    "performance monitor users",
    "pre-windows 2000 compatible access",
    "print operators",
    "protected users",
    "ras and ias servers",
    "rdc denied password replication group",
    "read-only domain controllers",
    "remote desktop users",
    "remote management users",
    "replicator",
    "schema admins",
    "server operators",
    "storage replica administrators",
    "terminal server license servers",
    "users",
    "windows authorization access group",
}

_LDAP_NOISY_USER_CANDIDATE_CNS = {
    "guest",
    "invitado",
    "krbtgt",
}


def _display_ldap_anonymous_pattern_preview(
    records: list[LDAPAnonymousUserRecord],
    *,
    pattern_key: str,
    max_rows: int = 20,
) -> None:
    """Preview how a username pattern applies to CN-only LDAP candidates."""
    if not records:
        return

    from adscan_core.theme import COLOR_MUTED, COLOR_STEEL

    table = Table(
        title=(
            "Username Inference Preview "
            f"({USERNAME_PATTERN_LABELS.get(pattern_key, pattern_key)})"
        ),
        show_header=True,
        header_style=f"bold {COLOR_STEEL}",
    )
    table.add_column("#", style=COLOR_MUTED, width=4, justify="right")
    table.add_column("CN observed", style=COLOR_STEEL, max_width=32)
    table.add_column("Inferred username", max_width=40)

    shown_records = records[: max(1, max_rows)]
    for idx, record in enumerate(shown_records, 1):
        candidates = build_username_pattern_candidates(str(record.common_name or ""))
        inferred = candidates.get(pattern_key) or candidates.get("single") or "-"
        table.add_row(str(idx), str(record.common_name), str(inferred))

    if len(records) > max_rows:
        table.caption = (
            f"Showing first {max_rows}. {len(records) - max_rows} additional rows omitted."
        )

    print_panel_with_table(table, border_style=COLOR_MUTED)


def _select_recommended_username_pattern(
    ranked_patterns: list[tuple[str, int]],
) -> str | None:
    """Return the strongest recommended username pattern, if any."""
    if not ranked_patterns:
        return None

    top_pattern, top_score = ranked_patterns[0]
    if len(ranked_patterns) == 1 or (
        len(ranked_patterns) > 1 and ranked_patterns[1][1] < top_score
    ):
        return top_pattern
    return None


def _choose_username_pattern(
    shell: LdapShell,
    *,
    domain: str,
    unresolved_records: list[LDAPAnonymousUserRecord],
    ranked_patterns: list[tuple[str, int]],
) -> str:
    """Choose a naming pattern for CN-only LDAP user objects."""
    if not unresolved_records:
        return "first.last"

    recommended_pattern = _select_recommended_username_pattern(ranked_patterns)
    if recommended_pattern:
        print_info_debug(
            f"[ldap] Recommended username pattern {recommended_pattern} from "
            f"{ranked_patterns[0][1]} confirmed anonymous LDAP match(es)."
        )

    pattern_keys: list[str] = []
    seen_pattern_keys: set[str] = set()
    for record in unresolved_records:
        candidates = build_username_pattern_candidates(str(record.common_name or ""))
        for pattern_key in candidates:
            if pattern_key in seen_pattern_keys:
                continue
            seen_pattern_keys.add(pattern_key)
            pattern_keys.append(pattern_key)

    if recommended_pattern and recommended_pattern not in seen_pattern_keys:
        pattern_keys.append(recommended_pattern)
        seen_pattern_keys.add(recommended_pattern)

    if "single" not in seen_pattern_keys:
        pattern_keys.append("single")
        seen_pattern_keys.add("single")

    example_record = next(
        (
            record
            for record in unresolved_records
            if len(build_username_pattern_candidates(str(record.common_name or ""))) > 1
        ),
        unresolved_records[0],
    )
    sample_cn = str(example_record.common_name or "").strip() or "John Smith"
    options: list[str] = []
    for pattern_key in pattern_keys:
        label = format_username_pattern_option(pattern_key, sample_cn)
        if pattern_key == recommended_pattern:
            label = f"{label} (Recommended)"
        options.append(label)

    selector = getattr(shell, "_questionary_select", None)
    marked_domain = mark_sensitive(domain, "domain")
    if selector and not getattr(shell, "auto", False):
        if recommended_pattern:
            if Confirm.ask(
                (
                    f"Use the recommended username format "
                    f"'{USERNAME_PATTERN_LABELS.get(recommended_pattern, recommended_pattern)}' "
                    f"for {marked_domain}?"
                ),
                default=True,
            ):
                return recommended_pattern

        while True:
            default_idx = 0
            if recommended_pattern and recommended_pattern in pattern_keys:
                default_idx = pattern_keys.index(recommended_pattern)
            idx = selector(
                (
                    f"Anonymous LDAP exposed CN-only users in {marked_domain}. "
                    "Select the username format to validate via Kerberos:"
                ),
                options,
                default_idx,
            )
            chosen_pattern = recommended_pattern or pattern_keys[0]
            if idx is not None and 0 <= idx < len(pattern_keys):
                chosen_pattern = pattern_keys[idx]

            _display_ldap_anonymous_pattern_preview(
                unresolved_records,
                pattern_key=chosen_pattern,
            )
            if Confirm.ask(
                "Use this inferred username format for Kerberos validation?",
                default=True,
            ):
                return chosen_pattern

    if recommended_pattern:
        return recommended_pattern

    default_pattern = pattern_keys[0] if pattern_keys else "first.last"
    print_info_debug(
        f"[ldap] Falling back to default username pattern {default_pattern} for "
        f"anonymous LDAP CN inference in {domain}."
    )
    return default_pattern


def _save_ldap_anonymous_inventory_json(
    shell: LdapShell,
    records: list[LDAPAnonymousUserRecord],
    domain: str,
) -> Optional[str]:
    """Persist anonymous LDAP user inventory for troubleshooting."""
    if not records:
        return None

    try:
        workspace_cwd = shell._get_workspace_cwd()
        ldap_dir = domain_subpath(
            workspace_cwd, shell.domains_dir, domain, shell.ldap_dir
        )
        os.makedirs(ldap_dir, exist_ok=True)
        json_file = os.path.join(ldap_dir, "anonymous_inventory.json")
        with open(json_file, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "domain": domain,
                    "count": len(records),
                    "users": [record.to_dict() for record in records],
                },
                handle,
                indent=2,
                ensure_ascii=False,
            )
        return json_file
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_warning(f"Failed to save anonymous LDAP inventory: {exc}")
        return None


def _display_ldap_anonymous_unresolved_users(
    records: list[LDAPAnonymousUserRecord],
    *,
    pattern_key: str | None = None,
    max_rows: int = 20,
) -> None:
    """Display CN-only users that still need username inference."""
    unresolved = [
        record
        for record in records
        if not str(record.samaccountname or "").strip()
        and str(record.common_name or "").strip()
    ]
    if not unresolved:
        return

    from adscan_core.theme import COLOR_AMBER, COLOR_MUTED, COLOR_STEEL

    table = Table(
        title=f"! Unresolved LDAP user objects ({len(unresolved)})",
        show_header=True,
        header_style=f"bold {COLOR_AMBER}",
    )
    table.add_column("", width=2, justify="center")
    table.add_column("#", style=COLOR_MUTED, width=4, justify="right")
    table.add_column("CN", style=COLOR_STEEL, max_width=32)
    if pattern_key:
        table.add_column("Inferred username", max_width=40)

    for idx, record in enumerate(unresolved[: max(1, max_rows)], 1):
        if pattern_key:
            candidates = build_username_pattern_candidates(
                str(record.common_name or "")
            )
            inferred = candidates.get(pattern_key) or candidates.get("single") or "-"
            table.add_row(
                f"[{COLOR_AMBER}]?[/{COLOR_AMBER}]",
                str(idx),
                str(record.common_name),
                str(inferred),
            )
        else:
            table.add_row(
                f"[{COLOR_AMBER}]?[/{COLOR_AMBER}]",
                str(idx),
                str(record.common_name),
            )

    if len(unresolved) > max_rows:
        table.caption = (
            f"Showing first {max_rows}. {len(unresolved) - max_rows} additional rows omitted."
        )

    print_panel_with_table(table, border_style=COLOR_AMBER)
    if pattern_key:
        print_info(
            f"[{COLOR_AMBER}]Next:[/{COLOR_AMBER}] kerbrute these inferred CNs against the KDC to "
            "promote them from CN candidates to confirmed sAMAccountNames."
        )


def _display_ldap_anonymous_confirmed_users(
    usernames: list[str], *, max_rows: int = 20
) -> None:
    """Display usernames confirmed directly through anonymous LDAP."""
    if not usernames:
        return

    from adscan_core.theme import COLOR_CRIMSON, COLOR_MUTED, COLOR_SAGE

    # This is a high-value finding: anonymous LDAP exposed enabled usernames.
    # The row should JUMP. Verdict-first headline with crimson glyph.
    print_info(
        f"[{COLOR_CRIMSON}]* Anonymous LDAP leaked {len(usernames)} enabled sAMAccountName(s)[/{COLOR_CRIMSON}] "
        f"  -> usable for AS-REP roasting, password spraying, and Kerberos pre-auth probing."
    )

    table = Table(
        title=f"* Anonymous LDAP confirmed enabled users ({len(usernames)})",
        show_header=True,
        header_style=f"bold {COLOR_CRIMSON}",
    )
    table.add_column("", width=2, justify="center")
    table.add_column("#", style=COLOR_MUTED, width=4, justify="right")
    table.add_column("sAMAccountName", style=COLOR_SAGE, max_width=40)

    shown = usernames[: max(1, max_rows)]
    for idx, username in enumerate(shown, 1):
        table.add_row(
            f"[{COLOR_CRIMSON}]*[/{COLOR_CRIMSON}]",
            str(idx),
            username,
        )

    if len(usernames) > max_rows:
        table.caption = (
            f"Showing first {max_rows}. {len(usernames) - max_rows} additional rows omitted."
        )

    print_panel_with_table(table, border_style=COLOR_CRIMSON)
    print_info(
        f"[{COLOR_CRIMSON}]Next:[/{COLOR_CRIMSON}] feed this list into AS-REP roasting and a targeted "
        "password-spray round before falling back to wordlist guessing."
    )


def _is_likely_ldap_user_candidate(record: LDAPAnonymousUserRecord) -> bool:
    """Best-effort filter for CN-only objects discovered via anonymous LDAP.

    The broad ``(objectClass=*)`` query can expose users without attributes, but
    it also exposes groups, containers and system objects. We keep the heuristic
    intentionally conservative and let Kerberos validation decide the final set.
    """
    dn = str(record.distinguished_name or "").strip()
    common_name = str(record.common_name or "").strip()
    if not dn or not common_name:
        return False

    dn_lower = dn.casefold()
    cn_lower = common_name.casefold()
    if dn.startswith("DC="):
        return False
    if common_name.endswith("$"):
        return False
    if "cn=configuration," in dn_lower or "cn=schema," in dn_lower:
        return False
    if cn_lower in _LDAP_NON_USER_DISCOVERY_CNS:
        return False
    if cn_lower in _LDAP_NOISY_USER_CANDIDATE_CNS:
        return False

    # Keep likely user placements: standard Users container or custom OUs.
    return ",cn=users," in f",{dn_lower}" or ",ou=" in f",{dn_lower}"


@dataclass
class _CNInferenceResult:
    """Structured result from CN-only anonymous LDAP username inference."""

    validated: set[str]
    inferred_pattern: str | None
    pattern_score: int
    known_users_analyzed: int
    rows: list[tuple[str, str, bool]]
    cn_only_count: int


def _infer_username_pattern_from_known_users(
    known_users: list,
) -> tuple[str | None, int, int]:
    """Infer the dominant username format from users that have both a DN and SAM.

    Returns a three-tuple: ``(pattern_key, score, analyzed_count)``.
    ``pattern_key`` is ``None`` when inference is inconclusive.
    """
    from adscan_core.username_patterns import rank_username_patterns_from_observed_pairs

    pairs: list[tuple[str, str]] = []
    for u in known_users:
        dn = str(getattr(u, "distinguished_name", "") or "")
        sam = str(getattr(u, "samaccountname", "") or "").strip()
        if not dn or not sam:
            continue
        cn_part = dn.split(",")[0]
        if cn_part.upper().startswith("CN="):
            display_name = cn_part[3:].strip()
            if display_name:
                pairs.append((display_name, sam))

    if not pairs:
        return None, 0, 0

    ranked = rank_username_patterns_from_observed_pairs(pairs)
    if not ranked:
        return None, 0, len(pairs)

    top_pattern, top_score = ranked[0]
    print_info_debug(
        f"[ldap-cn-inference] pattern inference from {len(pairs)} known users: "
        f"dominant={top_pattern!r} score={top_score} "
        f"(all: {[(p, s) for p, s in ranked[:3]]})"
    )
    return top_pattern, top_score, len(pairs)


def _validate_ldap_anonymous_username_candidates(
    shell: LdapShell,
    domain: str,
    candidates: list[str],
    *,
    known_users: list | None = None,
) -> _CNInferenceResult:
    """Validate inferred usernames with Kerberos pre-auth enumeration.

    When ``known_users`` (list of LDAPActiveUser) is supplied, the dominant
    username format is inferred from their DN+SAM pairs and applied to each
    CN-only candidate to generate format-correct wordlist entries.  Without
    known_users the function falls back to naive normalization — which only
    works when the CN itself is the username.

    Returns a :class:`_CNInferenceResult` with the full inference context so
    the caller can render a rich diagnostic panel.
    """
    from adscan_core.username_patterns import build_username_pattern_candidates

    cn_only_count = len(candidates)
    print_info_debug(
        f"[ldap-cn-inference] {cn_only_count} CN-only record(s) to validate: {candidates}"
    )

    inferred_pattern, pattern_score, known_users_analyzed = (
        _infer_username_pattern_from_known_users(known_users or [])
    )

    cn_to_candidate: dict[str, str] = {}
    candidate_set: set[str] = set()
    for cn_name in candidates:
        if not cn_name:
            continue
        if inferred_pattern:
            variants = build_username_pattern_candidates(
                cn_name, pattern_keys=[inferred_pattern]
            )
            generated = set(v for v in variants.values() if v)
            if not generated:
                generated = {normalize_username_candidate(cn_name)}
        else:
            variants = build_username_pattern_candidates(cn_name)
            generated = set(v for v in variants.values() if v)
            if not generated:
                generated = {normalize_username_candidate(cn_name)}

        chosen = sorted(generated)[0] if generated else normalize_username_candidate(cn_name)
        cn_to_candidate[cn_name] = chosen
        print_info_debug(
            f"[ldap-cn-inference] CN={cn_name!r} pattern={inferred_pattern!r} → {sorted(generated)}"
        )
        candidate_set.update(generated)

    normalized = sorted(c for c in candidate_set if c)
    empty_result = _CNInferenceResult(
        validated=set(),
        inferred_pattern=inferred_pattern,
        pattern_score=pattern_score,
        known_users_analyzed=known_users_analyzed,
        rows=[],
        cn_only_count=cn_only_count,
    )

    if not normalized:
        return empty_result

    kerbrute_path = os.path.join(TOOLS_INSTALL_DIR, "kerbrute", "kerbrute")
    if not os.path.isfile(kerbrute_path) or not os.access(kerbrute_path, os.X_OK):
        print_warning(
            "kerbrute is not available; skipping validation of anonymous LDAP username candidates."
        )
        return empty_result

    workspace_cwd = shell._get_workspace_cwd()
    kerberos_dir = domain_subpath(
        workspace_cwd, shell.domains_dir, domain, shell.kerberos_dir
    )
    os.makedirs(kerberos_dir, exist_ok=True)
    wordlist_path = Path(os.path.join(kerberos_dir, "ldap_anonymous_candidates.txt"))
    output_file = Path(
        os.path.join(kerberos_dir, "ldap_anonymous_candidate_validation.log")
    )
    wordlist_path.write_text("\n".join(normalized) + "\n", encoding="utf-8")

    print_info(
        f"Validating {len(normalized)} inferred LDAP anonymous username candidate(s) via Kerberos."
    )
    enum_service = EnumerationService()
    executor = shell._get_service_executor()
    validated_raw = enum_service.kerberos.enumerate_users_kerberos(
        domain=domain,
        pdc=shell.domains_data[domain]["pdc"],
        wordlist=str(wordlist_path),
        kerbrute_path=kerbrute_path,
        output_file=output_file,
        executor=executor,
        spawn=shell._get_service_spawner(),
        scan_id=None,
        timeout=300,
    )
    validated_set = {
        normalize_username_candidate(username) for username in validated_raw if username
    }
    print_info_debug(
        f"[ldap] Validated {len(validated_set)}/{len(normalized)} inferred username "
        "candidate(s) through Kerberos."
    )

    rows: list[tuple[str, str, bool]] = [
        (cn_name, candidate, candidate in validated_set)
        for cn_name, candidate in cn_to_candidate.items()
    ]

    return _CNInferenceResult(
        validated=validated_set,
        inferred_pattern=inferred_pattern,
        pattern_score=pattern_score,
        known_users_analyzed=known_users_analyzed,
        rows=rows,
        cn_only_count=cn_only_count,
    )


def run_post_user_discovery_followups(
    shell: LdapShell,
    domain: str,
    *,
    source: str,
    pre_with_users_callback: Callable[[], None] | None = None,
    pre_with_users_step: str | None = None,
    allow_with_users: bool = True,
) -> None:
    """Run the shared follow-up workflow after recovering domain users.

    This centralizes the transition from "we recovered users" to optional
    pre-follow-up steps (for example LDAP/SMB descriptions) and finally the
    legacy ``with_users`` flow. The helper avoids duplicated AS-REP/spraying
    prompts by skipping the ``with_users`` transition when the domain is
    already authenticated or already marked as ``with_users``.
    """

    def _capture_followup_event(action: str, **extra: object) -> None:
        """Emit a telemetry event for post-user-discovery flow transitions."""
        try:
            properties: dict[str, object] = {
                "source": source,
                "action": action,
                "auth_type": shell.domains_data.get(domain, {}).get("auth", "unknown"),
                "pre_with_users_step": pre_with_users_step,
                "allow_with_users": allow_with_users,
                "scan_mode": getattr(shell, "scan_mode", None),
                "workspace_type": getattr(shell, "type", None),
                "auto_mode": getattr(shell, "auto", False),
            }
            properties.update(build_lab_event_fields(shell=shell, include_slug=True))
            properties.update(extra)
            telemetry.capture("user_discovery_followups", properties)
        except Exception as exc:  # pragma: no cover - best effort telemetry
            telemetry.capture_exception(exc)

    current_auth = str(shell.domains_data.get(domain, {}).get("auth") or "unknown")
    print_info_debug(
        f"[user_discovery_followups] source={source} domain={domain} "
        f"auth_before={current_auth} allow_with_users={allow_with_users}"
    )
    _capture_followup_event("start", auth_before=current_auth)

    if pre_with_users_callback is not None:
        step_name = pre_with_users_step or "pre_with_users_callback"
        print_info_debug(
            f"[user_discovery_followups] source={source} domain={domain} "
            f"running_pre_step={step_name}"
        )
        pre_with_users_callback()
        current_auth = str(shell.domains_data.get(domain, {}).get("auth") or "unknown")
        print_info_debug(
            f"[user_discovery_followups] source={source} domain={domain} "
            f"auth_after_pre_step={current_auth}"
        )
        _capture_followup_event(
            "pre_step_completed",
            auth_after=current_auth,
            executed_pre_step=step_name,
        )

    if not allow_with_users:
        print_info_debug(
            f"[user_discovery_followups] source={source} domain={domain} "
            "with_users_disabled_for_this_flow=True"
        )
        _capture_followup_event("skip_with_users", reason="allow_with_users_false")
        return

    if current_auth in {"auth", "pwned"}:
        print_info_debug(
            f"[user_discovery_followups] source={source} domain={domain} "
            f"skipping_with_users_due_to_auth={current_auth}"
        )
        _capture_followup_event(
            "skip_with_users",
            reason="domain_already_authenticated",
            auth_after=current_auth,
        )
        return

    if current_auth == "with_users":
        print_info_debug(
            f"[user_discovery_followups] source={source} domain={domain} "
            "skipping_with_users_already_active=True"
        )
        _capture_followup_event(
            "skip_with_users",
            reason="with_users_already_active",
            auth_after=current_auth,
        )
        return

    print_info_debug(
        f"[user_discovery_followups] source={source} domain={domain} "
        "launching_with_users=True"
    )
    _capture_followup_event("launch_with_users", auth_after=current_auth)
    shell.do_enum_with_users(domain)


def _run_ldap_anonymous_followups(shell: LdapShell, domain: str) -> None:
    """Expand an anonymous LDAP bind into native Phase 2.5 enrichment.

    This was historically a NetExec-backed flow (``nxc ldap -u "" -p "" -M
    user-desc -M get-desc-users …``) wrapped around a sync badldap helper that
    crashed with ``Connected, but not bound.`` on hardened DCs because the
    NONE-protocol path never issued a real anonymous SIMPLE bind.

    The Phase 2.5 enrichment service (``unauth_enrichment_service``) now
    covers the same surface natively (anonymous LDAP active users with a real
    ``ldap+simple://`` bind, SAMR over null SMB, GPP cpassword harvest with
    AES decryption). The unauth scan flow calls it directly. This function
    exists so that callers OUTSIDE the unauth flow (e.g. the standalone
    ``ldap_anonymous`` command in this module) get the same coverage.

    Behaviour:
      * Builds a one-shot ``UnauthEnrichmentConfig`` from ``shell.domains_data``.
      * Runs the native enrichment.
      * Routes results through ``_apply_unauth_enrichment_results`` so the
        same artifacts (LDAP active users JSON, SAMR users JSON, GPP leaks
        as credentials + technical findings) are persisted.
    """
    domain_data = shell.domains_data.get(domain, {}) or {}
    pdc = str(domain_data.get("pdc") or "").strip()
    if not pdc:
        print_warning(
            "[ldap-anon] Cannot run native enrichment: no PDC recorded for domain"
        )
        return

    smb_null_open = bool(domain_data.get("smb_null_session"))
    workspace_dir = shell.current_workspace_dir or os.getcwd()

    try:
        from adscan_internal.services.unauth_enrichment_service import (
            UnauthEnrichmentConfig,
            run_unauth_enrichment,
        )

        config = UnauthEnrichmentConfig(
            domain=domain,
            dc_ip=pdc,
            smb_null_open=smb_null_open,
            ldap_anon_open=True,
            smb_readable_targets=[pdc] if smb_null_open else [],
            workspace_dir=workspace_dir,
            timeout=60,
        )
        results = run_unauth_enrichment(config)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error(f"Native LDAP anonymous enrichment failed: {exc}")
        return

    try:
        from adscan_internal.cli.scan import _apply_unauth_enrichment_results

        _apply_unauth_enrichment_results(shell, domain=domain, results=results)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning(f"Failed to apply enrichment results for {domain}: {exc}")


def run_ldap_anonymous(shell: LdapShell, domain: str) -> dict[str, object] | None:
    """Test anonymous LDAP access via the native probe service.

    The netexec_path guard is gone — anonymous LDAP probing is fully native
    (via :func:`_run_ldap_anonymous_followups` which uses the unauth enrichment
    service and ``ldap+simple://`` bind, not netexec).
    """
    if domain not in shell.domains_data:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"Unknown domain: {marked_domain}")
        return None

    if shell.type == "ctf" and shell.domains_data[domain].get("auth") in [
        "auth",
        "pwned",
    ]:
        return None

    print_operation_header(
        "Anonymous LDAP Access Test",
        details={
            "Domain": domain,
            "PDC": shell.domains_data[domain]["pdc"],
            "Authentication": "Anonymous (Empty Credentials)",
            "Protocol": "LDAP",
        },
        icon="🔓",
    )

    # Native probe — no netexec required.
    enum_service = EnumerationService()
    result = enum_service.ldap.test_anonymous_access(
        pdc=shell.domains_data[domain]["pdc"],
        netexec_path="",  # compat shim — unused by native implementation
        timeout=60,
    )

    accessible = bool(result.get("accessible"))
    if accessible:
        print_success("Anonymous LDAP bind succeeded.")
        shell.update_report_field(domain, "ldap_anonymous", True)
        try:
            from adscan_internal.services.attack_graph_service import (
                upsert_ldap_anonymous_bind_entry_edge,
            )

            upsert_ldap_anonymous_bind_entry_edge(
                shell,
                domain,
                status="success",
                notes={
                    "source": "ldap_anonymous",
                    "protocol": "ldap",
                    "authentication": "anonymous_bind",
                    "pdc": shell.domains_data[domain]["pdc"],
                },
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
        _run_ldap_anonymous_followups(shell, domain)
        try:
            from adscan_core.reporting.technical_report import record_technical_finding

            # Gate the evidence block on whether domain_data confirms the bind.
            record_technical_finding(
                shell,
                domain,
                key="ldap_anonymous",
                value=True,
                details={
                    "pdc": shell.domains_data[domain]["pdc"],
                },
            )
        except Exception as exc:  # pragma: no cover
            if not handle_optional_report_service_exception(
                exc,
                action="Technical finding sync",
                debug_printer=print_info_debug,
                prefix="[ldap-anon]",
            ):
                telemetry.capture_exception(exc)
    else:
        print_warning("Anonymous LDAP bind denied.")
        shell.update_report_field(domain, "ldap_anonymous", False)

    return result


def run_ldap_computers(shell: LdapShell, target_domain: str) -> list[str] | None:
    """Enumerate LDAP computers (authenticated) via a native badldap search.

    Prefers the persisted collector inventory (``inventory/computers.json``)
    when the native collector has already enumerated the domain; otherwise
    falls back to a live native ``(objectCategory=computer)`` LDAP query.
    """
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return None

    if not shell.domain or shell.domain not in shell.domains_data:
        print_error("No authenticated domain selected. Select a domain first.")
        return None

    username = shell.domains_data[shell.domain].get("username")
    password = shell.domains_data[shell.domain].get("password") or shell.domains_data[
        shell.domain
    ].get("nt_hash")
    if not username or not password:
        print_error(
            "Missing credentials (username/password) for LDAP computer enumeration."
        )
        return None

    output_rel = domain_relpath(shell.domains_dir, target_domain, "computers.txt")

    # ── Source selection: prefer the persisted collector inventory ──────────
    # The native LDAP collector already enumerated every computer object into
    # ``inventory/computers.json``. When that snapshot exists, reuse it and
    # skip the live LDAP query entirely; otherwise fall back to a native search.
    inventory_hostnames = _load_computer_hostnames_from_inventory(shell, target_domain)
    if inventory_hostnames is not None:
        print_operation_header(
            "LDAP Computer Enumeration",
            details={
                "Target Domain": target_domain,
                "Auth Domain": shell.domain,
                "Username": username,
                "Source": "Collector inventory (computers.json)",
                "Output": output_rel,
            },
            icon="💻",
        )
        hostnames = inventory_hostnames
    else:
        print_operation_header(
            "LDAP Computer Enumeration",
            details={
                "Target Domain": target_domain,
                "Auth Domain": shell.domain,
                "Username": username,
                "LDAP Server": shell.domains_data[target_domain]["pdc"],
                "Mode": "Native badldap (single paged search)",
                "Output": output_rel,
            },
            icon="💻",
        )

        # Posture wiring: let the auth planner skip a doomed LDAPS:636 connect
        # when the workspace already knows LDAPS is unavailable, and let a fresh
        # 636 transport failure record the signal for downstream consumers.
        posture_snapshot = None
        posture_sink = None
        domains_data = getattr(shell, "domains_data", None)
        if domains_data is not None:
            try:
                from adscan_internal import get_console
                from adscan_internal.cli.widgets.intelligence_update import (
                    render_intelligence_update,
                )
                from adscan_internal.services.domain_posture import get_posture
                from adscan_internal.services.posture_sink import (
                    make_workspace_posture_sink,
                )

                posture_snapshot = get_posture(domains_data, domain=target_domain)
                posture_sink = make_workspace_posture_sink(
                    domains_data,
                    on_finding=lambda finding: get_console().print(
                        render_intelligence_update(finding)
                    ),
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_info_debug(f"[ldap-computers] posture wiring skipped: {exc}")

        enum_service = EnumerationService()
        computers = enum_service.ldap.enumerate_computers(
            domain=target_domain,
            pdc=shell.domains_data[target_domain]["pdc"],
            auth_mode=AuthMode.AUTHENTICATED,
            username=username,
            password=password,
            scan_id=None,
            timeout=120,
            posture_snapshot=posture_snapshot,
            posture_sink=posture_sink,
        )

        hostnames = [
            c.dns_hostname or c.hostname
            for c in computers
            if (c.dns_hostname or c.hostname)
        ]
    shell._write_domain_list_file(target_domain, "computers.txt", hostnames)
    shell._display_items(hostnames, "Computers")

    try:
        properties = {
            "count": len(hostnames),
            "scan_mode": getattr(shell, "scan_mode", None),
            "auth_type": shell.domains_data[target_domain].get("auth", "unknown"),
        }
        properties.update(build_lab_event_fields(shell=shell, include_slug=True))
        telemetry.capture("ldap_computers_enumerated", properties)
    except Exception as e:  # pragma: no cover
        telemetry.capture_exception(e)

    return hostnames



def _run_enum_domain_auth(
    shell: LdapShell,
    domain: str,
    *,
    stop_after_phase: int | None,
) -> None:
    """Shared authenticated domain scan flow with optional early stop."""
    from adscan_internal.rich_output import ScanProgressTracker, mark_sensitive

    # Mint a fresh timeline run id at the top so every phase span emitted
    # below — Topology, Collection, the analysis pipeline — shares the same
    # grouping key. ``adscan show timeline`` and the web dashboard use this
    # to render one run per row group.
    try:
        from adscan_internal.services.scan_timeline import begin_timeline_run

        begin_timeline_run(shell)
    except Exception:  # noqa: BLE001
        pass

    username = shell.domains_data.get(domain, {}).get("username", "N/A")
    pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")
    is_dev_session = os.getenv("ADSCAN_SESSION_ENV", "").strip().lower() == "dev"
    native_graph_enabled = True
    graph_mode = (
        "Native Graph"
        if native_graph_enabled
        else "Collector Selector"
        if is_dev_session
        else "Legacy Graph Collector"
    )
    # Resume / Refresh / Replay / Inspect — the operator's intent when prior
    # results exist drives whether we re-collect, re-analyse, or just resume
    # downstream phases. The decision is taken once here so the rest of the
    # flow has a single source of truth for what to skip.
    workspace_action: str | None = None
    if stop_after_phase is None:
        from adscan_internal.cli.workspace_resume_panel import (
            resolve_workspace_action,
        )
        from adscan_internal.services.workspace_resume import (
            WorkspaceAction,
            inspect_workspace,
        )

        snapshot = inspect_workspace(shell, domain)
        print_info_debug(
            f"[ldap._run_enum_domain_auth] snapshot for {domain}: "
            f"has_attack_graph={snapshot.has_attack_graph} "
            f"phase1_complete={snapshot.phase1_complete} "
            f"domain_auth={snapshot.domain_auth!r}"
        )
        if snapshot.has_attack_graph or snapshot.phase1_complete:
            # One-shot resume-offer collapse: when the operator already chose
            # "Resume" in the incomplete-scan offer (workspace_resume_offer), the
            # workspace-action panel and the phase-scope prompt below are the same
            # decision asked twice. Read-and-clear the flag so it fires EXACTLY
            # once — a later direct enum_domain_auth / start_auth in the same
            # session still gets the genuine four-action panel.
            predecided = getattr(shell, "_resume_action_predecided", None)
            if predecided is not None:
                try:
                    shell._resume_action_predecided = None
                except Exception:  # noqa: BLE001 - clearing must never break the scan
                    pass

            if predecided is WorkspaceAction.RESUME:
                # Skip resolve_workspace_action (the workspace-action panel) AND
                # maybe_prompt_phase_preset (the phase-scope prompt): the offer we
                # already showed carries the orientation + the RESUME choice, and
                # the preset's default ("Run all phases") equals the resume
                # default, so skipping is behaviour-identical minus the click.
                # Still record the decision on the event sink so the web dashboard
                # sees the same RESUME the operator made.
                from adscan_internal.cli.workspace_resume_panel import (
                    _emit_action_event,
                )

                action = WorkspaceAction.RESUME
                workspace_action = action.value
                _emit_action_event(action, snapshot, source="resume_offer")
                print_info_debug(
                    "[ldap._run_enum_domain_auth] resume-offer predecided RESUME: "
                    "skipping workspace-action panel + phase-scope prompt"
                )
            else:
                action, _ = resolve_workspace_action(shell, domain, snapshot=snapshot)
                workspace_action = action.value
                print_info_debug(
                    f"[ldap._run_enum_domain_auth] resolved action={action.value!r} for {domain}"
                )

                if action is WorkspaceAction.INSPECT:
                    print_info(
                        "Workspace opened for inspection. Run `adscan show` "
                        "or re-invoke the scan when ready."
                    )
                    return

                # Optional power-user phase preset — offered once here (interactive
                # only, default all phases) so it applies to whichever of Resume /
                # Refresh / Replay runs below. No-op non-interactively.
                from adscan_internal.cli.start_resume_frontdoor import (
                    maybe_prompt_phase_preset,
                )

                maybe_prompt_phase_preset(shell)

            if action is WorkspaceAction.RESUME:
                # Skip collection entirely, jump to analysis with cached graph.
                print_info_debug(
                    "[ldap._run_enum_domain_auth] RESUME branch: clock sync + run_enumeration (no collection)"
                )
                try:
                    shell.do_sync_clock_with_pdc(domain)  # type: ignore[attr-defined]
                except Exception as exc:  # noqa: BLE001
                    print_info_debug(f"[DEBUG] Clock sync skipped due to error: {exc}")
                shell.domains_data.setdefault(domain, {})["_workspace_action"] = (
                    workspace_action
                )
                shell.run_enumeration(domain)  # type: ignore[attr-defined]
                return

            if action is WorkspaceAction.REPLAY:
                # Keep the cached graph but force the analysis pipeline to
                # re-run end to end (new attack rules, updated reporting, ...).
                print_info_debug(
                    "[ldap._run_enum_domain_auth] REPLAY branch: clock sync + run_enumeration (no collection)"
                )
                shell.domains_data.setdefault(domain, {})["phase1_complete"] = False
                shell.domains_data[domain]["_workspace_action"] = workspace_action
                # Replay is a deliberate end-to-end re-run — drop the crash-resume
                # checkpoint so every phase runs (not just the ones a prior
                # interrupted run had not reached).
                from adscan_internal.services.scan_progress import (
                    reset_scan_progress,
                )

                reset_scan_progress(shell, domain)
                try:
                    shell.do_sync_clock_with_pdc(domain)  # type: ignore[attr-defined]
                except Exception as exc:  # noqa: BLE001
                    print_info_debug(f"[DEBUG] Clock sync skipped due to error: {exc}")
                shell.run_enumeration(domain)  # type: ignore[attr-defined]
                return

            # REFRESH falls through to the full collection flow below, but we
            # invalidate phase1_complete so the analysis pipeline re-runs too.
            print_info_debug(
                "[ldap._run_enum_domain_auth] REFRESH branch: falling through to tracker + collection flow"
            )
            shell.domains_data.setdefault(domain, {})["phase1_complete"] = False
            shell.domains_data[domain]["_workspace_action"] = workspace_action
            # Refresh re-collects + re-analyses end to end — drop the checkpoint
            # so the resume gate does not skip phases on this deliberate re-run.
            from adscan_internal.services.scan_progress import reset_scan_progress

            reset_scan_progress(shell, domain)

    # Clock sync must be done against the KDC/realm used for Kerberos authentication.
    # In multi-domain setups, we may be scanning a target domain without having
    # credentials for it, while still using Kerberos tickets from `shell.domain`.
    sync_domain = domain
    try:
        has_target_creds = bool(
            shell.domains_data.get(domain, {}).get("username")
            and shell.domains_data.get(domain, {}).get("username") != "N/A"
        )
    except Exception:
        has_target_creds = False

    if not has_target_creds and getattr(shell, "domain", None):
        sync_domain = shell.domain  # type: ignore[attr-defined]

    if sync_domain != domain:
        print_info_debug(
            "[DEBUG] Authenticated scan clock sync domain mismatch: "
            f"target_domain={mark_sensitive(domain, 'domain')}, "
            f"sync_domain={mark_sensitive(sync_domain, 'domain')}"
        )

    # Initialize progress tracker for authenticated scan.
    print_info_debug(
        f"[ldap._run_enum_domain_auth] entering tracker section for {domain}: "
        f"workspace_action={workspace_action!r} sync_domain={sync_domain}"
    )
    tracker = ScanProgressTracker(
        "Authenticated Domain Scan",
        total_steps=2,
    )

    # Start workflow with detailed information
    tracker.start(
        details={
            "Domain": domain,
            "PDC": pdc,
            "Username": username,
            "Graph Mode": graph_mode,
        }
    )

    # Step 1: Clock Synchronization
    sync_details = "Syncing with domain PDC"
    if sync_domain != domain:
        sync_details = (
            f"Syncing with auth-domain PDC ({mark_sensitive(sync_domain, 'domain')})"
        )
    tracker.start_step("Clock Synchronization", details=sync_details)
    try:
        shell.do_sync_clock_with_pdc(sync_domain)  # type: ignore[attr-defined]
        tracker.complete_step(details="Clock synchronized successfully")
    except Exception as exc:  # noqa: BLE001
        tracker.fail_step(details=f"Clock sync error: {str(exc)[:50]}")

    # Step 2: Graph Collection
    collection_details = (
        "Running ADscan native graph collector"
        if native_graph_enabled
        else "Running selected graph collector"
        if is_dev_session
        else "Running legacy graph collector"
    )
    tracker.start_step(
        "Graph Collection",
        details=collection_details,
    )

    # Surface graph collection as a top-level chapter (numbered alongside
    # Topology & Trusts and the analysis pipeline) and capture deltas to
    # the workspace timeline so the operator and the web service both see
    # the +nodes/+edges produced by this phase.
    try:
        from adscan_internal.services.scan_phases import emit_chapter
        from adscan_internal.services.scan_timeline import phase_span

        _scan_type = getattr(shell, "type", "default")
        emit_chapter("domain_collection", scan_type=_scan_type)
        _collection_phase_cm = phase_span(
            shell,
            domain,
            phase_id="domain_collection",
            phase_title="Domain Collection",
        )
        _collection_phase_cm.__enter__()
    except Exception:  # noqa: BLE001
        _collection_phase_cm = None

    try:

        def _continue_after_collection() -> None:
            shell.run_enumeration(  # type: ignore[attr-defined]
                domain,
                stop_after_phase=stop_after_phase,
            )

        collector_results = shell.ask_for_graph_collection(  # type: ignore[attr-defined]
            domain,
            callback=_continue_after_collection,
        )
        if collector_results == []:
            tracker.complete_step(
                details="Graph collection completed; continuing with Phase 1"
            )
        else:
            tracker.complete_step(details="Graph collection completed")
    except Exception as exc:  # noqa: BLE001
        tracker.fail_step(details=f"Graph collection error: {str(exc)[:50]}")
    finally:
        try:
            if _collection_phase_cm is not None:
                _collection_phase_cm.__exit__(None, None, None)
        except Exception:  # noqa: BLE001
            pass

    # Print workflow summary
    tracker.print_summary()


def run_enum_domain_auth(shell: LdapShell, domain: str) -> None:
    """Perform an authenticated domain scan around ADscan's local graph collection."""
    _run_enum_domain_auth(shell, domain, stop_after_phase=None)


def run_enum_domain_auth_phase1(shell: LdapShell, domain: str) -> None:
    """Perform an authenticated domain scan through Phase 1 only."""
    _run_enum_domain_auth(shell, domain, stop_after_phase=1)


def run_enum_with_users(shell: LdapShell, domain: str) -> None:
    """Unauthenticated enumeration when only a user list is available.

    This preserves the legacy behaviour of ``do_enum_with_users``: mark the
    domain as ``with_users`` and then offer AS-REP roasting and password
    spraying. If the spraying step compromises the domain, it can update the
    auth state to ``auth``/``pwned`` which is respected by this flow.
    """
    shell.domains_data[domain]["auth"] = "with_users"
    shell.ask_for_asreproast(domain)  # type: ignore[attr-defined]
    if shell.domains_data[domain]["auth"] not in ["auth", "pwned"]:
        shell.ask_for_spraying(domain)  # type: ignore[attr-defined]




def run_ldap_admincount_and_signing(
    shell: LdapShell,
    *,
    domain: str,
    username: str,
    password: str,
    logging: bool = True,
) -> bool | None:
    """Check `adminCount` for a user via native LDAP, handling transport fallback.

    This helper keeps the legacy return contract:
      - ``True``  : adminCount == 1
      - ``False`` : adminCount != 1 (no error)
      - ``None``  : invalid credentials or execution failure
    """
    from adscan_internal import (
        print_info,
        print_success,
    )  # local import to avoid circular dependency

    if domain not in shell.domains_data:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"Domain {marked_domain} is not configured.")
        return None

    workspace_cwd = shell.current_workspace_dir or shell._get_workspace_cwd()
    ldap_dir_abs = domain_subpath(
        workspace_cwd,
        shell.domains_dir,
        domain,
        shell.ldap_dir,
    )
    os.makedirs(ldap_dir_abs, exist_ok=True)
    marked_domain = mark_sensitive(domain, "domain")
    marked_username = mark_sensitive(username, "user")
    if logging:
        print_info(f"Enumerating adminCount for {marked_username}.")
    try:
        from adscan_internal.services.ldap_query_service import (
            query_shell_ldap_attribute_values,
        )

        values = query_shell_ldap_attribute_values(
            shell,
            domain=domain,
            ldap_filter=f"(sAMAccountName={username})",
            attribute="adminCount",
            auth_username=str(shell.domains_data[domain]["username"]),
            auth_password=str(shell.domains_data[domain]["password"]),
            pdc=str(shell.domains_data[domain].get("pdc") or ""),
            prefer_kerberos=True,
            allow_ntlm_fallback=True,
            operation_name="adminCount check",
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[ldap-admincount] Native LDAP adminCount query failed for {marked_username}: "
            f"{mark_sensitive(str(exc), 'detail')}"
        )
        return None

    if values is None:
        return None

    for value in values:
        try:
            if int(str(value).strip()) == 1:
                if logging:
                    print_success(
                        f"User {marked_username} has adminCount=1 (likely privileged account)."
                    )
                return True
        except ValueError:
            continue

    if logging:
        print_error(
            f"The user {marked_username} does not have elevated privileges according to adminCount in domain {marked_domain}"
        )
    return False


def _group_names_from_memberof_dns(member_of_dns: list[str]) -> list[str]:
    """Extract group names from a list of ``memberOf`` distinguished names.

    ``CN=Domain Admins,CN=Users,DC=corp,DC=local`` -> ``Domain Admins``.

    Pure logic (no network) so it is unit-testable. The first RDN value of each
    DN is the group's common name; DNs with an escaped comma inside the CN are
    handled by only splitting on the first unescaped ``,``.

    Args:
        member_of_dns: Raw ``memberOf`` DN strings.

    Returns:
        De-duplicated, order-preserving list of group common names.
    """
    names: list[str] = []
    seen: set[str] = set()
    for dn in member_of_dns:
        text = str(dn or "").strip()
        if not text:
            continue
        # First RDN, respecting a backslash-escaped comma inside the CN value.
        first_rdn = re.split(r"(?<!\\),", text, maxsplit=1)[0].strip()
        if "=" in first_rdn:
            name = first_rdn.split("=", 1)[1].strip().replace("\\,", ",")
        else:
            name = first_rdn
        key = name.casefold()
        if name and key not in seen:
            seen.add(key)
            names.append(name)
    return names


def run_ldap_groupmembership_privileged(
    shell: LdapShell,
    *,
    domain: str,
    username: str,
    password: str,
) -> dict | None:
    """Native fallback privilege check via the user's direct ``memberOf``.

    Replaces the legacy ``nxc ldap -M groupmembership`` subprocess. Runs a
    single native badldap query (Kerberos-first with NTLM fallback, through the
    same posture-aware ``_run_native_ldap_query_attribute_values`` plumbing the
    recursive lookups use) for the principal's direct ``memberOf`` group DNs,
    then feeds the resolved group names into ``_parse_privileged_group_output``
    so the returned dict shape is identical to the legacy path. This is the
    non-recursive last-resort fallback reached only when the recursive in-chain
    lookups return no data.
    """
    if domain not in shell.domains_data:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"Domain {marked_domain} is not configured.")
        return None

    pdc = str(shell.domains_data[domain].get("pdc") or "").strip()
    if not pdc:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"No PDC recorded for domain {marked_domain}; cannot query group membership."
        )
        return None

    sanitized_user = str(username).replace("'", "\\'")
    member_query = (
        f"(&(|(objectClass=user)(objectClass=computer))"
        f"(sAMAccountName={sanitized_user}))"
    )
    member_of_dns = _run_native_ldap_query_attribute_values(
        shell,
        domain=domain,
        ldap_query=member_query,
        attribute="memberOf",
        auth_username=str(username),
        auth_password=str(password),
        pdc=pdc,
        timeout=300,
        retries=2,
        require_non_empty=False,
        prefer_kerberos=True,
        allow_ntlm_fallback=True,
        debug_label="Direct memberOf",
    )
    if member_of_dns is None:
        marked_username = mark_sensitive(username, "user")
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            "[ldap-groupmembership] Native memberOf query returned no data for "
            f"{marked_username}@{marked_domain}."
        )
        return None

    group_names = _group_names_from_memberof_dns(member_of_dns)
    raw_text = "\n".join(f"{name}@{domain}" for name in group_names)

    # Reuse the parser already exposed by the shell, when available.
    parser = getattr(shell, "_parse_privileged_group_output", None)
    if callable(parser):
        return parser(raw_text)

    return None


def _combined_completed_process_output(
    completed_process: subprocess.CompletedProcess[str] | None,
) -> str:
    """Return combined stdout/stderr text for a completed process."""
    if not isinstance(completed_process, subprocess.CompletedProcess):
        return ""
    return f"{completed_process.stdout or ''}\n{completed_process.stderr or ''}"


_EXACT_LDAP_TIMEOUT_STATE_ATTR = "_adscan_exact_ldap_timeout_state"


def clear_exact_ldap_connection_timeout_state(shell: object) -> None:
    """Clear the per-shell exact LDAP timeout state used by higher-level flows."""
    try:
        setattr(shell, _EXACT_LDAP_TIMEOUT_STATE_ATTR, False)
    except Exception:
        pass


def mark_exact_ldap_connection_timeout_state(shell: object) -> None:
    """Record that the current LDAP flow hit the exact NetExec timeout signature."""
    try:
        setattr(shell, _EXACT_LDAP_TIMEOUT_STATE_ATTR, True)
    except Exception:
        pass


def consume_exact_ldap_connection_timeout_state(shell: object) -> bool:
    """Return and clear the exact LDAP timeout state for the current shell."""
    try:
        value = bool(getattr(shell, _EXACT_LDAP_TIMEOUT_STATE_ATTR, False))
        setattr(shell, _EXACT_LDAP_TIMEOUT_STATE_ATTR, False)
        return value
    except Exception:
        return False


def peek_exact_ldap_connection_timeout_state(shell: object) -> bool:
    """Return the exact LDAP timeout state without clearing it."""
    try:
        return bool(getattr(shell, _EXACT_LDAP_TIMEOUT_STATE_ATTR, False))
    except Exception:
        return False


def _is_exact_ldap_connection_timeout_result(
    completed_process: subprocess.CompletedProcess[str] | None,
) -> bool:
    """Return True when a NetExec LDAP result matches the exact timeout signature."""
    return output_has_exact_ldap_connection_timeout(
        _combined_completed_process_output(completed_process)
    )


def _run_native_ldap_query_attribute_values(
    shell: LdapShell,
    *,
    domain: str,
    ldap_query: str,
    attribute: str,
    auth_username: str,
    auth_password: str,
    pdc: str,
    timeout: int = 300,
    retries: int = 1,
    retry_delay_seconds: float = 1.0,
    retry_backoff: float = 1.5,
    require_non_empty: bool = False,
    prefer_kerberos: bool = True,
    allow_ntlm_fallback: bool = True,
    debug_label: str = "ldap-query",
) -> list[str] | None:
    """Run a native LDAP query and return attribute values with retries.

    This helper centralizes a robust execution policy used by runtime privilege
    verification flows:
    - Prefer Kerberos authentication for LDAP queries.
    - Optionally fallback to NTLM if Kerberos does not return usable data.
    - Retry transient failures and optional empty result-sets with backoff.
    """
    from adscan_internal.services.ldap_query_service import (
        query_shell_ldap_attribute_values,
    )

    if domain not in shell.domains_data:
        return None

    attempts = max(1, int(retries))
    delay = max(0.0, float(retry_delay_seconds))
    backoff = max(1.0, float(retry_backoff))

    saw_successful_query = False

    successful_empty_result = False
    for attempt in range(1, attempts + 1):
        print_info_debug(
            f"[ldap-in-chain] {debug_label} native LDAP query "
            f"(attempt {attempt}/{attempts}) for attribute {attribute}"
        )
        values = query_shell_ldap_attribute_values(
            shell,
            domain=domain,
            ldap_filter=ldap_query,
            attribute=attribute,
            auth_username=str(auth_username),
            auth_password=str(auth_password),
            pdc=str(pdc),
            prefer_kerberos=prefer_kerberos,
            allow_ntlm_fallback=allow_ntlm_fallback,
            operation_name=debug_label,
        )
        if values is None:
            if attempt < attempts:
                time.sleep(delay * (backoff ** (attempt - 1)))
            continue

        saw_successful_query = True
        values = [str(value).strip() for value in values if str(value).strip()]
        if values:
            return values

        if not require_non_empty:
            return []

        successful_empty_result = True
        if attempt < attempts:
            print_info_debug(
                "[ldap-in-chain] "
                f"{debug_label} returned 0 {attribute} values "
                f"(attempt {attempt}/{attempts}); retrying."
            )
            time.sleep(delay * (backoff ** (attempt - 1)))

    if successful_empty_result:
        print_info_debug(
            "[ldap-in-chain] "
            f"{debug_label} exhausted retries with 0 {attribute} values."
        )
        return []

    if saw_successful_query:
        return []
    return None


def get_recursive_user_groups_in_chain(
    shell: LdapShell,
    *,
    domain: str,
    target_username: str,
    auth_username: str | None = None,
    auth_password: str | None = None,
    pdc: str | None = None,
    timeout: int = 300,
    retries: int = 3,
    retry_delay_seconds: float = 1.0,
    retry_backoff: float = 1.5,
    retry_on_empty: bool = True,
    prefer_kerberos: bool = True,
    allow_ntlm_fallback: bool = True,
) -> list[str] | None:
    """Return recursive group memberships for a principal via LDAP_MATCHING_RULE_IN_CHAIN.

    This is a runtime helper used when we need accurate group memberships even
    after in-engagement changes (e.g., adding the operator to a group).

    It performs 2 LDAP queries via native LDAP:
      1) Resolve the principal's distinguishedName (DN) using sAMAccountName.
      2) Query groups whose ``member`` chain contains that DN using:
            member:1.2.840.113556.1.4.1941:=<USER_DN>

    Args:
        shell: Shell instance providing LDAP context.
        domain: Target AD domain.
        target_username: Principal sAMAccountName whose groups we want. This
            works for both Users and Computers (including trailing ``$``).
        auth_username: Auth principal used to query LDAP. Defaults to the
            active domain credential in ``shell.domains_data[domain]``.
        auth_password: Auth secret used to query LDAP. Defaults to the active
            domain credential in ``shell.domains_data[domain]``.
        pdc: DC target for the query. Defaults to ``shell.domains_data[domain]["pdc"]``.
        timeout: Command timeout in seconds.

    Returns:
        List of group sAMAccountName values (may include spaces) on success,
        otherwise None when prerequisites are missing or lookup failed.
    """
    if domain not in shell.domains_data:
        return None

    auth_username = auth_username or shell.domains_data[domain].get("username")
    auth_password = auth_password or shell.domains_data[domain].get("password")
    pdc = pdc or shell.domains_data[domain].get("pdc")
    if not auth_username or not auth_password or not pdc:
        return None

    # Fast path: resolve the principal DN from the graph when available.
    # This avoids an extra LDAP query and keeps node enrichment consistent.
    user_dn = ""
    try:
        service_getter = getattr(shell, "_get_graph_service", None) or getattr(
            shell,
            "_get_graph_service",
            None,
        )
        if callable(service_getter):
            service = service_getter()
            resolver = getattr(service, "get_user_node_by_samaccountname", None)
            if callable(resolver):
                node_props = resolver(domain, str(target_username or "").strip())
                if isinstance(node_props, dict):
                    user_dn = str(
                        node_props.get("distinguishedname")
                        or node_props.get("distinguishedName")
                        or ""
                    ).strip()
                    if user_dn:
                        marked_user = mark_sensitive(str(target_username), "user")
                        marked_domain = mark_sensitive(str(domain), "domain")
                        print_info_debug(
                            "[ldap-in-chain] Resolved distinguishedName from BloodHound for "
                            f"{marked_user}@{marked_domain}"
                        )
    except Exception:
        user_dn = ""

    # 1) Resolve DN for the principal (fallback to native LDAP query when BH is unavailable).
    if not user_dn:
        sanitized_target = str(target_username).replace("'", "\\'")
        dn_query = f"(&(|(objectClass=user)(objectClass=computer))(sAMAccountName={sanitized_target}))"
        dn_values = _run_native_ldap_query_attribute_values(
            shell,
            domain=domain,
            ldap_query=dn_query,
            attribute="distinguishedName",
            auth_username=str(auth_username),
            auth_password=str(auth_password),
            pdc=str(pdc),
            timeout=timeout,
            retries=max(1, retries),
            retry_delay_seconds=retry_delay_seconds,
            retry_backoff=retry_backoff,
            require_non_empty=True,
            prefer_kerberos=prefer_kerberos,
            allow_ntlm_fallback=allow_ntlm_fallback,
            debug_label="Resolve DN",
        )
        if dn_values is None:
            return None
        user_dn = dn_values[0] if dn_values else ""
        if not user_dn:
            return None

    # 2) Resolve recursive group memberships using in-chain on `member`.
    group_query = (
        f"(&(objectCategory=group)(member:1.2.840.113556.1.4.1941:={user_dn}))"
    )
    groups = _run_native_ldap_query_attribute_values(
        shell,
        domain=domain,
        ldap_query=group_query,
        attribute="sAMAccountName",
        auth_username=str(auth_username),
        auth_password=str(auth_password),
        pdc=str(pdc),
        timeout=timeout,
        retries=max(1, retries),
        retry_delay_seconds=retry_delay_seconds,
        retry_backoff=retry_backoff,
        require_non_empty=retry_on_empty,
        prefer_kerberos=prefer_kerberos,
        allow_ntlm_fallback=allow_ntlm_fallback,
        debug_label="Recursive groups",
    )
    if groups is None:
        return None

    # Normalise: keep stable display while avoiding duplicates.
    groups = [g.strip() for g in groups if str(g).strip()]
    if not groups:
        return []
    return sorted(set(groups), key=str.lower)


def get_recursive_principal_group_sids_in_chain(
    shell: LdapShell,
    *,
    domain: str,
    target_samaccountname: str,
    auth_username: str | None = None,
    auth_password: str | None = None,
    pdc: str | None = None,
    timeout: int = 300,
    retries: int = 3,
    retry_delay_seconds: float = 1.0,
    retry_backoff: float = 1.5,
    retry_on_empty: bool = True,
    prefer_kerberos: bool = True,
    allow_ntlm_fallback: bool = True,
) -> list[str] | None:
    """Return recursive group SIDs for a principal via LDAP_MATCHING_RULE_IN_CHAIN.

    This is similar to `get_recursive_user_groups_in_chain`, but returns
    `objectSid` values for each group. This is useful for robust privileged
    group checks because group names can be localized.

    Args:
        shell: Shell instance providing LDAP context.
        domain: Target AD domain.
        target_samaccountname: Principal sAMAccountName (user or computer).
        auth_username/auth_password/pdc/timeout: Same meaning as in
            `get_recursive_user_groups_in_chain`.

    Returns:
        List of group objectSid strings on success, otherwise None.
    """
    if domain not in shell.domains_data:
        return None

    auth_username = auth_username or shell.domains_data[domain].get("username")
    auth_password = auth_password or shell.domains_data[domain].get("password")
    pdc = pdc or shell.domains_data[domain].get("pdc")
    if not auth_username or not auth_password or not pdc:
        return None

    # Resolve principal DN (graph first, fallback native LDAP query).
    user_dn = ""
    try:
        service_getter = getattr(shell, "_get_graph_service", None) or getattr(
            shell,
            "_get_graph_service",
            None,
        )
        if callable(service_getter):
            service = service_getter()
            resolver = getattr(service, "get_user_node_by_samaccountname", None)
            if callable(resolver):
                node_props = resolver(domain, str(target_samaccountname or "").strip())
                if isinstance(node_props, dict):
                    user_dn = str(
                        node_props.get("distinguishedname")
                        or node_props.get("distinguishedName")
                        or ""
                    ).strip()
                    if user_dn:
                        marked_user = mark_sensitive(str(target_samaccountname), "user")
                        marked_domain = mark_sensitive(str(domain), "domain")
                        print_info_debug(
                            "[ldap-in-chain] Resolved distinguishedName from BloodHound for "
                            f"{marked_user}@{marked_domain}"
                        )
    except Exception:
        user_dn = ""

    if not user_dn:
        sanitized_target = str(target_samaccountname).replace("'", "\\'")
        dn_query = f"(&(|(objectClass=user)(objectClass=computer))(sAMAccountName={sanitized_target}))"
        dn_values = _run_native_ldap_query_attribute_values(
            shell,
            domain=domain,
            ldap_query=dn_query,
            attribute="distinguishedName",
            auth_username=str(auth_username),
            auth_password=str(auth_password),
            pdc=str(pdc),
            timeout=timeout,
            retries=max(1, retries),
            retry_delay_seconds=retry_delay_seconds,
            retry_backoff=retry_backoff,
            require_non_empty=True,
            prefer_kerberos=prefer_kerberos,
            allow_ntlm_fallback=allow_ntlm_fallback,
            debug_label="Resolve DN",
        )
        if dn_values is None:
            return None
        user_dn = dn_values[0] if dn_values else ""
        if not user_dn:
            return None

    # Resolve recursive group memberships using in-chain on `member`, returning objectSid.
    group_query = (
        f"(&(objectCategory=group)(member:1.2.840.113556.1.4.1941:={user_dn}))"
    )
    sids = _run_native_ldap_query_attribute_values(
        shell,
        domain=domain,
        ldap_query=group_query,
        attribute="objectSid",
        auth_username=str(auth_username),
        auth_password=str(auth_password),
        pdc=str(pdc),
        timeout=timeout,
        retries=max(1, retries),
        retry_delay_seconds=retry_delay_seconds,
        retry_backoff=retry_backoff,
        require_non_empty=retry_on_empty,
        prefer_kerberos=prefer_kerberos,
        allow_ntlm_fallback=allow_ntlm_fallback,
        debug_label="Recursive group SIDs",
    )
    if sids is None:
        return None

    sids = [sid.strip() for sid in sids if str(sid).strip()]
    if not sids:
        return []
    return sorted(set(sids), key=str.upper)


def get_recursive_principal_groups_in_chain(
    shell: LdapShell,
    *,
    domain: str,
    target_samaccountname: str,
    auth_username: str | None = None,
    auth_password: str | None = None,
    pdc: str | None = None,
    timeout: int = 300,
) -> list[str] | None:
    """Alias for ``get_recursive_user_groups_in_chain`` (kept for clarity)."""
    return get_recursive_user_groups_in_chain(
        shell,
        domain=domain,
        target_username=target_samaccountname,
        auth_username=auth_username,
        auth_password=auth_password,
        pdc=pdc,
        timeout=timeout,
    )


def _get_domain_admins_via_native_ldap(shell: LdapShell, domain: str) -> list[str] | None:
    """Return enabled Domain Admin members using ADscan's native LDAP transport."""
    try:
        from adscan_internal.services.native_group_membership import (
            resolve_enabled_group_members_by_rid_native,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return None

    return resolve_enabled_group_members_by_rid_native(
        shell,
        domain,
        512,
        member_kind="user",
        operation_name="Domain Admins lookup",
    )


def get_domain_admins(shell: LdapShell, domain: str) -> list[str]:
    """Return members of the Domain Admins group from local artifacts or native LDAP."""
    try:
        marked_domain = mark_sensitive(domain, "domain")
        snapshot_admins = resolve_group_members_by_rid(
            shell, domain, 512, enabled_only=True
        )
        if snapshot_admins is not None:
            if snapshot_admins:
                return snapshot_admins
            print_info_debug(
                f"[ldap] RID 512 resolved 0 Domain Admins for {marked_domain}; "
                "falling back to LDAP."
            )
        else:
            print_info_debug(
                f"[ldap] RID 512 resolution unavailable for {marked_domain}; "
                "falling back to native LDAP."
            )

        print_info_verbose("Retrieving Domain Admins")
        admins = _get_domain_admins_via_native_ldap(shell, domain)
        if admins:
            return admins

        print_warning(
            f"No Domain Admins resolved via LDAP for {marked_domain}. "
            "Manual selection may be required."
        )
        creds = shell.domains_data.get(domain, {}).get("credentials", {})
        candidate_users = [
            str(user).strip()
            for user in creds.keys()
            if isinstance(user, str) and str(user).strip()
        ]
        candidate_users = sorted(set(candidate_users), key=str.lower)
        if not candidate_users:
            manual = Prompt.ask(
                f"Specify a Domain Admin username for {marked_domain} (leave blank to skip)",
                default="",
            ).strip()
            manual = manual.lower()
            if manual:
                marked_user = mark_sensitive(manual, "user")
                print_info_debug(
                    f"[ldap] Domain Admin selected manually for {marked_domain}: {marked_user}"
                )
                return [manual]
            return []

        if hasattr(shell, "_questionary_select"):
            options = [*candidate_users, "Enter manually", "Skip"]
            selected_idx = shell._questionary_select(
                f"Select a Domain Admin account for {marked_domain}:", options
            )
            if selected_idx is None:
                return []
            choice = options[selected_idx]
            if choice == "Enter manually":
                manual = Prompt.ask(
                    f"Specify a Domain Admin username for {marked_domain} (leave blank to skip)",
                    default="",
                ).strip()
                manual = manual.lower()
                if manual:
                    marked_user = mark_sensitive(manual, "user")
                    print_info_debug(
                        f"[ldap] Domain Admin selected manually for {marked_domain}: {marked_user}"
                    )
                    return [manual]
                return []
            if choice == "Skip":
                return []
            selected = choice.lower()
            marked_user = mark_sensitive(selected, "user")
            print_info_debug(
                f"[ldap] Domain Admin selected from credentials for {marked_domain}: {marked_user}"
            )
            return [selected]

        manual = Prompt.ask(
            f"Specify a Domain Admin username for {marked_domain} (leave blank to skip)",
            default="",
        ).strip()
        manual = manual.lower()
        if manual:
            marked_user = mark_sensitive(manual, "user")
            print_info_debug(
                f"[ldap] Domain Admin selected manually for {marked_domain}: {marked_user}"
            )
            return [manual]
        return []
    except Exception as exc:
        telemetry.capture_exception(exc)


def run_kerberos_enum_users(shell: LdapShell, domain: str) -> None:
    """Enumerate users of the specified domain using Kerberos.

    This is a CLI wrapper around the Kerberos enumeration service that
    preserves the existing UX: wordlist selection, operation header and
    persistence of the aggregated user list under ``domains/<domain>/users.txt``.
    """

    from adscan_internal import print_operation_header

    if domain not in shell.domains_data:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"Unknown domain: {marked_domain}")
        return

    shell.domains_data[domain]["auth"] = "user_enum"

    # Wordlist selection via single-tree strategy selector
    wordlist = _select_kerberos_wordlist_strategy(shell, domain)
    if not wordlist:
        return

    workspace_cwd = shell._get_workspace_cwd()
    kerberos_dir = domain_subpath(
        workspace_cwd, shell.domains_dir, domain, shell.kerberos_dir
    )
    os.makedirs(kerberos_dir, exist_ok=True)
    should_continue = _prompt_for_repeated_kerberos_wordlist_if_needed(
        shell=shell,
        domain=domain,
        kerberos_dir=Path(kerberos_dir),
        wordlist_path=Path(wordlist),
    )
    if not should_continue:
        return
    output_file = Path(os.path.join(kerberos_dir, "enum_users.log"))

    wordlist_name = os.path.basename(wordlist) if os.path.exists(wordlist) else wordlist
    print_operation_header(
        "Kerberos User Enumeration",
        details={
            "Domain": domain,
            "PDC": shell.domains_data[domain]["pdc"],
            "Wordlist": wordlist_name,
            "Protocol": "Kerberos Pre-Authentication",
        },
        icon="🔑",
    )

    kerbrute_path = os.path.join(TOOLS_INSTALL_DIR, "kerbrute", "kerbrute")
    if not os.path.isfile(kerbrute_path) or not os.access(kerbrute_path, os.X_OK):
        print_error(
            f"kerbrute binary not found or not executable at {kerbrute_path}. "
            "Please ensure tools are installed via 'adscan install'."
        )
        return

    enum_service = EnumerationService()
    executor = shell._get_service_executor()

    # Operator early-stop for this run. On a large wordlist (statistically-
    # likely-usernames, thousands of candidates) this can take minutes to
    # hours; the operator's first Ctrl+C (or the platform "Stop" sentinel)
    # stops feeding candidates and continues the scan with the usernames
    # found so far -- the SAME cooperative-stop contract as the SMB host
    # enrichment sweep, via the generic token (see
    # ``adscan_internal.services.cooperative_cancellation``).
    from adscan_internal.services.cooperative_cancellation import (  # noqa: PLC0415
        CooperativeCancellation,
        cli_cooperative_stop,
        cooperative_stop_sentinel_path,
    )

    _workspace_root = getattr(shell, "current_workspace_dir", None)
    user_enum_cancellation = CooperativeCancellation(
        operation="kerberos_user_enum",
        sentinel_path=(
            cooperative_stop_sentinel_path(_workspace_root, "kerberos_user_enum")
            if _workspace_root
            else None
        ),
    )

    with cli_cooperative_stop(
        user_enum_cancellation,
        shell=shell,
        stop_message=(
            "Kerberos user enumeration: stopping early and continuing the scan "
            "with the usernames found so far. Press Ctrl+C again to abort the "
            "whole scan."
        ),
    ):
        users = enum_service.kerberos.enumerate_users_kerberos(
            domain=domain,
            pdc=shell.domains_data[domain]["pdc"],
            wordlist=wordlist,
            kerbrute_path=kerbrute_path,
            output_file=output_file,
            executor=executor,
            spawn=shell._get_service_spawner(),
            scan_id=None,
            timeout=300,
            cancellation=user_enum_cancellation,
        )
    _record_kerberos_wordlist_attempt(
        domain=domain,
        kerberos_dir=Path(kerberos_dir),
        wordlist_path=Path(wordlist),
        valid_users_count=len(sorted(set(users))),
    )

    if not users:
        print_warning("No Kerberos users were discovered.")
        _show_kerberos_enum_shortcut_hint(shell, domain, had_results=False)
        shell.ask_for_kerberos_user_enum(domain, relaunch=True)
        return

    unique_users = sorted(set(users))
    shell._write_user_list_file(
        domain,
        "users.txt",
        unique_users,
        merge_existing=True,
        update_source="Kerberos user enumeration",
    )
    shell._postprocess_user_list_file(
        domain,
        "users.txt",
        trigger_followups=False,
        source="kerberos_user_enum",
    )

    shell.ask_for_kerberos_user_enum(domain, relaunch=True)
    run_post_user_discovery_followups(
        shell,
        domain,
        source="kerberos_user_enum",
    )
    _show_kerberos_enum_shortcut_hint(shell, domain, had_results=True)


def _compute_file_sha256(path: Path) -> str | None:
    """Return a stable SHA-256 digest for one file, or ``None`` if unreadable."""
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as exc:
        telemetry.capture_exception(exc)
        marked_path = mark_sensitive(str(path), "path")
        print_info_debug(
            f"[ldap] Could not hash Kerberos wordlist {marked_path}: "
            f"{type(exc).__name__}: {exc}"
        )
        return None


def _resolve_kerberos_enum_history_path(kerberos_dir: Path) -> Path:
    """Return the history artifact path for Kerberos user enumeration attempts."""
    return kerberos_dir / "enum_users_history.json"


def _load_kerberos_enum_history(kerberos_dir: Path) -> dict:
    """Load Kerberos enumeration history, returning an empty payload on errors."""
    history_path = _resolve_kerberos_enum_history_path(kerberos_dir)
    payload: dict[str, object] = {"schema_version": 1, "runs": []}
    if not history_path.exists():
        return payload
    try:
        loaded = json.loads(history_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        telemetry.capture_exception(exc)
        marked_path = mark_sensitive(str(history_path), "path")
        print_info_debug(
            f"[ldap] Could not load Kerberos enum history {marked_path}: "
            f"{type(exc).__name__}: {exc}"
        )
        return payload
    if isinstance(loaded, dict):
        loaded.setdefault("schema_version", 1)
        loaded.setdefault("runs", [])
        if isinstance(loaded.get("runs"), list):
            return loaded
    return payload


def _record_kerberos_wordlist_attempt(
    *,
    domain: str,
    kerberos_dir: Path,
    wordlist_path: Path,
    valid_users_count: int,
) -> None:
    """Persist one Kerberos username enumeration attempt for cheap exact-match warnings."""
    digest = _compute_file_sha256(wordlist_path)
    if not digest:
        return
    history_path = _resolve_kerberos_enum_history_path(kerberos_dir)
    history_payload = _load_kerberos_enum_history(kerberos_dir)
    runs = history_payload.get("runs")
    if not isinstance(runs, list):
        runs = []

    try:
        line_count = 0
        with wordlist_path.open("r", encoding="utf-8", errors="ignore") as handle:
            for _ in handle:
                line_count += 1
    except OSError:
        line_count = 0

    runs.append(
        {
            "domain": domain,
            "wordlist_path": str(wordlist_path),
            "wordlist_name": wordlist_path.name,
            "wordlist_sha256": digest,
            "wordlist_line_count": line_count,
            "valid_users_count": valid_users_count,
            "tested_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    history_payload["runs"] = runs[-200:]
    try:
        history_path.write_text(
            json.dumps(history_payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        marked_path = mark_sensitive(str(history_path), "path")
        print_info_debug(f"[ldap] Kerberos enum history updated at {marked_path}")
    except OSError as exc:
        telemetry.capture_exception(exc)
        marked_path = mark_sensitive(str(history_path), "path")
        print_info_debug(
            f"[ldap] Could not persist Kerberos enum history {marked_path}: "
            f"{type(exc).__name__}: {exc}"
        )


def _find_prior_kerberos_wordlist_attempt(
    *,
    domain: str,
    kerberos_dir: Path,
    wordlist_path: Path,
) -> dict[str, object] | None:
    """Return the most recent prior attempt using the exact same wordlist content."""
    digest = _compute_file_sha256(wordlist_path)
    if not digest:
        return None
    payload = _load_kerberos_enum_history(kerberos_dir)
    runs = payload.get("runs")
    if not isinstance(runs, list):
        return None
    for entry in reversed(runs):
        if not isinstance(entry, dict):
            continue
        if str(entry.get("domain") or "").strip().lower() != domain.strip().lower():
            continue
        if str(entry.get("wordlist_sha256") or "") != digest:
            continue
        return entry
    return None


def _prompt_for_repeated_kerberos_wordlist_if_needed(
    *,
    shell: LdapShell,
    domain: str,
    kerberos_dir: Path,
    wordlist_path: Path,
) -> bool:
    """Warn when the exact same Kerberos username list was already tested recently."""
    prior_attempt = _find_prior_kerberos_wordlist_attempt(
        domain=domain,
        kerberos_dir=kerberos_dir,
        wordlist_path=wordlist_path,
    )
    if not prior_attempt:
        return True

    marked_domain = mark_sensitive(domain, "domain")
    marked_wordlist = mark_sensitive(wordlist_path.name, "path")
    tested_at = str(prior_attempt.get("tested_at") or "unknown time")
    valid_users_count = int(prior_attempt.get("valid_users_count") or 0)
    line_count = int(prior_attempt.get("wordlist_line_count") or 0)
    history_rel = domain_relpath(
        shell._get_workspace_cwd(),
        shell.domains_dir,
        domain,
        shell.kerberos_dir,
        "enum_users_history.json",
    )
    marked_history = mark_sensitive(history_rel, "path")
    print_panel(
        (
            f"Domain: {marked_domain}\n"
            f"Wordlist: {marked_wordlist}\n"
            f"This exact username list was already tested previously.\n"
            f"Previous run: {tested_at}\n"
            f"Candidates in list: {line_count}\n"
            f"Valid usernames found previously: {valid_users_count}\n"
            f"History artifact: {marked_history}"
        ),
        title="♻️ Kerberos Username List Already Tested",
        border_style=BRAND_COLORS["warning"],
    )
    options = [
        "Run this exact list again",
        "Go back and choose another wordlist strategy",
    ]
    choice_idx = shell._questionary_select(
        f"This exact Kerberos username list was already tested for {marked_domain}.",
        options,
        default_idx=0,
    )
    return choice_idx == 0


def _select_kerberos_wordlist_strategy(shell: LdapShell, domain: str) -> str | None:
    """Single-tree strategy selector for Kerberos username wordlist generation.

    Replaces the old two-level redundant menu (top-level + nested confirm) with one
    clean decision: how does the operator know (or not know) the username format?
    The "general common wordlist" option is intentionally absent — it is too slow
    (~300s+ timeout) and adds no value when targeted generation is available.
    """
    workspace_type = str(getattr(shell, "type", "") or "").strip().lower()
    is_audit = workspace_type == "audit"

    # ── Context panel ────────────────────────────────────────────────────────
    strategy_rows = [
        (
            "[bold #1AA0AE]Detect format automatically[/bold #1AA0AE]",
            "Runs a Kerberos probe (may take a few minutes) to identify\n"
            "the naming convention, then generates a focused list.",
        ),
        (
            "[bold #1AA0AE]I know the format[/bold #1AA0AE]",
            "Pick the naming pattern and choose sources:\n"
            "statistically-likely names, LinkedIn employees, or manual entry.",
        ),
        (
            "[bold #1AA0AE]Use my own wordlist[/bold #1AA0AE]",
            "Provide a file; ADscan will pass it directly to kerbrute.",
        ),
    ]
    table = Table(show_header=False, box=None, padding=(0, 2), expand=False)
    table.add_column(style="bold", no_wrap=True)
    table.add_column(style="dim")
    for label, desc in strategy_rows:
        table.add_row(label, desc)

    print_panel(
        table,
        title="[bold]How should ADscan build the username list?[/bold]",
        border_style=BRAND_COLORS["info"],
        expand=False,
        spacing="before",
    )

    options = [
        "Detect the format automatically" + (" (Recommended)" if not is_audit else ""),
        "I know the username format" + (" (Recommended)" if is_audit else ""),
        "Use my own wordlist",
    ]
    choice_idx = shell._questionary_select("Select a strategy", options, default_idx=0)
    if choice_idx is None:
        print_error("Selection cancelled.")
        return None

    if choice_idx == 0:
        return _kerberos_auto_detect_then_build(shell, domain)
    if choice_idx == 1:
        return _kerberos_known_format_build(shell, domain)
    return _prompt_custom_kerberos_username_wordlist(shell, domain)


def _kerberos_auto_detect_then_build(shell: LdapShell, domain: str) -> str | None:
    """Run the inference probe then build a focused wordlist from the result.

    This is the "Detect format automatically" branch. It runs kerbrute with an
    inference wordlist, identifies the dominant naming pattern, and hands
    off to source selection. On failure it offers manual pattern selection or a
    custom file — never the slow general wordlist.
    """
    strategy, value = _infer_kerberos_username_pattern_via_runtime_probe(shell, domain)
    if strategy == "pattern" and value:
        return _build_focused_kerberos_wordlist_for_pattern(
            shell, domain, pattern_key=value
        )
    if strategy == "manual":
        return _kerberos_known_format_build(shell, domain)
    if strategy == "custom":
        return _prompt_custom_kerberos_username_wordlist(shell, domain)
    return None


def _kerberos_known_format_build(shell: LdapShell, domain: str) -> str | None:
    """Build a focused wordlist when the operator already knows the naming convention."""
    pattern_key = _prompt_kerberos_username_pattern(shell, domain)
    if not pattern_key:
        return None
    return _build_focused_kerberos_wordlist_for_pattern(
        shell, domain, pattern_key=pattern_key
    )


def _prompt_custom_kerberos_username_wordlist(
    shell: LdapShell,
    domain: str,
) -> str | None:
    """Prompt until a valid custom Kerberos username wordlist is selected or skipped."""

    in_container_runtime = is_full_container_runtime(shell)
    marked_domain = mark_sensitive(domain, "domain")

    while True:
        wordlist = ""
        if in_container_runtime:
            wordlist = (
                select_host_file_via_gui(
                    shell,
                    title=f"Select the Kerberos username wordlist for domain {domain}",
                    initial_dir=str(get_effective_user_home()),
                    log_prefix="ldap",
                )
                or ""
            ).strip()
            if not wordlist:
                print_info_debug(
                    "[ldap] Host GUI picker not used/failed; falling back to manual path prompt"
                )

        if not wordlist:
            wordlist = (
                Prompt.ask(
                    f"Specify the path of the custom username wordlist for domain {marked_domain}:"
                )
                or ""
            ).strip()
        if not wordlist:
            print_warning(
                "Kerberos user enumeration skipped: no wordlist path was provided."
            )
            return None

        imported_wordlist = maybe_import_host_file_to_workspace(
            shell,
            domain=domain,
            source_path=wordlist,
            dest_dir="wordlists_custom",
            log_prefix="ldap",
        )
        if os.path.exists(imported_wordlist):
            return imported_wordlist

        marked_wordlist = mark_sensitive(imported_wordlist, "path")
        print_warning(f"The wordlist file {marked_wordlist} does not exist.")

        options = [
            "Re-enter the wordlist path (Recommended)",
            "Skip Kerberos user enumeration",
        ]
        choice_idx = shell._questionary_select(
            "Kerberos username wordlist not found. How do you want to proceed?",
            options,
            default_idx=0,
        )
        if choice_idx == 1:
            print_info(
                "Skipping Kerberos user enumeration. You can rerun it later with "
                f"`kerberos_enum_users {domain}`."
            )
            _show_kerberos_enum_shortcut_hint(shell, domain)
            return None


def _prompt_kerberos_username_pattern(shell: LdapShell, domain: str) -> str | None:
    """Prompt for a known corporate username format with a live preview panel."""
    sample_domain = mark_sensitive(domain, "domain")
    sample_name = "John Smith"

    preview_table = Table(
        show_header=True,
        header_style=f"bold {BRAND_COLORS['info']}",
        box=None,
        padding=(0, 2),
    )
    preview_table.add_column("Format key")
    preview_table.add_column("Example for 'John Smith'", style="dim")
    for pattern_key in SUPPORTED_KERBEROS_PATTERN_KEYS:
        label = format_supported_pattern_label(pattern_key, sample_value=sample_name)
        key_part = label.split("(")[0].strip()
        example_part = f"({label.split('(')[1].rstrip(')')})" if "(" in label else label
        preview_table.add_row(key_part, example_part)

    print_panel(
        preview_table,
        title=f"[bold]Username formats · {sample_domain}[/bold]",
        border_style=BRAND_COLORS["info"],
        expand=False,
        spacing="before",
    )

    option_map: dict[str, str] = {}
    options: list[str] = []
    for pattern_key in SUPPORTED_KERBEROS_PATTERN_KEYS:
        label = format_supported_pattern_label(pattern_key, sample_value=sample_name)
        options.append(label)
        option_map[label] = pattern_key

    idx = shell._questionary_select(
        f"Select the username format used in {sample_domain}",
        options,
        default_idx=0,
    )
    if idx is None:
        print_error("Username format selection cancelled.")
        return None
    return option_map[options[idx]]


def _collect_name_pairs_interactive(
    shell: LdapShell,
    domain: str,
) -> list[tuple[str, str]] | None:
    """Collect first/last name pairs for targeted username generation."""
    options = [
        "Use a file with 'Firstname Lastname' entries",
        "Enter names interactively",
    ]
    choice = shell._questionary_select(
        f"Select how to provide employee names for {mark_sensitive(domain, 'domain')}",
        options,
    )
    if choice is None:
        print_error("Selection cancelled.")
        return None

    names: list[tuple[str, str]] = []
    if choice == 0:
        path = _prompt_custom_kerberos_username_wordlist(shell, domain)
        if not path:
            return None
        with open(path, encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                parts = line.strip().split()
                if len(parts) >= 2:
                    names.append((parts[0], parts[-1]))
    else:
        initial = "# Enter each 'Firstname Lastname' on a new line\n"
        text = shell._open_fullscreen_editor(
            f"Kerberos user entries for {domain}", initial
        )
        if text is None:
            print_error("User entry cancelled.")
            return None
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                names.append((parts[0], parts[-1]))

    if not names:
        print_warning("No usable first/last-name pairs were provided.")
        return None
    return names


def _prompt_linkedin_ready(shell: LdapShell) -> bool:
    """Guide the operator through the LinkedIn login step."""
    print_panel(
        "\n".join(
            [
                "A browser window will open for LinkedIn authentication.",
                "",
                "1. Log in to LinkedIn in that browser.",
                "2. Leave the browser open.",
                "3. Return here and confirm when the session is ready.",
            ]
        ),
        title="[bold cyan]LinkedIn Employee Discovery[/bold cyan]",
        border_style="cyan",
        expand=False,
    )
    return Confirm.ask(
        "Have you completed the LinkedIn login in the browser?", default=True
    )


def _prompt_validated_linkedin_company_slug(shell: LdapShell) -> str | None:
    """Prompt for a LinkedIn company slug and validate it before continuing."""
    linkedin_service = LinkedInUsernameDiscoveryService()
    while True:
        company_slug = (
            (
                Prompt.ask(
                    "Specify the LinkedIn company slug "
                    "(for https://www.linkedin.com/company/<slug>/)",
                    default="",
                )
                or ""
            )
            .strip()
            .strip("/")
        )
        if not company_slug:
            print_warning(
                "Skipping LinkedIn source because no company slug was provided."
            )
            return None

        marked_slug = mark_sensitive(company_slug, "company")
        validation_result = linkedin_service.validate_company_slug_public(company_slug)
        if validation_result is True:
            print_info(f"LinkedIn company slug validated successfully: {marked_slug}")
            return company_slug
        if validation_result is None:
            print_warning(
                f"Could not validate the LinkedIn company slug {marked_slug} pre-login. "
                "Continuing anyway."
            )
            return company_slug

        print_warning(
            f"The LinkedIn company slug {marked_slug} does not appear to exist."
        )
        options = [
            "Re-enter the LinkedIn company slug (Recommended)",
            "Skip LinkedIn employee discovery",
        ]
        choice_idx = shell._questionary_select(
            "LinkedIn company slug validation failed. How do you want to proceed?",
            options,
            default_idx=0,
        )
        if choice_idx == 1:
            return None


def _infer_kerberos_username_pattern_via_runtime_probe(
    shell: LdapShell,
    domain: str,
) -> tuple[str, str | None]:
    """Run a Kerberos probe to infer the dominant username format."""
    wordlist_service = KerberosUsernameWordlistService()
    inference_wordlist = wordlist_service.get_format_inference_wordlist_path()
    metadata_path = wordlist_service.get_format_inference_metadata_path()
    marked_domain = mark_sensitive(domain, "domain")
    if inference_wordlist is None or metadata_path is None:
        print_warning(
            "The Kerberos username-format inference assets are not available in this runtime."
        )
        return "manual", None

    kerbrute_path = os.path.join(TOOLS_INSTALL_DIR, "kerbrute", "kerbrute")
    if not os.path.isfile(kerbrute_path) or not os.access(kerbrute_path, os.X_OK):
        print_warning(
            "Kerbrute is not available, so username-format inference cannot run."
        )
        return "manual", None

    kerberos_dir = domain_subpath(
        shell._get_workspace_cwd(),
        shell.domains_dir,
        domain,
        shell.kerberos_dir,
    )
    os.makedirs(kerberos_dir, exist_ok=True)
    output_file = Path(os.path.join(kerberos_dir, "enum_users_format_inference.log"))

    print_operation_header(
        "Kerberos Username Format Inference",
        details={
            "Domain": domain,
            "PDC": shell.domains_data[domain]["pdc"],
            "Wordlist": inference_wordlist.name,
            "Protocol": "Kerberos Pre-Authentication",
        },
        icon="🧠",
    )

    users = EnumerationService().kerberos.enumerate_users_kerberos(
        domain=domain,
        pdc=shell.domains_data[domain]["pdc"],
        wordlist=str(inference_wordlist),
        kerbrute_path=kerbrute_path,
        output_file=output_file,
        executor=shell._get_service_executor(),
        spawn=shell._get_service_spawner(),
        scan_id=None,
        timeout=600,
        auth_mode=AuthMode.UNAUTHENTICATED,
    )
    ranked_patterns = wordlist_service.rank_inferred_patterns_from_candidates(users)
    if not ranked_patterns:
        if users:
            print_warning(
                "Kerberos username format inference found valid usernames, but could not "
                "identify a dominant pattern confidently."
            )
        else:
            print_warning(
                f"Could not infer a username format for {marked_domain}: no valid usernames "
                "were discovered with the inference list."
            )
        fallback_options = [
            "Choose the username format manually (Recommended)",
            "Use my own wordlist",
            "Skip Kerberos enumeration",
        ]
        fallback_idx = shell._questionary_select(
            "No format detected. How do you want to continue?",
            fallback_options,
            default_idx=0,
        )
        if fallback_idx == 1:
            return "custom", None
        if fallback_idx == 2:
            return "skip", None
        return "manual", None

    sample_name = "John Smith"
    unique_count = len(set(users))

    result_table = Table(
        show_header=True,
        header_style=f"bold {BRAND_COLORS['info']}",
        box=None,
        padding=(0, 2),
    )
    result_table.add_column("Format", style="bold")
    result_table.add_column("Example", style="dim")
    result_table.add_column(
        "Hits", justify="right", style=f"bold {BRAND_COLORS['success']}"
    )
    for pattern_key, score in ranked_patterns[:5]:
        label = format_supported_pattern_label(pattern_key, sample_value=sample_name)
        result_table.add_row(
            label.split("(")[0].strip(),
            f"({label.split('(')[1].rstrip(')')})" if "(" in label else "",
            str(score),
        )

    print_panel(
        [
            f"[dim]Confirmed usernames from probe:[/dim] [bold]{unique_count}[/bold]",
            "",
            result_table,
        ],
        title=f"[bold]Format detected · {marked_domain}[/bold]",
        border_style=BRAND_COLORS["info"],
        expand=False,
    )

    detected_pattern = ranked_patterns[0][0]
    detected_label = format_supported_pattern_label(
        detected_pattern, sample_value=sample_name
    )
    options = [
        f"Use detected format: {detected_label} (Recommended)",
        "Choose another format manually",
        "Use my own wordlist",
    ]
    choice_idx = shell._questionary_select(
        f"Format detected for {marked_domain}. How do you want to continue?",
        options,
        default_idx=0,
    )
    if choice_idx == 1:
        return "manual", None
    if choice_idx == 2:
        return "custom", None
    return "pattern", detected_pattern


def _load_statistically_likely_candidates_with_cap(
    shell: LdapShell,
    wordlist_service: KerberosUsernameWordlistService,
    stat_path: Path,
    *,
    domain: str,
) -> set[str]:
    """Load the statistically-likely wordlist, capped to a safe unattended budget.

    The built-in statistically-likely wordlists are frequency-ordered (the
    most common username ever the top of the file), so capping reads the TOP
    of the file -- the highest-value candidates are never dropped. When the
    list already fits within a safe unattended budget it is loaded whole,
    unchanged from prior behavior. When it does not, the real candidate count
    and true ETA are shown and the operator explicitly opts in to the full
    run through the centralized non-interactive-safe prompt (default = the
    capped/safe choice, so ``adscan ci`` never hangs on an hours-long
    kerbrute run).

    Args:
        shell: The active shell, used for the opt-in prompt.
        wordlist_service: Service used for the unchanged, below-cap load path.
        stat_path: Path to the frequency-ordered statistically-likely wordlist.
        domain: Target domain, used only for the operator-facing message.

    Returns:
        The set of normalized username candidates to use.
    """
    from adscan_internal.services.enumeration.kerberos import (
        compute_default_wordlist_cap,
        estimate_kerbrute_duration_seconds,
    )
    from adscan_core.tui.progress_dashboard import format_eta

    try:
        with stat_path.open(encoding="utf-8", errors="ignore") as handle:
            total_candidates = sum(1 for line in handle if line.strip())
    except OSError:
        return wordlist_service.load_candidates_from_file(stat_path)

    default_cap = compute_default_wordlist_cap()
    if total_candidates <= default_cap:
        return wordlist_service.load_candidates_from_file(stat_path)

    marked_domain = mark_sensitive(domain, "domain")
    full_eta = format_eta(estimate_kerbrute_duration_seconds(total_candidates))
    capped_eta = format_eta(estimate_kerbrute_duration_seconds(default_cap))

    print_warning(
        f"The statistically-likely username list for {marked_domain} has "
        f"{total_candidates:,} candidates -- a full Kerberos enumeration run "
        f"would take {full_eta}."
    )

    choice_idx = shell._questionary_select(
        "How do you want to proceed?",
        [
            f"Use the {default_cap:,} most likely candidates (~{capped_eta}) — Recommended",
            f"Run the full {total_candidates:,}-candidate list (~{full_eta})",
        ],
        default_idx=0,
    )

    if choice_idx == 1:
        return wordlist_service.load_candidates_from_file(stat_path)

    capped_candidates: set[str] = set()
    try:
        with stat_path.open(encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                candidate = normalize_username_candidate(line)
                if not candidate:
                    continue
                capped_candidates.add(candidate)
                if len(capped_candidates) >= default_cap:
                    break
    except OSError:
        pass
    return capped_candidates


def _build_focused_kerberos_wordlist_for_pattern(
    shell: LdapShell,
    domain: str,
    *,
    pattern_key: str,
) -> str | None:
    """Build a focused Kerberos username wordlist for one selected format."""
    workspace_type = str(getattr(shell, "type", "") or "").strip().lower()
    marked_domain = mark_sensitive(domain, "domain")
    wordlist_service = KerberosUsernameWordlistService()
    kerberos_dir = Path(
        domain_subpath(
            shell._get_workspace_cwd(),
            shell.domains_dir,
            domain,
            shell.kerberos_dir,
        )
    )

    # Estimate statistically-likely count for display hint
    stat_path = wordlist_service.get_statistically_likely_wordlist_path(pattern_key)
    stat_count_hint = ""
    if stat_path and stat_path.exists():
        try:
            stat_count_hint = f" (~{sum(1 for _ in stat_path.open(encoding='utf-8', errors='ignore') if _.strip()):,} candidates)"
        except OSError:
            pass

    if workspace_type == "audit":
        source_options = [
            f"Statistically likely usernames{stat_count_hint}",
            "LinkedIn company employees  (requires browser login)",
            "Known employee names / manual entry",
        ]
        default_sources = [f"Statistically likely usernames{stat_count_hint}"]
    else:
        source_options = [
            f"Statistically likely usernames{stat_count_hint}",
            "Known employee names / manual entry",
        ]
        default_sources = [f"Statistically likely usernames{stat_count_hint}"]

    selected_sources = shell._questionary_checkbox(
        f"Select username sources for {marked_domain}",
        source_options,
        default_values=default_sources,
    )

    # Normalise keys back to canonical labels regardless of hint suffix
    def _normalise_source(s: str) -> str:
        s = s.split("(")[0].strip()
        if s.startswith("Statistically"):
            return "Statistically likely usernames"
        if s.startswith("LinkedIn"):
            return "LinkedIn company employees"
        return "Known employee names / manual generation"

    selected_sources = [_normalise_source(s) for s in (selected_sources or [])]
    if not selected_sources:
        print_warning("No username sources were selected.")
        return None

    merged_candidates: set[str] = set()
    source_metadata: list[KerberosWordlistSourceMetadata] = []

    if "Statistically likely usernames" in selected_sources:
        stat_path = wordlist_service.get_statistically_likely_wordlist_path(pattern_key)
        if stat_path is None:
            print_warning(
                f"No statistically-likely wordlist is available for the "
                f"'{USERNAME_PATTERN_LABELS.get(pattern_key, pattern_key)}' format."
            )
        else:
            stat_candidates = _load_statistically_likely_candidates_with_cap(
                shell, wordlist_service, stat_path, domain=domain
            )
            merged_candidates.update(stat_candidates)
            source_metadata.append(
                KerberosWordlistSourceMetadata(
                    source="statistically_likely_usernames",
                    pattern_key=pattern_key,
                    candidate_count=len(stat_candidates),
                    details={"path": str(stat_path)},
                )
            )

    if "Known employee names / manual generation" in selected_sources:
        names = _collect_name_pairs_interactive(shell, domain)
        if names:
            generated_candidates = wordlist_service.generate_candidates_from_names(
                names,
                pattern_key=pattern_key,
            )
            merged_candidates.update(generated_candidates)
            source_metadata.append(
                KerberosWordlistSourceMetadata(
                    source="manual_names",
                    pattern_key=pattern_key,
                    candidate_count=len(generated_candidates),
                    details={"name_pairs": len(names)},
                )
            )

    if "LinkedIn company employees" in selected_sources:
        if pattern_key not in LINKEDIN_SUPPORTED_PATTERN_KEYS:
            print_warning(
                f"LinkedIn generation does not support the "
                f"'{USERNAME_PATTERN_LABELS.get(pattern_key, pattern_key)}' format yet."
            )
        else:
            company_slug = _prompt_validated_linkedin_company_slug(shell)
            if not company_slug:
                print_info("Skipping LinkedIn employee discovery.")
            else:
                try:
                    session_cache_path = kerberos_dir / "linkedin_session.json"
                    linkedin_service = LinkedInUsernameDiscoveryService(
                        cache_provider=CachedLinkedInSessionProvider(session_cache_path)
                    )
                    company_info, employees = linkedin_service.login_and_collect(
                        company_slug=company_slug,
                        wait_for_user_ready=lambda: _prompt_linkedin_ready(shell),
                        geoblast=True,
                    )
                    raw_name_lines = [employee.full_name for employee in employees]
                    if raw_name_lines:
                        generated_candidates = (
                            wordlist_service.generate_candidates_from_linkedin_names(
                                raw_name_lines,
                                pattern_key=pattern_key,
                            )
                        )
                        merged_candidates.update(generated_candidates)
                        (
                            kerberos_dir / f"linkedin_{company_slug}_raw_names.txt"
                        ).write_text(
                            "\n".join(sorted(set(raw_name_lines))) + "\n",
                            encoding="utf-8",
                        )
                        source_metadata.append(
                            KerberosWordlistSourceMetadata(
                                source="linkedin_employees",
                                pattern_key=pattern_key,
                                candidate_count=len(generated_candidates),
                                details={
                                    "company_slug": company_slug,
                                    "company_name": company_info.name,
                                    "staff_count": company_info.staff_count,
                                    "raw_profiles": len(employees),
                                    "usable_full_names": len(raw_name_lines),
                                },
                            )
                        )
                    else:
                        print_warning(
                            "LinkedIn employee discovery completed, but no usable employee names "
                            "were extracted from the returned profiles."
                        )
                except Exception as exc:
                    telemetry.capture_exception(exc)
                    print_warning(f"LinkedIn employee discovery failed: {exc}")

    if not merged_candidates:
        print_warning(
            f"No username candidates were generated for {marked_domain}. "
            "Try another source selection or use a custom wordlist."
        )
        return None

    output_path = wordlist_service.write_generated_wordlist(
        kerberos_dir=kerberos_dir,
        output_name="kerberos_user_candidates.txt",
        candidates=merged_candidates,
        metadata=source_metadata,
        domain=domain,
    )
    marked_output = mark_sensitive(str(output_path), "path")
    print_success(
        f"Generated {len(merged_candidates)} focused Kerberos username candidates at {marked_output}"
    )
    return str(output_path)


def _build_targeted_kerberos_wordlist(shell: LdapShell, domain: str) -> str | None:
    """Legacy entry point — delegates to the unified strategy selector."""
    return _select_kerberos_wordlist_strategy(shell, domain)


def _show_kerberos_enum_shortcut_hint(
    shell: LdapShell, domain: str, *, had_results: bool = True
) -> None:
    """Render a reusable reminder for rerunning Kerberos user enumeration only."""

    marked_domain = mark_sensitive(domain, "domain")
    workspace_cwd = shell.current_workspace_dir or shell._get_workspace_cwd()
    users_file = domain_subpath(workspace_cwd, shell.domains_dir, domain, "users.txt")
    users_rel = os.path.join("domains", domain, "users.txt")
    has_users_file = os.path.exists(users_file) and os.path.getsize(users_file) > 0

    lines: list[str]
    if had_results:
        lines = [
            "If you want to keep enumerating users via Kerberos later, you do not need to rerun the full scan.",
            "",
            f"Use this shortcut instead: kerberos_enum_users {marked_domain}",
        ]
    else:
        lines = [
            "No users were validated with the last Kerberos enumeration run.",
            "",
            "You can retry this step directly later with a different strategy or wordlist.",
            "",
            f"Use this shortcut instead: kerberos_enum_users {marked_domain}",
        ]
    if has_users_file:
        lines.append(f"Current users file: {mark_sensitive(users_rel, 'path')}")
    else:
        lines.append(
            "If you skipped the wordlist or want to retry with a better list, "
            "you can come back to this step directly."
        )

    from adscan_core.theme import ADSCAN_PRIMARY

    print_panel(
        "\n".join(lines),
        title=f"[bold {ADSCAN_PRIMARY}]Shortcut: Kerberos user enumeration[/bold {ADSCAN_PRIMARY}]",
        border_style=ADSCAN_PRIMARY,
        expand=False,
    )


def get_domain_controllers(shell: LdapShell, domain: str) -> list[str]:
    """Return members of the Domain Controllers group via native LDAP."""
    try:
        from adscan_internal.services.native_group_membership import (
            resolve_enabled_group_members_by_rid_native,
        )

        members = resolve_enabled_group_members_by_rid_native(
            shell,
            domain,
            516,
            member_kind="computer",
            operation_name="Domain Controllers lookup",
        )
        return members or []
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Error in get_domain_controllers.")
        print_exception(show_locals=False, exception=exc)
        return []


def get_not_delegated_users(shell: LdapShell, domain: str) -> list[str]:
    """Return users with the NOT_DELEGATED UAC flag via native LDAP query."""
    try:
        from adscan_internal.services.ldap_query_service import (
            query_shell_ldap_attribute_values,
        )

        values = query_shell_ldap_attribute_values(
            shell,
            domain=domain,
            ldap_filter=(
                "(&(objectCategory=person)(objectClass=user)"
                "(userAccountControl:1.2.840.113556.1.4.803:=1048576))"
            ),
            attribute="samAccountName",
            auth_username=str(shell.domains_data[domain]["username"]),
            auth_password=str(shell.domains_data[domain]["password"]),
            pdc=str(shell.domains_data[domain].get("pdc") or ""),
            prefer_kerberos=True,
            allow_ntlm_fallback=True,
            operation_name="NOT_DELEGATED users",
        )
        if values is None:
            return []
        return sorted(
            {str(value).strip() for value in values if str(value).strip()},
            key=str.lower,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Error in get_not_delegated_users.")
        print_exception(show_locals=False, exception=exc)
        return []


def check_maq(shell: LdapShell, domain: str, username: str, password: str) -> int:
    """Check MachineAccountQuota using ADscan's native LDAP transport."""
    try:
        print_success("Checking MachineAccountQuota")
        value = _read_machine_account_quota_native(
            domain=domain,
            dc_ip=str(shell.domains_data[domain]["pdc"]),
            username=username,
            password=password,
        )
        if value is None:
            print_error("Could not retrieve the MachineAccountQuota")
            return 0
        print_success(f"MachineAccountQuota found: {value}")
        return value
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Error checking MAQ.")
        print_exception(show_locals=False, exception=exc)
        return 0


def _read_machine_account_quota_native(
    *,
    domain: str,
    dc_ip: str,
    username: str,
    password: str,
) -> int | None:
    """Read ``ms-DS-MachineAccountQuota`` directly from the domain object.

    Args:
        domain: Target domain FQDN.
        dc_ip: Target domain controller IP or hostname.
        username: Authenticating username.
        password: Authenticating password.

    Returns:
        The configured domain MAQ value, or ``None`` when it cannot be read.
    """
    from adscan_internal.services.ldap_transport_service import ADscanLDAPConfig  # noqa: PLC0415
    from adscan_internal.services.machine_account_provisioning_service import (  # noqa: PLC0415
        assess_machine_account_capacity,
    )

    config = ADscanLDAPConfig(
        domain=domain,
        dc_ip=dc_ip,
        use_ldaps=True,
        use_kerberos=False,
        username=username,
        password=password,
    )
    capacity = assess_machine_account_capacity(
        ldap_config=config,
        actor_username=username,
    )
    return capacity.domain_quota


def run_ldap_descriptions(
    shell: LdapShell, target_domain: str, *, anonymous: bool = False
) -> None:
    """Enumerate user descriptions and analyze them for leaked credentials.

    Native badldap implementation: a single paged search for
    ``(&(objectCategory=person)(objectClass=user))`` over an explicit
    ``ldap+simple://`` (anonymous) or authenticated ``ADscanLDAPConnection``
    bind, requesting ``sAMAccountName``, ``description``, ``info``,
    ``comment``, ``unixUserPassword``, ``userPassword``. Replaces the
    five-NetExec-modules subprocess fan-out (-M user-desc, get-desc-users,
    get-unixUserPassword, get-userPassword, get-info-users).

    Backwards-compatible artefacts:
      * ``domains/<domain>/ldap/descriptions.log`` text dump (parsed by
        downstream credsweeper analysis)
      * ``domains/<domain>/ldap/descriptions.json`` structured findings

    Sensitive-keyword matches in any of the description-class fields are
    surfaced as ``ldap_user_description_password_leak`` technical findings.
    """
    # The authenticated Phase 3 quick-win is part of ``quick_credential_wins``;
    # honor a scan-config disable. The anonymous/unauth-surface call path is a
    # different phase and is never gated here.
    if not anonymous:
        from adscan_internal.services.scan_phases import (
            phase_is_enabled,
            subphase_is_enabled,
        )

        if not phase_is_enabled(shell, "quick_credential_wins"):
            return
        if not subphase_is_enabled(shell, "quick_credential_wins", "ldap_descriptions"):
            print_info(
                "LDAP description parsing skipped (disabled in scan configuration)."
            )
            return
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return

    pdc_target = str(shell.domains_data[target_domain].get("pdc") or "").strip()
    if not pdc_target:
        print_error(
            f"No PDC recorded for domain {mark_sensitive(target_domain, 'domain')}; "
            "cannot enumerate LDAP descriptions."
        )
        return

    if anonymous:
        username = ""
        password = ""
        nt_hash = ""
        auth_label = "Anonymous"
    else:
        username = str(shell.domains_data[shell.domain].get("username") or "")
        password = str(shell.domains_data[shell.domain].get("password") or "")
        nt_hash = str(shell.domains_data[shell.domain].get("nt_hash") or "")
        auth_label = "Password / Hash"

    print_operation_header(
        "LDAP User Descriptions Enumeration",
        details={
            "Domain": target_domain,
            "PDC": pdc_target,
            "Authentication": auth_label,
            "Mode": "Native badldap (single paged search)",
            "Username": username if username else "Anonymous",
        },
        icon="📝",
    )

    sensitive_attrs = (
        "sAMAccountName",
        "description",
        "info",
        "comment",
        "unixUserPassword",
        "userPassword",
    )
    ldap_filter = "(&(objectCategory=person)(objectClass=user))"

    # ── Source selection: prefer the persisted collector inventory ──────────
    # The native collector already enumerated and persisted the four
    # credential-bearing fields (description, unixUserPassword, userPassword,
    # info) for every user into ``inventory/users.json``. When that snapshot
    # exists, reuse it and skip the live LDAP query entirely; otherwise fall
    # back to the live native search. Both sources converge on the same
    # downstream artefacts, display, analysis and credential extraction.
    cred_fields = _load_credential_fields_from_inventory(shell, target_domain)
    using_inventory = bool(cred_fields)

    rows: list[dict[str, object]] = []
    if using_inventory:
        print_info_verbose(
            "Using persisted LDAP user inventory; skipping live description query."
        )
    else:
        # ── Native query ─────────────────────────────────────────────────────
        # Posture wiring: let the auth planner skip a doomed LDAPS:636 connect
        # when the workspace already knows LDAPS is unavailable (e.g. the native
        # collector connected on LDAP/389 because 636 is filtered with RST), and
        # let a fresh 636 transport failure on this path record the signal for
        # downstream consumers. Mirrors the canonical pattern in cli/rdp.py.
        posture_snapshot = None
        posture_sink = None
        if not anonymous:
            domains_data = getattr(shell, "domains_data", None)
            if domains_data is not None:
                try:
                    from adscan_internal import get_console
                    from adscan_internal.cli.widgets.intelligence_update import (
                        render_intelligence_update,
                    )
                    from adscan_internal.services.domain_posture import get_posture
                    from adscan_internal.services.posture_sink import (
                        make_workspace_posture_sink,
                    )

                    posture_snapshot = get_posture(domains_data, domain=target_domain)
                    posture_sink = make_workspace_posture_sink(
                        domains_data,
                        on_finding=lambda finding: get_console().print(
                            render_intelligence_update(finding)
                        ),
                    )
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
                    print_info_debug(f"[ldap-desc] posture wiring skipped: {exc}")

        try:
            rows = _native_user_description_query(
                domain=target_domain,
                dc_ip=pdc_target,
                anonymous=anonymous,
                username=username,
                password=password,
                nt_hash=nt_hash,
                ldap_filter=ldap_filter,
                attributes=list(sensitive_attrs),
                timeout=120,
                posture_snapshot=posture_snapshot,
                posture_sink=posture_sink,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error(f"Error executing native LDAP description query: {exc}")
            print_exception(show_locals=False, exception=exc)
            return

        if not rows:
            print_warning("No user descriptions returned from LDAP.")
            return

        cred_fields = _credential_fields_from_live_rows(rows)

    # ── Persist artefacts (text + JSON) ──────────────────────────────────
    workspace_cwd = shell._get_workspace_cwd()
    ldap_dir = domain_subpath(
        workspace_cwd, shell.domains_dir, target_domain, shell.ldap_dir
    )
    os.makedirs(ldap_dir, exist_ok=True)
    descriptions_log = os.path.join(ldap_dir, "descriptions.log")
    descriptions_json = os.path.join(ldap_dir, "descriptions.json")

    # Description-only view drives the text dump and the Rich display; the
    # full per-field map (``cred_fields``) drives the CredSweeper analysis.
    user_descriptions: dict[str, str] = _descriptions_only_view(cred_fields)
    json_records: list[dict[str, object]] = []
    sensitive_pattern = re.compile(r"(?i)password|pwd|pass|secret|cred|key|p@ss|p4ss")
    sensitive_findings: list[dict[str, object]] = []

    if using_inventory:
        # Build JSON records / sensitive findings from the persisted per-field
        # map. ``comment`` is not a credential-bearing field, so it is omitted
        # here (the live path tracks it for parity only).
        for sam, fields in cred_fields.items():
            desc = str(fields.get("description") or "").strip()
            info = str(fields.get("info") or "").strip()
            unix_pw = str(fields.get("unixUserPassword") or "").strip()
            user_pw = str(fields.get("userPassword") or "").strip()
            json_records.append(
                {
                    "samaccountname": sam,
                    "description": desc,
                    "info": info,
                    "comment": "",
                    "unixUserPassword": unix_pw,
                    "userPassword": user_pw,
                }
            )
            blob = " || ".join(filter(None, [desc, info, unix_pw, user_pw]))
            if blob and sensitive_pattern.search(blob):
                sensitive_findings.append(
                    {
                        "samaccountname": sam,
                        "matched_text": blob[:300],
                        "fields": {
                            "description": desc,
                            "info": info,
                            "comment": "",
                            "unixUserPassword": unix_pw,
                            "userPassword": user_pw,
                        },
                    }
                )
        try:
            with open(descriptions_log, "w", encoding="utf-8") as log_fp:
                log_fp.write("User:                     Description:\n")
                for sam, desc in user_descriptions.items():
                    log_fp.write(f"{sam:<25} {desc}\n")
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning(f"Failed to write descriptions.log: {exc}")
    else:
        try:
            with open(descriptions_log, "w", encoding="utf-8") as log_fp:
                log_fp.write("User:                     Description:\n")
                for row in rows:
                    sam = str(row.get("sAMAccountName") or "").strip()
                    if not sam:
                        continue
                    desc = str(row.get("description") or "").strip()
                    info = str(row.get("info") or "").strip()
                    comment = str(row.get("comment") or "").strip()
                    unix_pw = str(row.get("unixUserPassword") or "").strip()
                    user_pw = str(row.get("userPassword") or "").strip()
                    # Primary description for parity with the legacy parser.
                    if desc:
                        log_fp.write(f"{sam:<25} {desc}\n")
                    # Side-channel password fields are tracked in JSON only.
                    json_records.append(
                        {
                            "samaccountname": sam,
                            "description": desc,
                            "info": info,
                            "comment": comment,
                            "unixUserPassword": unix_pw,
                            "userPassword": user_pw,
                        }
                    )
                    blob = " || ".join(
                        filter(None, [desc, info, comment, unix_pw, user_pw])
                    )
                    if blob and sensitive_pattern.search(blob):
                        sensitive_findings.append(
                            {
                                "samaccountname": sam,
                                "matched_text": blob[:300],
                                "fields": {
                                    "description": desc,
                                    "info": info,
                                    "comment": comment,
                                    "unixUserPassword": unix_pw,
                                    "userPassword": user_pw,
                                },
                            }
                        )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning(f"Failed to write descriptions.log: {exc}")

    try:
        import json as _json

        with open(descriptions_json, "w", encoding="utf-8") as jfp:
            _json.dump(
                {
                    "domain": target_domain,
                    "anonymous": anonymous,
                    "count": len(json_records),
                    "records": json_records,
                    "sensitive_findings": sensitive_findings,
                },
                jfp,
                indent=2,
                ensure_ascii=False,
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning(f"Failed to write descriptions.json: {exc}")

    # ── Render + analysis (sweep all four credential-bearing fields) ──────
    if user_descriptions:
        _display_ldap_descriptions_with_rich(user_descriptions)
    if cred_fields:
        try:
            _analyze_descriptions_for_passwords(
                shell,
                descriptions_log,
                cred_fields,
                target_domain,
                anonymous=anonymous,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning(f"Description analysis failed: {exc}")

    # ── Surface sensitive findings into the report ───────────────────────
    if sensitive_findings:
        try:
            from adscan_core.reporting.technical_report import record_technical_finding

            record_technical_finding(
                shell,
                target_domain,
                key="ldap_user_description_password_leak",
                value={"count": len(sensitive_findings)},
                details={
                    "anonymous": anonymous,
                    "samples": [
                        {
                            "samaccountname": entry["samaccountname"],
                            "matched_text": entry["matched_text"],
                        }
                        for entry in sensitive_findings[:10]
                    ],
                },
                evidence=[
                    {
                        "type": "log",
                        "summary": "LDAP user description / password fields",
                        "artifact_path": descriptions_log,
                    },
                    {
                        "type": "json",
                        "summary": "Structured LDAP description findings",
                        "artifact_path": descriptions_json,
                    },
                ],
            )
        except Exception as exc:  # noqa: BLE001
            if not handle_optional_report_service_exception(
                exc,
                action="LDAP description password leak finding sync",
                debug_printer=print_info_debug,
                prefix="[ldap-desc]",
            ):
                telemetry.capture_exception(exc)


def _native_user_description_query(
    *,
    domain: str,
    dc_ip: str,
    anonymous: bool,
    username: str,
    password: str,
    nt_hash: str,
    ldap_filter: str,
    attributes: list[str],
    timeout: int,
    posture_snapshot: object | None = None,
    posture_sink: object | None = None,
) -> list[dict[str, object]]:
    """Run the native LDAP description-attribute search.

    Anonymous path uses the same ``ldap+simple://`` simple-bind pattern as
    :func:`adscan_internal.services.unauth_enrichment_service._enrich_ldap_active_users_native`.
    Authenticated path goes through ``ADscanLDAPConnection`` so LDAPS->LDAP
    fallback, sign/seal toggles, and Kerberos ccache plumbing all stay
    centralized.

    ``posture_snapshot`` / ``posture_sink`` are forwarded to
    ``ADscanLDAPConfig`` so the auth planner prunes already-known-unavailable
    LDAPS (skips a doomed 636 connect when the workspace recorded LDAPS down)
    and a real 636 transport failure on this path emits an LDAPS-unavailable
    signal for downstream consumers. The helper stays shell-agnostic: the
    caller resolves these objects from ``shell`` and passes them in.
    """
    if anonymous:
        return _native_user_description_query_anonymous(
            dc_ip=dc_ip,
            ldap_filter=ldap_filter,
            attributes=attributes,
            timeout=timeout,
        )

    from adscan_internal.services.ldap_transport_service import (
        ADscanLDAPConfig,
        ADscanLDAPConnection,
    )

    secret = nt_hash or password
    if not username or not secret:
        raise ValueError(
            "Authenticated LDAP descriptions query requires username + password/nt_hash."
        )

    config = ADscanLDAPConfig(
        domain=domain,
        dc_ip=dc_ip,
        use_ldaps=True,
        use_kerberos=False,
        username=username,
        password=secret,
        posture_snapshot=posture_snapshot,
        posture_sink=posture_sink,
    )

    rows: list[dict[str, object]] = []
    with ADscanLDAPConnection(config) as conn:
        # The connection's domain_dn is derived from `domain`; that's the
        # canonical search base.
        conn.search(
            search_base=conn.domain_dn,
            search_filter=ldap_filter,
            attributes=attributes,
            search_scope="SUBTREE",
            paged_size=1000,
        )
        for entry in conn.entries:
            attrs = entry.entry_attributes_as_dict
            row: dict[str, object] = {}
            for attr in attributes:
                values = attrs.get(attr)
                if isinstance(values, list):
                    row[attr] = values[0] if values else ""
                elif values is not None:
                    row[attr] = values
                else:
                    row[attr] = ""
            rows.append(row)
    return rows


def _native_user_description_query_anonymous(
    *,
    dc_ip: str,
    ldap_filter: str,
    attributes: list[str],
    timeout: int,
) -> list[dict[str, object]]:
    """Anonymous variant — centralized simple-bind, then paged search."""
    from adscan_internal.services.async_bridge import run_async_sync
    from adscan_internal.services.ldap_transport_service import (
        anonymous_default_naming_context,
        async_anonymous_ldap_connection,
    )

    async def _run() -> list[dict[str, object]]:
        # Centralized anonymous SIMPLE-bind with LDAPS->LDAP fallback.
        async with async_anonymous_ldap_connection(
            dc_ip, timeout=timeout
        ) as (conn, _used_ldaps):
            base_dn = anonymous_default_naming_context(conn)
            if not base_dn:
                return []

            collected: list[dict[str, object]] = []
            try:
                async for item, err in conn.pagedsearch(
                    ldap_filter,
                    attributes,
                    controls=None,
                    tree=base_dn,
                    search_scope=2,
                ):
                    if err is not None:
                        raise err
                    attrs = dict(item.get("attributes", {}) or {})
                    row: dict[str, object] = {}
                    for attr in attributes:
                        v = attrs.get(attr)
                        if v is None:
                            v = attrs.get(attr.lower())
                        if isinstance(v, list):
                            row[attr] = v[0] if v else ""
                        elif v is not None:
                            row[attr] = v
                        else:
                            row[attr] = ""
                    collected.append(row)
            except Exception as exc:  # noqa: BLE001
                # Bind OK but search denied — return what we have.
                telemetry.capture_exception(exc)
                print_info_debug(
                    f"[ldap-desc] anonymous search denied on "
                    f"{mark_sensitive(dc_ip, 'host')}: {exc}"
                )
                return collected
            return collected

    return run_async_sync(_run())


def run_enumerate_user_aces(shell: LdapShell, args: str) -> None:
    """Parse arguments and initiate user ACE enumeration.

    This function parses the command-line arguments (domain, username, password)
    and delegates to the shell's `ask_for_enumerate_user_aces` method.

    Args:
        shell: Shell instance with `ask_for_enumerate_user_aces` method.
        args: Space-separated string containing domain, username, and password.

    Usage:
        run_enumerate_user_aces(shell, "example.local alice Passw0rd!")
    """
    parts = args.split()
    if len(parts) != 3:
        print_error(
            "Usage: enumerate_user_aces <domain> <user> <password>\n"
            "Example: enumerate_user_aces example.local username password"
        )
        return

    domain, username, password = parts
    shell.ask_for_enumerate_user_aces(domain, username, password)


# Helper functions for NetExec LDAP descriptions processing


def _get_nxc_base_dir() -> str:
    """Return the NetExec (nxc) state directory (~/.nxc) for the effective user."""
    return os.path.join(str(get_effective_user_home()), ".nxc")


def _find_and_move_userdesc_log(shell: LdapShell, domain: str) -> Optional[str]:
    """Find the most recent UserDesc log file generated by netexec and move it to our domain directory.

    Args:
        shell: Shell instance with workspace and domain helpers.
        domain: Domain name.

    Returns:
        Path to moved file, or None if not found.
    """
    try:
        nxc_dir = _get_nxc_base_dir()
        if not os.path.exists(nxc_dir):
            print_warning("NetExec log directory not found (~/.nxc).")
            return None

        # Find all UserDesc log files
        userdesc_files = []
        for filename in os.listdir(nxc_dir):
            if filename.startswith("UserDesc-") and filename.endswith(".log"):
                filepath = os.path.join(nxc_dir, filename)
                # Get modification time
                mtime = os.path.getmtime(filepath)
                userdesc_files.append((mtime, filepath, filename))

        if not userdesc_files:
            print_warning("No UserDesc log files found in ~/.nxc/")
            return None

        # Sort by modification time (most recent first)
        userdesc_files.sort(reverse=True)

        # Get the most recent file
        _, source_file, _ = userdesc_files[0]

        workspace_cwd = shell._get_workspace_cwd()
        ldap_dir = domain_subpath(
            workspace_cwd, shell.domains_dir, domain, shell.ldap_dir
        )
        os.makedirs(ldap_dir, exist_ok=True)

        dest_file = os.path.join(ldap_dir, "descriptions.log")
        dest_file_rel = domain_relpath(
            shell.domains_dir, domain, shell.ldap_dir, "descriptions.log"
        )

        # Move the file (not copy)
        if SECRET_MODE:
            print_info_verbose(f"Moving {source_file} to {dest_file}")
        shutil.move(source_file, dest_file)

        print_success(f"Moved UserDesc log to {dest_file_rel}")
        return dest_file

    except Exception as e:
        telemetry.capture_exception(e)
        print_warning(f"Error finding/moving UserDesc log file: {e}")
        return None


def _parse_userdesc_log_file(log_file: str) -> dict[str, str]:
    """Parse netexec UserDesc log file to extract user:description pairs.

    Format:
    User:                     Description:
    Administrator             Built-in account for administering the computer/domain
    Guest                     Built-in account for guest access to the computer/domain

    Args:
        log_file: Path to UserDesc log file.

    Returns:
        Dictionary mapping usernames to their descriptions.
    """
    user_descriptions = {}

    try:
        with open(log_file, "r", encoding="utf-8") as f:
            lines = f.readlines()

        # Skip header line "User:                     Description:"
        # Start from line 2 (index 1)
        for line in lines[1:]:
            line = line.rstrip("\n\r")
            if not line.strip():
                continue

            # Format: "username                     description"
            # Username and description are separated by multiple spaces
            # Split by multiple spaces (2+)
            parts = re.split(r"\s{2,}", line.strip())

            if len(parts) >= 2:
                username = parts[0].strip()
                description = " ".join(
                    parts[1:]
                ).strip()  # Join in case description has spaces

                if username and description:
                    user_descriptions[username] = description
            elif len(parts) == 1 and parts[0].strip():
                # Sometimes description might be empty, skip
                if SECRET_MODE:
                    print_info_debug(f"Skipping line with only username: {parts[0]}")

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error parsing UserDesc log file.")
        print_exception(show_locals=False, exception=e)

    return user_descriptions


def _save_ldap_descriptions_json(
    shell: LdapShell, user_descriptions: dict[str, str], domain: str
) -> Optional[str]:
    """Save user descriptions to JSON file (for our own format/storage).

    Args:
        shell: Shell instance with workspace helpers.
        user_descriptions: Dictionary mapping usernames to descriptions.
        domain: Domain name.

    Returns:
        Path to saved JSON file, or None if failed.
    """
    if not domain or not user_descriptions:
        return None

    try:
        # Create directory if it doesn't exist
        workspace_cwd = shell._get_workspace_cwd()
        ldap_dir = domain_subpath(
            workspace_cwd, shell.domains_dir, domain, shell.ldap_dir
        )
        os.makedirs(ldap_dir, exist_ok=True)

        # Save as JSON
        json_file = os.path.join(ldap_dir, "descriptions.json")
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "domain": domain,
                    "count": len(user_descriptions),
                    "users": [
                        {"username": username, "description": description}
                        for username, description in sorted(user_descriptions.items())
                    ],
                },
                f,
                indent=2,
                ensure_ascii=False,
            )

        return json_file
    except Exception as e:
        telemetry.capture_exception(e)
        print_warning(f"Error saving LDAP descriptions JSON: {e}")
        return None


def _display_ldap_descriptions_with_rich(
    user_descriptions: dict[str, str], *, max_rows: int = 30
) -> None:
    """Display user descriptions in a structured, aesthetic format using Rich.

    Args:
        user_descriptions: Dictionary mapping usernames to descriptions.
        max_rows: Maximum rows to show (sorted by username).
    """
    if not user_descriptions:
        return

    from adscan_core.theme import COLOR_MUTED, COLOR_STEEL

    max_rows = max(1, int(max_rows))

    table = Table(
        title=f"User descriptions harvested via LDAP ({len(user_descriptions)})",
        show_header=True,
        header_style=f"bold {COLOR_STEEL}",
    )
    table.add_column("#", style=COLOR_MUTED, width=4, justify="right")
    table.add_column("sAMAccountName", style=COLOR_STEEL, no_wrap=False, max_width=30)
    table.add_column("description", no_wrap=False, max_width=80)

    sorted_users = sorted(user_descriptions.items())
    shown_users = sorted_users[:max_rows]

    for idx, (username, description) in enumerate(shown_users, 1):
        display_description = (
            description[:77] + "..." if len(description) > 80 else description
        )
        table.add_row(str(idx), username, display_description)

    if len(sorted_users) > max_rows:
        remaining = len(sorted_users) - max_rows
        table.caption = (
            f"Showing first {max_rows}. {remaining} additional rows omitted."
        )

    print_panel_with_table(
        table,
        border_style=COLOR_STEEL,
    )


def _display_ldap_description_candidates_with_rich(
    user_descriptions: dict[str, str],
    *,
    title: str,
    max_rows: int = 30,
) -> None:
    """Display a subset of user descriptions (e.g., those with credential candidates).

    Args:
        user_descriptions: Dictionary mapping usernames to descriptions.
        title: Table title to display.
        max_rows: Maximum rows to show (sorted by username).
    """
    if not user_descriptions:
        return

    from adscan_core.theme import COLOR_CRIMSON, COLOR_MUTED, COLOR_SAGE

    # Credential patterns in user descriptions are rare and high-value. The row
    # must JUMP: crimson glyph, prominent header, action-oriented "Next:" line.
    print_info(
        f"[{COLOR_CRIMSON}]* {len(user_descriptions)} description(s) match credential patterns[/{COLOR_CRIMSON}] "
        "  -> review each for plaintext passwords, shared secrets, or onboarding hints."
    )

    max_rows = max(1, int(max_rows))
    table = Table(
        title=f"* {title}",
        show_header=True,
        header_style=f"bold {COLOR_CRIMSON}",
    )
    table.add_column("", width=2, justify="center")
    table.add_column("#", style=COLOR_MUTED, width=4, justify="right")
    table.add_column("sAMAccountName", style=COLOR_SAGE, no_wrap=False, max_width=30)
    table.add_column("description (candidate)", no_wrap=False, max_width=80)

    sorted_users = sorted(user_descriptions.items())
    shown_users = sorted_users[:max_rows]

    for idx, (username, description) in enumerate(shown_users, 1):
        display_description = (
            description[:77] + "..." if len(description) > 80 else description
        )
        table.add_row(
            f"[{COLOR_CRIMSON}]*[/{COLOR_CRIMSON}]",
            str(idx),
            username,
            display_description,
        )

    if len(sorted_users) > max_rows:
        remaining = len(sorted_users) - max_rows
        table.caption = (
            f"Showing first {max_rows}. {remaining} additional rows omitted."
        )

    print_panel_with_table(table, border_style=COLOR_CRIMSON)
    print_info(
        f"[{COLOR_CRIMSON}]Next:[/{COLOR_CRIMSON}] try each candidate as a password for its owning account "
        "(and for common shared accounts) before discarding."
    )


def _find_user_for_password_from_line(
    context_line: str, user_descriptions: dict[str, str]
) -> Optional[str]:
    """Find which user a password belongs to based on context line from UserDesc log format.

    Format: "username                     description with password"

    Args:
        context_line: Line containing the password (from UserDesc log).
        user_descriptions: Dictionary mapping usernames to descriptions.

    Returns:
        Username if found, None otherwise.
    """
    # Context line format: "username                     description"
    # Split by multiple spaces to get username
    parts = re.split(r"\s{2,}", context_line.strip())
    if len(parts) >= 1:
        username = parts[0].strip()
        if username in user_descriptions:
            return username
    return None


def _extract_password_candidates_from_credsweeper_findings(
    findings: dict[str, list[tuple[str, Optional[float], str, int, str]]],
    user_descriptions: dict[str, str],
) -> list[dict[str, object]]:
    """Map CredSweeper findings back to LDAP users and return candidate secrets.

    Args:
        findings: CredSweeper findings grouped by rule name.
        user_descriptions: Mapping of usernames -> descriptions.

    Returns:
        List of candidate dicts with username, password, rule, ml_probability, and context.
    """
    candidates: list[dict[str, object]] = []
    for rule_name, items in (findings or {}).items():
        for value, ml_probability, context_line, _line_num, _path in items:
            username = _find_user_for_password_from_line(
                str(context_line or ""), user_descriptions
            )
            if not username:
                continue
            password_value = str(value or "").strip()
            if not password_value or len(password_value) < 3:
                continue
            candidates.append(
                {
                    "username": username,
                    "password": password_value,
                    "rule": str(rule_name or ""),
                    "ml_probability": ml_probability,
                    "context": str(context_line or ""),
                }
            )

    # De-duplicate rule-level duplicates (same username+password found by multiple rules).
    merged: dict[tuple[str, str], dict[str, object]] = {}
    for item in candidates:
        key = (str(item["username"]), str(item["password"]))
        existing = merged.get(key)
        if not existing:
            merged[key] = item
            continue
        # Keep the highest ML probability (when available) and merge rule names.
        existing_rules = (
            set(str(existing.get("rule") or "").split(", "))
            if existing.get("rule")
            else set()
        )
        existing_rules.add(str(item.get("rule") or ""))
        merged[key]["rule"] = ", ".join(sorted(r for r in existing_rules if r))

        existing_prob = existing.get("ml_probability")
        new_prob = item.get("ml_probability")
        if isinstance(existing_prob, (int, float)) and isinstance(
            new_prob, (int, float)
        ):
            merged[key]["ml_probability"] = max(float(existing_prob), float(new_prob))
        elif existing_prob is None and isinstance(new_prob, (int, float)):
            merged[key]["ml_probability"] = float(new_prob)

    return list(merged.values())


_LDAP_DESCRIPTION_NTLM_KEYWORD_RE = re.compile(
    r"(?ix)"
    r"\b(?:ntlm\s*hash|nt\s*hash|nthash)\b"
    r"[^\r\n]{0,24}?"
    r"(?:\:|=|\bis\b|\bto\b)\s*"
    r"([0-9a-f]{32})\b"
)


def _extract_ntlm_hash_candidates_from_descriptions(
    user_descriptions: dict[str, str],
    *,
    source_path: str,
) -> list[dict[str, str]]:
    """Return deterministic NTLM hash candidates anchored to LDAP descriptions."""
    candidates: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for owner_username, description in sorted(user_descriptions.items()):
        description_text = str(description or "").strip()
        if not description_text:
            continue

        parsed_hashes = parse_secretsdump_output(description_text)
        for parsed in parsed_hashes:
            username = (
                str(getattr(parsed, "username", "") or "").strip()
                or str(owner_username or "").strip()
            )
            ntlm_hash = str(getattr(parsed, "ntlm_hash", "") or "").strip().lower()
            if not username or not ntlm_hash:
                continue
            key = (username.lower(), ntlm_hash, str(source_path))
            if key in seen:
                continue
            seen.add(key)
            candidates.append(
                {
                    "username": username,
                    "ntlm_hash": ntlm_hash,
                    "source_path": str(source_path),
                }
            )

        for match in _LDAP_DESCRIPTION_NTLM_KEYWORD_RE.finditer(description_text):
            ntlm_hash = str(match.group(1) or "").strip().lower()
            username = str(owner_username or "").strip()
            if not username or not ntlm_hash:
                continue
            key = (username.lower(), ntlm_hash, str(source_path))
            if key in seen:
                continue
            seen.add(key)
            candidates.append(
                {
                    "username": username,
                    "ntlm_hash": ntlm_hash,
                    "source_path": str(source_path),
                }
            )

    return candidates


# Canonical credential-bearing LDAP fields swept for leaked secrets. Keys are
# the normalized property names the native collector persists into
# ``inventory/users.json`` (see ldap_collector._entry_to_node); values are the
# human-facing field labels surfaced in candidate displays and report findings.
# All four are migrated from the legacy NetExec modules user-desc /
# get-unixUserPassword / get-userPassword / get-info-users — keep them in sync.
_CRED_FIELD_INVENTORY_KEYS: tuple[tuple[str, str], ...] = (
    ("description", "description"),
    ("unix_user_password", "unixUserPassword"),
    ("user_password", "userPassword"),
    ("info_field", "info"),
)

# Live LDAP rows carry the raw attribute names rather than the collector's
# normalized property keys. Map them to the same canonical field labels.
_CRED_FIELD_LIVE_KEYS: tuple[tuple[str, str], ...] = (
    ("description", "description"),
    ("unixUserPassword", "unixUserPassword"),
    ("userPassword", "userPassword"),
    ("info", "info"),
)


def _load_computer_hostnames_from_inventory(
    shell: LdapShell, domain: str
) -> list[str] | None:
    """Read persisted computer hostnames from ``inventory/computers.json``.

    The native LDAP collector persists every computer object (with its
    ``dnshostname`` property and ``samaccountname``) into the domain inventory.
    Reuse that snapshot so this flow does not re-query LDAP when the collector
    has already run. Uses the same workspace-aware inventory path API
    (``domain_subpath`` + ``read_json_file``) as the users-inventory loader.

    Returns:
        A de-duplicated, sorted list of hostnames (``dnshostname`` when present,
        else ``samaccountname`` without the trailing ``$``) when the inventory
        file exists and holds computer records, otherwise ``None`` so the caller
        falls back to a live native query.
    """
    workspace_cwd = (
        shell._get_workspace_cwd()  # noqa: SLF001
        if hasattr(shell, "_get_workspace_cwd")
        else getattr(shell, "current_workspace_dir", "")
    )
    domains_dir = getattr(shell, "domains_dir", "domains")
    inventory_path = domain_subpath(
        workspace_cwd, domains_dir, domain, "inventory", "computers.json"
    )
    if not os.path.exists(inventory_path):
        return None

    try:
        payload = read_json_file(inventory_path)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(f"[ldap-computers] failed to read computers inventory: {exc}")
        return None

    records = payload.get("records") if isinstance(payload, dict) else None
    if not isinstance(records, list):
        return None

    hostnames: list[str] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        properties = record.get("properties")
        dns_name = ""
        if isinstance(properties, dict):
            dns_name = str(properties.get("dnshostname") or "").strip()
        sam = str(record.get("samaccountname") or "").strip().rstrip("$")
        hostname = dns_name or sam
        if hostname:
            hostnames.append(hostname)

    if not hostnames:
        return None
    return sorted(set(hostnames), key=str.lower)


def _load_credential_fields_from_inventory(
    shell: LdapShell, domain: str
) -> dict[str, dict[str, str]]:
    """Read persisted credential-bearing LDAP fields from ``inventory/users.json``.

    The native collector already enumerated and persisted ``description``,
    ``unixUserPassword``, ``userPassword`` and ``info`` for every user into the
    domain inventory. Reuse that snapshot so the analysis phase does not re-query
    LDAP when the collector has already run. Uses the same workspace-aware
    inventory path API (``domain_subpath`` + ``read_json_file``) as
    ``LocalGraphService._inventory_records`` — never a hand-rolled path.

    Returns:
        Mapping of ``sAMAccountName`` -> ``{field_label: value}`` for users that
        carry at least one non-empty credential-bearing field. Empty when the
        inventory file is absent or holds no such fields.
    """
    workspace_cwd = (
        shell._get_workspace_cwd()  # noqa: SLF001
        if hasattr(shell, "_get_workspace_cwd")
        else getattr(shell, "current_workspace_dir", "")
    )
    domains_dir = getattr(shell, "domains_dir", "domains")
    inventory_path = domain_subpath(
        workspace_cwd, domains_dir, domain, "inventory", "users.json"
    )
    if not os.path.exists(inventory_path):
        return {}

    try:
        payload = read_json_file(inventory_path)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(f"[ldap-desc] failed to read users inventory: {exc}")
        return {}

    records = payload.get("records") if isinstance(payload, dict) else None
    if not isinstance(records, list):
        return {}

    cred_fields: dict[str, dict[str, str]] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        sam = str(record.get("samaccountname") or "").strip()
        if not sam:
            continue
        properties = record.get("properties")
        if not isinstance(properties, dict):
            continue
        per_user: dict[str, str] = {}
        for prop_key, label in _CRED_FIELD_INVENTORY_KEYS:
            value = str(properties.get(prop_key) or "").strip()
            if value:
                per_user[label] = value
        if per_user:
            cred_fields[sam] = per_user
    return cred_fields


def _credential_fields_from_live_rows(
    rows: list[dict[str, object]],
) -> dict[str, dict[str, str]]:
    """Convert live LDAP description-query rows into the per-field credential map.

    Mirrors :func:`_load_credential_fields_from_inventory` so both the
    inventory-backed and live-query sources feed the analysis identically. Only
    the four canonical credential-bearing fields are carried; ``comment`` stays
    out of CredSweeper scope (it never held a migrated NetExec module).
    """
    cred_fields: dict[str, dict[str, str]] = {}
    for row in rows:
        sam = str(row.get("sAMAccountName") or "").strip()
        if not sam:
            continue
        per_user: dict[str, str] = {}
        for attr_key, label in _CRED_FIELD_LIVE_KEYS:
            value = str(row.get(attr_key) or "").strip()
            if value:
                per_user[label] = value
        if per_user:
            cred_fields[sam] = per_user
    return cred_fields


def _descriptions_only_view(
    cred_fields: dict[str, dict[str, str]],
) -> dict[str, str]:
    """Return a ``sAMAccountName -> description`` view for description-only helpers.

    The Rich harvest display and the NTLM-hash keyword extraction operate on the
    ``description`` field specifically; this keeps those helpers unchanged while
    the broader analysis sweeps all four fields.
    """
    return {
        sam: fields["description"]
        for sam, fields in cred_fields.items()
        if fields.get("description")
    }


def _analyze_descriptions_for_passwords(
    shell: LdapShell,
    descriptions_file: str,
    cred_fields: dict[str, dict[str, str]],
    domain: str,
    *,
    anonymous: bool = False,
) -> None:
    """Analyze credential-bearing LDAP fields with CredSweeper (in-memory).

    Sweeps all four migrated fields per user — ``description``,
    ``unixUserPassword``, ``userPassword`` and ``info`` — not just
    ``description`` (closing the prior gap where only ``description`` was
    analysed on the live path while the collector swept all four). Mirrors the
    CredSweeper settings used elsewhere so every flow behaves identically:
    ldap_description rules, ml_threshold=0.0, no_filters=True, doc=True. The
    library avoids the CLI subprocess and credsweeper_path dependency entirely.

    Args:
        shell: Runtime shell for credential storage and prompts.
        descriptions_file: Path to the persisted descriptions artefact (used as
            the source anchor for NTLM-hash provenance and report evidence).
        cred_fields: Mapping of ``sAMAccountName`` -> ``{field_label: value}``
            where ``field_label`` is one of ``description``, ``unixUserPassword``,
            ``userPassword`` or ``info``.
        domain: Target domain.
        anonymous: Whether the source bind was anonymous (provenance only).
    """
    if not cred_fields:
        return

    targets: list[InMemoryCredSweeperTarget] = []
    # file_path → (samaccountname, field_label)
    path_index: dict[str, tuple[str, str]] = {}

    for sam, fields in cred_fields.items():
        for field_label, raw_value in fields.items():
            value = (raw_value or "").strip()
            if not value:
                continue
            key = f"ldap/{sam}/{field_label}"
            targets.append(
                InMemoryCredSweeperTarget(
                    content=value.encode("utf-8", errors="replace"),
                    file_path=key,
                    file_type=".txt",
                    info=f"{sam}/{field_label}",
                )
            )
            path_index[key] = (sam, field_label)

    if not targets:
        return

    # Description-only view kept for the harvest display and the NTLM-hash
    # keyword extractor, which are anchored to the description field.
    descriptions_only = _descriptions_only_view(cred_fields)

    try:
        raw = CredSweeperLibraryService().analyze_targets_with_options(
            targets,
            rules_profile=CREDSWEEPER_RULES_PROFILE_LDAP_DESCRIPTION,
            include_custom_rules=True,
            ml_threshold="0.0",
            no_filters=True,
            doc=True,
        )

        # Map findings back to (user, field) via path_index — no heuristics needed.
        findings: dict[str, list] = {}
        for rule_name, entries in (raw or {}).items():
            mapped = []
            for value, ml_probability, context_line, line_num, file_path in entries:
                if file_path not in path_index:
                    continue
                mapped.append((value, ml_probability, context_line, line_num, file_path))
            if mapped:
                findings[rule_name] = mapped

        ntlm_hash_candidates = _extract_ntlm_hash_candidates_from_descriptions(
            descriptions_only,
            source_path=descriptions_file,
        )
        if ntlm_hash_candidates:
            for item in ntlm_hash_candidates:
                username_norm = str(item["username"]).strip().lower()
                ntlm_hash = str(item["ntlm_hash"]).strip().lower()
                shell.add_credential(
                    domain,
                    username_norm,
                    ntlm_hash,
                    source_steps=_build_user_description_source_steps(
                        username=username_norm,
                        anonymous=anonymous,
                        secret=ntlm_hash,
                    ),
                    credential_origin="userdescription",
                )

            descriptions_dir = os.path.dirname(descriptions_file) or "."
            try:
                workspace_cwd = shell.current_workspace_dir or os.getcwd()
                loot_rel = os.path.relpath(descriptions_dir, workspace_cwd)
            except Exception:  # noqa: BLE001
                loot_rel = descriptions_dir
            render_ntlm_hash_findings_flow(
                shell,
                domain=domain,
                loot_dir=descriptions_dir,
                loot_rel=loot_rel,
                phase_label="LDAP description scan",
                ntlm_hash_findings=ntlm_hash_candidates,
                source_scope="LDAP description NTLM hash findings",
                fallback_source_shares=["ldap"],
            )

        # Build candidates directly from path_index, carrying the field each
        # hit came from so the operator can tell a description leak apart from
        # a unixUserPassword / userPassword / info leak. Dedupe per (user, field,
        # value): the same secret echoed across two fields is still two findings.
        seen_cands: set[tuple[str, str, str]] = set()
        candidates: list[dict] = []
        for rule_name, entries in findings.items():
            for value, ml_probability, context_line, _line_num, file_path in entries:
                indexed = path_index.get(file_path)
                if not indexed:
                    continue
                sam, field_label = indexed
                v = str(value or "").strip()
                if not v or len(v) < 3:
                    continue
                ckey = (sam.lower(), field_label, v)
                if ckey in seen_cands:
                    continue
                seen_cands.add(ckey)
                candidates.append({
                    "username": sam,
                    "field": field_label,
                    "password": v,
                    "rule": str(rule_name or ""),
                    "ml_probability": ml_probability,
                    "context": str(context_line or ""),
                })

        if not candidates and not ntlm_hash_candidates:
            print_info_verbose(
                "No passwords detected in LDAP credential-bearing fields."
            )
            return

        # Record the finding for the technical report from the computed
        # candidates (carrying rule / ml_probability / username / field). This
        # runs in both interactive and CI flows — the phase executes when
        # shell.auto is True — so the report no longer depends on the collector
        # having analysed the fields itself.
        _record_credential_in_ldap_attribute_finding(
            shell,
            domain,
            candidates,
            anonymous=anonymous,
            source_path=descriptions_file,
        )

        # Display the matching field value per candidate (not only the
        # description), labelled by field, so non-description leaks are visible.
        candidate_rows: dict[str, str] = {}
        for item in candidates:
            username = str(item["username"])
            field_label = str(item["field"])
            value = str(item["password"])
            row_key = f"{username} [{field_label}]"
            candidate_rows[row_key] = value

        _display_ldap_description_candidates_with_rich(
            candidate_rows,
            title=f"Potential Passwords in LDAP Fields ({len(candidate_rows)} found)",
            max_rows=30,
        )

        for item in candidates:
            field_label = str(item["field"])
            marked_user = mark_sensitive(str(item["username"]), "user")
            marked_value = mark_sensitive(str(item["password"]), "password")
            selection = shell._questionary_select(
                f"Candidate for {marked_user} ({field_label}): {marked_value}"
                "\nHow do you want to handle this?",
                [
                    "Ignore (false positive)",
                    "Save and verify now",
                    "Stop reviewing",
                ],
                default_idx=1,
            )
            if selection is None or selection == 2:
                break
            if selection == 0:
                continue

            username_norm = str(item["username"]).strip().lower()
            value_norm = str(item["password"]).strip()
            shell.add_credential(
                domain,
                username_norm,
                value_norm,
                source_steps=_build_user_description_source_steps(
                    username=username_norm,
                    anonymous=anonymous,
                    secret=value_norm,
                ),
                credential_origin="userdescription",
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("Error analyzing LDAP credential-bearing fields for passwords.")
        print_exception(show_locals=False, exception=exc)


def _record_credential_in_ldap_attribute_finding(
    shell: LdapShell,
    domain: str,
    candidates: list[dict],
    *,
    anonymous: bool,
    source_path: str,
) -> None:
    """Persist the ``credential_in_ldap_attribute`` technical finding.

    Emitted from the computed CredSweeper candidates (carrying rule,
    ml_probability, username and field), moved here from the collector
    intelligence step so the report finding tracks the analysis that owns it.
    LITE-safe: imports ``record_technical_finding`` from ``adscan_core``.
    """
    if not candidates:
        return
    try:
        from adscan_core.reporting.technical_report import record_technical_finding

        record_technical_finding(
            shell,
            domain,
            key="credential_in_ldap_attribute",
            value={"count": len(candidates)},
            details={
                "anonymous": anonymous,
                "count": len(candidates),
                "findings": [
                    {
                        "samaccountname": str(item.get("username") or ""),
                        "field": str(item.get("field") or ""),
                        "rule_name": str(item.get("rule") or ""),
                        "ml_probability": item.get("ml_probability"),
                    }
                    for item in candidates[:50]
                ],
            },
            evidence=[
                {
                    "type": "log",
                    "summary": "LDAP credential-bearing fields (CredSweeper)",
                    "artifact_path": source_path,
                }
            ],
        )
    except Exception as exc:  # noqa: BLE001
        if not handle_optional_report_service_exception(
            exc,
            action="credential-in-LDAP-attribute finding sync",
            debug_printer=print_info_debug,
            prefix="[ldap-desc]",
        ):
            telemetry.capture_exception(exc)


def _build_user_description_source_steps(
    *, username: str, anonymous: bool, secret: str | None = None
) -> list[CredentialSourceStep]:
    """Build credential provenance for a password recovered from LDAP descriptions."""
    username_clean = str(username or "").strip().lower()
    auth_mechanism = "ldap_anonymous_bind" if anonymous else "ldap_authenticated_bind"
    return [
        CredentialSourceStep(
            relation="UserDescription",
            edge_type="user_description",
            entry_label="Domain Users",
            notes={
                "source": "ldap_descriptions",
                "source_username": username_clean,
                "source_protocol": "ldap",
                "auth_mechanism": auth_mechanism,
                **(
                    {"secret": str(secret).strip()} if str(secret or "").strip() else {}
                ),
            },
        )
    ]


def execute_netexec_users(
    shell: LdapShell, *, command: str, domain: str, filename: str
) -> None:
    """Execute the command to generate user lists (e.g., all, admin, privileged) via BloodHound.

    Args:
        shell: Shell instance with command execution and user list processing.
        command: Full command to run.
        domain: Target domain.
        filename: Output filename (e.g., "admins.txt", "privileged.txt").
    """
    try:
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            f"Executing command for {filename} in domain {marked_domain}: {command}"
        )
        completed_process = shell.run_command(
            command,
            timeout=300,
        )
        errors = completed_process.stderr if completed_process else None
        # output = completed_process.stdout # stdout is not directly used, output is written to file by bloodhound-cli

        # Check the process output
        if completed_process and completed_process.returncode == 0:
            try:
                shell._postprocess_user_list_file(
                    domain,
                    filename,
                    source=f"netexec_users:{filename}",
                )
            except Exception as e:
                telemetry.capture_exception(e)
                print_error("Error reading the users file.")
                print_exception(show_locals=False, exception=e)

        else:
            marked_domain = mark_sensitive(domain, "domain")
            print_error(f"Error enumerating users in domain {marked_domain}.")
            if errors:
                print_error(errors)
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error executing netexec.")
        print_exception(show_locals=False, exception=e)


def execute_ldap_computers(
    shell: LdapShell, *, command: str, domain: str, comp_file: str
) -> None:
    """Execute the provided command to generate the computer list,
    then process and display the result, and finally ask whether to perform a port scan.
    If the comp_file is 'enabled_computers.txt', convert hostnames to IPs in the background and then scan.

    Args:
        shell: Shell instance with command execution and computer processing.
        command: Full command to run.
        domain: Target domain.
        comp_file: Output filename (e.g., "enabled_computers.txt").
    """
    try:
        # Ensure relative output paths like `domains/<domain>/...` are written
        # inside the active workspace, regardless of the process CWD.
        workspace_cwd = shell.current_workspace_dir or os.getcwd()
        completed_process = shell.run_command(command, timeout=300, cwd=workspace_cwd)
        if completed_process is None:
            marked_domain = mark_sensitive(domain, "domain")
            print_error(
                f"Computer enumeration did not return a result (timeout or execution error) for domain {marked_domain}."
            )
            return
        errors = completed_process.stderr
        # stdout = completed_process.stdout # Captured, but not directly used by original logic for command output

        if completed_process.returncode == 0:
            marked_domain = mark_sensitive(domain, "domain")
            print_success_verbose(
                f"Computer list successfully generated on domain {marked_domain}."
            )

            # Path to the computers file and nmap directory
            computers_file = domain_subpath(
                workspace_cwd, shell.domains_dir, domain, comp_file
            )
            nmap_dir = domain_subpath(workspace_cwd, shell.domains_dir, domain, "nmap")

            # Read the computers file and count the non-empty lines
            try:
                if not os.path.exists(computers_file):
                    marked_path = mark_sensitive(computers_file, "path")
                    print_error(
                        f"The file {marked_path} does not exist. Did you run and import bloodhound data?"
                    )
                    return
                marked_path = mark_sensitive(computers_file, "path")
                print_info_debug(f"Computers file: {marked_path}")
                with open(
                    computers_file, "r", encoding="utf-8", errors="ignore"
                ) as file:  # 'file' shadows built-in, but kept for consistency
                    computers = [line.strip() for line in file if line.strip()]
                    marked_computers = [mark_sensitive(c, "host") for c in computers]
                    print_info_debug(f"Computers: {marked_computers}")

                # Telemetry: track computer enumeration results
                try:
                    comp_type = comp_file.replace(".txt", "").replace("_", "_")
                    properties = {
                        "computer_type": comp_type,
                        "count": len(computers),
                        "scan_mode": getattr(shell, "scan_mode", None),
                        "auth_type": shell.domains_data[domain].get("auth", "unknown"),
                    }
                    properties.update(
                        build_lab_event_fields(shell=shell, include_slug=True)
                    )
                    telemetry.capture("computers_enumerated", properties)
                except Exception as e:
                    telemetry.capture_exception(e)

                if comp_file == "enabled_computers_with_laps.txt":
                    shell._display_items(computers, "Computers with LAPS")
                elif comp_file == "enabled_computers_without_laps.txt":
                    shell._display_items(computers, "Computers without LAPS")
                else:
                    shell._display_items(computers, "Enabled Computers")
            except Exception as e:
                telemetry.capture_exception(e)
                print_error("Error reading the computers file.")
                print_exception(show_locals=False, exception=e)

            # Create the nmap directory if it does not exist
            if not os.path.exists(nmap_dir):
                os.makedirs(nmap_dir)

            if comp_file == "enabled_computers.txt":
                # Start the hostname-to-IP conversion (and subsequent port scan) sequentially.
                if not shell.do_check_dns(domain):
                    shell.do_update_resolv_conf(
                        f"{domain} {shell.domains_data[domain]['pdc']}"
                    )
                shell.convert_hostnames_to_ips_and_scan(
                    domain, computers_file, nmap_dir
                )
        else:
            marked_domain = mark_sensitive(domain, "domain")
            print_error(f"Error enumerating computers in domain {marked_domain}.")
            if errors:
                print_error(errors)
    except Exception as e:
        telemetry.capture_exception(e)
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"Error enumerating computers in domain {marked_domain}.")
        print_exception(show_locals=False, exception=e)


def ask_for_ldap_users(shell: "LdapShell", target_domain: str) -> None:
    """Prompt to enumerate LDAP users for a domain — mirrors ask_for_ldap_computers."""
    from rich.prompt import Confirm as _Confirm
    from adscan_internal.rich_output import mark_sensitive as _ms
    marked = _ms(target_domain, "domain")
    if _Confirm.ask(f"Do you want to enumerate LDAP users for the domain {marked}?"):
        run_ldap_active_users(shell, target_domain)


def run_ldap_active_users(shell: "LdapShell", target_domain: str) -> None:
    """Enumerate active/enabled users via LDAP for a domain."""
    from adscan_internal.cli.intelligence import run_identity_inventory
    run_identity_inventory(shell, target_domain)
