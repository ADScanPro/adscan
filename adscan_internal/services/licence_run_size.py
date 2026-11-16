"""Size counts of one assessed domain, for the PRO licence usage register.

Every count is read from the place the engine already derives it, never
re-derived here:

* ``users_total``, ``computers_total``, ``domain_controllers`` and
  ``certificate_authorities``: the attack graph's scale counts
  (``domains_data[<domain>]["collection_stats"]``, written by every graph export
  through ``attack_graph_service._compute_ad_scale_stats``).
* ``users_enabled``: the enabled-user count the size band and the Enterprise
  identity count are computed from
  (:func:`adscan_internal.services.estate_size_telemetry.build_estate_size_properties`),
  so ``band == band_for(users_enabled)`` always holds.
* ``computers_enabled``, ``computers_resolving`` and ``computers_reachable``:
  the network-reach coverage derivation
  (:func:`adscan_core.reporting.host_reach_coverage.build_host_reach_coverage`)
  over the enabled computer list and the reachability report the scan wrote.
  Enabled is its ``computers_in_scope``; resolving is the enabled computers
  that resolved to an address the reachability pass probed (reached plus not
  reached); reachable is ``computers_reached``, a computer that answered the
  discovery probe or exposed an open port.
* the three asset-scope counts (``computers_in_asset_scope``,
  ``computers_excluded_by_asset_scope``, ``computers_asset_scope_unconfirmed``):
  the three figures of the report's network-reach statement under an asset
  scope, from its own derivation
  (:func:`adscan_internal.services.host_reach_coverage_stamp.asset_scope_computer_counts`).
  ``None`` when the run had no asset scope (:func:`asset_scope_partition_counts`).

A count this run did not produce is ``None``, never zero and never the figure
an earlier run left in the workspace. "Produced by this run" is decided by
comparing each source with the baseline captured when the domain was admitted
(:func:`capture_size_baseline`): a file whose identity (inode, modification
time in nanoseconds, size) did not change, or a ``collection_stats`` object
that is the same object, was not written by this run. The comparison is by
equality, never by ordering, so the host-clock steps ADscan makes for Kerberos
cannot fool it.

Best-effort throughout: nothing here raises into a scan.
"""

from __future__ import annotations

import json
import os
from typing import Any

from adscan_core import telemetry
from adscan_core.engagement.model import RUN_COMPLETE, RUN_INTERRUPTED, RUN_PARTIAL
from adscan_core.pro_license.run_size import (
    COMPUTER_TIER_FIELDS,
    SIZE_FIELDS,
    normalize_domain_size,
    normalize_run_status,
)
from adscan_core.rich_output import print_exception

_USERS_FILE = "enabled_users.txt"
_COMPUTERS_FILE = "enabled_computers.txt"
_REACHABILITY_FILE = "network_reachability_report.json"
_SCAN_SUMMARY_FILE = "scan_summary.json"
_STATS_KEY = "collection_stats"

#: Register field -> ``collection_stats`` key (the graph's own counts).
_STATS_FIELDS: dict[str, str] = {
    "users_total": "users",
    "computers_total": "computers",
    "computers_total_servers": "servers",
    "computers_total_workstations": "workstations",
    "computers_total_os_unknown": "os_unknown",
    "computers_enabled": "enabled_computers",
    "computers_enabled_servers": "enabled_servers",
    "computers_enabled_workstations": "enabled_workstations",
    "computers_enabled_os_unknown": "enabled_os_unknown",
    "computers_enabled_tier0_direct": "enabled_computers_tier0_direct",
    "computers_enabled_tier0_escalation_capable": "enabled_computers_tier0_escalation_capable",
    "computers_enabled_tier1": "enabled_computers_tier1",
    "computers_enabled_tier2": "enabled_computers_tier2",
    "computers_enabled_tier_by_right": "enabled_computers_tier_by_right",
    "computers_enabled_tier_unknown": "enabled_computers_tier_unknown",
    "domain_controllers": "domain_controllers",
    "certificate_authorities": "certificate_authorities",
}


def _workspace_dir(shell: Any) -> str:
    return str(getattr(shell, "current_workspace_dir", "") or "")


def _domain_file(shell: Any, domain: str, name: str) -> str:
    workspace_dir = _workspace_dir(shell)
    if not workspace_dir or not domain:
        return ""
    from adscan_internal.workspaces import domain_subpath

    try:
        return domain_subpath(workspace_dir, getattr(shell, "domains_dir", None) or "domains", domain, name)
    except (OSError, TypeError, ValueError):
        return ""


def _signature(path: str) -> tuple[int, int, int] | None:
    if not path:
        return None
    try:
        stat = os.stat(path)
    except OSError:
        return None
    return (stat.st_ino, stat.st_mtime_ns, stat.st_size)


def _changed(path: str, before: Any) -> bool:
    current = _signature(path)
    return current is not None and current != (tuple(before) if isinstance(before, (list, tuple)) else before)


def _collection_stats(shell: Any, domain: str) -> Any:
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return None
    data = domains_data.get(domain)
    return data.get(_STATS_KEY) if isinstance(data, dict) else None


def capture_size_baseline(shell: Any, domain: str) -> dict[str, Any]:
    """What the workspace held for ``domain`` before this run assessed it.

    Captured once, at the domain's first admission in the run. Never raises.
    """
    try:
        workspace_dir = _workspace_dir(shell)
        summary = os.path.join(workspace_dir, _SCAN_SUMMARY_FILE) if workspace_dir else ""
        return {
            "users": _signature(_domain_file(shell, domain, _USERS_FILE)),
            "computers": _signature(_domain_file(shell, domain, _COMPUTERS_FILE)),
            "reachability": _signature(_domain_file(shell, domain, _REACHABILITY_FILE)),
            "scan_summary": _signature(summary),
            "stats": _collection_stats(shell, domain),
        }
    except Exception as exc:  # noqa: BLE001 - a baseline never blocks an admission
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return {}


def asset_scope_partition_counts(
    shell: Any, domain: str, baseline: dict[str, Any] | None = None
) -> tuple[int | None, int | None, int | None]:
    """Enabled computers inside the asset scope, excluded by it, and not confirmed.

    The engagement scope engine already says which computers it excluded and
    which it could not confirm (the scope record's two populations), and the
    report's network-reach statement already counts the enabled computers
    against them. These are those three figures, read from that derivation
    (``host_reach_coverage_stamp.asset_scope_computer_counts``): no verdict is
    asked here, no list is partitioned here, and nothing is derived twice, so
    the register states what the report states.

    * inside: enabled computers the scope leaves in (the denominator of the
      report's network-reach statement);
    * excluded: enabled computers the client's scope excludes (a deny entry, or
      an allow-list that does not cover them);
    * not confirmed: enabled computers ADscan could not confirm as within the
      scope and left alone.

    ``(None, None, None)`` when the run had no asset scope. Also when this run
    produced no enabled-computer list for the domain (the directory was not
    collected, or the list is an earlier run's): there is then nothing this
    run counted, and the register never carries an earlier run's figure.
    """
    from adscan_internal.services.host_reach_coverage_stamp import asset_scope_computer_counts

    base = baseline if isinstance(baseline, dict) else {}
    if not _changed(_domain_file(shell, domain, _COMPUTERS_FILE), base.get("computers")):
        return (None, None, None)
    counts = asset_scope_computer_counts(shell, domain)
    if counts is None:
        return (None, None, None)
    return counts


def _reach_counts(shell: Any, domain: str, baseline: dict[str, Any]) -> dict[str, int | None]:
    from adscan_core.reporting.host_reach_coverage import build_host_reach_coverage

    counts: dict[str, int | None] = {"computers_resolving": None, "computers_reachable": None}
    computers_path = _domain_file(shell, domain, _COMPUTERS_FILE)
    report_path = _domain_file(shell, domain, _REACHABILITY_FILE)
    if not _changed(report_path, baseline.get("reachability")):
        return counts
    computers: list[str] = []
    if computers_path:
        try:
            with open(computers_path, "r", encoding="utf-8", errors="ignore") as handle:
                computers = [line.strip() for line in handle if line.strip()]
        except OSError:
            computers = []
    if not computers:
        # No enabled computer list: the coverage derivation would fall back to
        # the report's own hosts, which is not the enabled count.
        return counts
    try:
        with open(report_path, "r", encoding="utf-8") as handle:
            loaded = json.load(handle)
    except (OSError, ValueError):
        return counts
    report = loaded if isinstance(loaded, dict) else None
    block = build_host_reach_coverage(enabled_computers=computers, reachability_report=report)
    if report is not None and block.get("measured"):
        reached = int(block["computers_reached"])
        counts["computers_resolving"] = reached + int(block["computers_not_reached"])
        counts["computers_reachable"] = reached
    return counts


def domain_size_counts(shell: Any, domain: str, baseline: dict[str, Any] | None) -> dict[str, int | None]:
    """The counts of one domain this run produced; ``None`` for the rest. Never raises."""
    size: dict[str, int | None] = dict.fromkeys(SIZE_FIELDS)
    base = baseline if isinstance(baseline, dict) else {}
    try:
        stats = _collection_stats(shell, domain)
        if isinstance(stats, dict) and stats is not base.get("stats"):
            for field, key in _STATS_FIELDS.items():
                size[field] = stats.get(key)
            enabled = stats.get("enabled_computers")
            if isinstance(enabled, int) and enabled > 0 and stats.get("enabled_computers_tier_unknown") == enabled:
                # No enabled computer carries a tier stamp: the graph predates
                # the stamp, so there is no tier count, not "all unknown".
                for field in COMPUTER_TIER_FIELDS:
                    size[field] = None
        if _changed(_domain_file(shell, domain, _USERS_FILE), base.get("users")):
            from adscan_internal.services.estate_size_telemetry import build_estate_size_properties

            size["users_enabled"] = build_estate_size_properties(shell, domain).get("user_count")
        size.update(_reach_counts(shell, domain, base))
        inside, excluded, unconfirmed = asset_scope_partition_counts(shell, domain, base)
        size["computers_in_asset_scope"] = inside
        size["computers_excluded_by_asset_scope"] = excluded
        size["computers_asset_scope_unconfirmed"] = unconfirmed
    except Exception as exc:  # noqa: BLE001 - a size count never breaks a scan
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    return normalize_domain_size(size) or dict.fromkeys(SIZE_FIELDS)


def _scan_was_stopped() -> bool:
    from adscan_core.scan_control import scan_control

    return bool(scan_control().last_scan_aborted)


def run_completion_status(shell: Any, *, baseline: dict[str, Any] | None) -> str:
    """How this run ended, in the engagement vocabulary. Never raises.

    The unattended run (``adscan ci``) already decided it: its coverage
    recorder's run status, read after the coverage is finalised. An
    interactive session has no coverage recorder, so its existing completion
    signals are read instead: an operator stop of the last scan is
    ``partial``; a scan that wrote ``scan_summary.json`` since this domain was
    admitted reached its natural end (``complete``); otherwise the run did not
    reach its end (``interrupted``).
    """
    try:
        recorder = getattr(shell, "_coverage_recorder", None)
        if recorder is not None:
            status = normalize_run_status(getattr(recorder.snapshot(), "run_status", None))
            if status is not None:
                return status
        if _scan_was_stopped():
            return RUN_PARTIAL
        base = baseline if isinstance(baseline, dict) else {}
        workspace_dir = _workspace_dir(shell)
        summary = os.path.join(workspace_dir, _SCAN_SUMMARY_FILE) if workspace_dir else ""
        if _changed(summary, base.get("scan_summary")):
            return RUN_COMPLETE
    except Exception as exc:  # noqa: BLE001 - the status never breaks a scan
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    return RUN_INTERRUPTED


__all__ = [
    "asset_scope_partition_counts",
    "capture_size_baseline",
    "domain_size_counts",
    "run_completion_status",
]
