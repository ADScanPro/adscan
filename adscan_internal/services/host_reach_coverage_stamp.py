"""Stamp the network-reach coverage block from the engine's own measurement.

The SSOT for which computers the assessment reached is the per-domain
``network_reachability_report.json`` the reachability pass writes, scoped by the
enabled computer objects in ``enabled_computers.txt``. This module reads those
two artifacts, adds where the assessment ran from, and persists the
client-facing block through
:func:`adscan_core.reporting.technical_report.record_host_reach_coverage`.

It is called from the scan itself, never only from a report step, because the
web platform's default scan generates no report and still has to declare the
gap: right after the reachability report is written, and once more at scan end
(which also covers a domain whose reachability pass never ran, or a report that
a pivot later widened). Every call re-derives from disk, so the last stamp
always matches the latest measurement.

Best-effort throughout: a coverage stamp never breaks a scan.
"""

from __future__ import annotations

import json
import os
from typing import Any

from adscan_core import telemetry
from adscan_core.reporting.host_reach_coverage import build_host_reach_coverage
from adscan_core.reporting.technical_report import record_host_reach_coverage
from adscan_core.rich_output import print_exception, print_info_debug

_ENABLED_COMPUTERS_FILE = "enabled_computers.txt"
_REACHABILITY_REPORT_FILE = "network_reachability_report.json"


def _domain_dir(shell: Any, domain: str) -> str:
    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "")
    if not workspace_dir or not domain:
        return ""
    domains_dir = str(getattr(shell, "domains_dir", "") or "domains")
    return os.path.join(workspace_dir, domains_dir, domain)


def _read_lines(path: str) -> list[str]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return [line.strip() for line in handle if line.strip()]
    except OSError:
        return []


def _read_json(path: str) -> dict[str, Any] | None:
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _scope_excluded_hostnames(report: dict[str, Any] | None) -> set[str]:
    """Hostnames the reachability pass left out because of the engagement scope."""
    block = (report or {}).get("excluded_by_engagement_scope")
    if not isinstance(block, dict):
        return set()
    return {
        str(name).strip().rstrip(".").lower()
        for name in block.get("hostnames") or ()
        if str(name or "").strip()
    }


def _interface_can_receive_callback(name: str) -> bool:
    from adscan_core.callback_interfaces import (  # noqa: PLC0415
        interface_can_receive_callback,
    )

    return interface_can_receive_callback(name)


def _resolve_vantage(shell: Any, domain: str | None = None) -> dict[str, Any]:
    """Return where the assessment reached ``domain`` from.

    The SSOT is the segment map (``services/network_segments.py``): the
    callback-capable interfaces this domain's in-scope assets are actually routed
    through, with the address the kernel uses on each, so an appliance with one
    adapter per segment reads as every segment interface and a developer host
    never reads as its container bridge. Only when no segment is known yet does
    the operator's selected interface stand in, and never one a target could not
    call back to (``docker0`` was once recorded as the vantage this way).
    """
    try:
        from adscan_internal.services import network_segments  # noqa: PLC0415

        mapped = network_segments.coverage_vantage(shell, domain=domain)
        if mapped.get("interface"):
            return mapped
    except Exception as exc:  # noqa: BLE001 - the vantage is a nicety, never a blocker
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    interface = str(getattr(shell, "interface", "") or "").strip()
    if interface and not _interface_can_receive_callback(interface):
        interface = ""
    address = ""
    if interface:
        try:
            from adscan_core.pal.net import interface_ipv4_for

            address = str(interface_ipv4_for(interface) or "").strip()
        except Exception:  # noqa: BLE001 - the address is a nicety, never a blocker
            address = ""
    if not address:
        # Only an operator declaration stands for "where we ran from" on its own;
        # an interface-derived myip is the startup guess this fallback distrusts.
        from adscan_internal.services.listener_ip import myip_is_declared  # noqa: PLC0415

        if myip_is_declared(shell):
            address = str(getattr(shell, "myip", "") or "").strip()
    return {"interface": interface, "address": address, "interfaces": []}


def _resolve_idle_interfaces(shell: Any) -> list[dict[str, str]]:
    """Adapters a target could call back to that no in-scope host was reached through."""
    try:
        from adscan_internal.services import network_segments  # noqa: PLC0415

        return network_segments.idle_interfaces(shell)
    except Exception as exc:  # noqa: BLE001 - a declaration aid, never a blocker
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return []


def _scoped_reach_inputs(
    shell: Any, domain: str
) -> tuple[list[str], Any, frozenset[str], frozenset[str]] | None:
    """What the network-reach figures of one domain are derived from.

    ``(enabled computers, reachability report, excluded hosts, unconfirmed hosts)``,
    or ``None`` when the domain has neither a computer list nor a reachability
    measurement. The ONE place the engagement scope's two populations are read
    for a count of computers: the stamped block and the usage register's
    asset-scope counts (:func:`asset_scope_computer_counts`) both start here.
    """
    domain_dir = _domain_dir(shell, domain)
    if not domain_dir or not os.path.isdir(domain_dir):
        return None
    computers = _read_lines(os.path.join(domain_dir, _ENABLED_COMPUTERS_FILE))
    report = _read_json(os.path.join(domain_dir, _REACHABILITY_REPORT_FILE))
    if not computers and report is None:
        return None
    # Computers the client excluded from the engagement scope leave every
    # figure: ADscan never contacted them on purpose, so they must not read
    # as computers that did not answer.
    from adscan_internal.services.asset_scope_coverage_stamp import (  # noqa: PLC0415
        excluded_host_names,
    )

    # Which of the two populations a computer is in (excluded by the client,
    # or not confirmed as within the scope) is the scope record's to say.
    excluded_hosts = excluded_host_names(shell, domain, population="excluded")
    unconfirmed_hosts = excluded_host_names(shell, domain, population="unconfirmed")
    # A computer the reachability pass itself left out because of the scope
    # was not measured on purpose either: when the scope record no longer
    # places it in one of the two populations, it still leaves the
    # denominator, so it never reads as a computer that did not answer.
    classified = {str(name).strip().rstrip(".").lower() for name in excluded_hosts}
    classified |= {str(name).strip().rstrip(".").lower() for name in unconfirmed_hosts}
    left_out = _scope_excluded_hostnames(report) - classified
    if left_out:
        computers = [name for name in computers if name.strip().rstrip(".").lower() not in left_out]
    return computers, report, excluded_hosts, unconfirmed_hosts


def asset_scope_computer_counts(shell: Any, domain: str) -> tuple[int, int, int] | None:
    """Enabled computers of ``domain`` inside the asset scope, excluded by it, not confirmed.

    The three figures of the report's network-reach statement, from the same
    derivation (:func:`build_host_reach_coverage` over the enabled computer
    list, with the scope record's two populations): ``computers_in_scope``,
    ``computers_excluded_by_scope`` and ``computers_unconfirmed_scope``. Nothing
    is derived here, so the usage register can never state a number the report
    does not.

    ``None`` when the run has no asset scope, or the domain has no enabled
    computer list to count (the directory was not collected). Never raises.
    """
    try:
        from adscan_internal.services.asset_scope_coverage_stamp import (  # noqa: PLC0415
            asset_scope_block_for_domain,
        )

        if asset_scope_block_for_domain(shell, domain) is None:
            return None
        inputs = _scoped_reach_inputs(shell, domain)
        if inputs is None or not inputs[0]:
            return None
        computers, report, excluded_hosts, unconfirmed_hosts = inputs
        block = build_host_reach_coverage(
            enabled_computers=computers,
            reachability_report=report,
            excluded_hosts=excluded_hosts,
            unconfirmed_hosts=unconfirmed_hosts,
        )
        return (
            int(block.get("computers_in_scope") or 0),
            int(block.get("computers_excluded_by_scope") or 0),
            int(block.get("computers_unconfirmed_scope") or 0),
        )
    except Exception as exc:  # noqa: BLE001 - a count never breaks a scan
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


def stamp_host_reach_coverage(shell: Any, domain: str) -> dict[str, Any] | None:
    """Derive and persist the ``host_reach_coverage`` block for one domain.

    Returns the persisted block, or ``None`` when the domain has nothing in
    scope (no enabled computer list and no reachability measurement) or the
    workspace cannot be resolved. Never raises.
    """
    try:
        inputs = _scoped_reach_inputs(shell, domain)
        if inputs is None:
            return None
        computers, report, excluded_hosts, unconfirmed_hosts = inputs
        block = build_host_reach_coverage(
            enabled_computers=computers,
            reachability_report=report,
            vantage=_resolve_vantage(shell, domain),
            idle_interfaces=_resolve_idle_interfaces(shell),
            excluded_hosts=excluded_hosts,
            unconfirmed_hosts=unconfirmed_hosts,
        )
        if block["computers_in_scope"] <= 0:
            return None
        record_host_reach_coverage(shell, domain, coverage=block)
        print_info_debug(
            "host-reach coverage stamped: "
            f"in_scope={block['computers_in_scope']} "
            f"reached={block['computers_reached']} "
            f"not_reached={block['computers_not_reached']} "
            f"not_attempted={block['computers_not_attempted']} "
            f"not_measured={block['computers_not_measured']} "
            f"silent_segments={block['unreached_segments']}"
        )
        return block
    except Exception as exc:  # noqa: BLE001 - a coverage stamp never breaks a scan
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


def stamp_host_reach_coverage_for_all_domains(shell: Any) -> None:
    """Scan-end pass: stamp every domain the session knows about. Never raises."""
    try:
        domains_data = getattr(shell, "domains_data", {}) or {}
        if not isinstance(domains_data, dict):
            return
        for domain in list(domains_data.keys()):
            if isinstance(domain, str) and domain.strip():
                stamp_host_reach_coverage(shell, domain)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


__all__ = [
    "asset_scope_computer_counts",
    "stamp_host_reach_coverage",
    "stamp_host_reach_coverage_for_all_domains",
]
