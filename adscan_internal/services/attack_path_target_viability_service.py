"""Assess attack-path target viability for operator-facing execution UX."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adscan_internal.services.current_vantage_reachability_service import (
    CurrentVantageResolution,
    resolve_targets_from_current_vantage,
)
from adscan_internal.workspaces.computers import load_enabled_computer_samaccounts


def _normalize_label_token(value: object) -> str:
    """Normalize one principal label token for computer matching."""
    token = str(value or "").strip()
    if "\\" in token:
        token = token.split("\\", 1)[1]
    if "@" in token:
        token = token.split("@", 1)[0]
    return token.strip().rstrip(".")


def _computer_stem(value: object) -> str:
    """Return a lowercase hostname stem for one computer identifier."""
    token = _normalize_label_token(value)
    if token.endswith("$"):
        token = token[:-1]
    if "." in token:
        token = token.split(".", 1)[0]
    return token.strip().lower()


def _candidate_computer_targets(*values: object) -> tuple[str, ...]:
    """Return unique IP/hostname/FQDN candidates for one computer target."""
    candidates: list[str] = []
    seen: set[str] = set()
    for raw_value in values:
        token = _normalize_label_token(raw_value)
        if not token:
            continue
        variants = {token}
        stem = _computer_stem(token)
        if stem:
            variants.add(stem)
            variants.add(f"{stem}$")
        if token.endswith("$"):
            variants.add(token[:-1])
        if "." in token:
            variants.add(token.split(".", 1)[0])
        for candidate in variants:
            candidate_clean = str(candidate or "").strip()
            candidate_key = candidate_clean.lower()
            if not candidate_clean or candidate_key in seen:
                continue
            seen.add(candidate_key)
            candidates.append(candidate_clean)
    return tuple(candidates)


@dataclass(frozen=True)
class ComputerTargetViability:
    """Operator-facing viability assessment for one computer target."""

    requested_target: str
    status: str
    enabled_in_inventory: bool | None
    enabled_inventory_source: str
    resolved_in_current_vantage_inventory: bool | None
    reachable_from_current_vantage: bool | None
    matched_ips: tuple[str, ...]
    matched_hostnames: tuple[str, ...]
    vantage_mode: str | None
    operator_summary: str
    execution_advisory: str | None
    debug_reason: str


def _summarize_computer_viability(
    *,
    requested_target: str,
    enabled_in_inventory: bool | None,
    enabled_inventory_source: str,
    resolution: CurrentVantageResolution,
) -> ComputerTargetViability:
    """Build one stable viability summary from inventory + reachability inputs."""
    matched_assessments = tuple(
        item for item in resolution.assessments if item.matched
    )
    reachable_assessments = tuple(
        item for item in matched_assessments if item.reachable
    )
    matched_ips = tuple(
        sorted({ip for item in matched_assessments for ip in item.matched_ips})
    )
    matched_hostnames = tuple(
        sorted({host for item in matched_assessments for host in item.matched_hostnames})
    )
    resolved_in_current_vantage_inventory = (
        bool(matched_assessments) if resolution.report_available else None
    )
    reachable_from_current_vantage = (
        bool(reachable_assessments) if resolution.report_available else None
    )
    vantage_mode = resolution.vantage_mode

    if enabled_in_inventory is False:
        return ComputerTargetViability(
            requested_target=requested_target,
            status="not_in_enabled_inventory",
            enabled_in_inventory=False,
            enabled_inventory_source=enabled_inventory_source,
            resolved_in_current_vantage_inventory=resolved_in_current_vantage_inventory,
            reachable_from_current_vantage=reachable_from_current_vantage,
            matched_ips=matched_ips,
            matched_hostnames=matched_hostnames,
            vantage_mode=vantage_mode,
            operator_summary=(
                "Not present in ADscan's enabled computer inventory. BloodHound may be stale, "
                "or the host may have been disabled, removed from DNS, or decommissioned."
            ),
            execution_advisory=(
                "Treat this host as potentially stale before attempting host-bound execution."
            ),
            debug_reason="computer_missing_from_enabled_inventory",
        )

    if resolution.report_available:
        if matched_assessments and reachable_assessments:
            return ComputerTargetViability(
                requested_target=requested_target,
                status="reachable_from_current_vantage",
                enabled_in_inventory=enabled_in_inventory,
                enabled_inventory_source=enabled_inventory_source,
                resolved_in_current_vantage_inventory=True,
                reachable_from_current_vantage=True,
                matched_ips=matched_ips,
                matched_hostnames=matched_hostnames,
                vantage_mode=vantage_mode,
                operator_summary="Reachable from the current vantage.",
                execution_advisory=None,
                debug_reason="computer_reachable_from_current_vantage",
            )
        if matched_assessments:
            return ComputerTargetViability(
                requested_target=requested_target,
                status="resolved_but_unreachable",
                enabled_in_inventory=enabled_in_inventory,
                enabled_inventory_source=enabled_inventory_source,
                resolved_in_current_vantage_inventory=True,
                reachable_from_current_vantage=False,
                matched_ips=matched_ips,
                matched_hostnames=matched_hostnames,
                vantage_mode=vantage_mode,
                operator_summary=(
                    "Resolved in current-vantage inventory, but not reachable from the current vantage."
                ),
                execution_advisory=(
                    "Host-bound execution may fail until you pivot or refresh reachability from a better vantage."
                ),
                debug_reason="computer_resolved_but_unreachable_from_current_vantage",
            )
        if enabled_in_inventory is True:
            return ComputerTargetViability(
                requested_target=requested_target,
                status="enabled_but_unresolved",
                enabled_in_inventory=True,
                enabled_inventory_source=enabled_inventory_source,
                resolved_in_current_vantage_inventory=False,
                reachable_from_current_vantage=False,
                matched_ips=(),
                matched_hostnames=(),
                vantage_mode=vantage_mode,
                operator_summary=(
                    "Enabled in directory inventory, but unresolved to IP in current-vantage reachability data."
                ),
                execution_advisory=(
                    "The host may be stale in DNS/AD, or the reachability inventory may need a refresh."
                ),
                debug_reason="computer_enabled_inventory_but_missing_from_current_vantage_inventory",
            )

    if enabled_in_inventory is True:
        return ComputerTargetViability(
            requested_target=requested_target,
            status="enabled_inventory_only",
            enabled_in_inventory=True,
            enabled_inventory_source=enabled_inventory_source,
            resolved_in_current_vantage_inventory=resolved_in_current_vantage_inventory,
            reachable_from_current_vantage=reachable_from_current_vantage,
            matched_ips=matched_ips,
            matched_hostnames=matched_hostnames,
            vantage_mode=vantage_mode,
            operator_summary=(
                "Present in enabled computer inventory, but no current-vantage reachability report is available."
            ),
            execution_advisory=(
                "Refresh network reachability if you want a stronger pre-execution signal for this host."
            ),
            debug_reason="computer_enabled_inventory_without_current_vantage_report",
        )

    return ComputerTargetViability(
        requested_target=requested_target,
        status="unknown",
        enabled_in_inventory=enabled_in_inventory,
        enabled_inventory_source=enabled_inventory_source,
        resolved_in_current_vantage_inventory=resolved_in_current_vantage_inventory,
        reachable_from_current_vantage=reachable_from_current_vantage,
        matched_ips=matched_ips,
        matched_hostnames=matched_hostnames,
        vantage_mode=vantage_mode,
        operator_summary="No reliable target-viability signal is available yet.",
        execution_advisory=None,
        debug_reason="computer_target_viability_unknown",
    )


def assess_computer_target_viability(
    shell: Any,
    *,
    domain: str,
    principal_name: str,
    node: dict[str, Any] | None = None,
) -> ComputerTargetViability:
    """Assess whether one computer target looks viable for host-bound execution."""
    workspace_dir = (
        shell._get_workspace_cwd()  # type: ignore[attr-defined]
        if hasattr(shell, "_get_workspace_cwd")
        else getattr(shell, "current_workspace_dir", "")
    )
    domains_dir = getattr(shell, "domains_dir", "domains")
    props = node.get("properties") if isinstance(node, dict) else {}
    props = props if isinstance(props, dict) else {}

    requested_target = str(
        props.get("name")
        or props.get("samaccountname")
        or node.get("name") if isinstance(node, dict) else ""
    ).strip() or str(principal_name or "").strip()

    candidate_targets = _candidate_computer_targets(
        requested_target,
        props.get("name"),
        props.get("samaccountname"),
        props.get("dnshostname"),
        node.get("label") if isinstance(node, dict) else "",
        principal_name,
    )

    enabled_in_inventory: bool | None
    enabled_inventory_source = "enabled_computers"
    try:
        enabled_samaccounts = load_enabled_computer_samaccounts(
            workspace_dir,
            domains_dir,
            domain,
        )
        enabled_stems = {
            _computer_stem(item)
            for item in enabled_samaccounts
            if _computer_stem(item)
        }
        target_stems = {
            _computer_stem(item) for item in candidate_targets if _computer_stem(item)
        }
        enabled_in_inventory = bool(target_stems.intersection(enabled_stems))
    except OSError:
        enabled_in_inventory = None
        enabled_inventory_source = "enabled_computers_unavailable"

    resolution = resolve_targets_from_current_vantage(
        workspace_dir,
        domains_dir,
        domain,
        targets=candidate_targets,
    )
    if enabled_in_inventory is False:
        matched_host_stems = {
            _computer_stem(hostname)
            for assessment in resolution.assessments
            for hostname in assessment.matched_hostnames
            if _computer_stem(hostname)
        }
        if matched_host_stems and matched_host_stems.intersection(enabled_stems):
            enabled_in_inventory = True

    return _summarize_computer_viability(
        requested_target=requested_target or str(principal_name or "").strip(),
        enabled_in_inventory=enabled_in_inventory,
        enabled_inventory_source=enabled_inventory_source,
        resolution=resolution,
    )
