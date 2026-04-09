"""Diagnose and offer pivot opportunities when host-bound execution is blocked."""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Any

from adscan_internal import print_info, print_info_debug, print_warning, telemetry
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.attack_path_target_viability_service import (
    ComputerTargetViability,
    assess_computer_target_viability,
)
from adscan_internal.services.attack_graph_service import (
    get_owned_domain_usernames_for_attack_paths,
)
from adscan_internal.services.ligolo_service import LigoloProxyService
from adscan_internal.services.pivot_capability_registry import (
    get_pivot_service_capability,
    list_pivot_service_capabilities,
)
from adscan_internal.services.service_access_probe_history import (
    load_service_access_probe_history,
)
from adscan_internal.workspaces.computers import (
    load_target_entries,
    resolve_domain_service_target_file,
)

UNREACHABLE_HOST_VIABILITY_STATUSES = frozenset(
    {
        "resolved_but_unreachable",
        "enabled_but_unresolved",
        "not_in_enabled_inventory",
    }
)


@dataclass(frozen=True, slots=True)
class PivotProbeCandidate:
    """One user/service/host candidate that may unlock a pivot."""

    username: str
    credential: str
    service: str
    host: str
    status: str  # confirmed | pending | unconfirmed
    checked_at: str | None = None


@dataclass(frozen=True, slots=True)
class PivotOpportunityAssessment:
    """Structured view of pivot opportunities for one blocked host-bound action."""

    blocked_target: str
    active_pivot_hosts: tuple[str, ...]
    confirmed_candidates: tuple[PivotProbeCandidate, ...]
    pending_candidates: tuple[PivotProbeCandidate, ...]
    unconfirmed_candidates: tuple[PivotProbeCandidate, ...]

    @property
    def has_confirmed_candidate(self) -> bool:
        return bool(self.confirmed_candidates)

    @property
    def has_pending_candidate(self) -> bool:
        return bool(self.pending_candidates)


def maybe_offer_pivot_opportunity_for_host_viability(
    shell: Any,
    *,
    domain: str,
    blocked_target: str,
    viability_status: str,
    operator_summary: str | None = None,
) -> bool:
    """Offer pivot diagnostics when a host is blocked by current-vantage viability.

    Returns ``True`` when the viability status maps to an unreachable-host class
    and the pivot-opportunity follow-up was evaluated.
    """
    normalized_status = str(viability_status or "").strip().lower()
    if normalized_status not in UNREACHABLE_HOST_VIABILITY_STATUSES:
        return False
    summary = str(operator_summary or "").strip()
    if summary:
        print_info(summary)
    maybe_offer_pivot_opportunity_followup(
        shell,
        domain=domain,
        blocked_target=blocked_target,
    )
    return True


def ensure_host_bound_workflow_target_viable(
    shell: Any,
    *,
    domain: str,
    target_host: str,
    workflow_label: str,
) -> ComputerTargetViability | None:
    """Return target viability for one host-bound workflow or block with pivot UX.

    This helper centralizes the operator-facing precheck for workflows that need
    direct access to a computer target from the current vantage. When the host
    is blocked by reachability or stale-inventory signals, ADscan shows the
    common pivot-opportunity UX instead of each workflow reimplementing its own
    warnings.
    """
    viability = assess_computer_target_viability(
        shell,
        domain=domain,
        principal_name=target_host,
    )
    if viability.status not in UNREACHABLE_HOST_VIABILITY_STATUSES:
        return viability

    marked_workflow = mark_sensitive(workflow_label, "detail")
    marked_target = mark_sensitive(target_host, "hostname")
    print_warning(
        f"{marked_workflow} is blocked because ADscan cannot currently reach "
        f"{marked_target} from the active vantage."
    )
    maybe_offer_pivot_opportunity_for_host_viability(
        shell,
        domain=domain,
        blocked_target=target_host,
        viability_status=viability.status,
        operator_summary=viability.operator_summary,
    )
    return None


def _workspace_dir(shell: Any) -> str:
    """Return the current workspace root."""

    return (
        shell._get_workspace_cwd()  # type: ignore[attr-defined]
        if hasattr(shell, "_get_workspace_cwd")
        else getattr(shell, "current_workspace_dir", os.getcwd())
    )


def _domains_dir(shell: Any) -> str:
    """Return the workspace domains directory."""

    return str(getattr(shell, "domains_dir", "domains"))


def _normalize_account(value: str) -> str:
    """Normalize user labels to one SAM-like lowercase value."""

    text = str(value or "").strip()
    if "\\" in text:
        text = text.split("\\", 1)[1]
    if "@" in text:
        text = text.split("@", 1)[0]
    return text.strip().lower()


def _load_active_pivot_hosts(shell: Any) -> set[str]:
    """Return host identifiers already serving an active Ligolo pivot."""

    try:
        service = LigoloProxyService(
            workspace_dir=_workspace_dir(shell),
            current_domain=getattr(shell, "current_domain", None),
        )
        records = service.list_tunnel_records()
    except Exception as exc:  # pragma: no cover - best effort only
        telemetry.capture_exception(exc)
        print_info_debug(f"[pivot-opportunity] failed to load Ligolo tunnel state: {exc}")
        return set()
    active_hosts: set[str] = set()
    for record in records:
        status = str(record.get("status") or "").strip().lower()
        if status not in {"running", "connected"}:
            continue
        pivot_host = str(record.get("pivot_host") or "").strip()
        if pivot_host:
            active_hosts.add(pivot_host.lower())
    return active_hosts


def _owned_cleartext_credentials(shell: Any, *, domain: str) -> list[tuple[str, str]]:
    """Return owned users that have reusable cleartext credentials."""

    owned_users = get_owned_domain_usernames_for_attack_paths(shell, domain)
    credentials = getattr(shell, "domains_data", {}).get(domain, {}).get("credentials", {})
    results: list[tuple[str, str]] = []
    if not isinstance(credentials, dict):
        return results
    for owned_user in owned_users:
        normalized_owned = _normalize_account(owned_user)
        if not normalized_owned:
            continue
        for stored_user, stored_credential in credentials.items():
            if _normalize_account(str(stored_user)) != normalized_owned:
                continue
            credential = str(stored_credential or "").strip()
            if not credential or getattr(shell, "is_hash", lambda _: False)(credential):
                break
            results.append((str(stored_user), credential))
            break
    return results


def assess_pivot_opportunities(
    shell: Any,
    *,
    domain: str,
    blocked_target: str,
) -> PivotOpportunityAssessment:
    """Return pivot-capable access that could help with one blocked host-bound action."""

    workspace_dir = _workspace_dir(shell)
    domains_dir = _domains_dir(shell)
    active_pivot_hosts = _load_active_pivot_hosts(shell)
    history = load_service_access_probe_history(
        workspace_dir=workspace_dir,
        domains_dir=domains_dir,
        domain=domain,
    )
    history_by_key = {
        (
            _normalize_account(str(record.get("username") or "")),
            str(record.get("service") or "").strip().lower(),
            str(record.get("host") or "").strip().lower(),
        ): record
        for record in history
        if isinstance(record, dict)
    }

    confirmed: list[PivotProbeCandidate] = []
    pending: list[PivotProbeCandidate] = []
    unconfirmed: list[PivotProbeCandidate] = []
    for capability in list_pivot_service_capabilities():
        target_file, source = resolve_domain_service_target_file(
            workspace_dir,
            domains_dir,
            domain,
            service=capability.service,
            domain_data=getattr(shell, "domains_data", {}).get(domain, {}),
            scope_preference="optimized",
        )
        if not target_file:
            continue
        targets = sorted(load_target_entries(target_file))
        if not targets:
            continue
        for username, credential in _owned_cleartext_credentials(shell, domain=domain):
            normalized_user = _normalize_account(username)
            for host in targets:
                normalized_host = str(host or "").strip().lower()
                if not normalized_host or normalized_host in active_pivot_hosts:
                    continue
                probe = PivotProbeCandidate(
                    username=username,
                    credential=credential,
                    service=capability.service,
                    host=host,
                    status="pending",
                )
                history_record = history_by_key.get(
                    (normalized_user, capability.service, normalized_host)
                )
                if not history_record:
                    pending.append(probe)
                    continue
                result = str(history_record.get("result") or "").strip().lower()
                checked_at = str(history_record.get("checked_at") or "").strip() or None
                probe = PivotProbeCandidate(
                    username=username,
                    credential=credential,
                    service=capability.service,
                    host=host,
                    status=result or "unconfirmed",
                    checked_at=checked_at,
                )
                if result == "confirmed":
                    confirmed.append(probe)
                else:
                    unconfirmed.append(probe)
        print_info_debug(
            "[pivot-opportunity] target scope: "
            f"domain={mark_sensitive(domain, 'domain')} "
            f"service={capability.service} source={mark_sensitive(source, 'detail')} "
            f"targets={len(targets)}"
        )

    return PivotOpportunityAssessment(
        blocked_target=blocked_target,
        active_pivot_hosts=tuple(sorted(active_pivot_hosts)),
        confirmed_candidates=tuple(
            sorted(confirmed, key=lambda item: (item.service, item.host.lower(), item.username.lower()))
        ),
        pending_candidates=tuple(
            sorted(pending, key=lambda item: (item.service, item.host.lower(), item.username.lower()))
        ),
        unconfirmed_candidates=tuple(
            sorted(unconfirmed, key=lambda item: (item.service, item.host.lower(), item.username.lower()))
        ),
    )


def maybe_offer_pivot_opportunity_followup(
    shell: Any,
    *,
    domain: str,
    blocked_target: str,
) -> None:
    """Offer pivot-capable access probes or follow-ups for one blocked target host."""

    assessment = assess_pivot_opportunities(shell, domain=domain, blocked_target=blocked_target)
    if assessment.active_pivot_hosts:
        print_info(
            "A pivot is already active in this workspace. Reuse or extend the current pivot before "
            "retesting this host-bound action."
        )
        return

    if assessment.has_confirmed_candidate:
        candidates = list(assessment.confirmed_candidates)
        options = [
            f"{item.username} -> {item.service.upper()} -> {item.host}"
            for item in candidates
        ]
        selected_options = (
            shell._questionary_checkbox(  # type: ignore[attr-defined]
                "Confirmed pivot-capable access exists. Select targets to open for pivot follow-up:",
                options,
                default_values=options,
            )
            if hasattr(shell, "_questionary_checkbox")
            else options
        )
        if selected_options is None:
            print_info("Skipping pivot-capable follow-up by user choice.")
            return
        selected = {
            str(option).strip()
            for option in selected_options
            if str(option).strip()
        }
        for item, label in zip(candidates, options, strict=False):
            if label not in selected:
                continue
            handler = getattr(shell, f"ask_for_{item.service}_access", None)
            if callable(handler):
                capability = get_pivot_service_capability(item.service)
                print_warning(
                    f"Host-bound execution to {mark_sensitive(blocked_target, 'hostname')} is blocked. "
                    f"Opening the {item.service.upper()} pivoting workflow on "
                    f"{mark_sensitive(item.host, 'hostname')} to pursue pivoting. "
                    "[This will run the pivoting branch only, not the full service-enumeration workflow.]"
                )
                if capability and capability.followup_workflow_intent:
                    handler(
                        domain,
                        item.host,
                        item.username,
                        item.credential,
                        workflow_intent=capability.followup_workflow_intent,
                    )
                else:
                    handler(domain, item.host, item.username, item.credential)
        return

    if assessment.has_pending_candidate:
        candidates = list(assessment.pending_candidates)
        options = [
            f"{item.username} -> {item.service.upper()} -> {item.host}"
            for item in candidates
        ]
        selected_options = (
            shell._questionary_checkbox(  # type: ignore[attr-defined]
                (
                    "This host-bound action is blocked by current-vantage reachability. "
                    "Select pending pivot-capable access probes to test now:"
                ),
                options,
                default_values=options,
            )
            if hasattr(shell, "_questionary_checkbox")
            else options
        )
        if selected_options is None:
            print_info("Skipping pending pivot-capable access probes by user choice.")
            return
        selected = {
            str(option).strip()
            for option in selected_options
            if str(option).strip()
        }
        from adscan_internal.cli.privileges import run_service_access_sweep

        for item, label in zip(candidates, options, strict=False):
            if label not in selected:
                continue
            print_info(
                f"Checking {mark_sensitive(item.service.upper(), 'detail')} access for "
                f"{mark_sensitive(item.username, 'user')} on {mark_sensitive(item.host, 'hostname')} "
                "to look for a pivot-capable route."
            )
            run_service_access_sweep(
                shell,
                domain=domain,
                username=item.username,
                password=item.credential,
                services=[item.service],
                hosts=[item.host],
                prompt=True,
                scope_preference="optimized",
                include_previously_tested=False,
            )
        return

    if assessment.unconfirmed_candidates:
        confirmer = getattr(shell, "_questionary_confirm", None)
        rerun = (
            bool(
                confirmer(
                    "Previously tested pivot-capable access paths exist but none are confirmed. Re-check them now?",
                    default=False,
                )
            )
            if callable(confirmer)
            else False
        )
        if not rerun:
            print_info(
                "No new pivot-capable access probes remain. Previously tested candidates can be re-checked later if needed."
            )
            return
        candidates = list(assessment.unconfirmed_candidates)
        from adscan_internal.cli.privileges import run_service_access_sweep

        for item in candidates:
            run_service_access_sweep(
                shell,
                domain=domain,
                username=item.username,
                password=item.credential,
                services=[item.service],
                hosts=[item.host],
                prompt=True,
                scope_preference="optimized",
                include_previously_tested=True,
            )
        return

    print_info(
        "No pivot-capable access paths are known or pending for the currently owned users."
    )
