"""Offer and execute relaunch of previously established pivots.

The relaunch path must work even when the Ligolo proxy/API is no longer alive,
so this service relies on persisted tunnel records plus workspace credentials
instead of runtime-only state.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rich.prompt import Confirm

from adscan_internal import print_info, print_info_debug, print_instruction, print_warning
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.current_vantage_reachability_service import (
    resolve_targets_from_current_vantage,
)
from adscan_internal.services.ligolo_service import LigoloProxyService
from adscan_internal.services.pivot_capability_registry import (
    get_pivot_service_capability,
)


@dataclass(frozen=True, slots=True)
class PivotRelaunchCandidate:
    """One persisted pivot that may be relaunched."""

    tunnel_id: str
    domain: str
    pivot_host: str
    pivot_username: str
    source_service: str
    pivot_method: str
    pivot_tool: str
    routes: tuple[str, ...]
    credential_available: bool
    service_reachable: bool


@dataclass(frozen=True, slots=True)
class PivotRelaunchAssessment:
    """Human-readable relaunch assessment for one persisted tunnel record."""

    tunnel_id: str
    relaunchable: bool
    status_label: str
    reason: str


def _workspace_dir(shell: Any) -> str:
    """Return the current workspace root."""

    return str(getattr(shell, "current_workspace_dir", "") or "").strip()


def _load_tunnel_records(shell: Any) -> list[dict[str, Any]]:
    """Return persisted Ligolo tunnel records without requiring a live API."""

    service = LigoloProxyService(
        workspace_dir=_workspace_dir(shell),
        current_domain=getattr(shell, "current_domain", None),
    )
    return service.load_tunnels_state()


def _resolve_credential(shell: Any, *, domain: str, username: str) -> str | None:
    """Return the current reusable credential for one user if still present."""

    domains_data = getattr(shell, "domains_data", {})
    domain_data = domains_data.get(domain, {}) if isinstance(domains_data, dict) else {}
    credentials = domain_data.get("credentials", {}) if isinstance(domain_data, dict) else {}
    if not isinstance(credentials, dict):
        return None
    secret = str(credentials.get(username) or "").strip()
    if not secret:
        return None
    if getattr(shell, "is_hash", lambda _: False)(secret):
        return None
    return secret


def _is_service_reachable_from_current_vantage(
    shell: Any,
    *,
    domain: str,
    host: str,
    service_name: str,
) -> bool:
    """Return whether the pivot host is reachable on the service's required ports."""

    capability = get_pivot_service_capability(service_name)
    required_ports = capability.required_ports if capability else ()
    resolution = resolve_targets_from_current_vantage(
        _workspace_dir(shell),
        getattr(shell, "domains_dir", "domains"),
        domain,
        targets=[host],
        required_ports=required_ports,
    )
    return bool(resolution.reachable_targets)


def list_relaunch_candidates(
    shell: Any,
    *,
    domain_filter: str | None = None,
) -> list[PivotRelaunchCandidate]:
    """Return persisted pivots that ADscan may be able to relaunch."""

    normalized_filter = str(domain_filter or "").strip().lower() or None
    candidates: list[PivotRelaunchCandidate] = []
    for record in _load_tunnel_records(shell):
        domain = str(record.get("domain") or "").strip()
        if not domain:
            continue
        if normalized_filter and domain.lower() != normalized_filter:
            continue
        pivot_host = str(record.get("pivot_host") or "").strip()
        pivot_username = str(record.get("pivot_username") or "").strip()
        source_service = str(record.get("source_service") or "winrm").strip().lower()
        capability = get_pivot_service_capability(source_service)
        if capability is None or not capability.followup_handler_name:
            continue
        credential = _resolve_credential(
            shell,
            domain=domain,
            username=pivot_username,
        )
        candidates.append(
            PivotRelaunchCandidate(
                tunnel_id=str(record.get("tunnel_id") or "").strip() or "unknown",
                domain=domain,
                pivot_host=pivot_host,
                pivot_username=pivot_username,
                source_service=source_service,
                pivot_method=str(record.get("pivot_method") or "ligolo_winrm_pivot").strip(),
                pivot_tool=str(record.get("pivot_tool") or "Ligolo").strip(),
                routes=tuple(str(route) for route in (record.get("routes") or []) if str(route).strip()),
                credential_available=credential is not None,
                service_reachable=_is_service_reachable_from_current_vantage(
                    shell,
                    domain=domain,
                    host=pivot_host,
                    service_name=source_service,
                ),
            )
        )
    return sorted(
        candidates,
        key=lambda item: (item.domain.lower(), item.pivot_host.lower(), item.pivot_username.lower()),
    )


def assess_persisted_tunnel_relaunchability(
    shell: Any,
    *,
    record: dict[str, Any],
) -> PivotRelaunchAssessment:
    """Return one relaunch assessment for a persisted tunnel record."""

    tunnel_id = str(record.get("tunnel_id") or "").strip() or "unknown"
    domain = str(record.get("domain") or "").strip()
    source_service = str(record.get("source_service") or "winrm").strip().lower()
    pivot_host = str(record.get("pivot_host") or "").strip()
    pivot_username = str(record.get("pivot_username") or "").strip()
    capability = get_pivot_service_capability(source_service)
    if capability is None or not capability.followup_handler_name:
        return PivotRelaunchAssessment(
            tunnel_id=tunnel_id,
            relaunchable=False,
            status_label="No",
            reason=f"{source_service.upper()} relaunch not supported yet",
        )
    credential = _resolve_credential(shell, domain=domain, username=pivot_username)
    if not credential:
        return PivotRelaunchAssessment(
            tunnel_id=tunnel_id,
            relaunchable=False,
            status_label="No",
            reason="No cleartext credential stored",
        )
    if not _is_service_reachable_from_current_vantage(
        shell,
        domain=domain,
        host=pivot_host,
        service_name=source_service,
    ):
        return PivotRelaunchAssessment(
            tunnel_id=tunnel_id,
            relaunchable=False,
            status_label="Blocked",
            reason=f"{source_service.upper()} not reachable from current vantage",
        )
    return PivotRelaunchAssessment(
        tunnel_id=tunnel_id,
        relaunchable=True,
        status_label="Yes",
        reason=f"Ready via {source_service.upper()}",
    )


def relaunch_persisted_pivot(
    shell: Any,
    *,
    candidate: PivotRelaunchCandidate,
) -> bool:
    """Open the service workflow that can recreate one previous pivot."""

    capability = get_pivot_service_capability(candidate.source_service)
    if capability is None or not capability.followup_handler_name:
        print_warning(
            f"ADscan does not have a relaunch workflow for {mark_sensitive(candidate.source_service, 'detail')} pivots yet."
        )
        return False
    credential = _resolve_credential(
        shell,
        domain=candidate.domain,
        username=candidate.pivot_username,
    )
    if not credential:
        print_warning(
            f"Cannot relaunch the previous pivot via {mark_sensitive(candidate.source_service.upper(), 'detail')} "
            f"because no cleartext credential is stored for {mark_sensitive(candidate.pivot_username, 'user')}."
        )
        return False
    if not candidate.service_reachable:
        print_warning(
            f"Cannot relaunch the previous pivot because the pivot host "
            f"{mark_sensitive(candidate.pivot_host, 'hostname')} is not currently reachable on "
            f"{mark_sensitive(candidate.source_service.upper(), 'detail')}."
        )
        return False

    handler = getattr(shell, capability.followup_handler_name, None)
    if not callable(handler):
        print_warning(
            f"Missing relaunch handler {mark_sensitive(capability.followup_handler_name, 'detail')} "
            f"for {mark_sensitive(candidate.source_service.upper(), 'detail')}."
        )
        return False

    route_count = len(candidate.routes)
    print_info(
        f"Re-launching the previous {mark_sensitive(candidate.pivot_tool, 'detail')} pivot via "
        f"{mark_sensitive(candidate.source_service.upper(), 'detail')} on "
        f"{mark_sensitive(candidate.pivot_host, 'hostname')} "
        f"as {mark_sensitive(candidate.pivot_username, 'user')} "
        f"({route_count} persisted route(s))."
    )
    workflow_intent = capability.relaunch_workflow_intent or capability.followup_workflow_intent
    if workflow_intent:
        handler(
            candidate.domain,
            candidate.pivot_host,
            candidate.pivot_username,
            credential,
            workflow_intent=workflow_intent,
        )
    else:
        handler(
            candidate.domain,
            candidate.pivot_host,
            candidate.pivot_username,
            credential,
        )
    return True


def maybe_offer_previous_pivot_relaunch(
    shell: Any,
    *,
    domain: str,
    interactive: bool,
    trigger: str,
) -> bool:
    """Offer relaunch of one previous pivot for a domain.

    When ``interactive`` is false, this emits a premium diagnostic/instruction
    without prompting from background threads.
    """

    candidates = [
        item for item in list_relaunch_candidates(shell, domain_filter=domain)
        if item.credential_available
    ]
    if not candidates:
        return False
    candidate = candidates[0]
    marked_domain = mark_sensitive(domain, "domain")
    marked_host = mark_sensitive(candidate.pivot_host, "hostname")
    marked_user = mark_sensitive(candidate.pivot_username, "user")
    marked_service = mark_sensitive(candidate.source_service.upper(), "detail")

    if not interactive:
        print_info(
            f"A previous pivot for {marked_domain} can likely be relaunched via "
            f"{marked_service} on {marked_host} as {marked_user}."
        )
        print_instruction(
            "Run `ligolo tunnel relaunch "
            f"{mark_sensitive(candidate.tunnel_id, 'text')}` to reopen the previous pivot workflow."
        )
        print_info_debug(
            "[pivot-relaunch] non-interactive relaunch hint emitted: "
            f"domain={marked_domain} trigger={mark_sensitive(trigger, 'detail')} "
            f"tunnel_id={mark_sensitive(candidate.tunnel_id, 'text')}"
        )
        return True

    confirmer = getattr(shell, "_questionary_confirm", None)
    prompt = (
        f"A previous {mark_sensitive(candidate.pivot_tool, 'detail')} pivot for "
        f"{marked_domain} is no longer active. Reopen the {marked_service} pivoting workflow on "
        f"{marked_host} as {marked_user} to relaunch it now? "
        "[dim](This will run the pivoting branch only, not the full service-enumeration workflow.)[/dim]"
    )
    should_relaunch = (
        bool(confirmer(prompt, default=False))
        if callable(confirmer)
        else bool(Confirm.ask(prompt, default=False))
    )
    if not should_relaunch:
        print_info("Skipping previous pivot relaunch by user choice.")
        return False
    return relaunch_persisted_pivot(shell, candidate=candidate)


__all__ = [
    "PivotRelaunchAssessment",
    "PivotRelaunchCandidate",
    "assess_persisted_tunnel_relaunchability",
    "list_relaunch_candidates",
    "maybe_offer_previous_pivot_relaunch",
    "relaunch_persisted_pivot",
]
