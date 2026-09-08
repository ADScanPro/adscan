"""Diagnose and offer pivot opportunities when host-bound execution is blocked."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from rich.box import ROUNDED
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from adscan_core.rich_output import get_console
from adscan_core.theme import ADSCAN_PRIMARY, ADSCAN_PRIMARY_DIM
from adscan_internal import print_info, print_info_debug, print_warning, telemetry
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.attack_path_target_viability_service import (
    ComputerTargetViability,
    assess_computer_target_viability,
)
from adscan_internal.services.attack_graph_service import (
    get_graph_service_access_pairs,
    get_owned_domain_usernames_for_attack_paths,
)
from adscan_internal.services.async_bridge import run_async_sync
from adscan_internal.services.ligolo_service import LigoloProxyService
from adscan_internal.services.network_probe_service import (
    SERVICE_PROBE_PORTS,
    TCPProbeResult,
    tcp_probe_multi,
)
from adscan_internal.services.pivot_capability_registry import (
    get_pivot_service_capability,
    list_pivot_service_capabilities,
)
from adscan_internal.services.service_access_probe_history import (
    load_service_access_probe_history,
)
from adscan_internal.workspaces import domain_subpath, resolve_workspace_cwd
from adscan_internal.workspaces.computers import (
    load_target_entries,
    resolve_domain_service_target_file,
)
from adscan_core.rich_output import print_exception


# Graph-affinity tiers for ``PivotProbeCandidate.graph_affinity``.
#
# ``direct``: the attack graph holds an explicit ``user -> relation -> host``
#   edge for this candidate (e.g. ``L.WILSON_ADM --CanPSRemote--> DC01$``).
#   These candidates are the ones the operator almost certainly wants to test
#   first — the graph already proved they should work.
# ``none``: no graph evidence ties the user to the host for this service.
#   ADscan still surfaces these as a fallback when nothing graph-confirmed is
#   available, but they are deprioritized in the UX.
GRAPH_AFFINITY_DIRECT = "direct"
GRAPH_AFFINITY_NONE = "none"

UNREACHABLE_HOST_VIABILITY_STATUSES = frozenset(
    {
        "resolved_but_unreachable",
        "enabled_but_unresolved",
        "not_in_enabled_inventory",
        "service_port_filtered",
        "service_probe_unavailable",
    }
)

LIVE_SERVICE_UNREACHABLE_STATUSES = frozenset(
    {
        "service_port_closed",
        "service_port_filtered",
        "service_probe_unavailable",
    }
)

# Substring that identifies the "no Ligolo proxy configured" RuntimeError raised
# by ``LigoloProxyService._get_api_base_url`` when a pivot API call is attempted
# with no proxy running. The pivot-offer seam catches exactly this condition and
# translates it into actionable operator guidance instead of a raw traceback.
_LIGOLO_PROXY_UNAVAILABLE_MARKER = "proxy API address is not available"

# Per-session guard so the "no pivot configured" guidance is shown at most once
# per blocked target, even when several attack paths share the same unreachable
# host and the executor re-enters the pivot-offer seam for each one.
_PIVOT_UNAVAILABLE_NOTICE_SHOWN: set[tuple[str, str]] = set()


@dataclass(frozen=True, slots=True)
class PivotProbeCandidate:
    """One user/service/host candidate that may unlock a pivot."""

    username: str
    credential: str
    service: str
    host: str
    status: str  # confirmed | pending | unconfirmed
    checked_at: str | None = None
    # Affinity from the attack graph: ``direct`` when an explicit edge proves
    # this user holds the service relation against this host, ``none`` when
    # there is no graph evidence (the candidate exists only because the user
    # is owned and the host runs the service). See module docstring.
    graph_affinity: str = GRAPH_AFFINITY_NONE
    # Computer label as it appears in the attack graph (e.g. ``DC01$``) when
    # the host IP could be resolved to an inventoried computer. Surfaced in
    # the UX so the operator sees ``CanPSRemote -> DC01$`` rather than only
    # the IP.
    computer_label: str | None = None


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


def _build_live_service_viability(
    *,
    target_host: str,
    service: str,
    probe: TCPProbeResult | None,
    status: str,
    summary: str,
    debug_reason: str,
) -> ComputerTargetViability:
    """Build a viability result from a direct single-host service probe."""

    matched_ips = (target_host,) if target_host else ()
    open_ports: tuple[int, ...] = (
        (int(probe.port),)
        if probe is not None and probe.status == "open" and probe.port
        else ()
    )
    return ComputerTargetViability(
        requested_target=target_host,
        status=status,
        enabled_in_inventory=None,
        enabled_inventory_source="not_checked_for_single_host_live_probe",
        resolved_in_current_vantage_inventory=None,
        reachable_from_current_vantage=probe is not None and probe.status == "open",
        matched_ips=matched_ips,
        matched_hostnames=(target_host,) if target_host else (),
        vantage_mode="live_service_probe",
        operator_summary=summary,
        execution_advisory=None
        if open_ports
        else "Verify service exposure or establish a pivot before retrying.",
        debug_reason=f"{debug_reason}: service={service} open_ports={open_ports}",
    )


def assess_single_host_service_reachability(
    *,
    target_host: str,
    service: str,
    timeout: float = 3.0,
) -> ComputerTargetViability:
    """Assess one host-bound workflow with a live service-specific TCP probe.

    This is intentionally separate from current-vantage inventory resolution:
    for a single host, probing the service now is cheaper and more authoritative
    than trusting a persisted reachability snapshot.
    """

    normalized_service = str(service or "").strip().lower()
    ports = SERVICE_PROBE_PORTS.get(normalized_service, [])
    if not ports:
        return _build_live_service_viability(
            target_host=target_host,
            service=normalized_service or "unknown",
            probe=None,
            status="service_probe_unavailable",
            summary="No live service probe is configured for this workflow.",
            debug_reason="single_host_service_probe_unavailable",
        )

    probe = run_async_sync(tcp_probe_multi(target_host, ports, timeout=timeout))
    if probe.status == "open":
        return _build_live_service_viability(
            target_host=target_host,
            service=normalized_service,
            probe=probe,
            status="reachable_by_live_service_probe",
            summary=(
                f"Reachable by live {normalized_service.upper()} probe "
                f"on port {probe.port}/tcp."
            ),
            debug_reason="single_host_service_probe_open",
        )
    if probe.status == "closed":
        return _build_live_service_viability(
            target_host=target_host,
            service=normalized_service,
            probe=probe,
            status="service_port_closed",
            summary=(
                f"Live {normalized_service.upper()} probe reached the host, "
                f"but port {probe.port}/tcp is closed."
            ),
            debug_reason="single_host_service_probe_closed",
        )
    return _build_live_service_viability(
        target_host=target_host,
        service=normalized_service,
        probe=probe,
        status="service_port_filtered",
        summary=(
            f"Live {normalized_service.upper()} probe could not reach "
            f"port {probe.port}/tcp from the active vantage."
        ),
        debug_reason="single_host_service_probe_filtered",
    )


def maybe_offer_pivot_opportunity_for_host_viability(
    shell: Any,
    *,
    domain: str,
    blocked_target: str,
    viability_status: str,
    operator_summary: str | None = None,
    workflow_intent_override: str | None = None,
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
    try:
        maybe_offer_pivot_opportunity_followup(
            shell,
            domain=domain,
            blocked_target=blocked_target,
            workflow_intent_override=workflow_intent_override,
        )
    except RuntimeError as exc:
        if _LIGOLO_PROXY_UNAVAILABLE_MARKER not in str(exc):
            raise
        _notify_no_pivot_proxy_configured(
            domain=domain, blocked_target=blocked_target
        )
    return True


def _notify_no_pivot_proxy_configured(*, domain: str, blocked_target: str) -> None:
    """Emit actionable guidance, once per target, when no pivot proxy exists.

    Pursuing a pivot for an unreachable host reaches into the Ligolo-ng proxy
    API. When no proxy is running that call raises a ``RuntimeError`` the
    executor would otherwise surface as a bare error line (repeated once per
    attack path sharing the target). This replaces it with a single clear,
    operator-facing next step.
    """

    notice_key = (str(domain or "").strip().lower(), str(blocked_target or "").strip().lower())
    if notice_key in _PIVOT_UNAVAILABLE_NOTICE_SHOWN:
        print_info_debug(
            "pivot-opportunity: suppressing repeated no-pivot notice: "
            f"target={mark_sensitive(blocked_target, 'hostname')}"
        )
        return
    _PIVOT_UNAVAILABLE_NOTICE_SHOWN.add(notice_key)
    marked_target = mark_sensitive(blocked_target or "the target host", "hostname")
    print_warning(
        f"No Ligolo pivot is configured for this workspace, and {marked_target} is not "
        "reachable from your current vantage. To pursue this path, start a pivot with "
        "'ligolo proxy start', deploy an agent on a reachable host, then retry this step."
    )


def ensure_host_bound_workflow_target_viable(
    shell: Any,
    *,
    domain: str,
    target_host: str,
    workflow_label: str,
    service: str | None = None,
    resume_after_pivot: bool = False,
) -> ComputerTargetViability | None:
    """Return target viability for one host-bound workflow or block with pivot UX.

    This helper centralizes the operator-facing precheck for workflows that need
    direct access to a computer target from the current vantage. When the host
    is blocked by reachability or stale-inventory signals, ADscan shows the
    common pivot-opportunity UX instead of each workflow reimplementing its own
    warnings.
    """
    using_live_service_probe = bool(service)
    if service:
        viability = assess_single_host_service_reachability(
            target_host=target_host,
            service=service,
        )
        print_info_debug(
            "[host_viability] single-host live service probe: "
            f"workflow={mark_sensitive(workflow_label, 'detail')} "
            f"target={mark_sensitive(target_host, 'hostname')} "
            f"service={mark_sensitive(service, 'detail')} "
            f"status={mark_sensitive(viability.status, 'detail')} "
            f"reason={mark_sensitive(viability.debug_reason, 'detail')}"
        )
        if viability.status not in LIVE_SERVICE_UNREACHABLE_STATUSES:
            return viability
    else:
        viability = assess_computer_target_viability(
            shell,
            domain=domain,
            principal_name=target_host,
        )
        if viability.status not in UNREACHABLE_HOST_VIABILITY_STATUSES:
            return viability

    if (
        viability.status
        not in UNREACHABLE_HOST_VIABILITY_STATUSES | LIVE_SERVICE_UNREACHABLE_STATUSES
    ):
        return viability

    marked_workflow = mark_sensitive(workflow_label, "detail")
    marked_target = mark_sensitive(target_host, "hostname")
    print_warning(
        f"{marked_workflow} is blocked because ADscan cannot currently reach "
        f"{marked_target} from the active vantage."
    )
    if resume_after_pivot:
        print_info(
            "ADscan will use pivoting only to restore reachability for this host-bound workflow, "
            "then return to the blocked action."
        )
    maybe_offer_pivot_opportunity_for_host_viability(
        shell,
        domain=domain,
        blocked_target=target_host,
        viability_status=viability.status,
        operator_summary=viability.operator_summary,
        workflow_intent_override="pivot_host_bound_resume"
        if resume_after_pivot
        else None,
    )
    if not resume_after_pivot:
        return None

    if using_live_service_probe and service:
        refreshed_viability = assess_single_host_service_reachability(
            target_host=target_host,
            service=service,
        )
        refreshed_unreachable_statuses = LIVE_SERVICE_UNREACHABLE_STATUSES
    else:
        refreshed_viability = assess_computer_target_viability(
            shell,
            domain=domain,
            principal_name=target_host,
        )
        refreshed_unreachable_statuses = UNREACHABLE_HOST_VIABILITY_STATUSES
    if refreshed_viability.status not in refreshed_unreachable_statuses:
        print_info(
            f"{mark_sensitive(workflow_label, 'detail')} can continue: "
            f"{mark_sensitive(target_host, 'hostname')} is now reachable from the active vantage."
        )
        return refreshed_viability
    return None


def _workspace_dir(shell: Any) -> str:
    """Return the current workspace root."""

    return resolve_workspace_cwd(shell)


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
        print_exception(exception=exc)
        print_info_debug(
            f"[pivot-opportunity] failed to load Ligolo tunnel state: {exc}"
        )
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
    credentials = (
        getattr(shell, "domains_data", {}).get(domain, {}).get("credentials", {})
    )
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


def _normalize_computer_stem(value: object) -> str:
    """Return a SAM-like lowercase stem for a computer identifier.

    Mirrors the normalization used by attack-graph principal labels so the
    inventory side and the graph side agree on the same key:
    ``DC01.GARFIELD.HTB`` / ``DC01$@GARFIELD.HTB`` / ``dc01`` all collapse
    to ``dc01``.
    """

    token = str(value or "").strip()
    if "\\" in token:
        token = token.split("\\", 1)[1]
    if "@" in token:
        token = token.split("@", 1)[0]
    token = token.strip().rstrip(".")
    if token.endswith("$"):
        token = token[:-1]
    if "." in token:
        token = token.split(".", 1)[0]
    return token.lower()


@dataclass(frozen=True, slots=True)
class _ComputerInventoryEntry:
    """Resolved inventory facts for one computer used in pivot offers."""

    stem: str
    sam: str
    label: str  # display label preserving casing (e.g. ``DC01$``)


def _load_computer_inventory_index(
    workspace_dir: str,
    domains_dir: str,
    domain: str,
) -> dict[str, _ComputerInventoryEntry]:
    """Index inventoried computers by every alias they expose.

    Returns a mapping where each key is a normalized alias (IP, hostname stem,
    DNS short name, FQDN component, samaccountname stem) and the value is the
    resolved :class:`_ComputerInventoryEntry`. The same entry may appear under
    multiple keys so callers can look up by IP *or* by hostname without
    knowing which form ``winrm/ips.txt`` (or any other target file) used.
    """

    inventory_path = Path(
        domain_subpath(workspace_dir, domains_dir, domain, "inventory", "computers.json")
    )
    try:
        if not inventory_path.exists() or inventory_path.stat().st_size == 0:
            return {}
        payload = json.loads(inventory_path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError) as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            f"[pivot-opportunity] failed to load computer inventory: {exc}"
        )
        return {}

    records = payload.get("records") if isinstance(payload, dict) else None
    if not isinstance(records, list):
        return {}

    index: dict[str, _ComputerInventoryEntry] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        properties = record.get("properties") if isinstance(record.get("properties"), dict) else {}
        sam_raw = str(record.get("samaccountname") or properties.get("samaccountname") or "").strip()
        if not sam_raw:
            continue
        stem = _normalize_computer_stem(sam_raw)
        if not stem:
            continue
        entry = _ComputerInventoryEntry(stem=stem, sam=sam_raw, label=sam_raw)

        aliases: set[str] = {stem}
        for raw_alias in (
            sam_raw,
            record.get("name"),
            properties.get("dnshostname"),
            properties.get("name"),
        ):
            normalized_alias = _normalize_computer_stem(raw_alias)
            if normalized_alias:
                aliases.add(normalized_alias)
        # Preserve the raw IP exactly as it appears in inventory — target
        # files store IPs verbatim and we want a string-equality match.
        ip_value = str(properties.get("ip_address") or "").strip()
        if ip_value:
            aliases.add(ip_value.lower())
        # DNS hostnames may also appear in their full FQDN form in target
        # files (rare, but cheap to support).
        dns_value = str(properties.get("dnshostname") or "").strip()
        if dns_value:
            aliases.add(dns_value.lower())

        for alias in aliases:
            index.setdefault(alias, entry)
    return index


def _resolve_inventory_entry(
    index: dict[str, _ComputerInventoryEntry],
    host: str,
) -> _ComputerInventoryEntry | None:
    """Look up one host (IP or hostname) in the inventory alias index."""

    if not index:
        return None
    raw = str(host or "").strip()
    if not raw:
        return None
    direct = index.get(raw.lower())
    if direct is not None:
        return direct
    return index.get(_normalize_computer_stem(raw))


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
    inventory_index = _load_computer_inventory_index(workspace_dir, domains_dir, domain)
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

        # Pull the (user_stem, computer_stem) pairs the attack graph already
        # knows about for this service's relation. This lets us mark
        # candidates with ``direct`` graph affinity so the offer UX can show
        # only the high-signal ones (e.g. owned users with ``CanPSRemote`` to
        # the candidate pivot host) and fall back to the full fan-out when
        # no graph evidence exists.
        graph_pairs: frozenset[tuple[str, str]] = frozenset()
        if capability.graph_relation:
            graph_pairs = get_graph_service_access_pairs(
                shell, domain, relation=capability.graph_relation
            )

        for username, credential in _owned_cleartext_credentials(shell, domain=domain):
            normalized_user = _normalize_account(username)
            for host in targets:
                normalized_host = str(host or "").strip().lower()
                if not normalized_host or normalized_host in active_pivot_hosts:
                    continue

                inventory_entry = _resolve_inventory_entry(inventory_index, host)
                computer_stem = (
                    inventory_entry.stem
                    if inventory_entry is not None
                    else _normalize_computer_stem(host)
                )
                computer_label = (
                    inventory_entry.label if inventory_entry is not None else None
                )
                graph_affinity = (
                    GRAPH_AFFINITY_DIRECT
                    if capability.graph_relation
                    and computer_stem
                    and (normalized_user, computer_stem) in graph_pairs
                    else GRAPH_AFFINITY_NONE
                )

                history_record = history_by_key.get(
                    (normalized_user, capability.service, normalized_host)
                )
                if not history_record:
                    pending.append(
                        PivotProbeCandidate(
                            username=username,
                            credential=credential,
                            service=capability.service,
                            host=host,
                            status="pending",
                            graph_affinity=graph_affinity,
                            computer_label=computer_label,
                        )
                    )
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
                    graph_affinity=graph_affinity,
                    computer_label=computer_label,
                )
                if result == "confirmed":
                    confirmed.append(probe)
                else:
                    unconfirmed.append(probe)
        print_info_debug(
            "[pivot-opportunity] target scope: "
            f"domain={mark_sensitive(domain, 'domain')} "
            f"service={capability.service} source={mark_sensitive(source, 'detail')} "
            f"targets={len(targets)} graph_relation={capability.graph_relation or 'n/a'} "
            f"graph_pairs={len(graph_pairs)}"
        )

    return PivotOpportunityAssessment(
        blocked_target=blocked_target,
        active_pivot_hosts=tuple(sorted(active_pivot_hosts)),
        confirmed_candidates=tuple(
            sorted(
                confirmed,
                key=lambda item: (
                    item.service,
                    item.host.lower(),
                    item.username.lower(),
                ),
            )
        ),
        pending_candidates=tuple(
            sorted(
                pending,
                key=lambda item: (
                    item.service,
                    item.host.lower(),
                    item.username.lower(),
                ),
            )
        ),
        unconfirmed_candidates=tuple(
            sorted(
                unconfirmed,
                key=lambda item: (
                    item.service,
                    item.host.lower(),
                    item.username.lower(),
                ),
            )
        ),
    )


def _split_by_graph_affinity(
    candidates: tuple[PivotProbeCandidate, ...] | list[PivotProbeCandidate],
) -> tuple[list[PivotProbeCandidate], list[PivotProbeCandidate]]:
    """Partition candidates into ``(graph_confirmed, fallback)`` buckets."""

    graph_confirmed: list[PivotProbeCandidate] = []
    fallback: list[PivotProbeCandidate] = []
    for item in candidates:
        if item.graph_affinity == GRAPH_AFFINITY_DIRECT:
            graph_confirmed.append(item)
        else:
            fallback.append(item)
    return graph_confirmed, fallback


def _prefer_graph_confirmed_candidates(
    candidates: tuple[PivotProbeCandidate, ...] | list[PivotProbeCandidate],
) -> tuple[list[PivotProbeCandidate], bool]:
    """Return the subset to offer plus a flag indicating graph filtering kicked in.

    When the attack graph already proves a service relation for at least one
    owned user against the candidate hosts, we surface ONLY those candidates —
    the rest are noise. When the graph holds no evidence, we fall back to the
    full set so operators are not stranded if the collector missed something.
    """

    graph_confirmed, fallback = _split_by_graph_affinity(candidates)
    if graph_confirmed:
        return graph_confirmed, True
    return fallback, False


def _render_graph_affinity_panel(
    candidates: list[PivotProbeCandidate],
    *,
    blocked_target: str,
) -> None:
    """Render a premium Rich panel summarizing graph-confirmed pivot access.

    Shown above the questionary checkbox so the operator immediately sees why
    these specific users are being offered (and why other owned users were
    filtered out): each row is a concrete attack-graph edge that proves the
    user already holds the service relation against the candidate pivot host.
    """

    if not candidates:
        return

    # Group by service so a single panel covers e.g. both WinRM and (future)
    # RDP graph evidence without one hiding the other.
    by_service: dict[str, list[PivotProbeCandidate]] = {}
    for item in candidates:
        by_service.setdefault(item.service, []).append(item)

    table = Table(
        show_header=True,
        header_style=f"bold {ADSCAN_PRIMARY}",
        box=None,
        padding=(0, 1),
        expand=False,
    )
    table.add_column("USER", style="bold")
    table.add_column("EDGE", style=ADSCAN_PRIMARY_DIM)
    table.add_column("PIVOT TARGET")
    table.add_column("HOST", style="dim")

    for service in sorted(by_service):
        capability = get_pivot_service_capability(service)
        relation = (
            capability.graph_relation if capability and capability.graph_relation else "—"
        )
        for item in sorted(
            by_service[service],
            key=lambda candidate: (
                candidate.host.lower(),
                candidate.username.lower(),
            ),
        ):
            target_label = item.computer_label or item.host
            table.add_row(
                str(item.username),
                Text(relation, style=ADSCAN_PRIMARY),
                str(target_label),
                str(item.host),
            )

    plural = "s" if len(candidates) != 1 else ""
    intro = Text.from_markup(
        f"[bold]ADscan found {len(candidates)} graph-confirmed pivot path{plural}[/] "
        "for the currently owned users.\n"
        "[dim]Pivoting through any of these unlocks a vantage capable of reaching "
        f"{blocked_target}.[/dim]"
    )

    panel = Panel(
        Group(intro, Text(""), table),
        title=f"[bold {ADSCAN_PRIMARY}]Pivot — Attack Graph Affinity[/]",
        title_align="left",
        subtitle=Text.from_markup(
            f"[dim]Filtered out owned users with no {','.join(sorted(by_service.keys())).upper()} "
            "edge in the attack graph.[/dim]"
        ),
        subtitle_align="left",
        border_style=ADSCAN_PRIMARY,
        box=ROUNDED,
        padding=(1, 2),
    )
    get_console().print(panel)
    # Shadow the panel content into the adscan log file so post-mortem
    # analysis (and headless/non-TTY runs) preserve which graph-confirmed
    # paths the operator was offered. Rich-rendered panels do not flow
    # through the logging pipeline on their own.
    for item in candidates:
        capability = get_pivot_service_capability(item.service)
        relation = capability.graph_relation if capability else "?"
        print_info_debug(
            "[pivot-opportunity] graph-confirmed candidate: "
            f"user={mark_sensitive(item.username, 'user')} "
            f"service={item.service} relation={relation} "
            f"target={mark_sensitive(item.computer_label or item.host, 'hostname')} "
            f"host={mark_sensitive(item.host, 'hostname')}"
        )


def maybe_offer_pivot_opportunity_followup(
    shell: Any,
    *,
    domain: str,
    blocked_target: str,
    workflow_intent_override: str | None = None,
) -> None:
    """Offer pivot-capable access probes or follow-ups for one blocked target host."""

    assessment = assess_pivot_opportunities(
        shell, domain=domain, blocked_target=blocked_target
    )
    if assessment.active_pivot_hosts:
        print_info(
            "A pivot is already active in this workspace. Reuse or extend the current pivot before "
            "retesting this host-bound action."
        )
        return

    if assessment.has_confirmed_candidate:
        candidates, graph_filtered = _prefer_graph_confirmed_candidates(
            assessment.confirmed_candidates
        )
        if graph_filtered:
            _render_graph_affinity_panel(candidates, blocked_target=blocked_target)
            print_info_debug(
                "[pivot-opportunity] confirmed branch filtered by graph affinity: "
                f"kept={len(candidates)} "
                f"dropped={len(assessment.confirmed_candidates) - len(candidates)}"
            )
        prompt_text = (
            "Graph-confirmed pivot-capable access. Select targets to open for pivot follow-up:"
            if graph_filtered
            else "Confirmed pivot-capable access exists. Select targets to open for pivot follow-up:"
        )
        options = [
            f"{item.username} -> {item.service.upper()} -> {item.host}"
            for item in candidates
        ]
        selected_options = (
            shell._questionary_checkbox(  # type: ignore[attr-defined]
                prompt_text,
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
            str(option).strip() for option in selected_options if str(option).strip()
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
                    workflow_intent = (
                        workflow_intent_override or capability.followup_workflow_intent
                    )
                    handler(
                        domain,
                        item.host,
                        item.username,
                        item.credential,
                        workflow_intent=workflow_intent,
                    )
                else:
                    handler(domain, item.host, item.username, item.credential)
        return

    if assessment.has_pending_candidate:
        candidates, graph_filtered = _prefer_graph_confirmed_candidates(
            assessment.pending_candidates
        )
        if graph_filtered:
            _render_graph_affinity_panel(candidates, blocked_target=blocked_target)
            print_info_debug(
                "[pivot-opportunity] pending branch filtered by graph affinity: "
                f"kept={len(candidates)} "
                f"dropped={len(assessment.pending_candidates) - len(candidates)}"
            )
        prompt_text = (
            "Graph-confirmed pivot-capable access. Select probes to test now:"
            if graph_filtered
            else (
                "This host-bound action is blocked by current-vantage reachability. "
                "Select pending pivot-capable access probes to test now:"
            )
        )
        options = [
            f"{item.username} -> {item.service.upper()} -> {item.host}"
            for item in candidates
        ]
        selected_options = (
            shell._questionary_checkbox(  # type: ignore[attr-defined]
                prompt_text,
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
            str(option).strip() for option in selected_options if str(option).strip()
        }
        from adscan_internal.cli.privileges import run_service_access_sweep

        for item, label in zip(candidates, options, strict=False):
            if label not in selected:
                continue
            capability = get_pivot_service_capability(item.service)
            workflow_intent = workflow_intent_override or (
                capability.followup_workflow_intent if capability else None
            )
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
                workflow_intent=workflow_intent,
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
            capability = get_pivot_service_capability(item.service)
            workflow_intent = workflow_intent_override or (
                capability.followup_workflow_intent if capability else None
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
                include_previously_tested=True,
                workflow_intent=workflow_intent,
            )
        return

    print_info(
        "No pivot-capable access paths are known or pending for the currently owned users."
    )
