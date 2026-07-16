"""Concurrent WinRM service-access probing with PSRP and Kerberos support."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
import ipaddress
import os
from pathlib import Path
import threading
from typing import TYPE_CHECKING, Any, Callable, Iterable, Optional

from adscan_internal import print_info_debug
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.current_vantage_reachability_service import (
    load_current_vantage_reachability_report,
)
from adscan_internal.services.kerberos_hostname_inventory import (
    choose_hostname_for_kerberos_spn,
    load_workspace_ip_hostname_inventory,
)
from adscan_internal.services.service_access_results import (
    ServiceAccessCategory,
    ServiceAccessFinding,
)
from adscan_internal.services.winrm_psrp_service import (
    WinRMPSRPError,
    WinRMPSRPService,
    is_clock_skew_error,
)
from adscan_internal.services.posture_sink import PostureSink

if TYPE_CHECKING:  # pragma: no cover
    from adscan_internal.services.domain_posture import DomainPosture


WINRM_ACCESS_PROBE_BACKEND = "winrm-psrp"
DEFAULT_WINRM_PROBE_WORKERS = 32
WINRM_PROBE_SCRIPT = (
    "$ErrorActionPreference = 'Stop'; "
    "[pscustomobject]@{ComputerName=$env:COMPUTERNAME; UserName=[Environment]::UserName} "
    "| ConvertTo-Json -Compress"
)


@dataclass(frozen=True, slots=True)
class WinRMProbeTarget:
    """Resolved target for one WinRM access probe."""

    host: str
    kerberos_spn_host: str | None = None


@dataclass(slots=True)
class _ClockSkewRetryCoordinator:
    """Coordinate one shared clock-sync retry budget across WinRM probe workers."""

    sync_clock_with_pdc: Callable[[str], bool] | None
    domain: str
    max_attempts: int = 3
    _lock: threading.Lock = field(init=False, repr=False)
    _generation: int = field(init=False, default=0, repr=False)
    _attempts: int = field(init=False, default=0, repr=False)

    def __post_init__(self) -> None:
        self._lock = threading.Lock()

    def next_retry_generation(self, *, seen_generation: int) -> int | None:
        """Return a new retry generation after one shared clock sync, if possible.

        The clock sync is performed while holding ``self._lock`` so that only ONE
        worker per generation ever syncs: a concurrent worker blocks on the lock
        and, once it acquires it, observes the already-bumped generation and skips
        its own sync. Releasing the lock across the sync (the previous shape) let
        two workers both pass the ``_generation > seen_generation`` check before
        either bumped it, so both stepped the clock — defeating the "one shared
        sync" contract this coordinator exists to enforce.
        """
        marked_domain = mark_sensitive(self.domain, "domain")
        with self._lock:
            if self._generation > seen_generation:
                return self._generation
            if not callable(self.sync_clock_with_pdc):
                return None
            if self._attempts >= self.max_attempts:
                return None
            self._attempts += 1
            attempt = self._attempts

            print_info_debug(
                "[winrm_probe] clock-skew retry requested: "
                f"domain={marked_domain} "
                f"attempt={attempt}/{self.max_attempts}"
            )
            sync_ok = bool(self.sync_clock_with_pdc(self.domain))
            if not sync_ok:
                print_info_debug(
                    "[winrm_probe] clock-skew retry aborted: "
                    f"domain={marked_domain} "
                    f"attempt={attempt}/{self.max_attempts} "
                    "reason=clock_sync_failed"
                )
                return None

            self._generation += 1
            generation = self._generation

        print_info_debug(
            "[winrm_probe] clock-skew retry scheduled: "
            f"domain={marked_domain} "
            f"attempt={attempt}/{self.max_attempts} "
            f"generation={generation}"
        )
        return generation


def _normalize_target(value: object) -> str:
    """Return a stable target token suitable for matching persisted inventory."""
    return str(value or "").strip().rstrip(".")


def _is_ip_address(value: str) -> bool:
    """Return whether a target string is an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _fqdn_or_domain_host(hostname: str, domain: str) -> str:
    """Return a Kerberos-friendly hostname candidate."""
    cleaned = _normalize_target(hostname).lower()
    if not cleaned:
        return ""
    domain_clean = _normalize_target(domain).lower()
    if "." in cleaned or not domain_clean:
        return cleaned
    return f"{cleaned}.{domain_clean}"


def _load_targets(targets: Iterable[str] | str) -> list[str]:
    """Load targets from an iterable or a file path."""
    if isinstance(targets, str):
        candidate = Path(targets)
        if candidate.is_file():
            return [
                line.strip()
                for line in candidate.read_text(
                    encoding="utf-8", errors="ignore"
                ).splitlines()
                if line.strip()
            ]
        return [targets] if targets.strip() else []
    return [str(target).strip() for target in targets if str(target or "").strip()]


def _reason_has_clock_skew(reason: str) -> bool:
    """Return True when *reason* indicates a Kerberos time-skew error.

    Delegates to ``is_clock_skew_error`` so both paths share a single source
    of truth for the set of recognised error markers.
    """
    return is_clock_skew_error(RuntimeError(reason))


def _build_ip_hostname_map_from_reachability(
    *,
    workspace_dir: str,
    domains_dir: str,
    domain: str,
) -> dict[str, str]:
    """Build an IP to preferred FQDN map from the current-vantage report.

    Fallback path used only when the ranked inventory is empty/unavailable.
    The candidate order here is NOT liveness-ranked, so a stale DNS A-record
    sharing an IP with the live host may win — see ``_build_ip_hostname_map``.
    """
    payload, _report_path = load_current_vantage_reachability_report(
        workspace_dir,
        domains_dir,
        domain,
    )
    if not isinstance(payload, dict):
        return {}

    mapping: dict[str, str] = {}
    ip_entries = payload.get("ips")
    if isinstance(ip_entries, list):
        for entry in ip_entries:
            if not isinstance(entry, dict):
                continue
            ip_value = _normalize_target(entry.get("ip"))
            if not ip_value:
                continue
            candidates = entry.get("hostname_candidates", [])
            if not isinstance(candidates, list):
                continue
            for candidate in candidates:
                fqdn = _fqdn_or_domain_host(str(candidate), domain)
                if fqdn:
                    mapping[ip_value.lower()] = fqdn
                    break

    host_entries = payload.get("hosts")
    if isinstance(host_entries, list):
        for entry in host_entries:
            if not isinstance(entry, dict):
                continue
            hostname = _fqdn_or_domain_host(str(entry.get("hostname") or ""), domain)
            if not hostname:
                continue
            for ip_entry in entry.get("ips", []):
                if not isinstance(ip_entry, dict):
                    continue
                ip_value = _normalize_target(ip_entry.get("ip"))
                if ip_value and ip_value.lower() not in mapping:
                    mapping[ip_value.lower()] = hostname
    return mapping


def _build_ip_hostname_map(
    *,
    workspace_dir: str,
    domains_dir: str,
    domain: str,
) -> dict[str, str]:
    """Build an IP to preferred FQDN map for WinRM Kerberos SPN targeting.

    Prefers the liveness-RANKED workspace inventory
    (``load_workspace_ip_hostname_inventory``) so that, when two enabled
    computers share an IP (stale DNS A-record / IP reuse), the SPN binds to the
    host that is ACTUALLY live at that IP (most-recently-authenticated first).
    This keeps the WinRM sweep consistent with the MSSQL collector and the SMB
    share path. Falls back to the (unranked) current-vantage reachability report
    when the ranked inventory is empty or unavailable, so a working sweep never
    regresses. Best-effort: never raises.
    """
    mapping: dict[str, str] = {}
    try:
        inventory = load_workspace_ip_hostname_inventory(
            workspace_dir=workspace_dir,
            domains_dir=domains_dir,
            domain=domain,
        )
    except Exception:  # noqa: BLE001 - best-effort; fall back below
        inventory = {}

    if isinstance(inventory, dict):
        for ip_value in inventory:
            normalized_ip = _normalize_target(ip_value)
            if not normalized_ip:
                continue
            best = choose_hostname_for_kerberos_spn(
                ip=normalized_ip,
                domain=domain,
                inventory=inventory,
            )
            fqdn = _fqdn_or_domain_host(str(best or ""), domain)
            if fqdn:
                mapping[normalized_ip.lower()] = fqdn

    if mapping:
        return mapping

    # Ranked inventory empty/unavailable — fall back to the previous behavior.
    try:
        return _build_ip_hostname_map_from_reachability(
            workspace_dir=workspace_dir,
            domains_dir=domains_dir,
            domain=domain,
        )
    except Exception:  # noqa: BLE001 - best-effort; never regress the sweep
        return {}


def resolve_winrm_probe_targets(
    *,
    targets: Iterable[str] | str,
    domain: str,
    workspace_dir: str,
    domains_dir: str,
    domain_data: dict[str, Any] | None = None,
) -> list[WinRMProbeTarget]:
    """Resolve raw WinRM targets into transport hosts plus Kerberos SPN hosts."""
    raw_targets = list(dict.fromkeys(_load_targets(targets)))
    ip_hostname_map = _build_ip_hostname_map(
        workspace_dir=workspace_dir,
        domains_dir=domains_dir,
        domain=domain,
    )
    resolved: list[WinRMProbeTarget] = []
    pdc_ip = _normalize_target((domain_data or {}).get("pdc"))
    pdc_hostname = _fqdn_or_domain_host(
        str((domain_data or {}).get("pdc_hostname") or ""), domain
    )

    for raw_target in raw_targets:
        target = _normalize_target(raw_target)
        if not target:
            continue
        spn_host: str | None = None
        if _is_ip_address(target):
            spn_host = ip_hostname_map.get(target.lower())
            if (
                not spn_host
                and pdc_ip
                and target.lower() == pdc_ip.lower()
                and pdc_hostname
            ):
                spn_host = pdc_hostname
        else:
            spn_host = _fqdn_or_domain_host(target, domain)
        resolved.append(WinRMProbeTarget(host=target, kerberos_spn_host=spn_host))
    return resolved


def _classify_probe_exception(exc: BaseException) -> tuple[ServiceAccessCategory, str]:
    """Normalize PSRP exceptions into service-access categories."""
    message = str(exc or "").strip()
    lowered = message.lower()
    if any(
        marker in lowered
        for marker in (
            "access is denied",
            "unauthorized",
            "forbidden",
            "credentials were rejected",
            "logon failure",
            "invalid credentials",
        )
    ):
        return "denied", message or "authentication_denied"
    if any(
        marker in lowered
        for marker in (
            "connection refused",
            "timed out",
            "timeout",
            "clock skew too great",
            "skew too great",
            "name or service not known",
            "no route to host",
            "could not resolve",
            "failed to establish",
        )
    ):
        return "transport", message or "transport_error"
    return "ambiguous", message or exc.__class__.__name__


def _probe_one_target(
    *,
    target: WinRMProbeTarget,
    domain: str,
    username: str,
    password: str,
    auth_mode: str,
    kdc_ip: str | None = None,
    workspace_dir: str | None = None,
    clock_skew_retry: _ClockSkewRetryCoordinator | None = None,
    posture_sink: Optional[PostureSink] = None,
    posture_snapshot: Optional["DomainPosture"] = None,
) -> ServiceAccessFinding:
    """Probe one target and return one normalized service-access finding."""
    retry_generation = 0
    while True:
        try:
            service = WinRMPSRPService(
                domain=domain,
                host=target.host,
                username=username,
                password=password,
                auth_mode=auth_mode,
                kerberos_spn_host=target.kerberos_spn_host,
                kdc_ip=kdc_ip,
                workspace_dir=workspace_dir,
                posture_sink=posture_sink,
                posture_snapshot=posture_snapshot,
                domain_for_posture=domain,
            )
            result = service.execute_powershell(
                WINRM_PROBE_SCRIPT,
                operation_name="winrm_access_probe",
            )
            if not result.had_errors:
                finding = ServiceAccessFinding(
                    service="winrm",
                    host=target.host,
                    username=username,
                    category="confirmed",
                    reason="psrp_session_established",
                    status=(result.stdout or "PSRP session established").strip()[:500],
                    backend=WINRM_ACCESS_PROBE_BACKEND,
                )
            else:
                finding = ServiceAccessFinding(
                    service="winrm",
                    host=target.host,
                    username=username,
                    category="ambiguous",
                    reason="psrp_had_errors",
                    status=(
                        result.stderr or result.stdout or "PSRP returned errors"
                    ).strip()[:500],
                    backend=WINRM_ACCESS_PROBE_BACKEND,
                )
        except WinRMPSRPError as exc:
            category, reason = _classify_probe_exception(exc)
            finding = ServiceAccessFinding(
                service="winrm",
                host=target.host,
                username=username,
                category=category,
                reason=reason[:500],
                status=reason[:500],
                backend=WINRM_ACCESS_PROBE_BACKEND,
            )
        except Exception as exc:  # noqa: BLE001
            category, reason = _classify_probe_exception(exc)
            finding = ServiceAccessFinding(
                service="winrm",
                host=target.host,
                username=username,
                category=category,
                reason=reason[:500],
                status=reason[:500],
                backend=WINRM_ACCESS_PROBE_BACKEND,
            )

        if (
            finding.category == "transport"
            and _reason_has_clock_skew(finding.reason)
            and clock_skew_retry is not None
        ):
            next_generation = clock_skew_retry.next_retry_generation(
                seen_generation=retry_generation
            )
            if next_generation is not None:
                retry_generation = next_generation
                continue

        print_info_debug(
            "[winrm_probe] target result: "
            f"host={mark_sensitive(target.host, 'hostname')} "
            f"spn_host={mark_sensitive(str(target.kerberos_spn_host or '-'), 'hostname')} "
            f"category={mark_sensitive(finding.category, 'detail')} "
            f"reason={mark_sensitive(finding.reason, 'text')}"
        )
        return finding


def run_winrm_access_probe_sweep(
    *,
    domain: str,
    username: str,
    password: str,
    targets: Iterable[str] | str,
    workspace_dir: str,
    domains_dir: str,
    domain_data: dict[str, Any] | None = None,
    auth_mode: str = "kerberos",
    max_workers: int | None = None,
    sync_clock_with_pdc: Callable[[str], bool] | None = None,
    posture_sink: Optional[PostureSink] = None,
    posture_snapshot: Optional["DomainPosture"] = None,
) -> list[ServiceAccessFinding]:
    """Probe WinRM access concurrently using the reusable PSRP backend."""
    probe_targets = resolve_winrm_probe_targets(
        targets=targets,
        domain=domain,
        workspace_dir=workspace_dir,
        domains_dir=domains_dir,
        domain_data=domain_data,
    )
    if not probe_targets:
        return []

    # Resolve the target domain's KDC IP so kerbad can mint a TGT for
    # plaintext-password / NT-hash Kerberos auth without depending on the
    # container's system krb5 (single source of truth: resolve_dc_ip).
    sweep_kdc_ip: str | None = None
    try:
        from adscan_internal.models.domain import resolve_dc_ip

        sweep_kdc_ip = resolve_dc_ip(domain_data or {}) or None
    except Exception:  # noqa: BLE001 - best-effort; None keeps legacy behaviour
        sweep_kdc_ip = None

    worker_count = max(
        1, min(max_workers or DEFAULT_WINRM_PROBE_WORKERS, len(probe_targets))
    )
    print_info_debug(
        "[winrm_probe] starting PSRP access sweep: "
        f"domain={mark_sensitive(domain, 'domain')} "
        f"user={mark_sensitive(username, 'user')} "
        f"targets={len(probe_targets)} workers={worker_count} "
        f"auth={mark_sensitive(auth_mode, 'detail')}"
    )

    findings: list[ServiceAccessFinding] = []
    clock_skew_retry = _ClockSkewRetryCoordinator(
        sync_clock_with_pdc=sync_clock_with_pdc,
        domain=domain,
    )
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {
            executor.submit(
                _probe_one_target,
                target=target,
                domain=domain,
                username=username,
                password=password,
                auth_mode=auth_mode,
                kdc_ip=sweep_kdc_ip,
                workspace_dir=workspace_dir,
                clock_skew_retry=clock_skew_retry,
                posture_sink=posture_sink,
                posture_snapshot=posture_snapshot,
            ): target
            for target in probe_targets
        }
        for future in as_completed(future_map):
            finding = future.result()
            findings.append(finding)
            if finding.category == "confirmed":
                print_info_debug(
                    "[winrm_probe] confirmed access: "
                    f"host={mark_sensitive(finding.host, 'hostname')} "
                    f"backend={mark_sensitive(finding.backend, 'detail')} "
                    f"reason={mark_sensitive(finding.reason, 'text')}"
                )

    order = {target.host.lower(): index for index, target in enumerate(probe_targets)}
    findings.sort(key=lambda finding: order.get(finding.host.lower(), len(order)))
    confirmed = sum(1 for finding in findings if finding.category == "confirmed")
    print_info_debug(
        "[winrm_probe] completed PSRP access sweep: "
        f"domain={mark_sensitive(domain, 'domain')} "
        f"user={mark_sensitive(username, 'user')} "
        f"targets={len(findings)} confirmed={confirmed}"
    )
    return findings


def get_winrm_probe_worker_count() -> int:
    """Return operator-configurable WinRM probe concurrency."""
    raw_value = os.getenv("ADSCAN_WINRM_PROBE_WORKERS", "").strip()
    if not raw_value:
        return DEFAULT_WINRM_PROBE_WORKERS
    try:
        return max(1, min(int(raw_value), 128))
    except ValueError:
        return DEFAULT_WINRM_PROBE_WORKERS


# ---------------------------------------------------------------------------
# Single-host availability probe (used by the remote_exec cascade fingerprint)
# ---------------------------------------------------------------------------


WinRMAvailability = str  # Literal["available", "auth_failed", "port_closed", "unknown"]


def _category_to_availability(category: ServiceAccessCategory) -> WinRMAvailability:
    """Map a ServiceAccessCategory to the cascade's availability vocabulary."""
    if category == "confirmed":
        return "available"
    if category == "denied":
        return "auth_failed"
    if category == "transport":
        return "port_closed"
    return "unknown"


async def probe_winrm_available(
    host: str,
    *,
    domain: str,
    username: str,
    password: str,
    auth_mode: str = "auto",
    kerberos_spn_host: str | None = None,
    kdc_ip: str | None = None,
    workspace_dir: str | None = None,
    timeout: int = 10,
    posture_sink: Optional[PostureSink] = None,
    posture_snapshot: Optional["DomainPosture"] = None,
) -> WinRMAvailability:
    """Probe one host for WinRM PSRP availability and credential acceptance.

    Returns:
        ``"available"``  — port open AND auth works.
        ``"auth_failed"`` — port open but auth rejected; do not retry with
            this credential.
        ``"port_closed"`` — connection refused / unreachable / timeout.
        ``"unknown"``     — probe failed for an inconclusive reason.

    Args:
        host: Target IP or hostname.
        domain: Credential domain.
        username: Account username (no domain prefix).
        password: Password, NT hash, or path to a Kerberos ccache file.
        auth_mode: ``"auto"`` (default) | ``"ntlm"`` | ``"kerberos"`` |
            ``"negotiate"``. ``"auto"`` selects Kerberos for ccache paths
            and NTLM otherwise.
        kerberos_spn_host: Optional SPN hostname override (FQDN) used when
            authenticating with Kerberos against an IP target.
        kdc_ip: Optional KDC IP for the target domain. Threaded into the PSRP
            service so kerbad can mint a TGT for plaintext-password / NT-hash
            Kerberos auth without relying on the container's system krb5.
        workspace_dir: Optional workspace root. When set, the PSRP service
            prefers an already-minted ccache for this principal under
            ``domains/<domain>/kerberos/tickets/<user>.ccache``.
        timeout: Per-call timeout in seconds.

    Notes:
        Wraps the existing :func:`_probe_one_target` private helper so the
        same classification rules apply to bulk sweeps and single-host
        availability checks. Never raises.
    """
    import asyncio  # local to keep module top-level imports unchanged

    target = WinRMProbeTarget(host=host, kerberos_spn_host=kerberos_spn_host)

    def _run() -> ServiceAccessFinding:
        return _probe_one_target(
            target=target,
            domain=domain,
            username=username,
            password=password,
            auth_mode=auth_mode,
            kdc_ip=kdc_ip,
            workspace_dir=workspace_dir,
            clock_skew_retry=None,
            posture_sink=posture_sink,
            posture_snapshot=posture_snapshot,
        )

    try:
        finding = await asyncio.wait_for(asyncio.to_thread(_run), timeout=timeout)
    except asyncio.TimeoutError:
        return "port_closed"
    except Exception:  # noqa: BLE001 - never let a probe break the caller
        return "unknown"
    return _category_to_availability(finding.category)
