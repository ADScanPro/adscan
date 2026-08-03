"""Service target resolution — the single source of truth for "which hosts
should I attempt ``<service>`` on?".

A service collector must not gate its discovery on the SYN-scan-reachable set
alone (``<service>/ips.txt``). Over a Ligolo pivot — or against a filtered /
non-standard port — the direct SYN scan misses the port, so a host we KNOW runs
the service (from its ``MSSQLSvc/*`` SPN, or that a pivot confirmed reachable on
the port) gets silently skipped. That is a whole class of bug: the per-instance
auth fallback (Kerberos→NTLM) never fires because DISCOVERY short-circuits
upstream.

This primitive answers the question ONCE, by unioning three evidence sources
that already exist in the workspace — never a fourth parallel mechanism:

  * **syn** — the SYN-scan-reachable IPs in ``<service>/ips.txt``
    (produced by the Phase-2 nmap port scan).
  * **spn** — service hosts known from the attack graph's SPNs (e.g.
    ``MSSQLSvc/<host>`` → ``<host>`` → resolved to an IP via the workspace
    hostname↔IP inventory). The caller supplies the ``{fqdn_host: spn}`` map so
    the OPSEC decision of WHICH SPN class to seed stays at the call site — a
    dedicated-service SPN (``MSSQLSvc``) is safe to seed; a ubiquitous SPN
    (``cifs/HOST``, present on every computer) is NOT and must never be passed
    here, or the union becomes a domain-wide spray.
  * **pivot** — hosts a pivot confirmed reachable on the service port, from the
    per-pivot reachability reports (via
    :func:`target_reachability_inference_service.collect_pivot_reachable_targets`).

Every target is enriched with an FQDN (from the IP→FQDN inventory, then from a
matching SPN host) and the FQDN is promoted through the Kerberos-SPN SSOT
(:func:`_kerberos_spn.normalize_kerberos_target_hostname`) so a Kerberos connect
that follows requests ``MSSQLSvc/<fqdn>``, never ``MSSQLSvc/<ip>``.

OPSEC / scale (skill ``adscan-ad-constraints`` §§10-11): the union is bounded to
hosts with REAL evidence (a reachable port, a dedicated-service SPN, or a
pivot-confirmed port) — never "attempt every host". A false "attempt this SPN
host" costs one bounded, cleanly-failing connect, not a spray. Dedup is by
resolved IP (then FQDN, then host string) so the same host discovered by two
sources is attempted once, carrying the union of its provenance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from adscan_core import telemetry
from adscan_core.rich_output import print_exception


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ServiceTarget:
    """One host worth attempting ``<service>`` on, with its provenance.

    Attributes:
        host: The connect target — the resolved IP when known, else the FQDN.
            Always non-empty. This is what a TDS/SMB/WinRM connect opens.
        ip: The resolved IP address, or ``None`` when only a hostname is known
            (an SPN host the inventory could not resolve to an address).
        fqdn: The FQDN for the Kerberos SPN, promoted to a fully-qualified name,
            or ``None`` when no hostname is known.
        spn: The service SPN that surfaced this host (e.g. ``MSSQLSvc/...``),
            when one is known.
        sources: The evidence sources that contributed this target — a subset of
            ``{"syn", "spn", "pivot"}``.
    """

    host: str
    ip: str | None = None
    fqdn: str | None = None
    spn: str | None = None
    sources: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class ServiceTargetResolution:
    """The resolved connect-target set for one service, with provenance counts."""

    service: str
    targets: tuple[ServiceTarget, ...]
    syn_count: int = 0
    spn_count: int = 0
    pivot_count: int = 0

    @property
    def spn_only_hosts(self) -> tuple[ServiceTarget, ...]:
        """Targets NOT in the SYN-scan set — surfaced by SPN/pivot evidence only.

        These are exactly the hosts the old ``ips.txt``-only gate would have
        silently skipped; a caller promotes them to a visible advisory.
        """
        return tuple(t for t in self.targets if "syn" not in t.sources)


# ---------------------------------------------------------------------------
# Internal target accumulator (keyed by dedup identity)
# ---------------------------------------------------------------------------


class _TargetAccumulator:
    """Merge targets from every source, deduping by resolved IP → FQDN → host."""

    def __init__(self) -> None:
        self._by_key: dict[str, dict[str, Any]] = {}
        self._order: list[str] = []

    @staticmethod
    def _key(*, ip: str | None, fqdn: str | None, host: str) -> str:
        if ip:
            return f"ip:{ip.lower()}"
        if fqdn:
            return f"fqdn:{fqdn.lower()}"
        return f"host:{host.lower()}"

    def add(
        self,
        *,
        ip: str | None,
        fqdn: str | None,
        spn: str | None,
        source: str,
    ) -> None:
        ip_clean = (ip or "").strip() or None
        fqdn_clean = (fqdn or "").strip().rstrip(".").lower() or None
        host = ip_clean or fqdn_clean
        if not host:
            return
        key = self._key(ip=ip_clean, fqdn=fqdn_clean, host=host)
        record = self._by_key.get(key)
        if record is None:
            record = {
                "ip": ip_clean,
                "fqdn": fqdn_clean,
                "spn": spn,
                "sources": set(),
            }
            self._by_key[key] = record
            self._order.append(key)
        else:
            # Enrich: an FQDN/SPN learned from a later source fills a gap.
            if not record["fqdn"] and fqdn_clean:
                record["fqdn"] = fqdn_clean
            if not record["spn"] and spn:
                record["spn"] = spn
            if not record["ip"] and ip_clean:
                record["ip"] = ip_clean
        record["sources"].add(source)

    def finalize(self) -> tuple[ServiceTarget, ...]:
        targets: list[ServiceTarget] = []
        for key in self._order:
            record = self._by_key[key]
            ip = record["ip"]
            fqdn = record["fqdn"]
            host = ip or fqdn
            if not host:
                continue
            targets.append(
                ServiceTarget(
                    host=host,
                    ip=ip,
                    fqdn=fqdn,
                    spn=record["spn"],
                    sources=frozenset(record["sources"]),
                )
            )
        return tuple(targets)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def resolve_service_targets(
    shell: Any,
    domain: str,
    *,
    service: str,
    spn_hosts: Mapping[str, str] | None = None,
    include_pivot_reachable: bool = True,
) -> ServiceTargetResolution:
    """Resolve the connect-target set for ``service`` in ``domain``.

    Unions the SYN-scan-reachable IPs (``<service>/ips.txt``), the caller-supplied
    SPN hosts (resolved to IPs via the workspace inventory), and the pivot-reachable
    hosts (confirmed on the service port). Never raises — any source that fails is
    skipped and the others still contribute.

    Args:
        shell: Shell exposing ``current_workspace_dir`` / ``domains_dir``.
        domain: Target domain whose evidence is read.
        service: Service key (``"mssql"``, ``"winrm"``, …) — selects the
            ``<service>/ips.txt`` dir, the pivot-report dir, and the port filter.
        spn_hosts: ``{fqdn_host: spn}`` service hosts known from the graph. Pass
            ONLY a dedicated-service SPN class (e.g. ``MSSQLSvc``); a ubiquitous
            SPN would turn the union into a spray. ``None`` = no SPN seeding.
        include_pivot_reachable: When True, add hosts a pivot confirmed reachable
            on the service port.

    Returns:
        A :class:`ServiceTargetResolution` — the deduped union with provenance.
    """
    from adscan_internal.services.network_probe_service import SERVICE_PROBE_PORTS

    domain_clean = str(domain or "").strip()
    service_clean = str(service or "").strip().lower()
    if not domain_clean or not service_clean:
        return ServiceTargetResolution(service=service_clean, targets=())

    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "")
    domains_dir = str(getattr(shell, "domains_dir", "") or "")
    if not workspace_dir or not domains_dir:
        return ServiceTargetResolution(service=service_clean, targets=())

    ip_to_fqdns = _load_ip_hostname_inventory(shell, domain_clean)
    fqdn_to_ip = _load_hostname_ip_inventory(shell, domain_clean)
    spn_map = {
        str(host or "").strip().rstrip(".").lower(): str(spn or "").strip()
        for host, spn in (spn_hosts or {}).items()
        if str(host or "").strip()
    }

    acc = _TargetAccumulator()
    syn_count = 0
    spn_count = 0
    pivot_count = 0

    # --- Source: syn (mssql/ips.txt) ---
    for ip in _load_service_ips(workspace_dir, domains_dir, domain_clean, service_clean):
        fqdn = _fqdn_for_ip(ip, ip_to_fqdns, domain_clean)
        spn = spn_map.get(fqdn.lower()) if fqdn else None
        acc.add(ip=ip, fqdn=fqdn, spn=spn, source="syn")
        syn_count += 1

    # --- Source: spn (graph MSSQLSvc/* → host → IP) ---
    for host_lc, spn in spn_map.items():
        fqdn = _normalize_fqdn(host_lc, domain_clean)
        ip = fqdn_to_ip.get(host_lc) or fqdn_to_ip.get(host_lc.split(".", 1)[0])
        acc.add(ip=ip, fqdn=fqdn or host_lc, spn=spn or None, source="spn")
        spn_count += 1

    # --- Source: pivot (confirmed reachable on the service port) ---
    if include_pivot_reachable:
        try:
            from adscan_internal.services.target_reachability_inference_service import (
                collect_pivot_reachable_targets,
            )

            ports = SERVICE_PROBE_PORTS.get(service_clean)
            reachable = collect_pivot_reachable_targets(
                shell, domain=domain_clean, service=service_clean, ports=ports
            )
            for ip in reachable:
                fqdn = _fqdn_for_ip(ip, ip_to_fqdns, domain_clean)
                spn = spn_map.get(fqdn.lower()) if fqdn else None
                acc.add(ip=ip, fqdn=fqdn, spn=spn, source="pivot")
                pivot_count += 1
        except Exception as exc:  # noqa: BLE001 — pivot enrichment is best-effort
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    return ServiceTargetResolution(
        service=service_clean,
        targets=acc.finalize(),
        syn_count=syn_count,
        spn_count=spn_count,
        pivot_count=pivot_count,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_service_ips(
    workspace_dir: str, domains_dir: str, domain: str, service: str
) -> list[str]:
    """Read the SYN-scan-reachable IPs from ``<domain>/<service>/ips.txt``."""
    import os

    try:
        from adscan_internal.workspaces import domain_subpath

        path = domain_subpath(workspace_dir, domains_dir, domain, service, "ips.txt")
    except Exception as exc:  # noqa: BLE001 — path helper must never break resolution
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return []
    if not path or not os.path.exists(path):
        return []
    ips: list[str] = []
    seen: set[str] = set()
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                ip = line.strip()
                if ip and ip not in seen:
                    seen.add(ip)
                    ips.append(ip)
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    return ips


def _load_ip_hostname_inventory(shell: Any, domain: str) -> dict[str, list[str]]:
    """Load the workspace IP→FQDN inventory; ``{}`` on any failure (best-effort)."""
    try:
        from adscan_internal.services.kerberos_hostname_inventory import (
            load_workspace_ip_hostname_inventory,
        )

        workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "")
        domains_dir = str(getattr(shell, "domains_dir", "") or "")
        if not workspace_dir or not domains_dir:
            return {}
        inventory = load_workspace_ip_hostname_inventory(
            workspace_dir=workspace_dir, domains_dir=domains_dir, domain=domain
        )
        return inventory if isinstance(inventory, dict) else {}
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return {}


def _load_hostname_ip_inventory(shell: Any, domain: str) -> dict[str, str]:
    """Load the workspace hostname→IP inventory; ``{}`` on any failure."""
    try:
        from adscan_internal.services.kerberos_hostname_inventory import (
            load_workspace_hostname_ip_inventory,
        )

        workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "")
        domains_dir = str(getattr(shell, "domains_dir", "") or "")
        if not workspace_dir or not domains_dir:
            return {}
        inventory = load_workspace_hostname_ip_inventory(
            workspace_dir=workspace_dir, domains_dir=domains_dir, domain=domain
        )
        return inventory if isinstance(inventory, dict) else {}
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return {}


def _fqdn_for_ip(
    ip: str, ip_to_fqdns: Mapping[str, list[str]], domain: str
) -> str | None:
    """Best FQDN candidate for one IP, promoted to a fully-qualified name."""
    candidates = ip_to_fqdns.get(ip) if isinstance(ip_to_fqdns, Mapping) else None
    if isinstance(candidates, list):
        for candidate in candidates:
            cand = str(candidate or "").strip().rstrip(".").lower()
            if cand:
                return _normalize_fqdn(cand, domain)
    return None


def _normalize_fqdn(host: str | None, domain: str) -> str | None:
    """Promote a short host to an FQDN via the Kerberos-SPN SSOT (lowercased)."""
    from adscan_internal.services._kerberos_spn import (
        normalize_kerberos_target_hostname,
    )

    promoted = normalize_kerberos_target_hostname(host, domain)
    return promoted.lower() if promoted else None


__all__ = [
    "ServiceTarget",
    "ServiceTargetResolution",
    "resolve_service_targets",
]
