"""Concurrent SMB service-access probing on the native aiosmb stack.

Native replacement for the netexec ``smb`` ``(Pwn3d!)`` sweep. Reuses the
existing admin-access primitive in :mod:`adscan_internal.services.smb_privilege`
(``ADMIN$``/``C$`` tree-connect == netexec Pwn3d semantics) and normalizes the
result into the backend-agnostic :class:`ServiceAccessFinding` model so the
shared rendering / persistence / follow-up UX is identical to the WinRM PSRP
sweep.

Constraints handled transparently by the underlying transport:
  - NTLM disabled by GPO  → Kerberos via smb_machine_with_fallback
  - SMB signing required  → negotiated by smb_transport
  - AES-only KDC          → ETYPE-INFO2 probe in kerberos_transport
  - Cross-domain creds    → auth_domain / kdc_ip separate from target host

Enterprise scale (skill §10): bounded concurrency via the semaphore inside
``check_smb_privilege_batch``, per-host connection timeout, and a TCP
pre-filter on 445 performed by the caller before the sweep starts.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Iterable, Optional

from adscan_internal import print_info_debug
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.service_access_results import ServiceAccessFinding
from adscan_internal.services.smb_privilege import (
    SMBPrivilegeConfig,
    SMBPrivilegeResult,
    SMBPrivilegeStatus,
    check_smb_privilege_batch,
)
from adscan_internal.services.posture_sink import PostureSink

if TYPE_CHECKING:  # pragma: no cover
    from adscan_internal.services.domain_posture import DomainPosture


SMB_ACCESS_PROBE_BACKEND = "smb-native"
DEFAULT_SMB_PROBE_WORKERS = 30


def get_smb_probe_worker_count() -> int:
    """Return operator-configurable SMB probe concurrency (clamped 1-128)."""
    raw_value = os.getenv("ADSCAN_SMB_PROBE_WORKERS", "").strip()
    if not raw_value:
        return DEFAULT_SMB_PROBE_WORKERS
    try:
        return max(1, min(int(raw_value), 128))
    except ValueError:
        return DEFAULT_SMB_PROBE_WORKERS


def _normalize_target(value: object) -> str:
    """Return a stable target token suitable for matching persisted inventory."""
    return str(value or "").strip().rstrip(".")


def _status_to_finding(
    result: SMBPrivilegeResult,
    *,
    username: str,
) -> ServiceAccessFinding:
    """Map one :class:`SMBPrivilegeResult` onto a normalized service finding.

    Only ``ADMIN`` (a successful ADMIN$/C$ tree-connect, i.e. netexec Pwn3d)
    counts as confirmed SMB privileged access. ``NOT_ADMIN`` is a successful
    authentication without admin rights — surfaced as ``denied`` so the
    summary distinguishes "no access" from "no answer".
    """
    host = result.target_ip
    if result.status == SMBPrivilegeStatus.ADMIN:
        share = result.admin_share or "ADMIN$"
        proto = result.auth_protocol or "?"
        return ServiceAccessFinding(
            service="smb",
            host=host,
            username=username,
            category="confirmed",
            reason="admin_tree_connect",
            status=f"{share} tree_connect OK ({proto})"[:500],
            backend=SMB_ACCESS_PROBE_BACKEND,
        )
    if result.status == SMBPrivilegeStatus.NOT_ADMIN:
        return ServiceAccessFinding(
            service="smb",
            host=host,
            username=username,
            category="denied",
            reason="authenticated_not_admin",
            status="authenticated but no admin share access"[:500],
            backend=SMB_ACCESS_PROBE_BACKEND,
        )
    if result.status == SMBPrivilegeStatus.AUTH_FAILED:
        return ServiceAccessFinding(
            service="smb",
            host=host,
            username=username,
            category="denied",
            reason="auth_failed",
            status=(result.error or "credentials rejected")[:500],
            backend=SMB_ACCESS_PROBE_BACKEND,
        )
    if result.status == SMBPrivilegeStatus.UNREACHABLE:
        return ServiceAccessFinding(
            service="smb",
            host=host,
            username=username,
            category="transport",
            reason="unreachable",
            status=(result.error or "host unreachable")[:500],
            backend=SMB_ACCESS_PROBE_BACKEND,
        )
    return ServiceAccessFinding(
        service="smb",
        host=host,
        username=username,
        category="ambiguous",
        reason="probe_error",
        status=(result.error or "unexpected error")[:500],
        backend=SMB_ACCESS_PROBE_BACKEND,
    )


async def run_smb_access_probe_sweep(
    *,
    domain: str,
    username: str,
    password: str | None = None,
    nt_hash: str | None = None,
    aes_key: str | None = None,
    ccache_path: str | None = None,
    targets: Iterable[str],
    auth_domain: str | None = None,
    kdc_ip: str | None = None,
    use_kerberos: bool = False,
    target_hostnames: Optional[dict[str, str]] = None,
    timeout: int = 15,
    max_workers: int | None = None,
    posture_sink: Optional[PostureSink] = None,
    posture_snapshot: Optional["DomainPosture"] = None,
) -> list[ServiceAccessFinding]:
    """Probe SMB admin access concurrently using the native aiosmb primitive.

    Args:
        domain: Target domain of the hosts being probed.
        username: Account to test.
        password: Plaintext password (mutually exclusive with the other
            credential fields; an NT hash that lands here is auto-routed).
        nt_hash: NT hash for pass-the-hash.
        aes_key: AES-128/256 Kerberos key.
        ccache_path: Path to a Kerberos ccache file.
        targets: Host IPs (or FQDNs) to probe. Callers should TCP-pre-filter
            on 445 before calling so offline hosts do not consume a worker.
        auth_domain: Credential domain when different from the target domain.
        kdc_ip: KDC for ``auth_domain`` (Kerberos cross-domain).
        use_kerberos: Force Kerberos; skip NTLM entirely.
        target_hostnames: Optional IP→FQDN map used for the Kerberos SPN
            (``cifs/<fqdn>``). The transport promotes short names to FQDN.
        timeout: Per-host connection timeout in seconds.
        max_workers: Bounded concurrency. ``None`` → ``get_smb_probe_worker_count``.
        posture_sink: Optional sink for Intelligence Updates emitted by the
            transport when it observes a domain-wide hardening signal.
        posture_snapshot: Posture snapshot threaded into the ``SMBConfig`` so
            the planner prunes impossible auth combinations on the first try.

    Returns:
        One :class:`ServiceAccessFinding` per resolved target, ordered to match
        the input ``targets`` order. Never raises — internal failures map to
        ``ambiguous`` findings via the underlying batch primitive.
    """
    resolved_targets: list[str] = []
    seen: set[str] = set()
    for raw in targets:
        target = _normalize_target(raw)
        if not target or target.lower() in seen:
            continue
        seen.add(target.lower())
        resolved_targets.append(target)

    if not resolved_targets:
        return []

    # Liveness re-gate (445/tcp). smb/ips.txt was populated by the Phase-3 port
    # scan, but minutes can have passed and hosts may have gone down since — a
    # stale-dead host that still answers TCP (or hangs) would otherwise burn a
    # worker and stall the sweep. This is a cheap one-port concurrent probe, NOT
    # a re-scan. Gating HERE (in the service, not the caller) is the robust SSOT:
    # the docstring's old "callers should pre-filter" contract was fragile — the
    # SMB privilege path did not, which is how a single hung host blocked the
    # whole sweep for >10min. The per-host wall-clock budget in
    # check_smb_privilege_batch is the backstop for hosts that pass this gate
    # (TCP-accept) but then hang the SMB negotiate / Kerberos.
    from adscan_internal.services.host_reachability_filter import (
        filter_reachable_hosts,
    )

    # Scale the gate fan-out with the fleet: a TCP connect is cheap (no auth), so
    # high concurrency is safe and keeps the gate to a few seconds even at 1-2k
    # hosts (vs ~60s at the default 50). Dead hosts cost only the 3s probe
    # timeout, not the 45s auth budget they would burn without the gate.
    gate_concurrency = max(50, min(len(resolved_targets), 256))
    reach = await filter_reachable_hosts(
        resolved_targets, 445, max_concurrency=gate_concurrency
    )
    if len(reach.reachable) != len(resolved_targets):
        print_info_debug(
            f"[smb_probe] 445 liveness gate: {len(reach.reachable)}/"
            f"{len(resolved_targets)} reachable now "
            f"({len(reach.offline)} down since the port scan, skipped; "
            f"{reach.elapsed_ms:.0f}ms)"
        )
    resolved_targets = list(reach.reachable)
    if not resolved_targets:
        return []

    worker_count = max(
        1, min(max_workers or get_smb_probe_worker_count(), len(resolved_targets))
    )
    hostname_map = {
        _normalize_target(ip).lower(): _normalize_target(host)
        for ip, host in (target_hostnames or {}).items()
        if _normalize_target(host)
    }

    print_info_debug(
        "[smb_probe] starting native SMB access sweep: "
        f"domain={mark_sensitive(domain, 'domain')} "
        f"user={mark_sensitive(username, 'user')} "
        f"targets={len(resolved_targets)} workers={worker_count} "
        f"kerberos={use_kerberos}"
    )

    configs = [
        SMBPrivilegeConfig(
            target_ip=target,
            target_hostname=hostname_map.get(target.lower()),
            domain=domain,
            username=username,
            password=password,
            nt_hash=nt_hash,
            aes_key=aes_key,
            ccache_path=ccache_path,
            auth_domain=auth_domain,
            kdc_ip=kdc_ip,
            use_kerberos=use_kerberos,
            timeout=timeout,
            posture_sink=posture_sink,
            posture_snapshot=posture_snapshot,
        )
        for target in resolved_targets
    ]

    results = await check_smb_privilege_batch(configs, max_concurrency=worker_count)

    findings = [_status_to_finding(result, username=username) for result in results]
    confirmed = sum(1 for finding in findings if finding.is_confirmed)
    for finding in findings:
        if finding.is_confirmed:
            print_info_debug(
                "[smb_probe] confirmed admin access: "
                f"host={mark_sensitive(finding.host, 'hostname')} "
                f"backend={mark_sensitive(finding.backend, 'detail')} "
                f"reason={mark_sensitive(finding.reason, 'text')}"
            )
    print_info_debug(
        "[smb_probe] completed native SMB access sweep: "
        f"domain={mark_sensitive(domain, 'domain')} "
        f"user={mark_sensitive(username, 'user')} "
        f"targets={len(findings)} confirmed={confirmed}"
    )
    return findings
