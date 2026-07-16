"""Concurrent MSSQL service-access probing on the native impacket.tds stack.

Native replacement for the netexec ``mssql`` sweep. The access check is a
real MSSQL login performed in-process by :class:`ImpacketMSSQLBackend`
(impacket TDS, NOT a subprocess). A successful login confirms MSSQL access;
when the login principal is ``sysadmin`` (``IS_SRVROLEMEMBER('sysadmin')``)
we surface that so the dispatch can record a ``SQLAdmin`` edge instead of a
``SQLAccess`` edge — matching the netexec ``(Pwn3d!)`` semantics.

Constraints handled by the backend:
  - Kerberos SPN FQDN     → promoted by ImpacketMSSQLBackend.__init__
  - Kerberos infra errors → retried with NTLM when fallback is allowed
  - ccache credentials    → kerberosLogin(useCache=True)

Enterprise scale (skill §10): bounded concurrency via an ``asyncio.Semaphore``,
each blocking TDS login executed in a worker thread, per-host login timeout,
and a TCP pre-filter on the MSSQL port performed by the caller.
"""

from __future__ import annotations

import asyncio
import os
from typing import Iterable, Optional

from adscan_internal import print_info_debug, telemetry
from adscan_internal.integrations.mssql import queries
from adscan_internal.integrations.mssql.native_backend import ImpacketMSSQLBackend
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.service_access_results import ServiceAccessFinding


MSSQL_ACCESS_PROBE_BACKEND = "mssql-native"
DEFAULT_MSSQL_PROBE_WORKERS = 30
DEFAULT_MSSQL_PORT = 1433

# Substrings that indicate a transport / infrastructure failure rather than a
# credential rejection. Keep narrow — anything not matched is treated as a
# definitive auth denial (the actionable default after a TCP pre-filter).
_TRANSPORT_MARKERS = (
    "timed out",
    "timeout",
    "connection refused",
    "connection reset",
    "no route to host",
    "name or service not known",
    "could not resolve",
    "broken pipe",
    "unreachable",
)


def get_mssql_probe_worker_count() -> int:
    """Return operator-configurable MSSQL probe concurrency (clamped 1-128)."""
    raw_value = os.getenv("ADSCAN_MSSQL_PROBE_WORKERS", "").strip()
    if not raw_value:
        return DEFAULT_MSSQL_PROBE_WORKERS
    try:
        return max(1, min(int(raw_value), 128))
    except ValueError:
        return DEFAULT_MSSQL_PROBE_WORKERS


def _normalize_target(value: object) -> str:
    """Return a stable target token suitable for matching persisted inventory."""
    return str(value or "").strip().rstrip(".")


def _classify_login_failure(error_message: str | None) -> tuple[str, str]:
    """Return a ``(category, reason)`` pair for a failed MSSQL login.

    Transport errors classify as ``transport``; everything else as a
    credential ``denied`` — the most actionable default for a host that
    already passed the TCP pre-filter on the MSSQL port.
    """
    lowered = str(error_message or "").lower()
    if any(marker in lowered for marker in _TRANSPORT_MARKERS):
        return "transport", "transport_error"
    return "denied", "login_failed"


def _probe_one_target(
    *,
    host: str,
    port: int,
    domain: str,
    username: str,
    secret: str,
    use_kerberos: bool,
    kerberos_target_hostname: str | None,
    timeout: int,
    kdc_host: str | None = None,
    ntlm_fallback_secret: str | None = None,
) -> ServiceAccessFinding:
    """Run one blocking MSSQL login + sysadmin probe and normalize the result.

    Never raises — every failure maps onto a ``ServiceAccessFinding`` so the
    bounded gather in :func:`run_mssql_access_probe_sweep` cannot be broken by
    a single misbehaving host. A single ``IS_SRVROLEMEMBER('sysadmin')`` query
    serves as both the login check (success ⇒ authenticated) and the privilege
    check (row value ⇒ sysadmin).
    """
    try:
        backend = ImpacketMSSQLBackend(
            host=host,
            port=port,
            kerberos_target_hostname=kerberos_target_hostname,
            domain=domain,
            kdc_host=kdc_host,
        )
        # Allow the backend's Kerberos→NTLM infra fallback so a hardened KDC
        # path does not produce a false "no access" when NTLM would work.
        # ``ntlm_fallback_secret`` carries a password / NT hash so a ccache-only
        # sweep credential can still reach an instance with no MSSQLSvc SPN
        # (Kerberos → KDC_ERR_S_PRINCIPAL_UNKNOWN) over NTLM.
        result = backend.execute_query(
            domain=domain,
            username=username,
            secret=secret,
            query=queries.IS_SYSADMIN,
            timeout=timeout,
            use_kerberos=use_kerberos,
            allow_ntlm_fallback=True,
            ntlm_fallback_secret=ntlm_fallback_secret,
        )
    except Exception as exc:  # noqa: BLE001 — probe must never raise
        telemetry.capture_exception(exc)
        return ServiceAccessFinding(
            service="mssql",
            host=host,
            username=username,
            category="ambiguous",
            reason="probe_error",
            status=str(exc)[:500],
            backend=MSSQL_ACCESS_PROBE_BACKEND,
        )

    if not result.success:
        category, reason = _classify_login_failure(result.error_message)
        return ServiceAccessFinding(
            service="mssql",
            host=host,
            username=username,
            category=category,
            reason=reason,
            status=(result.error_message or "MSSQL login failed")[:500],
            backend=MSSQL_ACCESS_PROBE_BACKEND,
        )

    is_sysadmin = bool(result.rows) and _truthy(result.rows[0].get("is_sysadmin"))
    status_label = "sysadmin login confirmed" if is_sysadmin else "authenticated login"
    return ServiceAccessFinding(
        service="mssql",
        host=host,
        username=username,
        category="confirmed",
        reason="sysadmin_login" if is_sysadmin else "authenticated_access",
        status=status_label,
        backend=MSSQL_ACCESS_PROBE_BACKEND,
    )


def _truthy(value: object) -> bool:
    """Coerce a TDS scalar (int/str/bool) to bool for the sysadmin flag."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "t"}
    return bool(value)


def finding_is_sysadmin(finding: ServiceAccessFinding) -> bool:
    """Return whether a confirmed MSSQL finding reached sysadmin.

    Pure helper so the dispatch can pick the ``SQLAdmin`` vs ``SQLAccess``
    edge relation without re-probing. Mirrors the netexec ``(Pwn3d!)`` rule.
    """
    return finding.is_confirmed and finding.reason == "sysadmin_login"


async def run_mssql_access_probe_sweep(
    *,
    domain: str,
    username: str,
    secret: str,
    targets: Iterable[str],
    port: int = DEFAULT_MSSQL_PORT,
    use_kerberos: bool = False,
    target_hostnames: Optional[dict[str, str]] = None,
    kdc_host: str | None = None,
    timeout: int = 30,
    max_workers: int | None = None,
    ntlm_fallback_secret: str | None = None,
) -> list[ServiceAccessFinding]:
    """Probe MSSQL login access concurrently using the native impacket backend.

    Args:
        domain: Target domain of the SQL hosts.
        username: Account to test.
        secret: Plaintext password, 32-hex NT hash, or path to a ccache file.
        targets: SQL host IPs (or FQDNs). Callers should TCP-pre-filter on the
            MSSQL port before calling.
        port: MSSQL TCP port (default 1433).
        use_kerberos: Use Kerberos (Windows auth) instead of NTLM. Auto-forced
            when ``secret`` is a ccache path.
        target_hostnames: Optional IP→FQDN map for the Kerberos SPN
            (``MSSQLSvc/<fqdn>:<port>``).
        kdc_host: DC/KDC IP for impacket's self-minted AS-REQ/TGS-REQ. When
            ``None`` impacket resolves the KDC by DNS from the domain name,
            which fails inside a container without AD DNS. An IP is acceptable
            here (transport target, not a service SPN).
        timeout: Per-host login timeout in seconds.
        max_workers: Bounded concurrency. ``None`` → ``get_mssql_probe_worker_count``.
        ntlm_fallback_secret: Optional password / NT hash for the same principal,
            used for the NTLM attempt when ``secret`` is a ccache path. Lets a
            Kerberos-only sweep still assess instances with no ``MSSQLSvc`` SPN
            (Kerberos → ``KDC_ERR_S_PRINCIPAL_UNKNOWN``). Callers must gate this
            on NTLM not being known-blocked by domain posture, and must never
            pass a ccache here.

    Returns:
        One :class:`ServiceAccessFinding` per resolved target, ordered to match
        the input ``targets`` order. Never raises.
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

    effective_use_kerberos = bool(
        use_kerberos or str(secret or "").strip().lower().endswith(".ccache")
    )
    worker_count = max(
        1, min(max_workers or get_mssql_probe_worker_count(), len(resolved_targets))
    )
    hostname_map = {
        _normalize_target(ip).lower(): _normalize_target(host)
        for ip, host in (target_hostnames or {}).items()
        if _normalize_target(host)
    }

    print_info_debug(
        "[mssql_probe] starting native MSSQL access sweep: "
        f"domain={mark_sensitive(domain, 'domain')} "
        f"user={mark_sensitive(username, 'user')} "
        f"targets={len(resolved_targets)} workers={worker_count} "
        f"kerberos={effective_use_kerberos} "
        f"ntlm_fallback={bool(ntlm_fallback_secret)}"
    )

    semaphore = asyncio.Semaphore(worker_count)

    async def _bounded(host: str) -> ServiceAccessFinding:
        async with semaphore:
            try:
                return await asyncio.wait_for(
                    asyncio.to_thread(
                        _probe_one_target,
                        host=host,
                        port=port,
                        domain=domain,
                        username=username,
                        secret=secret,
                        use_kerberos=effective_use_kerberos,
                        kerberos_target_hostname=hostname_map.get(host.lower()),
                        kdc_host=kdc_host,
                        timeout=timeout,
                        ntlm_fallback_secret=ntlm_fallback_secret,
                    ),
                    # Hard ceiling above the per-login timeout so a wedged
                    # TDS socket cannot pin a worker indefinitely.
                    timeout=timeout + 15,
                )
            except (asyncio.TimeoutError, TimeoutError):
                return ServiceAccessFinding(
                    service="mssql",
                    host=host,
                    username=username,
                    category="transport",
                    reason="timeout",
                    status="MSSQL login timed out",
                    backend=MSSQL_ACCESS_PROBE_BACKEND,
                )

    findings = list(
        await asyncio.gather(*(_bounded(host) for host in resolved_targets))
    )

    confirmed = sum(1 for finding in findings if finding.is_confirmed)
    for finding in findings:
        if finding.is_confirmed:
            print_info_debug(
                "[mssql_probe] confirmed access: "
                f"host={mark_sensitive(finding.host, 'hostname')} "
                f"sysadmin={finding_is_sysadmin(finding)} "
                f"backend={mark_sensitive(finding.backend, 'detail')}"
            )
    print_info_debug(
        "[mssql_probe] completed native MSSQL access sweep: "
        f"domain={mark_sensitive(domain, 'domain')} "
        f"user={mark_sensitive(username, 'user')} "
        f"targets={len(findings)} confirmed={confirmed}"
    )
    return findings
