"""Centralized Kerberos SPN resolution + NTLM-fallback decision.

Single source of truth for one recurring decision: a transport target may be
an IP address, but Kerberos service tickets cannot bind to ``cifs/<ip>`` /
``ldap/<ip>`` — the KDC/server reject it and the client only ever sees a
generic ``invalidCredentials`` / ``SEC_E_LOGON_DENIED`` (see
:mod:`adscan_internal.services._kerberos_spn`).

Before this module the IP→FQDN promotion and the NTLM-fallback decision were
scattered: some call sites wired ``ip_hostname_inventory`` into their config,
some relied on ``__post_init__`` promotion that cannot promote an IP, and the
LSASS-dump path passed the raw IP and let the hard guard abort the whole
operation with no NTLM fallback — even when NTLM-password auth would have
worked (the exact ``khal.drogo → BRAAVOS$`` regression).

This helper fuses the four inputs (target, domain, IP→hostname inventory /
``domains_data``, and the posture snapshot) into one decision so no future
call site has to remember the recipe. The pieces it composes already exist and
are tested individually:

- :func:`adscan_internal.services._kerberos_spn.is_ip_address` /
  :func:`normalize_kerberos_target_hostname`
- :func:`adscan_internal.services.kerberos_tcp_target.resolve_kerberos_tcp_target`
  (inventory → live PTR; returns the IP unchanged when nothing resolves)
- :func:`adscan_internal.services.kerberos_hostname_inventory.choose_hostname_for_kerberos_spn`
- :func:`adscan_internal.models.domain.resolve_dc_fqdn` (DC-specific chain)

Posture gating follows the canonical rule (see ``CLAUDE.md`` § "Posture
caching policy"): only an *observed* ``NTLM_AUTHENTICATION = DISABLED`` at
``HIGH`` confidence blocks the NTLM fallback. ``UNKNOWN`` / ``LOW`` (inferred
by absence, transient timeouts) must NOT block it — the fallback stays allowed.
This module only reads posture; it never emits a signal.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adscan_internal.services._kerberos_spn import (
    is_ip_address,
    normalize_kerberos_target_hostname,
)


@dataclass(frozen=True)
class SpnResolution:
    """Outcome of resolving a (possibly-IP) target for Kerberos vs NTLM.

    Attributes:
        spn_host: The FQDN to use as the Kerberos SPN host, or ``None`` when no
            FQDN could be resolved (target is an IP with no inventory/PTR hit).
        server_ip: The IP to connect to (``serverip=`` / TCP host) when the SPN
            host differs from the connect target; ``None`` otherwise.
        kerberos_viable: ``True`` only when ``spn_host`` is a real FQDN. When
            ``False`` the caller must NOT request Kerberos (it would abort on
            the IP-as-SPN guard).
        ntlm_fallback_ok: ``True`` when posture does not report NTLM disabled at
            HIGH confidence — i.e. NTLM may be used as the fallback. ``False``
            only when NTLM is observed-disabled HIGH (caller should surface a
            clear error instead of silently failing).
        reason: Human-readable explanation for debug output / error surfaces.
    """

    spn_host: str | None
    server_ip: str | None
    kerberos_viable: bool
    ntlm_fallback_ok: bool
    reason: str


def ntlm_disabled_high(posture_snapshot: Any | None) -> bool:
    """Return ``True`` only when posture observed NTLM disabled at HIGH confidence.

    Mirrors the canonical check in
    :func:`adscan_internal.services.auth_plan.build_smb_plan`. Inferred-by-absence
    states (``UNKNOWN`` / ``LOW``) return ``False`` so the NTLM fallback stays
    allowed — a transient probe timeout must never look like a hardening signal.
    """
    if posture_snapshot is None:
        return False
    try:
        from adscan_internal.services.domain_posture import (
            ConstraintCategory,
            SignalConfidence,
            TriState,
        )

        entry = posture_snapshot.get(ConstraintCategory.NTLM_AUTHENTICATION)
        if entry is None:
            return False
        return bool(
            getattr(entry, "effective_state", None) is TriState.DISABLED
            and getattr(entry, "confidence", None) is SignalConfidence.HIGH
        )
    except Exception:  # noqa: BLE001 - posture read is best-effort
        return False


def resolve_spn_or_decide_ntlm(
    *,
    target_host: str | None,
    domain: str | None,
    domains_data: dict | None = None,
    ip_hostname_inventory: dict | None = None,
    resolver_ip: str | None = None,
    dns_server: str | None = None,
    posture_snapshot: Any | None = None,
    is_dc_target: bool = False,
) -> SpnResolution:
    """Resolve the Kerberos SPN host for *target_host*, or decide NTLM fallback.

    Args:
        target_host: The IP or hostname the operation targets.
        domain: The target domain (used to promote short labels and pick the
            domain-suffixed hostname candidate).
        domains_data: Full ``shell.domains_data`` (consulted for a DC target, to
            walk the ``resolve_dc_fqdn`` alias chain, AND — for any IP target — to
            read the split-DC/DNS server via ``resolve_dns_server`` so the live
            PTR that recovers the SPN FQDN queries the AD-zone DNS server, not the
            DC, on a segmented network).
        ip_hostname_inventory: ``{ip: [hostname, …]}`` workspace map (massdns /
            reachability), loaded via ``load_workspace_ip_hostname_inventory``.
        resolver_ip: KDC IP, passed to the TCP-target resolver for the multi-homed
            A-record preference and as the DNS resolver when no ``dns_server`` is
            configured.
        dns_server: Explicit split-DC/DNS AD-zone DNS server (issue #15). When
            ``None`` it is read from ``domains_data[domain]["dns_server"]`` via
            :func:`resolve_dns_server`; still ``None`` -> the DC (``resolver_ip``)
            doubles as the resolver (legacy, byte-identical).
        posture_snapshot: ``get_posture(domains_data, domain=domain)`` result.
        is_dc_target: ``True`` when the target is the domain's DC (enables the
            ``resolve_dc_fqdn`` alias chain in addition to the generic resolver).

    Returns:
        An :class:`SpnResolution`. ``kerberos_viable`` is ``True`` only when a
        real FQDN was resolved; otherwise the caller should use NTLM when
        ``ntlm_fallback_ok`` is ``True`` (and surface an error when not).
    """
    fallback_ok = not ntlm_disabled_high(posture_snapshot)

    # Split-DC/DNS resolver (issue #15): an explicit argument wins; otherwise read
    # the persisted AD-zone DNS server from domains_data. ``None`` when neither is
    # present -> the DC doubles as the DNS resolver (byte-identical to legacy).
    effective_dns_server = str(dns_server or "").strip() or None
    if effective_dns_server is None and isinstance(domains_data, dict) and domain:
        try:
            from adscan_internal.models.domain import resolve_dns_server

            effective_dns_server = resolve_dns_server(domains_data.get(domain) or {})
        except Exception:  # noqa: BLE001 - resolver read is best-effort
            effective_dns_server = None
    cleaned = str(target_host or "").strip().rstrip(".")

    if not cleaned:
        return SpnResolution(
            spn_host=None,
            server_ip=None,
            kerberos_viable=False,
            ntlm_fallback_ok=fallback_ok,
            reason="empty target host",
        )

    # Already a hostname (dotted FQDN or short label we can promote with domain).
    if not is_ip_address(cleaned):
        promoted = normalize_kerberos_target_hostname(cleaned, domain)
        if promoted and not is_ip_address(promoted):
            return SpnResolution(
                spn_host=promoted,
                server_ip=None,
                kerberos_viable=True,
                ntlm_fallback_ok=fallback_ok,
                reason=f"hostname target promoted to {promoted!r}",
            )
        # Short label with no domain → cannot promote safely.
        return SpnResolution(
            spn_host=None,
            server_ip=None,
            kerberos_viable=False,
            ntlm_fallback_ok=fallback_ok,
            reason="short hostname with no domain to promote against",
        )

    # IP target — try to recover an FQDN.
    resolved: str | None = None

    if is_dc_target and isinstance(domains_data, dict) and domain:
        try:
            from adscan_internal.models.domain import resolve_dc_fqdn

            candidate = resolve_dc_fqdn(
                domains_data.get(domain) or {},
                target_domain=domain,
                ip_hostname_inventory=ip_hostname_inventory,
            )
            if candidate and not is_ip_address(candidate):
                resolved = candidate
        except Exception:  # noqa: BLE001 - resolution is best-effort
            resolved = None

    if resolved is None:
        try:
            from adscan_internal.services.kerberos_tcp_target import (
                resolve_kerberos_tcp_target,
            )

            tcp_target = resolve_kerberos_tcp_target(
                target_host=cleaned,
                spn_host=None,
                resolver_ip=resolver_ip or None,
                dns_server=effective_dns_server,
                domain=domain,
                ip_hostname_inventory=ip_hostname_inventory,
            )
            # resolve_kerberos_tcp_target returns the IP unchanged when nothing
            # resolves — only accept it when it produced a real FQDN.
            if tcp_target.spn_host and not is_ip_address(tcp_target.spn_host):
                resolved = tcp_target.spn_host
        except Exception:  # noqa: BLE001 - resolution is best-effort
            resolved = None

    if resolved:
        return SpnResolution(
            spn_host=resolved,
            server_ip=cleaned,
            kerberos_viable=True,
            ntlm_fallback_ok=fallback_ok,
            reason=f"IP {cleaned} resolved to FQDN {resolved!r}",
        )

    return SpnResolution(
        spn_host=None,
        server_ip=cleaned,
        kerberos_viable=False,
        ntlm_fallback_ok=fallback_ok,
        reason=(
            f"IP {cleaned} has no resolvable FQDN; "
            + ("NTLM fallback allowed" if fallback_ok else "NTLM disabled by posture")
        ),
    )
