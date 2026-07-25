"""Resolve TCP and SPN targets for Kerberos-backed service connections.

Kerberos service clients often need two different host values:

* the SPN hostname, for example ``cifs/braavos.essos.local``;
* the TCP address, ideally an IP when container/system DNS is unreliable.

This module keeps that split explicit so native SMB/RPC callers do not depend
on a perfectly configured ``/etc/resolv.conf``. ADscan normally configures
Unbound, but lab runners and customer containers can still have broken system
DNS. In those cases we can query the DC/KDC directly for A/PTR records.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from typing import Iterable, Mapping

from adscan_internal import telemetry
from adscan_internal.rich_output import mark_sensitive, print_info_debug
from adscan_core.rich_output import print_exception


@dataclass(frozen=True)
class KerberosTcpTarget:
    """Resolved target values for Kerberos-over-TCP protocols."""

    spn_host: str
    tcp_host: str
    server_ip: str | None = None


def is_ip_address(value: str) -> bool:
    """Return True when *value* is an IP address."""
    try:
        ipaddress.ip_address(str(value or "").strip())
        return True
    except ValueError:
        return False


def _query_a_records(fqdn: str, resolver_ip: str | None, timeout_s: float) -> list[str]:
    """Resolve ALL A records (in resolution order), optionally via a resolver.

    Returns the full ordered, de-duplicated list of IPv4 addresses the host
    resolves to. Callers that only need one address use :func:`_query_a_record`;
    callers that must choose among multiple A records (e.g. a multi-homed host
    that advertises both an internal and a routable address) use this.
    """
    hostname = str(fqdn or "").strip().rstrip(".")
    if not hostname:
        return []

    # Try /etc/hosts + system resolver via socket first — this respects the
    # /etc/hosts entries added by ADscan's host-helper (e.g. babydc.baby.vl).
    # dns.resolver with configure=True reads resolv.conf nameservers which may
    # fail or be misconfigured; socket.getaddrinfo uses the full NSS stack.
    if not resolver_ip:
        import socket as _socket

        def _try_socket(name: str) -> list[str]:
            ips: list[str] = []
            try:
                results = _socket.getaddrinfo(name, None, _socket.AF_INET)
                for _fam, _typ, _pro, _cn, sockaddr in results:
                    c = sockaddr[0]
                    if c and is_ip_address(c) and c not in ips:
                        ips.append(c)
            except _socket.gaierror:
                pass
            except Exception:  # noqa: BLE001
                pass
            return ips

        # Try the hostname as given first.
        found = _try_socket(hostname)
        if found:
            return found

        # If the hostname is a short label (no dots), also try with the search
        # domain from /etc/resolv.conf — short hostnames like 'babydc' may not
        # resolve via NSS but 'babydc.baby.vl' will if it's in /etc/hosts.
        if "." not in hostname:
            try:
                with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as _rf:
                    for _line in _rf:
                        _l = _line.strip()
                        if _l.startswith("search ") or _l.startswith("domain "):
                            for _domain in _l.split()[1:]:
                                found = _try_socket(f"{hostname}.{_domain}")
                                if found:
                                    return found
            except Exception:  # noqa: BLE001
                pass
        return found

    found: list[str] = []
    try:
        import dns.exception
        import dns.resolver

        # dns.resolver.Resolver(configure=True) reads /etc/resolv.conf.
        # If resolv.conf contains a hostname as a nameserver entry (e.g.
        # "nameserver babydc.baby.vl" instead of an IP), dnspython 2.x raises
        # a ValueError/TypeError during Resolver.__init__. Log the resolv.conf
        # state to help diagnose this when it occurs, then fall through cleanly.
        try:
            resolver = dns.resolver.Resolver(configure=not bool(resolver_ip))
        except Exception:  # noqa: BLE001
            _log_resolv_conf_state(hostname)
            raise

        if resolver_ip:
            resolver.nameservers = [resolver_ip]
        resolver.timeout = timeout_s
        resolver.lifetime = timeout_s
        answers = resolver.resolve(hostname, "A")
        for answer in answers:
            candidate = str(answer).strip()
            if candidate and is_ip_address(candidate) and candidate not in found:
                found.append(candidate)
    except dns.exception.DNSException as exc:
        print_info_debug(
            f"[kerberos-target] A lookup failed for {mark_sensitive(hostname, 'hostname')}: {exc}"
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            f"[kerberos-target] unexpected A lookup error for {mark_sensitive(hostname, 'hostname')}: {exc}"
        )
    return found


def _query_a_record(fqdn: str, resolver_ip: str | None, timeout_s: float) -> str | None:
    """Resolve a single A record (first in resolution order)."""
    records = _query_a_records(fqdn, resolver_ip, timeout_s)
    return records[0] if records else None


def _log_resolv_conf_state(context: str) -> None:
    """Dump /etc/resolv.conf nameserver lines to DEBUG when DNS init fails.

    Called only when dns.resolver.Resolver(configure=True) raises — the most
    common cause is a hostname (not an IP) in /etc/resolv.conf, which dnspython
    2.x rejects. Logging the nameserver lines makes post-mortem diagnosis fast.
    """
    try:
        lines: list[str] = []
        with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped.startswith("nameserver") or stripped.startswith("search"):
                    lines.append(stripped)
        print_info_debug(
            f"[kerberos-target] resolv.conf state (context={context!r}): "
            + ("; ".join(lines) if lines else "<empty or no nameserver/search lines>")
        )
    except Exception:  # noqa: BLE001
        pass


def _query_ptr_record(ip: str, resolver_ip: str | None, timeout_s: float) -> str | None:
    """Resolve a PTR record, optionally querying a specific resolver directly."""
    ip_clean = str(ip or "").strip()
    if not is_ip_address(ip_clean):
        return None

    try:
        import dns.exception
        import dns.reversename
        import dns.resolver

        resolver = dns.resolver.Resolver(configure=not bool(resolver_ip))
        if resolver_ip:
            resolver.nameservers = [resolver_ip]
        resolver.timeout = timeout_s
        resolver.lifetime = timeout_s
        reverse_name = dns.reversename.from_address(ip_clean)
        answers = resolver.resolve(reverse_name, "PTR")
        for answer in answers:
            candidate = str(answer).strip().rstrip(".")
            if candidate and not is_ip_address(candidate):
                return candidate
    except dns.exception.DNSException as exc:
        print_info_debug(
            f"[kerberos-target] PTR lookup failed for {mark_sensitive(ip_clean, 'ip')}: {exc}"
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            f"[kerberos-target] unexpected PTR lookup error for {mark_sensitive(ip_clean, 'ip')}: {exc}"
        )
    return None


def resolve_kerberos_tcp_target(
    *,
    target_host: str,
    spn_host: str | None = None,
    resolver_ip: str | None = None,
    domain: str | None = None,
    ip_hostname_inventory: Mapping[str, Iterable[str] | str] | None = None,
    timeout_s: float = 2.0,
) -> KerberosTcpTarget:
    """Resolve SPN and TCP hosts for Kerberos-backed TCP connections.

    Args:
        target_host: Operator/discovery target, either IP or hostname.
        spn_host: Explicit SPN hostname when known from LDAP/workspace data.
        resolver_ip: DC/KDC resolver to query directly when system DNS is not enough.
        domain: Target DNS domain, used to promote short inventory hostnames.
        ip_hostname_inventory: Optional persisted IP → hostname candidates from
            MassDNS/reachability inventory. Checked before live PTR lookups.
        timeout_s: Per-query DNS timeout.

    Returns:
        ``KerberosTcpTarget``. ``spn_host`` is the URL/SPN host. ``tcp_host`` is
        the address to pass to transports that open a socket directly.
        ``server_ip`` should be appended to aiosmb URLs as ``serverip=...`` when
        it differs from ``spn_host``.
    """
    target_clean = str(target_host or "").strip().rstrip(".")
    explicit_spn = str(spn_host or "").strip().rstrip(".")
    resolver_clean = str(resolver_ip or "").strip() or None

    if not target_clean:
        return KerberosTcpTarget(spn_host="", tcp_host="", server_ip=None)

    if is_ip_address(target_clean):
        resolved_spn = explicit_spn
        if not resolved_spn:
            from adscan_internal.services.kerberos_hostname_inventory import (
                choose_hostname_for_kerberos_spn,
            )

            resolved_spn = choose_hostname_for_kerberos_spn(
                ip=target_clean,
                domain=domain,
                inventory=ip_hostname_inventory,
            )
        if not resolved_spn:
            resolved_spn = _query_ptr_record(target_clean, resolver_clean, timeout_s)
        spn_value = resolved_spn or target_clean
        return KerberosTcpTarget(
            spn_host=spn_value,
            tcp_host=target_clean,
            server_ip=target_clean if spn_value != target_clean else None,
        )

    resolved_ips = _query_a_records(target_clean, resolver_clean, timeout_s)
    # Prefer the resolver IP when the target resolves to it among several A
    # records. ``resolver_clean`` is the reachability-selected DC/KDC IP we are
    # already successfully talking to, so for a multi-homed host (e.g. an
    # Enterprise CA co-located on a DC that advertises both an internal and a
    # routable address) it is the reachable one. The bare first A record may be
    # an internal, non-routable IP that times out on connect — observed live:
    # ADCS ESC enrollment to dc1.<realm> resolved to the internal 192.168.x A
    # record and timed out on EPM/135, while the routable KDC IP (already
    # selected for Kerberos) was reachable on every port.
    if resolver_clean and resolver_clean in resolved_ips:
        resolved_ip: str | None = resolver_clean
    else:
        resolved_ip = resolved_ips[0] if resolved_ips else None
    spn_value = explicit_spn or target_clean
    return KerberosTcpTarget(
        spn_host=spn_value,
        tcp_host=resolved_ip or target_clean,
        server_ip=resolved_ip if resolved_ip and resolved_ip != spn_value else None,
    )
