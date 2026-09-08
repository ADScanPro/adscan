"""Shared configuration and observation types for the MITM6 suite.

The MITM6 suite has three independently composable layers:

* DHCPv6 poisoning — answer Solicit/Request/Renew so clients use us as
  their DNS server (operates at Ethernet/L2 via scapy).
* DNS hijacking — answer A/AAAA queries arriving at our IPv6 socket
  pointing victims at the attacker IP (asyncio UDP server).
* Router Advertisement (RA) — periodically nudge clients into stateful
  IPv6 mode so they ask DHCPv6 in the first place.

Every layer reads the same ``MITM6Config`` and emits structured
observations through a callback so callers can plumb them into ADscan
telemetry or queue-based pipelines without each layer reinventing its
own event surface.
"""

from __future__ import annotations

import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MITM6Config:
    """Configuration shared by all MITM6 layers.

    Only ``interface_name`` is strictly required.  Every other field is
    auto-derived from the interface at start-up if left blank — keeping
    operator ergonomics close to mitm6's CLI defaults.

    Attributes
    ----------
    interface_name:
        Network interface to operate on (e.g. ``eth0``).  Used both as
        scapy's sniff/sendp ``iface`` and as the source of MAC/IPv4/IPv6
        autodetection.
    our_mac, our_ipv4, our_ipv6_linklocal:
        Attacker addresses.  ``None`` triggers autodetection from the
        interface; any explicit value overrides.
    ipv6_prefix:
        IPv6 prefix used to mint per-victim addresses in DHCPv6 Advertise
        replies.  The default mirrors mitm6's ``fe80::100:`` choice.
    local_domain:
        Optional DNS search domain advertised in DHCPv6 Reply (option 24).
        Useful when the lab has multiple AD domains and we want victims
        biased toward one.
    dns_allowlist / dns_blocklist:
        Filters applied to inbound DNS queries.  Allowlist takes priority:
        when non-empty, only matching queries get poisoned.  Blocklist
        suppresses matches.  Both use case-insensitive substring match
        against the FQDN.
    host_allowlist / host_blocklist:
        Same filtering applied to DHCPv6 client FQDN (DHCP6OptClientFQDN).
        Used to scope poisoning to specific machines (e.g. only
        ``braavos.essos.local``) and avoid DCs that ignore DHCPv6 anyway.
    ignore_no_fqdn:
        When ``True``, DHCPv6 packets that lack a ClientFQDN option are
        silently ignored.  Mirrors ``--ignore-nofqdn`` in mitm6.
    send_router_advertisement:
        When ``True``, the suite emits an RA every
        ``router_advertisement_interval_seconds`` to push clients into
        stateful DHCPv6 mode.
    router_advertisement_interval_seconds:
        Cadence for periodic RA emission.  300 s is conservative and avoids
        flooding the network.
    """

    interface_name: str

    our_mac: str | None = None
    our_ipv4: str | None = None
    our_ipv6_linklocal: str | None = None

    ipv6_prefix: str = "fe80::100:"
    local_domain: str | None = None

    dns_allowlist: frozenset[str] = field(default_factory=frozenset)
    dns_blocklist: frozenset[str] = field(default_factory=frozenset)
    host_allowlist: frozenset[str] = field(default_factory=frozenset)
    host_blocklist: frozenset[str] = field(default_factory=frozenset)

    ignore_no_fqdn: bool = False

    send_router_advertisement: bool = True
    router_advertisement_interval_seconds: float = 300.0


# ---------------------------------------------------------------------------
# Observations
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DHCPv6Observation:
    """Emitted when the suite poisons one DHCPv6 exchange."""

    kind: str         # "advertise" | "reply" | "renew_reply"
    victim_mac: str
    victim_fqdn: str
    assigned_ipv6: str


@dataclass(frozen=True)
class DNSObservation:
    """Emitted when the suite spoofs one DNS reply."""

    qname: str
    qtype: str       # "A" | "AAAA"
    victim_ip: str
    answer: str      # the IP we returned


MITM6Callback = (
    Callable[[DHCPv6Observation | DNSObservation], Awaitable[None]] | None
)


# ---------------------------------------------------------------------------
# Filter helpers
# ---------------------------------------------------------------------------

def matches_filter(
    value: str,
    *,
    allowlist: frozenset[str],
    blocklist: frozenset[str],
) -> bool:
    """Apply allowlist/blocklist semantics to ``value``.

    Empty allowlist means "match everything"; non-empty allowlist requires at
    least one substring hit.  Blocklist always suppresses regardless.
    """

    lowered = value.casefold()
    if blocklist and any(token.casefold() in lowered for token in blocklist):
        return False
    if allowlist and not any(token.casefold() in lowered for token in allowlist):
        return False
    return True


def autodetect_interface_addresses(interface_name: str) -> tuple[str, str, str] | None:
    """Return ``(mac, ipv4, ipv6_linklocal)`` for ``interface_name`` or ``None``.

    All three are needed for DHCPv6 to work end-to-end; missing any of them
    is treated as a fatal config error by the suite.
    """

    from adscan_core.pal import net as pal_net

    return pal_net.interface_mac_ipv4_linklocal(interface_name)


def is_ipv6_address(value: str) -> bool:
    """Return whether ``value`` parses as an IPv6 address."""

    try:
        socket.inet_pton(socket.AF_INET6, value)
        return True
    except (OSError, ValueError):
        return False


__all__ = [
    "MITM6Config",
    "DHCPv6Observation",
    "DNSObservation",
    "MITM6Callback",
    "matches_filter",
    "autodetect_interface_addresses",
    "is_ipv6_address",
]
