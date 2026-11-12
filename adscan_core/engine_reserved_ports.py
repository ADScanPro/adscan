"""Ports the scan engine listens on, and the web platform's ports that must avoid them.

The engine runs with host networking (``docker run --network host`` on Linux),
and so does the Enterprise web stack on the same machine. Two listeners on one
port collide, and whichever binds second fails: when the web console held 443,
a Ligolo pivot fell back to 80 and then collided with the HTTP capture listener,
so a coercion technique failed to start and its absent callback read as "not
vulnerable". This module is the single list of what the engine reserves, so
every service that shares the machine with it can be checked against it.

What counts: every port the engine BINDS, on any address. A loopback-only
listener still conflicts with a wildcard bind on the same port, so loopback
reservations are listed too. Ports the engine only CONNECTS to on a target
(LDAP, Kerberos, a CA's HTTPS enrolment endpoint, NTP for timeroasting) are not
reserved. Packets the IPv6 poisoning path reads by packet capture (DHCPv6
546/547) are not bound and are not listed.

Drift is locked by ``tests/unit/appliance/test_web_stack_listener_policy.py``:
every bind-address literal and listener default in the engine must appear here,
and the web stack's ports (below) must not.

The appliance's inbound host firewall (``adscan-console``, table
``adscan_inbound``) is generated from THIS file at run time: every reserved port
that is not loopback-only is allowed in, from any source, on every interface.
The console reads the three literals below without importing the module
(``ast.literal_eval``), so they must stay plain literals; a test fails if the
console can no longer read them. A port added here reaches the firewall at the
next platform start, with no other change: a missed port would silently turn a
capture technique into a false "not vulnerable".
"""

from __future__ import annotations

#: TCP ports the engine binds, with the listener(s) that use each one.
ENGINE_RESERVED_TCP_PORTS: dict[int, str] = {
    53: "local DNS resolver (Unbound, loopback)",
    80: "HTTP capture/relay listener (WebClient coercion, ESC8 and WPAD relay); Ligolo proxy and HTTP staging fallback",
    443: "Ligolo pivot proxy (default); HTTP staging (default)",
    389: "LDAP relay source (relay runner source ldap, through the listener broker)",
    445: "shared SMB capture listener (coercion callbacks, relay, poisoning, write-share bait); Ligolo pivot redirect",
    636: "LDAPS relay source (relay runner source ldaps, through the listener broker)",
    8443: "HTTP staging unprivileged fallback; Ligolo proxy custom-address default",
    11601: "Ligolo proxy API (loopback)",
    11602: "Ligolo proxy API fallback (loopback)",
    11603: "Ligolo proxy API fallback (loopback)",
    11611: "Ligolo proxy API custom-address default (loopback)",
}

#: UDP ports the engine binds.
ENGINE_RESERVED_UDP_PORTS: dict[int, str] = {
    53: "local DNS resolver (Unbound, loopback); IPv6 poisoning DNS responder",
    137: "NBT-NS poisoning",
    5353: "mDNS poisoning",
    5355: "LLMNR poisoning",
}

#: Reserved TCP ports the engine binds on LOOPBACK only (the local resolver, the
#: Ligolo API). Conflicts are still checked against them, but the appliance
#: firewall does not open them to the network: nothing outside the machine ever
#: connects to them. Every port marked "(loopback" in its description above is
#: listed here and no other (locked by a test), so a new port is opened by
#: default unless it is declared loopback-only.
ENGINE_LOOPBACK_ONLY_TCP_PORTS: tuple[int, ...] = (53, 11601, 11602, 11603, 11611)

#: Network interfaces the engine creates for pivoting (Ligolo TUN devices),
#: as nftables interface-name patterns. A pivot's traffic leaves through one of
#: them toward the network behind the pivot host, whatever its addresses, so
#: the appliance's outbound firewall always lets it out (a pivot that the
#: firewall silently cut would read as "not reachable"). Built by
#: ``pivot_service._build_ligolo_interface_name`` (``lg`` + 10 hex chars);
#: ``ligolo*`` covers an operator-named TUN. Read by the appliance console with
#: ``ast.literal_eval`` like the port lists above; locked by a test.
ENGINE_TUNNEL_INTERFACE_PATTERNS: tuple[str, ...] = ("lg*", "ligolo*")

#: The Enterprise appliance's management port: nginx serves the web console on
#: it over TLS. Not 443 and not 80, which the engine owns (above). Mirrored in
#: adscan_web/docker-compose.appliance.yml, the appliance units and scripts.
APPLIANCE_MANAGEMENT_PORT = 9443

#: The base (non-appliance) compose's default nginx port, plain HTTP. Also off
#: the engine's reserved set, so a dev or self-hosted stack that runs scans on
#: the same host does not take the HTTP capture listener's port.
WEB_DEFAULT_HTTP_PORT = 8080

#: Ports the web stack binds on loopback (docker-compose.yml): backend, frontend,
#: Postgres, Redis. Kept off the engine's set for the same reason.
WEB_LOOPBACK_PORTS: tuple[int, ...] = (8000, 3000, 5432, 6379)


def is_engine_reserved(port: int, protocol: str = "tcp") -> bool:
    """Return True when the scan engine binds ``port`` over ``protocol``."""
    table = ENGINE_RESERVED_UDP_PORTS if protocol.lower() == "udp" else ENGINE_RESERVED_TCP_PORTS
    return int(port) in table


def engine_network_ports(protocol: str = "tcp") -> tuple[int, ...]:
    """The reserved ports a caller OUTSIDE the machine connects to, sorted.

    What the appliance firewall opens: every reserved UDP port, and every
    reserved TCP port that is not loopback-only.
    """
    if protocol.lower() == "udp":
        return tuple(sorted(ENGINE_RESERVED_UDP_PORTS))
    loopback = set(ENGINE_LOOPBACK_ONLY_TCP_PORTS)
    return tuple(sorted(p for p in ENGINE_RESERVED_TCP_PORTS if p not in loopback))
