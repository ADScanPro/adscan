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
"""

from __future__ import annotations

#: TCP ports the engine binds, with the listener(s) that use each one.
ENGINE_RESERVED_TCP_PORTS: dict[int, str] = {
    53: "local DNS resolver (Unbound, loopback)",
    80: "HTTP capture/relay listener (WebClient coercion, ESC8 and WPAD relay); Ligolo proxy and HTTP staging fallback",
    443: "Ligolo pivot proxy (default); HTTP staging (default)",
    445: "shared SMB capture listener (coercion callbacks, relay, poisoning, write-share bait); Ligolo pivot redirect",
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
