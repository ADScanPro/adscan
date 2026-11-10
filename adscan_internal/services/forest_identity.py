"""Resolve which Active Directory forest a domain belongs to, before authenticating.

The licence counts environments, and one environment is one forest identified
by its forest root domain GUID (``adscan_core.environment_ledger``). That GUID
is returned anonymously by the CLDAP netlogon ping ("LDAP ping", MS-ADTS
6.3.3): one UDP datagram to port 389 asking for the ``Netlogon`` attribute of
the rootDSE with a ``(&(DnsDomain=<domain>)(NtVer=<flags>))`` filter. Every
Windows client sends exactly this to locate a DC, so it cannot be disabled
without breaking the domain, it needs no credential, and it is the same
request a domain-joined workstation makes at logon (no assessment noise).

The reply (``NETLOGON_SAM_LOGON_RESPONSE_EX``, MS-ADTS 6.3.1.9) carries the
answering DC's ``DomainGuid``, ``DnsForestName`` and ``DnsDomainName``. When the
answering domain IS the forest root, its GUID is the root GUID. When it is a
child, a DC of the forest root is located through DNS (the PDC SRV record,
through the resolver ADscan already uses) and pinged the same way. When the
root cannot be reached the identity is provisional (forest name + child GUID),
and when nothing answers it is name-only; both still count, so an unreachable
forest never reads as free.

Transport: the asysocks UDP endpoint (the same one the timeroasting runner
uses) and the badldap ASN.1 message types for encoding. Both are the vendored
native stack; no raw socket. Latency budget: one round trip per attempt, three
seconds each, two attempts (UDP may drop a datagram over a VPN).
"""

from __future__ import annotations

import asyncio
import contextlib
import struct
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from adscan_core.environment_ledger import (
    SOURCE_CLDAP_CHILD,
    SOURCE_CLDAP_ROOT,
    SOURCE_NAME_ONLY,
    ForestIdentity,
)

CLDAP_PORT = 389
#: NETLOGON_NT_VERSION_5 | NETLOGON_NT_VERSION_5EX: ask for the EX reply.
_NT_VERSION_5EX = 0x00000006
_OPCODES_EX = frozenset({23, 25})  # LOGON_SAM_LOGON_RESPONSE_EX / USER_UNKNOWN_EX
_ATTEMPT_TIMEOUT_SECONDS = 3.0
_ATTEMPTS = 2


@dataclass(frozen=True)
class NetlogonReply:
    """The parts of a netlogon EX reply the licence needs."""

    domain_guid: str
    dns_forest_name: str
    dns_domain_name: str
    dns_host_name: str
    netbios_domain_name: str

    @property
    def is_forest_root(self) -> bool:
        return (
            bool(self.dns_forest_name)
            and self.dns_forest_name.lower() == self.dns_domain_name.lower()
        )


# ── Encoding / decoding (pure, unit-tested on bytes) ────────────────────────


def build_ldap_ping(domain: str, *, message_id: int = 1) -> bytes:
    """Encode the CLDAP netlogon request for ``domain``."""
    from badldap.protocol.messages import (  # vendored native stack
        AttributeSelection,
        Filter,
        LDAPMessage,
        SearchRequest,
        protocolOp,
    )

    def _eq(name: str, value: bytes) -> Filter:
        return Filter(
            {"equalityMatch": {"attributeDesc": name.encode("ascii"), "assertionValue": value}}
        )

    clauses = []
    normalized = str(domain or "").strip().rstrip(".")
    if normalized:
        clauses.append(_eq("DnsDomain", normalized.encode("utf-8")))
    clauses.append(_eq("NtVer", struct.pack("<I", _NT_VERSION_5EX)))
    request = SearchRequest(
        {
            "baseObject": b"",
            "scope": 0,  # baseObject
            "derefAliases": 0,
            "sizeLimit": 0,
            "timeLimit": 0,
            "typesOnly": False,
            "filter": Filter({"and": clauses}),
            "attributes": AttributeSelection([b"Netlogon"]),
        }
    )
    message = LDAPMessage(
        {"messageID": message_id, "protocolOp": protocolOp({"searchRequest": request})}
    )
    return message.dump()


def _read_compressed_name(buf: bytes, pos: int) -> tuple[str, int]:
    """Read one RFC 1035 compressed name; return it and the position after it."""
    labels: list[str] = []
    end: int | None = None
    hops = 0
    while True:
        if pos >= len(buf):
            raise ValueError("name runs past the buffer")
        length = buf[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(buf):
                raise ValueError("truncated name pointer")
            pointer = ((length & 0x3F) << 8) | buf[pos + 1]
            if end is None:
                end = pos + 2
            hops += 1
            if hops > 32 or pointer >= len(buf):
                raise ValueError("bad name pointer")
            pos = pointer
            continue
        pos += 1
        labels.append(buf[pos : pos + length].decode("utf-8", errors="replace"))
        pos += length
    return ".".join(labels), (end if end is not None else pos)


def parse_netlogon_ex(blob: bytes) -> NetlogonReply:
    """Decode a ``NETLOGON_SAM_LOGON_RESPONSE_EX`` structure.

    Raises:
        ValueError: not an EX reply, or truncated.
    """
    if len(blob) < 24:
        raise ValueError("netlogon reply too short")
    opcode = struct.unpack_from("<H", blob, 0)[0]
    if opcode not in _OPCODES_EX:
        raise ValueError(f"unexpected netlogon opcode {opcode}")
    domain_guid = str(uuid.UUID(bytes_le=bytes(blob[8:24])))
    pos = 24
    names: list[str] = []
    for _ in range(5):  # forest, domain, host, netbios domain, netbios computer
        name, pos = _read_compressed_name(blob, pos)
        names.append(name)
    return NetlogonReply(
        domain_guid=domain_guid,
        dns_forest_name=names[0],
        dns_domain_name=names[1],
        dns_host_name=names[2],
        netbios_domain_name=names[3],
    )


def parse_ldap_ping_response(datagram: bytes) -> NetlogonReply | None:
    """Extract the netlogon reply from a CLDAP response datagram."""
    from badldap.protocol.messages import LDAPMessage

    data = bytes(datagram or b"")
    while data:
        try:
            message = LDAPMessage.load(data, strict=False)
            consumed = len(message.dump())
        except Exception:  # noqa: BLE001 - malformed datagram: no answer
            return None
        op = message["protocolOp"]
        if op.name == "searchResEntry":
            for attribute in op.chosen["attributes"]:
                if bytes(attribute["type"].native or b"").lower() != b"netlogon":
                    continue
                for value in attribute["attributes"]:
                    raw = value.native
                    if isinstance(raw, str):
                        raw = raw.encode("latin-1")
                    try:
                        return parse_netlogon_ex(bytes(raw))
                    except ValueError:
                        return None
        if consumed <= 0:
            break
        data = data[consumed:]
    return None


# ── Network ──────────────────────────────────────────────────────────────────


async def ldap_ping(
    dc_ip: str,
    domain: str,
    *,
    timeout: float = _ATTEMPT_TIMEOUT_SECONDS,
    attempts: int = _ATTEMPTS,
) -> NetlogonReply | None:
    """Send the CLDAP netlogon ping to ``dc_ip``; None when nothing answers.

    Never raises: a refused port, an ICMP unreachable or a timeout are all
    "no answer" (an observation about our reach, never a verdict about the DC).
    """
    from asysocks.unicomm.client import UniClient
    from asysocks.unicomm.common.target import UniProto, UniTarget

    target = UniTarget(ip=dc_ip, port=CLDAP_PORT, protocol=UniProto.CLIENT_UDP, timeout=int(timeout) or 1)
    for attempt in range(max(1, attempts)):
        endpoint = None
        try:
            endpoint = await UniClient(target, None).connect()
            endpoint.send(build_ldap_ping(domain, message_id=attempt + 1), (dc_ip, CLDAP_PORT))
            datagram = await asyncio.wait_for(endpoint.read_one(), timeout=timeout)
        except (asyncio.TimeoutError, OSError, ValueError):
            datagram = None
        except Exception:  # noqa: BLE001 - transport quirks must not break a launch
            datagram = None
        finally:
            if endpoint is not None:
                with contextlib.suppress(Exception):
                    endpoint.close()
        if datagram:
            reply = parse_ldap_ping_response(datagram)
            if reply is not None:
                return reply
    return None


RootDcLocator = Callable[[str, str], Awaitable[str | None]]
Pinger = Callable[[str, str], Awaitable[NetlogonReply | None]]


async def resolve_forest_identity(
    domain: str,
    dc_ip: str | None,
    *,
    locate_root_dc: RootDcLocator | None = None,
    pinger: Pinger | None = None,
    root_sid: str | None = None,
) -> ForestIdentity:
    """Establish the forest identity of ``domain`` as well as the network allows.

    Args:
        domain: DNS name of the domain about to be assessed.
        dc_ip: A DC of that domain (the operator-given or discovered PDC).
        locate_root_dc: ``(forest_dns_name, resolver_ip) -> dc ip`` used when
            the answering domain is a child. None skips the root lookup.
        pinger: Override the network ping (tests).
        root_sid: Forest root SID when an authenticated phase already knows it.

    Returns:
        Always an identity: confirmed (root GUID), provisional (child GUID) or
        name-only. Never raises.
    """
    ping = pinger or ldap_ping
    normalized = str(domain or "").strip().rstrip(".").lower()
    reply: NetlogonReply | None = None
    if dc_ip:
        with contextlib.suppress(Exception):
            reply = await ping(dc_ip, normalized)
    if reply is None:
        return ForestIdentity(
            forest_dns_name=normalized,
            domain_dns_name=normalized,
            root_sid=root_sid,
            source=SOURCE_NAME_ONLY,
        )
    forest = (reply.dns_forest_name or normalized).lower()
    if reply.is_forest_root:
        return ForestIdentity(
            forest_dns_name=forest,
            domain_dns_name=reply.dns_domain_name or normalized,
            root_domain_guid=reply.domain_guid,
            domain_guid=reply.domain_guid,
            root_sid=root_sid,
            source=SOURCE_CLDAP_ROOT,
        )
    root_guid: str | None = None
    if locate_root_dc is not None and dc_ip:
        root_dc: str | None = None
        with contextlib.suppress(Exception):
            root_dc = await locate_root_dc(forest, dc_ip)
        if root_dc:
            root_reply: NetlogonReply | None = None
            with contextlib.suppress(Exception):
                root_reply = await ping(root_dc, forest)
            if root_reply is not None and root_reply.is_forest_root:
                root_guid = root_reply.domain_guid
    return ForestIdentity(
        forest_dns_name=forest,
        domain_dns_name=reply.dns_domain_name or normalized,
        root_domain_guid=root_guid,
        domain_guid=reply.domain_guid,
        root_sid=root_sid,
        source=SOURCE_CLDAP_ROOT if root_guid else SOURCE_CLDAP_CHILD,
    )


__all__ = [
    "CLDAP_PORT",
    "NetlogonReply",
    "build_ldap_ping",
    "ldap_ping",
    "parse_ldap_ping_response",
    "parse_netlogon_ex",
    "resolve_forest_identity",
]
