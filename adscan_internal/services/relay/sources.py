"""Native relay source adapters built on the async stack."""

from __future__ import annotations

import asyncio
import builtins
import logging
import sys
import traceback
from dataclasses import dataclass

from adscan_internal.rich_output import print_info_debug
from adscan_internal.services.native_log_taming import is_benign_native_noise
from adscan_internal.services.listener_broker import (
    ClaimHandle,
    ClaimRole,
    StreamHandler,
    acquire_listener,
)
from adscan_internal.services.relay.core import RelayAuthentication
from adscan_internal.services.relay.identity import extract_ntlm_identity

# Markers that are only safe to drop inside the relay listener flow — too
# broad to apply to the global tamer (e.g. ACCESS_DENIED can be a real
# finding elsewhere; TimeoutError can mask actionable failures).
_RELAY_EXTRA_NOISE_MARKERS: tuple[str, ...] = (
    "TimeoutError",
    "[DEBUG][NEGTOKEN_LOAD_ERROR]",
    "reply.command.Buffer:",
    "to_continue:",
    "NTStatus.ACCESS_DENIED",
)

_smb_relay_noise_filter_installed = False


def _is_benign_smb_relay_noise(message: str) -> bool:
    """Return whether a third-party SMB relay message is expected listener noise."""

    return is_benign_native_noise(message, extra_markers=_RELAY_EXTRA_NOISE_MARKERS)


class _RelayTracebackShim:
    """Module-local traceback shim for noisy third-party relay listener paths.

    Called synchronously by aiosmb internals (monkey-patched module attribute),
    so must not call asyncio.create_task — no event loop is guaranteed at the call site.
    """

    def print_exc(self, *args: object, **kwargs: object) -> None:
        exc_type, exc_value, exc_tb = sys.exc_info()
        rendered = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        if _is_benign_smb_relay_noise(rendered):
            print_info_debug(
                f"[relay-shim] suppressed benign SMB exception: {exc_value}"
            )
            return
        traceback.print_exc(*args, **kwargs)


class _BenignRelayLogFilter(logging.Filter):
    """Drop known benign relay listener records emitted by third-party libraries."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        if record.exc_info:
            exc_type, exc_value, exc_tb = record.exc_info
            message = f"{message}\n{''.join(traceback.format_exception(exc_type, exc_value, exc_tb))}"
        return not _is_benign_smb_relay_noise(message)


def _build_relay_print_shim() -> object:
    """Create a print-compatible shim for known third-party relay debug messages.

    Called synchronously by aiosmb internals — must not use asyncio.create_task.
    """

    def _relay_print(
        *values: object,
        sep: str = " ",
        end: str = "\n",
        file: object | None = None,
        flush: bool = False,
    ) -> None:
        message = sep.join(str(value) for value in values)
        if _is_benign_smb_relay_noise(message):
            print_info_debug(
                f"[relay-shim] suppressed benign SMB message: {message[:120]}"
            )
            return
        builtins.print(*values, sep=sep, end=end, file=file, flush=flush)

    return _relay_print


def _install_known_smb_relay_noise_filter() -> None:
    """Install process-local filters for known benign SMB relay listener noise."""

    global _smb_relay_noise_filter_installed
    if _smb_relay_noise_filter_installed:
        return

    from aiosmb import logger as aiosmb_logger
    from aiosmb import connection as smb_connection
    from aiosmb.relay import serverconnection as smb_serverconnection
    from badauth.protocols.spnego.relay import native as spnego_native

    relay_log_filter = _BenignRelayLogFilter()
    aiosmb_logger.addFilter(relay_log_filter)
    for handler in aiosmb_logger.handlers:
        handler.addFilter(relay_log_filter)
    for handler in logging.getLogger().handlers:
        handler.addFilter(relay_log_filter)

    _shim = _RelayTracebackShim()
    _print_shim = _build_relay_print_shim()
    smb_connection.traceback = _shim
    smb_serverconnection.traceback = _shim
    smb_serverconnection.print = _print_shim
    spnego_native.print = _print_shim
    _smb_relay_noise_filter_installed = True


@dataclass(frozen=True)
class RelaySourceConfig:
    """Listener configuration for native relay sources.

    ``expected_sources`` names the host(s) the relay is waiting for: the coerced
    target, as an IP and/or a name. The listener broker routes their connections
    to the relay and every other connection to the capture, so a relay and the
    background capture share the port. Empty means "any caller" (the mitm6 WPAD
    relay, whose victims are not known in advance).
    """

    listen_host: str = "0.0.0.0"
    listen_port: int = 445
    protocol: str = "smb"
    expected_sources: tuple[str, ...] = ()


class NativeRelaySource:
    """Base class for relay listeners that publish ADscan auth events.

    A source never binds. ``start`` opens its server in handoff mode and claims
    the port from the listener broker (``services/listener_broker.py``), which
    hands it the connections from the expected sources; ``stop`` releases the
    claim and stops the server.
    """

    protocol: str

    def __init__(
        self,
        *,
        config: RelaySourceConfig,
        auth_queue: asyncio.Queue[RelayAuthentication],
    ) -> None:
        self.config = config
        self.auth_queue = auth_queue
        self._relay_queue: asyncio.Queue[object] = asyncio.Queue()
        self._bridge_task: asyncio.Task[None] | None = None
        self._server_task: asyncio.Task[object] | None = None
        self._claim: ClaimHandle | None = None

    @property
    def consumer_id(self) -> str:
        return f"relay:{self.protocol}:{id(self):x}"

    async def start(self) -> None:
        """Open the server, then claim the port; raise when it cannot be served.

        Raises:
            RelayListenerUnavailableError: the broker could not serve the port
                (another process holds it, or the privileged port was refused).
                Nothing is left running; the runner converts it into a failed
                result.
        """

        handler, server_task = await self._open_server()
        self._server_task = server_task
        self._bridge_task = asyncio.create_task(self._bridge_relay_contexts())
        expected = tuple(item for item in self.config.expected_sources if item)
        try:
            self._claim = await acquire_listener(
                port=self.config.listen_port,
                consumer_id=self.consumer_id,
                handler=handler,
                role=ClaimRole.TARGETED if expected else ClaimRole.UNTARGETED,
                expected_sources=expected,
                local_address=self.config.listen_host,
            )
        except BaseException:
            await self.stop()
            raise

    async def stop(self) -> None:
        """Release the port claim and stop listener tasks (best-effort; never raises)."""

        claim, self._claim = self._claim, None
        if claim is not None:
            try:
                await claim.arelease()
            except Exception as exc:  # noqa: BLE001 - teardown must not raise
                print_info_debug(f"relay-teardown claim release failed: {exc}")
        for task in (self._server_task, self._bridge_task):
            if task is not None:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                except Exception as exc:  # noqa: BLE001
                    print_info_debug(
                        f"relay-teardown listener task ended with error: {exc}"
                    )
        self._server_task = None
        self._bridge_task = None

    async def _open_server(self) -> tuple[StreamHandler, "asyncio.Task[object] | None"]:
        """Build the protocol server in handoff mode; return its stream handler."""
        raise NotImplementedError

    async def _bridge_relay_contexts(self) -> None:
        while True:
            gssapi = await self._relay_queue.get()
            domain, username = extract_ntlm_identity(gssapi)
            await self.auth_queue.put(
                RelayAuthentication(
                    gssapi=gssapi,
                    source_protocol=self.protocol,
                    username=username,
                    domain=domain,
                )
            )


class SMBRelaySource(NativeRelaySource):
    """SMB listener backed by ``aiosmb.relay``."""

    protocol = "smb"

    async def start(self) -> None:
        """Start the SMB relay listener with third-party benign-noise filtering."""

        _install_known_smb_relay_noise_filter()
        await super().start()

    async def _open_server(self) -> tuple[StreamHandler, "asyncio.Task[object] | None"]:
        from badauth.protocols.ntlm.relay.native import (
            NTLMRelaySettings,
            ntlmrelay_factory,
        )
        from badauth.protocols.spnego.relay.native import spnegorelay_ntlm_factory
        from asysocks.unicomm.common.target import UniProto, UniTarget
        from aiosmb.protocol.smb2.commands.negotiate import NegotiateDialects
        from aiosmb.relay.server import SMBRelayServer, SMBServerSettings
        from aiosmb.wintypes.dtyp.constrcuted_security.guid import GUID

        target = UniTarget(
            self.config.listen_host, self.config.listen_port, UniProto.SERVER_TCP
        )
        from adscan_internal.services.native_log_taming import make_relay_log_callback  # noqa: PLC0415
        settings = SMBServerSettings(  # pylint: disable=unexpected-keyword-arg
            lambda: spnegorelay_ntlm_factory(
                self._relay_queue,
                lambda: ntlmrelay_factory(lambda: NTLMRelaySettings()),
            ),
            log_callback=make_relay_log_callback("smb-relay"),
        )
        settings.preferred_dialects = [NegotiateDialects.SMB202]
        settings.ServerGuid = GUID.random()
        settings.RequireSigning = False
        settings.shares = {}
        server = SMBRelayServer(target, settings, handoff=True)
        task, err = await server.run()
        if err is not None:
            raise err
        return server.handle_stream, task


class LDAPRelaySource(NativeRelaySource):
    """LDAP/LDAPS listener backed by ``badldap.relay``."""

    protocol = "ldap"

    async def _open_server(self) -> tuple[StreamHandler, "asyncio.Task[object] | None"]:
        from badauth.protocols.ntlm.relay.native import ntlmrelay_factory
        from badauth.protocols.spnego.relay.native import spnegorelay_ntlm_factory
        from asysocks.unicomm.common.target import UniProto, UniTarget
        from badldap.relay.server import LDAPRelayServer, LDAPServerSettings

        proto = (
            UniProto.SERVER_SSL_TCP
            if self.config.protocol.lower() == "ldaps"
            else UniProto.SERVER_TCP
        )
        target = UniTarget(self.config.listen_host, self.config.listen_port, proto)
        from adscan_internal.services.native_log_taming import make_relay_log_callback  # noqa: PLC0415
        settings = LDAPServerSettings(  # pylint: disable=unexpected-keyword-arg
            lambda: spnegorelay_ntlm_factory(
                self._relay_queue, lambda: ntlmrelay_factory()
            ),
            log_callback=make_relay_log_callback("ldap-relay"),
        )
        server = LDAPRelayServer(target, settings, handoff=True)
        task = await server.run()
        return server.handle_stream, task
