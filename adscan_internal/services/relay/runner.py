"""High-level native relay runner."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Literal

from adscan_internal.services.relay.core import (
    RelayEngine,
    RelayListenerUnavailableError,
    RelayRunConfig,
    RelayRunResult,
    RelayTarget,
    report_relay_listener_unavailable,
)
from adscan_internal.services.relay.http_ntlm_source import (
    HTTPNtlmRelaySource,
    HTTPNtlmRelaySourceConfig,
)
from adscan_internal.services.relay.sources import (
    LDAPRelaySource,
    NativeRelaySource,
    RelaySourceConfig,
    SMBRelaySource,
)

logger = logging.getLogger("adscan")

RelaySourceKind = Literal["smb", "ldap", "ldaps", "http-ntlm"]


@dataclass(frozen=True)
class NativeRelayRunConfig:
    """Runtime configuration for the native relay engine."""

    source: RelaySourceKind = "smb"
    listen_host: str = "0.0.0.0"
    listen_port: int | None = None
    max_authentications: int = 1
    timeout_seconds: float = 120.0
    stop_on_first_success: bool = True
    #: The coerced host(s) the relay waits for (IP and/or name). The listener
    #: broker routes their connections to the relay and every other caller to
    #: the background capture. Empty means any caller.
    expected_sources: tuple[str, ...] = ()


async def run_native_relay(
    *,
    targets: list[RelayTarget],
    config: NativeRelayRunConfig | None = None,
    success_event: asyncio.Event | None = None,
    listener_ready: asyncio.Event | None = None,
) -> RelayRunResult:
    """Start a native relay listener and dispatch captured auth to targets.

    ``success_event`` (optional) is set by the engine the instant a target
    succeeds, so a concurrent coercion loop can stop firing immediately.

    ``listener_ready`` (optional) is set once the listener is up, so a
    coordinating coercion fires only at a live listener. It is never set when
    the listener could not start: the run then returns a failed result straight
    away.

    The listener never binds the port itself: it claims it from the listener
    broker, which routes the expected sources' connections here while the
    background capture (poisoning, the write-share bait) keeps every other
    caller. Capture and relay run at the same time on one port.
    """

    effective = config or NativeRelayRunConfig()
    auth_queue = asyncio.Queue()
    source = _build_source(effective, auth_queue)
    engine = RelayEngine(
        auth_queue=auth_queue,
        targets=targets,
        config=RelayRunConfig(
            max_authentications=effective.max_authentications,
            timeout_seconds=effective.timeout_seconds,
            stop_on_first_success=effective.stop_on_first_success,
            success_event=success_event,
        ),
    )

    from adscan_core.rich_output import print_info_debug  # noqa: PLC0415

    try:
        await source.start()
    except RelayListenerUnavailableError as exc:
        # The listen port could not be served (another local process holds it,
        # or the privileged port was refused). A known limit of the scanning
        # host, never a defensive-control claim (Exposure-Validation doctrine):
        # one operator line, the traceback to the debug log only, and a failed
        # result the caller classifies.
        report_relay_listener_unavailable(exc, technique="relay")
        return RelayRunResult(
            results=(),
            timed_out=False,
            authentications_seen=0,
            listener_error=exc.reason_summary,
        )

    if listener_ready is not None:
        listener_ready.set()
    try:
        return await engine.run()
    finally:
        # Teardown trace: a freeze observed after a successful relay was traced
        # to this listener shutdown blocking on stray half-open coerced
        # connections. These markers pinpoint whether a hang is in
        # source.stop() vs downstream.
        print_info_debug("relay-teardown run_native_relay finally: stopping relay source listener")
        await source.stop()
        print_info_debug("relay-teardown relay source listener stopped cleanly")


def _build_source(
    config: NativeRelayRunConfig, auth_queue: asyncio.Queue
) -> NativeRelaySource:
    port = config.listen_port
    if port is None:
        port = _default_port(config.source)
    source_config = RelaySourceConfig(
        listen_host=config.listen_host,
        listen_port=port,
        protocol=config.source,
        expected_sources=tuple(config.expected_sources),
    )
    if config.source == "smb":
        return SMBRelaySource(config=source_config, auth_queue=auth_queue)
    if config.source in {"ldap", "ldaps"}:
        return LDAPRelaySource(config=source_config, auth_queue=auth_queue)
    if config.source == "http-ntlm":
        http_config = HTTPNtlmRelaySourceConfig(
            listen_host=config.listen_host,
            listen_port=port,
            expected_sources=tuple(config.expected_sources),
        )
        return HTTPNtlmRelaySource(config=http_config, auth_queue=auth_queue)
    raise ValueError(f"Unsupported relay source: {config.source}")


def _default_port(source: RelaySourceKind) -> int:
    if source == "smb":
        return 445
    if source == "ldap":
        return 389
    if source == "ldaps":
        return 636
    if source == "http-ntlm":
        return 80
    raise ValueError(f"Unsupported relay source: {source}")
