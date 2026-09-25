"""High-level native relay runner."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass
from typing import Literal

from adscan_internal.services.relay.core import (
    RelayEngine,
    RelayListenerUnavailableError,
    RelayRunConfig,
    RelayRunResult,
    RelayTarget,
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


async def run_native_relay(
    *,
    targets: list[RelayTarget],
    config: NativeRelayRunConfig | None = None,
    success_event: asyncio.Event | None = None,
) -> RelayRunResult:
    """Start a native relay listener and dispatch captured auth to targets.

    ``success_event`` (optional) is set by the engine the instant a target
    succeeds, so a concurrent coercion loop can stop firing immediately.
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

    from adscan_core.rich_output import (  # noqa: PLC0415
        print_exception,
        print_info_debug,
        print_warning,
    )
    from adscan_core import telemetry  # noqa: PLC0415

    try:
        await source.start()
    except RelayListenerUnavailableError as exc:
        # The listen port could not be bound (e.g. already held by the poisoning
        # / capture listener). Turn it into a failed result so the ESC8 / RBCD
        # caller continues to the next path instead of aborting the whole phase
        # with a raw traceback. This is a vantage/data gap, never a defensive
        # control claim (Exposure-Validation doctrine).
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_warning(
            f"Relay listener could not start on port {exc.port} "
            f"({exc.reason}). Skipping the relay attempt and continuing."
        )
        with contextlib.suppress(Exception):
            await source.stop()
        return RelayRunResult(
            results=(),
            timed_out=False,
            authentications_seen=0,
            listener_error=exc.reason_summary,
        )

    try:
        return await engine.run()
    finally:
        # Teardown trace: a freeze observed after a successful relay was traced to
        # this listener shutdown blocking on stray half-open coerced connections
        # (the coercion catalog fires many triggers, each opening a victim->listener
        # SMB connection that never completes its session). These markers pinpoint
        # whether the hang is in source.stop() vs downstream.
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
    )
    if config.source == "smb":
        return SMBRelaySource(config=source_config, auth_queue=auth_queue)
    if config.source in {"ldap", "ldaps"}:
        return LDAPRelaySource(config=source_config, auth_queue=auth_queue)
    if config.source == "http-ntlm":
        http_config = HTTPNtlmRelaySourceConfig(
            listen_host=config.listen_host,
            listen_port=port,
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
