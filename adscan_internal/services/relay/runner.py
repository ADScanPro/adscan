"""High-level native relay runner."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, replace
from typing import Any, Literal

from adscan_internal.services.engagement_scope import (
    Contact,
    partition_targets_in_scope,
)
from adscan_internal.services.engagement_scope_targets import prepare_targets_for_scope
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

#: Reused by every "not run" result this module returns once every expected
#: source host has been refused by the engagement scope.
RELAY_NOT_RUN_OUTSIDE_SCOPE_REASON = "outside the engagement scope"

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
    shell: Any = None,
    domain: str | None = None,
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

    ``shell`` is the active session, when one is in reach of the caller. Any
    named ``expected_sources`` host is checked against the engagement scope
    before the listener is opened; a host with no known scope (or ``shell``
    left unset) is treated as in scope, unchanged from before this check
    existed. An empty ``expected_sources`` ("any caller") names no specific
    host and is left unchecked.
    """

    effective = config or NativeRelayRunConfig()
    in_scope_targets = relay_targets_in_scope(targets, shell=shell, domain=domain)
    if targets and not in_scope_targets:
        logger.debug(
            "[relay] skipped: every relay destination is %s",
            RELAY_NOT_RUN_OUTSIDE_SCOPE_REASON,
        )
        return RelayRunResult(results=(), timed_out=False, authentications_seen=0)
    targets = in_scope_targets
    if effective.expected_sources:
        prepare_targets_for_scope(shell, effective.expected_sources, domain=domain)
        partition = partition_targets_in_scope(
            shell,
            effective.expected_sources,
            surface="native_relay",
            what="Relay",
            domain=domain,
        )
        if not partition.allowed:
            logger.debug(
                "[relay] skipped: every expected source host is %s",
                RELAY_NOT_RUN_OUTSIDE_SCOPE_REASON,
            )
            return RelayRunResult(results=(), timed_out=False, authentications_seen=0)
        effective = replace(effective, expected_sources=tuple(partition.allowed))

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


def _relay_destination(target: RelayTarget) -> tuple[str, str, str]:
    """``(name, address, protocol)`` of the host a relay target sends to.

    Read from the target's own configuration: a certification authority
    (``ca_fqdn`` / ``ca_host``) or a directory server (``dc_ip``). ``("", "",
    "")`` when the target names no destination this module knows; the egress
    backstop then remains its only gate.
    """

    target_config = getattr(target, "config", None)
    ca_host = str(getattr(target_config, "ca_host", "") or "").strip()
    if ca_host:
        ca_fqdn = str(getattr(target_config, "ca_fqdn", "") or "").strip()
        return ca_fqdn or ca_host, ca_host, "http"
    dc_ip = str(getattr(target_config, "dc_ip", "") or "").strip()
    if dc_ip:
        return dc_ip, dc_ip, "ldap"
    return "", "", ""


def relay_targets_in_scope(
    targets: list[RelayTarget], *, shell: Any, domain: str | None
) -> list[RelayTarget]:
    """The relay targets whose destination host the engagement scope allows.

    Asked before the listener opens, so an authentication is never forwarded
    to an excluded host. Each refusal is recorded once by the scope engine.
    A list with no named destination is returned as it came.
    """

    kept = list(targets or ())
    by_protocol: dict[str, list[RelayTarget]] = {}
    for target in kept:
        name, _address, protocol = _relay_destination(target)
        if name:
            by_protocol.setdefault(protocol, []).append(target)
    prepare_targets_for_scope(
        shell,
        [target for group in by_protocol.values() for target in group],
        key=lambda item: _relay_destination(item)[0],
        address=lambda item: _relay_destination(item)[1],
        domain=domain,
    )
    for protocol, group in by_protocol.items():
        partition = partition_targets_in_scope(
            shell,
            group,
            key=lambda item: _relay_destination(item)[0],
            address=lambda item: _relay_destination(item)[1],
            # What the relay opens on the destination, never a named purpose.
            contact=Contact(protocol),
            surface="native_relay_destination",
            what="Relay",
            domain=domain,
        )
        refused = {id(item) for item in partition.refused_items}
        kept = [item for item in kept if id(item) not in refused]
    return kept


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
