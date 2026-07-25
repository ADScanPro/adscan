"""Protocol-neutral relay orchestration contracts.

The relay layer intentionally owns orchestration only: listener lifecycle,
captured authentication metadata, target dispatch, and result aggregation.
Protocol-specific details live in source and target adapters.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from adscan_core import telemetry
from adscan_internal.rich_output import mark_sensitive, print_error_debug
from adscan_core.rich_output import print_exception


@dataclass(frozen=True)
class RelayAuthentication:
    """Authentication material captured from a relay source.

    Args:
        gssapi: Stateful authentication context that can be used as a client
            context against a target protocol.
        source_protocol: Listener protocol that received the authentication.
        client_host: Optional source host/IP.
        username: Optional authenticated principal, populated when known.
        domain: Optional authenticated domain, populated when known.
        metadata: Non-secret structured details useful for routing/debugging.
    """

    gssapi: Any
    source_protocol: str
    client_host: str | None = None
    username: str | None = None
    domain: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RelayTargetResult:
    """Result returned by a relay target adapter."""

    target_name: str
    success: bool
    technique: str
    principal: str | None = None
    artifact_paths: tuple[str, ...] = ()
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class RelayTarget(Protocol):
    """Attack target capable of consuming one relayed authentication context."""

    name: str
    technique: str

    async def run(self, authentication: RelayAuthentication) -> RelayTargetResult:
        """Execute the target-specific relay action."""


@dataclass(frozen=True)
class RelayRunConfig:
    """Bounded relay engine runtime configuration."""

    max_authentications: int = 1
    timeout_seconds: float = 120.0
    stop_on_first_success: bool = True
    # Set the instant a target succeeds so a coordinating coercion loop can stop
    # firing immediately (prevents stray coerced connections piling up on the
    # listener after the one-shot relay has already completed).
    success_event: "asyncio.Event | None" = None


@dataclass(frozen=True)
class RelayRunResult:
    """Aggregate result for a relay engine run."""

    results: tuple[RelayTargetResult, ...]
    timed_out: bool
    authentications_seen: int

    @property
    def success(self) -> bool:
        """Return whether any target succeeded."""

        return any(result.success for result in self.results)


class RelayEngine:
    """Small async dispatcher for captured relay authentications."""

    def __init__(
        self,
        *,
        auth_queue: asyncio.Queue[RelayAuthentication],
        targets: list[RelayTarget],
        config: RelayRunConfig | None = None,
    ) -> None:
        self.auth_queue = auth_queue
        self.targets = targets
        self.config = config or RelayRunConfig()

    async def run(self) -> RelayRunResult:
        """Consume captured authentications and dispatch them to targets."""

        deadline = time.monotonic() + self.config.timeout_seconds
        results: list[RelayTargetResult] = []
        authentications_seen = 0
        timed_out = False

        while authentications_seen < self.config.max_authentications:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break

            try:
                authentication = await asyncio.wait_for(
                    self.auth_queue.get(),
                    timeout=remaining,
                )
            except TimeoutError:
                timed_out = True
                break

            authentications_seen += 1
            for target in self.targets:
                result = await self._run_target(target, authentication)
                results.append(result)
                if result.success:
                    # Tell a coordinating coercion to stop firing right now.
                    if self.config.success_event is not None:
                        self.config.success_event.set()
                    if self.config.stop_on_first_success:
                        return RelayRunResult(
                            results=tuple(results),
                            timed_out=False,
                            authentications_seen=authentications_seen,
                        )

        return RelayRunResult(
            results=tuple(results),
            timed_out=timed_out,
            authentications_seen=authentications_seen,
        )

    @staticmethod
    async def _run_target(
        target: RelayTarget,
        authentication: RelayAuthentication,
    ) -> RelayTargetResult:
        """Run one target while converting unexpected exceptions to results."""

        try:
            return await target.run(authentication)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_error_debug(
                f"[relay] target {mark_sensitive(target.name, 'text')} raised unexpected exception: {exc}"
            )
            return RelayTargetResult(
                target_name=target.name,
                success=False,
                technique=target.technique,
                error=str(exc),
            )


@contextlib.asynccontextmanager
async def cancel_on_exit(task: asyncio.Task[Any]):
    """Cancel and drain a task when leaving an async context."""

    try:
        yield task
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
