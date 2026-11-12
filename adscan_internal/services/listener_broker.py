"""The listener broker: the single owner of every inbound TCP listener.

Several techniques need an inbound listener on a privileged port of the scanning
host: the background capture (poisoning, the write-share bait, the NTLM auth-type
sweep), the relay steps (ESC8, ESC11, RBCD, shadow credentials), the ESC8
Kerberos capture, the cross-forest Kerberos coercion capture and the share-drop
capture. When each bound the port itself they collided (``EADDRINUSE``), and the
bridge that lent the port from capture to relay made the two mutually exclusive.

This module is the SSOT that removes the contention:

* **One owner per (address, port).** The first claim binds the wildcard of its
  address family. When another local process holds the wildcard and the claim
  names a concrete callback address, that address is bound instead, one socket
  per address. A socket closes when the last claim it serves is released.
* **Accept, route, hand off.** One accept thread per bound socket. For each
  connection the broker reads only the peer address, chooses ONE claim with
  :func:`select_claim`, and hands it the connected socket. No protocol byte is
  read first, so the consumer sees a fresh connection with the real peer.
* **Routing policy** (:func:`select_claim`): a targeted claim whose expected
  sources contain the peer, then an untargeted claim, then the port's capture
  claim, then a targeted claim as the fallback when nothing captures. NTLM
  carries no principal before the server's challenge (the NEGOTIATE domain and
  workstation fields are optional), so the decision is the source address.

A claim never binds anything itself. An asyncio consumer passes a stream handler
and its loop (:func:`asyncio_delivery`, :func:`claim_listener`); the vendor
servers (``SMBRelayServer``, ``LDAPRelayServer``) take connections in their
``handoff`` mode through ``handle_stream``.

The accept threads never print to the operator: routing lines are debug-only and
failures go to telemetry and the debug log. Cross-platform: binding uses the
stdlib on both OSes, and :func:`classify_bind_error` reads POSIX errno values and
the Winsock codes alike, with the permission hint chosen through the PAL.
"""
from __future__ import annotations

import asyncio
import contextlib
import enum
import errno as _errno
import ipaddress
import socket
import threading
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Awaitable, Callable, Iterable, Optional, Sequence, Union

from adscan_core import telemetry
from adscan_core.rich_output import print_exception, print_info_debug

#: Delivers one accepted connection to a consumer. Called on the accept thread:
#: it must not block. Returns False when the consumer can no longer take
#: connections (its loop is gone), which drops the claim and re-routes.
Deliver = Callable[[socket.socket, Any], bool]

#: An asyncio stream handler, the ``asyncio.start_server`` callback shape.
StreamHandler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]

_IPV4_WILDCARD = "0.0.0.0"  # noqa: S104 - an inbound listener serves every segment
_IPV6_WILDCARD = "::"
_ACCEPT_POLL_SECONDS = 0.25
_THREAD_JOIN_SECONDS = 2.0
_BACKLOG = 128

#: Winsock codes Python reports as ``errno`` on Windows.
_WSAEACCES = 10013
_WSAEADDRINUSE = 10048
_WSAEADDRNOTAVAIL = 10049

_ADDRINUSE_CODES = frozenset({_errno.EADDRINUSE, _WSAEADDRINUSE})
_ACCESS_CODES = frozenset({_errno.EACCES, _errno.EPERM, _WSAEACCES})
_ADDRNOTAVAIL_CODES = frozenset({_errno.EADDRNOTAVAIL, _WSAEADDRNOTAVAIL})


# ── errors and their classification ──────────────────────────────────────────


class ListenerUnavailableError(Exception):
    """A listener could not open its port (a limit of the scanning host).

    Most commonly ``EADDRINUSE`` (another process holds the port) or a refused
    privileged port. It is a vantage/data gap, never a claim about the target
    environment (Exposure-Validation doctrine). ``code`` is host-free and safe
    for telemetry (``eaddrinuse`` / ``eacces`` / ``eaddrnotavail`` /
    ``capture_taken`` / ``no_address`` / ``other``).
    """

    def __init__(self, *, host: str, port: int, reason: str, code: str = "other") -> None:
        self.host = host
        self.port = port
        self.reason = reason
        self.code = code
        super().__init__(self.reason_summary)

    @property
    def reason_summary(self) -> str:
        """One-line reason, starting with the phrase the step-failure SSOT matches.

        ``relay listener port`` is what ``relay_listener_unavailable`` keys on, so
        a step that stopped here is classified, never "no cause recorded".
        """
        return f"relay listener port {self.port} unavailable: {self.reason}"


def _winerror_or_errno(exc: OSError) -> Optional[int]:
    winerror = getattr(exc, "winerror", None)
    if isinstance(winerror, int) and winerror:
        return winerror
    return exc.errno


def _find_oserror_code(exc: BaseException) -> Optional[int]:
    seen: set[int] = set()
    current: Optional[BaseException] = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, OSError):
            code = _winerror_or_errno(current)
            if code is not None:
                return code
        current = current.__cause__ or current.__context__
    return None


def _permission_hint() -> str:
    from adscan_core.pal.platform import is_windows  # noqa: PLC0415

    if is_windows():
        return "run ADscan from an elevated prompt to open it"
    return "the runtime needs CAP_NET_BIND_SERVICE to open it"


def classify_bind_error(exc: BaseException, *, port: Optional[int] = None) -> tuple[str, str]:
    """Return ``(code, operator_message)`` for a failed listener bind.

    Walks the cause chain for an ``OSError`` and reads its errno, or the Winsock
    code on Windows. The message is plain and bracket-free: Rich reads the raw
    ``[Errno 98]`` text as markup and drops it. The raw exception still reaches
    the debug log through the caller.
    """
    code = _find_oserror_code(exc)
    if code in _ADDRINUSE_CODES:
        return "eaddrinuse", "another listener on the scanning host already holds the port"
    if code in _ACCESS_CODES:
        privileged = port is None or int(port) < 1024
        what = "the privileged port" if privileged else "the port"
        message = f"the scanning host refused {what} (permission denied)"
        if privileged:
            message = f"{message}; {_permission_hint()}"
        return "eacces", message
    if code in _ADDRNOTAVAIL_CODES:
        return "eaddrnotavail", "the listen address is not configured on the scanning host"
    if code is not None:
        return "other", f"the port could not be opened (errno {code})"
    return "other", "the port could not be opened"


def describe_listener_bind_error(exc: BaseException, *, port: Optional[int] = None) -> str:
    """The operator message of :func:`classify_bind_error`."""
    return classify_bind_error(exc, port=port)[1]


# ── claims and the routing policy ────────────────────────────────────────────


class ClaimRole(str, enum.Enum):
    """How a claim takes part in routing (see :func:`select_claim`)."""

    #: The port's catch-all capture. At most one per bound address.
    CAPTURE = "capture"
    #: Wants connections from known sources (the coerced target).
    TARGETED = "targeted"
    #: Wants every connection it can get (no source is knowable, e.g. WPAD).
    UNTARGETED = "untargeted"


@dataclass(frozen=True)
class ListenerClaim:
    """A consumer's request for connections on ``port``.

    Args:
        claim_id: Stable id (``relay:smb``, ``capture:445@0.0.0.0``). Claiming an
            id again replaces the previous claim.
        port: TCP port.
        deliver: Receives each routed connection (see :data:`Deliver`).
        role: Routing role.
        expected_sources: For a targeted claim, the hosts whose connections it
            wants (IP literals or names; names are resolved to every address).
            Empty on a targeted claim, or none of them resolving, makes it
            untargeted (it takes any caller, as a lone listener would).
        local_address: The local address the consumer's callers dial (a wildcard
            when there is no single one). It decides which socket serves the
            claim, never the routing.
    """

    claim_id: str
    port: int
    deliver: Deliver
    role: ClaimRole = ClaimRole.TARGETED
    expected_sources: tuple[str, ...] = ()
    local_address: str = _IPV4_WILDCARD


@dataclass(frozen=True)
class ArmedClaim:
    """A registered claim, as the routing policy sees it."""

    claim_id: str
    role: ClaimRole
    expected_sources: frozenset[str]
    armed_order: int
    deliver: Deliver
    served_address: str = _IPV4_WILDCARD


def select_claim(candidates: Sequence[ArmedClaim], peer_ip: str) -> Optional[ArmedClaim]:
    """Choose the ONE claim a connection from ``peer_ip`` goes to.

    1. a targeted claim whose expected sources contain the peer;
    2. an untargeted claim;
    3. the capture claim;
    4. a targeted claim, when nothing captures (a multi-homed target calling
       back from another NIC still reaches its relay, as before the broker);
    5. none: the connection is closed.

    Within one step the earliest armed claim wins.
    """
    ordered = sorted(candidates, key=lambda claim: claim.armed_order)
    peer = normalize_peer(peer_ip)
    for claim in ordered:
        if claim.role is ClaimRole.TARGETED and peer and peer in claim.expected_sources:
            return claim
    for claim in ordered:
        if claim.role is ClaimRole.UNTARGETED:
            return claim
    for claim in ordered:
        if claim.role is ClaimRole.CAPTURE:
            return claim
    for claim in ordered:
        if claim.role is ClaimRole.TARGETED:
            return claim
    return None


def normalize_peer(address: object) -> str:
    """Return ``address`` as a canonical IP literal (IPv4-mapped IPv6 unwrapped)."""
    text = str(address or "").strip()
    if not text:
        return ""
    if "%" in text:
        text = text.split("%", 1)[0]
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        return ""
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return str(parsed.ipv4_mapped)
    return str(parsed)


def _wildcard_for(address: str) -> str:
    return _IPV6_WILDCARD if ":" in address else _IPV4_WILDCARD


def _is_wildcard(address: str) -> bool:
    return address in (_IPV4_WILDCARD, _IPV6_WILDCARD)


def resolve_sources(hosts: Iterable[str]) -> frozenset[str]:
    """Every address the given hosts resolve to (IP literals kept as they are).

    Best-effort: a name that does not resolve contributes nothing. Blocking
    (``getaddrinfo``); call it off the event loop.
    """
    resolved: set[str] = set()
    for host in hosts or ():
        text = str(host or "").strip()
        if not text:
            continue
        literal = normalize_peer(text)
        if literal:
            resolved.add(literal)
            continue
        try:
            infos = socket.getaddrinfo(text, None, proto=socket.IPPROTO_TCP)
        except (OSError, UnicodeError):
            continue
        for info in infos:
            address = normalize_peer(info[4][0])
            if address:
                resolved.add(address)
    return frozenset(resolved)


@dataclass(frozen=True)
class ClaimRefusal:
    """Why a claim could not be served."""

    claim_id: str
    port: int
    code: str
    message: str
    error: Optional[BaseException] = None


class ClaimHandle:
    """A live claim. :meth:`release` gives it back (idempotent)."""

    def __init__(self, broker: "ListenerBroker", armed: ArmedClaim, port: int) -> None:
        self._broker = broker
        self.claim_id = armed.claim_id
        self.port = port
        self.role = armed.role
        self.served_address = armed.served_address
        self.expected_sources = armed.expected_sources
        self._released = False

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        self._broker.release(self.claim_id, port=self.port)

    async def arelease(self) -> None:
        """Release off the event loop (the release joins an accept thread)."""
        await asyncio.to_thread(self.release)


ClaimResult = Union[ClaimHandle, ClaimRefusal]


# ── the owner ────────────────────────────────────────────────────────────────


@dataclass
class _Bound:
    port: int
    address: str
    sock: socket.socket
    stop: threading.Event = field(default_factory=threading.Event)
    thread: Optional[threading.Thread] = None


class ListenerBroker:
    """Owns every inbound listening socket and routes each connection to one claim."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._bound: dict[tuple[int, str], _Bound] = {}
        self._claims: dict[int, dict[str, ArmedClaim]] = {}
        self._order = 0

    # ── public API ──────────────────────────────────────────────────────────

    def claim(self, claim: ListenerClaim) -> ClaimResult:
        """Register ``claim``, binding the port when nothing serves it yet.

        Blocking (it may resolve names and start a thread): call it off the event
        loop. Never raises; a refusal carries a classified reason.
        """
        cid = str(claim.claim_id or "").strip()
        port = int(claim.port)
        requested = normalize_peer(claim.local_address) if claim.local_address else _IPV4_WILDCARD
        if not cid or not requested:
            return ClaimRefusal(
                claim_id=cid,
                port=port,
                code="no_address",
                message=f"no valid local address was given ({claim.local_address!r})",
            )
        role = claim.role
        sources: frozenset[str] = frozenset()
        if role is ClaimRole.TARGETED:
            if claim.expected_sources:
                sources = resolve_sources(claim.expected_sources)
                if not sources:
                    # No address is knowable: keep the single-listener behaviour
                    # (the claim takes any caller) rather than lose the coerced
                    # host's callback to the capture.
                    role = ClaimRole.UNTARGETED
                    print_info_debug(
                        f"listener-broker: {cid} names no resolvable source; it takes "
                        f"any :{port} caller"
                    )
            else:
                role = ClaimRole.UNTARGETED

        with self._lock:
            # A re-claim keeps the previous registration's socket alive until the
            # new one is registered, so the port is never closed and re-opened.
            previous = self._claims.get(port, {}).pop(cid, None)
            served = self._serving_address_locked(port, requested)
            newly_bound: Optional[_Bound] = None
            refusal: Optional[ClaimRefusal] = None
            if served is None:
                served, newly_bound, refusal = self._bind_for_locked(port, requested, cid)
            if served is not None and role is ClaimRole.CAPTURE and any(
                armed.role is ClaimRole.CAPTURE and armed.served_address == served
                for armed in self._claims.get(port, {}).values()
            ):
                refusal = ClaimRefusal(
                    claim_id=cid,
                    port=port,
                    code="capture_taken",
                    message=f"a capture already listens on {served}:{port}",
                )
            if refusal is not None or served is None:
                closing = [
                    self._unbind_if_unused_locked(port, address)
                    for address in {served, previous.served_address if previous else None}
                    if address
                ]
            else:
                self._order += 1
                armed = ArmedClaim(
                    claim_id=cid,
                    role=role,
                    expected_sources=sources,
                    armed_order=self._order,
                    deliver=claim.deliver,
                    served_address=served,
                )
                self._claims.setdefault(port, {})[cid] = armed
                if newly_bound is not None:
                    self._start_accepting(newly_bound)
                closing = (
                    [self._unbind_if_unused_locked(port, previous.served_address)]
                    if previous is not None and previous.served_address != served
                    else []
                )
        for bound in closing:
            self._stop_later(bound)
        if refusal is not None or served is None:
            return refusal or ClaimRefusal(cid, port, "other", "the port could not be opened")
        print_info_debug(
            f"listener-broker: {cid} armed on {served}:{port} ({role.value}"
            + (f", {len(sources)} expected source(s)" if sources else "")
            + ")"
        )
        return ClaimHandle(self, armed, port)

    def release(self, claim_id: str, *, port: Optional[int] = None) -> None:
        """Remove a claim; close its socket once no claim uses it (idempotent)."""
        cid = str(claim_id or "").strip()
        to_stop: list[_Bound] = []
        with self._lock:
            ports = [int(port)] if port is not None else list(self._claims)
            for each in ports:
                armed = self._claims.get(each, {}).pop(cid, None)
                if armed is None:
                    continue
                bound = self._unbind_if_unused_locked(each, armed.served_address)
                if bound is not None:
                    to_stop.append(bound)
                print_info_debug(f"listener-broker: {cid} released from :{each}")
        for bound in to_stop:
            self._stop(bound)

    def shutdown(self) -> None:
        """Close every socket and drop every claim (session end, tests)."""
        with self._lock:
            bound = list(self._bound.values())
            self._bound.clear()
            self._claims.clear()
        for each in bound:
            self._stop(each)

    def bound_addresses(self, port: int) -> list[str]:
        with self._lock:
            return sorted(address for (p, address) in self._bound if p == int(port))

    def bound_socknames(self, port: int) -> list[tuple]:
        """The live sockets' local names (a stable socket keeps the same entry)."""
        with self._lock:
            return sorted(
                (address, id(bound.sock))
                for (p, address), bound in self._bound.items()
                if p == int(port)
            )

    def claim_ids(self, port: int) -> list[str]:
        with self._lock:
            return sorted(self._claims.get(int(port), {}))

    def serving_address(self, port: int, requested: str) -> Optional[str]:
        """The bound address that already serves ``requested`` on ``port``, if any."""
        address = normalize_peer(requested) or _IPV4_WILDCARD
        with self._lock:
            return self._serving_address_locked(int(port), address)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                str(port): {
                    "bound": sorted(address for (p, address) in self._bound if p == port),
                    "claims": {
                        cid: {"role": armed.role.value, "served": armed.served_address}
                        for cid, armed in sorted(claims.items())
                    },
                }
                for port, claims in self._claims.items()
            }

    # ── binding ─────────────────────────────────────────────────────────────

    def _serving_address_locked(self, port: int, requested: str) -> Optional[str]:
        wildcard = _wildcard_for(requested)
        if (port, wildcard) in self._bound:
            return wildcard
        if (port, requested) in self._bound:
            return requested
        return None

    def _bind_for_locked(
        self, port: int, requested: str, cid: str
    ) -> tuple[Optional[str], Optional[_Bound], Optional[ClaimRefusal]]:
        """Bind the wildcard; when it is held elsewhere, the requested address."""
        wildcard = _wildcard_for(requested)
        bound, error = self._open(port, wildcard)
        if bound is not None:
            return wildcard, bound, None
        code, message = classify_bind_error(error, port=port) if error else ("other", "")
        if code != "eaddrinuse" or _is_wildcard(requested):
            return None, None, ClaimRefusal(cid, port, code, message, error)
        print_info_debug(
            f"listener-broker: {wildcard}:{port} is held by another local process; "
            f"binding the callback address {requested} only"
        )
        bound, error = self._open(port, requested)
        if bound is not None:
            return requested, bound, None
        code, message = classify_bind_error(error, port=port) if error else ("other", "")
        return None, None, ClaimRefusal(cid, port, code, message, error)

    def _open(self, port: int, address: str) -> tuple[Optional[_Bound], Optional[OSError]]:
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        try:
            sock = socket.create_server((address, port), family=family, backlog=_BACKLOG)
        except OSError as exc:
            print_info_debug(f"listener-broker: bind {address}:{port} failed: {type(exc).__name__}")
            return None, exc
        sock.settimeout(_ACCEPT_POLL_SECONDS)
        bound = _Bound(port=port, address=address, sock=sock)
        self._bound[(port, address)] = bound
        return bound, None

    def _start_accepting(self, bound: _Bound) -> None:
        bound.thread = threading.Thread(
            target=self._accept_loop,
            args=(bound,),
            name=f"listener-broker-{bound.address}:{bound.port}",
            daemon=True,
        )
        bound.thread.start()
        print_info_debug(f"listener-broker: listening on {bound.address}:{bound.port}")

    def _unbind_if_unused_locked(self, port: int, address: str) -> Optional[_Bound]:
        if any(armed.served_address == address for armed in self._claims.get(port, {}).values()):
            return None
        if not self._claims.get(port):
            self._claims.pop(port, None)
        return self._bound.pop((port, address), None)

    def _stop_later(self, bound: Optional[_Bound]) -> None:
        if bound is not None:
            self._stop(bound)

    def _stop(self, bound: _Bound) -> None:
        bound.stop.set()
        thread = bound.thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=_THREAD_JOIN_SECONDS)
        with contextlib.suppress(OSError):
            bound.sock.close()
        print_info_debug(f"listener-broker: stopped listening on {bound.address}:{bound.port}")

    # ── accepting and routing ───────────────────────────────────────────────

    def _accept_loop(self, bound: _Bound) -> None:
        while not bound.stop.is_set():
            try:
                conn, peer = bound.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if bound.stop.is_set():
                    break
                bound.stop.wait(0.05)
                continue
            try:
                self._dispatch(bound, conn, peer)
            except Exception as exc:  # noqa: BLE001 - one connection must never kill the owner
                telemetry.capture_exception(exc)
                print_exception(exception=exc, visible=False)
                with contextlib.suppress(OSError):
                    conn.close()

    def _dispatch(self, bound: _Bound, conn: socket.socket, peer: Any) -> None:
        peer_ip = normalize_peer(peer[0] if isinstance(peer, tuple) and peer else peer)
        for _attempt in range(8):
            with self._lock:
                candidates = [
                    armed
                    for armed in self._claims.get(bound.port, {}).values()
                    if armed.served_address == bound.address
                ]
            choice = select_claim(candidates, peer_ip)
            if choice is None:
                print_info_debug(
                    f"listener-broker: :{bound.port} connection from {peer_ip or '?'} "
                    "has no consumer; closed"
                )
                with contextlib.suppress(OSError):
                    conn.close()
                return
            try:
                delivered = bool(choice.deliver(conn, peer))
            except Exception as exc:  # noqa: BLE001 - a broken consumer is dropped
                telemetry.capture_exception(exc)
                print_exception(exception=exc, visible=False)
                delivered = False
            if delivered:
                print_info_debug(
                    f"listener-broker: :{bound.port} connection from {peer_ip or '?'} "
                    f"routed to {choice.claim_id}"
                )
                return
            print_info_debug(
                f"listener-broker: {choice.claim_id} can no longer take connections; dropped"
            )
            self.release(choice.claim_id, port=bound.port)
        with contextlib.suppress(OSError):
            conn.close()


_BROKER: Optional[ListenerBroker] = None
_BROKER_LOCK = threading.Lock()


def get_listener_broker() -> ListenerBroker:
    """The process-wide owner. A port is a property of the process, not a session."""
    global _BROKER  # noqa: PLW0603
    with _BROKER_LOCK:
        if _BROKER is None:
            _BROKER = ListenerBroker()
        return _BROKER


# ── asyncio consumers ────────────────────────────────────────────────────────


async def _serve_socket(conn: socket.socket, handler: StreamHandler) -> None:
    try:
        reader, writer = await asyncio.open_connection(sock=conn)
    except Exception:  # noqa: BLE001 - the peer may already be gone
        with contextlib.suppress(OSError):
            conn.close()
        return
    await handler(reader, writer)


def _log_handler_failure(future: "Any") -> None:
    if future.cancelled():
        return
    exc = future.exception()
    if exc is not None:
        print_exception(exception=exc, visible=False)
        print_info_debug(f"listener-broker: a consumer handler ended with {type(exc).__name__}")


def asyncio_delivery(loop: asyncio.AbstractEventLoop, handler: StreamHandler) -> Deliver:
    """A :data:`Deliver` that serves each connection on ``loop`` with ``handler``."""

    def _deliver(conn: socket.socket, _peer: Any) -> bool:
        if loop.is_closed() or not loop.is_running():
            return False
        try:
            future = asyncio.run_coroutine_threadsafe(_serve_socket(conn, handler), loop)
        except RuntimeError:
            return False
        future.add_done_callback(_log_handler_failure)
        return True

    return _deliver


async def acquire_listener(
    *,
    port: int,
    consumer_id: str,
    handler: StreamHandler,
    role: ClaimRole = ClaimRole.TARGETED,
    expected_sources: Iterable[str] = (),
    local_address: str = _IPV4_WILDCARD,
    broker: Optional[ListenerBroker] = None,
) -> ClaimHandle:
    """Claim ``port`` for ``handler`` on the running loop; raise when refused.

    Raises:
        ListenerUnavailableError: the port could not be served (classified).
    """
    loop = asyncio.get_running_loop()
    owner = broker if broker is not None else get_listener_broker()
    result = await asyncio.to_thread(
        owner.claim,
        ListenerClaim(
            claim_id=consumer_id,
            port=int(port),
            deliver=asyncio_delivery(loop, handler),
            role=role,
            expected_sources=tuple(str(item) for item in expected_sources or () if item),
            local_address=local_address or _IPV4_WILDCARD,
        ),
    )
    if isinstance(result, ClaimRefusal):
        error = ListenerUnavailableError(
            host=local_address or _IPV4_WILDCARD,
            port=int(port),
            reason=result.message,
            code=result.code,
        )
        if result.error is not None:
            raise error from result.error
        raise error
    return result


@contextlib.asynccontextmanager
async def claim_listener(
    *,
    port: int,
    consumer_id: str,
    handler: StreamHandler,
    role: ClaimRole = ClaimRole.TARGETED,
    expected_sources: Iterable[str] = (),
    local_address: str = _IPV4_WILDCARD,
    broker: Optional[ListenerBroker] = None,
) -> AsyncIterator[ClaimHandle]:
    """Hold a claim for the length of a block; released even on error or cancel."""
    handle = await acquire_listener(
        port=port,
        consumer_id=consumer_id,
        handler=handler,
        role=role,
        expected_sources=expected_sources,
        local_address=local_address,
        broker=broker,
    )
    try:
        yield handle
    finally:
        await asyncio.shield(asyncio.ensure_future(handle.arelease()))


__all__ = [
    "ArmedClaim",
    "ClaimHandle",
    "ClaimRefusal",
    "ClaimRole",
    "ListenerBroker",
    "ListenerClaim",
    "ListenerUnavailableError",
    "acquire_listener",
    "asyncio_delivery",
    "claim_listener",
    "classify_bind_error",
    "describe_listener_bind_error",
    "get_listener_broker",
    "normalize_peer",
    "resolve_sources",
    "select_claim",
]
