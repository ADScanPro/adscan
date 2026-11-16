"""Engagement-scope egress guard: the socket-level backstop of the asset scope.

A client can declare hosts an assessment must never contact. The primary checks
sit where each target list is built (``services/engagement_scope.py``). This
module is the net under them: while an asset scope is recorded, every outbound
connection or datagram this PROCESS attempts is checked against the scope
inside the process, and one aimed at an excluded address is refused before any
packet leaves, even when a call site forgot its own check. It restricts the
tool's own network activity; it never touches another program's traffic.

Design rules:

* **Addresses only, definite refusals only.** A socket carries an address, not a
  name. The verdict is one injected pure function (``str -> token | None``) that
  reads in-memory matchers and never opens a socket, reads the directory or
  resolves a name. An address whose status is not known passes: the primary
  check knows the name and owns the fail-closed decision.
* **Installed only while a scope exists.** Without one, ``socket`` and
  ``asyncio`` are untouched (:func:`install` is called by the engine when a
  scope is recorded or rehydrated, :func:`uninstall` when it is cleared).
* **No loop-bound state.** The patch is process-wide and safe under worker
  threads and many short-lived event loops: a ``threading.Lock``, a
  ``threading.local`` re-entry flag, plain dicts. No asyncio primitive.
* **Dependency inversion.** ``adscan_core`` never imports ``adscan_internal``:
  the verdict, the scope version and the hit recorder are injected with
  :func:`set_address_verdict_provider` (the ``set_finding_catalog_provider``
  pattern).

What is wrapped, and why the set is complete for Python-level sockets:

* ``socket.socket.connect`` / ``connect_ex`` / ``sendto`` / ``sendmsg``: every
  blocking client (``socket.create_connection``, ``ssl``, ``http.client``,
  urllib3, the TDS client, dnspython) and the asyncio SELECTOR loop end here.
  ``BaseSelectorEventLoop.sock_connect`` calls ``sock.connect`` and its
  datagram transport calls ``sock.sendto`` (read in CPython 3.12 and 3.13:
  ``selector_events.py`` ``_sock_connect`` and ``_SelectorDatagramTransport``),
  so ``create_connection``, ``open_connection``, ``create_datagram_endpoint``,
  ``sock_connect`` and ``sock_sendto`` are covered with no loop-level wrapper.
* The Windows PROACTOR loop never calls ``socket.connect``: it connects through
  overlapped ``ConnectEx`` / ``WSAConnect`` and sends datagrams through
  ``WSASendTo`` (``windows_events.py`` ``IocpProactor.connect`` / ``sendto``).
  Those two methods are the lowest point every proactor path reaches
  (``BaseProactorEventLoop.sock_connect``, ``sock_sendto`` and
  ``_ProactorDatagramTransport``), so both are wrapped where the module is
  importable, and ``BaseProactorEventLoop.sock_connect`` / ``sock_sendto`` are
  wrapped on every platform as a second layer.

A host NAME handed to a socket call (``sock.connect(("fs01.corp.example", 445))``)
would be resolved inside the C call, out of sight. The wrapper resolves it first
with the same libc lookup the C call would make (no Python socket is opened, so
nothing recurses), checks the first result, and hands the numeric address down.

Never refused: loopback, link-local, multicast, the limited broadcast address,
the unspecified address, the scanner's own interface addresses, Unix sockets and
every non-IP family. An IPv4-mapped IPv6 address is judged as its IPv4 address.

What this guard cannot see (child processes, link-layer frames, sockets opened
inside C extensions, a proxy's far side) is listed in the design
(``docs/superpowers/specs/2026-11-13-asset-scope-allow-deny-list.md`` §5.3).
"""

from __future__ import annotations

import errno
import ipaddress
import os
import socket
import sys
import threading
import time
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit

__all__ = (
    "AssetScopeEgressRefused",
    "GUARD_ERROR",
    "NOT_ALLOWED_REASONS",
    "PASS_THIS_PORT_ONLY",
    "REFUSAL_MARKER",
    "SIGNAL",
    "has_address_verdict_provider",
    "install",
    "installed_primitives",
    "is_egress_refusal",
    "is_installed",
    "recent_hits",
    "reset_cache",
    "route_source_ip",
    "self_test",
    "set_address_verdict_provider",
    "set_exemption_predicate",
    "stats",
    "uninstall",
)

#: Telemetry signal emitted for a refused connection (greppable).
SIGNAL = "asset_scope_backstop_hit"

#: Phrase every refusal message carries, so a wrapped or merged error (asyncio
#: joins several per-address errors into one ``OSError``) is still recognised.
REFUSAL_MARKER = "engagement-scope egress guard"

#: Verdict tokens that mean "outside the allow-list" rather than "named by a
#: deny entry". Only these yield to the product's own configured endpoints (a
#: proxy the operator set for the licence channel); a deny entry never does.
NOT_ALLOWED_REASONS = frozenset(
    {
        "not_in_allow_list",
        "dc_directory_only",
        "scope_record_unreadable",
        "identity_undetermined",
    }
)

#: Verdict token for a domain controller the scope keeps to directory reads,
#: contacted on a port that is not one of them. It is NOT an excluded address.
DC_DIRECTORY_ONLY = "dc_directory_only"

#: Verdict token for an address outside the scope's host allow-list.
NOT_IN_ALLOW_LIST = "not_in_allow_list"

#: Verdict tokens that mean "could not be confirmed inside the scope" (the
#: knowledge that would cover the address has lapsed and could not be
#: refreshed): refused all the same, and never worded as an exclusion.
NOT_CONFIRMED_REASONS = frozenset({"identity_undetermined"})

#: Verdict answer meaning "let THIS connection through, and do not remember
#: it": the pass depends on the port (a DNS server that is not a domain
#: controller, on port 53), so the same address must be asked again.
PASS_THIS_PORT_ONLY = "pass_this_port_only"

#: Entry token of a refusal made because the verdict itself failed. The guard
#: exists to refuse, so an address it cannot judge is treated as excluded
#: (fail closed) unless it is one the guard never refuses or a globally
#: routable one. :func:`self_test` finds such a fault when the guard is armed.
GUARD_ERROR = "guard_error"

AddressVerdict = Callable[..., "str | None"]

_PASSED_MAX = 200_000
_HITS_KEPT = 200
_INFRASTRUCTURE_TTL_SECONDS = 60.0
_WRAPPER_FLAG = "__adscan_egress_guard__"
_AF_INET = socket.AF_INET
_AF_INET6 = socket.AF_INET6
_UNSET = object()


def describe_refusal(entry: str) -> tuple[str, str]:
    """``(clause, sentence)`` wording one refusal, by the verdict token.

    Four distinct cases, never folded into "excluded": an address the scope
    excludes (a deny entry), one outside the allow list, a domain controller
    the scope keeps to directory reads, and one the scope could not confirm.
    """
    if entry in NOT_CONFIRMED_REASONS:
        return (
            "an address it could not confirm inside the scope",
            "the address could not be confirmed inside the engagement scope.",
        )
    if entry == DC_DIRECTORY_ONLY:
        return (
            "a domain controller the scope keeps to directory reads, on a port that is not one",
            "the address is a domain controller the engagement scope keeps to directory "
            "reads, and this port is not one of them.",
        )
    if entry == NOT_IN_ALLOW_LIST:
        return (
            "an address outside the scope's allow list",
            "the address is not in the engagement scope's allow list.",
        )
    return (
        "an address the scope excludes",
        "the address is excluded from the engagement scope.",
    )


class AssetScopeEgressRefused(PermissionError):
    """An outbound contact was stopped: its address is excluded from the scope.

    A ``PermissionError``, never a ``ConnectionRefusedError``: callers read a
    refused connection as "port closed" and would persist a false fact about a
    host that was never contacted. ``str()`` omits the ``[Errno 13]`` prefix so
    marker-based classifiers do not read it as a socket failure either.

    Attributes:
        address: The address that was refused.
        port: The destination port, when the call carried one.
        entry: The scope entry or reason token that decided it.
    """

    def __init__(self, address: str, port: int | None = None, entry: str = "") -> None:
        self.address = str(address)
        self.port = port
        self.entry = str(entry or "")
        where = f"{self.address} port {port}" if port else self.address
        why = describe_refusal(self.entry)[1]
        super().__init__(
            errno.EACCES,
            f"Outbound contact with {where} was stopped by the {REFUSAL_MARKER}: {why}",
        )

    def __str__(self) -> str:
        return str(self.strerror or "")

    def __reduce__(self) -> tuple[Any, ...]:
        return (type(self), (self.address, self.port, self.entry))


def is_egress_refusal(exc_or_msg: Any) -> bool:
    """Whether an error (or its cause, context or group members) is a guard refusal."""
    pending = [exc_or_msg]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if current is None:
            continue
        if not isinstance(current, BaseException):
            if REFUSAL_MARKER in str(current):
                return True
            continue
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, AssetScopeEgressRefused):
            return True
        try:
            if REFUSAL_MARKER in str(current):
                return True
        except Exception:  # noqa: BLE001 - an exception whose str() fails is not ours
            pass
        pending.append(current.__cause__)
        pending.append(current.__context__)
        members = getattr(current, "exceptions", None)
        if isinstance(members, (list, tuple)):
            pending.extend(members)
    return False


# ── State ──────────────────────────────────────────────────────────────────

_lock = threading.RLock()
_hit_lock = threading.Lock()
_tls = threading.local()


def _no_version() -> Any:
    return None


_verdict_fn: AddressVerdict | None = None
_verdict_takes_port = False
_version_fn: Callable[[], Any] = _no_version
_on_hit: Callable[..., Any] | None = None
_on_resolve: Callable[[str, list[str]], Any] | None = None
_exempt_override: Callable[[Any], bool] | None = None

#: ``(scope version, raw host strings known to pass under it)``. One object, so a
#: reader never pairs one version's answers with another version's token.
_cache: tuple[Any, dict[Any, bool]] = (_UNSET, {})

#: ``(owner, name, had_own_attribute, original, wrapper)`` per patched primitive.
_patches: list[tuple[Any, str, bool, Any, Any]] = []
_counters = {
    "refused": 0,
    "reentrant_passes": 0,
    "names_pinned": 0,
    "verdict_errors": 0,
    "names_observed": 0,
}
_hits: list[dict[str, Any]] = []
_announced_modules: set[str] = set()
_infrastructure_cache: tuple[float, frozenset[tuple[str, int | None]]] = (0.0, frozenset())

# The real socket primitives the module-level wrappers call (set at install).
_o_getaddrinfo: Any = socket.getaddrinfo
_o_connect: Any = socket.socket.connect
_o_connect_ex: Any = socket.socket.connect_ex
_o_sendto: Any = socket.socket.sendto
_o_sendmsg: Any = getattr(socket.socket, "sendmsg", None)


def _takes_port(verdict: Any) -> bool:
    """Whether a verdict callable accepts ``(ip, port)`` (else it is ``(ip)``)."""
    import inspect  # noqa: PLC0415

    try:
        parameters = list(inspect.signature(verdict).parameters.values())
    except (TypeError, ValueError):
        return False
    positional = [
        p
        for p in parameters
        if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD, p.VAR_POSITIONAL)
    ]
    return len(positional) >= 2 or any(p.kind is p.VAR_POSITIONAL for p in positional)


def set_address_verdict_provider(
    verdict: AddressVerdict | None,
    *,
    version: Callable[[], Any] | None = None,
    on_hit: Callable[..., Any] | None = None,
    on_resolve: Callable[[str, list[str]], Any] | None = None,
) -> None:
    """Inject the scope engine's address verdict (``None`` disarms the guard).

    Args:
        verdict: ``(ip text[, port]) -> token | None``. ``None`` lets the
            address through and may be remembered; :data:`PASS_THIS_PORT_ONLY`
            lets this connection through without being remembered; any other
            token (a deny entry id, or a reason in :data:`NOT_ALLOWED_REASONS`)
            refuses it. It reads in-memory matchers only: no socket, no
            directory read, no name resolution on the calling thread. (The
            engine's verdict may wait, within a bound, for a refresh of lapsed
            evidence that it runs on a thread of its own.)
        version: Returns a value that changes whenever the scope, a resolution
            pass or a learned address changes, and ``None`` when no scope is
            active (the guard then lets everything through). Cached answers are
            dropped when it changes.
        on_hit: Called as ``on_hit(module=<calling module>)`` for every refusal.
        on_resolve: Called as ``on_resolve(name, addresses)`` whenever this
            process resolves a host name through the system resolver, so the
            engine knows which name an address belongs to. In-memory only.
    """
    global _verdict_fn, _version_fn, _on_hit, _on_resolve, _verdict_takes_port  # noqa: PLW0603
    with _lock:
        if verdict is None:
            uninstall()
            _verdict_fn = None
            _verdict_takes_port = False
            _version_fn = _no_version
            _on_hit = None
            _on_resolve = None
            return
        _verdict_fn = verdict
        _verdict_takes_port = _takes_port(verdict)
        _version_fn = version or (lambda: 0)
        _on_hit = on_hit
        _on_resolve = on_resolve
        reset_cache()


def has_address_verdict_provider() -> bool:
    """Whether the scope engine armed the guard for this process."""
    return _verdict_fn is not None


def set_exemption_predicate(predicate: Callable[[Any], bool] | None) -> None:
    """Replace the never-refused address rule (``None`` restores the default).

    The default exempts loopback, link-local, multicast, the limited broadcast
    and the unspecified address. Tests replace it to treat a loopback alias as
    an ordinary host.
    """
    global _exempt_override  # noqa: PLW0603
    with _lock:
        _exempt_override = predicate
        reset_cache()


def reset_cache() -> None:
    """Forget every cached answer (the scope object itself was replaced)."""
    global _cache, _infrastructure_cache  # noqa: PLW0603
    with _lock:
        _cache = (_UNSET, {})
        _infrastructure_cache = (0.0, frozenset())


#: Addresses the self-test asks about: documentation ranges, never a real host.
_SELF_TEST_PROBES = (("192.0.2.1", 445), ("198.51.100.1", 53), ("2001:db8::1", 389))


def self_test() -> str:
    """Ask the verdict about three documentation addresses; ``""`` when it answers.

    Run by the engine every time the guard is armed. A verdict that raises is a
    fault of the guard itself: reported once, before any connection, as a
    configuration error, and from then on every engagement connection is
    refused (:data:`GUARD_ERROR`) until it is fixed or the operator turns the
    guard off. Never counted as a hit.
    """
    provider = _verdict_fn
    if provider is None:
        return ""
    try:
        for address, port in _SELF_TEST_PROBES:
            answer = provider(address, port) if _verdict_takes_port else provider(address)
            if answer is not None and not isinstance(answer, str):
                return f"the verdict answered {type(answer).__name__}, not a token"
    except Exception as exc:  # noqa: BLE001 - the fault is the finding
        _report_exception(exc)
        return f"{type(exc).__name__}: {exc}"
    return ""


def stats() -> dict[str, Any]:
    """Counters of the guard (refusals, re-entrant passes, pinned names)."""
    with _lock:
        return {
            **_counters,
            "installed": bool(_patches),
            "primitives": installed_primitives(),
            "cached_addresses": len(_cache[1]),
        }


def recent_hits() -> list[dict[str, Any]]:
    """The most recent refusals: calling module, operation and deciding entry."""
    with _lock:
        return [dict(hit) for hit in _hits]


# ── The check ──────────────────────────────────────────────────────────────


def _default_exempt(ip: Any) -> bool:
    return bool(
        ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or (ip.version == 4 and int(ip) == 0xFFFFFFFF)
    )


def _parse_ip(text: str) -> Any:
    """The address ``text`` names (IPv4-mapped IPv6 as IPv4), ``None`` for a name."""
    try:
        ip = ipaddress.ip_address(text.partition("%")[0])
    except ValueError:
        return None
    mapped = getattr(ip, "ipv4_mapped", None)
    return mapped if mapped is not None else ip


def _pin_name(
    sock: Any, address: tuple[Any, ...], family: Any
) -> tuple[Any, ...] | None:
    """Resolve a host name the way the C call would, and return a numeric address.

    ``getaddrinfo`` runs in libc: it opens no Python socket, so the guard is not
    re-entered. The first result is taken, as the C-level call does.
    """
    try:
        infos = socket.getaddrinfo(address[0], address[1], family, sock.type)
    except (OSError, UnicodeError, ValueError, TypeError):
        return None
    if not infos:
        return None
    resolved = infos[0][4]
    with _lock:
        _counters["names_pinned"] += 1
    if family == _AF_INET6 and len(address) > 2:
        return (resolved[0], *address[1:])
    return (resolved[0], address[1], *resolved[2:])


def _own_addresses() -> frozenset[str]:
    """The scanner's own interface addresses, read fresh (only before a refusal)."""
    try:
        from adscan_core.pal import net as pal_net  # noqa: PLC0415

        return frozenset(str(a) for a in pal_net.interface_ipv4_addresses())
    except Exception:  # noqa: BLE001 - no interface list is an empty answer
        return frozenset()


_DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
    "redis": 6379,
    "rediss": 6379,
    "socks4": 1080,
    "socks5": 1080,
    "socks5h": 1080,
}


def _infrastructure_endpoints() -> frozenset[tuple[str, int | None]]:
    """``(address, port)`` of the product's own configured endpoints.

    The proxy the operator set for the licence channel, the ``*_proxy``
    environment and the control queue. Read from the environment only before an
    allow-list refusal, and cached for a minute. The port is the endpoint's own
    (or its scheme's default; ``None`` when neither says): a proxy on
    ``10.0.0.5:3128`` lets port 3128 through, never 445 on the same address. A
    deny entry is never overridden by these.
    """
    global _infrastructure_cache  # noqa: PLW0603
    stamp, cached = _infrastructure_cache
    now = time.monotonic()
    if stamp and now - stamp < _INFRASTRUCTURE_TTL_SECONDS:
        return cached
    targets: set[tuple[str, int | None]] = set()
    values = [
        os.environ.get(name, "")
        for name in ("ADSCAN_LICENSE_PROXY", "ADSCAN_REDIS_URL", "REDIS_URL")
    ]
    try:
        from urllib.request import getproxies  # noqa: PLC0415

        values.extend(str(v) for v in getproxies().values())
    except Exception:  # noqa: BLE001
        pass
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        try:
            parts = urlsplit(text if "://" in text else f"//{text}")
            host = parts.hostname
            port = parts.port or _DEFAULT_PORTS.get((parts.scheme or "").lower())
        except ValueError:
            host, port = None, None
        if host:
            targets.add((host, port))
    endpoints: set[tuple[str, int | None]] = set()
    for host, port in targets:
        ip = _parse_ip(host)
        if ip is not None:
            endpoints.add((str(ip), port))
            continue
        try:
            for info in _o_getaddrinfo(host, None):
                found = _parse_ip(str(info[4][0]))
                if found is not None:
                    endpoints.add((str(found), port))
        except (OSError, UnicodeError):
            continue
    result = frozenset(endpoints)
    _infrastructure_cache = (now, result)
    return result


def _is_infrastructure(address: str, port: int | None) -> bool:
    endpoints = _infrastructure_endpoints()
    return (address, port) in endpoints or (address, None) in endpoints


def _cache_for(token: Any) -> dict[Any, bool]:
    global _cache  # noqa: PLW0603
    current = _cache
    if current[0] != token:
        with _lock:
            current = _cache
            if current[0] != token:
                current = (token, {})
                _cache = current
    return current[1]


def _remember(raw_host: Any, token: Any) -> None:
    cache = _cache_for(token)
    if len(cache) >= _PASSED_MAX:
        cache.clear()
    try:
        cache[raw_host] = True
    except TypeError:
        pass


def _admit(
    sock: Any, address: Any, operation: str, *, resolve_names: bool = True
) -> Any:
    """Return the address to hand to the real primitive, or refuse the contact.

    Raises:
        AssetScopeEgressRefused: The address is excluded from the engagement scope.
    """
    if type(address) is not tuple or len(address) < 2:
        return address
    token = _version_fn()
    if token is None:
        return address
    raw_host = address[0]
    host = raw_host
    if isinstance(host, (bytes, bytearray)):
        try:
            host = bytes(host).decode("ascii")
        except UnicodeDecodeError:
            return address
    if not isinstance(host, str):
        return address
    try:
        family = sock.family
    except Exception:  # noqa: BLE001 - not a socket we can read
        return address
    if family not in (_AF_INET, _AF_INET6):
        return address
    ip = _parse_ip(host)
    admitted = address
    if ip is None:
        if not resolve_names or host in ("", "<broadcast>", "<any>"):
            return address
        pinned = _pin_name(sock, address, family)
        if pinned is None:
            return address
        admitted = pinned
        raw_host = pinned[0]
        ip = _parse_ip(str(raw_host))
        if ip is None:
            return address
    exempt = _exempt_override or _default_exempt
    if exempt(ip):
        _remember(raw_host, token)
        return admitted
    if getattr(_tls, "busy", False):
        # A connection opened while a verdict is being computed (the provider
        # must not open one, but if it does it must not nest): let it through.
        with _lock:
            _counters["reentrant_passes"] += 1
        return admitted
    text = str(ip)
    port = address[1] if isinstance(address[1], int) else None
    _tls.busy = True
    try:
        entry = _ask(text, port)
        if not entry:
            if _version_fn() == token:
                _remember(raw_host, token)
            return admitted
        if entry == PASS_THIS_PORT_ONLY:
            return admitted
        if text in _own_addresses():
            _remember(raw_host, token)
            return admitted
        if entry == GUARD_ERROR and ip.is_global:
            # The verdict failed. A globally routable address is never judged
            # an engagement address without evidence, so it is let through
            # (not remembered); every other address is refused below.
            return admitted
        if (entry in NOT_ALLOWED_REASONS or entry == GUARD_ERROR) and _is_infrastructure(
            text, port
        ):
            return admitted
        _record_hit(text, operation, entry)
    finally:
        _tls.busy = False
    raise AssetScopeEgressRefused(text, port, entry)


def _ask(text: str, port: int | None = None) -> str | None:
    """The verdict's answer. A verdict that RAISES refuses (fail closed).

    The guard's purpose is to refuse, so its own fault must not open it. The
    fault is reported (telemetry and the debug log, with its traceback) and
    counted; :func:`self_test` surfaces it when the guard is armed, and the
    operator can turn the guard off (the engine's documented switch) while the
    per-operation checks stay on.
    """
    provider = _verdict_fn
    if provider is None:
        return None
    try:
        answer = provider(text, port) if _verdict_takes_port else provider(text)
        return answer or None
    except Exception as exc:  # noqa: BLE001 - fail closed, loudly
        with _lock:
            _counters["verdict_errors"] += 1
        _report_exception(exc)
        return GUARD_ERROR


def _report_exception(exc: BaseException) -> None:
    try:
        from adscan_core import telemetry  # noqa: PLC0415
        from adscan_core.rich_output import print_exception  # noqa: PLC0415

        telemetry.capture_exception(exc)  # type: ignore[arg-type]
        print_exception(exception=exc)  # type: ignore[arg-type]
    except Exception:  # noqa: BLE001 - reporting must never mask the original path
        pass


_OWN_PACKAGES = ("adscan_internal", "adscan_core", "adscan_launcher", "adscan")


def _calling_module() -> str:
    """The module that asked for the connection (resolved only on a refusal)."""
    stdlib = getattr(sys, "stdlib_module_names", frozenset())
    origin = ""
    owner = ""
    frame = sys._getframe(1)  # noqa: SLF001 - the stack is the only source of the caller
    depth = 0
    while frame is not None and depth < 200:
        name = str(frame.f_globals.get("__name__") or "")
        top = name.partition(".")[0]
        if name and name != __name__ and top not in stdlib:
            if not origin:
                origin = name
            if top in _OWN_PACKAGES:
                owner = name
                break
        frame = frame.f_back
        depth += 1
    if owner and origin and owner != origin:
        return f"{owner} via {origin}"
    return owner or origin or "unknown"


def _record_hit(address: str, operation: str, entry: str) -> None:
    """Surface one refusal: count it, record it, tell the operator, emit the signal."""
    module = _calling_module()
    with _lock:
        _counters["refused"] += 1
        _hits.append({"module": module, "operation": operation, "entry": entry})
        del _hits[:-_HITS_KEPT]
        first = module not in _announced_modules
        _announced_modules.add(module)
    recorder = _on_hit
    if recorder is not None:
        try:
            with _hit_lock:
                recorder(module=module)
        except Exception as exc:  # noqa: BLE001
            _report_exception(exc)
    try:
        from rich.markup import escape  # noqa: PLC0415

        from adscan_core import telemetry  # noqa: PLC0415
        from adscan_core.rich_output import print_info_debug, print_warning  # noqa: PLC0415
        from adscan_core.sensitive import mark_sensitive  # noqa: PLC0415

        shown = mark_sensitive(escape(address), "ip")
        if first:
            what = describe_refusal(entry)[0]
            print_warning(
                f"Engagement scope: ADscan stopped its own {escape(operation)} to {shown}, "
                f"{what}, before any packet left this machine. The request "
                f"came from {escape(module)} and should have been skipped earlier; please report it."
            )
            # The literal (== SIGNAL) keeps the event name inside the closed
            # vocabulary the telemetry allow-list test reads from the source.
            telemetry.capture(
                "asset_scope_backstop_hit",
                {"signal": SIGNAL, "module": module, "operation": operation},
            )
        else:
            print_info_debug(
                f"engagement-scope egress guard: stopped another {escape(operation)} to {shown} "
                f"from {escape(module)}"
            )
    except Exception as exc:  # noqa: BLE001
        _report_exception(exc)


# ── Wrapper: name resolution (an observer, it never changes an answer) ──────


def _observing_getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
    """``socket.getaddrinfo``, telling the engine which addresses a name has.

    A socket carries an address, never the name it was resolved from, so a
    host excluded BY NAME could only be refused at an address somebody had
    reported for it. Every client resolves through this function (blocking
    code, urllib3, and asyncio through its executor), so the name of every
    address this process is about to contact is known without any caller's
    cooperation. The answer is returned untouched.
    """
    result = _o_getaddrinfo(host, *args, **kwargs)
    observer = _on_resolve
    if observer is not None and result and _version_fn() is not None:
        try:
            name = host.decode("ascii") if isinstance(host, (bytes, bytearray)) else host
            if isinstance(name, str) and name and _parse_ip(name) is None:
                addresses = list(dict.fromkeys(str(info[4][0]) for info in result))
                observer(name, addresses)
                with _lock:
                    _counters["names_observed"] += 1
        except Exception as exc:  # noqa: BLE001 - an observer never breaks a lookup
            _report_exception(exc)
    return result


setattr(_observing_getaddrinfo, _WRAPPER_FLAG, True)


# ── Wrappers: blocking sockets and the selector loop ───────────────────────


def _is_route_query(sock: Any) -> bool:
    """True only inside :func:`route_source_ip`, for a datagram socket's connect.

    ``connect`` on a UDP socket sends nothing: it only asks the routing table
    which local address would be used. The marker is thread-local, set by that
    one helper (which owns and closes the socket), and honoured for datagram
    sockets only, so no stream connection can ride on it.
    """
    try:
        return bool(getattr(_tls, "route_query", False)) and sock.type == socket.SOCK_DGRAM
    except Exception:  # noqa: BLE001 - not a socket we can read
        return False


def route_source_ip(target: str, port: int = 9) -> str | None:
    """The local address the kernel would use toward ``target``; no packet is sent.

    The one sanctioned way to ask the routing table. A connected UDP socket
    resolves the route and binds the local address on ``connect`` and puts
    nothing on the wire, so this is not outbound contact and the engagement
    scope backstop does not judge it. The socket never leaves this function, so
    the exemption cannot be used to send. Everything else (any other connect,
    ``sendto``, a stream socket) is judged as before.

    Returns:
        The local address, or ``None`` when there is no route or ``target`` is
        not an IP literal.
    """
    ip = _parse_ip(str(target or ""))
    if ip is None:
        return None
    family = _AF_INET6 if ip.version == 6 else _AF_INET
    previous = getattr(_tls, "route_query", False)
    _tls.route_query = True
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.connect((str(ip), port))
            return str(sock.getsockname()[0])
    except OSError:
        return None
    finally:
        _tls.route_query = previous


def _guarded_connect(self: Any, address: Any) -> Any:
    try:
        cache = _cache
        known = address[0] in cache[1] and cache[0] == _version_fn()
    except Exception:  # noqa: BLE001 - an address shape the fast path cannot read
        known = False
    if not known and not _is_route_query(self):
        address = _admit(self, address, "connection")
    return _o_connect(self, address)


def _guarded_connect_ex(self: Any, address: Any) -> Any:
    try:
        cache = _cache
        known = address[0] in cache[1] and cache[0] == _version_fn()
    except Exception:  # noqa: BLE001
        known = False
    if not known and not _is_route_query(self):
        address = _admit(self, address, "connection")
    return _o_connect_ex(self, address)


def _guarded_sendto(self: Any, data: Any, *args: Any) -> Any:
    if args:
        address = args[-1]
        try:
            cache = _cache
            known = address[0] in cache[1] and cache[0] == _version_fn()
        except Exception:  # noqa: BLE001
            known = False
        if not known:
            admitted = _admit(self, address, "datagram")
            if admitted is not address:
                args = (*args[:-1], admitted)
    return _o_sendto(self, data, *args)


def _guarded_sendmsg(self: Any, buffers: Any, *args: Any) -> Any:
    if len(args) > 2 and args[2] is not None:
        address = args[2]
        try:
            cache = _cache
            known = address[0] in cache[1] and cache[0] == _version_fn()
        except Exception:  # noqa: BLE001
            known = False
        if not known:
            admitted = _admit(self, address, "datagram")
            if admitted is not address:
                args = (*args[:2], admitted, *args[3:])
    return _o_sendmsg(self, buffers, *args)


for _wrapper in (
    _guarded_connect,
    _guarded_connect_ex,
    _guarded_sendto,
    _guarded_sendmsg,
):
    setattr(_wrapper, _WRAPPER_FLAG, True)


# ── Wrappers: the proactor loop (Windows overlapped I/O) ───────────────────


def _proactor_connect_wrapper(original: Any) -> Any:
    def connect(self: Any, conn: Any, address: Any) -> Any:
        # ConnectEx takes a numeric address only, so a name is never resolved here.
        return original(
            self, conn, _admit(conn, address, "connection", resolve_names=False)
        )

    setattr(connect, _WRAPPER_FLAG, True)
    return connect


def _proactor_sendto_wrapper(original: Any) -> Any:
    def sendto(self: Any, conn: Any, buf: Any, flags: int = 0, addr: Any = None) -> Any:
        if addr is not None:
            addr = _admit(conn, addr, "datagram", resolve_names=False)
        return original(self, conn, buf, flags, addr)

    setattr(sendto, _WRAPPER_FLAG, True)
    return sendto


def _loop_sock_connect_wrapper(original: Any) -> Any:
    async def sock_connect(self: Any, sock: Any, address: Any) -> Any:
        return await original(
            self, sock, _admit(sock, address, "connection", resolve_names=False)
        )

    setattr(sock_connect, _WRAPPER_FLAG, True)
    return sock_connect


def _loop_sock_sendto_wrapper(original: Any) -> Any:
    async def sock_sendto(self: Any, sock: Any, data: Any, address: Any) -> Any:
        return await original(
            self, sock, data, _admit(sock, address, "datagram", resolve_names=False)
        )

    setattr(sock_sendto, _WRAPPER_FLAG, True)
    return sock_sendto


def _proactor_targets(
    extra: Iterable[type],
) -> list[tuple[Any, str, Callable[[Any], Any]]]:
    targets: list[tuple[Any, str, Callable[[Any], Any]]] = []
    try:
        from asyncio import proactor_events  # noqa: PLC0415

        loop_cls = proactor_events.BaseProactorEventLoop
        targets.append((loop_cls, "sock_connect", _loop_sock_connect_wrapper))
        targets.append((loop_cls, "sock_sendto", _loop_sock_sendto_wrapper))
    except Exception:  # noqa: BLE001 - a build without the proactor loop
        pass
    proactors: list[type] = list(extra)
    try:
        # Importable on Windows only (it needs the overlapped I/O extension).
        from asyncio import windows_events  # noqa: PLC0415

        proactors.append(windows_events.IocpProactor)
    except Exception:  # noqa: BLE001
        pass
    for proactor in proactors:
        targets.append((proactor, "connect", _proactor_connect_wrapper))
        targets.append((proactor, "sendto", _proactor_sendto_wrapper))
    return targets


# ── Install and restore ────────────────────────────────────────────────────


def _is_wrapper(value: Any) -> bool:
    return bool(getattr(value, _WRAPPER_FLAG, False))


def _patch(owner: Any, name: str, wrapper: Any, original: Any) -> None:
    had_own = name in vars(owner)
    setattr(owner, name, wrapper)
    _patches.append((owner, name, had_own, original, wrapper))


def install(*, proactors: Iterable[type] = ()) -> bool:
    """Put the guard in place. Idempotent: a second call adds nothing.

    Args:
        proactors: Further proactor implementations to guard (a class with
            ``connect(conn, address)`` and ``sendto(conn, buf, flags, addr)``),
            beyond the Windows ``IocpProactor``.

    Returns:
        True when the guard is in place.
    """
    global _o_connect, _o_connect_ex, _o_sendto, _o_sendmsg, _o_getaddrinfo  # noqa: PLW0603
    with _lock:
        if not _is_wrapper(socket.getaddrinfo):
            _o_getaddrinfo = socket.getaddrinfo
            _patch(socket, "getaddrinfo", _observing_getaddrinfo, _o_getaddrinfo)
        cls = socket.socket
        if not _is_wrapper(cls.connect):
            _o_connect = cls.connect
            _patch(cls, "connect", _guarded_connect, _o_connect)
        if not _is_wrapper(cls.connect_ex):
            _o_connect_ex = cls.connect_ex
            _patch(cls, "connect_ex", _guarded_connect_ex, _o_connect_ex)
        if not _is_wrapper(cls.sendto):
            _o_sendto = cls.sendto
            _patch(cls, "sendto", _guarded_sendto, _o_sendto)
        current_sendmsg = getattr(cls, "sendmsg", None)
        if current_sendmsg is not None and not _is_wrapper(current_sendmsg):
            _o_sendmsg = current_sendmsg
            _patch(cls, "sendmsg", _guarded_sendmsg, _o_sendmsg)
        for owner, name, factory in _proactor_targets(proactors):
            original = getattr(owner, name, None)
            if original is None or _is_wrapper(original):
                continue
            _patch(owner, name, factory(original), original)
        return bool(_patches)


def uninstall() -> None:
    """Restore every wrapped primitive to exactly what it was before :func:`install`."""
    with _lock:
        while _patches:
            owner, name, had_own, original, wrapper = _patches.pop()
            if vars(owner).get(name) is not wrapper:
                # Something else wrapped the primitive after the guard. Leave its
                # wrapper alone: with no scope the guard's layer lets everything by.
                continue
            if had_own:
                setattr(owner, name, original)
            else:
                delattr(owner, name)
        _announced_modules.clear()
        reset_cache()


def is_installed() -> bool:
    """Whether the guard currently wraps the socket primitives."""
    return bool(_patches)


def installed_primitives() -> list[str]:
    """The primitives currently wrapped, as ``module.Class.method``."""
    with _lock:
        return [
            (
                f"{owner.__module__}.{owner.__qualname__}.{name}"
                if hasattr(owner, "__qualname__")
                else f"{owner.__name__}.{name}"
            )
            for owner, name, *_ in _patches
        ]
