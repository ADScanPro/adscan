"""Diagnose the route from this machine to the licence server, one step at a time.

``adscan license check`` runs these steps and names the first that fails:

1. **proxy** — which proxy, if any, carries the connection (``ADSCAN_LICENSE_PROXY``
   first, then the standard ``HTTPS_PROXY`` family urllib reads).
2. **dns** — the licence host (or the proxy) resolves.
3. **tcp** — a TCP connection opens to it on its port (443).
4. **tls** — the TLS handshake verifies the server's certificate. A certificate
   not issued for the licence host means TLS inspection; one that reads as
   expired or not yet valid usually means this machine's clock is wrong.
5. **health** — ``GET /v1/health`` answers, and gives the server's time.
6. **clock** — the difference between this machine's clock and the server's.

Why the clock matters here (spec § 5.6, § 9.3): ADscan steps the host clock to a
domain controller during a scan, and a scan stopped abruptly can leave it there
(``clock-stepped.json``). The server refuses a request dated more than
:data:`FUTURE_TOLERANCE` ahead of it (``stale_request``), TLS rejects a
certificate outside its validity window by THIS machine's clock, and a clock
more than :data:`ROLLBACK_TOLERANCE` behind the last time the server confirmed
stops new assessments (``clock_rollback``).

No licence data is sent by these steps (the health check is a plain GET). Each
step has its own timeout; the whole diagnosis takes seconds even when nothing
answers. Never raises.
"""

from __future__ import annotations

import json
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any

STEP_TIMEOUT_SECONDS = 5.0
#: The server refuses a request dated further ahead than this (license_server config).
FUTURE_TOLERANCE = timedelta(hours=24)
#: A clock further behind the server than this stops new assessments (clock rollback).
ROLLBACK_TOLERANCE = timedelta(hours=72)
#: A difference worth mentioning, short of breaking anything.
NOTABLE_OFFSET = timedelta(minutes=5)

#: Failure causes, stable for ``adscan license check --json``.
CAUSE_PROXY = "proxy"
CAUSE_DNS = "dns"
CAUSE_EGRESS = "egress"
CAUSE_TLS_INSPECTION = "tls_inspection"
CAUSE_TLS_CLOCK = "tls_clock"
CAUSE_TLS = "tls"
CAUSE_HTTP = "http"
CAUSE_CLOCK_AHEAD = "clock_ahead"
CAUSE_CLOCK_BEHIND = "clock_behind"

# OpenSSL verification codes (X509_V_ERR_*).
_NOT_YET_VALID, _EXPIRED = 9, 10
_INSPECTION_CODES = frozenset({18, 19, 20, 21, 62})


@dataclass
class Step:
    """One diagnostic step: ``ok`` True/False, or None when skipped."""

    name: str
    ok: bool | None
    detail: str
    cause: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "ok": self.ok, "detail": self.detail, "cause": self.cause or None}


@dataclass
class RouteReport:
    """What the diagnosis found."""

    url: str
    host: str
    port: int
    proxy: str | None
    steps: list[Step] = field(default_factory=list)
    server_time: datetime | None = None
    clock_offset_seconds: float | None = None
    clock_stepped: bool = False
    container_proxy_hint: bool = False

    @property
    def reachable(self) -> bool:
        return any(s.name == "health" and s.ok for s in self.steps)

    @property
    def failed(self) -> Step | None:
        return next((s for s in self.steps if s.ok is False), None)

    @property
    def cause(self) -> str | None:
        failed = self.failed
        return failed.cause if failed is not None else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "proxy": self.proxy,
            "reachable": self.reachable,
            "cause": self.cause,
            "steps": [s.to_dict() for s in self.steps],
            "server_time": self.server_time.strftime("%Y-%m-%dT%H:%M:%SZ") if self.server_time else None,
            "clock_offset_seconds": None
            if self.clock_offset_seconds is None
            else round(self.clock_offset_seconds, 1),
            "clock_stepped_by_adscan": self.clock_stepped,
        }


def _redact(proxy: str) -> str:
    """The proxy URL without its credentials."""
    parsed = urllib.parse.urlparse(proxy)
    if parsed.username or parsed.password:
        netloc = parsed.hostname or ""
        if parsed.port:
            netloc += f":{parsed.port}"
        return parsed._replace(netloc=netloc).geturl()
    return proxy


def _proxy_for(url: str, host: str) -> str | None:
    from adscan_core.pro_license.client import licence_proxy

    explicit = licence_proxy()
    if explicit:
        return explicit
    proxies = urllib.request.getproxies()
    scheme = urllib.parse.urlparse(url).scheme
    proxy = proxies.get(scheme) or proxies.get("all")
    if not proxy:
        return None
    try:
        if urllib.request.proxy_bypass(host):
            return None
    except Exception:  # noqa: BLE001 - a broken NO_PROXY reads as "no bypass"
        pass
    return proxy


def _resolve(host: str, port: int, timeout: float) -> tuple[list[str], str]:
    """``(addresses, error)``; bounded even when the resolver hangs."""
    box: dict[str, Any] = {}

    def _run() -> None:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            box["ips"] = sorted({str(info[4][0]) for info in infos})
        except OSError as exc:
            box["error"] = str(exc) or exc.__class__.__name__

    worker = threading.Thread(target=_run, daemon=True, name="adscan-licence-dns")
    worker.start()
    worker.join(timeout)
    if "ips" in box:
        return box["ips"], ""
    return [], box.get("error") or "no answer"


def _connect(host: str, port: int, timeout: float) -> socket.socket:
    return socket.create_connection((host, port), timeout=timeout)


def _tunnel(sock: socket.socket, host: str, port: int, proxy: str) -> tuple[bool, str]:
    """Open an HTTP CONNECT tunnel through ``sock`` (already connected to the proxy)."""
    import base64

    parsed = urllib.parse.urlparse(proxy)
    lines = [f"CONNECT {host}:{port} HTTP/1.1", f"Host: {host}:{port}"]
    if parsed.username:
        token = base64.b64encode(
            f"{urllib.parse.unquote(parsed.username)}:{urllib.parse.unquote(parsed.password or '')}".encode()
        ).decode()
        lines.append(f"Proxy-Authorization: Basic {token}")
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
    reply = b""
    while b"\r\n\r\n" not in reply and len(reply) < 8192:
        chunk = sock.recv(1024)
        if not chunk:
            break
        reply += chunk
    status_line = reply.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    parts = status_line.split()
    code = parts[1] if len(parts) > 1 else "?"
    return code == "200", status_line or "no answer"


def _presented_issuer(host: str, port: int, proxy: str | None, timeout: float) -> str:
    """Who issued the certificate this machine is shown (unverified look, best-effort)."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        target = urllib.parse.urlparse(proxy) if proxy else None
        sock = _connect(target.hostname if target else host, (target.port or 8080) if target else port, timeout)
        if proxy:
            ok, _ = _tunnel(sock, host, port, proxy)
            if not ok:
                sock.close()
                return ""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with context.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
        if not der:
            return ""
        cert = x509.load_der_x509_certificate(der)
        names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME) or cert.issuer.get_attributes_for_oid(
            NameOID.ORGANIZATION_NAME
        )
        return str(names[0].value) if names else cert.issuer.rfc4514_string()
    except Exception:  # noqa: BLE001 - a best-effort hint
        return ""


def _server_time(response: Any, body: bytes) -> datetime | None:
    try:
        data = json.loads(body)
        value = data.get("server_time") if isinstance(data, dict) else None
        if isinstance(value, str):
            from adscan_core.pro_license.documents import parse_instant

            return parse_instant(value)
    except (ValueError, TypeError):
        pass
    header = response.headers.get("Date") if response is not None else None
    if header:
        try:
            moment = parsedate_to_datetime(header)
            return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            return None
    return None


def _timed_health(base: str, timeout: float) -> tuple[datetime | None, float | None]:
    """``GET /v1/health`` through the licence channel: ``(server_time, offset_seconds)``.

    ``offset_seconds`` is server time minus this machine's time at the midpoint
    of the request (positive: this machine is behind). Raises what urllib raises.
    """
    from adscan_core.pro_license.client import open_url

    request = urllib.request.Request(base + "/v1/health", method="GET")
    sent = datetime.now(timezone.utc)
    t0 = time.monotonic()
    with open_url(request, timeout=timeout) as response:
        body = response.read(4096)
        server_time = _server_time(response, body)
    if server_time is None:
        return None, None
    midpoint = sent + timedelta(seconds=(time.monotonic() - t0) / 2)
    return server_time, (server_time - midpoint).total_seconds()


#: Below this, signing with this machine's own clock is fine.
SIGNING_OFFSET_THRESHOLD = timedelta(minutes=1)


def server_corrected_now(store: Any = None, *, url: str | None = None, timeout: float = 3.0) -> datetime | None:
    """The licence server's current time, when this machine's clock is off by more than a minute.

    For anything this machine signs and the server checks against its own clock
    (the registry credential): ADscan steps the host clock to a domain
    controller during a scan, and a crash can leave it there. Returns None when
    the clock agrees (sign with the local clock) or when the server cannot be
    asked (then the local clock is all there is; the refusal, if any, is
    diagnosed as a clock problem). Never raises. ``store`` is accepted for the
    caller's symmetry with the other licence helpers and is not read.
    """
    del store
    try:
        from adscan_core.pro_license.client import server_url

        _server, offset = _timed_health((url or server_url()).rstrip("/"), timeout)
    except Exception:  # noqa: BLE001 - best effort: the local clock is the fallback
        return None
    if offset is None or abs(offset) < SIGNING_OFFSET_THRESHOLD.total_seconds():
        return None
    return datetime.now(timezone.utc) + timedelta(seconds=offset)


def _human_offset(seconds: float) -> str:
    value = abs(seconds)
    if value >= 86400:
        amount, unit = value / 86400, "day"
    elif value >= 3600:
        amount, unit = value / 3600, "hour"
    elif value >= 60:
        amount, unit = value / 60, "minute"
    else:
        return f"{int(round(value))} seconds"
    rounded = round(amount, 1)
    text = f"{rounded:g} {unit}"
    return text + ("" if rounded == 1 else "s")


def diagnose(*, url: str | None = None, licence_dir: Any = None, timeout: float = STEP_TIMEOUT_SECONDS) -> RouteReport:
    """Run every step against ``url`` (the configured licence server by default). Never raises."""
    from adscan_core.pro_license.client import licence_proxy, server_url

    base = (url or server_url()).rstrip("/")
    parsed = urllib.parse.urlparse(base)
    host = parsed.hostname or ""
    secure = parsed.scheme == "https"
    port = parsed.port or (443 if secure else 80)
    proxy = _proxy_for(base, host)
    report = RouteReport(url=base, host=host, port=port, proxy=_redact(proxy) if proxy else None)
    try:
        from adscan_core.enterprise_license import clock_currently_stepped

        report.clock_stepped = bool(clock_currently_stepped(licence_dir))
    except Exception:  # noqa: BLE001
        report.clock_stepped = False
    report.container_proxy_hint = bool(proxy and not licence_proxy())
    try:
        _run_steps(report, base, host, port, secure, proxy, timeout)
    except Exception as exc:  # noqa: BLE001 - a diagnosis reports, never raises
        report.steps.append(Step("health", False, f"The check stopped unexpectedly ({exc.__class__.__name__}).", CAUSE_HTTP))
    return report


def _run_steps(
    report: RouteReport, base: str, host: str, port: int, secure: bool, proxy: str | None, timeout: float
) -> None:
    steps = report.steps
    proxy_url = urllib.parse.urlparse(proxy) if proxy else None
    if proxy_url is not None:
        steps.append(Step("proxy", True, f"Connections go through the proxy at {report.proxy}."))
        target_host, target_port = proxy_url.hostname or "", proxy_url.port or 8080
    else:
        steps.append(Step("proxy", None, "No proxy is configured for this connection."))
        target_host, target_port = host, port

    ips, error = _resolve(target_host, target_port, timeout)
    if not ips:
        what = "the proxy" if proxy else "the licence server"
        steps.append(Step("dns", False, f"{target_host} ({what}) does not resolve on this machine ({error}).", CAUSE_DNS))
        return
    steps.append(Step("dns", True, f"{target_host} resolves to {', '.join(ips[:3])}."))

    started = time.monotonic()
    try:
        sock = _connect(target_host, target_port, timeout)
    except OSError as exc:
        reason = "timed out" if isinstance(exc, (socket.timeout, TimeoutError)) else (str(exc) or "refused")
        steps.append(
            Step("tcp", False, f"No connection to {target_host} on port {target_port} ({reason}).", CAUSE_EGRESS)
        )
        return
    steps.append(Step("tcp", True, f"Port {target_port} on {target_host} accepts connections."))

    with sock:
        if proxy:
            try:
                ok, line = _tunnel(sock, host, port, proxy)
            except OSError as exc:
                ok, line = False, str(exc) or "no answer"
            if not ok:
                steps.append(
                    Step("proxy", False, f"The proxy did not open a tunnel to {host}:{port} ({line}).", CAUSE_PROXY)
                )
                return
        if secure:
            try:
                remaining = max(1.0, timeout - (time.monotonic() - started))
                sock.settimeout(remaining)
                from adscan_core.pro_license.client import tls_context

                with tls_context().wrap_socket(sock, server_hostname=host) as tls:
                    version = tls.version() or "TLS"
                steps.append(Step("tls", True, f"The certificate for {host} verifies ({version})."))
            except ssl.SSLCertVerificationError as exc:
                code = int(getattr(exc, "verify_code", 0) or 0)
                message = str(getattr(exc, "verify_message", "") or exc)
                if code in (_NOT_YET_VALID, _EXPIRED):
                    when = "not valid yet" if code == _NOT_YET_VALID else "expired"
                    steps.append(
                        Step(
                            "tls",
                            False,
                            f"The certificate for {host} reads as {when} by this machine's clock.",
                            CAUSE_TLS_CLOCK,
                        )
                    )
                elif code in _INSPECTION_CODES:
                    issuer = _presented_issuer(host, port, proxy, timeout)
                    by = f", issued by {issuer}" if issuer else ""
                    steps.append(
                        Step(
                            "tls",
                            False,
                            f"This machine was shown a certificate for {host} that ADscan did not issue "
                            f"({message}{by}).",
                            CAUSE_TLS_INSPECTION,
                        )
                    )
                else:
                    steps.append(Step("tls", False, f"The TLS handshake with {host} failed ({message}).", CAUSE_TLS))
                return
            except (ssl.SSLError, OSError) as exc:
                steps.append(Step("tls", False, f"The TLS handshake with {host} failed ({exc}).", CAUSE_TLS))
                return
        else:
            steps.append(Step("tls", None, "Plain HTTP (a local test server)."))

    try:
        server_time, offset_seconds = _timed_health(base, timeout)
        ok = True
        detail = "The licence server answers."
    except urllib.error.HTTPError as exc:
        steps.append(Step("health", False, f"The licence server answered HTTP {exc.code}.", CAUSE_HTTP))
        return
    except (urllib.error.URLError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        steps.append(Step("health", False, f"The licence server did not answer ({reason}).", CAUSE_EGRESS))
        return
    steps.append(Step("health", ok, detail))

    if server_time is None or offset_seconds is None:
        steps.append(Step("clock", None, "The server did not state its time."))
        return
    offset = offset_seconds
    report.server_time = server_time
    report.clock_offset_seconds = offset
    ahead = -offset
    if ahead > FUTURE_TOLERANCE.total_seconds():
        steps.append(
            Step(
                "clock",
                False,
                f"This machine's clock is {_human_offset(offset)} ahead of the licence server, so the "
                "server refuses its requests as dated in the future.",
                CAUSE_CLOCK_AHEAD,
            )
        )
    elif offset > ROLLBACK_TOLERANCE.total_seconds():
        steps.append(
            Step(
                "clock",
                False,
                f"This machine's clock is {_human_offset(offset)} behind the licence server, so new "
                "assessments stop until it is corrected.",
                CAUSE_CLOCK_BEHIND,
            )
        )
    elif abs(offset) > NOTABLE_OFFSET.total_seconds():
        direction = "ahead of" if offset < 0 else "behind"
        steps.append(
            Step("clock", True, f"This machine's clock is {_human_offset(offset)} {direction} the licence server.")
        )
    else:
        steps.append(Step("clock", True, "This machine's clock agrees with the licence server."))


def fix_for(report: RouteReport) -> str:
    """What to do about the failed step, one or two sentences. ``""`` when nothing failed."""
    from adscan_core.pal.platform import is_windows

    cause = report.cause
    host, port = report.host, report.port
    resync = "w32tm /resync" if is_windows() else "sudo timedatectl set-ntp true"
    stepped = (
        " ADscan is holding this clock at a domain controller's time: a scan is running, or one "
        f"stopped before restoring it. Let the scan finish, or turn time sync back on (`{resync}`)."
        if report.clock_stepped
        else f" Correct the clock or turn time sync on (`{resync}`)."
    )
    if cause == CAUSE_DNS:
        return (
            f"Check the DNS server this machine uses, or ask for {host} to be allowed through your DNS filtering."
            if not report.proxy
            else "Check the proxy address in HTTPS_PROXY or ADSCAN_LICENSE_PROXY."
        )
    if cause == CAUSE_EGRESS:
        if report.proxy:
            return "Check that the proxy is running and that this machine may use it."
        return (
            f"Allow outbound HTTPS from this machine to {host} on TCP {port}. If your network only "
            "reaches the internet through a proxy, set HTTPS_PROXY (and ADSCAN_LICENSE_PROXY for scans)."
        )
    if cause == CAUSE_PROXY:
        return (
            f"The proxy refused the tunnel. A 407 answer means it wants credentials in the proxy URL; "
            f"otherwise ask for {host} to be allowed."
        )
    if cause == CAUSE_TLS_INSPECTION:
        return (
            f"A TLS inspection device is replacing the certificate. Exempt {host} from inspection. ADscan "
            "accepts only its own certificate chain, so trusting the inspection certificate does not help."
        )
    if cause == CAUSE_TLS_CLOCK:
        return "The certificate check failed on the date, which usually means this machine's clock is wrong." + stepped
    if cause == CAUSE_TLS:
        return f"Something between this machine and {host} interrupts TLS. Ask your network team to allow it."
    if cause == CAUSE_HTTP:
        return f"Something other than the ADscan licence server answered for {host}, such as a proxy or portal page."
    if cause in (CAUSE_CLOCK_AHEAD, CAUSE_CLOCK_BEHIND):
        return stepped.strip()
    return ""


__all__ = [
    "CAUSE_CLOCK_AHEAD",
    "CAUSE_CLOCK_BEHIND",
    "CAUSE_DNS",
    "CAUSE_EGRESS",
    "CAUSE_HTTP",
    "CAUSE_PROXY",
    "CAUSE_TLS",
    "CAUSE_TLS_CLOCK",
    "CAUSE_TLS_INSPECTION",
    "FUTURE_TOLERANCE",
    "ROLLBACK_TOLERANCE",
    "SIGNING_OFFSET_THRESHOLD",
    "RouteReport",
    "Step",
    "diagnose",
    "fix_for",
    "server_corrected_now",
]
