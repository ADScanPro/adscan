"""ADCS CA HTTP web enrollment probe (ESC8).

Detects whether the CA host exposes an exploitable ``/certsrv/`` web
enrollment endpoint. A raw TCP port check is NOT sufficient: ports 80/443 are
routinely open for unrelated IIS/ADFS sites, which produced ESC8 false
positives (e.g. an IIS host with no ``/certsrv/`` at all). The true-positive
signature of an ESC8-vulnerable certsrv endpoint is an HTTP ``401`` response
to ``GET /certsrv/certfnsh.asp`` carrying a ``WWW-Authenticate`` header that
offers ``NTLM`` or ``Negotiate`` — that is the surface an NTLM relay actually
lands on.

We deliberately avoid pulling in an HTTP client dependency (no aiohttp /
httpx). asysocks ships an HTTP ``ClientSession``, but it is a full session
abstraction (cookie jar, auth manager, connection factory, redirect handling,
proxy plumbing) — disproportionate for a stateless reachability probe that
only needs to read the status line and the ``WWW-Authenticate`` header. The
relay client (``relay/adcs_esc8.py``) already drives this exact endpoint with
``asyncio.open_connection`` + a permissive ``ssl`` context, so we mirror that
pattern here for a minimal hand-written HTTP/1.1 ``GET``: same transport, same
TLS posture (CA web certs are routinely self-signed → verification disabled),
no extra dependency.

False-negative biased: any failure, non-401 status, or absent NTLM/Negotiate
offer -> the scheme is treated as NOT web-enrollment-enabled.

EPA (Extended Protection for Authentication) gating
---------------------------------------------------
The passive 401 + ``WWW-Authenticate: NTLM`` signature above proves web
enrollment is *offered*, but it does NOT prove ESC8 is *exploitable*: if the
HTTPS ``/certsrv`` endpoint enforces EPA (channel binding for HTTP auth over
TLS), an NTLM relay is defeated at the auth exchange — EPA does not change the
initial 401 offer, so the passive probe cannot see it. When a scan credential
is available we run an ACTIVE differential test (mirroring Certipy's
``check_channel_binding``): complete an NTLM auth over the TLS channel to
``/certsrv`` first WITHOUT a channel-binding token, then WITH one.

  * auth accepted without CBT  -> EPA not enforced   (``epa_enforced=False``)
  * 401 without CBT, accepted with CBT -> EPA enforced (``epa_enforced=True``)
  * both 401 / inconclusive / no credential -> ``epa_enforced=None`` (unknown)

The verdict gates ESC8 emission with the HTTP-vs-HTTPS nuance:

  * HTTP web enrollment (port 80, no TLS) works regardless of EPA (no TLS
    channel to bind) -> ESC8 stays viable.
  * HTTPS-only: EPA decides. Enforced -> HTTPS is not a viable relay target.

Suppression requires POSITIVE evidence (``epa_enforced is True``): an unknown
EPA state (unauth scan, inconclusive test) never suppresses, so behaviour is
identical to the pre-EPA probe for those cases — no false-negative ESC8 is
introduced. When EPA closes the only HTTPS avenue and no HTTP avenue exists,
``web_enrollment_enabled`` resolves False so NO ESC8 edge is emitted at all
(this is the hardened, recommended CA state — there is no residual weakness to
report, so it is NOT surfaced as ``closed_by_configuration``).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import socket
import ssl
from dataclasses import dataclass

from adscan_core.rich_output import print_info_debug, print_info_verbose
from adscan_internal import telemetry
from adscan_internal.rich_output import mark_sensitive
from adscan_core.rich_output import print_exception

# Single source of truth for the certsrv enrollment endpoint path. Shared by
# the probe (detection) and conceptually mirrored by the relay client.
CERTSRV_ENROLL_PATH = "/certsrv/certfnsh.asp"

_HTTP_USER_AGENT = "Mozilla/5.0 (compatible; ADscan ADCS Web Enrollment Probe)"
# Header-read ceiling: certsrv 401 responses are tiny; cap so a misbehaving
# endpoint that never sends the header terminator cannot stall the probe.
_MAX_HEADER_BYTES = 64 * 1024
# Body-drain ceiling: the intermediate 401 (NTLM challenge) response body must
# be consumed so the keep-alive TLS connection can carry the type-3 request.
# certsrv 401 bodies are small; cap so a misbehaving endpoint cannot stall us.
_MAX_BODY_BYTES = 512 * 1024


@dataclass
class WebProbeCredential:
    """Minimal domain credential for the active EPA (channel-binding) test.

    Only NTLM-usable secrets qualify: EPA defeats the NTLM relay ESC8 depends
    on, so the honest test authenticates with NTLM (the exact auth type ESC8
    relays). A Kerberos-only / ccache credential cannot drive it -> the caller
    passes ``None`` and the EPA state stays unknown.
    """

    username: str
    domain: str
    password: str | None = None
    nt_hash: str | None = None

    def has_secret(self) -> bool:
        return bool(self.username and (self.password or self.nt_hash))


@dataclass
class WebEnrollmentProbeResult:
    """Outcome of probing a CA host for an exploitable certsrv endpoint.

    ``web_enrollment_enabled`` is the overall ESC8 verdict (HTTP-aware): True
    only when at least one scheme answered ``GET /certsrv/certfnsh.asp`` with a
    401 offering NTLM/Negotiate. The per-scheme ``*_ntlm`` flags and
    ``answering_scheme`` let the relay pick the right transport (HTTPS-first
    when both qualify).
    """

    target_host: str
    web_enrollment_enabled: bool
    https_enabled: bool
    http_enabled: bool
    https_ntlm: bool = False
    http_ntlm: bool = False
    answering_scheme: str | None = None
    error_message: str | None = None
    epa_enforced: bool | None = None
    # Certain-closure signals: True ONLY when the port actively refused. A
    # timeout leaves ``*_enabled`` False but ``*_refused`` False too — the
    # closure is not certain, so a consumer must not treat it as "not listening".
    https_refused: bool = False
    http_refused: bool = False
    """Extended Protection for Authentication on the HTTPS ``/certsrv`` endpoint.

    ``True`` = EPA (channel binding) enforced -> NTLM relay defeated -> HTTPS is
    not a viable ESC8 target. ``False`` = EPA not enforced -> HTTPS viable.
    ``None`` = not tested / inconclusive (no NTLM credential, TLS/HTTP error,
    or both requests returned 401). Only ``True`` suppresses ESC8; ``None``
    never does (preserves the pre-EPA behaviour for unauthenticated scans).
    """


@dataclass
class _SchemeProbeResult:
    """Per-scheme HTTP probe outcome."""

    tcp_open: bool
    status: int | None
    ntlm_offered: bool
    # True ONLY when the port actively refused the connection (certain closure).
    # A timeout/other error leaves this False (tcp_open is also False, but the
    # closure is NOT certain — see ``_tcp_open``).
    tcp_refused: bool = False


class ADCSWebEnrollmentProbe:
    """Detect an exploitable HTTP(S) ``/certsrv/`` endpoint on a CA host."""

    async def probe(
        self,
        *,
        host: str,
        timeout: float = 5.0,
        credential: WebProbeCredential | None = None,
    ) -> WebEnrollmentProbeResult:
        if not host:
            return WebEnrollmentProbeResult(
                target_host="",
                web_enrollment_enabled=False,
                https_enabled=False,
                http_enabled=False,
                error_message="missing host",
            )

        # Probe HTTPS first so HTTPS-first scheme selection in the relay reflects
        # the operator-preferred transport when both qualify.
        https = await self._probe_scheme(host, "https", 443, timeout)
        http = await self._probe_scheme(host, "http", 80, timeout)

        masked = mark_sensitive(host, "host")
        for scheme, res in (("https", https), ("http", http)):
            if not res.tcp_open:
                print_info_debug(
                    f"[adcs-web-probe] {scheme} port closed: host={masked}"
                )
                continue
            print_info_verbose(
                f"[adcs-web-probe] {scheme} {CERTSRV_ENROLL_PATH}: host={masked} "
                f"status={res.status} ntlm_or_negotiate={res.ntlm_offered}"
            )

        # Active EPA (channel-binding) test — only when HTTPS offers NTLM and we
        # hold an NTLM-usable credential. HTTP relay is EPA-agnostic (no TLS
        # channel), so we never need it for the HTTP-only case.
        epa_enforced: bool | None = None
        if https.ntlm_offered and credential is not None and credential.has_secret():
            epa_enforced = await self._probe_epa_over_https(
                host, 443, timeout, credential
            )
            print_info_verbose(
                f"[adcs-web-probe] EPA test host={masked}: epa_enforced={epa_enforced}"
            )
        elif https.ntlm_offered:
            print_info_debug(
                f"[adcs-web-probe] EPA test skipped for host={masked}: "
                "no NTLM credential available (state unknown)"
            )

        # ESC8 verdict — viability-based. A scheme qualifies on the 401 +
        # NTLM/Negotiate offer; HTTPS additionally requires EPA not be enforced.
        # HTTP is EPA-agnostic. Unknown EPA (None) never suppresses.
        https_viable = https.ntlm_offered and epa_enforced is not True
        answering_scheme: str | None = None
        if https_viable:
            answering_scheme = "https"
        elif http.ntlm_offered:
            answering_scheme = "http"

        enabled = answering_scheme is not None
        print_info_debug(
            f"[adcs-web-probe] ESC8 verdict for host={masked}: "
            f"enabled={enabled} answering_scheme={answering_scheme} "
            f"(https_ntlm={https.ntlm_offered} http_ntlm={http.ntlm_offered} "
            f"epa_enforced={epa_enforced})"
        )

        return WebEnrollmentProbeResult(
            target_host=host,
            web_enrollment_enabled=enabled,
            https_enabled=https.tcp_open,
            http_enabled=http.tcp_open,
            https_ntlm=https.ntlm_offered,
            http_ntlm=http.ntlm_offered,
            answering_scheme=answering_scheme,
            epa_enforced=epa_enforced,
            https_refused=https.tcp_refused,
            http_refused=http.tcp_refused,
        )

    async def _probe_epa_over_https(
        self, host: str, port: int, timeout: float, credential: WebProbeCredential
    ) -> bool | None:
        """Differential channel-binding (EPA) test with a valid credential.

        Authenticate over the TLS channel to ``/certsrv`` first without a
        channel-binding token, then with one. Mirrors Certipy's
        ``check_channel_binding`` semantics; the NTLM messages are produced by
        ``badauth`` so we control whether the ``MsvChannelBindings`` AV-pair is
        included.

        Returns True (EPA enforced), False (EPA not enforced), or None
        (inconclusive / error / bad credential).
        """
        try:
            status_no_cbt = await self._ntlm_http_auth_status(
                host, port, timeout, credential, use_cbt=False
            )
            if status_no_cbt is None:
                return None
            # Auth accepted WITHOUT a channel-binding token -> EPA not enforced.
            if status_no_cbt != 401:
                return False

            status_cbt = await self._ntlm_http_auth_status(
                host, port, timeout, credential, use_cbt=True
            )
            if status_cbt is None:
                return None
            # Accepted only WITH the channel-binding token -> EPA enforced.
            if status_cbt != 401:
                return True

            # Both attempts 401 — most likely an invalid credential; do not
            # claim EPA either way (unknown never suppresses ESC8).
            return None
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            return None

    async def _ntlm_http_auth_status(
        self,
        host: str,
        port: int,
        timeout: float,
        credential: WebProbeCredential,
        *,
        use_cbt: bool,
    ) -> int | None:
        """Run one full NTLM-over-HTTPS handshake against ``/certsrv``.

        Sends the type-1 negotiate, reads the type-2 challenge (401 +
        ``WWW-Authenticate: NTLM <token>``), then sends the type-3 authenticate
        — with or without the channel-binding AV-pair — over the same keep-alive
        TLS connection. Returns the final HTTP status, or None on any transport
        failure (treated as inconclusive by the caller).
        """
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host,
                    port,
                    ssl=ssl_context,
                    server_hostname=host,
                    limit=_MAX_HEADER_BYTES,
                ),
                timeout=timeout,
            )
        except (
            asyncio.TimeoutError,
            ConnectionRefusedError,
            ConnectionResetError,
            OSError,
            ssl.SSLError,
            socket.gaierror,
        ):
            return None

        try:
            cb_data: bytes | None = None
            if use_cbt:
                cb_data = _tls_server_endpoint_cbt_appdata(writer)
                if cb_data is None:
                    # No server certificate -> cannot build a CBT; inconclusive.
                    return None

            client = _build_ntlm_client(credential)
            spn = f"HTTP/{host}"

            negotiate, _cont, _err = await client.authenticate(None)
            writer.write(
                _build_ntlm_get(host, CERTSRV_ENROLL_PATH, negotiate, keep_alive=True)
            )
            await asyncio.wait_for(writer.drain(), timeout=timeout)

            status1, www1 = await _read_http_message(reader, timeout)
            challenge = _extract_ntlm_token(www1)
            if status1 != 401 or challenge is None:
                # No NTLM challenge to answer — cannot complete the differential.
                return status1

            auth_msg, _c2, _e2 = await client.authenticate(
                challenge, cb_data=cb_data, spn=spn
            )
            writer.write(
                _build_ntlm_get(
                    host, CERTSRV_ENROLL_PATH, auth_msg, keep_alive=False
                )
            )
            await asyncio.wait_for(writer.drain(), timeout=timeout)

            status2, _www2 = await _read_http_message(reader, timeout)
            return status2
        except (
            asyncio.TimeoutError,
            asyncio.LimitOverrunError,
            asyncio.IncompleteReadError,
            ConnectionResetError,
            ConnectionRefusedError,
            OSError,
            ssl.SSLError,
            socket.gaierror,
        ):
            return None
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            return None
        finally:
            try:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:  # noqa: BLE001
                    pass
            except Exception:  # noqa: BLE001
                pass

    async def _probe_scheme(
        self, host: str, scheme: str, port: int, timeout: float
    ) -> _SchemeProbeResult:
        """TCP pre-check, then an HTTP GET of the certsrv endpoint.

        Returns ``ntlm_offered=True`` only on the true-positive ESC8 signature
        (HTTP 401 with a ``WWW-Authenticate`` header offering NTLM/Negotiate).
        Any failure / non-401 / no-NTLM keeps the false-negative bias.
        """
        tcp_state = await self._tcp_open(host, port, timeout)
        if tcp_state != "open":
            return _SchemeProbeResult(
                tcp_open=False,
                status=None,
                ntlm_offered=False,
                tcp_refused=(tcp_state == "refused"),
            )

        try:
            status, www_authenticate = await self._http_get_certsrv(
                host, scheme, port, timeout
            )
        except (
            asyncio.TimeoutError,
            asyncio.LimitOverrunError,
            asyncio.IncompleteReadError,
            ConnectionResetError,
            ConnectionRefusedError,
            OSError,
            ssl.SSLError,
            socket.gaierror,
        ):
            # Reachable on TCP but the HTTP/TLS exchange failed — not a
            # confirmed certsrv endpoint. False-negative bias: not enabled.
            return _SchemeProbeResult(tcp_open=True, status=None, ntlm_offered=False)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            return _SchemeProbeResult(tcp_open=True, status=None, ntlm_offered=False)

        ntlm_offered = status == 401 and _offers_ntlm_or_negotiate(www_authenticate)
        return _SchemeProbeResult(
            tcp_open=True, status=status, ntlm_offered=ntlm_offered
        )

    async def _http_get_certsrv(
        self, host: str, scheme: str, port: int, timeout: float
    ) -> tuple[int | None, str]:
        """Issue ``GET /certsrv/certfnsh.asp`` and return (status, WWW-Authenticate).

        Hand-written HTTP/1.1; no redirect following. TLS verification is
        disabled for the https scheme because CA web certificates are commonly
        self-signed — we only inspect the status line and headers, never trust
        the channel for data.
        """
        ssl_context = None
        server_hostname = None
        if scheme == "https":
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            server_hostname = host

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host,
                port,
                ssl=ssl_context,
                server_hostname=server_hostname,
                limit=_MAX_HEADER_BYTES,
            ),
            timeout=timeout,
        )
        try:
            request = (
                f"GET {CERTSRV_ENROLL_PATH} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {_HTTP_USER_AGENT}\r\n"
                "Accept: */*\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("ascii")
            writer.write(request)
            await asyncio.wait_for(writer.drain(), timeout=timeout)

            header_bytes = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), timeout=timeout
            )
        finally:
            try:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:  # noqa: BLE001
                    pass
            except Exception:  # noqa: BLE001
                pass

        return parse_status_and_www_authenticate(header_bytes)

    @staticmethod
    async def _tcp_open(host: str, port: int, timeout: float) -> str:
        """Return the TCP reachability state as a tri-state string.

        ``"open"`` — a connection was established.
        ``"refused"`` — the host actively refused (ConnectionRefusedError):
            CERTAIN that nothing is listening on this port.
        ``"unknown"`` — a timeout or other transport error: NOT a certain
            closure (a flaky/slow/filtered host looks the same as a closed one
            over TCP). This distinction is load-bearing downstream: a CERTAIN
            refusal on both schemes is safe to act on (abort ESC8), but a
            timeout must NOT be treated as "closed" — doing so false-aborts a
            genuinely viable avenue whenever the CA is momentarily unresponsive.
        """
        try:
            fut = asyncio.open_connection(host, port)
            _reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            try:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:  # noqa: BLE001
                    pass
            except Exception:  # noqa: BLE001
                pass
            return "open"
        except ConnectionRefusedError:
            # Subclass of OSError — must be caught FIRST. The only certain
            # "nothing is listening here" signal.
            return "refused"
        except (asyncio.TimeoutError, OSError, socket.gaierror):
            return "unknown"
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            return "unknown"


def parse_status_and_www_authenticate(header_bytes: bytes) -> tuple[int | None, str]:
    """Parse an HTTP/1.1 response head into (status_code, joined WWW-Authenticate).

    Pure function so the FP-prevention contract is unit-testable without a
    socket. Folds repeated ``WWW-Authenticate`` headers (servers emit one per
    scheme: ``Negotiate`` then ``NTLM``) into a single comma-joined string.
    Returns ``(None, "")`` when the status line is unparseable.
    """
    text = header_bytes.decode("iso-8859-1", errors="replace")
    lines = text.split("\r\n")
    if not lines or not lines[0]:
        return None, ""

    status: int | None = None
    parts = lines[0].split(" ", 2)
    if len(parts) >= 2 and parts[0].upper().startswith("HTTP/"):
        try:
            status = int(parts[1])
        except ValueError:
            status = None

    www_authenticate_values: list[str] = []
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        if name.strip().lower() == "www-authenticate":
            stripped = value.strip()
            if stripped:
                www_authenticate_values.append(stripped)

    return status, ", ".join(www_authenticate_values)


def _offers_ntlm_or_negotiate(www_authenticate: str) -> bool:
    """True when the WWW-Authenticate header offers NTLM or Negotiate."""
    lowered = www_authenticate.lower()
    return "ntlm" in lowered or "negotiate" in lowered


def _tls_server_endpoint_cbt_appdata(writer: asyncio.StreamWriter) -> bytes | None:
    """Build the ``tls-server-end-point`` channel-binding application data.

    Reuses the exact primitive badldap applies for LDAP channel binding
    (``b'tls-server-end-point:' + sha256(cert_der)``, see
    ``vendor/badldap/badldap/connection.py``). Returned bytes are the
    ``application_data`` badauth wraps into a ``gss_channel_bindings_struct`` and
    MD5-hashes into the ``MsvChannelBindings`` NTLM AV-pair. Returns None when
    the server presented no certificate.
    """
    ssl_object = writer.get_extra_info("ssl_object")
    if ssl_object is None:
        return None
    cert_der = ssl_object.getpeercert(True)
    if not cert_der:
        return None
    return b"tls-server-end-point:" + hashlib.sha256(cert_der).digest()


def _build_ntlm_client(credential: WebProbeCredential):
    """Construct a native badauth NTLM client from a scan credential.

    NTLM is the auth type ESC8 relays, so the EPA test authenticates with NTLM
    (never Kerberos). Prefers an NT hash when present, else the password.
    """
    from badauth.common.constants import asyauthSecret  # noqa: PLC0415
    from badauth.common.credentials.ntlm import NTLMCredential  # noqa: PLC0415

    if credential.nt_hash:
        cred = NTLMCredential(
            secret=credential.nt_hash,
            username=credential.username,
            domain=credential.domain,
            stype=asyauthSecret.NT,
        )
    else:
        cred = NTLMCredential(
            secret=credential.password,
            username=credential.username,
            domain=credential.domain,
            stype=asyauthSecret.PASSWORD,
        )
    return cred.build_context()


def _build_ntlm_get(
    host: str, path: str, ntlm_token: bytes, *, keep_alive: bool
) -> bytes:
    """Build a ``GET`` carrying an NTLM token in the Authorization header."""
    token_b64 = base64.b64encode(ntlm_token).decode("ascii")
    connection = "Keep-Alive" if keep_alive else "close"
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {_HTTP_USER_AGENT}\r\n"
        f"Authorization: NTLM {token_b64}\r\n"
        "Accept: */*\r\n"
        f"Connection: {connection}\r\n"
        "\r\n"
    ).encode("ascii")


async def _read_http_message(
    reader: asyncio.StreamReader, timeout: float
) -> tuple[int | None, str]:
    """Read one full HTTP/1.1 response, draining the body.

    Returns ``(status, joined WWW-Authenticate)``. The body is consumed (per
    ``Content-Length`` or chunked transfer encoding) so the keep-alive
    connection can carry the next request in the NTLM handshake.
    """
    head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout)
    status, headers = _parse_http_head(head)

    content_length: int | None = None
    chunked = False
    for name, value in headers:
        if name == "content-length":
            try:
                content_length = int(value.strip())
            except ValueError:
                content_length = None
        elif name == "transfer-encoding" and "chunked" in value.lower():
            chunked = True

    if chunked:
        await _drain_chunked_body(reader, timeout)
    elif content_length:
        remaining = min(content_length, _MAX_BODY_BYTES)
        while remaining > 0:
            chunk = await asyncio.wait_for(
                reader.read(min(remaining, 65536)), timeout=timeout
            )
            if not chunk:
                break
            remaining -= len(chunk)

    www = ", ".join(
        value.strip()
        for name, value in headers
        if name == "www-authenticate" and value.strip()
    )
    return status, www


async def _drain_chunked_body(reader: asyncio.StreamReader, timeout: float) -> None:
    """Consume a ``Transfer-Encoding: chunked`` body up to the terminator."""
    total = 0
    while total <= _MAX_BODY_BYTES:
        size_line = await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout=timeout)
        try:
            size = int(size_line.strip().split(b";", 1)[0], 16)
        except ValueError:
            return
        if size == 0:
            # Trailing CRLF after the final chunk.
            await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout=timeout)
            return
        # Chunk data plus its trailing CRLF.
        await asyncio.wait_for(reader.readexactly(size + 2), timeout=timeout)
        total += size


def _parse_http_head(head_bytes: bytes) -> tuple[int | None, list[tuple[str, str]]]:
    """Parse an HTTP/1.1 response head into (status, [(name_lower, value)])."""
    text = head_bytes.decode("iso-8859-1", errors="replace")
    lines = text.split("\r\n")
    if not lines or not lines[0]:
        return None, []

    status: int | None = None
    parts = lines[0].split(" ", 2)
    if len(parts) >= 2 and parts[0].upper().startswith("HTTP/"):
        try:
            status = int(parts[1])
        except ValueError:
            status = None

    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers.append((name.strip().lower(), value.strip()))
    return status, headers


def _extract_ntlm_token(www_authenticate: str) -> bytes | None:
    """Extract and base64-decode the ``NTLM <token>`` server challenge.

    Returns None when no NTLM token is present (bare ``NTLM`` offer or a
    non-NTLM scheme). Base64 tokens contain no commas, so splitting the
    comma-folded header value is safe.
    """
    for part in www_authenticate.split(","):
        part = part.strip()
        if part[:5].lower() == "ntlm " and len(part) > 5:
            token = part[5:].strip()
            if token:
                try:
                    # binascii.Error subclasses ValueError.
                    return base64.b64decode(token)
                except ValueError:
                    return None
    return None
