"""Native async unauthenticated reconnaissance probe service.

Runs the unauthenticated probes that historically required NetExec subprocess
calls (SMB null session, SMB guest session, LDAP anonymous bind) entirely on
the native async stack — aiosmb for SMB, badldap (via the LDAPS→LDAP fallback
in :mod:`ldap_transport_service`) for LDAP.

The probes execute concurrently inside a single :func:`asyncio.run` boundary
and render a Rich Live status board so the operator sees every probe progress
in real time, exactly the way the authenticated native collector does for the
authenticated phase.

Design notes
------------
* SMB probes use :func:`smb_machine_for` from :mod:`smb_transport`, which gives
  us proxy support, AES/Kerberos plumbing, and the centralized exception
  translation layer for free. Null/guest sessions are just the no-credentials
  variant of the same connection helper.
* The LDAP anonymous probe reuses :func:`async_connect_with_ldap_fallback`,
  which means we get the LDAPS→LDAP transparent downgrade out of the box —
  the same property every authenticated badldap caller depends on.
* The Live board updates at 8 fps with a per-probe spinner; the status table
  collapses to a static result table on completion. The console used is the
  shared ADscan console so spacing rules and theme stay coherent.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Literal

from rich.box import ROUNDED, SIMPLE_HEAVY
from rich.console import Group
from adscan_core.tui import LiveSession, LiveSessionConfig
from rich.panel import Panel
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from adscan_core import telemetry
from adscan_core.rich_output import (
    _get_console,
    print_info_debug,
    print_info_verbose,
)
from adscan_core.theme import ADSCAN_PRIMARY, ADSCAN_PRIMARY_DIM
from adscan_internal.rich_output import mark_sensitive


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


ProbeStatus = Literal["pending", "running", "open", "denied", "timeout", "error"]


@dataclass
class UnauthProbeConfig:
    """Inputs for a single domain unauthenticated probe sweep."""

    domain: str
    dc_ip: str
    smb_null_targets: list[str]
    smb_guest_targets: list[str]
    timeout: int = 20
    smb_port: int = 445


@dataclass
class SMBShareInfo:
    """Minimal share descriptor surfaced by aiosmb's ``list_shares``."""

    name: str
    stype: int | None = None
    remark: str | None = None


@dataclass
class SMBProbeResult:
    """Outcome of a single SMB null/guest probe against one host."""

    target: str
    auth_label: Literal["null", "guest"]
    status: ProbeStatus
    shares: list[SMBShareInfo] = field(default_factory=list)
    signing_required: bool | None = None
    error: str | None = None


@dataclass
class LDAPAnonResult:
    """Outcome of an LDAP anonymous bind probe."""

    target: str
    status: ProbeStatus
    base_dn: str | None = None
    used_ldaps: bool = False
    naming_contexts: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class UnauthProbeResults:
    """Aggregate output of all probes in one sweep."""

    smb_null: list[SMBProbeResult] = field(default_factory=list)
    smb_guest: list[SMBProbeResult] = field(default_factory=list)
    ldap_anonymous: LDAPAnonResult | None = None
    duration_seconds: float = 0.0

    @property
    def smb_null_open(self) -> bool:
        return any(r.status == "open" for r in self.smb_null)

    @property
    def smb_guest_open_targets(self) -> list[str]:
        return [r.target for r in self.smb_guest if r.status == "open"]

    @property
    def ldap_anonymous_open(self) -> bool:
        return self.ldap_anonymous is not None and self.ldap_anonymous.status == "open"


# ---------------------------------------------------------------------------
# Internal probe primitives
# ---------------------------------------------------------------------------


def _concise_exc_reason(exc: BaseException) -> str:
    """Return a one-line cause for *exc* -- ``TypeName: errno=N: short msg``.

    Used on EXPECTED failure paths (LDAPS/389 connectivity timeouts on a
    known-disabled DC, anonymous-search denials on hardened AD) so the recording
    carries the diagnostic cause without a multi-frame Python traceback. Full
    tracebacks are reserved for genuinely unexpected failures.
    """
    parts = [type(exc).__name__]
    errno = getattr(exc, "errno", None)
    if errno is not None:
        parts.append(f"errno={errno}")
    message = " ".join(str(exc).split()).strip()
    if message:
        if len(message) > 200:
            message = message[:197] + "..."
        parts.append(message)
    return ": ".join(parts)


async def _probe_smb_session(
    target: str,
    auth_label: Literal["null", "guest"],
    timeout: int,
    port: int,
) -> SMBProbeResult:
    """Probe a single SMB target with empty (null) or guest credentials.

    Both modes go through aiosmb. The null-session path uses an aiosmb-native
    capability that nothing else in the ecosystem appears to expose: the
    NTLM client in badauth/asyauth has a dormant ``credential.is_guest``
    flag (default ``False``) that, when flipped to ``True``, causes the
    NTLMSSP_AUTHENTICATE message to be emitted with ``LMResponse=b'\\x00'``
    and an empty NT response — the exact wire format Windows treats as
    *anonymous null session*. The URL factory never sets this flag, which
    is why the obvious URL forms (``smb+ntlm-password://:@host``) fail with
    ``LOGON_FAILURE`` even on DCs that gladly accept null sessions.

    A second wrinkle: the anonymous path inside ``NTLMClientNative`` calls
    ``set_version(False)`` on the credential, but the local ``flags`` it
    later passes to ``NTLMAuthenticate.construct`` still carries
    ``NEGOTIATE_VERSION`` and no ``version`` argument, raising
    ``"NEGOTIATE_VERSION set but no Version supplied"``. The smallest
    self-contained workaround is to clear that flag on the credential
    *before* connecting. Once asyauth/badauth ships the upstream fix, the
    flag-strip line below becomes a no-op and can be removed.

    Guest auth (``Guest:`` + empty password) is plain NTLMv2 — no flag
    surgery needed.
    """
    from aiosmb.commons.connection.factory import SMBConnectionFactory
    from aiosmb.commons.interfaces.machine import SMBMachine

    if auth_label == "null":
        # The host part of the URL is irrelevant for credential parsing —
        # anything non-empty avoids the URL parser short-circuiting on the
        # missing user. We then flip is_guest and strip NEGOTIATE_VERSION.
        url = f"smb+ntlm-password://Guest:@{target}:{port}/?timeout={timeout}"
    else:
        url = f"smb+ntlm-password://Guest:@{target}:{port}/?timeout={timeout}"

    try:
        factory = SMBConnectionFactory.from_url(url)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return SMBProbeResult(
            target=target,
            auth_label=auth_label,
            status="error",
            error=f"URL factory error: {exc}",
        )

    if auth_label == "null":
        try:
            from badauth.protocols.ntlm.structures.negotiate_flags import (
                NegotiateFlags,
            )
        except ImportError:
            try:
                from badauth.protocols.ntlm.structures.negotiate_flags import (
                    NegotiateFlags,
                )
            except ImportError as exc:
                return SMBProbeResult(
                    target=target,
                    auth_label="null",
                    status="error",
                    error=f"NTLM negotiate flags unavailable: {exc}",
                )
        # Activate the dormant anonymous NTLMSSP path and dodge the upstream
        # NEGOTIATE_VERSION-without-version bug.
        factory.credential.is_guest = True
        factory.credential.flags &= ~NegotiateFlags.NEGOTIATE_VERSION

    conn = factory.get_connection()
    shares: list[SMBShareInfo] = []
    try:
        async with conn:
            _, err = await asyncio.wait_for(conn.login(), timeout=timeout)
            if err is not None:
                raise err

            machine = SMBMachine(conn)
            async with machine:
                try:
                    async for share, share_err in machine.list_shares():
                        if share_err is not None:
                            print_info_debug(
                                f"unauth-probe smb-{auth_label}: share iter "
                                f"error on {target}: {share_err}"
                            )
                            break
                        if share is None:
                            continue
                        shares.append(
                            SMBShareInfo(
                                name=str(getattr(share, "name", "") or "").strip(),
                                stype=getattr(share, "type", None),
                                remark=str(getattr(share, "remark", "") or "").strip()
                                or None,
                            )
                        )
                except Exception as iter_exc:  # noqa: BLE001
                    print_info_debug(
                        f"unauth-probe smb-{auth_label}: list_shares failed on "
                        f"{target}: {iter_exc}"
                    )

        return SMBProbeResult(
            target=target,
            auth_label=auth_label,
            status="open",
            shares=[s for s in shares if s.name],
        )
    except asyncio.TimeoutError:
        return SMBProbeResult(
            target=target,
            auth_label=auth_label,
            status="timeout",
            error=f"login/list_shares timed out after {timeout}s",
        )
    except Exception as exc:  # noqa: BLE001
        msg = str(exc)
        lower = msg.lower()
        if any(
            marker in lower
            for marker in (
                "logon_failure",
                "access_denied",
                "account_disabled",
                "authentication probably failed",
            )
        ):
            return SMBProbeResult(
                target=target,
                auth_label=auth_label,
                status="denied",
                error=msg,
            )
        if "timeout" in lower or "timed out" in lower:
            return SMBProbeResult(
                target=target,
                auth_label=auth_label,
                status="timeout",
                error=msg,
            )
        telemetry.capture_exception(exc)
        return SMBProbeResult(
            target=target,
            auth_label=auth_label,
            status="error",
            error=msg,
        )


async def _probe_ldap_anonymous(
    dc_ip: str,
    timeout: int,
) -> LDAPAnonResult:
    """Probe LDAP anonymous bind and validate that *enumeration* actually works.

    A non-empty RootDSE is not enough: hardened DCs (e.g. HTB Active, any
    domain with ``dsHeuristics fLDAPBlockAnonOps=1``) leak ``defaultNamingContext``
    over an unauthenticated TCP/TLS connection but reject every subsequent
    search with ``operationsError`` / ``ERROR_NOT_AUTHENTICATED``. Classifying
    that as ``open`` misleads downstream enrichment.

    Procedure:
      1. Open an explicit ``ldap+simple://`` (or ``ldaps+simple://``) bind with
         empty credentials. RFC 4513 §5.1.1 says servers MUST treat that as
         anonymous, which is exactly the wire pattern that NetExec's
         ``--active-users`` uses and what badldap's ``pagedsearch`` requires.
      2. Read the RootDSE for ``defaultNamingContext``.
      3. Issue a single bounded scoped search of ``(objectClass=user)`` with
         ``size_limit=1`` against ``base_dn``. If that fails with an LDAP
         operations / not-authenticated error, classify as ``denied``. If it
         returns an entry (or zero entries with no error), classify as
         ``open``.
    """
    # NOTE(ldap-centralization): this anonymous simple-bind probe owns its own
    # LDAPS->LDAP fallback loop (allow-listed in
    # tests/unit/services/test_no_direct_ldap_connection.py).
    # TODO(ldap-centralization): migrate to
    # async_connect_anonymous_with_ldap_fallback once that helper lands.
    from badldap.commons.factory import LDAPConnectionFactory

    from adscan_internal.services.ldap_transport_service import (
        is_ldaps_transport_failure,
    )

    # Try simple-bind on LDAPS first, then plain LDAP.
    #
    # A connectivity failure on LDAPS:636 (a TCP timeout when 636 is silently
    # DROPped, or a ConnectionError when it is RST/REJECTed) is NEVER an auth
    # failure -- it must fall through to plain LDAP/389 exactly like the
    # authenticated wrappers do. We therefore capture the exception and try the
    # next transport instead of short-circuiting; the final state is decided
    # only AFTER both transports have been exhausted. The historical bug here
    # returned ``status="timeout"`` on the FIRST transport's TimeoutError,
    # which reported "timeout" on a 636-filtered host even when 389 was open.
    last_exc: Exception | None = None
    last_failure_was_timeout = False
    conn = None
    used_ldaps = False
    for transport, port in (("ldaps", 636), ("ldap", 389)):
        url = f"{transport}+simple://@{dc_ip}:{port}"
        try:
            factory = LDAPConnectionFactory.from_url(url)
            client = factory.get_client()
            if hasattr(client, "_disable_signing"):
                client._disable_signing = True
            if hasattr(client, "_disable_channel_binding"):
                client._disable_channel_binding = True
            ok, err = await asyncio.wait_for(client.connect(), timeout=timeout)
            if not ok:
                raise err or RuntimeError(
                    f"{transport.upper()} connect returned ok=False"
                )
            conn = client
            used_ldaps = transport == "ldaps"
            break
        except Exception as exc:  # noqa: BLE001
            # A connectivity failure here (timeout when 636 is filtered, RST when
            # refused, TLS handshake error) is EXPECTED on a hardened/known-
            # disabled DC and simply falls through to the next transport, so log a
            # concise one-line cause instead of flooding the recording with a
            # multi-frame traceback per fallback. A full traceback is kept only
            # for a genuinely unexpected exception.
            if is_ldaps_transport_failure(exc):
                print_info_debug(
                    f"ldap_probe: {transport.upper()}:{port} transport failure: "
                    f"{_concise_exc_reason(exc)}"
                )
            else:
                import traceback as _tb
                print_info_debug(
                    f"ldap_probe: {transport.upper()}:{port} unexpected exception: "
                    f"{type(exc).__name__}: {exc}\n"
                    + "".join(_tb.format_tb(exc.__traceback__))
                )
            last_exc = exc
            # Record whether the most recent attempt failed for a timeout
            # reason so that, once every transport is exhausted, we can report
            # "timeout" (an inferred-by-absence, non-committal verdict the
            # posture layer keeps UNKNOWN/LOW and re-probes) rather than a
            # spurious "error"/"denied". We gate the timeout flag through the
            # central ``is_ldaps_transport_failure`` classifier -- the same one
            # the authenticated LDAPS->LDAP fallback uses -- so a TimeoutError
            # only sets the inferred-by-absence verdict when it is genuinely a
            # connectivity event.
            is_timeout = isinstance(exc, (asyncio.TimeoutError, TimeoutError))
            last_failure_was_timeout = is_timeout and is_ldaps_transport_failure(exc)
            # Both connectivity failures (timeout / ConnectionError) and
            # non-connectivity failures fall through to the next transport; we
            # never short-circuit before trying plain LDAP/389.
            continue

    if conn is None:
        telemetry.capture_exception(last_exc) if last_exc else None
        # Both transports were exhausted. A timeout on the final attempt is an
        # inferred-by-absence signal (we ran out of time; the DC told us
        # nothing): report "timeout" so the posture layer never derives a false
        # HIGH verdict and re-probes on the next contact.
        if last_failure_was_timeout:
            return LDAPAnonResult(
                target=dc_ip,
                status="timeout",
                error=(
                    f"LDAP anonymous probe timed out after {timeout}s on both "
                    "LDAPS/636 and LDAP/389"
                ),
            )
        msg = str(last_exc) if last_exc else "Anonymous LDAP bind failed"
        lower = msg.lower()
        status: ProbeStatus = (
            "denied"
            if any(k in lower for k in ("bind", "credentials", "auth", "denied"))
            else "error"
        )
        return LDAPAnonResult(target=dc_ip, status=status, error=msg)

    base_dn: str | None = None
    naming_contexts: list[str] = []
    try:
        # ── 1) RootDSE → base DN ─────────────────────────────────────────
        server_info = None
        if hasattr(conn, "get_server_info"):
            server_info = conn.get_server_info()
        if not server_info:
            server_info = getattr(conn, "_serverinfo", None)
        if isinstance(server_info, dict):
            raw_default = server_info.get("defaultNamingContext")
            if isinstance(raw_default, list):
                base_dn = str(raw_default[0]) if raw_default else None
            elif raw_default:
                base_dn = str(raw_default)

            raw_contexts = server_info.get("namingContexts")
            if isinstance(raw_contexts, list):
                naming_contexts = [str(c) for c in raw_contexts if c]
            elif raw_contexts:
                naming_contexts = [str(raw_contexts)]

        # No RootDSE at all → directory will not disclose anything to an
        # anonymous principal.
        if not base_dn and not naming_contexts:
            return LDAPAnonResult(
                target=dc_ip,
                status="denied",
                used_ldaps=used_ldaps,
                error="Anonymous bind returned empty RootDSE",
            )

        # ── 2) Validate that a *search* is actually allowed ──────────────
        # If the directory leaks RootDSE but rejects searches (hardened AD,
        # e.g. fLDAPBlockAnonOps), classify as denied — the enrichment
        # phase cannot do anything useful with this surface.
        search_base = base_dn or (naming_contexts[0] if naming_contexts else "")
        if not search_base:
            return LDAPAnonResult(
                target=dc_ip,
                status="denied",
                used_ldaps=used_ldaps,
                base_dn=base_dn,
                naming_contexts=naming_contexts,
                error="No usable naming context for search probe",
            )

        try:
            saw_entry = False
            async for item, err in conn.pagedsearch(  # type: ignore[union-attr]
                "(objectClass=user)",
                ["sAMAccountName"],
                controls=None,
                tree=search_base,
                search_scope=2,  # SUBTREE
            ):
                if err is not None:
                    raise err
                if item:
                    saw_entry = True
                    break  # one entry is enough — search is allowed
        except Exception as search_exc:  # noqa: BLE001
            msg = str(search_exc)
            lower = msg.lower()
            denial_markers = (
                "operationserror",
                "not_authenticated",
                "successful bind must be completed",
                "ldapprotocolerror",
                "ldapoperationserror",
                "insufficient access",
                "0c09075a",
                "connected, but not bound",
            )
            if any(m in lower for m in denial_markers):
                # Anonymous bind allowed but search denied (RootDSE-only, hardened
                # AD) is an EXPECTED outcome -- log a concise one-line cause, not a
                # multi-frame traceback.
                print_info_debug(
                    f"ldap_probe: anonymous search denied: {_concise_exc_reason(search_exc)}"
                )
                return LDAPAnonResult(
                    target=dc_ip,
                    status="denied",
                    used_ldaps=used_ldaps,
                    base_dn=base_dn,
                    naming_contexts=naming_contexts,
                    error="anonymous bind allowed but search denied (RootDSE only)",
                )
            # Genuinely unexpected search failure -- keep the full traceback.
            import traceback as _tb
            print_info_debug(
                f"ldap_probe: pagedsearch unexpected exception: "
                f"{type(search_exc).__name__}: {search_exc}\n"
                + "".join(_tb.format_tb(search_exc.__traceback__))
            )
            telemetry.capture_exception(search_exc)
            return LDAPAnonResult(
                target=dc_ip,
                status="error",
                used_ldaps=used_ldaps,
                base_dn=base_dn,
                naming_contexts=naming_contexts,
                error=msg,
            )

        # Search returned with no error — bind + search BOTH work.
        _ = saw_entry  # zero entries with no error is still a valid "open"
        return LDAPAnonResult(
            target=dc_ip,
            status="open",
            base_dn=base_dn,
            used_ldaps=used_ldaps,
            naming_contexts=naming_contexts,
        )
    finally:
        try:
            disconnect = getattr(conn, "disconnect", None)
            if disconnect is not None:
                maybe_coro = disconnect()
                if asyncio.iscoroutine(maybe_coro):
                    await maybe_coro
        except Exception as exc:  # noqa: BLE001
            print_info_debug(f"unauth-probe ldap-anon: disconnect error: {exc}")


# ---------------------------------------------------------------------------
# Live status board
# ---------------------------------------------------------------------------


_PROBE_ICONS: dict[ProbeStatus, tuple[str, str]] = {
    "pending": ("•", "dim"),
    "running": ("⠿", ADSCAN_PRIMARY),
    "open": ("✓", "bold green"),
    "denied": ("✗", "yellow"),
    "timeout": ("⏱", "yellow"),
    "error": ("✗", "red"),
}

_STATUS_LABEL: dict[ProbeStatus, str] = {
    "pending": "queued",
    "running": "probing…",
    "open": "OPEN",
    "denied": "denied",
    "timeout": "timeout",
    "error": "error",
}


@dataclass
class _ProbeRow:
    """One row in the live status board."""

    key: str
    name: str
    target: str
    port: int
    status: ProbeStatus = "pending"
    summary: str = ""


def _summarize_smb(result: SMBProbeResult) -> str:
    if result.status != "open":
        return result.error or _STATUS_LABEL[result.status]
    if not result.shares:
        return "session accepted, no shares enumerated"
    visible = [s.name for s in result.shares if s.name]
    head = ", ".join(visible[:5])
    if len(visible) > 5:
        head += f" (+{len(visible) - 5} more)"
    return f"{len(visible)} share{'s' if len(visible) != 1 else ''}: {head}"


def _summarize_ldap(result: LDAPAnonResult) -> str:
    if result.status != "open":
        return result.error or _STATUS_LABEL[result.status]
    transport = "LDAPS" if result.used_ldaps else "LDAP"
    if result.base_dn:
        return f"bind allowed via {transport} — base: {result.base_dn}"
    return f"bind allowed via {transport}"


def _render_board(rows: list[_ProbeRow], header: dict[str, str]) -> Group:
    """Build the Rich renderable shown inside the Live context."""
    spinner = Spinner("dots", style=ADSCAN_PRIMARY)

    header_table = Table.grid(padding=(0, 2))
    header_table.add_column(style="dim", justify="right")
    header_table.add_column(style="white")
    for key, value in header.items():
        header_table.add_row(f"{key}:", value)

    title = Text("🛰  Unauthenticated Reconnaissance", style=f"bold {ADSCAN_PRIMARY}")
    header_panel = Panel(
        Group(title, Text(""), header_table),
        border_style=ADSCAN_PRIMARY,
        padding=(1, 2),
        box=ROUNDED,
    )

    body = Table.grid(padding=(0, 1), expand=False)
    body.add_column(width=3)
    body.add_column(min_width=22)
    body.add_column(min_width=22, style="cyan")
    body.add_column(min_width=10, justify="center")
    body.add_column()

    for row in rows:
        icon_glyph, icon_style = _PROBE_ICONS[row.status]
        if row.status == "running":
            icon_renderable: Any = spinner
        else:
            icon_renderable = Text(icon_glyph, style=icon_style)

        name_text = Text(row.name, style="bold white")

        target_text = mark_sensitive(f"{row.target}:{row.port}", "ip")

        status_label = _STATUS_LABEL[row.status]
        status_style = _PROBE_ICONS[row.status][1]
        status_text = Text(status_label.upper(), style=f"bold {status_style}")

        summary_text = Text(row.summary or "", style="dim white")

        body.add_row(icon_renderable, name_text, target_text, status_text, summary_text)

    body_panel = Panel(
        body,
        border_style=ADSCAN_PRIMARY_DIM,
        padding=(1, 2),
        box=ROUNDED,
        title=f"[bold {ADSCAN_PRIMARY}]Probes[/bold {ADSCAN_PRIMARY}]",
        title_align="left",
    )

    return Group(header_panel, body_panel)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


async def run_unauth_probes_async(config: UnauthProbeConfig) -> UnauthProbeResults:
    """Run all probes concurrently with a Rich Live status board."""
    results = UnauthProbeResults()
    rows: list[_ProbeRow] = []
    row_index: dict[str, _ProbeRow] = {}

    def _add_row(key: str, name: str, target: str, port: int) -> _ProbeRow:
        row = _ProbeRow(key=key, name=name, target=target, port=port)
        rows.append(row)
        row_index[key] = row
        return row

    # SMB null
    null_targets = [t for t in config.smb_null_targets if t]
    if not null_targets and config.dc_ip:
        null_targets = [config.dc_ip]
    for target in null_targets:
        _add_row(f"smb_null::{target}", "SMB Null Session", target, config.smb_port)

    # SMB guest (skip duplicates against null targets — same auth surface, denial is implied)
    null_set = set(null_targets)
    guest_targets = [t for t in config.smb_guest_targets if t]
    for target in guest_targets:
        _add_row(f"smb_guest::{target}", "SMB Guest Session", target, config.smb_port)

    # LDAP anonymous
    if config.dc_ip:
        _add_row("ldap_anon::root", "LDAP Anonymous Bind", config.dc_ip, 389)

    header = {
        "Domain": mark_sensitive(config.domain, "domain"),
        "DC": mark_sensitive(config.dc_ip, "ip"),
        "Probes": str(len(rows)),
        "Mode": "Concurrent (native aiosmb + badldap)",
        "Timeout": f"{config.timeout}s per probe",
    }

    async def _drive_smb_null(target: str) -> None:
        row = row_index[f"smb_null::{target}"]
        row.status = "running"
        result = await _probe_smb_session(
            target, "null", config.timeout, config.smb_port
        )
        results.smb_null.append(result)
        row.status = result.status
        row.summary = _summarize_smb(result)

    async def _drive_smb_guest(target: str) -> None:
        row = row_index[f"smb_guest::{target}"]
        row.status = "running"
        result = await _probe_smb_session(
            target, "guest", config.timeout, config.smb_port
        )
        results.smb_guest.append(result)
        row.status = result.status
        row.summary = _summarize_smb(result)

    async def _drive_ldap_anon() -> None:
        row = row_index["ldap_anon::root"]
        row.status = "running"
        result = await _probe_ldap_anonymous(config.dc_ip, config.timeout)
        results.ldap_anonymous = result
        row.status = result.status
        row.summary = _summarize_ldap(result)
        row.port = 636 if result.used_ldaps else 389

    drivers: list[Any] = []
    drivers.extend(_drive_smb_null(t) for t in null_targets)
    drivers.extend(_drive_smb_guest(t) for t in guest_targets if t not in null_set or t)
    if config.dc_ip:
        drivers.append(_drive_ldap_anon())

    # Guard: nothing to do
    if not drivers:
        return results

    start = time.monotonic()
    tasks = [asyncio.create_task(d) for d in drivers]
    try:
        # alt_screen=False: the probe board stays inline; the per-probe
        # status table is short and the operator wants it in scrollback
        # alongside the unauth findings that follow.
        _live_cfg = LiveSessionConfig(refresh_per_second=8, alt_screen=False)
        async with LiveSession(
            _render_board(rows, header), config=_live_cfg
        ) as session:
            while not all(t.done() for t in tasks):
                session.update(_render_board(rows, header))
                await asyncio.sleep(0.12)
            await asyncio.gather(*tasks, return_exceptions=True)
            session.update(_render_board(rows, header))
    finally:
        results.duration_seconds = time.monotonic() - start

    return results


def run_unauth_probes(config: UnauthProbeConfig) -> UnauthProbeResults:
    """Synchronous entry point for callers outside an event loop.

    Falls back to ``run_until_complete`` on a fresh loop when ``asyncio.run``
    is not available (e.g. when called from a context that already manages
    an event loop in another thread).
    """
    try:
        return asyncio.run(run_unauth_probes_async(config))
    except RuntimeError as exc:
        # Defensive: another loop is already running on this thread. We do
        # not silently swallow this — surface a clear, actionable error.
        if "asyncio.run() cannot be called" in str(exc) or "running event loop" in str(
            exc
        ):
            raise RuntimeError(
                "run_unauth_probes was invoked from inside a running asyncio loop. "
                "Use `await run_unauth_probes_async(config)` instead."
            ) from exc
        raise


# ---------------------------------------------------------------------------
# Result rendering — final summary tables
# ---------------------------------------------------------------------------


def render_smb_share_table(
    results: list[SMBProbeResult],
    *,
    domain: str,
    auth_label: str,
) -> None:
    """Render a Rich table of discovered SMB shares for one auth label."""
    open_results = [r for r in results if r.status == "open" and r.shares]
    if not open_results:
        return

    title_session = "null session" if auth_label == "null" else "guest session"
    table = Table(
        title=(
            f"[bold cyan]SMB shares discovered on {mark_sensitive(domain, 'domain')} "
            f"({title_session})[/bold cyan]"
        ),
        header_style=f"bold {ADSCAN_PRIMARY}",
        box=SIMPLE_HEAVY,
    )
    table.add_column("Target", style="cyan")
    table.add_column("Share", style="bright_cyan")
    table.add_column("Type", justify="center", style="dim")
    table.add_column("Remark")

    priority = {"SYSVOL": 0, "NETLOGON": 1, "IPC$": 2}
    for result in open_results:
        ordered_shares = sorted(
            result.shares,
            key=lambda s: (priority.get(s.name.upper(), 99), s.name.lower()),
        )
        first = True
        for share in ordered_shares:
            stype_label = ""
            if share.stype is not None:
                # 0 = disk, 1 = print, 3 = device, 0x80000000 = special (IPC$, ADMIN$)
                stype_label = "DISK" if int(share.stype) & 0xFF == 0 else "OTHER"
            table.add_row(
                mark_sensitive(result.target, "ip") if first else "",
                share.name,
                stype_label,
                share.remark or "",
            )
            first = False

    panel = Panel(table, border_style="bright_blue", box=ROUNDED, padding=(0, 1))
    console = _get_console()
    console.print(panel)


def render_unauth_summary(results: UnauthProbeResults, *, domain: str) -> None:
    """Print a short summary panel after probes complete."""
    rows: list[Text] = []

    if results.smb_null:
        smb_open = [r for r in results.smb_null if r.status == "open"]
        if smb_open:
            total_shares = sum(len(r.shares) for r in smb_open)
            rows.append(
                Text.from_markup(
                    f"[bold green]✓[/] SMB null session [bold]OPEN[/] on "
                    f"{len(smb_open)}/{len(results.smb_null)} target(s) — "
                    f"{total_shares} share(s) discovered"
                )
            )
        else:
            rows.append(
                Text.from_markup(
                    f"[yellow]✗[/] SMB null session denied on all "
                    f"{len(results.smb_null)} target(s)"
                )
            )

    if results.smb_guest:
        guest_open = [r for r in results.smb_guest if r.status == "open"]
        if guest_open:
            total_shares = sum(len(r.shares) for r in guest_open)
            rows.append(
                Text.from_markup(
                    f"[bold green]✓[/] SMB guest session [bold]OPEN[/] on "
                    f"{len(guest_open)}/{len(results.smb_guest)} target(s) — "
                    f"{total_shares} share(s) discovered"
                )
            )
        else:
            rows.append(
                Text.from_markup(
                    f"[yellow]✗[/] SMB guest session denied on all "
                    f"{len(results.smb_guest)} target(s)"
                )
            )

    if results.ldap_anonymous is not None:
        ldap = results.ldap_anonymous
        if ldap.status == "open":
            transport = "LDAPS" if ldap.used_ldaps else "LDAP"
            base = f" — base DN: {ldap.base_dn}" if ldap.base_dn else ""
            rows.append(
                Text.from_markup(
                    f"[bold green]✓[/] LDAP anonymous bind [bold]ALLOWED[/] "
                    f"via {transport}{base}"
                )
            )
        else:
            rows.append(
                Text.from_markup(f"[yellow]✗[/] LDAP anonymous bind {ldap.status}")
            )

    rows.append(
        Text.from_markup(
            f"[dim]Total probe time: {results.duration_seconds:.2f}s[/dim]"
        )
    )

    panel = Panel(
        Group(*rows),
        title=f"[bold {ADSCAN_PRIMARY}]Unauthenticated Recon Summary[/]",
        title_align="left",
        border_style=ADSCAN_PRIMARY,
        box=ROUNDED,
        padding=(1, 2),
    )
    _get_console().print(panel)
    print_info_verbose(
        f"unauth-probe sweep finished in {results.duration_seconds:.2f}s"
    )
