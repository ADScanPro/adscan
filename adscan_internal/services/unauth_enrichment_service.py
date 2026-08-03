"""Native async unauthenticated enrichment service.

When the unauthenticated probe (:mod:`unauth_probe_service`) confirms that a
domain controller accepts SMB null sessions and/or LDAP anonymous binds, this
service mines that surface for actionable intel **without ever shelling out
to NetExec, impacket, or Get-GPPPassword**:

* **LDAP active users** — anonymous paged search for enabled user objects,
  mirroring :func:`enumeration.ldap.LDAPEnumerationMixin.query_anonymous_user_inventory`
  but flattened to the small set of fields the unauth phase actually consumes.
* **SAMR users via null session** — full ``list_domain_users`` enumeration
  through an aiosmb null SMB session and the SAMR DCERPC pipe.
* **SAMR user descriptions** — per-RID ``hSamrQueryInformationUser`` with
  ``UserAllInformation`` to surface description / comment / UAC flags.
* **GPP cpassword leaks** — recursive SYSVOL walk via aiosmb's
  :func:`SMBMachine.get_cpasswd`, then native AES-256-CBC decrypt with the
  Microsoft-published static key (no external tool dependency).

Design rules
------------
* A **single** null SMB session is opened and reused across SAMR enumeration,
  per-user description fetch, and GPP harvesting. Opening parallel null
  sessions against the same DC produces flaky behaviour on hardened boxes
  and burns connection slots.
* Per-user SAMR description fetches are bounded by an
  :class:`asyncio.Semaphore` of size 8 — fast on lab boxes, polite on
  production DCs.
* User-description fetches are capped at ``config.max_user_descriptions``
  to avoid enumerating ten-thousand-user domains synchronously.
* All exceptions are captured via :func:`telemetry.capture_exception` and
  surfaced through the ``errors`` map on :class:`UnauthEnrichmentResults`;
  no exception ever escapes the public entry points.
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
    print_exception,
    print_info_debug,
    print_info_verbose,
)
from adscan_core.theme import (
    ADSCAN_PRIMARY,
    ADSCAN_PRIMARY_BRIGHT,
    ADSCAN_PRIMARY_DIM,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.credential_disclosure_detection import (
    detect_credential_disclosure,
    is_builtin_principal,
)


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


TaskStatus = Literal["skipped", "running", "done", "error", "denied"]

# UF_DONT_REQUIRE_PREAUTH — AS-REP roastable accounts.
UF_DONT_REQUIRE_PREAUTH = 0x400000


@dataclass
class UnauthEnrichmentConfig:
    """Inputs for one unauthenticated enrichment sweep."""

    domain: str
    dc_ip: str
    smb_null_open: bool
    ldap_anon_open: bool
    smb_readable_targets: list[str]
    workspace_dir: str
    timeout: int = 60
    max_user_descriptions: int = 500
    # Guest-session config for LSARPC RID Cycling.  When provided, RID
    # cycling runs as a 5th enrichment task gated on SAMR's outcome (only
    # when SAMR returns 0 users or is denied — RID cycling is redundant
    # otherwise).  ``None`` means guest session is closed or unavailable.
    smb_guest_config: Any | None = None
    rid_cycling_first_pass_end: int = 2000
    rid_cycling_second_pass_end: int = 10000


@dataclass
class LDAPActiveUser:
    """One LDAP user record harvested via anonymous bind."""

    samaccountname: str
    distinguished_name: str = ""
    description: str = ""
    user_account_control: int = 0
    last_logon_timestamp: str | None = None
    asreproast_eligible: bool = False
    #: Carried so a Windows built-in is recognised by RID rather than by its
    #: description text, which is localised per install.
    object_sid: str = ""


# SAMRUser is owned by native_samr_service so unauth + auth flows share one
# dataclass. Re-exported here for backward compatibility (existing imports
# such as the htb_active_unauth_probe validator still resolve).
from adscan_internal.services.native_samr_service import SAMRUser  # noqa: E402,F401


# Re-export the canonical leak dataclasses from the unified harvester so
# existing imports (``from unauth_enrichment_service import GPPLeak``) keep
# resolving without pulling the old shim back into the codebase.
from adscan_internal.services.gpp_credential_harvester import (  # noqa: E402,F401
    GPPAutologinLeak,
    GPPCpasswordLeak as GPPLeak,
)


@dataclass
class UnauthEnrichmentResults:
    """Aggregate outcome of an enrichment sweep."""

    ldap_active_users: list[LDAPActiveUser] = field(default_factory=list)
    # Common-names without a confirmed sAMAccountName, collected from anonymous
    # LDAP nodes where the DC disclosed the object but not the account name.
    # These are fed into CN inference + kerbrute validation downstream.
    ldap_cn_only_records: list[str] = field(default_factory=list)
    samr_users: list[SAMRUser] = field(default_factory=list)
    gpp_leaks: list[GPPLeak] = field(default_factory=list)
    gpp_autologin_leaks: list[GPPAutologinLeak] = field(default_factory=list)
    duration_seconds: float = 0.0

    ldap_active_users_status: TaskStatus = "skipped"
    samr_users_status: TaskStatus = "skipped"
    samr_descriptions_status: TaskStatus = "skipped"
    gpp_status: TaskStatus = "skipped"

    # LSARPC RID Cycling via guest session — gated on SAMR's outcome.
    # ``rid_cycling_users`` holds raw LSARPCRidEntry records from the
    # native_lsarpc_service for the caller's merge step; status tracks
    # whether the technique ran, and ``rid_cycling_reason`` carries
    # human-readable context (e.g. "SAMR returned 47 users — redundant").
    rid_cycling_users: list[Any] = field(default_factory=list)
    rid_cycling_status: TaskStatus = "skipped"
    rid_cycling_reason: str = ""

    errors: dict[str, str] = field(default_factory=dict)

    @property
    def asreproast_eligible_users(self) -> list[str]:
        return [
            u.samaccountname for u in self.ldap_active_users if u.asreproast_eligible
        ]

    @property
    def sensitive_descriptions(self) -> list[tuple[str, str]]:
        """Accounts whose directory attributes disclose a credential.

        The judgement is the shared one in
        :mod:`adscan_internal.services.credential_disclosure_detection`, so the
        unauthenticated sweep and the authenticated LDAP description sweep can
        never disagree about what counts as a leak. A keyword on its own is
        prose, and a Windows built-in's stock description — localised, and the
        same on every domain on earth — is not a finding.
        """
        out: list[tuple[str, str]] = []
        for u in self.ldap_active_users:
            if not u.description:
                continue
            builtin = is_builtin_principal(
                samaccountname=u.samaccountname, object_sid=u.object_sid
            )
            if detect_credential_disclosure(
                "description", u.description, builtin=builtin
            ):
                out.append((u.samaccountname, u.description))
        for s in self.samr_users:
            builtin = is_builtin_principal(samaccountname=s.username, rid=s.rid)
            for field_name, text in (
                ("description", s.description or ""),
                ("comment", s.comment or ""),
                ("displayName", s.full_name or ""),
            ):
                if text and detect_credential_disclosure(
                    field_name, text, builtin=builtin
                ):
                    out.append((s.username, text.strip()))
                    break
        # Dedup on (username, text)
        seen: set[tuple[str, str]] = set()
        unique: list[tuple[str, str]] = []
        for entry in out:
            if entry in seen:
                continue
            seen.add(entry)
            unique.append(entry)
        return unique


# ---------------------------------------------------------------------------
# GPP cpassword decrypt — re-export the canonical helper from the unified
# harvester. Kept as a module-level alias so any external caller importing
# ``_decrypt_gpp_cpassword`` from this module keeps working.
# ---------------------------------------------------------------------------

from adscan_internal.services.gpp_credential_harvester import (  # noqa: E402,F401
    decrypt_gpp_cpassword as _decrypt_gpp_cpassword,
)


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# LDAP active-user harvest — runs the canonical ADscanLDAPCollector with
# anonymous SIMPLE-bind credentials and a narrow scope so this service stays
# in lock-step with the authenticated path.
# ---------------------------------------------------------------------------


async def _enrich_ldap_via_collector(
    *,
    domain: str,
    dc_ip: str,
    timeout: int,
) -> tuple[list[LDAPActiveUser], list[str], "TaskStatus"]:
    """Run :class:`ADscanLDAPCollector` with anonymous credentials + a narrow
    scope and project the resulting :class:`CollectorNode` users into
    :class:`LDAPActiveUser` records.

    Why the collector, not a bespoke pagedsearch:
        Before this refactor the unauth path duplicated ~150 lines of LDAP
        plumbing. That made every bug fix (LDAPS fallback, channel-binding,
        SIMPLE-bind state machine) a two-place change. The collector is the
        single source of truth for LDAP enumeration in ADscan; running it
        with anonymous creds and a narrow scope yields the same data shape
        the authenticated path produces.

    Returns:
        A ``(ldap_active_users, cn_only_names, status)`` triple.
        ``cn_only_names`` contains the raw ``node.name`` values (or parts
        thereof) for User nodes whose ``samaccountname`` was not disclosed
        by the anonymous bind. These are passed through CN inference and
        kerbrute validation downstream.

    Status mapping:
        * ``done`` — the collector returned at least one user node, or the
          underlying connection succeeded and the search produced an empty
          (but valid) result (the typical hardened-DC outcome).
        * ``denied`` — every collector phase raised, leaving zero nodes and
          zero edges. The collector's per-phase try/except converts denied
          searches into empty results, so reaching truly-zero requires
          either the bind itself failing or every search being rejected.
        * ``error`` — bubbles up via the caller's exception handler.

    The ``narrow_unauth`` scope opts OUT of ACL/membership/GPO-link/trust
    queries that anonymous binds typically can't satisfy, capped at 500
    user / 200 group / 200 computer entries to keep the sweep fast.
    """
    from adscan_internal.services.collector.ldap_collector import (
        ADscanLDAPCollector,
    )
    from adscan_internal.services.collector.ldap_credentials import (
        LDAPCredentials,
    )
    from adscan_internal.services.collector.ldap_scope import (
        LDAPCollectionScope,
    )

    credentials = LDAPCredentials.anonymous(domain=domain, dc_ip=dc_ip)
    scope = LDAPCollectionScope.narrow_unauth()

    def _run() -> Any:
        return ADscanLDAPCollector().collect(credentials=credentials, scope=scope)

    try:
        result = await asyncio.wait_for(asyncio.to_thread(_run), timeout=timeout)
    except asyncio.TimeoutError:
        return [], [], "error"

    users: list[LDAPActiveUser] = []
    cn_only_names: list[str] = []
    for node in result.nodes.values():
        if node.kind != "User":
            continue
        sam = node.samaccountname or ""
        cn_like = node.name.split("@", 1)[0] if node.name else ""
        if not sam and not cn_like:
            continue
        if not sam:
            # The DC disclosed the object but not the sAMAccountName.
            # Stash the CN-like string for downstream username inference.
            if cn_like:
                cn_only_names.append(cn_like)
            continue
        props = node.properties or {}
        # ``hasunconstrainedauth`` / ``dontreqpreauth`` are pre-decoded by the
        # collector — recompose ``user_account_control`` only insofar as
        # downstream consumers consult ``asreproast_eligible``.
        uac = 0
        if props.get("dontreqpreauth"):
            uac |= UF_DONT_REQUIRE_PREAUTH
        last_logon = props.get("lastlogon")
        users.append(
            LDAPActiveUser(
                samaccountname=str(sam),
                distinguished_name=node.distinguished_name or "",
                description=str(props.get("description") or "").strip(),
                user_account_control=uac,
                last_logon_timestamp=str(last_logon) if last_logon else None,
                asreproast_eligible=bool(props.get("dontreqpreauth")),
                object_sid=str(node.object_id or ""),
            )
        )

    # ── Supplementary query for users the collector silently dropped ────────
    # The collector discards User objects that have no objectSid (line
    # `if not sid: return None` in ldap_collector._entry_to_node). Some DCs
    # hide objectSid from anonymous queries while still returning the user
    # object — Baby.vl does this for Caroline Robinson and Ian Walker.
    # Those accounts never reach result.nodes so the cn_only_names list above
    # stays empty and the CN inference phase misses them entirely.
    #
    # Fix: run a second lightweight search that requests only name +
    # sAMAccountName + distinguishedName (no SID needed). Any user object
    # whose DN is absent from the collector result and whose sAMAccountName
    # is empty goes into cn_only_names.
    if users or result.nodes:
        known_dns = {
            (node.distinguished_name or "").lower()
            for node in result.nodes.values()
        }
        try:
            # Some DCs return user objects with objectClass + sAMAccountName +
            # objectSid all hidden (Baby.vl does this for specific accounts).
            # The collector never classifies them as User nodes because
            # `"user" in classes` is False with classes=set().
            # Strategy: query (objectClass=*) asking for as many attributes as
            # possible; for entries whose objectName (DN) is not in known_dns
            # and whose sAMAccountName is empty, extract the CN from the DN.
            # Kerbrute validation downstream confirms which CNs are real users.
            from adscan_internal.services.ldap_transport_service import (
                anonymous_default_naming_context,
                async_anonymous_ldap_connection,
            )

            async def _run_no_sid_query() -> None:
                # Centralized anonymous SIMPLE-bind with LDAPS->LDAP fallback.
                async with async_anonymous_ldap_connection(
                    dc_ip, timeout=timeout
                ) as (client, _used_ldaps):
                    tree = anonymous_default_naming_context(client)
                    # (objectClass=*) is the only filter the server evaluates
                    # for accounts whose attributes are fully hidden from
                    # anonymous queries. Baby.vl hides ALL attributes (objectClass,
                    # sAMAccountName, objectSid) for specific accounts, so
                    # (objectClass=user) never matches them server-side.
                    #
                    # Rule: keep only entries where objectClass was NOT returned.
                    # If objectClass is visible the object is already handled —
                    # either by the collector (users with sAMAccountName) or it's
                    # a group/computer/OU we can identify and skip. Objects with
                    # hidden objectClass are the unknown accounts; Kerberos
                    # pre-auth validation is the only correct filter for them.
                    async for entry, err in client.pagedsearch(
                        "(objectClass=*)",
                        ["sAMAccountName", "distinguishedName", "objectClass"],
                        controls=None,
                        tree=str(tree) if tree else None,
                        search_scope=2,
                    ):
                        if err is not None or entry is None:
                            continue
                        obj_name = str(entry.get("objectName") or "").strip()
                        attrs = entry.get("attributes") or {}

                        def _a(k: str) -> str:
                            v = attrs.get(k)
                            if isinstance(v, list):
                                return str(v[0]) if v else ""
                            return str(v or "")

                        # Skip objects where objectClass was returned — we know
                        # what they are (collector handles users; groups/OUs skipped).
                        if attrs.get("objectClass"):
                            continue

                        dn = _a("distinguishedName") or obj_name
                        if not dn or dn.lower() in known_dns:
                            continue

                        first_rdn = dn.split(",")[0].strip()
                        cn_like = ""
                        if "=" in first_rdn:
                            rdn_key, _, rdn_val = first_rdn.partition("=")
                            if rdn_key.strip().upper() == "CN":
                                cn_like = rdn_val.strip()

                        if cn_like and cn_like not in cn_only_names:
                            cn_only_names.append(cn_like)

            await asyncio.wait_for(_run_no_sid_query(), timeout=timeout)
        except Exception as _exc:  # noqa: BLE001
            print_info_debug(
                f"[ldap-unauth] supplementary no-sid query failed: {_exc}"
            )

    if users:
        return users, cn_only_names, "done"
    return [], cn_only_names, "denied"


# ---------------------------------------------------------------------------
# SMB null session — single shared connection, with SAMR + GPP layered on top
# ---------------------------------------------------------------------------


async def _open_null_smb_connection(target: str, timeout: int) -> Any:
    """Open a single aiosmb SMB connection authenticated as null session.

    Mirrors the flag surgery from :func:`unauth_probe_service._probe_smb_session`:
    flips ``credential.is_guest`` and clears ``NEGOTIATE_VERSION`` so the
    NTLMSSP_AUTHENTICATE message is emitted in the form Windows treats as
    *anonymous null session*. The caller owns the returned connection and
    must use it inside ``async with``.
    """
    from aiosmb.commons.connection.factory import SMBConnectionFactory

    url = f"smb+ntlm-password://Guest:@{target}:445/?timeout={timeout}"
    factory = SMBConnectionFactory.from_url(url)

    try:
        from badauth.protocols.ntlm.structures.negotiate_flags import (
            NegotiateFlags,
        )
    except ImportError:
        from badauth.protocols.ntlm.structures.negotiate_flags import (
            NegotiateFlags,
        )

    factory.credential.is_guest = True
    factory.credential.flags &= ~NegotiateFlags.NEGOTIATE_VERSION
    return factory.get_connection()


async def _samr_enumerate(
    connection: Any,
    domain_hint: str,
    max_descriptions: int,
    timeout: int,
) -> tuple[list[SAMRUser], TaskStatus, TaskStatus, str | None, str | None]:
    """Enumerate domain users + descriptions over an existing SMB null session.

    Thin adapter over :mod:`native_samr_service` so the unauth orchestrator
    stays unchanged. Returns
    ``(users, list_status, descriptions_status, list_error, desc_error)``.
    A SAMR ``STATUS_ACCESS_DENIED`` (RestrictAnonymousSAM=1) collapses to
    ``status="denied"``.
    """
    from adscan_internal.services.native_samr_service import (
        enumerate_samr_users_via,
        fetch_samr_user_details_via,
    )

    users, list_status, list_err = await enumerate_samr_users_via(
        connection, domain_hint=domain_hint, max_users=max_descriptions or 500
    )

    if list_status != "done":
        return users, list_status, "skipped", list_err, None

    if not users:
        return users, "done", "skipped", None, None

    targets = users[: max_descriptions or len(users)]
    _, desc_status, desc_err = await fetch_samr_user_details_via(
        connection,
        users=targets,
        domain_hint=domain_hint,
        max_concurrency=8,
        timeout=timeout,
    )
    return users, "done", desc_status, None, desc_err


def _samr_string(info: Any, key: str) -> str:
    """Best-effort extraction of a SAMR ``RPC_UNICODE_STRING`` value."""
    try:
        raw = info[key]
    except Exception:
        return ""
    # Common shapes: dict with 'Buffer', list of code units, or plain str.
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw.strip("\x00").strip()
    try:
        if hasattr(raw, "__getitem__"):
            buf = raw.get("Buffer") if hasattr(raw, "get") else raw["Buffer"]
            if isinstance(buf, str):
                return buf.strip("\x00").strip()
            if isinstance(buf, (bytes, bytearray)):
                return (
                    bytes(buf)
                    .decode("utf-16-le", errors="ignore")
                    .strip("\x00")
                    .strip()
                )
    except Exception:
        pass
    try:
        return str(raw).strip("\x00").strip()
    except Exception:
        return ""


# Re-exported for backward compat. Canonical list lives in the unified
# harvester (:mod:`gpp_credential_harvester.DEFAULT_GPP_SHARES`).
from adscan_internal.services.gpp_credential_harvester import (  # noqa: E402,F401
    DEFAULT_GPP_SHARES as _GPP_SHARE_CANDIDATES,
)


async def _gpp_harvest(
    connection: Any, timeout: int
) -> tuple[list[GPPLeak], list[GPPAutologinLeak], TaskStatus, str | None]:
    r"""Walk every plausible GPP share looking for cpassword + autologin.

    Thin shim over :func:`gpp_credential_harvester.harvest_gpp_on_connection`
    so the unauth orchestrator stays tidy. Returns
    ``(cpassword_leaks, autologin_leaks, status, last_error)`` — the
    legacy 3-tuple form was extended to surface autologin findings (the
    Get-GPPAutologon / Registry.xml vector that the previous walker
    silently dropped because it filtered files on the literal ``cpassword``
    substring before parsing).
    """
    from adscan_internal.services.gpp_credential_harvester import (
        harvest_gpp_on_connection,
    )

    result = await harvest_gpp_on_connection(connection, timeout=timeout)
    return (
        result.cpassword_leaks,
        result.autologin_leaks,
        result.status,
        result.error,
    )


# ---------------------------------------------------------------------------
# Live "Intel Dashboard"
# ---------------------------------------------------------------------------


@dataclass
class _IntelCard:
    key: str
    title: str
    icon: str
    status: TaskStatus = "skipped"
    count: int = 0
    chip_type: str = ""
    last_finding: str = ""
    highlight: bool = False  # set True on cpassword decryption


def _truncate(text: str, limit: int = 50) -> str:
    text = (text or "").strip().replace("\n", " ")
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _card_border(card: _IntelCard) -> str:
    if card.highlight:
        return ADSCAN_PRIMARY_BRIGHT
    if card.status == "running":
        return ADSCAN_PRIMARY
    if card.status == "done":
        return "green" if card.count > 0 else "yellow"
    if card.status == "denied":
        return "magenta"
    if card.status == "error":
        return "red"
    return ADSCAN_PRIMARY_DIM


def _card_glyph(card: _IntelCard, spinner: Spinner) -> Any:
    if card.status == "running":
        return spinner
    glyphs: dict[TaskStatus, tuple[str, str]] = {
        "skipped": ("·", "dim"),
        "done": ("✓", "bold green") if card.count > 0 else ("✓", "yellow"),
        "denied": ("✗", "magenta"),
        "error": ("✗", "red"),
        "running": ("⠿", ADSCAN_PRIMARY),
    }
    glyph, style = glyphs[card.status]
    return Text(glyph, style=style)


def _render_intel_dashboard(cards: list[_IntelCard], header: dict[str, str]) -> Group:
    spinner = Spinner("dots", style=ADSCAN_PRIMARY)

    title = Text("🛰  Unauthenticated Intel Enrichment", style=f"bold {ADSCAN_PRIMARY}")
    header_grid = Table.grid(padding=(0, 2))
    header_grid.add_column(style="dim", justify="right")
    header_grid.add_column(style="white")
    for k, v in header.items():
        header_grid.add_row(f"{k}:", v)
    header_panel = Panel(
        Group(title, Text(""), header_grid),
        border_style=ADSCAN_PRIMARY,
        padding=(1, 2),
        box=ROUNDED,
    )

    grid = Table.grid(expand=True, padding=(0, 1))
    grid.add_column(ratio=1)
    grid.add_column(ratio=1)

    rendered_cards: list[Panel] = []
    for card in cards:
        line1 = Table.grid(expand=True)
        line1.add_column(ratio=1)
        line1.add_column(justify="right")
        title_text = Text.assemble(
            (f"{card.icon}  ", "bold white"),
            (card.title, "bold white"),
        )
        chip = ""
        if card.count or card.chip_type:
            chip_label = (
                f"[{card.count} {card.chip_type}]"
                if card.chip_type
                else f"[{card.count}]"
            )
            chip = chip_label
        chip_text = Text(
            chip, style=f"bold {ADSCAN_PRIMARY_BRIGHT}" if card.highlight else "cyan"
        )
        line1.add_row(title_text, chip_text)

        status_label = card.status.upper()
        status_style = _card_border(card)
        status_line = Table.grid(padding=(0, 1))
        status_line.add_column(width=3)
        status_line.add_column()
        status_line.add_row(
            _card_glyph(card, spinner), Text(status_label, style=f"bold {status_style}")
        )

        finding = Text(_truncate(card.last_finding) or "—", style="dim white")

        body = Group(line1, status_line, finding)
        rendered_cards.append(
            Panel(
                body,
                border_style=_card_border(card),
                box=SIMPLE_HEAVY,
                padding=(0, 1),
            )
        )

    # Render as 2x2 (or NxN depending on count).
    rows: list[list[Panel]] = []
    for i in range(0, len(rendered_cards), 2):
        rows.append(rendered_cards[i : i + 2])
    body_grid = Table.grid(expand=True, padding=(0, 1))
    body_grid.add_column(ratio=1)
    body_grid.add_column(ratio=1)
    for row in rows:
        if len(row) == 1:
            body_grid.add_row(row[0], Text(""))
        else:
            body_grid.add_row(*row)

    body_panel = Panel(
        body_grid,
        border_style=ADSCAN_PRIMARY_DIM,
        box=ROUNDED,
        padding=(1, 2),
        title=f"[bold {ADSCAN_PRIMARY}]Intel Tasks[/bold {ADSCAN_PRIMARY}]",
        title_align="left",
    )

    return Group(header_panel, body_panel)


def _render_intel_sheet(
    results: UnauthEnrichmentResults,
    *,
    domain: str,
    workspace_dir: str,
) -> None:
    """Render the final premium "Intel Sheet" panel after enrichment."""
    console = _get_console()

    sections: list[Any] = []

    # 🔑 Credential leaks — top of the sheet, reverse-video chip when we
    # actually recovered a credential. This is the "moment of value" for the
    # pentester; everything else on the sheet is supporting evidence. Both
    # GPP cpassword (encrypted, decrypted in-process) and GPP autologon
    # (Registry.xml plaintext) are surfaced here in a single block.
    cred_lines: list[Text] = []
    decrypted = [g for g in results.gpp_leaks if g.cleartext]
    autologin = list(results.gpp_autologin_leaks)
    total_creds = len(decrypted) + len(autologin)

    for leak in decrypted[:8]:
        cred_lines.append(
            Text.from_markup(
                f"  [bold {ADSCAN_PRIMARY_BRIGHT}]🔓 cpassword[/]  "
                f"[bold]{mark_sensitive(leak.username, 'user')}[/]   "
                f"[bold yellow]{mark_sensitive(leak.cleartext, 'user')}[/]   "
                f"[dim]{mark_sensitive(_truncate(leak.unc_path, 60), 'path')}[/dim]"
            )
        )
    if len(decrypted) > 8:
        cred_lines.append(
            Text(f"  (+{len(decrypted) - 8} more cpassword)", style="dim")
        )

    for leak in autologin[:8]:
        domain_chip = (
            f" [dim]@{mark_sensitive(leak.domain, 'domain')}[/dim]"
            if leak.domain
            else ""
        )
        cred_lines.append(
            Text.from_markup(
                f"  [bold {ADSCAN_PRIMARY_BRIGHT}]🔓 autologon[/]  "
                f"[bold]{mark_sensitive(leak.username, 'user')}[/]{domain_chip}   "
                f"[bold yellow]{mark_sensitive(leak.password, 'user')}[/]   "
                f"[dim]{mark_sensitive(_truncate(leak.unc_path, 60), 'path')}[/dim]"
            )
        )
    if len(autologin) > 8:
        cred_lines.append(
            Text(f"  (+{len(autologin) - 8} more autologon)", style="dim")
        )

    if total_creds:
        chip = []
        if decrypted:
            chip.append(f"{len(decrypted)} cpassword")
        if autologin:
            chip.append(f"{len(autologin)} autologon")
        cred_header = Text.from_markup(
            f"[bold {ADSCAN_PRIMARY_BRIGHT} reverse] CREDENTIAL LEAK [/]  "
            f"[bold]🔑 {' + '.join(chip)} recovered[/bold]"
        )
    else:
        cred_header = Text.from_markup(
            f"[bold]🔑 Credential leaks[/bold]  "
            f"[dim]({len(results.gpp_leaks)} cpassword entries, none decrypted)[/dim]"
        )
    sections.append(Group(cred_header, *cred_lines) if cred_lines else cred_header)

    # 👥 Unified domain user inventory (LDAP + SAMR + LSARPC RID Cycling merged)
    # Per-source counts surface coverage gaps and tell the operator which
    # technique actually paid off — critical when SAMR is denied but RID
    # cycling via guest session still pulls the inventory.  The canonical
    # artefact lives at domains/<dom>/users.json — see
    # ``adscan_internal.services.unauth_inventory``.
    ldap_count = len(results.ldap_active_users)
    samr_count = len(results.samr_users)
    SID_TYPE_USER = 1
    rid_user_count = sum(
        1
        for e in results.rid_cycling_users
        if getattr(e, "sid_type", None) == SID_TYPE_USER
        and str(getattr(e, "name", "") or "").strip()
        and not str(getattr(e, "name", "") or "").strip().endswith("$")
    )
    inventory_path = f"{workspace_dir}/domains/{domain}/users.json"
    inv_header = Text.from_markup(
        f"[bold]👥 Domain user inventory[/bold]  "
        f"(LDAP: {ldap_count} [{results.ldap_active_users_status}]  ·  "
        f"SAMR: {samr_count} [{results.samr_users_status}]  ·  "
        f"LSARPC RID: {rid_user_count} [{results.rid_cycling_status}])"
    )
    inv_lines: list[Text] = []
    # Prefer LDAP sample names first (they carry richer metadata), then
    # SAMR, then RID cycling.  This mirrors the merge priority in
    # ``unauth_inventory.merge_unauth_users``.
    sample: list[str] = []
    if results.ldap_active_users:
        sample = [u.samaccountname for u in results.ldap_active_users[:4]]
    elif results.samr_users:
        sample = [u.username for u in results.samr_users[:4]]
    else:
        sample = [
            str(getattr(e, "name", "") or "").strip()
            for e in results.rid_cycling_users[:4]
            if getattr(e, "sid_type", None) == SID_TYPE_USER
            and str(getattr(e, "name", "") or "").strip()
            and not str(getattr(e, "name", "") or "").strip().endswith("$")
        ]
    if sample:
        rest = max(ldap_count, samr_count, rid_user_count) - len(sample)
        sample_text = ", ".join(mark_sensitive(s, "user") for s in sample)
        if rest > 0:
            sample_text += f"  (+{rest} more)"
        inv_lines.append(Text.from_markup(f"  {sample_text}"))
    if results.rid_cycling_reason and results.rid_cycling_status not in ("skipped", ""):
        # Surface the RID-cycling reason inline so the operator sees why it
        # ran and what it found (or why it was denied) without checking debug.
        inv_lines.append(
            Text.from_markup(
                f"  [dim]LSARPC RID Cycling: {results.rid_cycling_reason}[/dim]"
            )
        )
    inv_lines.append(
        Text.from_markup(
            f"  [dim]merged → {mark_sensitive(inventory_path, 'path')}[/dim]"
        )
    )
    sections.append(Group(inv_header, *inv_lines))

    # 📝 Sensitive descriptions
    sens = results.sensitive_descriptions
    sens_header = Text.from_markup(
        f"[bold]📝 Sensitive descriptions[/bold]  ({len(sens)})  "
        f"[{results.samr_descriptions_status}]"
    )
    sens_lines: list[Text] = []
    for username, desc in sens[:6]:
        sens_lines.append(
            Text.from_markup(
                f"  [bold]{mark_sensitive(username, 'user')}[/bold] — "
                f"[yellow]{_truncate(desc, 60)}[/yellow]"
            )
        )
    if len(sens) > 6:
        sens_lines.append(Text(f"  (+{len(sens) - 6} more)", style="dim"))
    sections.append(Group(sens_header, *sens_lines))

    # 🎯 Attack surface flags
    asrep = results.asreproast_eligible_users
    # ``sens`` is already the credential-disclosure set, so a second, weaker
    # keyword pass over it would only report a smaller number for the same
    # thing (and miss a password stored in ``userPassword``, where the word
    # "password" never appears in the value).
    flag_lines = [
        Text.from_markup(f"  AS-REP roastable accounts : [bold]{len(asrep)}[/bold]"),
        Text.from_markup(
            f"  Descriptions disclosing a credential : [bold]{len(sens)}[/bold]"
        ),
        Text.from_markup(
            f"  GPP cpassword leaks (decrypted) : [bold]{len(decrypted)}[/bold]"
        ),
        Text.from_markup(
            f"  GPP autologon credentials       : [bold]{len(autologin)}[/bold]"
        ),
    ]
    sections.append(
        Group(Text.from_markup("[bold]🎯 Attack surface flags[/bold]"), *flag_lines)
    )

    # ⏱ Total
    sections.append(
        Text.from_markup(
            f"[dim]⏱ Total enrichment time: {results.duration_seconds:.2f}s[/dim]"
        )
    )

    # Insert blank lines between sections for readability.
    interleaved: list[Any] = []
    for i, section in enumerate(sections):
        if i > 0:
            interleaved.append(Text(""))
        interleaved.append(section)

    panel = Panel(
        Group(*interleaved),
        title=f"[bold {ADSCAN_PRIMARY}]Unauthenticated Intel Sheet[/]",
        title_align="left",
        border_style=ADSCAN_PRIMARY,
        box=ROUNDED,
        padding=(1, 2),
    )
    console.print(panel)
    print_info_verbose(
        f"[unauth-enrich] enrichment finished in {results.duration_seconds:.2f}s"
    )


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


async def run_unauth_enrichment_async(
    config: UnauthEnrichmentConfig,
) -> UnauthEnrichmentResults:
    """Run all enrichment tasks with a Rich Live intel dashboard."""
    results = UnauthEnrichmentResults()

    # Card order groups by objective: user discovery (LDAP, SAMR, LSARPC) on
    # the first two rows, then credentials (SAMR descriptions + GPP) on the
    # third row.  The 3x2 layout avoids an orphaned card on the bottom row.
    cards: list[_IntelCard] = [
        _IntelCard("ldap_users", "LDAP Domain Inventory", "👤", chip_type="users"),
        _IntelCard("samr_users", "SAMR Domain Users", "📋", chip_type="users"),
        _IntelCard(
            "rid_cycling",
            "LSARPC RID Cycling (guest session)",
            "🔗",
            chip_type="users",
        ),
        _IntelCard("samr_desc", "SAMR Descriptions", "📝", chip_type="desc"),
        _IntelCard(
            "gpp",
            "GPP Credential Hunt (cpassword + autologon)",
            "🔑",
            chip_type="leaks",
        ),
    ]
    card_index = {c.key: c for c in cards}

    # Signal raised by _drive_smb_tasks once SAMR finishes so the RID
    # cycling driver can make an informed decision about redundancy.
    samr_completed = asyncio.Event()

    header = {
        "Domain": mark_sensitive(config.domain, "domain"),
        "DC": mark_sensitive(config.dc_ip, "ip"),
        "Surface": (
            ("SMB null + LDAP anon")
            if (config.smb_null_open and config.ldap_anon_open)
            else ("SMB null" if config.smb_null_open else "LDAP anon")
        ),
        "Tasks": str(len(cards)),
        "Started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    start = time.monotonic()

    async def _drive_ldap_users() -> None:
        if not config.ldap_anon_open:
            return
        card = card_index["ldap_users"]
        card.status = "running"
        results.ldap_active_users_status = "running"
        try:
            users, cn_only_names, status = await _enrich_ldap_via_collector(
                domain=config.domain, dc_ip=config.dc_ip, timeout=config.timeout
            )
            results.ldap_active_users = users
            results.ldap_cn_only_records = cn_only_names
            card.count = len(users)
            results.ldap_active_users_status = status
            card.status = status
            if users:
                # Surface AS-REP and sensitive-description sub-counters so the
                # operator sees the high-value findings at a glance, not just
                # the raw user count.
                asrep = sum(1 for u in users if u.asreproast_eligible)
                sensitive = sum(
                    1
                    for u in users
                    if u.description
                    and detect_credential_disclosure(
                        "description",
                        u.description,
                        builtin=is_builtin_principal(
                            samaccountname=u.samaccountname, object_sid=u.object_sid
                        ),
                    )
                )
                tags: list[str] = []
                if asrep:
                    tags.append(f"{asrep} AS-REP")
                if sensitive:
                    tags.append(f"{sensitive} sensitive")
                card.last_finding = (
                    f"{users[0].samaccountname} (+{len(users) - 1} more)"
                    + (" • " + " • ".join(tags) if tags else "")
                )
            elif status == "denied":
                card.last_finding = "Anonymous user enumeration denied (hardened DC)"
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            msg = str(exc)
            results.errors["ldap_active_users"] = msg
            results.ldap_active_users_status = (
                "denied"
                if "denied" in msg.lower() or "bind" in msg.lower()
                else "error"
            )
            card.status = results.ldap_active_users_status
            card.last_finding = _truncate(msg)

    async def _drive_smb_tasks() -> None:
        if not config.smb_null_open:
            # No null session — SAMR can never run.  Mark SAMR as resolved
            # so the RID cycling driver doesn't block waiting for it.
            samr_completed.set()
            return

        samr_card = card_index["samr_users"]
        desc_card = card_index["samr_desc"]
        gpp_card = card_index["gpp"]

        samr_card.status = "running"
        desc_card.status = "running"
        gpp_card.status = "running"
        results.samr_users_status = "running"
        results.samr_descriptions_status = "running"
        results.gpp_status = "running"

        connection = None
        try:
            connection = await _open_null_smb_connection(config.dc_ip, config.timeout)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            msg = str(exc)
            results.errors["smb_null_session"] = msg
            samr_card.status = "error"
            desc_card.status = "error"
            gpp_card.status = "error"
            results.samr_users_status = "error"
            results.samr_descriptions_status = "error"
            results.gpp_status = "error"
            samr_card.last_finding = _truncate(msg)
            samr_completed.set()
            return

        try:
            async with connection:
                _, login_err = await connection.login()
                if login_err is not None:
                    raise login_err

                # SAMR enumeration + descriptions.
                try:
                    (
                        users,
                        list_status,
                        desc_status,
                        list_err,
                        desc_err,
                    ) = await _samr_enumerate(
                        connection,
                        config.domain,
                        config.max_user_descriptions,
                        config.timeout,
                    )
                    results.samr_users = users
                    results.samr_users_status = list_status
                    results.samr_descriptions_status = desc_status
                    samr_card.status = list_status
                    samr_card.count = len(users)
                    if users:
                        samr_card.last_finding = users[0].username + (
                            f" +{len(users) - 1} more" if len(users) > 1 else ""
                        )
                    elif list_err:
                        samr_card.last_finding = _truncate(list_err)
                        results.errors["samr_users"] = list_err

                    if desc_status in ("done", "denied", "error"):
                        desc_card.status = desc_status
                    else:
                        desc_card.status = "skipped"
                    sensitive_count = len(
                        [u for u in users if u.description or u.full_name or u.comment]
                    )
                    desc_card.count = sensitive_count
                    if desc_err:
                        results.errors["samr_descriptions"] = desc_err
                        desc_card.last_finding = _truncate(desc_err)
                    elif sensitive_count:
                        first = next(
                            (
                                u
                                for u in users
                                if u.description or u.full_name or u.comment
                            ),
                            None,
                        )
                        if first:
                            desc_card.last_finding = (
                                f"{first.username}: "
                                f"{_truncate(first.description or first.full_name or first.comment, 40)}"
                            )
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
                    print_exception(exception=exc)
                    msg = str(exc)
                    results.errors["samr"] = msg
                    samr_card.status = "error"
                    desc_card.status = "error"
                    results.samr_users_status = "error"
                    results.samr_descriptions_status = "error"
                    samr_card.last_finding = _truncate(msg)
                finally:
                    # SAMR resolved (one way or the other) — release the
                    # RID cycling driver so it can decide whether to run.
                    samr_completed.set()

                # GPP cpassword + autologin harvest (single filesystem pass).
                try:
                    (
                        leaks,
                        autologin_leaks,
                        gpp_status,
                        gpp_err,
                    ) = await _gpp_harvest(connection, config.timeout)
                    results.gpp_leaks = leaks
                    results.gpp_autologin_leaks = autologin_leaks
                    results.gpp_status = gpp_status
                    gpp_card.status = gpp_status
                    decrypted = [g for g in leaks if g.cleartext]
                    findings_total = len(decrypted) + len(autologin_leaks)
                    gpp_card.count = findings_total
                    if decrypted or autologin_leaks:
                        gpp_card.highlight = True
                        if autologin_leaks:
                            first = autologin_leaks[0]
                            gpp_card.last_finding = (
                                f"autologon {first.username}: {first.password}"
                            )
                        else:
                            gpp_card.last_finding = (
                                f"{decrypted[0].username}: {decrypted[0].cleartext}"
                            )
                    elif gpp_err:
                        results.errors["gpp"] = gpp_err
                        # Show a clean user-facing message, not raw library internals
                        # (e.g. "NtFrs: Status: None" from aiosmb DCERPC layer).
                        if gpp_status == "denied":
                            gpp_card.last_finding = "SYSVOL not accessible via null session"
                        else:
                            gpp_card.last_finding = _truncate(gpp_err)
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
                    print_exception(exception=exc)
                    msg = str(exc)
                    results.errors["gpp"] = msg
                    gpp_card.status = "error"
                    results.gpp_status = "error"
                    gpp_card.last_finding = _truncate(msg)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            msg = str(exc)
            results.errors["smb_null_session"] = msg
            for c in (samr_card, desc_card, gpp_card):
                if c.status == "running":
                    c.status = "error"
                    c.last_finding = _truncate(msg)
            if results.samr_users_status == "running":
                results.samr_users_status = "error"
            if results.samr_descriptions_status == "running":
                results.samr_descriptions_status = "error"
            if results.gpp_status == "running":
                results.gpp_status = "error"
        finally:
            # Safety net: if SAMR threw before reaching its own ``finally``
            # (e.g. inside ``connection.login()``), this guarantees the
            # RID cycling driver never blocks indefinitely.
            samr_completed.set()

    async def _drive_rid_cycling() -> None:
        """LSARPC RID Cycling — gated on SAMR's outcome.

        Runs *only* when a guest session is open AND SAMR either failed
        or returned zero users.  When SAMR already harvested the user
        inventory there's no point spending another DCERPC round-trip
        to re-discover the same accounts, so the card stays SKIPPED with
        a clear reason.

        Status transitions for the live dashboard:
          - skipped → "no guest session" / "SAMR returned N users — redundant"
          - running → first then second RID pass against the DC
          - done    → ``count`` reflects new accounts (not already in SAMR/LDAP)
          - denied  → guest LSARPC bind rejected the lookup
          - error   → unexpected exception (captured + surfaced)
        """
        card = card_index["rid_cycling"]

        if config.smb_guest_config is None:
            results.rid_cycling_status = "skipped"
            results.rid_cycling_reason = "no guest session"
            card.status = "skipped"
            card.last_finding = "no guest session available"
            return

        # Wait for SAMR to finish so we can decide whether RID cycling
        # would just duplicate the user inventory we already harvested.
        try:
            await asyncio.wait_for(samr_completed.wait(), timeout=config.timeout)
        except asyncio.TimeoutError:
            # SAMR hung — proceed anyway, RID cycling is independent over
            # a different SMB session (guest, not null).
            pass

        if results.samr_users_status == "done" and len(results.samr_users) > 0:
            samr_n = len(results.samr_users)
            results.rid_cycling_status = "skipped"
            results.rid_cycling_reason = f"SAMR returned {samr_n} users — RID cycling redundant"
            card.status = "skipped"
            card.last_finding = f"SAMR found {samr_n} users — redundant"
            return

        card.status = "running"
        results.rid_cycling_status = "running"

        try:
            from adscan_internal.services.native_lsarpc_service import rid_cycle_via
            from adscan_internal.services.smb_transport import (
                smb_machine_with_fallback,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            results.rid_cycling_status = "error"
            results.rid_cycling_reason = f"import failed: {exc}"
            card.status = "error"
            card.last_finding = _truncate(str(exc))
            return

        try:
            async with smb_machine_with_fallback(config.smb_guest_config) as machine:
                # First pass: well-known + low RIDs (covers the bulk of
                # populated AD environments).
                entries, status, err = await rid_cycle_via(
                    machine,
                    domain_hint=config.domain,
                    rid_start=500,
                    rid_end=config.rid_cycling_first_pass_end,
                )
                if status == "done" and entries:
                    # Second pass: deep-RID sweep for environments that
                    # have created service accounts in higher RID ranges.
                    more, status2, err2 = await rid_cycle_via(
                        machine,
                        domain_hint=config.domain,
                        rid_start=config.rid_cycling_first_pass_end + 1,
                        rid_end=config.rid_cycling_second_pass_end,
                    )
                    if more:
                        entries.extend(more)
                    if status2 not in ("done", "skipped"):
                        # Log the deep-pass failure but don't fail the
                        # whole card — first-pass results are valuable.
                        results.errors["rid_cycling_deep"] = err2 or status2
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            results.rid_cycling_status = "error"
            results.rid_cycling_reason = str(exc)
            card.status = "error"
            card.last_finding = _truncate(str(exc))
            return

        # Filter to SID_TYPE_USER (1), exclude machine accounts ending in $
        # — same filter the merge function applies, but applied here so the
        # card count reflects what the operator will actually see.
        SID_TYPE_USER = 1
        user_entries = [
            e
            for e in entries
            if getattr(e, "sid_type", None) == SID_TYPE_USER
            and str(getattr(e, "name", "") or "").strip()
            and not str(getattr(e, "name", "") or "").strip().endswith("$")
        ]
        results.rid_cycling_users = list(entries)  # full list for the merge step

        if err and not entries:
            # Hard denial — surface clearly so the operator knows the
            # guest session itself is restricted, not just SAMR.
            results.rid_cycling_status = "denied"
            results.rid_cycling_reason = _truncate(str(err))
            card.status = "denied"
            card.last_finding = _truncate(str(err))
            return

        n = len(user_entries)
        results.rid_cycling_status = "done"
        card.status = "done"
        card.count = n
        if n:
            first = user_entries[0]
            first_name = str(getattr(first, "name", "") or "?")
            card.last_finding = (
                f"{first_name}" + (f" (+{n - 1} more)" if n > 1 else "")
            )
            results.rid_cycling_reason = (
                f"{n} user(s) discovered via LSARPC LookupSids"
            )
        else:
            card.last_finding = "no users in scanned RID range"
            results.rid_cycling_reason = "0 user-type SIDs resolved"

    drivers = [_drive_ldap_users(), _drive_smb_tasks(), _drive_rid_cycling()]
    tasks = [asyncio.create_task(d) for d in drivers]

    try:
        # alt_screen=False: the intel dashboard stays inline so the
        # post-run intel sheet (rendered by ``_render_intel_sheet``)
        # appears immediately below it in the operator's scrollback.
        _live_cfg = LiveSessionConfig(refresh_per_second=8, alt_screen=False)
        async with LiveSession(
            _render_intel_dashboard(cards, header), config=_live_cfg
        ) as session:
            while not all(t.done() for t in tasks):
                session.update(_render_intel_dashboard(cards, header))
                await asyncio.sleep(0.12)
            await asyncio.gather(*tasks, return_exceptions=True)
            session.update(_render_intel_dashboard(cards, header))
    finally:
        results.duration_seconds = time.monotonic() - start

    _render_intel_sheet(
        results, domain=config.domain, workspace_dir=config.workspace_dir
    )
    return results


def run_unauth_enrichment(config: UnauthEnrichmentConfig) -> UnauthEnrichmentResults:
    """Synchronous entry point — wraps :func:`run_unauth_enrichment_async`."""
    try:
        return asyncio.run(run_unauth_enrichment_async(config))
    except RuntimeError as exc:
        if "asyncio.run() cannot be called" in str(exc) or "running event loop" in str(
            exc
        ):
            raise RuntimeError(
                "run_unauth_enrichment was invoked from inside a running asyncio "
                "loop. Use `await run_unauth_enrichment_async(config)` instead."
            ) from exc
        raise
