"""Premium live view + summary panel for native trust enumeration.

Wired into ``cli/domains.run_enum_trusts`` so the user sees a single
self-updating panel while ``DomainService.enumerate_trusts`` recurses through
the trust topology, then a polished summary card after the BFS terminates.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import sys
import time
from typing import Any

from rich.console import Group, RenderableType
from rich.padding import Padding
from rich.panel import Panel
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from adscan_core.rich_output import print_info_verbose
from adscan_core.tui import LiveSession, LiveSessionConfig
from adscan_internal import get_console
from adscan_internal.rich_output import mark_sensitive


# ---------------------------------------------------------------------------
# Progress event contract
# ---------------------------------------------------------------------------


@dataclass
class TrustEnumProgressEvent:
    """One progress event emitted by ``DomainService.enumerate_trusts``.

    Phases:
        - ``connect``         : opening LDAP to ``current_domain``'s PDC
        - ``querying``        : LDAP search in flight
        - ``partner_resolved``: a trustedDomain entry was decoded for ``partner``
        - ``failed``          : LDAP query against ``current_domain`` raised
        - ``done``            : query for ``current_domain`` completed
    """

    phase: str
    current_domain: str
    pdc: str | None = None
    partner: str | None = None
    error: str | None = None
    duration_ms: float | None = None
    trust_count: int | None = None


# ---------------------------------------------------------------------------
# Live view
# ---------------------------------------------------------------------------


@dataclass
class _DomainRow:
    domain: str
    pdc: str | None
    status: str = "pending"  # pending|querying|done|failed
    started_at: float | None = None
    duration_ms: float | None = None
    trust_count: int = 0
    error: str | None = None


class TrustEnumLiveView:
    """Self-updating Rich panel covering the full BFS lifecycle.

    Use as a context manager. When the terminal is not a TTY or the user has
    set ``ADSCAN_NO_LIVE=1``, the renderer falls back to plain debug lines so
    log output stays readable in CI.
    """

    def __init__(self, *, source_domain: str, source_pdc: str, username: str) -> None:
        self.source_domain = source_domain
        self.source_pdc = source_pdc
        self.username = username
        self._rows: dict[str, _DomainRow] = {}
        self._order: list[str] = []
        self._partner_count = 0
        self._started = time.monotonic()
        self._console = get_console()
        # alt_screen=True is required here because the panel's row count
        # grows during the BFS (one row per discovered partner domain)
        # and the domain count is not knowable upfront — so the
        # pre-allocate-rows pattern that fixes posture_probe_live is not
        # applicable. Alt-screen contains the growth inside an isolated
        # buffer (no ghost frames in scrollback). The ``summary``
        # callback below re-prints the final panel to the operator's
        # scrollback once the alt-screen pops, so the post-run state is
        # still reviewable. See CLAUDE.md § "Rich Live UX — Stable
        # line-count rule" for the rationale.
        self._session: LiveSession | None = None
        self._is_tty = sys.stdout.isatty() and os.environ.get("ADSCAN_NO_LIVE") != "1"

    # ---- context management ------------------------------------------------

    def __enter__(self) -> "TrustEnumLiveView":
        if self._is_tty:
            self._session = LiveSession(
                self._render(),
                config=LiveSessionConfig(refresh_per_second=8, alt_screen=True),
                summary=self._print_final_panel,
            )
            self._session.__enter__()
        return self

    def _print_final_panel(self, console: Any) -> None:
        """Re-print the final BFS panel to the operator's scrollback.

        Called by ``LiveSession`` after the alt-screen pops. Without this
        callback the operator would only see the panel during the live
        run; switching to ``alt_screen=True`` (required to avoid ghost
        frames from the dynamically-growing renderable) would otherwise
        wipe the panel from scrollback on exit.
        """
        try:
            console.print(self._render())
        except Exception:  # noqa: BLE001
            pass

    def __exit__(self, *_args: Any) -> None:
        if self._session is not None:
            try:
                self._session.update(self._render(), refresh=True)
            except Exception:  # noqa: BLE001
                pass
            self._session.__exit__(*_args)
            self._session = None

    # ---- public API --------------------------------------------------------

    def on_event(self, event: TrustEnumProgressEvent) -> None:
        domain = event.current_domain
        row = self._rows.get(domain)
        if row is None:
            row = _DomainRow(domain=domain, pdc=event.pdc)
            self._rows[domain] = row
            self._order.append(domain)
        if event.pdc and not row.pdc:
            row.pdc = event.pdc

        if event.phase in ("connect", "querying"):
            row.status = "querying"
            if row.started_at is None:
                row.started_at = time.monotonic()
        elif event.phase == "partner_resolved":
            self._partner_count += 1
            row.trust_count += 1
        elif event.phase == "done":
            row.status = "done"
            row.duration_ms = event.duration_ms
            if event.trust_count is not None:
                row.trust_count = event.trust_count
        elif event.phase == "failed":
            row.status = "failed"
            row.error = event.error
            row.duration_ms = event.duration_ms

        self._refresh(event)

    # ---- internals ---------------------------------------------------------

    def _refresh(self, event: TrustEnumProgressEvent) -> None:
        if self._session is not None:
            self._session.update(self._render())
            return
        # Non-TTY path: log a single debug line per event.
        marked = mark_sensitive(event.current_domain, "domain")
        if event.phase == "querying":
            print_info_verbose(f"[trust] querying {marked}")
        elif event.phase == "partner_resolved":
            print_info_verbose(
                f"[trust] {marked} -> partner "
                f"{mark_sensitive(event.partner or '', 'domain')}"
            )
        elif event.phase == "done":
            print_info_verbose(
                f"[trust] {marked} done · {event.trust_count or 0} partner(s)"
            )
        elif event.phase == "failed":
            print_info_verbose(
                f"[trust] {marked} failed: {event.error or 'unknown error'}"
            )

    def _render(self) -> RenderableType:
        header = Text()
        header.append("Source domain  ", style="dim")
        header.append(mark_sensitive(self.source_domain, "domain"), style="bold")
        header.append("    PDC  ", style="dim")
        header.append(mark_sensitive(self.source_pdc, "ip"))
        header.append("    User  ", style="dim")
        header.append(mark_sensitive(self.username, "user"))

        table = Table.grid(padding=(0, 2))
        table.add_column(width=2)
        table.add_column(justify="left", no_wrap=False)
        table.add_column(justify="right", style="dim")

        for domain in self._order:
            row = self._rows[domain]
            icon, label = self._status_renderable(row)
            domain_text = Text()
            domain_text.append(mark_sensitive(domain, "domain"))
            if row.pdc:
                domain_text.append("  ", style="dim")
                domain_text.append(mark_sensitive(row.pdc, "ip"), style="dim")
            right = self._right_column(row)
            table.add_row(
                icon, Group(domain_text, label) if label else domain_text, right
            )

        elapsed = time.monotonic() - self._started
        partners = sum(r.trust_count for r in self._rows.values())
        footer = Text()
        footer.append("Discovered: ", style="dim")
        footer.append(f"{len(self._rows)} domain(s)", style="bold")
        footer.append("  ·  ", style="dim")
        footer.append(f"{partners} trust(s)", style="bold")
        footer.append("  ·  elapsed ", style="dim")
        footer.append(f"{elapsed:0.1f}s")

        body = Group(header, Text(), table, Text(), footer)
        return Panel(
            Padding(body, (1, 2)),
            title="[bold]Trust Enumeration · live[/bold]",
            border_style="cyan",
            expand=False,
        )

    @staticmethod
    def _status_renderable(
        row: _DomainRow,
    ) -> tuple[RenderableType, RenderableType | None]:
        if row.status == "querying":
            return Spinner("dots", style="cyan"), None
        if row.status == "done":
            return Text("✓", style="bold green"), None
        if row.status == "failed":
            return Text("✗", style="bold red"), None
        return Text("⏳", style="dim"), None

    @staticmethod
    def _right_column(row: _DomainRow) -> RenderableType:
        text = Text()
        if row.status == "querying":
            text.append("querying…", style="cyan")
            return text
        if row.status == "done":
            if row.duration_ms is not None:
                text.append(f"{row.duration_ms:0.0f}ms  ", style="dim")
            text.append(
                f"{row.trust_count} partner(s)",
                style="green" if row.trust_count else "dim",
            )
            return text
        if row.status == "failed":
            text.append(row.error or "failed", style="red")
            return text
        text.append("pending", style="dim")
        return text


# ---------------------------------------------------------------------------
# Summary panel
# ---------------------------------------------------------------------------


_TYPE_STYLE: dict[str, str] = {
    "Forest": "cyan",
    "External": "yellow",
    "Parent-Child": "dim",
    "TreeRoot": "cyan",
    "CrossLink": "magenta",
    "MIT": "magenta",
    "DCE": "magenta",
    "Windows NT": "yellow",
    "Unknown": "red",
}

_DIRECTION_ICON: dict[str, str] = {
    "Bidirectional": "↔",
    "Outbound": "→",
    "Inbound": "←",
    "Disabled": "⊘",
    "Unknown": "?",
}


def _direction_arrow(direction: str) -> str:
    return _DIRECTION_ICON.get(direction, "?")


def _type_style(trust_type: str) -> str:
    return _TYPE_STYLE.get(trust_type, "white")


def _remediation_for(error: str) -> str:
    text = (error or "").lower()
    if "signing" in text or "channel binding" in text or "strongerauth" in text:
        return "LDAP signing/CB required — try LDAPS or supply --ldap-channel-binding."
    if "cross-realm" in text or "not reachable with the current credential" in text:
        return "Partner realm not authenticatable with this credential — supply cross-forest creds for the partner domain."
    if "bind" in text or "credentials" in text or "preauth" in text:
        return "Bind failed — verify credentials are valid in the partner domain or supply cross-forest creds."
    if "timeout" in text or "unreachable" in text or "no route" in text:
        return "Partner DC unreachable from current vantage — consider pivoting through the partner network."
    if "kerberos" in text or "krb_ap_err" in text:
        return "Kerberos failure — check clock skew and SPN of the partner DC."
    return "Inspect logs for the underlying cause."


def render_trust_summary_panel(
    result: Any,
    *,
    source_domain: str,
) -> RenderableType:
    """Build the summary panel rendered after the live view exits."""
    trusts = list(getattr(result, "trusts", []) or [])
    discovered = list(getattr(result, "discovered_domains", []) or [])
    failed = dict(getattr(result, "failed_domains", {}) or {})
    durations = dict(getattr(result, "per_domain_durations", {}) or {})
    pdcs = dict(getattr(result, "domain_controllers", {}) or {})
    connectivity = dict(getattr(result, "domain_connectivity", {}) or {})

    if not trusts and not failed:
        body = Text(
            "No trust relationships found · domain operates as a single forest island.",
            style="dim italic",
        )
        return Panel(
            Padding(body, (1, 2)),
            title="[bold]Trust Enumeration · summary[/bold]",
            border_style="cyan",
            expand=False,
        )

    # Header
    header = Text()
    header.append("Source: ", style="dim")
    header.append(mark_sensitive(source_domain, "domain"), style="bold")
    header.append("   ·   ", style="dim")
    header.append(f"{len(trusts)} trust(s)", style="bold")
    header.append("   ·   ", style="dim")
    header.append(f"{len(discovered)} domain(s) discovered", style="bold")
    if failed:
        header.append("   ·   ", style="dim")
        header.append(f"{len(failed)} unreachable", style="bold red")

    # Trust matrix table
    matrix = Table(
        title="Trust matrix",
        title_justify="left",
        title_style="bold",
        expand=False,
        show_lines=False,
        pad_edge=False,
    )
    matrix.add_column("Source", style="bold")
    matrix.add_column("", justify="center")
    matrix.add_column("Partner", style="bold")
    matrix.add_column("Direction")
    matrix.add_column("Type")

    for trust in trusts:
        direction = getattr(trust, "trust_direction", "Unknown")
        ttype = getattr(trust, "trust_type", "Unknown")
        matrix.add_row(
            mark_sensitive(getattr(trust, "source_domain", ""), "domain"),
            Text(_direction_arrow(direction), style="bold cyan"),
            mark_sensitive(getattr(trust, "target_domain", ""), "domain"),
            Text(direction, style="dim"),
            Text(ttype, style=_type_style(ttype)),
        )

    # Discovered domains table
    domains_table = Table(
        title="Discovered domains",
        title_justify="left",
        title_style="bold",
        expand=False,
        show_lines=False,
        pad_edge=False,
    )
    domains_table.add_column("Domain", style="bold")
    domains_table.add_column("PDC")
    domains_table.add_column("Reachable", justify="center")
    domains_table.add_column("Trusts", justify="right")
    domains_table.add_column("Latency", justify="right", style="dim")

    trust_count_by_source: dict[str, int] = {}
    for trust in trusts:
        src = getattr(trust, "source_domain", "")
        trust_count_by_source[src] = trust_count_by_source.get(src, 0) + 1

    for dom in discovered:
        pdc = pdcs.get(dom) or ""
        conn_summary = connectivity.get(dom, {}) or {}
        reachable = conn_summary.get("reachable")
        if reachable is None:
            reach_cell = Text("—", style="dim")
        elif reachable:
            reach_cell = Text("✓", style="green")
        else:
            reach_cell = Text("✗", style="red")
        if dom in failed:
            reach_cell = Text("✗ query", style="red")
        latency = durations.get(dom)
        latency_cell = f"{latency:0.0f}ms" if latency is not None else "—"
        domains_table.add_row(
            mark_sensitive(dom, "domain"),
            mark_sensitive(pdc, "ip") if pdc else Text("—", style="dim"),
            reach_cell,
            str(trust_count_by_source.get(dom, 0)),
            latency_cell,
        )

    pieces: list[RenderableType] = [header, Text(), matrix, Text(), domains_table]

    if failed:
        pieces.append(Text())
        for fd, err in failed.items():
            line = Text()
            line.append("⚠ ", style="yellow")
            line.append(mark_sensitive(fd, "domain"), style="bold")
            line.append("  query failed: ", style="dim")
            line.append(err, style="red")
            pieces.append(line)
            tip = Text()
            tip.append("   ↳ ", style="dim")
            tip.append(_remediation_for(err), style="dim italic")
            pieces.append(tip)

    return Panel(
        Padding(Group(*pieces), (1, 2)),
        title="[bold green]Trust Enumeration · summary[/bold green]",
        border_style="green",
        expand=False,
    )
