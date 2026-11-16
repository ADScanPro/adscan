"""Premium Rich Live dashboard for the native CVE scanner.

Layout (per spec §5.2): header band, severity-colored host x CVE matrix,
sidebar with severity tally / top findings, footer with progress bar and
log tail, sticky Domain Breaker alert.

The renderer is designed to be testable in isolation — call
:meth:`CVEDashboard.render` against a canned set of results and snapshot
the resulting :class:`rich.console.RenderableType`.
"""

from __future__ import annotations

import collections
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from rich.align import Align
from rich.box import HEAVY, ROUNDED
from rich.columns import Columns
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.cve_scanner.catalog import CVEDefinition
from adscan_internal.services.cve_scanner.result import (
    CVEResult,
    CVEStatus,
    Severity,
    public_cve_reference,
)

#: Worst first. The top-findings list orders by ADscan severity, never by a
#: CVSS number (CLAUDE.md § "No CVSS on a client surface").
_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold bright_red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

_STATUS_GLYPH: dict[CVEStatus, str] = {
    CVEStatus.VULNERABLE: "●",
    CVEStatus.NOT_VULNERABLE: "○",
    CVEStatus.RUNNING: "…",
    CVEStatus.ERROR: "✗",
    CVEStatus.NOT_APPLICABLE: "–",
    CVEStatus.SKIPPED: "–",
}


@dataclass
class DashboardState:
    """Mutable dashboard state, populated as results stream in."""

    domain: str | None
    masked_creds: str
    concurrency: int
    cve_columns: tuple[CVEDefinition, ...]
    hosts: list[str] = field(default_factory=list)
    matrix: dict[str, dict[str, CVEResult]] = field(default_factory=dict)
    log_tail: collections.deque[str] = field(
        default_factory=lambda: collections.deque(maxlen=5)
    )
    domain_breaker_alert: str | None = None
    total_checks: int = 0
    completed_checks: int = 0
    # Tracks unique (host, cve_id) pairs already counted toward
    # ``completed_checks``. The coercion adapter expands a single engine
    # call into multiple per-technique results; without this guard
    # ``completed_checks`` would overshoot ``total_checks`` by 5x on every
    # coercion run.
    _counted_pairs: set[tuple[str, str]] = field(default_factory=set)

    def register_host(self, host: str) -> None:
        """Add a host row to the matrix if not already present."""

        if host not in self.matrix:
            self.matrix[host] = {}
            self.hosts.append(host)

    def record(self, result: CVEResult) -> None:
        """Update the matrix with a finalised result.

        Counts each ``(host, cve_id)`` pair at most once toward the
        progress counter so the coercion adapter's per-technique result
        fan-out does not overshoot ``total_checks``.
        """

        self.register_host(result.host)
        self.matrix[result.host][result.cve_id] = result
        pair_key = (result.host, result.cve_id)
        if pair_key not in self._counted_pairs:
            self._counted_pairs.add(pair_key)
            if self.completed_checks < self.total_checks:
                self.completed_checks += 1
        self.log_tail.append(
            f"{_glyph(result)} {result.aka} on "
            f"{mark_sensitive(result.host, 'host')} "
            f"[{result.status.value}]"
        )


class CVEDashboard:
    """Renderable dashboard. Use with :class:`rich.live.Live`."""

    def __init__(self, state: DashboardState) -> None:
        self.state = state

    def render(self) -> RenderableType:
        """Build the full dashboard renderable.

        Returns a single :class:`rich.console.Group` that
        :class:`rich.live.Live` can replace in place on every refresh —
        do not ``console.print`` this; pass it through ``live.update``.
        """

        header = self._render_header()
        matrix = self._render_matrix()
        sidebar = self._render_sidebar()
        footer = self._render_footer()

        body = Columns([matrix, sidebar], padding=(0, 2), expand=True)
        children: list[RenderableType] = [header, body]
        if self.state.domain_breaker_alert:
            children.append(self._render_alert())
        children.append(footer)
        return Group(*children)

    def _render_header(self) -> Panel:
        text = Text()
        text.append("ADscan", style="bold bright_magenta")
        text.append("  CVE scanner  ", style="bold")
        text.append("·  domain ", style="dim")
        text.append(
            mark_sensitive(self.state.domain or "—", "domain"), style="bold cyan"
        )
        text.append("  ·  creds ", style="dim")
        text.append(self.state.masked_creds, style="cyan")
        text.append("  ·  concurrency ", style="dim")
        text.append(str(self.state.concurrency), style="bold")
        text.append("  ·  ", style="dim")
        completed = min(self.state.completed_checks, self.state.total_checks)
        text.append(
            f"{completed}/{self.state.total_checks} checks",
            style="bold green",
        )
        return Panel(Align.left(text), box=HEAVY, border_style="bright_magenta")

    def _render_matrix(self) -> Panel:
        table = Table(
            box=ROUNDED,
            show_lines=False,
            border_style="bright_black",
            pad_edge=False,
            expand=True,
        )
        table.add_column("Host", style="bold cyan", no_wrap=True)
        for cve in self.state.cve_columns:
            table.add_column(cve.aka, justify="center", no_wrap=True)

        if not self.state.hosts:
            table.add_row(
                "(awaiting first result…)", *["" for _ in self.state.cve_columns]
            )
        for host in self.state.hosts:
            row: list[RenderableType] = [
                Text(mark_sensitive(host, "host"), style="cyan")
            ]
            row_results = self.state.matrix.get(host, {})
            for cve in self.state.cve_columns:
                result = row_results.get(cve.id)
                row.append(_cell(result))
            table.add_row(*row)
        return Panel(
            table, title="[bold]Findings matrix[/]", border_style="bright_black"
        )

    def _render_sidebar(self) -> Panel:
        tally = self._severity_tally()
        top = self._top_findings()
        sidebar_children: list[RenderableType] = [tally, top]
        return Panel(
            Group(*sidebar_children),
            title="[bold]Status[/]",
            border_style="bright_black",
        )

    def _severity_tally(self) -> Panel:
        counts: dict[Severity, int] = {s: 0 for s in Severity}
        for row in self.state.matrix.values():
            for result in row.values():
                if result.is_vulnerable:
                    counts[result.severity] += 1
        table = Table.grid(padding=(0, 1))
        table.add_column(justify="left")
        table.add_column(justify="right")
        for severity in (
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
        ):
            style = _SEVERITY_STYLE[severity]
            table.add_row(
                Text(severity.value.upper(), style=style),
                Text(str(counts[severity]), style=style),
            )
        return Panel(table, title="Severity tally", border_style="bright_black")

    def _top_findings(self) -> Panel:
        rows: list[CVEResult] = [
            r
            for host_results in self.state.matrix.values()
            for r in host_results.values()
            if r.is_vulnerable
        ]
        rows.sort(
            key=lambda r: (_SEVERITY_ORDER.index(r.severity), r.aka, r.host),
        )
        body = Table.grid(padding=(0, 1))
        body.add_column()
        if not rows:
            body.add_row(Text("no confirmed findings yet", style="dim italic"))
        for result in rows[:5]:
            line = Text()
            line.append("●", style=_SEVERITY_STYLE[result.severity])
            line.append(f"  {result.aka}  ", style="bold")
            line.append(mark_sensitive(result.host, "host"), style="cyan")
            cve_ref = public_cve_reference(result.cve_id)
            if cve_ref:
                line.append(f"  {cve_ref}", style="dim")
            body.add_row(line)
        return Panel(body, title="Top findings", border_style="bright_black")

    def _render_footer(self) -> Panel:
        progress = Progress(
            TextColumn("[bold]progress[/]"),
            BarColumn(bar_width=None, complete_style="bright_green"),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            expand=True,
        )
        total = max(1, self.state.total_checks)
        completed_capped = min(self.state.completed_checks, total)
        progress.add_task(
            "scan",
            total=total,
            completed=completed_capped,
        )
        log = Table.grid(padding=(0, 1))
        log.add_column()
        if not self.state.log_tail:
            log.add_row(Text("(idle)", style="dim italic"))
        for line in self.state.log_tail:
            log.add_row(Text(line, style="dim"))
        body = Group(progress, log)
        return Panel(
            body,
            title="[bold]Activity[/]",
            border_style="bright_black",
        )

    def _render_alert(self) -> Panel:
        text = Text()
        text.append("DOMAIN BREAKER CONFIRMED  ", style="bold bright_red blink")
        text.append(self.state.domain_breaker_alert or "", style="bold white")
        return Panel(
            Align.center(text),
            border_style="bright_red",
            box=HEAVY,
            title="[bold bright_red]ALERT[/]",
        )


def _glyph(result: CVEResult) -> str:
    return _STATUS_GLYPH.get(result.status, "?")


def _cell(result: CVEResult | None) -> RenderableType:
    if result is None:
        return Text(_STATUS_GLYPH[CVEStatus.RUNNING], style="dim")
    glyph = _STATUS_GLYPH.get(result.status, "?")
    if result.status is CVEStatus.VULNERABLE:
        return Text(glyph, style=_SEVERITY_STYLE[result.severity])
    if result.status is CVEStatus.ERROR:
        return Text(glyph, style="bold red")
    if result.status is CVEStatus.NOT_VULNERABLE:
        return Text(glyph, style="green")
    return Text(glyph, style="dim")


def build_state(
    *,
    domain: str | None,
    masked_creds: str,
    concurrency: int,
    cves: Iterable[CVEDefinition],
    targets: Iterable[Any],
) -> DashboardState:
    """Construct an initial :class:`DashboardState` for a scan."""

    cve_cols = tuple(cves)
    target_list = list(targets)
    state = DashboardState(
        domain=domain,
        masked_creds=masked_creds,
        concurrency=concurrency,
        cve_columns=cve_cols,
    )
    state.total_checks = len(cve_cols) * len(target_list)
    for t in target_list:
        host = getattr(t, "host", None) or str(t)
        state.register_host(host)
    return state


__all__ = ["CVEDashboard", "DashboardState", "build_state"]
