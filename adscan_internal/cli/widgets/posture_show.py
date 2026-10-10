"""Inspection panel for the ``posture show`` REPL command.

Pure renderer over :class:`DomainPosture` snapshots. Builds a single Rich
:class:`~rich.panel.Panel` with up to four sections (Stale, Hardening,
Permissive, Unknown) and locked copy. The widget never mutates state and
never reaches into the workspace — its sole input is the posture snapshot.

Locked copy and palette are asserted by tests; do not edit without bumping
``tests/unit/cli/widgets/test_posture_show.py``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from rich import box
from rich.console import Group, RenderableType
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.domain_posture import (
    ConstraintCategory,
    ConstraintState,
    DomainPosture,
    TriState,
)
from adscan_internal.cli.widgets.posture_probe_live import (
    _HARDENING_SORT_ORDER,
    _PROBE_HARDENING_LABEL,
    _PROBE_PERMISSIVE_LABEL,
)


# --------------------------------------------------------------------------- #
# Locked label maps
# --------------------------------------------------------------------------- #


_PROBE_UNKNOWN_LABEL: dict[ConstraintCategory, str] = {
    ConstraintCategory.LDAP_CHANNEL_BINDING: "LDAP channel binding",
    ConstraintCategory.KERBEROS_ETYPE_PROBE: "Kerberos non-default salt",
    ConstraintCategory.LDAPS_AVAILABLE: "LDAPS availability",
    ConstraintCategory.LDAP_SIGNING: "LDAP signing",
    ConstraintCategory.NTLM_AUTHENTICATION: "NTLM authentication",
    ConstraintCategory.SMB_SIGNING: "SMB signing",
    ConstraintCategory.KERBEROS_RC4: "Kerberos RC4 support",
    ConstraintCategory.KERBEROS_AES_ONLY: "Kerberos AES-only enforcement",
}


# --------------------------------------------------------------------------- #
# Formatting helpers
# --------------------------------------------------------------------------- #


def _format_relative(delta: timedelta) -> str:
    """Render a positive timedelta as 'N seconds/minutes/hours/days ago'."""
    secs = int(max(delta.total_seconds(), 0))
    if secs < 60:
        return f"{secs} seconds ago"
    if secs < 3600:
        return f"{secs // 60} minutes ago"
    if secs < 86400:
        return f"{secs // 3600} hours ago"
    return f"{secs // 86400} days ago"


def _format_ttl(remaining: Optional[timedelta], *, is_stale: bool) -> str:
    """Render a TTL-remaining label.

    Convention:
        stale (or remaining<=0)   → ``"expired"``
        < 60 seconds              → ``"<1m TTL"``
        < 1 hour                  → ``"NNm TTL"``
        < 1 day                   → ``"Hh Mm TTL"``
        otherwise                 → ``"Dd Hh TTL"``
    """
    if is_stale:
        return "expired"
    if remaining is None:
        return "unknown TTL"
    secs = int(remaining.total_seconds())
    if secs <= 0:
        return "expired"
    if secs < 60:
        return "<1m TTL"
    if secs < 3600:
        return f"{secs // 60}m TTL"
    if secs < 86400:
        hours = secs // 3600
        minutes = (secs % 3600) // 60
        return f"{hours}h {minutes}m TTL"
    days = secs // 86400
    hours = (secs % 86400) // 3600
    return f"{days}d {hours}h TTL"


def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
    """Best-effort parse of an ISO-8601 timestamp into UTC. Defensive."""
    if not ts:
        return None
    try:
        parsed = datetime.fromisoformat(ts)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


# --------------------------------------------------------------------------- #
# Public renderer
# --------------------------------------------------------------------------- #


def render_posture_show(
    *,
    posture: DomainPosture,
    domain: str,
    now: Optional[datetime] = None,
) -> Panel:
    """Build the 'Domain Posture' inspection panel.

    Args:
        posture: The posture snapshot to render.
        domain: Domain name shown in the panel title and re-probe hint.
        now: Optional override for "now" (used in tests for deterministic
            relative-time rendering).

    Returns:
        A :class:`rich.panel.Panel` ready to print.
    """
    now = now or datetime.now(timezone.utc)
    masked_domain = mark_sensitive(domain, "domain")
    title = f"[bold cyan]🛡️  Domain Posture · {masked_domain}[/bold cyan]"

    # Empty state — nothing has been observed for any category.
    known = [c for c in posture.constraints.values() if c.state is not TriState.UNKNOWN]
    if not known:
        return _render_empty(title=title, domain=domain)

    # Categorize known constraints.
    stale = [c for c in known if c.is_stale]
    fresh_known = [c for c in known if not c.is_stale]

    hardening: list[ConstraintState] = []
    permissive: list[ConstraintState] = []
    for c in fresh_known:
        if (c.category, c.state) in _PROBE_HARDENING_LABEL:
            hardening.append(c)
        elif (c.category, c.state) in _PROBE_PERMISSIVE_LABEL:
            permissive.append(c)

    # Unknown = every category never observed at all.
    unknown_categories: list[ConstraintCategory] = [
        cat
        for cat in _HARDENING_SORT_ORDER
        if posture.get(cat).state is TriState.UNKNOWN
    ]

    pieces: list[RenderableType] = []

    # Last-refresh line: most recent updated_at across known constraints.
    latest: Optional[datetime] = None
    for c in known:
        ts = _parse_iso(c.updated_at)
        if ts is not None and (latest is None or ts > latest):
            latest = ts
    refresh_line = Text()
    refresh_line.append("Last refresh: ", style="dim")
    if latest is not None:
        iso = latest.strftime("%Y-%m-%d %H:%M UTC")
        rel = _format_relative(now - latest)
        refresh_line.append(f"{iso} ({rel})")
    else:
        refresh_line.append("unknown", style="dim")
    pieces.append(refresh_line)
    pieces.append(Text())

    # Stale section first.
    if stale:
        pieces.append(Text(f"⚠ Stale ({len(stale)})", style="bold yellow"))
        stale_sorted = sorted(stale, key=_sort_key)
        for c in stale_sorted:
            row = Text()
            row.append("  ! ", style="yellow")
            row.append(_unknown_label(c.category))
            row.append("    was: ", style="dim")
            row.append(c.state.value.replace("likely_", ""), style="dim")
            row.append(f" {c.confidence.value}", style="dim")
            row.append(" · ", style="dim")
            row.append(
                _format_relative(c.age) if c.age is not None else "unknown",
                style="dim",
            )
            pieces.append(row)
        hint = Text()
        hint.append("    Re-probe to refresh: ", style="dim")
        hint.append(f"posture probe {domain}", style="bold")
        pieces.append(hint)
        pieces.append(Text())

    # Hardening section.
    if hardening:
        pieces.append(
            Text(f"Hardening detected ({len(hardening)})", style="bold green")
        )
        hardening_sorted = sorted(hardening, key=_sort_key)
        table = Table.grid(padding=(0, 2))
        table.add_column(width=2)
        table.add_column(no_wrap=False)
        table.add_column(style="dim")
        for c in hardening_sorted:
            label = _PROBE_HARDENING_LABEL.get((c.category, c.state), c.category.value)
            ttl_label = _format_ttl(c.ttl_remaining, is_stale=c.is_stale)
            ttl_cell = Text()
            ttl_cell.append(c.confidence.value)
            ttl_cell.append("  ·  ")
            ttl_cell.append(ttl_label)
            table.add_row(Text("✓", style="green"), Text(label), ttl_cell)
            # Evidence sub-row.
            evidence_text = _evidence_line(c, now=now)
            table.add_row(Text(""), Text(evidence_text, style="dim"), Text(""))
        pieces.append(table)
        pieces.append(Text())

    # Permissive section.
    if permissive:
        pieces.append(Text(f"Permissive ({len(permissive)})", style="bold"))
        permissive_sorted = sorted(permissive, key=_sort_key)
        for c in permissive_sorted:
            label = _PROBE_PERMISSIVE_LABEL.get((c.category, c.state), c.category.value)
            row = Text()
            row.append("  ✗ ", style="dim")
            row.append(label, style="dim")
            pieces.append(row)
        pieces.append(Text())

    # Unknown section.
    if unknown_categories:
        pieces.append(
            Text(
                f"Unknown / not yet probed ({len(unknown_categories)})",
                style="bold dim",
            )
        )
        for cat in unknown_categories:
            row = Text()
            row.append("  ? ", style="dim")
            row.append(_unknown_label(cat), style="dim")
            pieces.append(row)
        pieces.append(Text())

    # Footer hints.
    reprobe = Text()
    reprobe.append("Re-probe:  ", style="dim")
    reprobe.append(f"posture probe {domain}", style="bold")
    pieces.append(reprobe)
    clear = Text()
    clear.append("Clear:     ", style="dim")
    clear.append(f"posture clear {domain}", style="bold")
    pieces.append(clear)

    # Border palette: yellow if stale, green if hardening, dim otherwise.
    if stale:
        border_style = "yellow"
    elif hardening:
        border_style = "green"
    else:
        border_style = "dim"

    return Panel(
        Padding(Group(*pieces), (1, 2)),
        title=title,
        border_style=border_style,
        box=box.ROUNDED,
        expand=False,
    )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _render_empty(*, title: str, domain: str) -> Panel:
    pieces: list[RenderableType] = []
    pieces.append(Text("No posture data yet for this domain.", style="dim"))
    pieces.append(Text())
    pieces.append(
        Text(
            "Run a scan or probe to learn the domain's security posture:",
            style="dim",
        )
    )
    cmd = Text()
    cmd.append("  ")
    cmd.append(f"posture probe {domain}", style="bold")
    pieces.append(cmd)
    return Panel(
        Padding(Group(*pieces), (1, 2)),
        title=title,
        border_style="dim",
        box=box.ROUNDED,
        expand=False,
    )


def _evidence_line(c: ConstraintState, *, now: datetime) -> str:
    if not c.evidence:
        return "evidence: (no recorded evidence)"
    latest = c.evidence[-1]
    ts = _parse_iso(latest.timestamp)
    rel = _format_relative(now - ts) if ts is not None else "unknown"
    source = latest.source or "unknown"
    code = latest.signal_code or "unknown"
    return f"evidence: {code} via {source} · {rel}"


def _unknown_label(category: ConstraintCategory) -> str:
    return _PROBE_UNKNOWN_LABEL.get(category, category.value)


def _sort_key(c: ConstraintState) -> int:
    try:
        return _HARDENING_SORT_ORDER.index(c.category)
    except ValueError:
        return len(_HARDENING_SORT_ORDER)


__all__ = ["render_posture_show", "_PROBE_UNKNOWN_LABEL"]
