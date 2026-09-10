"""Rich output primitives for native collection summaries."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Sequence

from rich.box import ROUNDED, SIMPLE
from rich.columns import Columns
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from adscan_core.output._log import _extract_plain_text, _log_to_file
from adscan_core.output._state import _get_telemetry_console
from adscan_core.theme import (
    COLOR_AMBER as _AMBER,
    COLOR_CRIMSON as _CRIMSON,
    COLOR_MUTED as _MUTED,
    COLOR_SAGE as _SAGE,
    COLOR_STEEL as _STEEL,
    PHASE_ACTIVE as _PHASE_ACTIVE,
    PHASE_DONE as _PHASE_DONE,
    PHASE_PENDING as _PHASE_PENDING,
)


def _get_console() -> Any:
    from adscan_core.rich_output import _get_console as _base_get_console

    return _base_get_console()


def _renderable_to_plain_text(renderable: Any) -> str:
    """Render any Rich renderable (Panel, Table, Group, Text, str) to plain text.

    Strings and Text objects fast-path through _extract_plain_text (matching
    the canonical print_info behaviour). Composite renderables are rendered via
    a throwaway Console so the file log captures something meaningful — the
    rule is "every print also lands in the log file", and that includes panels
    and tables.
    """
    if isinstance(renderable, (str, Text)):
        return _extract_plain_text(renderable)
    try:
        import io

        from rich.console import Console as _Console

        buffer = io.StringIO()
        tmp_console = _Console(
            file=buffer, width=120, record=False, force_terminal=False
        )
        tmp_console.print(renderable)
        return buffer.getvalue().rstrip()
    except Exception:
        return str(renderable)


def _emit(renderable: Any, *, level: int = logging.INFO) -> None:
    """Print a renderable to console, telemetry, and log file.

    Mirror of the canonical pattern in adscan_core.output._log so premium
    components in this module respect the global "always log + telemetry" rule.
    """
    console = _get_console()
    _get_telemetry_console()
    console.print(renderable)
    plain = _renderable_to_plain_text(renderable)
    if plain:
        _log_to_file(level, plain)


def _emit_blank() -> None:
    """Print a blank line to console and telemetry console (not log file)."""
    console = _get_console()
    _get_telemetry_console()
    console.print()


_DIM = "dim"


# ---------------------------------------------------------------------------
# Session header
# ---------------------------------------------------------------------------


@dataclass
class SessionHeader:
    """Context shown at scan start: workspace, target, credential, mode.

    The ``experimental`` flag is the TUI-level signal that the active
    command is running unattended (autonomous, no operator prompts).
    When set, the Mode row is annotated with a visible
    ``⚡ AUTONOMOUS`` badge using the amber accent so operators see at a
    glance that the run is hands-off. The information is duplicated in a
    dedicated callout panel (:func:`print_ci_autonomous_callout`) for
    first-run discoverability.
    """

    workspace: str
    target_domain: str
    dc_ip: str
    credential_label: str = ""
    scan_mode: str = "ci"
    version: str = ""
    experimental: bool = False


def print_session_header(header: SessionHeader) -> None:
    """Print the branded session header at the start of a scan.

    Shows the ASCII gradient logo, a tagline line, then a compact info
    bar with workspace, target domain, DC IP, credential, and mode.
    When ``header.experimental`` is set the Mode row carries an inline
    AUTONOMOUS badge so unattended runs are always visible — never
    hidden behind a help flag.
    """
    from adscan_core.branding import build_gradient_ascii, ADSCAN_TAGLINE

    console = _get_console()
    width = console.width or 120

    _emit(build_gradient_ascii(width=width))

    tag_parts: list[Any] = [("  " + ADSCAN_TAGLINE, f"bold {_STEEL}")]
    if header.version:
        tag_parts.append((f"  v{header.version}", _MUTED))
    _emit(Text.assemble(*tag_parts))
    _emit_blank()

    grid = Table.grid(padding=(0, 3))
    grid.add_column(style=_DIM, justify="right", min_width=12)
    grid.add_column(justify="left")

    grid.add_row("Workspace", f"[bold {_STEEL}]{header.workspace}[/]")
    grid.add_row(
        "Target",
        f"[bold]{header.target_domain.upper()}[/]  [{_MUTED}]{header.dc_ip}[/]",
    )
    if header.credential_label:
        grid.add_row("Credential", f"[{_STEEL}]{header.credential_label}[/]")
    mode_style = _AMBER if header.scan_mode == "ci" else _SAGE
    mode_cell = f"[{mode_style}]{header.scan_mode.upper()}[/]"
    if header.experimental:
        # Inline badge — always visible, no chrome. The ⚡ glyph plus the
        # explicit word "AUTONOMOUS" mean the indicator is legible even
        # under NO_COLOR, and disambiguates what makes this mode different
        # (no prompts, defaults applied).
        mode_cell = f"{mode_cell}   [bold {_AMBER}]⚡ AUTONOMOUS[/]"
    grid.add_row("Mode", mode_cell)

    _emit(
        Panel(
            grid,
            border_style=f"bold {_STEEL}",
            box=ROUNDED,
            padding=(0, 2),
        )
    )
    _emit_blank()


# ---------------------------------------------------------------------------
# Autonomous mode callout
# ---------------------------------------------------------------------------


def print_ci_autonomous_callout() -> None:
    """Print the one-shot educational callout for autonomous (ci) mode.

    Rendered immediately after the session header on every ``adscan ci``
    run. Frames operator expectations before the scan starts:

    * ``adscan ci`` is a thin wrapper that drives the same engine the
      interactive ``adscan start`` shell drives, with all confirmation
      prompts skipped and defaults applied automatically.
    * Defaults are calibrated for common lab and CI/CD flows, and are
      applied without a prompt — this callout exists so the operator
      knows which decisions were made unattended.
    * Concrete recovery paths if a run looks wrong: ``--debug``, the
      docs link, and re-running in interactive mode for the same
      target.

    Visual contract — pure TUI design system:

    * Border: amber (warn accent) so the panel reads as a status banner
      and not as a hard error.
    * Title: ⚡ glyph + plain words so the signal carries through
      NO_COLOR terminals.
    * Body: three concise rows; no walls of text. Cyan accents for
      actionable verbs (re-run, switch), muted dim for metadata.
    """
    body = Table.grid(padding=(0, 2))
    body.add_column(style=_DIM, justify="right", min_width=10)
    body.add_column(justify="left")

    body.add_row(
        f"[bold {_STEEL}]What[/]",
        (
            f"[bold]Autonomous scan[/] — no prompts, defaults applied. "
            f"Same engine as [{_STEEL}]adscan start[/], hands-off control flow."
        ),
    )
    body.add_row(
        f"[bold {_AMBER}]Defaults[/]",
        (
            f"[bold {_AMBER}]Applied automatically[/]  "
            f"[{_MUTED}]No confirmation prompts — see below to review or override.[/]"
        ),
    )
    body.add_row(
        f"[bold {_STEEL}]If wrong[/]",
        (
            f"Re-run with [bold]--debug[/] for verbose telemetry, then "
            f"open an issue at [{_STEEL}]github.com/ADscanPro/adscan/issues[/]. "
            f"For operator-in-the-loop control switch to "
            f"[{_STEEL}]adscan start[/]."
        ),
    )

    panel = Panel(
        body,
        title=f"[bold {_AMBER}]⚡ Autonomous Mode[/]",
        title_align="left",
        border_style=f"bold {_AMBER}",
        box=ROUNDED,
        padding=(1, 2),
    )
    _emit(panel)
    _emit_blank()


@dataclass(frozen=True)
class CollectionSummary:
    """Counters rendered after one native domain collection pass."""

    domain: str
    users: int
    computers: int
    groups: int
    ous: int
    gpos: int
    memberof_edges: int
    acl_edges: int
    gplink_edges: int
    trustedby_edges: int
    elapsed_seconds: float
    credential_label: str = ""

    @property
    def total_nodes(self) -> int:
        """Return the primary AD object count shown to the operator."""
        return self.users + self.computers + self.groups + self.ous + self.gpos


def format_collection_summary_text(summary: CollectionSummary) -> str:
    """Return a plain-text representation for tests and non-Rich callers."""
    lines = [
        f"Domain: {summary.domain.upper()}",
        (
            f"Nodes: {summary.total_nodes} "
            f"(users={summary.users} computers={summary.computers} "
            f"groups={summary.groups} ous={summary.ous} gpos={summary.gpos})"
        ),
        (
            f"Edges: memberof={summary.memberof_edges} acl={summary.acl_edges} "
            f"gplink={summary.gplink_edges} trustedby={summary.trustedby_edges}"
        ),
        f"Elapsed: {summary.elapsed_seconds:.1f}s",
    ]
    if summary.credential_label:
        lines.append(f"Credential: {summary.credential_label}")
    return "\n".join(lines)


def _make_bar(value: int, total: int, width: int = 8) -> str:
    """Return an ASCII proportion bar string."""
    if total <= 0:
        filled = 0
    else:
        filled = min(width, round(value / total * width))
    return "█" * filled + "░" * (width - filled)


def print_collection_summary(summary: CollectionSummary) -> None:
    """Print a premium post-collection summary panel.

    Two-column layout: object/edge counters left, derived metrics right.
    Color coding: cyan users, green computers, magenta groups, amber ACLs.
    """
    relationship_total = (
        summary.memberof_edges
        + summary.acl_edges
        + summary.gplink_edges
        + summary.trustedby_edges
    )

    # --- Status icon ---
    if summary.total_nodes > 0:
        status_icon = f"[bold {_SAGE}]◉[/]"
        border = "green"
        title_label = "Collection Complete"
    else:
        status_icon = f"[bold {_CRIMSON}]✗[/]"
        border = "red"
        title_label = "Collection Empty"

    # --- Left column: object counters ---
    left = Table.grid(padding=(0, 2))
    left.add_column(style=_DIM, justify="right", min_width=13)
    left.add_column(justify="left")

    left.add_row(
        "Users",
        f"[bold cyan]{summary.users}[/] {_make_bar(summary.users, summary.total_nodes)}",
    )
    left.add_row(
        "Computers",
        f"[bold green]{summary.computers}[/] {_make_bar(summary.computers, summary.total_nodes)}",
    )
    left.add_row(
        "Groups",
        f"[bold magenta]{summary.groups}[/] {_make_bar(summary.groups, summary.total_nodes)}",
    )
    left.add_row(
        "OUs / GPOs",
        f"[{_MUTED}]{summary.ous} / {summary.gpos}[/]",
    )
    left.add_row("", "")
    left.add_row(
        "ACL edges",
        f"[bold {_AMBER}]{summary.acl_edges:,}[/]",
    )
    left.add_row(
        "MemberOf",
        f"[{_STEEL}]{summary.memberof_edges:,}[/]",
    )
    left.add_row(
        "All edges",
        f"[bold]{relationship_total:,}[/]",
    )

    # --- Right column: derived metrics ---
    right = Table.grid(padding=(0, 2))
    right.add_column(style=_DIM, justify="right", min_width=13)
    right.add_column(justify="left")

    acl_pct = (
        (summary.acl_edges / relationship_total * 100)
        if relationship_total > 0
        else 0.0
    )
    right.add_row(
        "ACL coverage",
        f"[bold {_AMBER}]{acl_pct:.0f}%[/]",
    )
    right.add_row(
        "Scope size",
        f"[bold]{summary.total_nodes:,}[/] objects",
    )
    right.add_row(
        "Elapsed",
        f"[{_MUTED}]{summary.elapsed_seconds:.1f}s[/]",
    )
    if summary.credential_label:
        right.add_row("", "")
        right.add_row(
            "Credential",
            f"[{_STEEL}]{summary.credential_label}[/]",
        )

    body = Columns([left, right], equal=False, expand=False, padding=(0, 4))

    title = Text.assemble(
        Text.from_markup(f"{status_icon} "),
        (title_label, "bold"),
        ("  ·  ", _MUTED),
        (summary.domain.upper(), f"bold {_STEEL}"),
    )

    _emit(
        Panel(
            body,
            title=title,
            border_style=border,
            box=ROUNDED,
            padding=(0, 1),
        )
    )


# ---------------------------------------------------------------------------
# Phase status dataclass
# ---------------------------------------------------------------------------


@dataclass
class PhaseStatus:
    """Single phase entry for the pipeline dashboard."""

    label: str
    subtitle: str
    status: str  # "done" | "active" | "pending" | "skipped" | "failed"


def print_phase_dashboard(phases: Sequence[PhaseStatus]) -> None:
    """Print a horizontal scan pipeline strip.

    Shows all phases with status icons in a single HUD-style panel:
      ◉ Phase  ▸ Phase  ○ Phase  ○ Phase
      Done     Active   Pending  Pending
    """
    _ICON = {
        "done": f"[{_PHASE_DONE}]◉[/]",
        "active": f"[{_PHASE_ACTIVE}]▸[/]",
        "pending": f"[{_PHASE_PENDING}]○[/]",
        "skipped": f"[{_MUTED}]—[/]",
        "failed": f"[bold {_CRIMSON}]✗[/]",
    }
    _LABEL_STYLE = {
        "done": _PHASE_DONE,
        "active": _PHASE_ACTIVE,
        "pending": _PHASE_PENDING,
        "skipped": _MUTED,
        "failed": f"bold {_CRIMSON}",
    }

    icon_row = Text()
    sub_row = Text()

    cell_width = 14
    for i, phase in enumerate(phases):
        icon = _ICON.get(phase.status, f"[{_PHASE_PENDING}]○[/]")
        label_style = _LABEL_STYLE.get(phase.status, _PHASE_PENDING)
        sep = "  " if i < len(phases) - 1 else ""

        icon_row.append_text(Text.from_markup(f"{icon} "))
        icon_row.append(phase.label.ljust(cell_width - 2), style=label_style)
        icon_row.append(sep)

        sub_row.append(phase.subtitle.ljust(cell_width), style=_MUTED)
        sub_row.append(sep)

    grid = Table.grid(padding=(0, 0))
    grid.add_row(icon_row)
    grid.add_row(sub_row)

    _emit(
        Panel(
            grid,
            title=f"[{_MUTED}]Scan Pipeline[/]",
            border_style="grey35",
            box=ROUNDED,
            padding=(0, 2),
        )
    )


# ---------------------------------------------------------------------------
# Domain card
# ---------------------------------------------------------------------------


@dataclass
class DomainReachability:
    """Reachability + auth state for a single domain."""

    domain: str
    dc_fqdn: str | None = None
    reachable: bool = False
    authenticated: bool = False
    trust_source: str | None = None
    user_count: int | None = None
    dc_count: int | None = None


def print_domain_card(info: DomainReachability) -> None:
    """Print a single-domain status card used in the pre-collection scope picker.

    Each card shows reachability, auth status, and available metadata.
    """
    reach_icon = f"[bold {_SAGE}]◉[/]" if info.reachable else f"[bold {_CRIMSON}]○[/]"
    auth_icon = f"[bold {_SAGE}]✓[/]" if info.authenticated else f"[{_MUTED}]—[/]"
    border = "green" if (info.reachable and info.authenticated) else "grey35"

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=_DIM, justify="right", min_width=12)
    grid.add_column(justify="left")

    dc_label = info.dc_fqdn or "unknown"
    grid.add_row("Domain Controller", f"[{_STEEL}]{dc_label}[/]")
    grid.add_row(
        "Reachability",
        Text.from_markup(
            f"{reach_icon} {'reachable' if info.reachable else 'unreachable'}"
        ),
    )
    grid.add_row(
        "Auth",
        Text.from_markup(
            f"{auth_icon} {'confirmed' if info.authenticated else 'not verified'}"
        ),
    )

    if info.trust_source:
        grid.add_row("Via trust", f"[{_MUTED}]{info.trust_source}[/]")
    if info.user_count is not None:
        grid.add_row("Users (LDAP)", f"[cyan]{info.user_count:,}[/]")
    if info.dc_count is not None:
        grid.add_row("DCs", f"[{_STEEL}]{info.dc_count}[/]")

    title = Text()
    title.append(info.domain.upper(), style=f"bold {_STEEL}")

    _emit(
        Panel(
            grid,
            title=title,
            border_style=border,
            box=ROUNDED,
            padding=(0, 1),
            expand=False,
        )
    )


# ---------------------------------------------------------------------------
# ACL findings table
# ---------------------------------------------------------------------------

_SEVERITY_STYLE = {
    "critical": f"bold {_CRIMSON}",
    "high": f"bold {_AMBER}",
    "medium": "bold yellow",
    "low": _MUTED,
}

_CRITICAL_RIGHTS = {"WriteDACL", "GenericAll", "WriteOwner", "GenericWrite", "Owns"}


@dataclass
class AclFinding:
    """Single ACE finding for the findings table."""

    source: str
    source_type: str
    right: str
    target: str
    target_type: str
    target_is_high_value: bool = False
    severity: str = "high"


def print_acl_findings_table(
    findings: Sequence[AclFinding],
    only_critical: bool = True,
    max_rows: int = 40,
) -> None:
    """Print a severity-coded ACE findings table.

    Used at end of Phase 1 to surface WriteDACL/GenericAll/WriteOwner edges
    targeting high-value nodes. Rows are sorted critical → high → medium → low.
    """
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    filtered = [f for f in findings if not only_critical or f.right in _CRITICAL_RIGHTS]
    sorted_findings = sorted(
        filtered, key=lambda f: (severity_order.get(f.severity, 9), f.target)
    )
    visible = sorted_findings[:max_rows]

    if not visible:
        _emit(f"[{_MUTED}]  No ACL findings to display.[/]")
        return

    table = Table(
        box=SIMPLE,
        show_header=True,
        header_style=f"bold {_MUTED}",
        border_style="grey35",
        expand=False,
        padding=(0, 1),
    )
    table.add_column("SEV", style=_DIM, width=5, no_wrap=True)
    table.add_column("RIGHT", style="bold", min_width=14, no_wrap=True)
    table.add_column("SOURCE", min_width=20)
    table.add_column("TYPE", style=_DIM, width=8, no_wrap=True)
    table.add_column("TARGET", min_width=20)
    table.add_column("HV", width=3, justify="center")

    for finding in visible:
        sev_style = _SEVERITY_STYLE.get(finding.severity, _MUTED)
        hv_mark = f"[bold {_AMBER}]★[/]" if finding.target_is_high_value else ""
        table.add_row(
            Text(finding.severity[:4].upper(), style=sev_style),
            Text(finding.right, style=sev_style),
            finding.source,
            Text(finding.source_type[:8], style=_MUTED),
            finding.target,
            Text.from_markup(hv_mark),
        )

    overflow_count = len(sorted_findings) - len(visible)
    caption = None
    if overflow_count > 0:
        caption = f"[{_MUTED}]… {overflow_count} more findings not shown[/]"

    _emit(
        Panel(
            table,
            title=f"[bold]ACL Findings[/]  [{_MUTED}]({len(visible)} shown)[/]",
            border_style=f"bold {_CRIMSON}"
            if any(f.severity == "critical" for f in visible)
            else _AMBER,
            box=ROUNDED,
            padding=(0, 1),
            subtitle=caption,
        )
    )


# ---------------------------------------------------------------------------
# Tactical findings panel
# ---------------------------------------------------------------------------

# Severity tier per relation — ordered from most critical down
_RELATION_SEVERITY: dict[str, str] = {
    "DCSync": "critical",
    "GetChangesAll": "critical",
    "GenericAll": "critical",
    "WriteDACL": "critical",
    "WriteOwner": "critical",
    "Owns": "critical",
    "ForceChangePassword": "high",
    "AddMember": "high",
    "AddSelf": "high",
    "ReadLAPSPassword": "high",
    "SyncLAPSPassword": "high",
    "ReadGMSAPassword": "high",
    "AllExtendedRights": "high",
    "GenericWrite": "high",
    "WriteSPN": "medium",
    "AddKeyCredentialLink": "medium",
    "WriteAccountRestrictions": "medium",
    "WriteLogonScript": "medium",
    "GetChanges": "medium",
    "AllowedToDelegate": "medium",
    "ManageRODCPrp": "low",
}

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_SEV_BADGE = {
    "critical": f"[bold {_CRIMSON}]CRIT[/]",
    "high": f"[bold {_AMBER}]HIGH[/]",
    "medium": "[bold yellow]MED [/]",
    "low": f"[{_MUTED}]LOW [/]",
}


@dataclass
class TacticalFinding:
    """One 1-hop attack-surface finding from the collected graph."""

    right: str
    source: str
    source_type: str
    target: str
    target_type: str
    target_is_high_value: bool = False
    # Canonical severity (CRITICAL/HIGH/MEDIUM/LOW/INFO/STRUCTURAL) computed
    # by adscan_internal.services.severity.compute_edge_severity. When unset
    # (legacy callers), the panel falls back to the relation-based heuristic
    # in the ``severity`` property below.
    canonical_severity: str | None = None
    # Optional Tier 0 asset role to display in brackets next to the target
    # name: "DC", "Exchange", "ADCS CA".
    target_role: str | None = None
    # True when the target is a Tier 0 asset. Used by the renderer to add
    # the "Tier0 Foothold · post-ex pending" hint under auth edges.
    target_is_tier0_asset: bool = False
    # Canonical edge kind (control/auth/escalation/derived/membership/trust/
    # unknown). Used by the renderer to detect Tier0 Foothold rows.
    edge_kind: str | None = None
    # True when the source principal is an unauthenticated well-known SID
    # (Anonymous Logon, Network, Everyone). Renderer adds a runtime caveat
    # under the row: "requires null session / Pre-Windows 2000 Compat".
    source_is_unauthenticated: bool = False
    # ★ HV is per-path, not per-edge. TODO: populate from shortest-path
    # computation against the Domain Compromised terminal. Until then, the
    # renderer leaves the HV column empty.
    on_shortest_path: bool = False

    @property
    def severity(self) -> str:
        """Legacy relation-based severity (kept for backward compat).

        New code should set ``canonical_severity`` from
        :func:`adscan_internal.services.severity.compute_edge_severity` —
        the renderer prefers it when available.
        """
        if self.right.startswith("ADCSESC"):
            return "critical"
        return _RELATION_SEVERITY.get(self.right, "low")


@dataclass
class TacticalFindings:
    """Post-collection 1-hop findings for the tactical panel."""

    domain: str
    findings: list[TacticalFinding] = field(default_factory=list)
    kerberoastable: list[str] = field(default_factory=list)
    asreproastable: list[str] = field(default_factory=list)
    adcs_esc_count: int = 0

    @property
    def has_content(self) -> bool:
        return bool(
            self.findings
            or self.kerberoastable
            or self.asreproastable
            or self.adcs_esc_count
        )


# Canonical severity → display tokens. Maps the Severity enum's string value
# (CRITICAL/HIGH/...) to the same colour/badge tokens the panel already uses,
# so existing legacy ("critical"/"high"/...) callers keep rendering correctly.
_CANONICAL_SEV_BADGE: dict[str, str] = {
    "CRITICAL": f"[bold {_CRIMSON}]CRIT[/]",
    "HIGH": f"[bold {_AMBER}]HIGH[/]",
    "MEDIUM": "[bold yellow]MED [/]",
    "LOW": f"[{_MUTED}]LOW [/]",
    "INFO": f"[{_MUTED}]INFO[/]",
    "STRUCTURAL": f"[{_MUTED}]STRC[/]",
}

_CANONICAL_SEV_STYLE: dict[str, str] = {
    "CRITICAL": f"bold {_CRIMSON}",
    "HIGH": f"bold {_AMBER}",
    "MEDIUM": "bold yellow",
    "LOW": _MUTED,
    "INFO": _MUTED,
    "STRUCTURAL": _MUTED,
}

_CANONICAL_SEV_RANK: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
    "STRUCTURAL": 5,
}


def _resolved_canonical_severity(f: TacticalFinding) -> str:
    """Return the upper-case canonical severity for one finding.

    Prefers ``canonical_severity`` set by the new builder. Falls back to
    mapping the legacy relation-based ``severity`` property to the closest
    canonical value, so legacy callers continue to render — but the new
    severity matrix only kicks in when the builder populates the field.
    """
    if f.canonical_severity:
        return f.canonical_severity.upper()
    legacy = (f.severity or "low").lower()
    return {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
    }.get(legacy, "LOW")


def _show_structural_default() -> bool:
    """Read the structural-band toggle from env (set by ``--show-structural``).

    Used as the default for :func:`print_tactical_findings`'s
    ``show_structural`` parameter so the flag plumbed at the CLI top level
    propagates without threading it through every subcommand.
    """
    import os

    return os.getenv("ADSCAN_SHOW_STRUCTURAL", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _build_findings_table(
    rows: list[TacticalFinding],
) -> Table:
    """Build the inner findings table for one band."""
    table = Table(
        box=SIMPLE,
        show_header=True,
        header_style=f"bold {_MUTED}",
        border_style="grey35",
        expand=False,
        padding=(0, 1),
        show_edge=False,
    )
    table.add_column("SEV", width=5, no_wrap=True)
    table.add_column("RIGHT", min_width=16, no_wrap=True)
    table.add_column("SOURCE", min_width=22)
    table.add_column("→", width=1, justify="center", style=_MUTED)
    table.add_column("TARGET", min_width=22)
    table.add_column("HV", width=3, justify="center")

    for f in rows:
        sev = _resolved_canonical_severity(f)
        sev_style = _CANONICAL_SEV_STYLE.get(sev, _MUTED)
        # ★ HV is per-path. We populate when the builder marks the edge as
        # being on the shortest path; otherwise leave blank rather than
        # invent a per-edge signal (anti-pattern: "validate before
        # implementing"). target_is_high_value is kept as a tie-breaker
        # for visual emphasis only.
        if f.on_shortest_path:
            hv_mark = Text.from_markup(f"[bold {_AMBER}]★[/]")
        else:
            hv_mark = Text("")
        source_label = f"[bold]{f.source}[/]" if f.target_is_high_value else f.source
        target_label = f.target
        if f.target_role:
            target_label = f"{f.target} [{_MUTED}]\\[{f.target_role}][/]"
        table.add_row(
            _CANONICAL_SEV_BADGE.get(sev, "    "),
            Text(f.right, style=sev_style),
            Text.from_markup(source_label),
            "→",
            Text.from_markup(target_label),
            hv_mark,
        )
        # Tier 0 Foothold annotation — render as a child line under any
        # auth edge whose target is a Tier 0 asset.
        if f.target_is_tier0_asset and (f.edge_kind or "").lower() == "auth":
            table.add_row(
                "",
                "",
                "",
                "",
                Text.from_markup(f"[{_MUTED}]└─ Tier0 Foothold · post-ex pending[/]"),
                "",
            )
        # Unauthenticated principal caveat — exploitation requires null
        # session / Pre-Windows 2000 Compatible Access; uncertain without
        # runtime validation.
        if f.source_is_unauthenticated:
            table.add_row(
                "",
                "",
                "",
                "",
                Text.from_markup(
                    f"[{_MUTED}]└─ requires null session / Pre-Windows 2000 Compatible Access[/]"
                ),
                "",
            )

    return table


def print_tactical_findings(
    findings: TacticalFindings,
    max_rows: int = 30,
    *,
    show_structural: bool | None = None,
) -> None:
    """Print a post-collection tactical findings panel in three bands.

    Default reorganises findings by *role in the path*, not by relation
    label, following the ``Tactical Findings`` UX in
    ``12_nomenclature_standard.md`` § "Severidad de edges":

    * 🎯 CHOKE POINTS  (CRITICAL + HIGH) — edges crossing into Tier 0.
    * 🔓 PRIVILEGED ESCALATIONS — sub-band of CHOKE POINTS where the
      source is a Privileged Escalator and the target is a Domain Breaker
      (printed only when at least one such row exists).
    * 📋 STRUCTURAL — INFO + STRUCTURAL counted but NOT printed unless
      ``show_structural=True`` (or ``ADSCAN_SHOW_STRUCTURAL=1``).

    The MEDIUM/LOW counters render as a single trailing line, since they
    rarely need triage attention but should not be silent.
    """
    if not findings.has_content:
        return

    if show_structural is None:
        show_structural = _show_structural_default()

    # Bucket findings by canonical severity.
    buckets: dict[str, list[TacticalFinding]] = {
        "CRITICAL": [],
        "HIGH": [],
        "MEDIUM": [],
        "LOW": [],
        "INFO": [],
        "STRUCTURAL": [],
    }
    for f in findings.findings:
        sev = _resolved_canonical_severity(f)
        buckets.setdefault(sev, []).append(f)

    def _sort(rows: list[TacticalFinding]) -> list[TacticalFinding]:
        return sorted(
            rows,
            key=lambda f: (
                _CANONICAL_SEV_RANK.get(_resolved_canonical_severity(f), 9),
                not f.on_shortest_path,
                not f.target_is_high_value,
                f.right,
                f.target,
            ),
        )

    # CHOKE POINTS = CRITICAL only. PRIVILEGED ESCALATIONS = HIGH only.
    # Each finding lands in exactly one band — no double counting. This
    # mirrors the UX rule: CRIT means "exploitable today by an unprivileged
    # principal", HIGH means "Privileged Escalator one technique away from
    # Domain". Both deserve their own table.
    choke_rows = _sort(buckets["CRITICAL"])
    priv_esc_rows = _sort(buckets["HIGH"])

    structural_count = len(buckets["INFO"]) + len(buckets["STRUCTURAL"])
    structural_rows = _sort(buckets["INFO"] + buckets["STRUCTURAL"])
    medium_count = len(buckets["MEDIUM"])
    low_count = len(buckets["LOW"])

    has_critical = bool(buckets["CRITICAL"])
    border = _CRIMSON if has_critical else _AMBER

    from rich.console import Group as RichGroup

    lines: list[Any] = []

    # 🎯 CHOKE POINTS band ----------------------------------------------------
    if choke_rows:
        n = len(choke_rows)
        lines.append(
            Text.from_markup(
                f"[bold {_CRIMSON}]🎯 CHOKE POINTS[/]  "
                f"[{_STEEL}]({n})[/]  "
                f"[{_MUTED}]edges crossing into Tier 0[/]"
            )
        )
        visible = choke_rows[:max_rows]
        overflow = len(choke_rows) - len(visible)
        lines.append(_build_findings_table(visible))
        if overflow:
            lines.append(
                Text.from_markup(f"  [{_MUTED}]… {overflow} more choke points[/]")
            )

    # 🔓 PRIVILEGED ESCALATIONS band ----------------------------------------
    if priv_esc_rows:
        if lines:
            lines.append(Text(""))
        n_pe = len(priv_esc_rows)
        lines.append(
            Text.from_markup(
                f"[bold {_AMBER}]🔓 PRIVILEGED ESCALATIONS[/]  "
                f"[{_STEEL}]({n_pe})[/]  "
                f"[{_MUTED}]Escalator → Domain · one known technique away[/]"
            )
        )
        visible_pe = priv_esc_rows[:max_rows]
        overflow_pe = len(priv_esc_rows) - len(visible_pe)
        lines.append(_build_findings_table(visible_pe))
        if overflow_pe:
            lines.append(
                Text.from_markup(
                    f"  [{_MUTED}]… {overflow_pe} more privileged escalations[/]"
                )
            )

    # 📋 STRUCTURAL band ------------------------------------------------------
    if structural_count:
        if lines:
            lines.append(Text(""))
        if show_structural:
            lines.append(
                Text.from_markup(
                    f"[bold {_MUTED}]📋 STRUCTURAL[/]  "
                    f"[{_STEEL}]({structural_count})[/]  "
                    f"[{_MUTED}]expected AD hierarchy[/]"
                )
            )
            visible = structural_rows[:max_rows]
            overflow = len(structural_rows) - len(visible)
            lines.append(_build_findings_table(visible))
            if overflow:
                lines.append(
                    Text.from_markup(
                        f"  [{_MUTED}]… {overflow} more structural rows[/]"
                    )
                )
        else:
            lines.append(
                Text.from_markup(
                    f"[bold {_MUTED}]📋 STRUCTURAL[/]  "
                    f"[{_STEEL}]({structural_count} hidden)[/]  "
                    f"[{_MUTED}]expected AD hierarchy[/]"
                )
            )
            lines.append(
                Text.from_markup(
                    f"  [{_MUTED}]Show with: --show-structural   or   press \\[s][/]"
                )
            )

    # Other-edges trailing counter -------------------------------------------
    other_parts: list[str] = []
    if medium_count:
        other_parts.append(f"{medium_count} MEDIUM")
    if low_count:
        other_parts.append(f"{low_count} LOW")
    if other_parts:
        if lines:
            lines.append(Text(""))
        lines.append(
            Text.from_markup(f"  [{_MUTED}]Other edges: {' · '.join(other_parts)}[/]")
        )

    # Roasting summary line (preserved verbatim from the legacy panel) -------
    roast_parts: list[str] = []
    if findings.kerberoastable:
        names = ", ".join(findings.kerberoastable[:4])
        tail = (
            f" +{len(findings.kerberoastable) - 4} more"
            if len(findings.kerberoastable) > 4
            else ""
        )
        roast_parts.append(
            f"[bold {_AMBER}]Kerberoastable[/]  [{_STEEL}]{len(findings.kerberoastable)}[/]"
            f" [{_MUTED}]({names}{tail})[/]"
        )
    if findings.asreproastable:
        names = ", ".join(findings.asreproastable[:4])
        tail = (
            f" +{len(findings.asreproastable) - 4} more"
            if len(findings.asreproastable) > 4
            else ""
        )
        roast_parts.append(
            f"[bold {_AMBER}]AS-REP Roastable[/]  [{_STEEL}]{len(findings.asreproastable)}[/]"
            f" [{_MUTED}]({names}{tail})[/]"
        )
    if findings.adcs_esc_count:
        roast_parts.append(
            f"[bold {_CRIMSON}]ADCS ESC paths[/]  [{_STEEL}]{findings.adcs_esc_count}[/]"
        )

    if roast_parts:
        if lines:
            lines.append(Text(""))
        for part in roast_parts:
            lines.append(Text.from_markup(f"  {part}"))

    body = RichGroup(*lines)

    title = Text.assemble(
        Text.from_markup(f"[bold {_CRIMSON}]⚡[/] "),
        ("Tactical Findings", "bold"),
        ("  ·  ", _MUTED),
        (findings.domain.upper(), f"bold {_STEEL}"),
    )

    _emit(
        Panel(
            body,
            title=title,
            border_style=border,
            box=ROUNDED,
            padding=(0, 1),
        )
    )


# ---------------------------------------------------------------------------
# End-of-run loot card
# ---------------------------------------------------------------------------


@dataclass
class SessionLootCard:
    """Aggregated post-run findings for the end-of-run loot card."""

    domain: str
    elapsed_seconds: float = 0.0
    da_paths: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    kerberoastable: int = 0
    asreproastable: int = 0
    adcs_esc_count: int = 0
    owned_accounts: list[str] = field(default_factory=list)
    total_nodes: int = 0

    @property
    def has_findings(self) -> bool:
        return bool(
            self.da_paths
            or self.critical_findings
            or self.kerberoastable
            or self.adcs_esc_count
            or self.owned_accounts
        )


def print_session_loot_card(card: SessionLootCard) -> None:
    """Print the end-of-run loot card panel.

    Surfaces the highest-value findings in a single shareable panel.
    Designed to be the last thing printed after adscan ci completes.
    """
    has_da = card.da_paths > 0
    border = _CRIMSON if has_da else (_AMBER if card.has_findings else "grey35")

    left = Table.grid(padding=(0, 2))
    left.add_column(style=_DIM, justify="right", min_width=16)
    left.add_column(justify="left")

    if card.da_paths > 0:
        left.add_row(
            "DA paths",
            f"[bold {_CRIMSON}]{card.da_paths}[/]  [bold {_CRIMSON}]← PWNED[/]",
        )
    else:
        left.add_row("DA paths", f"[{_MUTED}]No paths found[/]")

    left.add_row(
        "Critical / High",
        f"[bold {_CRIMSON}]{card.critical_findings}[/]"
        f"  [{_AMBER}]{card.high_findings}[/]",
    )
    left.add_row(
        "Kerberoastable",
        f"[bold {_AMBER}]{card.kerberoastable}[/]"
        if card.kerberoastable
        else f"[{_MUTED}]0[/]",
    )
    left.add_row(
        "AS-REP roastable",
        f"[bold {_AMBER}]{card.asreproastable}[/]"
        if card.asreproastable
        else f"[{_MUTED}]0[/]",
    )
    left.add_row(
        "ADCS ESC paths",
        f"[bold {_CRIMSON}]{card.adcs_esc_count}[/]"
        if card.adcs_esc_count
        else f"[{_MUTED}]0[/]",
    )

    right = Table.grid(padding=(0, 2))
    right.add_column(style=_DIM, justify="right", min_width=14)
    right.add_column(justify="left")

    right.add_row(
        "Scope",
        f"[bold]{card.total_nodes:,}[/] objects"
        if card.total_nodes
        else f"[{_MUTED}]—[/]",
    )
    right.add_row("Elapsed", f"[{_MUTED}]{card.elapsed_seconds:.1f}s[/]")

    if card.owned_accounts:
        right.add_row("", "")
        right.add_row("Owned", f"[bold {_SAGE}]{len(card.owned_accounts)}[/] accounts")
        preview = card.owned_accounts[:4]
        tail = (
            f" +{len(card.owned_accounts) - 4} more"
            if len(card.owned_accounts) > 4
            else ""
        )
        right.add_row(
            "",
            Text.from_markup(f"[{_STEEL}]{', '.join(preview)}{tail}[/]"),
        )

    body = Columns([left, right], equal=False, expand=False, padding=(0, 4))

    icon = f"[bold {_CRIMSON}]💀[/]" if has_da else f"[bold {_AMBER}]⚡[/]"
    title = Text.assemble(
        Text.from_markup(f"{icon} "),
        ("Loot Summary", "bold"),
        ("  ·  ", _MUTED),
        (card.domain.upper(), f"bold {_STEEL}"),
    )

    _emit(
        Panel(
            body,
            title=title,
            border_style=border,
            box=ROUNDED,
            padding=(0, 1),
        )
    )
    _emit_blank()


# ---------------------------------------------------------------------------
# Phase chapter divider
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PhaseChapter:
    """Major phase transition divider for a multi-phase scan run.

    Rendered as a full-width "act break" between major scan phases — distinct
    from print_phase_header / print_section / print_panel, which are
    sub-section headings. Use sparingly: 5-7 per run.

    Attributes:
        number: 1-indexed position of the active phase.
        title: Display title of the active phase (e.g. "Kerberos Attacks").
        subtitle: Optional one-line description of what this phase does.
        all_phases: Ordered tuple of every phase name in this run. When
            provided, the strip renders real names for completed/active/pending
            phases. When empty, the renderer falls back to placeholder names
            and uses ``number`` as the implicit total.
    """

    number: int
    title: str
    subtitle: str = ""
    all_phases: tuple[str, ...] = ()

    @property
    def total(self) -> int:
        """Total number of phases in this run.

        Derived from ``all_phases`` when present, otherwise falls back to
        ``number`` so legacy callers without a phase list still render a
        coherent badge.
        """
        return len(self.all_phases) or self.number


def print_phase_chapter(chapter: PhaseChapter) -> None:
    """Render a major phase transition divider.

    Visual structure (top rule, badge + progress glyph, big title, italic
    subtitle, completed/active/pending strip, bottom rule). Designed to be
    immediately recognisable as an act-break, not just another section.
    """
    from rich.console import Group as RichGroup
    from rich.rule import Rule

    n = max(1, int(chapter.number))
    total = max(n, int(chapter.total))

    # --- progress glyph: ▰ for done/active, ▱ for pending ---
    glyph = Text()
    for i in range(1, total + 1):
        if i < n:
            glyph.append("▰", style=_STEEL)
        elif i == n:
            glyph.append("▰", style=f"bold {_AMBER}")
        else:
            glyph.append("▱", style=_MUTED)

    # --- top badge line: "◆ PHASE 3 / 7   ▰▰▰▱▱▱▱" ---
    badge = Text()
    badge.append("  ")
    badge.append("◆ ", style=f"bold {_AMBER}")
    badge.append(f"PHASE {n} / {total}", style=f"bold {_AMBER}")
    badge.append("   ")
    badge.append_text(glyph)

    # --- title line: big, uppercase, amber bold ---
    title_text = Text()
    title_text.append("  ")
    title_text.append(chapter.title.upper(), style=f"bold {_AMBER}")

    # --- subtitle line: muted italic ---
    subtitle_text = Text()
    if chapter.subtitle:
        subtitle_text.append("  ")
        subtitle_text.append(chapter.subtitle, style=f"italic {_MUTED}")

    # --- phase strip: real names from all_phases, with state per index ---
    # When all_phases is provided, render its real names directly so the
    # operator sees what's coming. When it's empty (legacy callers), fall
    # back to placeholder names so the strip still renders consistently.
    strip = Text()
    strip.append("  ")
    if chapter.all_phases:
        labels = list(chapter.all_phases)
    else:
        labels = []
        for i in range(1, total + 1):
            if i == n:
                labels.append(chapter.title)
            else:
                labels.append(f"Phase {i}")

    sep = "   "
    for idx, label in enumerate(labels):
        position = idx + 1  # 1-indexed
        if position < n:
            strip.append("✓ ", style=_STEEL)
            strip.append(label, style=_STEEL)
        elif position == n:
            strip.append("▶ ", style=f"bold {_AMBER}")
            strip.append(label, style=f"bold {_AMBER}")
        else:
            strip.append("· ", style=_MUTED)
            strip.append(label, style=_MUTED)
        if idx < len(labels) - 1:
            strip.append(sep)

    rule_top = Rule(style=f"bold {_AMBER}")
    rule_bottom = Rule(style=f"bold {_AMBER}")

    spacer = Text("")

    body_parts: list[Any] = [
        rule_top,
        spacer,
        badge,
        title_text,
    ]
    if chapter.subtitle:
        body_parts.append(subtitle_text)
    body_parts.append(spacer)
    body_parts.append(strip)
    body_parts.append(spacer)
    body_parts.append(rule_bottom)

    _emit_blank()
    _emit(RichGroup(*body_parts))
    _emit_blank()


# ---------------------------------------------------------------------------
# Discovery card — high-impact reveal moments
# ---------------------------------------------------------------------------


_DISCOVERY_SEVERITY_STYLE: dict[str, str] = {
    "critical": _CRIMSON,
    "high": _AMBER,
    "medium": _STEEL,
    "info": _MUTED,
}

_DISCOVERY_DEFAULT_ICON: dict[str, str] = {
    "critical": "▲",
    "high": "◆",
    "medium": "●",
    "info": "·",
}


@dataclass(frozen=True)
class DiscoveryCard:
    """A high-impact reveal moment in the scan.

    Use for screenshot-worthy events only: DA owned, ADCS ESC vulnerability
    confirmed exploitable, attack path to DA confirmed, first credential
    captured, hash cracked.

    Attributes:
        severity: One of "critical" | "high" | "medium" | "info". Drives the
            border color and default icon.
        headline: Short, in-your-face headline. Will be rendered uppercase and
            bold (e.g. "DOMAIN ADMIN OWNED").
        target: The entity discovered. May contain sensitive data — callers
            should pre-mark via mark_sensitive when appropriate.
        evidence: 1-5 short lines of supporting evidence. Rendered as a
            bulleted list. Lines may contain marked sensitive data.
        next_action: One-line description of what this enables / suggested
            next step. Rendered with a leading "→" and severity color.
        icon: Optional unicode glyph. When empty, picked from severity.
    """

    severity: str
    headline: str
    target: str = ""
    evidence: tuple[str, ...] = ()
    next_action: str = ""
    icon: str = ""


def print_discovery_card(card: DiscoveryCard) -> None:
    """Render a high-impact discovery reveal moment.

    Use sparingly — this is for screenshot-worthy moments only:
    DA owned, critical attack path confirmed, ADCS ESC vulnerability
    confirmed exploitable, first credential captured, hash cracked.
    """
    from rich.console import Group as RichGroup

    severity = card.severity if card.severity in _DISCOVERY_SEVERITY_STYLE else "info"
    color = _DISCOVERY_SEVERITY_STYLE[severity]
    icon = card.icon or _DISCOVERY_DEFAULT_ICON[severity]

    parts: list[Any] = []

    # --- severity badge ---
    badge = Text()
    badge.append(f"{icon}  ", style=f"bold {color}")
    badge.append(severity.upper(), style=f"bold {color}")
    parts.append(badge)
    parts.append(Text(""))

    # --- headline (big, uppercase, severity color) ---
    headline = Text()
    headline.append(card.headline.upper(), style=f"bold {color}")
    parts.append(headline)

    # --- target (regular weight, slightly muted) ---
    if card.target:
        target_line = Text()
        target_line.append(card.target, style=_STEEL)
        parts.append(target_line)

    # --- evidence (bulleted, muted) ---
    if card.evidence:
        parts.append(Text(""))
        for line in card.evidence[:5]:
            ev = Text()
            ev.append("• ", style=color)
            ev.append(line, style=_MUTED)
            parts.append(ev)

    # --- next action (italic, severity color, prefixed with arrow) ---
    if card.next_action:
        parts.append(Text(""))
        action = Text()
        action.append("→ ", style=f"bold {color}")
        action.append(card.next_action, style=f"italic {color}")
        parts.append(action)

    body = RichGroup(*parts)

    _emit_blank()
    _emit(
        Panel(
            body,
            border_style=f"bold {color}",
            box=ROUNDED,
            padding=(1, 3),
        )
    )
    _emit_blank()


# ---------------------------------------------------------------------------
# Phase ribbon — single-line progress marker for a multi-step session
# ---------------------------------------------------------------------------


_PHASE_RIBBON_STATUS_GLYPH: dict[str, str] = {
    "pending": "·",
    "live": "▸",
    "done": "·",
    "yielded": "◆",
    "skipped": "·",
    "failed": "✗",
}
_PHASE_RIBBON_STATUS_STYLE: dict[str, str] = {
    "pending": _MUTED,
    "live": _PHASE_ACTIVE,
    "done": _MUTED,
    "yielded": _AMBER,
    "skipped": _MUTED,
    "failed": _CRIMSON,
}


def print_phase_ribbon(
    *,
    index: int,
    total: int,
    name: str,
    status: str,
    detail: str = "",
) -> None:
    """Print a single-line ribbon marker for one phase of a session.

    Used for the WinRM session flow (probe → autologon → transcripts → dpapi
    → runascs) and any equivalent multi-step operation. Designed to be the
    *only* visible output for routine phase transitions — reveal cards stay
    reserved for screenshot-worthy yields.

    Status vocabulary:
      ``pending``  — not yet executed
      ``live``     — currently running
      ``done``     — completed without yield (informational)
      ``yielded``  — completed with operationally actionable output
      ``skipped``  — intentionally not run (gating policy, missing prereq)
      ``failed``   — execution error — show the reason in ``detail``
    """
    status = status if status in _PHASE_RIBBON_STATUS_STYLE else "pending"
    glyph = _PHASE_RIBBON_STATUS_GLYPH[status]
    color = _PHASE_RIBBON_STATUS_STYLE[status]

    line = Text()
    line.append(f"[{index}/{total}]", style=_MUTED)
    line.append("  ", style=_MUTED)
    name_style = f"bold {_STEEL}" if status in {"live", "yielded"} else _STEEL
    line.append(name, style=name_style)
    line.append("  ", style=_MUTED)
    line.append(f"{glyph} ", style=f"bold {color}")
    status_label_style = f"bold {color}" if status == "yielded" else color
    line.append(status, style=status_label_style)
    if detail:
        line.append("  ·  ", style=_MUTED)
        detail_style = color if status in {"yielded", "failed"} else _MUTED
        line.append(detail, style=detail_style)
    _emit(line)


def print_phase_recap(
    *,
    title: str,
    phases_total: int,
    phases_yielded: int | None = None,
    extra_metrics: Sequence[tuple[str, str]] = (),
) -> None:
    """Print a single-line closing recap for a multi-phase session.

    Mirrors the density of ``print_phase_ribbon``. The title is bold steel,
    metrics are pairs of ``(value, label)`` rendered as ``value label``
    separated by middle dots. ``phases_yielded`` is rendered when supplied
    (amber-emphasized when > 0); when None, the segment is omitted — useful
    when the orchestrator does not have a per-phase yield signal yet.
    """
    line = Text()
    line.append(title, style=f"bold {_STEEL}")
    line.append("  ·  ", style=_MUTED)
    line.append(f"{phases_total}", style=f"bold {_STEEL}")
    line.append(" phases", style=_MUTED)
    if phases_yielded is not None:
        line.append("  ·  ", style=_MUTED)
        yielded_color = _AMBER if phases_yielded > 0 else _MUTED
        line.append(f"{phases_yielded}", style=f"bold {yielded_color}")
        line.append(" yielded", style=_MUTED)
    for value, label in extra_metrics:
        line.append("  ·  ", style=_MUTED)
        line.append(str(value), style=f"bold {_STEEL}")
        line.append(f" {label}", style=_MUTED)
    _emit_blank()
    _emit(line)
    _emit_blank()


@dataclass(frozen=True)
class DpapiHaulEntry:
    """One Credential Manager entry, classified for the haul card.

    The card groups entries by ``kind`` and renders a compact table.
    All four string fields are operator-readable: pre-mark sensitive ones
    with ``mark_sensitive`` so downstream log/PDF redaction can find them.
    """

    kind: str
    target: str
    identity: str
    password: str


# Display order + label for credential kinds. Anything unrecognized falls
# under "generic". Order is deliberate: lateral-movement-shaped entries first
# (RDP, SSO, db), then storage/web/cloud, then generic.
_DPAPI_KIND_ORDER: tuple[str, ...] = (
    "rdp",
    "sso",
    "db",
    "git",
    "web",
    "cloud",
    "generic",
)
# Windows Credential Vault target strings carry verbose prefixes
# (``LegacyGeneric:target=``, ``Domain:target=``, ``WindowsLive:target=``,
# ``MicrosoftAccount:target=``) that crowd the table without adding
# information. Stripping them keeps the meaningful identifier visible.
_DPAPI_TARGET_PREFIXES: tuple[str, ...] = (
    "LegacyGeneric:target=",
    "Domain:target=",
    "WindowsLive:target=",
    "MicrosoftAccount:target=",
    "MicrosoftOffice:target=",
    "InternetExplorer:target=",
)


def _strip_vault_prefix(target: str) -> str:
    """Strip the Credential Vault category prefix from a target string."""
    cleaned = (target or "").strip()
    for prefix in _DPAPI_TARGET_PREFIXES:
        if cleaned.startswith(prefix):
            return cleaned[len(prefix) :] or cleaned
    return cleaned


_DPAPI_KIND_LABEL: dict[str, str] = {
    "rdp": "rdp",
    "sso": "sso",
    "db": "db",
    "git": "git",
    "web": "web",
    "cloud": "cloud",
    "generic": "other",
}


def _build_dpapi_haul_panel(
    *,
    auth_user: str,
    auth_domain: str,
    host: str,
    entries: Sequence[DpapiHaulEntry],
    masterkeys_decrypted: int,
    masterkeys_seen: int,
    max_rows: int,
) -> Panel:
    """Construct the DPAPI haul reveal Panel.

    Single source of truth for the haul visual: used by ``print_dpapi_haul_card``
    for live terminal output and by ``render_dpapi_haul_card_svg`` for PDF
    report figures. Any layout change should land here.
    """
    from rich.console import Group as RichGroup

    severity = "high"
    color = _DISCOVERY_SEVERITY_STYLE[severity]
    icon = _DISCOVERY_DEFAULT_ICON[severity]

    parts: list[Any] = []

    # --- severity badge ---
    badge = Text()
    badge.append(f"{icon}  ", style=f"bold {color}")
    badge.append(severity.upper(), style=f"bold {color}")
    parts.append(badge)
    parts.append(Text(""))

    # --- headline ---
    headline = Text()
    headline.append("DPAPI VAULT UNLOCKED", style=f"bold {color}")
    parts.append(headline)

    # --- target line: who · where ---
    target_line = Text()
    target_line.append(f"{auth_user}@{auth_domain.upper()}", style=_STEEL)
    target_line.append("  ·  ", style=_MUTED)
    target_line.append(host, style=_STEEL)
    parts.append(target_line)

    # --- impact line (Hormozi-voice, italic muted) ---
    impact = Text()
    impact.append(
        "What only this user could read — pulled without admin on the box.",
        style=f"italic {_MUTED}",
    )
    parts.append(Text(""))
    parts.append(impact)

    # --- counts band: total + per-kind breakdown ---
    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry.kind] = counts.get(entry.kind, 0) + 1
    total = len(entries)

    counts_line = Text()
    counts_line.append(f"{total}", style=f"bold {color}")
    counts_line.append(f" credential{'s' if total != 1 else ''}", style=_STEEL)
    breakdown = [(kind, counts[kind]) for kind in _DPAPI_KIND_ORDER if counts.get(kind)]
    for kind, count in breakdown:
        counts_line.append("  ·  ", style=_MUTED)
        counts_line.append(f"{count} ", style=f"bold {_STEEL}")
        counts_line.append(_DPAPI_KIND_LABEL.get(kind, kind), style=_MUTED)
    parts.append(Text(""))
    parts.append(counts_line)

    # --- credentials table (grouped by kind, capped at max_rows) ---
    sorted_entries = sorted(
        entries,
        key=lambda e: (
            _DPAPI_KIND_ORDER.index(e.kind)
            if e.kind in _DPAPI_KIND_ORDER
            else len(_DPAPI_KIND_ORDER),
            e.target.lower(),
        ),
    )
    visible = sorted_entries[:max_rows]
    overflow = max(0, total - len(visible))

    table = Table(
        box=SIMPLE,
        show_header=True,
        show_edge=False,
        pad_edge=False,
        padding=(0, 2),
        header_style=f"bold {_STEEL}",
    )
    table.add_column("type", style=_MUTED, no_wrap=True)
    table.add_column("target", style=_STEEL, overflow="fold")
    table.add_column("identity", style="bold", overflow="fold")
    table.add_column("password", style=color, overflow="fold")
    for entry in visible:
        table.add_row(
            _DPAPI_KIND_LABEL.get(entry.kind, entry.kind),
            _strip_vault_prefix(entry.target) or "—",
            entry.identity or "—",
            entry.password or "—",
        )

    parts.append(Text(""))
    parts.append(table)

    if overflow:
        overflow_line = Text()
        overflow_line.append(f"+{overflow} more", style=f"bold {_STEEL}")
        overflow_line.append(
            "  in workspace dump · scroll log for full list", style=_MUTED
        )
        parts.append(overflow_line)

    # --- stats footer (dim, supporting facts) ---
    stats = Text()
    stats.append(
        f"{masterkeys_decrypted}/{masterkeys_seen} masterkeys decrypted",
        style=_MUTED,
    )
    stats.append("  ·  ", style=_MUTED)
    stats.append("WinRM/PSRP only", style=_MUTED)
    stats.append("  ·  ", style=_MUTED)
    stats.append("no SMB admin required", style=_MUTED)
    parts.append(Text(""))
    parts.append(stats)

    # --- next action ---
    action = Text()
    action.append("→ ", style=f"bold {color}")
    action.append(
        "Spray every recovered credential across all in-scope targets. Volume negates luck.",
        style=f"italic {color}",
    )
    parts.append(Text(""))
    parts.append(action)

    body = RichGroup(*parts)

    return Panel(
        body,
        border_style=f"bold {color}",
        box=ROUNDED,
        padding=(1, 3),
    )


def print_dpapi_haul_card(
    *,
    auth_user: str,
    auth_domain: str,
    host: str,
    entries: Sequence[DpapiHaulEntry],
    masterkeys_decrypted: int,
    masterkeys_seen: int,
    max_rows: int = 12,
) -> None:
    """Render the premium DPAPI vault-unlocked reveal moment to the terminal.

    Reuses the discovery-card visual grammar (severity badge, uppercase
    headline, target line, italic next action) and extends it with a compact
    typed table of recovered credentials. Reserved for the success state with
    at least one credential — empty-haul and no-masterkeys cases use lighter
    renderers (panels or warnings) so this remains screenshot-worthy.
    """
    panel = _build_dpapi_haul_panel(
        auth_user=auth_user,
        auth_domain=auth_domain,
        host=host,
        entries=entries,
        masterkeys_decrypted=masterkeys_decrypted,
        masterkeys_seen=masterkeys_seen,
        max_rows=max_rows,
    )
    _emit_blank()
    _emit(panel)
    _emit_blank()


def render_dpapi_haul_card_svg(
    *,
    auth_user: str,
    auth_domain: str,
    host: str,
    entries: Sequence[DpapiHaulEntry],
    masterkeys_decrypted: int,
    masterkeys_seen: int,
    max_rows: int = 12,
    width: int = 120,
    title: str = "ADscan · DPAPI Vault Unlocked",
) -> str:
    """Return the haul card rendered as a self-contained SVG document.

    Same panel as the live terminal render — the operator's screenshot moment
    becomes the client's deliverable figure. The SVG is portable, vector, and
    embeds the monospace font, so it scales cleanly in print.

    Default width of 120 matches a standard pentester terminal and is wide
    enough to keep the headline + counts band on a single line.
    """
    import io

    from rich.console import Console as _Console

    panel = _build_dpapi_haul_panel(
        auth_user=auth_user,
        auth_domain=auth_domain,
        host=host,
        entries=entries,
        masterkeys_decrypted=masterkeys_decrypted,
        masterkeys_seen=masterkeys_seen,
        max_rows=max_rows,
    )
    console = _Console(
        record=True,
        width=width,
        file=io.StringIO(),
        force_terminal=True,
        color_system="truecolor",
    )
    console.print(panel)
    return console.export_svg(title=title)


def print_dpapi_no_vault_card(
    *,
    auth_user: str,
    auth_domain: str,
    host: str,
    masterkeys_decrypted: int,
    masterkeys_seen: int,
) -> None:
    """Render the "access proven, no vault here" intel reframe.

    Used when the masterkeys decrypt path works end-to-end but the user has
    no Credential Manager entries on this host. Treated as intel rather than
    failure — the operator just learned that this isn't where this user
    stores secrets, which redirects the next move instead of stalling.
    """
    from rich.console import Group as RichGroup

    severity = "info"
    color = _DISCOVERY_SEVERITY_STYLE[severity]
    icon = _DISCOVERY_DEFAULT_ICON[severity]

    parts: list[Any] = []

    badge = Text()
    badge.append(f"{icon}  ", style=f"bold {color}")
    badge.append("INTEL", style=f"bold {color}")
    parts.append(badge)
    parts.append(Text(""))

    headline = Text()
    headline.append("ACCESS PROVEN · NO VAULT HERE", style=f"bold {_STEEL}")
    parts.append(headline)

    target_line = Text()
    target_line.append(f"{auth_user}@{auth_domain.upper()}", style=_STEEL)
    target_line.append("  ·  ", style=_MUTED)
    target_line.append(host, style=_STEEL)
    parts.append(target_line)

    parts.append(Text(""))
    impact = Text()
    impact.append(
        "Decrypt path works. This isn't where they keep secrets.",
        style=f"italic {_MUTED}",
    )
    parts.append(impact)

    parts.append(Text(""))
    stats = Text()
    stats.append(
        f"{masterkeys_decrypted}/{masterkeys_seen} masterkeys decrypted",
        style=_MUTED,
    )
    stats.append("  ·  ", style=_MUTED)
    stats.append("0 Credential Manager entries", style=_MUTED)
    parts.append(stats)

    parts.append(Text(""))
    action = Text()
    action.append("→ ", style=f"bold {_STEEL}")
    action.append(
        "Re-run en su daily driver — workstation principal, post-RDP host, "
        "jump box. Storage follows usage.",
        style=f"italic {_STEEL}",
    )
    parts.append(action)

    body = RichGroup(*parts)

    _emit_blank()
    _emit(
        Panel(
            body,
            border_style=color,
            box=ROUNDED,
            padding=(1, 3),
        )
    )
    _emit_blank()


def print_dpapi_no_masterkeys_notice(
    *,
    auth_user: str,
    host: str,
) -> None:
    """Render a tight notice when the user has never invoked DPAPI here.

    Deliberately lighter than the panel cards — no border, no badge — because
    this is a routing signal, not a discovery. Two lines: state + redirect.
    """
    line1 = Text()
    line1.append("·  ", style=_MUTED)
    line1.append(auth_user, style=_STEEL)
    line1.append(" has never invoked DPAPI on ", style=_MUTED)
    line1.append(host, style=_STEEL)
    line1.append(".", style=_MUTED)

    line2 = Text()
    line2.append("→  ", style=f"bold {_STEEL}")
    line2.append(
        "Hit a host where they actually work — workstation principal, "
        "post-RDP target, jump host.",
        style=f"italic {_STEEL}",
    )

    _emit(line1)
    _emit(line2)


def print_da_owned_card(
    account: str,
    domain: str,
    evidence: Sequence[str] = (),
    method: str = "",
) -> None:
    """Render the canonical DOMAIN ADMIN OWNED discovery card.

    Convenience wrapper that fills in severity=critical, the standard
    headline, a "{account}@{DOMAIN}" target line (with sensitive masking),
    and a sensible next_action. Caller-supplied evidence is rendered as-is —
    callers are expected to pre-mark sensitive values (hashes, etc.) where
    appropriate.

    Args:
        account: Compromised account name (e.g. "krbtgt", "Administrator").
        domain: Domain the account belongs to.
        evidence: Optional supporting lines (hash preview, key types, ...).
        method: Optional short method label (e.g. "DCSync via drsuapi") used
            in the next_action line.
    """
    # Lazy import to avoid pulling adscan_internal symbols into adscan_core.
    from adscan_core.output._state import mark_sensitive

    masked_account = mark_sensitive(account, "user")
    masked_domain = mark_sensitive(domain.upper(), "domain")
    target = f"{masked_account}@{masked_domain}"

    if method:
        next_action = (
            f"Full domain compromise via {method}. Golden ticket forging now possible."
        )
    else:
        next_action = "Full domain compromise. Golden ticket forging now possible."

    card = DiscoveryCard(
        severity="critical",
        headline="DOMAIN ADMIN OWNED",
        target=target,
        evidence=tuple(evidence),
        next_action=next_action,
    )
    print_discovery_card(card)
