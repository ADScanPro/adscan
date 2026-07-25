"""Editorial welcome screen for `adscan` with no arguments.

Renders the brand header, value proposition, four discovery paths
(demo / assess / automate / cheat sheet), the PRO Client Deliverable
Kit disclosure strip, and the latest workspace posture (when a prior
scan exists in ``~/.adscan/workspaces/``).

Design constraints:
- Total height stays around 24-30 rows so it does not scroll on
  standard 80x24 terminals.
- Reuses the gradient ASCII from :mod:`adscan_core.branding` so the
  CLI splash and the welcome screen never drift apart.
- Pure presentation: no I/O beyond the optional posture lookup which
  is delegated to :func:`load_latest_posture` (best-effort, defensive).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Iterable

from rich.columns import Columns
from rich.console import Console, Group
from rich.padding import Padding
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

from adscan_core import telemetry
from adscan_core.branding import (
    ADSCAN_LINKS,
    ADSCAN_TAGLINE,
    build_gradient_ascii,
)
from adscan_core.posture_score import PostureScore
from adscan_core.rich_output import _get_console
from adscan_core.theme import ADSCAN_PRIMARY, ADSCAN_PRIMARY_DIM
from adscan_core.rich_output import print_exception


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


WELCOME_HEADLINE = "Find every path to Domain Admin. Close every one before they do."

_VALUE_LINES = (
    "Continuous Active Directory exposure management.",
    "Champion-grade tradecraft. CISO-ready reporting. Auditor-grade evidence.",
    "One toolkit, from assessment to remediation.",
)


@dataclass(frozen=True)
class _PathCard:
    eyebrow: str
    title: str
    command: str
    outcome: str


_PATH_CARDS: tuple[_PathCard, ...] = (
    _PathCard(
        eyebrow="1 · DEMO",
        title="Try the 60-second tour",
        command="$ adscan demo",
        outcome="See what a finished ADscan run looks like.",
    ),
    _PathCard(
        eyebrow="2 · ASSESS",
        title="Run a real scan",
        command="$ adscan start",
        outcome="Discover paths to Domain Admin in your environment.",
    ),
    # Card 3 was previously "WORKBENCH / adscan tui" — the Textual workbench
    # is still under active development and is intentionally hidden from
    # every user-facing surface until it is production-ready. The slot is
    # filled with `adscan ci` (hands-off pipeline) instead, which pairs
    # naturally with the interactive `adscan start` in card 2.
    _PathCard(
        eyebrow="3 · AUTOMATE",
        title="Run a hands-off scan",
        command="$ adscan ci",
        outcome="End-to-end pipeline. From CI, cron, or batch.",
    ),
    # Card 4 promises ONLY what LITE actually delivers. The four PRO PDFs
    # (Executive · Playbook · Checklist · Coverage Matrix) live behind the
    # `adscan deliver` command and are disclosed in the separate kit strip
    # below the grid — never advertised here as if they were free.
    _PathCard(
        eyebrow="4 · CHEAT SHEET",
        title="Pentester operator reference",
        command="$ adscan cheatsheet",
        outcome="Operational AD recipes. Yours to keep, free.",
    ),
)


# Names that compose the PRO Client Deliverable Kit, in the order they
# are shown to the operator. Mirrors :data:`adscan_core.welcome_host._PRO_KIT_ITEMS`
# so the host launcher and the container runtime render the same kit
# composition without a cross-package import.
_PRO_KIT_ITEMS: tuple[str, ...] = (
    "Security Assessment Report",
    "Hardening Playbook",
    "MITRE Checklist",
    "Coverage Matrix",
)


# Amber accent used exclusively for the PRO badge — matches the LITE
# edition badge in the header so the operator builds a stable mental
# map ("amber == PRO surface").
_PRO_BADGE = "#d29922"


def print_welcome(
    latest_posture: PostureScore | None = None,
    *,
    workspace_name: str | None = None,
    last_scan_age_days: int | None = None,
    version_tag: str | None = None,
    license_mode: str = "LITE",
    console: Console | None = None,
) -> None:
    """Render the editorial welcome screen.

    Args:
        latest_posture: Optional posture score for the most recent workspace.
            When provided, a single-line posture badge is rendered below the
            discovery grid.
        workspace_name: Name of the most recent workspace, surfaced alongside
            the posture line.
        last_scan_age_days: How long ago (in days) the latest scan ran.
        version_tag: Optional runtime version string (e.g. "v0.42.0"). When
            ``None`` the version line is omitted.
        license_mode: ``"PRO"`` or ``"LITE"``; controls the edition badge.
        console: Rich console to print to. Defaults to the shared ADscan
            console so theming stays consistent.
    """
    out = console or _get_console()

    # 1. Brand header (gradient ASCII + version + edition badge).
    out.print(build_gradient_ascii(out.width))

    badge_style = (
        f"bold {ADSCAN_PRIMARY}"
        if str(license_mode).upper() == "PRO"
        else "bold #d29922"
    )
    header_bits: list[str] = [f"  [bold {ADSCAN_PRIMARY}]ADscan[/bold {ADSCAN_PRIMARY}]"]
    if version_tag:
        header_bits.append(f"[dim]{version_tag}[/dim]")
    header_bits.append(
        f"[{badge_style}]{str(license_mode).upper()}[/{badge_style}]"
    )
    out.print("  ".join(header_bits))

    # 2. Headline + tagline (Fraunces-equivalent gravitas in a terminal:
    #    bold brand cyan headline, italic dim tagline).
    out.print(
        f"  [bold {ADSCAN_PRIMARY}]{WELCOME_HEADLINE}[/bold {ADSCAN_PRIMARY}]"
    )
    out.print(
        f"  [italic {ADSCAN_PRIMARY_DIM}]{ADSCAN_TAGLINE}[/italic {ADSCAN_PRIMARY_DIM}]"
    )

    # 3. Three-line value proposition.
    for line in _VALUE_LINES:
        out.print(f"  [dim]{line}[/dim]")

    out.print(Rule(style=f"dim {ADSCAN_PRIMARY}"))

    # 4. Four discovery paths in a 2x2 grid (Columns auto-wraps to 1xN on
    #    narrow terminals).
    out.print(Padding(_render_path_grid(), (0, 2)))

    # 4b. PRO Client Deliverable Kit disclosure strip — names the four
    #     PDFs behind ``adscan deliver`` so the LITE operator knows what
    #     unlocks with the upgrade, and the PRO operator gets a one-line
    #     reminder. Honest disclosure, not advertising.
    out.print(Padding(_render_pro_kit_strip(license_mode=license_mode), (0, 2)))

    # 5. Posture badge (only when the host has prior workspace data).
    if latest_posture is not None:
        out.print(_render_posture_line(
            latest_posture,
            workspace_name=workspace_name,
            last_scan_age_days=last_scan_age_days,
        ))

    # 6. Bottom links strip.
    out.print(Rule(style=f"dim {ADSCAN_PRIMARY}"))
    out.print(_render_links_strip(version_tag=version_tag))
    out.print()


# ---------------------------------------------------------------------------
# Posture loader (best-effort, defensive)
# ---------------------------------------------------------------------------


def load_latest_posture() -> tuple[PostureScore | None, str | None, int | None]:
    """Walk ``~/.adscan/workspaces/`` and return the most recent posture.

    Returns:
        A 3-tuple ``(posture, workspace_name, age_days)``. Any element may be
        ``None`` if the lookup fails. Never raises — telemetry captures
        unexpected errors so the welcome screen always renders.
    """
    try:
        # Imported lazily so the welcome module remains importable from
        # contexts where adscan_internal.tui is not on the path (e.g. unit
        # tests that exercise rendering only).
        from adscan_internal.tui.data import (  # type: ignore[import-not-found]
            list_workspaces,
        )
    except Exception as exc:  # pragma: no cover - defensive
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None, None, None

    try:
        summaries = list_workspaces()
    except Exception as exc:  # pragma: no cover - defensive
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None, None, None

    # Pick the workspace whose technical_report.json was last modified most
    # recently. Fall back to the first listed workspace if no report file
    # exists anywhere.
    best_mtime: float = -1.0
    best_summary = None
    for summary in summaries:
        report = summary.path / "technical_report.json"
        try:
            mtime = report.stat().st_mtime if report.exists() else -1.0
        except OSError:
            mtime = -1.0
        if mtime > best_mtime:
            best_mtime = mtime
            best_summary = summary

    if best_summary is None or best_summary.posture is None:
        return None, None, None

    age_days: int | None = None
    if best_mtime > 0:
        age_seconds = max(0.0, time.time() - best_mtime)
        age_days = int(age_seconds // 86400)

    return best_summary.posture, best_summary.name, age_days


# ---------------------------------------------------------------------------
# Internal renderers
# ---------------------------------------------------------------------------


def _render_path_grid() -> Columns:
    panels: list[Panel] = [_render_path_card(card) for card in _PATH_CARDS]
    # equal=True + expand=True gives a clean 2x2 layout on >=80 cols and
    # gracefully wraps to a single column on narrow terminals.
    return Columns(panels, equal=True, expand=True, padding=(0, 1))


def _render_path_card(card: _PathCard) -> Panel:
    body = Text()
    body.append(card.eyebrow, style=f"bold {ADSCAN_PRIMARY}")
    body.append("\n")
    body.append(card.title, style="bold white")
    body.append("\n")
    body.append(card.command, style=f"{ADSCAN_PRIMARY} on grey11")
    body.append("\n")
    body.append(card.outcome, style="dim")
    return Panel(
        body,
        border_style=f"dim {ADSCAN_PRIMARY}",
        padding=(0, 1),
    )


def _render_pro_kit_strip(*, license_mode: str) -> Group:
    """Render the Client Deliverable Kit disclosure strip.

    Sits directly below the discovery grid. Names the four PDFs that
    ship behind the ``adscan deliver`` (PRO) verb so the LITE operator
    knows what unlocks with the upgrade — and the PRO operator gets a
    one-line reminder that the kit is ready.

    Visually subordinate to the LITE cards above: a labelled rule plus
    a single dim line of items, no panel chrome. The amber ``PRO``
    badge is the only saturated accent so it reads as "different
    surface" even in 16-colour terminals.

    Adapts copy by tier:
      * ``LITE``  — ``Client Deliverable Kit`` (disclosure, no pressure)
      * ``PRO``   — ``Client Deliverable Kit ready`` (operator reminder)
    """
    is_pro = str(license_mode).upper() == "PRO"
    status_phrase = (
        "Client Deliverable Kit ready" if is_pro else "Client Deliverable Kit"
    )

    title = Text()
    title.append(" PRO ", style=f"bold {_PRO_BADGE}")
    title.append(f" · {status_phrase}  ", style="dim")
    title.append(" $ adscan deliver ", style=f"{ADSCAN_PRIMARY} on grey11")
    title.append(" ", style="dim")

    rule = Rule(title=title, style=f"dim {_PRO_BADGE}", align="left")

    items = Text()
    for idx, name in enumerate(_PRO_KIT_ITEMS):
        if idx > 0:
            items.append("  ·  ", style=f"dim {_PRO_BADGE}")
        items.append(name, style="dim")

    return Group(Text(""), rule, items)


def _render_posture_line(
    posture: PostureScore,
    *,
    workspace_name: str | None,
    last_scan_age_days: int | None,
) -> Text:
    label_upper = str(posture.label or "Unknown").upper()
    pieces: list[str] = []
    if workspace_name:
        pieces.append(f"workspace [bold]{workspace_name}[/bold]")
    pieces.append(f"posture [bold {ADSCAN_PRIMARY}]{posture.score}/100[/]")
    pieces.append(f"[bold]{label_upper}[/bold]")
    if last_scan_age_days is not None:
        if last_scan_age_days <= 0:
            pieces.append("scanned today")
        elif last_scan_age_days == 1:
            pieces.append("scanned 1 day ago")
        else:
            pieces.append(f"scanned {last_scan_age_days} days ago")
    pieces.append(f"refresh with [bold {ADSCAN_PRIMARY}]adscan ci[/]")

    line = Text.from_markup("  Latest · " + " · ".join(pieces), style="dim")
    return line


def _render_links_strip(*, version_tag: str | None) -> Text:
    parts: list[str] = []
    parts.append(f"[link={ADSCAN_LINKS['docs']}]Docs[/link]")
    parts.append(f"[link={ADSCAN_LINKS['discord']}]Community[/link]")
    parts.append(f"[link={ADSCAN_LINKS['github']}]Source[/link]")
    if version_tag:
        parts.append(version_tag)
    return Text.from_markup("  [dim]" + "  ·  ".join(parts) + "[/dim]")


__all__ = (
    "WELCOME_HEADLINE",
    "load_latest_posture",
    "print_welcome",
)


# Backwards-compat: expose a typed iterable for callers that want to render
# the discovery paths in another surface (e.g. the workbench empty-state).
def discovery_cards() -> Iterable[_PathCard]:
    """Return the discovery card definitions used by the welcome screen."""
    return _PATH_CARDS
