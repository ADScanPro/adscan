"""Host-side editorial welcome screen.

Mirrors :mod:`adscan_internal.cli.welcome` but lives in ``adscan_core`` so the
PyPI launcher can render the brand without spinning up the Docker container.

Keep this module dependency-light (stdlib + Rich + ``adscan_core``); never
import anything from ``adscan_internal`` here. The container-side
``adscan_internal.cli.welcome`` re-uses the same constants for parity.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Iterable

from rich.columns import Columns
from rich.console import Console, Group
from rich.padding import Padding
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

from adscan_core import telemetry, tier
from adscan_core.branding import (
    ADSCAN_LINKS,
    ADSCAN_TAGLINE,
    build_gradient_ascii,
)
from adscan_core.posture_score import (
    PostureInputs,
    PostureScore,
    compute_posture_score,
)
from adscan_core.theme import ADSCAN_PRIMARY, ADSCAN_PRIMARY_DIM
from adscan_core.rich_output import print_exception


WELCOME_HEADLINE = "Find every path to Domain Admin. Close every one before they do."

_VALUE_LINES = (
    "Continuous Active Directory exposure management.",
    "Champion-grade tradecraft. CISO-ready reporting. Auditor-grade evidence.",
    "One toolkit, from assessment to remediation.",
)

_BRAND_CYAN = "bright_cyan"


class _Card:
    __slots__ = ("eyebrow", "title", "command", "outcome")

    def __init__(self, eyebrow: str, title: str, command: str, outcome: str) -> None:
        self.eyebrow = eyebrow
        self.title = title
        self.command = command
        self.outcome = outcome


_PATH_CARDS: tuple[_Card, ...] = (
    _Card("1 · DEMO", "Try the 60-second tour", "$ adscan demo",
          "See what a finished ADscan run looks like."),
    _Card("2 · ASSESS", "Run a real scan", "$ adscan start",
          "Discover paths to Domain Admin in your environment."),
    # Card 3 was previously "WORKBENCH / adscan tui" — the Textual workbench
    # is still under active development and is intentionally hidden from
    # every user-facing surface until it is production-ready. The slot is
    # filled with `adscan ci` (hands-off pipeline) instead, which pairs
    # naturally with the interactive `adscan start` in card 2.
    _Card("3 · AUTOMATE", "Run a hands-off scan", "$ adscan ci",
          "End-to-end pipeline. From CI, cron, or batch."),
    # Card 4 promises ONLY what LITE actually delivers. The four PRO PDFs
    # (Executive · Playbook · Checklist · Coverage Matrix) live behind the
    # `adscan deliver` command and are disclosed in the separate kit strip
    # below the grid — never advertised here as if they were free.
    _Card("4 · CHEAT SHEET", "Pentester operator reference", "$ adscan cheatsheet",
          "Operational AD recipes. Yours to keep, free."),
)


# Names that compose the PRO Client Deliverable Kit, in the order they
# are shown to the operator. Single source of truth so the host and
# container welcome strips stay in lockstep.
_PRO_KIT_ITEMS: tuple[str, ...] = (
    "Security Assessment Report",
    "Hardening Playbook",
    "MITRE Checklist",
    "Coverage Matrix",
)


def print_welcome_host(
    latest_posture: PostureScore | None = None,
    *,
    workspace_name: str | None = None,
    last_scan_age_days: int | None = None,
    version_tag: str | None = None,
    license_mode: str = "LITE",
    console: Console | None = None,
) -> None:
    """Render the welcome screen on the host (no container required).

    Args mirror :func:`adscan_internal.cli.welcome.print_welcome`.
    """
    out = console or Console()

    out.print(build_gradient_ascii(out.width))

    badge_style = (
        f"bold {ADSCAN_PRIMARY}"
        if str(license_mode).upper() == "PRO"
        else "bold #d29922"
    )
    parts: list[str] = [f"  [bold {ADSCAN_PRIMARY}]ADscan[/bold {ADSCAN_PRIMARY}]"]
    if version_tag:
        parts.append(f"[dim]{version_tag}[/dim]")
    parts.append(f"[{badge_style}]{str(license_mode).upper()}[/{badge_style}]")
    out.print("  ".join(parts))

    out.print(
        f"  [bold {ADSCAN_PRIMARY}]{WELCOME_HEADLINE}[/bold {ADSCAN_PRIMARY}]"
    )
    out.print(
        f"  [italic {ADSCAN_PRIMARY_DIM}]{ADSCAN_TAGLINE}[/italic {ADSCAN_PRIMARY_DIM}]"
    )
    for line in _VALUE_LINES:
        out.print(f"  [dim]{line}[/dim]")

    out.print(Rule(style=f"dim {ADSCAN_PRIMARY}"))
    out.print(Padding(_render_grid(), (0, 2)))
    out.print(Padding(_render_pro_kit_strip(license_mode=license_mode), (0, 2)))

    if latest_posture is not None:
        out.print(_render_posture_line(
            latest_posture,
            workspace_name=workspace_name,
            last_scan_age_days=last_scan_age_days,
        ))

    out.print(Rule(style=f"dim {ADSCAN_PRIMARY}"))
    out.print(_render_links_strip(version_tag=version_tag))
    out.print()


def load_latest_posture_host() -> tuple[PostureScore | None, str | None, int | None]:
    """Walk ``~/.adscan/workspaces/`` for the most recent ``technical_report.json``.

    Returns ``(posture, workspace_name, age_days)``. Any element may be
    ``None`` if the lookup fails. Never raises.
    """
    try:
        from adscan_core.paths import get_workspaces_dir
        root = get_workspaces_dir()
    except Exception as exc:  # pragma: no cover - defensive
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None, None, None

    if not root.exists():
        return None, None, None

    best: tuple[float, Path] | None = None
    try:
        for entry in root.iterdir():
            if not entry.is_dir() or entry.name.startswith("."):
                continue
            report = entry / "technical_report.json"
            if not report.exists():
                continue
            try:
                mtime = report.stat().st_mtime
            except OSError:
                continue
            if best is None or mtime > best[0]:  # pylint: disable=unsubscriptable-object
                best = (mtime, entry)
    except OSError as exc:  # pragma: no cover - defensive
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None, None, None

    if best is None:
        return None, None, None

    mtime, ws_path = best
    try:
        report_data = json.loads((ws_path / "technical_report.json").read_text())
    except Exception as exc:  # pragma: no cover - defensive
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None, ws_path.name, None

    findings = _count_findings(report_data)
    paths_to_da = _count_paths_to_da(report_data)
    tier0 = _count_tier0(report_data)

    try:
        posture = compute_posture_score(
            PostureInputs(
                critical_findings=findings.get("critical", 0),
                high_findings=findings.get("high", 0),
                medium_findings=findings.get("medium", 0),
                low_findings=findings.get("low", 0),
                paths_to_da=paths_to_da,
                tier0_exposed=tier0,
            )
        )
    except Exception as exc:  # pragma: no cover - defensive
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None, ws_path.name, None

    age_days = int(max(0.0, time.time() - mtime) // 86400)
    return posture, ws_path.name, age_days


# ---------------------------------------------------------------------------
# Tier-aware intro renderer
# ---------------------------------------------------------------------------


def _load_pro_license_metadata() -> tuple[str, str]:
    """Return ``(org, expires)`` from ``~/.adscan/license.json`` defensively.

    Falls back to ``("registered", "no expiration")`` on any failure so the
    intro never breaks because the license file is missing or malformed.
    """
    org = "registered"
    expires = "no expiration"
    try:
        from adscan_core.paths import get_adscan_home_dir

        license_path = get_adscan_home_dir() / "license.json"
        if not license_path.exists():
            return org, expires
        data = json.loads(license_path.read_text())
    except Exception as exc:  # noqa: BLE001 — defensive: never fail the intro
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return org, expires

    if not isinstance(data, dict):
        return org, expires

    org_val = data.get("org") or data.get("organization") or data.get("customer")
    if isinstance(org_val, str) and org_val.strip():
        org = org_val.strip()

    exp_val = data.get("expires") or data.get("expiration") or data.get("expires_at")
    if isinstance(exp_val, str) and exp_val.strip():
        expires = exp_val.strip()

    return org, expires


def _render_intro_lite() -> Group:
    """Render the LITE intro body (without the brand ASCII / logo strip).

    Output is a Rich :class:`Group` so callers can ``console.print`` it
    inside any layout. Copy is locked — do not improvise.
    """
    headline = Text("ADscan LITE — community engine", style=f"bold {_BRAND_CYAN}")
    sub = Text("You have the same scan core the consultancies use. Run it.")

    cmd_demo = Text()
    cmd_demo.append("  adscan demo      ", style=f"{_BRAND_CYAN} on grey11")
    cmd_demo.append("see a 60-second sample run", style="dim")

    cmd_ci = Text()
    cmd_ci.append("  adscan ci        ", style=f"{_BRAND_CYAN} on grey11")
    cmd_ci.append("scan a real domain you control", style="dim")

    footer = Text()
    footer.append("Reports stay technical. PDF client kit lives in PRO. ")
    footer.append("(adscan upgrade)", style=f"bold {_BRAND_CYAN}")

    return Group(
        headline,
        sub,
        Text(""),
        cmd_demo,
        cmd_ci,
        Text(""),
        footer,
    )


def _render_intro_pro(*, org: str | None = None, expires: str | None = None) -> Group:
    """Render the PRO intro body with license metadata.

    Args:
        org: Organization name from ``license.json``. Falls back to a
            defensive read when ``None``.
        expires: Expiration string from ``license.json``. Falls back to
            a defensive read when ``None``.
    """
    if org is None or expires is None:
        loaded_org, loaded_exp = _load_pro_license_metadata()
        org = org or loaded_org
        expires = expires or loaded_exp

    headline = Text(
        "ADscan PRO — your client deliverable kit is ready",
        style=f"bold {_BRAND_CYAN}",
    )
    license_line = Text()
    license_line.append("License: ", style="bold")
    license_line.append(f"{org} · expires {expires}")

    cmd_demo = Text()
    cmd_demo.append("  adscan demo      ", style=f"{_BRAND_CYAN} on grey11")
    cmd_demo.append("generate a sample client kit (4 PDFs)", style="dim")

    cmd_ci = Text()
    cmd_ci.append("  adscan ci        ", style=f"{_BRAND_CYAN} on grey11")
    cmd_ci.append("run a real assessment", style="dim")

    footer = Text()
    footer.append("Outputs land in ")
    footer.append(
        "~/.adscan/workspaces/<domain>/deliverables/",
        style=f"{_BRAND_CYAN} on grey11",
    )

    return Group(
        headline,
        license_line,
        Text(""),
        cmd_demo,
        cmd_ci,
        Text(""),
        footer,
    )


def render_intro(*, force_pro: bool | None = None) -> Group:
    """Branched dispatch for the tier-aware intro.

    Args:
        force_pro: Test/override hook. When ``None`` (default), the
            current tier is detected via :func:`adscan_core.tier.is_pro`.

    Returns:
        A Rich :class:`Group` with the LITE or PRO intro body. The caller
        owns the console and can wrap this in any surrounding chrome
        (ASCII art, badges, links strip).
    """
    is_pro = tier.is_pro() if force_pro is None else force_pro
    return _render_intro_pro() if is_pro else _render_intro_lite()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _render_grid() -> Columns:
    panels = [_render_card(c) for c in _PATH_CARDS]
    return Columns(panels, equal=True, expand=True, padding=(0, 1))


# Amber accent used exclusively for the PRO badge — matches the LITE
# edition badge in the header so the operator builds a stable mental
# map ("amber == PRO surface").
_PRO_BADGE = "#d29922"


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


def _render_card(card: _Card) -> Panel:
    body = Text()
    body.append(card.eyebrow, style=f"bold {ADSCAN_PRIMARY}")
    body.append("\n")
    body.append(card.title, style="bold white")
    body.append("\n")
    body.append(card.command, style=f"{ADSCAN_PRIMARY} on grey11")
    body.append("\n")
    body.append(card.outcome, style="dim")
    return Panel(body, border_style=f"dim {ADSCAN_PRIMARY}", padding=(0, 1))


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
    return Text.from_markup("  Latest · " + " · ".join(pieces), style="dim")


def _render_links_strip(*, version_tag: str | None) -> Text:
    parts: list[str] = []
    parts.append(f"[link={ADSCAN_LINKS['docs']}]Docs[/link]")
    parts.append(f"[link={ADSCAN_LINKS['discord']}]Community[/link]")
    parts.append(f"[link={ADSCAN_LINKS['github']}]Source[/link]")
    if version_tag:
        parts.append(version_tag)
    return Text.from_markup("  [dim]" + "  ·  ".join(parts) + "[/dim]")


def _count_findings(report: dict) -> dict[str, int]:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    if not isinstance(report, dict):
        return out
    findings = report.get("findings") or report.get("vulnerabilities") or []
    if isinstance(findings, dict):
        # Already pre-bucketed.
        for k in out:
            try:
                out[k] = int(findings.get(k, 0) or 0)
            except (TypeError, ValueError):
                out[k] = 0
        return out
    if isinstance(findings, list):
        for item in findings:
            if not isinstance(item, dict):
                continue
            sev = str(item.get("severity") or item.get("risk") or "").strip().lower()
            if sev in out:
                out[sev] += 1
    return out


def _count_paths_to_da(report: dict) -> int:
    if not isinstance(report, dict):
        return 0
    for key in ("paths_to_da", "paths_to_domain_admin", "attack_paths"):
        v = report.get(key)
        if isinstance(v, int):
            return max(0, v)
        if isinstance(v, list):
            return len(v)
    return 0


def _count_tier0(report: dict) -> int:
    if not isinstance(report, dict):
        return 0
    for key in ("tier0_exposed", "tier_0_exposed", "tier0_compromised"):
        v = report.get(key)
        if isinstance(v, int):
            return max(0, v)
        if isinstance(v, list):
            return len(v)
    return 0


def discovery_cards() -> Iterable[_Card]:
    return _PATH_CARDS


__all__ = (
    "WELCOME_HEADLINE",
    "discovery_cards",
    "load_latest_posture_host",
    "print_welcome_host",
    "render_intro",
    "_render_intro_lite",
    "_render_intro_pro",
)
