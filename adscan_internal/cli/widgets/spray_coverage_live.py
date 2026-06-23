"""Static premium panels for Spray Coverage Orchestration.

This module is a pure UI layer for the spray-coverage feature (§10 of the
spray-coverage-orchestration design). It holds ONLY the static panel builders;
there is no Live class here — live streaming reuses the existing
``ProgressDashboard`` (``adscan_core.tui.progress_dashboard``) per spray. The
builders are pure functions that return Rich renderables. They never print and
never construct a ``Console`` (project invariant: resolve consoles via
``get_console()``; these builders simply hand a renderable back to the caller).

Builders:
    * :func:`render_spray_coverage_panel`  — §10.1 pre-execution overview.
    * :func:`render_deferred_pending_panel` — §10.4 end-of-scan deferred queue.
    * :func:`render_ci_spray_report`       — §10.6 compact ci audit report.
    * :func:`lockout_disabled_note`        — §10.7 lockout-disabled inline note.

Locked iconography (asserted verbatim by tests / spec §10):
    Per-type glyphs   ``▣ pre2k   ◆ useraspass   ⇄ reuse   ∅ blank``
    Status glyphs     ``✓ covered   ⊘ skipped(done)   ⏳ running   ○ queued``
                      ``◐ partial   ⏸ deferred(near-threshold)   ✗ failed``

Locked border palette: cyan = live/plan, green = safe/complete/recovered,
``COLOR_AMBER`` = deferred/pending, dim = covered/skipped. Red is reserved for
true errors only and is never used here. Color is never the sole signal: every
glyph and budget value carries literal text. English-only copy; no em dashes
(``·`` is the separator throughout).
"""

from __future__ import annotations

import time
from typing import Any, Mapping, Optional, Sequence

from rich import box
from rich.console import Group, RenderableType
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from adscan_core.theme import COLOR_AMBER, COLOR_MUTED, COLOR_STEEL
from adscan_internal.rich_output import mark_sensitive


# --------------------------------------------------------------------------- #
# Locked display vocabulary — tests / spec assert these strings verbatim.
# --------------------------------------------------------------------------- #


# Per-type glyph + human label. The display label for ``useraspass`` MUST read
# "user-as-password" (asserted by the test + nomenclature standard); the spray
# type id stays ``useraspass`` everywhere in logic.
_TYPE_GLYPH: dict[str, str] = {
    "pre2k": "▣",
    "useraspass": "◆",
    "reuse": "⇄",
    "blank": "∅",
}

_TYPE_LABEL: dict[str, str] = {
    "pre2k": "pre2k",
    "useraspass": "user-as-password",
    "reuse": "owned-credential reuse",
    "blank": "blank",
}

# Fixed display order — mirrors the prioritized spray sequence.
_TYPE_ORDER: tuple[str, ...] = ("pre2k", "useraspass", "reuse", "blank")


def _type_glyph(spray_type: str) -> str:
    return _TYPE_GLYPH.get(spray_type, "·")


def _type_label(spray_type: str) -> str:
    return _TYPE_LABEL.get(spray_type, spray_type)


def _ordered_type_ids(present: Sequence[str]) -> list[str]:
    """Return the present type ids in the fixed priority order (unknown last)."""
    seen = list(present)
    known = [t for t in _TYPE_ORDER if t in seen]
    extra = [t for t in seen if t not in _TYPE_ORDER]
    return known + extra


# --------------------------------------------------------------------------- #
# §10.7 — lockout-disabled inline note
# --------------------------------------------------------------------------- #


def lockout_disabled_note() -> RenderableType:
    """Inline ``dim`` note shown when ``lockoutThreshold == 0``.

    Replaces the budget block in §10.1 (and stands alone if §10.1 is skipped):
    every combo is sprayed immediately, with no eligibility filtering, no
    deferral, and no reconciliation. Leading ``ⓘ`` glyph, dim styling.

    Returns:
        A :class:`rich.text.Text` ready to print or embed in a Group.
    """
    note = Text(style="dim")
    note.append("ⓘ  ")
    note.append(
        "Lockout disabled (lockoutThreshold = 0) — spraying every combo "
        "immediately, no eligibility filtering, no deferral, no reconciliation."
    )
    return note


# --------------------------------------------------------------------------- #
# §10.1 — Spray Coverage plan panel (pre-execution overview)
# --------------------------------------------------------------------------- #


def render_spray_coverage_panel(
    plan: Any,
    *,
    domain: str,
    policy: Mapping[str, Any],
) -> Panel:
    """Build the §10.1 pre-execution coverage overview panel.

    Rendered once, before any spray runs, in both ``ci`` and interactive
    ``start`` Phase 4, right after the :class:`SprayCoveragePlan` is built.

    Hierarchy: policy line (the governing constraint) → per-type matrix
    (Planned / Covered / Eligible now / Deferred + status glyph) → tightest
    lockout-budget line → a one-line projection that always ends in the
    promise *0 lockouts projected*.

    Args:
        plan: A :class:`SprayCoveragePlan` with ``.by_type`` (mapping of type
            id to a ``TypePlan``) and ``.lockout_disabled``.
        domain: Target domain (masked via ``mark_sensitive``).
        policy: ``{"threshold": int, "observation_window_min": int,
            "margin": int}``.

    Returns:
        A :class:`rich.panel.Panel` (border ``cyan``).
    """
    masked_domain = mark_sensitive(domain, "domain")
    by_type: dict[str, Any] = dict(getattr(plan, "by_type", {}) or {})
    lockout_disabled = bool(getattr(plan, "lockout_disabled", False))

    pieces: list[RenderableType] = []

    # --- Policy / governing constraint -------------------------------------
    if lockout_disabled:
        pieces.append(lockout_disabled_note())
    else:
        threshold = policy.get("threshold")
        window = policy.get("observation_window_min")
        margin = policy.get("margin")
        policy_line = Text()
        policy_line.append("Lockout policy   ", style="dim")
        policy_line.append(f"threshold {threshold}", style="bold")
        policy_line.append("   ·   ", style="dim")
        policy_line.append(f"observation window {window}m", style="bold")
        policy_line.append("   ·   ", style="dim")
        policy_line.append(f"margin {margin}", style="bold")
        pieces.append(policy_line)
    pieces.append(Text())

    # --- Per-type matrix ----------------------------------------------------
    matrix = Table.grid(padding=(0, 2))
    matrix.add_column(width=2)  # glyph
    matrix.add_column(no_wrap=False)  # label
    matrix.add_column(justify="right")  # planned
    matrix.add_column(justify="right")  # covered
    if not lockout_disabled:
        matrix.add_column(justify="right")  # eligible now
        matrix.add_column(justify="right")  # deferred
    matrix.add_column(no_wrap=False)  # status

    header_cells = [
        Text(""),
        Text("Type", style="dim"),
        Text("Planned", style="dim"),
        Text("Covered", style="dim"),
    ]
    if not lockout_disabled:
        header_cells.append(Text("Eligible now", style="dim"))
        header_cells.append(Text("Deferred", style="dim"))
    header_cells.append(Text("Status", style="dim"))
    matrix.add_row(*header_cells)

    total_now = 0
    total_deferred = 0
    for type_id in _ordered_type_ids(list(by_type.keys())):
        tp = by_type[type_id]
        now_count = len(getattr(tp, "spray_now", []) or [])
        defer_count = len(getattr(tp, "defer", []) or [])
        covered = int(getattr(tp, "covered_count", 0) or 0)
        planned = int(getattr(tp, "planned_count", 0) or 0)
        total_now += now_count
        total_deferred += defer_count

        glyph = Text(_type_glyph(type_id), style="bold cyan")
        label = Text(_type_label(type_id))
        status_icon, status_text, status_style = _type_status(
            now_count=now_count, defer_count=defer_count, tp=tp
        )
        status = Text()
        status.append(status_icon + " ", style=status_style)
        status.append(status_text, style=status_style)

        cells: list[RenderableType] = [glyph, label, Text(str(planned)), Text(str(covered))]
        if not lockout_disabled:
            cells.append(Text(str(now_count) if now_count else "—"))
            cells.append(Text(str(defer_count) if defer_count else "—"))
        cells.append(status)
        matrix.add_row(*cells)
    pieces.append(matrix)
    pieces.append(Text())

    # --- Tightest lockout-budget line --------------------------------------
    if not lockout_disabled:
        pieces.append(_render_budget_line(plan=plan, policy=policy))

    # --- Projection line (always ends in "0 lockouts projected") -----------
    projection = Text()
    if total_now == 0 and total_deferred == 0:
        projection.append("Nothing to spray · all covered (re-runnable below)", style="dim")
    else:
        projection.append(f"{total_now} combos spray now", style="bold")
        if total_deferred:
            projection.append(" · ", style="dim")
            projection.append(
                f"{total_deferred} deferred to reconciliation", style=COLOR_AMBER
            )
        projection.append(" · ", style="dim")
        projection.append("0 lockouts projected", style="bold green")
    pieces.append(projection)

    title = f"💦  Spray Coverage Plan · {masked_domain}"
    return Panel(
        Padding(Group(*pieces), (1, 2)),
        title=title,
        border_style="cyan",
        box=box.ROUNDED,
        expand=False,
    )


def _type_status(*, now_count: int, defer_count: int, tp: Any) -> tuple[str, str, str]:
    """Return ``(glyph, text, style)`` for a coverage-matrix row.

    fully covered → ``⊘ done`` (dim); majority-covered but with remaining work
    → ``◐ NN%`` (amber, reads as "mostly done"); deferred-only → ``⏸ deferred``
    (amber); otherwise eligible-now (incl. lightly-covered) → ``○ runs`` (cyan).
    """
    covered = int(getattr(tp, "covered_count", 0) or 0)
    planned = int(getattr(tp, "planned_count", 0) or 0)
    if now_count == 0 and defer_count == 0:
        return "⊘", "done", "dim"
    # ``◐`` is the "mostly done" partial glyph — reserve it for rows that are
    # majority-covered so a lightly-covered type still reads as a fresh run.
    if planned > 0 and covered * 2 > planned:
        pct = int(round(100.0 * covered / planned))
        return "◐", f"{pct}%", COLOR_AMBER
    if now_count == 0 and defer_count > 0:
        return "⏸", "deferred", COLOR_AMBER
    return "○", "runs", "cyan"


def _render_budget_line(*, plan: Any, policy: Mapping[str, Any]) -> RenderableType:
    """Render the tightest-lockout-budget gauge line (color-blind safe).

    The budget value is always paired with the literal ``N of M`` text and a
    ``N left`` remaining count so the bar is never the sole signal. The
    "tightest user" is the account closest to lockout. Best-effort: when the
    plan does not carry per-user budget detail, render a conservative
    margin-holding line instead of guessing a user.
    """
    threshold = policy.get("threshold")
    margin = policy.get("margin")
    line = Text()
    line.append("Lockout budget  ", style="dim")

    tightest = getattr(plan, "tightest_user", None)
    used = getattr(plan, "tightest_used", None)
    try:
        threshold_int = int(threshold) if threshold is not None else None
    except (TypeError, ValueError):
        threshold_int = None

    if tightest and used is not None and threshold_int:
        used_int = int(used)
        left = max(threshold_int - used_int, 0)
        filled = min(max(used_int, 0), threshold_int)
        empty = max(threshold_int - filled, 0)
        bar = "█" * filled + "░" * empty
        bar_style = "green" if left > int(margin or 0) else COLOR_AMBER
        line.append("tightest user ", style="dim")
        line.append(mark_sensitive(str(tightest), "user"), style="bold")
        line.append("  [", style="dim")
        line.append(bar, style=bar_style)
        line.append("] ", style="dim")
        line.append(f"{used_int} of {threshold_int}", style="bold")
        line.append(" · ", style="dim")
        line.append(f"{left} left", style=bar_style)
    else:
        line.append("margin holding · no account near the lockout threshold", style="dim")
    return line


# --------------------------------------------------------------------------- #
# §10.4 — deferred-pending summary
# --------------------------------------------------------------------------- #


def render_deferred_pending_panel(queue: Any, *, mode: str) -> Panel:
    """Build the §10.4 deferred-pending summary panel (border ``COLOR_AMBER``).

    Rendered at the end of a scan, only when the deferred queue is non-empty.

    Args:
        queue: A :class:`DeferredSprayQueue` (``.combos`` of
            :class:`DeferredSprayCombo`, ``.earliest_reset_epoch()``, ``len()``).
        mode: ``"ci"`` to show the opt-in wait hint
            (``ADSCAN_SPRAY_WAIT_LOCKOUT=1``); any other value omits it
            (interactive gets the §10.5 prompt instead).

    Returns:
        A :class:`rich.panel.Panel`.
    """
    combos = list(getattr(queue, "combos", []) or [])
    total = len(combos)

    pieces: list[RenderableType] = []

    why = Text()
    why.append(
        f"{total} combos were not sprayed to protect near-threshold accounts.",
        style="dim",
    )
    pieces.append(why)
    pieces.append(
        Text(
            "They are queued and safe to run once the lockout window resets.",
            style="dim",
        )
    )
    pieces.append(Text())

    # --- Per-type deferred counts + earliest-safe --------------------------
    by_type_count: dict[str, int] = {}
    by_type_earliest: dict[str, Optional[float]] = {}
    for combo in combos:
        spray_type = getattr(combo, "spray_type", "") or ""
        by_type_count[spray_type] = by_type_count.get(spray_type, 0) + 1
        epoch = getattr(combo, "earliest_safe_epoch", None)
        if epoch is not None:
            cur = by_type_earliest.get(spray_type)
            if cur is None or epoch < cur:
                by_type_earliest[spray_type] = epoch

    table = Table.grid(padding=(0, 2))
    table.add_column(width=2)
    table.add_column(no_wrap=False)
    table.add_column(justify="right")
    table.add_column(no_wrap=False, style="dim")
    table.add_row(
        Text(""),
        Text("Type", style="dim"),
        Text("Deferred", style="dim"),
        Text("Earliest safe", style="dim"),
    )
    now = time.time()
    for type_id in _ordered_type_ids(list(by_type_count.keys())):
        count = by_type_count[type_id]
        epoch = by_type_earliest.get(type_id)
        table.add_row(
            Text(_type_glyph(type_id), style="bold " + COLOR_AMBER),
            Text(_type_label(type_id)),
            Text(str(count)),
            Text(_earliest_safe_text(epoch, now=now)),
        )
    pieces.append(table)
    pieces.append(Text())

    # --- Longest reset countdown -------------------------------------------
    # The "longest" reset is the max earliest-safe across all combos (the queue
    # is fully drainable only once the last near-threshold account resets).
    longest_epoch = None
    for combo in combos:
        epoch = getattr(combo, "earliest_safe_epoch", None)
        if epoch is not None and (longest_epoch is None or epoch > longest_epoch):
            longest_epoch = epoch

    reset_line = Text()
    if longest_epoch is None:
        reset_line.append("Lockout window reset time unknown", style="dim")
    elif longest_epoch <= now:
        reset_line.append(
            "Lockout window already reset · safe to drain now", style="bold green"
        )
    else:
        remaining_min = max(int((longest_epoch - now) // 60), 0)
        reset_line.append("Lockout window resets in ", style="dim")
        reset_line.append(f"~{remaining_min} min", style="bold")
        reset_line.append("  (longest of the queued combos)", style="dim")
    pieces.append(reset_line)

    # --- ci opt-in hint -----------------------------------------------------
    if str(mode).lower() == "ci":
        hint = Text()
        hint.append("ci  →  set  ", style="dim")
        hint.append("ADSCAN_SPRAY_WAIT_LOCKOUT=1", style="bold")
        hint.append("  to wait the window and drain these", style="dim")
        pieces.append(hint)

    title = "⏸  Spray Coverage · deferred"
    return Panel(
        Padding(Group(*pieces), (1, 2)),
        title=title,
        border_style=COLOR_AMBER,
        box=box.ROUNDED,
        expand=False,
    )


def _earliest_safe_text(epoch: Optional[float], *, now: float) -> str:
    if epoch is None:
        return "unknown"
    if epoch <= now:
        return "safe now"
    remaining_min = max(int((epoch - now) // 60), 0)
    clock = time.strftime("%H:%M", time.localtime(epoch))
    return f"in ~{remaining_min}m   (window resets ~{clock})"


# --------------------------------------------------------------------------- #
# §10.6 — ci coverage report (compact end-of-scan audit summary)
# --------------------------------------------------------------------------- #


def render_ci_spray_report(
    summary: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
) -> Panel:
    """Build the §10.6 compact ``ci`` coverage report (the client audit record).

    Border ``green`` when ``summary["locked"] == 0``, else ``COLOR_AMBER``.

    Args:
        summary: Keys ``types_planned``, ``types_run``, ``types_covered``,
            ``locked``, ``combos_sprayed``, ``recovered``, ``pending`` and an
            optional ``domain``.
        rows: Per-type rows: ``{"type", "sprayed", "hits", "pending",
            "status"}``.

    Returns:
        A :class:`rich.panel.Panel`.
    """
    locked = int(summary.get("locked", 0) or 0)
    recovered = int(summary.get("recovered", 0) or 0)
    pending = int(summary.get("pending", 0) or 0)
    combos_sprayed = int(summary.get("combos_sprayed", 0) or 0)
    types_planned = int(summary.get("types_planned", 0) or 0)
    types_run = int(summary.get("types_run", 0) or 0)
    types_covered = int(summary.get("types_covered", 0) or 0)
    domain = summary.get("domain")

    pieces: list[RenderableType] = []

    # --- Headline ----------------------------------------------------------
    headline = Text()
    headline.append(f"{types_planned} types planned", style="bold")
    headline.append(" · ", style="dim")
    headline.append(f"{types_run} run", style="bold")
    headline.append(" · ", style="dim")
    headline.append(f"{types_covered} already covered", style="dim")
    headline.append(" · ", style="dim")
    if locked == 0:
        headline.append("0 accounts locked", style="bold green")
    else:
        headline.append(f"{locked} accounts locked", style="bold " + COLOR_AMBER)
    pieces.append(headline)
    pieces.append(Text())

    # --- Per-type one-liners -----------------------------------------------
    table = Table.grid(padding=(0, 2))
    table.add_column(width=2)  # type glyph
    table.add_column(no_wrap=False)  # label
    table.add_column(width=2)  # status glyph
    table.add_column(no_wrap=False)  # sprayed
    table.add_column(no_wrap=False)  # hits
    table.add_column(no_wrap=False)  # pending
    for row in rows:
        type_id = str(row.get("type", ""))
        sprayed = int(row.get("sprayed", 0) or 0)
        hits = int(row.get("hits", 0) or 0)
        row_pending = int(row.get("pending", 0) or 0)
        status = str(row.get("status", "")).lower()
        status_glyph, status_style = _ci_row_status(status=status)
        hits_text = f"{hits} hit" if hits == 1 else f"{hits} hits"
        if status == "covered":
            sprayed_text = "covered"
            hits_text = "—"
        else:
            sprayed_text = f"{sprayed} sprayed"
        table.add_row(
            Text(_type_glyph(type_id), style="bold cyan"),
            Text(_type_label(type_id)),
            Text(status_glyph, style=status_style),
            Text(sprayed_text, style="dim"),
            Text("· " + hits_text, style="green" if hits else "dim"),
            Text(f"· {row_pending} pending", style=COLOR_AMBER if row_pending else "dim"),
        )
    pieces.append(table)
    pieces.append(Text())

    # --- Footer totals ------------------------------------------------------
    footer = Text()
    footer.append(f"{combos_sprayed} combos sprayed", style="dim")
    footer.append(" · ", style="dim")
    recovered_label = f"{recovered} credentials recovered"
    footer.append(recovered_label, style="bold green" if recovered else "dim")
    footer.append(" · ", style="dim")
    footer.append(f"{pending} pending", style=COLOR_AMBER if pending else "dim")
    footer.append(" · ", style="dim")
    footer.append(
        "0 lockouts" if locked == 0 else f"{locked} lockouts",
        style="bold green" if locked == 0 else "bold " + COLOR_AMBER,
    )
    pieces.append(footer)

    # --- Pending hint (only when pending) ----------------------------------
    if pending > 0:
        hint = Text()
        hint.append(f"{pending} pending until lockout window resets — set ", style="dim")
        hint.append("ADSCAN_SPRAY_WAIT_LOCKOUT=1", style="bold")
        pieces.append(hint)

    masked_domain = mark_sensitive(str(domain), "domain") if domain else None
    title = "💦  Spraying Coverage"
    if masked_domain is not None:
        title = f"💦  Spraying Coverage · {masked_domain}"

    return Panel(
        Padding(Group(*pieces), (1, 2)),
        title=title,
        border_style="green" if locked == 0 else COLOR_AMBER,
        box=box.ROUNDED,
        expand=False,
    )


def _ci_row_status(*, status: str) -> tuple[str, str]:
    """Map a per-type row status to ``(glyph, style)`` for the ci report."""
    if status == "covered":
        return "⊘", "dim"
    if status == "failed":
        return "✗", "dim"
    if status in ("run", "done", "ran"):
        return "✓", "green"
    if status in ("deferred", "pending"):
        return "⏸", COLOR_AMBER
    return "○", "dim"


# --------------------------------------------------------------------------- #
# Pre2k educational panel (Phase 6 · Step 1)
# --------------------------------------------------------------------------- #


def render_pre2k_education_panel(domain: str, *, computer_count: int) -> Panel:
    """Build the teaching panel shown before the pre2k computer-account spray.

    Pre2k spray runs as its own first step in the spraying phase. Because many
    operators have never run it, this panel explains what it is, why it is safe
    to run first, and what a hit means, before asking for confirmation.

    Args:
        domain: Target domain (masked via ``mark_sensitive``).
        computer_count: Number of enabled computer accounts in scope.

    Returns:
        A :class:`rich.panel.Panel` (border ``cyan``).
    """
    masked_domain = mark_sensitive(domain, "domain")
    pieces: list[RenderableType] = []

    def _section(heading: str, body: str) -> None:
        head = Text()
        head.append(heading, style="bold cyan")
        pieces.append(head)
        pieces.append(Text(body, style="default"))
        pieces.append(Text())

    _section(
        "What it is",
        "Pre-Windows-2000 computer accounts are frequently provisioned with a "
        "password equal to the hostname in lowercase (e.g. WS01$ → \"ws01\"). "
        "This step sprays that single pattern across every enabled computer "
        "account in the domain.",
    )
    _section(
        "Why it runs first, and why it is safe",
        "Computer accounts are NOT governed by the user account-lockout policy, "
        "so this can never lock out a domain user. It is the cheapest, "
        "lowest-risk foothold check available, so it leads the phase.",
    )
    _section(
        "What a hit means",
        "A valid computer credential is an authenticated foothold (LDAP / SMB) "
        "and often opens RBCD, delegation, or deeper enumeration.",
    )

    scope = Text(style="dim")
    scope.append("ⓘ  ")
    scope.append(f"{computer_count} enabled computer account(s) in scope.")
    pieces.append(scope)

    return Panel(
        Padding(Group(*pieces), (1, 2)),
        title=f"▣  Pre-Windows 2000 Computer Spray · {masked_domain}",
        border_style="cyan",
        box=box.ROUNDED,
    )


# --------------------------------------------------------------------------- #
# Coverage selector overview (Phase 6 · Step 2)
# --------------------------------------------------------------------------- #


def _coverage_bar(pct: int, *, width: int = 10) -> Text:
    """A 10-cell coverage bar: filled green, remainder dim."""
    pct = max(0, min(100, int(pct)))
    filled = round(pct / 100 * width)
    bar = Text()
    bar.append("█" * filled, style="green" if pct >= 100 else COLOR_STEEL)
    bar.append("░" * (width - filled), style="dim")
    return bar


def render_coverage_selector_panel(
    rows: Sequence[Mapping[str, Any]],
    *,
    domain: str,
    threshold: Any,
    margin: Any,
    near_lockout: int,
    lockout_disabled: bool = False,
) -> Panel:
    """Build the coverage overview shown above the spray-type selector.

    Each row is ``{"type": id, "planned": int, "covered": int, "pct": int,
    "eligible": int}``. A coverage bar + percentage shows how much of each spray
    type is already done; ``Eligible now`` shows how many users can still be
    sprayed within the lockout margin. Status: ✓ complete, ⏸ none eligible (all
    deferred near threshold), ◐ partial, ○ untouched.

    Returns:
        A :class:`rich.panel.Panel` (border ``cyan``).
    """
    masked_domain = mark_sensitive(domain, "domain")
    pieces: list[RenderableType] = []

    if lockout_disabled:
        pieces.append(lockout_disabled_note())
    else:
        head = Text()
        head.append("Lockout policy   ", style="dim")
        head.append(f"threshold {threshold}", style="bold")
        head.append("   ·   ", style="dim")
        head.append(f"margin {margin}", style="bold")
        head.append("   ·   ", style="dim")
        near_style = "bold green" if not near_lockout else "bold " + COLOR_AMBER
        head.append(f"{near_lockout} users near lockout", style=near_style)
        pieces.append(head)
    pieces.append(Text())

    table = Table.grid(padding=(0, 2))
    table.add_column(width=2)  # glyph
    table.add_column(no_wrap=False)  # label
    table.add_column(no_wrap=True)  # bar
    table.add_column(justify="right")  # pct
    table.add_column(justify="right")  # eligible
    table.add_column(no_wrap=False)  # status
    table.add_row(
        Text(""),
        Text("Type", style="dim"),
        Text("Coverage", style="dim"),
        Text(""),
        Text("Eligible now", style="dim"),
        Text("Status", style="dim"),
    )

    for row in rows:
        type_id = str(row.get("type", ""))
        pct = int(row.get("pct", 0) or 0)
        eligible = int(row.get("eligible", 0) or 0)
        if pct >= 100:
            status_icon, status_text, status_style = "✓", "complete", "green"
        elif eligible <= 0:
            status_icon, status_text, status_style = "⏸", "none eligible", COLOR_AMBER
        elif pct > 0:
            status_icon, status_text, status_style = "◐", "partial", COLOR_STEEL
        else:
            status_icon, status_text, status_style = "○", "ready", COLOR_MUTED
        status = Text()
        status.append(status_icon + " ", style=status_style)
        status.append(status_text, style=status_style)
        table.add_row(
            Text(_type_glyph(type_id), style="bold cyan"),
            Text(_type_label(type_id)),
            _coverage_bar(pct),
            Text(f"{pct}%", style="bold"),
            Text(str(eligible)),
            status,
        )

    pieces.append(table)

    return Panel(
        Padding(Group(*pieces), (1, 2)),
        title=f"💦  Spray Coverage · {masked_domain}",
        border_style="cyan",
        box=box.ROUNDED,
    )


__all__ = [
    "render_spray_coverage_panel",
    "render_deferred_pending_panel",
    "render_ci_spray_report",
    "lockout_disabled_note",
    "render_pre2k_education_panel",
    "render_coverage_selector_panel",
]
