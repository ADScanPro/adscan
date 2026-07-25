"""Live progress widget + summary panel for the posture probe phase.

The probe engine in :mod:`adscan_internal.services.posture_probe` is the
source of truth for state and signals; this module is a pure UI layer.
:class:`PostureProbeLiveView` consumes the engine's
:data:`~adscan_internal.services.posture_probe.ProbeProgressCallback` contract
and renders a single self-updating panel covering both UNAUTH and AUTH phases.
:func:`render_posture_probe_summary` builds the post-probe summary card.

Locked icons (project conventions):
    🔍  exclusive to the live-progress title (probing in flight)
    🛡️  exclusive to the summary title (probe complete)
    ⏳  running        ✓  done OK        ✗  failed/permissive
    ⊘  skipped (already known)

Locked palette: green border for hardening detected, dim for permissive,
dim cyan for cached, cyan for live. Never red (red is reserved for true
errors elsewhere in the codebase).
"""

from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Optional

from rich import box
from rich.console import Group, RenderableType
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from adscan_core.tui import LiveSession, LiveSessionConfig

from adscan_core import telemetry
from adscan_internal import get_console
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.domain_posture import (
    ConstraintCategory,
    DomainPosture,
    SignalConfidence,
    TriState,
)
from adscan_internal.services.posture_probe import ProbePhase, ProbeResult
from adscan_core.rich_output import print_exception


# --------------------------------------------------------------------------- #
# Locked label maps — tests assert these strings verbatim.
# --------------------------------------------------------------------------- #


_PROBE_CONSTRAINT_LABEL: dict[ConstraintCategory, str] = {
    ConstraintCategory.LDAPS_AVAILABLE: "LDAPS availability",
    ConstraintCategory.LDAP_STARTTLS_AVAILABLE: "StartTLS availability",
    ConstraintCategory.LDAP_SIGNING: "LDAP signing required",
    ConstraintCategory.LDAP_CHANNEL_BINDING: "LDAP channel binding",
    ConstraintCategory.NTLM_AUTHENTICATION: "NTLM acceptance",
    ConstraintCategory.KERBEROS_RC4: "Kerberos RC4 support",
    ConstraintCategory.KERBEROS_AES_ONLY: "Kerberos AES-only enforcement",
    ConstraintCategory.KERBEROS_ETYPE_PROBE: "Kerberos non-default salt",
    ConstraintCategory.SMB_SIGNING: "SMB signing",
}


_PROBE_HARDENING_LABEL: dict[tuple[ConstraintCategory, TriState], str] = {
    (ConstraintCategory.NTLM_AUTHENTICATION, TriState.DISABLED): (
        "NTLM authentication disabled"
    ),
    (ConstraintCategory.KERBEROS_RC4, TriState.DISABLED): (
        "RC4 Kerberos encryption disabled"
    ),
    (ConstraintCategory.KERBEROS_AES_ONLY, TriState.ENABLED): (
        "AES-only Kerberos enforced"
    ),
    (ConstraintCategory.KERBEROS_ETYPE_PROBE, TriState.ENABLED): (
        "Non-default Kerberos salt"
    ),
    (ConstraintCategory.LDAP_SIGNING, TriState.REQUIRED): "LDAP signing required",
    (ConstraintCategory.LDAP_CHANNEL_BINDING, TriState.REQUIRED): (
        "LDAP channel binding required"
    ),
    # LDAPS is the only inverse-polarity category here: the SECURE state is
    # ENABLED (the encrypted channel is offered), not a non-default toggle.
    # LDAPS *available* is therefore the hardening signal; LDAPS *unavailable*
    # is a plaintext-downgrade weakness and lives in the permissive map below
    # — matching both the report renderer (``render_detected_posture``) and the
    # ``ldaps_unavailable`` finding emitted from posture (which fires on
    # DISABLED, never ENABLED).
    (ConstraintCategory.LDAPS_AVAILABLE, TriState.ENABLED): "LDAPS available",
    # StartTLS shares LDAPS's inverse polarity: StartTLS *available* on 389 is
    # the hardening signal (an encrypted-channel option), StartTLS
    # *unavailable* is the plaintext-downgrade weakness (permissive map below).
    (ConstraintCategory.LDAP_STARTTLS_AVAILABLE, TriState.ENABLED): (
        "StartTLS available"
    ),
    (ConstraintCategory.SMB_SIGNING, TriState.REQUIRED): "SMB signing required",
}


# Locked sort order for hardening rows in the summary panel (matches PR7 report).
_HARDENING_SORT_ORDER: list[ConstraintCategory] = [
    ConstraintCategory.NTLM_AUTHENTICATION,
    ConstraintCategory.KERBEROS_RC4,
    ConstraintCategory.KERBEROS_AES_ONLY,
    ConstraintCategory.KERBEROS_ETYPE_PROBE,
    ConstraintCategory.LDAP_SIGNING,
    ConstraintCategory.LDAP_CHANNEL_BINDING,
    ConstraintCategory.LDAPS_AVAILABLE,
    ConstraintCategory.LDAP_STARTTLS_AVAILABLE,
    ConstraintCategory.SMB_SIGNING,
]


# Permissive labels — rendered in the "Permissive" block when a probe ran
# successfully but observed the OPPOSITE of hardening.
_PROBE_PERMISSIVE_LABEL: dict[tuple[ConstraintCategory, TriState], str] = {
    (ConstraintCategory.NTLM_AUTHENTICATION, TriState.ENABLED): (
        "NTLM authentication accepted"
    ),
    (ConstraintCategory.KERBEROS_RC4, TriState.ENABLED): (
        "RC4 Kerberos encryption accepted"
    ),
    (ConstraintCategory.KERBEROS_ETYPE_PROBE, TriState.DISABLED): (
        "Standard Kerberos salt"
    ),
    # LDAPS unavailable = the DC offers only plaintext LDAP/389 → a
    # downgrade vector, surfaced as the ``ldaps_unavailable`` finding. See
    # the inverse-polarity note in ``_PROBE_HARDENING_LABEL`` above.
    (ConstraintCategory.LDAPS_AVAILABLE, TriState.DISABLED): "LDAPS unavailable",
    (ConstraintCategory.LDAP_STARTTLS_AVAILABLE, TriState.DISABLED): (
        "StartTLS unavailable"
    ),
    (ConstraintCategory.LDAP_CHANNEL_BINDING, TriState.DISABLED): (
        "LDAP channel binding not enforced"
    ),
    # Signing categories are polarity-symmetric with channel binding: the probe
    # emits a definitive DISABLED/HIGH "not required" verdict (unsigned bind
    # accepted -> LDAP_BIND_NO_SIGN_OK; NEGOTIATE without signing-required ->
    # SMB_SIGNING_NEGOTIATED_NOT_REQUIRED). Without these permissive labels that
    # observed weakness matched NEITHER map and was silently dropped from the
    # panel — the exact gap that hid "LDAP signing not required" on a DC where
    # signing is off while "channel binding not enforced" still rendered.
    (ConstraintCategory.LDAP_SIGNING, TriState.DISABLED): (
        "LDAP signing not required"
    ),
    (ConstraintCategory.SMB_SIGNING, TriState.DISABLED): (
        "SMB signing not required"
    ),
}


_PROGRESS_HINTS_BY_CATEGORY_DONE: dict[tuple[ConstraintCategory, TriState], str] = {
    (ConstraintCategory.LDAPS_AVAILABLE, TriState.ENABLED): "port 636 → ✓ Available",
    (ConstraintCategory.LDAPS_AVAILABLE, TriState.DISABLED): "port 636 → ✗ Unreachable",
    (ConstraintCategory.LDAP_STARTTLS_AVAILABLE, TriState.ENABLED): (
        "StartTLS/389 → ✓ Available"
    ),
    (ConstraintCategory.LDAP_STARTTLS_AVAILABLE, TriState.DISABLED): (
        "StartTLS/389 → ✗ Unavailable"
    ),
    (ConstraintCategory.LDAP_SIGNING, TriState.REQUIRED): (
        "strongerAuthRequired → ✓ Required"
    ),
    (ConstraintCategory.KERBEROS_RC4, TriState.ENABLED): (
        "AS-REQ etype=23 → ✓ Accepted"
    ),
    (ConstraintCategory.KERBEROS_RC4, TriState.DISABLED): (
        "AS-REQ etype=23 → ✗ Rejected"
    ),
    (ConstraintCategory.KERBEROS_ETYPE_PROBE, TriState.ENABLED): (
        "ETYPE-INFO2 → non-default salt"
    ),
    (ConstraintCategory.KERBEROS_ETYPE_PROBE, TriState.DISABLED): (
        "ETYPE-INFO2 → standard salt"
    ),
    (ConstraintCategory.NTLM_AUTHENTICATION, TriState.ENABLED): (
        "forced NTLM bind → ✓ Accepted"
    ),
    (ConstraintCategory.NTLM_AUTHENTICATION, TriState.DISABLED): (
        "forced NTLM bind → ✗ Rejected"
    ),
    (ConstraintCategory.SMB_SIGNING, TriState.REQUIRED): (
        "negotiate flags → ✓ Required"
    ),
    (ConstraintCategory.LDAP_CHANNEL_BINDING, TriState.REQUIRED): (
        "LDAPS bind no-CBT → ✗ Rejected (SEC_E_BAD_BINDINGS)"
    ),
    (ConstraintCategory.LDAP_CHANNEL_BINDING, TriState.DISABLED): (
        "LDAPS bind no-CBT → ✓ Accepted"
    ),
}


# --------------------------------------------------------------------------- #
# Locked summary copy. Single place to edit user-visible summary strings.
# --------------------------------------------------------------------------- #


_HEADLINE_DETECTED_NEW = (
    "{count} probes complete · {hardening} hardening controls detected · {elapsed}"
)
_HEADLINE_DETECTED_MERGED = (
    "{count} probes complete · {hardening} hardening controls now confirmed · {elapsed}"
)
_FRAMING_DETECTED_NEW = "ADscan will adapt every subsequent operation to this posture."
_FRAMING_DETECTED_MERGED = (
    "Adapting all subsequent operations to this complete posture."
)
_QUALIFIER_NEW = "⚡ NEW"
_QUALIFIER_KNOWN = "· already known"


# --------------------------------------------------------------------------- #
# Live view
# --------------------------------------------------------------------------- #


@dataclass
class _RowState:
    """Tracking row for one probed category.

    ``status`` values:
      * ``pending``  — pre-allocated before the probe engine started this
        row. Shown with a grey hourglass + ``"queued…"`` hint so the panel
        line-count is stable from the very first render (avoids the Rich
        Live header-stacking anti-pattern where a growing renderable
        leaves ghost frames in scrollback).
      * ``running``  — probe engine has fired ``on_progress(cat, None)``.
        Spinner + ``"checking…"``.
      * ``done`` / ``skipped`` / ``failed`` — final states with their
        own icon + hint copy.
    """

    category: ConstraintCategory
    phase: ProbePhase
    status: str = "pending"  # pending | running | done | skipped | failed
    result: Optional[ProbeResult] = None
    started_at: float = field(default_factory=time.monotonic)


# Canonical probe inventory — used by the live widget to pre-allocate
# rows so the rendered panel has a STABLE line count from frame 1.
# Matches the probe sets driven by
# ``adscan_internal.services.posture_probe.probe_unauth`` /
# ``probe_auth``. Order here is the order the operator sees in the panel.
_PREALLOCATED_UNAUTH_CATEGORIES: list[ConstraintCategory] = [
    ConstraintCategory.LDAPS_AVAILABLE,
    ConstraintCategory.LDAP_STARTTLS_AVAILABLE,
    ConstraintCategory.LDAP_SIGNING,
    ConstraintCategory.LDAP_CHANNEL_BINDING,
]
_PREALLOCATED_AUTH_CATEGORIES: list[ConstraintCategory] = [
    ConstraintCategory.KERBEROS_RC4,
    ConstraintCategory.NTLM_AUTHENTICATION,
    ConstraintCategory.SMB_SIGNING,
    ConstraintCategory.KERBEROS_ETYPE_PROBE,
]


class PostureProbeLiveView:
    """Live progress widget for the posture probe phase.

    Renders a :class:`rich.live.Live` panel that updates as probes start,
    finish, or skip. Use as a context manager: enter at the start of the
    probe phase, exit when probes complete (or fail). The widget exposes
    :meth:`on_phase_start` / :meth:`on_progress` for the probe engine to
    drive via its
    :data:`~adscan_internal.services.posture_probe.ProbeProgressCallback`
    contract.

    The widget never raises — defensive defaults guard malformed
    :class:`~adscan_internal.services.posture_probe.ProbeResult` fields.
    When the terminal is not a TTY (or ``ADSCAN_NO_LIVE=1``), the live
    refresh is suppressed and the rendered state is only emitted on exit.
    """

    def __init__(
        self,
        *,
        domain: str,
        dc_ip: str,
        username: Optional[str] = None,
    ) -> None:
        self.domain = domain
        self.dc_ip = dc_ip
        self.username = username
        self._rows: dict[ConstraintCategory, _RowState] = {}
        self._order: list[ConstraintCategory] = []
        self._current_phase: Optional[ProbePhase] = None
        self._started = time.monotonic()
        self._console = get_console()
        self._session: Optional[LiveSession] = None
        self._is_tty = sys.stdout.isatty() and os.environ.get("ADSCAN_NO_LIVE") != "1"

        # Pre-allocate every probe row up front. Combined with
        # ``alt_screen=True`` in ``__enter__``, this gives the panel a
        # stable rendered shape from frame 1 AND contains all refreshes
        # inside an isolated terminal buffer so ghost frames cannot leak
        # into the operator's scrollback. The pre-allocation alone is
        # not enough on ``alt_screen=False`` in practice — at
        # ``refresh_per_second=10`` Rich Live's overwrite logic loses
        # frames whenever a refresh is interrupted by another
        # ``update()`` mid-write, and the partial output ends up as a
        # ghost above the current Live region. See CLAUDE.md
        # § "Rich Live UX — Stable line-count rule" for the canonical
        # pattern.
        for cat in _PREALLOCATED_UNAUTH_CATEGORIES:
            self._rows[cat] = _RowState(category=cat, phase=ProbePhase.UNAUTH, status="pending")
            self._order.append(cat)
        if username:
            for cat in _PREALLOCATED_AUTH_CATEGORIES:
                self._rows[cat] = _RowState(category=cat, phase=ProbePhase.AUTH, status="pending")
                self._order.append(cat)

    # ---- context management -------------------------------------------------

    def __enter__(self) -> "PostureProbeLiveView":
        if self._is_tty:
            try:
                # ``alt_screen=True`` is required even though every row is
                # pre-allocated. Rich Live with ``alt_screen=False`` is
                # fragile in inline mode: any refresh that gets interrupted
                # mid-write (asyncio yielding, terminal slow to ingest, a
                # second ``update()`` arriving inside a single refresh
                # tick at 10 FPS) leaves the partial render in the
                # operator's scrollback as a ghost panel. Alt-screen
                # isolates the entire live region inside a separate
                # terminal buffer that the kernel disposes of on exit —
                # ghost frames become topologically impossible. The
                # ``summary`` callback below re-prints the FINAL panel
                # state to the real scrollback so the operator still
                # has the matrix visible for review after the run.
                self._session = LiveSession(
                    self._render(),
                    config=LiveSessionConfig(refresh_per_second=10, alt_screen=True),
                    summary=self._print_final_panel,
                )
                self._session.__enter__()
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                self._session = None
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self._session is not None:
            try:
                self._session.update(self._render(), refresh=True)
            except Exception as upd_exc:  # noqa: BLE001
                telemetry.capture_exception(upd_exc)
                print_exception(exception=upd_exc)
            try:
                self._session.__exit__(exc_type, exc, tb)
            except Exception as ext_exc:  # noqa: BLE001
                telemetry.capture_exception(ext_exc)
                print_exception(exception=ext_exc)
            self._session = None

    def _print_final_panel(self, console: Any) -> None:
        """Re-print the final posture-probe panel to the operator's scrollback.

        Called by ``LiveSession`` after the alt-screen pops. Without this
        callback, switching to ``alt_screen=True`` (required to avoid
        ghost frames) would wipe the panel from scrollback on exit and
        the operator would only see the post-run summary. With it, the
        scrollback receives:

          1. The final panel (this callback) — full matrix of results.
          2. The standalone :func:`render_posture_probe_summary` panel
             that the lifecycle prints right after the widget exits —
             the executive-tier digest.

        That ordering matches the operator's reading flow: detail first,
        digest below.
        """
        try:
            console.print(self._render())
        except Exception:  # noqa: BLE001
            pass

    # ---- public API ---------------------------------------------------------

    def on_phase_start(self, phase: ProbePhase) -> None:
        """Mark a phase as active. Idempotent for a given ``phase``."""
        self._current_phase = phase
        self._refresh()

    def on_progress(
        self,
        category: ConstraintCategory,
        result: Optional[ProbeResult],
    ) -> None:
        """Wire this directly to ``ProbeProgressCallback``.

        Convention:
            ``(cat, None)``    → probe started
            ``(cat, result)``  → probe finished or skipped
        """
        try:
            row = self._rows.get(category)
            if row is None:
                row = _RowState(
                    category=category,
                    phase=self._current_phase or ProbePhase.UNAUTH,
                )
                self._rows[category] = row
                self._order.append(category)

            if result is None:
                row.status = "running"
                row.started_at = time.monotonic()
            else:
                row.result = result
                if result.skipped:
                    row.status = "skipped"
                elif result.succeeded:
                    row.status = "done"
                else:
                    row.status = "failed"
            self._refresh()
        except Exception as exc:  # noqa: BLE001
            # Widget MUST NOT raise into the probe engine.
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    @property
    def all_results(self) -> list[ProbeResult]:
        """All collected results in registration order (omits unfinished)."""
        return [r.result for r in self._rows.values() if r.result is not None]

    # ---- internals ----------------------------------------------------------

    def _refresh(self) -> None:
        if self._session is None:
            return
        try:
            self._session.update(self._render())
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    def _render(self) -> RenderableType:
        masked_domain = mark_sensitive(self.domain, "domain")

        intro = Text()
        intro.append(
            "Probing the domain to learn its security posture before running"
            " the engagement.",
            style="dim",
        )

        groups: list[RenderableType] = [intro, Text()]

        unauth_rows = [
            self._rows[c]
            for c in self._order
            if self._rows[c].phase is ProbePhase.UNAUTH
        ]
        auth_rows = [
            self._rows[c] for c in self._order if self._rows[c].phase is ProbePhase.AUTH
        ]

        # Phase 1 is ALWAYS rendered (rows are pre-allocated in __init__).
        # Conditional rendering based on whether rows exist would cause
        # the panel to grow between refreshes, triggering the Rich Live
        # header-stacking anti-pattern.
        groups.append(Text("Phase 1 — Anonymous probes", style="bold"))
        groups.append(self._render_rows(unauth_rows))
        groups.append(Text())

        # Phase 2 is rendered only when auth probes are configured (i.e.
        # the widget was constructed with a username). That decision is
        # made at __init__ time and never changes during the session, so
        # the line count is still stable across refreshes.
        if auth_rows:
            user_label = self.username or ""
            if user_label:
                phase_heading = Text()
                phase_heading.append("Phase 2 — Authenticated probes ", style="bold")
                phase_heading.append("(", style="dim")
                phase_heading.append(mark_sensitive(user_label, "user"))
                phase_heading.append("@", style="dim")
                phase_heading.append(masked_domain)
                phase_heading.append(")", style="dim")
            else:
                phase_heading = Text("Phase 2 — Authenticated probes", style="bold")
            groups.append(phase_heading)
            groups.append(self._render_rows(auth_rows))
            groups.append(Text())

        # Footer: X/Y physical probes complete · elapsed Y.Ys
        # "Complete" means reached a final state (done/skipped/failed) —
        # not "pending" (queued) and not "running" (in-flight).
        total = len(self._rows)
        complete = sum(
            1
            for r in self._rows.values()
            if r.status in ("done", "skipped", "failed")
        )
        elapsed = time.monotonic() - self._started
        footer = Text()
        footer.append(f"{complete}/{total} physical probes complete", style="dim")
        footer.append(" · elapsed ", style="dim")
        footer.append(f"{elapsed:0.1f}s", style="dim")
        groups.append(footer)

        title = f"[bold cyan]🔍  ADscan Posture Probe · {masked_domain}[/bold cyan]"
        return Panel(
            Padding(Group(*groups), (1, 2)),
            title=title,
            border_style="cyan",
            box=box.ROUNDED,
            expand=False,
        )

    def _render_rows(self, rows: list[_RowState]) -> RenderableType:
        table = Table.grid(padding=(0, 2))
        table.add_column(width=2)
        table.add_column(no_wrap=False)
        table.add_column(no_wrap=False, style="dim")
        # Rows are pre-allocated in ``__init__`` so this list is never
        # empty in practice. Defensive empty-state kept as a safety net
        # (would only trigger if a future caller bypassed pre-allocation).
        if not rows:
            table.add_row(Text("○", style="dim"), Text("queued…", style="dim"), "")
            return table
        for row in rows:
            icon = self._row_icon(row)
            label = _PROBE_CONSTRAINT_LABEL.get(row.category, row.category.value)
            hint = self._row_hint(row)
            table.add_row(icon, Text(label), Text(hint))
        return table

    @staticmethod
    def _row_icon(row: _RowState) -> Text:
        if row.status == "pending":
            # Open circle = "queued, not started". Visually distinct from
            # the ⏳ hourglass used for "actively running" so the operator
            # can tell at a glance which probes haven't begun yet.
            return Text("○", style="dim")
        if row.status == "running":
            return Text("⏳", style="dim")
        if row.status == "done":
            return Text("✓", style="green")
        if row.status == "skipped":
            return Text("⊘", style="dim")
        if row.status == "failed":
            return Text("✗", style="dim")
        return Text("○", style="dim")

    @staticmethod
    def _row_hint(row: _RowState) -> str:
        if row.status == "pending":
            return "queued…"
        if row.status == "running":
            return "checking…"
        result = row.result
        if result is None:
            return ""
        if row.status == "skipped":
            # Distinguish "freshness skip" (posture already known with HIGH
            # confidence from a prior cycle) from "dependency skip" (e.g.
            # CBT skipped because LDAPS unavailable). The freshness-skip
            # path emits a result with state≠UNKNOWN that was carried over
            # from posture; the dependency-skip path emits a synthetic
            # result with state=UNKNOWN and a human-readable ``message``
            # — show that message verbatim to avoid the confusing
            # "already known: unknown (low)" copy.
            try:
                if result.state is TriState.UNKNOWN and result.message:
                    return result.message
                state_label = result.state.value
                conf_label = result.confidence.value
            except Exception:  # noqa: BLE001
                return "already known"
            return f"already known: {state_label} ({conf_label})"
        if row.status == "failed":
            code = result.signal_code or "timeout"
            return f"could not probe ({code})"
        # done
        try:
            hint = _PROGRESS_HINTS_BY_CATEGORY_DONE.get((result.category, result.state))
        except Exception:  # noqa: BLE001
            hint = None
        if hint:
            return hint
        # Fallback for KERBEROS_AES_ONLY (no probe runs in widget directly,
        # but if a result is forwarded just show the bare state).
        try:
            return f"{result.state.value}"
        except Exception:  # noqa: BLE001
            return ""


# --------------------------------------------------------------------------- #
# Summary panel
# --------------------------------------------------------------------------- #


def _format_elapsed(elapsed_s: float) -> str:
    """Format elapsed seconds for display.

    Convention:
        ``< 0.05s`` → ``"<0.1s"``
        otherwise   → ``"X.Xs"``
    """
    if elapsed_s < 0.05:
        return "<0.1s"
    return f"{elapsed_s:0.1f}s"


def _format_age(delta: timedelta) -> str:
    """Render a timedelta as 'N hours/minutes/seconds ago' style label."""
    secs = int(delta.total_seconds())
    if secs < 60:
        return f"{max(secs, 0)} seconds ago"
    if secs < 3600:
        return f"{secs // 60} minutes ago"
    hours = secs // 3600
    if hours < 48:
        return f"{hours} hours ago"
    return f"{secs // 86400} days ago"


def _format_remaining(delta: timedelta) -> str:
    """Render a remaining timedelta as 'Nh' / 'Nm' / '0' label."""
    secs = int(delta.total_seconds())
    if secs <= 0:
        return "expired"
    if secs < 3600:
        return f"{max(secs // 60, 1)}m"
    return f"{secs // 3600}h"


def _categories_newly_hardened(
    *,
    current: Optional[DomainPosture],
    prior: Optional[DomainPosture],
) -> set[ConstraintCategory]:
    """Return the set of categories that became HIGH-confidence hardening.

    A category is considered "newly hardened" when:

    - The current posture records it in a hardening (category, state) pair
      from :data:`_PROBE_HARDENING_LABEL` at HIGH confidence, AND
    - The prior posture either lacked that hardening pair entirely, recorded
      a different state, or recorded the same state but at LOW/MEDIUM
      confidence (the planner only respected HIGH confidence anyway, so a
      confidence upgrade to HIGH counts as a new discovery).

    Used to render the ⚡ NEW qualifier in the summary panel. When either
    ``current`` or ``prior`` is ``None`` the set is empty (single-call mode).
    """
    if current is None or prior is None:
        return set()
    out: set[ConstraintCategory] = set()
    for category, state in _PROBE_HARDENING_LABEL:
        cur = current.get(category)
        if cur.state != state:
            continue
        if cur.confidence != SignalConfidence.HIGH:
            continue
        prev = prior.get(category)
        prev_already_hardened_high = (
            prev.state == state and prev.confidence == SignalConfidence.HIGH
        )
        if not prev_already_hardened_high:
            out.add(category)
    return out


def render_posture_probe_summary(
    *,
    results: list[ProbeResult],
    domain: str,
    dc_ip: str,
    elapsed_s: float,
    posture: Optional[DomainPosture] = None,
    prior_posture: Optional[DomainPosture] = None,
) -> Panel:
    """Build the post-probe summary panel.

    Three render paths based on ``results``:

    - All probes were skipped (cached) → cached summary, dim-cyan border,
      ``(cached)`` qualifier in title.
    - At least one hardening control detected → detected summary, green border.
    - All probes ran but no hardening found → permissive summary, dim border.

    When ``prior_posture`` is provided AND the current posture has hardening
    controls that were not present at HIGH confidence in ``prior_posture``,
    those are tagged ⚡ NEW. Controls present in both are tagged
    ``· already known``. When ``prior_posture`` is ``None`` (first probe call
    in a session, or standalone subcommand) all hardening rows render without
    qualifier, preserving the historical behaviour.

    Args:
        results: Every ``ProbeResult`` collected during the probe phase.
        domain: Target domain (rendered through ``mark_sensitive``).
        dc_ip: DC IP — kept for future use; not currently rendered.
        elapsed_s: Total elapsed wall-clock seconds for the probe phase.
        posture: Optional posture snapshot used by the cached path to read
            constraint timestamps for "Last refresh" / "TTL remaining" lines.
            Also used as the "merged view" when computing the headline /
            framing copy for the detected path.
        prior_posture: Optional posture snapshot taken BEFORE the probe ran.
            When provided, the detected path renders unified rows showing
            both newly-discovered and previously-known hardening.

    Returns:
        A :class:`rich.panel.Panel` ready to print.
    """
    masked_domain = mark_sensitive(domain, "domain")
    elapsed_label = _format_elapsed(elapsed_s)
    total = len(results)
    _ = dc_ip  # Reserved for future expansion (per-DC labelling).

    # Path selection.
    all_skipped = total > 0 and all(r.skipped for r in results)
    if all_skipped:
        return _render_cached_summary(
            results=results,
            masked_domain=masked_domain,
            domain=domain,
            posture=posture,
        )

    detected_results: list[ProbeResult] = []
    permissive_results: list[ProbeResult] = []
    for result in results:
        if not result.succeeded or result.skipped:
            continue
        if (result.category, result.state) in _PROBE_HARDENING_LABEL:
            detected_results.append(result)
        elif (result.category, result.state) in _PROBE_PERMISSIVE_LABEL:
            permissive_results.append(result)

    # Build the merged hardening view: previously-known hardening categories
    # + this phase's freshly-detected ones. This keeps the panel cohesive
    # across the unauth→auth transition.
    merged_rows: list[tuple[ConstraintCategory, TriState, SignalConfidence]] = []
    seen: set[ConstraintCategory] = set()
    for r in detected_results:
        merged_rows.append((r.category, r.state, r.confidence))
        seen.add(r.category)

    if prior_posture is not None:
        for category, state in _PROBE_HARDENING_LABEL:
            if category in seen:
                continue
            cur = posture.get(category) if posture is not None else None
            if cur is None:
                # Fall back to prior when no current snapshot was provided.
                cur = prior_posture.get(category)
            if cur.state == state and cur.confidence == SignalConfidence.HIGH:
                merged_rows.append((category, state, cur.confidence))
                seen.add(category)

    if merged_rows:
        return _render_detected_summary(
            results=results,
            merged_rows=merged_rows,
            permissive=permissive_results,
            masked_domain=masked_domain,
            elapsed_label=elapsed_label,
            newly_hardened=_categories_newly_hardened(
                current=posture, prior=prior_posture
            ),
            merged_mode=prior_posture is not None,
        )
    return _render_permissive_summary(
        masked_domain=masked_domain,
        total=total,
        elapsed_label=elapsed_label,
    )


def _summary_title(masked_domain: str, *, cached: bool = False) -> str:
    qualifier = " (cached)" if cached else ""
    return (
        f"[bold cyan]🛡️  Posture Probe Summary · {masked_domain}{qualifier}[/bold cyan]"
        if not cached
        else f"[bold cyan]🛡️  Posture · {masked_domain} (cached)[/bold cyan]"
    )


def _render_detected_summary(
    *,
    results: list[ProbeResult],
    merged_rows: list[tuple[ConstraintCategory, TriState, SignalConfidence]],
    permissive: list[ProbeResult],
    masked_domain: str,
    elapsed_label: str,
    newly_hardened: set[ConstraintCategory],
    merged_mode: bool,
) -> Panel:
    pieces: list[RenderableType] = []

    headline_template = (
        _HEADLINE_DETECTED_MERGED if merged_mode else _HEADLINE_DETECTED_NEW
    )
    # Headline copy is rendered piece-by-piece so the count fragments keep
    # their bold/green styling instead of falling back to plain text.
    _ = headline_template  # locked-copy reference, see module constants.
    header = Text()
    header.append(f"{len(results)} probes complete", style="bold")
    header.append(" · ", style="dim")
    if merged_mode:
        header.append(
            f"{len(merged_rows)} hardening controls now confirmed",
            style="bold green",
        )
    else:
        header.append(
            f"{len(merged_rows)} hardening controls detected",
            style="bold green",
        )
    header.append(" · ", style="dim")
    header.append(elapsed_label, style="dim")
    pieces.append(header)
    pieces.append(Text())

    pieces.append(Text("Detected hardening", style="bold"))
    rows_sorted = sorted(merged_rows, key=lambda r: _hardening_sort_key(r[0]))
    table = Table.grid(padding=(0, 2))
    table.add_column(width=2)
    table.add_column(no_wrap=False)
    table.add_column(style="dim")
    table.add_column()
    for category, state, confidence in rows_sorted:
        label = _PROBE_HARDENING_LABEL.get((category, state), category.value)
        if merged_mode:
            if category in newly_hardened:
                qualifier_text = Text(_QUALIFIER_NEW, style="bold green")
            else:
                qualifier_text = Text(_QUALIFIER_KNOWN, style="dim")
        else:
            qualifier_text = Text("")
        table.add_row(
            Text("✓", style="green"),
            Text(label),
            Text(confidence.value),
            qualifier_text,
        )
    pieces.append(table)

    if permissive:
        pieces.append(Text())
        pieces.append(Text("Permissive (no hardening detected)", style="bold yellow"))
        perm_table = Table.grid(padding=(0, 2))
        perm_table.add_column(width=2)
        perm_table.add_column(no_wrap=False)
        for r in permissive:
            label = _PROBE_PERMISSIVE_LABEL.get((r.category, r.state), r.category.value)
            perm_table.add_row(Text("✗", style="dim"), Text(label, style="dim"))
        pieces.append(perm_table)

    pieces.append(Text())
    adapt_line = Text()
    adapt_line.append("⚡ ", style="bold green")
    framing = _FRAMING_DETECTED_MERGED if merged_mode else _FRAMING_DETECTED_NEW
    adapt_line.append(framing, style="bold green")
    pieces.append(adapt_line)

    pieces.append(Text())
    pieces.append(Text("Re-probe automatically in 24h, or anytime via:", style="dim"))
    cmd_line = Text()
    cmd_line.append("  ")
    cmd_line.append(
        f"adscan posture probe {masked_domain.plain if hasattr(masked_domain, 'plain') else masked_domain}",
        style="bold",
    )
    pieces.append(cmd_line)

    return Panel(
        Padding(Group(*pieces), (1, 2)),
        title=_summary_title(masked_domain),
        border_style="green",
        box=box.ROUNDED,
        expand=False,
    )


def _render_permissive_summary(
    *,
    masked_domain: str,
    total: int,
    elapsed_label: str,
) -> Panel:
    pieces: list[RenderableType] = []
    header = Text()
    header.append(f"{total} probes complete", style="bold")
    header.append(" · ", style="dim")
    header.append("0 hardening controls detected", style="bold")
    header.append(" · ", style="dim")
    header.append(elapsed_label, style="dim")
    pieces.append(header)
    pieces.append(Text())

    pieces.append(
        Text(
            "No defensive hardening detected on this domain.",
            style="dim",
        )
    )
    pieces.append(
        Text(
            "The environment is permissive across all probed controls.",
            style="dim",
        )
    )
    pieces.append(Text())
    pieces.append(
        Text(
            "ADscan will use the conservative authentication chain",
            style="dim",
        )
    )
    pieces.append(Text("(no posture-driven pruning).", style="dim"))

    return Panel(
        Padding(Group(*pieces), (1, 2)),
        title=_summary_title(masked_domain),
        border_style="dim",
        box=box.ROUNDED,
        expand=False,
    )


def _render_cached_summary(
    *,
    results: list[ProbeResult],
    masked_domain: str,
    domain: str,
    posture: Optional[DomainPosture],
) -> Panel:
    pieces: list[RenderableType] = []

    age_text = "unknown"
    ttl_text = "unknown"
    if posture is not None:
        latest_age: Optional[timedelta] = None
        latest_ttl: Optional[timedelta] = None
        for r in results:
            constraint = posture.get(r.category)
            if constraint.age is not None:
                if latest_age is None or constraint.age < latest_age:
                    latest_age = constraint.age
            if constraint.ttl_remaining is not None:
                if latest_ttl is None or constraint.ttl_remaining < latest_ttl:
                    latest_ttl = constraint.ttl_remaining
        if latest_age is not None:
            age_text = _format_age(latest_age)
        if latest_ttl is not None:
            ttl_text = _format_remaining(latest_ttl)

    pieces.append(Text("Posture already known from a previous probe.", style="dim"))
    refresh_line = Text()
    refresh_line.append("Last refresh: ", style="dim")
    refresh_line.append(age_text, style="bold")
    refresh_line.append(" · TTL remaining: ", style="dim")
    refresh_line.append(ttl_text, style="bold")
    pieces.append(refresh_line)

    pieces.append(Text())
    show_line = Text()
    show_line.append("View full state:  ", style="dim")
    show_line.append(f"adscan posture show {domain}", style="bold")
    pieces.append(show_line)
    force_line = Text()
    force_line.append("Force re-probe:   ", style="dim")
    force_line.append(f"adscan posture probe {domain}", style="bold")
    pieces.append(force_line)

    return Panel(
        Padding(Group(*pieces), (1, 2)),
        title=_summary_title(masked_domain, cached=True),
        border_style="dim cyan",
        box=box.ROUNDED,
        expand=False,
    )


def _hardening_sort_key(category: ConstraintCategory) -> int:
    try:
        return _HARDENING_SORT_ORDER.index(category)
    except ValueError:
        return len(_HARDENING_SORT_ORDER)


__all__ = [
    "PostureProbeLiveView",
    "render_posture_probe_summary",
]
