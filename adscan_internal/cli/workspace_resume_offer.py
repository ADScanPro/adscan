"""Auto-offer to resume an interrupted scan on workspace load.

When an operator opens a workspace whose last scan was interrupted mid-phase
(Ctrl+C, a lost connection, a killed container), ADscan should not make them
remember to re-type ``start_auth`` to pick up where they left off. This module
is invoked from the single workspace-load funnel (``load_workspace_data``) and,
right after the load has populated ``domains_data`` / ``scan_progress``, offers
to continue any incomplete scan from its stopped phase.

Design:
    * Composes with the ``start_auth`` front door — it reuses
      ``detect_resumable_domains`` (the SSOT detection + the "continue from
      <phase>" label) and simply filters to the domains whose persisted
      ``scan_progress`` is still ``running`` (the interrupted ones). No parallel
      detection logic.
    * The "Resume" choice routes into the SAME seam the front door uses
      (``finalize_domain_context`` + ``do_enum_domain_auth``), so the scan lands
      on the consolidated resume panel and ``run_enumeration`` skips the phases
      already marked complete. No extra bind is issued (the stored credential is
      reused), so the offer is ``badPwdCount``-safe.
    * Interactive only. Under ``adscan ci`` / non-interactive the whole offer is
      gated off (that flow drives its own scan) so it never blocks.
    * A per-session guard on the shell (``_resume_offer_seen``) makes the offer
      idempotent: a domain is presented at most once per session, no matter how
      many times ``load_workspace_data`` runs.
    * Every domain rendered is wrapped in ``mark_sensitive`` — cleartext on the
      terminal, sanitized in the session recording.
"""

from __future__ import annotations

from typing import Any

from adscan_core.rich_output import (
    mark_sensitive,
    print_info_debug,
    print_panel,
    questionary_select_index,
)
from adscan_core.theme import ADSCAN_PRIMARY, COLOR_STEEL
from adscan_internal.interaction import is_non_interactive
from adscan_internal.services.scan_progress import reset_scan_progress

# Runtime-only shell attribute holding the set of domains already offered this
# session. A plain shell attribute (NOT ``domains_data``) — it is a ``set`` and
# must never reach ``save_workspace_data`` (JSON serialization).
_SEEN_ATTR = "_resume_offer_seen"

# House-style glyph (leads the badge so meaning survives NO_COLOR).
_GLYPH_INCOMPLETE = "◐"  # ◐ half-filled: an interrupted, resumable scan


def _seen_set(shell: Any) -> set[str]:
    """Return the per-session set of already-offered domains (created on first use)."""
    seen = getattr(shell, _SEEN_ATTR, None)
    if not isinstance(seen, set):
        seen = set()
        try:
            setattr(shell, _SEEN_ATTR, seen)
        except Exception:  # noqa: BLE001 - a best-effort guard must never break the load
            pass
    return seen


def detect_incomplete_resumable_domains(shell: Any) -> list[Any]:
    """Return only the resumable domains whose last scan was INTERRUPTED.

    Thin filter over the front door's ``detect_resumable_domains`` (the SSOT):
    keep the domains that carry an ``incomplete_resume_phase`` (persisted
    ``scan_progress.status == "running"`` plus a resolvable resume phase).
    Complete / absent-record domains are dropped. Never raises.
    """
    try:
        from adscan_internal.cli.start_resume_frontdoor import detect_resumable_domains

        return [
            item
            for item in detect_resumable_domains(shell)
            if getattr(item, "incomplete_resume_phase", None)
        ]
    except Exception:  # noqa: BLE001 - a pure read must never break the load
        return []


def maybe_offer_incomplete_scan_resume(shell: Any) -> bool:
    """Offer to resume an interrupted scan detected on workspace load.

    Returns ``True`` when a scan was launched (resume or fresh), ``False`` on a
    clean no-op (nothing incomplete, non-interactive, already offered, "Not now").
    Never raises — a failure degrades to "no offer".
    """
    try:
        candidates = detect_incomplete_resumable_domains(shell)
    except Exception:  # noqa: BLE001
        return False
    if not candidates:
        return False

    # Interactive only: under ``adscan ci`` / non-interactive the calling flow
    # drives its own scan, so the offer is gated off entirely and never blocks.
    if is_non_interactive(shell):
        return False

    seen = _seen_set(shell)
    for candidate in candidates:
        domain = candidate.domain
        if domain in seen:
            continue
        # Mark seen up front: whatever the operator chooses, we do not re-nag for
        # this domain again this session.
        seen.add(domain)

        _render_offer_panel(candidate)
        idx = questionary_select_index(
            title=f"Incomplete scan for {mark_sensitive(domain, 'domain')}",
            options=[
                f"Resume from {candidate.incomplete_resume_phase}",
                "Start a fresh scan",
                "Not now",
            ],
            default_idx=0,
            shell=shell,
        )

        if idx == 1:
            _launch_fresh(shell, candidate)
            return True
        if idx in (None, 2):
            # "Not now" (or a cancelled prompt) — drop to the REPL, keep looking
            # at the next incomplete domain (if any).
            print_info_debug(
                f"[resume-offer] operator deferred resume for {mark_sensitive(domain, 'domain')}."
            )
            continue
        # Default / index 0 — resume from the stopped phase.
        _launch_resume(shell, candidate)
        return True

    return False


def _launch_resume(shell: Any, candidate: Any) -> None:
    """Continue the interrupted scan from its stopped phase (checkpoint preserved).

    Mirrors the ``start_auth`` front-door "reuse" seam: finalize the DNS/context
    for the stored PDC, then hand off to ``do_enum_domain_auth`` which reads the
    stored credential and lands on the resume panel. ``run_enumeration`` skips
    already-complete phases via ``phase_already_complete``.
    """
    from adscan_internal.cli.dns import finalize_domain_context
    from adscan_internal.cli.workspace_resume_panel import WorkspaceAction

    finalize_domain_context(
        shell,
        domain=candidate.domain,
        pdc_ip=candidate.pdc,
        interactive=True,
        make_active=True,
    )
    # One-shot handoff: the operator already chose "Resume" in the offer above,
    # so the workspace-action panel and the phase-scope prompt that
    # ``_run_enum_domain_auth`` would otherwise raise are the SAME decision asked
    # twice. Pre-decide RESUME on the shell (runtime-only, never persisted, never
    # in ``domains_data``). ``_run_enum_domain_auth`` reads-and-clears it so it
    # fires exactly once — a later direct ``enum_domain_auth`` / ``start_auth``
    # in the same session still gets the genuine four-action panel. Set here ONLY
    # (never in ``_launch_fresh``, which is REFRESH-shaped and wants the panel).
    try:
        shell._resume_action_predecided = WorkspaceAction.RESUME
    except Exception:  # noqa: BLE001 - best-effort; a set failure just re-shows the panel
        pass
    shell.do_enum_domain_auth(candidate.domain)


def _launch_fresh(shell: Any, candidate: Any) -> None:
    """Start a fresh scan of the domain: clear the checkpoint so every phase runs."""
    reset_scan_progress(shell, candidate.domain)
    from adscan_internal.cli.dns import finalize_domain_context

    finalize_domain_context(
        shell,
        domain=candidate.domain,
        pdc_ip=candidate.pdc,
        interactive=True,
        make_active=True,
    )
    shell.do_enum_domain_auth(candidate.domain)


def _render_offer_panel(candidate: Any) -> None:
    """Render the premium offer panel for one interrupted scan.

    Doubles as the resume orientation: alongside the stopped-at phase and the
    stored credential, it surfaces the current workspace state (collection size,
    attack paths, captured credentials) read off ``candidate.snapshot``. Because
    the operator's "Resume" choice is pre-decided downstream (``_launch_resume``
    → ``_run_enum_domain_auth``), this is the SINGLE panel shown before the scan
    resumes — no redundant workspace-action panel follows.
    """
    from rich.console import Group
    from rich.table import Table
    from rich.text import Text

    domain = mark_sensitive(candidate.domain, "domain")
    phase = candidate.incomplete_resume_phase
    snapshot = candidate.snapshot
    age = getattr(snapshot, "last_collection_age_human", "") or ""

    head = Text.from_markup(
        f"[bold {COLOR_STEEL}]{_GLYPH_INCOMPLETE}[/]  "
        f"A previous scan of [bold]{domain}[/] was interrupted"
        + (f" [dim]({age})[/]" if age else "")
    )

    detail = Table.grid(padding=(0, 2))
    detail.add_column(style="dim", justify="left")
    detail.add_column()
    detail.add_row("stopped at", f"[bold]{phase}[/]")
    detail.add_row("credential", mark_sensitive(candidate.username, "user"))
    # Orientation counts — only rows we actually have, so a not-yet-collected
    # interrupted scan stays terse instead of padding with "none" placeholders.
    if getattr(snapshot, "has_attack_graph", False):
        detail.add_row(
            "collected",
            f"[green]✓[/] {snapshot.node_count} nodes · {snapshot.edge_count} edges",
        )
    if getattr(snapshot, "has_attack_paths", False):
        detail.add_row("attack paths", "[green]✓[/] materialised")
    if getattr(snapshot, "credential_count", 0) > 0:
        detail.add_row("captured", f"[green]✓[/] {snapshot.credential_count} credentials")

    hint = Text(
        "Resume continues from that phase with the stored credential. "
        "The phases already finished are skipped.",
        style="dim",
    )

    print_panel(
        Group(head, Text(""), detail, Text(""), hint),
        title=f"[bold {ADSCAN_PRIMARY}]Resume interrupted scan[/]",
        title_align="left",
        border_style=ADSCAN_PRIMARY,
        padding=(1, 2),
    )


__all__ = [
    "detect_incomplete_resumable_domains",
    "maybe_offer_incomplete_scan_resume",
]
