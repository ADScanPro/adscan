"""Smart-resume front door for ``start_auth``.

When an operator re-launches ``start_auth`` (interactive, no positional args) in a
workspace that already holds results for one or more scanned domains, this module
offers a single clean selector: continue an already-initialized domain (reusing
the stored credential, zero preamble) or scan a new one.

The "continue" path hands off to ``enum_domain_auth``'s machinery
(``do_enum_domain_auth`` → ``_run_enum_domain_auth``), which reads the stored
``username`` / ``pdc`` straight from ``domains_data`` and lands directly on the
consolidated workspace-resume panel — no credential re-prompt, no PDC/DNS/preflight
wizard, no live re-verify.

Design constraints:
    * Pure filesystem reads only (``inspect_workspace``). Never touches the
      network — no extra bind, so it is ``badPwdCount``-safe.
    * All prompts route through the centralized helper
      ``questionary_select_index`` so they auto-resolve to a safe default under
      ``adscan ci`` / non-interactive mode instead of hanging.
    * Every principal / domain rendered is wrapped in ``mark_sensitive`` so the
      terminal shows cleartext while the session recording stays sanitized.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Union

from adscan_core.rich_output import (
    mark_sensitive,
    print_info_debug,
    print_panel,
    questionary_checkbox_values,
    questionary_select_index,
)
from adscan_core.theme import ADSCAN_PRIMARY, COLOR_STEEL
from adscan_internal.services.workspace_resume import (
    WorkspaceSnapshot,
    inspect_workspace,
)

# House-style glyphs (lead every state badge so meaning survives NO_COLOR).
_GLYPH_ACTIVE = "●"  # ● active / initialized

# Sentinel returned by the selectors when the operator wants a brand-new scan.
NEW_SCAN: Literal["new"] = "new"


@dataclass(frozen=True)
class ResumableDomain:
    """A domain in the current workspace that can be continued without re-typing.

    ``username`` / ``pdc`` come straight from ``domains_data[domain]``; ``snapshot``
    is the read-only filesystem view driving the summary line.

    ``incomplete_resume_phase`` is the human title of the phase a crash-interrupted
    scan will re-enter at (``None`` when the last run finished cleanly). It is the
    STRONGER resume signal — the front door surfaces it as "continue from <phase>".
    """

    domain: str
    username: str
    pdc: str
    snapshot: WorkspaceSnapshot
    incomplete_resume_phase: str | None = None


@dataclass(frozen=True)
class FrontdoorChoice:
    """The operator's front-door selection for a resumable domain.

    ``mode`` distinguishes the two ways an operator can pick a resumable domain:

    * ``"continue"`` — the primary one-click resume row (the default). The caller
      reuses the stored credential and predecides ``RESUME`` so the downstream
      workspace-action panel and phase-scope prompt are both skipped: a single
      front-door prompt, nothing else.
    * ``"other"`` — the deliberate "other actions…" opt-in that re-exposes the
      full alternative surface (Refresh / Replay / Inspect, and entering a
      different credential). The caller hands off WITHOUT predeciding, so today's
      genuine four-action panel renders unchanged.
    """

    domain: ResumableDomain
    mode: Literal["continue", "other"]


def _is_usable(value: Any) -> bool:
    """Return True when a stored field is present and not the ``N/A`` placeholder."""
    text = str(value or "").strip()
    return bool(text) and text.upper() != "N/A"


def detect_resumable_domains(shell: Any) -> list[ResumableDomain]:
    """Return the workspace's resumable domains, most-recently-scanned first.

    Pure read. A domain qualifies when it has collected results
    (``has_attack_graph`` or ``phase1_complete``) AND a usable stored
    ``username`` + ``pdc`` (so the continue path can reuse the credential with
    zero preamble). Fresh / entry-vectors-only / credential-less domains are
    excluded. Never raises.
    """
    domains_data = getattr(shell, "domains_data", {}) or {}
    resumable: list[ResumableDomain] = []
    for domain, data in domains_data.items():
        if not isinstance(data, dict):
            continue
        username = data.get("username")
        pdc = data.get("pdc")
        if not _is_usable(username) or not _is_usable(pdc):
            continue
        try:
            snapshot = inspect_workspace(shell, domain)
        except Exception:  # noqa: BLE001 - pure read must never break the flow
            continue
        if not (snapshot.has_attack_graph or snapshot.phase1_complete):
            continue
        # An entry-vectors-only graph (synthetic unauthenticated nodes:
        # ASREPRoasting / anonymous bind) is not an authenticated resume target —
        # the resume panel treats it as REFRESH. Exclude it unless phase 1 actually
        # completed against the domain.
        if snapshot.domain_auth == "unauth" and not snapshot.phase1_complete:
            continue
        resumable.append(
            ResumableDomain(
                domain=str(domain),
                username=str(username).strip(),
                pdc=str(pdc).strip(),
                snapshot=snapshot,
                incomplete_resume_phase=_incomplete_resume_phase(shell, str(domain)),
            )
        )
    # Incomplete (crash-interrupted) scans first — they carry the stronger
    # "continue from where it stopped" signal. Within each group, most recent
    # first (ISO-8601 timestamps sort chronologically as strings; a missing
    # timestamp sorts last under reverse ordering).
    resumable.sort(
        key=lambda item: (
            item.incomplete_resume_phase is not None,
            item.snapshot.last_run_at or "",
        ),
        reverse=True,
    )
    return resumable


def _incomplete_resume_phase(shell: Any, domain: str) -> str | None:
    """Return the human phase title a crash-interrupted scan will resume from.

    Reads the persisted ``scan_progress`` checkpoint. ``None`` when the last run
    finished cleanly (or there is no checkpoint) — the common case. Never raises;
    a missing / malformed record degrades to ``None`` (no hint, plain resume).
    """
    try:
        from adscan_internal.services import scan_progress as sp

        if not sp.is_incomplete(shell, domain):
            return None
        record = sp.read_scan_progress(shell, domain)
        scan_type = str(record.get("scan_type") or getattr(shell, "type", "") or "audit")
        phase_id = sp.resume_phase_id(shell, domain, scan_type)
        if not phase_id:
            return None
        from adscan_internal.services.scan_phases import get_phase

        phase = get_phase(phase_id)
        return phase.title if phase is not None else None
    except Exception:  # noqa: BLE001 - a pure read must never break the flow
        return None


def prompt_frontdoor_choice(
    shell: Any, resumable: list[ResumableDomain]
) -> Union[Literal["new"], FrontdoorChoice]:
    """Render the front-door summary panel and ask how to proceed.

    Progressive disclosure: each resumable domain contributes a dominant primary
    "Continue" row (the one-click resume) plus a subordinate "other actions…" row
    that opts into the full Refresh / Replay / Inspect / different-credential
    surface. The primary row of the most recent domain is index 0 — the default
    and the non-interactive resolution — so the common case is a single click.

    Returns a :class:`FrontdoorChoice` carrying the selected domain and the mode
    (``"continue"`` or ``"other"``), or :data:`NEW_SCAN` when the operator picks
    "Scan a new domain" (or the prompt is cancelled).
    """
    if not resumable:
        return NEW_SCAN

    _render_frontdoor_panel(resumable)

    options: list[str] = []
    actions: list[Union[Literal["new"], FrontdoorChoice]] = []
    for item in resumable:
        age = item.snapshot.last_collection_age_human
        if item.incomplete_resume_phase:
            tail = f"  ·  continue from {item.incomplete_resume_phase}"
        else:
            tail = f"  ·  {age}"
        # Primary, one-click resume row — visually dominant, the default choice.
        options.append(
            f"Continue {mark_sensitive(item.domain, 'domain')}"
            f"  ·  stored credential {mark_sensitive(item.username, 'user')}"
            f"{tail}"
        )
        actions.append(FrontdoorChoice(item, "continue"))
        # Subordinate opt-in — indented so it reads as a secondary action, never
        # the default. This is the ONLY place the Refresh / Replay / Inspect /
        # different-credential alternatives live for a Continue operator.
        options.append(
            f"   {mark_sensitive(item.domain, 'domain')} — other actions "
            f"(refresh · replay · inspect · different credential)"
        )
        actions.append(FrontdoorChoice(item, "other"))
    options.append("Scan a new domain")
    actions.append(NEW_SCAN)

    idx = questionary_select_index(
        title="How do you want to proceed?",
        options=options,
        default_idx=0,
        shell=shell,
    )
    if idx is None or idx < 0 or idx >= len(actions):
        return NEW_SCAN
    return actions[idx]


def prompt_credential_reuse(
    shell: Any, chosen: ResumableDomain
) -> Union[Literal["reuse"], tuple[str, str]]:
    """Ask whether to reuse the stored credential or enter a different one.

    Returns ``"reuse"`` to continue with the stored credential (default, index 0,
    and the non-interactive resolution), or ``(username, secret)`` for a fresh
    credential entered by the operator. A cancelled credential entry degrades to
    ``"reuse"`` (non-destructive: lands on the resume panel with the stored cred).
    """
    options = [
        f"Reuse the stored credential  ·  "
        f"{mark_sensitive(chosen.username, 'user')}   (recommended)",
        "Use a different credential",
    ]
    idx = questionary_select_index(
        title=f"Credential for {mark_sensitive(chosen.domain, 'domain')}",
        options=options,
        default_idx=0,
        shell=shell,
    )
    if idx != 1:
        return "reuse"

    # "Use a different credential" — this IS an unverified credential, so the
    # caller routes it through the normal machinery (target wizard / DNS /
    # preflight / live verify). Prompt via the existing SSOT helper.
    from adscan_internal.cli.start import _prompt_auth_credentials_interactive

    cred = _prompt_auth_credentials_interactive(shell)
    if cred is None:
        print_info_debug(
            "[frontdoor] different-credential prompt cancelled; "
            "falling back to reuse of the stored credential."
        )
        return "reuse"
    return cred


def maybe_prompt_phase_preset(shell: Any) -> None:
    """Optional power-user phase preset, offered at the resume point.

    Interactive only, default OFF ("Run all phases"). When the operator opts into
    a subset, persist a session-scoped enabled set of OPTIONAL phase ids on
    ``shell._phase_preset_enabled`` (a ``shell._attr``, never ``domains_data`` —
    it holds a ``set`` which is not JSON-serializable), consumed by
    ``phase_is_enabled``. No-op non-interactively: leaves the preset untouched so
    ``adscan ci`` and trust-pivot enumeration run every phase.
    """
    from adscan_internal.interaction import is_non_interactive

    if is_non_interactive(shell):
        return

    scope_idx = questionary_select_index(
        title="Phase scope for this run",
        options=["Run all phases", "Run only selected phases…"],
        default_idx=0,
        shell=shell,
    )
    if scope_idx != 1:
        # "Run all phases" (or a cancelled prompt) — clear any prior preset so
        # this run is unrestricted (identical to today's behaviour).
        _set_phase_preset(shell, None)
        return

    from adscan_internal.services.scan_phases import SCAN_PHASES

    # Only OPTIONAL phases can be toggled; mandatory phases (preflight + the
    # collection backbone) always run and are never presented as toggles.
    optional_phases = [phase for phase in SCAN_PHASES if getattr(phase, "optional", False)]
    if not optional_phases:
        _set_phase_preset(shell, None)
        return

    labels = [phase.title for phase in optional_phases]
    selected_labels = questionary_checkbox_values(
        title="Select the phases to run",
        options=labels,
        default_values=labels,  # all pre-checked — deselect to skip
        shell=shell,
    )
    if selected_labels is None:
        # Cancelled — do not restrict this run.
        _set_phase_preset(shell, None)
        return

    selected = set(selected_labels)
    enabled_ids = {phase.phase_id for phase in optional_phases if phase.title in selected}
    _set_phase_preset(shell, enabled_ids)


def _set_phase_preset(shell: Any, enabled_ids: "set[str] | None") -> None:
    """Persist the session phase preset on the shell (best-effort)."""
    try:
        shell._phase_preset_enabled = enabled_ids
    except Exception:  # noqa: BLE001 - a best-effort convenience must never break the scan
        pass


def _render_frontdoor_panel(resumable: list[ResumableDomain]) -> None:
    """Render the summary panel listing every resumable domain."""
    from rich.console import Group
    from rich.table import Table
    from rich.text import Text

    intro = Text(
        "This workspace already holds results for scanned domains. Pick up where "
        "you left off (no re-typing credentials) or start a new domain.",
    )

    listing = Table.grid(padding=(0, 1))
    listing.add_column()
    for item in resumable:
        snap = item.snapshot
        if item.incomplete_resume_phase:
            summary = f"incomplete · continue from {item.incomplete_resume_phase}"
        elif snap.has_attack_graph:
            summary = (
                f"{snap.domain_auth} · {snap.node_count} nodes · "
                f"{snap.edge_count} edges"
            )
        else:
            summary = "phase 1 complete"
        head = (
            f"[bold {COLOR_STEEL}]{_GLYPH_ACTIVE}[/] "
            f"[bold]{mark_sensitive(item.domain, 'domain')}[/]"
            f"   [dim]{summary}   {snap.last_collection_age_human}[/]"
        )
        detail = f"    [dim]credential[/]  {mark_sensitive(item.username, 'user')}"
        listing.add_row(head)
        listing.add_row(detail)

    body = Group(
        intro,
        Text(""),
        Text("Initialized domains", style="bold"),
        listing,
    )

    print_panel(
        body,
        title=f"[bold {ADSCAN_PRIMARY}]\U0001f504  Resume or start fresh[/]",
        title_align="left",
        border_style=ADSCAN_PRIMARY,
        padding=(1, 2),
    )
