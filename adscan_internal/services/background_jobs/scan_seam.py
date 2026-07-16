"""Scan-flow seam: the single launch-decision function for poisoning jobs.

``maybe_launch_poisoning_job`` is the SSOT for whether a poisoning job starts.
It is called at the primary-scan entry points (unauth + auth). The
``(kind, scope)`` idempotency guard makes a repeat call a no-op, so the same
function is safe to call from multiple entry points without double-launching —
and it must NOT be called from the trust-enumeration loop (which creates
secondary subworkspaces but is not a primary scan entry).
"""
from __future__ import annotations

import os
from typing import Any, Optional

from adscan_core import telemetry
from adscan_core.rich_output import (
    confirm_ask,
    print_info,
    print_instruction,
)
from adscan_internal.interaction import is_non_interactive
from adscan_internal.services.background_jobs.poisoning_job import PoisoningJobRuntime
from adscan_internal.services.background_jobs.registry import (
    BackgroundJob,
    get_or_create_registry,
)
from adscan_internal.services.background_jobs.results_bus import (
    make_registry_result_sink,
)

_CI_OPT_OUT_ENV = "ADSCAN_NO_POISONING"
_POISONING_KIND = "poisoning"


def _ci_opt_out() -> bool:
    """True when the non-interactive opt-OUT env disables the auto-launch."""
    return str(os.environ.get(_CI_OPT_OUT_ENV, "")).strip().lower() in {"1", "true", "yes"}


def _configured_poisoning_enabled(shell: Any) -> Optional[bool]:
    """Read the operator-configured poisoning toggle off ``shell.scan_config``.

    Reads the ``--scan-config`` ``poisoning.enabled`` key (SSOT:
    :class:`adscan_internal.services.scan_config.PoisoningConfig`). Returns
    ``None`` when unset — a plain interactive session with no ``scan_config``,
    or a config that omits the ``poisoning`` section — so the caller falls back
    to the workspace-type default. Defensive: never raises on a missing
    attribute or an unexpected value type.
    """
    try:
        scan_config = getattr(shell, "scan_config", None)
        poisoning = getattr(scan_config, "poisoning", None)
        enabled = getattr(poisoning, "enabled", None)
        return enabled if isinstance(enabled, bool) else None
    except Exception:  # noqa: BLE001 — a bad shell attr must never break the gate
        return None


def _render_poisoning_consent_panel(scope: str) -> None:
    """Render the premium, didactic consent panel for the poisoning offer.

    Carries the value (why it matters), the L2 scope, the noise/OPSEC cost, and
    the background-job controls, so the confirm line below can stay a clean
    one-liner. Best-effort: a rendering failure never blocks the offer. Rich
    wraps the copy, so it stays readable down to an 80-column terminal.
    """
    try:
        from rich.console import Group  # noqa: PLC0415
        from rich.text import Text  # noqa: PLC0415

        from adscan_core.rich_output import print_panel  # noqa: PLC0415
        from adscan_core.theme import (  # noqa: PLC0415
            ADSCAN_PRIMARY,
            ADSCAN_PRIMARY_BRIGHT,
        )

        lede = Text()
        lede.append("Answer ")
        lede.append("LLMNR / NBT-NS / mDNS", style=f"bold {ADSCAN_PRIMARY}")
        lede.append(
            " name lookups on this segment and capture the NetNTLM hash of any host "
            "that resolves a bad name — a low-effort way to capture credentials off "
            "the network while the scan runs."
        )

        def _row(label: str, value: str, value_style: str = "") -> Text:
            row = Text("  ")
            row.append(f"{label:<9}", style=f"bold {ADSCAN_PRIMARY_BRIGHT}")
            row.append(value, style=value_style)
            return row

        rows = Group(
            _row("Scope", f"Layer-2 segment on {scope} only — does not cross routers"),
            _row("Runs", "Non-blocking — the scan continues while it captures"),
            _row("Noise", "Generates network traffic a monitored network may flag", "yellow"),
            _row("Control", "'jobs' for status · 'stop_poisoning' stops it anytime"),
        )

        footer = Text()
        footer.append("Launch now, or anytime later with the ", style="dim")
        footer.append("poisoning", style=f"bold {ADSCAN_PRIMARY}")
        footer.append(" command.", style="dim")

        print_panel(
            Group(lede, Text(""), rows, Text(""), footer),
            title="📡  Broadcast Poisoning",
            subtitle=f"interface {scope}",
            border_style=ADSCAN_PRIMARY,
            title_align="left",
        )
    except Exception as exc:  # noqa: BLE001 — a panel must never block the offer
        telemetry.capture_exception(exc)


def maybe_launch_poisoning_job(
    shell: Any, domain: str, interface: Optional[str]
) -> Optional[BackgroundJob]:
    """Decide + launch a broadcast-poisoning background job. Best-effort.

    Order: no-interface guard → idempotency guard → decision gate → launch.
    The decision gate precedence, strongest first:

    1. ``ADSCAN_NO_POISONING=1`` (hard opt-out) → skip, unconditionally.
    2. ``scan_config.poisoning.enabled`` set (not ``None``) → authoritative:
       ``True`` launches, ``False`` skips — overriding the workspace-type
       default, in BOTH interactive and non-interactive runs.
    3. Otherwise → the workspace-type default: audit auto-launches (interactive
       prompt pre-set to Yes), ctf does not (prompt pre-set to No).

    Returns the job on launch (or the existing active job), else ``None``.
    Never raises.
    """
    try:
        if not interface:
            return None
        scope = str(interface)
        registry = get_or_create_registry(shell)

        # Idempotency: already running on this interface → no re-prompt, no relaunch.
        existing = registry.find_active(_POISONING_KIND, scope)
        if existing is not None:
            return existing

        # (1) Hard env opt-out — strongest precedence, applies everywhere
        # (out-of-scope / known-monitored engagements), even over an explicit
        # scan_config enable.
        if _ci_opt_out():
            return None

        # Poisoning is an AUDIT technique (harvest a first credential from a real
        # engagement), not a CTF one (CTF boxes rarely escalate via broadcast
        # poisoning). So the workspace-type DEFAULT is: audit ON, ctf OFF.
        is_ctf = str(getattr(shell, "type", "") or "").strip().lower() == "ctf"

        # (2) Explicit scan_config toggle is authoritative — it overrides the
        # type default in both modes. ``None`` = defer to the type default (3).
        configured = _configured_poisoning_enabled(shell)
        if configured is False:
            return None
        if configured is None:
            # (3) No explicit config → workspace-type default.
            if is_non_interactive(shell):
                # CI / non-interactive (adscan ci — the web/PoV worker path):
                # audit auto-launches unattended (the money path); ctf never does.
                if is_ctf:
                    return None
                # else (audit): fall through and launch unattended.
            else:
                # Interactive: the didactic consent panel + prompt is unchanged.
                _render_poisoning_consent_panel(scope)
                consent = confirm_ask(
                    f"Start background poisoning on {scope}?",
                    default=not is_ctf,  # audit → Yes, CTF → No
                )
                if not consent:
                    print_instruction(
                        "Skipped. Start it anytime with the 'poisoning' command."
                    )
                    return None
        # configured is True → authoritative launch (both modes, no prompt).

        job = registry.create(kind=_POISONING_KIND, scope=scope)
        sink = make_registry_result_sink(registry)
        runtime = PoisoningJobRuntime(
            shell,
            interface=scope,
            advertised_ip=getattr(shell, "myip", None),
            sink=sink,
            job_id=job.id,
        )
        if not runtime.start():
            registry.mark(job.id, state="failed")
            return None
        registry.attach_runtime(job.id, runtime)
        print_info(
            f"Background poisoning started on {scope}. Results appear as they land; "
            "'jobs' for status, 'stop_poisoning' to stop."
        )
        return job
    except Exception as exc:  # noqa: BLE001 — a launch failure must not abort the scan
        telemetry.capture_exception(exc)
        return None


# Job kinds that run to COMPLETION on their own (a finite crack) vs an
# INDEFINITE listener (poisoning) that captures until told to stop. The
# scan-end keep/stop choice is a real one only for the indefinite listeners:
# a finite crack always finishes, and killing it wastes GPU work already spent
# and can lose a credential that was seconds from cracking — so cracks are
# never offered for stop and never killed here (`jobs stop <id>` still works on
# demand). They surface via the harvest review as they land.
_FINITE_JOB_KINDS: frozenset[str] = frozenset({"cracking"})


def reconcile_jobs_at_scan_end(shell: Any) -> None:
    """At scan end, render the harvest summary and reconcile background jobs.

    Split by job lifecycle:

    * **Finite cracks** run to completion and are neither offered for stop nor
      killed — a one-liner notes they keep running and their results surface via
      the harvest review.
    * **Indefinite listeners** (broadcast poisoning) get the keep-or-stop prompt
      (default keep). Stopping them does NOT stop the cracks.
    """
    try:
        _render_scan_end_harvest_summary(shell)
        registry = get_or_create_registry(shell)
        active = registry.active()
        if not active:
            return
        if is_non_interactive(shell):
            return  # unattended runs keep jobs running; finalize() handles exit

        cracking_jobs = [j for j in active if j.kind in _FINITE_JOB_KINDS]
        listeners = [j for j in active if j.kind not in _FINITE_JOB_KINDS]

        # Finite cracks: never prompted, never killed — they run to completion.
        running_cracks = [j for j in cracking_jobs if j.state == "running"]
        if running_cracks:
            n = len(running_cracks)
            print_info(
                f"{n} credential crack{'s' if n != 1 else ''} still running in the "
                "background — results surface as they land; review with 'harvest' "
                "or 'jobs'."
            )

        # Indefinite listeners: the keep/stop choice applies ONLY to these.
        if not listeners:
            return
        summary = ", ".join(
            f"{j.kind}@{j.scope} ({int(j.result_summary.get('captured', 0))} captured)"
            for j in listeners
        )
        keep = confirm_ask(
            f"Poisoning still capturing: {summary}. Keep capturing?",
            default=True,
        )
        if keep:
            print_instruction(
                "Left running. Stop it anytime with 'stop_poisoning' "
                "(or 'jobs' to view, 'jobs stop <id>' for one interface)."
            )
            return
        for job in listeners:
            registry.stop(job.id)
        # Only the listeners were stopped; any finite crack keeps running.
        if running_cracks:
            print_info("Stopped background poisoning. Credential cracks continue to completion.")
        else:
            print_info("Stopped background poisoning.")
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)


def _render_scan_end_harvest_summary(shell: Any) -> None:
    """Render the persisted credential_harvest.json summary at scan end.

    The end-of-scan ROLL-UP: one consolidated view across ALL harvest sources
    (poisoning + spraying + kerberoasting + AS-REP roasting), ordered by
    priority (Privilege Tier first, Compromise Reach second) via the shared
    ``build_credential_harvest_panel`` — NOT a duplicate of the per-source
    panels each producer already rendered mid-scan.

    Renders the standing panel unconditionally (a quick executive recap of
    everything harvested this session), then branches on interactivity:

    * **Interactive** — offers the operator-driven review actions (add+scan /
      retry-crack / copy hash) via ``offer_credential_harvest_actions``.
    * **Non-interactive** (``adscan ci`` / the web-PoV worker) — no operator,
      so ``activate_and_escalate_harvest_ci`` value-prioritizes by the
      now-complete attack graph: it escalates THOROUGH cracking for Tier 0 /
      path-to-Tier-0 principals first and auto-activates the background-cracked
      credentials that complete a validated path to domain compromise. Still
      prompt-free — every decision auto-resolves (this module's CI contract).

    Best-effort: never raises. The caller wraps this in its own try/except, so
    a summary failure never breaks scan-end reconciliation.
    """
    from adscan_internal.cli.widgets.credential_harvest_panel import (  # noqa: PLC0415
        activate_and_escalate_harvest_ci,
        build_credential_harvest_panel,
        offer_credential_harvest_actions,
    )
    from adscan_internal.services.credential_harvest_view import (  # noqa: PLC0415
        load_effective_harvest_records,
    )

    domain = str(getattr(shell, "domain", "") or "")
    # Effective view = finished captures PLUS a "cracking…" row for every crack
    # still running. A fast scan can end while a background crack is mid-flight;
    # without the in-progress rows the panel would be empty even though a hash
    # was captured and is being worked — the operator must SEE that.
    records = load_effective_harvest_records(shell, domain)
    if not records:
        return
    console = getattr(shell, "console", None)
    panel = build_credential_harvest_panel(records)
    if console is not None:
        console.print(panel)
    if is_non_interactive(shell):
        # CI / non-interactive (adscan ci — the web/PoV worker): no operator to
        # review, so value-prioritize by the now-complete attack graph. Escalate
        # THOROUGH cracking for Tier 0 / path-to-Tier-0 principals first, and
        # auto-activate the background-cracked credentials that complete a
        # validated path to domain compromise (the money-path deliverable).
        activate_and_escalate_harvest_ci(shell, domain, records)
    else:
        offer_credential_harvest_actions(shell, domain, records)
