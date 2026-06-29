"""Lifecycle wiring for the posture probe phase.

Single helper used by both ``start_unauth`` and ``start_auth`` paths in
:mod:`adscan_internal.cli.start`. The helper owns the live-view + summary
panel orchestration and the sink wiring; the lifecycle paths just call
:func:`run_posture_probe` (sync) or :func:`arun_posture_probe` (async).

Opt-out is environment-only — set ``ADSCAN_NO_POSTURE_PROBE`` to any
truthy value (``1``, ``true``, ``yes``, ``on``) to skip the probe phase
silently. There is no CLI flag.
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any, Optional

from adscan_core import telemetry
from adscan_core.rich_output import print_warning
from adscan_internal import get_console
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.posture_probe import ProbeResult


def is_posture_probe_disabled() -> bool:
    """Return True when ``ADSCAN_NO_POSTURE_PROBE`` is set to a truthy value."""
    val = os.environ.get("ADSCAN_NO_POSTURE_PROBE", "").strip().lower()
    return val in {"1", "true", "yes", "on"}


def _publish_posture_widget_best_effort(
    shell: Any,
    domain: str,
    results: list[ProbeResult],
) -> None:
    """Build + emit + persist the domain-hardening posture as a shared widget.

    Taps the SAME structured ``ProbeResult`` objects the summary panel renders,
    reusing the posture-probe label maps, and reduces them to a ``matrix-panel``
    widget. Emitted live + persisted via ``publish_widget`` so the web premium
    component renders the identical contract.

    This is the web-side half of "one definition, both renderers" for Posture:
    the CLI keeps its battle-tested ``render_posture_probe_summary`` panel
    (premium, inside the LiveSession summary), while the web is driven purely by
    this emitted widget data — same source objects, no second hand-built UI.
    Best-effort: never raises into the probe flow.
    """
    try:
        from adscan_internal.cli.widgets.posture_probe_live import (
            _PROBE_HARDENING_LABEL,
            _PROBE_PERMISSIVE_LABEL,
        )
        from adscan_internal.cli.widgets.widget_artifacts import publish_widget
        from adscan_internal.cli.widgets.widget_builders import build_posture_widget

        detected: list[tuple[str, str, str]] = []
        permissive: list[tuple[str, str]] = []
        for result in results:
            if result.skipped or not result.succeeded:
                continue
            hardening = _PROBE_HARDENING_LABEL.get((result.category, result.state))
            if hardening is not None:
                detected.append(
                    (hardening, str(getattr(result.confidence, "value", "")), "")
                )
                continue
            weak = _PROBE_PERMISSIVE_LABEL.get((result.category, result.state))
            if weak is not None:
                permissive.append((weak, ""))

        widget = build_posture_widget(
            domain=domain,
            detected_hardening=detected,
            permissive=permissive,
        )
        publish_widget(shell, domain=domain, widget=widget)
    except Exception as exc:  # noqa: BLE001 — widget publication never aborts the scan
        telemetry.capture_exception(exc)


def _emit_posture_findings_best_effort(shell: Any, domain: str) -> None:
    """Translate the freshly-updated posture cache into technical findings.

    Called from both the live and silent ``arun_posture_probe`` paths
    right before they return — at that point the posture cache is
    confirmed persisted for ``domain`` (Wave A + Wave B + auth-phase
    sink writes have all completed).

    Lives in the lifecycle helper (not inside ``probe_unauth`` /
    ``probe_auth``) because:
      * Finding emission is a PRO-tier concern, not a probe concern.
      * The bridge module is in ``adscan_internal/pro/services/`` — a
        clean layering boundary that LITE builds simply don't ship.
      * The single call point here means every posture phase emits
        findings consistently regardless of which CLI verb triggered it.

    Best-effort: any failure (LITE build with no ``pro/`` directory,
    bridge import error, missing report context on ``shell``) is
    swallowed silently after capturing to telemetry. Finding emission
    never blocks the probe lifecycle.
    """
    try:
        from adscan_internal.pro.services.posture_findings_emitter import (
            emit_findings_from_posture,
        )
    except Exception as exc:  # noqa: BLE001
        # LITE build (no pro/) — silently skip.
        telemetry.capture_exception(exc)
        return

    try:
        emit_findings_from_posture(shell, domain=domain)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)


def run_posture_probe(
    shell: Any,
    *,
    domain: Optional[str],
    dc_ip: Optional[str],
    username: Optional[str] = None,
    password: Optional[str] = None,
    nt_hash: Optional[str] = None,
    aes_key: Optional[str] = None,
    ccache_path: Optional[str] = None,
    force: bool = False,
    render_ui: bool = True,
) -> list[ProbeResult]:
    """Synchronous wrapper around :func:`arun_posture_probe`.

    Failures are logged at warning level and never propagate — the lifecycle
    continues with conservative defaults.
    """
    if is_posture_probe_disabled():
        return []
    if not domain or not dc_ip:
        return []

    try:
        return asyncio.run(
            arun_posture_probe(
                shell,
                domain=domain,
                dc_ip=dc_ip,
                username=username,
                password=password,
                nt_hash=nt_hash,
                aes_key=aes_key,
                ccache_path=ccache_path,
                force=force,
                render_ui=render_ui,
            )
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning(
            f"Posture probe failed for {mark_sensitive(domain, 'domain')}: "
            f"{type(exc).__name__}. Continuing with conservative defaults."
        )
        return []


async def arun_posture_probe(
    shell: Any,
    *,
    domain: str,
    dc_ip: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    nt_hash: Optional[str] = None,
    aes_key: Optional[str] = None,
    ccache_path: Optional[str] = None,
    force: bool = False,
    render_ui: bool = True,
) -> list[ProbeResult]:
    """Drive the full probe phase, optionally inside one ``Live`` panel + summary.

    Args:
        shell: PentestShell-like object exposing ``domains_data``.
        domain: Target Kerberos realm / AD domain.
        dc_ip: DC IP to probe.
        username/password/nt_hash/aes_key/ccache_path: Credential fields.
        force: When True, ignore existing fresh HIGH posture and re-run.
        render_ui: When False, suppress the Live panel + summary print.

    Returns:
        List of :class:`ProbeResult` collected; empty list on early-out or
        when the probe phase failed before producing any result.
    """
    # Imports are deferred so import-time of ``cli.start`` stays cheap.
    from adscan_internal.cli.widgets.posture_probe_live import (
        PostureProbeLiveView,
        render_posture_probe_summary,
    )
    from adscan_internal.services.domain_posture import get_posture, persist_password_policy
    from adscan_internal.services.posture_probe import (
        ProbeCredentials,
        ProbePhase,
        probe_auth,
        probe_password_policy,
        probe_unauth,
    )
    from adscan_internal.services.posture_sink import make_workspace_posture_sink

    domains_data = getattr(shell, "domains_data", None)
    if domains_data is None:
        return []

    # Resolve the DC FQDN once, for the A6 Kerberos-path CBT probe's ldap/ SPN
    # (CLAUDE.md § Kerberos SPNs — never an IP). resolve_dc_fqdn walks the
    # collector's canonical alias chain; returns None when only an IP is known,
    # in which case A6 self-skips.
    dc_fqdn: Optional[str] = None
    try:
        from adscan_internal.models.domain import resolve_dc_fqdn

        dc_fqdn = resolve_dc_fqdn(
            domains_data.get(domain, {}) or {},
            target_domain=domain,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)

    console = get_console()
    # The probe phase has its own dedicated UX: the 🔍 PostureProbeLiveView
    # panel renders findings as they arrive, and the 🛡️ posture-probe
    # summary panel categorises them once the phase ends. The 🧠
    # Intelligence Update panel is reserved for first-time discoveries
    # made by REAL scan operations (LDAP collector, trust enum, etc.)
    # that surface posture signals AFTER the probe phase. Wiring
    # ``on_finding`` here would re-render the same finding twice
    # (Intelligence Update + Live + Summary) and degrade the premium
    # UX. The reactive ``on_finding`` sink lives elsewhere — built by
    # the collector orchestrator with the panel callback wired in — so
    # genuinely new posture discoveries during the scan still surface
    # via 🧠 Intelligence Update.
    sink = make_workspace_posture_sink(
        domains_data,
        on_finding=None,
    )

    have_creds = bool(username) and bool(password or nt_hash or ccache_path or aes_key)
    started = time.monotonic()
    collected: list[ProbeResult] = []
    # Snapshot the posture BEFORE the probe runs. The summary panel uses
    # this to distinguish newly-discovered constraints from already-known
    # ones (rendering ⚡ NEW vs · already known per row).
    prior_posture = get_posture(domains_data, domain=domain)

    async def _drive(progress_cb, on_phase_start) -> None:
        nonlocal collected
        # Phase 1 — anonymous probes.
        posture_before_unauth = get_posture(domains_data, domain=domain)
        on_phase_start(ProbePhase.UNAUTH)
        unauth = await probe_unauth(
            domain=domain,
            dc_ip=dc_ip,
            sink=sink,
            on_progress=progress_cb,
            posture=posture_before_unauth,
            force=force,
        )
        collected.extend(unauth)
        # Phase 2 — authenticated probes (only when creds available).
        if have_creds and username is not None:
            posture_before_auth = get_posture(domains_data, domain=domain)
            creds = ProbeCredentials(
                username=username,
                password=password,
                nt_hash=nt_hash,
                aes_key=aes_key,
                ccache_path=ccache_path,
            )
            on_phase_start(ProbePhase.AUTH)
            auth = await probe_auth(
                domain=domain,
                dc_ip=dc_ip,
                creds=creds,
                sink=sink,
                on_progress=progress_cb,
                posture=posture_before_auth,
                force=force,
                dc_fqdn=dc_fqdn,
            )
            collected.extend(auth)
            # Password policy probe — runs after AUTH phase so it can reuse
            # the same credential bundle. Skipped when force=False and the
            # policy is already present in domains_data (checked by reading
            # the current posture). Silent failure is intentional: a missing
            # policy snapshot never aborts the scan.
            existing_policy = get_posture(domains_data, domain=domain).password_policy
            if force or existing_policy is None:
                policy_snapshot = await probe_password_policy(
                    domain=domain,
                    dc_ip=dc_ip,
                    dc_fqdn=dc_fqdn,
                    username=username,
                    password=password,
                    nt_hash=nt_hash,
                    ccache_path=ccache_path,
                    use_kerberos=(
                        password is None
                        and nt_hash is None
                        and ccache_path is not None
                    ),
                )
                if policy_snapshot is not None:
                    persist_password_policy(
                        domains_data,
                        domain=domain,
                        snapshot=policy_snapshot,
                    )

    if render_ui:
        with PostureProbeLiveView(
            domain=domain,
            dc_ip=dc_ip,
            username=username if have_creds else None,
        ) as live:
            try:
                await _drive(live.on_progress, live.on_phase_start)
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_warning(
                    f"Posture probe failed for {mark_sensitive(domain, 'domain')}: "
                    f"{type(exc).__name__}. Continuing with conservative defaults."
                )
                return collected
            results = list(live.all_results)

        elapsed = time.monotonic() - started
        try:
            posture_after = get_posture(domains_data, domain=domain)
            console.print(
                render_posture_probe_summary(
                    results=results,
                    domain=domain,
                    dc_ip=dc_ip,
                    elapsed_s=elapsed,
                    posture=posture_after,
                    prior_posture=prior_posture,
                )
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
        _publish_posture_widget_best_effort(shell, domain, results)
        _emit_posture_findings_best_effort(shell, domain)
        return results

    # Silent path — no Live, no summary panel.
    try:
        await _drive(lambda *_a, **_k: None, lambda *_a, **_k: None)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning(
            f"Posture probe failed for {mark_sensitive(domain, 'domain')}: "
            f"{type(exc).__name__}. Continuing with conservative defaults."
        )
    _emit_posture_findings_best_effort(shell, domain)
    return collected


__all__ = [
    "arun_posture_probe",
    "is_posture_probe_disabled",
    "run_posture_probe",
]
