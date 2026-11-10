"""Persist the engagement timeline at scan end, from the live session.

The record itself is derived by the dependency-light SSOT
:mod:`adscan_core.reporting.engagement_timeline`. This module is the thin seam
that hands it the two things only the running engine has, and then stores the
result on ``technical_report.json`` so a later process can render it:

* the LIVE workspace state, read from the shell rather than from
  ``variables.json`` on disk. At the authenticated finalization seam the save
  happens AFTER the outcome is written, so a disk read there would miss the
  credentials the scan recovered last, which are the ones a client most needs
  accounted for.
* the client-facing label for each environment-change kind, injected from the
  cleanup taxonomy. ``adscan_core`` cannot import it, and a second label map
  would let the timeline and the environment-modifications section name the same
  change two different ways.

Best-effort throughout: a report must ship, so every failure degrades to not
writing the block rather than to failing the scan.
"""

from __future__ import annotations

import os
from typing import Any

from adscan_core import telemetry
from adscan_core.reporting.engagement_timeline import (
    build_engagement_timeline,
    load_engagement_timeline,
    merge_session_window_stamps,
    read_phase_trail,
)
from adscan_core.reporting.technical_report import record_engagement_timeline
from adscan_core.rich_output import print_exception, print_info_debug

__all__ = ["record_engagement_timeline_for_session"]


def _events_by_domain(workspace_dir: str) -> dict[str, list[dict[str, Any]]]:
    """Return ``{domain: events}`` from the persisted technical report."""
    import json  # noqa: PLC0415 - local, this is the only use

    try:
        path = os.path.join(workspace_dir, "technical_report.json")
        with open(path, "r", encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, ValueError):
        return {}
    domains = report.get("domains") if isinstance(report, dict) else None
    if not isinstance(domains, dict):
        return {}
    return {
        str(name): list(payload.get("events") or [])
        for name, payload in domains.items()
        if isinstance(payload, dict)
    }


def record_engagement_timeline_for_session(shell: Any) -> None:
    """Build this session's timeline and persist it. Never raises.

    Called from the scan-finalization seams, beside the scan-outcome write, so
    both ``adscan start`` and ``adscan ci`` leave the record behind.

    Args:
        shell: The live session shell.
    """
    try:
        workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "")
        if not workspace_dir:
            return
        from adscan_internal.services import cleanup_taxonomy  # noqa: PLC0415
        from adscan_internal.services.environment_change_ledger import (  # noqa: PLC0415
            resolve_environment_changes,
        )

        # The live ledger is fresher about the changes; the on-disk one is the
        # only record that stamps when the session itself opened and closed.
        changes = merge_session_window_stamps(
            resolve_environment_changes(workspace_dir=workspace_dir).block,
            workspace_dir,
        )
        domains_data = getattr(shell, "domains_data", None)
        variables = getattr(shell, "variables", None)
        if not isinstance(variables, dict):
            variables = {}
        timeline = build_engagement_timeline(
            domains_data=domains_data if isinstance(domains_data, dict) else {},
            events_by_domain=_events_by_domain(workspace_dir),
            phase_rows=read_phase_trail(workspace_dir),
            environment_changes=changes,
            vantage_address=str(variables.get("myip") or ""),
            vantage_interface=str(variables.get("interface") or ""),
            change_kind_label=cleanup_taxonomy.kind_display,
        )
        if not timeline:
            # The live path produced nothing usable (a session with no shell
            # state at all). Fall back to the workspace reader rather than
            # leaving no record, since the files may still carry one.
            timeline = load_engagement_timeline(
                workspace_dir,
                environment_changes=changes,
                change_kind_label=cleanup_taxonomy.kind_display,
            )
        record_engagement_timeline(shell, timeline=timeline)
        print_info_debug(
            "engagement timeline recorded: "
            f"{len(timeline.get('entries') or [])} entries"
        )
    except Exception as exc:  # noqa: BLE001 - a scan never fails on its own record
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
