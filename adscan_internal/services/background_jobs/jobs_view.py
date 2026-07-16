"""Pure view helpers for the ``jobs`` command + deferred notifications.

No I/O, no printing — returns Rich renderables / strings the caller prints on
the foreground thread. Keeps rendering L1-testable.
"""
from __future__ import annotations

from rich.table import Table

from adscan_internal.services.background_jobs.registry import BackgroundJob
from adscan_internal.services.background_jobs.results_bus import JobResult

_STATE_STYLE = {
    "running": "cyan",
    "done": "green",
    "failed": "red",
    "stopped": "yellow",
    "pending": "dim",
}


def format_jobs_table(jobs: list[BackgroundJob]) -> Table:
    """Build a table of background jobs (id, kind, scope, state, captured)."""
    table = Table(title="Background jobs", show_lines=False)
    table.add_column("ID", style="bold")
    table.add_column("Kind")
    table.add_column("Scope")
    table.add_column("State")
    table.add_column("Captured", justify="right")
    for job in jobs:
        style = _STATE_STYLE.get(job.state, "white")
        captured = str(int(job.result_summary.get("captured", 0)))
        table.add_row(
            job.id[:8],
            job.kind,
            job.scope,
            f"[{style}]{job.state}[/{style}]",
            captured,
        )
    return table


def format_cracking_summary(jobs: list[BackgroundJob]) -> str:
    """One line: 'Cracking: N cracked · M running' (or "" when nothing to report).

    A cracked job is recognized in either production shape its
    ``result_summary`` can carry: the crack-result sink persists the terminal
    ``{"status": "cracked", ...}`` detail and marks the job ``done`` (its LAST
    result is ``terminal``; see ``results_bus.make_registry_result_sink`` /
    ``CrackingJobRuntime._run_crack_tiers``); an explicit stop or session
    finalize overwrites it with ``CrackingJobRuntime.snapshot()`` ->
    ``{"cracked": 1, ...}``. Both are checked so the count is correct
    regardless of when this runs relative to the job's lifecycle.

    ``M running`` counts only jobs still in the ``running`` state — a finished
    crack has transitioned to ``done``, so it is counted as cracked (or, if it
    exhausted its wordlists, drops out of both tallies) and never lingers in the
    running count.
    """
    cracking_jobs = [j for j in jobs if j.kind == "cracking"]
    cracked = sum(
        1
        for j in cracking_jobs
        if j.result_summary.get("status") == "cracked" or j.result_summary.get("cracked")
    )
    running = sum(1 for j in cracking_jobs if j.state == "running")
    if not cracked and not running:
        return ""
    return f"Cracking: {cracked} cracked · {running} running"


def format_notification_line(results: list[JobResult]) -> str:
    """Return a single compact line summarizing new job results (or "")."""
    if not results:
        return ""
    n = len(results)
    return (
        f"ℹ  {n} new background job result{'s' if n != 1 else ''} "
        "— type 'jobs' for details."
    )
