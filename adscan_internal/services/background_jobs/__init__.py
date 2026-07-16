"""Background-job / deferred-results subsystem (v1: core + poisoning).

A framework-agnostic core for running wait-dependent techniques off the
synchronous scan flow. See docs/superpowers/specs/2026-07-06-background-job-subsystem-design.md.
"""
from __future__ import annotations

from adscan_internal.services.background_jobs.registry import (
    BackgroundJob,
    BackgroundJobRegistry,
    JobRuntime,
    get_or_create_registry,
)
from adscan_internal.services.background_jobs.results_bus import (
    JobResult,
    JobResultSink,
    make_registry_result_sink,
)
from adscan_internal.services.background_jobs.poisoning_job import PoisoningJobRuntime
from adscan_internal.services.background_jobs.cracking_job import CrackingJobRuntime
from adscan_internal.services.background_jobs.cracking_enqueue import enqueue_cracking_job
from adscan_internal.services.background_jobs.scan_seam import (
    maybe_launch_poisoning_job,
    reconcile_jobs_at_scan_end,
)
from adscan_internal.services.background_jobs.jobs_view import (
    format_cracking_summary,
    format_jobs_table,
    format_notification_line,
)

__all__ = [
    "BackgroundJob",
    "BackgroundJobRegistry",
    "JobRuntime",
    "get_or_create_registry",
    "JobResult",
    "JobResultSink",
    "make_registry_result_sink",
    "PoisoningJobRuntime",
    "CrackingJobRuntime",
    "enqueue_cracking_job",
    "maybe_launch_poisoning_job",
    "reconcile_jobs_at_scan_end",
    "format_cracking_summary",
    "format_jobs_table",
    "format_notification_line",
]
