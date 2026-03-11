"""Shared tuning heuristics for rclone-heavy SMB benchmark workloads.

This module centralizes concurrency decisions for rclone-backed benchmark
scenarios so ADscan does not couple SMB transfer tuning to CredSweeper's
parallelism model.
"""

from __future__ import annotations

from dataclasses import dataclass
import os


@dataclass(frozen=True)
class RcloneTuning:
    """Effective rclone tuning for one benchmark scenario."""

    target_workers: int
    transfers: int
    checkers: int
    buffer_size: str


@dataclass(frozen=True)
class RcloneCatTuning:
    """Effective tuning for rclone cat + in-memory analysis scenarios."""

    fetch_workers: int
    analysis_jobs: int


def _clamp(value: int, low: int, high: int) -> int:
    """Clamp one integer to an inclusive range."""
    return max(low, min(value, high))


def _resolve_total_memory_gib() -> float | None:
    """Return approximate total system memory in GiB when available."""
    try:
        page_size = int(os.sysconf("SC_PAGE_SIZE"))
        page_count = int(os.sysconf("SC_PHYS_PAGES"))
    except (AttributeError, OSError, ValueError):
        return None
    if page_size <= 0 or page_count <= 0:
        return None
    return float(page_size * page_count) / float(1024**3)


def choose_rclone_tuning(
    *,
    target_count: int,
    mostly_small_files: bool,
    logical_cpus: int | None = None,
) -> RcloneTuning:
    """Choose conservative but scalable rclone tuning for SMB workloads.

    Args:
        target_count: Number of host/share download jobs in the current scenario.
        mostly_small_files: True for text/document workloads with many small files.
        logical_cpus: Optional CPU count override for tests.

    Returns:
        RcloneTuning with process-level and per-process concurrency settings.
    """
    cpus = max(1, int(logical_cpus or os.cpu_count() or 4))
    total_memory_gib = _resolve_total_memory_gib()
    low_memory_mode = total_memory_gib is not None and total_memory_gib < 8.0

    max_target_workers = 4 if mostly_small_files else 2
    cpu_workers_cap = max(1, cpus // 4)
    target_workers = _clamp(
        min(max(1, int(target_count)), cpu_workers_cap),
        1,
        max_target_workers,
    )

    transfer_budget = _clamp(cpus, 8, 24)
    checker_budget = _clamp(cpus * 4, 16, 96)

    transfers = transfer_budget // max(1, target_workers)
    checkers = checker_budget // max(1, target_workers)

    if mostly_small_files:
        transfers = _clamp(transfers, 2, 8)
        checkers = _clamp(checkers, 8, 32 if target_workers == 1 else 16)
        buffer_size = "4Mi"
    else:
        transfers = _clamp(transfers, 2, 6)
        checkers = _clamp(checkers, 4, 12)
        buffer_size = "8Mi"

    if low_memory_mode:
        target_workers = _clamp(target_workers, 1, 2)
        transfers = _clamp(max(1, transfers // 2), 1, 4)
        checkers = _clamp(max(2, checkers // 2), 2, 8)
        buffer_size = "4Mi"

    return RcloneTuning(
        target_workers=target_workers,
        transfers=transfers,
        checkers=checkers,
        buffer_size=buffer_size,
    )


def choose_rclone_cat_tuning(
    *,
    file_count: int,
    share_count: int,
    mostly_small_files: bool,
    logical_cpus: int | None = None,
) -> RcloneCatTuning:
    """Choose tuning for rclone cat fetches plus in-memory CredSweeper analysis."""
    cpus = max(1, int(logical_cpus or os.cpu_count() or 4))
    total_memory_gib = _resolve_total_memory_gib()
    low_memory_mode = total_memory_gib is not None and total_memory_gib < 8.0

    files = max(1, int(file_count))
    shares = max(1, int(share_count))

    fetch_cap = 16 if mostly_small_files else 8
    share_budget = _clamp(shares * 2, 2, fetch_cap)
    cpu_budget = _clamp(cpus, 4, fetch_cap)
    fetch_workers = _clamp(min(files, share_budget, cpu_budget), 1, fetch_cap)

    if mostly_small_files:
        analysis_jobs = _clamp(cpus, 4, 12)
    else:
        analysis_jobs = _clamp(max(2, cpus // 2), 2, 8)

    if low_memory_mode:
        fetch_workers = _clamp(max(1, fetch_workers // 2), 1, 4)
        analysis_jobs = _clamp(max(1, analysis_jobs // 2), 1, 4)

    return RcloneCatTuning(
        fetch_workers=fetch_workers,
        analysis_jobs=analysis_jobs,
    )


__all__ = [
    "RcloneTuning",
    "RcloneCatTuning",
    "choose_rclone_tuning",
    "choose_rclone_cat_tuning",
]
