"""Tuning helpers for parallel artifact processing workloads."""

from __future__ import annotations

from dataclasses import dataclass
import os


@dataclass(frozen=True, slots=True)
class ArtifactProcessingTuning:
    """Concurrency settings for artifact benchmark processing."""

    workers: int


def choose_artifact_processing_tuning(
    *,
    file_count: int,
    logical_cpus: int | None = None,
) -> ArtifactProcessingTuning:
    """Choose one conservative worker count for heavy artifact processing.

    The artifact pipeline can invoke expensive local analysis such as ZIP
    inspection, extraction, and pypykatz over dumps. That workload is heavier
    than text credential scanning, so we keep concurrency intentionally bounded.
    """
    cpus = max(1, int(logical_cpus or os.cpu_count() or 4))
    files = max(0, int(file_count or 0))
    if files <= 1:
        workers = 1
    elif files <= 4:
        workers = min(2, cpus)
    elif files <= 12:
        workers = min(3, max(2, cpus))
    else:
        workers = min(4, max(2, cpus))
    return ArtifactProcessingTuning(workers=max(1, workers))


__all__ = [
    "ArtifactProcessingTuning",
    "choose_artifact_processing_tuning",
]
