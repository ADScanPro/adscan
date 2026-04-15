"""Shared Windows artifact acquisition helpers across transports."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from typing import Callable


@dataclass(slots=True, frozen=True)
class WindowsArtifactAcquisitionResult:
    """Structured result for one Windows artifact acquisition phase."""

    downloaded_files: list[str]
    staged_file_count: int = 0
    skipped_files: list[tuple[str, str]] | None = None
    batch_used: bool = False
    batch_fallback: bool = False
    per_file_failures: list[tuple[str, str]] | None = None
    auth_invalid_abort: bool = False
    auth_invalid_reason: str | None = None


BatchFetcher = Callable[[list[tuple[str, str]], str], WindowsArtifactAcquisitionResult]
FileFetcher = Callable[[str, str], str]
AuthInvalidPredicate = Callable[[str], bool]


def format_fetch_path_preview(
    *,
    items: list[tuple[str, str]],
    preview_limit: int = 3,
) -> str:
    """Return a compact preview of fetch paths for warning output."""
    preview = ", ".join(path for path, _reason in items[:preview_limit])
    remaining = len(items) - min(len(items), preview_limit)
    if remaining > 0:
        return f"{preview}, +{remaining} more"
    return preview


def classify_fetch_skip_reason(reason: str) -> str:
    """Collapse raw fetch failures into stable troubleshooting buckets."""
    normalized = str(reason or "").strip().casefold()
    if "being used by another process" in normalized or "used by another process" in normalized:
        return "file_in_use"
    if "access to the path" in normalized and "denied" in normalized:
        return "access_denied"
    if "access is denied" in normalized or "permission denied" in normalized:
        return "access_denied"
    return "other"


def summarize_fetch_skip_reasons(
    skipped_files: list[tuple[str, str]],
) -> dict[str, int]:
    """Count skipped fetch files by reason category."""
    summary = {
        "access_denied": 0,
        "file_in_use": 0,
        "other": 0,
    }
    for _path, reason in skipped_files:
        summary[classify_fetch_skip_reason(reason)] += 1
    return summary


def persist_fetch_report(
    *,
    phase_root_abs: str,
    fetch_result: WindowsArtifactAcquisitionResult,
) -> str:
    """Persist fetch metadata for later troubleshooting."""
    report_path = os.path.join(phase_root_abs, "fetch_report.json")
    skipped_files = list(fetch_result.skipped_files or [])
    per_file_failures = list(fetch_result.per_file_failures or [])
    payload = {
        "batch_used": fetch_result.batch_used,
        "batch_fallback": fetch_result.batch_fallback,
        "staged_file_count": int(fetch_result.staged_file_count or 0),
        "downloaded_file_count": len(fetch_result.downloaded_files),
        "auth_invalid_abort": fetch_result.auth_invalid_abort,
        "auth_invalid_reason": fetch_result.auth_invalid_reason,
        "skipped_files": [
            {"remote_path": path, "reason": reason}
            for path, reason in skipped_files
        ],
        "skipped_summary": summarize_fetch_skip_reasons(skipped_files),
        "per_file_failures": [
            {"remote_path": path, "reason": reason}
            for path, reason in per_file_failures
        ],
    }
    with open(report_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=True)
    return report_path


class WindowsArtifactAcquisitionService:
    """Acquire remote Windows files through transport-specific callbacks."""

    def acquire_files(
        self,
        *,
        file_targets: list[tuple[str, str]],
        download_dir: str,
        workspace_type: str | None = None,
        batch_threshold: int = 8,
        batch_fetcher: BatchFetcher | None = None,
        file_fetcher: FileFetcher,
        is_auth_invalid_error: AuthInvalidPredicate | None = None,
    ) -> WindowsArtifactAcquisitionResult:
        """Acquire files using batch or per-file backends when available."""
        if not file_targets:
            return WindowsArtifactAcquisitionResult(downloaded_files=[])

        if batch_fetcher is not None and len(file_targets) >= batch_threshold:
            try:
                return batch_fetcher(file_targets, download_dir)
            except Exception as exc:  # noqa: BLE001
                if (
                    workspace_type == "ctf"
                    and callable(is_auth_invalid_error)
                    and is_auth_invalid_error(str(exc))
                ):
                    reason = (
                        "Credentials became invalid during this CTF flow. "
                        "Skipping remaining fetches for this phase because subsequent "
                        f"downloads would fail with the same authentication error: {exc}"
                    )
                    return WindowsArtifactAcquisitionResult(
                        downloaded_files=[],
                        batch_used=True,
                        auth_invalid_abort=True,
                        auth_invalid_reason=reason,
                    )

        downloaded_files: list[str] = []
        per_file_failures: list[tuple[str, str]] = []
        for remote_path, relative_path in file_targets:
            save_path = os.path.join(download_dir, relative_path)
            try:
                downloaded_files.append(file_fetcher(remote_path, save_path))
            except Exception as exc:  # noqa: BLE001
                if (
                    workspace_type == "ctf"
                    and callable(is_auth_invalid_error)
                    and is_auth_invalid_error(str(exc))
                ):
                    reason = (
                        "Credentials became invalid during this CTF flow. "
                        "Aborting remaining per-file fetches for this phase to avoid repeated "
                        f"authentication failures: {exc}"
                    )
                    return WindowsArtifactAcquisitionResult(
                        downloaded_files=downloaded_files,
                        batch_used=batch_fetcher is not None and len(file_targets) >= batch_threshold,
                        batch_fallback=batch_fetcher is not None and len(file_targets) >= batch_threshold,
                        per_file_failures=per_file_failures,
                        auth_invalid_abort=True,
                        auth_invalid_reason=reason,
                    )
                per_file_failures.append((remote_path, str(exc)))
        return WindowsArtifactAcquisitionResult(
            downloaded_files=downloaded_files,
            batch_used=batch_fetcher is not None and len(file_targets) >= batch_threshold,
            batch_fallback=batch_fetcher is not None and len(file_targets) >= batch_threshold,
            per_file_failures=per_file_failures,
        )


__all__ = [
    "WindowsArtifactAcquisitionResult",
    "WindowsArtifactAcquisitionService",
    "classify_fetch_skip_reason",
    "format_fetch_path_preview",
    "persist_fetch_report",
    "summarize_fetch_skip_reasons",
]
