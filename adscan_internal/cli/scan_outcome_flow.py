"""Shared scan-outcome rendering helpers for SMB, WinRM, and future flows."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from collections import Counter
import json
import os

from rich.markup import escape as rich_escape
from rich.table import Table

from adscan_internal import print_info, print_panel
from adscan_internal.rich_output import (
    BRAND_COLORS,
    mark_sensitive,
    print_panel_with_table,
)
from adscan_internal.services.smb_sensitive_file_policy import (
    DIRECT_SECRET_ARTIFACT_EXTENSIONS,
    DOCUMENT_LIKE_CREDENTIAL_EXTENSIONS,
    HEAVY_ARTIFACT_EXTENSIONS,
    TEXT_LIKE_CREDENTIAL_EXTENSIONS,
    resolve_effective_sensitive_extension,
)
from adscan_internal.services.spidering_service import ArtifactProcessingRecord

_NO_EXTRACTED_TABLE_LIMIT = 8
_NO_EXTRACTED_REPORT_LIMIT = 50
_INTERESTING_FILENAME_HINTS = (
    "account",
    "backup",
    "config",
    "credential",
    "database",
    "deploy",
    "export",
    "login",
    "password",
    "procedure",
    "secret",
    "sql",
    "user",
    "vpn",
)


@dataclass(frozen=True)
class NoExtractedReviewCandidate:
    """One file retained for manual review after an automated scan found nothing."""

    relative_path: str
    file_type: str
    outcome: str
    recommendation: str
    reason: str
    manual_review_recommended: bool


def _artifact_status_label(status: str) -> str:
    """Return a user-friendly label for one artifact processing status."""
    normalized = str(status or "").strip().lower()
    mapping = {
        "processed": "Processed",
        "processed_no_findings": "Processed (no findings)",
        "manual_review": "Manual review",
        "failed": "Processing failed",
        "skipped": "Skipped",
    }
    return mapping.get(normalized, normalized.replace("_", " ").title() or "Unknown")


def collect_loot_file_preview(*, loot_dir: str, preview_limit: int = 5) -> list[str]:
    """Return a deterministic preview of downloaded files for one scan phase."""
    root = Path(str(loot_dir or "")).expanduser().resolve(strict=False)
    if not root.is_dir():
        return []

    preview: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for filename in sorted(filenames):
            file_path = Path(dirpath) / filename
            try:
                relative = file_path.relative_to(root).as_posix()
            except ValueError:
                relative = str(file_path)
            preview.append(relative)
            if len(preview) >= preview_limit:
                return preview
    return preview


def _looks_interesting_for_manual_review(relative_path: str) -> bool:
    """Return True when one filename/path hint suggests higher manual-review value."""
    lowered = str(relative_path or "").strip().lower()
    return any(token in lowered for token in _INTERESTING_FILENAME_HINTS)


def _classify_no_extracted_review_candidate(
    *,
    relative_path: str,
    category: str,
) -> NoExtractedReviewCandidate:
    """Classify one analyzed file into a reusable no-findings review outcome."""
    extension = resolve_effective_sensitive_extension(relative_path).casefold()
    file_type = extension.lstrip(".") or Path(relative_path).suffix.lstrip(".") or "file"
    category_key = str(category or "credential").strip().lower()
    interesting = _looks_interesting_for_manual_review(relative_path)

    if extension in DIRECT_SECRET_ARTIFACT_EXTENSIONS:
        return NoExtractedReviewCandidate(
            relative_path=relative_path,
            file_type=file_type,
            outcome="No extracted secrets",
            recommendation="Manual review recommended",
            reason="High-value secret artifact was analyzed but automation extracted nothing.",
            manual_review_recommended=True,
        )
    if extension in HEAVY_ARTIFACT_EXTENSIONS:
        return NoExtractedReviewCandidate(
            relative_path=relative_path,
            file_type=file_type,
            outcome="No extracted secrets",
            recommendation=(
                "Manual review recommended" if interesting else "Review if host/share context is high value"
            ),
            reason="Heavy artifact was processed but no actionable child artifacts or secrets were extracted.",
            manual_review_recommended=True if interesting else False,
        )
    if category_key == "artifact":
        return NoExtractedReviewCandidate(
            relative_path=relative_path,
            file_type=file_type,
            outcome="No extracted secrets",
            recommendation="Review if context looks relevant",
            reason="Artifact matched the scan scope but yielded no actionable extraction.",
            manual_review_recommended=interesting,
        )

    if extension in DOCUMENT_LIKE_CREDENTIAL_EXTENSIONS:
        return NoExtractedReviewCandidate(
            relative_path=relative_path,
            file_type=file_type,
            outcome="No extracted credentials",
            recommendation="Manual review recommended",
            reason="Document matched credential-scan scope but yielded no extractable secrets.",
            manual_review_recommended=True,
        )
    if extension in TEXT_LIKE_CREDENTIAL_EXTENSIONS:
        return NoExtractedReviewCandidate(
            relative_path=relative_path,
            file_type=file_type,
            outcome="No extracted credentials",
            recommendation=(
                "Manual review recommended" if interesting else "Review if filename/context is relevant"
            ),
            reason="Text-like file matched credential-scan scope but automation extracted no candidates.",
            manual_review_recommended=interesting,
        )
    return NoExtractedReviewCandidate(
        relative_path=relative_path,
        file_type=file_type,
        outcome="No extracted findings",
        recommendation="Review if context looks relevant",
        reason="File matched the scan scope but no useful candidates were extracted.",
        manual_review_recommended=interesting,
    )


def _collect_no_extracted_review_candidates(
    *,
    loot_dir: str,
    category: str,
    limit: int,
    candidate_paths: list[str] | None = None,
) -> list[NoExtractedReviewCandidate]:
    """Collect deterministic manual-review candidates from one loot directory."""
    preview_paths = [
        str(item).strip()
        for item in list(candidate_paths or [])
        if str(item).strip()
    ]
    if preview_paths:
        preview_paths = preview_paths[: max(1, int(limit or 1))]
    else:
        preview_paths = collect_loot_file_preview(
            loot_dir=loot_dir,
            preview_limit=max(1, int(limit or 1)),
        )
    return [
        _classify_no_extracted_review_candidate(relative_path=item, category=category)
        for item in preview_paths
    ]


def _sort_no_extracted_review_candidates(
    candidates: list[NoExtractedReviewCandidate],
) -> list[NoExtractedReviewCandidate]:
    """Sort manual-review candidates by operational value and path stability."""
    return sorted(
        candidates,
        key=lambda item: (
            0 if item.manual_review_recommended else 1,
            item.file_type.lower(),
            item.relative_path.lower(),
        ),
    )


def _summarize_candidate_file_types(
    candidates: list[NoExtractedReviewCandidate],
    *,
    limit: int = 3,
) -> str:
    """Return a compact `type=count` summary for the most common file types."""
    counts = Counter(item.file_type for item in candidates if str(item.file_type).strip())
    parts = [f"{file_type}={count}" for file_type, count in counts.most_common(max(1, int(limit or 1)))]
    return ", ".join(parts) if parts else "-"


def _persist_no_extracted_review_candidates(
    *,
    loot_dir: str,
    loot_rel: str,
    category: str,
    analyzed_count: int,
    candidates: list[NoExtractedReviewCandidate],
    report_root_abs: str | None = None,
) -> str:
    """Persist review candidates for scans that analyzed files but extracted nothing."""
    phase_root_abs = str(report_root_abs or "").strip() or os.path.dirname(
        str(loot_dir or "").rstrip(os.sep)
    )
    report_path = os.path.join(phase_root_abs, "manual_review_candidates.json")
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    payload = {
        "category": str(category or "credential").strip().lower(),
        "loot": loot_rel,
        "analyzed_count": int(analyzed_count or 0),
        "saved_candidates": [
            {
                "relative_path": item.relative_path,
                "file_type": item.file_type,
                "outcome": item.outcome,
                "recommendation": item.recommendation,
                "reason": item.reason,
                "manual_review_recommended": bool(item.manual_review_recommended),
            }
            for item in candidates
        ],
    }
    with open(report_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
    return report_path


def render_no_extracted_findings_preview(
    *,
    loot_dir: str,
    loot_rel: str,
    analyzed_count: int,
    category: str = "credential",
    phase_label: str | None = None,
    candidate_paths: list[str] | None = None,
    report_root_abs: str | None = None,
    scope_label: str | None = None,
    preview_limit: int = 5,
) -> None:
    """Render one reusable premium review summary when extraction found nothing."""
    if int(analyzed_count or 0) <= 0:
        return
    category_key = str(category or "credential").strip().lower()
    candidates = _collect_no_extracted_review_candidates(
        loot_dir=loot_dir,
        category=category_key,
        limit=min(
            max(int(preview_limit or 1), _NO_EXTRACTED_TABLE_LIMIT),
            _NO_EXTRACTED_REPORT_LIMIT,
        ),
        candidate_paths=candidate_paths,
    )
    if not candidates:
        return
    ordered_candidates = _sort_no_extracted_review_candidates(candidates)
    message_prefix = {
        "artifact": "Analyzed artifacts with no extracted secrets or actionable child artifacts",
        "credential": "Analyzed files with no extracted credentials",
    }.get(category_key, "Analyzed files with no extracted findings")
    report_path = _persist_no_extracted_review_candidates(
        loot_dir=loot_dir,
        loot_rel=loot_rel,
        category=category_key,
        analyzed_count=analyzed_count,
        candidates=ordered_candidates,
        report_root_abs=report_root_abs,
    )
    manual_review_recommended = sum(1 for item in ordered_candidates if item.manual_review_recommended)
    file_type_summary = _summarize_candidate_file_types(ordered_candidates)

    if int(analyzed_count or 0) <= _NO_EXTRACTED_TABLE_LIMIT:
        table = Table(show_header=True, header_style="bold")
        table.add_column("File", style=BRAND_COLORS["warning"])
        table.add_column("Type", style=BRAND_COLORS["info"], no_wrap=True)
        table.add_column("Outcome", style=BRAND_COLORS["success"], no_wrap=True)
        table.add_column("Recommendation")
        for item in ordered_candidates:
            table.add_row(
                mark_sensitive(item.relative_path, "path"),
                mark_sensitive(item.file_type, "text"),
                item.outcome,
                rich_escape(item.recommendation),
            )
        title = (
            f"{phase_label} Manual Review Candidates"
            if str(phase_label or "").strip()
            else "Manual Review Candidates"
        )
        print_panel_with_table(
            table,
            border_style=BRAND_COLORS["warning"],
            title=title,
        )

    marked_preview = ", ".join(
        mark_sensitive(item.relative_path, "path")
        for item in ordered_candidates[:preview_limit]
    )
    extra = int(analyzed_count or 0) - min(
        int(analyzed_count or 0),
        len(ordered_candidates[:preview_limit]),
    )
    if extra > 0:
        marked_preview = f"{marked_preview}, +{extra} more"
    location_fragment = (
        f"loot={mark_sensitive(loot_rel, 'path')}"
        if str(loot_rel or "").strip()
        else (
            f"scope={mark_sensitive(scope_label, 'text')}"
            if str(scope_label or "").strip()
            else ""
        )
    )
    report_rel = os.path.relpath(report_path, os.getcwd())
    summary_title = (
        f"{phase_label} Review Summary"
        if str(phase_label or "").strip()
        else "Review Summary"
    )
    summary_lines = [
        f"Analyzed: {analyzed_count}",
        f"Manual review recommended: {manual_review_recommended}",
        f"Common file types: {file_type_summary}",
        f"Location: {loot_rel or scope_label or '-'}",
        f"Review report: {report_rel}",
    ]
    print_panel(
        "\n".join(summary_lines),
        title=f"[bold]{summary_title}[/bold]",
        border_style=BRAND_COLORS["info"],
        padding=(0, 1),
    )
    print_info(
        f"{message_prefix}: "
        f"count={analyzed_count} "
        f"manual_review_recommended={manual_review_recommended} "
        f"file_types={file_type_summary} "
        f"preview=[{marked_preview}] "
        f"{location_fragment} "
        f"review_report={mark_sensitive(report_rel, 'path')}"
    )


def persist_artifact_processing_report(
    *,
    phase_root_abs: str,
    records: list[ArtifactProcessingRecord],
) -> str:
    """Persist one artifact processing report as JSON and return its path."""
    normalized_records = [item for item in records if item is not None]
    report_path = os.path.join(phase_root_abs, "artifact_processing_report.json")
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    payload = {
        "records": [
            {
                "path": item.path,
                "filename": item.filename,
                "artifact_type": item.artifact_type,
                "status": item.status,
                "note": item.note,
                "manual_review": bool(item.manual_review),
                "details": dict(item.details or {}),
            }
            for item in normalized_records
        ]
    }
    with open(report_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
    return report_path


def artifact_records_extracted_nothing(
    records: list[ArtifactProcessingRecord],
) -> bool:
    """Return True when every processed artifact ended without actionable findings."""
    normalized_records = [item for item in records if item is not None]
    if not normalized_records:
        return False
    return all(
        str(item.status or "").strip().lower() == "processed_no_findings"
        for item in normalized_records
    )


def render_artifact_processing_summary(
    shell: Any,
    *,
    phase_label: str,
    records: list[ArtifactProcessingRecord],
    report_path: str,
) -> None:
    """Render one compact artifact-processing summary with paths and statuses."""
    if not records:
        return

    normalized_records = [item for item in records if item is not None]
    if not normalized_records:
        return

    ordered_records = sorted(
        normalized_records,
        key=lambda item: (
            0 if item.status == "manual_review" else 1 if item.status == "failed" else 2,
            item.filename.lower(),
            item.path.lower(),
        ),
    )
    table = Table(show_header=True, header_style="bold")
    table.add_column("File", style=BRAND_COLORS["warning"])
    table.add_column("Type", style=BRAND_COLORS["info"], no_wrap=True)
    table.add_column("Status", style=BRAND_COLORS["success"], no_wrap=True)
    table.add_column("Path")
    table.add_column("Notes")

    workspace_cwd = (
        shell._get_workspace_cwd()
        if callable(getattr(shell, "_get_workspace_cwd", None))
        else os.getcwd()
    )
    for item in ordered_records:
        try:
            display_path = os.path.relpath(item.path, workspace_cwd)
        except ValueError:
            display_path = item.path
        table.add_row(
            mark_sensitive(item.filename, "path"),
            mark_sensitive(item.artifact_type, "text"),
            _artifact_status_label(item.status),
            mark_sensitive(display_path, "path"),
            rich_escape(str(item.note or "")),
        )

    print_panel_with_table(
        table,
        border_style=BRAND_COLORS["warning"],
        title=f"{phase_label} Artifact Review Summary",
    )

    manual_review_count = sum(1 for item in normalized_records if item.manual_review)
    failed_count = sum(1 for item in normalized_records if item.status == "failed")
    print_info(
        "Artifact review summary: "
        f"processed={len(normalized_records) - manual_review_count - failed_count} "
        f"manual_review={manual_review_count} "
        f"failed={failed_count} "
        f"report={mark_sensitive(os.path.relpath(report_path, workspace_cwd), 'path')}"
    )
