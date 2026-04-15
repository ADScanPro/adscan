"""Shared orchestration for one downloaded Windows sensitive-data phase."""

from __future__ import annotations

from dataclasses import dataclass
import os
import time
from typing import Any, Callable

from adscan_internal import print_info, print_warning
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.smb_sensitive_file_policy import (
    SMB_SENSITIVE_SCAN_PHASE_DOCUMENT_CREDENTIALS,
    SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS,
)
from adscan_internal.services.windows_artifact_acquisition_service import (
    WindowsArtifactAcquisitionResult,
    persist_fetch_report,
    summarize_fetch_skip_reasons,
)
from adscan_internal.services.windows_loot_analysis_service import (
    WindowsLootAnalysisService,
)


PhaseFetcher = Callable[[], WindowsArtifactAcquisitionResult]


@dataclass(frozen=True, slots=True)
class WindowsSensitivePhaseExecutionResult:
    """Normalized outcome for one transport-agnostic Windows sensitive phase."""

    completed: bool
    phase: str
    loot_dir: str
    candidate_files: int
    phase_excluded_candidates: int
    fetched_files: int = 0
    fetch_seconds: float = 0.0
    analysis_seconds: float = 0.0
    fetch_report_path: str | None = None
    credential_findings: int = 0
    files_with_findings: int = 0
    artifact_hits: int = 0
    aborted_due_to_auth_invalid: bool = False
    auth_invalid_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return the historical dict shape expected by current CLI callers."""
        payload: dict[str, Any] = {
            "completed": self.completed,
            "phase": self.phase,
            "loot_dir": self.loot_dir,
            "candidate_files": self.candidate_files,
            "phase_excluded_candidates": self.phase_excluded_candidates,
            "fetched_files": self.fetched_files,
            "fetch_seconds": float(self.fetch_seconds),
            "analysis_seconds": float(self.analysis_seconds),
        }
        if self.fetch_report_path is not None:
            payload["fetch_report_path"] = self.fetch_report_path
        if self.credential_findings:
            payload["credential_findings"] = int(self.credential_findings)
        else:
            payload["credential_findings"] = 0
        if self.files_with_findings:
            payload["files_with_findings"] = int(self.files_with_findings)
        else:
            payload["files_with_findings"] = 0
        if self.artifact_hits:
            payload["artifact_hits"] = int(self.artifact_hits)
        else:
            payload["artifact_hits"] = 0
        if self.aborted_due_to_auth_invalid:
            payload["aborted_due_to_auth_invalid"] = True
            payload["auth_invalid_reason"] = self.auth_invalid_reason
        return payload


class WindowsSensitivePhaseExecutionService:
    """Run one downloaded Windows-sensitive phase independently of transport."""

    def execute_phase(
        self,
        shell: Any,
        *,
        domain: str,
        host: str,
        username: str,
        phase: str,
        phase_label: str,
        phase_root_abs: str,
        loot_dir: str,
        selected_entries_count: int,
        phase_excluded_total: int,
        fetcher: PhaseFetcher,
        source_share: str,
        source_artifact: str,
        transport_label: str,
    ) -> WindowsSensitivePhaseExecutionResult:
        """Fetch and analyze one local loot phase."""
        fetch_started_at = time.perf_counter()
        fetch_result = fetcher()
        fetch_duration_seconds = time.perf_counter() - fetch_started_at
        fetch_report_path = persist_fetch_report(
            phase_root_abs=phase_root_abs,
            fetch_result=fetch_result,
        )
        fetch_skip_summary = summarize_fetch_skip_reasons(
            list(fetch_result.skipped_files or []) + list(fetch_result.per_file_failures or [])
        )
        downloaded_files = list(fetch_result.downloaded_files)

        if fetch_result.auth_invalid_abort:
            print_warning(
                f"Deterministic {transport_label} phase aborted early because the "
                f"{transport_label} credentials became invalid during the fetch stage."
            )
            return WindowsSensitivePhaseExecutionResult(
                completed=False,
                phase=phase,
                loot_dir=loot_dir,
                candidate_files=selected_entries_count,
                phase_excluded_candidates=phase_excluded_total,
                fetched_files=len(downloaded_files),
                fetch_seconds=float(fetch_duration_seconds),
                fetch_report_path=fetch_report_path,
                aborted_due_to_auth_invalid=True,
                auth_invalid_reason=fetch_result.auth_invalid_reason,
            )

        analysis_service = WindowsLootAnalysisService()
        if phase in {
            SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS,
            SMB_SENSITIVE_SCAN_PHASE_DOCUMENT_CREDENTIALS,
        }:
            analysis_started_at = time.perf_counter()
            credential_summary = analysis_service.analyze_credential_phase(
                shell,
                domain=domain,
                host=host,
                username=username,
                loot_dir=loot_dir,
                phase=phase,
                phase_label=phase_label,
                source_share=source_share,
                source_artifact=source_artifact,
                phase_root_abs=phase_root_abs,
            )
            analysis_duration_seconds = time.perf_counter() - analysis_started_at
            if credential_summary is None:
                print_warning(
                    f"CredSweeper is not configured; skipping {transport_label} credential scan."
                )
                return WindowsSensitivePhaseExecutionResult(
                    completed=False,
                    phase=phase,
                    loot_dir=loot_dir,
                    candidate_files=selected_entries_count,
                    phase_excluded_candidates=phase_excluded_total,
                )

            print_info(
                f"Deterministic {transport_label} phase summary: "
                f"phase={mark_sensitive(phase_label, 'text')} "
                f"candidate_files={selected_entries_count} "
                f"phase_excluded_candidates={phase_excluded_total} "
                f"fetched_files={len(downloaded_files)} "
                f"fetch_seconds={fetch_duration_seconds:.2f} "
                f"analysis_seconds={analysis_duration_seconds:.2f} "
                f"fetch_skipped_access_denied={fetch_skip_summary['access_denied']} "
                f"fetch_skipped_file_in_use={fetch_skip_summary['file_in_use']} "
                f"fetch_skipped_other={fetch_skip_summary['other']} "
                f"files_with_findings={credential_summary.files_with_findings + credential_summary.structured_files_with_findings} "
                f"credential_like_findings={credential_summary.total_findings} "
                f"loot={mark_sensitive(credential_summary.loot_rel, 'path')} "
                f"fetch_report={mark_sensitive(os.path.relpath(fetch_report_path, shell._get_workspace_cwd()), 'path')}"
            )
            return WindowsSensitivePhaseExecutionResult(
                completed=True,
                phase=phase,
                loot_dir=loot_dir,
                candidate_files=selected_entries_count,
                phase_excluded_candidates=phase_excluded_total,
                fetched_files=len(downloaded_files),
                fetch_seconds=float(fetch_duration_seconds),
                analysis_seconds=float(analysis_duration_seconds),
                fetch_report_path=fetch_report_path,
                credential_findings=int(credential_summary.total_findings),
                files_with_findings=int(
                    credential_summary.files_with_findings
                    + credential_summary.structured_files_with_findings
                ),
            )

        analysis_started_at = time.perf_counter()
        artifact_summary = analysis_service.analyze_artifact_phase(
            shell,
            domain=domain,
            host=host,
            username=username,
            loot_dir=loot_dir,
            phase_label=phase_label,
            source_share=source_share,
            phase_root_abs=phase_root_abs,
        )
        analysis_duration_seconds = time.perf_counter() - analysis_started_at
        print_info(
            f"Deterministic {transport_label} artifact summary: "
            f"phase={mark_sensitive(phase_label, 'text')} "
            f"candidate_files={selected_entries_count} "
            f"phase_excluded_candidates={phase_excluded_total} "
            f"fetched_files={len(downloaded_files)} "
            f"fetch_seconds={fetch_duration_seconds:.2f} "
            f"analysis_seconds={analysis_duration_seconds:.2f} "
            f"fetch_skipped_access_denied={fetch_skip_summary['access_denied']} "
            f"fetch_skipped_file_in_use={fetch_skip_summary['file_in_use']} "
            f"fetch_skipped_other={fetch_skip_summary['other']} "
            f"artifact_hits={artifact_summary.artifact_hits} "
            f"loot={mark_sensitive(str(artifact_summary.loot_rel or ''), 'path')} "
            f"fetch_report={mark_sensitive(os.path.relpath(fetch_report_path, shell._get_workspace_cwd()), 'path')}"
        )
        return WindowsSensitivePhaseExecutionResult(
            completed=True,
            phase=phase,
            loot_dir=loot_dir,
            candidate_files=selected_entries_count,
            phase_excluded_candidates=phase_excluded_total,
            fetched_files=len(downloaded_files),
            fetch_seconds=float(fetch_duration_seconds),
            analysis_seconds=float(analysis_duration_seconds),
            fetch_report_path=fetch_report_path,
            artifact_hits=artifact_summary.artifact_hits,
        )


__all__ = [
    "WindowsSensitivePhaseExecutionResult",
    "WindowsSensitivePhaseExecutionService",
]
