"""Shared local Windows loot analysis helpers across transports."""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Any

from adscan_internal.cli.ntlm_hash_finding_flow import (
    render_ntlm_hash_findings_flow,
)
from adscan_internal.cli.scan_outcome_flow import (
    artifact_records_extracted_nothing,
    persist_artifact_processing_report,
    render_artifact_processing_summary,
    render_no_extracted_findings_preview,
)
from adscan_internal.services.credsweeper_service import (
    get_default_credsweeper_jobs,
)
from adscan_internal.services.loot_credential_analysis_service import (
    ENGINE_CREDSWEEPER,
    run_loot_credential_analysis,
)
from adscan_internal.services.spidering_service import ArtifactProcessingRecord


@dataclass(frozen=True, slots=True)
class WindowsCredentialLootAnalysisSummary:
    """Normalized summary for one credential-oriented local loot phase."""

    total_findings: int
    files_with_findings: int
    structured_files_with_findings: int
    loot_rel: str


@dataclass(frozen=True, slots=True)
class WindowsArtifactLootAnalysisSummary:
    """Normalized summary for one artifact-oriented local loot phase."""

    artifact_hits: int
    report_path: str | None = None
    loot_rel: str | None = None


def count_grouped_credential_findings(
    findings: dict[str, list[tuple[str, float | None, str, int | None, str]]],
) -> tuple[int, int]:
    """Return total findings and number of files with at least one finding."""
    total = 0
    files: set[str] = set()
    for entries in findings.values():
        if not isinstance(entries, list):
            continue
        total += len(entries)
        for entry in entries:
            if isinstance(entry, tuple) and len(entry) >= 5 and entry[4]:
                files.add(str(entry[4]))
    return total, len(files)


def list_files_under_path(root_path: str) -> list[str]:
    """Return all regular files under one local root."""
    collected: list[str] = []
    for current_root, _, files in os.walk(root_path):
        for filename in files:
            collected.append(os.path.join(current_root, filename))
    return collected


class WindowsLootAnalysisService:
    """Analyze already downloaded Windows loot independently of transport."""

    def analyze_credential_phase(
        self,
        shell: Any,
        *,
        domain: str,
        host: str,
        username: str,
        loot_dir: str,
        phase: str,
        phase_label: str,
        source_share: str,
        source_artifact: str,
        phase_root_abs: str,
    ) -> WindowsCredentialLootAnalysisSummary | None:
        """Run shared credential analysis over one local loot directory."""
        credsweeper_path = str(getattr(shell, "credsweeper_path", "") or "").strip()
        if not credsweeper_path:
            return None

        analysis_result = run_loot_credential_analysis(
            shell,
            domain=domain,
            loot_dir=loot_dir,
            phase=phase,
            phase_label=phase_label,
            candidate_files=len(list_files_under_path(loot_dir)),
            analysis_context={
                "ai_configured": False,
                "credential_analysis_engine_by_phase": {phase: ENGINE_CREDSWEEPER},
            },
            ai_history_path="",
            credsweeper_path=credsweeper_path,
            credsweeper_output_dir=os.path.join(phase_root_abs, "credsweeper"),
            jobs=get_default_credsweeper_jobs(),
            credsweeper_findings=None,
        )
        findings = dict(analysis_result.findings)
        structured_stats = shell._get_spidering_service().process_local_structured_files(
            root_path=loot_dir,
            phase=phase,
            domain=domain,
            source_hosts=[host],
            source_shares=[source_share],
            auth_username=username,
            apply_actions=True,
        )
        total_findings, files_with_findings = count_grouped_credential_findings(findings)
        structured_files_with_findings = int(
            structured_stats.get("files_with_findings", 0) or 0
        )
        ntlm_hash_findings = structured_stats.get("ntlm_hash_findings")
        if findings:
            shell.handle_found_credentials(
                findings,
                domain,
                source_hosts=[host],
                source_shares=[source_share],
                auth_username=username,
                source_artifact=source_artifact,
            )
        loot_rel = os.path.relpath(loot_dir, shell._get_workspace_cwd())
        if isinstance(ntlm_hash_findings, list) and ntlm_hash_findings:
            render_ntlm_hash_findings_flow(
                shell,
                domain=domain,
                loot_dir=loot_dir,
                loot_rel=loot_rel,
                phase_label=phase_label,
                ntlm_hash_findings=[
                    item for item in ntlm_hash_findings if isinstance(item, dict)
                ],
                source_scope=f"{source_share.upper()} file NTLM hash findings from {phase_label}",
                fallback_source_hosts=[host],
                fallback_source_shares=[source_share],
            )
        if not findings and structured_files_with_findings == 0:
            render_no_extracted_findings_preview(
                loot_dir=loot_dir,
                loot_rel=loot_rel,
                analyzed_count=len(list_files_under_path(loot_dir)),
                category="credential",
                phase_label=phase_label,
                preview_limit=5,
            )
        return WindowsCredentialLootAnalysisSummary(
            total_findings=total_findings,
            files_with_findings=files_with_findings,
            structured_files_with_findings=structured_files_with_findings,
            loot_rel=loot_rel,
        )

    def analyze_artifact_phase(
        self,
        shell: Any,
        *,
        domain: str,
        host: str,
        username: str,
        loot_dir: str,
        phase_label: str,
        source_share: str,
        phase_root_abs: str,
    ) -> WindowsArtifactLootAnalysisSummary:
        """Run shared artifact analysis over one local loot directory."""
        spidering_service = shell._get_spidering_service()
        artifact_records: list[ArtifactProcessingRecord] = []
        for file_path in list_files_under_path(loot_dir):
            artifact_records.append(
                spidering_service.process_found_file(
                    file_path,
                    domain,
                    "ext",
                    source_hosts=[host],
                    source_shares=[source_share],
                    auth_username=username,
                    enable_legacy_zip_callbacks=False,
                    apply_actions=True,
                )
            )
        loot_rel = os.path.relpath(loot_dir, shell._get_workspace_cwd())
        report_path: str | None = None
        if artifact_records:
            report_path = persist_artifact_processing_report(
                phase_root_abs=phase_root_abs,
                records=artifact_records,
            )
            render_artifact_processing_summary(
                shell,
                phase_label=phase_label,
                records=artifact_records,
                report_path=report_path,
            )
            if artifact_records_extracted_nothing(artifact_records):
                render_no_extracted_findings_preview(
                    loot_dir=loot_dir,
                    loot_rel=loot_rel,
                    analyzed_count=len(list_files_under_path(loot_dir)),
                    category="artifact",
                    phase_label=phase_label,
                    preview_limit=5,
                )
        elif list_files_under_path(loot_dir):
            render_no_extracted_findings_preview(
                loot_dir=loot_dir,
                loot_rel=loot_rel,
                analyzed_count=len(list_files_under_path(loot_dir)),
                category="artifact",
                phase_label=phase_label,
                preview_limit=5,
            )
        return WindowsArtifactLootAnalysisSummary(
            artifact_hits=len(artifact_records),
            report_path=report_path,
            loot_rel=loot_rel,
        )


__all__ = [
    "WindowsArtifactLootAnalysisSummary",
    "WindowsCredentialLootAnalysisSummary",
    "WindowsLootAnalysisService",
    "count_grouped_credential_findings",
    "list_files_under_path",
]
