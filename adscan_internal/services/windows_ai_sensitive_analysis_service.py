"""Shared AI-assisted Windows sensitive-file analysis across transports."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Callable

from rich.table import Table
import rich.box

from adscan_internal import (
    print_exception,
    print_info,
    print_info_debug,
    print_warning,
    print_warning_debug,
    telemetry,
)
from adscan_internal.cli.scan_outcome_flow import render_no_extracted_findings_preview
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.share_file_analysis_pipeline_service import (
    ShareFileAnalysisPipelineService,
)
from adscan_internal.services.share_file_analyzer_service import (
    ShareFileAnalyzerService,
)
from adscan_internal.services.share_file_content_extraction_service import (
    ShareFileContentExtractionService,
)
from adscan_internal.services.share_credential_provenance_service import (
    ShareCredentialProvenanceService,
)
from adscan_internal.services.share_map_ai_triage_service import ShareMapAITriageService
from adscan_internal.services.windows_artifact_acquisition_service import (
    WindowsArtifactAcquisitionResult,
    persist_fetch_report,
)
from adscan_internal.services.windows_file_mapping_service import (
    WindowsFileMapEntry,
    WindowsFileMappingService,
)


SelectedEntryFetcher = Callable[[list[WindowsFileMapEntry], str], WindowsArtifactAcquisitionResult]
RenderFindingsTableCallback = Callable[[Any, Any, list[Any], str], None]
HandleFindingsActionsCallback = Callable[..., bool]
SkipDomainPredicate = Callable[[Any, str], bool]


@dataclass(frozen=True, slots=True)
class WindowsAISensitiveAnalysisResult:
    """Normalized result for one AI-prioritized Windows analysis flow."""

    completed: bool
    prioritized_files: int = 0
    analyzed: int = 0
    files_with_findings: int = 0
    credential_like_findings: int = 0
    fetch_seconds: float = 0.0
    analysis_seconds: float = 0.0
    fetch_report_path: str | None = None
    loot_dir: str | None = None
    skipped: bool = False
    reason: str | None = None
    aborted_due_to_auth_invalid: bool = False
    auth_invalid_reason: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return the historical dict payload shape used by CLI callers."""
        payload: dict[str, Any] = {
            "completed": self.completed,
            "prioritized_files": self.prioritized_files,
            "analyzed": self.analyzed,
            "files_with_findings": self.files_with_findings,
            "credential_like_findings": self.credential_like_findings,
            "fetch_seconds": float(self.fetch_seconds),
            "analysis_seconds": float(self.analysis_seconds),
        }
        if self.fetch_report_path is not None:
            payload["fetch_report_path"] = self.fetch_report_path
        if self.loot_dir is not None:
            payload["loot_dir"] = self.loot_dir
        if self.skipped:
            payload["skipped"] = True
        if self.reason is not None:
            payload["reason"] = self.reason
        if self.aborted_due_to_auth_invalid:
            payload["aborted_due_to_auth_invalid"] = True
            payload["auth_invalid_reason"] = self.auth_invalid_reason
        if self.error is not None:
            payload["error"] = self.error
        return payload


class WindowsAISensitiveAnalysisService:
    """Run AI-prioritized file analysis for any Windows transport."""

    def execute(
        self,
        shell: Any,
        *,
        domain: str,
        host: str,
        username: str,
        entries: list[WindowsFileMapEntry],
        run_root_abs: str,
        workflow_label: str,
        source_share: str,
        artifact_transport_folder: str,
        select_scope: Callable[[Any], str | None],
        should_inspect_prioritized_files: Callable[[Any], bool],
        should_continue_after_findings: Callable[[Any, str], bool],
        skip_for_pwned_ctf: SkipDomainPredicate,
        fetch_selected_entries: SelectedEntryFetcher,
        render_findings_table: RenderFindingsTableCallback,
        handle_findings_actions: HandleFindingsActionsCallback,
    ) -> WindowsAISensitiveAnalysisResult:
        """Execute one AI-assisted prioritized-files workflow."""
        ai_service = shell._get_ai_service()
        if ai_service is None:
            print_warning(f"AI service is not available; skipping {workflow_label} AI analysis.")
            return WindowsAISensitiveAnalysisResult(
                completed=False,
                error="ai_service_unavailable",
            )

        scope = select_scope(shell)
        if scope is None:
            print_info(f"{workflow_label} AI analysis skipped by user.")
            return WindowsAISensitiveAnalysisResult(completed=False, skipped=True)

        triage_service = ShareMapAITriageService()
        mapping_json = self._build_mapping_json(
            host=host,
            entries=entries,
            source_share=source_share,
        )
        print_info_debug(
            f"{workflow_label} AI triage manifest prepared: "
            f"host={mark_sensitive(host, 'hostname')} chars={len(mapping_json)}"
        )
        response = ai_service.ask_once(
            triage_service.build_triage_prompt(
                domain=domain,
                search_scope=scope,
                mapping_json=mapping_json,
            ),
            allow_cli_actions=False,
        )
        triage_parse = triage_service.parse_triage_response(response_text=response)
        prioritized_files = triage_parse.prioritized_files
        self._render_prioritization_summary(
            prioritized_files=prioritized_files,
            total_files=triage_service.count_total_file_entries(mapping_json=mapping_json),
            workflow_label=workflow_label,
        )
        if not prioritized_files:
            print_warning(f"{workflow_label} AI triage did not return valid prioritized files.")
            return WindowsAISensitiveAnalysisResult(
                completed=False,
                error="no_priority_files",
            )
        if skip_for_pwned_ctf(shell, domain):
            print_info(
                f"Skipping {workflow_label} AI prioritized file inspection because the CTF domain is already pwned."
            )
            return WindowsAISensitiveAnalysisResult(
                completed=False,
                skipped=True,
                reason="ctf_domain_pwned",
            )
        if not should_inspect_prioritized_files(shell):
            print_info(f"{workflow_label} AI prioritized file inspection cancelled by user.")
            return WindowsAISensitiveAnalysisResult(completed=False, skipped=True)

        entry_index = {
            str(entry.full_name).strip().lower(): entry
            for entry in entries
            if str(entry.full_name).strip()
        }
        selected_entries: list[WindowsFileMapEntry] = []
        for candidate in prioritized_files:
            match = entry_index.get(str(getattr(candidate, "path", "")).strip().lower())
            if match is not None:
                selected_entries.append(match)
        if not selected_entries:
            print_warning(
                f"{workflow_label} AI triage selected files that were not present in the current manifest."
            )
            return WindowsAISensitiveAnalysisResult(
                completed=False,
                error="priority_files_not_in_manifest",
            )

        phase_root_abs = os.path.join(run_root_abs, "ai_prioritized")
        loot_dir = os.path.join(phase_root_abs, "loot")
        os.makedirs(loot_dir, exist_ok=True)
        fetch_started_at = time.perf_counter()
        fetch_result = fetch_selected_entries(selected_entries, loot_dir)
        fetch_duration_seconds = time.perf_counter() - fetch_started_at
        fetch_report_path = persist_fetch_report(
            phase_root_abs=phase_root_abs,
            fetch_result=fetch_result,
        )
        if fetch_result.auth_invalid_abort:
            print_warning(
                f"{workflow_label} AI analysis aborted because the {workflow_label} credentials "
                "became invalid during file fetch."
            )
            return WindowsAISensitiveAnalysisResult(
                completed=False,
                aborted_due_to_auth_invalid=True,
                auth_invalid_reason=fetch_result.auth_invalid_reason,
                fetch_report_path=fetch_report_path,
            )

        pipeline_service = ShareFileAnalysisPipelineService(
            analyzer_service=ShareFileAnalyzerService(
                command_executor=getattr(shell, "run_command", None),
                pypykatz_path=getattr(shell, "pypykatz_path", None),
            ),
            extraction_service=ShareFileContentExtractionService(),
        )
        provenance_service = ShareCredentialProvenanceService()
        max_bytes = 10 * 1024 * 1024
        analyzed = 0
        deterministic_handled = 0
        deterministic_findings = 0
        read_failures = 0
        flagged_files = 0
        flagged_credentials = 0
        review_candidate_paths: list[str] = []
        continue_after_findings: bool | None = None
        analysis_started_at = time.perf_counter()
        for candidate in prioritized_files:
            remote_path = str(getattr(candidate, "path", "") or "").strip()
            local_path = os.path.join(
                loot_dir,
                WindowsFileMappingService.build_local_relative_path(remote_path),
            )
            if not os.path.isfile(local_path):
                read_failures += 1
                print_warning_debug(
                    f"{workflow_label} AI prioritized file missing from fetched loot: "
                    f"path={mark_sensitive(remote_path, 'path')}"
                )
                continue
            file_bytes = Path(local_path).read_bytes()
            pipeline_result = pipeline_service.analyze_from_bytes(
                domain=domain,
                scope=scope,
                candidate=candidate,
                source_path=remote_path,
                file_bytes=file_bytes,
                truncated=False,
                max_bytes=max_bytes,
                triage_service=triage_service,
                ai_service=ai_service,
            )
            if pipeline_result.deterministic_handled:
                deterministic_handled += 1
                if pipeline_result.deterministic_findings:
                    keepass_findings = [
                        finding
                        for finding in pipeline_result.deterministic_findings
                        if str(getattr(finding, "credential_type", "") or "").strip().lower()
                        == "keepass_artifact"
                    ]
                    if keepass_findings:
                        persisted_artifact = self._persist_prioritized_artifact_bytes(
                            shell=shell,
                            domain=domain,
                            host=host,
                            remote_path=remote_path,
                            file_bytes=file_bytes,
                            artifact_transport_folder=artifact_transport_folder,
                        )
                        try:
                            extracted_entries = int(
                                shell._process_keepass_artifact(
                                    domain,
                                    persisted_artifact,
                                    [host],
                                    [source_share],
                                    username,
                                )
                                or 0
                            )
                        except Exception as exc:  # noqa: BLE001
                            telemetry.capture_exception(exc)
                            extracted_entries = 0
                            print_warning(
                                f"Could not process KeePass artifact {mark_sensitive(remote_path, 'path')} deterministically."
                            )
                            print_exception(exception=exc)
                        finding_count = max(1, extracted_entries)
                        deterministic_findings += finding_count
                        flagged_files += 1
                        flagged_credentials += finding_count
                    else:
                        deterministic_findings += len(pipeline_result.deterministic_findings)
                        flagged_files += 1
                        flagged_credentials += len(pipeline_result.deterministic_findings)
                        render_findings_table(
                            shell,
                            candidate,
                            pipeline_result.deterministic_findings,
                            "Deterministic",
                        )
                        if not handle_findings_actions(
                            shell=shell,
                            domain=domain,
                            candidate=candidate,
                            findings=pipeline_result.deterministic_findings,
                            auth_username=username,
                            provenance_service=provenance_service,
                        ):
                            continue_after_findings = False
                        if continue_after_findings is None:
                            continue_after_findings = should_continue_after_findings(
                                shell, domain
                            )
                        if continue_after_findings is False:
                            break
                else:
                    review_candidate_paths.append(f"{host}/{source_share}/{remote_path}")
            if pipeline_result.error_message:
                read_failures += 1
                print_warning_debug(
                    f"{workflow_label} AI extraction failure: "
                    f"path={mark_sensitive(remote_path, 'path')} error={pipeline_result.error_message}"
                )
                continue
            if pipeline_result.ai_attempted:
                analyzed += 1
                if pipeline_result.ai_summary:
                    print_info(
                        f"AI summary for {mark_sensitive(remote_path, 'path')}: {pipeline_result.ai_summary}"
                    )
                if pipeline_result.ai_findings:
                    flagged_files += 1
                    flagged_credentials += len(pipeline_result.ai_findings)
                    render_findings_table(
                        shell,
                        candidate,
                        pipeline_result.ai_findings,
                        "AI",
                    )
                    if not handle_findings_actions(
                        shell=shell,
                        domain=domain,
                        candidate=candidate,
                        findings=pipeline_result.ai_findings,
                        auth_username=username,
                        provenance_service=provenance_service,
                    ):
                        continue_after_findings = False
                    if continue_after_findings is None:
                        continue_after_findings = should_continue_after_findings(
                            shell, domain
                        )
                    if continue_after_findings is False:
                        break
                else:
                    review_candidate_paths.append(f"{host}/{source_share}/{remote_path}")
        analysis_duration_seconds = time.perf_counter() - analysis_started_at
        if flagged_files == 0 and review_candidate_paths:
            render_no_extracted_findings_preview(
                loot_dir=loot_dir,
                loot_rel=os.path.relpath(loot_dir, shell._get_workspace_cwd()),
                analyzed_count=len(review_candidate_paths),
                category="mixed",
                phase_label="AI prioritized file analysis",
                candidate_paths=review_candidate_paths,
                report_root_abs=phase_root_abs,
                scope_label=f"AI prioritized {workflow_label} files",
                preview_limit=5,
            )
        print_info(
            f"{workflow_label} AI analysis summary: "
            f"prioritized_files={len(prioritized_files)} analyzed={analyzed} deterministic_handled={deterministic_handled} "
            f"deterministic_findings={deterministic_findings} read_failures={read_failures} files_with_findings={flagged_files} "
            f"credential_like_findings={flagged_credentials} fetch_seconds={fetch_duration_seconds:.2f} analysis_seconds={analysis_duration_seconds:.2f} "
            f"loot={mark_sensitive(os.path.relpath(loot_dir, shell._get_workspace_cwd()), 'path')} "
            f"fetch_report={mark_sensitive(os.path.relpath(fetch_report_path, shell._get_workspace_cwd()), 'path')}"
        )
        return WindowsAISensitiveAnalysisResult(
            completed=True,
            prioritized_files=len(prioritized_files),
            analyzed=analyzed,
            files_with_findings=flagged_files,
            credential_like_findings=flagged_credentials,
            fetch_seconds=float(fetch_duration_seconds),
            analysis_seconds=float(analysis_duration_seconds),
            fetch_report_path=fetch_report_path,
            loot_dir=loot_dir,
        )

    @staticmethod
    def _build_mapping_json(
        *,
        host: str,
        entries: list[WindowsFileMapEntry],
        source_share: str,
    ) -> str:
        """Build a synthetic share-map JSON payload for AI triage."""
        files: dict[str, dict[str, str]] = {}
        for entry in entries:
            full_name = str(entry.full_name or "").strip()
            if not full_name:
                continue
            size = int(entry.length or 0)
            files[full_name] = {"size": f"{size} B"}
        payload = {
            "hosts": {
                str(host).strip(): {
                    "shares": {source_share: {"files": files}}
                }
            }
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def _render_prioritization_summary(
        *,
        prioritized_files: list[Any],
        total_files: int,
        workflow_label: str,
    ) -> None:
        """Render a transport-neutral prioritized-files summary."""
        selected = len(prioritized_files)
        print_info(
            f"AI triage selected {selected} prioritized file(s) out of {total_files} total mapped file(s)."
        )
        if not prioritized_files:
            return
        table = Table(
            title=f"[bold cyan]AI Prioritized {workflow_label} Files[/bold cyan]",
            header_style="bold magenta",
            box=rich.box.SIMPLE_HEAVY,
        )
        table.add_column("#", style="cyan", justify="right")
        table.add_column("Host", style="cyan")
        table.add_column("Source", style="magenta")
        table.add_column("Path", style="yellow")
        table.add_column("Why", style="green")
        for idx, candidate in enumerate(prioritized_files, start=1):
            host = mark_sensitive(str(getattr(candidate, "host", "")), "hostname")
            share = mark_sensitive(str(getattr(candidate, "share", "")), "service")
            path = mark_sensitive(str(getattr(candidate, "path", "")), "path")
            why = str(getattr(candidate, "why", "") or "").strip()
            if len(why) > 120:
                why = why[:117] + "..."
            table.add_row(str(idx), host, share, path, why or "-")
        from adscan_internal import print_panel_with_table
        from adscan_internal.rich_output import BRAND_COLORS

        print_panel_with_table(table, border_style=BRAND_COLORS["info"])

    @staticmethod
    def _persist_prioritized_artifact_bytes(
        *,
        shell: Any,
        domain: str,
        host: str,
        remote_path: str,
        file_bytes: bytes,
        artifact_transport_folder: str,
    ) -> str:
        """Persist one AI-prioritized artifact into the workspace."""
        workspace_cwd = shell._get_workspace_cwd()
        filename = Path(remote_path or "artifact.bin").name or "artifact.bin"
        artifact_root = os.path.join(
            workspace_cwd,
            shell.domains_dir,
            domain,
            artifact_transport_folder,
            "ai_prioritized_artifacts",
            re.sub(r"[^A-Za-z0-9._-]+", "_", str(host).strip() or "unknown_host"),
        )
        os.makedirs(artifact_root, exist_ok=True)
        target_path = os.path.join(artifact_root, filename)
        with open(target_path, "wb") as handle:
            handle.write(file_bytes)
        print_info_debug(
            "Persisted prioritized artifact bytes: "
            f"path={mark_sensitive(target_path, 'path')}"
        )
        return target_path


__all__ = [
    "WindowsAISensitiveAnalysisResult",
    "WindowsAISensitiveAnalysisService",
]
