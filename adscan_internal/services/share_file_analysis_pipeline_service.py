"""Reusable pipeline for deterministic + AI file analysis."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adscan_internal.services.base_service import BaseService
from adscan_internal.services.share_file_analyzer_service import (
    ShareFileAnalyzerService,
)
from adscan_internal.services.share_file_content_extraction_service import (
    ShareFileContentExtractionService,
)


@dataclass(frozen=True)
class ShareFilePipelineAnalysisResult:
    """Outcome of one source-agnostic file analysis execution."""

    source_path: str
    deterministic_handled: bool
    deterministic_summary: str
    deterministic_notes: list[str]
    deterministic_findings: list[Any]
    ai_attempted: bool
    ai_summary: str
    ai_findings: list[Any]
    extraction_mode: str
    extraction_notes: list[str]
    extraction_chars: int
    error_message: str | None = None


class ShareFileAnalysisPipelineService(BaseService):
    """Execute deterministic analyzers first, then AI fallback when needed."""

    def __init__(
        self,
        *,
        analyzer_service: ShareFileAnalyzerService | None = None,
        extraction_service: ShareFileContentExtractionService | None = None,
    ) -> None:
        """Initialize pipeline dependencies."""
        super().__init__()
        self._analyzer = analyzer_service or ShareFileAnalyzerService()
        self._extractor = extraction_service or ShareFileContentExtractionService()

    def analyze_from_bytes(
        self,
        *,
        domain: str,
        scope: str,
        candidate: Any,
        source_path: str,
        file_bytes: bytes,
        truncated: bool,
        max_bytes: int,
        triage_service: Any,
        ai_service: Any,
    ) -> ShareFilePipelineAnalysisResult:
        """Run deterministic analyzers and optional AI analysis for one file."""
        deterministic = self._analyzer.analyze(
            source_path=source_path,
            file_bytes=file_bytes,
            truncated=truncated,
        )
        if deterministic.handled and not deterministic.continue_with_ai:
            return ShareFilePipelineAnalysisResult(
                source_path=source_path,
                deterministic_handled=True,
                deterministic_summary=deterministic.summary,
                deterministic_notes=list(deterministic.notes),
                deterministic_findings=list(deterministic.findings),
                ai_attempted=False,
                ai_summary="",
                ai_findings=[],
                extraction_mode="",
                extraction_notes=[],
                extraction_chars=0,
            )

        extraction = self._extractor.extract_for_ai(
            source_path=source_path,
            file_bytes=file_bytes,
            truncated=truncated,
            max_bytes=max_bytes,
        )
        if not extraction.success:
            return ShareFilePipelineAnalysisResult(
                source_path=source_path,
                deterministic_handled=deterministic.handled,
                deterministic_summary=deterministic.summary,
                deterministic_notes=list(deterministic.notes),
                deterministic_findings=list(deterministic.findings),
                ai_attempted=False,
                ai_summary="",
                ai_findings=[],
                extraction_mode=extraction.mode,
                extraction_notes=list(extraction.notes),
                extraction_chars=0,
                error_message=extraction.error_message
                or "Could not extract readable content for AI analysis.",
            )

        analysis_prompt = triage_service.build_file_analysis_prompt_from_content(
            domain=domain,
            search_scope=scope,
            candidate=candidate,
            content_block=extraction.content_block,
            truncated=extraction.truncated,
            max_bytes=max_bytes,
            extraction_mode=extraction.mode,
            extraction_notes=extraction.notes,
        )
        analysis_response = ai_service.ask_once(
            analysis_prompt,
            allow_cli_actions=False,
        )
        analysis = triage_service.parse_file_analysis_response(
            response_text=analysis_response
        )
        return ShareFilePipelineAnalysisResult(
            source_path=source_path,
            deterministic_handled=deterministic.handled,
            deterministic_summary=deterministic.summary,
            deterministic_notes=list(deterministic.notes),
            deterministic_findings=list(deterministic.findings),
            ai_attempted=True,
            ai_summary=analysis.summary.strip(),
            ai_findings=list(analysis.credentials),
            extraction_mode=extraction.mode,
            extraction_notes=list(extraction.notes),
            extraction_chars=len(extraction.content_block),
        )
