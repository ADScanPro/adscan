"""Reusable pipeline for deterministic + AI file analysis."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adscan_internal.services.base_service import BaseService
from adscan_internal.services.share_file_analyzer_service import (
    ShareFileAnalyzerFinding,
    ShareFileAnalyzerService,
)
from adscan_internal.services.share_file_content_extraction_service import (
    ShareFileContentExtractionService,
)


def _vm_credentials_to_findings(credentials: list[Any]) -> list[ShareFileAnalyzerFinding]:
    """Map recovered VM-artifact credentials to deterministic finding records."""
    findings: list[ShareFileAnalyzerFinding] = []
    for cred in credentials:
        nt_hash = getattr(cred, "nt_hash", None)
        plaintext = getattr(cred, "secret", None)
        kind = str(getattr(cred, "kind", "") or "unknown")
        rid = getattr(cred, "rid", None)
        secret = nt_hash or plaintext or "-"
        credential_type = f"vm_{kind}_hash" if nt_hash else f"vm_{kind}_secret"
        evidence = f"VM artifact ({getattr(cred, 'source', '') or 'disk'})"
        if rid is not None:
            evidence = f"{evidence} RID {rid}"
        findings.append(
            ShareFileAnalyzerFinding(
                credential_type=credential_type,
                username=str(getattr(cred, "principal", "") or "-"),
                secret=str(secret),
                confidence="high",
                evidence=evidence,
            )
        )
    return findings


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

    def analyze_vm_disk_candidate(
        self,
        *,
        shell: Any,
        domain: str,
        host: str,
        share: str,
        source_path: str,
        size: int,
        vm_service: Any = None,
    ) -> ShareFilePipelineAnalysisResult | None:
        """Sparse-extract credentials from a self-contained VM disk on a share.

        This is the single dispatch chokepoint for VM disk/memory artifacts: every
        share-analysis flow should call it FIRST, before the byte-based path, and
        only fall back to ``analyze_from_bytes`` when this returns ``None``.

        Returns ``None`` when ``source_path`` is not a VM disk image (caller uses the
        bytes path). When it IS, dissect reads the remote disk SPARSELY over aiosmb
        ranged reads — the multi-GB image is never downloaded — and recovered
        credentials are returned as deterministic findings, shaped exactly like
        :meth:`analyze_from_bytes` so the caller's findings handling is unchanged.

        Only self-contained disks (monolithic ``.vhdx``/``.vhd``/``.vmdk``) are
        handled here; split/snapshot-chain VMware disks need their sibling files and
        must be fetched locally by the caller.
        """
        from adscan_internal.services.vm_artifact_service import (
            VMArtifactService,
            classify_vm_artifact,
        )

        if classify_vm_artifact(source_path) != "disk":
            return None

        service = vm_service or VMArtifactService()
        extraction = service.extract_from_smb_disk(
            shell=shell,
            domain=domain,
            host=host,
            share=share,
            source_path=source_path,
            size=size,
        )
        return self._vm_extraction_to_result(
            extraction=extraction,
            source_path=source_path,
            extraction_mode="vm_disk_sparse",
        )

    def analyze_vm_disk_local(
        self,
        *,
        source_path: str,
        local_path: str,
        vm_service: Any = None,
    ) -> ShareFilePipelineAnalysisResult | None:
        """Extract credentials from a VM disk already present on the LOCAL filesystem.

        For the CIFS-mounted-share backend the artifact is a local path, so dissect
        opens it directly — this also handles split/snapshot-chain VMware disks
        (all sibling files are visible under the mount) and the CIFS layer reads
        sparsely over SMB underneath. Returns ``None`` when ``source_path`` is not a
        VM disk image (caller uses the bytes path).
        """
        from adscan_internal.services.vm_artifact_service import (
            VMArtifactService,
            classify_vm_artifact,
        )

        if classify_vm_artifact(source_path) != "disk":
            return None
        service = vm_service or VMArtifactService()
        extraction = service.extract_from_disk_source(source_path=local_path)
        return self._vm_extraction_to_result(
            extraction=extraction,
            source_path=source_path,
            extraction_mode="vm_disk_local",
        )

    @staticmethod
    def _vm_extraction_to_result(
        *,
        extraction: Any,
        source_path: str,
        extraction_mode: str,
    ) -> ShareFilePipelineAnalysisResult:
        """Shape a VM artifact extraction result like an analyze_from_bytes result."""
        findings = _vm_credentials_to_findings(extraction.credentials)
        summary = (
            f"VM disk artifact yielded {len(findings)} credential(s)."
            if findings
            else "VM disk artifact analysis recovered no credentials."
        )
        return ShareFilePipelineAnalysisResult(
            source_path=source_path,
            deterministic_handled=bool(extraction.handled),
            deterministic_summary=summary,
            deterministic_notes=list(extraction.notes),
            deterministic_findings=findings,
            ai_attempted=False,
            ai_summary="",
            ai_findings=[],
            extraction_mode=extraction_mode,
            extraction_notes=[],
            extraction_chars=0,
            error_message=extraction.error_message,
        )

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
