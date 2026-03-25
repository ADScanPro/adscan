"""Codex-backed AI analysis over local SMB/WinRM loot directories.

This service is intentionally separate from the existing app-server prompt flow.
For share/file-system loot we need a model runtime that can inspect the local
filesystem directly. ``codex exec`` is a better fit than app-server here
because it can work inside the loot directory with a read-only sandbox and
return one schema-constrained JSON payload.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any
import json
import shutil

from adscan_internal.command_runner import CommandRunner, CommandSpec, default_runner
from adscan_internal import print_info_debug
from adscan_internal.services.base_service import BaseService
from adscan_internal.services.llm.config import AIProvider, load_ai_config
from adscan_internal.services.llm.codex_exec_service import CodexExecService


@dataclass(frozen=True)
class ShareLootAICredentialFinding:
    """One credential-like finding returned by Codex loot analysis."""

    credential_type: str
    secret: str
    evidence: str
    local_source: str
    line_number: int | None = None
    username: str = ""
    account_scope: str = "unknown"
    service_hint: str = "unknown"
    host_hint: str = ""
    recommended_action: str = "manual_only"


@dataclass(frozen=True)
class ShareLootAIAnalysisResult:
    """Normalized result for one loot-directory AI analysis run."""

    completed: bool
    summary: str
    findings: list[ShareLootAICredentialFinding]
    notes: list[str]
    command: list[str]
    provider: str
    model: str
    raw_output_path: str
    loot_fingerprint: str = ""
    used_prior_context: bool = False
    error_message: str = ""


class ShareLootAIAnalysisService(BaseService):
    """Run schema-constrained Codex exec analysis against one loot directory."""

    _DEFAULT_TIMEOUT_SECONDS = 900
    _DOCUMENT_TIMEOUT_SECONDS = 1800

    def __init__(
        self,
        *,
        runner: CommandRunner | None = None,
    ) -> None:
        """Initialize service dependencies."""
        super().__init__()
        self._runner = runner or default_runner
        self._codex_exec = CodexExecService(runner=self._runner)

    def is_available(self) -> tuple[bool, str]:
        """Return whether Codex exec is available for loot analysis."""
        config = load_ai_config()
        if not config.enabled:
            return False, "AI is disabled."
        if config.provider != AIProvider.CODEX_CLI:
            return False, "Loot-path AI analysis currently requires Codex CLI."
        if not shutil.which("codex"):
            return False, "Codex CLI is not installed or not in PATH."

        result = self._runner.run(
            CommandSpec(
                command=["codex", "login", "status"],
                timeout=20,
                shell=False,
                capture_output=True,
                text=True,
                check=False,
            )
        )
        if result.returncode != 0:
            return False, "Codex CLI is not authenticated."
        return True, "ok"

    def analyze_loot_dir(
        self,
        *,
        loot_dir: str,
        domain: str,
        phase: str,
        phase_label: str,
        candidate_files: int,
        history_path: str = "",
        include_prior_context: bool = True,
    ) -> ShareLootAIAnalysisResult:
        """Analyze one loot directory with schema-constrained Codex exec."""
        available, reason = self.is_available()
        if not available:
            return ShareLootAIAnalysisResult(
                completed=False,
                summary="",
                findings=[],
                notes=[],
                command=[],
                provider="codex_cli",
                model="",
                raw_output_path="",
                error_message=reason,
            )

        config = load_ai_config()
        timeout_seconds = (
            self._DOCUMENT_TIMEOUT_SECONDS
            if "document" in str(phase).strip().lower()
            else self._DEFAULT_TIMEOUT_SECONDS
        )
        loot_root = Path(loot_dir).expanduser().resolve(strict=False)
        loot_fingerprint = self.compute_loot_fingerprint(loot_root)
        prior_context = self.load_matching_history_context(
            history_path=history_path,
            loot_fingerprint=loot_fingerprint,
        )
        if not include_prior_context:
            prior_context = {}
        if not loot_root.is_dir():
            return ShareLootAIAnalysisResult(
                completed=False,
                summary="",
                findings=[],
                notes=[],
                command=[],
                provider="codex_cli",
                model=str(config.model or ""),
                raw_output_path="",
                loot_fingerprint=loot_fingerprint,
                error_message=f"Loot directory is not accessible: {loot_dir}",
            )

        exec_result = self._codex_exec.run_structured_json(
            working_dir=str(loot_root),
            schema=self._build_output_schema(),
            model=str(config.model or "").strip(),
            prompt=self._build_prompt(
                domain=domain,
                phase=phase,
                phase_label=phase_label,
                candidate_files=candidate_files,
                prior_context=prior_context,
            ),
            timeout_seconds=timeout_seconds,
        )
        if not exec_result.payload:
            stdout_excerpt = exec_result.stdout_text[:400].strip().replace("\n", "\\n")
            stderr_excerpt = exec_result.stderr_text[:400].strip().replace("\n", "\\n")
            print_info_debug(
                "Codex exec loot analysis diagnostics: "
                f"phase={phase_label} returncode={exec_result.returncode} "
                f"output_exists={exec_result.output_exists} output_empty={exec_result.output_empty} "
                f"output_bytes={exec_result.output_bytes} "
                f"output_path={exec_result.output_path}"
            )
            if stdout_excerpt:
                print_info_debug(
                    f"Codex exec loot analysis stdout excerpt: {stdout_excerpt}"
                )
            if exec_result.stdout_tail and exec_result.stdout_tail != stdout_excerpt:
                print_info_debug(
                    f"Codex exec loot analysis stdout tail: {exec_result.stdout_tail}"
                )
            if stderr_excerpt:
                print_info_debug(
                    f"Codex exec loot analysis stderr excerpt: {stderr_excerpt}"
                )
            if exec_result.stderr_tail and exec_result.stderr_tail != stderr_excerpt:
                print_info_debug(
                    f"Codex exec loot analysis stderr tail: {exec_result.stderr_tail}"
                )
            if exec_result.output_excerpt:
                print_info_debug(
                    f"Codex exec loot analysis output excerpt: {exec_result.output_excerpt}"
                )
            return ShareLootAIAnalysisResult(
                completed=False,
                summary="",
                findings=[],
                notes=[],
                command=exec_result.command,
                provider="codex_cli",
                model=str(config.model or ""),
                raw_output_path=exec_result.output_path,
                loot_fingerprint=loot_fingerprint,
                used_prior_context=bool(prior_context),
                error_message=exec_result.error_message,
            )
        payload = exec_result.payload
        findings = self._parse_findings(payload)
        analysis_result = ShareLootAIAnalysisResult(
            completed=exec_result.completed,
            summary=str(payload.get("summary", "") or "").strip(),
            findings=findings,
            notes=[
                str(item).strip()
                for item in list(payload.get("notes") or [])
                if str(item).strip()
            ],
            command=exec_result.command,
            provider="codex_cli",
            model=str(config.model or ""),
            raw_output_path=exec_result.output_path,
            loot_fingerprint=loot_fingerprint,
            used_prior_context=bool(prior_context),
            error_message=exec_result.error_message,
        )
        if analysis_result.completed:
            self.write_history(
                history_path=history_path,
                domain=domain,
                phase=phase,
                phase_label=phase_label,
                candidate_files=candidate_files,
                loot_fingerprint=loot_fingerprint,
                result=analysis_result,
            )
        return analysis_result

    @staticmethod
    def compute_loot_fingerprint(loot_dir: Path) -> str:
        """Return one stable fingerprint for a loot tree."""
        digest = sha256()
        if not loot_dir.is_dir():
            return ""
        for file_path in sorted(path for path in loot_dir.rglob("*") if path.is_file()):
            relative_path = file_path.relative_to(loot_dir).as_posix()
            try:
                stat_result = file_path.stat()
            except OSError:
                continue
            digest.update(relative_path.encode("utf-8", "ignore"))
            digest.update(b"\0")
            digest.update(str(int(stat_result.st_size)).encode("ascii"))
            digest.update(b"\0")
            digest.update(str(int(stat_result.st_mtime_ns)).encode("ascii"))
            digest.update(b"\0")
        return digest.hexdigest()

    @staticmethod
    def load_matching_history_context(
        *,
        history_path: str,
        loot_fingerprint: str,
    ) -> dict[str, Any]:
        """Load compact prior context for the same loot fingerprint, when present."""
        normalized_path = str(history_path or "").strip()
        if not normalized_path or not loot_fingerprint:
            return {}
        history_file = Path(normalized_path)
        if not history_file.is_file():
            return {}
        try:
            payload = json.loads(history_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(payload, dict):
            return {}
        if str(payload.get("loot_fingerprint", "") or "").strip() != loot_fingerprint:
            return {}
        compact_findings: list[dict[str, Any]] = []
        for item in list(payload.get("findings") or [])[:25]:
            if not isinstance(item, dict):
                continue
            compact_findings.append(
                {
                    "credential_type": str(item.get("credential_type", "") or "").strip(),
                    "secret": str(item.get("secret", "") or "").strip(),
                    "local_source": str(item.get("local_source", "") or "").strip(),
                    "line_number": item.get("line_number"),
                    "username": str(item.get("username", "") or "").strip(),
                }
            )
        return {
            "summary": str(payload.get("summary", "") or "").strip(),
            "notes": [
                str(note).strip()
                for note in list(payload.get("notes") or [])[:10]
                if str(note).strip()
            ],
            "findings": [item for item in compact_findings if item.get("secret")],
            "generated_at": str(payload.get("generated_at", "") or "").strip(),
        }

    @staticmethod
    def write_history(
        *,
        history_path: str,
        domain: str,
        phase: str,
        phase_label: str,
        candidate_files: int,
        loot_fingerprint: str,
        result: ShareLootAIAnalysisResult,
    ) -> None:
        """Persist one compact AI analysis history payload for future context reuse."""
        normalized_path = str(history_path or "").strip()
        if not normalized_path or not loot_fingerprint:
            return
        history_file = Path(normalized_path)
        history_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": 1,
            "domain": domain,
            "phase": phase,
            "phase_label": phase_label,
            "candidate_files": int(candidate_files),
            "loot_fingerprint": loot_fingerprint,
            "provider": result.provider,
            "model": result.model,
            "summary": result.summary,
            "notes": result.notes,
            "generated_at": (
                datetime.fromtimestamp(
                    Path(result.raw_output_path).stat().st_mtime,
                    tz=timezone.utc,
                ).replace(microsecond=0).isoformat()
                if result.raw_output_path and Path(result.raw_output_path).exists()
                else ""
            ),
            "findings": [
                {
                    "credential_type": item.credential_type,
                    "secret": item.secret,
                    "evidence": item.evidence,
                    "local_source": item.local_source,
                    "line_number": item.line_number,
                    "username": item.username,
                    "account_scope": item.account_scope,
                    "service_hint": item.service_hint,
                    "host_hint": item.host_hint,
                    "recommended_action": item.recommended_action,
                }
                for item in result.findings
            ],
        }
        history_file.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    @staticmethod
    def _build_output_schema() -> dict[str, Any]:
        """Return JSON schema expected from Codex exec final output."""
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["summary", "notes", "findings"],
            "properties": {
                "summary": {"type": "string"},
                "notes": {"type": "array", "items": {"type": "string"}},
                "findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": [
                            "credential_type",
                            "secret",
                            "evidence",
                            "local_source",
                            "line_number",
                            "username",
                            "account_scope",
                            "service_hint",
                            "host_hint",
                            "recommended_action",
                        ],
                        "properties": {
                            "credential_type": {"type": "string"},
                            "secret": {"type": "string"},
                            "evidence": {"type": "string"},
                            "local_source": {"type": "string"},
                            "line_number": {"type": ["integer", "null"], "minimum": 1},
                            "username": {"type": "string"},
                            "account_scope": {"type": "string"},
                            "service_hint": {"type": "string"},
                            "host_hint": {"type": "string"},
                            "recommended_action": {"type": "string"},
                        },
                    },
                },
            },
        }

    @staticmethod
    def _build_prompt(
        *,
        domain: str,
        phase: str,
        phase_label: str,
        candidate_files: int,
        prior_context: dict[str, Any] | None = None,
    ) -> str:
        """Build the analyst prompt for one loot directory."""
        phase_hint = (
            "text-like files only"
            if "text" in phase
            else "document-like files only"
        )
        prompt = (
            "You are ADscan loot credential analyst.\n"
            "Working directory is the SMB/WinRM loot root for one analysis phase.\n"
            "Rules:\n"
            "- Inspect files under the current directory only.\n"
            "- Use read-only shell commands only.\n"
            "- Do not modify files.\n"
            "- Focus on credential-like values useful for access, spraying, or validation.\n"
            "- Ignore obvious placeholders and obvious lorem/test/demo strings.\n"
            "- Prefer precise, actionable findings over volume.\n"
            "- Return at most 100 findings.\n"
            "- local_source must be a path relative to the current working directory.\n"
            "- line_number is optional and should be null when unknown.\n"
            "- username should be the best concrete account identifier when present, otherwise an empty string.\n"
            "- account_scope must be one of: domain_user, local_user, service_account, application_secret, generic_secret, unknown.\n"
            "- service_hint must be one of: smb, mssql, mysql, ftp, vnc, smtp, http, oauth, unknown.\n"
            "- host_hint should be the target host/IP when the credential is clearly host-bound, otherwise an empty string.\n"
            "- recommended_action must be one of: add_domain_credential, add_local_smb_credential, add_local_mssql_credential, spray, manual_only.\n"
            "- Be conservative: if verification target/scope is unclear, use manual_only instead of guessing.\n"
            f"- Phase focus: {phase_label} ({phase_hint}).\n"
            f"- Target domain: {domain}.\n"
            f"- Candidate files already collected: {candidate_files}.\n"
            "Return only the schema-constrained final JSON payload."
        )
        if prior_context:
            prompt += (
                "\nHistorical context for the same unchanged loot is available.\n"
                "Use it only as analyst memory. Re-validate against the current files before returning findings.\n"
                f"Previous summary: {str(prior_context.get('summary', '') or '').strip()}\n"
                f"Previous notes: {json.dumps(list(prior_context.get('notes') or []), ensure_ascii=False)}\n"
                "Previous findings: "
                f"{json.dumps(list(prior_context.get('findings') or []), ensure_ascii=False)}\n"
            )
        return prompt

    @staticmethod
    def _parse_findings(payload: dict[str, Any]) -> list[ShareLootAICredentialFinding]:
        """Normalize Codex exec findings into dataclasses."""
        findings: list[ShareLootAICredentialFinding] = []
        for item in list(payload.get("findings") or []):
            if not isinstance(item, dict):
                continue
            secret = str(item.get("secret", "") or "").strip()
            local_source = str(item.get("local_source", "") or "").strip()
            if not secret or not local_source:
                continue
            line_number = item.get("line_number")
            findings.append(
                ShareLootAICredentialFinding(
                    credential_type=str(
                        item.get("credential_type", "") or "ai_credential"
                    ).strip()
                    or "ai_credential",
                    secret=secret,
                    evidence=str(item.get("evidence", "") or "").strip(),
                    local_source=local_source,
                    line_number=line_number
                    if isinstance(line_number, int) and line_number > 0
                    else None,
                    username=str(item.get("username", "") or "").strip(),
                    account_scope=str(item.get("account_scope", "") or "unknown").strip()
                    or "unknown",
                    service_hint=str(item.get("service_hint", "") or "unknown").strip()
                    or "unknown",
                    host_hint=str(item.get("host_hint", "") or "").strip(),
                    recommended_action=str(
                        item.get("recommended_action", "") or "manual_only"
                    ).strip()
                    or "manual_only",
                )
            )
        return findings
