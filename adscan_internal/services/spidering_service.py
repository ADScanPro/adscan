"""Spidering service for manspider-based SMB share content discovery.

This module encapsulates the logic for:

- Executing manspider for password-oriented spidering on SMB shares.
- Normalizing its output into a log file.
- Delegating credential extraction to :class:`CredSweeperService`.

The goal is to progressively migrate spidering responsibilities out of the
``PentestShell`` monolith in ``adscan.py`` while keeping the CLI responsible
for user interaction (confirmation prompts, password spraying decisions, etc.).
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import logging
import os
import subprocess
from pathlib import Path
import shlex
import shutil
import zipfile

from rich.markup import escape as rich_escape
import re

from adscan_internal import (
    print_info_verbose,
    print_info_debug,
    print_success,
    print_warning,
    print_warning_debug,
    print_error,
    print_error_debug,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.text_utils import strip_ansi_codes
from adscan_internal.services.base_service import BaseService
from adscan_internal.services.credsweeper_service import (
    CREDSWEEPER_RULES_PROFILE_FILESYSTEM_DOC,
    CREDSWEEPER_RULES_PROFILE_FILESYSTEM_TEXT,
    CredSweeperService,
    get_default_credsweeper_jobs,
)
from adscan_internal.services.share_file_analyzer_service import (
    ShareFileAnalyzerService,
)
from adscan_internal.services.share_file_finding_action_service import (
    ShareFileFindingActionService,
)
from adscan_internal.services.smb_exclusion_policy import (
    is_globally_excluded_smb_relative_path,
    prune_excluded_walk_dirs,
)
from adscan_internal.services.smb_sensitive_file_policy import (
    DIRECT_SECRET_ARTIFACT_EXTENSIONS,
    DOCUMENT_LIKE_CREDENTIAL_EXTENSIONS,
    SENSITIVE_FILE_WRAPPER_EXTENSIONS,
    SMB_SENSITIVE_SCAN_PHASE_DOCUMENT_CREDENTIALS,
    SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS,
    TEXT_LIKE_CREDENTIAL_EXTENSIONS,
    resolve_effective_sensitive_extension,
)
from adscan_internal.services.xml_sanitization_service import create_analysis_temp_root
from adscan_internal import telemetry


logger = logging.getLogger(__name__)


CommandExecutor = Callable[..., subprocess.CompletedProcess[str] | None]
HandleFoundCredentialsCallback = Callable[
    [dict, str, list[str] | None, list[str] | None, str | None, str | None], None
]
_NTLM_HASH_DUMP_RG_PATTERN = (
    r"^[^:\r\n]{1,256}:[0-9]{1,10}:[0-9A-Fa-f]{32}:[0-9A-Fa-f]{32}:::"
)
_NTLM_HASH_DUMP_LINE_RE = re.compile(_NTLM_HASH_DUMP_RG_PATTERN)
_ZIP_SELECTIVE_MAX_SUPPORTED_ENTRIES = 256
_ZIP_SELECTIVE_MAX_TOTAL_BYTES = 200 * 1024 * 1024
_ZIP_SELECTIVE_PREVIEW_LIMIT = 5
_ZIP_SELECTIVE_MAX_DEPTH = 1


@dataclass(frozen=True)
class ArtifactProcessingRecord:
    """Structured outcome for one artifact or structured file processed locally."""

    path: str
    filename: str
    artifact_type: str
    status: str
    note: str
    manual_review: bool = False
    details: dict[str, object] | None = None


class SpideringService(BaseService):
    """Service for manspider share spidering and password extraction.

    This service focuses on the *non-interactive* parts of spidering:

    - Running manspider with the appropriate command.
    - Persisting a cleaned log file that strips ANSI escape codes.
    - Calling :class:`CredSweeperService` to extract credentials.

    The CLI (``PentestShell``) remains responsible for:

    - Presenting results in Rich tables.
    - Asking for user confirmation.
    - Triggering password spraying or follow-up actions.
    """

    def __init__(
        self,
        command_executor: CommandExecutor,
        credsweeper_service: CredSweeperService,
        *,
        file2john_callback: Callable[[str, object, str, str], None] | None = None,
        certipy_callback: Callable[[str, str], bool] | None = None,
        list_zip_callback: Callable[[str], None] | None = None,
        extract_zip_callback: Callable[[str, str], None] | None = None,
        add_credential_callback: Callable[[str, str, str], None] | None = None,
        cpassword_callback: Callable[
            [str, str, str, list[str] | None, list[str] | None, str | None], bool
        ]
        | None = None,
        keepass_artifact_callback: Callable[
            [str, str, list[str] | None, list[str] | None, str | None], int
        ]
        | None = None,
        handle_found_credentials_callback: HandleFoundCredentialsCallback | None = None,
        credsweeper_path: str | None = None,
        pypykatz_path: str | None = None,
        share_file_analyzer_service: ShareFileAnalyzerService | None = None,
        share_file_finding_action_service: ShareFileFindingActionService | None = None,
    ) -> None:
        """Initialize SpideringService.

        Args:
            command_executor: Callable used to execute shell commands. In the
                CLI this should typically be ``PentestShell.run_command``.
            credsweeper_service: Shared instance of :class:`CredSweeperService`
                used to analyze spidering logs.
        """
        super().__init__()
        self._command_executor = command_executor
        self._credsweeper_service = credsweeper_service
        self._file2john_callback = file2john_callback
        self._certipy_callback = certipy_callback
        self._list_zip_callback = list_zip_callback
        self._extract_zip_callback = extract_zip_callback
        self._add_credential_callback = add_credential_callback
        self._cpassword_callback = cpassword_callback
        self._keepass_artifact_callback = keepass_artifact_callback
        self._handle_found_credentials_callback = handle_found_credentials_callback
        self._credsweeper_path = str(credsweeper_path or "").strip()
        self._pypykatz_path = pypykatz_path
        self._share_file_analyzer_service = (
            share_file_analyzer_service
            or ShareFileAnalyzerService(
                command_executor=self._command_executor,
                pypykatz_path=self._pypykatz_path,
            )
        )
        self._share_file_finding_action_service = (
            share_file_finding_action_service
            or ShareFileFindingActionService(
                add_credential_callback=self._add_credential_callback,
                file2john_callback=self._file2john_callback,
                cpassword_callback=self._cpassword_callback,
                certipy_callback=self._certipy_callback,
                keepass_artifact_callback=self._keepass_artifact_callback,
            )
        )

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def run_manspider_password_scan(
        self,
        command: str,
        log_file: str,
        *,
        credsweeper_path: Optional[str],
        timeout: int = 300,
    ) -> Dict[str, List]:
        """Execute manspider password scan and analyze results with CredSweeper.

        This method mirrors the previous ``execute_manspider(..., scan_type='passw')``
        behavior in ``adscan.py`` but without any CLI interactivity.

        Steps:

        1. Run manspider using the provided command.
        2. Save its stdout to ``log_file`` after stripping ANSI escape codes.
        3. On success, call :meth:`CredSweeperService.analyze_file` on the log
           and return the resulting credentials dictionary.

        Args:
            command: Fully constructed manspider command string.
            log_file: Path to the log file where cleaned output will be saved.
            credsweeper_path: Path to the ``credsweeper`` executable. When
                ``None``, CredSweeper analysis is skipped and an empty dict is
                returned.
            timeout: Optional timeout in seconds for manspider execution.

        Returns:
            Dictionary of credentials organized by CredSweeper rule name.
        """
        # Ensure parent directory for the log exists
        log_dir = os.path.dirname(log_file) or "."
        os.makedirs(log_dir, exist_ok=True)

        try:
            completed_process = self._command_executor(
                command,
                timeout=timeout,
                use_clean_env=None,
            )
            if completed_process is None:
                print_error(
                    "manspider scan failed before returning any output while "
                    "searching for possible passwords in shares."
                )
                return {}

            output_str = completed_process.stdout or ""
            if output_str:
                try:
                    with open(log_file, "w", encoding="utf-8") as handle:
                        for raw_line in output_str.splitlines():
                            line_stripped = raw_line.strip()
                            if not line_stripped:
                                continue
                            clean_line = strip_ansi_codes(line_stripped)
                            handle.write(clean_line + "\n")
                        handle.flush()
                    print_info_verbose(f"Log saved in {log_file}")
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
                    print_warning(
                        f"Error while saving manspider output to log file: {exc}"
                    )
            else:
                print_warning_debug(
                    "Manspider command for type 'passw' produced no output."
                )

            if completed_process.returncode != 0:
                print_error_debug(
                    "Error executing manspider (type passw). "
                    f"Return code: {completed_process.returncode}"
                )
                error_message = completed_process.stderr or ""
                if error_message:
                    print_error(f"Details: {error_message}")
                elif not error_message and output_str:
                    print_error(f"Details (from stdout): {output_str}")
                else:
                    print_error_debug("No error output from manspider command.")
                # Even on non-zero return code we stop here; no CredSweeper.
                return {}

            # If there is no output or the log file does not exist, nothing to analyze
            if not output_str or not os.path.exists(log_file):
                print_warning_debug(
                    "Manspider completed but no log file was generated for analysis."
                )
                return {}

            # Delegate to CredSweeperService for credential extraction
            if not credsweeper_path:
                print_info_verbose(
                    "Credential extraction tool not available. "
                    "Skipping CredSweeper analysis of manspider log."
                )
                return {}

            return self._credsweeper_service.analyze_file(
                log_file,
                credsweeper_path=credsweeper_path,
                timeout=timeout,
            )

        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error("Error executing manspider password spidering.")
            print_error_debug(f"Error type: {type(exc).__name__}")
            return {}

    # ------------------------------------------------------------------ #
    # Artifact processing (GPP, dumps, PFX, ZIP, etc.)
    # ------------------------------------------------------------------ #

    @staticmethod
    def _structured_suffix_to_scan_type_for_phase(phase: str) -> dict[str, str]:
        """Return structured file suffixes that require deterministic handling."""
        phase_name = str(phase or "").strip()
        if phase_name == SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS:
            return {
                ".xml": "gpp",
                ".yml": "gpp",
                ".yaml": "gpp",
            }
        if phase_name == SMB_SENSITIVE_SCAN_PHASE_DOCUMENT_CREDENTIALS:
            return {
                ".xlsm": "ext",
            }
        return {}

    def process_local_structured_files(
        self,
        *,
        root_path: str,
        phase: str,
        domain: str,
        source_hosts: list[str] | None = None,
        source_shares: list[str] | None = None,
        auth_username: str | None = None,
        apply_actions: bool = True,
    ) -> dict[str, object]:
        """Process deterministic structured files under one local loot root.

        This is the shared backend-agnostic path for structured findings such as
        GPP ``cpassword`` in XML files. It intentionally does not depend on
        CredSweeper so those findings remain stable across backends.
        """
        suffix_to_scan_type = self._structured_suffix_to_scan_type_for_phase(phase)
        if not suffix_to_scan_type:
            return {
                "candidate_files": 0,
                "processed_files": 0,
                "files_with_findings": 0,
                "ntlm_hash_findings": [],
            }

        root = Path(str(root_path or "")).expanduser().resolve(strict=False)
        if not root.is_dir():
            return {
                "candidate_files": 0,
                "processed_files": 0,
                "files_with_findings": 0,
                "ntlm_hash_findings": [],
            }

        candidates: list[tuple[str, str]] = []
        remaining_suffixes = dict(suffix_to_scan_type)
        xml_candidates = self._find_xml_cpassword_candidates(root)
        if xml_candidates is not None:
            remaining_suffixes.pop(".xml", None)
            candidates.extend((file_path, "gpp") for file_path in xml_candidates)
            if xml_candidates:
                preview = ", ".join(
                    mark_sensitive(path, "path") for path in xml_candidates[:3]
                )
                print_info_debug(
                    "Deterministic structured XML candidates selected via ripgrep: "
                    f"phase={phase} count={len(xml_candidates)} preview=[{rich_escape(preview)}]"
                )
        ntlm_hash_candidates = self._find_ntlm_hash_dump_candidates(root, phase)
        ntlm_hash_prefilter_available = ntlm_hash_candidates is not None
        if ntlm_hash_candidates:
            candidates.extend((file_path, "hashdump") for file_path in ntlm_hash_candidates)
            preview = ", ".join(
                mark_sensitive(path, "path") for path in ntlm_hash_candidates[:3]
            )
            print_info_debug(
                "Deterministic NTLM dump candidates selected via ripgrep: "
                f"phase={phase} count={len(ntlm_hash_candidates)} "
                f"preview=[{rich_escape(preview)}]"
            )

        for dirpath, dirnames, filenames in os.walk(root):
            prune_excluded_walk_dirs(dirnames)
            base_dir = Path(dirpath)
            for filename in sorted(filenames):
                file_path = base_dir / filename
                try:
                    relative_path = file_path.relative_to(root).as_posix()
                except ValueError:
                    continue
                if is_globally_excluded_smb_relative_path(relative_path):
                    continue
                if (
                    phase == SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS
                    and not ntlm_hash_prefilter_available
                    and file_path.suffix.lower() in {".txt", ".log", ".csv"}
                    and self._looks_like_ntlm_hash_dump_candidate(file_path)
                ):
                    candidates.append((str(file_path), "hashdump"))
                    continue
                scan_type = remaining_suffixes.get(
                    resolve_effective_sensitive_extension(
                        str(file_path),
                        allowed_extensions=tuple(remaining_suffixes.keys()),
                    )
                )
                if scan_type:
                    candidates.append((str(file_path), scan_type))

        # Preserve deterministic ordering and deduplicate overlapping paths.
        deduped_candidates: list[tuple[str, str]] = []
        seen_candidates: set[tuple[str, str]] = set()
        for file_path, scan_type in sorted(candidates, key=lambda item: (item[0], item[1])):
            key = (file_path, scan_type)
            if key in seen_candidates:
                continue
            seen_candidates.add(key)
            deduped_candidates.append(key)
        candidates = deduped_candidates

        processed = 0
        files_with_findings = 0
        ntlm_hash_findings: list[dict[str, str]] = []
        for file_path, scan_type in candidates:
            record = self.process_found_file(
                file_path,
                domain,
                scan_type,
                source_hosts=source_hosts,
                source_shares=source_shares,
                auth_username=auth_username,
                enable_legacy_zip_callbacks=False,
                apply_actions=apply_actions,
            )
            processed += 1
            if str(getattr(record, "status", "") or "").strip() == "processed":
                files_with_findings += 1
            details = getattr(record, "details", None)
            if isinstance(details, dict):
                raw_ntlm_hashes = details.get("ntlm_hash_findings")
                if isinstance(raw_ntlm_hashes, list):
                    for item in raw_ntlm_hashes:
                        if not isinstance(item, dict):
                            continue
                        username = str(item.get("username") or "").strip()
                        ntlm_hash = str(item.get("ntlm_hash") or "").strip()
                        source_path = str(item.get("source_path") or "").strip()
                        if not username or not ntlm_hash or not source_path:
                            continue
                        ntlm_hash_findings.append(
                            {
                                "username": username,
                                "ntlm_hash": ntlm_hash,
                                "source_path": source_path,
                            }
                        )

        print_info_debug(
            "Deterministic structured-file post-scan completed: "
            f"phase={phase} candidate_files={len(candidates)} processed_files={processed} "
            f"files_with_findings={files_with_findings} "
            f"root={root}"
        )
        return {
            "candidate_files": len(candidates),
            "processed_files": processed,
            "files_with_findings": files_with_findings,
            "ntlm_hash_findings": ntlm_hash_findings,
        }

    def _find_xml_cpassword_candidates(self, root: Path) -> list[str] | None:
        """Return XML files containing ``cpassword=`` using ``rg`` when available.

        Returns ``None`` when ``rg`` is unavailable or fails unexpectedly so the
        caller can fall back to the Python filesystem walk.
        """
        rg_path = shutil.which("rg")
        if not rg_path:
            return None

        command = " ".join(
            [shlex.quote(rg_path), "-l", "-0", "-i"]
            + [
                part
                for glob in (
                    ["*.xml"]
                    + [f"*.xml{wrapper}" for wrapper in SENSITIVE_FILE_WRAPPER_EXTENSIONS]
                )
                for part in ("--iglob", shlex.quote(glob))
            ]
            + [
                shlex.quote(r"cpassword\s*="),
                shlex.quote(str(root)),
            ]
        )
        completed_process = self._command_executor(
            command,
            timeout=120,
            use_clean_env=True,
        )
        if completed_process is None:
            return None

        return_code = int(getattr(completed_process, "returncode", 1))
        if return_code not in (0, 1):
            print_warning_debug(
                "ripgrep structured XML prefilter failed unexpectedly. "
                f"Falling back to Python walk. rc={return_code}"
            )
            return None

        stdout_text = str(getattr(completed_process, "stdout", "") or "")
        if not stdout_text.strip("\0\r\n\t "):
            return []

        candidates: list[str] = []
        for raw_path in stdout_text.split("\0"):
            normalized_path = str(raw_path or "").strip()
            if not normalized_path:
                continue
            file_path = Path(normalized_path).resolve(strict=False)
            if not file_path.is_file():
                continue
            try:
                relative_path = file_path.relative_to(root).as_posix()
            except ValueError:
                continue
            if is_globally_excluded_smb_relative_path(relative_path):
                continue
            candidates.append(str(file_path))

        print_info_debug(
            "ripgrep structured XML prefilter completed: "
            f"root={root} candidate_files={len(candidates)}"
        )
        return candidates

    def _find_ntlm_hash_dump_candidates(
        self,
        root: Path,
        phase: str,
    ) -> list[str] | None:
        """Return text files containing secretsdump/SAM-style NTLM hash lines."""
        if str(phase or "").strip() != SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS:
            return []

        rg_path = shutil.which("rg")
        if not rg_path:
            return None

        command = " ".join(
            [shlex.quote(rg_path), "-l", "-0", "-i"]
            + [
                part
                for glob in ("*.txt", "*.log", "*.csv")
                for part in ("--iglob", shlex.quote(glob))
            ]
            + [
                shlex.quote(_NTLM_HASH_DUMP_RG_PATTERN),
                shlex.quote(str(root)),
            ]
        )
        completed_process = self._command_executor(
            command,
            timeout=120,
            use_clean_env=True,
        )
        if completed_process is None:
            return None

        return_code = int(getattr(completed_process, "returncode", 1))
        if return_code not in (0, 1):
            print_warning_debug(
                "ripgrep NTLM hash prefilter failed unexpectedly. "
                f"Skipping NTLM dump prefilter. rc={return_code}"
            )
            return None

        stdout_text = str(getattr(completed_process, "stdout", "") or "")
        if not stdout_text.strip("\0\r\n\t "):
            return []

        candidates: list[str] = []
        for raw_path in stdout_text.split("\0"):
            normalized_path = str(raw_path or "").strip()
            if not normalized_path:
                continue
            file_path = Path(normalized_path).resolve(strict=False)
            if not file_path.is_file():
                continue
            try:
                relative_path = file_path.relative_to(root).as_posix()
            except ValueError:
                continue
            if is_globally_excluded_smb_relative_path(relative_path):
                continue
            candidates.append(str(file_path))

        print_info_debug(
            "ripgrep NTLM hash prefilter completed: "
            f"root={root} candidate_files={len(candidates)}"
        )
        return candidates

    @staticmethod
    def _looks_like_ntlm_hash_dump_candidate(file_path: Path) -> bool:
        """Return True when a text file contains one secretsdump/SAM-style hash line."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    if _NTLM_HASH_DUMP_LINE_RE.search(line):
                        return True
        except OSError:
            return False
        return False

    def process_found_file(
        self,
        file_path: str,
        domain: str,
        scan_type: str,
        *,
        source_hosts: list[str] | None = None,
        source_shares: list[str] | None = None,
        auth_username: str | None = None,
        enable_legacy_zip_callbacks: bool = True,
        apply_actions: bool = True,
        zip_depth: int = 0,
    ) -> ArtifactProcessingRecord:
        """Process one discovered file and return a structured result."""
        filename = os.path.basename(file_path)
        filename_lower = filename.lower()
        effective_suffix = resolve_effective_sensitive_extension(filename_lower)
        artifact_type = effective_suffix.lstrip(".") or (Path(filename_lower).suffix.lstrip(".") or "file")

        if effective_suffix == ".xml" and scan_type == "gpp":
            return self._process_gpp_xml_file(
                file_path=file_path,
                domain=domain,
                filename=filename,
                source_hosts=source_hosts,
                source_shares=source_shares,
                auth_username=auth_username,
                apply_actions=apply_actions,
            )

        if effective_suffix in {".yml", ".yaml"} and scan_type == "gpp":
            return self._process_yml_file(
                file_path=file_path,
                domain=domain,
                filename=filename,
                apply_actions=apply_actions,
            )

        if effective_suffix in {".txt", ".log", ".csv"} and scan_type == "hashdump":
            return self._process_ntlm_hash_dump_file(
                file_path=file_path,
                domain=domain,
                filename=filename,
                apply_actions=apply_actions,
            )

        if effective_suffix == ".xlsm" and scan_type == "ext":
            return self._process_xlsm_file(
                file_path=file_path,
                domain=domain,
                filename=filename,
                apply_actions=apply_actions,
            )

        if effective_suffix == ".dmp" and scan_type == "ext":
            print_warning(f"Memory dump file found: {filename}")
            return self._process_dmp_file(file_path, domain, apply_actions=apply_actions)

        if effective_suffix == ".pfx" and scan_type == "ext":
            print_info_verbose(f"Found .pfx file: {filename}")
            return self._process_pfx_file(
                file_path=file_path,
                domain=domain,
                apply_actions=apply_actions,
            )

        if effective_suffix in {".kdbx", ".kdb"} and scan_type == "ext":
            print_info_verbose(f"Found KeePass artifact: {filename}")
            return self._process_keepass_file(
                file_path=file_path,
                domain=domain,
                source_hosts=source_hosts,
                source_shares=source_shares,
                auth_username=auth_username,
                apply_actions=apply_actions,
            )

        if effective_suffix == ".zip" and scan_type == "ext":
            print_info_verbose(f"Found .zip file: {filename}")
            if enable_legacy_zip_callbacks and self._list_zip_callback:
                self._list_zip_callback(file_path)
            if enable_legacy_zip_callbacks and self._extract_zip_callback:
                self._extract_zip_callback(file_path, domain)
            return self._process_zip_file(
                file_path,
                domain,
                source_hosts=source_hosts,
                source_shares=source_shares,
                auth_username=auth_username,
                apply_actions=apply_actions,
                zip_depth=zip_depth,
            )

        manual_review_note = (
            "ADscan does not have deterministic support for this artifact type yet. "
            "Review the saved loot path manually."
        )
        marked_path = mark_sensitive(file_path, "path")
        print_warning(
            f"Unsupported artifact requires manual review: {marked_path} "
            f"({mark_sensitive(filename, 'path')})"
        )
        return ArtifactProcessingRecord(
            path=file_path,
            filename=filename,
            artifact_type=artifact_type,
            status="manual_review",
            note=manual_review_note,
            manual_review=True,
        )

    def process_found_files_batch(
        self,
        file_paths: list[str],
        domain: str,
        scan_type: str,
        *,
        source_hosts: list[str] | None = None,
        source_shares: list[str] | None = None,
        auth_username: str | None = None,
        enable_legacy_zip_callbacks: bool = True,
        apply_actions: bool = True,
        max_workers: int = 1,
    ) -> list[ArtifactProcessingRecord]:
        """Process multiple found files, optionally in parallel.

        Parallel execution is only enabled for the safe, analysis-only case
        where no follow-up actions or legacy ZIP callbacks are requested.
        """
        normalized_paths = [
            str(path or "").strip() for path in file_paths if str(path or "").strip()
        ]
        if not normalized_paths:
            return []

        workers = max(1, int(max_workers or 1))
        allow_parallel = (
            workers > 1
            and not apply_actions
            and not enable_legacy_zip_callbacks
        )
        if not allow_parallel:
            records: list[ArtifactProcessingRecord] = []
            for file_path in normalized_paths:
                records.append(
                        self.process_found_file(
                            file_path,
                            domain,
                            scan_type,
                        source_hosts=source_hosts,
                        source_shares=source_shares,
                        auth_username=auth_username,
                            enable_legacy_zip_callbacks=enable_legacy_zip_callbacks,
                            apply_actions=apply_actions,
                            zip_depth=0,
                        )
                    )
            return records

        print_info_debug(
            "Processing artifact batch in parallel: "
            f"files={len(normalized_paths)} workers={workers} scan_type={scan_type}"
        )

        def _process(file_path: str) -> ArtifactProcessingRecord:
            return self.process_found_file(
                file_path,
                domain,
                scan_type,
                source_hosts=source_hosts,
                source_shares=source_shares,
                auth_username=auth_username,
                enable_legacy_zip_callbacks=enable_legacy_zip_callbacks,
                apply_actions=apply_actions,
                zip_depth=0,
            )

        records: list[ArtifactProcessingRecord] = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(_process, file_path) for file_path in normalized_paths]
            for future in as_completed(futures):
                records.append(future.result())
        return records

    def _process_gpp_xml_file(
        self,
        *,
        file_path: str,
        domain: str,
        filename: str,
        source_hosts: list[str] | None,
        source_shares: list[str] | None,
        auth_username: str | None,
        apply_actions: bool,
    ) -> ArtifactProcessingRecord:
        """Process GPP XML files using shared deterministic analyzer."""
        marked_file_path = mark_sensitive(file_path, "path")
        try:
            print_info_debug(
                "Processing deterministic GPP XML candidate: "
                f"path={marked_file_path} apply_actions={apply_actions}"
            )
            result = self._share_file_analyzer_service.analyze_local_file(
                source_path=file_path
            )
            for note in result.notes:
                print_info_verbose(note)
            print_info_debug(
                "Deterministic GPP XML validator result: "
                f"path={marked_file_path} findings={len(result.findings)} "
                f"handled={result.handled} continue_with_ai={result.continue_with_ai}"
            )
            content = ""
            stats = None
            if result.findings:
                with open(file_path, "r", encoding="utf-8") as handle:
                    content = handle.read()
            if apply_actions:
                stats = self._share_file_finding_action_service.apply_findings(
                    domain=domain,
                    source_path=file_path,
                    findings=result.findings,
                    xml_content=content,
                    source_hosts=source_hosts,
                    source_shares=source_shares,
                    auth_username=auth_username,
                )
            applied = 0
            if stats:
                applied = int(stats.by_type.get("cpassword", 0))
            print_info_debug(
                "Deterministic GPP XML action result: "
                f"path={marked_file_path} findings={len(result.findings)} applied={applied}"
            )
            if result.findings:
                return ArtifactProcessingRecord(
                    path=file_path,
                    filename=filename,
                    artifact_type="xml",
                    status="processed",
                    note=f"Detected {len(result.findings)} cpassword candidate(s).",
                )
            return ArtifactProcessingRecord(
                path=file_path,
                filename=filename,
                artifact_type="xml",
                status="processed_no_findings",
                note="No cpassword candidates detected.",
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning("Error processing GPP XML file.")
            return ArtifactProcessingRecord(
                path=file_path,
                filename=filename,
                artifact_type="xml",
                status="failed",
                note=f"GPP XML processing failed: {type(exc).__name__}.",
            )

    def _process_yml_file(
        self,
        *,
        file_path: str,
        domain: str,
        filename: str,
        apply_actions: bool,
    ) -> ArtifactProcessingRecord:
        """Process YAML files with Ansible Vault blocks via deterministic analyzer."""
        print_success(f"Found .yml file: {filename}")
        try:
            result = self._share_file_analyzer_service.analyze_local_file(
                source_path=file_path
            )
            for note in result.notes:
                print_info_verbose(note)
            stats = None
            if apply_actions:
                stats = self._share_file_finding_action_service.apply_findings(
                    domain=domain,
                    source_path=file_path,
                    findings=result.findings,
                )
            if apply_actions and stats and stats.by_type.get("ansible_vault", 0) == 0:
                print_warning(f"No Ansible Vault hashes found in {filename}")
            if result.findings:
                return ArtifactProcessingRecord(
                    path=file_path,
                    filename=filename,
                    artifact_type=Path(filename).suffix.lstrip(".") or "yml",
                    status="processed",
                    note=f"Detected {len(result.findings)} Ansible Vault block(s).",
                )
            return ArtifactProcessingRecord(
                path=file_path,
                filename=filename,
                artifact_type=Path(filename).suffix.lstrip(".") or "yml",
                status="processed_no_findings",
                note="No Ansible Vault content detected.",
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error("Error processing yml file.")
            return ArtifactProcessingRecord(
                path=file_path,
                filename=filename,
                artifact_type=Path(filename).suffix.lstrip(".") or "yml",
                status="failed",
                note=f"YAML processing failed: {type(exc).__name__}.",
            )

    def _process_ntlm_hash_dump_file(
        self,
        *,
        file_path: str,
        domain: str,
        filename: str,
        apply_actions: bool,
    ) -> ArtifactProcessingRecord:
        """Process secretsdump/SAM-style NTLM hash dump text files."""
        try:
            result = self._share_file_analyzer_service.analyze_local_file(
                source_path=file_path
            )
            for note in result.notes:
                print_info_verbose(note)
            stats = None
            if apply_actions:
                stats = self._share_file_finding_action_service.apply_findings(
                    domain=domain,
                    source_path=file_path,
                    findings=result.findings,
                )
            if result.findings:
                applied = 0
                if stats:
                    applied = int(stats.by_type.get("ntlm_hash", 0))
                ntlm_hash_details = [
                    {
                        "username": str(getattr(finding, "username", "") or "").strip(),
                        "ntlm_hash": str(getattr(finding, "secret", "") or "").strip(),
                        "source_path": str(file_path),
                    }
                    for finding in result.findings
                    if str(getattr(finding, "username", "") or "").strip()
                    and str(getattr(finding, "secret", "") or "").strip()
                ]
                print_info_debug(
                    "Deterministic NTLM hash dump action result: "
                    f"path={mark_sensitive(file_path, 'path')} "
                    f"findings={len(result.findings)} applied={applied}"
                )
                return ArtifactProcessingRecord(
                    path=file_path,
                    filename=filename,
                    artifact_type=Path(filename).suffix.lstrip(".") or "text",
                    status="processed",
                    note=f"Detected {len(result.findings)} NTLM hash candidate(s).",
                    details={"ntlm_hash_findings": ntlm_hash_details},
                )
            return ArtifactProcessingRecord(
                path=file_path,
                filename=filename,
                artifact_type=Path(filename).suffix.lstrip(".") or "text",
                status="processed_no_findings",
                note="No NTLM hash candidates detected.",
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning("Error processing NTLM hash dump file.")
            return ArtifactProcessingRecord(
                path=file_path,
                filename=filename,
                artifact_type=Path(filename).suffix.lstrip(".") or "text",
                status="failed",
                note=f"NTLM hash dump processing failed: {type(exc).__name__}.",
            )

    def _process_xlsm_file(
        self,
        *,
        file_path: str,
        domain: str,
        filename: str,
        apply_actions: bool,
    ) -> ArtifactProcessingRecord:
        """Process XLSM files via shared deterministic analyzer."""
        print_success(f"Found .xlsm file: {filename}")
        try:
            result = self._share_file_analyzer_service.analyze_local_file(
                source_path=file_path
            )
            for note in result.notes:
                print_info_verbose(note)
            stats = None
            if apply_actions:
                stats = self._share_file_finding_action_service.apply_findings(
                    domain=domain,
                    source_path=file_path,
                    findings=result.findings,
                )
            if apply_actions and stats and stats.by_type.get("macro_password", 0) == 0:
                print_warning(f"No credential-related words found in {filename}")
            if result.findings:
                return ArtifactProcessingRecord(
                    path=file_path,
                    filename=filename,
                    artifact_type="xlsm",
                    status="processed",
                    note=f"Detected {len(result.findings)} macro credential candidate(s).",
                )
            return ArtifactProcessingRecord(
                path=file_path,
                filename=filename,
                artifact_type="xlsm",
                status="processed_no_findings",
                note="No credential-related words detected in macros.",
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error(f"Error executing olevba on {filename}.")
            return ArtifactProcessingRecord(
                path=file_path,
                filename=filename,
                artifact_type="xlsm",
                status="failed",
                note=f"XLSM processing failed: {type(exc).__name__}.",
            )

    def _process_dmp_file(
        self,
        dmp_file: str,
        domain: str,
        *,
        apply_actions: bool,
    ) -> ArtifactProcessingRecord:
        """Process a .DMP file through the shared deterministic analyzer."""
        try:
            result = self._share_file_analyzer_service.analyze_local_file(
                source_path=dmp_file
            )
            for note in result.notes:
                print_info_verbose(note)
            if not result.handled:
                print_warning("Deterministic analyzer did not handle this DMP file.")
                return ArtifactProcessingRecord(
                    path=dmp_file,
                    filename=Path(dmp_file).name,
                    artifact_type="dmp",
                    status="manual_review",
                    note="DMP analyzer could not handle this dump. Review manually.",
                    manual_review=True,
                )
            stats = None
            if apply_actions:
                stats = self._share_file_finding_action_service.apply_findings(
                    domain=domain,
                    source_path=dmp_file,
                    findings=result.findings,
                )
            if apply_actions and stats and stats.by_type.get("ntlm_hash", 0) == 0:
                print_warning("No valid credentials found in the dump file")
            if result.findings:
                return ArtifactProcessingRecord(
                    path=dmp_file,
                    filename=Path(dmp_file).name,
                    artifact_type="dmp",
                    status="processed",
                    note=f"Detected {len(result.findings)} dump credential candidate(s).",
                )
            return ArtifactProcessingRecord(
                path=dmp_file,
                filename=Path(dmp_file).name,
                artifact_type="dmp",
                status="processed_no_findings",
                note="DMP analyzed successfully but no valid credentials were extracted.",
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error("Error processing DMP file.")
            return ArtifactProcessingRecord(
                path=dmp_file,
                filename=Path(dmp_file).name,
                artifact_type="dmp",
                status="failed",
                note=f"DMP processing failed: {type(exc).__name__}.",
            )

    def _process_zip_file(
        self,
        zip_file: str,
        domain: str,
        *,
        source_hosts: list[str] | None = None,
        source_shares: list[str] | None = None,
        auth_username: str | None = None,
        apply_actions: bool,
        zip_depth: int = 0,
    ) -> ArtifactProcessingRecord:
        """Process ZIP artifacts through shared deterministic local handlers."""
        try:
            selective_result = self._process_zip_file_selectively(
                zip_file=zip_file,
                domain=domain,
                source_hosts=source_hosts,
                source_shares=source_shares,
                auth_username=auth_username,
                apply_actions=apply_actions,
                zip_depth=zip_depth,
            )
            if selective_result is not None:
                return selective_result

            result = self._share_file_analyzer_service.analyze_local_file(
                source_path=zip_file
            )
            for note in result.notes:
                print_info_verbose(note)
            if not result.handled:
                return ArtifactProcessingRecord(
                    path=zip_file,
                    filename=Path(zip_file).name,
                    artifact_type="zip",
                    status="manual_review",
                    note="ZIP analyzer did not handle this archive. Review manually.",
                    manual_review=True,
                )
            stats = None
            if apply_actions:
                stats = self._share_file_finding_action_service.apply_findings(
                    domain=domain,
                    source_path=zip_file,
                    findings=result.findings,
                )
            if apply_actions and stats and stats.by_type.get("ntlm_hash", 0) == 0:
                print_info_verbose("No deterministic credential findings in ZIP file.")
            if result.findings:
                return ArtifactProcessingRecord(
                    path=zip_file,
                    filename=Path(zip_file).name,
                    artifact_type="zip",
                    status="processed",
                    note=f"ZIP analysis produced {len(result.findings)} credential candidate(s).",
                )
            if result.continue_with_ai:
                return ArtifactProcessingRecord(
                    path=zip_file,
                    filename=Path(zip_file).name,
                    artifact_type="zip",
                    status="manual_review",
                    note=result.summary or "ZIP requires manual review.",
                    manual_review=True,
                )
            return ArtifactProcessingRecord(
                path=zip_file,
                filename=Path(zip_file).name,
                artifact_type="zip",
                status="processed_no_findings",
                note="ZIP analyzed successfully but no credentials were extracted.",
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error("Error processing ZIP file.")
            return ArtifactProcessingRecord(
                path=zip_file,
                filename=Path(zip_file).name,
                artifact_type="zip",
                status="failed",
                note=f"ZIP processing failed: {type(exc).__name__}.",
            )

    def _process_zip_file_selectively(
        self,
        *,
        zip_file: str,
        domain: str,
        source_hosts: list[str] | None,
        source_shares: list[str] | None,
        auth_username: str | None,
        apply_actions: bool,
        zip_depth: int,
    ) -> ArtifactProcessingRecord | None:
        """Selectively extract/process supported ZIP entries before fallback logic."""
        zip_path = Path(zip_file)
        if not zip_path.is_file():
            return ArtifactProcessingRecord(
                path=zip_file,
                filename=zip_path.name,
                artifact_type="zip",
                status="failed",
                note="ZIP file not found for processing.",
            )

        supported_text_suffixes = set(TEXT_LIKE_CREDENTIAL_EXTENSIONS)
        supported_document_suffixes = set(DOCUMENT_LIKE_CREDENTIAL_EXTENSIONS)
        supported_artifact_suffixes = set(DIRECT_SECRET_ARTIFACT_EXTENSIONS).union(
            {".dmp", ".pcap", ".vdi"}
        )
        allow_nested_zip = zip_depth < _ZIP_SELECTIVE_MAX_DEPTH
        if allow_nested_zip:
            supported_artifact_suffixes.add(".zip")
        supported_suffixes = (
            supported_text_suffixes
            | supported_document_suffixes
            | supported_artifact_suffixes
        )

        with zipfile.ZipFile(zip_path) as archive:
            all_supported_entries = [
                info
                for info in archive.infolist()
                if not info.is_dir()
                and resolve_effective_sensitive_extension(
                    info.filename,
                    allowed_extensions=supported_suffixes,
                ) in supported_suffixes
            ]
            if not all_supported_entries:
                return None

            supported_entries: list[zipfile.ZipInfo] = []
            skipped_due_limits = 0
            accumulated_supported_bytes = 0
            for info in all_supported_entries:
                entry_size = int(getattr(info, "file_size", 0) or 0)
                next_size = accumulated_supported_bytes + max(0, entry_size)
                if len(supported_entries) >= _ZIP_SELECTIVE_MAX_SUPPORTED_ENTRIES:
                    skipped_due_limits += 1
                    continue
                if next_size > _ZIP_SELECTIVE_MAX_TOTAL_BYTES:
                    skipped_due_limits += 1
                    continue
                supported_entries.append(info)
                accumulated_supported_bytes = next_size

            extracted_text = 0
            extracted_documents = 0
            extracted_artifacts = 0
            skipped_entries = 0
            processed_internal_paths: list[str] = []
            skipped_internal_paths: list[str] = []
            nested_zip_entries = 0
            zip_entry_path_aliases: dict[str, str] = {}
            temp_root = create_analysis_temp_root(
                prefix=".adscan_zip_",
                preferred_parent=zip_path.parent,
            )
            try:
                text_root = temp_root / "text"
                document_root = temp_root / "documents"
                artifact_root = temp_root / "artifacts"
                for root in (text_root, document_root, artifact_root):
                    root.mkdir(parents=True, exist_ok=True)

                for info in supported_entries:
                    entry_suffix = resolve_effective_sensitive_extension(
                        info.filename,
                        allowed_extensions=supported_suffixes,
                    )
                    if entry_suffix in supported_text_suffixes:
                        bucket_root = text_root
                        extracted_text += 1
                    elif entry_suffix in supported_document_suffixes:
                        bucket_root = document_root
                        extracted_documents += 1
                    else:
                        bucket_root = artifact_root
                        extracted_artifacts += 1

                    destination = self._resolve_safe_zip_entry_destination(
                        bucket_root=bucket_root,
                        entry_name=info.filename,
                    )
                    if destination is None:
                        skipped_entries += 1
                        skipped_internal_paths.append(str(info.filename))
                        continue
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        with archive.open(info, "r") as source_handle, destination.open(
                            "wb"
                        ) as destination_handle:
                            shutil.copyfileobj(source_handle, destination_handle)
                        processed_internal_paths.append(str(info.filename))
                        zip_entry_path_aliases[str(destination)] = self._build_zip_entry_origin_path(
                            zip_file=str(zip_path),
                            internal_path=str(info.filename),
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)
                        skipped_entries += 1
                        skipped_internal_paths.append(str(info.filename))

                grouped_findings: dict[
                    str, list[tuple[str, float | None, str, int, str]]
                ] = {}
                structured_processed = 0
                artifact_records: list[ArtifactProcessingRecord] = []

                if any(text_root.rglob("*")):
                    grouped_findings = self._scan_zip_credsweeper_bucket(
                        root_path=text_root,
                        document_mode=False,
                        path_aliases=zip_entry_path_aliases,
                    )
                    structured_stats = self.process_local_structured_files(
                        root_path=str(text_root),
                        phase=SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS,
                        domain=domain,
                        source_hosts=source_hosts,
                        source_shares=source_shares,
                        auth_username=auth_username,
                        apply_actions=apply_actions,
                    )
                    structured_processed += int(
                        structured_stats.get("processed_files", 0)
                    )

                if any(document_root.rglob("*")):
                    document_findings = self._scan_zip_credsweeper_bucket(
                        root_path=document_root,
                        document_mode=True,
                        path_aliases=zip_entry_path_aliases,
                    )
                    grouped_findings = self._merge_grouped_credential_findings(
                        grouped_findings,
                        document_findings,
                    )
                    structured_stats = self.process_local_structured_files(
                        root_path=str(document_root),
                        phase=SMB_SENSITIVE_SCAN_PHASE_DOCUMENT_CREDENTIALS,
                        domain=domain,
                        source_hosts=source_hosts,
                        source_shares=source_shares,
                        auth_username=auth_username,
                        apply_actions=apply_actions,
                    )
                    structured_processed += int(
                        structured_stats.get("processed_files", 0)
                    )

                artifact_paths = sorted(
                    str(path) for path in artifact_root.rglob("*") if path.is_file()
                )
                for artifact_path in artifact_paths:
                    if Path(artifact_path).suffix.casefold() == ".zip":
                        nested_zip_entries += 1
                    artifact_records.append(
                        self.process_found_file(
                            artifact_path,
                            domain,
                            "ext",
                            source_hosts=source_hosts,
                            source_shares=source_shares,
                            auth_username=auth_username,
                            enable_legacy_zip_callbacks=False,
                            apply_actions=apply_actions,
                            zip_depth=zip_depth + 1,
                        )
                    )

                if (
                    grouped_findings
                    and apply_actions
                    and self._handle_found_credentials_callback is not None
                ):
                    self._handle_found_credentials_callback(
                        grouped_findings,
                        domain,
                        source_hosts=source_hosts,
                        source_shares=source_shares,
                        auth_username=auth_username,
                        source_artifact=f"zip artifact analysis ({zip_path.name})",
                    )

                grouped_finding_count = sum(
                    len(entries) for entries in grouped_findings.values()
                )
                artifact_successes = sum(
                    1
                    for record in artifact_records
                    if record.status in {"processed", "processed_no_findings"}
                )
                processed_entry_count = (
                    extracted_text + extracted_documents + len(artifact_paths)
                )
                processed_preview = self._format_zip_internal_path_preview(
                    processed_internal_paths
                )
                skipped_preview = self._format_zip_internal_path_preview(
                    skipped_internal_paths
                )
                print_info_debug(
                    "ZIP selective processing summary: "
                    f"zip={mark_sensitive(str(zip_path), 'path')} "
                    f"supported_entries_total={len(all_supported_entries)} "
                    f"selected_entries={len(supported_entries)} "
                    f"processed_entry_count={processed_entry_count} "
                    f"skipped_entries={skipped_entries} "
                    f"skipped_due_limits={skipped_due_limits} "
                    f"nested_zip_entries={nested_zip_entries} "
                    f"processed_preview={processed_preview}"
                )
                if grouped_finding_count or structured_processed or artifact_successes:
                    notes: list[str] = []
                    notes.append(
                        "supported_entries="
                        f"{len(supported_entries)}/{len(all_supported_entries)}"
                    )
                    if grouped_finding_count:
                        notes.append(f"CredSweeper findings={grouped_finding_count}")
                    if structured_processed:
                        notes.append(f"structured_files={structured_processed}")
                    if artifact_successes:
                        notes.append(f"artifact_entries={artifact_successes}")
                    if nested_zip_entries:
                        notes.append(f"nested_zip_entries={nested_zip_entries}")
                    if skipped_entries:
                        notes.append(f"skipped_entries={skipped_entries}")
                    if skipped_due_limits:
                        notes.append(f"limit_skips={skipped_due_limits}")
                    if processed_preview:
                        notes.append(f"processed_entries={processed_preview}")
                    if skipped_preview:
                        notes.append(f"skipped_entries={skipped_preview}")
                    return ArtifactProcessingRecord(
                        path=zip_file,
                        filename=zip_path.name,
                        artifact_type="zip",
                        status="processed",
                        note=(
                            "ZIP selective analysis processed supported embedded entries: "
                            + ", ".join(notes)
                            + "."
                        ),
                        details={
                            "supported_entries_total": len(all_supported_entries),
                            "selected_entries": len(supported_entries),
                            "text_entries": extracted_text,
                            "document_entries": extracted_documents,
                            "artifact_entries": len(artifact_paths),
                            "nested_zip_entries": nested_zip_entries,
                            "cred_sweeper_findings": grouped_finding_count,
                            "structured_processed_files": structured_processed,
                            "artifact_successes": artifact_successes,
                            "skipped_entries": skipped_entries,
                            "limit_skips": skipped_due_limits,
                            "processed_preview": processed_internal_paths[:_ZIP_SELECTIVE_PREVIEW_LIMIT],
                            "skipped_preview": skipped_internal_paths[:_ZIP_SELECTIVE_PREVIEW_LIMIT],
                        },
                    )

                if processed_entry_count > 0:
                    notes: list[str] = [
                        f"supported_entries={len(supported_entries)}/{len(all_supported_entries)}",
                        f"text_entries={extracted_text}",
                        f"document_entries={extracted_documents}",
                        f"artifact_entries={len(artifact_paths)}",
                    ]
                    if nested_zip_entries:
                        notes.append(f"nested_zip_entries={nested_zip_entries}")
                    if skipped_entries:
                        notes.append(f"skipped_entries={skipped_entries}")
                    if skipped_due_limits:
                        notes.append(f"limit_skips={skipped_due_limits}")
                    if processed_preview:
                        notes.append(f"processed_entries={processed_preview}")
                    if skipped_preview:
                        notes.append(f"skipped_entries={skipped_preview}")
                    return ArtifactProcessingRecord(
                        path=zip_file,
                        filename=zip_path.name,
                        artifact_type="zip",
                        status="processed_no_findings",
                        note=(
                            "ZIP selective analysis processed supported embedded entries "
                            "but found no deterministic credentials: "
                            + ", ".join(notes)
                            + "."
                        ),
                        details={
                            "supported_entries_total": len(all_supported_entries),
                            "selected_entries": len(supported_entries),
                            "text_entries": extracted_text,
                            "document_entries": extracted_documents,
                            "artifact_entries": len(artifact_paths),
                            "nested_zip_entries": nested_zip_entries,
                            "skipped_entries": skipped_entries,
                            "limit_skips": skipped_due_limits,
                            "processed_preview": processed_internal_paths[:_ZIP_SELECTIVE_PREVIEW_LIMIT],
                            "skipped_preview": skipped_internal_paths[:_ZIP_SELECTIVE_PREVIEW_LIMIT],
                        },
                    )

                if skipped_entries:
                    return ArtifactProcessingRecord(
                        path=zip_file,
                        filename=zip_path.name,
                        artifact_type="zip",
                        status="manual_review",
                        note=(
                            "ZIP contained supported embedded entries but automatic "
                            "processing did not yield findings and some entries were "
                            f"skipped ({skipped_entries}). Review manually. "
                            f"Supported={len(supported_entries)}/{len(all_supported_entries)}. "
                            f"processed_entries={processed_preview or processed_entry_count}. "
                            f"skipped_entries={skipped_preview or skipped_entries}."
                        ),
                        manual_review=True,
                        details={
                            "supported_entries_total": len(all_supported_entries),
                            "selected_entries": len(supported_entries),
                            "skipped_entries": skipped_entries,
                            "limit_skips": skipped_due_limits,
                            "processed_preview": processed_internal_paths[:_ZIP_SELECTIVE_PREVIEW_LIMIT],
                            "skipped_preview": skipped_internal_paths[:_ZIP_SELECTIVE_PREVIEW_LIMIT],
                        },
                    )
            finally:
                shutil.rmtree(temp_root, ignore_errors=True)
        return None

    @staticmethod
    def _resolve_safe_zip_entry_destination(
        *,
        bucket_root: Path,
        entry_name: str,
    ) -> Path | None:
        """Return a safe extraction path for one ZIP entry or ``None`` on traversal."""
        normalized_parts = [
            part
            for part in Path(str(entry_name or "").replace("\\", "/")).parts
            if part not in {"", ".", ".."}
        ]
        if not normalized_parts:
            return None
        destination = bucket_root.joinpath(*normalized_parts).resolve(strict=False)
        try:
            destination.relative_to(bucket_root.resolve(strict=False))
        except ValueError:
            return None
        return destination

    def _scan_zip_credsweeper_bucket(
        self,
        *,
        root_path: Path,
        document_mode: bool,
        path_aliases: dict[str, str] | None = None,
    ) -> dict[str, list[tuple[str, float | None, str, int, str]]]:
        """Run CredSweeper against one extracted ZIP bucket when configured."""
        if not self._credsweeper_path or not root_path.exists():
            return {}
        findings = self._credsweeper_service.analyze_path_with_options(
            str(root_path),
            credsweeper_path=self._credsweeper_path,
            json_output_dir=str(root_path.parent / f".credsweeper_{root_path.name}"),
            include_custom_rules=True,
            rules_profile=(
                CREDSWEEPER_RULES_PROFILE_FILESYSTEM_DOC
                if document_mode
                else CREDSWEEPER_RULES_PROFILE_FILESYSTEM_TEXT
            ),
            custom_ml_threshold="0.0",
            doc=document_mode,
            jobs=get_default_credsweeper_jobs(),
        )
        if not path_aliases:
            return findings
        remapped: dict[str, list[tuple[str, float | None, str, int, str]]] = {}
        for rule_name, entries in findings.items():
            remapped_entries: list[tuple[str, float | None, str, int, str]] = []
            for value, ml_probability, context_line, line_num, file_path in entries:
                remapped_entries.append(
                    (
                        value,
                        ml_probability,
                        context_line,
                        line_num,
                        path_aliases.get(str(file_path), str(file_path)),
                    )
                )
            remapped[rule_name] = remapped_entries
        return remapped

    @staticmethod
    def _merge_grouped_credential_findings(
        left: dict[str, list[tuple[str, float | None, str, int, str]]],
        right: dict[str, list[tuple[str, float | None, str, int, str]]],
    ) -> dict[str, list[tuple[str, float | None, str, int, str]]]:
        """Merge two grouped CredSweeper result dictionaries."""
        merged: dict[str, list[tuple[str, float | None, str, int, str]]] = {
            key: list(value) for key, value in left.items()
        }
        for rule_name, entries in right.items():
            merged.setdefault(rule_name, []).extend(entries)
        return merged

    @staticmethod
    def _format_zip_internal_path_preview(paths: list[str], limit: int = _ZIP_SELECTIVE_PREVIEW_LIMIT) -> str:
        """Return a compact preview of internal ZIP paths."""
        normalized_paths = [str(path or "").strip() for path in paths if str(path or "").strip()]
        if not normalized_paths:
            return ""
        preview_items = normalized_paths[:limit]
        preview = ", ".join(preview_items)
        remaining = len(normalized_paths) - len(preview_items)
        if remaining > 0:
            preview = f"{preview}, +{remaining} more"
        return preview

    @staticmethod
    def _build_zip_entry_origin_path(
        *,
        zip_file: str,
        internal_path: str,
    ) -> str:
        """Build a logical origin path for one embedded ZIP entry."""
        normalized_internal = str(internal_path or "").replace("\\", "/").lstrip("/")
        if not normalized_internal:
            return str(zip_file)
        return f"{zip_file}!/{normalized_internal}"

    def _process_pfx_file(
        self,
        *,
        file_path: str,
        domain: str,
        apply_actions: bool,
    ) -> ArtifactProcessingRecord:
        """Process PFX artifacts via shared action dispatcher."""
        try:
            if apply_actions:
                handled = self._share_file_finding_action_service.apply_pfx_artifact(
                    domain=domain,
                    source_path=file_path,
                )
                note = (
                    "PFX processed successfully."
                    if handled
                    else "PFX requires password cracking or manual review."
                )
                status = "processed" if handled else "manual_review"
                return ArtifactProcessingRecord(
                    path=file_path,
                    filename=Path(file_path).name,
                    artifact_type="pfx",
                    status=status,
                    note=note,
                    manual_review=not handled,
                )
            return ArtifactProcessingRecord(
                path=file_path,
                filename=Path(file_path).name,
                artifact_type="pfx",
                status="skipped",
                note="PFX analysis skipped because follow-up actions are disabled.",
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error("Error processing PFX file.")
            return ArtifactProcessingRecord(
                path=file_path,
                filename=Path(file_path).name,
                artifact_type="pfx",
                status="failed",
                note=f"PFX processing failed: {type(exc).__name__}.",
            )

    def _process_keepass_file(
        self,
        *,
        file_path: str,
        domain: str,
        source_hosts: list[str] | None,
        source_shares: list[str] | None,
        auth_username: str | None,
        apply_actions: bool,
    ) -> ArtifactProcessingRecord:
        """Process KeePass artifacts via shared action dispatcher."""
        try:
            if apply_actions:
                extracted = self._share_file_finding_action_service.apply_keepass_artifact(
                    domain=domain,
                    source_path=file_path,
                    source_hosts=source_hosts,
                    source_shares=source_shares,
                    auth_username=auth_username,
                )
                note = (
                    f"KeePass artifact processed and yielded {extracted} extracted credential(s)."
                    if extracted > 0
                    else "KeePass artifact processed but no credentials were extracted automatically."
                )
                return ArtifactProcessingRecord(
                    path=file_path,
                    filename=Path(file_path).name,
                    artifact_type=Path(file_path).suffix.lstrip(".") or "kdbx",
                    status="processed" if extracted > 0 else "processed_no_findings",
                    note=note,
                )
            return ArtifactProcessingRecord(
                path=file_path,
                filename=Path(file_path).name,
                artifact_type=Path(file_path).suffix.lstrip(".") or "kdbx",
                status="skipped",
                note="KeePass analysis skipped because follow-up actions are disabled.",
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error("Error processing KeePass artifact.")
            return ArtifactProcessingRecord(
                path=file_path,
                filename=Path(file_path).name,
                artifact_type=Path(file_path).suffix.lstrip(".") or "kdbx",
                status="failed",
                note=f"KeePass processing failed: {type(exc).__name__}.",
            )


__all__ = [
    "ArtifactProcessingRecord",
    "SpideringService",
]
