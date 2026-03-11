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
import logging
import os
import subprocess
from pathlib import Path
import shlex
import shutil

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
from adscan_internal.services.credsweeper_service import CredSweeperService
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
    SMB_SENSITIVE_SCAN_PHASE_DOCUMENT_CREDENTIALS,
    SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS,
)
from adscan_internal import telemetry


logger = logging.getLogger(__name__)


CommandExecutor = Callable[..., subprocess.CompletedProcess[str] | None]


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
    ) -> dict[str, int]:
        """Process deterministic structured files under one local loot root.

        This is the shared backend-agnostic path for structured findings such as
        GPP ``cpassword`` in XML files. It intentionally does not depend on
        CredSweeper so those findings remain stable across backends.
        """
        suffix_to_scan_type = self._structured_suffix_to_scan_type_for_phase(phase)
        if not suffix_to_scan_type:
            return {"candidate_files": 0, "processed_files": 0}

        root = Path(str(root_path or "")).expanduser().resolve(strict=False)
        if not root.is_dir():
            return {"candidate_files": 0, "processed_files": 0}

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
                    f"phase={phase} count={len(xml_candidates)} preview=[{preview}]"
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
                scan_type = remaining_suffixes.get(file_path.suffix.casefold())
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
        for file_path, scan_type in candidates:
            self.process_found_file(
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

        print_info_debug(
            "Deterministic structured-file post-scan completed: "
            f"phase={phase} candidate_files={len(candidates)} processed_files={processed} "
            f"root={root}"
        )
        return {"candidate_files": len(candidates), "processed_files": processed}

    def _find_xml_cpassword_candidates(self, root: Path) -> list[str] | None:
        """Return XML files containing ``cpassword=`` using ``rg`` when available.

        Returns ``None`` when ``rg`` is unavailable or fails unexpectedly so the
        caller can fall back to the Python filesystem walk.
        """
        rg_path = shutil.which("rg")
        if not rg_path:
            return None

        command = " ".join(
            [
                shlex.quote(rg_path),
                "-l",
                "-0",
                "-i",
                "--iglob",
                shlex.quote("*.xml"),
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
    ) -> None:
        """Process a manspider-discovered file according to its extension."""
        filename = os.path.basename(file_path)
        filename_lower = filename.lower()

        if filename_lower.endswith(".xml") and scan_type == "gpp":
            self._process_gpp_xml_file(
                file_path=file_path,
                domain=domain,
                filename=filename,
                source_hosts=source_hosts,
                source_shares=source_shares,
                auth_username=auth_username,
                apply_actions=apply_actions,
            )
            return

        if filename_lower.endswith((".yml", ".yaml")) and scan_type == "gpp":
            self._process_yml_file(
                file_path=file_path,
                domain=domain,
                filename=filename,
                apply_actions=apply_actions,
            )
            return

        if filename_lower.endswith(".xlsm") and scan_type == "ext":
            self._process_xlsm_file(
                file_path=file_path,
                domain=domain,
                filename=filename,
                apply_actions=apply_actions,
            )
            return

        if filename_lower.endswith(".dmp") and scan_type == "ext":
            print_warning(f"Memory dump file found: {filename}")
            self._process_dmp_file(file_path, domain, apply_actions=apply_actions)
            return

        if filename_lower.endswith(".pfx") and scan_type == "ext":
            print_info_verbose(f"Found .pfx file: {filename}")
            self._process_pfx_file(
                file_path=file_path,
                domain=domain,
                apply_actions=apply_actions,
            )
            return

        if filename_lower.endswith(".zip") and scan_type == "ext":
            print_info_verbose(f"Found .zip file: {filename}")
            if enable_legacy_zip_callbacks and self._list_zip_callback:
                self._list_zip_callback(file_path)
            if enable_legacy_zip_callbacks and self._extract_zip_callback:
                self._extract_zip_callback(file_path, domain)
            self._process_zip_file(file_path, domain, apply_actions=apply_actions)
            return

        print_warning(f"No interesting information found in {scan_type}")

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
    ) -> None:
        """Process multiple found files, optionally in parallel.

        Parallel execution is only enabled for the safe, analysis-only case
        where no follow-up actions or legacy ZIP callbacks are requested.
        """
        normalized_paths = [
            str(path or "").strip() for path in file_paths if str(path or "").strip()
        ]
        if not normalized_paths:
            return

        workers = max(1, int(max_workers or 1))
        allow_parallel = (
            workers > 1
            and not apply_actions
            and not enable_legacy_zip_callbacks
        )
        if not allow_parallel:
            for file_path in normalized_paths:
                self.process_found_file(
                    file_path,
                    domain,
                    scan_type,
                    source_hosts=source_hosts,
                    source_shares=source_shares,
                    auth_username=auth_username,
                    enable_legacy_zip_callbacks=enable_legacy_zip_callbacks,
                    apply_actions=apply_actions,
                )
            return

        print_info_debug(
            "Processing artifact batch in parallel: "
            f"files={len(normalized_paths)} workers={workers} scan_type={scan_type}"
        )

        def _process(file_path: str) -> None:
            self.process_found_file(
                file_path,
                domain,
                scan_type,
                source_hosts=source_hosts,
                source_shares=source_shares,
                auth_username=auth_username,
                enable_legacy_zip_callbacks=enable_legacy_zip_callbacks,
                apply_actions=apply_actions,
            )

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(_process, file_path) for file_path in normalized_paths]
            for future in as_completed(futures):
                future.result()

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
    ) -> None:
        """Process GPP XML files using shared deterministic analyzer."""
        try:
            marked_file_path = mark_sensitive(file_path, "path")
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
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning("Error processing GPP XML file.")

    def _process_yml_file(
        self,
        *,
        file_path: str,
        domain: str,
        filename: str,
        apply_actions: bool,
    ) -> None:
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
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error("Error processing yml file.")

    def _process_xlsm_file(
        self,
        *,
        file_path: str,
        domain: str,
        filename: str,
        apply_actions: bool,
    ) -> None:
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
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error(f"Error executing olevba on {filename}.")

    def _process_dmp_file(
        self,
        dmp_file: str,
        domain: str,
        *,
        apply_actions: bool,
    ) -> None:
        """Process a .DMP file through the shared deterministic analyzer."""
        try:
            result = self._share_file_analyzer_service.analyze_local_file(
                source_path=dmp_file
            )
            for note in result.notes:
                print_info_verbose(note)
            if not result.handled:
                print_warning("Deterministic analyzer did not handle this DMP file.")
                return
            stats = None
            if apply_actions:
                stats = self._share_file_finding_action_service.apply_findings(
                    domain=domain,
                    source_path=dmp_file,
                    findings=result.findings,
                )
            if apply_actions and stats and stats.by_type.get("ntlm_hash", 0) == 0:
                print_warning("No valid credentials found in the dump file")
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error("Error processing DMP file.")

    def _process_zip_file(
        self,
        zip_file: str,
        domain: str,
        *,
        apply_actions: bool,
    ) -> None:
        """Process ZIP artifacts through the shared deterministic analyzer."""
        try:
            result = self._share_file_analyzer_service.analyze_local_file(
                source_path=zip_file
            )
            for note in result.notes:
                print_info_verbose(note)
            if not result.handled:
                return
            stats = None
            if apply_actions:
                stats = self._share_file_finding_action_service.apply_findings(
                    domain=domain,
                    source_path=zip_file,
                    findings=result.findings,
                )
            if apply_actions and stats and stats.by_type.get("ntlm_hash", 0) == 0:
                print_info_verbose("No deterministic credential findings in ZIP file.")
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error("Error processing ZIP file.")

    def _process_pfx_file(
        self,
        *,
        file_path: str,
        domain: str,
        apply_actions: bool,
    ) -> None:
        """Process PFX artifacts via shared action dispatcher."""
        try:
            if apply_actions:
                self._share_file_finding_action_service.apply_pfx_artifact(
                    domain=domain,
                    source_path=file_path,
                )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error("Error processing PFX file.")


__all__ = [
    "SpideringService",
]
