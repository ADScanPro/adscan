"""CIFS-mounted share scanning with CredSweeper.

This service scans mounted SMB share content through a local CIFS mount and
runs CredSweeper directly on candidate files. It is intended as the
deterministic successor to the legacy ``manspider + CredSweeper`` flow.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import os
import time

from adscan_internal import print_info_debug, print_info_verbose
from adscan_internal.services.base_service import BaseService
from adscan_internal.services.cifs_share_mapping_service import CIFSShareMappingService
from adscan_internal.services.credsweeper_service import CredSweeperService
from adscan_internal.services.credsweeper_service import (
    CREDSWEEPER_RULES_PROFILE_FILESYSTEM_DOC,
    CREDSWEEPER_RULES_PROFILE_FILESYSTEM_TEXT,
)
from adscan_internal.services.smb_exclusion_policy import (
    is_globally_excluded_smb_relative_path,
    prune_excluded_walk_dirs,
)
from adscan_internal.services.smb_sensitive_file_policy import (
    DEFAULT_SMB_SENSITIVE_FILE_PROFILE,
    get_sensitive_file_profile,
    resolve_effective_sensitive_extension,
)


@dataclass(slots=True)
class CIFSCredSweeperScanResult:
    """Summary for one CIFS-backed CredSweeper scan run."""

    candidate_files: int = 0
    scanned_files: int = 0
    files_with_findings: int = 0
    mapped_shares: int = 0
    prepare_seconds: float = 0.0
    analysis_seconds: float = 0.0
    findings: dict[str, list[tuple[str, float | None, str, int, str]]] = field(
        default_factory=dict
    )

    @property
    def total_findings(self) -> int:
        """Return total count of grouped credential-like findings."""
        return sum(len(values) for values in self.findings.values())


class CIFSCredSweeperScanService(BaseService):
    """Scan mounted SMB shares with CredSweeper using local filesystem access."""

    DEFAULT_PROFILE = DEFAULT_SMB_SENSITIVE_FILE_PROFILE

    def scan_mounted_shares(
        self,
        *,
        mount_root: str,
        hosts: list[str],
        shares: list[str],
        credsweeper_service: CredSweeperService,
        credsweeper_path: str | None,
        json_output_dir: str | None = None,
        profile: str = DEFAULT_SMB_SENSITIVE_FILE_PROFILE,
        aggregate_map_path: str | None = None,
        document_depth: bool = False,
    ) -> CIFSCredSweeperScanResult:
        """Scan CIFS-mounted shares and aggregate CredSweeper findings.

        Args:
            mount_root: Root directory where CIFS shares are mounted locally.
            hosts: Target hosts to scan.
            shares: Share names to scan.
            credsweeper_service: Initialized CredSweeper service wrapper.
            credsweeper_path: Path to CredSweeper executable.
            json_output_dir: Optional writable directory for CredSweeper JSON
                artifacts generated during scanning.

        Returns:
            Summary object with scan counters and grouped findings.
        """
        result = CIFSCredSweeperScanResult()
        mount_root_path = Path(mount_root).expanduser().resolve(strict=False)
        if not mount_root_path.is_dir():
            self.logger.warning("CIFS mount root is not a directory: %s", mount_root)
            return result
        if not credsweeper_path:
            self.logger.warning("CredSweeper path missing for CIFS share scan.")
            return result

        mapping_service = CIFSShareMappingService()
        unique_hosts = self._unique_non_empty(hosts)
        unique_shares = self._unique_non_empty(shares)
        allow_share_fallback = len(unique_hosts) <= 1
        prepare_started = time.perf_counter()
        mapped_candidates = mapping_service.resolve_candidate_local_paths_from_aggregate(
            aggregate_map_path=str(aggregate_map_path or "").strip(),
            mount_root=str(mount_root_path),
            hosts=unique_hosts,
            shares=unique_shares,
            extensions=self._profile_extensions(profile=profile),
        )
        result.prepare_seconds += max(0.0, time.perf_counter() - prepare_started)
        if mapped_candidates:
            result.mapped_shares = len(unique_shares)
            self._scan_candidate_paths(
                candidate_paths=mapped_candidates,
                credsweeper_service=credsweeper_service,
                credsweeper_path=credsweeper_path,
                json_output_dir=json_output_dir,
                profile=profile,
                document_depth=document_depth,
                result=result,
            )
            return result

        for host in unique_hosts:
            for share in unique_shares:
                prepare_started = time.perf_counter()
                share_root = mapping_service.resolve_share_mount_path(
                    mount_root=mount_root_path,
                    host=host,
                    share=share,
                    allow_share_root_fallback=allow_share_fallback,
                )
                result.prepare_seconds += max(0.0, time.perf_counter() - prepare_started)
                if share_root is None:
                    print_info_debug(
                        "[cifs-credsweeper] Share root not resolved: "
                        f"host={host} share={share}"
                    )
                    continue
                result.mapped_shares += 1
                self._scan_one_share_root(
                    host=host,
                    share=share,
                    share_root=share_root,
                    credsweeper_service=credsweeper_service,
                    credsweeper_path=credsweeper_path,
                    json_output_dir=json_output_dir,
                    profile=profile,
                    document_depth=document_depth,
                    result=result,
                )

        return result

    def _scan_candidate_paths(
        self,
        *,
        candidate_paths: list[str],
        credsweeper_service: CredSweeperService,
        credsweeper_path: str,
        json_output_dir: str | None,
        profile: str,
        document_depth: bool,
        result: CIFSCredSweeperScanResult,
    ) -> None:
        """Scan pre-resolved CIFS candidate files without walking the tree."""
        for candidate_path in candidate_paths:
            file_path = Path(candidate_path)
            mode = self._classify_candidate_mode(file_path, profile=profile)
            if mode is None:
                continue
            result.candidate_files += 1
            print_info_debug(
                "[cifs-credsweeper] Scanning mapped candidate file: "
                f"path={file_path} mode={mode}"
            )
            analysis_started = time.perf_counter()
            findings = self._scan_one_file(
                file_path=file_path,
                mode=mode,
                credsweeper_service=credsweeper_service,
                credsweeper_path=credsweeper_path,
                json_output_dir=json_output_dir,
                document_depth=document_depth,
            )
            result.analysis_seconds += max(0.0, time.perf_counter() - analysis_started)
            result.scanned_files += 1
            if findings:
                result.files_with_findings += 1
                self._merge_findings(result.findings, findings)

    def _scan_one_share_root(
        self,
        *,
        host: str,
        share: str,
        share_root: Path,
        credsweeper_service: CredSweeperService,
        credsweeper_path: str,
        json_output_dir: str | None,
        profile: str,
        document_depth: bool,
        result: CIFSCredSweeperScanResult,
    ) -> None:
        """Walk one mounted share path and aggregate findings."""
        visited_files = 0
        candidate_files = 0
        for dirpath, dirnames, filenames in os.walk(share_root):
            prune_excluded_walk_dirs(dirnames)
            base_dir = Path(dirpath)
            for filename in sorted(filenames):
                loop_prepare_started = time.perf_counter()
                file_path = base_dir / filename
                try:
                    relative_path = file_path.relative_to(share_root).as_posix()
                except ValueError:
                    result.prepare_seconds += max(
                        0.0, time.perf_counter() - loop_prepare_started
                    )
                    continue
                if is_globally_excluded_smb_relative_path(relative_path):
                    result.prepare_seconds += max(
                        0.0, time.perf_counter() - loop_prepare_started
                    )
                    continue
                visited_files += 1
                mode = self._classify_candidate_mode(file_path, profile=profile)
                if mode is None:
                    result.prepare_seconds += max(
                        0.0, time.perf_counter() - loop_prepare_started
                    )
                    continue

                candidate_files += 1
                result.candidate_files += 1
                result.prepare_seconds += max(
                    0.0, time.perf_counter() - loop_prepare_started
                )
                print_info_debug(
                    "[cifs-credsweeper] Scanning candidate file: "
                    f"path={file_path} mode={mode}"
                )
                analysis_started = time.perf_counter()
                findings = self._scan_one_file(
                    file_path=file_path,
                    mode=mode,
                    credsweeper_service=credsweeper_service,
                    credsweeper_path=credsweeper_path,
                    json_output_dir=json_output_dir,
                    document_depth=document_depth,
                )
                result.analysis_seconds += max(0.0, time.perf_counter() - analysis_started)
                result.scanned_files += 1
                if findings:
                    result.files_with_findings += 1
                    self._merge_findings(result.findings, findings)
        print_info_debug(
            "[cifs-credsweeper] Share scan summary: "
            f"host={host} share={share} share_root={share_root} "
            f"visited_files={visited_files} candidate_files={candidate_files}"
        )

    def _scan_one_file(
        self,
        *,
        file_path: Path,
        mode: str,
        credsweeper_service: CredSweeperService,
        credsweeper_path: str,
        json_output_dir: str | None,
        document_depth: bool,
    ) -> dict[str, list[tuple[str, float | None, str, int, str]]]:
        """Run CredSweeper against one local mounted file."""
        file_path_str = str(file_path)
        try:
            if mode == "doc":
                print_info_verbose(
                    f"Analyzing mounted document with CredSweeper: {file_path_str}"
                )
                return credsweeper_service.analyze_file_with_options(
                    file_path_str,
                    credsweeper_path=credsweeper_path,
                    json_output_dir=json_output_dir,
                    include_custom_rules=True,
                    rules_profile=CREDSWEEPER_RULES_PROFILE_FILESYSTEM_DOC,
                    doc=True,
                    depth=document_depth,
                )

            print_info_verbose(
                f"Analyzing mounted text file with CredSweeper: {file_path_str}"
            )
            return credsweeper_service.analyze_file_with_options(
                file_path_str,
                credsweeper_path=credsweeper_path,
                json_output_dir=json_output_dir,
                include_custom_rules=True,
                rules_profile=CREDSWEEPER_RULES_PROFILE_FILESYSTEM_TEXT,
            )
        except Exception:
            self.logger.exception(
                "CredSweeper scan failed for mounted CIFS file: %s",
                file_path_str,
            )
            return {}

    @staticmethod
    def _classify_candidate_mode(file_path: Path, *, profile: str) -> str | None:
        """Classify file path into supported CredSweeper scan mode."""
        profile_groups = get_sensitive_file_profile(profile or CIFSCredSweeperScanService.DEFAULT_PROFILE)
        text_extensions = set(profile_groups["text_like"])
        document_extensions = set(profile_groups["document_like"])
        suffix = resolve_effective_sensitive_extension(
            str(file_path),
            allowed_extensions=tuple(text_extensions | document_extensions),
        )
        if suffix in text_extensions:
            return "text"
        if suffix in document_extensions:
            return "doc"
        return None

    @staticmethod
    def _profile_extensions(*, profile: str) -> tuple[str, ...]:
        """Return merged suffixes for one CIFS CredSweeper profile."""
        profile_groups = get_sensitive_file_profile(
            profile or CIFSCredSweeperScanService.DEFAULT_PROFILE
        )
        return tuple(profile_groups["text_like"] + profile_groups["document_like"])

    @staticmethod
    def _merge_findings(
        aggregate: dict[str, list[tuple[str, float | None, str, int, str]]],
        findings: dict[str, list[tuple[str, float | None, str, int, str]]],
    ) -> None:
        """Merge grouped CredSweeper findings into one aggregate dictionary."""
        for rule_name, entries in findings.items():
            if not isinstance(entries, list) or not entries:
                continue
            aggregate.setdefault(rule_name, []).extend(entries)

    @staticmethod
    def _unique_non_empty(values: list[str]) -> list[str]:
        """Return stable, unique, non-empty strings."""
        seen: set[str] = set()
        ordered: list[str] = []
        for value in values:
            normalized = str(value or "").strip()
            if not normalized:
                continue
            key = normalized.casefold()
            if key in seen:
                continue
            seen.add(key)
            ordered.append(normalized)
        return ordered


__all__ = [
    "CIFSCredSweeperScanResult",
    "CIFSCredSweeperScanService",
]
