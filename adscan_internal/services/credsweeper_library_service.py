"""In-memory CredSweeper execution helpers.

This service executes the installed CredSweeper library directly over in-memory
byte payloads without writing files to disk. It is intended for benchmarks and
future streamed SMB analysis workflows where a caller already has byte content
available from another transport such as ``rclone cat``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import logging
import sys

from adscan_internal import print_warning, print_warning_debug, telemetry
from adscan_internal.services.base_service import BaseService
from adscan_internal.services.credsweeper_service import (
    get_credsweeper_rules_paths,
    resolve_credsweeper_drop_ml_none_for_ruleset,
)
from adscan_internal.services.smb_sensitive_file_policy import (
    DOCUMENT_LIKE_CREDENTIAL_EXTENSIONS,
)


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class InMemoryCredSweeperTarget:
    """One in-memory content target for CredSweeper library execution."""

    content: bytes
    file_path: str
    file_type: str
    info: str = ""


def _get_vendored_credsweeper_root() -> Path:
    """Return the source-tree root for vendored CredSweeper fallback code."""
    project_root = Path(__file__).resolve().parents[2]
    return project_root / "external_tools" / "CredSweeper"


def _load_credsweeper_library() -> tuple[Any, Any, Any]:
    """Load CredSweeper library classes from the installed package.

    Falls back to the vendored source tree only in development environments
    where the pinned package is not installed in the active interpreter.
    """
    try:
        from credsweeper import (  # type: ignore
            ByteContentProvider,
            CredSweeper,
            DataContentProvider,
        )

        return CredSweeper, ByteContentProvider, DataContentProvider
    except ModuleNotFoundError:
        vendored_root = _get_vendored_credsweeper_root()
        if str(vendored_root) not in sys.path:
            sys.path.insert(0, str(vendored_root))
        from credsweeper import (  # type: ignore
            ByteContentProvider,
            CredSweeper,
            DataContentProvider,
        )

        return CredSweeper, ByteContentProvider, DataContentProvider


class CredSweeperLibraryService(BaseService):
    """Execute CredSweeper as a Python library over byte payloads."""

    def analyze_targets_with_options(
        self,
        targets: list[InMemoryCredSweeperTarget],
        *,
        rules_path: Optional[str] = None,
        include_custom_rules: bool = False,
        drop_ml_none: bool | None = None,
        ml_threshold: str = "0.1",
        doc: bool = False,
        depth: bool = False,
        no_filters: bool = False,
        jobs: int | None = None,
        find_by_ext: bool = False,
    ) -> Dict[str, List[Tuple[str, Optional[float], str, int, str]]]:
        """Analyze in-memory byte targets with CredSweeper library semantics."""
        findings: Dict[str, List[Tuple[str, Optional[float], str, int, str]]] = {}
        if not targets:
            return findings

        primary_rules, custom_rules = get_credsweeper_rules_paths()
        selected_primary = rules_path or primary_rules
        rulesets: list[tuple[str, Optional[str], bool, str]] = [
            (
                "primary",
                selected_primary,
                resolve_credsweeper_drop_ml_none_for_ruleset(
                    ruleset_label="primary",
                    drop_ml_none=drop_ml_none,
                ),
                ml_threshold,
            ),
        ]
        if include_custom_rules and custom_rules:
            rulesets.append(
                (
                    "custom",
                    custom_rules,
                    resolve_credsweeper_drop_ml_none_for_ruleset(
                        ruleset_label="custom",
                        drop_ml_none=drop_ml_none,
                    ),
                    "0.0",
                )
            )

        for _label, selected_rules, selected_drop_ml_none, selected_ml_threshold in rulesets:
            if not selected_rules:
                continue
            try:
                run_findings = self._run_ruleset(
                    targets=targets,
                    rules_path=selected_rules,
                    drop_ml_none=selected_drop_ml_none,
                    ml_threshold=selected_ml_threshold,
                    doc=doc,
                    depth=depth,
                    no_filters=no_filters,
                    jobs=jobs,
                    find_by_ext=find_by_ext,
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_warning(
                    "CredSweeper library analysis failed for one in-memory ruleset."
                )
                print_warning_debug(
                    f"CredSweeper library ruleset failure: {type(exc).__name__}: {exc}"
                )
                logger.exception("CredSweeper library ruleset failure")
                continue
            findings = self._merge_grouped_findings(findings, run_findings)
        return findings

    def _run_ruleset(
        self,
        *,
        targets: list[InMemoryCredSweeperTarget],
        rules_path: str,
        drop_ml_none: bool,
        ml_threshold: str,
        doc: bool,
        depth: bool,
        no_filters: bool,
        jobs: int | None,
        find_by_ext: bool,
    ) -> Dict[str, List[Tuple[str, Optional[float], str, int, str]]]:
        """Execute one CredSweeper ruleset over one batch of byte targets."""
        CredSweeper, ByteContentProvider, DataContentProvider = (
            _load_credsweeper_library()
        )
        pool_count = max(1, int(jobs or 1))
        analyzer = CredSweeper(
            rule_path=rules_path,
            stdout=False,
            use_filters=not no_filters,
            pool_count=pool_count,
            ml_threshold=float(ml_threshold),
            find_by_ext=find_by_ext,
            depth=1 if depth else 0,
            doc=doc,
            thrifty=False,
        )
        providers = [
            self._build_provider_for_target(
                target=target,
                byte_provider_cls=ByteContentProvider,
                data_provider_cls=DataContentProvider,
                doc=doc,
                depth=depth,
            )
            for target in targets
        ]
        analyzer.scan(providers)
        analyzer.post_processing()
        return self._normalize_candidates(
            candidates=list(analyzer.credential_manager.get_credentials()),
            drop_ml_none=drop_ml_none,
        )

    @staticmethod
    def _build_provider_for_target(
        *,
        target: InMemoryCredSweeperTarget,
        byte_provider_cls: Any,
        data_provider_cls: Any,
        doc: bool,
        depth: bool,
    ) -> Any:
        """Build the correct CredSweeper content provider for one target."""
        normalized_type = str(target.file_type or "").strip().lower()
        use_data_provider = bool(doc or depth)
        if not use_data_provider and normalized_type in DOCUMENT_LIKE_CREDENTIAL_EXTENSIONS:
            use_data_provider = True
        if use_data_provider:
            return data_provider_cls(
                data=target.content,
                file_path=target.file_path,
                file_type=target.file_type,
                info=target.info,
            )
        return byte_provider_cls(
            content=target.content,
            file_path=target.file_path,
            file_type=target.file_type,
            info=target.info,
        )

    @staticmethod
    def _normalize_candidates(
        *,
        candidates: list[Any],
        drop_ml_none: bool,
    ) -> Dict[str, List[Tuple[str, Optional[float], str, int, str]]]:
        """Normalize CredSweeper Candidate objects into ADscan grouped findings."""
        findings: Dict[str, List[Tuple[str, Optional[float], str, int, str]]] = {}
        seen_credentials: set[Tuple[str, str, int, str]] = set()

        for candidate in candidates:
            rule_name = str(getattr(candidate, "rule_name", "") or "")
            ml_probability = getattr(candidate, "ml_probability", None)
            if drop_ml_none and ml_probability is None:
                continue
            try:
                if ml_probability is not None:
                    ml_probability = float(ml_probability)
            except (TypeError, ValueError):
                ml_probability = None
            findings.setdefault(rule_name, [])

            for line_data in list(getattr(candidate, "line_data_list", []) or []):
                value = str(getattr(line_data, "value", "") or "")
                context_line = str(getattr(line_data, "line", "") or "")
                file_path = str(getattr(line_data, "path", "") or "")
                try:
                    line_num = int(getattr(line_data, "line_num", 0) or 0)
                except (TypeError, ValueError):
                    line_num = 0
                if not value or len(value) < 3:
                    continue
                dedup_key = (rule_name, value, line_num, file_path)
                if dedup_key in seen_credentials:
                    continue
                seen_credentials.add(dedup_key)
                findings[rule_name].append(
                    (value, ml_probability, context_line, line_num, file_path)
                )
        return findings

    @staticmethod
    def _merge_grouped_findings(
        left: Dict[str, List[Tuple[str, Optional[float], str, int, str]]],
        right: Dict[str, List[Tuple[str, Optional[float], str, int, str]]],
    ) -> Dict[str, List[Tuple[str, Optional[float], str, int, str]]]:
        """Merge two grouped CredSweeper findings dictionaries."""
        merged: Dict[str, List[Tuple[str, Optional[float], str, int, str]]] = {
            rule_name: list(entries) for rule_name, entries in left.items()
        }
        seen: set[Tuple[str, str, int, str]] = set()
        for rule_name, entries in merged.items():
            for entry in entries:
                seen.add((rule_name, entry[0], entry[3], entry[4]))

        for rule_name, entries in right.items():
            bucket = merged.setdefault(rule_name, [])
            for entry in entries:
                dedup_key = (rule_name, entry[0], entry[3], entry[4])
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                bucket.append(entry)
        return merged


__all__ = [
    "CredSweeperLibraryService",
    "InMemoryCredSweeperTarget",
]
