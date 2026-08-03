"""CredSweeper service for credential discovery in textual files and logs.

This module centralizes:

- Resolution of CredSweeper rules files (``config.yaml`` and ``custom_config.yaml``)
- Execution of the installed CredSweeper Python library
- Normalization of CredSweeper candidates into a Python-friendly structure

The goal is to decouple CredSweeper-specific logic from the monolithic
``adscan.py`` file and make it easier to test and reuse from different
workflows (manspider spidering logs, PowerShell history, transcripts, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from importlib import metadata as importlib_metadata
from importlib import resources as importlib_resources
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from contextlib import nullcontext
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import yaml

from rich.markup import escape as rich_escape

from adscan_internal.services.base_service import BaseService
from adscan_internal.path_utils import get_adscan_home
from adscan_internal.services.smb_sensitive_file_policy import (
    resolve_effective_sensitive_extension,
)
from adscan_internal.services.xml_sanitization_service import (
    build_sanitized_xml_analysis_copy,
    build_sanitized_xml_overlay,
    contains_unescaped_xml_ampersand,
    create_analysis_temp_root,
    discover_malformed_xml_candidates,
)
from adscan_internal import (
    print_info_verbose,
    print_info_debug,
    print_warning,
    print_warning_debug,
)
from adscan_internal import telemetry
from adscan_core.rich_output import print_exception


logger = logging.getLogger(__name__)


CommandExecutor = Callable[..., subprocess.CompletedProcess[str] | None]


CREDSWEEPER_RULES_PROFILE_DEFAULT = "default"
CREDSWEEPER_RULES_PROFILE_FILESYSTEM = "filesystem"
CREDSWEEPER_RULES_PROFILE_FILESYSTEM_TEXT = "filesystem_text"
CREDSWEEPER_RULES_PROFILE_FILESYSTEM_DOC = "filesystem_doc"
CREDSWEEPER_RULES_PROFILE_LDAP_DESCRIPTION = "ldap_description"

# Generic keyword-only rules are useful for targeted code/config analysis, but
# they create disproportionate noise in large Windows filesystem crawls.
FILESYSTEM_RULESET_EXCLUDED_RULE_NAMES = {
    "API",
    "Auth",
    "Credential",
    "Key",
    "Nonce",
    "Password",
    "Salt",
    "Secret",
    "Token",
}

LDAP_DESCRIPTION_RULESET_ALLOWED_RULE_NAMES = {
    "DOC_GET",
    "DOC_CREDENTIALS",
    "SECRET_PAIR",
    "PASSWD_PAIR",
    "IP_ID_PASSWORD_TRIPLE",
    "ID_PAIR_PASSWD_PAIR",
    "ID_PASSWD_PAIR",
}

# Broad filesystem text scans run CredSweeper in ``doc=False`` mode because the
# inputs are still plain-text files. However, a small subset of upstream
# document-oriented rules is still valuable for narrative text such as:
#   "Your default password is: ..."
# CredSweeper only evaluates ``target=doc`` rules when ``--doc`` is enabled, so
# for this explicit allowlist we widen the generated profile target to
# ``['code', 'doc']``. We keep this list intentionally small to avoid
# reintroducing the noisy keyword-style document rules into large filesystem
# crawls.
FILESYSTEM_TEXT_NARRATIVE_RULE_NAMES = {
    "DOC_GET",
    "DOC_CREDENTIALS",
    "SECRET_PAIR",
    "PASSWD_PAIR",
    "IP_ID_PASSWORD_TRIPLE",
    "ID_PAIR_PASSWD_PAIR",
    "ID_PASSWD_PAIR",
}

CREDSWEEPER_TIMEOUT_TEXT_SECONDS = 300
CREDSWEEPER_TIMEOUT_DOC_SECONDS = 900
CREDSWEEPER_TIMEOUT_DOC_DEPTH_SECONDS = 1200
CREDSWEEPER_TIMEOUT_TEXT_MAX_SECONDS = 900
CREDSWEEPER_TIMEOUT_DOC_MAX_SECONDS = 3600
CREDSWEEPER_TIMEOUT_DOC_DEPTH_MAX_SECONDS = 5400


def _apply_credsweeper_timeout_growth(
    *,
    base_timeout: int,
    max_timeout: int,
    candidate_files: int | None,
    files_per_step: int,
    seconds_per_step: int,
) -> int:
    """Grow one timeout budget progressively as file volume increases."""
    try:
        normalized_count = max(0, int(candidate_files or 0))
    except (TypeError, ValueError):
        normalized_count = 0
    if normalized_count <= 0:
        return base_timeout
    step_size = max(1, int(files_per_step))
    step_seconds = max(1, int(seconds_per_step))
    extra_steps = (normalized_count - 1) // step_size
    grown_timeout = base_timeout + (extra_steps * step_seconds)
    return min(max_timeout, grown_timeout)


def get_default_credsweeper_timeout(
    *,
    doc: bool = False,
    depth: bool = False,
    candidate_files: int | None = None,
) -> int:
    """Return the default CredSweeper command timeout for one scan mode.

    Broad document scans are materially slower than plain-text scans because
    CredSweeper has to parse container/document formats before evaluating rules.
    Keep the default text timeout strict, but give ``--doc`` and ``--depth``
    workflows a larger execution budget. In large loot sets, grow the timeout
    progressively instead of relying on one fixed global ceiling.
    """
    if depth:
        return _apply_credsweeper_timeout_growth(
            base_timeout=CREDSWEEPER_TIMEOUT_DOC_DEPTH_SECONDS,
            max_timeout=CREDSWEEPER_TIMEOUT_DOC_DEPTH_MAX_SECONDS,
            candidate_files=candidate_files,
            files_per_step=1500,
            seconds_per_step=60,
        )
    if doc:
        return _apply_credsweeper_timeout_growth(
            base_timeout=CREDSWEEPER_TIMEOUT_DOC_SECONDS,
            max_timeout=CREDSWEEPER_TIMEOUT_DOC_MAX_SECONDS,
            candidate_files=candidate_files,
            files_per_step=2000,
            seconds_per_step=60,
        )
    return _apply_credsweeper_timeout_growth(
        base_timeout=CREDSWEEPER_TIMEOUT_TEXT_SECONDS,
        max_timeout=CREDSWEEPER_TIMEOUT_TEXT_MAX_SECONDS,
        candidate_files=candidate_files,
        files_per_step=10000,
        seconds_per_step=60,
    )


def resolve_credsweeper_drop_ml_none_for_ruleset(
    *,
    ruleset_label: str,
    drop_ml_none: bool | None,
) -> bool:
    """Resolve whether one ruleset should discard findings without ML confidence.

    Default service policy is intentionally asymmetric:
    - primary rules: drop ``ml_probability=None``
    - custom rules: keep ``ml_probability=None``

    This matches the legacy ``analyze_file()`` behavior that filtered noisy
    primary-rule findings such as ``UUID`` while preserving custom-rule output.

    Args:
        ruleset_label: Logical ruleset name, typically ``primary`` or ``custom``.
        drop_ml_none: Optional caller override. ``True`` drops all ``None``
            findings, ``False`` preserves all of them, and ``None`` applies the
            default policy above.

    Returns:
        Boolean decision for whether findings with ``ml_probability=None`` should
        be discarded for this ruleset.
    """
    if drop_ml_none is True:
        return True
    if drop_ml_none is False:
        return False
    return str(ruleset_label).strip().lower() == "primary"


def _get_installed_credsweeper_config_path() -> Optional[str]:
    """Return the primary rules file shipped by the installed CredSweeper package."""

    try:
        package_root = importlib_resources.files("credsweeper")
        config_resource = package_root / "rules" / "config.yaml"
        if config_resource.is_file():
            return str(config_resource)
    except Exception:  # noqa: BLE001
        return None
    return None


def _get_credsweeper_config_path() -> Optional[str]:
    """Return path to the primary CredSweeper rules file (``config.yaml``), if any.

    Priority:
    1. User override in ``$ADSCAN_HOME/credsweeper_config.yaml``
    2. Installed CredSweeper package rules
    3. Bundled config inside PyInstaller (legacy compatibility)
    4. Vendored upstream snapshot under ``external_tools``
    """

    # 1) User override in ADscan base directory
    override_path = get_adscan_home() / "credsweeper_config.yaml"
    if override_path.is_file():
        return str(override_path)

    installed_config = _get_installed_credsweeper_config_path()
    if installed_config:
        return installed_config

    # 3) PyInstaller bundle: config.yaml is bundled via --add-data
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        meipass = getattr(sys, "_MEIPASS", None)  # type: ignore[attr-defined]
        if meipass:
            bundled_path = Path(meipass) / "config.yaml"
            # Depending on how --add-data is interpreted, config.yaml may be:
            # - A direct file: <_MEIPASS>/config.yaml
            # - A directory:  <_MEIPASS>/config.yaml/config.yaml
            if bundled_path.is_file():
                return str(bundled_path)
            if bundled_path.is_dir():
                nested_path = bundled_path / "config.yaml"
                if nested_path.exists():
                    return str(nested_path)

    return _get_upstream_credsweeper_config_path()


def _get_upstream_credsweeper_config_path() -> Optional[str]:
    """Return the vendored upstream CredSweeper primary rules file when present."""

    installed_config = _get_installed_credsweeper_config_path()
    if installed_config:
        return installed_config
    project_root = Path(__file__).resolve().parents[2]
    upstream_config = (
        project_root / "external_tools" / "CredSweeper" / "credsweeper" / "rules" / "config.yaml"
    )
    if upstream_config.is_file():
        return str(upstream_config)
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        meipass = getattr(sys, "_MEIPASS", None)  # type: ignore[attr-defined]
        if meipass:
            bundled_path = Path(meipass) / "config.yaml"
            if bundled_path.is_file():
                return str(bundled_path)
            if bundled_path.is_dir():
                nested_path = bundled_path / "config.yaml"
                if nested_path.exists():
                    return str(nested_path)
    return None


def _get_vendored_credsweeper_version() -> Optional[str]:
    """Return the vendored CredSweeper source version when available."""

    project_root = Path(__file__).resolve().parents[2]
    init_path = project_root / "external_tools" / "CredSweeper" / "credsweeper" / "__init__.py"
    if not init_path.is_file():
        return None
    try:
        init_text = init_path.read_text(encoding="utf-8")
    except OSError:
        return None
    match = re.search(r'__version__\s*=\s*"([^"]+)"', init_text)
    if match:
        return match.group(1).strip()
    return None


def _get_installed_credsweeper_version() -> Optional[str]:
    """Return the installed CredSweeper package version when available."""

    try:
        return importlib_metadata.version("credsweeper")
    except importlib_metadata.PackageNotFoundError:
        return None


def _get_credsweeper_custom_rules_path() -> Optional[str]:
    """Return path to the secondary/custom CredSweeper rules file (``custom_config.yaml``)."""

    # 1) User override in ADscan base directory
    override_path = get_adscan_home() / "custom_config.yaml"
    if override_path.is_file():
        return str(override_path)

    # 2) PyInstaller bundle: custom_config.yaml is bundled via --add-data
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        meipass = getattr(sys, "_MEIPASS", None)  # type: ignore[attr-defined]
        if meipass:
            bundled_path = Path(meipass) / "custom_config.yaml"
            # Depending on how --add-data is interpreted, custom_config.yaml may be:
            # - A direct file: <_MEIPASS>/custom_config.yaml
            # - A directory:  <_MEIPASS>/custom_config.yaml/custom_config.yaml
            if bundled_path.is_file():
                return str(bundled_path)
            if bundled_path.is_dir():
                nested_path = bundled_path / "custom_config.yaml"
                if nested_path.exists():
                    return str(nested_path)

    # 3) Development mode: custom_config.yaml in project root
    project_root = Path(__file__).resolve().parents[2]
    root_config = project_root / "custom_config.yaml"
    if root_config.is_file():
        return str(root_config)

    return None


def _normalize_credsweeper_targets(target_value: Any) -> set[str]:
    """Return normalized CredSweeper target names from YAML rule payload."""

    if isinstance(target_value, str):
        return {target_value.strip().lower()} if target_value.strip() else set()
    if isinstance(target_value, list):
        return {
            str(item).strip().lower()
            for item in target_value
            if str(item).strip()
        }
    return set()


def _rule_targets_profile(rule: dict[str, Any], profile: str) -> bool:
    """Return whether one upstream rule should stay in the requested profile."""

    targets = _normalize_credsweeper_targets(rule.get("target"))
    if profile in {
        CREDSWEEPER_RULES_PROFILE_FILESYSTEM,
    }:
        return "code" in targets
    if profile == CREDSWEEPER_RULES_PROFILE_FILESYSTEM_TEXT:
        if "code" in targets:
            return True
        rule_name = str(rule.get("name", "")).strip()
        return (
            "doc" in targets
            and rule_name in FILESYSTEM_TEXT_NARRATIVE_RULE_NAMES
        )
    if profile == CREDSWEEPER_RULES_PROFILE_FILESYSTEM_DOC:
        return "doc" in targets
    if profile == CREDSWEEPER_RULES_PROFILE_LDAP_DESCRIPTION:
        return "doc" in targets
    return True


def _transform_profiled_rule(rule: dict[str, Any], profile: str) -> dict[str, Any]:
    """Return one profile-adjusted CredSweeper rule payload.

    For broad filesystem text scans we keep a small subset of document-oriented
    rules, but CredSweeper only executes them when their target includes
    ``code`` in non-``--doc`` mode. We therefore widen those specific rules to
    ``['code', 'doc']`` in the generated profile.
    """

    if profile != CREDSWEEPER_RULES_PROFILE_FILESYSTEM_TEXT:
        return dict(rule)

    rule_name = str(rule.get("name", "")).strip()
    if rule_name not in FILESYSTEM_TEXT_NARRATIVE_RULE_NAMES:
        return dict(rule)

    targets = _normalize_credsweeper_targets(rule.get("target"))
    if "doc" not in targets:
        return dict(rule)

    transformed_rule = dict(rule)
    transformed_rule["target"] = ["code", "doc"]
    return transformed_rule


def _build_profiled_rules_variant(
    source_rules_path: str,
    *,
    profile: str,
) -> Optional[str]:
    """Return a generated CredSweeper rules profile derived from one source YAML."""

    try:
        source_path = Path(source_rules_path).resolve()
        source_text = source_path.read_text(encoding="utf-8")
        digest = sha256(f"{profile}:{source_text}".encode("utf-8")).hexdigest()[:12]
        output_dir = get_adscan_home() / "generated" / "credsweeper"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / f"{source_path.stem}_{profile}_{digest}.yaml"
        if output_path.is_file():
            return str(output_path)

        parsed_rules = yaml.safe_load(source_text)
        if not isinstance(parsed_rules, list):
            logger.warning(
                "CredSweeper rules file %s is not a YAML list; using original rules.",
                source_rules_path,
            )
            return source_rules_path

        filtered_rules: list[dict[str, Any]] = []
        excluded_rule_names: set[str] = set()
        for rule in parsed_rules:
            if not isinstance(rule, dict):
                continue
            rule_name = str(rule.get("name", "")).strip()
            if not _rule_targets_profile(rule, profile):
                excluded_rule_names.add(rule_name)
                continue
            if profile in {
                CREDSWEEPER_RULES_PROFILE_FILESYSTEM,
                CREDSWEEPER_RULES_PROFILE_FILESYSTEM_TEXT,
                CREDSWEEPER_RULES_PROFILE_FILESYSTEM_DOC,
            } and rule_name in FILESYSTEM_RULESET_EXCLUDED_RULE_NAMES:
                excluded_rule_names.add(rule_name)
                continue
            if (
                profile == CREDSWEEPER_RULES_PROFILE_LDAP_DESCRIPTION
                and rule_name not in LDAP_DESCRIPTION_RULESET_ALLOWED_RULE_NAMES
            ):
                excluded_rule_names.add(rule_name)
                continue
            filtered_rules.append(_transform_profiled_rule(rule, profile))
        output_path.write_text(
            yaml.safe_dump(
                filtered_rules,
                sort_keys=False,
                allow_unicode=True,
                width=120,
            ),
            encoding="utf-8",
        )
        print_info_debug(
            "[credsweeper] Generated rules profile: "
            f"source={source_rules_path} output={output_path} "
            f"profile={profile} excluded_rules={sorted(rule for rule in excluded_rule_names if rule)}"
        )
        return str(output_path)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        logger.exception(
            "Failed to build CredSweeper rules variant for profile %s from %s",
            profile,
            source_rules_path,
        )
        print_warning_debug(
            f"[credsweeper] Failed to build rules profile {profile} from {source_rules_path}: "
            f"{type(exc).__name__}"
        )
        return source_rules_path


def get_credsweeper_rules_paths(
    *,
    profile: str = CREDSWEEPER_RULES_PROFILE_DEFAULT,
) -> Tuple[Optional[str], Optional[str]]:
    """Return both primary and custom CredSweeper rules file paths.

    Returns:
        Tuple of ``(primary_rules_path, custom_rules_path)``. Paths may be ``None``
        when the corresponding rules file is not available.
    """

    primary_rules = _get_credsweeper_config_path()
    custom_rules = _get_credsweeper_custom_rules_path()
    installed_version = _get_installed_credsweeper_version()
    vendored_version = _get_vendored_credsweeper_version()
    if profile in {
        CREDSWEEPER_RULES_PROFILE_FILESYSTEM,
        CREDSWEEPER_RULES_PROFILE_FILESYSTEM_TEXT,
        CREDSWEEPER_RULES_PROFILE_FILESYSTEM_DOC,
        CREDSWEEPER_RULES_PROFILE_LDAP_DESCRIPTION,
    }:
        base_rules = _get_upstream_credsweeper_config_path() or primary_rules
        if base_rules:
            primary_rules = _build_profiled_rules_variant(base_rules, profile=profile)
            print_info_debug(
                "[credsweeper] Rules profile source selected: "
                f"profile={profile} source=vendored_upstream "
                f"base_rules={base_rules} generated_rules={primary_rules} "
                f"installed_version={installed_version or 'unknown'} "
                f"vendored_version={vendored_version or 'unknown'}"
            )
    else:
        print_info_debug(
            "[credsweeper] Rules profile source selected: "
            f"profile={profile} source=runtime_default "
            f"primary_rules={primary_rules or 'missing'} "
            f"custom_rules={custom_rules or 'missing'} "
            f"installed_version={installed_version or 'unknown'} "
            f"vendored_version={vendored_version or 'unknown'}"
        )
    return primary_rules, custom_rules


def get_default_credsweeper_jobs(max_jobs: int = 8) -> int:
    """Return a conservative default process count for CredSweeper."""
    cpu_count = os.cpu_count() or 1
    return max(1, min(int(max_jobs), int(cpu_count)))


@dataclass
class CredSweeperFinding:
    """Single credential-like finding reported by CredSweeper.

    Attributes:
        rule_name: CredSweeper rule name (e.g. ``Password``, ``DOC_CREDENTIALS``)
        value: Extracted credential value
        ml_probability: Optional ML confidence score
        context_line: Source line where the value was found
        line_num: 1-based line number in the source file
        file_path: Path to the file where the value was found
    """

    rule_name: str
    value: str
    ml_probability: Optional[float]
    context_line: str
    line_num: int
    file_path: str


class CredSweeperService(BaseService):
    """Service wrapper around the installed CredSweeper Python library.

    ``credsweeper_path`` parameters remain on public methods for backward
    compatibility with older callers. They are no longer used for execution;
    availability is determined by importing the ``credsweeper`` package.
    """

    def __init__(
        self,
        command_executor: CommandExecutor,
    ) -> None:
        """Initialize service.

        Args:
            command_executor: Callable used to execute shell commands. In the
                CLI this should typically be ``PentestShell.run_command``.
        """
        super().__init__()
        self._command_executor = command_executor

    @staticmethod
    def is_library_available() -> bool:
        """Return whether CredSweeper can be imported in the active interpreter."""
        try:
            CredSweeperService._load_credsweeper_library()
        except Exception:  # noqa: BLE001
            return False
        return True

    @staticmethod
    def _get_vendored_credsweeper_root() -> Path:
        """Return the local CredSweeper reference tree used only as dev fallback."""
        project_root = Path(__file__).resolve().parents[2]
        return project_root / "external_tools" / "CredSweeper"

    @staticmethod
    def _load_credsweeper_library() -> tuple[Any, Any]:
        """Load CredSweeper classes from the package installed from PyPI."""
        from credsweeper import CredSweeper  # type: ignore  # pylint: disable=import-error
        from credsweeper.file_handler.files_provider import FilesProvider  # type: ignore  # pylint: disable=import-error

        return CredSweeper, FilesProvider

    # Public API ---------------------------------------------------------------

    @staticmethod
    def _count_total_grouped_findings(
        findings: Dict[str, List[Tuple[str, Optional[float], str, int, str]]]
    ) -> int:
        """Count total grouped findings across all CredSweeper rule buckets."""
        return sum(len(items) for items in findings.values())

    @staticmethod
    def _resolve_json_output_path(
        *,
        file_path: str,
        output_basename: str,
        json_output_dir: Optional[str],
    ) -> str:
        """Resolve CredSweeper JSON output path.

        By default the JSON is written next to the analyzed file to preserve the
        legacy manspider workflow. When ``json_output_dir`` is provided, the JSON
        is instead written under that directory, which is required for read-only
        mounts such as CIFS.
        """
        if not json_output_dir:
            base_path, _ = os.path.splitext(file_path)
            return f"{base_path}{output_basename}.json"

        output_dir = os.path.abspath(str(json_output_dir))
        os.makedirs(output_dir, exist_ok=True)
        file_name = Path(file_path).name or "credsweeper_input"
        stem = Path(file_name).stem or "credsweeper_input"
        safe_stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", stem).strip("._") or "input"
        normalized_basename = output_basename.strip("_") or "result"
        return os.path.join(output_dir, f"{safe_stem}_{normalized_basename}.json")

    @staticmethod
    def _merge_grouped_findings(
        left: Dict[str, List[Tuple[str, Optional[float], str, int, str]]],
        right: Dict[str, List[Tuple[str, Optional[float], str, int, str]]],
    ) -> Dict[str, List[Tuple[str, Optional[float], str, int, str]]]:
        """Merge grouped findings while deduplicating exact tuples."""
        merged: Dict[str, List[Tuple[str, Optional[float], str, int, str]]] = {
            key: list(values) for key, values in left.items()
        }
        for rule_name, entries in right.items():
            existing = set(merged.get(rule_name, []))
            for entry in entries:
                if entry in existing:
                    continue
                merged.setdefault(rule_name, []).append(entry)
                existing.add(entry)
        return merged

    @staticmethod
    def _remap_grouped_finding_paths(
        findings: Dict[str, List[Tuple[str, Optional[float], str, int, str]]],
        path_aliases: dict[str, str],
    ) -> Dict[str, List[Tuple[str, Optional[float], str, int, str]]]:
        """Replace temporary analysis paths with original evidence paths."""
        if not path_aliases:
            return findings

        remapped: Dict[str, List[Tuple[str, Optional[float], str, int, str]]] = {}
        for rule_name, entries in findings.items():
            remapped_entries: List[Tuple[str, Optional[float], str, int, str]] = []
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
    def _normalize_candidates(
        candidates: list[Any],
        *,
        drop_ml_none: bool,
    ) -> Dict[str, List[Tuple[str, Optional[float], str, int, str]]]:
        """Normalize CredSweeper Candidate objects into grouped ADscan findings."""
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

    def _run_library_ruleset(
        self,
        *,
        path_to_scan: str,
        rules_path: str,
        drop_ml_none: bool,
        ml_threshold: str,
        doc: bool,
        depth: bool,
        no_filters: bool,
        find_by_ext: bool,
        jobs: int | None,
    ) -> Dict[str, List[Tuple[str, Optional[float], str, int, str]]]:
        """Run one CredSweeper ruleset against a filesystem path via library API."""
        CredSweeper, FilesProvider = self._load_credsweeper_library()
        analyzer = CredSweeper(
            rule_path=rules_path,
            stdout=False,
            use_filters=not no_filters,
            pool_count=max(1, int(jobs or 1)),
            ml_threshold=float(ml_threshold),
            find_by_ext=find_by_ext,
            depth=1 if depth else 0,
            doc=doc,
            thrifty=False,
        )
        analyzer.run(FilesProvider([path_to_scan]))
        return self._normalize_candidates(
            list(analyzer.credential_manager.get_credentials()),
            drop_ml_none=drop_ml_none,
        )

    def _run_library_path_scan(
        self,
        *,
        path_to_scan: str,
        rules_path: Optional[str],
        include_custom_rules: bool,
        rules_profile: str,
        drop_ml_none: bool | None,
        ml_threshold: str,
        custom_ml_threshold: str | None = None,
        doc: bool = False,
        depth: bool = False,
        no_filters: bool = False,
        find_by_ext: bool = False,
        jobs: int | None = None,
    ) -> Dict[str, List[Tuple[str, Optional[float], str, int, str]]]:
        """Run all selected CredSweeper rulesets against a filesystem path."""
        primary_rules, custom_rules = get_credsweeper_rules_paths(profile=rules_profile)
        selected_primary = rules_path or primary_rules
        rulesets: list[tuple[str, str, str]] = []
        if selected_primary:
            rulesets.append(("primary", selected_primary, str(ml_threshold)))
        if include_custom_rules and custom_rules:
            rulesets.append(("custom", custom_rules, str(custom_ml_threshold or "0.0")))

        if not rulesets:
            print_info_verbose("No CredSweeper rules available. Skipping CredSweeper analysis.")
            return {}

        findings: Dict[str, List[Tuple[str, Optional[float], str, int, str]]] = {}
        for label, selected_rules, effective_ml_threshold in rulesets:
            started_at = time.perf_counter()
            try:
                ruleset_findings = self._run_library_ruleset(
                    path_to_scan=path_to_scan,
                    rules_path=selected_rules,
                    drop_ml_none=resolve_credsweeper_drop_ml_none_for_ruleset(
                        ruleset_label=label,
                        drop_ml_none=drop_ml_none,
                    ),
                    ml_threshold=effective_ml_threshold,
                    doc=doc,
                    depth=depth,
                    no_filters=no_filters,
                    find_by_ext=find_by_ext,
                    jobs=jobs,
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                print_warning(f"Credential analysis failed for path ({label} rules).")
                print_warning_debug(
                    f"[credsweeper] Library analysis failed ({label}): {type(exc).__name__}: {exc}"
                )
                logger.exception("CredSweeper library analysis failed")
                continue
            findings = self._merge_grouped_findings(findings, ruleset_findings)
            print_info_debug(
                "[credsweeper] Ruleset completed: "
                f"label={label} path={path_to_scan} duration_seconds={time.perf_counter() - started_at:.2f} "
                f"accumulated_results={self._count_total_grouped_findings(findings)}"
            )
        return findings

    @staticmethod
    def _needs_xml_sanitized_analysis(file_path: str) -> bool:
        """Return whether one file path should be sanitized before analysis."""
        effective_extension = resolve_effective_sensitive_extension(
            Path(file_path).name,
            allowed_extensions={".xml"},
        )
        if effective_extension != ".xml":
            return False
        try:
            text = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return False
        return contains_unescaped_xml_ampersand(text)

    def _analyze_sanitized_xml_overlay(
        self,
        *,
        root_path: str,
        credsweeper_path: str,
        json_output_dir: Optional[str],
        rules_path: Optional[str],
        include_custom_rules: bool,
        rules_profile: str,
        drop_ml_none: bool | None,
        ml_threshold: str,
        no_filters: bool,
        jobs: int | None,
        custom_ml_threshold: str | None,
        timeout: int,
    ) -> Dict[str, List[Tuple[str, Optional[float], str, int, str]]]:
        """Run a supplementary pass on malformed XML files using sanitized copies."""
        root = Path(root_path)
        if not root.is_dir():
            return {}

        candidate_paths = discover_malformed_xml_candidates(root)
        if not candidate_paths:
            return {}

        preview = ", ".join(str(path) for path in candidate_paths[:3])
        remaining = len(candidate_paths) - min(len(candidate_paths), 3)
        if remaining > 0:
            preview = f"{preview}, +{remaining} more"
        print_info_debug(
            "[credsweeper] XML sanitization supplementary pass selected: "
            f"root={root_path} candidate_files={len(candidate_paths)} "
            f"preview=\\[{rich_escape(preview)}]"
        )
        overlay = build_sanitized_xml_overlay(
            candidate_paths=candidate_paths,
            temp_parent=root,
        )
        if overlay is None:
            return {}

        overlay_root, path_aliases = overlay
        try:
            supplemental_findings = self.analyze_path_with_options(
                str(overlay_root),
                credsweeper_path=credsweeper_path,
                json_output_dir=json_output_dir,
                rules_path=rules_path,
                include_custom_rules=include_custom_rules,
                rules_profile=rules_profile,
                drop_ml_none=drop_ml_none,
                ml_threshold=ml_threshold,
                doc=False,
                no_filters=no_filters,
                find_by_ext=False,
                jobs=jobs,
                custom_ml_threshold=custom_ml_threshold,
                depth=False,
                timeout=timeout,
                _enable_xml_sanitization_pass=False,
            )
            remapped_findings = self._remap_grouped_finding_paths(
                supplemental_findings,
                path_aliases,
            )
            print_info_debug(
                "[credsweeper] XML sanitization supplementary pass completed: "
                f"root={root_path} candidate_files={len(candidate_paths)} "
                f"grouped_rules={len(remapped_findings)} "
                f"total_findings={self._count_total_grouped_findings(remapped_findings)}"
            )
            return remapped_findings
        finally:
            shutil.rmtree(overlay_root, ignore_errors=True)

    def analyze_file(
        self,
        file_path: str,
        *,
        credsweeper_path: Optional[str],
        json_output_dir: Optional[str] = None,
        timeout: int = 300,
    ) -> Dict[str, List[Tuple[str, Optional[float], str, int, str]]]:
        """Analyze a text file with CredSweeper and return structured findings.

        The return format matches the historical contract used by ``adscan.py``:

        .. code-block:: python

            {
                "Password": [
                    (value, ml_probability, context_line, line_num, file_path),
                    ...
                ],
                "API Key": [...],
                ...
            }

        Args:
            file_path: Path to the file to analyze.
            credsweeper_path: Path to the ``credsweeper`` executable. If ``None``,
                the analysis is skipped and an empty dict is returned.
            json_output_dir: Optional writable directory where CredSweeper should
                store temporary JSON output. When omitted, defaults to the source
                file directory for legacy compatibility.
            timeout: Optional timeout in seconds for each CredSweeper invocation.

        Returns:
            Dictionary of findings grouped by rule name.
        """

        _ = credsweeper_path
        return self.analyze_file_with_options(
            file_path,
            credsweeper_path=None,
            json_output_dir=json_output_dir,
            include_custom_rules=True,
            timeout=timeout,
        )

    def analyze_file_with_options(
        self,
        file_path: str,
        *,
        credsweeper_path: Optional[str],
        json_output_dir: Optional[str] = None,
        rules_path: Optional[str] = None,
        include_custom_rules: bool = False,
        rules_profile: str = CREDSWEEPER_RULES_PROFILE_DEFAULT,
        drop_ml_none: bool | None = None,
        ml_threshold: str = "0.1",
        doc: bool = False,
        depth: bool = False,
        no_filters: bool = False,
        timeout: int = 300,
    ) -> Dict[str, List[Tuple[str, Optional[float], str, int, str]]]:
        """Analyze a file with CredSweeper using explicit options.

        This is the recommended API when a caller needs full control over:
        - Which rules file is used (e.g. primary only)
        - Whether to run in document mode (``--doc``)
        - ML threshold behaviour (including ``0.0`` to avoid filtering)
        - Filter toggling (``--no-filters``)

        Args:
            file_path: Path to the file to analyze.
            credsweeper_path: Path to the CredSweeper executable.
            json_output_dir: Optional writable directory where CredSweeper should
                store temporary JSON output. When omitted, defaults to the source
                file directory for legacy compatibility.
            rules_path: Optional explicit rules file. When omitted, uses the
                primary rules from :func:`get_credsweeper_rules_paths`.
            include_custom_rules: When True, runs the custom ruleset in addition
                to the primary rules and merges results.
            rules_profile: Optional primary rules profile. Broad filesystem
                contexts should use ``filesystem_text`` or ``filesystem_doc``;
                targeted scans should keep the default profile.
            drop_ml_none: Optional override for findings where ``ml_probability``
                is missing. ``None`` applies the default service policy: drop
                them for primary rules and keep them for custom rules.
            ml_threshold: CredSweeper ML threshold value (string or float-like).
            doc: When True, run CredSweeper in document mode (``--doc``).
            depth: When True, enable CredSweeper's experimental recursive
                deep parsing mode (``--depth``).
            no_filters: When True, disable CredSweeper filters (``--no-filters``).
            timeout: Timeout in seconds for the command execution.

        Returns:
            Findings grouped by rule name.
        """
        findings: Dict[str, List[Tuple[str, Optional[float], str, int, str]]] = {}
        _ = (credsweeper_path, json_output_dir, timeout)
        if not os.path.exists(file_path):
            print_warning(f"File not found for CredSweeper analysis: {file_path}")
            return findings

        analysis_target = str(file_path)
        path_aliases: dict[str, str] = {}
        cleanup_dir: str | None = None
        if self._needs_xml_sanitized_analysis(str(file_path)):
            try:
                temp_root = create_analysis_temp_root(
                    prefix=".adscan_xml_file_",
                    preferred_parent=Path(file_path).resolve().parent,
                )
                cleanup_dir = str(temp_root)
                text = Path(file_path).read_text(encoding="utf-8", errors="replace")
                sanitized_path = build_sanitized_xml_analysis_copy(
                    source_path=str(file_path),
                    text=text,
                    temp_root=temp_root,
                )
                analysis_target = str(sanitized_path)
                path_aliases[str(sanitized_path)] = str(file_path)
                print_info_debug(
                    "[credsweeper] Using sanitized XML analysis copy: "
                    f"source={file_path} analysis_target={analysis_target}"
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                print_warning_debug(
                    f"[credsweeper] Failed to prepare sanitized XML copy for {file_path}: {type(exc).__name__}"
                )

        analysis_started_at = time.perf_counter()
        findings = self._run_library_path_scan(
            path_to_scan=analysis_target,
            rules_path=rules_path,
            include_custom_rules=include_custom_rules,
            rules_profile=rules_profile,
            drop_ml_none=drop_ml_none,
            ml_threshold=str(ml_threshold),
            doc=doc,
            depth=depth,
            no_filters=no_filters,
        )
        findings = self._remap_grouped_finding_paths(findings, path_aliases)

        try:
            print_info_debug(
                "[credsweeper] Analysis summary: "
                f"target={file_path} duration_seconds={time.perf_counter() - analysis_started_at:.2f} "
                f"grouped_rules={len(findings)} total_findings={self._count_total_grouped_findings(findings)}"
            )
            return findings
        finally:
            if cleanup_dir:
                shutil.rmtree(cleanup_dir, ignore_errors=True)

    def analyze_path_with_options(
        self,
        path_to_scan: str,
        *,
        credsweeper_path: Optional[str],
        json_output_dir: Optional[str] = None,
        rules_path: Optional[str] = None,
        include_custom_rules: bool = False,
        rules_profile: str = CREDSWEEPER_RULES_PROFILE_DEFAULT,
        drop_ml_none: bool | None = None,
        ml_threshold: str = "0.1",
        doc: bool = False,
        no_filters: bool = False,
        find_by_ext: bool = False,
        jobs: int | None = None,
        custom_ml_threshold: str | None = None,
        depth: bool = False,
        timeout: int = 300,
        _enable_xml_sanitization_pass: bool = True,
    ) -> Dict[str, List[Tuple[str, Optional[float], str, int, str]]]:
        """Analyze a file or directory path with CredSweeper using explicit options.

        Args:
            path_to_scan: File or directory path to analyze.
            credsweeper_path: Path to the CredSweeper executable.
            json_output_dir: Optional writable directory where CredSweeper should
                store temporary JSON output. When omitted, defaults to the source
                path directory for legacy compatibility.
            rules_path: Optional explicit rules file. When omitted, uses the
                primary rules from :func:`get_credsweeper_rules_paths`.
            include_custom_rules: When True, runs the custom ruleset in addition
                to the primary rules and merges results.
            rules_profile: Optional primary rules profile. Broad filesystem
                contexts should use ``filesystem_text`` or ``filesystem_doc``;
                targeted scans should keep the default profile.
            drop_ml_none: Optional override for findings where ``ml_probability``
                is missing. ``None`` applies the default service policy: drop
                them for primary rules and keep them for custom rules.
            ml_threshold: CredSweeper ML threshold value (string or float-like).
            doc: When True, run CredSweeper in document mode (``--doc``).
            no_filters: When True, disable CredSweeper filters (``--no-filters``).
            find_by_ext: When True, enable CredSweeper's native extension-based
                candidate discovery (``--find-by-ext``).
            jobs: Optional number of worker processes for CredSweeper ``--jobs``.
            depth: When True, enable CredSweeper's experimental recursive
                deep parsing mode (``--depth``) for documents/containers.
            timeout: Timeout in seconds for the command execution.

        Returns:
            Findings grouped by rule name.
        """
        findings: Dict[str, List[Tuple[str, Optional[float], str, int, str]]] = {}
        _ = (credsweeper_path, json_output_dir, timeout)
        if not os.path.exists(path_to_scan):
            print_warning(
                f"File or directory not found for CredSweeper analysis: {path_to_scan}"
            )
            return findings
        analysis_started_at = time.perf_counter()
        target_is_directory = os.path.isdir(path_to_scan)
        if target_is_directory:
            print_info_verbose(f"Analyzing path for credentials with CredSweeper: {path_to_scan}")
            print_info_debug(
                "[credsweeper] Library execution budget: "
                f"doc={doc} depth={depth} timeout_seconds={int(timeout)}"
            )
        # The library scan is a single OPAQUE call — no per-file signal — so a
        # directory scan shows an honest indeterminate spinner (spinner +
        # "Scanning N files for secrets…" + elapsed, no fabricated ETA) while it
        # runs. DISPLAY-ONLY and fail-open: on any dashboard failure the scan
        # runs plainly and returns identical findings.
        from adscan_internal.services.loot_progress import (
            count_files_under,
            indeterminate_scan_spinner,
        )

        spinner_ctx = (
            indeterminate_scan_spinner(
                "SMB Share Exposure · Secret Scan",
                label=f"Scanning {count_files_under(path_to_scan)} files for secrets…",
            )
            if target_is_directory
            else nullcontext()
        )
        with spinner_ctx:
            findings = self._run_library_path_scan(
                path_to_scan=path_to_scan,
                rules_path=rules_path,
                include_custom_rules=include_custom_rules,
                rules_profile=rules_profile,
                drop_ml_none=drop_ml_none,
                ml_threshold=str(ml_threshold),
                custom_ml_threshold=custom_ml_threshold,
                doc=doc,
                depth=depth,
                no_filters=no_filters,
                find_by_ext=find_by_ext,
                jobs=jobs,
            )

        if _enable_xml_sanitization_pass and os.path.isdir(path_to_scan) and not doc:
            supplemental_findings = self._analyze_sanitized_xml_overlay(
                root_path=path_to_scan,
                credsweeper_path=credsweeper_path,
                json_output_dir=json_output_dir,
                rules_path=rules_path,
                include_custom_rules=include_custom_rules,
                rules_profile=rules_profile,
                drop_ml_none=drop_ml_none,
                ml_threshold=ml_threshold,
                no_filters=no_filters,
                jobs=jobs,
                custom_ml_threshold=custom_ml_threshold,
                timeout=timeout,
            )
            findings = self._merge_grouped_findings(findings, supplemental_findings)

        if not findings:
            if target_is_directory:
                print_info_verbose("No credentials detected by CredSweeper.")
            return findings

        if target_is_directory:
            print_info_debug(
                "[credsweeper] Analysis summary: "
                f"target={path_to_scan} duration_seconds={time.perf_counter() - analysis_started_at:.2f} "
                f"grouped_rules={len(findings)} total_findings={self._count_total_grouped_findings(findings)}"
            )
        return findings


__all__ = [
    "CREDSWEEPER_RULES_PROFILE_DEFAULT",
    "CREDSWEEPER_RULES_PROFILE_FILESYSTEM",
    "CREDSWEEPER_RULES_PROFILE_FILESYSTEM_TEXT",
    "CREDSWEEPER_RULES_PROFILE_FILESYSTEM_DOC",
    "CREDSWEEPER_RULES_PROFILE_LDAP_DESCRIPTION",
    "CredSweeperService",
    "CredSweeperFinding",
    "get_default_credsweeper_jobs",
    "get_default_credsweeper_timeout",
    "get_credsweeper_rules_paths",
]
