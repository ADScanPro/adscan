"""CredSweeper service for credential discovery in textual files and logs.

This module centralizes:

- Resolution of CredSweeper rules files (``config.yaml`` and ``custom_config.yaml``)
- Execution of the external ``credsweeper`` CLI with proper environment handling
- Parsing and normalization of JSON output into a Python-friendly structure

The goal is to decouple CredSweeper-specific logic from the monolithic
``adscan.py`` file and make it easier to test and reuse from different
workflows (manspider spidering logs, PowerShell history, transcripts, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
import json
import logging
import os
import shlex
import subprocess
import sys

from adscan_internal.services.base_service import BaseService
from adscan_internal.path_utils import get_adscan_home
from adscan_internal.text_utils import strip_ansi_codes
from adscan_internal import (
    print_info_verbose,
    print_info_debug,
    print_warning,
    print_warning_debug,
)
from adscan_internal import telemetry


logger = logging.getLogger(__name__)


CommandExecutor = Callable[..., subprocess.CompletedProcess[str] | None]


def _get_credsweeper_config_path() -> Optional[str]:
    """Return path to the primary CredSweeper rules file (``config.yaml``), if any.

    Priority:
    1. User override in ``$ADSCAN_HOME/credsweeper_config.yaml``
    2. Bundled config inside PyInstaller (``_MEIPASS/config.yaml``)
    3. Project root ``config.yaml`` (development mode)
    """

    # 1) User override in ADscan base directory
    override_path = get_adscan_home() / "credsweeper_config.yaml"
    if override_path.is_file():
        return str(override_path)

    # 2) PyInstaller bundle: config.yaml is bundled via --add-data
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

    # 3) Development mode: config.yaml in project root
    # This service lives under adscan_internal/services/, so project root is two levels up.
    project_root = Path(__file__).resolve().parents[2]
    root_config = project_root / "config.yaml"
    if root_config.is_file():
        return str(root_config)

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


def get_credsweeper_rules_paths() -> Tuple[Optional[str], Optional[str]]:
    """Return both primary and custom CredSweeper rules file paths.

    Returns:
        Tuple of ``(primary_rules_path, custom_rules_path)``. Paths may be ``None``
        when the corresponding rules file is not available.
    """

    primary_rules = _get_credsweeper_config_path()
    custom_rules = _get_credsweeper_custom_rules_path()
    return primary_rules, custom_rules


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
    """Service wrapper around the CredSweeper CLI.

    This service is intentionally CLI-oriented and uses a pluggable command
    executor so that it can run through ADscan's ``run_command`` helper in
    production and a stub executor in tests.
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

    # Public API ---------------------------------------------------------------

    def analyze_file(
        self,
        file_path: str,
        *,
        credsweeper_path: Optional[str],
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
            timeout: Optional timeout in seconds for each CredSweeper invocation.

        Returns:
            Dictionary of findings grouped by rule name.
        """

        findings: Dict[str, List[Tuple[str, Optional[float], str, int, str]]] = {}

        if not credsweeper_path:
            print_info_verbose(
                "Credential extraction tool not available. Skipping CredSweeper analysis."
            )
            return findings

        if not os.path.exists(file_path):
            print_warning(f"File not found for CredSweeper analysis: {file_path}")
            return findings

        try:
            # Run CredSweeper twice with two rulesets:
            # - Primary rules (config.yaml): drop entries with ml_probability=None
            # - Custom rules (custom_config.yaml): keep entries even if ml_probability=None
            all_results: List[Dict[str, Any]] = []

            primary_rules, custom_rules = get_credsweeper_rules_paths()
            if primary_rules:
                print_info_debug(
                    f"[credsweeper] Using primary rules for file: {primary_rules}"
                )
            else:
                print_info_debug(
                    "[credsweeper] No primary rules (config.yaml) found for file."
                )

            if custom_rules:
                print_info_debug(
                    f"[credsweeper] Using custom rules for file: {custom_rules}"
                )
            else:
                print_info_debug(
                    "[credsweeper] No custom rules (custom_config.yaml) found for file."
                )

            base_path, _ = os.path.splitext(file_path)

            def _run_ruleset(
                rules_path: Optional[str],
                json_suffix: str,
                label: str,
                drop_ml_none: bool,
                ml_threshold: str,
            ) -> None:
                if not rules_path:
                    return

                json_output = f"{base_path}{json_suffix}.json"
                cmd_parts = [
                    shlex.quote(credsweeper_path),
                    "--path",
                    shlex.quote(file_path),
                    "--save-json",
                    shlex.quote(json_output),
                    "--ml_threshold",
                    ml_threshold,
                    "--rules",
                    shlex.quote(rules_path),
                ]
                command = " ".join(cmd_parts)

                print_info_verbose(
                    f"Analyzing file for credentials with CredSweeper ({label} rules)..."
                )
                print_info_debug(f"[credsweeper] Command ({label}): {command}")

                completed_process = self._command_executor(
                    command, timeout=timeout, use_clean_env=True
                )

                if not completed_process or completed_process.returncode != 0:
                    stdout_text = strip_ansi_codes(
                        (completed_process.stdout or "").strip()
                        if completed_process
                        else ""
                    )
                    stderr_text = strip_ansi_codes(
                        (completed_process.stderr or "").strip()
                        if completed_process
                        else ""
                    )
                    print_warning(
                        f"Credential analysis failed for file ({label} rules)."
                    )
                    print_warning_debug(
                        f"[credsweeper] Analysis failed ({label}). "
                        f"Return code: {getattr(completed_process, 'returncode', 'N/A')}\n"
                        f"Stdout: {stdout_text or 'No stdout'}\n"
                        f"Stderr: {stderr_text or 'No stderr'}"
                    )
                    return

                if not os.path.exists(json_output):
                    print_info_verbose(
                        f"[credsweeper] No JSON output generated for file ({label} rules)."
                    )
                    return

                try:
                    with open(json_output, "r", encoding="utf-8") as f:
                        results = json.load(f)
                except (json.JSONDecodeError, Exception) as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
                    print_warning(
                        f"Error parsing CredSweeper JSON ({label} rules): {exc}"
                    )
                    return
                finally:
                    try:
                        os.remove(json_output)
                    except Exception:  # noqa: BLE001
                        # Best-effort cleanup; safe to ignore failures here
                        pass

                if not isinstance(results, list):
                    print_warning_debug(
                        f"[credsweeper] Unexpected JSON structure for file ({label} rules)."
                    )
                    return

                for result in results:
                    ml_probability = result.get("ml_probability")
                    if drop_ml_none and ml_probability is None:
                        continue
                    all_results.append(result)

            # Primary rules: drop ml_probability=None
            _run_ruleset(
                primary_rules,
                json_suffix="_config",
                label="primary",
                drop_ml_none=True,
                ml_threshold="0.1",
            )

            # Custom rules: keep ml_probability=None
            _run_ruleset(
                custom_rules,
                json_suffix="_custom",
                label="custom",
                drop_ml_none=False,
                ml_threshold="0.0",
            )

            if not all_results:
                print_info_verbose("No credentials detected by CredSweeper.")
                return findings

            # Extract all credential types from CredSweeper results
            # Use a set to track seen credentials for deduplication
            seen_credentials: set[Tuple[str, str, int]] = set()

            for result in all_results:
                rule_name = result.get("rule", "") or ""
                ml_probability = result.get("ml_probability")

                # Ensure ml_probability is either float or None
                try:
                    if ml_probability is not None:
                        ml_probability = float(ml_probability)
                except (ValueError, TypeError):
                    ml_probability = None

                line_data_list = result.get("line_data_list", []) or []

                # Initialize category if not exists
                if rule_name not in findings:
                    findings[rule_name] = []

                for line_data in line_data_list:
                    value = line_data.get("value", "")
                    context_line = line_data.get("line", "") or ""
                    line_num = line_data.get("line_num", 0)

                    # Normalize line number
                    if line_num is None:
                        line_num = 0
                    try:
                        line_num = int(line_num)
                    except (ValueError, TypeError):
                        line_num = 0

                    file_path_entry = line_data.get("path", file_path)
                    if file_path_entry is None:
                        file_path_entry = file_path
                    if not isinstance(file_path_entry, str):
                        file_path_entry = str(file_path_entry) or file_path

                    # Ensure value is a string and not None
                    if value is None:
                        value = ""
                    if not isinstance(value, str):
                        value = str(value) if value else ""

                    if value and len(value) >= 3:
                        # Create a unique key for deduplication: (rule_name, value, line_num)
                        dedup_key = (rule_name, value, line_num)

                        if dedup_key not in seen_credentials:
                            seen_credentials.add(dedup_key)
                            findings[rule_name].append(
                                (
                                    value,
                                    ml_probability,
                                    context_line,
                                    line_num,
                                    file_path_entry,
                                )
                            )

        except json.JSONDecodeError as exc:
            telemetry.capture_exception(exc)
            print_warning(f"Error parsing CredSweeper JSON output: {exc}")
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning("Error analyzing file for credentials with CredSweeper.")
            logger.exception("Error in CredSweeperService.analyze_file: %s", exc)

        return findings

    def analyze_file_with_options(
        self,
        file_path: str,
        *,
        credsweeper_path: Optional[str],
        rules_path: Optional[str] = None,
        include_custom_rules: bool = False,
        drop_ml_none: bool = False,
        ml_threshold: str = "0.1",
        doc: bool = False,
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
            rules_path: Optional explicit rules file. When omitted, uses the
                primary rules from :func:`get_credsweeper_rules_paths`.
            include_custom_rules: When True, runs the custom ruleset in addition
                to the primary rules and merges results.
            drop_ml_none: When True, drops results where ``ml_probability`` is missing.
            ml_threshold: CredSweeper ML threshold value (string or float-like).
            doc: When True, run CredSweeper in document mode (``--doc``).
            no_filters: When True, disable CredSweeper filters (``--no-filters``).
            timeout: Timeout in seconds for the command execution.

        Returns:
            Findings grouped by rule name.
        """
        findings: Dict[str, List[Tuple[str, Optional[float], str, int, str]]] = {}
        if not credsweeper_path:
            print_info_verbose(
                "Credential extraction tool not available. Skipping CredSweeper analysis."
            )
            return findings
        if not os.path.exists(file_path):
            print_warning(f"File not found for CredSweeper analysis: {file_path}")
            return findings

        primary_rules, custom_rules = get_credsweeper_rules_paths()
        selected_primary = rules_path or primary_rules
        rulesets: list[tuple[str, str]] = []
        if selected_primary:
            rulesets.append(("primary", selected_primary))
        if include_custom_rules and custom_rules:
            rulesets.append(("custom", custom_rules))

        if not rulesets:
            print_info_verbose(
                "No CredSweeper rules available. Skipping CredSweeper analysis."
            )
            return findings

        base_path, _ = os.path.splitext(file_path)
        all_results: List[Dict[str, Any]] = []

        for label, rules in rulesets:
            json_output = f"{base_path}_{label}.json"
            cmd_parts = [
                shlex.quote(credsweeper_path),
                "--path",
                shlex.quote(file_path),
                "--save-json",
                shlex.quote(json_output),
                "--ml_threshold",
                str(ml_threshold),
                "--rules",
                shlex.quote(rules),
            ]
            if doc:
                cmd_parts.append("--doc")
            if no_filters:
                cmd_parts.append("--no-filters")
            command = " ".join(cmd_parts)

            print_info_verbose(
                f"Analyzing file for credentials with CredSweeper ({label} rules)..."
            )
            print_info_debug(f"[credsweeper] Command ({label}): {command}")

            completed_process = self._command_executor(
                command, timeout=timeout, use_clean_env=True
            )

            if not completed_process or completed_process.returncode != 0:
                stdout_text = strip_ansi_codes(
                    (completed_process.stdout or "").strip()
                    if completed_process
                    else ""
                )
                stderr_text = strip_ansi_codes(
                    (completed_process.stderr or "").strip()
                    if completed_process
                    else ""
                )
                print_warning(f"Credential analysis failed for file ({label} rules).")
                print_warning_debug(
                    f"[credsweeper] Analysis failed ({label}). "
                    f"Return code: {getattr(completed_process, 'returncode', 'N/A')}\n"
                    f"Stdout: {stdout_text or 'No stdout'}\n"
                    f"Stderr: {stderr_text or 'No stderr'}"
                )
                continue

            if not os.path.exists(json_output):
                print_info_verbose(
                    f"[credsweeper] No JSON output generated for file ({label} rules)."
                )
                continue

            try:
                with open(json_output, "r", encoding="utf-8") as handle:
                    results = json.load(handle)
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_warning(f"Error parsing CredSweeper JSON ({label} rules): {exc}")
                continue
            finally:
                try:
                    os.remove(json_output)
                except Exception:  # noqa: BLE001
                    pass

            if not isinstance(results, list):
                print_warning_debug(
                    f"[credsweeper] Unexpected JSON structure for file ({label} rules)."
                )
                continue

            for result in results:
                ml_probability = result.get("ml_probability")
                if drop_ml_none and ml_probability is None:
                    continue
                all_results.append(result)

        if not all_results:
            print_info_verbose("No credentials detected by CredSweeper.")
            return findings

        seen_credentials: set[Tuple[str, str, int]] = set()
        for result in all_results:
            rule_name = result.get("rule", "") or ""
            ml_probability = result.get("ml_probability")
            try:
                if ml_probability is not None:
                    ml_probability = float(ml_probability)
            except (ValueError, TypeError):
                ml_probability = None

            line_data_list = result.get("line_data_list", []) or []
            findings.setdefault(rule_name, [])

            for line_data in line_data_list:
                value = line_data.get("value", "")
                context_line = line_data.get("line", "") or ""
                line_num = line_data.get("line_num", 0)
                try:
                    line_num = int(line_num or 0)
                except (ValueError, TypeError):
                    line_num = 0

                file_path_entry = line_data.get("path", file_path) or file_path
                if not isinstance(file_path_entry, str):
                    file_path_entry = str(file_path_entry) or file_path

                if value is None:
                    value = ""
                if not isinstance(value, str):
                    value = str(value) if value else ""

                if not value or len(value) < 3:
                    continue

                dedup_key = (rule_name, value, line_num)
                if dedup_key in seen_credentials:
                    continue
                seen_credentials.add(dedup_key)
                findings[rule_name].append(
                    (value, ml_probability, context_line, line_num, file_path_entry)
                )

        return findings


__all__ = [
    "CredSweeperService",
    "CredSweeperFinding",
    "get_credsweeper_rules_paths",
]

