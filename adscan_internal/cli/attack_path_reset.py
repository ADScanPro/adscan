"""Helpers for resetting persisted attack-path execution state in a workspace."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from adscan_core.path_utils import get_adscan_home
from adscan_internal import telemetry
from adscan_internal.cli.attack_path_execution import ATTACK_PATH_SNAPSHOT_FILENAME
from adscan_internal.reporting_compat import import_optional_pro_module
from adscan_internal.rich_output import (
    mark_sensitive,
    print_error,
    print_info,
    print_info_debug,
    print_instruction,
    print_success,
)
from adscan_internal.services.attack_graph_service import (
    reset_attack_graph_execution_statuses,
)
from adscan_internal.services.attack_paths_materialized_cache import (
    invalidate_attack_path_artifacts,
)
from adscan_internal.workspaces import domain_subpath
from adscan_internal.workspaces.manager import resolve_workspace_paths

LOGGER = logging.getLogger("adscan")


@dataclass(slots=True)
class AttackPathResetShell:
    """Minimal shell-like workspace context for report/graph helpers."""

    current_workspace_dir: str
    domains_dir: str = "domains"
    technical_report_file: str = "technical_report.json"

    def _get_workspace_cwd(self) -> str:
        """Return the workspace cwd expected by attack-path helpers."""
        return self.current_workspace_dir


@dataclass(slots=True)
class AttackPathResetResult:
    """Summary of a reset operation."""

    workspace_dir: str
    domain: str
    graph: dict[str, int]
    report: dict[str, int]
    report_available: bool
    snapshot_removed: bool


def _default_workspaces_root() -> Path:
    """Return the configured workspaces root directory."""
    override = os.getenv("ADSCAN_WORKSPACES_DIR", "").strip()
    if override:
        return Path(os.path.expanduser(override)).resolve()
    return (get_adscan_home() / "workspaces").resolve()


def _discover_workspace_from_cwd() -> Path | None:
    """Return the nearest parent directory that looks like an ADscan workspace."""
    current = Path.cwd().resolve()
    for candidate in (current, *current.parents):
        variables_json = candidate / "variables.json"
        domains_dir = candidate / "domains"
        if variables_json.is_file() or domains_dir.is_dir():
            return candidate
    return None


def resolve_workspace_directory(workspace: str | None) -> str:
    """Resolve a workspace name or path into an absolute directory."""
    if workspace:
        candidate = Path(os.path.expanduser(workspace))
        if candidate.is_dir():
            return str(candidate.resolve())
        named_workspace = resolve_workspace_paths(
            str(_default_workspaces_root()),
            workspace,
        ).root
        if os.path.isdir(named_workspace):
            return str(Path(named_workspace).resolve())
        raise FileNotFoundError(f"Workspace not found: {workspace}")

    discovered = _discover_workspace_from_cwd()
    if discovered is not None:
        return str(discovered)

    default_root = _default_workspaces_root()
    raise FileNotFoundError(
        f"No workspace provided and current directory is not inside a workspace. "
        f"Checked {default_root}"
    )


def _reset_report_statuses_if_available(
    shell: AttackPathResetShell,
    domain: str,
) -> tuple[dict[str, int], bool]:
    """Reset report attack-path statuses when the PRO module is available."""
    report_service = import_optional_pro_module(
        "adscan_internal.pro.services.report_service",
        action="Attack path report reset",
        debug_printer=print_info_debug,
        prefix="[attack-path-reset]",
    )
    if report_service is None:
        LOGGER.debug("Attack path report reset unavailable in this edition")
        return ({}, False)

    reset_fn = getattr(report_service, "reset_attack_path_statuses", None)
    if not callable(reset_fn):
        print_info_debug(
            "[attack-path-reset] report reset skipped: "
            "reset_attack_path_statuses not exported"
        )
        return ({}, False)

    summary = reset_fn(shell, domain)
    if isinstance(summary, dict):
        return (summary, True)
    return ({}, True)


def reset_attack_path_statuses_for_testing(
    *,
    workspace: str | None,
    domain: str,
) -> AttackPathResetResult:
    """Reset persisted attack-path execution state for one workspace/domain."""
    domain_clean = str(domain or "").strip()
    if not domain_clean:
        raise ValueError("A domain is required.")

    workspace_dir = resolve_workspace_directory(workspace)
    shell = AttackPathResetShell(current_workspace_dir=workspace_dir)

    graph_summary = reset_attack_graph_execution_statuses(shell, domain_clean)
    report_summary, report_available = _reset_report_statuses_if_available(
        shell,
        domain_clean,
    )
    invalidate_attack_path_artifacts(shell, domain_clean)

    snapshot_path = Path(
        domain_subpath(
            workspace_dir,
            shell.domains_dir,
            domain_clean,
            ATTACK_PATH_SNAPSHOT_FILENAME,
        )
    )
    snapshot_removed = False
    if snapshot_path.exists():
        snapshot_path.unlink()
        snapshot_removed = True

    return AttackPathResetResult(
        workspace_dir=workspace_dir,
        domain=domain_clean,
        graph=graph_summary,
        report=report_summary,
        report_available=report_available,
        snapshot_removed=snapshot_removed,
    )


def _print_reset_summary(result: AttackPathResetResult) -> None:
    """Render a consistent summary after a successful reset."""
    marked_workspace = mark_sensitive(result.workspace_dir, "path")
    marked_domain = mark_sensitive(result.domain, "domain")
    print_success(
        f"Attack path statuses reset for {marked_domain} in {marked_workspace}."
    )
    print_info(
        "Graph edges reset: "
        f"{result.graph.get('changed', 0)} "
        f"(discovered={result.graph.get('to_discovered', 0)}, "
        f"blocked={result.graph.get('to_blocked', 0)}, "
        f"unsupported={result.graph.get('to_unsupported', 0)})"
    )
    if result.report_available:
        print_info(
            "Technical report reset: "
            f"paths={result.report.get('paths_reset', 0)}, "
            f"steps={result.report.get('steps_reset', 0)}"
        )
    if result.snapshot_removed:
        print_info("Removed cached attack path snapshot.")
    print_info_debug(
        "[attack-path-reset] "
        f"workspace={marked_workspace} "
        f"domain={marked_domain} "
        f"graph={result.graph} report={result.report} "
        f"snapshot_removed={result.snapshot_removed}"
    )


def run_reset_attack_path_statuses(shell: Any, args: str) -> int:
    """Interactive-shell entrypoint for resetting attack-path state.

    Usage:
        reset_attack_path_statuses [domain]

    When the domain is omitted, the current shell domain is used.
    """
    parts = str(args or "").split()
    domain = parts[0] if parts else str(getattr(shell, "domain", "") or "").strip()
    if not domain:
        print_instruction("Usage: reset_attack_path_statuses [domain]")
        return 1

    workspace = str(getattr(shell, "current_workspace_dir", "") or "").strip() or None
    try:
        result = reset_attack_path_statuses_for_testing(
            workspace=workspace,
            domain=domain,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        LOGGER.exception(
            "Failed to reset attack path statuses from interactive shell",
            extra={"workspace": workspace, "domain": domain},
        )
        print_error("Could not reset attack path statuses.")
        print_info(
            f"Workspace: {mark_sensitive(str(workspace or Path.cwd()), 'path')}"
        )
        print_info(f"Domain: {mark_sensitive(str(domain), 'domain')}")
        print_info_debug(f"[attack-path-reset] error: {exc}")
        return 1

    _print_reset_summary(result)
    return 0
