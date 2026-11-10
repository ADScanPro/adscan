"""What a non-interactive run does with the workspace it creates for itself.

One rule for ``adscan ci`` and ``adscan execute`` (and the disposal step of
``adscan doctor``):

- The workspace is the run's output (credentials, graph, report, logs), so a
  run KEEPS it. An auto-created one gets a readable name
  (``<prefix>-<domain>-<YYYYMMDD-HHMM>``) because the operator has to find it.
- ``--ephemeral`` opts in to deleting the workspace the run created. A failed
  run keeps only its ``logs/`` (:func:`finish_ephemeral_workspace`).
- A workspace that existed before the run is never deleted by it.

``doctor`` is a health check, not a scan: its auto-created throwaway workspace
is always disposed of (it has no flag), and a named ``-w`` one is kept.
"""

from __future__ import annotations

import os
import re
from datetime import datetime
from typing import Any, Optional

#: ``--ephemeral`` help, shared so ``ci`` and ``execute`` describe it alike.
EPHEMERAL_HELP = (
    "Delete the workspace this run creates when it ends (a failed run keeps only "
    "its logs). By default the workspace is kept."
)


def add_ephemeral_argument(parser: Any, *, help_suffix: str = "") -> None:
    """Register ``--ephemeral`` on a ``ci`` / ``execute`` parser."""
    text = f"{EPHEMERAL_HELP} {help_suffix}".strip()
    parser.add_argument("--ephemeral", action="store_true", help=text)


def auto_workspace_name(prefix: str, domain: Optional[str], workspaces_dir: str) -> str:
    """``<prefix>-<domain>-<YYYYMMDD-HHMM>`` (``<prefix>-<YYYYMMDD-HHMM>`` without one).

    A second run in the same minute gets ``-2``, ``-3``...
    """
    slug = str(domain or "").strip().lower()
    slug = re.sub(r"[^a-z0-9.-]+", "-", slug).strip(".-")
    stamp = datetime.now().strftime("%Y%m%d-%H%M")
    base = f"{prefix}-{slug}-{stamp}" if slug else f"{prefix}-{stamp}"
    name, suffix = base, 2
    while os.path.exists(os.path.join(workspaces_dir, name)):
        name = f"{base}-{suffix}"
        suffix += 1
    return name


def host_display_path(path: Optional[str]) -> str:
    """Show a container path as the operator sees it on the host (``~/.adscan``)."""
    text = str(path or "")
    try:
        from adscan_core.pal.paths import (  # noqa: PLC0415
            container_adscan_root,
            host_adscan_root_display,
        )

        root = str(container_adscan_root()).rstrip("/")
        if text == root or text.startswith(root + "/"):
            return str(host_adscan_root_display()) + text[len(root):]
    except Exception:  # noqa: BLE001 — display only
        pass
    return text


def close_run_workspace(
    *,
    name: Optional[str],
    workspace_dir: Optional[str],
    created: bool,
    ephemeral: bool,
    failed: bool,
    report_path: Optional[str] = None,
    announce: bool = True,
) -> str:
    """Keep or delete the run's workspace and say which.

    Args:
        name: Logical workspace name (display).
        workspace_dir: Its directory.
        created: The run created it (only such a workspace may be deleted).
        ephemeral: Delete it (``--ephemeral``; ``doctor``'s throwaway).
        failed: The run failed: a deleted workspace keeps its ``logs/``.
        report_path: A report the kept workspace holds, named in the summary.
        announce: Print the outcome (``doctor`` stays quiet: its output is the
            check matrix or a JSON document).

    Returns:
        ``"deleted"``, ``"kept_logs"``, ``"kept"`` or ``"error"``.
    """
    from adscan_internal import (  # noqa: PLC0415
        print_error,
        print_exception,
        print_info,
        print_success,
        telemetry,
    )
    from adscan_internal.rich_output import mark_sensitive  # noqa: PLC0415

    marked = mark_sensitive(str(name or ""), "workspace")
    if ephemeral and created and workspace_dir:
        try:
            # Through the workspace SSOT: log handles released first (an open
            # handle blocks the delete on Windows), residue outside the
            # directory removed too, and a failed run keeps only logs/.
            from adscan_internal.workspaces.manager import (  # noqa: PLC0415
                finish_ephemeral_workspace,
            )

            outcome = finish_ephemeral_workspace(workspace_dir, failed=failed)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error(f"Failed to remove workspace '{marked}'.")
            print_exception(show_locals=False, exception=exc)
            return "error"
        if outcome == "deleted" and announce:
            print_success(f"Workspace '{marked}' deleted (--ephemeral)")
        return outcome

    if not announce:
        return "kept"
    if ephemeral and not created:
        print_info(
            f"Workspace '{marked}' existed before this run, so --ephemeral leaves it in place."
        )
    report_part = (
        f" Report: {mark_sensitive(host_display_path(report_path), 'path')}."
        if report_path and os.path.exists(report_path)
        else ""
    )
    if workspace_dir:
        print_info(
            "Workspace: "
            f"{mark_sensitive(host_display_path(workspace_dir), 'path')} "
            f"(kept on disk with the credentials it collected).{report_part}"
        )
    return "kept"
