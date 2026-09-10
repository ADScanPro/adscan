"""``adscan report`` — tier-adaptive report regeneration from a kept workspace.

The tier decides the output and the CTA (the same rule as ``ci`` and the REPL
``deliver`` verb): LITE renders the self-contained LITE exposure report WITH
its PRO CTA; PRO renders the single Security Assessment Report PDF WITHOUT a
sales CTA. This command is LITE-safe and is NOT in ``PRO_ONLY_COMMANDS`` — its
LITE purpose is to let an operator regenerate the forwardable exposure report
without re-scanning.

ROLE: ``report`` = the report (a single PDF in PRO); ``deliver`` = the full
Client Deliverable Kit (4 PDFs + ZIP, PRO-only). They never produce the same
output — ``report`` never calls ``run_deliver_sync``.
"""

from __future__ import annotations

import argparse
from typing import Any

from adscan_core import tier
from adscan_core.reporting.technical_report import _get_technical_report_path
from adscan_core.rich_output import print_error
from adscan_internal.cli.ci import run_generate_report
from adscan_internal.services.lite_html_report import generate_lite_report_artifacts


def _build_workspace_shell(workspace: str | None) -> Any | None:
    """Resolve ``workspace`` into a loaded :class:`PentestShell`, or ``None``.

    Mirrors the exact shell-construction + workspace-loading pattern used by
    ``adscan execute`` / ``adscan ci`` (``_setup_workspace`` in
    ``adscan_internal/cli/execute.py``) and the workspace resolution ``adscan
    deliver`` uses (``adscan_internal/cli/common.py::_resolve_workspace``), so
    ``report`` behaves identically to its siblings rather than reinventing a
    third resolution order.

    ``_resolve_workspace`` lives in the LITE-safe ``adscan_internal.cli.common``
    (not ``deliver.py``, which is a PRO-flow module stripped from the LITE
    image) — ``report``/``writeup`` are both LITE-safe, NOT PRO-gated commands,
    so this module must never import ``deliver`` even lazily.

    ``PentestShell`` lives in the top-level ``adscan.py`` module; imported
    lazily here (not at module import time) so importing ``report_cmd`` never
    pulls in the whole monolith unless a report is actually being generated.
    """
    from adscan_internal.cli.common import _resolve_workspace as _resolve_ws

    ws_dir = _resolve_ws(argparse.Namespace(workspace=workspace))
    if ws_dir is None or not ws_dir.is_dir():
        return None

    from adscan import PentestShell, _resolve_license_mode  # noqa: PLC0415

    shell = PentestShell(license_mode=_resolve_license_mode(requested_pro=False))
    shell.type = getattr(shell, "type", None) or "audit"
    shell.ensure_workspaces_dir()
    shell.current_workspace = ws_dir.name
    shell.current_workspace_dir = str(ws_dir)
    shell.load_workspace_data(str(ws_dir))
    return shell


def _resolve_report_json(shell: Any) -> str:
    """Resolve the workspace's ``technical_report.json`` path from ``shell``.

    Reuses the shared SSOT resolver (:func:`_get_technical_report_path`) that
    both the LITE renderer and the PRO report service already use — never
    hand-rolled, so a filename/location change only needs one fix.
    """
    return str(_get_technical_report_path(shell))


def run_report_sync(args: argparse.Namespace) -> int:
    """Regenerate the report for a kept workspace. Tier decides the output.

    LITE: the self-contained LITE exposure report (with its PRO CTA).
    PRO: the single Security Assessment Report PDF (NOT the full kit — that
    is ``adscan deliver``).

    Returns:
        Process exit code: ``0`` on success, ``1`` on render failure, ``2``
        when no workspace could be resolved.
    """
    shell = _build_workspace_shell(getattr(args, "workspace", None))
    if shell is None:
        print_error(
            "No workspace available. Run 'adscan start' first, or pass --workspace WS."
        )
        return 2

    if tier.is_pro():
        # Lazy import: `_parse_frameworks` is a pure validator with no
        # `adscan_internal.pro` dependency and lives in the LITE-safe
        # `adscan_internal.cli.common` (not `deliver.py`, which is PRO-flow
        # code stripped from the LITE image). Kept lazy here anyway — this
        # branch only runs under PRO — mirroring `_build_workspace_shell`'s
        # lazy import style.
        from adscan_internal.cli.common import _parse_frameworks

        frameworks_raw = getattr(args, "frameworks", None)
        try:
            frameworks = _parse_frameworks(frameworks_raw)
        except ValueError as exc:
            print_error(str(exc))
            return 1

        report_json = _resolve_report_json(shell)
        result = run_generate_report(
            shell,
            report_json,
            report_format="pdf",
            frameworks=frameworks,
            display_name=getattr(args, "client", "") or "",
        )
        return 0 if result else 1

    # LITE: the self-contained exposure report, with its PRO CTA intact.
    artifacts = generate_lite_report_artifacts(shell, asked_for_the_kit=True)
    return 0 if artifacts is not None else 1


def add_report_subparser(
    subparsers: argparse._SubParsersAction,
) -> argparse.ArgumentParser:
    """Register the ``report`` subparser. Shared by container + launcher.

    Explicit flags (not ``REMAINDER``) mirror ``deliver``'s pattern — ``report``
    is a tier-adaptive single-document render, not a REMAINDER-forwarded
    verb, so its flag surface is small and stable enough to declare directly.
    """
    parser = subparsers.add_parser(
        "report",
        help="Regenerate the report for a kept workspace without re-scanning.",
        description=(
            "Render the report from an existing workspace's technical_report.json. "
            "LITE renders the self-contained exposure report (with a PRO CTA); "
            "PRO renders the single Security Assessment Report PDF. "
            "Not PRO-gated — use 'adscan deliver' for the full Client Deliverable Kit."
        ),
    )
    parser.add_argument(
        "--workspace",
        dest="workspace",
        default=None,
        help="Workspace name or path (default: prompt or most-recent).",
    )
    parser.add_argument(
        "--client",
        dest="client",
        default=None,
        help="Client name (optional, embedded in the report's cover as the display name; PRO only).",
    )
    parser.add_argument(
        "--frameworks",
        dest="frameworks",
        type=str,
        default=None,
        help=(
            "Comma-separated compliance frameworks to render (PRO only). "
            "Choices: ens, nis2, iso27001, dora, pci_dss, cis. Default: none."
        ),
    )
    # Mirrors the per-subcommand --debug on start/ci/deliver/execute/doctor.
    # The host launcher forwards --debug to the container subcommand, so
    # `report` must accept it (argparse rejects unknown flags). Activation
    # into DEBUG_MODE happens in the top-level dispatcher's debug block.
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable debug mode.",
    )
    return parser


__all__ = (
    "add_report_subparser",
    "run_report_sync",
)
