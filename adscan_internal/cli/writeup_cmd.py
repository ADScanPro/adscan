"""``adscan writeup`` — write the lab writeup evidence spine for a workspace.

Records the mechanical two-thirds of a lab writeup (ports, directory
contents, the attack chain as a mermaid diagram, every step that ran with
its outcome and a public reference, credential provenance, and the routes
that went nowhere) without writing any of the prose — the paragraphs are
left as marked, empty placeholders for the author to fill in.

LITE-safe and NOT PRO-gated (not in ``PRO_ONLY_COMMANDS``): the spine
references no PRO-only verbs and is useful to any operator who wants the
mechanical part of a writeup on disk from a kept workspace, without
re-running a scan.
"""

from __future__ import annotations

import argparse
from typing import Any

from adscan_core.rich_output import print_error
from adscan_internal.services.post_scan_report import TRIGGER_REPL_WRITEUP
from adscan_internal.services.writeup_spine import generate_writeup_spine


def _build_workspace_shell(workspace: str | None) -> Any | None:
    """Resolve ``workspace`` into a loaded :class:`PentestShell`, or ``None``.

    Reuses the exact resolver ``adscan report`` already uses (kept workspace
    → shell context), so ``writeup`` behaves identically to its sibling
    command rather than reinventing a second resolution order.
    """
    from adscan_internal.cli.report_cmd import _build_workspace_shell as _b

    return _b(workspace)


def run_writeup_sync(args: argparse.Namespace) -> int:
    """Write the writeup evidence spine for a kept workspace.

    Returns:
        Process exit code: ``0`` on success, ``2`` when no workspace could
        be resolved.
    """
    shell = _build_workspace_shell(getattr(args, "workspace", None))
    if shell is None:
        print_error(
            "No workspace available. Run 'adscan start' first, or pass --workspace WS."
        )
        return 2

    generate_writeup_spine(
        shell,
        output_dir=getattr(args, "output_dir", None),
        trigger=TRIGGER_REPL_WRITEUP,
    )
    return 0


def add_writeup_subparser(
    subparsers: argparse._SubParsersAction,
) -> argparse.ArgumentParser:
    """Register the ``writeup`` subparser. Shared by container + launcher."""
    parser = subparsers.add_parser(
        "writeup",
        help="Write a Markdown evidence spine for a lab writeup from a kept workspace.",
        description=(
            "Record the mechanical part of a writeup while it is still on disk: "
            "the ports that answered, what the directory held, the chain as a "
            "mermaid diagram, every step that ran with its outcome and a public "
            "reference for the technique, which credential came from which "
            "technique, and the routes that went nowhere. Writes no analysis — "
            "the paragraphs that carry a writeup are left as marked, empty "
            "placeholders for the author to fill in. Not PRO-gated."
        ),
    )
    parser.add_argument(
        "--workspace",
        dest="workspace",
        default=None,
        help="Workspace name or path (default: prompt or most-recent).",
    )
    parser.add_argument(
        "output_dir",
        nargs="?",
        default=None,
        help=(
            "Destination directory for the spine (default: a timestamped "
            "directory under <workspace>/writeups/)."
        ),
    )
    # Mirrors the per-subcommand --debug on start/ci/deliver/report/execute/doctor.
    # The host launcher forwards --debug to the container subcommand, so
    # `writeup` must accept it (argparse rejects unknown flags). Activation
    # into DEBUG_MODE happens in the top-level dispatcher's debug block.
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable debug mode.",
    )
    return parser


__all__ = (
    "add_writeup_subparser",
    "run_writeup_sync",
)
