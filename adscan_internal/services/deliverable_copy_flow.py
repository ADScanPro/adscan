"""The interactive "save a copy elsewhere, then open it" step for deliverables.

One flow for both tiers: the guided ``deliver`` (PRO kit) and the LITE exposure
report call :func:`offer_copy_and_open` once the files exist. Only the files
differ; the questions, the destination rules and the open behaviour are the
same. Destination resolution, path mapping and copying live in the shared SSOT
``adscan_core.deliverable_destination``; this module adds the prompts and the
opener, which need ``adscan_internal``.

Never prompts in a non-interactive run (``adscan ci``, ``adscan execute``, the
web worker): those choose a destination with ``--output`` instead.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional, Sequence

from rich.markup import escape

from adscan_core import telemetry
from adscan_core.deliverable_destination import (
    DeliverablesRoot,
    copy_to_destination,
    default_destination_display,
    deliverables_root,
    resolve_destination,
)
from adscan_core.interaction import is_non_interactive
from adscan_core.rich_output import (
    confirm_ask,
    print_exception,
    print_info_debug,
    print_success,
    print_warning,
    prompt_ask,
)

__all__ = ("offer_copy_and_open", "offer_deliverable_copy")

_COPY_QUESTION = "Also save a copy to another folder?"


def _ask_destination(shell: Any, root: DeliverablesRoot, workspace: str) -> Optional[Path]:
    """Ask for a folder until it is reachable; None when the operator declines.

    An unreachable folder is explained plainly and the deliverables folder is
    offered instead, so the operator is never left at a dead end.
    """
    default_display = default_destination_display(root, workspace)
    answer = prompt_ask("Folder", default=default_display, shell=shell)
    resolution = resolve_destination(answer or default_display, root)
    if resolution.ok:
        return resolution.io_path
    print_warning(escape(resolution.error))
    if not confirm_ask(f"Save it in {escape(default_display)} instead?", default=True):
        return None
    return resolve_destination(default_display, root).io_path


def offer_deliverable_copy(
    shell: Any,
    *,
    files: Sequence[Path | str],
    workspace: str,
) -> dict[Path, Path]:
    """Offer to copy ``files`` to a folder of the operator's choosing.

    Args:
        shell: The active shell, for the non-interactive predicate (may be None).
        files: The artefacts to copy; missing ones are skipped.
        workspace: Workspace name or path, used for the suggested subfolder.

    Returns:
        ``{source: copy}`` for every file copied; empty when nothing was.
    """
    if is_non_interactive(shell):
        return {}
    sources = [Path(f) for f in files if f and Path(f).is_file()]
    if not sources:
        return {}
    root = deliverables_root()
    if root is None:
        print_info_debug(
            "deliverable copy skipped: no deliverables folder is mounted in this container"
        )
        return {}
    if not confirm_ask(_COPY_QUESTION, default=True):
        return {}
    destination = _ask_destination(shell, root, workspace)
    if destination is None:
        return {}
    try:
        copied = copy_to_destination(sources, destination)
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_warning(f"Could not save the copy: {escape(str(exc))}")
        return {}
    from adscan_internal.services.host_open import display_host_path  # noqa: PLC0415

    count = len(copied)
    noun = "file" if count == 1 else "files"
    print_success(f"Saved {count} {noun} to {escape(display_host_path(destination))}")
    return {src: dst for src, dst in zip(sources, copied)}


def offer_copy_and_open(
    shell: Any,
    *,
    files: Sequence[Path | str],
    headline: Optional[Path | str],
    workspace: str,
    open_prompt: str,
) -> Optional[Path]:
    """Offer the copy, then offer to open the headline from where it now lives.

    The open step opens the copy when one was made, otherwise the workspace
    copy. Both steps are skipped in a non-interactive run.

    Returns:
        The path offered for opening (the copy or the original), or None.
    """
    copies = offer_deliverable_copy(shell, files=files, workspace=workspace)
    if not headline:
        return None
    original = Path(headline)
    target = copies.get(original, original)
    if not target.is_file():
        return None
    from adscan_internal.services.host_open import prompt_and_open  # noqa: PLC0415

    prompt_and_open(target, prompt=open_prompt)
    return target
