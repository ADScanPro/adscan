"""First-run discovery panel.

A subtle, non-blocking 3-line hint shown the very first time an operator
opens the ADscan shell with no prior scan history. Disappears
permanently after the first ``start_auth`` / ``start_unauth`` / ``demo``.

This is intentionally separate from the older ``is_first_run`` /
``.first_run_complete`` flag in :mod:`adscan_internal.cli.common`:

* ``.first_run_complete``: first launch ever (already used by the
  getting-started panel).
* ``.first_scan_done``: no successful scan yet. New flag introduced
  by this module so the demo hint can persist across launcher restarts
  until the operator actually scans something.

Design notes:
- Anti-pattern #10 (over-decorated chrome) is the failure mode here.
  This panel is the first frame of ADscan; it must feel premium without
  shouting. The body stays at three lines, the only chrome is a thin
  brand-tinted border and a small landmark glyph anchoring the action.
- Brand color comes from ``adscan_core.theme`` rather than a bare ANSI
  name so a future theme swap stays single-source.
"""

from __future__ import annotations

from pathlib import Path

from adscan_core.path_utils import get_adscan_state_dir
from adscan_core.paths import get_workspaces_dir
from adscan_core.rich_output import print_panel
from adscan_core.theme import ADSCAN_PRIMARY


_FLAG_FILENAME = ".first_scan_done"


def _flag_path() -> Path:
    """Return the canonical first-scan flag path (mounted from host)."""
    return get_adscan_state_dir() / _FLAG_FILENAME


def first_scan_done() -> bool:
    """Return ``True`` once the operator has completed a real scan or demo."""
    return _flag_path().exists()


def mark_first_scan_done() -> None:
    """Persist that the operator has completed a scan or demo (idempotent)."""
    flag = _flag_path()
    try:
        flag.parent.mkdir(parents=True, exist_ok=True)
        flag.touch()
    except Exception:
        # Non-critical: failing to write the flag at worst shows the panel
        # one extra time. Never block the success path on this.
        pass


def _workspaces_dir_is_empty() -> bool:
    """Return ``True`` when no real workspace directories exist on disk.

    A workspace is considered "real" when it is a directory whose name
    does not start with ``.`` (we ignore ``.gitkeep`` and other hidden
    bookkeeping files).
    """
    try:
        ws_dir = get_workspaces_dir()
    except Exception:
        return True
    if not ws_dir.exists():
        return True
    try:
        for entry in ws_dir.iterdir():
            if entry.is_dir() and not entry.name.startswith("."):
                return False
    except Exception:
        return True
    return True


def should_show_first_run_panel() -> bool:
    """Return whether the first-run discovery panel should be rendered."""
    if first_scan_done():
        return False
    return _workspaces_dir_is_empty()


def show_first_run_panel() -> None:
    """Render the non-blocking 3-line discovery panel.

    Idempotent suppression rules are enforced by
    :func:`should_show_first_run_panel`; callers may call this directly
    to force-render (e.g. for tests).
    """
    body = (
        "[grey70]New to ADscan? Watch a 60-second tour of what it finds.[/]\n"
        f"  [bold {ADSCAN_PRIMARY}]▸ adscan demo[/]\n"
        "[grey50]Or continue below to scan a real domain.[/]"
    )
    print_panel(
        body,
        title=f"[bold {ADSCAN_PRIMARY}]Welcome[/]",
        title_align="left",
        border_style=f"dim {ADSCAN_PRIMARY}",
        padding=(0, 2),
    )


def maybe_show_first_run_panel() -> None:
    """Render the panel only when :func:`should_show_first_run_panel` says so."""
    if should_show_first_run_panel():
        show_first_run_panel()


def workspace_explainer_should_show(workspaces_dir: str | None = None) -> bool:
    """Return whether the "what is a workspace" explainer should render.

    True only for a brand-new operator with no workspaces yet. A returning
    operator (one or more workspaces on disk) never sees it. When
    ``workspaces_dir`` is provided it is authoritative; otherwise we fall back
    to the mounted workspaces directory used by the first-run panel.
    """
    if workspaces_dir is not None:
        try:
            from adscan_internal.workspaces import list_workspaces

            return not list_workspaces(workspaces_dir)
        except Exception:
            return _workspaces_dir_is_empty()
    return _workspaces_dir_is_empty()


def show_workspace_explainer() -> None:
    """Render the one-time, premium "what is a workspace" orientation panel.

    Shown once before the brand-new operator's first workspace-name prompt to
    remove the "what do I even type" friction that drives step-zero drop-off.
    Kept intentionally tight (three lines) so it orients without a wall of text.
    """
    body = (
        "[grey70]A workspace is one environment you audit (a domain or forest).[/]\n"
        "[grey70]ADscan keeps each environment's data, credentials and findings "
        "isolated from the others.[/]\n"
        f"[grey50]Name it after the environment, or press [bold {ADSCAN_PRIMARY}]"
        "Enter[/] to accept the suggested default.[/]"
    )
    print_panel(
        body,
        title=f"[bold {ADSCAN_PRIMARY}]Your first workspace[/]",
        title_align="left",
        border_style=f"dim {ADSCAN_PRIMARY}",
        padding=(0, 2),
    )


def maybe_show_workspace_explainer(workspaces_dir: str | None = None) -> None:
    """Render the workspace explainer only for a brand-new operator."""
    if workspace_explainer_should_show(workspaces_dir):
        show_workspace_explainer()


__all__ = [
    "first_scan_done",
    "mark_first_scan_done",
    "maybe_show_first_run_panel",
    "maybe_show_workspace_explainer",
    "should_show_first_run_panel",
    "show_first_run_panel",
    "show_workspace_explainer",
    "workspace_explainer_should_show",
]
