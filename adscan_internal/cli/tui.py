"""``adscan tui`` — top-level entry point for the Textual workbench.

This is a thin wrapper around the existing ``start --tui`` path so champions
can discover the workbench as a first-class command. The implementation
re-uses :func:`handle_start` (in ``adscan.py``) to ensure license, telemetry
and shell construction stay identical between ``adscan start --tui`` and
``adscan tui``.

Adding ``--demo`` boots the TUI on top of the deterministic demo workspace
fixture so the operator can preview the workbench without running a real
scan.
"""

from __future__ import annotations

import argparse
from typing import Callable

from adscan_core import telemetry
from adscan_core.rich_output import print_error, print_info_verbose, print_warning
from adscan_core.rich_output import print_exception


def run_tui(
    args: argparse.Namespace,
    *,
    handle_start: Callable[[argparse.Namespace], None],
) -> int:
    """Launch the ADscan workbench TUI.

    Args:
        args: Parsed argparse namespace. Supported attributes:
            ``demo`` (bool), ``verbose`` (bool), ``debug`` (bool).
        handle_start: Reference to ``adscan.py:handle_start`` — injected
            to avoid a circular import.

    Returns:
        Process exit code (0 on success, non-zero on failure).
    """
    # Hard fail early if textual is missing — never silently fall back to
    # the prompt_toolkit shell when the user explicitly asked for the TUI.
    try:
        import textual  # noqa: F401
    except ImportError as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(
            "TUI dependencies are not available in this runtime. "
            "Install/build a runtime image that includes Textual support."
        )
        return 1

    if getattr(args, "demo", False):
        try:
            _seed_demo_workspace()
        except Exception as exc:  # noqa: BLE001 — demo seeding is non-fatal
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_warning(f"Could not seed demo workspace: {exc}")

    # Reuse handle_start with tui=True. We force the flag on the namespace
    # so handle_start's create_shell factory selects the TUI wrapper.
    args.tui = True
    print_info_verbose("Launching ADscan workbench TUI…")
    try:
        handle_start(args)
    except SystemExit as exc:
        return int(exc.code or 0)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(f"TUI exited with an error: {exc}")
        return 1
    return 0


# ---------------------------------------------------------------------------
# Demo seeding
# ---------------------------------------------------------------------------


def _seed_demo_workspace() -> None:
    """Materialize the demo workspace on disk (idempotent).

    Delegates to :mod:`adscan_internal.cli.demo` so the demo data, posture
    score and PDF assets stay in lock-step with ``adscan demo``.
    """
    try:
        from adscan_internal.cli import demo as demo_mod
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return

    seeder = getattr(demo_mod, "ensure_demo_workspace", None)
    if callable(seeder):
        seeder()  # pylint: disable=not-callable
        return
    # Fallback: best-effort — touch the demo workspace directory so the
    # sidebar surfaces it even before any scan runs.
    from adscan_core.paths import get_workspaces_dir

    demo_name = getattr(demo_mod, "DEMO_WORKSPACE_NAME", "demo-north-haven")
    demo_path = get_workspaces_dir() / demo_name
    demo_path.mkdir(parents=True, exist_ok=True)
