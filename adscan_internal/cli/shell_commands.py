"""Registry of top-level CLI commands surfaced inside :class:`PentestShell`.

Each entry in :data:`REGISTRY` binds a shell verb to its handler module.
New top-level commands plug in here once and inherit help, autocomplete,
telemetry, and post-scan suggestions automatically — so the shell never
has to grow another hand-written ``do_*`` method for these surfaces.

Design rules
------------

* **Single source of truth.** The shell binder, the help-tree builder,
  the splash editorial, and the post-scan suggestion panel all read from
  this registry. No verb is hardcoded twice.
* **Snake-case verbs.** ``cmd``-style shells dispatch on Python
  identifiers, so the in-shell verb is the snake-case form. Top-level
  kebab variants (e.g. ``coverage-matrix``) live behind
  ``adscan deliver --only`` rather than as standalone commands.
* **Handlers receive ``(shell, args_str)``.** The bound ``do_<verb>``
  passes the raw argument string through verbatim — handlers are
  responsible for parsing it (typically by reusing the existing
  argparse subparser declared by the underlying CLI module).
"""

from __future__ import annotations

import argparse
import shlex
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from adscan_core.rich_output import print_exception


# ---------------------------------------------------------------------------
# Spec
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ShellCommandSpec:
    """One registered top-level command surfaced inside the shell.

    Attributes:
        verb: ``do_<verb>`` exposed in :class:`PentestShell`. Must be a
            valid Python identifier (snake_case).
        category: Help-tree category. Drives ``help <category>`` output.
        short_help: One-line, action-verb-first description (table cell).
        long_help: Multi-line help text (``help <verb>`` output). Should
            include ``Usage:``, flags, and an ``Examples:`` block.
        handler: Called with ``(shell, args_str)``. The handler is
            responsible for argparse parsing, telemetry of internal
            errors, and exit-code translation into Rich output.
        suggested_after: Verbs that should suggest this one once they
            complete successfully (drives the post-scan "Next step"
            panel).
        is_deliverable: Surface in the post-scan deliverables list.
        is_dev_only: Hide from default ``help``; show only with
            ``help --all`` (reserved — no entries today).
    """

    verb: str
    category: str
    short_help: str
    long_help: str
    handler: Callable[[Any, str], None]
    suggested_after: tuple[str, ...] = field(default_factory=tuple)
    is_deliverable: bool = False
    is_dev_only: bool = False


# ---------------------------------------------------------------------------
# Argparse helpers — keep flag declarations in sync with the top-level CLI
# without redeclaring them here.
# ---------------------------------------------------------------------------


def _parse_demo_args(args: str) -> argparse.Namespace:
    """Parse a shell-side ``demo`` arg string using the canonical subparser."""
    from adscan_internal.cli.demo import add_demo_subparser

    parser = argparse.ArgumentParser(prog="demo", add_help=False)
    sub = parser.add_subparsers(dest="_cmd")
    add_demo_subparser(sub)
    tokens = ["demo", *shlex.split(args)] if args.strip() else ["demo"]
    return parser.parse_args(tokens)


def _parse_bonus_args(args: str) -> argparse.Namespace:
    """Parse a shell-side bonus-PDF arg string into the namespace shape used
    by :mod:`adscan_internal.cli.bonuses`.

    The bonus subparsers all share the same flag surface
    (``--output``/``--no-open``/``--no-render``); we re-use the existing
    add-helper so a flag drift is impossible.
    """
    parser = argparse.ArgumentParser(prog="bonus", add_help=False)
    parser.add_argument("--output", dest="output_path", default=None)
    parser.add_argument("--no-open", dest="no_open", action="store_true")
    parser.add_argument("--no-render", dest="no_render", action="store_true")
    return parser.parse_args(shlex.split(args) if args.strip() else [])


def _parse_tui_args(args: str) -> argparse.Namespace:
    """Parse a shell-side ``tui`` arg string."""
    parser = argparse.ArgumentParser(prog="tui", add_help=False)
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-d", "--debug", action="store_true")
    return parser.parse_args(shlex.split(args) if args.strip() else [])


def _parse_deliver_args(args: str) -> argparse.Namespace:
    """Parse a shell-side ``deliver`` arg string."""
    parser = argparse.ArgumentParser(prog="deliver", add_help=False)
    parser.add_argument("--workspace", dest="workspace", default=None)
    parser.add_argument("--client", dest="client", default=None)
    parser.add_argument("--engagement", dest="engagement", default=None)
    parser.add_argument("--output", dest="output", default=None)
    parser.add_argument("--only", dest="only", default=None)
    parser.add_argument("--frameworks", dest="frameworks", default=None)
    parser.add_argument("--no-navigator", dest="no_navigator", action="store_true")
    parser.add_argument(
        "--report-theme",
        dest="report_theme",
        default="",
    )
    parser.add_argument(
        "--theme",
        dest="theme",
        default="",
        choices=["", "dark", "premium_dark", "light", "corporate_light"],
    )
    return parser.parse_args(shlex.split(args) if args.strip() else [])


def _parse_mitre_navigator_args(args: str) -> argparse.Namespace:
    """Parse a shell-side ``mitre_navigator`` arg string.

    Mirrors the flag surface declared by the canonical subparser in
    :mod:`adscan_internal.cli.mitre_navigator` so the namespace the
    entrypoint reads (``workspace``/``output``/``client``/``engagement``/
    ``web``/``no_html``/``no_history``/``verbose``) is fully populated.
    """
    parser = argparse.ArgumentParser(prog="mitre_navigator", add_help=False)
    parser.add_argument("--workspace", dest="workspace", default=None)
    parser.add_argument("--output", dest="output", default=None)
    parser.add_argument("--client", dest="client", default=None)
    parser.add_argument("--engagement", dest="engagement", default=None)
    parser.add_argument("--web", dest="web", action="store_true")
    parser.add_argument("--no-html", dest="no_html", action="store_true")
    parser.add_argument("--no-history", dest="no_history", action="store_true")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true")
    return parser.parse_args(shlex.split(args) if args.strip() else [])


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


def _run_demo(shell: Any, args: str) -> None:
    from adscan_internal.cli.demo import run_demo

    parsed = _parse_demo_args(args)
    run_demo(parsed)
    # Mark the first-scan flag — running the demo counts as engagement.
    try:
        from adscan_internal.cli.first_run_panel import mark_first_scan_done

        mark_first_scan_done()
    except Exception:  # noqa: BLE001 — flag is best-effort
        pass


def _run_tui(shell: Any, args: str) -> None:
    from adscan_internal.cli.tui import run_tui

    parsed = _parse_tui_args(args)
    # Reuse the launcher's handle_start indirection by routing through the
    # shell's already-running instance — the TUI module will set tui=True
    # on the namespace and call handle_start.
    handle_start = getattr(shell, "_handle_start_for_tui", None)
    if handle_start is None:
        # Fall back to importing handle_start lazily — adscan.py exposes it.
        import adscan as _adscan_main  # type: ignore[import-not-found]

        handle_start = _adscan_main.handle_start
    run_tui(parsed, handle_start=handle_start)


def _run_cheatsheet(shell: Any, args: str) -> None:
    from adscan_internal.cli.bonuses import run_cheatsheet

    run_cheatsheet(_parse_bonus_args(args))


def _run_deliver(shell: Any, args: str) -> None:
    """Render the full Client Deliverable Kit from the shell.

    The shell sets the active workspace as ``ADSCAN_CURRENT_WORKSPACE``
    so deliver's resolver picks it up without a prompt.

    LITE behaviour: ``adscan_internal/cli/deliver.py`` is stripped from the
    LITE image, so attempting the import would raise ``ModuleNotFoundError``
    and surface as a generic "Couldn't run deliver" error in the shell.
    Instead we short-circuit to the canonical PRO upsell panel — same one
    rendered by the host launcher and the post-scan suggestions — so the
    LITE operator sees a consistent upgrade path at every entry point.
    """
    import os

    from adscan_core import tier

    if not tier.is_pro():
        # LITE: produce the artifact, never point at another verb. The REPL
        # aliases ``report`` / ``reporting`` / ``generate_report`` onto
        # ``deliver``, so an upsell telling the operator to run
        # ``generate_report`` routes straight back here and loops forever with
        # no report at the end. The tier decides the output, not the verb (same
        # rule as ``ci``): LITE renders the self-contained HTML exposure report
        # and the success panel carries the pointer to the PRO kit.
        #
        # Kept byte-identical to the ``do_deliver`` branch in ``adscan.py``:
        # both handlers are reachable through the registry binder, and letting
        # them disagree is how this bug reached a real session.
        from adscan_internal.services.post_scan_report import (
            TRIGGER_REPL_DELIVER,
            generate_report_with_telemetry,
        )

        generate_report_with_telemetry(
            shell, trigger=TRIGGER_REPL_DELIVER, asked_for_the_kit=True
        )
        return

    from adscan_internal.cli.deliver import run_deliver_sync

    parsed = _parse_deliver_args(args)
    ws_dir = getattr(shell, "current_workspace_dir", None)
    prev = os.environ.get("ADSCAN_CURRENT_WORKSPACE")
    if ws_dir and not getattr(parsed, "workspace", None):
        os.environ["ADSCAN_CURRENT_WORKSPACE"] = str(ws_dir)
    try:
        run_deliver_sync(parsed)
    finally:
        if prev is None:
            os.environ.pop("ADSCAN_CURRENT_WORKSPACE", None)
        else:
            os.environ["ADSCAN_CURRENT_WORKSPACE"] = prev


def _run_writeup(shell: Any, args: str) -> None:
    """Write the writeup evidence spine for the active workspace.

    The single positional argument is an output directory, so the operator can
    drop the spine straight into a blog repository instead of the workspace.
    """
    from adscan_internal.services.writeup_spine import generate_writeup_spine

    tokens = shlex.split(args) if args.strip() else []
    generate_writeup_spine(shell, output_dir=tokens[0] if tokens else None)


def _run_mitre_navigator(shell: Any, args: str) -> None:
    """Export a MITRE ATT&CK Navigator layer from the active workspace.

    Reuses the canonical entrypoint
    :func:`adscan_internal.cli.mitre_navigator.run_mitre_navigator_sync`
    with zero logic duplication. The active workspace directory is injected
    as ``--workspace`` when the operator did not pass one explicitly, so the
    export targets the session's current workspace without a prompt.
    """
    from adscan_internal.cli.mitre_navigator import run_mitre_navigator_sync

    parsed = _parse_mitre_navigator_args(args)
    ws_dir = getattr(shell, "current_workspace_dir", None)
    if ws_dir and not getattr(parsed, "workspace", None):
        parsed.workspace = str(ws_dir)
    run_mitre_navigator_sync(parsed)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


_DELIVERABLES_CATEGORY = "Deliverables"


REGISTRY: tuple[ShellCommandSpec, ...] = (
    ShellCommandSpec(
        verb="demo",
        category=_DELIVERABLES_CATEGORY,
        short_help="Run a 60-second deterministic preview against a baked-in fake AD.",
        long_help=(
            "Usage:\n"
            "  demo [--fast] [--no-pdf] [--seed N] [--output PATH]\n\n"
            "Render the deterministic demo workspace and produce a real PDF\n"
            "report. Useful for previewing ADscan output without configuring\n"
            "credentials.\n\n"
            "Examples:\n"
            "  demo                   # full 60s tour, opens PDF at the end\n"
            "  demo --fast --no-pdf   # smoke run, no PDF\n"
        ),
        handler=_run_demo,
        suggested_after=(),
        is_deliverable=False,
    ),
    # The Textual workbench is still under active development. The verb
    # remains registered (developers can invoke `tui` inside the shell)
    # but is flagged is_dev_only so production help listings can elide
    # it without losing the dispatch. Mirrors the launcher/container
    # SUPPRESS on `adscan tui`.
    ShellCommandSpec(
        verb="tui",
        category=_DELIVERABLES_CATEGORY,
        short_help="Open the Textual workbench (multi-pane interactive UI).",
        long_help=(
            "Usage:\n"
            "  tui [--demo]\n\n"
            "Open the workbench TUI overlay in this terminal session. The shell\n"
            "remains intact when the TUI exits.\n\n"
            "Examples:\n"
            "  tui                # current workspace\n"
            "  tui --demo         # baked-in demo workspace, no real scan needed\n"
        ),
        handler=_run_tui,
        suggested_after=(),
        is_deliverable=False,
        is_dev_only=True,
    ),
    ShellCommandSpec(
        verb="cheatsheet",
        category=_DELIVERABLES_CATEGORY,
        short_help="Generate the Quick-Start Cheat Sheet PDF (operator companion).",
        long_help=(
            "Usage:\n"
            "  cheatsheet [--output PATH] [--no-open] [--no-render]\n\n"
            "Render the 2-page Quick-Start Cheat Sheet — desk reference: 15\n"
            "commands, 14 key bindings, 5 fast fixes.\n\n"
            "Examples:\n"
            "  cheatsheet\n"
            "  cheatsheet --output ./cs.pdf\n"
        ),
        handler=_run_cheatsheet,
        suggested_after=(),
        is_deliverable=True,
    ),
    ShellCommandSpec(
        verb="deliver",
        category=_DELIVERABLES_CATEGORY,
        short_help="Generate full Client Deliverable Kit (4 PDFs + ZIP).",
        long_help=(
            "Usage:\n"
            "  deliver [--client NAME] [--engagement CODE] [--output DIR]\n"
            "          [--only SLUGS] [--frameworks ens,iso27001,dora,pci_dss]\n"
            "          [--no-navigator]\n"
            "          [--theme dark|light|premium_dark|corporate_light]\n\n"
            "Generates the four PDFs in parallel and packages them into a single ZIP\n"
            "under the active workspace's deliverables/ folder.\n\n"
            "Inside the shell, the workspace is auto-detected — no flag needed.\n\n"
            "--only:        report, playbook, checklist, coverage-matrix (default: all).\n"
            "--frameworks:  comma-separated compliance set rendered in the kit.\n"
            "               In a TTY a checkbox prompts; non-interactive defaults to 'ens'.\n\n"
            "Examples:\n"
            "  deliver\n"
            "  deliver --client 'Acme Corp' --engagement ENG-001\n"
            "  deliver --theme light                       # corporate white for board/auditor\n"
            "  deliver --theme dark                        # operator dark mode\n"
            "  deliver --only report                       # security assessment PDF only\n"
            "  deliver --frameworks ens,iso27001,dora      # multi-framework compliance kit\n"
        ),
        handler=_run_deliver,
        suggested_after=("start_auth", "start_unauth"),
        is_deliverable=True,
    ),
    ShellCommandSpec(
        verb="mitre_navigator",
        category=_DELIVERABLES_CATEGORY,
        short_help="Export a MITRE ATT&CK Navigator layer (JSON) from the latest scan.",
        long_help=(
            "Usage:\n"
            "  mitre_navigator [--workspace NAME] [--output DIR]\n"
            "                  [--client NAME] [--engagement CODE]\n"
            "                  [--web] [--no-html] [--no-history] [-v]\n\n"
            "Generate a MITRE ATT&CK Navigator v4.5 layer from the latest scan.\n"
            "LITE writes a community-watermarked navigator-layer.json that loads\n"
            "directly in the official MITRE ATT&CK Navigator UI. PRO additionally\n"
            "produces an interactive HTML bundle, a posture diff vs the previous\n"
            "scan, and a history snapshot.\n\n"
            "Inside the shell, the workspace is auto-detected — no flag needed.\n\n"
            "Examples:\n"
            "  mitre_navigator\n"
            "  mitre_navigator --workspace Essos\n"
            "  mitre_navigator --no-html --no-history     # JSON-only (CI)\n"
        ),
        handler=_run_mitre_navigator,
        suggested_after=("start_auth", "start_unauth"),
        is_deliverable=True,
    ),
    # Not flagged as a deliverable and not suggested after a scan: this is a
    # lab artifact, and the post-scan seam already offers it to the population
    # that wants it (``post_scan_report``, lab workspaces only). Putting it in
    # the client deliverables list would push a personal blog draft into an
    # engagement's end-of-scan panel.
    ShellCommandSpec(
        verb="writeup",
        category=_DELIVERABLES_CATEGORY,
        short_help="Write a Markdown evidence spine for a lab writeup (you write the prose).",
        long_help=(
            "Usage:\n"
            "  writeup [OUTPUT_DIR]\n\n"
            "Record the mechanical part of a writeup while it is still on disk:\n"
            "the ports that answered, what the directory held, the chain as a\n"
            "mermaid diagram, every step that ran with its outcome and a public\n"
            "reference for the technique, which credential came from which\n"
            "technique, and the routes that went nowhere.\n\n"
            "It writes no analysis. The paragraphs that carry a writeup are left\n"
            "as marked, empty placeholders for you to fill in.\n\n"
            "The output is a local Markdown draft under the workspace, marked\n"
            "draft in its frontmatter. Nothing is published or uploaded.\n\n"
            "Examples:\n"
            "  writeup\n"
            "  writeup ~/blog/content/posts/certified\n"
        ),
        handler=_run_writeup,
        suggested_after=(),
        is_deliverable=False,
    ),
)


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------


def get_spec(verb: str) -> ShellCommandSpec | None:
    """Return the spec for ``verb``, or ``None`` if not registered."""
    for spec in REGISTRY:
        if spec.verb == verb:
            return spec
    return None


def specs_by_category(category: str) -> tuple[ShellCommandSpec, ...]:
    """Return all registered specs in ``category``, in registration order."""
    return tuple(s for s in REGISTRY if s.category == category)


def deliverables() -> tuple[ShellCommandSpec, ...]:
    """Return all specs flagged ``is_deliverable=True``."""
    return tuple(s for s in REGISTRY if s.is_deliverable)


def specs_suggested_after(verb: str) -> tuple[ShellCommandSpec, ...]:
    """Return specs that should be suggested after ``verb`` succeeds."""
    return tuple(s for s in REGISTRY if verb in s.suggested_after)


def categories() -> tuple[str, ...]:
    """Return the unique categories declared in the registry, preserving order."""
    seen: list[str] = []
    for spec in REGISTRY:
        if spec.category not in seen:
            seen.append(spec.category)
    return tuple(seen)


# ---------------------------------------------------------------------------
# Binder
# ---------------------------------------------------------------------------


def bind_registered_shell_commands(cls: type) -> type:
    """Inject ``do_<verb>`` methods from :data:`REGISTRY` into ``cls``.

    Existing ``do_<verb>`` attributes are never overridden — this keeps the
    binder additive against the 137 hand-rolled commands already on
    :class:`PentestShell`.

    The injected method:
        * forwards the raw arg string to the spec's handler,
        * captures any exception via :mod:`adscan_core.telemetry`,
        * prints a concise error via :func:`print_error` so the shell loop
          stays alive on handler failure,
        * inherits ``long_help`` as its docstring so ``help <verb>`` works.

    Returns:
        The (mutated) ``cls`` — convenient for use as a decorator-style call.
    """
    from adscan_core import telemetry
    from adscan_core.rich_output import print_error

    for spec in REGISTRY:
        method_name = f"do_{spec.verb}"
        if hasattr(cls, method_name):
            continue

        def _make_handler(captured: ShellCommandSpec):
            def _do(self: Any, args: str) -> None:
                try:
                    captured.handler(self, args or "")
                except SystemExit:
                    # argparse exits via SystemExit on bad flags — swallow so
                    # the shell loop keeps running.
                    return
                except Exception as exc:  # noqa: BLE001 — shell loop must survive
                    telemetry.capture_exception(exc)
                    print_exception(exception=exc)
                    print_error(f"Couldn't run {captured.verb}: {exc}")

            _do.__doc__ = captured.long_help
            _do.__name__ = method_name
            return _do

        setattr(cls, method_name, _make_handler(spec))

    return cls


__all__ = [
    "REGISTRY",
    "ShellCommandSpec",
    "bind_registered_shell_commands",
    "categories",
    "deliverables",
    "get_spec",
    "specs_by_category",
    "specs_suggested_after",
]
