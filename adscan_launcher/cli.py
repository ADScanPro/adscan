"""Host-side ADscan launcher CLI.

This CLI is intended for PyPI/GitHub distribution as open source.
It orchestrates Docker to run the real ADscan CLI inside the container image.

Supported commands (host-side):
- install: pull the ADscan runtime image
- check: sanity checks for Docker mode
- start: run interactive container session
- ci: run CI mode inside container
- update/upgrade: update the launcher and pull the latest image
- version: show launcher version

Any other arguments are passed through to the container.
"""

from __future__ import annotations

import argparse
import platform
import re
from io import StringIO
import os
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Callable

from rich.console import Console

from adscan_core.interrupts import emit_interrupt_debug
from adscan_core.theme import ADSCAN_THEME
from adscan_launcher import __version__
from adscan_launcher.docker_commands import (
    get_docker_image_name,
    handle_check_docker,
    handle_install_docker,
    handle_start_docker,
    run_adscan_passthrough_docker,
    normalize_pull_timeout_seconds,
)
from adscan_launcher.docker_runtime import (
    ensure_image_pulled,
    image_exists,
    is_docker_env,
    register_pre_container_exec_hook,
    run_docker,
)
from adscan_launcher.output import (
    confirm_ask,
    print_error,
    print_info,
    print_info_debug,
    print_instruction,
    print_panel,
    print_success,
    print_warning,
    set_output_config,
)
from adscan_launcher.paths import get_state_dir
from adscan_launcher.telemetry import (
    HOST_SESSION_CAPTURE_COMMANDS,
    SESSION_CAPTURE_ALLOWED_COMMANDS,
    capture,
    capture_command_session,
    capture_exception,
    collect_system_context,
)
from adscan_launcher.update_manager import (
    UpdateContext,
    get_local_update_recency_summary,
    is_dev_update_context,
    offer_updates_for_command,
    run_update_command,
)


ADSCAN_SUDO_ALIAS_MARKER = "# ADscan auto-sudo alias"
_SESSION_CAPTURE_FINALIZED = False
_ALLOW_UNSUPPORTED_PLATFORM_ENV = "ADSCAN_ALLOW_UNSUPPORTED_PLATFORM"
_ALLOW_UNSUPPORTED_ARCH_ENV = "ADSCAN_ALLOW_UNSUPPORTED_ARCH"
_ALLOW_UNSUPPORTED_WSL_ENV = "ADSCAN_ALLOW_UNSUPPORTED_WSL"
# Host architectures for which multi-arch runtime images are published (see
# scripts/build_docker_lite_image.sh --multiarch + Dockerfile TARGETARCH).
# x86_64/amd64 and arm64/aarch64 (Apple-Silicon Macs, Graviton, arm64 Linux)
# have native image variants; Docker auto-selects the right one on pull.
_SUPPORTED_HOST_ARCHES = frozenset({"x86_64", "amd64", "arm64", "aarch64"})
# Host operating systems the launcher supports in Docker mode. Linux runs
# containers on the host network namespace directly; macOS (Darwin) runs them
# inside Docker Desktop's Linux VM over bridge/NAT (see docker_runtime
# `_host_uses_network_host`). Windows remains unsupported (WSL is blocked
# separately below).
_SUPPORTED_HOST_PLATFORMS = frozenset({"linux", "darwin"})
# One-time guard so the macOS networking caveat is printed at most once per
# launcher invocation.
_MACOS_CAVEAT_SHOWN = False
_LINUX_REQUIRED_COMMANDS = {
    "install",
    "check",
    "start",
    "ci",
    "update",
    "upgrade",
    "host-helper",
}
_KNOWN_LAUNCHER_COMMANDS = {
    "install",
    "check",
    "start",
    "tui",
    "ci",
    "demo",
    "update",
    "upgrade",
    "version",
    "welcome",
}

# Deliverable subcommands handled as host-side passthrough (Pass C). Each is
# routed through the PRO upsell gate (`_run_pro_passthrough_with_upsell_gate`)
# so PRO-only deliverables render the canonical upsell panel on exit-42.
# LITE deliverables (``cheatsheet``, ``mitre-navigator``) run to completion
# in the container and return 0 — the gate is a no-op for them because they
# are not in ``PRO_ONLY_COMMANDS``.
_DELIVERABLE_PASSTHROUGH_COMMANDS = {
    "deliver",
    "cheatsheet",
    "mitre-navigator",
}


def _remove_legacy_adscan_sudo_alias(rcfile: str) -> bool:
    """Remove the legacy ADscan auto-sudo alias from a shell rc file (best-effort)."""
    try:
        path = Path(rcfile)
        if not path.exists():
            return False
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        changed = False
        new_lines: list[str] = []

        idx = 0
        while idx < len(lines):
            line = lines[idx]
            if line.strip() == ADSCAN_SUDO_ALIAS_MARKER.strip():
                next_idx = idx + 1
                if next_idx < len(lines) and lines[next_idx].lstrip().startswith(
                    "alias adscan='sudo -E "
                ):
                    changed = True
                    idx += 2
                    continue
            new_lines.append(line)
            idx += 1

        if not changed:
            return False

        path.write_text("".join(new_lines), encoding="utf-8")
        return True
    except Exception:
        return False


def _cleanup_legacy_sudo_alias() -> None:
    """Best-effort removal of the legacy auto-sudo alias from user shell configs."""
    is_sudo = "SUDO_USER" in os.environ
    if os.geteuid() == 0 and is_sudo:
        target_user = os.environ.get("SUDO_USER")
    else:
        target_user = os.environ.get("USER")

    home = (
        os.path.expanduser(f"~{target_user}")
        if target_user
        else os.path.expanduser("~")
    )
    shell = os.environ.get("SHELL", "")
    if "zsh" in shell:
        rcfiles = [os.path.join(home, ".zshrc")]
    else:
        rcfiles = [os.path.join(home, ".bash_aliases"), os.path.join(home, ".bashrc")]

    for rcfile in rcfiles:
        _remove_legacy_adscan_sudo_alias(rcfile)


class _DeliverablesAwareParser(argparse.ArgumentParser):
    """Argparse parser that appends a tiered Deliverables section to --help.

    The deliverable subcommands (``deliver``, ``cheatsheet``,
    ``mitre-navigator``) already register their own ``help`` strings with
    ``[PRO]`` / ``[LITE]`` badges, but argparse renders all subcommands as a
    single flat block. This override appends a clearly titled section after
    the default help, split into two groups — LITE (free) first, then PRO —
    so operators can see the deliverables family at a glance and the free
    offers are never undersold.
    """

    def format_help(self) -> str:  # type: ignore[override]
        base = super().format_help()
        try:
            from adscan_core.cli_catalog import (
                DELIVERABLE_COMMAND_ORDER as _DELIV_ORDER,
                tier_for_command as _tier_for_command,
            )
        except Exception:  # noqa: BLE001 — defensive: never break --help
            return base

        descriptions: dict[str, str] = {
            "deliver":         "Full Client Deliverable Kit (4 PDFs + ZIP)",
            "cheatsheet":      "Pentester Cheatsheet PDF",
            "mitre-navigator": "MITRE ATT&CK Navigator layer (JSON)",
        }

        # Bucket each deliverable by its tier (driven by the catalog, never
        # hardcoded) while preserving the stable display order.
        buckets: dict[str, list[str]] = {"LITE": [], "PRO": []}
        for name in _DELIV_ORDER:
            buckets.setdefault(_tier_for_command(name), []).append(name)

        groups = (
            ("LITE", "Deliverables — LITE (free)"),
            ("PRO", "Deliverables — PRO"),
        )

        lines: list[str] = []
        for tier_key, header in groups:
            names = buckets.get(tier_key) or []
            if not names:
                continue
            lines.append("")
            lines.append(header)
            for name in names:
                badge = f"[{_tier_for_command(name)}]"
                desc = descriptions.get(name, name)
                lines.append(f"  {name:<18} {desc:<43} {badge}")
        if not lines:
            return base
        return base + "\n".join(lines) + "\n"


def _build_parser() -> argparse.ArgumentParser:
    parser = _DeliverablesAwareParser(prog="adscan", add_help=True)
    parser.add_argument(
        "--version",
        action="store_true",
        help="Show launcher version and Docker image configuration.",
    )
    parser.add_argument(
        "--image",
        help="Override the ADscan Docker image (defaults to env ADSCAN_DOCKER_IMAGE or channel).",
        default=None,
    )
    parser.add_argument(
        "--channel",
        choices=["stable", "dev"],
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output (launcher + forwarded to container subcommands where applicable).",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output (launcher + forwarded to container subcommands where applicable).",
    )
    parser.add_argument(
        "--dev",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    # Top-level twin of the subcommand --no-update-check (defined on
    # update_check_parent below). Declaring it here too lets the flag be used as
    # a PREFIX before ANY command — including the container passthroughs `doctor`
    # / `execute`, which are argparse.REMAINDER and would otherwise forward the
    # flag verbatim to the in-container engine ("unrecognized arguments:
    # --no-update-check"). The air-gapped appliance relies on exactly this: it
    # sets ADSCAN_CLI_PATH="adscan --no-update-check" as a universal prefix
    # (appliance-celery.sh), so EVERY launched command (ci, doctor, ...) must
    # accept it at the top level and have the launcher consume it (skip the
    # PyPI/Docker-Hub probe) instead of leaking it into the container.
    parser.add_argument(
        "--no-update-check",
        action="store_true",
        dest="no_update_check",
        default=False,
        help=(
            "Skip the launcher/runtime version probe and update prompts (no "
            "PyPI / Docker Hub call). Usable as a prefix before any command, "
            "including container passthroughs. Mid-engagement / airgapped / "
            "version-pinned use only."
        ),
    )
    # ``metavar="command"`` keeps the usage synopsis to ``adscan ... command``
    # (follows the convention used by `git`, `gh`, `docker`) so subcommands
    # we want to hide (e.g. the work-in-progress ``tui``) don't leak into
    # the curly-brace choices list at the top of ``--help``.
    sub = parser.add_subparsers(dest="command", required=False, metavar="command")

    install = sub.add_parser("install", help="Install ADscan (Docker mode)")
    install.add_argument(
        "--pull-timeout",
        type=int,
        default=3600,
        help="Docker pull timeout in seconds for the ADscan runtime image pull (0 disables). Default: 3600.",
    )
    install.add_argument(
        "--allow-low-memory",
        action="store_true",
        help=(
            "Allow install to continue when available RAM is critically low "
            "(below 1.0 GB). Use only for constrained environments."
        ),
    )

    # Shared update-check flag. Used by every subcommand whose dispatch
    # path runs ``offer_updates_for_command``. Defined once on a parent
    # parser instead of duplicated three times so the help text stays in
    # one place. The intent:
    #
    # --no-update-check  user-facing escape hatch. Skips the launcher
    #                    + image version probe entirely (no PyPI / Docker
    #                    Hub call). Reserved for mid-engagement, airgapped
    #                    runs, or version-pinning by procurement. Tier 3
    #                    "critical" detection still emits a non-blocking
    #                    note so the operator does not forget they are
    #                    running an unsupported combination.
    #
    # The complementary ``--dev`` flag already exists at the top-level
    # parser (it sets ``ADSCAN_DOCKER_CHANNEL=dev``). Dev-mode launches
    # skip update checks via ``is_dev_update_context`` automatically — no
    # additional flag at this layer is needed, and adding one would create
    # a confusing dual `--dev` (one before the subcommand, one after).
    update_check_parent = argparse.ArgumentParser(add_help=False)
    update_check_parent.add_argument(
        "--no-update-check",
        action="store_true",
        dest="no_update_check",
        # SUPPRESS so this subcommand-level copy never WRITES the dest when the
        # flag is absent — otherwise `adscan --no-update-check ci` (prefix form)
        # would have the top-level True reset to the subparser default False.
        # The top-level twin (above) owns the default; this copy only flips it
        # True when the flag is typed AFTER the verb (`adscan ci --no-update-check`).
        default=argparse.SUPPRESS,
        help=(
            "Skip the launcher/runtime version probe and update prompts for "
            "this run. Use only when you intentionally want to stay on the "
            "current version (mid-engagement, airgapped, pinned for a "
            "customer requirement)."
        ),
    )

    check = sub.add_parser(
        "check",
        help="Check Docker-mode prerequisites",
        parents=[update_check_parent],
    )
    check.add_argument(
        "--allow-low-memory",
        action="store_true",
        help=(
            "Allow checks to continue when available RAM is critically low "
            "(below 1.0 GB)."
        ),
    )

    start = sub.add_parser(
        "start",
        help="Start ADscan interactive session",
        parents=[update_check_parent],
    )
    start.add_argument(
        "--pull-timeout",
        type=int,
        default=3600,
        help="Docker pull timeout in seconds for the ADscan runtime image pull (0 disables). Default: 3600.",
    )
    start.add_argument(
        "--allow-low-memory",
        action="store_true",
        help=(
            "Allow start to continue when available RAM is critically low "
            "(below 1.0 GB)."
        ),
    )
    # `--tui` and the top-level `tui` subcommand are intentionally hidden
    # from --help while the Textual workbench is under active development.
    # Routing is preserved so anyone who knows the verb can still invoke
    # it, but it is not advertised on any user-facing surface (welcome
    # cards, --help listing) until the workbench is production-ready.
    start.add_argument(
        "--tui",
        action="store_true",
        help=argparse.SUPPRESS,
    )

    tui = sub.add_parser(
        "tui",
        help=argparse.SUPPRESS,
    )
    # Note: the help-listing entry for ``tui`` is dropped in the final
    # ``_drop_suppressed_choices`` call below (Python <3.12 renders
    # ``argparse.SUPPRESS`` on a subparser literally rather than hiding it).
    tui.add_argument(
        "--pull-timeout",
        type=int,
        default=3600,
        help="Docker pull timeout in seconds. Default: 3600.",
    )
    tui.add_argument(
        "--allow-low-memory",
        action="store_true",
        help=(
            "Allow tui to continue when available RAM is critically low "
            "(below 1.0 GB)."
        ),
    )
    tui.add_argument(
        "--demo",
        action="store_true",
        help="Boot the workbench on top of the deterministic demo workspace.",
    )

    ci = sub.add_parser(
        "ci",
        help="[EXPERIMENTAL] Run ADscan in autonomous mode (no prompts, end-to-end automated scan)",
        parents=[update_check_parent],
        description=(
            "EXPERIMENTAL · BETA — Autonomous scan mode.\n\n"
            "`adscan ci` launches ADscan in fully non-interactive mode: sensible "
            "defaults are applied, every confirmation prompt is skipped, and the "
            "complete scan pipeline (preflight → recon → enumeration → "
            "exploitation → reporting) runs end-to-end without operator input.\n\n"
            "Intended for CI/CD pipelines, automated lab validation (HTB/GOAD), "
            "and unattended engagements where a human is not available to drive "
            "the interactive shell.\n\n"
            "STATUS — Beta. Behaviour, defaults, and output format may change "
            "between releases. The interactive `adscan start` shell is the "
            "supported production path; `adscan ci` is the automation companion "
            "and is graduating from experimental as confidence in the autonomous "
            "decisions accumulates.\n\n"
            "If autonomous decisions look wrong on your engagement, re-run with "
            "`--debug` and report the trace at https://adscanpro.com/docs."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ci.add_argument(
        "--pull-timeout",
        type=int,
        default=3600,
        help="Docker pull timeout in seconds for the ADscan runtime image pull (0 disables). Default: 3600.",
    )
    ci.add_argument(
        "--allow-low-memory",
        action="store_true",
        help=(
            "Allow CI preflight to continue when available RAM is critically low "
            "(below 1.0 GB). Place this before CI passthrough args."
        ),
    )
    # Engagement-posture toggles. These are translated into container environment
    # variables at the launcher seam (see run_adscan_passthrough_docker), NOT
    # forwarded verbatim as `adscan ci` args, because the internal runtime honours
    # them through env (ADSCAN_OFFLINE for the weakpass/no-external guard,
    # ADSCAN_TELEMETRY=0 for the telemetry opt-out). They are the CLI half of the
    # web Settings tab's two toggles; the Celery builder appends them for the
    # matching scan-config booleans. Place them BEFORE the CI passthrough args
    # (argparse.REMAINDER stops parsing flags at the first positional); the seam
    # also rescues them if they appear later in the passthrough, so order is
    # forgiving for operators.
    ci.add_argument(
        "--offline",
        action="store_true",
        help=(
            "Offline mode: disable every external lookup (weakpass / no-external "
            "guard) for air-gapped or sovereign engagements. Sets ADSCAN_OFFLINE=1 "
            "inside the scan container."
        ),
    )
    ci.add_argument(
        "--no-telemetry",
        action="store_true",
        dest="no_telemetry",
        help=(
            "Disable anonymous usage telemetry for this run (sensitive "
            "engagements). Sets ADSCAN_TELEMETRY=0 inside the scan container."
        ),
    )
    ci.add_argument(
        "--scan-config",
        dest="scan_config",
        default=None,
        help=(
            "Path to a YAML/JSON scan-configuration file that pre-configures the "
            "scan (disable optional phases, set the trust-enumeration and "
            "attack-path policies). Absent = today's interactive defaults. The "
            "file is bind-mounted read-only into the scan container. Place it "
            "before the auth/unauth positional."
        ),
    )
    ci.add_argument(
        "args",
        nargs=argparse.REMAINDER,
        help="Arguments passed to the container after `ci`",
    )

    demo = sub.add_parser(
        "demo",
        help="Run a deterministic 60-second demo scan and produce a real PDF.",
    )
    demo.add_argument(
        "--fast",
        action="store_true",
        help="Compress phase pacing to ~12s (CI / marketing capture).",
    )
    demo.add_argument(
        "--no-pdf",
        action="store_true",
        help="Skip PDF generation (headless smoke).",
    )
    demo.add_argument(
        "--output",
        dest="output_path",
        default=None,
        help="Override the output PDF path.",
    )
    demo.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for jitter (default: 42).",
    )

    # ── adscan execute / doctor — container passthrough ───────────────
    # Both run inside the container (the container owns the REPL engine and
    # the preflight/auth/posture bootstrap). The launcher only needs to (a)
    # recognise the verb so it surfaces in --help and (b) forward every
    # remaining token verbatim through run_adscan_passthrough_docker. The
    # container-side subparser (cli/execute.py, cli/doctor.py) is the single
    # source of truth for the flag surface, so the launcher uses a permissive
    # REMAINDER catch-all and never re-declares the flags (no drift).
    execute_p = sub.add_parser(
        "execute",
        help="Run a single REPL command non-interactively (scripting / smoke-test).",
    )
    execute_p.add_argument(
        "execute_args",
        nargs=argparse.REMAINDER,
        help="Verb and arguments forwarded to the container (see `adscan execute --list`).",
    )
    doctor_p = sub.add_parser(
        "doctor",
        help="Fast one-shot health check (DNS, connectivity, auth, posture).",
    )
    doctor_p.add_argument(
        "doctor_args",
        nargs=argparse.REMAINDER,
        help="Arguments forwarded to the container health check.",
    )

    # ── Client Deliverables (Pass C) — passthrough into container ─────
    # Tier badges come from `adscan_core.cli_catalog` so the launcher and
    # the container dispatcher agree on which commands are PRO-only.
    from adscan_core.cli_catalog import (
        DELIVERABLE_COMMAND_ORDER as _DELIV_ORDER,
        tier_for_command as _tier_for_command,
    )

    _DELIVERABLE_HELP: dict[str, str] = {
        "deliver":         "Generate full Client Deliverable Kit (4 PDFs + ZIP)",
        "cheatsheet":      "Pentester Cheatsheet PDF",
        "mitre-navigator": "MITRE ATT&CK Navigator layer (JSON)",
    }

    for _deliv_name in _DELIV_ORDER:
        _badge = f"[{_tier_for_command(_deliv_name)}]"
        _deliv_help = f"{_DELIVERABLE_HELP[_deliv_name]}  {_badge}"
        _deliv_p = sub.add_parser(_deliv_name, help=_deliv_help)
        if _deliv_name == "mitre-navigator":
            # The MITRE ATT&CK Navigator export (LITE deliverable) has a
            # distinct flag surface from the PDF deliverables: ``--output`` is
            # a directory (not a PDF path) and there is no --no-open/--no-render.
            # The launcher only needs to (a) recognise the flags so
            # ``adscan mitre-navigator --help`` lists them and (b) forward them
            # verbatim through the passthrough block below. Mirror this set with
            # the container subparser in ``adscan_internal/cli/mitre_navigator``.
            _deliv_p.add_argument(
                "--workspace", dest="nav_workspace", default=None,
                metavar="NAME",
                help="Workspace name or path (default: most recent).",
            )
            _deliv_p.add_argument(
                "--output", dest="nav_output", default=None,
                metavar="DIR",
                help="Output directory (default: <workspace>/mitre/).",
            )
            _deliv_p.add_argument(
                "--client", dest="nav_client", default=None,
                metavar="NAME",
                help="Client name embedded in the report header (PRO).",
            )
            _deliv_p.add_argument(
                "--engagement", dest="nav_engagement", default=None,
                metavar="CODE",
                help="Engagement code embedded as layer metadata (PRO).",
            )
            _deliv_p.add_argument(
                "--web", dest="nav_web", action="store_true",
                help="Open the generated interactive HTML in the browser (PRO).",
            )
            _deliv_p.add_argument(
                "--no-html", dest="nav_no_html", action="store_true",
                help="Skip the interactive HTML bundle, JSON only (PRO).",
            )
            _deliv_p.add_argument(
                "--no-history", dest="nav_no_history", action="store_true",
                help="Do not snapshot the layer into the workspace history (PRO).",
            )
            _deliv_p.add_argument(
                "-v", "--verbose", dest="nav_verbose", action="store_true",
                help="Enable verbose mode for detailed informational output.",
            )
            continue
        _deliv_p.add_argument("--output", dest="output_path", default=None,
                              help="Override the output PDF path.")
        _deliv_p.add_argument("--no-open", action="store_true",
                              help="Do not prompt to open the PDF.")
        _deliv_p.add_argument("--no-render", action="store_true",
                              help="Smoke / dry-run only — skip PDF render.")
        if _deliv_name == "deliver":
            _deliv_p.add_argument(
                "--theme",
                dest="theme",
                default="",
                choices=["", "dark", "premium_dark", "light", "corporate_light"],
                help=(
                    "Report theme. 'dark'/'premium_dark' = operator dark mode. "
                    "'light'/'corporate_light' = corporate white (for printing/board). "
                    "Default: env var ADSCAN_PDF_THEME or system default."
                ),
            )
            # The remaining flags are interpreted inside the container. The
            # launcher only needs to (a) recognise them so ``adscan deliver
            # --help`` lists them and (b) forward them verbatim through the
            # passthrough below. New flags added in deliver.py also need a
            # one-line entry both here and in the forwarding block.
            _deliv_p.add_argument(
                "--workspace", dest="ws_workspace", default=None,
                help="Workspace name or path (default: prompt or most-recent).",
            )
            _deliv_p.add_argument(
                "--client", dest="ws_client", default=None,
                help="Client name embedded in the kit metadata.",
            )
            _deliv_p.add_argument(
                "--engagement", dest="ws_engagement", default=None,
                help="Engagement code embedded in the kit metadata.",
            )
            _deliv_p.add_argument(
                "--only", dest="ws_only", default=None,
                help=(
                    "Comma-separated deliverables: "
                    "report, playbook, checklist, coverage-matrix."
                ),
            )
            _deliv_p.add_argument(
                "--frameworks", dest="ws_frameworks", default=None,
                help=(
                    "Comma-separated compliance frameworks: "
                    "ens, nis2, iso27001, dora, pci_dss. "
                    "Default: none — pick the regimes that apply."
                ),
            )
            _deliv_p.add_argument(
                "--no-navigator", dest="ws_no_navigator", action="store_true",
                help="Skip the MITRE ATT&CK Navigator extras in the ZIP.",
            )
            _deliv_p.add_argument(
                "--report-theme", dest="ws_report_theme", default="",
                help="Legacy alias for --theme (kept for back-compat).",
            )

    upd = sub.add_parser(
        "update", help="Update the launcher (pip) and pull the latest ADscan image"
    )
    upd.add_argument(
        "--pull-timeout",
        type=int,
        default=3600,
        help="Docker pull timeout in seconds (0 disables). Default: 3600.",
    )

    upg = sub.add_parser("upgrade", help="Alias of update")
    upg.add_argument(
        "--pull-timeout",
        type=int,
        default=3600,
        help="Docker pull timeout in seconds (0 disables). Default: 3600.",
    )

    sub.add_parser("version", help="Show launcher version")

    sub.add_parser(
        "welcome",
        help="Show the editorial welcome screen (default with no command).",
    )

    # Internal-only command used by the host launcher to run the privileged
    # helper process required by container runtime features (notably host
    # clock sync — Kerberos AS-REQ rejects requests outside a 5-minute skew
    # window). Hidden from end users.
    host_helper = sub.add_parser("host-helper", help=argparse.SUPPRESS)
    host_helper.add_argument(
        "--socket",
        required=True,
        help=argparse.SUPPRESS,
    )

    # Final pass: strip any subparser entry whose ``help`` was set to
    # ``argparse.SUPPRESS`` from the help-formatter's choices listing.
    # Python <3.12 renders the literal "==SUPPRESS==" sentinel instead of
    # hiding the entry (bpo-44793). Applies to ``tui`` (work-in-progress)
    # and ``host-helper`` (internal-only). Safe to run unconditionally —
    # popping a non-existent dest is a no-op.
    _drop_suppressed_choices(sub, {"tui", "host-helper"})

    return parser


def _drop_suppressed_choices(subparsers_action, dests: set[str]) -> None:
    """Pop entries from a subparsers action's help-listing by ``dest``.

    Workaround for Python <3.12 where ``help=argparse.SUPPRESS`` on
    ``add_parser`` renders the literal sentinel instead of hiding the
    entry. The dispatch path is untouched — only the help formatter's
    side-table is mutated.
    """
    choices_actions = getattr(subparsers_action, "_choices_actions", None)
    if not choices_actions:
        return
    for action in list(choices_actions):
        if getattr(action, "dest", None) in dests:
            choices_actions.remove(action)


def _apply_image_overrides(args: argparse.Namespace) -> None:
    if getattr(args, "image", None):
        os.environ["ADSCAN_DOCKER_IMAGE"] = str(args.image)
    if getattr(args, "channel", None):
        os.environ["ADSCAN_DOCKER_CHANNEL"] = "dev" if args.channel == "dev" else ""
    if getattr(args, "dev", False):
        os.environ["ADSCAN_DOCKER_CHANNEL"] = "dev"


def _consume_trailing_global_flags(
    ns: argparse.Namespace, unknown: list[str]
) -> list[str]:
    """Consume global launcher flags that appear after a known subcommand.

    `argparse` only applies top-level options reliably when they are placed
    before the subcommand (e.g., `adscan --debug start`). Users often type
    `adscan start --debug`; for known launcher commands we normalize both forms.
    """
    cmd = str(getattr(ns, "command", "") or "")
    low_memory_supported_cmds = {"install", "check", "start", "ci"}
    # Deliverable passthrough commands (deliver/cheatsheet) also need
    # trailing global flags (--dev, --debug, --verbose, --image) consumed,
    # otherwise typing `adscan deliver --dev` silently falls through to
    # the prod image because `--dev` never reaches _apply_image_overrides.
    if cmd not in (_KNOWN_LAUNCHER_COMMANDS | _DELIVERABLE_PASSTHROUGH_COMMANDS):
        return unknown

    remaining: list[str] = []
    idx = 0
    while idx < len(unknown):
        token = unknown[idx]

        if token == "--verbose":
            setattr(ns, "verbose", True)
            idx += 1
            continue
        if token == "--debug":
            setattr(ns, "debug", True)
            idx += 1
            continue
        if token == "--dev":
            setattr(ns, "dev", True)
            idx += 1
            continue
        if token == "--allow-low-memory" and cmd in low_memory_supported_cmds:
            setattr(ns, "allow_low_memory", True)
            idx += 1
            continue
        if token == "--tui" and cmd == "start":
            setattr(ns, "tui", True)
            idx += 1
            continue
        if token == "--demo" and cmd == "tui":
            setattr(ns, "demo", True)
            idx += 1
            continue
        if token.startswith("--image="):
            setattr(ns, "image", token.split("=", 1)[1])
            idx += 1
            continue
        if token == "--image" and idx + 1 < len(unknown):
            setattr(ns, "image", unknown[idx + 1])
            idx += 2
            continue
        if token.startswith("--channel="):
            setattr(ns, "channel", token.split("=", 1)[1])
            idx += 1
            continue
        if token == "--channel" and idx + 1 < len(unknown):
            setattr(ns, "channel", unknown[idx + 1])
            idx += 2
            continue
        remaining.append(token)
        idx += 1

    return remaining


def _consume_ci_remainder_global_flags(ns: argparse.Namespace) -> None:
    """Consume launcher-global flags from `ci` remainder args.

    For `adscan ci`, argparse stores everything after `ci` in `ns.args`
    (`argparse.REMAINDER`), so trailing launcher flags (e.g. `--debug --dev`)
    never appear in `unknown`.

    If the remainder starts with `--`, treat it as an explicit passthrough
    separator and leave tokens untouched.
    """
    if str(getattr(ns, "command", "") or "") != "ci":
        return

    remainder = list(getattr(ns, "args", []) or [])
    if not remainder or remainder[0] == "--":
        return

    setattr(ns, "args", _consume_trailing_global_flags(ns, remainder))


def _ci_posture_env_from_flags(
    ns: argparse.Namespace, passthrough: list[str]
) -> tuple[list[tuple[str, str]], list[str]]:
    """Translate the `ci` engagement-posture flags into container env vars.

    The two Settings-tab toggles (``--offline`` / ``--no-telemetry``) are
    interpreted at the launcher seam rather than forwarded as `adscan ci`
    arguments, because the internal runtime honours them via environment:

    - ``--offline``      -> ``ADSCAN_OFFLINE=1`` (weakpass / no-external guard,
      ``weakpass_service.offline_mode_enabled``).
    - ``--no-telemetry`` -> ``ADSCAN_TELEMETRY=0`` (telemetry opt-out,
      ``adscan_core.telemetry``).

    Both the parsed namespace attributes (set when the flag precedes the
    auth/unauth positional) AND the raw passthrough list are inspected, so a
    token that landed after the positional (past ``argparse.REMAINDER``'s
    flag cut-off) still takes effect. Recognised tokens are removed from the
    returned passthrough so they never reach the container's own parser.

    Returns:
        A ``(extra_env, cleaned_passthrough)`` tuple. ``extra_env`` is a list
        of ``(key, value)`` pairs suitable for ``DockerRunConfig.extra_env``;
        empty when neither toggle is active (default behaviour unchanged).
    """
    offline = bool(getattr(ns, "offline", False))
    no_telemetry = bool(getattr(ns, "no_telemetry", False))

    cleaned: list[str] = []
    for token in passthrough:
        if token == "--offline":
            offline = True
            continue
        if token == "--no-telemetry":
            no_telemetry = True
            continue
        cleaned.append(token)

    extra_env: list[tuple[str, str]] = []
    if offline:
        extra_env.append(("ADSCAN_OFFLINE", "1"))
    if no_telemetry:
        extra_env.append(("ADSCAN_TELEMETRY", "0"))

    return extra_env, cleaned


# Container path the scan-config file is bind-mounted at. Fixed (not under the
# workspace tree) so the engine resolves it the same way regardless of where the
# host file lives. Read-only.
_CI_SCAN_CONFIG_CONTAINER_PATH = "/opt/adscan/state/scan-config.in"


def _ci_scan_config_from_flags(
    ns: argparse.Namespace, passthrough: list[str]
) -> tuple[list[tuple[str, str]], list[tuple[str, str]], list[str]]:
    """Translate ``--scan-config <path>`` into a container env var + RO mount.

    The scan-config file lives on the HOST and must be readable INSIDE the
    container. Rather than require it under the standard mounted tree, the
    launcher bind-mounts it read-only at a fixed container path and tells the
    engine where to find it via ``ADSCAN_SCAN_CONFIG`` (read by
    ``adscan_internal.cli.ci``). Like the posture toggles, the flag is consumed
    at the launcher seam and stripped from the passthrough so it never reaches
    the container's own ``ci`` parser.

    Both the parsed namespace attribute (set when the flag precedes the
    auth/unauth positional) AND the raw passthrough list are inspected, so a
    token that landed after the positional (past ``argparse.REMAINDER``'s flag
    cut-off) still takes effect.

    Returns:
        ``(extra_env, extra_mounts, cleaned_passthrough)``. ``extra_env`` and
        ``extra_mounts`` are empty when no ``--scan-config`` was given (default
        behaviour unchanged). Exits non-zero via ``raise SystemExit`` when the
        referenced file does not exist (fail loud, never silently ignore).
    """
    host_path = getattr(ns, "scan_config", None)

    cleaned: list[str] = []
    index = 0
    tokens = list(passthrough)
    while index < len(tokens):
        token = tokens[index]
        if token == "--scan-config":
            if index + 1 < len(tokens):
                host_path = tokens[index + 1]
                index += 2
                continue
            print_error("--scan-config requires a file path argument.")
            raise SystemExit(2)
        if token.startswith("--scan-config="):
            host_path = token.split("=", 1)[1]
            index += 1
            continue
        cleaned.append(token)
        index += 1

    if not host_path:
        return [], [], cleaned

    resolved = os.path.abspath(os.path.expanduser(str(host_path)))
    if not os.path.isfile(resolved):
        print_error(f"Scan config file not found: {resolved}")
        raise SystemExit(2)

    extra_env = [("ADSCAN_SCAN_CONFIG", _CI_SCAN_CONFIG_CONTAINER_PATH)]
    extra_mounts = [(resolved, _CI_SCAN_CONFIG_CONTAINER_PATH)]
    return extra_env, extra_mounts, cleaned


def _apply_host_posture_env(ns: argparse.Namespace, raw_argv: list[str]) -> None:
    """Gate the LAUNCHER's OWN telemetry when a ``ci`` run opts out.

    ``_ci_posture_env_from_flags`` configures the scan CONTAINER, but the host
    launcher independently drains the telemetry queue and uploads its own
    preflight recording (both gated by the launcher process's environment, not
    the container's). Without this, ``adscan ci --no-telemetry`` / ``--offline``
    from a plain CLI host would still replay queued telemetry and upload the
    launcher session. We therefore set the launcher process environment BEFORE
    the queue drain runs, so ``adscan_core.offline.offline_mode_enabled`` and
    ``_is_telemetry_enabled`` observe the opt-out.

    Flags are read from both the parsed namespace and the raw argv (a token can
    land past ``argparse.REMAINDER``'s flag cut-off). Offline implies no
    telemetry (``ADSCAN_OFFLINE=1`` disables telemetry via the adscan_core
    offline SSOT), so it is sufficient on its own.
    """
    offline = bool(getattr(ns, "offline", False)) or "--offline" in raw_argv
    no_telemetry = (
        bool(getattr(ns, "no_telemetry", False)) or "--no-telemetry" in raw_argv
    )
    if offline:
        os.environ["ADSCAN_OFFLINE"] = "1"
    if no_telemetry:
        os.environ["ADSCAN_TELEMETRY"] = "0"


def _should_print_debug_enabled_banner(command: str | None) -> bool:
    """Return whether launcher should emit the debug-enabled confirmation."""
    return command in (None, "start", "ci", "install", "check")


def _should_emit_system_context(command: str | None) -> bool:
    """Return whether launcher should emit system-context diagnostics."""
    return command in {"install", "start", "ci", "update", "upgrade"}


def _emit_launcher_privilege_context(command: str | None) -> None:
    """Emit launcher privilege/sudo context for troubleshooting."""
    try:
        is_root = os.geteuid() == 0
        has_sudo_user = bool(os.getenv("SUDO_USER"))
        has_sudo_uid = bool(os.getenv("SUDO_UID"))
        has_sudo_gid = bool(os.getenv("SUDO_GID"))
        has_adscan_home = bool(os.getenv("ADSCAN_HOME"))
        has_ci = bool(os.getenv("CI"))
        is_container_runtime = os.getenv("ADSCAN_CONTAINER_RUNTIME") == "1"
        is_sudo_invocation = has_sudo_user or has_sudo_uid or has_sudo_gid
        # Best-effort heuristic for root shells entered via `sudo su` / `su -`.
        # We avoid storing usernames/paths and only capture boolean context.
        likely_sudo_su_shell = (
            is_root and not is_sudo_invocation and not has_adscan_home and not has_ci
        )
        context = {
            "command_type": str(command or ""),
            "is_root": is_root,
            "is_low_priv_user": not is_root,
            "is_sudo_invocation": is_sudo_invocation,
            "likely_sudo_su_shell": likely_sudo_su_shell,
            "has_sudo_user": has_sudo_user,
            "has_sudo_uid": has_sudo_uid,
            "has_sudo_gid": has_sudo_gid,
            "has_adscan_home": has_adscan_home,
            "has_ci": has_ci,
            "is_container_runtime": is_container_runtime,
            "root_without_user_context": is_root
            and not is_sudo_invocation
            and not has_adscan_home,
        }
        print_info_debug(f"Launcher privilege context: {context}")
        capture("launcher_privilege_context", context)
    except Exception as exc:  # pragma: no cover - best effort only
        capture_exception(exc)


def _guard_root_shell_without_user_context(command: str | None) -> None:
    """Block accidental root-shell state split unless operator explicitly confirms.

    Running launcher commands from a root shell created via `sudo su` / `su -`
    commonly drops `SUDO_USER`, so launcher state can drift into `/root/.adscan`.
    """
    if command not in {"install", "start", "check"}:
        return
    if os.geteuid() != 0:
        return
    if os.getenv("CI"):
        return
    if os.getenv("SUDO_USER"):
        return
    if os.getenv("ADSCAN_HOME"):
        return

    message = (
        "ADscan launcher is running as root, but without SUDO_USER/ADSCAN_HOME context.\n\n"
        "This usually happens with `sudo su` or `su -` and can create state under `/root/.adscan`,\n"
        "causing later permission and consistency issues.\n\n"
        "Recommended:\n"
        "  1) Exit the root shell\n"
        "  2) Run ADscan as your normal user (without sudo)\n\n"
        "Advanced alternative:\n"
        "  Set ADSCAN_HOME explicitly before running as root."
    )
    print_panel(
        message,
        title="Root Shell Detected",
        border_style="yellow",
    )
    proceed = confirm_ask("Continue anyway (not recommended)?", default=False)
    if not proceed:
        print_warning("Aborted to avoid creating launcher state under /root.")
        raise SystemExit(1)


def _allow_unsupported_platform_override() -> bool:
    """Return True when unsupported-platform guard is explicitly bypassed."""
    raw = str(os.getenv(_ALLOW_UNSUPPORTED_PLATFORM_ENV, "")).strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _allow_unsupported_arch_override() -> bool:
    """Return True when unsupported-arch guard is explicitly bypassed."""
    raw = str(os.getenv(_ALLOW_UNSUPPORTED_ARCH_ENV, "")).strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _allow_unsupported_wsl_override() -> bool:
    """Return True when unsupported-WSL guard is explicitly bypassed."""
    raw = str(os.getenv(_ALLOW_UNSUPPORTED_WSL_ENV, "")).strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _is_windows_subsystem_for_linux() -> bool:
    """Return True when launcher appears to be running inside WSL."""
    release = str(platform.release() or "").strip().lower()
    version_text = str(platform.version() or "").strip().lower()
    if "microsoft" in release or "microsoft" in version_text:
        return True
    if os.getenv("WSL_INTEROP", "").strip():
        return True
    if os.getenv("WSL_DISTRO_NAME", "").strip():
        return True
    return False


def _warn_macos_networking_caveat() -> None:
    """Warn once that broadcast poisoning is unavailable on macOS Docker Desktop.

    On macOS the container runs inside Docker Desktop's Linux VM, so it cannot
    reach the Mac's own network interface at Layer 2. Routed scanning works over
    NAT; broadcast poisoning does not. Tell the operator plainly, once.
    """
    global _MACOS_CAVEAT_SHOWN
    if _MACOS_CAVEAT_SHOWN:
        return
    _MACOS_CAVEAT_SHOWN = True
    print_warning(
        "Running on macOS. Docker Desktop runs containers inside a Linux VM, so "
        "ADscan cannot reach your Mac's network interface directly."
    )
    print_instruction(
        "Routed scanning works normally: authenticated and unauthenticated "
        "enumeration against a reachable AD target (LDAP, Kerberos, SMB) runs "
        "over Docker's NAT."
    )
    print_instruction(
        "Broadcast poisoning (LLMNR, NBT-NS, mDNS) is unavailable on macOS: it "
        "needs Layer-2 access to the local network, which Docker Desktop does not "
        "provide. Run ADscan on a Linux host or Linux VM if you need it."
    )


def _guard_supported_host_platform(
    *,
    command: str | None,
    has_passthrough_args: bool,
) -> None:
    """Block launcher runtime commands on unsupported host platforms.

    ADscan launcher Docker-mode runtime supports Linux and macOS hosts. Fail
    fast with a clear message on unsupported host OSes (e.g. native Windows) so
    users do not hit deeper runtime errors, and surface the macOS networking
    caveat up front.
    """
    host_platform = str(platform.system() or "").strip() or "Unknown"
    needs_linux = bool(command in _LINUX_REQUIRED_COMMANDS or has_passthrough_args)
    if not needs_linux:
        return

    host_arch = str(platform.machine() or "").strip() or "unknown"
    normalized_arch = host_arch.lower()

    if host_platform.lower() not in _SUPPORTED_HOST_PLATFORMS:
        if _allow_unsupported_platform_override():
            print_warning(
                "Proceeding on an unsupported host platform because "
                f"{_ALLOW_UNSUPPORTED_PLATFORM_ENV}=1 was set."
            )
            print_info_debug(
                "[platform] unsupported platform override enabled: "
                f"platform={host_platform} arch={host_arch} "
                f"command={command or 'passthrough'}"
            )
            capture(
                "launcher_platform_guard",
                {
                    "blocked": False,
                    "override": True,
                    "platform": host_platform,
                    "architecture": host_arch,
                    "reason": "unsupported_platform_override",
                    "command": command or "passthrough",
                },
            )
            return

        print_error(
            "ADscan launcher Docker mode is supported on Linux and macOS hosts."
        )
        print_instruction(f"Detected platform: {host_platform}")
        print_instruction(
            "Use a supported host: Linux (recommended: Kali, Ubuntu, Debian, or "
            "Parrot) or macOS with Docker Desktop, then retry."
        )
        print_instruction(
            "System requirements: https://www.adscanpro.com/docs/getting-started/system-requirements"
        )
        print_info_debug(
            "[platform] blocked unsupported host platform: "
            f"platform={host_platform} arch={host_arch} "
            f"command={command or 'passthrough'}"
        )
        capture(
            "launcher_platform_guard",
            {
                "blocked": True,
                "override": False,
                "platform": host_platform,
                "architecture": host_arch,
                "reason": "unsupported_platform",
                "command": command or "passthrough",
            },
        )
        raise SystemExit(2)

    if host_platform.lower() == "darwin":
        # macOS is supported over bridge/NAT networking. Surface the poisoning
        # caveat up front, then fall through to the shared architecture check
        # (Apple-Silicon arm64 and Intel x86_64 both have native images).
        _warn_macos_networking_caveat()
        capture(
            "launcher_platform_guard",
            {
                "blocked": False,
                "override": False,
                "platform": host_platform,
                "architecture": host_arch,
                "reason": "supported_platform_macos",
                "command": command or "passthrough",
            },
        )

    if _is_windows_subsystem_for_linux():
        if _allow_unsupported_wsl_override():
            print_warning(
                "Proceeding on an unsupported WSL host because "
                f"{_ALLOW_UNSUPPORTED_WSL_ENV}=1 was set."
            )
            print_info_debug(
                "[platform] unsupported WSL override enabled: "
                f"platform={host_platform} arch={host_arch} "
                f"release={platform.release()} "
                f"command={command or 'passthrough'}"
            )
            capture(
                "launcher_platform_guard",
                {
                    "blocked": False,
                    "override": True,
                    "platform": host_platform,
                    "architecture": host_arch,
                    "reason": "unsupported_wsl_override",
                    "command": command or "passthrough",
                },
            )
            return

        print_error("ADscan launcher Docker mode is not currently supported on WSL.")
        print_instruction("Detected environment: Windows Subsystem for Linux (WSL)")
        print_instruction(
            "Use a native Linux host or Linux VM instead of Docker-from-WSL."
        )
        print_instruction(
            "System requirements: https://www.adscanpro.com/docs/getting-started/system-requirements"
        )
        print_info_debug(
            "[platform] blocked unsupported WSL environment: "
            f"platform={host_platform} arch={host_arch} "
            f"release={platform.release()} "
            f"command={command or 'passthrough'}"
        )
        capture(
            "launcher_platform_guard",
            {
                "blocked": True,
                "override": False,
                "platform": host_platform,
                "architecture": host_arch,
                "reason": "unsupported_wsl",
                "command": command or "passthrough",
            },
        )
        raise SystemExit(2)

    if normalized_arch in _SUPPORTED_HOST_ARCHES:
        return

    if _allow_unsupported_arch_override():
        print_warning(
            "Proceeding on an unsupported host architecture because "
            f"{_ALLOW_UNSUPPORTED_ARCH_ENV}=1 was set."
        )
        print_info_debug(
            "[platform] unsupported architecture override enabled: "
            f"platform={host_platform} arch={host_arch} "
            f"command={command or 'passthrough'}"
        )
        capture(
            "launcher_platform_guard",
            {
                "blocked": False,
                "override": True,
                "platform": host_platform,
                "architecture": host_arch,
                "reason": "unsupported_arch_override",
                "command": command or "passthrough",
            },
        )
        return

    print_error(
        "ADscan launcher Docker mode supports x86_64/amd64 and arm64/aarch64 Linux hosts."
    )
    print_instruction(f"Detected architecture: {host_arch}")
    print_instruction(
        "Use an x86_64 or arm64 Linux host, or rebuild/run the container stack with compatible images."
    )
    print_instruction(
        "System requirements: https://www.adscanpro.com/docs/getting-started/system-requirements"
    )
    print_info_debug(
        "[platform] blocked unsupported host architecture: "
        f"platform={host_platform} arch={host_arch} "
        f"command={command or 'passthrough'}"
    )
    capture(
        "launcher_platform_guard",
        {
            "blocked": True,
            "override": False,
            "platform": host_platform,
            "architecture": host_arch,
            "reason": "unsupported_architecture",
            "command": command or "passthrough",
        },
    )
    raise SystemExit(2)


def _emit_launcher_system_context(command: str | None) -> None:
    """Emit non-sensitive host system context for telemetry diagnostics."""
    if not _should_emit_system_context(command):
        return
    try:
        system_context = collect_system_context()
        print_info_debug(f"System context: {system_context}")
        event_payload = dict(system_context)
        if command:
            event_payload["command_type"] = str(command)
        capture("telemetry_system_context", event_payload)
    except Exception as exc:  # pragma: no cover - best effort only
        capture_exception(exc)


def _seed_session_environment_from_host() -> None:
    """Seed ADSCAN_SESSION_ENV from host context when not explicitly overridden.

    This keeps container telemetry aligned with host classification (ci/dev/prod)
    and avoids relying on container-local environment heuristics.
    """
    if os.getenv("ADSCAN_ENV") or os.getenv("ADSCAN_SESSION_ENV"):
        return
    try:
        context = collect_system_context()
        environment = str(context.get("environment") or "").strip().lower()
        if environment:
            os.environ["ADSCAN_SESSION_ENV"] = environment
            print_info_debug(
                f"Seeded ADSCAN_SESSION_ENV from host context: {environment!r}"
            )
    except Exception as exc:  # pragma: no cover - best effort only
        capture_exception(exc)


def _seed_session_trace_id() -> None:
    """Seed ADSCAN_SESSION_TRACE_ID once per launcher invocation."""
    if os.getenv("ADSCAN_SESSION_TRACE_ID"):
        return
    try:
        trace_id = uuid.uuid4().hex
        os.environ["ADSCAN_SESSION_TRACE_ID"] = trace_id
        print_info_debug(f"Seeded ADSCAN_SESSION_TRACE_ID: {trace_id!r}")
    except Exception as exc:  # pragma: no cover - best effort only
        capture_exception(exc)


def _build_launcher_telemetry_console() -> Console:
    """Create a dedicated in-memory Rich console for session recording export."""
    return Console(record=True, theme=ADSCAN_THEME, file=StringIO())


def _capture_launcher_command_session(
    *,
    command_type: str,
    telemetry_console: Console,
    success: bool | None = None,
    extra: dict[str, Any] | None = None,
    allowed_commands: set[str] | None = None,
) -> None:
    """Capture host-side command session exactly once for launcher-owned commands."""
    global _SESSION_CAPTURE_FINALIZED
    if _SESSION_CAPTURE_FINALIZED:
        return

    capture_command_session(
        console=telemetry_console,
        command_type=command_type,
        success=success,
        extra=extra,
        allowed_commands=allowed_commands or set(HOST_SESSION_CAPTURE_COMMANDS),
    )
    _SESSION_CAPTURE_FINALIZED = True


def _run_host_command_with_session_capture(
    *,
    command_type: str,
    telemetry_console: Console,
    runner: Callable[[], bool | int],
    extra: dict[str, Any] | None = None,
    allowed_commands: set[str] | None = None,
) -> int:
    """Execute a launcher-owned command and always finalize session capture.

    Session-capture timing — read this before changing the flow:

    * The launcher runs preflight (privilege check, daemon check, image
      pull, network checks) and THEN execs ``docker run`` to hand the
      terminal over to the container. The container runs for the rest
      of the session — minutes for ``install/check``, hours for ``start/ci``.
    * If we waited until ``runner()`` returns to flush the launcher
      session, the upload arrives only when the container exits, often
      hours after the launcher work was relevant.
    * The fix: register a one-shot hook with ``docker_runtime`` that
      fires at the EXACT moment Docker is about to take over (right
      before the container subprocess starts). The hook flushes the
      launcher session at the handoff, capturing all preflight +
      pull diagnostics, while keeping the container session
      independent.
    * ``_capture_launcher_command_session`` is internally idempotent
      via ``_SESSION_CAPTURE_FINALIZED``, so the ``finally`` block
      below remains as the safety net for code paths that never reach
      ``docker run`` (early errors, EOFs, KeyboardInterrupt) — it
      becomes a no-op when the hook already fired.
    """
    success = False

    def _handoff_flush() -> None:
        # No success signal available at handoff (container still
        # hasn't run); keep ``success=None`` for the metadata.
        _capture_launcher_command_session(
            command_type=command_type,
            telemetry_console=telemetry_console,
            success=None,
            extra=extra,
            allowed_commands=allowed_commands,
        )

    register_pre_container_exec_hook(_handoff_flush)
    try:
        result = runner()
        if isinstance(result, bool):
            success = bool(result)
            return 0 if success else 1
        exit_code = int(result)
        success = exit_code == 0
        return exit_code
    except KeyboardInterrupt:
        _log_launcher_interrupt(
            kind="keyboard_interrupt",
            source=f"launcher.host_command:{command_type}",
        )
        return 130
    except EOFError:
        _log_launcher_interrupt(
            kind="eof",
            source=f"launcher.host_command:{command_type}",
        )
        return 130
    finally:
        # Ensure the hook is cleared even if it never fired (early
        # error path before ``docker run``). Idempotent if already
        # consumed by the hook itself.
        register_pre_container_exec_hook(None)
        # Safety-net flush — no-op if the handoff hook already ran.
        _capture_launcher_command_session(
            command_type=command_type,
            telemetry_console=telemetry_console,
            success=success,
            extra=extra,
            allowed_commands=allowed_commands,
        )


def _log_launcher_interrupt(*, kind: str, source: str) -> None:
    """Emit a standardized debug line for launcher interrupt events."""
    emit_interrupt_debug(kind=kind, source=source, print_debug=print_info_debug)


def _detect_installer_for_launcher() -> str:
    """Best-effort detection for whether `adscan` is installed via pipx or pip.

    pipx is the documented primary install method. A pipx venv's
    ``bin/python`` is a symlink to the system interpreter, so resolving it
    with ``os.path.realpath`` ERASES the ``pipx/venvs`` path component and a
    pipx install gets misdetected as pip — the upgrade then runs in the wrong
    environment and the pipx launcher is never updated. So detect pipx from
    the UNRESOLVED prefix/executable, and only fall back to ``realpath`` as a
    last-ditch tiebreak.
    """
    pipx_marker = f"pipx{os.sep}venvs"

    # 1. Explicit pipx home (env override or the documented default).
    pipx_home = os.environ.get("PIPX_HOME")
    pipx_roots: list[str] = []
    if pipx_home:
        pipx_roots.append(os.path.join(pipx_home, "venvs"))
    pipx_roots.append(os.path.join(str(Path.home()), ".local", "pipx", "venvs"))

    try:
        unresolved_prefix = os.path.abspath(str(sys.prefix))
    except Exception:
        unresolved_prefix = str(sys.prefix)
    for root in pipx_roots:
        try:
            normalized_root = os.path.abspath(root)
        except Exception:
            normalized_root = root
        # The adscan venv lives directly under <root>/adscan.
        if unresolved_prefix == os.path.join(normalized_root, "adscan") or (
            unresolved_prefix + os.sep
        ).startswith(os.path.join(normalized_root, "adscan") + os.sep):
            return "pipx"

    # 2. Unresolved sys.prefix / sys.executable carrying the pipx layout.
    for candidate in (str(sys.prefix), str(sys.executable)):
        if pipx_marker in candidate or "pipx/venvs" in candidate:
            return "pipx"

    # 3. pipx writes a metadata file at the venv root (Path(sys.prefix).parent
    #    is the venvs dir, but the metadata lives in the venv itself).
    try:
        if (Path(sys.prefix) / "pipx_metadata.json").is_file():
            return "pipx"
    except Exception:
        pass

    # 4. Last-ditch: the resolved executable (only useful when the symlink was
    #    not collapsed, e.g. a copied interpreter).
    try:
        resolved = os.path.realpath(sys.executable).lower()
    except Exception:
        resolved = str(sys.executable).lower()
    if pipx_marker in resolved or "pipx/venvs" in resolved:
        return "pipx"

    return "pip"


def _get_clean_env_for_launcher_update() -> dict[str, str]:
    """Return a conservative env dict for pip installs (best-effort)."""
    env = os.environ.copy()
    # Avoid surprising behavior when users have custom pythonpaths.
    env.pop("PYTHONPATH", None)
    return env


def _run_pip_install_with_break_system_packages_retry(
    *,
    python_executable: str,
    args: list[str],
    env: dict[str, str] | None,
    prefer_break_system_packages: bool,
) -> None:
    """Run pip install and retry with --break-system-packages when needed."""

    def _requires_break_system_packages(output: str) -> bool:
        """Return True when pip output indicates a PEP 668 managed env error."""
        normalized = (output or "").lower()
        # pip errors vary across distros/versions:
        # - "externally managed environment"
        # - "externally-managed-environment"
        return bool(
            re.search(r"externally[-\\s]+managed[-\\s]+environment", normalized)
        )

    base_cmd = [python_executable, "-m", "pip", "install"] + list(args)
    proc = subprocess.run(  # noqa: S603
        base_cmd, check=False, capture_output=True, text=True, env=env
    )
    if proc.returncode == 0:
        return

    combined = (proc.stderr or "") + "\n" + (proc.stdout or "")
    needs_break = _requires_break_system_packages(combined)
    if prefer_break_system_packages and needs_break:
        retry_cmd = base_cmd + ["--break-system-packages"]
        proc2 = subprocess.run(  # noqa: S603
            retry_cmd, check=False, capture_output=True, text=True, env=env
        )
        if proc2.returncode == 0:
            return
        combined = (proc2.stderr or "") + "\n" + (proc2.stdout or "")

    raise RuntimeError(f"pip install failed: {combined.strip()}")


def _build_update_context_for_launcher(
    *, docker_pull_timeout_seconds: int | None
) -> UpdateContext:
    """Build an UpdateContext suitable for the PyPI launcher distribution."""
    return UpdateContext(
        adscan_base_dir=str(get_state_dir()),
        docker_pull_timeout_seconds=docker_pull_timeout_seconds,
        get_installed_version=lambda: __version__,
        detect_installer=_detect_installer_for_launcher,
        get_clean_env_for_compilation=_get_clean_env_for_launcher_update,
        run_pip_install_with_optional_break_system_packages=_run_pip_install_with_break_system_packages_retry,
        mark_passthrough=lambda s: s,
        telemetry_capture_exception=lambda exc: capture_exception(exc),
        get_docker_image_name=get_docker_image_name,
        image_exists=image_exists,
        ensure_image_pulled=ensure_image_pulled,
        run_docker=run_docker,
        is_container_runtime=is_docker_env,
        sys_stdin_isatty=sys.stdin.isatty,
        os_getenv=os.getenv,
        print_info=print_info,
        print_info_debug=print_info_debug,
        print_warning=print_warning,
        print_instruction=print_instruction,
        print_error=print_error,
        print_success=print_success,
        print_panel=print_panel,
        confirm_ask=lambda prompt, default: confirm_ask(prompt, default),
    )



def _run_pro_passthrough_with_upsell_gate(
    *,
    cmd: str,
    adscan_args: list[str],
    verbose: bool,
    debug: bool,
    pull_timeout_seconds: int | None,
) -> int:
    """Run a deliverable command in the container and honor the exit-42 protocol.

    LITE container exits with code 42 plus a single JSON line on stdout:
    ``{"error":"pro_required","feature":"<name>"}``. When that pattern is
    detected the launcher renders the canonical PRO upsell panel and exits
    with 0 — the user did not type a broken command, they tried a PRO
    feature, and the panel is the actionable response.

    For any other exit code (including a clean run on PRO), the captured
    stdout is replayed to the user verbatim and the original return code
    is propagated. This keeps the host-side gate a single, predictable
    seam without nesting docker capture machinery deeper in the runtime.
    """

    # Lazy import to keep `cli_catalog` the only host-side dep.
    from adscan_core.cli_catalog import is_pro_only

    # Run the container with stdout/stderr captured — we need to inspect
    # exit-42 + the trailing JSON line. The container's own Rich output is
    # replayed on the host TTY so the user sees the same lines either way.
    rc = run_adscan_passthrough_docker(
        adscan_args=adscan_args,
        verbose=verbose,
        debug=debug,
        pull_timeout_seconds=pull_timeout_seconds,
    )

    # Streaming passthrough does not capture stdout, so the exit-42 JSON
    # protocol cannot be parsed from a captured buffer here. Instead, we
    # use a separate capture call when we know we are gating a PRO command
    # and the rc came back as 42.
    if rc == 42 and is_pro_only(cmd):
        try:
            from adscan_core.pro_upsell import render_pro_upsell_panel

            console = Console(theme=ADSCAN_THEME)
            panel = render_pro_upsell_panel(cmd, context="direct_invocation")
            console.print(panel)
            return 0
        except Exception as exc:  # noqa: BLE001 — best-effort upsell render
            capture_exception(exc)
            return rc

    # Defensive: a malformed exit 42 (e.g. PRO container emitting 42 by
    # accident, or a future protocol change) should not eat user output.
    return int(rc)


def _render_host_welcome() -> None:
    """Render the host-side editorial welcome screen.

    Uses ``adscan_core`` primitives only — no container roundtrip — so a
    fresh user typing ``adscan`` sees the brand within milliseconds.
    Posture lookup walks ``~/.adscan/workspaces/`` if it exists; otherwise
    the screen renders without a posture line.
    """
    from adscan_core.welcome_host import (
        load_latest_posture_host,
        print_welcome_host,
    )
    posture, ws_name, age_days = load_latest_posture_host()
    print_welcome_host(
        latest_posture=posture,
        workspace_name=ws_name,
        last_scan_age_days=age_days,
        version_tag=f"v{__version__}",
    )


def main(argv: list[str] | None = None) -> None:
    global _SESSION_CAPTURE_FINALIZED
    _SESSION_CAPTURE_FINALIZED = False
    _cleanup_legacy_sudo_alias()

    raw_argv = list(sys.argv[1:] if argv is None else argv)
    parser = _build_parser()
    if not raw_argv:
        try:
            _render_host_welcome()
        except Exception:
            parser.print_help()
        raise SystemExit(0)

    ns, unknown = parser.parse_known_args(raw_argv)
    unknown = _consume_trailing_global_flags(ns, unknown)
    _consume_ci_remainder_global_flags(ns)
    if (
        getattr(ns, "command", None) in _KNOWN_LAUNCHER_COMMANDS
        and unknown
    ):
        parser.error(f"unrecognized arguments: {' '.join(unknown)}")

    cmd = getattr(ns, "command", None)
    show_version = bool(getattr(ns, "version", False)) or cmd == "version"
    if cmd is None and not unknown and not show_version:
        try:
            _render_host_welcome()
        except Exception:
            parser.print_help()
        raise SystemExit(0)

    telemetry_console = _build_launcher_telemetry_console()
    set_output_config(
        verbose=bool(getattr(ns, "verbose", False)),
        debug=bool(getattr(ns, "debug", False)),
        telemetry_console=telemetry_console,
    )
    if bool(getattr(ns, "debug", False)) and _should_print_debug_enabled_banner(
        "version" if show_version else cmd
    ):
        print_success("Debug mode enabled")

    # Ensure runtime container telemetry can distinguish launcher vs runtime
    # version contexts.
    os.environ["ADSCAN_LAUNCHER_VERSION"] = str(__version__)

    _apply_image_overrides(ns)

    if show_version:
        print_info(f"ADscan launcher: v{__version__}")
        img = get_docker_image_name()
        print_info(f"Docker image: {img}")
        if not is_dev_update_context(image_name=img):
            recency = get_local_update_recency_summary(str(get_state_dir()))
            recency_message = str(recency.get("message") or "").strip()
            if recency_message:
                if bool(recency.get("is_stale")):
                    print_warning(recency_message)
                else:
                    print_info(recency_message)
        print_info(
            "Recommended: keep both launcher and runtime current with `adscan update`."
        )
        raise SystemExit(0)

    _guard_supported_host_platform(
        command=cmd,
        has_passthrough_args=bool(unknown),
    )

    if cmd == "welcome":
        try:
            _render_host_welcome()
        except Exception as exc:
            capture_exception(exc)
            print_error("Could not render welcome screen.")
        raise SystemExit(0)

    if cmd == "host-helper":
        try:
            from adscan_launcher.host_privileged_helper import run_host_helper_server
        except Exception as exc:
            capture_exception(exc)
            print_error("Host helper is unavailable in this launcher build.")
            raise SystemExit(2) from exc
        raise SystemExit(run_host_helper_server(str(getattr(ns, "socket", ""))))

    _emit_launcher_privilege_context(cmd)
    _guard_root_shell_without_user_context(cmd)
    _seed_session_environment_from_host()
    _seed_session_trace_id()
    _emit_launcher_system_context(cmd)

    # A ci --offline / --no-telemetry run must gate the launcher's OWN telemetry
    # (the queue drain below + the preflight recording upload), not just the
    # scan container. Apply the opt-out to this process's environment BEFORE the
    # drain so the gate sees it. (See _apply_host_posture_env.)
    _apply_host_posture_env(ns, raw_argv)

    # Best-effort drain of any telemetry sessions that failed to upload
    # in previous CLI invocations (network blip, crash mid-flight,
    # oversize payload, etc.). Runs on a background thread; the launcher
    # foreground command never waits for it. Safe to no-op if telemetry
    # is disabled or the queue module is unavailable.
    try:
        from adscan_core.telemetry import start_telemetry_queue_drain

        start_telemetry_queue_drain()
    except Exception:
        # Telemetry queue drain must never break the launcher CLI.
        pass

    # Offer upgrades early for relevant subcommands (interactive only).
    cmd_for_update_offer = cmd or "start"
    pull_timeout_raw = getattr(ns, "pull_timeout", 3600)
    pull_timeout_norm = normalize_pull_timeout_seconds(int(pull_timeout_raw))
    # ``--no-update-check`` is the explicit user opt-out. ``--dev`` is the
    # existing top-level launcher flag (defined ~line 230). Either signal
    # routes through to ``offer_updates_for_command`` as a skip; the dev
    # variant additionally suppresses the "dev channel detected" debug
    # noise via the canonical ``is_dev_update_context`` env-var path that
    # the top-level flag already populates.
    no_update_check = bool(getattr(ns, "no_update_check", False))
    dev_mode = bool(getattr(ns, "dev", False))
    try:
        offer_updates_for_command(
            _build_update_context_for_launcher(
                docker_pull_timeout_seconds=pull_timeout_norm
            ),
            cmd_for_update_offer,
            skip_update_check=no_update_check or dev_mode,
            dev_mode=dev_mode,
        )
    except KeyboardInterrupt:
        _log_launcher_interrupt(
            kind="keyboard_interrupt",
            source="launcher.offer_updates",
        )
        raise SystemExit(130)
    except EOFError:
        _log_launcher_interrupt(
            kind="eof",
            source="launcher.offer_updates",
        )
        raise SystemExit(130)

    if cmd == "start":
        pull_timeout = getattr(ns, "pull_timeout", 3600)
        raise SystemExit(
            _run_host_command_with_session_capture(
                command_type="start",
                telemetry_console=telemetry_console,
                runner=lambda: handle_start_docker(
                    verbose=bool(getattr(ns, "verbose", False)),
                    debug=bool(getattr(ns, "debug", False)),
                    pull_timeout_seconds=int(pull_timeout),
                    allow_low_memory=bool(getattr(ns, "allow_low_memory", False)),
                    tui=bool(getattr(ns, "tui", False)),
                ),
                extra={"mode": "docker", "session_scope": "launcher_preflight"},
                allowed_commands=set(SESSION_CAPTURE_ALLOWED_COMMANDS),
            )
        )

    if cmd == "tui":
        # The workbench shares the start lifecycle (Docker preflight, session
        # capture, image pull) — only the in-container command differs. We
        # forward as `adscan tui` so the container-side handler can apply
        # --demo / --dev semantics consistently.
        pull_timeout_tui = getattr(ns, "pull_timeout", 3600)
        tui_passthrough = ["tui"]
        if bool(getattr(ns, "demo", False)):
            tui_passthrough.append("--demo")
        if bool(getattr(ns, "verbose", False)):
            tui_passthrough.append("--verbose")
        if bool(getattr(ns, "debug", False)):
            tui_passthrough.append("--debug")
        raise SystemExit(
            _run_host_command_with_session_capture(
                command_type="tui",
                telemetry_console=telemetry_console,
                runner=lambda: run_adscan_passthrough_docker(
                    adscan_args=tui_passthrough,
                    verbose=bool(getattr(ns, "verbose", False)),
                    debug=bool(getattr(ns, "debug", False)),
                    pull_timeout_seconds=int(pull_timeout_tui),
                ),
                extra={"mode": "docker", "session_scope": "launcher_preflight"},
                allowed_commands=set(SESSION_CAPTURE_ALLOWED_COMMANDS),
            )
        )

    if cmd == "install":
        raise SystemExit(
            _run_host_command_with_session_capture(
                command_type="install",
                telemetry_console=telemetry_console,
                runner=lambda: handle_install_docker(
                    pull_timeout_seconds=int(ns.pull_timeout),
                    allow_low_memory=bool(getattr(ns, "allow_low_memory", False)),
                ),
                extra={"mode": "docker"},
            )
        )

    if cmd == "check":
        raise SystemExit(
            _run_host_command_with_session_capture(
                command_type="check",
                telemetry_console=telemetry_console,
                runner=lambda: handle_check_docker(
                    allow_low_memory=bool(getattr(ns, "allow_low_memory", False)),
                ),
                extra={"mode": "docker"},
            )
        )

    if cmd in ("update", "upgrade"):
        pull_timeout_norm = normalize_pull_timeout_seconds(int(ns.pull_timeout))
        raise SystemExit(
            _run_host_command_with_session_capture(
                command_type=str(cmd),
                telemetry_console=telemetry_console,
                runner=lambda: run_update_command(
                    _build_update_context_for_launcher(
                        docker_pull_timeout_seconds=pull_timeout_norm
                    )
                ),
                extra={"mode": "docker"},
            )
        )

    if cmd == "ci":
        # Pass-through execution inside the container, but still do Docker-mode preflight.
        passthrough = list(getattr(ns, "args", []) or [])
        # argparse.REMAINDER keeps leading --, but may start with a "--" separator.
        if passthrough and passthrough[0] == "--":
            passthrough = passthrough[1:]
        # Translate the engagement-posture toggles (--offline / --no-telemetry)
        # into container environment variables. The flags are consumed here, NOT
        # forwarded into the container as `ci` args, because the internal runtime
        # honours them via env. ``_ci_posture_env_from_flags`` also strips the
        # tokens out of the passthrough so a token that landed after the
        # auth/unauth positional (past argparse.REMAINDER's flag cut-off) still
        # takes effect and never reaches the container parser.
        posture_env, passthrough = _ci_posture_env_from_flags(ns, passthrough)
        # Translate --scan-config <host-path> into a read-only container mount +
        # ADSCAN_SCAN_CONFIG env var. Consumed at the seam and stripped from the
        # passthrough (mirrors the posture-toggle pattern). Absent = no-op.
        scan_config_env, scan_config_mounts, passthrough = _ci_scan_config_from_flags(
            ns, passthrough
        )
        ci_extra_env = list(posture_env) + list(scan_config_env)
        raise SystemExit(
            _run_host_command_with_session_capture(
                command_type="ci",
                telemetry_console=telemetry_console,
                runner=lambda: run_adscan_passthrough_docker(
                    adscan_args=["ci"] + passthrough,
                    verbose=bool(getattr(ns, "verbose", False)),
                    debug=bool(getattr(ns, "debug", False)),
                    pull_timeout_seconds=int(ns.pull_timeout),
                    allow_low_memory=bool(getattr(ns, "allow_low_memory", False)),
                    extra_env=ci_extra_env,
                    extra_mounts=scan_config_mounts,
                ),
                extra={"mode": "docker", "session_scope": "launcher_preflight"},
                allowed_commands=set(SESSION_CAPTURE_ALLOWED_COMMANDS),
            )
        )

    if cmd in ("execute", "doctor"):
        # Container passthrough with launcher preflight + session capture.
        # The REMAINDER args were captured on the dest named "<cmd>_args"; any
        # leading option-looking token (e.g. `execute --list`) lands in
        # ``unknown`` instead, so we prepend it — everything the operator typed
        # after the verb is forwarded verbatim to the container (the container
        # subparser is the single source of truth for the flag surface).
        passthrough = list(unknown) + list(getattr(ns, f"{cmd}_args", []) or [])
        if passthrough and passthrough[0] == "--":
            passthrough = passthrough[1:]
        raise SystemExit(
            _run_host_command_with_session_capture(
                command_type=str(cmd),
                telemetry_console=telemetry_console,
                runner=lambda: run_adscan_passthrough_docker(
                    adscan_args=[cmd] + passthrough,
                    verbose=bool(getattr(ns, "verbose", False)),
                    debug=bool(getattr(ns, "debug", False)),
                    pull_timeout_seconds=3600,
                ),
                extra={"mode": "docker", "session_scope": "launcher_preflight"},
                allowed_commands=set(SESSION_CAPTURE_ALLOWED_COMMANDS),
            )
        )

    if cmd in _DELIVERABLE_PASSTHROUGH_COMMANDS:
        deliv_args: list[str] = [cmd]
        output_path = getattr(ns, "output_path", None)
        if output_path:
            deliv_args.extend(["--output", str(output_path)])
        if bool(getattr(ns, "no_open", False)):
            deliv_args.append("--no-open")
        if bool(getattr(ns, "no_render", False)):
            deliv_args.append("--no-render")
        if hasattr(ns, "theme") and ns.theme:
            deliv_args.extend(["--theme", str(ns.theme)])
        # ``deliver``-specific flags. Using ``ws_*`` dests on the host parser
        # avoids clobbering the launcher's own ``output_path``/``no_render``
        # while still surfacing the container's full flag set in --help.
        if cmd == "deliver":
            ws_workspace = getattr(ns, "ws_workspace", None)
            if ws_workspace:
                deliv_args.extend(["--workspace", str(ws_workspace)])
            ws_client = getattr(ns, "ws_client", None)
            if ws_client:
                deliv_args.extend(["--client", str(ws_client)])
            ws_engagement = getattr(ns, "ws_engagement", None)
            if ws_engagement:
                deliv_args.extend(["--engagement", str(ws_engagement)])
            ws_only = getattr(ns, "ws_only", None)
            if ws_only:
                deliv_args.extend(["--only", str(ws_only)])
            ws_frameworks = getattr(ns, "ws_frameworks", None)
            if ws_frameworks:
                deliv_args.extend(["--frameworks", str(ws_frameworks)])
            if bool(getattr(ns, "ws_no_navigator", False)):
                deliv_args.append("--no-navigator")
            ws_report_theme = getattr(ns, "ws_report_theme", "") or ""
            if ws_report_theme:
                deliv_args.extend(["--report-theme", str(ws_report_theme)])
        # ``mitre-navigator``-specific flags. Distinct ``nav_*`` dests so the
        # navigator's directory ``--output`` and boolean flags never clash
        # with the PDF deliverables' ``output_path``/``no_open``/``no_render``.
        # Forwarded verbatim into the container, where the navigator subparser
        # interprets them. New navigator flags need a one-line entry both at
        # registration above and in this forwarding block.
        if cmd == "mitre-navigator":
            nav_workspace = getattr(ns, "nav_workspace", None)
            if nav_workspace:
                deliv_args.extend(["--workspace", str(nav_workspace)])
            nav_output = getattr(ns, "nav_output", None)
            if nav_output:
                deliv_args.extend(["--output", str(nav_output)])
            nav_client = getattr(ns, "nav_client", None)
            if nav_client:
                deliv_args.extend(["--client", str(nav_client)])
            nav_engagement = getattr(ns, "nav_engagement", None)
            if nav_engagement:
                deliv_args.extend(["--engagement", str(nav_engagement)])
            if bool(getattr(ns, "nav_web", False)):
                deliv_args.append("--web")
            if bool(getattr(ns, "nav_no_html", False)):
                deliv_args.append("--no-html")
            if bool(getattr(ns, "nav_no_history", False)):
                deliv_args.append("--no-history")
            if bool(getattr(ns, "nav_verbose", False)):
                deliv_args.append("--verbose")
        raise SystemExit(
            _run_pro_passthrough_with_upsell_gate(
                cmd=str(cmd),
                adscan_args=deliv_args,
                verbose=bool(getattr(ns, "verbose", False)),
                debug=bool(getattr(ns, "debug", False)),
                pull_timeout_seconds=3600,
            )
        )

    if cmd == "demo":
        # Reconstruct the demo CLI args from the parsed namespace and forward
        # them into the container (where the demo lives, alongside the deliverable
        # orchestrator). Keeping this explicit makes the arg surface obvious.
        demo_args: list[str] = ["demo"]
        if bool(getattr(ns, "fast", False)):
            demo_args.append("--fast")
        if bool(getattr(ns, "no_pdf", False)):
            demo_args.append("--no-pdf")
        output_path = getattr(ns, "output_path", None)
        if output_path:
            demo_args.extend(["--output", str(output_path)])
        seed = getattr(ns, "seed", None)
        if seed is not None:
            demo_args.extend(["--seed", str(seed)])
        # Mirror the start/ci convention: forward --debug / --verbose into the
        # container so the demo respects the global launcher flags. --dev is
        # consumed by _apply_image_overrides above (sets the docker channel).
        if bool(getattr(ns, "debug", False)):
            demo_args.append("--debug")
        if bool(getattr(ns, "verbose", False)):
            demo_args.append("--verbose")
        raise SystemExit(
            _run_host_command_with_session_capture(
                command_type="demo",
                telemetry_console=telemetry_console,
                runner=lambda: run_adscan_passthrough_docker(
                    adscan_args=demo_args,
                    verbose=bool(getattr(ns, "verbose", False)),
                    debug=bool(getattr(ns, "debug", False)),
                    pull_timeout_seconds=3600,
                ),
                extra={"mode": "docker", "session_scope": "launcher_preflight"},
                allowed_commands=set(SESSION_CAPTURE_ALLOWED_COMMANDS),
            )
        )

    # Anything else: pass through to the container.
    if cmd:
        adscan_args = [cmd] + unknown
    else:
        adscan_args = unknown

    if not adscan_args:
        print_error("No command provided.")
        print_instruction("Try: adscan --help")
        raise SystemExit(2)

    try:
        rc = run_adscan_passthrough_docker(
            adscan_args=adscan_args,
            verbose=bool(getattr(ns, "verbose", False)),
            debug=bool(getattr(ns, "debug", False)),
            pull_timeout_seconds=3600,
        )
    except KeyboardInterrupt:
        _log_launcher_interrupt(
            kind="keyboard_interrupt",
            source="launcher.generic_passthrough",
        )
        rc = 130
    except EOFError:
        _log_launcher_interrupt(
            kind="eof",
            source="launcher.generic_passthrough",
        )
        rc = 130
    raise SystemExit(rc)
