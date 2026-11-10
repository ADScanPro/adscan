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
import dataclasses
import platform
import re
from io import StringIO
import os
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from rich.console import Console

from adscan_core.cli_passthrough_spec import (
    CI_PASSTHROUGH,
    DOCTOR_PASSTHROUGH,
    EXECUTE_PASSTHROUGH,
    ENGAGEMENT_PASSTHROUGH,
    RECHECK_PASSTHROUGH,
    PACE_PASSTHROUGH,
    POLICY_PASSTHROUGH,
    RUN_PASSTHROUGH,
    render_passthrough_epilog,
)
from adscan_core.interrupts import emit_interrupt_debug
from adscan_core.outbound_links import cta_display_url, cta_url
from adscan_core.theme import ADSCAN_THEME
from adscan_core.report_options import forward_report_options as _forward_report_options
from adscan_launcher import __version__
from adscan_launcher.docker_commands import (
    get_docker_image_name,
    handle_check_docker,
    handle_install_docker,
    handle_start_docker,
    resolve_runtime_license_mode,
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
from adscan_core.rich_output import print_exception


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
    "report",
    "writeup",
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

        # Automation section — `ci` is the one PRO automation surface today
        # (autonomous, non-interactive scanning). Badge is catalog-driven via
        # `tier_for_command`, never hardcoded, so it stays correct if the
        # catalog ever adds a second automation command.
        automation_descriptions: dict[str, str] = {
            "ci": "Autonomous, non-interactive scanning",
            "execute": "One REPL command from a shell or a script",
            "recheck": "Re-verify findings, steps and attack paths",
        }
        automation_names = [
            name for name in automation_descriptions if _tier_for_command(name) == "PRO"
        ]
        if automation_names:
            lines.append("")
            lines.append("Automation — PRO")
            for name in automation_names:
                badge = f"[{_tier_for_command(name)}]"
                desc = automation_descriptions.get(name, name)
                lines.append(f"  {name:<18} {desc:<43} {badge}")

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


# Help text for the launcher-own ``--partner-tag`` flag, shared by `start` and
# `ci` so both read identically. This is a LAUNCHER flag (consumed at the seam,
# never forwarded as a container argument), so it is deliberately NOT part of
# `adscan_core.cli_passthrough_spec` — that SSOT only mirrors arguments the
# container parser owns.
_PARTNER_TAG_FLAG_HELP = (
    "ADscan PRO: activate this install with the partner tag from your "
    "onboarding email (for example: --partner-tag acme-mssp). The tag is saved "
    "under ~/.adscan/state and reused on every later run, so you pass it once "
    "per machine. Ignored by the free tier."
)


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
        # `-v` is the universal short form and six independent documentation
        # sites had already written it, so a user typing what they expect must
        # not get an error. The subcommand-level `-v` on mitre-navigator is a
        # separate namespace and is unaffected.
        "-v",
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
            "PyPI / Docker Hub call). Alias: --no-update. Usable as a prefix "
            "before any command, including container passthroughs. "
            "Mid-engagement / airgapped / version-pinned use only. Note: "
            "--offline already skips the probe on its own."
        ),
    )
    # Alias for the flag above: --no-update is the exact name a user is likely to
    # guess (issue #24). Hidden from --help (the canonical row already names it as
    # an alias) so it does not widen the option column, and default=SUPPRESS so it
    # never resets the canonical flag's value when absent. Same dest.
    parser.add_argument(
        "--no-update",
        action="store_true",
        dest="no_update_check",
        default=argparse.SUPPRESS,
        help=argparse.SUPPRESS,
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
            "this run (alias: --no-update). Use when you intentionally stay on "
            "the current version (mid-engagement, airgapped, pinned for a "
            "customer requirement). --offline already skips the probe on its own."
        ),
    )
    # Hidden alias of --no-update-check on the same dest (issue #24: --no-update
    # is the name users guess). SUPPRESS help so it does not widen the option
    # column; SUPPRESS default so it never resets the value when absent.
    update_check_parent.add_argument(
        "--no-update",
        action="store_true",
        dest="no_update_check",
        default=argparse.SUPPRESS,
        help=argparse.SUPPRESS,
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
            "Report, instead of failing, when available RAM is critically low "
            "(below 1.0 GB)."
        ),
    )
    # The runtime's own `check` prints "Run: adscan check --fix" whenever a
    # tool venv or system package is broken (doctor.py, isolated_tools.py,
    # check.py). Users type that on the HOST, so the launcher has to accept
    # the flag and route the repair into the container — otherwise the
    # remediation ADscan prints is unrunnable. Locked by
    # tests/unit/launcher/test_printed_commands_are_runnable.py.
    check.add_argument(
        "--fix",
        action="store_true",
        help=(
            "Attempt automatic repairs for detected issues (best effort). "
            "Runs the in-container repair pass after the host prerequisites pass."
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
    # Engagement-posture toggles, same semantics as on `ci`: translated into
    # container environment variables at the launcher seam (they are launcher-own
    # flags, never forwarded as `adscan start` arguments) and applied to the
    # launcher's own process environment by `_apply_host_posture_env`.
    start.add_argument(
        "--offline",
        action="store_true",
        help=(
            "Offline mode: disable every external lookup (weakpass / no-external "
            "guard) for air-gapped or sovereign engagements. Sets ADSCAN_OFFLINE=1 "
            "inside the session container."
        ),
    )
    start.add_argument(
        "--no-telemetry",
        action="store_true",
        dest="no_telemetry",
        help=(
            "Disable anonymous usage telemetry for this session (sensitive "
            "engagements). Sets ADSCAN_TELEMETRY=0 inside the session container. "
            "To opt out permanently, run 'set telemetry off' in the shell."
        ),
    )
    start.add_argument(
        "--partner-tag",
        dest="partner_tag",
        default=None,
        metavar="TAG",
        help=_PARTNER_TAG_FLAG_HELP,
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

    from adscan_core.cli_catalog import tier_for_command as _ci_tier_for_command

    ci = sub.add_parser(
        "ci",
        help=(
            "Run ADscan in autonomous mode (no prompts, end-to-end automated scan)"
            f"  [{_ci_tier_for_command('ci')}]"
        ),
        parents=[update_check_parent],
        description=(
            "Autonomous scan mode.\n\n"
            "`adscan ci` launches ADscan in fully non-interactive mode: sensible "
            "defaults are applied, every confirmation prompt is skipped, and the "
            "complete scan pipeline (preflight → recon → enumeration → "
            "exploitation → reporting) runs end-to-end without operator input.\n\n"
            "Intended for CI/CD pipelines, automated lab validation (HTB/GOAD), "
            "and unattended engagements where a human is not available to drive "
            "the interactive shell.\n\n"
            "The interactive `adscan start` shell remains available for scans "
            "where operator judgement is preferred.\n\n"
            "If a run fails, re-run with `--debug` and report the trace at "
            + cta_url("ci_help_debug")
        ),
        # The scan arguments below are forwarded to the container runtime through
        # argparse.REMAINDER (`args`), so argparse cannot list them natively. The
        # epilog renders them (and real invocation examples) from the shared SSOT
        # so `adscan ci --help` shows what the run actually requires. The launcher
        # never re-declares them, so there is no drift; the contract test
        # (tests/unit/launcher/test_passthrough_spec_contract.py) keeps the SSOT
        # in lockstep with the container `ci` parser.
        epilog=render_passthrough_epilog(CI_PASSTHROUGH),
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
        "--partner-tag",
        dest="partner_tag",
        default=None,
        metavar="TAG",
        help=_PARTNER_TAG_FLAG_HELP,
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
        help=(
            "Run a single REPL command non-interactively (scripting / smoke-test)"
            f"  [{_ci_tier_for_command('execute')}]"
        ),
        description=(
            "Run ONE ADscan REPL verb non-interactively, then exit. PRO: every "
            "verb is also available interactively in `adscan start` (LITE)."
        ),
        # Forwarded verbatim via REMAINDER; the epilog surfaces the container
        # flags + examples from the shared SSOT (no drift, no re-declaration).
        epilog=render_passthrough_epilog(EXECUTE_PASSTHROUGH),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    execute_p.add_argument(
        "execute_args",
        nargs=argparse.REMAINDER,
        help="Verb and arguments forwarded to the container (see `adscan execute --list`).",
    )
    doctor_p = sub.add_parser(
        "doctor",
        help="Fast one-shot health check (DNS, connectivity, auth, posture).",
        description="Run the pre-engagement validations and print a GREEN/RED matrix.",
        # Forwarded verbatim via REMAINDER; the epilog surfaces the container
        # flags + examples from the shared SSOT (no drift, no re-declaration).
        epilog=render_passthrough_epilog(DOCTOR_PASSTHROUGH),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    doctor_p.add_argument(
        "doctor_args",
        nargs=argparse.REMAINDER,
        help="Arguments forwarded to the container health check.",
    )
    engagement_p = sub.add_parser(
        "engagement",
        help="[PRO] Engagement history: findings and attack steps across runs.",
        description=(
            "Read a workspace's engagement ledger: what is open, what was fixed, what "
            "the latest run could not re-check, and when each item was last verified."
        ),
        epilog=render_passthrough_epilog(ENGAGEMENT_PASSTHROUGH),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    engagement_p.add_argument(
        "engagement_args",
        nargs=argparse.REMAINDER,
        help="Subcommand and arguments forwarded to the container.",
    )
    recheck_p = sub.add_parser(
        "recheck",
        help="[PRO] Re-verify findings, attack steps and attack paths from a workspace.",
        description=(
            "Re-verify what a previous scan found, without a full scan: re-read a "
            "condition (read-only), re-perform one attack step, or walk one attack path. "
            "Results update the workspace's engagement history."
        ),
        epilog=render_passthrough_epilog(RECHECK_PASSTHROUGH),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    recheck_p.add_argument(
        "recheck_args",
        nargs=argparse.REMAINDER,
        help="Arguments forwarded to the container.",
    )
    policy_p = sub.add_parser(
        "policy",
        help="Create and manage saved scan policies, without opening the shell.",
        description=(
            "Saved scan policies: which checks ADscan may run and at what pace. "
            "Create, edit, export and apply them here, with the same prompts as the shell. "
            "Use one with `adscan ci --policy <name>` or pick it when `start` asks."
        ),
        epilog=render_passthrough_epilog(POLICY_PASSTHROUGH),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    policy_p.add_argument(
        "policy_args",
        nargs=argparse.REMAINDER,
        help="Subcommand and arguments forwarded to the container.",
    )

    pace_p = sub.add_parser(
        "pace",
        help="Create and manage saved pace profiles, without opening the shell.",
        description=(
            "Saved pace profiles: a named scan pace you reuse with any scan policy. "
            "Create, edit, export and apply them here, with the same prompts as the shell. "
            "Use one with `adscan ci --pace-profile <name>` or `pace use` in `start`."
        ),
        epilog=render_passthrough_epilog(PACE_PASSTHROUGH),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    pace_p.add_argument(
        "pace_args",
        nargs=argparse.REMAINDER,
        help="Subcommand and arguments forwarded to the container.",
    )

    # ── adscan run --plan (engine contract) ───────────────────────────
    # One RunPlan file in: the same run `ci` / `doctor` / `deliver` flags
    # describe. The launcher validates the plan host-side, mounts its directory
    # read-only and the events file's directory read-write, and rewrites both
    # paths; every other token is forwarded (the container parser is the SSOT).
    run_p = sub.add_parser(
        "run",
        help="Run one engine plan (adscan.run_plan/1): a scan, a validation or a deliverable kit.",
        description=(
            "Run the engine from a RunPlan file. The plan names the run kind "
            "(scan, doctor, deliver), the target and the options. Credentials "
            "are references (env:NAME, or file:<path> relative to the plan's "
            "directory), never values, so a plan can be stored and reviewed."
        ),
        epilog=render_passthrough_epilog(RUN_PASSTHROUGH),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    run_p.add_argument(
        "--offline",
        action="store_true",
        help="Offline mode: disable every external lookup (sets ADSCAN_OFFLINE=1 inside the container).",
    )
    run_p.add_argument(
        "--no-telemetry",
        action="store_true",
        dest="no_telemetry",
        help="Disable anonymous usage telemetry for this run (sets ADSCAN_TELEMETRY=0).",
    )
    run_p.add_argument(
        "--partner-tag",
        dest="partner_tag",
        default=None,
        metavar="TAG",
        help=_PARTNER_TAG_FLAG_HELP,
    )
    run_p.add_argument(
        "run_args",
        nargs=argparse.REMAINDER,
        help="Arguments forwarded to the container after `run` (see below).",
    )

    # ── Client Deliverables (Pass C) — passthrough into container ─────
    # Tier badges come from `adscan_core.cli_catalog` so the launcher and
    # the container dispatcher agree on which commands are PRO-only.
    from adscan_core.cli_catalog import (
        DELIVERABLE_COMMAND_ORDER as _DELIV_ORDER,
        tier_for_command as _tier_for_command,
    )
    from adscan_core.report_options import add_report_arguments as _add_report_arguments

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
        if _deliv_name != "deliver":
            # Single-PDF deliverables only. ``deliver`` neither opens the kit
            # nor has a dry run, and its container parser rejects both flags:
            # declaring them here let ``adscan deliver --no-open`` start the
            # container and then exit 2 inside it.
            _deliv_p.add_argument("--no-open", action="store_true",
                                  help="Do not prompt to open the PDF.")
            _deliv_p.add_argument("--no-render", action="store_true",
                                  help="Smoke / dry-run only — skip PDF render.")
        if _deliv_name == "deliver":
            # The container interprets every deliverable option; the launcher
            # declares them (so ``adscan deliver --help`` lists them and an
            # unknown-flag check passes) from the SAME shared model the container
            # ``deliver`` and ``ci`` parsers use, under ``ws_*`` dests so they
            # never collide with the launcher's own --output/--no-open, and
            # forwards them with ``forward_report_options`` below. A new
            # deliverable option is added to ``adscan_core.report_options``
            # once, never here.
            _deliv_p.add_argument(
                "--workspace", dest="ws_workspace", default=None,
                help="Workspace name or path (default: prompt or most-recent).",
            )
            _add_report_arguments(_deliv_p, dest_prefix="ws_")
            _deliv_p.add_argument(
                "--progress-model", dest="ws_progress_model", default=None,
                metavar="PATH",
                help=(
                    "Render the Executive Progress Report from a progress "
                    "report model (JSON) instead of the kit. PATH is relative "
                    "to the workspace."
                ),
            )

    # ── adscan report (tier-adaptive report regeneration) ──────────────
    # Regenerates the report for a kept workspace without re-scanning. Unlike
    # `deliver`, `report` is NOT PRO-gated — it renders in either tier (LITE:
    # the exposure report with its PRO CTA; PRO: the single Security
    # Assessment Report PDF), so it is registered as a plain known launcher
    # command rather than through the PRO-upsell deliverable loop above.
    report_p = sub.add_parser(
        "report",
        help="Regenerate the report for a kept workspace (no re-scan). [LITE/PRO]",
    )
    report_p.add_argument(
        "--workspace", dest="workspace", default=None,
        help="Workspace name or path (default: prompt or most-recent).",
    )
    report_p.add_argument(
        "--client", dest="client", default=None,
        help="Client name embedded in the report's cover as the display name (PRO only).",
    )
    report_p.add_argument(
        "--frameworks", dest="frameworks", default=None,
        help=(
            "Comma-separated compliance frameworks (PRO only): "
            "ens, nis2, iso27001, dora, pci_dss, cis. Default: none."
        ),
    )

    # ── adscan writeup (lab writeup evidence spine) ─────────────────────
    # Writes the mechanical two-thirds of a lab writeup from a kept
    # workspace, without re-scanning. LITE-safe and NOT PRO-gated — mirrors
    # `report`'s plain-passthrough registration.
    writeup_p = sub.add_parser(
        "writeup",
        help="Write a Markdown evidence spine for a lab writeup from a kept workspace. [LITE/PRO]",
    )
    writeup_p.add_argument(
        "--workspace", dest="workspace", default=None,
        help="Workspace name or path (default: prompt or most-recent).",
    )
    writeup_p.add_argument(
        "--full-credentials", dest="full_credentials", action="store_true",
        help=(
            "Write the complete recovered-credential table, with values, into "
            "the writeup. On a client engagement the values are withheld by "
            "default and the writeup points at the workspace register instead."
        ),
    )
    writeup_p.add_argument(
        "output_dir", nargs="?", default=None,
        help=(
            "Destination directory for the spine (default: a timestamped "
            "directory under <workspace>/writeups/)."
        ),
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
    ns: argparse.Namespace, unknown: list[str], *, force: bool = False
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
    if not force and cmd not in (_KNOWN_LAUNCHER_COMMANDS | _DELIVERABLE_PASSTHROUGH_COMMANDS):
        return unknown

    remaining: list[str] = []
    idx = 0
    while idx < len(unknown):
        token = unknown[idx]

        if token in ("-v", "--verbose"):
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


def _consume_run_passthrough(ns: argparse.Namespace, unknown: list[str]) -> list[str]:
    """Join `adscan run`'s forwarded tokens and lift the launcher-global flags out.

    ``run`` forwards through ``argparse.REMAINDER``, and its first token
    (``--plan``) is option-shaped, so argparse splits the run's tokens between
    ``unknown`` and ``ns.run_args``. They are rejoined in order into
    ``ns.run_args``, and the launcher-global flags among them (``--dev``,
    ``--debug``, ``-v``, ``--image``, ``--channel``) are consumed so they select
    the image here instead of reaching the container parser. Returns the
    ``unknown`` left for the caller (always empty for ``run``).
    """
    if str(getattr(ns, "command", "") or "") != "run":
        return unknown
    tokens = list(unknown) + list(getattr(ns, "run_args", []) or [])
    if tokens and tokens[0] == "--":
        setattr(ns, "run_args", tokens[1:])
        return []
    setattr(ns, "run_args", _consume_trailing_global_flags(ns, tokens, force=True))
    return []


def _posture_env_from_flags(
    ns: argparse.Namespace, passthrough: list[str]
) -> tuple[list[tuple[str, str]], list[str]]:
    """Translate the engagement-posture flags into container env vars.

    Shared by `ci` and `start` (both declare `--offline` / `--no-telemetry`).

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


def _extract_partner_tag_flag(
    ns: argparse.Namespace, passthrough: list[str]
) -> tuple[str | None, list[str]]:
    """Pull ``--partner-tag <value>`` out of the namespace and the passthrough.

    Mirrors ``--scan-config``: the parsed attribute is used when the flag
    preceded the auth/unauth positional, and the raw passthrough is scanned for
    tokens that landed after it (past ``argparse.REMAINDER``'s flag cut-off).
    Recognised tokens are removed so they never reach the container's parser.

    Returns:
        ``(tag_or_None, cleaned_passthrough)``.

    Raises:
        SystemExit: with code 2 when ``--partner-tag`` is given without a value.
    """
    tag = getattr(ns, "partner_tag", None)

    cleaned: list[str] = []
    tokens = list(passthrough)
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--partner-tag":
            if index + 1 < len(tokens):
                tag = tokens[index + 1]
                index += 2
                continue
            print_error("--partner-tag requires a tag argument.")
            raise SystemExit(2)
        if token.startswith("--partner-tag="):
            tag = token.split("=", 1)[1]
            index += 1
            continue
        cleaned.append(token)
        index += 1

    normalized = str(tag).strip() if tag is not None else None
    return (normalized or None), cleaned


def _apply_partner_tag_flag(
    ns: argparse.Namespace, passthrough: list[str]
) -> list[str]:
    """Activate this install with ``--partner-tag`` and strip it from the args.

    ADscan PRO refuses to start without a partner tag, and until this flag
    existed the only documented recovery was an environment variable — which is
    a route the operator cannot take on their own if the launcher does not
    forward it. This is the route that always works: the tag is validated
    against the shared format contract, persisted to the bind-mounted state dir
    (``~/.adscan/state/partner.json`` -> ``/opt/adscan/state``, so it survives
    ``docker run --rm`` and every later run), and exported on the launcher
    process so the standard env forwarding carries it into THIS run.

    Setting the launcher's own environment (rather than returning an extra
    ``-e``) keeps one forwarding mechanism: an explicit flag simply overrides an
    ambient ``ADSCAN_PARTNER_TAG`` for this run instead of racing it.

    Args:
        ns: Parsed launcher namespace.
        passthrough: Raw container passthrough tokens (empty for ``start``).

    Returns:
        The passthrough with any ``--partner-tag`` tokens removed.

    Raises:
        SystemExit: with code 2 when the tag is missing its value or malformed.
    """
    tag, cleaned = _extract_partner_tag_flag(ns, passthrough)
    if not tag:
        return cleaned

    from adscan_core import telemetry as _telemetry

    if not _telemetry.validate_partner_tag(tag):
        print_error(
            "Invalid partner tag. Use the tag from your onboarding email: "
            f"{_telemetry.PARTNER_TAG_FORMAT_HINT}."
        )
        raise SystemExit(2)

    tag = tag.lower()
    try:
        _telemetry.persist_partner_tag(tag)
    except OSError as exc:
        capture_exception(exc)
        print_exception(exception=exc)
        # Non-fatal: the tag still reaches this run through the environment
        # below; only the "ask once per machine" convenience is lost.
        print_warning(
            "Could not save the partner tag for future runs. Check that "
            "~/.adscan is writable; this run continues with the tag you passed."
        )

    os.environ["ADSCAN_PARTNER_TAG"] = tag
    try:
        _telemetry.refresh_partner_tag()
    except Exception:  # noqa: BLE001 — attribution is never worth failing a run
        pass
    return cleaned


def _image_ref_is_dev_edge(image_ref: str) -> bool:
    """True when the resolved image is the internal dev/CI ``:edge`` build.

    Mirrors :func:`adscan_internal.cli.partner_tag_gate._is_dev_edge_runtime`:
    partners always receive ``:latest`` / a pinned ``:vX.Y.Z`` tag, so an
    ``:edge`` tag is the founder's own ``--dev`` run or the CI regression
    workflow. The partner-tag gate is attribution, not access control, so those
    internal runs are never gated. Tolerant of a ``host:port`` registry prefix by
    reading only the final path segment's tag.
    """
    last_segment = str(image_ref or "").strip().lower().rsplit("/", 1)[-1]
    if ":" not in last_segment:
        return False
    return last_segment.rsplit(":", 1)[-1] == "edge"


def _should_block_pro_without_tag(
    license_mode: str | None, resolved_tag: str, image_ref: str = ""
) -> bool:
    """Return True when a PRO run has no resolvable partner tag.

    Pure decision function so the gate can be unit-tested in isolation.

    Args:
        license_mode: The runtime license mode the launcher resolved before any
            Docker pull (``"PRO"`` / ``"LITE"`` / ``None`` when undeterminable).
        resolved_tag: The partner tag resolved via
            :func:`adscan_core.telemetry.resolve_partner_tag` (env → persisted
            volume file), ``""`` when none is resolvable by any route.
        image_ref: The resolved runtime image reference. When it is the internal
            dev/CI ``:edge`` build, the run is NEVER gated — mirroring the
            in-container ``_is_dev_edge_runtime`` skip, so `--dev`/CI PRO runs are
            not blocked (the regression this argument fixes).

    Returns:
        True only when the run is PRO, is not the dev/CI ``:edge`` image, and no
        partner tag is resolvable — the one case the in-container gate would
        refuse. Anything else (LITE, an undeterminable mode, the dev/CI image, or
        a resolvable tag) returns False so the run proceeds and the in-container
        gate stays the backstop.
    """
    if str(license_mode or "").strip().upper() != "PRO":
        return False
    if _image_ref_is_dev_edge(image_ref):
        return False
    return not resolved_tag


def _enforce_partner_tag_before_container() -> None:
    """Abort a doomed PRO-without-tag run BEFORE the launcher spends a docker run.

    The in-container start gate (:mod:`adscan_internal.cli.partner_tag_gate`)
    already refuses PRO without a partner tag, but only after the image starts
    and the entrypoint runs. This is the fastest layer: it resolves the license
    mode locally (no network) and the partner tag through the SAME SSOT resolver
    the container uses (:func:`adscan_core.telemetry.resolve_partner_tag`, which
    reads ``ADSCAN_PARTNER_TAG`` and the bind-mounted ``partner.json``), so host
    and container agree by construction. Call it AFTER
    :func:`_apply_partner_tag_flag` — a run WITH ``--partner-tag`` has already
    exported the tag, so the resolver sees it and this no-ops.

    LITE runs, and PRO runs with a resolvable tag, are never gated. The
    in-container gate remains the backstop for a direct ``docker run`` that
    bypasses the launcher.

    Raises:
        SystemExit: with code 1 when a PRO run has no resolvable partner tag.
    """
    from adscan_core import telemetry as _telemetry
    from adscan_launcher.docker_commands import _select_existing_or_preferred_image

    # Resolve the image ONCE so the license inference and the dev/CI :edge skip
    # both key off the exact same reference the run will use.
    image_ref = _select_existing_or_preferred_image()
    if not _should_block_pro_without_tag(
        resolve_runtime_license_mode(), _telemetry.resolve_partner_tag(), image_ref
    ):
        return

    print_error(_telemetry.PARTNER_TAG_REQUIRED_MESSAGE)
    raise SystemExit(1)


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


#: Container directory the files of `adscan policy import` / `export --output`
#: are mounted under. Outside the ADscan home so nothing is left on the volume.
from adscan_core.container_io import POLICY_IO_CONTAINER_DIR  # noqa: E402


class _HostOutput:
    """A host ``--output`` made writable from the container, safely.

    The container is removed when the command ends, so a host path forwarded
    verbatim was written inside the container and lost with it (a kit "saved"
    to a folder that never appeared on the host). The launcher instead creates
    a FRESH staging folder next to the destination, bind-mounts only that folder
    read-write at :data:`OUTPUT_IO_CONTAINER_DIR`, forwards the container-side
    path, and moves the results into place when the container exits. Mounting
    the destination's parent instead would hand the container write access to
    it (``--output ~/report.pdf`` would have mounted the whole home folder).

    A ``:`` in the path cannot be expressed in a Docker ``-v`` spec, so such a
    path is refused up front with a clear message.
    """

    def __init__(self, value: str, *, is_file: bool) -> None:
        from adscan_core.container_io import OUTPUT_IO_CONTAINER_DIR  # noqa: PLC0415
        from adscan_core.deliverable_destination import plan_host_output  # noqa: PLC0415

        try:
            plan = plan_host_output(value, is_file=is_file)
        except ValueError as exc:
            print_error(str(exc))
            raise SystemExit(2) from exc
        self.final = plan.final
        self.is_file = is_file
        os.makedirs(plan.dest_dir, exist_ok=True)
        self.dest_dir = plan.dest_dir
        self.staging = tempfile.mkdtemp(prefix=".adscan-output-", dir=plan.dest_dir)
        self.container_arg = plan.container_arg
        self.mount = (self.staging, OUTPUT_IO_CONTAINER_DIR)

    def finalize(self) -> None:
        """Move what the container wrote into the destination; drop staging."""
        from adscan_core.deliverable_destination import move_staged_into  # noqa: PLC0415

        move_staged_into(self.staging, self.dest_dir)


def _host_output_mount(value: str, *, is_file: bool) -> _HostOutput:
    """Prepare a host ``--output`` for a containerised command (see _HostOutput)."""
    return _HostOutput(value, is_file=is_file)


def _policy_file_mounts(
    passthrough: list[str],
) -> tuple[list[str], list[tuple[str, str]], list[tuple[str, str]]]:
    """Make the host files of ``adscan policy`` and ``adscan pace`` visible in the container.

    ``import FILE`` reads a host file: it is mounted read-only (one file, never
    its directory) under :data:`POLICY_IO_CONTAINER_DIR` with its own name, so
    a policy without a ``name`` still takes the file stem. ``export --output
    FILE`` writes one: the launcher creates it empty on the host and mounts that
    file read-write (the engine writes in place, not through a rename).

    Returns:
        ``(rewritten_args, read_only_mounts, read_write_mounts)``.
    """
    args = list(passthrough)
    ro: list[tuple[str, str]] = []
    rw: list[tuple[str, str]] = []
    action = next((a for a in args if not a.startswith("-")), "")

    def _container_path(host_path: str, slot: str) -> str:
        return f"{POLICY_IO_CONTAINER_DIR}/{slot}/{os.path.basename(host_path)}"

    if action == "import":
        index = args.index("import")
        target_index = next(
            (i for i in range(index + 1, len(args)) if not args[i].startswith("-")), None
        )
        if target_index is not None:
            host = os.path.abspath(os.path.expanduser(args[target_index]))
            if not os.path.isfile(host):
                print_error(f"File not found: {host}")
                raise SystemExit(2)
            container = _container_path(host, "in")
            ro.append((host, container))
            args[target_index] = container

    for index, token in enumerate(list(args)):
        value: str | None = None
        value_index = index
        if token in ("--output", "-o") and index + 1 < len(args):
            value = args[index + 1]
            value_index = index + 1
        elif token.startswith("--output="):
            value = token.split("=", 1)[1]
        if not value:
            continue
        host = os.path.abspath(os.path.expanduser(value))
        parent = os.path.dirname(host)
        if not os.path.isdir(parent):
            print_error(f"Folder not found: {parent}")
            raise SystemExit(2)
        if not os.path.exists(host):
            with open(host, "w", encoding="utf-8"):
                pass
        container = _container_path(host, "out")
        rw.append((host, container))
        args[value_index] = container if value_index != index else f"--output={container}"
        break
    return args, ro, rw


# Container paths for `adscan run --plan`, fixed and outside the ADscan home so
# nothing is left behind on the host volume. Nothing is mounted wholesale: the
# plan FILE and each file it references (read-only), the events FILE
# (read-write), a private directory holding env: secrets (read-only), and the
# dedicated operator-decision directory of the file sink (read-write).
RUN_PLAN_CONTAINER_DIR = "/opt/adscan-io/plan"
RUN_EVENTS_CONTAINER_DIR = "/opt/adscan-io/events"
RUN_ENV_SECRETS_CONTAINER_DIR = "/opt/adscan-io/env-secrets"
RUN_INTERACTIVE_CONTAINER_DIR = "/opt/adscan-io/interactive"
_RUN_EVENTS_CONTAINER_FILE = f"{RUN_EVENTS_CONTAINER_DIR}/events.jsonl"

#: Legacy command each RunPlan kind normalises from (tier gate, session label).
#: Mirrors ``adscan_internal.cli.run_plan.KIND_COMMAND``; the launcher cannot
#: import the engine, and ``tests/unit/launcher/test_run_plan_launcher.py``
#: locks the two together.
_RUN_KIND_COMMAND = {"scan": "ci", "doctor": "doctor", "deliver": "deliver"}


@dataclass(frozen=True)
class RunPlanIo:
    """What the launcher derived from ``adscan run`` flags before the container.

    Reading the plan writes nothing secret: ``env_names`` lists the env:
    references, and :meth:`with_env_secrets` materialises them, which the
    dispatch calls only AFTER the tier and partner-tag gates (either may exit)
    and inside the ``try`` whose ``finally`` calls :meth:`cleanup`.
    """

    passthrough: list[str]
    ro_mounts: list[tuple[str, str]]
    rw_mounts: list[tuple[str, str]]
    kind: str
    command: str
    extra_env: list[tuple[str, str]] = field(default_factory=list)
    env_exclude_keys: tuple[str, ...] = ()
    cleanup_paths: tuple[str, ...] = ()
    env_names: tuple[str, ...] = ()

    def with_env_secrets(self) -> "RunPlanIo":
        """Return this I/O plan with the env: secrets written and mounted."""
        if not self.env_names:
            return self
        secrets_dir, secret_mounts = _materialise_env_secrets(list(self.env_names))
        return dataclasses.replace(
            self,
            ro_mounts=list(self.ro_mounts) + secret_mounts,
            extra_env=list(self.extra_env) + [("ADSCAN_RUN_ENV_SECRETS_DIR", RUN_ENV_SECRETS_CONTAINER_DIR)],
            env_exclude_keys=tuple(self.env_names),
            cleanup_paths=tuple(self.cleanup_paths) + (secrets_dir,),
        )

    def cleanup(self) -> None:
        """Remove every materialised secret; best-effort, never raises."""
        import shutil

        for path in self.cleanup_paths:
            shutil.rmtree(path, ignore_errors=True)


def _take_flag_value(tokens: list[str], flag: str) -> tuple[str | None, list[str]]:
    """Remove ``flag VALUE`` / ``flag=VALUE`` from ``tokens``; return the value."""
    value: str | None = None
    rest: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == flag:
            if index + 1 >= len(tokens):
                print_error(f"{flag} requires a file path argument.")
                raise SystemExit(2)
            value = tokens[index + 1]
            index += 2
            continue
        if token.startswith(f"{flag}="):
            value = token.split("=", 1)[1]
            index += 1
            continue
        rest.append(token)
        index += 1
    return value, rest


def _plan_references(node: Any) -> list[str]:
    """Every ``{"ref": "..."}`` value in a plan document, in document order."""
    found: list[str] = []
    if isinstance(node, dict):
        ref = node.get("ref")
        if isinstance(ref, str) and set(node) == {"ref"}:
            found.append(ref)
        for value in node.values():
            if isinstance(value, (dict, list)):
                found.extend(_plan_references(value))
    elif isinstance(node, list):
        for value in node:
            found.extend(_plan_references(value))
    return found


def _refuse_run(message: str) -> None:
    print_error(message)
    raise SystemExit(2)


def _materialise_env_secrets(names: list[str]) -> tuple[str, list[tuple[str, str]]]:
    """Write each ``env:`` secret to a 0600 file in a private 0700 directory.

    ``docker run -e NAME`` would keep the value off the command line but still
    copy it into the container's configuration, which ``docker inspect`` prints,
    so the value travels as a file mounted read-only instead.
    """
    import tempfile

    import shutil

    directory = tempfile.mkdtemp(prefix="adscan-run-env-")
    try:
        os.chmod(directory, 0o700)
        for name in names:
            target = os.path.join(directory, name)
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(os.environ[name])
    except BaseException:
        shutil.rmtree(directory, ignore_errors=True)
        raise
    return directory, [(directory, RUN_ENV_SECRETS_CONTAINER_DIR)]


#: System top-level directories a decision directory may never be or contain.
_SYSTEM_TOP_LEVEL_DIRS = ("/etc", "/var", "/usr", "/home", "/root", "/opt", "/srv", "/boot", "/proc", "/sys", "/dev")


def _refuse_unsafe_interactive_dir(directory: Path, *, plan_dir: Path) -> None:
    """Refuse a decision directory that is, or contains, something it must not expose.

    It is mounted read-write, so it may not be the filesystem root, the home
    directory, a system top-level directory, or any directory containing one of
    those or the run plan. A dedicated directory INSIDE such a tree is fine.
    """
    resolved = Path(os.path.abspath(os.path.expanduser(str(directory)))).resolve()
    protected = [Path(resolved.anchor), Path.home().resolve(), plan_dir.resolve()]
    protected += [Path(item) for item in _SYSTEM_TOP_LEVEL_DIRS]
    if any(item == resolved or item.is_relative_to(resolved) for item in protected):
        _refuse_run(
            "ADSCAN_INTERACTIVE_DIR must be a dedicated directory: not the filesystem "
            "root, your home directory, a system directory, or one that contains any "
            "of those or the run plan."
        )


def _interactive_dir_mount(plan_dir: Path) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Mount the file-sink decision directory, when the run uses that sink."""
    sink = str(os.environ.get("ADSCAN_INTERACTIVE_SINK", "") or "").strip().lower()
    raw = str(os.environ.get("ADSCAN_INTERACTIVE_DIR", "") or "").strip()
    if sink != "file" or not raw:
        return [], []
    directory = Path(os.path.abspath(os.path.expanduser(raw)))
    _refuse_unsafe_interactive_dir(directory, plan_dir=plan_dir)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    return (
        [(str(directory.resolve()), RUN_INTERACTIVE_CONTAINER_DIR)],
        [("ADSCAN_INTERACTIVE_DIR", RUN_INTERACTIVE_CONTAINER_DIR)],
    )


def _run_plan_io_from_flags(passthrough: list[str]) -> RunPlanIo:
    """Validate the host plan file and translate its paths for the container.

    The plan is validated HOST-side against the shared contract schema
    (``adscan_core.engagement.contract``), so a malformed plan, or one carrying
    an inline secret, fails before a ``docker run`` is spent. The per-kind rules
    are re-checked inside the container, which owns them.

    Exposure is minimal: the plan file and the files it references are mounted
    one by one (a reference that resolves outside the plan's directory, a
    symlink included, is refused), the events file is created and mounted as a
    single file, and env: secrets never appear on the command line.

    Raises:
        SystemExit: code 2 when ``--plan`` is missing, unreadable or invalid, a
            reference cannot be satisfied, or a path is unsafe to mount.
    """
    import json

    from adscan_core.engagement.contract import ContractError, validate

    plan_value, rest = _take_flag_value(list(passthrough), "--plan")
    events_value, rest = _take_flag_value(rest, "--events-file")
    if not plan_value:
        _refuse_run("adscan run needs --plan FILE (a RunPlan, schema adscan.run_plan/1).")
    plan_path = Path(os.path.abspath(os.path.expanduser(plan_value)))
    if not plan_path.is_file():
        _refuse_run(f"Run plan file not found: {plan_path}")
    try:
        doc = json.loads(plan_path.read_text(encoding="utf-8"))
        validate("run_plan", doc)
    except ContractError as exc:
        _refuse_run(f"Invalid run plan: {exc}")
    except (OSError, ValueError) as exc:
        _refuse_run(f"Invalid run plan: {exc}")

    run_dir = plan_path.parent.resolve()
    plan_real = plan_path.resolve()
    ro_mounts: list[tuple[str, str]] = [(str(plan_real), f"{RUN_PLAN_CONTAINER_DIR}/{plan_path.name}")]
    referenced: set[Path] = {plan_real}
    env_names: list[str] = []
    for ref in _plan_references(doc):
        scheme, _, name = ref.partition(":")
        if scheme == "env":
            if name not in os.environ:
                _refuse_run(f"The run plan references environment variable {name}, which is not set.")
            if name not in env_names:
                env_names.append(name)
        elif scheme == "file":
            target = (run_dir / name).resolve()
            if not target.exists():
                _refuse_run(f"The run plan references {name}, which is not in the plan's directory.")
            if not target.is_relative_to(run_dir):
                _refuse_run(f"The run plan reference {name} resolves outside the plan's directory.")
            if target not in referenced:
                referenced.add(target)
                ro_mounts.append((str(target), f"{RUN_PLAN_CONTAINER_DIR}/{name}"))

    out = ["--plan", f"{RUN_PLAN_CONTAINER_DIR}/{plan_path.name}"]
    rw_mounts: list[tuple[str, str]] = []
    if events_value:
        events_path = Path(os.path.abspath(os.path.expanduser(events_value)))
        if events_path.is_symlink() or (events_path.exists() and not events_path.is_file()):
            _refuse_run(f"--events-file must be a regular file: {events_path}")
        if events_path.resolve() in referenced:
            _refuse_run("--events-file cannot be the run plan or a file the plan references.")
        # Create it host-side so docker does not create the bind source as root,
        # and mount that ONE file, never its directory.
        events_path.parent.mkdir(parents=True, exist_ok=True)
        events_path.touch(mode=0o600, exist_ok=True)
        rw_mounts.append((str(events_path.resolve()), _RUN_EVENTS_CONTAINER_FILE))
        out += ["--events-file", _RUN_EVENTS_CONTAINER_FILE]

    extra_env: list[tuple[str, str]] = []
    interactive_mounts, interactive_env = _interactive_dir_mount(run_dir)
    rw_mounts.extend(interactive_mounts)
    extra_env.extend(interactive_env)

    kind = str(doc.get("kind") or "")
    return RunPlanIo(
        passthrough=out + rest,
        ro_mounts=ro_mounts,
        rw_mounts=rw_mounts,
        kind=kind,
        command=_RUN_KIND_COMMAND.get(kind, kind),
        extra_env=extra_env,
        env_names=tuple(env_names),
    )


# Accepted client-logo suffixes. The AUTHORITATIVE set lives in the container SSOT
# ``adscan_internal.services.client_logo.SUPPORTED_LOGO_SUFFIXES``; the launcher
# (host-only, must not import ``adscan_internal``) keeps this small mirror purely
# to reject an obviously-wrong file before copying it into the volume. The
# container re-validates.
_CLIENT_LOGO_SUFFIXES: tuple[str, ...] = (".png", ".svg", ".jpg", ".jpeg", ".gif", ".webp")

#: Sub-directory under the ADscan home where a staged client logo is copied. Must
#: match ``adscan_internal.services.client_logo.CLIENT_LOGO_DIRNAME``.
_CLIENT_LOGO_DIRNAME = "branding"


def _stage_client_logo(host_path: str) -> str | None:
    """Copy a host client-logo file into the mounted ``~/.adscan`` volume.

    The report renders INSIDE the container, which can only read the operator's
    logo if it lives under the bind-mounted ADscan home. This copies the selected
    host file to ``~/.adscan/branding/<name>`` (host side) and returns the path
    RELATIVE to the ADscan home (e.g. ``branding/acme.png``). The container joins
    that against its own ADscan home (``/opt/adscan``), so the one value stays
    valid across the host/container path split — the launcher never hardcodes a
    container path.

    Args:
        host_path: Path to the logo on the host filesystem.

    Returns:
        The home-relative POSIX path to forward to the container, or ``None`` when
        the file is missing or of an unsupported type (a warning is printed; a
        cosmetic logo never aborts the command).
    """
    import shutil

    from adscan_core.paths import get_adscan_home_dir

    resolved = os.path.abspath(os.path.expanduser(str(host_path)))
    if not os.path.isfile(resolved):
        print_error(f"Client logo file not found: {resolved}")
        return None
    suffix = Path(resolved).suffix.lower()
    if suffix not in _CLIENT_LOGO_SUFFIXES:
        print_error(
            f"Unsupported client logo type '{suffix}'. "
            f"Supported: {', '.join(_CLIENT_LOGO_SUFFIXES)}."
        )
        return None
    try:
        dest_dir = get_adscan_home_dir() / _CLIENT_LOGO_DIRNAME
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_name = Path(resolved).name
        dest_path = dest_dir / dest_name
        shutil.copyfile(resolved, dest_path)
    except OSError as exc:
        print_error(f"Could not stage the client logo into the ADscan volume: {exc}")
        return None
    return f"{_CLIENT_LOGO_DIRNAME}/{dest_name}"


def _ci_output_from_flags(passthrough: list[str]) -> tuple[list[str], "_HostOutput | None"]:
    """Stage ``ci --output <host-dir>`` (the report copy) like a deliverable.

    ``ci`` forwards its arguments verbatim, so a host folder would reach the
    container as a path it cannot see. The folder is staged and mounted
    (:class:`_HostOutput`) and the container path substituted.
    """
    tokens = list(passthrough)
    for index, token in enumerate(tokens):
        value: str | None = None
        if token == "--output":
            if index + 1 >= len(tokens):
                print_error("--output requires a folder argument.")
                raise SystemExit(2)
            value = tokens[index + 1]
            host_output = _host_output_mount(value, is_file=False)
            tokens[index + 1] = host_output.container_arg
            return tokens, host_output
        if token.startswith("--output="):
            value = token.split("=", 1)[1]
            host_output = _host_output_mount(value, is_file=False)
            tokens[index] = f"--output={host_output.container_arg}"
            return tokens, host_output
    return tokens, None


def _ci_client_logo_from_flags(
    ns: argparse.Namespace, passthrough: list[str]
) -> list[str]:
    """Stage a ``--client-logo`` host file and rewrite it to a container path.

    ``ci`` forwards its arguments verbatim through ``argparse.REMAINDER``, so a
    ``--client-logo <host-path>`` the operator typed carries a HOST path the
    container cannot read. This copies the file into the mounted volume
    (:func:`_stage_client_logo`) and substitutes the home-relative container path
    back into the passthrough, so the container's ``ci`` parser receives a value
    it can resolve. An unstageable value is dropped with a warning.

    Both the parsed namespace attribute (when the flag preceded the positional)
    and the raw passthrough list are inspected, mirroring
    :func:`_ci_scan_config_from_flags`.
    """
    host_path = getattr(ns, "client_logo", None)

    cleaned: list[str] = []
    index = 0
    tokens = list(passthrough)
    while index < len(tokens):
        token = tokens[index]
        if token == "--client-logo":
            if index + 1 < len(tokens):
                host_path = tokens[index + 1]
                index += 2
                continue
            print_error("--client-logo requires a file path argument.")
            raise SystemExit(2)
        if token.startswith("--client-logo="):
            host_path = token.split("=", 1)[1]
            index += 1
            continue
        cleaned.append(token)
        index += 1

    if not host_path:
        return cleaned

    staged = _stage_client_logo(str(host_path))
    if staged:
        cleaned.extend(["--client-logo", staged])
    return cleaned


def _apply_host_posture_env(ns: argparse.Namespace, raw_argv: list[str]) -> None:
    """Gate the LAUNCHER's OWN telemetry when a run opts out (``ci`` or ``start``).

    ``_posture_env_from_flags`` configures the scan CONTAINER, but the host
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
        print_exception(exception=exc)


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
        if host_platform.lower() == "windows":
            print_instruction(
                "On Windows, use the native self-contained bundle instead of this "
                "PyPI launcher: download adscan.exe (no Docker, no Python install) "
                "and run it directly."
            )
        else:
            print_instruction(
                "Use a supported host: Linux (recommended: Kali, Ubuntu, Debian, or "
                "Parrot) or macOS with Docker Desktop, then retry."
            )
        print_instruction(
            "System requirements: " + cta_display_url("unsupported_platform")
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
            "System requirements: " + cta_display_url("unsupported_wsl")
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
        "System requirements: " + cta_display_url("unsupported_arch")
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
        print_exception(exception=exc)


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
        print_exception(exception=exc)


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
        print_exception(exception=exc)


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


# Host exit code for a PRO-gated command run on LITE. Same value the LITE
# container emits. Never 0: ``ci``/``execute`` are unattended entry points and
# a pipeline that scanned nothing must not read as success.
PRO_GATE_EXIT_CODE = 42


def _render_pro_upsell_and_record(
    cmd: str,
    *,
    telemetry_console: Console | None = None,
    capture_session: bool = False,
) -> None:
    """Render the canonical PRO upsell on the shared, tee'd host console.

    Single seam for every host-side PRO-upsell impression (the pre-gate and
    the exit-42 backstops). It renders through :func:`get_console` — the
    shared ``_TeeConsole`` that ``set_output_config`` wired to the launcher's
    recording ``telemetry_console`` — so the panel auto-mirrors into the
    session recording. A bare ``Console`` here would paint the terminal but
    never reach ``telemetry_console``, leaving the peak-value LITE->PRO
    activation moment invisible to the activation radar.

    Args:
        cmd: The PRO-only command that was refused (``"ci"`` / ``"deliver"``).
        telemetry_console: The launcher's recording console. Required for the
            session capture; ignored when ``capture_session`` is ``False``.
        capture_session: When ``True`` (the host pre-gate, which exits before
            :func:`_run_host_command_with_session_capture` ever runs), flush
            the launcher session here so the impression reaches the recording
            before the process exits. The refused command is force-added to
            the allow-list so a ``deliver`` refusal (not in the default set)
            is captured too.
    """
    from adscan_core.operator_role import resolve_cta_lane
    from adscan_core.output._state import get_console
    from adscan_core.pro_upsell import render_pro_upsell_panel

    lane = resolve_cta_lane()
    get_console().print(
        render_pro_upsell_panel(cmd, context="direct_invocation", lane=lane)
    )
    if capture_session and telemetry_console is not None:
        _capture_launcher_command_session(
            command_type=cmd,
            telemetry_console=telemetry_console,
            success=None,
            extra={
                "mode": "host",
                "session_scope": "launcher_pro_pregate",
                "pro_pregate_refused": True,
                "pro_pregate_command": cmd,
                "cta_lane": getattr(lane, "value", str(lane)),
            },
            allowed_commands=set(SESSION_CAPTURE_ALLOWED_COMMANDS) | {cmd},
        )


def _run_pro_passthrough_with_upsell_gate(
    *,
    cmd: str,
    adscan_args: list[str],
    verbose: bool,
    debug: bool,
    pull_timeout_seconds: int | None,
    extra_rw_mounts: list[tuple[str, str]] | None = None,
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
    passthrough_kwargs: dict[str, Any] = {}
    if extra_rw_mounts:
        passthrough_kwargs["extra_rw_mounts"] = list(extra_rw_mounts)
    rc = run_adscan_passthrough_docker(
        adscan_args=adscan_args,
        verbose=verbose,
        debug=debug,
        pull_timeout_seconds=pull_timeout_seconds,
        **passthrough_kwargs,
    )

    # Streaming passthrough does not capture stdout, so the exit-42 JSON
    # protocol cannot be parsed from a captured buffer here. Instead, we
    # use a separate capture call when we know we are gating a PRO command
    # and the rc came back as 42.
    if rc == 42 and is_pro_only(cmd):
        try:
            _render_pro_upsell_and_record(cmd)
        except Exception as exc:  # noqa: BLE001 — best-effort upsell render
            capture_exception(exc)
            print_exception(exception=exc)
        return PRO_GATE_EXIT_CODE

    # Defensive: a malformed exit 42 (e.g. PRO container emitting 42 by
    # accident, or a future protocol change) should not eat user output.
    return int(rc)


def _pro_passthrough_rc(cmd: str, rc: int) -> int:
    """Map a PRO-only passthrough's container rc to a host exit code (exit-42 aware).

    LITE exits 42 (+ the pro_required JSON) for a PRO-only command. Render the
    role/OS-aware upsell (``_render_pro_upsell_and_record``) and exit
    ``PRO_GATE_EXIT_CODE`` (42), even if the panel fails to render: an unattended
    caller (pipeline, script) reads the exit code, and 0 would read a scan that
    never ran as a success. Any other rc, or a command that is not PRO-only, is
    propagated verbatim.
    """
    from adscan_core.cli_catalog import is_pro_only

    if rc == 42 and is_pro_only(cmd):
        try:
            _render_pro_upsell_and_record(cmd)
        except Exception as exc:  # noqa: BLE001 — best-effort upsell render
            capture_exception(exc)
            print_exception(exception=exc)
        return PRO_GATE_EXIT_CODE
    return int(rc)


def _ci_handle_passthrough_rc(rc: int) -> int:
    """Map the `ci` container rc to a host exit code, honoring exit-42.

    LITE exits 42 (+ the pro_required JSON) when `ci` is PRO-gated. Render the
    canonical PRO upsell and exit ``PRO_GATE_EXIT_CODE`` (42): the message stays
    friendly, but an unattended caller reads the exit code and 0 would read a scan
    that never ran as a success. Any other rc (including a clean PRO run) is
    propagated verbatim.
    """
    from adscan_core.cli_catalog import is_pro_only

    if rc == 42 and is_pro_only("ci"):
        try:
            _render_pro_upsell_and_record("ci")
        except Exception as exc:  # noqa: BLE001 — best-effort upsell render
            capture_exception(exc)
            print_exception(exception=exc)
        return PRO_GATE_EXIT_CODE
    return int(rc)


def _maybe_pregate_pro_command(
    cmd: str, *, telemetry_console: Console | None = None
) -> None:
    """Skip the container entirely for a PRO-only command under confirmed LITE.

    ``resolve_runtime_license_mode()`` already resolves the tier for free
    (no network, no ``docker run``) before every passthrough command. For a
    PRO-only command (``is_pro_only(cmd)``) known to be running against a
    LITE image, spending a full container start (entrypoint, Unbound, DNS,
    capability setup) just to have it exit 42 is wasted work. Render the
    canonical upsell panel and exit 42 immediately instead (the same code the
    container would have produced; an unattended caller must not read a scan
    that never ran as a success).

    This is a **pre-gate**, not a replacement for the exit-42 protocol: it is
    fail-safe by construction and only fires on a CONFIRMED ``"LITE"``. Any
    other result (``"PRO"``, or ``None`` when the tier cannot be resolved
    locally, e.g. no image pulled yet) is a no-op — the function returns
    normally and the caller proceeds to `docker run`, where the container's
    own exit-42 + ``_run_pro_passthrough_with_upsell_gate`` /
    ``_ci_handle_passthrough_rc`` remain the backstop.

    The upsell is rendered through the shared tee'd console and the launcher
    session is captured HERE, before the ``SystemExit(42)`` — this pre-gate
    fires before :func:`_run_host_command_with_session_capture` ever runs, so
    without an explicit capture the peak-value LITE->PRO activation moment (a
    free user reaching for the paid autonomous scan) never reaches the session
    recording and the activation radar stays blind to it.

    Args:
        cmd: The subcommand about to run (e.g. ``"ci"``, ``"deliver"``,
            ``"report"``). A no-op for any command not in
            :data:`adscan_core.cli_catalog.PRO_ONLY_COMMANDS`.
        telemetry_console: The launcher's recording console, so the captured
            impression reaches the session recording. When ``None`` the panel
            still renders (through the tee'd console) but no session is flushed.

    Raises:
        SystemExit: With code ``PRO_GATE_EXIT_CODE`` (42), when the pre-gate fires.
    """
    from adscan_core.cli_catalog import is_pro_only

    if not is_pro_only(cmd):
        return
    if (resolve_runtime_license_mode() or "").upper() != "LITE":
        return

    _render_pro_upsell_and_record(
        cmd, telemetry_console=telemetry_console, capture_session=True
    )
    raise SystemExit(PRO_GATE_EXIT_CODE)


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

    # A removed ci/execute/doctor flag fails here, before a container starts,
    # with what to pass instead (adscan_core/cli_removed_flags.py).
    from adscan_core.cli_removed_flags import removed_flag_message  # noqa: PLC0415

    removed_flag = removed_flag_message(raw_argv)
    if removed_flag:
        parser.error(removed_flag)

    ns, unknown = parser.parse_known_args(raw_argv)
    unknown = _consume_trailing_global_flags(ns, unknown)
    _consume_ci_remainder_global_flags(ns)
    unknown = _consume_run_passthrough(ns, unknown)
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
    # Log files: only a maintenance command (install/update/check/version) gets
    # the global log. Everything else this launcher logs is held in memory and
    # dropped at exit, so no engagement detail (the ci target, credentials)
    # lands outside a workspace. See adscan_core.logging_config.
    try:
        from adscan_core.logging_config import enable_global_log_for_command

        enable_global_log_for_command("version" if show_version else cmd)
    except Exception:  # noqa: BLE001 — logging setup must never block a command
        pass
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
            print_exception(exception=exc)
            print_error("Could not render welcome screen.")
        raise SystemExit(0)

    if cmd == "host-helper":
        try:
            from adscan_launcher.host_privileged_helper import run_host_helper_server
        except Exception as exc:
            capture_exception(exc)
            print_exception(exception=exc)
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

    # One-time promotion of a per-workspace telemetry opt-out to the global
    # preference, before anything can upload. Idempotent and best-effort.
    try:
        from adscan_core.telemetry_preference import migrate_and_notify

        migrate_and_notify()
    except Exception:
        pass

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
        # Same seam as `ci`: the posture toggles are consumed here and handed to
        # the container as environment, never as `adscan start` arguments.
        start_posture_env, _ = _posture_env_from_flags(ns, [])
        # PRO activation: persist + export the partner tag before the container
        # starts, so the in-container start gate finds it.
        _apply_partner_tag_flag(ns, [])
        # Fast pre-container gate: abort a PRO run with no resolvable partner tag
        # here, before spending a docker run. Runs AFTER activation so a run WITH
        # --partner-tag passes cleanly. No-op for LITE / when a tag is resolvable.
        _enforce_partner_tag_before_container()
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
                    extra_env=start_posture_env,
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
                    fix=bool(getattr(ns, "fix", False)),
                    verbose=bool(getattr(ns, "verbose", False)),
                    debug=bool(getattr(ns, "debug", False)),
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
        # Host-side pre-gate: skip the container entirely when the resolvable
        # tier is confirmed LITE. No-op (returns) for PRO / unresolvable —
        # the exit-42 backstop below still applies in that case.
        _maybe_pregate_pro_command(cmd, telemetry_console=telemetry_console)
        # Pass-through execution inside the container, but still do Docker-mode preflight.
        passthrough = list(getattr(ns, "args", []) or [])
        # argparse.REMAINDER keeps leading --, but may start with a "--" separator.
        if passthrough and passthrough[0] == "--":
            passthrough = passthrough[1:]
        # Translate the engagement-posture toggles (--offline / --no-telemetry)
        # into container environment variables. The flags are consumed here, NOT
        # forwarded into the container as `ci` args, because the internal runtime
        # honours them via env. ``_posture_env_from_flags`` also strips the
        # tokens out of the passthrough so a token that landed after the
        # auth/unauth positional (past argparse.REMAINDER's flag cut-off) still
        # takes effect and never reaches the container parser.
        posture_env, passthrough = _posture_env_from_flags(ns, passthrough)
        # PRO activation: validate + persist the partner tag and export it on
        # this process so the standard env forwarding carries it into the scan
        # container (the in-container gate otherwise refuses to start PRO).
        # Consumed at the seam and stripped from the passthrough, like the
        # toggles above.
        passthrough = _apply_partner_tag_flag(ns, passthrough)
        # Fast pre-container gate: abort a PRO run with no resolvable partner tag
        # here, before spending a docker run. Runs AFTER activation so a run WITH
        # --partner-tag passes cleanly. No-op for LITE / when a tag is resolvable.
        _enforce_partner_tag_before_container()
        # Translate --scan-config <host-path> into a read-only container mount +
        # ADSCAN_SCAN_CONFIG env var. Consumed at the seam and stripped from the
        # passthrough (mirrors the posture-toggle pattern). Absent = no-op.
        scan_config_env, scan_config_mounts, passthrough = _ci_scan_config_from_flags(
            ns, passthrough
        )
        # Copy a --client-logo host file into the mounted volume and rewrite the
        # flag to the container-visible path, so the post-scan report co-brands
        # its cover. Consumed at the seam, like --scan-config.
        passthrough = _ci_client_logo_from_flags(ns, passthrough)
        # --output <host-dir>: the report copy lands on the host (staged mount).
        passthrough, ci_output = _ci_output_from_flags(passthrough)
        ci_extra_env = list(posture_env) + list(scan_config_env)
        try:
            _ci_rc = _run_host_command_with_session_capture(
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
                    extra_rw_mounts=[ci_output.mount] if ci_output else None,
                ),
                extra={"mode": "docker", "session_scope": "launcher_preflight"},
                allowed_commands=set(SESSION_CAPTURE_ALLOWED_COMMANDS),
            )
        finally:
            if ci_output is not None:
                ci_output.finalize()
        if ci_output is not None and os.listdir(ci_output.dest_dir):
            print_info(f"Report folder: {ci_output.dest_dir}")
        raise SystemExit(_ci_handle_passthrough_rc(int(_ci_rc)))

    if cmd == "report":
        # Plain passthrough, no PRO-upsell gate — `report` is NOT PRO-gated,
        # it renders in either tier (see report_cmd.run_report_sync). Mirrors
        # `deliver`'s explicit-flag forwarding but skips
        # `_run_pro_passthrough_with_upsell_gate` since exit-42 never fires
        # for this command.
        report_args: list[str] = ["report"]
        report_workspace = getattr(ns, "workspace", None)
        if report_workspace:
            report_args.extend(["--workspace", str(report_workspace)])
        report_client = getattr(ns, "client", None)
        if report_client:
            report_args.extend(["--client", str(report_client)])
        report_frameworks = getattr(ns, "frameworks", None)
        if report_frameworks:
            report_args.extend(["--frameworks", str(report_frameworks)])
        if bool(getattr(ns, "debug", False)):
            report_args.append("--debug")
        raise SystemExit(
            _run_host_command_with_session_capture(
                command_type="report",
                telemetry_console=telemetry_console,
                runner=lambda: run_adscan_passthrough_docker(
                    adscan_args=report_args,
                    verbose=bool(getattr(ns, "verbose", False)),
                    debug=bool(getattr(ns, "debug", False)),
                    pull_timeout_seconds=3600,
                ),
                extra={"mode": "docker", "session_scope": "launcher_preflight"},
                allowed_commands=set(SESSION_CAPTURE_ALLOWED_COMMANDS) | {"report"},
            )
        )

    if cmd == "writeup":
        # Plain passthrough, no PRO-upsell gate — `writeup` is NOT PRO-gated,
        # it renders in either tier. Mirrors `report`'s explicit-flag
        # forwarding but skips `_run_pro_passthrough_with_upsell_gate` since
        # exit-42 never fires for this command.
        writeup_args: list[str] = ["writeup"]
        writeup_workspace = getattr(ns, "workspace", None)
        if writeup_workspace:
            writeup_args.extend(["--workspace", str(writeup_workspace)])
        if bool(getattr(ns, "full_credentials", False)):
            writeup_args.append("--full-credentials")
        writeup_output_dir = getattr(ns, "output_dir", None)
        if writeup_output_dir:
            writeup_args.append(str(writeup_output_dir))
        if bool(getattr(ns, "debug", False)):
            writeup_args.append("--debug")
        raise SystemExit(
            _run_host_command_with_session_capture(
                command_type="writeup",
                telemetry_console=telemetry_console,
                runner=lambda: run_adscan_passthrough_docker(
                    adscan_args=writeup_args,
                    verbose=bool(getattr(ns, "verbose", False)),
                    debug=bool(getattr(ns, "debug", False)),
                    pull_timeout_seconds=3600,
                ),
                extra={"mode": "docker", "session_scope": "launcher_preflight"},
                allowed_commands=set(SESSION_CAPTURE_ALLOWED_COMMANDS) | {"writeup"},
            )
        )

    if cmd == "run":
        # Engine contract entry. The plan decides the tier (a `scan` plan is the
        # `ci` gate, a `deliver` plan the `deliver` gate, `doctor` is free), so
        # the plan is read and validated host-side first.
        passthrough = list(getattr(ns, "run_args", []) or [])
        posture_env, passthrough = _posture_env_from_flags(ns, passthrough)
        passthrough = _apply_partner_tag_flag(ns, passthrough)
        run_io = _run_plan_io_from_flags(passthrough)
        # Both gates may exit; they run before any env: secret touches the disk.
        _maybe_pregate_pro_command(run_io.command, telemetry_console=telemetry_console)
        if run_io.command == "ci":
            _enforce_partner_tag_before_container()
        try:
            run_io = run_io.with_env_secrets()
            _run_rc = _run_host_command_with_session_capture(
                command_type=run_io.command,
                telemetry_console=telemetry_console,
                runner=lambda: run_adscan_passthrough_docker(
                    adscan_args=["run"] + run_io.passthrough,
                    verbose=bool(getattr(ns, "verbose", False)),
                    debug=bool(getattr(ns, "debug", False)),
                    pull_timeout_seconds=3600,
                    extra_env=list(posture_env) + list(run_io.extra_env),
                    extra_mounts=run_io.ro_mounts,
                    extra_rw_mounts=run_io.rw_mounts,
                    env_exclude_keys=run_io.env_exclude_keys,
                ),
                extra={"mode": "docker", "session_scope": "launcher_preflight", "entry": "run_plan"},
                allowed_commands=set(SESSION_CAPTURE_ALLOWED_COMMANDS) | {run_io.command},
            )
        finally:
            # The env: secrets were materialised for this container only.
            run_io.cleanup()
        if int(_run_rc) == 42:
            from adscan_core.cli_catalog import is_pro_only

            if is_pro_only(run_io.command):
                try:
                    _render_pro_upsell_and_record(run_io.command)
                except Exception as exc:  # noqa: BLE001 — best-effort upsell render
                    capture_exception(exc)
                    print_exception(exception=exc)
                raise SystemExit(PRO_GATE_EXIT_CODE)
        raise SystemExit(int(_run_rc))

    if cmd in ("execute", "doctor", "recheck"):
        # Container passthrough with launcher preflight + session capture.
        # The REMAINDER args were captured on the dest named "<cmd>_args"; any
        # leading option-looking token (e.g. `execute --list`) lands in
        # ``unknown`` instead, so we prepend it — everything the operator typed
        # after the verb is forwarded verbatim to the container (the container
        # subparser is the single source of truth for the flag surface).
        passthrough = list(unknown) + list(getattr(ns, f"{cmd}_args", []) or [])
        if passthrough and passthrough[0] == "--":
            passthrough = passthrough[1:]
        # `execute` and `recheck` are PRO: skip the container under a confirmed
        # LITE license, and honour exit-42 otherwise. A no-op for `doctor`,
        # which stays free.
        _maybe_pregate_pro_command(str(cmd), telemetry_console=telemetry_console)
        _passthrough_rc = _run_host_command_with_session_capture(
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
        raise SystemExit(_pro_passthrough_rc(str(cmd), int(_passthrough_rc)))

    if cmd == "engagement":
        # PRO: the engagement ledger. Gate host-side (a confirmed LITE licence
        # never starts the container), then forward verbatim like ``policy``;
        # the command reads and writes only inside the workspace mount.
        _maybe_pregate_pro_command(cmd, telemetry_console=telemetry_console)
        passthrough = list(unknown) + list(getattr(ns, "engagement_args", []) or [])
        if passthrough and passthrough[0] == "--":
            passthrough = passthrough[1:]
        raise SystemExit(
            run_adscan_passthrough_docker(
                adscan_args=["engagement"] + passthrough,
                verbose=bool(getattr(ns, "verbose", False)),
                debug=bool(getattr(ns, "debug", False)),
                pull_timeout_seconds=3600,
            )
        )

    if cmd == "pace":
        passthrough = list(unknown) + list(getattr(ns, "pace_args", []) or [])
        if passthrough and passthrough[0] == "--":
            passthrough = passthrough[1:]
        # Same file seam as `policy`: import reads a host file, export writes one.
        passthrough, ro_mounts, rw_mounts = _policy_file_mounts(passthrough)
        raise SystemExit(
            run_adscan_passthrough_docker(
                adscan_args=["pace"] + passthrough,
                verbose=bool(getattr(ns, "verbose", False)),
                debug=bool(getattr(ns, "debug", False)),
                pull_timeout_seconds=3600,
                extra_mounts=ro_mounts,
                extra_rw_mounts=rw_mounts,
            )
        )

    if cmd == "policy":
        passthrough = list(unknown) + list(getattr(ns, "policy_args", []) or [])
        if passthrough and passthrough[0] == "--":
            passthrough = passthrough[1:]
        passthrough, ro_mounts, rw_mounts = _policy_file_mounts(passthrough)
        raise SystemExit(
            run_adscan_passthrough_docker(
                adscan_args=["policy"] + passthrough,
                verbose=bool(getattr(ns, "verbose", False)),
                debug=bool(getattr(ns, "debug", False)),
                pull_timeout_seconds=3600,
                extra_mounts=ro_mounts,
                extra_rw_mounts=rw_mounts,
            )
        )

    if cmd in _DELIVERABLE_PASSTHROUGH_COMMANDS:
        # Host-side pre-gate: no-op for LITE-tier deliverables (cheatsheet,
        # mitre-navigator) since `is_pro_only` gates first; skips the
        # container for `deliver` under a confirmed LITE license.
        _maybe_pregate_pro_command(cmd, telemetry_console=telemetry_console)
        deliv_args: list[str] = [cmd]
        deliv_outputs: list[_HostOutput] = []
        output_path = getattr(ns, "output_path", None)
        if output_path:
            # ``deliver --output`` names a folder; the single-PDF deliverables
            # (cheatsheet) name a file. Either way it is a HOST path: stage it.
            host_output = _host_output_mount(str(output_path), is_file=cmd != "deliver")
            deliv_outputs.append(host_output)
            deliv_args.extend(["--output", host_output.container_arg])
        if bool(getattr(ns, "no_open", False)):
            deliv_args.append("--no-open")
        if bool(getattr(ns, "no_render", False)):
            deliv_args.append("--no-render")
        # ``deliver``-specific flags. Using ``ws_*`` dests on the host parser
        # avoids clobbering the launcher's own ``output_path``/``no_render``
        # while still surfacing the container's full flag set in --help.
        if cmd == "deliver":
            ws_workspace = getattr(ns, "ws_workspace", None)
            if ws_workspace:
                deliv_args.extend(["--workspace", str(ws_workspace)])
            # Every deliverable option, re-emitted from the shared model. Cover,
            # back and progress-model paths are read inside the container (a
            # path under the mounted volume or the workspace); the client logo
            # is a HOST file, so it is staged into the volume first.
            deliv_args.extend(
                _forward_report_options(ns, dest_prefix="ws_", exclude=("client_logo",))
            )
            ws_client_logo = getattr(ns, "ws_client_logo", None)
            if ws_client_logo:
                staged_logo = _stage_client_logo(str(ws_client_logo))
                if staged_logo:
                    deliv_args.extend(["--client-logo", staged_logo])
            ws_progress_model = getattr(ns, "ws_progress_model", None)
            if ws_progress_model:
                deliv_args.extend(["--progress-model", str(ws_progress_model)])
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
                host_output = _host_output_mount(str(nav_output), is_file=False)
                deliv_outputs.append(host_output)
                deliv_args.extend(["--output", host_output.container_arg])
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
        try:
            deliv_rc = _run_pro_passthrough_with_upsell_gate(
                cmd=str(cmd),
                adscan_args=deliv_args,
                verbose=bool(getattr(ns, "verbose", False)),
                debug=bool(getattr(ns, "debug", False)),
                pull_timeout_seconds=3600,
                extra_rw_mounts=[output.mount for output in deliv_outputs],
            )
        finally:
            for output in deliv_outputs:
                output.finalize()
        raise SystemExit(deliv_rc)

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
