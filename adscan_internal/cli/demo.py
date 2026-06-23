"""``adscan demo`` — deterministic, replayable demo scan against a baked-in fake AD.

The demo is the lead-magnet command: pentesters install ADscan, run ``adscan demo``,
and 60-90 seconds later have a polished PDF in their workspace ready to show their
boss. There is **no** network activity, no DC, no VPN, no lab — every line of output
is scripted; the only real work is the final PDF generation against a baked-in
``technical_report.json`` fixture.

Goals:
    - Sub-90s end-to-end (configurable via ``--fast`` for ~12s capture).
    - Premium aesthetic — uses ``print_phase_ribbon`` / ``print_phase_recap`` /
      ``print_panel`` so it matches the rest of the runtime.
    - The PDF is **real** (engine + renderer + template are exercised end-to-end);
      only the input data is canned.

Module is loaded from both:
    - ``adscan demo`` (top-level CLI in ``adscan.py``)
    - The launcher passthrough (``adscan_launcher/cli.py`` registers ``demo`` and
      forwards into the container).
"""

from __future__ import annotations

import argparse
import os
import random
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from adscan_core import telemetry
from adscan_core.paths import get_workspaces_dir
from adscan_core.posture_score import PostureInputs, PostureScore, compute_posture_score
from adscan_core.rich_output import (
    print_error,
    print_info,
    print_panel,
    print_success,
    print_warning,
)
from adscan_core.rich_output_collection import (
    print_phase_ribbon,
    print_phase_recap,
)

from adscan_core import tier
from adscan_core.paths import get_adscan_home_dir
from adscan_internal.cli._sample_kit import all_samples, samples_dir
from adscan_internal.services.host_open import display_host_path, prompt_and_open


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# Cast file path — override via ADSCAN_DEMO_CAST env var or replace the
# placeholder file at adscan_internal/assets/demo_workspace/demo.cast with a
# real asciinema v2 recording.
DEMO_CAST_PATH = Path(
    os.environ.get("ADSCAN_DEMO_CAST", "")
    or Path(__file__).resolve().parents[1] / "assets" / "demo_workspace" / "demo.cast"
)

DEMO_DOMAIN = "essos.local"
DEMO_WORKSPACE_NAME = "demo-goad"
DEMO_REPORT_FILENAME = "Sample_Report.pdf"
DEMO_KIT_FILENAME = "Sample_Kit.zip"
DEMO_DOCS_URL = "https://adscanpro.com/docs"

# Color tokens (mirrors adscan_core.theme — kept inline so we don't widen the
# public theme surface for one command).
_CYAN = "#1AA0AE"  # ADscan brand teal (on-dark accent, site --brand-accent); name kept for call-site stability
_AMBER = "#FF9500"
_CRIMSON = "#DC2626"
_STEEL = "#4A9EBA"
_MUTED = "grey50"


# ---------------------------------------------------------------------------
# Phase scripts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _ScriptLine:
    """One scripted output line for a demo phase.

    Attributes:
        text: Rich-markup string to print.
        delay_after: Seconds to sleep AFTER this line in default pacing
            (jittered ±15% at runtime; multiplied by ``fast_factor`` in
            ``--fast`` mode).
        kind: Semantic role — drives the leading glyph and color.
            One of: ``"step"``, ``"ok"``, ``"warn"``, ``"crit"``.
    """

    text: str
    delay_after: float
    kind: str = "step"


@dataclass(frozen=True)
class _Phase:
    """One named phase in the demo timeline."""

    name: str
    lines: tuple[_ScriptLine, ...]
    yielded: bool  # True when the phase produced operationally interesting output


_PHASES: tuple[_Phase, ...] = (
    _Phase(
        name="Reconnaissance",
        yielded=True,
        lines=(
            _ScriptLine("Resolving domain controllers via DNS SRV records…", 1.6),
            _ScriptLine("DC01.north-haven.local · 10.42.10.10", 0.8, "ok"),
            _ScriptLine("DC02.north-haven.local · 10.42.10.11", 0.8, "ok"),
            _ScriptLine("Mapping subnets from sites & services", 1.4),
            _ScriptLine("4 subnets identified · 2 sites", 0.6, "ok"),
        ),
    ),
    _Phase(
        name="Anonymous enumeration",
        yielded=True,
        lines=(
            _ScriptLine("Probing LDAP anonymous bind on DC01…", 1.4),
            _ScriptLine("Anonymous LDAP rejected — enumerating via authenticated path", 0.9),
            _ScriptLine("Pulled 14 user objects · 6 computers · 4 groups", 1.4, "ok"),
            _ScriptLine("DC01, DC02, FS01, SQL01, WKS-FIN-04, WKS-FIN-12", 0.8),
            _ScriptLine("Privileged groups: Domain Admins · Enterprise Admins · Tier0-Admins", 1.0, "ok"),
        ),
    ),
    _Phase(
        name="Authenticated assessment",
        yielded=True,
        lines=(
            _ScriptLine("Querying SPNs for kerberoastable accounts…", 1.6),
            _ScriptLine("svc_sql — TGS extracted, member of Backup Operators (Tier-0)", 1.0, "warn"),
            _ScriptLine("Probing accounts without Kerberos pre-auth…", 1.4),
            _ScriptLine("helpdesk_admin — AS-REP roastable", 0.9, "warn"),
            _ScriptLine("Auditing ADCS templates on NorthHaven-CA01…", 1.6),
            _ScriptLine("NorthHaven-WebServer — ESC1 (enrollee supplies subject)", 1.0, "crit"),
            _ScriptLine("Sweeping SMB shares for plaintext credentials…", 1.4),
            _ScriptLine("FS01\\Public — credential pattern in handover_notes.txt:47", 0.9, "warn"),
        ),
    ),
    _Phase(
        name="Attack path analysis",
        yielded=True,
        lines=(
            _ScriptLine("Building reachability graph from 14 principals…", 1.6),
            _ScriptLine("Materializing edges: GenericAll · ADCSESC1 · MemberOf · DCSync", 1.4),
            _ScriptLine("3 paths to Domain Admin · 1 path to Tier-0 group", 1.0, "crit"),
            _ScriptLine("Top choke point: NorthHaven-WebServer template (blast radius 184)", 1.0, "warn"),
        ),
    ),
    _Phase(
        name="Report generation",
        yielded=True,
        lines=(
            _ScriptLine("Composing executive narrative…", 0.8),
            _ScriptLine("Rendering attack path diagrams (Cytoscape)…", 1.0),
            _ScriptLine("Materializing Chromium PDF…", 0.4),
        ),
    ),
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _line_glyph_and_color(kind: str) -> tuple[str, str]:
    """Return (glyph, rich-color) for a scripted line kind."""
    return {
        "step": ("▸", _STEEL),
        "ok": ("✓", _CYAN),
        "warn": ("⚠", _AMBER),
        "crit": ("✗", _CRIMSON),
    }.get(kind, ("▸", _STEEL))


def _jitter(value: float, fast_factor: float, *, rng: random.Random) -> float:
    """Apply ±15% jitter and the fast-mode compression factor.

    The RNG is caller-controlled so tests can pin pacing deterministically.
    """
    if fast_factor <= 0:
        return 0.0
    multiplier = 1.0 + (rng.random() * 0.30 - 0.15)
    return max(0.0, value * fast_factor * multiplier)


def _resolve_demo_fixture_dir() -> Path:
    """Locate the baked-in fixture directory.

    Resolves to ``adscan_internal/assets/demo_workspace`` whether running from
    Python source (LITE) or the PyInstaller binary (PRO). PyInstaller copies the
    datas tree relative to ``_MEIPASS`` at the same package-relative path, so a
    ``Path(__file__).resolve().parents[1] / "assets" / "demo_workspace"`` walk
    works for both.
    """
    return (
        Path(__file__).resolve().parents[1] / "assets" / "demo_workspace"
    )


def _print_title_banner() -> None:
    """Print the opening banner that frames the demo."""
    body = (
        f"[bold {_STEEL}]GOAD reference lab[/]   "
        f"[{_MUTED}]·[/]   "
        f"[{_CYAN}]60-second tour[/]\n"
        f"[{_MUTED}]Real Active Directory engagement, end to end · "
        f"deterministic, replayable, safe to demo to your boss.[/]"
    )
    print_panel(
        body,
        title=f"[bold {_CYAN}]ADSCAN DEMO[/]   "
              f"[{_MUTED}]·[/]   "
              f"[bold]{DEMO_DOMAIN}[/]",
        border_style=_CYAN,
        title_align="left",
    )


def _print_kpi_tile(*, posture_score: int, delta: int, paths_to_da: int) -> None:
    """Print the closing KPI tile mirroring the PDF page-2 KPIs."""
    body = (
        f"[{_MUTED}]POSTURE SCORE[/]            "
        f"[{_MUTED}]Δ FROM CLEAN[/]            "
        f"[{_MUTED}]PATHS TO DA[/]\n"
        f"[bold {_CRIMSON}]   {posture_score:>2}/100[/]                 "
        f"[bold {_AMBER}]    +{delta}[/]                  "
        f"[bold {_CRIMSON}]    {paths_to_da}[/]"
    )
    print_panel(
        body,
        border_style=_CYAN,
    )


def _print_next_steps() -> None:
    """Print the closing call-to-action."""
    body = (
        f"[bold {_CYAN}]•[/] Run against your own domain:\n"
        f"    [bold]adscan start[/]\n"
        f"[bold {_CYAN}]•[/] Read the playbook:\n"
        f"    [bold]{DEMO_DOCS_URL}[/]"
    )
    print_panel(body, title=f"[bold {_CYAN}]NEXT STEPS[/]", border_style=_CYAN)


def _emit_scripted_line(line: _ScriptLine) -> None:
    """Print one scripted line.

    The ``print_*`` helpers prepend their own brand glyph (ℹ, ✓, ⚠, ✗); we lean
    on those rather than emitting a redundant marker so the demo output reads
    the same as a real ADscan scan.
    """
    if line.kind == "warn":
        print_warning(line.text)
    elif line.kind == "crit":
        print_error(line.text)
    elif line.kind == "ok":
        print_success(line.text)
    else:
        print_info(line.text)


def _run_phase(
    *,
    index: int,
    total: int,
    phase: _Phase,
    fast_factor: float,
    sleep_fn,
    rng: random.Random,
) -> None:
    """Render one phase: live ribbon, scripted lines, terminal ribbon."""
    print_phase_ribbon(
        index=index, total=total, name=phase.name, status="live",
    )
    for line in phase.lines:
        _emit_scripted_line(line)
        delay = _jitter(line.delay_after, fast_factor, rng=rng)
        if delay > 0:
            sleep_fn(delay)
    print_phase_ribbon(
        index=index,
        total=total,
        name=phase.name,
        status="yielded" if phase.yielded else "done",
    )


def _copy_fixture_into_workspace(workspace_dir: Path) -> Path:
    """Copy the baked-in fixture into the user's workspace directory.

    Returns the path to the copied ``technical_report.json``.
    """
    fixture_dir = _resolve_demo_fixture_dir()
    src = fixture_dir / "technical_report.json"
    if not src.is_file():
        raise FileNotFoundError(
            f"Demo fixture not found at {src}. The asset may be missing from "
            f"this build."
        )
    workspace_dir.mkdir(parents=True, exist_ok=True)
    dest = workspace_dir / "technical_report.json"
    shutil.copyfile(src, dest)
    return dest


def _compute_demo_posture(technical_report_path: Path) -> PostureScore:
    """Score the demo fixture with the canonical posture algorithm.

    The fixture is the same JSON the PDF is generated from, so the recap
    KPI and the PDF money-shot stay in lock-step automatically.
    """
    import json as _json

    raw = _json.loads(technical_report_path.read_text(encoding="utf-8"))
    domains = raw.get("domains", {}) if isinstance(raw, dict) else {}
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    paths_to_da = 0
    tier0_targets: set[str] = set()
    tier0_outcomes = {"direct_domain_control", "domain_compromise_enabler"}

    iter_domains = (
        domains.values() if isinstance(domains, dict) else list(domains)
    )
    for domain_data in iter_domains:
        if not isinstance(domain_data, dict):
            continue
        for finding in domain_data.get("findings", []) or []:
            sev = str(finding.get("severity") or "").lower()
            if sev in counts:
                counts[sev] += 1
        for path in domain_data.get("attack_paths", []) or []:
            outcome = str(path.get("outcome_class") or "").strip().lower()
            target = str(path.get("target") or "").strip().lower()
            # Demo paths use ``direct_compromise``/``followup_terminal`` against
            # privileged groups; treat any path landing on a Tier-0 target as a
            # path-to-DA for the canonical score.
            looks_da = (
                outcome in tier0_outcomes
                or "domain admins" in target
                or "tier0" in target
                or "tier-0" in target
                or "enterprise admins" in target
            )
            if looks_da:
                paths_to_da += 1
                if target:
                    tier0_targets.add(target)

    return compute_posture_score(
        PostureInputs(
            critical_findings=counts["critical"],
            high_findings=counts["high"],
            medium_findings=counts["medium"],
            low_findings=counts["low"],
            paths_to_da=paths_to_da,
            tier0_exposed=len(tier0_targets),
        )
    )


def _generate_demo_pdf(
    *,
    technical_report_path: Path,
    out_path: Path,
    workspace_name: str,
) -> int:
    """Render the real PDF from the fixture. Returns bytes written."""
    # Deferred import — orchestrator pulls in heavy reporting deps that we want
    # to skip entirely under ``--no-pdf``.
    import json as _json

    from adscan_internal.pro.reporting.orchestrator import (
        describe_runtime,
        generate_report_pdf,
    )

    runtime = describe_runtime()
    chromium_state = runtime["engines"].get("chromium", {})
    if not chromium_state.get("available"):
        reason = chromium_state.get("reason", "unknown")
        raise RuntimeError(
            f"Chromium engine unavailable ({reason}). "
            f"Install Playwright + Chromium first."
        )

    raw = _json.loads(technical_report_path.read_text(encoding="utf-8"))
    if isinstance(raw, dict) and "domains" in raw and isinstance(raw["domains"], dict):
        report_data = raw["domains"]
    else:
        report_data = raw

    metadata = {
        "workspace_name": workspace_name,
        "report_date": time.strftime("%B %d, %Y"),
        "report_type": "Active Directory Security Assessment (Demo)",
        "report_version": "ADscan",
    }

    pdf_bytes = generate_report_pdf(
        report_data,
        metadata=metadata,
        report_profile="full",
        frameworks=["pci_dss", "ens"],
        engine="chromium",
        renderer="cytoscape",
        template="premium",
        theme="premium_dark",
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(pdf_bytes)
    return len(pdf_bytes)




# ---------------------------------------------------------------------------
# Tier-aware demo output (LITE vs PRO)
# ---------------------------------------------------------------------------


_PRO_PREVIEW_README = """These PDFs are real samples generated by ADscan PRO
against the same north-haven.local scan you just ran.

Reproduce against your own domain:
  adscan upgrade

- Security_Assessment_Report.pdf
- AD_Hardening_Playbook.pdf
- AD_Control_Coverage_Report.pdf
"""


def _demo_output_root() -> Path:
    """Return ``~/.adscan/demo-output`` — host or container, same path resolver."""
    return (get_adscan_home_dir() / "demo-output").resolve()


def _lite_paths() -> tuple[Path, Path]:
    """Return ``(lite_dir, pro_preview_dir)`` for the LITE demo output."""
    root = _demo_output_root()
    return root / "lite", root / "pro-preview"


def _stage_pro_preview(pro_preview_dir: Path) -> int:
    """Copy the bundled sample PDFs into ``pro_preview_dir``.

    Returns the number of PDFs that were copied. Missing source files
    are skipped silently — the closing panel still renders so the demo
    never hard-fails on a partial asset bundle.
    """
    pro_preview_dir.mkdir(parents=True, exist_ok=True)
    src_dir = samples_dir()
    copied = 0
    for sample in all_samples():
        src = src_dir / sample.filename
        if not src.is_file():
            continue
        shutil.copyfile(src, pro_preview_dir / sample.filename)
        copied += 1
    (pro_preview_dir / "README.txt").write_text(_PRO_PREVIEW_README, encoding="utf-8")
    return copied


def _render_lite_closing_panel(*, lite_dir: Path, pro_preview_dir: Path) -> None:
    """Print the LITE demo closing panel — premium cyan, mono paths."""
    from rich.console import Group
    from rich.text import Text

    eyebrow = Text("DEMO COMPLETE", style="bold bright_cyan")

    lite_line = Text()
    lite_line.append("Your LITE report:    ", style="bold")
    lite_line.append(str(lite_dir) + "/", style="bright_cyan on grey11")

    pro_line = Text()
    pro_line.append("PRO sample kit:      ", style="bold")
    pro_line.append(str(pro_preview_dir) + "/", style="bright_cyan on grey11")

    tagline = Text("PRO ships these for every engagement.", style="dim")

    cta = Text()
    cta.append("Upgrade: ", style="bold")
    cta.append("https://adscanpro.com/pro", style="bold bright_cyan")

    body = Group(
        eyebrow,
        Text(""),
        lite_line,
        pro_line,
        Text(""),
        tagline,
        cta,
    )
    print_panel(body, border_style="bright_cyan", padding=(1, 2))


def _render_pro_closing_panel(*, output_dir: Path) -> None:
    """Print the PRO demo closing one-liner panel."""
    from rich.text import Text

    line = Text()
    line.append("Demo complete. Output: ", style="bold")
    line.append(display_host_path(output_dir) + "/", style="bright_cyan on grey11")
    print_panel(line, border_style="bright_cyan", padding=(1, 2))


def _run_lite_demo(
    *,
    workspace_dir: Path,
    no_pdf: bool,
) -> int:
    """LITE demo flow: stage workspace, copy sample kit, render closing panel.

    Returns the process exit code. The LITE engine does not include the
    PRO reporting orchestrator, so we deliberately skip live PDF
    generation and surface the bundled samples as a credible preview.
    """
    try:
        _copy_fixture_into_workspace(workspace_dir)
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error(f"Failed to stage demo workspace: {exc}")
        return 1

    lite_dir, pro_preview_dir = _lite_paths()
    lite_dir.mkdir(parents=True, exist_ok=True)
    # Mirror the staged workspace into demo-output/lite/ so the operator
    # has a single, predictable address for the LITE artefacts.
    try:
        for child in workspace_dir.iterdir():
            if child.is_file():
                shutil.copyfile(child, lite_dir / child.name)
    except Exception as exc:  # noqa: BLE001 — best-effort mirroring
        telemetry.capture_exception(exc)

    if no_pdf:
        print_info("Skipping PDF generation (--no-pdf).")

    try:
        copied = _stage_pro_preview(pro_preview_dir)
        if copied == 0:
            print_warning("PRO sample kit not bundled with this build.")
    except Exception as exc:  # noqa: BLE001 — preview is non-fatal
        telemetry.capture_exception(exc)
        print_warning(f"Could not stage PRO sample kit: {exc}")

    _render_lite_closing_panel(lite_dir=lite_dir, pro_preview_dir=pro_preview_dir)
    return 0


# ---------------------------------------------------------------------------
# Cast-played artifact staging — bundled kit, no live regeneration
# ---------------------------------------------------------------------------


def _stage_demo_kit(workspace_dir: Path) -> Path:
    """Stage the bundled demo artefacts into the user's workspace.

    Reproduces the layout of a real engagement:

    - ``<workspace>/report.pdf`` — the full technical report
      (output of ``adscan generate_report``).
    - ``<workspace>/deliverables/<kit>.zip`` — the client kit
      (output of ``adscan deliver``).
    - ``<workspace>/deliverables/`` — the deliverable PDFs and MITRE
      Navigator bonus extracted from the kit for direct access.

    Returns the path to the full ``report.pdf``, used by the "Open it now?"
    prompt as the natural entry point (most complete deliverable).
    """
    import zipfile

    fixture_dir = _resolve_demo_fixture_dir()
    bundled_zip = fixture_dir / DEMO_KIT_FILENAME
    bundled_full_report = fixture_dir / DEMO_REPORT_FILENAME

    if not bundled_zip.is_file():
        raise FileNotFoundError(
            f"Demo kit not bundled with this build: {bundled_zip}. "
            "The asset may be missing from this build."
        )
    if not bundled_full_report.is_file():
        raise FileNotFoundError(
            f"Demo report not bundled with this build: {bundled_full_report}. "
            "The asset may be missing from this build."
        )

    workspace_dir.mkdir(parents=True, exist_ok=True)
    deliverables_dir = workspace_dir / "deliverables"
    deliverables_dir.mkdir(parents=True, exist_ok=True)

    # Full technical report at workspace root.
    full_report_path = workspace_dir / DEMO_REPORT_FILENAME
    shutil.copyfile(bundled_full_report, full_report_path)

    # Client kit ZIP under deliverables/.
    staged_zip = deliverables_dir / bundled_zip.name
    shutil.copyfile(bundled_zip, staged_zip)

    # Extract the kit alongside the ZIP for direct access.
    with zipfile.ZipFile(bundled_zip) as zf:
        zf.extractall(deliverables_dir)

    return full_report_path


def _render_lite_cast_closing_panel(*, workspace_dir: Path) -> None:
    """LITE closing panel after a cast-played demo.

    The artefacts shipped with the demo are what ADscan PRO produces; the
    LITE binary cannot regenerate them. Use the panel to pitch the upgrade.
    """
    from rich.console import Group
    from rich.text import Text

    eyebrow = Text("DEMO READY", style="bold bright_cyan")

    deliverable_line = Text()
    deliverable_line.append("Deliverable:  ", style="bold")
    deliverable_line.append(
        display_host_path(workspace_dir / DEMO_REPORT_FILENAME),
        style="bright_cyan on grey11",
    )

    bonus_line = Text()
    bonus_line.append("Bonus kit:    ", style="bold")
    bonus_line.append(
        display_host_path(workspace_dir / "deliverables") + "/",
        style="bright_cyan on grey11",
    )

    tagline = Text(
        "This is what ADscan PRO produces for every engagement.",
        style="dim",
    )

    cta = Text()
    cta.append("Upgrade: ", style="bold")
    cta.append("https://adscanpro.com/pro", style="bold bright_cyan")

    body = Group(
        eyebrow,
        Text(""),
        deliverable_line,
        bonus_line,
        Text(""),
        tagline,
        cta,
    )
    print_panel(body, border_style="bright_cyan", padding=(1, 2))


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def add_demo_subparser(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """Register the ``demo`` subparser on the main argparse tree."""
    parser = subparsers.add_parser(
        "demo",
        help="Run a deterministic 60-second demo scan against a baked-in fake AD.",
        description=(
            "Run a deterministic, replayable demo scan against a baked-in fake AD "
            f"environment ({DEMO_DOMAIN}) and produce a real ADscan PDF report.\n"
            "No network, no DC, no lab — perfect for a 60-second pitch.\n\n"
            "To use a real recording instead of the scripted demo:\n"
            "  asciinema rec demo.cast   # record a real ADscan session\n"
            "  # then move demo.cast to:\n"
            f"  #   adscan_internal/assets/demo_workspace/demo.cast\n"
            "  # or set ADSCAN_DEMO_CAST=/path/to/demo.cast\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Compress phase pacing to ~12s (CI / marketing capture).",
    )
    parser.add_argument(
        "--no-pdf",
        action="store_true",
        help="Skip PDF generation (headless smoke).",
    )
    parser.add_argument(
        "--output",
        dest="output_path",
        default=None,
        help="Override the output PDF path. Default: "
             f"~/.adscan/workspaces/{DEMO_WORKSPACE_NAME}/{DEMO_REPORT_FILENAME}",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for jitter (default: 42 — keeps pacing reproducible).",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable debug output (forwarded to verbose mode).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output.",
    )
    parser.add_argument(
        "--dev",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--scripted",
        action="store_true",
        help="Force the scripted demo even if a .cast recording exists.",
    )
    return parser


def run_demo(args: argparse.Namespace) -> int:
    """Run the demo flow end-to-end. Returns process exit code."""
    fast = bool(getattr(args, "fast", False))
    no_pdf = bool(getattr(args, "no_pdf", False))
    output_override = getattr(args, "output_path", None)
    seed = int(getattr(args, "seed", 42) or 42)

    fast_factor = 0.18 if fast else 1.0
    rng = random.Random(seed)
    sleep_fn = time.sleep

    try:
        # If a real .cast recording exists and --scripted was not requested,
        # replay it directly and skip the scripted phases entirely.
        scripted = bool(getattr(args, "scripted", False))
        if DEMO_CAST_PATH.is_file() and not scripted:
            from adscan_internal.cli.cast_player import play_cast

            _print_title_banner()
            cast_played = False
            try:
                play_cast(DEMO_CAST_PATH, fast_factor=fast_factor, idle_time_limit=3.0)
                cast_played = True
            except Exception as exc:
                telemetry.capture_exception(exc)
                print_warning(f"Cast playback failed ({exc}), falling back to scripted demo.")

            if cast_played:
                # After cast playback, stage the bundled GOAD kit into the
                # user's workspace. The kit is the same artefact the cast
                # showed `adscan deliver` produce — coherent narrative,
                # tangible artefact, no live regeneration required.
                if output_override:
                    workspace_dir = Path(output_override).expanduser().resolve().parent
                else:
                    workspace_dir = (get_workspaces_dir() / DEMO_WORKSPACE_NAME).resolve()

                try:
                    full_report_pdf = _stage_demo_kit(workspace_dir)
                except Exception as exc:
                    telemetry.capture_exception(exc)
                    print_error(f"Failed to stage demo kit: {exc}")
                    return 1

                print_success(f"Demo ready: {display_host_path(workspace_dir)}")

                if tier.is_pro():
                    _render_pro_closing_panel(output_dir=workspace_dir)
                else:
                    _render_lite_cast_closing_panel(workspace_dir=workspace_dir)

                _print_next_steps()
                prompt_and_open(full_report_pdf)
                return 0

        _print_title_banner()

        total = len(_PHASES)
        for idx, phase in enumerate(_PHASES, start=1):
            _run_phase(
                index=idx,
                total=total,
                phase=phase,
                fast_factor=fast_factor,
                sleep_fn=sleep_fn,
                rng=rng,
            )

        # Workspace + fixture
        if output_override:
            pdf_path = Path(output_override).expanduser().resolve()
            workspace_dir = pdf_path.parent
        else:
            workspace_dir = (get_workspaces_dir() / DEMO_WORKSPACE_NAME).resolve()
            pdf_path = workspace_dir / DEMO_REPORT_FILENAME

        # Tier-aware branch: LITE skips live PDF generation (the PRO
        # reporting orchestrator is absent from the LITE binary) and
        # ships the bundled sample kit as a preview instead.
        if not tier.is_pro():
            return _run_lite_demo(workspace_dir=workspace_dir, no_pdf=no_pdf)

        try:
            technical_report_path = _copy_fixture_into_workspace(workspace_dir)
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_error(f"Failed to stage demo workspace: {exc}")
            return 1

        # Compute the demo posture from the same fixture the PDF will use,
        # so the recap tile and the report's hero numeral match by construction.
        try:
            demo_posture = _compute_demo_posture(technical_report_path)
        except Exception as exc:  # noqa: BLE001 — demo recap must not crash
            telemetry.capture_exception(exc)
            demo_posture = compute_posture_score(PostureInputs())

        # Findings + paths counted from the fixture for honest recap copy.
        try:
            import json as _json_demo
            _raw_demo = _json_demo.loads(technical_report_path.read_text(encoding="utf-8"))
            _domains_demo = _raw_demo.get("domains", {}) if isinstance(_raw_demo, dict) else {}
            _iter = (
                _domains_demo.values() if isinstance(_domains_demo, dict) else list(_domains_demo)
            )
            findings_total = sum(
                len(d.get("findings", []) or []) for d in _iter if isinstance(d, dict)
            )
            paths_total = sum(
                len(d.get("attack_paths", []) or []) for d in _iter if isinstance(d, dict)
            )
        except Exception:  # noqa: BLE001
            findings_total, paths_total = 8, 3

        # Final PDF generation (the only "real" work)
        pdf_bytes_len = 0
        if no_pdf:
            print_info("Skipping PDF generation (--no-pdf).")
        else:
            try:
                pdf_bytes_len = _generate_demo_pdf(
                    technical_report_path=technical_report_path,
                    out_path=pdf_path,
                    workspace_name=DEMO_WORKSPACE_NAME,
                )
            except Exception as exc:
                telemetry.capture_exception(exc)
                print_error(f"Demo PDF generation failed: {exc}")
                # Still print the recap and next-steps panel — the workspace was
                # staged successfully and the operator may want to retry with
                # ``adscan report --workspace demo-north-haven``.
                print_phase_recap(
                    title="Demo complete (PDF skipped)",
                    phases_total=total,
                    phases_yielded=sum(1 for p in _PHASES if p.yielded),
                    extra_metrics=(
                        (str(paths_total), "paths to DA"),
                        (str(findings_total), "findings"),
                    ),
                )
                _print_next_steps()
                return 1

        # Recap line, KPI tile, location, next steps
        print_phase_recap(
            title="Demo complete",
            phases_total=total,
            phases_yielded=sum(1 for p in _PHASES if p.yielded),
            extra_metrics=(
                (str(paths_total), "paths to DA"),
                (str(findings_total), "findings"),
                (f"{demo_posture.score}/100", f"posture · {demo_posture.label.lower()}"),
            ),
        )

        _print_kpi_tile(
            posture_score=demo_posture.score,
            delta=5,
            paths_to_da=paths_total,
        )

        if no_pdf:
            print_success(
                f"Workspace staged: {workspace_dir} "
                f"(run: adscan report --workspace {DEMO_WORKSPACE_NAME})"
            )
        else:
            kb = pdf_bytes_len / 1024.0
            print_success(
                f"Report ready: {pdf_path}  ({kb:,.0f} KB)"
            )

        _render_pro_closing_panel(output_dir=workspace_dir)
        _print_next_steps()

        if not no_pdf:
            prompt_and_open(pdf_path)

        return 0
    except KeyboardInterrupt:
        print_warning("Demo cancelled.")
        return 130
    except Exception as exc:  # noqa: BLE001 — top-level safety net
        telemetry.capture_exception(exc)
        print_error(f"Demo failed: {exc}")
        return 1


__all__: Sequence[str] = (
    "DEMO_CAST_PATH",
    "DEMO_DOMAIN",
    "DEMO_WORKSPACE_NAME",
    "DEMO_REPORT_FILENAME",
    "add_demo_subparser",
    "run_demo",
)
