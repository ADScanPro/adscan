"""``adscan mitre-navigator`` — export MITRE ATT&CK Navigator artefacts.

LITE tier (community attraction offer):
    Writes a single ``navigator-layer.json`` snapshot stamped with the
    ``ADscan Community`` watermark to the workspace's ``mitre/`` folder.
    The artefact loads directly in the official MITRE ATT&CK Navigator UI
    at https://mitre-attack.github.io/attack-navigator/ — no server, no
    account, no extra tooling. The watermark is preserved as Navigator
    metadata so every shared layer carries the source attribution.

PRO tier (premium UX & retainer driver):
    Adds three artefacts to every export:

        * Enriched ``navigator-layer.json`` (no community watermark; PRO
          attribution + engagement metadata).
        * ``navigator.html`` — self-contained interactive bundle with KPI
          strip, severity filters, technique drawer, "Open in MITRE
          Navigator" deep link, and a "Diff vs previous" tab when a
          baseline snapshot exists. No server, no CDN, opens offline.
        * History snapshot under ``mitre/history/<UTC-timestamp>.json``
          plus a ``navigator-diff-layer.json`` against the prior snapshot
          when one is available — the artefact that justifies recurring
          assessments and annual retainers.

The ``--web`` flag opens the generated ``navigator.html`` in the user's
default browser at the end of the run (PRO only). The ``--no-html`` flag
suppresses the interactive bundle (useful in CI). The ``--no-history``
flag skips the history snapshot (useful when re-rendering off an
existing report without a fresh scan).
"""

from __future__ import annotations

import argparse
import json
import os
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from adscan_core import telemetry, tier
from adscan_core.pal.paths import get_workspaces_dir
from adscan_core.reporting.finding_vuln_map import build_vuln_map_from_findings
from adscan_core.rich_output import (
    print_error,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_success,
    print_warning,
)
from adscan_internal.services.mitre_navigator import (
    WATERMARK_COMMUNITY,
    WATERMARK_PRO,
    build_diff_layer,
    build_navigator_layer,
    diff_summary,
)
from adscan_core.rich_output import print_exception


# ---------------------------------------------------------------------------
# Workspace resolution (kept local — deliver.py's helper is PRO-only).
# ---------------------------------------------------------------------------
def _workspaces_root() -> Path:
    """Return the workspaces root, container path first, host fallback."""
    container = get_workspaces_dir()
    if container.is_dir():
        return container
    return Path.home() / ".adscan" / "workspaces"


def _resolve_workspace(args: argparse.Namespace) -> Path | None:
    """Resolve the target workspace directory.

    Order: explicit ``--workspace``, ``ADSCAN_CURRENT_WORKSPACE`` env
    var, most-recent workspace under the workspaces root.
    """
    explicit = getattr(args, "workspace", None)
    if explicit:
        candidate = Path(explicit).expanduser()
        if not candidate.is_absolute():
            candidate = _workspaces_root() / candidate
        return candidate.resolve()

    env_ws = os.environ.get("ADSCAN_CURRENT_WORKSPACE", "").strip()
    if env_ws:
        return Path(env_ws).expanduser().resolve()

    root = _workspaces_root()
    if not root.is_dir():
        return None
    candidates = sorted((p for p in root.iterdir() if p.is_dir()),
                        key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None


def _load_report(workspace_dir: Path) -> dict[str, Any] | None:
    """Load ``technical_report.json`` from a workspace, with telemetry."""
    report_path = workspace_dir / "technical_report.json"
    if not report_path.is_file():
        print_error(
            f"technical_report.json not found in {workspace_dir}. "
            "Run a scan first (`adscan ci` or `adscan start`)."
        )
        return None
    try:
        with report_path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(f"Failed to read technical_report.json: {exc}")
        return None


def _previous_snapshot(history_dir: Path) -> Path | None:
    """Return the most recent layer snapshot under ``history_dir``, if any."""
    if not history_dir.is_dir():
        return None
    snapshots = sorted(history_dir.glob("*-layer.json"))
    return snapshots[-1] if snapshots else None


def _save_history_snapshot(history_dir: Path, layer: dict[str, Any]) -> Path:
    """Write a timestamped immutable snapshot of the layer for later diffing.

    The filename is suffixed with a monotonic counter when two snapshots
    land in the same second — defensive against rapid re-invocations in
    CI smoke tests; in real assessments scans are minutes apart at best.
    """
    history_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    snapshot = history_dir / f"{stamp}-layer.json"
    counter = 1
    while snapshot.exists():
        snapshot = history_dir / f"{stamp}-{counter:02d}-layer.json"
        counter += 1
    snapshot.write_text(json.dumps(layer, indent=2, sort_keys=True), encoding="utf-8")
    return snapshot


def _domain_entries(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return the per-domain entries from a ``technical_report.json`` payload.

    The on-disk report nests domains under a ``domains`` wrapper:
    ``{"domains": {"<fqdn>": {"findings": [...], ...}}}``. Older flat layouts
    stored ``{"<fqdn>": {...}}`` at the top level — both are tolerated so a
    pre-existing report does not silently render zero techniques.
    """
    domains_raw = report.get("domains")
    if isinstance(domains_raw, dict):
        return {
            name: entry
            for name, entry in domains_raw.items()
            if isinstance(name, str) and name and isinstance(entry, dict)
        }
    # Flat fallback: top-level domain dicts carrying a ``findings`` list.
    flat: dict[str, dict[str, Any]] = {}
    for name, entry in report.items():
        if (
            isinstance(name, str)
            and name
            and isinstance(entry, dict)
            and isinstance(entry.get("findings"), list)
        ):
            flat[name] = entry
    return flat


def _domain_from_report(report: dict[str, Any]) -> str | None:
    """Return the in-scope AD domain — the one carrying the most findings.

    The ``domains`` wrapper holds every domain seen during the engagement, but
    only the authenticated/enumerated one carries findings (the others are
    trust stubs with empty lists). Selecting the domain with the most findings
    targets the layer at the assessment the operator actually ran.
    """
    entries = _domain_entries(report)
    if not entries:
        return None

    def _finding_count(entry: dict[str, Any]) -> int:
        findings = entry.get("findings")
        return len(findings) if isinstance(findings, list) else 0

    # Stable ordering: most findings first, then name for determinism.
    best = max(entries.items(), key=lambda kv: (_finding_count(kv[1]), kv[0]))
    name, entry = best
    if _finding_count(entry) == 0:
        # No domain has findings — still return a name so the layer is labelled.
        return name
    return name


def _normalized_findings_payload(
    report: dict[str, Any], domain: str | None
) -> dict[str, dict[str, Any]]:
    """Build a ``{domain: {"vulnerabilities": <map>}}`` payload for the builder.

    ``build_navigator_layer`` expects either a finding iterable or a
    ``technical_report.json``-shaped mapping where each domain exposes a
    ``vulnerabilities`` map. The on-disk report leaves ``vulnerabilities``
    ``null`` (the map is derived on demand from ``findings``), so we synthesize
    it here via the LITE-safe core normalizer — which also attaches the ATT&CK
    ``mitre`` list onto each entry so the technique aggregation has data to work
    with.
    """
    entries = _domain_entries(report)
    payload: dict[str, dict[str, Any]] = {}
    for name, entry in entries.items():
        if domain is not None and name != domain:
            continue
        findings = entry.get("findings")
        vuln_map = build_vuln_map_from_findings(
            findings if isinstance(findings, list) else []
        )
        payload[name] = {"vulnerabilities": vuln_map}
    return payload


def _open_browser_safe(path: Path) -> None:
    """Open a path in the user's default browser, swallowing headless errors."""
    try:
        webbrowser.open(path.as_uri())
    except Exception as exc:  # noqa: BLE001 — headless / no DISPLAY is fine
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_warning(f"Could not open browser: {exc}")


# ---------------------------------------------------------------------------
# Subparser registration
# ---------------------------------------------------------------------------
def add_mitre_navigator_subparser(
    subparsers: argparse._SubParsersAction,
) -> argparse.ArgumentParser:
    """Register ``mitre-navigator`` on the main argparse tree."""
    parser = subparsers.add_parser(
        "mitre-navigator",
        help="Export a MITRE ATT&CK Navigator layer (JSON + interactive HTML).",
        description=(
            "Generate a MITRE ATT&CK Navigator v4.5 layer from the latest "
            "scan, optionally with an interactive single-file HTML bundle "
            "(PRO) and a diff against a previous snapshot (PRO)."
        ),
    )
    parser.add_argument(
        "--workspace", dest="workspace", default=None,
        help="Workspace name or path (default: most recent).",
    )
    parser.add_argument(
        "--output", dest="output", default=None,
        help="Output directory (default: <workspace>/mitre/).",
    )
    parser.add_argument(
        "--client", dest="client", default=None,
        help="Client name embedded in the report header (PRO).",
    )
    parser.add_argument(
        "--engagement", dest="engagement", default=None,
        help="Engagement code embedded as layer metadata (PRO).",
    )
    parser.add_argument(
        "--web", dest="web", action="store_true",
        help="Open the generated interactive HTML in the default browser (PRO).",
    )
    parser.add_argument(
        "--no-html", dest="no_html", action="store_true",
        help="Skip the interactive HTML bundle, JSON only (PRO).",
    )
    parser.add_argument(
        "--no-history", dest="no_history", action="store_true",
        help="Do not snapshot the layer into the workspace history (PRO).",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose mode for detailed informational output.",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable debug output (detailed diagnostics).",
    )
    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def run_mitre_navigator(args: argparse.Namespace) -> int:
    """Execute the subcommand. Returns a CLI-style exit code."""
    workspace_dir = _resolve_workspace(args)
    if workspace_dir is None or not workspace_dir.is_dir():
        print_error(
            "No workspace found. Pass --workspace, set "
            "ADSCAN_CURRENT_WORKSPACE, or run `adscan ci` first."
        )
        return 2

    report = _load_report(workspace_dir)
    if report is None:
        return 1

    is_pro = tier.is_pro()
    domain = _domain_from_report(report)
    findings_payload = _normalized_findings_payload(report, domain)
    out_dir = Path(args.output).expanduser() if args.output else (workspace_dir / "mitre")
    out_dir.mkdir(parents=True, exist_ok=True)

    extra_meta: dict[str, str] = {}
    if args.engagement:
        extra_meta["engagement"] = args.engagement
    if args.client:
        extra_meta["client"] = args.client
    extra_meta["assessment_date"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    layer = build_navigator_layer(
        findings_payload,
        domain=domain,
        watermark=(WATERMARK_PRO if is_pro else WATERMARK_COMMUNITY),
        extra_metadata=extra_meta,
    )
    layer_path = out_dir / "navigator-layer.json"
    layer_path.write_text(json.dumps(layer, indent=2, sort_keys=True), encoding="utf-8")

    print_success(f"Navigator layer written → {layer_path}")
    print_info(
        "  Open it in the official MITRE ATT&CK Navigator: "
        "https://mitre-attack.github.io/attack-navigator/"
    )
    print_info_verbose(
        f"  techniques={len(layer['techniques'])}  domain={domain}  "
        f"watermark={'PRO' if is_pro else 'Community'}"
    )
    if not layer["techniques"]:
        print_warning(
            "  No ATT&CK techniques mapped — the report has no findings that "
            "match the technique catalog. Run a scan first (`adscan ci`)."
        )

    if not is_pro:
        # LITE stops here. Emphasize the upgrade hook without nagging.
        print_info(
            "  Tip: ADscan PRO adds an interactive HTML bundle, posture diff "
            "between scans, and engagement metadata. See `adscan deliver`."
        )
        return 0

    # ───────────── PRO additional artefacts ─────────────
    history_dir = workspace_dir / "mitre" / "history"
    previous_snapshot = _previous_snapshot(history_dir)
    diff_layer: dict[str, Any] | None = None
    previous_layer: dict[str, Any] | None = None
    diff_path: Path | None = None

    if previous_snapshot is not None:
        try:
            previous_layer = json.loads(previous_snapshot.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_warning(f"Could not read previous snapshot {previous_snapshot}: {exc}")
            previous_layer = None

    if previous_layer is not None:
        diff_layer = build_diff_layer(layer, previous_layer, domain=domain)
        diff_path = out_dir / "navigator-diff-layer.json"
        diff_path.write_text(json.dumps(diff_layer, indent=2, sort_keys=True), encoding="utf-8")
        summary = diff_summary(layer, previous_layer)
        print_success(
            f"Posture diff vs previous scan → {diff_path} "
            f"(new={summary['new']}, resolved={summary['resolved']}, "
            f"unchanged={summary['unchanged']})"
        )

    if not args.no_html:
        # Lazy import — keeps LITE imports clean and PRO failure isolated.
        #
        # The absent ``pro/`` package is the NORMAL state of the free tier, not
        # an error: this is an optional-feature probe, so it is logged at debug
        # level and the operator gets the one line that is actually useful to
        # them. A blanket ``capture_exception`` + ``print_exception`` here sent
        # a PostHog error event and printed an internal traceback every time a
        # free-tier user ran ``adscan mitre``. Anything OTHER than the module
        # being absent is unexpected and keeps the full three-sink treatment.
        try:
            from adscan_internal.pro.reporting.mitre_navigator_html import (
                build_interactive_html,
            )
        except (ImportError, ModuleNotFoundError) as exc:
            print_info_debug(f"Interactive HTML bundle unavailable: {exc}")
            print_error(
                "Interactive HTML bundle unavailable in this build. "
                "The Navigator layer JSON above is complete; re-run with "
                "--no-html to skip this step."
            )
        except Exception as exc:  # noqa: BLE001 — genuinely unexpected failure
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_error(f"Interactive HTML bundle unavailable: {exc}")
        else:
            html = build_interactive_html(
                layer,
                domain=domain,
                engagement=args.engagement,
                client=args.client,
                diff_layer=diff_layer,
                previous_layer=previous_layer,
            )
            html_path = out_dir / "navigator.html"
            html_path.write_text(html, encoding="utf-8")
            print_success(f"Interactive ATT&CK bundle → {html_path}")
            if args.web:
                _open_browser_safe(html_path)

    if not args.no_history:
        try:
            snapshot_path = _save_history_snapshot(history_dir, layer)
            print_info_verbose(f"  history snapshot saved → {snapshot_path}")
        except OSError as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_warning(f"Could not write history snapshot: {exc}")

    return 0


def run_mitre_navigator_sync(args: argparse.Namespace) -> int:
    """Synchronous wrapper for the top-level CLI dispatcher."""
    try:
        return run_mitre_navigator(args)
    except KeyboardInterrupt:
        print_warning("mitre-navigator cancelled.")
        return 130
    except Exception as exc:  # noqa: BLE001 — top-level safety net
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(f"mitre-navigator failed: {exc}")
        return 1


__all__ = (
    "add_mitre_navigator_subparser",
    "run_mitre_navigator",
    "run_mitre_navigator_sync",
)
