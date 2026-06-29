"""``adscan deliver`` — render the full Client Deliverable Kit.

Generates the PRO PDFs in parallel and packages them into a single
ZIP under ``<workspace>/deliverables/<YYYY-MM-DD>-adscan-kit.zip``:

* Security Assessment Report     (live engagement assessment)
* AD Hardening Playbook          (bonus, value-stack)
* AD Control Coverage Report     (proof-of-coverage / board-ready control assurance)

The standalone MITRE Remediation Checklist was retired — its ATT&CK lens
is now folded into the Security Assessment Report. ``--only checklist``
still resolves (aliased to the main report) so pinned customer scripts do
not break.

This command is **PRO only**. In LITE, the canonical PRO upsell panel
is rendered via :func:`adscan_core.pro_upsell.render_pro_upsell_panel`
and the function returns ``2`` (matches argparse "usage error" so the
shell does not treat it as a crash).

The generators run concurrently (``asyncio.gather`` over a thread
pool) — sequential rendering would Time-Delay the operator without any
quality gain.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import time
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from adscan_core import telemetry, tier
from adscan_core.paths import get_workspaces_dir
from adscan_core.rich_output import (
    print_error,
    print_info,
    print_info_debug,
    print_panel,
    print_success,
    print_warning,
)


# ---------------------------------------------------------------------------
# Kit definition — single source of truth for what ships in the ZIP.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _KitItem:
    """One artefact in the Client Deliverable Kit.

    Attributes:
        slug: Short selector used by ``--only`` and ``manifest.json``.
        filename: On-disk filename inside the staging dir and ZIP.
        title: Human title (displayed in panels).
        bonus_key: Bonus renderer key, or ``None`` for the executive
            assessment which uses its own generator.
    """

    slug: str
    filename: str
    title: str
    bonus_key: str | None  # None → executive assessment (separate generator).


_KIT: tuple[_KitItem, ...] = (
    # Slug stays ``executive`` so existing callers (``--only executive``,
    # the web Celery task's selection dict, every customer-side script)
    # keep working. The artefact itself is now the *full* assessment
    # (executive section + technical section + attack paths) — the
    # ``executive`` profile shipped an attack-path-stripped variant
    # that operators were already supplementing manually with the full
    # ``report.pdf``. See ``_render_assessment_async`` for the bake.
    _KitItem(
        "executive",
        "Security_Assessment_Report.pdf",
        "Security Assessment Report",
        None,
    ),
    _KitItem(
        "playbook", "AD_Hardening_Playbook.pdf", "AD Hardening Playbook", "playbook"
    ),
    # The standalone MITRE Remediation Checklist (slug ``checklist``) was
    # retired in e6e0355c — its ATT&CK lens is now folded into the main
    # Security Assessment Report, so a separate PDF was redundant. The
    # ``checklist`` slug is kept resolving via ``_ONLY_ALIASES`` (→ the main
    # report) so pinned ``--only checklist`` scripts do not error.
    # Slug stays ``coverage-matrix`` for back-compat (``--only coverage-matrix``,
    # the web Celery task selection, customer scripts); the artefact it renders
    # is the AD Control Coverage Report (sourced from control_evidence).
    _KitItem(
        "coverage-matrix",
        "AD_Control_Coverage_Report.pdf",
        "AD Control Coverage Report",
        "coverage-matrix",
    ),
)

_VALID_SLUGS: tuple[str, ...] = tuple(item.slug for item in _KIT)

# ---------------------------------------------------------------------------
# Public deliverable SSOT — the single source of truth the rest of the
# product (REPL, CI, and the cross-boundary web contract test) reads instead
# of re-deriving the slug set. The slugs were hand-copied in five places
# before this — the same drift gap that caused the ``--frameworks``/``nis2``
# mismatch. ``tests/unit/test_cli_web_deliverable_contract.py`` now binds the
# web copies to these so future drift fails CI.
# ---------------------------------------------------------------------------

#: Selectable deliverable slugs, in canonical kit order. Mirrors ``_VALID_SLUGS``
#: (kept as a clean public name so callers never reach into the private alias).
DELIVERABLE_SLUGS: tuple[str, ...] = _VALID_SLUGS

#: ``{slug: human title}`` for every selectable deliverable — drives the
#: deliverable checkbox labels (the operator picks titles, we map back to slugs).
DELIVERABLE_LABELS: dict[str, str] = {item.slug: item.title for item in _KIT}

#: Default deliverable selection: everything. A human-facing deliver run ships
#: the full kit unless the operator deselects; automation (CI) overrides this
#: with an explicit ``--only`` and never inherits the full kit by accident.
DEFAULT_DELIVERABLE_SLUGS: tuple[str, ...] = DELIVERABLE_SLUGS

# ``--only`` aliases. The slug ``executive`` is preserved internally for
# back-compat (web Celery task, ``Sample_Kit.zip``, every customer script
# pinned to ``--only executive``), but the artefact it renders is now the
# **full** Security Assessment Report. ``--only report`` is the public,
# semantically correct alias we direct users to. Add new aliases here when
# the public vocabulary drifts ahead of the internal slug — never rename
# the slug itself in this codebase.
# ``checklist`` → ``executive``: the standalone MITRE Remediation Checklist was
# retired (folded into the main report). A pinned ``--only checklist`` now renders
# the Security Assessment Report (which carries the ATT&CK lens) instead of erroring.
_ONLY_ALIASES: dict[str, str] = {"report": "executive", "checklist": "executive"}


# ---------------------------------------------------------------------------
# Compliance frameworks — single source of truth for the kit
# ---------------------------------------------------------------------------
#
# Mirrors ``do_generate_report`` (adscan.py). When this list changes here,
# update both. Tests in ``tests/unit/cli/test_deliver_command.py`` lock the
# parity. Adding a new framework requires the orchestrator + Coverage
# Matrix bonus to know about it — do not add a label here in isolation.

# ENS and NIS2 are DISTINCT compliance regimes (ENS = Spanish public sector /
# CCN-CERT; NIS2 = EU critical-infrastructure directive) and are selectable
# independently — a client may need NIS2 but not ENS. They share findings/
# attack-path semantics, which is modularized in the content layer, not by
# collapsing them into one key.
_FRAMEWORK_KEY_MAP: dict[str, str] = {
    "ENS Alto — Spain / CCN-CERT (recommended)": "ens",
    "NIS2 — EU Directive (EU) 2022/2555 (critical infrastructure)": "nis2",
    "ISO 27001:2022 — International ISMS standard": "iso27001",
    "DORA — EU 2022/2554 (financial sector)": "dora",
    "PCI DSS v4.0.1 — Payment Card Industry": "pci_dss",
}
_VALID_FRAMEWORK_KEYS: tuple[str, ...] = tuple(_FRAMEWORK_KEY_MAP.values())
# Default selection when the caller does not choose any framework: NONE. The
# client must explicitly pick the regimes that apply to them (e.g. PCI DSS +
# ISO 27001), so no compliance regime is forced onto a report that did not
# request it. Kept in lockstep with the web SSOT
# (``app.schemas.report_config.DEFAULT_FRAMEWORKS``); the cross-boundary
# contract test ``tests/unit/test_cli_web_framework_contract.py`` asserts the
# two defaults match.
_DEFAULT_FRAMEWORKS: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Workspace + metadata resolution
# ---------------------------------------------------------------------------


def _is_inside_shell() -> bool:
    """Return ``True`` when invoked from inside the running PentestShell.

    The shell sets ``ADSCAN_INSIDE_SHELL=1`` before dispatching, so we
    can decide whether to take the workspace from the active session
    rather than prompting.
    """
    return os.environ.get("ADSCAN_INSIDE_SHELL", "").strip() == "1"


def _resolve_workspace(args: argparse.Namespace) -> Path | None:
    """Resolve the target workspace directory.

    Order:
        1. Explicit ``--workspace`` flag (CLI, launcher, shell).
        2. ``ADSCAN_CURRENT_WORKSPACE`` env var (set by the shell when
           dispatching internal commands).
        3. Interactive questionary picker over ``~/.adscan/workspaces/``.

    Returns ``None`` if no workspace can be resolved (e.g. non-TTY,
    no flag, no existing workspaces).
    """
    explicit = getattr(args, "workspace", None)
    if explicit:
        candidate = Path(explicit).expanduser()
        if not candidate.is_absolute():
            candidate = get_workspaces_dir() / candidate
        return candidate.resolve()

    env_ws = os.environ.get("ADSCAN_CURRENT_WORKSPACE", "").strip()
    if env_ws:
        return Path(env_ws).expanduser().resolve()

    workspaces_root = get_workspaces_dir()
    if not workspaces_root.is_dir():
        return None

    candidates = sorted(p for p in workspaces_root.iterdir() if p.is_dir())
    if not candidates:
        return None

    from adscan_internal.interaction import is_non_interactive as _is_non_interactive
    if _is_non_interactive() or getattr(args, "_prompts_prefilled", False):
        # Non-interactive: fall back to the most recently modified one.
        return max(candidates, key=lambda p: p.stat().st_mtime)

    try:
        from questionary import select  # type: ignore[import-untyped]

        choice = select(
            "Pick a workspace to deliver:",
            choices=[p.name for p in candidates],
        ).ask()
    except Exception:  # noqa: BLE001 — questionary missing or non-TTY edge cases
        return max(candidates, key=lambda p: p.stat().st_mtime)
    if not choice:
        return None
    return (workspaces_root / choice).resolve()


def _resolve_client_meta(args: argparse.Namespace) -> tuple[str, str]:
    """Resolve ``(client_name, engagement_code)`` from flags or prompt.

    Both are optional. If neither flag is present and we have a TTY, a
    single questionary panel asks for both with blank defaults. Empty
    answers are accepted — the kit metadata will read "—".
    """
    client = (getattr(args, "client", None) or "").strip()
    engagement = (getattr(args, "engagement", None) or "").strip()
    if client or engagement:
        return client, engagement

    from adscan_internal.interaction import is_non_interactive as _is_non_interactive
    if _is_non_interactive() or getattr(args, "_prompts_prefilled", False):
        return "", ""

    try:
        from questionary import text  # type: ignore[import-untyped]

        client = (text("Client name (optional):").ask() or "").strip()
        engagement = (text("Engagement code (optional):").ask() or "").strip()
    except Exception:  # noqa: BLE001
        return client, engagement
    return client, engagement


def _parse_only(raw: str | None) -> tuple[_KitItem, ...]:
    """Filter ``_KIT`` by a comma-separated slug list.

    Args:
        raw: Raw ``--only`` value, or ``None`` for "all four".

    Returns:
        Tuple of selected ``_KitItem`` in canonical kit order.

    Raises:
        ValueError: If any token is not a valid kit slug, with a
            message naming the invalid token and the allowed set.
    """
    if raw is None or not raw.strip():
        return _KIT
    tokens = [tok.strip().lower() for tok in raw.split(",") if tok.strip()]
    if not tokens:
        return _KIT
    # Resolve aliases (e.g. ``report`` → ``executive``) before validation so
    # public-facing names never reach the slug check. Unknown tokens still
    # raise — the alias map is intentionally narrow.
    normalised = [_ONLY_ALIASES.get(tok, tok) for tok in tokens]
    invalid = [tok for tok in normalised if tok not in _VALID_SLUGS]
    if invalid:
        allowed = ", ".join(list(_VALID_SLUGS) + list(_ONLY_ALIASES.keys()))
        raise ValueError(
            f"--only: unknown deliverable(s): {', '.join(invalid)}. "
            f"Use one of: {allowed}."
        )
    selected_slugs = set(normalised)
    return tuple(item for item in _KIT if item.slug in selected_slugs)


def _parse_frameworks(raw: str | None) -> list[str] | None:
    """Validate a comma-separated framework list from ``--frameworks``.

    Args:
        raw: Raw ``--frameworks`` value, or ``None`` if the flag was not
            passed. Empty / whitespace-only string is treated as ``None``.

    Returns:
        Canonicalised list of framework keys (preserving caller order, no
        duplicates) when ``raw`` is a non-empty valid input. ``None`` when
        the flag was not provided — caller should then prompt or default.

    Raises:
        ValueError: Any token is not a known framework key. The message
            names the bad token and the allowed set so the operator can
            self-correct without reading source.
    """
    if raw is None or not raw.strip():
        return None
    tokens = [tok.strip().lower() for tok in raw.split(",") if tok.strip()]
    if not tokens:
        return None
    invalid = [tok for tok in tokens if tok not in _VALID_FRAMEWORK_KEYS]
    if invalid:
        raise ValueError(
            f"--frameworks: unknown value(s): {', '.join(invalid)}. "
            f"Use one of: {', '.join(_VALID_FRAMEWORK_KEYS)}."
        )
    seen: set[str] = set()
    ordered: list[str] = []
    for tok in tokens:
        if tok not in seen:
            seen.add(tok)
            ordered.append(tok)
    return ordered


def _resolve_frameworks(args: argparse.Namespace) -> list[str]:
    """Resolve compliance frameworks from flag, prompt, or default.

    Order:
        1. ``--frameworks`` flag value, validated via :func:`_parse_frameworks`.
        2. Interactive questionary checkbox in TTY contexts.
        3. Default :data:`_DEFAULT_FRAMEWORKS` (NONE) in non-interactive
           contexts or when the user cancels / deselects everything.

    The function never raises for empty selection. An empty result is valid
    and intended: no framework was selected, so the report omits the compliance
    sections entirely rather than forcing a regime the client did not request.
    """
    raw = getattr(args, "frameworks", None)
    parsed = _parse_frameworks(raw)
    if parsed is not None:
        return parsed

    from adscan_internal.interaction import is_non_interactive as _is_non_interactive
    if _is_non_interactive() or getattr(args, "_prompts_prefilled", False):
        return list(_DEFAULT_FRAMEWORKS)

    try:
        from questionary import checkbox  # type: ignore[import-untyped]

        selected = checkbox(
            "Select compliance frameworks to include in the kit:",
            choices=list(_FRAMEWORK_KEY_MAP.keys()),
        ).ask()
    except Exception:  # noqa: BLE001 — questionary missing or non-TTY edge cases
        return list(_DEFAULT_FRAMEWORKS)

    if not selected:
        return list(_DEFAULT_FRAMEWORKS)

    chosen = [
        _FRAMEWORK_KEY_MAP[label]
        for label in selected
        if label in _FRAMEWORK_KEY_MAP
    ]
    return chosen or list(_DEFAULT_FRAMEWORKS)


def _resolve_deliverables(args: argparse.Namespace, *, shell: object | None = None) -> str | None:
    """Resolve which deliverables to render, returning a ``--only`` string.

    Precedence:
        1. An explicit ``--only`` already on ``args`` wins untouched — automation
           (CI / the web) sets it deliberately and the checkbox must never
           override an explicit selection.
        2. Interactive TTY contexts render a checkbox with every deliverable
           pre-selected, so the default gesture (Enter) ships the full kit and
           the operator can deselect down to e.g. only the Security Assessment
           Report. Routed through the centralized prompt helper so it auto-resolves
           to ALL deliverables non-interactively (CI/web) and is telemetry-mirrored.

    Args:
        args: argparse namespace; reads ``only``, writes nothing.
        shell: Optional shell, threaded into the prompt helper so its
            non-interactive predicate (``shell.auto`` / posture) is honoured.

    Returns:
        A comma-separated slug string for ``--only`` (a strict subset, or the
        full set), or ``None`` when nothing should be narrowed (the caller then
        treats ``None`` as "all" via :func:`_parse_only`). An explicit
        ``args.only`` is returned verbatim.
    """
    explicit = getattr(args, "only", None)
    if explicit and str(explicit).strip():
        return str(explicit)

    from adscan_core.rich_output import questionary_checkbox_values

    labels = [DELIVERABLE_LABELS[slug] for slug in DELIVERABLE_SLUGS]
    selected_labels = questionary_checkbox_values(
        title="Select the deliverables to generate (all selected by default):",
        options=labels,
        default_values=None,  # None → ALL pre-selected / auto-all non-interactively.
        shell=shell,
    )

    # ``None`` = cancelled / prompt unavailable → fall back to the full kit.
    if not selected_labels:
        return None

    label_to_slug = {title: slug for slug, title in DELIVERABLE_LABELS.items()}
    chosen = [label_to_slug[label] for label in selected_labels if label in label_to_slug]
    if not chosen or len(chosen) == len(DELIVERABLE_SLUGS):
        # Nothing resolved, or the full set chosen → let _parse_only default to all.
        return None
    return ",".join(chosen)


# ---------------------------------------------------------------------------
# Generators — async wrappers around the existing PRO renderers
# ---------------------------------------------------------------------------


async def _render_bonus_async(
    bonus_key: str,
    output_path: Path,
    workspace_dir: Path | None = None,
    theme: str = "",
    frameworks: list[str] | None = None,
) -> int:
    """Render a single bonus PDF in a worker thread.

    When ``workspace_dir`` is supplied it is threaded into the bonus
    renderer so the playbook / checklist / coverage matrix can re-rank
    their content against the techniques actually observed in the scan.
    ``theme`` overrides the per-bonus default when non-empty.

    ``frameworks`` carries the operator-selected compliance regimes so the
    playbook/checklist render ONLY those frameworks' controls — the same
    selection the Security Assessment Report honours. Without this the bonuses
    fell back to ALL five frameworks and leaked DORA/ENS into an ISO 27001 kit.
    """
    from adscan_internal.cli.bonuses import render_bonus

    return await asyncio.to_thread(
        render_bonus,
        bonus_key,
        output_path,
        workspace_dir=workspace_dir,
        theme=theme or None,
        frameworks=frameworks,
    )


_VALID_REPORT_THEMES: tuple[str, ...] = ("corporate_light", "premium_dark", "editorial")
# Audit-grade light by default. The Security Assessment Report is the client's
# status instrument toward their board and DORA auditors — it must read as a
# serious, print-clean compliance document, not a dark terminal artefact. The
# report template is built on the ``--bg-0``/``--text`` variable scheme, which
# only ``corporate_light`` re-skins (``premium_dark`` is built on
# ``--paper``/``--ink`` for the editorial bonuses and would leave the report on
# its own DARK ``:root``). So ``corporate_light`` is both the strategy-correct
# AND the technically-correct default for the report. Bonuses keep their own
# editorial catalog theme (see ``bonus_theme`` in ``_render_kit``).
_DEFAULT_REPORT_THEME: str = "corporate_light"

# Short aliases for --theme: operators can pass "dark" or "light" instead of
# the full canonical names. Empty string means "not set — use env var or default".
_THEME_ALIASES: dict[str, str] = {
    "dark": "premium_dark",
    "light": "corporate_light",
    "warm": "editorial",
    "": "",
}

# Labels shown in the questionary picker. Order is intentional: dark first
# (default for screen demos), light second (auditor / board print). Keep
# this map in lockstep with :data:`_VALID_REPORT_THEMES`.
_THEME_PICKER_MAP: dict[str, str] = {
    "Editorial — warm bone, ember accent (premium, McKinsey-grade)": "editorial",
    "Corporate — white/navy, print-safe (Big-4 / auditor)": "corporate_light",
}


def _resolve_theme(args: argparse.Namespace) -> str:
    """Resolve the report theme using the canonical precedence chain.

    Order of precedence:
        1. ``--theme`` flag (with short aliases ``dark``/``light``).
        2. Legacy ``--report-theme`` flag.
        3. ``ADSCAN_PDF_THEME`` environment variable.
        4. Interactive questionary select in TTY contexts — mirrors the
           ``generate_report`` REPL command for cross-command parity.
        5. :data:`_DEFAULT_REPORT_THEME` (``premium_dark``).

    Returns:
        A theme value guaranteed to be in :data:`_VALID_REPORT_THEMES`.
        Invalid explicit inputs (typo'd env var, garbage flag) silently
        fall back to the default — the kit must always render.
    """
    raw_theme = getattr(args, "theme", "") or ""
    resolved_alias = _THEME_ALIASES.get(raw_theme, raw_theme)
    report_theme_flag = getattr(args, "report_theme", "") or ""
    env_theme = os.environ.get("ADSCAN_PDF_THEME", "").strip()

    chosen = resolved_alias or report_theme_flag or env_theme
    if chosen:
        return chosen if chosen in _VALID_REPORT_THEMES else _DEFAULT_REPORT_THEME

    from adscan_internal.interaction import is_non_interactive as _is_non_interactive
    if _is_non_interactive() or getattr(args, "_prompts_prefilled", False):
        return _DEFAULT_REPORT_THEME

    try:
        from questionary import select  # type: ignore[import-untyped]

        label = select(
            "Report theme:",
            choices=list(_THEME_PICKER_MAP.keys()),
        ).ask()
    except Exception:  # noqa: BLE001 — questionary missing or non-TTY edge cases
        return _DEFAULT_REPORT_THEME

    if not label:
        return _DEFAULT_REPORT_THEME
    return _THEME_PICKER_MAP.get(label, _DEFAULT_REPORT_THEME)


async def _render_assessment_async(
    output_path: Path,
    workspace_dir: Path,
    metadata: dict[str, str],
    report_theme: str = _DEFAULT_REPORT_THEME,
    frameworks: list[str] | None = None,
) -> int:
    """Render the Security Assessment Report PDF in a worker thread.

    Reads ``technical_report.json`` from the workspace and feeds it
    through the canonical PRO orchestrator with the **full** profile —
    executive section + technical section + attack paths. The earlier
    ``executive`` profile shipped a stripped variant (zero attack
    paths) that operators routinely supplemented by copying the
    standalone ``report.pdf`` into their delivery directory; the kit
    now ships the full report directly so the headline artefact is the
    one the customer actually wants to open.

    Args:
        output_path: Where to write the rendered PDF.
        workspace_dir: Workspace containing ``technical_report.json``.
        metadata: Report metadata (workspace_name, report_date, client, ...).
        report_theme: Visual theme — one of :data:`_VALID_REPORT_THEMES`.
            Defaults to ``premium_dark`` for backwards compatibility with
            existing callers that did not pass a theme. Invalid values fall
            back to the default rather than raising — the kit should always
            render even with a typo'd flag.
    """
    if report_theme not in _VALID_REPORT_THEMES:
        report_theme = _DEFAULT_REPORT_THEME

    # Resolve the selected frameworks. An empty/None selection stays empty
    # (default none): the kit omits the compliance sections rather than forcing
    # a regime the client did not request.
    fw: list[str] = list(frameworks) if frameworks else list(_DEFAULT_FRAMEWORKS)

    def _run() -> int:
        import json as _json

        from adscan_internal.pro.reporting.orchestrator import generate_report_pdf
        from adscan_internal.pro.reporting.report_builder import (
            build_report_data_from_raw,
        )
        from adscan_internal.pro.services.report_service import (
            _find_adscan_logo,
            ensure_report_attack_paths,
        )

        report_json = workspace_dir / "technical_report.json"
        if not report_json.is_file():
            raise FileNotFoundError(
                f"technical_report.json not found in {workspace_dir}. "
                f"Run 'start_auth' or 'report' first to populate the workspace."
            )
        raw = _json.loads(report_json.read_text(encoding="utf-8"))
        # Normalize the raw technical report into the renderer mapping via
        # the single source of truth shared with ``generate_report``. The
        # raw JSON stores ``domains[*].vulnerabilities`` empty (the vuln
        # map is derived on demand from ``findings``); feeding it raw made
        # the compliance engine see zero findings per requirement and
        # falsely report ~100% conformant for every framework.
        report_data = build_report_data_from_raw(raw) if isinstance(raw, dict) else {}
        # Compute + inject attack paths the same way ``generate_report`` does.
        # The renderer expects them already present; the workspace JSON stores
        # them empty (computed on demand), so without this the kit report
        # shipped with ZERO attack paths -- the "deliver is suspiciously fast"
        # symptom. Single source of truth shared with report_service.
        # Also emits the per-framework compliance block into
        # technical_report.json for the selected frameworks (verbatim ingest by
        # the web) — same SSOT engine as the PDF compliance sections.
        ensure_report_attack_paths(report_data, workspace_dir, frameworks=fw)
        pdf_bytes = generate_report_pdf(
            report_data,
            metadata=metadata,
            report_profile="full",
            frameworks=fw,
            logo_path=_find_adscan_logo(report_theme),
            engine="chromium",
            renderer="cytoscape",
            template="premium",
            theme=report_theme,
        )
        output_path.write_bytes(pdf_bytes)
        return len(pdf_bytes)

    return await asyncio.to_thread(_run)


async def _render_kit(
    *,
    staging_dir: Path,
    workspace_dir: Path,
    metadata: dict[str, str],
    items: tuple[_KitItem, ...],
    report_theme: str = _DEFAULT_REPORT_THEME,
    bonus_theme: str = "",
    frameworks: list[str] | None = None,
) -> dict[str, int]:
    """Render the selected kit artefacts in parallel.

    Args:
        staging_dir: Directory where individual PDFs are written.
        workspace_dir: Source workspace (for ``technical_report.json``).
        metadata: Report metadata threaded into the executive PDF.
        items: Subset of ``_KIT`` to render (canonical order preserved).
        report_theme: Visual theme for the Security Assessment Report.
        bonus_theme: Visual theme for the bonus PDFs. Empty string means each
            bonus renders with its OWN catalog theme (the warm-bone editorial
            for playbook/checklist, white for coverage) — the decoupled
            default. A non-empty value (set only when the operator passes an
            explicit ``--theme``/``--report-theme``) overrides every bonus so
            the whole kit shares one skin.

    Returns:
        Mapping ``{filename: byte_size}`` for the rendered artefacts.
    """
    staging_dir.mkdir(parents=True, exist_ok=True)
    tasks: list[Any] = []
    for item in items:
        out_path = staging_dir / item.filename
        if item.bonus_key is None:
            tasks.append(
                _render_assessment_async(
                    out_path,
                    workspace_dir,
                    metadata,
                    report_theme=report_theme,
                    frameworks=frameworks,
                )
            )
        else:
            tasks.append(
                _render_bonus_async(
                    item.bonus_key,
                    out_path,
                    workspace_dir,
                    theme=bonus_theme,
                    frameworks=frameworks,
                )
            )
    sizes = await asyncio.gather(*tasks)
    return {item.filename: size for item, size in zip(items, sizes)}


def _generate_affected_assets_appendix(
    *,
    staging_dir: Path,
    workspace_dir: Path,
) -> tuple[str, ...]:
    """Write the consolidated affected-assets appendix into ``staging_dir``.

    Emits ``affected_assets_appendix.csv`` and ``affected_assets_appendix.json``
    carrying the COMPLETE, untruncated affected-asset set for every finding —
    the full machine-readable record the capped inline PDF lists point at. The
    data is sourced from the SAME affected-assets SSOT the PDFs use (loaded the
    same way as the assessment report), so the appendix and the PDF inline lists
    cannot diverge. Best-effort: a failure here never aborts the kit.

    Returns the bundled filenames (added flat to the kit ZIP), or ``()`` when
    the appendix could not be produced.
    """
    try:
        from adscan_internal.pro.reporting.affected_assets_exports import (
            write_affected_assets_appendix,
        )
        from adscan_internal.pro.reporting.report_builder import (
            build_report_data_from_raw,
        )
        from adscan_internal.pro.services.report_service import (
            ensure_report_attack_paths,
        )

        report_json = workspace_dir / "technical_report.json"
        if not report_json.is_file():
            print_warning(
                "Affected-assets appendix skipped: technical_report.json not found."
            )
            return ()
        raw = json.loads(report_json.read_text(encoding="utf-8"))
        report_data = build_report_data_from_raw(raw) if isinstance(raw, dict) else {}
        # Compute + inject attack paths the same way the assessment report does,
        # so the appendix's correlated assets match the PDF exactly.
        ensure_report_attack_paths(report_data, workspace_dir)
        result = write_affected_assets_appendix(report_data, output_dir=staging_dir)
        print_info_debug(
            f"Affected-assets appendix: {int(result['row_count'])} rows "
            f"→ {result['csv_filename']}, {result['json_filename']}"
        )
        return (str(result["csv_filename"]), str(result["json_filename"]))
    except Exception as exc:  # noqa: BLE001 — appendix is best-effort but logged
        telemetry.capture_exception(exc)
        print_warning(f"Affected-assets appendix skipped: {exc}")
        return ()


# ---------------------------------------------------------------------------
# Packaging + presentation
# ---------------------------------------------------------------------------


def _package_zip(
    staging_dir: Path,
    zip_path: Path,
    items: tuple[_KitItem, ...],
    extras: tuple[str, ...] = (),
    appendix: tuple[str, ...] = (),
) -> None:
    """Bundle the selected PDFs (and optional extras) into ``zip_path``.

    ``extras`` is a tuple of filenames living in ``staging_dir`` that are
    not part of the four canonical PDFs but ship alongside them — e.g.
    the MITRE ATT&CK Navigator JSON layer and the interactive HTML
    bundle. Extras are written into the ZIP under a top-level
    ``mitre/`` folder so the kit stays tidy when the client unzips it.

    ``appendix`` is a tuple of filenames (the consolidated affected-assets
    appendix CSV/JSON) bundled FLAT at the top level next to the PDFs — the
    PDFs reference the CSV by its bare name, so it must not be nested.
    """
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for item in items:
            src = staging_dir / item.filename
            if src.is_file():
                zf.write(src, arcname=item.filename)
        for name in appendix:
            src = staging_dir / name
            if src.is_file():
                zf.write(src, arcname=name)
        for extra in extras:
            src = staging_dir / extra
            if src.is_file():
                zf.write(src, arcname=f"mitre/{extra}")


def _write_manifest(
    *,
    manifest_path: Path,
    zip_path: Path,
    staging_dir: Path,
    items: tuple[_KitItem, ...],
    workspace_dir: Path,
    extras: tuple[str, ...] = (),
    appendix: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Write ``manifest.json`` next to the ZIP describing the deliverable.

    The manifest is the contract consumed by the web/Celery task in the
    next batch — keep its shape stable. Returns the dict that was written
    so callers (and tests) can assert against it without re-reading.

    The affected-assets appendix files are listed under the existing
    ``extras`` key with a flat (top-level) ``arcname``, so the web ingestion —
    which already enumerates ``extras`` — picks them up with no schema change.
    """
    selection = {slug: (slug in {it.slug for it in items}) for slug in _VALID_SLUGS}

    files: list[dict[str, Any]] = []
    for item in items:
        path = staging_dir / item.filename
        size = path.stat().st_size if path.is_file() else 0
        files.append(
            {
                "slug": item.slug,
                "name": item.filename,
                "title": item.title,
                "size": size,
                "path": str(path),
            }
        )

    extra_files: list[dict[str, Any]] = []
    for name in appendix:
        path = staging_dir / name
        size = path.stat().st_size if path.is_file() else 0
        extra_files.append(
            {
                "name": name,
                "size": size,
                "path": str(path),
                "arcname": name,
            }
        )
    for extra in extras:
        path = staging_dir / extra
        size = path.stat().st_size if path.is_file() else 0
        extra_files.append(
            {
                "name": extra,
                "size": size,
                "path": str(path),
                "arcname": f"mitre/{extra}",
            }
        )

    manifest: dict[str, Any] = {
        "manifest_version": 2,
        "kit_id": f"{workspace_dir.name}-{time.strftime('%Y%m%d')}",
        "workspace": workspace_dir.name,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "selection": selection,
        "zip": str(zip_path),
        "files": files,
        "extras": extra_files,
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def _format_size(num_bytes: int) -> str:
    """Return a human-readable size string (KB / MB)."""
    if num_bytes >= 1_000_000:
        return f"{num_bytes / 1_000_000:.1f} MB"
    return f"{num_bytes / 1024:.0f} KB"


# ---------------------------------------------------------------------------
# MITRE ATT&CK Navigator extras — bundled into every PRO kit by default.
# Hormozi rationale: the interactive HTML is the SOC-facing artefact and
# the JSON layer opens in MITRE's own free Navigator UI. Bundling both in
# the same ZIP collapses two operator gestures into one and makes the
# kit a single shareable unit (PDF for the board + HTML for the SOC +
# JSON for the detection engineer). Generated in the staging dir and
# packaged under ``mitre/`` inside the ZIP.
# ---------------------------------------------------------------------------


_NAVIGATOR_LAYER_FILE: str = "navigator-layer.json"
_NAVIGATOR_HTML_FILE: str = "navigator.html"
_NAVIGATOR_DIFF_FILE: str = "navigator-diff-layer.json"


def _generate_navigator_extras(
    *,
    staging_dir: Path,
    workspace_dir: Path,
    client: str | None,
    engagement: str | None,
) -> tuple[str, ...]:
    """Render the Navigator layer + interactive HTML + (optional) diff.

    Reads ``technical_report.json`` from ``workspace_dir``, builds the
    PRO-watermarked Navigator layer, snapshots it into the workspace
    history, and renders the interactive HTML bundle. When a previous
    history snapshot exists, also emits a diff layer.

    Errors are swallowed: the kit must still ship if the navigator
    extras fail. Failures are logged via telemetry and surfaced as
    warnings to the operator.

    Returns:
        Tuple of filenames written into ``staging_dir`` (later passed to
        ``_package_zip`` as ``extras``). Empty tuple on failure.
    """
    # Lazy imports — keeps the deliver module's import surface small and
    # isolates failures in the navigator stack from the four PDFs.
    from adscan_internal.cli.mitre_navigator import (
        _previous_snapshot,
        _save_history_snapshot,
    )
    from adscan_internal.pro.reporting.mitre_navigator_html import (
        build_interactive_html,
    )
    from adscan_internal.pro.reporting.report_builder import (
        build_report_data_from_raw,
    )
    from adscan_internal.services.mitre_navigator import (
        WATERMARK_PRO,
        build_diff_layer,
        build_navigator_layer,
    )

    report_path = workspace_dir / "technical_report.json"
    if not report_path.is_file():
        print_warning(
            "MITRE navigator artefacts skipped: "
            "technical_report.json not found in workspace."
        )
        return ()

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        telemetry.capture_exception(exc)
        print_warning(f"MITRE navigator artefacts skipped: {exc}")
        return ()

    # Normalize the raw report so the navigator sees synthesized
    # ``vulnerabilities`` maps (the raw JSON stores them empty -- the same
    # root cause that made the compliance section render ~100% conformant).
    # Without this the navigator layer was always empty of techniques.
    report_data = build_report_data_from_raw(report) if isinstance(report, dict) else {}

    # Pick the domain with the MOST findings rather than the first non-empty
    # one, so a multi-domain kit targets the domain that actually carries the
    # exposure (e.g. essos.local over a near-clean child domain).
    def _vuln_count(value: object) -> int:
        if not isinstance(value, dict):
            return 0
        vulns = value.get("vulnerabilities")
        return len(vulns) if isinstance(vulns, dict) else 0

    domain: str | None = (
        max(report_data, key=lambda k: _vuln_count(report_data[k]), default=None)
        if report_data
        else None
    )
    if domain is not None and _vuln_count(report_data.get(domain)) == 0:
        domain = None

    extra_meta: dict[str, str] = {
        "assessment_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
    }
    if engagement:
        extra_meta["engagement"] = engagement
    if client:
        extra_meta["client"] = client

    try:
        layer = build_navigator_layer(
            report_data,
            domain=domain,
            watermark=WATERMARK_PRO,
            extra_metadata=extra_meta,
        )
    except Exception as exc:  # noqa: BLE001 — best-effort, kit must still ship
        telemetry.capture_exception(exc)
        print_warning(f"MITRE navigator layer build failed: {exc}")
        return ()

    written: list[str] = []
    staging_dir.mkdir(parents=True, exist_ok=True)

    layer_path = staging_dir / _NAVIGATOR_LAYER_FILE
    layer_path.write_text(json.dumps(layer, indent=2, sort_keys=True), encoding="utf-8")
    written.append(_NAVIGATOR_LAYER_FILE)

    # Diff vs previous workspace snapshot (if any).
    history_dir = workspace_dir / "mitre" / "history"
    previous_snapshot_path = _previous_snapshot(history_dir)
    previous_layer: dict[str, Any] | None = None
    diff_layer: dict[str, Any] | None = None
    if previous_snapshot_path is not None:
        try:
            previous_layer = json.loads(
                previous_snapshot_path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            telemetry.capture_exception(exc)
            print_warning(
                f"Could not read previous Navigator snapshot {previous_snapshot_path}: {exc}"
            )
            previous_layer = None
    if previous_layer is not None:
        try:
            diff_layer = build_diff_layer(layer, previous_layer, domain=domain)
            diff_path = staging_dir / _NAVIGATOR_DIFF_FILE
            diff_path.write_text(
                json.dumps(diff_layer, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            written.append(_NAVIGATOR_DIFF_FILE)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning(f"Navigator diff layer build failed: {exc}")

    # Interactive HTML bundle.
    try:
        html = build_interactive_html(
            layer,
            domain=domain,
            engagement=engagement,
            client=client,
            diff_layer=diff_layer,
            previous_layer=previous_layer,
        )
        html_path = staging_dir / _NAVIGATOR_HTML_FILE
        html_path.write_text(html, encoding="utf-8")
        written.append(_NAVIGATOR_HTML_FILE)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning(f"Navigator interactive HTML failed: {exc}")

    # Snapshot the layer into history so the *next* deliver run can diff.
    try:
        _save_history_snapshot(history_dir, layer)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning(f"Could not snapshot Navigator history: {exc}")

    # Lightweight telemetry — Hormozi: instrument what matters before
    # iterating. Tracks bundle adoption without leaking customer data.
    try:
        telemetry.capture(
            "deliver.navigator_bundled",
            {
                "techniques": len(layer.get("techniques", [])),
                "has_diff": diff_layer is not None,
                "has_html": _NAVIGATOR_HTML_FILE in written,
                "watermark": "pro",
            },
        )
    except Exception:  # noqa: BLE001 — telemetry must never break the kit
        pass

    return tuple(written)


def _render_closing_panel(
    *,
    sizes: dict[str, int],
    zip_path: Path,
    items: tuple[_KitItem, ...],
    extras: tuple[str, ...] = (),
    staging_dir: Path | None = None,
) -> None:
    """Render the premium kit-ready panel — eyebrow caps, mono paths.

    The four canonical PDFs are listed first; MITRE Navigator extras
    (when bundled) appear under a separate "BONUS · MITRE ATT&CK" eyebrow
    so the operator sees at a glance what the client will unzip.
    """
    from rich.console import Group
    from rich.table import Table
    from rich.text import Text

    eyebrow = Text(
        "CLIENT DELIVERABLE KIT · READY TO SHIP",
        style="bold bright_cyan",
    )

    table = Table.grid(padding=(0, 2))
    table.add_column(justify="left")
    table.add_column(justify="right")
    for item in items:
        size = sizes.get(item.filename, 0)
        table.add_row(
            Text(item.filename, style="bright_cyan on grey11"),
            Text(_format_size(size) if size else "—", style="dim"),
        )

    blocks: list[Any] = [eyebrow, Text(""), table]

    if extras and staging_dir is not None:
        extras_eyebrow = Text(
            "BONUS · MITRE ATT&CK NAVIGATOR (mitre/)",
            style="bold bright_magenta",
        )
        extras_table = Table.grid(padding=(0, 2))
        extras_table.add_column(justify="left")
        extras_table.add_column(justify="right")
        for extra in extras:
            extra_path = staging_dir / extra
            size = extra_path.stat().st_size if extra_path.is_file() else 0
            extras_table.add_row(
                Text(f"mitre/{extra}", style="bright_magenta on grey11"),
                Text(_format_size(size) if size else "—", style="dim"),
            )
        blocks.extend([Text(""), extras_eyebrow, Text(""), extras_table])

    zip_line = Text()
    zip_line.append("ZIP:  ", style="bold")
    zip_line.append(str(zip_path), style="bright_cyan on grey11")

    final = Text("Kit ready. Hand it to your client.", style="bold")

    blocks.extend([Text(""), zip_line, Text(""), final])
    print_panel(Group(*blocks), border_style="bright_cyan", padding=(1, 2))


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


async def run_deliver(args: argparse.Namespace) -> int:
    """Orchestrate playbook + checklist + coverage_matrix + executive assessment.

    Args:
        args: argparse namespace; honours ``--workspace``, ``--client``,
            ``--engagement``, ``--output``, ``--only``.

    Returns:
        Process exit code: ``0`` on success, ``1`` on failure, ``2`` on
        usage error (LITE invocation, no workspace, invalid ``--only``).
    """
    if not tier.is_pro():
        # Use the canonical helper so we don't double-wrap the panel
        # (``print_panel`` adds its own border around the already-bordered
        # panel returned by the renderer). Single source of truth lives
        # in ``adscan_core.pro_upsell.print_pro_upsell``.
        from adscan_core.pro_upsell import print_pro_upsell

        print_pro_upsell("deliver", "direct_invocation")
        return 2

    try:
        items = _parse_only(getattr(args, "only", None))
    except ValueError as exc:
        print_error(str(exc))
        return 2

    # Resolve interactive inputs in the order an operator naturally thinks
    # about a delivery: which scan → who is the client → what compliance
    # → how it looks. Each helper is idempotent and silently picks defaults
    # in non-interactive contexts, so this order also degrades cleanly in
    # ``adscan ci`` and other CI gates.
    workspace_dir = _resolve_workspace(args)
    if workspace_dir is None or not workspace_dir.is_dir():
        print_error(
            "No workspace available. Run 'adscan start' first, or pass --workspace WS."
        )
        return 2

    client, engagement = _resolve_client_meta(args)

    try:
        frameworks = _resolve_frameworks(args)
    except ValueError as exc:
        print_error(str(exc))
        return 2
    # Use the client name as the workspace display name when provided so the
    # cover title reads "Acme Corp Security Report" rather than the internal
    # workspace directory name (e.g. "Goad-example").
    display_name = client or workspace_dir.name
    metadata: dict[str, str] = {
        "workspace_name": display_name,
        "report_date": time.strftime("%B %d, %Y"),
        "report_type": "Active Directory Security Assessment",
        "report_version": "ADscan",
        "client_name": client or "",
        "engagement_id": engagement or "",
    }

    deliverables_dir = workspace_dir / "deliverables"
    output_override = getattr(args, "output", None)
    if output_override:
        deliverables_dir = Path(output_override).expanduser().resolve()
    staging_dir = deliverables_dir / "staging"
    today = time.strftime("%Y-%m-%d")
    zip_path = deliverables_dir / f"{today}-adscan-kit.zip"
    manifest_path = deliverables_dir / "manifest.json"

    # Resolve the report theme via the canonical precedence chain — flags
    # → env var → questionary picker (TTY only) → default. Keeping this in
    # ``_resolve_theme`` mirrors ``_resolve_frameworks`` and gives the
    # operator one place to look when the kit ships with the wrong skin.
    report_theme = _resolve_theme(args)

    # Decouple the bonus skin from the report skin. By default the bonuses
    # render with their OWN editorial catalog theme (warm-bone playbook /
    # checklist, white coverage) — passing an empty ``bonus_theme`` tells
    # ``render_bonus`` to fall back to ``BONUSES[key]["theme"]``. Only when the
    # operator explicitly chose a theme (``--theme`` / ``--report-theme`` /
    # ``ADSCAN_PDF_THEME``) do we force that one skin across the whole kit.
    # ``_prefill_interactive_inputs`` stashes this before folding the resolved
    # theme back into ``args.theme`` (which would otherwise make the inline
    # check always true). Fall back to the inline computation when prefill did
    # not run (defensive — every real path goes through ``run_deliver_sync``).
    explicit_theme_set = getattr(args, "_explicit_theme_set", None)
    if explicit_theme_set is None:
        explicit_theme_set = bool(
            (getattr(args, "theme", "") or "").strip()
            or (getattr(args, "report_theme", "") or "").strip()
            or os.environ.get("ADSCAN_PDF_THEME", "").strip()
        )
    bonus_theme = report_theme if explicit_theme_set else ""

    print_info(
        f"Rendering Client Deliverable Kit for {workspace_dir.name} "
        f"(frameworks: {', '.join(frameworks)})…"
    )
    try:
        sizes = await _render_kit(
            staging_dir=staging_dir,
            workspace_dir=workspace_dir,
            metadata=metadata,
            items=items,
            report_theme=report_theme,
            bonus_theme=bonus_theme,
            frameworks=frameworks,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error(f"Kit generation failed: {exc}")
        return 1

    extras: tuple[str, ...] = ()
    if not getattr(args, "no_navigator", False):
        extras = _generate_navigator_extras(
            staging_dir=staging_dir,
            workspace_dir=workspace_dir,
            client=client,
            engagement=engagement,
        )

    # Consolidated affected-assets appendix (CSV + JSON) — the complete,
    # untruncated record of every finding's affected assets, bundled flat next
    # to the PDFs. Always generated; the PDFs' overflow lines name the CSV.
    appendix = _generate_affected_assets_appendix(
        staging_dir=staging_dir,
        workspace_dir=workspace_dir,
    )

    try:
        _package_zip(staging_dir, zip_path, items, extras, appendix)
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error(f"Could not package ZIP: {exc}")
        return 1

    try:
        _write_manifest(
            manifest_path=manifest_path,
            zip_path=zip_path,
            staging_dir=staging_dir,
            items=items,
            workspace_dir=workspace_dir,
            extras=extras,
            appendix=appendix,
        )
    except Exception as exc:  # noqa: BLE001 — manifest is best-effort but logged
        telemetry.capture_exception(exc)
        print_warning(f"Manifest could not be written: {exc}")

    _render_closing_panel(
        sizes=sizes,
        zip_path=zip_path,
        items=items,
        extras=extras,
        staging_dir=staging_dir,
    )
    print_success(f"Kit packaged at {zip_path}")

    # Stash the headline artefact (the Security Assessment Report — full
    # profile). The "open it now?" prompt is fired by ``run_deliver_sync``
    # AFTER the event loop exits: ``prompt_and_open`` spins a
    # prompt_toolkit Application that leaks a coroutine if run inside
    # ``asyncio.run``'s running loop.
    headline_pdf = staging_dir / "Security_Assessment_Report.pdf"
    if headline_pdf.is_file():
        setattr(args, "_headline_pdf", str(headline_pdf))

    return 0


def add_deliver_subparser(
    subparsers: argparse._SubParsersAction,
) -> argparse.ArgumentParser:
    """Register the ``deliver`` subparser on the main argparse tree."""
    parser = subparsers.add_parser(
        "deliver",
        help="Generate the full Client Deliverable Kit (4 PDFs + ZIP).",
        description=(
            "Render the four PRO PDFs in parallel and package them into a "
            "single ZIP under <workspace>/deliverables/. PRO only."
        ),
    )
    parser.add_argument(
        "--workspace",
        dest="workspace",
        default=None,
        help="Workspace name or path (default: prompt or active workspace).",
    )
    parser.add_argument(
        "--client",
        dest="client",
        default=None,
        help="Client name (optional, embedded in metadata).",
    )
    parser.add_argument(
        "--engagement",
        dest="engagement",
        default=None,
        help="Engagement code (optional, embedded in metadata).",
    )
    parser.add_argument(
        "--output",
        dest="output",
        default=None,
        help="Override the deliverables output directory.",
    )
    parser.add_argument(
        "--only",
        dest="only",
        type=str,
        default=None,
        help=(
            "Comma-separated list of deliverables to generate. "
            f"Choices: report, {', '.join(s for s in _VALID_SLUGS if s != 'executive')}. "
            "Default: all four. ('executive' kept as a deprecated alias for 'report'.)"
        ),
    )
    parser.add_argument(
        "--frameworks",
        dest="frameworks",
        type=str,
        default=None,
        help=(
            "Comma-separated compliance frameworks to render in the kit. "
            f"Choices: {', '.join(_VALID_FRAMEWORK_KEYS)}. "
            "When omitted, an interactive checkbox prompts in TTY contexts; "
            "non-interactive runs include no compliance section unless one is "
            "selected explicitly."
        ),
    )
    parser.add_argument(
        "--no-navigator",
        dest="no_navigator",
        action="store_true",
        help=(
            "Skip the MITRE ATT&CK Navigator extras (JSON layer + "
            "interactive HTML + diff). Default: included in every kit."
        ),
    )
    # NOTE on theme validation: we deliberately do NOT use argparse
    # ``choices=`` here. Only the two SUPPORTED, homogeneous kit themes
    # (``editorial`` / ``corporate_light``) are advertised via ``metavar`` and
    # the help text. ``premium_dark`` (and its ``dark`` alias) remain ACCEPTED
    # for internal preview/testing — they render a mixed kit (dark report +
    # light bonuses), so we don't surface them to customers, but a developer
    # can still pass ``--theme dark``. Unknown/typo'd values degrade to the
    # default inside :func:`_resolve_theme` (it never raises).
    parser.add_argument(
        "--report-theme",
        dest="report_theme",
        metavar="{editorial,corporate_light}",
        default="",
        help=(
            "Visual theme for the whole kit. 'editorial' = premium warm-bone "
            "(McKinsey-grade); 'corporate_light' = white Big-4/auditor. "
            f"Default: {_DEFAULT_REPORT_THEME}."
        ),
    )
    parser.add_argument(
        "--theme",
        dest="theme",
        default="",
        metavar="{editorial,corporate_light}",
        help=(
            "Kit theme. 'editorial' = premium warm-bone editorial "
            "(McKinsey-grade). 'corporate_light' = white Big-4/auditor. "
            f"Default: env var ADSCAN_PDF_THEME or '{_DEFAULT_REPORT_THEME}'."
        ),
    )
    # Mirrors the per-subcommand --debug on start/ci/install/check. The host
    # launcher forwards --debug to the container subcommand, so deliver must
    # accept it (argparse rejects unknown flags). Activation into DEBUG_MODE
    # happens in the top-level dispatcher's debug block (adscan.py), which
    # lists "deliver" alongside the other debug-aware commands.
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable debug mode.",
    )
    return parser


def _prefill_interactive_inputs(args: argparse.Namespace) -> None:
    """Resolve every interactive input in the SYNC context, before the loop.

    ``questionary.ask()`` spins its own prompt_toolkit ``Application``
    synchronously; invoked inside ``asyncio.run``'s running loop it leaks the
    coroutine ("Application.run_async was never awaited") and the prompt never
    displays — so the kit silently fell back to defaults (e.g. it never asked
    which compliance frameworks to include). Resolving here, where no event
    loop runs, lets the prompts actually work. Results are written back to
    ``args`` and the ``_prompts_prefilled`` sentinel makes the async resolvers
    trust them instead of re-prompting (and re-leaking).
    """
    # Capture "did the operator explicitly choose a theme?" BEFORE we fold the
    # resolved value into ``args.theme`` — the report/bonus theme decouple
    # depends on distinguishing an explicit choice from the resolved default.
    setattr(
        args,
        "_explicit_theme_set",
        bool(
            (getattr(args, "theme", "") or "").strip()
            or (getattr(args, "report_theme", "") or "").strip()
            or os.environ.get("ADSCAN_PDF_THEME", "").strip()
        ),
    )

    workspace = _resolve_workspace(args)
    if workspace is not None:
        args.workspace = str(workspace)
    client, engagement = _resolve_client_meta(args)
    args.client = client
    args.engagement = engagement
    # Deliverable selection FIRST: a checkbox (everything pre-selected) so the
    # operator can deselect down to e.g. only the Security Assessment Report. An
    # explicit ``--only`` is returned verbatim and never overridden; CI/web run
    # non-interactively and auto-resolve to ALL (or their explicit ``--only``).
    args.only = _resolve_deliverables(args, shell=getattr(args, "_shell", None))
    try:
        args.frameworks = ",".join(_resolve_frameworks(args))
    except ValueError:
        # Invalid --frameworks value: leave it for run_deliver to re-validate
        # and surface a clean error (exit 2) instead of swallowing it here.
        pass
    args.theme = _resolve_theme(args)
    args.report_theme = ""  # folded into args.theme above; avoid double-resolution

    setattr(args, "_prompts_prefilled", True)


def _maybe_open_headline(args: argparse.Namespace) -> None:
    """Offer to open the Security Assessment Report once the kit is built.

    Runs in the SYNC wrapper, after the event loop has exited — the
    ``prompt_and_open`` confirm prompt is yet another prompt_toolkit
    Application that must not run inside ``asyncio.run``'s loop. Auto-skips
    in non-interactive contexts (handled inside ``prompt_and_open``).
    """
    headline = getattr(args, "_headline_pdf", "") or ""
    if not headline:
        return
    path = Path(headline)
    if not path.is_file():
        return
    from adscan_internal.services.host_open import prompt_and_open

    prompt_and_open(path, prompt="Open the security assessment report now?")


def run_deliver_sync(args: argparse.Namespace) -> int:
    """Synchronous wrapper for the top-level CLI dispatcher."""
    try:
        # All interactive prompts run HERE, outside the event loop. See
        # _prefill_interactive_inputs for why (questionary + asyncio.run).
        _prefill_interactive_inputs(args)
        rc = asyncio.run(run_deliver(args))
    except KeyboardInterrupt:
        print_warning("Deliver cancelled.")
        return 130
    if rc == 0:
        _maybe_open_headline(args)
    return rc


__all__ = (
    "DEFAULT_DELIVERABLE_SLUGS",
    "DELIVERABLE_LABELS",
    "DELIVERABLE_SLUGS",
    "add_deliver_subparser",
    "run_deliver",
    "run_deliver_sync",
)
