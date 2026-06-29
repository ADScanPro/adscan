"""Bonus PDF asset library — shared catalog and renderer.

After the surface-unification kill, the standalone ``adscan playbook``,
``adscan checklist`` and ``adscan coverage-matrix`` commands have been
removed. Those four PDFs are now generated exclusively through
``adscan deliver`` (with optional ``--only <slug>`` selection).

The LITE-tier ``adscan cheatsheet`` command remains — it is an operator
desk reference, not part of the Client Deliverable Kit, so it keeps its
own dedicated entry point.

This module retains:

* :data:`BONUSES` — the catalog (filename, title, template, theme) used
  by ``adscan deliver`` and ``adscan cheatsheet`` to render each item.
* :data:`_CONTEXT_BUILDERS` — Jinja context builders, one per bonus.
* :func:`render_bonus` — entry point used by ``deliver.py``.
* :func:`run_cheatsheet` / :func:`add_cheatsheet_subparser` — LITE CLI
  surface for the operator cheat sheet.

Workspace-aware filtering
-------------------------

When ``render_bonus`` is invoked with a ``workspace_dir`` pointing at a
real scan (``technical_report.json`` present), the playbook, checklist
and coverage matrix re-rank their content to surface techniques actually
observed in the engagement above the static reference catalog. The full
catalog is preserved in a clearly-labelled "for reference" section at
the end of each bonus, so audit / coverage use-cases still get
the comprehensive view.

When no workspace data is available, a visible warning is printed and
the bonuses fall back to the historical static behaviour.
"""

from __future__ import annotations

import argparse
import os
import time
from pathlib import Path
from typing import Any, Callable

from jinja2 import BaseLoader, Environment, select_autoescape

from adscan_core import telemetry
from adscan_core.paths import get_adscan_home_dir
from adscan_core.rich_output import (
    print_error,
    print_info,
    print_success,
    print_warning,
)


# ---------------------------------------------------------------------------
# Bonus catalog — central source of truth for filenames + stated values.
# ---------------------------------------------------------------------------

BONUSES: dict[str, dict[str, Any]] = {
    "playbook": {
        "filename": "AD_Hardening_Playbook.pdf",
        "title":    "AD Hardening Playbook",
        "value":    497,
        "subtitle": "30-day playbook for the six tactics that cause 80% of AD breaches.",
        "template": "playbook/playbook.html",
        # Warm editorial skin — the flagship report theme. ``editorial`` bridges
        # the bonus token scheme (--paper/--ink/--sev-*) onto its warm-bone + teal
        # palette, so the playbook reads as the same document family as the
        # editorial Security Assessment Report.
        "theme":    "editorial",
    },
    "cheatsheet": {
        "filename": "Quick_Start_Cheatsheet.pdf",
        "title":    "Quick-Start Cheat Sheet",
        "value":    197,
        "subtitle": "Two-page desk reference: 15 commands, 14 key bindings, 5 fast fixes.",
        "template": "cheatsheet/cheatsheet.html",
        # Themeless ON PURPOSE. The cheatsheet ships a complete, self-contained
        # DARK operator palette in its own ``:root`` (``--bg-0:#070b14``, cyan
        # accent). Injecting any shared theme is actively harmful: the light
        # ``premium_dark`` theme defines ``--surface``/``--accent``/``--line``
        # with the SAME names, lands AFTER the template's ``:root`` in the
        # cascade, and would override the cards to cream + the accent to ember
        # while the page background (``--bg-0``, not defined by the theme)
        # stays dark — a broken mixed render. An empty theme makes the
        # template's own palette authoritative and immune to theme changes.
        # (The cheatsheet is a standalone LITE lead magnet — it is NOT part of
        # the ``adscan deliver`` kit, so no ``--theme`` is ever forced on it.)
        "theme":    "",
    },
    "checklist": {
        "filename": "MITRE_Remediation_Checklist.pdf",
        "title":    "MITRE Remediation Checklist",
        "value":    297,
        "subtitle": "Auditor-grade remediation worksheet for every tracked ATT&CK technique.",
        "template": "checklist/checklist.html",
        # Unified editorial skin — see the playbook entry above.
        "theme":    "editorial",
    },
    # The Coverage Matrix bonus was folded into the AD Control Coverage Report:
    # the verified-clear coverage view (sourced from the scan's
    # ``control_evidence`` entries) IS the coverage matrix done right — it
    # proves scope from what was actually tested, not from a static catalog.
    # The kit slug stays ``coverage-matrix`` for back-compat (``deliver.py``
    # ``_KIT``, ``--only coverage-matrix``, the web selection dict); only the
    # rendered artifact changed.
    "coverage-matrix": {
        "filename":   "AD_Control_Coverage_Report.pdf",
        "title":      "AD Control Coverage Report",
        "value":      0,  # Assurance utility — no value-stack tag.
        "subtitle":   "The controls ADscan tested and confirmed clear in this engagement.",
        "template":   "coverage_report/coverage_report.html",
        "theme":      "editorial",
        "is_bonus":   False,
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_THEME_MARKER = "<!-- {{ THEME_CSS }} -->"


def _bonus_output_dir() -> Path:
    """Return the canonical output directory for bonus PDFs.

    Falls back to ``~/.adscan/bonuses`` when ADscan is running outside the
    container (e.g., during ``pytest``).
    """
    return get_adscan_home_dir() / "bonuses"


def _load_template(template_relpath: str) -> str:
    """Load a Jinja template source from the reporting templates package.

    Honors ``ADSCAN_TEMPLATE_OVERRIDE_DIR`` when set — the override dir is
    consulted FIRST and only falls through to the bundled package resource
    when the override path does not exist. This lets the LITE cheatsheet
    bake pipeline mount the live template directory from the host into the
    PRO container, so editing ``cheatsheet.html`` on disk takes effect on
    the next ``adscan cheatsheet`` invocation without requiring a full PRO
    image rebuild. Layout under the override dir mirrors the package
    layout exactly (e.g. ``cheatsheet/cheatsheet.html``).

    The override is opt-in: when the env var is empty/unset, behavior is
    byte-identical to the legacy "read from bundled resource" path.
    """
    override_dir = str(os.environ.get("ADSCAN_TEMPLATE_OVERRIDE_DIR") or "").strip()
    if override_dir:
        override_path = Path(override_dir) / template_relpath
        try:
            if override_path.is_file():
                return override_path.read_text(encoding="utf-8")
        except OSError:
            # Treat any I/O hiccup on the override path as "not present"
            # and fall through to the bundled resource so the bake never
            # hard-fails on a misconfigured mount.
            pass

    from importlib.resources import files

    root = files("adscan_internal.pro.reporting.templates")
    candidate = root.joinpath(template_relpath)
    if not candidate.is_file():
        raise FileNotFoundError(f"Bonus template missing: {template_relpath}")
    return candidate.read_text(encoding="utf-8")


def _load_theme(theme_name: str) -> str:
    """Load theme CSS — empty string if the theme is missing.

    Honors ``ADSCAN_THEME_OVERRIDE_DIR`` — same opt-in mechanism as
    ``_load_template``. The override dir holds theme files named
    ``<theme>.css`` (e.g. ``premium_dark.css``). When the override is
    unset or the file is not found, falls back to the bundled
    ``adscan_internal.pro.reporting.themes`` loader.
    """
    override_dir = str(os.environ.get("ADSCAN_THEME_OVERRIDE_DIR") or "").strip()
    if override_dir:
        override_path = Path(override_dir) / f"{theme_name}.css"
        try:
            if override_path.is_file():
                return override_path.read_text(encoding="utf-8")
        except OSError:
            pass

    try:
        from adscan_internal.pro.reporting.themes import load_theme_css

        return load_theme_css(theme_name)
    except Exception:
        return ""


# Cached base64 data-URIs for the ADscan wordmark. The asset lives in the
# canonical logos home ``adscan_internal/assets/logos/`` (same place
# ``report_service._find_adscan_logo`` reads, bundled in BOTH the PRO
# PyInstaller binary and the LITE image via the ``--add-data
# adscan_internal/assets/logos`` line in build_adscan.sh / adscan.spec):
#   * ``logo-wordmark-dark.png``  — charcoal ink, for the LIGHT paper
#     deliverable themes (the default; correct for every current bonus).
#   * ``logo-wordmark.png``       — original white ink, for a dark band.
# We embed as a data-URI (not a file path) because that is the only
# render-time-robust option across the LITE cheatsheet bake, the PRO
# binary's ``_MEIPASS`` tree, and source mode — the bytes travel inside
# the HTML so there is no path to resolve when WeasyPrint/chromium runs.
_BRAND_LOGO_CACHE: dict[str, str] = {}
_BRAND_LOGO_FILENAMES: dict[str, str] = {
    "dark": "logo-wordmark-dark.png",
    "light": "logo-wordmark.png",
}


def _brand_logo_data_uri(variant: str = "dark") -> str:
    """Return a base64 PNG data-URI for the ADscan wordmark.

    Reads from the canonical ``adscan_internal/assets/logos/`` home using
    the same search roots as ``report_service._find_adscan_logo``: the
    module-relative path (source mode + PyInstaller, since the binary
    unpacks ``assets/logos`` into its tree) and the ``_MEIPASS`` bundle
    root as a defensive fallback.

    Args:
        variant: ``"dark"`` (charcoal ink — light themes, the default) or
            ``"light"`` (white ink — dark band).

    Returns:
        ``data:image/png;base64,...`` string, or ``""`` if the asset
        cannot be read (never raises — the logo is cosmetic, and every
        template keeps a text-wordmark ``{% else %}`` fallback).
    """
    if variant in _BRAND_LOGO_CACHE:
        return _BRAND_LOGO_CACHE[variant]

    filename = _BRAND_LOGO_FILENAMES.get(variant, _BRAND_LOGO_FILENAMES["dark"])
    data_uri = ""
    try:
        import base64
        import sys

        raw: bytes | None = None
        # 1. Module-relative: bonuses.py → cli/ → adscan_internal/ → assets/logos/.
        #    Works in source mode and in the PyInstaller-unpacked tree.
        try:
            candidate = (
                Path(__file__).parent.parent / "assets" / "logos" / filename
            )
            if candidate.is_file():
                raw = candidate.read_bytes()
        except OSError:
            raw = None
        # 2. PyInstaller _MEIPASS bundle root (defensive — mirrors
        #    _find_adscan_logo's second search root).
        if raw is None:
            meipass = getattr(sys, "_MEIPASS", None)
            if meipass:
                mp = Path(meipass) / "adscan_internal" / "assets" / "logos" / filename
                try:
                    if mp.is_file():
                        raw = mp.read_bytes()
                except OSError:
                    raw = None
        if raw is not None:
            encoded = base64.b64encode(raw).decode("ascii")
            data_uri = f"data:image/png;base64,{encoded}"
    except Exception as exc:  # noqa: BLE001 — logo is cosmetic; never break render
        telemetry.capture_exception(exc)
        data_uri = ""

    _BRAND_LOGO_CACHE[variant] = data_uri
    return data_uri


def _wordmark_variant_for_theme(theme: str | None) -> str:
    """Pick the wordmark ink that contrasts with ``theme``'s page background.

    Thin delegate to the single source of truth in the themes package so the
    report and the bonus kit can never disagree on the wordmark ink for a
    given theme.

    Args:
        theme: Resolved theme name (e.g. ``"premium_dark"``,
            ``"corporate_light"``), or ``None`` to assume the light default.

    Returns:
        ``"light"`` (white ink — for a dark page background) or ``"dark"``
        (charcoal ink — for a light page background, the default).
    """
    from adscan_internal.pro.reporting.themes import wordmark_variant_for_theme

    return wordmark_variant_for_theme(theme)


def _render_html(template_source: str, context: dict[str, Any], theme_css: str) -> str:
    """Render a bonus template with theme CSS injected into ``<head>``."""
    env = Environment(loader=BaseLoader(), autoescape=select_autoescape(["html"]))
    rendered = env.from_string(template_source).render(**context)
    if theme_css:
        inject = f"<style data-adscan-theme>\n{theme_css}\n</style>"
        if _THEME_MARKER in rendered:
            rendered = rendered.replace(_THEME_MARKER, inject, 1)
        else:
            rendered = rendered.replace("</head>", f"{inject}\n</head>", 1)
    return rendered


def _render_pdf(html_str: str) -> bytes:
    """Render HTML to PDF bytes via the chromium engine."""
    from adscan_internal.pro.reporting.engines import get_engine
    from adscan_internal.pro.reporting.engines import (  # noqa: F401 - registration
        chromium_engine as _chromium,
    )

    engine = get_engine("chromium")
    ok, reason = engine.is_available()
    if not ok:
        raise RuntimeError(
            f"Chromium engine unavailable ({reason}). "
            "Install with: pip install playwright && playwright install chromium"
        )
    return engine.render_pdf(html_str, base_url=None, options={})


def _maybe_prompt_open(pdf_path: Path) -> None:
    """Prompt the operator to open the PDF; route through the host helper.

    Delegates to :func:`adscan_internal.services.host_open.prompt_and_open`
    so the PDF actually opens on the operator's desktop (via the host
    helper socket) instead of a no-op ``xdg-open`` inside a display-less
    container. The helper auto-skips in non-interactive contexts so
    ``adscan ci`` and similar batch flows remain non-blocking.
    """
    from adscan_internal.services.host_open import prompt_and_open

    prompt_and_open(pdf_path, prompt="Open it now?", default=True)


def _resolve_output_path(bonus_key: str, override: str | None) -> Path:
    """Resolve the final output path; create the parent dir lazily."""
    if override:
        path = Path(override).expanduser().resolve()
    else:
        path = (_bonus_output_dir() / BONUSES[bonus_key]["filename"]).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _print_completion_panel(bonus_key: str, pdf_path: Path) -> None:
    """Print the completion panel."""
    from adscan_internal.services.host_open import display_host_path

    meta = BONUSES[bonus_key]
    print_success(f"{meta['title']} ready: {display_host_path(pdf_path)}")
    print_info("")
    if meta.get("is_bonus", True):
        print_info("  This bonus is included free with ADscan.")
        print_info(f"  Stated value: ${meta['value']}.")
    else:
        print_info(f"  {meta.get('subtitle', '')}")
    print_info("")


# ---------------------------------------------------------------------------
# Workspace-aware filtering helpers
# ---------------------------------------------------------------------------


def _resolve_observed_techniques(workspace_dir: Path | None) -> set[str]:
    """Best-effort lookup of techniques observed in the workspace scan.

    Wraps :func:`bonus_workspace.get_observed_techniques` with the visible
    warning required by the bonus contract: if no workspace signal is
    available, the operator must know the bonus is being rendered from
    the static reference catalog rather than the live engagement.
    """
    if workspace_dir is None:
        return set()
    try:
        from adscan_internal.pro.reporting.bonus_workspace import (
            get_observed_techniques,
        )
        return get_observed_techniques(workspace_dir)
    except Exception as exc:  # noqa: BLE001 — bonus must still ship on failure
        telemetry.capture_exception(exc)
        return set()


def _is_observed(technique_id: str, observed: set[str]) -> bool:
    """Return ``True`` if the technique (or any ancestor) is in ``observed``.

    Match rules:

    * Exact ID hit (``T1558.003`` in observed set) → True
    * Parent technique hit when the ID is a subtechnique (observed
      contains ``T1558`` and ``technique_id`` is ``T1558.003``) → True
    * Any subtechnique of ``technique_id`` is observed (observed
      contains ``T1558.003`` and ``technique_id`` is ``T1558``) → True

    The third rule keeps the top-level reference techniques in the
    "observed" bucket whenever a more specific subtechnique fired.
    """
    if not observed:
        return False
    if technique_id in observed:
        return True
    if "." in technique_id:
        parent = technique_id.split(".", 1)[0]
        if parent in observed:
            return True
    else:
        prefix = technique_id + "."
        if any(tid.startswith(prefix) for tid in observed):
            return True
    return False


# ---------------------------------------------------------------------------
# Context builders — one per bonus.
# ---------------------------------------------------------------------------

# Map a tactic name (as used in the playbook chapter dicts) to the tactic
# label used in :mod:`mitre_data` so we can score chapters by how many
# observed techniques fall under each.
_PLAYBOOK_TACTIC_ALIASES: dict[str, str] = {
    "Credential Access":      "Credential Access",
    "Privilege Escalation":   "Privilege Escalation",
    "Lateral Movement":       "Lateral Movement",
    "Persistence":            "Persistence",
    "Defense Evasion":        "Defense Evasion",
    "Initial Access":         "Initial Access",
}


def _extract_technique_ids_from_action(action: str) -> list[str]:
    """Pull every ``T####(.###)?`` token out of a playbook action string."""
    import re

    return re.findall(r"T\d{4}(?:\.\d{3})?", action)


def _ctx_playbook(
    *,
    observed: set[str] | None = None,
    has_workspace_signal: bool = False,
    workspace_dir: Path | None = None,
    frameworks: list[str] | None = None,
) -> dict[str, Any]:
    """Build the Jinja context for the AD Hardening Playbook.

    Tier-3 behaviour: when ``workspace_dir`` yields a readable
    ``technical_report.json`` with findings, the playbook LEADS with the
    client's own data — an environment-specific executive opening, a
    severity/CVSS-ranked findings section (hosts + remediation + compliance
    controls closed), a prioritised 30-day roadmap seeded from those
    findings, and a compliance-gap summary. The curated six-tactic
    methodology and 30-day calendar remain as the subordinate "how"
    reference. The heavy lifting lives in
    :mod:`adscan_internal.pro.reporting.playbook_databinding` so this
    builder stays thin.

    Tier-1/2 fallback: when there is observed-technique signal but no
    readable findings payload, each chapter is still annotated with an
    ``observed_count`` and chapters re-order so observed tactics surface
    first. With no signal at all, the static chapter order is preserved and
    the generic narrative renders unchanged.
    """
    from adscan_internal.pro.reporting.playbook_content import PLAYBOOK

    observed = observed or set()
    tactics = [dict(chapter) for chapter in PLAYBOOK["tactics"]]

    # Annotate every chapter with the count of attacker actions whose
    # cited technique IDs appear in the observed set. The template uses
    # this to render an "observed in your scan" badge per chapter.
    for chapter in tactics:
        ids: set[str] = set()
        for action in chapter.get("attacker_actions", []):
            for tid in _extract_technique_ids_from_action(action):
                ids.add(tid)
        chapter["technique_ids"] = sorted(ids)
        chapter["observed_techniques"] = sorted(
            t for t in ids if _is_observed(t, observed)
        )
        chapter["observed_count"] = len(chapter["observed_techniques"])
        chapter["is_observed"] = chapter["observed_count"] > 0

    if has_workspace_signal and observed:
        # Stable resort: observed chapters first (descending observed_count),
        # then unobserved chapters in the original chapter order.
        tactics.sort(
            key=lambda c: (
                0 if c["is_observed"] else 1,
                -c["observed_count"],
                c["chapter"],
            )
        )

    # Tier-3 client-specific payload (None when no readable findings).
    client: dict[str, Any] | None = None
    try:
        from adscan_internal.pro.reporting.playbook_databinding import (
            build_playbook_databinding,
        )

        client = build_playbook_databinding(workspace_dir, frameworks)
    except Exception as exc:  # noqa: BLE001 — bonus must still ship on failure
        telemetry.capture_exception(exc)
        client = None

    return {
        "title":                PLAYBOOK["title"],
        "subtitle":             PLAYBOOK["subtitle"],
        "narrative_paragraphs": PLAYBOOK["narrative_paragraphs"],
        "tactics":              tactics,
        "calendar":             PLAYBOOK["calendar"],
        "report_date":          time.strftime("%B %d, %Y"),
        "has_workspace_signal": has_workspace_signal,
        "observed_count_total": sum(c["observed_count"] for c in tactics),
        # Tier-3 sections — present only when the workspace yielded findings.
        "client":               client,
        "has_client_data":      client is not None,
    }


def _ctx_cheatsheet() -> dict[str, Any]:
    """Build the Jinja context for the Quick-Start Cheat Sheet.

    Delegates to :mod:`adscan_internal.pro.reporting.cheatsheet_content`
    which (a) holds the curated commands / posture labels in one data
    structure, (b) auto-pulls scan phases from the canonical
    ``SCAN_PHASES`` tuple, and (c) runs a structural validator that
    fails the bake if any curated entry references a verb / category /
    phase that no longer exists. The import is lazy because this module
    lives under ``adscan_internal/pro/`` and is stripped from LITE; in
    LITE the cheatsheet command takes the pre-baked-PDF fast-path and
    never calls this function.
    """
    from adscan_internal.pro.reporting.cheatsheet_content import (
        build_cheatsheet_context,
    )

    return build_cheatsheet_context()


# Severity heuristic for the checklist — picked once per technique using the
# tactic + technique-id as a tiebreak. Keeps the catalog deterministic and
# aligned with the rest of the report engine. Workspace-observed techniques
# are surfaced separately at render time via the ``observed`` argument to
# :func:`_ctx_checklist`.
_CHECKLIST_SEVERITY: dict[str, str] = {
    # Critical — direct breakage of the domain or NTLM/Kerberos pillars.
    "T1003": "critical", "T1003.001": "critical", "T1003.006": "critical",
    "T1558.003": "critical", "T1558.004": "critical", "T1558": "critical",
    "T1550.002": "critical", "T1550.003": "critical",
    "T1078": "critical", "T1078.002": "critical",
    "T1486": "critical",
    # High — prerequisite or amplifier paths.
    "T1110.003": "high", "T1187": "high",
    "T1552.006": "high", "T1557.001": "high", "T1649": "high",
    "T1098": "high", "T1136": "high",
    "T1556.007": "high", "T1133": "high", "T1190": "high",
    "T1068": "high", "T1021.001": "high", "T1021.002": "high",
    # Medium — discovery and lateral helpers.
    "T1110.001": "medium", "T1552.001": "medium", "T1555": "medium",
    "T1018": "medium", "T1069": "medium", "T1087": "medium", "T1087.002": "medium",
    "T1482": "medium", "T1570": "medium", "T1027": "medium", "T1070": "medium",
}


def _ctx_checklist(
    *,
    observed: set[str] | None = None,
    has_workspace_signal: bool = False,
    workspace_dir: Path | None = None,
    frameworks: list[str] | None = None,
) -> dict[str, Any]:
    """Build the Jinja context for the MITRE Remediation Checklist.

    The template renders ``observed_groups`` (techniques actually surfaced
    by the scan, grouped by tactic) and ``reference_groups`` (the rest of
    the catalog, for coverage / audit completeness). When no workspace
    signal is available, ``observed_groups`` is empty and the template
    falls back to rendering ``reference_groups`` only.

    When ``workspace_dir`` is supplied, the per-finding **remediation
    tracker** (the actionable client-specific section that distinguishes
    this deliverable from the Coverage Matrix) is bound via
    ``checklist_databinding.build_checklist_databinding``. ``client`` is
    ``None`` and ``has_client_data`` is ``False`` when no usable findings
    exist — the template then renders the generic reference checklist.
    """
    from adscan_internal.pro.reporting.checklist_content import (
        TECHNIQUE_MITIGATIONS,
    )
    from adscan_internal.pro.reporting.mitre_data import (
        TACTICS_ORDER,
        TECHNIQUES,
    )

    observed = observed or set()
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    def _row(tid: str, name: str) -> dict[str, Any]:
        return {
            "id":         tid,
            "name":       name,
            "severity":   _CHECKLIST_SEVERITY.get(tid, "low"),
            "mitigation": TECHNIQUE_MITIGATIONS.get(
                tid, "Document the mitigation in the next sprint."
            ),
            "observed":   _is_observed(tid, observed),
        }

    by_tactic_obs: dict[str, list[dict[str, Any]]] = {t: [] for t in TACTICS_ORDER}
    by_tactic_ref: dict[str, list[dict[str, Any]]] = {t: [] for t in TACTICS_ORDER}
    for tid, meta in TECHNIQUES.items():
        tactic = meta["tactic"]
        if tactic not in by_tactic_obs:
            continue
        row = _row(tid, meta["name"])
        if row["observed"]:
            by_tactic_obs[tactic].append(row)
        else:
            by_tactic_ref[tactic].append(row)

    def _make_groups(by_tactic: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
        groups: list[dict[str, Any]] = []
        for tactic in TACTICS_ORDER:
            items = by_tactic.get(tactic) or []
            if not items:
                continue
            items.sort(key=lambda it: (-sev_rank.get(it["severity"], 0), it["id"]))
            groups.append({"tactic": tactic, "techniques": items})
        return groups

    observed_groups = _make_groups(by_tactic_obs) if has_workspace_signal else []
    reference_groups = _make_groups(by_tactic_ref)

    # When there is no workspace signal we still expose ``tactic_groups``
    # in the legacy shape so any external override of the template keeps
    # working. With signal, ``tactic_groups`` mirrors ``observed_groups``
    # for the same reason.
    tactic_groups = observed_groups if has_workspace_signal else reference_groups

    # Bind the per-finding remediation tracker (Tier-2/3 client section).
    # Best-effort: a binding failure must never break the reference
    # checklist render — mirror the playbook's defensive pattern.
    client: dict[str, Any] | None = None
    try:
        from adscan_internal.pro.reporting.checklist_databinding import (
            build_checklist_databinding,
        )

        client = build_checklist_databinding(workspace_dir, frameworks)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        client = None

    return {
        "tactic_groups":        tactic_groups,
        "observed_groups":      observed_groups,
        "reference_groups":     reference_groups,
        "has_workspace_signal": has_workspace_signal,
        "observed_count_total": sum(
            len(g["techniques"]) for g in observed_groups
        ),
        "report_date":          time.strftime("%B %d, %Y"),
        "client":               client,
        "has_client_data":      client is not None,
    }


def _ctx_coverage_matrix(
    *,
    observed: set[str] | None = None,
    has_workspace_signal: bool = False,
    workspace_dir: Path | None = None,
    frameworks: list[str] | None = None,
) -> dict[str, Any]:
    """Build the Jinja context for the AD Control Coverage Report.

    Sources the controls ADscan actively tested and confirmed clear from the
    scan's ``control_evidence`` entries (``category == "Coverage"``), written
    by ``update_report_field`` → ``record_control_evidence``. This folds the
    legacy Coverage Matrix into a positive-assurance view driven by what was
    actually tested, rather than a static ATT&CK reference catalog. The
    ``observed`` / ``has_workspace_signal`` / ``frameworks`` args are accepted
    for the uniform dynamic-builder signature but unused — coverage state comes
    from the report's control evidence (control name + what it defends against),
    NOT from any per-framework compliance map, so the selected ``--frameworks``
    do not change this report's content.

    Delegates to
    ``coverage_report_databinding.build_coverage_report_databinding``, which
    ALWAYS returns a full context (never ``None``): with no coverage evidence
    the template renders an empty-state explainer rather than a misleading
    empty table.
    """
    from adscan_internal.pro.reporting.coverage_report_databinding import (
        build_coverage_report_databinding,
    )

    return build_coverage_report_databinding(workspace_dir)


# Builders that consume workspace signal share a uniform signature
# ``builder(observed: set[str], has_workspace_signal: bool) -> dict``.
# Cheatsheet remains static — operator desk reference, not a deliverable.
_CONTEXT_BUILDERS_STATIC: dict[str, Callable[[], dict[str, Any]]] = {
    "cheatsheet": _ctx_cheatsheet,
}

_CONTEXT_BUILDERS_DYNAMIC: dict[
    str, Callable[..., dict[str, Any]]
] = {
    "playbook":        _ctx_playbook,
    "checklist":       _ctx_checklist,
    "coverage-matrix": _ctx_coverage_matrix,
}


def _build_context(
    bonus_key: str,
    workspace_dir: Path | None,
    theme: str | None = None,
    frameworks: list[str] | None = None,
) -> dict[str, Any]:
    """Build the Jinja context for ``bonus_key``, threading workspace data.

    Static bonuses (currently only the cheatsheet) ignore ``workspace_dir``.
    Dynamic bonuses receive the observed-technique set and a boolean
    flag indicating whether the workspace produced any usable signal —
    they use the flag to decide whether to render the "observed in this
    scan" sections.

    Args:
        bonus_key: One of the ``BONUSES`` keys.
        workspace_dir: Optional workspace to data-bind dynamic bonuses.
        theme: The resolved theme the deliverable will render with. Drives
            the theme-aware ``brand_logo`` ink so the wordmark always
            contrasts with the page background — no template guesses.
        frameworks: The compliance regimes the operator selected. Threaded into
            the playbook / checklist builders so their per-finding compliance
            cards and compliance-gap roll-ups render ONLY the selected
            frameworks (an ISO 27001 kit never leaks DORA/ENS). ``None`` keeps
            the legacy all-frameworks behaviour; the coverage report ignores it
            (it is framework-agnostic).
    """
    def _with_brand(ctx: dict[str, Any]) -> dict[str, Any]:
        """Inject the ADscan wordmark data-URIs into every context.

        Three template-facing variables, so a template author never has to
        reason about ink-vs-background:

        * ``{{ brand_logo }}`` — THEME-AWARE. Charcoal on a light theme,
          white on a dark theme. Use this on any band that inherits the
          deliverable theme (the report and the three themed bonuses).
        * ``{{ brand_logo_white }}`` — always white ink. Use only on a band
          with a FIXED dark background that does NOT follow the theme
          (the cheatsheet masthead).
        * ``{{ brand_logo_charcoal }}`` — always charcoal ink, for a fixed
          light band.

        ``brand_logo_light`` is kept as a deprecated alias of
        ``brand_logo_white`` so older templates do not silently lose the
        mark. Templates fall back to their text wordmark when a value is
        empty. Done here so all builders — static and dynamic — get the
        brand consistently without each one importing the helper.
        """
        theme_aware = _brand_logo_data_uri(_wordmark_variant_for_theme(theme))
        ctx.setdefault("brand_logo", theme_aware)
        ctx.setdefault("brand_logo_white", _brand_logo_data_uri("light"))
        ctx.setdefault("brand_logo_charcoal", _brand_logo_data_uri("dark"))
        ctx.setdefault("brand_logo_light", _brand_logo_data_uri("light"))
        return ctx

    if bonus_key in _CONTEXT_BUILDERS_STATIC:
        return _with_brand(_CONTEXT_BUILDERS_STATIC[bonus_key]())

    builder = _CONTEXT_BUILDERS_DYNAMIC.get(bonus_key)
    if builder is None:
        raise KeyError(f"No context builder for bonus '{bonus_key}'")

    observed = _resolve_observed_techniques(workspace_dir)
    has_signal = bool(observed)
    if workspace_dir is not None and not has_signal:
        # Workspace was supplied but produced no signal — operator must
        # know the bonus is being rendered from the static catalog so
        # they can investigate before sending it to the customer.
        print_warning(
            f"Bonus '{bonus_key}': no observed techniques in {workspace_dir} — "
            "rendering the static reference catalog as fallback."
        )
    # All three dynamic bonuses now consume the raw workspace to bind
    # client-specific sections: the playbook binds Tier-3 findings /
    # roadmap / compliance gaps, the checklist binds the per-finding
    # remediation tracker, and the coverage matrix binds the observed /
    # checked-clean / in-scope three-state view. They share the
    # extraction helpers in ``finding_databinding`` so hosts /
    # remediation / compliance render identically across the kit.
    kwargs: dict[str, Any] = {
        "observed": observed,
        "has_workspace_signal": has_signal,
    }
    if bonus_key in ("playbook", "checklist", "coverage-matrix"):
        kwargs["workspace_dir"] = workspace_dir
        kwargs["frameworks"] = frameworks
    return _with_brand(builder(**kwargs))


# ---------------------------------------------------------------------------
# Core renderer — used by ``adscan deliver`` to produce each kit PDF.
# ---------------------------------------------------------------------------

def render_bonus(
    bonus_key: str,
    output_path: Path,
    *,
    is_sample: bool = False,
    truncate: bool = False,
    workspace_dir: Path | None = None,
    theme: str | None = None,
    frameworks: list[str] | None = None,
) -> int:
    """Render a single bonus PDF to ``output_path``. Returns bytes written.

    Args:
        bonus_key: One of ``BONUSES`` keys.
        output_path: Destination PDF path (parent dirs must exist).
        is_sample: When ``True`` (only set by ``scripts/regenerate_samples.py``),
            inject the public-sample watermark band on every page. The
            cheatsheet is product documentation and is NEVER watermarked
            even when this flag is set.
        truncate: Playbook-only — render cover + narrative + Week 1 + a
            preview-CTA page (≈4 pages) instead of the full 30-day plan.
            Ignored for non-playbook bonuses.
        workspace_dir: Optional workspace path. When supplied, the
            playbook / checklist / coverage matrix bonuses re-rank their
            content so techniques observed in the workspace's
            ``technical_report.json`` surface above the static reference
            catalog. Passing ``None`` (or a workspace with no findings)
            falls back to the historical static behaviour with a visible
            warning.
        theme: Override the per-bonus default theme.  When non-empty,
            ``"premium_dark"`` / ``"dark"`` → dark operator aesthetic;
            ``"corporate_light"`` / ``"light"`` → white corporate theme
            suitable for printing or board presentations.  Empty string or
            ``None`` → use the theme catalogued in ``BONUSES[bonus_key]``.
        frameworks: The compliance regimes the operator selected (via
            ``adscan deliver --frameworks`` / the REPL / ``adscan ci``). The
            playbook and checklist render ONLY these frameworks' controls, so a
            kit built for one regime never leaks another's content. ``None``
            keeps the legacy all-frameworks behaviour; an empty list renders no
            compliance content. The coverage report ignores it.

    Real customer flows (``adscan deliver``, web Celery
    ``generate_deliverable_kit``) MUST NOT pass ``is_sample=True``.
    """
    _THEME_ALIASES = {"dark": "premium_dark", "light": "corporate_light"}
    if bonus_key not in BONUSES:
        raise KeyError(f"Unknown bonus '{bonus_key}'")

    meta = BONUSES[bonus_key]
    resolved_theme = _THEME_ALIASES.get(theme or "", theme or "") or meta["theme"]
    template_source = _load_template(meta["template"])
    theme_css = _load_theme(resolved_theme)
    context = _build_context(
        bonus_key, workspace_dir, theme=resolved_theme, frameworks=frameworks
    )
    if bonus_key == "playbook":
        context["truncate"] = bool(truncate)
    html_str = _render_html(template_source, context, theme_css)

    # Cheatsheet is product docs — never watermarked even on sample runs.
    if is_sample and bonus_key != "cheatsheet":
        from adscan_internal.pro.reporting.sample_watermark import (
            inject_sample_watermark,
        )
        html_str = inject_sample_watermark(html_str, is_sample=True)

    pdf_bytes = _render_pdf(html_str)
    output_path.write_bytes(pdf_bytes)
    return len(pdf_bytes)


# ---------------------------------------------------------------------------
# LITE CLI surface — only the operator cheat sheet keeps a standalone command.
# ---------------------------------------------------------------------------

# Pre-baked LITE cheatsheet PDF. The LITE runtime ships without the PRO
# reporting templates/engines, so it cannot render the cheatsheet on demand.
# Instead the LITE Dockerfile copies a single pre-baked PDF here (the
# private build pipeline produces it via ``scripts/bake_cheatsheet.sh``
# using the PRO renderer and seeds it into the build context).
_LITE_STATIC_CHEATSHEET_PATH = Path("/opt/adscan/static/cheatsheet/Quick_Start_Cheatsheet.pdf")


def _try_use_baked_static(bonus_key: str, output_path: Path) -> int | None:
    """When PRO renderer is unavailable, fall back to the pre-baked PDF.

    Returns the number of bytes copied when the fallback succeeds, ``None``
    when the fallback is not applicable (renderer is available or no
    baked artefact exists for ``bonus_key``).

    Currently only the LITE cheatsheet has a baked artefact — every other
    bonus belongs to the PRO Client Deliverable Kit and is gated by the
    exit-42 protocol upstream.
    """
    if bonus_key != "cheatsheet":
        return None
    try:
        # If this import succeeds we have the PRO renderer; defer to it.
        import adscan_internal.pro  # noqa: F401
        return None
    except ModuleNotFoundError:
        pass

    if not _LITE_STATIC_CHEATSHEET_PATH.is_file():
        # Image build pipeline failed to seed the asset. Surface the
        # condition clearly so it's a build-pipeline bug, not a silent
        # "your free thing is broken" moment for the operator.
        print_error(
            "LITE cheatsheet asset missing — the pre-baked PDF was not "
            "found at the expected path. This is a build-pipeline issue: "
            "rebuild the LITE image with `./scripts/build_docker_lite_image.sh --dev`."
        )
        return None

    output_path.parent.mkdir(parents=True, exist_ok=True)
    pdf_bytes = _LITE_STATIC_CHEATSHEET_PATH.read_bytes()
    output_path.write_bytes(pdf_bytes)
    return len(pdf_bytes)


def _run_one(args: argparse.Namespace, bonus_key: str) -> int:
    """Generic single-bonus runner — currently used only by ``run_cheatsheet``."""
    output_override = getattr(args, "output_path", None)
    no_open = bool(getattr(args, "no_open", False))
    no_render = bool(getattr(args, "no_render", False))

    output_path = _resolve_output_path(bonus_key, output_override)

    if no_render:
        try:
            meta = BONUSES[bonus_key]
            tpl = _load_template(meta["template"])
            ctx = _build_context(bonus_key, None, theme=meta["theme"])
            _render_html(tpl, ctx, _load_theme(meta["theme"]))
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error(f"Bonus dry-run failed: {exc}")
            return 1
        print_success(f"{BONUSES[bonus_key]['title']} dry-run OK (no PDF written).")
        return 0

    # LITE fast-path: if PRO renderer is stripped, copy the pre-baked PDF.
    baked_size = _try_use_baked_static(bonus_key, output_path)
    if baked_size is not None:
        size = baked_size
    else:
        try:
            size = render_bonus(bonus_key, output_path)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error(f"Could not render {BONUSES[bonus_key]['title']}: {exc}")
            return 1

    # Show the HOST path so the operator can copy/paste it. Inside the
    # container the artefact lives at /opt/adscan/bonuses/<file>, but the
    # bind mount surfaces the same bytes at ~/.adscan/bonuses/<file> on
    # the host — that's the path they'll actually need.
    from adscan_internal.services.host_open import display_host_path

    host_display = display_host_path(output_path)
    print_info(f"Wrote {size:,} bytes to {host_display}.")
    _print_completion_panel(bonus_key, output_path)
    if not no_open:
        _maybe_prompt_open(output_path)
    return 0


def run_cheatsheet(args: argparse.Namespace) -> int:
    """``adscan cheatsheet`` entry point (LITE-tier operator desk reference)."""
    return _run_one(args, "cheatsheet")


def add_cheatsheet_subparser(subparsers: argparse._SubParsersAction) -> None:
    """Register the LITE-tier ``cheatsheet`` subparser on the main argparse tree."""
    parser = subparsers.add_parser(
        "cheatsheet",
        help="Render the Quick-Start Cheat Sheet PDF (operator companion).",
    )
    parser.add_argument(
        "--output",
        dest="output_path",
        default=None,
        help=(
            "Override the output PDF path. Default: "
            f"~/.adscan/bonuses/{BONUSES['cheatsheet']['filename']}"
        ),
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="Do not prompt to open the PDF after rendering.",
    )
    parser.add_argument(
        "--no-render",
        action="store_true",
        help="Smoke / dry-run only — verify template + content, skip PDF render.",
    )


__all__ = [
    "BONUSES",
    "add_cheatsheet_subparser",
    "render_bonus",
    "run_cheatsheet",
]
