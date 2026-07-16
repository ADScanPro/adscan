"""Wordlist selection policy for the auto-crack job, by workspace type.

CTF favours speed (rockyou hits weak lab passwords). Audit favours recall under a
bounded wall-clock: an ESCALATING sequence of tiers, each run as a separate
background pass, so a match on tier 1 avoids ever paying for tier 3.

This module is also the cracking-effort SSOT (see
docs/superpowers/plans/2026-07-07-cracking-effort-engine.md Task 3):
``resolve_effort()`` turns a ``fast``/``balanced``/``thorough`` choice into a
concrete, time-budget-checked ladder of ``EffortTier`` (base wordlist x
rules), reading the hardware benchmark from
:mod:`adscan_internal.services.cracking_benchmark` so a CPU-only box
auto-downgrades the rule set instead of running for hours. The original
``wordlist_tiers_for_workspace`` is unchanged -- ``CrackingJobRuntime``
keeps consuming it byte-for-byte.

Audit base wordlist: the bundled ``combined_audit_base.txt`` (~94.0M entries).
It is a HOST-SIDE build-time merge of three frequency-ordered lists in strict
priority order (best first), de-duplicated keeping the FIRST occurrence so the
frequency ordering is preserved:

  1. hashmob "large" (~61.3M, richest + frequency-ordered)
  2. kerberoast_pws  (~35.6M; contributes ~32.7M UNIQUE service-account
     passwords not present in "large")
  3. kaonashi_10K    (10K top-ranked seeds)

The merge is a priority-concatenation piped through ``rling`` (order-preserving
dedup) — NOT ``sort -u`` (which would destroy the frequency order). Only the
merged ``combined_audit_base.txt`` ships in the runtime image; the three raw
components are dropped from the build context after the merge, so the audit
base is a single ~1GB file rather than ~2GB of overlapping lists (see
``scripts/build_combined_audit_wordlist.sh``). If the combined asset has not
been built yet the resolver falls back to the "large" component alone
(``hashmob_combined_large.found``); the caller skips any tier whose file is
missing at run time.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, List, Optional

from adscan_internal.services.cracking_benchmark import BENCHMARK_MODES

_ROCKYOU = "rockyou.txt"
# The bundled audit base: combined_audit_base.txt (~94.0M lines) — the host-side
# priority-concat + order-preserving rling merge of hashmob-large +
# kerberoast_pws + kaonashi_10K. Serves both the sync tier list
# (wordlist_tiers_for_workspace) and the effort base (base_for). See the module
# docstring for the merge rationale (shipped combined-only).
_COMBINED = "combined_audit_base.txt"
# The targeted-custom wordlist built by cli/cracking.py:_build_targeted_custom_wordlist
# (custom_wordlist_service.for_crack + the base+literal merge it performs) — see
# custom_wordlist_dir(domain) / custom_targeted.txt, NOT a generic "wordlist.txt".
_CUSTOM_TARGETED = "custom_targeted.txt"


def wordlist_tiers_for_workspace(
    workspace_type: str, domain: str, wordlists_dir: str
) -> List[str]:
    """Ordered wordlist paths to try for this workspace type.

    Returns absolute paths. The caller (the crack job) skips any tier whose file
    is missing at run time — so listing the combined/custom list here is safe
    even before it has been built.
    """
    wt = str(workspace_type or "").strip().lower()
    rockyou = os.path.join(wordlists_dir, _ROCKYOU)
    if wt == "audit":
        from adscan_internal.services.custom_wordlist_service import (  # noqa: PLC0415
            custom_wordlist_dir,
        )

        try:
            targeted = str(custom_wordlist_dir(domain))
            targeted_file = os.path.join(targeted, _CUSTOM_TARGETED)
        except Exception:  # noqa: BLE001 — a missing custom dir must not break selection
            targeted_file = os.path.join(wordlists_dir, "custom", domain, _CUSTOM_TARGETED)
        return [targeted_file, rockyou, os.path.join(wordlists_dir, _COMBINED)]
    return [rockyou]


# --- Effort tiers (fast/balanced/thorough) --------------------------------
#
# Promotes this module from "which wordlist file for this workspace type"
# into the time-budget effort SSOT. Every cracking consumer resolves "how
# much effort" through resolve_effort(), which picks the largest (base
# wordlist x rules) keyspace that fits the measured hardware's time budget
# for that tier -- so a 'thorough' request exploits the full 94M combined
# audit base on a GPU box and auto-downgrades on a CPU-only box instead of
# running for hours.
#
# Design principle -- "measured benchmark drives capping, budget is
# hardware-independent wall-clock". The per-tier budget in
# _TIER_BUDGET_SECONDS is a fixed WALL-CLOCK ceiling that does NOT depend on
# the hardware. What adapts is the RULE RUNG the resolver picks: it reads the
# per-machine H/s measured by cracking_benchmark (real hashcat -b on THIS box,
# GPU or CPU) and walks the ladder backward to the largest rung whose
# estimated (base_lines x rule_lines) / H_per_s time still fits the budget.
# So the SAME 'thorough' request lands on OneRule-full on a fast GPU,
# OneRule-10k on a mid GPU, and best64/bare on a CPU-only Kali VM -- one
# ladder, hardware-adaptive, no hardcoded rate. Any H/s figure quoted in the
# comments or the design doc is calibration-only; the live cap always uses the
# value cracking_benchmark measured on the box running the scan.

EFFORT_LEVELS: tuple[str, ...] = ("fast", "balanced", "thorough")
_DEFAULT_EFFORT = "balanced"

# Rule ladder, smallest keyspace first -- 4 rungs. A CPU/weak-GPU downgrade
# walks BACKWARD through this ladder (see _pick_capped_rule_index) until the
# keyspace fits the tier's time budget, so weak hardware steps DOWN THROUGH the
# intermediate rung rather than collapsing straight from OneRule-full to
# best64 (the gap this rung was added to close: on the 94M base a GPU that
# cannot finish 48,414 rules in the thorough budget can still finish 10,000).
#
#   index 0 = bare wordlist          (1 rule-pass  -- fast floor)
#   index 1 = best64.rule            (77 rules)
#   index 2 = OneRuleToRuleThemStill-10k.rule (10,000 rules -- the frequency-
#             ordered high-yield prefix of OneRule; the intermediate rung that
#             lets a mid-tier GPU exploit the 94M base within budget)
#   index 3 = OneRuleToRuleThemStill.rule (48,414 rules -- thorough top rung,
#             and the fixed rule set the custom-targeted tier always uses,
#             see _build_custom_tier)
_RULE_BEST64 = "best64.rule"
_RULE_ONE_TO_RULE_THEM_STILL_10K = "OneRuleToRuleThemStill-10k.rule"
_RULE_ONE_TO_RULE_THEM_STILL = "OneRuleToRuleThemStill.rule"
_RULE_LADDER: tuple[tuple[Optional[str], int], ...] = (
    (None, 1),
    (_RULE_BEST64, 77),
    (_RULE_ONE_TO_RULE_THEM_STILL_10K, 10_000),
    (_RULE_ONE_TO_RULE_THEM_STILL, 48_414),
)
# Nominal (uncapped) rung each effort level targets on the 4-rung ladder:
#   fast     -> bare wordlist (index 0)
#   balanced -> OneRule-10k intermediate (index 2)
#   thorough -> OneRule-full top rung (index 3)
# The measured-benchmark cap then downgrades from the nominal rung as needed
# (a mid GPU running 'thorough' lands on index 2, a CPU on index 1/0).
_EFFORT_RULE_INDEX: dict[str, int] = {"fast": 0, "balanced": 2, "thorough": 3}

# --- generic base wordlist -- pluggable, never hardcoded into the effort
# logic below. The DEFAULT audit base is the bundled combined_audit_base.txt
# (~94.0M entries) — the host-side priority-concat + order-preserving rling
# merge of hashmob-large + kerberoast_pws + kaonashi_10K (see the module
# docstring). Only the combined asset ships in the runtime image. The FALLBACK
# is the "large" component alone (hashmob_combined_large.found): on a machine
# where the merge has not run yet (a dev checkout, a synthetic test) base_for()
# degrades to it gracefully; the caller already skips any tier whose file is
# missing at run time. The default ctf base is rockyou.txt. Swapping the audit
# default for a different asset later (e.g. a curated weakpass list) is a
# one-line change to these constants, or a per-call ``override`` passed into
# base_for()/resolve_effort() -- resolve_effort()/_build_tier() never hardcode
# a filename.
_DEFAULT_CTF_BASE_FILENAME = _ROCKYOU
_DEFAULT_AUDIT_BASE_FILENAME = "combined_audit_base.txt"
_AUDIT_BASE_FALLBACK_FILENAME = "hashmob_combined_large.found"

# Approximate line counts, used ONLY as a fallback for the time-budget
# estimate when the base file isn't present on disk yet (a fresh workspace
# before the mounted asset is downloaded, or a synthetic test path) --
# _estimate_line_count() prefers a real stat()-based estimate whenever the
# file exists, which also makes an operator-supplied ``override`` work
# without needing its own hardcoded entry here.
_ROCKYOU_LINES_FALLBACK = 14_344_391
# combined_audit_base.txt measured at ~94,003,839 lines (large + kerberoast_pws
# + kaonashi_10K, order-preserving dedup, 2026-07-07 snapshot). Used only
# pre-build/pre-download; _estimate_line_count() prefers a real stat() when the
# file exists on disk.
_COMBINED_AUDIT_BASE_LINES_FALLBACK = 94_000_000
# The fallback base (the "large" component alone) is ~61,307,459 lines
# (2026-07-05 snapshot) — kept distinct from the combined count so the
# time-budget estimate stays accurate when the merge has not run and base_for()
# degrades to hashmob_combined_large.found.
_AUDIT_BASE_FALLBACK_LINES_FALLBACK = 61_300_000
# The auto-mined per-domain custom list is small (~1k-50k lines, owner-
# measured) -- used only as the fallback for the custom tier's estimate.
_CUSTOM_BASE_LINES_FALLBACK = 10_000

# Bytes-per-line average calibrated against rockyou.txt (~9.76 B/line) --
# used to turn a cheap os.path.getsize() stat() into an approximate line
# count without reading a (possibly 500MB+) wordlist on every resolution.
_AVG_BYTES_PER_LINE = 10.0

# Per-tier wall-clock ceiling (seconds), HARDWARE-INDEPENDENT: the resolver
# downgrades the rule rung until the estimated time (base_lines x rule_lines /
# measured H_per_s) fits under this budget on the ACTUAL hardware. fast stays
# near-instant even on CPU; balanced fits inside a background-job tick;
# thorough is a stoppable background job, so it gets a full 1h -- enough for a
# real GPU to reach OneRule-full (48,414 rules) over the 94M combined base,
# while the ladder still auto-downgrades to OneRule-10k / best64 / bare on
# weaker hardware that cannot finish the top rung in the hour.
_TIER_BUDGET_SECONDS: dict[str, float] = {
    "fast": 5.0,
    "balanced": 300.0,
    "thorough": 3600.0,
}

# Worst-case mode (lowest measured H/s of the four modes ADscan cracks) used
# to decide whether a tier needs capping -- Kerberoast is consistently the
# slowest in the design spec's calibration table.
_CAP_REFERENCE_MODE = "13100"

# The custom-targeted tier always runs first, at the heaviest rule set.
_CUSTOM_TIER_NAME = "custom"


@dataclass(frozen=True)
class EffortTier:
    """A concrete, budget-checked (base wordlist x rules) crack attempt."""

    name: str
    base_path: str
    rule_path: Optional[str]
    device_class: str  # "gpu" | "cpu" | "unknown"
    estimated_seconds_per_mode: "dict[str, float]" = field(default_factory=dict)


def _resolve_rule_asset_path(name: str) -> Optional[str]:
    """Resolve a bundled/managed hashcat rule file by name.

    Mirrors adscan_internal.cli.cracking.resolve_rules_path's search order
    (bundled in-repo asset dir, then the managed ~/.adscan/wordlists/rules/
    dir). Deliberately DUPLICATED here rather than imported: cli/cracking.py
    already imports FROM services/ (the established direction in this
    codebase), so importing back from services/ into cli/ would be a
    layering violation. Both resolve the SAME on-disk files.
    """
    if not name:
        return None

    from pathlib import Path  # noqa: PLC0415

    from adscan_core.paths import get_adscan_home  # noqa: PLC0415

    bundled = Path(__file__).resolve().parents[1] / "assets" / "rules" / name
    if bundled.is_file():
        return str(bundled)
    try:
        managed = get_adscan_home() / "wordlists" / "rules" / name
    except Exception:  # noqa: BLE001
        return None
    return str(managed) if managed.is_file() else None


def _estimate_line_count(path: str, fallback: int) -> int:
    """Approximate a wordlist's line count from its file size (a cheap
    ``stat()``, never a full read) -- generalizes to ANY base file, including
    an operator-supplied override, without a per-filename lookup table. Falls
    back to ``fallback`` when the file is not present on disk (yet).
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return fallback
    if size <= 0:
        return fallback
    return max(1, int(size / _AVG_BYTES_PER_LINE))


def base_for(
    workspace_type: str, wordlists_dir: str, *, override: Optional[str] = None
) -> "tuple[str, int]":
    """Resolve ``(base_path, approx_line_count)`` for a workspace type.

    This is the pluggable seam for the generic effort base -- see the module
    docstring above. ``override`` is an absolute path, or a filename resolved
    against ``wordlists_dir``, that replaces the default AUDIT base (ctf
    always stays on rockyou.txt). A missing/unreadable override silently
    falls back to the built-in default resolution so a bad config entry never
    breaks cracking.
    """
    wt = str(workspace_type or "").strip().lower()
    if wt != "audit":
        path = os.path.join(wordlists_dir, _DEFAULT_CTF_BASE_FILENAME)
        return path, _estimate_line_count(path, _ROCKYOU_LINES_FALLBACK)

    if override:
        candidate = (
            override if os.path.isabs(override) else os.path.join(wordlists_dir, override)
        )
        if os.path.isfile(candidate):
            return candidate, _estimate_line_count(
                candidate, _COMBINED_AUDIT_BASE_LINES_FALLBACK
            )

    combined = os.path.join(wordlists_dir, _DEFAULT_AUDIT_BASE_FILENAME)
    if os.path.isfile(combined):
        return combined, _estimate_line_count(combined, _COMBINED_AUDIT_BASE_LINES_FALLBACK)
    fallback = os.path.join(wordlists_dir, _AUDIT_BASE_FALLBACK_FILENAME)
    return fallback, _estimate_line_count(fallback, _AUDIT_BASE_FALLBACK_LINES_FALLBACK)


def _device_class_for(benchmark: dict, mode: str) -> str:
    rates = benchmark.get(mode) or {}
    if rates.get("gpu"):
        return "gpu"
    if rates.get("cpu"):
        return "cpu"
    return "unknown"


def _pick_capped_rule_index(
    nominal_index: int, base_lines: int, h_per_s: Optional[float], budget_seconds: float
) -> int:
    """Walk the rule ladder backward from ``nominal_index`` until the
    estimated keyspace/H_per_s time fits ``budget_seconds``. Never returns
    below 0 (a bare wordlist is always the floor)."""
    if not h_per_s:
        return nominal_index
    index = nominal_index
    while index > 0:
        _, rule_lines = _RULE_LADDER[index]
        estimated = (base_lines * rule_lines) / h_per_s
        if estimated <= budget_seconds:
            break
        index -= 1
    return index


def _build_tier(
    level: str,
    *,
    workspace_type: str,
    wordlists_dir: str,
    benchmark: Optional[dict],
    base_override: Optional[str] = None,
) -> EffortTier:
    base_path, base_lines = base_for(workspace_type, wordlists_dir, override=base_override)
    nominal_index = _EFFORT_RULE_INDEX[level]

    if not benchmark:
        rule_name, _ = _RULE_LADDER[0]
        return EffortTier(
            name=level,
            base_path=base_path,
            rule_path=_resolve_rule_asset_path(rule_name) if rule_name else None,
            device_class="unknown",
            estimated_seconds_per_mode={},
        )

    device_class = _device_class_for(benchmark, _CAP_REFERENCE_MODE)
    ref_rate = (benchmark.get(_CAP_REFERENCE_MODE) or {}).get(device_class)
    budget = _TIER_BUDGET_SECONDS[level]
    capped_index = _pick_capped_rule_index(nominal_index, base_lines, ref_rate, budget)
    rule_name, rule_lines = _RULE_LADDER[capped_index]

    estimated: "dict[str, float]" = {}
    for mode in BENCHMARK_MODES:
        rate = (benchmark.get(mode) or {}).get(device_class)
        if rate:
            estimated[mode] = (base_lines * rule_lines) / rate

    return EffortTier(
        name=level,
        base_path=base_path,
        rule_path=_resolve_rule_asset_path(rule_name) if rule_name else None,
        device_class=device_class,
        estimated_seconds_per_mode=estimated,
    )


def _resolve_custom_tier_base(domain: str) -> Optional[str]:
    """Path to the auto-mined per-domain custom-targeted list, or ``None``
    when it hasn't been built yet (fresh workspace, no domain, or the
    poisoning/auto-crack mining step never ran) -- never raises.
    """
    if not domain:
        return None
    try:
        from adscan_internal.services.custom_wordlist_service import (  # noqa: PLC0415
            custom_wordlist_dir,
        )

        candidate = custom_wordlist_dir(domain) / _CUSTOM_TARGETED
    except Exception:  # noqa: BLE001 -- a missing custom dir must not break resolution
        return None
    return str(candidate) if candidate.is_file() else None


def _build_custom_tier(domain: str, benchmark: Optional[dict]) -> Optional[EffortTier]:
    """The custom-targeted tier -- ALWAYS run first, at the heaviest rule set.

    The auto-mined per-domain list is small (~1k-50k lines) so it can carry
    OneRuleToRuleThemStill essentially for free (owner-measured: ~10k custom
    x OneRule is <1s on GPU, <=~67s worst-mode on CPU) -- cheap enough to run
    unconditionally ahead of the effort-scaled generic tiers, and never
    subject to the CPU rule-capping those tiers use. Returns ``None`` (skip
    gracefully) when the custom list has not been mined yet.
    """
    base_path = _resolve_custom_tier_base(domain)
    if not base_path:
        return None

    rule_name, rule_lines = _RULE_LADDER[-1]  # heaviest: OneRuleToRuleThemStill
    device_class = "unknown"
    estimated: "dict[str, float]" = {}
    if benchmark:
        device_class = _device_class_for(benchmark, _CAP_REFERENCE_MODE)
        base_lines = _estimate_line_count(base_path, _CUSTOM_BASE_LINES_FALLBACK)
        for mode in BENCHMARK_MODES:
            rate = (benchmark.get(mode) or {}).get(device_class)
            if rate:
                estimated[mode] = (base_lines * rule_lines) / rate

    return EffortTier(
        name=_CUSTOM_TIER_NAME,
        base_path=base_path,
        rule_path=_resolve_rule_asset_path(rule_name),
        device_class=device_class,
        estimated_seconds_per_mode=estimated,
    )


def resolve_effort(
    effort: str,
    *,
    workspace_type: str,
    domain: str,
    wordlists_dir: str,
    benchmark: Optional[dict],
    base_override: Optional[str] = None,
) -> "List[EffortTier]":
    """Resolve an effort choice into the tier ladder to try, in order.

    ALWAYS prepends the custom-targeted tier (max rules) when the per-domain
    auto-mined list is present, regardless of ``effort`` or ``benchmark`` --
    see ``_build_custom_tier``. The effort level then scales only the GENERIC
    base tiers that follow: the escalating ladder from ``effort`` up to
    ``thorough`` (the consumer walks it in order, stopping at the first
    crack). An unrecognised ``effort`` value falls back to ``'balanced'``. A
    missing benchmark (never run, or an unrecoverable failure with no prior
    cache) forces a single generic ``'fast'`` tier after the custom prepend --
    the only generic tier proven safe with no hardware measurement.

    ``base_override`` is the pluggable seam for the generic audit base (see
    ``base_for()``) -- swap the combined asset for a curated list without
    editing this function.
    """
    normalized = str(effort or "").strip().lower()
    if normalized not in EFFORT_LEVELS:
        normalized = _DEFAULT_EFFORT

    tiers: "List[EffortTier]" = []
    custom_tier = _build_custom_tier(domain, benchmark)
    if custom_tier is not None:
        tiers.append(custom_tier)

    if not benchmark:
        tiers.append(
            _build_tier(
                "fast",
                workspace_type=workspace_type,
                wordlists_dir=wordlists_dir,
                benchmark=None,
                base_override=base_override,
            )
        )
        return tiers

    start_idx = EFFORT_LEVELS.index(normalized)
    tiers.extend(
        _build_tier(
            level,
            workspace_type=workspace_type,
            wordlists_dir=wordlists_dir,
            benchmark=benchmark,
            base_override=base_override,
        )
        for level in EFFORT_LEVELS[start_idx:]
    )
    return tiers


def resolve_configured_effort(shell: Any) -> Optional[str]:
    """Read the operator-configured cracking effort off ``shell.scan_config``
    (the ``--scan-config`` YAML ``cracking.effort`` key), when present.

    Returns ``None`` when the shell has no scan_config (a plain interactive
    REPL session that never ran through ``adscan ci``) so callers fall back
    to their own default/prompt -- never raises on a missing attribute.
    """
    try:
        scan_config = getattr(shell, "scan_config", None)
        cracking = getattr(scan_config, "cracking", None)
        effort = getattr(cracking, "effort", None)
        return str(effort).strip().lower() if effort else None
    except Exception:  # noqa: BLE001
        return None


def default_effort_for_workspace(workspace_type: str) -> str:
    """The active-by-default effort tier when no ``cracking.effort`` was
    configured, so the effort engine is never dormant.

    ``audit`` -> ``balanced`` (matches today's audit auto-crack policy,
    upgraded to the rule-aware ladder). Everything else (``ctf``, unknown) ->
    ``fast``, matching the existing CTF "near-instant" precedent.
    """
    return (
        "balanced"
        if str(workspace_type or "").strip().lower() == "audit"
        else "fast"
    )


def resolve_effort_or_default(shell: Any) -> str:
    """:func:`resolve_configured_effort`, falling back to
    :func:`default_effort_for_workspace` when the scan config doesn't set
    ``cracking.effort`` explicitly (including plain interactive sessions with
    no ``scan_config`` at all).

    This is the entry point auto-crack callers use so the effort engine is
    active by default rather than dormant -- best-effort like
    ``resolve_configured_effort``, never raises.
    """
    configured = resolve_configured_effort(shell)
    if configured:
        return configured
    return default_effort_for_workspace(getattr(shell, "type", ""))


# --- Effort ESTIMATE (per-mode wall-clock for the interactive selector + web) --
#
# The interactive CLI effort selector and (later) the web effort cards both need
# a single number per (effort, hash-mode): "how long will this tier take on THIS
# box for THIS hash type". ``estimate_effort()`` is that SSOT. It reuses the
# EXACT keyspace / H-per-s math ``resolve_effort()`` uses (base_lines x the
# benchmark-capped rule_lines / measured H/s) so the advertised estimate matches
# what the crack job will actually do, including the rule-rung downgrade on weak
# hardware -- a 'thorough' request on a CPU-only box therefore reports the capped
# (budget-fitting) time, not a raw 26h keyspace.
#
# When no benchmark has been measured yet (cold box, warm-up still running) it
# falls back to a design-calibration rate table (an RTX 4060 GPU reference plus
# the CPU numbers from the same run) and flags the estimate ``provisional`` so
# the UI can render "(estimating...)".

# Fast fits inline (the operator waits the few seconds); anything slower routes
# to a background job. 30s is the fast/background boundary.
_BLOCKING_THRESHOLD_SECONDS = 30.0

# Design-calibration H/s (RTX 4060 reference, 2026-07-07 benchmark that
# calibrated the tiers) -- used ONLY when the live benchmark cache is cold so the
# selector can still show a ballpark. Provisional estimates use the GPU column
# (the appliance default); the CPU column is kept so a future provisional-CPU
# path stays a one-line change.
_CALIBRATION_RATES: dict[str, dict[str, float]] = {
    "5600": {"gpu": 1.79e9, "cpu": 69.6e6},
    "5500": {"gpu": 23.6e9, "cpu": 1.0e9},
    "13100": {"gpu": 555e6, "cpu": 7.27e6},
    "18200": {"gpu": 563e6, "cpu": 9.06e6},
}

# Bumped whenever the estimates-artifact SHAPE changes (the web consumes it).
_ESTIMATES_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class EffortEstimate:
    """A single (effort x hash-mode) wall-clock estimate for THIS hardware."""

    effort: str
    mode: str
    seconds: float
    human: str
    is_blocking: bool
    provisional: bool


def human_duration(seconds: float) -> str:
    """Render a duration the way the effort selector shows it: ``"≈ 5s"``,
    ``"≈ 8 min"``, ``"≈ 2.3 h"``. Never raises on a bad input."""
    try:
        secs = max(0.0, float(seconds))
    except (TypeError, ValueError):
        return "≈ ?"
    if secs < 1:
        return "≈ <1s"
    if secs < 60:
        return f"≈ {round(secs)}s"
    if secs < 3600:
        return f"≈ {round(secs / 60)} min"
    return f"≈ {secs / 3600:.1f} h"


def _calibration_rate(mode: str) -> Optional[float]:
    """GPU calibration H/s for ``mode`` (worst-case reference mode when the mode
    is not separately calibrated -- AES roast / timeroast)."""
    rates = _CALIBRATION_RATES.get(str(mode)) or _CALIBRATION_RATES.get(
        _CAP_REFERENCE_MODE
    )
    return (rates or {}).get("gpu")


def _measured_rate_for_mode(
    benchmark: dict, mode: str
) -> "tuple[Optional[float], str]":
    """``(rate, device_class)`` for ``mode`` from a measured benchmark. Modes
    ADscan does not separately benchmark (AES roast 19600.. / timeroast 31300)
    fall back to the worst-case reference mode so their estimate is pessimistic,
    never absent."""
    for candidate in (str(mode), _CAP_REFERENCE_MODE):
        rates = benchmark.get(candidate) or {}
        if rates.get("gpu"):
            return rates.get("gpu"), "gpu"
        if rates.get("cpu"):
            return rates.get("cpu"), "cpu"
    return None, "unknown"


def estimate_effort(
    effort: str,
    mode: str,
    *,
    benchmark: Optional[dict],
    base_lines: Optional[int] = None,
) -> EffortEstimate:
    """Estimate the wall-clock for one effort tier cracking ``mode`` on THIS box.

    Pure logic. Reuses the same keyspace/H-per-s math and the same benchmark
    rule-cap that :func:`resolve_effort` uses, so the estimate matches what the
    crack job actually runs. ``benchmark`` is the measured
    ``{mode: {gpu|cpu: H/s}}`` map (or ``None`` -> provisional calibration
    fallback). ``base_lines`` overrides the assumed base-wordlist line count
    (the selector passes the real ``base_for()`` count).
    """
    normalized = str(effort or "").strip().lower()
    if normalized not in EFFORT_LEVELS:
        normalized = _DEFAULT_EFFORT
    lines = (
        int(base_lines)
        if base_lines and base_lines > 0
        else _COMBINED_AUDIT_BASE_LINES_FALLBACK
    )
    nominal_index = _EFFORT_RULE_INDEX[normalized]
    budget = _TIER_BUDGET_SECONDS[normalized]

    provisional = False
    rate: Optional[float] = None
    if benchmark:
        rate, _device = _measured_rate_for_mode(benchmark, mode)
    if not rate:
        rate = _calibration_rate(mode)
        provisional = True

    if not rate:
        # No measurement AND no calibration for this mode -- cannot estimate.
        return EffortEstimate(
            effort=normalized,
            mode=str(mode),
            seconds=0.0,
            human="≈ ?",
            is_blocking=nominal_index == 0,
            provisional=True,
        )

    capped_index = _pick_capped_rule_index(nominal_index, lines, rate, budget)
    _rule_name, rule_lines = _RULE_LADDER[capped_index]
    seconds = (lines * rule_lines) / rate
    return EffortEstimate(
        effort=normalized,
        mode=str(mode),
        seconds=seconds,
        human=human_duration(seconds),
        is_blocking=seconds <= _BLOCKING_THRESHOLD_SECONDS,
        provisional=provisional,
    )


def resolve_single_tier(
    effort: str,
    *,
    workspace_type: str,
    wordlists_dir: str,
    benchmark: Optional[dict],
    base_override: Optional[str] = None,
) -> EffortTier:
    """The single benchmark-capped :class:`EffortTier` for one effort level.

    The interactive selector's inline / escape resolution: one tier (base
    wordlist x capped rules) rather than the escalating ladder
    :func:`resolve_effort` returns. Reuses the same ``_build_tier`` so capping
    and asset resolution stay identical.
    """
    normalized = str(effort or "").strip().lower()
    if normalized not in EFFORT_LEVELS:
        normalized = _DEFAULT_EFFORT
    return _build_tier(
        normalized,
        workspace_type=workspace_type,
        wordlists_dir=wordlists_dir,
        benchmark=benchmark,
        base_override=base_override,
    )


def build_estimates_payload(
    benchmark: Optional[dict],
    *,
    wordlists_dir: str,
    hardware_label: str,
) -> dict:
    """Build the ``cracking_benchmark_estimates.json`` payload (per mode x tier).

    The stable artifact the WEB consumes to render the same effort cards the CLI
    selector shows. Shape (schema v1)::

        {
          "schema_version": 1,
          "hardware_label": "NVIDIA GeForce RTX 4060",
          "base_wordlist": "combined_audit_base.txt",
          "base_lines": 94003839,
          "modes": {
            "13100": {
              "fast":     {"seconds": 0.9, "human": "≈ 1s",  "is_blocking": true,  "provisional": false},
              "balanced": {"seconds": 169, "human": "≈ 3 min","is_blocking": false, "provisional": false},
              "thorough": {"seconds": 1260,"human": "≈ 21 min","is_blocking": false,"provisional": false}
            },
            ...
          }
        }

    Pure logic (no IO). The IO writer lives in
    :func:`cracking_benchmark.write_benchmark_estimates`.
    """
    base_path, base_lines = base_for("audit", wordlists_dir)
    modes: dict[str, dict] = {}
    for mode in BENCHMARK_MODES:
        per_tier: dict[str, dict] = {}
        for level in EFFORT_LEVELS:
            est = estimate_effort(level, mode, benchmark=benchmark, base_lines=base_lines)
            per_tier[level] = {
                "seconds": round(est.seconds, 2),
                "human": est.human,
                "is_blocking": est.is_blocking,
                "provisional": est.provisional,
            }
        modes[str(mode)] = per_tier
    return {
        "schema_version": _ESTIMATES_SCHEMA_VERSION,
        "hardware_label": str(hardware_label or "unknown"),
        "base_wordlist": os.path.basename(base_path),
        "base_lines": base_lines,
        "modes": modes,
    }
