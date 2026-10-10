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
It is a HOST-SIDE build-time merge of two frequency-ordered lists in strict
priority order (best first), de-duplicated keeping the FIRST occurrence so the
frequency ordering is preserved:

  1. hashmob "large" (~61.3M, richest + frequency-ordered)
  2. kerberoast_pws  (~35.6M; contributes ~32.7M UNIQUE service-account
     passwords not present in "large")

The merge is a priority-concatenation piped through ``rling`` (order-preserving
dedup) — NOT ``sort -u`` (which would destroy the frequency order). Only the
merged ``combined_audit_base.txt`` ships in the runtime image; the raw
components are dropped from the build context after the merge, so the audit
base is a single ~1GB file rather than ~2GB of overlapping lists (see
``scripts/build_combined_audit_wordlist.sh``). If the combined asset has not
been built yet the resolver falls back to the "large" component alone
(``hashmob_combined_large.found``); the caller skips any tier whose file is
missing at run time.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional

from adscan_internal.services.cracking.achieved_rate_probe import (
    achieved_rate_key,
    mode_is_salted,
)
from adscan_internal.services.cracking_benchmark import BENCHMARK_MODES

#: A callable that answers "what rate does a real crack ACHIEVE for this
#: workload on this box", measuring it if it has to. Injected rather than
#: imported so this module stays pure logic and runnable with no shell: the web
#: renders the same estimates off a persisted cache and has no shell to probe
#: with. Built by ``cracking_benchmark.make_achieved_rate_provider(shell)``;
#: called with the keywords ``(mode, wordlist, rule_path, device_class,
#: hash_count)``.
AchievedRateProvider = Any

_ROCKYOU = "rockyou.txt"
# The bundled audit base: combined_audit_base.txt (~94.0M lines) — the host-side
# priority-concat + order-preserving rling merge of hashmob-large +
# kerberoast_pws. Serves both the sync tier list
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
            targeted_file = os.path.join(
                wordlists_dir, "custom", domain, _CUSTOM_TARGETED
            )
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
# merge of hashmob-large + kerberoast_pws (see the module
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

# The Windows onefile .exe bundles the ~928MB combined_audit_base.txt COMPRESSED
# with xz (built at bundle time via stdlib lzma) so the shipped binary stays
# ~500MB instead of ~1.2GB. At runtime the resolver decompresses it ONCE into the
# LOCALAPPDATA wordlists dir and reuses the plain .txt from then on (idempotent).
# This suffix is the ONLY compression variant we ship; the plain .txt always wins
# when present (Linux image, dev checkout, or a bundle that was staged raw).
_XZ_SUFFIX = ".xz"

# Approximate line counts, used ONLY as a fallback for the time-budget
# estimate when the base file isn't present on disk yet (a fresh workspace
# before the mounted asset is downloaded, or a synthetic test path) --
# _estimate_line_count() prefers a real stat()-based estimate whenever the
# file exists, which also makes an operator-supplied ``override`` work
# without needing its own hardcoded entry here.
_ROCKYOU_LINES_FALLBACK = 14_344_391
# combined_audit_base.txt measured at ~94,003,839 lines (large + kerberoast_pws,
# order-preserving dedup, 2026-07-07 snapshot). Used only
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

# The DEFAULT mode a tier's rule rung is capped against, for a caller that does
# not know which hash mode its lane will crack: the slowest mode ADscan
# measures (Kerberoast, consistently the slowest in the design spec's
# calibration table). Capping against the slowest mode can never overspend, so
# it is the right default for an unknown lane.
#
# It is the WRONG answer for a lane that DOES know its mode, and NT is why. NT
# benchmarks ~75x faster than Kerberoast, so planning the NT lane against
# Kerberoast's rate is not conservative, it discards most of the hardware: the
# ladder picks a rung the box finishes in seconds and the operator is quoted
# minutes. A lane that knows its mode therefore passes it as
# ``cap_reference_mode`` and is planned against the speed it will actually run
# at; every other caller keeps this default and is unchanged.
_CAP_REFERENCE_MODE = "13100"

# The rate a mode ADscan does NOT separately benchmark borrows for its estimate
# (etype-derived AES roast 19600.., timeroast 31300). Deliberately the slowest
# measured mode, so an unmeasured mode's estimate is pessimistic rather than
# absent. Same value as _CAP_REFERENCE_MODE today and a DIFFERENT question:
# this one is "what rate stands in for a mode we never measured", not "what mode
# do we plan an unknown lane against". They are kept apart so measuring one of
# these modes later moves only the role it belongs to.
_UNMEASURED_MODE_RATE_SOURCE = "13100"

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
    rule_rung: Optional[int] = None


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


def _bundled_wordlists_dir() -> Optional[Path]:
    """Return the PyInstaller-bundled ``wordlists`` directory when frozen.

    The Windows onefile ``.exe`` ships heavy wordlists (the ~94M-line
    ``combined_audit_base.txt``, rockyou) inside the binary; PyInstaller extracts
    them under ``sys._MEIPASS`` at runtime (the ``.spec`` adds
    ``("wordlists", "wordlists")``, so the bundled files live in
    ``<_MEIPASS>/wordlists/``). Callers point the resolver at
    ``%LOCALAPPDATA%\\ADscan\\wordlists`` instead, which does NOT contain the
    bundled assets, so without this seam the bundled combined is unreachable and
    audit cracking silently degrades to rockyou.

    Mirrors the frozen + ``_MEIPASS`` guard in
    :mod:`adscan_internal.services.credsweeper_service`. Returns ``None`` on any
    non-frozen / non-Windows / dev checkout (``sys.frozen`` is absent), so the
    behaviour off a frozen bundle is byte-identical to before.
    """
    if not (getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")):
        return None
    meipass = getattr(sys, "_MEIPASS", None)  # type: ignore[attr-defined]
    if not meipass:
        return None
    bundled = Path(meipass) / "wordlists"
    return bundled if bundled.is_dir() else None


def _bundled_wordlist_path(
    filename: str, decompress_dir: Optional[str] = None
) -> Optional[str]:
    """Absolute path to a bundled wordlist ``filename`` under ``_MEIPASS``.

    Handles both the direct-file layout (``<_MEIPASS>/wordlists/<filename>``) and
    the nested-dir layout PyInstaller may produce
    (``<_MEIPASS>/wordlists/<filename>/<filename>``), matching the
    credsweeper_service seam. When only an xz-compressed variant is bundled
    (``<filename>.xz`` — the Windows small-.exe case) it is decompressed once into
    ``decompress_dir`` (the caller's wordlists dir) and that plain path returned.
    Returns ``None`` when not frozen or the file (plain or .xz) is absent, so
    non-frozen callers see no change.
    """
    bundled_dir = _bundled_wordlists_dir()
    if bundled_dir is None:
        return None
    candidate = bundled_dir / filename
    if candidate.is_file():
        return str(candidate)
    if candidate.is_dir():
        nested = candidate / filename
        if nested.is_file():
            return str(nested)
    # The plain .txt is absent from the bundle. On Windows the heavy combined is
    # shipped xz-compressed (see _XZ_SUFFIX); decompress it ONCE into the
    # decompress_dir (the caller's wordlists dir, i.e. LOCALAPPDATA) and resolve
    # to that plain copy from then on.
    return _resolve_bundled_compressed(bundled_dir, filename, decompress_dir)


def _resolve_bundled_compressed(
    bundled_dir: "Path", filename: str, decompress_dir: Optional[str]
) -> Optional[str]:
    """Resolve ``filename`` from an xz-compressed bundled variant, if present.

    The Windows onefile ships the ~928MB combined_audit_base.txt as
    ``<filename>.xz`` to keep the .exe small. This locates that compressed
    variant under ``<_MEIPASS>/wordlists/`` (direct or nested layout) and
    decompresses it ONCE into ``decompress_dir`` (the CALLER's wordlists dir, so
    the decompressed copy lands exactly where ``base_for`` looks first on the
    next run — the idempotency guarantee), returning the decompressed plain path.
    A subsequent call reuses the already-decompressed file and never decompresses
    again. Returns ``None`` when no compressed variant is bundled, so non-Windows
    / raw-staged bundles are unaffected. ``decompress_dir`` falls back to the
    LOCALAPPDATA wordlists dir when not supplied.
    """
    compressed_name = filename + _XZ_SUFFIX
    compressed = bundled_dir / compressed_name
    compressed_path: Optional[Path] = None
    if compressed.is_file():
        compressed_path = compressed
    elif compressed.is_dir():
        # PyInstaller nested-dir layout: <_MEIPASS>/wordlists/<name>.xz/<name>.xz
        nested = compressed / compressed_name
        if nested.is_file():
            compressed_path = nested
    if compressed_path is None:
        return None
    return _decompress_bundled_xz_once(compressed_path, filename, decompress_dir)


def _decompress_bundled_xz_once(
    compressed_path: "Path", plain_filename: str, decompress_dir: Optional[str]
) -> Optional[str]:
    """Decompress a bundled ``.xz`` wordlist into ``decompress_dir``, once.

    Writes ``<decompress_dir>/<plain_filename>`` from ``compressed_path`` using
    stdlib :mod:`lzma` (no external ``xz`` binary), mirroring the
    decompress-on-first-run pattern used for rockyou (wordlist_service /
    adscan.py). ``decompress_dir`` is the CALLER's wordlists dir so the plain
    copy lands where ``base_for`` looks first next run; it defaults to the
    LOCALAPPDATA wordlists dir when ``None`` (the two are the SAME in production —
    both ``get_adscan_home()/wordlists``). Idempotent by construction: if the
    destination already exists (non-empty) it is returned untouched, so the
    ~928MB decompression happens only on the first run. Decompresses to a temp
    sibling and atomically renames so a crash mid-write never leaves a truncated
    file a later run would trust. Best-effort: on any error it returns ``None``
    (the caller then degrades to its next base), never raising into the crack
    flow.
    """
    import lzma  # noqa: PLC0415
    import shutil  # noqa: PLC0415

    from adscan_core.rich_output import (  # noqa: PLC0415
        print_exception,
        print_info_debug,
    )

    tmp: Optional[Path] = None
    try:
        if decompress_dir:
            dest_dir = Path(decompress_dir)
        else:
            from adscan_core.pal.paths import wordlists_dir  # noqa: PLC0415

            dest_dir = wordlists_dir()
        dest = dest_dir / plain_filename
        if dest.is_file() and dest.stat().st_size > 0:
            return str(dest)  # already decompressed on a previous run
        dest_dir.mkdir(parents=True, exist_ok=True)
        tmp = dest_dir / (plain_filename + ".partial")
        with lzma.open(compressed_path, "rb") as src, open(tmp, "wb") as out:
            shutil.copyfileobj(src, out)
        os.replace(tmp, dest)
        print_info_debug(
            f"Decompressed bundled {plain_filename} into the wordlists dir "
            "(first run only)."
        )
        return str(dest)
    except Exception as exc:  # noqa: BLE001
        print_exception(exception=exc)
        try:
            if tmp is not None and tmp.exists():
                tmp.unlink()
        except Exception:  # noqa: BLE001
            pass
        return None


def audit_base_is_available(wordlists_dir: str) -> bool:
    """Whether the combined audit base is resolvable, matching ``base_for``.

    The SSOT the availability check (``wordlist_service``) shares with the crack
    SELECTOR (``base_for``), so the two never disagree. It reports ``True`` when
    the combined_audit_base.txt is reachable by ANY of the routes ``base_for``
    uses for it: an operator-installed / already-decompressed copy in
    ``wordlists_dir`` (LOCALAPPDATA), the plain bundled copy under ``_MEIPASS``,
    or the xz-compressed bundled variant that ``base_for`` decompresses on first
    use. Purely observational — it never decompresses (a 928MB write is not an
    "is it present?" side effect); the actual first-run decompression is
    ``base_for``'s job when the tier is selected.
    """
    installed = os.path.join(wordlists_dir, _DEFAULT_AUDIT_BASE_FILENAME)
    if os.path.isfile(installed):
        return True
    bundled_dir = _bundled_wordlists_dir()
    if bundled_dir is None:
        return False
    plain = bundled_dir / _DEFAULT_AUDIT_BASE_FILENAME
    if plain.is_file() or (
        plain.is_dir() and (plain / _DEFAULT_AUDIT_BASE_FILENAME).is_file()
    ):
        return True
    compressed_name = _DEFAULT_AUDIT_BASE_FILENAME + _XZ_SUFFIX
    compressed = bundled_dir / compressed_name
    return compressed.is_file() or (
        compressed.is_dir() and (compressed / compressed_name).is_file()
    )


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
        if os.path.isfile(path):
            return path, _estimate_line_count(path, _ROCKYOU_LINES_FALLBACK)
        # Frozen .exe: rockyou may only exist inside the bundle, not in the
        # user data dir the caller passed. Prefer the bundled copy over a path
        # to a missing file. No-op off a frozen bundle (helper returns None).
        bundled_rockyou = _bundled_wordlist_path(
            _DEFAULT_CTF_BASE_FILENAME, decompress_dir=wordlists_dir
        )
        if bundled_rockyou:
            return bundled_rockyou, _estimate_line_count(
                bundled_rockyou, _ROCKYOU_LINES_FALLBACK
            )
        return path, _estimate_line_count(path, _ROCKYOU_LINES_FALLBACK)

    if override:
        candidate = (
            override
            if os.path.isabs(override)
            else os.path.join(wordlists_dir, override)
        )
        if os.path.isfile(candidate):
            return candidate, _estimate_line_count(
                candidate, _COMBINED_AUDIT_BASE_LINES_FALLBACK
            )

    combined = os.path.join(wordlists_dir, _DEFAULT_AUDIT_BASE_FILENAME)
    if os.path.isfile(combined):
        return combined, _estimate_line_count(
            combined, _COMBINED_AUDIT_BASE_LINES_FALLBACK
        )
    # Frozen .exe: the ~94M combined ships INSIDE the binary and extracts to
    # <_MEIPASS>/wordlists/, which is NOT the user data dir the caller passes.
    # An operator-installed combined in wordlists_dir (checked above) wins so an
    # override still works; otherwise reach the bundled copy. No-op off a frozen
    # bundle (helper returns None), so Linux/dev behaviour is byte-identical.
    bundled_combined = _bundled_wordlist_path(
        _DEFAULT_AUDIT_BASE_FILENAME, decompress_dir=wordlists_dir
    )
    if bundled_combined:
        return bundled_combined, _estimate_line_count(
            bundled_combined, _COMBINED_AUDIT_BASE_LINES_FALLBACK
        )
    fallback = os.path.join(wordlists_dir, _AUDIT_BASE_FALLBACK_FILENAME)
    if os.path.isfile(fallback):
        return fallback, _estimate_line_count(
            fallback, _AUDIT_BASE_FALLBACK_LINES_FALLBACK
        )
    # Last resort: any wordlist that actually EXISTS on disk beats returning a
    # path to a missing file (the cracker would then run against nothing and
    # recover zero — a silent false negative). Both audit bases above are
    # Linux build-time artifacts (a ~94M merge baked into the Docker image);
    # the Windows bundle ships only rockyou.txt, so on Windows both are absent
    # and this fallthrough is what makes cracking actually work there. rockyou
    # is the universally-present base (ctf default, and downloaded at build on
    # every deployment). Only if even rockyou is missing do we return the
    # (missing) fallback path, and the caller's coverage data-gap declares it.
    rockyou = os.path.join(wordlists_dir, _DEFAULT_CTF_BASE_FILENAME)
    if os.path.isfile(rockyou):
        return rockyou, _estimate_line_count(rockyou, _ROCKYOU_LINES_FALLBACK)
    # Frozen .exe: rockyou may only exist inside the bundle. No-op off frozen.
    bundled_rockyou = _bundled_wordlist_path(
        _DEFAULT_CTF_BASE_FILENAME, decompress_dir=wordlists_dir
    )
    if bundled_rockyou:
        return bundled_rockyou, _estimate_line_count(
            bundled_rockyou, _ROCKYOU_LINES_FALLBACK
        )
    return fallback, _estimate_line_count(fallback, _AUDIT_BASE_FALLBACK_LINES_FALLBACK)


def _device_class_for(benchmark: dict, mode: str) -> str:
    rates = benchmark.get(mode) or {}
    if rates.get("gpu"):
        return "gpu"
    if rates.get("cpu"):
        return "cpu"
    return "unknown"


def _resolve_cap_mode(benchmark: dict, cap_reference_mode: Optional[str]) -> str:
    """The mode a tier's rule rung is capped against, for this benchmark.

    ``cap_reference_mode`` is the mode the LANE will actually crack, when the
    caller knows it. It is honoured only when this benchmark genuinely measured
    it; a record that never measured it (an older cache, or a sweep paused
    before reaching that pair) falls back to :data:`_CAP_REFERENCE_MODE`, which
    is the slowest measured mode and therefore the pessimistic answer. So a
    missing measurement degrades to the previous, over-cautious behaviour rather
    than to no cap at all.
    """
    requested = str(cap_reference_mode or "").strip()
    if requested and (benchmark.get(requested) or {}):
        return requested
    return _CAP_REFERENCE_MODE


# --- keyspace, salt multiplier, and per-rung achieved rates ----------------
#
# Two corrections live here, and both moved the estimate by more than an order
# of magnitude on measured hardware.
#
# SALT. For a salted mode hashcat tries every candidate against every distinct
# hash loaded, so the keyspace is ``base_lines x rules x hash_count``, not
# ``base_lines x rules``. Measured on mode 13100 against the 94M base with the
# 10k rule file: one hash gives a keyspace of 940,038,390,000 and 25 hashes
# gives 23,500,959,750,000, exactly 25x, at the same ~155 MH/s. So a Kerberoast
# of fifty accounts costs fifty times what one costs and used to be quoted as
# though it were one. Four of the five modes ADscan benchmarks are salted; NT
# is the one that is not, which is why the NT lane's "thousands of accounts
# cost very nearly what one costs" is true THERE and false everywhere else.
#
# RATE PER WORKLOAD. The achieved rate is a property of the (mode, rule rung,
# hash count) triple, because the GPU amortizes the host's word-feed cost over
# the candidates it derives from each word: mode 1000 measured 0.017 GH/s
# ruleless, 0.52 GH/s at 77 rules and 2.12 GH/s at 10,000, and mode 13100 at 77
# rules measured 54 MH/s against one salt and 143 MH/s against twenty-five. So
# each candidate rung has to be evaluated at ITS OWN rate, never at one rate for
# the mode, or the ladder walk compares rungs against a number that only
# describes one of them.


def keyspace_for(
    base_lines: int, rule_lines: int, *, mode: str, hash_count: Optional[int]
) -> int:
    """The candidate keyspace hashcat will walk, in the units it counts in.

    ``hash_count`` multiplies only for a salted mode. ``None`` is treated as one
    hash, which is the smallest honest assumption; the caller is responsible for
    flagging such an estimate provisional for a salted mode, because a count it
    does not know could be any size.
    """
    lines = max(1, int(base_lines or 1))
    rules = max(1, int(rule_lines or 1))
    multiplier = 1
    if mode_is_salted(mode):
        try:
            multiplier = max(1, int(hash_count or 1))
        except (TypeError, ValueError):
            multiplier = 1
    return lines * rules * multiplier


def resolve_rung_rate(
    *,
    mode: str,
    rung: int,
    base_path: str,
    device_class: str,
    hash_count: Optional[int] = None,
    achieved: Optional[dict] = None,
    rate_provider: AchievedRateProvider = None,
    benchmark: Optional[dict] = None,
) -> "tuple[Optional[float], bool]":
    """``(rate, measured)`` for one (mode, rung) pair on this hardware.

    Preference order, and the reason for it:

    1. A live probe through ``rate_provider`` when one was injected. This is a
       short real attack in the production configuration, so it is the only
       number that describes what the crack will actually do. Measured.
    2. A persisted probe for the same workload. Same measurement, read off the
       cache. Measured.
    3. The ``hashcat -b`` rate for the mode. PROVISIONAL, and flagged as such:
       it benchmarks the optimized kernels against a synthetic mask and
       overstated the achieved rate by 1.7x to 15.5x across the five measured
       modes. It is kept because an honest ballpark beats no estimate on a host
       where no probe can run, but it must never be presented as measured.

    Returns ``(None, False)`` when nothing is available, which the caller turns
    into a provisional calibration estimate or an explicit "cannot estimate".
    """
    rule_name, _rule_lines = _RULE_LADDER[rung]
    rule_path = _resolve_rule_asset_path(rule_name) if rule_name else None
    # A rung whose rule FILE is not installed cannot be probed and has no cache
    # key, but it is still a rung the ladder walk has to price, so it drops
    # straight to the provisional benchmark rate. Returning nothing here would
    # stop the walk on that rung and keep a tier the budget cannot afford.
    measurable = bool(rule_path) or not rule_name

    if measurable and callable(rate_provider):
        try:
            rate = rate_provider(
                mode=str(mode),
                wordlist=base_path,
                rule_path=rule_path,
                device_class=device_class,
                hash_count=hash_count,
            )
        except Exception:  # noqa: BLE001 -- planning must never break on a probe
            rate = None
        if rate:
            return float(rate), True

    if measurable and achieved:
        key = achieved_rate_key(base_path, rule_path, hash_count)
        cached = ((achieved.get(str(mode)) or {}).get(key) or {}).get(device_class)
        if cached:
            return float(cached), True

    if benchmark:
        fallback = (benchmark.get(str(mode)) or {}).get(device_class)
        if fallback:
            return float(fallback), False
    return None, False


def _pick_capped_rule_index(
    nominal_index: int,
    base_lines: int,
    budget_seconds: float,
    *,
    rate_at: "Any",
    mode: str,
    hash_count: Optional[int],
) -> int:
    """Walk the rule ladder backward from ``nominal_index`` until the estimated
    time fits ``budget_seconds``, evaluating each rung at ITS OWN rate.

    ``rate_at(rung)`` answers the achieved H/s for that rung, or ``None`` when
    unknown. A rung whose rate is unknown is accepted as-is rather than
    downgraded past, because downgrading on absent information would quietly
    shrink coverage. Never returns below 0: a bare wordlist is always the floor.
    """
    index = nominal_index
    while index > 0:
        rate = rate_at(index)
        if not rate:
            break
        _, rule_lines = _RULE_LADDER[index]
        keyspace = keyspace_for(
            base_lines, rule_lines, mode=mode, hash_count=hash_count
        )
        if keyspace / rate <= budget_seconds:
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
    cap_reference_mode: Optional[str] = None,
    hash_count: Optional[int] = None,
    achieved: Optional[dict] = None,
    rate_provider: AchievedRateProvider = None,
) -> EffortTier:
    base_path, base_lines = base_for(
        workspace_type, wordlists_dir, override=base_override
    )
    nominal_index = _EFFORT_RULE_INDEX[level]

    if not benchmark:
        rule_name, _ = _RULE_LADDER[0]
        return EffortTier(
            name=level,
            base_path=base_path,
            rule_path=_resolve_rule_asset_path(rule_name) if rule_name else None,
            device_class="unknown",
            estimated_seconds_per_mode={},
            rule_rung=0,
        )

    cap_mode = _resolve_cap_mode(benchmark, cap_reference_mode)
    device_class = _device_class_for(benchmark, cap_mode)
    budget = _TIER_BUDGET_SECONDS[level]

    def _rate_at(rung: int) -> Optional[float]:
        rate, _measured = resolve_rung_rate(
            mode=cap_mode,
            rung=rung,
            base_path=base_path,
            device_class=device_class,
            hash_count=hash_count,
            achieved=achieved,
            rate_provider=rate_provider,
            benchmark=benchmark,
        )
        return rate

    capped_index = _pick_capped_rule_index(
        nominal_index,
        base_lines,
        budget,
        rate_at=_rate_at,
        mode=cap_mode,
        hash_count=hash_count,
    )
    rule_name, rule_lines = _RULE_LADDER[capped_index]

    estimated: "dict[str, float]" = {}
    for mode in BENCHMARK_MODES:
        rate, _measured = resolve_rung_rate(
            mode=mode,
            rung=capped_index,
            base_path=base_path,
            device_class=device_class,
            hash_count=hash_count,
            achieved=achieved,
            # Only the rung the tier RESOLVED to is probed, and only for the
            # mode the lane will crack. Probing the other four modes here would
            # cost four short real attacks per tier for numbers nothing in this
            # ladder consumes; they read the cache or fall back.
            rate_provider=rate_provider if mode == cap_mode else None,
            benchmark=benchmark,
        )
        if rate:
            estimated[mode] = (
                keyspace_for(base_lines, rule_lines, mode=mode, hash_count=hash_count)
                / rate
            )

    return EffortTier(
        name=level,
        base_path=base_path,
        rule_path=_resolve_rule_asset_path(rule_name) if rule_name else None,
        device_class=device_class,
        estimated_seconds_per_mode=estimated,
        rule_rung=capped_index,
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


def _build_custom_tier(
    domain: str,
    benchmark: Optional[dict],
    *,
    cap_reference_mode: Optional[str] = None,
    hash_count: Optional[int] = None,
    achieved: Optional[dict] = None,
) -> Optional[EffortTier]:
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
        device_class = _device_class_for(
            benchmark, _resolve_cap_mode(benchmark, cap_reference_mode)
        )
        base_lines = _estimate_line_count(base_path, _CUSTOM_BASE_LINES_FALLBACK)
        for mode in BENCHMARK_MODES:
            # No probe here: the custom tier is deliberately never rule-capped
            # and runs unconditionally, so a measurement could not change what
            # it does. A cached one sharpens the number it reports; absent that,
            # the benchmark rate is the ballpark.
            rate, _measured = resolve_rung_rate(
                mode=mode,
                rung=len(_RULE_LADDER) - 1,
                base_path=base_path,
                device_class=device_class,
                hash_count=hash_count,
                achieved=achieved,
                benchmark=benchmark,
            )
            if rate:
                estimated[mode] = (
                    keyspace_for(
                        base_lines, rule_lines, mode=mode, hash_count=hash_count
                    )
                    / rate
                )

    return EffortTier(
        name=_CUSTOM_TIER_NAME,
        base_path=base_path,
        rule_path=_resolve_rule_asset_path(rule_name),
        device_class=device_class,
        estimated_seconds_per_mode=estimated,
        rule_rung=len(_RULE_LADDER) - 1,
    )


def resolve_effort(
    effort: str,
    *,
    workspace_type: str,
    domain: str,
    wordlists_dir: str,
    benchmark: Optional[dict],
    base_override: Optional[str] = None,
    cap_reference_mode: Optional[str] = None,
    hash_count: Optional[int] = None,
    achieved: Optional[dict] = None,
    rate_provider: AchievedRateProvider = None,
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

    ``cap_reference_mode`` is the hash mode this lane will actually crack. Given,
    the rule rung is capped against THAT mode's measured rate, so a lane on a
    fast kernel is planned at the speed it will run. Omitted, the cap falls back
    to the slowest measured mode (:data:`_CAP_REFERENCE_MODE`), which is the only
    safe answer when the lane is unknown and is what every caller that does not
    pass it keeps getting.

    ``hash_count`` is how many distinct hashes the lane will load. For a SALTED
    mode it multiplies the keyspace, so omitting it quotes a fifty-account
    Kerberoast as though it were one account. ``achieved`` is a persisted
    achieved-rate cache and ``rate_provider`` is the live probe seam; together
    they are what makes the planned rung and the quoted time describe the rate a
    crack actually runs at rather than the ``hashcat -b`` number.
    """
    normalized = str(effort or "").strip().lower()
    if normalized not in EFFORT_LEVELS:
        normalized = _DEFAULT_EFFORT

    tiers: "List[EffortTier]" = []
    custom_tier = _build_custom_tier(
        domain,
        benchmark,
        cap_reference_mode=cap_reference_mode,
        hash_count=hash_count,
        achieved=achieved,
    )
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
                cap_reference_mode=cap_reference_mode,
                hash_count=hash_count,
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
            cap_reference_mode=cap_reference_mode,
            hash_count=hash_count,
            achieved=achieved,
            rate_provider=rate_provider,
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
        "balanced" if str(workspace_type or "").strip().lower() == "audit" else "fast"
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
# When nothing has been measured for this workload (a cold box, a host with no
# hashcat) the rate falls back to the hardware benchmark and then to a
# design-calibration rate table (an RTX 4060 GPU reference plus the CPU numbers
# from the same run), and the estimate is flagged ``provisional`` so the UI can
# render "(provisional)". Neither fallback is a measurement of the achieved
# rate and neither may be presented as one.

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
# v2 adds ``hash_count``: for a salted mode the cost scales with the number of
# hashes loaded, so an estimate is only interpretable alongside the count it
# assumed.
_ESTIMATES_SCHEMA_VERSION = 2


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
        _UNMEASURED_MODE_RATE_SOURCE
    )
    return (rates or {}).get("gpu")


def estimate_effort(
    effort: str,
    mode: str,
    *,
    benchmark: Optional[dict],
    base_lines: Optional[int] = None,
    base_path: Optional[str] = None,
    hash_count: Optional[int] = None,
    achieved: Optional[dict] = None,
    rate_provider: AchievedRateProvider = None,
) -> EffortEstimate:
    """Estimate the wall-clock for one effort tier cracking ``mode`` on THIS box.

    Pure logic. Reuses the same keyspace math and the same rule-cap walk that
    :func:`resolve_effort` uses, so the estimate matches what the crack job
    actually runs.

    Args:
        effort: ``fast`` / ``balanced`` / ``thorough``.
        mode: The hashcat mode this lane will crack.
        benchmark: The ``hashcat -b`` ``{mode: {gpu|cpu: H/s}}`` map. Used only
            as the PROVISIONAL fallback rate, because it benchmarks the
            optimized kernels against a synthetic mask and overstated the
            achieved rate by 1.7x to 15.5x across the five measured modes.
        base_lines: The base wordlist's line count, from ``base_for()``.
        base_path: The base wordlist's path, which is half of the workload key
            an achieved-rate measurement is stored under. Defaults to the audit
            base's own filename so a caller that passes only ``base_lines``
            still resolves the common case.
        hash_count: How many distinct hashes the lane will load. For a SALTED
            mode this MULTIPLIES the keyspace. Omitting it for a salted mode
            makes the estimate PROVISIONAL rather than silently quoting one
            hash, because a count we do not know could be fifty.
        achieved: A persisted achieved-rate cache
            (``cracking_benchmark.load_cached_achieved_rates()``).
        rate_provider: The live probe seam
            (``cracking_benchmark.make_achieved_rate_provider(shell)``).
            Injected, never imported, so this stays pure logic.

    Returns:
        An :class:`EffortEstimate`. ``provisional`` is set whenever the rate was
        not measured on this workload or the salt multiplier is unknown, which
        is what lets the UI mark the number as provisional instead of
        asserting it.
    """
    normalized = str(effort or "").strip().lower()
    if normalized not in EFFORT_LEVELS:
        normalized = _DEFAULT_EFFORT
    lines = (
        int(base_lines)
        if base_lines and base_lines > 0
        else _COMBINED_AUDIT_BASE_LINES_FALLBACK
    )
    resolved_base = str(base_path or _DEFAULT_AUDIT_BASE_FILENAME)
    nominal_index = _EFFORT_RULE_INDEX[normalized]
    budget = _TIER_BUDGET_SECONDS[normalized]

    device_class = _device_class_for(benchmark or {}, str(mode))
    if device_class == "unknown":
        device_class = _device_class_for(benchmark or {}, _CAP_REFERENCE_MODE)
    if device_class == "unknown":
        device_class = "gpu"

    # A salted mode's cost scales with the number of hashes. Assuming one would
    # understate a real roast by exactly the number of accounts, so the
    # assumption is made but never presented as measured.
    hash_count_unknown = hash_count is None and mode_is_salted(mode)

    # Measured-ness is tracked PER RUNG and read off the rung the tier actually
    # resolves to. The ladder walk consults lower rungs on its way down, and a
    # fallback rate on a rung that was considered and rejected says nothing
    # about the number finally quoted.
    rate_cache: "dict[int, tuple[Optional[float], bool]]" = {}

    def _rate_entry(rung: int) -> "tuple[Optional[float], bool]":
        if rung in rate_cache:
            return rate_cache[rung]
        rate, measured = resolve_rung_rate(
            mode=str(mode),
            rung=rung,
            base_path=resolved_base,
            device_class=device_class,
            hash_count=hash_count,
            achieved=achieved,
            rate_provider=rate_provider,
            benchmark=benchmark,
        )
        if rate is None:
            # Modes ADscan does not separately benchmark (AES roast, timeroast)
            # borrow the slowest measured mode's rate so their estimate is
            # pessimistic rather than absent.
            rate, measured = resolve_rung_rate(
                mode=_UNMEASURED_MODE_RATE_SOURCE,
                rung=rung,
                base_path=resolved_base,
                device_class=device_class,
                hash_count=hash_count,
                achieved=achieved,
                benchmark=benchmark,
            )
        if rate is None:
            rate = _calibration_rate(mode)
            measured = False
        rate_cache[rung] = (rate, bool(measured))
        return rate_cache[rung]

    def _rate_at(rung: int) -> Optional[float]:
        return _rate_entry(rung)[0]

    if _rate_at(nominal_index) is None:
        # No measurement, no benchmark AND no calibration -- cannot estimate.
        return EffortEstimate(
            effort=normalized,
            mode=str(mode),
            seconds=0.0,
            human="≈ ?",
            is_blocking=nominal_index == 0,
            provisional=True,
        )

    capped_index = _pick_capped_rule_index(
        nominal_index,
        lines,
        budget,
        rate_at=_rate_at,
        mode=str(mode),
        hash_count=hash_count,
    )
    _rule_name, rule_lines = _RULE_LADDER[capped_index]
    rate, measured = _rate_entry(capped_index)
    if rate is None:
        rate, measured = _rate_entry(nominal_index)
    seconds = (
        keyspace_for(lines, rule_lines, mode=str(mode), hash_count=hash_count) / rate
    )
    return EffortEstimate(
        effort=normalized,
        mode=str(mode),
        seconds=seconds,
        human=human_duration(seconds),
        is_blocking=seconds <= _BLOCKING_THRESHOLD_SECONDS,
        provisional=(not measured) or hash_count_unknown,
    )


def resolve_single_tier(
    effort: str,
    *,
    workspace_type: str,
    wordlists_dir: str,
    benchmark: Optional[dict],
    base_override: Optional[str] = None,
    cap_reference_mode: Optional[str] = None,
    hash_count: Optional[int] = None,
    achieved: Optional[dict] = None,
    rate_provider: AchievedRateProvider = None,
) -> EffortTier:
    """The single benchmark-capped :class:`EffortTier` for one effort level.

    The interactive selector's inline / escape resolution: one tier (base
    wordlist x capped rules) rather than the escalating ladder
    :func:`resolve_effort` returns. Reuses the same ``_build_tier`` so capping
    and asset resolution stay identical, including ``cap_reference_mode`` (the
    mode this lane will actually crack, when the caller knows it).
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
        cap_reference_mode=cap_reference_mode,
        hash_count=hash_count,
        achieved=achieved,
        rate_provider=rate_provider,
    )


def build_estimates_payload(
    benchmark: Optional[dict],
    *,
    wordlists_dir: str,
    hardware_label: str,
    achieved: Optional[dict] = None,
    hash_count: Optional[int] = None,
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
            est = estimate_effort(
                level,
                mode,
                benchmark=benchmark,
                base_lines=base_lines,
                base_path=base_path,
                hash_count=hash_count,
                achieved=achieved,
            )
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
        # What the estimates assume about how many hashes the lane loads. It
        # matters to a consumer because for a SALTED mode the cost scales with
        # it, so an estimate for one hash and an estimate for fifty are
        # different numbers for the same tier. ``null`` means unknown, which is
        # also why those tiers come back ``provisional``.
        "hash_count": int(hash_count) if hash_count else None,
        "modes": modes,
    }
