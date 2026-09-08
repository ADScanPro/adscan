"""John the Ripper rates backend for the cracking-effort engine.

The GPU benchmark SSOT (:mod:`adscan_internal.services.cracking_benchmark`) runs
``hashcat -b`` and caches measured H/s per mode. On a CPU-only host (e.g. a
hardened Windows box with no GPU/OpenCL runtime) hashcat cannot benchmark at all,
so the effort engine has no rates and always falls back to the safe "fast" tier.

John the Ripper cracks on pure CPU and has its own self-test — ``john --test``
prints a candidates-per-second figure per format. This module runs that self-test
for each of the four benchmark modes and produces the SAME shape the effort engine
already consumes from ``benchmark.json`` — ``{mode: {"cpu": rate}}`` keyed to the
canonical hashcat mode strings (``5600``/``5500``/``13100``/``18200``) — so a
CPU-only host gets calibrated effort tiers instead of the flat fast-tier fallback.

It mirrors the GPU benchmark's best-effort, never-raise contract: any subprocess
failure, missing John format, or parse failure for a mode skips that mode (the key
is omitted); a total failure returns ``{}``. Diagnostics go to
``print_warning_debug`` (the debug log always, the console only under ``--debug``)
and NEVER ``print_exception`` — a warm-up probe the operator never asked for must
not surface an error carrying a raw command line. See the noise rationale in
``cracking_benchmark.py``.

Wiring this backend into ``resolve_effort`` / the warm-up is a separate task; this
module is only the runner + its parser.
"""

from __future__ import annotations

import re
from typing import Any, Callable

from adscan_core import telemetry
from adscan_core.rich_output import print_warning_debug
from adscan_internal.services.cracking.hash_kind import (
    john_format_for,
    resolve_kind_for_mode,
)
from adscan_internal.services.john_artifact_cracking_service import (
    JohnArtifactCrackingService,
)

# The four benchmark modes the effort engine expects, identical to
# ``cracking_benchmark.BENCHMARK_MODES``: NetNTLMv2, NetNTLMv1, Kerberoast
# (TGS-REP, RC4), AS-REP Roasting (RC4). Kept as a local literal (not imported)
# so this CPU backend does not couple to the GPU module's import graph.
BENCHMARK_MODES: tuple[str, ...] = ("5600", "5500", "13100", "18200")

# A magnitude suffix John appends to a candidates-per-second figure. John prints
# rates like ``2718K c/s`` or ``2.5M c/s``; map each suffix to its multiplier.
_SUFFIX_MULTIPLIERS: dict[str, float] = {
    "": 1.0,
    "K": 1e3,
    "M": 1e6,
    "G": 1e9,
    "T": 1e12,
}

# Match a ``<number><suffix> c/s`` speed figure anywhere on a line, e.g.
# ``2718K c/s real`` / ``45.6M c/s`` / ``1234 c/s``. The number is float-capable
# and the suffix optional; the first (real) figure on the line is the one used —
# John prints "N c/s real, M c/s virtual" and the real rate is authoritative.
_SPEED_RE = re.compile(r"([0-9]+(?:\.[0-9]+)?)\s*([KMGT]?)\s*c/s", re.IGNORECASE)


def parse_john_candidates_per_second(output: str) -> float | None:
    """Parse the highest candidates/second figure from ``john --test`` output.

    John's self-test emits one or more speed lines, each of the shape
    ``N c/s real, M c/s virtual`` (a ``Raw:`` line for a saltless format, or
    ``Many salts:`` / ``Only one salt:`` lines for a salted one). The **real**
    figure — the FIRST ``c/s`` on the line — is the authoritative throughput;
    ``virtual`` is an idealized upper bound and must not be used. Across lines this
    returns the LARGEST real rate: for a salted format the "many salts" throughput
    is the relevant upper bound for keyspace budgeting.

    Args:
        output: Combined stdout/stderr text from a ``john --test`` run.

    Returns:
        The candidates-per-second as a float (suffix expanded: K=1e3, M=1e6,
        G=1e9), or ``None`` when no ``c/s`` figure is present.
    """
    best: float | None = None
    for line in (output or "").splitlines():
        # Only the FIRST match per line is the real rate; a second figure on the
        # same line is the "virtual" idealized number, which overstates throughput.
        match = _SPEED_RE.search(line)
        if match is None:
            continue
        try:
            value = float(match.group(1))
        except (TypeError, ValueError):
            continue
        multiplier = _SUFFIX_MULTIPLIERS.get(match.group(2).upper(), 1.0)
        rate = value * multiplier
        if rate > 0 and (best is None or rate > best):
            best = rate
    return best


def _run_single_john_test(
    command_executor: Callable[..., Any], john_path: str, john_format: str
) -> float | None:
    """Run ``john --test=0 --format=<fmt>`` and parse its candidates/second.

    Best-effort: a raised executor, a ``None`` result, a non-zero return code, or
    unparseable output all yield ``None`` (the caller then omits the mode). Never
    raises.

    Args:
        command_executor: A ``shell.run_command``-shaped callable that runs a
            command STRING and returns a ``CompletedProcess``-like object (with
            ``returncode``/``stdout``/``stderr``) or ``None``.
        john_path: Resolved John binary path.
        john_format: The John ``--format`` name to self-test (e.g. ``krb5asrep``).

    Returns:
        The measured candidates/second as a float, or ``None`` on any failure.
    """
    # ``--test=0`` runs the quick self-test (a short timed pass) and prints the
    # ``... c/s`` speed lines without the longer full correctness test.
    command = f"{john_path} --test=0 --format={john_format}"
    try:
        completed = command_executor(command, timeout=120)
    except Exception as exc:  # noqa: BLE001 -- optional probe, degrades to "fast"
        telemetry.capture_exception(exc)
        print_warning_debug(
            f"john-benchmark: format {john_format} self-test failed: {exc}"
        )
        return None
    if completed is None:
        return None
    if int(getattr(completed, "returncode", 1)) != 0:
        print_warning_debug(
            f"john-benchmark: format {john_format} self-test returned nonzero rc"
        )
        return None
    combined = (
        f"{getattr(completed, 'stdout', '') or ''}\n"
        f"{getattr(completed, 'stderr', '') or ''}"
    )
    rate = parse_john_candidates_per_second(combined)
    if rate is None:
        print_warning_debug(
            f"john-benchmark: format {john_format} self-test produced no c/s rate"
        )
    return rate


def run_john_benchmark(
    command_executor: Callable[..., Any],
) -> dict[str, dict[str, float]]:
    """Measure John CPU candidates/second for every benchmark mode.

    For each of :data:`BENCHMARK_MODES`, resolves the mode's John ``--format`` and
    runs ``john --test=0`` to measure its throughput, building a map in the SAME
    shape the effort engine consumes from ``benchmark.json`` —
    ``{mode: {"cpu": rate}}`` — so a CPU-only host gets calibrated tiers.

    Best-effort throughout: a mode whose format is missing, whose self-test fails,
    or whose output does not parse is simply omitted; a total failure (no John
    binary, or nothing measured) returns ``{}``. NEVER raises.

    Args:
        command_executor: A ``shell.run_command``-shaped callable that runs a
            command STRING and returns a ``CompletedProcess``-like object or
            ``None``. Injectable so callers (and tests) control the subprocess.

    Returns:
        ``{mode: {"cpu": candidates_per_second}}`` for every mode that measured a
        rate, keyed by the canonical hashcat mode string; ``{}`` when nothing did.
    """
    rates: dict[str, dict[str, float]] = {}
    try:
        john_path = JohnArtifactCrackingService.resolve_john_path()
    except Exception as exc:  # noqa: BLE001 -- resolution is best-effort
        telemetry.capture_exception(exc)
        print_warning_debug(f"john-benchmark: john path resolution failed: {exc}")
        john_path = None
    if not john_path:
        print_warning_debug("john-benchmark: no John binary available, skipping")
        return {}

    for mode in BENCHMARK_MODES:
        kind = resolve_kind_for_mode(mode)
        john_format = john_format_for(kind) if kind is not None else None
        if not john_format:
            print_warning_debug(
                f"john-benchmark: mode {mode} has no John format, skipping"
            )
            continue
        rate = _run_single_john_test(command_executor, john_path, john_format)
        if rate is not None and rate > 0:
            rates[mode] = {"cpu": rate}
    return rates


__all__ = [
    "BENCHMARK_MODES",
    "parse_john_candidates_per_second",
    "run_john_benchmark",
]
