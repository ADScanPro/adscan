"""REPL surface for the cracking hardware benchmark (``benchmark`` command).

Manual re-run path for the cracking-effort engine's benchmark cache -- see
``services/cracking_benchmark.py`` for the automatic lazy-fallback-on-first-
crack path, which every effort-aware consumer already goes through.
"""

from __future__ import annotations

from typing import Any

from rich.table import Table
from rich.text import Text

from adscan_core import telemetry
from adscan_internal import get_console, print_error, print_info, print_success
from adscan_internal.rich_output import BRAND_COLORS
from adscan_internal.services.cracking_benchmark import (
    BENCHMARK_MODES,
    get_or_run_benchmark,
)

# Human-readable label for each hashcat mode ADscan benchmarks -- keeps the
# table readable without forcing the operator to memorize hashcat mode IDs.
_MODE_LABELS: dict[str, str] = {
    "5600": "NetNTLMv2",
    "5500": "NetNTLMv1",
    "13100": "Kerberoast",
    "18200": "AS-REP Roasting",
}


def _format_rate(value: float | None) -> str:
    """Render a measured H/s rate, or 'n/a' when the device class was not measured."""
    if not value:
        return "n/a"
    return f"{value:,.0f} H/s"


def _format_ratio(gpu: float | None, cpu: float | None) -> str:
    """Render the GPU/CPU speed-up ratio, or 'n/a' when either side is missing."""
    if not gpu or not cpu:
        return "n/a"
    return f"{gpu / cpu:,.1f}x"


def build_benchmark_table(rates: dict[str, dict[str, float]] | None) -> Table:
    """Build the per-mode GPU vs CPU hardware benchmark table.

    Pure function (no I/O, no printing) so it is directly unit-testable: given
    a benchmark rates dict shaped like
    ``services.cracking_benchmark.get_or_run_benchmark``'s return value,
    returns a Rich ``Table`` ready to render via ``get_console().print(table)``.
    A ``None``/empty ``rates`` still returns a table with every cell set to
    'n/a' -- callers decide separately whether to print an error instead of
    the table (see ``handle_benchmark_command``).
    """
    table = Table(
        title=Text("Cracking Hardware Benchmark", style=f"bold {BRAND_COLORS['info']}"),
        show_header=True,
        header_style=f"bold {BRAND_COLORS['info']}",
        show_lines=False,
    )
    table.add_column("Mode", style="bold")
    table.add_column("GPU H/s", justify="right")
    table.add_column("CPU H/s", justify="right")
    table.add_column("GPU/CPU ratio", justify="right", style="dim")

    rates = rates or {}
    for mode in BENCHMARK_MODES:
        row = rates.get(mode) or {}
        gpu = row.get("gpu")
        cpu = row.get("cpu")
        label = _MODE_LABELS.get(mode, mode)
        table.add_row(
            f"{mode} ({label})",
            _format_rate(gpu),
            _format_rate(cpu),
            _format_ratio(gpu, cpu),
        )
    return table


def handle_benchmark_command(shell: Any, args: str) -> None:
    """Usage: benchmark [refresh]

    benchmark          Show the cached benchmark, running it once if none
                        exists yet (or if the cache is stale/fingerprint-
                        mismatched).
    benchmark refresh  Force a fresh measurement even if the cache is warm.
    """
    force = str(args or "").strip().lower() in {"refresh", "force", "-f"}
    print_info(
        "Running the hashcat hardware benchmark (GPU + CPU, one pass per "
        "cracking mode)... this can take up to a couple of minutes."
        if force
        else "Checking the cracking hardware benchmark cache..."
    )

    try:
        rates = get_or_run_benchmark(shell, force=force)
    except Exception as exc:  # noqa: BLE001 -- a REPL command must never crash the shell
        telemetry.capture_exception(exc)
        print_error(f"Benchmark failed: {exc}")
        return

    if not rates or not any(rates.get(mode) for mode in BENCHMARK_MODES):
        print_error(
            "Could not measure or load a hardware benchmark (no hashcat "
            "device rates available -- hashcat may not be installed, or no "
            "GPU/CPU backend responded). Cracking effort tiers will default "
            "to the safe 'fast' tier until this succeeds."
        )
        return

    print_success("Hardware benchmark ready:")
    get_console().print(build_benchmark_table(rates))

    has_gpu = any((rates.get(mode) or {}).get("gpu") for mode in BENCHMARK_MODES)
    if not has_gpu:
        print_info(
            "No GPU backend was detected -- rates above are CPU-only. "
            "Cracking effort tiers auto-downgrade the rule keyspace on "
            "CPU-only hardware to stay within each tier's time budget."
        )
