"""Upfront patience notice for long-running ADscan operations.

Shown BEFORE a long op starts, only above a count threshold (silent below →
clean UX for small runs). Count-scaled buckets set the wording. Env-overridable
per op. Non-interactive → a single ``print_info`` line, never a blocking panel.

Subsumes the former SMB-slowness warning (collector spec Component D.2). The
thresholds ship as provisional defaults calibrated from the per-operation
timing telemetry (collector spec § 8); real large-estate numbers tune them.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Optional

from rich.panel import Panel
from rich.text import Text

from adscan_core.theme import ADSCAN_PRIMARY, COLOR_MUTED

__all__ = [
    "PatienceNoticeConfig",
    "maybe_show_patience_notice",
    "PATIENCE_BUCKETS",
]

# (min_count, expectation_label). Highest bucket whose min_count <= count wins.
PATIENCE_BUCKETS: tuple[tuple[int, str], ...] = (
    (0, "a few seconds"),
    (100, "up to a minute"),
    (500, "a few minutes"),
    (2000, "several minutes — grab a coffee"),
    (10000, "ten minutes or more"),
    (50000, "roughly an hour or more"),
    (150000, "several hours"),
    (500000, "the better part of a day"),
)


@dataclass(frozen=True)
class PatienceNoticeConfig:
    """Static config for one operation's patience notice.

    Attributes:
        operation: Human-readable op name (English only).
        unit: Plural noun for the count ("hosts", "users").
        threshold: Default count below which the notice is silent.
        env_var: Optional env var that overrides ``threshold`` at runtime.
    """

    operation: str
    unit: str = "items"
    threshold: int = 100
    env_var: Optional[str] = None


def _select_bucket(count: int) -> tuple[int, str]:
    """Return the highest :data:`PATIENCE_BUCKETS` entry with ``min_count <= count``."""
    chosen = PATIENCE_BUCKETS[0]
    for bucket in PATIENCE_BUCKETS:
        if count >= bucket[0]:
            chosen = bucket
        else:
            break
    return chosen


def _resolve_threshold(config: PatienceNoticeConfig) -> int:
    if config.env_var:
        raw = os.environ.get(config.env_var)
        if raw:
            try:
                value = int(raw)
                if value > 0:
                    return value
            except ValueError:
                pass
    return config.threshold


def maybe_show_patience_notice(
    config: PatienceNoticeConfig,
    *,
    count: int,
    non_interactive: bool,
    rate_per_second: Optional[float] = None,
    _printer: Optional[Callable[..., None]] = None,
    _panel_printer: Optional[Callable[..., None]] = None,
) -> bool:
    """Show the patience notice when ``count`` is at/above the threshold.

    Args:
        config: The operation's :class:`PatienceNoticeConfig`.
        count: Number of items the op will process.
        non_interactive: When ``True``, emit a single info line, never a panel.
        rate_per_second: Optional known throughput (items/sec). When provided
            and positive, the notice shows a computed ETA (``count /
            rate_per_second``) instead of the generic count-scaled bucket
            label — callers with real calibration data (e.g. kerbrute
            userenum) get an accurate wait estimate rather than a guess.
        _printer: Injected ``print_info``-style fn (tests). Defaults to the
            real ``print_info``.
        _panel_printer: Injected panel printer (tests). Defaults to
            ``get_console().print``.

    Returns:
        ``True`` when a notice was shown, ``False`` when below threshold.
    """
    threshold = _resolve_threshold(config)
    if count < threshold:
        return False

    if rate_per_second and rate_per_second > 0:
        from adscan_core.tui.progress_dashboard import format_eta

        expectation = f"roughly {format_eta(count / rate_per_second)}"
    else:
        _, expectation = _select_bucket(count)
    headline = (
        f"{config.operation}: processing {count} {config.unit}. "
        f"This may take {expectation}. Progress will be shown live — "
        "please do not interrupt."
    )

    if non_interactive:
        printer = _printer or _default_printer()
        printer(headline)
        return True

    panel_printer = _panel_printer or _default_panel_printer()
    body = Text(headline, style=ADSCAN_PRIMARY)
    panel = Panel(
        body,
        title=Text("Heads up", style=f"bold {ADSCAN_PRIMARY}"),
        title_align="left",
        border_style=COLOR_MUTED,
        padding=(0, 1),
    )
    panel_printer(panel)
    return True


def _default_printer() -> Callable[..., None]:
    from adscan_core.rich_output import print_info

    return print_info


def _default_panel_printer() -> Callable[..., None]:
    from adscan_core.output._state import get_console

    return get_console().print
