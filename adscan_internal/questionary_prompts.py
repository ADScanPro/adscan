"""Centralized Questionary prompt helpers for consistent ADscan UX."""

from __future__ import annotations

from collections.abc import Sequence

from adscan_core.rich_output import (
    questionary_checkbox_values_raw,
    questionary_select_value,
)


def prompt_questionary_select(
    *,
    title: str,
    options: Sequence[str],
) -> str | None:
    """Render a Questionary single-select prompt and return selected value."""
    return questionary_select_value(title=title, options=list(options))


def prompt_questionary_checkbox(
    *,
    title: str,
    options: Sequence[str],
) -> list[str] | None:
    """Render a Questionary checkbox prompt and return selected values."""
    return questionary_checkbox_values_raw(title=title, options=list(options))
