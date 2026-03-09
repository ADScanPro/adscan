"""Centralized Questionary prompt helpers for consistent ADscan UX."""

from __future__ import annotations

from collections.abc import Sequence

from adscan_core.rich_output import (
    questionary_checkbox_values,
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
    default_values: Sequence[str] | None = None,
) -> list[str] | None:
    """Render a Questionary checkbox prompt and return selected values."""
    return questionary_checkbox_values(
        title=title,
        options=list(options),
        default_values=list(default_values) if default_values is not None else None,
    )
