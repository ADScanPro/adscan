"""Centralized Questionary prompt helpers for consistent ADscan UX.

This module centralizes prompt-toolkit/Questionary visual style and invocation
for select + checkbox menus used across CLI controllers.
"""

from __future__ import annotations

from collections.abc import Sequence

import questionary


_ADSCAN_QUESTIONARY_STYLE = questionary.Style(
    [
        ("qmark", "fg:#00D4FF bold"),
        ("question", "bold white"),
        ("answer", "fg:#00D4FF bold"),
        ("pointer", "fg:#00D4FF bold"),
        ("highlighted", "fg:#00D4FF bold"),
        ("selected", "fg:#00D4FF bold"),
        ("separator", "fg:#00D4FF"),
        ("instruction", "fg:#cccccc"),
        ("text", "white"),
        ("choice", "white"),
        ("disabled", "fg:#888888 italic"),
    ]
)


def prompt_questionary_select(
    *,
    title: str,
    options: Sequence[str],
) -> str | None:
    """Render a Questionary single-select prompt and return selected value."""
    if not options:
        return None
    try:
        return questionary.select(
            title,
            choices=list(options),
            style=_ADSCAN_QUESTIONARY_STYLE,
        ).ask()
    except (EOFError, KeyboardInterrupt):
        # Non-interactive stdin or interrupted prompt: behave like cancel.
        return None


def prompt_questionary_checkbox(
    *,
    title: str,
    options: Sequence[str],
) -> list[str] | None:
    """Render a Questionary checkbox prompt and return selected values."""
    if not options:
        return None
    try:
        selected_values = questionary.checkbox(
            title,
            choices=list(options),
            style=_ADSCAN_QUESTIONARY_STYLE,
        ).ask()
    except (EOFError, KeyboardInterrupt):
        # Non-interactive stdin or interrupted prompt: behave like cancel.
        return None
    if selected_values is None:
        return None
    return [str(value) for value in selected_values if str(value).strip()]
