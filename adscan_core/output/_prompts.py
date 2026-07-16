"""Confirm/prompt/questionary input helpers."""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from rich.console import Group
from rich.table import Table
from rich.text import Text

import adscan_core.output._state as _state
from adscan_core.output._log import (
    BRAND_COLORS,
    print_info,
    print_info_debug,
    print_telemetry_only,
    print_warning,
)
from adscan_core.output._panels import print_panel

__all__ = [
    "confirm_ask",
    "prompt_ask",
    "confirm_operation",
    "questionary_select_value",
    "questionary_checkbox_values",
    "questionary_checkbox_values_raw",
    "questionary_select_index",
    "questionary_ordered_selection",
    "install_prompt_logging_wrappers",
]

# Prompt wrapper state
_ORIGINAL_PROMPT_ASK: Optional[Callable[..., Any]] = None
_ORIGINAL_CONFIRM_ASK: Optional[Callable[..., Any]] = None
_ORIGINAL_INT_PROMPT_ASK: Optional[Callable[..., Any]] = None
_ORIGINAL_FLOAT_PROMPT_ASK: Optional[Callable[..., Any]] = None
_PROMPT_LOGGING_WRAPPERS_INSTALLED = False


def _classify_prompt_answer(
    answer_text: str,
    *,
    password_mode: bool,
    prompt_message: str = "",
) -> str:
    """Best-effort classification for prompt answer sanitization."""
    from adscan_core import prompting

    return prompting.classify_prompt_answer(
        answer_text,
        password_mode=password_mode,
        prompt_message=prompt_message,
    )


def _logged_prompt_ask(*prompt_args: Any, **kwargs: Any) -> str:
    """Prompt.ask wrapper with centralized telemetry/debug answer logging."""
    from adscan_core import prompting

    return prompting.logged_prompt_ask(
        *prompt_args,
        original_prompt_ask=_ORIGINAL_PROMPT_ASK,
        telemetry=print_telemetry_only,
        debug=print_info_debug,
        info=print_info,
        **kwargs,
    )


def _logged_confirm_ask(*confirm_args: Any, **kwargs: Any) -> bool:
    """Confirm.ask wrapper with centralized telemetry/debug answer logging."""
    from adscan_core import prompting

    return prompting.logged_confirm_ask(
        *confirm_args,
        original_confirm_ask=_ORIGINAL_CONFIRM_ASK,
        telemetry=print_telemetry_only,
        debug=print_info_debug,
        info=print_info,
        **kwargs,
    )


def _logged_int_prompt_ask(*prompt_args: Any, **kwargs: Any) -> Any:
    """IntPrompt.ask wrapper with centralized telemetry/debug answer logging."""
    from adscan_core import prompting

    return prompting.logged_int_prompt_ask(
        *prompt_args,
        original_int_prompt_ask=_ORIGINAL_INT_PROMPT_ASK,
        telemetry=print_telemetry_only,
        debug=print_info_debug,
        info=print_info,
        **kwargs,
    )


def _logged_float_prompt_ask(*prompt_args: Any, **kwargs: Any) -> Any:
    """FloatPrompt.ask wrapper with centralized telemetry/debug answer logging."""
    from adscan_core import prompting

    return prompting.logged_float_prompt_ask(
        *prompt_args,
        original_float_prompt_ask=_ORIGINAL_FLOAT_PROMPT_ASK,
        telemetry=print_telemetry_only,
        debug=print_info_debug,
        info=print_info,
        **kwargs,
    )


def install_prompt_logging_wrappers() -> None:
    """Install Prompt/Confirm wrappers to centrally log questions and answers."""
    global _ORIGINAL_PROMPT_ASK, _ORIGINAL_CONFIRM_ASK
    global _ORIGINAL_INT_PROMPT_ASK, _ORIGINAL_FLOAT_PROMPT_ASK
    global _PROMPT_LOGGING_WRAPPERS_INSTALLED

    if _PROMPT_LOGGING_WRAPPERS_INSTALLED:
        return

    from rich.prompt import Confirm, FloatPrompt, IntPrompt, Prompt

    _ORIGINAL_PROMPT_ASK = Prompt.ask
    _ORIGINAL_CONFIRM_ASK = Confirm.ask
    _ORIGINAL_INT_PROMPT_ASK = IntPrompt.ask
    _ORIGINAL_FLOAT_PROMPT_ASK = FloatPrompt.ask
    Prompt.ask = _logged_prompt_ask  # type: ignore[assignment]
    Confirm.ask = _logged_confirm_ask  # type: ignore[assignment]
    IntPrompt.ask = _logged_int_prompt_ask  # type: ignore[assignment]
    FloatPrompt.ask = _logged_float_prompt_ask  # type: ignore[assignment]
    _PROMPT_LOGGING_WRAPPERS_INSTALLED = True


def confirm_ask(prompt: str, default: bool) -> bool:
    """Ask a yes/no confirmation prompt with centralized prompt logging."""
    try:
        install_prompt_logging_wrappers()
        from rich.prompt import Confirm

        return bool(Confirm.ask(prompt, default=default))
    except Exception as exc:
        print_info_debug(
            f"[confirm] Fallback to default for '{prompt}': {default} ({type(exc).__name__})"
        )
        answer_text = "Yes" if bool(default) else "No"
        print_telemetry_only(f"[confirm][answer] {prompt}: {answer_text}")
        return default


def prompt_ask(
    prompt: str,
    default: str | None = None,
    *,
    password: bool = False,
    shell: object | None = None,
    **kwargs: Any,
) -> str:
    """Ask a text prompt with centralized prompt logging and safe fallback.

    In non-interactive mode the prompt auto-resolves to ``default`` (or an
    empty string when no default is provided) instead of blocking on stdin,
    mirroring the questionary helpers. Pass ``shell`` so the non-interactive
    predicate can see ``shell.auto`` / the session command type.
    """
    if _state._should_disable_prompt_interaction(shell):
        resolved = "" if default is None else str(default)
        answer_tag = "[prompt][password][answer]" if password else "[prompt][answer]"
        data_type = _classify_prompt_answer(
            resolved, password_mode=password, prompt_message=prompt
        )
        print_info_debug(
            f"[prompt] Non-interactive; auto-resolving '{prompt}' to default"
        )
        print_telemetry_only(
            f"{answer_tag} {prompt}: {_state.mark_sensitive(resolved, data_type)}"
        )
        return resolved
    try:
        install_prompt_logging_wrappers()
        from rich.prompt import Prompt

        answer = Prompt.ask(prompt, default=default, password=password, **kwargs)
        return "" if answer is None else str(answer)
    except Exception as exc:
        fallback = "" if default is None else str(default)
        print_info_debug(
            f"[prompt] Fallback to default for '{prompt}': "
            f"{_state.mark_sensitive(fallback, _classify_prompt_answer(fallback, password_mode=password, prompt_message=prompt))} "
            f"({type(exc).__name__})"
        )
        answer_tag = "[prompt][password][answer]" if password else "[prompt][answer]"
        data_type = _classify_prompt_answer(
            fallback,
            password_mode=password,
            prompt_message=prompt,
        )
        print_telemetry_only(
            f"{answer_tag} {prompt}: {_state.mark_sensitive(fallback, data_type)}"
        )
        return fallback


def questionary_select_value(
    *,
    title: str,
    options: list[str],
) -> str | None:
    """Render a Questionary single-select prompt and return selected value."""
    from adscan_core import prompting

    return prompting.questionary_select_value(title=title, options=options)


def questionary_checkbox_values(
    *,
    title: str,
    options: list[str],
    default_values: list[str] | None = None,
    shell: object | None = None,
) -> list[str] | None:
    """Render a Questionary checkbox prompt and return selected values."""
    if not options:
        return None
    resolved_defaults = (
        [str(value) for value in default_values if str(value).strip()]
        if default_values is not None
        else [str(option) for option in options if str(option).strip()]
    )
    if _state._should_disable_prompt_interaction(shell):
        print_info_debug(
            "[questionary] Non-interactive; selecting default checkbox values "
            f"for '{title}': {resolved_defaults}"
        )
        print_telemetry_only(
            f"[questionary][answer] {title}: "
            f"{_state.mark_sensitive(str(resolved_defaults), 'text')}"
        )
        return resolved_defaults

    print_info_debug(f"[questionary] Prompt: {title}")
    print_telemetry_only(f"[questionary] Prompt: {title}")
    try:
        selected_values = questionary_checkbox_values_raw(
            title=title,
            options=options,
            default_values=resolved_defaults,
        )
    except KeyboardInterrupt:
        _state._emit_prompt_interrupt_debug(
            kind="keyboard_interrupt", source="questionary.checkbox"
        )
        return None
    except Exception as exc:
        print_info_debug(
            f"[DEBUG] questionary.checkbox failed: {type(exc).__name__}: {exc}"
        )
        return None
    if selected_values is None:
        return None
    print_info_debug(f"[questionary] Selected: {selected_values}")
    print_telemetry_only(
        f"[questionary][answer] {title}: {_state.mark_sensitive(str(selected_values), 'text')}"
    )
    return selected_values


def questionary_checkbox_values_raw(
    *,
    title: str,
    options: list[str],
    default_values: list[str] | None = None,
) -> list[str] | None:
    """Render Questionary checkbox without extra logging logic."""
    from adscan_core import prompting

    return prompting.questionary_checkbox_values_raw(
        title=title,
        options=options,
        default_values=default_values,
    )


def _questionary_style(questionary_module: Any) -> Any:
    """Return shared Questionary style used across prompts."""
    from adscan_core import prompting

    return prompting.questionary_style(questionary_module)


def questionary_select_index(
    *,
    title: str,
    options: list[str],
    default_idx: int = 0,
    shell: object | None = None,
) -> int | None:
    """Select option index via Questionary with centralized fallback/logging."""
    if not options:
        return None

    resolved_default_idx = default_idx
    if resolved_default_idx < 0 or resolved_default_idx >= len(options):
        resolved_default_idx = 0

    if _state._should_disable_prompt_interaction(shell):
        print_info_debug(
            "[questionary] Non-interactive; selecting default "
            f"idx={resolved_default_idx}: {options[resolved_default_idx]}"
        )
        print_telemetry_only(
            f"[questionary][answer] {title}: "
            f"{_state.mark_sensitive(str(options[resolved_default_idx]), 'text')}"
        )
        return resolved_default_idx

    print_info_debug(f"[questionary] Prompt: {title}")
    print_telemetry_only(f"[questionary] Prompt: {title}")
    try:
        selected_value = questionary_select_value(title=title, options=options)
    except KeyboardInterrupt:
        _state._emit_prompt_interrupt_debug(
            kind="keyboard_interrupt", source="questionary.select"
        )
        return None
    except Exception as exc:
        print_info_debug(
            f"[DEBUG] questionary.select failed: {type(exc).__name__}: {exc}, "
            "falling back to numeric selection."
        )
        return _fallback_numeric_select_index(
            title=title, options=options, default_idx=resolved_default_idx
        )
    if selected_value is None:
        print_info_debug(f"[questionary] Cancelled: {title}")
        print_telemetry_only(f"[questionary][answer] {title}: [cancelled]")
        return None

    print_info_debug(f"[questionary] Selected: {selected_value}")
    print_telemetry_only(
        f"[questionary][answer] {title}: {_state.mark_sensitive(str(selected_value), 'text')}"
    )
    try:
        return options.index(selected_value)
    except ValueError:
        return None


def questionary_ordered_selection(
    *,
    title: str,
    options: list[str],
    default_order: list[str],
    shell: object | None = None,
) -> list[str]:
    """Select a subset of ``options`` AND the order to run them in.

    Fills the gap between the unordered checkbox prompt and the single-select:
    the operator picks options one at a time, each pick is appended to the
    result order and removed from the remaining set, and the loop ends when the
    operator picks the ``"Done"`` entry or the remaining set is empty. This is a
    pure selection helper: it returns an ordered list of chosen options and runs
    nothing — the caller executes the actions in the returned order.

    In non-interactive runs (``adscan ci``) the prompt must NEVER block, so it
    auto-resolves to ``default_order`` filtered to ``options`` (i.e. every
    available option in the given order). The resolution is logged via
    ``print_info_debug`` and mirrored to telemetry with ``mark_sensitive``,
    exactly like the other questionary helpers.

    Args:
        title: Prompt title shown above the remaining choices each round.
        options: The available options to choose from.
        default_order: Ordered preference used as the CI auto-resolve answer
            (filtered to ``options``); also the conservative default.
        shell: Optional shell used by the non-interactive predicate.

    Returns:
        The ordered list of chosen options (subset of ``options``). Empty when
        the operator picks ``"Done"`` immediately or cancels.
    """
    if not options:
        return []

    available = [str(option) for option in options if str(option).strip()]
    if not available:
        return []

    # CI auto-resolve: default_order filtered to the available options, in the
    # given order. Never block; log + mirror like the other helpers.
    if _state._should_disable_prompt_interaction(shell):
        available_set = set(available)
        resolved = [str(value) for value in default_order if str(value) in available_set]
        print_info_debug(
            "[questionary] Non-interactive; selecting default ordered selection "
            f"for '{title}': {resolved}"
        )
        print_telemetry_only(
            f"[questionary][answer] {title}: "
            f"{_state.mark_sensitive(str(resolved), 'text')}"
        )
        return resolved

    done_label = "Done"
    remaining = list(available)
    chosen: list[str] = []

    print_info_debug(f"[questionary] Prompt: {title}")
    print_telemetry_only(f"[questionary] Prompt: {title}")

    while remaining:
        menu = list(remaining) + [done_label]
        round_title = title
        if chosen:
            round_title = f"{title} (selected so far: {', '.join(chosen)})"
        selected_idx = questionary_select_index(
            title=round_title,
            options=menu,
            default_idx=0,
            shell=shell,
        )
        # Cancellation (Ctrl-C / EOF / cancel) ends the loop with what we have.
        if selected_idx is None:
            break
        if selected_idx < 0 or selected_idx >= len(menu):
            break
        picked = menu[selected_idx]
        if picked == done_label:
            break
        chosen.append(picked)
        remaining.remove(picked)

    print_info_debug(f"[questionary] Ordered selection: {chosen}")
    print_telemetry_only(
        f"[questionary][answer] {title}: {_state.mark_sensitive(str(chosen), 'text')}"
    )
    return chosen


def _fallback_numeric_select_index(
    *,
    title: str,
    options: list[str],
    default_idx: int,
) -> int | None:
    """Fallback select menu using Rich numbered prompt."""
    if not options:
        return None

    print_info(f"[bold]{title}[/bold]")
    for idx, option in enumerate(options, start=1):
        print_info(f"  {idx}. {option}")

    default_number = (default_idx + 1) if 0 <= default_idx < len(options) else 1
    try:
        from rich.prompt import IntPrompt

        choice_num = IntPrompt.ask(
            "Enter a number (0 to cancel)",
            default=default_number,
        )
    except Exception:
        return None

    if choice_num == 0:
        return None
    if 1 <= choice_num <= len(options):
        return choice_num - 1
    return None


def confirm_operation(
    operation_name: str,
    description: str,
    context: Optional[Dict[str, str]] = None,
    default: bool = True,
    icon: str = "🔍",
    show_panel: bool = True,
) -> bool:
    """Display a professional confirmation prompt for an operation.

    This function provides a rich, informative prompt that helps users understand
    what an operation will do before confirming it. It can display context information
    in a structured format and uses ADscan brand styling.

    Args:
        operation_name: Name of the operation (e.g., "SMB Service Scan")
        description: Brief description of what the operation does
        context: Optional dict of contextual information to display (e.g., {"Domain": "example.local"})
        default: Default answer (True = yes, False = no)
        icon: Emoji icon to display with the operation name
        show_panel: Whether to show a panel with context info (if False, shows compact format)

    Returns:
        bool: True if user confirmed, False otherwise

    Example:
        >>> confirmed = confirm_operation(
        ...     "ADCS Detection",
        ...     "Searches for Active Directory Certificate Services in the domain",
        ...     context={"Domain": "example.local", "PDC": "dc.example.local"},
        ...     icon="🔐"
        ... )
    """
    # Build the prompt message
    if show_panel and context:
        # Create a context table
        context_table = Table.grid(padding=(0, 2))
        context_table.add_column(style="bold cyan", justify="right")
        context_table.add_column(style="white")

        for key, value in context.items():
            context_table.add_row(f"{key}:", value)

        # Create a panel with operation info
        panel_content = Group(
            Text(description, style="white"),
            Text(""),  # Empty line
            context_table,
        )

        print_panel(
            panel_content,
            title=f"{icon} {operation_name}",
            title_align="left",
            border_style=BRAND_COLORS["info"],
            padding=(1, 2),
            spacing="none",
        )
        prompt_text = "Proceed with this operation?"
    else:
        # Compact format without panel
        if context:
            context_str = " ".join([f"{k}: {v}" for k, v in context.items()])
            prompt_text = f"{icon} {operation_name} - {description} ({context_str})"
        else:
            prompt_text = f"{icon} {operation_name} - {description}"

    # Show confirmation prompt
    try:
        return confirm_ask(prompt_text, default=default)
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        print_warning("Operation cancelled")
        return False
