"""Central prompt runtime for ADscan CLI interactions.

This module owns backend selection for operator prompts.  Questionary is treated
as an optional sync-only backend; code running inside an active asyncio event
loop falls back to Rich's original prompt implementation to avoid nested event
loop failures.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
from typing import Any, Callable

from adscan_core.sensitive import mark_sensitive

PromptAsk = Callable[..., Any]
ConfirmAsk = Callable[..., Any]
LogMessage = Callable[[str], None]
InterruptLogger = Callable[[str, str], None]
NonInteractivePredicate = Callable[[object | None], bool]
QuestionaryPredicate = Callable[[], bool]

_PROMPT_AUTO_MODE_ACTIVE = False
_PROMPT_SHOULD_DISABLE_INTERACTIVE: NonInteractivePredicate | None = None
_PROMPT_INTERRUPT_LOGGER: InterruptLogger | None = None
_PROMPT_USE_QUESTIONARY_IN_CONTAINER: QuestionaryPredicate | None = None


def default_should_disable_interactive_prompts(shell: object | None = None) -> bool:
    """Return whether prompts should auto-resolve for this runtime."""
    from adscan_core.interaction import is_non_interactive

    return is_non_interactive(shell=shell)


def default_interrupt_logger(kind: str, source: str, *, debug: LogMessage) -> None:
    """Emit standardized prompt interrupt diagnostics."""
    from adscan_core.interrupts import emit_interrupt_debug

    emit_interrupt_debug(kind=kind, source=source, print_debug=debug)


def default_use_questionary_in_container() -> bool:
    """Return True when the container runtime should prefer Questionary."""
    return os.getenv("ADSCAN_CONTAINER_RUNTIME") == "1"


def configure_prompt_behavior(
    *,
    should_disable_interactive_prompts: NonInteractivePredicate | None = None,
    interrupt_logger: InterruptLogger | None = None,
    use_questionary_in_container: QuestionaryPredicate | None = None,
) -> None:
    """Configure prompt runtime hooks shared by CLI host and container code."""
    global _PROMPT_SHOULD_DISABLE_INTERACTIVE
    global _PROMPT_INTERRUPT_LOGGER
    global _PROMPT_USE_QUESTIONARY_IN_CONTAINER

    _PROMPT_SHOULD_DISABLE_INTERACTIVE = should_disable_interactive_prompts
    _PROMPT_INTERRUPT_LOGGER = interrupt_logger
    _PROMPT_USE_QUESTIONARY_IN_CONTAINER = use_questionary_in_container


def set_prompt_auto_mode(active: bool) -> None:
    """Enable or disable prompt auto-mode."""
    global _PROMPT_AUTO_MODE_ACTIVE
    _PROMPT_AUTO_MODE_ACTIVE = bool(active)


def is_prompt_auto_mode_enabled() -> bool:
    """Return whether prompt auto-mode is currently active."""
    return bool(_PROMPT_AUTO_MODE_ACTIVE)


def should_disable_prompt_interaction(shell: object | None = None) -> bool:
    """Best-effort predicate for non-interactive prompt behavior."""
    callback = (
        _PROMPT_SHOULD_DISABLE_INTERACTIVE or default_should_disable_interactive_prompts
    )
    try:
        return bool(callback(shell))
    except Exception:
        return True


def should_use_questionary_prompt() -> bool:
    """Return True when Questionary may be considered as a prompt backend."""
    callback = (
        _PROMPT_USE_QUESTIONARY_IN_CONTAINER or default_use_questionary_in_container
    )
    try:
        return bool(callback())
    except Exception:
        return False


def is_running_event_loop() -> bool:
    """Return True when the current thread is inside an asyncio event loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return False
    return True


def classify_prompt_answer(
    answer_text: str,
    *,
    password_mode: bool,
    prompt_message: str = "",
) -> str:
    """Best-effort answer classification for telemetry sanitization."""
    prompt_lower = str(prompt_message or "").strip().lower()
    if password_mode or any(
        keyword in prompt_lower
        for keyword in (
            "password",
            "passphrase",
            "hash",
            "ntlm",
            "secret",
            "credential",
            "token",
            "apikey",
            "api key",
        )
    ):
        return "password"

    cleaned = str(answer_text or "").strip()
    if not cleaned:
        return "user"

    try:
        ipaddress.ip_network(cleaned, strict=False)
        return "ip"
    except ValueError:
        pass

    if cleaned.startswith(("/", "./", "../", "~")) or re.match(
        r"^[A-Za-z]:\\", cleaned
    ):
        return "path"
    if re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", cleaned):
        return "domain"
    return "user"


def emit_prompt_interrupt_debug(
    *,
    kind: str,
    source: str,
    debug: LogMessage,
) -> None:
    """Emit standardized interrupt debug messages for prompt flows."""
    callback = _PROMPT_INTERRUPT_LOGGER
    try:
        if callback is not None:
            callback(kind, source)
            return
        default_interrupt_logger(kind, source, debug=debug)
    except Exception:
        return


def logged_prompt_ask(
    *prompt_args: Any,
    original_prompt_ask: PromptAsk | None,
    telemetry: LogMessage,
    debug: LogMessage,
    info: LogMessage,
    **kwargs: Any,
) -> str:
    """Prompt.ask wrapper with backend selection and centralized logging."""
    prompt_message = str(prompt_args[0]) if prompt_args else "?"
    password_mode = bool(kwargs.get("password", False))
    default_value = kwargs.get("default")

    prompt_tag = "[prompt][password]" if password_mode else "[prompt]"
    telemetry(f"{prompt_tag} {prompt_message}")
    debug(f"[prompt] Prompt: {prompt_message}")

    if _PROMPT_AUTO_MODE_ACTIVE:
        fallback = "" if default_value is None else str(default_value)
        shown = "[hidden]" if password_mode and fallback else fallback
        info(f"{prompt_message} [dim](auto: {shown})[/dim]")
        _log_prompt_answer(
            prompt_message=prompt_message,
            answer_text=fallback,
            password_mode=password_mode,
            telemetry=telemetry,
            debug=debug,
        )
        return fallback

    if should_disable_prompt_interaction():
        fallback = "" if default_value is None else str(default_value)
        debug(f"[prompt] Non-interactive mode; using fallback for '{prompt_message}'.")
        _log_prompt_answer(
            prompt_message=prompt_message,
            answer_text=fallback,
            password_mode=password_mode,
            telemetry=telemetry,
            debug=None,
        )
        return fallback

    answer: Any = None
    if should_use_questionary_prompt() and not is_running_event_loop():
        answer = _ask_questionary_text(
            prompt_message=prompt_message,
            default_value=default_value,
            password_mode=password_mode,
            telemetry=telemetry,
            debug=debug,
        )
    elif should_use_questionary_prompt():
        debug(
            f"[prompt] Active asyncio event loop detected; using Rich prompt fallback for '{prompt_message}'."
        )

    if answer is None:
        if original_prompt_ask is None:
            from rich.prompt import Prompt

            answer = Prompt.ask(*prompt_args, **kwargs)
        else:
            answer = original_prompt_ask(*prompt_args, **kwargs)

    answer_text = "" if answer is None else str(answer)
    _log_prompt_answer(
        prompt_message=prompt_message,
        answer_text=answer_text,
        password_mode=password_mode,
        telemetry=telemetry,
        debug=debug,
    )
    return answer_text


def logged_numeric_prompt_ask(
    *prompt_args: Any,
    original_prompt_ask: PromptAsk | None,
    coerce: Callable[[Any], Any],
    rich_prompt_name: str,
    telemetry: LogMessage,
    debug: LogMessage,
    info: LogMessage,
    **kwargs: Any,
) -> Any:
    """IntPrompt/FloatPrompt wrapper mirroring :func:`logged_prompt_ask`.

    Numeric Rich prompts (``IntPrompt.ask`` / ``FloatPrompt.ask``) were never
    wrapped, so a raw call stayed interactive and HUNG ``adscan ci`` (Docker
    ``-it`` hands a blocking TTY rather than EOF). This wrapper applies the same
    non-interactive auto-resolve-to-``default`` behavior the text/confirm
    wrappers use, returning the SAME native type Rich would (``int`` /
    ``float``) so call sites that arithmetic on the result keep working.

    Args:
        prompt_args: Positional args forwarded to the original prompt.
        original_prompt_ask: Captured original ``IntPrompt.ask`` /
            ``FloatPrompt.ask`` (``None`` → resolved lazily from Rich).
        coerce: Value coercer applied to the resolved default
            (``int`` / ``float``) so the auto-resolved answer matches Rich's
            native return type.
        rich_prompt_name: ``"IntPrompt"`` / ``"FloatPrompt"`` — used to resolve
            the original callable lazily when ``original_prompt_ask`` is None.
        telemetry: Telemetry sink callback.
        debug: Debug-log sink callback.
        info: Visible-info sink callback.
        kwargs: Keyword args forwarded to the original prompt (``default`` is
            read for the auto-resolve path).

    Returns:
        The numeric answer (``int`` / ``float``).
    """
    prompt_message = str(prompt_args[0]) if prompt_args else "?"
    default_value = kwargs.get("default")

    telemetry(f"[prompt] {prompt_message}")
    debug(f"[prompt] Prompt: {prompt_message}")

    def _resolve_default() -> Any:
        if default_value is None:
            return None
        try:
            return coerce(default_value)
        except (TypeError, ValueError):
            return default_value

    if _PROMPT_AUTO_MODE_ACTIVE or should_disable_prompt_interaction():
        resolved = _resolve_default()
        if _PROMPT_AUTO_MODE_ACTIVE:
            info(f"{prompt_message} [dim](auto: {resolved})[/dim]")
        else:
            debug(
                f"[prompt] Non-interactive mode; using fallback for '{prompt_message}'."
            )
        _log_prompt_answer(
            prompt_message=prompt_message,
            answer_text="" if resolved is None else str(resolved),
            password_mode=False,
            telemetry=telemetry,
            debug=debug if _PROMPT_AUTO_MODE_ACTIVE else None,
        )
        return resolved

    if original_prompt_ask is None:
        import rich.prompt as _rich_prompt

        original_prompt_ask = getattr(_rich_prompt, rich_prompt_name).ask
    answer = original_prompt_ask(*prompt_args, **kwargs)

    _log_prompt_answer(
        prompt_message=prompt_message,
        answer_text="" if answer is None else str(answer),
        password_mode=False,
        telemetry=telemetry,
        debug=debug,
    )
    return answer


def logged_int_prompt_ask(
    *prompt_args: Any,
    original_int_prompt_ask: PromptAsk | None,
    telemetry: LogMessage,
    debug: LogMessage,
    info: LogMessage,
    **kwargs: Any,
) -> Any:
    """IntPrompt.ask wrapper: auto-resolve to ``int(default)`` non-interactively."""
    return logged_numeric_prompt_ask(
        *prompt_args,
        original_prompt_ask=original_int_prompt_ask,
        coerce=int,
        rich_prompt_name="IntPrompt",
        telemetry=telemetry,
        debug=debug,
        info=info,
        **kwargs,
    )


def logged_float_prompt_ask(
    *prompt_args: Any,
    original_float_prompt_ask: PromptAsk | None,
    telemetry: LogMessage,
    debug: LogMessage,
    info: LogMessage,
    **kwargs: Any,
) -> Any:
    """FloatPrompt.ask wrapper: auto-resolve to ``float(default)`` non-interactively."""
    return logged_numeric_prompt_ask(
        *prompt_args,
        original_prompt_ask=original_float_prompt_ask,
        coerce=float,
        rich_prompt_name="FloatPrompt",
        telemetry=telemetry,
        debug=debug,
        info=info,
        **kwargs,
    )


def logged_confirm_ask(
    *confirm_args: Any,
    original_confirm_ask: ConfirmAsk | None,
    telemetry: LogMessage,
    debug: LogMessage,
    info: LogMessage,
    **kwargs: Any,
) -> bool:
    """Confirm.ask wrapper with backend selection and centralized logging."""
    prompt_message = str(confirm_args[0]) if confirm_args else "Confirm?"
    telemetry(f"[confirm] {prompt_message}")
    debug(f"[confirm] Prompt: {prompt_message}")

    if _PROMPT_AUTO_MODE_ACTIVE:
        resolved = bool(kwargs.get("default", True))
        response_text = "Yes" if resolved else "No"
        info(f"{prompt_message} [dim](auto: {response_text})[/dim]")
        _log_confirm_answer(prompt_message, resolved, telemetry=telemetry, debug=debug)
        return resolved

    if should_disable_prompt_interaction():
        resolved = bool(kwargs.get("default", True))
        debug(
            f"[confirm] Non-interactive mode; using fallback for '{prompt_message}': {resolved}"
        )
        _log_confirm_answer(prompt_message, resolved, telemetry=telemetry, debug=None)
        return resolved

    answer: Any = None
    if should_use_questionary_prompt() and not is_running_event_loop():
        answer = _ask_questionary_confirm(
            prompt_message=prompt_message,
            default_value=bool(kwargs.get("default", False)),
            telemetry=telemetry,
            debug=debug,
        )
        if answer is not None:
            resolved = bool(answer)
            _log_confirm_answer(
                prompt_message, resolved, telemetry=telemetry, debug=debug
            )
            return resolved
    elif should_use_questionary_prompt():
        debug(
            f"[confirm] Active asyncio event loop detected; using Rich confirm fallback for '{prompt_message}'."
        )

    if original_confirm_ask is None:
        from rich.prompt import Confirm

        answer = Confirm.ask(*confirm_args, **kwargs)
    else:
        answer = original_confirm_ask(*confirm_args, **kwargs)

    resolved = bool(answer)
    _log_confirm_answer(prompt_message, resolved, telemetry=telemetry, debug=debug)
    return resolved


def questionary_style(questionary_module: Any) -> Any:
    """Return shared Questionary style used across prompts."""
    return questionary_module.Style(
        [
            ("qmark", "fg:#1AA0AE bold"),
            ("question", "bold white"),
            ("answer", "fg:#1AA0AE bold"),
            ("pointer", "fg:#1AA0AE bold"),
            ("highlighted", "fg:#1AA0AE bold"),
            ("selected", "fg:#1AA0AE bold"),
            ("separator", "fg:#1AA0AE"),
            ("instruction", "fg:#cccccc"),
            ("text", "white"),
            ("choice", "white"),
            ("disabled", "fg:#888888 italic"),
        ]
    )


def _rich_numeric_select_value(*, title: str, options: list[str]) -> str | None:
    """Rich-based numeric single-select usable inside an active event loop.

    ``questionary``/``prompt_toolkit`` cannot run a prompt session inside a
    running asyncio loop. This fallback renders a numbered menu and reads the
    choice with ``rich.prompt.IntPrompt`` (which needs no event loop of its
    own) — mirroring the text/confirm fallbacks. Returns ``None`` only when
    truly non-interactive (so the caller resolves its own default) or on
    cancellation.
    """
    if not options:
        return None
    if default_should_disable_interactive_prompts():
        return None
    try:
        from rich.prompt import IntPrompt

        from adscan_core.output._state import get_console

        console = get_console()
        console.print(title)
        for idx, option in enumerate(options, start=1):
            console.print(f"  {idx}. {option}")
        choice = IntPrompt.ask(
            "Select an option (number)",
            choices=[str(i) for i in range(1, len(options) + 1)],
            default=1,
            console=console,
        )
    except (EOFError, KeyboardInterrupt):
        return None
    except Exception:  # noqa: BLE001 - never let the fallback crash the caller
        return None
    index = int(choice)
    if 1 <= index <= len(options):
        return options[index - 1]
    return None


def questionary_select_value(*, title: str, options: list[str]) -> str | None:
    """Render a Questionary single-select prompt and return selected value."""
    if not options:
        return None
    if is_running_event_loop():
        # prompt_toolkit cannot nest a prompt session inside a running asyncio
        # loop. Returning None here silently skipped the prompt — callers read
        # that as "cancelled", which (e.g.) ran DCSync against a bogus target
        # when the follow-up executes inside the dump's loop. Fall back to a
        # Rich numeric select that works without its own event loop.
        return _rich_numeric_select_value(title=title, options=options)
    try:
        import questionary  # type: ignore
    except Exception:
        return None
    try:
        return questionary.select(
            title,
            choices=list(options),
            style=questionary_style(questionary),
        ).ask()
    except (EOFError, KeyboardInterrupt):
        return None


def _rich_numeric_checkbox_values(
    *,
    title: str,
    options: list[str],
    default_values: list[str] | None = None,
    labels_by_value: dict[str, str] | None = None,
) -> list[str] | None:
    """Rich-based multi-select usable inside an active event loop.

    Companion to :func:`_rich_numeric_select_value` for checkbox prompts —
    ``questionary`` cannot run inside a running asyncio loop. Reads
    comma-separated numbers (or ``all`` / ``none`` / Enter for defaults).
    """
    if not options:
        return None
    if default_should_disable_interactive_prompts():
        return None
    resolved_defaults = {str(v) for v in (default_values or []) if str(v).strip()}
    try:
        from rich.prompt import Prompt

        from adscan_core.output._state import get_console

        console = get_console()
        console.print(title)
        for idx, option in enumerate(options, start=1):
            label = str((labels_by_value or {}).get(str(option), str(option)))
            mark = "x" if str(option) in resolved_defaults else " "
            console.print(f"  [{mark}] {idx}. {label}")
        raw = Prompt.ask(
            "Select (comma-separated numbers, 'all', 'none', Enter=defaults)",
            default="",
            console=console,
        )
    except (EOFError, KeyboardInterrupt):
        return None
    except Exception:  # noqa: BLE001 - never let the fallback crash the caller
        return None
    cleaned = str(raw or "").strip().lower()
    if cleaned == "":
        return [str(o) for o in options if str(o) in resolved_defaults]
    if cleaned == "all":
        return [str(o) for o in options]
    if cleaned == "none":
        return []
    chosen: list[str] = []
    for token in cleaned.replace(" ", "").split(","):
        if token.isdigit() and 1 <= int(token) <= len(options):
            value = str(options[int(token) - 1])
            if value not in chosen:
                chosen.append(value)
    return chosen or None


def questionary_checkbox_values_raw(
    *,
    title: str,
    options: list[str],
    default_values: list[str] | None = None,
    labels_by_value: dict[str, str] | None = None,
) -> list[str] | None:
    """Render Questionary checkbox without extra logging logic."""
    if not options:
        return None
    if is_running_event_loop():
        # prompt_toolkit cannot nest inside a running asyncio loop — fall back to
        # a Rich numeric multi-select (see _rich_numeric_select_value rationale).
        return _rich_numeric_checkbox_values(
            title=title,
            options=options,
            default_values=default_values,
            labels_by_value=labels_by_value,
        )
    try:
        import questionary  # type: ignore
    except Exception:
        return None
    try:
        resolved_defaults = (
            {str(value) for value in default_values if str(value).strip()}
            if default_values is not None
            else {str(option) for option in options if str(option).strip()}
        )
        choices = [
            questionary.Choice(
                title=str((labels_by_value or {}).get(str(option), str(option))),
                value=str(option),
                checked=str(option) in resolved_defaults,
            )
            for option in options
        ]
        selected = questionary.checkbox(
            title,
            choices=choices,
            style=questionary_style(questionary),
        ).ask()
    except (EOFError, KeyboardInterrupt):
        return None
    if selected is None:
        return None
    return [str(value) for value in selected if str(value).strip()]


def _ask_questionary_text(
    *,
    prompt_message: str,
    default_value: object,
    password_mode: bool,
    telemetry: LogMessage,
    debug: LogMessage,
) -> Any:
    """Ask a text prompt through Questionary when the backend is safe."""
    try:
        import questionary  # type: ignore
    except Exception:
        return None

    default_text = "" if default_value is None else str(default_value)
    try:
        if password_mode:
            return questionary.password(prompt_message, default=default_text).ask()
        return questionary.text(prompt_message, default=default_text).ask()
    except EOFError:
        emit_prompt_interrupt_debug(
            kind="eof", source="rich_prompt.ask(container)", debug=debug
        )
        fallback = "" if default_value is None else str(default_value)
        _log_prompt_answer(
            prompt_message=prompt_message,
            answer_text=fallback,
            password_mode=password_mode,
            telemetry=telemetry,
            debug=None,
        )
        return fallback
    except KeyboardInterrupt:
        emit_prompt_interrupt_debug(
            kind="keyboard_interrupt", source="rich_prompt.ask(container)", debug=debug
        )
        return ""


def _ask_questionary_confirm(
    *,
    prompt_message: str,
    default_value: bool,
    telemetry: LogMessage,
    debug: LogMessage,
) -> bool | None:
    """Ask a confirmation through Questionary when the backend is safe."""
    try:
        import questionary  # type: ignore
    except Exception:
        return None
    try:
        q_answer = questionary.confirm(prompt_message, default=default_value).ask()
        return default_value if q_answer is None else bool(q_answer)
    except EOFError:
        emit_prompt_interrupt_debug(
            kind="eof", source="rich_confirm.ask(container)", debug=debug
        )
        _log_confirm_answer(
            prompt_message, default_value, telemetry=telemetry, debug=None
        )
        return default_value
    except KeyboardInterrupt:
        emit_prompt_interrupt_debug(
            kind="keyboard_interrupt", source="rich_confirm.ask(container)", debug=debug
        )
        _log_confirm_answer(
            prompt_message, default_value, telemetry=telemetry, debug=None
        )
        return default_value


def _log_prompt_answer(
    *,
    prompt_message: str,
    answer_text: str,
    password_mode: bool,
    telemetry: LogMessage,
    debug: LogMessage | None,
) -> None:
    answer_type = classify_prompt_answer(
        answer_text,
        password_mode=password_mode,
        prompt_message=prompt_message,
    )
    marked_answer = mark_sensitive(answer_text, answer_type)
    answer_tag = "[prompt][password][answer]" if password_mode else "[prompt][answer]"
    telemetry(f"{answer_tag} {prompt_message}: {marked_answer}")
    if debug is not None:
        debug(f"[prompt] Answer for '{prompt_message}': {marked_answer}")


def _log_confirm_answer(
    prompt_message: str,
    resolved: bool,
    *,
    telemetry: LogMessage,
    debug: LogMessage | None,
) -> None:
    answer_text = "Yes" if resolved else "No"
    telemetry(f"[confirm][answer] {prompt_message}: {answer_text}")
    if debug is not None:
        debug(f"[confirm] Answer for '{prompt_message}': {answer_text}")
