"""The one SIGINT policy and the Ctrl+C operator menu.

Before this module, Ctrl+C during a scan ran the shell's graceful shutdown and
ended the process (``PentestShell.signal_handler``); the session and its context
were lost. Now the shell hands every SIGINT to :func:`handle_sigint` first:

1. A centralized cooked-mode prompt is waiting on the MAIN thread: raise
   ``KeyboardInterrupt``, which cancels that prompt exactly as before.
2. A scan or step scope is open:

   * interactive: open the operator menu (stop this step, skip the rest of the
     phase, stop the scan, keep going);
   * unattended (``adscan ci``): the first SIGINT asks for ``abort_scan``, a
     clean stop that still writes artifacts and declares the gap; the second
     falls back to the shell's graceful shutdown.

3. No scope is open:

   * interactive: raise ``KeyboardInterrupt``; the running command is cancelled
     and the REPL returns to its prompt. Ctrl+C never ends an interactive CLI;
   * unattended: the graceful shutdown, as before.

The menu renders on its own daemon thread so the scan keeps working while the
operator reads it. Before rendering it pauses every ``LiveSession`` and holds the
visible console (other threads' output is captured and replayed afterwards,
other prompts wait), so nothing paints over it and nothing else reads stdin. It
is a questionary select in raw mode: a second Ctrl+C reaches it as a key and
means "stop the scan".
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable

from adscan_core.scan_control.controller import ScanControl, scan_control
from adscan_core.scan_control.vocabulary import (
    SOURCE_OPERATOR_MENU,
    SOURCE_SIGNAL,
    ControlAction,
    ControlRequest,
)

#: Shown on the first unattended SIGINT.
UNATTENDED_STOP_NOTICE = (
    "Stopping the scan cleanly: results so far are kept and the report declares "
    "what was not assessed. Press Ctrl+C again to stop immediately."
)

#: Operator-facing confirmation per menu decision.
_DECISION_NOTICES: dict[ControlAction, str] = {
    ControlAction.SKIP_STEP: (
        "Stopping this step: finishing the work already in flight, then moving on. "
        "Results found so far are kept."
    ),
    ControlAction.SKIP_PHASE: (
        "Skipping the rest of this phase after the work already in flight. "
        "Results found so far are kept."
    ),
    ControlAction.ABORT_SCAN: (
        "Stopping the scan: finishing the work already in flight, then returning "
        "to the prompt. Results found so far are kept."
    ),
    ControlAction.CONTINUE: "Continuing.",
}

#: Prompt function used by the menu: ``(title, options) -> index | None``.
#: ``None`` means cancelled by Ctrl+C. Replaceable in tests.
MenuPrompt = Callable[[str, list[str]], "int | None"]

_MENU_LOCK = threading.Lock()
_MENU_OPEN = threading.Event()

#: A second Ctrl+C within this many seconds of a command cancel is absorbed.
COMMAND_CANCEL_DEBOUNCE_SECONDS = 1.0
_LAST_COMMAND_CANCEL = -1e9


def menu_is_open() -> bool:
    """Whether the operator menu is on screen."""
    return _MENU_OPEN.is_set()


def _main_thread_in_prompt() -> bool:
    try:
        from adscan_core.output._state import prompt_active_on_thread  # noqa: PLC0415

        return prompt_active_on_thread(threading.main_thread().ident)
    except Exception:  # noqa: BLE001
        return False


def _no_scope_interactive() -> bool:
    try:
        from adscan_core.interaction import is_non_interactive  # noqa: PLC0415

        return not is_non_interactive()
    except Exception:  # noqa: BLE001 - unknown reads as unattended
        return False


def handle_sigint(
    signum: int,
    frame: Any,
    *,
    fallback: Callable[[int, Any], None],
    control: ScanControl | None = None,
    open_menu: Callable[[ScanControl], None] | None = None,
) -> None:
    """Apply the SIGINT policy described in the module docstring.

    Args:
        signum: The signal number (SIGINT).
        frame: The interrupted frame.
        fallback: The shell's graceful shutdown, for the unattended cases.
        control: The control plane (default: the process-wide one).
        open_menu: Menu launcher (default: :func:`open_operator_menu`).
    """
    ctl = control or scan_control()
    if _main_thread_in_prompt():
        raise KeyboardInterrupt
    if ctl.active():
        if ctl.interactive():
            if menu_is_open():
                # Only reachable with the cooked-mode fallback prompt: a second
                # Ctrl+C while the menu is up means "stop the scan".
                ctl.request(ControlRequest(ControlAction.ABORT_SCAN, source=SOURCE_OPERATOR_MENU))
                _warn(_DECISION_NOTICES[ControlAction.ABORT_SCAN])
                return
            (open_menu or open_operator_menu)(ctl)
            return
        if ctl.note_signal() == 1:
            ctl.request(ControlRequest(ControlAction.ABORT_SCAN, source=SOURCE_SIGNAL))
            _warn(UNATTENDED_STOP_NOTICE)
            return
        fallback(signum, frame)
        return
    if _no_scope_interactive():
        # Debounce the panicked mash: the first Ctrl+C cancels the command; one
        # landing within a second of it (while that cancellation unwinds or the
        # REPL prints its notice) is absorbed instead of escaping the prompt
        # loop and ending the session.
        global _LAST_COMMAND_CANCEL
        now = time.monotonic()
        if now - _LAST_COMMAND_CANCEL < COMMAND_CANCEL_DEBOUNCE_SECONDS:
            _debug("scan-control: repeated Ctrl+C absorbed while the command cancels")
            return
        _LAST_COMMAND_CANCEL = now
        raise KeyboardInterrupt
    fallback(signum, frame)


def resolve_menu_choice(
    control: ScanControl,
    *,
    interactive: bool,
    prompt: MenuPrompt | None = None,
) -> ControlAction:
    """Ask the operator what to do and return the chosen action.

    Unattended: never prompts, returns ``continue`` (the safe default: an
    automated run that somehow reaches the menu changes nothing). A prompt that
    is cancelled with Ctrl+C means "stop the scan".
    """
    choices = control.menu_choices()
    if not interactive:
        return ControlAction.CONTINUE
    labels = [label for _action, label in choices]
    position = control.position_line()
    title = f"Ctrl+C · {position}" if position else "Ctrl+C"
    asker = prompt or _questionary_menu_prompt
    try:
        index = asker(title, labels)
    except KeyboardInterrupt:
        index = None
    if index is None:
        return ControlAction.ABORT_SCAN
    if 0 <= index < len(choices):
        return choices[index][0]
    return ControlAction.CONTINUE


def apply_menu_choice(control: ScanControl, action: ControlAction) -> bool:
    """Register the operator's decision; returns whether it was accepted."""
    step = control.current_step()
    accepted = control.request(
        ControlRequest(
            action=action,
            source=SOURCE_OPERATOR_MENU,
            target_step=step.step_id if step is not None else "",
            target_phase=control.phase_id,
        )
    )
    _telemetry_line(f"[scan-control] operator chose {action.value} accepted={accepted}")
    return accepted


def open_operator_menu(
    control: ScanControl | None = None,
    *,
    prompt: MenuPrompt | None = None,
    blocking: bool = False,
) -> threading.Thread | None:
    """Open the operator menu on its own thread (one menu at a time).

    Returns the menu thread, or ``None`` when a menu is already open. With
    ``blocking=True`` the menu runs on the calling thread (tests).
    """
    ctl = control or scan_control()
    if not _MENU_LOCK.acquire(blocking=False):
        return None
    _MENU_OPEN.set()

    def _run() -> None:
        try:
            _run_menu(ctl, prompt=prompt)
        finally:
            _MENU_OPEN.clear()
            _MENU_LOCK.release()

    if blocking:
        _run()
        return None
    thread = threading.Thread(target=_run, name="adscan-scan-control-menu", daemon=True)
    try:
        thread.start()
    except RuntimeError:
        _MENU_OPEN.clear()
        _MENU_LOCK.release()
        return None
    return thread


def _run_menu(control: ScanControl, *, prompt: MenuPrompt | None) -> None:
    held = _hold_console()
    paused = _pause_live()
    action = ControlAction.CONTINUE
    try:
        action = resolve_menu_choice(control, interactive=True, prompt=prompt)
        accepted = apply_menu_choice(control, action)
        notice = _DECISION_NOTICES.get(action, "")
        if action != ControlAction.CONTINUE and not accepted:
            notice = "That step finished while the menu was open. Continuing."
        _info(notice)
    except Exception as exc:  # noqa: BLE001 - the menu must never break the scan
        _debug(f"scan-control: operator menu failed ({type(exc).__name__}: {exc})")
    finally:
        _resume_live(paused)
        if held:
            _release_console()


def _questionary_menu_prompt(title: str, options: list[str]) -> int | None:
    """Raw-mode select on the menu thread. Ctrl+C raises KeyboardInterrupt."""
    try:
        import questionary  # noqa: PLC0415

        from adscan_core import prompting  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        return _numeric_menu_prompt(title, options)
    try:
        answer = questionary.select(
            title,
            choices=list(options),
            style=prompting.questionary_style(questionary),
        ).unsafe_ask()
    except KeyboardInterrupt:
        raise
    except Exception:  # noqa: BLE001 - a terminal questionary cannot drive
        return _numeric_menu_prompt(title, options)
    if answer is None:
        return None
    try:
        return options.index(answer)
    except ValueError:
        return None


def _numeric_menu_prompt(title: str, options: list[str]) -> int | None:
    from rich.prompt import IntPrompt  # noqa: PLC0415

    from adscan_core.output._state import get_console  # noqa: PLC0415

    console = get_console()
    console.print(title)
    for index, option in enumerate(options, start=1):
        console.print(f"  {index}. {option}")
    choice = IntPrompt.ask(
        "Select an option (number)",
        choices=[str(i) for i in range(1, len(options) + 1)],
        default=len(options),
        console=console,
    )
    return int(choice) - 1


def hint_text(control: ScanControl | None = None) -> str:
    """The dim footer a long step's progress view shows, or ``""``."""
    ctl = control or scan_control()
    step = ctl.current_step()
    if step is None or not step.long or not ctl.interactive():
        return ""
    if step.stopped or ctl.stop_pending():
        return "Stopping: finishing the work already in flight. Ctrl+C for more options."
    return "Ctrl+C for options: stop this step, skip the phase or stop the scan."


# ----------------------------------------------------------------------------
# Thin, best-effort adapters to the output layer (kept here so the controller
# stays free of Rich and prompt imports).
# ----------------------------------------------------------------------------
def _hold_console() -> bool:
    try:
        from adscan_core.output._state import hold_visible_console  # noqa: PLC0415

        return bool(hold_visible_console())
    except Exception:  # noqa: BLE001
        return False


def _release_console() -> None:
    try:
        from adscan_core.output._state import release_visible_console  # noqa: PLC0415

        release_visible_console()
    except Exception:  # noqa: BLE001
        pass


def _pause_live() -> list[Any]:
    try:
        from adscan_core.tui.live_session import pause_active_live_sessions  # noqa: PLC0415

        return pause_active_live_sessions()
    except Exception:  # noqa: BLE001
        return []


def _resume_live(sessions: list[Any]) -> None:
    if not sessions:
        return
    try:
        from adscan_core.tui.live_session import resume_live_sessions  # noqa: PLC0415

        resume_live_sessions(sessions)
    except Exception:  # noqa: BLE001
        pass


def _info(message: str) -> None:
    if not message:
        return
    try:
        from adscan_core.rich_output import print_info  # noqa: PLC0415

        print_info(message)
    except Exception:  # noqa: BLE001
        pass


def _warn(message: str) -> None:
    try:
        from adscan_core.rich_output import print_warning  # noqa: PLC0415

        print_warning(message)
    except Exception:  # noqa: BLE001
        pass


def _debug(message: str) -> None:
    try:
        from adscan_core.rich_output import print_info_debug  # noqa: PLC0415

        print_info_debug(message)
    except Exception:  # noqa: BLE001
        pass


def _telemetry_line(message: str) -> None:
    try:
        from adscan_core.rich_output import print_telemetry_only  # noqa: PLC0415

        print_telemetry_only(message)
    except Exception:  # noqa: BLE001
        _debug(message)


__all__ = [
    "UNATTENDED_STOP_NOTICE",
    "apply_menu_choice",
    "handle_sigint",
    "hint_text",
    "menu_is_open",
    "open_operator_menu",
    "resolve_menu_choice",
]
