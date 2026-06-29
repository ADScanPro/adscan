"""Log/print primitives — info, success, warning, error, exception."""

from __future__ import annotations

import logging
import os
import re
import sys
from typing import Any, Dict, List, Optional, Union

from rich.box import ROUNDED
from rich.console import Group, RenderableType  # noqa: F401 — re-exported
from rich.markup import MarkupError
from rich.panel import Panel
from rich.text import Text

from adscan_core.output import _state
from adscan_core.theme import ADSCAN_PRIMARY


def _safe_markup_text(message: Any, *, style: Optional[str] = None) -> Text:
    """Render ``message`` as a Rich ``Text`` without ever raising ``MarkupError``.

    This is the single source of truth for turning a caller-supplied message
    into a ``Text`` inside every ``print_*`` helper. The historical pattern —
    ``Text.from_markup(message)`` whenever the string contained ``[`` and
    ``]`` — crashes the whole print call when the brackets are NOT valid Rich
    markup. The dominant real-world trigger is an interpolated value the caller
    did not author and cannot sanitise: an absolute path (``[/opt/adscan/...]``
    — Rich reads ``[/...]`` as a closing tag), or an exception message rendered
    via ``f"...: {e}"`` whose text happens to contain a bracketed path. That
    raised a fresh ``MarkupError`` out of ``print_warning``/``print_error`` and
    propagated up to the command dispatcher as ``Error executing command``.

    Behaviour:
    - A ``Text`` is returned unchanged (caller already styled it).
    - A string with ``[`` and ``]`` is parsed as markup; on ``MarkupError`` it
      falls back to a LITERAL ``Text`` (brackets shown verbatim) with ``style``.
    - A plain string (or any other type, stringified) becomes a styled ``Text``.

    Args:
        message: Caller-supplied message (``Text``, markup string, plain string).
        style: Default style applied to the plain/fallback ``Text``.

    Returns:
        A ``Text`` suitable for ``console.print`` / ``Text.append``.
    """
    if isinstance(message, Text):
        return message
    text = message if isinstance(message, str) else str(message)
    if "[" in text and "]" in text:
        try:
            return Text.from_markup(text)
        except MarkupError:
            # Brackets were not valid markup (uncontrolled path / exception
            # text). Render the string literally instead of crashing the print.
            return Text(text, style=style) if style else Text(text)
    return Text(text, style=style) if style else Text(text)

# Brand color mappings for message types
BRAND_COLORS = {
    "info": ADSCAN_PRIMARY,  # Info uses primary brand color (cyan)
    "success": "green",  # Success keeps green (standard for positive actions)
    "warning": "yellow",  # Warning uses yellow (standard for warnings)
    "error": "red",  # Error keeps red (standard for critical issues)
    "instruction": "dim",  # Instructions remain dim
}


# Container ↔ host path translation for user-facing output.
#
# ADscan ships every command inside a Docker container that bind-mounts the
# user's ``~/.adscan/`` directory to ``/opt/adscan/`` inside the container.
# The container code legitimately refers to paths under ``/opt/adscan/``
# (that's where the files physically live in the container), but every
# string the user reads in the TUI must show the host path — otherwise they
# try ``cat /opt/adscan/...`` from their shell and get "No such file or
# directory", which is a UX failure that compounds across the product.
#
# The substitution runs only when ``ADSCAN_CONTAINER_RUNTIME=1`` is set.
# Outside the container (dev mode, host process) the input passes through.
#
# The regex anchors on a boundary character after ``/opt/adscan`` so that
# sibling paths like ``/opt/adscan-src`` (the source mount) are NOT
# rewritten — they are container-internal and never user-facing.
_CONTAINER_DISPLAY_PATH_RE = re.compile(r"/opt/adscan(?=[/\s\"'`,;:)\]}]|$)")
_HOST_DISPLAY_PATH_REPLACEMENT = "~/.adscan"


def _translate_paths_for_display(value: Any) -> Any:
    """Rewrite container paths to host paths for display.

    Strings get a regex substitution. Other types pass through unchanged
    (Rich ``Text`` objects assembled by callers must be pre-translated by
    the caller using ``adscan_internal.services.host_open.display_host_path``;
    walking arbitrary Rich renderables would be fragile and is not worth
    the complexity for the small fraction of call sites that build Text
    objects manually).
    """
    if not isinstance(value, str):
        return value
    if os.environ.get("ADSCAN_CONTAINER_RUNTIME") != "1":
        return value
    return _CONTAINER_DISPLAY_PATH_RE.sub(_HOST_DISPLAY_PATH_REPLACEMENT, value)


def _translate_items_for_display(
    items: Optional[List[Union[str, Text]]],
) -> Optional[List[Union[str, Text]]]:
    """Translate every string entry in an ``items`` list for display."""
    if items is None:
        return items
    return [_translate_paths_for_display(item) for item in items]

# Spacing state — owned here because _handle_spacing / reset_spacing live here
_last_message_type: Optional[str] = None
_last_was_panel: bool = False

# Convenience aliases so moved code doesn't need to change call sites
_get_console = _state._get_console
_get_telemetry_console = _state._get_telemetry_console
_diag_log = _state._diag_log


def print_telemetry_only(message: Any) -> None:
    """Print a message only to the telemetry console (if configured).

    This is intentionally silent for the primary user console. It is used to
    record interactive prompt questions (and other internal events) into the
    session recording without duplicating what the user already sees.

    Args:
        message: Any Rich renderable or markup string to record.
    """
    telemetry_console = _get_telemetry_console()
    if telemetry_console is None:
        return
    telemetry_console.print(message)


def _handle_spacing(message_type: str, is_panel: bool, spacing: str = "auto") -> str:
    """Handle intelligent spacing between messages for better UX/UI.

    Spacing rules:
    - Panels: Always have space before and after (visual blocks)
    - Change of message type: Add space before (info -> success, error -> info, etc.)
    - Same message type: No space (group related messages)
    - Manual control: Use spacing parameter

    Args:
        message_type: Type of message ('info', 'success', 'warning', 'error',
            'instruction')
        is_panel: Whether this is a panel (always gets spacing)
        spacing: Spacing control:
            - "auto" (default): Intelligent spacing based on context
            - "none": No spacing
            - "before": Space before message
            - "after": Space after message
            - "both": Space before and after

    Returns:
        String with appropriate newlines ("", "\n", "\n\n", etc.)
    """
    global _last_message_type, _last_was_panel

    # Manual control overrides automatic behavior
    if spacing != "auto":
        if spacing == "none":
            _last_message_type = message_type
            _last_was_panel = is_panel
            return ""
        if spacing == "before":
            _last_message_type = message_type
            _last_was_panel = is_panel
            return "\n"
        if spacing == "after":
            _last_message_type = message_type
            _last_was_panel = is_panel
            return ""  # Will be handled after print
        if spacing == "both":
            _last_message_type = message_type
            _last_was_panel = is_panel
            return "\n"

    # Automatic spacing logic
    spacing_before = ""

    # Panels always get space before (they're visual blocks)
    if is_panel:
        spacing_before = "\n"
    # If last message was a panel, add space (panels need separation)
    elif _last_was_panel:
        spacing_before = "\n"
    # If message type changed, add space (visual separation of different contexts)
    elif _last_message_type is not None and _last_message_type != message_type:
        # Special: errors and warnings get more space when transitioning
        error_warning_types = ("error", "warning")
        if (
            message_type in error_warning_types
            and _last_message_type not in error_warning_types
        ):
            spacing_before = "\n"
        elif (
            _last_message_type in error_warning_types
            and message_type not in error_warning_types
        ):
            spacing_before = "\n"
        else:
            spacing_before = "\n"

    # Update tracking
    _last_message_type = message_type
    _last_was_panel = is_panel

    return spacing_before


def reset_spacing():
    """Reset spacing tracking (useful for new sections or after major operations)."""
    global _last_message_type, _last_was_panel
    _last_message_type = None
    _last_was_panel = False


def _extract_plain_text(message: object) -> str:
    """Extract plain text from Rich message for logging.

    Args:
        message: Rich message (string with markup or Text object)

    Returns:
        Plain text string without Rich markup
    """
    if isinstance(message, Text):
        return message.plain
    if isinstance(message, str):
        # Remove Rich markup tags (simple approach)
        import re

        # Remove [tag]...[/tag] patterns
        plain = re.sub(r"\[/?[^\]]+\]", "", message)
        return plain.strip()
    return str(message)


def _get_logger() -> logging.Logger:
    """Get logger instance, always fresh from logging_config to ensure it has all handlers.

    This function always gets the logger from logging_config.get_logger() to ensure
    it has all handlers (including telemetry handler) that may have been added after
    the logger was first cached. This is critical for telemetry capture.
    """
    try:
        from adscan_core.logging_config import get_logger

        # Always get fresh logger to ensure it has all handlers (including telemetry)
        # get_logger() returns the same singleton, so this is safe and ensures handlers are up-to-date
        return get_logger()
    except ImportError:
        # Fallback: create basic logger if logging_config not available
        return logging.getLogger("adscan")


def _log_to_file(level: int, message: str) -> None:
    """Log a message only to file handlers, without touching console handlers.

    Kept for backwards compatibility and potential future use. The current
    architecture prefers routing verbose/debug helpers through the main logger
    so that all handlers (file, console, telemetry) can make consistent
    decisions based on their own levels.
    """
    try:
        # Preferred path: delegate to logging_config, which knows about the
        # file and workspace handlers but not the Rich console handlers.
        from adscan_core.logging_config import log_to_file_only

        log_to_file_only(level, message)
        return
    except Exception:
        # Fallback: use the main logger directly (this may hit console handlers
        # in edge cases, but we prefer persistence over silence).
        logger = _get_logger()
        logger.log(level, message)


def _build_persisted_message(
    message: Union[str, Text],
    items: Optional[List[Union[str, Text]]] = None,
) -> str:
    """Build one plain-text file log message from Rich output inputs.

    Normal operator-facing print helpers render directly to the console and
    telemetry console. To keep workspace/global log files useful in normal mode,
    we also persist a plain-text version of the same message to file-only
    handlers without duplicating console output.

    Args:
        message: Primary message body.
        items: Optional bullet items shown underneath the primary message.

    Returns:
        Plain-text representation suitable for file logging.
    """
    parts = [_extract_plain_text(message)]
    if items:
        for item in items:
            parts.append(f"- {_extract_plain_text(item)}")
    return "\n".join(part for part in parts if part)


def _print_logger_format_fallback(
    level_name: str, message: Union[str, Text], level_color: str = "blue"
) -> None:
    """Print a message with logger-style format (INFO/DEBUG) as fallback when RichHandler is not available.

    This function simulates the RichHandler format to ensure verbose/debug messages
    are visually differentiated even when the RichHandler is not configured correctly.

    Args:
        level_name: Log level name (e.g., "INFO", "DEBUG", "WARNING", "ERROR")
        message: Message to display (supports Rich markup strings or Text objects)
        level_color: Color for the level name (default: "blue" for INFO, "cyan" for DEBUG)
    """
    from rich.text import Text

    console = _get_console()
    _get_telemetry_console()

    # Extract plain text if needed
    if isinstance(message, Text):
        plain_text = message.plain
    else:
        plain_text = _extract_plain_text(message)

    # Create logger-style format: "LEVEL     message"
    # RichHandler uses 8 characters for level name, left-aligned
    level_padding = 8
    level_text = level_name.ljust(level_padding)

    # Create formatted output similar to RichHandler
    output = Text()
    output.append(level_text, style=f"bold {level_color}")
    output.append(" ")

    # Add the message (preserve Rich markup if it's a string)
    if isinstance(message, Text):
        output.append(message)
    elif "[" in str(message) and "]" in str(message):
        # Rich markup string - parse it (literal fallback on malformed markup)
        output.append(_safe_markup_text(message))
    else:
        # Plain string
        output.append(plain_text)

    console.print(output)


# --- Basic Print Functions with Enhanced Styling ---


def print_info(
    message: Union[str, Text],
    panel: bool = False,
    icon: str = "ℹ",
    items: Optional[List[Union[str, Text]]] = None,
    spacing: str = "auto",
):
    """Print an informational message with optional panel and icon.

    Args:
        message: Message to display. Can be:
            - Plain string: "Hello world"
            - Rich markup string: "[bold]Hello[/bold] [red]world[/red]"
            - Text object: Text("Hello", style="bold")
        panel: If True, display in a panel with border
        icon: Icon to display (default: ℹ)
        items: Optional list of items to display below message (supports same formats as message)
        spacing: Spacing control ("auto", "none", "before", "after", "both"). Default: "auto"
            - "auto": Intelligent spacing based on context
            - "none": No spacing
            - "before": Space before message
            - "after": Space after message
            - "both": Space before and after
    """
    # Rewrite container paths in user-facing output so the path the user
    # sees matches what they can ``cat`` or open from their host shell.
    message = _translate_paths_for_display(message)
    items = _translate_items_for_display(items)

    console = _get_console()
    _get_telemetry_console()

    # Handle spacing
    spacing_before = _handle_spacing("info", panel, spacing)
    if spacing_before:
        console.print()

    # Format icon
    icon_text = Text(f"{icon} ", style=BRAND_COLORS["info"])

    # Format message (preserves Rich markup or Text object)
    # Render via the SSOT helper: parse markup when present, fall back to a
    # LITERAL Text on malformed markup (e.g. a bracketed path / exception text)
    # instead of raising MarkupError out of the print call.
    message_text = _safe_markup_text(message, style=BRAND_COLORS["info"])

    if panel:
        content = Text()
        content.append(icon_text)
        content.append(message_text)

        if items:
            content.append("\n\n", style=BRAND_COLORS["info"])
            for item in items:
                if isinstance(item, Text):
                    content.append("  • ")
                    content.append(item)
                    content.append("\n")
                elif "[" in item and "]" in item:
                    # Rich markup (literal fallback on malformed markup)
                    item_text = _safe_markup_text(item)
                    content.append("  • ")
                    content.append(item_text)
                    content.append("\n")
                else:
                    content.append(f"  • {item}\n", style=f"dim {BRAND_COLORS['info']}")

        panel_renderable = Panel(
            content, border_style=BRAND_COLORS["info"], box=ROUNDED, padding=(0, 1)
        )
        console.print(panel_renderable)
        # Panels always get space after
        if spacing != "none":
            console.print()
    else:
        # Simple output: icon + message (Rich will handle markup)
        output = Text()
        output.append(icon_text)
        output.append(message_text)
        try:
            console.print(output)
        except Exception:
            raise

        # Handle spacing after if requested
        if spacing in ("after", "both"):
            console.print()

    _log_to_file(logging.INFO, _build_persisted_message(message, items))


def print_info_verbose(message: Union[str, Text], panel: bool = False, icon: str = "ℹ"):
    """Print verbose informational message (only if verbose or debug mode enabled).

    This function uses the logger directly, which will:
    - Always log to file (both global and workspace if active)
    - Conditionally show Rich output in console via RichHandler (if verbose/debug mode)
    - Uses RichHandler format (with "INFO" level indicator) to differentiate from normal print_info()

    Args:
        message: Message to display (supports Rich markup strings or Text objects)
        panel: Not used (kept for compatibility)
        icon: Not used (kept for compatibility)
    """
    import logging

    plain_text = _extract_plain_text(message)
    logger = _get_logger()

    # DIAGNOSTIC: Log telemetry handler status for debugging
    # COMMENTED: Not directly related to module re-execution tracking
    # Use print_info() directly (not logger) to ensure diagnostic is always visible
    # even if logger has issues
    # try:
    #     from .logging_config import _telemetry_console_handler, _console_handler
    #     has_telemetry_handler = _telemetry_console_handler is not None
    #     telemetry_handler_level = _telemetry_console_handler.level if _telemetry_console_handler else None
    #     logger_handlers_count = len(logger.handlers)
    #     logger_has_telemetry = any(
    #         h == _telemetry_console_handler for h in logger.handlers
    #     ) if _telemetry_console_handler else False
    #
    #     # Get handler types for debugging
    #     handler_types = [type(h).__name__ for h in logger.handlers]
    #
    #     # Print diagnostic info directly (bypasses logger to ensure visibility)
    #     diagnostic_msg = (
    #         f"[TELEMETRY_DIAG] print_info_verbose: "
    #         f"verbose_mode={_state._verbose_mode}, debug_mode={_state._debug_mode}, "
    #         f"has_telemetry_handler={has_telemetry_handler}, "
    #         f"telemetry_handler_level={telemetry_handler_level}, "
    #         f"logger_handlers_count={logger_handlers_count}, "
    #         f"logger_has_telemetry={logger_has_telemetry}, "
    #         f"handler_types={handler_types}, "
    #         f"console_handler_level={_console_handler.level if _console_handler else None}, "
    #         f"message_preview={plain_text[:50]}..."
    #     )
    #     # Use print_info() directly to ensure diagnostic is always visible
    #     print_info(diagnostic_msg)
    # except Exception:
    #     # Don't fail if diagnostic logging fails
    #     pass

    # When verbose/debug is disabled, do not emit anything to the console.
    # We still want these messages persisted to the log files.
    if not (_state._verbose_mode or _state._debug_mode):
        _diag_log(
            "print_info_verbose: suppressed to file-only "
            f"verbose={_state._verbose_mode}, debug={_state._debug_mode}"
        )
        try:
            from adscan_core import logging_config as _logging_config

            record = logger.makeRecord(
                logger.name,
                logging.INFO,
                "",
                0,
                plain_text,
                args=(),
                exc_info=None,
            )
            for handler in (
                getattr(_logging_config, "_file_handler", None),
                getattr(_logging_config, "_workspace_file_handler", None),
            ):
                if handler is None:
                    continue
                try:
                    handler.emit(record)
                except Exception:
                    continue
        except Exception:
            pass
        return

    # Verbose/debug enabled: send to logger so RichHandler renders to console + logs to file.
    _diag_log(
        "print_info_verbose: emitting to logger "
        f"verbose={_state._verbose_mode}, debug={_state._debug_mode}"
    )
    if isinstance(message, Text):
        logger.info(plain_text, stacklevel=2)
    else:
        logger.info(message, stacklevel=2)

    # DIAGNOSTIC: Verify telemetry handler is receiving messages
    # COMMENTED: Not directly related to module re-execution tracking
    # try:
    #     from .logging_config import _telemetry_console_handler, get_logger
    #     telemetry_console = _get_telemetry_console()
    #     fresh_logger = get_logger()
    #
    #     # Check handler state
    #     has_telemetry_handler = _telemetry_console_handler is not None
    #     handler_console_id = id(_telemetry_console_handler.console) if _telemetry_console_handler and _telemetry_console_handler.console else None
    #     telemetry_console_id = id(telemetry_console) if telemetry_console else None
    #     console_match = handler_console_id == telemetry_console_id
    #
    #     # Check if handler is in logger
    #     logger_has_telemetry = _telemetry_console_handler in fresh_logger.handlers if _telemetry_console_handler else False
    #
    #     # Check buffer length to see if handler is writing to it
    #     buffer_length = None
    #     if telemetry_console and hasattr(telemetry_console, 'file'):
    #         try:
    #             file_obj = telemetry_console.file
    #             if hasattr(file_obj, 'getvalue'):
    #                 buffer_length = len(file_obj.getvalue())
    #         except Exception:
    #             pass
    #
    #     print_info(
    #         f"[TELEMETRY_DIAG] After logger.info() call (verbose): "
    #         f"has_telemetry_handler={has_telemetry_handler}, "
    #         f"handler_console_id={handler_console_id}, "
    #         f"telemetry_console_id={telemetry_console_id}, "
    #         f"console_match={console_match}, "
    #         f"logger_has_telemetry={logger_has_telemetry}, "
    #         f"logger_handlers_count={len(fresh_logger.handlers)}, "
    #         f"buffer_length={buffer_length}"
    #     )
    # except Exception as e:
    #     print_info(f"[TELEMETRY_DIAG] Error checking telemetry handler state (verbose): {e}")
    #
    # # DIAGNOSTIC: Also try to send directly to telemetry console to verify it's working
    # try:
    #     telemetry_console = _get_telemetry_console()
    #     if telemetry_console is not None:
    #         # Try to send diagnostic message directly to telemetry console
    #         diagnostic_msg = f"[TELEMETRY_DIRECT] print_info_verbose: {plain_text[:50]}..."
    #         telemetry_console.print(diagnostic_msg)
    #     else:
    #         print_info("[TELEMETRY_DIAG] telemetry_console is None in print_info_verbose")
    # except Exception as e:
    #     print_info(f"[TELEMETRY_DIAG] Error sending to telemetry console (verbose): {e}")

    # FALLBACK: If RichHandler is not configured or not showing messages,
    # use logger-style format to ensure visibility and differentiation (this should not happen in normal operation)
    # This is a safety net in case the RichHandler level is not configured correctly
    try:
        from adscan_core.logging_config import _console_handler

        if _console_handler is None or _console_handler.level > logging.INFO:
            # RichHandler not configured or level too high, use logger-style format as fallback
            if _state._verbose_mode or _state._debug_mode:
                _print_logger_format_fallback("INFO", message, level_color="blue")
    except (ImportError, AttributeError):
        # logging_config not available or _console_handler not accessible, use logger-style format as fallback
        if _state._verbose_mode or _state._debug_mode:
            _print_logger_format_fallback("INFO", message, level_color="blue")


def print_info_debug(message: Union[str, Text], panel: bool = False, icon: str = "ℹ"):
    """Print debug informational message (only if debug mode enabled).

    This function uses the logger directly, which will:
    - Always log to file (both global and workspace if active)
    - Conditionally show Rich output in console via RichHandler (if debug mode)
    - Uses RichHandler format (with "DEBUG" level indicator) to differentiate from normal print_info()

    Args:
        message: Message to display (supports Rich markup strings or Text objects)
        panel: Not used (kept for compatibility)
        icon: Not used (kept for compatibility)
    """
    import logging

    plain_text = _extract_plain_text(message)
    logger = _get_logger()

    # DIAGNOSTIC: Log telemetry handler status for debugging
    # COMMENTED: Not directly related to module re-execution tracking
    # Use print_info() directly (not logger) to ensure diagnostic is always visible
    # even if logger has issues
    # try:
    #     from .logging_config import _telemetry_console_handler, _console_handler
    #     has_telemetry_handler = _telemetry_console_handler is not None
    #     telemetry_handler_level = _telemetry_console_handler.level if _telemetry_console_handler else None
    #     logger_handlers_count = len(logger.handlers)
    #     logger_has_telemetry = any(
    #         h == _telemetry_console_handler for h in logger.handlers
    #     ) if _telemetry_console_handler else False
    #
    #     # Get handler types for debugging
    #     handler_types = [type(h).__name__ for h in logger.handlers]
    #
    #     # Print diagnostic info directly (bypasses logger to ensure visibility)
    #     diagnostic_msg = (
    #         f"[TELEMETRY_DIAG] print_info_debug: "
    #         f"debug_mode={_state._debug_mode}, "
    #         f"has_telemetry_handler={has_telemetry_handler}, "
    #         f"telemetry_handler_level={telemetry_handler_level}, "
    #         f"logger_handlers_count={logger_handlers_count}, "
    #         f"logger_has_telemetry={logger_has_telemetry}, "
    #         f"handler_types={handler_types}, "
    #         f"console_handler_level={_console_handler.level if _console_handler else None}, "
    #         f"message_preview={plain_text[:50]}..."
    #     )
    #     # Use print_info() directly to ensure diagnostic is always visible
    #     print_info(diagnostic_msg)
    # except Exception:
    #     # Don't fail if diagnostic logging fails
    #     pass

    # Always send to logger - RichHandler will show it in console if debug mode is enabled
    # This gives the distinctive logger format (with "DEBUG" level) to differentiate from normal print_info()
    if isinstance(message, Text):
        logger.debug(plain_text, stacklevel=2)
    else:
        logger.debug(message, stacklevel=2)

    # DIAGNOSTIC: Verify telemetry handler is receiving messages
    # COMMENTED: Not directly related to module re-execution tracking
    # try:
    #     from .logging_config import _telemetry_console_handler, get_logger
    #     telemetry_console = _get_telemetry_console()
    #     fresh_logger = get_logger()
    #
    #     # Check handler state
    #     has_telemetry_handler = _telemetry_console_handler is not None
    #     handler_console_id = id(_telemetry_console_handler.console) if _telemetry_console_handler and _telemetry_console_handler.console else None
    #     telemetry_console_id = id(telemetry_console) if telemetry_console else None
    #     console_match = handler_console_id == telemetry_console_id
    #
    #     # Check if handler is in logger
    #     logger_has_telemetry = _telemetry_console_handler in fresh_logger.handlers if _telemetry_console_handler else False
    #
    #     # Check buffer length to see if handler is writing to it
    #     buffer_length = None
    #     if telemetry_console and hasattr(telemetry_console, 'file'):
    #         try:
    #             file_obj = telemetry_console.file
    #             if hasattr(file_obj, 'getvalue'):
    #                 buffer_length = len(file_obj.getvalue())
    #         except Exception:
    #             pass
    #
    #     print_info(
    #         f"[TELEMETRY_DIAG] After logger.debug() call: "
    #         f"has_telemetry_handler={has_telemetry_handler}, "
    #         f"handler_console_id={handler_console_id}, "
    #         f"telemetry_console_id={telemetry_console_id}, "
    #         f"console_match={console_match}, "
    #         f"logger_has_telemetry={logger_has_telemetry}, "
    #         f"logger_handlers_count={len(fresh_logger.handlers)}, "
    #         f"buffer_length={buffer_length}"
    #     )
    # except Exception as e:
    #     print_info(f"[TELEMETRY_DIAG] Error checking telemetry handler state: {e}")
    #
    # # DIAGNOSTIC: Also try to send directly to telemetry console to verify it's working
    # try:
    #     telemetry_console = _get_telemetry_console()
    #     if telemetry_console is not None:
    #         # Try to send diagnostic message directly to telemetry console
    #         diagnostic_msg = f"[TELEMETRY_DIRECT] print_info_debug: {plain_text[:50]}..."
    #         telemetry_console.print(diagnostic_msg)
    #     else:
    #         print_info("[TELEMETRY_DIAG] telemetry_console is None in print_info_debug")
    # except Exception as e:
    #     print_info(f"[TELEMETRY_DIAG] Error sending to telemetry console: {e}")

    # FALLBACK: If RichHandler is not configured or not showing messages,
    # use logger-style format to ensure visibility and differentiation (this should not happen in normal operation)
    # This is a safety net in case the RichHandler level is not configured correctly
    try:
        from adscan_core.logging_config import _console_handler

        if _console_handler is None or _console_handler.level > logging.DEBUG:
            # RichHandler not configured or level too high, use logger-style format as fallback
            if _state._debug_mode:
                _print_logger_format_fallback("DEBUG", message, level_color="cyan")
    except (ImportError, AttributeError):
        # logging_config not available or _console_handler not accessible, use logger-style format as fallback
        if _state._debug_mode:
            _print_logger_format_fallback("DEBUG", message, level_color="cyan")


def print_event_debug(message: Union[str, Text], panel: bool = False, icon: str = "◈"):
    """Print structured-event diagnostics with a dedicated debug channel.

    This uses the exact same debug/telemetry path as ``print_info_debug``:
    ``logger.debug`` for file logging + telemetry-aware handlers, plus the same
    DEBUG fallback behavior when the Rich console handler is unavailable. The
    only difference is UX: event diagnostics are prefixed distinctly so they
    stand out from general debug noise.

    Args:
        message: Message to display.
        panel: Kept for API symmetry; currently unused.
        icon: Optional event icon prefix for fallback rendering.
    """
    import logging

    plain_text = _extract_plain_text(message)
    logger = _get_logger()
    event_message = f"[events] {plain_text}"

    if isinstance(message, Text):
        logger.debug(event_message, stacklevel=2)
    else:
        logger.debug(event_message, stacklevel=2)

    try:
        from adscan_core.logging_config import _console_handler

        if _console_handler is None or _console_handler.level > logging.DEBUG:
            if _state._debug_mode:
                _print_logger_format_fallback(
                    "DEBUG",
                    f"{icon} [events] {plain_text}",
                    level_color="magenta",
                )
    except (ImportError, AttributeError):
        if _state._debug_mode:
            _print_logger_format_fallback(
                "DEBUG",
                f"{icon} [events] {plain_text}",
                level_color="magenta",
            )


def print_cypher_query(query: str) -> None:
    """Print a Cypher query in a clean, copy-paste-friendly format.

    - Always writes to log file for post-analysis.
    - In debug mode: prints directly to console (no DEBUG prefix, no source file,
      no syntax highlighting) so the query can be copy-pasted into BloodHound UI as-is.

    Args:
        query: Cypher query string, already normalized to a single line.
    """
    import logging

    plain_log = f"[bh-cypher] {query}"

    # Always persist to file handlers regardless of debug mode
    try:
        from adscan_core import logging_config as _logging_config

        _state._logger = _get_logger()
        record = _state._logger.makeRecord(
            _state._logger.name,
            logging.DEBUG,
            "",
            0,
            plain_log,
            args=(),
            exc_info=None,
        )
        for _handler in (
            getattr(_logging_config, "_file_handler", None),
            getattr(_logging_config, "_workspace_file_handler", None),
        ):
            if _handler is None:
                continue
            try:
                _handler.emit(record)
            except Exception:
                continue

        # In debug mode also capture to telemetry handler — mirrors print_info_debug
        # behaviour where logger.debug() triggers _telemetry_console_handler.
        if _state._debug_mode:
            _telemetry_handler = getattr(
                _logging_config, "_telemetry_console_handler", None
            )
            if _telemetry_handler is not None:
                try:
                    _telemetry_handler.emit(record)
                except Exception:
                    pass
    except Exception:
        pass

    # Show in console only in debug mode — bypass RichHandler for clean display
    if not _state._debug_mode:
        return

    from rich.text import Text as _Text

    console = _get_console()
    line = _Text("[bh-cypher] ", style="dim cyan")
    line.append(query, style="dim")
    console.print(line, highlight=False, soft_wrap=True)


def print_success(
    message: Union[str, Text],
    panel: bool = False,
    icon: str = "✓",
    items: Optional[List[Union[str, Text]]] = None,
    spacing: str = "auto",
):
    """Print a success message with optional panel and icon.

    Args:
        message: Message to display. Can be:
            - Plain string: "Operation completed"
            - Rich markup string: "[bold]Operation[/bold] [green]completed[/green]"
            - Text object: Text("Operation", style="bold")
        panel: If True, display in a panel with border
        icon: Icon to display (default: ✓)
        items: Optional list of items to display below message (supports same formats as message)
        spacing: Spacing control ("auto", "none", "before", "after", "both"). Default: "auto"
    """
    message = _translate_paths_for_display(message)
    items = _translate_items_for_display(items)

    console = _get_console()
    _get_telemetry_console()

    # Handle spacing
    spacing_before = _handle_spacing("success", panel, spacing)
    if spacing_before:
        console.print()

    # Format icon
    icon_text = Text(f"{icon} ", style="green")

    # Format message (preserves Rich markup or Text object)
    # SSOT markup rendering with literal fallback (see _safe_markup_text).
    message_text = _safe_markup_text(message, style="green")

    if panel:
        content = Text()
        content.append(icon_text)
        content.append(message_text)

        if items:
            content.append("\n\n", style="green")
            for item in items:
                if isinstance(item, Text):
                    content.append("  • ")
                    content.append(item)
                    content.append("\n")
                elif "[" in item and "]" in item:
                    # Rich markup (literal fallback on malformed markup)
                    item_text = _safe_markup_text(item)
                    content.append("  • ")
                    content.append(item_text)
                    content.append("\n")
                else:
                    content.append(f"  • {item}\n", style="dim green")

        panel_renderable = Panel(
            content, border_style="green", box=ROUNDED, padding=(0, 1)
        )
        console.print(panel_renderable)
        # Panels always get space after
        if spacing != "none":
            console.print()
    else:
        # Simple output: icon + message
        output = Text()
        output.append(icon_text)
        output.append(message_text)
        console.print(output)

        # Handle spacing after if requested
        if spacing in ("after", "both"):
            console.print()

    _log_to_file(logging.INFO, _build_persisted_message(message, items))


def print_success_verbose(
    message: Union[str, Text], panel: bool = False, icon: str = "✓"
):
    """Print verbose success message (only if verbose mode enabled).

    This function uses the logger directly, which will:
    - Always log to file (both global and workspace if active)
    - Conditionally show Rich output in console via RichHandler (if verbose mode)
    - Uses RichHandler format (with "INFO" level indicator) to differentiate from normal print_success()

    Args:
        message: Message to display (supports Rich markup strings or Text objects)
        panel: Not used (kept for compatibility)
        icon: Not used (kept for compatibility)
    """
    import logging

    plain_text = _extract_plain_text(message)
    logger = _get_logger()

    # When verbose/debug is disabled, do not emit anything to the console.
    # We still want these messages persisted to the log files.
    if not (_state._verbose_mode or _state._debug_mode):
        _diag_log(
            "print_success_verbose: suppressed to file-only "
            f"verbose={_state._verbose_mode}, debug={_state._debug_mode}"
        )
        try:
            from adscan_core import logging_config as _logging_config

            record = logger.makeRecord(
                logger.name,
                logging.INFO,
                "",
                0,
                plain_text,
                args=(),
                exc_info=None,
            )
            for handler in (
                getattr(_logging_config, "_file_handler", None),
                getattr(_logging_config, "_workspace_file_handler", None),
            ):
                if handler is None:
                    continue
                try:
                    handler.emit(record)
                except Exception:
                    continue
        except Exception:
            pass
        return

    # Verbose/debug enabled: send to logger so RichHandler renders to console + logs to file.
    _diag_log(
        "print_success_verbose: emitting to logger "
        f"verbose={_state._verbose_mode}, debug={_state._debug_mode}"
    )
    if isinstance(message, Text):
        logger.info(plain_text, stacklevel=2)
    else:
        logger.info(message, stacklevel=2)

    # FALLBACK: If RichHandler is not configured or not showing messages,
    # use logger-style format to ensure visibility and differentiation (this should not happen in normal operation)
    # This is a safety net in case the RichHandler level is not configured correctly
    try:
        from adscan_core.logging_config import _console_handler

        if _console_handler is None or _console_handler.level > logging.INFO:
            # RichHandler not configured or level too high, use logger-style format as fallback
            if _state._verbose_mode or _state._debug_mode:
                _print_logger_format_fallback("INFO", message, level_color="green")
    except (ImportError, AttributeError):
        # logging_config not available or _console_handler not accessible, use logger-style format as fallback
        if _state._verbose_mode or _state._debug_mode:
            _print_logger_format_fallback("INFO", message, level_color="green")


def print_success_debug(
    message: Union[str, Text], panel: bool = False, icon: str = "✓"
):
    """Print debug success message (only if debug mode enabled).

    This function uses the logger directly, which will:
    - Always log to file (both global and workspace if active)
    - Conditionally show Rich output in console via RichHandler (if debug mode)
    - Uses RichHandler format (with "DEBUG" level indicator) to differentiate from normal print_success()

    Args:
        message: Message to display (supports Rich markup strings or Text objects)
        panel: Not used (kept for compatibility)
        icon: Not used (kept for compatibility)
    """
    import logging

    plain_text = _extract_plain_text(message)
    logger = _get_logger()

    # Always send to logger - RichHandler will show it in console if debug mode is enabled
    # This gives the distinctive logger format (with "DEBUG" level) to differentiate from normal print_success()
    if isinstance(message, Text):
        logger.debug(plain_text, stacklevel=2)
    else:
        logger.debug(message, stacklevel=2)

    # FALLBACK: If RichHandler is not configured or not showing messages,
    # use logger-style format to ensure visibility and differentiation (this should not happen in normal operation)
    # This is a safety net in case the RichHandler level is not configured correctly
    try:
        from adscan_core.logging_config import _console_handler

        if _console_handler is None or _console_handler.level > logging.DEBUG:
            # RichHandler not configured or level too high, use logger-style format as fallback
            if _state._debug_mode:
                _print_logger_format_fallback("DEBUG", message, level_color="cyan")
    except (ImportError, AttributeError):
        # logging_config not available or _console_handler not accessible, use logger-style format as fallback
        if _state._debug_mode:
            _print_logger_format_fallback("DEBUG", message, level_color="cyan")


def print_success_tick(message: Union[str, Text], panel: bool = False):
    """Print success message with tick icon (alias for print_success with tick).

    Args:
        message: Message to display (supports Rich markup strings or Text objects)
        panel: If True, display in a panel with border
    """
    print_success(message, panel=panel, icon="✓")


def print_warning(
    message: Union[str, Text],
    panel: bool = False,
    icon: str = "⚠",
    items: Optional[List[Union[str, Text]]] = None,
    spacing: str = "auto",
):
    """Print a warning message with optional panel and icon.

    Args:
        message: Message to display. Can be:
            - Plain string: "Warning message"
            - Rich markup string: "[bold]Warning[/bold] [yellow]message[/yellow]"
            - Text object: Text("Warning", style="bold")
        panel: If True, display in a panel with border
        icon: Icon to display (default: ⚠)
        items: Optional list of items to display below message (supports same formats as message)
        spacing: Spacing control ("auto", "none", "before", "after", "both"). Default: "auto"
    """
    message = _translate_paths_for_display(message)
    items = _translate_items_for_display(items)

    console = _get_console()
    _get_telemetry_console()

    # Handle spacing
    spacing_before = _handle_spacing("warning", panel, spacing)
    if spacing_before:
        console.print()

    # Format icon
    icon_text = Text(f"{icon} ", style="yellow")

    # Format message (preserves Rich markup or Text object)
    # SSOT markup rendering with literal fallback (see _safe_markup_text).
    message_text = _safe_markup_text(message, style="yellow")

    if panel:
        content = Text()
        content.append(icon_text)
        content.append(message_text)

        if items:
            content.append("\n\n", style="yellow")
            for item in items:
                if isinstance(item, Text):
                    content.append("  • ")
                    content.append(item)
                    content.append("\n")
                elif "[" in item and "]" in item:
                    # Rich markup (literal fallback on malformed markup)
                    item_text = _safe_markup_text(item)
                    content.append("  • ")
                    content.append(item_text)
                    content.append("\n")
                else:
                    content.append(f"  • {item}\n", style="dim yellow")

        panel_renderable = Panel(
            content, border_style="yellow", box=ROUNDED, padding=(0, 1)
        )
        console.print(panel_renderable)
        # Panels always get space after
        if spacing != "none":
            console.print()
    else:
        # Simple output: icon + message
        output = Text()
        output.append(icon_text)
        output.append(message_text)
        console.print(output)

        # Handle spacing after if requested
        if spacing in ("after", "both"):
            console.print()

    _log_to_file(logging.WARNING, _build_persisted_message(message, items))


def print_warning_verbose(
    message: Union[str, Text], panel: bool = False, icon: str = "⚠"
):
    """Print verbose warning message (only if verbose mode enabled).

    This function uses the logger directly, which will:
    - Always log to file (both global and workspace if active)
    - Conditionally show Rich output in console via RichHandler (if verbose mode)
    - Uses RichHandler format (with "WARNING" level indicator) to differentiate from normal print_warning()

    Args:
        message: Message to display (supports Rich markup strings or Text objects)
        panel: Not used (kept for compatibility)
        icon: Not used (kept for compatibility)
    """
    import logging

    plain_text = _extract_plain_text(message)
    logger = _get_logger()

    # When verbose/debug is disabled, do not emit anything to the console.
    # We still want these messages persisted to the log files.
    if not (_state._verbose_mode or _state._debug_mode):
        try:
            from adscan_core import logging_config as _logging_config

            record = logger.makeRecord(
                logger.name,
                logging.WARNING,
                "",
                0,
                plain_text,
                args=(),
                exc_info=None,
            )
            for handler in (
                getattr(_logging_config, "_file_handler", None),
                getattr(_logging_config, "_workspace_file_handler", None),
            ):
                if handler is None:
                    continue
                try:
                    handler.emit(record)
                except Exception:
                    continue
        except Exception:
            pass
        return

    # Verbose/debug enabled: send to logger so RichHandler renders to console + logs to file.
    if isinstance(message, Text):
        logger.warning(plain_text, stacklevel=2)
    else:
        logger.warning(message, stacklevel=2)

    # FALLBACK: If RichHandler is not configured or not showing messages,
    # use logger-style format to ensure visibility and differentiation (this should not happen in normal operation)
    # This is a safety net in case the RichHandler level is not configured correctly
    try:
        from adscan_core.logging_config import _console_handler

        if _console_handler is None or _console_handler.level > logging.WARNING:
            # RichHandler not configured or level too high, use logger-style format as fallback
            if _state._verbose_mode or _state._debug_mode:
                _print_logger_format_fallback("WARNING", message, level_color="yellow")
    except (ImportError, AttributeError):
        # logging_config not available or _console_handler not accessible, use logger-style format as fallback
        if _state._verbose_mode or _state._debug_mode:
            _print_logger_format_fallback("WARNING", message, level_color="yellow")


def print_warning_debug(
    message: Union[str, Text], panel: bool = False, icon: str = "⚠"
):
    """Print debug warning message (only if debug mode enabled).

    This function uses the logger directly, which will:
    - Always log to file (both global and workspace if active)
    - Conditionally show Rich output in console via RichHandler (if debug mode)
    - Uses RichHandler format (with "DEBUG" level indicator) to differentiate from normal print_warning()

    Args:
        message: Message to display (supports Rich markup strings or Text objects)
        panel: Not used (kept for compatibility)
        icon: Not used (kept for compatibility)
    """
    import logging

    plain_text = _extract_plain_text(message)
    logger = _get_logger()

    # Always send to logger - RichHandler will show it in console if debug mode is enabled
    # This gives the distinctive logger format (with "DEBUG" level) to differentiate from normal print_warning()
    if isinstance(message, Text):
        logger.debug(plain_text, stacklevel=2)
    else:
        logger.debug(message, stacklevel=2)

    # FALLBACK: If RichHandler is not configured or not showing messages,
    # use logger-style format to ensure visibility and differentiation (this should not happen in normal operation)
    # This is a safety net in case the RichHandler level is not configured correctly
    try:
        from adscan_core.logging_config import _console_handler

        if _console_handler is None or _console_handler.level > logging.DEBUG:
            # RichHandler not configured or level too high, use logger-style format as fallback
            if _state._debug_mode:
                _print_logger_format_fallback("DEBUG", message, level_color="cyan")
    except (ImportError, AttributeError):
        # logging_config not available or _console_handler not accessible, use logger-style format as fallback
        if _state._debug_mode:
            _print_logger_format_fallback("DEBUG", message, level_color="cyan")


def print_error(
    message: Union[str, Text],
    panel: bool = False,
    icon: str = "✗",
    items: Optional[List[Union[str, Text]]] = None,
    spacing: str = "auto",
):
    """Print an error message with optional panel and icon.

    Args:
        message: Message to display. Can be:
            - Plain string: "Error occurred"
            - Rich markup string: "[bold]Error[/bold] [red]occurred[/red]"
            - Text object: Text("Error", style="bold")
        panel: If True, display in a panel with border
        icon: Icon to display (default: ✗)
        items: Optional list of items to display below message (supports same formats as message)
        spacing: Spacing control ("auto", "none", "before", "after", "both"). Default: "auto"
    """
    message = _translate_paths_for_display(message)
    items = _translate_items_for_display(items)

    console = _get_console()
    _get_telemetry_console()

    # Handle spacing
    spacing_before = _handle_spacing("error", panel, spacing)
    if spacing_before:
        console.print()

    # Format icon
    icon_text = Text(f"{icon} ", style="bold red")

    # Format message (preserves Rich markup or Text object)
    # SSOT markup rendering with literal fallback (see _safe_markup_text).
    message_text = _safe_markup_text(message, style="bold red")

    if panel:
        content = Text()
        content.append(icon_text)
        content.append(message_text)

        if items:
            content.append("\n\n", style="bold red")
            for item in items:
                if isinstance(item, Text):
                    content.append("  • ")
                    content.append(item)
                    content.append("\n")
                elif "[" in item and "]" in item:
                    # Rich markup (literal fallback on malformed markup)
                    item_text = _safe_markup_text(item)
                    content.append("  • ")
                    content.append(item_text)
                    content.append("\n")
                else:
                    content.append(f"  • {item}\n", style="dim red")

        panel_renderable = Panel(
            content, border_style="red", box=ROUNDED, padding=(0, 1)
        )
        console.print(panel_renderable)
        # Panels always get space after
        if spacing != "none":
            console.print()
    else:
        # Simple output: icon + message
        output = Text()
        output.append(icon_text)
        output.append(message_text)
        console.print(output)

        # Handle spacing after if requested
        if spacing in ("after", "both"):
            console.print()

    _log_to_file(logging.ERROR, _build_persisted_message(message, items))


def print_error_verbose(
    message: Union[str, Text], panel: bool = False, icon: str = "✗"
):
    """Print verbose error message (only if verbose or debug mode enabled).

    This function uses the logger directly, which will:
    - Always log to file (both global and workspace if active)
    - Conditionally show Rich output in console via RichHandler (if verbose/debug mode)
    - Uses RichHandler format (with "ERROR" level indicator) to differentiate from normal print_error()

    Args:
        message: Message to display (supports Rich markup strings or Text objects)
        panel: Not used (kept for compatibility)
        icon: Not used (kept for compatibility)
    """
    import logging

    plain_text = _extract_plain_text(message)
    logger = _get_logger()

    # When verbose/debug is disabled, do not emit anything to the console.
    # We still want these messages persisted to the log files.
    if not (_state._verbose_mode or _state._debug_mode):
        try:
            from adscan_core import logging_config as _logging_config

            record = logger.makeRecord(
                logger.name,
                logging.ERROR,
                "",
                0,
                plain_text,
                args=(),
                exc_info=None,
            )
            for handler in (
                getattr(_logging_config, "_file_handler", None),
                getattr(_logging_config, "_workspace_file_handler", None),
            ):
                if handler is None:
                    continue
                try:
                    handler.emit(record)
                except Exception:
                    continue
        except Exception:
            pass
        return

    # Verbose/debug enabled: send to logger so RichHandler renders to console + logs to file.
    if isinstance(message, Text):
        logger.error(plain_text, stacklevel=2)
    else:
        logger.error(message, stacklevel=2)

    # FALLBACK: If RichHandler is not configured or not showing messages,
    # use logger-style format to ensure visibility and differentiation (this should not happen in normal operation)
    # This is a safety net in case the RichHandler level is not configured correctly
    try:
        from adscan_core.logging_config import _console_handler

        if _console_handler is None or _console_handler.level > logging.ERROR:
            # RichHandler not configured or level too high, use logger-style format as fallback
            if _state._verbose_mode or _state._debug_mode:
                _print_logger_format_fallback("ERROR", message, level_color="red")
    except (ImportError, AttributeError):
        # logging_config not available or _console_handler not accessible, use logger-style format as fallback
        if _state._verbose_mode or _state._debug_mode:
            _print_logger_format_fallback("ERROR", message, level_color="red")


def print_error_debug(message: Union[str, Text], panel: bool = False, icon: str = "✗"):
    """Print debug error message (only if debug mode enabled).

    This function uses the logger directly, which will:
    - Always log to file (both global and workspace if active)
    - Conditionally show Rich output in console via RichHandler (if debug mode)
    - Uses RichHandler format (with "DEBUG" level indicator) to differentiate from normal print_error()

    Args:
        message: Message to display (supports Rich markup strings or Text objects)
        panel: Not used (kept for compatibility)
        icon: Not used (kept for compatibility)
    """
    import logging

    plain_text = _extract_plain_text(message)
    logger = _get_logger()

    # Always send to logger - RichHandler will show it in console if debug mode is enabled
    # This gives the distinctive logger format (with "DEBUG" level) to differentiate from normal print_error()
    if isinstance(message, Text):
        logger.debug(plain_text, stacklevel=2)
    else:
        logger.debug(message, stacklevel=2)

    # FALLBACK: If RichHandler is not configured or not showing messages,
    # use logger-style format to ensure visibility and differentiation (this should not happen in normal operation)
    # This is a safety net in case the RichHandler level is not configured correctly
    try:
        from adscan_core.logging_config import _console_handler

        if _console_handler is None or _console_handler.level > logging.DEBUG:
            # RichHandler not configured or level too high, use logger-style format as fallback
            if _state._debug_mode:
                _print_logger_format_fallback("DEBUG", message, level_color="cyan")
    except (ImportError, AttributeError):
        # logging_config not available or _console_handler not accessible, use logger-style format as fallback
        if _state._debug_mode:
            _print_logger_format_fallback("DEBUG", message, level_color="cyan")


def _format_exception_context(context: Optional[Dict[str, Any]]) -> str:
    """Format optional exception context for file-only diagnostics."""
    context_items = []
    for key, value in dict(context or {}).items():
        context_items.append(f"{key}={value}")
    return " ".join(context_items)


# ---------------------------------------------------------------------------
# Diagnostic context provider (pluggable hook for global observability)
# ---------------------------------------------------------------------------
#
# Higher-level layers (the CLI command dispatcher, the REPL shell, the CI
# orchestrator) can register a zero-argument callable here. When an exception
# is logged via ``print_exception`` and the caller did not supply its own
# ``context`` dict, the registered provider is consulted to attach the active
# workspace / domain snapshot to the file log.
#
# The provider returns a dict (already mark_sensitive-applied where needed)
# that gets formatted alongside the exception. This turns every exception
# trace into a self-contained diagnostic — operator does not have to ask the
# user "what was the active domain at that moment?" because it is already in
# the trace context.
#
# The hook is intentionally pluggable rather than a hard import: ``_log.py``
# lives at the bottom of the layer stack and must not import shell / CLI
# code. The CLI registers itself by calling ``register_exception_context_provider``
# during startup; if nothing registers, the previous behaviour (empty context)
# applies.

_exception_context_provider: Optional[Any] = None


def register_exception_context_provider(provider: Optional[Any]) -> None:
    """Install (or clear) a callable that returns diagnostic context.

    The provider is called by :func:`_log_exception_to_file` when the caller
    did not supply an explicit ``context`` dict. The callable must:

    * Accept no arguments.
    * Return ``None`` or a ``dict`` whose values are already safe for the
      file log (sensitive values pre-masked with ``mark_sensitive``).
    * Never raise — any exception is swallowed and the file log proceeds
      without the context.

    Pass ``None`` to clear the provider (returns to no-context behaviour).
    """
    global _exception_context_provider
    _exception_context_provider = provider


def _resolve_default_exception_context() -> Optional[Dict[str, Any]]:
    """Pull the diagnostic context from the registered provider, if any.

    Defensive: any error in the provider is swallowed so that exception
    logging never fails because the diagnostic plumbing failed.
    """
    provider = _exception_context_provider
    if provider is None:
        return None
    try:
        result = provider()
    except Exception:
        return None
    if isinstance(result, dict):
        return result
    return None


def _log_exception_to_file(
    *,
    message: str,
    exception: Optional[BaseException] = None,
    context: Optional[Dict[str, Any]] = None,
) -> None:
    """Persist one exception traceback without changing user-facing output."""
    import logging

    plain_text = str(message or "Unhandled exception").strip() or "Unhandled exception"

    # Fall back to the registered diagnostic context provider when the caller
    # did not supply explicit context. This is how every print_exception
    # called from deep services / async stacks inherits the active workspace
    # + domain snapshot for free — the CLI command hook registers a provider
    # on startup and every traceback that hits this codepath carries the
    # workspace state with it.
    effective_context = context
    if not effective_context:
        effective_context = _resolve_default_exception_context()

    context_text = _format_exception_context(effective_context)
    if context_text:
        plain_text = f"{plain_text}: {context_text}"

    if exception is not None:
        exc_info: object = (type(exception), exception, exception.__traceback__)
    else:
        active_exc = sys.exc_info()
        exc_info = active_exc if active_exc[0] is not None else None

    logger = _get_logger()
    try:
        from adscan_core import logging_config as _logging_config

        record = logger.makeRecord(
            logger.name,
            logging.ERROR,
            "",
            0,
            plain_text,
            args=(),
            exc_info=exc_info,
        )
        emitted = False
        for handler in (
            getattr(_logging_config, "_file_handler", None),
            getattr(_logging_config, "_workspace_file_handler", None),
        ):
            if handler is None:
                continue
            try:
                handler.emit(record)
                emitted = True
            except Exception:
                continue
        if emitted:
            return
    except Exception:
        pass

    logger.error(plain_text, exc_info=exc_info, stacklevel=3)


def log_exception_debug(
    message: str,
    *,
    exception: Optional[BaseException] = None,
    context: Optional[Dict[str, Any]] = None,
) -> None:
    """Log handled exception diagnostics through the debug/telemetry pipeline.

    This helper is for handled/retryable failures where showing a user-facing
    error would be misleading, but the traceback still needs to land in ADscan
    debug output, telemetry recordings, and the configured log files.

    Args:
        message: Short diagnostic message for the log record.
        exception: Optional exception object to persist with traceback.
        context: Optional key/value diagnostics. Sensitive values should already
            be wrapped with ``mark_sensitive``.
    """
    import logging

    plain_text = str(message or "Handled exception").strip() or "Handled exception"
    context_text = _format_exception_context(context)
    if context_text:
        plain_text = f"{plain_text}: {context_text}"

    if exception is not None:
        exc_info: object = (type(exception), exception, exception.__traceback__)
    else:
        active_exc = sys.exc_info()
        exc_info = active_exc if active_exc[0] is not None else None

    logger = _get_logger()
    logger.debug(plain_text, exc_info=exc_info, stacklevel=2)

    try:
        from adscan_core.logging_config import _console_handler

        if _console_handler is None or _console_handler.level > logging.DEBUG:
            if _state._debug_mode:
                _print_logger_format_fallback("DEBUG", plain_text, level_color="cyan")
    except (ImportError, AttributeError):
        if _state._debug_mode:
            _print_logger_format_fallback("DEBUG", plain_text, level_color="cyan")


def print_exception(
    show_locals: bool = False,
    exception: Optional[Exception] = None,
    *,
    context: Optional[Dict[str, Any]] = None,
):
    """Print exception traceback with Rich formatting.

    **IMPORTANT**: Tracebacks are only shown when `SECRET_MODE = True` to protect
    internal implementation details. When `SECRET_MODE = False`, only a generic
    error message is displayed to end users. Full traceback details are still
    persisted to ADscan log files through the centralized Rich logging pipeline.

    Args:
        show_locals: If True, show local variables in traceback (default: False)
        exception: Optional exception object to extract message from. If None, uses
            the current exception context (must be called within except block).
        context: Optional key/value diagnostics for the file log. Values should
            already be wrapped with ``mark_sensitive`` when sensitive.

    Examples:
        try:
            risky_operation()
        except Exception as e:
            # In SECRET_MODE: shows full traceback
            # In normal mode: shows generic error message
            print_exception(show_locals=True, exception=e)
    """
    _log_exception_to_file(
        message="Exception rendered via print_exception",
        exception=exception,
        context=context,
    )
    console = _get_console()
    telemetry_console = _get_telemetry_console()

    # Only show full tracebacks in SECRET_MODE (protects internal structure)
    if _state._secret_mode:
        # Rich's Console.print_exception() requires an active exception context.
        # When an exception object is provided (e.g. raised elsewhere and stored),
        # render it explicitly to avoid ValueError: "Value for 'trace' required...".
        if exception is not None:
            from rich.traceback import Traceback

            traceback_renderable = Traceback.from_exception(
                type(exception),
                exception,
                exception.__traceback__,
                show_locals=show_locals,
            )
            console.print(traceback_renderable)
        else:
            console.print_exception(show_locals=show_locals)
            if telemetry_console is not None:
                telemetry_console.print_exception(show_locals=show_locals)
    else:
        # Generic error message for end users (no internal details)
        # Never show tracebacks, file paths, or internal structure
        if exception:
            error_type = type(exception).__name__
            error_msg = str(exception)

            # Sanitize: remove all internal details
            import re

            # Remove file paths and line numbers (multiple patterns)
            clean_msg = re.sub(r'File "[^"]+", line \d+', "", error_msg)
            clean_msg = re.sub(r'File "[^"]+"', "", clean_msg)
            clean_msg = re.sub(r", line \d+", "", clean_msg)
            # Remove absolute paths
            clean_msg = re.sub(r"/[^\s:]+", "[path hidden]", clean_msg)
            # Remove relative paths
            clean_msg = re.sub(r"[./][^\s:]+\.py", "[file hidden]", clean_msg)
            # Remove stack trace indicators
            clean_msg = re.sub(r"Traceback \(most recent call last\):", "", clean_msg)
            clean_msg = re.sub(r"^\s+File.*$", "", clean_msg, flags=re.MULTILINE)
            # Remove any remaining path-like patterns
            clean_msg = re.sub(r"/[a-zA-Z0-9_/.-]+", "[path hidden]", clean_msg)

            # Extract just the first line (usually the actual error message)
            clean_msg = clean_msg.split("\n")[0].strip()

            # Remove any remaining technical details
            if (
                "File" in clean_msg
                or "line" in clean_msg
                or "/home" in clean_msg
                or "/usr" in clean_msg
            ):
                # Still contains technical details, use generic message
                print_error(
                    f"An error occurred ({error_type}). Please try again or contact support."
                )
            elif not clean_msg or len(clean_msg) > 200:
                # Message is empty or too long, use generic message
                print_error(
                    f"An error occurred ({error_type}). Please try again or contact support."
                )
            else:
                # Show sanitized error message
                # Use a Text object to avoid Rich markup parsing of bracketed placeholders
                # like "[path hidden]" or "[PATH]" in sanitized messages.
                print_error(Text(f"Error: {clean_msg}", style="bold red"))
        else:
            # No exception object provided, show generic message
            print_error(
                "An unexpected error occurred. Please try again or contact support."
            )


def print_untrusted_command_output(
    text_or_renderable: Any,
    *,
    line_count: Optional[int] = None,
) -> None:
    """Show arbitrary external-command output on screen, keep it OUT of telemetry.

    Output produced by a user-initiated external command — ``cat``-ing an
    engagement file, a ``system <cmd>`` shell passthrough — may contain
    unredactable client data (file contents, raw username lists, anything the
    operator chose to display). The telemetry sanitizer pattern-matches known
    sensitive shapes (``mark_sensitive`` tokens, domains, IPs, hashes); it
    CANNOT know what arbitrary file/command content is, so recording it
    verbatim leaks client data into the session recording (a real audit
    captured 75 client AD usernames from ``cat users.txt``).

    This helper renders the output to the VISIBLE console with the
    :class:`~adscan_core.output._state._TeeConsole` auto-mirror DISABLED, so
    the operator still sees the full cleartext output, and records a privacy
    PLACEHOLDER to telemetry instead of the raw content. The recording still
    shows that the command produced output (and the masked command echo is
    recorded separately), without exposing the content itself.

    This is the SANCTIONED exception to the "do not use
    ``_explicit_telemetry_mirror`` from new code" rule — a deliberate privacy
    carve-out for untrusted external-command output, not a convenience bypass.
    Do NOT route ADscan's own structured/tool output through this helper:
    that output is sanitized per-token via ``mark_sensitive`` and SHOULD be
    recorded.

    Args:
        text_or_renderable: The command's stdout (or any Rich renderable) to
            display to the operator.
        line_count: Optional explicit line count for the placeholder. When
            omitted and the argument is a string, it is counted automatically.
    """
    console = _get_console()
    telemetry_console = _get_telemetry_console()

    if line_count is None and isinstance(text_or_renderable, str):
        # Count non-empty trailing newline gracefully: "a\nb\n" -> 2 lines.
        stripped = text_or_renderable.rstrip("\n")
        line_count = stripped.count("\n") + 1 if stripped else 0

    # Render the cleartext to the operator's terminal WITHOUT auto-mirroring
    # it into the telemetry recording.
    with _state._explicit_telemetry_mirror():
        console.print(text_or_renderable)

    # Record a privacy placeholder so the recording shows output was produced
    # without exposing the (potentially client-sensitive) content.
    if telemetry_console is not None:
        if line_count is not None:
            plural = "s" if line_count != 1 else ""
            placeholder = (
                f"<external command output omitted from recording for privacy "
                f"— {line_count} line{plural}>"
            )
        else:
            placeholder = (
                "<external command output omitted from recording for privacy>"
            )
        try:
            telemetry_console.print(placeholder)
        except Exception:  # noqa: BLE001 — never break the visible flow on telemetry
            pass


__all__ = [
    "BRAND_COLORS",
    "print_info",
    "print_info_verbose",
    "print_info_debug",
    "print_success",
    "print_success_verbose",
    "print_success_debug",
    "print_success_tick",
    "print_warning",
    "print_warning_verbose",
    "print_warning_debug",
    "print_error",
    "print_error_verbose",
    "print_error_debug",
    "print_telemetry_only",
    "print_untrusted_command_output",
    "print_event_debug",
    "print_cypher_query",
    "print_exception",
    "log_exception_debug",
    "reset_spacing",
]
