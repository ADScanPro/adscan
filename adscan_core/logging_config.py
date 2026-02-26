"""Logging configuration for ADscan.

This module provides centralized logging configuration that integrates with Rich
for console output and file-based logging for persistence. All logs are written
to files regardless of verbose/debug mode, while console output is controlled
by verbose/debug flags.
"""

import logging
from logging.handlers import RotatingFileHandler
import os
import sys
from pathlib import Path
import subprocess
import shutil
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler

from adscan_core.path_utils import expand_effective_user_path, get_adscan_home


# Global logger instance (initialized by init_logging)
_logger: Optional[logging.Logger] = None
_console_handler: Optional[RichHandler] = None
_file_handler: Optional[RotatingFileHandler] = None
_workspace_file_handler: Optional[RotatingFileHandler] = None
_telemetry_console_handler: Optional[RichHandler] = None


def _diag_enabled() -> bool:
    return os.getenv("ADSCAN_DIAG_LOGGING", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }


def _diag_log(message: str) -> None:
    if _diag_enabled():
        print(f"[DIAG][logging_config] {message}", file=sys.stderr)


def _try_fix_log_dir_permissions(console: Console, log_dir: Path) -> bool:
    """Attempt to repair permissions for the ADscan log directory using sudo.

    This targets the common case where a legacy `sudo -E` alias created
    `~/.adscan` as root, causing non-root runs (including `--version`) to crash
    at import-time when the file logger initializes.

    The fix is intentionally conservative:
    - Only tries when running as a non-root user.
    - Only tries when the target is under the current user's home directory.
    - Only runs once, and never raises.

    Args:
        console: Rich console for user-facing output.
        log_dir: Intended log directory (e.g., ~/.adscan/logs).

    Returns:
        True if a repair command was attempted and returned success.
    """
    if os.geteuid() == 0:
        return False

    if os.getenv("CI"):
        return False

    if not shutil.which("sudo"):
        return False

    try:
        resolved_log_dir = log_dir.expanduser().resolve()
        resolved_home = Path.home().resolve()
        if os.path.commonpath([str(resolved_home), str(resolved_log_dir)]) != str(
            resolved_home
        ):
            return False

        # Prefer fixing the whole ~/.adscan tree when we're dealing with the standard layout.
        target = (
            resolved_log_dir.parent
            if resolved_log_dir.name == "logs"
            else resolved_log_dir
        )

        console.print(
            "[yellow]⚠ ADscan cannot write to its log directory due to permissions. "
            "Attempting to repair ownership with sudo...[/yellow]"
        )
        console.print(
            "[dim]This usually happens if ADscan was previously run via a legacy sudo alias.[/dim]"
        )

        user = os.getenv("SUDO_USER") or os.getenv("USER") or str(os.getuid())
        cmd = ["sudo", "chown", "-R", f"{user}:{user}", str(target)]
        result = subprocess.run(cmd, check=False)
        return result.returncode == 0
    except Exception:
        return False


def init_logging(
    console: Console,
    verbose_mode: bool = False,
    debug_mode: bool = False,
    secret_mode: bool = False,
    log_dir: Optional[Path] = None,
    workspace_dir: Optional[Path] = None,
    telemetry_console: Optional[Console] = None,
) -> logging.Logger:
    """Initialize logging system with file and console handlers.

    Args:
        console: Rich Console instance for console output
        verbose_mode: Enable verbose console output
        debug_mode: Enable debug console output
        secret_mode: Enable secret mode (show paths in tracebacks)
        log_dir: Directory for log files (defaults to ~/.adscan/logs)
        workspace_dir: Optional workspace directory for workspace-specific logs

    Returns:
        Configured logger instance
    """
    global _logger, _console_handler, _file_handler, _workspace_file_handler
    global _telemetry_console_handler

    # CRITICAL: Preserve active verbose/debug modes from rich_output if they're already active
    # This prevents losing debug/verbose mode when module re-executes (e.g., PyInstaller)
    # and init_logging is called with default False values
    try:
        from adscan_core import rich_output

        # If rich_output has active modes, use those instead of the parameters
        # (which may be False due to module re-execution)
        if hasattr(rich_output, "_verbose_mode") and rich_output._verbose_mode:
            verbose_mode = True
        if hasattr(rich_output, "_debug_mode") and rich_output._debug_mode:
            debug_mode = True
    except Exception:
        pass  # Don't fail if we can't check rich_output state

    # DIAGNOSTIC: Log when init_logging is called
    # DIAGNOSTIC: Only log when module re-executes (when handler already exists)
    # This helps track module re-initialization issues
    is_reinitialization = (
        _telemetry_console_handler is not None or _console_handler is not None
    )
    try:
        if is_reinitialization:
            # from adscan_internal.rich_output import print_info
            # print_info(
            #     f"[TELEMETRY_DIAG] init_logging called (RE-INITIALIZATION): "
            #     f"verbose_mode_param={verbose_mode}, debug_mode_param={debug_mode}, "
            #     f"has_console={console is not None}, "
            #     f"has_telemetry_console={telemetry_console is not None}, "
            #     f"telemetry_console_id={id(telemetry_console) if telemetry_console else None}, "
            #     f"existing_telemetry_handler_id={id(_telemetry_console_handler) if _telemetry_console_handler else None}"
            # )
            pass
    except Exception:
        pass  # Don't fail if diagnostic logging fails

    # Create log directory (best-effort). If ~/.adscan is not writable (e.g., it
    # was created earlier under sudo), fall back to a user-writable location so
    # even `adscan --version` won't crash at import time.
    if log_dir is None:
        adscan_home = os.getenv("ADSCAN_HOME")
        if adscan_home:
            log_dir = Path(expand_effective_user_path(adscan_home)) / "logs"
        else:
            log_dir = get_adscan_home() / "logs"

    requested_log_dir = log_dir
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        repaired = _try_fix_log_dir_permissions(console, log_dir)
        if repaired:
            try:
                log_dir.mkdir(parents=True, exist_ok=True)
            except PermissionError:
                log_dir = None
        else:
            log_dir = None

    # Create logger
    logger = logging.getLogger("adscan")
    logger.setLevel(logging.DEBUG)  # Always capture all levels to file

    # CRITICAL: Preserve existing handlers BEFORE clearing handlers
    # This prevents losing debug/verbose mode and telemetry during module re-execution (e.g., PyInstaller).
    preserved_console_level = None
    if _console_handler is not None:
        existing_level = _console_handler.level
        if existing_level <= logging.INFO:  # DEBUG (10) or INFO (20)
            # Existing handler has better level, preserve it even if reinitializing with worse values
            preserved_console_level = existing_level

    # Preserve existing telemetry handler if it exists, but only if console hasn't changed
    # This prevents losing telemetry capture when module re-executes, but ensures
    # we create a new handler if the console changed (new buffer)
    preserved_telemetry_handler = None
    old_console_id = None
    new_console_id = None

    # DIAGNOSTIC: Log telemetry handler preservation logic (only on re-initialization)
    try:
        if is_reinitialization and _telemetry_console_handler is not None:
            # from adscan_internal.rich_output import print_info
            old_console_id = (
                id(_telemetry_console_handler.console)
                if _telemetry_console_handler.console
                else None
            )
            new_console_id = id(telemetry_console) if telemetry_console else None
            _console_changed = old_console_id != new_console_id
            # print_info(
            #     f"[TELEMETRY_DIAG] init_logging telemetry handler check: "
            #     f"has_preserved_handler={_telemetry_console_handler is not None}, "
            #     f"has_new_console={telemetry_console is not None}, "
            #     f"old_console_id={old_console_id}, new_console_id={new_console_id}, "
            #     f"console_changed={console_changed}"
            # )
            pass
    except Exception:
        pass  # Don't fail if diagnostic logging fails

    if _telemetry_console_handler is not None:
        # Only preserve if no new console is provided OR if the console is the same
        # If a new console is provided, we need a new handler to use the new buffer
        if (
            telemetry_console is None
            or _telemetry_console_handler.console is telemetry_console
        ):
            preserved_telemetry_handler = _telemetry_console_handler
            try:
                if is_reinitialization:
                    _diag_log(
                        "Preserving telemetry handler (console unchanged): "
                        f"handler_id={id(_telemetry_console_handler)}, console_id={old_console_id}"
                    )
            except Exception:
                pass

    # Remove existing handlers to avoid duplicates
    logger.handlers.clear()

    # Global file handler (always active, INFO+ by default) - best-effort.
    file_handler: RotatingFileHandler | None = None
    if log_dir is not None:
        try:
            log_file = log_dir / "adscan.log"
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=10 * 1024 * 1024,  # 10 MB
                backupCount=5,
                encoding="utf-8",
            )
            # Default to INFO+ in files so DEBUG-level internals are not written
            # unless the user explicitly enables debug mode. Telemetry handlers
            # still receive DEBUG in all modes.
            file_handler.setLevel(logging.INFO)
            file_handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )
            )
            logger.addHandler(file_handler)
        except PermissionError:
            file_handler = None
        except Exception:
            file_handler = None
    _file_handler = file_handler

    # Workspace-specific file handler (if workspace_dir is provided)
    if workspace_dir:
        try:
            workspace_log_dir = Path(workspace_dir) / "logs"
            workspace_log_dir.mkdir(parents=True, exist_ok=True)
            workspace_log_file = workspace_log_dir / "adscan.log"
            workspace_file_handler = RotatingFileHandler(
                workspace_log_file,
                maxBytes=10 * 1024 * 1024,  # 10 MB
                backupCount=5,
                encoding="utf-8",
            )
            # Same policy as the global file handler: INFO+ by default.
            workspace_file_handler.setLevel(logging.INFO)
            workspace_file_handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )
            )
            logger.addHandler(workspace_file_handler)
            _workspace_file_handler = workspace_file_handler
        except PermissionError:
            _workspace_file_handler = None
        except Exception:
            _workspace_file_handler = None
    else:
        _workspace_file_handler = None

    # Console handler (Rich, conditional based on verbose/debug mode)
    console_handler = RichHandler(
        rich_tracebacks=True,
        show_path=bool(debug_mode or secret_mode),
        console=console,
        show_time=False,  # Rich handles time visually
        markup=True,  # Support Rich markup in log messages
    )

    # Set console level based on mode
    # CRITICAL: If we preserved a better level from existing handler, use it.
    # Otherwise, set based on mode flags. This prevents losing debug/verbose mode
    # during module re-execution (e.g., PyInstaller).
    if preserved_console_level is not None:
        # Preserve existing console handler level (don't downgrade to ERROR)
        console_handler.setLevel(preserved_console_level)
        _diag_log(f"Console handler level preserved: level={console_handler.level}")
    elif debug_mode:
        console_handler.setLevel(logging.DEBUG)
        _diag_log("Console handler level set to DEBUG")
    elif verbose_mode:
        console_handler.setLevel(logging.INFO)
        _diag_log("Console handler level set to INFO")
    else:
        # Only show errors and critical in console when not verbose/debug
        console_handler.setLevel(logging.ERROR)
        _diag_log("Console handler level set to ERROR")

    # DIAGNOSTIC: Log console handler level setup (write directly to file handler)
    # COMMENTED: Not directly related to module re-execution tracking
    # try:
    #     if _file_handler is not None:
    #         preserved_info = ""
    #         if preserved_console_level is not None:
    #             preserved_info = f", preserved_level={preserved_console_level} (preserved from existing handler)"
    #         diagnostic_msg = (
    #             f"[LOGGING_DIAG] init_logging console handler setup: "
    #             f"verbose_mode={verbose_mode}, debug_mode={debug_mode}, "
    #             f"console_handler_level={console_handler.level} (DEBUG=10, INFO=20, ERROR=40)"
    #             f"{preserved_info}"
    #         )
    #         _file_handler.emit(logging.LogRecord(
    #             name="adscan.diagnostic",
    #             level=logging.DEBUG,
    #             pathname="",
    #             lineno=0,
    #             msg=diagnostic_msg,
    #             args=(),
    #             exc_info=None
    #         ))
    # except Exception:
    #     pass  # Don't fail if diagnostic logging fails

    logger.addHandler(console_handler)
    _console_handler = console_handler

    # Telemetry console handler (optional, always DEBUG level)
    # Mirrors all log records to an in-memory Rich console used only for
    # session recordings (Vercel/n8n). This handler never writes to disk
    # and does not affect what the user sees in the terminal.
    # CRITICAL: If a new telemetry_console is provided, always create a new handler
    # to ensure it uses the current TELEMETRY_CONSOLE buffer. The preserved handler
    # may have references to the old console/buffer that don't update correctly.
    # Creating a new handler ensures clean state and proper buffer association.
    if telemetry_console is not None:
        # Always create a new handler when a new telemetry_console is provided
        # This ensures the handler uses the current buffer, not an old one
        # Even if a preserved handler exists, create new to avoid buffer mismatch
        try:
            if is_reinitialization:
                # from adscan_internal.rich_output import print_info
                # print_info(
                #     f"[TELEMETRY_DIAG] Creating NEW telemetry handler: "
                #     f"new_console_id={id(telemetry_console)}, "
                #     f"had_preserved_handler={preserved_telemetry_handler is not None}, "
                #     f"preserved_handler_id={id(preserved_telemetry_handler) if preserved_telemetry_handler else None}"
                # )
                pass
        except Exception:
            pass

        # CRITICAL: Preserve buffer content from old handler before creating new one
        # This ensures all previous messages are not lost when module re-executes
        old_buffer_content = None
        if (
            preserved_telemetry_handler is not None
            and preserved_telemetry_handler.console is not None
        ):
            try:
                old_console = preserved_telemetry_handler.console
                if hasattr(old_console, "file") and hasattr(
                    old_console.file, "getvalue"
                ):
                    old_buffer_content = old_console.file.getvalue()
                    try:
                        if is_reinitialization:
                            # from adscan_internal.rich_output import print_info
                            # print_info(
                            #     f"[TELEMETRY_DIAG] Preserving old buffer content: "
                            #     f"old_buffer_length={len(old_buffer_content)}, "
                            #     f"old_console_id={id(old_console)}"
                            # )
                            pass
                    except Exception:
                        pass
            except Exception:
                try:
                    # from adscan_internal.rich_output import print_info
                    # print_info(f"[TELEMETRY_DIAG] Error preserving old buffer: {e}")
                    pass
                except Exception:
                    pass

        telemetry_handler = RichHandler(
            rich_tracebacks=True,
            show_path=False,
            console=telemetry_console,
            show_time=False,
            markup=True,
        )
        telemetry_handler.setLevel(logging.DEBUG)
        logger.addHandler(telemetry_handler)
        _telemetry_console_handler = telemetry_handler

        # CRITICAL: Restore old buffer content to new console if we preserved it
        if (
            old_buffer_content
            and telemetry_console is not None
            and hasattr(telemetry_console, "file")
        ):
            try:
                new_buffer = telemetry_console.file
                if hasattr(new_buffer, "write"):
                    # Write old content to new buffer
                    new_buffer.write(old_buffer_content)
                    try:
                        if is_reinitialization:
                            # from adscan_internal.rich_output import print_info
                            # print_info(
                            #     f"[TELEMETRY_DIAG] Restored old buffer content to new console: "
                            #     f"old_content_length={len(old_buffer_content)}, "
                            #     f"new_buffer_length={len(new_buffer.getvalue()) if hasattr(new_buffer, 'getvalue') else 'unknown'}"
                            # )
                            pass
                    except Exception:
                        pass
            except Exception:
                try:
                    # from adscan_internal.rich_output import print_info
                    # print_info(f"[TELEMETRY_DIAG] Error restoring old buffer: {e}")
                    pass
                except Exception:
                    pass

        try:
            # from adscan_internal.rich_output import print_info
            # Verify handler was added correctly
            _handler_in_logger = telemetry_handler in logger.handlers
            handler_console_id = (
                id(telemetry_handler.console) if telemetry_handler.console else None
            )
            expected_console_id = id(telemetry_console) if telemetry_console else None
            _console_matches = handler_console_id == expected_console_id

            # Check console buffer state
            _console_has_file = (
                hasattr(telemetry_console, "file") if telemetry_console else False
            )
            _console_file_id = (
                id(telemetry_console.file)
                if telemetry_console and hasattr(telemetry_console, "file")
                else None
            )
            _console_record_enabled = (
                getattr(telemetry_console, "_record", False)
                if telemetry_console
                else False
            )

            # Try to get buffer content length (if it's a StringIO)
            buffer_length_before = None
            if telemetry_console and hasattr(telemetry_console, "file"):
                try:
                    file_obj = telemetry_console.file
                    if hasattr(file_obj, "getvalue"):
                        buffer_length_before = len(file_obj.getvalue())
                except Exception:
                    pass

            # TEST: Try to write a test message directly to the handler
            test_record = logger.makeRecord(
                logger.name,
                logging.DEBUG,
                "",
                0,
                "[TELEMETRY_TEST] Handler test message after creation",
                (),
                None,
            )
            telemetry_handler.emit(test_record)

            # Check buffer length after test message
            buffer_length_after = None
            if telemetry_console and hasattr(telemetry_console, "file"):
                try:
                    file_obj = telemetry_console.file
                    if hasattr(file_obj, "getvalue"):
                        buffer_length_after = len(file_obj.getvalue())
                except Exception:
                    pass

            _buffer_grew = (
                buffer_length_after is not None
                and buffer_length_before is not None
                and buffer_length_after > buffer_length_before
            )

            if is_reinitialization:
                # print_info(
                #     f"[TELEMETRY_DIAG] New telemetry handler created and added: "
                #     f"handler_id={id(telemetry_handler)}, "
                #     f"handler_console_id={handler_console_id}, "
                #     f"expected_console_id={expected_console_id}, "
                #     f"console_matches={console_matches}, "
                #     f"handler_in_logger={handler_in_logger}, "
                #     f"logger_handlers_count={len(logger.handlers)}, "
                #     f"handler_level={telemetry_handler.level}, "
                #     f"console_has_file={console_has_file}, "
                #     f"console_file_id={console_file_id}, "
                #     f"console_record_enabled={console_record_enabled}, "
                #     f"buffer_length_before={buffer_length_before}, "
                #     f"buffer_length_after={buffer_length_after}, "
                #     f"buffer_grew={buffer_grew}"
                # )
                pass
        except Exception:
            try:
                # from adscan_internal.rich_output import print_info
                # print_info(f"[TELEMETRY_DIAG] Error in handler verification: {e}")
                pass
            except Exception:
                pass
    elif preserved_telemetry_handler is not None:
        # No new console provided, but handler exists - preserve it
        try:
            if is_reinitialization:
                # from adscan_internal.rich_output import print_info
                # print_info(
                #     f"[TELEMETRY_DIAG] Reusing preserved telemetry handler: "
                #     f"handler_id={id(preserved_telemetry_handler)}, "
                #     f"console_id={id(preserved_telemetry_handler.console) if preserved_telemetry_handler.console else None}"
                # )
                pass
        except Exception:
            pass
        logger.addHandler(preserved_telemetry_handler)
        _telemetry_console_handler = preserved_telemetry_handler
    else:
        try:
            if is_reinitialization:
                # from adscan_internal.rich_output import print_info
                # print_info("[TELEMETRY_DIAG] No telemetry handler created (no console, no preserved handler)")
                pass
        except Exception:
            pass
        _telemetry_console_handler = None

    # Prevent propagation to root logger
    logger.propagate = False

    # Attach selected directories for debug purposes (do not include full paths in output).
    logger.adscan_log_dir_is_fallback = (
        log_dir is not None
        and requested_log_dir is not None
        and log_dir != requested_log_dir
    )

    _logger = logger

    # DIAGNOSTIC: Log final state of init_logging (only on re-initialization)
    try:
        if is_reinitialization:
            # from adscan_internal.rich_output import print_info
            _handler_types = [type(h).__name__ for h in logger.handlers]
            _telemetry_handler_id = (
                id(_telemetry_console_handler) if _telemetry_console_handler else None
            )
            _telemetry_console_id = (
                id(_telemetry_console_handler.console)
                if _telemetry_console_handler and _telemetry_console_handler.console
                else None
            )
            # print_info(
            #     f"[TELEMETRY_DIAG] init_logging completed: "
            #     f"logger_handlers_count={len(logger.handlers)}, "
            #     f"handler_types={handler_types}, "
            #     f"telemetry_handler_id={telemetry_handler_id}, "
            #     f"telemetry_console_id={telemetry_console_id}, "
            #     f"telemetry_handler_level={_telemetry_console_handler.level if _telemetry_console_handler else None}"
            # )
            pass
    except Exception:
        pass  # Don't fail if diagnostic logging fails

    return logger


def update_logging_console_level(
    verbose_mode: bool = False,
    debug_mode: bool = False,
):
    """Update handler levels based on verbose/debug mode changes.

    Args:
        verbose_mode: New verbose mode value
        debug_mode: New debug mode value
    """
    global _console_handler, _file_handler, _workspace_file_handler
    global _telemetry_console_handler

    # DIAGNOSTIC: Log when console level is updated (write directly to file handler to ensure visibility)
    # COMMENTED: Not directly related to module re-execution tracking
    # try:
    #     old_level = _console_handler.level if _console_handler else None
    #     if _file_handler is not None:
    #         # Write directly to file handler to ensure diagnostic is always visible
    #         diagnostic_msg = (
    #             f"[LOGGING_DIAG] update_logging_console_level called: "
    #             f"verbose_mode={verbose_mode}, debug_mode={debug_mode}, "
    #             f"old_console_level={old_level}"
    #         )
    #         _file_handler.emit(logging.LogRecord(
    #             name="adscan.diagnostic",
    #             level=logging.DEBUG,
    #             pathname="",
    #             lineno=0,
    #             msg=diagnostic_msg,
    #             args=(),
    #             exc_info=None
    #         ))
    # except Exception:
    #     pass  # Don't fail if diagnostic logging fails

    # Console handler controls what the user sees in the terminal.
    if _console_handler is not None:
        if debug_mode:
            _console_handler.setLevel(logging.DEBUG)
            _diag_log("update_logging_console_level: set console handler DEBUG")
        elif verbose_mode:
            _console_handler.setLevel(logging.INFO)
            _diag_log("update_logging_console_level: set console handler INFO")
        else:
            _console_handler.setLevel(logging.ERROR)
            _diag_log("update_logging_console_level: set console handler ERROR")

        # DIAGNOSTIC: Log the new level (write directly to file handler)
        # COMMENTED: Not directly related to module re-execution tracking
        # try:
        #     new_level = _console_handler.level
        #     if _file_handler is not None:
        #         diagnostic_msg = (
        #             f"[LOGGING_DIAG] update_logging_console_level result: "
        #             f"new_console_level={new_level} (DEBUG=10, INFO=20, ERROR=40)"
        #         )
        #         _file_handler.emit(logging.LogRecord(
        #             name="adscan.diagnostic",
        #             level=logging.DEBUG,
        #             pathname="",
        #             lineno=0,
        #             msg=diagnostic_msg,
        #             args=(),
        #             exc_info=None
        #         ))
        # except Exception:
        #     pass  # Don't fail if diagnostic logging fails

    # File handlers control what is persisted to disk. We default to INFO+ so
    # DEBUG-level internals are only written when debug mode is explicitly
    # enabled, while telemetry handlers still receive DEBUG in all modes.
    file_level = logging.DEBUG if debug_mode else logging.INFO

    if _file_handler is not None:
        _file_handler.setLevel(file_level)

    if _workspace_file_handler is not None:
        _workspace_file_handler.setLevel(file_level)

    # Telemetry console handler should always be at DEBUG level
    # Ensure it remains at DEBUG even after mode updates
    if _telemetry_console_handler is not None:
        _telemetry_console_handler.setLevel(logging.DEBUG)


def get_logger() -> logging.Logger:
    """Get the configured logger instance.

    Returns:
        Logger instance (creates one if not initialized)
    """
    global _logger

    if _logger is None:
        # Fallback: create basic logger if not initialized
        logger = logging.getLogger("adscan")
        if not logger.handlers:
            # Add basic handler to avoid "No handlers" warnings
            handler = logging.StreamHandler()
            handler.setLevel(logging.WARNING)
            logger.addHandler(handler)
        _logger = logger

    return _logger


def update_workspace_logging(workspace_dir: Optional[Path]):
    """Update logging to include workspace-specific log file.

    Args:
        workspace_dir: Workspace directory path. If None, removes workspace handler.
    """
    global _logger, _workspace_file_handler

    if _logger is None:
        return

    # Remove existing workspace handler if present
    if _workspace_file_handler is not None:
        _logger.removeHandler(_workspace_file_handler)
        _workspace_file_handler.close()
        _workspace_file_handler = None

    # Add new workspace handler if workspace_dir is provided
    if workspace_dir:
        try:
            workspace_log_dir = Path(workspace_dir) / "logs"
            workspace_log_dir.mkdir(parents=True, exist_ok=True)
            workspace_log_file = workspace_log_dir / "adscan.log"
            workspace_file_handler = RotatingFileHandler(
                workspace_log_file,
                maxBytes=10 * 1024 * 1024,  # 10 MB
                backupCount=5,
                encoding="utf-8",
            )
            # Match the current global file handler level (INFO by default,
            # potentially DEBUG if debug mode was enabled before workspace
            # logging is configured).
            if _file_handler is not None:
                workspace_file_handler.setLevel(_file_handler.level)
            else:
                workspace_file_handler.setLevel(logging.INFO)
            workspace_file_handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )
            )
            _logger.addHandler(workspace_file_handler)
            _workspace_file_handler = workspace_file_handler
        except PermissionError:
            _workspace_file_handler = None
        except Exception:
            _workspace_file_handler = None


def log_to_file_only(level: int, message: str):
    """Log a message only to file, bypassing console handlers.

    This is used by print_*_verbose/debug functions to avoid duplicate
    console output (they handle console output themselves via Rich).

    Args:
        level: Logging level (logging.DEBUG, logging.INFO, etc.)
        message: Message to log
    """
    global _file_handler, _workspace_file_handler

    logger = get_logger()

    # Create a log record
    record = logger.makeRecord(
        logger.name,
        level,
        "",  # filename (not needed)
        0,  # lineno (not needed)
        message,
        (),
        None,  # exc_info
    )

    # Emit to global file handler
    if _file_handler is not None:
        _file_handler.emit(record)

    # Emit to workspace file handler if present
    if _workspace_file_handler is not None:
        _workspace_file_handler.emit(record)
