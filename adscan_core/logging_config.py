"""Logging configuration for ADscan.

This module provides centralized logging configuration that integrates with Rich
for console output and file-based logging for persistence. All logs are written
to files regardless of verbose/debug mode, while console output is controlled
by verbose/debug flags.
"""

import collections
import copy
import logging
from logging.handlers import RotatingFileHandler
import os
import sys
import threading
from pathlib import Path
import subprocess
import shutil
from typing import Optional

from rich.console import Console, ConsoleRenderable
from rich.logging import RichHandler
from rich.markup import MarkupError
from rich.text import Text

from adscan_core.path_utils import expand_effective_user_path, get_adscan_home
from adscan_core.sensitive import strip_sensitive_markers


class MarkupSafeRichHandler(RichHandler):
    """``RichHandler`` whose markup parse can never crash a ``logger.*`` call.

    The stock ``RichHandler.render_message`` calls ``Text.from_markup(message)``
    when markup is enabled. If ``message`` contains brackets that are NOT valid
    Rich markup — an absolute path (``[/opt/...]`` reads as a closing tag), an
    exception string with a bracketed token, or a sanitizer that corrupted a
    closing tag (``[/bold]`` -> ``[/sozf]``, the 1adb425f regression) — that
    raises ``rich.errors.MarkupError`` which propagates UNCAUGHT out of
    ``logger.info``/``debug`` and crashes the whole command.

    This subclass overrides only the markup-parse step: on ``MarkupError`` it
    falls back to a LITERAL ``Text(message)`` (brackets rendered verbatim) and
    continues with the normal highlighter / keyword pass. No logging path can
    crash on malformed markup again, regardless of where the bad markup came
    from. This is the durable, source-independent guarantee — complementary to
    (not a replacement for) sanitizing PLAIN text in
    ``TelemetrySanitizingFormatter``.
    """

    def render_message(
        self, record: logging.LogRecord, message: str
    ) -> ConsoleRenderable:
        use_markup = getattr(record, "markup", self.markup)
        if use_markup:
            try:
                message_text = Text.from_markup(message)
            except MarkupError:
                # Brackets were not valid markup — render literally instead of
                # letting the MarkupError escape and crash the command.
                message_text = Text(message)
        else:
            message_text = Text(message)

        highlighter = getattr(record, "highlighter", self.highlighter)
        if highlighter:
            message_text = highlighter(message_text)

        if self.keywords is None:
            self.keywords = self.KEYWORDS

        if self.keywords:
            message_text.highlight_words(self.keywords, "logging.keyword")

        return message_text


# Lazily-resolved, cached reference to the ``_TeeConsole`` auto-mirror opt-out
# context manager. Resolved on first use (never at import time) to sidestep any
# adscan_core import-order coupling; only cached on success so a transient early
# import failure does not permanently pin the no-op fallback.
_explicit_mirror_cm = None


def _get_explicit_telemetry_mirror():
    """Return the tee-console auto-mirror opt-out context manager (or a no-op).

    The visible-console logging handler renders each record through
    ``self.console.print(...)``. At runtime ``self.console`` is a
    ``_TeeConsole`` whose ``print`` AUTO-MIRRORS every renderable into the
    telemetry buffer. Wrapping the render in this context manager suppresses
    that mirror so a ``logger.*`` record reaches telemetry through EXACTLY ONE
    path — the dedicated telemetry handler (see ``_VisibleRichHandler``).

    Returns:
        The ``_explicit_telemetry_mirror`` context manager when the state
        module is importable, otherwise ``contextlib.nullcontext`` (a no-op
        that is not cached, so a later successful import still wins).
    """
    global _explicit_mirror_cm
    if _explicit_mirror_cm is not None:
        return _explicit_mirror_cm
    try:
        from adscan_core.output._state import _explicit_telemetry_mirror

        _explicit_mirror_cm = _explicit_telemetry_mirror
        return _explicit_mirror_cm
    except Exception:
        from contextlib import nullcontext

        return nullcontext


class _VisibleRichHandler(MarkupSafeRichHandler):
    """Visible-console handler that renders WITHOUT the tee auto-mirror.

    Single-source-of-truth rule for logger→telemetry: a ``logger.*`` record
    must land in the telemetry recording exactly once. There are two handlers
    on the ``"adscan"`` logger that could deliver a record to the telemetry
    buffer:

    1. this visible handler, bound to the shared ``_TeeConsole`` — its
       ``console.print`` render auto-mirrors into telemetry as a side effect;
    2. the dedicated telemetry handler, always at DEBUG, bound directly to the
       telemetry console.

    Before the ``_TeeConsole`` auto-mirror existed, path (2) was the ONLY
    logger→telemetry route (one copy). Once auto-mirror shipped, any record the
    visible handler actually rendered (in ``--debug`` its level is DEBUG, so it
    renders EVERYTHING) produced a SECOND telemetry copy — every ``logger.*``
    line doubled in ``--debug`` recordings.

    The telemetry handler is the correct single source: it is always at DEBUG
    independently of screen verbosity, which is the whole point of telemetry
    (full recording even when the screen shows only ERROR). So the fix is to
    stop the VISIBLE render from also mirroring: this subclass wraps
    ``super().emit`` in the sanctioned ``_explicit_telemetry_mirror`` opt-out.
    The opt-out disables only the telemetry mirror; it does NOT disable the
    deferred-live-buffer capture (that append happens before the opt-out check
    in ``_TeeConsole.print``), so ``LiveSession`` deferred-flush is unaffected.

    Only the VISIBLE handler is this subclass; the telemetry handler stays a
    plain ``MarkupSafeRichHandler`` so nothing suppresses its (single) write.
    """

    def emit(self, record: logging.LogRecord) -> None:
        with _get_explicit_telemetry_mirror()():
            super().emit(record)


# Global logger instance (initialized by init_logging)
_logger: Optional[logging.Logger] = None
_console_handler: Optional[RichHandler] = None
_file_handler: Optional[RotatingFileHandler] = None
_debug_file_handler: Optional[RotatingFileHandler] = None
_workspace_file_handler: Optional[RotatingFileHandler] = None
_workspace_debug_file_handler: Optional[RotatingFileHandler] = None
_telemetry_console_handler: Optional[RichHandler] = None
# Last workspace directory that workspace logging was (re)configured for.
# The process re-executes ``adscan.py`` in-process mid-run (a spawn context
# re-imports ``__main__`` at the preflight->scan boundary), and that re-import
# calls ``init_logging()`` WITHOUT a ``workspace_dir``. Remembering the active
# workspace dir here lets such a re-init re-attach the workspace file handlers
# instead of silently dropping them (which froze ``<workspace>/logs/
# adscan.debug.log`` after preflight). Cleared only on an intentional detach
# (``update_workspace_logging(None)``).
_active_workspace_dir: Optional[Path] = None

# ---------------------------------------------------------------------------
# Where log FILES go (decided 2026-11-05)
# ---------------------------------------------------------------------------
#
# Every line written while a workspace is active goes to that workspace's
# ``logs/`` and nowhere else, so deleting the workspace deletes its logs. There
# is no global sink for workspace activity any more: the old global
# ``~/.adscan/logs/adscan*.log`` collected the domain, DC IPs, users and the
# ``-p`` secret of every engagement on the machine and nothing ever removed it.
#
# A process records what it logs BEFORE any workspace is active into a bounded
# in-memory buffer. When a workspace activates, the buffer is written into that
# workspace's log (so the ``ci`` preamble lands with its run). A process that
# never activates one drops the buffer at exit, unless it is a maintenance
# command in ``GLOBAL_LOG_COMMANDS`` (install, update, check, version): only
# those keep a global log, and they never touch an engagement.
GLOBAL_LOG_COMMANDS: frozenset[str] = frozenset(
    {"install", "update", "upgrade", "check", "version", "uninstall"}
)
_PRE_WORKSPACE_BUFFER_CAPACITY = 20000
_global_log_dir: Optional[Path] = None
_global_log_enabled: bool = False
_global_log_command: Optional[str] = None
# File level of the INFO sinks (adscan.log): INFO by default, DEBUG under --debug.
# The ``*.debug.log`` sinks are always DEBUG.
_file_level: int = logging.INFO

_LOG_LINE_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
_LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


class MarkerStrippingFormatter(logging.Formatter):
    """Formatter that strips invisible sensitivity markers from rendered logs."""

    def format(self, record: logging.LogRecord) -> str:
        rendered = super().format(record)
        return strip_sensitive_markers(rendered)


_masking_guard = threading.local()


class SecretMaskingFileFormatter(logging.Formatter):
    """Formatter of every log FILE: secrets masked, identifiers kept.

    Log files are what users paste into issues and send to support, so a
    password, hash, ticket or key never reaches one in clear. Users, domains,
    hosts and IPs stay readable: the operator debugs with them, and they live
    in the workspace (and leave with it) anyway.

    The masking is ``adscan_core.telemetry.mask_secrets``, the secrets-only
    layer of the telemetry sanitizer, so there is one set of detectors. This is
    deliberately NOT chained into the telemetry handler: that one has its own
    ``TelemetrySanitizingFormatter`` running the full sanitizer once.

    The masked line is cached on the record, so the INFO and DEBUG file sinks
    of one record share one masking pass. Fail-closed: if masking raises, the
    message body is withheld rather than written raw.
    """

    def __init__(self) -> None:
        super().__init__(_LOG_LINE_FORMAT, datefmt=_LOG_DATE_FORMAT)

    def format(self, record: logging.LogRecord) -> str:
        cached = record.__dict__.get("_adscan_masked_file_line")
        if cached is not None:
            return cached
        if getattr(_masking_guard, "active", False):
            # A record emitted from INSIDE the masking pass (sanitizer
            # internals). Never recurse into the sanitizer; withhold the body.
            return self._withheld(record, "nested")
        rendered = super().format(record)
        _masking_guard.active = True
        try:
            from adscan_core.telemetry import mask_secrets

            masked = mask_secrets(rendered)
        except Exception as exc:  # noqa: BLE001 — fail closed, never raw
            masked = self._withheld(record, type(exc).__name__)
        finally:
            _masking_guard.active = False
        record.__dict__["_adscan_masked_file_line"] = masked
        return masked

    def _withheld(self, record: logging.LogRecord, reason: str) -> str:
        stamp = self.formatTime(record, self.datefmt)
        return (
            f"{stamp} - {record.name} - {record.levelname} - "
            f"<log line withheld: secret masking unavailable ({reason})>"
        )


class _PreWorkspaceBufferHandler(logging.Handler):
    """Hold the records a process emits before any workspace is active.

    Nothing here touches disk. The records are written into the workspace log
    when one activates, into the global log only for a maintenance command,
    and are otherwise discarded with the process.
    """

    def __init__(self, capacity: int = _PRE_WORKSPACE_BUFFER_CAPACITY) -> None:
        super().__init__(logging.DEBUG)
        self.records: "collections.deque[logging.LogRecord]" = collections.deque(
            maxlen=capacity
        )

    def emit(self, record: logging.LogRecord) -> None:
        try:
            # Freeze a COPY now: args can mutate later and the traceback
            # objects would pin whole frames in memory. The record itself is
            # shared with the handlers after this one (console, telemetry),
            # which must still see its args and its exc_info.
            held = copy.copy(record)
            held.msg = record.getMessage()
            held.args = None
            if record.exc_info and not held.exc_text:
                held.exc_text = logging.Formatter().formatException(record.exc_info)
            held.exc_info = None
            self.records.append(held)
        except Exception:  # noqa: BLE001 — logging must never raise
            pass

    def drain_into(self, handlers: list[logging.Handler]) -> None:
        """Replay the held records into ``handlers`` (level-filtered) and clear."""
        pending = list(self.records)
        self.records.clear()
        for record in pending:
            for handler in handlers:
                if record.levelno >= handler.level:
                    try:
                        handler.handle(record)
                    except Exception:  # noqa: BLE001
                        continue

    def discard(self) -> None:
        self.records.clear()


_pre_workspace_buffer = _PreWorkspaceBufferHandler()


def _make_file_handler(path: Path, *, max_bytes: int, level: int) -> RotatingFileHandler:
    handler = RotatingFileHandler(
        path, maxBytes=max_bytes, backupCount=5, encoding="utf-8"
    )
    handler.setLevel(level)
    handler.setFormatter(SecretMaskingFileFormatter())
    return handler


def _make_sink_pair(log_dir: Path) -> tuple[RotatingFileHandler, RotatingFileHandler]:
    """Return the ``adscan.log`` (INFO+, DEBUG under --debug) + ``adscan.debug.log`` pair."""
    log_dir.mkdir(parents=True, exist_ok=True)
    info_handler = _make_file_handler(
        log_dir / "adscan.log", max_bytes=10 * 1024 * 1024, level=_file_level
    )
    try:
        debug_handler = _make_file_handler(
            log_dir / "adscan.debug.log", max_bytes=25 * 1024 * 1024, level=logging.DEBUG
        )
    except Exception:
        info_handler.close()
        raise
    return info_handler, debug_handler


def _detach(logger: logging.Logger, handler: Optional[logging.Handler]) -> None:
    if handler is not None and handler in logger.handlers:
        logger.removeHandler(handler)


def _attach(logger: logging.Logger, handler: Optional[logging.Handler]) -> None:
    if handler is not None and handler not in logger.handlers:
        logger.addHandler(handler)


def _active_file_sinks() -> list[logging.Handler]:
    """The file sinks a record goes to right now (workspace, else global)."""
    workspace = [
        h for h in (_workspace_file_handler, _workspace_debug_file_handler) if h is not None
    ]
    if workspace:
        return workspace
    if _global_log_enabled:
        return [h for h in (_file_handler, _debug_file_handler) if h is not None]
    return []


def _route_file_sinks(logger: logging.Logger) -> None:
    """Attach exactly one family of file sinks to ``logger``.

    Workspace sinks when a workspace is active (global ones detached), else the
    global sinks for a maintenance command, else the in-memory buffer. Whatever
    the buffer held is written into the sinks that take over.
    """
    workspace = [
        h for h in (_workspace_file_handler, _workspace_debug_file_handler) if h is not None
    ]
    global_sinks = [h for h in (_file_handler, _debug_file_handler) if h is not None]
    if workspace:
        for handler in global_sinks:
            _detach(logger, handler)
        _detach(logger, _pre_workspace_buffer)
        for handler in workspace:
            _attach(logger, handler)
        _pre_workspace_buffer.drain_into(workspace)
        return
    if _global_log_enabled and global_sinks:
        _detach(logger, _pre_workspace_buffer)
        for handler in global_sinks:
            _attach(logger, handler)
        _pre_workspace_buffer.drain_into(global_sinks)
        return
    for handler in global_sinks:
        _detach(logger, handler)
    _attach(logger, _pre_workspace_buffer)


def emit_to_file_sinks(record: logging.LogRecord, *, respect_levels: bool = True) -> bool:
    """Write ``record`` to the log files only (no console, no telemetry).

    Routes like a normal record: the active workspace's files, else the global
    files of a maintenance command, else the pre-workspace buffer.

    Args:
        record: The record to persist.
        respect_levels: When False every active sink takes the record whatever
            its level (the historical ``log_to_file_only`` behaviour).

    Returns:
        True when a file sink (or the buffer) took the record.
    """
    sinks = _active_file_sinks()
    if not sinks:
        _pre_workspace_buffer.handle(record)
        return True
    for handler in sinks:
        if not respect_levels or record.levelno >= handler.level:
            try:
                handler.handle(record)
            except Exception:  # noqa: BLE001
                continue
    return True


# Lines an engagement command logged outside any workspace, kept for the
# operator's diagnosis and written through the full telemetry sanitizer.
OUTSIDE_WORKSPACE_LOG_NAME = "adscan-outside-workspace.log"
_OUTSIDE_WORKSPACE_LOG_MAX_BYTES = 10 * 1024 * 1024
_outside_workspace_flush_dir: Optional[Path] = None


def _resolve_global_log_dir() -> Path:
    if _global_log_dir is not None:
        return _global_log_dir
    adscan_home = os.getenv("ADSCAN_HOME")
    if adscan_home:
        return Path(expand_effective_user_path(adscan_home)) / "logs"
    return get_adscan_home() / "logs"


def _register_outside_workspace_flush(log_dir: Path) -> None:
    """Arrange for the leftover pre-workspace buffer to be flushed at exit.

    The target directory is fixed now, at the entry point, so a later change of
    environment cannot redirect it.
    """
    global _outside_workspace_flush_dir
    first = _outside_workspace_flush_dir is None
    _outside_workspace_flush_dir = Path(log_dir)
    if first:
        import atexit  # noqa: PLC0415

        atexit.register(flush_outside_workspace_log)


def flush_outside_workspace_log() -> Optional[Path]:
    """Write what is still buffered (logged outside any workspace), sanitized.

    The lines go through ``telemetry._sanitize_rich_output``, the same
    sanitizer as an uploaded session recording: domains, hosts, IPs, users,
    SIDs and secrets are replaced by pseudonyms. Fail-closed: when the
    sanitizer cannot run, only a count of withheld lines is written.

    Returns:
        The file written, or None when there was nothing to write.
    """
    target_dir = _outside_workspace_flush_dir
    records = list(_pre_workspace_buffer.records)
    _pre_workspace_buffer.discard()
    if target_dir is None or not records:
        return None
    formatter = logging.Formatter(_LOG_LINE_FORMAT, datefmt=_LOG_DATE_FORMAT)
    lines = []
    for record in records:
        try:
            lines.append(formatter.format(record))
        except Exception:  # noqa: BLE001
            continue
    raw = "\n".join(lines)
    try:
        from adscan_core.telemetry import (  # noqa: PLC0415
            _sanitize_rich_output,
            register_home_workspace_names,
        )

        # The flushing process (the host launcher, or one whose workspace is
        # already gone) does not run inside a workspace, so the sanitizer would
        # not know the workspace names it must pseudonymize.
        register_home_workspace_names()
        body = strip_sensitive_markers(_sanitize_rich_output(raw))
    except Exception as exc:  # noqa: BLE001 — fail closed: never write raw
        body = (
            f"<{len(lines)} line(s) withheld: sanitizer unavailable "
            f"({type(exc).__name__})>"
        )
    path = target_dir / OUTSIDE_WORKSPACE_LOG_NAME
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.stat().st_size > _OUTSIDE_WORKSPACE_LOG_MAX_BYTES:
            path.replace(path.with_name(path.name + ".1"))
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(
                f"--- pid {os.getpid()}: lines logged outside any workspace "
                "(sanitized like telemetry) ---\n"
            )
            handle.write(body.rstrip("\n") + "\n")
    except Exception:  # noqa: BLE001
        return None
    return path


def enable_global_log_for_command(command: Optional[str]) -> bool:
    """Open the global log for a maintenance command; no-op for anything else.

    Called by the launcher and the runtime entry points once the command is
    known. Only ``GLOBAL_LOG_COMMANDS`` (install, update, check, version) get a
    log in clear outside a workspace. For every engagement command, what it
    logged outside any workspace (a launcher failing to pull the image, a crash
    before a workspace was selected, the lines after its workspace was removed)
    is written at exit to ``OUTSIDE_WORKSPACE_LOG_NAME`` through the FULL
    telemetry sanitizer: the operator keeps a usable error, and no domain, IP,
    user or secret of the engagement reaches a global file in clear.

    Returns:
        True when the global log is now active for this process.
    """
    global _global_log_enabled, _global_log_command, _file_handler, _debug_file_handler
    name = str(command or "").strip().lower()
    log_dir = _resolve_global_log_dir()
    if name not in GLOBAL_LOG_COMMANDS:
        _register_outside_workspace_flush(log_dir)
        return False
    if _file_handler is None or _debug_file_handler is None:
        try:
            _file_handler, _debug_file_handler = _make_sink_pair(log_dir)
        except PermissionError:
            console = getattr(_console_handler, "console", None)
            if console is None or not _try_fix_log_dir_permissions(console, log_dir):
                return False
            try:
                _file_handler, _debug_file_handler = _make_sink_pair(log_dir)
            except Exception:
                return False
        except Exception:
            return False
    _global_log_enabled = True
    _global_log_command = name
    _route_file_sinks(logging.getLogger("adscan"))
    return True


class TelemetrySanitizingFormatter(logging.Formatter):
    """Formatter that sanitizes a record's message before it reaches telemetry.

    The telemetry console buffer is sanitized once more at export time
    (``telemetry._sanitize_rich_output`` over the whole buffer), but that
    pass runs AFTER Rich has laid the message out for the console. Rich's
    layout (word wrapping at the console width) can inject newlines into the
    middle of a marked value, and can move the invisible zero-width markers
    away from the value they wrap — so the marker pass at export time may no
    longer see an intact ``<start>value<end>`` triplet. ``print_info_debug``
    routes through ``logger.debug`` → ``RichHandler``, so a ``mark_sensitive``
    value on a debug line is exposed to exactly that layout step.

    This formatter closes the gap by sanitizing the message string at FORMAT
    time — before ``RichHandler`` renders it to the telemetry console — while
    the markers are still glued to their value. It reuses the single export
    sanitizer (marker pass + keyword pass), so there is no parallel
    sanitization logic. The VISIBLE console uses a different handler
    (``_console_handler``) with no sanitizing formatter, so the operator still
    sees cleartext (the markers are invisible on screen).

    Critical: the message string may contain Rich MARKUP tags
    (``[bold]...[/bold]``), and ``_sanitize_rich_output`` is designed for
    POST-render PLAIN text. Running it on a markup string CORRUPTS the closing
    tags — the ``/bold`` fragment inside ``[/bold]`` is pseudonymized as if it
    were a path (``[/sozf]``), and when the telemetry ``RichHandler`` re-parses
    that broken markup it raises ``rich.errors.MarkupError`` which propagates
    uncaught through ``logger.info`` and crashes the whole command. So we first
    resolve the markup to PLAIN text (``_safe_markup_text(...).plain`` — the
    crash-safe parser that never raises on bad markup), THEN sanitize the plain
    text. Sanitizing plain text cannot corrupt markup tags because there are
    none. The telemetry handler also runs with ``markup=False`` (defense in
    depth), so a stray ``[`` in a sanitized value or path can never crash it.

    Fail-closed: if the telemetry sanitizer cannot be imported/run, fall back
    to stripping the markers so a marked value is never emitted raw.
    """

    def format(self, record: logging.LogRecord) -> str:
        rendered = super().format(record)
        try:
            from adscan_core import telemetry
            from adscan_core.output._log import _safe_markup_text

            # Resolve any Rich markup to PLAIN text BEFORE sanitizing. The
            # sanitizer is a plain-text transform; handing it a markup string
            # corrupts the closing tags (e.g. [/bold] -> [/sozf]) which then
            # crashes the markup re-parse. _safe_markup_text never raises on
            # bad markup.
            plain = _safe_markup_text(rendered).plain
            return telemetry._sanitize_rich_output(plain)
        except Exception:
            # Never let a sanitization failure leak a marked value: strip the
            # markers as the conservative fallback (matches the file-handler
            # formatter behaviour).
            return strip_sensitive_markers(rendered)


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
    log_dir: Optional[Path] = None,
    workspace_dir: Optional[Path] = None,
    telemetry_console: Optional[Console] = None,
) -> logging.Logger:
    """Initialize logging system with file and console handlers.

    Args:
        console: Rich Console instance for console output
        verbose_mode: Enable verbose console output
        debug_mode: Enable debug console output (shows paths in tracebacks)
        log_dir: Directory for log files (defaults to ~/.adscan/logs)
        workspace_dir: Optional workspace directory for workspace-specific logs

    Returns:
        Configured logger instance
    """
    global _logger, _console_handler, _file_handler, _debug_file_handler
    global _workspace_file_handler, _workspace_debug_file_handler
    global _telemetry_console_handler, _active_workspace_dir
    global _global_log_dir, _file_level

    # Re-attach the last-known workspace on an in-process re-init that passes no
    # workspace_dir. adscan.py's module top-level re-executes mid-run (a spawn
    # context re-imports __main__ at the preflight->scan boundary) and calls
    # init_logging() with workspace_dir=None; without this the workspace file
    # handlers are dropped for the rest of the run and <workspace>/logs/
    # adscan.debug.log freezes after preflight. RotatingFileHandler opens in
    # append mode, so re-attaching the remembered dir never truncates.
    if workspace_dir is None:
        workspace_dir = _active_workspace_dir

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

    # Remember where the GLOBAL log would live. Nothing is created here: only a
    # maintenance command opens it (``enable_global_log_for_command``), and every
    # engagement command logs into its workspace only. See GLOBAL_LOG_COMMANDS.
    if log_dir is not None:
        _global_log_dir = Path(log_dir)
    requested_log_dir = log_dir

    # Create logger
    logger = logging.getLogger("adscan")
    logger.setLevel(logging.DEBUG)  # Always capture all levels to file

    # Vendor-noise taming is centralized in
    # ``adscan_internal.services.native_log_taming`` and invoked once at CLI
    # startup (see adscan.py). Do not install vendor-noise filters here —
    # ``adscan_core`` is shared with the host launcher and must not import
    # ``adscan_internal`` directly. See § "Vendor noise — single source of
    # truth" in CLAUDE.md.

    # CRITICAL: Preserve existing handlers BEFORE clearing handlers
    # This prevents losing debug/verbose mode and telemetry during module re-execution (e.g., PyInstaller).
    preserved_console_level = None
    if _console_handler is not None and (debug_mode or verbose_mode):
        existing_level = _console_handler.level
        requested_level = logging.DEBUG if debug_mode else logging.INFO
        if existing_level <= requested_level:
            # Preserve an already-more-permissive console level only while the
            # active runtime mode still asks for verbose/debug console logging.
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

    # File sinks. The level of the adscan.log sinks follows --debug (INFO by
    # default); the *.debug.log sinks are always DEBUG.
    _file_level = logging.DEBUG if debug_mode else logging.INFO
    for _handler in (_file_handler, _workspace_file_handler):
        if _handler is not None:
            _handler.setLevel(_file_level)

    # Workspace-specific sinks: every record of a workspace session goes here
    # and nowhere else (see the module note above GLOBAL_LOG_COMMANDS).
    if workspace_dir:
        same_workspace = (
            _active_workspace_dir is not None
            and Path(workspace_dir) == _active_workspace_dir
            and _workspace_file_handler is not None
            and _workspace_debug_file_handler is not None
        )
        if not same_workspace:
            for _handler in (_workspace_file_handler, _workspace_debug_file_handler):
                if _handler is not None:
                    try:
                        _handler.close()
                    except Exception:
                        pass
            try:
                (
                    _workspace_file_handler,
                    _workspace_debug_file_handler,
                ) = _make_sink_pair(Path(workspace_dir) / "logs")
            except Exception:
                _workspace_file_handler = None
                _workspace_debug_file_handler = None
        if _workspace_file_handler is not None:
            # Remember the active workspace so a later re-init with no
            # workspace_dir re-attaches these handlers (see the top of init_logging).
            _active_workspace_dir = Path(workspace_dir)
    else:
        _workspace_file_handler = None
        _workspace_debug_file_handler = None
    _route_file_sinks(logger)

    # Console handler (Rich, conditional based on verbose/debug mode).
    # _VisibleRichHandler: MarkupSafeRichHandler that renders WITHOUT triggering
    # the ``_TeeConsole`` auto-mirror, so a ``logger.*`` record reaches the
    # telemetry buffer through exactly ONE path (the dedicated telemetry handler
    # below), never doubled. It also keeps the malformed-markup safety of its
    # base class (a bracketed path / exception token reaching logger.* with
    # markup=True renders literally instead of raising a MarkupError).
    console_handler = _VisibleRichHandler(
        rich_tracebacks=True,
        show_path=bool(debug_mode),
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

        telemetry_handler = MarkupSafeRichHandler(
            rich_tracebacks=True,
            show_path=False,
            console=telemetry_console,
            show_time=False,
            # markup=False (defense in depth): TelemetrySanitizingFormatter
            # already resolves markup to plain text and sanitizes it, so the
            # handler receives a plain string with no intentional markup. With
            # markup=False, a stray '[' surviving in a sanitized value or path
            # can never be parsed as a Rich tag and crash emit() with a
            # MarkupError (the regression from 1adb425f). The VISIBLE console
            # handler keeps markup=True so the operator still sees styling.
            markup=False,
        )
        telemetry_handler.setLevel(logging.DEBUG)
        # Sanitize the message at FORMAT time (before Rich's console layout can
        # split a marked value across a wrap boundary or displace its invisible
        # markers). This protects mark_sensitive values on print_info_debug
        # lines, which route through logger.debug -> this RichHandler. The
        # whole-buffer export sanitizer still runs as the second layer.
        telemetry_handler.setFormatter(TelemetrySanitizingFormatter())
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
    logger.adscan_log_dir_is_fallback = False
    del requested_log_dir

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
    global _file_level
    _file_level = logging.DEBUG if debug_mode else logging.INFO

    if _file_handler is not None:
        _file_handler.setLevel(_file_level)

    if _workspace_file_handler is not None:
        _workspace_file_handler.setLevel(_file_level)

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
    """Point the log files at a workspace, or detach them from it.

    With a directory, ``<workspace>/logs/adscan.log`` and ``adscan.debug.log``
    become the ONLY file sinks: the global ones are detached and whatever the
    process logged before (held in memory) is written into the workspace log.
    With ``None`` the workspace files are closed (so the directory can be
    removed, also on Windows) and later records go back to the in-memory
    buffer, or to the global log of a maintenance command.

    Args:
        workspace_dir: Workspace directory path. If None, removes workspace handler.
    """
    global _logger, _workspace_file_handler, _workspace_debug_file_handler
    global _active_workspace_dir

    if _logger is None:
        return

    # Remember/forget the active workspace so an in-process re-init that passes
    # no workspace_dir re-attaches (or, on an intentional detach, does not
    # re-attach) these handlers. See the top of init_logging.
    _active_workspace_dir = Path(workspace_dir) if workspace_dir else None

    # The dev-only sanitizer trace also writes into the workspace's logs/:
    # release its handle too (it reopens lazily under the new workspace).
    _telemetry_module = sys.modules.get("adscan_core.telemetry")
    if _telemetry_module is not None:
        try:
            _telemetry_module.close_sanitizer_trace()
        except Exception:
            pass

    # Remove existing workspace handler if present
    for handler in (_workspace_file_handler, _workspace_debug_file_handler):
        if handler is not None:
            _logger.removeHandler(handler)
            try:
                handler.close()
            except Exception:
                pass
    _workspace_file_handler = None
    _workspace_debug_file_handler = None

    if workspace_dir:
        try:
            (
                _workspace_file_handler,
                _workspace_debug_file_handler,
            ) = _make_sink_pair(Path(workspace_dir) / "logs")
        except Exception:
            _workspace_file_handler = None
            _workspace_debug_file_handler = None
            _active_workspace_dir = None
    _route_file_sinks(_logger)


def log_to_file_only(level: int, message: str):
    """Log a message only to file, bypassing console handlers.

    This is used by print_*_verbose/debug functions to avoid duplicate
    console output (they handle console output themselves via Rich).
    Every active file sink receives it regardless of its level, as before.

    Args:
        level: Logging level (logging.DEBUG, logging.INFO, etc.)
        message: Message to log
    """
    logger = get_logger()
    record = logger.makeRecord(
        logger.name,
        level,
        "",  # filename (not needed)
        0,  # lineno (not needed)
        message,
        (),
        None,  # exc_info
    )
    emit_to_file_sinks(record, respect_levels=False)
