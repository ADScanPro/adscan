"""Premium TUI session — single source of truth for ``rich.live.Live``.

Every Live surface in ADscan goes through :class:`LiveSession`. The class
wraps :class:`rich.live.Live` with the defaults that ship a premium-grade
terminal experience and that prevent the four recurring failure modes we
have shipped slices to fix in the past:

1. **Header stacking.** Without ``redirect_stdout``/``redirect_stderr``,
   any ``print_*`` call issued while Live is rendering inserts a fresh
   block above the live region — every refresh "stamps" a new header.
   ``LiveSession`` always sets the redirects on TTYs.
2. **Scrollback leak.** Live updates that grow in height push earlier
   frames into the user's scrollback. ``screen=True`` (alt-screen buffer)
   contains the entire dashboard inside an isolated scroll region;
   when the session exits, the alt-screen pops cleanly and only the
   :paramref:`summary` callback writes to the permanent scrollback.
3. **Non-TTY breakage.** CI runs, pytest captured stdout and shell pipes
   do not support alt-screen escape codes. ``LiveSession`` detects this
   via :pyattr:`rich.console.Console.is_terminal` (and the
   ``ADSCAN_NO_LIVE`` env var) and falls back to inline plain-text
   logging — the same caller code works in both modes.
4. **Signal-handling corruption.** A ``Ctrl-C`` while alt-screen is
   active must pop the screen before the traceback is printed,
   otherwise the user is left staring at an empty alt-screen until they
   blindly type ``reset``. ``LiveSession`` installs an interrupt hook
   that tears Live down cleanly, runs the optional callback for partial
   output, then re-raises.

Deferred diagnostic logs
------------------------
When Live runs with ``alt_screen=True`` + ``redirect_io=True`` (the
premium default), any ``print_*`` diagnostic emitted DURING the render is
routed into Rich Live's internal log region — which lives inside the
alternate-screen buffer and is discarded when the alt-screen pops. To stop
operators losing those logs, ``LiveSession`` pushes a *deferred live-log
buffer* on the shared ``_TeeConsole`` for the duration of the render (only
in that exact alt-screen + redirect case) and FLUSHES it to the real
scrollback after the alt-screen has popped. The premium panel stays clean
during the render; the captured logs appear after it, beneath the summary.
This reuses the existing ``_TeeConsole`` interception point — it never
touches ``sys.stdout`` or Rich's ``redirect_*`` machinery (a prior decision
rejected that approach as fragile; see CLAUDE.md § "Diagnostic logs during
Live").

The module is intentionally framework-light: no ``adscan_internal``
imports. It is safe to use from launcher code, services and CLI alike.
"""

from __future__ import annotations

import asyncio
import os
import sys
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Optional

from rich.console import Console
from rich.live import Live
from rich.rule import Rule

if TYPE_CHECKING:
    from rich.console import RenderableType


__all__ = ["LiveSession", "LiveSessionConfig"]


# Env var honoured by the legacy widgets (``trust_enum_live``, etc.) — kept
# so customers that already export it for paranoid engagements keep getting
# the inline-logging behaviour after the migration.
_NO_LIVE_ENV = "ADSCAN_NO_LIVE"


@dataclass(frozen=True)
class LiveSessionConfig:
    """Premium-CLI defaults for a :class:`LiveSession`.

    Override per call site only when the call site has a documented UX
    reason. The defaults are tuned for the most common case (long-running
    dashboard, interactive operator, scrollback must stay clean).

    Attributes:
        refresh_per_second: How often Live re-renders the cached
            renderable. ``8`` matches the existing ``cves_native`` /
            widget cadence; bump to ``10`` only for sub-second progress
            visuals (timeroasting).
        alt_screen: When ``True`` and the console is a TTY, Live renders
            inside the terminal's alternate-screen buffer. On exit the
            alt-screen pops back to normal and only the summary block
            stays in scrollback. Disable when the call site relies on
            inline scrolling (small progress bars, transient renders).
        redirect_io: When ``True``, ``stdout``/``stderr`` are routed
            through Live so concurrent ``print_*`` calls interleave with
            the live region instead of stacking headers above it.
        transient: Forwarded to :class:`rich.live.Live`. Only honoured
            when ``alt_screen`` is ``False`` — alt-screen already wipes
            the dashboard on exit.
        show_summary_on_exit: Whether to invoke the optional ``summary``
            callback after Live exits. Set to ``False`` to suppress
            persistent output (e.g. when the caller prints its own
            recap).
        defer_live_logs: When ``True`` (default) AND the session enters
            Live with ``alt_screen=True`` + ``redirect_io=True``, every
            ``print_*`` call issued during the render is captured and
            re-printed to the real scrollback after the alt-screen pops
            (below the summary). This recovers the diagnostic logs that
            Rich Live would otherwise discard inside the alt-screen
            buffer. Set to ``False`` only when a call site has a
            documented reason to drop those logs entirely.
    """

    refresh_per_second: int = 8
    alt_screen: bool = True
    redirect_io: bool = True
    transient: bool = False
    show_summary_on_exit: bool = True
    defer_live_logs: bool = True


def _resolve_console() -> Console:
    """Return the shared ADscan console, falling back to a plain one.

    ``LiveSession`` must work even before ``adscan_core.rich_output`` has
    been initialised (early launcher path, structural tests). When the
    shared console is unavailable we construct a default :class:`Console`
    so the abstraction never raises during import.
    """
    try:
        from adscan_core.output._state import get_console as _get_console

        return _get_console()
    except Exception:  # noqa: BLE001 — defensive, never propagate
        return Console()


def _resolve_telemetry_console() -> Optional[Console]:
    """Return the session-recording :class:`Console`, or ``None`` if absent.

    The telemetry console is a separate ``Console(record=True)`` that
    mirrors every standard ``print_*`` call (managed by
    ``adscan_core.output``). Renderables routed through
    :class:`rich.live.Live` bypass that pipeline entirely — they hit the
    visible console only — so the session recording loses every panel
    rendered inside a ``LiveSession`` unless we explicitly stamp the
    final state into the telemetry console on exit.

    Returns ``None`` when the recording console has not been initialised
    yet (early launcher path, tests) — the caller treats absence as
    "no telemetry mirroring required" and continues silently.
    """
    try:
        from adscan_core.output._state import (
            _get_telemetry_console as _telemetry,
        )

        return _telemetry()
    except Exception:  # noqa: BLE001 — defensive, never propagate
        return None


def _is_no_live_env() -> bool:
    """True when the operator has opted out of Live UIs via env."""
    return os.environ.get(_NO_LIVE_ENV, "") == "1"


def _is_noninteractive_env() -> bool:
    """True when the session is non-interactive (CI / ``adscan ci`` / pipeline).

    ``console.is_terminal`` (≈ ``isatty()``) is NOT a reliable gate for Live:
    ``adscan ci`` runs under Docker ``-it`` and the CI workflow exports
    ``FORCE_COLOR=1`` / ``TERM=xterm-256color``, so Rich reports a terminal even
    though stdout is captured to a non-interactive log. Rendering Live there
    emits alt-screen / cursor escapes the log cannot interpret, so every refresh
    STACKS the full panel instead of overwriting it — flooding the CI output.

    Keyed on the EXPLICIT non-interactive markers ``adscan ci`` sets
    (``ADSCAN_NONINTERACTIVE=1`` — adscan.py entry point — and ``ADSCAN_SESSION_ENV=ci``),
    NOT on the bare ``CI`` / ``GITHUB_ACTIONS`` markers. The flood is driven by
    ``adscan ci`` (which sets these), and keying narrowly avoids a footgun: the
    unit-test suite itself runs under ``GITHUB_ACTIONS=true`` and must still be
    able to exercise real Live mode. Kept dependency-light — ``adscan_core`` must
    not import ``adscan_internal.interaction.is_non_interactive``; this mirrors
    its explicit-marker branch.
    """
    if os.environ.get("ADSCAN_NONINTERACTIVE", "").strip().lower() in {"1", "true", "yes"}:
        return True
    return os.environ.get("ADSCAN_SESSION_ENV", "").strip().lower() == "ci"


def _renderable_summary_text(renderable: "RenderableType", console: Console) -> str:
    """Best-effort one-line digest of a Rich renderable for non-TTY logs.

    We deliberately pass through :meth:`Console.render` so styled text,
    tables and panels degrade to readable plain text without colour
    codes. The first non-empty line is returned; everything else is
    truncated so the inline log never floods the operator's terminal.
    """
    try:
        with console.capture() as capture:
            console.print(renderable, no_wrap=False, soft_wrap=False)
        text = capture.get().strip()
    except Exception:  # noqa: BLE001
        return ""
    if not text:
        return ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


class LiveSession:
    """Premium TUI session wrapping :class:`rich.live.Live`.

    Use as a synchronous context manager from sync callers, and as an
    asynchronous context manager from coroutine callers. The two flavours
    are equivalent — ``__aenter__``/``__aexit__`` simply delegate to the
    sync entry/exit so callers do not need to think about which version
    the caller is on.

    Example:
        ```python
        from adscan_core.tui import LiveSession, LiveSessionConfig

        config = LiveSessionConfig(refresh_per_second=8)
        with LiveSession(dashboard.render(), config=config) as session:
            for event in stream:
                session.update(dashboard.render())
        ```

    On non-TTY consoles (CI, pytest captured stdout, ``ADSCAN_NO_LIVE=1``)
    the session never enters Live; ``update()`` emits a one-line digest
    and ``announce()`` prints the message verbatim. The same code keeps
    working without branches in the caller.
    """

    def __init__(
        self,
        renderable: "RenderableType",
        *,
        config: LiveSessionConfig | None = None,
        summary: Callable[[Console], None] | None = None,
        on_interrupt: Callable[[], None] | None = None,
    ) -> None:
        """Initialise the session.

        Args:
            renderable: The initial Rich renderable to display.
            config: Optional override of the default
                :class:`LiveSessionConfig`. The defaults are correct for
                most call sites — only override when there is a
                documented UX reason.
            summary: Optional callback invoked once after Live exits and
                the alt-screen has popped. Receives the shared
                :class:`Console`. Use this for the persistent recap that
                stays in the operator's scrollback.
            on_interrupt: Optional callback invoked on
                :class:`KeyboardInterrupt`. Runs after Live tears down
                cleanly but before the exception is re-raised. Use this
                to print a partial summary so Ctrl-C never leaves the
                operator with a blank terminal.
        """
        self._renderable = renderable
        self._config = config or LiveSessionConfig()
        self._summary = summary
        self._on_interrupt = on_interrupt
        self._console = _resolve_console()
        self._live: Optional[Live] = None
        # ``is_live`` is decided at __enter__ time and cached so the rest
        # of the lifecycle never has to re-check sys.stdout / env vars.
        self._is_live: bool = False
        self._entered: bool = False
        # Last line emitted by the inline (non-Live) fallback — used to collapse
        # consecutive identical progress digests so CI logs stay tight.
        self._last_inline_line: Optional[str] = None
        # Token for the deferred live-log buffer pushed in __enter__ (only
        # in the alt-screen + redirect_io case). ``None`` means no buffer
        # was pushed and __exit__ has nothing to flush.
        self._deferred_log_token: object | None = None
        # Captured ``(args, kwargs)`` entries retrieved when the buffer is
        # popped (capture stopped) but not yet re-printed to scrollback.
        self._deferred_log_entries: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def console(self) -> Console:
        """Shared Rich console — same instance ``print_*`` writes to."""
        return self._console

    @property
    def is_live(self) -> bool:
        """``True`` when Live is rendering (TTY mode), ``False`` otherwise."""
        return self._is_live

    # ------------------------------------------------------------------
    # Sync context
    # ------------------------------------------------------------------

    def __enter__(self) -> "LiveSession":
        """Enter Live (TTY) or set up inline-logging fallback (non-TTY)."""
        self._entered = True
        self._is_live = (
            bool(self._console.is_terminal)
            and not _is_no_live_env()
            and not _is_noninteractive_env()
        )
        if not self._is_live:
            # Non-TTY: emit the initial frame as a single digest line so
            # the operator at least sees what the dashboard would have
            # shown.
            self._inline_log(self._renderable)
            return self

        live_kwargs: dict[str, Any] = {
            "console": self._console,
            "refresh_per_second": self._config.refresh_per_second,
        }
        if self._config.redirect_io:
            live_kwargs["redirect_stdout"] = True
            live_kwargs["redirect_stderr"] = True
        if self._config.alt_screen:
            # Alt-screen makes ``transient`` redundant — the buffer pop
            # already wipes the dashboard. Forwarding both confuses Rich
            # on some terminals, so we honour ``transient`` only in the
            # non-alt-screen branch.
            live_kwargs["screen"] = True
        else:
            live_kwargs["transient"] = self._config.transient

        # Deferred live-log capture. Only in the EXACT case where Rich Live
        # would discard the log region on exit — alt-screen ON (the region
        # lives inside the alt-buffer) AND redirect_io ON (``print_*`` is
        # actually routed through Live). With alt_screen=False, Rich's
        # inline log region persists in scrollback, so capturing here would
        # double-print — we deliberately skip the push in that case.
        if (
            self._config.defer_live_logs
            and self._config.alt_screen
            and self._config.redirect_io
        ):
            with suppress(Exception):
                from adscan_core.output._state import push_deferred_live_buffer

                self._deferred_log_token = push_deferred_live_buffer()

        self._live = Live(self._renderable, **live_kwargs)
        try:
            self._live.__enter__()
        except Exception:
            # If Live failed to start (rare — locked terminal, exotic
            # env) we degrade to inline logging so the caller still gets
            # useful output instead of crashing. Pop the buffer (capture
            # off) WITHOUT retaining entries: Live never rendered, so the
            # normal print path already showed everything — nothing to
            # re-print, and nothing must dangle on the stack.
            self._live = None
            self._is_live = False
            self._stop_deferred_capture(retain=False)
            self._inline_log(self._renderable)
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool | None:
        """Tear Live down, then run summary / interrupt / deferred-log flush."""
        try:
            if self._live is not None:
                # Flush the last cached frame so the alt-screen captures
                # the final state before popping.
                with suppress(Exception):
                    self._live.refresh()
                with suppress(Exception):
                    self._live.__exit__(exc_type, exc, tb)
                self._live = None
                self._is_live = False

            # Stop capturing the instant the alt-screen has popped, and
            # retain the entries for the flush below. Doing this BEFORE the
            # summary / telemetry mirror is deliberate: those callbacks
            # ``print`` to the same shared console, and if capture were
            # still active they would be appended to the buffer and then
            # re-printed by the flush — a double-print. By stopping capture
            # here, only the logs emitted DURING the live body are flushed.
            self._stop_deferred_capture(retain=True)

            # Interrupt path runs before summary so partial summaries
            # stay clean even if the operator hit Ctrl-C mid-scan.
            if exc_type is KeyboardInterrupt and self._on_interrupt is not None:
                with suppress(Exception):
                    self._on_interrupt()

            if (
                exc_type is None
                and self._summary is not None
                and self._config.show_summary_on_exit
            ):
                # Only run the success-path summary when the body
                # finished cleanly. Errors get the interrupt callback or
                # propagate as-is.
                self._summary(self._console)

            # Mirror the final renderable + summary into the telemetry
            # console so the session recording captures the panel.
            # Without this, every LiveSession (posture probe, CVE
            # scanner, trust enum, hassession exploit, timeroasting,
            # …) writes only to the visible terminal and the recording
            # is missing the most diagnostically valuable frames.
            #
            # We capture the final renderable to plain text via
            # ``console.capture()`` so the recording sees the SAME
            # bytes the user saw (post-render Rich markup, layout,
            # colour codes preserved). Then we run the summary
            # callback against the telemetry console too — most
            # summary callbacks are pure print calls so the second
            # invocation is idempotent; callers with side effects
            # already gate them in their own state.
            if exc_type is None:
                with suppress(Exception):
                    self._mirror_to_telemetry()
        finally:
            # Always emit the captured diagnostic logs, on EVERY path
            # (clean exit, body exception, KeyboardInterrupt). This runs
            # last so the captured detail lands BELOW the summary headline
            # in scrollback — summary first (the recap), then the logs
            # captured during the view (the detail). ``_stop_deferred_capture``
            # has already popped the buffer off the module stack above (or
            # in the interrupt/exception path it is popped here lazily), so
            # nothing can dangle even when the body raised.
            self._emit_deferred_logs()
        return None

    def _mirror_to_telemetry(self) -> None:
        """Mirror the final renderable + optional summary to telemetry.

        Best-effort: any failure is swallowed (telemetry recording is
        never allowed to break a user-visible flow). Skipped silently
        when the telemetry console has not been initialised.
        """
        telemetry_console = _resolve_telemetry_console()
        if telemetry_console is None:
            return
        # Diagnostic — surfaces every time the LiveSession dumps its
        # final renderable into the recording. If you see this fire
        # multiple times per session for the same widget, the widget is
        # leaking ``__exit__`` calls (re-entering the context) — fix at
        # the caller.
        try:
            from adscan_core.output._log import print_info_debug as _dbg
            _dbg(
                "[live_session] mirror_to_telemetry: dumping final "
                "renderable + summary into telemetry buffer"
            )
        except Exception:  # noqa: BLE001
            pass
        with suppress(Exception):
            telemetry_console.print(self._renderable)
        if (
            self._summary is not None
            and self._config.show_summary_on_exit
        ):
            with suppress(Exception):
                self._summary(telemetry_console)

    def _stop_deferred_capture(self, *, retain: bool) -> None:
        """Pop the deferred buffer off the module stack (stops capture).

        Always removes the buffer from the module-level stack so it cannot
        dangle. When ``retain`` is ``True`` the captured ``(args, kwargs)``
        entries are stashed on ``self`` for :meth:`_emit_deferred_logs` to
        re-print after the alt-screen has popped. When ``retain`` is
        ``False`` (Live never started) the entries are discarded — there
        was no alt-screen to hide them, so the normal print path already
        showed everything. Idempotent and best-effort.

        Args:
            retain: Keep the captured entries for a later flush.
        """
        token = self._deferred_log_token
        self._deferred_log_token = None
        if token is None:
            return
        try:
            from adscan_core.output._state import pop_deferred_live_buffer

            captured = pop_deferred_live_buffer(token)
        except Exception:  # noqa: BLE001
            return
        if retain and captured:
            self._deferred_log_entries = list(captured)

    def _emit_deferred_logs(self) -> None:
        """Re-print the captured diagnostic logs to the real scrollback.

        Runs in ``__exit__``'s ``finally`` so it executes after the
        alt-screen has popped and after the summary callback. If the buffer
        was never popped (interrupt/exception path that skipped
        :meth:`_stop_deferred_capture`) it is popped here lazily. Prints a
        dim header rule followed by each captured renderable in order, only
        when there is something to flush. Best-effort throughout: any
        failure is swallowed so a broken flush never breaks the caller's
        flow.
        """
        # Lazily pop the buffer if an early-return path left it active
        # (e.g. an exception before ``_stop_deferred_capture`` ran).
        if self._deferred_log_token is not None:
            self._stop_deferred_capture(retain=True)
        entries = self._deferred_log_entries
        self._deferred_log_entries = []
        if not entries:
            return
        with suppress(Exception):
            self._console.print(
                Rule(
                    "logs captured during this view",
                    style="dim",
                    characters="─",
                )
            )
        for entry in entries:
            try:
                args, kwargs = entry
                self._console.print(*args, **kwargs)
            except Exception:  # noqa: BLE001
                # One malformed entry must not abort the rest of the flush.
                continue

    # ------------------------------------------------------------------
    # Async context — delegates to sync. We use ``asyncio.to_thread`` so
    # that on a heavily-loaded loop the alt-screen entry/exit syscalls
    # don't block the event loop, but the entry/exit semantics remain
    # identical to the sync path.
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "LiveSession":
        """Async-context entry — equivalent to the sync ``__enter__``."""
        await asyncio.to_thread(self.__enter__)
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> bool | None:
        """Async-context exit — equivalent to the sync ``__exit__``."""
        await asyncio.to_thread(self.__exit__, exc_type, exc, tb)
        return None

    # ------------------------------------------------------------------
    # Update / announce API
    # ------------------------------------------------------------------

    def update(self, renderable: "RenderableType", *, refresh: bool = False) -> None:
        """Replace the live renderable.

        Args:
            renderable: New Rich renderable to display.
            refresh: When ``True`` force an immediate re-render rather
                than waiting for the next refresh tick. Mirrors
                :meth:`rich.live.Live.update`.
        """
        self._renderable = renderable
        if self._live is not None:
            with suppress(Exception):
                self._live.update(renderable, refresh=refresh)
            self._check_stable_line_count_invariant(renderable)
            return
        if self._is_live:
            # Live failed to start but ``is_live`` was True at entry —
            # this should not happen, but if it does we still want the
            # inline log so the operator sees progress.
            self._inline_log(renderable)
            return
        # Non-TTY: log the digest line.
        self._inline_log(renderable)

    def _check_stable_line_count_invariant(
        self, renderable: "RenderableType"
    ) -> None:
        """Detect the Rich Live header-stacking anti-pattern.

        Rich Live with ``alt_screen=False`` (inline mode) tracks a fixed
        line count and overwrites those lines on every refresh. When the
        rendered renderable's line count GROWS between two updates, the
        older frames leak into the user's scrollback as "ghost" panel
        copies — the symptom that drove the 2026-05 posture-probe widget
        fix. The right fix is always at the call site: pre-allocate every
        row up front (as ``pending`` placeholders if needed) so the
        rendered line count is stable from the first frame.

        This invariant fires a one-line developer warning when growth is
        observed under inline mode. Costs are gated:

          * alt_screen=True → no-op (alt-screen contains growth in an
            isolated buffer, so it doesn't leak to scrollback).
          * Non-TTY → no-op (no Live region to leak into).
          * Not in debug mode → no-op (avoids the ``render_lines`` cost
            on the hot path of long-running dashboards).

        Best-effort: any failure (renderable raises during measurement,
        console without ``render_lines``) is swallowed silently — the
        invariant must never break the UI.
        """
        if self._config.alt_screen:
            return
        if not self._is_live:
            return
        try:
            from adscan_core.output._state import is_debug_mode

            if not is_debug_mode():
                return
        except Exception:  # noqa: BLE001
            return
        try:
            lines = self._console.render_lines(
                renderable, self._console.options, pad=False
            )
            line_count = len(lines)
        except Exception:  # noqa: BLE001
            return
        prev = getattr(self, "_prev_line_count", None)
        if prev is not None and line_count > prev:
            try:
                from adscan_core.output._log import print_info_debug as _dbg

                _dbg(
                    f"[LiveSession] renderable line count grew "
                    f"{prev} → {line_count}. Rich Live with alt_screen=False "
                    "leaks ghost frames into scrollback when content grows. "
                    "Fix at the call site: pre-allocate rows up front (e.g. "
                    "'pending' placeholders) so the line count stays stable "
                    "from frame 1. See CLAUDE.md § 'Rich Live UX' for the "
                    "canonical pattern."
                )
            except Exception:  # noqa: BLE001
                pass
        self._prev_line_count = line_count

    def announce(self, message: str, *, severity: str = "info") -> None:
        """Surface a one-line status line to the operator.

        On TTY consoles the renderable is expected to expose its own
        "activity" region; this method is a stub for that layout — it
        only writes to the Live region if the renderable is a
        :class:`rich.layout.Layout` with a region named ``activity``,
        otherwise it is a no-op (TTY) or a plain print (non-TTY).

        Args:
            message: Human-readable status line.
            severity: One of ``"info"``, ``"warning"``, ``"error"``.
                Used to colour the line in non-TTY mode and for the
                ``activity`` region styling.
        """
        if self._is_live:
            self._update_activity_region(message, severity=severity)
            return
        # Non-TTY: emit a styled plain line. Severity-based colour is
        # purely advisory — the console may strip styling.
        style = {
            "info": "cyan",
            "warning": "yellow",
            "error": "red",
        }.get(severity, "cyan")
        self._console.print(f"[{style}]{message}[/{style}]")

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _update_activity_region(self, message: str, *, severity: str) -> None:
        """Write ``message`` into the renderable's ``activity`` region.

        No-op when the cached renderable does not expose a Layout with
        that region — the abstraction must not break call sites that do
        not opt into the activity convention.
        """
        try:
            from rich.layout import (
                Layout,
            )  # local import: avoid Rich layout cost on non-TTY
            from rich.text import Text
        except Exception:  # noqa: BLE001
            return
        if not isinstance(self._renderable, Layout):
            return
        try:
            region = self._renderable["activity"]
        except (KeyError, IndexError, AttributeError):
            return
        style = {
            "info": "cyan",
            "warning": "yellow",
            "error": "red",
        }.get(severity, "cyan")
        with suppress(Exception):
            region.update(Text(message, style=style))
            if self._live is not None:
                with suppress(Exception):
                    self._live.refresh()

    def _inline_log(self, renderable: "RenderableType") -> None:
        """Emit a single readable line for non-TTY consumers.

        Consecutive identical digests are collapsed (a progress widget that
        ``update()``s on every tick would otherwise print the same line dozens
        of times in a CI log).
        """
        line = _renderable_summary_text(renderable, self._console)
        if not line or line == self._last_inline_line:
            return
        self._last_inline_line = line
        # ``file=sys.stderr`` would split the stream from
        # ``print_*`` output; we keep stdout to match the rest of
        # ADscan's logging conventions.
        print(line, file=sys.stdout, flush=True)
