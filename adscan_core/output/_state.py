"""Shared state, console initialisation, and infrastructure helpers.

This module holds every piece of global state and the setup/accessor functions
that the rest of adscan_core.rich_output (and callers) depend on.  Moving them
here allows the public ``adscan_core.rich_output`` module to be progressively
split into focused submodules while keeping a single source-of-truth for all
mutable globals.

Circular-import note
--------------------
This module MUST NOT import from ``adscan_core.rich_output`` at module level.
Functions that need symbols from that module (e.g. ``print_info_debug``,
``install_prompt_logging_wrappers``) must use deferred (lazy) imports inside
the function body.
"""

from __future__ import annotations

import contextvars
import logging
import os
import sys
import threading
from contextlib import contextmanager
from typing import Any, Callable, Dict, Optional

from rich.console import Console

from adscan_core.theme import ADSCAN_PRIMARY  # noqa: F401 (re-exported convenience)

# ---------------------------------------------------------------------------
# Module-level globals
# ---------------------------------------------------------------------------

# Global console instance (will be initialized from adscan.py)
_console: Optional[Console] = None

# Secondary console dedicated to telemetry recording.
# This console is never shown directly to the user; it is used only to
# capture a full Rich session (including info/warning/error messages)
# for sanitized upload to remote storage (Vercel/n8n).
_telemetry_console: Optional[Console] = None

# Global mode flags (will be initialized from adscan.py)
_verbose_mode: bool = False
_debug_mode: bool = False
_secret_mode: bool = False

# Track last message type for intelligent spacing
_last_message_type: Optional[str] = None
_last_was_panel: bool = False

# Logger instance (will be initialized from logging_config)
_logger: Optional[logging.Logger] = None

# ---------------------------------------------------------------------------
# Sensitive masking helpers
# ---------------------------------------------------------------------------


def strip_sensitive_markers(text: str) -> str:
    """Remove invisible sensitive markers from a string.

    These markers are used by :func:`mark_sensitive` to tag sensitive values
    (user/domain/ip/path/etc.) in Rich output so telemetry can sanitize them.
    They must never be present in real OS commands or filesystem paths because
    external tools would receive a different byte sequence and fail.

    Args:
        text: Input string that may contain invisible markers.

    Returns:
        The same string with all known markers removed.
    """
    from adscan_core.sensitive import strip_sensitive_markers as _strip

    return _strip(text)


def mark_passthrough(value: str) -> str:
    """Wrap a non-sensitive value with invisible passthrough markers.

    Use this when you want the value to remain unchanged in session recordings
    (telemetry sanitization will skip it), for example public URLs.

    Args:
        value: Public/non-sensitive value to preserve verbatim.

    Returns:
        Value wrapped with invisible passthrough markers.
    """
    from adscan_core.sensitive import mark_passthrough as _mark

    return _mark(value)


def mark_sensitive(value: str, data_type: str) -> str:
    """Wrap sensitive data with invisible markers for automatic sanitization.

    This function wraps sensitive values with zero-width space markers that are
    invisible to users but can be detected by telemetry sanitization code. This
    allows us to show sensitive data to users while automatically sanitizing it
    before uploading to telemetry services.

    Args:
        value: The sensitive value to mark (e.g., "example.local", "10.0.0.1", "admin")
        data_type: Type of sensitive data, one of:
            - "user": Usernames, account names
            - "domain": Domain names, FQDNs
            - "ip": IP addresses
            - "password": Passwords, hashes, credentials
            - "service": Service names, SPNs, delegation targets
            - "path": File paths, registry keys, share paths
            - "hostname": Hostnames, computer names
            - "workspace": Workspace names/identifiers

    Returns:
        String with invisible markers wrapping the value

    Example:
        >>> marked = mark_sensitive("example.local", "domain")
        >>> # User sees: "example.local"
        >>> # Telemetry sees the value wrapped with invisible markers that
        >>> # are later replaced by \"{DOMAIN}\" during sanitization.
    """
    from adscan_core.sensitive import mark_sensitive as _mark

    return _mark(value, data_type)


def mark_dict_values(
    data: Dict[str, str],
    type_mapping: Dict[str, str],
) -> Dict[str, str]:
    """Mark all values in a dictionary based on key-to-type mapping.

    This helper function applies mark_sensitive() to all values in a dictionary
    based on a mapping from dictionary keys to sensitive data types.

    Args:
        data: Dictionary with keys and values to mark
        type_mapping: Dictionary mapping keys to data types (e.g., {"Domain": "domain", "Username": "user"})

    Returns:
        New dictionary with marked values

    Example:
        >>> data = {"Domain": "example.local", "Username": "admin", "Target": "10.0.0.1"}
        >>> mapping = {"Domain": "domain", "Username": "user", "Target": "ip"}
        >>> marked = mark_dict_values(data, mapping)
        >>> # marked = {"Domain": "\\u200b[SENSITIVE:DOMAIN]\\u200bexample.local\\u200b[/SENSITIVE:DOMAIN]\\u200b", ...}
    """
    result = {}
    for key, value in data.items():
        data_type = type_mapping.get(key)
        if data_type:
            result[key] = mark_sensitive(str(value), data_type)
        else:
            result[key] = value
    return result


def _mark_operation_details(details: Dict[str, str]) -> Dict[str, str]:
    """Automatically mark sensitive values in operation details based on key patterns.

    This function intelligently detects sensitive data types based on dictionary key names
    and applies appropriate marking. Used by print_operation_header() and similar functions.

    Args:
        details: Dictionary of operation details (e.g., {"Domain": "example.local", "Username": "admin"})

    Returns:
        New dictionary with sensitive values marked

    Example:
        >>> details = {"Domain": "example.local", "PDC": "10.0.0.1", "Username": "admin"}
        >>> marked = _mark_operation_details(details)
        >>> # All sensitive values are marked with invisible markers
    """
    import re

    marked = {}

    for key, value in details.items():
        if not value or not isinstance(value, str):
            marked[key] = value
            continue

        key_lower = key.lower()
        value_lower = value.lower()

        # Detect IP addresses
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b"
        if re.search(ip_pattern, value):
            marked[key] = mark_sensitive(value, "ip")
            continue

        # Domain-related keys
        if any(
            keyword in key_lower for keyword in ["domain", "fqdn", "realm", "forest"]
        ):
            # Skip generic values
            if value_lower not in ["n/a", "-", "none", "any"]:
                marked[key] = mark_sensitive(value, "domain")
            else:
                marked[key] = value
            continue

        # User-related keys
        if any(
            keyword in key_lower for keyword in ["user", "account", "admin", "owner"]
        ):
            # Skip generic/anonymous values
            if value_lower not in ["n/a", "-", "none", "anonymous", "guest", "system"]:
                marked[key] = mark_sensitive(value, "user")
            else:
                marked[key] = value
            continue

        # Hostname/Computer keys (PDC, DC, Target Host, Computer, Server, etc.)
        # More specific patterns to avoid false positives like "Scan Target" or "Target Domain"
        if any(
            keyword in key_lower
            for keyword in [
                "pdc",
                "dc",
                "target host",
                "target computer",
                "target server",
                "computer name",
                "server name",
                "hostname",
            ]
        ) or (
            key_lower in ["host", "computer", "server"]
        ):  # Exact match only for these
            # Could be IP (already handled) or hostname/FQDN
            if not re.search(ip_pattern, value):
                # Check if it looks like a domain (has dots) or hostname
                if "." in value and value_lower not in ["n/a", "-"]:
                    # Could be FQDN - mark as domain
                    marked[key] = mark_sensitive(value, "domain")
                elif value_lower not in ["n/a", "-", "none", "any", "all"]:
                    # Hostname without domain
                    marked[key] = mark_sensitive(value, "hostname")
                else:
                    marked[key] = value
            else:
                # IP already marked above
                marked[key] = marked.get(key, value)
            continue

        # Path-related keys (Search Path, Output, Registry Key, etc.)
        if any(
            keyword in key_lower
            for keyword in ["path", "output", "directory", "folder", "file", "registry"]
        ):
            if value_lower not in ["n/a", "-", "none"]:
                marked[key] = mark_sensitive(value, "path")
            else:
                marked[key] = value
            continue

        # Service-related keys (Service, Protocol, Scan Target with specific services)
        if any(keyword in key_lower for keyword in ["service", "spn"]):
            if value_lower not in [
                "n/a",
                "-",
                "none",
                "smb",
                "ldap",
                "winrm",
                "rdp",
                "ssh",
                "http",
                "https",
            ]:
                # Don't mark generic protocol names, but mark specific service targets
                if "/" in value or "\\" in value:
                    # Looks like SPN or service path
                    marked[key] = mark_sensitive(value, "service")
                else:
                    marked[key] = value
            else:
                marked[key] = value
            continue

        # Password/Credential Type keys - mark the type but not generic values
        if any(
            keyword in key_lower
            for keyword in ["password", "hash", "credential", "secret"]
        ):
            # Only mark if it looks like actual credential data (long strings, hex patterns, etc.)
            if len(value) > 8 and value_lower not in [
                "password",
                "hash",
                "ntlm",
                "aes",
            ]:
                marked[key] = mark_sensitive(value, "password")
            else:
                marked[key] = value
            continue

        # Default: don't mark
        marked[key] = value

    return marked


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------


def _diag_enabled() -> bool:
    return os.getenv("ADSCAN_DIAG_LOGGING", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }


def _diag_log(message: str) -> None:
    if _diag_enabled():
        print(f"[DIAG][rich_output] {message}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Tee Console — auto-mirror every visible print into the telemetry recording
# ---------------------------------------------------------------------------
#
# Why this exists.
#
# The session viewer is built from a separate ``Console`` with
# ``record=True`` that captures everything the operator sees so it can be
# replayed by reviewers. Before this subclass, the only way a panel /
# table / Rich renderable made it into the recording was if the call
# site went through one of the canonical helpers (``print_panel``,
# ``print_info``, …) — those helpers mirror manually with two
# ``console.print()`` calls in sequence.
#
# Direct call sites — ``console.print(Panel(...))``,
# ``shell.console.print(table)``, ``self._console.print(some_table)``,
# 191 occurrences across the runtime — bypassed the recording entirely.
# Posture probe panels, credential-dump tables, ADCS pre-flight,
# CVE results, inventory timelines, the CTF flags panel, ligolo
# tables — all of that high-value content was missing from session
# replays. We discovered this by spot-checking customer recordings.
#
# What this subclass does.
#
# ``_TeeConsole`` overrides ``print()`` to also call the telemetry
# console's ``print()`` with the same arguments. Once installed as
# ``_console``, every ``console.print(...)`` in ADscan — old, new, via
# helper, via direct call, via Rich Live exit, anywhere — lands in the
# recording. There is nothing for future code to remember.
#
# Auto-mirror opt-out (for canonical helpers only).
#
# The canonical helpers were written before this subclass existed; they
# already do ``console.print(x); telemetry_console.print(x)`` explicitly.
# Without an opt-out, the helpers would double-print into the recording.
# The :func:`_explicit_telemetry_mirror` context manager turns
# auto-mirror off for the duration of the helper's manual mirror; the
# helper keeps its existing two-line pattern and the recording stays
# clean. New code does NOT need this — just call ``console.print()``.

_skip_auto_mirror: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "adscan_skip_auto_mirror", default=False
)

# ---------------------------------------------------------------------------
# Deferred live-log buffers — capture print_* output emitted DURING a Live
# render so it can be flushed AFTER the alt-screen pops.
# ---------------------------------------------------------------------------
#
# Why this exists.
#
# A ``LiveSession`` with ``alt_screen=True`` + ``redirect_io=True`` (the
# premium default) routes every ``print_*`` call issued WHILE Live is
# rendering into Rich Live's internal log region, which lives inside the
# alternate-screen buffer and is DISCARDED when the alt-screen pops on
# exit. Operators therefore lose all diagnostic logs emitted from inside a
# live render (e.g. posture-probe per-probe timings) unless they re-run the
# whole thing with ``ADSCAN_NO_LIVE=1``.
#
# A prior decision (CLAUDE.md § "Diagnostic logs during Live") rejected the
# stdout-capture approach (touching ``sys.stdout`` / Rich ``redirect_*`` /
# ``FileProxy``) as fragile. Instead we reuse the EXISTING ``_TeeConsole``
# interception point: while a deferred buffer is active, every visible
# ``print()`` ALSO appends its renderable(s) to the top buffer — in
# ADDITION to the normal visible-print + telemetry-mirror behaviour. The
# ``LiveSession`` pops the buffer after the alt-screen has popped and
# re-prints the captured renderables to the operator's real scrollback.
#
# The buffers form a stack so nested ``LiveSession`` contexts each capture
# their own slice. Each entry stores the ``(args, kwargs)`` exactly as
# passed to ``print()`` — for ``print_*`` helpers these are fresh
# strings / ``Text`` / ``Panel`` objects per call, so re-printing them
# later faithfully preserves styling and layout. We deliberately store the
# objects as-passed rather than snapshotting to text: a text snapshot would
# bake in the alt-screen console's width / colour-system and lose the
# ability to re-render at the real terminal's dimensions on flush.

# Each buffer is a list of ``(args, kwargs)`` tuples captured from
# ``_TeeConsole.print`` while that buffer sits on top of the stack.
_DEFERRED_LIVE_BUFFERS: list[list[tuple[tuple[Any, ...], Dict[str, Any]]]] = []


def push_deferred_live_buffer() -> object:
    """Start capturing visible ``print()`` output into a fresh deferred buffer.

    Pushes a new empty buffer onto the deferred-live-log stack and returns
    it as an opaque token. While at least one buffer is active, every
    :meth:`_TeeConsole.print` call ALSO appends its ``(args, kwargs)`` to
    the top buffer, in addition to the normal visible + telemetry paths.

    The returned token must be passed back to
    :func:`pop_deferred_live_buffer` to stop capturing and retrieve the
    captured entries. Callers should always pair push/pop in a
    ``try/finally`` so a buffer is never left dangling on the stack.

    Returns:
        An opaque token identifying the pushed buffer.
    """
    buffer: list[tuple[tuple[Any, ...], Dict[str, Any]]] = []
    _DEFERRED_LIVE_BUFFERS.append(buffer)
    return buffer


def pop_deferred_live_buffer(
    token: object,
) -> list[tuple[tuple[Any, ...], Dict[str, Any]]]:
    """Stop capturing into ``token`` and return its captured entries.

    Tolerant of double-pop and out-of-order pop: if the token is no longer
    on the stack (already popped, or popped on an exception path) the token
    itself is returned (when it looks like a captured list) and the stack
    is left untouched. If the token is on the stack but not on top (nested
    misuse) it is removed in place.

    Args:
        token: The opaque token returned by
            :func:`push_deferred_live_buffer`.

    Returns:
        The list of captured ``(args, kwargs)`` entries (empty if the
        token was never a buffer).
    """
    try:
        # Fast path: token is on top of the stack.
        if _DEFERRED_LIVE_BUFFERS and _DEFERRED_LIVE_BUFFERS[-1] is token:
            return _DEFERRED_LIVE_BUFFERS.pop()
        # Tolerant path: remove by identity wherever it sits, return it.
        for index, buffer in enumerate(_DEFERRED_LIVE_BUFFERS):
            if buffer is token:
                return _DEFERRED_LIVE_BUFFERS.pop(index)
    except Exception:  # noqa: BLE001 — never break the caller on teardown
        pass
    # Already popped / never pushed: return the token if it is a captured
    # list (so the caller can still flush what was captured), else empty.
    if isinstance(token, list):
        return token
    return []


# ---------------------------------------------------------------------------
# Background-thread console silence — a worker thread NEVER paints the live
# console; its output is telemetered + deferred for the foreground to render.
# ---------------------------------------------------------------------------
#
# Why this exists.
#
# Background work (the poisoning listener, the benchmark warm-up, background
# cracking) runs on daemon threads. If such a thread writes to the visible
# console it (a) interleaves with the foreground sequential scan flow so the
# operator cannot tell foreground from background, and (b) — the real bug —
# collides with a live interactive prompt, garbling a selector
# (``? Crack discovered user? (Use arrow keys)DEBUG Result: exit_code=0...``).
#
# The single enforcement point is here, at ``_TeeConsole.print`` (which ALL
# ``print_*`` helpers route through). A worker marks its thread via
# :func:`background_console_context` (or :func:`mark_background_thread`) for the
# duration of its run. While that marker is active on the CURRENT thread, every
# ``print()`` is (a) mirrored into telemetry as usual and (b) appended to a
# shared deferred buffer the FOREGROUND drains + renders at a safe breakpoint
# (``check_background_tasks``, before the next prompt) — and is NEVER written to
# the live visible console. This makes it structurally impossible for any
# background thread to collide with the foreground flow or a prompt, for ALL
# background threads at once, without any per-caller code.
#
# Default (non-debug) behaviour is unchanged: ``print_info_debug`` is a no-op
# when debug is off, so nothing is captured and nothing is deferred — this only
# changes WHERE background output goes when it exists.

# Per-thread marker. ``depth`` > 0 means the current thread is a background
# worker; ``labels`` is a stack of human-readable attributions for the flush.
_bg_console_local = threading.local()

# Shared, thread-safe buffer of ``(label, args, kwargs)`` captured from
# background worker threads, drained + re-rendered by the FOREGROUND.
_BACKGROUND_CONSOLE_LOCK = threading.Lock()
_BACKGROUND_CONSOLE_BUFFER: list[tuple[str, tuple[Any, ...], Dict[str, Any]]] = []


def _is_background_console_thread() -> bool:
    """True when the CURRENT thread is marked as a background worker."""
    try:
        return int(getattr(_bg_console_local, "depth", 0)) > 0
    except Exception:  # noqa: BLE001 — never let the console path raise
        return False


def _current_background_label() -> str:
    labels = getattr(_bg_console_local, "labels", None)
    if labels:
        return str(labels[-1])
    return "background"


@contextmanager
def background_console_context(label: str = "background"):
    """Route this thread's console output off the live terminal for its lifetime.

    While active on the CURRENT thread, every ``print()`` / ``print_*`` call is
    telemetered as usual AND appended to a shared deferred buffer the foreground
    drains + renders at a safe breakpoint — but is NEVER painted to the live
    visible console. This is the single enforcement point for the background-job
    invariant "a worker thread never prints/prompts": a background thread can
    neither interleave with the foreground sequential flow nor corrupt a live
    interactive prompt.

    Best-effort and reentrant: nesting increments a depth counter; the console
    path never raises. Use this to wrap a worker thread's run body.

    Args:
        label: Short attribution shown in the foreground flush header.
    """
    depth = int(getattr(_bg_console_local, "depth", 0))
    labels = getattr(_bg_console_local, "labels", None)
    if labels is None:
        labels = []
        _bg_console_local.labels = labels
    _bg_console_local.depth = depth + 1
    labels.append(str(label))
    try:
        yield
    finally:
        try:
            if labels:
                labels.pop()
        except Exception:  # noqa: BLE001
            pass
        _bg_console_local.depth = max(
            0, int(getattr(_bg_console_local, "depth", 1)) - 1
        )


def mark_background_thread(label: str = "background") -> None:
    """Permanently mark the CURRENT thread as a background worker (no scope).

    Convenience for a dedicated daemon thread whose entire life is background
    work and cannot wrap its body in :func:`background_console_context`. Prefer
    the context manager where a clear scope exists.

    Args:
        label: Short attribution shown in the foreground flush header.
    """
    _bg_console_local.depth = int(getattr(_bg_console_local, "depth", 0)) + 1
    labels = getattr(_bg_console_local, "labels", None)
    if labels is None:
        labels = []
        _bg_console_local.labels = labels
    labels.append(str(label))


def _capture_background_console(
    label: str, args: tuple[Any, ...], kwargs: Dict[str, Any]
) -> None:
    """Best-effort append of one captured background renderable."""
    try:
        with _BACKGROUND_CONSOLE_LOCK:
            _BACKGROUND_CONSOLE_BUFFER.append((label, args, dict(kwargs)))
    except Exception:  # noqa: BLE001 — never break the caller on capture
        pass


def drain_background_console_output() -> (
    list[tuple[str, tuple[Any, ...], Dict[str, Any]]]
):
    """Return + clear every captured background-thread renderable.

    Called by the FOREGROUND at a safe breakpoint. The returned entries are
    re-printed to the operator's real terminal by
    :func:`flush_deferred_background_console`.
    """
    with _BACKGROUND_CONSOLE_LOCK:
        drained = list(_BACKGROUND_CONSOLE_BUFFER)
        _BACKGROUND_CONSOLE_BUFFER.clear()
        return drained


def flush_deferred_background_console() -> int:
    """Render captured background-thread output to the operator's terminal.

    Runs on the FOREGROUND REPL thread only (from ``check_background_tasks``,
    after any active render has completed). Drains the shared buffer and
    re-prints each renderable — attributed under a dim header — so background
    diagnostics that were withheld from the live console during the run surface
    at a safe point instead of colliding with the foreground flow or a prompt.

    Each entry was already mirrored into telemetry at capture time, so the
    re-print here is wrapped in :func:`_explicit_telemetry_mirror` to avoid a
    double telemetry record; only the decorative header is new. Best-effort:
    never raises. Returns the number of entries flushed.
    """
    entries = drain_background_console_output()
    if not entries:
        return 0
    console = _get_console()
    header = None
    try:
        from rich.text import Text  # noqa: PLC0415

        labels = ", ".join(sorted({label for label, _, _ in entries}))
        header = Text(f"─ background output · {labels}", style="dim")
    except Exception:  # noqa: BLE001
        header = None
    with _explicit_telemetry_mirror():
        if header is not None:
            try:
                console.print(header)
            except Exception:  # noqa: BLE001
                pass
        for _label, args, kwargs in entries:
            try:
                console.print(*args, **kwargs)
            except Exception:  # noqa: BLE001
                pass
    return len(entries)


class _TeeConsole(Console):
    """Visible :class:`rich.console.Console` that mirrors print to telemetry.

    Subclasses :class:`rich.console.Console` and only adds the auto-mirror
    side effect to :meth:`print`. Every other ``Console`` method is
    inherited unchanged — ``rule``, ``log``, ``status`` etc. still work
    as before. The mirror is best-effort: any failure on the telemetry
    side is swallowed because a broken record buffer must never break
    the user-visible flow.
    """

    def print(self, *args: Any, **kwargs: Any) -> None:
        # Background worker thread: NEVER paint the live visible console —
        # it would interleave with the foreground sequential scan flow or
        # corrupt a live interactive prompt. Instead route the renderable to
        # telemetry (as usual) + a shared deferred buffer the foreground
        # drains + renders at a safe breakpoint. This is the single
        # enforcement point for the background-job "never prints" invariant,
        # applied to ALL background threads at once.
        if _is_background_console_thread():
            _capture_background_console(_current_background_label(), args, kwargs)
            if not _skip_auto_mirror.get():
                self._mirror_to_telemetry(args, kwargs)
            return

        # Always render to the visible terminal first. If the visible
        # render itself raises, we let that propagate — that's a real
        # bug the operator needs to see.
        super().print(*args, **kwargs)

        # Deferred live-log capture (best-effort, additive). While a
        # ``LiveSession`` with alt-screen has pushed a buffer, also stash
        # the renderable so it can be flushed to the real scrollback after
        # the alt-screen pops. This never replaces or short-circuits the
        # visible print above or the telemetry mirror below — it is purely
        # an ADDITIONAL sink, and any failure here is swallowed so it can
        # never break the user-visible flow.
        if _DEFERRED_LIVE_BUFFERS:
            try:
                _DEFERRED_LIVE_BUFFERS[-1].append((args, dict(kwargs)))
            except Exception:  # noqa: BLE001
                pass

        # Opt-out for canonical helpers that already mirror manually
        # (see the module docstring for the rationale).
        if _skip_auto_mirror.get():
            return

        self._mirror_to_telemetry(args, kwargs)

    def _mirror_to_telemetry(self, args: tuple[Any, ...], kwargs: Dict[str, Any]) -> None:
        """Best-effort mirror of one ``print`` into the telemetry recording."""
        telemetry_console = _telemetry_console
        if telemetry_console is None or telemetry_console is self:
            return
        try:
            telemetry_console.print(*args, **kwargs)
        except Exception:  # noqa: BLE001
            # Best-effort: never let telemetry recording break the
            # user-visible flow. The recording loses one frame; the
            # operator's terminal is unaffected.
            pass


@contextmanager
def _explicit_telemetry_mirror():
    """Disable :class:`_TeeConsole` auto-mirror for the wrapped block.

    Use ONLY from the canonical helpers in
    ``adscan_core/output/_*.py`` that already perform a manual mirror
    (``console.print(x); telemetry_console.print(x)`` pattern). Wrapping
    that two-line block keeps the recording from receiving the same
    renderable twice.

    Do NOT use from new code. New code just calls ``console.print()`` and
    relies on auto-mirror.
    """
    token = _skip_auto_mirror.set(True)
    try:
        yield
    finally:
        _skip_auto_mirror.reset(token)


def _ensure_tee_console(console: Optional[Console]) -> Console:
    """Return a :class:`_TeeConsole` for the given console.

    If ``console`` is already a :class:`_TeeConsole`, returns it. If it
    is a plain :class:`Console`, upgrades it **in place** to a
    ``_TeeConsole`` so the object the caller passed *is* the shared
    visible console. If ``console`` is ``None``, returns a default
    ``_TeeConsole``.

    Why in-place. ``_TeeConsole`` adds only an overridden :meth:`print`
    (no ``__init__``, no ``__slots__``), so its instance layout is
    identical to ``Console`` and a ``__class__`` reassignment is safe and
    preserves every piece of state — ``file``, ``theme``, ``width``, and
    crucially the ``record`` flag. Rebuilding a fresh ``_TeeConsole``
    here used to orphan the caller's reference and silently force
    ``record=False``: any caller that later read from the console it
    passed (e.g. ``console.export_text()`` in tests, or width queries)
    saw an empty / divergent object instead of the live shared console.

    This makes the install path idempotent and lets callers keep passing
    plain ``Console`` instances; the state module transparently upgrades
    them without breaking identity.
    """
    if console is None:
        return _TeeConsole()
    if isinstance(console, _TeeConsole):
        return console
    if type(console) is Console:
        # Layout-compatible in-place upgrade: preserves identity and all
        # instance state (file, theme, width, record).
        console.__class__ = _TeeConsole
        return console
    # Exotic Console subclass we can't safely re-class in place. Mirror
    # the visible-side configuration so behaviour is preserved, and carry
    # the record flag across so capture is not silently dropped.
    return _TeeConsole(
        file=console.file,
        force_terminal=console.is_terminal,
        force_jupyter=console.is_jupyter,
        force_interactive=console.is_interactive,
        soft_wrap=console.soft_wrap,
        theme=getattr(console, "_theme_stack", None) and None,  # rebuilt via theme
        width=console.width if not console.is_terminal else None,
        no_color=getattr(console, "no_color", False),
        markup=True,
        emoji=True,
        record=getattr(console, "record", False),
    )


# ---------------------------------------------------------------------------
# Console init / getters
# ---------------------------------------------------------------------------


def init_rich_output(
    console: Console,
    verbose_mode: bool = False,
    debug_mode: bool = False,
    secret_mode: bool = False,
    logger: Optional[logging.Logger] = None,
):
    """Initialize the rich output module with console and mode flags.

    Args:
        console: Rich Console instance to use for output
        verbose_mode: Enable verbose output mode
        debug_mode: Enable debug output mode
        secret_mode: Enable secret mode (show internal details)
        logger: Optional logger instance (if None, will get from logging_config)
    """
    global _console, _verbose_mode, _debug_mode, _secret_mode, _logger
    previous_console = _console
    # Upgrade any incoming vanilla ``Console`` to a ``_TeeConsole`` so
    # that every ``console.print(...)`` site (helper or direct) is
    # automatically mirrored into the telemetry recording. See the
    # ``_TeeConsole`` docstring above for the full rationale.
    _console = _ensure_tee_console(console)

    # CRITICAL FIX: If console is already initialized and modes are already active,
    # don't overwrite them with False values (prevents reset during module reimport)
    # Only update if:
    # 1. First initialization (_console is None), OR
    # 2. New values are "better" (activating modes that were previously False)
    if previous_console is None or previous_console is not console:
        # First initialization (or a new Console instance) - set all values
        _verbose_mode = verbose_mode
        _debug_mode = debug_mode
        _secret_mode = secret_mode
        _diag_log(
            "init_rich_output: set modes (new console) "
            f"verbose={_verbose_mode}, debug={_debug_mode}, secret={_secret_mode}"
        )
    else:
        # Already initialized - only update if new values are "better" (activating modes)
        # Don't deactivate modes that are already active
        if verbose_mode and not _verbose_mode:
            _verbose_mode = verbose_mode
        if debug_mode and not _debug_mode:
            _debug_mode = debug_mode
        if secret_mode and not _secret_mode:
            _secret_mode = secret_mode
        _diag_log(
            "init_rich_output: preserved modes (existing console) "
            f"verbose={_verbose_mode}, debug={_debug_mode}, secret={_secret_mode}"
        )
        # Note: We intentionally don't deactivate modes here to prevent reset during reimport

    # Set logger if provided, otherwise get from logging_config
    if logger is not None:
        _logger = logger
        _diag_log("init_rich_output: logger injected")
    else:
        try:
            from adscan_core.logging_config import get_logger

            _logger = get_logger()
            _diag_log("init_rich_output: logger from logging_config")
        except ImportError:
            # Fallback: create basic logger if logging_config not available
            _logger = logging.getLogger("adscan")
            _diag_log("init_rich_output: fallback logger")


def set_telemetry_console(console: Optional[Console]) -> None:
    """Configure optional telemetry console used for session recordings.

    This console is intended to record ALL rendered output (at least for the
    high-level helpers in this module) regardless of verbose/debug flags, while
    the primary console continues to control what the end user actually sees.
    """
    global _telemetry_console
    _telemetry_console = console


def is_debug_mode() -> bool:
    """Return True when debug output mode is active."""
    return _debug_mode


def is_verbose_mode() -> bool:
    """Return True when verbose output mode is active."""
    return _verbose_mode


def is_secret_mode() -> bool:
    """Return True when secret/internal-details output mode is active."""
    return _secret_mode


def update_modes(
    verbose_mode: Optional[bool] = None,
    debug_mode: Optional[bool] = None,
    secret_mode: Optional[bool] = None,
):
    """Update mode flags dynamically.

    Args:
        verbose_mode: New verbose mode value (None to keep current)
        debug_mode: New debug mode value (None to keep current)
        secret_mode: New secret mode value (None to keep current)
    """
    global _verbose_mode, _debug_mode, _secret_mode
    if verbose_mode is not None:
        _verbose_mode = verbose_mode
    if debug_mode is not None:
        _debug_mode = debug_mode
    if secret_mode is not None:
        _secret_mode = secret_mode

    _diag_log(
        "update_modes: "
        f"verbose={_verbose_mode}, debug={_debug_mode}, secret={_secret_mode}"
    )

    # Update logging console level when modes change
    try:
        from adscan_core.logging_config import update_logging_console_level

        update_logging_console_level(
            verbose_mode=_verbose_mode,
            debug_mode=_debug_mode,
        )
    except ImportError:
        pass  # logging_config not available, skip


def _get_console() -> Console:
    """Get the global console instance."""
    if _console is None:
        return Console()
    return _console


def _get_telemetry_console() -> Optional[Console]:
    """Get the optional telemetry console instance."""
    return _telemetry_console


def get_console() -> Console:
    """Public accessor for the shared Rich console instance."""
    return _get_console()


def set_output_config(
    *, verbose: bool, debug: bool, telemetry_console: Optional[Console] = None
) -> None:
    """Configure shared Rich output + logging modes.

    This is the canonical setup path for both launcher and runtime callers.
    It mirrors the initialization sequence used by the monolithic CLI:
    1. Initialize Rich-aware logging handlers.
    2. Bind shared console/logger into rich_output.
    3. Apply runtime modes (verbose/debug/secret).
    """
    from adscan_core.logging_config import init_logging

    console = get_console()
    secret_mode = debug

    logger = init_logging(
        console=console,
        verbose_mode=verbose,
        debug_mode=debug,
        secret_mode=secret_mode,
        telemetry_console=telemetry_console,
    )
    init_rich_output(
        console,
        verbose_mode=verbose,
        debug_mode=debug,
        secret_mode=secret_mode,
        logger=logger,
    )
    if telemetry_console is not None:
        set_telemetry_console(telemetry_console)
    # Lazy import to avoid circular dependency: _prompts -> _state -> _prompts
    from adscan_core.output._prompts import install_prompt_logging_wrappers  # noqa: PLC0415

    install_prompt_logging_wrappers()
    update_modes(verbose_mode=verbose, debug_mode=debug, secret_mode=secret_mode)


# ---------------------------------------------------------------------------
# Prompt-mode helpers
# ---------------------------------------------------------------------------


def configure_prompt_behavior(
    *,
    should_disable_interactive_prompts: Callable[[object | None], bool] | None = None,
    interrupt_logger: Callable[[str, str], None] | None = None,
    use_questionary_in_container: Callable[[], bool] | None = None,
) -> None:
    """Configure centralized prompt behavior hooks.

    Args:
        should_disable_interactive_prompts: Predicate used to decide whether
            prompts must auto-resolve defaults (non-interactive runs).
        interrupt_logger: Callable invoked on EOF/KeyboardInterrupt.
        use_questionary_in_container: Predicate to enable Questionary fallback
            for Prompt/Confirm when running in container runtime.
    """
    from adscan_core import prompting

    prompting.configure_prompt_behavior(
        should_disable_interactive_prompts=should_disable_interactive_prompts,
        interrupt_logger=interrupt_logger,
        use_questionary_in_container=use_questionary_in_container,
    )


def set_prompt_auto_mode(active: bool) -> None:
    """Enable/disable centralized prompt auto-mode."""
    from adscan_core import prompting

    prompting.set_prompt_auto_mode(active)


def is_prompt_auto_mode_enabled() -> bool:
    """Return whether centralized prompt auto-mode is currently active."""
    from adscan_core import prompting

    return prompting.is_prompt_auto_mode_enabled()


def _should_disable_prompt_interaction(shell: object | None = None) -> bool:
    """Best-effort predicate for non-interactive prompt behavior."""
    from adscan_core import prompting

    return prompting.should_disable_prompt_interaction(shell)


def _emit_prompt_interrupt_debug(*, kind: str, source: str) -> None:
    """Emit standardized interrupt debug messages for prompt flows."""
    from adscan_core import prompting

    # Lazy import to avoid circular dependency
    from adscan_core.rich_output import print_info_debug  # noqa: PLC0415

    prompting.emit_prompt_interrupt_debug(
        kind=kind, source=source, debug=print_info_debug
    )


def _should_use_questionary_prompt() -> bool:
    """Return True when Prompt/Confirm should use Questionary fallback."""
    from adscan_core import prompting

    return prompting.should_use_questionary_prompt()


# ---------------------------------------------------------------------------
# TelemetryAwareConsole
# ---------------------------------------------------------------------------


class TelemetryAwareConsole:
    """Wrapper that mirrors a *plain* console's prints into telemetry.

    Fallback for the rare case where the visible console is a vanilla
    :class:`rich.console.Console` rather than a :class:`_TeeConsole`. A
    :class:`_TeeConsole` already auto-mirrors every ``print()`` into the
    telemetry recording, so wrapping one in this class would record every
    line TWICE (the tee's auto-mirror + this wrapper's explicit mirror).

    Never wrap a :class:`_TeeConsole` in this class — use
    :func:`wrap_console_for_telemetry`, which returns a tee console unchanged
    and only wraps genuine plain consoles so capture happens exactly once.
    """

    def __init__(self, main_console, telemetry_console):
        self.main_console = main_console
        self.telemetry_console = telemetry_console

    def print(self, *args, **kwargs):
        self.main_console.print(*args, **kwargs)
        if self.telemetry_console:
            self.telemetry_console.print(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self.main_console, name)


def wrap_console_for_telemetry(
    console: Console, telemetry_console: Optional[Console]
) -> Console:
    """Return a console that records every ``print`` into telemetry exactly once.

    This is the single decision point for "make direct ``console.print`` calls
    land in the session recording". It exists to prevent the double-mirror bug:

    * If ``console`` is already a :class:`_TeeConsole`, it auto-mirrors every
      ``print()`` into the telemetry recording on its own, so it is returned
      **unchanged**. Wrapping it in :class:`TelemetryAwareConsole` would record
      every line twice (auto-mirror copy + the wrapper's explicit copy),
      doubling the size of every session recording.
    * Otherwise (a genuine plain :class:`rich.console.Console` with no
      auto-mirror) it is wrapped in :class:`TelemetryAwareConsole` so its prints
      are still captured — exactly once.

    Args:
        console: The visible console to make telemetry-aware.
        telemetry_console: The telemetry recording console (may be ``None``).

    Returns:
        ``console`` itself when it already auto-mirrors, otherwise a
        :class:`TelemetryAwareConsole` wrapping it. In both cases a single
        telemetry copy is produced per ``print``.
    """
    if isinstance(console, _TeeConsole):
        # Already auto-mirrors into telemetry; wrapping would double-record.
        return console
    return TelemetryAwareConsole(console, telemetry_console)


__all__ = [
    # accessors / init
    "get_console",
    "set_telemetry_console",
    "init_rich_output",
    "set_output_config",
    "update_modes",
    "is_debug_mode",
    "is_verbose_mode",
    # prompt-mode helpers
    "configure_prompt_behavior",
    "set_prompt_auto_mode",
    "is_prompt_auto_mode_enabled",
    # sensitive masking
    "strip_sensitive_markers",
    "mark_passthrough",
    "mark_sensitive",
    "mark_dict_values",
    # deferred live-log capture
    "push_deferred_live_buffer",
    "pop_deferred_live_buffer",
    # background-thread console silence
    "background_console_context",
    "mark_background_thread",
    "drain_background_console_output",
    "flush_deferred_background_console",
    # console wrapper
    "TelemetryAwareConsole",
    "wrap_console_for_telemetry",
]
