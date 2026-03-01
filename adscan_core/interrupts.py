"""Shared helpers for standardized interrupt debug logging."""

from __future__ import annotations

from collections.abc import Callable

_KNOWN_INTERRUPT_KINDS: frozenset[str] = frozenset(
    {"keyboard_interrupt", "eof", "signal"}
)


def normalize_interrupt_kind(kind: str) -> str:
    """Normalize an interrupt kind to a stable identifier."""
    normalized = str(kind or "").strip().lower()
    if normalized in _KNOWN_INTERRUPT_KINDS:
        return normalized
    return "unknown"


def build_interrupt_debug_message(*, kind: str, source: str) -> str:
    """Build a standardized interrupt debug line.

    Args:
        kind: Interrupt kind identifier.
        source: Source/context where the interruption was detected.

    Returns:
        Formatted debug message suitable for telemetry/session logs.
    """
    normalized_kind = normalize_interrupt_kind(kind)
    normalized_source = str(source or "").strip() or "unknown"
    return f"[interrupt] kind={normalized_kind} source={normalized_source}"


def emit_interrupt_debug(
    *,
    kind: str,
    source: str,
    print_debug: Callable[[str], None],
) -> None:
    """Emit a standardized interrupt debug line via a provided print function.

    This helper is intentionally best-effort: failures in the logging sink must
    never affect control flow when handling interrupts.
    """
    try:
        print_debug(build_interrupt_debug_message(kind=kind, source=source))
    except Exception:
        return

