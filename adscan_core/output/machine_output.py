"""Reserve stdout for one machine-readable document (``--json``).

A command that prints a JSON document for a script (``adscan recheck --json``,
``adscan engagement status --json``) promises that stdout carries that document
and nothing else, so ``| jq`` or ``json.loads(stdout)`` works. Everything a
human reads (Rich panels, ``print_*`` lines, a stray ``print()``) still renders,
on stderr.

The shared visible console is built bound to the real stdout
(``console_runtime.build_rich_console`` wraps ``sys.stdout`` in a
``MarkerStrippingTextIO``), so swapping ``sys.stdout`` alone would not move it:
the reservation rebinds that console to stderr, keeping the marker-stripping
wrapper, and redirects ``sys.stdout`` for everything else. Only consoles bound
to stdout move; the telemetry recording console writes to its own buffer and is
left alone, so the session recording keeps the human output.

Reserve as early as possible (before the first line a command prints) and
write the document through :func:`write_machine_document`, which goes to the
real stdout the reservation set aside.
"""

from __future__ import annotations

import json
import sys
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Iterator, Optional, TextIO

from adscan_core.console_runtime import MarkerStrippingTextIO
from adscan_core.sensitive import strip_sensitive_markers


@dataclass
class _Reservation:
    real_stdout: TextIO
    saved_sys_stdout: Any
    rebound: list[tuple[Any, Any]] = field(default_factory=list)
    depth: int = 1


_lock = threading.Lock()
_reservation: Optional[_Reservation] = None


def _targets(stream: Any, real_stdout: Any) -> bool:
    """Whether ``stream`` writes to the real stdout (directly or wrapped)."""
    seen = 0
    while stream is not None and seen < 4:
        if stream is real_stdout or stream is sys.__stdout__:
            return True
        stream = getattr(stream, "_wrapped", None)
        seen += 1
    return False


def _stdout_consoles() -> list[Any]:
    from adscan_core.output import _state  # noqa: PLC0415

    consoles = []
    for console in (getattr(_state, "_console", None), getattr(_state, "_fallback_console", None)):
        if console is not None and console not in consoles:
            consoles.append(console)
    return consoles


def reserve_stdout_for_machine_output() -> TextIO:
    """Route human output to stderr until released; return the real stdout.

    Re-entrant: a nested reservation shares the outer one.
    """
    global _reservation  # noqa: PLW0603
    with _lock:
        if _reservation is not None:
            _reservation.depth += 1
            return _reservation.real_stdout
        real = sys.stdout
        reservation = _Reservation(real_stdout=real, saved_sys_stdout=sys.stdout)
        for console in _stdout_consoles():
            bound = getattr(console, "_file", None)
            if bound is None or _targets(bound, real):
                replacement = (
                    MarkerStrippingTextIO(sys.stderr)
                    if isinstance(bound, MarkerStrippingTextIO)
                    else sys.stderr
                )
                reservation.rebound.append((console, bound))
                console.file = replacement
        sys.stdout = sys.stderr
        _reservation = reservation
        return real


def release_machine_stdout() -> None:
    """Undo :func:`reserve_stdout_for_machine_output` (outermost call restores)."""
    global _reservation  # noqa: PLW0603
    with _lock:
        if _reservation is None:
            return
        _reservation.depth -= 1
        if _reservation.depth > 0:
            return
        for console, bound in _reservation.rebound:
            console._file = bound  # noqa: SLF001 - restore the exact binding, None included
        sys.stdout = _reservation.saved_sys_stdout
        _reservation = None


@contextmanager
def machine_readable_stdout() -> Iterator[TextIO]:
    """Context manager form; yields the real stdout."""
    real = reserve_stdout_for_machine_output()
    try:
        yield real
    finally:
        release_machine_stdout()


def machine_stdout_reserved() -> bool:
    """Whether stdout is currently reserved for a machine document."""
    return _reservation is not None


def write_machine_document(doc: Any, *, default: Any = None) -> None:
    """Write ``doc`` as JSON to the real stdout, alone, newline-terminated.

    Uses the reserved stdout when a reservation is active, else ``sys.stdout``.
    """
    reservation = _reservation
    stream = reservation.real_stdout if reservation is not None else sys.stdout
    # Sensitivity markers are invisible on a terminal but are real characters
    # in a document: strip them from the values before encoding.
    plain = json.loads(strip_sensitive_markers(json.dumps(doc, ensure_ascii=False, default=default)))
    text = json.dumps(plain, indent=2, sort_keys=True)
    stream.write(text + "\n")
    stream.flush()


__all__ = (
    "machine_readable_stdout",
    "machine_stdout_reserved",
    "release_machine_stdout",
    "reserve_stdout_for_machine_output",
    "write_machine_document",
)
