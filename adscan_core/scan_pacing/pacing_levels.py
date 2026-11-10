"""Named scan-pacing levels: the vocabulary every surface shows.

Four levels, ordered from slowest to fastest. ``normal`` is today's behaviour,
byte for byte, and is the default everywhere. ``fast`` is only ever reached by
an explicit operator choice; nothing in ADscan selects it on its own.

The label and the description of each level are client-facing (the web scan
form, the REPL ``show pacing`` table, the report's assessment-pace sentence),
so they are written once here and pass the ``adscan-writing`` gate.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class PacingLevel(str, Enum):
    """Scan-pacing level, ordered by :attr:`rank` from slowest to fastest."""

    FRAGILE = "fragile"
    POLITE = "polite"
    NORMAL = "normal"
    FAST = "fast"

    @property
    def rank(self) -> int:
        """Return 0 for the slowest level, increasing towards ``fast``."""
        return _RANK[self]

    @classmethod
    def coerce(cls, value: object) -> PacingLevel | None:
        """Return the level named by ``value`` (case-insensitive), else ``None``."""
        if isinstance(value, PacingLevel):
            return value
        token = str(value or "").strip().lower()
        for level in cls:
            if level.value == token:
                return level
        return None


_RANK: dict[PacingLevel, int] = {
    PacingLevel.FRAGILE: 0,
    PacingLevel.POLITE: 1,
    PacingLevel.NORMAL: 2,
    PacingLevel.FAST: 3,
}

#: The level used when nobody chose one. Reproduces today's behaviour exactly.
DEFAULT_LEVEL = PacingLevel.NORMAL

#: The level the built-in "safe for production" scan policy carries. The policy
#: layer imports this constant and never writes the level name as a literal, so
#: a rename here cannot leave the built-in pointing at a level that does not
#: exist (decision D1, 2026-11-04).
PRODUCTION_SAFE_LEVEL = PacingLevel.POLITE

#: Levels in rank order, slowest first. Every list a surface renders uses this.
ORDERED_LEVELS: tuple[PacingLevel, ...] = tuple(sorted(PacingLevel, key=lambda lv: lv.rank))


@dataclass(frozen=True)
class LevelDescription:
    """Client-facing copy for one level."""

    label: str
    summary: str
    description: str
    requires_confirmation: bool = False


LEVEL_DESCRIPTIONS: dict[PacingLevel, LevelDescription] = {
    PacingLevel.FRAGILE: LevelDescription(
        label="Fragile",
        summary="For networks with fragile servers or a thin link.",
        description=(
            "Works at most 4 hosts at a time with one connection each, waits half a second "
            "between operations on the same host and keeps the whole scan under 10 requests "
            "per second. Timeouts are doubled so ADscan keeps waiting for a slow server. "
            "Expect the network phases to take many times longer than Normal."
        ),
    ),
    PacingLevel.POLITE: LevelDescription(
        label="Polite",
        summary="Recommended for production networks.",
        description=(
            "Works at most 8 hosts at a time with up to two connections each, waits 200 ms "
            "between operations on the same host and keeps the whole scan under 50 requests "
            "per second. Timeouts are 50 percent longer than Normal."
        ),
    ),
    PacingLevel.NORMAL: LevelDescription(
        label="Normal",
        summary="The standard ADscan pace.",
        description=(
            "Each part of the scan runs at its standard tuned concurrency. ADscan still slows "
            "down on its own if a server starts to struggle."
        ),
    ),
    PacingLevel.FAST: LevelDescription(
        label="Fast",
        summary="For labs and networks you own.",
        description=(
            "Roughly doubles the number of hosts worked at once and lets the port scan run "
            "at up to 800 packets per second. Use it only where the network owner has agreed "
            "to a faster assessment."
        ),
        requires_confirmation=True,
    ),
}


def level_is_not_faster_than(level: PacingLevel, ceiling: PacingLevel) -> bool:
    """Return True when ``level`` is the same speed as ``ceiling`` or slower."""
    return level.rank <= ceiling.rank


def slower_level(a: PacingLevel, b: PacingLevel) -> PacingLevel:
    """Return the slower of two levels."""
    return a if a.rank <= b.rank else b


__all__ = [
    "DEFAULT_LEVEL",
    "LEVEL_DESCRIPTIONS",
    "LevelDescription",
    "ORDERED_LEVELS",
    "PRODUCTION_SAFE_LEVEL",
    "PacingLevel",
    "level_is_not_faster_than",
    "slower_level",
]
