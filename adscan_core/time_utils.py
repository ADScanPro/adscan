"""Centralized time helpers for robust timestamp handling.

Internal persistence should use timezone-aware UTC datetimes. This avoids
mixing naive and aware values, and keeps serialized timestamps stable across
machines. For elapsed-time calculations within a running process, use the
monotonic clock instead of wall-clock timestamps.
"""

from __future__ import annotations

from datetime import UTC, datetime
import time


def utc_now() -> datetime:
    """Return the current timezone-aware UTC datetime."""
    return datetime.now(UTC)


def utc_now_iso() -> str:
    """Return the current UTC datetime serialized as ISO-8601."""
    return utc_now().isoformat()


def ensure_utc(value: datetime | None) -> datetime | None:
    """Normalize a datetime to timezone-aware UTC.

    Historical ADscan data may contain naive timestamps serialized from
    ``datetime.utcnow()``. Those are interpreted as UTC for backward
    compatibility.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def parse_iso_datetime(value: str) -> datetime:
    """Parse an ISO-8601 datetime string and normalize it to UTC."""
    return ensure_utc(datetime.fromisoformat(value))  # type: ignore[return-value]


def parse_iso_datetime_or_now(value: str | None) -> datetime:
    """Parse an ISO-8601 datetime string or fall back to current UTC time."""
    if value:
        return parse_iso_datetime(value)
    return utc_now()


def monotonic_now() -> float:
    """Return a monotonic timestamp for elapsed-time calculations."""
    return time.monotonic()
