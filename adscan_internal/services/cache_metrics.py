"""Shared helpers for lightweight cache metrics instrumentation."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, MutableMapping


def copy_stats(stats: Mapping[str, int]) -> dict[str, int]:
    """Return a shallow copy of cache counters."""
    return {str(key): int(value) for key, value in stats.items()}


def reset_stats(stats: MutableMapping[str, int]) -> None:
    """Reset all cache counters to zero in-place."""
    for key in list(stats.keys()):
        stats[key] = 0


def increment_stats(stats: MutableMapping[str, int], key: str, by: int = 1) -> None:
    """Increase one counter in-place."""
    stats[key] = int(stats.get(key, 0)) + int(by)


def increment_scoped_stats(
    *,
    global_stats: MutableMapping[str, int],
    scoped_stats: MutableMapping[str, MutableMapping[str, int]],
    scope_key: str,
    key: str,
    by: int = 1,
) -> None:
    """Increase both global and scoped counters."""
    increment_stats(global_stats, key, by=by)
    bucket = scoped_stats.setdefault(scope_key, {})
    increment_stats(bucket, key, by=by)


def diff_stats(
    *,
    before: Mapping[str, int],
    after: Mapping[str, int],
    keys: Iterable[str],
) -> dict[str, int]:
    """Return per-key delta (`after - before`) for selected counters."""
    return {
        str(key): int(after.get(str(key), 0)) - int(before.get(str(key), 0))
        for key in keys
    }

