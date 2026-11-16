"""A hashable stand-in for a JSON-like value, equal exactly when the values are equal.

The report pipelines deduplicate lists of dicts (edge entries, note records) with
``if item not in target``, which is quadratic: on a large directory a finding
carries hundreds of thousands of edges. :func:`equality_key` lets those loops
keep a set instead, with the SAME result: two values get equal keys if and only
if ``a == b`` (numbers by value, ``True == 1 == 1.0`` included; dicts regardless
of key order; a list never equal to a tuple). A value of any other type returns
``None`` and the caller falls back to the list scan, so nothing is ever merged
that ``==`` would keep apart.
"""

from __future__ import annotations

from collections.abc import Hashable
from typing import Any


def equality_key(value: Any) -> Hashable | None:
    """Hashable key with ``equality_key(a) == equality_key(b)`` iff ``a == b``.

    ``None`` when ``value`` (or anything inside it) is not one of ``None``,
    ``bool``, ``int``, ``float``, ``str``, ``list``, ``tuple`` or ``dict``, or is
    a float NaN (which is not equal to itself).
    """
    if value is None:
        return ("none",)
    if isinstance(value, bool):
        return ("num", int(value))
    if isinstance(value, int):
        return ("num", value)
    if isinstance(value, float):
        if value != value:  # NaN: never equal, never deduplicated by ==
            return None
        return ("num", int(value)) if value.is_integer() else ("num", value)
    if isinstance(value, str):
        return ("str", value)
    if isinstance(value, (list, tuple)):
        items = []
        for item in value:
            key = equality_key(item)
            if key is None:
                return None
            items.append(key)
        return ("list" if isinstance(value, list) else "tuple", tuple(items))
    if isinstance(value, dict):
        pairs = []
        for item_key, item in value.items():
            k = equality_key(item_key)
            v = equality_key(item)
            if k is None or v is None:
                return None
            pairs.append((k, v))
        return ("dict", frozenset(pairs))
    return None


class UniqueAppender:
    """Append to one list only what it does not hold yet, in order, in linear time.

    Same result as ``if item not in target: target.append(item)`` per item, for
    a ``target`` that only this appender adds to after it is created.
    """

    def __init__(self, target: list[Any]) -> None:
        self.target = target
        self._keys: set[Hashable] = set()
        self._opaque = False
        for existing in target:
            self._remember(existing)

    def _remember(self, item: Any) -> None:
        key = equality_key(item)
        if key is None:
            self._opaque = True
        else:
            self._keys.add(key)

    def append(self, item: Any) -> bool:
        """Append ``item`` unless an equal one is held; return whether it was."""
        key = equality_key(item)
        if key is not None:
            if key in self._keys:
                return False
            if self._opaque and item in self.target:
                return False
        elif item in self.target:
            return False
        self.target.append(item)
        if key is None:
            self._opaque = True
        else:
            self._keys.add(key)
        return True
