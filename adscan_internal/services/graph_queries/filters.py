"""Shared node predicates for the attack-graph inventory queries.

TWO ORTHOGONAL AXES, and conflating them is a defect class
-----------------------------------------------------------
An AD principal carries two independent facts, and the whole of this module
exists to keep them apart:

``enabled``
    The ``userAccountControl`` fact: the object is not marked ACCOUNTDISABLE.
    It is derived faithfully for LIVE objects **and for tombstones**, because a
    deleted object preserves its ``userAccountControl`` and whether it was
    enabled at deletion is exactly what tells an operator whether reanimating
    it yields a usable account. Never falsify it, and never strip it.

``tombstoned``
    The object is deleted and sitting in the AD Recycle Bin. Stamped by
    ``collector/ldap_collector._deleted_entry_to_node``.

From them, the two populations the rest of the product means:

``live``
    The object exists in the directory: ``not tombstoned``.

``active``
    **live AND enabled.** This is the population every KPI, artifact, finding
    count, telemetry counter and client-facing figure means when it says
    "enabled users", and the one that used to be wrong, because ``is_enabled``
    alone let tombstones into it. A real engagement reported a spray population
    of 9 accounts on a ~180-user domain where 7 of the 9 were tombstones.

Use ``is_active`` for any population, count or inventory. Use ``is_enabled``
only when the question genuinely is "does the UAC mark this account disabled",
which for a tombstone means "would reanimating it yield a usable account".
"""

from __future__ import annotations

import time
from typing import Any

STALE_DAYS_DEFAULT: int = 180
_WIN_EPOCH_OFFSET = 116444736000000000


def _props(node: dict[str, Any]) -> dict[str, Any]:
    return node.get("properties") or {}


def resolve_properties(subject: Any) -> dict[str, Any]:
    """Return the properties of a node, a bare properties dict, or a node object.

    Three shapes circulate in this codebase and every one of them reaches these
    predicates, so accepting only one is how half the call sites silently keep
    the old behaviour:

    * a graph **node dict** -- ``{"kind": "User", "properties": {...}}``;
    * a bare **properties dict** -- what ``inventories._nodes_props`` and the
      flattened ``inventory/*.json`` records hand around;
    * a **node object** (``collector.models.CollectorNode``) carrying
      ``.properties`` plus its own ``.enabled`` field.

    A node dict is distinguished from a properties dict by carrying a
    ``properties`` key; a properties dict is returned as itself.
    """
    if isinstance(subject, dict):
        nested = subject.get("properties")
        if isinstance(nested, dict):
            return nested
        if "properties" in subject:
            return {}
        return subject
    nested = getattr(subject, "properties", None)
    return nested if isinstance(nested, dict) else {}


def _resolve_enabled(subject: Any) -> Any:
    """Return the raw ``enabled`` value, preferring the outer field when present."""
    if isinstance(subject, dict):
        nested = subject.get("properties")
        if isinstance(nested, dict):
            outer = subject.get("enabled")
            return nested.get("enabled") if outer is None else outer
        return subject.get("enabled")
    outer = getattr(subject, "enabled", None)
    if outer is not None:
        return outer
    return resolve_properties(subject).get("enabled")


def is_enabled(node: Any) -> bool:
    """Return whether ``userAccountControl`` does NOT mark the account disabled.

    Fail-open: an unknown (``None``) state counts as enabled, which is what the
    rest of the engine assumes for a node collected without the attribute.

    This is the RAW UAC fact and it is true for tombstones that were enabled at
    deletion. For "should this count toward the domain's population", use
    :func:`is_active` instead.
    """
    value = _resolve_enabled(node)
    return bool(value) if value is not None else True


def is_tombstoned(node: Any) -> bool:
    """Return whether the object is deleted (sitting in the AD Recycle Bin)."""
    return bool(resolve_properties(node).get("tombstoned"))


def is_live(node: Any) -> bool:
    """Return whether the object exists in the directory (``not tombstoned``)."""
    return not is_tombstoned(node)


def is_active(node: Any) -> bool:
    """Return whether the object belongs to the live, enabled population.

    ``live AND enabled`` -- the population every count, KPI, inventory artifact
    and client-facing figure means. This is the predicate to reach for; a
    deleted account must never be counted as part of a domain's account
    population, however it was configured on the day it was deleted.
    """
    return is_live(node) and is_enabled(node)


def domain_matches(node: dict[str, Any], domain: str) -> bool:
    return str(_props(node).get("domain") or "").upper() == domain.upper()


def has_flag(node: dict[str, Any], flag: str) -> bool:
    return bool(_props(node).get(flag))


def is_stale(node: dict[str, Any], stale_days: int = STALE_DAYS_DEFAULT) -> bool:
    last_logon = _props(node).get("lastlogon")
    if not last_logon:
        return False
    try:
        filetime = int(last_logon)
        if filetime == 0:
            return True
        epoch_s = (filetime - _WIN_EPOCH_OFFSET) * 100 / 1_000_000_000
        return epoch_s < time.time() - stale_days * 86400
    except (TypeError, ValueError):
        return False
