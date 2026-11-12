"""Group-to-members index (dependency-light SSOT).

Inverted group-membership index built from a prepared membership snapshot:
``{group: {principals}}`` with transitive ancestors and the implicit
primary-group merge already applied by the snapshot. Lives apart from
``attack_paths_core`` because the appliance backend bundles it (affected-assets
example resolution) and ``attack_paths_core`` pulls in the whole scan engine.
Stdlib only: keep it that way. ``attack_paths_core`` re-exports every name.
"""

from __future__ import annotations

from typing import Any, TypeVar

# Holding the snapshot in each cached value (compared by identity, never by
# ``id()``) keeps a freed snapshot's address from being mistaken for a live
# snapshot's content. See ``attack_paths_core`` for the full rationale.
_GROUP_MEMBER_INDEX_CACHE: dict[
    tuple[str, bool, bool],
    tuple[
        dict[str, Any],
        tuple[dict[str, set[str]], dict[str, set[str]], bool],
    ],
] = {}

_CachedT = TypeVar("_CachedT")

# The membership file on disk can be the RAW collector shape (``nodes`` +
# ``edges``) rather than the prepared one (``user_to_groups`` and friends), and
# the index below reads only the prepared shape. Preparing it is
# ``attack_paths_core.prepare_membership_snapshot``, which this module cannot
# import: the appliance backend bundles this module and must never carry the
# scan engine. So the engine registers its preparer here when it loads
# (dependency inversion, same pattern as ``set_finding_catalog_provider``), and
# a reader that loaded the file itself calls :func:`prepared_membership_snapshot`.
# Unregistered (the appliance backend), the snapshot is returned as read.
_MEMBERSHIP_SNAPSHOT_PREPARER: Any = None


def set_membership_snapshot_preparer(preparer: Any) -> None:
    """Register the engine's snapshot preparer (``prepare_membership_snapshot``)."""
    global _MEMBERSHIP_SNAPSHOT_PREPARER  # noqa: PLW0603
    _MEMBERSHIP_SNAPSHOT_PREPARER = preparer


def prepared_membership_snapshot(
    snapshot: dict[str, Any] | None, domain: str
) -> dict[str, Any] | None:
    """``snapshot`` in the prepared shape the index reads, when a preparer is known.

    A raw file (``nodes`` + ``edges`` with empty ``user_to_groups``) is the case
    that matters: read unprepared it yields no members at all, so a group
    source's command fell back to ``<member_of_the_source_group>`` even though
    the directory named its members. Never raises; returns ``snapshot``
    unchanged when no preparer is registered or preparing fails.
    """
    if not isinstance(snapshot, dict) or _MEMBERSHIP_SNAPSHOT_PREPARER is None:
        return snapshot
    try:
        prepared = _MEMBERSHIP_SNAPSHOT_PREPARER(snapshot, domain)
    except Exception:  # noqa: BLE001 - a reader falls back to the file as read
        return snapshot
    return prepared if isinstance(prepared, dict) else snapshot


def _snapshot_memo_get(
    cache: dict[Any, tuple[dict[str, Any], _CachedT]],
    key: Any,
    snapshot: dict[str, Any],
) -> _CachedT | None:
    """Return the memoized value for ``key`` iff it came from THIS snapshot.

    Identity, not ``id()``: the cached snapshot is compared with ``is`` against
    the one in hand, so a freed snapshot's address cannot be mistaken for a live
    snapshot's content.
    """
    entry = cache.get(key)
    if entry is None:
        return None
    cached_snapshot, value = entry
    if cached_snapshot is not snapshot:
        return None
    return value


def _snapshot_memo_set(
    cache: dict[Any, tuple[dict[str, Any], _CachedT]],
    key: Any,
    snapshot: dict[str, Any],
    value: _CachedT,
) -> _CachedT:
    """Memoize ``value`` for ``key`` together with the snapshot that produced it."""
    cache[key] = (snapshot, value)
    return value


def _canonical_membership_label(domain: str, value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if "@" in raw:
        left, _, right = raw.partition("@")
        if left and right:
            return f"{left.strip().upper()}@{right.strip().upper()}"
    return f"{raw.upper()}@{str(domain or '').strip().upper()}"


def _expand_group_ancestors(
    domain: str,
    group_label: str,
    group_to_parents: dict[str, Any],
    cache: dict[str, set[str]],
) -> set[str]:
    """Expand recursive parent groups without Python recursion.

    The previous recursive implementation could hit ``RecursionError`` in very
    large/degenerate environments (deep nested groups or accidental cycles).
    This iterative DFS keeps the same cache contract while avoiding call-stack
    growth.
    """
    if group_label in cache:
        return cache[group_label]

    def _parent_labels(label: str) -> list[str]:
        parents = group_to_parents.get(label, []) if group_to_parents else []
        if not isinstance(parents, list):
            return []
        normalized: list[str] = []
        for parent in parents:
            parent_label = _canonical_membership_label(domain, parent)
            if not parent_label:
                continue
            normalized.append(parent_label)
        return normalized

    stack: list[tuple[str, bool]] = [(group_label, False)]
    resolving: set[str] = set()

    while stack:
        current, expanded = stack.pop()
        if current in cache:
            continue

        if expanded:
            results: set[str] = set()
            for parent_label in _parent_labels(current):
                if parent_label == current:
                    continue
                results.add(parent_label)
                parent_cached = cache.get(parent_label)
                if parent_cached:
                    results.update(parent_cached)
            results.discard(current)
            cache[current] = results
            resolving.discard(current)
            continue

        if current in resolving:
            continue
        resolving.add(current)
        stack.append((current, True))

        for parent_label in _parent_labels(current):
            if (
                parent_label in cache
                or parent_label in resolving
                or parent_label == current
            ):
                continue
            stack.append((parent_label, False))

    return cache.get(group_label, set())


def build_group_member_index(
    snapshot: dict[str, Any] | None,
    domain: str,
    *,
    exclude_tier0: bool = False,
    include_computers: bool = True,
) -> tuple[dict[str, set[str]], dict[str, set[str]], bool]:
    """Build inverted group-membership indices from the snapshot.

    Args:
        snapshot: Prepared membership snapshot (from ``prepare_membership_snapshot``).
        domain: Canonical domain name used for label normalisation.
        exclude_tier0: When True, tier-0 users are excluded from the user index.
        include_computers: When True (default), also build a computer membership
            index from ``computer_to_groups``.  Computers are kept separate from
            users so that execution helpers (which resolve user credentials) are
            not polluted with computer accounts.

    Returns:
        ``(user_group_members, computer_group_members, has_principals)`` where:
        - ``user_group_members``     — ``{group_canonical: {user_labels}}``
        - ``computer_group_members`` — ``{group_canonical: {computer_labels}}``
        - ``has_principals``         — True when at least one user *or* computer
          was found in the snapshot (guards against completely empty snapshots).
    """
    if not snapshot:
        return {}, {}, False

    user_to_groups = snapshot.get("user_to_groups")
    computer_to_groups = snapshot.get("computer_to_groups")
    group_to_parents = snapshot.get("group_to_parents")

    has_users = isinstance(user_to_groups, dict) and bool(user_to_groups)
    has_computers = (
        include_computers
        and isinstance(computer_to_groups, dict)
        and bool(computer_to_groups)
    )

    if not has_users and not has_computers:
        return {}, {}, False

    cache_key = (
        str(domain or "").strip().upper(),
        bool(exclude_tier0),
        bool(include_computers),
    )
    cached = _snapshot_memo_get(_GROUP_MEMBER_INDEX_CACHE, cache_key, snapshot)
    if cached is not None:
        return cached

    user_group_members: dict[str, set[str]] = {}
    computer_group_members: dict[str, set[str]] = {}
    ancestor_cache: dict[str, set[str]] = {}
    parents_map = group_to_parents if isinstance(group_to_parents, dict) else {}

    tier0_users: set[str] = set()
    if exclude_tier0:
        tier0_from_snapshot = snapshot.get("tier0_users")
        if isinstance(tier0_from_snapshot, list):
            tier0_users.update(
                _canonical_membership_label(domain, user)
                for user in tier0_from_snapshot
                if str(user or "").strip()
            )

    def _add_to_index(
        index: dict[str, set[str]],
        principal_label: str,
        direct_groups: list[str],
    ) -> None:
        for group in direct_groups:
            group_label = _canonical_membership_label(domain, group)
            if not group_label:
                continue
            groups_to_add = {group_label}
            groups_to_add.update(
                _expand_group_ancestors(
                    domain, group_label, parents_map, ancestor_cache
                )
            )
            # Sorted: the index's key insertion order is consumer-visible.
            for ancestor in sorted(groups_to_add):
                index.setdefault(ancestor, set()).add(principal_label)

    if has_users:
        for user_label, direct_groups in user_to_groups.items():  # type: ignore[union-attr]
            if not isinstance(direct_groups, list):
                continue
            canonical_user = _canonical_membership_label(domain, user_label)
            if not canonical_user:
                continue
            if exclude_tier0 and canonical_user in tier0_users:
                continue
            _add_to_index(user_group_members, canonical_user, direct_groups)

    if has_computers:
        for computer_label, direct_groups in computer_to_groups.items():  # type: ignore[union-attr]
            if not isinstance(direct_groups, list):
                continue
            canonical_computer = _canonical_membership_label(domain, computer_label)
            if not canonical_computer:
                continue
            _add_to_index(computer_group_members, canonical_computer, direct_groups)

    result = (user_group_members, computer_group_members, has_users or has_computers)
    _snapshot_memo_set(_GROUP_MEMBER_INDEX_CACHE, cache_key, snapshot, result)
    return result
