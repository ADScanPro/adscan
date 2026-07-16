"""Canonical Privilege-Tier resolver for a principal, from real membership data.

This is the SSOT for "what Privilege Tier (axis 1) is a USER principal GRANTED"
when the caller has only a username. It resolves the principal's TRANSITIVE group
memberships from the membership snapshot (``memberships.json``, the group-
membership SSOT) and feeds them to the canonical
:func:`compromise_class.privilege_tier_for_principal` /
:func:`compromise_class.classify_principal_by_groups` — the same group->tier
classifier (4-way, directness-graded) the rest of the product uses.

Why this exists: the harvest tier column previously used the legacy
``high_value.classify_users_tier0_high_value`` (BloodHound ``isTierZero`` /
``highvalue`` node flags + RID/admins.txt fallbacks). Those flags are set to
False on the SYNTHETIC fallback nodes an unauthenticated scan writes, so a real
Domain Admin (e.g. ``robb.stark``, a member of BUILTIN\\Administrators) graded a
false "Tier 2: Standard". Reading the actual MemberOf edges and classifying by
the canonical group sets kills that false positive at the root.

UNDETERMINED (``None``) is returned whenever there is NO membership data for the
principal — no ``memberships.json`` (unauth / pre-collection), or the principal
is not present in it. That is distinct from a genuine TIER2 (the principal IS in
the membership data and simply holds no Tier-0 group). Best-effort; never raises.
"""
from __future__ import annotations

from typing import Any

from adscan_core import telemetry
from adscan_internal.services.compromise_class import (
    PrivilegeTier,
    privilege_tier_for_principal,
)
from adscan_internal.services.high_value import normalize_samaccountname


def _rid_from_sid(sid: str | None) -> int | None:
    """Return the trailing RID of a SID, or ``None``."""
    if not sid:
        return None
    try:
        return int(str(sid).strip().rstrip("/").rsplit("-", 1)[-1])
    except (ValueError, IndexError):
        return None


def _load_tier_membership_snapshot(shell: Any, domain: str) -> dict[str, Any] | None:
    """Load the augmented membership snapshot (the SSOT loader). Never raises."""
    try:
        from adscan_internal.services.attack_graph_service import (  # noqa: PLC0415
            _load_membership_snapshot,
        )

        snapshot = _load_membership_snapshot(shell, domain)
        return snapshot if isinstance(snapshot, dict) else None
    except Exception as exc:  # noqa: BLE001 — a membership read is best-effort
        telemetry.capture_exception(exc)
        return None


def _expand_transitive_groups(
    user_label: str,
    user_to_groups: dict[str, Any],
    group_to_parents: dict[str, Any],
) -> set[str]:
    """Return every group label the user belongs to, transitively.

    Starts from the user's DIRECT groups (``user_to_groups``) and follows nested
    group memberships (``group_to_parents``) breadth-first, so a user who is a
    member of a group that is itself a member of Domain Admins is classified as
    Tier 0. Cycle-safe via the visited set.
    """
    seen: set[str] = set()
    queue: list[str] = [g for g in (user_to_groups.get(user_label) or []) if g]
    while queue:
        group = queue.pop()
        if group in seen:
            continue
        seen.add(group)
        for parent in group_to_parents.get(group) or []:
            if parent and parent not in seen:
                queue.append(parent)
    return seen


def resolve_user_privilege_tier(
    shell: Any, *, domain: str, username: str
) -> PrivilegeTier | None:
    """Return the :class:`PrivilegeTier` a USER principal IS GRANTED, or ``None``.

    Reads the principal's transitive group memberships from the membership
    snapshot and classifies them with the canonical
    :func:`privilege_tier_for_principal`. The group tokens are the memberships'
    resolved SIDs (RID-accurate: ``S-1-5-32-544`` -> BUILTIN\\Administrators ->
    Tier 0 direct) with a fall-back to the group label name (which the canonical
    classifier also matches, e.g. ``DOMAIN ADMINS``). The principal's own SID/RID
    is passed too, so the built-in Administrator (RID 500) / krbtgt (502)
    classify as Tier 0 direct by their own RID.

    Returns:
        The :class:`PrivilegeTier` when the principal HAS membership data (a real
        TIER2 verdict is trustworthy — the user is genuinely non-Tier-0), or
        ``None`` (UNDETERMINED) when there is no membership data for the
        principal: no ``memberships.json`` (unauth / pre-collection) or the
        principal is absent from it. Never raises.
    """
    normalized = normalize_samaccountname(username)
    if not normalized:
        return None

    snapshot = _load_tier_membership_snapshot(shell, domain)
    if not isinstance(snapshot, dict):
        return None
    user_to_groups = snapshot.get("user_to_groups")
    if not isinstance(user_to_groups, dict) or not user_to_groups:
        return None
    label_to_sid = (
        snapshot.get("label_to_sid")
        if isinstance(snapshot.get("label_to_sid"), dict)
        else {}
    )
    group_to_parents = (
        snapshot.get("group_to_parents")
        if isinstance(snapshot.get("group_to_parents"), dict)
        else {}
    )

    # Resolve the user's canonical label (case-insensitive sAMAccountName match).
    user_label: str | None = None
    for label in user_to_groups:
        if normalize_samaccountname(str(label)) == normalized:
            user_label = str(label)
            break
    if user_label is None:
        # The principal is not present in the enumerated membership data → we
        # cannot determine its tier. UNDETERMINED, not a false TIER2.
        return None

    group_labels = _expand_transitive_groups(user_label, user_to_groups, group_to_parents)
    # Prefer the RID-accurate SID token; fall back to the group label name (the
    # canonical classifier matches both — well-known RIDs via SID, named groups
    # like "Domain Admins" via name).
    group_tokens = [str(label_to_sid.get(label, label)) for label in group_labels]
    user_sid = label_to_sid.get(user_label)
    rid = _rid_from_sid(user_sid if isinstance(user_sid, str) else None)

    try:
        return privilege_tier_for_principal(
            group_tokens, sid=user_sid if isinstance(user_sid, str) else None, rid=rid
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return None


__all__ = ["resolve_user_privilege_tier"]
