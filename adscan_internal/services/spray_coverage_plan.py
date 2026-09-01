"""Pure-logic spray coverage planner.

Turns (password policy + per-user effective badPwdCount + the granular spray
history) into a per-type decision: which (user,password) combos to spray NOW
(uncovered AND lockout-eligible), which to DEFER (uncovered but near-threshold),
and which are already COVERED. No I/O, no network — fully unit-testable.

``passwords_for_type[t]`` semantics:
  * ``None``  -> username-as-password (one combo (u, u) per user).
  * ``str``   -> a single shared password sprayed to every user (reuse / blank).
  * ``dict``  -> per-user password mapping (adaptive-year / variation plans).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Mapping


@dataclass(frozen=True)
class TypePlan:
    spray_type: str
    spray_now: list[tuple[tuple[str, str], float | None]] = field(default_factory=list)
    defer: list[tuple[tuple[str, str], float | None]] = field(default_factory=list)
    covered_count: int = 0
    planned_count: int = 0

    @property
    def default_on(self) -> bool:
        return bool(self.spray_now) or bool(self.defer)

    @property
    def fully_covered(self) -> bool:
        return self.planned_count > 0 and not self.spray_now and not self.defer


@dataclass(frozen=True)
class SprayCoveragePlan:
    by_type: dict[str, TypePlan]
    # ``lockout_disabled`` means the DC was OBSERVED to enforce no lockout
    # (``lockoutThreshold <= 0``). ``lockout_unknown`` means the policy has not
    # been read yet (``lockout_threshold is None``) — the two are NOT the same:
    # an unknown threshold can still lock real accounts and must never be
    # labelled "disabled". Behaviourally both spray every eligible combo (no
    # eligibility margin to apply), but the caller renders a different note.
    lockout_disabled: bool = False
    lockout_unknown: bool = False


def _password_for(spec, user: str) -> str:
    if spec is None:
        return user
    if isinstance(spec, Mapping):
        return str(spec.get(user) or "")
    return str(spec)


def build_spray_coverage_plan(
    *,
    types: Iterable[str],
    users: Iterable[str],
    badpwd_by_user: Mapping[str, int],
    passwords_for_type: Mapping[str, object],
    already_attempted: set[tuple[str, str]],
    lockout_threshold: int | None,
    margin: int = 2,
    earliest_safe_by_user: Mapping[str, float] | None = None,
) -> SprayCoveragePlan:
    users = list(users)
    earliest_safe_by_user = earliest_safe_by_user or {}
    # Split "observed disabled" (threshold <= 0) from "not yet known" (None).
    # ``not None`` used to collapse UNKNOWN into "disabled" — the mislabel bug.
    lockout_unknown = lockout_threshold is None
    lockout_disabled = lockout_threshold is not None and int(lockout_threshold) <= 0
    attempted_norm = {(u.casefold(), p) for (u, p) in already_attempted}

    def _eligible(user: str) -> bool:
        # No usable threshold (disabled OR unknown) → no eligibility margin to
        # apply, so every combo is eligible. Behaviour is unchanged from before;
        # only the rendered label distinguishes the two states.
        if lockout_disabled or lockout_unknown:
            return True
        used = int(badpwd_by_user.get(user, 0))
        return (used + 1) <= (int(lockout_threshold) - int(margin))

    by_type: dict[str, TypePlan] = {}
    for t in types:
        spec = passwords_for_type.get(t)
        spray_now: list[tuple[tuple[str, str], float | None]] = []
        defer: list[tuple[tuple[str, str], float | None]] = []
        covered = 0
        planned = 0
        for user in users:
            pwd = _password_for(spec, user)
            if not user or pwd is None:
                continue
            combo = (user.casefold(), pwd)
            planned += 1
            if combo in attempted_norm:
                covered += 1
                continue
            if _eligible(user):
                spray_now.append((combo, None))
            else:
                defer.append((combo, earliest_safe_by_user.get(user)))
        by_type[t] = TypePlan(
            spray_type=t, spray_now=spray_now, defer=defer,
            covered_count=covered, planned_count=planned,
        )
    return SprayCoveragePlan(
        by_type=by_type,
        lockout_disabled=lockout_disabled,
        lockout_unknown=lockout_unknown,
    )


# Full spray-type priority order for sorting a caller-supplied set that MAY
# include pre2k. This differs from spraying._SPRAY_CI_TYPES BY DESIGN — do NOT
# unify them:
#   * `pre2k` (machine-account spray) is kept HERE at the front because callers
#     of ordered_spray_types() may pass it in and it must sort first; but it is
#     absent from _SPRAY_CI_TYPES because machine accounts never lock out and are
#     handled in their own step, OUTSIDE the user-account coverage selector.
#   * month/season is TWO types (month_year, season_year) — one per coverage
#     pass — not the old single `month_season`, so ci sprays both.
# The relative order of the user-account types matches _SPRAY_CI_TYPES; keep them
# in lockstep on those, differing only by pre2k's presence.
_SEQUENCE = ("pre2k", "useraspass", "month_year", "season_year", "reuse", "blank")


def ordered_spray_types(selected: Iterable[str]) -> list[str]:
    """Return the selected types in the fixed priority sequence (unknown types last, stable)."""
    selected = list(selected)
    known = [t for t in _SEQUENCE if t in selected]
    extra = [t for t in selected if t not in _SEQUENCE]
    return known + extra
