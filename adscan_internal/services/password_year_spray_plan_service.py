"""Adaptive password-year spraying plan helpers.

This module converts one password pattern with a year token into per-user
``username:password`` combos based on each user's password-last-set year.  It
reuses the central password-year token parser so single-user credential repair
and spraying workflows share the same year heuristics.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from adscan_internal import telemetry
from adscan_internal.rich_output import mark_sensitive, print_info_debug
from adscan_internal.services.password_year_variant_service import (
    extract_password_year_candidates,
    replace_password_year_candidate,
)


PwdLastSetSource = Literal["bloodhound"]
_BLOODHOUND_PWDLASTSET_USER_CHUNK_SIZE = 500


@dataclass(frozen=True)
class AdaptiveYearSprayCombo:
    """One per-user password combo derived from a pwdLastSet year."""

    username: str
    password: str
    pwdlastset_year: int
    source: PwdLastSetSource


@dataclass(frozen=True)
class AdaptiveYearSprayPlan:
    """Adaptive year spray plan for one base password."""

    base_password: str
    original_year: int
    token_kind: str
    combos: tuple[AdaptiveYearSprayCombo, ...]
    source: PwdLastSetSource


def build_adaptive_year_spray_plan(
    *,
    base_password: str,
    users: list[str],
    pwdlastset_years_by_user: dict[str, int],
    source: PwdLastSetSource,
) -> AdaptiveYearSprayPlan | None:
    """Build per-user combos for a password with one clear year token.

    Unlike same-user credential repair, adaptive spraying intentionally allows
    earlier and later years because each target user gets their own pwdLastSet
    year.  The safety boundary is one generated combo per eligible user.

    Args:
        base_password: Password pattern selected for spraying.
        users: Eligible users from the lockout-aware spraying planner.
        pwdlastset_years_by_user: Mapping of lowercase username to pwdLastSet year.
        source: Source used for pwdLastSet values.

    Returns:
        Adaptive plan, or ``None`` when the password has no unambiguous year
        token or no target user has pwdLastSet data.
    """
    candidates = extract_password_year_candidates(base_password)
    if len(candidates) != 1:
        return None

    candidate = candidates[0]
    combos: list[AdaptiveYearSprayCombo] = []
    seen_users: set[str] = set()
    for raw_user in users:
        username = str(raw_user or "").strip()
        if not username:
            continue
        user_key = username.casefold()
        if user_key in seen_users:
            continue
        seen_users.add(user_key)
        pwdlastset_year = pwdlastset_years_by_user.get(user_key)
        if pwdlastset_year is None:
            continue
        password = replace_password_year_candidate(
            base_password,
            candidate,
            pwdlastset_year,
        )
        if not password:
            continue
        combos.append(
            AdaptiveYearSprayCombo(
                username=username,
                password=password,
                pwdlastset_year=pwdlastset_year,
                source=source,
            )
        )

    if not combos:
        return None
    return AdaptiveYearSprayPlan(
        base_password=base_password,
        original_year=candidate.year,
        token_kind=candidate.kind,
        combos=tuple(combos),
        source=source,
    )


def resolve_bloodhound_pwdlastset_years(
    shell: Any,
    *,
    domain: str,
    users: list[str],
) -> dict[str, int]:
    """Resolve pwdLastSet years for many users from BloodHound.

    Args:
        shell: Active shell exposing ``_get_bloodhound_service``.
        domain: Target domain.
        users: Eligible users to resolve.

    Returns:
        Mapping keyed by lowercase username.
    """
    wanted_users = {str(user or "").strip().casefold() for user in users}
    wanted_users.discard("")
    if not wanted_users:
        return {}

    try:
        service = shell._get_bloodhound_service()
        records: list[dict[str, Any]] = []
        wanted_user_list = sorted(wanted_users)
        for start in range(
            0,
            len(wanted_user_list),
            _BLOODHOUND_PWDLASTSET_USER_CHUNK_SIZE,
        ):
            chunk = wanted_user_list[
                start : start + _BLOODHOUND_PWDLASTSET_USER_CHUNK_SIZE
            ]
            chunk_records = service.get_password_last_change(domain, users=chunk)
            if isinstance(chunk_records, list):
                records.extend(
                    record for record in chunk_records if isinstance(record, dict)
                )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            "[adaptive-year-spray] BloodHound pwdLastSet batch lookup failed for "
            f"{mark_sensitive(domain, 'domain')}: {exc}"
        )
        return {}

    if not isinstance(records, list):
        return {}

    from adscan_internal.services.password_year_variant_service import (
        epoch_seconds_to_year,
    )

    years_by_user: dict[str, int] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        username = str(record.get("samaccountname") or "").strip()
        user_key = username.casefold()
        if user_key not in wanted_users:
            continue
        year = epoch_seconds_to_year(record.get("pwdlastset"))
        if year is None:
            continue
        years_by_user[user_key] = year
    return years_by_user


def resolve_adaptive_year_spray_plan(
    shell: Any,
    *,
    domain: str,
    base_password: str,
    users: list[str],
) -> AdaptiveYearSprayPlan | None:
    """Resolve an adaptive year spray plan for eligible users.

    Args:
        shell: Active shell.
        domain: Target domain.
        base_password: Password selected for spraying.
        users: Lockout-eligible users.

    Returns:
        Adaptive plan based on BloodHound data, or ``None``.
    """
    if len(extract_password_year_candidates(base_password)) != 1:
        return None
    pwdlastset_years = resolve_bloodhound_pwdlastset_years(
        shell,
        domain=domain,
        users=users,
    )
    return build_adaptive_year_spray_plan(
        base_password=base_password,
        users=users,
        pwdlastset_years_by_user=pwdlastset_years,
        source="bloodhound",
    )
