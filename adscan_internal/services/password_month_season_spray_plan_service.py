"""Adaptive month/season + year spraying plan helpers.

For an authenticated (``type=audit``) engagement, each user's ``pwdLastSet``
tells us the month and year they last changed their password. Forced-rotation
policies push users toward ``<current-period><year>`` passwords, so the single
strongest guess per user is the month/season word of *their* last change plus
that year (``March2026``, ``Spring2026``, ``Verano2026``).

This mirrors :mod:`password_year_spray_plan_service`: it reuses the lockout-aware
eligible-user set and produces exactly ONE combo per eligible user, preserving
the anti-lockout safety boundary. Language and symbol variants live in
:mod:`password_month_season_generator`; this planner selects the single
highest-priority candidate per user so a spray never spends more than one
attempt per account.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from adscan_internal import telemetry
from adscan_internal.rich_output import mark_sensitive, print_info_debug
from adscan_internal.services.password_month_season_generator import (
    generate_month_season_variations,
)
from adscan_internal.services.password_year_variant_service import (
    epoch_seconds_to_year_month,
)
from adscan_core.rich_output import print_exception


PwdLastSetSource = Literal["bloodhound"]
_BLOODHOUND_PWDLASTSET_USER_CHUNK_SIZE = 500


@dataclass(frozen=True)
class AdaptiveMonthSeasonCombo:
    """One per-user month/season password combo derived from a pwdLastSet date."""

    username: str
    password: str
    pwdlastset_year: int
    pwdlastset_month: int
    rule: str
    source: PwdLastSetSource


@dataclass(frozen=True)
class AdaptiveMonthSeasonPlan:
    """Adaptive month/season spray plan for eligible users (one combo each)."""

    combos: tuple[AdaptiveMonthSeasonCombo, ...]
    languages: tuple[str, ...]
    source: PwdLastSetSource


def build_adaptive_month_season_plan(
    *,
    users: list[str],
    pwdlastset_dates_by_user: dict[str, tuple[int, int]],
    languages: tuple[str, ...] = ("en", "es"),
    source: PwdLastSetSource = "bloodhound",
    kinds: tuple[str, ...] = ("month", "season"),
) -> AdaptiveMonthSeasonPlan | None:
    """Build one month/season combo per eligible user from pwdLastSet dates.

    The safety boundary is one generated combo per eligible user: the single
    highest-priority candidate for that user's ``(month, year)``.

    Args:
        users: Eligible users from the lockout-aware spraying planner.
        pwdlastset_dates_by_user: Mapping of lowercase username to
            ``(year, month)`` of the user's last password change.
        languages: Languages to generate, in order.
        source: Source used for the pwdLastSet values.
        kinds: Which candidate kinds to consider (``"month"`` / ``"season"``).
            Restricting to a single kind is how the ``month_year`` and
            ``season_year`` coverage passes each build their own one-combo-per-user
            plan. Symbols are intentionally excluded from the threshold spray flow
            (``Word+Year`` only) — the destructive ``!@#`` forms are reserved for
            the lockout-free expansion path, not this one-attempt-per-user pass.

    Returns:
        Adaptive plan, or ``None`` when no eligible user has usable pwdLastSet
        data.
    """
    combos: list[AdaptiveMonthSeasonCombo] = []
    seen_users: set[str] = set()
    for raw_user in users:
        username = str(raw_user or "").strip()
        if not username:
            continue
        user_key = username.casefold()
        if user_key in seen_users:
            continue
        seen_users.add(user_key)
        date = pwdlastset_dates_by_user.get(user_key)
        if date is None:
            continue
        year, month = date
        candidates = generate_month_season_variations(
            month=month,
            year=year,
            languages=languages,
            include_symbols=False,
            kinds=kinds,
        )
        if not candidates:
            continue
        # One combo per user: the single strongest candidate (plain Month+Year).
        top = candidates[0]
        combos.append(
            AdaptiveMonthSeasonCombo(
                username=username,
                password=top.password,
                pwdlastset_year=year,
                pwdlastset_month=month,
                rule=top.rule,
                source=source,
            )
        )

    if not combos:
        return None
    return AdaptiveMonthSeasonPlan(
        combos=tuple(combos),
        languages=languages,
        source=source,
    )


def resolve_bloodhound_pwdlastset_dates(
    shell: Any,
    *,
    domain: str,
    users: list[str],
) -> dict[str, tuple[int, int]]:
    """Resolve ``(year, month)`` of each user's last password change.

    Args:
        shell: Active shell exposing graph service access.
        domain: Target domain.
        users: Eligible users to resolve.

    Returns:
        Mapping keyed by lowercase username to ``(year, month)``.
    """
    wanted_users = {str(user or "").strip().casefold() for user in users}
    wanted_users.discard("")
    if not wanted_users:
        return {}

    try:
        service_getter = getattr(shell, "_get_graph_service", None)
        if not callable(service_getter):
            return {}
        service = service_getter()
        records: list[dict[str, Any]] = []
        wanted_user_list = sorted(wanted_users)
        for start in range(0, len(wanted_user_list), _BLOODHOUND_PWDLASTSET_USER_CHUNK_SIZE):
            chunk = wanted_user_list[start : start + _BLOODHOUND_PWDLASTSET_USER_CHUNK_SIZE]
            chunk_records = service.get_password_last_change(domain, users=chunk)
            if isinstance(chunk_records, list):
                records.extend(record for record in chunk_records if isinstance(record, dict))
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            "[adaptive-month-season-spray] pwdLastSet batch lookup failed for "
            f"{mark_sensitive(domain, 'domain')}: {exc}"
        )
        return {}

    dates_by_user: dict[str, tuple[int, int]] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        username = str(record.get("samaccountname") or "").strip()
        user_key = username.casefold()
        if user_key not in wanted_users:
            continue
        year_month = epoch_seconds_to_year_month(record.get("pwdlastset"))
        if year_month is None:
            continue
        dates_by_user[user_key] = year_month
    return dates_by_user


def resolve_adaptive_month_season_plan(
    shell: Any,
    *,
    domain: str,
    users: list[str],
    languages: tuple[str, ...] = ("en", "es"),
    kinds: tuple[str, ...] = ("month", "season"),
) -> AdaptiveMonthSeasonPlan | None:
    """Resolve an adaptive month/season plan for eligible users.

    Args:
        shell: Active shell.
        domain: Target domain.
        users: Lockout-eligible users.
        languages: Languages to generate, in order.
        kinds: Which candidate kinds to consider (``"month"`` / ``"season"``) —
            lets the ``month_year`` and ``season_year`` coverage passes each build
            their own plan.

    Returns:
        Adaptive plan based on pwdLastSet data, or ``None``.
    """
    pwdlastset_dates = resolve_bloodhound_pwdlastset_dates(shell, domain=domain, users=users)
    return build_adaptive_month_season_plan(
        users=users,
        pwdlastset_dates_by_user=pwdlastset_dates,
        languages=languages,
        source="bloodhound",
        kinds=kinds,
    )
