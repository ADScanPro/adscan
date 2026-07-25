"""Variation spray plan builder for lockout-free spraying.

Loads password_compliance.json from the workspace, partitions
eligible users into cohorts, applies per-cohort policy filters, and
truncates to a budget cap using variation-major emission order.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from adscan_internal import telemetry
from adscan_internal.rich_output import print_info_debug
from adscan_internal.services.collector.models import (
    PasswordComplianceReport,
    UserPasswordCompliance,
)
from adscan_internal.services.password_variation_generator import (
    generate_variations,
)
from adscan_core.rich_output import print_exception

_LEGACY_AGE_THRESHOLD_DAYS: int = 730


class UserCohort(str, Enum):
    COMPLIANT = "compliant"
    LEGACY = "legacy"


@dataclass(frozen=True)
class VariationCombo:
    """One username/password combo produced by the variation planner."""

    username: str
    password: str
    base_password: str
    tier: int
    rule: str
    cohort: UserCohort


@dataclass(frozen=True)
class VariationSprayPlan:
    """Full variation spray plan ready for execution.

    Attributes:
        base_password: Original seed password.
        max_tier: Highest tier included in the plan.
        budget: Maximum authentications cap.
        combos: Ordered variation combos (variation-major, truncated to budget).
        cohort_compliant_count: Number of users in the compliant cohort.
        cohort_legacy_count: Number of users in the legacy cohort.
        policy_never_modified: True if the domain policy was never explicitly
            changed by an admin (all users get policy-aware filter).
        truncated: True if budget cap was hit.
        truncated_at_tier: Tier where truncation occurred (None if not truncated).
        applied_policies: Distinct policy names used for filtering.
        year_sweep_back: How many years the Tier 2/3 year sweep reaches back.
            Computed dynamically from the legacy cohort's oldest pwdLastSet,
            falling back to the global minimum, then to a static default.
        year_sweep_min: ``current_year - year_sweep_back`` — the earliest year
            included in Tier 2/3 mutations (rendered in the panel for
            transparency).
    """

    base_password: str
    max_tier: int
    budget: int
    combos: tuple[VariationCombo, ...]
    cohort_compliant_count: int
    cohort_legacy_count: int
    policy_never_modified: bool
    truncated: bool
    truncated_at_tier: int | None
    applied_policies: tuple[str, ...]
    year_sweep_back: int = 12
    year_sweep_min: int = 0


_DEFAULT_YEAR_SWEEP_BACK: int = 12
_HARD_CAP_YEAR_SWEEP_BACK: int = 25


def compute_dynamic_year_sweep_back(
    *,
    compliance_report: PasswordComplianceReport | None,
    current_year: int,
    fallback: int = _DEFAULT_YEAR_SWEEP_BACK,
    hard_cap: int = _HARD_CAP_YEAR_SWEEP_BACK,
) -> int:
    """Compute the dynamic ``year_sweep_back`` for Tier 2 / Tier 3 mutations.

    Priority order:

    1. Minimum ``pwd_last_set_iso`` year across the **legacy cohort** —
       these are the users whose passwords most plausibly carry a year
       token from a past rotation cycle. Floor based on real legacy data.
    2. Minimum across all users with valid ``pwd_last_set_iso`` — used
       when no user qualifies for the legacy cohort. Still useful for
       Tier 2 against compliant users with year-based passwords.
    3. ``fallback`` (default 12 years) — when no compliance data is
       available at all (audit-only run, restricted bind, missing
       artifact).

    The result is capped at ``hard_cap`` (default 25 years) to protect
    against impossible outliers (e.g. ``krbtgt`` accounts with
    ``pwdLastSet`` predating the realistic operational window).

    Args:
        compliance_report: Optional compliance report from workspace.
        current_year: Current year integer (e.g. 2026).
        fallback: Static fallback when no data is available.
        hard_cap: Maximum allowed lookback in years.

    Returns:
        ``year_sweep_back`` integer to pass to ``generate_variations``.
    """
    if compliance_report is None or not compliance_report.entries:
        return fallback

    def _year_from_iso(iso: str | None) -> int | None:
        if not iso or len(iso) < 4:
            return None
        try:
            year = int(iso[:4])
        except ValueError:
            return None
        # Sanity range: AD timestamps before 1995 or in the future are bogus.
        if year < 1995 or year > current_year:
            return None
        return year

    legacy_years: list[int] = []
    all_years: list[int] = []
    for entry in compliance_report.entries:
        year = _year_from_iso(entry.pwd_last_set_iso)
        if year is None:
            continue
        all_years.append(year)
        is_legacy = (entry.pwd_predates_policy and entry.pwd_never_expires) or (
            entry.pwd_never_expires
            and entry.pwd_age_days is not None
            and entry.pwd_age_days > 730
        )
        if is_legacy:
            legacy_years.append(year)

    candidate_years = legacy_years if legacy_years else all_years
    if not candidate_years:
        return fallback

    sweep_back = current_year - min(candidate_years)
    return max(0, min(sweep_back, hard_cap))


def _classify_cohort(user: UserPasswordCompliance) -> UserCohort:
    """Classify a user as LEGACY or COMPLIANT for variation filtering.

    Primary signal: pwdLastSet predates current policy AND password
    never expires — the password demonstrably may not satisfy current
    minPwdLength / complexity.

    Secondary signal: password never expires AND age > threshold — the
    password has not rotated in over two years, even if predates_policy
    is False (covers environments where the policy was provisioned once
    and never changed by an admin).
    """
    if user.pwd_predates_policy and user.pwd_never_expires:
        return UserCohort.LEGACY
    if (
        user.pwd_never_expires
        and user.pwd_age_days is not None
        and user.pwd_age_days > _LEGACY_AGE_THRESHOLD_DAYS
    ):
        return UserCohort.LEGACY
    return UserCohort.COMPLIANT


def _meets_policy(
    password: str,
    *,
    min_length: int,
    complexity_enabled: bool,
) -> bool:
    """Return True when ``password`` satisfies the given policy constraints.

    Complexity check: AD requires characters from >= 3 of 4 categories
    (uppercase, lowercase, digit, non-alphanumeric).  We do not check
    username/displayname containment — the generator never embeds
    usernames and per-user checking would require a second loop.
    """
    if len(password) < min_length:
        return False
    if complexity_enabled:
        categories = sum([
            any(c.isupper() for c in password),
            any(c.islower() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        ])
        if categories < 3:
            return False
    return True


def build_variation_spray_plan(
    *,
    base_password: str,
    eligible_users: list[str],
    compliance_report: PasswordComplianceReport | None,
    ddp_min_length: int,
    ddp_complexity: bool,
    pso_policies: dict[str, tuple[int, bool]],  # policy_name -> (min_length, complexity)
    max_tier: int,
    budget: int,
    current_year: int,
) -> VariationSprayPlan:
    """Build a variation spray plan ready for execution.

    Args:
        base_password: Seed password (e.g. "adscan", "Adscan2026").
        eligible_users: Locked-out-aware eligible user list from the
            caller's SprayEligibilityResult.
        compliance_report: Loaded from password_compliance.json.
            Pass None to fall back to "all compliant against DDP".
        ddp_min_length: Default Domain Policy minPwdLength.
        ddp_complexity: Default Domain Policy complexity flag (assumed
            True when not directly available from DomainPolicy).
        pso_policies: Per-PSO policy constraints keyed by
            ``applied_policy_name`` (e.g. "PSO:HighPriv").
        max_tier: Maximum variation tier (1, 2, or 3).
        budget: Maximum combo count before truncation.
        current_year: Year used for year-based mutations.

    Returns:
        VariationSprayPlan with combos in variation-major order,
        truncated to budget.
    """
    # Build compliance index for quick lookup
    compliance_by_user: dict[str, UserPasswordCompliance] = {}
    policy_never_modified = False
    if compliance_report is not None:
        policy_never_modified = compliance_report.policy_never_modified
        for entry in compliance_report.entries:
            compliance_by_user[entry.samaccountname.casefold()] = entry

    # Deduplicate and normalise users
    unique_users: list[str] = []
    seen_users: set[str] = set()
    for raw in eligible_users:
        u = str(raw or "").strip()
        if u and u.casefold() not in seen_users:
            seen_users.add(u.casefold())
            unique_users.append(u)

    # Classify each user into a cohort
    cohort_of: dict[str, UserCohort] = {}
    for u in unique_users:
        entry = compliance_by_user.get(u.casefold())
        if entry is None or policy_never_modified:
            cohort_of[u] = UserCohort.COMPLIANT
        else:
            cohort_of[u] = _classify_cohort(entry)

    compliant_users = [u for u in unique_users if cohort_of[u] == UserCohort.COMPLIANT]
    legacy_users = [u for u in unique_users if cohort_of[u] == UserCohort.LEGACY]

    # Compute the dynamic year sweep range (Tier 2 + Tier 3 use this).
    year_sweep_back = compute_dynamic_year_sweep_back(
        compliance_report=compliance_report,
        current_year=current_year,
    )

    # Generate the full variation set (deduplicated, tier-prioritised)
    variations = generate_variations(
        base_password,
        max_tier=max_tier,
        current_year=current_year,
        year_sweep_back=year_sweep_back,
    )

    # Helper: resolve policy constraints for a user
    def _policy_for(username: str) -> tuple[int, bool]:
        entry = compliance_by_user.get(username.casefold())
        if entry is not None and entry.applied_policy_name != "DDP":
            pso_key = entry.applied_policy_name
            if pso_key in pso_policies:
                return pso_policies[pso_key]
        return (ddp_min_length, ddp_complexity)

    # Variation-major emission: every user gets variation[0] before any
    # user gets variation[1], etc.  This guarantees no user is starved.
    combos: list[VariationCombo] = []
    truncated = False
    truncated_at_tier: int | None = None
    applied_policies: set[str] = set()

    for var in variations:
        # Compliant cohort with policy filter
        for u in compliant_users:
            min_len, complexity = _policy_for(u)
            entry = compliance_by_user.get(u.casefold())
            applied_policies.add(entry.applied_policy_name if entry is not None else "DDP")
            if not _meets_policy(var.password, min_length=min_len, complexity_enabled=complexity):
                continue
            combos.append(VariationCombo(
                username=u,
                password=var.password,
                base_password=base_password,
                tier=var.tier,
                rule=var.rule,
                cohort=UserCohort.COMPLIANT,
            ))
            if len(combos) >= budget:
                truncated = True
                truncated_at_tier = var.tier
                break
        if truncated:
            break

        # Legacy cohort — no policy filter
        for u in legacy_users:
            entry = compliance_by_user.get(u.casefold())
            if entry:
                applied_policies.add(entry.applied_policy_name)
            combos.append(VariationCombo(
                username=u,
                password=var.password,
                base_password=base_password,
                tier=var.tier,
                rule=var.rule,
                cohort=UserCohort.LEGACY,
            ))
            if len(combos) >= budget:
                truncated = True
                truncated_at_tier = var.tier
                break
        if truncated:
            break

    return VariationSprayPlan(
        base_password=base_password,
        max_tier=max_tier,
        budget=budget,
        combos=tuple(combos),
        cohort_compliant_count=len(compliant_users),
        cohort_legacy_count=len(legacy_users),
        policy_never_modified=policy_never_modified,
        truncated=truncated,
        truncated_at_tier=truncated_at_tier,
        applied_policies=tuple(sorted(applied_policies)),
        year_sweep_back=year_sweep_back,
        year_sweep_min=current_year - year_sweep_back,
    )


def load_compliance_report_from_workspace(
    inventory_dir: str | Path,
) -> PasswordComplianceReport | None:
    """Load and reconstruct PasswordComplianceReport from workspace JSON.

    Returns None on any error (missing file, bad JSON, schema mismatch)
    so callers fall back gracefully to "all compliant against DDP".

    The persistence layer (_write_password_compliance_file) stores user
    counts under a nested "totals" key.  This loader accepts both the
    nested form (from real workspace files) and flat top-level keys
    (for test fixtures and forward-compat).
    """
    path = Path(inventory_dir) / "password_compliance.json"
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None

    try:
        raw_entries = data.get("entries", [])
        entries: list[UserPasswordCompliance] = []
        for e in raw_entries:
            entries.append(UserPasswordCompliance(
                samaccountname=str(e.get("samaccountname") or ""),
                object_id=str(e.get("object_id") or ""),
                distinguished_name=str(e.get("distinguished_name") or ""),
                enabled=bool(e.get("enabled", True)),
                is_admin_like=bool(e.get("is_admin_like", False)),
                pwd_last_set_filetime=e.get("pwd_last_set_filetime"),
                pwd_last_set_iso=e.get("pwd_last_set_iso"),
                pwd_age_days=e.get("pwd_age_days"),
                applied_policy_name=str(e.get("applied_policy_name") or "DDP"),
                applied_policy_dn=str(e.get("applied_policy_dn") or ""),
                applied_policy_when_changed=e.get("applied_policy_when_changed"),
                pwd_predates_policy=bool(e.get("pwd_predates_policy", False)),
                pwd_over_max_age=bool(e.get("pwd_over_max_age", False)),
                pwd_never_expires=bool(e.get("pwd_never_expires", False)),
                risk_level=str(e.get("risk_level") or "info"),
                notes=tuple(e.get("notes") or []),
            ))

        # Resolve user-count fields — the persistence layer nests them under
        # "totals"; test fixtures may provide them at the top level.
        totals: dict[str, Any] = data.get("totals") or {}
        users_total = int(
            totals.get("users") or data.get("users_total") or len(entries)
        )
        users_with_predates_policy = int(
            totals.get("users_with_predates_policy")
            or data.get("users_with_predates_policy")
            or 0
        )
        users_with_over_max_age = int(
            totals.get("users_with_over_max_age")
            or data.get("users_with_over_max_age")
            or 0
        )
        users_with_never_expires = int(
            totals.get("users_with_never_expires")
            or data.get("users_with_never_expires")
            or 0
        )

        raw_attrs = data.get("policy_pwd_attrs") or []
        policy_pwd_attrs: tuple[tuple[str, str, int], ...] = tuple(
            (str(t[0]), str(t[1]), int(t[2])) for t in raw_attrs if len(t) >= 3
        )

        return PasswordComplianceReport(
            domain=str(data.get("domain") or ""),
            policy_pwd_last_changed=data.get("policy_pwd_last_changed"),
            policy_never_modified=bool(data.get("policy_never_modified", False)),
            policy_pwd_attrs=policy_pwd_attrs,
            psos_count=int(data.get("psos_count") or 0),
            users_total=users_total,
            users_with_predates_policy=users_with_predates_policy,
            users_with_over_max_age=users_with_over_max_age,
            users_with_never_expires=users_with_never_expires,
            entries=tuple(entries),
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[variation-spray] failed to parse password_compliance.json: {exc}")
        return None


def load_ddp_policy_from_workspace(
    inventory_dir: str | Path,
) -> tuple[int, bool]:
    """Return (min_pwd_length, complexity_enabled) from domain_policy.json.

    Falls back to (7, True) — the Windows historical defaults — when the
    file is missing or the field is absent.  Never raises.
    """
    path = Path(inventory_dir) / "domain_policy.json"
    _default_min = 7
    _default_complexity = True
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        policy = data.get("policy", {})
        min_len = policy.get("min_pwd_length")
        min_len = int(min_len) if min_len is not None else _default_min
        # DomainPolicy does not expose complexity as a boolean;
        # conservatively assume complexity is enabled.
        return (min_len, _default_complexity)
    except Exception:  # noqa: BLE001
        return (_default_min, _default_complexity)
