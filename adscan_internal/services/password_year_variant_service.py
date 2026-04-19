"""Password year-rollover suggestion helpers.

These helpers keep failed credential repair logic separate from the interactive
credential verification flow.  The first supported signal is BloodHound
``pwdlastset`` data: when a password contains a clear year and the target user
changed their password in a later year, ADscan can offer one same-user retry
with the year replaced.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Any, Literal

from adscan_internal import telemetry
from adscan_internal.rich_output import mark_sensitive, print_info_debug


PwdLastSetSource = Literal["bloodhound"]
PasswordYearTokenKind = Literal["four_digit", "two_digit"]

_FOUR_DIGIT_YEAR_RE = re.compile(r"(?<!\d)(20[0-3]\d|19[9]\d)(?!\d)")
_TWO_DIGIT_YEAR_RE = re.compile(r"(?<!\d)([2-3]\d)(?!\d)")


@dataclass(frozen=True)
class PasswordYearVariantSuggestion:
    """Suggested same-user password retry derived from ``pwdLastSet``."""

    original_password: str
    suggested_password: str
    original_year: int
    pwdlastset_year: int
    username: str
    source: PwdLastSetSource
    token_kind: PasswordYearTokenKind = "four_digit"


@dataclass(frozen=True)
class PasswordYearCandidate:
    """One unambiguous year-like token found in a password."""

    token: str
    year: int
    kind: PasswordYearTokenKind


def extract_password_years(password: str) -> list[int]:
    """Extract distinct plausible four-digit years from a password.

    Args:
        password: Password candidate that failed validation.

    Returns:
        Distinct years in appearance order.
    """
    seen: set[int] = set()
    years: list[int] = []
    for match in _FOUR_DIGIT_YEAR_RE.finditer(str(password or "")):
        year = int(match.group(1))
        if year not in seen:
            years.append(year)
            seen.add(year)
    return years


def extract_password_year_candidates(password: str) -> list[PasswordYearCandidate]:
    """Extract plausible year tokens from a password.

    Four-digit years are high-confidence and take priority.  Two-digit years are
    only considered when no full year is present and the token is a standalone
    digit run such as ``25`` in ``Password25@``.

    Args:
        password: Password candidate that failed validation.

    Returns:
        Distinct year candidates in appearance order.
    """
    value = str(password or "")
    four_digit_candidates: list[PasswordYearCandidate] = []
    seen_four_digit_years: set[int] = set()
    for match in _FOUR_DIGIT_YEAR_RE.finditer(value):
        token = match.group(1)
        year = int(token)
        if year in seen_four_digit_years:
            continue
        four_digit_candidates.append(
            PasswordYearCandidate(token=token, year=year, kind="four_digit")
        )
        seen_four_digit_years.add(year)
    if four_digit_candidates:
        return four_digit_candidates

    two_digit_candidates: list[PasswordYearCandidate] = []
    seen_two_digit_years: set[int] = set()
    for match in _TWO_DIGIT_YEAR_RE.finditer(value):
        token = match.group(1)
        year = 2000 + int(token)
        if year in seen_two_digit_years:
            continue
        two_digit_candidates.append(
            PasswordYearCandidate(token=token, year=year, kind="two_digit")
        )
        seen_two_digit_years.add(year)
    return two_digit_candidates


def replace_password_year(password: str, old_year: int, new_year: int) -> str:
    """Replace one unambiguous four-digit year token in ``password``.

    Args:
        password: Original password.
        old_year: Year token to replace.
        new_year: Replacement year.

    Returns:
        Password with the first matching standalone year token replaced.
    """
    pattern = re.compile(rf"(?<!\d){re.escape(str(old_year))}(?!\d)")
    return pattern.sub(str(new_year), password, count=1)


def replace_password_year_candidate(
    password: str, candidate: PasswordYearCandidate, new_year: int
) -> str:
    """Replace one year candidate while preserving its original token width.

    Args:
        password: Original password.
        candidate: Year token selected for replacement.
        new_year: Replacement year.

    Returns:
        Password with the first matching candidate token replaced.
    """
    replacement = str(new_year)[-2:] if candidate.kind == "two_digit" else str(new_year)
    pattern = re.compile(rf"(?<!\d){re.escape(candidate.token)}(?!\d)")
    return pattern.sub(replacement, password, count=1)


def build_pwdlastset_year_variant(
    *,
    password: str,
    username: str,
    pwdlastset_year: int | None,
    source: PwdLastSetSource,
) -> PasswordYearVariantSuggestion | None:
    """Build a year-rollover suggestion when the signal is unambiguous.

    Args:
        password: Failed password candidate.
        username: Target username.
        pwdlastset_year: Year derived from the user's password last-set value.
        source: Source used for the ``pwdLastSet`` signal.

    Returns:
        A suggestion, or ``None`` when no safe single retry should be offered.
    """
    if pwdlastset_year is None:
        return None

    candidates = extract_password_year_candidates(password)
    if len(candidates) != 1:
        return None

    candidate = candidates[0]
    original_year = candidate.year
    if pwdlastset_year <= original_year:
        return None

    suggested_password = replace_password_year_candidate(
        password, candidate, pwdlastset_year
    )
    if not suggested_password or suggested_password == password:
        return None

    return PasswordYearVariantSuggestion(
        original_password=password,
        suggested_password=suggested_password,
        original_year=original_year,
        pwdlastset_year=pwdlastset_year,
        username=username,
        source=source,
        token_kind=candidate.kind,
    )


def epoch_seconds_to_year(value: object) -> int | None:
    """Convert BloodHound epoch-second ``pwdlastset`` values to a UTC year.

    Args:
        value: Raw value from BloodHound.

    Returns:
        Four-digit year, or ``None`` when the value is not usable.
    """
    try:
        epoch_seconds = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if epoch_seconds <= 0:
        return None
    try:
        return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).year
    except (OSError, OverflowError, ValueError):
        return None


def resolve_bloodhound_pwdlastset_year(
    shell: Any,
    *,
    domain: str,
    username: str,
) -> int | None:
    """Resolve one user's ``pwdLastSet`` year from BloodHound.

    Args:
        shell: Active shell exposing ``_get_bloodhound_service``.
        domain: Target domain.
        username: SAM account name.

    Returns:
        Password-last-set year, or ``None`` when unavailable.
    """
    try:
        service = shell._get_bloodhound_service()
        records = service.get_password_last_change(domain, user=username)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            "[password-year-variant] BloodHound pwdLastSet lookup failed for "
            f"{mark_sensitive(username, 'user')}@{mark_sensitive(domain, 'domain')}: {exc}"
        )
        return None

    if not isinstance(records, list):
        return None
    for record in records:
        if not isinstance(record, dict):
            continue
        record_user = str(record.get("samaccountname") or "").strip()
        if record_user and record_user.casefold() != username.strip().casefold():
            continue
        year = epoch_seconds_to_year(record.get("pwdlastset"))
        if year is not None:
            return year
    return None


def resolve_password_year_variant_suggestion(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> PasswordYearVariantSuggestion | None:
    """Resolve a same-user password year-rollover suggestion.

    Args:
        shell: Active shell.
        domain: Target domain.
        username: Target username.
        password: Failed password candidate.

    Returns:
        Suggestion when ``pwdLastSet`` supports a later-year retry.
    """
    pwdlastset_year = resolve_bloodhound_pwdlastset_year(
        shell,
        domain=domain,
        username=username,
    )
    return build_pwdlastset_year_variant(
        password=password,
        username=username,
        pwdlastset_year=pwdlastset_year,
        source="bloodhound",
    )
