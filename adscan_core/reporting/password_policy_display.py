"""How a domain's maximum password age is stated to a client.

Active Directory has no boolean for "passwords never expire". It has one
duration attribute, ``maxPwdAge``, and three different ways of saying never:

* ``0`` — the documented "no expiry" value.
* ``-0x8000000000000000`` — the int64 minimum, what ``net accounts
  /maxpwage:unlimited`` writes.
* A duration so long no password reaches it. Windows' own configuration
  surfaces (the Default Domain Policy editor and
  ``Set-ADDefaultDomainPasswordPolicy``) refuse anything past 999 days, so a
  larger value was written straight to the attribute and means the same thing.

Converted naively, the third form arrives at a report as a number: the
``essos.local`` assessment printed ``37201`` against a "``<= 365`` days"
baseline, and 37,201 days is 101 years. Every AD administrator reads that as a
broken table rather than as the finding it is, which is why the interpretation
lives here rather than in one renderer — the paid PDF and the web platform both
read it, and they have to say the same thing.

Deliberately dependency-free and in ``adscan_core`` so the container-side report
and the ``adscan_web`` backend (which ships only ``adscan_core`` plus stubs on
the appliance) share one definition instead of mirroring it.
"""

from __future__ import annotations

__all__ = [
    "AD_NEVER_EXPIRES_FILETIME",
    "NEVER_EXPIRES_THRESHOLD_DAYS",
    "format_max_pwd_age_days",
    "format_observed_knob_value",
    "max_pwd_age_never_expires",
    "observed_knob_passes",
]

#: ``maxPwdAge`` written by ``net accounts /maxpwage:unlimited``: the int64
#: minimum, which a 100-nanosecond-to-days conversion turns into 10,675,199.
AD_NEVER_EXPIRES_FILETIME = -(2**63)

#: Above this, a maximum password age is reported as "never expires" rather
#: than as a duration. Ten years is well past the point where the setting still
#: describes a rotation anyone will live to see, and past both what Windows'
#: own configuration surfaces will set (the Default Domain Policy editor and
#: ``Set-ADDefaultDomainPasswordPolicy`` cap at 999 days) and what the AD
#: tooling ecosystem treats as a real lifetime. A value in between — say three
#: years — is unusual but still a rotation, and is reported as the duration it
#: is.
NEVER_EXPIRES_THRESHOLD_DAYS = 3650


def _as_int(days: object) -> int | None:
    try:
        return int(days)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def max_pwd_age_never_expires(days: object) -> bool:
    """Return True when a maximum password age means passwords never expire.

    Covers all three AD spellings: the value is absent (the collector records
    ``None`` for both ``0`` and the int64 sentinel), it is zero or negative, or
    it is past :data:`NEVER_EXPIRES_THRESHOLD_DAYS`.

    Args:
        days: The maximum password age in whole days, or ``None``.

    Returns:
        ``True`` when no password in the domain is ever forced to change.
        ``False`` for a real, enforced lifetime and for an unparseable value —
        a garbled reading must not be reported as a never-expiring policy.
    """
    if days is None:
        return True
    value = _as_int(days)
    if value is None:
        return False
    return value <= 0 or value > NEVER_EXPIRES_THRESHOLD_DAYS


def format_max_pwd_age_days(days: object) -> str:
    """Return the client-facing wording for a maximum password age.

    A never-expiring policy is stated as such, with the configured duration
    kept in parentheses when there is one — an auditor wants to see the raw
    attribute, and hiding it would replace one unreadable figure with a
    different kind of gap.

    Args:
        days: The maximum password age in whole days, or ``None``.

    Returns:
        ``"Never expires (no maximum age set)"``, ``"Never expires (set to
        37,201 days)"``, or ``"365 days"``. A value that will not parse is
        returned verbatim rather than interpreted — reporting a garbled reading
        as a never-expiring policy would be a claim the scan cannot support.
    """
    if days is None:
        return "Never expires (no maximum age set)"
    value = _as_int(days)
    if value is None:
        return str(days)
    if value <= 0:
        return "Never expires (no maximum age set)"
    if value > NEVER_EXPIRES_THRESHOLD_DAYS:
        return f"Never expires (set to {value:,} days)"
    return f"{value} day" if value == 1 else f"{value} days"


#: Knobs whose measured value needs interpreting before a client reads it.
#: Everything else is a plain number or a boolean and is printed as-is.
_KNOB_FORMATTERS = {"max_pwd_age_days": format_max_pwd_age_days}


def format_observed_knob_value(knob: str, value: object) -> str:
    """Return the client-facing wording for one observed policy setting.

    The observed-vs-recommended table pairs a measured value with the baseline
    it is judged against, so the measured side has to read as a fact. Two cases
    need help: the maximum password age (see
    :func:`format_max_pwd_age_days`), and a value the scan never obtained —
    which printed as the bare word ``None``.

    Args:
        knob: The setting's key, as it appears in ``details.observed``.
        value: The measured value.

    Returns:
        The string to print in the observed column.
    """
    formatter = _KNOB_FORMATTERS.get(str(knob or "").strip())
    if formatter is not None:
        return formatter(value)
    if value is None:
        return "Not collected"
    return str(value)


def observed_knob_passes(knob: str, value: object, target: object) -> bool | None:
    """Return the verdict override for a knob whose absence carries meaning.

    ``max_pwd_age_days`` is the one setting where "no value" is not a gap in
    the assessment: it is how the collector records a domain that never expires
    a password, which fails any maximum-age baseline outright. Left to a
    generic comparison it reads as *unknown*, which understates the finding.

    Args:
        knob: The setting's key.
        value: The measured value.
        target: The baseline value.

    Returns:
        ``False`` when the knob is a never-expiring maximum password age judged
        against a numeric ceiling, otherwise ``None`` — meaning "no override,
        use the generic comparison".
    """
    if str(knob or "").strip() != "max_pwd_age_days":
        return None
    if isinstance(target, bool) or not isinstance(target, (int, float)):
        return None
    return False if max_pwd_age_never_expires(value) else None
