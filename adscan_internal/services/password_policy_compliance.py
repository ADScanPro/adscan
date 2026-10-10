"""Password policy compliance analysis — offline, pure-logic helper.

Active Directory does not expose the previous values of policy attributes.
``msDS-ReplAttributeMetaData`` on the domain root object and on each PSO
provides per-attribute replication metadata, including the ISO 8601
timestamp of the last originating change for every attribute. This is far
more precise than ``whenChanged`` (which is updated by any modification to
the object, including internal AD counters like ``creationTime``).

This module uses that per-attribute data to determine when the
password-policy attributes specifically were last modified and whether
each enabled user's ``pwdLastSet`` predates those changes — i.e. the user
has not rotated their credential since the policy was last updated.

No LDAP queries are performed here. Analysis is offline from an already-
collected :class:`adscan_internal.services.collector.models.CollectionResult`.

Output (:class:`PasswordComplianceReport`) is consumed by:

* the post-collection hygiene panel,
* the PDF report builder,
* the web product,
* password spraying candidate selection.

Limitations (must be surfaced on any user-facing output):

* ``msDS-ReplAttributeMetaData`` gives the timestamp of the last
  originating change but not the previous value. "Predates" means the
  credential has not been rotated since that attribute was last touched —
  not that the credential violates the current policy value.
* AD does not store previous policy values; exact verification requires
  DC audit logs (event 5136) or external snapshots.
* ``msDS-ResultantPSO`` is a constructed attribute. Without read
  permission this module falls back to direct ``msDS-PSOAppliesTo`` DN
  matching, skipping group-membership expansion — conservative, never
  overstates findings.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from adscan_internal.services.collector.models import (
    CollectionResult,
    CollectorNode,
    DomainPolicy,
    PasswordComplianceReport,
    PasswordSettingsObject,
    UserPasswordCompliance,
)
from adscan_internal.services.graph_queries.filters import is_active

_FILETIME_EPOCH_OFFSET = 116_444_736_000_000_000
_100NS_PER_SECOND = 10_000_000

# Matches both LDAP GeneralizedTime ("20240901123005.0Z") and
# the ISO 8601 format from msDS-ReplAttributeMetaData ("2024-09-01T12:30:05Z").
_GENERALIZED_TIME_RE = re.compile(
    r"^(?P<y>\d{4})(?P<m>\d{2})(?P<d>\d{2})"
    r"(?P<H>\d{2})(?P<M>\d{2})(?P<S>\d{2})"
    r"(?:\.(?P<frac>\d+))?Z$"
)
_ISO8601_RE = re.compile(
    r"^(?P<y>\d{4})-(?P<m>\d{2})-(?P<d>\d{2})"
    r"T(?P<H>\d{2}):(?P<M>\d{2}):(?P<S>\d{2})Z$"
)


def filetime_to_datetime(filetime: int | None) -> datetime | None:
    """Convert a Windows FILETIME integer to a UTC datetime.

    Returns ``None`` for the standard sentinel values (0, never-set,
    never-expires) so callers can treat them uniformly.
    """
    if filetime is None or filetime == 0:
        return None
    # Windows "never expires" sentinel.
    if filetime <= -(2**63) + 1 or filetime == 0x7FFFFFFFFFFFFFFF:
        return None
    unix_seconds = (filetime - _FILETIME_EPOCH_OFFSET) / _100NS_PER_SECOND
    if unix_seconds <= 0:
        return None
    return datetime.fromtimestamp(unix_seconds, tz=timezone.utc)


def parse_generalized_time(value: str | None) -> datetime | None:
    """Parse either LDAP GeneralizedTime (``YYYYMMDDHHMMSS[.f]Z``) or
    the ISO 8601 format emitted by ``msDS-ReplAttributeMetaData``
    (``YYYY-MM-DDTHH:MM:SSZ``).

    Returns ``None`` on any parse failure.
    """
    if not value:
        return None
    s = str(value).strip()
    for pattern in (_ISO8601_RE, _GENERALIZED_TIME_RE):
        m = pattern.match(s)
        if m:
            try:
                return datetime(
                    int(m["y"]), int(m["m"]), int(m["d"]),
                    int(m["H"]), int(m["M"]), int(m["S"]),
                    tzinfo=timezone.utc,
                )
            except ValueError:
                continue
    return None


def policy_never_modified(policy: DomainPolicy) -> bool:
    """True when every password-policy attribute has ``dwVersion == 1``.

    A version of 1 means the attribute was written exactly once — at domain
    provisioning — and has never been explicitly modified since. This signal
    comes from ``msDS-ReplAttributeMetaData`` and is precise: it is not
    affected by internal AD counters (like ``creationTime``) that inflate
    ``whenChanged`` on the domain root object.
    """
    attrs = policy.pwd_attrs_when_changed
    if not attrs:
        return False
    return all(ver == 1 for _, _, ver in attrs)


def _is_admin_like(node: CollectorNode) -> bool:
    if node.properties.get("admincount"):
        return True
    if node.highvalue:
        return True
    return False


def _enabled_users(result: CollectionResult) -> list[CollectorNode]:
    """Return the ACTIVE user population the password-policy report measures.

    ``is_active`` rather than ``node.enabled``: a deleted account preserves both
    its ``userAccountControl`` and its ``pwdLastSet``, so a tombstone would be
    counted as a live account out of compliance with a policy that no longer
    applies to it.
    """
    return [
        node
        for node in result.nodes.values()
        if node.kind == "User" and is_active(node)
    ]


def ad_duration_to_days(raw: object) -> int | None:
    """Convert an AD duration attribute (negative 100-ns FILETIME) to whole days.

    Canonical converter shared by the live policy API (``posture_probe``) and
    the duration legs of policy resolution. AD stores ``maxPwdAge`` /
    ``minPwdAge`` (and the PSO equivalents) as negative 100-nanosecond
    intervals; ``0`` and the int64 ``never-expires`` sentinel both mean
    "no limit".

    Args:
        raw: Raw attribute value (int, str, or ``None``).

    Returns:
        Whole days enforced, or ``None`` when absent, zero, unparseable, or
        the never-expires sentinel.
    """
    try:
        ft_int = int(raw) if raw is not None else None
    except (ValueError, TypeError):
        return None
    if ft_int is None or ft_int == 0:
        return None
    if ft_int <= -(2**63) + 1:
        return None
    seconds = abs(ft_int) / _100NS_PER_SECOND
    days = int(seconds // 86400)
    return days if days > 0 else None


def ad_duration_to_minutes(raw: object) -> int | None:
    """Convert an AD duration attribute (negative 100-ns FILETIME) to minutes.

    Canonical converter for ``lockoutObservationWindow`` / ``lockoutDuration``
    (and the PSO equivalents). Same sentinel handling as
    :func:`ad_duration_to_days`. ``0`` (e.g. ``lockoutDuration`` =
    admin-unlock-only) maps to ``None``.

    Args:
        raw: Raw attribute value (int, str, or ``None``).

    Returns:
        Whole minutes, or ``None`` when absent, zero, unparseable, or the
        never-expires sentinel.
    """
    try:
        ft_int = int(raw) if raw is not None else None
    except (ValueError, TypeError):
        return None
    if ft_int is None or ft_int == 0:
        return None
    if ft_int <= -(2**63) + 1:
        return None
    seconds = abs(ft_int) / _100NS_PER_SECOND
    minutes = int(seconds // 60)
    return minutes if minutes > 0 else None


def select_winning_pso_dn(
    *,
    resultant_pso_dn: str | None,
    user_dn: str,
    principal_dns: tuple[str, ...] | list[str],
    candidate_psos: list[tuple[str, tuple[str, ...], int | None]],
) -> str | None:
    """Resolve the effective PSO DN for a principal — single algorithm.

    Pure helper shared by the offline collector path
    (:func:`_select_pso_for_user`) and the live LDAP path
    (``posture_probe.resolve_resultant_password_policy``). It deliberately
    operates on primitives only (DN strings, precedence ints) so neither path
    has to materialise the other's object model.

    Selection mirrors the AD PSO precedence rule:

    1. ``resultant_pso_dn`` (``msDS-ResultantPSO``) is authoritative when it is
       present *and* matches one of the candidate PSOs.
    2. Otherwise, among the PSOs whose ``applies_to`` covers the user DN or any
       of the principal's (group) DNs, pick the one with the lowest numeric
       ``msDS-PasswordSettingsPrecedence`` (``None`` precedence sorts last).
    3. No covering PSO -> ``None`` (caller falls back to the domain default).

    Args:
        resultant_pso_dn: Value of ``msDS-ResultantPSO`` on the user object, or
            ``None`` when absent/unreadable.
        user_dn: The user's distinguished name.
        principal_dns: Group DNs (incl. nested) the user is a member of.
        candidate_psos: ``(pso_dn, applies_to_dns, precedence)`` tuples.

    Returns:
        The winning PSO DN (in the casing of ``candidate_psos``) or ``None``.
    """
    psos_by_dn_upper = {dn.upper(): dn for dn, _applies, _prec in candidate_psos if dn}

    if isinstance(resultant_pso_dn, str) and resultant_pso_dn:
        winner = psos_by_dn_upper.get(resultant_pso_dn.upper())
        if winner is not None:
            return winner

    if not candidate_psos:
        return None

    covered: set[str] = {user_dn.upper()} if user_dn else set()
    covered.update(dn.upper() for dn in principal_dns if dn)
    if not covered:
        return None

    matches: list[tuple[str, int]] = []
    for dn, applies_to, precedence in candidate_psos:
        if not dn:
            continue
        for trustee in applies_to:
            if trustee.upper() in covered:
                # ``precedence`` lower wins; treat None as worst.
                matches.append((dn, precedence if precedence is not None else 2**31))
                break
    if not matches:
        return None
    matches.sort(key=lambda item: item[1])
    return matches[0][0]


def _select_pso_for_user(
    node: CollectorNode,
    psos_by_dn: dict[str, PasswordSettingsObject],
    psos_sorted: list[PasswordSettingsObject],
) -> PasswordSettingsObject | None:
    """Resolve the effective PSO for a user.

    Preference order:

    1. ``msDS-ResultantPSO`` — the constructed attribute computed by the
       DC. Authoritative when present.
    2. Direct match of the user's DN against any PSO ``applies_to``,
       picking the highest-precedence (lowest numeric) value.

    Returns ``None`` when no PSO governs the user — caller falls back
    to the Default Domain Policy.
    """
    resultant_dn = node.properties.get("resultantpso")
    candidate_psos = [
        (pso.distinguished_name, pso.applies_to, pso.precedence)
        for pso in psos_sorted
        if pso.distinguished_name
    ]
    winning_dn = select_winning_pso_dn(
        resultant_pso_dn=resultant_dn if isinstance(resultant_dn, str) else None,
        user_dn=node.distinguished_name or "",
        # Offline analysis intentionally does not expand group membership
        # (documented conservative behaviour — never overstates findings).
        principal_dns=(),
        candidate_psos=candidate_psos,
    )
    if winning_dn is None:
        return None
    return psos_by_dn.get(winning_dn.upper())


def _resolve_max_pwd_age_days(
    pso: PasswordSettingsObject | None,
    domain_policy: DomainPolicy,
) -> int | None:
    if pso is not None and pso.max_pwd_age_days is not None:
        return pso.max_pwd_age_days
    return domain_policy.max_pwd_age_days


def _resolve_policy_last_changed(
    pso: PasswordSettingsObject | None,
    domain_policy: DomainPolicy,
) -> str | None:
    """Return the most recent password-policy attribute change timestamp.

    Prefers the PSO's ``pwd_policy_last_changed`` when a PSO governs the
    user; falls back to the DDP's value. Both are derived from
    ``msDS-ReplAttributeMetaData`` and reflect only password-relevant
    attributes — not generic domain-object churn.
    """
    if pso is not None and pso.pwd_policy_last_changed:
        return pso.pwd_policy_last_changed
    return domain_policy.pwd_policy_last_changed


def _classify_risk(
    *,
    is_admin_like: bool,
    pwd_never_expires: bool,
    pwd_predates_policy: bool,
    pwd_over_max_age: bool,
) -> str:
    # Severity mirrors contextual_rules.py "stale_passwords":
    # baseline LOW (3.5); Tier-0/admin elevation to MEDIUM (6.0).
    # pwd_never_expires alone stays LOW — handled by its own finding category.
    if is_admin_like and (pwd_predates_policy or pwd_over_max_age):
        return "medium"
    if pwd_predates_policy or pwd_over_max_age:
        return "low"
    if pwd_never_expires:
        return "low"
    return "info"


def analyze_password_compliance(
    result: CollectionResult,
    *,
    now: datetime | None = None,
) -> PasswordComplianceReport | None:
    """Build a :class:`PasswordComplianceReport` from an already-collected
    domain.

    Returns ``None`` when no domain policy was collected (typical for
    minimal CTF scope or unreadable bind). Reporting layers should treat
    that as "no signal" and skip the section.
    """
    domain_policy = result.domain_policy
    if domain_policy is None:
        return None

    if now is None:
        now = datetime.now(timezone.utc)

    psos = list(result.psos)
    psos_by_dn = {p.distinguished_name.upper(): p for p in psos if p.distinguished_name}
    # Pre-sort once for per-user lookups — applies_to matching needs it.
    psos_sorted = sorted(
        psos,
        key=lambda p: (p.precedence if p.precedence is not None else 2**31),
    )

    entries: list[UserPasswordCompliance] = []
    predates = 0
    over_max = 0
    never_expires = 0

    for node in _enabled_users(result):
        pso = _select_pso_for_user(node, psos_by_dn, psos_sorted)
        max_age_days = _resolve_max_pwd_age_days(pso, domain_policy)
        applied_when_changed = _resolve_policy_last_changed(pso, domain_policy)

        pwd_last_set_ft = node.properties.get("pwdlastset")
        pwd_last_set_ft = (
            int(pwd_last_set_ft) if isinstance(pwd_last_set_ft, int) else None
        )
        pwd_last_set_dt = filetime_to_datetime(pwd_last_set_ft)
        pwd_age_days = (
            (now - pwd_last_set_dt).days if pwd_last_set_dt is not None else None
        )

        pwd_never_exp = bool(node.properties.get("pwdneverexpires"))
        pwd_over_max = bool(
            max_age_days is not None
            and pwd_age_days is not None
            and pwd_age_days > max_age_days
            and not pwd_never_exp
        )

        policy_changed_dt = parse_generalized_time(applied_when_changed)
        pwd_predates = bool(
            pwd_last_set_dt is not None
            and policy_changed_dt is not None
            and pwd_last_set_dt < policy_changed_dt
        )

        is_admin = _is_admin_like(node)

        notes: list[str] = []
        if pwd_predates and policy_changed_dt is not None:
            notes.append(
                f"pwdLastSet ({pwd_last_set_dt.date().isoformat() if pwd_last_set_dt else 'n/a'}) "
                f"predates {pso.name if pso else 'Default Domain Policy'} "
                f"last modification ({policy_changed_dt.date().isoformat()})."
            )
        if pwd_over_max and max_age_days is not None and pwd_age_days is not None:
            notes.append(
                f"Password age {pwd_age_days}d exceeds maxPwdAge "
                f"({max_age_days}d) of {pso.name if pso else 'Default Domain Policy'}."
            )
        if pwd_never_exp:
            notes.append("DONT_EXPIRE_PASSWORD UAC flag set.")

        risk = _classify_risk(
            is_admin_like=is_admin,
            pwd_never_expires=pwd_never_exp,
            pwd_predates_policy=pwd_predates,
            pwd_over_max_age=pwd_over_max,
        )

        entries.append(
            UserPasswordCompliance(
                samaccountname=node.samaccountname,
                object_id=node.object_id,
                distinguished_name=node.distinguished_name,
                enabled=True,
                is_admin_like=is_admin,
                pwd_last_set_filetime=pwd_last_set_ft,
                pwd_last_set_iso=(
                    pwd_last_set_dt.isoformat() if pwd_last_set_dt else None
                ),
                pwd_age_days=pwd_age_days,
                applied_policy_name=pso.name if pso else "DDP",
                applied_policy_dn=(
                    pso.distinguished_name if pso else (
                        # The DDP applies on the domain root; we don't carry
                        # a separate DN for it but the consumer can derive
                        # it from the domain name when needed.
                        ""
                    )
                ),
                applied_policy_when_changed=applied_when_changed,
                pwd_predates_policy=pwd_predates,
                pwd_over_max_age=pwd_over_max,
                pwd_never_expires=pwd_never_exp,
                risk_level=risk,
                notes=tuple(notes),
            )
        )

        if pwd_predates:
            predates += 1
        if pwd_over_max:
            over_max += 1
        if pwd_never_exp:
            never_expires += 1

    return PasswordComplianceReport(
        domain=result.domain,
        policy_pwd_last_changed=domain_policy.pwd_policy_last_changed,
        policy_never_modified=policy_never_modified(domain_policy),
        policy_pwd_attrs=domain_policy.pwd_attrs_when_changed,
        psos_count=len(psos),
        users_total=len(entries),
        users_with_predates_policy=predates,
        users_with_over_max_age=over_max,
        users_with_never_expires=never_expires,
        entries=tuple(entries),
    )


__all__ = [
    "ad_duration_to_days",
    "ad_duration_to_minutes",
    "analyze_password_compliance",
    "filetime_to_datetime",
    "parse_generalized_time",
    "policy_never_modified",
    "select_winning_pso_dn",
]
