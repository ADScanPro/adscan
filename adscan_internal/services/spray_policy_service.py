"""Native LDAP-based password policy and BadPwdCount fetch for spraying.

Replaces NetExec subprocess calls for:
- Domain default password policy (lockoutThreshold, lockoutDuration)
- Per-user badPwdCount (all enabled user accounts)
- Fine-grained PSO lockout threshold per user (msDS-ResultantPSO)

All functions return gracefully on failure so callers can fall back to
NetExec without user-visible errors.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from adscan_core.rich_output import print_info_debug, print_warning_debug
from adscan_internal import telemetry
from adscan_internal.services.ldap_transport_service import (
    ADscanLDAPConfig,
    async_connect_with_ldap_fallback,
)

# Safety margin (seconds) added to the lockout observation window before an
# account's stored badPwdCount is treated as effectively reset. Only relaxes
# exclusion when the account is CLEARLY outside its window (covers residual
# clock skew between this host and the DC); errs toward staying excluded.
_OBSERVATION_WINDOW_SAFETY_SECONDS = 120

# Attributes to fetch per user for spray eligibility
_USER_SPRAY_ATTRS = [
    "sAMAccountName",
    "badPwdCount",
    "badPasswordTime",
    "userAccountControl",
    "msDS-ResultantPSO",
    # Currently-locked accounts reset badPwdCount to 0 (so they look "eligible"),
    # but spraying them is pointless and can extend the lockout.
    # msDS-User-Account-Control-Computed is the DC's LIVE, constructed UAC: its
    # UF_LOCKOUT (0x10) bit is the authoritative "locked right now" signal — it
    # already accounts for auto-unlock AND per-user PSO lockout duration, which a
    # manual lockoutTime-vs-domain-lockoutDuration calculation cannot (a Tier-0 PSO
    # with a different/zero duration would be mis-judged). Validated against
    # cyberzaintza: Administrator (Tier-0 PSO) reads 0x10 here while its lockoutTime
    # is a year old, so the manual heuristic wrongly cleared it.
    "msDS-User-Account-Control-Computed",
]

# UF_LOCKOUT flag in msDS-User-Account-Control-Computed.
_UF_LOCKOUT = 0x0010


def _cn_from_dn(dn: str) -> str:
    """Best-effort CN/leaf RDN of a DN for display (``CN=TIER0,...`` -> ``TIER0``)."""
    leaf = str(dn or "").split(",", 1)[0]
    return leaf.split("=", 1)[-1].strip() or str(dn or "")

# Attributes to fetch from domain root for default password policy
_DOMAIN_POLICY_ATTRS = [
    "lockoutThreshold",
    "lockoutDuration",
    "lockoutObservationWindow",
    "minPwdLength",
    "maxPwdAge",
]

# Attributes to fetch from PSO objects
_PSO_ATTRS = [
    "name",
    "distinguishedName",
    "msDS-LockoutThreshold",
    "msDS-LockoutDuration",
    "msDS-LockoutObservationWindow",
    "msDS-PSOAppliesTo",
    "msDS-PasswordSettingsPrecedence",
]

# sAMAccountType for normal user accounts (excludes computers by default)
_USER_ONLY_FILTER = "(&(sAMAccountType=805306368)(!(isDeleted=TRUE))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

# sAMAccountType for machine (computer) accounts. Used by the computer-pre2k
# spray eligibility path, which needs per-machine badPwdCount + the same
# observation-window reset as users so a near-lockout computer is not sprayed.
_COMPUTER_ONLY_FILTER = "(&(sAMAccountType=805306369)(!(isDeleted=TRUE))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

# Account-scope selector for fetch_spray_policy_native / _sync.
_SCOPE_FILTERS: dict[str, str] = {
    "user": _USER_ONLY_FILTER,
    "computer": _COMPUTER_ONLY_FILTER,
}

# Filter to locate PSO container
_PSO_FILTER = "(objectClass=msDS-PasswordSettings)"


@dataclass(slots=True)
class DomainPasswordPolicy:
    """Default domain password policy lockout settings."""

    lockout_threshold: int | None = None
    lockout_duration_seconds: int | None = None
    observation_window_seconds: int | None = None
    no_lockout_enforced: bool = False


@dataclass(slots=True)
class PSOPolicy:
    """Fine-grained password policy object (PSO)."""

    name: str = ""
    dn: str = ""
    lockout_threshold: int | None = None
    observation_window_seconds: int | None = None
    precedence: int = 0


@dataclass(slots=True)
class SprayPolicyResult:
    """Complete spray-safe policy result from native LDAP.

    Attributes:
        default_policy: Domain-level lockout settings.
        pso_by_name: PSO objects keyed by DN (for per-user resolution).
        badpwd_by_user: Lowercase sAMAccountName → EFFECTIVE badPwdCount. This is
            the observation-window-adjusted count, NOT the raw stored attribute:
            a user whose last bad password (``badPasswordTime``) is outside the
            lockout observation window has an effective count of 0, because the
            window has elapsed and the next failed logon starts fresh — exactly
            how Windows enforces lockout. (Windows resets the stored attribute
            lazily, so the raw value can read stale-high.)
        raw_badpwd_by_user: Lowercase sAMAccountName → RAW stored badPwdCount,
            before the observation-window adjustment (kept for diagnostics).
        badpwdtime_by_user: Lowercase sAMAccountName → badPasswordTime (UTC).
        pso_dn_by_user: Lowercase sAMAccountName → resultant PSO DN (if any).
        fetch_errors: Non-fatal errors encountered during fetch.
    """

    default_policy: DomainPasswordPolicy = field(default_factory=DomainPasswordPolicy)
    pso_by_dn: dict[str, PSOPolicy] = field(default_factory=dict)
    badpwd_by_user: dict[str, int] = field(default_factory=dict)
    raw_badpwd_by_user: dict[str, int] = field(default_factory=dict)
    badpwdtime_by_user: dict[str, datetime] = field(default_factory=dict)
    pso_dn_by_user: dict[str, str] = field(default_factory=dict)
    locked_users: set[str] = field(default_factory=set)
    """Lowercase sAMAccountNames currently locked out (lockoutTime set + lockout
    not yet elapsed vs the domain lockoutDuration). These reset badPwdCount to 0,
    so they look 'eligible' — spraying them is pointless and extends the lockout."""
    fetch_errors: list[str] = field(default_factory=list)

    def effective_lockout_threshold(self, username_lower: str) -> int | None:
        """Return the effective lockout threshold for a user.

        PSO takes precedence over default domain policy when present.
        """
        pso_dn = self.pso_dn_by_user.get(username_lower)
        if pso_dn:
            pso = self.pso_by_dn.get(pso_dn.lower())
            if pso and pso.lockout_threshold is not None:
                return pso.lockout_threshold
        return self.default_policy.lockout_threshold

    def lockout_threshold_with_source(
        self, username_lower: str, *, unreadable_pso_fallback: int
    ) -> "tuple[int | None, str, bool]":
        """Resolve a user's lockout threshold AND where it came from.

        Returns ``(threshold, source_label, is_unreadable_pso_fallback)``:

        * No PSO assigned → ``(domain threshold, "domain", False)``.
        * PSO assigned and readable → ``(pso threshold, "PSO '<name>'", False)``.
        * PSO assigned but the PSO object is UNREADABLE (the spraying principal
          lacks read access to the Password Settings Container — common for
          low-priv users, and exactly the privileged Tier-0 accounts we must not
          lock) → ``(unreadable_pso_fallback, "PSO '<cn>' unreadable", True)``.
          Using the domain default here would be UNSAFE: a stricter PSO threshold
          would be over-estimated and a spray could lock the account. The
          conservative fallback (with the 2-attempt safety margin) caps such users
          at a single attempt.
        """
        pso_dn = self.pso_dn_by_user.get(username_lower)
        if not pso_dn:
            return self.default_policy.lockout_threshold, "domain", False
        pso = self.pso_by_dn.get(pso_dn.lower())
        if pso and pso.lockout_threshold is not None:
            name = pso.name or _cn_from_dn(pso_dn)
            return pso.lockout_threshold, f"PSO '{name}'", False
        return unreadable_pso_fallback, f"PSO '{_cn_from_dn(pso_dn)}' unreadable", True

    def effective_observation_window(self, username_lower: str) -> int | None:
        """Return the effective lockout observation window (seconds) for a user.

        PSO takes precedence over the default domain policy when present and the
        PSO defines its own window; otherwise the domain default applies.
        """
        pso_dn = self.pso_dn_by_user.get(username_lower)
        if pso_dn:
            pso = self.pso_by_dn.get(pso_dn.lower())
            if pso and pso.observation_window_seconds is not None:
                return pso.observation_window_seconds
        return self.default_policy.observation_window_seconds


def _ci(attrs: Any) -> dict[str, Any]:
    """Return a case-insensitive view (lowercased keys) of an LDAP attrs dict.

    LDAP attribute names are case-insensitive, and badldap keys search results by
    the server's canonical lDAPDisplayName (``convert_attributes`` →
    ``e['type'].decode()``). AD's casing is inconsistent — e.g.
    ``lockOutObservationWindow`` has a capital O while ``lockoutDuration`` /
    ``lockoutThreshold`` are lowercase — so a fixed-case ``attrs.get(...)``
    silently misses some attributes (this returned the observation window as
    ``None`` and broke the badPwdCount observation-window reset). Lowercasing the
    keys makes every read robust to the server's casing.
    """
    if not isinstance(attrs, dict):
        return {}
    return {str(k).lower(): v for k, v in attrs.items()}


def _interval_to_seconds(interval: int | None) -> int | None:
    """Convert a Windows LDAP interval (100-nanosecond units, negative) to seconds."""
    if interval is None:
        return None
    try:
        # AD stores durations as negative 100-ns intervals
        return abs(int(interval)) // 10_000_000
    except (TypeError, ValueError):
        return None


def _parse_badpwdtime(value: Any) -> datetime | None:
    """Parse a ``badPasswordTime`` LDAP value into a UTC datetime, or ``None``.

    badldap decodes ``badPasswordTime`` via ``single_interval`` → a tz-aware UTC
    ``datetime`` (1601-01-01 for never/0, ``datetime.max`` for the never sentinel).
    Defensive against a raw FILETIME int just in case. ``None`` means "no usable
    last-bad-password time" (never set / unparseable) — the caller then keeps the
    raw count (conservative, never relaxes on missing data).
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        # 1601 epoch == never had a bad password; treat as "no recent failure".
        if dt.year <= 1601 or dt.year >= 9999:
            return None
        return dt.astimezone(timezone.utc)
    try:
        ft = int(value)
    except (TypeError, ValueError):
        return None
    if ft <= 0 or ft == 0x7FFFFFFFFFFFFFFF:
        return None
    # FILETIME: 100-ns intervals since 1601-01-01 UTC.
    unix_seconds = (ft - 116_444_736_000_000_000) / 10_000_000
    if unix_seconds <= 0:
        return None
    try:
        return datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


async def _fetch_domain_policy(
    conn: Any,
    domain_nc: str,
) -> DomainPasswordPolicy:
    """Fetch lockout policy from the domain naming context root."""
    policy = DomainPasswordPolicy()
    try:
        async for entry, err in conn.pagedsearch(
            query="(objectClass=domain)",
            attributes=_DOMAIN_POLICY_ATTRS,
            tree=domain_nc,
            search_scope=0,  # BASE scope — domain root only
        ):
            if err is not None:
                print_warning_debug(f"[spray_policy] domain policy search error: {err}")
                continue
            attrs = _ci(entry.get("attributes", {}))
            raw_threshold = attrs.get("lockoutthreshold")
            if raw_threshold is not None:
                try:
                    threshold = int(raw_threshold)
                    policy.lockout_threshold = threshold
                    policy.no_lockout_enforced = threshold == 0
                except (TypeError, ValueError):
                    pass

            policy.lockout_duration_seconds = _interval_to_seconds(
                attrs.get("lockoutduration")
            )
            policy.observation_window_seconds = _interval_to_seconds(
                attrs.get("lockoutobservationwindow")
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning_debug(f"[spray_policy] Failed to fetch domain policy: {exc}")
    return policy


async def _fetch_pso_objects(
    conn: Any,
    domain_nc: str,
) -> dict[str, PSOPolicy]:
    """Fetch all PSO objects from the Password Settings Container."""
    pso_container = f"CN=Password Settings Container,CN=System,{domain_nc}"
    pso_by_dn: dict[str, PSOPolicy] = {}
    try:
        async for entry, err in conn.pagedsearch(
            query=_PSO_FILTER,
            attributes=_PSO_ATTRS,
            tree=pso_container,
        ):
            if err is not None:
                print_warning_debug(f"[spray_policy] PSO search error: {err}")
                continue
            attrs = _ci(entry.get("attributes", {}))
            dn = str(entry.get("objectName") or attrs.get("distinguishedname") or "")
            name = str(attrs.get("name") or "")
            threshold_raw = attrs.get("msds-lockoutthreshold")
            threshold: int | None = None
            if threshold_raw is not None:
                try:
                    threshold = int(threshold_raw)
                except (TypeError, ValueError):
                    pass
            precedence_raw = attrs.get("msds-passwordsettingsprecedence")
            precedence = int(precedence_raw) if precedence_raw is not None else 0
            obs_window = _interval_to_seconds(attrs.get("msds-lockoutobservationwindow"))
            pso = PSOPolicy(
                name=name,
                dn=dn,
                lockout_threshold=threshold,
                observation_window_seconds=obs_window,
                precedence=precedence,
            )
            pso_by_dn[dn.lower()] = pso
    except Exception as exc:  # noqa: BLE001
        # PSO container may not exist on basic AD — non-fatal
        print_info_debug(f"[spray_policy] PSO fetch skipped or failed: {exc}")
    return pso_by_dn


async def _fetch_user_badpwdcounts(
    conn: Any,
    domain_nc: str,
    *,
    include_pso: bool = True,
    spray_filter: str = _USER_ONLY_FILTER,
) -> tuple[dict[str, int], dict[str, str], dict[str, datetime], set[str]]:
    """Fetch badPwdCount, badPasswordTime, resultant PSO DN and lock state per account.

    Args:
        conn: An open badldap connection.
        domain_nc: Domain naming context (search base).
        include_pso: Whether to request ``msDS-ResultantPSO``.
        spray_filter: LDAP filter selecting the account scope. Defaults to the
            user-account filter; pass ``_COMPUTER_ONLY_FILTER`` for machine
            accounts (computer-pre2k spray eligibility). Both scopes carry
            badPwdCount + the live UF_LOCKOUT computed bit, so the same
            observation-window reset and locked-account exclusion apply.

    Returns:
        (badpwd_by_user, pso_dn_by_user, badpwdtime_by_user, locked_users). The
        first three are keyed by lowercase sAMAccountName; ``badpwd_by_user`` is the
        RAW stored count (observation-window adjustment is applied by the caller).
        ``locked_users`` is the set of currently locked-out accounts, read from the
        DC's live ``msDS-User-Account-Control-Computed`` (UF_LOCKOUT bit) — already
        PSO- and auto-unlock-aware.
    """
    attrs = list(_USER_SPRAY_ATTRS)
    if not include_pso and "msDS-ResultantPSO" in attrs:
        attrs.remove("msDS-ResultantPSO")

    badpwd_by_user: dict[str, int] = {}
    pso_dn_by_user: dict[str, str] = {}
    badpwdtime_by_user: dict[str, datetime] = {}
    locked_users: set[str] = set()

    try:
        async for entry, err in conn.pagedsearch(
            query=spray_filter,
            attributes=attrs,
            tree=domain_nc,
        ):
            if err is not None:
                print_warning_debug(f"[spray_policy] user search error: {err}")
                continue
            attrs_data = _ci(entry.get("attributes", {}))
            sam = str(attrs_data.get("samaccountname") or "").strip()
            if not sam:
                continue
            sam_lower = sam.lower()
            bad_raw = attrs_data.get("badpwdcount")
            if bad_raw is not None:
                try:
                    badpwd_by_user[sam_lower] = int(bad_raw)
                except (TypeError, ValueError):
                    pass
            pso_dn_raw = attrs_data.get("msds-resultantpso")
            if pso_dn_raw:
                pso_dn_by_user[sam_lower] = str(pso_dn_raw)
            bpt = _parse_badpwdtime(attrs_data.get("badpasswordtime"))
            if bpt is not None:
                badpwdtime_by_user[sam_lower] = bpt
            # Authoritative "locked right now" from the DC's computed UAC
            # (PSO-aware, auto-unlock-aware). The UF_LOCKOUT bit is what nxc/Windows
            # report as STATUS_ACCOUNT_LOCKED_OUT.
            uacc = attrs_data.get("msds-user-account-control-computed")
            if uacc is not None:
                try:
                    if int(uacc) & _UF_LOCKOUT:
                        locked_users.add(sam_lower)
                except (TypeError, ValueError):
                    pass
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning_debug(f"[spray_policy] Failed to fetch user badPwdCounts: {exc}")

    return badpwd_by_user, pso_dn_by_user, badpwdtime_by_user, locked_users


def _apply_observation_window_reset(
    result: SprayPolicyResult, now: datetime
) -> tuple[dict[str, int], int]:
    """Compute the EFFECTIVE badPwdCount per user from the raw stored counts.

    A stored ``badPwdCount`` only counts toward lockout within the lockout
    observation window. When a user's last bad password (``badPasswordTime``) is
    older than the effective window (plus a safety margin for clock skew), the
    window has elapsed: the next failed logon starts fresh, so the effective
    count is 0 — exactly how Windows enforces lockout. Windows resets the stored
    attribute only lazily, so the raw value can read stale-high and cause spray
    over-exclusion.

    Conservative by construction — the raw count is kept (never relaxed to 0)
    whenever the effective window or ``badPasswordTime`` is unknown, so a missing
    signal can never make an at-risk account look sprayable.

    Returns ``(effective_by_user, reset_count)``.
    """
    effective: dict[str, int] = {}
    reset_count = 0
    # Diagnostic breakdown of WHY each non-zero account was / was not reset
    # (counts only + anonymised numeric samples — no usernames in logs).
    reasons = {
        "reset": 0,
        "kept_missing_window": 0,
        "kept_missing_badpasswordtime": 0,
        "kept_within_window": 0,
    }
    samples: list[str] = []
    for user, raw in result.raw_badpwd_by_user.items():
        if raw <= 0:
            effective[user] = raw
            continue
        window = result.effective_observation_window(user)
        bpt = result.badpwdtime_by_user.get(user)
        if window is None or window <= 0:
            effective[user] = raw  # cannot prove the window expired → keep raw
            reasons["kept_missing_window"] += 1
            continue
        if bpt is None:
            effective[user] = raw
            reasons["kept_missing_badpasswordtime"] += 1
            if len(samples) < 6:
                samples.append(f"raw={raw} bpt=None window={window}s→kept")
            continue
        age_seconds = (now - bpt).total_seconds()
        if age_seconds > window + _OBSERVATION_WINDOW_SAFETY_SECONDS:
            effective[user] = 0  # outside the window → effectively reset
            reset_count += 1
            reasons["reset"] += 1
        else:
            effective[user] = raw
            reasons["kept_within_window"] += 1
            if len(samples) < 6:
                samples.append(f"raw={raw} age={int(age_seconds)}s window={window}s→kept(within)")
    print_info_debug(
        "[spray_policy] observation-window eval: "
        f"default_window={result.default_policy.observation_window_seconds}s "
        f"safety={_OBSERVATION_WINDOW_SAFETY_SECONDS}s reasons={reasons} "
        f"samples={samples}"
    )
    return effective, reset_count


async def fetch_spray_policy_native(
    *,
    domain: str,
    dc_ip: str,
    username: str | None = None,
    password: str | None = None,
    use_kerberos: bool = False,
    kerberos_target_hostname: str | None = None,
    auth_domain: str | None = None,
    auth_kdc: str | None = None,
    account_scope: str = "user",
) -> SprayPolicyResult:
    """Fetch domain password policy + per-account badPwdCount via native LDAP.

    Returns a SprayPolicyResult with all available data. Non-fatal errors
    are collected in result.fetch_errors so callers can decide how to proceed.

    Args:
        domain: Target domain (DNS name).
        dc_ip: Domain controller IP.
        username: Authenticating username (or None for anonymous/Kerberos).
        password: Authenticating password.
        use_kerberos: Use Kerberos ticket auth instead of password.
        kerberos_target_hostname: Target DC FQDN for the LDAP service SPN.
        auth_domain: Authenticating domain when different from target.
        auth_kdc: Auth KDC IP for cross-realm scenarios.
        account_scope: ``"user"`` (default) or ``"computer"``. Selects the LDAP
            account filter for the badPwdCount sweep — computer-pre2k spray
            eligibility needs the machine-account scope.

    Returns:
        SprayPolicyResult (partial results on error).
    """
    result = SprayPolicyResult()
    spray_filter = _SCOPE_FILTERS.get(account_scope, _USER_ONLY_FILTER)
    try:
        config = ADscanLDAPConfig(
            domain=domain,
            dc_ip=dc_ip,
            username=username,
            password=password,
            use_ldaps=True,
            use_kerberos=use_kerberos,
            kerberos_target_hostname=kerberos_target_hostname,
            auth_domain=auth_domain or domain,
            auth_kdc=auth_kdc,
        )
        conn, _used_ldaps = await async_connect_with_ldap_fallback(config)

        # Derive domain naming context
        server_info = getattr(conn, "_serverinfo", None) or {}
        domain_nc = (
            server_info.get("defaultNamingContext")
            or ",".join(f"DC={part}" for part in domain.split("."))
        )

        # Fetch policy and users concurrently
        (
            policy,
            pso_by_dn,
            (raw_badpwd_by_user, pso_dn_by_user, badpwdtime_by_user, locked_users),
        ) = await asyncio.gather(
            _fetch_domain_policy(conn, domain_nc),
            _fetch_pso_objects(conn, domain_nc),
            _fetch_user_badpwdcounts(
                conn, domain_nc, include_pso=True, spray_filter=spray_filter
            ),
        )

        result.default_policy = policy
        result.pso_by_dn = pso_by_dn
        result.raw_badpwd_by_user = raw_badpwd_by_user
        result.pso_dn_by_user = pso_dn_by_user
        result.badpwdtime_by_user = badpwdtime_by_user
        result.locked_users = locked_users

        # Observation-window adjustment: a stored badPwdCount only counts toward
        # lockout within the lockout observation window. Accounts whose last bad
        # password is outside that window have an EFFECTIVE count of 0 (Windows
        # resets the stored attribute only lazily, so it reads stale-high). This
        # is what stops spray over-exclusion of accounts that are not actually
        # near lockout.
        effective_badpwd, reset_count = _apply_observation_window_reset(
            result, datetime.now(timezone.utc)
        )
        result.badpwd_by_user = effective_badpwd

        print_info_debug(
            f"[spray_policy] fetched: threshold={policy.lockout_threshold}, "
            f"lockout_duration_s={policy.lockout_duration_seconds}, "
            f"pso_count={len(pso_by_dn)}, users={len(effective_badpwd)}, "
            f"pso_assigned_users={len(pso_dn_by_user)}, "
            f"observation_window_resets={reset_count}, "
            f"currently_locked={len(result.locked_users)} "
            f"(currently_locked = DC msDS-User-Account-Control-Computed UF_LOCKOUT, "
            f"PSO- and auto-unlock-aware)"
        )
        if result.locked_users:
            print_info_debug(
                "[spray_policy] currently-locked (excluded from spray): "
                + ", ".join(sorted(result.locked_users))
            )

        try:
            if hasattr(conn, "disconnect"):
                await conn.disconnect()
        except Exception:  # noqa: BLE001
            pass

    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        msg = f"Native policy fetch failed: {exc}"
        result.fetch_errors.append(msg)
        print_warning_debug(f"[spray_policy] {msg}")

    return result


def fetch_spray_policy_sync(
    *,
    domain: str,
    dc_ip: str,
    username: str | None = None,
    password: str | None = None,
    use_kerberos: bool = False,
    kerberos_target_hostname: str | None = None,
    auth_domain: str | None = None,
    auth_kdc: str | None = None,
    account_scope: str = "user",
) -> SprayPolicyResult:
    """Synchronous wrapper around fetch_spray_policy_native."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(
                    lambda: asyncio.run(
                        fetch_spray_policy_native(
                            domain=domain,
                            dc_ip=dc_ip,
                            username=username,
                            password=password,
                            use_kerberos=use_kerberos,
                            kerberos_target_hostname=kerberos_target_hostname,
                            auth_domain=auth_domain,
                            auth_kdc=auth_kdc,
                            account_scope=account_scope,
                        )
                    )
                )
                return future.result(timeout=30)
    except RuntimeError:
        pass

    return asyncio.run(
        fetch_spray_policy_native(
            domain=domain,
            dc_ip=dc_ip,
            username=username,
            password=password,
            use_kerberos=use_kerberos,
            kerberos_target_hostname=kerberos_target_hostname,
            auth_domain=auth_domain,
            auth_kdc=auth_kdc,
            account_scope=account_scope,
        )
    )
