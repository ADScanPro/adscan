"""Lockout guard for every sign-in ADscan sends with a password, hash or key.

ADscan must never be what locks a domain account. Spraying has always been held
to that by its eligibility service, which reads each account's live
``badPwdCount``. Every OTHER sign-in (verifying a stored credential, a revert
cascade, a lateral step, a ticket re-mint) used to rely on the caller doing the
right thing. Nothing counted what those sign-ins cost, so a caller that retried
a wrong secret, or several callers that each tried one, could add up to a
lockout with no single place able to stop it.

This module is that place. It is consulted by the authentication seams
themselves, so a caller cannot forget it:

* every Kerberos AS exchange that carries a password, NT hash or AES key
  (kerbad ``get_TGT``, async and sync; patched once in
  ``adscan_internal.services._kerberos_recovery``, which covers aiosmb, badldap,
  aardwolf and ADscan's own transports);
* every NTLM session setup over SMB (``smb_transport.smb_machine_for``);
* every NTLM bind over LDAP (``ldap_transport_service.async_connect_with_ldap_fallback``).

The rules, per principal per realm:

1. A secret that the domain already rejected is never sent again. Re-sending a
   known-bad secret can only add a failed sign-in.
2. A principal the domain reported as disabled or locked out is not tried
   again until a sign-in as that principal succeeds.
3. Failed sign-ins inside the lockout observation window are counted. Once the
   count reaches the budget, further sign-ins as that principal are refused
   until the window passes or a sign-in succeeds (the domain controller resets
   ``badPwdCount`` on a successful sign-in). A principal with no failure in the
   window is never refused: there is no evidence its secret is wrong, and
   refusing it would block every legitimate sign-in.

The budget is supplied by the session (:func:`register_policy_provider`) from
the scan policy's password-attempt rules and the domain's lockout policy, so
the reserve margin is the same number spraying keeps. Without a provider the
guard fails closed: one failed sign-in per principal per hour.

4. A sign-in with NO secret (an empty password, a username with nothing to send)
   is refused before it reaches the wire. The domain counts an empty secret like
   any other wrong one, and a caller that reaches a seam without a secret has a
   bug. The one deliberate exception, the blank-password check, opts in with
   :func:`allow_empty_secret`.

5. In a real environment, before a password, hash or key sign-in as a DOMAIN
   principal, the guard knows that principal's live headroom: its effective
   lockout threshold (fine-grained policy aware) minus the scan policy's reserve
   margin minus the ``badPwdCount`` the domain controller holds right now
   (observation-window adjusted). Below one attempt, the sign-in is refused
   without being sent, whatever this session has or has not sent before. The
   read is supplied by the session (:func:`register_live_headroom_provider`)
   from the same SSOT spraying uses, run once per principal per short window
   and dropped as soon as ADscan records a sign-in outcome for that principal.
   When the counter cannot be read, rule 3 applies at its most conservative
   (one failed sign-in per principal per window) and the session is told, so
   the gap is reported rather than assumed away. A secret the domain already
   accepted in this session is held to the strict floor instead of the margin:
   it is refused only when a single failure could lock the account (it can only
   fail if the password changed). Lab policies install no live read, and
   host-local accounts and SQL logins are never read (their lockout policy lives
   on the host), so rule 3 alone covers them.

What counts as a failure, an unusable account, or neither is decided by ONE
classifier, :mod:`adscan_core.auth_outcome`: only a verdict the domain controller
counted against ``badPwdCount`` is recorded as a failure, so a correct secret
that met a blocked protocol, a missing channel binding, an etype, a clock or a
ticket the service rejected is never withheld from the fallback that recovers it.

Local accounts and SQL logins are not domain principals: they are keyed to the
host (:func:`local_realm`) or the SQL instance (:func:`sql_login_realm`), so they
never share an entry, or a budget, with a domain account of the same name.

The guard is O(1) per sign-in (one dict lookup under a lock, budget memoized per
realm; the live read is cached per principal), thread-safe, and holds secrets
only as keyed digests in memory.
"""

from __future__ import annotations

import contextlib
import contextvars
import hashlib
import os
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

from adscan_core.sensitive import mark_sensitive

if TYPE_CHECKING:  # pragma: no cover - typing only
    from adscan_core.auth_outcome import AuthVerdict

__all__ = [
    "AuthAttemptRefused",
    "LiveHeadroom",
    "LockoutBudget",
    "OUTCOME_FAILED",
    "OUTCOME_UNUSABLE",
    "FAIL_CLOSED_BUDGET",
    "UNKNOWN_WINDOW_SECONDS",
    "LOCAL_REALM_PREFIX",
    "SQL_REALM_PREFIX",
    "LIVE_SKIPPED",
    "LIVE_UNVERIFIED",
    "allow_empty_secret",
    "refusal_in_chain",
    "unknown_headroom",
    "budget_from_policy",
    "check_attempt",
    "is_host_scoped_realm",
    "live_counter_checked_by_caller",
    "local_realm",
    "prefetch_live_headroom",
    "record_failure",
    "record_success",
    "record_unusable",
    "record_verdict",
    "sql_login_realm",
    "unusable_reason",
    "register_live_headroom_provider",
    "register_policy_provider",
    "remaining_failures",
    "unregister_policy_provider",
    "reset_for_tests",
    "snapshot",
]

#: Outcome labels (also used in the refusal reason).
OUTCOME_FAILED = "failed"
OUTCOME_UNUSABLE = "unusable"

#: How long a realm's budget is reused before the provider is asked again.
_BUDGET_TTL_SECONDS = 120.0

#: How long a principal's live headroom is reused before it is read again.
#: Short: other people's failed sign-ins keep arriving while ADscan works. Any
#: outcome ADscan records for the principal drops the entry earlier.
_LIVE_TTL_SECONDS = 120.0

#: How long a live read may take before the guard gives up on it and treats the
#: counter as unreadable (fail closed). Covers the LDAPS -> StartTLS -> sealed
#: LDAP ladder over a slow VPN.
_LIVE_READ_TIMEOUT_SECONDS = 45.0

#: Principals asked for in one read. One LDAP filter carries them all.
_LIVE_BATCH_SIZE = 100

#: Per-process key for secret digests. Never persisted; a new process starts a
#: new ledger, which matches the session-scoped promise.
_DIGEST_KEY = os.urandom(32)


class AuthAttemptRefused(PermissionError):
    """A sign-in was withheld because it could push the account toward lockout.

    Attributes:
        realm: Canonical realm (upper-case) the principal belongs to.
        principal: Normalized account name.
        reason: Operator-facing English sentence.
    """

    def __init__(self, realm: str, principal: str, reason: str) -> None:
        self.realm = realm
        self.principal = principal
        self.reason = reason
        # Marked at the source: the message reaches the terminal (cleartext for
        # the operator) and the session recording (scrubbed by the sanitizer).
        super().__init__(
            f"Sign-in as {mark_sensitive(principal, 'user')}@{mark_sensitive(realm, 'domain')} "
            f"withheld to protect the account from lockout: {reason}"
        )


@dataclass(frozen=True)
class LockoutBudget:
    """How many failed sign-ins ADscan may cause for one principal.

    Attributes:
        max_failures: Failed sign-ins allowed inside the window, or ``None``
            when the account cannot be locked out.
        window_seconds: The domain's lockout observation window (the counter
            resets once this long has passed since the last failure), or
            ``None`` when failures never expire.
        source: Short description of where the numbers came from.
    """

    max_failures: Optional[int]
    window_seconds: Optional[float]
    source: str


#: The fail-closed budget: one failed sign-in per principal per hour. It mirrors
#: the scan policy's conservative handling of an unreadable threshold (assume 3,
#: keep a margin of 2, one attempt per account per hour).
FAIL_CLOSED_BUDGET = LockoutBudget(
    max_failures=1, window_seconds=3600.0, source="lockout policy unknown"
)

#: The window assumed when the domain's observation window cannot be read: the
#: scan policy's conservative "one attempt per account per hour".
UNKNOWN_WINDOW_SECONDS = 3600.0


@dataclass(frozen=True)
class LiveHeadroom:
    """One domain principal's lockout state as the domain controller holds it now.

    Built by the session's live read (the spray-eligibility SSOT: the account's
    effective lockout threshold, fine-grained policy aware, and its
    observation-window-adjusted ``badPwdCount``, read from the lockout authority).

    Attributes:
        known: The counter was read. ``False`` means the guard must not assume
            anything about it (rule 3 then applies at its most conservative).
        threshold: The account's effective lockout threshold, ``0`` when the
            account provably cannot lock.
        bad_count: The effective ``badPwdCount`` (failures inside the
            observation window).
        locked: The domain controller reports the account locked out right now.
        margin: The scan policy's reserve margin.
        conservative: The counter came from a replica whose PDC emulator could
            not be reached, so it may lag: at most one failed sign-in per window.
        source: Where the numbers came from, or why they are unknown (English,
            operator-facing).
    """

    known: bool
    threshold: Optional[int] = None
    bad_count: Optional[int] = None
    locked: bool = False
    margin: int = 0
    conservative: bool = False
    source: str = ""

    def remaining(self, *, known_good_secret: bool = False) -> Optional[int]:
        """Failed sign-ins ADscan may still cause, or ``None`` when it cannot lock.

        ``threshold - margin - bad_count`` for a secret the domain has not
        accepted. A secret it already accepted in this session is held to the
        strict floor (``threshold - 1 - bad_count``): it fails only if the
        password changed, and then one failure must still not lock the account.
        An unknown counter returns ``0``.
        """
        if not self.known or self.threshold is None or self.bad_count is None:
            return 0
        if self.threshold <= 0:
            return None
        keep = 1 if known_good_secret else max(0, int(self.margin))
        return int(self.threshold) - keep - int(self.bad_count)


def unknown_headroom(reason: str) -> LiveHeadroom:
    """A headroom whose counter could not be read (never treated as zero failures)."""
    return LiveHeadroom(known=False, source=str(reason or "the counter could not be read"))


def budget_from_policy(
    *,
    threshold: Optional[int],
    window_minutes: Optional[int],
    reserve_margin: int,
    lab: bool,
    ignore_threshold: bool,
    attempt_anyway_when_unknown: bool,
) -> LockoutBudget:
    """Derive the per-principal budget from the policy rules and the domain policy.

    Args:
        threshold: The domain's default lockout threshold (``0`` = no lockout),
            or ``None`` when it was not read.
        window_minutes: The domain's lockout observation window, or ``None``.
        reserve_margin: The scan policy's reserve margin (the same number
            spraying keeps).
        lab: The scan policy's environment is a lab.
        ignore_threshold: Lab-only policy switch: no account can lock.
        attempt_anyway_when_unknown: Lab-only handling of an unread threshold.

    The domain default is only a floor of knowledge: a fine-grained password
    policy can lower the threshold for some accounts (privileged ones above
    all), and reading it per account would mean an LDAP bind inside the
    authentication seam. So a real environment never budgets above the
    conservative assumed threshold, whatever the domain default says, and a
    domain without lockout is not taken as proof that no account can lock.
    A lab uses the observed threshold as it is.
    """
    from adscan_core.scan_policy.policy import (  # noqa: PLC0415
        CONSERVATIVE_ASSUMED_THRESHOLD,
    )

    margin = max(0, int(reserve_margin))
    window = float(window_minutes) * 60.0 if window_minutes and window_minutes > 0 else None
    if lab:
        if ignore_threshold:
            return LockoutBudget(None, None, "the lab policy ignores the lockout threshold")
        if threshold == 0:
            return LockoutBudget(None, None, "the domain enforces no lockout")
        if threshold is None:
            if attempt_anyway_when_unknown:
                return LockoutBudget(
                    None, None, "the lab policy attempts anyway when the threshold is unknown"
                )
            effective = CONSERVATIVE_ASSUMED_THRESHOLD
            source = f"threshold unknown, assumed {effective}"
        else:
            effective = int(threshold)
            source = f"lockout threshold {effective}"
    else:
        if threshold is None or threshold <= 0:
            effective = CONSERVATIVE_ASSUMED_THRESHOLD
            source = (
                f"no domain-wide lockout, assumed {effective} for accounts a "
                "fine-grained policy may cover"
                if threshold == 0
                else f"threshold unknown, assumed {effective}"
            )
        else:
            effective = min(int(threshold), CONSERVATIVE_ASSUMED_THRESHOLD)
            source = (
                f"lockout threshold {int(threshold)}, capped at {effective} for accounts "
                "a fine-grained policy may cover"
                if effective < int(threshold)
                else f"lockout threshold {effective}"
            )
    return LockoutBudget(
        max_failures=max(1, effective - margin),
        window_seconds=window if window is not None else UNKNOWN_WINDOW_SECONDS,
        source=f"{source}, keeping {margin} spare",
    )


#: Realm prefixes for principals that are NOT domain accounts. A local account
#: lives in one host's SAM, a SQL login in one instance: each gets its own ledger
#: entry and never shares a budget with a domain account of the same name.
LOCAL_REALM_PREFIX = "LOCAL@"
SQL_REALM_PREFIX = "SQL@"


def local_realm(host: str) -> str:
    """The ledger realm of a host-local account (the host's own SAM)."""
    return f"{LOCAL_REALM_PREFIX}{str(host or '').strip().rstrip('.').lower()}"


def sql_login_realm(host: str, port: int | str = 1433) -> str:
    """The ledger realm of a SQL Server login (one instance)."""
    return f"{SQL_REALM_PREFIX}{str(host or '').strip().rstrip('.').lower()}:{port}"


def is_host_scoped_realm(realm: str) -> bool:
    """True for a local-account or SQL-login realm (never a domain)."""
    upper = str(realm or "").strip().upper()
    return upper.startswith(LOCAL_REALM_PREFIX) or upper.startswith(SQL_REALM_PREFIX)


_EMPTY_SECRET_ALLOWED: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "adscan_auth_guard_empty_secret_allowed", default=False
)


@contextlib.contextmanager
def allow_empty_secret() -> Iterator[None]:
    """Allow an EMPTY secret inside this block (the blank-password check only).

    The blank-password check sends an empty password on purpose: that is the
    test. Everywhere else an empty secret is a caller bug the guard refuses.
    The sign-in is still counted when the domain rejects it.
    """
    token = _EMPTY_SECRET_ALLOWED.set(True)
    try:
        yield
    finally:
        _EMPTY_SECRET_ALLOWED.reset(token)


PolicyProvider = Callable[[str], Optional[LockoutBudget]]
RealmCanonicalizer = Callable[[str], str]
#: ``provider(realm, principals)`` returns the live headroom of each principal
#: (normalized name -> :class:`LiveHeadroom`), or ``None`` when live reads do
#: not apply to the realm (a lab policy). A principal missing from the mapping
#: is unknown. It runs on a worker thread with no event loop of its own.
LiveHeadroomProvider = Callable[[str, tuple[str, ...]], Optional[dict[str, LiveHeadroom]]]
#: ``sink(realm, principal, kind, headroom)``: ``kind`` is ``"skipped"`` (a
#: sign-in withheld because the live counter left no headroom) or
#: ``"unverified"`` (a sign-in judged without a readable counter). Called once
#: per principal and kind per session, outside the guard's lock.
LiveHeadroomSink = Callable[[str, str, str, LiveHeadroom], None]

#: Kinds passed to the live headroom sink.
LIVE_SKIPPED = "skipped"
LIVE_UNVERIFIED = "unverified"


@dataclass
class _PrincipalState:
    failures: int = 0
    last_failure: float = 0.0
    failed_secrets: set[bytes] = field(default_factory=set)
    accepted_secrets: set[bytes] = field(default_factory=set)
    unusable_reason: str = ""


_LOCK = threading.Lock()
_STATES: dict[tuple[str, str], _PrincipalState] = {}
_BUDGETS: dict[str, tuple[LockoutBudget, float]] = {}
_PROVIDER: Optional[PolicyProvider] = None
_CANONICALIZER: Optional[RealmCanonicalizer] = None

_LIVE_PROVIDER: Optional[LiveHeadroomProvider] = None
_LIVE_SINK: Optional[LiveHeadroomSink] = None
#: (realm, principal) -> (headroom, monotonic time read). ``None`` headroom means
#: the realm has no live read (lab).
_LIVE_CACHE: dict[tuple[str, str], tuple[Optional[LiveHeadroom], float]] = {}
_LIVE_REPORTED: set[tuple[str, str, str]] = set()
#: One read in flight per realm; a second caller waits and reuses its answer.
_LIVE_REALM_LOCKS: dict[str, threading.Lock] = {}

#: Set on the worker thread that performs a live read: the read's own sign-in
#: (as the reading principal) is judged by rules 1 to 4 only, never by a nested
#: read of its own counter.
_LIVE_READ_ACTIVE: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "adscan_auth_guard_live_read_active", default=False
)
#: Set by a caller that already applied the live counter to these exact
#: sign-ins (the spray eligibility SSOT, which reads every candidate's
#: ``badPwdCount`` in one pass and spends at most one attempt per account).
_LIVE_VOUCHED: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "adscan_auth_guard_live_vouched", default=False
)


def register_policy_provider(
    provider: PolicyProvider, canonicalizer: Optional[RealmCanonicalizer] = None
) -> None:
    """Install the session's budget provider (and optional realm canonicalizer).

    ``provider(realm)`` returns the :class:`LockoutBudget` for a canonical realm,
    or ``None`` when it does not know the realm (the fail-closed budget then
    applies). ``canonicalizer(name)`` maps a NetBIOS name or FQDN to one
    canonical realm so ``ESSOS`` and ``essos.local`` share a ledger entry.
    """
    global _PROVIDER, _CANONICALIZER  # noqa: PLW0603 - process-wide seam by design
    with _LOCK:
        _PROVIDER = provider
        _CANONICALIZER = canonicalizer
        _BUDGETS.clear()


def register_live_headroom_provider(
    provider: LiveHeadroomProvider, sink: Optional[LiveHeadroomSink] = None
) -> None:
    """Install the session's live ``badPwdCount`` read (rule 5) and its reporting sink."""
    global _LIVE_PROVIDER, _LIVE_SINK  # noqa: PLW0603 - process-wide seam by design
    with _LOCK:
        _LIVE_PROVIDER = provider
        _LIVE_SINK = sink
        _LIVE_CACHE.clear()


def unregister_policy_provider() -> None:
    """Remove the session's providers; the fail-closed budget applies again.

    The live read is part of the same session registration, so it goes too.
    """
    global _PROVIDER, _CANONICALIZER, _LIVE_PROVIDER, _LIVE_SINK  # noqa: PLW0603
    with _LOCK:
        _PROVIDER = None
        _CANONICALIZER = None
        _LIVE_PROVIDER = None
        _LIVE_SINK = None
        _BUDGETS.clear()
        _LIVE_CACHE.clear()


def reset_for_tests() -> None:
    """Forget every principal, budget and live read (unit tests only)."""
    with _LOCK:
        _STATES.clear()
        _BUDGETS.clear()
        _LIVE_CACHE.clear()
        _LIVE_REPORTED.clear()


@contextlib.contextmanager
def live_counter_checked_by_caller() -> Iterator[None]:
    """Mark sign-ins whose live counter the caller already applied.

    Only for the password spray and the hash-reuse spray: their eligibility SSOT
    reads every candidate's ``badPwdCount`` from the lockout authority in one
    pass, applies the same margin, and spends at most one attempt per account,
    so a second read per account here would cost one LDAP bind per user for
    nothing. Rules 1 to 4 still apply inside the block.
    """
    token = _LIVE_VOUCHED.set(True)
    try:
        yield
    finally:
        _LIVE_VOUCHED.reset(token)


def _normalize_principal(principal: str) -> str:
    name = str(principal or "").strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name.strip().lower()


def _canonical_realm(realm: str) -> str:
    raw = str(realm or "").strip().rstrip(".")
    canonicalizer = _CANONICALIZER
    if raw and is_host_scoped_realm(raw):
        return raw.upper()
    if canonicalizer is not None and raw:
        try:
            mapped = canonicalizer(raw)
            if mapped:
                raw = str(mapped).strip().rstrip(".")
        except Exception:  # noqa: BLE001 - a broken canonicalizer keeps the raw name
            pass
    return raw.upper()


def _digest(secret: Optional[str]) -> Optional[bytes]:
    # An EMPTY secret is a real secret: an empty-password bind is judged and
    # counted by the domain like any other, so it must be remembered as rejected.
    if secret is None:
        return None
    return hashlib.blake2b(str(secret).encode("utf-8"), key=_DIGEST_KEY, digest_size=16).digest()


def _budget_for(realm: str, now: float) -> LockoutBudget:
    cached = _BUDGETS.get(realm)
    if cached is not None and now - cached[1] < _BUDGET_TTL_SECONDS:
        return cached[0]
    budget: Optional[LockoutBudget] = None
    provider = _PROVIDER
    if provider is not None:
        try:
            budget = provider(realm)
        except Exception:  # noqa: BLE001 - an unreadable policy fails closed
            budget = None
    if budget is None:
        budget = FAIL_CLOSED_BUDGET
    _BUDGETS[realm] = (budget, now)
    return budget


def _expire(state: _PrincipalState, budget: LockoutBudget, now: float) -> None:
    window = budget.window_seconds
    if state.failures and window is not None and now - state.last_failure >= window:
        state.failures = 0


def _key(realm: str, principal: str) -> tuple[str, str]:
    return (_canonical_realm(realm), _normalize_principal(principal))


def _live_entry_fresh(key: tuple[str, str], now: float) -> bool:
    entry = _LIVE_CACHE.get(key)
    return entry is not None and now - entry[1] < _LIVE_TTL_SECONDS


def _run_live_provider(
    provider: LiveHeadroomProvider, realm: str, principals: tuple[str, ...]
) -> tuple[Optional[dict[str, LiveHeadroom]], str]:
    """Run one live read on its own worker thread.

    The seams call the guard from inside running event loops (kerbad, badauth),
    so the read cannot reuse the caller's loop; a fresh thread gives it its own.
    Returns ``(result, failure_reason)``: ``failure_reason`` is set when the
    read raised or timed out, and every principal is then unknown.
    """
    box: dict[str, object] = {}

    def _worker() -> None:
        token = _LIVE_READ_ACTIVE.set(True)
        try:
            box["result"] = provider(realm, principals)
        except BaseException as exc:  # noqa: BLE001 - an unreadable counter fails closed
            box["error"] = exc
        finally:
            _LIVE_READ_ACTIVE.reset(token)

    worker = threading.Thread(target=_worker, name="adscan-lockout-counter-read", daemon=True)
    worker.start()
    worker.join(_LIVE_READ_TIMEOUT_SECONDS)
    if worker.is_alive():
        return {}, "the read of the failed sign-in count timed out"
    if "error" in box:
        return {}, f"the read of the failed sign-in count failed ({type(box['error']).__name__})"
    result = box.get("result")
    if result is None:
        return None, ""
    return (result if isinstance(result, dict) else {}), ""


def _fetch_live(realm: str, principals: list[str]) -> None:
    """Read (and cache) the live headroom of ``principals`` that are not fresh."""
    provider = _LIVE_PROVIDER
    if provider is None or not principals:
        return
    with _LOCK:
        realm_lock = _LIVE_REALM_LOCKS.setdefault(realm, threading.Lock())
    with realm_lock:
        now = time.monotonic()
        with _LOCK:
            pending = list(
                dict.fromkeys(p for p in principals if p and not _live_entry_fresh((realm, p), now))
            )
        for start in range(0, len(pending), _LIVE_BATCH_SIZE):
            chunk = tuple(pending[start : start + _LIVE_BATCH_SIZE])
            result, failure = _run_live_provider(provider, realm, chunk)
            stamp = time.monotonic()
            with _LOCK:
                for principal in chunk:
                    if result is None and not failure:
                        headroom: Optional[LiveHeadroom] = None  # no live read for this realm
                    else:
                        headroom = (result or {}).get(principal) or unknown_headroom(
                            failure or "no failed sign-in count was returned for this account"
                        )
                    _LIVE_CACHE[(realm, principal)] = (headroom, stamp)


def _live_applies(realm: str) -> bool:
    return (
        _LIVE_PROVIDER is not None
        and not is_host_scoped_realm(realm)
        and not _LIVE_READ_ACTIVE.get()
        and not _LIVE_VOUCHED.get()
    )


def _live_headroom(key: tuple[str, str]) -> Optional[LiveHeadroom]:
    """The principal's live headroom, read if needed; ``None`` when rule 5 does not apply."""
    if not _live_applies(key[0]):
        return None
    with _LOCK:
        fresh = _live_entry_fresh(key, time.monotonic())
        entry = _LIVE_CACHE.get(key)
    if not fresh:
        _fetch_live(key[0], [key[1]])
        with _LOCK:
            entry = _LIVE_CACHE.get(key)
    if entry is None:
        return unknown_headroom("the failed sign-in count could not be read")
    return entry[0]


def _report_live(key: tuple[str, str], kind: str, headroom: LiveHeadroom) -> None:
    sink = _LIVE_SINK
    if sink is None:
        return
    marker = (key[0], key[1], kind)
    with _LOCK:
        if marker in _LIVE_REPORTED:
            return
        _LIVE_REPORTED.add(marker)
    try:
        sink(key[0], key[1], kind, headroom)
    except Exception:  # noqa: BLE001 - reporting must never change the verdict
        pass


def _most_conservative(budget: LockoutBudget, live: Optional[LiveHeadroom]) -> LockoutBudget:
    """Rule 3 at its tightest when the live counter is unknown or may lag."""
    if live is None or (live.known and not live.conservative):
        return budget
    if budget.max_failures is None or budget.max_failures > 1:
        reason = (
            "the account's failed sign-in count was read from a replica that can lag the PDC"
            if live.known
            else f"the account's failed sign-in count could not be read ({live.source})"
        )
        return LockoutBudget(
            max_failures=1,
            window_seconds=budget.window_seconds or UNKNOWN_WINDOW_SECONDS,
            source=f"{budget.source}; {reason}, so one failed sign-in per window",
        )
    return budget


def _live_refusal_reason(live: LiveHeadroom, *, known_good: bool) -> str:
    if live.locked:
        return "the domain controller reports the account locked out right now"
    spare = (
        "so one more failure could lock it"
        if known_good
        else f"and this scan keeps {int(live.margin)} spare"
    )
    return (
        f"the domain controller already counts {int(live.bad_count or 0)} failed sign-in(s) "
        f"against a lockout threshold of {int(live.threshold or 0)}, {spare} ({live.source})"
    )


def check_attempt(realm: str, principal: str, secret: Optional[str]) -> None:
    """Raise :class:`AuthAttemptRefused` when this sign-in must not be sent.

    Call it immediately before a password, hash or key sign-in goes on the wire.
    A sign-in without a usable principal is not judged (there is nothing to
    count it against). An empty secret for a named principal is refused unless
    :func:`allow_empty_secret` is active.
    """
    key = _key(realm, principal)
    if not key[1]:
        return
    if (secret is None or secret == "") and not _EMPTY_SECRET_ALLOWED.get():
        raise AuthAttemptRefused(
            key[0],
            key[1],
            "no password, hash or key was supplied for this sign-in; an empty secret "
            "is never sent, because the domain would count it as a failed sign-in",
        )
    digest = _digest(secret)
    known_good = False
    with _LOCK:
        state = _STATES.get(key)
        if state is not None:
            if state.unusable_reason:
                raise AuthAttemptRefused(
                    key[0],
                    key[1],
                    f"the domain reported the account as {state.unusable_reason}; it is not "
                    "tried again in this session",
                )
            if digest is not None and digest in state.failed_secrets:
                raise AuthAttemptRefused(
                    key[0], key[1], "the domain already rejected this exact secret"
                )
            known_good = digest is not None and digest in state.accepted_secrets
    # Rule 5: the domain controller's own counter, read outside the lock.
    live = _live_headroom(key)
    if live is not None and live.known:
        remaining = live.remaining(known_good_secret=known_good)
        if live.locked or (remaining is not None and remaining < 1):
            _report_live(key, LIVE_SKIPPED, live)
            raise AuthAttemptRefused(
                key[0], key[1], _live_refusal_reason(live, known_good=known_good)
            )
    elif live is not None:
        _report_live(key, LIVE_UNVERIFIED, live)
    now = time.monotonic()
    with _LOCK:
        state = _STATES.get(key)
        if state is None:
            return
        budget = _most_conservative(_budget_for(key[0], now), live)
        _expire(state, budget, now)
        if budget.max_failures is None or state.failures == 0:
            return
        if state.failures >= budget.max_failures:
            raise AuthAttemptRefused(
                key[0],
                key[1],
                f"{state.failures} failed sign-in(s) already sent inside the lockout "
                f"window, the most this scan allows ({budget.source})",
            )


def prefetch_live_headroom(realm: str, principals: "list[str] | tuple[str, ...]") -> None:
    """Read the live counters of many principals in one pass before signing in as them.

    For a caller about to sign in as several domain principals (verifying
    recovered credentials, re-verifying owned ones): one LDAP read instead of
    one per principal. A no-op where rule 5 does not apply.
    """
    canonical = _canonical_realm(realm)
    if not canonical or not _live_applies(canonical):
        return
    names = [_normalize_principal(p) for p in principals]
    _fetch_live(canonical, [n for n in names if n])


def remaining_failures(realm: str, principal: str) -> Optional[int]:
    """Failed sign-ins ADscan may still send as ``principal`` with an untried secret.

    The smaller of the session budget (rule 3, at its most conservative when the
    live counter is unknown) and the live headroom (rule 5). ``None`` when
    neither limits it; ``0`` when the next sign-in with a new secret would be
    refused. Callers that try several candidate secrets for one account use it
    to decide how many to try, instead of deriving a budget of their own.
    """
    key = _key(realm, principal)
    if not key[1]:
        return 0
    live = _live_headroom(key)
    live_remaining: Optional[int] = None
    if live is not None and live.known:
        live_remaining = 0 if live.locked else live.remaining()
    now = time.monotonic()
    with _LOCK:
        state = _STATES.get(key)
        if state is not None and state.unusable_reason:
            return 0
        budget = _most_conservative(_budget_for(key[0], now), live)
        failures = 0
        if state is not None:
            _expire(state, budget, now)
            failures = state.failures
    session_remaining = (
        None if budget.max_failures is None else max(0, budget.max_failures - failures)
    )
    values = [v for v in (live_remaining, session_remaining) if v is not None]
    return max(0, min(values)) if values else None


def record_failure(
    realm: str, principal: str, secret: Optional[str], *, weight: int = 1
) -> None:
    """Count a sign-in the domain rejected as a wrong secret.

    ``weight`` is how many failed sign-ins the exchange cost on the domain
    controller (a Kerberos client that retried pre-authentication once with a
    corrected salt sent two).
    """
    key = _key(realm, principal)
    if not key[1]:
        return
    now = time.monotonic()
    digest = _digest(secret)
    with _LOCK:
        state = _STATES.setdefault(key, _PrincipalState())
        budget = _budget_for(key[0], now)
        _expire(state, budget, now)
        state.failures += max(1, int(weight))
        state.last_failure = now
        if digest is not None:
            state.failed_secrets.add(digest)
            state.accepted_secrets.discard(digest)
        # The domain controller's counter just moved: read it again next time.
        _LIVE_CACHE.pop(key, None)


def record_unusable(realm: str, principal: str, reason: str) -> None:
    """Remember that the domain reported the account as disabled or locked."""
    key = _key(realm, principal)
    if not key[1]:
        return
    with _LOCK:
        state = _STATES.setdefault(key, _PrincipalState())
        state.unusable_reason = str(reason or "disabled or locked out")
        _LIVE_CACHE.pop(key, None)


def record_success(realm: str, principal: str, secret: Optional[str] = None) -> None:
    """A sign-in succeeded: the domain controller reset the failure counter.

    Secrets that failed earlier stay remembered (they are still wrong). The
    accepted ``secret``, when given, is remembered as accepted: rule 5 holds it
    to the strict floor rather than the reserve margin.
    """
    key = _key(realm, principal)
    if not key[1]:
        return
    digest = _digest(secret) if secret else None
    with _LOCK:
        # The domain controller reset its counter: read it again next time.
        _LIVE_CACHE.pop(key, None)
        state = _STATES.get(key)
        if state is None:
            if digest is None:
                return
            state = _STATES.setdefault(key, _PrincipalState())
        state.failures = 0
        state.unusable_reason = ""
        if digest is not None:
            state.accepted_secrets.add(digest)


def record_verdict(
    realm: str,
    principal: str,
    secret: Optional[str],
    verdict: "AuthVerdict",
    *,
    weight: int = 1,
) -> None:
    """Apply a classified outcome (:mod:`adscan_core.auth_outcome`) to the ledger.

    Only ``WRONG_SECRET`` counts, only ``ACCOUNT_STATE`` stops the principal,
    and ``SUCCESS`` clears it. ``METHOD_OR_CONFIG`` and ``UNKNOWN`` leave the
    ledger untouched, so the caller's fallback runs with the same secret.
    """
    from adscan_core.auth_outcome import AuthOutcome  # noqa: PLC0415

    outcome = verdict.outcome
    if outcome is AuthOutcome.SUCCESS:
        record_success(realm, principal, secret)
    elif outcome is AuthOutcome.WRONG_SECRET:
        record_failure(realm, principal, secret, weight=weight)
    elif outcome is AuthOutcome.ACCOUNT_STATE:
        record_unusable(realm, principal, verdict.reason or "disabled or locked out")


def refusal_in_chain(exc: Optional[BaseException]) -> Optional[AuthAttemptRefused]:
    """The guard refusal behind ``exc`` (itself or a cause / context), or ``None``.

    A transport may wrap the refusal in its own error type; a caller that must
    tell "never sent" from "sent and rejected" walks the chain with this.
    """
    seen: set[int] = set()
    current = exc
    while current is not None and id(current) not in seen:
        if isinstance(current, AuthAttemptRefused):
            return current
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return None


def unusable_reason(realm: str, principal: str) -> str:
    """Why the domain reported this principal unusable in this session, or ``""``."""
    key = _key(realm, principal)
    if not key[1]:
        return ""
    with _LOCK:
        state = _STATES.get(key)
        return state.unusable_reason if state is not None else ""


def snapshot() -> dict[tuple[str, str], dict[str, object]]:
    """Counts per principal, for diagnostics and tests. Never includes secrets."""
    with _LOCK:
        return {
            key: {
                "failures": state.failures,
                "failed_secrets": len(state.failed_secrets),
                "unusable": state.unusable_reason,
            }
            for key, state in _STATES.items()
        }
