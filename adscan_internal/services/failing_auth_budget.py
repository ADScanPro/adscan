"""Lockout budget for probes whose negative outcome is a failed sign-in.

Some detection probes authenticate as the scanning account on purpose in a way a
patched server REJECTS: the CVE-2019-1040 (Drop the MIC) check sends an NTLM
AUTHENTICATE without its MIC. (The CVE-2019-1166 check sent one too until 13.2;
no sign-in tells a patched host from a vulnerable one for that CVE, so it now
reads the patch level and sends nothing a server rejects.) With the earlier
construction of those probes (which corrupted the user / workstation
names) that rejection was recorded by the domain controller as a failed sign-in
for the scanning account (event 4625, status 0xC000006D / sub-status
0xC000006A), which increments its ``badPwdCount``. Measured on GOAD 2026-11-05:
one failure per probe against a patched DC, one probe per CVE pass, so a scan
with two passes sent two. Against many patched hosts the count is one per host,
which reaches any lockout threshold. The current probes send the real
credential, so the rejection is expected to come from the target's MIC check
rather than the DC; the budget stays in force until that is measured.

ADscan must never lock an account, so every such probe reserves one attempt from
a :class:`FailingAuthBudget` before it sends anything, and the budget is derived
from the account's real lockout headroom through the spray-eligibility SSOT
(:mod:`adscan_internal.services.spray_policy_service`: effective lockout
threshold, PSO-aware, observation-window-adjusted ``badPwdCount``, live lock bit).
The rules:

* Headroom unknown (policy or count unreadable): no attempt (fail closed). The
  probe is reported as not assessed, never as clean.
* Account cannot lock (threshold 0 / no lockout enforced): unlimited.
* Otherwise: ``threshold - effective_badPwdCount - SAFETY_MARGIN`` attempts,
  never below zero. The margin keeps room for the operator's own sign-ins and a
  typo, so the scan alone can never be what crosses the threshold.

One budget object is kept per ``(domain, account)`` for the whole session, so a
second CVE pass in the same scan draws from what the first one left.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Optional

from adscan_core import telemetry
from adscan_core.rich_output import print_exception, print_info_debug
from adscan_core.scan_policy.model import FAILING_SIGN_IN_SAFETY_MARGIN
from adscan_core.sensitive import mark_sensitive

#: Attempts always left unused below the lockout threshold. The value lives in
#: the scan-policy model so the client safety line states the same number.
SAFETY_MARGIN = FAILING_SIGN_IN_SAFETY_MARGIN

#: Threshold assumed when a PSO governs the account but cannot be read (same
#: conservative value the spray eligibility uses).
_UNREADABLE_PSO_FALLBACK_THRESHOLD = 3

_SHELL_ATTR = "_failing_auth_budgets"


@dataclass
class FailingAuthBudget:
    """How many deliberately-failing sign-ins an account can still absorb.

    Attributes:
        remaining: Attempts left, or ``None`` when the account cannot lock.
        reason: Why the budget has this size (operator-facing, English).
    """

    remaining: Optional[int]
    reason: str
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def try_reserve(self) -> bool:
        """Reserve one attempt; ``False`` when none is left. Thread-safe."""
        with self._lock:
            if self.remaining is None:
                return True
            if self.remaining <= 0:
                return False
            self.remaining -= 1
            return True

    def refund(self) -> None:
        """Give back a reservation whose attempt did not count as a failure."""
        with self._lock:
            if self.remaining is not None:
                self.remaining += 1


def exhausted_budget(reason: str) -> FailingAuthBudget:
    """A budget that allows nothing (the fail-closed default)."""
    return FailingAuthBudget(remaining=0, reason=reason)


def budget_from_lockout(
    *,
    threshold: Optional[int],
    effective_bad_pwd_count: Optional[int],
    locked: bool = False,
    no_lockout_enforced: bool = False,
    margin: int = SAFETY_MARGIN,
) -> FailingAuthBudget:
    """Derive the budget from one account's lockout state.

    Args:
        threshold: Effective lockout threshold for the account (``0`` = cannot
            lock), or ``None`` when unknown.
        effective_bad_pwd_count: Observation-window-adjusted ``badPwdCount``, or
            ``None`` when unknown.
        locked: The account is locked right now.
        no_lockout_enforced: The domain enforces no lockout.
        margin: Attempts always left unused.
    """
    if locked:
        return exhausted_budget("the scanning account is locked out right now")
    if no_lockout_enforced or threshold == 0:
        return FailingAuthBudget(remaining=None, reason="the account cannot be locked out")
    if threshold is None or effective_bad_pwd_count is None:
        return exhausted_budget(
            "the scanning account's lockout headroom could not be read"
        )
    remaining = max(0, int(threshold) - int(effective_bad_pwd_count) - int(margin))
    return FailingAuthBudget(
        remaining=remaining,
        reason=(
            f"{int(effective_bad_pwd_count)} failed sign-in(s) already counted "
            f"against a lockout threshold of {int(threshold)}, keeping {int(margin)} spare"
        ),
    )


def budget_from_spray_policy(policy: Any, username: str) -> FailingAuthBudget:
    """Derive the budget from a ``SprayPolicyResult`` for ``username``."""
    user = str(username or "").strip().lower()
    if "\\" in user:
        user = user.split("\\", 1)[1]
    if "@" in user:
        user = user.split("@", 1)[0]
    badpwd_by_user = getattr(policy, "badpwd_by_user", None) or {}
    if user not in badpwd_by_user:
        return exhausted_budget(
            "the scanning account's failed sign-in count could not be read"
        )
    default_policy = getattr(policy, "default_policy", None)
    lockout = policy.effective_lockout(
        user, conservative_threshold=_UNREADABLE_PSO_FALLBACK_THRESHOLD
    )
    return budget_from_lockout(
        threshold=lockout.threshold,
        effective_bad_pwd_count=badpwd_by_user.get(user),
        locked=user in (getattr(policy, "locked_users", None) or set()),
        no_lockout_enforced=bool(getattr(default_policy, "no_lockout_enforced", False)),
    )


def resolve_failing_auth_budget(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: Optional[str],
    dc_ip: Optional[str],
    kerberos_target_hostname: Optional[str] = None,
    reader_username: Optional[str] = None,
    reader_password: Optional[str] = None,
) -> FailingAuthBudget:
    """Return the session budget for ``username`` in ``domain`` (read once, memoized).

    By default the account reads its own lockout headroom. ``reader_username`` /
    ``reader_password`` read it as another account instead, for a sign-in AS an
    account whose current secret the caller does not hold yet (the confirming
    sign-in after a password restore).

    Never raises: any failure yields an exhausted budget, so the probes that
    consume it are skipped rather than sent blind.
    """
    key = (str(domain or "").strip().lower(), str(username or "").strip().lower())
    memo = getattr(shell, _SHELL_ATTR, None)
    if not isinstance(memo, dict):
        memo = {}
        try:
            setattr(shell, _SHELL_ATTR, memo)
        except Exception:  # noqa: BLE001 - a read-only shell just skips the memo
            pass
    cached = memo.get(key)
    if isinstance(cached, FailingAuthBudget):
        return cached
    bind_user = str(reader_username or username or "")
    bind_secret = reader_password if reader_username else password
    if not (domain and username and bind_secret and dc_ip):
        budget = exhausted_budget("no credential or domain controller to read the lockout policy")
    else:
        try:
            from adscan_internal.services.spray_policy_service import (  # noqa: PLC0415
                fetch_spray_policy_sync,
            )

            policy = fetch_spray_policy_sync(
                domain=domain,
                dc_ip=dc_ip,
                username=bind_user,
                password=bind_secret,
                kerberos_target_hostname=kerberos_target_hostname,
                only_account=username,
            )
            budget = budget_from_spray_policy(policy, username)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            budget = exhausted_budget("the lockout policy read failed")
    print_info_debug(
        "[failing-auth-budget] "
        f"user={mark_sensitive(username, 'user')} domain={mark_sensitive(domain, 'domain')} "
        f"remaining={'unlimited' if budget.remaining is None else budget.remaining} "
        f"reason={budget.reason}"
    )
    memo[key] = budget
    return budget


__all__ = [
    "SAFETY_MARGIN",
    "FailingAuthBudget",
    "budget_from_lockout",
    "budget_from_spray_policy",
    "exhausted_budget",
    "resolve_failing_auth_budget",
]
