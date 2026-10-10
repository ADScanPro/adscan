"""Persisting the password-hygiene block, and keeping it current afterwards.

:mod:`adscan_core.reporting.password_hygiene` owns the DERIVATION (the recovery
rate, the per-tier coverage, the reuse grouping, the absence rule) and the
pure FOLD that moves accounts from the unrecovered side to the recovered one.
This module owns the two session-bound halves neither of those can do: writing
the block as control evidence, and grading a later recovery's accounts by
privilege tier from the live workspace.

WHY A SECOND SEAM EXISTS AT ALL
-------------------------------
The block is derived once, when credential material is extracted. The local
wordlist attack on those same hashes runs as a BACKGROUND job and finishes
afterwards, so the figures written at extraction time can be older than the
recovery picture by the time a client reads them. The error runs in the
direction that reads as "these passwords held", which is the false negative the
Exposure-Validation doctrine forbids: a document stating two of fifty passwords
were resolved, on an engagement where thirty of fifty fell, understates exposure
to the one reader who cannot check it.

So the figures are folded forward at the SAME seam that promotes the attack's
coverage class from "still running" to "completed". That co-location is the
invariant, not a convenience: the coverage statement and the hygiene figures are
two sentences about one event, and the only way they can contradict each other
is if one is updated without the other.

WHAT THIS MODULE REFUSES TO DO
------------------------------
It never creates a block. A domain whose extraction never produced one has no
extracted population on record, and the accounts a later attack recovered are
not that population: using them as the denominator would invent a figure. The
honest outcome there is the absence the client already gets, and the coverage
statement still declares what the attack did.

It never runs from a job thread. The background-job invariant is that a worker
never writes the report; every entry point here is called from the foreground
drain.
"""

from __future__ import annotations

from typing import Any, Iterable, Sequence

from adscan_core import telemetry
from adscan_core.rich_output import print_exception, print_info_debug

#: The client-facing title and category the block is filed under. Here rather
#: than at each call site so the extraction-time write and the later fold cannot
#: file the same evidence under two different names.
HYGIENE_TITLE = "Password Hygiene"
HYGIENE_CATEGORY = "Password Hygiene"


def persist_password_hygiene_details(
    shell: Any, domain: str, details: dict[str, Any]
) -> bool:
    """Write ``details`` as this domain's password-hygiene control evidence.

    The ONE writer. Callers decide WHETHER to write (the absence rule lives with
    them, because only they know whether the block carries figures); this
    decides WHERE and under what name.

    Returns:
        ``True`` when the write was issued. Best-effort: never raises, because a
        deliverable is never failed over its own evidence record.
    """
    if not domain or not isinstance(details, dict) or not details:
        return False
    try:
        from adscan_core.reporting.password_hygiene import PASSWORD_HYGIENE_KEY
        from adscan_core.reporting.technical_report import record_control_evidence

        record_control_evidence(
            shell,
            domain,
            key=PASSWORD_HYGIENE_KEY,
            title=HYGIENE_TITLE,
            category=HYGIENE_CATEGORY,
            status="observed",
            details=details,
        )
        return True
    except Exception as exc:  # noqa: BLE001 — evidence is never worth a failure
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False


def _tier_resolver(shell: Any, domain: str, accounts: Sequence[str]):
    """Return ``(tier_for, high_value_for)``, resolved once for the whole batch.

    Reuses the grading the extraction-time derivation used, so an account lands
    in the same privilege tier whichever seam credits it. An account the grading
    cannot place resolves to ``ungraded``, which is what
    ``build_password_hygiene`` does with it too: reporting it as Tier 2 would
    state a grade nothing observed supports, and a grading failure must not
    quietly reclassify a domain admin as a standard user.

    The high-value flag is returned separately because it is the other axis.
    """
    from adscan_core.reporting.privilege_tier_labels import TIER_TOKEN_UNGRADED

    by_account: dict[str, str] = {}
    high_value: set[str] = set()
    normalize = None
    try:
        from adscan_internal.services.high_value import (
            classify_users_privilege_tier,
            normalize_samaccountname,
        )

        normalize = normalize_samaccountname
        for username, flags in (
            classify_users_privilege_tier(
                shell, domain=domain, usernames=list(accounts)
            )
            or {}
        ).items():
            key = normalize(str(username))
            tier = str(getattr(flags, "tier", "") or "")
            if tier:
                by_account[key] = tier
            if getattr(flags, "is_high_value", False):
                high_value.add(key)
    except Exception as exc:  # noqa: BLE001 — an ungradable account stays ungraded
        telemetry.capture_exception(exc)
        print_exception(exception=exc)

    def _key(account: str) -> str:
        return normalize(str(account)) if normalize else str(account).casefold()

    def _tier_for(account: str) -> str:
        return by_account.get(_key(account), TIER_TOKEN_UNGRADED)

    def _high_value_for(account: str) -> bool:
        return _key(account) in high_value

    return _tier_for, _high_value_for


def reconcile_password_hygiene_after_recovery(
    shell: Any, *, domain: str, recovered_accounts: Iterable[str]
) -> bool:
    """Fold a later recovery into this domain's persisted hygiene figures.

    Called from the foreground drain, with the accounts a finished background
    attack resolved. Reads the block back from the report (not from whatever the
    extraction path held in memory), folds the named accounts in through the
    shared pure merge, and writes the result only when the fold actually changed
    something.

    Args:
        shell: The active session.
        domain: The domain the recovered accounts belong to. Per-domain, because
            an attack is dispatched per target domain and one domain's
            recoveries say nothing about another's passwords.
        recovered_accounts: ``sAMAccountName`` of each resolved account. Names
            only: the fold needs no secret and is never handed one.

    Returns:
        ``True`` when the stored figures were updated. Best-effort: never raises
        into the drain.
    """
    try:
        accounts = [str(name or "").strip() for name in recovered_accounts or ()]
        accounts = [name for name in accounts if name]
        if not domain or not accounts:
            return False

        from adscan_core.reporting.password_hygiene import merge_recovered_into_hygiene
        from adscan_core.reporting.technical_report import (
            read_password_hygiene_details,
        )

        stored = read_password_hygiene_details(shell, domain)
        if not isinstance(stored, dict) or not stored:
            # No extracted population on record, so there is no denominator to
            # fold into. Declared absence, never an invented figure.
            print_info_debug(
                "password-hygiene: no stored block for this domain, so a later "
                f"recovery of {len(accounts)} account(s) has nothing to fold into"
            )
            return False

        tier_for, high_value_for = _tier_resolver(shell, domain, accounts)
        merged = merge_recovered_into_hygiene(
            stored,
            recovered_accounts=accounts,
            tier_for=tier_for,
            high_value_for=high_value_for,
        )
        if merged is None:
            return False
        if not persist_password_hygiene_details(shell, domain, merged):
            return False
        print_info_debug(
            "password-hygiene: folded a later recovery into the stored figures "
            f"({merged.get('recovered_total')} of {merged.get('extracted_total')} "
            "accounts resolved)"
        )
        return True
    except Exception as exc:  # noqa: BLE001 — the drain must never break on this
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False


__all__ = [
    "HYGIENE_CATEGORY",
    "HYGIENE_TITLE",
    "persist_password_hygiene_details",
    "reconcile_password_hygiene_after_recovery",
]
