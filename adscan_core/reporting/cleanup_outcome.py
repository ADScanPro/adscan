"""What the client is told about ONE change ADscan made: ONE module, every surface.

This module owns the whole per-change cleanup vocabulary. Whether a change is
still in place, why it is, whose action it needs, how a kept change is labelled,
and how the figure of changes still in place is split. ``cleanup_disclosures``
states the few SECTION-level facts that are not a restatement of a change's
outcome (the account that did the reverting, the machine-account quota, the
account kept by agreement, the certificates revoked) and re-exports the
vocabulary below, so there is one definition and one import path.


A change the assessment made and did not remove can be in place for reasons
that ask very different things of the client:

* **kept by decision**: automatic reversion was off, or the operator chose to
  keep it. Nobody tried to undo it. Neutral.
* **needs rights**: automatic reversion was on, but no account available to the
  assessment had the rights to undo it (no cleanup account was provided and no
  domain administrator account was obtained). A missing input, not a fault, and
  the client can close it by providing a cleanup account.
* **revert failed**: ADscan had what it needed and the revert, or the re-read
  that confirms it, failed. ADscan's responsibility, shown as an error with the
  recorded reason and the accounts it tried.
* **reverted, not confirmed**: the revert ran but no account could read the
  object back.
* **no automatic undo**: no automatic revert exists for the change (a reset
  password whose previous value was never held).

The engine decides the ``manual_reason`` at the moment it gives up on a revert
(``revert_credentials.stamp_revert_rights``, from the candidates it had and the
attempts it recorded); this module only maps that recorded reason onto the
outcome and its client copy. It never infers a reason from error text.

The PRO report, the free report, the CLI exit panel and the web CTEM all read
this module, so the same change can never be described differently on two
surfaces. Stdlib only: the web backend bundles ``adscan_core``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Iterable, Mapping, Optional

__all__ = [
    "OUTCOME_IN_PROGRESS",
    "OUTCOME_REVERTED",
    "OUTCOME_KEPT",
    "OUTCOME_NEEDS_RIGHTS",
    "OUTCOME_FAILED",
    "OUTCOME_UNCONFIRMED",
    "OUTCOME_NO_AUTOMATIC_UNDO",
    "OUTCOME_ORDER",
    "OUTCOME_COPY",
    "REASON_NO_PRIVILEGED_CREDENTIAL",
    "REASON_NO_PRIVILEGED_CREDENTIAL_LABEL",
    "RIGHTS_SENSITIVE_REASONS",
    "REVERT_ROLE_LABELS",
    "ELEVATED_REVERT_ROLES",
    "OutcomeCopy",
    "cleanup_outcome",
    "outcome_copy",
    "revert_attempt_rows",
    "client_revert_error",
    "group_by_outcome",
    "outcome_tally",
    "outcome_is_still_in_place",
    "MANUAL_REASON_NEUTRALIZED",
    "MANUAL_REASON_NEUTRALIZED_LABEL",
    "RETAINED_ACCOUNT_METHOD",
    "KEPT_REASON_AUTO_REVERT_OFF",
    "KEPT_REASON_OPERATOR",
    "KEPT_REASON_RETAINED",
    "KEPT_LABEL_DEFAULT",
    "kept_reason_label",
    "STILL_IN_PLACE_LABEL",
    "still_in_place_count",
    "cleanup_counters",
]

# ── Reasons and labels a ledger record carries ────────────────────────────────
#: ``manual_reason`` for a computer account ADscan created and could only
#: DISABLE: it is unusable, but it still exists and still holds a quota slot.
MANUAL_REASON_NEUTRALIZED = "neutralized_not_deleted"
MANUAL_REASON_NEUTRALIZED_LABEL = (
    "Disabled, not deleted. It still counts against the computer-account quota"
)

#: The ledger ``method`` of the one computer account kept under ``retain_one``.
RETAINED_ACCOUNT_METHOD = "Computer account kept by agreement for continuous validation"

#: Why a change was left in place on purpose (the ledger ``kept_reason``). A
#: kept change is not a failure: nobody tried to undo it. It is still something
#: the client has to remove or accept, so every surface lists it with the
#: command that removes it and counts it among the changes left in place.
KEPT_REASON_AUTO_REVERT_OFF = "auto_revert_off"
KEPT_REASON_OPERATOR = "operator_choice"
KEPT_REASON_RETAINED = "retained_by_agreement"

#: Label of a kept change whose reason was not recorded (older workspaces).
KEPT_LABEL_DEFAULT = "Left in place on purpose"

_KEPT_REASON_LABELS: dict[str, str] = {
    KEPT_REASON_AUTO_REVERT_OFF: (
        "Left in place because automatic reversion was off for this assessment"
    ),
    KEPT_REASON_OPERATOR: "Left in place at the operator's request",
    KEPT_REASON_RETAINED: RETAINED_ACCOUNT_METHOD,
}


def kept_reason_label(reason: Optional[str], method: Optional[str] = None) -> str:
    """Client-facing label for a change left in place on purpose.

    The per-row reason WITHIN the ``kept_by_decision`` outcome, so it is finer
    than that outcome's chip and must never contradict it.

    Args:
        reason: The ledger ``kept_reason`` (one of ``KEPT_REASON_*``), if recorded.
        method: The ledger ``method``; the computer account kept by agreement is
            recognised by it on records written before ``kept_reason`` existed.

    Returns:
        A label that reads as a deliberate state, never as a failed revert.
    """
    key = str(reason or "").strip().lower()
    if key in _KEPT_REASON_LABELS:
        return _KEPT_REASON_LABELS[key]
    if str(method or "") == RETAINED_ACCOUNT_METHOD:
        return RETAINED_ACCOUNT_METHOD
    return KEPT_LABEL_DEFAULT


# ── Outcome keys ──────────────────────────────────────────────────────────────
OUTCOME_IN_PROGRESS = "in_progress"
OUTCOME_REVERTED = "reverted"
OUTCOME_KEPT = "kept_by_decision"
OUTCOME_NEEDS_RIGHTS = "needs_rights"
OUTCOME_FAILED = "revert_failed"
OUTCOME_UNCONFIRMED = "revert_unconfirmed"
OUTCOME_NO_AUTOMATIC_UNDO = "no_automatic_undo"

#: Display order: what the client must act on first, the good side last.
OUTCOME_ORDER: tuple[str, ...] = (
    OUTCOME_IN_PROGRESS,
    OUTCOME_FAILED,
    OUTCOME_NEEDS_RIGHTS,
    OUTCOME_UNCONFIRMED,
    OUTCOME_NO_AUTOMATIC_UNDO,
    OUTCOME_KEPT,
    OUTCOME_REVERTED,
)

# ── The reason the engine records when no account had the rights ──────────────
#: Automatic reversion was on and the revert ran out of candidates, and none of
#: them was the client cleanup account or a verified privileged account. Set by
#: ``revert_credentials.stamp_revert_rights`` at the moment the revert ends.
REASON_NO_PRIVILEGED_CREDENTIAL = "no_privileged_credential"
REASON_NO_PRIVILEGED_CREDENTIAL_LABEL = (
    "No account available to the assessment had the rights to undo it"
)

#: Reasons a revert ends with when it ran out of credentials or was refused.
#: Which outcome they mean depends on whether an account with the rights was
#: available, so the engine re-stamps them (``no_privileged_credential`` when no
#: elevated account existed) at the moment it gives up.
RIGHTS_SENSITIVE_REASONS: frozenset[str] = frozenset(
    {"revert_failed", "access_denied", "missing_credential", REASON_NO_PRIVILEGED_CREDENTIAL}
)

#: Revert roles that carry the rights to undo a change: the client cleanup
#: account (passed with the run or saved in the workspace) and the
#: highest-privilege account the run verified (Domain Admins, Enterprise Admins,
#: the RID-500 Administrator).
ELEVATED_REVERT_ROLES: frozenset[str] = frozenset({"cleanup", "cleanup_saved", "privileged"})

#: What each revert role is called on a client surface ("Performed as", the
#: accounts a failed revert tried). ``cleanup_taxonomy.REVERT_ROLE_PERFORMED_AS``
#: is this map.
REVERT_ROLE_LABELS: dict[str, str] = {
    "cleanup": "Client cleanup account",
    # The same account, saved in the workspace by an earlier session. Starts
    # with the "cleanup" label: cleanup_disclosures matches that prefix.
    "cleanup_saved": "Client cleanup account saved in the workspace",
    "privileged": "Verified privileged account",
    "creator": "Account that made the change",
    "session": "Assessment account",
    "target_ticket": "Account compromised in the step",
    # A change the operator cleaned up by hand and attested; never a re-read.
    "operator": "Operator, after manual cleanup",
}

_ATTEMPT_OUTCOME_LABELS: dict[str, str] = {
    "reverted": "reverted",
    "failed": "failed",
    "unconfirmed": "ran, not confirmed",
}

_REASON_OUTCOME: dict[str, str] = {
    REASON_NO_PRIVILEGED_CREDENTIAL: OUTCOME_NEEDS_RIGHTS,
    "missing_credential": OUTCOME_NEEDS_RIGHTS,
    # A computer account the creator could only disable: the copy already asks
    # for a cleanup account so ADscan can delete it.
    MANUAL_REASON_NEUTRALIZED: OUTCOME_NEEDS_RIGHTS,
    "revert_failed": OUTCOME_FAILED,
    "access_denied": OUTCOME_FAILED,
    "session_died": OUTCOME_FAILED,
    "missing_metadata": OUTCOME_FAILED,
    "revert_unconfirmed": OUTCOME_UNCONFIRMED,
    "operator_declined": OUTCOME_KEPT,
    "not_attempted": OUTCOME_NO_AUTOMATIC_UNDO,
    "original_secret_unknown": OUTCOME_NO_AUTOMATIC_UNDO,
    "password_restored_from_hash": OUTCOME_NO_AUTOMATIC_UNDO,
}


@dataclass(frozen=True)
class OutcomeCopy:
    """The client copy of one outcome.

    Attributes:
        key: One of the ``OUTCOME_*`` keys.
        title: Section heading.
        chip: Short label on a single change.
        tally: The phrase this outcome contributes to the split under the
            "still in place" figure ("3 left in place on purpose, 1 revert
            failed"). Each outcome has its own, so the figure is never a single
            phrase covering cases that need different actions.
        explanation: What happened and whose action it needs, as prose.
        next_step: What the client does next, or "".
        tone: Presentation tone (``good``, ``pending``, ``neutral``, ``access``,
            ``error``, ``check``, ``action``). Every surface maps it to its own
            palette; the four outcomes a client must tell apart never share one.
        responsibility: ``adscan`` when the outcome is ADscan's to own,
            ``client`` when it needs an input or action from the client, ``""``
            otherwise.
        cta_label: The call to action that leads to the cleanup-account setting,
            or "" when the outcome has none.
        cta_where: Where that setting lives, for a surface that cannot link to
            it (the reports, the CLI), or "".
    """

    key: str
    title: str
    chip: str
    tally: str
    explanation: str
    next_step: str
    tone: str
    responsibility: str = ""
    cta_label: str = ""
    cta_where: str = ""

    def as_dict(self) -> dict[str, str]:
        """The copy as a plain dict (what a template or the API serves)."""
        return asdict(self)


OUTCOME_COPY: dict[str, OutcomeCopy] = {
    OUTCOME_IN_PROGRESS: OutcomeCopy(
        key=OUTCOME_IN_PROGRESS,
        title="Pending rollback",
        chip="Pending",
        tally="still being reverted",
        explanation=(
            "ADscan is tracking these changes and reverts them at the end of the scan."
        ),
        next_step="",
        tone="pending",
    ),
    OUTCOME_FAILED: OutcomeCopy(
        key=OUTCOME_FAILED,
        title="Revert failed",
        chip="Revert failed",
        tally="revert failed",
        explanation=(
            "ADscan could not complete the revert of these changes, and the cause is on "
            "ADscan's side. Each change shows the reason recorded and the accounts ADscan "
            "tried."
        ),
        next_step=(
            "Remove each change with the command shown, and send the recorded reason to "
            "ADscan support so it can be fixed."
        ),
        tone="error",
        responsibility="adscan",
    ),
    OUTCOME_NEEDS_RIGHTS: OutcomeCopy(
        key=OUTCOME_NEEDS_RIGHTS,
        title="Needs an account with the rights to undo it",
        chip="Needs a cleanup account",
        tally="waiting for an account with the rights",
        explanation=(
            "Automatic reversion was on, but the assessment had no account with the rights "
            "to undo these changes. No cleanup account was provided for this domain and no "
            "domain administrator account was obtained, so at most ADscan could try the "
            "account that made the change. What was missing is an account, and providing "
            "one closes it."
        ),
        next_step=(
            "Provide a cleanup account with domain administrator rights when you launch "
            "the next assessment, and ADscan reverts changes like these itself. Until "
            "then, run the command shown for each one."
        ),
        tone="access",
        responsibility="client",
        cta_label="Set a cleanup account",
        cta_where=(
            "In the platform, the cleanup account is set in the new-scan form. In the "
            "command-line tool, start asks for it, and cleanup_credential set saves it for "
            "the workspace."
        ),
    ),
    OUTCOME_UNCONFIRMED: OutcomeCopy(
        key=OUTCOME_UNCONFIRMED,
        title="Reverted, not confirmed",
        chip="Not confirmed",
        tally="not confirmed as reverted",
        explanation=(
            "The revert ran and the directory accepted it, but no account could read the "
            "object back to confirm the change is gone."
        ),
        next_step=(
            "Check each object. If the change is still there, the command shown removes it."
        ),
        tone="check",
        responsibility="client",
    ),
    OUTCOME_NO_AUTOMATIC_UNDO: OutcomeCopy(
        key=OUTCOME_NO_AUTOMATIC_UNDO,
        title="No automatic undo",
        chip="No automatic undo",
        tally="with no automatic undo",
        explanation=(
            "These changes have no automatic revert, for example a password reset whose "
            "previous value the assessment never held."
        ),
        next_step="Your team completes each one with the step shown.",
        tone="action",
        responsibility="client",
    ),
    OUTCOME_KEPT: OutcomeCopy(
        key=OUTCOME_KEPT,
        title="Left in place on purpose",
        chip="Kept by decision",
        tally="left in place on purpose",
        explanation=(
            "Nobody tried to undo these changes. Automatic reversion was off for this "
            "assessment, or the operator chose to keep them, so they are still in the "
            "directory."
        ),
        next_step=(
            "Remove each one with its command, or record that your team accepts it."
        ),
        tone="neutral",
    ),
    OUTCOME_REVERTED: OutcomeCopy(
        key=OUTCOME_REVERTED,
        title="Reverted and confirmed",
        chip="Reverted",
        tally="reverted and confirmed",
        explanation=(
            "ADscan undid these changes and read each object back to confirm the change "
            "is gone."
        ),
        next_step="",
        tone="good",
    ),
}


def _text(change: Mapping[str, Any], key: str) -> str:
    return str(change.get(key) or "").strip().lower()


def cleanup_outcome(change: Mapping[str, Any]) -> str:
    """The outcome of one normalized change (``bucket`` plus ``manual_reason``).

    A row that already carries a known ``outcome`` is taken at its word, so a
    surface holding the normalized record does not re-derive what the ledger
    stamped. Anything else is derived here. A manual change whose reason is
    missing or unknown reads as a failed revert: the safe direction, since it
    never turns ADscan's failure into a request for the client's input.
    """
    stamped = _text(change, "outcome")
    if stamped in OUTCOME_COPY:
        return stamped
    bucket = _text(change, "bucket")
    if bucket == "reverted":
        return OUTCOME_REVERTED
    if bucket == "kept":
        return OUTCOME_KEPT
    if bucket == "manual":
        return _REASON_OUTCOME.get(_text(change, "manual_reason"), OUTCOME_FAILED)
    return OUTCOME_IN_PROGRESS


def outcome_is_still_in_place(key: str) -> bool:
    """Whether a change with this outcome is still in the client's directory.

    The ONE predicate behind both halves of the rule: a change still in place
    is counted in the still-in-place figure AND carries the instruction that
    removes it. Everything except a confirmed revert qualifies, a revert still
    running included, so a session that dies mid-revert leaves a record with
    its command rather than an empty cell.
    """
    return str(key or "") != OUTCOME_REVERTED


def outcome_copy(key: str) -> OutcomeCopy:
    """The copy of one outcome (in-progress for an unknown key)."""
    return OUTCOME_COPY.get(str(key or ""), OUTCOME_COPY[OUTCOME_IN_PROGRESS])


def revert_attempt_rows(attempts: Optional[Iterable[Any]]) -> list[dict[str, str]]:
    """The accounts a revert tried, in client words, in the order they were tried.

    Args:
        attempts: The ledger's ``revert_credential_attempts`` (``principal``,
            ``role``, ``outcome``); anything else is skipped.

    Returns:
        ``{"account", "role", "role_label", "outcome", "outcome_label"}`` rows. No
        secret is ever recorded on an attempt, so none can appear here.
    """
    rows: list[dict[str, str]] = []
    for attempt in attempts or ():
        if not isinstance(attempt, Mapping):
            continue
        role = str(attempt.get("role") or "").strip()
        outcome = str(attempt.get("outcome") or "").strip().lower()
        rows.append(
            {
                "account": str(attempt.get("principal") or "").strip(),
                "role": role,
                "role_label": REVERT_ROLE_LABELS.get(role, "Assessment account"),
                "outcome": outcome,
                "outcome_label": _ATTEMPT_OUTCOME_LABELS.get(outcome, outcome or "failed"),
            }
        )
    return rows


#: Names of the libraries the engine is built on. A revert error can carry one
#: from an exception message; the client reads the reason, not the stack.
_INTERNAL_NAMES_RE = None


def client_revert_error(error: Any, *, limit: int = 300) -> str:
    """The recorded reason a revert failed, fit to show a client.

    The reason is the engine's own sentence ("Revert as Verified privileged
    account was not confirmed: the directory refused the change") or an
    exception message. Library names are replaced with what they are, and an
    overlong message is cut at a word boundary.
    """
    import re  # noqa: PLC0415

    global _INTERNAL_NAMES_RE  # noqa: PLW0603
    if _INTERNAL_NAMES_RE is None:
        _INTERNAL_NAMES_RE = re.compile(
            r"\b(?:kerbad|aiosmb|badldap|badauth|winacl|asysocks|aardwolf|pypykatz|impacket"
            r"|minikerberos|msldap|asyauth)\b(?:\.[\w.]+)?",
            re.IGNORECASE,
        )
    text = " ".join(str(error or "").split())
    if not text:
        return ""
    text = _INTERNAL_NAMES_RE.sub("the directory client", text)
    if len(text) > limit:
        text = text[:limit].rsplit(" ", 1)[0].rstrip(" ,;:") + "..."
    return text


def group_by_outcome(changes: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Normalized changes grouped by outcome, in :data:`OUTCOME_ORDER`.

    Returns:
        One ``{**OutcomeCopy.as_dict(), "changes": [...]}`` per outcome that has
        at least one change. Changes keep their input order.
    """
    groups: dict[str, list[Mapping[str, Any]]] = {}
    for change in changes:
        if not isinstance(change, Mapping):
            continue
        groups.setdefault(cleanup_outcome(change), []).append(change)
    return [
        {**OUTCOME_COPY[key].as_dict(), "changes": groups[key]}
        for key in OUTCOME_ORDER
        if groups.get(key)
    ]


# ── The figure of changes still in place, and its split ───────────────────────
#: Headline of the figure every surface shows for what the client still has to
#: deal with. A change left in place on purpose is not a failure, but it is in
#: the directory all the same, so it is never left out of this figure.
STILL_IN_PLACE_LABEL = "Still in place"


def still_in_place_count(*, manual_required: int, kept: int, in_progress: int) -> int:
    """Every recorded change not confirmed as reverted.

    The ONE definition of the ledger's ``pending_manual`` figure: a revert that
    failed or was never confirmed, a change left in place on purpose, and a
    change whose revert has not settled yet are all still in the directory.
    """
    return int(manual_required) + int(kept) + int(in_progress)


def outcome_tally(changes: Iterable[Mapping[str, Any]]) -> list[tuple[str, int]]:
    """``(outcome key, count)`` for the changes still in place, in display order.

    The reverted outcome is excluded: those are gone from the directory.
    """
    counts: dict[str, int] = {}
    for change in changes:
        if not isinstance(change, Mapping):
            continue
        key = cleanup_outcome(change)
        if key == OUTCOME_REVERTED:
            continue
        counts[key] = counts.get(key, 0) + 1
    return [(key, counts[key]) for key in OUTCOME_ORDER if counts.get(key)]


def _count(summary: Mapping[str, Any], *keys: str) -> int:
    for key in keys:
        value = summary.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            return max(value, 0)
    return 0


def cleanup_counters(
    summary: Mapping[str, Any] | None,
    changes: Optional[Iterable[Mapping[str, Any]]] = None,
) -> dict[str, Any]:
    """The cleanup figures and their split, worded once for every surface.

    The split names each outcome separately, because the four reasons a change
    is still in place ask different things of the client: one is a decision,
    one needs an account the assessment did not have, one is a revert that
    failed, and one ran without being confirmed. Wording them as a single
    phrase told a client that changes nobody had tried to revert were "not
    confirmed as reverted", which reads as an attempt that fell short.

    Args:
        summary: A cleanup summary (``reverted_confirmed``, ``manual_required``,
            ``kept``, ``in_progress``; legacy keys accepted).
        changes: The normalized rows, when the caller holds them. The split is
            worded per outcome from these; a caller with only a summary gets a
            split that states no outcome it cannot know.

    Returns:
        ``reverted``, ``still_in_place``, ``kept``, ``not_confirmed``, ``label``
        and ``split``. ``split`` is empty when nothing is still in place.
    """
    summary = summary if isinstance(summary, Mapping) else {}
    reverted = _count(summary, "reverted_confirmed", "reverted")
    manual = _count(summary, "manual_required", "failed")
    kept = _count(summary, "kept")
    in_progress = _count(summary, "in_progress", "pending")
    still = still_in_place_count(manual_required=manual, kept=kept, in_progress=in_progress)
    not_confirmed = manual + in_progress
    split = ""
    if still:
        tally = outcome_tally(changes or ())
        # Only when the rows account for the whole figure: a split that does not
        # add up to the number beside it is worse than a general phrase.
        if tally and sum(count for _, count in tally) == still:
            split = ", ".join(
                f"{count} {OUTCOME_COPY[key].tally}" for key, count in tally
            )
        else:
            # Only the counts a summary alone can justify, and never a zero.
            parts = []
            if kept:
                parts.append(f"{kept} left in place on purpose")
            if not_confirmed:
                parts.append(f"{not_confirmed} still to resolve")
            split = ", ".join(parts)
    return {
        "reverted": reverted,
        "still_in_place": still,
        "kept": kept,
        "not_confirmed": not_confirmed,
        "label": STILL_IN_PLACE_LABEL,
        "split": split,
    }
