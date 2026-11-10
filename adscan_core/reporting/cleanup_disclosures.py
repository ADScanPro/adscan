"""Section-level facts about how ADscan undid its changes: ONE module, PDF and CTEM.

The report's cleanup section and the web CTEM cleanup view both read this
module, so the two surfaces can never word the same fact differently (spec
13.4). Every function takes the NORMALIZED change shape both surfaces already
hold (``kind``, ``bucket``, ``revert_status``, ``manual_reason``, ``method``,
``target``, ``performed_as``), never the raw ledger detail, because the web
stores only the normalized row.

**What belongs here and what does not.** Anything that describes ONE change,
why it is still in place and whose action it needs, lives in
``cleanup_outcome`` and is re-exported below, so a fact has one definition and
one import path. This module states only what the per-change outcome cannot,
and each of these is an extra fact rather than a restatement:

* Which changes the client's cleanup account removed: the account is named so
  the client can correlate its own logs; it was used only to undo changes.
* Computer accounts that are disabled but not deleted: each one still counts
  against the machine-account quota of the account that created it, so an
  unattended engagement would otherwise stop validating that avenue after a
  few runs without anyone noticing (the burn forecast).
* The one computer account ADscan keeps by agreement (continuous engagements):
  named in every report with the command to remove it.
* Certificates ADscan revoked on the CA: revoked is not yet rejected; relying
  parties stop accepting them when the CA publishes its next revocation list.

Stdlib only: the web backend bundles ``adscan_core``.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional

# The per-change vocabulary. Defined in ``cleanup_outcome`` (one rule, one
# definition) and re-exported here so the surfaces that already import it from
# this module keep one import path.
from adscan_core.reporting.cleanup_outcome import (
    KEPT_LABEL_DEFAULT,
    KEPT_REASON_AUTO_REVERT_OFF,
    KEPT_REASON_OPERATOR,
    KEPT_REASON_RETAINED,
    MANUAL_REASON_NEUTRALIZED,
    MANUAL_REASON_NEUTRALIZED_LABEL,
    RETAINED_ACCOUNT_METHOD,
    STILL_IN_PLACE_LABEL,
    cleanup_counters,
    kept_reason_label,
    still_in_place_count,
)

__all__ = [
    "MANUAL_REASON_NEUTRALIZED",
    "MANUAL_REASON_NEUTRALIZED_LABEL",
    "RETAINED_ACCOUNT_METHOD",
    "KEPT_REASON_AUTO_REVERT_OFF",
    "KEPT_REASON_OPERATOR",
    "KEPT_REASON_RETAINED",
    "KEPT_LABEL_DEFAULT",
    "kept_reason_label",
    "CLEANUP_ACCOUNT_PERFORMED_AS_PREFIX",
    "CLEANUP_ACCOUNT_SAVED_PERFORMED_AS_PREFIX",
    "neutralized_machine_account_remediation",
    "retained_machine_account_remediation",
    "cleanup_disclosures",
    "STILL_IN_PLACE_LABEL",
    "still_in_place_count",
    "cleanup_counters",
]


#: ``performed_as`` prefix of a revert the client's cleanup account performed
#: (mirrors ``cleanup_taxonomy.REVERT_ROLE_PERFORMED_AS["cleanup"]``).
CLEANUP_ACCOUNT_PERFORMED_AS_PREFIX = "Client cleanup account"
#: The same account taken from the workspace where it was saved in an earlier
#: session (``REVERT_ROLE_PERFORMED_AS["cleanup_saved"]``), not passed with the run.
CLEANUP_ACCOUNT_SAVED_PERFORMED_AS_PREFIX = "Client cleanup account saved in the workspace"


def neutralized_machine_account_remediation(
    *,
    sam_account_name: str,
    creator: Optional[str] = None,
    domain_quota: Optional[int] = None,
) -> str:
    """The per-object instruction for a disabled-but-not-deleted computer account."""
    name = str(sam_account_name or "").strip() or "the computer account"
    quota_clause = ""
    if creator and isinstance(domain_quota, int) and domain_quota > 0:
        quota_clause = (
            f" Until it is deleted it uses one of the {domain_quota} computer accounts "
            f"{creator} may create (ms-DS-MachineAccountQuota)."
        )
    elif creator:
        quota_clause = (
            f" Until it is deleted it uses one of the computer accounts {creator} may "
            "create (ms-DS-MachineAccountQuota)."
        )
    return (
        f"ADscan disabled {name} because the account that created it cannot delete "
        f"it.{quota_clause} Delete it with an account allowed to remove computer "
        f"objects.\n  Remove-ADComputer -Identity '{name}' -Confirm:$false"
    )


def retained_machine_account_remediation(*, sam_account_name: str) -> str:
    """How the client removes the account ADscan keeps by agreement."""
    name = str(sam_account_name or "").strip() or "the computer account"
    return (
        f"ADscan keeps {name} between assessments by agreement, so validation does "
        "not create a new computer account on every run. It is removed when "
        "continuous validation ends. To remove it earlier, run this command.\n"
        f"  Remove-ADComputer -Identity '{name}' -Confirm:$false"
    )


def _text(change: Mapping[str, Any], key: str) -> str:
    return str(change.get(key) or "").strip()


def _cleanup_principal(performed_as: str) -> str:
    if "(" in performed_as and performed_as.endswith(")"):
        return performed_as.rsplit("(", 1)[1][:-1].strip()
    return ""


def cleanup_disclosures(changes: Iterable[Mapping[str, Any]]) -> list[str]:
    """Section-level sentences about how the assessment's changes were undone.

    Args:
        changes: Normalized cleanup rows (any order, any bucket).

    Returns:
        Zero or more sentences, in a stable order. The cleanup account that did
        the reverting, the computer accounts left disabled and the quota they
        hold, the computer account kept by agreement, and the certificates
        revoked. Why each change is still in place is the outcome group's to
        state, beside the rows it describes, so it is not repeated here.
    """
    rows = [c for c in changes if isinstance(c, Mapping)]
    lines: list[str] = []

    by_cleanup = [
        c for c in rows
        if _text(c, "performed_as").startswith(CLEANUP_ACCOUNT_PERFORMED_AS_PREFIX)
    ]
    if by_cleanup:
        principals = sorted(
            {p for p in (_cleanup_principal(_text(c, "performed_as")) for c in by_cleanup) if p}
        )
        who = f" ({', '.join(principals)})" if principals else ""
        count = len(by_cleanup)
        noun = "change was" if count == 1 else "changes were"
        saved = any(
            _text(c, "performed_as").startswith(CLEANUP_ACCOUNT_SAVED_PERFORMED_AS_PREFIX)
            for c in by_cleanup
        )
        provenance = (
            " It was saved with this engagement in an earlier session and reused for "
            "this run."
            if saved
            else ""
        )
        lines.append(
            f"{count} {noun} removed with the cleanup account your team provided{who}."
            f"{provenance} ADscan used that account only to undo its own changes, never "
            "for the assessment."
        )

    neutralized = [c for c in rows if _text(c, "manual_reason") == MANUAL_REASON_NEUTRALIZED]
    if neutralized:
        count = len(neutralized)
        single = count == 1
        subject = (
            "1 computer account created during the assessment is"
            if single
            else f"{count} computer accounts created during the assessment are"
        )
        still = "It still counts" if single else "Each one still counts"
        what = "it with the command below" if single else "them with the commands below"
        lines.append(
            f"{subject} disabled but not deleted. {still} against the machine-account "
            "quota of the account that created it, so after a few more assessments that "
            f"account can no longer create the one the next assessment needs. Delete {what}."
        )

    retained = [
        c for c in rows
        if _text(c, "method") == RETAINED_ACCOUNT_METHOD and _text(c, "bucket") == "kept"
    ]
    if retained:
        names = ", ".join(sorted({_text(c, "target") for c in retained if _text(c, "target")}))
        lines.append(
            f"By agreement, ADscan keeps the computer account {names} in your directory "
            "for continuous validation. It is listed in every report and removed when "
            "continuous validation ends."
        )

    revoked = [
        c for c in rows
        if _text(c, "kind") == "issued_certificate" and _text(c, "bucket") == "reverted"
    ]
    if revoked:
        count = len(revoked)
        noun = "certificate" if count == 1 else "certificates"
        lines.append(
            f"ADscan revoked {count} {noun} on your certification authority. Relying "
            "parties stop accepting a revoked certificate once the CA publishes its next "
            "revocation list. To make the revocation take effect immediately, publish one "
            "now with certutil -CRL on the CA."
        )
    return lines
