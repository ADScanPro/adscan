"""Client-facing wording of the coverage-aware lifecycle (single copy source).

Every surface that shows an item (CLI, PDF, web CTEM) renders these strings, so
the same state cannot be worded two ways. Dependency-light: the web backend
imports it.

Two facts per item, never merged:

* ``Last verified <date>``: the last run whose coverage actually observed the
  item (or proved its absence);
* ``Not re-checked in the latest scan``: the latest run did not re-run the check
  that observes it, so its status was left alone.

Wording rule (Exposure Validation): a non-check is never attributed to a
defensive control. The reasons name what ADscan did or could not do.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from adscan_core.engagement.sources import BASIS_LABELS

NOT_RECHECKED_PREFIX = "Not re-checked in the latest scan"

#: Noun for the item, per kind, used in the notice sentence.
_NOUNS = {"finding": "finding", "step": "step", "path": "route"}

#: Second sentence of the notice, by kind, WITHOUT its trailing period: the
#: default clause (the check did not run) and the ``check_partial`` clause (the
#: check ran on only part of the scope). A partial reason never reads "did not
#: run" (it ran, just not everywhere) — the two together were a contradiction a
#: web badge showed next to "covered only part of the scope" (gate finding R53).
_CLAUSE_DEFAULT = {
    "finding": "The check that observes this finding did not run on this scope",
    "step": "The check that observes this step did not run on this scope",
    "path": "None of the steps of this route could be re-checked",
}
_CLAUSE_PARTIAL = {
    "finding": "The check that observes this finding ran on only part of this scope",
    "step": "The check that observes this step ran on only part of this scope",
    "path": "None of the steps of this route could be re-checked",
}

_NOTICE = {kind: f"{NOT_RECHECKED_PREFIX}. {clause}." for kind, clause in _CLAUSE_DEFAULT.items()}

_REASON_DETAIL = {
    "run_incomplete": "The latest scan did not finish.",
    "coverage_unknown": "ADscan has no record of what the latest scan checked, so nothing was closed from it.",
    "artifact_unreadable": "The latest scan's results could not be read, so nothing was closed from them.",
    "ingestion_incomplete": "The platform could not load all of the latest scan's results, so nothing was closed from them.",
    "graph_not_current": "The latest scan did not finish building its relationship graph, so the previous one is kept and nothing was closed from it.",
    "no_spec": "No re-check is defined for it yet.",
    "never_auto": "Only a deliberate re-check closes it, since its absence from a scan proves nothing.",
    "check_skipped": "That check did not produce a result in the latest scan.",
    "check_partial": "That check covered only part of the scope in the latest scan.",
    "check_failed": "That check failed in the latest scan.",
    "scope_mismatch": "That check did not cover this domain in the latest scan.",
    "vantage": "The latest scan had less access than the scan that last observed it.",
    "step_unverified": "No step of the route could be re-checked in the latest scan.",
    "no_step_evidence": "The route could not be tied to a recorded step.",
}

#: The client words for a register row's lifecycle state (an attack route or a
#: finding: ``active``/``open``, ``reopened``, ``remediated``, ``accepted``). The
#: raw token reached a client screen as "active"; every surface prints these.
LIFECYCLE_STATUS_LABELS: dict[str, str] = {
    "active": "Open",
    "open": "Open",
    "reopened": "Reopened",
    "remediated": "No longer detected",
    "accepted": "Risk accepted",
}


def lifecycle_status_label(status: object) -> str:
    """Client label for a lifecycle state token; ``""`` when unknown."""
    raw = getattr(status, "value", status)
    return LIFECYCLE_STATUS_LABELS.get(str(raw or "").strip().lower(), "")


NOT_VERIFIED_LABEL = "Not verified yet"
VERIFIED_PREFIX = "Last verified"

ALL_COPY_STRINGS: tuple[str, ...] = (
    *_NOTICE.values(),
    *(f"{clause}." for clause in _CLAUSE_PARTIAL.values()),
    *_REASON_DETAIL.values(),
    *BASIS_LABELS.values(),
    NOT_VERIFIED_LABEL,
    VERIFIED_PREFIX,
)


def reason_detail(reason_code: Optional[str]) -> str:
    """Return the client-safe sentence for a reconciliation reason code.

    A code qualified with the read that was not obtained
    (``check_skipped:host_registry_not_read``) reads as its sentence followed by
    that read, worded once in ``adscan_core.engagement.sources``.
    """
    code, _sep, basis = str(reason_code or "").partition(":")
    detail = _REASON_DETAIL.get(code, "")
    label = BASIS_LABELS.get(basis, "") if basis else ""
    if detail and label:
        return f"{detail} {label[0].upper()}{label[1:]}."
    return detail


def _compose_notice(kind: str, reason: Optional[str]) -> str:
    """The full "not re-checked" notice: a lead, one clause, and the read that failed.

    A reason qualified with an unread source (``check_partial:share_permissions_not_read``,
    ``check_skipped:host_registry_not_read``) reads as a single clause naming what
    could not be read, so CLI, PDF and web show one coherent sentence. A partial
    reason uses the "ran on only part of this scope" clause, never "did not run".
    A reason with no basis keeps the existing lead + detail wording.
    """
    code, _sep, basis_token = str(reason or "").partition(":")
    basis = BASIS_LABELS.get(basis_token, "") if basis_token else ""
    if basis:
        clauses = _CLAUSE_PARTIAL if code == "check_partial" else _CLAUSE_DEFAULT
        clause = clauses.get(kind, clauses["finding"])
        return f"{NOT_RECHECKED_PREFIX}. {clause}: {basis}."
    if code == "check_partial":
        clause = _CLAUSE_PARTIAL.get(kind, _CLAUSE_PARTIAL["finding"])
        return f"{NOT_RECHECKED_PREFIX}. {clause}."
    notice = _NOTICE.get(kind, _NOTICE["finding"])
    detail = reason_detail(reason)
    return f"{notice} {detail}" if detail else notice


def _date_label(when: Optional[datetime]) -> str:
    if when is None:
        return ""
    if when.tzinfo is not None:
        when = when.astimezone(timezone.utc)
    return when.strftime("%Y-%m-%d")


def build_lifecycle_view(
    evaluation_state: Optional[str],
    evaluation_reason: Optional[str],
    last_verified_at: Optional[datetime],
    *,
    kind: str = "finding",
    fallback_seen: Optional[datetime] = None,
) -> dict[str, Any]:
    """Build the lifecycle block every surface renders.

    Args:
        evaluation_state: ``not_reevaluated`` or anything else (``NULL`` = evaluated).
        evaluation_reason: Stable reason code of a ``not_reevaluated`` state.
        last_verified_at: When a run last observed the item or proved it absent.
        kind: ``finding``, ``step`` or ``path`` (selects the noun).
        fallback_seen: Date to show when ``last_verified_at`` is unknown (rows
            written before coverage existed): the last time the item was seen.

    Returns:
        ``{not_reevaluated, reason_code, short_label, notice, last_verified_at,
        last_verified_label}``. ``short_label`` (the badge text) and ``notice``
        (the full sentence) are empty unless not re-evaluated.
    """
    when = last_verified_at or fallback_seen
    label = f"{VERIFIED_PREFIX} {_date_label(when)}" if when else NOT_VERIFIED_LABEL
    not_reevaluated = evaluation_state == "not_reevaluated"
    notice = ""
    if not_reevaluated:
        notice = _compose_notice(kind, evaluation_reason)
    return {
        "not_reevaluated": not_reevaluated,
        "reason_code": evaluation_reason if not_reevaluated else None,
        "short_label": NOT_RECHECKED_PREFIX if not_reevaluated else "",
        "notice": notice,
        "last_verified_at": when,
        "last_verified_label": label,
    }
