"""ESC9 / ESC10 (implicit certificate mapping) collection-time confirmation — pure SSOT.

The passive LDAP detectors (``collector/adcs_detectors/esc9.py`` and ``esc10.py``)
emit an ``ADCSESC9`` / ``ADCSESC10`` candidate from the TEMPLATE shape
(``CT_FLAG_NO_SECURITY_EXTENSION`` + a client-auth EKU + a low-priv enroll right).
But ESC9/10's exploitability existence condition is the DOMAIN's certificate-binding
posture — whether the DCs still honour the WEAK implicit (UPN-from-subject) mapping a
no-SID certificate relies on. Under KB5014754 ``StrongCertificateBindingEnforcement``
(SCBE) that mapping is honoured at SCBE 0/1 and REFUSED at 2 (Full). The passive
detector cannot see SCBE, so an unconfirmed ESC9/10 edge is a CRITICAL
false-positive risk on a hardened domain controller.

This module holds the PURE, import-light decision logic for the active confirmation
phase (the network/credential driver lives in
:mod:`adscan_internal.cli.esc9_confirmation_phase`). It mirrors the ESC15 shape and
reuses the SHARED SCBE observation (:func:`observe_domain_scbe`) — the OBSERVATION
is shared with ESC14, but the PREDICATE here is ESC9-specific: ESC9's existence
condition IS the weak binding, so a Full SCBE closes it entirely.

Verdict (a domain-wide :class:`ScbeVerdict`) -> collection action:

* ``REMOVE_HARDENED`` -> SCBE is OBSERVED HARDENED (registry Full on every DC, or a
  behavioral code-66 PKINIT refusal of a self no-SID certificate): the implicit /
  weak mapping ESC9/10 relies on is refused domain-wide, so the technique is not
  viable. REMOVE the edge and record a positive control. SCBE is ESC9's existence
  condition, so this is NOT ``closed_by_configuration`` (no residual weakness to
  report, not a closed orthogonal avenue).
* ``KEEP_CONFIRMED`` -> SCBE is OBSERVED WEAK (registry SCBE < 2, or a behavioral
  PKINIT success for a self no-SID certificate): the weak-binding existence
  condition is confirmed present. KEEP the edge, stamp it confirmed.
* ``KEEP_PENDING`` -> SCBE is indeterminate (absent / unreachable / opt-out / no
  credential / clock-skew / a non-66 failure): keep the edge, mark it
  confirmation-pending, so the report is honest and never a flat critical.

**Posture guardrail (hard):** REMOVE only on an OBSERVED hardened verdict. An
absence / timeout / unreachable read is UNKNOWN -> PENDING, never REMOVE; and a
``KDC_ERR_CLIENT_NOT_TRUSTED`` (0x3E) from the behavioral probe is CLOCK SKEW, not
hardening, so it never produces a hardened verdict (the canary only maps a code-66
``certificate_binding_refused`` to hardened). This mirrors the posture doctrine
"cache observations, never cache absences".
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from typing import Any

from adscan_internal.services.adcs.esc14_confirmation import (
    ScbeState,
    ScbeVerdict,
)

#: Opt-out env (mirrors ``ADSCAN_NO_ESC14_CONFIRM`` / ``ADSCAN_NO_ESC15_CONFIRM``):
#: skip the active ESC9/10 confirmation entirely. The edges then fall to
#: confirmation-pending (never silently dropped, never a flat critical).
ESC9_CONFIRM_DISABLED_ENV = "ADSCAN_NO_ESC9_CONFIRM"

_TRUTHY = {"1", "true", "yes", "on"}

#: ESC9 and ESC10 share the same implicit-mapping existence condition (SCBE), and
#: ESC10 delegates to the ESC9 flow — so one confirmation gates BOTH relations.
_ESC9_RELATIONS = frozenset({"ADCSESC9", "ADCSESC10"})


def esc9_confirmation_disabled() -> bool:
    """Return True when the active ESC9/10 confirmation phase is opted out."""
    return str(os.environ.get(ESC9_CONFIRM_DISABLED_ENV, "")).strip().lower() in _TRUTHY


class Esc9CollectionAction(str, Enum):
    """What the collection phase does to an ESC9/10 edge given a confirm verdict."""

    #: SCBE observed WEAK — the weak-binding existence condition is confirmed.
    KEEP_CONFIRMED = "keep_confirmed"
    #: SCBE observed HARDENED (Full) — the implicit mapping is refused domain-wide.
    REMOVE_HARDENED = "remove_hardened"
    #: SCBE indeterminate — keep, mark pending (never a flat critical).
    KEEP_PENDING = "keep_pending"


def resolve_edge_action(scbe: ScbeVerdict) -> Esc9CollectionAction:
    """Resolve the ESC9/10 collection action from the SCBE posture (pure SSOT).

    The predicate is domain-wide (unlike ESC14's per-edge write-access condition):
    ESC9/10's existence condition IS the weak certificate binding, so the SCBE
    verdict decides every edge uniformly.

    * HARDENED -> REMOVE_HARDENED (Full enforcement refuses the implicit mapping).
    * WEAK -> KEEP_CONFIRMED (a DC honours the weak binding).
    * UNKNOWN -> KEEP_PENDING (the decisive gate could not be observed).

    The posture guardrail is enforced here by construction: REMOVE requires the
    HARDENED state, which the observation/canary layer produces ONLY from a positive
    hardened observation (registry Full everywhere, or a code-66 refusal) — never
    from an absence, a timeout, or a clock-skew (0x3E) failure.
    """
    if scbe.state is ScbeState.HARDENED:
        return Esc9CollectionAction.REMOVE_HARDENED
    if scbe.state is ScbeState.WEAK:
        return Esc9CollectionAction.KEEP_CONFIRMED
    return Esc9CollectionAction.KEEP_PENDING


def esc9_edge_notes_update(
    action: Esc9CollectionAction, scbe: ScbeVerdict
) -> dict[str, Any]:
    """Build the notes to merge onto a KEPT ESC9/10 edge for ``action``.

    ``esc9_confirmed`` / ``confirmation_pending`` are the markers the report and web
    CTEM read (consistent with the ESC14/ESC15 note shape). ESC9 and ESC10 share the
    implicit-mapping existence condition, so the shared ``esc9_confirmed`` flag
    carries the weak-binding confirmation for both relations. Only valid for the KEEP
    actions; REMOVE drops the edge so it carries no notes.
    """
    update: dict[str, Any] = {
        "confirm_verdict": action.value,
        "confirmation_reason": scbe.reason,
        "confirmation_basis": scbe.basis.value,
    }
    if scbe.scbe is not None:
        update["strong_certificate_binding_enforcement"] = scbe.scbe
    if scbe.cert_mapping_methods is not None:
        update["certificate_mapping_methods"] = scbe.cert_mapping_methods
    if action is Esc9CollectionAction.KEEP_CONFIRMED:
        update["esc9_confirmed"] = True
        update["confirmation_pending"] = False
    else:  # KEEP_PENDING
        update["esc9_confirmed"] = False
        update["confirmation_pending"] = True
    return update


def graph_has_esc9_edges(graph: dict[str, Any]) -> bool:
    """Return whether the graph carries at least one ADCSESC9 / ADCSESC10 edge."""
    edges = graph.get("edges")
    if not isinstance(edges, list):
        return False
    return any(
        isinstance(edge, dict)
        and str(edge.get("relation") or "").strip() in _ESC9_RELATIONS
        for edge in edges
    )


@dataclass(frozen=True)
class Esc9ApplyResult:
    """Counts from applying the ESC9/10 confirmation to a graph."""

    removed: int = 0
    confirmed: int = 0
    pending: int = 0


def apply_esc9_confirmation_to_graph(
    graph: dict[str, Any], scbe: ScbeVerdict
) -> Esc9ApplyResult:
    """Resolve + apply the ESC9/10 edges' action in place (pure given ``scbe``).

    Every ADCSESC9 / ADCSESC10 edge is decided by the single domain-wide SCBE
    verdict. A REMOVE_HARDENED verdict drops the edge; a KEEP action stamps the
    confirmation notes. Returns an :class:`Esc9ApplyResult` with the removed /
    confirmed / pending counts.
    """
    edges = graph.get("edges")
    if not isinstance(edges, list):
        return Esc9ApplyResult()

    action = resolve_edge_action(scbe)
    kept: list[Any] = []
    removed = confirmed = pending = 0
    for edge in edges:
        if (
            not isinstance(edge, dict)
            or str(edge.get("relation") or "").strip() not in _ESC9_RELATIONS
        ):
            kept.append(edge)
            continue
        if action is Esc9CollectionAction.REMOVE_HARDENED:
            removed += 1
            continue
        notes = edge.get("notes")
        if not isinstance(notes, dict):
            notes = {}
            edge["notes"] = notes
        notes.update(esc9_edge_notes_update(action, scbe))
        if action is Esc9CollectionAction.KEEP_CONFIRMED:
            confirmed += 1
        else:
            pending += 1
        kept.append(edge)

    if removed:
        graph["edges"] = kept
    return Esc9ApplyResult(removed=removed, confirmed=confirmed, pending=pending)


__all__ = [
    "ESC9_CONFIRM_DISABLED_ENV",
    "esc9_confirmation_disabled",
    "Esc9CollectionAction",
    "Esc9ApplyResult",
    "resolve_edge_action",
    "esc9_edge_notes_update",
    "graph_has_esc9_edges",
    "apply_esc9_confirmation_to_graph",
]
