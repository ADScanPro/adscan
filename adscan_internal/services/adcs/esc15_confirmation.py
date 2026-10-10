"""ESC15 (EKUwu / CVE-2024-49019) collection-time confirmation — pure SSOT.

The passive LDAP detector (``collector/adcs_detectors/esc15.py``) emits an
``ADCSESC15`` candidate from template attributes alone (schema-v1 +
EnrolleeSuppliesSubject + enrollable). But the exploitability existence
condition — whether the issuing CA is patched for CVE-2024-49019 — is INVISIBLE
to passive LDAP, so an unconfirmed ESC15 edge is a CRITICAL false-positive risk
(``Authenticated Users -> domain``).

This module holds the PURE, import-light decision logic for the active
confirmation phase that runs during ADCS collection (the network/credential
driver lives in :mod:`adscan_internal.cli.esc15_confirmation_phase`). It mirrors
the ESC8/ESC11 probe-gating pattern: the edge survives only when confirmation
proves (or cannot rule out) exploitability.

Verdict -> collection action:

* ``confirmed_vulnerable`` -> KEEP the edge, stamp it confirmed (proven, CRITICAL).
* ``hardened`` -> REMOVE the edge entirely (the ESC15 existence condition is
  absent, so there is no exploitable path to hold in the graph), and the driver
  records a positive-control instead.
* everything else (``indeterminate`` / ``attempted`` / unknown / confirmation
  SKIPPED: no enrollment rights, CA unreachable, opt-out) -> KEEP the edge but
  mark it confirmation-pending, so the report is honest ("critical if confirmed;
  CA patch state not actively verified") and never a flat critical.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from typing import Any

#: CVE the confirmation proves present/absent on the issuing CA.
ESC15_CVE_ID = "CVE-2024-49019"

#: Opt-out env (mirrors ``ADSCAN_NO_POISONING``): skip the active confirmation
#: entirely for a client that forbids any certificate issuance. The ESC15 edge
#: then falls to confirmation-pending (never silently dropped, never a flat
#: critical). Offline mode does NOT gate the confirmation — it issues a cert on
#: the CLIENT's own internal CA, reaching no external service — but this opt-out
#: is honored regardless for the paranoid / issuance-forbidden engagement.
ESC15_CONFIRM_DISABLED_ENV = "ADSCAN_NO_ESC15_CONFIRM"

_TRUTHY = {"1", "true", "yes", "on"}

_ESC15_RELATION = "ADCSESC15"


def esc15_confirmation_disabled() -> bool:
    """Return True when the active ESC15 confirmation phase is opted out."""
    return str(os.environ.get(ESC15_CONFIRM_DISABLED_ENV, "")).strip().lower() in _TRUTHY


class Esc15CollectionAction(str, Enum):
    """What the collection phase does to an ESC15 edge given a confirm verdict."""

    #: Confirmation proved the CA honours application-policy injection.
    KEEP_CONFIRMED = "keep_confirmed"
    #: Confirmation proved the CA strips the injected policy (patched).
    REMOVE_HARDENED = "remove_hardened"
    #: Confirmation could not run or could not conclude — keep, mark pending.
    KEEP_PENDING = "keep_pending"


def classify_esc15_collection_action(verdict: str | None) -> Esc15CollectionAction:
    """Map a confirm verdict string to the collection action (pure SSOT).

    Args:
        verdict: ``evidence['verdict']`` from ``confirm_esc15_vulnerable`` —
            ``confirmed_vulnerable`` / ``hardened`` / ``indeterminate`` /
            ``attempted``; an empty/unknown value (confirmation skipped) maps to
            KEEP_PENDING.

    Returns:
        The :class:`Esc15CollectionAction` the phase must apply.
    """
    normalized = str(verdict or "").strip().lower()
    if normalized == "confirmed_vulnerable":
        return Esc15CollectionAction.KEEP_CONFIRMED
    if normalized == "hardened":
        return Esc15CollectionAction.REMOVE_HARDENED
    return Esc15CollectionAction.KEEP_PENDING


def esc15_edge_notes_update(
    action: Esc15CollectionAction,
    *,
    verdict: str | None,
    reason: str | None = None,
    canary_oid: str | None = None,
) -> dict[str, Any]:
    """Build the notes to merge onto a KEPT ESC15 edge for ``action``.

    ``confirmation_pending`` / ``esc15_confirmed`` are the two markers the report
    and web CTEM read to render the finding honestly (proven vs awaiting the
    client-held CA-patch fact). Only valid for the KEEP actions; REMOVE drops the
    edge so it carries no notes.
    """
    update: dict[str, Any] = {
        "cve_id": ESC15_CVE_ID,
        "confirm_verdict": str(verdict or "").strip() or "skipped",
    }
    if action is Esc15CollectionAction.KEEP_CONFIRMED:
        update["esc15_confirmed"] = True
        update["confirmation_pending"] = False
    else:  # KEEP_PENDING
        update["esc15_confirmed"] = False
        update["confirmation_pending"] = True
    cleaned_reason = str(reason or "").strip()
    if cleaned_reason:
        update["confirmation_reason"] = cleaned_reason
    cleaned_canary = str(canary_oid or "").strip()
    if cleaned_canary:
        update["canary_oid"] = cleaned_canary
    return update


@dataclass(frozen=True)
class Esc15TemplateRef:
    """A distinct ESC15 vulnerable template referenced by one or more edges.

    Attributes:
        object_id: The CertTemplate's object id (empty when the edge carried no
            vulnerable-resource template, e.g. a legacy-shaped edge).
        cn: The template enrollment CN (the name the CA requires for enrollment),
            or ``None`` when it could not be derived.
    """

    object_id: str
    cn: str | None


def _iter_esc15_edges(graph: dict[str, Any]):
    """Yield ``(index, edge)`` for every ADCSESC15 edge in a graph dict."""
    edges = graph.get("edges")
    if not isinstance(edges, list):
        return
    for index, edge in enumerate(edges):
        if not isinstance(edge, dict):
            continue
        if str(edge.get("relation") or "").strip() == _ESC15_RELATION:
            yield index, edge


def _edge_template_object_ids(edge: dict[str, Any]) -> list[str]:
    """Return the CertTemplate object ids an ESC15 edge abuses (possibly empty).

    The derived ESC15 edge (``principal -> Domain Admins``) carries the abused
    template(s) under ``notes.vulnerable_resources`` (see
    ``collector/persistence._build_esc_vulnerable_resource_entry``). An edge may
    aggregate more than one vulnerable template.
    """
    notes = edge.get("notes")
    if not isinstance(notes, dict):
        return []
    resources = notes.get("vulnerable_resources")
    if not isinstance(resources, list):
        return []
    object_ids: list[str] = []
    for resource in resources:
        if not isinstance(resource, dict):
            continue
        if str(resource.get("kind") or "").strip() != "CertTemplate":
            continue
        object_id = str(resource.get("object_id") or "").strip()
        if object_id:
            object_ids.append(object_id)
    return object_ids


def _template_cn_for_object_id(graph: dict[str, Any], object_id: str) -> str | None:
    """Find the enrollment CN for ``object_id`` across every ESC15 edge's notes."""
    for _index, edge in _iter_esc15_edges(graph):
        notes = edge.get("notes")
        if not isinstance(notes, dict):
            continue
        for resource in notes.get("vulnerable_resources") or []:
            if not isinstance(resource, dict):
                continue
            if str(resource.get("object_id") or "").strip() != object_id:
                continue
            cn = str(resource.get("name") or "").strip()
            if cn:
                return cn
    return None


def collect_esc15_template_refs(graph: dict[str, Any]) -> list[Esc15TemplateRef]:
    """Return the distinct ESC15 vulnerable templates referenced in the graph.

    A template with no resolvable object id (legacy-shaped edge) is represented
    by a single ``object_id=""`` ref so the driver still confirms it once,
    resolving the template name from domain data.
    """
    seen: dict[str, Esc15TemplateRef] = {}
    has_untyped = False
    for _index, edge in _iter_esc15_edges(graph):
        object_ids = _edge_template_object_ids(edge)
        if not object_ids:
            has_untyped = True
            continue
        for object_id in object_ids:
            if object_id not in seen:
                seen[object_id] = Esc15TemplateRef(
                    object_id=object_id,
                    cn=_template_cn_for_object_id(graph, object_id),
                )
    refs = list(seen.values())
    if has_untyped and "" not in seen:
        refs.append(Esc15TemplateRef(object_id="", cn=None))
    return refs


def _resolve_edge_action(
    edge: dict[str, Any],
    verdicts: dict[str, Esc15CollectionAction],
) -> Esc15CollectionAction:
    """Resolve ONE edge's action from its templates' per-template verdicts.

    An edge is removed only when EVERY template it abuses is hardened; a single
    confirmed template keeps the edge confirmed, and any pending template (short
    of a confirmed one) keeps it pending. Precedence: CONFIRMED > PENDING >
    HARDENED. An edge with no resolved template uses the untyped ("") verdict.
    """
    object_ids = _edge_template_object_ids(edge)
    if not object_ids:
        return verdicts.get("", Esc15CollectionAction.KEEP_PENDING)
    actions = {
        verdicts.get(object_id, Esc15CollectionAction.KEEP_PENDING)
        for object_id in object_ids
    }
    if Esc15CollectionAction.KEEP_CONFIRMED in actions:
        return Esc15CollectionAction.KEEP_CONFIRMED
    if Esc15CollectionAction.KEEP_PENDING in actions:
        return Esc15CollectionAction.KEEP_PENDING
    return Esc15CollectionAction.REMOVE_HARDENED


def apply_esc15_verdicts_to_graph(
    graph: dict[str, Any],
    verdicts: dict[str, Esc15CollectionAction],
    *,
    notes_by_template: dict[str, dict[str, Any]] | None = None,
) -> tuple[int, int]:
    """Apply per-template ESC15 verdicts to the graph edges in place (pure).

    Args:
        graph: The attack-graph dict (``edges`` is a list of edge dicts).
        verdicts: ``{template_object_id: action}`` (``""`` keys the untyped edge).
        notes_by_template: ``{template_object_id: notes_update}`` to merge onto a
            kept edge. The update for a resolved edge is chosen from the template
            whose action won (confirmed first, else pending).

    Returns:
        ``(removed_count, marked_count)``.
    """
    edges = graph.get("edges")
    if not isinstance(edges, list):
        return (0, 0)
    notes_by_template = notes_by_template or {}

    kept: list[Any] = []
    removed = 0
    marked = 0
    for edge in edges:
        if not isinstance(edge, dict) or str(edge.get("relation") or "").strip() != _ESC15_RELATION:
            kept.append(edge)
            continue
        action = _resolve_edge_action(edge, verdicts)
        if action is Esc15CollectionAction.REMOVE_HARDENED:
            removed += 1
            continue
        notes = edge.get("notes")
        if not isinstance(notes, dict):
            notes = {}
            edge["notes"] = notes
        update = _select_notes_update(edge, verdicts, notes_by_template, action)
        if update:
            notes.update(update)
            marked += 1
        kept.append(edge)

    if removed:
        graph["edges"] = kept
    return (removed, marked)


def _select_notes_update(
    edge: dict[str, Any],
    verdicts: dict[str, Esc15CollectionAction],
    notes_by_template: dict[str, dict[str, Any]],
    edge_action: Esc15CollectionAction,
) -> dict[str, Any]:
    """Pick the notes update for a kept edge from its winning template."""
    object_ids = _edge_template_object_ids(edge) or [""]
    # Prefer the template whose action matches the edge's resolved action, so a
    # confirmed edge carries the confirmed template's notes.
    for object_id in object_ids:
        if verdicts.get(object_id) is edge_action and object_id in notes_by_template:
            return notes_by_template[object_id]
    for object_id in object_ids:
        if object_id in notes_by_template:
            return notes_by_template[object_id]
    return {}


__all__ = [
    "ESC15_CVE_ID",
    "ESC15_CONFIRM_DISABLED_ENV",
    "esc15_confirmation_disabled",
    "Esc15CollectionAction",
    "classify_esc15_collection_action",
    "esc15_edge_notes_update",
    "Esc15TemplateRef",
    "collect_esc15_template_refs",
    "apply_esc15_verdicts_to_graph",
]
