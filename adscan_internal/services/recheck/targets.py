"""Resolve a recheck target to ledger items (spec section 10.1 and 10.2).

The ledger (``engagement.sqlite``) is the source: a target names ledger items,
never a fresh computation. Three joins live here and nowhere else:

* item -> detector check id (``adscan_core.engagement.detectors``), kept only when
  the family has a read-only check in this release (``observers.OBSERVERS``);
* step relation -> finding key through the attack-step catalog's ``vuln_key``
  (spec 10.2), so a finding recheck expands to the steps that back it and a step
  found present marks its finding present;
* path id -> its ordered step items (``walk.path_step_item_ids``).
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Optional, Sequence

from adscan_core.engagement.detectors import detector_for
from adscan_core.engagement.identity import finding_id
from adscan_core.engagement.model import STATUS_REMEDIATED, Vantage
from adscan_core.engagement.recheck import (
    LEVEL_ALL,
    LEVEL_PATH,
    LEVEL_STEP,
    RecheckError,
    RecheckTarget,
    TargetItem,
    is_open,
)
from adscan_internal.services.recheck.observers import has_read_only_check

#: Ledger kinds a recheck selects. Structural edges (membership, containment)
#: are collected facts of the graph, not attack steps a client fixes.
RECHECK_KINDS = ("finding", "step")

_VULN_KEYS: Optional[dict[str, str]] = None


def vuln_key_for(relation: str) -> str:
    """The finding key a step relation backs (catalog ``vuln_key``), or ``""``."""
    global _VULN_KEYS  # noqa: PLW0603
    if _VULN_KEYS is None:
        from adscan_internal.services.attack_step_catalog import (  # noqa: PLC0415
            ATTACK_STEP_CATALOG,
        )

        _VULN_KEYS = {
            str(rel).lower(): str(entry.vuln_key)
            for rel, entry in ATTACK_STEP_CATALOG.items()
            if getattr(entry, "vuln_key", None)
        }
    return _VULN_KEYS.get(str(relation or "").lower(), "")


def relations_backing(finding_key: str) -> frozenset[str]:
    """Step relations whose catalog ``vuln_key`` is ``finding_key``."""
    vuln_key_for("")  # warm the map
    assert _VULN_KEYS is not None
    return frozenset(rel for rel, key in _VULN_KEYS.items() if key == finding_key)


def read_check_for(kind: str, key: str) -> Optional[str]:
    """The detector check that re-observes an item read-only, or ``None``."""
    det = detector_for(kind, key)
    if det is None or not has_read_only_check(det.check_id):
        return None
    return det.check_id


def to_target_item(row: dict[str, Any]) -> TargetItem:
    """A ledger row as a :class:`TargetItem` (with its read check and joins)."""
    kind, key = str(row["kind"]), str(row["key"])
    backed = vuln_key_for(key) if kind != "finding" else ""
    return TargetItem(
        item_id=str(row["item_id"]),
        kind=kind,
        key=key,
        domain_id=str(row["domain_id"]),
        object_id=row.get("object_id"),
        label=str(row.get("label") or key),
        status=str(row.get("status") or ""),
        last_vantage=Vantage(int(row.get("last_vantage") or 0)),
        check_id=read_check_for(kind, key),
        finding_keys=(backed,) if backed else (),
        disposition=str(row.get("disposition") or ""),
    )


def _status_ok(row: dict[str, Any], status: str) -> bool:
    if status in ("", "all"):
        return True
    if status == "open":
        return is_open(str(row["status"]), str(row.get("disposition") or ""))
    if status == "remediated":
        return row["status"] == STATUS_REMEDIATED
    if status == "not_reevaluated":
        return row.get("evaluation_state") == "not_reevaluated"
    return False


def _match_prefix(rows: Iterable[dict[str, Any]], token: str, what: str) -> dict[str, Any]:
    token = token.strip().lower()
    hits = [r for r in rows if str(r["item_id"]).startswith(token)]
    if not hits:
        raise RecheckError(f"No {what} with id '{token}' in this engagement.")
    if len(hits) > 1:
        raise RecheckError(f"'{token}' matches {len(hits)} {what}s; give more characters of the id.")
    return hits[0]


def select_targets(
    store: Any,
    target: RecheckTarget,
    *,
    path_steps: Optional[Callable[[str], Sequence[str]]] = None,
) -> list[TargetItem]:
    """Resolve ``target`` to the ledger items a recheck decides.

    Args:
        store: An open :class:`adscan_core.engagement.store.EngagementStore`.
        target: The validated target.
        path_steps: ``path_id -> ordered step item ids`` (path level only).

    Raises:
        RecheckError: the target names nothing in this engagement, or an id
            prefix is ambiguous.
    """
    domain = target.filter_value("domain")
    rows = [
        r
        for r in store.items()
        if r["kind"] in RECHECK_KINDS and (not domain or r["domain_id"] == domain)
    ]
    if target.level == LEVEL_ALL:
        status = target.filter_value("status") or "open"
        return [to_target_item(r) for r in rows if _status_ok(r, status)]

    if target.level == LEVEL_STEP:
        row = _match_prefix((r for r in rows if r["kind"] == "step"), target.step, "attack step")
        return [to_target_item(row)]

    if target.level == LEVEL_PATH:
        if path_steps is None:
            raise RecheckError("Path targets need the attack-path computation.")
        by_id = {r["item_id"]: r for r in rows}
        ordered = list(path_steps(target.path))
        missing = [sid for sid in ordered if sid not in by_id]
        if missing:
            raise RecheckError(
                f"{len(missing)} step(s) of this path are not in the engagement ledger; "
                "run a scan first so the ledger holds them."
            )
        return [to_target_item(by_id[sid]) for sid in ordered]

    # Finding level.
    token = target.finding.strip().lower()
    status = target.filter_value("status") or "all"
    if len(token) == 64 and all(c in "0123456789abcdef" for c in token):
        findings = [r for r in rows if r["kind"] == "finding" and r["item_id"] == token]
        if not findings:
            raise RecheckError(f"No finding with id '{token}' in this engagement.")
        key = str(findings[0]["key"])
    else:
        key = token
        findings = [r for r in rows if r["kind"] == "finding" and r["key"] == key]
    findings = [r for r in findings if _status_ok(r, status)]
    domains = {r["domain_id"] for r in findings} or ({domain} if domain else {r["domain_id"] for r in rows})
    items = [to_target_item(r) for r in findings]
    known = {(i.key, i.domain_id) for i in items}
    for dom in sorted(domains):
        if (key, dom) in known or not dom:
            continue
        # A finding the ledger does not hold yet can still be re-checked: if
        # the read finds it, it is recorded as new.
        items.append(
            TargetItem(
                item_id=finding_id(key, dom), kind="finding", key=key, domain_id=dom,
                object_id=None, label=key, status="", last_vantage=Vantage.UNAUTH,
                check_id=read_check_for("finding", key),
            )
        )
    backing = relations_backing(key)
    objects = set(target.objects)
    for row in rows:
        if row["kind"] != "step" or str(row["key"]).lower() not in backing:
            continue
        if row["domain_id"] not in domains or not _status_ok(row, status):
            continue
        if objects and row.get("object_id") not in objects:
            continue
        items.append(to_target_item(row))
    if not items:
        raise RecheckError(f"Nothing to re-check for finding '{key}' in this engagement.")
    return items


def read_plan(
    targets: Sequence[TargetItem], *, narrowed_objects: Iterable[str] = ()
) -> dict[tuple[str, str], Optional[frozenset[str]]]:
    """Which reads to run: ``(check_id, domain_id) -> objects`` (``None`` = domain-wide).

    A domain-scoped item (a finding row) needs a domain-wide read unless the
    operator narrowed the finding to named objects; otherwise the read covers
    exactly the objects of the targeted steps plus the named objects.
    """
    narrowed = frozenset(narrowed_objects)
    plan: dict[tuple[str, str], Optional[frozenset[str]]] = {}
    for item in targets:
        if not item.check_id:
            continue
        group = (item.check_id, item.domain_id)
        if group in plan and plan[group] is None:
            continue
        if item.object_id is None:
            plan[group] = narrowed if narrowed else None
            continue
        current = plan.get(group) or frozenset()
        plan[group] = frozenset(current | {item.object_id} | narrowed)
    return plan


__all__ = (
    "RECHECK_KINDS",
    "read_check_for",
    "read_plan",
    "relations_backing",
    "select_targets",
    "to_target_item",
    "vuln_key_for",
)

