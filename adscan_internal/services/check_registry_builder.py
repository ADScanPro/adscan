"""Assemble the scan-policy check registry from the catalog declarations.

Engine-side and generation-time only: it may import anything (the CVE catalog,
the safeguard derivations). Its output is written into the committed snapshot
``adscan_core/scan_policy/registry_data.py`` by ``scripts/build_check_registry.py``,
and ``tests/unit/scan_policy/test_registry_snapshot_current.py`` rebuilds it in
memory and fails CI on any difference. Runtime consumers never import this
module; they read the snapshot through ``adscan_core.scan_policy.registry``.

Sources, one declaration each:

* attack-step catalog: ``family``, ``lockout_risk``/``lockout_guard``,
  ``service_interference``, ``environment_change_kinds``, ``detection_event_ids``;
* ``vuln_catalog_meta``: ``FINDING_FAMILY``, ``FINDING_EVIDENCE``;
* ``cve_scanner.catalog``: ``CVE_POLICY_DECLARATIONS``;
* ``scan_phases``: ``SUBPHASE_CHECK_BINDINGS``, ``MODULE_CHECK_DECLARATIONS``.

The ``environment_change`` enum and the rollback line are DERIVED from the
declared change kinds through ``safeguard_profile.rollback_class_for_kind``, the
same derivation the coverage matrix uses, so the two cannot disagree.

Design: docs/superpowers/specs/2026-11-04-scan-policy-checks-by-family-design.md § 4.3, § 5.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from adscan_core.reporting.vuln_catalog_meta import (
    EVIDENCE_MANDATORY_SOURCES,
    FINDING_EVIDENCE,
    FINDING_FAMILY,
    VULN_CATALOG_META,
)
from adscan_core.scan_policy import model as m
from adscan_internal.services import cleanup_taxonomy as _tax
from adscan_internal.services.attack_relation_labels import format_relation_label
from adscan_internal.services.attack_step_catalog import (
    ATTACK_STEP_CATALOG,
    AttackStepCatalogEntry,
    declares_no_native_event_telemetry,
)
from adscan_internal.services.cve_scanner.catalog import (
    CVE_CATALOG,
    CVE_EVENT_DECLARATIONS,
    CVE_POLICY_DECLARATIONS,
)
from adscan_internal.services.destructive_action_policy import (
    HARD_BLOCKED_TARGET_VARIANTS,
    classify_destructive,
)
from adscan_internal.services.safeguard_profile import (
    CLEANUP_ACCOUNT_REVERT_RIGHTS,
    LEDGER_UNSETTLED_WRITES,
    LEDGER_UNTRACKED_WRITES,
    PENDING,
    ROLLBACK_CLASS_CLEANUP_ACCOUNT,
    ROLLBACK_CLASS_NEVER,
    ROLLBACK_CLASS_OPERATOR,
    change_scope_token_for_kind,
    rollback_class_for_kind,
)
from adscan_internal.services.scan_phases import (
    MODULE_CHECK_DECLARATIONS,
    SUBPHASE_CHECK_BINDINGS,
)

#: Execution aliases folded into ONE check (spec § 5.1). Key: the relation that
#: is folded; value: the relation whose check id carries both. A structural test
#: asserts every executable alias pair is listed here, so a new alias forces a
#: decision instead of silently producing two toggles for one technique.
ALIAS_FOLDS: dict[str, str] = {
    "coerceandrelayntlmtoadcs": "adcsesc8",
    "sqlaccess": "sqladmin",
}

#: Whole phases a technique check also gates (the phase is skipped only when
#: every check bound to it is off). The wordlist spray has no subphase of its
#: own; it is the remainder of the spraying phase.
STEP_PHASE_BINDINGS: dict[str, tuple[str, ...]] = {
    "passwordspray": ("password_spraying",),
}

#: Technique inputs that come from an optional collection (all-of). Every id
#: referenced must exist (structural test).
CHECK_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "step:hassession": ("module:domain_collection.samr",),
    "step:sqladmin": ("module:domain_collection.mssql",),
    "step:readshare": ("module:domain_collection.shares",),
    "module:share_credential_hunt": ("module:domain_collection.shares",),
    "module:writeshare_bait": ("module:domain_collection.shares",),
}

#: Rollback lines that cannot be composed from the change kinds alone, because
#: the technique's writes depend on the target. Client-facing.
ROLLBACK_DETAIL_OVERRIDES: dict[str, str] = {
    "step:allextendedrights": (
        "Depends on the target. On a user account it resets the password, which "
        "cannot be restored, and the report names the account. On the domain or a "
        "computer it only reads."
    ),
    # The account and the Domain Admins membership are written only when the
    # session user already administers the domain (the rights ladder in
    # cli/attack_path_execution.py); any other session runs one read-only
    # command and writes neither.
    "step:scheduledtask": (
        "Scheduled task created on an assessed host, removed at the end and re-read "
        "to confirm, or listed for manual cleanup if that fails. File written on an "
        "assessed host, deleted from the host at the end, or listed for manual "
        "cleanup if that fails. Only when the logged-on user already administers the "
        "domain: a domain account created and added to Domain Admins, both removed at "
        "the end and re-read to confirm, or listed for manual cleanup if that fails. "
        "Any other user's session runs one read-only command, and no account or "
        "membership is written."
    ),
    "module:password_rotation_on_required_change": (
        "Sets a new password on an account whose current password the domain "
        "refuses until it is changed. The old password cannot be restored; the "
        "report names the account so its owner can set a new one."
    ),
}

#: Client-facing titles where the relation label alone would be ambiguous: a
#: relation the destructive-action policy splits by target keeps its runnable
#: half under the relation's id and gets a locked sibling per blocked target.
TITLE_OVERRIDES: dict[str, str] = {
    "step:forcechangepassword": "ForceChangePassword on a user account",
}

#: Titles of the locked per-target siblings, keyed by target class.
_TARGET_VARIANT_TITLES: dict[str, str] = {
    "computer": "{label} on a computer account",
    "krbtgt": "{label} on a krbtgt account",
    "managed_service_account": "{label} on a managed service account",
    "directory_sync": "{label} on an Entra ID sync account",
}

_NOT_REVERSIBLE_KINDS = frozenset({"password_changed", _tax.KIND_CA_PRIVATE_KEY_EXFILTRATED})


# ── derivations ──────────────────────────────────────────────────────────────


def derive_environment_change(
    kinds: tuple[str, ...] | None, *, relation: str = "", never_executed: bool = False
) -> str:
    """The ``environment_change`` enum for a set of declared change kinds."""
    if never_executed:
        return m.ENV_NEVER_EXECUTED
    if kinds is None:
        return m.UNDECLARED
    if not kinds:
        return m.ENV_NONE
    if set(kinds) & _NOT_REVERSIBLE_KINDS:
        return m.ENV_NOT_REVERSIBLE
    # A relation whose writes the ledger never settles is described by that,
    # whatever its kinds' classes (same precedence as safeguard_profile).
    if relation in LEDGER_UNSETTLED_WRITES or relation in LEDGER_UNTRACKED_WRITES:
        return m.ENV_MANUAL_CLEANUP
    classes = [rollback_class_for_kind(k) for k in kinds]
    if any(c == PENDING for c in classes):
        return m.UNDECLARED
    if ROLLBACK_CLASS_NEVER in classes:
        return m.ENV_MANUAL_CLEANUP
    if ROLLBACK_CLASS_CLEANUP_ACCOUNT in classes:
        # Undone only with an account allowed to remove it: resolved per run
        # from the client's cleanup account (scan_policy.revert_permission).
        return m.ENV_REVERTED_WHEN_PERMITTED
    if ROLLBACK_CLASS_OPERATOR in classes:
        return m.ENV_REVERTED_AT_EXIT
    return m.ENV_REVERTED_AUTO


def derive_rollback_detail(kinds: tuple[str, ...] | None, *, relation: str = "") -> str:
    """One client-readable line composed from per-class clauses."""
    if not kinds:
        return ""
    unsettled = relation in LEDGER_UNSETTLED_WRITES or relation in LEDGER_UNTRACKED_WRITES
    lines: list[str] = []
    for kind in dict.fromkeys(kinds):
        what = _tax.kind_display(kind)
        if kind in m.KIND_SPECIFIC_ROLLBACK_CLAUSES:
            clause = m.ROLLBACK_CLAUSES[kind]
        elif unsettled:
            clause = m.ROLLBACK_CLAUSES["unsettled"]
        else:
            clause = m.ROLLBACK_CLAUSES.get(rollback_class_for_kind(kind), "")
        if clause:
            lines.append(clause.format(what=what))
    return " ".join(lines)


def derive_revert_requirement(kinds: tuple[str, ...] | None) -> dict[str, Any]:
    """``revert_requires`` / ``revert_rights`` for a set of declared change kinds.

    Recorded on every check that writes a change only a cleanup (or other
    privileged) account can undo, whatever its ``environment_change``, so the
    per-run resolution and the disclosure read it instead of re-deriving it.
    """
    rights = sorted(
        {CLEANUP_ACCOUNT_REVERT_RIGHTS[k] for k in (kinds or ()) if k in CLEANUP_ACCOUNT_REVERT_RIGHTS}
    )
    return {
        "revert_requires": m.REVERT_REQUIRES_CLEANUP_ACCOUNT if rights else "",
        "revert_rights": rights,
    }


def _change_scope(kinds: tuple[str, ...] | None) -> list[str]:
    return list(dict.fromkeys(change_scope_token_for_kind(k) for k in (kinds or ())))


def _events(ids: tuple[str, ...] | None) -> tuple[list[str], str]:
    if ids is None:
        return [], m.UNDECLARED
    if declares_no_native_event_telemetry(ids):
        return [], m.EVENTS_NO_NATIVE
    if not ids:
        return [], m.UNDECLARED
    return [str(i) for i in ids], m.EVENTS_DECLARED


def _entry_events(entry: AttackStepCatalogEntry) -> tuple[list[str], str]:
    """A step's events: its declared ones plus those its declared changes make."""
    from adscan_internal.services.change_kind_events import signal_event_ids  # noqa: PLC0415

    ids = entry.detection_event_ids
    if ids is None or declares_no_native_event_telemetry(ids) or not ids:
        return _events(ids)
    return _events(signal_event_ids(entry))


def _base_record(**values: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "relations": [],
        "finding_keys": [],
        "subphases": [],
        "phases": [],
        "cve_ids": [],
        "jobs": [],
        "requires": [],
        "requires_any": [],
        "related": [],
        "mitre": [],
        "reads_credential_material": False,
        "introduced_in": 1,
        "revert_requires": "",
        "revert_rights": [],
    }
    record.update(values)
    return record


# ── per-source builders ──────────────────────────────────────────────────────

_SUBPHASES_BY_CHECK: dict[str, list[str]] = {}
for (_phase, _sub), _cid in SUBPHASE_CHECK_BINDINGS.items():
    _SUBPHASES_BY_CHECK.setdefault(_cid, []).append(f"{_phase}.{_sub}")


def _executable(entry: AttackStepCatalogEntry) -> bool:
    return entry.support_kind in {"supported", "policy_blocked"}


def _step_records() -> list[dict[str, Any]]:
    folded_into: dict[str, list[str]] = {}
    for alias, target in ALIAS_FOLDS.items():
        folded_into.setdefault(target, []).append(alias)
    records: list[dict[str, Any]] = []
    for relation, entry in sorted(ATTACK_STEP_CATALOG.items()):
        if not _executable(entry) or relation in ALIAS_FOLDS:
            continue
        cid = f"step:{relation}"
        never = entry.support_kind == "policy_blocked"
        kinds = entry.environment_change_kinds
        event_ids, events_state = _entry_events(entry)
        vuln_key = entry.vuln_key if entry.vuln_key in VULN_CATALOG_META else None
        records.append(
            _base_record(
                check_id=cid,
                kind=m.KIND_TECHNIQUE,
                source=m.SOURCE_ATTACK_STEP,
                family=entry.family,
                title=TITLE_OVERRIDES.get(cid) or format_relation_label(relation),
                selectable=not never,
                locked_state=m.LOCKED_NEVER_EXECUTED if never else "",
                environment_change=derive_environment_change(
                    kinds, relation=relation, never_executed=never
                ),
                change_scope=_change_scope(kinds),
                rollback_detail=ROLLBACK_DETAIL_OVERRIDES.get(cid)
                or derive_rollback_detail(kinds, relation=relation),
                lockout_risk=entry.lockout_risk,
                lockout_guard=entry.lockout_guard,
                service_interference=entry.service_interference,
                event_ids=event_ids,
                events_declared=events_state,
                relations=[relation, *sorted(folded_into.get(relation, []))],
                subphases=sorted(_SUBPHASES_BY_CHECK.get(cid, [])),
                phases=list(STEP_PHASE_BINDINGS.get(relation, ())),
                requires=list(CHECK_REQUIREMENTS.get(cid, ())),
                related=[f"finding:{vuln_key}"] if vuln_key else [],
                mitre=[entry.mitre_technique_id] if entry.mitre_technique_id else [],
                reads_credential_material=entry.family == "credential_dumping",
                **({} if never else derive_revert_requirement(kinds)),
            )
        )
    records.extend(_target_variant_records())
    return records


def _target_variant_records() -> list[dict[str, Any]]:
    """Locked siblings for the per-target hard blocks of runnable relations.

    The destructive-action policy refuses some targets of a relation that is
    otherwise executable (a computer account's password reset). Each refused
    pair becomes a ``never_executed`` check named after its target, so the
    policy a client signs lists it with the other techniques ADscan never runs.
    It carries no relation: the runnable half keeps the gate, and the hard block
    keeps refusing this target in every mode.
    """
    records: list[dict[str, Any]] = []
    for (relation, target), _reason in sorted(HARD_BLOCKED_TARGET_VARIANTS.items()):
        entry = ATTACK_STEP_CATALOG.get(relation)
        if entry is None or not _executable(entry):
            continue
        if not classify_destructive(relation, target).hard_blocked:
            continue
        event_ids, events_state = _entry_events(entry)
        label = format_relation_label(relation)
        title = _TARGET_VARIANT_TITLES.get(target, "{label} on a {target}").format(
            label=label, target=target
        )
        records.append(
            _base_record(
                check_id=f"step:{relation}.{target}",
                kind=m.KIND_TECHNIQUE,
                source=m.SOURCE_ATTACK_STEP,
                family=entry.family,
                title=title,
                selectable=False,
                locked_state=m.LOCKED_NEVER_EXECUTED,
                environment_change=m.ENV_NEVER_EXECUTED,
                change_scope=[],
                rollback_detail="",
                lockout_risk=entry.lockout_risk,
                lockout_guard=entry.lockout_guard,
                service_interference=entry.service_interference,
                event_ids=event_ids,
                events_declared=events_state,
                mitre=[entry.mitre_technique_id] if entry.mitre_technique_id else [],
            )
        )
    return records


def _module_traffic_source(decl: Any) -> Any:
    """The declaration whose traffic ``decl`` reports (itself, or its owner).

    A follow-up trigger that re-runs another check's network action names it in
    ``same_action_as``: its events, lockout and interference are the owner's,
    read from the owner's declaration so they cannot drift apart.
    """
    owner_id = str(getattr(decl, "same_action_as", "") or "")
    if not owner_id:
        return decl
    owners = [d for d in MODULE_CHECK_DECLARATIONS if d.check_id == owner_id]
    if len(owners) != 1 or owners[0].same_action_as:
        raise ValueError(
            f"{decl.check_id}: same_action_as {owner_id!r} must name one module "
            "check that owns its action itself"
        )
    return owners[0]


def _module_records() -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for decl in MODULE_CHECK_DECLARATIONS:
        locked = decl.locked_state == m.LOCKED_ALWAYS_RUNS
        source = _module_traffic_source(decl)
        if source.no_native_events:
            event_ids, events_state = [], m.EVENTS_NO_NATIVE
        elif source.events_from_relation:
            event_ids, events_state = _events(
                ATTACK_STEP_CATALOG[source.events_from_relation].detection_event_ids
            )
        else:
            event_ids, events_state = _events(source.event_ids)
        requires = list(CHECK_REQUIREMENTS.get(decl.check_id, ()))
        if decl.same_action_as and decl.same_action_as not in requires:
            requires.append(decl.same_action_as)
        records.append(
            _base_record(
                check_id=decl.check_id,
                kind=m.KIND_TECHNIQUE,
                source=m.SOURCE_MODULE,
                family=decl.family,
                title=decl.title,
                selectable=not locked,
                locked_state=decl.locked_state,
                environment_change=derive_environment_change(decl.environment_change_kinds),
                change_scope=_change_scope(decl.environment_change_kinds),
                rollback_detail=ROLLBACK_DETAIL_OVERRIDES.get(decl.check_id)
                or derive_rollback_detail(decl.environment_change_kinds),
                **derive_revert_requirement(decl.environment_change_kinds),
                lockout_risk=source.lockout_risk,
                lockout_guard=source.lockout_guard,
                service_interference=source.service_interference,
                event_ids=event_ids,
                events_declared=events_state,
                subphases=sorted(_SUBPHASES_BY_CHECK.get(decl.check_id, [])),
                phases=list(decl.phases),
                jobs=list(decl.jobs),
                requires=requires,
                group=decl.group
                or (m.GROUP_COLLECTION if decl.family == "collection" else m.GROUP_ATTACK_STEPS),
            )
        )
    return records


def _probe_records() -> list[dict[str, Any]]:
    findings_by_probe: dict[str, list[str]] = {}
    for key, sources in FINDING_EVIDENCE.items():
        for source in sources:
            if source.startswith("probe:"):
                findings_by_probe.setdefault(source, []).append(f"finding:{key}")
    records: list[dict[str, Any]] = []
    for cve in CVE_CATALOG:
        decl = CVE_POLICY_DECLARATIONS.get(cve.id, {})
        cid = f"probe:{cve.id.lower()}"
        title = cve.aka if cve.id.startswith("ADSCAN-") else f"{cve.aka} ({cve.id})"
        records.append(
            _base_record(
                check_id=cid,
                kind=m.KIND_TECHNIQUE,
                source=m.SOURCE_PROBE,
                family=decl.get("family"),
                title=title,
                selectable=True,
                locked_state="",
                # Read-only by the phase contract: probes register no ledger change.
                environment_change=derive_environment_change(()),
                change_scope=[],
                rollback_detail="",
                lockout_risk=decl.get("lockout_risk", m.UNDECLARED),
                lockout_guard=decl.get("lockout_guard", ""),
                service_interference=decl.get("service_interference", m.UNDECLARED),
                event_ids=list(CVE_EVENT_DECLARATIONS.get(cve.id, ())),
                events_declared=(
                    m.EVENTS_DECLARED if cve.id in CVE_EVENT_DECLARATIONS else m.UNDECLARED
                ),
                phases=["audit_extras"],
                cve_ids=[cve.id],
                related=sorted(findings_by_probe.get(cid, [])),
                mitre=list(cve.mitre_attack),
            )
        )
    return records


def _finding_records(technique_ids: set[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for key, meta in VULN_CATALOG_META.items():
        evidence = tuple(FINDING_EVIDENCE.get(key, ()))
        requires_any = (
            list(evidence)
            if evidence and not any(e in EVIDENCE_MANDATORY_SOURCES for e in evidence)
            else []
        )
        step_relation = None
        for relation, entry in ATTACK_STEP_CATALOG.items():
            if entry.vuln_key == key and _executable(entry):
                step_relation = ALIAS_FOLDS.get(relation, relation)
                break
        related = [f"step:{step_relation}"] if step_relation and f"step:{step_relation}" in technique_ids else []
        records.append(
            _base_record(
                check_id=f"finding:{key}",
                kind=m.KIND_DETECTION,
                source=m.SOURCE_FINDING,
                family=FINDING_FAMILY.get(key),
                title=str(meta.get("title") or key),
                selectable=True,
                locked_state="",
                environment_change=m.ENV_NOT_APPLICABLE,
                change_scope=[],
                rollback_detail="",
                lockout_risk=m.LOCKOUT_NOT_APPLICABLE,
                lockout_guard="",
                service_interference=m.INTERFERENCE_NONE,
                event_ids=[],
                events_declared=m.EVENTS_DETECTION,
                finding_keys=[key],
                requires_any=requires_any,
                related=related,
                mitre=[str(t.get("id")) for t in meta.get("mitre") or [] if t.get("id")],
            )
        )
    return records


# ── groups, execution, pairing, availability (two-groups spec § 2) ───────────


def derive_availability(record: Mapping[str, Any]) -> str:
    """``locked`` / ``opt_in`` / ``default`` for one record.

    A technique is off by default when running it leaves something the client
    has to clean up or cannot undo, can lock accounts, or has a safety axis
    nobody declared yet (fail safe: an undeclared check never runs by default).
    """
    if record.get("locked_state"):
        return m.AVAILABILITY_LOCKED
    if record.get("kind") != m.KIND_TECHNIQUE:
        return m.AVAILABILITY_DEFAULT
    if record.get("environment_change") in {m.ENV_MANUAL_CLEANUP, m.ENV_NOT_REVERSIBLE, m.UNDECLARED}:
        return m.AVAILABILITY_OPT_IN
    if record.get("lockout_risk") in {m.LOCKOUT_POSSIBLE, m.UNDECLARED}:
        return m.AVAILABILITY_OPT_IN
    if record.get("service_interference") == m.UNDECLARED:
        return m.AVAILABILITY_OPT_IN
    return m.AVAILABILITY_DEFAULT


def _derive_execution(record: Mapping[str, Any]) -> str:
    if record.get("kind") == m.KIND_DETECTION:
        return m.EXECUTION_DETECTION
    source = record.get("source")
    if source == m.SOURCE_PROBE:
        return m.EXECUTION_PROBE
    if source == m.SOURCE_MODULE:
        return m.EXECUTION_ACTIVE
    if record.get("subphases") or record.get("phases") or record.get("jobs"):
        return m.EXECUTION_ACTIVE
    return m.EXECUTION_GRAPH


def _pair_detections(techniques: list[dict[str, Any]], detections: list[dict[str, Any]]) -> None:
    """Derive ``owned_by`` / ``owns`` from the ``related`` links the sources declare.

    A technique owns a detection when its declaration names it (an attack step's
    catalog ``vuln_key``, a probe's evidence). Locked techniques never own: a
    detection whose only executable owner is locked belongs to the probe that
    produces it, and one with no owner at all is a plain vulnerability.
    """
    by_id = {d["check_id"]: d for d in detections}
    owners_of: dict[str, list[str]] = {}
    for tech in techniques:
        owns: list[str] = []
        if tech.get("locked_state") != m.LOCKED_NEVER_EXECUTED:
            owns = sorted(rel for rel in tech.get("related") or () if rel in by_id)
        tech["owns"] = owns
        for det_id in owns:
            owners_of.setdefault(det_id, []).append(tech["check_id"])
    tech_group = {t["check_id"]: t.get("group") for t in techniques}
    for det in detections:
        owners = sorted(owners_of.get(det["check_id"], []))
        det["owned_by"] = owners
        groups = {tech_group.get(o) for o in owners}
        det["group"] = (
            m.GROUP_ATTACK_STEPS if m.GROUP_ATTACK_STEPS in groups else m.GROUP_VULNERABILITIES
        )
        if owners:
            # A paired detection follows its owners; it has no switch of its own.
            det["selectable"] = False


def build_check_records() -> list[dict[str, Any]]:
    """Every check record, in registry order (techniques first, then detections)."""
    techniques = _module_records() + _step_records() + _probe_records()
    for record in techniques:
        if not record.get("group"):
            record["group"] = (
                m.GROUP_VULNERABILITIES
                if record["source"] == m.SOURCE_PROBE
                else m.GROUP_ATTACK_STEPS
            )
    detections = _finding_records({r["check_id"] for r in techniques})
    _pair_detections(techniques, detections)
    for record in techniques + detections:
        record["execution"] = _derive_execution(record)
        record["availability"] = derive_availability(record)
        record.setdefault("owned_by", [])
        record.setdefault("owns", [])
    return techniques + detections


def non_check_relations() -> list[str]:
    """Catalog relations that are not checks (never executed, or graph glue)."""
    return sorted(r for r, e in ATTACK_STEP_CATALOG.items() if not _executable(e))


def build_registry_payload(
    *,
    previous_version: int = 0,
    previous_checks: Iterable[Mapping[str, Any]] = (),
    previous_retired: Mapping[str, str | None] | None = None,
) -> dict[str, Any]:
    """Build the full snapshot payload, preserving id history.

    ``REGISTRY_VERSION`` increments only when the id SET changes. An id that
    existed before keeps its ``introduced_in``; a new id gets the new version. An
    id that disappeared is recorded in ``RETIRED`` (as ``None`` unless a rename
    target was already recorded), so a saved policy naming it resolves honestly;
    an id that comes back is removed from ``RETIRED`` and counts as new.
    """
    records = build_check_records()
    prev = {str(c["check_id"]): c for c in previous_checks}
    new_ids = {r["check_id"] for r in records}
    changed = set(prev) != new_ids
    version = (previous_version + 1) if (changed or not previous_version) else previous_version
    for record in records:
        before = prev.get(record["check_id"])
        record["introduced_in"] = int(before["introduced_in"]) if before else version
    retired = dict(previous_retired or {})
    for gone in sorted(set(prev) - new_ids):
        retired.setdefault(gone, None)
    # An id that returns (a technique that had no executor and gained one, such
    # as ScheduledTask) is live again, so it leaves ``RETIRED``: the snapshot
    # never lists one id as both. It re-enters as a NEW check (``introduced_in``
    # is this version, since it is absent from ``prev``), which is what a saved
    # custom policy should be told through ``new_checks``.
    for revived in sorted(set(retired) & new_ids):
        del retired[revived]
    return {
        "version": version,
        "checks": records,
        "retired": dict(sorted(retired.items())),
        "non_check_relations": non_check_relations(),
    }


__all__ = (
    "ALIAS_FOLDS",
    "CHECK_REQUIREMENTS",
    "ROLLBACK_DETAIL_OVERRIDES",
    "STEP_PHASE_BINDINGS",
    "TITLE_OVERRIDES",
    "build_check_records",
    "derive_availability",
    "build_registry_payload",
    "derive_environment_change",
    "derive_revert_requirement",
    "derive_rollback_detail",
    "non_check_relations",
)
