"""Scan-policy coverage: what the run's policy excluded, stated once for every surface.

A check the policy switched off did not run. Under the Exposure-Validation
doctrine that is a boundary of the assessment, in the same family as the
cracking and vantage coverage gaps: the deliverable says what was left out and
why, and the area reads as not assessed, never as clean.

This module is the SSOT for both halves (the ``cracking_coverage`` pattern):

* :func:`build_scan_policy_coverage` turns the resolved policy (plus what the
  engine actually refused during the run) into the block persisted by
  :func:`adscan_core.reporting.technical_report.record_scan_policy_coverage`
  under ``domains[<domain>]["scan_policy_coverage"]``; and
* :func:`scan_policy_coverage_view` turns that persisted block into the render
  shape the PRO report, the LITE report and the web CTEM all read, so no two
  surfaces word the same boundary differently.

A default run (no policy) still writes a block: ``complete: true`` under the
built-in Full validation. That is a positive, observed statement about the run,
not an absence.

Stdlib only (plus ``adscan_core.scan_policy``): importable from the engine, the
LITE runtime, the PRO renderer and the web backend.

Design: docs/superpowers/specs/2026-11-04-scan-policy-checks-by-family-design.md § 8.1.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from adscan_core.scan_policy.execution import (
    DECISION_ATTENDED,
    DECISION_MAP_ONLY,
    DECISION_UNATTENDED,
    MAP_ONLY_STATEMENT,
    MAP_ONLY_STEP_LABEL,
)
from adscan_core.scan_policy.families import FAMILIES, FAMILIES_BY_ID
from adscan_core.scan_policy.model import (
    EXECUTION_ACTIVE,
    EXECUTION_GRAPH,
    GROUP_ATTACK_STEPS,
    GROUP_COLLECTION,
    GROUP_LABELS,
    GROUP_VULNERABILITIES,
    GROUPS,
    KIND_DETECTION,
    KIND_TECHNIQUE,
    LOCKED_NEVER_EXECUTED,
    CheckDefinition,
)
from adscan_core.scan_policy.policy import (
    BASE_FULL_VALIDATION,
    BUILTIN_LABELS,
    EXECUTION_MODE_LABELS,
    builtin_definition,
    effective_password_attempts,
    password_attempts_line,
    policy_display_name,
)
from adscan_core.scan_policy.new_checks import (
    new_checks_since_saved,
    unreviewed_checks_ran_line,
)
from adscan_core.scan_policy.registry import CheckRegistry, load_registry
from adscan_core.scan_policy.settings import changed_settings, changed_settings_line
from adscan_core.scan_policy.resolve import (
    REASON_EXCLUDED_BY_POLICY,
    REASON_NEEDS_CLEANUP_ACCOUNT,
    ResolvedScanPolicy,
    resolve_policy,
)
from adscan_core.scan_policy.summary import (
    build_policy_safety_summary,
    policy_sends_password_attempts,
)

#: Per-domain key in ``technical_report.json`` and in the renderer's ``report_data``.
SCAN_POLICY_COVERAGE_KEY = "scan_policy_coverage"
SCHEMA_VERSION = 2

#: What a check the policy kept off means for the assessment, by how the check
#: produces its result (two-groups spec § 6). Client-facing labels.
OUTCOME_MAPPED_NOT_EXECUTED = "mapped_not_executed"
OUTCOME_NOT_ASSESSED = "not_assessed"
OUTCOME_NOT_CHECKED = "not_checked"
OUTCOME_NOT_COLLECTED = "not_collected"
OUTCOME_LABELS: dict[str, str] = {
    OUTCOME_MAPPED_NOT_EXECUTED: "Not executed: your scan policy excludes it.",
    OUTCOME_NOT_ASSESSED: "Not assessed, excluded by the policy",
    OUTCOME_NOT_CHECKED: "Not checked, excluded by the policy",
    OUTCOME_NOT_COLLECTED: "Not collected, excluded by the policy",
}

#: ``excluded[].reason`` for a check switched off because something it needs is off.
REASON_DEPENDENCY_EXCLUDED = "dependency_excluded"

#: Report label of a check left out because no cleanup account was supplied.
NEEDS_CLEANUP_ACCOUNT_LABEL = (
    "Not run: undoing its change needs a cleanup account, and none was supplied"
)

#: The ``not_assessed_reason`` a compliance control carries when its evidence
#: depends on a check the policy excluded.
NOT_ASSESSED_REASON = "excluded_by_scan_policy"

#: Positive controls that only one CVE probe can produce (see
#: ``positive_control_evidence._CVE_NOT_VULNERABLE_POSITIVES``; a unit test locks
#: the two tables together). When that probe is excluded the control cannot
#: turn green, and the compliance card says why.
POSITIVE_CONTROL_CVE_PRODUCERS: dict[str, str] = {
    "zerologon_not_vulnerable": "CVE-2020-1472",
    "nopac_not_vulnerable": "CVE-2021-42278",
    "ms17_010_not_present": "CVE-2017-0144",
}

#: Where the policy of a run came from, in client words.
SOURCE_LABELS: dict[str, str] = {
    "scan_config": "set in the scan configuration",
    "repl": "set by the operator for this workspace",
    "workspace": "saved with this workspace",
    "unreadable": "applied because the saved policy file could not be read",
}

#: How this run treated attack steps, in client words. The map-only sentence is
#: also part of the statement, because it changes what every route means.
EXECUTION_LINES: dict[str, str] = {
    DECISION_UNATTENDED: (
        "The policy ran unattended, so ADscan executed the enabled attack steps it "
        "reached without asking."
    ),
    DECISION_ATTENDED: "An operator decided each attack step during the scan.",
    DECISION_MAP_ONLY: MAP_ONLY_STATEMENT,
}

#: Refusal surfaces, in client words, for the "reached and not run" line.
_MAX_ROWS = 40


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    return f"{count} {singular if count == 1 else (plural or singular + 's')}"


def _family_label(family_id: str) -> str:
    family = FAMILIES_BY_ID.get(family_id)
    return family.label if family is not None else family_id


def _family_order(family_id: str) -> int:
    family = FAMILIES_BY_ID.get(family_id)
    return family.order if family is not None else 99


def _runnable(registry: CheckRegistry) -> list:
    return [c for c in registry.checks if c.locked_state != LOCKED_NEVER_EXECUTED]


def outcome_for(check: CheckDefinition) -> str:
    """What switching ``check`` off means for the assessment."""
    if check.group == GROUP_COLLECTION:
        return OUTCOME_NOT_COLLECTED
    if check.group == GROUP_ATTACK_STEPS and check.kind == KIND_TECHNIQUE:
        if check.execution == EXECUTION_GRAPH:
            return OUTCOME_MAPPED_NOT_EXECUTED
        if check.execution == EXECUTION_ACTIVE:
            return OUTCOME_NOT_ASSESSED
    return OUTCOME_NOT_CHECKED


def map_only_relation_checks(
    resolved: ResolvedScanPolicy, registry: CheckRegistry | None = None
) -> dict[str, str]:
    """``{relation: check_id}`` of every enabled attack step a map-only run did not execute."""
    reg = registry or load_registry()
    out: dict[str, str] = {}
    for check in reg.checks:
        if not check.is_attack_step or check.locked_state == LOCKED_NEVER_EXECUTED:
            continue
        if check.check_id not in resolved.effective_ids:
            continue
        for relation in check.relations:
            out.setdefault(str(relation).strip().lower(), check.check_id)
    return dict(sorted(out.items()))


def excluded_relation_checks(
    resolved: ResolvedScanPolicy, registry: CheckRegistry | None = None
) -> dict[str, str]:
    """``{relation: check_id}`` for every technique relation the policy keeps from running.

    Hard-blocked techniques are left out: the safety policy refuses them and
    labels them itself, so the scan policy never claims them.
    """
    reg = registry or load_registry()
    out: dict[str, str] = {}
    for check in reg.checks:
        if check.kind == KIND_DETECTION or check.locked_state == LOCKED_NEVER_EXECUTED:
            continue
        if check.check_id in resolved.effective_ids:
            continue
        for relation in check.relations:
            out.setdefault(str(relation).strip().lower(), check.check_id)
    return dict(sorted(out.items()))


def excluded_control_keys(
    resolved: ResolvedScanPolicy, registry: CheckRegistry | None = None
) -> list[str]:
    """Positive-control keys whose only producer the policy excluded."""
    reg = registry or load_registry()
    keys: list[str] = []
    for control_key, cve_id in POSITIVE_CONTROL_CVE_PRODUCERS.items():
        check = reg.check_for_cve(cve_id)
        if check is not None and check.check_id not in resolved.effective_ids:
            keys.append(control_key)
    return sorted(keys)


def _summarise_refusals(
    refusals: Iterable[Mapping[str, Any]], registry: CheckRegistry
) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for item in refusals or ():
        if not isinstance(item, Mapping):
            continue
        check_id = str(item.get("check_id") or "").strip()
        if not check_id:
            continue
        check = registry.get(check_id)
        entry = grouped.setdefault(
            check_id,
            {
                "check_id": check_id,
                "title": check.title if check is not None else check_id,
                "family": check.family if check is not None else "",
                "count": 0,
                "surfaces": [],
            },
        )
        entry["count"] += 1
        surface = str(item.get("surface") or "").strip()
        if surface and surface not in entry["surfaces"]:
            entry["surfaces"].append(surface)
    return sorted(
        grouped.values(),
        key=lambda e: (_family_order(e["family"]), str(e["title"]).lower()),
    )


def build_scan_policy_coverage(
    resolved: ResolvedScanPolicy | None,
    *,
    registry: CheckRegistry | None = None,
    source: str = "",
    refusals: Iterable[Mapping[str, Any]] = (),
    routes_not_executed: int | None = None,
    cleared: Mapping[str, Any] | None = None,
    posture_probe_disabled: bool = False,
    engine_version: str = "",
    pacing_applied: Mapping[str, Any] | None = None,
    execution_decision: str = "",
    password_attempts: Mapping[str, Any] | None = None,
    revert_verdicts: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Build the persisted coverage block for one run.

    Args:
        resolved: The run's resolved policy, or ``None`` when no policy applies
            (the block then states the built-in Full validation, complete).
        registry: The check registry; the committed snapshot when omitted.
        source: Where the policy came from (``scan_config``, ``repl``,
            ``workspace``, ``unreadable``).
        refusals: The engine's refusal records (``shell._scan_policy_refusals``).
        routes_not_executed: Routes carrying an excluded, not-run step, filled at
            scan end from the canonical listing.
        cleared: The operator's ``policy clear`` record when this run is the
            first after it (D-1), else ``None``.
        posture_probe_disabled: ``ADSCAN_NO_POSTURE_PROBE`` was set (D-10).
        engine_version: Engine version string, for the record.
        pacing_applied: The assessment-pace view, so the policy export and the
            report state checks and pace together.
        execution_decision: How this run treated attack steps
            (:func:`adscan_core.scan_policy.execution.execution_decision`).
            ``map_only`` adds every enabled attack step to the not-executed set.
        password_attempts: The password-attempt rules the run used
            (``PasswordAttemptRules.to_dict()``); when omitted, the policy's own
            (:func:`effective_password_attempts`), so the margin is stated the
            way the pace is.
        revert_verdicts: What the run established, per domain, about the cleanup
            account (``RevertPermissionVerdict.to_dict()``), for the statement of
            which steps ran or did not because of it.

    Returns:
        A JSON-safe block. Always carries ``statement``.
    """
    reg = registry or load_registry()
    policy_set = resolved is not None
    if resolved is None:
        resolved = resolve_policy(builtin_definition(BASE_FULL_VALIDATION), reg)
    definition = resolved.definition
    identity = definition.identity

    excluded: list[dict[str, Any]] = []
    for check in reg.checks:
        if check.check_id in resolved.effective_ids or check.locked_state == LOCKED_NEVER_EXECUTED:
            continue
        if check.is_paired_detection:
            # Folded into its owner's row: the detection is reported whenever the
            # owner maps it, and its owner's outcome says why it was not.
            continue
        if check.check_id in resolved.dependency_excluded:
            reason = REASON_DEPENDENCY_EXCLUDED
        elif check.check_id in resolved.revert_excluded_ids:
            reason = REASON_NEEDS_CLEANUP_ACCOUNT
        else:
            reason = REASON_EXCLUDED_BY_POLICY
        row: dict[str, Any] = {
            "check_id": check.check_id,
            "title": check.title or check.check_id,
            "family": check.family,
            "kind": check.kind,
            "group": check.group,
            "outcome": outcome_for(check),
            "reason": reason,
        }
        if reason == REASON_DEPENDENCY_EXCLUDED:
            blocker = resolved.dependency_excluded.get(check.check_id, "")
            blocker_check = reg.get(blocker)
            row["blocked_by"] = blocker
            row["blocked_by_title"] = blocker_check.title if blocker_check else blocker
        excluded.append(row)
    excluded.sort(key=lambda r: (_family_order(r["family"]), r["kind"], str(r["title"]).lower()))

    families: list[dict[str, Any]] = []
    runnable = _runnable(reg)
    for family in FAMILIES:
        members = [c for c in runnable if c.family == family.family_id]
        if not members:
            continue
        enabled = sum(1 for c in members if c.check_id in resolved.effective_ids)
        families.append(
            {
                "family": family.family_id,
                "label": family.label,
                "enabled": enabled,
                "total": len(members),
                "excluded": len(members) - enabled,
            }
        )

    counts: dict[str, dict[str, int]] = {}
    for kind in (KIND_TECHNIQUE, KIND_DETECTION):
        members = [c for c in runnable if c.kind == kind]
        enabled = sum(1 for c in members if c.check_id in resolved.effective_ids)
        counts[kind] = {"enabled": enabled, "total": len(members), "excluded": len(members) - enabled}
    never_executed = sum(1 for c in reg.checks if c.locked_state == LOCKED_NEVER_EXECUTED)

    group_counts: dict[str, dict[str, int]] = {}
    for group in GROUPS:
        members = [c for c in runnable if c.group == group and not c.is_paired_detection]
        enabled = sum(1 for c in members if c.check_id in resolved.effective_ids)
        group_counts[group] = {
            "enabled": enabled,
            "total": len(members),
            "excluded": len(members) - enabled,
        }

    map_only = execution_decision == DECISION_MAP_ONLY
    relation_checks = excluded_relation_checks(resolved, reg)
    relation_labels: dict[str, str] = {}
    if map_only:
        for relation, check_id in map_only_relation_checks(resolved, reg).items():
            if relation not in relation_checks:
                relation_checks[relation] = check_id
                relation_labels[relation] = MAP_ONLY_STEP_LABEL
        relation_checks = dict(sorted(relation_checks.items()))

    complete = not excluded and not map_only
    block: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "policy_set": policy_set,
        "policy": {
            "name": policy_display_name(definition),
            "id": identity.policy_id,
            "revision": int(identity.revision or 0),
            "base": definition.base,
            "base_label": BUILTIN_LABELS.get(definition.base, definition.base),
            "modified_for_this_scan": bool(identity.modified_for_this_scan),
            "digest": resolved.digest,
            "source": str(source or ("default" if not policy_set else "")),
        },
        "registry_version": resolved.registry_version,
        "engine_version": str(engine_version or ""),
        "complete": complete,
        "excluded": excluded,
        "unknown_ids": list(resolved.unknown_ids),
        "warnings": list(resolved.warnings),
        "families": families,
        "counts": counts,
        "group_counts": group_counts,
        "execution_mode": resolved.execution_mode,
        "execution_decision": str(execution_decision or ""),
        "never_executed_count": never_executed,
        "safety_summary": build_policy_safety_summary(resolved, reg),
        "excluded_relations": sorted(relation_checks),
        "excluded_relation_checks": relation_checks,
        "excluded_relation_labels": relation_labels,
        "excluded_finding_keys": sorted(resolved.excluded_finding_keys),
        "excluded_control_keys": excluded_control_keys(resolved, reg),
        "refusals": _summarise_refusals(refusals, reg),
        "routes_not_executed": routes_not_executed,
        "cleared": dict(cleared) if isinstance(cleared, Mapping) and cleared else None,
        "posture_probe_disabled": bool(posture_probe_disabled),
        "pacing_applied": dict(pacing_applied) if isinstance(pacing_applied, Mapping) else None,
        # Checks the saved policy gained since it was saved and nobody has
        # reviewed; the ones that ran are named in the disclosure.
        "new_checks": (
            notice.to_dict()
            if policy_set
            and (notice := new_checks_since_saved(definition, registry=reg, resolved=resolved))
            is not None
            else None
        ),
        "password_attempts": (
            dict(password_attempts)
            if isinstance(password_attempts, Mapping) and password_attempts
            else effective_password_attempts(definition if policy_set else None)
        ),
        # Behaviour settings the policy changed from its environment's defaults
        # (a built-in changes none, so its disclosure is unchanged).
        "changed_settings": changed_settings(definition) if policy_set else {},
        # The checks that hinge on the cleanup account, and what the run
        # established about it in each domain.
        "revert_permission": {
            "conditional": sorted(resolved.revert_conditional_ids),
            "excluded": sorted(resolved.revert_excluded_ids),
            "verdicts": [dict(v) for v in (revert_verdicts or ()) if isinstance(v, Mapping)],
        },
    }
    block["statement"] = _statement(block)
    return block


# ── statements (client-facing; pass the adscan-writing gate) ─────────────────


def _policy_phrase(block: Mapping[str, Any]) -> str:
    policy = block.get("policy") or {}
    name = str(policy.get("name") or "Full validation")
    revision = int(policy.get("revision") or 0)
    base_label = str(policy.get("base_label") or "")
    bits = [f"the scan policy '{name}'"]
    detail: list[str] = []
    if revision:
        detail.append(f"revision {revision}")
    if base_label and base_label not in name:
        detail.append(f"based on {base_label}")
    if detail:
        bits.append(f"({', '.join(detail)})")
    return " ".join(bits)


def _statement(block: Mapping[str, Any]) -> str:
    if not block.get("policy_set"):
        return (
            "This assessment ran under the default policy, Full validation, which "
            "enables every check ADscan can run."
        )
    lead = f"This assessment ran under {_policy_phrase(block)}"
    map_only = block.get("execution_decision") == DECISION_MAP_ONLY
    groups = block.get("group_counts")
    parts: list[str] = []
    if isinstance(groups, Mapping) and groups:
        steps = int((groups.get(GROUP_ATTACK_STEPS) or {}).get("excluded", 0) or 0)
        vulns = int((groups.get(GROUP_VULNERABILITIES) or {}).get("excluded", 0) or 0)
        collection = int((groups.get(GROUP_COLLECTION) or {}).get("excluded", 0) or 0)
        if steps:
            parts.append(_plural(steps, "attack step"))
        if vulns:
            parts.append(_plural(vulns, "vulnerability check"))
        if collection:
            parts.append(_plural(collection, "collection step"))
    else:
        counts = block.get("counts") or {}
        techniques = (counts.get(KIND_TECHNIQUE) or {}).get("excluded", 0)
        detections = (counts.get(KIND_DETECTION) or {}).get("excluded", 0)
        if techniques:
            parts.append(_plural(techniques, "technique"))
        if detections:
            parts.append(_plural(detections, "detection"))
    tail = f" {MAP_ONLY_STATEMENT}" if map_only else ""
    if not parts:
        return f"{lead}, which excluded no check.{tail}"
    joined = parts[0] if len(parts) == 1 else f"{', '.join(parts[:-1])} and {parts[-1]}"
    return (
        f"{lead}. It excluded {joined}. Excluded attack steps stay on the attack "
        "paths as not executed, and every other excluded check is listed as not "
        f"assessed.{tail}"
    )


def _routes_line(count: Any) -> str:
    if not isinstance(count, int) or isinstance(count, bool) or count <= 0:
        return ""
    if count == 1:
        return (
            "1 attack path includes a step the policy excluded. It is shown with its "
            "own status and the excluded step is marked as not executed."
        )
    return (
        f"{count} attack paths include a step the policy excluded. They are shown "
        "with their own status and each excluded step is marked as not executed."
    )


def _refusal_line(refusals: Any) -> str:
    rows = [r for r in (refusals or ()) if isinstance(r, Mapping) and r.get("count")]
    if not rows:
        return ""
    total = sum(int(r.get("count") or 0) for r in rows)
    names = [str(r.get("title") or r.get("check_id")) for r in rows[:4]]
    named = ", ".join(names)
    if len(rows) > 4:
        named += f" and {_plural(len(rows) - 4, 'other')}"
    return (
        f"During the run ADscan reached an excluded technique {_plural(total, 'time')} "
        f"and stopped each time without running it ({named})."
    )


def _cleared_line(cleared: Any) -> str:
    if not isinstance(cleared, Mapping) or not cleared:
        return ""
    previous = cleared.get("previous") if isinstance(cleared.get("previous"), Mapping) else {}
    name = str(previous.get("name") or "").strip()
    when = str(cleared.get("cleared_at") or "").strip()[:10]
    subject = f"The scan policy '{name}'" if name else "The previous scan policy"
    on = f" on {when}" if when else ""
    return (
        f"{subject} was removed by the operator{on}, before this run. This run used the "
        "default policy instead."
    )


def scan_policy_coverage_view(block: Any) -> dict[str, Any]:
    """Render shape for the PDF, the LITE report and the web CTEM.

    ``prominent`` is True when the run did not use the default: then the
    surfaces show the safety summary, the per-family table and the excluded
    list. At the default the surfaces show ``headline`` only, one line.
    """
    if not isinstance(block, Mapping) or not block.get("statement"):
        return {"present": False}
    policy = block.get("policy") if isinstance(block.get("policy"), Mapping) else {}
    excluded = [r for r in (block.get("excluded") or ()) if isinstance(r, Mapping)]
    policy_set = bool(block.get("policy_set"))
    cleared_line = _cleared_line(block.get("cleared"))
    map_only = block.get("execution_decision") == DECISION_MAP_ONLY
    prominent = bool(policy_set and (excluded or not block.get("complete", True))) or bool(
        cleared_line
    )
    families = [
        {
            "label": str(f.get("label") or _family_label(str(f.get("family") or ""))),
            "enabled": int(f.get("enabled") or 0),
            "total": int(f.get("total") or 0),
            "excluded": int(f.get("excluded") or 0),
        }
        for f in (block.get("families") or ())
        if isinstance(f, Mapping) and int(f.get("excluded") or 0) > 0
    ]
    excluded_rows = []
    for row in excluded[:_MAX_ROWS]:
        reason = str(row.get("reason") or "")
        if reason == REASON_DEPENDENCY_EXCLUDED:
            reason_label = (
                f"Not run because {row.get('blocked_by_title') or row.get('blocked_by')} is excluded"
            )
        elif reason == REASON_NEEDS_CLEANUP_ACCOUNT:
            reason_label = NEEDS_CLEANUP_ACCOUNT_LABEL
        else:
            reason_label = OUTCOME_LABELS.get(
                str(row.get("outcome") or ""), "Excluded by the policy"
            )
        group = str(row.get("group") or "")
        excluded_rows.append(
            {
                "title": str(row.get("title") or row.get("check_id") or ""),
                "family": _family_label(str(row.get("family") or "")),
                "group": GROUP_LABELS.get(group, ""),
                "kind": "Detection" if row.get("kind") == KIND_DETECTION else "Technique",
                "reason": reason_label,
            }
        )
    never = int(block.get("never_executed_count") or 0)
    never_line = (
        f"ADscan never runs {_plural(never, 'further technique')} under any policy, "
        "because it treats them as unsafe for a live directory."
        if prominent and never
        else ""
    )
    unknown = [str(u) for u in (block.get("unknown_ids") or ()) if str(u).strip()]
    unknown_line = (
        f"The policy names {_plural(len(unknown), 'check')} this version of ADscan does not "
        "know, so they had no effect."
        if unknown
        else ""
    )
    posture_line = (
        "The automatic detection of authentication hardening was turned off for this run, "
        "so ADscan relied on what each connection reported."
        if block.get("posture_probe_disabled")
        else ""
    )
    if policy_set:
        headline = str(block.get("statement") or "")
    else:
        headline = "Full validation, the default policy. Every check ADscan can run was enabled."
    safety = block.get("safety_summary") if isinstance(block.get("safety_summary"), Mapping) else {}
    digest = str(policy.get("digest") or "")
    algo, _, hexpart = digest.partition(":")
    return {
        "present": True,
        "policy_set": policy_set,
        "prominent": prominent,
        "headline": headline,
        "statement": str(block.get("statement") or ""),
        "policy_name": str(policy.get("name") or ""),
        "policy_revision": int(policy.get("revision") or 0),
        "base_label": str(policy.get("base_label") or ""),
        "source_label": SOURCE_LABELS.get(str(policy.get("source") or ""), ""),
        "digest": digest,
        "digest_short": f"{algo}:{hexpart[:12]}" if hexpart else digest,
        "safety_statement": str(safety.get("statement") or "") if prominent else "",
        "families": families,
        "excluded": excluded_rows,
        "excluded_total": len(excluded),
        "excluded_omitted": max(0, len(excluded) - _MAX_ROWS),
        "routes_line": _routes_line(block.get("routes_not_executed")),
        "refusal_line": _refusal_line(block.get("refusals")),
        "cleared_line": cleared_line,
        "never_executed_line": never_line,
        "unknown_line": unknown_line,
        "posture_line": posture_line,
        "execution_mode_label": (
            EXECUTION_MODE_LABELS.get(str(block.get("execution_mode") or ""), "")
            if policy_set
            else ""
        ),
        "execution_line": (
            EXECUTION_LINES.get(str(block.get("execution_decision") or ""), "")
            if policy_set
            else ""
        ),
        "map_only": map_only,
        "new_checks_line": unreviewed_checks_ran_line(block.get("new_checks")),
        # The password-attempt margin, stated whatever the policy, like the pace.
        "password_attempts_line": password_attempts_line(
            block.get("password_attempts"),
            sends_password_attempts=policy_sends_password_attempts(block.get("safety_summary")),
        ),
        "settings_line": changed_settings_line(block.get("changed_settings")),
        "revert_permission_line": revert_permission_line(block),
    }


def revert_permission_line(block: Any) -> str:
    """What the run did about the cleanup account, or ``""``.

    The policy-level lines (which steps hinge on the account) come from the
    safety summary; the per-domain verdicts say what the run established.
    """
    from adscan_core.scan_policy.revert_permission import (  # noqa: PLC0415
        RevertPermissionVerdict,
        verdict_line,
    )

    if not isinstance(block, Mapping):
        return ""
    safety = block.get("safety_summary") if isinstance(block.get("safety_summary"), Mapping) else {}
    parts = [str(x) for x in (safety.get("revert_permission_lines") or ()) if str(x).strip()]
    section = block.get("revert_permission") if isinstance(block.get("revert_permission"), Mapping) else {}
    for raw in section.get("verdicts") or ():
        if isinstance(raw, Mapping):
            parts.append(verdict_line(RevertPermissionVerdict.from_mapping(raw)))
    return " ".join(parts)


def merge_scan_policy_coverage(entries: Iterable[Any]) -> dict[str, Any]:
    """One view for a multi-domain report: the block is the same for every domain.

    The first block found wins; a later domain carrying more exclusions (a run
    that stamped domains at different moments) is preferred so the stricter
    statement is the one printed.
    """
    best: Mapping[str, Any] | None = None
    for entry in entries or ():
        if not isinstance(entry, Mapping):
            continue
        block = entry.get(SCAN_POLICY_COVERAGE_KEY)
        if not isinstance(block, Mapping) or not block.get("statement"):
            continue
        if best is None or len(block.get("excluded") or ()) > len(best.get("excluded") or ()):
            best = block
    return scan_policy_coverage_view(best)


def policy_excluded_keys(json_data: Mapping[str, Any]) -> tuple[frozenset[str], frozenset[str]]:
    """``(finding_keys, control_keys)`` the run's policy excluded, across domains.

    Read by the compliance engine from the renderer's ``report_data``. Empty
    when no block is present (an older workspace, or a run without a policy).
    """
    findings: set[str] = set()
    controls: set[str] = set()
    for value in (json_data or {}).values():
        if not isinstance(value, Mapping):
            continue
        block = value.get(SCAN_POLICY_COVERAGE_KEY)
        if not isinstance(block, Mapping):
            continue
        findings.update(str(k) for k in (block.get("excluded_finding_keys") or ()) if k)
        controls.update(str(k) for k in (block.get("excluded_control_keys") or ()) if k)
    return frozenset(findings), frozenset(controls)


__all__ = (
    "NOT_ASSESSED_REASON",
    "POSITIVE_CONTROL_CVE_PRODUCERS",
    "REASON_DEPENDENCY_EXCLUDED",
    "SCAN_POLICY_COVERAGE_KEY",
    "EXECUTION_LINES",
    "OUTCOME_LABELS",
    "OUTCOME_MAPPED_NOT_EXECUTED",
    "OUTCOME_NOT_ASSESSED",
    "OUTCOME_NOT_CHECKED",
    "OUTCOME_NOT_COLLECTED",
    "SCHEMA_VERSION",
    "SOURCE_LABELS",
    "build_scan_policy_coverage",
    "excluded_control_keys",
    "excluded_relation_checks",
    "map_only_relation_checks",
    "outcome_for",
    "merge_scan_policy_coverage",
    "policy_excluded_keys",
    "scan_policy_coverage_view",
)
