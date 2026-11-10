"""The policy safety summary: what an MSSP attaches to a written authorization.

Computed over the EFFECTIVE technique checks of a resolved policy, from the
declared safety metadata only. The statement is assembled from fixed phrases so
every surface (policy editor, export, report scope section, scan detail) prints
the same words. Undeclared counts are always stated when non-zero: a check whose
safety is not declared must never vanish from a summary meant for a signature.

Design: docs/superpowers/specs/2026-11-04-scan-policy-checks-by-family-design.md § 8.2.
"""

from __future__ import annotations

from typing import Any

from adscan_core.scan_policy.model import (
    ENV_MANUAL_CLEANUP,
    ENV_NOT_REVERSIBLE,
    ENV_REVERTED_AT_EXIT,
    ENV_REVERTED_AUTO,
    ENV_REVERTED_WHEN_PERMITTED,
    EVENTS_DECLARED,
    EVENTS_NO_NATIVE,
    GROUP_ATTACK_STEPS,
    GROUP_VULNERABILITIES,
    LOCKED_NEVER_EXECUTED,
    INTERFERENCE_TRANSIENT,
    KIND_DETECTION,
    KIND_TECHNIQUE,
    LOCKOUT_BOUNDED,
    LOCKOUT_NONE,
    LOCKOUT_POSSIBLE,
    UNDECLARED,
)
from adscan_core.scan_policy.model import CheckDefinition
from adscan_core.scan_policy.policy import BASE_RULES
from adscan_core.scan_policy.registry import CheckRegistry, load_registry
from adscan_core.scan_policy.resolve import ResolvedScanPolicy


def _n(count: int, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


#: What an undeclared safety axis is called in the summary, keyed like
#: ``undeclared``. Worded here once; the web renders :func:`undeclared_lines`.
_UNDECLARED_AXES: tuple[tuple[str, str, str], ...] = (
    ("environment_change", "its change to the environment", "their change to the environment"),
    ("lockout_risk", "its lockout risk", "their lockout risk"),
    ("service_interference", "whether it interferes with other systems",
     "whether they interfere with other systems"),
    ("events", "the Windows events it produces", "the Windows events they produce"),
)


#: Environment-change values that write to the client's environment.
_WRITING = frozenset(
    {
        ENV_REVERTED_AUTO,
        ENV_REVERTED_AT_EXIT,
        ENV_REVERTED_WHEN_PERMITTED,
        ENV_MANUAL_CLEANUP,
        ENV_NOT_REVERSIBLE,
    }
)


def revert_permission_lines(
    resolved: ResolvedScanPolicy, registry: CheckRegistry | None = None
) -> list[str]:
    """Which checks run, or are left out, because of the cleanup account.

    Worded once in :mod:`adscan_core.scan_policy.revert_permission`; every
    surface (CLI recap, report, web policy view) renders these lines.
    """
    from adscan_core.scan_policy.revert_permission import (  # noqa: PLC0415
        conditional_line,
        excluded_line,
    )

    reg = registry or load_registry()

    def _titles(ids: frozenset[str]) -> list[str]:
        return sorted(
            (c.title or c.check_id) for c in (reg.get(i) for i in ids) if c is not None
        )

    lines = [
        conditional_line(_titles(resolved.revert_conditional_ids)),
        excluded_line(
            _titles(resolved.revert_excluded_ids),
            run_context=resolved.revert_permission is not None,
        ),
    ]
    return [line for line in lines if line]


def _join(parts: list[str]) -> str:
    """"a, b and c"."""
    return parts[0] if len(parts) == 1 else f"{', '.join(parts[:-1])} and {parts[-1]}"


def _both(steps: int, vulns: int, one: str, many: str) -> str:
    """"3 attack steps and 2 vulnerability checks <many>", either part left out at zero.

    The verb agrees with the whole subject: singular only when it names exactly
    one check. Returns "" when both counts are zero.
    """
    parts = []
    if steps:
        parts.append(_n(steps, "attack step", "attack steps"))
    if vulns:
        parts.append(_n(vulns, "vulnerability check", "vulnerability checks"))
    if not parts:
        return ""
    return f"{' and '.join(parts)} {one if steps + vulns == 1 else many}"


def undeclared_lines(undeclared: dict[str, int]) -> list[str]:
    """One sentence per safety axis some enabled technique has not declared yet."""
    lines: list[str] = []
    for key, one, many in _UNDECLARED_AXES:
        count = int(undeclared.get(key) or 0)
        if count <= 0:
            continue
        if count == 1:
            lines.append(f"1 enabled technique does not declare {one} yet.")
        else:
            lines.append(f"{count} enabled techniques do not declare {many} yet.")
    return lines


#: How a dependency note reads: a property of the policy, or of an edit to it.
DEPENDENCY_TONE_POLICY = "policy"
DEPENDENCY_TONE_SELECTION = "selection"


def _root_blocker(resolved: ResolvedScanPolicy, check_id: str) -> str:
    """The check actually switched off behind a dependency-excluded check."""
    current = str(check_id)
    seen: set[str] = set()
    deps = resolved.dependency_excluded
    while current in deps and current not in seen:
        seen.add(current)
        current = str(deps[current])
    return current


def dependency_lines(
    resolved: ResolvedScanPolicy, registry: CheckRegistry | None = None
) -> list[dict[str, str]]:
    """Sentences for the checks left not assessed because something they need is off.

    Two cases read differently, so they are worded apart. When the base itself
    leaves the needed check out (Production-sensitive never runs a probe that
    makes a domain controller authenticate to the scanner, so it cannot confirm
    the coercion weaknesses), that is a property of the policy, stated neutrally.
    When an edit to the selection switched the needed check off, the edit is what
    left the others unassessed, and the note says so. A paired detection has no
    switch of its own, so neither sentence calls these checks "selected".

    Returns:
        ``[{"tone": "policy" | "selection", "text": ...}]``, empty when nothing
        is left out by a dependency.
    """
    reg = registry or load_registry()
    base_rule = BASE_RULES.get(resolved.definition.base)
    by_tone: dict[str, dict[str, list[CheckDefinition]]] = {}
    for check_id in resolved.dependency_excluded:
        check = reg.get(check_id)
        if check is None:
            continue
        root = reg.get(_root_blocker(resolved, check_id))
        from_policy = (
            root is None
            or root.locked_state == LOCKED_NEVER_EXECUTED
            or base_rule is None
            or not base_rule(root)
        )
        tone = DEPENDENCY_TONE_POLICY if from_policy else DEPENDENCY_TONE_SELECTION
        bucket = by_tone.setdefault(tone, {"checks": [], "roots": []})
        bucket["checks"].append(check)
        if root is not None:
            bucket["roots"].append(root)

    lines: list[dict[str, str]] = []
    policy = by_tone.get(DEPENDENCY_TONE_POLICY)
    if policy:
        steps = sum(1 for c in policy["checks"] if c.group == GROUP_ATTACK_STEPS)
        subject = _both(steps, len(policy["checks"]) - steps, "is", "are")
        roots = policy["roots"]
        one = len(policy["checks"]) == 1
        if roots and all(r.service_interference == INTERFERENCE_TRANSIENT for r in roots):
            reason = (
                f"Confirming {'it' if one else 'them'} means making other systems "
                "authenticate to the scanner, which this policy does not do."
            )
        else:
            reason = (
                f"The {'check it relies on is' if one else 'checks they rely on are'} "
                "not part of this policy."
            )
        lines.append(
            {
                "tone": DEPENDENCY_TONE_POLICY,
                "text": f"{subject} reported as not assessed under this policy. {reason}",
            }
        )
    selection = by_tone.get(DEPENDENCY_TONE_SELECTION)
    if selection:
        steps = sum(1 for c in selection["checks"] if c.group == GROUP_ATTACK_STEPS)
        subject = _both(steps, len(selection["checks"]) - steps, "is", "are")
        lines.append(
            {
                "tone": DEPENDENCY_TONE_SELECTION,
                "text": (
                    f"{subject} not assessed because this selection excludes "
                    f"{'a check it relies on' if len(selection['checks']) == 1 else 'checks they rely on'}."
                ),
            }
        )
    return lines


def build_policy_safety_summary(
    resolved: ResolvedScanPolicy, registry: CheckRegistry | None = None
) -> dict[str, Any]:
    """Counts and the client-facing statement for one resolved policy."""
    reg = registry or load_registry()
    techniques = [c for c in reg.checks if c.kind == KIND_TECHNIQUE]
    detections = [c for c in reg.checks if c.kind == KIND_DETECTION]
    on = [c for c in techniques if c.check_id in resolved.effective_ids]
    detections_on = sum(1 for c in detections if c.check_id in resolved.effective_ids)

    writes = {
        ENV_REVERTED_AUTO: sum(1 for c in on if c.environment_change == ENV_REVERTED_AUTO),
        ENV_REVERTED_AT_EXIT: sum(1 for c in on if c.environment_change == ENV_REVERTED_AT_EXIT),
        ENV_REVERTED_WHEN_PERMITTED: sum(
            1 for c in on if c.environment_change == ENV_REVERTED_WHEN_PERMITTED
        ),
        ENV_MANUAL_CLEANUP: sum(1 for c in on if c.environment_change == ENV_MANUAL_CLEANUP),
        ENV_NOT_REVERSIBLE: sum(1 for c in on if c.environment_change == ENV_NOT_REVERSIBLE),
    }
    writes_total = sum(writes.values())
    auth = {
        LOCKOUT_BOUNDED: sum(1 for c in on if c.lockout_risk == LOCKOUT_BOUNDED),
        LOCKOUT_POSSIBLE: sum(1 for c in on if c.lockout_risk == LOCKOUT_POSSIBLE),
        LOCKOUT_NONE: sum(1 for c in on if c.lockout_risk == LOCKOUT_NONE),
    }
    transient = sum(1 for c in on if c.service_interference == INTERFERENCE_TRANSIENT)
    undeclared = {
        "environment_change": sum(1 for c in on if c.environment_change == UNDECLARED),
        "lockout_risk": sum(1 for c in on if c.lockout_risk == UNDECLARED),
        "service_interference": sum(1 for c in on if c.service_interference == UNDECLARED),
        "events": sum(
            1 for c in on if c.events_declared not in {EVENTS_DECLARED, EVENTS_NO_NATIVE}
        ),
    }
    credential_reads = sum(1 for c in on if c.reads_credential_material)

    # ONE unit for everything a client reads (two-groups spec § 2): the attack
    # steps and the vulnerability checks. Paired detections are reported with
    # their step, so they are not counted as checks of their own, and collection
    # is neither group. Every figure below, the "N of M" and each safety count,
    # is computed over these two sets, so a delta between two policies is a plain
    # subtraction of the same figures (``tests/unit/scan_policy/test_summary_units.py``).
    runnable = [c for c in reg.checks if c.locked_state != LOCKED_NEVER_EXECUTED]
    steps = [c for c in runnable if c.group == GROUP_ATTACK_STEPS and c.kind == KIND_TECHNIQUE]
    vulns = [
        c for c in runnable if c.group == GROUP_VULNERABILITIES and not c.is_paired_detection
    ]
    steps_on = [c for c in steps if c.check_id in resolved.effective_ids]
    vulns_on = [c for c in vulns if c.check_id in resolved.effective_ids]

    def _group_figures(enabled: list, total: list) -> dict[str, Any]:
        members = {
            "enabled": enabled,
            "writes": [c for c in enabled if c.environment_change in _WRITING],
            "not_reversible": [c for c in enabled if c.environment_change == ENV_NOT_REVERSIBLE],
            "password_attempts": [
                c for c in enabled if c.lockout_risk in {LOCKOUT_BOUNDED, LOCKOUT_POSSIBLE}
            ],
            "lockout_possible": [c for c in enabled if c.lockout_risk == LOCKOUT_POSSIBLE],
            "interference": [
                c for c in enabled if c.service_interference == INTERFERENCE_TRANSIENT
            ],
        }
        figures: dict[str, Any] = {key: len(checks) for key, checks in members.items()}
        figures["total"] = len(total)
        # The ids behind each figure, so a comparison between two policies is a
        # set difference ("adds N"), never a subtraction of counts that would
        # misstate two policies that are not nested.
        figures["ids"] = {key: sorted(c.check_id for c in checks) for key, checks in members.items()}
        return figures

    by_group = {
        GROUP_ATTACK_STEPS: _group_figures(steps_on, steps),
        GROUP_VULNERABILITIES: _group_figures(vulns_on, vulns),
    }
    step_writes = {
        kind: sum(1 for c in steps_on if c.environment_change == kind)
        for kind in (
            ENV_REVERTED_AUTO,
            ENV_REVERTED_AT_EXIT,
            ENV_REVERTED_WHEN_PERMITTED,
            ENV_MANUAL_CLEANUP,
            ENV_NOT_REVERSIBLE,
        )
    }
    step_writes_total = sum(step_writes.values())

    sentences = [
        f"This policy runs {len(steps_on)} of {_n(len(steps), 'attack step', 'attack steps')} "
        f"and {len(vulns_on)} of {_n(len(vulns), 'vulnerability check', 'vulnerability checks')}."
    ]
    if step_writes_total:
        parts = []
        if step_writes[ENV_REVERTED_AUTO]:
            parts.append(f"{step_writes[ENV_REVERTED_AUTO]} roll back automatically when possible")
        if step_writes[ENV_REVERTED_AT_EXIT]:
            parts.append(f"{step_writes[ENV_REVERTED_AT_EXIT]} roll back at exit when possible")
        if step_writes[ENV_REVERTED_WHEN_PERMITTED]:
            parts.append(
                f"{step_writes[ENV_REVERTED_WHEN_PERMITTED]} roll back with the cleanup account"
            )
        if step_writes[ENV_MANUAL_CLEANUP]:
            parts.append(f"{step_writes[ENV_MANUAL_CLEANUP]} need a manual cleanup step")
        if step_writes[ENV_NOT_REVERSIBLE]:
            parts.append(f"{step_writes[ENV_NOT_REVERSIBLE]} cannot be undone")
        sentences.append(
            f"{_n(step_writes_total, 'of those attack steps writes', 'of those attack steps write')} "
            f"to your environment, of which {_join(parts)}."
        )
    else:
        sentences.append("Nothing it runs writes to your environment.")
    steps_fig = by_group[GROUP_ATTACK_STEPS]
    vulns_fig = by_group[GROUP_VULNERABILITIES]
    bounded = _both(
        steps_fig["password_attempts"] - steps_fig["lockout_possible"],
        vulns_fig["password_attempts"] - vulns_fig["lockout_possible"],
        "sends", "send",
    )
    if bounded:
        sentences.append(f"{bounded} password attempts limited by a lockout guard.")
    possible = _both(steps_fig["lockout_possible"], vulns_fig["lockout_possible"], "sends", "send")
    if possible:
        sentences.append(f"{possible} password attempts that can count toward account lockout.")
    if not bounded and not possible:
        sentences.append("Nothing it runs sends password attempts that count toward lockout.")
    interfering = _both(steps_fig["interference"], vulns_fig["interference"], "makes", "make")
    if interfering:
        sentences.append(f"{interfering} other systems authenticate to the scanner while it runs.")
    undeclared_any = max(undeclared["environment_change"], undeclared["lockout_risk"],
                         undeclared["service_interference"])
    if undeclared_any:
        sentences.append(
            f"{_n(undeclared_any, 'enabled check has', 'enabled checks have')} "
            "safety details not declared yet."
        )
    return {
        "attack_steps_enabled": len(steps_on),
        "attack_steps_total": len(steps),
        "vulnerability_checks_enabled": len(vulns_on),
        "vulnerability_checks_total": len(vulns),
        "by_group": by_group,
        "undeclared_lines": undeclared_lines(undeclared),
        # Checks a dependency leaves out, worded once (policy property vs edit).
        "dependency_lines": dependency_lines(resolved, reg),
        # Checks included or left out because of the cleanup account.
        "revert_permission_lines": revert_permission_lines(resolved, reg),
        "techniques_enabled": len(on),
        "techniques_total": len(techniques),
        "detections_enabled": detections_on,
        "detections_total": len(detections),
        "writes": {"total": writes_total, **writes},
        "authentication_attempts": auth,
        "service_interference": {INTERFERENCE_TRANSIENT: transient},
        "reads_credential_material": credential_reads,
        "undeclared": undeclared,
        "statement": " ".join(sentences),
    }


def policy_sends_password_attempts(safety_summary: Any) -> bool | None:
    """Whether any check the policy runs sends a password attempt.

    Read from the summary's per-group ``password_attempts`` figures, the same
    ones its statement words ("Nothing it runs sends password attempts ...").
    ``None`` when the summary does not carry them.
    """
    if not isinstance(safety_summary, dict):
        return None
    by_group = safety_summary.get("by_group")
    if not isinstance(by_group, dict) or not by_group:
        return None
    total = 0
    for figures in by_group.values():
        if not isinstance(figures, dict) or "password_attempts" not in figures:
            return None
        try:
            total += int(figures.get("password_attempts") or 0)
        except (TypeError, ValueError):
            return None
    return total > 0


__all__ = (
    "build_policy_safety_summary",
    "policy_sends_password_attempts",
    "dependency_lines",
    "revert_permission_lines",
    "undeclared_lines",
)
