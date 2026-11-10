"""Resolve a scan-policy definition against the check registry.

One function, :func:`resolve_policy`, turns a definition (plus the legacy
``phases.disabled`` / ``phases.steps`` keys, folded in so there is ONE
resolution) into a :class:`ResolvedScanPolicy`: precomputed frozensets the
enforcement gates read with set lookups, and the disclosure facts (what was
excluded, by selection or by dependency, which ids this engine does not know).

Precedence for one selectable check, highest first:

1. Locked checks ignore every override (``always_runs`` stays on,
   ``never_executed`` stays off); an override aimed at one is a warning.
2. An explicit check id beats a family selector. At equal specificity
   ``disabled`` beats ``enabled`` (warned).
3. ``new_checks == "disabled"`` switches off a check introduced after the
   registry version the policy was saved against.
4. Otherwise the base rule.

Then the legacy phase/step disables AND in (most restrictive wins), then the
dependency fixpoint runs (techniques: all-of ``requires``; detections: any-of
``requires_any``).

Design: docs/superpowers/specs/2026-11-04-scan-policy-checks-by-family-design.md § 6.1, § 7.1.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Iterable, Mapping

from adscan_core.scan_policy.families import FAMILY_IDS
from adscan_core.scan_policy.model import (
    ENV_MANUAL_CLEANUP,
    ENV_NOT_REVERSIBLE,
    ENV_REVERTED_AT_EXIT,
    ENV_REVERTED_AUTO,
    ENV_REVERTED_WHEN_PERMITTED,
    EXECUTION_GRAPH,
    KIND_DETECTION,
    LOCKED_ALWAYS_RUNS,
    LOCKED_NEVER_EXECUTED,
    CheckDefinition,
)
from adscan_core.scan_policy.policy import (
    BASE_RULES,
    NEW_CHECKS_DISABLED,
    ScanPolicyDefinition,
    effective_execution_mode,
)
from adscan_core.scan_policy.registry import CheckRegistry, load_registry

REASON_EXCLUDED_BY_POLICY = "excluded_by_policy"
REASON_NEVER_EXECUTED = "never_executed"
#: A ``reverted_when_permitted`` check left out because the policy allows no
#: manual cleanup and the run has no cleanup account to undo its change with.
REASON_NEEDS_CLEANUP_ACCOUNT = "needs_cleanup_account"

#: Environment-change classes, least invasive first. A policy that accepts one
#: accepts every class before it.
CHANGE_CLASS_ORDER: tuple[str, ...] = (
    ENV_REVERTED_AUTO,
    ENV_REVERTED_AT_EXIT,
    # Below manual_cleanup on purpose: ranking it AS manual_cleanup would grant a
    # policy that runs it the preparatory changes reserved for manual cleanup
    # (restoring a deleted object), which nobody asked for.
    ENV_REVERTED_WHEN_PERMITTED,
    ENV_MANUAL_CLEANUP,
    ENV_NOT_REVERSIBLE,
)

#: Classes that leave a change for the client to remove by hand.
_MANUAL_CLASSES = frozenset({ENV_MANUAL_CLEANUP, ENV_NOT_REVERSIBLE})


@dataclass(frozen=True)
class RevertPermissionContext:
    """What the run knows, before it starts, about undoing changes.

    Attributes:
        cleanup_account_supplied: A client cleanup account is configured for at
            least one domain of the run (passed with it or saved in the
            workspace). Whether it holds the right in a given domain is verified
            per domain, read-only, before the write
            (``adscan_internal.services.revert_permission``).
    """

    cleanup_account_supplied: bool = False


@dataclass(frozen=True)
class ResolvedScanPolicy:
    """The effective selection of one run, ready for set-lookup gates.

    Attributes:
        definition: The definition that was resolved.
        registry_version: Registry version it was resolved against.
        digest: ``sha256:<hex>`` of the canonical definition + registry version.
        effective_ids: Checks that will run / be evaluated.
        excluded_ids: Selectable checks switched off by the policy itself.
        dependency_excluded: ``{check_id: blocking_check_id}`` for checks selected
            on but switched off because something they need is off.
        never_executed_ids: Locked hard-blocked techniques (disclosed, never run).
        unknown_ids: Ids in the definition that this registry does not know.
        warnings: Human-readable resolution warnings, in order.
        excluded_relations / excluded_finding_keys / excluded_subphases /
        excluded_phases / excluded_cve_ids / excluded_jobs: what the gates refuse.
    """

    definition: ScanPolicyDefinition
    registry_version: int
    digest: str
    effective_ids: frozenset[str]
    excluded_ids: frozenset[str]
    dependency_excluded: Mapping[str, str]
    never_executed_ids: frozenset[str]
    unknown_ids: tuple[str, ...]
    warnings: tuple[str, ...]
    excluded_relations: frozenset[str] = field(default_factory=frozenset)
    excluded_finding_keys: frozenset[str] = field(default_factory=frozenset)
    excluded_subphases: frozenset[str] = field(default_factory=frozenset)
    excluded_phases: frozenset[str] = field(default_factory=frozenset)
    excluded_cve_ids: frozenset[str] = field(default_factory=frozenset)
    excluded_jobs: frozenset[str] = field(default_factory=frozenset)
    permitted_change_classes: frozenset[str] = field(default_factory=frozenset)
    #: ``reverted_when_permitted`` checks the policy selected that run only
    #: because a cleanup account was supplied; each is verified per domain
    #: before it writes. Empty when the policy accepts manual cleanup (they run
    #: unconditionally, as any manual-cleanup check does).
    revert_conditional_ids: frozenset[str] = field(default_factory=frozenset)
    #: The same checks left out because no cleanup account was supplied (or no
    #: run context was given: a policy view resolves conservatively).
    revert_excluded_ids: frozenset[str] = field(default_factory=frozenset)
    #: The context the policy was resolved with; ``None`` for a policy view.
    revert_permission: "RevertPermissionContext | None" = None
    #: Legacy disables folded in, kept so the engine can re-resolve the same
    #: inputs when the cleanup account changes mid-session.
    legacy_disabled_phases: tuple[str, ...] = ()
    legacy_disabled_steps: tuple[tuple[str, tuple[str, ...]], ...] = ()

    @property
    def execution_mode(self) -> str:
        """The attack-step execution mode the policy asks for (``unattended`` / ``attended``)."""
        return effective_execution_mode(self.definition)

    def permits_change_class(self, change_class: str) -> bool:
        """Whether the policy accepts a preparatory change of this class."""
        return str(change_class or "") in self.permitted_change_classes

    @property
    def complete(self) -> bool:
        """True when the policy excluded nothing (by selection or dependency)."""
        return not self.excluded_ids and not self.dependency_excluded

    def is_effective(self, check_id: str) -> bool:
        return check_id in self.effective_ids


def policy_digest(definition: ScanPolicyDefinition, registry_version: int) -> str:
    """Stable digest a client can match against the policy on their authorization."""
    payload = json.dumps(
        {"definition": definition.canonical(), "registry_version": int(registry_version)},
        sort_keys=True,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _split_selectors(
    selectors: Iterable[str], registry: CheckRegistry, unknown: list[str], warnings: list[str]
) -> tuple[set[str], set[str]]:
    """Return ``(check_ids, family_ids)``, mapping retired ids and recording unknowns."""
    ids: set[str] = set()
    families: set[str] = set()
    for token in selectors:
        if token.startswith("family:"):
            family = token.split(":", 1)[1]
            if family in FAMILY_IDS:
                families.add(family)
            else:
                unknown.append(token)
            continue
        if token in registry:
            ids.add(token)
            continue
        if token in registry.retired:
            replacement = registry.retired[token]
            if replacement and replacement in registry:
                warnings.append(f"Check '{token}' was renamed to '{replacement}'; applied to the new id.")
                ids.add(replacement)
            else:
                warnings.append(f"Check '{token}' no longer exists in this version; ignored.")
                unknown.append(token)
            continue
        unknown.append(token)
    return ids, families


def _owner_maps(owner: CheckDefinition, effective: set[str]) -> bool:
    """Whether an owning technique puts its weakness on the map in this run.

    A graph step is mapped by the collector whatever its own switch says, as
    long as the collection it reads is on. An active technique or a probe maps
    its result only by running.
    """
    if owner.check_id in effective:
        return True
    if owner.execution == EXECUTION_GRAPH and owner.locked_state != LOCKED_NEVER_EXECUTED:
        return all(r in effective for r in owner.requires)
    return False


def _permitted_change_classes(reg: CheckRegistry, effective: set[str]) -> frozenset[str]:
    """The environment-change classes a policy accepts, from what it enables.

    A policy that enables a technique leaving a manual cleanup has accepted
    manual-cleanup changes, and every less invasive class with it. The consent
    rule for a preparatory directory change (re-enabling an account, restoring
    a deleted object) reads this.
    """
    ranks = [
        CHANGE_CLASS_ORDER.index(c.environment_change)
        for c in reg.checks
        if c.check_id in effective and c.environment_change in CHANGE_CLASS_ORDER
    ]
    if not ranks:
        return frozenset()
    return frozenset(CHANGE_CLASS_ORDER[: max(ranks) + 1])


def resolve_policy(
    definition: ScanPolicyDefinition,
    registry: CheckRegistry | None = None,
    *,
    legacy_disabled_phases: Iterable[str] = (),
    legacy_disabled_steps: Mapping[str, Iterable[str]] | None = None,
    revert_permission: RevertPermissionContext | None = None,
) -> ResolvedScanPolicy:
    """Resolve ``definition`` (and the legacy phase/step disables) into gates.

    Args:
        definition: The scan-policy definition.
        registry: The registry; the committed snapshot when omitted.
        legacy_disabled_phases: ``scan_config.phases.disabled``.
        legacy_disabled_steps: ``scan_config.phases.steps`` (``{phase: [sub, ...]}``).
        revert_permission: What the run knows about the cleanup account. A
            ``reverted_when_permitted`` check under a policy that allows no
            manual cleanup runs only when a cleanup account is supplied; without
            a context (a policy view) it is left out, because an unresolvable
            revert counts as not undoable.

    Returns:
        The resolved policy.
    """
    reg = registry or load_registry()
    unknown: list[str] = []
    warnings: list[str] = []
    on_ids, on_families = _split_selectors(definition.enabled, reg, unknown, warnings)
    off_ids, off_families = _split_selectors(definition.disabled, reg, unknown, warnings)
    for clash in sorted(on_ids & off_ids):
        warnings.append(f"Check '{clash}' is both enabled and disabled; it stays disabled.")
    for clash in sorted(on_families & off_families):
        warnings.append(f"Family '{clash}' is both enabled and disabled; it stays disabled.")

    base_rule = BASE_RULES[definition.base]
    selected: dict[str, bool] = {}
    never_executed: set[str] = set()
    for check in reg.checks:
        cid = check.check_id
        if check.locked_state == LOCKED_NEVER_EXECUTED:
            never_executed.add(cid)
            if cid in on_ids:
                warnings.append(f"Check '{cid}' is never executed by ADscan; it cannot be enabled.")
            selected[cid] = False
            continue
        if check.locked_state == LOCKED_ALWAYS_RUNS:
            if cid in off_ids or check.family in off_families:
                warnings.append(f"Check '{cid}' always runs; it cannot be disabled.")
            selected[cid] = True
            continue
        if check.is_paired_detection:
            # Reported whenever an owner is mapped (decided after the fixpoint
            # below); it has no switch of its own.
            if cid in off_ids:
                warnings.append(
                    f"Check '{cid}' is reported with the attack step that relies on it; "
                    "it cannot be switched off on its own."
                )
            selected[cid] = True
            continue
        if cid in off_ids:
            value = False
        elif cid in on_ids:
            value = True
        elif check.family in off_families:
            value = False
        elif check.family in on_families:
            value = True
        elif (
            definition.new_checks == NEW_CHECKS_DISABLED
            and definition.saved_at_registry_version > 0
            and check.introduced_in > definition.saved_at_registry_version
        ):
            value = False
        else:
            value = bool(base_rule(check))
        selected[cid] = value

    # Legacy phase / step disables fold into the same selection.
    for phase_id in legacy_disabled_phases or ():
        for check in reg.checks_for_phase(phase_id):
            if check.locked_state != LOCKED_ALWAYS_RUNS:
                selected[check.check_id] = False
    for phase_id, subs in (legacy_disabled_steps or {}).items():
        for sub_id in subs or ():
            check = reg.check_for_subphase(phase_id, sub_id)
            if check is not None and check.locked_state != LOCKED_ALWAYS_RUNS:
                selected[check.check_id] = False

    # Changes only a cleanup account can undo (reversible-by-construction § 3):
    # a policy that already accepts manual cleanup runs them as it runs any
    # manual-cleanup check; one that does not runs them only with a cleanup
    # account, and leaves them out otherwise.
    conditional = {
        cid
        for cid, on in selected.items()
        if on and (c := reg.get(cid)) is not None
        and c.environment_change == ENV_REVERTED_WHEN_PERMITTED
    }
    accepts_manual = any(
        on and (c := reg.get(cid)) is not None and c.environment_change in _MANUAL_CLASSES
        for cid, on in selected.items()
    )
    revert_conditional: set[str] = set()
    revert_excluded: set[str] = set()
    if conditional and not accepts_manual:
        if revert_permission is not None and revert_permission.cleanup_account_supplied:
            revert_conditional = set(conditional)
        else:
            revert_excluded = set(conditional)
            for cid in conditional:
                selected[cid] = False

    # Dependency fixpoint.
    effective = {cid for cid, on in selected.items() if on}
    dependency_excluded: dict[str, str] = {}
    changed = True
    while changed:
        changed = False
        for check in reg.checks:
            cid = check.check_id
            if cid not in effective:
                continue
            blocker = next((r for r in check.requires if r not in effective), None)
            if blocker is None and check.requires_any:
                if not any(r in effective for r in check.requires_any):
                    blocker = check.requires_any[0]
            if blocker is None and check.is_paired_detection:
                owners = [reg.get(o) for o in check.owned_by]
                if not any(
                    owner is not None and _owner_maps(owner, effective) for owner in owners
                ):
                    blocker = check.owned_by[0]
            if blocker is not None:
                effective.discard(cid)
                dependency_excluded[cid] = blocker
                changed = True

    excluded_ids = {
        cid
        for cid, on in selected.items()
        if not on and cid not in never_executed and cid not in revert_excluded
    }
    off_checks: list[CheckDefinition] = [c for c in reg.checks if c.check_id not in effective]
    technique_off = [c for c in off_checks if c.kind != KIND_DETECTION]
    return ResolvedScanPolicy(
        definition=definition,
        registry_version=reg.version,
        digest=policy_digest(definition, reg.version),
        effective_ids=frozenset(effective),
        excluded_ids=frozenset(excluded_ids),
        dependency_excluded=dict(sorted(dependency_excluded.items())),
        never_executed_ids=frozenset(never_executed),
        unknown_ids=tuple(dict.fromkeys(unknown)),
        warnings=tuple(warnings),
        excluded_relations=frozenset(r for c in technique_off for r in c.relations),
        excluded_finding_keys=frozenset(
            k for c in off_checks if c.kind == KIND_DETECTION for k in c.finding_keys
        ),
        excluded_subphases=frozenset(s for c in technique_off for s in c.subphases),
        excluded_phases=frozenset(
            phase
            for phase in {p for c in reg.checks for p in c.phases}
            | {s.split(".", 1)[0] for c in reg.checks for s in c.subphases}
            if reg.checks_for_phase(phase)
            and all(c.check_id not in effective for c in reg.checks_for_phase(phase))
        ),
        excluded_cve_ids=frozenset(i for c in technique_off for i in c.cve_ids),
        excluded_jobs=frozenset(j for c in technique_off for j in c.jobs),
        permitted_change_classes=_permitted_change_classes(reg, effective),
        revert_conditional_ids=frozenset(revert_conditional & effective),
        revert_excluded_ids=frozenset(revert_excluded),
        revert_permission=revert_permission,
        legacy_disabled_phases=tuple(legacy_disabled_phases or ()),
        legacy_disabled_steps=tuple(
            (str(phase), tuple(str(s) for s in (subs or ())))
            for phase, subs in sorted((legacy_disabled_steps or {}).items())
        ),
    )


def re_resolve_with_revert_permission(
    resolved: ResolvedScanPolicy,
    revert_permission: RevertPermissionContext | None,
    registry: CheckRegistry | None = None,
) -> ResolvedScanPolicy:
    """The same policy and legacy inputs, resolved again for a new context.

    The engine calls it when the cleanup account changes during a session (the
    run loaded one, or the operator set or removed it), so the gates follow the
    account without a second source of truth. The digest does not change: the
    context is a fact about the run, not part of the policy.
    """
    return resolve_policy(
        resolved.definition,
        registry,
        legacy_disabled_phases=resolved.legacy_disabled_phases,
        legacy_disabled_steps={p: list(s) for p, s in resolved.legacy_disabled_steps},
        revert_permission=revert_permission,
    )


__all__ = (
    "CHANGE_CLASS_ORDER",
    "REASON_EXCLUDED_BY_POLICY",
    "REASON_NEEDS_CLEANUP_ACCOUNT",
    "RevertPermissionContext",
    "re_resolve_with_revert_permission",
    "REASON_NEVER_EXECUTED",
    "ResolvedScanPolicy",
    "policy_digest",
    "resolve_policy",
)
