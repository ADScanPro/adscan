"""Fail-closed scan-policy gate predicates (pure, shell-attribute based).

The enforcement seams (spec § 7.2) ask these questions. They read
``shell.scan_policy`` (a :class:`~adscan_core.scan_policy.resolve.ResolvedScanPolicy`
set by the run entry point) and never import ``adscan_internal``, so the
``adscan_core`` finding-emission seam can use them too.

Contract:

* No policy on the shell: every predicate returns True (today's behaviour).
* A policy is set: the answer is a set lookup. An id or relation the registry
  does not know returns **False** (fail closed): with an authorization in force,
  "I do not know this technique" must never mean "run it".
* Any internal error with a policy set returns False, for the same reason.
"""

from __future__ import annotations

from typing import Any

from adscan_core.scan_policy.model import CheckDefinition
from adscan_core.scan_policy.registry import CheckRegistry, load_registry
from adscan_core.scan_policy.resolve import ResolvedScanPolicy


def active_policy(shell: Any) -> Any | None:
    """The resolved policy on ``shell``, or ``None``.

    A :class:`ResolvedScanPolicy` is the contract. Any other object counts as a
    policy (and so fails closed in every predicate) unless it answers
    ``effective_ids`` with something that is not a set: that is an auto-attribute
    of a test double (``MagicMock``), not a policy anyone resolved, and treating
    it as one would refuse every technique on every mocked shell. An object whose
    ``effective_ids`` raises is a broken policy and stays active (fail closed).
    """
    policy = getattr(shell, "scan_policy", None)
    if policy is None or isinstance(policy, ResolvedScanPolicy):
        return policy
    try:
        ids = policy.effective_ids
    except Exception:  # noqa: BLE001 - a broken policy object fails closed
        return policy
    return policy if isinstance(ids, (set, frozenset)) else None


def _registry(shell: Any) -> CheckRegistry:
    reg = getattr(shell, "scan_policy_registry", None)
    return reg if isinstance(reg, CheckRegistry) else load_registry()


def _map_only(shell: Any) -> bool:
    from adscan_core.scan_policy.execution import (  # noqa: PLC0415
        DECISION_MAP_ONLY,
        execution_decision,
    )

    return execution_decision(shell) == DECISION_MAP_ONLY


def _runs(shell: Any, policy: Any, check: CheckDefinition) -> bool:
    """Whether a technique may run: in the policy, and not held to the map.

    A run whose policy leaves every attack step to an operator, with no operator
    present, maps the attack steps and executes none (execution spec § 4).
    Collection, probes and detections are not attack steps and still run.
    """
    if check.check_id not in policy.effective_ids:
        return False
    if check.is_attack_step and _map_only(shell):
        return False
    return True


def check_allowed(shell: Any, check_id: str) -> bool:
    """Whether ``check_id`` may run / be evaluated in this run."""
    policy = active_policy(shell)
    if policy is None:
        return True
    try:
        check = _registry(shell).get(str(check_id))
        if check is None:
            return str(check_id) in policy.effective_ids
        return _runs(shell, policy, check)
    except Exception:  # noqa: BLE001 - a broken policy object fails closed
        return False


def relation_allowed(shell: Any, relation: str) -> bool:
    """Whether an attack-step relation may execute.

    A relation that is not a check (graph glue, or a relation ADscan never
    executes) is allowed: it sends nothing. A relation absent from the catalog
    entirely is refused when a policy is set.
    """
    policy = active_policy(shell)
    if policy is None:
        return True
    try:
        reg = _registry(shell)
        check = reg.check_for_relation(relation)
        if check is None:
            return reg.is_known_relation(relation)
        return _runs(shell, policy, check)
    except Exception:  # noqa: BLE001
        return False


def finding_allowed(shell: Any, key: str) -> bool:
    """Whether a finding key may be recorded.

    A key that is not a catalog finding is not a check; it is allowed (the
    emission seam already routes non-catalog metrics elsewhere).
    """
    policy = active_policy(shell)
    if policy is None:
        return True
    try:
        check = _registry(shell).check_for_finding(key)
        if check is None:
            return True
        return check.check_id in policy.effective_ids
    except Exception:  # noqa: BLE001
        return False


def subphase_allowed(shell: Any, phase_id: str, subphase_id: str) -> bool:
    """Whether a pipeline subphase bound to a check may run.

    A subphase with no bound check is not the policy's decision (True).
    """
    policy = active_policy(shell)
    if policy is None:
        return True
    try:
        check = _registry(shell).check_for_subphase(phase_id, subphase_id)
        if check is None:
            return True
        return _runs(shell, policy, check)
    except Exception:  # noqa: BLE001
        return False


def phase_allowed(shell: Any, phase_id: str) -> bool:
    """A phase runs unless every check bound to it is excluded."""
    policy = active_policy(shell)
    if policy is None:
        return True
    try:
        if str(phase_id) in policy.excluded_phases:
            return False
        bound = _registry(shell).checks_for_phase(str(phase_id))
        if bound and _map_only(shell):
            return any(_runs(shell, policy, c) for c in bound)
        return True
    except Exception:  # noqa: BLE001
        return False


def cve_allowed(shell: Any, cve_id: str) -> bool:
    """Whether a CVE probe may run. An unknown probe id fails closed."""
    policy = active_policy(shell)
    if policy is None:
        return True
    try:
        check = _registry(shell).check_for_cve(cve_id)
        if check is None:
            return False
        return check.check_id in policy.effective_ids
    except Exception:  # noqa: BLE001
        return False


def job_allowed(shell: Any, kind: str) -> bool:
    """Whether a background job kind bound to a check may launch.

    A job kind with no bound check (cracking) is not the policy's decision.
    """
    policy = active_policy(shell)
    if policy is None:
        return True
    try:
        check = _registry(shell).check_for_job(kind)
        if check is None:
            return True
        return _runs(shell, policy, check)
    except Exception:  # noqa: BLE001
        return False


__all__ = (
    "active_policy",
    "check_allowed",
    "cve_allowed",
    "finding_allowed",
    "job_allowed",
    "phase_allowed",
    "relation_allowed",
    "subphase_allowed",
)
