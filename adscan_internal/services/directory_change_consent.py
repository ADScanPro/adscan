"""Consent gate for opt-in directory changes, decided by the scan policy.

A step that writes to a client object (ForceChangePassword on a user, the ACL
menu's GenericAll/WriteSPN/AddMember options), and every preparatory write a
step needs before it can run (re-enabling a disabled account, restoring a
deleted object from the AD Recycle Bin), passes this ONE rule. Assigning a new
password to an account that must change it at next logon is a technique of its
own (``module:password_rotation_on_required_change``) and is consented by that
check.

The answer comes from the scan policy, not from the workspace type
(scan-policy two-groups spec § 5):

* **Unattended** (``adscan ci`` / the web worker under a policy that runs its
  enabled steps on their own): no prompt. A step is consented when the policy
  enables it (``check_id``); a preparatory change when the policy accepts its
  class (``change_class``): a policy that enables a technique needing a manual
  cleanup has accepted manual-cleanup changes.
* **Attended** (an interactive ``start``, or the web with an operator deciding
  each step): the operator is asked, with the prompt preset to that same answer.
* **Map-only** (decide-during-scan policy, no operator): refused.
* **No policy**: the built-in for the environment of the policy the workspace
  last had (:func:`adscan_core.scan_policy.policy.builtin_for_environment`: a
  lab is Lab / CTF, anything else, unknown included, Audit) answers the same way.

The destructive-action hard blocks run BEFORE this rule and are untouched by it.

A YES-defaulted ``Confirm.ask`` in front of a directory write is the defect this
module exists to prevent: the global prompt hook auto-answers the default. The
structural test ``tests/unit/test_directory_change_consent_gate.py`` fails CI if
one reappears in front of a known directory-writing helper.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from adscan_core.scan_policy import gate
from adscan_core.scan_policy.execution import (
    DECISION_MAP_ONLY,
    DECISION_UNATTENDED,
    execution_decision,
)
from adscan_core.scan_policy.policy import builtin_definition, builtin_for_environment
from adscan_core.scan_policy.settings import policy_environment
from adscan_core.scan_policy.resolve import ResolvedScanPolicy, resolve_policy

__all__ = [
    "CHANGE_CLASS_ACCOUNT_ENABLED",
    "CHANGE_CLASS_OBJECT_RESTORED",
    "CHANGE_CLASS_PASSWORD_ROTATED",
    "PASSWORD_ROTATION_CHECK_ID",
    "confirm_directory_change",
    "directory_change_consent_default",
    "policy_for_consent",
]

#: Preparatory change classes, in the environment-change vocabulary the
#: registry uses. Re-enabling an account is re-disabled at exit by the ACL
#: cleanup service and confirmed by re-reading userAccountControl, so the
#: registry derives its kind (``account_enabled``) as ``reverted_auto``; it used
#: to be filed as ``reverted_at_exit``, which Audit granted only because Owns was
#: then declared at that class. A restored object is left for the client to
#: delete; a rotated password cannot be put back. Locked against the derivation
#: by tests/unit/services/test_directory_change_consent_policy.py.
CHANGE_CLASS_ACCOUNT_ENABLED = "reverted_auto"
CHANGE_CLASS_OBJECT_RESTORED = "manual_cleanup"
CHANGE_CLASS_PASSWORD_ROTATED = "not_reversible"

#: The scan-policy check for rotating a password the domain requires changed
#: (``STATUS_PASSWORD_MUST_CHANGE``). It sits in the same family as
#: ForceChangePassword, so one setting decides both.
PASSWORD_ROTATION_CHECK_ID = "module:password_rotation_on_required_change"


@lru_cache(maxsize=8)
def _implied_policy(builtin_id: str) -> ResolvedScanPolicy:
    return resolve_policy(builtin_definition(builtin_id))


def policy_for_consent(shell: Any) -> ResolvedScanPolicy:
    """The policy that answers consent: the run's, else its environment's built-in."""
    policy = gate.active_policy(shell)
    if isinstance(policy, ResolvedScanPolicy):
        return policy
    return _implied_policy(builtin_for_environment(policy_environment(shell)))


def directory_change_consent_default(
    shell: Any, *, check_id: str | None = None, change_class: str | None = None
) -> bool:
    """The policy's answer for one opt-in directory change.

    Args:
        shell: The active shell.
        check_id: The technique whose own write this is (``step:forcechangepassword``).
        change_class: For a preparatory write, its environment-change class
            (:data:`CHANGE_CLASS_ACCOUNT_ENABLED` and siblings).

    Returns:
        True when the policy consents. With neither argument, True only when the
        policy accepts changes that are not reversible (the strictest reading).
    """
    try:
        policy = policy_for_consent(shell)
        consented = True
        if check_id:
            consented = str(check_id) in policy.effective_ids
        if consented and change_class:
            consented = policy.permits_change_class(change_class)
        if not check_id and not change_class:
            consented = policy.permits_change_class(CHANGE_CLASS_PASSWORD_ROTATED)
        return bool(consented)
    except Exception:  # noqa: BLE001 - an unreadable policy declines
        return False


def confirm_directory_change(
    shell: Any,
    prompt: str,
    *,
    check_id: str | None = None,
    change_class: str | None = None,
) -> bool:
    """Decide one opt-in directory change: by the policy, or by asking with its answer.

    Args:
        shell: The active shell.
        prompt: The question shown when the operator decides.
        check_id: The technique whose own write this is, when it is one.
        change_class: The class of a preparatory write, when it is one.

    Returns:
        Whether to make the change. Never raises: a failure declines it.
    """
    try:
        decision = execution_decision(shell)
    except Exception:  # noqa: BLE001
        decision = DECISION_MAP_ONLY
    if decision == DECISION_MAP_ONLY:
        return False
    default = directory_change_consent_default(
        shell, check_id=check_id, change_class=change_class
    )
    if decision == DECISION_UNATTENDED:
        return default
    from adscan_internal.rich_output import confirm_ask  # noqa: PLC0415

    try:
        # Attended, or no policy (DECISION_LEGACY): the operator answers, and an
        # unattended legacy run auto-resolves to the policy's answer.
        return bool(confirm_ask(prompt, default=default))
    except Exception:  # noqa: BLE001 - a broken prompt must decline, not approve
        return False
