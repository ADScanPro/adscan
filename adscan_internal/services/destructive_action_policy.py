"""Destructive-action guardrail — single source of truth (safety-critical).

ADscan is an authorized assessment tool. This module is a HARD REFUSAL layer:
it classifies Active Directory relationship steps that would DISRUPT a client's
production systems and lets every execution gate refuse to run them. It strictly
NARROWS what ADscan will execute — it adds no offensive capability.

Two axes are expressed by :class:`DestructiveVerdict`:

- ``hard_blocked`` — NEVER executable, in ANY mode (interactive, CTF, or
  non-interactive ``adscan ci`` / web). A pentester cannot force it.
- ``opt_in_only`` — disabled by default; runs only on an explicit interactive
  operator opt-in and is skipped in non-interactive mode.

The single classifier :func:`classify_destructive` is consumed by the execution
gates (``run_exploit_force_change_password``, the ACE-step dispatcher, the
attack-path executor) and by the graph stamping so the display and the executor
never disagree about what is refused.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "DestructiveVerdict",
    "classify_destructive",
    "is_machine_account_name",
    "safety_abstention_statement",
    "DANGEROUS_DESTRUCTIVE_MARKER",
    "SAFETY_ABSTENTION_LABEL",
    "SAFETY_ABSTENTION_LEAD",
    "safety_abstention_notes",
]

# Graph-edge marker (``blocked_kind``) stamped on an edge whose step ADscan
# hard-refused for safety. It marks EVERY safety abstention — a destructive reset
# (ForceChangePassword on a computer) OR a disruptive technique (Zerologon, NoPac,
# PrintNightmare, DNSAdmins abuse) — routed uniformly through the single
# :func:`classify_destructive` classifier. The client-facing render keys off this
# marker to place the path in the "Not executed for safety" bucket.
#
# ADscan is an EXPOSURE-VALIDATION product, not a security-validation product: it
# proves a path EXISTS but never attributes a non-execution to a defensive control
# (EDR/AV/MDI) it cannot observe remotely with certainty. There is therefore NO
# "an environment control blocked us" marker — an execution that did not complete
# is ``attempted`` (neutral), never a claim that a client control stopped it.
DANGEROUS_DESTRUCTIVE_MARKER = "dangerous_destructive"

# Client-facing display label + framing for a path/step ADscan deliberately did
# not execute for safety. These are consumed verbatim by the PDF report bucket
# and the attack-step narrative, and MIRRORED by the web platform (adscan_web
# frontend, which runs as a separate process and cannot import this module). A
# contract test keeps the two in sync so report and web say the same thing.
SAFETY_ABSTENTION_LABEL = "Not executed for safety"
SAFETY_ABSTENTION_LEAD = (
    "This attack path is real and exploitable. ADscan deliberately chose not to "
    "execute this step to avoid disrupting a production host."
)

# Statically disruptive techniques ADscan refuses to execute in every mode.
# Kept in lockstep with the ``policy_blocked`` catalog entries; the client-safe
# reason is sourced from that catalog (see ``_hard_blocked_reason``) so this
# stays a single source of truth rather than a second hardcoded copy.
_HARD_BLOCKED_RELATIONS: frozenset[str] = frozenset(
    {"zerologon", "nopac", "printnightmare", "dnsadminabuse"}
)

_FCP_RELATION = "forcechangepassword"

# Client-facing reasons — no offensive-tool names (they flow into deliverables).
_FCP_COMPUTER_REASON = (
    "Resetting a computer account password would disrupt that host; "
    "ADscan does not execute it."
)
_FCP_USER_REASON = (
    "Resetting a user's password is disruptive and irreversible, so ADscan "
    "only executes it with explicit operator opt-in."
)
_GENERIC_HARD_BLOCK_REASON = (
    "This technique is disruptive and ADscan does not execute it automatically."
)

# Authored, client-facing reasons for each statically hard-blocked technique.
# Deep and specific (the disruption mechanism a CISO's sysadmin will recognize),
# free of offensive-tool names (they flow verbatim into the PDF report and the web
# platform). These are the specific "why" that :func:`safety_abstention_statement`
# appends to the fixed lead ("…real and exploitable… ADscan deliberately chose not
# to execute…"), so they state the MECHANISM, not the abstention itself.
_HARD_BLOCKED_REASONS: dict[str, str] = {
    "zerologon": (
        "Exploiting this domain-controller authentication weakness resets the "
        "domain controller's own machine-account password to an empty value. That "
        "severs the controller from the domain and can take Active Directory "
        "offline for every user."
    ),
    "nopac": (
        "This technique creates and manipulates a machine account to impersonate a "
        "domain controller. Executing it leaves rogue accounts behind and can "
        "disrupt domain authentication."
    ),
    "printnightmare": (
        "This technique abuses the print spooler service to run code on the target "
        "with system privileges. Executing it can crash the spooler service or the "
        "host itself."
    ),
    "dnsadminabuse": (
        "This technique loads attacker-controlled code into the DNS service running "
        "on the domain controller. Executing it can crash DNS and break name "
        "resolution across the whole domain."
    ),
}


@dataclass(frozen=True, slots=True)
class DestructiveVerdict:
    """Classification of a relationship step against the destructive-action policy.

    Attributes:
        hard_blocked: The step is NEVER executable, in any mode.
        opt_in_only: The step is disabled by default and runs only on an explicit
            interactive operator opt-in (skipped in non-interactive mode).
        client_safe_reason: A client-facing sentence explaining the decision,
            free of offensive-tool names (safe to surface in deliverables).
    """

    hard_blocked: bool
    opt_in_only: bool
    client_safe_reason: str


def is_machine_account_name(name: str | None) -> bool:
    """Return True when a principal name denotes a machine/computer account.

    Windows machine accounts have a ``$``-suffixed sAMAccountName. This is an
    independent signal from the graph node ``kind`` — either is sufficient to
    treat a target as a computer for the guardrail.
    """
    return bool(name) and str(name).strip().endswith("$")


def _is_computer_target(target_kind: str | None) -> bool:
    """Return True when ``target_kind`` denotes a computer/machine target.

    Accepts a graph node kind (``"Computer"``/``"computer"``/``"machine"``) or a
    ``$``-suffixed value (a sAMAccountName passed in place of a kind), so a
    machine target is detected from either signal.
    """
    value = (target_kind or "").strip().lower()
    if not value:
        return False
    if value.endswith("$"):
        return True
    return value in {"computer", "machine"}


def _hard_blocked_reason(relation: str) -> str:
    """Return the client-safe reason for a statically hard-blocked technique.

    Prefers the authored, client-facing wording in :data:`_HARD_BLOCKED_REASONS`
    (deep + deliverable-safe). Falls back to the catalog ``support_reason`` via
    the support registry, then to a generic sentence, so the guardrail never
    raises even if the registry is unavailable.
    """
    authored = _HARD_BLOCKED_REASONS.get(relation)
    if authored:
        return authored
    try:
        from adscan_internal.services.attack_step_support_registry import (
            POLICY_BLOCKED_RELATIONS,
        )

        reason = POLICY_BLOCKED_RELATIONS.get(relation)
        if reason:
            return str(reason)
    except Exception:  # noqa: BLE001 - best-effort; never break the guardrail.
        pass
    return _GENERIC_HARD_BLOCK_REASON


def classify_destructive(relation: str, target_kind: str | None) -> DestructiveVerdict:
    """Classify one relationship step against the destructive-action policy.

    Args:
        relation: The BloodHound/ACL relationship name (case-insensitive).
        target_kind: The target's graph node kind (``"Computer"``/``"User"``/…)
            or a ``$``-suffixed sAMAccountName. Either signal is enough to treat
            the target as a computer.

    Returns:
        A :class:`DestructiveVerdict`. Relations not covered by the policy return
        ``DestructiveVerdict(False, False, "")`` (no change to their behavior).
    """
    rel = (relation or "").strip().lower()
    if not rel:
        return DestructiveVerdict(False, False, "")
    if rel in _HARD_BLOCKED_RELATIONS:
        return DestructiveVerdict(True, False, _hard_blocked_reason(rel))
    if rel == _FCP_RELATION:
        if _is_computer_target(target_kind):
            return DestructiveVerdict(True, False, _FCP_COMPUTER_REASON)
        return DestructiveVerdict(False, True, _FCP_USER_REASON)
    return DestructiveVerdict(False, False, "")


def safety_abstention_notes(
    relation: str, target_kind: str | None = None
) -> dict[str, str] | None:
    """Return graph/step ``details`` notes for a safety-abstained step, or None.

    The single place that decides whether a step is a safety abstention and what
    marker + client-safe reason to stamp. Every stamping site (the persisted
    graph edge notes AND the per-path ``steps_for_ui`` builders in
    ``attack_graph_service``/``attack_graph_core``) routes through this so a
    hard-blocked technique can never be stamped ``"dangerous"`` in one place and
    ``"dangerous_destructive"`` in another.

    Args:
        relation: The BloodHound/ACL relationship name (case-insensitive).
        target_kind: The target's graph node kind or ``$``-suffixed name (only
            matters for ForceChangePassword; the statically hard-blocked
            techniques are hard-blocked regardless of target).

    Returns:
        ``{"blocked_kind": "dangerous_destructive", "reason": …,
        "client_safe_reason": …}`` when the step is a hard-blocked safety
        abstention; ``None`` otherwise (the caller keeps its own default).
    """
    verdict = classify_destructive(relation, target_kind)
    if not verdict.hard_blocked:
        return None
    return {
        "blocked_kind": DANGEROUS_DESTRUCTIVE_MARKER,
        "reason": verdict.client_safe_reason,
        "client_safe_reason": verdict.client_safe_reason,
    }


def safety_abstention_statement(client_safe_reason: str | None) -> str:
    """Return the full client-facing statement for a safety-abstained step.

    Combines the fixed framing (:data:`SAFETY_ABSTENTION_LEAD`) — which presents
    the abstention as a deliberate protective decision — with the specific,
    engine-produced ``client_safe_reason`` (from :func:`classify_destructive`).
    The reason is never re-authored here; this only frames it.

    Args:
        client_safe_reason: The verdict's ``client_safe_reason`` for the blocked
            step (may be empty).

    Returns:
        A single client-safe sentence pair. When no reason is supplied, only the
        framing lead is returned.
    """
    reason = str(client_safe_reason or "").strip()
    if reason:
        return f"{SAFETY_ABSTENTION_LEAD} {reason}"
    return SAFETY_ABSTENTION_LEAD
