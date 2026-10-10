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

This module is also the single source of truth for the CLIENT-FACING wording of
why a step did not execute — :func:`non_execution_statement` and the constants
behind it. A step that did not run has exactly two honest client statements: a
deliberate safety abstention (only ever a hard-blocked step, keyed on
:data:`DANGEROUS_DESTRUCTIVE_MARKER`) or "mapped but not exercised". Everything
else — the catalog's engineering-register ``support_reason`` in particular — is
screened out by :func:`is_internal_engineering_reason` before it can reach a
deliverable.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

__all__ = [
    "DestructiveVerdict",
    "classify_destructive",
    "opt_in_default_for_workspace",
    "skipped_by_default_in_audit",
    "OPT_IN_PREAPPROVED_WORKSPACE_TYPES",
    "client_safe_step_reason",
    "is_machine_account_name",
    "is_internal_engineering_reason",
    "non_execution_statement",
    "safety_abstention_statement",
    "DANGEROUS_DESTRUCTIVE_MARKER",
    "GENERIC_DISRUPTION_CLAUSE",
    "NOT_EXERCISED_STATEMENT",
    "SAFETY_ABSTENTION_LABEL",
    "SAFETY_ABSTENTION_LEAD",
    "path_is_safety_abstention",
    "step_is_safety_abstention",
    "safety_abstention_position",
    "SAFETY_ABSTENTION_TERMINAL",
    "SAFETY_ABSTENTION_MID_CHAIN",
    "path_safety_abstention_reason",
    "path_safety_abstention_relations",
    "safety_abstention_disruption_clause",
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

# Client-facing statement for a step that simply was NOT run — the honest
# alternative to the safety framing above, and the default for every
# non-execution that is not a hard-blocked safety abstention.
#
# The distinction is not cosmetic: claiming a protective motive for a step
# ADscan did not attempt misrepresents the engagement, and stating WHY ADscan
# did not attempt it ("not implemented yet") is a capability-gap confession that
# belongs in the engineering log, never in a priced deliverable. What is true
# and useful to the reader is that the step was derived from the environment's
# own configuration and left unexercised, so the finding still stands on the
# evidence that produced it.
NOT_EXERCISED_STATEMENT = (
    "This step was identified from the environment's configuration and was not "
    "exercised during this engagement."
)

# Statically disruptive techniques ADscan refuses to execute in every mode.
# Kept in lockstep with the ``policy_blocked`` catalog entries; the client-safe
# reason is sourced from that catalog (see ``_hard_blocked_reason``) so this
# stays a single source of truth rather than a second hardcoded copy.
_HARD_BLOCKED_RELATIONS: frozenset[str] = frozenset(
    {"zerologon", "nopac", "printnightmare", "dnsadminabuse"}
)

_FCP_RELATION = "forcechangepassword"

# ── Workspace-type consent defaults for opt-in-only steps ────────────────────
# An ``opt_in_only`` step does not run unless the operator says yes, and the
# centralized prompt helpers AUTO-RESOLVE to the prompt's default when nobody is
# at the keyboard (``adscan ci``, the web PoV worker). So the DEFAULT is what
# decides whether an unattended run performs the action at all, and it is
# workspace-type dependent: a CTF/lab target is disposable, a real engagement is
# not.
#
# This is the SSOT for that rule. ``run_exploit_force_change_password`` (the
# single ForceChangePassword consent choke point) consumes it, and the
# customer-facing safeguard matrix derives its "not executed in an audit"
# statement from it, so the document and the gate can never disagree.
OPT_IN_PREAPPROVED_WORKSPACE_TYPES: frozenset[str] = frozenset({"ctf"})


def opt_in_default_for_workspace(workspace_type: str | None) -> bool:
    """Return the consent DEFAULT for an opt-in-only step in this workspace.

    Args:
        workspace_type: The engagement type (``"audit"``, ``"ctf"``, ``"lab"``).

    Returns:
        True when the step is pre-approved for this workspace type (an
        unattended run performs it), False when the default is to decline (an
        unattended run SKIPS it, and an interactive operator is asked with the
        answer preset to no).
    """
    return (
        str(workspace_type or "").strip().lower()
        in OPT_IN_PREAPPROVED_WORKSPACE_TYPES
    )


def skipped_by_default_in_audit(relation: str, target_kind: str | None) -> bool:
    """Whether this step is declined by default in an ``audit`` workspace.

    True only for a step that is opt-in-only AND not pre-approved for an audit
    engagement, i.e. one ADscan does not perform on its own against a real
    client: unattended it is skipped outright, and interactively the operator
    has to override a prompt that defaults to no.
    """
    verdict = classify_destructive(relation, target_kind)
    return verdict.opt_in_only and not opt_in_default_for_workspace("audit")

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

# Short disruption CLAUSES, one per hard-blocked technique. These are the verb
# phrase that completes "Running {it} would have ..." in the executive summary,
# where the full authored sentence above is too long to carry. Client-facing
# prose: name the disruption the client's own sysadmin would recognise, never a
# tool and never ADscan's internals.
_HARD_BLOCKED_DISRUPTION_CLAUSES: dict[str, str] = {
    "zerologon": (
        "severed a domain controller from the domain and taken Active Directory "
        "offline for every user"
    ),
    "nopac": "disrupted domain authentication and left rogue machine accounts behind",
    "printnightmare": "crashed the print spooler service or the host running it",
    "dnsadminabuse": "disrupted name resolution for your production domain",
    _FCP_RELATION: (
        "broken the domain membership of the production host whose account "
        "password it resets"
    ),
}

#: The truthful fallback when the abstained techniques are mixed, or when the
#: technique is one this table does not name specifically. Deliberately vague
#: about the mechanism rather than guessing one: a wrong mechanism in a client
#: deliverable is worse than a general one.
GENERIC_DISRUPTION_CLAUSE = "disrupted production services"


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


def is_internal_engineering_reason(text: str | None) -> bool:
    """Return True when ``text`` is an internal, engineering-register reason.

    Screens a candidate reason string against every ``support_reason`` authored
    in the attack-step catalog and the support registry (see
    ``attack_step_support_registry.internal_support_reasons``). Those strings
    explain ADscan's automation coverage to a developer; a client reading one in
    a deliverable gets a capability-gap confession instead of a finding.

    Best-effort by design: if the registry cannot be imported (a trimmed
    deployment), nothing is screened rather than raising inside a renderer.
    """
    candidate = str(text or "").strip().casefold()
    if not candidate:
        return False
    try:
        from adscan_internal.services.attack_step_support_registry import (  # noqa: PLC0415
            internal_support_reasons,
        )

        return candidate in internal_support_reasons()
    except Exception:  # noqa: BLE001 - never break a render over the screen.
        return False


def client_safe_step_reason(details: dict | None) -> str:
    """Return the step's reason text that is safe to print to a client, or "".

    ``client_safe_reason`` is the ONLY key a producer promises to author as
    client-facing prose (:func:`safety_abstention_notes`,
    :func:`classify_destructive`). The generic ``reason`` key carries whatever
    the engine had — usually the engineering-register ``support_reason`` — so it
    is read only for a safety abstention, where
    :func:`safety_abstention_notes` writes the same authored sentence into both
    keys and older persisted graphs may carry only ``reason``.

    Whatever survives that is still screened by
    :func:`is_internal_engineering_reason`, so an internal string cannot reach a
    deliverable even if a future producer writes one into the wrong key.

    Args:
        details: A step/edge ``details`` (or graph ``notes``) mapping.

    Returns:
        A client-safe sentence, or ``""`` when the step has none.
    """
    if not isinstance(details, dict):
        return ""
    candidates = [details.get("client_safe_reason")]
    blocked_kind = str(details.get("blocked_kind") or "").strip().lower()
    if blocked_kind == DANGEROUS_DESTRUCTIVE_MARKER:
        candidates.append(details.get("reason"))
    for candidate in candidates:
        text = str(candidate or "").strip()
        if text and not is_internal_engineering_reason(text):
            return text
    return ""


def non_execution_statement(details: dict | None) -> str:
    """Return the client-facing sentence for a step that did not execute, or "".

    The single mapping every client surface (PDF report, web platform) uses, so
    the two can never disagree about what ADscan claims:

    - hard-blocked safety abstention (``blocked_kind`` is
      :data:`DANGEROUS_DESTRUCTIVE_MARKER`) → :data:`SAFETY_ABSTENTION_LEAD`
      plus the authored reason. This is the ONLY route to the safety framing;
      a bare reason string never reaches it.
    - any other non-execution marker (``unsupported``, the opt-in-only
      ``dangerous``) → :data:`NOT_EXERCISED_STATEMENT`, plus a client-safe
      reason when the producer authored one.
    - no marker at all → ``""`` (the step is theoretical; the narrative already
      says so and needs no trailing sentence).

    Args:
        details: A step/edge ``details`` (or graph ``notes``) mapping.

    Returns:
        A complete, client-safe sentence, or ``""``.
    """
    if not isinstance(details, dict):
        return ""
    blocked_kind = str(details.get("blocked_kind") or "").strip().lower()
    if not blocked_kind:
        return ""
    reason = client_safe_step_reason(details)
    if blocked_kind == DANGEROUS_DESTRUCTIVE_MARKER:
        return safety_abstention_statement(reason)
    if reason:
        return f"{NOT_EXERCISED_STATEMENT} {reason}"
    return NOT_EXERCISED_STATEMENT


def safety_abstention_disruption_clause(relations: Iterable[str] | None) -> str:
    """Return the "Running it would have ..." clause for abstained techniques.

    Args:
        relations: The relationship names of the steps ADscan abstained from.
            Several routes commonly share ONE technique, in which case that
            technique's specific clause is returned.

    Returns:
        A verb phrase completing "Running them would have ...". A mixed set of
        techniques, an unrecognised technique or an empty set resolves to
        :data:`GENERIC_DISRUPTION_CLAUSE` rather than a guessed mechanism.
    """
    distinct = {
        normalized
        for raw in (relations or ())
        if (normalized := str(raw or "").strip().lower())
    }
    if len(distinct) != 1:
        return GENERIC_DISRUPTION_CLAUSE
    return _HARD_BLOCKED_DISRUPTION_CLAUSES.get(
        distinct.pop(), GENERIC_DISRUPTION_CLAUSE
    )


def step_is_safety_abstention(step: object) -> bool:
    """Return True when ONE step was hard-refused for safety.

    The step-granularity half of :func:`path_is_safety_abstention`, and the one
    definition both use. A renderer that badges an individual hop needs it: a
    withheld step must read as restraint ("Not Executed for Safety"), never as
    the neutral ``attempted`` the bare ``blocked`` token degrades to, or the card
    contradicts its own prose one line apart.
    """
    if not isinstance(step, Mapping):
        return False
    details = step.get("details")
    if not isinstance(details, Mapping):
        return False
    return (
        str(details.get("blocked_kind") or "").strip().lower()
        == DANGEROUS_DESTRUCTIVE_MARKER
    )


def _iter_safety_abstained_steps(path: object) -> Iterable[Mapping]:
    """Yield the steps of ``path`` that were hard-refused for safety."""
    if not isinstance(path, Mapping):
        return
    steps = path.get("steps")
    if not isinstance(steps, Sequence) or isinstance(steps, (str, bytes)):
        return
    for step in steps:
        if step_is_safety_abstention(step):
            yield step  # type: ignore[misc]


def path_is_safety_abstention(path: object) -> bool:
    """Return True when a path carries a step ADscan hard-refused for safety.

    The ONE predicate for "did ADscan confirm this route and deliberately not
    execute it". Both the engine-stamped KPI count
    (``exposure_score_service.compute_exposure_kpis`` ->
    ``path_axis[<class>]["safety_withheld"]``) and the report's display bucket
    (``attack_path_render.group_attack_paths_by_status`` -> ``safety_blocked``)
    call it, so the headline figure and the section that details those routes
    can never disagree about which routes they are.

    A safety abstention is DISTINCT from a bare ``blocked`` status: ADscan is an
    exposure-validation product and never attributes a non-execution to a
    control in the client's environment, so a ``blocked`` path with no safety
    marker is reported as ``attempted``, never as restraint.
    """
    for _step in _iter_safety_abstained_steps(path):
        return True
    return False


#: Where in a chain the withheld step sits. The STATUS token is deliberately
#: position-blind (one token, ``blocked``: this repo already carries three status
#: vocabularies and a compound token would deepen that), so the POSITION is a
#: separate fact the client-facing PROSE reads, because the two cases are
#: different stories and only one of them may be told as "the route stops at the
#: act we declined".
SAFETY_ABSTENTION_TERMINAL = "terminal"
SAFETY_ABSTENTION_MID_CHAIN = "mid_chain"


def safety_abstention_position(path: object) -> str:
    """Return where a path's withheld step sits, or ``""`` when none is marked.

    :data:`SAFETY_ABSTENTION_TERMINAL` when the LAST actionable step of the chain
    is the withheld one: the strongest and most precise story, because everything
    the route needed was established and only the disruptive final act was
    declined. :data:`SAFETY_ABSTENTION_MID_CHAIN` when the withheld step sits
    earlier: the hops beyond it were never walked, so narrating that route as one
    ADscan took to its end would overclaim.

    Structural / context hops (``MemberOf`` and friends) are not actionable
    steps, so a trailing one does not demote a terminal abstention to mid-chain.
    """
    if not isinstance(path, Mapping):
        return ""
    steps = path.get("steps")
    if not isinstance(steps, Sequence) or isinstance(steps, (str, bytes)):
        return ""
    actionable: list[Mapping] = [
        step
        for step in steps
        if isinstance(step, Mapping)
        and str(step.get("status") or "").strip().lower() != "structural"
    ]
    if not actionable:
        return ""
    withheld = [
        index
        for index, step in enumerate(actionable)
        if step_is_safety_abstention(step)
    ]
    if not withheld:
        return ""
    if withheld[-1] == len(actionable) - 1:
        return SAFETY_ABSTENTION_TERMINAL
    return SAFETY_ABSTENTION_MID_CHAIN


def path_safety_abstention_reason(path: object) -> str:
    """Return the client-safe reason a path was NOT executed for safety, or "".

    The step carries the engine-produced ``client_safe_reason`` (see
    :func:`safety_abstention_notes`); this returns it verbatim so a render can
    surface it without re-authoring the sentence. Resolution goes through
    :func:`client_safe_step_reason`, which screens out any engineering-register
    reason before it can reach a deliverable.
    """
    for step in _iter_safety_abstained_steps(path):
        return client_safe_step_reason(dict(step.get("details") or {}))
    return ""


def path_safety_abstention_relations(paths: Iterable[object] | None) -> list[str]:
    """Return the relationship names of every safety-abstained step in ``paths``.

    Feeds :func:`safety_abstention_disruption_clause`, which needs the set of
    techniques withheld rather than any one path.
    """
    relations: list[str] = []
    for path in paths or ():
        for step in _iter_safety_abstained_steps(path):
            relation = str(
                step.get("relation") or step.get("action") or step.get("edge") or ""
            ).strip()
            if relation:
                relations.append(relation)
    return relations
