"""Whether an attack step runs on its own, is decided live, or is only mapped.

ONE decision, :func:`execution_decision`, keyed on the run's ENTRY POINT and on
the active policy's execution mode. The gates (:mod:`adscan_core.scan_policy.gate`),
the consent rule for directory writes and the operator-decision relay all read
it, so no caller decides it on its own.

* **Interactive** (``adscan start``, the REPL): always ``attended``, whatever
  the policy says. A policy only subtracts there; an enabled step is still
  confirmed live. Unattended execution of attack steps is a PRO capability and
  lives in ``adscan ci``.
* **Unattended entry** (``adscan ci``, ``adscan execute``, the web worker that
  runs ``ci``): the policy's mode decides. ``unattended`` runs exactly the
  enabled steps without asking. ``attended`` asks the operator through the
  remote bridge when one is connected (the web), and otherwise maps the steps
  without executing any (``map_only``), which the coverage block discloses.
* **No policy**: :data:`DECISION_LEGACY`, today's behaviour, unchanged.

An unstamped shell is interactive: a new entry point cannot become unattended by
forgetting to declare itself. The entry is stamped once, by
:func:`stamp_run_entry`, at the ``ci`` and ``execute`` entry points.

Stdlib only; never imports ``adscan_internal``.

Design: docs/superpowers/specs/2026-11-04-scan-policy-two-groups-three-states.md § 4.
"""

from __future__ import annotations

from typing import Any

from adscan_core.scan_policy.policy import EXECUTION_ATTENDED, EXECUTION_UNATTENDED

#: Run entry points.
ENTRY_INTERACTIVE = "interactive"
ENTRY_CI = "ci"
ENTRY_EXECUTE = "execute"
#: ``adscan recheck`` at depth exercise / walk, run without an operator.
ENTRY_RECHECK = "recheck"
#: Entries that may run attack steps without a person at the keyboard.
UNATTENDED_ENTRIES: frozenset[str] = frozenset({ENTRY_CI, ENTRY_EXECUTE, ENTRY_RECHECK})

#: Shell attributes this module owns.
ATTR_RUN_ENTRY = "scan_run_entry"
ATTR_OPERATOR_PRESENT = "scan_operator_present"

#: Decisions.
DECISION_UNATTENDED = "unattended"
DECISION_ATTENDED = "attended"
DECISION_MAP_ONLY = "map_only"
DECISION_LEGACY = "legacy"

#: Operator-decision categories that are ATTACK-STEP decisions. Under an
#: unattended decision they are never relayed to a remote operator: the policy
#: already answered them.
ATTACK_STEP_DECISION_CATEGORIES: frozenset[str] = frozenset(
    {"attack_path_execution", "rodc_followup"}
)
#: The trust-scope question ("which trusted domains join this scan?"). The policy
#: answers it too: its ``scope_expansion`` setting says whether a trusted domain
#: is followed on its own (Lab / CTF) or stays out unless the request named it
#: (every real-environment policy). Relaying it to the web operator turned an
#: unattended Audit run into an attended one (release gate 14.0.0, Audit row).
TRUST_SCOPE_DECISION_CATEGORY = "trust_scope"
#: Every operator-decision category an unattended policy answers on its own.
POLICY_ANSWERED_DECISION_CATEGORIES: frozenset[str] = frozenset(
    {*ATTACK_STEP_DECISION_CATEGORIES, TRUST_SCOPE_DECISION_CATEGORY}
)

#: Client-facing statement of a run that mapped the attack steps without an
#: operator to decide them. Worded once; the coverage block and the CLI print it.
MAP_ONLY_STATEMENT = (
    "The policy leaves each attack step to an operator, and this run had none, so "
    "ADscan mapped the attack steps and executed none of them."
)
#: The same fact, announced when the run STARTS, so the operator learns before
#: the scan that no step will run rather than discovering it in the recap.
MAP_ONLY_START_STATEMENT = (
    "No operator is connected, and the scan policy asks one to approve each attack "
    "step, so this run maps the attack paths and executes none of their steps."
)

# ── The three reasons a mapped attack step did not run ──────────────────────
# Each has its own label on every surface (CLI, both reports, the web), and
# none of them may be read as a defence that held. Founder wording, 2026-11-08.
#
# 1. Excluded by the scan policy: the check is off. Label:
#    ``adscan_core.scan_policy.annotate.NOT_EXECUTED_BY_POLICY_LABEL``.
# 2. Awaiting approval: an attended policy, and nobody answered (no operator
#    connected, or the relayed decision timed out). Nobody decided "no", so it
#    is never worded as a decision.
# 3. Declined: an operator answered "no" during the scan, recorded with WHO and
#    WHEN.

#: Label printed beside a step a map-only run did not execute (reason 2).
MAP_ONLY_STEP_LABEL = "Mapped, awaiting approval: no operator was present to decide."
#: Step-note reason token of reason 2. The engine's refusal record uses the same
#: value (``scan_policy_enforcement.REASON_OPERATOR_REQUIRED``).
REASON_AWAITING_APPROVAL = "operator_required"
#: Step-note reason token of reason 3.
REASON_OPERATOR_DECLINED = "operator_declined"
#: Label of reason 3, before the who/when suffix (:func:`operator_declined_label`).
OPERATOR_DECLINED_LABEL = "Not executed: the operator chose not to run it."


#: A later step of the same route that never ran because an earlier step was
#: left awaiting approval (reason 2) or declined (reason 3). Worded like the
#: engagement-scope continuation (``depends on a step outside the engagement
#: scope``): it names what it waited on and never reads as a failure.
DEPENDS_ON_AWAITING_APPROVAL_LABEL = "Not executed: depends on a step awaiting approval."
DEPENDS_ON_DECLINED_STEP_LABEL = (
    "Not executed: depends on a step the operator chose not to run."
)


def dependent_step_label(reason: str) -> str:
    """The label of a step left unrun behind an operator decision, or ``""``.

    ``reason`` is the decision note's reason token (reason 2 or reason 3).
    """
    token = str(reason or "").strip().lower()
    if token == REASON_AWAITING_APPROVAL:
        return DEPENDS_ON_AWAITING_APPROVAL_LABEL
    if token == REASON_OPERATOR_DECLINED:
        return DEPENDS_ON_DECLINED_STEP_LABEL
    return ""


def awaiting_approval_label(timeout_seconds: int | None = None) -> str:
    """Reason 2's label; names the wait when a relayed decision timed out."""
    if timeout_seconds and timeout_seconds > 0:
        minutes = max(1, round(timeout_seconds / 60))
        unit = "minute" if minutes == 1 else "minutes"
        return f"Mapped, awaiting approval: no answer within {minutes} {unit}."
    return MAP_ONLY_STEP_LABEL


def operator_declined_label(declined_by: str = "", declined_at: str = "") -> str:
    """Reason 3's label with who declined and when, as recorded at the decision.

    ``declined_at`` is an ISO-8601 UTC stamp; only its date and minute are shown.
    """
    who = " ".join(str(declined_by or "").split())
    when = str(declined_at or "").strip()
    if len(when) >= 16 and when[10] == "T":
        when = f"{when[:10]} {when[11:16]} UTC"
    tail = ", ".join(part for part in (f"by {who}" if who else "", when) if part)
    if not tail:
        return OPERATOR_DECLINED_LABEL
    return f"{OPERATOR_DECLINED_LABEL[:-1]} ({tail})."


def stamp_run_entry(shell: Any, entry: str, *, operator_present: bool = False) -> None:
    """Record how this run was started. Called once, at the run's entry point.

    Args:
        shell: The run's shell.
        entry: :data:`ENTRY_CI`, :data:`ENTRY_EXECUTE` or :data:`ENTRY_INTERACTIVE`.
        operator_present: True when a person can answer a decision during the
            run (the web's remote bridge). Ignored for an interactive entry,
            where there is always one.
    """
    value = str(entry or ENTRY_INTERACTIVE).strip().lower()
    if value not in UNATTENDED_ENTRIES:
        value = ENTRY_INTERACTIVE
    try:
        setattr(shell, ATTR_RUN_ENTRY, value)
        setattr(
            shell,
            ATTR_OPERATOR_PRESENT,
            True if value == ENTRY_INTERACTIVE else bool(operator_present),
        )
    except Exception:  # noqa: BLE001 - a frozen test double stays interactive
        return


def run_entry(shell: Any) -> str:
    """The stamped entry point, :data:`ENTRY_INTERACTIVE` when never stamped."""
    value = getattr(shell, ATTR_RUN_ENTRY, None)
    return value if isinstance(value, str) and value in UNATTENDED_ENTRIES else ENTRY_INTERACTIVE


def operator_present(shell: Any) -> bool:
    """Whether a person can answer a decision during this run."""
    if run_entry(shell) == ENTRY_INTERACTIVE:
        return True
    return getattr(shell, ATTR_OPERATOR_PRESENT, False) is True


def decide(entry: str, *, operator: bool, policy_mode: str | None) -> str:
    """The pure decision table (spec § 4). ``policy_mode`` ``None`` = no policy."""
    if policy_mode is None:
        return DECISION_LEGACY
    if entry not in UNATTENDED_ENTRIES:
        return DECISION_ATTENDED
    if policy_mode == EXECUTION_UNATTENDED:
        return DECISION_UNATTENDED
    if policy_mode == EXECUTION_ATTENDED and operator:
        return DECISION_ATTENDED
    return DECISION_MAP_ONLY


def execution_decision(shell: Any) -> str:
    """How attack steps run in this run: unattended, attended, map-only or legacy."""
    from adscan_core.scan_policy.gate import active_policy  # noqa: PLC0415

    policy = active_policy(shell)
    mode: str | None = None
    if policy is not None:
        try:
            mode = str(policy.execution_mode)
        except Exception:  # noqa: BLE001 - a broken policy object is map-only
            mode = ""
    return decide(run_entry(shell), operator=operator_present(shell), policy_mode=mode)


def policy_asks_operator(shell: Any) -> bool:
    """True when the active policy's execution mode is ``attended`` ("Decide during scan").

    Read from the POLICY, not from :func:`execution_decision`: an interactive
    entry is always ``attended`` whatever the policy says, while this answers
    whether the policy itself asked for a person to decide each attack step.
    That is what makes the conservative choice the default of every attack-step
    decision (step through, never "run continuously"). False without a policy.
    """
    from adscan_core.scan_policy.gate import active_policy  # noqa: PLC0415

    policy = active_policy(shell)
    if policy is None:
        return False
    try:
        return str(policy.execution_mode) == EXECUTION_ATTENDED
    except Exception:  # noqa: BLE001 - a broken policy object asks, conservatively
        return True


def silence_must_not_run(shell: Any) -> bool:
    """True when an UNANSWERED attack-step decision must resolve to "do not run".

    Every decision except one an unattended policy already answered: with a
    policy in force, only the ``unattended`` decision lets a decision resolve to
    running something without a person saying so. Without a policy (legacy) the
    historical behaviour is kept. Callers use it for the no-answer branch only:
    a timed-out relay, or a run with nobody to ask.
    """
    try:
        decision = execution_decision(shell)
    except Exception:  # noqa: BLE001 - unknown decision: never run on silence
        return True
    return decision not in {DECISION_UNATTENDED, DECISION_LEGACY}


def suppress_remote_decision(shell: Any, category: str | None) -> bool:
    """True when a relayed operator decision must resolve locally instead.

    Under an unattended decision the policy answered every attack-step decision
    and the trust-scope question already; relaying either to the web operator
    would turn an unattended run into an attended one. The local resolution is
    the policy's own answer (the prompt helpers' non-interactive default).
    """
    if str(category or "") not in POLICY_ANSWERED_DECISION_CATEGORIES:
        return False
    try:
        return execution_decision(shell) == DECISION_UNATTENDED
    except Exception:  # noqa: BLE001 - keep relaying when the decision is unknown
        return False


__all__ = (
    "ATTACK_STEP_DECISION_CATEGORIES",
    "ATTR_OPERATOR_PRESENT",
    "ATTR_RUN_ENTRY",
    "DECISION_ATTENDED",
    "DECISION_LEGACY",
    "DECISION_MAP_ONLY",
    "DECISION_UNATTENDED",
    "ENTRY_CI",
    "ENTRY_EXECUTE",
    "ENTRY_RECHECK",
    "ENTRY_INTERACTIVE",
    "MAP_ONLY_START_STATEMENT",
    "MAP_ONLY_STATEMENT",
    "MAP_ONLY_STEP_LABEL",
    "OPERATOR_DECLINED_LABEL",
    "POLICY_ANSWERED_DECISION_CATEGORIES",
    "REASON_AWAITING_APPROVAL",
    "REASON_OPERATOR_DECLINED",
    "TRUST_SCOPE_DECISION_CATEGORY",
    "UNATTENDED_ENTRIES",
    "awaiting_approval_label",
    "decide",
    "DEPENDS_ON_AWAITING_APPROVAL_LABEL",
    "DEPENDS_ON_DECLINED_STEP_LABEL",
    "dependent_step_label",
    "operator_declined_label",
    "execution_decision",
    "operator_present",
    "policy_asks_operator",
    "run_entry",
    "silence_must_not_run",
    "stamp_run_entry",
    "suppress_remote_decision",
)
