"""The operator notice for a step the scan policy kept from running.

In an interactive scan the policy only subtracts (see
:mod:`adscan_core.scan_policy.execution`): an enabled step is still confirmed
live, and a disabled one is neither run nor asked. That second half is silent by
nature, so an operator who does not remember switching something off reads the
gap as a defect. This module words the explanation ONCE, for every place the
engine skips a check because of the policy:

* what was skipped, in the operator's words;
* that the active policy turned it off, by name;
* that the weakness still reaches the report, when it does (a graph attack step
  is mapped whether or not it runs);
* the exact ``policy include`` command that turns it back on, with the real,
  tab-completable selector (the root dependency when the check is off only
  because something it needs is off).

It also builds the end-of-scan recap rows. The report status column reuses the
coverage SSOT (:data:`adscan_core.scan_policy.coverage.OUTCOME_LABELS`), so the
recap and the deliverable describe an excluded check in the same words.

Pure and stdlib only: the renderer, the per-run ledger and the collapse of
repeats live in ``adscan_internal.services.scan_policy_notice``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from adscan_core.scan_policy.coverage import (
    OUTCOME_LABELS,
    OUTCOME_MAPPED_NOT_EXECUTED,
    outcome_for,
)
from adscan_core.scan_policy.execution import MAP_ONLY_STEP_LABEL
from adscan_core.scan_policy.model import CheckDefinition
from adscan_core.scan_policy.policy import policy_display_name
from adscan_core.scan_policy.registry import CheckRegistry, load_registry
from adscan_core.scan_policy.resolve import ResolvedScanPolicy

#: The REPL verb that turns a check or a family back on.
INCLUDE_VERB = "policy include"
#: The REPL command that lists the whole policy.
SHOW_COMMAND = "policy show"
#: Most selectors a single notice names before it points at ``policy show``.
MAX_COMMANDS = 2
#: Title of the end-of-scan recap (``{policy}`` is the policy's display name).
RECAP_TITLE = "Skipped by your policy '{policy}'"
#: Recap footer when rows were left out.
RECAP_MORE = "And {count} more. Run '" + SHOW_COMMAND + "' to see every exclusion."
#: Recap hint for a step awaiting approval: an operator, not a policy change.
AWAITING_APPROVAL_HINT = "run it with an operator present (adscan start, or the web console)"
#: Report status of a skip whose check the registry does not know.
UNKNOWN_REPORT_STATUS = "Not run, excluded by the policy"
#: The REPL command that supplies the client's cleanup account.
CLEANUP_ACCOUNT_COMMAND = "cleanup_credential set"
#: ``print_step_status`` details for a step skipped by each cause.
STEP_DETAIL_POLICY = "Off in the scan policy"
STEP_DETAIL_CONFIG = "Disabled in scan configuration"


@dataclass(frozen=True)
class SkipNotice:
    """Everything the operator is told about one policy skip.

    Attributes:
        key: Collapse key; repeats of one key are one notice.
        subject: What was skipped, in the operator's words.
        policy_name: Display name of the active policy.
        commands: ``policy include`` commands that turn it back on, in order.
            Empty when no single command does (the notice then points at
            ``policy show``).
        blocker: Title of the check that is really off, when the subject is off
            only because it needs that check. Empty otherwise.
        report_status: How the report shows the excluded check (coverage SSOT).
        still_mapped: True when the report still maps the weakness.
        awaiting_approval: True when the policy ENABLES the step and it did not
            run only because the policy asks an operator to approve each step
            and none was present (reason 2). Never worded as an exclusion: the
            check is on, and no policy change would run it.
    """

    key: str
    subject: str
    policy_name: str
    commands: tuple[str, ...]
    blocker: str = ""
    report_status: str = UNKNOWN_REPORT_STATUS
    still_mapped: bool = False
    awaiting_approval: bool = False
    #: The policy enables the step but leaves it out because undoing its change
    #: needs a cleanup account and none is supplied. The fix is the account, not
    #: a policy change.
    needs_cleanup_account: bool = False


# ── selector resolution ──────────────────────────────────────────────────────
def root_check_id(resolved: ResolvedScanPolicy, check_id: str) -> str:
    """The check that is actually switched off behind ``check_id``.

    A check that is off only because something it needs is off cannot be turned
    on directly: ``policy include`` on it leaves it off. Follow the dependency
    chain to the check the policy itself excluded.
    """
    current = str(check_id)
    seen: set[str] = set()
    deps = resolved.dependency_excluded
    while current in deps and current not in seen:
        seen.add(current)
        current = str(deps[current])
    return current


def _check_selector(check: CheckDefinition | None) -> str:
    """The selector ``policy include`` accepts for one check, or ``""``."""
    if check is None or check.locked_state:
        return ""
    if check.selectable and not check.is_paired_detection:
        return check.check_id
    return f"family:{check.family}" if check.family else ""


def enable_selectors(
    resolved: ResolvedScanPolicy,
    check_ids: Iterable[str],
    registry: CheckRegistry | None = None,
) -> tuple[str, ...]:
    """The fewest selectors that turn every check in ``check_ids`` back on.

    One root check: its own id (an id beats a family or the base). Several roots
    in at most :data:`MAX_COMMANDS` families, none of them disabled by its own
    id: those families. Otherwise each root's id, up to :data:`MAX_COMMANDS`;
    past that, nothing, and the notice points at ``policy show``.
    """
    reg = registry or load_registry()
    roots: list[CheckDefinition] = []
    seen: set[str] = set()
    pending = list(check_ids)
    while pending:
        root = root_check_id(resolved, pending.pop(0))
        if root in seen:
            continue
        seen.add(root)
        check = reg.get(root)
        if check is None:
            return ()
        if root in resolved.revert_excluded_ids:
            # Off for want of a cleanup account: no policy command turns it on.
            return ()
        roots.append(check)
        # A root the policy itself excluded can ALSO need a check that is off
        # (a follow-up trigger whose action another check owns): including the
        # root alone would leave it off, so its unmet requirements are roots too.
        pending.extend(r for r in check.requires if r not in resolved.effective_ids)
    if not roots:
        return ()
    if len(roots) == 1:
        selector = _check_selector(roots[0])
        return (selector,) if selector else ()
    families = list(dict.fromkeys(c.family for c in roots))
    disabled_by_id = set(resolved.definition.disabled)
    if (
        all(families)
        and len(families) <= MAX_COMMANDS
        and not any(c.check_id in disabled_by_id for c in roots)
    ):
        return tuple(f"family:{family}" for family in families)
    selectors = [s for s in (_check_selector(c) for c in roots) if s]
    if len(selectors) != len(roots) or len(selectors) > MAX_COMMANDS:
        return ()
    return tuple(dict.fromkeys(selectors))


def _report_status(checks: list[CheckDefinition]) -> tuple[str, bool]:
    outcomes = [outcome_for(c) for c in checks]
    if not outcomes:
        return UNKNOWN_REPORT_STATUS, False
    first = outcomes[0]
    mapped = all(o == OUTCOME_MAPPED_NOT_EXECUTED for o in outcomes)
    return OUTCOME_LABELS.get(first, UNKNOWN_REPORT_STATUS), mapped


def build_skip_notice(
    resolved: ResolvedScanPolicy,
    check_ids: Iterable[str],
    *,
    subject: str = "",
    key: str = "",
    registry: CheckRegistry | None = None,
    awaiting_approval: bool = False,
) -> SkipNotice:
    """Build the notice for one skip.

    Args:
        resolved: The active policy.
        check_ids: The check (or, for a phase, the checks) the policy kept off.
        subject: What was skipped, in the operator's words. Defaults to the
            first check's title.
        key: Collapse key. Defaults to the first check id.
        registry: The check registry (the committed snapshot when omitted).
        awaiting_approval: The step is enabled and waits for an operator who was
            not present (reason 2), not excluded.
    """
    reg = registry or load_registry()
    ids = [str(c) for c in check_ids if str(c or "").strip()]
    checks = [c for c in (reg.get(i) for i in ids) if c is not None]
    title = subject or (checks[0].title if checks else (ids[0] if ids else "This step"))
    blocker = ""
    if len(ids) == 1:
        root = root_check_id(resolved, ids[0])
        if root != ids[0]:
            root_check = reg.get(root)
            blocker = root_check.title if root_check is not None else root
    report_status, still_mapped = _report_status(checks)
    if ids and all(i in resolved.revert_excluded_ids for i in ids):
        return SkipNotice(
            key=key or ids[0],
            subject=title,
            policy_name=policy_display_name(resolved.definition),
            commands=(CLEANUP_ACCOUNT_COMMAND,),
            report_status=report_status,
            still_mapped=still_mapped,
            needs_cleanup_account=True,
        )
    if awaiting_approval:
        return SkipNotice(
            key=key or (ids[0] if ids else title),
            subject=title,
            policy_name=policy_display_name(resolved.definition),
            commands=(),
            report_status=MAP_ONLY_STEP_LABEL,
            still_mapped=True,
            awaiting_approval=True,
        )
    return SkipNotice(
        key=key or (ids[0] if ids else title),
        subject=title,
        policy_name=policy_display_name(resolved.definition),
        commands=tuple(f"{INCLUDE_VERB} {s}" for s in enable_selectors(resolved, ids, reg)),
        blocker=blocker,
        report_status=report_status,
        still_mapped=still_mapped,
    )


# ── copy ─────────────────────────────────────────────────────────────────────
# Every sentence below is client-facing CLI text. Each function returns the
# pieces separately so the renderer can style the command without parsing it.


def _quoted(command: str) -> str:
    return f"'{command}'"


def reason_sentence(notice: SkipNotice) -> str:
    """Why it was skipped, one sentence ending in a period."""
    if notice.awaiting_approval:
        return (
            f"The scan policy '{notice.policy_name}' asks an operator to approve "
            "each attack step, and none was present to decide."
        )
    if notice.needs_cleanup_account:
        return (
            "Undoing its change needs a cleanup account, and none is supplied for this "
            f"scan, so the scan policy '{notice.policy_name}' leaves it out."
        )
    if notice.blocker:
        return f"It needs {notice.blocker}, which the scan policy '{notice.policy_name}' turns off."
    return f"The scan policy '{notice.policy_name}' turns it off."


#: Sentence added when the report still maps the weakness of a skipped step.
STILL_MAPPED_SENTENCE = "The report still maps the weakness."


def enable_lead(notice: SkipNotice) -> str:
    """The words before the command(s), or the whole sentence when there is none."""
    if not notice.commands:
        return f"Run {_quoted(SHOW_COMMAND)} to review the policy."
    if notice.needs_cleanup_account:
        return "Supply one with "
    return "Turn that on with " if notice.blocker else "Turn it on with "


Part = tuple[str, str]


def notice_groups(notice: SkipNotice, *, target: str = "") -> list[list[Part]]:
    """The full first-time notice as sentences of ``(text, role)`` pieces.

    Roles: ``subject``, ``body`` and ``command``. A renderer keeps each sentence
    whole and may start any sentence on a new line; joined with single spaces
    the sentences read as one line, for example::

        Kerberoasting skipped. The scan policy 'Audit' turns it off. The report
        still maps the weakness. Turn it on with 'policy include step:kerberoasting'.
    """
    subject = f"{notice.subject} on {target}" if target else notice.subject
    groups: list[list[Part]] = [
        [(subject, "subject"), (" skipped.", "body")],
        [(reason_sentence(notice), "body")],
    ]
    if notice.still_mapped:
        groups.append([(STILL_MAPPED_SENTENCE, "body")])
    enable: list[Part] = [(enable_lead(notice), "body")]
    if notice.commands:
        for index, command in enumerate(notice.commands):
            if index:
                enable.append((" or ", "body"))
            enable.append((_quoted(command), "command"))
        enable.append((".", "body"))
    groups.append(enable)
    return groups


def repeat_groups(notice: SkipNotice, *, target: str = "") -> list[list[Part]]:
    """The short notice for a repeat the operator asked for directly."""
    subject = f"{notice.subject} on {target}" if target else notice.subject
    return [
        [(subject, "subject"), (" skipped.", "body")],
        [(f"The scan policy '{notice.policy_name}' turns it off.", "body")],
    ]


def flatten(groups: Iterable[Iterable[Part]]) -> list[Part]:
    """Join sentence groups into one line of pieces (single spaces between)."""
    out: list[Part] = []
    for index, group in enumerate(groups):
        if index:
            out.append((" ", "body"))
        out.extend(group)
    return out


def notice_parts(notice: SkipNotice, *, target: str = "") -> list[Part]:
    """:func:`notice_groups` as one line of pieces."""
    return flatten(notice_groups(notice, target=target))


def repeat_parts(notice: SkipNotice, *, target: str = "") -> list[Part]:
    """:func:`repeat_groups` as one line of pieces."""
    return flatten(repeat_groups(notice, target=target))


#: ``reason_code`` of a step the policy kept from running, in a run's explanation.
EXPLANATION_REASON_CODE = "excluded_by_scan_policy"


#: How to turn a step back on when the run has no shell to type into (the web).
NO_SHELL_ENABLE_SENTENCE = "Include it in the scan policy to run it."


def explanation_fields(notice: SkipNotice, *, shell_command: bool = True) -> dict[str, str]:
    """The notice in the attack-path run's explanation shape.

    A step the policy keeps off is a choice, not a failure: the run shows it as
    "Not run" with these lines instead of "stopped without a recorded result".
    ``shell_command`` False words the way back without the REPL command, for a
    run started from ``adscan ci`` or the web, where nobody types it.
    """
    if notice.blocker:
        headline = (
            f"This step needs {notice.blocker}, which the scan policy "
            f"'{notice.policy_name}' turns off."
        )
    else:
        headline = f"The scan policy '{notice.policy_name}' turns this step off."
    if not shell_command:
        next_step = NO_SHELL_ENABLE_SENTENCE
    elif notice.commands:
        next_step = enable_lead(notice) + " or ".join(_quoted(c) for c in notice.commands) + "."
    else:
        next_step = enable_lead(notice)
    return {
        "code": "",
        "reason_code": EXPLANATION_REASON_CODE,
        "headline": headline,
        "detail": STILL_MAPPED_SENTENCE if notice.still_mapped else "",
        "next_step": next_step,
    }


def plain_text(parts: Iterable[Part]) -> str:
    """Join notice pieces into the plain line (logs and tests)."""
    return "".join(text for text, _role in parts)


def recap_title(policy_name: str) -> str:
    """Title of the end-of-scan recap."""
    return RECAP_TITLE.format(policy=policy_name)


def recap_command(notice: SkipNotice) -> str:
    """The recap's enable column: the command(s), or the ``policy show`` hint."""
    if notice.awaiting_approval:
        # Nothing to switch on: the step is enabled. It needs someone to approve it.
        return AWAITING_APPROVAL_HINT
    if not notice.commands:
        return SHOW_COMMAND
    return " or ".join(notice.commands)


def recap_more(count: int) -> str:
    """Footer line when the recap left ``count`` rows out."""
    return RECAP_MORE.format(count=count)


def times_label(count: int) -> str:
    """``""`` for a single skip, ``"3 times"`` for repeats."""
    return f"{count} times" if count > 1 else ""


__all__ = (
    "EXPLANATION_REASON_CODE",
    "INCLUDE_VERB",
    "MAX_COMMANDS",
    "NO_SHELL_ENABLE_SENTENCE",
    "RECAP_MORE",
    "RECAP_TITLE",
    "SHOW_COMMAND",
    "STEP_DETAIL_CONFIG",
    "STEP_DETAIL_POLICY",
    "STILL_MAPPED_SENTENCE",
    "SkipNotice",
    "UNKNOWN_REPORT_STATUS",
    "build_skip_notice",
    "enable_lead",
    "enable_selectors",
    "explanation_fields",
    "flatten",
    "notice_groups",
    "notice_parts",
    "plain_text",
    "reason_sentence",
    "recap_command",
    "recap_more",
    "recap_title",
    "repeat_groups",
    "repeat_parts",
    "root_check_id",
    "times_label",
)
