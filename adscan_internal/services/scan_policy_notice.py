"""Tell the operator, once and calmly, when the scan policy skipped something.

The single seam every policy skip goes through. The copy lives in
:mod:`adscan_core.scan_policy.skip_notice`; this module decides WHEN and HOW it
is shown:

* :func:`notify_policy_skip` is called at the moment the scan reaches a check
  the policy keeps off. The first skip of a check prints one dim line naming
  what was skipped, the policy and the ``policy include`` command; repeats of
  the same check print nothing and are counted, except when the operator asked
  for that step directly (an attack path they chose), where a short reminder
  line answers the request.
* :func:`announce_phase_skip` is the phase / subphase gate's explanation: it
  tells a policy skip from a scan-configuration skip, so a policy skip is never
  worded "disabled in scan configuration".
* :func:`print_policy_skip_recap` prints the "Skipped by your policy" recap at
  the end of the scan and clears the run's ledger.

Per-step lines are shown only in an interactive run that is not quiet; a
non-interactive run (``adscan ci``) writes them to the debug log only, and the
recap states the whole set once. Nothing here changes a decision: the gates in
:mod:`adscan_core.scan_policy.gate` decide, this module only explains.

Every line goes through the shared console (``print_instruction`` /
``print_table``), so it reaches the session recording and survives a
``LiveSession`` deferred flush. Dynamic values are rendered as ``Text`` pieces,
never as markup.
"""

from __future__ import annotations

from typing import Any, Iterable

from rich.markup import escape
from rich.table import Table
from rich.text import Text

from adscan_core import telemetry
from adscan_core.rich_output import (
    BRAND_COLORS,
    print_exception,
    print_info,
    print_info_debug,
    print_instruction,
    print_table,
)
from adscan_core.scan_policy import gate
from adscan_core.scan_policy import skip_notice as copy
from adscan_core.scan_policy.registry import CheckRegistry, load_registry

#: Shell attribute holding this run's skip ledger (``{key: entry}``).
LEDGER_ATTR = "_scan_policy_skip_notices"
#: Legacy line for a phase or step the scan configuration disabled.
CONFIG_SKIP_LINE = "{label} skipped (disabled in scan configuration)."
#: Glyph of a skipped step, shared with ``print_step_status``.
SKIP_GLYPH = "○"
#: Recap rows shown before the remainder is summarised.
RECAP_MAX_ROWS = 12
#: Indent of a command printed on its own line under its subject (narrow
#: terminals): it lines up with the subject text after the glyph.
_RECAP_COMMAND_INDENT = 2

CAUSE_POLICY = "policy"
CAUSE_CONFIG = "config"

_STYLE_SUBJECT = "dim bold"
_STYLE_BODY = "dim"
_STYLE_COMMAND = BRAND_COLORS["info"]


# ── environment ──────────────────────────────────────────────────────────────
def _registry(shell: Any) -> CheckRegistry:
    reg = getattr(shell, "scan_policy_registry", None)
    return reg if isinstance(reg, CheckRegistry) else load_registry()


def _is_non_interactive(shell: Any) -> bool:
    from adscan_internal.interaction import is_non_interactive  # noqa: PLC0415

    return bool(is_non_interactive(shell))


def _is_quiet(shell: Any) -> bool:
    """True under ``--output quiet``/``json`` or ``set explain_level quiet``."""
    try:
        from adscan_core.output._modes import suppress_rich  # noqa: PLC0415

        if suppress_rich():
            return True
    except Exception:  # noqa: BLE001 - output mode is best-effort
        pass
    try:
        from adscan_internal.services.didactic_service import (  # noqa: PLC0415
            ExplainLevel,
        )

        return ExplainLevel.coerce(getattr(shell, "explain_level", None)) == ExplainLevel.OFF
    except Exception:  # noqa: BLE001
        return False


def _shows_step_lines(shell: Any) -> bool:
    return not _is_non_interactive(shell) and not _is_quiet(shell)


def _ledger(shell: Any) -> dict[str, dict[str, Any]]:
    ledger = getattr(shell, LEDGER_ATTR, None)
    if isinstance(ledger, dict):
        return ledger
    ledger = {}
    try:
        setattr(shell, LEDGER_ATTR, ledger)
    except Exception:  # noqa: BLE001 - a read-only shell still gets the line
        pass
    return ledger


def skip_ledger(shell: Any) -> list[dict[str, Any]]:
    """This run's recorded skips, oldest first (``notice`` + ``count``)."""
    return list(_ledger(shell).values())


# ── rendering ────────────────────────────────────────────────────────────────
_ROLE_STYLES = {"subject": _STYLE_SUBJECT, "body": _STYLE_BODY, "command": _STYLE_COMMAND}


#: Columns before the notice text: ``print_instruction``'s indent plus the glyph.
_LEAD_COLUMNS = 5


def _console_width() -> int:
    try:
        from adscan_core.output._state import get_console  # noqa: PLC0415

        return int(get_console().width or 0)
    except Exception:  # noqa: BLE001 - width only shapes the wrap
        return 0


def _render_line(groups: list[list[tuple[str, str]]], *, width: int | None = None) -> Text:
    """The styled notice. Sentences stay whole: one that does not fit on the
    current line starts an aligned new one, so a wrap never splits the command."""
    width = _console_width() if width is None else width
    line = Text(f"{SKIP_GLYPH} ", style=_STYLE_BODY)
    column = _LEAD_COLUMNS
    for index, group in enumerate(groups):
        size = sum(len(text) for text, _role in group)
        if index:
            if width and column + 1 + size > width:
                line.append("\n" + " " * _LEAD_COLUMNS, style=_STYLE_BODY)
                column = _LEAD_COLUMNS
            else:
                line.append(" ", style=_STYLE_BODY)
                column += 1
        for text, role in group:
            line.append(text, style=_ROLE_STYLES.get(role, _STYLE_BODY))
        column += size
    return line


def _emit(shell: Any, groups: list[list[tuple[str, str]]], *, visible: bool) -> None:
    plain = copy.plain_text(copy.flatten(groups))
    if visible:
        print_instruction(_render_line(groups))
    # The debug log always keeps the line, so a non-interactive run can be read
    # after the fact and an interactive one keeps a timestamped record.
    print_info_debug(f"scan-policy skip: {escape(plain)}")


# ── the seam ─────────────────────────────────────────────────────────────────
def notify_policy_skip(
    shell: Any,
    check_ids: str | Iterable[str],
    *,
    subject: str = "",
    key: str = "",
    target: str = "",
    operator_request: bool = False,
    announce: bool = True,
    inline: bool = True,
    awaiting_approval: bool = False,
) -> None:
    """Explain one policy skip. Never raises; never changes a decision.

    Args:
        shell: The pentest shell.
        check_ids: The check id, or for a phase the check ids, the policy kept off.
        subject: What was skipped, in the operator's words (the check title when
            empty).
        key: Collapse key (the first check id when empty).
        target: The object the step would have acted on, when there is one.
        operator_request: True when the operator asked for this step directly
            (an attack path they chose). A repeat then prints a short line
            instead of nothing, so the request is never answered by silence.
        announce: False records the skip for the recap without a line (a
            listing that already labels the item as excluded).
        inline: False counts the skip but prints no line, for a surface that
            shows the same explanation itself (an attack-path run's step result).
        awaiting_approval: The policy ENABLES the step; it did not run because
            the policy asks an operator to approve each step and none was present.
            Recapped as awaiting approval, never as an exclusion.
    """
    try:
        policy = gate.active_policy(shell)
        if policy is None or not hasattr(policy, "dependency_excluded"):
            return
        ids = [check_ids] if isinstance(check_ids, str) else list(check_ids or ())
        notice = copy.build_skip_notice(
            policy,
            ids,
            subject=subject,
            key=key,
            registry=_registry(shell),
            awaiting_approval=awaiting_approval,
        )
        ledger = _ledger(shell)
        entry = ledger.get(notice.key)
        if entry is None:
            entry = {"notice": notice, "count": 0}
            ledger[notice.key] = entry
        if not announce:
            return
        entry["count"] = int(entry.get("count") or 0) + 1
        visible = inline and _shows_step_lines(shell)
        marked_target = ""
        if target:
            from adscan_internal.rich_output import mark_sensitive  # noqa: PLC0415

            marked_target = mark_sensitive(target, "node")
        if not entry.get("shown"):
            _emit(shell, copy.notice_groups(notice, target=marked_target), visible=visible)
            entry["shown"] = True
            return
        if operator_request:
            _emit(shell, copy.repeat_groups(notice, target=marked_target), visible=visible)
    except Exception as exc:  # noqa: BLE001 - an explanation never breaks the scan
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def policy_skip_explanation(shell: Any, check_id: str, *, subject: str = "") -> dict[str, str]:
    """The skip notice in the attack-path run's explanation shape (``{}`` without a policy)."""
    try:
        policy = gate.active_policy(shell)
        if policy is None or not hasattr(policy, "dependency_excluded"):
            return {}
        ids = [check_id] if check_id else []
        built = copy.build_skip_notice(
            policy, ids, subject=subject, key=check_id or subject, registry=_registry(shell)
        )
        from adscan_core.scan_policy.execution import (  # noqa: PLC0415
            ENTRY_INTERACTIVE,
            run_entry,
        )

        return copy.explanation_fields(
            built, shell_command=run_entry(shell) == ENTRY_INTERACTIVE
        )
    except Exception as exc:  # noqa: BLE001 - wording only
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return {}


def policy_skip_cause(shell: Any, phase_id: str, subphase_id: str | None = None) -> str:
    """Why a phase or subphase gate said no: :data:`CAUSE_POLICY` or :data:`CAUSE_CONFIG`."""
    try:
        from adscan_internal.services.scan_phases import (  # noqa: PLC0415
            _scan_policy_allows_phase,
            _scan_policy_allows_subphase,
        )

        if not _scan_policy_allows_phase(shell, phase_id):
            return CAUSE_POLICY
        if subphase_id and not _scan_policy_allows_subphase(shell, phase_id, subphase_id):
            return CAUSE_POLICY
    except Exception as exc:  # noqa: BLE001 - wording only; never breaks the gate
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    return CAUSE_CONFIG


def _phase_check_ids(shell: Any, phase_id: str, subphase_id: str | None) -> list[str]:
    reg = _registry(shell)
    policy = gate.active_policy(shell)
    effective = getattr(policy, "effective_ids", frozenset())
    if subphase_id:
        check = reg.check_for_subphase(phase_id, subphase_id)
        if check is not None and check.check_id not in effective:
            return [check.check_id]
    return [c.check_id for c in reg.checks_for_phase(phase_id) if c.check_id not in effective]


def announce_phase_skip(
    shell: Any,
    phase_id: str,
    *,
    label: str,
    subphase_id: str | None = None,
    config_line: bool = True,
) -> str:
    """Explain why a phase or subphase gate kept ``label`` from running.

    Call it in the branch where ``phase_is_enabled`` / ``subphase_is_enabled``
    returned False. A policy skip gets the policy notice; any other cause keeps
    the scan-configuration line (unless ``config_line`` is False, for a gate
    that has always skipped silently on a configuration disable).

    Returns:
        :data:`CAUSE_POLICY` or :data:`CAUSE_CONFIG`, so a caller that renders a
        step status can pick :func:`step_detail` for it.
    """
    cause = policy_skip_cause(shell, phase_id, subphase_id)
    if cause == CAUSE_POLICY:
        ids = _phase_check_ids(shell, phase_id, subphase_id)
        key = f"phase:{phase_id}.{subphase_id}" if subphase_id else f"phase:{phase_id}"
        if len(ids) == 1:
            key = ids[0]
        notify_policy_skip(shell, ids, subject=label, key=key)
    elif config_line:
        print_info(CONFIG_SKIP_LINE.format(label=escape(label)))
    return cause


def step_detail(cause: str) -> str:
    """``print_step_status`` details for a skip of ``cause``."""
    return copy.STEP_DETAIL_POLICY if cause == CAUSE_POLICY else copy.STEP_DETAIL_CONFIG


# ── end-of-scan recap ────────────────────────────────────────────────────────
def build_recap_table(shell: Any) -> Table | None:
    """The recap table for this run's skips, or ``None`` when there are none."""
    entries = [e for e in skip_ledger(shell) if isinstance(e.get("notice"), copy.SkipNotice)]
    if not entries:
        return None
    policy = gate.active_policy(shell)
    first: copy.SkipNotice = entries[0]["notice"]
    policy_name = first.policy_name
    if policy is not None and hasattr(policy, "definition"):
        from adscan_core.scan_policy.policy import policy_display_name  # noqa: PLC0415

        policy_name = policy_display_name(policy.definition)
    rows = entries[:RECAP_MAX_ROWS]
    subjects: list[Text] = []
    for entry in rows:
        notice: copy.SkipNotice = entry["notice"]
        subject = Text(f"{SKIP_GLYPH} ", style=_STYLE_BODY)
        subject.append(notice.subject, style=_STYLE_SUBJECT)
        times = copy.times_label(int(entry.get("count") or 0))
        if times:
            subject.append(f" ({times})", style=_STYLE_BODY)
        subjects.append(subject)
    statuses = [Text(e["notice"].report_status) for e in rows]
    commands = [Text(copy.recap_command(e["notice"])) for e in rows]
    # Priority collapse: on a narrow terminal the report-status column goes
    # first; the subject and the command it takes to turn it on always stay.
    width = _console_width()

    def _span(*cols: list[Text]) -> int:
        return sum(max(len(t.plain) for t in col) + 2 for col in cols)

    show_status = not width or _span(subjects, statuses, commands) <= width
    # A command is something the operator copies, so it is never cut or
    # broken mid-token. When even the subject + command columns do not fit,
    # each command moves to its own full-width line under its subject.
    stacked = bool(width) and not show_status and _span(subjects, commands) > width
    table = Table(
        title=Text(copy.recap_title(policy_name), style="bold"),
        title_justify="left",
        show_header=False,
        box=None,
        pad_edge=False,
        padding=(0, 2, 0, 0),
    )
    if stacked:
        table.add_column(overflow="fold")
        # One decision for the whole table, so the rows read alike.
        inline_status = _span(subjects, statuses) <= width
        for subject, status, entry in zip(subjects, statuses, rows):
            line = subject.copy()
            if inline_status:
                line.append("  ")
                line.append_text(Text(status.plain, style=_STYLE_BODY))
            table.add_row(line)
            notice_: copy.SkipNotice = entry["notice"]
            lines = list(notice_.commands) or [copy.recap_command(notice_)]
            for index, command in enumerate(lines):
                if index:
                    table.add_row(Text(" " * _RECAP_COMMAND_INDENT + "or", style=_STYLE_BODY))
                table.add_row(
                    Text(" " * _RECAP_COMMAND_INDENT + command, style=_STYLE_COMMAND)
                )
    else:
        table.add_column(no_wrap=True)
        if show_status:
            table.add_column(style=_STYLE_BODY, no_wrap=True)
        table.add_column(style=_STYLE_COMMAND, no_wrap=True)
        for subject, status, command in zip(subjects, statuses, commands):
            table.add_row(*((subject, status, command) if show_status else (subject, command)))
    hidden = len(entries) - RECAP_MAX_ROWS
    if hidden > 0:
        table.caption = Text(copy.recap_more(hidden), style=_STYLE_BODY)
        table.caption_justify = "left"
    return table


def print_policy_skip_recap(shell: Any) -> None:
    """Print the "Skipped by your policy" recap once, then clear the ledger.

    Silent when nothing was skipped, and under ``--output quiet``/``json``.
    Never raises.
    """
    try:
        table = build_recap_table(shell)
        if table is None:
            return
        try:
            from adscan_core.output._modes import suppress_rich  # noqa: PLC0415

            suppressed = suppress_rich()
        except Exception:  # noqa: BLE001
            suppressed = False
        if not suppressed:
            print_table(table, spacing="both")
        for entry in skip_ledger(shell):
            notice = entry.get("notice")
            if isinstance(notice, copy.SkipNotice):
                print_info_debug(
                    escape(
                        f"scan-policy recap: {notice.subject} | {notice.report_status} | "
                        f"{copy.recap_command(notice)} | count={entry.get('count')}"
                    )
                )
        _ledger(shell).clear()
    except Exception as exc:  # noqa: BLE001 - the recap never breaks the summary
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


__all__ = (
    "CAUSE_CONFIG",
    "CAUSE_POLICY",
    "CONFIG_SKIP_LINE",
    "LEDGER_ATTR",
    "RECAP_MAX_ROWS",
    "SKIP_GLYPH",
    "announce_phase_skip",
    "build_recap_table",
    "notify_policy_skip",
    "policy_skip_cause",
    "policy_skip_explanation",
    "print_policy_skip_recap",
    "skip_ledger",
    "step_detail",
)
