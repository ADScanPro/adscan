"""Shared evidence rendering for credential candidates found in text fields.

A credential candidate is a token a detector (CredSweeper, a keyword rule) lifted
out of free-form text: an LDAP ``description``/``info`` attribute, a ``userPassword``
value, a file a scan read. The token alone is not reviewable. ``Str0ngP4ss!`` could
be the password of a service account or it could be a ticket code, a host name or a
licence key, and the only thing that tells the two apart is the sentence it was taken
from: ``Cuenta de conexion al AD de la aplicacion X Psswd: Str0ngP4ss!`` is an obvious
true positive, ``INC-4481 Str0ngP4ss!`` on its own is not.

Every surface that asks an operator to judge a candidate therefore renders it through
this module, so none of them can drop the discriminator again.

Three rules this module exists to keep:

* The source text is UNCONTROLLED input from a client directory, so it never reaches
  Rich as a markup string. Everything here is built as :class:`rich.text.Text` with
  explicit style spans, which sidesteps markup parsing entirely: a description holding
  ``[/opt/adscan/x]`` would otherwise raise ``MarkupError`` and abort the command.
* The token stays in cleartext (the operator needs to read it) and is wrapped with
  ``mark_sensitive`` so telemetry scrubs it. Only the token span is marked, never the
  surrounding sentence.
* When a value is too long to print whole, the window is CENTRED on the match. A blind
  head truncation can cut away the very token under review.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Optional, Sequence

from rich.console import Group
from rich.table import Table
from rich.text import Text

from adscan_core.rich_output import print_panel
from adscan_core.theme import COLOR_CRIMSON, COLOR_MUTED, COLOR_SAGE
from adscan_internal.rich_output import mark_sensitive

# Characters of source text rendered around a match before the window is bounded.
# Generous on purpose: the sentence IS the evidence, so clipping it to a tweet
# defeats the point. At 100 columns this is roughly three wrapped lines.
DEFAULT_EVIDENCE_BUDGET = 240

# Full evidence lines rendered per (account, field) group in the summary panel.
# One long description can produce several matches; repeating the same sentence
# once per match floods the panel without adding information.
_MAX_FULL_EVIDENCE_PER_GROUP = 3

# A non-interactive run resolves every prompt to its default, so the panel is
# read later from a log rather than acted on at the terminal. It stays (the
# evidence is why a saved credential was saved) but tightened, so a domain with
# dozens of hits does not bury the rest of the scan output.
_NONINTERACTIVE_MAX_ENTRIES = 10
_NONINTERACTIVE_BUDGET = 160

# ML probability at or above which the detector's own score is worth showing as a
# confidence bar. Below it the score says more about the model (trained on code and
# config, not on prose) than about the candidate, so the rule name is the better signal.
_HIGH_CONFIDENCE = 0.70

_ELLIPSIS = "…"


@dataclass(frozen=True)
class CredentialCandidateEvidence:
    """One credential candidate together with the text it was extracted from.

    Attributes:
        account: Principal the field belongs to (sAMAccountName, or a file owner).
        field_label: Name of the field the hit came from, as the operator knows it
            (``description``, ``info``, ``userPassword``, ``unixUserPassword``).
        token: The extracted candidate secret, verbatim.
        source_value: The COMPLETE, untruncated value of that field. Falling back to a
            detector's context line is acceptable only when the real value is
            genuinely unavailable.
        rule: Name of the detector rule that fired, for false-positive triage.
        ml_probability: The detector's confidence, when it produced one.
    """

    account: str
    field_label: str
    token: str
    source_value: str
    rule: str = ""
    ml_probability: Optional[float] = None


def _normalize_source(value: str) -> str:
    """Collapse newlines and runs of whitespace so the evidence reads as one sentence."""
    return " ".join(str(value or "").split())


def _locate(haystack: str, needle: str) -> int:
    """Return the index of ``needle`` in ``haystack``, case-insensitively as a fallback."""
    if not needle:
        return -1
    index = haystack.find(needle)
    if index >= 0:
        return index
    return haystack.lower().find(needle.lower())


def _snap_to_word_start(source: str, start: int, limit: int) -> int:
    """Advance ``start`` to the next word boundary, so a window does not open mid-word."""
    space = source.find(" ", start, min(len(source), start + limit))
    return space + 1 if space >= 0 else start


def _snap_to_word_end(source: str, end: int, limit: int) -> int:
    """Retreat ``end`` to the previous word boundary, so a window does not close mid-word."""
    space = source.rfind(" ", max(0, end - limit), end)
    return space if space > 0 else end


def evidence_window(
    source_value: str,
    token: str,
    *,
    budget: int = DEFAULT_EVIDENCE_BUDGET,
) -> tuple[str, int, bool, bool]:
    """Bound a source value to ``budget`` characters without losing the match.

    Args:
        source_value: The full field value.
        token: The extracted candidate.
        budget: Maximum characters of source text to keep.

    Returns:
        ``(window, match_index, clipped_left, clipped_right)`` where ``match_index`` is
        the offset of the token inside ``window``, or ``-1`` when the token could not
        be located in the source text. The window ALWAYS contains the whole token, even
        when the token alone exceeds the budget: the discriminator is never clipped.
    """
    source = _normalize_source(source_value)
    needle = _normalize_source(token)
    budget = max(16, int(budget))

    index = _locate(source, needle)
    if len(source) <= budget:
        return source, index, False, False
    if index < 0:
        return source[:budget], -1, False, True

    end_of_match = index + len(needle)
    slack = budget - len(needle)
    if slack <= 0:
        start, end = index, end_of_match
    else:
        start = max(0, index - slack // 2)
        end = min(len(source), start + budget)
        start = max(0, min(start, end - budget))
        end = max(end, end_of_match)
        # Open and close the window on word boundaries when one is close by: a
        # window starting mid-word reads as corrupted text. Never move a boundary
        # across the match itself.
        snap_limit = max(4, min(24, slack // 3))
        snapped_start = _snap_to_word_start(source, start, snap_limit)
        if snapped_start <= index:
            start = snapped_start
        snapped_end = _snap_to_word_end(source, end, snap_limit)
        if snapped_end >= end_of_match:
            end = snapped_end
    return source[start:end], index - start, start > 0, end < len(source)


def build_evidence_text(
    evidence: CredentialCandidateEvidence,
    *,
    budget: int = DEFAULT_EVIDENCE_BUDGET,
    body_style: str = COLOR_MUTED,
    token_style: str = f"bold {COLOR_CRIMSON}",
) -> Text:
    """Render the source text with the matched token highlighted inside it.

    The result is a :class:`rich.text.Text`, so the uncontrolled source text is never
    parsed as Rich markup. The token is wrapped with ``mark_sensitive`` and left in
    cleartext.
    """
    window, index, clipped_left, clipped_right = evidence_window(
        evidence.source_value, evidence.token, budget=budget
    )
    rendered = Text(no_wrap=False, overflow="fold")
    if clipped_left:
        rendered.append(_ELLIPSIS, style=COLOR_MUTED)

    token = _normalize_source(evidence.token)
    if index < 0 or not token:
        # The detector reported a token we cannot find in the field value (a
        # normalised or decoded form, typically). Show the source text as-is rather
        # than inventing a highlight the operator cannot verify.
        rendered.append(window or "(empty value)", style=body_style)
    else:
        rendered.append(window[:index], style=body_style)
        rendered.append(
            mark_sensitive(window[index : index + len(token)], "password"),
            style=token_style,
        )
        rendered.append(window[index + len(token) :], style=body_style)

    if clipped_right:
        rendered.append(_ELLIPSIS, style=COLOR_MUTED)
    return rendered


def format_rule_label(rule: str, ml_probability: Optional[float]) -> Text:
    """Render the detector signal an operator triages a false positive with.

    A score at or above the high-confidence mark renders as a bar, because there the
    number means something. Below it the rule name carries more: the natural-language
    rules fire deterministically on a keyword and score near zero by design, and a
    ``0.01`` next to a match on the word ``password`` reads as "ignore me" when it is
    the strongest signal on the panel.
    """
    rule_name = str(rule or "").strip()
    if ml_probability is not None and ml_probability >= _HIGH_CONFIDENCE:
        filled = round(float(ml_probability) * 4)
        bar = "█" * filled + "░" * (4 - filled)
        return Text(f"{bar} {ml_probability:.2f}", style="bold green")
    if not rule_name:
        return Text("-", style=COLOR_MUTED)
    short = rule_name.replace("DOC ", "").replace("DOC_", "").replace("_", " ").title()
    style = (
        "bold yellow" if ml_probability is None or ml_probability > 0 else COLOR_MUTED
    )
    return Text(short, style=style)


def _headline(
    evidence: CredentialCandidateEvidence,
    *,
    account_style: str = COLOR_SAGE,
) -> Text:
    line = Text(no_wrap=False, overflow="fold")
    line.append(mark_sensitive(evidence.account, "user"), style=f"bold {account_style}")
    line.append(" \u00b7 ", style=COLOR_MUTED)
    line.append(evidence.field_label, style=COLOR_MUTED)
    line.append("    ")
    line.append(
        mark_sensitive(evidence.token, "password"), style=f"bold {COLOR_CRIMSON}"
    )
    return line


def _entry_grid(
    evidence: CredentialCandidateEvidence,
    *,
    index_label: str,
    evidence_body: Text,
) -> Table:
    grid = Table.grid(expand=True, padding=(0, 1))
    grid.add_column(width=4, justify="right", style=COLOR_MUTED)
    grid.add_column(ratio=1, overflow="fold")
    grid.add_column(justify="right", no_wrap=True)
    grid.add_row(
        index_label,
        _headline(evidence),
        format_rule_label(evidence.rule, evidence.ml_probability),
    )
    grid.add_row("", evidence_body, "")
    return grid


def build_candidate_evidence_block(
    evidence: CredentialCandidateEvidence,
    *,
    index_label: str = "",
    budget: int = DEFAULT_EVIDENCE_BUDGET,
) -> Table:
    """Build the two-line block one candidate occupies: headline, then its evidence."""
    return _entry_grid(
        evidence,
        index_label=index_label,
        evidence_body=build_evidence_text(evidence, budget=budget),
    )


def render_credential_candidates_panel(
    candidates: Sequence[CredentialCandidateEvidence],
    *,
    title: str,
    interactive: bool = True,
    max_entries: int = 30,
    budget: int = DEFAULT_EVIDENCE_BUDGET,
) -> None:
    """Render every candidate as a headline plus the text it was taken from.

    Entries keep caller order. When one field value produced several matches, the
    source text is printed in full for the first few and the rest are summarised, so a
    long description holding five hits does not print the same sentence five times.
    """
    entries = [item for item in candidates if str(item.token or "").strip()]
    if not entries:
        return

    max_entries = max(1, int(max_entries))
    if not interactive:
        max_entries = min(max_entries, _NONINTERACTIVE_MAX_ENTRIES)
        budget = min(budget, _NONINTERACTIVE_BUDGET)
    shown = entries[:max_entries]

    seen_per_group: dict[tuple[str, str], int] = {}
    blocks: list[Any] = []
    for position, item in enumerate(shown, start=1):
        group_key = (item.account.strip().lower(), item.field_label.strip().lower())
        seen = seen_per_group.get(group_key, 0)
        seen_per_group[group_key] = seen + 1
        if seen < _MAX_FULL_EVIDENCE_PER_GROUP:
            body = build_evidence_text(item, budget=budget)
        else:
            body = Text(
                f"↳ further match in the same {item.field_label} value, shown above",
                style=COLOR_MUTED,
            )
        blocks.append(_entry_grid(item, index_label=str(position), evidence_body=body))
        if position < len(shown):
            blocks.append(Text(""))

    if len(entries) > max_entries:
        blocks.append(Text(""))
        blocks.append(
            Text(
                f"{len(entries) - max_entries} further candidate(s) not shown here. "
                "Each one is still reviewed below.",
                style=COLOR_MUTED,
            )
        )

    header = Text(no_wrap=False, overflow="fold")
    header.append(
        f"{len(entries)} candidate(s) matched a credential pattern. ",
        style=f"bold {COLOR_CRIMSON}",
    )
    header.append(
        "The highlighted span is what fired; the text around it is what tells a real "
        "secret apart from a ticket code or a host name.",
        style=COLOR_MUTED,
    )

    print_panel(
        Group(header, Text(""), *blocks),
        title=f"[bold {COLOR_CRIMSON}]{title}[/bold {COLOR_CRIMSON}]",
        title_align="left",
        border_style=COLOR_CRIMSON,
    )


def render_candidate_decision_evidence(
    evidence: CredentialCandidateEvidence,
    *,
    position: int,
    total: int,
    budget: int = DEFAULT_EVIDENCE_BUDGET,
) -> None:
    """Render one candidate's evidence immediately before its decision prompt.

    Keeps the discriminator on screen at the moment of the decision, so the operator
    never has to scroll back to the summary panel to answer the question.
    """
    print_panel(
        Group(build_candidate_evidence_block(evidence, index_label="", budget=budget)),
        title=f"[{COLOR_MUTED}]Candidate {position} of {total}[/{COLOR_MUTED}]",
        title_align="left",
        border_style=COLOR_MUTED,
        padding=(0, 2),
    )


def format_candidate_prompt(evidence: CredentialCandidateEvidence) -> str:
    """Build the short question line that follows the evidence panel.

    The evidence lives in the panel above, so the prompt stays one readable line:
    questionary renders the question beside its own selector and a paragraph there
    pushes the options off screen.
    """
    account = mark_sensitive(evidence.account, "user")
    token = mark_sensitive(evidence.token, "password")
    return (
        f"{account} ({evidence.field_label}): {token}\nHow do you want to handle this?"
    )


def iter_candidate_review(
    candidates: Iterable[CredentialCandidateEvidence],
    *,
    interactive: bool,
    budget: int = DEFAULT_EVIDENCE_BUDGET,
) -> Iterable[tuple[int, CredentialCandidateEvidence, str]]:
    """Yield ``(position, evidence, prompt)`` per candidate, rendering the evidence panel.

    The panel is rendered only when ``interactive`` is true: a non-interactive run
    resolves every prompt to its default, so a per-candidate panel there is output
    nobody reads, in a log everybody greps.
    """
    items = list(candidates)
    total = len(items)
    for position, item in enumerate(items, start=1):
        if interactive:
            render_candidate_decision_evidence(
                item, position=position, total=total, budget=budget
            )
        yield position, item, format_candidate_prompt(item)
