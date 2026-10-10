"""Ask the operator for the ENS scope of the system, and never guess it.

A compliance section states which Anexo II measures are EXIGIBLE for the system
that was assessed, and that answer comes from the system's security category.
The category is a client decision (RD 311/2022, Anexo I): it belongs to the
system, not to the command that renders a report, so ADscan reads it and never
derives it from the data it collected.

This module is the one interactive way to supply it. Two entry points share it:
``adscan deliver`` runs it once, in the sync prefill, when the operator selected
ENS and the workspace carries no declaration; the REPL verb ``compliance_scope``
runs it on demand so a scope can be declared or replaced without a re-render.
One implementation, so the two can never drift into two flows that resemble
each other.

What it will not do
-------------------
It will not trap the operator who does not have the categorisation to hand.
Every question carries an exit that costs one keypress, and taking it is free:
the resolver then answers with the common core of Anexo II, the measures
required at every category, which is a true and non-empty answer. A wizard you
cannot leave is one the operator fills in at random, and an invented scope is
worse than none.

It also offers no "all five dimensions at the same level" shortcut. That is the
frequent real case and exactly the trap this product refuses elsewhere: a
comfortable click that enters data nobody checked. Five keypresses are not a
burden; a wrongly declared scope is.

Nothing here computes a category, a count or a label. The derived category is
``EnsScope.category`` (Anexo I, apdos. 4.1 y 4.2), the totals come from
``EnsScopeResolution.as_header()``, and the file is written by
``write_compliance_scope_declaration``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

from adscan_core.reporting.compliance_scope_declaration import (
    COMPLIANCE_SCOPE_ENV,
    compliance_scope_path,
    load_ens_scope,
    write_compliance_scope_declaration,
)
from adscan_core.reporting.ens_applicability import (
    DIMENSION_NAMES,
    DIMENSION_ORDER,
    ENS_VERSION,
    PROFILE_CCN_STIC_890A,
    PROFILE_CCN_STIC_890C,
    PROFILE_GENERAL,
    PROFILE_OTHER_SPECIFIC,
    PROFILES,
    Dimension,
    EnsScope,
    Level,
    ProfileTableStatus,
    resolve_ens_applicability,
    resolve_profile,
)
from adscan_core.rich_output import (
    confirm_ask,
    get_console,
    print_info,
    print_panel,
    print_warning,
    prompt_ask,
    questionary_select_index,
)

#: The framework key whose selection makes the ENS scope relevant.
ENS_FRAMEWORK_KEY = "ens"

#: The key the declaration date is written under. Additive: the resolver ignores
#: it, and it is a better record than the file's mtime, which a copy resets.
_DECLARED_AT_KEY = "declared_at"

#: The order the profiles are offered in: the general profile, then the two
#: transcribed Perfiles de Cumplimiento Específico, then the honest catch-all.
#: Everything else the engine recognises (the superseded CCN-STIC 883 family) is
#: appended after those, because it is a profile an operator should be able to
#: declare truthfully and be told why no verdict follows, not one to put in
#: front of them.
_PROFILE_OFFER_ORDER: tuple[str, ...] = (
    PROFILE_GENERAL,
    PROFILE_CCN_STIC_890A,
    PROFILE_CCN_STIC_890C,
    PROFILE_OTHER_SPECIFIC,
)


def profile_choices() -> tuple[tuple[str, str], ...]:
    """The profiles to offer, with the label each one reads as.

    Public so the flag-driven path lists the same profiles in the same order:
    the general profile first, then the two transcribed specific ones, and the
    superseded family last rather than alphabetically in front of the one almost
    every system declares.

    Built from the engine registry rather than listed here. The three profiles
    this wizard used to hard-code were names nobody had checked against a
    published document, and two of them matched none: a list maintained beside
    the registry drifts from it, and this one drifted into inventions.
    """
    keys = list(_PROFILE_OFFER_ORDER) + [
        key for key in PROFILES if key not in _PROFILE_OFFER_ORDER
    ]
    choices: list[tuple[str, str]] = []
    for key in keys:
        profile = PROFILES.get(key)
        if profile is None:
            continue
        label = profile.name
        if profile.max_level is not None:
            label = f"{label} (covers {profile.max_level.value.upper()} only)"
        elif not profile.table_populated:
            label = f"{label} (no applicability table held)"
        choices.append((key, label))
    return tuple(choices)

#: The levels a dimension can carry, each with the plain-language harm test that
#: separates it from its neighbours. The operator in front of this prompt is a
#: pentester, not the client's security officer, so the test is the question
#: being answered rather than a citation to look up.
_LEVEL_CHOICES: tuple[tuple[Level, str], ...] = (
    (Level.BAJO, "BAJO: limited harm, absorbed inside the organisation"),
    (
        Level.MEDIO,
        "MEDIO: serious harm to the organisation, or harm to people outside it",
    ),
    (Level.ALTO, "ALTO: very serious or irreparable harm, or harm to many people"),
    (
        Level.NOT_AFFECTED,
        "Not affected: this system has nothing to protect in this dimension",
    ),
)

#: The label of the exit, identical at every question so it is learned once.
_LEAVE_UNDECLARED_LABEL = "Leave the scope undeclared (I do not have the client's categorisation)"

#: What each dimension actually asks, phrased as the harm question of Anexo I
#: apartado 3 rather than as its legal definition.
_DIMENSION_QUESTIONS: dict[Dimension, str] = {
    Dimension.C: (
        "Someone who is not authorised reads this information. "
        "How much harm does the disclosure cause?"
    ),
    Dimension.I: (
        "The information is altered and nobody notices. "
        "How much harm does working from the altered version cause?"
    ),
    Dimension.T: (
        "Nobody can reconstruct who did what in the system. "
        "How much harm does losing that record cause?"
    ),
    Dimension.A: (
        "Someone acts in the system as a person or a service they are not. "
        "How much harm does the impersonation cause?"
    ),
    Dimension.D: (
        "The service stops and stays down. How much harm does the outage cause?"
    ),
}

_SAVE_TO_WORKSPACE = "Save it to the workspace, so later renders reuse it"
_USE_FOR_THIS_RUN = "Use it for this run only, without writing it to the workspace"
_DISCARD_DECLARATION = "Discard it and leave the scope undeclared"

_TOTAL_QUESTIONS = 1 + len(DIMENSION_ORDER)


@dataclass(frozen=True)
class ScopeDeclarationOutcome:
    """What the wizard produced.

    Attributes:
        scope: The declared scope, or ``None`` when the operator left without
            declaring one.
        persisted: Whether the declaration was written into the workspace.
        path: The declaration file the resolver will read, when one was written
            (the workspace file, or the run-scoped file behind
            ``ADSCAN_COMPLIANCE_SCOPE``).
    """

    scope: Optional[EnsScope] = None
    persisted: bool = False
    path: Optional[Path] = None

    @property
    def declared(self) -> bool:
        return self.scope is not None


def workspace_has_declared_ens_scope(workspace_dir: Any) -> bool:
    """Whether this workspace already carries a usable ENS declaration."""
    return load_ens_scope(workspace_dir) is not None


def declaration_date(workspace_dir: Any) -> str:
    """The date the declaration carries, or the file's own date, or empty."""
    from adscan_core.reporting.compliance_scope_declaration import (
        read_compliance_scope_declaration,
    )

    declaration = read_compliance_scope_declaration(workspace_dir) or {}
    stamped = str(declaration.get(_DECLARED_AT_KEY) or "").strip()
    if stamped:
        return stamped
    target = compliance_scope_path(workspace_dir)
    try:
        if target is not None and target.is_file():
            return datetime.fromtimestamp(target.stat().st_mtime).date().isoformat()
    except OSError:
        pass
    return ""


def render_declared_scope(
    scope: EnsScope,
    *,
    title: str = "ENS scope of the assessed system",
    declared_on: str = "",
) -> None:
    """State a scope as the report's own scope header states it.

    Every figure here is read off :meth:`EnsScopeResolution.as_header`, so this
    panel and the rendered document can never disagree on one.
    """
    header = resolve_ens_applicability(scope).as_header()
    lines = [
        f"[bold]Category {header['category_label']}[/bold], "
        f"derived from the five levels ({header['category_derivation_citation']}).",
        "",
    ]
    for entry in header["dimension_levels"]:  # type: ignore[union-attr]
        name = f"{entry['name']} ({entry['dimension']})"
        lines.append(f"  {name:<26} [bold]{entry['label']}[/bold]")
    lines.append("")
    if header.get("profile_applies") is False:
        lines.append(
            "[bold]No measure is exigible under the declared profile.[/bold]"
        )
        lines.append(str(header.get("profile_out_of_scope_reason") or ""))
    else:
        lines.append(
            f"{header['required_total']} of {header['measures_total']} Anexo II "
            "measures are exigible under this scope."
        )
        not_applicable = int(header["not_applicable_by_table_total"]) + int(
            header["not_applicable_by_dimension_total"]
        )
        if not_applicable:
            lines.append(
                f"{not_applicable} are outside it, and are reported as not "
                "applicable rather than as a gap."
            )
    lines.append("")
    lines.append(
        f"Normative version {header['ens_version']}, "
        f"{header.get('profile_name') or header['profile']}."
    )
    if scope.system_label:
        lines.append(f"System covered: {scope.system_label}")
    if declared_on:
        lines.append(f"Declared on {declared_on}.")
    note = str(header.get("note") or "").strip()
    if note:
        lines.append("")
        lines.append(note)
    print_panel("\n".join(lines), title=title, title_align="left")


def _common_core_total() -> int:
    """How many measures the undeclared answer still covers."""
    return int(resolve_ens_applicability(None).as_header()["common_core_total"])


def _print_intro() -> None:
    print_panel(
        "\n".join(
            [
                "The compliance section maps your findings onto the Anexo II measures "
                "that are exigible for this system, so it needs the system's security "
                "category. ADscan never infers it: the category is the client's own "
                "categorisation decision (RD 311/2022, Anexo I).",
                "",
                f"{_TOTAL_QUESTIONS} questions: the compliance profile, then the level "
                "of each of the five security dimensions. The category follows from "
                "those five levels, so you do not choose it.",
                "",
                "No categorisation to hand? Take the last option at any question. The "
                f"report then maps the common core of {_common_core_total()} measures "
                "required at every category, and says so.",
            ]
        ),
        title="Declare the ENS scope",
        title_align="left",
    )


def _print_question_header(
    *, index: int, heading: str, question: str, progress: str
) -> None:
    """Print the compact block that sits above one select.

    Deliberately not a panel: five framed questions in a row is chrome, and the
    content is what the operator is reading.
    """
    console = get_console()
    console.print(
        f"\n[bold]{heading}[/bold]  [dim]question {index} of {_TOTAL_QUESTIONS}[/dim]"
    )
    console.print(f"[dim]{question}[/dim]")
    if progress:
        console.print(f"[dim]{progress}[/dim]")


def _progress_line(
    levels: dict[Dimension, Level], profile: str = PROFILE_GENERAL
) -> str:
    """The live derived category, so the operator sees the sixth value fall out.

    It also carries the profile's own verdict on the answers so far. An answer
    that takes the system outside the declared profile is worth seeing on the
    next question rather than at the end: the operator can still correct the
    level, or go back and declare the general profile, while the questions are
    in front of them.
    """
    declared = [
        f"{dimension.value} {_level_label(levels[dimension])}"
        for dimension in DIMENSION_ORDER
        if dimension in levels
    ]
    if not declared:
        return ""
    scope = EnsScope(dimension_levels=dict(levels), profile=profile)
    category = scope.category
    label = category.value.upper() if category else "none yet"
    line = f"So far: {', '.join(declared)}. Derived category: {label}."
    if scope.profile_out_of_scope_reason:
        line = f"{line} Already outside the declared profile."
    return line


def _level_label(level: Level) -> str:
    return "not affected" if level is Level.NOT_AFFECTED else level.value.upper()


def _select(
    *,
    title: str,
    labels: Sequence[str],
    default_idx: int,
    shell: object | None,
) -> Optional[int]:
    """One select, with the exit appended as its last option.

    Returns the chosen index into ``labels``, or ``None`` for the exit and for a
    cancelled prompt. The default lands on the exit for every question except
    the profile, so a stray Enter declines to declare instead of inventing a
    level: declining is free and recoverable, a fabricated category is not.
    """
    options = list(labels) + [_LEAVE_UNDECLARED_LABEL]
    chosen = questionary_select_index(
        title=title,
        options=options,
        default_idx=default_idx,
        shell=shell,
    )
    if chosen is None or chosen >= len(labels):
        return None
    return chosen


def _ask_profile(shell: object | None) -> Optional[str]:
    _print_question_header(
        index=1,
        heading="Compliance profile",
        question=(
            "Which profile does the system certify under? The general profile "
            "applies unless the client certifies under a specific one."
        ),
        progress="",
    )
    choices = profile_choices()
    chosen = _select(
        title="Compliance profile:",
        labels=[label for _token, label in choices],
        default_idx=0,
        shell=shell,
    )
    if chosen is None:
        return None
    token = choices[chosen][0]
    _announce_profile(token)
    return token


def _announce_profile(token: str) -> None:
    """Say what the picked profile is and is not, before the five questions.

    The precondition is the half worth saying here. A specific profile can hold
    a full applicability table and still not reach the system, because the
    guide that publishes it states which systems it covers, and the levels that
    decide it are the five answers about to be given. Finding that out
    afterwards is avoidable, so the ceiling is stated now.
    """
    profile = resolve_profile(token)
    if profile is None or profile.key == PROFILE_GENERAL:
        return

    if profile.table_status is ProfileTableStatus.SUPERSEDED_BY_VERSION:
        print_warning(profile.superseded_note)
        return

    if not profile.table_populated:
        print_warning(
            "This build does not hold the applicability table for that profile. "
            "The report will state the declared profile and that no applicability "
            "verdict follows from it, rather than reading the general table in "
            "its place."
        )
        return

    if profile.max_level is not None:
        print_info(
            f"{profile.name} covers a system valued "
            f"{profile.max_level.value.upper()} in every security dimension. "
            "Answer any of the next five questions above that and the system "
            "falls outside this profile, and the report will say so and name "
            "the general profile of Anexo II as what applies instead."
        )
    if profile.scope_statement:
        print_info(profile.scope_statement)


def _ask_dimensions(
    shell: object | None, profile: str = PROFILE_GENERAL
) -> Optional[dict[Dimension, Level]]:
    levels: dict[Dimension, Level] = {}
    for offset, dimension in enumerate(DIMENSION_ORDER):
        _print_question_header(
            index=offset + 2,
            heading=f"{DIMENSION_NAMES[dimension]} ({dimension.value})",
            question=_DIMENSION_QUESTIONS[dimension],
            progress=_progress_line(levels, profile),
        )
        labels = [label for _level, label in _LEVEL_CHOICES]
        chosen = _select(
            title=f"{DIMENSION_NAMES[dimension]} level:",
            labels=labels,
            # The exit, not a level: see _select.
            default_idx=len(labels),
            shell=shell,
        )
        if chosen is None:
            return None
        levels[dimension] = _LEVEL_CHOICES[chosen][0]
    return levels


def _ask_system_label(shell: object | None) -> str:
    """The system this declaration covers. Optional, and never invented.

    Anexo II apartado 2.2 admits a declaration below the whole system, and the
    ITS de Auditoría expects the audited object to be named. A blank answer is a
    real answer: naming it after the workspace would be a fabrication.
    """
    answer = prompt_ask(
        "Which system or subsystem does this declaration cover? (optional, Enter to skip)",
        default="",
        shell=shell,
        prefill_default=False,
    )
    return str(answer or "").strip()


def declaration_payload(scope: EnsScope) -> dict[str, Any]:
    """The persisted block, in the shape the loader parses back.

    Public so the flag-driven declaration path writes the byte-identical shape
    this wizard writes. One payload builder, so the two surfaces cannot drift
    into two files that resemble each other.
    """
    return {
        "ens_version": scope.ens_version,
        "profile": scope.profile,
        "dimensions": {
            dimension.value: scope.level(dimension).value
            for dimension in DIMENSION_ORDER
            if scope.level(dimension) is not Level.NOT_AFFECTED
        },
        "compensatory_measures": sorted(scope.compensatory_measures),
        "system": scope.system_label or "",
        _DECLARED_AT_KEY: date.today().isoformat(),
    }


def _persist_for_this_run(scope: EnsScope) -> Optional[Path]:
    """Write a run-scoped declaration and point the documented override at it.

    Uses the same writer as the workspace case, so there is one JSON shape and
    no hand-built file, and the same ``ADSCAN_COMPLIANCE_SCOPE`` override the
    container and CI already read. The holder directory carries the process id
    so two concurrent renders cannot read each other's declaration.
    """
    from adscan_core.pal.paths import scratch_dir

    try:
        holder = Path(scratch_dir()) / f"adscan-compliance-scope-{os.getpid()}"
        written = write_compliance_scope_declaration(holder, declaration_payload(scope))
    except OSError as exc:
        print_warning(
            "Could not stage the declaration for this run "
            f"({type(exc).__name__}); the scope stays undeclared."
        )
        return None
    os.environ[COMPLIANCE_SCOPE_ENV] = str(written)
    return written


def _announce_undeclared() -> None:
    print_info(
        "Scope left undeclared. The compliance section maps the common core of "
        f"{_common_core_total()} Anexo II measures required at every category, and "
        "states that the category was not declared. Declare it later with the "
        "compliance_scope command, or point --compliance-scope at the client's "
        "written categorisation."
    )


def run_ens_scope_wizard(
    *,
    workspace_dir: Any = None,
    shell: object | None = None,
    show_intro: bool = True,
) -> ScopeDeclarationOutcome:
    """Ask for the ENS scope and persist the answer. The single implementation.

    Args:
        workspace_dir: Workspace to write the declaration into. ``None`` keeps
            the run-scoped path as the only option.
        shell: Threaded into every prompt helper so its non-interactive
            predicate sees the session.
        show_intro: Whether to print the framing panel first. The REPL verb
            keeps it; a second pass inside one command does not need it.

    Returns:
        The outcome. An undeclared outcome is a legitimate result, not a
        failure, and the caller renders the common core for it.
    """
    if show_intro:
        _print_intro()

    profile = _ask_profile(shell)
    if profile is None:
        _announce_undeclared()
        return ScopeDeclarationOutcome()

    levels = _ask_dimensions(shell, profile)
    if levels is None:
        _announce_undeclared()
        return ScopeDeclarationOutcome()

    system_label = _ask_system_label(shell)
    scope = EnsScope(
        dimension_levels={
            dimension: level
            for dimension, level in levels.items()
            if level is not Level.NOT_AFFECTED
        },
        profile=profile,
        ens_version=ENS_VERSION,
        compensatory_measures=frozenset(),
        system_label=system_label or None,
    )

    render_declared_scope(scope, title="Declared ENS scope")
    if scope.category is None:
        print_warning(
            "No dimension carries a level, so no category follows. A system that "
            "handles no information and provides no service has nothing to map."
        )
    if scope.profile_out_of_scope_reason:
        print_warning(
            f"{scope.profile_out_of_scope_reason} Keeping this declaration is "
            "legitimate, and the report will state that the profile does not "
            "reach the system rather than reading its table anyway. To have "
            "the measures scoped instead, declare the general profile of "
            "Anexo II."
        )

    options = [_SAVE_TO_WORKSPACE, _USE_FOR_THIS_RUN, _DISCARD_DECLARATION]
    if workspace_dir is None:
        options = [_USE_FOR_THIS_RUN, _DISCARD_DECLARATION]
    choice = questionary_select_index(
        title="Keep this declaration?",
        options=options,
        default_idx=0,
        shell=shell,
    )
    selected = options[choice] if choice is not None else _DISCARD_DECLARATION

    if selected == _DISCARD_DECLARATION:
        _announce_undeclared()
        return ScopeDeclarationOutcome()

    if selected == _SAVE_TO_WORKSPACE:
        try:
            written = write_compliance_scope_declaration(
                workspace_dir, declaration_payload(scope)
            )
        except OSError as exc:
            print_warning(
                f"Could not write the declaration ({type(exc).__name__}); "
                "falling back to this run only."
            )
            return ScopeDeclarationOutcome(
                scope=scope, persisted=False, path=_persist_for_this_run(scope)
            )
        print_info(f"Declaration saved to {written}.")
        return ScopeDeclarationOutcome(scope=scope, persisted=True, path=written)

    written = _persist_for_this_run(scope)
    if written is None:
        return ScopeDeclarationOutcome()
    print_info("Declaration kept for this run only, not written to the workspace.")
    return ScopeDeclarationOutcome(scope=scope, persisted=False, path=written)


def declare_or_review_ens_scope(
    *, workspace_dir: Any = None, shell: object | None = None
) -> ScopeDeclarationOutcome:
    """Show the declared scope if there is one, then offer to change it.

    This is what both entry points call. An already-declared workspace is never
    re-asked: it is shown, and replacing it is an explicit choice.
    """
    existing = load_ens_scope(workspace_dir)
    if existing is None:
        return run_ens_scope_wizard(workspace_dir=workspace_dir, shell=shell)

    render_declared_scope(existing, declared_on=declaration_date(workspace_dir))
    if confirm_ask("Use this declared scope?", default=True):
        return ScopeDeclarationOutcome(
            scope=existing, persisted=True, path=compliance_scope_path(workspace_dir)
        )
    return run_ens_scope_wizard(workspace_dir=workspace_dir, shell=shell)


def maybe_declare_ens_scope(
    *,
    workspace_dir: Any,
    frameworks: Iterable[str],
    engagement_type: Optional[str],
    shell: object | None = None,
    prompts_prefilled: bool = False,
) -> Optional[ScopeDeclarationOutcome]:
    """Run the wizard from a report entry point, when it is the right moment.

    Returns ``None`` when nothing was asked. The guards, in order:

    * ENS was not selected, so the scope changes nothing in the output.
    * A ``ctf`` workspace: a lab has no regulatory regime, so no categorisation.
    * Non-interactive, or the prompts were already resolved by the sync prefill
      (``deliver`` resolves frameworks twice, and only the first pass runs
      outside the event loop where a prompt can display at all).

    A workspace that already carries a declaration is never re-asked the six
    questions: it is shown what the report will map against, with one
    confirmation that defaults to using it, because stating the scope the paid
    deliverable was built on is worth a line even when nothing changes.
    """
    from adscan_internal.interaction import is_non_interactive
    from adscan_internal.services.compliance_scope import CTF_ENGAGEMENT

    if ENS_FRAMEWORK_KEY not in {str(key).strip().lower() for key in frameworks}:
        return None
    if engagement_type == CTF_ENGAGEMENT:
        return None
    if is_non_interactive() or prompts_prefilled:
        return None
    return declare_or_review_ens_scope(workspace_dir=workspace_dir, shell=shell)


__all__ = (
    "ENS_FRAMEWORK_KEY",
    "ScopeDeclarationOutcome",
    "declaration_date",
    "declaration_payload",
    "declare_or_review_ens_scope",
    "maybe_declare_ens_scope",
    "profile_choices",
    "render_declared_scope",
    "run_ens_scope_wizard",
    "workspace_has_declared_ens_scope",
)
