"""The ``compliance_scope`` verb: read the declared ENS scope, or declare one.

Three surfaces, one verb, and which one runs is decided by what the operator
supplied rather than by where the verb was typed:

* **No arguments, interactive terminal** -> the six-question wizard
  (:func:`~adscan_internal.cli.compliance_scope_wizard.declare_or_review_ens_scope`),
  unchanged. A person in front of a prompt gets the prompt.
* **No arguments, non-interactive** -> the READ. It states the declaration on
  file, or states that none is on file and what the report maps instead. Both
  are legitimate states of a workspace, so both exit 0.
* **Flags** -> the DECLARATION, with no prompt at all, in either context. This
  is what makes the verb usable from ``adscan execute``, which is
  non-interactive by construction and would otherwise run a wizard whose every
  answer auto-resolves to "decline".

Why the flag path refuses rather than completes
-----------------------------------------------
The whole subsystem exists so that a compliance section never asserts
exigibility nobody declared. A flag surface that filled in a missing dimension,
coerced an unrecognised level, or silently wrote a declaration that reads back
as undeclared would reintroduce exactly that, one layer lower down. So every
incomplete or unrecognised input is REFUSED with a non-zero exit and nothing is
written: here the operator asked to declare something, and it did not happen.

The one thing the flag path will never accept is the category. It is derived
from the five levels (RD 311/2022, Anexo I, apdos. 4.1 y 4.2) and
:class:`~adscan_core.reporting.ens_applicability.EnsScope` has no field for it,
so a contradictory declaration is unexpressible. Keeping it unexpressible is
the point: a flag that set it would hand an operator the one input that is not
theirs to give.
"""

from __future__ import annotations

import os
import shlex
from pathlib import Path
from typing import Any, Optional

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
    PROFILE_GENERAL,
    Dimension,
    EnsScope,
    Level,
    resolve_ens_applicability,
    resolve_profile,
)
from adscan_core.rich_output import print_error, print_info, print_panel, print_warning

#: Exit codes. ``0`` covers every legitimate outcome, including an undeclared
#: workspace; ``2`` is reserved for "you asked to declare and it did not
#: happen", which is a usage failure and must be visible to a script.
EXIT_OK = 0
EXIT_REFUSED = 2

#: The level tokens the flag path accepts, folded onto a level. Deliberately
#: STRICTER than ``ens_applicability.parse_level``, which reads anything it does
#: not recognise as "not affected": that is the right conservative default when
#: reading a file somebody else wrote, and the wrong one for a flag, where an
#: unrecognised token is a typo and silently withholding the measures a
#: dimension governs would be a fabricated declaration.
_LEVEL_TOKENS: dict[str, Level] = {
    "bajo": Level.BAJO,
    "baja": Level.BAJO,
    "low": Level.BAJO,
    "medio": Level.MEDIO,
    "media": Level.MEDIO,
    "medium": Level.MEDIO,
    "alto": Level.ALTO,
    "alta": Level.ALTO,
    "high": Level.ALTO,
    "na": Level.NOT_AFFECTED,
    "n/a": Level.NOT_AFFECTED,
    "no_afectada": Level.NOT_AFFECTED,
    "not_affected": Level.NOT_AFFECTED,
}

#: What an error message offers, rather than the full tolerance list above.
_LEVEL_HELP = "bajo, medio, alto, na"

_FLAG_SHOW = "--show"
_FLAG_PROFILE = "--profile"
_FLAG_LEVELS = "--levels"
_FLAG_SYSTEM = "--system"

_USAGE = (
    "compliance_scope [--show]\n"
    "compliance_scope --profile <profile> "
    "--levels C=<level>,I=<level>,T=<level>,A=<level>,D=<level> "
    '[--system "<system this covers>"]'
)


class _Refused(Exception):
    """One refusal, carrying the line the operator reads and an optional hint."""

    def __init__(self, message: str, *hints: str) -> None:
        super().__init__(message)
        self.message = message
        self.hints = tuple(h for h in hints if h)


class _Request:
    """What the operator asked for, after parsing and before validation."""

    def __init__(self) -> None:
        self.show = False
        self.profile: Optional[str] = None
        self.levels: dict[Dimension, Level] = {}
        self.system = ""

    @property
    def declares(self) -> bool:
        return self.profile is not None or bool(self.levels)


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


def _split_flag(token: str) -> tuple[str, Optional[str]]:
    """Split ``--flag=value`` into its two halves; ``--flag`` keeps a ``None``."""
    if "=" in token:
        name, _, value = token.partition("=")
        return name, value
    return token, None


def _parse(args: str) -> _Request:
    """Parse the verb's argument string. Raises :class:`_Refused` on anything odd.

    Hand-rolled rather than argparse: four flags do not justify a parser that
    calls ``sys.exit`` on an operator's typo, and the refusal messages carry the
    valid set, which argparse's own errors would not.
    """
    try:
        tokens = shlex.split(args or "")
    except ValueError as exc:
        raise _Refused(f"Could not read the arguments: {exc}.") from exc

    request = _Request()
    index = 0
    while index < len(tokens):
        name, inline = _split_flag(tokens[index])
        index += 1
        value = inline
        if value is None and name in (_FLAG_PROFILE, _FLAG_LEVELS, _FLAG_SYSTEM):
            if index >= len(tokens) or tokens[index].startswith("--"):
                raise _Refused(f"{name} needs a value.")
            value = tokens[index]
            index += 1

        if name == _FLAG_SHOW:
            request.show = True
        elif name == _FLAG_PROFILE:
            request.profile = str(value).strip().lower()
        elif name == _FLAG_LEVELS:
            _merge_levels(request.levels, str(value))
            # Keep taking further assignments, so the five levels read the same
            # typed with commas or with spaces. Only a token that IS an
            # assignment is absorbed, so a stray word is still refused by name
            # rather than swallowed.
            while (
                index < len(tokens)
                and not tokens[index].startswith("--")
                and "=" in tokens[index]
            ):
                _merge_levels(request.levels, tokens[index])
                index += 1
        elif name == _FLAG_SYSTEM:
            request.system = str(value).strip()
        else:
            raise _Refused(
                f"Unrecognised argument {name!r}.",
                f"Usage:\n{_USAGE}",
            )

    if request.show and request.declares:
        raise _Refused(
            f"{_FLAG_SHOW} reads the declaration on file, so it cannot be "
            f"combined with {_FLAG_PROFILE} or {_FLAG_LEVELS}.",
        )
    return request


def _merge_levels(into: dict[Dimension, Level], spec: str) -> None:
    """Read one ``--levels`` value into the accumulated map.

    ``--levels`` is repeatable and its pairs may be separated by commas or
    spaces, so the five levels can be typed as one token or built up. A
    dimension declared twice is refused rather than resolved last-wins: two
    levels for one dimension is a contradiction, and picking one of them is the
    kind of quiet completion this command does not do.
    """
    for raw in str(spec or "").replace(",", " ").split():
        key, sep, value = raw.partition("=")
        if not sep:
            raise _Refused(
                f"{raw!r} is not a dimension assignment.",
                "Write each dimension as KEY=LEVEL, for example C=medio.",
            )
        initial = key.strip().upper()
        if initial not in {d.value for d in Dimension}:
            raise _Refused(
                f"{key!r} is not an ENS security dimension.",
                "The five dimensions are: " + _dimension_help() + ".",
            )
        dimension = Dimension(initial)
        token = value.strip().lower()
        if token not in _LEVEL_TOKENS:
            raise _Refused(
                f"{value!r} is not an ENS level for {dimension.value} "
                f"({DIMENSION_NAMES[dimension]}).",
                f"The levels are: {_LEVEL_HELP}.",
            )
        if dimension in into:
            raise _Refused(
                f"Dimension {dimension.value} is declared more than once.",
                "Declare each of the five dimensions exactly once.",
            )
        into[dimension] = _LEVEL_TOKENS[token]


def _dimension_help() -> str:
    return ", ".join(
        f"{d.value} ({DIMENSION_NAMES[d]})" for d in DIMENSION_ORDER
    )


# --------------------------------------------------------------------------- #
# Validation: a partial or unusable declaration is refused, never completed
# --------------------------------------------------------------------------- #


def _validate(request: _Request) -> EnsScope:
    """Turn a parsed request into a scope, or refuse it."""
    if request.profile is None:
        raise _Refused(
            "No compliance profile was declared, so the scope is incomplete.",
            f"Add {_FLAG_PROFILE} <profile>. The profiles are:\n"
            + _profile_help(),
        )
    # Resolved rather than matched against the registry keys, so a documented
    # alias ("890a") is read as the document it names instead of refused, and a
    # typo is still refused rather than normalised into something adjacent.
    profile = resolve_profile(request.profile)
    if profile is None:
        raise _Refused(
            f"{request.profile!r} is not a compliance profile this build holds.",
            "The profiles are:\n" + _profile_help(),
        )

    missing = [d for d in DIMENSION_ORDER if d not in request.levels]
    if missing:
        named = ", ".join(f"{d.value} ({DIMENSION_NAMES[d]})" for d in missing)
        raise _Refused(
            "The declaration is incomplete: no level was given for "
            f"{named}.",
            "All five dimensions are required. ADscan will not infer the "
            "missing one: that is the client's categorisation decision "
            "(RD 311/2022, Anexo I). Declare a dimension this system has "
            "nothing to protect in as 'na'.",
        )

    declared = {
        dimension: level
        for dimension, level in request.levels.items()
        if level is not Level.NOT_AFFECTED
    }
    if not declared:
        raise _Refused(
            "Every dimension was declared not affected, which is not a scope.",
            "A system that holds no information and provides no service has "
            "no category to derive and nothing to map. At least one dimension "
            "must carry bajo, medio or alto.",
        )

    return EnsScope(
        dimension_levels=declared,
        profile=profile.key,
        ens_version=ENS_VERSION,
        compensatory_measures=frozenset(),
        system_label=request.system or None,
    )


def _profile_help() -> str:
    """The profiles, in the order and with the labels the wizard offers them.

    Read off the wizard's own choice builder so the two surfaces cannot list
    different profiles, or list them in a different order: the general profile
    first, the superseded family last.
    """
    from adscan_internal.cli.compliance_scope_wizard import (  # noqa: PLC0415
        profile_choices,
    )

    return "\n".join(
        f"  {key:<24} {label}" for key, label in profile_choices()
    )


# --------------------------------------------------------------------------- #
# The read
# --------------------------------------------------------------------------- #


def _print_undeclared(workspace_dir: Any) -> None:
    """State the undeclared case, and what the report does with it.

    An undeclared workspace is a legitimate state, not an error, and the honest
    answer is the one the resolver already gives: the measures Anexo II requires
    at every category. Every figure is read off ``as_header()``.
    """
    header = resolve_ens_applicability(None).as_header()
    print_panel(
        "\n".join(
            [
                "No ENS scope is declared for this workspace.",
                "",
                "The compliance section maps the common core of "
                f"{header['common_core_total']} of {header['measures_total']} "
                "Anexo II measures, the ones required at every category, and "
                "states that the category was not declared. Nothing is "
                "inferred from the scan: the security category belongs to the "
                "system and is the client's own categorisation decision "
                f"({header['category_derivation_citation']}).",
                "",
                # Shape first, then the two valid sets, rather than one long
                # example: at a container's 80 columns a full example wraps,
                # and a wrapped command is one an operator retypes wrong.
                "[bold]To declare it, in one command[/bold]",
                "  compliance_scope --profile <profile> --levels <C,I,T,A,D>",
                "",
                "  profile     general, ccn_stic_890a, ccn_stic_890c,",
                "              other_specific_profile",
                "  levels      C=medio,I=medio,T=bajo,A=medio,D=bajo",
                "              one per dimension, all five: bajo, medio, "
                "alto, na",
                "",
                f"Or point {COMPLIANCE_SCOPE_ENV} at the client's written "
                "categorisation, which every surface reads in place of the "
                "workspace file.",
            ]
        ),
        title="ENS scope: not declared",
        title_align="left",
    )


def _print_declared(scope: EnsScope, workspace_dir: Any) -> None:
    """State the declaration on file, through the one scope renderer."""
    from adscan_internal.cli.compliance_scope_wizard import (  # noqa: PLC0415
        declaration_date,
        render_declared_scope,
    )

    render_declared_scope(
        scope,
        title="ENS scope of the assessed system",
        declared_on=declaration_date(workspace_dir),
    )
    source = compliance_scope_path(workspace_dir)
    if source is not None:
        print_info(f"Read from {source}.")


def _read(workspace_dir: Any) -> int:
    scope = load_ens_scope(workspace_dir)
    if scope is None:
        _print_undeclared(workspace_dir)
    else:
        _print_declared(scope, workspace_dir)
    return EXIT_OK


# --------------------------------------------------------------------------- #
# The declaration
# --------------------------------------------------------------------------- #


def _declare(scope: EnsScope, workspace_dir: Any) -> int:
    from adscan_internal.cli.compliance_scope_wizard import (  # noqa: PLC0415
        declaration_payload,
        render_declared_scope,
    )

    previous = load_ens_scope(workspace_dir)
    try:
        written = write_compliance_scope_declaration(
            workspace_dir, declaration_payload(scope)
        )
    except OSError as exc:
        print_error(
            f"Could not write the declaration ({type(exc).__name__}): "
            "nothing was declared."
        )
        return EXIT_REFUSED

    if previous is not None:
        print_warning(
            "Replaced the declaration this workspace already carried "
            f"(category {resolve_ens_applicability(previous).category_label})."
        )
    render_declared_scope(scope, title="Declared ENS scope")
    if scope.profile_out_of_scope_reason:
        print_warning(
            f"{scope.profile_out_of_scope_reason} The report will state that "
            "the profile does not reach the system rather than reading its "
            "table anyway. To have the measures scoped instead, declare the "
            f"general profile of Anexo II ({_FLAG_PROFILE} {PROFILE_GENERAL})."
        )
    print_info(f"Declaration saved to {written}.")
    return EXIT_OK


def _refuse_overridden_write() -> int:
    """Refuse to write a declaration the env override would shadow on read."""
    override = os.environ.get(COMPLIANCE_SCOPE_ENV, "").strip()
    print_error(
        f"{COMPLIANCE_SCOPE_ENV} points at {override}, and that file is what "
        "every surface reads. A workspace declaration written now would never "
        "be read, so nothing was written."
    )
    print_info(
        f"Unset {COMPLIANCE_SCOPE_ENV} to declare into the workspace, or edit "
        "that file, which is the client's written categorisation."
    )
    return EXIT_REFUSED


def _refuse_ephemeral_write() -> int:
    """Refuse to write into a workspace that is deleted when the command ends."""
    print_error(
        "This run's workspace is deleted when the command ends, so a "
        "declaration written into it would not survive. Nothing was written."
    )
    print_info(
        "Declare into a workspace that persists: pass -w <workspace>, the one "
        "the report is rendered from. A workspace `execute` creates itself is "
        "removed on exit unless --keep-workspace is also passed."
    )
    return EXIT_REFUSED


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def run_compliance_scope_command(
    args: str = "",
    *,
    workspace_dir: Any,
    shell: object | None = None,
    interactive: Optional[bool] = None,
) -> int:
    """Run the verb. Returns the process exit code ``adscan execute`` reports.

    Args:
        args: The verb's raw argument string, as the REPL dispatches it.
        workspace_dir: The open workspace. The declaration lives in it.
        shell: The session, threaded into the wizard's prompt helpers.
        interactive: Override the interactivity decision. ``None`` asks
            :func:`~adscan_internal.interaction.is_non_interactive`, which is
            the real gate (``sys.stdin.isatty`` is not: ``adscan ci`` and
            ``adscan execute`` run under a Docker TTY).

    Returns:
        ``EXIT_OK`` for a read in either state and for a completed declaration,
        ``EXIT_REFUSED`` when the operator asked to declare and it did not
        happen.
    """
    try:
        request = _parse(args)
    except _Refused as refusal:
        print_error(refusal.message)
        for hint in refusal.hints:
            print_info(hint)
        return EXIT_REFUSED

    if request.declares:
        try:
            scope = _validate(request)
        except _Refused as refusal:
            print_error(refusal.message)
            for hint in refusal.hints:
                print_info(hint)
            return EXIT_REFUSED
        if os.environ.get(COMPLIANCE_SCOPE_ENV, "").strip():
            return _refuse_overridden_write()
        if bool(getattr(shell, "workspace_is_ephemeral", False)):
            return _refuse_ephemeral_write()
        return _declare(scope, workspace_dir)

    if request.show:
        return _read(workspace_dir)

    if interactive is None:
        from adscan_internal.interaction import is_non_interactive  # noqa: PLC0415

        interactive = not is_non_interactive(shell)

    if not interactive:
        return _read(workspace_dir)

    from adscan_internal.cli.compliance_scope_wizard import (  # noqa: PLC0415
        declare_or_review_ens_scope,
    )

    declare_or_review_ens_scope(workspace_dir=workspace_dir, shell=shell)
    return EXIT_OK


def declaration_file_for(workspace_dir: Any) -> Optional[Path]:
    """The declaration file this workspace reads, override included."""
    return compliance_scope_path(workspace_dir)


__all__ = (
    "EXIT_OK",
    "EXIT_REFUSED",
    "declaration_file_for",
    "run_compliance_scope_command",
)
