"""Compliance-framework scoping: the one resolver every report path calls.

A compliance section does not merely add content to a report, it asserts a
conformance verdict against a specific regime. Asserting one against a
framework the client is not subject to is worse than asserting none (handing a
Spanish public-sector ENS verdict to a bank regulated under DORA signals that
we do not know their regime, in the exact document meant to win them), so
ADscan never picks a framework on the operator's behalf. There is no built-in
default of any kind: not ENS, not none-as-a-silent-choice, not DORA.

Two inputs decide the scope:

* The operator's EXPLICIT selection (``--frameworks``, the interactive picker,
  the web's selector). It always wins, on every entry point.
* The ENGAGEMENT TYPE, which is a property of the SCAN and is persisted in the
  workspace (``variables.json`` top-level ``type``), never of the command that
  re-renders it. An ``audit`` engagement REQUIRES an explicit framework: it is
  a client engagement whose regime comes from the signed scope, not something
  the binary infers. A ``ctf`` engagement has no regulatory regime, so it
  renders with none and is never prompted.

Every report entry point (``adscan ci --generate-report``, ``adscan report``,
``adscan deliver``, the REPL ``generate_report``/``deliver`` verbs) resolves
through :func:`resolve_compliance_scope`, so the requiredness answer cannot
differ by command. Two opposite defaults for the same decision is the defect
this module closes: ``ci`` used to substitute ENS while ``deliver`` substituted
nothing, so one scan yielded a compliance-mapped report from one command and a
compliance-free one from the other, and a CTF lab got an ENS conformance
verdict about a public practice box.

The absence of a framework is MADE VISIBLE rather than silent
(:func:`announce_compliance_scope`): a quietly missing paid-tier section is how
a kit ships without compliance and nobody notices.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

from adscan_core.lab_context import normalize_workspace_type
from adscan_core.rich_output import print_info, print_info_debug, print_warning
from adscan_internal.cli.common import _VALID_FRAMEWORK_KEYS

# The engagement types ADscan records on a workspace (``adscan ci --type`` /
# the interactive ``start`` picker). Anything else, including an absent value,
# is NOT an engagement classification: it is a data gap (see
# :func:`resolve_engagement_type`).
AUDIT_ENGAGEMENT = "audit"
CTF_ENGAGEMENT = "ctf"
KNOWN_ENGAGEMENT_TYPES: frozenset[str] = frozenset({AUDIT_ENGAGEMENT, CTF_ENGAGEMENT})

_VARIABLES_FILENAME = "variables.json"

#: Workspaces already told about an undeclared ENS scope in THIS process, so a
#: run that resolves and announces twice states the fact once. Keyed by path.
_ens_notice_announced: set[str] = set()


@dataclass(frozen=True)
class ComplianceScope:
    """The resolved compliance scoping decision for one report render.

    Attributes:
        frameworks: The canonical framework keys to render, in operator order.
            Empty means no compliance mapping at all.
        engagement_type: ``"audit"``, ``"ctf"``, or ``None`` when the workspace
            carries no classification (a data gap, never treated as an audit).
        required: Whether this engagement requires an explicit selection.
        workspace_dir: The workspace this scope was resolved against, as a
            string, or ``None`` when the caller held no workspace yet (the
            ``adscan ci`` pre-scan gate, which runs before the workspace
            exists). Carried on the scope so a consumer can read per-workspace
            state, such as the client's ENS scope declaration, without being
            handed the directory a second time.
    """

    frameworks: tuple[str, ...]
    engagement_type: Optional[str]
    required: bool
    workspace_dir: Optional[str] = None

    @property
    def selected(self) -> bool:
        """Whether any framework was selected."""
        return bool(self.frameworks)

    @property
    def missing_required(self) -> bool:
        """An audit engagement reached a render with no framework selected."""
        return self.required and not self.frameworks

    def as_list(self) -> Optional[list[str]]:
        """The selection as the report pipeline takes it (``None`` = no mapping)."""
        return list(self.frameworks) or None


def frameworks_are_required(engagement_type: Optional[str]) -> bool:
    """Whether an explicit framework selection is mandatory for this engagement.

    Only an ``audit`` engagement requires one. A ``ctf`` lab has no regulatory
    regime, and an undetermined type is a data gap: requiring a framework there
    would hard-fail a re-render of an older workspace that worked yesterday.
    """
    return normalize_workspace_type(engagement_type) == AUDIT_ENGAGEMENT


def workspace_engagement_type(workspace_dir: Any) -> Optional[str]:
    """Read the engagement type the SCAN persisted in its workspace.

    The type lives at the top level of ``variables.json`` (written at workspace
    creation by ``write_initial_workspace_variables`` and re-saved on every
    workspace save). Returns ``None`` for a missing, unreadable or
    unclassified workspace: an absent type is a data gap, not a
    classification.
    """
    if not workspace_dir:
        return None
    try:
        path = Path(str(workspace_dir)) / _VARIABLES_FILENAME
        if not path.is_file():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - an unreadable workspace is a data gap
        return None
    if not isinstance(data, dict):
        return None
    value = normalize_workspace_type(data.get("type"))
    return value if value in KNOWN_ENGAGEMENT_TYPES else None


def resolve_engagement_type(
    shell: Any = None,
    workspace_dir: Any = None,
) -> Optional[str]:
    """Resolve the engagement type for a report render.

    The WORKSPACE is the ONLY source when a directory is given, and an
    unclassified workspace stays unclassified. The engagement type is a
    property of the scan that produced the data, so a command re-rendering it
    cannot redefine it, and a command-level bootstrap default (``adscan
    report`` assumes ``audit`` while it opens a shell) must never be mistaken
    for the scan's own classification: that is what would hard-fail a
    re-render of an older typeless workspace that worked yesterday. A missing
    persisted type is a DATA GAP, not an engagement classification.

    The live shell is consulted only when no workspace directory is available
    at all (a shell that has not written its variables yet).

    Returns ``None`` when the engagement is not classified.
    """
    if workspace_dir is not None:
        return workspace_engagement_type(workspace_dir)
    shell_type = normalize_workspace_type(getattr(shell, "type", None))
    return shell_type if shell_type in KNOWN_ENGAGEMENT_TYPES else None


def _clean(values: Optional[Iterable[str]]) -> tuple[str, ...]:
    """Normalize a selection: strip, drop blanks, dedupe, preserve order."""
    if not values:
        return ()
    seen: set[str] = set()
    ordered: list[str] = []
    for raw in values:
        key = str(raw or "").strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        ordered.append(key)
    return tuple(ordered)


def resolve_compliance_scope(
    *,
    explicit: Optional[Sequence[str]] = None,
    shell: Any = None,
    workspace_dir: Any = None,
    engagement_type: Optional[str] = None,
) -> ComplianceScope:
    """Resolve the compliance scope for one report render. The SSOT.

    Args:
        explicit: The operator's selection (already validated by
            ``_parse_frameworks`` or the web's ``normalize_frameworks``).
            ``None`` or empty means nothing was chosen. It always wins.
        shell: The live CLI shell, when there is one.
        workspace_dir: The workspace being rendered. Authoritative source of
            the engagement type.
        engagement_type: Pre-resolved engagement type, for a caller that holds
            it directly and has no workspace yet (the ``adscan ci`` pre-scan
            gate reads it from ``--type``). Wins over shell/workspace lookup.

    Returns:
        The resolved :class:`ComplianceScope`. Never raises, and never
        substitutes a framework the operator did not choose.
    """
    resolved_type = (
        normalize_workspace_type(engagement_type)
        if engagement_type is not None
        else resolve_engagement_type(shell=shell, workspace_dir=workspace_dir)
    )
    if resolved_type not in KNOWN_ENGAGEMENT_TYPES:
        resolved_type = None
    return ComplianceScope(
        frameworks=_clean(explicit),
        engagement_type=resolved_type,
        required=frameworks_are_required(resolved_type),
        workspace_dir=str(workspace_dir) if workspace_dir else None,
    )


def valid_framework_list() -> str:
    """The accepted framework keys, for an operator-facing message."""
    return ", ".join(_VALID_FRAMEWORK_KEYS)


def missing_framework_error(*, rerender_hint: Optional[str] = None) -> str:
    """The message shown when an audit render has no framework selected.

    Names the valid values so the operator can self-correct without reading
    source, and (when the data already exists) the exact command to re-render.
    """
    message = (
        "No compliance framework was selected for this audit engagement. "
        "A compliance section asserts a conformance verdict, so the framework "
        "is a scoping decision ADscan will not make for you. "
        f"Pass --frameworks with one or more of: {valid_framework_list()}."
    )
    if rerender_hint:
        message += f" The workspace is kept, so you can re-render with: {rerender_hint}"
    return message


def no_framework_notice() -> str:
    """The one line a report with no compliance mapping must carry."""
    return (
        "No compliance framework was selected, so this report carries no "
        f"compliance mapping. Add one with --frameworks ({valid_framework_list()})."
    )


def _declaration_path_hint(workspace_dir: Any = None) -> str:
    """Where to write the declaration, named concretely when we know it."""
    from adscan_core.reporting.compliance_scope_declaration import (
        COMPLIANCE_SCOPE_FILENAME,
    )

    if workspace_dir:
        return str(Path(str(workspace_dir)) / COMPLIANCE_SCOPE_FILENAME)
    return f"<workspace>/{COMPLIANCE_SCOPE_FILENAME}"


def undeclared_ens_scope_notice(workspace_dir: Any = None) -> str:
    """The line an unattended ENS render owes the operator.

    Every figure is read off the ENS scope header, the same data the rendered
    document states its own scope from, so the terminal and the deliverable
    cannot disagree on a count.
    """
    from adscan_core.reporting.ens_applicability import resolve_ens_applicability

    header = resolve_ens_applicability(None).as_header()
    required = header["required_total"]
    total = header["measures_total"]
    pending = header["exigibility_undeclared_total"]
    target = _declaration_path_hint(workspace_dir)
    return (
        "No ENS scope is declared for this workspace, so the compliance "
        f"section is scored against the {required} of {total} Anexo II "
        f"measures that are exigible at every category. The other {pending} "
        "follow from the system's security category and from which security "
        "dimensions are affected, and are reported as pending that "
        "declaration rather than assumed. The client's own categorisation "
        "resolves them: declare it once with the 'compliance_scope' command "
        "in an interactive session, or write the five dimension levels into "
        f"{target}, then re-render."
    )


def _announce_undeclared_ens_scope(scope: ComplianceScope) -> None:
    """Tell an UNATTENDED operator that one datum would widen the ENS section.

    The interactive paths ask instead: ``deliver``'s framework resolution fires
    the six-question scope wizard the moment ENS lands in the selection and the
    workspace carries no declaration. A non-interactive run correctly skips
    that wizard, because a prompt inside ``adscan ci`` or the Enterprise worker
    would hang the run. Without this notice the operator never learns the
    question exists, and finds out when the client asks.

    Three conditions, and only their conjunction is both certainly affected and
    certainly not being asked:

    * ENS is in the selection, so the declaration changes what the document
      maps. A kit that only wants ISO 27001 must not hear about it.
    * The context is non-interactive, so nobody is being asked.
    * The workspace carries no declaration. One that does is already correct.

    A resolved workspace is required too: the ``adscan ci`` pre-scan gate
    resolves a scope with no workspace at all, and before the scan there is no
    declaration to look for. That gate never announces, so it is excluded
    twice over.

    Never an error, never a prompt, and nothing here can block a run.
    """
    from adscan_internal.cli.compliance_scope_wizard import (
        ENS_FRAMEWORK_KEY,
        workspace_has_declared_ens_scope,
    )
    from adscan_internal.interaction import is_non_interactive

    workspace_dir = scope.workspace_dir
    if not workspace_dir:
        return
    if ENS_FRAMEWORK_KEY not in scope.frameworks:
        return
    if not is_non_interactive():
        return
    if workspace_has_declared_ens_scope(workspace_dir):
        return
    # One notice per run per workspace: a run that resolves the scope twice
    # (``deliver`` does) is stating one fact, not two.
    key = str(Path(str(workspace_dir)))
    if key in _ens_notice_announced:
        return
    _ens_notice_announced.add(key)
    print_warning(undeclared_ens_scope_notice(workspace_dir))


def announce_compliance_scope(scope: ComplianceScope) -> None:
    """State the compliance scoping decision on the operator's terminal.

    An absence is announced, not implied: a silently missing paid-tier section
    is how a kit ships without compliance and nobody notices. The same reading
    governs an ENS render whose scope was never declared: the output is
    correct, and an unattended operator is the one person nobody asked.
    """
    if scope.selected:
        print_info(f"Compliance frameworks: {', '.join(scope.frameworks)}")
        # Best-effort, and deliberately so: a notice about the output must
        # never be able to stop the output. Mirrors the same subsystem's
        # ``applicability_resolver_for``, which degrades the same way.
        try:
            _announce_undeclared_ens_scope(scope)
        except Exception as exc:  # noqa: BLE001 - the render goes on without it
            print_info_debug(f"ENS scope: undeclared-scope notice skipped: {exc}")
        return
    print_warning(no_framework_notice())


__all__ = (
    "AUDIT_ENGAGEMENT",
    "CTF_ENGAGEMENT",
    "KNOWN_ENGAGEMENT_TYPES",
    "ComplianceScope",
    "announce_compliance_scope",
    "frameworks_are_required",
    "missing_framework_error",
    "no_framework_notice",
    "resolve_compliance_scope",
    "resolve_engagement_type",
    "undeclared_ens_scope_notice",
    "valid_framework_list",
    "workspace_engagement_type",
)
