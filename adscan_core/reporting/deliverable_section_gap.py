"""A client-specific deliverable section that could not be produced.

Several kit documents LEAD with a section built from the client's own findings
and fall back to a general reference catalog when there is nothing to bind. The
fallback is correct, and a document that loses one section is worth more to the
client than no document at all.

What is not correct is the two causes being indistinguishable. "The workspace
yielded no readable findings" and "the builder for that section raised" both
arrived at the renderer as ``client = None``, so a single boolean decided
whether the client-specific pages rendered, and the fallback copy for the empty
case ("run an authenticated scan and this worksheet binds to your own
findings") was printed to a client whose scan DID run and whose section build
crashed. The document then shipped looking finished.

Under the Exposure-Validation doctrine that is a **data gap**, the same family
as a bounded computation: the deliverable states where it stopped, and never
renders an incomplete document as a complete one. So the three states are named
here, once:

* :data:`CAUSE_BOUND` the section was built and renders;
* :data:`CAUSE_NO_CLIENT_DATA` there was nothing to bind, and the general
  reference content plus its invitation to run an authenticated scan is the
  honest and correct thing to print;
* :data:`CAUSE_BUILD_FAILED` the section could not be produced. The client gets
  an explicit declaration that the document is incomplete, the operator gets a
  warning naming the document, and the invitation copy is suppressed because it
  would tell the client to do something they already did.

This module is the SSOT for both halves, mirroring
:mod:`adscan_core.reporting.cracking_coverage`:

* :func:`build_section_gap` turns an observed cause into the recorded block, and
* :func:`section_gap_view` turns that block into the small render-ready shape
  every surface consumes, so two documents cannot word the same gap
  differently.

The same fact has a third reader. The Enterprise platform lists a kit's
documents for download from the kit MANIFEST, not from the PDFs, so a degraded
document could be offered there with no indicator at all: the client opened a
document that presented itself as complete. :func:`manifest_completeness` writes
the per-document record into the manifest and :func:`completeness_view` reads it
back for the download list, in this same vocabulary, so the in-document
declaration and the platform cannot word one gap two ways.

:func:`operator_warning` carries the matching terminal line, which is
operator-facing rather than client-facing: the client sentence never names an
internal reason, and the operator one always says there is one to go read.

Pure logic: no IO, no console, no network. Safe to import from ``adscan_core``,
the LITE runtime, the PRO report renderer and the web backend alike.
"""

from __future__ import annotations

from typing import Any, Mapping

#: Key this block is recorded under in a render context (and, should a surface
#: ever persist it, in the report payload). One name, so the writer and every
#: reader cannot drift apart on where the record lives.
SECTION_GAP_KEY = "client_section_gap"

#: The section was built from the client's findings and renders in full.
CAUSE_BOUND = "bound"

#: The workspace carried no readable findings to bind. A legitimate empty
#: state, not a gap: the document's general reference content is the whole
#: honest answer, and inviting an authenticated scan is the correct next step
#: to offer.
CAUSE_NO_CLIENT_DATA = "no_client_data"

#: The section's builder raised, so the section could not be produced for an
#: assessment that may well have had plenty to report. A gap, declared to the
#: client and warned about to the operator.
CAUSE_BUILD_FAILED = "build_failed"

#: Every recognised cause. Anything else normalizes to :data:`CAUSE_BOUND`, so a
#: malformed value can never manufacture a gap in a healthy document.
_CAUSES: frozenset[str] = frozenset(
    {CAUSE_BOUND, CAUSE_NO_CLIENT_DATA, CAUSE_BUILD_FAILED}
)

#: Heading above the client-facing declaration. States the consequence the
#: reader needs (this document is not whole) without an internal reason, a
#: traceback, or an apology.
GAP_HEADING = "This document is incomplete"


def build_section_gap(*, document: str, section: str, cause: str) -> dict[str, Any]:
    """Return the recorded gap block for one document's client-specific section.

    Args:
        document: The deliverable's client-facing title, as the kit names it
            (e.g. ``"AD Hardening Playbook"``). Used in the operator warning so
            a degraded kit names which document degraded.
        section: The client-facing name of the section that was to be built
            (e.g. ``"remediation worksheet built from your own findings"``).
            Reads inside the client sentence, so it is written as a noun phrase
            in the document's own register.
        cause: One of :data:`CAUSE_BOUND`, :data:`CAUSE_NO_CLIENT_DATA`,
            :data:`CAUSE_BUILD_FAILED`.

    Returns:
        The block, carrying the resolved cause and the client statement for the
        one cause that has one. The statement is composed here rather than at a
        render boundary so every document says it identically.
    """
    resolved = str(cause or "").strip().lower()
    if resolved not in _CAUSES:
        resolved = CAUSE_BOUND
    statement = ""
    if resolved == CAUSE_BUILD_FAILED:
        statement = (
            f"The {section} could not be generated for this assessment, so this "
            "document carries only its general reference content. Treat it as "
            "incomplete and ask for a regenerated copy. The assessment data "
            "itself is unaffected."
        )
    return {
        "cause": resolved,
        "document": str(document or ""),
        "section": str(section or ""),
        "heading": GAP_HEADING if statement else "",
        "statement": statement,
    }


def section_gap_view(gap: Any) -> dict[str, Any]:
    """Return the render-ready view of a gap block.

    The one shape every surface reads, so a client meets the same words
    wherever the gap surfaces.

    Returns a mapping with:
      * ``has_gap`` whether to render the declaration at all;
      * ``heading`` / ``statement`` the client-facing declaration;
      * ``may_invite_scan`` whether the document may print the copy that invites
        the reader to run an authenticated scan. True ONLY for a genuinely
        empty workspace. False when the build failed, because the reader's scan
        already ran, and False when the section is bound, because the copy is
        then unreachable anyway;
      * ``build_failed`` the machine-readable form of the same fact;
      * ``cause`` / ``document`` / ``section`` for a machine consumer.

    An absent or unreadable block yields the bound view: a caller that never
    recorded a cause renders exactly as it did before rather than growing a
    declaration nobody observed.
    """
    if not isinstance(gap, Mapping):
        return {
            "has_gap": False,
            "heading": "",
            "statement": "",
            "may_invite_scan": False,
            "build_failed": False,
            "cause": CAUSE_BOUND,
            "document": "",
            "section": "",
        }
    cause = str(gap.get("cause") or "").strip().lower()
    if cause not in _CAUSES:
        cause = CAUSE_BOUND
    statement = str(gap.get("statement") or "").strip()
    build_failed = cause == CAUSE_BUILD_FAILED
    return {
        "has_gap": bool(build_failed and statement),
        "heading": str(gap.get("heading") or "").strip() if build_failed else "",
        "statement": statement if build_failed else "",
        "may_invite_scan": cause == CAUSE_NO_CLIENT_DATA,
        "build_failed": build_failed,
        "cause": cause,
        "document": str(gap.get("document") or ""),
        "section": str(gap.get("section") or ""),
    }


#: Completeness of ONE kit document, as the kit recorded it at build time. The
#: manifest is the only place a download list can learn this from, so the three
#: values below are the vocabulary the platform reads. They are a projection of
#: the causes above, not a second taxonomy: ``CAUSE_BOUND`` and
#: ``CAUSE_NO_CLIENT_DATA`` are both complete documents (an empty workspace has
#: nothing missing to declare), and ``CAUSE_BUILD_FAILED`` is the one that is
#: not.
COMPLETENESS_COMPLETE = "complete"

#: A section the document was meant to carry could not be produced. The document
#: is downloadable and still worth reading, and it says so about itself.
COMPLETENESS_INCOMPLETE = "incomplete"

#: The kit never recorded a completeness for this document, so nothing is known
#: either way. Reached by a manifest written before this field existed, and by a
#: kit that is still rendering. It is deliberately NOT a synonym for
#: :data:`COMPLETENESS_COMPLETE`: a document nobody measured must not present
#: itself as whole, which is the same distinction compliance draws between an
#: observed-good control and one that was never assessed. It renders as no
#: indicator at all, exactly as before this field existed, so it never
#: manufactures a verdict in either direction.
COMPLETENESS_UNDECLARED = "undeclared"

#: Short label for a degraded document in a list of files, where the full
#: in-document declaration does not fit.
COMPLETENESS_LABEL = "Incomplete"

#: The one-line form of the in-document declaration, for the same list. Shorter
#: wording, same fact and same consequence, composed here so the document and
#: the platform cannot describe one degraded document two ways.
COMPLETENESS_NOTICE = (
    "One section of this document could not be generated, so it carries only "
    "its general reference content. Ask for a regenerated copy before relying "
    "on it."
)


def manifest_completeness(gap: Any = None) -> dict[str, Any]:
    """Return the completeness record a kit manifest carries for ONE document.

    Called once per manifest file entry by the kit's manifest writer. ``gap`` is
    that document's gap block or its view (:func:`section_gap_view` accepts
    either), or ``None`` for a document that has no client-specific section to
    lose. ``None`` resolves to :data:`COMPLETENESS_COMPLETE` rather than to
    :data:`COMPLETENESS_UNDECLARED`, and that is the deliberate asymmetry with
    the reader below: the WRITER knows there was nothing that could be missing,
    so it can state completeness; a READER facing an absent field knows only
    that nobody recorded one.

    Every entry a manifest writes therefore carries a value, so an absent field
    on a current manifest means a hop in the chain dropped it, never that a
    document declined to answer.

    Returns:
        A mapping with ``completeness``, the client-facing ``notice`` (empty for
        a complete document) and the ``section`` that is missing (empty likewise),
        ready to be merged into the manifest's per-file dict.
    """
    view = section_gap_view(gap)
    if not view["build_failed"]:
        return {
            "completeness": COMPLETENESS_COMPLETE,
            "notice": "",
            "missing_section": "",
        }
    return {
        "completeness": COMPLETENESS_INCOMPLETE,
        "notice": COMPLETENESS_NOTICE,
        "missing_section": view["section"],
    }


def completeness_view(entry: Any) -> dict[str, Any]:
    """Return the render-ready completeness view for one manifest file entry.

    The reader half of :func:`manifest_completeness`, consumed by the platform's
    download list so the list and the document itself word the same gap
    identically.

    ``entry`` is the manifest's per-file mapping. An absent, unreadable or
    unrecognised ``completeness`` resolves to :data:`COMPLETENESS_UNDECLARED`
    with nothing to render, which is how a kit built before this field existed
    keeps behaving exactly as it did: no indicator, and no claim that the
    document is whole.

    Returns a mapping with:
      * ``completeness`` one of the three values;
      * ``is_incomplete`` whether to draw the indicator;
      * ``label`` / ``notice`` the client-facing text, empty unless incomplete;
      * ``missing_section`` the section that is absent, empty unless incomplete.
    """
    completeness = COMPLETENESS_UNDECLARED
    notice = ""
    missing_section = ""
    if isinstance(entry, Mapping):
        raw = str(entry.get("completeness") or "").strip().lower()
        if raw in {COMPLETENESS_COMPLETE, COMPLETENESS_INCOMPLETE}:
            completeness = raw
        notice = str(entry.get("notice") or "").strip()
        missing_section = str(entry.get("missing_section") or "").strip()
    is_incomplete = completeness == COMPLETENESS_INCOMPLETE
    return {
        "completeness": completeness,
        "is_incomplete": is_incomplete,
        "label": COMPLETENESS_LABEL if is_incomplete else "",
        # Fall back to the canonical sentence rather than rendering an indicator
        # with no explanation, for a row whose notice was lost in transit.
        "notice": (notice or COMPLETENESS_NOTICE) if is_incomplete else "",
        "missing_section": missing_section if is_incomplete else "",
    }


def operator_warning(gap: Any) -> str:
    """Return the terminal line for the operator, or ``""`` when there is none.

    Operator-facing, so unlike the client sentence it says a cause exists and
    where to read it. It is deliberately printed at warning level rather than
    only under ``--debug``: the traceback already reaches the debug log and the
    recording, and an operator on a normal run was seeing nothing at all before
    handing the kit to a client.
    """
    view = section_gap_view(gap)
    if not view["build_failed"]:
        return ""
    document = view["document"] or "This deliverable"
    return (
        f"{document}: the client-specific sections failed to build. The document "
        "will ship with its general reference content only and declares itself "
        "incomplete to the reader. Fix the cause (traceback above, and in the "
        "workspace debug log) and re-run before sending this kit."
    )


__all__ = [
    "CAUSE_BOUND",
    "CAUSE_BUILD_FAILED",
    "CAUSE_NO_CLIENT_DATA",
    "COMPLETENESS_COMPLETE",
    "COMPLETENESS_INCOMPLETE",
    "COMPLETENESS_LABEL",
    "COMPLETENESS_NOTICE",
    "COMPLETENESS_UNDECLARED",
    "GAP_HEADING",
    "SECTION_GAP_KEY",
    "build_section_gap",
    "completeness_view",
    "manifest_completeness",
    "operator_warning",
    "section_gap_view",
]
