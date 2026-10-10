"""Render a cited framework control through the client's declared scope.

Why this module exists
----------------------
A technique-to-control cross-map is a factual statement about the technique:
the control an auditor will look at when that technique succeeds. It is NOT a
statement that the control is an obligation on the client in front of us. For
ENS those two things come apart, because the exigible measure set is a function
of the system's declared categorisation (see
:mod:`adscan_core.reporting.ens_applicability`), so a paid document that prints
``op.acc.3`` the same way for a BÁSICA system as for an ALTA one cites one of
them a measure its own category does not require.

The fix is NOT to hide the control. Hiding it loses information the client
wants, and it would make the document disagree with the Security Assessment
Report, which does list the measure and marks it not applicable. So each cited
control is rendered THROUGH the resolver for the declared scope and carries
what the norm says about it, exactly as the report's compliance section already
does.

The seam, and why it is framework-agnostic
------------------------------------------
:func:`annotate_control_codes` takes the SAME ``applicability_resolver``
callable shape that
``compliance_engine.build_framework_requirement_model(..., applicability_resolver=...)``
already takes: ``(requirement_id) -> dict | None``, the serialized
``MeasureApplicability``. A framework with no declared-scope dimension supplies
no resolver and its codes come back unannotated, byte-identical to before. So a
future framework (an ISO 27001 Statement of Applicability, a PCI-DSS SAQ type)
joins by supplying a resolver, not by being special-cased here.

There is deliberately no category comparison in this module and no second copy
of any applicability rule. It reads the resolver's answer and decides only how
to SAY it.

The three outcomes a renderer has to distinguish
------------------------------------------------
* **Exigible, or no resolver at all.** Nothing is added. This is every control
  of the other five frameworks, and every ENS measure the declared scope
  requires.
* **Positively not exigible** (the two ``n.a.`` states, and the art. 28.3
  compensatory measure). The control is still listed, marked, and carries the
  reason and the citation behind it.
* **Undeclared, or a declaration this build cannot honour.** Nothing is added,
  on purpose. The norm has not said the measure is not exigible; nobody has
  told us the category. Marking it would assert a non-obligation we cannot
  support, and a workspace with no declaration must read exactly as it did
  before anyone declared anything. The report's scope header is where the
  undeclared state is stated, once, rather than on every chip.

Pure data and pure logic (stdlib only, no ADscan imports), so both the report
engine and the appliance backend can read it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence

#: The resolver shape: a requirement/measure id in, the serialized
#: applicability block out, ``None`` when the framework does not carry that
#: requirement. Identical to the ``applicability_resolver`` the compliance
#: engine takes, so one resolver serves both.
ApplicabilityResolver = Callable[[str], Optional[Mapping[str, Any]]]

#: The marker a not-exigible control carries. Same vocabulary as the Security
#: Assessment Report's conformity label for the same state, so the two paid
#: documents name one thing one way.
NOT_APPLICABLE_MARKER: str = "not applicable"

#: The marker for a measure the client declares satisfied by a substitute under
#: art. 28.3. It IS exigible, which is why it does not share the marker above.
COMPENSATORY_MARKER: str = "compensatory measure"

#: The states that put a control outside what the client's declared scope
#: requires. Mirrors ``ens_applicability.NOT_APPLICABLE_STATES`` by VALUE rather
#: than importing it, so this module stays readable without the ENS table and
#: another framework's resolver can report the same state.
NOT_APPLICABLE_STATE_VALUES: frozenset[str] = frozenset(
    {"not_applicable_by_table", "not_applicable_by_dimension"}
)

#: The compensatory-measure state value.
COMPENSATORY_STATE_VALUE: str = "compensatory_measure"

#: The sentence a document prints ONCE, wherever annotated controls appear. It
#: explains the marker without restating the norm on every chip.
EXIGIBILITY_FOOTNOTE: str = (
    "A control marked not applicable sits outside the measures this system's "
    "declared categorisation requires, so it cannot be a non-conformity. It is "
    "still listed, because the technique maps to it and closing it may still be "
    "worth doing on technical grounds."
)

#: The same sentence for the compensatory case, printed only when one appears.
COMPENSATORY_FOOTNOTE: str = (
    "A control marked compensatory measure is exigible, and this system declares "
    "it satisfied by a substitute measure rather than by the measure itself."
)


@dataclass(frozen=True)
class ControlCitation:
    """One cited control, as the client's declared scope makes it read."""

    code: str
    #: The resolver's state value, or ``""`` when no resolver answered.
    state: str = ""
    #: ``False`` only when the scope positively says the control is not
    #: required. An undeclared scope leaves this ``True``.
    exigible: bool = True
    #: The short marker a chip prints beside the code, or ``""``.
    marker: str = ""
    #: The resolver's own normative sentence, or ``""``.
    reason: str = ""
    #: The article behind the reason, or ``""``.
    citation: str = ""
    #: The measure's name in the norm, when the resolver carries one.
    measure_name: str = ""

    @property
    def annotated(self) -> bool:
        """Whether this citation says anything the plain code does not."""
        return bool(self.marker)

    @property
    def label(self) -> str:
        """The code as a renderer prints it inline."""
        return f"{self.code} ({self.marker})" if self.marker else self.code

    def as_dict(self) -> dict[str, Any]:
        """The serializable shape a template and the web CTEM read."""
        return {
            "code": self.code,
            "state": self.state,
            "exigible": self.exigible,
            "marker": self.marker,
            "label": self.label,
            "annotated": self.annotated,
            "reason": self.reason,
            "citation": self.citation,
            "measure_name": self.measure_name,
        }


def annotate_control_codes(
    codes: Iterable[str],
    resolver: Optional[ApplicabilityResolver] = None,
) -> list[ControlCitation]:
    """Render each cited control code through a declared-scope resolver.

    Args:
        codes: The control codes the cross-map cites, in their own order.
        resolver: The framework's declared-scope resolver, or ``None`` when the
            framework has no declared scope. ``None`` yields plain citations,
            so a caller can always annotate and let the resolver decide.

    Returns:
        One :class:`ControlCitation` per code, order preserved, duplicates
        preserved. Never raises: a resolver that fails on one code leaves that
        code plain rather than breaking the deliverable.
    """
    out: list[ControlCitation] = []
    for raw in codes:
        code = str(raw).strip()
        if not code:
            continue
        out.append(_annotate_one(code, resolver))
    return out


def _annotate_one(
    code: str, resolver: Optional[ApplicabilityResolver]
) -> ControlCitation:
    """One code's citation. Any resolver failure degrades to the plain code."""
    if resolver is None:
        return ControlCitation(code=code)
    try:
        block = resolver(code)
    except Exception:  # noqa: BLE001 - a paid document ships without the marker
        return ControlCitation(code=code)
    if not isinstance(block, Mapping):
        return ControlCitation(code=code)

    state = str(block.get("state") or "").strip()
    reason = str(block.get("reason") or "").strip()
    citation = str(block.get("citation") or "").strip()
    measure_name = str(block.get("name") or "").strip()

    if state in NOT_APPLICABLE_STATE_VALUES:
        return ControlCitation(
            code=code,
            state=state,
            exigible=False,
            marker=NOT_APPLICABLE_MARKER,
            reason=reason,
            citation=citation,
            measure_name=measure_name,
        )
    if state == COMPENSATORY_STATE_VALUE:
        # Exigible, and satisfied by a declared substitute. Marked, because the
        # client needs to see which of their declarations is carrying it.
        return ControlCitation(
            code=code,
            state=state,
            exigible=True,
            marker=COMPENSATORY_MARKER,
            reason=reason,
            citation=citation,
            measure_name=measure_name,
        )
    # Required, undeclared, or an unresolvable declaration. All three print the
    # bare code: see the module docstring on why undeclared is NOT marked.
    return ControlCitation(
        code=code, state=state, reason=reason, citation=citation,
        measure_name=measure_name,
    )


def _citation_state(citation: ControlCitation | Mapping[str, Any]) -> str:
    if isinstance(citation, Mapping):
        return str(citation.get("state") or "")
    return citation.state


def _citation_annotated(citation: ControlCitation | Mapping[str, Any]) -> bool:
    if isinstance(citation, Mapping):
        return bool(citation.get("marker"))
    return citation.annotated


def _citation_label(citation: ControlCitation | Mapping[str, Any]) -> str:
    if isinstance(citation, Mapping):
        code = str(citation.get("code") or "")
        marker = str(citation.get("marker") or "")
        return f"{code} ({marker})" if marker else code
    return citation.label


def format_control_codes(
    citations: Sequence[ControlCitation | Mapping[str, Any]],
) -> str:
    """Join citations into the one-line form a compact chip prints."""
    return ", ".join(_citation_label(citation) for citation in citations)


def footnotes_for(
    citations: Iterable[ControlCitation | Mapping[str, Any]],
) -> list[str]:
    """The explanatory sentences THESE citations actually need, in order.

    Returns an empty list when nothing was annotated, which is the whole point:
    a document with no not-applicable control prints no footnote about one, so
    the other five frameworks and every undeclared workspace are unchanged.

    Accepts either :class:`ControlCitation` objects or their ``as_dict()`` form,
    because an aggregate view (a per-framework card collecting codes across many
    findings) carries the serialized shape and must not have to rebuild the
    objects to ask this.
    """
    states = {
        _citation_state(citation)
        for citation in citations
        if _citation_annotated(citation)
    }
    out: list[str] = []
    if states & NOT_APPLICABLE_STATE_VALUES:
        out.append(EXIGIBILITY_FOOTNOTE)
    if COMPENSATORY_STATE_VALUE in states:
        out.append(COMPENSATORY_FOOTNOTE)
    return out


__all__ = [
    "ApplicabilityResolver",
    "COMPENSATORY_FOOTNOTE",
    "COMPENSATORY_MARKER",
    "COMPENSATORY_STATE_VALUE",
    "ControlCitation",
    "EXIGIBILITY_FOOTNOTE",
    "NOT_APPLICABLE_MARKER",
    "NOT_APPLICABLE_STATE_VALUES",
    "annotate_control_codes",
    "footnotes_for",
    "format_control_codes",
]
