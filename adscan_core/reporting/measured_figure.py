"""A client-facing figure that could not be measured, told apart from a zero.

Several deliverable KPIs are counts, and a count has a value that is also the
value a failed computation leaves behind. The AD Hardening Playbook's "Findings
on a validated path" cell is the case this module was written for: its builder
set the figure to ``0`` when the underlying count raised, and zero is ALSO the
legitimate measured answer, so the client-facing cell could not distinguish a
real zero from a failure. That matters in both directions. A real zero is a
meaningful and reassuring fact about the directory, and printing it where
nothing was measured impersonates it; a failure printed as zero tells the client
their exposure is smaller than anybody actually checked.

Under the Exposure-Validation doctrine this is a data gap, the same family as a
bounded computation: the deliverable states where it stopped, and never renders
an unmeasured figure as a measured one. So the two states are named here, once,
mirroring :mod:`adscan_core.reporting.deliverable_section_gap` (which does the
same job one layer up, for a whole section) and
:mod:`adscan_core.reporting.cracking_coverage`:

* :func:`build_measured_figure` turns an observed cause into the recorded block;
* :func:`measured_figure_view` turns that block into the render-ready shape every
  surface consumes, so two documents cannot word the same gap differently.

The client sentence never names an internal reason. The operator gets the cause
from the three diagnostic sinks at the call site (``capture_exception`` +
``print_exception`` + the debug log), exactly as the section-level gap does.

Pure logic: no IO, no console, no network. Safe to import from ``adscan_core``,
the LITE runtime, the PRO report renderer and the web backend alike.
"""

from __future__ import annotations

from typing import Any, Mapping

#: The figure was computed and renders as its value, zero included.
CAUSE_MEASURED = "measured"

#: The figure could not be computed, so there is no value to render. Declared to
#: the client instead of substituted with a number.
CAUSE_NOT_MEASURABLE = "not_measurable"

#: Every recognised cause. Anything else normalizes to :data:`CAUSE_MEASURED`,
#: so a malformed value can never manufacture a gap on a healthy figure.
_CAUSES: frozenset[str] = frozenset({CAUSE_MEASURED, CAUSE_NOT_MEASURABLE})

#: What a surface prints in place of the number. Short enough for a KPI cell,
#: and it reads as a state rather than as a value, which "0" or "n/a" do not.
NOT_MEASURED_DISPLAY = "Not measured"


def build_measured_figure(
    *,
    figure: str,
    cause: str,
    value: Any = None,
    reference: str = "",
) -> dict[str, Any]:
    """Return the recorded block for one client-facing figure.

    Args:
        figure: The figure's client-facing name as the document labels it (e.g.
            ``"count of findings on a validated attack path"``). It reads inside
            the client sentence, so write it as a noun phrase in the document's
            own register.
        cause: :data:`CAUSE_MEASURED` or :data:`CAUSE_NOT_MEASURABLE`.
        value: The measured value. Carried only when the cause is
            :data:`CAUSE_MEASURED`; forced to ``None`` otherwise, so no reader
            can pick a substituted number back up.
        reference: Optional closing clause pointing the reader at where the
            underlying material IS reported (e.g. "The validated attack paths
            are listed in full in your Security Assessment Report."). Printed
            only on the unmeasured path.

    Returns:
        The block, carrying the resolved cause, the value for the one cause that
        has one, and the client statement for the one cause that needs one. The
        statement is composed here rather than at a render boundary so every
        document says it identically.
    """
    resolved = str(cause or "").strip().lower()
    if resolved not in _CAUSES:
        resolved = CAUSE_MEASURED
    statement = ""
    if resolved == CAUSE_NOT_MEASURABLE:
        value = None
        name = str(figure or "").strip() or "figure"
        statement = (
            f"The {name} could not be computed for this assessment, so it is "
            "reported as not measured. A zero here would be a measured result "
            "about your directory, and this is not one."
        )
        closing = str(reference or "").strip()
        if closing:
            statement = f"{statement} {closing}"
    return {
        "cause": resolved,
        "figure": str(figure or ""),
        "value": value,
        "display": (
            NOT_MEASURED_DISPLAY
            if resolved == CAUSE_NOT_MEASURABLE
            else ("" if value is None else f"{value:,}" if isinstance(value, int) else str(value))
        ),
        "statement": statement,
    }


def measured_figure_view(figure: Any) -> dict[str, Any]:
    """Return the render-ready view of a figure block.

    The one shape every surface reads, so a client meets the same words wherever
    the gap surfaces.

    Returns a mapping with:
      * ``measured`` whether there is a number to print at all. A template gates
        on this, so it can never print the value and the declaration together;
      * ``value`` the measured value, or ``None``;
      * ``display`` what to print in the cell: the formatted number, or
        :data:`NOT_MEASURED_DISPLAY`;
      * ``statement`` the client-facing declaration, empty when measured;
      * ``cause`` / ``figure`` for a machine consumer.

    An absent or unreadable block yields the measured view with no value, so a
    caller that never recorded a cause renders as it did before rather than
    growing a declaration nobody observed.
    """
    if not isinstance(figure, Mapping):
        return {
            "measured": True,
            "value": None,
            "display": "",
            "statement": "",
            "cause": CAUSE_MEASURED,
            "figure": "",
        }
    cause = str(figure.get("cause") or "").strip().lower()
    if cause not in _CAUSES:
        cause = CAUSE_MEASURED
    measured = cause == CAUSE_MEASURED
    value = figure.get("value") if measured else None
    return {
        "measured": measured,
        "value": value,
        "display": (
            str(figure.get("display") or "")
            if measured
            else NOT_MEASURED_DISPLAY
        ),
        "statement": "" if measured else str(figure.get("statement") or "").strip(),
        "cause": cause,
        "figure": str(figure.get("figure") or ""),
    }


__all__ = [
    "CAUSE_MEASURED",
    "CAUSE_NOT_MEASURABLE",
    "NOT_MEASURED_DISPLAY",
    "build_measured_figure",
    "measured_figure_view",
]
