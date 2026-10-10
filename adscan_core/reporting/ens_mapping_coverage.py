"""What share of the ENS regime an assessment actually measures, stated once.

The compliance section of a Security Assessment Report prints a conformance
figure over the Anexo II measures this engine maps. Eleven of the annex's 73
measures are mapped at all, because the other 62 are organisational, physical or
personnel measures that no reading of Active Directory can evidence. A
denominator of ten or eleven left unexplained reads as if it were the ENS, so the
share is stated rather than implied.

Two things make that statement a shared derivation rather than a sentence beside
one renderer.

The first is that the exigible total MOVES. Anexo II holds 73 measures; 52 are
required at every category, and a declared scope resolves the rest up or down
(a CCN-STIC 890A system at BAJO in all five dimensions is exigible for 38). So
the same document on two clients prints two denominators, and a reader comparing
them can only tell why if the figure says what it is a fraction of.

The second is that two paid documents in one kit print it. The Security
Assessment Report states it inside its ENS scope header; the AD Control Coverage
Report needs it because it counts control AREAS and otherwise never says what
share of the regime those areas are. Written twice, the two would eventually
disagree, which is the drift this repo keeps paying for. So the FIGURES are
derived here, once, and each document reads the register written for its
audience from the same block.

:func:`build_ens_mapping_coverage` is the whole surface. It takes the resolved
applicability of the scope the assessment ran against, plus the measure ids this
engine maps, and returns the figures and both registers. Pure logic: no IO, no
console, no network, and no knowledge of which document is asking.
"""

from __future__ import annotations

from typing import Any, Iterable

from adscan_core.reporting.ens_applicability import (
    ApplicabilityState,
    anexo_ii_measure_ids,
)

#: Key this block is carried under inside an ENS scope header. One name, so the
#: producer and every reader cannot drift apart on where it lives.
MAPPING_COVERAGE_KEY = "mapping_coverage"

#: The exigible total follows the client's declared scope.
BASIS_DECLARED = "declared_scope"

#: Nothing is declared, so the exigible total is the common core: the measures
#: Anexo II requires at every category. Honest without implying a category.
BASIS_COMMON_CORE = "common_core"

#: No measure carries a verdict at all (an unsupported normative version, a
#: profile whose own table this build does not hold, a scope out of the declared
#: profile's scope of application). There is no fraction to state, so none is.
BASIS_UNRESOLVED = "unresolved"


def _unmeasurable_clause(remaining: int, *, here: bool) -> str:
    """The clause naming what the engine cannot reach, in one of two registers."""
    if remaining == 1:
        subject = "The remaining measure is an organisational, physical or personnel measure"
    else:
        subject = (
            f"The remaining {remaining:,} are organisational, physical or "
            "personnel measures"
        )
    verb = (
        "so it is" if remaining == 1 else "so they are"
    ) if here else (
        "and is" if remaining == 1 else "and are"
    )
    tail = (
        "neither assessed here nor reported as satisfied"
        if here
        else "neither assessed nor reported as conformant"
    )
    return (
        f"{subject} that cannot be observed from Active Directory, "
        f"{verb} {tail}."
    )


def _assessment_statement(
    *, basis: str, measured: int, exigible: int, remaining: int
) -> str:
    """The register the Security Assessment Report's scope header prints.

    Reads as a clause inside the per-state breakdown that precedes it, which is
    why it opens on the assessment rather than on the annex.
    """
    if basis == BASIS_UNRESOLVED:
        return ""
    if basis == BASIS_COMMON_CORE:
        opening = (
            f"This assessment measures {measured:,} of the {exigible:,} "
            "measures Anexo II requires at every system category, which are "
            "the ones it assesses while no category is declared."
        )
    else:
        opening = (
            f"This assessment measures {measured:,} of the {exigible:,} Anexo "
            "II measures exigible for this system."
        )
    return f"{opening} {_unmeasurable_clause(remaining, here=False)}"


def _coverage_statement(
    *,
    basis: str,
    measured: int,
    exigible: int,
    remaining: int,
    annex_total: int,
    undeclared: int,
) -> str:
    """The register the AD Control Coverage Report prints.

    Written for procurement and for an auditor reading two coverage reports side
    by side, so it opens on the annex, names the exigible total as a fraction of
    it, and closes by saying that the total follows the scope. Without that last
    sentence the figure moves between two clients with nothing on the page
    accounting for it.
    """
    if basis == BASIS_UNRESOLVED:
        return ""
    annex = (
        f"Anexo II of the ENS holds {annex_total:,} security measures."
    )
    if basis == BASIS_COMMON_CORE:
        body = (
            "No system category is declared for this assessment, so it covers "
            f"the {exigible:,} measures Anexo II requires at every category, "
            f"and this report measures {measured:,} of them."
        )
        closing = (
            f"Declaring the scope resolves the other {undeclared:,} measures "
            f"and moves the exigible total up or down from {exigible:,}."
        )
    else:
        body = (
            f"Of those, {exigible:,} are exigible for the system declared for "
            f"this assessment, and this report measures {measured:,} of them."
        )
        closing = (
            "The exigible total follows the declared scope, so a report on a "
            "system scoped differently states a different one."
        )
    return (
        f"{annex} {body} {_unmeasurable_clause(remaining, here=True)} {closing}"
    )


def build_ens_mapping_coverage(
    resolution: Any, mapped_measure_ids: Iterable[str]
) -> dict[str, Any]:
    """Return the regime-coverage block for one resolved ENS scope.

    Args:
        resolution: The :class:`~adscan_core.reporting.ens_applicability.EnsScopeResolution`
            for the scope the assessment ran against.
        mapped_measure_ids: The Anexo II measure ids this engine maps to a
            check. Passed in rather than imported, because the mapping is a PRO
            report asset and this module stays in ``adscan_core``, which the
            appliance ships whole and the web backend can import.

    Returns:
        The figures, the resolved ``basis``, and both registers
        (``statement`` for the Security Assessment Report's scope header,
        ``coverage_statement`` for the AD Control Coverage Report). Both are
        empty strings when no measure carries a verdict, because there is then
        no fraction to state and printing "0 of 0" would be worse than silence.
    """
    annex_ids = set(anexo_ii_measure_ids())
    mapped = {str(mid) for mid in mapped_measure_ids or ()} & annex_ids
    measures = getattr(resolution, "measures", {}) or {}
    required = {
        measure_id
        for measure_id, measure in measures.items()
        if getattr(measure, "state", None) is ApplicabilityState.REQUIRED
    }
    undeclared = sum(
        1
        for measure in measures.values()
        if getattr(measure, "state", None)
        is ApplicabilityState.EXIGIBILITY_UNDECLARED
    )
    declared = bool(getattr(resolution, "declared", False))

    measured = len(required & mapped)
    remaining = len(required - mapped)
    if not required:
        basis = BASIS_UNRESOLVED
    elif declared:
        basis = BASIS_DECLARED
    else:
        basis = BASIS_COMMON_CORE

    return {
        "basis": basis,
        "declared": declared,
        "anexo_ii_total": len(annex_ids),
        "mapped_total": len(mapped),
        "unmapped_total": len(annex_ids) - len(mapped),
        "required_total": len(required),
        "required_and_mapped_total": measured,
        "required_and_unmapped_total": remaining,
        "exigibility_undeclared_total": undeclared,
        "statement": _assessment_statement(
            basis=basis,
            measured=measured,
            exigible=len(required),
            remaining=remaining,
        ),
        "coverage_statement": _coverage_statement(
            basis=basis,
            measured=measured,
            exigible=len(required),
            remaining=remaining,
            annex_total=len(annex_ids),
            undeclared=undeclared,
        ),
    }


__all__ = [
    "BASIS_COMMON_CORE",
    "BASIS_DECLARED",
    "BASIS_UNRESOLVED",
    "MAPPING_COVERAGE_KEY",
    "build_ens_mapping_coverage",
]
