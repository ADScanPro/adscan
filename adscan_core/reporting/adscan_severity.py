"""The ADscan severity a client surface rates a finding by, read in one place.

A finding is rated in two layers. A BASELINE band is authored per key in the
finding catalog and recorded as ``severity``: what the technique is worth in any
directory. A CONTEXTUAL overlay then raises it for what this assessment actually
observed, such as a Tier-0 account or a domain controller inside the finding's
scope, or a technique carried through to a result.

Both layers are real and the deliverable discloses both. What this module owns is
which of the two a CLIENT SURFACE COUNTS ON, and the answer is the contextual
one: the figure the reader is told to plan from is the figure the counts, the
chips and the posture score have to be grouped by, or the document asks the
reader to plan from a number it never totals.

Why it is a reader and not a computation
----------------------------------------
The overlay used to be re-derived at each surface that printed it, and the
failure mode was always the same: ONE scan produced a different critical count in
each document of one kit, because one page applied the lift and the next printed
the baseline underneath it. So the band is computed ONCE, at the artifact write
(``technical_report.stamp_adscan_severity``), and every surface READS it here.

Recomputing the overlay to produce a count is therefore the one thing a caller
must not do, however convenient a local ``compute_finding_severity`` call looks:
it is the defect this module exists to close, and it comes back silently, as a
figure that disagrees with the figure on the facing page.

What raised it, and whether anything did
----------------------------------------
The rating carries whether this assessment's context raised it, and a surface
that prints an explanation for the lift must take that from the rating rather
than deciding for itself. Deciding locally needs the baseline the overlay built
on, and a deployment without the finding catalog cannot resolve one: against a
baseline of zero a rule that would never move the real one appears to move it,
and the surface then explains a lift the scan recorded as never happening.

Absent is not Informational
---------------------------
An old workspace, and a finding whose rating could not be resolved, carry NONE of
:data:`ADSCAN_SEVERITY_FIELDS`. That is a different fact from a finding rated
``info``, and the two stay distinguishable by the field's PRESENCE alone. On
absence a reader degrades to the recorded baseline band, which is exactly what
every surface counted before the rating was persisted, so an old artifact renders
as it always did rather than losing its findings to a substituted default.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

#: The contextual band: ``critical`` / ``high`` / ``medium`` / ``low`` / ``info``.
ADSCAN_SEVERITY_FIELD = "adscan_severity"
#: The contextual numeric the band was derived from.
ADSCAN_PRIORITY_SCORE_FIELD = "adscan_priority_score"
#: The baseline numeric the overlay built on.
ADSCAN_BASELINE_SCORE_FIELD = "adscan_baseline_score"
#: Whether the context raised the rating above its baseline.
ADSCAN_SEVERITY_ELEVATED_FIELD = "adscan_severity_elevated"

#: Every field the stamper writes, as one tuple a consumer can iterate (and a
#: test can assert the absence of).
ADSCAN_SEVERITY_FIELDS = (
    ADSCAN_SEVERITY_FIELD,
    ADSCAN_PRIORITY_SCORE_FIELD,
    ADSCAN_BASELINE_SCORE_FIELD,
    ADSCAN_SEVERITY_ELEVATED_FIELD,
)

#: The published band vocabulary. Anything else is not a band this product rates
#: in, so it is read as unrated rather than coerced into one.
ADSCAN_SEVERITY_BANDS = frozenset({"critical", "high", "medium", "low", "info"})

#: Worst-first order, so a band can be ranked without re-deriving the vocabulary.
_BAND_ORDER = ("critical", "high", "medium", "low", "info")
_BAND_RANK: dict[str, int] = {band: rank for rank, band in enumerate(_BAND_ORDER)}


@dataclass(frozen=True)
class AuthoredAdscanRating:
    """The rating one scan authored onto one finding record."""

    #: The contextual band every client surface counts the finding under.
    band: str
    #: The contextual numeric behind that band.
    score: float
    #: The baseline numeric the overlay built on.
    baseline: float
    #: Whether this assessment's own context raised the rating above the
    #: baseline. ``False`` means the two agree, so no "raised because" claim
    #: belongs on the finding, and a surface that carries such a line must
    #: read this rather than deciding for itself.
    elevated: bool


def context_raised_rating(score: float, baseline: float) -> bool:
    """Return whether a contextual *score* sits above its *baseline*.

    The rule the stamper applies when it writes the flag, exposed so a surface
    holding the two numerics without the flag resolves it identically rather
    than inlining its own comparison. A persisted row is the case that needs
    it: the platform stores both numerics in columns and no flag.

    Args:
        score: The contextual numeric.
        baseline: The numeric the overlay built on.

    Returns:
        ``True`` when the context moved the rating.
    """
    return float(score) > float(baseline)


def _normalized_band(value: Any) -> str:
    """Return *value* as a published band, or ``""`` when it is not one."""
    band = str(value or "").strip().lower()
    return band if band in ADSCAN_SEVERITY_BANDS else ""


def authored_adscan_rating(finding: Mapping[str, Any]) -> AuthoredAdscanRating | None:
    """Return the rating the scan authored on *finding*, or ``None``.

    ``None`` means the artifact does not carry one, which happens for an older
    workspace and for a finding the scan could not rate. The caller then
    degrades to its own documented fallback, never to a substituted default.

    Args:
        finding: One finding record from ``technical_report.json``.

    Returns:
        The authored rating, or ``None`` when it is absent or malformed.
    """
    if not isinstance(finding, Mapping):
        return None
    band = _normalized_band(finding.get(ADSCAN_SEVERITY_FIELD))
    if not band:
        return None
    try:
        score = float(finding.get(ADSCAN_PRIORITY_SCORE_FIELD))  # type: ignore[arg-type]
        baseline = float(finding.get(ADSCAN_BASELINE_SCORE_FIELD))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    # A record written before the flag existed still carries both numerics, and
    # they answer the same question, so derive it rather than discard an
    # otherwise complete rating or report it as unraised when it was raised.
    raised = finding.get(ADSCAN_SEVERITY_ELEVATED_FIELD)
    elevated = (
        bool(raised)
        if raised is not None
        else context_raised_rating(score, baseline)
    )
    return AuthoredAdscanRating(
        band=band, score=score, baseline=baseline, elevated=elevated
    )


def recorded_baseline_severity(
    finding: Mapping[str, Any], *, fallback: str = ""
) -> str:
    """Return *finding*'s BASELINE band, what the technique is worth anywhere.

    The deliverable still discloses this beside the rating it counts by, so a
    reader can see that a Critical in this directory is a High technique the
    directory's own conditions lifted. It is NOT what any count groups by.

    Args:
        finding: One finding record from ``technical_report.json``.
        fallback: Returned when the record carries no published band.

    Returns:
        A published band, or *fallback*.
    """
    if not isinstance(finding, Mapping):
        return fallback
    return _normalized_band(finding.get("severity")) or fallback


def reported_finding_severity(finding: Mapping[str, Any], *, fallback: str = "") -> str:
    """Return the band a client surface counts *finding* under.

    This is the ONE reader every counter, chip, bar and rollup in the paid
    deliverable and the free report resolves through, so no two of them can
    group on a different layer of the rating.

    Args:
        finding: One finding record from ``technical_report.json``.
        fallback: Returned when neither the authored rating nor a recorded
            baseline band is present. Defaults to ``""`` so a caller with no
            sensible default gets an empty string rather than an invented band.

    Returns:
        A published band, or *fallback*.
    """
    rating = authored_adscan_rating(finding)
    if rating is not None:
        return rating.band
    return recorded_baseline_severity(finding, fallback=fallback)


def severity_band_rank(band: str) -> int:
    """Return a worst-first sort rank for *band* (an unknown band sorts last)."""
    return _BAND_RANK.get(str(band or "").strip().lower(), len(_BAND_RANK))


__all__ = [
    "ADSCAN_BASELINE_SCORE_FIELD",
    "ADSCAN_PRIORITY_SCORE_FIELD",
    "ADSCAN_SEVERITY_BANDS",
    "ADSCAN_SEVERITY_ELEVATED_FIELD",
    "ADSCAN_SEVERITY_FIELD",
    "ADSCAN_SEVERITY_FIELDS",
    "AuthoredAdscanRating",
    "authored_adscan_rating",
    "context_raised_rating",
    "recorded_baseline_severity",
    "reported_finding_severity",
    "severity_band_rank",
]
