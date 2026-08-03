"""Client-facing names for the two scores a finding can carry.

One vocabulary, declared once, so no surface in the deliverable can call a
number something it is not. The report's scoring methodology section already
introduces both names to the reader; every table header, chip, bullet and
column that shows a score reads from here instead of hard-coding a word.

Two scores, and only one of them is CVSS:

* :data:`CVSS_BASE_LABEL` — the FIRST-calculable Base score, and it exists only
  where the finding carries a Base vector to recompute it from
  (:func:`adscan_core.cvss.vector_score.score_from_vector`).
* :data:`ADSCAN_PRIORITY_LABEL` — ADscan's own severity model: the catalog
  baseline plus the environmental overlay (Tier-0 exposure, DC targeting,
  confirmed exploitation). Every finding has one. It is what the report ranks
  and schedules by, and it is never a CVSS score.
"""

from __future__ import annotations

#: The ADscan-derived priority score, as the client reads it.
ADSCAN_PRIORITY_LABEL = "ADscan Priority"

#: Short form for a table column or a compact chip where the row context
#: already establishes what is being scored.
ADSCAN_PRIORITY_SHORT_LABEL = "Priority"

#: The formal CVSS Base score. Only ever printed next to a Base vector.
CVSS_BASE_LABEL = "CVSS Base"

#: The threshold prose the compliance section uses to split major from minor
#: non-conformities. Named here so the section cannot drift back to "CVSS".
PRIORITY_THRESHOLD_NOUN = "ADscan Priority"

__all__ = [
    "ADSCAN_PRIORITY_LABEL",
    "ADSCAN_PRIORITY_SHORT_LABEL",
    "CVSS_BASE_LABEL",
    "PRIORITY_THRESHOLD_NOUN",
]
