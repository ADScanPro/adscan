"""Assessed vs discovered domains — the single source of truth for report scope.

A scan touches two very different kinds of domain and, until this module
existed, the reports counted them identically:

* **Assessed** — ADscan authenticated against the domain and enumerated it.
  Everything the report says about that domain rests on collected evidence.
* **Discovered** — ADscan learned the domain EXISTS, almost always by reading a
  trust off an assessed domain, and never enumerated it. Nothing was collected,
  nothing was tested, and the domain appears nowhere in the body of the report.

Both end up as a key under ``technical_report.json`` ``domains``: the write-side
recorders create the entry the moment any producer names the domain, and the
report pipeline stamps report-time blocks such as ``exposure_score`` onto every
entry regardless. So ``len(domains)`` counts a discovered domain as covered
ground — a kit whose body only ever mentions ``essos.local`` carried "3 scoped"
on its cover and "3 DOMAINS (…)" in every page footer. A reader who checks the
two extra names finds no evidence behind them and stops trusting the rest of the
document, which is the opposite of what a "validated, not estimated" product can
afford.

The classification is deliberately two-layered:

1. **Recorded fact wins.** ``entry["assessment"]["enumerated"]`` is stamped by
   the report pipeline from the workspace itself (did the collector produce an
   attack graph for this domain?), so the answer is something ADscan observed,
   not something it inferred.
2. **Evidence inference is the fallback** for artifacts written before the
   marker existed. Only evidence that a producer actually collected something
   counts. Report-time blocks (``exposure_score``, ``exposure_kpis``,
   ``compliance``) are stamped onto EVERY entry by the report run itself, so
   they say nothing about whether the domain was assessed and are excluded on
   purpose — treating them as evidence would classify every phantom domain as
   assessed and reintroduce the bug.
3. **Inference never reports zero coverage.** If no marker was recorded and no
   domain looks assessed, every known domain is treated as assessed. An
   assessment that found nothing worth recording is still an assessment, and
   calling its only domain "not enumerated" would be a false claim in the
   opposite direction. So the split only ever narrows the count when there is a
   distinguishable assessed set to narrow it to.

Discovered domains are not noise to be dropped. An unenumerated trusted domain
is real, unmeasured attack surface, and naming it is worth more to the client
than silently omitting it. The rule is only that it must never be counted as
coverage.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

#: Top-level keys in the renderer ``report_data`` mapping (and in
#: ``technical_report.json`` ``domains``) that are NOT domains. The mapping is
#: otherwise ``{domain_name: {...}}``; these ride alongside as workspace-scoped
#: blocks. Every loop that treats each value as a domain must skip them.
RESERVED_REPORT_DATA_KEYS = frozenset(
    {"environment_changes", "attack_fanout_rollup", "post_compromise_obligations"}
)

#: The per-domain block that records whether the domain was actually enumerated.
ASSESSMENT_KEY = "assessment"

#: Per-domain keys whose presence proves a producer COLLECTED something for the
#: domain. Deliberately excludes ``exposure_score`` / ``exposure_kpis`` /
#: ``compliance``: those are stamped at report time onto every entry.
_COLLECTION_EVIDENCE_KEYS: tuple[str, ...] = (
    "findings",
    "vulnerabilities",
    "attack_paths",
    "control_evidence",
    "events",
    "collection_coverage",
    "collection_stats",
)


@dataclass(frozen=True)
class DomainScope:
    """The assessed / discovered split for one report.

    ``assessed`` is what the headline count must mean: the domains this
    engagement actually enumerated. ``discovered`` is the trusted domains whose
    existence the assessment established without testing them.
    """

    assessed: tuple[str, ...] = ()
    discovered: tuple[str, ...] = ()

    @property
    def assessed_count(self) -> int:
        """Number of domains ADscan authenticated against and enumerated."""
        return len(self.assessed)

    @property
    def discovered_count(self) -> int:
        """Number of domains reached only as a name (typically over a trust)."""
        return len(self.discovered)

    @property
    def total_count(self) -> int:
        """Every domain the engagement knows about, assessed or not."""
        return self.assessed_count + self.discovered_count

    @property
    def has_discovered(self) -> bool:
        """True when at least one domain was named but never enumerated."""
        return bool(self.discovered)


def is_report_domain_key(name: Any, value: Any) -> bool:
    """Return True when ``(name, value)`` is a real domain entry to iterate."""
    return isinstance(value, dict) and name not in RESERVED_REPORT_DATA_KEYS


def has_collection_evidence(entry: Any) -> bool:
    """Return True when a report domain block carries collected data.

    The inference fallback, and the secondary signal the workspace-aware
    resolver uses. Only keys a PRODUCER writes count — see the module docstring
    on why the report-time blocks are excluded.
    """
    if not isinstance(entry, Mapping):
        return False
    for key in _COLLECTION_EVIDENCE_KEYS:
        value = entry.get(key)
        if isinstance(value, (list, dict, tuple)) and len(value) > 0:
            return True
    return False


def domain_was_assessed(entry: Mapping[str, Any]) -> bool:
    """Return True when *entry* describes a domain the engagement enumerated.

    Prefers the recorded ``assessment.enumerated`` fact; falls back to
    collection evidence for artifacts written before the marker existed.
    """
    if not isinstance(entry, Mapping):
        return False
    marker = entry.get(ASSESSMENT_KEY)
    if isinstance(marker, Mapping):
        enumerated = marker.get("enumerated")
        if isinstance(enumerated, bool):
            return enumerated
    return has_collection_evidence(entry)


def classify_report_domains(domains: Mapping[str, Any] | None) -> DomainScope:
    """Split a report's domain mapping into assessed and discovered names.

    Accepts either shape the pipelines carry: the raw ``technical_report.json``
    ``domains`` block (``findings`` / ``control_evidence`` / ``events``) or the
    renderer's ``report_data`` (``vulnerabilities`` / ``attack_paths``), with
    reserved non-domain keys skipped. Order is the mapping's own, so the report
    lists domains in the order the scan met them.
    """
    if not isinstance(domains, Mapping):
        return DomainScope()
    assessed: list[str] = []
    discovered: list[str] = []
    any_recorded = False
    for name, entry in domains.items():
        if not is_report_domain_key(name, entry):
            continue
        label = str(name).strip()
        if not label:
            continue
        marker = entry.get(ASSESSMENT_KEY)
        if isinstance(marker, Mapping) and isinstance(marker.get("enumerated"), bool):
            any_recorded = True
        (assessed if domain_was_assessed(entry) else discovered).append(label)

    # Inference-only artifact where nothing looks assessed: keep the previous
    # behaviour rather than reporting zero coverage. The split exists to separate
    # an assessed domain from one reached only over a trust, and with no assessed
    # domain to separate FROM there is nothing to separate — an assessment that
    # found no finding worth recording is still an assessment, and calling its
    # only domain "not enumerated" would be a new false claim in the other
    # direction. A recorded marker is always honoured, so this never overrides an
    # observed fact.
    if not assessed and not any_recorded:
        return DomainScope(assessed=tuple(discovered))
    return DomainScope(assessed=tuple(assessed), discovered=tuple(discovered))


def format_domain_scope_label(scope: DomainScope) -> str:
    """Return the cover/footer label for a scope, e.g. ``"1 assessed · 2 discovered"``.

    The assessed figure leads because that is the number a reader takes as
    coverage. Discovered domains are named as a separate, smaller fact rather
    than folded into the same total.
    """
    label = f"{scope.assessed_count} assessed"
    if scope.discovered_count:
        label = f"{label} · {scope.discovered_count} discovered"
    return label


def format_discovered_domains_note(scope: DomainScope) -> str:
    """Return a client-facing sentence naming the unenumerated trusted domains.

    Empty when every known domain was assessed. The wording states the fact and
    its consequence — untested surface — without dressing it up as a finding.
    """
    if not scope.discovered:
        return ""
    names = ", ".join(scope.discovered)
    if scope.discovered_count == 1:
        return (
            "One further domain was reached through a trust relationship but not "
            f"enumerated in this engagement: {names}. Its exposure is unmeasured "
            "and is not reflected in any figure in this report."
        )
    return (
        f"{scope.discovered_count} further domains were reached through trust "
        "relationships but not enumerated in this engagement: "
        f"{names}. Their exposure is unmeasured and is not reflected in any "
        "figure in this report."
    )
