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

import json
import os
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from adscan_core.workspace_domain_buckets import is_reserved_domain_bucket

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


#: Workspace layout the collector writes: ``<workspace>/domains/<domain>/attack_graph.json``.
WORKSPACE_DOMAINS_DIR = "domains"
ATTACK_GRAPH_FILENAME = "attack_graph.json"
TECHNICAL_REPORT_FILENAME = "technical_report.json"


def domain_collection_verdict(
    *, graph_present: bool, report_entry: Any = None
) -> tuple[bool, str]:
    """Return ``(enumerated, basis)`` from what the workspace holds for one domain.

    The one rule for "did this engagement enumerate the domain" when no marker
    has been recorded yet. The collector's own attack graph is decisive and is
    checked first, because a perfectly clean assessed domain carries no
    findings and would otherwise read as untested. Collected report evidence is
    the secondary signal. Shared by the engine resolver that WRITES the marker
    (``report_attack_paths.resolve_domain_assessment``) and by the workspace
    reader below, so the verdict a surface reads cannot differ from the one the
    report recorded.
    """
    if graph_present:
        return True, "attack_graph"
    if has_collection_evidence(report_entry):
        return True, "report_evidence"
    return False, "no_collection_evidence"


def workspace_domain_graph_present(workspace_dir: str | os.PathLike[str], domain: str) -> bool:
    """Return True when the collector wrote an attack graph for *domain*.

    Domain names are case-insensitive while the filesystem is not, and the
    collector writes the directory in lower case, so both spellings are tried.
    """
    label = str(domain or "").strip().rstrip(".")
    if not label:
        return False
    root = os.path.join(os.fspath(workspace_dir), WORKSPACE_DOMAINS_DIR)
    return any(
        os.path.isfile(os.path.join(root, candidate, ATTACK_GRAPH_FILENAME))
        for candidate in dict.fromkeys((label, label.lower()))
    )


def _load_report_domains(workspace_dir: str | os.PathLike[str]) -> Mapping[str, Any]:
    path = os.path.join(os.fspath(workspace_dir), TECHNICAL_REPORT_FILENAME)
    try:
        with open(path, encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, ValueError):
        return {}
    domains = report.get("domains") if isinstance(report, Mapping) else None
    return domains if isinstance(domains, Mapping) else {}


def resolve_workspace_domain_scope(
    workspace_dir: str | os.PathLike[str],
    domain_names: Iterable[str] = (),
    *,
    report_domains: Mapping[str, Any] | None = None,
) -> DomainScope:
    """Split every domain a workspace knows into assessed and discovered.

    The workspace-backed form of :func:`classify_report_domains`, for a reader
    that holds a list of domain NAMES from somewhere other than the report (the
    web's domain list, its trust partners, its persisted domain rows) and must
    not count one the engagement only learned of across a trust. Each name is
    classified by the same ladder the report uses: the recorded
    ``assessment.enumerated`` marker in ``technical_report.json`` wins, then
    :func:`domain_collection_verdict` over the collector's own output. Domains
    the report names are classified too, so a caller passing no names gets the
    report's own split.

    Reserved storage buckets are never domains and are dropped. Names compare
    case-insensitively; the first spelling seen is kept. As in
    :func:`classify_report_domains`, inference never reports zero coverage: with
    no recorded marker and nothing that looks assessed, every name is assessed.
    """
    if report_domains is None:
        report_domains = _load_report_domains(workspace_dir)
    entries = {
        str(name).strip().lower(): entry
        for name, entry in report_domains.items()
        if is_report_domain_key(name, entry)
    }

    ordered: dict[str, str] = {}
    for name in [*domain_names, *report_domains.keys()]:
        label = str(name or "").strip().rstrip(".")
        if not label or is_reserved_domain_bucket(label) or label in RESERVED_REPORT_DATA_KEYS:
            continue
        ordered.setdefault(label.lower(), label)

    assessed: list[str] = []
    discovered: list[str] = []
    any_recorded = False
    for key, label in ordered.items():
        entry = entries.get(key)
        marker = entry.get(ASSESSMENT_KEY) if isinstance(entry, Mapping) else None
        if isinstance(marker, Mapping) and isinstance(marker.get("enumerated"), bool):
            any_recorded = True
            enumerated = bool(marker["enumerated"])
        else:
            enumerated, _basis = domain_collection_verdict(
                graph_present=workspace_domain_graph_present(workspace_dir, label),
                report_entry=entry,
            )
        (assessed if enumerated else discovered).append(label)

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


def format_discovered_domains_note(
    scope: DomainScope, *, engagement_scope: Mapping[str, Any] | None = None
) -> str:
    """Return a client-facing sentence naming the unenumerated trusted domains.

    Empty when every known domain was assessed and the scope record withheld
    nothing. The wording states the fact and its consequence — untested
    surface — without dressing it up as a finding. With the workspace scope
    record (``engagement_scope``, the engine's ``scope.json``) it also states
    how the engagement scope was decided and which cross-domain routes it kept
    from running (``adscan_core.reporting.engagement_scope``).
    """
    from adscan_core.reporting.engagement_scope import (  # noqa: PLC0415
        format_engagement_scope_note,
    )

    scope_note = format_engagement_scope_note(engagement_scope)
    if not scope.discovered:
        return scope_note
    return " ".join(
        part for part in (_discovered_sentence(scope), scope_note) if part
    )


def _discovered_sentence(scope: DomainScope) -> str:
    """The sentence naming the trusted domains reached but not enumerated."""
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
