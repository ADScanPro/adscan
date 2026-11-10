"""Project the attack graph's AD CS edges into the exposures a client reads.

Why this exists
---------------
The collector writes two things. ``attack_graph.json`` holds the AD CS edges
the whole platform derives from: the actor principal, what it compromises, and
the PKI object it abuses. ``inventory/adcs_attack_steps.json`` holds the raw
per-``(principal × object)`` enrollment-rights records, before the engine's
Tier-0 source suppression and before the compromise-centric projection that
turns them into edges.

The second is an engine handoff. Counting it as client-facing exposure is a
measured defect: on one real two-domain workspace it reported 246 "AD CS paths"
where the graph holds 45 escalation steps over 42 affected objects, and 226 of
the 246 were sourced from Domain Admins or Enterprise Admins, which is how AD
works rather than an exposure. This module takes graph edges only.

The unit
--------
An AD CS **exposure** is one ``(domain, technique, affected object)``. That is
the thing an administrator changes: a certificate template, an enrollment
service, an AIA or root CA, the NTAuth store, or, for the mapping abuses, the
principal whose ``altSecurityIdentities`` is writable. The principals who can
reach it are carried on the exposure as detail, never as a multiplier: one
template that four groups can rewrite is one template to fix.

An **escalation step** is one graph edge. Both counts are reported, because
they answer different questions and a client comparing this page against the
attack-path page needs to know which is which. Neither is a path: a path is a
route through several steps and is counted elsewhere.

Pure logic: stdlib only, no IO, no console, no network. Safe to import from
``adscan_core``, the LITE runtime, the PRO report renderer and the web backend
alike.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final, Iterable, Mapping, Sequence

from adscan_core.adcs_relations import is_adcs_pki_object_kind, is_adcs_relation
from adscan_core.reporting.principal_display import format_graph_node_label

#: Step / edge statuses that mean the escalation actually ran. Spans the three
#: status vocabularies' proven tokens, the same set the rest of the reporting
#: layer uses (``adcs_finding_state``, ``user_exposure_ranking``).
_PROVEN_STATUSES: Final[frozenset[str]] = frozenset(
    {"success", "exploited", "domain_compromised"}
)


@dataclass(frozen=True)
class AdcsExposure:
    """One ``(domain, technique, affected object)`` exposure."""

    domain: str
    technique: str
    object_name: str
    object_kind: str
    #: Distinguished name of the affected object when the edge carried one.
    object_dn: str | None = None
    #: The object's client-facing name. A template or authority keeps its
    #: directory name verbatim; a principal goes through the shared display
    #: humanizer (``jorah.mormont``, never ``JORAH.MORMONT@ESSOS.LOCAL``).
    #: ``object_name`` stays the raw identifier, used for matching.
    object_display: str = ""
    #: Principals that can reach this object through this technique, as the
    #: graph's own source labels. Detail, not a multiplier.
    actors: tuple[str, ...] = ()
    #: What the escalation reaches once used, as the graph's target labels.
    reaches: tuple[str, ...] = ()
    #: Highest severity among the contributing edges, as the graph stamped it.
    severity: str = ""
    #: Number of graph edges that contributed to this exposure.
    escalation_steps: int = 0
    #: ``True`` when at least one contributing edge ran to completion.
    executed: bool = False

    @property
    def is_pki_object(self) -> bool:
        """Whether the affected object is PKI configuration."""
        return is_adcs_pki_object_kind(self.object_kind)


@dataclass(frozen=True)
class AdcsTechniqueTally:
    """Per-technique counts, both units side by side."""

    technique: str
    exposures: int
    escalation_steps: int
    executed_escalation_steps: int


@dataclass(frozen=True)
class AdcsExposureView:
    """The whole projection, ready to serialize."""

    exposures: tuple[AdcsExposure, ...] = ()
    techniques: tuple[AdcsTechniqueTally, ...] = ()
    escalation_step_count: int = 0
    executed_escalation_count: int = 0
    #: AD CS edges the engine kept in the graph but marked as no client finding
    #: (``notes.client_finding is False``): a Tier 0 holder over its own estate,
    #: such as a CA host's machine account administering its own CA. They stay
    #: in the graph as attack-path stepping stones and are never counted here.
    withheld_escalation_count: int = 0

    @property
    def exposure_count(self) -> int:
        """Distinct ``(domain, technique, affected object)`` count."""
        return len(self.exposures)

    @property
    def technique_count(self) -> int:
        """Distinct AD CS techniques with at least one exposure."""
        return len(self.techniques)

    @property
    def pki_object_count(self) -> int:
        """Distinct PKI configuration objects affected, across techniques."""
        return len(
            {
                (
                    exposure.domain,
                    exposure.object_kind.lower(),
                    exposure.object_name.lower(),
                )
                for exposure in self.exposures
                if exposure.is_pki_object
            }
        )


_SEVERITY_RANK: Final[dict[str, int]] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def _worst_severity(left: str, right: str) -> str:
    """Return whichever severity token ranks higher, preferring a known one."""
    if _SEVERITY_RANK.get(right.strip().lower(), 0) > _SEVERITY_RANK.get(
        left.strip().lower(), 0
    ):
        return right
    return left


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _clean(value: Any) -> str:
    return str(value or "").strip()


#: Prefix the attack graph puts on a node ID (``name:jorah.mormont``,
#: ``name:S-1-5-32-548``). An ID is a key, never a display label.
_NODE_ID_PREFIX = "name:"


def _display_principal(label: str, domain: str) -> str:
    """Return a principal's client-facing name through the shared humanizer.

    Routes through ``format_graph_node_label``, the SSOT the PDF report graph
    and the rest of the web CTEM already use, so this page cannot name a
    principal differently from them. A raw node ID is unwrapped first, so a
    well-known SID still resolves to its name (``S-1-5-11`` reads
    "Authenticated Users").
    """
    raw = _clean(label)
    if raw.lower().startswith(_NODE_ID_PREFIX):
        raw = raw[len(_NODE_ID_PREFIX) :]
    if not raw:
        return ""
    return format_graph_node_label(raw, domain or None) or raw


def _display_object(name: str, kind: str, domain: str) -> str:
    """A PKI object keeps its directory name; a principal is humanized."""
    if is_adcs_pki_object_kind(kind):
        return name
    return _display_principal(name, domain) or name


def _affected_objects(notes: Mapping[str, Any]) -> list[tuple[str, str, str | None]]:
    """Return ``(name, kind, dn)`` for every object the edge's notes name.

    Reads ``vulnerable_resources``, which is where the detectors stamp the
    abused template / CA / victim principal (``attack_graph_core`` writes it
    from ``make_adcs_edge(template_node=...)``). Falls back to the legacy
    single-``template`` note, then to nothing — a caller that gets nothing
    keeps the edge under its target label rather than dropping it, because
    losing a mapped escalation is worse than naming it imprecisely.
    """
    objects: list[tuple[str, str, str | None]] = []
    seen: set[tuple[str, str]] = set()

    raw = notes.get("vulnerable_resources")
    if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes)):
        for entry in raw:
            entry_map = _as_mapping(entry)
            name = _clean(entry_map.get("name"))
            if not name:
                continue
            kind = _clean(entry_map.get("kind"))
            key = (name.lower(), kind.lower())
            if key in seen:
                continue
            seen.add(key)
            objects.append(
                (name, kind, _clean(entry_map.get("distinguished_name")) or None)
            )

    if objects:
        return objects

    legacy = _clean(notes.get("template"))
    if legacy:
        objects.append((legacy, "CertTemplate", None))
    return objects


def build_adcs_exposure_view(edges: Iterable[Mapping[str, Any]]) -> AdcsExposureView:
    """Project AD CS attack-graph edges into exposures and per-technique counts.

    Args:
        edges: Attack-graph edges, each a mapping with ``relation`` (or
            ``edge_type``), ``domain``, ``notes`` (the edge's notes dict, where
            ``vulnerable_resources`` lives), and optionally ``status``,
            ``source_label`` / ``from`` and ``target_label`` / ``to``.
            Non-AD CS relations are ignored, so a caller may pass the whole
            edge list.

    Returns:
        An :class:`AdcsExposureView`. Exposures are ordered by descending
        escalation-step count, then domain, then technique, then object name,
        so the object with the most ways in leads.
    """
    # Keyed by (domain, technique, object name lowered, object kind lowered).
    accumulator: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    escalation_step_count = 0
    executed_escalation_count = 0
    executed_by_technique: dict[str, int] = {}
    steps_by_technique: dict[str, int] = {}
    withheld_escalation_count = 0

    for edge in edges:
        edge_map = _as_mapping(edge)
        relation = _clean(edge_map.get("relation") or edge_map.get("edge_type"))
        if not is_adcs_relation(relation):
            continue

        notes = _as_mapping(edge_map.get("notes"))
        # The engine's own finding verdict, stamped at the graph-write seam by
        # the same gate the report's finding derivation applies. Only an
        # explicit ``False`` withholds: a graph written before the stamp existed
        # carries no verdict and keeps every edge, so an upgrade can never hide
        # a mapped escalation.
        if notes.get("client_finding") is False:
            withheld_escalation_count += 1
            continue
        domain = _clean(edge_map.get("domain")) or _clean(notes.get("domain"))
        status = _clean(edge_map.get("status"))
        executed = status.lower() in _PROVEN_STATUSES

        escalation_step_count += 1
        steps_by_technique[relation] = steps_by_technique.get(relation, 0) + 1
        if executed:
            executed_escalation_count += 1
            executed_by_technique[relation] = executed_by_technique.get(relation, 0) + 1

        # The graph node's own label first: it carries the realm
        # (``DOMAIN USERS@CORP``), which is what lets the humanizer render a
        # group in words and strip an intra-domain suffix. The engine's note
        # (often the bare ``DOMAIN USERS``) next, the node ID last. Humanized
        # whichever wins.
        actor = _display_principal(
            _clean(edge_map.get("source_label"))
            or _clean(notes.get("source_label"))
            or _clean(edge_map.get("from"))
            or _clean(edge_map.get("source_node")),
            domain,
        )
        reached = _display_principal(
            _clean(edge_map.get("target_label"))
            or _clean(notes.get("target_label"))
            or _clean(edge_map.get("to"))
            or _clean(edge_map.get("target_node")),
            domain,
        )
        severity = _clean(notes.get("severity"))

        objects = _affected_objects(notes)
        if not objects:
            # No named object: keep the escalation under what it reaches, so a
            # mapped step is never silently dropped from the client's view.
            objects = [(reached or relation, _clean(notes.get("target_kind")), None)]

        for name, kind, dn in objects:
            key = (domain, relation, name.lower(), kind.lower())
            slot = accumulator.get(key)
            if slot is None:
                slot = {
                    "domain": domain,
                    "technique": relation,
                    "object_name": name,
                    "object_kind": kind,
                    "object_dn": dn,
                    "object_display": _display_object(name, kind, domain),
                    "actors": [],
                    "reaches": [],
                    "severity": severity,
                    "escalation_steps": 0,
                    "executed": False,
                }
                accumulator[key] = slot
            slot["escalation_steps"] += 1
            slot["executed"] = bool(slot["executed"]) or executed
            slot["severity"] = _worst_severity(str(slot["severity"]), severity)
            if dn and not slot["object_dn"]:
                slot["object_dn"] = dn
            if actor and actor not in slot["actors"]:
                slot["actors"].append(actor)
            if reached and reached not in slot["reaches"]:
                slot["reaches"].append(reached)

    exposures = tuple(
        AdcsExposure(
            domain=str(slot["domain"]),
            technique=str(slot["technique"]),
            object_name=str(slot["object_name"]),
            object_kind=str(slot["object_kind"]),
            object_dn=slot["object_dn"],
            object_display=str(slot["object_display"]),
            actors=tuple(sorted(slot["actors"], key=str.lower)),
            reaches=tuple(sorted(slot["reaches"], key=str.lower)),
            severity=str(slot["severity"]),
            escalation_steps=int(slot["escalation_steps"]),
            executed=bool(slot["executed"]),
        )
        for slot in sorted(
            accumulator.values(),
            key=lambda item: (
                -int(item["escalation_steps"]),
                str(item["domain"]).lower(),
                str(item["technique"]).lower(),
                str(item["object_name"]).lower(),
            ),
        )
    )

    exposures_by_technique: dict[str, int] = {}
    for exposure in exposures:
        exposures_by_technique[exposure.technique] = (
            exposures_by_technique.get(exposure.technique, 0) + 1
        )

    techniques = tuple(
        AdcsTechniqueTally(
            technique=technique,
            exposures=count,
            escalation_steps=steps_by_technique.get(technique, 0),
            executed_escalation_steps=executed_by_technique.get(technique, 0),
        )
        for technique, count in sorted(
            exposures_by_technique.items(), key=lambda kv: (-kv[1], kv[0])
        )
    )

    return AdcsExposureView(
        exposures=exposures,
        techniques=techniques,
        escalation_step_count=escalation_step_count,
        executed_escalation_count=executed_escalation_count,
        withheld_escalation_count=withheld_escalation_count,
    )


def adcs_edge_from_web_row(
    *,
    edge_type: Any,
    domain: Any,
    status: Any,
    properties: Mapping[str, Any] | None,
    source_node: Any = "",
    target_node: Any = "",
) -> dict[str, Any]:
    """Map a persisted web attack-graph row onto the engine edge shape.

    The web ingestion stores an engine edge's ``notes`` under
    ``properties["graph_notes"]`` and its execution status under
    ``properties["graph_status"]``. The row's own ``status`` column is the web
    lifecycle and stays ``discovered`` for an edge the engine executed, so it
    is only a fallback here. Kept beside the projection so the CLI shape and
    the web shape are provably read the same way.
    """
    props = _as_mapping(properties)
    notes = props.get("graph_notes")
    return {
        "relation": _clean(edge_type),
        "domain": _clean(domain),
        "status": _clean(props.get("graph_status")) or _clean(status),
        "notes": notes if isinstance(notes, Mapping) else {},
        "source_label": _clean(props.get("source_label")),
        "target_label": _clean(props.get("target_label")),
        "source_node": _clean(source_node),
        "target_node": _clean(target_node),
    }


@dataclass(frozen=True)
class AdcsEnrollmentRightsTally:
    """Counts for the raw enrollment-rights inventory, as inventory.

    Deliberately carries no exposure language and no per-technique breakdown:
    it exists so a surface can say what the collector observed without any of
    it reading as a finding. Most of these holders normally already own the
    domain, which is why the count belongs beside the inventory and never in a
    risk figure.
    """

    record_count: int = 0
    holder_count: int = 0
    object_count: int = 0


def build_enrollment_rights_tally(
    rows: Iterable[Mapping[str, Any]],
) -> AdcsEnrollmentRightsTally:
    """Count enrollment-rights records, their holders and the objects they name.

    Args:
        rows: Mappings with ``source_name`` (the holder) and ``target_name``
            (the PKI object), the shape the collector's enrollment-rights
            inventory records use.
    """
    holders: set[str] = set()
    objects: set[str] = set()
    record_count = 0
    for row in rows:
        row_map = _as_mapping(row)
        record_count += 1
        holder = _clean(row_map.get("source_name")).lower()
        if holder:
            holders.add(holder)
        target = _clean(row_map.get("target_name")).lower()
        if target:
            objects.add(target)
    return AdcsEnrollmentRightsTally(
        record_count=record_count,
        holder_count=len(holders),
        object_count=len(objects),
    )


_EXPOSURE_FIELDS: Final[tuple[str, ...]] = (
    "domain",
    "technique",
    "object_name",
    "object_kind",
    "object_dn",
    "object_display",
    "severity",
    "escalation_steps",
    "executed",
)


def exposure_payload(exposure: AdcsExposure) -> dict[str, Any]:
    """Serialize one exposure for an API response."""
    payload: dict[str, Any] = {
        field_name: getattr(exposure, field_name) for field_name in _EXPOSURE_FIELDS
    }
    payload["actors"] = list(exposure.actors)
    payload["reaches"] = list(exposure.reaches)
    payload["is_pki_object"] = exposure.is_pki_object
    return payload


def technique_payload(tally: AdcsTechniqueTally) -> dict[str, Any]:
    """Serialize one per-technique tally for an API response."""
    return {
        "technique": tally.technique,
        "exposures": tally.exposures,
        "escalation_steps": tally.escalation_steps,
        "executed_escalation_steps": tally.executed_escalation_steps,
    }


__all__ = [
    "SURFACE_ABSENT",
    "SURFACE_EXPOSED",
    "SURFACE_NOT_ASSESSED",
    "SURFACE_NO_EXPOSURE",
    "AdcsEnrollmentRightsTally",
    "AdcsExposure",
    "AdcsExposureView",
    "AdcsSurfaceState",
    "AdcsTechniqueTally",
    "build_adcs_exposure_view",
    "adcs_edge_from_web_row",
    "build_enrollment_rights_tally",
    "ISSUING_CA_KIND",
    "issuing_ca_count",
    "exposure_payload",
    "resolve_adcs_surface_state",
    "surface_state_payload",
    "technique_payload",
]


# ---------------------------------------------------------------------------
# Surface state — four honest answers, never a blank panel of zeros
# ---------------------------------------------------------------------------

#: The certificate-services phase did not reach a conclusive answer, so nothing
#: can be said about this environment's PKI. An unassessed surface must never
#: read as a clean one.
SURFACE_NOT_ASSESSED: Final[str] = "not_assessed"
#: The directory was read and holds no certificate authority and no certificate
#: template. An observed absence, which is a fact worth stating.
SURFACE_ABSENT: Final[str] = "absent"
#: Certificate services are deployed and no exploitable condition was found.
#: A positive result, and a good one.
SURFACE_NO_EXPOSURE: Final[str] = "no_exposure"
#: Certificate services are deployed and at least one exposure was found.
SURFACE_EXPOSED: Final[str] = "exposed"

#: Coverage statuses that mean the detection reached a conclusive answer. A
#: ``skipped`` / ``failed`` / ``partial`` check did not, so an empty inventory
#: behind one of those is unassessed, not absent.
_CONCLUSIVE_COVERAGE_STATUSES: Final[frozenset[str]] = frozenset({"ran"})


@dataclass(frozen=True)
class AdcsSurfaceState:
    """Which of the four honest answers this environment's PKI gets."""

    state: str
    #: Client-facing heading for the state.
    headline: str
    #: Client-facing sentence stating what was looked for and what was found.
    statement: str
    #: What the reader should do next. Empty when there is nothing to do.
    next_step: str = ""

    @property
    def has_inventory(self) -> bool:
        """Whether there is a template or CA inventory to render."""
        return self.state in (SURFACE_NO_EXPOSURE, SURFACE_EXPOSED)


_STATE_COPY: Final[dict[str, tuple[str, str, str]]] = {
    SURFACE_NOT_ASSESSED: (
        "Certificate services were not assessed",
        "This scan did not reach a conclusive reading of Active Directory "
        "Certificate Services, so nothing here should be taken as evidence "
        "that the environment has none or that what it has is sound.",
        "Run an authenticated scan with read access to the Configuration "
        "partition, which is where certificate templates and authorities are "
        "published.",
    ),
    SURFACE_ABSENT: (
        "No certificate services in this environment",
        "Active Directory Certificate Services were enumerated and the "
        "directory holds no certificate authority and no certificate "
        "template. The certificate-based escalation routes do not apply here.",
        "",
    ),
    SURFACE_NO_EXPOSURE: (
        "Certificate services are deployed and no exposure was found",
        "Every certificate template and authority was read and none of them "
        "carries a configuration that lets an account obtain a certificate it "
        "should not have. The inventory below is what was examined.",
        "",
    ),
    SURFACE_EXPOSED: (
        "Exposures found in certificate services",
        "",
        "",
    ),
}


def resolve_adcs_surface_state(
    *,
    template_count: int,
    ca_count: int,
    exposure_count: int,
    detection_conclusive: bool,
) -> AdcsSurfaceState:
    """Classify the certificate-services surface into one of four states.

    Args:
        template_count: Certificate templates collected for the workspace.
        ca_count: Certificate authorities and NTAuth stores collected.
        exposure_count: AD CS exposures derived from the attack graph.
        detection_conclusive: Whether the certificate-services detection check
            reached a conclusive answer in the run that wrote these artifacts
            (``adcs.detection`` in the run coverage record). This is what tells
            an observed absence apart from an unassessed surface, so it must
            come from the coverage record and never be inferred from the counts
            being zero.

    Returns:
        The :class:`AdcsSurfaceState` for the surface.
    """
    has_inventory = int(template_count) > 0 or int(ca_count) > 0
    if int(exposure_count) > 0:
        # The graph proved an exposure, so the surface exists whether or not
        # the template / CA inventory reached the database (a workspace
        # ingested by an older engine can carry AD CS edges with no inventory
        # rows). An exposure must never be hidden behind "not assessed".
        state = SURFACE_EXPOSED
    elif has_inventory:
        state = SURFACE_NO_EXPOSURE
    elif detection_conclusive:
        state = SURFACE_ABSENT
    else:
        state = SURFACE_NOT_ASSESSED
    headline, statement, next_step = _STATE_COPY[state]
    return AdcsSurfaceState(
        state=state, headline=headline, statement=statement, next_step=next_step
    )


def surface_state_payload(state: AdcsSurfaceState) -> dict[str, Any]:
    """Serialize a surface state for an API response."""
    return {
        "state": state.state,
        "headline": state.headline,
        "statement": state.statement,
        "next_step": state.next_step,
    }


#: The Configuration-NC object kind that ISSUES certificates
#: (``pKIEnrollmentService``). The root, NTAuth and AIA entries the collector
#: also reads are certificate-store objects, not authorities.
ISSUING_CA_KIND = "enterprise"


def issuing_ca_count(kinds: Iterable[Any]) -> int:
    """Count the issuing enterprise certificate authorities among ``kinds``.

    The figure a client reads as "certificate authorities": each enterprise CA
    publishes several store objects, and counting those put 8 where the
    environment runs 2.
    """
    return sum(
        1
        for kind in kinds
        if str(getattr(kind, "value", kind) or "").strip().lower() == ISSUING_CA_KIND
    )
