"""What each edge and node MEANS when several attack paths are drawn together.

Every view that draws more than one route at once (the web CTEM graph on the
domain and scan pages, the report's attack-surface map) merges them into one
picture with one node per object and one edge per ``(source, target,
relation)``. That merge loses three facts a reader needs, and losing them draws
routes nobody computed:

* **Where a route ends.** A foothold that stops at a host and a route that
  takes the host over and goes on meet on the same node, so the eye follows the
  foothold into the node and out along the other route's edges (the Gate14
  ``stark -CanRDP-> winterfell$`` foothold read as continuing through
  ``winterfell$ -MemberOf-> Domain Controllers -DCSync-> domain``).
* **Presence versus control.** An arrival the route holds only through an access
  session (the engine's ``target_held_as`` stamp,
  ``adscan_core.reporting.session_held_arrivals``) puts the attacker on the host,
  never in control of its account.
* **Which routes use what.** A chokepoint is a node routes pass THROUGH, not one
  where footholds end.

:func:`build_route_overlay` computes those facts once, as sets of route indices,
so a consumer drawing any SUBSET of the routes (a filter, a selection, a page)
restricts by intersection and never re-derives a meaning. The report renderers
call it directly; the web backend serves :meth:`RouteOverlay.to_payload` with
the routes it returns and the frontend reads that payload (it never rebuilds
these facts from relation names). The client-facing legend copy lives here too
(:data:`LEGEND`), so the map and the web graph decode their marks in the same
words; the web mirrors it verbatim under a contract test.

Dependency-light (stdlib only): importable by the engine, the report and the web
backend alike.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from adscan_core.reporting.object_state_track import (
    HELD_STAGE,
    stage_words,
    StepStateResolver,
    route_occurrences,
    stage_payload,
    state_words_payload,
    step_attachments,
    step_semantics,
    step_source_proven,
)
from adscan_core.reporting.session_held_arrivals import step_target_held_as_session

#: A node is a chokepoint when at least this many drawn routes pass THROUGH it
#: (neither start nor end there).
CHOKEPOINT_MIN_THROUGH = 3

#: Legend rows every merging view shares: ``key -> (label, description)``.
#: Client copy (passes the adscan-writing gate).
LEGEND: dict[str, tuple[str, str]] = {
    "presence": (
        "Arrives as a session",
        "A line ending in a bar. The route holds a session on the object and goes "
        "no further along this line; it controls the object only after a later "
        "step takes it over, such as a credential dump or a delegation.",
    ),
    "route_end": (
        "Route ends here",
        "A faint line is a route that stops at a box other routes go on from. "
        "The lines leaving that box belong to those other routes.",
    ),
    "in_place": (
        "Step on the object itself",
        "A step performed on that object, such as a credential dump, drawn "
        "inside its box between the state it starts from and the state it leaves.",
    ),
    "access_state": (
        "Access (control not proven)",
        "A solid outline. ADscan used this session or login on the object, and "
        "the route has not taken the object over.",
    ),
    "access_mapped": (
        "Access (mapped)",
        "A dashed outline. The configuration grants this session or login, and "
        "ADscan did not use it.",
    ),
    "compromised_state": (
        "Compromised",
        "A filled box. A step ADscan executed took the object over.",
    ),
    "compromised_mapped": (
        "Compromised (mapped)",
        "A dashed box, not filled. The configuration lets a route take the "
        "object over, and ADscan did not execute the step that would.",
    ),
    "object_property": (
        "Property of the object",
        "A mark on the box for a setting the object carries, such as an existing "
        "shadow credential or a delegation right. It is not a step of the route.",
    ),
}


def legend_text(key: str) -> str:
    """One legend row as a single line (``Label. Description``)."""
    label, description = LEGEND[key]
    return f"{label}. {description}"


def route_end_note(count: int) -> str:
    """The note a node carries when some drawn routes end there and others go on."""
    return f"{count} route ends here" if count == 1 else f"{count} routes end here"


@dataclass(frozen=True)
class OverlayRoute:
    """One drawn route, as the overlay needs it.

    ``node_keys`` are the keys the consumer draws nodes by (graph ids on the web,
    labels in the report); ``presence[i]`` says whether step ``i``'s target is
    held only as a session (the engine stamp).
    """

    index: int
    node_keys: tuple[str, ...]
    relations: tuple[str, ...]
    presence: tuple[bool, ...]
    #: Each step's execution status (``success``, ``structural``, ...). It
    #: decides which stages of an object's track are PROVEN. ``None`` = unknown:
    #: nothing past the route's start reads as proven.
    statuses: tuple[str, ...] | None = None


def overlay_route_from_record(
    record: Mapping[str, Any],
    *,
    index: int,
    node_keys: Sequence[Any] | None = None,
) -> OverlayRoute:
    """Build an :class:`OverlayRoute` from an engine display record.

    ``node_keys`` overrides the keys (defaults to ``str(n)`` of each node, or the
    node's ``id`` / ``label`` when nodes are dicts). The presence flags are read
    from each step's engine stamp; a record without steps has none.
    """
    raw_nodes = node_keys if node_keys is not None else (record.get("nodes") or [])
    keys = tuple(_node_key(n) for n in raw_nodes)
    relations = tuple(str(r or "") for r in (record.get("relations") or []))
    steps = record.get("steps") or []
    presence = tuple(
        step_target_held_as_session(steps[i]) if i < len(steps) else False
        for i in range(len(relations))
    )
    statuses = tuple(
        _step_status(steps[i]) if i < len(steps) else "" for i in range(len(relations))
    )
    return OverlayRoute(index=int(index), node_keys=keys, relations=relations,
                        presence=presence, statuses=statuses)


def _step_status(step: Any) -> str:
    if isinstance(step, Mapping):
        return str(step.get("status") or "")
    return ""


def _node_key(node: Any) -> str:
    if isinstance(node, Mapping):
        return str(node.get("id") or node.get("label") or "")
    return str(node)


@dataclass
class EdgeOverlay:
    """One merged edge and the routes behind it (sets of route indices)."""

    source: str
    target: str
    relation: str
    routes: set[int] = field(default_factory=set)
    #: Routes for which this edge is their LAST step: the route ends at target.
    terminal: set[int] = field(default_factory=set)
    #: Routes that go on past this edge's target.
    continuing: set[int] = field(default_factory=set)
    #: Routes that hold the target only as a session after this step.
    presence: set[int] = field(default_factory=set)
    #: ``stage -> routes``: which stage of the SOURCE's state track each route
    #: leaves from (``object_state_track``). Only stages other than the held one
    #: are interesting to a consumer; a route absent here leaves the held box.
    source_stages: dict[str, set[int]] = field(default_factory=dict)
    #: ``stage -> routes``: which stage of the TARGET's track each route lands on.
    target_stages: dict[str, set[int]] = field(default_factory=dict)
    #: Routes on which this step leaves a stage NO executed step reached. A step
    #: with no proof of its own (a directory fact) is drawn mapped on them.
    unproven_source: set[int] = field(default_factory=set)

    @property
    def is_self_loop(self) -> bool:
        """True for a step performed on the object itself (DumpLSA, ...)."""
        return self.source == self.target

    def presence_only(self, drawn: set[int] | None = None) -> bool:
        """True when every drawn route using this edge holds only a session."""
        routes = _restrict(self.routes, drawn)
        return bool(routes) and routes <= self.presence

    def ends_only(self, drawn: set[int] | None = None) -> bool:
        """True when no drawn route using this edge goes on past its target."""
        routes = _restrict(self.routes, drawn)
        return bool(routes) and not (routes & self.continuing)

    def source_unproven(self, drawn: set[int] | None = None) -> bool:
        """True when every drawn route on this edge leaves an unproven stage."""
        routes = _restrict(self.routes, drawn)
        return bool(routes) and routes <= self.unproven_source

    def stage_pairs(self, drawn: set[int] | None = None) -> dict[tuple[str, str], set[int]]:
        """``(source_stage, target_stage) -> routes`` for the drawn routes.

        One entry when every drawn route uses the edge between the same two
        stages (the common case); several when routes leave or land on
        different stages of the same object, which a consumer draws as one
        edge per pair so no route reads as standing where it does not.
        """
        pairs: dict[tuple[str, str], set[int]] = {}
        for route in _restrict(self.routes, drawn):
            source = _stage_for(self.source_stages, route)
            target = _stage_for(self.target_stages, route)
            pairs.setdefault((source, target), set()).add(route)
        return pairs


@dataclass
class NodeOverlay:
    """One merged node and how the drawn routes use it."""

    key: str
    routes: set[int] = field(default_factory=set)
    start: set[int] = field(default_factory=set)
    through: set[int] = field(default_factory=set)
    end: set[int] = field(default_factory=set)
    #: ``stage -> routes`` standing on each stage of this object's state track.
    stages: dict[str, set[int]] = field(default_factory=dict)
    #: ``(from_stage, to_stage, relation) -> routes`` for each in-place step that
    #: moves the object along its track.
    transitions: dict[tuple[str, str, str], set[int]] = field(default_factory=dict)
    #: ``relation -> routes`` for each self-loop that is a property of the object.
    properties: dict[str, set[int]] = field(default_factory=dict)
    #: ``stage -> routes`` on which an EXECUTED step reached that stage.
    proven_stages: dict[str, set[int]] = field(default_factory=dict)
    #: ``stage -> {arrival state -> routes}``: the state each route arrived in.
    stage_states: dict[str, dict[str, set[int]]] = field(default_factory=dict)

    def stage_proven(self, stage: str, drawn: set[int] | None = None) -> bool:
        """True when some drawn route reached ``stage`` through an executed step."""
        return bool(_restrict(self.proven_stages.get(stage, set()), drawn))

    def stage_arrival_states(self, stage: str, drawn: set[int] | None = None) -> set[str]:
        """The arrival states the drawn routes stand on ``stage`` in."""
        return {
            state
            for state, routes in self.stage_states.get(stage, {}).items()
            if _restrict(routes, drawn)
        }

    def stage_words(self, stage: str, drawn: set[int] | None = None) -> tuple[str, str]:
        """``(label, caption)`` of ``stage`` for the drawn routes (proof-aware)."""
        words = stage_words(
            stage,
            self.stage_arrival_states(stage, drawn),
            proven=self.stage_proven(stage, drawn),
        )
        return words.label, words.caption

    def has_track(self) -> bool:
        """True when some route stands on a stage other than the held box, or
        an in-place step or a property mark is recorded on this object."""
        return bool(
            self.transitions
            or self.properties
            or any(stage != HELD_STAGE for stage in self.stages)
        )

    def track_stages(self, drawn: set[int] | None = None) -> dict[str, set[int]]:
        """``stage -> routes`` restricted to the drawn routes (empty sets dropped)."""
        return _restrict_map(self.stages, drawn)

    def track_transitions(
        self, drawn: set[int] | None = None
    ) -> dict[tuple[str, str, str], set[int]]:
        """In-place steps restricted to the drawn routes."""
        return _restrict_map(self.transitions, drawn)

    def track_properties(self, drawn: set[int] | None = None) -> dict[str, set[int]]:
        """Property marks restricted to the drawn routes."""
        return _restrict_map(self.properties, drawn)

    def through_count(self, drawn: set[int] | None = None) -> int:
        """Routes that pass THROUGH this node (neither start nor end here)."""
        return len(_restrict(self.through, drawn))

    def end_count(self, drawn: set[int] | None = None) -> int:
        """Routes that end at this node."""
        return len(_restrict(self.end, drawn))

    def leaving(self, drawn: set[int] | None = None) -> set[int]:
        """Drawn routes that go on FROM this node (pass through or start here)."""
        return _restrict((self.through | self.start) - self.end, drawn)

    def is_chokepoint(self, drawn: set[int] | None = None) -> bool:
        """True when at least :data:`CHOKEPOINT_MIN_THROUGH` routes pass through."""
        return self.through_count(drawn) >= CHOKEPOINT_MIN_THROUGH

    def is_split(self, drawn: set[int] | None = None) -> bool:
        """True when some drawn routes end here and others go on from here."""
        return self.end_count(drawn) > 0 and bool(self.leaving(drawn))


def _restrict(values: set[int], drawn: set[int] | None) -> set[int]:
    return set(values) if drawn is None else values & drawn


def _restrict_map(mapping: Mapping[Any, set[int]], drawn: set[int] | None) -> dict[Any, set[int]]:
    out: dict[Any, set[int]] = {}
    for key, routes in mapping.items():
        kept = _restrict(routes, drawn)
        if kept:
            out[key] = kept
    return out


def _stage_for(stages: Mapping[str, set[int]], route: int) -> str:
    for stage, routes in stages.items():
        if route in routes:
            return stage
    return HELD_STAGE


def _stage_rows(mapping: Mapping[str, set[int]]) -> list[dict[str, Any]]:
    return [
        {"stage": stage, "routes": sorted(routes)}
        for stage, routes in sorted(mapping.items())
    ]


@dataclass
class RouteOverlay:
    """The merged graph's meaning, keyed like the consumer draws it."""

    nodes: dict[str, NodeOverlay] = field(default_factory=dict)
    edges: dict[tuple[str, str, str], EdgeOverlay] = field(default_factory=dict)

    def node(self, key: Any) -> NodeOverlay | None:
        return self.nodes.get(str(key))

    def edge(self, source: Any, target: Any, relation: Any) -> EdgeOverlay | None:
        return self.edges.get((str(source), str(target), str(relation)))

    def ends_where_others_go_on(
        self, edge: EdgeOverlay, drawn: set[int] | None = None
    ) -> bool:
        """True when every drawn route on ``edge`` ends at its target while other
        drawn routes go on from that target.

        This is the arrival a merged view must draw as yielding: without the
        mark the eye follows it into the node and out along the other routes'
        edges. An arrival at a node nothing leaves (the domain, a pure
        foothold) is not ambiguous and is drawn normally.
        """
        if edge.is_self_loop or not edge.ends_only(drawn):
            return False
        target = self.nodes.get(edge.target)
        if target is None:
            return False
        return bool(target.leaving(drawn) - _restrict(edge.routes, drawn))

    def to_payload(self) -> dict[str, Any]:
        """JSON-safe form the web backend serves (sorted, index lists)."""
        return {
            "chokepoint_min_through": CHOKEPOINT_MIN_THROUGH,
            "nodes": [_node_payload(n) for n in self.nodes.values()],
            "edges": [_edge_payload(e) for e in self.edges.values()],
            "legend": [
                {"key": key, "label": label, "description": description}
                for key, (label, description) in LEGEND.items()
            ],
            # The state-track vocabulary (``object_state_track.STAGES`` and the
            # per-arrival-state words), so the web draws and labels a stage from
            # the served words, never a copy.
            "stages": stage_payload(),
            "state_words": state_words_payload(),
        }


def _node_payload(node: NodeOverlay) -> dict[str, Any]:
    row: dict[str, Any] = {
        "key": node.key,
        "routes": sorted(node.routes),
        "start": sorted(node.start),
        "through": sorted(node.through),
        "end": sorted(node.end),
    }
    # The state track rides only on objects that have one, so a domain graph of
    # plain objects carries no extra bytes.
    if node.has_track():
        row["stages"] = [
            {
                "stage": stage,
                "routes": sorted(routes),
                "proven": sorted(node.proven_stages.get(stage, set())),
                "states": {
                    state: sorted(state_routes)
                    for state, state_routes in sorted(node.stage_states.get(stage, {}).items())
                },
            }
            for stage, routes in sorted(node.stages.items())
        ]
        row["transitions"] = [
            {
                "from": from_stage,
                "to": to_stage,
                "relation": relation,
                "label": _step_label(relation),
                "routes": sorted(routes),
            }
            for (from_stage, to_stage, relation), routes in sorted(node.transitions.items())
        ]
        row["properties"] = [
            {"relation": relation, "label": _step_label(relation), "routes": sorted(routes)}
            for relation, routes in sorted(node.properties.items())
        ]
    return row


def _step_label(relation: str) -> str:
    """The client phrase of an in-place step, from the catalog provider."""
    semantics = step_semantics(relation)
    return semantics.label if semantics is not None and semantics.label else relation


def _edge_payload(edge: EdgeOverlay) -> dict[str, Any]:
    row: dict[str, Any] = {
        "source": edge.source,
        "target": edge.target,
        "relation": edge.relation,
        "routes": sorted(edge.routes),
        "terminal": sorted(edge.terminal),
        "continuing": sorted(edge.continuing),
        "presence": sorted(edge.presence),
    }
    if edge.source_stages:
        row["source_stages"] = _stage_rows(edge.source_stages)
    if edge.target_stages:
        row["target_stages"] = _stage_rows(edge.target_stages)
    if edge.unproven_source:
        row["unproven_source"] = sorted(edge.unproven_source)
    return row


def build_route_overlay(
    routes: Iterable[OverlayRoute],
    *,
    resolver: StepStateResolver | None = None,
) -> RouteOverlay:
    """Merge ``routes`` and record, per edge and node, which routes do what.

    Per route, the LAST node is where it ends and its first node where it starts;
    every other node it visits it passes through (a self-loop run on one node
    counts once). An edge is terminal for a route when it lands on the node the
    route ends at (so the arrival and any in-place step there both are), and
    continuing otherwise.

    Each route is also split into the visits it makes to each object
    (``object_state_track.route_occurrences``, the catalog's
    ``resulting_state`` read through ``resolver`` or the installed provider):
    which stage of the object's state track it stands on, the in-place steps
    that move it along the track, the self-loops that are only properties of
    the object, and, per edge, the stage each route leaves from and lands on.
    """
    overlay = RouteOverlay()
    for route in routes:
        keys = route.node_keys
        if not keys:
            continue
        steps = min(len(route.relations), len(keys) - 1)
        start_key, end_key = keys[0], keys[steps]
        for key in dict.fromkeys(keys[: steps + 1]):
            node = overlay.nodes.setdefault(key, NodeOverlay(key=key))
            node.routes.add(route.index)
            if key == start_key:
                node.start.add(route.index)
            if key == end_key:
                node.end.add(route.index)
            if key not in (start_key, end_key):
                node.through.add(route.index)
        for i in range(steps):
            source, target, relation = keys[i], keys[i + 1], route.relations[i]
            edge = overlay.edges.setdefault(
                (source, target, relation),
                EdgeOverlay(source=source, target=target, relation=relation),
            )
            edge.routes.add(route.index)
            if target == end_key:
                edge.terminal.add(route.index)
            else:
                edge.continuing.add(route.index)
            if i < len(route.presence) and route.presence[i]:
                edge.presence.add(route.index)
        _record_state_tracks(overlay, route, steps, resolver)
    return overlay


def _record_state_tracks(
    overlay: RouteOverlay,
    route: OverlayRoute,
    steps: int,
    resolver: StepStateResolver | None,
) -> None:
    keys = route.node_keys[: steps + 1]
    occurrences = route_occurrences(
        keys,
        route.relations[:steps],
        statuses=route.statuses[:steps] if route.statuses is not None else None,
        resolver=resolver,
    )
    for occurrence in occurrences:
        node = overlay.nodes.get(occurrence.key)
        if node is None:
            continue
        for stage in occurrence.stages:
            node.stages.setdefault(stage, set()).add(route.index)
        for stage in occurrence.proven_stages:
            node.proven_stages.setdefault(stage, set()).add(route.index)
        if occurrence.arrival_state is not None:
            node.stage_states.setdefault(occurrence.arrival_stage, {}).setdefault(
                occurrence.arrival_state, set()
            ).add(route.index)
        for transition in occurrence.transitions:
            node.transitions.setdefault(
                (transition.from_stage, transition.to_stage, transition.relation), set()
            ).add(route.index)
        for mark in occurrence.properties:
            node.properties.setdefault(mark.relation, set()).add(route.index)
    for step_index, (source_stage, target_stage) in step_attachments(occurrences).items():
        edge = overlay.edges.get(
            (keys[step_index], keys[step_index + 1], route.relations[step_index])
        )
        if edge is None:
            continue
        if source_stage != HELD_STAGE:
            edge.source_stages.setdefault(source_stage, set()).add(route.index)
        if target_stage != HELD_STAGE:
            edge.target_stages.setdefault(target_stage, set()).add(route.index)
    for step_index, proven in step_source_proven(occurrences).items():
        if proven:
            continue
        edge = overlay.edges.get(
            (keys[step_index], keys[step_index + 1], route.relations[step_index])
        )
        if edge is not None:
            edge.unproven_source.add(route.index)


def served_paths_overlay_payload(paths: Iterable[Any], *, key: str = "id") -> dict[str, Any] | None:
    """The overlay payload of the paths a web response serves.

    ``paths`` are the served path objects (``index``, ``nodes`` with ``id`` and
    ``label``, ``edges`` with ``relation`` and ``details``), read by attribute
    or by key. ``key`` names the node field the frontend draws nodes by: ``id``
    (the domain attack-paths page) or ``label`` (the scan page, which merges by
    label); the payload records it. Route indices are the paths' own ``index``.
    ``None`` when no path has a step.
    """
    routes: list[OverlayRoute] = []
    for path in paths or []:
        nodes = list(_field(path, "nodes") or [])
        edges = list(_field(path, "edges") or [])
        if len(nodes) < 2:
            continue
        routes.append(
            OverlayRoute(
                index=int(_field(path, "index") or 0),
                node_keys=tuple(str(_field(node, key) or "") for node in nodes),
                relations=tuple(str(_field(edge, "relation") or "") for edge in edges),
                presence=tuple(
                    step_target_held_as_session({"details": _field(edge, "details")})
                    for edge in edges
                ),
                statuses=tuple(str(_field(edge, "status") or "") for edge in edges),
            )
        )
    if not routes:
        return None
    payload = build_route_overlay(routes).to_payload()
    payload["key"] = key
    return payload


#: Bounds on a client-supplied route set (the scan page's streamed routes). A
#: graph never draws more; the bound keeps the endpoint from being an
#: arbitrary-size computation.
MAX_CLIENT_ROUTES = 2000
MAX_CLIENT_ROUTE_STEPS = 64


def client_routes_overlay_payload(
    routes: Iterable[Mapping[str, Any]], *, key: str = "label"
) -> dict[str, Any] | None:
    """The overlay payload of routes a client already holds.

    The scan page draws the routes a scan streams over the websocket whenever
    the persisted snapshot cannot be read (before the first snapshot, after the
    run's execution workspace was promoted and removed, on a failed fetch). The
    streamed events carry the engine's per-step stamp, which the page reads into
    ``presence``; this computes the same overlay ``served_paths_overlay_payload``
    does for a served page, through the same :func:`build_route_overlay`.

    Each route is a mapping with ``index`` (the page's own route index),
    ``nodes`` (the node keys the page draws by), ``relations`` and ``presence``
    (one flag per step). Routes past :data:`MAX_CLIENT_ROUTES`, and steps past
    :data:`MAX_CLIENT_ROUTE_STEPS`, are dropped. ``None`` when no route has a
    step.
    """
    overlay_routes: list[OverlayRoute] = []
    for route in list(routes or [])[:MAX_CLIENT_ROUTES]:
        if not isinstance(route, Mapping):
            continue
        relations = [str(r or "") for r in (route.get("relations") or [])][
            :MAX_CLIENT_ROUTE_STEPS
        ]
        nodes = [str(n or "") for n in (route.get("nodes") or [])][
            : len(relations) + 1
        ]
        if len(nodes) < 2:
            continue
        presence_raw = list(route.get("presence") or [])
        statuses_raw = route.get("statuses")
        step_count = min(len(relations), len(nodes) - 1)
        overlay_routes.append(
            OverlayRoute(
                index=int(route.get("index") or 0),
                node_keys=tuple(nodes),
                relations=tuple(relations[: len(nodes) - 1]),
                presence=tuple(
                    bool(presence_raw[i]) if i < len(presence_raw) else False
                    for i in range(step_count)
                ),
                # An older client sends no statuses: nothing past the start
                # then reads as proven, the conservative reading.
                statuses=(
                    tuple(
                        str(statuses_raw[i] or "") if i < len(statuses_raw) else ""
                        for i in range(step_count)
                    )
                    if isinstance(statuses_raw, list)
                    else None
                ),
            )
        )
    if not overlay_routes:
        return None
    payload = build_route_overlay(overlay_routes).to_payload()
    payload["key"] = key
    return payload


def _field(obj: Any, name: str) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(name)
    return getattr(obj, name, None)


__all__ = [
    "CHOKEPOINT_MIN_THROUGH",
    "LEGEND",
    "EdgeOverlay",
    "NodeOverlay",
    "OverlayRoute",
    "RouteOverlay",
    "MAX_CLIENT_ROUTES",
    "MAX_CLIENT_ROUTE_STEPS",
    "build_route_overlay",
    "client_routes_overlay_payload",
    "legend_text",
    "overlay_route_from_record",
    "route_end_note",
    "served_paths_overlay_payload",
]
