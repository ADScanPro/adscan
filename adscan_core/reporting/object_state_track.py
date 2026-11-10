"""Object state tracks: one object, the states a route moves it through.

Some attack steps act IN PLACE on one object (the engine draws them as a step
whose source and target are the same node) and turn ACCESS to it into CONTROL of
it: a session on a host becomes its machine account once its LSA secrets are
read, a session of a user becomes that user once a scheduled task runs as them,
a SQL Server login becomes operating-system commands and then SYSTEM. A graph
that draws one box per object has to show that transition, or the reader takes
"a session reached this host" for "this host is controlled", which is false.

This module turns a route's node chain into per-object **state tracks**: the
ordered stages a route visits on each object (``access`` -> ... ->
``compromised``), the in-place steps that move it from one stage to the next,
and the self-loops that are only PROPERTIES of the object (an existing shadow
credential, a delegation setting), which are marks on the object and never a
stage.

Nothing here is decided from a relation name. Every step's effect is read from
the attack-step catalog's ``resulting_state`` field through an injected provider
(:func:`set_step_state_provider`, installed by
``adscan_internal.services.attack_step_catalog`` at import), so a technique the
catalog learns later is drawn correctly with no change to this module or to any
renderer. ``adscan_core`` cannot import the catalog, which is why it is injected,
the same pattern as ``technical_report.set_finding_catalog_provider``.

The vocabulary (:data:`STAGES`, :data:`RESULTING_STATES`) and its client labels
live here once; the report's diagrams and the web graph read them from here (the
web through the served route overlay payload, never a TypeScript copy).

Dependency-light (stdlib only).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

from adscan_core.reporting.execution_status import FULLY_EXECUTED_PATH_STATUSES

#: The stage a held object is in: the object's own box. Every route that holds
#: an object (it started there, or reached it by a step that controls it) stands
#: here, and every onward step that needs control leaves from here.
HELD_STAGE = "compromised"


@dataclass(frozen=True)
class StageDefinition:
    """One stage of an object's state track, with its client-facing words.

    ``order`` places it on the track left to right; stages sharing an order are
    alternatives drawn one above the other (a host reached both by a session and
    by a SQL login). ``held`` marks the stage that is control of the object.
    """

    key: str
    order: int
    label: str
    description: str
    held: bool = False
    #: What the stage is NOT yet, read under its label when no single arrival
    #: state names it more precisely.
    caption: str = ""


#: The stages, in track order. Client copy (passes the adscan-writing gate).
STAGES: dict[str, StageDefinition] = {
    "access": StageDefinition(
        key="access",
        order=1,
        label="Access",
        description=(
            "A session or administrator access on the object. Control of the "
            "object is not proven until a later step takes it over."
        ),
        caption="control not proven",
    ),
    "sql_access": StageDefinition(
        key="sql_access",
        order=1,
        label="SQL Server login",
        description=(
            "A login on the SQL Server instance. The host it runs on is not "
            "controlled yet."
        ),
        caption="host not controlled",
    ),
    "os_execution": StageDefinition(
        key="os_execution",
        order=2,
        label="Commands as service account",
        description=(
            "Operating-system commands run on the host as the SQL Server service "
            "account, which is less than control of the host."
        ),
        caption="not yet SYSTEM",
    ),
    HELD_STAGE: StageDefinition(
        key=HELD_STAGE,
        order=3,
        label="Compromised",
        description=(
            "Control of the object is proven: its credentials were read, or the "
            "route acts as it or as SYSTEM on it."
        ),
        held=True,
    ),
}

#: The closed vocabulary of the catalog's ``resulting_state`` field: the state a
#: step leaves its target object in, mapped to the stage it occupies. Several
#: states share a stage: the access stage is reached by administrator access, a
#: remote session or a reachable logon session, and the held stage by credentials
#: read, acting as the session user or SYSTEM. HOW the object was taken over is
#: said by the step that got there.
RESULTING_STATES: dict[str, str] = {
    # Local administrator access on a host (AdminTo, a recovered LAPS password,
    # the RBCD relay): code runs there, the host's own credentials not read yet.
    "admin_access": "access",
    # A user-level remote session on a host (RDP, PowerShell remoting, DCOM).
    "session_access": "access",
    # A user's logon session on a host the route can act on, not yet AS the user.
    "logon_session": "access",
    # A login on a SQL Server instance, below the host's operating system.
    "sql_access": "sql_access",
    # Operating-system commands as the SQL Server service account.
    "os_execution_as_service": "os_execution",
    # The object's own credentials read (LSA secrets, memory, local hashes).
    "credentials_read": HELD_STAGE,
    # The route acts AS the user whose session it reached.
    "acting_as_session_user": HELD_STAGE,
    # SYSTEM on the host.
    "system": HELD_STAGE,
}


@dataclass(frozen=True)
class StateWords:
    """How a stage reads when the route arrived in a given state.

    ``label`` names the state, ``caption`` says what it is NOT yet, so the box
    and the step text on the same page agree (an administrator on a host runs
    code there; reading the host's credentials is the next step).
    """

    label: str
    caption: str


#: Client words per arrival state, in ONE place. A state on the held stage reads
#: as the stage itself ("Compromised"); the step that got there says how.
STATE_WORDS: dict[str, StateWords] = {
    "admin_access": StateWords("Administrator access", "credentials not yet read"),
    "session_access": StateWords("Remote session", "control not proven"),
    "logon_session": StateWords("Logged-on session", "not yet acting as the user"),
    "sql_access": StateWords("SQL Server login", "host not controlled"),
    "os_execution_as_service": StateWords("Commands as service account", "not yet SYSTEM"),
}

#: The words a stage reads with when several arrival states share it, or none:
#: the stage's own label and caption (one source, :data:`STAGES`).
STAGE_WORDS: dict[str, StateWords] = {
    key: StateWords(stage.label, stage.caption) for key, stage in STAGES.items()
}

#: Suffix a stage carries when no executed step reached it.
MAPPED_SUFFIX = " (mapped)"


def stage_words(stage: str, states: Iterable[str] = (), *, proven: bool = True) -> StateWords:
    """The label and caption a stage is drawn with.

    One arrival state on the stage reads as that state ("Administrator access,
    credentials not yet read"); several, or none, read as the stage. A stage no
    executed step reached carries " (mapped)": the configuration allows it and
    ADscan did not prove it.
    """
    distinct = sorted({s for s in states if RESULTING_STATES.get(s) == stage and s in STATE_WORDS})
    if len(distinct) == 1:
        words = STATE_WORDS[distinct[0]]
    else:
        words = STAGE_WORDS.get(stage, StateWords(stage, ""))
    if not proven:
        return StateWords(words.label + MAPPED_SUFFIX, words.caption)
    return words


def state_words_payload() -> list[dict[str, str]]:
    """The arrival-state words as served to the web (one row per state)."""
    return [
        {
            "key": key,
            "stage": RESULTING_STATES[key],
            "label": words.label,
            "caption": words.caption,
        }
        for key, words in STATE_WORDS.items()
    ]


# ── Proof: which stages an EXECUTED step reached ─────────────────────────────
# A stage is PROVEN when a step ADscan executed (a success status) reached it,
# or when a directory fact (a ``structural`` hop, or a step with no recorded
# status) carried proof forward from a proven stage. Anything else (a mapped,
# attempted or withheld step) leaves the stage MAPPED: the configuration allows
# it, and the report must not draw it as held.

#: Step statuses that mean ADscan executed the step and it succeeded.
EXECUTED_STEP_STATUSES: frozenset[str] = frozenset(FULLY_EXECUTED_PATH_STATUSES | {"succeeded"})

#: Step statuses that carry no proof of their own: a directory fact, or no
#: recorded outcome. Such a step is as proven as the stage it leaves.
INHERITING_STEP_STATUSES: frozenset[str] = frozenset({"", "structural"})


def step_is_executed(status: object) -> bool:
    """True when the step's status says ADscan executed it successfully."""
    return str(status or "").strip().lower() in EXECUTED_STEP_STATUSES


def step_inherits_proof(status: object) -> bool:
    """True for a step whose proof is the proof of the stage it leaves."""
    return str(status or "").strip().lower() in INHERITING_STEP_STATUSES


def step_proves(status: object, *, source_proven: bool) -> bool:
    """Whether the stage a step reaches is proven by that step."""
    if step_is_executed(status):
        return True
    return source_proven and step_inherits_proof(status)


@dataclass(frozen=True)
class StepStateSemantics:
    """What the catalog says one relation does to the object it reaches.

    ``resulting_state`` is a key of :data:`RESULTING_STATES`, or ``None`` when
    the step does not move its target through a state track (an ordinary control
    step, or a self-loop that is only a property of the object). ``label`` is the
    client-facing phrase for the step.
    """

    resulting_state: str | None
    label: str


#: Resolves a relation to its :class:`StepStateSemantics` (``None`` = unknown).
StepStateResolver = Callable[[str], "StepStateSemantics | None"]

_STATE_PROVIDER: StepStateResolver | None = None


def set_step_state_provider(resolver: StepStateResolver | None) -> None:
    """Install the catalog-backed resolver (``None`` uninstalls it)."""
    global _STATE_PROVIDER  # noqa: PLW0603 - module-level injection seam
    _STATE_PROVIDER = resolver


def step_state_provider() -> StepStateResolver | None:
    """The installed resolver, or ``None`` before the catalog was imported."""
    return _STATE_PROVIDER


def step_semantics(
    relation: str, resolver: StepStateResolver | None = None
) -> StepStateSemantics | None:
    """The semantics of ``relation`` from ``resolver`` (default: the provider).

    An unknown state token is dropped (``resulting_state=None``) rather than
    trusted, so a catalog typo can never invent a stage.
    """
    fn = resolver if resolver is not None else _STATE_PROVIDER
    if fn is None or not relation:
        return None
    try:
        semantics = fn(str(relation))
    except Exception:  # noqa: BLE001 - a resolver failure must never break a render
        return None
    if semantics is None:
        return None
    if semantics.resulting_state not in RESULTING_STATES:
        return StepStateSemantics(resulting_state=None, label=semantics.label)
    return semantics


def stage_of_state(resulting_state: str | None) -> str | None:
    """The stage a resulting state occupies, or ``None``."""
    if resulting_state is None:
        return None
    return RESULTING_STATES.get(resulting_state)


def is_held_stage(stage: str | None) -> bool:
    """True for the stage that is control of the object."""
    definition = STAGES.get(str(stage or ""))
    return bool(definition and definition.held)


@dataclass(frozen=True)
class TrackTransition:
    """An in-place step that moves the object from one stage to another.

    ``from_stage == to_stage`` is an in-place step that changes nothing the
    track draws (a second credential dump on a host already held).
    """

    step_index: int
    relation: str
    from_stage: str
    to_stage: str
    #: Whether the stage this step leaves is proven (for the display cap).
    from_proven: bool = True
    #: Whether the stage it reaches is proven by it.
    to_proven: bool = True


@dataclass(frozen=True)
class PropertyMark:
    """A self-loop that is a PROPERTY of the object, not a step on its track."""

    step_index: int
    relation: str


#: How a route uses one object it visits.
OCCURRENCE_PLAIN = "plain"
OCCURRENCE_ACCESS_ONLY = "access_only"
OCCURRENCE_COMPROMISED = "compromised"


@dataclass(frozen=True)
class NodeOccurrence:
    """One visit of a route to one object (a run of identical node keys).

    ``arrival_stage`` is where the route lands on the object, ``departure_stage``
    where it stands when it leaves (or ends). ``first_index`` / ``last_index``
    are positions in the route's node list.
    """

    key: str
    first_index: int
    last_index: int
    arrival_step: int | None
    arrival_stage: str
    departure_stage: str
    transitions: tuple[TrackTransition, ...] = ()
    properties: tuple[PropertyMark, ...] = ()
    #: The arriving step's ``resulting_state`` when it lands on an access stage.
    arrival_state: str | None = None
    #: Whether the stage the route LEFT to arrive here is proven.
    source_proven: bool = True
    #: The stages of this visit an executed step reached.
    proven_stages: frozenset[str] = frozenset()

    @property
    def departure_proven(self) -> bool:
        """Whether the stage the route leaves this object from is proven."""
        return self.departure_stage in self.proven_stages

    @property
    def state(self) -> str:
        """``access_only``, ``compromised`` (a track was walked) or ``plain``."""
        if not is_held_stage(self.departure_stage):
            return OCCURRENCE_ACCESS_ONLY
        if not is_held_stage(self.arrival_stage):
            return OCCURRENCE_COMPROMISED
        return OCCURRENCE_PLAIN

    @property
    def stages(self) -> tuple[str, ...]:
        """Every stage this visit stands on, in visiting order, without repeats."""
        seen = [self.arrival_stage]
        for transition in self.transitions:
            if transition.to_stage not in seen:
                seen.append(transition.to_stage)
        return tuple(seen)


def route_occurrences(
    node_keys: Sequence[str],
    relations: Sequence[str],
    *,
    statuses: Sequence[object] | None = None,
    resolver: StepStateResolver | None = None,
) -> tuple[NodeOccurrence, ...]:
    """Split a route into the visits it makes to each object, with their stages.

    Step ``i`` joins ``node_keys[i]`` to ``node_keys[i + 1]``. A run of
    consecutive identical keys is one visit; the self-loop steps inside it are
    either track transitions (the catalog gives the step a ``resulting_state``)
    or property marks (it does not). The visit's arrival stage is the arriving
    step's access stage when the catalog declares one, else the held stage: a
    route that starts on an object, or reaches it by a step that controls it,
    holds it.

    ``statuses`` (one per step) decides which stages are PROVEN
    (:func:`step_proves`): the route's starting object is held, and proof flows
    forward only through executed steps and directory facts. Without statuses
    nothing past the start is proven, the conservative reading.
    """
    keys = [str(k) for k in node_keys]
    status_list = list(statuses or [])

    def _status(index: int) -> object:
        return status_list[index] if index < len(status_list) else None

    previous_departure_proven = True
    steps = min(len(relations), max(len(keys) - 1, 0))
    keys = keys[: steps + 1]
    occurrences: list[NodeOccurrence] = []
    position = 0
    while position < len(keys):
        run_end = position
        while run_end + 1 < len(keys) and keys[run_end + 1] == keys[position]:
            run_end += 1
        arrival_step = position - 1 if position > 0 else None
        arrival_stage = HELD_STAGE
        arrival_state: str | None = None
        if arrival_step is not None:
            semantics = step_semantics(str(relations[arrival_step] or ""), resolver)
            state = semantics.resulting_state if semantics else None
            stage = stage_of_state(state)
            if stage is not None and not is_held_stage(stage):
                arrival_stage = stage
                arrival_state = state
        source_proven = previous_departure_proven
        arrival_proven = (
            True
            if arrival_step is None
            else (statuses is not None and step_proves(_status(arrival_step), source_proven=source_proven))
        )
        proven: set[str] = {arrival_stage} if arrival_proven else set()
        current = arrival_stage
        current_proven = arrival_proven
        transitions: list[TrackTransition] = []
        properties: list[PropertyMark] = []
        for step_index in range(position, run_end):
            relation = str(relations[step_index] or "")
            semantics = step_semantics(relation, resolver)
            stage = stage_of_state(semantics.resulting_state if semantics else None)
            if stage is None:
                properties.append(PropertyMark(step_index=step_index, relation=relation))
                continue
            reached = statuses is not None and step_proves(
                _status(step_index), source_proven=current_proven
            )
            transitions.append(
                TrackTransition(
                    step_index=step_index,
                    relation=relation,
                    from_stage=current,
                    to_stage=stage,
                    from_proven=current_proven,
                    to_proven=reached,
                )
            )
            current = stage
            current_proven = reached or (stage in proven)
            if reached:
                proven.add(stage)
        occurrences.append(
            NodeOccurrence(
                key=keys[position],
                first_index=position,
                last_index=run_end,
                arrival_step=arrival_step,
                arrival_stage=arrival_stage,
                departure_stage=current,
                transitions=tuple(transitions),
                properties=tuple(properties),
                arrival_state=arrival_state,
                source_proven=source_proven,
                proven_stages=frozenset(proven),
            )
        )
        previous_departure_proven = current in proven
        position = run_end + 1
    return tuple(occurrences)


def step_source_proven(occurrences: Sequence[NodeOccurrence]) -> dict[int, bool]:
    """``step_index -> whether the stage the step LEAVES is proven``.

    Covers every step of the route: the moves between objects (the stage the
    route stood on at the source) and the in-place steps (the stage they start
    from). A renderer uses it to cap a step that carries no proof of its own: a
    directory fact leaving a stage nothing executed reached is drawn mapped,
    never in the colour of a validated hop.
    """
    out: dict[int, bool] = {}
    for previous, current in zip(occurrences, occurrences[1:]):
        if current.arrival_step is not None:
            out[current.arrival_step] = previous.departure_proven
    for occurrence in occurrences:
        for transition in occurrence.transitions:
            out[transition.step_index] = transition.from_proven
    return out


def step_attachments(
    occurrences: Sequence[NodeOccurrence],
) -> dict[int, tuple[str, str]]:
    """``step_index -> (source_stage, target_stage)`` for every move between objects.

    A move leaves its source from the stage the route stood on there and lands
    on the stage its arrival put it in. Self-loop steps are not moves and are
    absent (they are the occurrence's transitions or properties).
    """
    attachments: dict[int, tuple[str, str]] = {}
    for previous, current in zip(occurrences, occurrences[1:]):
        if current.arrival_step is None:
            continue
        attachments[current.arrival_step] = (
            previous.departure_stage,
            current.arrival_stage,
        )
    return attachments


def stage_payload() -> list[dict[str, object]]:
    """The stage vocabulary as served to the web (ordered, JSON-safe)."""
    return [
        {
            "key": stage.key,
            "order": stage.order,
            "label": stage.label,
            "description": stage.description,
            "caption": stage.caption,
            "held": stage.held,
        }
        for stage in sorted(STAGES.values(), key=lambda s: (s.order, s.key))
    ]


__all__ = [
    "EXECUTED_STEP_STATUSES",
    "HELD_STAGE",
    "INHERITING_STEP_STATUSES",
    "MAPPED_SUFFIX",
    "STAGE_WORDS",
    "STATE_WORDS",
    "StateWords",
    "stage_words",
    "state_words_payload",
    "step_inherits_proof",
    "step_is_executed",
    "step_proves",
    "step_source_proven",
    "OCCURRENCE_ACCESS_ONLY",
    "OCCURRENCE_COMPROMISED",
    "OCCURRENCE_PLAIN",
    "RESULTING_STATES",
    "STAGES",
    "NodeOccurrence",
    "PropertyMark",
    "StageDefinition",
    "StepStateResolver",
    "StepStateSemantics",
    "TrackTransition",
    "is_held_stage",
    "route_occurrences",
    "set_step_state_provider",
    "stage_of_state",
    "stage_payload",
    "step_attachments",
    "step_semantics",
    "step_state_provider",
]
