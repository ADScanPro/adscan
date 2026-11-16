"""Record types of the workspace graph store (the interface contract).

The graph store is the INTERNAL working store behind one domain's attack graph:
the raw inventory the collectors append, the runtime overlay the exploitation
steps write, and the build watermark. ``attack_graph.json`` is an EXPORT built
from it and stays the file the web and integrators read. Design:
``docs/superpowers/specs/2026-11-12-inventory-first-graph-persistence.md``.

These dataclasses are the wire format between every package of that design, so
they are frozen, hold only JSON-serialisable values, and never carry a secret:
a secret-bearing note is replaced by a credential-store reference BEFORE it
reaches a record (``adscan_core.graph_secret_refs``).

Stdlib only: imported by the engine, the web backend and the Windows bundle.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

#: Bumped when a record or table changes shape. A store written by a different
#: major is refused by ``open_graph_store`` (it is rebuilt from a re-collection
#: or migrated by the store module, never read on trust).
GRAPH_STORE_SCHEMA_VERSION = 1

# --------------------------------------------------------------------------- #
# Collection stages
# --------------------------------------------------------------------------- #

#: A collector stage. Open vocabulary by design (a new stage needs no store
#: change), but the stages the engine ships are named here so two packages
#: never spell one differently.
STAGE_LDAP_OBJECTS = "ldap_objects"
STAGE_LDAP_ACLS = "ldap_acls"
STAGE_LDAP_RELATIONSHIPS = "ldap_relationships"
STAGE_WELL_KNOWN = "well_known_principals"
STAGE_ADCS = "adcs"
STAGE_ADCS_CA_REGISTRY = "adcs_ca_registry"
STAGE_TRUSTS = "trusts"
STAGE_SMB_HOSTS = "smb_hosts"
STAGE_SMB_SHARES = "smb_shares"
STAGE_MSSQL = "mssql"
STAGE_UNAUTH = "unauthenticated"
STAGE_CVE = "cve_checks"
#: A 14.0.x ``attack_graph.json`` imported as the base layer (no raw inventory).
STAGE_LEGACY_IMPORT = "legacy_graph_import"

KNOWN_STAGES: tuple[str, ...] = (
    STAGE_LDAP_OBJECTS,
    STAGE_LDAP_ACLS,
    STAGE_LDAP_RELATIONSHIPS,
    STAGE_WELL_KNOWN,
    STAGE_ADCS,
    STAGE_ADCS_CA_REGISTRY,
    STAGE_TRUSTS,
    STAGE_SMB_HOSTS,
    STAGE_SMB_SHARES,
    STAGE_MSSQL,
    STAGE_UNAUTH,
    STAGE_CVE,
    STAGE_LEGACY_IMPORT,
)

#: How a stage run ended. ``running`` is also what a crash leaves behind.
StageStatus = Literal["running", "complete", "stopped", "skipped", "failed"]

#: Unit name for a stage that is not split into units (one commit for the stage).
WHOLE_STAGE_UNIT = "*"


@dataclass(frozen=True)
class ObjectRecord:
    """One directory object as collected (a future graph node).

    Mirrors ``collector.models.CollectorNode`` field for field, so the collector
    converts without loss. Keyed by ``object_id`` (SID, or GUID for objects
    without one); a later record for the same id REPLACES the earlier one.
    """

    object_id: str
    kind: str
    name: str
    domain: str
    samaccountname: str = ""
    distinguished_name: str = ""
    enabled: bool | None = None
    highvalue: bool = False
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class FactRecord:
    """One raw relationship observed by a collector (a future base edge, or an input to one).

    The same level as ``collector.models.CollectorEdge``: the collector has
    already decoded the ACE / membership / session / share grant into a
    relation name; nothing is DERIVED yet (no Kerberoasting, DCSync, ESC, ...).

    Attributes:
        subject_id: Object id of the principal that holds the right (edge source).
        object_id: Object id of what the right is over (edge target).
        relation: Relation name as the collector emits it (``GenericAll``,
            ``MemberOf``, ``HasSession``, ``AdminTo``, ``ReadShare``, ...).
        source: Collector that observed it (``ldap``, ``smb``, ``mssql``, ...).
            The base edge's ``edge_type`` is ``native_<source>``.
        method: How it was observed (``acl``, ``samr_builtin``, ``share_acl:<name>``).
        notes: Small JSON object. Becomes the edge's ``notes``. Never a secret.
        first_seen: Set by the store on read: when a fact with this identity
            (stage, subject, object, relation, method, identity notes) was first
            committed. Survives the replacement of its unit, so a re-collected
            host does not make its long-standing edges look new.
        last_seen: Set by the store on read: when its unit was last committed.
    """

    subject_id: str
    object_id: str
    relation: str
    source: str
    method: str = ""
    notes: dict[str, Any] = field(default_factory=dict)
    first_seen: str = ""
    last_seen: str = ""


@dataclass(frozen=True)
class DatumRecord:
    """One typed collection result that is neither an object nor a relationship.

    Domain policy, PSOs, audit findings, shadow-credential findings, password
    compliance, MSSQL instance facts, AD CS CA configuration: whatever the build
    or the inventory export needs and the collector holds today on
    ``CollectionResult``. ``kind`` names the family, ``key`` identifies the
    record inside it (replace-on-same-key), ``body`` is the JSON payload.
    """

    kind: str
    key: str
    body: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class StageRun:
    """State of one collector stage in the store.

    ``units_done`` counts committed units; ``units_total`` is 0 when the stage
    does not know its total up front. ``detail`` is operator text for a stop,
    skip or failure and feeds the coverage declaration; it is never client copy.
    """

    stage: str
    status: StageStatus
    run_id: str = ""
    units_total: int = 0
    units_done: int = 0
    reason: str = ""
    detail: str = ""
    collector_version: str = ""
    started_at: str = ""
    updated_at: str = ""


# --------------------------------------------------------------------------- #
# Runtime overlay
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class EdgeRef:
    """Identity of one graph edge by its endpoints, as the graph names them.

    ``from_id`` / ``to_id`` are graph node ids. The overlay keys an edge by
    ``adscan_core.attack_graph_edge_identity.attack_graph_edge_fingerprint`` of
    ``(from_id, relation, to_id, notes)``, the SSOT the web shares, so a status
    written at runtime lands on the same edge after any rebuild.
    """

    from_id: str
    to_id: str
    relation: str
    #: Only the identity-bearing notes (the share of a share-access edge).
    identity_notes: dict[str, Any] = field(default_factory=dict)


#: What a runtime operation does. The build applies them in ``seq`` order.
OverlayOpKind = Literal[
    "upsert_node",  # a node the inventory does not hold (synthetic, runtime-found)
    "patch_node",  # merge properties into a node (base or overlay)
    "upsert_edge",  # an edge found at runtime (AdminTo from a sweep, a reuse edge)
    "set_edge_status",  # an attack-step status transition, with optional notes merge
    "patch_edge",  # merge notes / top-level stamps into an edge, status untouched
    "retire_edge",  # the edge no longer holds (a cleaned-up change); kept as history
    "reset_statuses",  # bulk: put executed statuses back to their discovered state
]


@dataclass(frozen=True)
class OverlayOp:
    """One runtime mutation of the graph, appended to the overlay.

    The overlay is an ordered log: nothing in it is ever rewritten, so an
    executed step's status survives every rebuild, and "what did ADscan do, in
    what order" is answerable from the store alone.

    Attributes:
        kind: The operation.
        edge: Target edge, for the edge operations.
        node_id: Target graph node id, for the node operations.
        status: New status for ``set_edge_status`` / initial status for ``upsert_edge``.
        edge_type: ``edge_type`` for ``upsert_edge`` (``runtime``, ``netexec_privilege``, ...).
        payload: Notes to merge (edge ops), node payload (``upsert_node``),
            properties (``patch_node``), or the selector of ``reset_statuses``.
        origin: Which writer produced it (module or step id), for diagnosis.
        run_id: Recorded run that produced it ("" outside a recorded run).
        seq: Store-assigned order. 0 on a record not yet appended.
        recorded_at: UTC ISO timestamp assigned by the caller's clock.
    """

    kind: OverlayOpKind
    edge: EdgeRef | None = None
    node_id: str = ""
    status: str = ""
    edge_type: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    origin: str = ""
    run_id: str = ""
    seq: int = 0
    recorded_at: str = ""


# --------------------------------------------------------------------------- #
# Build state
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class StoreGeneration:
    """What the store held at one instant: the build's cache key.

    Two equal generations hold the same inventory and the same overlay, so a
    graph built from one is valid for the other. ``inventory`` moves on every
    committed unit, ``overlay`` on every appended op.
    """

    inventory: int = 0
    overlay: int = 0


@dataclass(frozen=True)
class ExportRecord:
    """The last ``attack_graph.json`` written from the store.

    A graph is current for ``(generation, fingerprint)``: the store generation
    covers what the store holds, ``fingerprint`` (the build context's
    ``GraphBuildContext.fingerprint()``, "" when unknown) the inputs from
    outside it. A backend persists both. A record read back without its
    fingerprint ("") matches only an export made without a context, so it
    never proves an export current by mistake: the next one rewrites it.
    """

    generation: StoreGeneration = field(default_factory=StoreGeneration)
    exported_at: str = ""
    duration_seconds: float = 0.0
    nodes: int = 0
    edges: int = 0
    size_bytes: int = 0
    fingerprint: str = ""


@dataclass(frozen=True)
class StoreStats:
    """Counts for the bench, the doctor command and the coverage record."""

    objects: int = 0
    facts: int = 0
    data: int = 0
    overlay_ops: int = 0
    size_bytes: int = 0


__all__ = (
    "GRAPH_STORE_SCHEMA_VERSION",
    "KNOWN_STAGES",
    "WHOLE_STAGE_UNIT",
    "DatumRecord",
    "EdgeRef",
    "ExportRecord",
    "FactRecord",
    "ObjectRecord",
    "OverlayOp",
    "OverlayOpKind",
    "StageRun",
    "StageStatus",
    "StoreGeneration",
    "StoreStats",
)
