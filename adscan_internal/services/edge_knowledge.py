"""Technique knowledge of an attack-graph edge, rendered when it is read.

Until ``attack_graph.json`` format 2 every technique edge carried its own copy
of the description, remediation and verification text (about 10 KB per edge,
1.7 GB on a 288,000-edge graph). The text now lives where it is authored, the
attack-step catalog, and this module renders it for one edge on demand: the
block for the relation, then this edge's own differences (its endpoints'
identities, the scan's coordinates, the facts in its notes).

ONE renderer for every reader: the web edge panel, the graph writer's
``technique_knowledge`` block, the format-1 compatibility writer and the
optional integrator export all call :func:`render_edge_knowledge` or
:func:`render_relation_knowledge`, so they cannot word one edge differently.
It is pure (no ``shell``, no file access beyond the arguments) and import-safe
for the appliance backend: its closure is the attack-step catalog, the finding
catalog and the affected-assets helpers the backend already bundles, plus the
``step_identity`` and ``finding_specifics`` leaves.

The output is byte-identical to the block ``upsert_edge`` baked and
``save_attack_graph`` refreshed before format 2, locked by
``tests/unit/services/test_edge_knowledge_renderer.py`` against digests frozen
from that bake.
Design: ``docs/superpowers/specs/2026-11-12-inventory-first-graph-persistence.md``.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Iterator, Mapping
from typing import TYPE_CHECKING, Any

from adscan_core.attack_graph_coordinates import GraphCoordinates
from adscan_core.attack_graph_edge_identity import attack_graph_edge_fingerprint

if TYPE_CHECKING:  # pragma: no cover - typing only
    from adscan_internal.services.affected_assets_struct import (
        GroupMemberExampleResolver,
    )


# ── Relation-level block ──────────────────────────────────────────────────────

#: Suffix of a ``knowledge_ref`` for an edge whose source is Tier 0 direct.
_TIER0_DIRECT_REF_SUFFIX = "#tier0_direct"

# Cache of the relation-level block, keyed by ``(relation, source_is_tier0_direct)``.
# The prose is a function of the relation, that one flag and the static
# catalogs, so it is resolved once per key per process. ``{}`` records a
# relation that maps to no technique.
_RELATION_KNOWLEDGE_CACHE: dict[tuple[str, bool], dict[str, Any]] = {}


def _report_exception(exc: BaseException) -> None:
    """Telemetry plus the debug-log traceback for a swallowed render failure."""
    try:
        from adscan_core import telemetry  # noqa: PLC0415
        from adscan_core.rich_output import print_exception  # noqa: PLC0415

        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    except Exception:  # noqa: BLE001 - reporting never breaks a render
        pass


def _normalize_relation(relation: Any) -> str:
    return str(relation or "").strip()


def _normalize_relation_key(value: str) -> str:
    """Case-insensitive, punctuation-free relation key."""
    return re.sub(r"[^a-z0-9]+", "", (value or "").strip().lower())


def _relation_block(relation: str, source_is_tier0_direct: bool) -> dict[str, Any] | None:
    """The cached relation-level block (shared; callers copy before changing it).

    Reuses ``build_step_knowledge``, the per-step technique prose SSOT that also
    feeds ``attack_paths_snapshot.json``, so the edge card and the path-step card
    read identical prose. Only TECHNIQUE relations (those resolving to a
    ``vuln_key``) carry a block; a structural relation (MemberOf, Contains,
    GpLink) yields ``None``. The finding catalog adds the title and severity the
    web panel renders its severity band from.
    """
    if not relation:
        return None
    cache_key = (relation, bool(source_is_tier0_direct))
    cached = _RELATION_KNOWLEDGE_CACHE.get(cache_key)
    if cached is not None:
        return cached or None
    try:
        from adscan_internal.services.attack_step_catalog import (  # noqa: PLC0415
            build_step_knowledge,
        )
        from adscan_internal.services.compromise_class import (  # noqa: PLC0415
            PrivilegeTier,
        )

        knowledge = build_step_knowledge(
            {
                "relation": relation,
                "details": {
                    "source_privilege_tier": (
                        PrivilegeTier.TIER0_DIRECT.value
                        if source_is_tier0_direct
                        else PrivilegeTier.TIER2.value
                    )
                },
            }
        )
    except Exception as exc:  # noqa: BLE001
        _report_exception(exc)
        knowledge = None

    block: dict[str, Any] | None = None
    catalog_key = (
        str(knowledge.get("vuln_key") or "").strip() if isinstance(knowledge, dict) else ""
    )
    if isinstance(knowledge, dict) and knowledge and catalog_key:
        block = knowledge
        try:
            from adscan_internal.pro.reporting.vuln_catalog import (  # noqa: PLC0415
                VULN_CATALOG,
            )

            catalog_entry = VULN_CATALOG.get(catalog_key)
        except Exception:  # noqa: BLE001 - a LITE runtime has no finding catalog
            catalog_entry = None
        if isinstance(catalog_entry, dict):
            title = str(catalog_entry.get("title") or "").strip()
            severity = str(catalog_entry.get("severity") or "").strip()
            if title:
                block["title"] = title
            if severity:
                block["severity"] = severity
    _RELATION_KNOWLEDGE_CACHE[cache_key] = block if isinstance(block, dict) else {}
    return block


def render_relation_knowledge(
    relation: str, *, source_is_tier0_direct: bool = False
) -> dict[str, Any] | None:
    """The generic block for a relation (no edge specifics), or ``None`` for a
    structural relation. Cached per ``knowledge_ref``. This is what the graph
    export writes once per relation into ``technique_knowledge``."""
    block = _relation_block(_normalize_relation(relation), source_is_tier0_direct)
    return copy.deepcopy(block) if block else None


def knowledge_ref(relation: str, *, source_is_tier0_direct: bool = False) -> str:
    """Key of a relation's generic knowledge block in the graph's
    ``technique_knowledge`` map ("" for a relation with no technique)."""
    relation_norm = _normalize_relation(relation)
    if not _relation_block(relation_norm, source_is_tier0_direct):
        return ""
    return relation_norm + (_TIER0_DIRECT_REF_SUFFIX if source_is_tier0_direct else "")


def source_is_tier0_direct(source_node: Mapping[str, Any] | None) -> bool:
    """Whether an edge out of ``source_node`` is built-in AD hierarchy.

    Such an edge's block carries the structural-hierarchy line instead of
    removal advice (telling a client to strip replication rights off its own
    domain controllers would be wrong).
    """
    try:
        from adscan_internal.services.compromise_class import (  # noqa: PLC0415
            is_structural_hierarchy_source,
        )

        return is_structural_hierarchy_source(
            source_node if isinstance(source_node, Mapping) else None
        )
    except Exception as exc:  # noqa: BLE001
        _report_exception(exc)
        return False


# ── Edge-level specifics ──────────────────────────────────────────────────────

#: Relations whose execution seams stamp a defensive-posture observation onto
#: the edge (the credential-dump family), as ``_normalize_relation_key`` spells
#: them. Keyed through that normalizer because a graph edge arrives as
#: ``DumpSAM`` and a lower-case membership test never matched (the fix that
#: introduced this set was a no-op in production until then).
#: ``backupoperatorescalation`` belongs here because ``cli/dumps.py`` stamps
#: registry posture notes onto that edge too; ``dumpdpapi`` has its own
#: renderer.
POSTURE_BEARING_RELATIONS: frozenset[str] = frozenset(
    {
        "dumplsass",
        "dumplsa",
        "dumpsam",
        "backupoperatorescalation",
        "backupoperatorsescalation",
        "dumpdpapi",
    }
)


def render_edge_posture_context(relation: str, edge_notes: Mapping[str, Any] | None) -> str:
    """THIS edge's defensive-posture sentence, or ``""``.

    Built from the edge's posture notes (stamped at the dump seam) through the
    catalog SSOT, so the web CTEM renders the SAME authored sentence the PDF
    reads from the step details. The three renderers key on non-overlapping
    stamp fields, so at most one produces a sentence. Empty for an edge without
    posture notes, so it never fabricates a claim.
    """
    if (
        not edge_notes
        or _normalize_relation_key(relation) not in POSTURE_BEARING_RELATIONS
    ):
        return ""
    try:
        from adscan_internal.services.attack_step_catalog import (  # noqa: PLC0415
            render_dpapi_posture_context,
            render_lsass_posture_context,
            render_registry_posture_context,
        )

        posture_step = {"relation": relation, "details": dict(edge_notes)}
        return (
            render_lsass_posture_context(posture_step)
            or render_registry_posture_context(posture_step)
            or render_dpapi_posture_context(posture_step)
        )
    except Exception as exc:  # noqa: BLE001 - a render never breaks the reader
        _report_exception(exc)
        return ""


def personalize_relation_knowledge(
    relation: str,
    edge_notes: Mapping[str, Any] | None,
    *,
    source_is_tier0_direct: bool = False,
    dc_ip: str = "",
    domain: str = "",
) -> dict[str, Any] | None:
    """Weave one edge's concrete assets into the relation block.

    The impact and remediation name the exact assets on the edge (the abused
    certificate template, the enrolling principal), the verification commands
    are filled with ``dc_ip`` and ``domain`` against the edge's labels, and the
    posture sentence is added when the edge carries one. Never mutates the
    cached relation block. ``None`` when the relation maps to no technique and
    the edge carries no posture observation.

    Mirrors the finding-side weave in ``report_service.sync_attack_graph_findings``
    through the SAME affected-assets SSOT, so the edge card and the finding card
    name identical assets. ``<user>``/``<pass>`` tokens are never substituted.
    """
    relation = _normalize_relation(relation)
    base = _relation_block(relation, source_is_tier0_direct)
    notes: dict[str, Any] = dict(edge_notes) if isinstance(edge_notes, Mapping) else {}
    posture_context = render_edge_posture_context(relation, notes)
    if not isinstance(base, dict) or not base:
        # The credential-dump family has no technique block (no ``vuln_key``)
        # but is exactly what carries a posture observation, an edge-observed
        # fact that travels on its own.
        return {"defensive_posture_context": posture_context} if posture_context else base
    verify_override: dict[str, Any] = {}
    if (dc_ip or domain) and (
        base.get("verify_windows") or base.get("verify_linux") or base.get("verification")
    ):
        try:
            from adscan_core.reporting.verification_model import (  # noqa: PLC0415
                legacy_text_from_items,
            )
            from adscan_internal.services.attack_step_catalog import (  # noqa: PLC0415
                render_step_verification,
            )

            verify_step = {
                "relation": relation,
                "details": {
                    **notes,
                    "from": str(notes.get("source_label") or ""),
                    "to": str(notes.get("target_label") or ""),
                    **({"dc_ip": dc_ip} if dc_ip else {}),
                    **({"domain": domain} if domain else {}),
                },
            }
            rendered = render_step_verification(verify_step)
            if rendered["verify"] or rendered["exploit"]:
                verify_override["verification"] = rendered
            windows = legacy_text_from_items(rendered["verify"], "windows")
            linux = legacy_text_from_items(rendered["verify"], "linux")
            if windows and base.get("verify_windows"):
                verify_override["verify_windows"] = windows
            if linux and base.get("verify_linux"):
                verify_override["verify_linux"] = linux
        except Exception as exc:  # noqa: BLE001
            _report_exception(exc)

    def _with_verify(result: dict[str, Any] | None) -> dict[str, Any] | None:
        if not isinstance(result, dict) or (not verify_override and not posture_context):
            return result
        merged = dict(result)
        merged.update(verify_override)
        if posture_context:
            merged["defensive_posture_context"] = posture_context
        return merged

    if not notes and not verify_override and not posture_context:
        return base
    try:
        from adscan_internal.pro.reporting.finding_specifics import (  # noqa: PLC0415
            weave_specifics_into_knowledge,
        )
    except Exception:  # noqa: BLE001 - a LITE runtime has no finding catalog
        return _with_verify(base)
    vuln_key = str(base.get("vuln_key") or "").strip()
    if not vuln_key or not notes:
        return _with_verify(base)
    synthetic_details = {
        "attack_graph_edges": [
            {
                "relation": relation,
                "source": notes.get("source_label") or "",
                "target": notes.get("target_label") or "",
                "notes": notes,
            }
        ]
    }
    try:
        return _with_verify(weave_specifics_into_knowledge(vuln_key, base, synthetic_details))
    except Exception as exc:  # noqa: BLE001
        _report_exception(exc)
        return _with_verify(base)


def edge_verification_step(
    edge: Mapping[str, Any],
    env: Mapping[str, str],
    *,
    source_node: Mapping[str, Any] | None = None,
    target_node: Mapping[str, Any] | None = None,
    stamp_identity: bool = True,
    member_resolver: GroupMemberExampleResolver | None = None,
) -> dict[str, Any]:
    """The synthetic step a technique edge's verify block renders against.

    Carries the edge's own notes (template, CA, SPNs, impersonation hint), the
    graph coordinates, and the REAL identifiers of both endpoint nodes so a
    command names the object the client can resolve, never the display label.
    A GROUP source acts through a known member (membership SSOT, a controlled
    one first), the same rule the report's step render uses.
    """
    notes = edge.get("notes") if isinstance(edge.get("notes"), Mapping) else {}
    details: dict[str, Any] = {
        **notes,
        "from": str(notes.get("source_label") or edge.get("from") or ""),
        "to": str(notes.get("target_label") or edge.get("to") or ""),
        **env,
    }
    if stamp_identity:
        from adscan_internal.services.step_identity import (  # noqa: PLC0415
            stamp_step_identity,
        )

        stamp_step_identity(details, source_node, target_node)
    if member_resolver is not None:
        from adscan_internal.services.affected_assets_struct import (  # noqa: PLC0415
            stamp_step_source_member,
        )

        stamp_step_source_member(details, member_resolver)
    return {"relation": _normalize_relation(edge.get("relation")), "details": details}


def _refresh_verification(
    knowledge: dict[str, Any],
    edge: Mapping[str, Any],
    env: Mapping[str, str],
    *,
    source_node: Mapping[str, Any] | None,
    target_node: Mapping[str, Any] | None,
    member_resolver: GroupMemberExampleResolver | None,
) -> dict[str, Any]:
    """Re-render the verification block against the edge's own endpoints.

    The block from :func:`personalize_relation_knowledge` is filled from the
    edge's labels; this fills it from the endpoint nodes' real identifiers and
    every graph coordinate. A no-op without coordinates or without a verify
    block. Returns a new dict when something changed.
    """
    if not (env.get("dc_ip") or env.get("domain")):
        return knowledge
    if not (
        knowledge.get("verify_windows")
        or knowledge.get("verify_linux")
        or knowledge.get("verification")
    ):
        return knowledge
    if not _normalize_relation(edge.get("relation")):
        return knowledge
    try:
        from adscan_core.reporting.verification_model import (  # noqa: PLC0415
            legacy_text_from_items,
        )
        from adscan_internal.services.attack_step_catalog import (  # noqa: PLC0415
            render_step_verification,
        )

        rendered = render_step_verification(
            edge_verification_step(
                edge,
                env,
                source_node=source_node,
                target_node=target_node,
                member_resolver=member_resolver,
            )
        )
    except Exception:  # noqa: BLE001 - keep the label-filled commands
        return knowledge
    updates: dict[str, Any] = {}
    if rendered["verify"] or rendered["exploit"]:
        updates["verification"] = rendered
    windows = legacy_text_from_items(rendered["verify"], "windows")
    linux = legacy_text_from_items(rendered["verify"], "linux")
    if windows:
        updates["verify_windows"] = windows
    if linux:
        updates["verify_linux"] = linux
    if not any(knowledge.get(key) != value for key, value in updates.items()):
        return knowledge
    refreshed = dict(knowledge)
    refreshed.update(updates)
    return refreshed


def _edge_is_engine_followup(edge: Mapping[str, Any]) -> bool:
    from adscan_core.reporting.engine_followup import (  # noqa: PLC0415
        notes_are_engine_followup,
    )

    return notes_are_engine_followup(edge.get("notes"))


def render_edge_knowledge(
    edge: Mapping[str, Any],
    *,
    source_node: Mapping[str, Any] | None,
    target_node: Mapping[str, Any] | None,
    coordinates: GraphCoordinates,
    member_resolver: GroupMemberExampleResolver | None = None,
) -> dict[str, Any] | None:
    """The knowledge block of ONE edge, with this edge's specifics filled in.

    Returns the same keys a format-1 edge carried under ``knowledge`` (so a
    consumer's rendering code does not change), or ``None`` when the edge has
    neither a technique nor an observed defensive-posture context.

    A format-1 edge that still carries a baked ``knowledge`` block is rendered
    from the catalog like any other; the stored block is ignored, so a workspace
    written by 14.0.x reads with current wording.

    ``member_resolver`` is the workspace's group-member resolver
    (``affected_assets_struct.safe_member_example_resolver``); without it a
    group source keeps a fill-in token in its commands.
    """
    if not isinstance(edge, Mapping):
        return None
    relation = _normalize_relation(edge.get("relation"))
    if not relation:
        return None
    notes = edge.get("notes") if isinstance(edge.get("notes"), Mapping) else {}
    # An engine follow-up was baked by the writer without the source-tier flag;
    # kept so the text stays the one the bake produced.
    tier0_direct = (
        False if _edge_is_engine_followup(edge) else source_is_tier0_direct(source_node)
    )
    knowledge = personalize_relation_knowledge(
        relation,
        notes,
        source_is_tier0_direct=tier0_direct,
        dc_ip=coordinates.dc_ip,
        domain=coordinates.domain,
    )
    if not knowledge:
        return None
    knowledge = _refresh_verification(
        knowledge,
        edge,
        coordinates.verification_env(),
        source_node=source_node,
        target_node=target_node,
        member_resolver=member_resolver,
    )
    # Never hand out the shared cached block: a caller may change its copy.
    return copy.deepcopy(knowledge)


def edge_endpoints(edge: Mapping[str, Any]) -> tuple[str, str]:
    """``(source id, target id)``; host-check edges name them ``source``/``target``."""
    return (
        str(edge.get("from") or edge.get("source") or "").strip(),
        str(edge.get("to") or edge.get("target") or "").strip(),
    )


def iter_edge_knowledge(
    graph: Mapping[str, Any],
    *,
    member_resolver: GroupMemberExampleResolver | None = None,
) -> Iterator[tuple[str, dict[str, Any]]]:
    """``(edge fingerprint, knowledge block)`` for every technique edge of a
    graph, streamed. Backs the integrator export and the format-1 compatibility
    writer; never materialises all blocks at once."""
    if not isinstance(graph, Mapping):
        return
    coordinates = GraphCoordinates.from_graph(graph)
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), Mapping) else {}
    edges = graph.get("edges")
    if not isinstance(edges, list):
        return
    for edge in edges:
        if not isinstance(edge, Mapping):
            continue
        source_id, target_id = edge_endpoints(edge)
        block = render_edge_knowledge(
            edge,
            source_node=nodes.get(source_id),
            target_node=nodes.get(target_id),
            coordinates=coordinates,
            member_resolver=member_resolver,
        )
        if not block:
            continue
        yield (
            attack_graph_edge_fingerprint(
                source_id, _normalize_relation(edge.get("relation")), target_id, edge.get("notes")
            ),
            block,
        )


def build_technique_knowledge(graph: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """The root ``technique_knowledge`` map of a format-2 graph.

    One generic block per ``knowledge_ref`` the graph's edges use, so its size
    follows the number of relation types in the graph, not the number of edges.
    """
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), Mapping) else {}
    edges = graph.get("edges")
    seen: set[tuple[str, bool]] = set()
    blocks: dict[str, dict[str, Any]] = {}
    if not isinstance(edges, list):
        return blocks
    for edge in edges:
        if not isinstance(edge, Mapping):
            continue
        relation = _normalize_relation(edge.get("relation"))
        if not relation:
            continue
        tier0_direct = (
            False
            if _edge_is_engine_followup(edge)
            else source_is_tier0_direct(nodes.get(str(edge.get("from") or "")))
        )
        key = (relation, tier0_direct)
        if key in seen:
            continue
        seen.add(key)
        ref = knowledge_ref(relation, source_is_tier0_direct=tier0_direct)
        if ref:
            block = render_relation_knowledge(relation, source_is_tier0_direct=tier0_direct)
            if block:
                blocks[ref] = block
    return dict(sorted(blocks.items()))


__all__ = (
    "GraphCoordinates",
    "POSTURE_BEARING_RELATIONS",
    "build_technique_knowledge",
    "edge_endpoints",
    "edge_verification_step",
    "iter_edge_knowledge",
    "knowledge_ref",
    "personalize_relation_knowledge",
    "render_edge_knowledge",
    "render_edge_posture_context",
    "render_relation_knowledge",
    "source_is_tier0_direct",
)
