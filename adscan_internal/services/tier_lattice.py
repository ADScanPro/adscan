"""Single source of truth for per-target tier classification.

Answers, for one attack-step edge: *what tier of standing does arriving at the
TARGET via this edge confer on that target object?* This is the primitive the
tier-aware display filters consume so a higher-tier path (Domain object / direct
compromise) is never trimmed against a lower-tier one.

Design input: docs/superpowers/specs/2026-06-06-tier-lattice-research.md.

Ground-truth ONLY — this module deliberately does NOT read
``compromise_semantics`` (the research found it mislabels >=12 relations, e.g.
CanPSRemote tagged local_admin_session when it is USER-level). Tier is derived
from: the access-lane model (``access_followups._ACCESS_LANES`` — the single
truth for which ACCESS relations confer a local-admin session), ``EdgeKind``,
the target node's own tier (``compromise_class``), and the T2A4D conditional
encoded in :func:`edge_grants_local_admin_session`. ``SPNJack`` is the only
non-access (ESCALATION) relation that deterministically grants local admin.

Comparability: tiers in DIFFERENT lanes are NON-comparable — ``tier_dominates``
returns False across lanes. This is the safe direction: the filters only ever
*prevent* a trim, never force one, so erring toward incomparable stops the
over-trimming this work targets. The ``domain`` lane (target IS the Domain
object / a direct domain breaker) is the top lane and is never dominated.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final, Literal, Mapping

from adscan_internal.services.attack_step_support_registry import (
    CONTEXT_ONLY_RELATIONS,
)
from adscan_internal.services.compromise_class import (
    is_direct_domain_breaker_target,
    is_privileged_escalator_target,
)
from adscan_internal.services.edge_kind import EdgeKind, classify_edge_kind
from adscan_internal.services.post_exploitation.access_followups import (
    get_access_lane,
    grants_host_system_session,
    is_principal_compromise_followup,
    is_self_credential_followup,
)
from adscan_internal.services.post_exploitation.models import PrivLevel

# Context relations whose terminal does not confer a tier on the target. Mirrors
# attack_paths_core._CONTEXT_RELATIONS_LOWER (same registry source) — kept here so
# tier_lattice has no dependency on attack_paths_core (which imports this module).
_CONTEXT_RELATIONS_LOWER: Final[frozenset[str]] = frozenset(
    str(rel).strip().lower() for rel in CONTEXT_ONLY_RELATIONS.keys()
)


# Lane order is NOT a total order across lanes (cross-lane = incomparable). Within
# the ``os`` / ``mssql`` lanes, ``level`` uses PrivLevel.rank (USER=1 <
# LOCAL_ADMIN=2 < SYSTEM=3). The single-level lanes use level 1.
TierLane = Literal["context", "os", "mssql", "object", "cred", "domain"]

_OBJECT_LEVEL: Final[int] = 1
_CRED_LEVEL: Final[int] = 1
_DOMAIN_LEVEL: Final[int] = 1


@dataclass(frozen=True)
class TargetTier:
    """The tier conferred on a target object by one terminal edge.

    Attributes:
        lane: Comparability bucket. Tiers in different lanes never dominate one
            another.
        level: Ordered WITHIN the lane (os/mssql use PrivLevel.rank; single-level
            lanes use 1).
        self_cred_recovered: True after the DumpLSA self-credential follow-up has
            "become" the host machine account — strictly dominates a bare
            local-admin session at the same level on the same lane.
    """

    lane: TierLane
    level: int
    self_cred_recovered: bool = False


def source_grants_local_admin_for_relation(
    relation: str | None, source_node: Mapping[str, Any] | None
) -> bool:
    """Return True when ``relation`` from ``source_node`` yields local admin.

    The access-lane model (``access_followups._ACCESS_LANES``) is the single
    truth for which ACCESS relations confer a local-admin session
    (``unlocks_self_credential``). ``SPNJack`` is the only non-access
    (ESCALATION) relation that deterministically grants local admin.
    ``AllowedToDelegate`` does so ONLY when the source has protocol transition
    (``hastrustedtoauth`` / TrustedToAuthForDelegation) — the C1 conditional.
    The MSSQL SYSTEM-escalation self-loops (``MssqlSeImpersonateEscalation`` /
    ``MssqlTokenTheftEscalation``) grant local admin unconditionally: reaching
    ``NT AUTHORITY\\SYSTEM`` on the host IS the host machine account, so the
    self-credential DumpLSA bridge and the direct-DCSync bridge (F6) both unlock
    off them, exactly as they do off ``AdminTo`` (``grants_host_system_session``).
    """
    rel = str(relation or "").strip().lower()
    lane = get_access_lane(rel)
    if lane is not None:
        return lane.unlocks_self_credential
    if rel == "spnjack":
        return True
    if grants_host_system_session(rel):
        return True
    if rel == "allowedtodelegate":
        props = (
            source_node.get("properties")
            if isinstance(source_node, Mapping)
            and isinstance(source_node.get("properties"), Mapping)
            else {}
        )
        return bool(props.get("hastrustedtoauth"))
    return False


def edge_grants_local_admin_session(
    edge: dict[str, Any], nodes_map: dict[str, Any]
) -> bool:
    """Return True when this edge yields a deterministic local-admin session.

    Relocated from attack_graph_core (unchanged behavior). Resolves the source
    node from ``nodes_map`` and defers to
    :func:`source_grants_local_admin_for_relation`.
    """
    source_node = nodes_map.get(str(edge.get("from") or "").strip())
    return source_grants_local_admin_for_relation(
        edge.get("relation"), source_node if isinstance(source_node, dict) else None
    )


def _is_stamped_direct_breaker(node: Mapping[str, Any] | None) -> bool:
    """Return whether ``node`` carries a membership-aware ``tier0_direct`` stamp.

    Tier-label SSOT: this augments the name/RID ``is_direct_domain_breaker_target``
    detector so a terminal on a Domain Admins MEMBER (a User the NAME matcher on
    its own identity misses, but whose membership-aware stamp is ``tier0_direct``)
    is classified into the top ``domain`` lane. It is purely ADDITIVE — it only
    ever RAISES a terminal into the protective domain lane, never lowers one — so
    the redundant-MemberOf minimizer never strips a proven compromise prefix. The
    stamped-label read is unconditional — validated in lab and made permanent (the
    ADSCAN_TIER_LABEL_SSOT reader switch was removed 2026-09-09).
    """
    from adscan_internal.services.compromise_class import (  # noqa: PLC0415
        PrivilegeTier,
        node_stamped_privilege_tier,
    )

    return node_stamped_privilege_tier(node) is PrivilegeTier.TIER0_DIRECT


def classify_target_tier(
    *,
    relation: str | None,
    source_node: Mapping[str, Any] | None,
    target_node: Mapping[str, Any] | None,
    prior_path_relations: list[str],
) -> TargetTier:
    """Classify the tier conferred on ``target_node`` by ``relation``.

    Order matters: domain-terminal first (top, protective), then the DumpLSA
    self-cred upgrade, then access lanes (ground truth, overrides catalog
    semantics), then the local-admin escalation/delegation conditional, then the
    EdgeKind fallback for control/cred edges, then the context floor.
    """
    rel = str(relation or "").strip().lower()

    # 1. Domain object / direct domain breaker target — top lane, never dominated.
    #    A principal-compromise follow-up self-loop (DumpLSA / DumpLSASS /
    #    ScheduledTask) landing on a domain-breaker principal still carries the
    #    access→ownership tier bump: without it, an access arrival (HasSession)
    #    and the compromise re-arrival (ScheduledTask) on the SAME domain-breaker
    #    user would be indistinguishable (both domain/_DOMAIN_LEVEL), and the
    #    redundant-MemberOf minimizer would wrongly strip the compromise prefix.
    #    Mirrors the self_cred_recovered bump DumpLSA gets on a (non-breaker) host.
    if is_direct_domain_breaker_target(target_node) or _is_stamped_direct_breaker(
        target_node
    ):
        return TargetTier(
            lane="domain",
            level=_DOMAIN_LEVEL,
            self_cred_recovered=is_principal_compromise_followup(rel),
        )

    # 2. Self-credential follow-up (DumpLSA): "became" the host machine account.
    if is_self_credential_followup(rel):
        return TargetTier(
            lane="os", level=PrivLevel.LOCAL_ADMIN.rank, self_cred_recovered=True
        )

    # 3. Access (AUTH) edges — access-lane model is ground truth, NOT semantics.
    lane_info = get_access_lane(rel)
    if lane_info is not None:
        lane: TierLane = "mssql" if lane_info.is_mssql_lane else "os"
        return TargetTier(lane=lane, level=lane_info.priv_level.rank)

    # 4. Local-admin-conferring escalation/delegation (SPNJack, AllowedToDelegate
    #    with T2A4D). The C1 conditional lives in source_grants_local_admin_*.
    if source_grants_local_admin_for_relation(rel, source_node):
        return TargetTier(lane="os", level=PrivLevel.LOCAL_ADMIN.rank)

    # 5. EdgeKind fallback for unmapped-semantics edges (research §1c/§1d).
    kind = classify_edge_kind(str(relation or ""))
    if kind is EdgeKind.CONTROL:
        return TargetTier(lane="object", level=_OBJECT_LEVEL)
    if kind in (EdgeKind.DERIVED, EdgeKind.ESCALATION):
        return TargetTier(lane="cred", level=_CRED_LEVEL)

    # 6. Membership / trust / unknown / context → floor.
    return TargetTier(lane="context", level=0)


def tier_dominates(a: TargetTier, b: TargetTier) -> bool:
    """Return True iff ``a`` is at least as strong as ``b`` in the SAME lane.

    Cross-lane → False (incomparable). Within a lane, higher ``level`` dominates;
    at equal level, a self-cred-recovered tier dominates a non-self-cred one and
    equal tiers mutually dominate (the caller's secondary key, e.g. length, breaks
    the tie).
    """
    if a.lane != b.lane:
        return False
    if a.level != b.level:
        return a.level > b.level
    if b.self_cred_recovered and not a.self_cred_recovered:
        return False
    return True


def comparability_key(t: TargetTier) -> tuple[str, ...]:
    """Stable grouping key for de-dup filters: the lane.

    Args:
        t: The tier to key.

    Returns:
        A single-element tuple ``(t.lane,)``. Callers combine it with the target
        object id to form the per-object-per-lane de-dup bucket.
    """
    return (t.lane,)


def _terminal_edge_index(rels: list[Any]) -> int | None:
    """Index of the last non-context relation (mirrors filter_shortest_paths)."""
    for i in range(len(rels) - 1, -1, -1):
        if str(rels[i] or "").strip().lower() in _CONTEXT_RELATIONS_LOWER:
            continue
        return i
    return None


def record_terminal_tier(
    record: Mapping[str, Any],
    label_to_node: Mapping[str, Mapping[str, Any]] | None = None,
) -> TargetTier:
    """Compute the :class:`TargetTier` of a display record's terminal edge.

    Pure: reads ``record["nodes"]`` / ``record["relations"]`` (node labels) and
    resolves source/target node dicts via ``label_to_node`` when supplied (needed
    for the T2A4D source check and Domain detection). Falls back to the context
    floor when the record has no real terminal edge.
    """
    nodes = record.get("nodes")
    rels = record.get("relations")
    if not isinstance(nodes, list) or not isinstance(rels, list) or not rels:
        return TargetTier(lane="context", level=0)
    terminal_idx = _terminal_edge_index(rels)
    if terminal_idx is None or terminal_idx + 1 >= len(nodes):
        return TargetTier(lane="context", level=0)
    resolve = label_to_node or {}
    source_node = resolve.get(str(nodes[terminal_idx]))
    target_node = resolve.get(str(nodes[terminal_idx + 1]))
    # Domain detection also works off the bare terminal label when no node dict is
    # available (is_direct_domain_breaker_target matches kind=="Domain" / names).
    if target_node is None:
        target_node = {"name": str(nodes[terminal_idx + 1])}
    return classify_target_tier(
        relation=str(rels[terminal_idx]),
        source_node=source_node,
        target_node=target_node,
        prior_path_relations=[str(r) for r in rels[:terminal_idx]],
    )


def stamp_records_target_tier(
    records: list[dict[str, Any]],
    label_to_node: Mapping[str, Mapping[str, Any]] | None = None,
) -> None:
    """Stamp ``record["target_tier"]`` (serializable dict) on each record in place.

    Idempotent: re-stamps every call (cheap; the terminal can change after a
    minimizer rewrites the record). Stored as a plain dict so it survives JSON
    round-trips in the materialized cache.

    Args:
        records: List of display-record dicts to stamp in place.
        label_to_node: Optional label-to-node index for resolving the terminal
            node's tier. When omitted, classification falls back to the
            string-based heuristics in ``record_terminal_tier`` (no source-node
            T2A4D check, no Domain detection via node properties).
    """
    for record in records:
        if not isinstance(record, dict):
            continue
        t = record_terminal_tier(record, label_to_node=label_to_node)
        record["target_tier"] = {
            "lane": t.lane,
            "level": t.level,
            "self_cred_recovered": t.self_cred_recovered,
        }


def target_tier_from_record(record: Mapping[str, Any]) -> TargetTier:
    """Read back the stamped tier from a display record, recomputing if missing.

    Args:
        record: A display-record dict, optionally carrying ``record["target_tier"]``
            written by :func:`stamp_records_target_tier`.

    Returns:
        The :class:`TargetTier` for the record's terminal edge. Falls back to
        ``record_terminal_tier(record)`` (no label_to_node) when the stamp is
        absent or was written by an older version.
    """
    raw = record.get("target_tier")
    if isinstance(raw, Mapping):
        return TargetTier(
            lane=str(raw.get("lane") or "context"),  # type: ignore[arg-type]
            level=int(raw.get("level") or 0),
            self_cred_recovered=bool(raw.get("self_cred_recovered")),
        )
    return record_terminal_tier(record)


# ── 4-tier domain-compromise dominance (F5) ────────────────────────────────────
# A SEPARATE axis from the per-target lane model above. ``TargetTier`` answers
# "what standing on THIS object" (and is deliberately cross-lane incomparable so
# the per-host filters never over-trim). ``domain_compromise_tier`` answers "how
# directly does this terminal achieve DOMAIN COMPROMISE" — a TOTAL order used only
# by the whole-path prefix/contained filters to collapse redundant domain-tier
# subpaths (e.g. a truncated "...→Domain Controllers" path inside the full
# "...→Domain Controllers→DCSync→DOMAIN" path). Operator-defined table:
#
#   4 — the Domain object itself (kind=="domain") — strictly above everything.
#   3 — a direct domain breaker group/principal (DA/EA/DC group/Administrators/
#       krbtgt) reached as the terminal — is_direct_domain_breaker_target minus T4.
#   2 — a domain-compromise enabler (DnsAdmins/Backup Operators/Cert Publishers/
#       Operators/Key Admins/Exchange) — is_privileged_escalator_target.
#   1 — everything else (hosts, sessions, low-priv principals).
_DOMAIN_COMPROMISE_TIER_OBJECT: Final[int] = 4
_DOMAIN_COMPROMISE_TIER_DIRECT_BREAKER: Final[int] = 3
_DOMAIN_COMPROMISE_TIER_ENABLER: Final[int] = 2
_DOMAIN_COMPROMISE_TIER_LOWPRIV: Final[int] = 1


def domain_compromise_tier(target_node: Mapping[str, Any] | None) -> int:
    """Classify how directly arriving at ``target_node`` IS domain compromise.

    Returns a value on the 4-tier total order (4 > 3 > 2 > 1). Reuses the
    canonical detectors in ``compromise_class`` — does NOT duplicate the RID /
    group-name sets. The Domain object (``kind=="domain"``) is Tier 4 and strictly
    above a direct-breaker group (Tier 3) so the path that reaches the actual
    Domain object always wins over a path truncated at the Domain Controllers /
    Domain Admins group.

    Args:
        target_node: The terminal node dict (or a ``{"name": ...}`` stub). ``None``
            yields the low-privilege floor.

    Returns:
        ``4`` for the Domain object, ``3`` for a direct domain breaker
        group/principal, ``2`` for a privileged-escalator enabler, else ``1``.
    """
    if target_node is None:
        return _DOMAIN_COMPROMISE_TIER_LOWPRIV
    if str(target_node.get("kind") or "").strip().lower() == "domain":
        return _DOMAIN_COMPROMISE_TIER_OBJECT
    if is_direct_domain_breaker_target(target_node):
        return _DOMAIN_COMPROMISE_TIER_DIRECT_BREAKER
    if is_privileged_escalator_target(target_node):
        return _DOMAIN_COMPROMISE_TIER_ENABLER
    # Tier-label SSOT scoping note — this 4-tier TOTAL ORDER is deliberately NOT
    # migrated to the stamped ``privilege_tier``, even though the stamp is now
    # membership-aware. The migration was IMPLEMENTED and MEASURED — but it still
    # MOVES the reach set. This order drives the domain-listing prefix/contained
    # COLLAPSE, and promoting the (correct) DA-member / escalation terminals from
    # the low-priv floor to rank 3/2 reshuffles which representative survives: on
    # Goad-example essos it traded five ``target=all`` stepping-stone
    # representations to a Tier-2 gMSA for a broader-source one (count 48->43,
    # 59->53), a change that could not be proven lossless. The failure is inherent
    # to re-ranking a COLLAPSE total order, not to membership-blindness, so this
    # reader stays on its legacy name/RID classification. The Tier-0 SELECTION
    # improvement (a DA member / escalation group / ADCS CA now correctly CHOSEN as
    # a high-value target) flows through ``_node_is_tier0`` (a provable lossless
    # superset) and the per-target lane via ``classify_target_tier`` (which the
    # redundant-MemberOf minimizer consumes and which IS migrated, count-identical).
    # When the ADSCAN_TIER_LABEL_SSOT reader switch was removed (2026-09-09, once
    # the migrated readers were lab-validated), this reader was left legacy on
    # purpose — it never read the switch, so its behaviour is unchanged.
    return _DOMAIN_COMPROMISE_TIER_LOWPRIV


def record_domain_compromise_tier(
    record: Mapping[str, Any],
    label_to_node: Mapping[str, Mapping[str, Any]] | None = None,
) -> int:
    """Compute the 4-tier domain-compromise rank of a display record.

    Classifies the record's TRUE displayed terminal node — the LAST node of
    ``record["nodes"]``. Unlike :func:`record_terminal_tier`, this does NOT strip
    a trailing ``MemberOf`` when the terminal is a breaker group: that membership
    IS the achievement (reaching Domain Controllers / Domain Admins as the
    terminal is itself a Tier-3 domain compromise, not context noise).

    Args:
        record: A display-record dict (reads ``record["nodes"]``).
        label_to_node: Optional label-to-node index to resolve the terminal node's
            ``kind`` / RID / name. When omitted, classification falls back to the
            bare terminal label (a ``{"name": ...}`` stub) — sufficient for the
            name-based direct-breaker / enabler matches but not ``kind=="domain"``.

    Returns:
        The 4-tier rank (1–4) of the record's terminal.
    """
    nodes = record.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        return _DOMAIN_COMPROMISE_TIER_LOWPRIV
    terminal_label = str(nodes[-1])
    resolve = label_to_node or {}
    terminal_node = resolve.get(terminal_label)
    if terminal_node is None:
        terminal_node = {"name": terminal_label}
    return domain_compromise_tier(terminal_node)


def stamp_records_domain_compromise_tier(
    records: list[dict[str, Any]],
    label_to_node: Mapping[str, Mapping[str, Any]] | None = None,
) -> None:
    """Stamp ``record["domain_compromise_tier"]`` (int 1–4) on each record in place.

    Computed at the central choke-point where ``label_to_node`` is fully built so
    the Domain object (``kind=="domain"``) is recognized as Tier 4. The
    prefix/contained filters then read the stamp via
    :func:`domain_compromise_tier_from_record` without re-threading
    ``label_to_node`` through their signatures.

    Args:
        records: List of display-record dicts to stamp in place.
        label_to_node: Label-to-node index for resolving the terminal node's kind /
            RID / name (required to detect the Domain object as Tier 4).
    """
    for record in records:
        if not isinstance(record, dict):
            continue
        record["domain_compromise_tier"] = record_domain_compromise_tier(
            record, label_to_node=label_to_node
        )


def domain_compromise_tier_from_record(record: Mapping[str, Any]) -> int:
    """Read back the stamped 4-tier domain-compromise rank, recomputing if absent.

    Args:
        record: A display-record dict, optionally carrying
            ``record["domain_compromise_tier"]`` from
            :func:`stamp_records_domain_compromise_tier`.

    Returns:
        The 4-tier rank (1–4). Falls back to
        ``record_domain_compromise_tier(record)`` (no label_to_node — name-based
        T3/T2 detection only, Domain object may under-classify to T1) when the
        stamp is absent.
    """
    raw = record.get("domain_compromise_tier")
    if isinstance(raw, int) and 1 <= raw <= 4:
        return raw
    return record_domain_compromise_tier(record)


# ── context-insensitive attack-core matching (F5 Fix #1) ───────────────────────
# ``MemberOf`` (and the other structural relations) plus ``X→DumpLSA→X``
# self-loops are display artifacts, not attack progress. Two records whose only
# difference is which group they pass through, or whether the implicit DumpLSA
# self-loop was rendered, represent the SAME attack and must be recognized as
# prefix / sub-sequence of one another. The literal node/rel arrays do not see
# this (the self-loop doubles a node, MemberOf inserts a context hop), so the
# prefix/contained filters match on this canonical core instead.
_SELF_LOOP_RELATIONS_LOWER: Final[frozenset[str]] = frozenset({"dumplsa"})

# Public: the actionable attack-core of a path = (start_node, ((rel, to_node), …))
# with every context relation and every self-loop edge removed. A is a prefix of
# B iff same start and A's step tuple is a prefix of B's; A is contained in B iff
# A's step tuple is a contiguous sub-sequence of B's (same start at the matching
# offset). Pure on (nodes, rels) label arrays — no node dicts required.
AttackCore = tuple[str, tuple[tuple[str, str], ...]]


def attack_core_signature(
    nodes: list[Any] | tuple[Any, ...],
    rels: list[Any] | tuple[Any, ...],
) -> AttackCore | None:
    """Return the context-insensitive actionable attack-core of a path.

    Walks the edges ``n[i] --rel[i]--> n[i+1]``. For each edge that is neither a
    context relation (``_CONTEXT_RELATIONS_LOWER`` — MemberOf, Contains, …) nor a
    ``X→DumpLSA→X`` self-loop, emit an actionable step ``(rel_lower, to_node)``.
    Context edges and self-loops advance the current node but emit no step. The
    core is ``(start_node, tuple_of_steps)``.

    Args:
        nodes: The path's ordered node labels (length ``len(rels) + 1``).
        rels: The path's ordered relation labels.

    Returns:
        The ``(start_node, steps)`` core, or ``None`` when the arrays are malformed
        (too short / mismatched) to derive a core.
    """
    if not isinstance(nodes, (list, tuple)) or not isinstance(rels, (list, tuple)):
        return None
    if len(nodes) < 1 or len(nodes) != len(rels) + 1:
        return None
    start = str(nodes[0])
    steps: list[tuple[str, str]] = []
    for i, rel in enumerate(rels):
        rel_lower = str(rel or "").strip().lower()
        from_node = str(nodes[i])
        to_node = str(nodes[i + 1])
        if rel_lower in _CONTEXT_RELATIONS_LOWER:
            continue  # structural hop — advances position, no attack progress
        if rel_lower in _SELF_LOOP_RELATIONS_LOWER and from_node == to_node:
            continue  # implicit self-credential self-loop — not a distinct step
        steps.append((rel_lower, to_node))
    return (start, tuple(steps))


def attack_core_is_prefix(inner: AttackCore | None, outer: AttackCore | None) -> bool:
    """Return True iff ``inner``'s core is a strict leading prefix of ``outer``'s.

    Same start node AND ``inner`` steps equal the first ``len(inner)`` steps of
    ``outer`` AND ``inner`` is strictly shorter (a path is never its own strict
    prefix). ``None`` cores never match. An EMPTY-steps core (a path whose every
    edge is contextual, e.g. ``LocalAdminPassReuse``/``MemberOf``) never matches —
    it carries no attack core and must not subsume real paths from the same node
    (mirrors the ``n == 0`` guard in :func:`attack_core_is_subsequence`).
    """
    if inner is None or outer is None:
        return False
    if inner[0] != outer[0]:
        return False
    n = len(inner[1])
    if n == 0 or n >= len(outer[1]):
        return False
    return outer[1][:n] == inner[1]


def attack_core_is_subsequence(
    inner: AttackCore | None, outer: AttackCore | None
) -> bool:
    """Return True iff ``inner``'s core is a strict contiguous sub-sequence of ``outer``.

    Matches ``inner``'s step tuple at SOME contiguous offset inside ``outer``'s,
    with ``inner`` strictly shorter. When the match begins at offset 0 the start
    nodes must agree; for an interior match the sub-sequence start node is implied
    by the preceding ``outer`` step's target, so only the step tuples are compared.
    ``None`` cores never match.
    """
    if inner is None or outer is None:
        return False
    inner_steps = inner[1]
    outer_steps = outer[1]
    n = len(inner_steps)
    if n == 0 or n >= len(outer_steps):
        return False
    for offset in range(0, len(outer_steps) - n + 1):
        if outer_steps[offset : offset + n] != inner_steps:
            continue
        if offset == 0 and inner[0] != outer[0]:
            continue
        return True
    return False


__all__ = [
    "AttackCore",
    "TargetTier",
    "attack_core_is_prefix",
    "attack_core_is_subsequence",
    "attack_core_signature",
    "classify_target_tier",
    "comparability_key",
    "domain_compromise_tier",
    "domain_compromise_tier_from_record",
    "edge_grants_local_admin_session",
    "record_domain_compromise_tier",
    "record_terminal_tier",
    "source_grants_local_admin_for_relation",
    "stamp_records_domain_compromise_tier",
    "stamp_records_target_tier",
    "target_tier_from_record",
    "tier_dominates",
]
