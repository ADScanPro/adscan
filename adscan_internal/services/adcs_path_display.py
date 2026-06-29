"""Helpers for rendering ADCS attack-path context without changing graph semantics."""

from __future__ import annotations

from typing import Any, Mapping

from adscan_internal.services.compromise_class import is_direct_domain_breaker_target


# Well-known high-privilege principals that are never genuine *escalating actors*
# for a principal-first ESC. SYSTEM / LOCAL SYSTEM / NT AUTHORITY do not "escalate
# via ESC1" — listing them as an ESC source is noise, not a finding. Matched by
# bare name (case-insensitive, @domain suffix stripped) and by well-known SID.
_WELL_KNOWN_NON_ACTOR_NAMES: frozenset[str] = frozenset(
    name.lower()
    for name in (
        "SYSTEM",
        "LOCAL SYSTEM",
        "NT AUTHORITY",
        "NT AUTHORITY\\SYSTEM",
        "LOCAL SERVICE",
        "NETWORK SERVICE",
    )
)
_WELL_KNOWN_NON_ACTOR_SIDS: frozenset[str] = frozenset(
    {
        "S-1-5-18",  # LOCAL SYSTEM
        "S-1-5-19",  # LOCAL SERVICE
        "S-1-5-20",  # NETWORK SERVICE
    }
)

# Node kinds that are CA / abuse-infrastructure, not escalating principals. A CA
# or computer object appearing as the *source* of a principal-first ESC (ESC1/2/3,
# …) is the abuse target's infrastructure, not an actor. The genuinely CA-targeted
# ESCs (6/8/11/…) are modelled separately and do not flow through this predicate as
# "sources" that need rendering as escalating actors.
_CA_INFRA_SOURCE_KINDS: frozenset[str] = frozenset(
    {
        "computer",
        "enterpriseca",
        "aiaca",
        "rootca",
        "certtemplate",
        "certauthority",
        "ntauthstore",
    }
)


def is_meaningful_esc_source(
    source_name: str, source_kind: str | None = None
) -> bool:
    """Return ``True`` when *source* is a genuine escalating actor for an ESC.

    The ``/adcs`` "Detected AD CS paths" list reads raw, pre-derivation
    collector edges — one per principal holding an enrollment ACE on a
    vulnerable template — with no source filtering. That surfaces meaningless
    "sources": domain-breakers (Domain Admins, Enterprise Admins, BUILTIN
    Administrators, krbtgt, DCs) that do not *escalate* via ESC, well-known
    SIDs (SYSTEM / LOCAL SYSTEM / NT AUTHORITY) that are not actors, and CA /
    computer abuse-infrastructure that is the target's plumbing, not a
    principal.

    This is the same source-pruning the rest of the platform applies — the
    attack-graph engine prunes breaker *sources*
    (``attack_graph_service._prune_tier0_source_attack_edges``) and the
    affected-assets registry drops breaker *targets*
    (``compromise_class.is_direct_domain_breaker_target``). This predicate
    reuses that SSOT breaker check so the ``/adcs`` dashboard, the engine and
    the report agree on what counts as an ESC actor.

    Args:
        source_name: The edge's ``source_name`` (label / sAMAccountName / SID).
        source_kind: The edge's ``source_kind`` (node kind), if known.

    Returns:
        ``False`` to filter the source OUT (breaker / well-known SID /
        CA-infra), ``True`` for a genuine — typically low-privilege —
        principal (Domain Users, Authenticated Users, Domain Computers as a
        group, normal users/groups).
    """
    name = str(source_name or "").strip()
    kind = str(source_kind or "").strip().lower()

    # CA / computer abuse-infrastructure is never an escalating actor.
    if kind in _CA_INFRA_SOURCE_KINDS:
        return False

    bare = name.split("@", 1)[0].strip()
    lowered = bare.lower()
    upper = bare.upper()

    # Well-known non-actor principals (SYSTEM family), by name or SID.
    if lowered in _WELL_KNOWN_NON_ACTOR_NAMES:
        return False
    if upper in _WELL_KNOWN_NON_ACTOR_SIDS:
        return False

    # Direct domain-breaker sources (DA/EA/BUILTIN Administrators/krbtgt/DCs):
    # reuse the SSOT predicate so we never drift from the engine/report.
    node = {"name": name, "kind": kind} if name or kind else None
    if is_direct_domain_breaker_target(node):
        return False

    return True


_ADCS_RELATIONS = {
    "adcsesc1",
    "adcsesc2",
    "adcsesc3",
    "adcsesc4",
    "adcsesc6",
    "adcsesc6a",
    "adcsesc6b",
    "adcsesc7",
    "adcsesc8",
    "adcsesc9",
    "adcsesc9a",
    "adcsesc9b",
    "adcsesc10",
    "adcsesc10a",
    "adcsesc10b",
    "adcsesc11",
    "adcsesc13",
    "adcsesc14",
    "adcsesc15",
    "adcsesc16",
    "adcsesc17",
    "coerceandrelayntlmtoadcs",
    "goldencert",
}
_CA_FIRST_RELATIONS = {
    "adcsesc6",
    "adcsesc6a",
    "adcsesc6b",
    "adcsesc8",
    "adcsesc11",
    "adcsesc16",
    "coerceandrelayntlmtoadcs",
    "goldencert",
}


def is_adcs_relation(relation: object) -> bool:
    """Return ``True`` when the relation is ADCS-related."""
    return str(relation or "").strip().lower() in _ADCS_RELATIONS


def extract_adcs_template_names(details: Mapping[str, Any] | None) -> list[str]:
    """Extract distinct template names from ADCS edge notes."""
    if not isinstance(details, Mapping):
        return []

    templates: list[str] = []

    def _append(candidate: object) -> None:
        if isinstance(candidate, str):
            name = candidate.strip()
            if name:
                templates.append(name)

    _append(details.get("template"))

    for key in ("templates", "agent_templates", "target_templates"):
        raw_value = details.get(key)
        if not isinstance(raw_value, list):
            continue
        for entry in raw_value:
            if isinstance(entry, dict):
                _append(entry.get("name") or entry.get("template"))
            else:
                _append(entry)

    # Compromise-centric ESC edges carry the abused templates / CAs in
    # ``vulnerable_resources`` (the canonical post-derivation field). Some ESCs
    # (e.g. ESC9/ESC10) also list the impersonatable "puppet" principals there
    # as ``kind == "User"`` / ``"Computer"`` entries — those are NOT templates,
    # so filter to certificate-template entries only. Entries without a ``kind``
    # are kept (a bare template-name list predates the kind tagging).
    raw_resources = details.get("vulnerable_resources")
    if isinstance(raw_resources, list):
        for entry in raw_resources:
            if isinstance(entry, dict):
                kind = str(entry.get("kind") or "").strip().lower()
                if kind and kind != "certtemplate":
                    continue
                _append(entry.get("name"))

    summary = details.get("templates_summary")
    if isinstance(summary, str) and summary.strip():
        for item in summary.split(","):
            candidate = item.strip()
            if not candidate or candidate.startswith("+"):
                continue
            if "(" in candidate:
                candidate = candidate.split("(", 1)[0].strip()
            _append(candidate)

    return sorted({name for name in templates if name}, key=str.lower)


def has_compromise_centric_target(details: Mapping[str, Any] | None) -> bool:
    """Return True when the edge already targets the impersonated principal.

    Compromise-centric ESC edges carry ``vulnerable_resources`` in their notes
    (set by ``_persist_esc_compromise_steps``). Their ``to`` is the actual
    principal compromised (Domain Admins, Domain Controllers), so display
    redirects must not override the target — the templates belong as a
    relation-column annotation, not as a fake terminal.
    """
    if not isinstance(details, Mapping):
        return False
    raw_resources = details.get("vulnerable_resources")
    return isinstance(raw_resources, list) and bool(raw_resources)


def format_adcs_templates_summary(
    details: Mapping[str, Any] | None,
    *,
    template_metadata: Mapping[str, Mapping[str, Any]] | None = None,
    max_items: int = 3,
) -> str:
    """Build a compact template summary for ADCS notes."""
    template_names = extract_adcs_template_names(details)
    if not template_names:
        return ""

    labels: list[str] = []
    for name in template_names:
        min_key = None
        if isinstance(template_metadata, Mapping):
            metadata = template_metadata.get(name)
            if isinstance(metadata, Mapping):
                raw_min_key = metadata.get("min_key_length")
                if isinstance(raw_min_key, int) and raw_min_key > 0:
                    min_key = raw_min_key
        if min_key:
            labels.append(f"{name}(min_key={min_key})")
        else:
            labels.append(name)

    summary_items = labels[: max_items if max_items > 0 else len(labels)]
    remaining = len(labels) - len(summary_items)
    if remaining > 0:
        summary_items.append(f"+{remaining} more")
    return ", ".join(summary_items)


def resolve_adcs_display_target(
    relation: object,
    details: Mapping[str, Any] | None,
    *,
    fallback_target: str = "",
) -> str:
    """Return the UX display target for an ADCS edge while preserving domain impact internally."""
    fallback = str(fallback_target or "").strip()
    if not is_adcs_relation(relation):
        return fallback

    # Compromise-centric edges (post _persist_esc_compromise_steps) already point
    # at the impersonated principal. Do not override the target — the templates
    # surface as a relation annotation instead.
    if has_compromise_centric_target(details):
        return fallback

    info = details if isinstance(details, Mapping) else {}
    relation_key = str(relation or "").strip().lower()
    ca_name = str(
        info.get("enterpriseca_name") or info.get("enterpriseca") or ""
    ).strip()
    template_names = extract_adcs_template_names(info)

    if relation_key == "adcsesc13":
        linked_group = str(
            info.get("effective_group")
            or info.get("linked_group")
            or info.get("policy_group")
            or info.get("issuance_policy_group")
            or ""
        ).strip()
        return linked_group or fallback
    if relation_key in _CA_FIRST_RELATIONS and ca_name:
        return ca_name
    if len(template_names) == 1:
        return template_names[0]
    if len(template_names) > 1:
        summary = format_adcs_templates_summary(info)
        return f"Templates: {summary}" if summary else "Templates"
    if ca_name:
        return ca_name
    return fallback
