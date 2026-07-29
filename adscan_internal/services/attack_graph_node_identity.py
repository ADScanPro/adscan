"""Alias-aware identity resolution for attack-graph nodes.

Attack-graph nodes are addressed from two very different places:

* the **graph itself**, which keys nodes by a synthetic id (``name:<sid>``,
  ``name:<samaccountname>``, ``name:<guid>``) and renders them with a display
  label (``BRAAVOS$@ESSOS.LOCAL``, ``ESSOS-CA@ESSOS.LOCAL``);
* **runtime execution flows**, which only ever hold the display label a step
  was rendered with — and for host-shaped endpoints (an ADCS CA, a relay
  victim, a lateral-movement target) that label can legitimately arrive as an
  IP, a short hostname, an FQDN, or a ``HOST$`` machine account.

Matching those two spaces with naive string equality silently loses edges: an
``ADCSESC8`` step that names its Enterprise CA by IP never resolves against a
CA node labelled by hostname, so the proven step is dropped and the whole
attack path renders as theoretical. Host matching in ADscan is required to be
alias-aware (IP ↔ short ↔ FQDN ↔ ``HOST$``); this module is the single place
that implements it for graph nodes.

Resolution is layered so it can only ever ADD matches, never change an existing
one:

1. exact normalised display-label equality (the historic behaviour),
2. node id / ``objectId`` (SID, GUID) equality,
3. alias-aware identity keys (account aliases and host aliases).

Within each layer, security principals (``Group``/``User``/``Computer``/
``Domain``) win over structural AD objects (OU, Container, CertTemplate,
EnterpriseCA) that may share a normalised label.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from adscan_core.rich_output import strip_sensitive_markers

__all__ = [
    "PRINCIPAL_KINDS",
    "describe_resolution_failure",
    "host_alias_keys",
    "label_lookup_keys",
    "node_identity_keys",
    "normalize_account_key",
    "resolve_node_candidates",
    "resolve_node_id",
]

_IPV4_RE = re.compile(r"\A\d{1,3}(?:\.\d{1,3}){3}\Z")

#: Security principals must win over structural AD objects (OU, Container,
#: CertTemplate, EnterpriseCA) when several nodes share a normalised label.
PRINCIPAL_KINDS: frozenset[str] = frozenset({"Group", "User", "Computer", "Domain"})

_ACCOUNT_NS = "acct:"
_HOST_NS = "host:"
_ID_NS = "id:"

#: Node property keys that carry a host identity (name, DNS name, or address).
_HOST_PROPERTY_KEYS: tuple[str, ...] = (
    "dnshostname",
    "dns_hostname",
    "hostname",
    "ip_address",
    "ipaddress",
    "ip",
    "name",
    "ca_hostname",
    "cahostname",
    "computer_name",
)

#: Node property keys that carry an account identity.
_ACCOUNT_PROPERTY_KEYS: tuple[str, ...] = (
    "samaccountname",
    "name",
)

#: Node property keys that carry a stable object identifier (SID / GUID).
_ID_PROPERTY_KEYS: tuple[str, ...] = (
    "objectid",
    "object_id",
    "guid",
    "sid",
)

#: Kinds whose nodes denote a machine, so their labels/properties are expanded
#: into host aliases. Every other kind only contributes account/id keys.
_HOST_BEARING_KINDS: frozenset[str] = frozenset(
    {"Computer", "EnterpriseCA", "AIACA", "RootCA", "NTAuthStore", "CertAuthority"}
)


def _clean(value: Any) -> str:
    """Return a marker-free, stripped string for any incoming value."""
    return strip_sensitive_markers(str(value or "")).strip()


def normalize_account_key(value: Any) -> str:
    """Return the canonical account form of a label (``DOMAIN\\u@realm`` -> ``u``).

    Mirrors the historic ``_normalize_account`` in ``attack_graph_service`` so
    the exact-match layer keeps byte-for-byte identical behaviour.
    """
    name = _clean(value)
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name.strip().lower()


def is_ipv4(value: Any) -> bool:
    """Return whether the value is a bare IPv4 literal."""
    return bool(_IPV4_RE.match(_clean(value)))


def host_alias_keys(value: Any) -> set[str]:
    """Return the alias-aware comparison keys for one host identifier.

    ``BRAAVOS$@ESSOS.LOCAL``, ``braavos``, ``braavos.essos.local`` and
    ``BRAAVOS$`` all reduce to a set sharing ``braavos``; an IPv4 literal is
    preserved verbatim (an address has no short form). Empty input yields an
    empty set so it never matches anything.
    """
    raw = _clean(value)
    if not raw:
        return set()
    # A ``NAME@REALM`` label carries the realm as a suffix, not as a DNS name.
    if "@" in raw:
        raw = raw.split("@", 1)[0]
    raw = raw.strip().strip(".").rstrip("$").lower()
    if not raw:
        return set()
    if _IPV4_RE.match(raw):
        return {raw}
    keys = {raw}
    short = raw.split(".", 1)[0].strip()
    if short:
        keys.add(short)
    return keys


def _node_kind(node: Mapping[str, Any]) -> str:
    kind = node.get("kind")
    if isinstance(kind, list):
        kind = kind[0] if kind else ""
    return str(kind or "")


def _node_properties(node: Mapping[str, Any]) -> Mapping[str, Any]:
    props = node.get("properties")
    return props if isinstance(props, Mapping) else {}


def _id_key(value: Any) -> str:
    cleaned = _clean(value).lower()
    return f"{_ID_NS}{cleaned}" if cleaned else ""


def node_identity_keys(node_id: str, node: Mapping[str, Any]) -> set[str]:
    """Return every namespaced identity key a graph node answers to.

    Keys are namespaced (``acct:`` / ``host:`` / ``id:``) so an account name can
    never be confused with a machine address, and a host alias is only produced
    for nodes that actually denote a machine.
    """
    if not isinstance(node, Mapping):
        return set()

    keys: set[str] = set()
    props = _node_properties(node)
    kind = _node_kind(node)
    label = node.get("label")

    # --- identifiers -----------------------------------------------------
    for candidate in (node_id, node.get("id"), node.get("objectId")):
        key = _id_key(candidate)
        if key:
            keys.add(key)
    raw_id = _clean(node_id)
    if ":" in raw_id:
        suffix = raw_id.split(":", 1)[1]
        key = _id_key(suffix)
        if key:
            keys.add(key)
    for prop_key in _ID_PROPERTY_KEYS:
        key = _id_key(props.get(prop_key))
        if key:
            keys.add(key)

    # --- account aliases -------------------------------------------------
    account_sources: list[Any] = [label]
    account_sources.extend(props.get(prop_key) for prop_key in _ACCOUNT_PROPERTY_KEYS)
    for candidate in account_sources:
        account = normalize_account_key(candidate)
        if account:
            keys.add(f"{_ACCOUNT_NS}{account}")

    # --- host aliases ----------------------------------------------------
    host_sources: list[Any] = []
    if kind in _HOST_BEARING_KINDS:
        host_sources.append(label)
    for prop_key in _HOST_PROPERTY_KEYS:
        value = props.get(prop_key)
        if value in (None, ""):
            continue
        # ``name`` is only a host identity on a machine-bearing node.
        if prop_key == "name" and kind not in _HOST_BEARING_KINDS:
            continue
        host_sources.append(value)
    for candidate in host_sources:
        for host_key in host_alias_keys(candidate):
            keys.add(f"{_HOST_NS}{host_key}")

    return keys


def label_lookup_keys(label: Any) -> set[str]:
    """Return the namespaced identity keys a display label can match on."""
    cleaned = _clean(label)
    if not cleaned:
        return set()

    keys: set[str] = set()
    key = _id_key(cleaned)
    if key:
        keys.add(key)
    if ":" in cleaned:
        suffix_key = _id_key(cleaned.split(":", 1)[1])
        if suffix_key:
            keys.add(suffix_key)
    account = normalize_account_key(cleaned)
    if account:
        keys.add(f"{_ACCOUNT_NS}{account}")
    for host_key in host_alias_keys(cleaned):
        keys.add(f"{_HOST_NS}{host_key}")
    return keys


def _all_matching(
    nodes_map: Mapping[str, Any],
    predicate,
    *,
    prefer_kinds: Iterable[str],
) -> list[str]:
    """Return every matching node id, preferred kinds first, order preserved."""
    preferred = frozenset(prefer_kinds or ())
    hits: list[str] = []
    others: list[str] = []
    for node_id, node in nodes_map.items():
        if not isinstance(node, Mapping):
            continue
        if not predicate(node_id, node):
            continue
        (hits if _node_kind(node) in preferred else others).append(str(node_id))
    return hits + others


def resolve_node_candidates(
    nodes_map: Mapping[str, Any],
    label: Any,
    *,
    prefer_kinds: Iterable[str] = PRINCIPAL_KINDS,
) -> list[str]:
    """Return every node id a display label can denote, best candidate first.

    Layered so that anything resolvable by the historic exact-label rule keeps
    resolving to exactly the same node; the id and alias layers only run when
    the exact layer found nothing. The full candidate list matters because
    duplicate display labels are normal in an AD graph — an Enterprise CA, its
    AIA CA and its Root CA all render as ``<CA>@<REALM>`` — so the caller must
    be able to disambiguate with information the node identity alone does not
    carry (e.g. which candidate already has the edge being updated).

    Args:
        nodes_map: The graph's ``nodes`` mapping (id -> node dict).
        label: The display label (or node id) the caller holds.
        prefer_kinds: Node kinds that win when several nodes match.

    Returns:
        Ordered candidate node ids; empty when nothing matched.
    """
    if not isinstance(nodes_map, Mapping) or not nodes_map:
        return []
    wanted_account = normalize_account_key(label)
    if not wanted_account and not _clean(label):
        return []

    # Layer 1 — exact normalised display-label equality (historic behaviour).
    if wanted_account:
        exact = _all_matching(
            nodes_map,
            lambda _nid, node: normalize_account_key(node.get("label")) == wanted_account,
            prefer_kinds=prefer_kinds,
        )
        if exact:
            return exact

    wanted_keys = label_lookup_keys(label)
    if not wanted_keys:
        return []

    # Layer 2 — node id / objectId equality (covers a label that is really an
    # id, which is what ``label()`` falls back to when a node is missing from a
    # stale nodes map, and SID-keyed callers).
    id_keys = {key for key in wanted_keys if key.startswith(_ID_NS)}
    if id_keys:
        by_id = _all_matching(
            nodes_map,
            lambda nid, node: bool(id_keys & node_identity_keys(nid, node)),
            prefer_kinds=prefer_kinds,
        )
        if by_id:
            return by_id

    # Layer 3 — alias-aware identity (host IP ↔ short ↔ FQDN ↔ HOST$, and
    # account aliases carried on properties rather than the label).
    return _all_matching(
        nodes_map,
        lambda nid, node: bool(wanted_keys & node_identity_keys(nid, node)),
        prefer_kinds=prefer_kinds,
    )


def resolve_node_id(
    nodes_map: Mapping[str, Any],
    label: Any,
    *,
    prefer_kinds: Iterable[str] = PRINCIPAL_KINDS,
) -> str:
    """Return the single best-matching node id for a display label, alias-aware.

    Thin wrapper over :func:`resolve_node_candidates` for callers that have no
    way to disambiguate duplicates.
    """
    candidates = resolve_node_candidates(nodes_map, label, prefer_kinds=prefer_kinds)
    return candidates[0] if candidates else ""


def _kind_census(nodes_map: Mapping[str, Any], *, max_kinds: int = 20) -> str:
    counts: dict[str, int] = {}
    for node in nodes_map.values():
        if not isinstance(node, Mapping):
            continue
        kind = _node_kind(node) or "Unknown"
        counts[kind] = counts.get(kind, 0) + 1
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return ",".join(f"{kind}:{count}" for kind, count in ordered[:max_kinds])


def _similar_labels(
    nodes_map: Mapping[str, Any], label: Any, *, max_labels: int = 3
) -> list[str]:
    """Return node labels that look like ``label`` without matching it.

    Deliberately weaker than :func:`resolve_node_id` (a prefix overlap, not an
    alias match), so a non-empty result means "the node exists under a different
    label" while an empty result means "no such node at all". That distinction
    is what makes a resolution failure diagnosable from a recording alone.
    """
    probe = normalize_account_key(label) or _clean(label).lower()
    probe = probe.split(".", 1)[0].rstrip("$")
    if len(probe) < 3:
        return []
    stem = probe[:4]
    seen: set[str] = set()
    out: list[str] = []
    for node in nodes_map.values():
        if not isinstance(node, Mapping):
            continue
        node_label = _clean(node.get("label"))
        if not node_label or node_label in seen:
            continue
        candidate = normalize_account_key(node_label).split(".", 1)[0].rstrip("$")
        if not candidate:
            continue
        if candidate.startswith(stem) or probe.startswith(candidate[:4]):
            seen.add(node_label)
            out.append(node_label)
            if len(out) >= max_labels:
                break
    return out


def describe_resolution_failure(
    nodes_map: Mapping[str, Any],
    *,
    from_label: Any,
    to_label: Any,
    from_id: str,
    to_id: str,
    mask_label: Callable[[str], str] | None = None,
) -> str:
    """Return a compact diagnostic for a failed endpoint resolution.

    Answers the one question a recording could not answer before: is the node
    absent from the graph entirely (a collection gap), or present under a label
    the caller did not use (a naming/alias gap)? The kind census settles the
    first, the similar-label sample settles the second.

    Args:
        nodes_map: The graph's ``nodes`` mapping.
        from_label: The label the caller used for the source endpoint.
        to_label: The label the caller used for the target endpoint.
        from_id: The resolved source node id (``""`` when it failed).
        to_id: The resolved target node id (``""`` when it failed).
        mask_label: Applied to each sampled node label. Pass the caller's
            ``mark_sensitive`` so identifiers are scrubbed from telemetry while
            the counts and kind census — which carry no identity — stay
            readable in a recording. Marking the whole string instead would
            reduce the diagnostic to one opaque pseudonym.
    """
    if not isinstance(nodes_map, Mapping):
        return "nodes_total=0"
    mask = mask_label or (lambda value: value)
    missing = []
    if not from_id:
        missing.append("from")
    if not to_id:
        missing.append("to")
    parts = [
        f"missing={'+'.join(missing) if missing else 'none'}",
        f"nodes_total={len(nodes_map)}",
        f"kinds={_kind_census(nodes_map) or 'none'}",
    ]
    for side, label, resolved in (
        ("from", from_label, from_id),
        ("to", to_label, to_id),
    ):
        if resolved:
            continue
        similar = [mask(item) for item in _similar_labels(nodes_map, label)]
        parts.append(f"{side}_similar={'|'.join(similar) if similar else 'none'}")
    return " ".join(parts)
