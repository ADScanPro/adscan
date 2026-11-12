"""Stable identity for engagement items: objects, findings, steps and paths.

Required properties (spec section 6): an id survives re-runs, renames, IP changes
and a graph re-key. So nothing here hashes a name or an address when the
directory gives a durable identifier:

* object: ``objectSid`` for principals and computers, ``guid:<objectGUID>`` for
  templates, authorities, GPOs, OUs and containers, ``wk:<SID>`` for well-known
  and built-in SIDs, ``synthetic:<id>`` for ADscan's own scope groups, and an
  explicit ``unresolved:<name>`` bucket when the node carries no identifier;
* finding: ``finding_id(key, domain)``; instance: ``instance_id(finding, object)``;
* step: ``step_id(relation, source object, target object, discriminator)``;
* path: the ORDERED hop sequence (:func:`path_key`). This is the one path rule:
  the web keys ``attack_path_records`` with the same function
  (``app/services/attack_path_identity.py`` re-exports it), so the engine ledger
  and the web projection can never key a route differently.

Stdlib only: the web backend, its migrations and LITE on Windows import it.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable, Mapping

IDENTITY_VERSION = "v2"

Hop = tuple[str, str, str]


def normalize_identity_token(value: Any) -> str:
    """Casefold and whitespace-collapse a node label or relation name.

    The realm suffix is deliberately kept: ``svc@A.LOCAL`` and ``svc@B.LOCAL``
    are different principals in a multi-domain forest.
    """
    return " ".join(str(value or "").split()).casefold()


def _node_label(node: Any) -> str:
    if isinstance(node, dict):
        return str(node.get("label") or node.get("name") or node.get("id") or "")
    return str(node or "")


def _node_lookup(nodes: Iterable[Any]) -> dict[str, str]:
    lookup: dict[str, str] = {}
    for node in nodes:
        if not isinstance(node, dict):
            continue
        node_id = str(node.get("id") or node.get("name") or "").strip()
        label = _node_label(node).strip()
        if node_id and label:
            lookup[node_id] = label
    return lookup


def _step_endpoint(step: dict[str, Any], keys: tuple[str, ...]) -> str:
    details = step.get("details")
    for key in keys:
        value = step.get(key)
        if not value and isinstance(details, dict):
            value = details.get(key)
        if value:
            return str(value).strip()
    return ""


def path_hops(steps: Any, nodes: Any) -> list[Hop]:
    """Return the ordered ``(source, relation, target)`` hops, normalized."""
    step_list = (
        [s for s in steps if isinstance(s, dict)] if isinstance(steps, list) else []
    )
    node_list = list(nodes) if isinstance(nodes, list) else []
    lookup = _node_lookup(node_list)
    ordered_labels = [_node_label(n) for n in node_list]
    # A node sequence lines up with the hops only when it is one longer.
    positional = len(ordered_labels) == len(step_list) + 1

    hops: list[Hop] = []
    for index, step in enumerate(step_list):
        relation = str(
            step.get("action")
            or step.get("edge_type")
            or step.get("type")
            or step.get("relation")
            or ""
        )
        source = _step_endpoint(step, ("source", "from"))
        target = _step_endpoint(step, ("target", "to"))
        source = lookup.get(source, source)
        target = lookup.get(target, target)
        if positional:
            source = source or ordered_labels[index]
            target = target or ordered_labels[index + 1]
        hops.append(
            (
                normalize_identity_token(source),
                normalize_identity_token(relation),
                normalize_identity_token(target),
            )
        )
    return hops


def compute_attack_path_fingerprint(
    *,
    steps: Any,
    nodes: Any = None,
    domain: str = "",
    source: Any = "",
    target: Any = "",
    title: Any = "",
) -> str:
    """SHA256 identity of one route within a domain (order-sensitive)."""
    hops = path_hops(steps, nodes)
    if hops:
        payload: list[Any] = [IDENTITY_VERSION, normalize_identity_token(domain), hops]
    else:
        # No hops to key on: degrade to the only route-level facts available so
        # distinct paths still stay distinct instead of collapsing together.
        payload = [
            IDENTITY_VERSION,
            normalize_identity_token(domain),
            [],
            normalize_identity_token(source),
            normalize_identity_token(target),
            normalize_identity_token(title),
        ]
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Object, domain, finding and step identity.
# ---------------------------------------------------------------------------

_SID_RE = re.compile(r"S-1-\d+(?:-\d+)+", re.IGNORECASE)
_GUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
_DOMAIN_SID_PREFIX = "S-1-5-21-"
_SYNTHETIC_PREFIX = "ADSCAN-"
_ID_VERSION = "v1"


def _digest(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def _raw_object_id(node: Mapping[str, Any]) -> str:
    props = node.get("properties") if isinstance(node.get("properties"), Mapping) else {}
    for value in (node.get("objectId"), node.get("objectid"), props.get("objectid")):
        text = str(value or "").strip()
        if text and text.lower() != "none":
            return text
    return ""


def _sid_id(sid: str) -> str:
    sid = sid.upper()
    return sid if sid.startswith(_DOMAIN_SID_PREFIX) else f"wk:{sid}"


def object_id_from_node(node: Mapping[str, Any]) -> str:
    """Return the stable object id of a graph or inventory node.

    Never a name or an address when the directory gave an identifier; the
    ``unresolved:`` bucket is explicit, so a consumer can tell a guess from a
    durable id and never mistakes one for the other.
    """
    raw = _raw_object_id(node)
    if raw:
        upper = raw.upper()
        if upper.startswith(_SYNTHETIC_PREFIX):
            return f"synthetic:{raw.casefold()}"
        if _SID_RE.fullmatch(raw):
            return _sid_id(raw)
        # The collector prefixes some ids with the domain name
        # (``CORP.EXAMPLE-S-1-5-7``, ``CORP.EXAMPLE-<GUID>``).
        match = _SID_RE.search(raw)
        if match and upper.endswith(match.group(0).upper()):
            return _sid_id(match.group(0))
        tail = raw[-36:]
        if _GUID_RE.match(tail):
            return f"guid:{tail.lower()}"
        return f"unresolved:{raw.casefold()}"
    props = node.get("properties") if isinstance(node.get("properties"), Mapping) else {}
    name = str(node.get("label") or props.get("name") or node.get("name") or node.get("id") or "")
    name = name.split("@", 1)[0] if "@" in name else name
    return f"unresolved:{name.strip().casefold()}"


def domain_id_from(entry: Mapping[str, Any], domain_name: str) -> str:
    """Domain identity: its SID once collected, else ``dns:<fqdn>``."""
    sid = str((entry or {}).get("domain_sid") or "").strip().upper()
    if sid.startswith(_DOMAIN_SID_PREFIX):
        return sid
    return "dns:" + str(domain_name or "").strip().rstrip(".").casefold()


def _domain_token(domain: str) -> str:
    return str(domain or "").strip().rstrip(".").casefold()


def finding_id(key: str, domain: str) -> str:
    """One finding row per catalog key per domain (matches the web's row grain)."""
    return _digest("finding", _ID_VERSION, str(key or "").strip(), _domain_token(domain))


def instance_id(finding: str, object_id: str) -> str:
    """One affected object of one finding."""
    return _digest("instance", _ID_VERSION, finding, str(object_id or ""))


def step_id(
    relation: str,
    source_object_id: str,
    target_object_id: str,
    discriminator: str = "",
    *,
    domain: str = "",
) -> str:
    """One edge instance: relation x source x target x what tells twins apart.

    ``discriminator`` carries what makes two same-relation edges between the same
    objects different (the certificate template, the share, the ACE right).
    ``domain`` scopes it: an edge between two well-known principals (``wk:``
    ids are the same in every domain) is a different item in each domain.
    """
    return _digest(
        "step",
        _ID_VERSION,
        normalize_identity_token(relation),
        str(source_object_id or ""),
        str(target_object_id or ""),
        str(discriminator or "").strip().casefold(),
        _domain_token(domain),
    )


def path_key(steps: Any, *, nodes: Any = None, domain: str = "") -> str:
    """Identity of one route: the ORDERED hop sequence within a domain."""
    return compute_attack_path_fingerprint(steps=steps, nodes=nodes, domain=domain)


# ---------------------------------------------------------------------------
# The public attack-path id: one id for the report, the web, recheck and files.
# ---------------------------------------------------------------------------

#: Key under which a path record carries its id (the full route fingerprint).
PATH_ID_KEY = "path_id"

#: Characters of the id a document prints. ``recheck --path`` takes any
#: unambiguous prefix of 8 or more, so the printed form is always accepted.
PATH_ID_DISPLAY_LENGTH = 12


def derive_attack_path_id(record: Mapping[str, Any], domain: str) -> str:
    """Derive the path id of one attack-path record from its route.

    The one derivation of the arguments :func:`compute_attack_path_fingerprint`
    takes from a record: ``details.nodes`` before ``nodes``, and the route-level
    facts (source, target, title) only when the record has no hops. The web
    ingestion keys ``attack_path_records`` with exactly this.
    """
    details = record.get("details") if isinstance(record.get("details"), Mapping) else {}
    return compute_attack_path_fingerprint(
        steps=record.get("steps"),
        nodes=details.get("nodes") or record.get("nodes") or [],
        domain=domain,
        source=record.get("source") or details.get("source"),
        target=details.get("target") or record.get("target"),
        title=record.get("title"),
    )


def attack_path_id_for_record(record: Mapping[str, Any], domain: str) -> str:
    """The id of one attack-path record: its ordered-route fingerprint.

    The one path identifier every surface agrees on. The web keys its
    ``attack_path_records`` with it, ``recheck --path`` resolves it, the
    attack-path snapshot and the report data carry it, and the report prints its
    first :data:`PATH_ID_DISPLAY_LENGTH` characters. A record that already
    carries :data:`PATH_ID_KEY` (stamped by :func:`stamp_attack_path_ids`) is
    trusted; otherwise the id is derived (:func:`derive_attack_path_id`).
    """
    stamped = str(record.get(PATH_ID_KEY) or "").strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", stamped):
        return stamped
    return derive_attack_path_id(record, domain)


def display_path_id(path_id: str) -> str:
    """The printed form of a path id (its first :data:`PATH_ID_DISPLAY_LENGTH` characters)."""
    return str(path_id or "").strip().lower()[:PATH_ID_DISPLAY_LENGTH]


def stamp_attack_path_ids(records: Iterable[Any], domain: str) -> None:
    """Stamp :data:`PATH_ID_KEY` on every record that lacks it (in place, idempotent)."""
    for record in records:
        if isinstance(record, dict) and not record.get(PATH_ID_KEY):
            record[PATH_ID_KEY] = derive_attack_path_id(record, domain)


def object_ids(nodes: Iterable[Mapping[str, Any]]) -> dict[str, str]:
    """Map each node's graph id to its stable object id."""
    out: dict[str, str] = {}
    for node in nodes:
        if isinstance(node, Mapping):
            gid = str(node.get("id") or "")
            if gid:
                out[gid] = object_id_from_node(node)
    return out
