"""How ``memberships.json`` becomes the snapshot every membership reader uses.

The file on disk is the RAW collector shape (``nodes`` + ``edges``, membership
1.0). Every reader that resolves who is in a group (the attack-path engine, the
affected-assets member examples, the edge technique text) needs the PREPARED
shape: ``user_to_groups`` / ``computer_to_groups`` / ``group_to_parents``, the
implicit primary-group memberships, and the label/SID/real-name maps.

:func:`prepare_membership_snapshot` is that one function. It lives in this leaf
module, stdlib plus ``group_member_index`` (itself dependency-light), so the
appliance web backend, which bundles no scan engine, runs the SAME code the
engine runs. ``attack_paths_core`` re-exports every name under its historical
spelling. Moved verbatim from ``attack_paths_core``.
"""

from __future__ import annotations

import re
from array import array
from dataclasses import dataclass, field
from typing import Any, Iterable

from adscan_core.directory_object_state import is_tombstoned
from adscan_internal.services.group_member_index import _canonical_membership_label

_SID_PATTERN = re.compile(r"(S-1-\d+(?:-\d+)+)", re.IGNORECASE)


def _extract_sid(value: str) -> str | None:
    if not value:
        return None
    match = _SID_PATTERN.search(value)
    if not match:
        return None
    return match.group(1).upper()


def _domain_sid_from_sid(sid: str) -> str | None:
    """Return the AD domain SID for a domain object SID or principal SID."""
    sid = str(sid or "").strip().upper()
    if not sid.startswith("S-1-5-21-"):
        return None
    parts = sid.split("-")
    if len(parts) == 7:
        return sid
    if len(parts) > 7:
        return "-".join(parts[:-1])
    return None


def prepare_membership_snapshot(
    data: dict[str, Any] | None, domain: str
) -> dict[str, Any] | None:
    """Normalize memberships.json into a consistent snapshot structure."""
    if not isinstance(data, dict):
        return None

    if isinstance(data.get("user_to_groups"), dict) or isinstance(
        data.get("group_to_parents"), dict
    ):
        normalized = dict(data)
        normalized.setdefault("tier0_users", [])
        # Ensure the label->real-name map exists on a pre-built snapshot too, so
        # locale-sensitive names resolve losslessly regardless of which branch
        # produced the snapshot. Merge (never clobber) any persisted map.
        if isinstance(normalized.get("nodes"), dict):
            derived_names = _build_label_to_name(normalized["nodes"], domain)
            existing_names = normalized.get("label_to_name")
            if isinstance(existing_names, dict):
                for key, value in derived_names.items():
                    existing_names.setdefault(key, value)
            elif derived_names:
                normalized["label_to_name"] = derived_names
        # When the file also has raw BH edges (membership-1.0 schema written by
        # persist_bloodhound_membership_snapshot), merge those MemberOf edges into
        # the existing dicts. This prevents runtime additions (ESC13, AddMember)
        # from shadowing real AD memberships when user_to_groups was only partially
        # populated before the BH edges were present.
        nodes_map = normalized.get("nodes")
        edges = normalized.get("edges")
        if isinstance(nodes_map, dict) and isinstance(edges, list) and edges:
            u2g: dict[str, list[str]] = normalized.get("user_to_groups") or {}
            if not isinstance(u2g, dict):
                u2g = {}
            c2g: dict[str, list[str]] = normalized.get("computer_to_groups") or {}
            if not isinstance(c2g, dict):
                c2g = {}
            g2p: dict[str, list[str]] = normalized.get("group_to_parents") or {}
            if not isinstance(g2p, dict):
                g2p = {}
            u2g_sets: dict[str, set[str]] = {
                k: set(v) for k, v in u2g.items() if isinstance(v, list)
            }
            c2g_sets: dict[str, set[str]] = {
                k: set(v) for k, v in c2g.items() if isinstance(v, list)
            }
            g2p_sets: dict[str, set[str]] = {
                k: set(v) for k, v in g2p.items() if isinstance(v, list)
            }
            changed = False
            for edge in edges:
                if not isinstance(edge, dict):
                    continue
                relation = (
                    edge.get("relation") or edge.get("label") or edge.get("kind") or ""
                )
                if str(relation) != "MemberOf":
                    continue
                from_id = edge.get("from") or edge.get("source")
                to_id = edge.get("to") or edge.get("target")
                if not from_id or not to_id:
                    continue
                from_node = nodes_map.get(str(from_id))
                to_node = nodes_map.get(str(to_id))
                if not isinstance(from_node, dict) or not isinstance(to_node, dict):
                    continue
                if _node_kind(to_node) != "Group":
                    continue
                from_label = _canonical_membership_label(
                    domain, _canonical_principal_label_for_membership(from_node)
                )
                to_label = _canonical_membership_label(
                    domain, _canonical_node_label(to_node)
                )
                if not from_label or not to_label:
                    continue
                from_kind = _node_kind(from_node)
                if from_kind == "User":
                    before = len(u2g_sets.get(from_label, set()))
                    u2g_sets.setdefault(from_label, set()).add(to_label)
                    changed = changed or len(u2g_sets[from_label]) != before
                elif from_kind == "Computer":
                    before = len(c2g_sets.get(from_label, set()))
                    c2g_sets.setdefault(from_label, set()).add(to_label)
                    changed = changed or len(c2g_sets[from_label]) != before
                elif from_kind == "Group":
                    before = len(g2p_sets.get(from_label, set()))
                    g2p_sets.setdefault(from_label, set()).add(to_label)
                    changed = changed or len(g2p_sets[from_label]) != before
            primary_changed = _merge_primary_group_memberships_from_nodes(
                domain=domain,
                nodes_map=nodes_map,
                user_to_groups=u2g_sets,
                computer_to_groups=c2g_sets,
            )
            changed = changed or primary_changed
            if changed:
                normalized["user_to_groups"] = {
                    k: sorted(v, key=str.lower) for k, v in sorted(u2g_sets.items())
                }
                normalized["computer_to_groups"] = {
                    k: sorted(v, key=str.lower) for k, v in sorted(c2g_sets.items())
                }
                normalized["group_to_parents"] = {
                    k: sorted(v, key=str.lower) for k, v in sorted(g2p_sets.items())
                }
        return normalized

    nodes_map = data.get("nodes")
    edges = data.get("edges")
    if not isinstance(nodes_map, dict) or not isinstance(edges, list):
        return None

    user_to_groups: dict[str, set[str]] = {}
    computer_to_groups: dict[str, set[str]] = {}
    group_to_parents: dict[str, set[str]] = {}
    group_labels: set[str] = set()
    label_to_sid: dict[str, str] = {}
    sid_to_label: dict[str, str] = {}
    # Canonical UPPER label -> REAL sAMAccountName (lower-cased for census/display
    # parity). Captured from the node's true samaccountname so a locale-sensitive
    # name (Turkish dotless-i, German ß) can be recovered exactly instead of being
    # rebuilt by lower-casing the UPPER label (which corrupts it). See
    # ``membership_label_to_real_name`` and the KPI reconciliation it fixes.
    label_to_name: dict[str, str] = _build_label_to_name(nodes_map, domain)
    domain_sid: str | None = None
    preferred_domain_sid: str | None = None
    first_domain_sid: str | None = None
    tier0_users: set[str] = set()

    for node in nodes_map.values():
        if not isinstance(node, dict):
            continue
        label = _canonical_membership_label(
            domain, _canonical_principal_label_for_membership(node)
        )
        if not label:
            continue
        if _node_kind(node) == "Group":
            group_labels.add(label)
        props = (
            node.get("properties") if isinstance(node.get("properties"), dict) else {}
        )
        object_id = str(
            node.get("objectId") or props.get("objectid") or props.get("objectId") or ""
        ).strip()
        sid = _extract_sid(object_id)
        if sid:
            label_to_sid[label] = sid
            sid_to_label.setdefault(sid, label)
            if sid.startswith("S-1-5-21-"):
                candidate_sid = _domain_sid_from_sid(sid)
                if candidate_sid:
                    if not first_domain_sid:
                        first_domain_sid = candidate_sid
                    if not preferred_domain_sid:
                        label_domain = str(domain or "").strip().upper()
                        label_match = label.endswith(f"@{label_domain}")
                        rid = sid.split("-")[-1]
                        preferred_rids = {
                            "512",
                            "513",
                            "514",
                            "515",
                            "516",
                            "517",
                            "518",
                            "519",
                            "520",
                        }
                        if label_match and rid in preferred_rids:
                            preferred_domain_sid = candidate_sid
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        relation = edge.get("relation") or edge.get("label") or edge.get("kind") or ""
        if str(relation) != "MemberOf":
            continue
        from_id = edge.get("from") or edge.get("source")
        to_id = edge.get("to") or edge.get("target")
        if not from_id or not to_id:
            continue
        from_node = nodes_map.get(str(from_id))
        to_node = nodes_map.get(str(to_id))
        if not isinstance(from_node, dict) or not isinstance(to_node, dict):
            continue
        if _node_kind(to_node) != "Group":
            continue

        from_label = _canonical_membership_label(
            domain, _canonical_principal_label_for_membership(from_node)
        )
        to_label = _canonical_membership_label(domain, _canonical_node_label(to_node))
        if not from_label or not to_label:
            continue

        from_kind = _node_kind(from_node)
        if from_kind == "User":
            user_to_groups.setdefault(from_label, set()).add(to_label)
        elif from_kind == "Computer":
            computer_to_groups.setdefault(from_label, set()).add(to_label)
        elif from_kind == "Group":
            group_to_parents.setdefault(from_label, set()).add(to_label)

    _merge_primary_group_memberships_from_nodes(
        domain=domain,
        nodes_map=nodes_map,
        user_to_groups=user_to_groups,
        computer_to_groups=computer_to_groups,
    )

    domain_sid = preferred_domain_sid or first_domain_sid
    return {
        "user_to_groups": {
            user: sorted(groups, key=str.lower)
            for user, groups in sorted(user_to_groups.items())
        },
        "computer_to_groups": {
            computer: sorted(groups, key=str.lower)
            for computer, groups in sorted(computer_to_groups.items())
        },
        "group_to_parents": {
            group: sorted(parents, key=str.lower)
            for group, parents in sorted(group_to_parents.items())
        },
        "group_labels": sorted(group_labels, key=str.lower),
        "tier0_users": sorted(tier0_users, key=str.lower),
        "label_to_sid": label_to_sid,
        "sid_to_label": sid_to_label,
        "label_to_name": label_to_name,
        "domain_sid": domain_sid,
    }


_KIND_NONE = 0
_KIND_USER = 1
_KIND_COMPUTER = 2
_KIND_GROUP = 3
_PREFERRED_DOMAIN_RIDS = frozenset(
    {"512", "513", "514", "515", "516", "517", "518", "519", "520"}
)
#: Root keys whose presence marks a file as already prepared (a runtime write
#: re-embeds the prepared maps beside the raw ones); such a file keeps going
#: through :func:`prepare_membership_snapshot` so its snapshot is unchanged.
_PREPARED_ROOT_KEYS = frozenset({"user_to_groups", "group_to_parents"})


@dataclass
class StreamedMembership:
    """What :func:`prepare_membership_snapshot_from_events` learned from a file.

    Attributes:
        snapshot: The prepared snapshot, or ``None`` when the document is not a
            raw membership export or has to be prepared whole (see ``prepared``).
        prepared: The file already carries ``user_to_groups`` or
            ``group_to_parents`` at its root. The caller prepares it whole
            (``prepare_membership_snapshot``), as before; nothing is returned.
        saw_nodes: At least one node event was read.
        saw_edges: At least one edge event was read. An empty ``nodes`` or
            ``edges`` list yields no event, so the caller settles "absent or
            empty" against the file text when either is False.
        root_keys: Root keys read, for diagnostics.
        generated_at: The ``generated_at`` root value, when present.
    """

    snapshot: dict[str, Any] | None = None
    prepared: bool = False
    saw_nodes: bool = False
    saw_edges: bool = False
    root_keys: list[str] = field(default_factory=list)
    generated_at: Any = None


def prepare_membership_snapshot_from_events(
    events: Iterable[tuple[str, Any, Any]], domain: str
) -> StreamedMembership:
    """Prepare a RAW ``memberships.json`` from its streamed elements.

    ``events`` is ``graph_compact.iter_graph_file`` over the file: ``("root",
    key, value)``, ``("edge", index, edge)`` and ``("node", node_id, node)``.
    The result equals ``prepare_membership_snapshot`` on the whole document
    (same maps, same sorting, same primary-group and domain-SID rules), but
    neither the raw ``nodes`` nor the raw ``edges`` are ever held: an edge is
    kept as two small integers, a node as the few facts the maps need, and
    each label string is created once and shared by every map that names it.
    A runtime ``MemberOf`` edge (``edge_type`` ``runtime_membership``) is an
    ordinary ``MemberOf`` edge here, exactly as in the whole-document path.
    """
    result = StreamedMembership()
    suffix = "@" + str(domain or "").strip().upper()

    ids: dict[str, int] = {}
    labels: list[str | None] = []
    kinds = bytearray()
    edge_from = array("I")
    edge_to = array("I")

    group_labels: set[str] = set()
    label_to_sid: dict[str, str] = {}
    sid_to_label: dict[str, str] = {}
    label_to_name: dict[str, str] = {}
    group_by_sid: dict[str, str] = {}
    # Primary-group candidates (parallel columns, 17 bytes each): resolved
    # once every group node has been read, whatever the order of the file.
    pg_labels: list[str] = []
    pg_kinds = bytearray()
    pg_group_sids: list[str] = []
    pg_sid_pool: dict[str, str] = {}  # a handful of distinct primary-group SIDs
    preferred_domain_sid: str | None = None
    first_domain_sid: str | None = None

    def _slot(node_id: str) -> int:
        slot = ids.get(node_id)
        if slot is None:
            slot = len(labels)
            ids[node_id] = slot
            labels.append(None)
            kinds.append(_KIND_NONE)
        return slot

    for event, key, value in events:
        if event == "root":
            result.root_keys.append(str(key))
            if key == "generated_at":
                result.generated_at = value
            elif key in _PREPARED_ROOT_KEYS and isinstance(value, dict):
                result.prepared = True
                return result
            continue
        if event == "edge":
            result.saw_edges = True
            if not isinstance(value, dict):
                continue
            relation = value.get("relation") or value.get("label") or value.get("kind") or ""
            if str(relation) != "MemberOf":
                continue
            from_id = value.get("from") or value.get("source")
            to_id = value.get("to") or value.get("target")
            if not from_id or not to_id:
                continue
            edge_from.append(_slot(str(from_id)))
            edge_to.append(_slot(str(to_id)))
            continue
        # A node.
        result.saw_nodes = True
        node = value
        if not isinstance(node, dict):
            continue
        label = _canonical_membership_label(
            domain, _canonical_principal_label_for_membership(node)
        )
        if not label:
            continue
        kind = _node_kind(node)
        kind_code = {"User": _KIND_USER, "Computer": _KIND_COMPUTER, "Group": _KIND_GROUP}.get(
            kind, _KIND_NONE
        )
        # Edges precede nodes in every file ADscan writes, so a node that no
        # edge named is never needed by an edge; when the nodes come first an
        # edge has not been seen yet, so every node keeps its slot.
        # An id is dropped once its node is read, so the id table shrinks to
        # nothing by the end of the nodes.
        slot = ids.pop(str(key), None)
        if slot is None and not result.saw_edges and kind_code:
            slot = _slot(str(key))
        if slot is not None and kind_code:
            labels[slot] = label
            kinds[slot] = kind_code
        sid = _extract_node_sid(node)
        if kind_code == _KIND_GROUP:
            group_labels.add(label)
            if sid:
                group_by_sid[sid] = label
        if sid:
            label_to_sid[label] = sid
            sid_to_label.setdefault(sid, label)
            if sid.startswith("S-1-5-21-"):
                candidate = _domain_sid_from_sid(sid)
                if candidate:
                    if not first_domain_sid:
                        first_domain_sid = candidate
                    if (
                        not preferred_domain_sid
                        and label.endswith(suffix)
                        and sid.split("-")[-1] in _PREFERRED_DOMAIN_RIDS
                    ):
                        preferred_domain_sid = candidate
        if kind_code in (_KIND_USER, _KIND_COMPUTER):
            real_name = str(_canonical_principal_label_for_membership(node) or "").strip()
            if real_name:
                label_to_name.setdefault(label, real_name.lower())
            # A deleted object keeps its primaryGroupID but is a member of
            # nothing until it is restored.
            pg_sid = "" if is_tombstoned(node) else _primary_group_sid_for_node(node)
            if pg_sid:
                pg_labels.append(label)
                pg_kinds.append(kind_code)
                pg_group_sids.append(pg_sid_pool.setdefault(pg_sid, pg_sid))

    ids.clear()
    user_to_groups: dict[str, list[str]] = {}
    computer_to_groups: dict[str, list[str]] = {}
    group_to_parents: dict[str, list[str]] = {}
    targets = {
        _KIND_USER: user_to_groups,
        _KIND_COMPUTER: computer_to_groups,
        _KIND_GROUP: group_to_parents,
    }
    for index in range(len(edge_from)):
        to_slot = edge_to[index]
        if kinds[to_slot] != _KIND_GROUP:
            continue
        from_slot = edge_from[index]
        from_kind = kinds[from_slot]
        if not from_kind:
            continue
        targets[from_kind].setdefault(labels[from_slot], []).append(labels[to_slot])  # type: ignore[arg-type]
    labels.clear()
    kinds.clear()
    del edge_from[:]
    del edge_to[:]
    for index, principal in enumerate(pg_labels):
        group_label = group_by_sid.get(pg_group_sids[index])
        if not group_label or group_label == principal:
            continue
        targets[pg_kinds[index]].setdefault(principal, []).append(group_label)

    def _finish(mapping: dict[str, list[str]]) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for name in sorted(mapping):
            out[name] = sorted(set(mapping.pop(name)), key=str.lower)
        return out

    result.snapshot = {
        "user_to_groups": _finish(user_to_groups),
        "computer_to_groups": _finish(computer_to_groups),
        "group_to_parents": _finish(group_to_parents),
        "group_labels": sorted(group_labels, key=str.lower),
        "tier0_users": [],
        "label_to_sid": label_to_sid,
        "sid_to_label": sid_to_label,
        "label_to_name": label_to_name,
        "domain_sid": preferred_domain_sid or first_domain_sid,
    }
    return result


def _merge_primary_group_memberships_from_nodes(
    *,
    domain: str,
    nodes_map: dict[str, Any],
    user_to_groups: dict[str, set[str]],
    computer_to_groups: dict[str, set[str]],
) -> bool:
    """Add effective primary-group memberships omitted from LDAP ``memberOf``.

    Active Directory does not include a principal's primary group in the
    ``memberOf`` attribute. Native graph snapshots therefore need to derive that
    edge from ``primaryGroupID`` and the principal/domain SID so owned-scope
    path search can inherit rights granted to groups such as Domain Users.
    """
    sid_to_group_label = _build_group_label_by_sid(domain, nodes_map)
    changed = False
    for node in nodes_map.values():
        if not isinstance(node, dict):
            continue
        kind = _node_kind(node)
        if kind not in {"User", "Computer"}:
            continue
        # A deleted object keeps its primaryGroupID but is a member of nothing
        # until it is restored (adscan_core.directory_object_state).
        if is_tombstoned(node):
            continue
        principal_label = _canonical_membership_label(
            domain, _canonical_principal_label_for_membership(node)
        )
        primary_group_sid = _primary_group_sid_for_node(node)
        if not principal_label or not primary_group_sid:
            continue
        group_label = sid_to_group_label.get(primary_group_sid)
        if not group_label or group_label == principal_label:
            continue
        target = user_to_groups if kind == "User" else computer_to_groups
        groups = target.setdefault(principal_label, set())
        before = len(groups)
        groups.add(group_label)
        changed = changed or len(groups) != before
    return changed


def _build_group_label_by_sid(domain: str, nodes_map: dict[str, Any]) -> dict[str, str]:
    """Return SID -> canonical group label for group nodes in a graph snapshot."""
    result: dict[str, str] = {}
    for node in nodes_map.values():
        if not isinstance(node, dict) or _node_kind(node) != "Group":
            continue
        sid = _extract_node_sid(node)
        label = _canonical_membership_label(domain, _canonical_node_label(node))
        if sid and label:
            result[sid] = label
    return result


def _primary_group_sid_for_node(node: dict[str, Any]) -> str:
    """Return the primary group SID for a user/computer node, if derivable."""
    principal_sid = _extract_node_sid(node)
    if not principal_sid or not principal_sid.startswith("S-1-5-21-"):
        return ""
    primary_group_id = _node_primary_group_id(node)
    if primary_group_id is None:
        return ""
    domain_sid, _, _rid = principal_sid.rpartition("-")
    if not domain_sid:
        return ""
    return f"{domain_sid}-{primary_group_id}"


def _node_primary_group_id(node: dict[str, Any]) -> int | None:
    """Return a normalized ``primaryGroupID`` value from node metadata."""
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    for key in ("primarygroupid", "primaryGroupID", "primary_group_id"):
        value = node.get(key)
        if value is None:
            value = props.get(key)
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return None


def _extract_node_sid(node: dict[str, Any]) -> str:
    """Extract a normalized SID from a graph node."""
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    object_id = str(
        node.get("objectId") or props.get("objectid") or props.get("objectId") or ""
    ).strip()
    return _extract_sid(object_id)


def _membership_label_to_name(label: str) -> str:
    raw = str(label or "").strip()
    if "@" in raw:
        return raw.split("@", 1)[0].strip()
    return raw


def _build_label_to_name(nodes_map: dict[str, Any], domain: str) -> dict[str, str]:
    """Map each User/Computer canonical label -> its REAL sAMAccountName (lower).

    Captured from the node's actual ``samaccountname`` BEFORE the canonical label
    is upper-cased, so a locale-sensitive name (Turkish dotless-i ``ı``, German
    ``ß``) survives losslessly. Consumers use :func:`membership_label_to_real_name`
    to recover it instead of lower-casing the UPPER canonical label, which
    corrupts such names (``AYAZICI`` -> ``ayazici`` != real ``ayazıcı``).
    """
    out: dict[str, str] = {}
    if not isinstance(nodes_map, dict):
        return out
    for node in nodes_map.values():
        if not isinstance(node, dict) or _node_kind(node) not in {"User", "Computer"}:
            continue
        real_name = str(_canonical_principal_label_for_membership(node) or "").strip()
        if not real_name:
            continue
        label = _canonical_membership_label(domain, real_name)
        if label:
            out.setdefault(label, real_name.lower())
    return out


def membership_label_to_real_name(snapshot: Any, label: str) -> str:
    """Recover a principal's REAL sAMAccountName from its canonical label.

    Uses the snapshot's ``label_to_name`` map (populated by
    :func:`prepare_membership_snapshot` from the node's true ``samaccountname``)
    so locale-sensitive names are exact. Falls back to the legacy
    ``_membership_label_to_name(label).lower()`` reconstruction only when the
    label is absent from the map (a synthetic / augmented label with no backing
    node) — for plain ASCII names the two agree, so the fallback never regresses
    the common case.

    This is the SSOT for "canonical membership label -> real name". Never rebuild
    a real name inline by lower-casing the UPPER label: that silently drops
    accounts whose name contains ``ı`` / ``ß`` from every real-name-keyed set
    (the enabled-users census, the exposure-KPI ordinary denominator).
    """
    lossy = _membership_label_to_name(label).strip().lower()
    if isinstance(snapshot, dict):
        mapping = snapshot.get("label_to_name")
        if isinstance(mapping, dict):
            resolved = mapping.get(label)
            if isinstance(resolved, str) and resolved:
                return resolved
    return lossy


def _canonical_node_label(node: dict[str, Any]) -> str:
    label = node.get("label") or node.get("name")
    if isinstance(label, str) and label.strip():
        return label.strip()
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    name = props.get("name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    return str(label or "").strip()


def _canonical_principal_label_for_membership(node: dict[str, Any]) -> str:
    """Return the canonical principal label used for membership snapshot keys.

    Membership lookups (``_snapshot_get_direct_groups``) canonicalize the
    incoming principal as ``<sAMAccountName>@<DOMAIN>``.  For consistency,
    the snapshot writer must store keys in the same form.  BloodHound's
    ``label`` field equals the sAMAccountName for User nodes but the
    FQDN for Computer nodes (``RODC01.GARFIELD.HTB``), which would key
    Computer entries under a form lookups never use.

    Prefers ``properties.samaccountname`` (BloodHound CE / native collector
    populate this on User and Computer nodes), then falls back to the
    existing ``_canonical_node_label`` behaviour for non-principal node
    kinds (Group, Domain, OU, GPO, etc.) where the label IS the canonical
    identifier.
    """
    kind = _node_kind(node)
    if kind in {"User", "Computer"}:
        props = (
            node.get("properties") if isinstance(node.get("properties"), dict) else {}
        )
        for key in ("samaccountname", "sAMAccountName", "sam_account_name"):
            value = props.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return _canonical_node_label(node)


def _node_kind(node: dict[str, Any]) -> str:
    kind = node.get("kind") or node.get("labels") or node.get("type")
    if isinstance(kind, list) and kind:
        preferred = {
            "User",
            "Computer",
            "Group",
            "Domain",
            "GPO",
            "OU",
            "Container",
            "CertTemplate",
            "EnterpriseCA",
            "AIACA",
            "RootCA",
            "NTAuthStore",
        }
        for entry in kind:
            if str(entry) in preferred:
                return str(entry)
        return str(kind[0])
    if isinstance(kind, str) and kind:
        return kind
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    fallback = props.get("type") or props.get("objecttype")
    if isinstance(fallback, str) and fallback:
        return fallback
    return "Unknown"


__all__ = (
    "_build_group_label_by_sid",
    "_build_label_to_name",
    "_canonical_node_label",
    "_canonical_principal_label_for_membership",
    "_domain_sid_from_sid",
    "_extract_node_sid",
    "_extract_sid",
    "_membership_label_to_name",
    "_merge_primary_group_memberships_from_nodes",
    "_node_kind",
    "_node_primary_group_id",
    "_primary_group_sid_for_node",
    "membership_label_to_real_name",
    "StreamedMembership",
    "prepare_membership_snapshot",
    "prepare_membership_snapshot_from_events",
)
