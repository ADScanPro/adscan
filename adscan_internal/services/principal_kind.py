"""What kind of principal does a label name? (user / group / computer) — the SSOT.

Every actor and credential resolver asks this question about a step's source
label, and the answer decides who may act: a user acts as itself, a group acts
through the members ADscan controls, a computer through its own machine-account
credential. It must come from directory DATA, never from the label's shape:
``CASTELBLACKADMINS`` passes a sAMAccountName syntax check, and reading it as a
user produced a "user" with no credential, so the local-admin access that group
proved carried nobody into the next step (release gate 14.0.0).

The ladder, first answer wins:

1. the attack-graph node's own kind (the collector's verdict);
2. the SID, when the label is one: well-known SIDs and the fixed domain RIDs
   (500-502 accounts, 512-527 and the other built-in groups);
3. the membership snapshot (``memberships.json``): a key of ``user_to_groups``
   is a user, a key of ``computer_to_groups`` is a computer, and a label that
   has members or parents in the group hierarchy is a group;
4. unknown (``""``). An unknown label never becomes a user because of what its
   name looks like: the caller treats it as "no actor" and says so.

Graph construction uses the same evidence when it has to WRITE a kind: the SID
(:func:`principal_kind_from_sid`), the directory attributes it holds
(:func:`principal_kind_from_properties`: ``sAMAccountType`` / ``objectClass``),
or ``Unknown`` (:func:`graph_kind_label`). A synthetic node is never given a
kind guessed from its name.

Sits beside the group-membership SSOT (``group_member_index`` /
``membership_snapshot``) so a group answer is resolved to its members with the
same closure-aware index.
"""

from __future__ import annotations

from typing import Any, Callable, Final

from adscan_core.rich_output import print_exception
from adscan_internal import telemetry
from adscan_internal.services.group_member_index import (
    _canonical_membership_label,
    _snapshot_memo_get,
    _snapshot_memo_set,
)

PRINCIPAL_KIND_USER: Final[str] = "user"
PRINCIPAL_KIND_GROUP: Final[str] = "group"
PRINCIPAL_KIND_COMPUTER: Final[str] = "computer"
PRINCIPAL_KIND_UNKNOWN: Final[str] = ""

# Domain-relative RIDs whose object class is fixed by Windows in every domain.
# Anything else under a domain SID (RID >= 1000) carries no class in the SID.
_DOMAIN_USER_RIDS: Final[frozenset[int]] = frozenset({500, 501, 502, 503})
_DOMAIN_GROUP_RIDS: Final[frozenset[int]] = frozenset(
    {
        498,  # Enterprise Read-only Domain Controllers
        512,  # Domain Admins
        513,  # Domain Users
        514,  # Domain Guests
        515,  # Domain Computers
        516,  # Domain Controllers
        517,  # Cert Publishers
        518,  # Schema Admins
        519,  # Enterprise Admins
        520,  # Group Policy Creator Owners
        521,  # Read-only Domain Controllers
        522,  # Cloneable Domain Controllers
        525,  # Protected Users
        526,  # Key Admins
        527,  # Enterprise Key Admins
        553,  # RAS and IAS Servers
        571,  # Allowed RODC Password Replication Group
        572,  # Denied RODC Password Replication Group
    }
)

# sAMAccountType values (MS-ADTS 2.2.15): the directory's own class marker.
_SAM_ACCOUNT_TYPE_KIND: Final[dict[int, str]] = {
    0x10000000: PRINCIPAL_KIND_GROUP,  # SAM_GROUP_OBJECT
    0x10000001: PRINCIPAL_KIND_GROUP,  # SAM_NON_SECURITY_GROUP_OBJECT
    0x20000000: PRINCIPAL_KIND_GROUP,  # SAM_ALIAS_OBJECT
    0x20000001: PRINCIPAL_KIND_GROUP,  # SAM_NON_SECURITY_ALIAS_OBJECT
    0x30000000: PRINCIPAL_KIND_USER,  # SAM_USER_OBJECT
    0x30000001: PRINCIPAL_KIND_COMPUTER,  # SAM_MACHINE_ACCOUNT
    0x30000002: PRINCIPAL_KIND_USER,  # SAM_TRUST_ACCOUNT
}

_GRAPH_KIND_LABEL: Final[dict[str, str]] = {
    PRINCIPAL_KIND_USER: "User",
    PRINCIPAL_KIND_GROUP: "Group",
    PRINCIPAL_KIND_COMPUTER: "Computer",
}

# Per-snapshot, per-domain sets of canonical labels by kind (identity-memoized,
# so a reloaded snapshot can never serve a stale answer).
_KIND_INDEX_CACHE: dict[
    str, tuple[dict[str, Any], tuple[frozenset[str], frozenset[str], frozenset[str]]]
] = {}


def principal_kind_from_graph_node(node: Any) -> str:
    """Return the lowercased kind of an attack-graph node, or ``""`` when absent."""
    if not isinstance(node, dict):
        return PRINCIPAL_KIND_UNKNOWN
    kind = node.get("kind") or node.get("labels") or node.get("type")
    if isinstance(kind, list):
        kind = kind[0] if kind else ""
    text = str(kind or "").strip().lower()
    return "" if text in {"", "unknown"} else text


def principal_kind_from_sid(sid: str | None) -> str:
    """Return the kind a SID itself proves, or ``""``.

    A well-known SID (``S-1-1-0``, ``S-1-5-32-544`` ...) carries its class in the
    shared well-known table; a domain SID proves its class only for the fixed
    RIDs Windows creates in every domain (500-502 accounts, 512-527 and the
    other built-in domain groups). Every other SID proves nothing.
    """
    text = str(sid or "").strip().upper()
    if not text.startswith("S-1-"):
        return PRINCIPAL_KIND_UNKNOWN
    from adscan_core.reporting.principal_display import _WELL_KNOWN  # noqa: PLC0415

    entry = _WELL_KNOWN.get(text)
    if entry is not None:
        return str(entry[1]).strip().lower()
    if text.startswith("S-1-5-21-"):
        rid_text = text.rsplit("-", 1)[-1]
        if rid_text.isdigit():
            rid = int(rid_text)
            if rid in _DOMAIN_USER_RIDS:
                return PRINCIPAL_KIND_USER
            if rid in _DOMAIN_GROUP_RIDS:
                return PRINCIPAL_KIND_GROUP
    return PRINCIPAL_KIND_UNKNOWN


def principal_kind_from_properties(properties: Any) -> str:
    """Return the kind directory attributes prove (``sAMAccountType`` / ``objectClass``).

    ``computer`` is checked before ``user`` in ``objectClass`` because a computer
    object's class chain includes ``user``.
    """
    if not isinstance(properties, dict):
        return PRINCIPAL_KIND_UNKNOWN
    lowered = {str(key).lower(): value for key, value in properties.items()}
    sam_type = lowered.get("samaccounttype")
    try:
        if sam_type is not None and str(sam_type).strip() != "":
            kind = _SAM_ACCOUNT_TYPE_KIND.get(int(str(sam_type).strip(), 0))
            if kind:
                return kind
    except ValueError:
        pass
    object_class = lowered.get("objectclass")
    if isinstance(object_class, str):
        classes = {object_class.strip().lower()}
    elif isinstance(object_class, (list, tuple, set)):
        classes = {str(item).strip().lower() for item in object_class}
    else:
        classes = set()
    if "computer" in classes:
        return PRINCIPAL_KIND_COMPUTER
    if "group" in classes:
        return PRINCIPAL_KIND_GROUP
    if "user" in classes or "person" in classes:
        return PRINCIPAL_KIND_USER
    return PRINCIPAL_KIND_UNKNOWN


def graph_kind_label(kind: str | None) -> str:
    """Return the attack-graph spelling of a kind: ``User`` / ``Group`` /
    ``Computer``, or ``Unknown`` when nothing proved it."""
    return _GRAPH_KIND_LABEL.get(str(kind or "").strip().lower(), "Unknown")


def _kind_index(
    snapshot: dict[str, Any], domain: str
) -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """Return ``(users, computers, groups)`` canonical label sets for a snapshot."""
    key = str(domain or "").strip().upper()
    cached = _snapshot_memo_get(_KIND_INDEX_CACHE, key, snapshot)
    if cached is not None:
        return cached

    def _canon_all(values: Any) -> set[str]:
        out: set[str] = set()
        if isinstance(values, (list, tuple, set, frozenset)):
            for value in values:
                label = _canonical_membership_label(domain, str(value or ""))
                if label:
                    out.add(label)
        return out

    users: set[str] = set()
    computers: set[str] = set()
    groups: set[str] = set()
    user_to_groups = snapshot.get("user_to_groups")
    computer_to_groups = snapshot.get("computer_to_groups")
    group_to_parents = snapshot.get("group_to_parents")
    if isinstance(user_to_groups, dict):
        for principal, parent_groups in user_to_groups.items():
            users.update(_canon_all([principal]))
            groups.update(_canon_all(parent_groups))
    if isinstance(computer_to_groups, dict):
        for principal, parent_groups in computer_to_groups.items():
            computers.update(_canon_all([principal]))
            groups.update(_canon_all(parent_groups))
    if isinstance(group_to_parents, dict):
        for group, parents in group_to_parents.items():
            groups.update(_canon_all([group]))
            groups.update(_canon_all(parents))
    result = (frozenset(users), frozenset(computers), frozenset(groups))
    return _snapshot_memo_set(_KIND_INDEX_CACHE, key, snapshot, result)


def principal_kind_from_snapshot(
    snapshot: dict[str, Any] | None, domain: str, label: str | None
) -> str:
    """Return the kind the membership snapshot records for ``label``, or ``""``.

    A label recorded as a member principal wins over appearing as a group, so a
    snapshot that is internally inconsistent never turns a known user into a
    group. A label absent from the snapshot is unknown.
    """
    if not isinstance(snapshot, dict) or not snapshot:
        return PRINCIPAL_KIND_UNKNOWN
    canonical = _canonical_membership_label(domain, str(label or ""))
    if not canonical:
        return PRINCIPAL_KIND_UNKNOWN
    users, computers, groups = _kind_index(snapshot, domain)
    if canonical in users:
        return PRINCIPAL_KIND_USER
    if canonical in computers:
        return PRINCIPAL_KIND_COMPUTER
    if canonical in groups:
        return PRINCIPAL_KIND_GROUP
    return PRINCIPAL_KIND_UNKNOWN


def resolve_principal_kind(
    shell: Any,
    domain: str,
    label: str | None,
    *,
    get_node: Callable[..., Any] | None = None,
    load_snapshot: Callable[[Any, str], Any] | None = None,
) -> str:
    """Return the kind of principal ``label`` names: graph, then snapshot, then ``""``.

    ``get_node`` / ``load_snapshot`` default to the attack-graph and membership
    SSOT loaders; a caller passes its own module-level lookup so that one seam
    serves both the executor and its tests. Best-effort: a failing lookup is an
    unknown answer, never an exception.
    """
    text = str(label or "").strip()
    if not text:
        return PRINCIPAL_KIND_UNKNOWN

    if get_node is None:
        from adscan_internal.services.attack_graph_service import (  # noqa: PLC0415
            get_node_by_label as get_node,
        )
    try:
        kind = principal_kind_from_graph_node(get_node(shell, domain, label=text))
    except Exception as exc:  # noqa: BLE001 — graph lookup is best-effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        kind = PRINCIPAL_KIND_UNKNOWN
    if kind:
        return kind

    # A label that IS a SID proves its own class for the well-known SIDs and the
    # fixed domain RIDs.
    kind = principal_kind_from_sid(text.split("@", 1)[0])
    if kind:
        return kind

    if load_snapshot is None:
        from adscan_internal.services.membership_snapshot import (  # noqa: PLC0415
            load_membership_snapshot as load_snapshot,
        )
    try:
        snapshot = load_snapshot(shell, domain)
    except Exception as exc:  # noqa: BLE001 — snapshot lookup is best-effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        snapshot = None
    return principal_kind_from_snapshot(snapshot, domain, text)


__all__ = [
    "PRINCIPAL_KIND_COMPUTER",
    "PRINCIPAL_KIND_GROUP",
    "PRINCIPAL_KIND_UNKNOWN",
    "PRINCIPAL_KIND_USER",
    "graph_kind_label",
    "principal_kind_from_graph_node",
    "principal_kind_from_properties",
    "principal_kind_from_sid",
    "principal_kind_from_snapshot",
    "resolve_principal_kind",
]
