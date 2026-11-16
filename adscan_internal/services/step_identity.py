"""The real identifiers of an attack step's two endpoints.

A step's display labels are humanized names no directory tool resolves, so the
verification and remediation commands are filled from the endpoint NODES' own
identifiers (sAMAccountName, distinguished name, DNS host name, object class,
SID). Every surface that renders a step reads them through this module: the
attack-path display records (``attack_graph_core``) and the per-edge technique
knowledge (``edge_knowledge``), which the web edge panel renders too.

A leaf on purpose: stdlib only, so the appliance backend can bundle it without
the engine.
"""

from __future__ import annotations

from typing import Any


def node_identity_from_node(node: Any) -> dict[str, str]:
    """Return a graph node's REAL, machine-resolvable identifiers.

    The display ``label`` is the humanized, realm-qualified name (e.g.
    ``"EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL"``) — good for prose but NOT a
    value any AD tool resolves: it is neither a real ``sAMAccountName`` (case
    differs, the ``@REALM`` suffix is not part of the attribute), a
    distinguished name, nor a DNS hostname. The per-step
    independent-verification / remediation commands need the object's OWN
    identifiers, sourced from the graph node's ``properties`` (populated by the
    native collector), so a copy-pasted ``Get-ADObject``/``-ComputerName``
    command in the client report actually resolves the finding instead of
    silently matching nothing. Empty strings when a field is not carried on the
    node (a Domain object has no ``sAMAccountName``; a Group/User has no
    ``dNSHostName``) — that honest gap is what the verify renderer degrades to
    an angle-bracket fill-in token, never a fabricated identifier.
    """
    props = (
        node.get("properties")
        if isinstance(node, dict) and isinstance(node.get("properties"), dict)
        else {}
    )
    # The node's object class ("Group"/"User"/"Computer"/"Domain"/...) is a
    # top-level graph-node key (``kind``), not a ``properties`` field. Stamped so
    # the catalog can select an object-class-aware abuse (a group target is abused
    # with AddMember, never with a user-only password reset / Shadow Credentials /
    # SPN write). Empty string when the endpoint is a synthetic label with no node.
    kind = ""
    if isinstance(node, dict):
        raw_kind = node.get("kind") or node.get("type") or node.get("labels")
        if isinstance(raw_kind, (list, tuple)):
            raw_kind = raw_kind[0] if raw_kind else ""
        kind = str(raw_kind or "").strip()
    # The object's SID (``objectId`` on a native node) — the invariant identifier
    # a downstream renderer uses to decide, per instance, whether the endpoint is a
    # DYNAMIC well-known identity with no manageable member list (Everyone /
    # Authenticated Users / Domain Users), which changes the remediation from
    # "remove principal X from it" (impossible) to "scope what it is granted".
    sid = ""
    if isinstance(node, dict):
        sid = str(
            node.get("objectId") or node.get("objectid") or props.get("objectsid") or ""
        ).strip()
    return {
        "dn": str(
            props.get("distinguishedname") or props.get("distinguishedName") or ""
        ).strip(),
        "samaccountname": str(
            props.get("samaccountname") or props.get("sAMAccountName") or ""
        ).strip(),
        "dnshostname": str(
            props.get("dnshostname") or props.get("dNSHostName") or ""
        ).strip(),
        "kind": kind,
        "sid": sid,
        # A Group Policy object's policy GUID (its ``{GUID}`` CN, the "Unique ID"
        # GPMC shows). Its label is the display name a person gave it, which is
        # not unique, so the GUID travels with the step as its identity.
        "gpo_guid": str(props.get("gpo_guid") or "").strip(),
    }


def stamp_gpo_guid(details: dict[str, Any], source: dict[str, str], target: dict[str, str]) -> None:
    """Stamp ``source_gpo_guid`` / ``target_gpo_guid`` only for an endpoint that is a GPO.

    Absent otherwise, so a step between two non-GPO objects keeps exactly the
    keys it had.
    """
    if source.get("gpo_guid"):
        details["source_gpo_guid"] = source["gpo_guid"]
    if target.get("gpo_guid"):
        details["target_gpo_guid"] = target["gpo_guid"]


def stamp_step_identity(
    details: dict[str, Any],
    source_node: Any,
    target_node: Any,
) -> None:
    """Stamp the REAL source/target identifiers into a step's ``details``.

    Baked here (never derived downstream from the display label) because this is
    a layer that holds the graph NODES the step's endpoints resolve to — the
    same reason ``source_privilege_tier`` is stamped here. Keeps the key order
    consistent between the eager (``decorate=True``) build and the deferred
    ``decorate_display_record`` seam so the two decoration modes stay
    byte-identical.
    """
    src = node_identity_from_node(source_node)
    tgt = node_identity_from_node(target_node)
    details["source_dn"] = src["dn"]
    details["target_dn"] = tgt["dn"]
    details["source_samaccountname"] = src["samaccountname"]
    details["target_samaccountname"] = tgt["samaccountname"]
    details["source_dnshostname"] = src["dnshostname"]
    details["target_dnshostname"] = tgt["dnshostname"]
    details["source_kind"] = src["kind"]
    details["target_kind"] = tgt["kind"]
    # Fill the endpoint SIDs from the graph node only when the step does not
    # already carry one (an edge's own notes may provide a more meaningful
    # source_sid — e.g. the well-known reader SID on a synthetic unauth entry —
    # which must win over the node's objectId).
    if src["sid"] and not str(details.get("source_sid") or "").strip():
        details["source_sid"] = src["sid"]
    if tgt["sid"] and not str(details.get("target_sid") or "").strip():
        details["target_sid"] = tgt["sid"]
    stamp_gpo_guid(details, src, tgt)


__all__ = ("node_identity_from_node", "stamp_gpo_guid", "stamp_step_identity")
