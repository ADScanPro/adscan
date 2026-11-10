"""Identity of one attack-graph edge: the SSOT shared by the engine and the web.

Most relations are one edge per ``(source, relation, target)``. Some relations
carry the fact that tells two REAL edges apart outside that triple, in the
edge's ``notes``. Today that is the SMB share-access family (ReadShare,
WriteShare, FullControlShare): one principal can hold different access to
several shares on one host, and each grant is its own finding.

The engine keys these relations by share when it upserts an edge
(``attack_graph_service.upsert_edge``), so ``attack_graph.json`` carries one
edge per share. The web persisted ``attack_graph_edges`` keyed on the bare
triple, so edges that differed only by share collided and all but one were
dropped from the Shares page with no error. Both sides now read the identity
from this module.

Fingerprint contract (``attack_graph_edge_fingerprint``):

* Without a discriminator the fingerprint is byte-identical to the historical
  ``sha256(f"{source}|{relation}|{target}")``. It doubles as the stable
  attack-step id behind ``/attack-steps/{step_id}`` deep links and
  ``compromised_via_step_id``, so an edge whose identity did not change keeps
  its id.
* With a discriminator the canonical ``|<name>=<value>`` suffix is appended.
  Values are casefolded and whitespace-trimmed, so a case-only variant of a
  share name can never fork identity.
* Source, relation and target are hashed verbatim (the legacy contract);
  only membership in a discriminated family is case-insensitive.

To discriminate a new relation family, add its rule to
``edge_identity_discriminator`` and ship a data migration that re-keys the
already-persisted rows (see web Alembic revision 052 for the share case).

Stdlib only: imported by the engine, the web backend and an Alembic migration.
"""

from __future__ import annotations

import hashlib
from typing import Any

#: Relations whose identity includes the share they grant (lowercase keys).
SHARE_ACCESS_RELATION_KEYS: frozenset[str] = frozenset(
    {"readshare", "writeshare", "fullcontrolshare"}
)

_SHARE_ACL_METHOD_PREFIX = "share_acl:"


def share_access_name_from_notes(notes: Any) -> str:
    """Return the share name a share-access edge carries, as written.

    Reads ``share_name``, then ``share``, then the native collector's
    ``collector_method`` (``share_acl:<name>``). Empty when absent.
    """
    if not isinstance(notes, dict):
        return ""
    share_name = str(notes.get("share_name") or notes.get("share") or "").strip()
    if share_name:
        return share_name
    collector_method = str(notes.get("collector_method") or "").strip()
    if collector_method.lower().startswith(_SHARE_ACL_METHOD_PREFIX):
        return collector_method.split(":", 1)[1].strip()
    return ""


def is_share_access_relation(relation: Any) -> bool:
    """Whether ``relation`` belongs to the SMB share-access family."""
    return str(relation or "").strip().lower() in SHARE_ACCESS_RELATION_KEYS


def edge_identity_discriminator(relation: Any, notes: Any) -> str:
    """Return the canonical identity component beyond the triple, or ``""``.

    ``"share=<casefolded name>"`` for a share-access edge that names its share;
    ``""`` for every other edge (and for a share edge with no share recorded,
    which then degrades to the triple exactly as the engine does).
    """
    if is_share_access_relation(relation):
        share = share_access_name_from_notes(notes).casefold()
        if share:
            return f"share={share}"
    return ""


def attack_graph_edge_fingerprint(
    source: str, relation: str, target: str, notes: Any = None
) -> str:
    """SHA256 identity of one attack-graph edge (see module contract)."""
    fingerprint_input = f"{source}|{relation}|{target}"
    discriminator = edge_identity_discriminator(relation, notes)
    if discriminator:
        fingerprint_input = f"{fingerprint_input}|{discriminator}"
    return hashlib.sha256(fingerprint_input.encode()).hexdigest()
