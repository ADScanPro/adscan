"""Whether a directory object still exists: the one deleted-object predicate.

A domain controller answers a search of ``CN=Deleted Objects`` only for an
account allowed to read that container, which by default means an
administrator. So a scan that reaches Domain Admin and refreshes its collection
with that account sees the directory's deleted objects, and a scan that stays
unprivileged sees none. The collector keeps them on purpose: a deleted account
somebody can restore is a real route to a foothold, and its access control
entries are how that route is found. It stamps each one ``tombstoned``.

What a deleted object is, everywhere else:

* a **target** of the rights that allow restoring it, and a waypoint through
  the rights it would hold again once restored;
* never an account anyone can sign in as, so never a member of the sign-in
  groups the operating system computes (Authenticated Users, Everyone, its
  primary group), never the start of an attack path, never an affected user,
  and never part of a population, a denominator or a size count.

A deleted object keeps most of its attributes, ``userAccountControl`` included,
so it reads as ``enabled`` whenever it was enabled on the day it was deleted.
``enabled`` therefore never answers "does this account exist". Ask
:func:`is_tombstoned` (or :func:`is_live`) first, wherever a set of accounts,
computers or groups is counted or used as a source.

This module is stdlib-only so every layer (the collector, the graph build, the
attack-path engine, the membership snapshot the web backend imports, the
reports) asks the same function.
"""

from __future__ import annotations

from typing import Any

__all__ = ["TOMBSTONED_PROPERTY", "is_live", "is_tombstoned", "resolve_properties"]

#: The node property the collector stamps on a deleted object.
TOMBSTONED_PROPERTY = "tombstoned"


def resolve_properties(subject: Any) -> dict[str, Any]:
    """Return the properties of a node, a bare properties dict, or a node object.

    Three shapes circulate in this codebase and every one of them reaches these
    predicates, so accepting only one is how half the call sites silently keep
    the old behaviour:

    * a graph **node dict** -- ``{"kind": "User", "properties": {...}}``;
    * a bare **properties dict** -- what ``inventories._nodes_props`` and the
      flattened ``inventory/*.json`` records hand around;
    * a **node object** (``collector.models.CollectorNode``) carrying
      ``.properties`` plus its own ``.enabled`` field.

    A node dict is distinguished from a properties dict by carrying a
    ``properties`` key; a properties dict is returned as itself.
    """
    if isinstance(subject, dict):
        nested = subject.get("properties")
        if isinstance(nested, dict):
            return nested
        if "properties" in subject:
            return {}
        return subject
    nested = getattr(subject, "properties", None)
    return nested if isinstance(nested, dict) else {}


def is_tombstoned(subject: Any) -> bool:
    """Return whether the object is deleted (sitting in the AD Recycle Bin).

    Reads the collector's stamp from the properties, and from the record's own
    top level too: an inventory record states it there for an integrator.
    """
    if bool(resolve_properties(subject).get(TOMBSTONED_PROPERTY)):
        return True
    return isinstance(subject, dict) and subject.get(TOMBSTONED_PROPERTY) is True


def is_live(subject: Any) -> bool:
    """Return whether the object exists in the directory (``not tombstoned``)."""
    return not is_tombstoned(subject)
