"""Which listing an ``attack_paths_snapshot.json`` holds.

The snapshot is rewritten by every attack-path listing a scan shows: the scan-end
re-materialization writes the DOMAIN listing (every route to Tier 0 the engine
found), while an operator-scope listing (routes from the accounts the run
controls, from one user, from a set of principals) writes its own narrower set
under its own ``scope`` label. A consumer that states a domain figure from the
file (a count on the loot card, a KPI in a deliverable) must read only the
domain listing, or it states the operator's subset as though it were the
domain's whole inventory.

Dependency-light by design (stdlib only): the engine, the reports and the web
backend can all import it.
"""

from __future__ import annotations

from typing import Any, Mapping

#: The ``scope`` label the domain listing is persisted under.
DOMAIN_LISTING_SCOPE = "domain"


def is_domain_listing_snapshot(payload: Any) -> bool:
    """True when ``payload`` is the persisted DOMAIN listing.

    A snapshot without a ``scope`` field predates the label and was written by
    the domain listing, so it is read as one. Anything else (``owned``,
    ``user``, ``principals``, or a start user's name) is an operator-scope
    listing.
    """
    if not isinstance(payload, Mapping):
        return False
    scope = payload.get("scope")
    if scope is None:
        return True
    return str(scope).strip().lower() in {"", DOMAIN_LISTING_SCOPE}


def domain_listing_snapshot_paths(payload: Any) -> list[dict[str, Any]]:
    """Return the path records of a DOMAIN-listing snapshot, else ``[]``.

    An operator-scope snapshot yields ``[]`` so the caller degrades exactly as it
    does for a missing snapshot, rather than reporting a subset as the domain.
    """
    if not is_domain_listing_snapshot(payload):
        return []
    paths = payload.get("paths")
    if not isinstance(paths, list):
        return []
    return [path for path in paths if isinstance(path, dict)]


__all__ = [
    "DOMAIN_LISTING_SCOPE",
    "domain_listing_snapshot_paths",
    "is_domain_listing_snapshot",
]
