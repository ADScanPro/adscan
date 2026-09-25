"""Per-user exposure ranking: rank accounts by how many compromise paths reach them.

This is the *transpose* of the affected-users data the deliverable already
carries. Instead of "path P affects users A, B, C", it answers the question a
client actually asks first — "which of my accounts is the most exposed?" — by
counting, per account, how many distinct domain-compromise attack paths can
REACH (execute against) it. A client then reads a single, decisive line:
"user1 is the most exposed account — reachable by 4 compromise paths, 2 of
them validated."

Two design constraints shape the shape it returns:

* **Scale.** A 1k-2k-user domain must never render 1000 rows. The ranking keeps
  the first ``top_n`` accounts individually and COLLAPSES the long tail into
  buckets keyed by the exact reachable-path count. A small, distinctive bucket
  (a handful of accounts all reachable by the same N paths) still lists its
  names — that is a finding a client wants to see; a large bucket collapses to a
  count.
* **Exposure-Validation honesty.** "Reachable" (a route exists) and "proven"
  (ADscan executed the route) are kept SEPARATE per account and never conflated.
  A later renderer words the first as "can reach" and the second as "validated";
  this module never merges them.

Pure logic: no IO, no console, no network, and — deliberately — no import from
``adscan_internal`` or the engine/native stack. Safe to import from the stripped
LITE build and the web backend alike.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

#: Path display statuses that count as PROVEN (ADscan actually executed the
#: route end to end). Mirrors the proven-token set used across the reporting
#: layer; kept local so this module stays dependency-free.
_PROVEN_STATUSES = frozenset({"exploited", "domain_compromised", "success"})


def _path_is_proven(path: Mapping[str, Any]) -> bool:
    """Return True when a path record's status marks it as proven/executed."""
    return str(path.get("status", "")).strip().lower() in _PROVEN_STATUSES


def _clean_display_name(name: str) -> str:
    """Strip stray leading/trailing underscores from a service-account name.

    Directory service accounts are frequently stored with cosmetic underscore
    padding (``___vmware_conv_sa___``, ``__vmware_user__``) that reads as noise in
    a client deliverable. Trim only the leading/trailing runs — internal
    underscores are part of the real ``sAMAccountName`` and are preserved — and
    fall back to the original when trimming would leave nothing (an all-underscore
    token). Pure display cleanup; the ranking still keys on the raw name.
    """
    stripped = name.strip().strip("_")
    return stripped or name


def _build_domain_tier2_set(paths: Iterable[Mapping[str, Any]]) -> set[str] | None:
    """The DOMAIN-level ordinary Tier-2 user set, from every path's tier map.

    Aggregates ``meta.affected_users_tier_map`` across ALL paths and returns the
    accounts graded ``tier2`` (lower-cased). Must be domain-level, not per-path:
    only the broad-group paths resolve full membership and carry a tier map, so a
    per-path filter would leak every single-user path's account. This yields the
    one ordinary-Tier-2 population the exposure-KPI headline counts. Returns
    ``None`` when NO path carries any tier data (an old snapshot) so the caller
    degrades to an unfiltered ranking rather than an empty one.
    """
    result: set[str] = set()
    saw_tier_data = False
    for path in paths or ():
        if not isinstance(path, Mapping):
            continue
        meta = path.get("meta")
        if not isinstance(meta, Mapping):
            continue
        tier_map = meta.get("affected_users_tier_map")
        if not isinstance(tier_map, Mapping) or not tier_map:
            continue
        saw_tier_data = True
        for user, tier in tier_map.items():
            if (
                isinstance(user, str)
                and user.strip()
                and str(tier).strip().lower() == "tier2"
            ):
                result.add(user.strip().lower())
    return result if saw_tier_data else None


def _affected_users(
    path: Mapping[str, Any], tier2_set: set[str] | None = None
) -> set[str]:
    """Extract the lowercased ordinary **Tier-2** affected users from ``meta``.

    Reads ``meta.affected_users`` and FILTERS it to ``tier2_set`` — the DOMAIN-level
    ordinary Tier-2 population the caller built once (:func:`_build_domain_tier2_set`)
    — the SAME "standard user" population the exposure-KPI headline counts. A Tier-0
    account (already privileged; ranking it as "most exposed" is meaningless — it IS
    the target) and any account outside that ordinary-Tier-2 set are dropped, so the
    per-user ranking and its ``total_exposed_users`` agree with the KPI's ordinary
    figure rather than the raw affected set (which mixes Tier-0 + untiered accounts).

    ``tier2_set`` is ``None`` only when the whole domain carried no tier data (an old
    snapshot); the list is then kept UNFILTERED — a best-effort degrade. Returns an
    empty set when the field is absent or not a list. Non-string / blank entries are
    dropped. Never raises.
    """
    meta = path.get("meta")
    if not isinstance(meta, Mapping):
        return set()
    raw = meta.get("affected_users")
    if not isinstance(raw, (list, tuple, set)):
        return set()
    names = {e.strip().lower() for e in raw if isinstance(e, str) and e.strip()}
    if tier2_set is not None:
        return names & tier2_set
    return names


def build_user_exposure_ranking(
    paths: Iterable[Mapping[str, Any]],
    *,
    top_n: int = 15,
    name_bucket_max: int = 5,
) -> dict[str, Any]:
    """Rank accounts by how many distinct compromise paths can reach them.

    Args:
        paths: The attack-path records. Each is a mapping that may carry
            ``meta.affected_users`` (a list of principal names) and a
            ``status`` string. Records without affected users contribute
            nothing to the ranking.
        top_n: How many top-ranked accounts to return individually in
            ``top_users``. The remainder collapse into ``buckets``.
        name_bucket_max: A collapsed bucket lists its member names only when it
            holds this many accounts or fewer; larger buckets collapse to a
            count with ``users=None``.

    Returns:
        A pure JSON-safe render model:

        ``{"top_users": [{"name", "reachable_paths", "proven_paths"}],``
        ``"buckets": [{"route_count", "user_count", "has_proven", "users"}],``
        ``"total_exposed_users", "max_reachable",``
        ``"uniform", "is_ranked", "population_statement",``
        ``"shared_route_count", "shared_proven_count"}``

        ``uniform`` is ``True`` when every exposed account shares the identical
        exposure profile (the same reachable-path count AND the same proven
        count), so a per-account ranking discriminates nothing — on a bridged
        domain every ordinary user is equally, maximally exposed. In that case
        ``is_ranked`` is ``False`` and ``population_statement`` carries the one
        honest population sentence a renderer shows INSTEAD of the fake row list;
        ``shared_route_count`` / ``shared_proven_count`` are the values every
        account shares. When exposure varies, ``uniform`` is ``False``,
        ``is_ranked`` is ``True``, ``population_statement`` is ``""`` and the
        named ranking is the thing to render.

        Empty or degenerate input yields a well-formed empty model
        (``top_users=[]``, ``buckets=[]``, totals ``0``, ``uniform=False``); this
        function never raises.
    """
    top_n = max(int(top_n), 0)
    name_bucket_max = max(int(name_bucket_max), 0)

    # Per-user tallies: reachable = distinct paths that list the user;
    # proven = how many of those are executed. A set of path identities is not
    # needed because we iterate each path once and each contributes at most one
    # to a given user.
    reachable: dict[str, int] = {}
    proven: dict[str, int] = {}

    # The DOMAIN-level ordinary Tier-2 population, resolved ONCE so every path's
    # affected users filter to the SAME set the exposure-KPI headline counts (only
    # the broad-group paths carry a tier map, so it is aggregated across all paths).
    # Materialize the iterable because we pass over it twice.
    materialized = [p for p in paths if isinstance(p, Mapping)]
    tier2_set = _build_domain_tier2_set(materialized)

    for path in materialized:
        users = _affected_users(path, tier2_set)
        if not users:
            continue
        is_proven = _path_is_proven(path)
        for user in users:
            reachable[user] = reachable.get(user, 0) + 1
            if is_proven:
                proven[user] = proven.get(user, 0) + 1

    # Rank: reachable desc, proven desc, name asc.
    ranked = sorted(
        reachable.keys(),
        key=lambda name: (-reachable[name], -proven.get(name, 0), name),
    )

    total_exposed_users = len(ranked)
    max_reachable = reachable[ranked[0]] if ranked else 0

    top_users = [
        {
            "name": _clean_display_name(name),
            "reachable_paths": reachable[name],
            "proven_paths": proven.get(name, 0),
        }
        for name in ranked[:top_n]
    ]

    # Collapse the tail into buckets keyed by exact reachable_paths, descending.
    tail = ranked[top_n:]
    grouped: dict[int, list[str]] = {}
    for name in tail:
        grouped.setdefault(reachable[name], []).append(name)

    buckets: list[dict[str, Any]] = []
    for route_count in sorted(grouped.keys(), reverse=True):
        names = sorted(grouped[route_count])
        user_count = len(names)
        has_proven = any(proven.get(name, 0) > 0 for name in names)
        buckets.append(
            {
                "route_count": route_count,
                "user_count": user_count,
                "has_proven": has_proven,
                "users": (
                    [_clean_display_name(n) for n in names]
                    if user_count <= name_bucket_max
                    else None
                ),
            }
        )

    # Uniform-exposure detection. When every exposed account shares the identical
    # (reachable, proven) profile there is no discriminator: a per-account ranking
    # would list N alphabetical rows all reading "reaches K routes, M validated"
    # and misleadingly tell the client to harden THOSE named accounts, when the
    # real finding is that the ENTIRE ordinary population is equally, maximally
    # exposed through the same shared chains. A renderer collapses this to one
    # population sentence instead of the fake ranking.
    profiles = {(reachable[name], proven.get(name, 0)) for name in ranked}
    uniform = total_exposed_users >= 2 and len(profiles) == 1
    shared_route_count = max_reachable if uniform else 0
    shared_proven_count = proven.get(ranked[0], 0) if uniform else 0
    population_statement = (
        _build_population_statement(
            total_exposed_users, shared_route_count, shared_proven_count
        )
        if uniform
        else ""
    )

    return {
        "top_users": top_users,
        "buckets": buckets,
        "total_exposed_users": total_exposed_users,
        "max_reachable": max_reachable,
        "uniform": uniform,
        "is_ranked": not uniform,
        "population_statement": population_statement,
        "shared_route_count": shared_route_count,
        "shared_proven_count": shared_proven_count,
    }


def _build_population_statement(
    total_exposed: int, route_count: int, proven_count: int
) -> str:
    """Return the honest population sentence for the uniform-exposure case.

    Client-safe, human-grade English (no em-dash, no percentage): states that
    exposure is uniform across the whole ordinary population, so the finding is
    the population, not a ranking of interchangeable accounts. The hardening
    advice it invites is population-level (fix the shared chain), never "add these
    specific accounts to Protected Users".
    """
    users_noun = "ordinary user" if total_exposed == 1 else "ordinary users"
    routes_noun = "compromise route" if route_count == 1 else "compromise routes"
    proven_clause = ""
    if proven_count > 0:
        # "them" already refers to the routes, so the noun is not repeated:
        # "2 of them validated end to end", not "2 of them routes validated".
        proven_clause = f", {proven_count:,} of them validated end to end"
    return (
        f"There is no low-risk ordinary account here: all {total_exposed:,} "
        f"{users_noun} share the same exposure. Each one reaches the same "
        f"{route_count:,} {routes_noun}{proven_clause}. Harden the shared chain "
        f"the whole population funnels through, not any single account."
    )
