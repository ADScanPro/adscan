"""In-memory per-principal Compromise-Reach memo for the credential-harvest drain.

The between-phases harvest drain re-fires per REPL poll, and each drain
recomputes attack-path reach for that drain's principals. The attack-path
compute cache (``attack_graph_service``) is keyed on the WHOLE principal SET
(plus the graph/snapshot mtimes), so a batch computed for ``{robb, eddard}``
cannot serve a later ``{eddard}`` drain — a set-granular miss, one redundant
depth-bounded DFS per principal. This memo sits in FRONT of that set-granular
cache at PER-PRINCIPAL granularity, keyed on the SAME graph/snapshot mtime epoch
the compute cache trusts (:func:`attack_graph_service.attack_paths_epoch_fingerprint`),
so once a principal's reach is computed under a graph epoch it is reused across
every later drain until the graph changes.

**Correctness (pure performance, never a stale reach).** The epoch is
``(graph_mtime, snapshot_mtime)``. Attack-step state (theoretical → success, the
``derived`` edge success inserts) is persisted INSIDE ``attack_graph.json``;
every ``save_attack_graph`` bumps the graph file mtime AND calls
``_invalidate_attack_paths_cache``. So any step-state change changes the epoch,
which resets this memo for the domain — the memo can never return a reach that a
fresh recompute would not. It only avoids RECOMPUTING an unchanged reach; it
never alters a computed value. A principal's reach is also independent of which
OTHER principals share its batch (each attack path has a single source; the
priority order over a subset preserves the first-per-source path), so a value
memoized from one drain's batch is identical to the value a later, differently
composed batch would produce.

**Scope: in-memory, per-session, by design.** It removes the observed
intra-session redundant recompute (the reported "3 computations for 2 users").
It is lost on restart, which self-heals: the next session recomputes each
principal once per graph epoch. Cross-session reuse of the persisted
``HarvestedPrincipal.compromise_reach`` is deliberately NOT done here — that
record carries no epoch stamp, so reusing it could return a stale reach and
would violate the "identical to a fresh recompute" invariant. Stamping a
fingerprint onto the persisted record is a documented deferred extension, not
required to eliminate the intra-session waste.
"""
from __future__ import annotations

from typing import Any

from adscan_internal.services.attack_graph_service import attack_paths_epoch_fingerprint
from adscan_internal.services.compromise_class import CompromiseClass

_MEMO_ATTR = "_harvest_reach_memo"


def _current_epoch(shell: Any, domain: str) -> tuple[Any, ...]:
    """Return the current graph epoch tokens for ``domain`` (never raises)."""
    try:
        return attack_paths_epoch_fingerprint(shell, domain)
    except Exception:  # noqa: BLE001 — best-effort; a bad epoch just forces recompute
        return (None, None)


def _epoch_reach_map(shell: Any, domain: str) -> dict[str, CompromiseClass | None]:
    """Return the per-principal reach map for the CURRENT graph epoch.

    The memo lives on ``shell._harvest_reach_memo`` as
    ``{domain_lower: {"epoch": epoch, "reach": {principal: CompromiseClass|None}}}``.
    When the epoch changed for a domain (any ``save_attack_graph`` since the last
    drain), the domain's reach map is reset — self-pruning, so the memo stays
    bounded to roughly one entry per harvested principal per domain.
    """
    epoch = _current_epoch(shell, domain)
    store = getattr(shell, _MEMO_ATTR, None)
    if not isinstance(store, dict):
        store = {}
        try:
            setattr(shell, _MEMO_ATTR, store)
        except Exception:  # noqa: BLE001 — a shell that rejects the attr just gets no memo
            return {}
    key = str(domain or "").strip().lower()
    entry = store.get(key)
    if not isinstance(entry, dict) or entry.get("epoch") != epoch:
        entry = {"epoch": epoch, "reach": {}}
        store[key] = entry
    reach = entry.get("reach")
    if not isinstance(reach, dict):
        reach = {}
        entry["reach"] = reach
    return reach


def split_hits_and_misses(
    shell: Any, *, domain: str, principals: list[str]
) -> tuple[dict[str, CompromiseClass | None], list[str]]:
    """Split ``principals`` (normalized keys) into memo hits and misses.

    Args:
        shell: The session shell carrying the in-memory memo.
        domain: The AD domain being classified.
        principals: Already-normalized principal keys
            (``normalize_samaccountname`` output).

    Returns:
        ``(hits, misses)`` where ``hits`` maps each already-memoized principal to
        its reused reach and ``misses`` is the list of principals needing a fresh
        compute. On any failure the memo degrades to "all misses" (recompute
        everything) — never raises.
    """
    try:
        reach = _epoch_reach_map(shell, domain)
    except Exception:  # noqa: BLE001
        return {}, list(principals)
    hits: dict[str, CompromiseClass | None] = {}
    misses: list[str] = []
    for principal in principals:
        if principal in reach:
            hits[principal] = reach[principal]
        else:
            misses.append(principal)
    return hits, misses


def store_reach(
    shell: Any, *, domain: str, reach_by_principal: dict[str, CompromiseClass | None]
) -> None:
    """Memoize freshly-computed per-principal reach under the current epoch.

    Best-effort; never raises. A later drain under the same graph epoch reuses
    these values via :func:`split_hits_and_misses`.
    """
    if not reach_by_principal:
        return
    try:
        reach = _epoch_reach_map(shell, domain)
        reach.update(reach_by_principal)
    except Exception:  # noqa: BLE001 — memoization is an optimization, never critical
        return


__all__ = [
    "split_hits_and_misses",
    "store_reach",
]
