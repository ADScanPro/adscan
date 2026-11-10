"""Can this principal sign in at all? One answer for every actor selection.

An attack step needs an actor, and an actor that the domain will refuse is not
an actor: picking it only costs the account a failed sign-in and the step its
chance. A GOAD run picked the disabled ``vagrant`` account as the actor of its
ESC1 and ESC4 steps and drew ``KDC_ERR_CLIENT_REVOKED`` six times, because the
candidate ranking knew the account's privilege but not that it was disabled.

A principal is unusable when ADscan has either piece of evidence:

* the attack graph marks it outside the active population (disabled, through the
  ``userAccountControl`` ACCOUNTDISABLE bit), the same field the enabled-user
  inventory reads (``graph_queries.inventories``);
* the sign-in lockout guard heard the domain say so in this session
  (``KDC_ERR_CLIENT_REVOKED``, ``STATUS_ACCOUNT_LOCKED_OUT``, an LDAP ``data
  775`` / ``533`` ...), see ``adscan_core.auth_attempt_guard.unusable_reason``.

A missing ``enabled`` property is NOT evidence: an old or partial graph must
never make a working credential disappear. The graph index is rebuilt only when
the memoized graph object changes, so a lookup is a dict probe.
"""

from __future__ import annotations

from typing import Any, Iterable

from adscan_core import telemetry
from adscan_core.rich_output import print_exception
from adscan_internal.services.graph_queries.filters import is_active, is_live

__all__ = ["principal_unusable_reason", "partition_usable_principals"]

_INDEX_CACHE: dict[str, tuple[int, dict[tuple[str, str], str]]] = {}


def _normalize(name: str) -> str:
    value = str(name or "").strip()
    if "\\" in value:
        value = value.split("\\", 1)[1]
    if "@" in value:
        value = value.split("@", 1)[0]
    return value.strip().lower()


def _graph_disabled_index(shell: Any, domain: str) -> dict[tuple[str, str], str]:
    """``{(domain, samaccountname): reason}`` for every principal the graph marks disabled."""
    try:
        from adscan_internal.services.attack_graph_service import (  # noqa: PLC0415
            _load_attack_graph_for_paths,
        )

        graph = _load_attack_graph_for_paths(shell, domain)
    except Exception as exc:  # noqa: BLE001 - no graph means no evidence
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return {}
    if not isinstance(graph, dict):
        return {}
    cache_key = str(domain or "").strip().lower()
    cached = _INDEX_CACHE.get(cache_key)
    if cached is not None and cached[0] == id(graph):
        return cached[1]
    index: dict[tuple[str, str], str] = {}
    nodes = graph.get("nodes")
    iterable = nodes.values() if isinstance(nodes, dict) else (nodes or [])
    for node in iterable:
        if not isinstance(node, dict):
            continue
        if str(node.get("kind") or "").strip().lower() not in ("user", "computer"):
            continue
        # The active-population SSOT: live AND enabled. A missing enabled flag
        # counts as enabled (no evidence), and a deleted object cannot sign in
        # either, so both disabled and tombstoned accounts are unusable.
        if is_active(node):
            continue
        props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
        reason = "disabled" if is_live(node) else "deleted"
        sam = _normalize(props.get("samaccountname") or node.get("label") or "")
        node_domain = str(props.get("domain") or "").strip().lower()
        if not node_domain:
            label = str(node.get("label") or "")
            node_domain = label.split("@", 1)[1].strip().lower() if "@" in label else ""
        if sam:
            index[(node_domain, sam)] = reason
    _INDEX_CACHE[cache_key] = (id(graph), index)
    return index


def principal_unusable_reason(shell: Any, domain: str, username: str) -> str:
    """Why ``username`` of ``domain`` cannot sign in, or ``""`` when nothing says so."""
    sam = _normalize(username)
    if not sam:
        return ""
    try:
        from adscan_core.auth_attempt_guard import unusable_reason  # noqa: PLC0415

        observed = unusable_reason(domain, sam)
    except Exception as exc:  # noqa: BLE001 - the ledger is best-effort here
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        observed = ""
    if observed:
        return f"the domain reported it {observed} during this scan"
    index = _graph_disabled_index(shell, domain)
    domain_key = str(domain or "").strip().lower()
    reason = index.get((domain_key, sam)) or index.get(("", sam))
    if reason:
        return f"the directory marks it {reason}"
    return ""


def partition_usable_principals(
    shell: Any, domain: str, candidates: Iterable[str]
) -> tuple[list[str], dict[str, str]]:
    """Split ``candidates`` into the usable ones (order kept) and the rest with reasons."""
    usable: list[str] = []
    dropped: dict[str, str] = {}
    for candidate in candidates:
        reason = principal_unusable_reason(shell, domain, candidate)
        if reason:
            dropped[candidate] = reason
        else:
            usable.append(candidate)
    return usable, dropped
