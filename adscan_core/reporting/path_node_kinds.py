"""Per-node object kinds for an attack-path record (dependency-light, stdlib only).

An attack-path record carries node LABELS only. The kind of each node (User,
Group, Computer, Domain, ...) is known to the engine and is already stamped on
every step as ``details.source_kind`` / ``details.target_kind`` from the graph.
Consumers that draw a node chip (the live web attack graph) must use these real
kinds instead of guessing from the label, which mislabels sAMAccountNames with a
dot as domains and well-known groups as users.

Both the CLI snapshot writer and the web backend call
:func:`derive_path_node_kinds`, so the two cannot disagree.
"""

from __future__ import annotations

from typing import Any, Sequence

UNKNOWN_KIND = ""


def _clean_kind(value: Any) -> str:
    return value.strip() if isinstance(value, str) and value.strip() else UNKNOWN_KIND


def derive_path_node_kinds(
    nodes: Sequence[Any] | None, steps: Sequence[Any] | None
) -> list[str]:
    """Return one kind per node (``""`` when the graph did not say).

    Step ``i`` joins node ``i`` to node ``i + 1``, so node ``i`` takes the
    ``source_kind`` of step ``i`` and the last node the ``target_kind`` of the
    last step. A node already resolved is never overwritten by a later step.
    """
    count = len(nodes or [])
    kinds = [UNKNOWN_KIND] * count
    for idx, step in enumerate(steps or []):
        if not isinstance(step, dict) or idx >= count:
            continue
        details = step.get("details")
        if not isinstance(details, dict):
            continue
        source_kind = _clean_kind(details.get("source_kind"))
        if source_kind and not kinds[idx]:
            kinds[idx] = source_kind
        target_kind = _clean_kind(details.get("target_kind"))
        if target_kind and idx + 1 < count and not kinds[idx + 1]:
            kinds[idx + 1] = target_kind
    return kinds
