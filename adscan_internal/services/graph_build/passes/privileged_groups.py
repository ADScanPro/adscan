"""Privileged-group escalation: one ``Group -> Domain`` (or domain controller) edge per
Backup Operators / DnsAdmins / Print Operators group.

The rule itself lives in :mod:`adscan_internal.services.privileged_group_escalation`
(its single emitter, shared with the load-time backfill of
``attack_graph_core.load_attack_graph``); this pass is its place in the build.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from adscan_internal.services.privileged_group_escalation import (
    PRIVILEGED_GROUP_ESCALATION_RELATIONS,
    derive_privileged_group_escalation_edges,
)


def derive_privileged_group_edges(
    graph: dict[str, Any], *, domain_data: Mapping[str, Any] | None = None
) -> int:
    """Derive the privileged-group escalation edges of ``graph``.

    ``domain_data`` pins a domain-controller-targeted escalation to the
    domain's recorded primary controller, exactly as the persist does.
    """
    entry = dict(domain_data) if isinstance(domain_data, Mapping) else None
    return derive_privileged_group_escalation_edges(graph, domain_data=entry)


__all__ = ("PRIVILEGED_GROUP_ESCALATION_RELATIONS", "derive_privileged_group_edges")
