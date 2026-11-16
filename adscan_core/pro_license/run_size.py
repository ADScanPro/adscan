"""The size of each domain a run assessed, as counts only (the licence usage register).

A partner licence reports these counts so ADscan and the partner can compare
usage figures from both sides, and so a charging unit (enabled identities,
domain controllers and certificate authorities, or computers in scope) can be
chosen later from real data instead of a band that cannot be re-cut.

Every field is a whole number or ``None``. ``None`` means the run did not
count it (the phase did not run, was skipped by the policy, or the scan
stopped before it); ``0`` means the run counted and found none. Nothing else
is ever kept: no name, host, address, distinguished name, SID or finding.
A value that is not a whole count is dropped to ``None`` and a key that is not
declared here is dropped, so neither the engine nor the licence server can
carry an identifier through these fields by mistake.

The run status reuses the engagement vocabulary of ``coverage.json``
(:mod:`adscan_core.engagement.model`): ``complete``, ``partial`` (the run ended
without completing its assessment, an operator stop included) and
``interrupted`` (the run never reached its end: a crash, a kill, or a run still
going). It is informational. Which runs are billable is decided by the retest
window (:mod:`adscan_core.pro_license.billable_engagements`), so a relaunch of a
run that did not finish is a retest of the same engagement.

Stdlib only: the licence server validates what it stores with these functions.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from adscan_core.engagement.model import RUN_COMPLETE, RUN_INTERRUPTED, RUN_PARTIAL

#: Enabled computers inside the run's asset scope, excluded by it, and not
#: confirmed either way: the three figures of the report's network-reach
#: statement (``adscan_internal.services.licence_run_size.asset_scope_partition_counts``).
#: Null when the run had no asset scope (and, like every count, when the run
#: did not count the domain's enabled computers).
ASSET_SCOPE_FIELDS: tuple[str, ...] = (
    "computers_in_asset_scope",
    "computers_excluded_by_asset_scope",
    "computers_asset_scope_unconfirmed",
)

#: Enabled computers by their own privilege tier (the engine's stamped
#: ``privilege_tier``), counted only when membership, role or the computer's own
#: attributes placed it there: inventory, never an assessment result. A computer
#: placed by a permission someone holds is counted only in ``tier_by_right``
#: (which permission is never said), one with no stamp only in
#: ``tier_unknown``. The six add up to ``computers_enabled``. All six are null
#: when the graph this run exported carries no stamp at all.
COMPUTER_TIER_FIELDS: tuple[str, ...] = (
    "computers_enabled_tier0_direct",
    "computers_enabled_tier0_escalation_capable",
    "computers_enabled_tier1",
    "computers_enabled_tier2",
    "computers_enabled_tier_by_right",
    "computers_enabled_tier_unknown",
)

#: Every count one domain may carry, in the order the register prints them.
SIZE_FIELDS: tuple[str, ...] = (
    "users_total",
    "users_enabled",
    "computers_total",
    "computers_total_servers",
    "computers_total_workstations",
    "computers_total_os_unknown",
    "computers_enabled",
    "computers_enabled_servers",
    "computers_enabled_workstations",
    "computers_enabled_os_unknown",
    *COMPUTER_TIER_FIELDS,
    "computers_resolving",
    "computers_reachable",
    "domain_controllers",
    "certificate_authorities",
    *ASSET_SCOPE_FIELDS,
)

RUN_STATUSES: tuple[str, ...] = (RUN_COMPLETE, RUN_PARTIAL, RUN_INTERRUPTED)

#: Most domains one usage line carries (one forest, one run). Keeps a signed
#: request well inside the server's request size limit.
MAX_DOMAINS_PER_RUN = 64
#: A count above this is not a directory figure: it is dropped to ``None``.
MAX_COUNT = 50_000_000


def _count(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < 0 or value > MAX_COUNT:
        return None
    return value


def normalize_domain_size(value: Any) -> dict[str, int | None] | None:
    """Every declared field of one domain's size, each a count or ``None``.

    Returns ``None`` when ``value`` is not a mapping.
    """
    if not isinstance(value, Mapping):
        return None
    return {key: _count(value.get(key)) for key in SIZE_FIELDS}


def _order_key(size: Mapping[str, int | None]) -> tuple[int, ...]:
    return tuple(-1 if size.get(key) is None else int(size[key]) for key in SIZE_FIELDS)


def normalize_domain_sizes(value: Any) -> list[dict[str, int | None]] | None:
    """The sizes of the domains of one usage line, largest first, bounded.

    The list carries no identifier, so its order is the counts' own (largest
    first); entries that are not a mapping are dropped. ``None`` when ``value``
    is not a list (the line has no sizes).
    """
    if not isinstance(value, (list, tuple)):
        return None
    sizes = [size for size in (normalize_domain_size(item) for item in value) if size is not None]
    sizes.sort(key=_order_key, reverse=True)
    return sizes[:MAX_DOMAINS_PER_RUN]


def normalize_run_status(value: Any) -> str | None:
    """``value`` when it is a run status of the engagement vocabulary, else ``None``."""
    return value if isinstance(value, str) and value in RUN_STATUSES else None


__all__ = [
    "ASSET_SCOPE_FIELDS",
    "COMPUTER_TIER_FIELDS",
    "MAX_COUNT",
    "MAX_DOMAINS_PER_RUN",
    "RUN_STATUSES",
    "SIZE_FIELDS",
    "normalize_domain_size",
    "normalize_domain_sizes",
    "normalize_run_status",
]
