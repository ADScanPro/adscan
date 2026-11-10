"""The "Start here" remediation per scope, read verbatim from what the scan stamped.

The engine stamps the "Start here" remediation model twice:

* per domain, at ``domains[<d>]["chokepoint_cardinality"]["remediation_start_here"]``
  (``chokepoint_cardinality.stamp_chokepoint_cardinality_for_domain``);
* once for the whole workspace, at the top-level :data:`WORKSPACE_REMEDIATION_KEY`
  (``scan_headline_blocks.stamp_workspace_remediation``), through the same
  composition the Security Assessment Report uses for its own "Start here"
  section: every domain's listing, concatenated, ranked once.

This module is the read side both surfaces share. It never ranks, counts, sums or
re-words anything: a scope either carries the block the engine stamped, copied
verbatim, or it says why it does not. In particular it never adds domain rows
together into a workspace ranking, because the SAR does not do that either (it
ranks the union of the paths, which reorders ties and re-derives every
percentage), and a sum would be a third ranking that neither the report nor the
engine produced.

Dependency-light by contract (stdlib only), so the web backend imports it in the
appliance, where ``adscan_internal`` is absent, and its tests run anywhere.
"""

from __future__ import annotations

import copy
from typing import Any, Mapping, Sequence

#: Top-level ``technical_report.json`` key of the workspace-wide block. Like
#: ``attack_fanout_rollup`` it is workspace-scoped, not a domain.
WORKSPACE_REMEDIATION_KEY = "workspace_remediation"

#: Version of the workspace block's shape.
WORKSPACE_REMEDIATION_SCHEMA_VERSION = 1

#: The derivation marker the per-domain choke block carries (see
#: ``chokepoint_cardinality.PATH_DERIVED_BLOCKS_KEY``, which imports this value so
#: the writer and this reader cannot drift).
PATH_DERIVED_BLOCKS_KEY = "path_derived_blocks"

#: The scope id of the all-domains view.
WORKSPACE_SCOPE = "workspace"

#: Why a scope carries no "Start here" model. Each is a different statement to a
#: client, so they are kept apart rather than collapsed into "empty":
#:
#: * not computed: the scan predates the block, or its derivation never ran, so
#:   nothing can be said about this scope's priorities;
#: * no attack paths: the derivation ran and found no attack path to rank;
#: * nothing to rank: there were attack paths, none of them carrying a fix the
#:   client can make (closed by configuration, or a data gap).
REASON_NOT_COMPUTED = "not_computed"
REASON_NO_ATTACK_PATHS = "no_attack_paths"
REASON_NOTHING_TO_RANK = "nothing_to_rank"


def start_here_from_block(block: Any) -> dict[str, Any] | None:
    """Return the stamped "Start here" lead of a per-domain choke block, as-is.

    ``None`` when the block is absent, predates the lead, or carries no rows.
    """
    if not isinstance(block, Mapping):
        return None
    lead = block.get("remediation_start_here")
    if not isinstance(lead, dict):
        return None
    rows = lead.get("rows")
    if not isinstance(rows, list) or not rows:
        return None
    return lead


def user_exposure_from_block(block: Any) -> dict[str, Any] | None:
    """Return the stamped "Most exposed accounts" ranking of a block, as-is.

    ``None`` when absent or when it names no account.
    """
    if not isinstance(block, Mapping):
        return None
    exposure = block.get("user_exposure")
    if isinstance(exposure, dict) and exposure.get("top_users"):
        return exposure
    return None


def _considered(value: Any) -> int:
    try:
        return max(int(value or 0), 0)
    except (TypeError, ValueError):
        return 0


def _view(
    scope: str,
    domains: list[str],
    *,
    start_here: dict[str, Any] | None,
    user_exposure: dict[str, Any] | None,
    reason: str,
) -> dict[str, Any]:
    present = start_here is not None
    return {
        "scope": scope,
        "domains": list(domains),
        "present": present,
        "reason": "" if present else reason,
        # Deep copies: the caller serializes these, and a mutation on the way out
        # must never reach the block a later request reads.
        "remediation_start_here": copy.deepcopy(start_here),
        "user_exposure": copy.deepcopy(user_exposure),
    }


def domain_remediation_view(domain: str, block: Any) -> dict[str, Any]:
    """Return one domain's scope view from its persisted choke block."""
    start_here = start_here_from_block(block)
    reason = REASON_NOT_COMPUTED
    if start_here is None and isinstance(block, Mapping):
        marker = block.get(PATH_DERIVED_BLOCKS_KEY)
        if isinstance(marker, Mapping):
            reason = (
                REASON_NOTHING_TO_RANK
                if _considered(marker.get("attack_paths_considered"))
                else REASON_NO_ATTACK_PATHS
            )
    return _view(
        domain,
        [domain],
        start_here=start_here,
        user_exposure=user_exposure_from_block(block),
        reason=reason,
    )


def _workspace_view_from_block(block: Mapping[str, Any]) -> dict[str, Any]:
    domains = [str(d) for d in block.get("domains") or [] if isinstance(d, str)]
    start_here = start_here_from_block(block)
    reason = (
        REASON_NOTHING_TO_RANK
        if _considered(block.get("attack_paths_considered"))
        else REASON_NO_ATTACK_PATHS
    )
    return _view(
        WORKSPACE_SCOPE,
        domains,
        start_here=start_here,
        user_exposure=user_exposure_from_block(block),
        reason=reason,
    )


def build_remediation_scopes(
    domain_blocks: Sequence[tuple[str, Any]],
    *,
    workspace_block: Any,
) -> dict[str, Any]:
    """Return ``{"workspace": view, "domains": [view, ...]}`` for the web route.

    Args:
        domain_blocks: ``(domain, chokepoint_cardinality block or None)`` pairs,
            in the order the page lists the domains.
        workspace_block: The top-level :data:`WORKSPACE_REMEDIATION_KEY` block, or
            ``None`` when the scan predates it.

    The workspace view is the stamped workspace block when there is one. Without
    it, a workspace whose ONLY stamped domain is one domain still gets that
    domain's model as its workspace view: over one domain the SAR's composition
    and the per-domain stamp are the same two calls on the same paths. Over two
    or more stamped domains it reports "not computed", never a sum.
    """
    domain_views = [domain_remediation_view(name, block) for name, block in domain_blocks]

    if isinstance(workspace_block, Mapping) and "remediation_start_here" in workspace_block:
        workspace = _workspace_view_from_block(workspace_block)
    else:
        stamped = [
            (name, block)
            for name, block in domain_blocks
            if isinstance(block, Mapping) and isinstance(block.get(PATH_DERIVED_BLOCKS_KEY), Mapping)
        ]
        if len(stamped) == 1:
            name, block = stamped[0]
            single = domain_remediation_view(name, block)
            workspace = dict(single, scope=WORKSPACE_SCOPE)
        else:
            workspace = _view(
                WORKSPACE_SCOPE,
                [],
                start_here=None,
                user_exposure=None,
                reason=REASON_NOT_COMPUTED,
            )

    return {"workspace": workspace, "domains": domain_views}


def start_here_top_actions(scopes: Any, *, limit: int = 3) -> list[dict[str, Any]]:
    """Return the leading "Start here" rows of the workspace scope, as stamped.

    Read from the SAME workspace view the Remediation page serves
    (:func:`build_remediation_scopes`), in the stamped order, never ranked
    again, each copied as ``{label, line, proven}``. The executive progress
    report lists these as the open risks to fix first. Empty when the workspace
    scope carries no stamped ranking.
    """
    if not isinstance(scopes, Mapping):
        return []
    workspace = scopes.get("workspace")
    if not isinstance(workspace, Mapping) or not workspace.get("present"):
        return []
    lead = start_here_from_block(workspace)
    if lead is None:
        return []
    actions: list[dict[str, Any]] = []
    for row in lead["rows"]:
        if len(actions) >= max(limit, 0):
            break
        if not isinstance(row, Mapping) or not row.get("label"):
            continue
        actions.append(
            {
                "label": str(row.get("label") or ""),
                "line": str(row.get("item_line") or ""),
                "proven": bool(row.get("proven")),
            }
        )
    return actions


def start_here_top_action(scopes: Any) -> dict[str, Any] | None:
    """Return the first "Start here" row of the workspace scope, as stamped.

    The assessment notifications quote this one action: the first entry of
    :func:`start_here_top_actions`. ``None`` when the workspace scope carries no
    stamped ranking (or its first row has no label).
    """
    if not isinstance(scopes, Mapping):
        return None
    workspace = scopes.get("workspace")
    if not isinstance(workspace, Mapping) or not workspace.get("present"):
        return None
    lead = start_here_from_block(workspace)
    if lead is None:
        return None
    first = lead["rows"][0]
    if not isinstance(first, Mapping) or not first.get("label"):
        return None
    return start_here_top_actions(scopes, limit=1)[0]


__all__ = [
    "PATH_DERIVED_BLOCKS_KEY",
    "REASON_NOTHING_TO_RANK",
    "REASON_NOT_COMPUTED",
    "REASON_NO_ATTACK_PATHS",
    "WORKSPACE_REMEDIATION_KEY",
    "WORKSPACE_REMEDIATION_SCHEMA_VERSION",
    "WORKSPACE_SCOPE",
    "build_remediation_scopes",
    "domain_remediation_view",
    "start_here_from_block",
    "start_here_top_action",
    "start_here_top_actions",
    "user_exposure_from_block",
]
