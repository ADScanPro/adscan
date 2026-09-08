"""Canonical attack-path derivation for the client reports (SHARED, LITE-safe).

Both client reports — the PRO Client Deliverable Kit and the LITE exposure
report — must show the SAME attack-path picture, and it must be the picture of
what the environment EXPOSES, not whatever the operator last happened to query.

The trap this module closes: the on-disk interactive path snapshot is NOT a
canonical path set. It is a point-in-time projection persisted with whatever
``scope`` / ``target`` / ``target_mode`` the LAST query used — including an
interactive listing scoped to a single principal someone was investigating. A
report that reads the snapshot therefore renders whatever fragment that query
produced (e.g. two chains that both begin mid-way through the real path, with no
blast radius), which is not the exposure of the domain.

So the reports derive their attack paths ONCE, here, from the reconciled
on-disk attack graph via the same production engine the CLI uses, at the
canonical domain listing scope (``target="highvalue"``, ``target_mode="object"``,
``keep_longest=True``). This is the four-layer report doctrine (see
``CLAUDE.md`` § Dual-tier reporting): the derivation of report figures is a
SHARED layer, and it lives in ``adscan_internal/services/`` so LITE can reach it
(``pro/`` is stripped from the LITE image).

This module is the SSOT both ``pro/services/report_service.py`` and
``services/lite_html_report.py`` call. Neither reads the interactive snapshot.
"""

from __future__ import annotations

import os
from typing import Any

from adscan_core import telemetry
from adscan_core.reporting.attack_path_memory_gate import (
    _AttackPathMemoryBudgetExceeded,
)
from adscan_core.reporting.domain_scope import has_collection_evidence
from adscan_core.rich_output import (
    mark_sensitive,
    print_exception,
    print_info_debug,
)

#: The canonical listing depth the CLI, the snapshot re-materializer, and the
#: PRO report all use, so every surface computes the same holistic projection.
REPORT_ATTACK_PATH_MAX_DEPTH = 10


class _ReportShell:
    """The minimal shell surface ``attack_graph_service`` needs to locate a graph.

    The compute path only reads ``current_workspace_dir`` / ``domains_dir`` and
    ``_get_workspace_cwd`` to resolve the on-disk ``attack_graph.json``; it never
    authenticates or mutates. A throwaway object keeps the report generators from
    having to own a full ``PentestShell``.

    ``domains_data`` is an empty dict, not absent: an annotate/decorate stage in
    ``compute_display_paths_for_domain`` (affected-user metadata, owned-user
    resolution) reads ``shell.domains_data`` and an unguarded reader raises
    ``AttributeError`` when the attribute is missing (observed on Ctrl+C report
    generation). An empty dict is the correct "no live credential state" for a
    report-only shell — every reader treats a missing-domain lookup as empty, so
    ``{}`` yields the same result while never raising.
    """

    def __init__(self, workspace_dir: str) -> None:
        self.current_workspace_dir = str(workspace_dir)
        self.domains_dir = "domains"
        self.domains_data: dict[str, Any] = {}

    def _get_workspace_cwd(self) -> str:
        return self.current_workspace_dir


def compute_report_attack_paths(
    workspace_dir: str,
    domain: str,
    *,
    max_depth: int = REPORT_ATTACK_PATH_MAX_DEPTH,
    no_cache: bool = False,
) -> list[dict[str, Any]]:
    """Return the canonical domain-scoped attack-path summaries for a report.

    A pure projection of the reconciled ``attack_graph.json`` at the canonical
    domain listing scope. Best-effort: returns ``[]`` (never raises) when the
    graph is missing or the compute fails, so a report renders with an empty
    attack-path section rather than crashing.

    Args:
        workspace_dir: Workspace root (container path). The graph is resolved
            under ``<workspace_dir>/domains/<domain>/attack_graph.json``.
        domain: The domain to compute paths for.
        max_depth: Traversal depth cap; the canonical listing default.
        no_cache: Force a read of the reconciled on-disk graph, bypassing any
            in-process attack-path cache. The reports leave this ``False`` — a
            warm cache from the scan is the same canonical projection — but a
            caller that must guarantee freshness (e.g. right after execution
            reconciliation) can set it.

    Returns:
        The engine's display-friendly path summaries (``source`` / ``target`` /
        ``status`` / ``compromise_class`` / ``nodes`` / ``relations`` / ``steps``
        / ``meta`` / ``path_state`` …), the same shape the CLI listing and the
        persisted snapshot carry. Never ``None``.
    """
    from adscan_internal.services import attack_graph_service

    shell = _ReportShell(workspace_dir)
    try:
        graph_path = attack_graph_service._graph_path(shell, domain)  # noqa: SLF001
        if not os.path.exists(graph_path):
            print_info_debug(
                "[report] attack graph missing for "
                f"{mark_sensitive(domain, 'domain')}: "
                f"{mark_sensitive(graph_path, 'path')}"
            )
            return []
    except Exception:  # noqa: BLE001 - a resolution error just means "no graph"
        pass

    try:
        paths = attack_graph_service.compute_display_paths_for_domain(
            shell,
            domain,
            max_depth=max_depth,
            target="highvalue",
            target_mode="object",
            display_friendly=True,
            # Holistic keep_longest domain listing — all distinct entry points,
            # broadest-reach + PROVEN paths preserved via the affected-widening
            # rule — identical to the CLI default and the snapshot
            # re-materializer, so every surface agrees.
            keep_longest=True,
            no_cache=no_cache,
        )
    except _AttackPathMemoryBudgetExceeded as exc:
        # A DELIBERATE, clean coverage-bounded stop — NOT an error. Discovery hit
        # the memory ceiling and stopped cleanly before it could be SIGKILLed. The
        # SERVICE-layer ``compute_display_paths_for_domain`` now recovers this at
        # the source, so this catch is a belt-and-suspenders backstop for a future
        # in which the service seam changes. Route it through the ONE shared
        # recovery helper (operator line + honest coverage declaration + bounded
        # per-terminal fallback), NEVER a hand-duplicated copy of that logic and
        # NEVER a traceback / "contact support" line, per CLAUDE.md § "A bounded
        # computation is a data gap — declare it, never a scary crash". The helper
        # is best-effort and never raises; its ``recompute_bounded`` re-runs the
        # domain compute with ``force_perterminal=True`` so the deliverable carries
        # the real per-terminal + floor route set instead of an empty one.
        def _recompute_bounded_report() -> list[dict[str, Any]]:
            return attack_graph_service.compute_display_paths_for_domain(
                shell,
                domain,
                max_depth=max_depth,
                target="highvalue",
                target_mode="object",
                display_friendly=True,
                keep_longest=True,
                no_cache=no_cache,
                force_perterminal=True,
            )

        paths = attack_graph_service._recover_from_memory_abort(  # noqa: SLF001
            shell, domain, exc, recompute_bounded=_recompute_bounded_report
        )
        if not isinstance(paths, list):
            return []
        return [path for path in paths if isinstance(path, dict)]
    except Exception as exc:  # noqa: BLE001 - a report never crashes on paths
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            "[report] attack path computation failed for "
            f"{mark_sensitive(domain, 'domain')}: {exc}"
        )
        return []

    if not isinstance(paths, list):
        return []
    return [path for path in paths if isinstance(path, dict)]


def resolve_domain_assessment(
    workspace_dir: str,
    domain: str,
    report_entry: Any = None,
) -> tuple[bool, str]:
    """Return ``(enumerated, basis)`` for one domain in a workspace.

    Answers the question the report headline depends on: did this engagement
    actually enumerate the domain, or does the name only appear because a trust
    on another domain pointed at it? Both report pipelines call this so the two
    tiers cannot disagree about what "assessed" means.

    The decisive evidence is the collector's own output — a domain with an
    ``attack_graph.json`` under ``<workspace>/domains/<domain>/`` is a domain the
    collector enumerated. That fact holds even for a perfectly clean domain,
    which is why it is checked before the report evidence: inferring from "no
    findings" alone would report a clean assessed domain as untested.

    Args:
        workspace_dir: Workspace root (container path).
        domain: The domain to classify.
        report_entry: Optional per-domain block from ``technical_report.json`` /
            the renderer's ``report_data``, used as the secondary signal.

    Returns:
        ``(True, "attack_graph")`` when the collector produced a graph,
        ``(True, "report_evidence")`` when the report carries collected data for
        it, else ``(False, "no_collection_evidence")``.
    """
    from adscan_internal.services import attack_graph_service

    try:
        graph_path = attack_graph_service._graph_path(  # noqa: SLF001
            _ReportShell(workspace_dir), domain
        )
        if graph_path and os.path.exists(graph_path):
            return True, "attack_graph"
    except Exception:  # noqa: BLE001 - a resolution error just means "no graph"
        pass

    if has_collection_evidence(report_entry):
        return True, "report_evidence"
    return False, "no_collection_evidence"
