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
    clean = [path for path in paths if isinstance(path, dict)]
    for path in clean:
        stamp_adcs_finding_views(path)
    return clean


def compute_report_attack_paths_display(
    workspace_dir: str,
    domain: str,
    *,
    max_depth: int = REPORT_ATTACK_PATH_MAX_DEPTH,
    no_cache: bool = False,
) -> list[dict[str, Any]]:
    """Return the FOLDED display projection of the canonical report attack paths.

    Axis-D story-level fold (COUNT != DISPLAY): the SAME canonical finding set
    :func:`compute_report_attack_paths` returns — which every COUNT / KPI / score
    reads and which stays byte-identical — is collapsed for RENDERING via
    :func:`attack_graph_core.fold_origin_stories`, so N routes that reach the same
    terminal by the same edge sequence from N different origin principals render as
    ONE row carrying the origins in ``origin_alternatives`` (+ ``origin_route_count``).

    This is the SHARED SSOT the LITE report, the PRO report and the web CTEM all
    consume for their RENDERED rows, so the three surfaces fold identically. It
    MUST NEVER feed a count: the canonical unfolded set (``compute_report_attack_paths``)
    is the authoritative count source (guardrail: exposure score / the Tier-2 →
    Tier-0 headline / ``path_axis`` all read the canonical set). Best-effort:
    returns ``[]`` on any failure, mirroring the canonical function.
    """
    from adscan_internal.services import attack_graph_core

    canonical = compute_report_attack_paths(
        workspace_dir, domain, max_depth=max_depth, no_cache=no_cache
    )
    if not canonical:
        return []
    try:
        return attack_graph_core.fold_origin_stories([dict(p) for p in canonical])
    except Exception as exc:  # noqa: BLE001 - a display fold never breaks the report
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return [dict(p) for p in canonical]


def build_origin_footholds_summary(
    record: dict[str, Any], *, report_domain: str, max_named: int = 6
) -> str | None:
    """Return the human "reachable from N footholds" line for an origin-folded row.

    ``None`` when the row is not an origin fold (``origin_route_count <= 1``), so a
    non-folded card renders nothing extra. When it is a fold, names each distinct
    origin principal through the humanization SSOT
    (:func:`~adscan_internal.services.well_known_principals.humanize_principal_for_prose`)
    so a client never sees a raw / shouting / ``@WELLKNOWN`` label — the SAME
    humanizer every other client-facing principal label uses. Long lists are
    truncated to ``max_named`` named principals plus an "and N more" tail so the
    card stays readable on a dense domain.
    """
    try:
        count = int(record.get("origin_route_count") or 1)
    except (TypeError, ValueError):
        count = 1
    origins = record.get("origin_alternatives")
    if count <= 1 or not isinstance(origins, list) or len(origins) <= 1:
        return None

    from adscan_internal.services.well_known_principals import (
        humanize_principal_for_prose,
    )

    names: list[str] = []
    seen: set[str] = set()
    for origin in origins:
        if not isinstance(origin, dict):
            continue
        raw = str(origin.get("source") or origin.get("origin_node") or "").strip()
        if not raw:
            continue
        try:
            display = humanize_principal_for_prose(
                label=raw, report_domain=str(report_domain or "")
            )
        except Exception:  # noqa: BLE001 - a label never breaks the render
            display = raw
        key = display.strip().lower()
        if key in seen:
            continue
        seen.add(key)
        names.append(display)

    distinct = len(names)
    if distinct <= 1:
        return None
    if distinct <= max_named:
        named = ", ".join(names)
        return f"Reachable from {distinct} footholds: {named}."
    shown = ", ".join(names[:max_named])
    remaining = distinct - max_named
    return f"Reachable from {distinct} footholds: {shown}, and {remaining} more."


def stamp_adcs_finding_views(path: Any) -> None:
    """Derive + stamp the ADCS three-state and ESC8-transport VIEWS onto a path.

    Mutates each ADCS step's ``details`` in place, adding the render-ready views
    both the PDF report and the paid web CTEM read from the SAME SSOT
    (:mod:`adscan_core.reporting.adcs_finding_state` /
    :mod:`adscan_core.reporting.adcs_esc8_transport`), so the two surfaces cannot
    word the same ADCS state or ESC8 remediation differently. Best-effort: never
    raises, so a report renders even if a step dict is malformed.

    * ``adcs_finding_state_view`` — the three honest states (validated / data gap /
      hygiene). Derived from the step status; ``hygiene`` requires a collector
      ``is_orphaned_ca`` signal on the step details (absent today, wired when the
      collector emits it — validated + data-gap render now).
    * ``esc8_transport_view`` — the ESC8 observed transport + EPA-conditional
      remediation, present only when the ESC8 relay stamped ``esc8_transport``.
    """

    from adscan_core.reporting.adcs_esc8_transport import (
        ESC8_TRANSPORT_KEY,
        esc8_transport_view,
    )
    from adscan_core.reporting.adcs_finding_state import (
        ADCS_FINDING_STATE_KEY,
        adcs_finding_state_view,
        build_adcs_finding_state,
        classify_adcs_edge_state,
        is_adcs_esc_relation,
    )

    if not isinstance(path, dict):
        return
    steps = path.get("steps")
    if not isinstance(steps, list):
        return
    for step in steps:
        if not isinstance(step, dict):
            continue
        details = step.get("details")
        if not isinstance(details, dict):
            continue
        if not is_adcs_esc_relation(step.get("action")):
            continue

        # ESC8 observed transport + EPA-conditional remediation.
        transport_block = details.get(ESC8_TRANSPORT_KEY)
        if isinstance(transport_block, dict):
            details["esc8_transport_view"] = esc8_transport_view(transport_block)

        # Three honest states. Prefer a state a previous stage already stamped;
        # otherwise derive from the step status + a collector orphaned-CA signal.
        state_block = details.get(ADCS_FINDING_STATE_KEY)
        if not isinstance(state_block, dict) or not state_block.get("state"):
            state_name = classify_adcs_edge_state(
                status=step.get("status"),
                is_orphaned_ca=bool(details.get("is_orphaned_ca")),
            )
            if state_name:
                state_block = build_adcs_finding_state(
                    state=state_name,
                    ca_host=str(
                        details.get("target_dnshostname")
                        or details.get("ca_host")
                        or details.get("to")
                        or ""
                    ),
                )
                details[ADCS_FINDING_STATE_KEY] = state_block
        if isinstance(state_block, dict) and state_block.get("state"):
            details["adcs_finding_state_view"] = adcs_finding_state_view(state_block)


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
