"""Field-data convergence metrics for the ``scan_complete`` telemetry event.

ADscan already COMPUTES how many attack paths funnel through one object and
how many paths a single fix closes; until this module existed it never captured
any of it, so the only citable convergence figure in the market was a
competitor's. This assembles ADscan's own — as INTEGERS ONLY, which is what
makes it safe: an ``int`` passes through the telemetry sanitizer verbatim, so no
node id, principal, host or domain name can ride along.

Two denominator rules make the resulting figures publishable:

* **Findings** come from :func:`~adscan_internal.services.lite_html_report.reportable_finding_keys`
  — the same inventory the free report's finding table is built from — so a
  published "share of findings that reach nothing" equals what a customer counts
  in their own PDF.
* **Paths** come from :func:`~adscan_internal.services.report_attack_paths.compute_report_attack_paths`,
  the canonical domain-scoped projection both report tiers render. The persisted
  ``attack_paths_snapshot.json`` is deliberately NOT used: it is a point-in-time
  projection written with whatever ``scope``/``target`` the last interactive
  query happened to use (possibly a single-principal listing), which is why the
  reports refuse it too.

Both counts are emitted raw and never as a ratio — a percentage cannot be
re-aggregated across audits, two counts can.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from adscan_core import telemetry
from adscan_core.rich_output import print_exception, print_info_debug

#: Keys this module always returns, so the event shape is stable even when a
#: workspace has no graph or no findings yet.
_EMPTY: dict[str, int] = {
    "findings_total": 0,
    "findings_on_path": 0,
    "findings_dead_end": 0,
    "choke_point_nodes": 0,
    "max_paths_through_node": 0,
    "nodes_on_paths_total": 0,
    # The path denominator for the convergence figures. It is the CURATED client
    # path set, so it equals the ``paths_total`` the same event carries from the
    # counts SSOT (:mod:`adscan_internal.services.attack_path_counts`) and a
    # choke-point ratio read against either is the same ratio. It was NOT always
    # so: the event used to also carry a raw graph-walk enumeration under
    # ``paths_to_tier0`` (~14x this figure on the same workspace), and a ratio
    # read against that denominator was wrong by an order of magnitude while
    # looking authoritative. That property is retired; do not reintroduce a
    # second path denominator on this event.
    "paths_total_analyzed": 0,
    "paths_closed_by_top_3_fixes": 0,
}


def _resolve_workspace_dir(shell: Any) -> str:
    """Return the workspace root whose artifacts belong to this scan.

    A live scan writes into its execution (``.run_*``) workspace, which is what
    ``current_workspace_dir`` points at while the scan runs — so this resolves
    the same directory the report generator would read.
    """
    getter = getattr(shell, "_get_workspace_cwd", None)
    if callable(getter):
        resolved = getter()
        if isinstance(resolved, str) and resolved:
            return resolved
    workspace_dir = getattr(shell, "current_workspace_dir", None)
    return workspace_dir if isinstance(workspace_dir, str) and workspace_dir else ""


def build_field_convergence_properties(shell: Any, domain: str) -> dict[str, int]:
    """Return the convergence + dead-end integers for one domain.

    Best-effort by construction: any missing artifact or failed computation
    yields the all-zero shape rather than raising, because this is analytics
    riding on the scan-completion seam and must never break a scan.

    Args:
        shell: The active ``PentestShell`` (workspace context only — nothing is
            authenticated or mutated).
        domain: The domain whose ``scan_complete`` event is being built.

    Returns:
        A mapping of seven integers:

        * ``findings_total`` / ``findings_on_path`` / ``findings_dead_end`` —
          the finding inventory the report counts, split by whether the finding
          appears on at least one complete attack path. ``findings_dead_end`` is
          the remainder and is carried explicitly so a consumer never has to
          reconstruct it.
        * ``choke_point_nodes`` / ``max_paths_through_node`` /
          ``nodes_on_paths_total`` / ``paths_closed_by_top_3_fixes`` — the
          topological convergence shape; see
          :func:`~adscan_internal.services.attack_surface_analysis.convergence_metrics`
          for the exact definition of each (notably that
          ``paths_closed_by_top_3_fixes`` is an upper bound, not an exact union).
    """
    properties = dict(_EMPTY)
    domain_name = str(domain or "").strip()
    if not domain_name:
        return properties

    try:
        from adscan_core.reporting.technical_report import _get_technical_report_path
        from adscan_internal.services.affected_assets import count_findings_on_paths
        from adscan_internal.services.attack_surface_analysis import (
            compute_attack_surface_analysis,
            convergence_metrics,
        )
        from adscan_internal.services.lite_html_report import reportable_finding_keys
        from adscan_internal.services.report_attack_paths import (
            compute_report_attack_paths,
        )
        from adscan_internal.workspaces import read_json_file

        workspace_dir = _resolve_workspace_dir(shell)
        if not workspace_dir:
            return properties

        # The report's own paths — a warm in-process cache from the scan serves
        # this, so it is not a second expensive traversal.
        paths = compute_report_attack_paths(workspace_dir, domain_name)

        analysis = compute_attack_surface_analysis(paths, domain=domain_name)
        properties.update(convergence_metrics(analysis))

        report_path = Path(_get_technical_report_path(shell))
        technical_report = (
            read_json_file(str(report_path)) if report_path.exists() else None
        )
        domains = (
            technical_report.get("domains")
            if isinstance(technical_report, dict)
            else None
        )
        # Scope the denominator to THIS domain: ``scan_complete`` is emitted per
        # domain, so a multi-domain workspace must not report the whole
        # workspace's findings against one domain's paths.
        domain_entry = domains.get(domain_name) if isinstance(domains, dict) else None
        finding_keys = (
            reportable_finding_keys({domain_name: domain_entry})
            if isinstance(domain_entry, dict)
            else []
        )

        findings_on_path, findings_total = count_findings_on_paths(finding_keys, paths)
        properties["findings_total"] = findings_total
        properties["findings_on_path"] = findings_on_path
        properties["findings_dead_end"] = max(0, findings_total - findings_on_path)
    except Exception as exc:  # noqa: BLE001 - analytics must never break the scan
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[field-data] convergence metrics unavailable: {exc}")
        return dict(_EMPTY)

    return properties
