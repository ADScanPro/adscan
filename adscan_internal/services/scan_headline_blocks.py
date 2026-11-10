"""Stamp a domain's headline report blocks from the scan itself (tier-shared SSOT).

Three blocks the deliverable AND the paid web CTEM read straight out of
``technical_report.json`` used to be written only by the report flows:

* ``exposure_score`` (the AD Exposure Score),
* ``exposure_kpis`` (the path-axis + user-axis blast radius, the headline KPI),
* ``chokepoint_cardinality`` (choke points, the "Start Here" remediation lead and
  "Most Exposed Accounts").

A scan that finished without rendering a report therefore carried none of them,
and every SSOT-first web route silently degraded to a weaker legacy derivation.
A figure the scan already computes must not depend on a rendering step, so the
scan's own finalization seam calls :func:`stamp_headline_blocks_for_domain` with
the canonical domain listing it has just recomputed from the reconciled graph.

Each block goes through the SAME shared function the report flows use
(``compute_exposure_score`` + ``record_exposure_score``,
``stamp_exposure_kpis_for_domain``, ``stamp_chokepoint_cardinality_for_domain``),
fed the same inputs the PRO report seam builds (reachability over the base graph
from the enabled low-privilege start set, the reachable value-terminal ids, the
coverage-derived ``bounded`` caveat), so a scan-end block and a later report
block cannot be derived differently. Every block is OVERWRITTEN: a block a
previous run left in ``technical_report.json`` is stale by definition.

:func:`stamp_scan_end_report_blocks` closes the rest of that class: the
``assessment`` verdict, the structured affected assets and the final ADscan
severity they imply, ``compliance`` for the frameworks the scan selected, and
the workspace ``attack_fanout_rollup``, each through the function the report
flows call, so the web reads the same values with or without a report.

LITE-safe: depends only on ``services`` / ``adscan_core``, never
``adscan_internal.pro`` (the PRO compliance engine is reached through the
optional-PRO seam). Best-effort throughout: each block is guarded on its own,
so a failure omits that block and never breaks the scan.
"""

from __future__ import annotations

import copy
from types import SimpleNamespace
from typing import Any, Mapping, Sequence

from adscan_core import telemetry
from adscan_core.rich_output import print_exception


def stamp_headline_blocks_for_domain(
    workspace_dir: str,
    domain: str,
    *,
    summaries: Sequence[Mapping[str, Any]],
    engine_marker_bounded: bool = False,
) -> None:
    """Compute and persist the three headline blocks for one domain.

    Args:
        workspace_dir: The workspace root the scan writes to (the ``.run_*``
            execution workspace during a live scan; promoted with the rest of
            ``technical_report.json`` at scan end).
        domain: The domain the blocks belong to.
        summaries: The CANONICAL domain listing (the set the report, the snapshot
            and the web render). An empty list is a measured answer for an
            assessed domain and is stamped as such, never skipped.
        engine_marker_bounded: The engine-marker fallback for the ``bounded``
            caveat, used only when no coverage block is persisted.
    """
    # Deep copies: the not-executed annotation below writes step notes in place,
    # and the caller's listing is the one it persists for the web.
    records = [copy.deepcopy(dict(r)) for r in summaries if isinstance(r, Mapping)]
    # A route's stopping cause is the first step that stopped it, and that is
    # only known once the scan policy's excluded steps carry their note. The
    # reports annotate before they stamp; stamping here on the raw listing
    # counted a route whose FIRST step the policy excludes as declined by the
    # operator because a later, shared step carried the operator's decision, so
    # the console summary and the report disagreed on one scan (3 declined and
    # 4 excluded against 1 and 6).
    from adscan_internal.services.report_attack_paths import (  # noqa: PLC0415
        annotate_report_policy_exclusions,
    )

    annotate_report_policy_exclusions(str(workspace_dir), domain, records)
    shell = SimpleNamespace(
        current_workspace_dir=str(workspace_dir), domains_dir="domains"
    )

    computed_at = _stamp_exposure_score(shell, domain, records)

    reachability, norm_graph, value_terminal_ids = _resolve_reachability(shell, domain)

    try:
        from adscan_internal.services.exposure_score_service import (  # noqa: PLC0415
            stamp_exposure_kpis_for_domain,
        )

        stamp_exposure_kpis_for_domain(
            shell,
            domain,
            summaries=records,
            domain_data={},
            computed_at=computed_at,
            reachability=reachability,
            no_cache=True,
        )
    except Exception as exc:  # noqa: BLE001 - one block never breaks the others
        telemetry.capture_exception(exc)
        print_exception(exception=exc)

    if norm_graph is not None:
        _stamp_chokepoints(
            shell,
            domain,
            records,
            norm_graph=norm_graph,
            value_terminal_ids=value_terminal_ids,
            engine_marker_bounded=engine_marker_bounded,
        )


def _stamp_exposure_score(
    shell: SimpleNamespace, domain: str, records: list[dict[str, Any]]
) -> str | None:
    """Compute + persist ``exposure_score``; return its ``computed_at`` or None.

    Same call the PRO report makes (``compute_exposure_score(paths,
    scope="domain", workspace=...)`` then ``record_exposure_score``), so the
    figure the web ingests is the figure the deliverable prints.
    """
    try:
        from adscan_core.reporting.technical_report import (  # noqa: PLC0415
            record_exposure_score,
        )
        from adscan_internal.services.exposure_score_service import (  # noqa: PLC0415
            compute_exposure_score,
        )

        exposure = compute_exposure_score(
            records,
            scope="domain",
            workspace=str(shell.current_workspace_dir),
        ).to_dict()
        record_exposure_score(shell, domain, exposure=exposure)
        return str(exposure.get("computed_at") or "") or None
    except Exception as exc:  # noqa: BLE001 - one block never breaks the others
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


def _resolve_reachability(
    shell: SimpleNamespace, domain: str
) -> tuple[dict[str, int] | None, dict[str, Any] | None, set[str]]:
    """Return ``(reachability summary, normalized graph, value-terminal ids)``.

    Mirrors the PRO report seam exactly: the BASE attack graph, the enabled
    low-privilege start set, ``target="all"`` reachable terminals, and the node
    dict normalized to a list (``compute_reachable_terminals`` iterates a list;
    a dict silently yields nothing). Loaded ONCE and shared by the exposure-KPI
    and choke-point blocks. ``(None, None, set())`` on any failure.
    """
    try:
        from adscan_internal.services.attack_graph_service import (  # noqa: PLC0415
            _resolve_domain_enabled_low_priv_user_start_ids,
            load_attack_graph,
        )
        from adscan_internal.services.attack_reachability import (  # noqa: PLC0415
            compute_reachable_terminals,
            summarize_reachable_terminals,
        )

        graph = load_attack_graph(shell, domain)
        start_ids = _resolve_domain_enabled_low_priv_user_start_ids(
            shell, domain, graph
        )
        raw_nodes = graph.get("nodes")
        norm_graph = {
            "nodes": (
                list(raw_nodes.values())
                if isinstance(raw_nodes, dict)
                else (raw_nodes or [])
            ),
            "edges": graph.get("edges") or [],
        }
        reachable = compute_reachable_terminals(
            norm_graph, start_node_ids=start_ids, target="all"
        )
        value_terminal_ids = {str(t.node_id) for t in reachable if t.node_id}
        return summarize_reachable_terminals(reachable), norm_graph, value_terminal_ids
    except Exception as exc:  # noqa: BLE001 - degrade to the stamp's own reload
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None, None, set()


def _stamp_chokepoints(
    shell: SimpleNamespace,
    domain: str,
    records: list[dict[str, Any]],
    *,
    norm_graph: dict[str, Any],
    value_terminal_ids: set[str],
    engine_marker_bounded: bool,
) -> None:
    """Overwrite ``chokepoint_cardinality`` from the canonical listing.

    The in-memory entry is seeded with the listing (``attack_paths``, which the
    "Start Here" and "Most Exposed Accounts" sub-blocks derive from) and with the
    coverage block the listing's computation just persisted (which the
    ``bounded`` caveat reads first). Seeded in memory only: the stamp persists
    just its own block. An empty value-terminal set is stamped too, as the honest
    "nothing reachable to rank" answer, so a block an earlier run left can never
    survive a scan that measured a cleaner domain.
    """
    try:
        from adscan_core.reporting.technical_report import (  # noqa: PLC0415
            read_attack_path_coverage,
        )
        from adscan_internal.services.chokepoint_cardinality import (  # noqa: PLC0415
            resolve_choke_bounded,
            stamp_chokepoint_cardinality_for_domain,
        )

        domain_data: dict[str, Any] = {"attack_paths": records}
        coverage = read_attack_path_coverage(shell, domain)
        if coverage is not None:
            domain_data["attack_path_coverage"] = coverage
        bounded = resolve_choke_bounded(
            domain_data, engine_marker_bounded=engine_marker_bounded
        )
        stamp_chokepoint_cardinality_for_domain(
            shell=shell,
            domain=domain,
            norm_graph=norm_graph,
            value_terminals=value_terminal_ids,
            bounded=bounded,
            domain_data=domain_data,
            no_cache=True,
        )
    except Exception as exc:  # noqa: BLE001 - one block never breaks the others
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def stamp_scan_end_report_blocks(
    workspace_dir: str,
    *,
    summaries_by_domain: Mapping[str, Sequence[Mapping[str, Any]]],
    frameworks: Sequence[str] | None = None,
) -> None:
    """Stamp the blocks only the report step used to write, from the scan itself.

    The headline blocks above are per-domain and need the listing. Four more
    blocks the paid web reads out of ``technical_report.json`` were written only
    when a report was rendered, so the default web flow (a scan, then a kit from
    the scan page, which never re-ingests) left the web on a weaker reading than
    the PDF it had just produced:

    * ``assessment`` (was this domain enumerated, or only named by a trust);
    * the structured affected assets of every finding, and with them the FINAL
      ADscan severity: the contextual overlay raises a finding whose affected set
      holds a Tier-0 object or a domain controller, so without the entities a
      finding the PDF prints Critical reached the web as High;
    * ``compliance`` for the frameworks the scan selected (PRO only);
    * the workspace-level ``attack_fanout_rollup``.

    Each goes through the SAME function the report flows call
    (:func:`report_attack_paths.stamp_domain_assessment`,
    ``stamp_workspace_affected_assets``, the PRO ``stamp_domain_compliance``,
    :func:`stamp_attack_fanout_rollup`), fed the same inputs, so a later report
    re-derives the same values instead of a second, different answer.

    Order matters: the affected-asset stamp settles the ratings, and the
    compliance scoring reads the ratings, so compliance runs after it.

    Args:
        workspace_dir: The workspace the scan writes to.
        summaries_by_domain: The canonical listing per domain that the
            finalization seam just recomputed. A domain without a graph is
            absent; it still gets its assessment verdict.
        frameworks: The compliance frameworks the scan selected. Empty or
            ``None`` removes any compliance block an earlier run left behind:
            this scan scoped no regime, so a verdict over its findings is one
            nobody chose.
    """
    from adscan_internal.services.report_attack_paths import (  # noqa: PLC0415
        as_report_attack_paths,
        stamp_domain_assessment,
    )

    domains = _technical_report_domains(workspace_dir)
    for domain in domains:
        stamp_domain_assessment(workspace_dir, domain, domains[domain])

    report_paths: dict[str, list[dict[str, Any]]] = {
        str(domain): as_report_attack_paths([dict(p) for p in paths if isinstance(p, Mapping)])
        for domain, paths in summaries_by_domain.items()
    }
    for domain, paths in report_paths.items():
        _stamp_affected_assets(workspace_dir, domain, paths)

    _stamp_compliance(workspace_dir, frameworks, report_paths)
    stamp_attack_fanout_rollup(workspace_dir, list(domains))


def stamp_attack_fanout_rollup(
    workspace_dir: str, domains: Sequence[str]
) -> list[dict[str, Any]]:
    """Compute and persist the workspace's outbound fan-out rollup. The one stamp.

    The collapsed capability nodes ("one delegated right controls N objects"),
    computed over each domain's materialized attack graph by the rollup SSOT the
    CLI recap uses, and persisted under the TOP-LEVEL ``attack_fanout_rollup``
    key the web ingests. Called by the scan's finalization seam and by the PRO
    report, which also prints the returned list. An empty list is written too, so
    a cleaner run clears an earlier rollup. Best-effort: returns ``[]`` on failure.
    """
    try:
        from adscan_core.reporting.technical_report import (  # noqa: PLC0415
            record_attack_fanout_rollup,
        )
        from adscan_internal.cli.post_scan_suggestions import (  # noqa: PLC0415
            build_recap_fanout_steps,
        )
        from adscan_internal.services.attack_fanout_rollup import (  # noqa: PLC0415
            fanout_step_to_dict,
        )

        shell = SimpleNamespace(
            current_workspace_dir=str(workspace_dir), domains_dir="domains"
        )
        rollup: list[dict[str, Any]] = []
        for domain in domains:
            steps = build_recap_fanout_steps(shell, domain, max_steps=None)
            rollup.extend(fanout_step_to_dict(step) for step in steps)
        record_attack_fanout_rollup(shell, rollup=rollup)
        return rollup
    except Exception as exc:  # noqa: BLE001 - a rollup never breaks its caller
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return []


def _technical_report_domains(workspace_dir: str) -> dict[str, Any]:
    """Return the ``domains`` map of the workspace's technical report (or ``{}``)."""
    try:
        from adscan_core.reporting.technical_report import (  # noqa: PLC0415
            _load_technical_report,
        )

        report = _load_technical_report(
            SimpleNamespace(current_workspace_dir=str(workspace_dir))
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return {}
    entries = report.get("domains") if isinstance(report, dict) else None
    if not isinstance(entries, dict):
        return {}
    return {str(name): entry for name, entry in entries.items() if str(name).strip()}


def _stamp_affected_assets(
    workspace_dir: str, domain: str, paths: list[dict[str, Any]]
) -> None:
    """Resolve the domain's affected assets, and so its final ratings, on disk."""
    try:
        from adscan_internal.services.affected_assets_struct import (  # noqa: PLC0415
            stamp_workspace_affected_assets,
        )

        stamp_workspace_affected_assets(
            workspace_dir, domain, attack_paths=paths or None
        )
    except Exception as exc:  # noqa: BLE001 - one block never breaks the others
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def _stamp_compliance(
    workspace_dir: str,
    frameworks: Sequence[str] | None,
    report_paths: dict[str, list[dict[str, Any]]],
) -> None:
    """Stamp the scan's compliance blocks (PRO), or clear a stale one.

    The compliance engine lives in the PRO tree, which the LITE build strips, so
    it is reached through the optional-PRO seam and never imported here. LITE
    carries no compliance mapping by design; on LITE, or when the scan selected
    no framework, any block an earlier run left is removed instead.
    """
    from adscan_core.rich_output import print_info_debug  # noqa: PLC0415

    selected = [str(f).strip().lower() for f in (frameworks or []) if str(f).strip()]
    stamper = None
    if selected:
        try:
            from adscan_internal.reporting_compat import (  # noqa: PLC0415
                load_optional_pro_attr,
            )

            stamper = load_optional_pro_attr(
                "adscan_internal.pro.services.report_service",
                "stamp_workspace_compliance",
                action="scan-end compliance mapping",
                debug_printer=print_info_debug,
                prefix="[report]",
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            stamper = None
    if callable(stamper):
        try:
            stamper(
                workspace_dir,
                frameworks=selected,
                attack_paths_by_domain=report_paths,
            )
        except Exception as exc:  # noqa: BLE001 - one block never breaks the others
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
        return

    from adscan_core.reporting.technical_report import clear_compliance  # noqa: PLC0415

    clear_compliance(SimpleNamespace(current_workspace_dir=str(workspace_dir)))


def stamp_workspace_remediation(
    workspace_dir: str,
    listings: Mapping[str, Sequence[Mapping[str, Any]]],
) -> None:
    """Stamp the workspace-wide "Start here" and "Most exposed accounts" blocks.

    The Security Assessment Report ranks the remediation ONCE for the whole
    workspace: every assessed domain's listing, concatenated and domain-tagged,
    through ``build_start_here_for_domains`` (the composition the SAR calls), and
    the per-user ranking over the same concatenation. The web CTEM has no paths
    to do that with, so the scan does it here, from the canonical listings it has
    just recomputed and stamped each domain from, and persists the result at the
    top-level ``workspace_remediation`` key for the web to serve verbatim.

    Domains are iterated in the technical report's own order (the order the SAR
    iterates), and the structural-choke badge map and ``bounded`` caveat are
    merged from the per-domain choke blocks exactly as the SAR merges them. Must
    run AFTER every domain's headline blocks are stamped. Always overwrites, an
    empty workspace included. Best-effort: never raises into the scan.

    Args:
        workspace_dir: The workspace root the scan writes to.
        listings: ``{domain: canonical listing}`` for every domain whose listing
            the scan recomputed. A domain with no graph is simply absent.
    """
    try:
        from adscan_core.reporting.remediation_scope_view import (  # noqa: PLC0415
            WORKSPACE_REMEDIATION_SCHEMA_VERSION,
        )
        from adscan_core.reporting.technical_report import (  # noqa: PLC0415
            _load_technical_report,
            record_workspace_remediation,
        )
        from adscan_core.reporting.user_exposure_ranking import (  # noqa: PLC0415
            build_user_exposure_ranking,
        )
        from adscan_internal.services.chokepoint_cardinality import (  # noqa: PLC0415
            _node_cardinality_map_from_summary,
        )
        from adscan_internal.services.remediation_start_here import (  # noqa: PLC0415
            build_start_here_for_domains,
        )
        from adscan_internal.services.technique_priority import (  # noqa: PLC0415
            iter_domain_tagged_paths,
        )

        shell = SimpleNamespace(
            current_workspace_dir=str(workspace_dir), domains_dir="domains"
        )
        report = _load_technical_report(shell)
        report_domains = report.get("domains") if isinstance(report, dict) else None
        report_domains = report_domains if isinstance(report_domains, dict) else {}

        ordered = [d for d in report_domains if d in listings]
        ordered += [d for d in listings if d not in report_domains]

        domains_data: list[dict[str, Any]] = []
        node_cardinality: dict[str, int] = {}
        bounded = False
        for domain in ordered:
            records = [dict(r) for r in listings.get(domain) or () if isinstance(r, Mapping)]
            domains_data.append({"name": domain, "attack_paths": records})
            entry = report_domains.get(domain)
            block = entry.get("chokepoint_cardinality") if isinstance(entry, dict) else None
            if isinstance(block, dict):
                bounded = bounded or bool(block.get("bounded"))
                for node, card in _node_cardinality_map_from_summary(block).items():
                    node_cardinality[node] = max(node_cardinality.get(node, 0), card)

        start_here = build_start_here_for_domains(
            domains_data, node_cardinality=node_cardinality, bounded=bounded
        )
        exposure = build_user_exposure_ranking(iter_domain_tagged_paths(domains_data))
        record_workspace_remediation(
            shell,
            block={
                "schema_version": WORKSPACE_REMEDIATION_SCHEMA_VERSION,
                "domains": ordered,
                "attack_paths_considered": sum(
                    len(d["attack_paths"]) for d in domains_data
                ),
                "remediation_start_here": start_here,
                "user_exposure": exposure if exposure.get("top_users") else None,
            },
        )
    except Exception as exc:  # noqa: BLE001 - never affects the scan flow
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


__all__ = [
    "stamp_attack_fanout_rollup",
    "stamp_headline_blocks_for_domain",
    "stamp_scan_end_report_blocks", "stamp_workspace_remediation"]
