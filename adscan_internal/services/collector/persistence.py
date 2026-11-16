"""Persistence bridge from a CollectionResult to the domain's graph store.

The collector commits what it collected as store units; the graph build derives
every edge and the export writes ``attack_graph.json``, ``memberships.json`` and
``inventory/*.json``. Nothing here loads, merges or writes the graph itself
(locked by ``tests/unit/services/collector/test_collector_never_writes_edges.py``).
"""

from __future__ import annotations

from typing import Any

from adscan_core import telemetry
from adscan_core.rich_output import mark_sensitive, print_exception, print_info_debug
from adscan_internal.services import attack_graph_service
from adscan_internal.services.collector.models import (
    CollectionResult,
    ForeignNodeRef,
)

# The edge-derivation rules live in the graph build, their one home. Re-exported
# here because many tests and lab harnesses import them from this module; the
# build never imports them from here.
from adscan_internal.services.graph_build.base_edges import (  # noqa: F401
    _ensure_foreign_endpoint_node,
    emit_base_edges,
)
from adscan_internal.services.graph_build.nodes import (  # noqa: F401
    _build_classified_node_payloads,
    _merge_system_tags,
    _resolve_inherited_privileged_memberships,
    _stamp_privilege_tier_on_payloads,
    _terminal_class_from_privileged_decision,
    upsert_result_nodes,
)
from adscan_internal.services.graph_build.passes._common import (  # noqa: F401
    _node_bool_property,
    _node_list_property,
    _upsert_derived_edge,
)
from adscan_internal.services.graph_build.passes.adcs import (  # noqa: F401
    _BROAD_ENROLL_RIDS,
    _BROAD_ENROLL_WELLKNOWN_SIDS,
    _DOMAIN_ADMINS_RID,
    _DOMAIN_CONTROLLERS_RID,
    _ESC9_BFS_MAX_DEPTH,
    _ESC9_USER_WRITE_RELATIONS,
    _ESC_CA_KEY_TO_DOMAIN_ADMINS,
    _ESC_DERIVED_RELATIONS,
    _ESC_TO_DOMAIN_ADMINS,
    _ESC_TO_DOMAIN_CONTROLLERS,
    _ESC_TO_VICTIM,
    _ESC_WRITER_MEDIATED,
    _WELL_KNOWN_GROUP_LABELS,
    _build_dn_to_graph_id_map,
    _build_esc_vulnerable_resource_entry,
    _client_auth_template_enroller_sids,
    _derive_domain_sid_from_result,
    _domain_can_enroll_client_auth_cert,
    _emit_esc14a_write_access_edges,
    _find_well_known_group_graph_id,
    _persist_esc_compromise_steps,
    _result_has_enterprise_ca,
    _sid_is_broad_principal,
    _synthesize_well_known_group_node,
    _template_cn,
)
from adscan_internal.services.graph_build.passes.dcsync import (  # noqa: F401
    _persist_dcsync_steps,
)
from adscan_internal.services.graph_build.passes.delegation import (  # noqa: F401
    _SPN_WRITE_RELATIONS,
    _bfs_memberof_node_ids,
    _host_from_spn,
    _persist_delegation_steps,
    _resolve_delegation_target_graph_id,
    derive_delegation_edges,
    derive_spnjack_edges,
)
from adscan_internal.services.graph_build.passes.prunes import (  # noqa: F401
    _ADCS_OBJECT_KINDS,
    _ADCS_RAW_ACL_RELATIONS,
    _CONTAINER_SCOPE_KINDS,
    _CONTAINER_SCOPE_RELATIONS,
    _DOMAIN_COMPROMISE_RELATION_PRIORITY,
    _KEY_ADMINS_RIDS,
    _REPLICATION_RIGHT_RELATIONS,
    _drop_redundant_direct_compromise_to_domain_edges,
    _is_redundant_container_scope_edge,
    _should_skip_attack_graph_edge,
)
from adscan_internal.services.graph_build.passes.roasting import (  # noqa: F401
    _AUTHENTICATED_USERS_SID,
    _adcs_ca_web_enrollment_hosts,
    _exclude_adcs_ca_http_spns,
    _finalize_enumerated_surface_census,
    _find_authenticated_users_graph_id,
    _http_service_spns,
    _new_surface_tallies,
    _node_account_signals,
    _node_account_type,
    _node_is_enabled,
    _node_is_roastable,
    _node_is_roastable_candidate,
    _spn_instance_host,
    _tier0_predicate,
    collect_http_spn_findings,
    derive_roasting_edges,
)


def _register_collected_hostnames_for_telemetry(result: CollectionResult) -> None:
    """Register every collected computer name with the telemetry sanitizer.

    The workspace loader seeds the sanitizer's hostname set from
    ``enabled_computers.txt`` at workspace-ACTIVATION time. On a fresh
    ``adscan ci`` that file does not exist yet -- activation happens before
    collection -- so the set is seeded EMPTY and nothing re-seeds it once
    collection discovers the estate. An FQDN and an IP still get scrubbed by
    their structural nets, but a single-label NetBIOS name has no structural
    signature to anchor on, so the customer's DC short name travelled to the
    uploaded recording in cleartext beside its own pseudonymized FQDN.

    This is the right seam because every collection path converges here: both
    the writer of ``enabled_computers.txt`` (``_process_computers_list``) and
    the Phase-2 port scan, which writes that file directly, run downstream of
    it. Registering the FQDN alone would not be enough either -- the sanitizer
    derives the short label from a known domain suffix, and a computer whose
    DNS name sits outside the collected domains has no suffix to strip -- so the
    ``sAMAccountName`` is registered as well, stripped of its trailing ``$``.

    Sanitization runs at EXPORT time over the whole buffer, so registering here
    also masks every occurrence recorded BEFORE collection reached this point.

    Best-effort by construction: telemetry hygiene must never be able to abort
    a collection run.

    Args:
        result: The collection result whose Computer nodes should be registered.
    """
    try:
        names: list[str] = []
        for node in result.nodes.values():
            if getattr(node, "kind", "") != "Computer":
                continue
            fqdn = str(getattr(node, "name", "") or "").strip()
            if fqdn:
                names.append(fqdn)
            sam = str(getattr(node, "samaccountname", "") or "").strip()
            short = sam.rstrip("$")
            if short:
                names.append(short)
            dns_name = str(
                (getattr(node, "properties", None) or {}).get("dnshostname") or ""
            ).strip()
            if dns_name:
                names.append(dns_name)
        if names:
            telemetry.add_known_hostname(*names)
    except Exception as exc:  # noqa: BLE001 - never break collection for telemetry
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


#: What the findings derivation counts, for the coverage statement of a stop:
#: the classification of the collected objects, the web-service (HTTP SPN)
#: findings, the replication-right census and the Kerberos census.
FINDINGS_DERIVATION_UNIT = "directory analyses"
FINDINGS_DERIVATION_STEPS = 4


def _step_done(stage: Any) -> None:
    """Count one derivation step on the stage boundary (samples memory)."""
    if stage is not None:
        stage.tick()


def derive_result_findings(result: CollectionResult, stage: Any = None) -> None:
    """Fill the findings the run reads off the collected result itself.

    ``http_spn_findings`` and the enumerated-surface census
    (``enumerated_surfaces``) are read by ``cli/intelligence.py`` from the
    in-memory result after collection. The graph build derives the attack steps
    from the store and never touches the caller's result, so they are computed
    here with the SAME rule functions the build's passes call, over a scratch
    graph that is discarded (the store and the export are untouched).
    Best-effort: a failure leaves the fields as they were.

    ``stage`` is the memory-bounded stage it runs in (:func:`derive_findings_bounded`):
    each of the :data:`FINDINGS_DERIVATION_STEPS` steps is counted on it, and the
    classification loops ask its guard as they go. A memory stop leaves both
    fields as they were.
    """
    previous_http = result.http_spn_findings
    try:
        scratch: dict[str, Any] = {"domain": result.domain, "nodes": {}, "edges": []}
        upserted = upsert_result_nodes(scratch, result)
        _step_done(stage)
        sid_to_graph_id = upserted.sid_to_graph_id
        result.http_spn_findings = []
        collect_http_spn_findings(result, sid_to_graph_id=sid_to_graph_id)
        _step_done(stage)
        tallies = _new_surface_tallies()
        is_tier0 = _tier0_predicate(upserted.payload_by_sid)
        index = attack_graph_service.EdgeUpsertIndex()
        _persist_dcsync_steps(
            scratch,
            result=result,
            sid_to_graph_id=sid_to_graph_id,
            surface_tally=tallies.get("credential_access"),
            is_tier0=is_tier0,
            edge_index=index,
        )
        _step_done(stage)
        derive_roasting_edges(
            scratch,
            result=result,
            sid_to_graph_id=sid_to_graph_id,
            kerberos_tally=tallies.get("kerberos"),
            edge_index=index,
        )
        _step_done(stage)
        result.enumerated_surfaces = _finalize_enumerated_surface_census(result, tallies, is_tier0)
    except Exception as exc:  # noqa: BLE001 - never break collection for a census
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    except BaseException:
        # A memory stop (or an abort): the half-built list is not this result's.
        result.http_spn_findings = previous_http
        raise


def derive_findings_bounded(shell: Any, domain: str, result: CollectionResult) -> None:
    """Run :func:`derive_result_findings` under the collection stage's memory boundary.

    The derivation builds a scratch graph of the whole collection result next to
    the result itself, so it is the heaviest step of a persist. It runs:

    * not at all when a collection or graph stage of ``domain`` already stopped
      at the memory ceiling in THIS run and the derivation already ran over
      this result (``findings_derivation`` set): the directory was read in
      full, the findings were derived from it before the stop (or the
      derivation itself stopped), and a second walk would only climb back to
      the ceiling (it took the process to the kernel's kill on a
      ten-times-partner directory). The stop that came first already declares
      what this run did not finish;
    * otherwise under ``memory_bounded``: a stop there is declared as a
      collection stop ("N of 4 directory analyses"), marks the collection phase
      incomplete (``adscan ci`` exits 3) and leaves the fields as they were.
    """
    from adscan_core.memory_guard import OUTCOME_STOPPED, memory_bounded  # noqa: PLC0415
    from adscan_core.reporting.resource_coverage import STAGE_COLLECTION  # noqa: PLC0415
    from adscan_internal.services.graph_availability import (  # noqa: PLC0415
        collection_memory_stop_this_run,
    )

    stopped = collection_memory_stop_this_run(shell, domain)
    if stopped and result.findings_derivation:
        print_info_debug(
            f"collector: {mark_sensitive(domain, 'domain')}: findings not derived again: "
            f"the {stopped} stage stopped at the memory ceiling earlier in this run; "
            "the findings derived from the directory read stand"
        )
        return
    from adscan_internal.services.resource_coverage_recorder import (  # noqa: PLC0415
        collection_stop_recorder,
    )

    with memory_bounded(
        STAGE_COLLECTION,
        unit=FINDINGS_DERIVATION_UNIT,
        total=FINDINGS_DERIVATION_STEPS,
        record=collection_stop_recorder(
            shell,
            domain,
            detail="Domain collection could not derive its findings within the available memory.",
        ),
    ) as stage:
        derive_result_findings(result, stage)
    result.findings_derivation = "stopped" if stage.outcome == OUTCOME_STOPPED else "complete"


class CollectorPersistence:
    """Commit collector output into the domain's graph store and export the graph."""

    def persist(
        self,
        shell: object,
        *,
        domain: str,
        result: CollectionResult,
        foreign_sid_to_label: dict[str, "ForeignNodeRef"] | None = None,
    ) -> dict[str, int]:
        """Commit ``result`` as store units, end its stages and export the graph.

        Inventory-first persistence (package G): the result is split into the
        units of its stages (``collector.store_writer``), only units whose
        content moved are written, every stage that wrote is ended, and the
        graph, ``memberships.json`` and ``inventory/*.json`` are exported from
        the store on the export throttle (``graph_runtime.export_graph_if_due``):
        the first export of a domain is never throttled, a later one may wait
        for the collection's forced export at its end. Nothing
        here builds, loads or saves the graph itself.

        ``foreign_sid_to_label`` is accepted for compatibility and unused: the
        build resolves a foreign endpoint through the other domains' stores.

        Returns counters: ``nodes`` / ``edges`` of the exported graph,
        ``units_written`` / ``units_unchanged`` / ``units_pruned``.
        """
        del foreign_sid_to_label
        from adscan_internal.services.collector.inventory_persistence import (  # noqa: PLC0415
            _observe_adcs_escalations,
            adcs_attack_step_records,
        )
        from adscan_internal.services.collector.store_writer import (  # noqa: PLC0415
            store_writer_for_shell,
        )
        from adscan_internal.services.graph_runtime import (  # noqa: PLC0415
            export_graph_if_due,
        )

        _register_collected_hostnames_for_telemetry(result)
        # Bounded, and not repeated after a memory stop of this run (the stop is
        # a state the rest of the run reads; see ``derive_findings_bounded``).
        derive_findings_bounded(shell, domain, result)
        writer = store_writer_for_shell(shell, domain)
        counters = writer.commit_result(result)
        # Throttled: the collection's one forced export runs when its last
        # stage ends (``CollectionOrchestrator._persist_cross_domain_edges``).
        export_graph_if_due(shell, domain)
        _observe_adcs_escalations(shell, domain, result, adcs_attack_step_records(result))
        record = writer.store.last_export()
        return {
            "nodes": int(record.nodes) if record is not None else len(result.nodes),
            "edges": int(record.edges) if record is not None else 0,
            **counters,
        }
