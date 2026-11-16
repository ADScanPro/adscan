"""Multi-domain collection orchestrator."""

from __future__ import annotations

import threading
import time
from contextlib import nullcontext
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Protocol, TYPE_CHECKING

if TYPE_CHECKING:
    from adscan_internal.services.collector.host_collector import (
        HostPhaseProgress,
        HostPhaseTiming,
    )
    from adscan_internal.services.collector.host_sweep_cancellation import (
        HostSweepCancellation,
    )
    from adscan_internal.services.domain_posture import DomainPosture
    from adscan_internal.services.posture_sink import PostureSink

from adscan_core import telemetry
from adscan_core.memory_guard import OUTCOME_STOPPED, memory_bounded
from adscan_core.scan_control import ScanAbortRequested
from adscan_core.reporting.host_enrichment_coverage import (
    REASON_DESELECTED,
    deselected_host_parts,
)
from adscan_core.reporting.resource_coverage import (
    DIRECTORY_READ_UNIT,
    REASON_MEMORY,
    STAGE_COLLECTION,
)
from adscan_internal.rich_output import (
    mark_sensitive,
    print_info,
    print_info_debug,
    print_info_verbose,
)
from adscan_internal.services.collector.shadow_credentials_analyzer import (
    analyze_shadow_credentials,
)
from adscan_internal.services.collector.audit_analyzer import analyze_audit_findings
from adscan_internal.services.collector.dns_resolver import resolve_computer_nodes
from adscan_internal.services.collector.group_inference_analyzer import (
    analyze_group_inferences,
)
from adscan_internal.services import attack_graph_service
from adscan_internal.services.collector.ldap_collector import ADscanLDAPCollector
from adscan_internal.services.collector.models import (
    COLLECTION_SCOPE_DOMAIN_COMPROMISE,
    COLLECTION_SCOPE_FULL_ASSESSMENT,
    CollectionResult,
    ForeignNodeRef,
)
from adscan_internal.services.collector.persistence import CollectorPersistence
from adscan_internal.services.collector.smb_collector import SMBCollectorConfig
from adscan_internal.services.collector.stage_progress import (
    STAGE_DIRECTORY_READ,
    STAGE_GRAPH_SAVE,
    collection_stage_progress,
)
from adscan_internal.services.collector.share_collector import ShareCollectorConfig
from adscan_internal.workspaces import domain_subpath
from adscan_core.rich_output import print_exception


@dataclass
class DomainScope:
    """Target scope for a single domain collection pass."""

    domain: str
    dc_address: str
    auth_domain: str
    auth_kdc: str
    kerberos_target_hostname: str | None = None


@dataclass
class CollectionTiming:
    """Wall-clock durations (seconds) for each collection phase."""

    ldap: float = 0.0
    adcs: float = 0.0
    dns: float = 0.0
    post_processing: float = 0.0
    host_negotiate: float = 0.0
    host_samr: float = 0.0
    host_shares: float = 0.0
    extra: dict[str, float] = field(default_factory=dict)
    # Operator early-stop coverage for the per-host SMB enrichment sweep. Empty
    # when the sweep ran to completion (full coverage). When the operator halted
    # the sweep early (CLI Ctrl+C or the platform button), this carries the
    # transparent X-of-Y so the report + web can render an audit-defensible
    # coverage statement: {"early_stopped", "hosts_swept", "hosts_total",
    # "hosts_remaining", "source"}. The identity graph is always 100%.
    host_coverage: dict[str, Any] = field(default_factory=dict)
    # --- Observability-only wall-clock + host-distribution telemetry (additive). ---
    # These carry the perf signals up to the CLI emit; they never alter collection.
    # host_wall is the REAL fan-out duration measured around the host-collection
    # call — distinct from host_negotiate/host_samr/host_shares, which are
    # OVERLAPPING CONCURRENT per-stage sums (read their ratio, not their absolute).
    host_wall: float = 0.0
    gate_probe: float = 0.0  # 445 reachability-gate probe duration (seconds)
    persist: float = 0.0  # end-of-sweep graph persist duration (seconds)
    host_count: int = 0  # candidate hosts fed to the 445 gate
    reachable_445: int = 0  # hosts that passed the 445 gate
    concurrency: int = 0  # per-host SMB sweep concurrency knob
    dead_host_count: int = 0  # candidates that failed the 445 gate (unreachable)
    budget_timeouts: int = 0  # per-host safety-net abandonments
    host_p50: float = 0.0  # per-host wall-clock p50 (seconds)
    host_p95: float = 0.0  # per-host wall-clock p95 (seconds)
    host_max: float = 0.0  # per-host wall-clock max (seconds)
    host_outcomes: dict[str, int] = field(default_factory=dict)  # outcome histogram

    @property
    def host_total(self) -> float:
        return self.host_negotiate + self.host_samr + self.host_shares

    @property
    def total(self) -> float:
        return self.ldap + self.adcs + self.dns + self.post_processing + self.host_total

    def as_dict(self) -> dict[str, float]:
        d = {
            "elapsed_ldap_s": round(self.ldap, 2),
            "elapsed_adcs_s": round(self.adcs, 2),
            "elapsed_dns_s": round(self.dns, 2),
            "elapsed_post_processing_s": round(self.post_processing, 2),
            "elapsed_host_negotiate_s": round(self.host_negotiate, 2),
            "elapsed_host_samr_s": round(self.host_samr, 2),
            "elapsed_host_shares_s": round(self.host_shares, 2),
            "elapsed_host_total_s": round(self.host_total, 2),
            "elapsed_total_s": round(self.total, 2),
        }
        d.update({f"elapsed_{k}_s": round(v, 2) for k, v in self.extra.items()})
        return d


class _Credential(Protocol):
    username: str | None
    password: str | None
    use_kerberos: bool
    ccache_path: str | None
    aes_key: str | None


def build_cross_domain_label_registry(
    results: "dict[str, CollectionResult]",
) -> dict[str, ForeignNodeRef]:
    """Build a SID -> :class:`ForeignNodeRef` registry over all collected domains.

    Walks every node of every collected domain and records, per SID, the exact
    graph identity (``name:<canonical>``) and ``NAME@DOMAIN`` label that domain's
    own ``attack_graph.json`` uses. Per-domain persistence consumes this map so a
    cross-domain edge whose target SID belongs to another domain points at the
    real foreign node (same graph id → the query-time merge collapses them), which
    is what lets a single attack path span the domain boundary.

    Args:
        results: SID-keyed collection results, one per collected domain.

    Returns:
        SID (uppercased) -> :class:`ForeignNodeRef`. Later domains win on a SID
        collision (impossible in practice — SIDs are globally unique).
    """
    registry: dict[str, ForeignNodeRef] = {}
    for result in results.values():
        for sid, node in result.nodes.items():
            payload = node.to_graph_payload()
            registry[sid.upper()] = ForeignNodeRef(
                node_id=attack_graph_service._node_id(payload),  # noqa: SLF001
                label=str(payload.get("label") or node.name or sid),
                kind=str(payload.get("kind") or "Base"),
                is_tier0=bool(
                    payload.get("isTierZero") or payload.get("highvalue")
                ),
            )
    return registry


class CollectionOrchestrator:
    """Orchestrates LDAP collection across one or more domain scopes."""

    def __init__(self, *, ldap_collector: Any = None, persistence: Any = None) -> None:
        self._ldap_collector = ldap_collector or ADscanLDAPCollector()
        self._persistence = persistence or CollectorPersistence()
        # Serialises every graph persist this orchestrator makes. The host
        # sweep's mid-sweep checkpoint persists a snapshot on its own thread and
        # the sweep does not wait for it (a stop must return in seconds), so
        # the end-of-sweep persist takes this lock first: a running checkpoint
        # finishes, then the complete graph is written over it, never under it.
        self._persist_lock = threading.Lock()
        # A "stop the scan" chosen during the host sweep, held until the domain's
        # graph is saved so the sweep's findings are kept (see ``collect_scope``).
        self._held_scan_abort: BaseException | None = None

    def _persist(self, shell: Any, *, domain: str, result: Any, **kwargs: Any) -> Any:
        """``persistence.persist`` under the orchestrator's persist lock."""
        if not self._persist_lock.acquire(blocking=False):
            print_info_verbose(
                "Saving the collected graph: waiting for the progress checkpoint "
                "that is still writing to finish first."
            )
            self._persist_lock.acquire()
        try:
            return self._persistence.persist(shell, domain=domain, result=result, **kwargs)
        finally:
            self._persist_lock.release()

    @staticmethod
    def _report_progress(
        progress_callback: Callable[[int], None] | None,
        result: CollectionResult,
    ) -> None:
        """Report the running object count to an optional progress callback.

        Pure observability: invoked at collection-phase boundaries with the
        number of graph nodes pulled so far (``len(result.nodes)``), so a caller
        can surface a live "objects pulled" count that climbs mid-run. A None
        callback is a no-op (default), keeping behaviour byte-for-byte identical
        to a run without the callback. A callback exception is captured and
        swallowed so observability can never abort collection.
        """
        if progress_callback is None:
            return
        try:
            progress_callback(len(result.nodes))
        except Exception as exc:  # noqa: BLE001 — progress must never abort collection
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    def collect_domain(
        self,
        *,
        target_domain: str,
        auth_domain: str,
        dc_address: str,
        auth_kdc: str,
        credential: _Credential,
        kerberos_target_hostname: str | None = None,
        use_ldaps: bool = True,
        collection_scope: str = COLLECTION_SCOPE_DOMAIN_COMPROMISE,
        collect_smb: bool = True,
        collect_shares: bool = True,
        posture_sink: Optional["PostureSink"] = None,
        posture_snapshot: Optional["DomainPosture"] = None,
        output_dir: str | None = None,
        progress_callback: Callable[[int], None] | None = None,
        host_progress_callback: "Callable[[HostPhaseProgress], None] | None" = None,
        host_stage_timing_beacon: (
            "Callable[[HostPhaseTiming, int, int], None] | None"
        ) = None,
        host_cancellation: "HostSweepCancellation | None" = None,
        host_cap: int = 0,
        scale_gate_callback: "Callable[[int], Any] | None" = None,
        shell: Any = None,
        defer_ca_registry_rerun: bool = False,
        host_sweep_scope: "Callable[[], Any] | None" = None,
    ) -> tuple[CollectionResult, CollectionTiming]:
        """Collect a single domain and return the raw result with per-phase timing.

        When ``output_dir`` is supplied it is the workspace domain directory the
        Phase 2 DNS resolver persists ``massdns_resolution_report.json`` into;
        when None the resolver stays in-memory only (no file written).

        ``progress_callback`` is an optional observability hook invoked with the
        running object count (``len(result.nodes)``) at each collection-phase
        boundary, so the caller can render live "objects pulled" motion. None
        (default) makes it a no-op and leaves collection unchanged.

        ``host_progress_callback`` is the DETERMINATE host-phase hook: it is
        invoked (throttled) during the per-host SMB sweep with a
        :class:`HostPhaseProgress` carrying hosts ``done`` of ``total`` plus the
        rolling rate/ETA/elapsed, so the caller can render "342 / 1,847 hosts ·
        ETA 12m" — a real ETA the object-count hook cannot give (no known total).
        None (default) is a no-op.

        ``host_cap`` bounds the per-host SMB enrichment sweep to at most this many
        hosts (representative-first, Tier 0 / DCs / ADCS first), so a large estate
        stays inside a PoV time budget. ``0`` (default) means unlimited — the full
        sweep. The identity graph (LDAP) is always 100%; only deep host enrichment
        is bounded.

        ``shell`` enables host-granular Domain-Collection crash-resume: when
        supplied (the CLI/web scan path) the per-host SMB sweep records which hosts
        it enriched under ``domains_data[domain]["collection_progress"]`` and
        checkpoints the partial graph mid-sweep, so a Ctrl+C / crash resumes from
        the remaining hosts on reload. ``None`` (default, lab scripts / tests)
        leaves collection byte-for-byte identical to the pre-resume behaviour.

        ``host_sweep_scope`` is a zero-argument factory returning the context
        manager the per-host SMB sweep runs inside (the CLI passes the
        operator-stoppable "SMB host enrichment" step). It wraps the sweep ONLY,
        never the directory read or the graph save, so a Ctrl+C during those
        stages is not read as a stop of host enrichment. It is never entered
        when both SMB sub-collections are deselected.
        """
        timing = CollectionTiming()
        print_info_verbose(
            f"Collecting domain {mark_sensitive(target_domain, 'domain')}..."
        )

        if shell is not None:
            # A new collection of the domain is judged afresh: an earlier
            # collection stop is no longer what this run rests on.
            from adscan_internal.services.resource_coverage_recorder import (
                clear_stage_coverage,
            )

            clear_stage_coverage(shell, target_domain, STAGE_COLLECTION)
        _t = time.monotonic()
        # The directory read holds the whole result in memory until it is
        # committed, so it runs under the collection stage's memory boundary
        # (the paged searches and the ACL parsing watch it). A stop keeps what
        # earlier runs committed, commits nothing partial, and is declared.
        with memory_bounded(
            STAGE_COLLECTION,
            unit=DIRECTORY_READ_UNIT,
            record=self._collection_stop_recorder(shell, target_domain),
        ) as ldap_stage, collection_stage_progress(shell, label=STAGE_DIRECTORY_READ):
            result = self._ldap_collect(
                target_domain=target_domain,
                dc_address=dc_address,
                credential=credential,
                use_ldaps=use_ldaps,
                kerberos_target_hostname=kerberos_target_hostname,
                auth_domain=auth_domain,
                auth_kdc=auth_kdc,
                collection_scope=collection_scope,
                posture_sink=posture_sink,
                posture_snapshot=posture_snapshot,
                shell=shell,
                defer_ca_registry_rerun=defer_ca_registry_rerun,
            )
        if ldap_stage.outcome == OUTCOME_STOPPED:
            timing.ldap = time.monotonic() - _t
            return self._memory_stopped_result(target_domain, collection_scope), timing
        timing.adcs = result.adcs_elapsed
        timing.ldap = time.monotonic() - _t - timing.adcs
        # Live observability: the LDAP pass pulled the bulk of the graph nodes.
        self._report_progress(progress_callback, result)
        return self._collect_after_directory(
            result,
            timing,
            target_domain=target_domain,
            auth_domain=auth_domain,
            dc_address=dc_address,
            auth_kdc=auth_kdc,
            credential=credential,
            kerberos_target_hostname=kerberos_target_hostname,
            collection_scope=collection_scope,
            collect_smb=collect_smb,
            collect_shares=collect_shares,
            posture_sink=posture_sink,
            posture_snapshot=posture_snapshot,
            output_dir=output_dir,
            progress_callback=progress_callback,
            host_progress_callback=host_progress_callback,
            host_stage_timing_beacon=host_stage_timing_beacon,
            host_cancellation=host_cancellation,
            host_cap=host_cap,
            scale_gate_callback=scale_gate_callback,
            shell=shell,
            host_sweep_scope=host_sweep_scope,
        )

    def _ldap_collect(
        self,
        *,
        target_domain: str,
        dc_address: str,
        credential: _Credential,
        use_ldaps: bool,
        kerberos_target_hostname: str | None,
        auth_domain: str,
        auth_kdc: str,
        collection_scope: str,
        posture_sink: Optional["PostureSink"],
        posture_snapshot: Optional["DomainPosture"],
        shell: Any,
        defer_ca_registry_rerun: bool,
    ) -> CollectionResult:
        """The directory read (one call, so a memory stop releases its frames)."""
        return self._ldap_collector.collect(
            domain=target_domain,
            dc_address=dc_address,
            username=getattr(credential, "username", None),
            password=getattr(credential, "password", None),
            use_kerberos=getattr(credential, "use_kerberos", False),
            use_ldaps=use_ldaps,
            kerberos_target_hostname=kerberos_target_hostname,
            auth_domain=auth_domain,
            auth_kdc=auth_kdc,
            aes_key=getattr(credential, "aes_key", None),
            ccache_path=getattr(credential, "ccache_path", None),
            collection_scope=collection_scope,
            posture_sink=posture_sink,
            posture_snapshot=posture_snapshot,
            shell=shell,
            defer_ca_registry_rerun=defer_ca_registry_rerun,
        )

    @staticmethod
    def _collection_stop_recorder(shell: Any, domain: str) -> Any:
        """The ``record`` callback of a collection stage stopped at the ceiling."""
        from adscan_internal.services.resource_coverage_recorder import (
            collection_stop_recorder,
        )

        return collection_stop_recorder(shell, domain)

    @staticmethod
    def _memory_stopped_result(domain: str, collection_scope: str) -> CollectionResult:
        """The result of a directory read stopped at the memory ceiling.

        Holds nothing, and records the directory and AD CS stages as cut off, so
        the store keeps what earlier runs committed (no stale prune, no "no AD
        CS" stamped from an absence) and the collection reads incomplete.
        """
        result = CollectionResult(domain=domain, collection_scope=collection_scope)
        result.record_stage_failure("objects_acls", REASON_MEMORY)
        result.record_stage_failure("adcs", REASON_MEMORY)
        return result

    def _collect_after_directory(
        self,
        result: CollectionResult,
        timing: CollectionTiming,
        *,
        target_domain: str,
        auth_domain: str,
        dc_address: str,
        auth_kdc: str,
        credential: _Credential,
        kerberos_target_hostname: str | None,
        collection_scope: str,
        collect_smb: bool,
        collect_shares: bool,
        posture_sink: Optional["PostureSink"],
        posture_snapshot: Optional["DomainPosture"],
        output_dir: str | None,
        progress_callback: Callable[[int], None] | None,
        host_progress_callback: Any,
        host_stage_timing_beacon: Any,
        host_cancellation: Any,
        host_cap: int,
        scale_gate_callback: Any,
        shell: Any,
        host_sweep_scope: "Callable[[], Any] | None" = None,
    ) -> tuple[CollectionResult, CollectionTiming]:
        """Everything a domain collection does after the directory read."""
        _t = time.monotonic()
        result.shadow_credential_findings = analyze_shadow_credentials(result)
        result.audit_findings = analyze_audit_findings(result, result.domain_policy)
        analyze_group_inferences(result)
        # Well-known SID nodes and implicit Authenticated Users / Everyone
        # memberships are needed for any code path that consumes the graph
        # (path-builder, attack-step rendering, choke-point analysis), not
        # only when SMB/share collection runs. Both are idempotent and cheap.
        from adscan_internal.services.collector.well_known_sids import (
            analyze_implicit_well_known_memberships,
            inject_all_well_known_sid_nodes,
        )

        inject_all_well_known_sid_nodes(result)
        analyze_implicit_well_known_memberships(result)
        timing.post_processing = time.monotonic() - _t
        # Live observability: well-known SID injection grew the node count.
        self._report_progress(progress_callback, result)

        # Machine-account password rotation policy (audit scope): read the GPO
        # SYSVOL security templates over SMB to flag disabled/relaxed rotation — a
        # domain-wide static-machine-password (Timeroast) surface. Best-effort.
        if collection_scope == COLLECTION_SCOPE_FULL_ASSESSMENT and self._dc_share_read_in_scope(
            shell,
            result,
            target_domain=target_domain,
            dc_address=dc_address,
            dc_fqdn=kerberos_target_hostname,
        ):
            self._inspect_machine_password_policy(
                result,
                target_domain=target_domain,
                dc_address=dc_address,
                dc_fqdn=kerberos_target_hostname,
                auth_domain=auth_domain,
                auth_kdc=auth_kdc,
                credential=credential,
                posture_sink=posture_sink,
                posture_snapshot=posture_snapshot,
            )

        # Inventory-first persistence: the directory stages are committed to the
        # store NOW, before the host sweep, so the graph exists (and is exported
        # for the live view) while the long sweep runs, and a crash in the sweep
        # loses no directory data. The end-of-domain persist in ``collect_scope``
        # commits again and writes only what moved since (host properties learned
        # by DNS and SMB, the host audit findings, well-known nodes added later).
        if shell is not None:
            with collection_stage_progress(shell, label=STAGE_GRAPH_SAVE):
                self._persist(shell, domain=target_domain, result=result)
            # The directory objects of this domain are committed: tell the
            # engagement scope NOW, before the first stage that contacts a
            # host, so the entries that waited for them (an account name, a
            # SID, a DN, a short host name) resolve and no host is judged
            # against a half-resolved scope.
            self._directory_committed(shell, target_domain)

        if not (collect_smb and collect_shares):
            # A deselected SMB sub-collection is a declared coverage gap, never
            # a silently clean one. With BOTH deselected nothing below contacts
            # a host (no DNS resolution of the computers, no 445 gate, no sweep);
            # with one deselected the sweep runs the other stage only.
            timing.host_coverage = self._deselected_host_coverage(
                result, collect_smb=collect_smb, collect_shares=collect_shares
            )

        if collect_smb or collect_shares:
            _t = time.monotonic()
            resolve_computer_nodes(
                result,
                dc_address,
                output_dir=output_dir,
                domain=target_domain,
            )
            timing.dns = time.monotonic() - _t

            # Duplicate-DNS hygiene: Computer nodes now carry their resolved IP,
            # so flag IPs that more than one enabled computer resolves to (stale
            # A-record / IP reuse → breaks Kerberos SPN targeting).
            from adscan_internal.services.collector.audit_analyzer import (
                analyze_duplicate_dns_findings,
            )

            result.audit_findings.extend(analyze_duplicate_dns_findings(result))

        if collect_smb or collect_shares:
            from adscan_internal.services.collector.host_collector import (
                HostCollectorConfig,
                _percentile,
            )

            smb_cfg = SMBCollectorConfig(
                domain=target_domain,
                auth_domain=auth_domain,
                dc_address=dc_address,
                username=getattr(credential, "username", None),
                password=getattr(credential, "password", None),
                nt_hash=getattr(credential, "nt_hash", None),
                aes_key=getattr(credential, "aes_key", None),
                ccache_path=getattr(credential, "ccache_path", None),
                use_kerberos=getattr(credential, "use_kerberos", False),
                kdc_ip=auth_kdc,
                posture_sink=posture_sink,
                posture_snapshot=posture_snapshot,
            )
            share_cfg = ShareCollectorConfig(
                domain=target_domain,
                auth_domain=auth_domain,
                dc_address=dc_address,
                username=getattr(credential, "username", None),
                password=getattr(credential, "password", None),
                nt_hash=getattr(credential, "nt_hash", None),
                aes_key=getattr(credential, "aes_key", None),
                ccache_path=getattr(credential, "ccache_path", None),
                use_kerberos=getattr(credential, "use_kerberos", False),
                kdc_ip=auth_kdc,
                posture_sink=posture_sink,
                posture_snapshot=posture_snapshot,
            )
            host_cfg = HostCollectorConfig(
                smb=smb_cfg,
                share=share_cfg,
                collect_samr=collect_smb,
                collect_shares=collect_shares,
                host_progress_callback=host_progress_callback,
                stage_timing_beacon=host_stage_timing_beacon,
                cancellation=host_cancellation,
                scale_gate_callback=scale_gate_callback,
            )
            # Honor an explicit cap from the caller (scan config / web). When 0
            # (default) the field keeps its env-overridable default, preserving
            # the unlimited full sweep.
            if host_cap and host_cap > 0:
                host_cfg.host_cap = int(host_cap)
            # Host-granular Domain-Collection crash-resume (Slice 1). Only wired
            # when a shell is available (the CLI/web scan path); the pure-service
            # callers (lab scripts, unit tests) leave it off and keep byte-for-byte
            # legacy behaviour. The hooks close over ``shell`` + ``result`` +
            # ``self._persistence`` so the host_collector service itself stays
            # shell-free (it only invokes the opaque callables).
            committer = None
            if shell is not None:
                # Engagement scope: the sweep asks this once, before its 445
                # gate, so an excluded computer receives no packet at all.
                host_cfg.scope_partition = self._host_scope_partition(
                    shell, target_domain
                )
                # And once more per computer, right before a worker contacts it:
                # a long sweep is not held to the answer from its start.
                host_cfg.scope_admit = self._host_scope_admit(shell, target_domain)
                committer = self._wire_collection_resume(
                    host_cfg, shell=shell, domain=target_domain,
                    collection_scope=collection_scope, result=result,
                )
            # Seam 1 — REAL host fan-out wall-clock (distinct from the overlapping
            # concurrent negotiate/samr/shares sums). Monotonic per the clock-step
            # doctrine. Only the surrounding timers are added; the call is unchanged.
            _host_wall_start = time.monotonic()
            held: dict[str, Any] = {}
            # The operator-stoppable step (``host_sweep_scope``) spans the sweep
            # and nothing else. Leaving it raises ``ScanAbortRequested`` when the
            # operator chose "stop the scan" during the sweep; that abort is held
            # until this domain's graph is saved (``collect_scope``), so what the
            # sweep found is kept, exactly as when the step wrapped the whole
            # collection. An abort raised from INSIDE the sweep propagates at once.
            sweep_scope = host_sweep_scope() if host_sweep_scope is not None else nullcontext()
            sweep_returned = False
            try:
                with sweep_scope:
                    # The per-host sweep under the collection stage's memory
                    # boundary: its workers stop dispatching when memory crosses
                    # the line, every host already committed stays, and the
                    # boundary declares the hosts left out (the sweep resumes
                    # from them on a larger machine).
                    with memory_bounded(
                        STAGE_COLLECTION,
                        unit="hosts",
                        record=self._collection_stop_recorder(shell, target_domain),
                    ) as sweep_stage:
                        self._run_host_sweep(
                            sweep_stage,
                            held,
                            result=result,
                            host_cfg=host_cfg,
                            committer=committer,
                            shell=shell,
                            target_domain=target_domain,
                        )
                    sweep_returned = True
            except ScanAbortRequested as exc:
                if not sweep_returned:
                    raise
                self._held_scan_abort = exc
            host_timing = held["timing"]
            timing.host_wall = time.monotonic() - _host_wall_start
            # Carry the share-collection abort coverage into domains_data so Phase
            # 7 (SMB Share Exposure), which runs later off the graph and cannot
            # re-derive it, can distinguish an aborted enumeration (incomplete)
            # from a genuine "no shares" result. JSON-safe (list of dicts + int).
            if shell is not None and collect_shares:
                try:
                    domains_data = getattr(shell, "domains_data", None)
                    if isinstance(domains_data, dict):
                        domains_data.setdefault(target_domain, {})[
                            "share_collection"
                        ] = {
                            "aborted_hosts": [
                                {"host": host, "ip": ip}
                                for (host, ip) in host_timing.shares_aborted_hosts
                            ],
                            "reached_hosts": int(host_timing.shares_reached_hosts),
                        }
                except Exception as exc:  # noqa: BLE001 — telemetry must never abort collection
                    telemetry.capture_exception(exc)
                    print_exception(exception=exc)
            # Persist what the host fan-out could NOT examine (unreachable on the
            # 445 gate, per-host budget timeouts) so the run's coverage record can
            # keep host-scoped items from being closed on a host nobody reached.
            # Counts only (JSON-safe ints); read by ``coverage_recorder``.
            if shell is not None:
                try:
                    domains_data = getattr(shell, "domains_data", None)
                    if isinstance(domains_data, dict):
                        _candidates = int(host_timing.candidate_count)
                        _reachable = int(host_timing.reachable_445_count)
                        domains_data.setdefault(target_domain, {})[
                            "host_collection"
                        ] = {
                            "candidates": _candidates,
                            "reachable": _reachable,
                            "unreachable": max(0, _candidates - _reachable),
                            "budget_timeouts": int(host_timing.host_budget_timeouts),
                            # Computers the engagement scope kept out: never a
                            # candidate, never unreachable, never contacted.
                            "outside_scope": int(
                                getattr(host_timing, "skipped_out_of_scope", 0) or 0
                            ),
                        }
                except Exception as exc:  # noqa: BLE001 — telemetry must never abort collection
                    telemetry.capture_exception(exc)
                    print_exception(exception=exc)
                # Which hosts this sweep fully examined (every stage, no error).
                # Only meaningful when every stage was collected: a sweep that
                # skipped SAMR or shares examined no host completely.
                if collect_smb and collect_shares:
                    from adscan_internal.services.engagement.coverage_recorder import (
                        note_collection_hosts,
                    )

                    note_collection_hosts(
                        shell, target_domain, host_timing.examined_host_ids
                    )
                    # Share edges close only on hosts where every share's
                    # security descriptor was read: an unread descriptor
                    # (no admin for SRVSVC level 502) yields no edge, which is
                    # not evidence that the access was removed.
                    from adscan_internal.services.engagement.host_source_observations import (
                        observe_share_acl_reads,
                    )

                    observe_share_acl_reads(
                        shell,
                        target_domain,
                        host_timing.share_acl_examined_host_ids,
                        host_timing.examined_host_ids,
                        swept_hosts=int(getattr(host_timing, "candidate_count", 0) or 0) or None,
                    )
            timing.host_negotiate = host_timing.negotiate
            timing.host_samr = host_timing.samr
            timing.host_shares = host_timing.shares
            # Seams 2 + 3 — propagate the already-measured 445-gate + host
            # distribution fields (gate probe, reachable/candidate counts,
            # concurrency, per-host p50/p95/max, dead-host + budget-timeout counts,
            # outcome histogram). Best-effort: a copy failure never aborts collection.
            try:
                timing.gate_probe = host_timing.gate_probe_ms / 1000.0
                timing.host_count = int(host_timing.candidate_count)
                timing.reachable_445 = int(host_timing.reachable_445_count)
                timing.dead_host_count = max(
                    0,
                    int(host_timing.candidate_count)
                    - int(host_timing.reachable_445_count),
                )
                timing.budget_timeouts = int(host_timing.host_budget_timeouts)
                timing.concurrency = int(getattr(host_cfg, "concurrency", 0) or 0)
                _durations = list(host_timing.per_host_durations or [])
                if _durations:
                    timing.host_p50 = _percentile(_durations, 50)
                    timing.host_p95 = _percentile(_durations, 95)
                    timing.host_max = max(_durations)
                timing.host_outcomes = dict(host_timing.outcome_counts or {})
            except Exception as exc:  # noqa: BLE001 — observability must never abort collection
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
            # Carry the host-enrichment coverage up to the report/web. Populated
            # when the sweep was bounded — an operator early stop (Ctrl+C /
            # platform), a proactive scale-gate decision (cap or skip before the
            # sweep), or an env/scan-config host cap applied inside the sweep.
            # Otherwise stays empty (full coverage) so the surfaces read "100% host
            # enrichment". The three reasons are mutually reconciled here so the CLI
            # records ONE coverage statement.
            if host_timing.early_stopped and host_timing.stop_source == "memory":
                # Stopped at the memory ceiling: the ``resource_coverage`` block
                # states the gap (one sentence, never also the operator-stop
                # one); ``early_stopped`` keeps the sweep resumable.
                timing.host_coverage = {
                    "early_stopped": True,
                    "reason": REASON_MEMORY,
                    "hosts_swept": int(host_timing.swept_before_stop),
                    "hosts_total": int(host_timing.total_dispatch),
                    "hosts_remaining": max(
                        0,
                        int(host_timing.total_dispatch)
                        - int(host_timing.swept_before_stop),
                    ),
                    "source": "memory",
                }
            elif host_timing.early_stopped:
                timing.host_coverage = {
                    "early_stopped": True,
                    "reason": "early_stop",
                    "hosts_swept": int(host_timing.swept_before_stop),
                    "hosts_total": int(host_timing.total_dispatch),
                    "hosts_remaining": max(
                        0,
                        int(host_timing.total_dispatch)
                        - int(host_timing.swept_before_stop),
                    ),
                    "source": host_timing.stop_source or "cli",
                }
            elif host_timing.scale_gate_reason == "skip":
                # Operator declined SMB enrichment before the sweep. No hosts
                # swept of the reachable set; the identity graph is complete.
                reachable = int(host_timing.scale_gate_reachable)
                timing.host_coverage = {
                    "reason": "skip",
                    "hosts_swept": 0,
                    "hosts_total": reachable,
                    "hosts_remaining": reachable,
                    "source": "cli",
                }
            elif host_timing.host_capped or host_timing.scale_gate_reason == "cap":
                # A cap (scale-gate proactive choice, or env/scan-config cap)
                # truncated the representative-first reachable set. ``total_dispatch``
                # is what the sweep enriched; ``capped_skipped`` is the remainder.
                swept = int(host_timing.total_dispatch)
                reachable = swept + int(host_timing.capped_skipped)
                if host_timing.scale_gate_reachable > reachable:
                    reachable = int(host_timing.scale_gate_reachable)
                timing.host_coverage = {
                    "reason": "cap",
                    "hosts_swept": swept,
                    "hosts_total": reachable,
                    "hosts_remaining": max(0, reachable - swept),
                    "source": "cli",
                }
            # One SMB stage deselected while the other ran: whatever bounded the
            # sweep, the deselected stage was collected on no host at all.
            deselected = deselected_host_parts(
                collect_smb=collect_smb, collect_shares=collect_shares
            )
            if deselected and timing.host_coverage.get("reason") != REASON_DESELECTED:
                timing.host_coverage["deselected_parts"] = list(deselected)

            # Second-pass audit: findings that need SMB host data (signing,
            # dialect). Extends the list built by the first-pass analyze_audit_findings().
            from adscan_internal.services.collector.audit_analyzer import (
                analyze_host_audit_findings,
            )
            result.audit_findings.extend(analyze_host_audit_findings(result))
            # Per-host sources a completed sweep can leave unread (the registry
            # of a host where the account is not a local admin, an inconclusive
            # SMBv1 probe): record, per family, on which hosts it was read, so
            # a later run that could not read it never closes its finding.
            if (
                shell is not None
                and result.collection_scope == COLLECTION_SCOPE_FULL_ASSESSMENT
            ):
                from adscan_internal.services.engagement.host_source_observations import (
                    observe_host_sources,
                )

                observe_host_sources(
                    shell,
                    target_domain,
                    list(result.nodes.values()),
                    swept_hosts=int(getattr(host_timing, "candidate_count", 0) or 0) or None,
                )
            # Live observability: SMB/share host collection added host nodes.
            self._report_progress(progress_callback, result)

        return result, timing

    @staticmethod
    def _deselected_host_coverage(
        result: CollectionResult, *, collect_smb: bool, collect_shares: bool
    ) -> dict[str, Any]:
        """The ``host_coverage`` record of an operator-deselected SMB stage.

        ``hosts_total`` is the enabled computer accounts the directory read
        returned (the hosts the sweep would have considered); none was swept for
        the deselected stage. The client statement is worded by
        :mod:`adscan_core.reporting.host_enrichment_coverage`.
        """
        computers = 0
        for node in result.nodes.values():
            if str(getattr(node, "kind", "")) != "Computer":
                continue
            if getattr(node, "enabled", None) is False:
                continue
            computers += 1
        return {
            "reason": REASON_DESELECTED,
            "hosts_swept": 0,
            "hosts_total": computers,
            "hosts_remaining": computers,
            "deselected_parts": list(
                deselected_host_parts(
                    collect_smb=collect_smb, collect_shares=collect_shares
                )
            ),
            "source": "operator",
        }

    def _run_host_sweep(
        self,
        stage: Any,
        held: dict[str, Any],
        *,
        result: CollectionResult,
        host_cfg: Any,
        committer: Any,
        shell: Any,
        target_domain: str,
    ) -> None:
        """Run the per-host sweep; raise the stage's stop when memory ended it.

        The body of the sweep's memory boundary (one call). The sweep runs on a
        worker thread that only asks ``over_line()``; when it stopped for
        memory, the stop is raised here, on the boundary thread, with the hosts
        swept and the hosts it had in front of it.
        """
        from adscan_internal.services.collector.host_collector import (
            collect_domain_hosts,
        )

        host_cfg.memory_guard = stage.guard
        host_timing = None
        sweep_exc: BaseException | None = None
        try:
            host_timing = collect_domain_hosts(result, host_cfg)
        except BaseException as exc:
            sweep_exc = exc
            raise
        finally:
            if committer is not None:
                self._finish_host_commits(
                    shell, target_domain, committer, host_timing, sweep_exc
                )
        held["timing"] = host_timing
        if host_timing.early_stopped and host_timing.stop_source == "memory":
            stage.total = int(host_timing.total_dispatch)
            stage.guard.progress(int(host_timing.swept_before_stop))
            stage.guard.stop_now()

    @staticmethod
    def _directory_committed(shell: Any, domain: str) -> None:
        """Tell the engagement scope that ``domain``'s directory objects are committed.

        Called when a domain's directory stage commits, before the first stage
        that contacts a host. The scope SSOT resolves the entries that waited
        for the directory and reads the record of every host name learned so
        far. Best-effort: an entry that cannot be resolved stays pending, and a
        pending entry keeps the hosts it could name out (the verdict fails
        closed), so a failure here never widens the scope.
        """
        try:
            from adscan_internal.services.engagement_scope import (  # noqa: PLC0415
                on_directory_committed,
            )

            on_directory_committed(shell, domain=domain)
        except Exception as exc:  # noqa: BLE001 - pending entries stay fail-closed
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            return
        try:
            # The scan credential the operator supplied was let in before the
            # scope could place it: it is judged again now that the directory
            # can, and an excluded account ends the run.
            from adscan_internal.services.engagement_scope_principals import (  # noqa: PLC0415
                stop_run_if_controller_excluded,
                stop_run_if_operator_credential_excluded,
            )

            # The same for the controller the operator named: an entry only the
            # directory can match may turn out to be that controller.
            if not stop_run_if_operator_credential_excluded(shell, domain=domain):
                stop_run_if_controller_excluded(shell, domain=domain)
        except Exception as exc:  # noqa: BLE001 - the sign-in guard still refuses it
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    @staticmethod
    def _dc_share_read_in_scope(
        shell: Any,
        result: CollectionResult,
        *,
        target_domain: str,
        dc_address: str,
        dc_fqdn: str | None,
    ) -> bool:
        """May the collection open an SMB session to the domain controller's shares?

        The GPO security templates are read from SYSVOL over SMB, and that is
        how the read is described to the scope SSOT (an SMB tree connect to the
        SYSVOL share, nothing written), so a domain controller the scope keeps
        to directory reads is still read. A refused read is announced as not
        checked, never as "no policy found".

        The domain controller's own directory object (already collected) gives
        the verdict its DN and SID, so a subtree or SID entry needs no lookup.
        Without a session shell there is no engagement to hold the read to.
        """
        if shell is None:
            return True
        from adscan_internal.services.engagement_scope import (  # noqa: PLC0415
            Contact,
            asset_scope_recorded,
            require_host_in_scope,
        )

        if not asset_scope_recorded(shell):
            return True
        host = str(dc_fqdn or dc_address or "").strip()
        wanted = host.rstrip(".").lower()
        host_dn = host_sid = None
        for node in result.nodes.values():
            if getattr(node, "kind", "") != "Computer":
                continue
            dns = str((getattr(node, "properties", None) or {}).get("dnshostname") or "")
            if dns.rstrip(".").lower() == wanted:
                host_dn = str(getattr(node, "distinguished_name", "") or "") or None
                host_sid = str(getattr(node, "object_id", "") or "") or None
                break
        return require_host_in_scope(
            shell,
            host=host,
            connect_address=dc_address,
            contact=Contact("smb", share="SYSVOL"),
            surface="gpo_sysvol_read",
            what="Machine-account password policy read",
            domain=target_domain,
            host_dn=host_dn,
            host_sid=host_sid,
        )

    @staticmethod
    def _host_scope_partition(shell: Any, domain: str) -> Any:
        """The engagement-scope partition the host sweep asks before its 445 gate.

        Bound to the session's scope SSOT. The sweep hands it its computer
        nodes; each is judged with the identity the collector already holds
        (name, resolved address, distinguished name, SID), so a subtree or SID
        entry costs no directory lookup per host. Returns ``(allowed, refused)``.

        SMB host collection (sessions, local groups, shares, registry) is host
        assessment, so nothing narrower is stated about the contact: a domain
        controller the scope keeps to directory reads is not swept.
        """

        def _partition(nodes: list[Any]) -> tuple[list[Any], list[Any]]:
            from adscan_internal.services.collector.smb_collector import (  # noqa: PLC0415
                resolve_target_hostname,
                resolve_target_ip,
            )
            from adscan_internal.services.engagement_scope import (  # noqa: PLC0415
                asset_scope_recorded,
                note_host_addresses_batch,
                partition_targets_in_scope,
            )

            if asset_scope_recorded(shell):
                # The collection just resolved each computer's address: report
                # it, so an entry naming a computer also covers the address a
                # later step (or the socket-level backstop) sees on its own.
                learned: dict[str, list[str]] = {}
                for node in nodes:
                    name = resolve_target_hostname(node)
                    address = str(
                        (getattr(node, "properties", None) or {}).get("ip_address") or ""
                    ).strip()
                    if name and address:
                        learned.setdefault(name, []).append(address)
                note_host_addresses_batch(shell, learned)
            split = partition_targets_in_scope(
                shell,
                nodes,
                key=lambda node: resolve_target_hostname(node) or resolve_target_ip(node) or "",
                address=resolve_target_ip,
                dn=lambda node: getattr(node, "distinguished_name", "") or "",
                sid=lambda node: getattr(node, "object_id", "") or "",
                surface="smb_collection",
                what="SMB collection",
                domain=domain,
            )
            return list(split.allowed), list(split.refused_items)

        return _partition

    @staticmethod
    def _host_scope_admit(shell: Any, domain: str) -> Any:
        """The per-computer scope check a sweep worker makes right before its contact.

        The same verdict as :meth:`_host_scope_partition`, with the same
        identity (name, resolved address, distinguished name, SID), asked for
        ONE computer when it is about to be contacted. The address is reported
        again first, so what the session knows about the host is current. A
        computer the scope keeps out now is recorded like the ones the
        partition left out. ``None``-safe: without an asset scope every
        computer is admitted at the cost of one attribute read.
        """

        def _admit(node: Any) -> bool:
            from adscan_internal.services.collector.smb_collector import (  # noqa: PLC0415
                resolve_target_hostname,
                resolve_target_ip,
            )
            from adscan_internal.services.engagement_scope import (  # noqa: PLC0415
                asset_scope_recorded,
                host_scope_verdict,
                note_host_addresses_batch,
                record_scope_refusals,
            )

            if not asset_scope_recorded(shell):
                return True
            name = resolve_target_hostname(node) or ""
            address = str(resolve_target_ip(node) or "")
            if name and address:
                note_host_addresses_batch(shell, {name: [address]})
            verdict = host_scope_verdict(
                shell,
                host=name or address,
                connect_address=address or None,
                domain=domain,
                host_dn=getattr(node, "distinguished_name", "") or None,
                host_sid=getattr(node, "object_id", "") or None,
            )
            if verdict.allowed:
                return True
            record_scope_refusals(
                shell,
                [(node, verdict)],
                surface="smb_collection",
                domain=domain,
                key=lambda item: resolve_target_hostname(item) or resolve_target_ip(item) or "",
            )
            return False

        return _admit

    def _inspect_machine_password_policy(
        self,
        result: CollectionResult,
        *,
        target_domain: str,
        dc_address: str,
        dc_fqdn: str | None,
        auth_domain: str,
        auth_kdc: str,
        credential: _Credential,
        posture_sink: Optional["PostureSink"],
        posture_snapshot: Optional["DomainPosture"],
    ) -> None:
        """Read the machine-account password rotation policy from GPO SYSVOL.

        Reuses the GPO nodes already collected by the LDAP collector and the
        existing SMB transport (no new collector). Best-effort: any failure leaves
        ``result.machine_password_policy`` unset and emits no finding.
        """
        from adscan_internal.services.collector.audit_analyzer import (
            analyze_machine_rotation_finding,
        )
        from adscan_internal.services.collector.machine_password_policy import (
            collect_machine_password_policy_sync,
        )
        from adscan_internal.services.smb_transport import SMBConfig

        try:
            gpo_specs = [
                (node.name or node.object_id, f"{node.name} {node.distinguished_name}")
                for node in result.nodes.values()
                if node.kind == "GPO"
            ]
            if not gpo_specs:
                return
            use_kerberos = bool(getattr(credential, "use_kerberos", False))
            dc_unc_host = (dc_fqdn or dc_address) if use_kerberos else dc_address
            smb_config = SMBConfig(
                target_ip=dc_address,
                target_hostname=dc_fqdn or dc_address,
                domain=target_domain,
                auth_domain=auth_domain,
                username=getattr(credential, "username", None),
                password=getattr(credential, "password", None),
                nt_hash=getattr(credential, "nt_hash", None),
                aes_key=getattr(credential, "aes_key", None),
                ccache_path=getattr(credential, "ccache_path", None),
                use_kerberos=use_kerberos,
                kdc_ip=auth_kdc or dc_address,
                posture_sink=posture_sink,
                posture_snapshot=posture_snapshot,
            )
            policy = collect_machine_password_policy_sync(
                smb_config=smb_config,
                dc_unc_host=dc_unc_host,
                domain_fqdn=target_domain,
                gpo_specs=gpo_specs,
            )
            if policy is None:
                return
            result.machine_password_policy = policy
            result.audit_findings.extend(analyze_machine_rotation_finding(result))
            print_info_verbose(
                "Machine-account password policy: inspected "
                f"{policy.inspected_gpos} GPO(s), rotation "
                f"{'DISABLED' if policy.disable_password_change else 'enabled'}"
                f"{f', max age {policy.max_age_days}d' if policy.max_age_days else ''}."
            )
        except Exception as exc:  # noqa: BLE001 — best-effort, never break collection
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(f"machine-pwd-policy: inspection failed: {exc}")

    def _wire_collection_resume(
        self,
        host_cfg: Any,
        *,
        shell: Any,
        domain: str,
        collection_scope: str,
        result: "CollectionResult",
    ) -> Any:
        """Attach the host-granular store commit and the resume skip-set to ``host_cfg``.

        Each swept host is committed to the domain's graph store as one unit per
        sweep stage (``store_writer.HostUnitCommitter``), on its own thread, the
        moment it is merged: the unit is the host's facts AND its done-mark, so a
        Ctrl+C or a crash keeps every committed host and nothing else. The skip
        set of a resumed sweep is the store's committed hosts
        (``collection_progress.resumed_done_ids``). ``ADSCAN_COLLECTOR_FRESH``
        begins the sweep's stages ``fresh``. During the sweep the graph is
        exported on the export throttle, so the live view grows.

        Returns the committer (the caller finishes it), or ``None`` when the
        store cannot be opened: the sweep then runs without per-host commits
        and the end-of-domain persist commits its hosts.
        """
        del result
        from adscan_core.graph_store import GraphStoreError
        from adscan_internal.services.collection_progress import (
            collector_fresh_requested,
            mark_collection_running,
            record_hosts_done_count,
            resumed_done_ids,
        )
        from adscan_internal.services.collector.store_writer import (
            HostUnitCommitter,
            LiveExporter,
            smb_stages_for,
            store_writer_for_shell,
        )
        from adscan_internal.services.graph_runtime import export_graph_if_due

        stages = smb_stages_for(
            collect_samr=bool(getattr(host_cfg, "collect_samr", True)),
            collect_shares=bool(getattr(host_cfg, "collect_shares", True)),
        )
        try:
            writer = store_writer_for_shell(shell, domain)
        except GraphStoreError as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            return None
        fresh = collector_fresh_requested()
        # Skip-set for a resumed sweep (empty on a fresh run, after a sweep that
        # completed, or under ``ADSCAN_COLLECTOR_FRESH``).
        host_cfg.resumed_host_ids = resumed_done_ids(shell, domain, stages=stages)
        self._announce_resume(shell=shell, domain=domain)
        scan_type = collection_scope
        host_cap = int(getattr(host_cfg, "host_cap", 0) or 0)
        resumed_count = len(host_cfg.resumed_host_ids or ())
        # The live export during the sweep exists for the platform, the only
        # reader of the file while a scan runs, so it runs only in an unattended
        # run (``adscan ci``, the web worker). It runs throttled on its own
        # single-flight thread: a build of a large graph takes minutes, and on
        # the commit thread it would hold every queued host commit behind it.
        # An interactive scan never pays its GIL contention (a build slowed the
        # partner-shape commits to a p99 of 477 ms; BACKLOG "live graph export
        # in a subprocess").
        from adscan_internal.interaction import is_non_interactive

        exporter = (
            LiveExporter(lambda: export_graph_if_due(shell, domain))
            if is_non_interactive(shell)
            else None
        )

        def _on_commit() -> None:
            # The record's "N of M" stays live for the resume notice and the
            # platform; the export request returns at once.
            record_hosts_done_count(shell, domain, resumed_count + committer.committed)
            if exporter is not None:
                exporter.request()

        committer = HostUnitCommitter(writer, stages=stages, on_commit=_on_commit)
        committer.resumed_count = resumed_count
        committer.live_exporter = exporter  # None in an interactive run
        writer.sweep_owns_smb = True

        def _on_sweep_start(hosts_total: int) -> None:
            mark_collection_running(
                shell,
                domain,
                scan_type=scan_type,
                hosts_total=hosts_total,
                host_cap=host_cap,
            )
            for stage in committer.stages:
                writer.store.begin_stage(stage, units_total=int(hosts_total), fresh=fresh)

        host_cfg.collection_on_sweep_start = _on_sweep_start
        host_cfg.collection_commit_host = committer.submit
        committer.start()
        return committer

    @staticmethod
    def _finish_host_commits(
        shell: Any,
        domain: str,
        committer: Any,
        host_timing: Any,
        sweep_exc: BaseException | None = None,
    ) -> None:
        """Drain the host commits and end the sweep's stages, in a ``finally``.

        ``complete`` for a sweep that ran to its end (a host cap is a coverage
        boundary already declared in the host coverage, recorded as the
        reason), ``stopped`` for an operator stop (``operator_stop``, with the
        stop's source; ``abort_scan`` when the scan was aborted mid-sweep),
        ``skipped`` when the operator declined the sweep before it started,
        ``failed`` when the sweep raised an error.
        Then the graph and its sidecars are exported. Never raises.
        """
        exporter = getattr(committer, "live_exporter", None)
        try:
            drained = committer.close()
            if exporter is not None:
                # No new live export; one already running finishes on its own.
                exporter.stop()
            if sweep_exc is not None and not isinstance(sweep_exc, Exception):
                committer.end_stages(
                    "stopped", reason="abort_scan", detail=type(sweep_exc).__name__
                )
            elif host_timing is None:
                committer.end_stages(
                    "failed",
                    reason="sweep_error",
                    detail=type(sweep_exc).__name__ if sweep_exc is not None else "",
                )
            elif getattr(host_timing, "early_stopped", False) and (
                getattr(host_timing, "stop_source", "") == "memory"
            ):
                committer.end_stages("stopped", reason=REASON_MEMORY)
            elif getattr(host_timing, "early_stopped", False):
                committer.end_stages(
                    "stopped",
                    reason="operator_stop",
                    detail=str(getattr(host_timing, "stop_source", "") or "cli"),
                )
            elif getattr(host_timing, "scale_gate_reason", "") == "skip":
                committer.end_stages("skipped", reason="operator_skip")
            elif not drained or committer.failed:
                committer.end_stages(
                    "failed",
                    reason="host_commit_failed",
                    detail=f"{committer.failed} host(s) not committed",
                )
            else:
                capped = bool(getattr(host_timing, "host_capped", False)) or (
                    getattr(host_timing, "scale_gate_reason", "") == "cap"
                )
                # A sweep that covered every in-scope host is complete: the
                # computers the engagement scope excludes are a boundary the
                # client asked for, declared in the stage record (and in
                # ``scope.json``), never an incomplete sweep.
                from adscan_internal.services.engagement_scope import (  # noqa: PLC0415
                    HOST_OUTSIDE_ASSET_SCOPE,
                )

                outside = int(getattr(host_timing, "skipped_out_of_scope", 0) or 0)
                reason = "host_cap" if capped else (HOST_OUTSIDE_ASSET_SCOPE if outside else "")
                detail = (
                    f"{outside} computer(s) excluded from the engagement scope, not contacted"
                    if outside
                    else ""
                )
                if outside and bool(getattr(host_timing, "all_out_of_scope", False)):
                    # Every computer was excluded: the sweep never started, so
                    # its stages are a declared skip, not a completed read.
                    committer.end_stages(
                        "skipped", reason=HOST_OUTSIDE_ASSET_SCOPE, detail=detail
                    )
                else:
                    committer.end_stages("complete", reason=reason, detail=detail)
            from adscan_internal.services.collection_progress import (
                record_hosts_done_count,
            )
            from adscan_internal.services.graph_runtime import export_graph_if_due

            record_hosts_done_count(
                shell, domain, int(getattr(committer, "resumed_count", 0)) + committer.committed
            )
            # Throttled: the one forced export of the collection runs when the
            # last domain's last stage ends (``_persist_cross_domain_edges``).
            # Skipped while a live export is still building, so two builds of
            # one graph never run at once.
            if exporter is None or not exporter.busy():
                export_graph_if_due(shell, domain)
            if committer.commit_seconds:
                ordered = sorted(committer.commit_seconds)
                print_info_debug(
                    "collector-timing host-commit "
                    f"hosts={committer.committed} failed={committer.failed} "
                    f"median_ms={ordered[len(ordered) // 2] * 1000:.1f} "
                    f"p99_ms={ordered[min(len(ordered) - 1, int(len(ordered) * 0.99))] * 1000:.1f} "
                    f"max_ms={ordered[-1] * 1000:.1f}"
                )
        except Exception as exc:  # noqa: BLE001 — finishing must never mask the sweep's outcome
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    @staticmethod
    def _announce_resume(*, shell: Any, domain: str) -> None:
        """Print the calm resume notice when a prior session already enriched hosts.

        No-op unless there is a genuine resume: an empty skip-set (a fresh or
        finished workspace, or an ``ADSCAN_COLLECTOR_FRESH`` re-scan) yields no
        counts and no output, so a fresh run is byte-for-byte unchanged. When a
        prior interrupted session left enriched hosts behind, one calm info panel
        states the memory and the plan — what was already done, what continues
        now, and the single explicit action to re-scan everything instead. Advise
        and continue: never a prompt, identical interactive and non-interactive
        (in ``adscan ci`` the line lands in the log so a resume is on record).
        Best-effort: a render glitch never breaks the sweep.
        """
        from adscan_internal.services.collection_progress import (
            COLLECTOR_FRESH_ENV,
            resume_notice_counts,
        )

        try:
            counts = resume_notice_counts(shell, domain)
            if counts is None:
                return
            already_done, total, remaining = counts
            print_info(
                f"Resuming host enrichment. A previous session already enriched "
                f"{already_done:,} of {total:,} hosts; continuing with the "
                f"{remaining:,} remaining.",
                panel=True,
                icon="🔄",
                items=[
                    f"To re-scan every host from scratch instead, "
                    f"start with {COLLECTOR_FRESH_ENV}=1.",
                ],
            )
        except Exception as exc:  # noqa: BLE001 — the notice must never break collection
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    @staticmethod
    def _finalize_collection_progress(
        shell: Any, domain: str, timing: "CollectionTiming"
    ) -> None:
        """Flip / flush the ``collection_progress`` record after the end-of-sweep persist.

        Called AFTER ``persist`` has written the full partial graph (ordering:
        graph first, then the record). Only acts on a record left ``running`` by
        the sweep — a no-op when collection did not run or was already finalized.
        A clean finish marks it ``complete`` so the reload offer stops; an operator
        early-stop keeps it ``running`` with the full done-set so a reload resumes
        only the remaining hosts. Best-effort: never raises.
        """
        try:
            from adscan_internal.services.collection_progress import (
                STATUS_RUNNING,
                checkpoint_collection_progress,
                mark_collection_complete,
                read_collection_progress,
            )

            if read_collection_progress(shell, domain).get("status") != STATUS_RUNNING:
                return
            coverage = getattr(timing, "host_coverage", None) or {}
            if coverage.get("reason") == REASON_DESELECTED:
                # The sweep did not run this time (both SMB stages deselected),
                # so an earlier interrupted sweep is still unfinished: keep its
                # record so a later run with SMB selected resumes it.
                return
            early_stopped = bool(
                (getattr(timing, "host_coverage", None) or {}).get("early_stopped")
            )
            if early_stopped:
                # Flush the done-set (now matching the just-persisted graph) but
                # keep the record ``running`` so the sweep can be resumed.
                checkpoint_collection_progress(shell, domain)
            else:
                mark_collection_complete(shell, domain)
        except Exception as exc:  # noqa: BLE001 — finalize is best-effort
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    def collect_scope(
        self,
        *,
        shell: Any,
        scopes: list[DomainScope],
        credential: _Credential,
        use_ldaps: bool = True,
        collection_scope: str = COLLECTION_SCOPE_DOMAIN_COMPROMISE,
        collect_smb: bool = True,
        collect_shares: bool = True,
        posture_sink: Optional["PostureSink"] = None,
        posture_snapshot: Optional["DomainPosture"] = None,
        progress_callback: Callable[[int], None] | None = None,
        host_progress_callback: "Callable[[HostPhaseProgress], None] | None" = None,
        host_stage_timing_beacon: (
            "Callable[[HostPhaseTiming, int, int], None] | None"
        ) = None,
        host_cancellation: "HostSweepCancellation | None" = None,
        host_cap: int = 0,
        scale_gate_callback: "Callable[[int], Any] | None" = None,
        host_sweep_scope: "Callable[[], Any] | None" = None,
    ) -> tuple[
        dict[str, dict[str, int]],
        dict[str, "CollectionResult"],
        dict[str, "CollectionTiming"],
    ]:
        """Collect all scopes in sequence, persist each, and resolve cross-domain FSPs.

        ``progress_callback`` is an optional observability hook. When supplied it
        is invoked at collection-phase boundaries with the running object count
        (graph nodes pulled so far) so the caller can surface live mid-run
        motion. It defaults to None (no-op), leaving collection byte-for-byte
        identical to a run without it.

        ``host_sweep_scope`` (see :meth:`collect_domain`) wraps each domain's
        per-host SMB sweep only. A scan stop the operator chose inside it is
        raised here, after the domain's graph is saved.
        """
        self._held_scan_abort = None
        results: dict[str, CollectionResult] = {}
        counters: dict[str, dict[str, int]] = {}
        timings: dict[str, CollectionTiming] = {}
        for scope in scopes:
            result, timing = self.collect_domain(
                target_domain=scope.domain,
                auth_domain=scope.auth_domain,
                dc_address=scope.dc_address,
                auth_kdc=scope.auth_kdc,
                credential=credential,
                kerberos_target_hostname=scope.kerberos_target_hostname,
                use_ldaps=use_ldaps,
                collection_scope=collection_scope,
                collect_smb=collect_smb,
                collect_shares=collect_shares,
                posture_sink=posture_sink,
                posture_snapshot=posture_snapshot,
                output_dir=self._domain_output_dir(shell, scope.domain),
                progress_callback=progress_callback,
                host_progress_callback=host_progress_callback,
                host_stage_timing_beacon=host_stage_timing_beacon,
                host_cancellation=host_cancellation,
                host_cap=host_cap,
                scale_gate_callback=scale_gate_callback,
                shell=shell,
                # The AD CS registry probe needs a proven CA-host administrator;
                # CAs without one on the LDAP pass are finished below, after the
                # persist that lets the graph resolve roles.
                defer_ca_registry_rerun=True,
                host_sweep_scope=host_sweep_scope,
            )
            results[scope.domain] = result
            timings[scope.domain] = timing
            from adscan_internal.services.collector.well_known_sids import (
                inject_well_known_sid_nodes,
            )

            injected = inject_well_known_sid_nodes(result)
            if injected:
                print_info_debug(
                    f"[orchestrator] injected {injected} well-known SID node(s) "
                    f"for {scope.domain}"
                )
            # Seam 7 — persist wall-clock (monotonic). Only the timer is added; the
            # persist call itself is unchanged.
            _persist_start = time.monotonic()
            with collection_stage_progress(shell, label=STAGE_GRAPH_SAVE):
                counters[scope.domain] = self._persist(
                    shell, domain=scope.domain, result=result
                )
            # AD CS registry probe, second pass: the graph just persisted now
            # resolves roles the LDAP pass could not see (a local administrator
            # of the CA host found by the SMB sweep). Every deferred CA is
            # recorded once here, as its own store unit.
            from adscan_internal.services.adcs.ca_registry_rerun import (
                rerun_pending_ca_registry_probes,
            )

            # The late reads commit their own ``adcs_ca_registry`` units and
            # export; nothing is persisted again here.
            rerun_pending_ca_registry_probes(
                shell, domain=scope.domain, result=result, dc_ip=scope.dc_address
            )
            # Patch-level CVE checks, second pass: a host the run's CVE scan left
            # not assessed (its registry refused the scan credential) is read
            # again now that the persisted graph may prove an administrator of it
            # (the privileged refresh after a domain compromise, a local admin
            # found by the SMB sweep). No-op until a CVE scan ran in this run.
            if shell is not None:
                from adscan_internal.services.cve_scanner.patch_level_rerun import (
                    rerun_not_assessed_patch_level_checks,
                )

                rerun_not_assessed_patch_level_checks(
                    shell, domain=scope.domain, dc_ip=scope.dc_address
                )
            timing.persist = time.monotonic() - _persist_start
            # The domain was collected and persisted in THIS run: the coverage
            # record may now trust the directory read for it.
            from adscan_internal.services.engagement.coverage_recorder import (
                note_collection_ran,
            )

            note_collection_ran(shell, scope.domain)
            # Host-granular Domain-Collection resume: the end-of-sweep persist
            # above wrote the full partial graph, so finalize the checkpoint now
            # (ordering: graph first, then the record). A clean sweep flips to
            # ``complete`` so the reload offer stops; an early-stopped sweep stays
            # ``running`` with the full done-set so a reload resumes the remainder.
            self._finalize_collection_progress(shell, scope.domain, timing)
            if self._held_scan_abort is not None:
                # The operator stopped the scan during this domain's sweep: its
                # graph is saved, so honour the stop now (no further domain).
                break
        self._resolve_cross_domain_references(results)
        with collection_stage_progress(shell, label=STAGE_GRAPH_SAVE):
            self._persist_cross_domain_edges(shell, results, counters)
        held_abort, self._held_scan_abort = self._held_scan_abort, None
        if held_abort is not None:
            raise held_abort
        return counters, results, timings

    def _persist_cross_domain_edges(
        self,
        shell: Any,
        results: dict[str, "CollectionResult"],
        counters: dict[str, dict[str, int]],
    ) -> None:
        """The collection's ONE forced export: every collected domain, at the end.

        Every earlier export of the collection (the directory stages, the live
        export of the host sweep, the AD CS re-run, the sweep's end) is
        throttled; this is where each domain's ``attack_graph.json`` and its
        sidecars are made current, after the last stage of the last domain. A
        domain's build also resolves a foreign endpoint through the other
        domains' stores and derives the trust escalations
        (``graph_build/passes/trusts``), so a domain exported before its partner
        was collected is rewritten here; a file already current is not.
        """
        from adscan_internal.services.graph_runtime import (
            export_graph_if_due,
            graph_store_for,
        )

        for domain in results:
            try:
                export_graph_if_due(shell, domain, force=True)
                store = graph_store_for(shell, domain, create=False)
                record = store.last_export() if store is not None else None
                if record is not None:
                    counters.setdefault(domain, {}).update(
                        {"nodes": int(record.nodes), "edges": int(record.edges)}
                    )
            except Exception as exc:  # noqa: BLE001 — a re-export failure must not abort collection
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                print_info_debug(
                    f"[orchestrator] cross-domain re-export failed for "
                    f"{mark_sensitive(domain, 'domain')}"
                )

    @staticmethod
    def _domain_output_dir(shell: Any, domain: str) -> str | None:
        """Return the workspace domain dir for persisting Phase 2 artifacts.

        Mirrors the path Phase 3 (``cli/nmap``) and ``CollectorPersistence``
        use: ``<workspace>/<domains_dir>/<domain>/``. Returns None when the
        workspace dir is unavailable so the resolver stays in-memory only.
        """
        workspace_cwd = (
            shell._get_workspace_cwd()  # noqa: SLF001
            if hasattr(shell, "_get_workspace_cwd")
            else getattr(shell, "current_workspace_dir", "")
        )
        if not workspace_cwd:
            return None
        domains_dir = getattr(shell, "domains_dir", "domains")
        return domain_subpath(workspace_cwd, domains_dir, domain)

    def _resolve_cross_domain_references(
        self, results: dict[str, CollectionResult]
    ) -> None:
        """Resolve FSP SIDs across collected domains.

        For each FSP placeholder in every collected result:
        - If the SID exists as a real node in any other collected result → mark resolved.
        - If the SID's foreign domain is in scope but the SID is not found → create a
          ForeignSecurityPrincipal placeholder node with degraded_reason
          ``"not_found_in_scope"``.
        - If the SID's foreign domain is not in scope at all → create a
          ForeignSecurityPrincipal placeholder node with degraded_reason
          ``"domain_out_of_scope"``.
        """
        from adscan_internal.services.collector.models import (
            CollectorNode,
        )  # local to avoid circular

        # Build a flat SID → node map across all collected results.
        all_nodes: dict[str, CollectorNode] = {}
        for r in results.values():
            all_nodes.update(r.nodes)

        in_scope_domains = {d.lower() for d in results}

        for domain, result in results.items():
            resolved: list[str] = []
            for fsp_sid, foreign_domain in list(result.fsp_placeholders.items()):
                fsp_sid_upper = fsp_sid.upper()

                if fsp_sid_upper in all_nodes:
                    # Real node found across any collected domain — mark resolved.
                    result.fsp_placeholders[fsp_sid] = "RESOLVED"
                    resolved.append(fsp_sid)
                    print_info_debug(
                        f"[orchestrator] FSP resolved "
                        f"{mark_sensitive(fsp_sid, 'domain')} "
                        f"in {mark_sensitive(domain, 'domain')}"
                    )
                    continue

                # No real node found — determine degraded reason.
                if foreign_domain.lower() in in_scope_domains:
                    degraded_reason = "not_found_in_scope"
                else:
                    degraded_reason = "domain_out_of_scope"

                placeholder = CollectorNode(
                    object_id=fsp_sid_upper,
                    kind="ForeignSecurityPrincipal",
                    name=f"FSP[{fsp_sid_upper}]",
                    domain=foreign_domain,
                    properties={
                        "is_placeholder": True,
                        "degraded_reason": degraded_reason,
                    },
                )
                result.add_node(placeholder)
                result.fsp_placeholders[fsp_sid] = f"degraded:{degraded_reason}"
                print_info_debug(
                    f"[orchestrator] FSP unresolved ({degraded_reason}) "
                    f"{mark_sensitive(fsp_sid, 'domain')} "
                    f"foreign_domain={mark_sensitive(foreign_domain, 'domain')} "
                    f"in {mark_sensitive(domain, 'domain')}"
                )
