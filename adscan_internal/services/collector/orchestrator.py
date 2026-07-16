"""Multi-domain collection orchestrator."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Protocol, TYPE_CHECKING

if TYPE_CHECKING:
    from adscan_internal.services.collector.host_collector import HostPhaseProgress
    from adscan_internal.services.collector.host_sweep_cancellation import (
        HostSweepCancellation,
    )
    from adscan_internal.services.domain_posture import DomainPosture
    from adscan_internal.services.posture_sink import PostureSink

from adscan_core import telemetry
from adscan_internal.rich_output import (
    mark_sensitive,
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
from adscan_internal.services.collector.ldap_collector import ADscanLDAPCollector
from adscan_internal.services.collector.models import CollectionResult
from adscan_internal.services.collector.persistence import CollectorPersistence
from adscan_internal.services.collector.smb_collector import SMBCollectorConfig
from adscan_internal.services.collector.share_collector import ShareCollectorConfig
from adscan_internal.workspaces import domain_subpath


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


class CollectionOrchestrator:
    """Orchestrates LDAP collection across one or more domain scopes."""

    def __init__(self, *, ldap_collector: Any = None, persistence: Any = None) -> None:
        self._ldap_collector = ldap_collector or ADscanLDAPCollector()
        self._persistence = persistence or CollectorPersistence()

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
        collection_scope: str = "ctf",
        collect_smb: bool = True,
        collect_shares: bool = True,
        posture_sink: Optional["PostureSink"] = None,
        posture_snapshot: Optional["DomainPosture"] = None,
        output_dir: str | None = None,
        progress_callback: Callable[[int], None] | None = None,
        host_progress_callback: "Callable[[HostPhaseProgress], None] | None" = None,
        host_cancellation: "HostSweepCancellation | None" = None,
        host_cap: int = 0,
        shell: Any = None,
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
        """
        timing = CollectionTiming()
        print_info_verbose(
            f"Collecting domain {mark_sensitive(target_domain, 'domain')}..."
        )

        _t = time.monotonic()
        result = self._ldap_collector.collect(
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
        )
        timing.adcs = result.adcs_elapsed
        timing.ldap = time.monotonic() - _t - timing.adcs
        # Live observability: the LDAP pass pulled the bulk of the graph nodes.
        self._report_progress(progress_callback, result)

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
        if collection_scope == "audit":
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
                collect_domain_hosts,
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
                cancellation=host_cancellation,
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
            if shell is not None:
                self._wire_collection_resume(
                    host_cfg, shell=shell, domain=target_domain,
                    collection_scope=collection_scope, result=result,
                )
            host_timing = collect_domain_hosts(result, host_cfg)
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
            timing.host_negotiate = host_timing.negotiate
            timing.host_samr = host_timing.samr
            timing.host_shares = host_timing.shares
            # Carry the operator early-stop coverage up to the report/web. Only
            # populated when the sweep was halted early; otherwise stays empty
            # (full coverage) so the surfaces read "100% host enrichment".
            if host_timing.early_stopped:
                timing.host_coverage = {
                    "early_stopped": True,
                    "hosts_swept": int(host_timing.swept_before_stop),
                    "hosts_total": int(host_timing.total_dispatch),
                    "hosts_remaining": max(
                        0,
                        int(host_timing.total_dispatch)
                        - int(host_timing.swept_before_stop),
                    ),
                    "source": host_timing.stop_source or "cli",
                }

            # Second-pass audit: findings that need SMB host data (signing,
            # dialect). Extends the list built by the first-pass analyze_audit_findings().
            from adscan_internal.services.collector.audit_analyzer import (
                analyze_host_audit_findings,
            )
            result.audit_findings.extend(analyze_host_audit_findings(result))
            # Live observability: SMB/share host collection added host nodes.
            self._report_progress(progress_callback, result)

        return result, timing

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
            print_info_debug(f"machine-pwd-policy: inspection failed: {exc}")

    def _wire_collection_resume(
        self,
        host_cfg: Any,
        *,
        shell: Any,
        domain: str,
        collection_scope: str,
        result: "CollectionResult",
    ) -> None:
        """Attach the host-granular Domain-Collection crash-resume hooks to ``host_cfg``.

        Builds the three fan-out callbacks (sweep-start marker, per-host done
        recorder, mid-sweep graph checkpoint) plus the resume skip-set, closing
        over ``shell`` / ``domain`` / ``result`` / ``self._persistence`` so the pure
        host_collector service never touches the shell/workspace SSOT. All hooks
        are best-effort; the SSOT helpers are themselves fail-open.
        """
        from adscan_internal.services.collection_progress import (
            checkpoint_collection_progress,
            mark_collection_running,
            mark_host_done,
            resumed_done_ids,
        )

        # Skip-set for a reload that hit a prior interrupted sweep (empty on a
        # fresh run — a non-``running`` record yields no skips).
        host_cfg.resumed_host_ids = resumed_done_ids(shell, domain)
        scan_type = "audit" if collection_scope == "audit" else "ctf"
        host_cap = int(getattr(host_cfg, "host_cap", 0) or 0)

        def _on_sweep_start(hosts_total: int) -> None:
            mark_collection_running(
                shell,
                domain,
                scan_type=scan_type,
                hosts_total=hosts_total,
                host_cap=host_cap,
            )

        def _mark_host_done(object_id: str) -> None:
            mark_host_done(shell, domain, object_id)

        def _checkpoint() -> None:
            # Ordering is load-bearing: persist the partial graph FIRST so no
            # done-id is ever flushed for a host whose edges are not yet on disk
            # (a resume would otherwise skip it and silently drop its enrichment).
            # Reuses the SAME ``persist`` the end-of-sweep path calls (load-then-
            # merge, re-entrant) — no duplicate persist logic.
            try:
                self._persistence.persist(shell, domain=domain, result=result)
            except Exception as exc:  # noqa: BLE001 — a failed persist must not flush the done-set
                telemetry.capture_exception(exc)
                return
            checkpoint_collection_progress(shell, domain)

        host_cfg.collection_on_sweep_start = _on_sweep_start
        host_cfg.collection_mark_host_done = _mark_host_done
        host_cfg.collection_checkpoint = _checkpoint

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

    def collect_scope(
        self,
        *,
        shell: Any,
        scopes: list[DomainScope],
        credential: _Credential,
        use_ldaps: bool = True,
        collection_scope: str = "ctf",
        collect_smb: bool = True,
        collect_shares: bool = True,
        posture_sink: Optional["PostureSink"] = None,
        posture_snapshot: Optional["DomainPosture"] = None,
        progress_callback: Callable[[int], None] | None = None,
        host_progress_callback: "Callable[[HostPhaseProgress], None] | None" = None,
        host_cancellation: "HostSweepCancellation | None" = None,
        host_cap: int = 0,
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
        """
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
                host_cancellation=host_cancellation,
                host_cap=host_cap,
                shell=shell,
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
            counters[scope.domain] = self._persistence.persist(
                shell, domain=scope.domain, result=result
            )
            # Host-granular Domain-Collection resume: the end-of-sweep persist
            # above wrote the full partial graph, so finalize the checkpoint now
            # (ordering: graph first, then the record). A clean sweep flips to
            # ``complete`` so the reload offer stops; an early-stopped sweep stays
            # ``running`` with the full done-set so a reload resumes the remainder.
            self._finalize_collection_progress(shell, scope.domain, timing)
        self._resolve_cross_domain_references(results)
        return counters, results, timings

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
