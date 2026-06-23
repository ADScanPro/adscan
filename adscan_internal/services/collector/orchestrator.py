"""Multi-domain collection orchestrator."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol, TYPE_CHECKING

if TYPE_CHECKING:
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
    ) -> tuple[CollectionResult, CollectionTiming]:
        """Collect a single domain and return the raw result with per-phase timing.

        When ``output_dir`` is supplied it is the workspace domain directory the
        Phase 2 DNS resolver persists ``massdns_resolution_report.json`` into;
        when None the resolver stays in-memory only (no file written).
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
            )
            host_timing = collect_domain_hosts(result, host_cfg)
            timing.host_negotiate = host_timing.negotiate
            timing.host_samr = host_timing.samr
            timing.host_shares = host_timing.shares

            # Second-pass audit: findings that need SMB host data (signing,
            # dialect). Extends the list built by the first-pass analyze_audit_findings().
            from adscan_internal.services.collector.audit_analyzer import (
                analyze_host_audit_findings,
            )
            result.audit_findings.extend(analyze_host_audit_findings(result))

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
    ) -> tuple[
        dict[str, dict[str, int]],
        dict[str, "CollectionResult"],
        dict[str, "CollectionTiming"],
    ]:
        """Collect all scopes in sequence, persist each, and resolve cross-domain FSPs."""
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
