"""Native Phase 1 orchestration for collection and inventory artifacts."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from adscan_internal import telemetry
from adscan_internal.rich_output import (
    mark_sensitive,
    print_error,
    print_info_debug,
    print_info_verbose,
)
from adscan_internal.services.attack_graph_service import load_attack_graph
from adscan_internal.services.collector.orchestrator import (
    CollectionOrchestrator,
    CollectionTiming,
    DomainScope,
)
from adscan_internal.services.collector.audit_analyzer import (
    _days_since_filetime as _ft_to_days,
)
from adscan_internal.services.graph_queries import (
    get_enabled_computers,
    get_enabled_users,
)

if TYPE_CHECKING:
    from adscan_core.rich_output_collection import TacticalFinding
    from adscan_core.rich_output_collection import TacticalFindings


@dataclass(frozen=True)
class CollectionCredential:
    """Credential material consumed by CollectionOrchestrator."""

    username: str | None
    password: str | None
    use_kerberos: bool
    ccache_path: str | None = None
    aes_key: str | None = None


def build_collection_credential(
    shell: Any,
    domain: str,
    *,
    auth_username: str | None = None,
    auth_password: str | None = None,
    use_kerberos: bool | None = None,
    ccache_path: str | None = None,
    aes_key: str | None = None,
) -> CollectionCredential:
    """Extract collector credentials from shell domain metadata."""
    domain_data = _domain_data(shell, domain)
    auth_mode = str(domain_data.get("auth") or "").strip().lower()
    return CollectionCredential(
        username=auth_username or domain_data.get("username") or None,
        password=auth_password or domain_data.get("password") or None,
        use_kerberos=(auth_mode == "kerberos")
        if use_kerberos is None
        else use_kerberos,
        ccache_path=ccache_path or domain_data.get("ccache_path") or None,
        aes_key=aes_key or domain_data.get("aes_key") or None,
    )


def _domain_data(shell: Any, domain: str) -> dict[str, Any]:
    data = getattr(shell, "domains_data", {}).get(domain, {})
    return data if isinstance(data, dict) else {}


def _has_collection_credential(domain_data: dict[str, Any]) -> bool:
    """Return True when domain metadata has material usable for LDAP collection."""
    return bool(
        domain_data.get("username")
        and (
            domain_data.get("password")
            or domain_data.get("ccache_path")
            or domain_data.get("aes_key")
        )
    )


def _resolve_auth_domain(
    shell: Any, target_domain: str, auth_domain: str | None
) -> str:
    """Resolve the credential domain for native graph collection."""
    explicit_domain = str(auth_domain or "").strip().lower()
    if explicit_domain:
        return explicit_domain

    target_data = _domain_data(shell, target_domain)
    stored_auth_domain = str(target_data.get("auth_domain") or "").strip().lower()
    if stored_auth_domain:
        return stored_auth_domain
    if _has_collection_credential(target_data):
        return target_domain

    current_domain = str(getattr(shell, "domain", "") or "").strip().lower()
    if current_domain and _has_collection_credential(
        _domain_data(shell, current_domain)
    ):
        return current_domain

    return target_domain


def _prepare_native_kerberos_credential(
    shell: Any,
    target_domain: str,
    auth_domain: str,
    credential: CollectionCredential,
    *,
    requested_use_kerberos: bool | None,
) -> CollectionCredential:
    """Prefer Kerberos when ADscan can prepare a ticket for native collection."""
    if requested_use_kerberos is False or not credential.username:
        return credential

    ensure_kerberos = getattr(shell, "_ensure_kerberos_environment_for_command", None)
    if not callable(ensure_kerberos):
        return credential

    try:
        kerberos_ready = bool(
            ensure_kerberos(
                target_domain,
                auth_domain,
                credential.username,
                "adscan-native-graph -k",
            )
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(f"[intelligence] Kerberos preparation failed: {exc}")
        return credential

    if not kerberos_ready:
        return credential

    auth_domain_data = _domain_data(shell, auth_domain)

    # If the credential already carries its OWN ccache, use it directly.
    if credential.ccache_path:
        return CollectionCredential(
            username=credential.username,
            password=None,
            use_kerberos=True,
            ccache_path=credential.ccache_path,
            aes_key=credential.aes_key or auth_domain_data.get("aes_key") or None,
        )

    # Otherwise mint/get a ccache for THIS EXACT principal from its stored secret
    # (a password, or an NT hash / AES key recovered via DCSync), posture-aware
    # (AES etype + correct salt when AES is enforced). Never fall back to another
    # principal's active ccache (the domain's "active" ccache_path or KRB5CCNAME,
    # which after a DA step is the DA's ticket) — doing so silently re-attributes
    # the whole collection and its sessions to the wrong user. That was the
    # daenerys-labelled refresh actually authenticating as administrator. This is
    # the single-source-of-truth ensure_user_ccache exists to enforce.
    from adscan_internal.services.kerberos_ticket_service import ensure_user_ccache

    dc_ip = str(auth_domain_data.get("pdc") or "").strip() or None
    user_ccache: str | None = None
    try:
        user_ccache = ensure_user_ccache(
            shell,
            user=credential.username,
            domain=auth_domain,
            credential=credential.password or None,  # None -> look up stored hash/AES
            dc_ip=dc_ip,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            "native collection: ensure_user_ccache failed for "
            f"{mark_sensitive(credential.username, 'user')}: {exc}"
        )

    if not user_ccache:
        # Could not mint a ccache for this exact principal. Do NOT hijack another
        # principal's active ccache — return the original credential so the
        # transport authenticates as THIS user via its own secret (inline TGT /
        # NTLM), correctly attributed.
        print_info_debug(
            "native collection: no per-user ccache minted for "
            f"{mark_sensitive(credential.username, 'user')}; using its own credential "
            "(not another principal's active ccache)"
        )
        return credential

    return CollectionCredential(
        username=credential.username,
        password=None,
        use_kerberos=True,
        ccache_path=user_ccache,
        aes_key=credential.aes_key or auth_domain_data.get("aes_key") or None,
    )


def _resolve_dc_info(shell: Any, domain: str) -> tuple[str, str | None]:
    """Return DC IP and optional hostname for a domain."""
    domain_data = _domain_data(shell, domain)
    dc_ip = str(domain_data.get("pdc") or "").strip()
    if not dc_ip:
        raise RuntimeError(
            f"No PDC/DC IP configured for domain {mark_sensitive(domain, 'domain')}"
        )
    dc_hostname = str(domain_data.get("pdc_hostname") or "").strip() or None
    return dc_ip, dc_hostname


def run_native_collection(
    shell: Any,
    target_domain: str,
    *,
    auth_username: str | None = None,
    auth_password: str | None = None,
    auth_domain: str | None = None,
    use_kerberos: bool | None = None,
    ccache_path: str | None = None,
    aes_key: str | None = None,
) -> list[str]:
    """Collect and persist native graph artifacts for one Phase 1 domain."""
    try:
        dc_ip, dc_hostname = _resolve_dc_info(shell, target_domain)
        domain_data = _domain_data(shell, target_domain)
        resolved_auth_domain = _resolve_auth_domain(shell, target_domain, auth_domain)
        auth_domain_data = _domain_data(shell, resolved_auth_domain)
        credential = build_collection_credential(
            shell,
            resolved_auth_domain,
            auth_username=auth_username,
            auth_password=auth_password,
            use_kerberos=use_kerberos,
            ccache_path=ccache_path,
            aes_key=aes_key,
        )
        credential = _prepare_native_kerberos_credential(
            shell,
            target_domain,
            resolved_auth_domain,
            credential,
            requested_use_kerberos=use_kerberos,
        )
        auth_kdc = str(
            domain_data.get("auth_kdc") or auth_domain_data.get("pdc") or dc_ip
        )
        scope = DomainScope(
            domain=target_domain,
            dc_address=dc_ip,
            auth_domain=resolved_auth_domain,
            auth_kdc=auth_kdc,
            kerberos_target_hostname=dc_hostname,
        )

        started = time.time()
        workspace_type = str(getattr(shell, "type", "ctf") or "ctf").lower()
        collection_scope = "audit" if workspace_type == "audit" else "ctf"
        from adscan_internal import get_console
        from adscan_internal.cli.widgets.intelligence_update import (
            render_intelligence_update,
        )
        from adscan_internal.services.domain_posture import get_posture
        from adscan_internal.services.posture_sink import (
            make_workspace_posture_sink,
        )

        posture_sink = make_workspace_posture_sink(
            shell.domains_data,
            on_finding=lambda finding: get_console().print(
                render_intelligence_update(finding)
            ),
        )
        posture_snapshot = get_posture(shell.domains_data, domain=target_domain)

        from adscan_internal.cli._collection_selector import (
            prompt_collection_selection,
        )

        selection = prompt_collection_selection(shell, target_domain)
        # Persist the MSSQL toggle for later re-collection triggers (e.g. the
        # ask_for_user_privs followup re-running the collector for a new
        # credential). The Phase-2 MSSQL collector below is gated directly on
        # ``selection.collect_mssql``; the SMB toggles are consumed inline.
        try:
            domain_data["_collect_mssql"] = bool(selection.collect_mssql)
        except Exception:  # noqa: BLE001 — selection persistence is best-effort
            pass

        counters, collection_results, domain_timings = (
            CollectionOrchestrator().collect_scope(
                shell=shell,
                scopes=[scope],
                credential=credential,
                collection_scope=collection_scope,
                collect_smb=selection.collect_samr,
                collect_shares=selection.collect_shares,
                posture_sink=posture_sink,
                posture_snapshot=posture_snapshot,
            )
        )
        elapsed = time.time() - started
        domain_counters = counters.get(target_domain, {})
        timing = domain_timings.get(target_domain, CollectionTiming())
        print_info_verbose(
            "[intelligence] native collection complete "
            f"domain={mark_sensitive(target_domain, 'domain')} "
            f"nodes={domain_counters.get('nodes', 0)} "
            f"edges={domain_counters.get('edges', 0)} "
            f"elapsed={elapsed:.1f}s "
            f"| ldap={timing.ldap:.1f}s "
            f"adcs={timing.adcs:.1f}s "
            f"host={timing.host_total:.1f}s "
            f"(neg={timing.host_negotiate:.1f}s "
            f"samr={timing.host_samr:.1f}s "
            f"shares={timing.host_shares:.1f}s) "
            f"dns={timing.dns:.1f}s "
            f"post={timing.post_processing:.1f}s"
        )
        _emit_collection_performance_telemetry(
            shell, target_domain, domain_counters, timing
        )
        collector_result = collection_results.get(target_domain)
        _print_collection_summary_from_graph(shell, target_domain, elapsed)
        _print_collector_enrichment_panel(collector_result, target_domain)
        _persist_collector_findings(shell, target_domain, collector_result)
        _persist_machine_pwd_rotation_interval(shell, target_domain, collector_result)
        _populate_adcs_metadata(shell, target_domain, collector_result)
        # Unified Phase-2 reachability: now that the graph (and enabled_computers)
        # exist, run the single nmap port scan that feeds every collector + the
        # post-auth sweeps + the Phase-3 reachability UI. render=False (Phase 3
        # presents from the persisted report), auto=True (no operator prompt).
        # ADSCAN_NO_PORT_SCAN opts out → collectors keep their existing async
        # floor and Phase 3 falls back to its legacy operator-prompted scan.
        # Best-effort: a scan failure must never abort collection.
        _run_phase2_port_scan(shell, target_domain)
        # MSSQL authorization collector — Phase-2 peer that consumes the
        # mssql/ips.txt the scan just produced. Uses the already-built
        # CollectionCredential (incl. ccache) so the SSOT detects Kerberos
        # correctly. Gated by the operator's collector selection.
        if getattr(selection, "collect_mssql", True):
            _run_phase2_mssql_collection(shell, target_domain, credential)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error(f"Native collection failed: {exc}")
    return []


def _run_phase2_port_scan(shell: Any, target_domain: str) -> None:
    """Run the unified Phase-2 nmap port scan that feeds every collector + sweep.

    Writes ``enabled_computers.txt`` from the freshly built graph, then runs the
    important-port scan producer (``render=False``, ``auto=True``) so every
    ``{service}/ips.txt`` and ``network_reachability_report.json`` exist before
    the MSSQL collector / post-auth sweeps / Phase-3 Host Inventory consume them.

    The scan is additive — the SMB collector keeps its own async 445 floor inside
    ``collect_scope`` (unchanged). Opt-out via ``ADSCAN_NO_PORT_SCAN``: the scan is
    skipped entirely, collectors keep their existing async-connect behavior, and
    Phase-3 Host Inventory falls back to its legacy operator-prompted scan.

    Best-effort: any failure is captured and swallowed — it must never abort
    collection.
    """
    import os

    if os.getenv("ADSCAN_NO_PORT_SCAN"):
        print_info_debug(
            "[phase2-scan] ADSCAN_NO_PORT_SCAN set; skipping the unified nmap "
            f"port scan for {mark_sensitive(target_domain, 'domain')} "
            "(collectors fall back to their async-connect floor)."
        )
        return
    try:
        from adscan_internal.workspaces import DEFAULT_DOMAIN_LAYOUT, domain_subpath

        graph = load_attack_graph(shell, target_domain)
        hosts = [
            _host_inventory_name(computer, target_domain)
            for computer in get_enabled_computers(graph, target_domain)
        ]
        hosts = [host for host in hosts if host]
        if not hosts:
            print_info_debug(
                "[phase2-scan] no enabled computers in the graph for "
                f"{mark_sensitive(target_domain, 'domain')}; skipping port scan."
            )
            return

        workspace_cwd = getattr(shell, "current_workspace_dir", None) or os.getcwd()
        computers_file = domain_subpath(
            workspace_cwd, shell.domains_dir, target_domain, "enabled_computers.txt"
        )
        nmap_dir = domain_subpath(
            workspace_cwd,
            shell.domains_dir,
            target_domain,
            DEFAULT_DOMAIN_LAYOUT.nmap,
        )
        os.makedirs(os.path.dirname(computers_file), exist_ok=True)
        os.makedirs(nmap_dir, exist_ok=True)

        # Write enabled_computers.txt directly (deduped) WITHOUT going through
        # shell._process_computers_list, which would itself trigger the scan and
        # the reachability render — we run the scan ourselves with render=False.
        seen: set[str] = set()
        deduped: list[str] = []
        for host in hosts:
            key = host.strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            deduped.append(host.strip())
        with open(computers_file, "w", encoding="utf-8") as handle:
            handle.write("\n".join(deduped) + "\n" if deduped else "")

        print_info_debug(
            "[phase2-scan] running unified important-port scan for "
            f"{mark_sensitive(target_domain, 'domain')} "
            f"({len(deduped)} enabled computers)."
        )
        # render=False: Phase-3 Host Inventory presents the summary from the
        # persisted report. auto=True: no operator confirmation prompt.
        shell.convert_hostnames_to_ips_and_scan(
            target_domain, computers_file, nmap_dir, render=False, auto=True
        )
    except Exception as exc:  # noqa: BLE001 — scan failure must not abort collection
        telemetry.capture_exception(exc)
        print_info_debug(
            "[phase2-scan] unified port scan failed for "
            f"{mark_sensitive(target_domain, 'domain')}: {exc}"
        )


def _run_phase2_mssql_collection(
    shell: Any,
    target_domain: str,
    credential: "CollectionCredential",
) -> None:
    """Run the MSSQL authorization collector as a Phase-2 peer (after the scan).

    Consumes ``mssql/ips.txt`` (produced by :func:`_run_phase2_port_scan`) and the
    already-built :class:`CollectionCredential`. The secret is resolved
    ccache-first (``ccache_path`` → ``password`` → ``aes_key``); the SSOT
    (:func:`run_mssql_authorization_collection`) detects a ``.ccache`` path and
    forces Kerberos. This fixes the prior bug where the Phase-3 wrapper read empty
    ``shell.username`` / ``shell.password`` under ccache auth and skipped MSSQL.

    Best-effort: any failure is captured and swallowed.
    """
    try:
        username = (credential.username or "").strip()
        secret = (
            credential.ccache_path or credential.password or credential.aes_key or ""
        )
        if not username or not secret:
            print_info_debug(
                "[mssql-collector] no held credential for "
                f"{mark_sensitive(target_domain, 'domain')}; skipping authorization "
                "collection."
            )
            return
        from adscan_internal.cli.privileges import run_mssql_authorization_collection

        run_mssql_authorization_collection(
            shell,
            domain=target_domain,
            username=username,
            password=secret,
        )
    except Exception as exc:  # noqa: BLE001 — MSSQL collection must not abort the phase
        telemetry.capture_exception(exc)
        print_info_debug(
            "[mssql-collector] Phase-2 authorization collection failed for "
            f"{mark_sensitive(target_domain, 'domain')}: {exc}"
        )


def _emit_collection_performance_telemetry(
    shell: Any,
    domain: str,
    counters: dict[str, int],
    timing: "CollectionTiming",
) -> None:
    try:
        from adscan_internal.cli.common import build_lab_event_fields

        properties: dict[str, Any] = {
            "domain": mark_sensitive(domain, "domain"),
            "nodes": counters.get("nodes", 0),
            "edges": counters.get("edges", 0),
            **timing.as_dict(),
        }
        try:
            properties.update(build_lab_event_fields(shell=shell, include_slug=False))
        except Exception:  # noqa: BLE001
            pass
        telemetry.capture("native_collection_performance", properties)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)


def _persist_collector_findings(
    shell: Any,
    domain: str,
    result: Any,
) -> None:
    """Write collector findings to technical_report.json."""
    if result is None:
        return
    try:
        from adscan_core.reporting.technical_report import record_technical_finding
    except ImportError:
        return

    def _safe_record(**kwargs: Any) -> None:
        try:
            record_technical_finding(shell, domain, **kwargs)
        except Exception as exc:  # noqa: BLE001
            from adscan_internal import telemetry as _tel

            _tel.capture_exception(exc)
            print_info_debug(f"[intelligence] technical finding persist failed: {exc}")

    # ── Shadow credentials ────────────────────────────────────────────────
    shadow = getattr(result, "shadow_credential_findings", None) or []
    if shadow:
        _safe_record(
            key="shadow_credentials_present",
            details={
                "count": len(shadow),
                "objects": [
                    {
                        "samaccountname": f.samaccountname,
                        "kind": f.kind,
                        "key_count": f.key_count,
                        "distinguished_name": f.distinguished_name,
                    }
                    for f in shadow
                ],
            },
        )

    # ── Audit findings (audit scope only) ─────────────────────────────────
    audit = getattr(result, "audit_findings", None) or []
    if not audit:
        return

    by_cat: dict[str, list[Any]] = {}
    for f in audit:
        by_cat.setdefault(f.category, []).append(f)

    # Map audit-finding categories to canonical vuln_catalog keys.
    # Note: prior aliases (stale_user_accounts, pwd_never_expires_accounts,
    # obsolete_operating_systems) were duplicates of canonical keys with
    # divergent CVSS scores — collapsed to a single source of truth here.
    _CAT_KEY = {
        "stale_user": "stale_enabled_users",
        "pwd_never_expires": "password_never_expires",
        "pwd_predates_policy": "stale_passwords",
        "passwd_notreqd": "password_not_required",
        "krbtgt_age": "krbtgt_password_age",
        "machine_quota_risk": "machine_account_quota_risk",
        "obsolete_os": "obsolete_computers",
        "stale_computer": "stale_enabled_computers",
        "duplicate_dns_fqdn": "duplicate_computer_dns",
        "machine_pwd_rotation_disabled": "machine_password_rotation_disabled",
        "machine_pwd_rotation_relaxed": "machine_password_rotation_relaxed",
        "smb_v1_enabled": "smb_v1_enabled",
        "smb_signing_disabled": "smb_signing_disabled",
        "rc4_only": "rc4_only_accounts",
        "weak_password_policy": "weak_password_policy",
    }

    for category, findings in by_cat.items():
        vuln_key = _CAT_KEY.get(category)
        if not vuln_key:
            continue
        details: dict[str, Any] = {
            "count": len(findings),
            "severity_summary": findings[0].severity if findings else "",
            "accounts": [
                {
                    "samaccountname": f.samaccountname,
                    "object_id": f.object_id,
                    "detail": f.detail,
                }
                for f in findings
            ],
        }
        # Surface the structured observed values (e.g. the concrete password
        # policy knobs for ``weak_password_policy``) into the finding details
        # so the report/web can compare observed-vs-recommended per knob.
        # Findings without structured observation carry an empty dict.
        observed = next(
            (dict(f.observed) for f in findings if getattr(f, "observed", None)),
            None,
        )
        if observed:
            details["observed"] = observed
        _safe_record(
            key=vuln_key,
            details=details,
        )


def _persist_machine_pwd_rotation_interval(shell: Any, domain: str, result: Any) -> None:
    """Stash the recovered machine-password rotation interval into domains_data.

    Lets the Timeroast threshold use the real GPO value instead of the 30d default.
    Only stored when a GPO sets an explicit max age AND rotation is NOT disabled —
    a disabled-rotation domain intentionally leaves it unset so the low default
    keeps every stale machine a candidate (coverage). Best-effort.
    """
    try:
        policy = getattr(result, "machine_password_policy", None)
        if policy is None:
            return
        domain_data = shell.domains_data.setdefault(domain, {})
        max_age = getattr(policy, "max_age_days", None)
        disabled = bool(getattr(policy, "disable_password_change", False))
        if isinstance(max_age, int) and max_age > 0 and not disabled:
            domain_data["machine_pwd_rotation_days"] = max_age
        else:
            domain_data.pop("machine_pwd_rotation_days", None)
        domain_data["machine_pwd_rotation_disabled"] = disabled
    except Exception as exc:  # noqa: BLE001 — best-effort persistence
        telemetry.capture_exception(exc)


def _populate_adcs_metadata(shell: Any, domain: str, result: Any) -> None:
    """Bridge Phase 2 ADCS collection into the Phase 3 metadata cache.

    Phase 2 (native domain collection) already enumerates CAs/templates into
    the graph. This extracts the enrollment server + CA name from the
    ALREADY-COLLECTED result and writes the same ``domains_data[domain]`` ADCS
    flags Phase 3 sets, so the Phase 3 metadata step consumes this verdict
    instead of re-running a second ``ADCSCollector.collect()`` (same dedup
    pattern applied to massdns). When ``result`` is ``None`` (no native
    collection ran) the flags are left absent and Phase 3 still falls back.
    """
    try:
        from adscan_internal.cli.adcs import populate_adcs_metadata_from_collection

        populate_adcs_metadata_from_collection(shell, domain=domain, result=result)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[intelligence] ADCS metadata populate failed for "
            f"{mark_sensitive(domain, 'domain')}: {exc}"
        )


def _print_collection_summary_from_graph(
    shell: Any, domain: str, elapsed: float
) -> None:
    """Render collection counters from the persisted attack graph."""
    try:
        from adscan_core.rich_output_collection import (
            CollectionSummary,
            print_collection_summary,
        )

        graph = load_attack_graph(shell, domain)
        nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
        edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
        kind_counts: dict[str, int] = {}
        for node in nodes.values():
            kind = str(node.get("kind") or "Unknown")
            kind_counts[kind] = kind_counts.get(kind, 0) + 1

        acl_relations = {
            "AllExtendedRights",
            "GenericAll",
            "GenericWrite",
            "WriteDACL",
            "WriteOwner",
        }
        print_collection_summary(
            CollectionSummary(
                domain=domain,
                users=kind_counts.get("User", 0),
                computers=kind_counts.get("Computer", 0),
                groups=kind_counts.get("Group", 0),
                ous=kind_counts.get("OU", 0),
                gpos=kind_counts.get("GPO", 0),
                memberof_edges=sum(
                    1 for edge in edges if edge.get("relation") == "MemberOf"
                ),
                acl_edges=sum(
                    1 for edge in edges if edge.get("relation") in acl_relations
                ),
                gplink_edges=sum(
                    1 for edge in edges if edge.get("relation") == "GPLink"
                ),
                trustedby_edges=sum(
                    1 for edge in edges if edge.get("relation") == "TrustedBy"
                ),
                elapsed_seconds=elapsed,
            )
        )
        _print_tactical_findings(domain, nodes, edges)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(f"[intelligence] collection summary failed: {exc}")


def _print_tactical_findings(
    domain: str,
    nodes: dict[str, Any],
    edges: list[dict[str, Any]],
) -> None:
    """Build and render the post-collection tactical findings panel."""
    try:
        from adscan_core.rich_output_collection import print_tactical_findings

        tf = _build_tactical_findings(domain, nodes, edges)
        print_tactical_findings(tf)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(f"[intelligence] tactical findings failed: {exc}")


# Relations that produce tactical findings (excludes pure graph topology edges)
_TACTICAL_RELATIONS: frozenset[str] = frozenset(
    {
        "DCSync",
        "GetChangesAll",
        "GetChanges",
        "GetChangesInFilteredSet",
        "GenericAll",
        "WriteDACL",
        "WriteOwner",
        "Owns",
        "AllExtendedRights",
        "GenericWrite",
        "ForceChangePassword",
        "AddMember",
        "AddSelf",
        "ReadLAPSPassword",
        "SyncLAPSPassword",
        "ReadGMSAPassword",
        "WriteSPN",
        "AddKeyCredentialLink",
        "HasShadowCredentials",
        "HasSession",
        "AdminTo",
        "CanRDP",
        "CanPSRemote",
        "ReadShare",
        "WriteShare",
        "FullControlShare",
        "WriteAccountRestrictions",
        "WriteLogonScript",
        "AllowedToDelegate",
        "ManageRODCPrp",
    }
)
_CONTAINER_SCOPE_RELATIONS: frozenset[str] = frozenset(
    {
        "ReadLAPSPassword",
        "SyncLAPSPassword",
    }
)
_CONTAINER_SCOPE_KINDS: frozenset[str] = frozenset({"OU", "Container"})
_CONTROL_ACL_RELATIONS: frozenset[str] = frozenset(
    {
        "AllExtendedRights",
        "GenericAll",
        "GenericWrite",
        "WriteDACL",
        "WriteOwner",
        "Owns",
        "ForceChangePassword",
        "AddMember",
        "AddSelf",
        "WriteSPN",
        "AddKeyCredentialLink",
        "WriteAccountRestrictions",
        "WriteLogonScript",
        "AllowedToDelegate",
        "ManageRODCPrp",
    }
)
_NOISY_WELL_KNOWN_CONTROL_SOURCES: frozenset[str] = frozenset(
    {
        "creator owner",
        "principal self",
    }
)
_NOISY_EXTENDED_RIGHTS_SOURCES: frozenset[str] = frozenset(
    {
        "authenticated users",
        "everyone",
        "principal self",
    }
)

# High-value target kinds — findings targeting these always float to the top
_HIGH_VALUE_KINDS: frozenset[str] = frozenset({"Domain", "Group", "Computer", "User"})

# Privileged group name fragments that mark a target as high-value
_PRIVILEGED_GROUP_FRAGMENTS: tuple[str, ...] = (
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "account operators",
    "backup operators",
    "print operators",
    "server operators",
    "domain controllers",
    "group policy creator",
    "dns admins",
    "protected users",
)


def _print_collector_enrichment_panel(
    result: Any,
    domain: str,
) -> None:
    """Render post-collection enrichment panels from CollectionResult.

    Shows Shadow Credentials, RC4-only kerberoast priority targets, and
    (audit mode only) domain hygiene findings. Each panel is shown only when
    relevant data exists.
    """
    try:
        from adscan_internal.services.collector.models import (
            CollectionResult as _CollectionResult,
        )

        if not isinstance(result, _CollectionResult):
            return
    except Exception:
        return

    from rich.table import Table

    from adscan_internal.rich_output import (
        BRAND_COLORS,
        print_panel,
        print_panel_with_table,
    )

    marked_domain = mark_sensitive(domain, "domain")

    # ── Panel 1: Shadow Credentials ──────────────────────────────────────────
    shadow_findings = list(result.shadow_credential_findings or [])
    if shadow_findings:
        table = Table(
            show_header=True,
            header_style="bold red",
            show_edge=False,
            pad_edge=False,
        )
        table.add_column("Object", style="white", min_width=28)
        table.add_column("Kind", style="dim", width=10)
        table.add_column("Keys", justify="right", style="red bold", width=5)
        table.add_column("Action", style="yellow")
        for f in shadow_findings:
            marked_sam = mark_sensitive(f.samaccountname, "user")
            action = (
                "pkinit → getnthash"
                if f.kind == "User"
                else "investigate (WHfB or backdoor?)"
            )
            table.add_row(marked_sam, f.kind, str(f.key_count), action)
        print_panel(
            f"[bold]{len(shadow_findings)} object(s)[/bold] have existing "
            f"[bold red]msDS-KeyCredentialLink[/bold red] entries on "
            f"{marked_domain}.\n"
            "These allow PKINIT authentication → NT hash retrieval "
            "[bold]without knowing the account password[/bold].\n"
            "Legitimate entries exist only when WHfB is deployed via GPO.",
            title="[bold red]Shadow Credentials Detected[/bold red]",
            border_style=BRAND_COLORS["error"],
        )
        print_panel_with_table(
            table,
            title=f"Shadow Credential Targets ({len(shadow_findings)})",
            border_style=BRAND_COLORS["error"],
        )

    # ── Panel 2: RC4-only Kerberoast Priority ────────────────────────────────
    rc4_nodes = [
        node
        for node in result.nodes.values()
        if node.kind in ("User", "Computer")
        and node.properties.get("rc4_only")
        and node.properties.get("hasspn")
    ]
    if rc4_nodes:
        table = Table(
            show_header=True,
            header_style="bold yellow",
            show_edge=False,
            pad_edge=False,
        )
        table.add_column("Account", style="white", min_width=28)
        table.add_column("Kind", style="dim", width=10)
        table.add_column("SPNs", justify="right", style="cyan", width=5)
        table.add_column("Pwd Age (days)", justify="right", style="red")
        for node in rc4_nodes:
            spns = node.properties.get("serviceprincipalnames") or []
            pwdlastset = node.properties.get("pwdlastset")
            days_val = _ft_to_days(pwdlastset)
            pwd_days = str(int(days_val)) if days_val is not None else ""
            table.add_row(
                mark_sensitive(node.samaccountname, "user"),
                node.kind,
                str(len(spns)),
                pwd_days,
            )
        print_panel(
            f"[bold]{len(rc4_nodes)}[/bold] SPN-bearing account(s) lack AES "
            f"encryption support on {marked_domain}.\n"
            "RC4 Kerberos tickets crack [bold yellow]significantly faster[/bold "
            "yellow] than AES offline. Prioritise these in kerberoasting.",
            title="[bold yellow]RC4-Only Kerberoast Priority[/bold yellow]",
            border_style=BRAND_COLORS["warning"],
        )
        print_panel_with_table(
            table,
            title=f"RC4-Only SPN Accounts ({len(rc4_nodes)})",
            border_style=BRAND_COLORS["warning"],
        )

    # ── Panel 3: Audit Findings (audit scope only) ───────────────────────────
    audit_findings = list(result.audit_findings or [])
    domain_policy = result.domain_policy

    if result.collection_scope == "audit" and (audit_findings or domain_policy):
        # Severity badges with fixed-width text + colour. Two-track signal
        # so the panel stays usable under NO_COLOR / colourblind operators
        # (the badge text alone communicates severity), while the colour
        # reinforces it for everyone else. Width is uniform so badges
        # column-align without table machinery.
        severity_colors = {
            "critical": "[bold red]CRITICAL[/bold red]",
            "high":     "[red]HIGH    [/red]",
            "medium":   "[yellow]MEDIUM  [/yellow]",
            "low":      "[cyan]LOW     [/cyan]",
            "info":     "[dim]INFO    [/dim]",
        }
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

        # Single-section layout: every actionable observation goes into
        # the Findings list. The legacy "Domain Policy" section was a
        # symptom of an inconsistent contract — half of its rows were
        # already classified findings by ``audit_analyzer.py`` (e.g. MAQ
        # as LOW), the rest (account lockout, min length, complexity)
        # were rendered here but never persisted to ``technical_report.json``
        # and never reached the catalogued vuln list. The new
        # ``weak_password_policy`` consolidated finding closes that gap
        # so password-policy weaknesses now travel end-to-end (panel →
        # technical_report → PDF).
        finding_lines: list[str] = []
        footer_lines: list[str] = []

        # Categories that are noise here because the same data is already
        # the headline of another finding. Currently empty since the
        # consolidation of MAQ + password-policy made every category
        # carry distinct signal.
        _DUPLICATE_OF_OTHER_FINDING: set[str] = set()

        category_labels = {
            "stale_user": "Stale enabled users (>90d no logon)",
            "stale_computer": "Stale enabled computers (>90d no logon)",
            "pwd_never_expires": "Password never expires",
            "pwd_predates_policy": "Passwords older than current policy",
            "passwd_notreqd": "PASSWD_NOTREQD (no password required)",
            "krbtgt_age": "Krbtgt password age",
            "machine_quota_risk": "Machine Account Quota risk",
            "obsolete_os": "Obsolete operating systems",
            "smb_v1_enabled": "SMBv1 protocol enabled",
            "smb_signing_disabled": "SMB signing not required",
            "duplicate_dns_fqdn": "Duplicate computer DNS (multiple FQDNs → one IP)",
            "machine_pwd_rotation_disabled": "Machine password rotation disabled (GPO)",
            "machine_pwd_rotation_relaxed": "Machine password rotation relaxed (GPO)",
            "rc4_only": "RC4-only accounts",
            "weak_password_policy": "Weak password policy",
            "pwd_policy_never_modified": "Password policy never modified",
        }
        # Denominator sets for contextual X/total display.
        _USER_HYGIENE_CATS = {"stale_user", "pwd_never_expires", "pwd_predates_policy", "passwd_notreqd"}
        _COMPUTER_HYGIENE_CATS = {"obsolete_os", "smb_signing_disabled", "smb_v1_enabled", "stale_computer"}
        total_enabled_users = sum(
            1 for n in result.nodes.values()
            if n.kind == "User" and n.enabled
            and not str(n.samaccountname).endswith("$")
        )
        total_computers = sum(
            1 for n in result.nodes.values() if n.kind == "Computer"
        )

        by_category: dict[str, list] = {}
        for f in audit_findings:
            by_category.setdefault(f.category, []).append(f)

        # Pre-compiled at module scope would be cleaner but keeping the
        # regex local makes the krbtgt special-case self-contained — the
        # only consumer is this branch.
        _KRBTGT_AGE_DAYS_RE = re.compile(r"(\d+)\s+days")

        for cat, items in sorted(
            by_category.items(),
            key=lambda x: min(severity_order.get(f.severity, 9) for f in x[1]),
        ):
            if cat in _DUPLICATE_OF_OTHER_FINDING:
                continue
            label = category_labels.get(cat, cat)
            worst_sev = min(items, key=lambda f: severity_order.get(f.severity, 9)).severity
            sev = severity_colors.get(worst_sev, worst_sev)
            count = len(items)

            if cat == "machine_quota_risk":
                # MAQ is a domain-wide finding; the count is always 1 and
                # adds no signal. The interesting value is the MAQ itself
                # (extracted from the finding detail, format set by
                # ``audit_analyzer.py``: ``ms-DS-MachineAccountQuota = N — …``).
                # When we cannot parse it, fall back to the consequence
                # text so the row still reads correctly.
                first = items[0]
                m = re.search(r"=\s*(\d+)", first.detail or "")
                if m:
                    count_str = (
                        f"[bold]{m.group(1)}[/bold] "
                        f"[dim]— any domain user can join computers[/dim]"
                    )
                else:
                    count_str = (
                        "[bold]MAQ > 0[/bold] "
                        "[dim]— any domain user can join computers[/dim]"
                    )
            elif cat == "weak_password_policy":
                # Composite finding — the value is the enumeration of
                # active sub-issues, persisted in ``detail`` by
                # ``_analyze_weak_password_policy`` with format
                # ``Weak Default Domain Password Policy — <issue> · <issue>``.
                # Trim the prefix so the headline reads cleanly inline.
                first = items[0]
                sub_part = (first.detail or "").split("— ", 1)[-1]
                if sub_part and sub_part != (first.detail or ""):
                    count_str = (
                        f"[bold]{sub_part}[/bold]"
                    )
                else:
                    count_str = (
                        f"[bold]{count}[/bold] sub-issue(s)"
                    )
            elif cat == "krbtgt_age":
                # krbtgt is a single-object finding; the count is always 1
                # and adds no signal. The *interesting* number is "how
                # many days since rotation" — that lives in the finding's
                # detail string (``audit_analyzer.py``). Parse it out and
                # render it directly so the operator sees the rotation
                # gap, not a meaningless ``1``.
                days_ago: int | None = None
                for item in items:
                    m = _KRBTGT_AGE_DAYS_RE.search(item.detail or "")
                    if m:
                        try:
                            days_ago = int(m.group(1))
                            break
                        except (TypeError, ValueError):
                            continue
                if days_ago is not None:
                    count_str = (
                        f"[bold]{days_ago}[/bold] days "
                        f"[dim]since last rotation (>180d recommended)[/dim]"
                    )
                else:
                    # Defensive fallback when audit_analyzer changes the
                    # detail format. The finding still surfaces; just
                    # without the headline number.
                    count_str = f"[bold]{count}[/bold] [dim](rotation overdue)[/dim]"
            elif cat in _USER_HYGIENE_CATS and total_enabled_users > 0:
                count_str = f"[bold]{count}[/bold][dim]/{total_enabled_users} enabled users[/dim]"
            elif cat in _COMPUTER_HYGIENE_CATS and total_computers > 0:
                count_str = f"[bold]{count}[/bold][dim]/{total_computers} computers[/dim]"
            else:
                count_str = f"[bold]{count}[/bold]"

            hv_count = sum(1 for f in items if f.highvalue)
            hv_suffix = (
                f"  [red]({hv_count} privileged)[/red]" if hv_count > 0 else ""
            )
            finding_lines.append(f"{sev}  {label}: {count_str}{hv_suffix}")

        # ── Footer: contextual metadata (not findings) ─────────────────
        # The last password-policy attribute change date is contextual:
        # useful for the auditor to know but not actionable on its own
        # (the operator decides whether a multi-year-old policy is
        # concerning given the engagement scope). Render it dim and
        # under the findings list so it never competes for attention
        # with a real finding.
        if domain_policy is not None:
            pwd_last_changed = getattr(domain_policy, "pwd_policy_last_changed", None)
            if pwd_last_changed:
                footer_lines.append(
                    f"[dim]Password policy attributes last modified: "
                    f"{pwd_last_changed[:10]}[/dim]"
                )

        # Single-section render. ``Findings`` is the only header — any
        # contextual metadata lives in the dim footer.
        summary_lines: list[str] = []
        if finding_lines:
            summary_lines.append(
                f"[bold]Findings ({len(finding_lines)})[/bold]"
            )
            summary_lines.extend(f"  {line}" for line in finding_lines)
        if footer_lines:
            if summary_lines:
                summary_lines.append("")  # blank line before footer
            summary_lines.extend(footer_lines)

        if summary_lines:
            # Panel title MUST NOT carry sensitivity markers. Rich `Panel`
            # measures the title width *before* the real console's
            # ``MarkerStrippingTextIO`` removes the zero-width characters
            # from the write path, so the border drawing (╭ ╮) gets
            # misaligned by the count of invisible markers — the panel
            # appears "broken" at the corners. The domain is still
            # sanitised end-to-end: the at-export regex in
            # ``_sanitize_rich_output`` matches ``[A-Za-z0-9._-]+\.<tld>``
            # tokens anywhere in the recording, including panel titles,
            # so removing the markers here costs no telemetry coverage.
            print_panel(
                "\n".join(summary_lines),
                title=(
                    f"[bold blue]Domain Hygiene Audit — {domain}[/bold blue]"
                ),
                border_style=BRAND_COLORS["info"],
            )
    elif result.collection_scope != "audit":
        print_info_verbose(
            "[collector] Audit findings skipped — scope is ctf. "
            "Use audit workspace type for hygiene checks."
        )


def _node_display_name(node: dict[str, Any]) -> str:
    props = node.get("properties") or {}
    display_name = str(props.get("display_name") or "").strip()
    if display_name:
        return display_name
    for key in ("samaccountname", "dnshostname", "name"):
        v = str(props.get(key) or "").strip()
        if v:
            if v.upper().endswith("@WELLKNOWN"):
                return v.rsplit("@", 1)[0]
            return v
    fallback = str(node.get("name") or node.get("label") or "").strip()
    if fallback.upper().endswith("@WELLKNOWN"):
        return fallback.rsplit("@", 1)[0]
    return fallback


def _node_is_high_value(node: dict[str, Any]) -> bool:
    if node.get("highvalue"):
        return True
    kind = str(node.get("kind") or "")
    if kind == "Domain":
        return True
    if kind == "Group":
        name = _node_display_name(node).casefold()
        return any(frag in name for frag in _PRIVILEGED_GROUP_FRAGMENTS)
    return False


def _normalized_tactical_principal_name(value: str) -> str:
    """Return a stable comparison key for tactical principal names."""
    name = str(value or "").strip().casefold()
    if "@" in name:
        name = name.rsplit("@", 1)[0].strip()
    return " ".join(name.split())


def _is_noisy_tactical_control_edge(
    *,
    relation: str,
    source_node: dict[str, Any],
    target_node: dict[str, Any],
) -> bool:
    """Return True for default/schema ACL rows that should not lead tactical UX."""
    if relation not in _CONTROL_ACL_RELATIONS:
        return False

    source_name = _normalized_tactical_principal_name(_node_display_name(source_node))
    if source_name in _NOISY_WELL_KNOWN_CONTROL_SOURCES:
        return True
    if (
        relation == "AllExtendedRights"
        and source_name in _NOISY_EXTENDED_RIGHTS_SOURCES
    ):
        return True

    target_kind = str(target_node.get("kind") or "")
    return target_kind in _CONTAINER_SCOPE_KINDS


def _filter_container_scope_findings(
    findings: list["TacticalFinding"],
) -> list["TacticalFinding"]:
    """Hide inherited container-scope rows when concrete targets are present."""
    concrete_sources: set[tuple[str, str]] = {
        (finding.right, finding.source.casefold())
        for finding in findings
        if finding.right in _CONTAINER_SCOPE_RELATIONS
        and finding.target_type not in _CONTAINER_SCOPE_KINDS
    }
    if not concrete_sources:
        return findings
    return [
        finding
        for finding in findings
        if not (
            finding.right in _CONTAINER_SCOPE_RELATIONS
            and finding.target_type in _CONTAINER_SCOPE_KINDS
            and (finding.right, finding.source.casefold()) in concrete_sources
        )
    ]


# ---------------------------------------------------------------------------
# Severity classification — fourth canonical dimension (2026-05-02)
# ---------------------------------------------------------------------------
#
# Each TacticalFinding gets a canonical Severity computed by
# adscan_internal.services.severity.compute_edge_severity. Severity is a pure
# function of (source.compromise_class, target.compromise_class, edge_kind,
# target_is_tier0_asset, target_is_domain) — never a property of the relation
# label. This is the rule that removes the 444-CRIT noise observed on HTB
# Forest where >95% of entries were tautologies of the AD hierarchy.
#
# Reference: adscan-obsidian/business/12_nomenclature_standard.md
#            § "Severidad de edges — cuarta dimensión canónica".

# Group-name fragments → CompromiseClass. Comparison is case-insensitive over
# the node display name (samaccountname / name / label).
_DOMAIN_BREAKER_GROUPS: frozenset[str] = frozenset(
    name.lower()
    for name in (
        "Domain Admins",
        "Enterprise Admins",
        "Administrators",
        "BUILTIN\\Administrators",
        "Domain Controllers",
        "Enterprise Domain Controllers",
        "Read-only Domain Controllers",
        "krbtgt",
    )
)

_TIER0_ASSET_NAME_FRAGMENTS: tuple[str, ...] = (
    # Exchange role markers (server name conventions / CN suffixes)
    "exchange",
    # ADCS CA hosts often include these tokens; the ADCS CA target is
    # typically detected via the ``isTierZero`` system tag, but name-based
    # detection is the fallback.
    "-ca",
    "ca01",
    "ca02",
    "rootca",
    "issuingca",
)


# Well-known SIDs that are Tier 0 by definition (Domain Breakers).
_DOMAIN_BREAKER_WELL_KNOWN_SIDS: frozenset[str] = frozenset(
    {
        "S-1-5-18",  # NT AUTHORITY\SYSTEM (LocalSystem)
        "S-1-5-32-544",  # BUILTIN\Administrators
    }
)

# Well-known SIDs that map to Privileged Escalator groups.
_PRIVILEGED_ESCALATOR_WELL_KNOWN_SIDS: frozenset[str] = frozenset(
    {
        "S-1-5-32-548",  # BUILTIN\Account Operators
        "S-1-5-32-549",  # BUILTIN\Server Operators
        "S-1-5-32-550",  # BUILTIN\Print Operators
        "S-1-5-32-551",  # BUILTIN\Backup Operators
    }
)

# Unauthenticated principals — Anonymous Logon (S-1-5-7), Network (S-1-5-2),
# Everyone (S-1-1-0). Edges from these principals are real in the graph but
# only exploitable when null sessions / Pre-Windows 2000 Compatible Access
# are enabled. Surface them as HIGH (not CRITICAL) with a runtime caveat.
_UNAUTHENTICATED_PRINCIPAL_SIDS: frozenset[str] = frozenset(
    {"S-1-5-7", "S-1-5-2", "S-1-1-0"}
)
_UNAUTHENTICATED_PRINCIPAL_NAMES: frozenset[str] = frozenset(
    n.lower()
    for n in (
        "anonymous logon",
        "nt authority\\anonymous logon",
        "anonymous",
        "everyone",
        "network",
        "nt authority\\network",
    )
)


def _node_object_id(node: dict[str, Any]) -> str:
    """Return the node's object SID (upper-case, stripped) — best-effort."""
    if not node:
        return ""
    for key in ("objectId", "objectid", "object_id"):
        v = node.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip().upper()
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    if isinstance(props, dict):
        for key in ("objectid", "objectId", "object_id", "objectsid"):
            v = props.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip().upper()
    return ""


def _is_unauthenticated_principal(node: dict[str, Any]) -> bool:
    """Return True for Anonymous Logon / Network / Everyone-style nodes."""
    sid = _node_object_id(node)
    if sid:
        # Some collectors suffix SIDs with the domain (S-1-5-7@DOMAIN).
        head = sid.split("@", 1)[0]
        if head in {s.upper() for s in _UNAUTHENTICATED_PRINCIPAL_SIDS}:
            return True
        # Trailing well-known SID after a domain prefix
        for ws in _UNAUTHENTICATED_PRINCIPAL_SIDS:
            if head.endswith(ws.upper()):
                return True
    name = _node_display_name(node).strip().lower()
    if name in _UNAUTHENTICATED_PRINCIPAL_NAMES:
        return True
    return False


def _node_compromise_class(node: dict[str, Any]):
    """Best-effort canonical CompromiseClass for one graph node.

    Reads only static node attributes — no graph traversal — because the
    Tactical Findings panel runs immediately after collection, before
    attack-path materialisation. The class is therefore "membership-only";
    multi-hop COMPROMISE_ENABLER classifications come from the materializer.

    Recognition order (highest impact wins):

    1. Unauthenticated principals (Anonymous Logon, Network, Everyone)
       → ``UNAUTHENTICATED_PRINCIPAL`` — capped at HIGH severity even when
       the edge crosses into Tier 0, because exploitation requires a
       runtime predicate (null session enabled).
    2. Well-known Tier 0 SIDs (LocalSystem, BUILTIN\\Administrators)
       → ``DOMAIN_BREAKER``.
    3. Well-known Privileged Escalator SIDs (Account/Server/Print/Backup
       Operators) → ``PRIVILEGED_ESCALATOR``.
    4. Name-based group matches (legacy heuristic).
    """
    from adscan_internal.services.compromise_class import (
        CompromiseClass,
        _PRIVILEGED_ESCALATOR_GROUP_NAMES,
    )

    if not node:
        return None

    # Rule 1 — unauthenticated principals: highest precedence so the
    # severity matrix caps the row at HIGH instead of CRITICAL.
    if _is_unauthenticated_principal(node):
        return CompromiseClass.UNAUTHENTICATED_PRINCIPAL

    # Rule 2/3 — SID-based well-known classification.
    sid = _node_object_id(node)
    if sid:
        head = sid.split("@", 1)[0]
        candidates = {head}
        # Strip a domain SID prefix to compare against BUILTIN\* SIDs.
        for ws in (
            _DOMAIN_BREAKER_WELL_KNOWN_SIDS | _PRIVILEGED_ESCALATOR_WELL_KNOWN_SIDS
        ):
            if head.endswith(ws.upper()):
                candidates.add(ws.upper())
        for cand in candidates:
            if cand in {s.upper() for s in _DOMAIN_BREAKER_WELL_KNOWN_SIDS}:
                return CompromiseClass.DOMAIN_BREAKER
            if cand in {s.upper() for s in _PRIVILEGED_ESCALATOR_WELL_KNOWN_SIDS}:
                return CompromiseClass.PRIVILEGED_ESCALATOR

    # Rule 4 — name-based matches.
    name = _node_display_name(node).strip().lower()
    if not name:
        return None
    if any(frag in name for frag in _DOMAIN_BREAKER_GROUPS):
        return CompromiseClass.DOMAIN_BREAKER
    # exact-match check too
    if name in _DOMAIN_BREAKER_GROUPS:
        return CompromiseClass.DOMAIN_BREAKER
    if name in _PRIVILEGED_ESCALATOR_GROUP_NAMES:
        return CompromiseClass.PRIVILEGED_ESCALATOR
    return None


_EXCHANGE_NAME_FRAGMENTS: tuple[str, ...] = (
    "exchange",
    "exch0",
    "exch-",
    "msexch",
    "mail",
)
_ADCS_CA_NAME_FRAGMENTS: tuple[str, ...] = (
    "-ca",
    "ca01",
    "ca02",
    "rootca",
    "issuingca",
    "pki",
    "adcs",
    "certsrv",
)


def _name_matches_role(name: str, fragments: tuple[str, ...]) -> bool:
    return any(frag in name for frag in fragments)


def _node_tier0_asset_role(node: dict[str, Any]) -> str | None:
    """Return Tier 0 asset role string ("DC" / "Exchange" / "ADCS CA" / "Tier 0").

    ``is_dc`` (snake or in ``properties``) is the **authoritative** DC signal —
    if True, the role is "DC" regardless of the host name. Exchange and ADCS
    detection only fire when the DC flag is unset, so a DC named ``MAILSRV``
    is not miscategorised.

    When the node is Tier 0 (``isTierZero``) but the name does not match any
    known role, return the generic ``"Tier 0"`` rather than assuming DC. This
    is the honest answer and avoids the HTB Forest false positive where
    ``EXCH01$`` was rendered as ``[DC]``.
    """
    if not node:
        return None
    kind = str(node.get("kind") or "")
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    if not isinstance(props, dict):
        props = {}
    name = _node_display_name(node).lower()

    # Authoritative DC signal — wins over any name-based heuristic.
    if bool(node.get("is_dc")) or bool(props.get("is_dc")):
        return "DC"

    is_tier0 = bool(props.get("isTierZero")) or bool(node.get("isTierZero"))

    if kind == "Computer":
        if _name_matches_role(name, _EXCHANGE_NAME_FRAGMENTS):
            return "Exchange"
        if _name_matches_role(name, _ADCS_CA_NAME_FRAGMENTS):
            return "ADCS CA"
        if is_tier0:
            # Tier 0 host but the name does not match a known role.
            # Honest fallback — never silently label as DC.
            return "Tier 0"
    return None


def _compute_finding_severity(
    *,
    source_node: dict[str, Any],
    target_node: dict[str, Any],
    relation: str,
) -> tuple[str, str | None, bool, bool]:
    """Compute the canonical severity for one tactical finding.

    Returns:
        (severity_value, target_role, target_is_tier0_asset,
        source_is_unauthenticated).
    """
    from adscan_internal.services.compromise_class import CompromiseClass
    from adscan_internal.services.edge_kind import classify_edge_kind
    from adscan_internal.services.severity import (
        EdgeSeverityInput,
        compute_edge_severity,
    )

    src_cls = _node_compromise_class(source_node)
    tgt_cls = _node_compromise_class(target_node)
    target_role = _node_tier0_asset_role(target_node)
    target_is_t0_asset = target_role is not None
    target_is_domain = str(target_node.get("kind") or "").lower() == "domain"
    kind = classify_edge_kind(relation)
    sev = compute_edge_severity(
        EdgeSeverityInput(
            source_compromise_class=src_cls,
            target_compromise_class=tgt_cls,
            edge_kind=kind,
            target_is_tier0_asset=target_is_t0_asset,
            target_is_domain=target_is_domain,
        )
    )
    src_unauth = src_cls is CompromiseClass.UNAUTHENTICATED_PRINCIPAL
    return sev.value, target_role, target_is_t0_asset, src_unauth


def _build_tactical_findings(
    domain: str,
    nodes: dict[str, Any],
    edges: list[dict[str, Any]],
) -> "TacticalFindings":
    from adscan_core.rich_output_collection import TacticalFinding, TacticalFindings

    findings: list[TacticalFinding] = []
    kerberoastable: list[str] = []
    asreproastable: list[str] = []
    adcs_esc_count = 0

    for edge in edges:
        relation = str(edge.get("relation") or "")

        if relation == "Kerberoasting":
            target_node = nodes.get(str(edge.get("to") or ""))
            if target_node:
                kerberoastable.append(_node_display_name(target_node))
            continue

        if relation == "ASREPRoasting":
            target_node = nodes.get(str(edge.get("to") or ""))
            if target_node:
                asreproastable.append(_node_display_name(target_node))
            continue

        if relation.startswith("ADCSESC"):
            adcs_esc_count += 1
            from_node = nodes.get(str(edge.get("from") or ""))
            to_node = nodes.get(str(edge.get("to") or ""))
            if not from_node or not to_node:
                continue
            sev_val, target_role, t0_asset, src_unauth = _compute_finding_severity(
                source_node=from_node,
                target_node=to_node,
                relation=relation,
            )
            findings.append(
                TacticalFinding(
                    right=relation,
                    source=_node_display_name(from_node),
                    source_type=str(from_node.get("kind") or ""),
                    target=_node_display_name(to_node),
                    target_type=str(to_node.get("kind") or ""),
                    target_is_high_value=_node_is_high_value(to_node),
                    canonical_severity=sev_val,
                    target_role=target_role,
                    target_is_tier0_asset=t0_asset,
                    edge_kind="control",  # ADCSESC* classified as control
                    source_is_unauthenticated=src_unauth,
                )
            )
            continue

        if relation not in _TACTICAL_RELATIONS:
            continue

        from_node = nodes.get(str(edge.get("from") or ""))
        to_node = nodes.get(str(edge.get("to") or ""))
        if not from_node or not to_node:
            continue
        if _is_noisy_tactical_control_edge(
            relation=relation,
            source_node=from_node,
            target_node=to_node,
        ):
            continue

        is_hv = _node_is_high_value(to_node)
        sev_val, target_role, t0_asset, src_unauth = _compute_finding_severity(
            source_node=from_node,
            target_node=to_node,
            relation=relation,
        )
        from adscan_internal.services.edge_kind import classify_edge_kind

        edge_kind_value = classify_edge_kind(relation).value
        findings.append(
            TacticalFinding(
                right=relation,
                source=_node_display_name(from_node),
                source_type=str(from_node.get("kind") or ""),
                target=_node_display_name(to_node),
                target_type=str(to_node.get("kind") or ""),
                target_is_high_value=is_hv,
                canonical_severity=sev_val,
                target_role=target_role,
                target_is_tier0_asset=t0_asset,
                edge_kind=edge_kind_value,
                source_is_unauthenticated=src_unauth,
            )
        )

    # Deduplicate — keep one finding per (right, source, target) triple
    seen: set[tuple[str, str, str]] = set()
    unique: list[TacticalFinding] = []  # type: ignore[name-defined]
    for f in findings:
        key = (f.right, f.source.casefold(), f.target.casefold())
        if key not in seen:
            seen.add(key)
            unique.append(f)

    unique = _filter_container_scope_findings(unique)

    return TacticalFindings(
        domain=domain,
        findings=unique,
        kerberoastable=sorted(set(kerberoastable)),
        asreproastable=sorted(set(asreproastable)),
        adcs_esc_count=adcs_esc_count,
    )


def _inventory_name(properties: dict[str, Any]) -> str:
    """Return the most useful inventory display name from graph properties."""
    for key in ("samaccountname", "dnshostname", "name"):
        value = str(properties.get(key) or "").strip()
        if value:
            return value
    return ""


def _host_inventory_name(properties: dict[str, Any], domain: str) -> str:
    """Return a resolver-friendly hostname for a computer inventory entry."""
    dns_name = str(properties.get("dnshostname") or "").strip().rstrip(".")
    if dns_name:
        return dns_name

    name = str(properties.get("name") or "").strip().rstrip(".")
    if "." in name and "@" not in name:
        return name

    samaccountname = str(properties.get("samaccountname") or "").strip().rstrip("$")
    if not samaccountname:
        return ""
    normalized_domain = domain.strip().rstrip(".")
    return (
        f"{samaccountname}.{normalized_domain}" if normalized_domain else samaccountname
    )


def run_native_identity_inventory(shell: Any, target_domain: str) -> None:
    """Populate enabled_users.txt from the native attack graph."""
    try:
        from adscan_internal.cli.ci_events import emit_event
        from adscan_internal.services.identity_choke_point_service import (
            build_identity_choke_point_snapshot,
        )
        from adscan_internal.services.identity_risk_service import (
            build_identity_risk_snapshot,
        )

        graph = load_attack_graph(shell, target_domain)
        users = [
            _inventory_name(user) for user in get_enabled_users(graph, target_domain)
        ]
        users = [user for user in users if user]
        shell._write_user_list_file(target_domain, "enabled_users.txt", users)
        shell._postprocess_user_list_file(
            target_domain,
            "enabled_users.txt",
            source="native_graph_enabled_users",
        )
        build_identity_risk_snapshot(shell, target_domain)
        build_identity_choke_point_snapshot(shell, target_domain)
        emit_event(
            "coverage",
            phase="domain_analysis",
            phase_label="Domain Intelligence",
            category="identity_inventory",
            domain=target_domain,
            metric_type="enabled_users",
            count=len(users),
            message=f"Identity inventory updated: {len(users)} active users discovered.",
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error(f"Native identity inventory failed: {exc}")


def run_identity_inventory(shell: Any, target_domain: str) -> None:
    """Populate identity inventory artifacts from ADscan's local graph."""
    run_native_identity_inventory(shell, target_domain)


def run_native_host_inventory(shell: Any, target_domain: str) -> None:
    """Populate enabled_computers.txt from the native attack graph."""
    try:
        from adscan_internal.cli.ci_events import emit_event

        graph = load_attack_graph(shell, target_domain)
        hosts = [
            _host_inventory_name(computer, target_domain)
            for computer in get_enabled_computers(graph, target_domain)
        ]
        hosts = [host for host in hosts if host]
        shell._process_computers_list(
            target_domain,
            "enabled_computers.txt",
            hosts,
        )
        emit_event(
            "coverage",
            phase="domain_analysis",
            phase_label="Domain Intelligence",
            category="host_inventory",
            domain=target_domain,
            metric_type="enabled_hosts",
            count=len(hosts),
            message=f"Host inventory updated: {len(hosts)} active computers discovered.",
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error(f"Native host inventory failed: {exc}")


def run_host_inventory(shell: Any, target_domain: str) -> None:
    """Populate host inventory artifacts from ADscan's local graph."""
    run_native_host_inventory(shell, target_domain)


def run_attack_path_discovery(
    shell: Any,
    target_domain: str,
    *,
    max_depth: int = 6,  # requested actionable-edge budget; bounded by _effective_max_depth (user+all caps at 6)
    build_only: bool = False,
) -> None:
    """Build and display attack paths from ADscan's local attack graph.

    ``build_only`` is honoured strictly: when False the table renders and
    execution is enabled; when True the table is suppressed and only the
    graph artefacts are persisted (the explicit cross-domain merge in
    ``cli/domains.py`` uses this to build every per-domain graph silently
    before ``run_cross_domain_attack_path_discovery`` shows the merged
    view).

    Earlier this helper auto-flipped ``effective_build_only = True`` when
    the workspace had multiple configured domains, on the assumption that
    a cross-domain merge would follow.  That assumption only holds when
    the caller orchestrates the merge explicitly (the multi-domain pivot
    flow in ``cli/domains.py``).  Phase 4 of ``run_enumeration`` calls
    this helper one domain at a time and does NOT invoke the merge, so
    the auto-flip silently gated execution forever in multi-domain
    workspaces.  Trust the caller's explicit ``build_only``.
    """
    from adscan_internal.cli.attack_graph_reports import run_attack_paths

    run_attack_paths(
        shell,
        target_domain,
        max_depth=max_depth,
        build_only=build_only,
    )


def run_cross_domain_attack_path_discovery(
    shell: Any,
    domains: list[str],
) -> None:
    """Display merged cross-domain attack paths from local graph artifacts."""
    from adscan_internal.cli.attack_graph_reports import run_cross_domain_attack_paths

    run_cross_domain_attack_paths(shell, domains)
