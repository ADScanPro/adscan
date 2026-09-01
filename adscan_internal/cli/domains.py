"""Domain CLI helpers (workspace sub-scope).

This module hosts domain-scoped CLI logic (trust enumeration and the per-domain
save hook). It intentionally depends on dependency injection (the shell object)
to avoid import cycles into `adscan.py`.
"""

from __future__ import annotations

import os
import sys
import time
import subprocess
from typing import Any, Protocol

from adscan_internal import telemetry
from adscan_internal.rich_output import (
    mark_sensitive,
    print_error,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_success,
    print_warning,
    print_warning_debug,
)
from adscan_internal.cli.dns import (
    confirm_domain_pdc_mapping,
    finalize_domain_context,
    prompt_pdc_ip_interactive,
)
from adscan_internal.cli.nmap import probe_host_reachability_with_nmap
from adscan_internal.services.domain_connectivity_service import (
    merge_domain_connectivity,
)
from adscan_core.rich_output import print_exception


class DomainShell(Protocol):
    """Protocol for domain management methods on the legacy shell."""

    current_workspace: str | None
    current_workspace_dir: str | None
    current_domain: str | None
    domains_dir: str
    domains: list[str]
    domains_data: dict[str, dict[str, Any]]
    cracking_dir: str
    ldap_dir: str
    netexec_path: str | None
    domain_connectivity: dict[str, dict[str, Any]]

    def save_domain_data(self) -> None: ...

    def run_command(
        self, command: str, timeout: int | None = None
    ) -> subprocess.CompletedProcess: ...

    def create_sub_workspace_for_domain(
        self, domain: str, pdc_ip: str | None = None
    ) -> None: ...

    def do_enum_domain_auth_phase1(self, domain: str) -> None: ...

    def ask_for_enum_domain_auth(self, domain: str) -> None: ...
    def save_workspace_data(self) -> bool: ...

    def _run_netexec(
        self,
        command: str,
        *,
        domain: str | None = None,
        timeout: int | None = None,
        pre_sync: bool = True,
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[str] | None: ...

    def _get_dns_discovery_service(self) -> Any: ...


def domain_save(shell: DomainShell) -> None:
    """Refresh the current domain's write-only snapshot file.

    Called before switching workspaces so the domain directory on disk reflects
    the state the operator is leaving. The authoritative store stays the
    workspace-root ``variables.json``.
    """
    if not shell.current_domain:
        print_error("No domain selected.")
        return
    shell.save_domain_data()
    print_success(f"Domain data for '{shell.current_domain}' saved.")


def run_enum_trusts(shell: DomainShell, domain: str) -> None:
    """Enumerate trusts for a domain and update workspace/domain metadata.

    This is a CLI orchestration helper extracted from the legacy shell to keep
    `adscan.py` slimmer. It expects PRO checks to have been done by the caller.
    """
    # Trust RELATIONSHIP mapping ALWAYS runs — mapping the trust graph is cheap
    # and an operator may want the map without collecting a trusted forest they
    # are not authorized to touch. The scan-config policy governs only WHICH
    # DOMAINS get COLLECTED afterward (decided downstream in the scope selection,
    # see ``default_scope_for_selection``), NOT whether trusts are enumerated.
    # ``selected`` still constrains the recursive BFS to the listed partner
    # domains (that is a mapping-scope choice, not a suppression). ``origin_only``
    # (and its back-compat alias ``skip``) no longer short-circuit here — they
    # only mean "collect the origin domain only" at scope-selection time.
    from adscan_internal.services.scan_config import (
        TRUST_POLICY_SELECTED,
    )

    scan_config = getattr(shell, "scan_config", None)
    trust_cfg = getattr(scan_config, "trust_enumeration", None)
    trust_policy = getattr(trust_cfg, "policy", None)
    trust_allowlist: set[str] | None = None
    if trust_policy == TRUST_POLICY_SELECTED:
        trust_allowlist = {d.strip().lower() for d in getattr(trust_cfg, "domains", ())}

    if (
        domain not in shell.domains_data
        or "pdc" not in shell.domains_data[domain]
        or not shell.domains_data[domain]["pdc"]
    ):
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            f"Could not find the PDC for the domain {marked_domain}. Skipping trust enumeration."
        )
        return

    # Initialised at function scope so the outer finally can close the span
    # safely no matter where execution leaves the function.
    _trust_phase_cm = None
    try:
        from adscan_internal import get_console, print_operation_header
        from adscan_internal.cli.widgets.trust_enum_live import (
            TrustEnumLiveView,
            render_trust_summary_panel,
        )
        from adscan_internal.cli.widgets.intelligence_update import (
            render_intelligence_update,
        )
        from adscan_internal.services.domain_posture import get_posture
        from adscan_internal.services.domain_service import DomainService
        from adscan_internal.services.posture_sink import (
            make_workspace_posture_sink,
        )

        username = shell.domains_data[domain]["username"]
        password = shell.domains_data[domain]["password"]
        pdc = shell.domains_data[domain]["pdc"]
        domain_state = shell.domains_data.get(domain, {}) or {}
        auth_domain = str(domain_state.get("auth_domain") or domain)
        auth_kdc = str(domain_state.get("auth_kdc") or pdc)

        # Surface this as a top-level chapter so it shares the numbered
        # phase strip with Domain Collection and the analysis pipeline.
        # ``emit_chapter`` below fires the canonical ``topology_and_trusts``
        # phase event for both the CLI strip and the web — no separate
        # ``emit_phase`` (which previously used the drifted ``trust_enumeration``
        # id) is needed.
        # The timeline span is opened here and closed in the function-level
        # finally so the row is written even on the error path.
        try:
            from adscan_internal.services.scan_phases import emit_chapter
            from adscan_internal.services.scan_timeline import phase_span

            scan_type = getattr(shell, "type", "default")
            emit_chapter("topology_and_trusts", scan_type=scan_type)
            _trust_phase_cm = phase_span(
                shell,
                domain,
                phase_id="topology_and_trusts",
                phase_title="Topology & Trusts",
            )
            _trust_phase_cm.__enter__()
        except Exception:  # noqa: BLE001 — chapter/timeline must never block the scan
            _trust_phase_cm = None

        print_operation_header(
            "Trust Enumeration",
            details={
                "Domain": domain,
                "PDC": pdc,
                "Username": username,
                "Auth": "Kerberos (LDAPS w/ fallback)",
            },
            icon="🔗",
        )
        print_info_debug(
            "Native badldap recursive trust enumeration · BFS · timeout=60s/domain"
        )

        dns_service = None
        try:
            dns_service = shell._get_dns_discovery_service()
        except Exception:
            dns_service = None

        partner_hostname_cache: dict[str, str] = {}
        # Trusted realms whose own A-records are all unreachable from this
        # vantage. For these, the source domain's DC IP is ONLY a DNS resolver —
        # never a DC candidate — so ``find_pdc_with_selection(cross_domain=True)``
        # returns no IP. We record them here so the result handler marks them
        # discovered-but-unreachable instead of leaking the resolver IP into the
        # workspace / PDC store / /etc/hosts / unbound (the cross-domain leak).
        cross_domain_unreachable: set[str] = set()
        # Pivot-retry breadcrumbs for the realms above. Keyed by trusted-realm
        # name → a connectivity update carrying the trusted realm's OWN real DC
        # A-record IP (e.g. pong.htb → 192.168.2.2), NEVER the source resolver IP,
        # with ``reachable=False``. Persisted via ``merge_domain_connectivity`` so
        # the Ligolo pivot follow-up can re-probe that IP through the tunnel and,
        # once reachable, re-trigger authenticated enumeration of the realm. The
        # ``reachable=False`` gate keeps it out of every authenticated/KDC path
        # pre-pivot — it is only ever used as a pivot-probe TARGET.
        cross_domain_breadcrumbs: dict[str, dict[str, Any]] = {}

        def _resolve_pdc_ip(trusted_domain: str, resolver_ip: str) -> str | None:
            if not dns_service or not hasattr(dns_service, "find_pdc_with_selection"):
                return None
            # cross_domain=True: ``resolver_ip`` is the SOURCE domain's DC, used
            # ONLY as a DNS resolver to query the TRUSTED realm's SRV/A records.
            # It must NEVER be selected as the trusted realm's PDC (wrong KDC →
            # KDC_ERR_WRONG_REALM). The flag is the precise fix — keep passing
            # ``resolver_ip`` so the foreign records can still be resolved.
            # ``return_selection=True`` surfaces the full DcIpSelection so we can
            # recover the realm's OWN real A-record IP for the breadcrumb even
            # when ``selected_ip is None`` (cross-domain-unreachable).
            result_tuple = dns_service.find_pdc_with_selection(
                domain=trusted_domain,
                resolver_ip=resolver_ip,
                preferred_ips=[resolver_ip],
                reference_ip=resolver_ip,
                cross_domain=True,
                return_selection=True,
            )
            if len(result_tuple) == 3:
                selected_ip, hostname, selection = result_tuple
            else:  # defensive — a stubbed dns_service may ignore the flag
                selected_ip, hostname = result_tuple
                selection = None
            normalized_partner = trusted_domain.strip().lower()
            partner_fqdn: str | None = None
            if hostname:
                partner_fqdn = (
                    hostname if "." in hostname else f"{hostname}.{normalized_partner}"
                )
                partner_hostname_cache[normalized_partner] = partner_fqdn
            if not selected_ip:
                # The trusted realm was discovered (SRV/A query answered) but none
                # of ITS DCs are reachable — mark unreachable and stop. Do NOT fall
                # back to the resolver IP.
                cross_domain_unreachable.add(normalized_partner)
                # Leave a pivot-retry breadcrumb with the realm's OWN real DC IP
                # (from its A-records — NEVER the source resolver IP). Only when
                # we actually recovered such an IP; absent it there is nothing
                # safe to probe later and we record no breadcrumb.
                breadcrumb_ip = (
                    str(getattr(selection, "unreachable_dns_ip", "") or "").strip()
                    if selection is not None
                    else ""
                )
                if breadcrumb_ip and breadcrumb_ip != str(resolver_ip or "").strip():
                    cross_domain_breadcrumbs[normalized_partner] = {
                        "domain": normalized_partner,
                        "source_domain": domain,
                        "pdc_ip": breadcrumb_ip,
                        "host": breadcrumb_ip,
                        "reachable": False,
                        "status": "cross_domain_unreachable",
                        "hostname_candidates": (
                            [partner_fqdn] if partner_fqdn else []
                        ),
                        "method": "trust_enum_cross_domain_unreachable",
                    }
            return selected_ip

        def _resolve_dc_hostname(trusted_domain: str, _resolver_ip: str) -> str | None:
            return partner_hostname_cache.get(trusted_domain.strip().lower())

        def _resolve_dns_server_for_domain(source_domain: str) -> str | None:
            # Split-DC/DNS (issue #15): the AD-zone DNS server configured for the
            # source domain, used as the resolver for partner-realm SRV/A/PTR
            # discovery instead of the source DC. ``None`` -> DC as resolver.
            from adscan_internal.models.domain import (  # noqa: PLC0415
                resolve_dns_server,
            )

            key = source_domain.strip().rstrip(".")
            entry = shell.domains_data.get(key)
            if not isinstance(entry, dict):
                # Domains_data may key on a different case than the trust walk's
                # normalized (lower-cased) domain name — match case-insensitively.
                key_lower = key.lower()
                entry = next(
                    (
                        v
                        for k, v in shell.domains_data.items()
                        if isinstance(v, dict)
                        and str(k or "").strip().rstrip(".").lower() == key_lower
                    ),
                    None,
                )
            return resolve_dns_server(entry) if isinstance(entry, dict) else None

        def _check_trusted_domain_reachability(
            trusted_domain: str,
            trusted_pdc_ip: str,
            source_domain: str,
        ) -> dict[str, Any]:
            probe_result = probe_host_reachability_with_nmap(
                shell,
                host=trusted_pdc_ip,
                ports=[88, 389, 53],
                timeout_seconds=20,
                report_label=f"trusted_dc_{trusted_domain.replace('.', '_')}",
            )
            probe_result["domain"] = trusted_domain
            probe_result["source_domain"] = source_domain
            probe_result["pdc_ip"] = trusted_pdc_ip
            return probe_result

        posture_sink = make_workspace_posture_sink(
            shell.domains_data,
            on_finding=lambda finding: get_console().print(
                render_intelligence_update(finding)
            ),
        )
        posture_snapshot = get_posture(shell.domains_data, domain=domain)

        service = DomainService()
        with TrustEnumLiveView(
            source_domain=domain,
            source_pdc=pdc,
            username=username,
        ) as live_view:
            result = service.enumerate_trusts(
                domain=domain,
                pdc=pdc,
                username=username,
                password=password,
                auth_domain=auth_domain,
                auth_kdc=auth_kdc,
                use_kerberos=True,
                dc_hostname=(
                    shell.domains_data.get(domain, {}).get("dc_fqdn")
                    or shell.domains_data.get(domain, {}).get("pdc_hostname")
                ),
                resolve_pdc_ip=_resolve_pdc_ip,
                resolve_dc_hostname=_resolve_dc_hostname,
                resolve_dns_server_for_domain=_resolve_dns_server_for_domain,
                check_domain_reachability=_check_trusted_domain_reachability,
                progress_cb=live_view.on_event,
                posture_sink=posture_sink,
                posture_snapshot=posture_snapshot,
                allowed_partner_domains=trust_allowlist,
            )

        # Premium summary card.
        get_console().print(render_trust_summary_panel(result, source_domain=domain))

        merge_domain_connectivity(
            shell,
            source_domain=domain,
            connectivity_updates=result.domain_connectivity,
        )
        # Persist pivot-retry breadcrumbs for cross-domain-unreachable realms.
        # The trust-enum loop only emits a ``domain_connectivity`` entry when the
        # partner PDC IP is truthy; with the cross-realm leak fix that IP is None
        # for an unreachable realm, so without this the realm leaves NO breadcrumb
        # and the Ligolo pivot follow-up can never re-trigger its enumeration.
        # These updates carry the realm's OWN real DC A-record IP with
        # ``reachable=False`` — never the source resolver IP — so they re-arm the
        # pivot probe without re-introducing the leak (reachable=False keeps the
        # IP out of every authenticated/KDC path until the tunnel confirms it).
        if cross_domain_breadcrumbs:
            merge_domain_connectivity(
                shell,
                source_domain=domain,
                connectivity_updates=cross_domain_breadcrumbs,
            )
        if (
            result.domain_connectivity or cross_domain_breadcrumbs
        ) and hasattr(shell, "save_workspace_data"):
            try:
                shell.save_workspace_data()
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                print_warning(
                    "Failed to persist trusted-domain reachability state to the workspace."
                )

        _handle_trust_enumeration_result(
            shell,
            domain=domain,
            trusts=result.trusts,
            discovered_domains=result.discovered_domains,
            domain_pdc_mapping=result.domain_controllers,
            cross_domain_unreachable=cross_domain_unreachable,
            domain_dc_sets=result.domain_dc_sets,
            dc_set_degraded_reasons=result.dc_set_degraded_reasons,
            domain_dc_fqdns=result.domain_dc_fqdns,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        from adscan_internal import print_error_context

        print_error_context(
            "Trust enumeration failed",
            context={
                "Domain": domain,
                "PDC": shell.domains_data[domain].get("pdc", "N/A"),
            },
            suggestions=[
                "Verify domain credentials are correct",
                "Check network connectivity to PDC",
                "Confirm LDAP (389) or LDAPS (636) is reachable on the PDC",
            ],
            show_exception=True,
            exception=exc,
        )
    finally:
        # Always close the timeline span so the row + delta footer are
        # emitted even when the trust enumeration failed.
        try:
            if _trust_phase_cm is not None:
                _trust_phase_cm.__exit__(None, None, None)
        except Exception:  # noqa: BLE001
            pass


def order_domains_for_scan(source_domain: str, domains: list[str]) -> list[str]:
    """Order domains for scanning: source first, then closest relations."""
    source_norm = source_domain.lower().strip()
    normalized_to_original: dict[str, str] = {}
    seen: set[str] = set()
    ordered_norm: list[str] = []

    for item in domains:
        item_norm = item.lower().strip()
        if not item_norm or item_norm in seen:
            continue
        seen.add(item_norm)
        normalized_to_original.setdefault(item_norm, item.strip())
        ordered_norm.append(item_norm)

    if source_norm:
        normalized_to_original.setdefault(source_norm, source_domain.strip())
        if source_norm in ordered_norm:
            ordered_norm = [source_norm] + [d for d in ordered_norm if d != source_norm]
        else:
            ordered_norm.insert(0, source_norm)

    parent_chain: list[str] = []
    source_parts = source_norm.split(".") if source_norm else []
    if len(source_parts) > 2:
        for idx in range(1, len(source_parts)):
            parent = ".".join(source_parts[idx:])
            if parent and parent not in parent_chain:
                parent_chain.append(parent)

    start_root = ".".join(source_parts[-2:]) if len(source_parts) >= 2 else ""

    def _group_key(dom: str) -> tuple[int, int | str]:
        if dom == source_norm:
            return (0, 0)
        if dom in parent_chain:
            return (1, parent_chain.index(dom))
        if start_root and dom.endswith(start_root):
            return (2, dom)
        parts = dom.split(".")
        root_rank = 0 if len(parts) == 2 else 1
        return (3, f"{root_rank}:{dom}")

    ordered_norm = sorted(ordered_norm, key=lambda d: _group_key(d))
    return [normalized_to_original.get(dom, dom) for dom in ordered_norm]


# ---------------------------------------------------------------------------
# Trust-scope selection default (SSOT)
# ---------------------------------------------------------------------------
#
# When a pivot (e.g. an MSSQL linked-server tunnel) unlocks a NEWLY-REACHABLE
# trusted domain, ADscan must decide which of the reachable domains to enumerate
# (full Phase 1 BH collection + attack graph). There are two orthogonal answers:
#
#   * the SAFE fallback (cancel / timeout / exception) — ALWAYS origin-only, so a
#     hung/abandoned/cancelled decision never silently enumerates a trusted forest;
#   * the PRIMARY default (the interactive checkbox pre-selection, and the
#     non-interactive auto-selection) — TYPE-AWARE, overridable by scan config.
#
# CLI-side override contract (mirrors the existing ``trust_enumeration.policy``
# scan-config concept, so the web forwards ONE trust knob, not two):
#   * ``shell.scan_config.trust_enumeration.policy``:
#       - ``all``       -> enumerate every reachable domain (origin + unlocked)
#       - ``skip``      -> origin only
#       - ``selected``  -> origin + the listed ``domains`` that are reachable
#       - ``interactive`` (default) -> defer to the by-type default below
#   * env var ``ADSCAN_TRUST_SCOPE`` (for CLI/CI users with no scan-config file,
#     following the ``ADSCAN_NO_POISONING`` pattern): ``all`` | ``origin`` —
#     takes precedence over the by-type default, NOT over an explicit non-
#     ``interactive`` scan-config policy.
# By-type default (when neither override applies):
#   * ``ctf``            -> all reachable (our labs; full enumeration is wanted)
#   * ``audit`` / other  -> origin only (a client often does not authorize
#     enumerating a trusted forest — legal scope).

_TRUST_SCOPE_ENV = "ADSCAN_TRUST_SCOPE"
_TRUST_SCOPE_ENV_ALL = "all"
_TRUST_SCOPE_ENV_ORIGIN = "origin"


def _origin_only_scope(candidates: list[str], source_domain: str) -> list[str]:
    """Return the conservative origin-only scope (never enumerate a trust).

    The single safe fallback used by every cancel / timeout / exception path so
    an abandoned decision never silently enumerates a trusted forest. When the
    source domain is not among the candidates it degrades to the first candidate
    (there is always at least the origin in practice).
    """
    if source_domain in candidates:
        return [source_domain]
    return candidates[:1]


def default_scope_for_selection(
    shell: Any,
    *,
    candidates: list[str],
    new_domains: list[str],
    source_domain: str,
) -> list[str]:
    """Resolve the DEFAULT trust-scope pre-selection (type-aware + overridable).

    This is the value the interactive prompt pre-checks (so the operator sees +
    decides on the newly-unlocked domains) AND the value a non-interactive run
    auto-selects. The safe cancel/timeout/exception fallbacks do NOT use this —
    they call :func:`_origin_only_scope` and stay origin-only unconditionally.

    An ALREADY-ENUMERATED domain (the origin, and any domain that already
    completed Phase 1) is NEVER pre-selected — re-enumerating a domain that is
    already done is pointless, so it is left unchecked in both CLI and web and in
    both ctf and audit. The operator may still select it manually to force a
    re-enumeration, but the default only ever pre-checks domains that genuinely
    NEED enumeration (the newly-unlocked ones). So every branch below intersects
    its choice with ``new_domains`` — an empty result means "nothing new to
    enumerate", which is the correct default (no pre-selection).

    Resolution order (first match wins):
      1. ``shell.scan_config.trust_enumeration.policy`` when set to a non-
         ``interactive`` value (``all`` / ``origin_only`` / ``selected``; the
         legacy ``skip`` is accepted as an alias of ``origin_only``).
      2. env var ``ADSCAN_TRUST_SCOPE`` (``all`` / ``origin``).
      3. the by-type default: ``ctf`` -> all NEW domains; ``audit`` / other ->
         none (a trusted forest is opt-in on an audit).

    Args:
        shell: The session shell (read-only; ``type`` and ``scan_config`` are
            consulted best-effort — a missing/garbage value degrades to the
            conservative by-type default).
        candidates: All reachable domains (origin + newly-unlocked).
        new_domains: The newly-reachable domains (``candidates`` minus the
            already-enumerated set). Pre-selecting these is the whole point of
            the prompt — enumerating them populates their attack graph so a
            later cross-forest DCSync/TGT-delegation step can resolve.
        source_domain: The origin domain enumeration was launched from.

    Returns:
        The subset of ``new_domains`` (order-preserved) to pre-select /
        auto-select. Never includes an already-enumerated domain. Empty when
        there is nothing new to enumerate.
    """
    # Only domains that still NEED enumeration are ever pre-selected.
    new_set = {str(d).strip().lower() for d in new_domains}
    all_new = [d for d in candidates if str(d).strip().lower() in new_set]

    # 1. Explicit scan-config policy (the web forwards this one trust knob).
    scan_config = getattr(shell, "scan_config", None)
    trust_cfg = getattr(scan_config, "trust_enumeration", None)
    policy = str(getattr(trust_cfg, "policy", "") or "").strip().lower()
    if policy and policy != "interactive":
        if policy == "all":
            return all_new
        if policy in ("origin_only", "skip"):  # skip = back-compat alias
            return []  # collect only the origin (already done) — nothing new
        if policy == "selected":
            listed = {
                str(d).strip().lower() for d in getattr(trust_cfg, "domains", ()) or ()
            }
            # Only the listed domains that still need enumeration (the origin,
            # if listed, is already done and is not re-selected).
            return [d for d in all_new if d.strip().lower() in listed]

    # 2. env-var override (CLI/CI users without a scan-config file).
    env_scope = str(os.environ.get(_TRUST_SCOPE_ENV, "") or "").strip().lower()
    if env_scope == _TRUST_SCOPE_ENV_ALL:
        return all_new
    if env_scope == _TRUST_SCOPE_ENV_ORIGIN:
        return []

    # 3. by-type default.
    scan_type = str(getattr(shell, "type", "") or "").strip().lower()
    if scan_type == "ctf":
        return all_new
    # audit / default: a trusted forest stays opt-in — nothing pre-selected.
    return []


def _prompt_scope_selection(
    candidates: list[str],
    source_domain: str,
    phase1_complete_domains: set[str] | None = None,
    shell: Any = None,
) -> list[str]:
    """Ask the user which trusted domains to include in scope.

    Domains with Phase 1 already completed are shown with a re-run label so the
    operator understands only the attack graph is rebuilt, not the full BH collection.

    The DEFAULT scope is type-aware and overridable (see
    :func:`default_scope_for_selection`): a non-interactive run auto-selects it,
    and the interactive prompt pre-checks it so the operator sees + decides on the
    newly-unlocked domains. Cancel / timeout / exception always fall back to the
    conservative origin-only scope — a trusted forest is never silently enumerated
    on an abandoned decision.

    Args:
        candidates: All reachable domains to offer (including source).
        source_domain: The domain trust enumeration was launched from.
        phase1_complete_domains: Domains whose BH collection is already done.
        shell: The session shell (read-only), consulted for ``type`` and
            ``scan_config`` to resolve the type-aware / overridable default.

    Returns:
        Subset of candidates selected by the user, preserving original order.
    """
    # A single candidate is no choice — auto-select it and never prompt. Mirrors the
    # remote bridge's `len(candidates) <= 1` short-circuit, and also covers the
    # interactive-local path so a one-item checkbox never appears for a single-domain
    # environment (the common client case).
    if len(candidates) <= 1:
        return candidates

    done = phase1_complete_domains or set()
    new_domains = [d for d in candidates if d not in done]
    rerun_domains = [d for d in candidates if d in done]

    # Nothing to offer if every candidate is already fully enumerated
    # and there are no new domains at all.
    if not new_domains and not rerun_domains:
        return candidates

    scope_default = default_scope_for_selection(
        shell,
        candidates=candidates,
        new_domains=new_domains,
        source_domain=source_domain,
    )

    from adscan_internal.interaction import is_non_interactive as _is_non_interactive
    if _is_non_interactive():
        # Non-interactive default is TYPE-AWARE (ctf -> all reachable; audit ->
        # origin only) and overridable via scan config / ``ADSCAN_TRUST_SCOPE``.
        # A trusted forest is enumerated only when the type/config says so.
        return scope_default

    try:
        from adscan_core import prompting
        from adscan_internal import get_console

        console = get_console()

        # Context panel — tactical intel aesthetic: dark background, sharp borders
        has_rerun = bool(rerun_domains)
        has_new = bool(new_domains)

        legend_lines: list[str] = []
        if has_new:
            legend_lines.append(
                "  [bold green]★[/bold green]  [dim]Full enumeration[/dim]   "
                "[dim]→ BH collection · attack graph · attack paths[/dim]"
            )
        if has_rerun:
            legend_lines.append(
                "  [bold yellow]↺[/bold yellow]  [dim]Attack paths only[/dim]  "
                "[dim]→ skip BH collection · rebuild graph with cross-domain context[/dim]"
            )

        from rich.panel import Panel
        from rich.padding import Padding

        panel_body = "\n".join(legend_lines)
        console.print(
            Panel(
                Padding(panel_body, (1, 2)),
                title="[bold]Trust Scope Selection[/bold]",
                border_style="dim cyan",
                expand=False,
            )
        )

        options: list[str] = []
        labels_by_value: dict[str, str] = {}
        for d in candidates:
            if d in done:
                label = f"↺  {d}   [already enumerated — rebuild attack graph only]"
            else:
                label = f"★  {d}   [full enumeration]"
            labels_by_value[d] = label
            options.append(d)

        # Pre-check the type-aware default so the operator SEES the newly-unlocked
        # domains selected and can decide, rather than the origin-only default that
        # hid them.
        interactive_default = [d for d in options if d in set(scope_default)]

        selected = prompting.questionary_checkbox_values_raw(
            title="Select domains to include in scope:",
            options=options,
            default_values=interactive_default or _origin_only_scope(options, source_domain),
            labels_by_value=labels_by_value,
        )

        if selected is None:
            # Ctrl-C / cancelled — fall back to the origin domain only (the safe
            # default: never silently enumerate trusted domains on a cancel).
            return _origin_only_scope(candidates, source_domain)

        return [d for d in candidates if d in set(selected)]
    except Exception:
        return _origin_only_scope(candidates, source_domain)


def _build_trust_scope_context(
    shell: DomainShell,
    *,
    candidates: list[str],
    source_domain: str,
    phase1_complete_domains: set[str],
    trusts: list[Any],
    domain_pdc_mapping: dict[str, str],
) -> dict[str, Any]:
    """Build the trust-topology decision payload for the remote picker.

    Shapes the in-memory trust enumeration result + ``shell.domains_data`` into
    the ``context`` the web platform renders: the origin domain, a trust matrix
    (source/partner/direction/type edges) and a per-domain node list with PDC,
    reachability and trust count. Everything here is read-only metadata; the
    actual scope decision is the operator's multiselect answer.
    """
    source_lower = source_domain.strip().lower()

    def _pdc_for(domain_name: str) -> str:
        candidate_data = (
            shell.domains_data.get(domain_name, {})
            if isinstance(getattr(shell, "domains_data", {}), dict)
            else {}
        )
        if not isinstance(candidate_data, dict):
            candidate_data = {}
        summary_pdc = ""
        connectivity = candidate_data.get("connectivity")
        if isinstance(connectivity, dict):
            summary = connectivity.get("summary")
            if isinstance(summary, dict):
                summary_pdc = str(summary.get("pdc_ip") or "")
        return str(
            candidate_data.get("pdc")
            or domain_pdc_mapping.get(domain_name)
            or summary_pdc
            or ""
        )

    # Trust matrix from the in-memory TrustRelationship records.
    trust_matrix: list[dict[str, str]] = []
    trust_count_by_domain: dict[str, int] = {}
    for trust in trusts or []:
        source = str(getattr(trust, "source_domain", "") or "").strip().lower()
        partner = str(getattr(trust, "target_domain", "") or "").strip().lower()
        if not source or not partner:
            continue
        direction = str(getattr(trust, "trust_direction", "") or "Unknown").lower()
        trust_type = str(getattr(trust, "trust_type", "") or "Unknown")
        trust_matrix.append(
            {
                "source": source,
                "partner": partner,
                "direction": direction,
                "type": trust_type,
            }
        )
        trust_count_by_domain[source] = trust_count_by_domain.get(source, 0) + 1
        trust_count_by_domain[partner] = trust_count_by_domain.get(partner, 0) + 1

    discovered_domains: list[dict[str, Any]] = []
    for candidate in candidates:
        candidate_lower = candidate.strip().lower()
        candidate_data = (
            shell.domains_data.get(candidate, {})
            if isinstance(getattr(shell, "domains_data", {}), dict)
            else {}
        )
        if not isinstance(candidate_data, dict):
            candidate_data = {}
        connectivity = candidate_data.get("connectivity", {})
        summary = (
            connectivity.get("summary", {})
            if isinstance(connectivity, dict)
            and isinstance(connectivity.get("summary", {}), dict)
            else {}
        )
        latency_value = summary.get("latency_ms") if isinstance(summary, dict) else None
        discovered_domains.append(
            {
                "domain": candidate_lower,
                "pdc": _pdc_for(candidate),
                "reachable": True,  # candidates are pre-filtered to reachable only
                "trust_count": trust_count_by_domain.get(candidate_lower, 0),
                "latency": latency_value,
                "is_origin": candidate_lower == source_lower,
                "phase1_complete": candidate in phase1_complete_domains,
            }
        )

    return {
        "category": "trust_scope",
        "origin_domain": source_lower,
        "candidate_count": len(candidates),
        "trust_matrix": trust_matrix,
        "discovered_domains": discovered_domains,
    }


def _remote_trust_scope_selection(
    shell: DomainShell,
    *,
    candidates: list[str],
    source_domain: str,
    phase1_complete_domains: set[str] | None = None,
    trusts: list[Any],
    domain_pdc_mapping: dict[str, str],
) -> list[str] | None:
    """Offer the trust-scope decision over the remote interaction bridge.

    Returns the operator-selected domains (order-preserved, origin always kept)
    on a platform scan with >1 reachable domain. Returns ``None`` when the bridge
    is disabled or there is a single reachable domain, so the caller falls back
    to the local prompt (which keeps the origin-only default for headless ``ci``).

    The multiselect PRE-SELECTION is the type-aware / overridable default (so the
    operator sees the newly-unlocked domains checked and decides), but the TIMEOUT
    result stays origin-only, so a hung/abandoned/timed-out session never blocks
    past the request timeout and never silently enumerates trusted domains.
    """
    try:
        from adscan_internal.interactive_requests import is_remote_interaction_enabled
    except Exception:  # noqa: BLE001
        return None

    if not is_remote_interaction_enabled() or len(candidates) <= 1:
        return None

    selector = getattr(shell, "_questionary_multiselect", None)
    if not callable(selector):
        return None

    done = phase1_complete_domains or set()
    new_domains = [d for d in candidates if d not in done]
    origin_default = _origin_only_scope(candidates, source_domain)
    # The pre-selection the operator sees checked is the type-aware default; the
    # timeout fallback stays origin-only (never enumerate a trust on an abandon).
    preselect_default = default_scope_for_selection(
        shell,
        candidates=candidates,
        new_domains=new_domains,
        source_domain=source_domain,
    )
    context = _build_trust_scope_context(
        shell,
        candidates=candidates,
        source_domain=source_domain,
        phase1_complete_domains=done,
        trusts=trusts,
        domain_pdc_mapping=domain_pdc_mapping,
    )
    context["remote_interaction"] = True

    try:
        selected_values = selector(
            "Select trusted domains to include in enumeration scope:",
            candidates,
            default_values=preselect_default,
            timeout_values=origin_default,
            context=context,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return origin_default

    if not selected_values:
        # Empty selection from a remote operator is coerced to origin-only — the
        # client opted out of enumerating trusted domains, never an empty scope.
        return origin_default
    chosen = {value.strip().lower() for value in selected_values}
    resolved = [d for d in candidates if d.strip().lower() in chosen]
    if source_domain in candidates and source_domain not in resolved:
        resolved.insert(0, source_domain)
    return resolved or origin_default


def _persist_scope_selection(
    shell: DomainShell,
    *,
    source_domain: str,
    candidates: list[str],
    selected_domains: list[str],
    domain_pdc_mapping: dict[str, str],
) -> None:
    """Persist selected trusted-domain scope to the workspace scope.json."""
    try:
        from adscan_internal.services.collector.scope import (
            ScopeEntry,
            ScopeResult,
            save_scope,
        )

        workspace_cwd = (
            getattr(shell, "current_workspace_dir", None)
            or getattr(shell, "current_workspace", None)
            or os.getcwd()
        )
        selected = {item.lower().strip() for item in selected_domains}
        source_data = shell.domains_data.get(source_domain, {})
        # Source-domain broadcast auth context — the correct default for the
        # common single-credential transitive trust, where ONE owned credential
        # reaches every trusted domain via the trust chain.
        source_auth_domain = str(source_data.get("auth_domain") or source_domain)
        source_auth_kdc = str(
            source_data.get("auth_kdc") or source_data.get("pdc") or ""
        )
        entries: list[ScopeEntry] = []
        for candidate in candidates:
            candidate_data = shell.domains_data.get(candidate, {})
            connectivity = candidate_data.get("connectivity", {})
            summary = (
                connectivity.get("summary", {})
                if isinstance(connectivity, dict)
                and isinstance(connectivity.get("summary", {}), dict)
                else {}
            )
            reachability = "reachable_ldap"
            degraded_reason = None
            if isinstance(summary, dict) and summary.get("reachable") is False:
                reachability = "unreachable"
                degraded_reason = str(summary.get("reason") or "") or None
            # Per-forest auth context: prefer the credential/KDC that actually
            # reached THIS candidate (persisted on its own domains_data by the
            # path that authenticated to it) — required for a selective/one-way
            # trust that needs a distinct credential per forest. Fall back to the
            # source broadcast for the transitive one-credential case.
            candidate_auth_domain = (
                str(candidate_data.get("auth_domain") or "").strip()
                or source_auth_domain
            )
            candidate_auth_kdc = (
                str(candidate_data.get("auth_kdc") or "").strip()
                or source_auth_kdc
            )
            entries.append(
                ScopeEntry(
                    domain=candidate,
                    dc_address=str(
                        candidate_data.get("pdc")
                        or domain_pdc_mapping.get(candidate)
                        or ""
                    ),
                    auth_domain=candidate_auth_domain,
                    auth_kdc=candidate_auth_kdc,
                    reachability=reachability,
                    in_scope=candidate.lower().strip() in selected,
                    kerberos_target_hostname=str(
                        candidate_data.get("pdc_hostname") or ""
                    )
                    or None,
                    degraded_reason=degraded_reason,
                )
            )

        scope_path = os.path.join(workspace_cwd, "scope.json")
        save_scope(ScopeResult(entries=entries), scope_path)
        print_info_debug(
            f"[scope] Persisted trust scope to {mark_sensitive(scope_path, 'path')}"
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[scope] Failed to persist scope.json: {exc}")


def _merge_domain_dc_set(
    shell: DomainShell,
    domain: str,
    dc_fqdns: list[str],
    degraded_reason: str | None,
    *,
    primary_dc_fqdn: str | None = None,
) -> None:
    """Persist a domain's full DC set into ``domains_data[domain]["dcs"]``.

    ``finalize_domain_context`` already appended the PDC *IP*; this adds the
    domain's other DC FQDNs (enumerated from its own Configuration NC) so
    ``resolve_domain_controllers`` reports the true multi-DC topology of a
    trusted forest instead of ``count == 1``.

    To avoid the alias-aware resolver miscounting the PDC (known only by IP) and
    its OWN FQDN as two DCs, the PDC's FQDN is stamped onto the primary DC
    field-group (``dc_fqdn``) when known — so the PDC's IP and FQDN fold into one
    record and only the *additional* DCs count as alternates.

    Best-effort and idempotent: a re-run adds no duplicates; a domain with no
    enumerated set (graceful degradation) records the reason and keeps today's
    PDC-only view.
    """
    if not isinstance(getattr(shell, "domains_data", None), dict):
        return
    domain_info = shell.domains_data.get(domain)
    if not isinstance(domain_info, dict):
        return

    from adscan_internal.services.credential_store_service import (  # noqa: PLC0415
        hosts_match,
    )

    if degraded_reason:
        domain_info["dc_set_enum_status"] = degraded_reason

    # Stamp the primary DC FQDN so the PDC IP<->FQDN link exists for the resolver.
    primary_fqdn = str(primary_dc_fqdn or "").strip()
    if primary_fqdn and not str(domain_info.get("dc_fqdn") or "").strip():
        domain_info["dc_fqdn"] = primary_fqdn

    if not dc_fqdns:
        return

    existing = domain_info.get("dcs")
    if not isinstance(existing, list):
        existing = []
    added = 0
    for fqdn in dc_fqdns:
        text = str(fqdn or "").strip()
        if not text:
            continue
        # Skip if an existing entry already aliases this DC (IP/short/FQDN aware).
        if any(hosts_match(text, str(e or "").strip()) for e in existing if e):
            continue
        existing.append(text)
        added += 1
    domain_info["dcs"] = existing

    if added:
        print_info_debug(
            f"[trust] Recorded {added} additional DC(s) for "
            f"{mark_sensitive(domain, 'domain')} from its Configuration NC "
            f"(full DC set now {len(existing)})."
        )


def _persist_trust_records_to_domains_data(
    shell: DomainShell, trusts: list[Any]
) -> None:
    """Store decoded trust records into ``domains_data[<source>]["trusts"]``.

    Each :class:`TrustRelationship` (or its already-serialized dict form) is
    grouped by its ``source_domain`` — the domain whose ``trustedDomain`` object
    it was read from — so a recursive multi-domain enumeration lands every trust
    under the domain that actually owns its TDO. This is the durable SSOT the
    attack-graph cross-forest coupling reads on load; without it the decoded
    ``trust_attributes`` / ``attribute_flags`` (including
    ``CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION``) live only in the in-memory
    enumeration result and never reach the graph load path.

    Idempotent: replaces the ``trusts`` list for each touched source domain with
    the freshly enumerated records (de-duplicated by ``target_domain``).
    """
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict) or not trusts:
        return

    grouped: dict[str, list[dict[str, Any]]] = {}
    for trust in trusts:
        record = trust.to_dict() if hasattr(trust, "to_dict") else trust
        if not isinstance(record, dict):
            continue
        source_domain = str(record.get("source_domain") or "").strip()
        if not source_domain:
            continue
        grouped.setdefault(source_domain, []).append(record)

    for source_domain, records in grouped.items():
        entry = domains_data.get(source_domain)
        if not isinstance(entry, dict):
            entry = {}
            domains_data[source_domain] = entry
        # De-duplicate by target domain, last write wins (freshest enumeration).
        deduped: dict[str, dict[str, Any]] = {}
        for record in records:
            key = str(record.get("target_domain") or "").strip().lower()
            deduped[key or str(len(deduped))] = record
        entry["trusts"] = list(deduped.values())


def _handle_trust_enumeration_result(
    shell: DomainShell,
    *,
    domain: str,
    trusts: list[Any],
    discovered_domains: list[str],
    domain_pdc_mapping: dict[str, str],
    cross_domain_unreachable: set[str] | None = None,
    domain_dc_sets: dict[str, list[str]] | None = None,
    dc_set_degraded_reasons: dict[str, str] | None = None,
    domain_dc_fqdns: dict[str, str] | None = None,
) -> None:
    """Process recursive trust enumeration results and update domain state.

    Args:
        cross_domain_unreachable: Lower-cased trusted-realm names that were
            discovered but whose own DCs are all unreachable from this vantage.
            These are forced to the discovered-but-unreachable path: no
            sub-workspace, no persisted PDC, no resolver/hosts entry, not offered
            for full enumeration — and any prior-run poison line is cleaned.
        domain_dc_sets: Per-domain full DC set (FQDNs) discovered from each
            domain's OWN Configuration NC during enumeration. Merged into
            ``domains_data[<domain>]["dcs"]`` so ``resolve_domain_controllers``
            reports the true count for a multi-DC trusted forest. A domain
            absent here degraded gracefully to the PDC-only view.
        dc_set_degraded_reasons: Per-domain reason a full DC set could not be
            enumerated (recorded on the domain for auditability; never blocks).
    """
    dc_sets = domain_dc_sets or {}
    dc_degraded = dc_set_degraded_reasons or {}
    dc_fqdns = domain_dc_fqdns or {}
    unreachable_realms = {
        name.strip().lower()
        for name in (cross_domain_unreachable or set())
        if name and name.strip()
    }
    # Persist the decoded trust records into ``domains_data`` (the canonical SSOT
    # the attack-graph cross-forest coupling and ``resolve_domain_controllers``
    # read). Keyed by each trust's OWN source domain so a multi-domain forest
    # enumeration lands each trust under the domain whose TDO it belongs to. This
    # is what carries ``trust_attributes`` / ``attribute_flags`` (incl.
    # CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION) durably to the graph load path.
    try:
        _persist_trust_records_to_domains_data(shell, trusts)
    except Exception as exc:  # noqa: BLE001 — never break trust-enum on persist
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    try:

        def _domain_reachable_from_current_vantage(candidate_domain: str) -> bool:
            """Return whether one trusted domain is currently reachable."""
            if candidate_domain == domain:
                return True
            # A trusted realm whose own A-records are all unreachable is NOT
            # reachable, regardless of any stale connectivity summary. This is the
            # cross-domain leak gate: it keeps the source DC IP out of the
            # workspace / PDC store / /etc/hosts / unbound / scope offer.
            if candidate_domain.strip().lower() in unreachable_realms:
                return False
            domain_state = (
                shell.domains_data.get(candidate_domain, {})
                if isinstance(getattr(shell, "domains_data", {}), dict)
                else {}
            )
            if not isinstance(domain_state, dict):
                return True
            connectivity = domain_state.get("connectivity", {})
            if not isinstance(connectivity, dict):
                return True
            summary = connectivity.get("summary", {})
            if not isinstance(summary, dict):
                return True
            if "reachable" not in summary:
                return True
            return bool(summary.get("reachable"))

        invalid_domains: set[str] = set()
        dns_service = None
        try:
            dns_service = shell._get_dns_discovery_service()
        except Exception:
            dns_service = None

        ordered_domains: list[str] = []
        seen_domains: set[str] = set()

        for main_domain in discovered_domains:
            if main_domain in invalid_domains or main_domain in seen_domains:
                continue
            seen_domains.add(main_domain)
            ordered_domains.append(main_domain)
            if main_domain not in shell.domains_data:
                shell.domains_data[main_domain] = {}
            is_reachable = _domain_reachable_from_current_vantage(main_domain)
            if is_reachable:
                shell.domains_data[main_domain]["auth"] = "auth"
                print_warning(f"Valid domain found: {main_domain}")
            else:
                marked_domain = mark_sensitive(main_domain, "domain")
                marked_pdc = mark_sensitive(
                    str(
                        shell.domains_data.get(main_domain, {})
                        .get("connectivity", {})
                        .get("summary", {})
                        .get("pdc_ip")
                        or domain_pdc_mapping.get(main_domain)
                        or ""
                    ),
                    "ip",
                )
                print_warning(
                    f"Trusted domain discovered but not currently reachable: {marked_domain}"
                    + (f" (PDC/DC {marked_pdc})" if str(marked_pdc).strip() else "")
                )
                # Stale-poison cleanup: a prior run may have written a wrong
                # /etc/hosts line or unbound forward-zone for this realm (e.g. the
                # source DC IP mapped onto the foreign DC FQDN before this fix).
                # Strip ADscan's own marker-scoped entries so the poison does not
                # survive. Only for realms we determined cross-domain-unreachable
                # this run — never touch a realm we merely have no summary for.
                if main_domain.strip().lower() in unreachable_realms and hasattr(
                    shell, "_clean_domain_entries"
                ):
                    try:
                        shell._clean_domain_entries(main_domain)
                    except Exception as cexc:  # noqa: BLE001
                        telemetry.capture_exception(cexc)
                        print_exception(exception=cexc)
                        print_warning_debug(
                            "cross_domain_cleanup failed for "
                            f"{mark_sensitive(main_domain, 'domain')}"
                        )
                continue
            pdc_ip = domain_pdc_mapping.get(main_domain)
            if (
                not pdc_ip
                and dns_service
                and hasattr(dns_service, "resolve_ipv4_addresses_robust")
            ):
                a_candidates = dns_service.resolve_ipv4_addresses_robust(main_domain)
                if len(a_candidates) == 1:
                    pdc_ip = a_candidates[0]
                    domain_pdc_mapping[main_domain] = pdc_ip
                    marked_domain = mark_sensitive(main_domain, "domain")
                    marked_ip = mark_sensitive(pdc_ip, "ip")
                    print_info_verbose(
                        f"Using A-record fallback for {marked_domain}: {marked_ip}"
                    )
                elif a_candidates:
                    marked_domain = mark_sensitive(main_domain, "domain")
                    marked_candidates = mark_sensitive(a_candidates, "ip")
                    print_info_verbose(
                        f"Multiple A-record candidates for {marked_domain}: {marked_candidates}"
                    )
            if pdc_ip:
                confirmed = confirm_domain_pdc_mapping(
                    shell,
                    domain=main_domain,
                    candidate_ip=pdc_ip,
                    interactive=bool(sys.stdin.isatty()),
                    mode_label="trust_enum",
                    on_reenter=lambda: (
                        main_domain,
                        prompt_pdc_ip_interactive(domain=main_domain),
                    ),
                )
                if confirmed:
                    main_domain, pdc_ip = confirmed
                else:
                    pdc_ip = None
                    print_warning(
                        "No confirmed DC/PDC for "
                        f"{mark_sensitive(main_domain, 'domain')}; continuing without a PDC."
                    )

            if pdc_ip:
                shell.domains_data.setdefault(main_domain, {})["pdc"] = pdc_ip
            if not os.path.exists(os.path.join("domains", main_domain)):
                shell.domains.append(main_domain)
                shell.domains = list(set(shell.domains))

                if pdc_ip:
                    marked_pdc_ip = mark_sensitive(pdc_ip, "ip")
                    print_info(
                        f"Creating workspace for {main_domain} with PDC IP: {marked_pdc_ip}"
                    )
                    shell.create_sub_workspace_for_domain(main_domain, pdc_ip)
                else:
                    print_info(f"Creating workspace for {main_domain} without PDC IP")
                    shell.create_sub_workspace_for_domain(main_domain)

                time.sleep(1)
                domain_path = os.path.join(shell.domains_dir, main_domain)
                cracking_path = os.path.join(domain_path, shell.cracking_dir)
                ldap_path = os.path.join(domain_path, shell.ldap_dir)

                for directory in [cracking_path, ldap_path]:
                    if not os.path.exists(directory):
                        os.makedirs(directory)

            if pdc_ip:
                # Trust-enumeration loop over DISCOVERED trusted/foreign domains:
                # populate each domain's domains_data (pdc/dc_ip/dcs/FQDN keys)
                # but never flip the operator's active REPL context to a
                # discovered domain — keep make_active False (the default).
                finalize_domain_context(
                    shell,
                    domain=main_domain,
                    pdc_ip=pdc_ip,
                    interactive=False,
                    make_active=False,
                )
                # Merge this domain's FULL DC set (FQDNs from its own
                # Configuration NC) alongside the PDC that finalize_domain_context
                # just appended, so resolve_domain_controllers() sees the true
                # multi-DC topology of a trusted forest instead of count==1.
                _merge_domain_dc_set(
                    shell,
                    main_domain,
                    dc_sets.get(main_domain, []),
                    dc_degraded.get(main_domain),
                    primary_dc_fqdn=dc_fqdns.get(main_domain),
                )

        from adscan_internal import (
            create_domains_table,
            get_console,
            print_results_summary,
        )

        ordered_domains = order_domains_for_scan(domain, ordered_domains)

        discovered_domains_data: dict[str, dict[str, Any]] = {}
        for main_domain in ordered_domains:
            domain_state = (
                shell.domains_data.get(main_domain, {})
                if isinstance(getattr(shell, "domains_data", {}), dict)
                else {}
            )
            connectivity_summary = (
                domain_state.get("connectivity", {}).get("summary", {})
                if isinstance(domain_state, dict)
                and isinstance(domain_state.get("connectivity", {}), dict)
                else {}
            )
            discovered_domains_data[main_domain] = {
                "pdc": domain_pdc_mapping.get(main_domain, "N/A"),
                "auth": "auth",
                "reachable": (
                    bool(connectivity_summary.get("reachable"))
                    if isinstance(connectivity_summary, dict)
                    and "reachable" in connectivity_summary
                    else main_domain == domain
                ),
            }

        if trusts:
            # Legacy verbose-only summary; the new summary panel is rendered
            # in run_enum_trusts() before this handler. Keep as a debug aid.
            if getattr(shell, "verbose", False):
                print_results_summary(
                    "Trust Enumeration Results",
                    {
                        "Source Domain": domain,
                        "Trusted Domains Found": max(len(ordered_domains) - 1, 0),
                        "Trust Relationships Found": len(trusts),
                        "Status": "Completed Successfully",
                    },
                )
                if discovered_domains_data:
                    console = get_console()
                    table = create_domains_table(
                        discovered_domains_data,
                        title="Discovered Trust Relationships",
                    )
                    console.print(table)
            for trusted_domain, connectivity in sorted(
                (
                    (name, data)
                    for name, data in domain_pdc_mapping.items()
                    if name != domain
                ),
                key=lambda item: item[0].lower(),
            ):
                stored_connectivity = (
                    shell.domains_data.get(trusted_domain, {}).get("connectivity", {})
                    if isinstance(shell.domains_data.get(trusted_domain, {}), dict)
                    else {}
                )
                if not isinstance(stored_connectivity, dict) or not stored_connectivity:
                    continue
                summary = stored_connectivity.get("summary", {})
                if isinstance(summary, dict) and summary.get("reachable"):
                    continue
                marked_domain = mark_sensitive(trusted_domain, "domain")
                marked_pdc = mark_sensitive(
                    str(
                        (
                            summary.get("pdc_ip")
                            if isinstance(summary, dict)
                            else stored_connectivity.get("pdc_ip")
                        )
                        or connectivity
                    ),
                    "ip",
                )
                print_warning(
                    f"Skipping recursive trust enumeration for {marked_domain}: "
                    f"PDC/DC {marked_pdc} is not reachable from the current vantage."
                )

            # All reachable domains — including those with Phase 1 already done.
            # Domains with Phase 1 complete are still included because they need
            # their attack graph rebuilt with the new cross-domain context.
            all_reachable = [
                main_domain
                for main_domain in ordered_domains
                if _domain_reachable_from_current_vantage(main_domain)
            ]

            # Track which domains already have BH data collected.
            phase1_complete_set: set[str] = {
                d
                for d in all_reachable
                if bool(shell.domains_data.get(d, {}).get("phase1_complete"))
            }

            # Exclude domains fully enumerated with no new cross-domain peers.
            # If every reachable domain already ran Phase 1 AND there are no new
            # domains to add context, there is nothing to do.
            new_domains = [d for d in all_reachable if d not in phase1_complete_set]
            if all_reachable == [domain] and any(
                candidate != domain for candidate in ordered_domains
            ):
                print_info(
                    "Trust analysis found no reachable trusted domains from the current vantage."
                )
                shell.domains_data.setdefault(domain, {})["auth"] = "auth"
                shell.ask_for_enum_domain_auth(domain)
                return
            if not all_reachable or (not new_domains and len(all_reachable) <= 1):
                print_info(
                    "Trust analysis completed, but all reachable trusted domains "
                    "were already fully enumerated."
                )
                return

            # On a platform-launched scan with >1 reachable domain, delegate the
            # trust-scope decision to the operator via the remote interaction
            # bridge (premium domain-topology picker). Returns None when the
            # bridge is off / single-domain — then the local prompt is used,
            # which keeps the origin-only default for headless ci.
            selected_domains = _remote_trust_scope_selection(
                shell,
                candidates=all_reachable,
                source_domain=domain,
                phase1_complete_domains=phase1_complete_set,
                trusts=trusts,
                domain_pdc_mapping=domain_pdc_mapping,
            )
            if selected_domains is None:
                selected_domains = _prompt_scope_selection(
                    all_reachable,
                    source_domain=domain,
                    phase1_complete_domains=phase1_complete_set,
                    shell=shell,
                )
            _persist_scope_selection(
                shell,
                source_domain=domain,
                candidates=all_reachable,
                selected_domains=selected_domains,
                domain_pdc_mapping=domain_pdc_mapping,
            )

            if not selected_domains:
                print_info("No trusted domains selected for enumeration.")
                return

            # Separate domains by what work they need.
            phase1_needed = [
                d for d in selected_domains if d not in phase1_complete_set
            ]
            phase2_all = selected_domains  # every selected domain needs graph rebuilt

            # Collection FIRST for every domain that still needs it. This MUST
            # finish for ALL selected domains before any attack-paths compute runs,
            # because the merged multi-domain graph is read-time: each per-domain
            # attack-path DFS reads every domain's on-disk ``attack_graph.json`` and
            # only sees a complete, trust-coupled forest once every graph exists.
            # (An already-enumerated selected peer + the source domain already have
            # theirs from an earlier run, so only ``phase1_needed`` collect here.)
            for main_domain in phase1_needed:
                shell.do_enum_domain_auth_phase1(main_domain)

            # ---- INTERLEAVED per-domain enumeration --------------------------
            # After collection, run ONE loop over the selected domains that, for
            # EACH domain in turn, computes THAT domain's attack paths and then runs
            # THAT domain's remaining phases (quick wins, spraying, SMB, unauth, CVE
            # …) before moving to the next domain — instead of the old two-loop shape
            # ``[attack-paths for ALL domains] → [phases-3+ for EACH domain]``.
            #
            # Consequence, ACCEPTED intentionally: an earlier domain is EXPLOITED
            # (its phases-3+ run) before a later domain computes its attack paths, so
            # the later domain sees the graph/credentials already mutated by the
            # earlier domain's exploitation — realistic cross-domain chaining. Merged-
            # graph correctness is unaffected: the merge is read-time and every
            # domain's graph is already on disk before this loop starts (above).
            #
            # State that MUST persist across iterations — and does, because the loop
            # shares ONE ``shell``:
            #   * the credential pool / ``domains_data`` the shell accumulates as
            #     each domain is exploited (so what an earlier domain cracks is
            #     available to a later domain's compute + execution);
            #   * ONE ``seen_path_keys`` de-duplication ledger threaded through every
            #     per-domain attack-paths call, so a cross-domain path reachable from
            #     several trust-connected domains is shown once (under the first
            #     domain that lists it) even though each domain's attack-paths run is
            #     now interleaved with its own phases-3+;
            #   * the per-domain ``scan_progress`` checkpoint (each domain's phase
            #     lifecycle marks ``attack_paths_discovery`` complete for itself).
            #
            # The attack-paths lifecycle (announce + compute + checkpoint) is owned
            # by the single seam ``run_attack_paths_discovery_phase`` — the SAME seam
            # the per-domain Phase 2 in ``run_enumeration`` routes through — so this
            # pivot can never announce the phase without also marking it complete (the
            # resume-checkpoint HOLE that ``74cb0c72`` half-fixed). ``announce=True``
            # per domain: each domain's attack-paths gets its own chapter right before
            # its phases-3+, matching the interleaved narrative and the per-domain
            # chapters ``run_enumeration`` already emits for phases 3+.
            #
            # Checkpoint set is preserved EXACTLY: the source domain plus every
            # ``phase1_needed`` domain get ``attack_paths_discovery`` marked (those are
            # the domains whose ``scan_progress`` record this pivot drives, where the
            # hole would otherwise be permanent). Already-complete selected peers keep
            # their own (complete) checkpoint — not re-marked here, matching the prior
            # ``[domain, *phase1_needed]`` set rather than all of ``phase2_all``.
            from adscan_internal.services.attack_paths_phase import (
                run_attack_paths_discovery_phase,
            )

            checkpoint_set = {domain, *phase1_needed}
            phase1_needed_set = set(phase1_needed)
            seen_path_keys: set[tuple[Any, ...]] = set()
            for main_domain in phase2_all:
                run_attack_paths_discovery_phase(
                    shell,
                    domains=[main_domain],
                    checkpoint_domains=(
                        [main_domain] if main_domain in checkpoint_set else []
                    ),
                    span_domain=main_domain,
                    scan_type=getattr(shell, "type", "default"),
                    announce=True,
                    seen_path_keys=seen_path_keys,
                )
                # Phase 3+ only for domains that needed Phase 1 here (new domains).
                # An already-enumerated selected peer completed phases 3+ in its own
                # earlier full run, and the source domain completed them before this
                # pivot; re-running would repeat spraying (lockout-critical) and SMB
                # touches. This mirrors the old ``for main_domain in phase1_needed``
                # loop exactly — only now each domain's phases-3+ run immediately
                # after its own attack paths, not after every domain's.
                if main_domain in phase1_needed_set:
                    shell.run_enumeration(main_domain, start_from_phase=3)

            # Defensive: if the operator deselected the source domain from scope so
            # it never appeared in ``phase2_all`` above, its ``attack_paths_discovery``
            # checkpoint would be missed. The old code checkpointed the source domain
            # unconditionally (``[domain, *phase1_needed]``); preserve that so a
            # crash-resume never reports a false hole for the origin.
            if domain not in phase2_all:
                from adscan_internal.services import scan_progress as _scan_progress

                _scan_progress.mark_phase_complete(
                    shell, domain, "attack_paths_discovery"
                )
        else:
            print_info("No trust relationships found.")
            shell.domains_data[domain]["auth"] = "auth"
            shell.ask_for_enum_domain_auth(domain)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error(
            "An unexpected error occurred while processing trust enumeration output."
        )
        print_exception(show_locals=False, exception=exc)

        # A failure provisioning a DISCOVERED TRUST PARTNER (e.g. it has no
        # confirmed DC IP and DNS resolution cannot be configured for it) must
        # not silently abandon the PRIMARY domain's scan. By the time this
        # function runs, the primary domain's own auth/PDC/setup already
        # succeeded independently (``run_enum_trusts`` requires
        # ``shell.domains_data[domain]["pdc"]`` before calling this handler),
        # so resume it via the SAME path the normal "no reachable trusted
        # domains" flow above uses instead of swallowing the exception.
        try:
            failed_partner = main_domain  # noqa: F821 — set if the failure hit the per-domain loop
        except NameError:
            failed_partner = None
        marked_domain = mark_sensitive(domain, "domain")
        if failed_partner and failed_partner != domain:
            marked_partner = mark_sensitive(failed_partner, "domain")
            print_warning(
                f"Trust partner {marked_partner} could not be provisioned; "
                f"continuing the scan for the primary domain {marked_domain}."
            )
        else:
            print_warning(
                f"Trust-partner provisioning failed; continuing the scan for "
                f"the primary domain {marked_domain}."
            )
        try:
            shell.domains_data.setdefault(domain, {})["auth"] = "auth"
            shell.ask_for_enum_domain_auth(domain)
        except Exception as resume_exc:  # noqa: BLE001
            telemetry.capture_exception(resume_exc)
            print_exception(exception=resume_exc)
            print_error(
                f"Failed to resume enumeration for the primary domain {marked_domain} "
                "after the trust-partner provisioning error."
            )
