"""Domain CLI helpers (workspace sub-scope).

This module hosts interactive domain management logic used by the legacy CLI.
It intentionally depends on dependency injection (the shell object) to avoid
import cycles into `adscan.py`.
"""

from __future__ import annotations

from collections.abc import Sequence
import os
import sys
import time
import subprocess
from typing import Any, Protocol

import curses
from rich.prompt import IntPrompt

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


class DomainShell(Protocol):
    """Protocol for domain management methods on the legacy shell."""

    current_workspace: str | None
    current_workspace_dir: str | None
    current_domain: str | None
    current_domain_dir: str | None
    domains_dir: str
    domain_path: str | None
    domains: list[str]
    domains_data: dict[str, dict[str, Any]]
    cracking_dir: str
    ldap_dir: str
    netexec_path: str | None
    domain_connectivity: dict[str, dict[str, Any]]

    def save_domain_data(self) -> None: ...

    def load_workspace_data(self, workspace_path: str) -> None: ...

    def workspace_save(self) -> None: ...

    def select_domain_curses(self, stdscr: Any, domains: Sequence[str]) -> None: ...

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
    """Save the current domain data."""
    if not shell.current_domain:
        print_error("No domain selected.")
        return
    shell.save_domain_data()
    print_success(f"Domain data for '{shell.current_domain}' saved.")


def domain_create(shell: DomainShell, domain_name: str) -> None:
    """Create a new domain directory under the current workspace."""
    from adscan_internal.workspaces import create_domain_dir, resolve_domain_paths

    domain_path = resolve_domain_paths(
        shell.current_workspace_dir,
        shell.domains_dir,
        domain_name,
    ).domain_dir
    if os.path.exists(domain_path):
        marked_domain_name = mark_sensitive(domain_name, "domain")
        print_error(f"Domain '{marked_domain_name}' already exists.")
        return
    create_domain_dir(shell.current_workspace_dir, shell.domains_dir, domain_name)
    marked_domain_name = mark_sensitive(domain_name, "domain")
    print_success(f"Domain '{marked_domain_name}' created in '{shell.domains_dir}'.")


def domain_delete(shell: DomainShell, domain_name: str) -> None:
    """Delete an existing domain directory."""
    from adscan_internal.workspaces import (
        delete_domain_dir,
        resolve_domain_paths,
        resolve_domains_root,
    )

    shell.domain_path = resolve_domains_root(
        shell.current_workspace_dir, shell.domains_dir
    )
    domain_path = resolve_domain_paths(
        shell.current_workspace_dir,
        shell.domains_dir,
        domain_name,
    ).domain_dir
    if not os.path.exists(domain_path):
        marked_domain_name = mark_sensitive(domain_name, "domain")
        print_error(f"Domain '{marked_domain_name}' does not exist.")
        return
    delete_domain_dir(shell.current_workspace_dir, shell.domains_dir, domain_name)
    marked_domain_name = mark_sensitive(domain_name, "domain")
    print_success(f"Domain '{marked_domain_name}' deleted.")


def domain_select(shell: DomainShell) -> None:
    """Select a domain under the current workspace."""
    from adscan_internal.workspaces import activate_domain, list_domains

    shell.domain_path = os.path.join(
        shell.current_workspace_dir or "", shell.domains_dir
    )
    domains = list_domains(shell.current_workspace_dir, shell.domains_dir)
    if not domains:
        print_error("No domains available.")
        return

    if shell.current_domain:
        domain_save(shell)

    if shell.current_workspace:
        shell.workspace_save()

    if len(domains) == 1:
        activate_domain(
            shell,
            workspace_dir=shell.current_workspace_dir,
            domains_dir_name=shell.domains_dir,
            domain=domains[0],
        )
        shell.load_workspace_data(shell.current_domain_dir or "")
        print_success(f"Domain '{shell.current_domain}' selected automatically.\n")
        return

    try:
        if (
            sys.stdin.isatty()
            and sys.stdout.isatty()
            and os.environ.get("TERM", "") not in ("", "dumb", "unknown")
        ):
            curses.wrapper(shell.select_domain_curses, domains)
            return
    except Exception as exc:  # noqa: BLE001
        try:
            telemetry.capture_exception(exc)
        except Exception:
            pass

    print_info("Select a domain:")
    for i, domain in enumerate(domains, 1):
        print_info(f"  {i}. {domain}", spacing="none")

    try:
        idx = IntPrompt.ask("Enter a number (0 to cancel)", default=1)
    except Exception:
        return
    if idx == 0:
        return
    if 1 <= idx <= len(domains):
        activate_domain(
            shell,
            workspace_dir=shell.current_workspace_dir,
            domains_dir_name=shell.domains_dir,
            domain=domains[idx - 1],
        )
        shell.load_workspace_data(shell.current_domain_dir or "")
        print_success(f"Domain '{shell.current_domain}' selected.")


def domain_show(shell: DomainShell) -> None:
    """List available domains."""
    from adscan_internal.workspaces import list_domains

    shell.domain_path = os.path.join(
        shell.current_workspace_dir or "", shell.domains_dir
    )
    domains = list_domains(shell.current_workspace_dir, shell.domains_dir)
    if not domains:
        print_error("No domains available.")
        return
    print_info("[bold]Available domains:[/bold]")
    for domain in domains:
        marked_domain = mark_sensitive(domain, "domain")
        print_info(f"  • {marked_domain}")


def run_enum_trusts(shell: DomainShell, domain: str) -> None:
    """Enumerate trusts for a domain and update workspace/domain metadata.

    This is a CLI orchestration helper extracted from the legacy shell to keep
    `adscan.py` slimmer. It expects PRO checks to have been done by the caller.
    """
    # Honor the scan-config trust-enumeration policy. ``skip`` short-circuits
    # before any DC contact; ``selected`` constrains the recursive BFS to the
    # listed partner domains; ``all`` / ``interactive`` (default) run the full
    # enumeration exactly as before. Absent config = interactive = unchanged.
    from adscan_internal.services.scan_config import (
        TRUST_POLICY_SELECTED,
        TRUST_POLICY_SKIP,
    )

    scan_config = getattr(shell, "scan_config", None)
    trust_cfg = getattr(scan_config, "trust_enumeration", None)
    trust_policy = getattr(trust_cfg, "policy", None)
    trust_allowlist: set[str] | None = None
    if trust_policy == TRUST_POLICY_SKIP:
        print_info("Trust enumeration skipped (disabled in scan configuration).")
        return
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


def _prompt_scope_selection(
    candidates: list[str],
    source_domain: str,
    phase1_complete_domains: set[str] | None = None,
) -> list[str]:
    """Ask the user which trusted domains to include in scope.

    Domains with Phase 1 already completed are shown with a re-run label so the
    operator understands only the attack graph is rebuilt, not the full BH collection.
    In non-interactive environments only the source (origin) domain is returned —
    trusted domains are not auto-enumerated unless the operator opts in.

    Args:
        candidates: All reachable domains to offer (including source).
        source_domain: The domain trust enumeration was launched from.
        phase1_complete_domains: Domains whose BH collection is already done.

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

    from adscan_internal.interaction import is_non_interactive as _is_non_interactive
    if _is_non_interactive():
        # Default scope = the origin domain only. Trusted domains are NOT auto-
        # enumerated unless the operator explicitly opts in (a client often does not
        # authorize enumerating trusted domains). The platform surfaces an interactive
        # trust-scope selection for opt-in; headless ci stays origin-only.
        return [source_domain] if source_domain in candidates else candidates[:1]

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

        selected = prompting.questionary_checkbox_values_raw(
            title="Select domains to include in scope:",
            options=options,
            default_values=[source_domain] if source_domain in options else options[:1],
            labels_by_value=labels_by_value,
        )

        if selected is None:
            # Ctrl-C / cancelled — fall back to the origin domain only (the safe
            # default: never silently enumerate trusted domains on a cancel).
            return [source_domain] if source_domain in candidates else candidates[:1]

        return [d for d in candidates if d in set(selected)]
    except Exception:
        return [source_domain] if source_domain in candidates else candidates[:1]


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

    The multiselect default and the timeout result are both origin-only, so a
    hung/abandoned/timed-out session never blocks past the request timeout and
    never silently enumerates trusted domains.
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
    origin_default = (
        [source_domain] if source_domain in candidates else candidates[:1]
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
            default_values=origin_default,
            timeout_values=origin_default,
            context=context,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
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
        auth_domain = str(source_data.get("auth_domain") or source_domain)
        auth_kdc = str(source_data.get("auth_kdc") or source_data.get("pdc") or "")
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
            entries.append(
                ScopeEntry(
                    domain=candidate,
                    dc_address=str(
                        candidate_data.get("pdc")
                        or domain_pdc_mapping.get(candidate)
                        or ""
                    ),
                    auth_domain=auth_domain,
                    auth_kdc=auth_kdc,
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
        print_info_debug(f"[scope] Failed to persist scope.json: {exc}")


def _handle_trust_enumeration_result(
    shell: DomainShell,
    *,
    domain: str,
    trusts: list[Any],
    discovered_domains: list[str],
    domain_pdc_mapping: dict[str, str],
    cross_domain_unreachable: set[str] | None = None,
) -> None:
    """Process recursive trust enumeration results and update domain state.

    Args:
        cross_domain_unreachable: Lower-cased trusted-realm names that were
            discovered but whose own DCs are all unreachable from this vantage.
            These are forced to the discovered-but-unreachable path: no
            sub-workspace, no persisted PDC, no resolver/hosts entry, not offered
            for full enumeration — and any prior-run poison line is cleaned.
    """
    unreachable_realms = {
        name.strip().lower()
        for name in (cross_domain_unreachable or set())
        if name and name.strip()
    }
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

            # Phase 1: native collection only for domains that haven't been collected yet.
            for main_domain in phase1_needed:
                shell.do_enum_domain_auth_phase1(main_domain)

            # Attack Paths Discovery for the trust/cross-domain pivot. This runs
            # OUTSIDE ``run_enumeration`` because the merged multi-domain graph can
            # only be built after every selected domain's Phase-1 chunk above has
            # populated its ``attack_graph.json``. The lifecycle (announce +
            # compute + checkpoint) is owned by the single seam
            # ``run_attack_paths_discovery_phase`` — the SAME seam the per-domain
            # Phase 2 in ``run_enumeration`` routes through — so this pivot can
            # never again announce the phase without also marking it complete (the
            # resume-checkpoint HOLE that ``74cb0c72`` half-fixed). ``announce=True``
            # here (the seam emits the chapter ONCE, covering both the merged
            # cross-domain pass and the single selected-domain pass, and keeps the
            # worker's ``current_phase`` advancing past ``domain_analysis``). The
            # merged-vs-single choice is a parameter (``len(domains)``), not a fork.
            #
            # Checkpoint the phase for the source domain plus every domain that
            # still needs its phases-3+ chunk (``phase1_needed``) — those are the
            # domains whose ``scan_progress`` record this pivot drives and where the
            # hole would otherwise be permanent. Already-complete peers keep their
            # own (complete) checkpoint; the mark is idempotent.
            from adscan_internal.services.attack_paths_phase import (
                run_attack_paths_discovery_phase,
            )

            checkpoint_domains = list(dict.fromkeys([domain, *phase1_needed]))
            run_attack_paths_discovery_phase(
                shell,
                domains=phase2_all,
                checkpoint_domains=checkpoint_domains,
                span_domain=domain,
                scan_type=getattr(shell, "type", "default"),
                announce=True,
            )

            # Phase 3+: only for new domains (credential spraying, share scan, etc.)
            # Already-enumerated domains completed these phases before the pivot.
            for main_domain in phase1_needed:
                shell.run_enumeration(main_domain, start_from_phase=3)
        else:
            print_info("No trust relationships found.")
            shell.domains_data[domain]["auth"] = "auth"
            shell.ask_for_enum_domain_auth(domain)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error(
            "An unexpected error occurred while processing trust enumeration output."
        )
        from adscan_internal.rich_output import print_exception

        print_exception(show_locals=False, exception=exc)
