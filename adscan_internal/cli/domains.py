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
)
from adscan_internal.cli.ci_events import emit_phase
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
    enum_trusts_path: str | None
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

    try:
        if not shell.netexec_path:
            print_error(
                "NetExec (nxc) executable not found. Please ensure NetExec is installed and configured."
            )
            return

        # Professional operation header
        from adscan_internal import print_operation_header
        from adscan_internal.services.domain_service import DomainService

        username = shell.domains_data[domain]["username"]
        password = shell.domains_data[domain]["password"]
        pdc = shell.domains_data[domain]["pdc"]

        emit_phase("trust_enumeration")
        print_operation_header(
            "Trust Enumeration",
            details={
                "Domain": domain,
                "PDC": pdc,
                "Username": username,
            },
            icon="🔗",
        )

        marked_domain = mark_sensitive(domain, "domain")
        marked_user = mark_sensitive(username, "user")
        marked_password = mark_sensitive(password, "password")
        marked_pdc = mark_sensitive(pdc, "ip")
        cmd_preview = (
            f"{shell.netexec_path} ldap {marked_pdc} -u {marked_user} "
            f"-p {marked_password} -d {marked_domain} --dc-list"
        )
        print_info_debug(f"Recursive trust enumeration via NetExec: {cmd_preview}")

        dns_service = None
        try:
            dns_service = shell._get_dns_discovery_service()
        except Exception:
            dns_service = None

        def _execute(
            command: str, timeout_seconds: int
        ) -> subprocess.CompletedProcess[str] | None:
            netexec_runner = getattr(shell, "_run_netexec", None)
            if callable(netexec_runner):
                return netexec_runner(
                    command,
                    domain=domain,
                    timeout=timeout_seconds,
                )
            return shell.run_command(command, timeout=timeout_seconds)

        def _resolve_pdc_ip(trusted_domain: str, resolver_ip: str) -> str | None:
            if not dns_service or not hasattr(dns_service, "find_pdc_with_selection"):
                return None
            selected_ip, _ = dns_service.find_pdc_with_selection(
                domain=trusted_domain,
                resolver_ip=resolver_ip,
                preferred_ips=[resolver_ip],
                reference_ip=resolver_ip,
            )
            return selected_ip

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

        service = DomainService()
        result = service.enumerate_trusts(
            domain=domain,
            pdc=pdc,
            username=username,
            password=password,
            netexec_path=shell.netexec_path,
            executor=_execute,
            resolve_pdc_ip=_resolve_pdc_ip,
            check_domain_reachability=_check_trusted_domain_reachability,
        )

        merge_domain_connectivity(
            shell,
            source_domain=domain,
            connectivity_updates=result.domain_connectivity,
        )
        if result.domain_connectivity and hasattr(shell, "save_workspace_data"):
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
                "Ensure NetExec is properly installed",
            ],
            show_exception=True,
            exception=exc,
        )


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


def _handle_trust_enumeration_result(
    shell: DomainShell,
    *,
    domain: str,
    trusts: list[Any],
    discovered_domains: list[str],
    domain_pdc_mapping: dict[str, str],
) -> None:
    """Process recursive trust enumeration results and update domain state."""
    try:
        def _domain_reachable_from_current_vantage(candidate_domain: str) -> bool:
            """Return whether one trusted domain is currently reachable."""
            if candidate_domain == domain:
                return True
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
                    + (
                        f" (PDC/DC {marked_pdc})"
                        if str(marked_pdc).strip()
                        else ""
                    )
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
                finalize_domain_context(
                    shell,
                    domain=main_domain,
                    pdc_ip=pdc_ip,
                    interactive=False,
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

            pending_auth_domains = [
                main_domain
                for main_domain in ordered_domains
                if _domain_reachable_from_current_vantage(main_domain)
                if not bool(
                    shell.domains_data.get(main_domain, {}).get("phase1_complete")
                )
            ]

            if not pending_auth_domains:
                print_info(
                    "Trust analysis completed, but all reachable trusted domains were already authenticated and analyzed."
                )
                return

            if len(pending_auth_domains) > 1:
                for main_domain in pending_auth_domains:
                    shell.do_enum_domain_auth_phase1(main_domain)
                for main_domain in pending_auth_domains:
                    shell.ask_for_enum_domain_auth(main_domain)
            else:
                for main_domain in pending_auth_domains:
                    shell.ask_for_enum_domain_auth(main_domain)
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
