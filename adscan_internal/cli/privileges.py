"""CLI helpers for privilege enumeration commands."""

from __future__ import annotations

from typing import Any
import os
import shlex

from adscan_internal import (
    print_error,
    print_exception,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_success,
    print_warning,
    telemetry,
)
from adscan_core.interaction import is_non_interactive
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.integrations.netexec.timeouts import (
    get_recommended_internal_timeout,
)
from adscan_internal.cli.rdp import run_rdp_service_access_sweep_with_medusa
from adscan_internal.services.service_access_probe_history import (
    load_service_access_probe_history,
    partition_targets_by_probe_history,
)
from adscan_internal.workspaces import domain_subpath
from adscan_internal.workspaces.computers import (
    count_target_file_entries,
    consume_service_targeting_fallback_notice,
    load_target_entries,
    resolve_domain_service_scope_preference,
    resolve_domain_service_target_file,
)
from rich.prompt import Confirm


def _build_service_sweep_target_argument(
    *,
    workspace_dir: str,
    domains_dir: str,
    domain: str,
    service: str,
    username: str,
    targets: list[str],
) -> str | None:
    """Materialize one host list into the argument expected by service backends."""
    cleaned_targets = [
        str(target).strip() for target in targets if str(target or "").strip()
    ]
    if not cleaned_targets:
        return None
    if len(cleaned_targets) == 1:
        return cleaned_targets[0]

    tmp_dir = domain_subpath(workspace_dir, domains_dir, domain, "tmp")
    os.makedirs(tmp_dir, exist_ok=True)
    targets_path = os.path.join(
        tmp_dir,
        f"hosts.{service}.{username}.filtered.txt",
    )
    with open(targets_path, "w", encoding="utf-8") as handle:
        for entry in cleaned_targets:
            handle.write(entry + "\n")
    return targets_path


def _select_effective_service_targets(
    shell: Any,
    *,
    workspace_dir: str,
    domains_dir: str,
    domain: str,
    username: str,
    service: str,
    current_targets: list[str],
    include_previously_tested: bool,
) -> list[str]:
    """Return the target list that should be probed for one service sweep.

    By default, previously tested targets are skipped. When every target was
    already checked, the caller may offer a re-check prompt with a default of
    ``No`` so the operator can intentionally opt back into reprobing.
    """
    if include_previously_tested:
        return list(current_targets)

    history = load_service_access_probe_history(
        workspace_dir=workspace_dir,
        domains_dir=domains_dir,
        domain=domain,
    )
    fresh_targets, previous_records = partition_targets_by_probe_history(
        records=history,
        username=username,
        service=service,
        targets=current_targets,
    )
    if fresh_targets:
        if previous_records:
            print_info(
                f"Skipping {len(previous_records)} previously tested "
                f"{service.upper()} target(s) by default. Checking "
                f"{len(fresh_targets)} new target(s)."
            )
            skipped_hosts = [
                mark_sensitive(str(record.get("host") or ""), "hostname")
                for record in previous_records
                if str(record.get("host") or "").strip()
            ]
            if skipped_hosts:
                print_info_debug(
                    "[privileges] previously tested targets skipped by default: "
                    f"service={service} user={mark_sensitive(username, 'user')} "
                    f"targets={skipped_hosts}"
                )
        return fresh_targets

    if not previous_records:
        return list(current_targets)

    prompt = (
        f"All current {service.upper()} targets for "
        f"{mark_sensitive(username, 'user')} were tested before. Re-check them now?"
    )
    confirmer = getattr(shell, "_questionary_confirm", None)
    should_recheck = (
        bool(confirmer(prompt, default=False))
        if callable(confirmer)
        else False
    )
    if should_recheck:
        print_info(
            f"Re-checking {len(previous_records)} previously tested "
            f"{service.upper()} target(s) by user choice."
        )
        return list(current_targets)

    print_info(
        f"Skipping {service.upper()} sweep because all {len(previous_records)} "
        "current target(s) were already tested."
    )
    return []


def _resolve_next_broader_scope(
    *,
    service: str,
    source: str,
    current_scope_preference: str,
) -> str | None:
    """Return the next broader target scope after one empty sweep."""
    normalized_source = str(source or "").strip().lower()
    normalized_scope = str(current_scope_preference or "optimized").strip().lower()

    if normalized_scope == "full":
        return None
    if normalized_scope == "reachable":
        return "full"
    if normalized_source.startswith(f"{service}_ips"):
        return "reachable"
    if normalized_source.startswith("reachable_ips"):
        return "full"
    return None


def _prompt_broader_postauth_scope_retry(
    shell: Any,
    *,
    service: str,
    domain: str,
    current_source: str,
    next_scope_preference: str,
    next_target_count: int,
) -> bool:
    """Ask whether to retry one empty service sweep with a broader scope."""
    _ = domain
    if is_non_interactive(shell):
        return False
    if not hasattr(shell, "_questionary_select"):
        return False

    scope_label_map = {
        "reachable": "Current-vantage reachable hosts only",
        "full": "Full resolved host scope",
    }
    next_scope_label = scope_label_map.get(next_scope_preference, next_scope_preference)
    options = [
        f"Retry {service.upper()} sweep with {next_scope_label} ({next_target_count} targets)",
        "Skip broader retry",
    ]
    selected_idx = shell._questionary_select(  # type: ignore[attr-defined]
        (
            f"No {service.upper()} privileges were found using "
            f"{current_source}. Broaden the sweep?"
        ),
        options,
        default_idx=0,
    )
    return selected_idx == 0


def run_enum_all_user_postauth_access(shell: Any, args: str | None) -> None:
    """Run post-auth user access enumeration for all users in a domain.

    This extracts the logic from the shell wrapper so orchestration
    can live outside ``adscan.py``.
    """
    if not args:
        print_error("You must specify a domain. Usage: enum_all_privs <domain>")
        return

    domain = args.strip()

    # Verify that the domain exists in domains_data
    if domain not in shell.domains_data:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"The domain {marked_domain} is not in the database.")
        return

    marked_domain = mark_sensitive(domain, "domain")
    print_success(
        f"Enumerating post-auth access for all users in domain {marked_domain}"
    )

    # Check if credentials are stored
    if (
        "credentials" not in shell.domains_data[domain]
        or not shell.domains_data[domain]["credentials"]
    ):
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"No credentials stored for domain {marked_domain}")
        return

    auto = Confirm.ask("Do you want to perform automatic enumeration", default=False)

    # Iterate over each user and their credentials
    for username, credential in shell.domains_data[domain]["credentials"].items():
        # Check if the credential is a hash or a password
        if shell.is_hash(credential):
            marked_username = mark_sensitive(username, "user")
            print_error(
                f"Skipping user {marked_username} - has a hash instead of a password"
            )
            continue

        # Call ask_for_user_privs for each user
        if not auto:
            auto = Confirm.ask(
                "Do you want to switch to automatic enumeration", default=False
            )
        shell.ask_for_user_privs(domain, username, credential, auto)


def run_enum_all_user_privs(shell: Any, args: str | None) -> None:
    """Backward-compatible alias for all-user post-auth access enumeration."""
    run_enum_all_user_postauth_access(shell, args)


def run_netexec_user_postauth_access(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    hosts: list[str] | None = None,
) -> None:
    """Enumerate post-auth service access for a user across multiple services."""
    if domain not in shell.domains_data:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"Domain {marked_domain} not found.")
        return

    marked_username = mark_sensitive(username, "user")
    marked_domain = mark_sensitive(domain, "domain")
    response = Confirm.ask(
        "Do you want to enumerate host/service access for user "
        f"{marked_username} on various services on hosts? "
        f"(⚠ WARNING: This will saturate the network if the number of hosts in domain {marked_domain} is very high)"
    )
    if not response:
        return

    run_service_access_sweep(
        shell,
        domain=domain,
        username=username,
        password=password,
        services=["smb", "winrm", "rdp", "mssql"],
        hosts=hosts,
        prompt=True,
        scope_preference="optimized",
    )


def run_postauth_service_and_share_followup(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    hosts: list[str] | None = None,
    prompt: bool = False,
    scope_preference: str = "optimized",
) -> None:
    """Run the standard post-auth follow-up for one user.

    This is the shared "minimal valuable" post-auth workflow reused by attack-step
    follow-ups and post-pivot follow-ups:

    1. Probe service access across SMB/WinRM/RDP/MSSQL.
    2. Enumerate authenticated SMB shares reachable by that user.
    """
    from adscan_internal.cli.smb import run_auth_shares

    run_service_access_sweep(
        shell,
        domain=domain,
        username=username,
        password=password,
        services=["smb", "winrm", "rdp", "mssql"],
        hosts=hosts,
        prompt=prompt,
        scope_preference=scope_preference,
    )
    run_auth_shares(
        shell,
        domain=domain,
        username=username,
        password=password,
    )


def run_netexec_user_privs(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    hosts: list[str] | None = None,
) -> None:
    """Backward-compatible alias for post-auth user access enumeration."""
    run_netexec_user_postauth_access(
        shell,
        domain=domain,
        username=username,
        password=password,
        hosts=hosts,
    )


def run_service_access_sweep(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    services: list[str],
    hosts: list[str] | None = None,
    prompt: bool = False,
    scope_preference: str = "optimized",
    include_previously_tested: bool = False,
) -> None:
    """Enumerate access across a set of services for one user."""
    if domain not in shell.domains_data:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"Domain {marked_domain} not found.")
        return

    for service in services:
        try:
            workspace_cwd = (
                shell._get_workspace_cwd()  # type: ignore[attr-defined]
                if hasattr(shell, "_get_workspace_cwd")
                else getattr(shell, "current_workspace_dir", os.getcwd())
            )
            domains_dir = getattr(shell, "domains_dir", "domains")

            cleaned_hosts = [
                h.strip() for h in (hosts or []) if isinstance(h, str) and h.strip()
            ]
            current_scope_preference = scope_preference
            if not cleaned_hosts and current_scope_preference == "optimized":
                current_scope_preference = resolve_domain_service_scope_preference(
                    shell,
                    workspace_dir=workspace_cwd,
                    domains_dir=domains_dir,
                    domain=domain,
                    service=service,
                    domain_data=shell.domains_data.get(domain, {}),
                    prompt_title=(
                        f"Choose the target scope for {service.upper()} post-auth service sweeps:"
                    ),
                )
            while True:
                targets: str | None = None
                original_targets_arg: str | None = None
                current_target_entries: set[str] = set()
                source = "explicit_hosts"
                if cleaned_hosts:
                    current_target_list = list(dict.fromkeys(cleaned_hosts))
                    current_target_entries = {
                        entry.lower() for entry in current_target_list
                    }
                    original_targets_arg = _build_service_sweep_target_argument(
                        workspace_dir=workspace_cwd,
                        domains_dir=domains_dir,
                        domain=domain,
                        service=service,
                        username=username,
                        targets=current_target_list,
                    )
                    targets = original_targets_arg
                else:
                    default_hosts_file, source = resolve_domain_service_target_file(
                        workspace_cwd,
                        domains_dir,
                        domain,
                        service=service,
                        domain_data=shell.domains_data.get(domain, {}),
                        scope_preference=current_scope_preference,
                    )
                    if not default_hosts_file:
                        break
                    targets = default_hosts_file
                    target_count = count_target_file_entries(default_hosts_file)
                    print_info_debug(
                        f"[privileges] using domain target file source={source} "
                        f"for {mark_sensitive(domain, 'domain')}: "
                        f"{mark_sensitive(str(targets), 'path')}"
                    )
                    print_info(
                        f"{service.upper()} sweep scope: "
                        f"{mark_sensitive(source, 'detail')} "
                        f"({target_count} target(s))"
                    )
                    targeting_notice = consume_service_targeting_fallback_notice(
                        shell,
                        workspace_dir=workspace_cwd,
                        domains_dir=domains_dir,
                        domain=domain,
                        service=service,
                        source=source,
                    )
                    if targeting_notice:
                        print_info(targeting_notice)
                    current_target_entries = load_target_entries(default_hosts_file)
                    current_target_list = sorted(current_target_entries)
                    original_targets_arg = default_hosts_file

                effective_target_list = _select_effective_service_targets(
                    shell,
                    workspace_dir=workspace_cwd,
                    domains_dir=domains_dir,
                    domain=domain,
                    username=username,
                    service=service,
                    current_targets=current_target_list,
                    include_previously_tested=include_previously_tested,
                )
                effective_target_entries = {
                    entry.lower() for entry in effective_target_list
                }
                if effective_target_list == current_target_list and original_targets_arg:
                    targets = original_targets_arg
                else:
                    targets = _build_service_sweep_target_argument(
                        workspace_dir=workspace_cwd,
                        domains_dir=domains_dir,
                        domain=domain,
                        service=service,
                        username=username,
                        targets=effective_target_list,
                    )
                if not targets:
                    found_hosts = False
                    if cleaned_hosts:
                        break
                    next_scope_preference = _resolve_next_broader_scope(
                        service=service,
                        source=source,
                        current_scope_preference=current_scope_preference,
                    )
                    if not next_scope_preference:
                        break
                    next_targets_file, _next_source = resolve_domain_service_target_file(
                        workspace_cwd,
                        domains_dir,
                        domain,
                        service=service,
                        domain_data=shell.domains_data.get(domain, {}),
                        scope_preference=next_scope_preference,
                    )
                    next_target_count = count_target_file_entries(next_targets_file)
                    if not next_targets_file or next_target_count <= 0:
                        break
                    next_target_entries = load_target_entries(next_targets_file)
                    if next_target_entries and next_target_entries.issubset(current_target_entries):
                        print_info_debug(
                            "[privileges] skipping broader sweep prompt because "
                            f"{mark_sensitive(next_scope_preference, 'detail')} does not add "
                            f"new {service.upper()} targets beyond "
                            f"{mark_sensitive(source, 'detail')}"
                        )
                        break
                    if not _prompt_broader_postauth_scope_retry(
                        shell,
                        service=service,
                        domain=domain,
                        current_source=source,
                        next_scope_preference=next_scope_preference,
                        next_target_count=next_target_count,
                    ):
                        break
                    current_scope_preference = next_scope_preference
                    continue

                marked_domain = mark_sensitive(domain, "domain")
                marked_username = mark_sensitive(username, "user")
                print_info(
                    f"Starting {service} privilege enumeration for user {marked_username}"
                )
                if service == "rdp":
                    print_info_debug(
                        "[privileges] service access sweep dispatch: "
                        f"domain={marked_domain} user={marked_username} service={service} "
                        f"backend=medusa prompt_on_success={prompt!r} "
                        f"targets={mark_sensitive(str(targets), 'path')}"
                    )
                    found_hosts = bool(
                        run_rdp_service_access_sweep_with_medusa(
                            shell,
                            domain=domain,
                            username=username,
                            password=password,
                            targets=str(targets),
                            prompt=prompt,
                            target_count=(
                                len(cleaned_hosts)
                                if cleaned_hosts
                                else len(effective_target_list)
                            ),
                        )
                    )
                else:
                    auth_str = shell.build_auth_nxc(
                        username,
                        password,
                        domain,
                        kerberos=False,
                    )
                    netexec_timeout_seconds = get_recommended_internal_timeout(service)
                    command = (
                        f"{shlex.quote(shell.netexec_path)} {service} {shlex.quote(targets)} {auth_str} "
                        f"-t 20 --timeout {netexec_timeout_seconds} "
                        f"--log domains/{marked_domain}/{service}/{marked_username}_privs.log"
                    )
                    print_info_debug(
                        "[privileges] service access sweep dispatch: "
                        f"domain={marked_domain} user={marked_username} service={service} "
                        f"backend=netexec prompt_on_success={prompt!r} "
                        f"targets={mark_sensitive(str(targets), 'path')}"
                    )
                    print_info_verbose(f"Command: {command}")
                    found_hosts = bool(
                        shell.run_service_command(
                            command,
                            domain,
                            service,
                            username,
                            password,
                            prompt=prompt,
                        )
                    )
                if found_hosts or cleaned_hosts:
                    break

                next_scope_preference = _resolve_next_broader_scope(
                    service=service,
                    source=source,
                    current_scope_preference=current_scope_preference,
                )
                if not next_scope_preference:
                    break
                next_targets_file, _next_source = resolve_domain_service_target_file(
                    workspace_cwd,
                    domains_dir,
                    domain,
                    service=service,
                    domain_data=shell.domains_data.get(domain, {}),
                    scope_preference=next_scope_preference,
                )
                next_target_count = count_target_file_entries(next_targets_file)
                if not next_targets_file or next_target_count <= 0:
                    break
                next_target_entries = load_target_entries(next_targets_file)
                if next_target_entries and next_target_entries.issubset(
                    effective_target_entries or current_target_entries
                ):
                    print_info_debug(
                        "[privileges] skipping broader sweep prompt because "
                        f"{mark_sensitive(next_scope_preference, 'detail')} does not add "
                        f"new {service.upper()} targets beyond "
                        f"{mark_sensitive(source, 'detail')}"
                    )
                    break
                if not _prompt_broader_postauth_scope_retry(
                    shell,
                    service=service,
                    domain=domain,
                    current_source=source,
                    next_scope_preference=next_scope_preference,
                    next_target_count=next_target_count,
                ):
                    break
                current_scope_preference = next_scope_preference
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error(f"Error processing service {service}.")
            print_exception(show_locals=False, exception=exc)


def run_user_postauth_access_with_orchestration(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    hosts: list[str] | None = None,
    include_acl_enumeration: bool = True,
) -> None:
    """Enumerate post-auth user opportunities after attack-path review.

    This flow focuses on service access, delegations, ADCS, shares, and
    spraying. Low-priv ACL review is intentionally optional and can be skipped
    by callers such as ``ask_for_user_privs`` because attack paths already
    surface those routes earlier in the UX.
    """
    from rich.prompt import Confirm

    # First, run the basic privilege enumeration
    run_netexec_user_postauth_access(
        shell, domain=domain, username=username, password=password, hosts=hosts
    )

    # Additional orchestration after privilege enumeration
    if include_acl_enumeration:
        shell.ask_for_enumerate_user_aces(domain, username, password)

    # Check if the user has Kerberos delegations
    if (
        "delegations" in shell.domains_data[domain]
        and username in shell.domains_data[domain]["delegations"]
    ):
        marked_username = mark_sensitive(username, "user")
        print_warning(f"User {marked_username} has Kerberos delegations configured")
        shell.enum_delegations_user(domain, username, password)

    # Check if there is ADCS in the domain
    if shell.domains_data[domain].get("adcs"):
        marked_username = mark_sensitive(username, "user")
        respuesta_adcs = Confirm.ask(
            f"Do you want to enumerate ADCS privileges for user {marked_username}?"
        )
        if respuesta_adcs:
            run_enum_adcs_privs(
                shell, domain=domain, username=username, password=password
            )

    if not (shell.type == "ctf" and shell.domains_data[domain]["auth"] == "pwned"):
        shell.ask_for_enum_shares(domain, username, password)
    if not (shell.type == "ctf" and shell.domains_data[domain]["auth"] == "pwned"):
        if shell.is_hash(password):
            marked_username = mark_sensitive(username, "user")
            marked_domain = mark_sensitive(domain, "domain")
            print_info_verbose(
                "Skipping password spraying prompt for user "
                f"{marked_username} in domain {marked_domain} because the "
                "credential is a hash."
            )
        else:
            marked_password = mark_sensitive(password, "password")
            marked_username = mark_sensitive(username, "user")
            marked_domain = mark_sensitive(domain, "domain")
            respuesta = Confirm.ask(
                "Do you want to perform a password spraying with the "
                f"{marked_password} password of the user {marked_username} "
                f"in the {marked_domain} domain?"
            )
            if respuesta:
                shell.spraying_with_password(domain, password)
    marked_username = mark_sensitive(username, "user")
    print_success(f"Complete enumeration for user {marked_username}")


def run_netexec_user_privs_with_orchestration(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    hosts: list[str] | None = None,
    include_acl_enumeration: bool = True,
) -> None:
    """Backward-compatible alias for post-auth user access orchestration."""
    run_user_postauth_access_with_orchestration(
        shell,
        domain=domain,
        username=username,
        password=password,
        hosts=hosts,
        include_acl_enumeration=include_acl_enumeration,
    )


def run_enum_adcs_privs(
    shell: Any, *, domain: str, username: str, password: str
) -> None:
    """Enumerate ADCS privileges for a user and prompt for exploitation."""
    from adscan_internal.cli.adcs import ask_for_adcs_esc
    from adscan_internal.services.exploitation import ExploitationService

    try:
        auth = shell.build_auth_certipy(domain, username, password)
        pdc_ip = shell.domains_data[domain].get("pdc")
        if not pdc_ip:
            marked_domain = mark_sensitive(domain, "domain")
            print_error(
                f"Missing PDC IP for domain {marked_domain}. "
                "Re-run domain initialization or update domain data."
            )
            return

        marked_username = mark_sensitive(username, "user")
        marked_domain = mark_sensitive(domain, "domain")
        print_info(
            f"Enumerating ADCS privileges for user {marked_username} in domain {marked_domain}"
        )

        service = ExploitationService()
        pdc_hostname = shell.domains_data[domain].get("pdc_hostname")
        target_host = None
        if isinstance(pdc_hostname, str) and pdc_hostname.strip():
            target_host = (
                pdc_hostname if "." in pdc_hostname else f"{pdc_hostname}.{domain}"
            )
        output_prefix = None
        domain_dir = shell.domains_data[domain].get("dir")
        if isinstance(domain_dir, str) and domain_dir:
            adcs_dir = os.path.join(domain_dir, "adcs")
            os.makedirs(adcs_dir, exist_ok=True)
            output_prefix = os.path.join(adcs_dir, "certipy_find")
        result = service.adcs.enum_privileges(
            certipy_path=shell.certipy_path,
            pdc_ip=pdc_ip,
            target_host=target_host,
            auth_string=auth,
            output_prefix=output_prefix,
            timeout=300,
            run_command=getattr(shell, "run_command", None),
        )

        if not result.success:
            print_error("Error enumerating ADCS privileges.")
            if result.raw_output:
                print_error(result.raw_output)
            return

        # Process vulnerabilities
        ca_vulns = [v for v in result.vulnerabilities if v.source == "ca"]
        template_vulns = [v for v in result.vulnerabilities if v.source == "template"]

        if ca_vulns:
            marked_username = mark_sensitive(username, "user")
            print_warning(
                f"Vulnerabilities in Certificate Authorities for user {marked_username}:"
            )
            for vuln in sorted(ca_vulns, key=lambda v: int(v.esc_number)):
                shell.console.print(f"   - ESC{vuln.esc_number}")
                ask_for_adcs_esc(
                    shell,
                    domain=domain,
                    esc=vuln.esc_number,
                    username=username,
                    password=password,
                    template=None,
                )
        else:
            marked_username = mark_sensitive(username, "user")
            print_error(
                f"No vulnerabilities found in Certificate Authorities for user {marked_username}"
            )

        if template_vulns:
            for vuln in template_vulns:
                print_warning(
                    f"Vulnerability in template '{vuln.template}': ESC{vuln.esc_number}"
                )
                ask_for_adcs_esc(
                    shell,
                    domain=domain,
                    esc=vuln.esc_number,
                    username=username,
                    password=password,
                    template=vuln.template,
                )
        elif not ca_vulns:
            print_error("No vulnerabilities found in Certificate Templates.")

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error enumerating ADCS.")
        print_exception(show_locals=False, exception=e)


def run_raise_child(shell: Any, *, domain: str, username: str, password: str) -> None:
    """Escalate from child domain to parent domain using raiseChild.py."""
    from adscan_internal.services.exploitation import ExploitationService

    try:
        auth = shell.build_auth_impacket_no_host(username, password, domain)
        if not shell.impacket_scripts_dir:
            print_error(
                "Impacket scripts directory not configured. Please ensure Impacket is installed via 'adscan install'."
            )
            return

        print_info_verbose("Trying to escalate from child domain to parent domain")

        service = ExploitationService()
        result = service.persistence.raise_child(
            impacket_scripts_dir=shell.impacket_scripts_dir,
            auth_string=auth,
            timeout=300,
        )

        if not result.success:
            error_detail = (
                result.raw_output.strip() if result.raw_output else "Unknown error"
            )
            print_error("Error executing raiseChild.py.")
            if error_detail:
                print_error(f"Details: {error_detail}")
            return

        # Process extracted credentials
        for cred in result.credentials:
            marked_username = mark_sensitive(cred["username"], "user")
            marked_nt_hash = mark_sensitive(cred["nt_hash"], "password")
            print_warning(
                f"Credential found - Domain: {cred['domain']}, User: {marked_username}, NT Hash: {marked_nt_hash}"
            )
            shell.add_credential(cred["domain"], cred["username"], cred["nt_hash"])

        print_success("Escalation completed. The credentials have been saved.")

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error executing raiseChild.")
        print_exception(show_locals=False, exception=e)


def run_enum_cross_domain_acl(shell: Any, *, domain: str) -> None:
    """Enumerate cross-domain ACLs and show options to exploit them."""
    shell.enumerate_user_aces(domain, "", "", cross_domain=True)


def ask_for_enum_cross_domain_acl(shell: Any, *, domain: str) -> None:
    """Ask if you want to attempt to enumerate ACLs from this domain to other domains."""
    # Only prompt if there is at least one other domain configured
    if not any(d != domain for d in shell.domains):
        return

    marked_domain = mark_sensitive(domain, "domain")
    respuesta = Confirm.ask(
        f"Do you want to attempt to enumerate the ACLs from domain {marked_domain} to other domains?"
    )
    if respuesta:
        run_enum_cross_domain_acl(shell, domain=domain)


def ask_for_raise_child(
    shell: Any, *, domain: str, username: str, password: str
) -> None:
    """Ask if you want to attempt to escalate from the child domain to the parent domain."""
    # Only prompt if domain is a subdomain of a configured parent domain
    parts = domain.split(".", 1)
    if len(parts) < 2 or parts[1] not in shell.domains:
        return

    marked_domain = mark_sensitive(domain, "domain")
    respuesta = Confirm.ask(
        f"Do you want to attempt to escalate from the child domain {marked_domain} to the parent domain?"
    )
    if respuesta:
        run_raise_child(shell, domain=domain, username=username, password=password)
    else:
        ask_for_enum_cross_domain_acl(shell, domain=domain)


def run_raise_child_command(shell: Any, args: str) -> None:
    """
    Process the command to raise the child domain to the parent domain level.

    Args:
        shell: The shell instance
        args: A string containing the domain, user, and password separated by spaces.

    Usage:
        raise_child <domain> <user> <password>

    The function splits the input string into components, validates the correct number of arguments,
    and then calls the `run_raise_child` function with the provided domain, user, and password.
    """
    args_list = args.split()
    if len(args_list) != 3:
        print_error("Usage: raise_child <domain> <user> <password>")
        return
    domain, username, password = args_list
    run_raise_child(shell, domain=domain, username=username, password=password)
