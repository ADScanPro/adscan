"""CLI orchestration for Kerberos operations.

This module keeps interactive CLI concerns (printing, reporting, file persistence)
separate from the Kerberos service layer. It handles:
- Kerberos enumeration and user enumeration
- Kerberos ticket generation and management
- Kerberoast and ASREPRoast attacks
- Kerberos environment setup and validation
- LDAP-related Kerberos operations

It uses:
- adscan_internal.services.enumeration.kerberos for enumeration logic
- adscan_internal.services.kerberos_ticket_service for ticket operations
- adscan_internal.cli.ldap for LDAP-related Kerberos operations
"""

from __future__ import annotations

from collections.abc import Callable
import os
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from adscan_internal.services.kerberos_ticket_service import KerberosTGTResult

import rich.box
from rich.console import Group
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from adscan_core.theme import (
    COLOR_AMBER,
    COLOR_CRIMSON,
    COLOR_MUTED,
    COLOR_SAGE,
    COLOR_STEEL,
)

from adscan_internal import (
    print_error,
    print_info,
    print_warning,
    telemetry,
)
from adscan_internal.rich_output import (
    mark_sensitive,
    print_panel,
    print_info_debug,
    print_info_verbose,
    print_success_verbose,
    print_warning_debug,
    print_warning_verbose,
)
from adscan_internal.cli.common import build_lab_event_fields
from adscan_internal.services import EnumerationService
from adscan_internal.integrations.impacket import (
    extract_kerberoast_candidate_users,
    parse_asreproast_output,
    parse_kerberoast_output,
)
from adscan_internal.workspaces import (
    DEFAULT_DOMAIN_LAYOUT,
    domain_relpath,
    domain_subpath,
)


def _resolve_dcsync_target_user(
    shell: Any, *, domain: str, username: str | None = None
) -> str | None:
    """Resolve the target user for interactive DCSync execution.

    Keeps ``All`` as a first-class option while still guiding the operator with
    known privileged accounts when available.

    Default-to-"All" policy (the priority is: get a DA credential first, THEN
    replicate everything — a full "All" can be slow/fragile at 10k-user scale):
    default to "All" when we ALREADY hold a Domain Admin credential — either the
    domain is already pwned, OR ``username`` (the principal running THIS DCSync)
    is itself a DA (e.g. ESC1 just minted administrator). When the executor is
    NOT a DA (e.g. an ESC8 DC machine account replicating to EXTRACT a DA),
    default to the single DA member so we get the DA first; the post-compromise
    pipeline then runs the full "All" once that DA credential is in hand.
    """
    admins = shell.get_domain_admins(domain)
    da_set = {str(a or "").strip().casefold() for a in admins if str(a or "").strip()}
    executor_is_da = bool(username) and str(username).strip().casefold() in da_set
    already_pwned = (shell.domains_data.get(domain, {}) or {}).get("auth") in ["pwned"]
    default_user = (
        "All"
        if (already_pwned or executor_is_da)
        else (admins[0] if admins else "Administrator")
    )
    selector = getattr(shell, "_questionary_select", None)
    if callable(selector):
        options = ["All"]
        for admin in admins:
            candidate = str(admin or "").strip()
            if not candidate or candidate in options:
                continue
            options.append(candidate)
        options.extend(["Enter manually", "Cancel"])
        try:
            selected_idx = selector(
                f"Select the user to extract NTLM hashes from in {mark_sensitive(domain, 'domain')}:",
                options,
                default_idx=0
                if default_user == "All"
                else max(options.index(default_user), 0)
                if default_user in options
                else 0,
            )
        except TypeError:
            selected_idx = selector(
                f"Select the user to extract NTLM hashes from in {mark_sensitive(domain, 'domain')}:",
                options,
            )
        if selected_idx is None:
            return None
        choice = options[selected_idx]
        if choice == "Cancel":
            return None
        if choice == "Enter manually":
            target_user_raw = Prompt.ask(
                "Specify the user to extract NTLM hashes from (type 'All' for all users)",
                default=default_user,
            )
            return target_user_raw
        return choice

    return Prompt.ask(
        "Specify the user to extract NTLM hashes from (type 'All' for all users)",
        default=default_user,
    )


class KerberosShell(Protocol):
    """Minimal shell surface used by the Kerberos CLI controller.

    This protocol unifies the requirements for both general Kerberos operations
    and roasting attacks (Kerberoast/ASREPRoast).
    """

    console: object
    domains: list[str]
    domains_dir: str
    kerberos_dir: str
    cracking_dir: str
    domain: str | None
    type: str | None
    auto: bool
    scan_mode: str | None
    current_workspace_dir: str | None
    domains_data: dict
    netexec_path: str | None
    impacket_scripts_dir: str | None
    command_runner: object
    license_mode: object

    def _questionary_select(
        self, title: str, options: list[str], default_idx: int = 0
    ) -> int | None: ...

    def _get_workspace_cwd(self) -> str: ...

    def _get_service_executor(
        self,
    ) -> Callable[[str, int], subprocess.CompletedProcess[str]]: ...

    def _get_lab_slug(self) -> str | None: ...

    def _get_license_mode_enum(self) -> object: ...

    def run_command(
        self, command: str, timeout: int | None = None, cwd: str | None = None
    ) -> subprocess.CompletedProcess[str] | None: ...

    def do_sync_clock_with_pdc(self, domain: str, verbose: bool = False) -> bool: ...

    def _display_items(self, items: list[str], label: str) -> None: ...

    def get_domain_admins(self, domain: str) -> list[str]: ...

    def build_auth_impacket(
        self, username: str, password: str, domain: str, kerberos: bool = False
    ) -> str: ...

    dcsync_dir: str

    def ask_for_kerberos_user_enum(
        self, domain: str, relaunch: bool = False
    ) -> None: ...

    def do_enum_with_users(self, domain: str) -> None: ...

    def build_auth_nxc(
        self, username: str, password: str, domain: str, kerberos: bool = True
    ) -> str: ...

    def build_auth_impacket_no_host(
        self, username: str, password: str, domain: str, kerberos: bool = True
    ) -> str: ...

    def check_high_value(
        self, domain: str, username: str, *, logging: bool = True
    ) -> bool: ...

    def update_report_field(self, domain: str, field: str, value: object) -> None: ...

    def ask_for_cracking(
        self,
        roast_type: str,
        domain: str,
        hashes_file: str,
        *,
        confirm: bool = True,
    ) -> None: ...


def detect_kerberos_time_error(stdout: str | None, stderr: str | None) -> bool:
    """Return True if output indicates a Kerberos time synchronization error.

    Args:
        stdout: Process stdout.
        stderr: Process stderr.

    Returns:
        True if a Kerberos clock-skew / ticket-not-yet-valid error is detected.
    """
    combined = f"{stdout or ''}\n{stderr or ''}".lower()
    patterns = (
        "clock skew too great",
        "ticket not yet valid",
        "krb_ap_err_skew",  # KRB_AP_ERR_SKEW
        "krb_ap_err_tkt_nyv",  # ticket not yet valid
    )
    return any(pattern in combined for pattern in patterns)


def ensure_kerberos_output_dir(shell: KerberosShell, domain: str) -> str:
    """Ensure the kerberos output directory exists for a given domain.

    Args:
        shell: Shell instance with workspace and domain configuration.
        domain: Domain name.

    Returns:
        Relative path 'domains/<domain>/kerberos' (from workspace root).
    """
    output_dir = domain_relpath(
        shell.domains_dir, domain, DEFAULT_DOMAIN_LAYOUT.kerberos
    )
    workspace_cwd = shell.current_workspace_dir or shell._get_workspace_cwd()
    output_dir_abs = domain_subpath(
        workspace_cwd, shell.domains_dir, domain, DEFAULT_DOMAIN_LAYOUT.kerberos
    )
    try:
        os.makedirs(output_dir_abs, exist_ok=True)
    except OSError as exc:
        telemetry.capture_exception(exc)
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"Unable to prepare kerberos output directory for {marked_domain}: {exc}"
        )
    return output_dir


# Note: execute_kerberos_enum_users is a legacy function that appears to be unused.
# The modern approach uses run_kerberos_enum_users from adscan_internal.cli.ldap
# which delegates to the EnumerationService.kerberos.enumerate_users_kerberos service.
# If this function is still needed, it should be refactored to use the service layer.


def ask_for_kerberos_user_enum(
    shell: KerberosShell, domain: str, relaunch: bool = False
) -> None:
    """Prompt user to enumerate domain users via Kerberos.

    This function delegates to run_kerberos_enum_users in adscan_internal.cli.ldap,
    which uses the EnumerationService.kerberos service for the actual enumeration.

    Args:
        shell: Shell instance with domain data and workspace configuration.
        domain: Target domain name.
        relaunch: Whether this is a retry/relaunch of enumeration.
    """
    if shell.domains_data[domain]["auth"] in ["auth", "pwned", "with_users"]:
        return

    from adscan_internal.rich_output import confirm_operation
    from adscan_internal.workspaces import domain_subpath

    pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")

    if confirm_operation(
        operation_name=f"Kerberos User Enumeration {'(Retry)' if relaunch else ''}",
        description="Enumerates valid domain users by testing Kerberos pre-authentication",
        context={
            "Domain": domain,
            "PDC": pdc,
            "Protocol": "Kerberos/88",
            "Method": "AS-REQ pre-auth testing",
            "Mode": "Additional users" if relaunch else "Initial enumeration",
        },
        default=not relaunch,
        icon="👤",
    ):
        workspace_cwd = shell.current_workspace_dir or shell._get_workspace_cwd()
        kerberos_path = domain_subpath(
            workspace_cwd, shell.domains_dir, domain, shell.kerberos_dir
        )

        if not os.path.exists(kerberos_path):
            os.makedirs(kerberos_path)

        # Delegate to the LDAP CLI module which uses the EnumerationService
        from adscan_internal.cli.ldap import run_kerberos_enum_users

        run_kerberos_enum_users(shell, domain)


def auto_generate_kerberos_ticket(
    shell: KerberosShell,
    username: str,
    credential: str,
    domain: str,
    dc_ip: str | None = None,
) -> str | None:
    """Automatically generate Kerberos ticket based on credential type.

    This function wraps KerberosTicketService.auto_generate_tgt to provide
    a CLI-friendly interface with proper error handling and user feedback.

    Args:
        shell: Shell instance with workspace configuration.
        username: Username for authentication.
        credential: Password or NTLM hash.
        domain: Domain name.
        dc_ip: Optional Domain Controller IP address.

    Returns:
        Path to the created ccache file, or None if failed.
    """
    from adscan_internal.services.kerberos_ticket_service import (
        KerberosTicketService,
    )
    from adscan_internal.rich_output import mark_sensitive, print_warning

    try:
        service = KerberosTicketService()
        result = service.auto_generate_tgt(
            username=username,
            credential=credential,
            domain=domain,
            workspace_dir=shell.current_workspace_dir or shell._get_workspace_cwd(),
            dc_ip=dc_ip,
        )
        if result.success:
            return result.ticket_path
        if result.error_message:
            marked_username = mark_sensitive(username, "user")
            marked_domain = mark_sensitive(domain, "domain")
            print_warning(
                "Failed to auto-generate Kerberos ticket for "
                f"{marked_username}@{marked_domain}: {result.error_message}"
            )
            return None

    except Exception as e:
        telemetry.capture_exception(e)
        marked_username = mark_sensitive(username, "user")
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            f"Failed to auto-generate Kerberos ticket for {marked_username}@{marked_domain}: {e}"
        )
        return None


def auto_generate_kerberos_ticket_result(
    shell: KerberosShell,
    username: str,
    credential: str,
    domain: str,
    dc_ip: str | None = None,
) -> "KerberosTGTResult | None":
    """Return the full KerberosTGTResult including error_kind for structured error handling.

    Args:
        shell: Shell instance with workspace configuration.
        username: Username for authentication.
        credential: Password or NTLM hash.
        domain: Domain name.
        dc_ip: Optional Domain Controller IP address.

    Returns:
        KerberosTGTResult with success status and error_kind, or None on unexpected error.
    """
    from adscan_internal.services.kerberos_ticket_service import KerberosTicketService

    try:
        service = KerberosTicketService()
        return service.auto_generate_tgt(
            username=username,
            credential=credential,
            domain=domain,
            workspace_dir=shell.current_workspace_dir or shell._get_workspace_cwd(),
            dc_ip=dc_ip,
        )
    except Exception as e:
        telemetry.capture_exception(e)
        return None


def ensure_kerberos_environment_for_command(
    shell: KerberosShell,
    domain: str,
    user_domain: str,
    username: str | None = None,
    command_name: str = "kerberos command",
) -> bool:
    """Ensure Kerberos environment is ready before executing Kerberos commands.

    This function wraps KerberosTicketService to set up and validate the
    Kerberos environment (KRB5_CONFIG and KRB5CCNAME) for command execution.

    Args:
        shell: Shell instance with workspace and domain configuration.
        domain: Target domain name.
        user_domain: Domain used to look up stored tickets.
        username: Optional username for Kerberos operations.
        command_name: Name of the command being executed (for logging).

    Returns:
        True if environment is ready, False otherwise.
    """
    from adscan_internal.services.kerberos_ticket_service import (
        KerberosEnvironmentStatus,
        KerberosTicketService,
    )
    from adscan_internal.rich_output import (
        mark_sensitive,
        print_info_verbose,
        print_warning,
    )

    try:
        service = KerberosTicketService()

        # Set up the environment (workspace krb5.conf + ticket if available)
        _krb5_config_set, _ticket_set, _conf_path, _ticket_path = (
            service.setup_environment_for_domain(
                workspace_dir=shell.current_workspace_dir or shell._get_workspace_cwd(),
                domain=domain,
                user_domain=user_domain,
                username=username,
                domains_data=shell.domains_data,
            )
        )

        # Validate the resulting environment
        status: KerberosEnvironmentStatus = service.validate_environment(
            username=username
        )

        if status.ready_for_kerberos_commands:
            return True

        print_warning(f"Kerberos environment not ready for {command_name}")
        for issue in status.issues:
            print_info_verbose(f"Issue: {issue}")

        # Provide a slightly more user-friendly hint if no ticket is ready
        if username and not status.kerberos_ticket_ready:
            marked_username = mark_sensitive(username, "user")
            marked_domain = mark_sensitive(domain, "domain")
            print_info_verbose(
                f"No Kerberos ticket available for {marked_username}@{marked_domain}. "
                "You may need to generate a TGT first."
            )
            return False

    except Exception as e:
        telemetry.capture_exception(e)
        print_warning(f"Error ensuring Kerberos environment for {command_name}: {e}")
    return False


def _print_roast_choice_help(
    default_choice: str,
    selection_options: list[str],
    *,
    priority_available: bool,
) -> None:
    """Render an enhanced helper panel for cracking scope choices.

    Each option is rendered with its estimated time-to-crack impact and a
    visual cue (bold for the recommended option, dim for the rest) so the
    operator can pick the right scope at a glance.

    Hierarchy is encoded by weight (bold vs dim) and a leading marker
    (``>`` for the active default, ``+`` for the recommended option, blank
    for the rest), not by color alone, so the panel stays legible under
    ``NO_COLOR`` and on monochrome terminals.
    """
    # (label, time_hint, use_case)
    _OPTION_META: dict[str, tuple[str, str, str]] = {
        "recommended": (
            "Recommended",
            "fastest impact",
            "High-value accounts plus users with attack paths only",
        ),
        "all": (
            "All users",
            "slowest",
            "Every roastable account in the domain",
        ),
        "specific": (
            "Specific",
            "your choice",
            "Comma-separated list of usernames",
        ),
        "none": (
            "Skip",
            "no cracking",
            "Save hashes for later, no cracking now",
        ),
    }

    lines: list[str] = [
        f"[bold {COLOR_SAGE}]Select cracking scope[/bold {COLOR_SAGE}]",
        "",
    ]
    for option in selection_options:
        label, time_hint, use_case = _OPTION_META.get(option, (option, "", ""))
        is_default = option == default_choice
        is_recommended = option == "recommended"

        if is_recommended and priority_available:
            marker = "+"
            line = (
                f"  [bold {COLOR_SAGE}]{marker} {label}[/bold {COLOR_SAGE}]"
                f"  [dim {COLOR_SAGE}]RECOMMENDED[/dim {COLOR_SAGE}]"
                f"  [dim]({time_hint})[/dim]"
                f"\n      [{COLOR_MUTED}]{use_case}[/{COLOR_MUTED}]"
            )
        elif is_default:
            marker = ">"
            line = (
                f"  [bold {COLOR_STEEL}]{marker} {label}[/bold {COLOR_STEEL}]"
                f"  [dim]({time_hint})[/dim]"
                f"\n      [{COLOR_MUTED}]{use_case}[/{COLOR_MUTED}]"
            )
        else:
            line = (
                f"    [dim]{label}[/dim]"
                f"  [dim]({time_hint})[/dim]"
                f"\n      [{COLOR_MUTED}]{use_case}[/{COLOR_MUTED}]"
            )
        lines.append(line)
        lines.append("")

    if not priority_available and "recommended" in selection_options:
        lines.append(
            f"[{COLOR_AMBER}]No priority users detected, defaulting to all accounts.[/{COLOR_AMBER}]"
        )
        lines.append("")

    lines.append(f"[dim]Default selection: [bold]{default_choice}[/bold][/dim]")
    print_panel("\n".join(lines), title="Cracking options", expand=False)


def _should_crack_single_roast_user(
    shell: KerberosShell,
    *,
    roast_type: str,
    username: str,
) -> bool:
    """Return whether to crack immediately when only one user was discovered."""
    if shell.auto:
        print_info_verbose(
            f"Auto-selected cracking option: crack single discovered {roast_type} user {username}"
        )
        return True

    if hasattr(shell, "_questionary_select"):
        options = [
            f"crack: Crack {username} now",
            "none: Skip cracking for now",
        ]
        selected_idx = shell._questionary_select(
            "Crack discovered user?",
            options,
            default_idx=0,
        )
        return selected_idx in (None, 0)

    print_panel(
        (
            "[bold]Single roastable user discovered[/bold]\n"
            f"[cyan]{username}[/cyan]\n"
            f"[dim]Attack type: {roast_type}[/dim]"
        ),
        title="Cracking Options",
        expand=False,
    )
    choice = Prompt.ask(
        "Crack discovered user?",
        choices=["crack", "none"],
        default="crack",
    )
    return choice == "crack"


# ============================================================================
# Roasting Attack Functions (Kerberoast and ASREPRoast)
# ============================================================================


def _load_valid_roast_hash_entries(
    *,
    roast_type: str,
    hashes_file_abs: str,
) -> list[tuple[str, str]]:
    """Return parsed ``(username, hash)`` pairs from one roast output file."""
    if not os.path.exists(hashes_file_abs):
        return []

    try:
        raw = Path(hashes_file_abs).read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        telemetry.capture_exception(exc)
        marked_path = mark_sensitive(hashes_file_abs, "path")
        print_info_debug(
            f"[kerberos] Could not read roast hashes file {marked_path}: "
            f"{type(exc).__name__}: {exc}"
        )
        return []

    if roast_type == "kerberoast":
        parsed = parse_kerberoast_output(raw)
        return [
            (item.username.strip(), item.hash_value.strip())
            for item in parsed
            if item.username.strip() and item.hash_value.strip()
        ]

    if roast_type == "asreproast":
        parsed = parse_asreproast_output(raw)
        return [
            (item.username.strip(), item.hash_value.strip())
            for item in parsed
            if item.username.strip() and item.hash_value.strip()
        ]

    return []


# Hashcat roast lines embed the Kerberos etype number:
#   Kerberoast (TGS-REP): $krb5tgs$<etype>$...   AS-REP Roast: $krb5asrep$<etype>$...
# RC4-HMAC = etype 23, AES128-CTS = 17, AES256-CTS = 18. The encryption type of
# every captured roastable hash is therefore derivable from the line prefix
# WITHOUT reading the ciphertext, username, SPN, or any secret material.
_ROAST_ETYPE_RE = re.compile(r"\$krb5(?:tgs|asrep)\$(\d+)\$")


def _summarize_roast_etypes(
    parsed_hash_entries: list[tuple[str, str]],
) -> dict[str, int]:
    """Return sanitized per-encryption-type counts for a set of roast hashes.

    Only the Kerberos etype number embedded in each hashcat line is inspected;
    no username, SPN, ciphertext, realm, or secret material is read or emitted.
    The result is pure integer counts, safe for telemetry.

    Args:
        parsed_hash_entries: ``(username, hash_line)`` pairs from one roast run.

    Returns:
        Dict of etype-family counts: ``rc4_count`` (etype 23), ``aes128_count``
        (17), ``aes256_count`` (18), ``aes_count`` (17+18), ``other_count``
        (any other/unparseable etype), and ``hash_total``.
    """
    rc4 = aes128 = aes256 = other = 0
    for _username, hash_line in parsed_hash_entries:
        match = _ROAST_ETYPE_RE.search(hash_line or "")
        etype = match.group(1) if match else None
        if etype == "23":
            rc4 += 1
        elif etype == "17":
            aes128 += 1
        elif etype == "18":
            aes256 += 1
        else:
            other += 1
    return {
        "rc4_count": rc4,
        "aes128_count": aes128,
        "aes256_count": aes256,
        "aes_count": aes128 + aes256,
        "other_count": other,
        "hash_total": rc4 + aes128 + aes256 + other,
    }


def _extract_roast_candidate_users_from_stdout(
    roast_type: str,
    output: str | None,
) -> list[str]:
    """Extract roastable usernames from raw tool stdout without shell pipelines."""
    if not output:
        return []

    if roast_type == "kerberoast":
        return extract_kerberoast_candidate_users(output)

    if roast_type == "asreproast":
        return [
            item.username for item in parse_asreproast_output(output) if item.username
        ]

    return [line.strip() for line in output.splitlines() if line.strip()]


def _classify_roast_account(username: str) -> str:
    """Return a privilege label string for a roastable account.

    Classification is purely name-heuristic. The caller is responsible for
    passing accounts that have already been confirmed as high-value via
    ``check_high_value`` into the ``admin_users`` bucket rather than here.
    """
    low = username.lower()
    if low == "krbtgt":
        return "krbtgt"
    if any(low.startswith(p) for p in ("svc_", "svc-", "_svc", "service")):
        return "service"
    if any(
        kw in low
        for kw in ("admin", "mgmt", "backup", "sql", "iis", "mssql", "web", "exchange", "exch")
    ):
        return "sensitive-svc"
    return "normal"


def _roast_console_no_color(shell: KerberosShell) -> bool:
    """Return True when the active console suppresses color (NO_COLOR / pipe / dumb terminal).

    The privilege column and hash-type badges must remain readable when color
    is unavailable, so the renderers prepend a glyph that carries the meaning
    even when every span collapses to plain text. We consult the shared
    Rich console rather than re-implementing the detection.
    """
    console = getattr(shell, "console", None)
    if console is None:
        return False
    if getattr(console, "no_color", False):
        return True
    if not getattr(console, "is_terminal", True):
        return True
    return False


def _roast_privilege_cell(username: str, is_admin: bool, *, no_color: bool = False) -> str:
    """Return a Rich markup string for the privilege column.

    The glyph prefix (``!!``, ``!``, ``*``, ``.``) encodes the same severity
    ranking as the color, so a color-blind operator, a monochrome terminal,
    or ``NO_COLOR=1`` still reads the hierarchy. Colors map to the project
    semantic tokens in ``adscan_core.theme`` instead of ad-hoc hex values,
    so light themes and user palette overrides apply cleanly.
    """
    if is_admin:
        if no_color:
            return "!! DA"
        return f"[bold {COLOR_CRIMSON}]!! DA[/bold {COLOR_CRIMSON}]"
    cls = _classify_roast_account(username)
    if cls == "krbtgt":
        if no_color:
            return "!! krbtgt"
        return f"[bold {COLOR_CRIMSON}]!! krbtgt[/bold {COLOR_CRIMSON}]"
    if cls == "sensitive-svc":
        if no_color:
            return "! Sensitive SVC"
        return f"[bold {COLOR_AMBER}]! Sensitive SVC[/bold {COLOR_AMBER}]"
    if cls == "service":
        if no_color:
            return "* Service"
        return f"[{COLOR_AMBER}]* Service[/{COLOR_AMBER}]"
    if no_color:
        return ". Normal"
    return f"[{COLOR_MUTED}]. Normal[/{COLOR_MUTED}]"


def _hash_type_badge(roast_type: str, *, no_color: bool = False) -> str:
    """Return the bracket badge for a roast hash type.

    The bracketed token itself (``[TGS]`` / ``[AS-REP]``) carries the meaning
    so color is purely an enhancement. Tokens map to semantic theme slots.
    """
    if roast_type == "kerberoast":
        if no_color:
            return "[TGS]"
        return f"[dim {COLOR_STEEL}][TGS][/dim {COLOR_STEEL}]"
    if roast_type == "asreproast":
        if no_color:
            return "[AS-REP]"
        return f"[dim {COLOR_AMBER}][AS-REP][/dim {COLOR_AMBER}]"
    return "[dim][HASH][/dim]"


def _print_roast_zero_results(
    shell: KerberosShell,
    *,
    roast_type: str,
    domain: str,
) -> None:
    """Render a muted informational panel when zero roastable accounts are found.

    A zero result is a positive security signal: all accounts require
    pre-authentication (for AS-REP roasting) or have no SPNs registered
    (for Kerberoasting). The panel explains this instead of alarming the
    operator with a red error, and ends with a state-specific footer
    telling them what to try next (skill: contextual intelligence).
    """
    attack_label = "Kerberoast" if roast_type == "kerberoast" else "AS-REP Roast"
    if roast_type == "kerberoast":
        detail = (
            "No Service Principal Names (SPNs) were found on user accounts. "
            "All accounts appear to be standard user objects without registered services, "
            "a good security posture indicator."
        )
        next_step = (
            "Try AS-REP Roasting next, or pivot to ACL enumeration "
            "to surface attack paths that do not depend on SPNs."
        )
    else:
        detail = (
            "All accounts require Kerberos pre-authentication. "
            "No AS-REP hashes can be obtained without valid credentials, "
            "a good security posture indicator."
        )
        next_step = (
            "If you already hold credentials, run Kerberoasting next. "
            "Otherwise pivot to unauthenticated SMB or LDAP enumeration."
        )
    body = (
        f"[{COLOR_MUTED}]0 {attack_label}able accounts[/{COLOR_MUTED}]\n\n"
        f"[dim]{detail}[/dim]\n\n"
        f"[dim]Next:[/dim] [dim]{next_step}[/dim]"
    )
    shell.console.print(
        Panel(
            body,
            title=f"[dim]{attack_label}: No targets found[/dim]",
            title_align="left",
            border_style="dim",
            box=rich.box.MINIMAL,
            expand=False,
            padding=(0, 1),
        )
    )


def _print_roast_results_table(
    shell: KerberosShell,
    *,
    roast_type: str,
    domain: str,
    admin_users: list[str],
    privileged_users: list[str],
    non_admin_users: list[str],
    has_attack_paths_fn: object,
    auth_mode: str,
) -> None:
    """Render the roastable-accounts results in a single panel.

    Round 2 collapses the previous two stacked panels (table + summary) into a
    single panel whose footer holds the summary line plus the context-aware
    next-action hint. This removes the nested-card anti-pattern and the
    double chrome that the tui-design skill flags under Anti-Pattern #10
    (over-decorated chrome) and impeccable flags as "nested cards are always
    wrong".

    Hierarchy is carried by typography + glyphs (bold for DA, ``!!`` prefix in
    the privilege column, section rule between groups) so the panel remains
    legible without color. Border color is a semantic accent only: it does
    not encode required information.
    """
    no_color = _roast_console_no_color(shell)
    badge = _hash_type_badge(roast_type, no_color=no_color)
    attack_label = "Kerberoast" if roast_type == "kerberoast" else "AS-REP Roast"
    hashcat_mode = "13100" if roast_type == "kerberoast" else "18200"

    total_admin = len(admin_users)
    total_normal = len(non_admin_users) + len(privileged_users)
    total_all = total_admin + total_normal

    if auth_mode == "auth":
        # Authenticated table: privilege columns + DA visual grouping.
        # Border accent escalates to crimson when a DA account is present.
        border_color = COLOR_CRIMSON if total_admin > 0 else COLOR_STEEL
        table = Table(
            show_header=True,
            header_style=f"bold {COLOR_STEEL}",
            box=rich.box.SIMPLE_HEAVY,
            border_style=border_color,
            expand=True,
            show_lines=False,
            pad_edge=False,
        )
        table.add_column("Account", style="cyan", no_wrap=True)
        table.add_column("Privilege", justify="left", no_wrap=True)
        table.add_column("Hash", justify="center", no_wrap=True)
        table.add_column("Path", justify="center", no_wrap=True)

        def _path_cell(has_path: bool, is_da: bool) -> str:
            if not has_path:
                return "[dim].[/dim]" if no_color else "[dim]none[/dim]"
            if no_color:
                return "+ yes"
            color = COLOR_CRIMSON if is_da else COLOR_AMBER
            return f"[bold {color}]+ yes[/bold {color}]"

        # DA accounts first: these are the jackpot.
        for user in admin_users:
            has_path = bool(
                callable(has_attack_paths_fn) and has_attack_paths_fn(shell, domain, user)
            )
            table.add_row(
                f"[bold]{user}[/bold]",
                _roast_privilege_cell(user, is_admin=True, no_color=no_color),
                badge,
                _path_cell(has_path, is_da=True),
            )

        # Visual rule between DA and standard accounts when both groups exist.
        if admin_users and (privileged_users or non_admin_users):
            table.add_section()

        for user in privileged_users:
            has_path = bool(
                callable(has_attack_paths_fn) and has_attack_paths_fn(shell, domain, user)
            )
            table.add_row(
                user,
                _roast_privilege_cell(user, is_admin=False, no_color=no_color),
                badge,
                _path_cell(has_path, is_da=False),
            )

        for user in non_admin_users:
            has_path = bool(
                callable(has_attack_paths_fn) and has_attack_paths_fn(shell, domain, user)
            )
            table.add_row(
                user,
                _roast_privilege_cell(user, is_admin=False, no_color=no_color),
                badge,
                _path_cell(has_path, is_da=False),
            )

        # Summary debrief line (color is an enhancement; the counts carry meaning).
        parts: list[str] = [f"[bold {COLOR_SAGE}]{total_all} {attack_label}able[/bold {COLOR_SAGE}]"]
        if total_admin > 0:
            parts.append(
                f"[bold {COLOR_CRIMSON}]{total_admin} DA account"
                f"{'s' if total_admin != 1 else ''}[/bold {COLOR_CRIMSON}]"
            )
        if total_normal > 0:
            parts.append(f"[{COLOR_MUTED}]{total_normal} standard[/{COLOR_MUTED}]")
        summary_line = "  ·  ".join(parts)

        # Context-aware footer: the most actionable command depends on whether
        # any DA account is present. When it is, the operator's first move is
        # almost always to crack DA accounts first, so we surface that explicitly.
        if total_admin > 0:
            next_action = (
                f"[dim]Next:[/dim]  "
                f"[bold {COLOR_STEEL}]hashcat -m {hashcat_mode} "
                f"hashes.{roast_type}.recommended wordlist.txt[/bold {COLOR_STEEL}]"
                f"   [dim](DA-first subset)[/dim]"
            )
        else:
            next_action = (
                f"[dim]Next:[/dim]  "
                f"[bold {COLOR_STEEL}]hashcat -m {hashcat_mode} "
                f"hashes.{roast_type} wordlist.txt[/bold {COLOR_STEEL}]"
            )

        # Render table + footer inside a single panel (no nested cards).
        body = Group(
            table,
            Text(""),  # one-line spacer
            Text.from_markup(f"{summary_line}\n{next_action}", justify="left"),
        )
        shell.console.print(
            Panel(
                body,
                title=f"[bold]{attack_label}able accounts: {domain}[/bold]",
                title_align="left",
                border_style=border_color,
                box=rich.box.ROUNDED,
                expand=True,
                padding=(0, 1),
            )
        )
    else:
        # Guest / unauthenticated table: simplified, no privilege data.
        table = Table(
            show_header=True,
            header_style=f"bold {COLOR_STEEL}",
            box=rich.box.SIMPLE_HEAVY,
            border_style=COLOR_STEEL,
            expand=True,
            pad_edge=False,
        )
        table.add_column("Account", style="cyan")
        table.add_column("Hash", justify="center", no_wrap=True)
        for user in non_admin_users:
            table.add_row(user, badge)

        next_action = (
            f"[dim]Next:[/dim]  "
            f"[bold {COLOR_STEEL}]hashcat -m {hashcat_mode} "
            f"hashes.{roast_type} wordlist.txt[/bold {COLOR_STEEL}]"
        )
        summary_line = (
            f"[bold {COLOR_SAGE}]{total_all} {attack_label}able "
            f"account{'s' if total_all != 1 else ''}[/bold {COLOR_SAGE}]"
            f"  [dim](unauthenticated scan)[/dim]"
        )

        body = Group(
            table,
            Text(""),
            Text.from_markup(f"{summary_line}\n{next_action}", justify="left"),
        )
        shell.console.print(
            Panel(
                body,
                title=f"[bold]{attack_label}able accounts: {domain}[/bold]",
                title_align="left",
                border_style=COLOR_STEEL,
                box=rich.box.ROUNDED,
                expand=True,
                padding=(0, 1),
            )
        )


def finalize_roast_results(
    shell: KerberosShell,
    *,
    domain: str,
    roast_type: str,
    users: list[str],
    auto_crack: bool,
) -> str | None:
    """Finalize roast results: show UI, update report/telemetry, and prepare hashes file.

    Args:
        shell: Shell instance with workspace and domain configuration.
        domain: Target domain name.
        roast_type: Type of roast attack ('kerberoast' or 'asreproast').
        users: List of users found to be roastable.
        auto_crack: Whether to automatically prompt for cracking.

    Returns:
        Relative path to hashes file if successful, None otherwise.
    """
    workspace_cwd = shell._get_workspace_cwd()
    hashes_file_abs = domain_subpath(
        workspace_cwd,
        shell.domains_dir,
        domain,
        shell.cracking_dir,
        f"hashes.{roast_type}",
    )
    hashes_file_rel = domain_relpath(
        shell.domains_dir, domain, shell.cracking_dir, f"hashes.{roast_type}"
    )
    cracking_hashes_file_abs = hashes_file_abs
    cracking_hashes_file_rel = hashes_file_rel

    hashes_file_exists = os.path.exists(hashes_file_abs)
    hashes_file_size = 0
    if hashes_file_exists:
        try:
            hashes_file_size = os.path.getsize(hashes_file_abs)
        except (OSError, IOError):
            hashes_file_size = 0

    parsed_hash_entries = _load_valid_roast_hash_entries(
        roast_type=roast_type,
        hashes_file_abs=hashes_file_abs,
    )
    normalized_users = []
    seen_users: set[str] = set()
    for user in users:
        stripped = user.strip() if user else ""
        lowered = stripped.lower()
        if not stripped or lowered in seen_users:
            continue
        normalized_users.append(stripped)
        seen_users.add(lowered)

    hash_users = [username for username, _ in parsed_hash_entries]
    if not normalized_users and hash_users:
        normalized_users = hash_users

    marked_hashes_file = mark_sensitive(hashes_file_rel, "path")
    print_info_debug(
        "[kerberos] Roast result diagnostics: "
        f"type={roast_type}, file={marked_hashes_file}, "
        f"file_exists={hashes_file_exists}, file_size={hashes_file_size}, "
        f"candidate_users={len(normalized_users)}, valid_hashes={len(parsed_hash_entries)}"
    )

    if hashes_file_exists and parsed_hash_entries:
        from adscan_internal.cli.roasting_execution import (
            _normalize_hashes_file_for_hashcat,
        )

        normalization_target_user = next(
            (username for username, _ in parsed_hash_entries if username.strip()),
            normalized_users[0] if normalized_users else "",
        )
        if normalization_target_user:
            hashcat_mode = "13100" if roast_type == "kerberoast" else "18200"
            cracking_hashes_file_abs = _normalize_hashes_file_for_hashcat(
                hashes_file_abs=hashes_file_abs,
                target_user=normalization_target_user,
                mode=hashcat_mode,
            )
            cracking_hashes_file_rel = os.path.relpath(
                cracking_hashes_file_abs,
                workspace_cwd,
            )
            print_info_debug(
                "[kerberos] Roast cracking file prepared: "
                f"type={roast_type}, raw_file={mark_sensitive(hashes_file_rel, 'path')} "
                f"cracking_file={mark_sensitive(cracking_hashes_file_rel, 'path')}"
            )

    if not normalized_users:
        _print_roast_zero_results(shell=shell, roast_type=roast_type, domain=domain)

        try:
            properties = {
                "scan_mode": getattr(shell, "scan_mode", None),
                "auth_type": shell.domains_data[domain].get("auth", "unknown"),
                "workspace_type": getattr(shell, "type", None),
                "auto_mode": getattr(shell, "auto", False),
            }
            properties.update(build_lab_event_fields(shell=shell, include_slug=True))
            telemetry.capture(f"{roast_type}_no_users_found", properties)
        except Exception as e:  # pragma: no cover - best effort
            telemetry.capture_exception(e)

        report_field = roast_type.lower()
        if report_field:
            domain_data = shell.domains_data.get(domain, {})
            if domain_data.get("auth") == "auth":
                value = {
                    "all_users": None,
                    "admin_users": None,
                    "priv_users": None,
                    "general_users": None,
                }
            else:
                value = {"all_users": None}
            shell.update_report_field(domain, report_field, value)
        return None

    from adscan_internal.services.attack_graph_service import (
        has_attack_paths_for_user,
        upsert_roast_entry_edge,
    )

    all_users: list[str] = []
    admin_users: list[str] = []
    privileged_users: list[str] = []
    non_admin_users: list[str] = []

    domain_data = shell.domains_data.get(domain, {})
    if domain_data.get("auth") == "auth":
        for user in normalized_users:
            all_users.append(user)
            if shell.check_high_value(domain, user, logging=False):
                admin_users.append(user)
            else:
                non_admin_users.append(user)

            # Record entry-vector edges for roasting for every discovered user.
            upsert_roast_entry_edge(
                shell,
                domain,
                roast_type=roast_type,
                username=user,
                status="discovered",
            )

        _print_roast_results_table(
            shell=shell,
            roast_type=roast_type,
            domain=domain,
            admin_users=admin_users,
            privileged_users=privileged_users,
            non_admin_users=non_admin_users,
            has_attack_paths_fn=has_attack_paths_for_user,
            auth_mode="auth",
        )
    else:
        for user in normalized_users:
            all_users.append(user)
            upsert_roast_entry_edge(
                shell,
                domain,
                roast_type=roast_type,
                username=user,
                status="discovered",
            )
        _print_roast_results_table(
            shell=shell,
            roast_type=roast_type,
            domain=domain,
            admin_users=[],
            privileged_users=[],
            non_admin_users=normalized_users,
            has_attack_paths_fn=has_attack_paths_for_user,
            auth_mode="guest",
        )

    report_field = roast_type.lower()
    if report_field:
        if domain_data.get("auth") == "auth":
            value = {
                "all_users": all_users if all_users else None,
                "admin_users": admin_users if admin_users else None,
                "priv_users": privileged_users if privileged_users else None,
                "general_users": non_admin_users if non_admin_users else None,
            }
        else:
            value = {
                "all_users": all_users if all_users else None,
                "admin_users": "NS",
                "priv_users": "NS",
                "general_users": "NS",
            }
        shell.update_report_field(domain, report_field, value)

    try:
        total_users = len(all_users)
        admin_count = len(admin_users) if domain_data.get("auth") == "auth" else 0
        base_properties = {
            "total_users": total_users,
            "admin_users": admin_count,
            "scan_mode": getattr(shell, "scan_mode", None),
            "auth_type": domain_data.get("auth", "unknown"),
            "workspace_type": getattr(shell, "type", None),
            "auto_mode": getattr(shell, "auto", False),
        }
        base_properties.update(build_lab_event_fields(shell=shell, include_slug=True))
        telemetry.capture(f"{roast_type}_users_found", base_properties)

        # RC4-vs-AES prevalence of the roastable hashes captured this run.
        # Sanitized by construction: only counts + the Kerberos etype (derived
        # from the hashcat line prefix) leave the host — never a hash, username,
        # SPN, realm, or any secret. One event per roast run, tagged with
        # roast_type + workspace_type so production-audit prevalence can be
        # measured in PostHog by filtering to workspace_type = audit (ctf is
        # lab noise). Only emitted when hashes were actually written.
        if parsed_hash_entries:
            etype_properties: dict[str, Any] = {
                "roast_type": roast_type,
                "scan_mode": getattr(shell, "scan_mode", None),
                "auth_type": domain_data.get("auth", "unknown"),
                "workspace_type": getattr(shell, "type", None),
                "auto_mode": getattr(shell, "auto", False),
            }
            etype_counts = _summarize_roast_etypes(parsed_hash_entries)
            etype_properties.update(etype_counts)
            etype_properties["rc4_present"] = etype_counts["rc4_count"] > 0
            etype_properties["aes_present"] = etype_counts["aes_count"] > 0
            etype_properties.update(
                build_lab_event_fields(shell=shell, include_slug=True)
            )
            telemetry.capture("roast_etype_prevalence", etype_properties)

        # Track TTFH (Time To First Hash) for case study metrics
        # Use scan_start_time (not session_start_time) for accurate timing
        # Use time.monotonic() because system clock may be manipulated for Kerberos
        if (
            hasattr(shell, "_session_first_hash_time")
            and shell._session_first_hash_time is None
            and hasattr(shell, "scan_start_time")
            and shell.scan_start_time is not None
            and total_users > 0
        ):
            import time as time_module

            shell._session_first_hash_time = time_module.monotonic()
            ttfh_seconds = max(
                0.0, shell._session_first_hash_time - shell.scan_start_time
            )
            ttfh_properties = {
                "ttfh_seconds": round(ttfh_seconds, 2),
                "ttfh_minutes": round(ttfh_seconds / 60.0, 2),
                "hash_type": roast_type,
                "hash_count": total_users,
                "scan_mode": getattr(shell, "scan_mode", None),
            }
            ttfh_properties.update(
                build_lab_event_fields(shell=shell, include_slug=True)
            )
            telemetry.capture("metric_ttfh", ttfh_properties)

        # Track hash count for case study metrics
        if hasattr(shell, "_session_hashes_count"):
            shell._session_hashes_count += total_users

    except Exception as e:  # pragma: no cover - best effort
        telemetry.capture_exception(e)

    if not parsed_hash_entries:
        print_warning(
            f"Roastable users were discovered, but no valid {roast_type} hashes were written to "
            f"{marked_hashes_file}. Skipping cracking."
        )
        return None

    try:
        updated_hashes: list[str] = [
            f"{username}:{hash_value}" for username, hash_value in parsed_hash_entries
        ]

        with open(hashes_file_abs, "w", encoding="utf-8") as f:
            for entry in updated_hashes:
                f.write(f"{entry}\n")

        if auto_crack:
            if len(all_users) == 1:
                selected_user = all_users[0]
                if _should_crack_single_roast_user(
                    shell,
                    roast_type=roast_type,
                    username=selected_user,
                ):
                    shell.ask_for_cracking(
                        roast_type,
                        domain,
                        cracking_hashes_file_rel,
                        confirm=False,
                    )
                return cracking_hashes_file_rel

            priority_users = {
                user.lower()
                for user in (admin_users + privileged_users + non_admin_users)
                if user in admin_users or has_attack_paths_for_user(shell, domain, user)
            }
            priority_list = [
                user for user in all_users if user.lower() in priority_users
            ]

            if shell.auto:
                default_choice = (
                    "all" if getattr(shell, "type", "") == "ctf" else "recommended"
                )
            else:
                default_choice = "recommended"

            selection_options = ["recommended", "all", "specific", "none"]
            if not priority_list:
                selection_options = ["all", "specific", "none"]
                default_choice = "all"

            if shell.auto:
                choice = default_choice
                print_info_verbose(f"Auto-selected cracking option: {choice}")
            else:
                if hasattr(shell, "_questionary_select"):
                    option_descriptions = {
                        "recommended": "Admins + users with attack paths (fastest impact)",
                        "all": "All roastable users (slowest)",
                        "specific": "Choose a comma-separated list of usernames",
                        "none": "Skip cracking for now",
                    }
                    options = [
                        f"{option}: {option_descriptions.get(option, '')}".strip()
                        for option in selection_options
                    ]
                    default_idx = selection_options.index(default_choice)
                    selected_idx = shell._questionary_select(
                        "Crack which users?", options, default_idx=default_idx
                    )
                    if selected_idx is None:
                        choice = default_choice
                    else:
                        choice = selection_options[selected_idx]
                else:
                    _print_roast_choice_help(
                        default_choice,
                        selection_options,
                        priority_available=bool(priority_list),
                    )
                    choice = Prompt.ask(
                        "Crack which users?",
                        choices=selection_options,
                        default=default_choice,
                    )

            def _write_subset_file(label: str, selected_users: list[str]) -> str | None:
                if not selected_users:
                    return None
                subset_rel = domain_relpath(
                    shell.domains_dir,
                    domain,
                    shell.cracking_dir,
                    f"hashes.{roast_type}.{label}",
                )
                subset_abs = domain_subpath(
                    workspace_cwd,
                    shell.domains_dir,
                    domain,
                    shell.cracking_dir,
                    f"hashes.{roast_type}.{label}",
                )
                selected_set = {user.lower() for user in selected_users}
                subset_entries = [
                    entry
                    for entry in updated_hashes
                    if entry.split(":", 1)[0].lower() in selected_set
                ]
                if not subset_entries:
                    return None
                with open(subset_abs, "w", encoding="utf-8") as handle:
                    for entry in subset_entries:
                        handle.write(f"{entry}\n")
                return subset_rel

            if choice == "none":
                return cracking_hashes_file_rel
            if choice == "recommended":
                subset_file = _write_subset_file("recommended", priority_list)
                if subset_file:
                    shell.ask_for_cracking(
                        roast_type, domain, subset_file, confirm=False
                    )
                else:
                    shell.ask_for_cracking(
                        roast_type, domain, cracking_hashes_file_rel, confirm=False
                    )
            elif choice == "specific":
                if shell.auto:
                    shell.ask_for_cracking(
                        roast_type, domain, cracking_hashes_file_rel, confirm=False
                    )
                else:
                    selection = Prompt.ask(
                        "Enter usernames (comma-separated)",
                        default=",".join(priority_list) if priority_list else "",
                    )
                    selected = [u.strip() for u in selection.split(",") if u.strip()]
                    subset_file = _write_subset_file("selected", selected)
                    if subset_file:
                        shell.ask_for_cracking(
                            roast_type, domain, subset_file, confirm=False
                        )
                    else:
                        shell.ask_for_cracking(
                            roast_type, domain, cracking_hashes_file_rel, confirm=False
                        )
            else:
                shell.ask_for_cracking(
                    roast_type, domain, cracking_hashes_file_rel, confirm=False
                )
        return cracking_hashes_file_rel
    except FileNotFoundError as e:
        telemetry.capture_exception(e)
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"No {roast_type}able users found in domain {marked_domain}")
        return None


def run_kerberoast(
    shell: KerberosShell, target_domain: str, *, auto_crack: bool
) -> str | None:
    """CLI entrypoint for Kerberoast using the service layer + local UI.

    Args:
        shell: Shell instance with workspace and domain configuration.
        target_domain: Target domain name.
        auto_crack: Whether to automatically prompt for cracking.

    Returns:
        Relative path to hashes file if successful, None otherwise.
    """
    from adscan_internal import print_operation_header

    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return None

    workspace_cwd = shell._get_workspace_cwd()
    cracking_path = domain_subpath(
        workspace_cwd, shell.domains_dir, target_domain, shell.cracking_dir
    )
    os.makedirs(cracking_path, exist_ok=True)

    domain_credentials = shell.domains_data.get(target_domain, {})
    username = domain_credentials.get("username") or shell.domains_data.get(
        shell.domain or "", {}
    ).get("username")
    password = domain_credentials.get("password") or shell.domains_data.get(
        shell.domain or "", {}
    ).get("password")

    # Determine the auth domain: if target_domain has its own credentials use it;
    # otherwise we are using cross-domain trust credentials from shell.domain.
    auth_domain: str = (
        target_domain
        if domain_credentials.get("username") and domain_credentials.get("password")
        else (shell.domain or target_domain)
    )

    if not username or not password:
        print_error(
            "Missing credentials for Kerberoast (username/password not configured)."
        )
        return None

    output_file_rel = domain_relpath(
        shell.domains_dir, target_domain, shell.cracking_dir, "hashes.kerberoast"
    )
    output_file_abs = domain_subpath(
        workspace_cwd,
        shell.domains_dir,
        target_domain,
        shell.cracking_dir,
        "hashes.kerberoast",
    )

    print_operation_header(
        "Kerberoast Attack",
        details={
            "Target Domain": target_domain,
            "Username": username,
            "Output": output_file_rel,
        },
        icon="🎫",
    )

    enum_service = EnumerationService(license_mode=shell._get_license_mode_enum())
    hashes = enum_service.kerberos.kerberoast(
        domain=target_domain,
        pdc=shell.domains_data[target_domain]["pdc"],
        username=username,
        password=password,
        hashes=None,
        auth_domain=auth_domain,
        output_file=Path(output_file_abs),
        workspace_dir=workspace_cwd,
        domains_data=shell.domains_data,
        sync_clock=getattr(shell, "sync_clock_with_pdc", None),
        scan_id=None,
    )
    # Ensure usernames are in stable order for downstream UI.
    result_users = [h.username for h in hashes]

    try:
        properties = {
            "scan_mode": getattr(shell, "scan_mode", None),
            "auth_type": shell.domains_data[target_domain].get("auth", "unknown"),
            "workspace_type": getattr(shell, "type", None),
            "auto_mode": getattr(shell, "auto", False),
        }
        properties.update(build_lab_event_fields(shell=shell, include_slug=True))
        telemetry.capture("kerberoast_started", properties)
    except Exception as e:  # pragma: no cover - best effort
        telemetry.capture_exception(e)

    if not result_users:
        marked_domain = mark_sensitive(target_domain, "domain")
        print_error(f"No kerberoastable users found in domain {marked_domain}")
        return None

    return finalize_roast_results(
        shell,
        domain=target_domain,
        roast_type="kerberoast",
        users=result_users,
        auto_crack=auto_crack,
    )


def run_asreproast(
    shell: KerberosShell, target_domain: str, *, auto_crack: bool
) -> str | None:
    """CLI entrypoint for ASREPRoast using the service layer + local UI.

    Args:
        shell: Shell instance with workspace and domain configuration.
        target_domain: Target domain name.
        auto_crack: Whether to automatically prompt for cracking.

    Returns:
        Relative path to hashes file if successful, None otherwise.
    """
    from adscan_internal import print_operation_header

    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return None

    workspace_cwd = shell._get_workspace_cwd()
    cracking_path = domain_subpath(
        workspace_cwd, shell.domains_dir, target_domain, shell.cracking_dir
    )
    os.makedirs(cracking_path, exist_ok=True)

    output_file_rel = domain_relpath(
        shell.domains_dir, target_domain, shell.cracking_dir, "hashes.asreproast"
    )
    output_file_abs = domain_subpath(
        workspace_cwd,
        shell.domains_dir,
        target_domain,
        shell.cracking_dir,
        "hashes.asreproast",
    )
    users_file_abs = domain_subpath(
        workspace_cwd, shell.domains_dir, target_domain, "users.txt"
    )

    username_display = (
        shell.domains_data.get(shell.domain or "", {}).get("username", "N/A")
        if shell.domains_data[target_domain].get("auth") == "auth"
        or shell.domains_data[target_domain].get("auth") == "pwned"
        else "Unauthenticated"
    )

    print_operation_header(
        "AS-REP Roasting Attack",
        details={
            "Target Domain": target_domain,
            "Username": username_display,
            "Output": output_file_rel,
        },
        icon="🎟️",
    )

    auth_mode = shell.domains_data[target_domain].get("auth")
    enum_service = EnumerationService(license_mode=shell._get_license_mode_enum())

    if auth_mode == "auth" or auth_mode == "pwned":
        hashes = enum_service.kerberos.asreproast(
            domain=target_domain,
            pdc=shell.domains_data[target_domain]["pdc"],
            username=shell.domains_data[shell.domain]["username"],
            password=shell.domains_data[shell.domain]["password"],
            auth_domain=shell.domain,
            usersfile=Path(users_file_abs),
            output_file=Path(output_file_abs),
            workspace_dir=workspace_cwd,
            domains_data=shell.domains_data,
            sync_clock=getattr(shell, "sync_clock_with_pdc", None),
            scan_id=None,
        )
        result_users = [h.username for h in hashes]
    else:
        hashes = enum_service.kerberos.asreproast(
            domain=target_domain,
            pdc=shell.domains_data[target_domain]["pdc"],
            usersfile=Path(users_file_abs),
            output_file=Path(output_file_abs),
            workspace_dir=workspace_cwd,
            domains_data=shell.domains_data,
            sync_clock=getattr(shell, "sync_clock_with_pdc", None),
            scan_id=None,
        )
        result_users = [h.username for h in hashes]

    try:
        properties = {
            "scan_mode": getattr(shell, "scan_mode", None),
            "auth_type": shell.domains_data[target_domain].get("auth", "unknown"),
            "workspace_type": getattr(shell, "type", None),
            "auto_mode": getattr(shell, "auto", False),
        }
        properties.update(build_lab_event_fields(shell=shell, include_slug=True))
        telemetry.capture("asreproast_started", properties)
    except Exception as e:  # pragma: no cover - best effort
        telemetry.capture_exception(e)

    return finalize_roast_results(
        shell,
        domain=target_domain,
        roast_type="asreproast",
        users=result_users,
        auto_crack=auto_crack,
    )


def ask_for_asreproast(
    shell: KerberosShell, target_domain: str, *, auto_crack: bool = True
) -> None:
    """Prompt user to perform AS-REP Roasting attack.

    Args:
        shell: Shell instance with workspace and domain configuration.
        target_domain: Target domain name.
        auto_crack: Whether to automatically prompt for cracking.
    """
    from adscan_internal.rich_output import confirm_operation, print_info

    if shell.auto:
        workspace_cwd = shell.current_workspace_dir or shell._get_workspace_cwd()
        hashes_file_abs = domain_subpath(
            workspace_cwd,
            shell.domains_dir,
            target_domain,
            shell.cracking_dir,
            "hashes.asreproast",
        )
        if os.path.exists(hashes_file_abs):
            marked_target_domain = mark_sensitive(target_domain, "domain")
            print_info(
                f"Asreproast for domain {marked_target_domain} has already been performed. Skipping..."
            )
            return
        # Continue with asreproast
        run_asreproast(shell, target_domain, auto_crack=auto_crack)
    else:
        pdc = shell.domains_data.get(target_domain, {}).get("pdc", "N/A")
        auth_type = shell.domains_data[target_domain]["auth"]
        print_info_verbose(f"Auth type: {auth_type}")
        if auth_type == "auth" or auth_type == "pwned":
            username = shell.domains_data.get(shell.domain or "", {}).get(
                "username", "N/A"
            )
        else:
            username = "Unauthenticated"

        if confirm_operation(
            operation_name="AS-REP Roasting Attack",
            description="Retrieves Kerberos AS-REP hashes for accounts without pre-authentication",
            context={
                "Domain": target_domain,
                "PDC": pdc,
                "Username": username,
                "Auth Type": auth_type.capitalize(),
                "Target": "Accounts without Kerberos Pre-Auth",
            },
            default=True,
            icon="🎫",
        ):
            run_asreproast(shell, target_domain, auto_crack=auto_crack)


def ask_for_kerberoast(
    shell: KerberosShell, target_domain: str, *, auto_crack: bool = True
) -> None:
    """Prompt user to perform Kerberoasting attack.

    Args:
        shell: Shell instance with workspace and domain configuration.
        target_domain: Target domain name.
        auto_crack: Whether to automatically prompt for cracking.
    """
    from adscan_internal.rich_output import confirm_operation

    if shell.auto:
        run_kerberoast(shell, target_domain, auto_crack=auto_crack)
    else:
        pdc = shell.domains_data.get(target_domain, {}).get("pdc", "N/A")
        domain_credentials = shell.domains_data.get(target_domain, {}) or {}
        username = domain_credentials.get("username") or shell.domains_data.get(
            shell.domain or "", {}
        ).get("username", "N/A")

        if confirm_operation(
            operation_name="Kerberoasting Attack",
            description="Extracts service account TGS tickets for offline password cracking",
            context={
                "Domain": target_domain,
                "PDC": pdc,
                "Username": username,
                "Target": "Service Principal Names (SPNs)",
                "Output": "Crackable Kerberos hashes",
            },
            default=True,
            icon="🎟️",
        ):
            run_kerberoast(shell, target_domain, auto_crack=auto_crack)


def execute_roast(
    shell: KerberosShell,
    command: str,
    domain: str,
    roast_type: str,
    *,
    auto_crack: bool = True,
) -> str | None:
    """Execute a Kerberoast/AS-REP roast command and optionally trigger cracking.

    Important UX note:
        In scan orchestrators (e.g. `run_enumeration`) we often want the step
        "Completed" status to reflect the end of the roast command itself (hash
        extraction + file generation), not the downstream cracking and credential
        processing. For those cases, call with `auto_crack=False` and run cracking
        as a separate step.

    Args:
        shell: Shell instance with workspace and domain configuration.
        command: Roast command to execute.
        domain: Target domain.
        roast_type: Roast type ("kerberoast" or "asreproast").
        auto_crack: If True (default), continue into cracking via `ask_for_cracking`.

    Returns:
        The hashes file path if hashes were produced, otherwise None.
    """
    try:
        completed_process = shell.run_command(command, timeout=300)

        # Check the process output
        if completed_process and completed_process.returncode == 0:
            output_str = completed_process.stdout or ""
            users = _extract_roast_candidate_users_from_stdout(roast_type, output_str)

            return finalize_roast_results(
                shell,
                domain=domain,
                roast_type=roast_type,
                users=users,
                auto_crack=auto_crack,
            )
        else:
            print_error(f"Error attempting to perform {roast_type}")
            if completed_process and completed_process.stderr:
                print_error(completed_process.stderr)
            return None
    except Exception as e:
        telemetry.capture_exception(e)
        if "No such file or directory" in str(e):
            marked_domain = mark_sensitive(domain, "domain")
            print_error(f"No {roast_type}able users found in domain {marked_domain}")
        else:
            print_error(f"Error executing {roast_type}.")
            from adscan_internal.rich_output import print_exception

            print_exception(show_locals=False, exception=e)
        return None


def sync_clock_with_pdc(
    shell: KerberosShell, domain: str, verbose: bool = False
) -> bool:
    """Synchronize local system clock with PDC.

    Args:
        shell: Shell instance with workspace and domain configuration.
        domain: Domain name for which the clock should be synchronized.
        verbose: Whether to emit verbose messages.

    Returns:
        True if clock synchronization is successful, False otherwise.
    """
    from adscan_internal.rich_output import print_exception
    from adscan import _is_full_adscan_container_runtime, _sudo_validate

    # Validate domain format
    if (
        not domain
        or "." not in domain
        or not domain.replace(".", "").replace("-", "").isalnum()
    ):
        if verbose:
            marked_domain = mark_sensitive(domain, "domain")
            print_warning_verbose(
                f"Invalid domain format: {marked_domain}. Expected format: example.com or domain.local"
            )
        return False

    # Avoid spamming repeated clock-sync failures
    disabled_reasons = getattr(shell, "_clock_sync_disabled_reasons", None)
    if isinstance(disabled_reasons, dict) and disabled_reasons.get(domain):
        reason = str(disabled_reasons.get(domain))
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            "[kerberos] Clock sync skipped due to prior disable reason: "
            f"domain={marked_domain}, reason={reason}"
        )
        return False

    # SSOT physical clock-sync: route the primary physical step through the
    # single source of truth ``ensure_clock_synced_fresh`` (force=True so this
    # coarse caller always re-measures + re-steps when needed). This is the ONE
    # physical-sync implementation. The legacy ntpdate / RPC / net-time machinery
    # below is retained ONLY as a fallback for environments where the SSOT guard
    # cannot step the clock (no host helper, read unavailable) — it returns
    # FELL_BACK / FAILED in those cases and we drop through to legacy.
    try:
        from adscan_internal.models.domain import resolve_dc_ip
        from adscan_internal.services.dc_time import (
            ClockSyncOutcome,
            do_ensure_clock_synced_fresh,
        )

        _ssot_domain_data = (shell.domains_data or {}).get(domain) or {}
        _ssot_dc_ip = resolve_dc_ip(_ssot_domain_data)
        if _ssot_dc_ip:
            _ssot_result = do_ensure_clock_synced_fresh(
                shell, domain, _ssot_dc_ip, force=True
            )
            if _ssot_result.outcome in (
                ClockSyncOutcome.SYNCED,
                ClockSyncOutcome.NOOP_IN_TOLERANCE,
                ClockSyncOutcome.ALREADY_FRESH,
            ):
                return True
            # FELL_BACK_TO_REQUEST_SKEW / FAILED → fall through to legacy paths.
            print_info_debug(
                "[kerberos] SSOT clock guard did not converge "
                f"(outcome={_ssot_result.outcome.value}); trying legacy paths"
            )
    except Exception as _ssot_exc:  # noqa: BLE001 — never block legacy fallback
        telemetry.capture_exception(_ssot_exc)
        print_info_debug(
            f"[kerberos] SSOT clock guard raised; trying legacy paths: {_ssot_exc}"
        )

    pdc_ip = shell.domains_data[domain]["pdc"]

    if _is_full_adscan_container_runtime():
        # Docker runtime: perform host clock sync via the host helper socket
        sock_path = os.getenv("ADSCAN_HOST_HELPER_SOCK", "").strip()
        if not sock_path:
            _set_clock_sync_disabled_reason(
                shell,
                key=domain,
                reason="host_helper_missing",
                detail="ADSCAN_HOST_HELPER_SOCK is unset or empty",
            )
            if verbose:
                marked_domain = mark_sensitive(domain, "domain")
                print_warning_verbose(
                    "Clock synchronization requires host privileges, but the host helper socket "
                    f"is not available. Domain: {marked_domain}"
                )
            return False

        try:
            from adscan_internal.host_privileged_helper import (
                HostHelperError,
                host_helper_client_request,
            )

            # Disable host NTP once per session
            if not getattr(shell, "_host_ntp_disabled_once", False):
                ntp_off_resp = host_helper_client_request(
                    sock_path,
                    op="timedatectl_set_ntp",
                    payload={"value": False},
                )
                _log_host_helper_clock_sync_response(
                    operation="timedatectl_set_ntp(false)",
                    host=pdc_ip,
                    response=ntp_off_resp,
                )
                if not ntp_off_resp.ok:
                    print_warning_verbose(
                        "Could not disable NTP via timedatectl on the host; clock sync may be unreliable."
                    )
                setattr(shell, "_host_ntp_disabled_once", True)

            # --- Primary path: dc_time service (SMB Negotiate → NTP → net time) ---
            # See ``adscan_internal/services/dc_time.py`` for channel ordering rationale.
            # The legacy ntpdate / container ntpdate / RPC chain below is kept as a final
            # fallback in case every read channel fails (e.g. SMB filtered AND ntpdate
            # absent AND net-time absent) so existing customer environments don't regress.
            try:
                import asyncio as _asyncio
                from adscan_internal.services.dc_time import (
                    DCTimeUnavailable,
                    get_dc_time,
                    is_plausible_reading,
                )

                # When this sync clock-sync helper is invoked from within a
                # running event loop (e.g. the native async SMB/MSSQL service
                # sweeps), asyncio.run() cannot nest. Detect the running loop
                # FIRST and skip straight to the legacy path: merely creating the
                # coroutine to let asyncio.run reject it leaks an un-awaited
                # coroutine ("coroutine '_read_dc_time' was never awaited").
                try:
                    _asyncio.get_running_loop()
                    _loop_running = True
                except RuntimeError:
                    _loop_running = False

                if _loop_running:
                    print_info_debug(
                        "[clock-sync] running inside an active event loop; "
                        "skipping async DC-time read, using legacy path"
                    )
                    reading = None
                else:

                    async def _read_dc_time():
                        return await get_dc_time(pdc_ip, sock_path=sock_path)

                    try:
                        reading = _asyncio.run(_read_dc_time())
                    except DCTimeUnavailable as exc:
                        print_info_debug(
                            "[clock-sync] all DC-time read channels failed, "
                            f"falling back to legacy ntpdate/net-time path: {exc}"
                        )
                        reading = None
                    except RuntimeError as exc:
                        # Defense in depth: asyncio.run still refuses to nest.
                        telemetry.capture_exception(exc)
                        print_info_debug(
                            "[clock-sync] DC-time read could not start a new event loop, "
                            f"falling back to legacy path: {exc}"
                        )
                        reading = None

                if reading is not None:
                    # Sanity-check the reading before handing it to the
                    # privileged host clock setter. A parser bug or a
                    # corrupted DC response can produce a year-1601 or
                    # year-2099 datetime, or a multi-second stale read —
                    # applying either silently corrupts the host clock
                    # (TLS, cron, Kerberos retries) for the whole session.
                    plausible, reason = is_plausible_reading(reading)
                    if not plausible:
                        print_warning(reason or "DC time reading failed sanity check.")
                        telemetry.capture_exception(
                            RuntimeError(
                                f"dc_time reading rejected by sanity gate: {reason}"
                            )
                        )
                        return False

                    set_resp = host_helper_client_request(
                        sock_path,
                        op="set_system_time",
                        payload={"datetime_iso": reading.when_utc.isoformat()},
                    )
                    _log_host_helper_clock_sync_response(
                        operation="set_system_time",
                        host=pdc_ip,
                        response=set_resp,
                    )
                    if set_resp.ok:
                        marked_pdc_ip = mark_sensitive(pdc_ip, "ip")
                        print_success_verbose(
                            f"Clock synchronized with PDC {marked_pdc_ip} "
                            f"via {reading.channel.value} (rtt={reading.rtt_ms}ms)"
                        )
                        return True
                    print_info_debug(
                        "[clock-sync] DC time read succeeded but host-helper "
                        f"set_system_time failed; falling back to legacy path: "
                        f"rc={set_resp.returncode} msg={set_resp.message!r}"
                    )
            except (HostHelperError, OSError) as _dctime_exc:
                telemetry.capture_exception(_dctime_exc)
                print_info_debug(
                    "[clock-sync] dc_time path raised host-helper error, "
                    f"falling back to legacy path: {_dctime_exc}"
                )
            except Exception as _dctime_exc:  # noqa: BLE001 — defensive
                telemetry.capture_exception(_dctime_exc)
                print_info_debug(
                    "[clock-sync] dc_time path raised unexpected error, "
                    f"falling back to legacy path: {_dctime_exc}"
                )


            ntp_resp = host_helper_client_request(
                sock_path, op="ntpdate", payload={"host": pdc_ip}
            )
            _log_host_helper_clock_sync_response(
                operation="ntpdate",
                host=pdc_ip,
                response=ntp_resp,
            )

            if ntp_resp.ok:
                marked_pdc_ip = mark_sensitive(pdc_ip, "ip")
                print_success_verbose(
                    f"Clock synchronized successfully with PDC {marked_pdc_ip}"
                )
                print_info_debug(
                    "[kerberos] Host-helper clock sync reported success. "
                    "Kerberos retry will be used as the effective post-sync validation."
                )
                return True

            # Fallback: try syncing from inside the container
            if (ntp_resp.returncode == 127) or (
                ntp_resp.message and "not found" in ntp_resp.message.lower()
            ):
                ntp_cmd = None
                if shutil.which("ntpdate"):
                    ntp_cmd = f"sudo -n ntpdate {pdc_ip}"
                elif shutil.which("ntpdig"):
                    ntp_cmd = f"sudo -n ntpdig -gq {pdc_ip}"
                if ntp_cmd:
                    marked_pdc_ip = mark_sensitive(pdc_ip, "ip")
                    proc = shell.run_command(ntp_cmd, timeout=60)
                    if proc and proc.returncode == 0:
                        print_success_verbose(
                            f"Clock synchronized successfully with PDC {marked_pdc_ip} "
                            "(container NTP fallback)"
                        )
                        return True

            # Fallback: try RPC-based clock sync
            try:
                if _is_tcp_port_open(shell, pdc_ip, 445):
                    if _sync_clock_via_net_time(shell, pdc_ip, domain=domain):
                        marked_pdc_ip = mark_sensitive(pdc_ip, "ip")
                        print_success_verbose(
                            f"Clock synchronized successfully via RPC using PDC {marked_pdc_ip}"
                        )
                        return True
            except (HostHelperError, OSError):
                pass

            marked_pdc_ip = mark_sensitive(pdc_ip, "ip")
            print_warning(f"Failed to synchronize clock with PDC {marked_pdc_ip}")
            return False
        except (HostHelperError, OSError) as exc:
            telemetry.capture_exception(exc)
            stored_reason = _set_clock_sync_disabled_reason(
                shell,
                key=domain,
                reason="host_helper_error",
                detail=exc,
            )
            marked_domain = mark_sensitive(domain, "domain")
            print_warning_debug(
                f"[kerberos] Clock sync host helper failed for {marked_domain}: {stored_reason}"
            )
            if verbose:
                print_warning_verbose(
                    f"Clock sync host helper failed for {marked_domain}: {exc}"
                )
            return False

    needs_sudo = os.geteuid() != 0
    if needs_sudo and not _sudo_validate():
        _set_clock_sync_disabled_reason(
            shell,
            key=domain,
            reason="sudo_unavailable",
        )
        if verbose:
            marked_domain = mark_sensitive(domain, "domain")
            print_warning_verbose(
                f"Clock synchronization requires elevated privileges. "
                f"Unable to use sudo; skipping clock sync for {marked_domain}."
            )
        return False

    # Disable system NTP only once per session
    timedatectl_cmd = "timedatectl set-ntp false"
    if needs_sudo:
        timedatectl_cmd = f"sudo -n {timedatectl_cmd}"
    try:
        if not getattr(shell, "_system_ntp_disabled_once", False):
            shell.run_command(timedatectl_cmd, timeout=300)
            setattr(shell, "_system_ntp_disabled_once", True)
        ntp_available = _is_ntp_service_available(shell, pdc_ip)
        if ntp_available:
            ntpdate_cmd = f"ntpdate {pdc_ip}"
            if needs_sudo:
                ntpdate_cmd = f"sudo -n {ntpdate_cmd}"
            max_ntpdig_attempts = 3
            attempt = 1
            while attempt <= max_ntpdig_attempts:
                time.sleep(1)
                process = shell.run_command(ntpdate_cmd, timeout=300)
                if process and process.returncode == 0:
                    marked_pdc_ip = mark_sensitive(pdc_ip, "ip")
                    print_success_verbose(
                        f"Clock synchronized successfully with PDC {marked_pdc_ip}"
                    )
                    return True

                error_output = ""
                if process:
                    error_output = (process.stderr or "").strip()
                    if not error_output and process.stdout:
                        error_output = process.stdout.strip()

                if "operation not permitted" in (error_output or "").lower():
                    marked_domain = mark_sensitive(domain, "domain")
                    marked_pdc_ip = mark_sensitive(pdc_ip, "ip")
                    print_warning_debug(
                        f"NTP clock sync not permitted (requires elevated privileges). "
                        f"Falling back to RPC for domain {marked_domain} and pdc {marked_pdc_ip}."
                    )
                    break

                if (
                    "ntpdig: no eligible servers" in error_output
                    and attempt < max_ntpdig_attempts
                ):
                    print_info_verbose(
                        f"ntpdig reported no eligible servers. Retrying clock sync attempt {attempt + 1}/"
                        f"{max_ntpdig_attempts}"
                    )
                    attempt += 1
                    time.sleep(1)
                    continue

                if error_output:
                    marked_domain = mark_sensitive(domain, "domain")
                    marked_pdc_ip = mark_sensitive(pdc_ip, "ip")
                    print_warning(
                        f"Error synchronizing clock: {error_output} for domain {marked_domain} and pdc {marked_pdc_ip}"
                    )
                break
        else:
            marked_pdc_ip = mark_sensitive(pdc_ip, "ip")
            print_warning_debug(
                f"NTP probe did not receive a response from {marked_pdc_ip} (UDP/123 may be blocked or rate-limited). "
                "Attempting RPC fallback."
            )

        if _is_tcp_port_open(shell, pdc_ip, 445):
            if _sync_clock_via_net_time(shell, pdc_ip, domain=domain):
                return True
        else:
            print_warning(
                "Could not connect to SMB/RPC port 445 on the PDC. Unable to use 'net time' fallback."
            )

        marked_pdc_ip = mark_sensitive(pdc_ip, "ip")
        print_warning(f"Failed to synchronize clock with PDC {marked_pdc_ip}")
        return False
    except subprocess.CalledProcessError as e:
        telemetry.capture_exception(e)
        print_error("Error synchronizing clock.")
        print_exception(show_locals=False, exception=e)
        return False


def _is_ntp_service_available(
    shell: KerberosShell, host: str, timeout: int = 3
) -> bool:
    """Check whether the remote host responds to a basic NTP request."""
    try:
        packet = b"\x1b" + 47 * b"\0"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (host, 123))
            sock.recvfrom(512)
        return True
    except OSError:
        return False


def _is_tcp_port_open(
    shell: KerberosShell, host: str, port: int, timeout: int = 3
) -> bool:
    """Check whether a TCP port is reachable."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _sanitize_clock_sync_preview(value: str | None, *, host: str) -> str:
    """Return a single-line preview for clock-sync helper output."""
    if not value:
        return "-"
    preview = " ".join(str(value).split())
    if len(preview) > 220:
        preview = f"{preview[:217]}..."
    try:
        marked_host = mark_sensitive(host, "ip")
        preview = preview.replace(host, str(marked_host))
    except Exception:  # noqa: BLE001
        pass
    return preview


def _set_clock_sync_disabled_reason(
    shell: KerberosShell,
    *,
    key: str,
    reason: str,
    detail: object | None = None,
) -> str:
    """Persist a memoized clock-sync disable reason with optional diagnostic detail."""
    disabled_reasons = getattr(shell, "_clock_sync_disabled_reasons", None)
    if not isinstance(disabled_reasons, dict):
        disabled_reasons = {}

    detail_text = str(detail or "").strip()
    stored_reason = reason if not detail_text else f"{reason}: {detail_text}"
    disabled_reasons[key] = stored_reason
    setattr(shell, "_clock_sync_disabled_reasons", disabled_reasons)
    return stored_reason


def _log_host_helper_clock_sync_response(
    *, operation: str, host: str, response: object
) -> None:
    """Emit debug diagnostics for host-helper clock sync operations."""
    returncode = getattr(response, "returncode", None)
    message = getattr(response, "message", None)
    stdout = getattr(response, "stdout", None)
    stderr = getattr(response, "stderr", None)
    ok = bool(getattr(response, "ok", False))
    marked_host = mark_sensitive(host, "ip")
    print_info_debug(
        "[kerberos] Host helper clock sync response: "
        f"op={operation} host={marked_host} ok={ok} rc={returncode} "
        f"msg={message!r} stdout={_sanitize_clock_sync_preview(stdout, host=host)!r} "
        f"stderr={_sanitize_clock_sync_preview(stderr, host=host)!r}"
    )


def _sync_clock_via_net_time(
    shell: KerberosShell, host: str, *, domain: str | None = None
) -> bool:
    """Attempt to sync system clock using Samba's 'net time' command."""
    from adscan import _is_full_adscan_container_runtime, _sudo_validate

    if _is_full_adscan_container_runtime():
        sock_path = os.getenv("ADSCAN_HOST_HELPER_SOCK", "").strip()
        disable_key = domain or host
        if not sock_path:
            _set_clock_sync_disabled_reason(
                shell,
                key=disable_key,
                reason="host_helper_missing",
                detail="ADSCAN_HOST_HELPER_SOCK is unset or empty",
            )
            return False
        try:
            from adscan_internal.host_privileged_helper import (
                HostHelperError,
                host_helper_client_request,
            )

            resp = host_helper_client_request(
                sock_path, op="net_time_set", payload={"host": host}
            )
            _log_host_helper_clock_sync_response(
                operation="net_time_set",
                host=host,
                response=resp,
            )
            return bool(resp.ok)
        except (HostHelperError, OSError):
            return False

    if shutil.which("net") is None:
        print_warning(
            "Cannot synchronize clock via RPC because the 'net' command was not found. "
            "Install samba-common-bin to enable this fallback."
        )
        return False

    # If we already determined that clock sync is not possible for this domain (e.g.,
    # due to missing privileges), skip quietly to avoid repeated warnings during scans.
    disable_key = domain or host
    disabled_reasons = getattr(shell, "_clock_sync_disabled_reasons", None)
    if isinstance(disabled_reasons, dict) and disabled_reasons.get(disable_key):
        return False

    sensitive_kind = (
        "ip" if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host or "") else "hostname"
    )
    marked_host = mark_sensitive(host, sensitive_kind)

    # Setting the system clock requires privileges. Prefer a sudo path (prompt allowed
    # once via _sudo_validate()) and then run with -n to avoid repeated prompts.
    if os.geteuid() == 0:
        command = f"net time set -S {marked_host}"
    else:
        if _sudo_validate():
            command = f"sudo -n net time set -S {marked_host}"
        else:
            # We cannot elevate, so this will consistently fail; disable further attempts.
            _set_clock_sync_disabled_reason(
                shell,
                key=disable_key,
                reason="sudo_unavailable",
            )
            print_warning(
                f"'net time' synchronization requires elevated privileges and could not use sudo. "
                f"Disabling clock sync attempts for {mark_sensitive(disable_key, 'domain' if domain else sensitive_kind)}."
            )
            return False

    process = shell.run_command(command, timeout=120)
    if process and process.returncode == 0:
        marked_host = mark_sensitive(host, sensitive_kind)
        print_success_verbose(
            f"Clock synchronized successfully via RPC using PDC {marked_host}"
        )
        return True

    error_output = ""
    if process:
        error_output = (process.stderr or "").strip()
        if not error_output and process.stdout:
            error_output = process.stdout.strip()

    marked_host = mark_sensitive(host, sensitive_kind)
    if "operation not permitted" in (error_output or "").lower():
        # This is typically a privilege/capability issue (e.g., running without root,
        # sudo not available, or restricted environments). Avoid repeating this for
        # every Kerberos command by disabling further sync attempts.
        _set_clock_sync_disabled_reason(
            shell,
            key=disable_key,
            reason="operation_not_permitted",
            detail=error_output or None,
        )
    print_warning(
        f"'net time' synchronization failed against {marked_host}: {error_output or 'unknown error'}"
    )
    return False


def run_dcsync(
    shell: KerberosShell,
    domain: str,
    username: str,
    password: str,
    target_domain: str | None = None,
) -> dict | None:
    """Perform DCSync to extract NTLM hashes of domain users.

    Args:
        shell: Shell instance with workspace and domain configuration.
        domain: Auth domain — where the credential lives.
        username: Username for authentication.
        password: Password or hash for authentication.
        target_domain: Domain to extract secrets from. Defaults to
            ``domain`` for single-realm DCSync. When provided and different,
            the DCSync targets ``target_domain``'s DC using the credential
            from ``domain`` (cross-realm DCSync via trust).
    """
    from adscan_internal.rich_output import print_operation_header
    from adscan import _resolve_domain_key, _normalize_interactive_text

    resolved_auth = _resolve_domain_key(shell.domains_data, domain)
    if not resolved_auth:
        print_error(
            f"Unknown domain: {mark_sensitive(domain, 'domain')}. "
            "Run `domains` to list available domains."
        )
        return
    auth_domain_explicit = resolved_auth

    # Resolve the target domain (DC to dump). Defaults to auth domain.
    if target_domain and target_domain.strip():
        resolved_target = _resolve_domain_key(shell.domains_data, target_domain)
        if not resolved_target:
            print_error(
                f"Unknown target domain for DCSync: "
                f"{mark_sensitive(target_domain, 'domain')}. "
                "Run `domains` to list available domains."
            )
            return
        domain = resolved_target
    else:
        domain = resolved_auth

    # SSOT physical clock-sync guard before DCSync. DRSUAPI rides Kerberos and
    # a skewed host clock breaks the bind; the per-request kerbad skew is the
    # fallback. Idempotent + best-effort: never blocks the dump on failure.
    try:
        from adscan_internal.models.domain import resolve_dc_ip
        from adscan_internal.services.dc_time import do_ensure_clock_synced_fresh

        _dcsync_domain_data = (shell.domains_data or {}).get(domain) or {}
        _dcsync_dc_ip = resolve_dc_ip(_dcsync_domain_data)
        if _dcsync_dc_ip:
            do_ensure_clock_synced_fresh(shell, domain, _dcsync_dc_ip)
    except Exception:  # noqa: BLE001 — clock guard must never block DCSync
        pass

    target_user_raw = _resolve_dcsync_target_user(shell, domain=domain, username=username)
    target_user = _normalize_interactive_text(target_user_raw)
    if not target_user:
        print_warning("No target user specified. Aborting DCSync.")
        return

    auth_method = (
        "Kerberos (ccache)" if password.lower().endswith(".ccache") else "Password"
    )
    print_operation_header(
        "DCSync Attack",
        details={
            "Domain": mark_sensitive(domain, "domain"),
            "Target User": mark_sensitive(target_user, "user"),
            "Username": mark_sensitive(username, "user"),
            "Authentication": auth_method,
        },
        icon="🔄",
    )

    marked_target = mark_sensitive(target_user, "user")
    if target_user.casefold() == "all":
        print_info_debug("[dcsync] Target scope: All users")
    else:
        print_info_debug(f"[dcsync] Target scope: single user {marked_target}")

    previous_context = getattr(shell, "_current_dcsync_context", None)
    shell._current_dcsync_context = {
        "domain": domain,
        "username": username,
        "password": password,
        "target_user": target_user,
        "retry_attempted": False,
    }
    try:
        from adscan_internal.cli.secretsdump import execute_dcsync_native

        # Cross-realm: keep the explicit auth domain so the AS-REQ goes to
        # the credential's KDC, not the target domain's KDC.
        auth_domain_for_native = (
            auth_domain_explicit
            if auth_domain_explicit != domain
            else str(
                (shell.domains_data.get(domain, {}) or {}).get("auth_domain") or domain
            )
        )
        target_users_for_native: list[str] | None = (
            None if target_user.casefold() == "all" else [target_user]
        )
        result = execute_dcsync_native(
            shell,
            domain=domain,
            auth_domain=auth_domain_for_native,
            target_users=target_users_for_native,
        )
    finally:
        shell._current_dcsync_context = previous_context
    # NOTE: the ``dcsync_all_done`` marker for a full ("all") replication is set
    # inside execute_dcsync_native (the common native-DRSUAPI point), so EVERY
    # full-dump path — this one, secretsdump, attack-path steps — records it
    # uniformly. Do not duplicate the marker here.
    return result


def _resolve_logon_capable_dcsync_credential(
    shell: KerberosShell, *, domain: str, username: str, password: str
) -> tuple[str, str]:
    """Pick a credential that can NETWORK-logon to the DC for DRSUAPI.

    DCSync replicates over an SMB session to the DC, so the principal needs a
    network logon there. The queued credential (the one that achieved the
    compromise) may be a Domain Admin the DC DENIES a network logon
    (SeDenyNetworkLogonRight). Prefer, in order:

      1. A host-scoped service ticket for the DC (e.g. minted + probed
         logon-capable by a prior AllowedToAct / SPNJack step) — reused via the
         same ``resolve_execution_credential`` chokepoint the attack-path DCSync
         uses, so both entry points behave identically.
      2. The queued credential as-is — but if it is known-denied a network logon
         on the DC and no scoped ticket exists, warn loudly (DRSUAPI will fail;
         no silent failure).

    Returns ``(username, secret)`` — ``secret`` may be a ccache path (the ST).
    """
    domain_data = shell.domains_data.get(domain, {}) or {}
    try:
        from adscan_internal.models.domain import resolve_dc_ip  # noqa: PLC0415

        dc_host = (
            domain_data.get("dc_fqdn")
            or domain_data.get("pdc_hostname_fqdn")
            or domain_data.get("pdc_hostname")
            or resolve_dc_ip(domain_data)
            or ""
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        dc_host = ""
    if not dc_host:
        return username, password

    # 1. Scoped-ticket-first (logon-capable by construction — the ST was probed).
    try:
        from adscan_internal.services.credential_store_service import (  # noqa: PLC0415
            resolve_execution_credential,
        )

        scoped = resolve_execution_credential(
            shell, domain=domain, host=dc_host, relation="dcsync"
        )
        if scoped is not None:
            su, sp = scoped
            print_info_debug(
                f"[dcsync] reusing host-scoped service ticket for "
                f"{mark_sensitive(dc_host, 'hostname')} as {mark_sensitive(su, 'user')} "
                "(logon-capable; avoids a DA the DC may deny a network logon)"
            )
            return su, sp
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)

    # 2. No scoped ticket — warn if the queued principal is known-denied (no
    #    silent failure; the operator/CI sees exactly why DRSUAPI will fail).
    try:
        from adscan_internal.services.credential_store_service import (  # noqa: PLC0415
            is_logon_denied,
        )

        if username and is_logon_denied(
            shell.domains_data, domain, principal=username, host=dc_host
        ):
            print_warning(
                f"DCSync principal {mark_sensitive(username, 'user')} is known-denied "
                f"a network logon on {mark_sensitive(dc_host, 'hostname')} "
                "(SeDenyNetworkLogonRight); DRSUAPI will likely fail and no "
                "host-scoped ticket is available to reuse."
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
    return username, password


def ask_for_dcsync(
    shell: KerberosShell, domain: str, username: str, password: str
) -> None:
    """Prompt user to perform DCSync attack.

    Args:
        shell: Shell instance with workspace and domain configuration.
        domain: Target domain name.
        username: Username for authentication.
        password: Password or hash for authentication.
    """
    from adscan_internal.rich_output import confirm_operation

    # Prefer a logon-capable principal (scoped ticket first) — the queued DA may
    # be denied a network logon on the DC, which DRSUAPI needs.
    username, password = _resolve_logon_capable_dcsync_credential(
        shell, domain=domain, username=username, password=password
    )

    pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")

    if confirm_operation(
        operation_name="DCSync Attack",
        description="Replicates Active Directory credentials from the Domain Controller",
        context={
            "Domain": domain,
            "PDC": pdc,
            "Username": username,
            "Privileges Required": "Replication Rights (DCSync)",
            "Target": "Domain credentials database",
        },
        default=True,
        icon="🔄",
    ):
        run_dcsync(shell, domain, username, password)


def do_dcsync(shell: KerberosShell, args: str) -> None:
    """Perform DCSync to extract NTLM hashes of domain users.

    Args:
        shell: Shell instance with workspace and domain configuration.
        args: Command arguments as string (format: "<domain> <username> <password>").

    Usage:
        dcsync <domain> <username> <password>

    Requires that the domain is defined in the domains list and that a username and password
    have been specified for authentication.
    """
    args_list = args.split()
    if len(args_list) != 3:
        print_warning("Usage: dcsync <domain> <username> <password>")
        return
    domain = args_list[0]
    username = args_list[1]
    password = args_list[2]
    run_dcsync(shell, domain, username, password)


def run_kerberoast_preauth(shell: KerberosShell, domain: str, user: str) -> None:
    """Perform pre-authenticated Kerberoasting attack.

    Args:
        shell: Shell instance with workspace and domain configuration.
        domain: Target domain name.
        user: Username for authentication.
    """
    workspace_cwd = shell.current_workspace_dir or shell._get_workspace_cwd()
    cracking_path = domain_subpath(
        workspace_cwd, shell.domains_dir, domain, shell.cracking_dir
    )
    if not os.path.exists(cracking_path):
        os.makedirs(cracking_path)

    users_file_abs = domain_subpath(
        workspace_cwd, shell.domains_dir, domain, "users.txt"
    )
    pdc = shell.domains_data[domain]["pdc"]
    marked_user = mark_sensitive(user, "user")
    marked_domain = mark_sensitive(domain, "domain")

    print_info(
        f"Generating kerberoastable user list with pre-auth for user {marked_user} "
        f"in domain {marked_domain}"
    )
    try:
        enum_service = EnumerationService(license_mode=shell._get_license_mode_enum())
        hashes = enum_service.kerberos.kerberoast_no_preauth(
            domain=domain,
            pdc=pdc,
            no_preauth_username=user,
            usersfile=Path(users_file_abs),
            output_file=Path(
                domain_subpath(
                    workspace_cwd,
                    shell.domains_dir,
                    domain,
                    shell.cracking_dir,
                    "hashes.kerberoast",
                )
            ),
            scan_id=None,
        )
        if not hashes:
            print_error("No no-preauth Kerberoast hashes were produced.")
            return

        print_success_verbose("No-preauth Kerberoast completed successfully.")
        finalize_roast_results(
            shell,
            domain=domain,
            roast_type="kerberoast",
            users=[item.username for item in hashes],
            auto_crack=True,
        )
        print_info_verbose(
            f"Generated Kerberoast hashes with no-preauth user {marked_user} "
            f"in domain {marked_domain}"
        )
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error executing no-preauth Kerberoast.")
        from adscan_internal.rich_output import print_exception

        print_exception(show_locals=False, exception=e)


def ask_for_kerberoast_preauth(shell: KerberosShell, domain: str, user: str) -> None:
    """Prompt user to perform pre-authenticated Kerberoasting attack.

    Args:
        shell: Shell instance with workspace and domain configuration.
        domain: Target domain name.
        user: Username for authentication.
    """
    from adscan_internal.rich_output import confirm_operation

    if shell.auto:
        run_kerberoast_preauth(shell, domain, user)
    else:
        pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")

        if confirm_operation(
            operation_name="Pre-Authenticated Kerberoasting",
            description="Uses valid credentials to request service tickets for offline cracking",
            context={
                "Domain": domain,
                "PDC": pdc,
                "Username": user,
                "Method": "Pre-authenticated TGS request",
            },
            default=True,
            icon="🔐",
        ):
            run_kerberoast_preauth(shell, domain, user)


def do_kerberoast_preauth(shell: KerberosShell, args: str) -> None:
    """Perform pre-authenticated kerberoast attack for a user in a domain.

    Args:
        shell: Shell instance with workspace and domain configuration.
        args: Command arguments as string (format: "<domain> <user>").

    Usage:
        kerberoast_preauth <domain> <user>

    Requires that the domain is defined in the domains list and that a username
    and password have been specified for authentication.
    """
    args_list = args.split()
    if len(args_list) != 2:
        print_warning("Usage: kerberoast_preauth <domain> <user>")
        return
    domain = args_list[0]
    user = args_list[1]
    run_kerberoast_preauth(shell, domain, user)
