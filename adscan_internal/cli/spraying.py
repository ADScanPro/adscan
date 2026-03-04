"""CLI orchestration for password spraying attacks.

This module keeps password spraying *UI + reporting* logic out of the monolith.
The service layer (adscan_internal.spraying) performs the tool execution and basic parsing; this module:
- resolves workspace paths
- prints operation headers
- updates reports + telemetry
- renders Rich tables
- handles user prompts for spraying operations
"""

from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone
from typing import Optional, Protocol

from adscan_internal import (
    print_error,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_instruction,
    print_warning,
    print_warning_debug,
    print_warning_verbose,
    telemetry,
)
from adscan_internal.cli.common import build_lab_event_fields
from adscan_internal.rich_output import (
    mark_sensitive,
    print_exception,
    print_panel,
    print_table,
)
from adscan_internal.subprocess_env import command_string_needs_clean_env
from adscan_internal.text_utils import strip_ansi_codes
from adscan_internal.workspaces import domain_relpath, domain_subpath
from adscan_internal.workspaces.computers import (
    has_enabled_computer_list,
    load_enabled_computer_samaccounts,
)
from adscan_internal.integrations.netexec.parsers import (
    parse_netexec_computer_badpwd,
)
from rich.prompt import Confirm, Prompt
from rich.table import Table

# Import from internal spraying module
from adscan_internal.spraying import (
    SprayEligibilityResult,
    build_kerbrute_command,
    build_kerbrute_bruteforce_command,
    build_netexec_computers_query_command,
    build_netexec_pass_pol_command,
    build_netexec_users_command,
    compute_spray_eligibility,
    parse_netexec_lockout_threshold,
    parse_netexec_users_badpwd,
    read_user_list,
    safe_log_filename_fragment,
    write_temp_combo_file,
    write_temp_users_file,
)


class SprayShell(Protocol):
    """Minimal shell surface used by the spraying controller."""

    console: object
    domains: list[str]
    domains_dir: str
    kerberos_dir: str
    domain: str | None
    type: str | None
    auto: bool
    scan_mode: str | None
    current_workspace_dir: str | None
    domains_data: dict
    kerbrute_path: str | None
    netexec_path: str | None
    password_spraying_history: dict | None

    def _get_workspace_cwd(self) -> str: ...

    def _questionary_select(
        self, title: str, options: list[str], default_idx: int = 0
    ) -> int | None: ...

    def do_sync_clock_with_pdc(self, domain: str, verbose: bool = False) -> bool: ...

    def _run_netexec(
        self,
        command: str,
        domain: str | None = None,
        timeout: int | None = None,
        shell: bool = False,
        capture_output: bool = False,
        text: bool = False,
    ) -> subprocess.CompletedProcess[str] | None: ...

    def run_command(
        self, command: str, *, timeout: int | None = None, **kwargs
    ) -> subprocess.CompletedProcess[str] | None: ...

    def add_credential(
        self,
        domain: str,
        user: str,
        cred: str,
        host: str | None = None,
        service: str | None = None,
        skip_hash_cracking: bool = False,
    ) -> None: ...

    def ask_for_pass_policy(self, domain: str) -> None: ...

    def do_netexec_pass_policy(self, domain: str) -> None: ...


_SPRAYING_UX_STATE_KEY = "_spraying_ux"
_RECOMMENDED_SPRAY_CATEGORIES = {
    "useraspass",
    "useraspass_lower",
    "useraspass_upper",
    "computer_pre2k",
}


def _get_spraying_ux_state(shell: SprayShell, domain: str) -> dict[str, object]:
    """Return mutable UX state for spraying prompts in the given domain."""
    domain_state = shell.domains_data.get(domain)
    if not isinstance(domain_state, dict):
        domain_state = {}
        shell.domains_data[domain] = domain_state
    ux_state = domain_state.get(_SPRAYING_UX_STATE_KEY)
    if not isinstance(ux_state, dict):
        ux_state = {}
        domain_state[_SPRAYING_UX_STATE_KEY] = ux_state
    return ux_state


def _capture_spraying_ux_event(
    shell: SprayShell,
    event: str,
    domain: str,
    *,
    extra: dict[str, object] | None = None,
) -> None:
    """Best-effort telemetry capture for spraying UX events."""
    try:
        properties: dict[str, object] = {
            "domain": domain,
            "workspace_type": getattr(shell, "type", None),
            "scan_mode": getattr(shell, "scan_mode", None),
            "auto_mode": getattr(shell, "auto", False),
        }
        if extra:
            properties.update(extra)
        properties.update(build_lab_event_fields(shell=shell, include_slug=True))
        telemetry.capture(event, properties)
    except Exception as exc:  # pragma: no cover - telemetry must not break UX
        telemetry.capture_exception(exc)


def _mark_recommended_spraying_attempt(
    shell: SprayShell, domain: str, category: str
) -> None:
    """Record that a recommended CTF spraying technique was attempted."""
    ux_state = _get_spraying_ux_state(shell, domain)
    attempted = ux_state.get("recommended_attempted_categories")
    if not isinstance(attempted, list):
        attempted = []
        ux_state["recommended_attempted_categories"] = attempted
    if category not in attempted:
        attempted.append(category)


def _has_recommended_spraying_attempt(shell: SprayShell, domain: str) -> bool:
    """Return True when a recommended spray type was already attempted."""
    ux_state = _get_spraying_ux_state(shell, domain)
    attempted = ux_state.get("recommended_attempted_categories")
    if not isinstance(attempted, list):
        return False
    return any(str(item) in _RECOMMENDED_SPRAY_CATEGORIES for item in attempted)


def maybe_show_ctf_spraying_recommendation(
    shell: SprayShell,
    domain: str,
    *,
    reason: str,
) -> None:
    """Show one-time CTF recommendation when no recommended spraying was attempted."""
    if str(getattr(shell, "type", "") or "").strip().lower() != "ctf":
        return
    if shell.domains_data.get(domain, {}).get("auth") == "pwned":
        return
    if _has_recommended_spraying_attempt(shell, domain):
        return

    ux_state = _get_spraying_ux_state(shell, domain)
    if bool(ux_state.get("recommended_hint_shown", False)):
        return

    marked_domain = mark_sensitive(domain, "domain")
    panel_lines = [
        f"Domain: {marked_domain}",
        "In many HTB/CTF environments, a first foothold comes from spraying.",
        "",
        "High-value quick checks:",
        "1) Computer accounts (pre2k: hostname as password)",
        "2) Username as password (normal/lower/upper variants)",
        "",
        f"Run now: spraying {domain}",
    ]
    print_panel(
        "\n".join(panel_lines),
        title="[bold yellow]Recommended CTF Next Step[/bold yellow]",
        border_style="yellow",
        expand=False,
    )
    print_instruction(
        "If you skip spraying in CTF, you can miss the intended foothold path."
    )
    ux_state["recommended_hint_shown"] = True
    _capture_spraying_ux_event(
        shell,
        "ctf_spraying_recommendation_shown",
        domain,
        extra={"reason": reason},
    )


def get_spraying_user_list_path(
    shell: SprayShell, domain: str, requires_auth_users: bool
) -> str | None:
    """Return the user list path required for spraying, ensuring it exists and is not empty."""
    primary_filename = "enabled_users.txt" if requires_auth_users else "users.txt"
    fallback_filename = "users.txt" if requires_auth_users else "enabled_users.txt"
    candidate_filenames = [primary_filename]
    if fallback_filename != primary_filename:
        candidate_filenames.append(fallback_filename)

    workspace_cwd = shell.current_workspace_dir or os.getcwd()

    try:
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            f"[spray] Resolving user list for {marked_domain}: "
            f"requires_auth_users={requires_auth_users}, "
            f"primary={mark_sensitive(domain_relpath(shell.domains_dir, domain, primary_filename), 'path')}, "
            f"fallback={mark_sensitive(domain_relpath(shell.domains_dir, domain, fallback_filename), 'path')}"
        )
        candidate_reasons: list[tuple[str, str]] = []
        for idx, filename in enumerate(candidate_filenames):
            relative_path = domain_relpath(shell.domains_dir, domain, filename)
            absolute_path = domain_subpath(
                workspace_cwd, shell.domains_dir, domain, filename
            )
            marked_path = mark_sensitive(relative_path, "path")
            if not os.path.exists(absolute_path):
                candidate_reasons.append((relative_path, "missing"))
                print_info_debug(f"[spray] Missing user list file: {marked_path}")
                continue

            size = os.path.getsize(absolute_path)
            if size == 0:
                candidate_reasons.append((relative_path, "empty"))
                print_info_debug(f"[spray] User list file is empty: {marked_path}")
                continue

            if idx > 0:
                print_info_debug(
                    f"[spray] Falling back to alternate user list file: {marked_path}"
                )
            print_info_debug(
                f"[spray] User list file size: {size} bytes ({marked_path})"
            )
            return relative_path

        attempted_paths = ", ".join(
            domain_relpath(shell.domains_dir, domain, f) for f in candidate_filenames
        )
        print_warning(
            "Cannot perform password spraying: no valid user list file found "
            f"({attempted_paths})."
        )
        print_info(
            "Generate the user list first (e.g., run the corresponding enumeration command) "
            "and try again."
        )
        for candidate_path, reason in candidate_reasons:
            print_info_debug(
                "[spray] Candidate user list rejected: "
                f"path={mark_sensitive(candidate_path, 'path')} reason={reason}"
            )
        return None
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_error(f"Unable to validate spraying user list for domain {domain}: {exc}")
        print_info_debug(
            f"[spray] Exception while validating user list: {type(exc).__name__}: {exc}"
        )
        return None


def get_password_spraying_history(shell: SprayShell) -> dict:
    """Return the password spraying history dict, initializing it if needed.

    Structure:
        {
            "<domain>": {
                "<category>": {
                    "count": int,
                    "last_run": str,  # ISO 8601 UTC
                    # For category == "password":
                    # "passwords": {
                    #     "<password>": {"count": int, "last_run": str}
                    # }
                }
            }
        }
    """
    history = getattr(shell, "password_spraying_history", None)
    if not isinstance(history, dict):
        history = {}
        shell.password_spraying_history = history
    return history


def register_spraying_attempt(
    shell: SprayShell, domain: str, category: str, password: Optional[str] = None
) -> None:
    """Record a password spraying attempt in the in-memory history."""
    try:
        history = get_password_spraying_history(shell)
        domain_history = history.setdefault(domain, {})
        category_entry = domain_history.setdefault(category, {})
        now_iso = datetime.now(timezone.utc).isoformat()

        if category == "password":
            passwords_entry = category_entry.setdefault("passwords", {})
            if password is None:
                return
            pwd_entry = passwords_entry.setdefault(
                password, {"count": 0, "last_run": None}
            )
            pwd_entry["count"] = int(pwd_entry.get("count", 0)) + 1
            pwd_entry["last_run"] = now_iso
        else:
            category_entry["count"] = int(category_entry.get("count", 0)) + 1
            category_entry["last_run"] = now_iso
    except Exception as exc:
        telemetry.capture_exception(exc)


def should_proceed_with_repeated_spraying(
    shell: SprayShell, domain: str, category: str, password: Optional[str] = None
) -> bool:
    """Check if this spraying is a repeat and, if so, warn and ask for confirmation.

    Returns:
        bool: True if spraying should continue, False if it should be cancelled.
    """
    try:
        history = get_password_spraying_history(shell)
        domain_history = history.get(domain, {})
        category_entry = domain_history.get(category, {})

        is_repeat = False
        last_run = None

        if category == "password":
            passwords_entry = category_entry.get("passwords", {})
            if password is not None and password in passwords_entry:
                is_repeat = True
                last_run = passwords_entry[password].get("last_run")
        else:
            if category_entry:
                is_repeat = True
                last_run = category_entry.get("last_run")

        if not is_repeat:
            # First time: just register and continue silently
            register_spraying_attempt(shell, domain, category, password)
            return True

        marked_domain = mark_sensitive(domain, "domain")
        category_labels = {
            "useraspass": "Username as password",
            "useraspass_lower": "Username as password in lowercase",
            "useraspass_upper": "Username as password in uppercase",
            "password": "Specific password",
            "computer_pre2k": "Computer accounts (pre2k)",
        }
        category_label = category_labels.get(category, category)

        lines: list[str] = []
        lines.append(
            f"You have already performed a password spraying in domain {marked_domain}"
        )
        if category == "password" and password is not None:
            marked_password = mark_sensitive(password, "password")
            lines.append(
                f"using the password {marked_password} (same password spraying type)."
            )
        else:
            lines.append(f"with type: {category_label}.")

        if last_run:
            lines.append(f"Last execution time (UTC): {last_run}")

        lines.append(
            "\nRepeating the same spraying may increase the risk of account lockouts "
            "or violate password policy guidance."
        )
        lines.append(
            "Only continue if you are sure this is allowed and expected for your engagement."
        )

        panel_content = "\n".join(lines)

        print_panel(
            panel_content,
            title="[bold yellow]Repeated Password Spraying Detected[/bold yellow]",
            border_style="yellow",
            expand=False,
        )

        proceed = Confirm.ask(
            "Taking this into account, do you still want to continue with this password spraying?",
            default=False,
        )
        if not proceed:
            return False

        # User explicitly accepted the risk, register attempt
        register_spraying_attempt(shell, domain, category, password)
        return True
    except Exception as exc:
        telemetry.capture_exception(exc)
        # If anything goes wrong, do not block spraying flow
        return True


def compute_spraying_eligibility(
    shell: SprayShell,
    *,
    domain: str,
    user_list_file: str,
    safe_threshold: int,
) -> SprayEligibilityResult | None:
    """Compute eligible and excluded users for password spraying.

    This is a best-effort implementation that tries to use NetExec policy
    data (Account Lockout Threshold + BadPwdCount) when credentials are
    available for the current domain context. If policy data cannot be
    obtained or parsed, it falls back to the full user list.

    Returns:
        A `SprayEligibilityResult` instance (from `adscan_internal.spraying`)
        on success, or None on fatal errors (e.g., cannot read user list).
    """
    try:
        file_users = read_user_list(user_list_file)
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_error("Unable to read the spraying user list file.")
        print_exception(show_locals=False, exception=exc)
        return None

    is_auth = shell.domains_data[domain]["auth"] == "auth"
    pdc_ip = shell.domains_data[domain]["pdc"]
    marked_domain = mark_sensitive(domain, "domain")

    lockout_threshold = None
    badpwd_by_user = None

    print_info_verbose(
        f"Starting spray eligibility computation for {marked_domain} "
        f"(safe remaining threshold={safe_threshold}, users in list={len(file_users)})."
    )

    if is_auth and shell.netexec_path:
        auth_domain = getattr(shell, "domain", None)
        auth_username = shell.domains_data.get(auth_domain or "", {}).get("username")
        auth_password = shell.domains_data.get(auth_domain or "", {}).get("password")

        if not auth_domain or not auth_username or not auth_password:
            print_warning_verbose(
                "Skipping password policy lookup because authenticated domain "
                "credentials are incomplete."
            )
            return compute_spray_eligibility(
                file_users=file_users,
                lockout_threshold=lockout_threshold,
                badpwd_by_user=badpwd_by_user,
                safe_remaining_threshold=safe_threshold,
                strict_missing_badpwd=True,
            )
        if auth_domain and auth_username and auth_password:
            pass_pol_cmd = build_netexec_pass_pol_command(
                nxc_path=shell.netexec_path,
                dc_ip=pdc_ip,
                username=auth_username,
                password=auth_password,
                domain=auth_domain,
                kerberos=True,
            )
            print_info_debug(f"[netexec pass-pol] {pass_pol_cmd}")

            users_cmd = build_netexec_users_command(
                nxc_path=shell.netexec_path,
                dc_ip=pdc_ip,
                username=auth_username,
                password=auth_password,
                domain=auth_domain,
                kerberos=True,
            )

            pass_pol_proc = shell._run_netexec(
                pass_pol_cmd,
                domain=auth_domain,
                timeout=300,
                shell=True,
                capture_output=True,
                text=True,
            )
            if pass_pol_proc and pass_pol_proc.stdout:
                lockout_threshold = parse_netexec_lockout_threshold(
                    strip_ansi_codes(pass_pol_proc.stdout)
                )
                if lockout_threshold is None:
                    print_info_verbose(
                        "Password policy returned 'None' for account lockout threshold. "
                        "No lockout is enforced; spraying cannot lock accounts."
                    )
                else:
                    print_info_verbose(
                        f"Parsed account lockout threshold={lockout_threshold}."
                    )
            else:
                print_warning_verbose(
                    "Password policy command produced no output; "
                    "lockout threshold unavailable."
                )

            users_proc = shell._run_netexec(
                users_cmd,
                domain=auth_domain,
                timeout=300,
                shell=True,
                capture_output=True,
                text=True,
            )
            if users_proc and users_proc.stdout:
                badpwd_by_user = parse_netexec_users_badpwd(
                    strip_ansi_codes(users_proc.stdout)
                )
                print_info_verbose(
                    f"Parsed BadPwdCount data for {len(badpwd_by_user)} user(s)."
                )
                if len(badpwd_by_user) == 0:
                    print_warning_verbose(
                        "User query returned output but no BadPwdCount values were "
                        "recognized."
                    )
            else:
                print_warning_verbose(
                    "User query command produced no output; BadPwdCount data "
                    "unavailable."
                )
    else:
        if not is_auth:
            print_warning_verbose(
                f"Skipping password policy lookup for {marked_domain} because the "
                "current domain context is not authenticated."
            )
        elif not shell.netexec_path:
            print_warning_verbose(
                "Skipping password policy lookup because the policy query tool is "
                "not configured."
            )

    return compute_spray_eligibility(
        file_users=file_users,
        lockout_threshold=lockout_threshold,
        badpwd_by_user=badpwd_by_user,
        safe_remaining_threshold=safe_threshold,
        strict_missing_badpwd=True,
    )


def _load_enabled_computer_sams(shell: SprayShell, domain: str) -> list[str]:
    """Load enabled computer names and convert to sAMAccountName format."""
    workspace_cwd = shell.current_workspace_dir or os.getcwd()
    rel_path = domain_relpath(shell.domains_dir, domain, "enabled_computers.txt")
    abs_path = domain_subpath(
        workspace_cwd, shell.domains_dir, domain, "enabled_computers.txt"
    )

    marked_domain = mark_sensitive(domain, "domain")
    if not os.path.exists(abs_path):
        print_warning(
            "Cannot perform computer pre2k check: enabled_computers.txt does not exist."
        )
        print_info(
            "Generate the computer list first (e.g., run the corresponding enumeration command) "
            "and try again."
        )
        print_info_debug(
            f"[spray] Missing enabled_computers.txt for {marked_domain}: {mark_sensitive(rel_path, 'path')}"
        )
        return []

    try:
        results = load_enabled_computer_samaccounts(
            workspace_cwd, shell.domains_dir, domain
        )
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_error("Unable to read enabled_computers.txt.")
        print_info_debug(
            f"[spray] Failed reading enabled_computers.txt for {marked_domain}: {exc}"
        )
        return []

    print_info_debug(
        f"[spray] Loaded {len(results)} computer account(s) from enabled_computers.txt for {marked_domain}"
    )
    return results


def compute_computer_spraying_eligibility(
    shell: SprayShell,
    *,
    domain: str,
    computer_sams: list[str],
    safe_threshold: int,
) -> SprayEligibilityResult | None:
    """Compute eligible computer accounts for pre2k checks."""
    lockout_threshold = None
    badpwd_by_user = None

    is_auth = shell.domains_data[domain]["auth"] == "auth"
    pdc_ip = shell.domains_data[domain]["pdc"]
    marked_domain = mark_sensitive(domain, "domain")

    print_info_verbose(
        f"Starting computer pre2k eligibility computation for {marked_domain} "
        f"(safe remaining threshold={safe_threshold}, computers={len(computer_sams)})."
    )

    if is_auth and shell.netexec_path:
        auth_domain = getattr(shell, "domain", None)
        auth_username = shell.domains_data.get(auth_domain or "", {}).get("username")
        auth_password = shell.domains_data.get(auth_domain or "", {}).get("password")

        if not auth_domain or not auth_username or not auth_password:
            print_warning_verbose(
                "Skipping computer BadPwdCount lookup because authenticated "
                "domain credentials are incomplete."
            )
            return compute_spray_eligibility(
                file_users=computer_sams,
                lockout_threshold=lockout_threshold,
                badpwd_by_user=badpwd_by_user,
                safe_remaining_threshold=safe_threshold,
                strict_missing_badpwd=True,
            )

        pass_pol_cmd = build_netexec_pass_pol_command(
            nxc_path=shell.netexec_path,
            dc_ip=pdc_ip,
            username=auth_username,
            password=auth_password,
            domain=auth_domain,
        )
        print_info_debug(f"[netexec pass-pol] {pass_pol_cmd}")

        computers_cmd = build_netexec_computers_query_command(
            nxc_path=shell.netexec_path,
            dc_ip=pdc_ip,
            username=auth_username,
            password=auth_password,
            domain=auth_domain,
            kerberos=True,
        )
        print_info_debug(f"[netexec computers] {computers_cmd}")

        pass_pol_proc = shell._run_netexec(
            pass_pol_cmd,
            domain=auth_domain,
            timeout=300,
            shell=True,
            capture_output=True,
            text=True,
        )
        if pass_pol_proc and pass_pol_proc.stdout:
            lockout_threshold = parse_netexec_lockout_threshold(
                strip_ansi_codes(pass_pol_proc.stdout)
            )
            if lockout_threshold is None:
                print_info_verbose(
                    "Password policy returned 'None' for account lockout threshold. "
                    "No lockout is enforced; spraying cannot lock accounts."
                )
            else:
                print_info_verbose(
                    f"Parsed account lockout threshold={lockout_threshold}."
                )
        else:
            print_warning_verbose(
                "Password policy command produced no output; "
                "lockout threshold unavailable."
            )

        computers_proc = shell._run_netexec(
            computers_cmd,
            domain=auth_domain,
            timeout=300,
            shell=True,
            capture_output=True,
            text=True,
        )
        if computers_proc and computers_proc.stdout:
            badpwd_by_user = parse_netexec_computer_badpwd(
                strip_ansi_codes(computers_proc.stdout)
            )
            print_info_verbose(
                f"Parsed BadPwdCount data for {len(badpwd_by_user)} computer(s)."
            )
            if len(badpwd_by_user) == 0:
                print_warning_verbose(
                    "Computer query returned output but no BadPwdCount values were "
                    "recognized."
                )
        else:
            print_warning_verbose(
                "Computer query command produced no output; BadPwdCount data "
                "unavailable."
            )
    else:
        if not is_auth:
            print_warning_verbose(
                f"Skipping computer BadPwdCount lookup for {marked_domain} because the "
                "current domain context is not authenticated."
            )
        elif not shell.netexec_path:
            print_warning_verbose(
                "Skipping computer BadPwdCount lookup because the query tool is "
                "not configured."
            )

    return compute_spray_eligibility(
        file_users=computer_sams,
        lockout_threshold=lockout_threshold,
        badpwd_by_user=badpwd_by_user,
        safe_remaining_threshold=safe_threshold,
        strict_missing_badpwd=True,
    )


def print_spraying_eligibility(
    shell: SprayShell, domain: str, eligibility: SprayEligibilityResult
) -> None:
    """Render eligibility info for spraying in a user-friendly way."""
    marked_domain = mark_sensitive(domain, "domain")
    summary_lines: list[str] = [
        f"Domain: {marked_domain}",
        f"Users in list: {len(eligibility.input_users)}",
        f"Eligible users: {len(eligibility.eligible_users)}",
        f"Excluded users: {len(eligibility.excluded_users)}",
    ]
    if eligibility.lockout_threshold is not None:
        summary_lines.append(
            f"Account lockout threshold: {eligibility.lockout_threshold}"
        )
        summary_lines.append(
            f"Safe remaining attempts threshold: {eligibility.safe_remaining_threshold}"
        )
    if eligibility.notes:
        summary_lines.append("")
        summary_lines.extend(eligibility.notes)

    print_panel(
        "\n".join(summary_lines),
        title="[bold cyan]Spray Eligibility Summary[/bold cyan]",
        border_style="cyan",
        expand=False,
    )

    if eligibility.excluded_users:
        table = Table(title="Excluded users (preview)", show_lines=False)
        table.add_column("User")
        table.add_column("Reason")
        table.add_column("BadPwdCount", justify="right")
        table.add_column("Remaining", justify="right")

        preview = eligibility.excluded_users[:20]
        for excluded in preview:
            marked_user = mark_sensitive(excluded.username, "user")
            badpwd_str = (
                str(excluded.badpwd_count) if excluded.badpwd_count is not None else "-"
            )
            remaining_str = (
                str(excluded.remaining_attempts)
                if excluded.remaining_attempts is not None
                else "-"
            )
            table.add_row(marked_user, excluded.reason, badpwd_str, remaining_str)
        print_table(table)
        if len(eligibility.excluded_users) > len(preview):
            print_info_verbose(
                f"Excluded users total: {len(eligibility.excluded_users)} "
                f"(showing first {len(preview)})."
            )


def _show_lockout_policy_prompt(
    *,
    domain: str,
    eligibility: SprayEligibilityResult,
    prompt_text: str,
    default_confirm: bool = False,
) -> bool:
    """Show lockout policy UX and optionally prompt for confirmation.

    Returns:
        True if execution should continue, False if it should stop.
    """
    marked_domain = mark_sensitive(domain, "domain")
    if eligibility.lockout_threshold is None and any(
        "no lockout enforced" in note.lower() for note in eligibility.notes
    ):
        info_lines = [
            "[bold green]No account lockout enforced[/bold green]",
            f"Domain: {marked_domain}",
            "The domain reports no lockout threshold.",
            "Spraying attempts will not lock accounts, but proceed responsibly.",
        ]
        print_panel(
            "\n".join(info_lines),
            title="[bold green]Lockout Policy[/bold green]",
            border_style="green",
            expand=False,
        )
        return True

    warning_lines = [
        "[bold red]Lockout threshold unavailable[/bold red]",
        f"Domain: {marked_domain}",
        "Account lockout policy or BadPwdCount data could not be determined.",
        "Proceeding may lock accounts. It is recommended to wait at least 1 hour "
        "between attempts when the lockout threshold is unknown.",
    ]
    print_panel(
        "\n".join(warning_lines),
        title="[bold red]Caution[/bold red]",
        border_style="red",
        expand=False,
    )
    return bool(
        Confirm.ask(
            prompt_text,
            default=default_confirm,
        )
    )


def ask_for_spraying(shell: SprayShell, domain: str) -> None:
    """Prompt user to perform password spraying on a domain."""
    if shell.domains_data[domain]["auth"] == "pwned":
        return

    workspace_cwd = shell.current_workspace_dir or os.getcwd()
    kerberos_path = domain_subpath(
        workspace_cwd, shell.domains_dir, domain, shell.kerberos_dir
    )

    if not os.path.exists(kerberos_path):
        os.makedirs(kerberos_path)

    ux_state = _get_spraying_ux_state(shell, domain)
    ux_state["prompted"] = True
    _capture_spraying_ux_event(shell, "ctf_spraying_prompt_shown", domain)

    marked_domain = mark_sensitive(domain, "domain")
    marked_auth_1 = mark_sensitive(shell.domains_data[domain]["auth"], "domain")
    wants_spraying = Confirm.ask(
        f"Do you want to perform password spraying on domain {marked_domain} using a {marked_auth_1} session?",
        default=True,
    )
    if wants_spraying:
        if shell.domains_data[domain]["auth"] == "auth":
            shell.ask_for_pass_policy(domain)
        do_spraying(shell, domain)
        return

    if str(getattr(shell, "type", "") or "").strip().lower() == "ctf":
        ux_state["initial_declined"] = True
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            f"You skipped spraying for {marked_domain}. In many CTF labs this is a key foothold step."
        )
        skip_confirmed = Confirm.ask(
            "Skip CTF spraying checks for now?",
            default=False,
        )
        if not skip_confirmed:
            ux_state["decline_override"] = True
            _capture_spraying_ux_event(
                shell,
                "ctf_spraying_decline_override",
                domain,
            )
            if shell.domains_data[domain]["auth"] == "auth":
                shell.ask_for_pass_policy(domain)
            do_spraying(shell, domain)
            return

        _capture_spraying_ux_event(shell, "ctf_spraying_skipped", domain)
        maybe_show_ctf_spraying_recommendation(
            shell,
            domain,
            reason="ask_for_spraying_declined",
        )


def do_spraying(shell: SprayShell, domain: str) -> None:
    """
    Performs password spraying on the specified domain.

    This method displays a menu to select the type of spraying to perform on the specified domain.
    The available options are:

    1. Username as password in lowercase
    2. Username as password (First letter uppercase)
    3. Username with a specific password

    If the domain uses credential-based authentication, the user's credentials will be requested.
    If the domain uses Kerberos authentication, the domain's PDC will be used for spraying.

    After selecting an option, the method executes the corresponding command and
    saves the result to a log file in the domain directory.

    Args:
        shell: The shell instance with spraying capabilities.
        domain: The domain in which to perform spraying.
    """
    if not getattr(shell, "kerbrute_path", None):
        print_error(
            "kerbrute is not installed. Please run 'adscan install' to install it."
        )
        return

    # Professional password spraying header
    from adscan_internal import print_operation_header
    from adscan_internal.cli.kerberos import ensure_kerberos_output_dir

    pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")
    auth_type = shell.domains_data.get(domain, {}).get("auth", "N/A")
    print_operation_header(
        "Password Spraying Attack",
        details={
            "Domain": domain,
            "PDC": pdc,
            "Authentication Type": auth_type.upper(),
            "Protocol": "Kerberos Pre-Authentication",
        },
        icon="💦",
    )

    # Ensure kerberos output directory exists for spray logs
    ensure_kerberos_output_dir(shell, domain)

    auth_state = str(shell.domains_data[domain].get("auth", "")).strip().lower()
    requires_auth_users = auth_state in {"auth", "pwned"}
    user_list_file = get_spraying_user_list_path(
        shell,
        domain,
        requires_auth_users=requires_auth_users,
    )
    if not user_list_file:
        return

    options = [
        "Username as password",
        "Username as password in lowercase",
        "Username as password in uppercase",
        "Username with a specific password",
    ]
    workspace_cwd = shell.current_workspace_dir or os.getcwd()
    if has_enabled_computer_list(workspace_cwd, shell.domains_dir, domain):
        options.append("Computer accounts (pre2k: hostname as password)")

    ctf_mode = str(getattr(shell, "type", "") or "").strip().lower() == "ctf"
    default_idx = 0
    if ctf_mode:
        pre2k_idx = next(
            (idx for idx, opt in enumerate(options) if "pre2k" in opt), None
        )
        if pre2k_idx is not None:
            default_idx = pre2k_idx
            print_info(
                "CTF recommendation: try Computer accounts (pre2k) first when available."
            )
        else:
            print_info(
                "CTF recommendation: try Username-as-password spraying as an early foothold check."
            )

    if not shell.do_sync_clock_with_pdc(domain, verbose=True):
        return

    current_row = shell._questionary_select(
        f"Select a type of spraying from domain {domain}:",
        options,
        default_idx=default_idx,
    )
    if current_row is None:
        print_warning("Spraying cancelled by user")
        if ctf_mode:
            maybe_show_ctf_spraying_recommendation(
                shell,
                domain,
                reason="spraying_menu_cancelled",
            )
        return

    is_auth = shell.domains_data[domain]["auth"] == "auth"
    pdc_ip = shell.domains_data[domain]["pdc"]
    safe_threshold = 2 if is_auth else 0

    # Confirm repeating sprays before doing heavier eligibility checks.
    spray_password: str | None = None
    spray_category: str
    user_transform: str | None = None
    user_as_pass = True

    if current_row == 0:
        spray_category = "useraspass"
    elif current_row == 1:
        spray_category = "useraspass_lower"
        user_transform = "lower"
    elif current_row == 2:
        spray_category = "useraspass_upper"
        user_transform = "capitalize"
    elif current_row == 3:
        spray_password = Prompt.ask("Enter the password for spraying")
        spray_category = "password"
        user_as_pass = False
    elif current_row == 4 and len(options) == 5:
        spray_category = "computer_pre2k"
        user_as_pass = False
    else:
        print_error(f"Invalid option selected: {current_row}")
        return

    if spray_category == "computer_pre2k":
        _capture_spraying_ux_event(
            shell,
            "ctf_pre2k_selected" if ctf_mode else "spraying_pre2k_selected",
            domain,
        )
        do_computer_pre2k_spraying(shell, domain)
        return

    if not should_proceed_with_repeated_spraying(
        shell, domain, spray_category, spray_password
    ):
        print_info("Password spraying cancelled by user.")
        return

    eligibility = compute_spraying_eligibility(
        shell,
        domain=domain,
        user_list_file=user_list_file,
        safe_threshold=safe_threshold,
    )
    if eligibility is None:
        return

    if (shell.domains_data[domain]["auth"] != "auth") or (
        not eligibility.used_policy_data
    ):
        print_info_debug("[eligibility] Lockout data unavailable; showing policy UX.")
        default_mode = shell.type == "ctf"
        if not _show_lockout_policy_prompt(
            domain=domain,
            eligibility=eligibility,
            prompt_text="Continue with spraying using the full user list?",
            default_confirm=default_mode,
        ):
            print_info("Password spraying cancelled by user.")
            return

    print_spraying_eligibility(shell, domain, eligibility)

    if not eligibility.eligible_users:
        print_warning(
            "No eligible users available for spraying with the current safety rules."
        )
        return

    # Transform usernames for the spraying mode when using user-as-pass.
    eligible_for_kerbrute = list(eligibility.eligible_users)
    if user_as_pass and user_transform:
        if user_transform == "lower":
            eligible_for_kerbrute = [u.lower() for u in eligible_for_kerbrute]
        elif user_transform == "capitalize":
            eligible_for_kerbrute = [u.capitalize() for u in eligible_for_kerbrute]

    kerberos_output_dir = ensure_kerberos_output_dir(shell, domain)
    temp_users_path = write_temp_users_file(
        eligible_for_kerbrute, directory=kerberos_output_dir
    )

    try:
        if is_auth:
            password_fragment = (
                safe_log_filename_fragment(spray_password) if spray_password else None
            )
            output_file = os.path.join(
                "domains",
                domain,
                "kerberos",
                (
                    "auth_spray.log"
                    if spray_category == "useraspass"
                    else "auth_spray_low.log"
                    if spray_category == "useraspass_lower"
                    else "auth_spray_up.log"
                    if spray_category == "useraspass_upper"
                    else f"auth_spray_{password_fragment}.log"
                ),
            )
        else:
            password_fragment = (
                safe_log_filename_fragment(spray_password) if spray_password else None
            )
            output_file = os.path.join(
                "domains",
                domain,
                "kerberos",
                (
                    "unauth_spray.log"
                    if spray_category == "useraspass"
                    else "unauth_spray_low.log"
                    if spray_category == "useraspass_lower"
                    else "unauth_spray_up.log"
                    if spray_category == "useraspass_upper"
                    else f"unauth_spray_{password_fragment}.log"
                ),
            )

        kerbrute_cmd = build_kerbrute_command(
            kerbrute_path=shell.kerbrute_path,
            domain=domain,
            dc_ip=pdc_ip,
            users_file=temp_users_path,
            output_file=output_file,
            password=spray_password,
            user_as_pass=user_as_pass,
        )
        spray_type = (
            "Username as Password"
            if spray_category == "useraspass"
            else "Username as Password (lowercase)"
            if spray_category == "useraspass_lower"
            else "Username as Password (uppercase)"
            if spray_category == "useraspass_upper"
            else "Custom Password"
        )
        if spray_category in _RECOMMENDED_SPRAY_CATEGORIES:
            _mark_recommended_spraying_attempt(shell, domain, spray_category)
            _capture_spraying_ux_event(
                shell,
                "ctf_recommended_spraying_started"
                if ctf_mode
                else "spraying_recommended_started",
                domain,
                extra={"category": spray_category, "spray_type": spray_type},
            )
        spraying_command(shell, kerbrute_cmd, domain, spray_type=spray_type)
    finally:
        try:
            os.remove(temp_users_path)
        except OSError:
            pass


def spraying_with_password(
    shell: SprayShell,
    domain: str,
    password: str,
    *,
    source_context: dict[str, object] | None = None,
) -> None:
    """
    Performs password spraying on the specified domain using a specific password.

    This is a simplified version of do_spraying that directly uses the provided password
    without showing a menu.

    Args:
        shell: The shell instance with spraying capabilities.
        domain: The domain in which to perform spraying.
        password: The password to use for spraying.
    """
    from adscan_internal.cli.kerberos import ensure_kerberos_output_dir

    if not getattr(shell, "kerbrute_path", None):
        print_error(
            "kerbrute is not installed. Please run 'adscan install' to install it."
        )
        return

    # Ensure kerberos output directory exists for spray logs
    ensure_kerberos_output_dir(shell, domain)

    marked_domain = mark_sensitive(domain, "domain")
    auth_mode = shell.domains_data.get(domain, {}).get("auth")
    print_info_debug(
        f"[spray] Starting spraying_with_password for {marked_domain} "
        f"(auth={auth_mode!r}, kerbrute_path={shell.kerbrute_path})"
    )

    auth_state = str(shell.domains_data[domain].get("auth", "")).strip().lower()
    requires_auth_users = auth_state in {"auth", "pwned"}
    user_list_file = get_spraying_user_list_path(
        shell,
        domain,
        requires_auth_users=requires_auth_users,
    )
    if not user_list_file:
        print_info_debug(
            f"[spray] Aborting spraying_with_password for {marked_domain}: no user list available"
        )
        return

    if not shell.do_sync_clock_with_pdc(domain, verbose=True):
        print_info_debug(
            f"[spray] Aborting spraying_with_password for {marked_domain}: clock sync failed"
        )
        return

    # Check for repeated spraying with the same password in this domain
    if not should_proceed_with_repeated_spraying(shell, domain, "password", password):
        print_info("Password spraying cancelled by user.")
        print_info_debug(
            f"[spray] Aborting spraying_with_password for {marked_domain}: repeated spraying not approved"
        )
        return

    marked_password = mark_sensitive(password, "password")
    print_info(
        f"Performing password spraying on domain {marked_domain} with {marked_password} password..."
    )

    eligibility = compute_spraying_eligibility(
        shell,
        domain=domain,
        user_list_file=user_list_file,
        safe_threshold=2 if shell.domains_data[domain]["auth"] == "auth" else 0,
    )
    if eligibility is None:
        return
    print_spraying_eligibility(shell, domain, eligibility)
    file_users = list(eligibility.eligible_users)

    kerberos_output_dir = ensure_kerberos_output_dir(shell, domain)
    temp_users_path = write_temp_users_file(file_users, directory=kerberos_output_dir)
    try:
        output_file = os.path.join(
            "domains",
            domain,
            "kerberos",
            f"{'auth' if shell.domains_data[domain]['auth'] == 'auth' else 'unauth'}_spray_"
            f"{safe_log_filename_fragment(password)}.log",
        )
        kerbrute_cmd = build_kerbrute_command(
            kerbrute_path=shell.kerbrute_path,
            domain=domain,
            dc_ip=shell.domains_data[domain]["pdc"],
            users_file=temp_users_path,
            output_file=output_file,
            password=password,
            user_as_pass=False,
        )
        spraying_command(
            shell,
            kerbrute_cmd,
            domain,
            spray_type="Custom Password",
            source_context=source_context,
        )
    finally:
        try:
            os.remove(temp_users_path)
        except OSError:
            pass


def spraying_command(
    shell: SprayShell,
    command: str,
    domain: str,
    *,
    spray_type: str | None = None,
    entry_label: str | None = None,
    source_context: dict[str, object] | None = None,
) -> None:
    """Wrapper for executing spraying command with operation header."""
    # Professional operation header
    from adscan_internal import print_operation_header

    # Determine spray type from command
    resolved_spray_type = spray_type or "Custom Password"
    if spray_type is None:
        if "--user-as-pass" in command:
            if "spray_low" in command:
                resolved_spray_type = "Username as Password (lowercase)"
            elif "spray_up" in command:
                resolved_spray_type = "Username as Password (uppercase)"
            else:
                resolved_spray_type = "Username as Password"
        elif "bruteforce" in command:
            resolved_spray_type = "Bruteforce"

    print_operation_header(
        "Password Spraying Attack",
        details={
            "Domain": domain,
            "Spray Type": resolved_spray_type,
            "User List": "Domain Users",
            "PDC": shell.domains_data[domain].get("pdc", "N/A"),
        },
        icon="💧",
    )

    print_info_debug(f"Command: {command}")
    execute_spraying_command(
        shell,
        command,
        domain,
        spray_type=resolved_spray_type,
        entry_label=entry_label,
        source_context=source_context,
    )


def execute_spraying_command(
    shell: SprayShell,
    command: str,
    domain: str,
    *,
    spray_type: str | None = None,
    entry_label: str | None = None,
    source_context: dict[str, object] | None = None,
) -> None:
    """Execute the spraying command and process results."""
    import sys

    from adscan_internal.cli.common import SECRET_MODE
    from adscan_internal.rich_output import BRAND_COLORS, print_panel
    from adscan_internal.services.credential_store_service import CredentialStoreService
    from adscan_internal.workspaces import domain_subpath

    from adscan_internal.services.attack_graph_service import (
        upsert_password_spray_entry_edge,
        upsert_share_password_entry_edge,
    )
    from adscan_internal.cli.attack_path_execution import (
        offer_attack_paths_for_execution_for_principals,
    )
    from rich.prompt import Confirm
    from rich.table import Table
    from rich.text import Text

    marked_domain = mark_sensitive(domain, "domain")
    print_warning(
        f"Performing the spraying on {marked_domain}. Please be patient (this can take a while)"
    )

    try:
        # Use run_command instead of spawn_command to avoid output interleaving
        # run_command automatically handles clean_env and provides better error handling
        use_clean_env = command_string_needs_clean_env(command)
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            f"[spray] Executing spraying command with "
            f"use_clean_env={use_clean_env} on domain {marked_domain}"
        )

        completed_process = shell.run_command(
            command,
            timeout=None,  # No timeout for spraying (can take a long time)
            shell=True,
            capture_output=True,
            text=True,
            use_clean_env=use_clean_env,
        )

        if completed_process is None:
            print_error("Failed to execute password spraying command")
            return

        # Process output after command completes (avoids interleaving)
        raw_output = completed_process.stdout or ""
        raw_stderr_output = completed_process.stderr or ""
        output = strip_ansi_codes(raw_output)
        stderr_output = strip_ansi_codes(raw_stderr_output)
        output_lines = output.splitlines() if output else []

        hits_by_user: dict[str, dict[str, str]] = {}
        is_interactive = bool(
            sys.stdin.isatty() and not (os.getenv("CI") or os.getenv("GITHUB_ACTIONS"))
        )

        # Process output to find valid logins (batch).
        for line in output_lines:
            line_stripped = line.strip()
            if not line_stripped:
                continue

            if "VALID LOGIN" not in line_stripped:
                continue

            try:
                creds = line_stripped.split("VALID LOGIN:")[1].strip()
                user_domain, password = creds.split(":", 1)
                username = user_domain.split("@")[0].strip()
                if not username:
                    continue
                key = username.lower()
                hits_by_user.setdefault(
                    key, {"username": username, "password": password}
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_warning_debug("[spray] Failed to parse a VALID LOGIN line.")
                continue

        found_credentials = bool(hits_by_user)
        from adscan_internal.services.share_credential_provenance_service import (
            ShareCredentialProvenanceService,
        )

        share_provenance_service = ShareCredentialProvenanceService()
        share_edge_payload = share_provenance_service.build_share_password_edge_payload(
            source_context=source_context,
            spray_type=spray_type,
            verified_via="spraying",
        )

        if found_credentials:
            # Always show the raw hits in a succinct way (no passwords).
            table = Table(
                title=Text(
                    "Valid Credentials Found", style=f"bold {BRAND_COLORS['info']}"
                ),
                show_header=True,
                header_style=f"bold {BRAND_COLORS['info']}",
                show_lines=True,
            )
            table.add_column("#", style="dim", width=4, justify="right")
            table.add_column("Username", style="bold")
            table.add_column("Method", style="dim")

            hits = list(hits_by_user.values())
            hits_sorted = sorted(
                hits, key=lambda item: str(item.get("username", "")).lower()
            )
            for idx, hit in enumerate(hits_sorted[:10], start=1):
                user = str(hit.get("username") or "")
                table.add_row(
                    str(idx),
                    mark_sensitive(user, "user"),
                    spray_type or "Password spray",
                )

            if len(hits_sorted) > 10:
                print_warning(
                    f"Showing 10/{len(hits_sorted)} valid credentials. Use `creds show` to see stored credentials."
                )

            print_panel(
                [table],
                title=Text(
                    f"Spraying Results ({len(hits_sorted)} success{'es' if len(hits_sorted) != 1 else ''})",
                    style=f"bold {BRAND_COLORS['info']}",
                ),
                border_style=BRAND_COLORS["info"],
                expand=False,
            )

            # Record provenance edges in the attack graph for each hit.
            spray_type_label = spray_type or "Custom Password"
            should_record_spray_edge = (
                spray_type_label.startswith("Username as Password")
                or spray_type_label == "Computer Pre2k"
            )
            for hit in hits_sorted:
                username = str(hit.get("username") or "")
                password = str(hit.get("password") or "")
                if should_record_spray_edge:
                    try:
                        upsert_password_spray_entry_edge(
                            shell,
                            domain,
                            username=username,
                            password=password,
                            spray_type=spray_type,
                            status="success",
                            entry_label=entry_label or "Domain Users",
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)
                        print_info_debug(
                            "[spray] Failed to record PasswordSpray edge in attack graph (continuing)."
                        )
                if share_edge_payload:
                    try:
                        share_entry_label, share_notes = share_edge_payload
                        upsert_share_password_entry_edge(
                            shell,
                            domain,
                            username=username,
                            entry_label=share_entry_label,
                            status="success",
                            notes=dict(share_notes),
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)
                        print_info_debug(
                            "[spray] Failed to record PasswordInShare edge (continuing)."
                        )

            # Load admin list (best-effort) and decide whether to pivot immediately.
            workspace_cwd = (
                shell._get_workspace_cwd()  # type: ignore[attr-defined]
                if hasattr(shell, "_get_workspace_cwd")
                else (getattr(shell, "current_workspace_dir", None) or os.getcwd())
            )
            admins_file = domain_subpath(
                str(workspace_cwd), shell.domains_dir, domain, "admins.txt"
            )
            admin_users: set[str] = set()
            try:
                if os.path.exists(admins_file):
                    with open(
                        admins_file, "r", encoding="utf-8", errors="ignore"
                    ) as fh:
                        admin_users = {
                            strip_ansi_codes(line).strip().lower()
                            for line in fh
                            if line.strip()
                        }
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_info_debug("[spray] Failed to load admins.txt (continuing).")

            admin_hits = [
                hit
                for hit in hits_sorted
                if str(hit.get("username") or "").lower() in admin_users
            ]

            store = CredentialStoreService()

            if admin_hits:
                admin_table = Table(
                    title=Text(
                        "Administrator Credentials Detected",
                        style=f"bold {BRAND_COLORS['warning']}",
                    ),
                    show_header=True,
                    header_style=f"bold {BRAND_COLORS['warning']}",
                    show_lines=True,
                )
                admin_table.add_column("#", style="dim", width=4, justify="right")
                admin_table.add_column("Username", style="bold")

                for idx, hit in enumerate(admin_hits, start=1):
                    user = str(hit.get("username") or "")
                    admin_table.add_row(str(idx), mark_sensitive(user, "user"))

                message = Text()
                message.append(
                    "One or more administrator credentials were found during spraying.\n\n",
                    style="bold yellow",
                )
                message.append(
                    "Pivoting with an admin account is typically the fastest route to domain compromise.\n",
                    style="yellow",
                )

                print_panel(
                    [message, admin_table],
                    title=Text("Privileged Credentials Found", style="bold yellow"),
                    border_style="yellow",
                    expand=False,
                )

                pivot_now = (
                    Confirm.ask(
                        "Do you want to continue with one of these admin users now?",
                        default=True,
                    )
                    if is_interactive
                    else False
                )

                if pivot_now:
                    # Store all non-selected credentials silently (no verification prompts).
                    selected = admin_hits[0]
                    if len(admin_hits) > 1 and hasattr(shell, "_questionary_select"):
                        options = [
                            str(hit.get("username") or "") for hit in admin_hits
                        ] + ["Cancel"]
                        selected_idx = shell._questionary_select(
                            "Select an admin user to continue with:",
                            options,
                            default_idx=0,
                        )
                        if selected_idx is None or selected_idx >= len(options) - 1:
                            selected = admin_hits[0]
                        else:
                            selected = admin_hits[selected_idx]

                    selected_user = str(selected.get("username") or "")
                    selected_pass = str(selected.get("password") or "")

                    for hit in hits_sorted:
                        user = str(hit.get("username") or "")
                        if user.lower() == selected_user.lower():
                            continue
                        store.update_domain_credential(
                            domains_data=shell.domains_data,
                            domain=domain,
                            username=user,
                            credential=str(hit.get("password") or ""),
                            is_hash=False,
                        )

                    shell.add_credential(domain, selected_user, selected_pass)
                    return

            # Default flow: store all credentials silently, then offer attack paths for these principals.
            for hit in hits_sorted:
                user = str(hit.get("username") or "")
                store.update_domain_credential(
                    domains_data=shell.domains_data,
                    domain=domain,
                    username=user,
                    credential=str(hit.get("password") or ""),
                    is_hash=False,
                )

            principals = [str(hit.get("username") or "") for hit in hits_sorted]
            executed = offer_attack_paths_for_execution_for_principals(
                shell,
                domain,
                max_display=20,
                principals=principals,
                max_depth=10,
                include_all=False,
            )
            if not executed:
                marked_domain = mark_sensitive(domain, "domain")
                print_warning(
                    f"No attack paths found from sprayed users to high-value targets in {marked_domain}."
                )
                print_info_verbose(
                    "Tip: use `attack_paths <domain> owned --all` to include non-high-value targets."
                )
                if is_interactive or hasattr(shell, "_questionary_select"):
                    selection: list[dict[str, str]] = []
                    if len(hits_sorted) == 1:
                        only_hit = hits_sorted[0]
                        if hasattr(shell, "_questionary_select"):
                            choice_idx = shell._questionary_select(
                                "No attack paths found. Enumerate this user now?",
                                ["Enumerate user", "Skip"],
                                default_idx=0,
                            )
                            if choice_idx == 0:
                                selection = [only_hit]
                        else:
                            prompt = (
                                "Do you want to enumerate this user now "
                                f"({mark_sensitive(str(only_hit.get('username') or ''), 'user')})?"
                            )
                            if Confirm.ask(prompt, default=True):
                                selection = [only_hit]
                    else:
                        options = [
                            "All users",
                            "Select one user",
                            "Select multiple users",
                            "Skip",
                        ]
                        if hasattr(shell, "_questionary_select"):
                            choice_idx = shell._questionary_select(
                                "No attack paths found. Choose users to enumerate now:",
                                options,
                                default_idx=0,
                            )
                        else:
                            choice_idx = (
                                0
                                if Confirm.ask(
                                    "No attack paths found. Enumerate all users now?",
                                    default=False,
                                )
                                else 3
                            )

                        if choice_idx == 0:
                            selection = hits_sorted
                        elif choice_idx == 1:
                            user_options = [
                                str(hit.get("username") or "") for hit in hits_sorted
                            ] + ["Cancel"]
                            if hasattr(shell, "_questionary_select"):
                                idx = shell._questionary_select(
                                    "Select a user to enumerate:",
                                    user_options,
                                    default_idx=0,
                                )
                                if idx is not None and idx < len(user_options) - 1:
                                    selection = [hits_sorted[idx]]
                        elif choice_idx == 2:
                            user_options = ["All users"] + [
                                str(hit.get("username") or "") for hit in hits_sorted
                            ]
                            if hasattr(shell, "_questionary_checkbox"):
                                selected_values = shell._questionary_checkbox(
                                    "Select users to enumerate:",
                                    user_options,
                                )
                                if (
                                    isinstance(selected_values, list)
                                    and selected_values
                                ):
                                    if "All users" in selected_values:
                                        selection = hits_sorted
                                    else:
                                        requested = {
                                            str(item).strip().lower()
                                            for item in selected_values
                                            if str(item).strip()
                                        }
                                        selection = [
                                            hit
                                            for hit in hits_sorted
                                            if str(hit.get("username") or "").lower()
                                            in requested
                                        ]
                            if not selection:
                                print_warning(
                                    "Multi-select prompt cancelled. Please choose a single user instead."
                                )
                                user_options = [
                                    str(hit.get("username") or "")
                                    for hit in hits_sorted
                                ] + ["Cancel"]
                                if hasattr(shell, "_questionary_select"):
                                    idx = shell._questionary_select(
                                        "Select a user to enumerate:",
                                        user_options,
                                        default_idx=0,
                                    )
                                    if idx is not None and idx < len(user_options) - 1:
                                        selection = [hits_sorted[idx]]

                    if selection:
                        for hit in selection:
                            user = str(hit.get("username") or "")
                            pwd = str(hit.get("password") or "")
                            if not user or not pwd:
                                continue
                            shell.add_credential(
                                domain,
                                user,
                                pwd,
                                prompt_for_user_privs_after=True,
                            )
                    else:
                        auth_state = shell.domains_data.get(domain, {}).get("auth", "")
                        if auth_state not in {"auth", "pwned"} and hits_sorted:
                            first_hit = hits_sorted[0]
                            user = str(first_hit.get("username") or "")
                            pwd = str(first_hit.get("password") or "")
                            if user and pwd:
                                shell.add_credential(
                                    domain,
                                    user,
                                    pwd,
                                    prompt_for_user_privs_after=False,
                                )

        # Handle command result
        if completed_process.returncode != 0:
            print_error(
                f"Password spraying command failed with return code: {completed_process.returncode}"
            )
            # Detailed debug context for troubleshooting spray/kerbrute behaviour
            print_warning_debug(
                f"[spray] Debug context: returncode={completed_process.returncode}, "
                f"use_clean_env={use_clean_env}, stdout_len={len(output)}, "
                f"stderr_len={len(stderr_output)}"
            )

            if output_lines:
                print_warning("Command output (last 20 lines):")
                for line in output_lines[-20:]:
                    print_info_verbose(f"  {line}")
            if stderr_output:
                # Always log stderr in debug mode to aid troubleshooting
                print_warning_debug("[spray] Error output:")
                for line in stderr_output.splitlines():
                    clean_line = strip_ansi_codes(line)
                    print_info_debug(f"[spray][stderr] {clean_line}")
        elif not found_credentials:
            print_warning("No valid credentials found.")
            if output_lines and SECRET_MODE:
                print_info_verbose("Full command output:")
                for line in output_lines:
                    print_info_verbose(f"  {line}")
            elif output_lines:
                # Show summary even in non-SECRET mode
                error_lines = [
                    line
                    for line in output_lines
                    if "error" in line.lower() or "failed" in line.lower()
                ]
                if error_lines:
                    print_warning("Errors detected in output:")
                    for line in error_lines[:5]:  # Show first 5 error lines
                        print_info_verbose(f"  {line}")
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error executing password spraying command.")
        print_exception(show_locals=False, exception=e)


def do_computer_pre2k_spraying(shell: SprayShell, domain: str) -> None:
    """Attempt pre2k password checks for computer accounts (hostname as password)."""
    from adscan_internal import print_operation_header
    from adscan_internal.cli.kerberos import ensure_kerberos_output_dir

    if not getattr(shell, "netexec_path", None):
        print_error(
            "NetExec is not installed or configured. Please run 'adscan install'."
        )
        return
    if not getattr(shell, "kerbrute_path", None):
        print_error(
            "kerbrute is not installed. Please run 'adscan install' to install it."
        )
        return

    marked_domain = mark_sensitive(domain, "domain")
    auth_mode = shell.domains_data.get(domain, {}).get("auth")
    if auth_mode != "auth":
        print_warning(
            f"Computer pre2k checks require an authenticated session for {marked_domain}."
        )
        return

    print_operation_header(
        "Computer Pre2k Check",
        details={
            "Domain": domain,
            "Method": "Kerberos LDAP",
            "Password Pattern": "hostname (lowercase, without $)",
        },
        icon="🖥️",
    )

    computer_sams = _load_enabled_computer_sams(shell, domain)
    if not computer_sams:
        print_warning("No enabled computers available for pre2k checks.")
        return

    if not should_proceed_with_repeated_spraying(shell, domain, "computer_pre2k", None):
        print_info("Computer pre2k check cancelled by user.")
        return

    safe_threshold = 2
    eligibility = compute_computer_spraying_eligibility(
        shell,
        domain=domain,
        computer_sams=computer_sams,
        safe_threshold=safe_threshold,
    )
    if eligibility is None:
        return

    if not eligibility.used_policy_data:
        print_info_debug(
            "[spray] Lockout data unavailable for computer pre2k checks; "
            "showing policy UX."
        )
        if not _show_lockout_policy_prompt(
            domain=domain,
            eligibility=eligibility,
            prompt_text="Continue with computer pre2k checks using the full list?",
            default_confirm=False,
        ):
            print_info("Computer pre2k check cancelled by user.")
            return

    print_spraying_eligibility(shell, domain, eligibility)
    if not eligibility.eligible_users:
        print_warning("No eligible computer accounts available for pre2k checks.")
        return

    summary_lines = [
        f"Domain: {marked_domain}",
        f"Computers in list: {len(eligibility.input_users)}",
        f"Eligible computers: {len(eligibility.eligible_users)}",
        "Password pattern: hostname (lowercase, without $)",
    ]
    print_panel(
        "\n".join(summary_lines),
        title="[bold cyan]Pre2k Scan Plan[/bold cyan]",
        border_style="cyan",
        expand=False,
    )

    pdc_ip = shell.domains_data.get(domain, {}).get("pdc")
    kerberos_output_dir = ensure_kerberos_output_dir(shell, domain)
    combos = [f"{sam}:{sam.rstrip('$').lower()}" for sam in eligibility.eligible_users]
    combos_path = write_temp_combo_file(combos, directory=kerberos_output_dir)

    try:
        output_file = os.path.join(
            "domains",
            domain,
            "kerberos",
            "auth_pre2k_spray.log",
        )
        kerbrute_cmd = build_kerbrute_bruteforce_command(
            kerbrute_path=shell.kerbrute_path,
            domain=domain,
            dc_ip=pdc_ip,
            combos_file=combos_path,
            output_file=output_file,
        )
        _mark_recommended_spraying_attempt(shell, domain, "computer_pre2k")
        _capture_spraying_ux_event(
            shell,
            "ctf_recommended_spraying_started"
            if str(getattr(shell, "type", "") or "").strip().lower() == "ctf"
            else "spraying_recommended_started",
            domain,
            extra={
                "category": "computer_pre2k",
                "spray_type": "Computer Pre2k",
            },
        )
        spraying_command(
            shell,
            kerbrute_cmd,
            domain,
            spray_type="Computer Pre2k",
            entry_label="Domain Computers",
        )
    finally:
        try:
            os.remove(combos_path)
        except OSError:
            pass
