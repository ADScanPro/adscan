"""Secretsdump CLI orchestration helpers.

This module contains all Impacket secretsdump execution and output processing
operations, regardless of the context (DCSync, registry dumps, etc.).

Scope:
- Execute secretsdump commands
- Parse secretsdump output to extract credentials
- Handle secretsdump errors and retries
- Filter and store extracted credentials

These helpers keep command execution and output processing out of the monolithic
`adscan.py` while delegating credential storage and shell-specific operations
to the existing methods on the interactive shell.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple
import os
import re

from adscan_internal import (
    print_error,
    print_exception,
    print_info,
    print_info_debug,
    print_info_table,
    print_success,
    print_warning,
    print_warning_debug,
    telemetry,
)
from adscan_internal.rich_output import mark_sensitive, print_panel
from rich.prompt import Confirm

# DCSync All UX thresholds (compact output in large environments).
_DCSYNC_ALL_LARGE_THRESHOLD = 250
_DCSYNC_ALL_HUGE_THRESHOLD = 1000
_DCSYNC_ALL_CRACKED_PREVIEW_DEFAULT = 15
_DCSYNC_ALL_CRACKED_PREVIEW_LARGE = 8
_DCSYNC_ALL_UNCRACKED_TABLE_MAX = 10


def _get_positive_int_env(name: str, default: int) -> int:
    """Return a positive integer env value or the provided default."""
    raw_value = os.getenv(name, "").strip()
    if not raw_value:
        return default
    try:
        parsed = int(raw_value)
    except ValueError:
        return default
    return parsed if parsed > 0 else default


def _resolve_dcsync_all_ui_thresholds() -> dict[str, int]:
    """Resolve DCSync-All UX thresholds from environment variables."""
    large_threshold = _get_positive_int_env(
        "ADSCAN_DCSYNC_ALL_LARGE_THRESHOLD",
        _DCSYNC_ALL_LARGE_THRESHOLD,
    )
    huge_threshold = _get_positive_int_env(
        "ADSCAN_DCSYNC_ALL_HUGE_THRESHOLD",
        _DCSYNC_ALL_HUGE_THRESHOLD,
    )
    if huge_threshold < large_threshold:
        huge_threshold = large_threshold

    cracked_preview_default = _get_positive_int_env(
        "ADSCAN_DCSYNC_ALL_CRACKED_PREVIEW_DEFAULT",
        _DCSYNC_ALL_CRACKED_PREVIEW_DEFAULT,
    )
    cracked_preview_large = _get_positive_int_env(
        "ADSCAN_DCSYNC_ALL_CRACKED_PREVIEW_LARGE",
        _DCSYNC_ALL_CRACKED_PREVIEW_LARGE,
    )
    uncracked_table_max = _get_positive_int_env(
        "ADSCAN_DCSYNC_ALL_UNCRACKED_TABLE_MAX",
        _DCSYNC_ALL_UNCRACKED_TABLE_MAX,
    )

    return {
        "large_threshold": large_threshold,
        "huge_threshold": huge_threshold,
        "cracked_preview_default": cracked_preview_default,
        "cracked_preview_large": cracked_preview_large,
        "uncracked_table_max": uncracked_table_max,
    }


def execute_secretsdump_with_domain(shell: Any, command: str, domain: str) -> None:
    """Execute secretsdump command and extract credentials filtered by domain.

    This function filters credentials to only include those matching the specified
    domain, skipping machine accounts and service accounts.

    Args:
        shell: The active `PentestShell` instance (from `adscan.py`).
        command: Full Impacket secretsdump command to execute.
        domain: Target domain name for credential filtering.
    """
    try:
        completed_process = shell.run_command(command, timeout=300)

        if completed_process.returncode == 0:
            output_decoded = completed_process.stdout
            if not output_decoded:
                print_warning(
                    "secretsdump executed successfully but produced no output."
                )
                return

            # Extract credentials using regular expressions
            cred_matches = re.findall(
                r"(\S+):\d+:[^:]*:([a-f0-9]{32}):", output_decoded
            )

            if cred_matches:
                credentials_added_count = 0
                for user, cred in cred_matches:
                    user = user.strip()

                    if "\\" in user:
                        domain_prefix, username = user.split("\\", 1)
                        if domain_prefix.lower() != domain.lower():
                            # print_info(f"Skipping user {original_user_for_log} from different domain {domain_prefix}")
                            continue
                        user = username
                    elif user.lower() in ["administrator", "administrador"]:
                        pass  # Process with the indicated domain
                    else:
                        # print_info(f"Skipping user {original_user_for_log} as it's not Administrator and lacks domain prefix.")
                        continue  # Skip any user that does not have a domain and is not the exception

                    from adscan_internal.principal_utils import is_machine_account

                    if is_machine_account(user):
                        # print_info(f"Skipping machine account or similar: {user}")
                        continue
                    if (
                        user.startswith("MSOL_")
                        or user.startswith("SM_")
                        or user.startswith("HealthMailbox")
                    ):
                        # print_info(f"Skipping service account: {user}")
                        continue

                    shell.add_credential(domain, user, cred, verify_credential=False)
                    credentials_added_count += 1

                if credentials_added_count > 0:
                    marked_domain = mark_sensitive(domain, "domain")
                    print_success(
                        f"{credentials_added_count} credential(s) successfully extracted and stored for domain {marked_domain}."
                    )
                else:
                    marked_domain = mark_sensitive(domain, "domain")
                    print_warning(
                        f"No suitable credentials found in secretsdump output for domain {marked_domain} after filtering."
                    )
            else:
                marked_domain = mark_sensitive(domain, "domain")
                print_warning(
                    f"No credentials matching the pattern were found in the secretsdump output for domain {marked_domain}."
                )
        else:
            marked_domain = mark_sensitive(domain, "domain")
            print_error(
                f"Error executing secretsdump for domain {marked_domain}. Return code: {completed_process.returncode}"
            )
            error_message = (
                completed_process.stderr.strip()
                if completed_process.stderr
                else completed_process.stdout.strip()
            )
            if error_message:
                print_error(f"Details: {error_message}")
            else:
                print_error("No error output from secretsdump command.")

    except Exception as e:
        telemetry.capture_exception(e)
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"An error occurred during secretsdump execution for domain {marked_domain}: {str(e)}"
        )

        print_exception(exception=e)


def execute_secretsdump(shell: Any, command: str, domain: str) -> None:
    """Execute secretsdump command and extract all credentials from output.

    Run secretsdump, parse every "user:rid:lmhash:nthash" line (with or without
    DOMAIN\\ prefix) and store credentials using shell.add_credential().

    This function handles:
    - DCSync privilege rollback errors
    - Domain prefix trimming for -just-dc-user
    - Retry with -use-vss on errors
    - Hash cracking integration
    - Credential filtering (machine accounts, service accounts, etc.)

    Args:
        shell: The active `PentestShell` instance (from `adscan.py`).
        command: Full Impacket secretsdump command to execute.
        domain: Domain name that will be stored alongside every credential.
    """
    try:
        # ------------------------------------------------------------------ #
        # 1. Launch secretsdump and capture its complete stdout / stderr
        # ------------------------------------------------------------------ #
        completed_process = shell.run_command(command, timeout=300)

        if completed_process.returncode != 0:
            error_message = (
                completed_process.stderr.strip()
                if completed_process.stderr
                else completed_process.stdout.strip()
            )
            print_error(
                f"Error executing credential extraction. Return code: {completed_process.returncode}"
            )
            if error_message:
                print_error(f"Details: {error_message}")
            else:
                print_error("No error output from secretsdump command.")

            return

        error_blob = "\n".join(
            part
            for part in [
                completed_process.stdout or "",
                completed_process.stderr or "",
            ]
            if part
        )
        if "ERROR_DS_DRA_BAD_DN" in error_blob:
            print_warning_debug(
                "Detected ERROR_DS_DRA_BAD_DN during DCSync. "
                "This usually means the account lost replication privileges."
            )
            if shell._handle_dcsync_privilege_rollback(command, domain):
                return

        if (
            "ERROR_DS_NAME_ERROR_NOT_FOUND" in completed_process.stdout
            and "-just-dc-user" in command
        ):
            # Trim domain prefix from just-dc-user argument: keep only username after slash
            command = re.sub(r"-just-dc-user\s+\S+/(\S+)", r"-just-dc-user \1", command)
            print_info("Re-executing secretsdump with trimmed domain prefix")
            print_info_debug(f"Command: {command}")
            execute_secretsdump(shell, command, domain)
            return

        if (
            "Something went wrong" in completed_process.stdout
            and "-just-dc-user" not in command
        ):
            if command.endswith("-use-vss"):
                print_error(
                    "Something went wrong while executing credential extraction. Canceling..."
                )
                return
            print_error(
                "Something went wrong while executing credential extraction. Reattempting with another method..."
            )
            command += " -use-vss"
            execute_secretsdump(shell, command, domain)
            return

        dump: str = completed_process.stdout
        if not dump:
            print_warning(
                "Credential extraction executed successfully but produced no output."
            )
            return

        # ------------------------------------------------------------------ #
        # 2. Extract "user-like-token" and NT-hash from every credential line
        #    ^[^:\r\n]+  -> everything up to first ':' (DOMAIN\\user or user)
        # ------------------------------------------------------------------ #
        cred_matches: List[Tuple[str, str]] = re.findall(
            r"(^[^:\r\n]+):\d+:[^:]*:([a-fA-F0-9]{32}):", dump, flags=re.M
        )

        if not cred_matches:
            marked_domain = mark_sensitive(domain, "domain")
            print_error(
                f"No credentials matching the pattern were found in secretsdump output for domain {marked_domain}."
            )
            print_info_debug(f"Secretsdump output for {domain}:\n{dump}")
            _offer_machine_account_dump_fallback(shell, domain)
            return

        # ------------------------------------------------------------------ #
        # 3. Store every credential, removing DOMAIN\\ prefix from username
        # ------------------------------------------------------------------ #
        raw_credentials: List[Tuple[str, str]] = []
        creds_to_persist: List[Tuple[str, str]] = []
        display_rows: List[Dict[str, str]] = []
        context = getattr(shell, "_current_dcsync_context", None)
        target_user = (
            str(context.get("target_user") or "") if isinstance(context, dict) else ""
        )
        verify_credential = target_user.casefold() != "all"
        for user_token, nt_hash in cred_matches:
            # Apply same blacklist/filtering as in execute_secretsdump_with_domain for consistency
            user_for_filtering = user_token.strip()

            if "\\" in user_for_filtering:
                domain_prefix, username_part = user_for_filtering.split("\\", 1)
                # Optional: Check if domain_prefix matches the target 'domain' if strictness is needed
                # if domain_prefix.lower() != domain.lower():
                #     # print_info(f"Skipping user {original_user_for_log} from different domain {domain_prefix} in execute_secretsdump")
                #     continue
                username = username_part
            elif user_for_filtering.lower() in ["administrator", "administrador"]:
                username = user_for_filtering  # Process with the indicated domain
            else:
                # If no domain prefix and not a known global admin, decide if it should be skipped or associated with current domain
                # For now, assume it's for the current domain if no prefix
                username = user_for_filtering

            # Apply blacklist
            from adscan_internal.principal_utils import is_machine_account

            if is_machine_account(username):  # machine & gMSA accounts often end with $
                # print_info(f"Skipping account ending with $: {username}")
                continue
            if (
                username.startswith("MSOL_")
                or username.startswith("SM_")
                or username.startswith("HealthMailbox")
            ):  # Common service account prefixes
                # print_info(f"Skipping service account with known prefix: {username}")
                continue
            if username.lower() in [
                "guest",
                "invitado",
                "defaultaccount",
            ]:  # Specific accounts to ignore
                # print_info(f"Skipping specific blacklisted account: {username}")
                continue
            # ---------------------------------------------------------------- #

            # Persist the credential using the *provided* domain argument
            if verify_credential:
                marked_domain = mark_sensitive(domain, "domain")
                marked_username = mark_sensitive(username, "user")
                marked_nt_hash = mark_sensitive(nt_hash, "password")
                print_success(
                    f"Found credential: {marked_domain}/{marked_username} with hash {marked_nt_hash}"
                )

            raw_credentials.append((username, nt_hash))

        if verify_credential:
            # Single-user DCSync keeps per-credential cracking/verify behaviour.
            for username, nt_hash in raw_credentials:
                cred_to_store = nt_hash
                try:
                    cred_to_store, _ = shell._handle_hash_cracking(
                        domain, username, nt_hash
                    )
                except Exception:
                    # _handle_hash_cracking already logs/telemeters; keep going.
                    cred_to_store = nt_hash
                creds_to_persist.append((username, cred_to_store))
        else:
            # DCSync "All": process as batch for better performance.
            from adscan_internal.cli.creds import add_credentials_batch

            creds_to_persist = add_credentials_batch(
                shell=shell,
                domain=domain,
                credentials=raw_credentials,
                skip_hash_cracking=False,
                verify_credential=False,
                prompt_for_user_privs_after=False,
                ensure_fresh_kerberos_ticket=False,
                ui_silent=False,
            )
            _render_dcsync_batch_cracking_summary(
                domain=domain,
                credentials=creds_to_persist,
            )

        for username, cred_value in creds_to_persist:
            display_rows.append({"User": username, "Credential": cred_value})

        # Final DCSync summary
        print_success("DCSync completed successfully.")

        count = len(display_rows)
        if count == 0:
            print_info("No credentials were stored for this DCSync run.")
        else:
            print_info(f"Extracted {count} domain credentials.")
            if verify_credential and count <= 10:
                print_info_table(
                    display_rows,
                    ["User", "Credential"],
                    title=f"Extracted credentials for domain {domain}",
                )

            if verify_credential:
                # Persist after showing summary/table to keep output grouped.
                for username, cred_value in creds_to_persist:
                    shell.add_credential(
                        domain,
                        username,
                        cred_value,
                        skip_hash_cracking=True,
                        verify_credential=True,
                    )

    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Error executing secretsdump.")
        print_exception(show_locals=False, exception=exc)


def _offer_machine_account_dump_fallback(shell: Any, domain: str) -> None:
    context = getattr(shell, "_current_dcsync_context", None)
    if not isinstance(context, dict):
        return
    username = str(context.get("username") or "")
    password = str(context.get("password") or "")
    from adscan_internal.principal_utils import is_machine_account

    if not is_machine_account(username):
        return
    auth_state = shell.domains_data.get(domain, {}).get("auth")
    if auth_state == "pwned":
        return
    pdc_host = shell.domains_data.get(domain, {}).get(
        "pdc_hostname"
    ) or shell.domains_data.get(domain, {}).get("pdc")
    if not pdc_host:
        return

    marked_domain = mark_sensitive(domain, "domain")
    marked_user = mark_sensitive(username, "user")
    prompt = (
        "DCSync did not return credentials. "
        "Attempt SMB SAM/LSA/DPAPI dumps using machine delegation?"
    )
    if not Confirm.ask(prompt, default=True):
        return

    print_panel(
        "\n".join(
            [
                "⚠️  DCSync did not return credentials",
                f"Domain: {marked_domain}",
                f"Machine Account: {marked_user}",
                "Fallback: SMB SAM/LSA/DPAPI dumps with delegation",
            ]
        ),
        title="[bold yellow]DCSync Fallback[/bold yellow]",
        border_style="yellow",
        expand=False,
    )
    print_info_debug("[dcsync] Falling back to SMB dumps with machine delegation.")
    from adscan_internal.cli.dumps import run_dump_dpapi, run_dump_lsa, run_dump_sam

    print_info("Starting SMB SAM dump (delegated)...")
    run_dump_sam(
        shell,
        domain=domain,
        username=username,
        password=password,
        host=str(pdc_host),
        islocal="false",
    )
    if shell.domains_data.get(domain, {}).get("auth") == "pwned":
        return
    print_info("Starting SMB LSA dump (delegated)...")
    run_dump_lsa(
        shell,
        domain=domain,
        username=username,
        password=password,
        host=str(pdc_host),
        islocal="false",
    )
    if shell.domains_data.get(domain, {}).get("auth") == "pwned":
        return
    print_info("Starting SMB DPAPI dump (delegated)...")
    run_dump_dpapi(
        shell,
        domain=domain,
        username=username,
        password=password,
        host=str(pdc_host),
        islocal="false",
    )


def _render_dcsync_batch_cracking_summary(
    *,
    domain: str,
    credentials: list[tuple[str, str]],
) -> None:
    """Render compact cracking summary for DCSync All batch processing."""
    if not credentials:
        return

    cracked_rows: list[dict[str, str]] = []
    uncracked_rows: list[dict[str, str]] = []
    for username, credential in credentials:
        normalized_user = str(username or "").strip()
        normalized_credential = str(credential or "").strip()
        if not normalized_user or not normalized_credential:
            continue
        if re.fullmatch(r"[0-9a-fA-F]{32}", normalized_credential):
            uncracked_rows.append(
                {
                    "User": mark_sensitive(normalized_user, "user"),
                    "Hash": mark_sensitive(normalized_credential, "password"),
                }
            )
        else:
            cracked_rows.append(
                {
                    "User": mark_sensitive(normalized_user, "user"),
                    "Password": mark_sensitive(normalized_credential, "password"),
                }
            )

    total = len(cracked_rows) + len(uncracked_rows)
    summary_rows = [
        {"Metric": "Credentials Extracted", "Count": str(total)},
        {"Metric": "Hashes Cracked", "Count": str(len(cracked_rows))},
        {"Metric": "Hashes Uncracked", "Count": str(len(uncracked_rows))},
    ]
    print_info_table(
        summary_rows,
        ["Metric", "Count"],
        title=f"DCSync Cracking Summary ({mark_sensitive(domain, 'domain')})",
    )

    thresholds = _resolve_dcsync_all_ui_thresholds()
    large_threshold = thresholds["large_threshold"]
    huge_threshold = thresholds["huge_threshold"]
    cracked_preview_default = thresholds["cracked_preview_default"]
    cracked_preview_large = thresholds["cracked_preview_large"]
    uncracked_table_max = thresholds["uncracked_table_max"]

    if total >= huge_threshold:
        print_info(
            "Large environment detected. Showing aggregate results only to keep output concise."
        )
        return

    if total >= large_threshold:
        cracked_preview_limit = cracked_preview_large
    else:
        cracked_preview_limit = cracked_preview_default

    if cracked_rows:
        print_info_table(
            cracked_rows[:cracked_preview_limit],
            ["User", "Password"],
            title="Cracked Credentials",
        )
        if len(cracked_rows) > cracked_preview_limit:
            print_info(
                "Showing first "
                f"{cracked_preview_limit} cracked credentials out of {len(cracked_rows)}."
            )

    if (
        uncracked_rows
        and total < large_threshold
        and len(uncracked_rows) <= uncracked_table_max
    ):
        print_info_table(
            uncracked_rows,
            ["User", "Hash"],
            title="Uncracked Hashes",
        )
    elif uncracked_rows:
        print_info(
            f"Uncracked hashes retained for {len(uncracked_rows)} account(s)."
        )
