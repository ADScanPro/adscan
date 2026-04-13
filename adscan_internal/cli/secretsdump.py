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

from collections import Counter, defaultdict
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
from adscan_internal.integrations.impacket.runner import (
    RunCommandAdapter,
    run_raw_impacket_command,
)
from adscan_internal.rich_output import mark_sensitive, print_panel
from rich.prompt import Confirm

# DCSync All UX thresholds (compact output in large environments).
_DCSYNC_ALL_LARGE_THRESHOLD = 250
_DCSYNC_ALL_HUGE_THRESHOLD = 1000
_DCSYNC_ALL_CRACKED_PREVIEW_DEFAULT = 15
_DCSYNC_ALL_CRACKED_PREVIEW_LARGE = 8
_DCSYNC_ALL_UNCRACKED_TABLE_MAX = 10


def _capture_dcsync_batch_cracking_summary_telemetry(
    shell: Any,
    *,
    domain: str,
    total: int,
    cracked_total: int,
    uncracked_total: int,
    tier0_extracted: int,
    tier0_cracked: int,
    high_value_extracted: int,
    high_value_cracked: int,
    standard_extracted: int,
    standard_cracked: int,
    cracked_reuse_groups: dict[str, list[dict[str, str]]],
    uncracked_reuse_groups: dict[str, list[dict[str, str]]],
) -> None:
    """Emit telemetry for DCSync-All cracking summary analytics.

    Only aggregate counters/ratios are emitted (no credential or user values).
    """
    try:
        from adscan_internal.cli.common import build_lab_event_fields

        cracked_reused_accounts = sum(
            len(rows) for rows in cracked_reuse_groups.values()
        )
        uncracked_reused_accounts = sum(
            len(rows) for rows in uncracked_reuse_groups.values()
        )
        cracked_reuse_largest_group = max(
            (len(rows) for rows in cracked_reuse_groups.values()),
            default=0,
        )
        uncracked_reuse_largest_group = max(
            (len(rows) for rows in uncracked_reuse_groups.values()),
            default=0,
        )
        largest_cracked_group_rows = (
            max(cracked_reuse_groups.values(), key=len)
            if cracked_reuse_groups
            else []
        )
        largest_cracked_group_segment_counts = Counter(
            str(row.get("risk_segment") or "Standard")
            for row in largest_cracked_group_rows
        )

        properties: dict[str, Any] = {
            "domain": domain,
            "workspace_type": getattr(shell, "type", None),
            "auto_mode": getattr(shell, "auto", False),
            "scan_mode": getattr(shell, "scan_mode", None),
            "credentials_extracted": total,
            "hashes_cracked": cracked_total,
            "hashes_uncracked": uncracked_total,
            "hash_crack_rate_pct": round(((cracked_total / total) * 100), 2)
            if total > 0
            else 0.0,
            "tier0_extracted_count": tier0_extracted,
            "tier0_cracked_count": tier0_cracked,
            "tier0_crack_coverage_pct": round(((tier0_cracked / tier0_extracted) * 100), 2)
            if tier0_extracted > 0
            else 0.0,
            "tier0_cracked_pct": round(((tier0_cracked / cracked_total) * 100), 2)
            if cracked_total > 0
            else 0.0,
            "high_value_extracted_count": high_value_extracted,
            "high_value_cracked_count": high_value_cracked,
            "high_value_crack_coverage_pct": round(
                ((high_value_cracked / high_value_extracted) * 100), 2
            )
            if high_value_extracted > 0
            else 0.0,
            "high_value_cracked_pct": round(
                ((high_value_cracked / cracked_total) * 100), 2
            )
            if cracked_total > 0
            else 0.0,
            "standard_extracted_count": standard_extracted,
            "standard_cracked_count": standard_cracked,
            "standard_crack_coverage_pct": round(
                ((standard_cracked / standard_extracted) * 100), 2
            )
            if standard_extracted > 0
            else 0.0,
            "standard_cracked_pct": round(
                ((standard_cracked / cracked_total) * 100), 2
            )
            if cracked_total > 0
            else 0.0,
            "reused_cracked_secret_count": len(cracked_reuse_groups),
            "reused_cracked_accounts_count": cracked_reused_accounts,
            "reused_cracked_accounts_pct": round(
                ((cracked_reused_accounts / cracked_total) * 100), 2
            )
            if cracked_total > 0
            else 0.0,
            "reused_uncracked_hash_count": len(uncracked_reuse_groups),
            "reused_uncracked_accounts_count": uncracked_reused_accounts,
            "reused_cracked_largest_group_size": cracked_reuse_largest_group,
            "reused_uncracked_largest_group_size": uncracked_reuse_largest_group,
            "largest_cracked_reuse_cluster_tier0_count": largest_cracked_group_segment_counts.get(
                "Tier-0", 0
            ),
            "largest_cracked_reuse_cluster_high_value_count": largest_cracked_group_segment_counts.get(
                "High-Value", 0
            ),
            "largest_cracked_reuse_cluster_standard_count": largest_cracked_group_segment_counts.get(
                "Standard", 0
            ),
        }
        properties.update(build_lab_event_fields(shell=shell, include_slug=True))
        telemetry.capture("dcsync_cracking_summary", properties)
    except Exception as exc:  # pragma: no cover - telemetry best effort
        telemetry.capture_exception(exc)
        print_warning_debug(
            f"[dcsync] Failed to emit cracking summary telemetry: {type(exc).__name__}"
        )


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
        completed_process = run_raw_impacket_command(
            command,
            script_name="secretsdump.py",
            timeout=300,
            command_runner=RunCommandAdapter(shell.run_command),
        )
        if completed_process is None:
            print_error("Error executing secretsdump: command did not return output.")
            return

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
        completed_process = run_raw_impacket_command(
            command,
            script_name="secretsdump.py",
            timeout=300,
            command_runner=RunCommandAdapter(shell.run_command),
        )
        if completed_process is None:
            print_error("Error executing credential extraction: command did not return output.")
            return

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
                shell=shell,
                domain=domain,
                credentials=creds_to_persist,
            )
            try:
                created_domain_reuse_edges = _record_dcsync_domain_password_reuse(
                    shell,
                    domain=domain,
                    credentials=raw_credentials,
                )
                if created_domain_reuse_edges > 0:
                    marked_domain = mark_sensitive(domain, "domain")
                    print_info(
                        "Recorded "
                        f"{created_domain_reuse_edges} DomainPassReuse context step(s) "
                        f"from DCSync-All credentials in {marked_domain}."
                    )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                marked_domain = mark_sensitive(domain, "domain")
                print_warning(
                    "Failed to persist DomainPassReuse context steps from DCSync-All "
                    f"credentials in {marked_domain}; continuing."
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
    shell: Any,
    domain: str,
    credentials: list[tuple[str, str]],
) -> None:
    """Render compact cracking summary for DCSync All batch processing."""
    if not credentials:
        return

    cracked_rows: list[dict[str, str]] = []
    uncracked_rows: list[dict[str, str]] = []
    user_values: list[str] = []
    for username, credential in credentials:
        normalized_user = str(username or "").strip()
        normalized_credential = str(credential or "").strip()
        if not normalized_user or not normalized_credential:
            continue
        user_values.append(normalized_user)
        row_base = {
            "raw_user": normalized_user,
            "raw_credential": normalized_credential,
        }
        if re.fullmatch(r"[0-9a-fA-F]{32}", normalized_credential):
            uncracked_rows.append(row_base)
        else:
            cracked_rows.append(row_base)

    risk_map: dict[str, tuple[bool, bool]] = {}

    def normalize_user_for_lookup(value: str) -> str:
        return str(value or "").casefold()

    if user_values:
        try:
            from adscan_internal.services.high_value import (
                classify_users_tier0_high_value,
                normalize_samaccountname,
            )

            normalize_user_for_lookup = normalize_samaccountname
            resolved_risks = classify_users_tier0_high_value(
                shell, domain=domain, usernames=user_values
            )
            risk_map = {
                normalize_user_for_lookup(username): (
                    bool(flags.is_tier0),
                    bool(flags.is_high_value),
                )
                for username, flags in resolved_risks.items()
            }
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning_debug(
                f"[dcsync] Unable to classify cracked users by risk tier: {type(exc).__name__}"
            )

    def _classify_user(user_raw: str) -> tuple[bool, bool]:
        normalized = normalize_user_for_lookup(user_raw)
        return risk_map.get(normalized, (False, False))

    def _risk_segment_for_user(user_raw: str) -> str:
        is_tier0_user, is_high_value_user = _classify_user(user_raw)
        if is_tier0_user:
            return "Tier-0"
        if is_high_value_user:
            return "High-Value"
        return "Standard"

    for row in cracked_rows:
        row["risk_segment"] = _risk_segment_for_user(row["raw_user"])
        row["User"] = mark_sensitive(str(row["raw_user"]), "user")
        row["Password"] = mark_sensitive(str(row["raw_credential"]), "password")
    for row in uncracked_rows:
        row["risk_segment"] = _risk_segment_for_user(row["raw_user"])
        row["User"] = mark_sensitive(str(row["raw_user"]), "user")
        row["Hash"] = mark_sensitive(str(row["raw_credential"]), "password")

    cracked_total = len(cracked_rows)
    uncracked_total = len(uncracked_rows)
    extracted_by_segment = Counter(
        row["risk_segment"] for row in [*cracked_rows, *uncracked_rows]
    )
    cracked_by_segment = Counter(row["risk_segment"] for row in cracked_rows)
    tier0_extracted = int(extracted_by_segment.get("Tier-0", 0))
    high_value_extracted = int(extracted_by_segment.get("High-Value", 0))
    standard_extracted = int(extracted_by_segment.get("Standard", 0))
    tier0_cracked = int(cracked_by_segment.get("Tier-0", 0))
    high_value_cracked = int(cracked_by_segment.get("High-Value", 0))
    standard_cracked = int(cracked_by_segment.get("Standard", 0))

    def _format_count_and_percent(count: int, denominator: int) -> str:
        if denominator <= 0:
            return str(count)
        return f"{count} ({(count / denominator) * 100:.1f}%)"

    def _format_percent(count: int, denominator: int) -> str:
        if denominator <= 0:
            return "0.0%"
        return f"{(count / denominator) * 100:.1f}%"

    def _format_ratio_with_percent(count: int, denominator: int) -> str:
        return f"{count}/{denominator} ({_format_percent(count, denominator)})"

    def _build_reuse_groups(
        rows: list[dict[str, str]],
    ) -> dict[str, list[dict[str, str]]]:
        grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
        for row in rows:
            grouped[str(row["raw_credential"])].append(row)
        return {value: users for value, users in grouped.items() if len(users) > 1}

    cracked_reuse_groups = _build_reuse_groups(cracked_rows)
    uncracked_reuse_groups = _build_reuse_groups(uncracked_rows)
    cracked_reused_accounts = sum(len(rows) for rows in cracked_reuse_groups.values())
    uncracked_reused_accounts = sum(
        len(rows) for rows in uncracked_reuse_groups.values()
    )
    largest_cracked_reuse_cluster_size = max(
        (len(rows) for rows in cracked_reuse_groups.values()),
        default=0,
    )

    total = len(cracked_rows) + len(uncracked_rows)
    summary_rows = [
        {"Metric": "Credentials Extracted", "Count": str(total)},
        {
            "Metric": "Hashes Cracked",
            "Count": _format_count_and_percent(cracked_total, total),
        },
        {
            "Metric": "Hashes Uncracked",
            "Count": _format_count_and_percent(uncracked_total, total),
        },
        {
            "Metric": "Tier-0 Cracked (share of cracked)",
            "Count": _format_count_and_percent(tier0_cracked, cracked_total),
        },
        {"Metric": "Tier-0 Extracted", "Count": str(tier0_extracted)},
        {
            "Metric": "Tier-0 Crack Coverage",
            "Count": _format_ratio_with_percent(tier0_cracked, tier0_extracted),
        },
        {
            "Metric": "High-Value Cracked (share of cracked)",
            "Count": _format_count_and_percent(high_value_cracked, cracked_total),
        },
        {"Metric": "High-Value Extracted", "Count": str(high_value_extracted)},
        {
            "Metric": "High-Value Crack Coverage",
            "Count": _format_ratio_with_percent(
                high_value_cracked, high_value_extracted
            ),
        },
        {
            "Metric": "Standard Cracked (share of cracked)",
            "Count": _format_count_and_percent(standard_cracked, cracked_total),
        },
        {"Metric": "Standard Extracted", "Count": str(standard_extracted)},
        {
            "Metric": "Standard Crack Coverage",
            "Count": _format_ratio_with_percent(standard_cracked, standard_extracted),
        },
        {
            "Metric": "Reused Cracked Passwords",
            "Count": (
                f"{len(cracked_reuse_groups)} secret(s), {cracked_reused_accounts} account(s)"
            ),
        },
        {
            "Metric": "Cracked Accounts Using Reused Passwords",
            "Count": _format_count_and_percent(cracked_reused_accounts, cracked_total),
        },
        {
            "Metric": "Largest Reuse Cluster (Cracked)",
            "Count": f"{largest_cracked_reuse_cluster_size} account(s)",
        },
        {
            "Metric": "Reused Uncracked Hashes",
            "Count": (
                f"{len(uncracked_reuse_groups)} hash(es), {uncracked_reused_accounts} account(s)"
            ),
        },
    ]
    _capture_dcsync_batch_cracking_summary_telemetry(
        shell,
        domain=domain,
        total=total,
        cracked_total=cracked_total,
        uncracked_total=uncracked_total,
        tier0_extracted=tier0_extracted,
        tier0_cracked=tier0_cracked,
        high_value_extracted=high_value_extracted,
        high_value_cracked=high_value_cracked,
        standard_extracted=standard_extracted,
        standard_cracked=standard_cracked,
        cracked_reuse_groups=cracked_reuse_groups,
        uncracked_reuse_groups=uncracked_reuse_groups,
    )
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
        segment_breakdown_rows = []
        for segment in ("Tier-0", "High-Value", "Standard"):
            extracted_count = int(extracted_by_segment.get(segment, 0))
            cracked_count = int(cracked_by_segment.get(segment, 0))
            uncracked_count = max(extracted_count - cracked_count, 0)
            segment_breakdown_rows.append(
                {
                    "Segment": segment,
                    "Extracted": str(extracted_count),
                    "Cracked": str(cracked_count),
                    "Uncracked": str(uncracked_count),
                    "Crack Rate": _format_percent(cracked_count, extracted_count),
                    "Share of Cracked": _format_percent(cracked_count, cracked_total),
                }
            )
        print_info_table(
            segment_breakdown_rows,
            [
                "Segment",
                "Extracted",
                "Cracked",
                "Uncracked",
                "Crack Rate",
                "Share of Cracked",
            ],
            title="Cracked Privilege Breakdown",
        )
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

    reuse_rows: list[dict[str, str]] = []

    def _append_reuse_rows(
        *,
        secret_label: str,
        groups: dict[str, list[dict[str, str]]],
    ) -> None:
        ordered = sorted(
            groups.items(),
            key=lambda item: (-len(item[1]), str(item[0]).casefold()),
        )
        for secret_value, rows in ordered[:5]:
            segment_counts = Counter(str(row.get("risk_segment") or "Standard") for row in rows)
            reuse_rows.append(
                {
                    "Secret Type": secret_label,
                    "Secret": mark_sensitive(str(secret_value), "password"),
                    "Accounts": str(len(rows)),
                    "Tier-0": str(segment_counts.get("Tier-0", 0)),
                    "High-Value": str(segment_counts.get("High-Value", 0)),
                    "Standard": str(segment_counts.get("Standard", 0)),
                }
            )

    _append_reuse_rows(secret_label="Password", groups=cracked_reuse_groups)
    _append_reuse_rows(secret_label="Hash", groups=uncracked_reuse_groups)

    if reuse_rows:
        print_info_table(
            reuse_rows,
            ["Secret Type", "Secret", "Accounts", "Tier-0", "High-Value", "Standard"],
            title="Top Reused Secrets",
        )


def _record_dcsync_domain_password_reuse(
    shell: Any,
    *,
    domain: str,
    credentials: list[tuple[str, str]],
) -> int:
    """Record DomainPassReuse context edges from DCSync-All credential material."""
    from adscan_internal.services.attack_graph_service import (
        upsert_domain_password_reuse_edges,
    )

    grouped: dict[str, dict[str, object]] = {}
    for username, credential in credentials:
        user_clean = str(username or "").strip()
        credential_clean = str(credential or "").strip()
        if not user_clean or not credential_clean:
            continue
        key = credential_clean.lower()
        bucket = grouped.setdefault(
            key,
            {"credential": credential_clean, "users": set()},
        )
        users = bucket.get("users")
        if isinstance(users, set):
            users.add(user_clean)

    created_total = 0
    for value in grouped.values():
        users_raw = value.get("users")
        if not isinstance(users_raw, set):
            continue
        usernames = sorted(
            {
                str(user).strip()
                for user in users_raw
                if isinstance(user, str) and str(user).strip()
            },
            key=str.lower,
        )
        if len(usernames) < 2:
            continue
        credential_value = str(value.get("credential") or "").strip()
        if not credential_value:
            continue
        created_total += int(
            upsert_domain_password_reuse_edges(
                shell,
                domain,
                source_usernames=usernames,
                target_usernames=usernames,
                credential=credential_value,
                status="discovered",
                evidence_source="dcsync_all",
            )
            or 0
        )
    return created_total
