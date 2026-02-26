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
import os
import re
import sys

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
from adscan_internal.rich_output import (
    BRAND_COLORS,
    mark_sensitive,
    print_panel,
    print_attack_path_detail,
    print_attack_paths_summary,
)
from adscan_internal.services.attack_graph_service import (
    compute_display_paths_for_owned_users,
    compute_display_paths_for_principals,
    compute_display_paths_for_user,
    get_owned_domain_usernames,
    resolve_netexec_target_for_node_label,
    update_edge_status_by_labels,
)
from adscan_internal.services.attack_graph_runtime_service import (
    clear_attack_path_execution,
    set_attack_path_execution,
)
from adscan_internal.cli.roasting_execution import (
    run_asreproast_for_user,
    run_kerberoast_for_user,
)
from adscan_internal.cli.ace_step_execution import (
    ACL_ACE_RELATIONS,
    build_ace_step_context,
    describe_ace_step_support,
    execute_ace_step,
)
from adscan_internal.cli.attack_step_followups import (
    build_followups_for_step,
    render_followup_actions_panel,
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
    exec_username = _normalize_account(context_username or "")
    if exec_username:
        print_info_debug(
            f"[exec-user] Using context username: {mark_sensitive(exec_username, 'user')}"
        )
        return exec_username

    creds = getattr(shell, "domains_data", {}).get(domain, {}).get("credentials", {})
    if isinstance(creds, dict) and creds:
        from_user = _normalize_account(from_label or "")
        if from_user and from_user in {str(k).lower() for k in creds.keys()}:
            print_info_debug(
                f"[exec-user] Using from_label credential: {mark_sensitive(from_user, 'user')}"
            )
            return from_user

    meta = summary.get("meta") if isinstance(summary.get("meta"), dict) else {}
    affected_users = meta.get("affected_users") if isinstance(meta, dict) else None
    if isinstance(meta, dict):
        affected_count = meta.get("affected_user_count")
        affected_users_len = (
            len(affected_users) if isinstance(affected_users, list) else None
        )
        print_info_debug(
            "[exec-user] meta.affected_users summary: "
            f"count={affected_count!r}, list_len={affected_users_len!r}"
        )
    else:
        print_info_debug("[exec-user] No meta object available on path summary.")
    if not (isinstance(affected_users, list) and affected_users) and isinstance(
        meta, dict
    ):
        print_info_debug("[exec-user] meta.affected_users missing/empty.")

    candidate_users: list[str] = []
    if isinstance(affected_users, list) and isinstance(creds, dict):
        cred_keys = {str(k).lower(): str(k) for k in creds.keys()}
        for raw_user in affected_users:
            if not isinstance(raw_user, str):
                continue
            normalized = _normalize_account(raw_user)
            if not normalized:
                continue
            stored_key = cred_keys.get(normalized.lower())
            if stored_key:
                candidate_users.append(stored_key)

    if not candidate_users and isinstance(creds, dict) and creds:
        print_info_debug(
            "[exec-user] No meta.affected_users match; falling back to all stored credentials."
        )
        candidate_users = [str(k) for k in creds.keys()]

    if candidate_users:
        print_info_debug(
            f"[exec-user] Found {len(candidate_users)} candidate user(s) with stored credentials."
        )
        marked_domain = mark_sensitive(domain, "domain")
        print_panel(
            "\n".join(
                [
                    f"Domain: {marked_domain}",
                    f"Users with stored credentials: {len(candidate_users)}",
                ]
            ),
            title=Text("Select Execution User", style=f"bold {BRAND_COLORS['info']}"),
            border_style=BRAND_COLORS["info"],
            expand=False,
        )

        if len(candidate_users) == 1:
            print_info_debug(
                f"[exec-user] Auto-selected sole candidate: {mark_sensitive(candidate_users[0], 'user')}"
            )
            return candidate_users[0]

        if hasattr(shell, "_questionary_select"):
            options = [
                mark_sensitive(user, "user") for user in candidate_users[:max_options]
            ]
            if len(candidate_users) > max_options:
                options.append(
                    f"Enter username (showing {max_options} of {len(candidate_users)})"
                )
            options.append("Cancel")
            idx = shell._questionary_select(  # type: ignore[attr-defined]
                "Select a user to execute this step:",
                options,
                default_idx=0,
            )
            if idx is None or idx >= len(options) - 1:
                print_info_debug("[exec-user] User selection cancelled.")
                return None
            if len(candidate_users) > max_options and idx == len(options) - 2:
                manual_user = Prompt.ask("Enter username")
                if not manual_user:
                    print_info_debug("[exec-user] Manual username entry empty.")
                    return None
                normalized = _normalize_account(manual_user)
                if not normalized:
                    print_info_debug("[exec-user] Manual username entry invalid.")
                    print_warning("Invalid username entered.")
                    return None
                stored = cred_keys.get(normalized.lower())
                if not stored:
                    marked_user = mark_sensitive(normalized, "user")
                    print_warning(
                        f"No stored credential found for {marked_user}. "
                        "Please select a user with saved credentials."
                    )
                    print_info_debug(
                        f"[exec-user] Manual username not in credentials: {marked_user}"
                    )
                    return None
                print_info_debug(
                    f"[exec-user] Manual username matched credentials: {mark_sensitive(stored, 'user')}"
                )
                return stored
            print_info_debug(
                f"[exec-user] Selected candidate: {mark_sensitive(candidate_users[idx], 'user')}"
            )
            return str(candidate_users[idx]).strip().lower()

        return candidate_users[0]

    print_info_debug(
        "[exec-user] No execution user resolved: "
        f"from_label={from_label!r}, "
        f"meta.affected_users_len={len(affected_users) if isinstance(affected_users, list) else None!r}"
    )
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


def execute_selected_attack_path(
    shell: Any,
    domain: str,
    *,
    summary: dict[str, Any],
    context_username: str | None = None,
    context_password: str | None = None,
) -> bool:
    """Execute a selected attack path (best-effort).

    Currently supported step mappings:
    - AllowedToDelegate -> `shell.enum_delegations_user`

    Returns:
        True if an execution attempt was started, False otherwise.
    """
    set_attack_path_execution(shell)
    try:
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

        for idx, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                continue
            action = str(step.get("action") or "").strip()
            key = action.lower()
            if key in non_executable_actions:
                # Context-only edge (e.g. membership expansion), skip execution.
                continue
            if key in dangerous_actions:
                # High-risk step intentionally disabled.
                return execution_started
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
                target_host = (
                    resolve_netexec_target_for_node_label(
                        shell, domain, node_label=to_label
                    )
                    or to_label
                )

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
                    if followups:
                        render_followup_actions_panel(
                            step_action=action,
                            target_label=to_label or exec_context.target_sam_or_label,
                            followups=followups,
                        )
                        if hasattr(shell, "_questionary_select"):
                            options = (
                                ["Execute all recommended"]
                                + [f.title for f in followups]
                                + ["Skip"]
                            )
                            while True:
                                choice = shell._questionary_select(  # type: ignore[attr-defined]
                                    "Select a follow-up action to execute:",
                                    options,
                                    default_idx=0,
                                )
                                if choice is None:
                                    break
                                if choice == 0:
                                    for item in followups:
                                        item.handler()
                                    break
                                if choice >= len(options) - 1:
                                    break
                                followups[choice - 1].handler()
                        else:
                            # Non-interactive fallback: be explicit and skip.
                            print_info_verbose(
                                "Skipping follow-up actions (non-interactive environment)."
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

    def _compute_summaries() -> list[dict[str, Any]]:
        if start_norm == "owned":
            owned_users = get_owned_domain_usernames(shell, domain)
            if not owned_users:
                return []
            owned_summaries = compute_display_paths_for_owned_users(
                shell,
                domain,
                max_depth=max_depth,
                require_high_value_target=require_high_value_target,
            )
            return owned_summaries
        marked_domain = mark_sensitive(domain, "domain")
        marked_user = mark_sensitive(start, "user")
        print_info(f"Searching attack paths for {marked_user} in {marked_domain}...")
        return compute_display_paths_for_user(
            shell,
            domain,
            username=start,
            max_depth=max_depth,
            require_high_value_target=require_high_value_target,
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
        if start_norm == "owned":
            marked_domain = mark_sensitive(domain, "domain")
            scope = "high-value targets" if require_high_value_target else "all targets"
            print_warning(
                f"No attack paths found from owned users to {scope} for {marked_domain}."
            )
        else:
            marked_domain = mark_sensitive(domain, "domain")
            marked_user = mark_sensitive(start, "user")
            scope = "high-value targets" if require_high_value_target else "all targets"
            print_warning(
                f"No attack paths found for {marked_user} to {scope} in {marked_domain}."
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


def offer_attack_paths_for_execution_for_principals(
    shell: Any,
    domain: str,
    *,
    principals: list[str],
    max_depth: int = 10,
    max_display: int = 20,
    include_all: bool = False,
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
        return compute_display_paths_for_principals(
            shell,
            domain,
            principals=principals,
            max_depth=max_depth,
            require_high_value_target=require_high_value_target,
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
            return _sorted_paths(list(summaries))
        updated = recompute_summaries() or []
        return _sorted_paths(list(updated))

    def _domain_now_pwned() -> bool:
        domains_data = getattr(shell, "domains_data", None)
        if not isinstance(domains_data, dict):
            return False
        domain_data = domains_data.get(domain, {})
        if not isinstance(domain_data, dict):
            return False
        return domain_data.get("auth") == "pwned"

    summaries = _refresh_summaries()
    print_info_debug(
        f"[attack_paths] summaries refreshed: domain={marked_domain} count={len(summaries)}"
    )
    print_attack_paths_summary(
        domain, summaries, max_display=min(max_display, len(summaries))
    )

    executed = False
    desired_statuses = (
        {str(s).strip().lower() for s in execute_only_statuses}
        if execute_only_statuses
        else None
    )
    desired_statuses_set = (
        desired_statuses if isinstance(desired_statuses, set) else None
    )

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
                        str(summary.get("status") or "theoretical").strip().lower()
                        ,
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
            for summary in summaries:
                status = str(summary.get("status") or "theoretical").strip().lower()
                if not _status_allowed_by_filter(status, desired_statuses_set):
                    continue
                if not retry_attempted and status == "attempted":
                    continue
                if status == "exploited":
                    continue
                candidates.append(summary)

            if not candidates:
                print_info_verbose("No remaining attack paths eligible for execution.")
                print_info_debug(
                    f"[attack_paths] batch: domain={marked_domain} no eligible candidates"
                )
                return executed

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
        print_attack_path_detail(domain, selected, index=selected_idx + 1)

        status = str(selected.get("status") or "theoretical").lower()
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
            summaries = _refresh_summaries()
            if summaries:
                print_info_debug(
                    "[attack_paths] re-prompting after execution: "
                    f"domain={marked_domain} remaining={len(summaries)}"
                )
                print_attack_paths_summary(
                    domain, summaries, max_display=min(max_display, len(summaries))
                )
                continue
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
